// Oracle for siem-dbsync: drives Wazuh's real dbsync and rsync C APIs
// (shared_modules/dbsync, shared_modules/rsync) from a script and prints
// everything they produce.
//
// stdin: one command per line, fields separated by spaces, strings in hex,
// '-' for NULL. Handles are numbers: 0 is NULL, n the n-th handle created
// of that kind, 9999 a bogus non-NULL handle.
//   C  host dbtype path sql                    dbsync_create
//   P  host dbtype path sql n stmt1..stmtn|-   dbsync_create_persistent
//   X                                          dbsync_teardown
//   TX h tables threads maxq                   dbsync_create_txn
//   TC t | TR t json | TD t                    close_txn / sync_txn_row / get_deleted_rows
//   L h json | I h json | M h table max        add_table_relationship / insert_data / set_table_max_rows
//   S h json | Q h json | D h json             sync_row / select_rows / delete_rows
//   U h json | V h json                        update_with_snapshot / _cb
//   RC threads maxq                            rsync_create
//   RS r h json | RR r header h json           rsync_start_sync / rsync_register_sync_id
//   RP r payload | RX r | RT                   rsync_push_message / rsync_close / rsync_teardown
//   SLEEP ms                                   lets the rsync worker drain its queue
//                                              (rsync_close deregisters before it does)
//   DUMP path                                  every table of a database file
// stdout:
//   H n | R ret | J hex(result)       results
//   M hex | N hex                     dbsync / rsync log
//   F level tag file line func hex    rsync full log
//   B type hex|-                      dbsync callback (cJSON_PrintUnformatted)
//   Y hex                             rsync callback payload
//   E hex                             std::cerr lines
//   S hex | W table hex               dump: schema, rows
// The rsync worker thread's output is held until RX/RT (rundown) returns.

#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <chrono>
#include <ctime>
#include <iostream>
#include <mutex>
#include <sstream>
#include <streambuf>
#include <string>
#include <thread>
#include <vector>

#include "cJSON.h"
#include "dbsync.h"
#include "rsync.h"
#include "sqlite3.h"

static const long long ORACLE_TIME = 1700000000;

extern "C" time_t time(time_t* t)
{
    if (t)
    {
        *t = ORACLE_TIME;
    }
    return ORACLE_TIME;
}

static std::string hex(const void* p, size_t n)
{
    static const char* d = "0123456789abcdef";
    std::string s;
    const unsigned char* b = (const unsigned char*)p;
    for (size_t i = 0; i < n; i++)
    {
        s += d[b[i] >> 4];
        s += d[b[i] & 15];
    }
    return s;
}

static std::string hexs(const std::string& s)
{
    return hex(s.data(), s.size());
}

static std::string unhex(const std::string& h)
{
    std::string s;
    for (size_t i = 0; i + 1 < h.size(); i += 2)
    {
        s += (char)std::stoi(h.substr(i, 2), nullptr, 16);
    }
    return s;
}

static std::thread::id MAIN;
static std::mutex OUT_MUTEX;
static std::vector<std::string> PENDING;

static void emit(const std::string& line)
{
    std::lock_guard<std::mutex> lock(OUT_MUTEX);
    if (std::this_thread::get_id() == MAIN)
    {
        std::cout << line << "\n";
    }
    else
    {
        PENDING.push_back(line);
    }
}

static void flush_pending()
{
    std::lock_guard<std::mutex> lock(OUT_MUTEX);
    for (const auto& l : PENDING)
    {
        std::cout << l << "\n";
    }
    PENDING.clear();
}

// std::cerr → "E <hex line>"
class CerrBuf : public std::streambuf
{
    std::mutex m;
    std::string line;

protected:
    int overflow(int c) override
    {
        if (c != EOF)
        {
            std::string done;
            {
                std::lock_guard<std::mutex> lock(m);
                if (c == '\n')
                {
                    done = line;
                    line.clear();
                }
                else
                {
                    line += (char)c;
                    return c;
                }
            }
            emit("E " + hexs(done));
        }
        return c;
    }
};

static void dbsync_log(const char* msg)
{
    emit("M " + hex(msg, strlen(msg)));
}

static void rsync_log(const char* msg)
{
    emit("N " + hex(msg, strlen(msg)));
}

static void full_log(int level, const char* tag, const char* file, int line, const char* func, const char* msg, va_list args)
{
    char buf[65536];
    vsnprintf(buf, sizeof(buf), msg, args);
    const char* base = strrchr(file, '/');
    base = base ? base + 1 : file;
    emit("F " + std::to_string(level) + " " + tag + " " + base + " " + std::to_string(line) + " " + func + " " +
         hex(buf, strlen(buf)));
}

static void result_cb(ReturnTypeCallback type, const cJSON* json, void*)
{
    std::string s = "-";
    if (json)
    {
        char* p = cJSON_PrintUnformatted(json);
        s = hex(p, strlen(p));
        cJSON_free(p);
    }
    emit("B " + std::to_string((int)type) + " " + s);
}

static void sync_cb(const void* buffer, size_t size, void*)
{
    emit("Y " + hex(buffer, size));
}

static std::vector<void*> DB, TXN, RS;

static void* handle(std::vector<void*>& v, const std::string& f)
{
    const int n = std::stoi(f);
    if (n == 0)
    {
        return nullptr;
    }
    if (n == 9999 || n > (int)v.size())
    {
        return (void*)0xdead0;
    }
    return v[n - 1];
}

static cJSON* json(const std::string& f)
{
    if (f == "-")
    {
        return nullptr;
    }
    // parsed from bytes: an unparsable text gives a string value
    std::string s = unhex(f);
    cJSON* j = cJSON_Parse(s.c_str());
    if (!j)
    {
        j = cJSON_CreateString(s.c_str());
    }
    return j;
}

static void dump(const std::string& path)
{
    sqlite3* db = nullptr;
    if (sqlite3_open_v2(path.c_str(), &db, SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK)
    {
        std::cout << "S -\n";
        sqlite3_close_v2(db);
        return;
    }
    sqlite3_stmt* st = nullptr;
    sqlite3_prepare_v2(db, "SELECT name, sql FROM sqlite_master ORDER BY type, name", -1, &st, nullptr);
    std::vector<std::string> tables;
    while (sqlite3_step(st) == SQLITE_ROW)
    {
        const char* name = (const char*)sqlite3_column_text(st, 0);
        const char* sql = (const char*)sqlite3_column_text(st, 1);
        std::cout << "S " << hex(name, strlen(name)) << " " << (sql ? hex(sql, strlen(sql)) : "-") << "\n";
        if (sql && strncmp(sql, "CREATE TABLE", 12) == 0)
        {
            tables.push_back(name);
        }
    }
    sqlite3_finalize(st);
    for (const auto& t : tables)
    {
        sqlite3_stmt* rs = nullptr;
        const std::string q = "SELECT * FROM \"" + t + "\" ORDER BY rowid";
        if (sqlite3_prepare_v2(db, q.c_str(), -1, &rs, nullptr) != SQLITE_OK)
        {
            continue;
        }
        while (sqlite3_step(rs) == SQLITE_ROW)
        {
            std::string row;
            for (int i = 0; i < sqlite3_column_count(rs); i++)
            {
                switch (sqlite3_column_type(rs, i))
                {
                    case SQLITE_INTEGER: row += "i" + std::to_string(sqlite3_column_int64(rs, i)); break;
                    case SQLITE_FLOAT:
                    {
                        char b[64];
                        snprintf(b, sizeof(b), "%.17g", sqlite3_column_double(rs, i));
                        row += std::string("f") + b;
                        break;
                    }
                    case SQLITE_NULL: row += "n"; break;
                    default:
                    {
                        const void* p = sqlite3_column_blob(rs, i);
                        row += "t" + hex(p, sqlite3_column_bytes(rs, i));
                    }
                }
                row += ",";
            }
            std::cout << "W " << hexs(t) << " " << row << "\n";
        }
        sqlite3_finalize(rs);
    }
    sqlite3_close_v2(db);
}

int main()
{
    MAIN = std::this_thread::get_id();
    std::ios::sync_with_stdio(false);
    CerrBuf cerrbuf;
    std::cerr.rdbuf(&cerrbuf);
    // cerr flushes a tied cout: the worker thread would race the main one
    std::cerr.tie(nullptr);
    dbsync_initialize(dbsync_log);
    rsync_initialize(rsync_log);
    rsync_initialize_full_log_function(full_log);
    const callback_data_t cb {result_cb, nullptr};
    const sync_callback_data_t scb {sync_cb, nullptr};

    std::string line;
    while (std::getline(std::cin, line))
    {
        std::vector<std::string> f;
        std::istringstream is(line);
        std::string w;
        while (is >> w)
        {
            f.push_back(w);
        }
        if (f.empty())
        {
            continue;
        }
        const auto& c = f[0];
        auto s = [&](size_t i) { return f[i] == "-" ? std::string() : unhex(f[i]); };
        auto ps = [&](size_t i, std::string& keep) -> const char*
        {
            if (f[i] == "-")
            {
                return nullptr;
            }
            keep = unhex(f[i]);
            return keep.c_str();
        };
        int r = 0;
        bool print_r = true;
        if (c == "C" || c == "P")
        {
            std::string k1, k2;
            void* h;
            if (c == "C")
            {
                h = dbsync_create((HostType)std::stoi(f[1]), (DbEngineType)std::stoi(f[2]), ps(3, k1), ps(4, k2));
            }
            else
            {
                std::vector<std::string> keep;
                std::vector<const char*> stmts;
                const int n = std::stoi(f[5]);
                for (int i = 0; i < n; i++)
                {
                    keep.push_back(unhex(f[6 + i]));
                }
                for (auto& k : keep)
                {
                    stmts.push_back(k.c_str());
                }
                stmts.push_back(nullptr);
                h = dbsync_create_persistent(
                    (HostType)std::stoi(f[1]), (DbEngineType)std::stoi(f[2]), ps(3, k1), ps(4, k2), n < 0 ? nullptr : stmts.data());
            }
            if (h)
            {
                DB.push_back(h);
            }
            std::cout << "H " << (h ? DB.size() : 0) << "\n";
            print_r = false;
        }
        else if (c == "X")
        {
            dbsync_teardown();
        }
        else if (c == "TX")
        {
            cJSON* j = json(f[2]);
            void* t = dbsync_create_txn(
                handle(DB, f[1]), j, std::stoul(f[3]), std::stoul(f[4]), f.size() > 5 ? callback_data_t {nullptr, nullptr} : cb);
            cJSON_Delete(j);
            if (t)
            {
                TXN.push_back(t);
            }
            std::cout << "H " << (t ? TXN.size() : 0) << "\n";
            print_r = false;
        }
        else if (c == "TC")
        {
            r = dbsync_close_txn(handle(TXN, f[1]));
        }
        else if (c == "TR")
        {
            cJSON* j = json(f[2]);
            r = dbsync_sync_txn_row(handle(TXN, f[1]), j);
            cJSON_Delete(j);
        }
        else if (c == "TD")
        {
            r = dbsync_get_deleted_rows(handle(TXN, f[1]), cb);
        }
        else if (c == "L" || c == "I" || c == "S" || c == "Q" || c == "D" || c == "U" || c == "V")
        {
            cJSON* j = json(f[2]);
            void* h = handle(DB, f[1]);
            if (c == "L")
                r = dbsync_add_table_relationship(h, j);
            else if (c == "I")
                r = dbsync_insert_data(h, j);
            else if (c == "S")
                r = dbsync_sync_row(h, j, cb);
            else if (c == "Q")
                r = dbsync_select_rows(h, j, cb);
            else if (c == "D")
                r = dbsync_delete_rows(h, j);
            else if (c == "V")
                r = dbsync_update_with_snapshot_cb(h, j, cb);
            else
            {
                cJSON* res = nullptr;
                r = dbsync_update_with_snapshot(h, j, &res);
                if (res)
                {
                    char* p = cJSON_PrintUnformatted(res);
                    std::cout << "J " << hex(p, strlen(p)) << "\n";
                    cJSON_free(p);
                    dbsync_free_result(&res);
                }
            }
            cJSON_Delete(j);
        }
        else if (c == "M")
        {
            std::string k;
            r = dbsync_set_table_max_rows(handle(DB, f[1]), ps(2, k), std::stoll(f[3]));
        }
        else if (c == "RC")
        {
            void* h = rsync_create(std::stoul(f[1]), std::stoul(f[2]));
            if (h)
            {
                RS.push_back(h);
            }
            std::cout << "H " << (h ? RS.size() : 0) << "\n";
            print_r = false;
        }
        else if (c == "RS")
        {
            cJSON* j = json(f[3]);
            r = rsync_start_sync(handle(RS, f[1]), handle(DB, f[2]), j, scb);
            cJSON_Delete(j);
        }
        else if (c == "RR")
        {
            std::string k;
            cJSON* j = json(f[4]);
            r = rsync_register_sync_id(handle(RS, f[1]), ps(2, k), handle(DB, f[3]), j, scb);
            cJSON_Delete(j);
        }
        else if (c == "RP")
        {
            std::string p = s(2);
            r = rsync_push_message(handle(RS, f[1]), f[2] == "-" ? nullptr : p.data(), p.size());
        }
        else if (c == "RX")
        {
            r = rsync_close(handle(RS, f[1]));
            flush_pending();
        }
        else if (c == "RT")
        {
            rsync_teardown();
            flush_pending();
        }
        else if (c == "SLEEP")
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(std::stoi(f[1])));
            print_r = false;
        }
        else if (c == "DUMP")
        {
            dump(unhex(f[1]));
            print_r = false;
        }
        else
        {
            std::cout << "? " << line << "\n";
            print_r = false;
        }
        if (print_r)
        {
            std::cout << "R " << r << "\n";
        }
        std::cout.flush();
    }
    return 0;
}
