/* Differential oracle for the wazuh-db HTTP API (wdb-http.sock): the
 * router's router_register_api_endpoint / router_start_api /
 * router_stop_api (router.cpp, copied), the real wazuh-db gateway and
 * endpoints (shared_modules/router/src/wazuh-db) with cpp-httplib 0.14.2 and
 * nlohmann::json 3.11.2 (Wazuh's deps/54), over the real wdb_global_pre /
 * wdb_global_post of the wazuh-db library (wdb_harness.c drives it).
 *
 * stdin lines: the wdb_harness lines (Q / T / G), plus
 *   H <hex>   one exchange: connect to queue/sockets/wdb-http.sock, send
 *             the bytes, read until EOF or 300 ms of silence, then
 *             half-close and read until the server closes
 * stdout: the wdb_harness lines, "H <hex>" with what the client read, and
 *   "M <level> <hex>" for the router's error/warning/info logs.
 */
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "logging_helper.h"

static std::function<void(const modules_log_level_t, const std::string&)> GS_LOG_FUNCTION;

void logMessage(const modules_log_level_t level, const std::string& msg)
{
    if (!msg.empty() && GS_LOG_FUNCTION)
    {
        GS_LOG_FUNCTION(level, msg);
    }
}

#include "external/cpp-httplib/httplib.h"
#include "routerModuleGateway.hpp"

extern "C"
{
    int harness_init(const char* home);
    void harness_line(char* line);
    void harness_finish(void);
    sqlite3* wdb_global_pre(void** wdb_ctx);
    void wdb_global_post(void* wdb_ctx);
}

static std::mutex OUT_MUTEX;

static void printHex(const char* tag, const char* p, size_t n)
{
    std::lock_guard<std::mutex> lock(OUT_MUTEX);
    printf("%s ", tag);
    for (size_t i = 0; i < n; i++)
    {
        printf("%02x", static_cast<unsigned char>(p[i]));
    }
    printf("\n");
    fflush(stdout);
}

/* taggedLogFunction with the test stubs' rule: error/warning/info only */
static void callbackLog(modules_log_level_t level, const char* log, const char* /*tag*/)
{
    const char* lvl = nullptr;
    switch (level)
    {
        case LOG_ERROR: lvl = "M ERROR"; break;
        case LOG_ERROR_EXIT: lvl = "M CRITICAL"; break;
        case LOG_INFO: lvl = "M INFO"; break;
        case LOG_WARNING: lvl = "M WARNING"; break;
        default: return;
    }
    printHex(lvl, log, strlen(log));
}

/* ---- router.cpp (API part) ---- */

struct ServerInstance final
{
    std::unique_ptr<httplib::Server> server;
    std::thread serverThread;
    bool running {false};
};

std::map<std::string, std::shared_ptr<ServerInstance>> G_HTTPINSTANCES;

void router_register_api_endpoint(
    const char* module, const char* socketPath, const char* method, const char* endpoint, void* callbackPre, void* callbackPost)
{
    if (!socketPath || !endpoint || !method || !module)
    {
        logMessage(modules_log_level_t::LOG_ERROR, "Error registering API endpoint. Invalid parameters");
        return;
    }

    std::string socketPathStr(socketPath);
    if (G_HTTPINSTANCES.find(socketPathStr) == G_HTTPINSTANCES.end())
    {
        G_HTTPINSTANCES[socketPathStr] = std::make_shared<ServerInstance>();
        G_HTTPINSTANCES[socketPathStr]->server = std::make_unique<httplib::Server>();
    }

    auto instance = G_HTTPINSTANCES[socketPathStr];
    auto methodStr = std::string(method);
    auto endpointStr = std::string(endpoint);
    auto moduleStr = std::string(module);

    if (methodStr.compare("GET") == 0)
    {
        logMessage(modules_log_level_t::LOG_INFO, "Registering GET endpoint: " + endpointStr);
        instance->server->Get(
            endpoint,
            [callbackPre, callbackPost, endpointStr = std::move(endpointStr), moduleStr = std::move(moduleStr)](
                const httplib::Request& req, httplib::Response& res)
            {
                logMessage(modules_log_level_t::LOG_DEBUG_VERBOSE,
                           "GET: " + endpointStr + " request parameters: " + req.path);
                auto start = std::chrono::high_resolution_clock::now();
                RouterModuleGateway::redirect(moduleStr, callbackPre, callbackPost, endpointStr, "GET", req, res);
                auto end = std::chrono::high_resolution_clock::now();
                auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
                logMessage(modules_log_level_t::LOG_DEBUG,
                           "GET: " + endpointStr + " request processed in " + std::to_string(duration.count()) + " us");
            });
    }
    else if (methodStr.compare("POST") == 0)
    {
        logMessage(modules_log_level_t::LOG_INFO, "Registering POST endpoint: " + endpointStr);
        instance->server->Post(
            endpoint,
            [callbackPre, callbackPost, endpointStr = std::move(endpointStr), moduleStr = std::move(moduleStr)](
                const httplib::Request& req, httplib::Response& res)
            {
                auto start = std::chrono::high_resolution_clock::now();
                RouterModuleGateway::redirect(moduleStr, callbackPre, callbackPost, endpointStr, "POST", req, res);
                auto end = std::chrono::high_resolution_clock::now();
                auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
                logMessage(modules_log_level_t::LOG_DEBUG,
                           "POST: " + endpointStr + " request processed in " + std::to_string(duration.count()) + " us");
            });
    }
    else
    {
        logMessage(modules_log_level_t::LOG_ERROR, "Error registering API endpoint. Invalid method");
        return;
    }
}

void router_start_api(const char* socketPath)
{
    if (!socketPath)
    {
        logMessage(modules_log_level_t::LOG_ERROR, "Error starting API. Invalid socket path");
        return;
    }

    std::string socketPathStr(socketPath);
    if (G_HTTPINSTANCES.find(socketPath) == G_HTTPINSTANCES.end())
    {
        logMessage(modules_log_level_t::LOG_ERROR, "Error starting API. Socket path not found");
        return;
    }

    auto instance = G_HTTPINSTANCES[socketPath];

    instance->serverThread = std::thread(
        [instance, socketPathStr = std::move(socketPathStr)]()
        {
            const static std::string SOCKETPATH {"queue/sockets/"};
            std::filesystem::remove(SOCKETPATH + socketPathStr);
            std::filesystem::path path {SOCKETPATH + socketPathStr};
            std::filesystem::create_directories(path.parent_path());
            instance->server->set_address_family(AF_UNIX);
            instance->server->set_exception_handler(
                [](const auto& req, auto& res, std::exception_ptr ep)
                {
                    try
                    {
                        std::rethrow_exception(std::move(ep));
                    }
                    catch (const std::exception& e)
                    {
                        logMessage(modules_log_level_t::LOG_ERROR, std::string(e.what()) + " on endpoint: " + req.path);
                    }
                    catch (...)
                    {
                        logMessage(modules_log_level_t::LOG_ERROR, "Unknown exception");
                    }
                    res.status = 500;
                });
            instance->running = instance->server->listen(path.c_str(), true);

            if (instance->running == false)
            {
                logMessage(modules_log_level_t::LOG_ERROR, "Error starting API. Failed to listen on socket");
                return;
            }

            if (chmod(path.c_str(), 0660) == 0)
            {
                logMessage(modules_log_level_t::LOG_DEBUG_VERBOSE, "API socket permissions set to 0660");
            }
            else
            {
                logMessage(modules_log_level_t::LOG_ERROR,
                           "Error setting API socket permissions: " + std::string(strerror(errno)));
            }
        });
    // Spin lock until server is ready
    while (!instance->server->is_running() && instance->running)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    logMessage(modules_log_level_t::LOG_INFO, "API started successfully");
}

void router_stop_api(const char* socketPath)
{
    if (!socketPath)
    {
        logMessage(modules_log_level_t::LOG_ERROR, "Error stopping API. Invalid socket path");
        return;
    }

    auto it = G_HTTPINSTANCES.find(socketPath);
    if (it != G_HTTPINSTANCES.end())
    {
        it->second->server->stop();
        if (it->second->serverThread.joinable())
        {
            logMessage(modules_log_level_t::LOG_INFO, "Stopping server thread");
            it->second->serverThread.join();
        }
        G_HTTPINSTANCES.erase(it);
    }
}

/* ---- the client of an H line ---- */

static std::string unhex(const char* s)
{
    std::string out;
    while (s[0] && s[1])
    {
        unsigned v;
        if (sscanf(s, "%2x", &v) != 1)
        {
            break;
        }
        out.push_back(static_cast<char>(v));
        s += 2;
    }
    return out;
}

static void exchange(const std::string& request)
{
    std::string got;
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    sockaddr_un addr {};
    addr.sun_family = AF_UNIX;
    const char* p = "queue/sockets/wdb-http.sock";
    strncpy(addr.sun_path, p, sizeof(addr.sun_path) - 1);
    /* the server thread may still be binding */
    int ok = -1;
    for (int i = 0; i < 100 && ok != 0; i++)
    {
        ok = connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
        if (ok != 0)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
    }
    if (ok == 0)
    {
        size_t off = 0;
        while (off < request.size())
        {
            auto n = send(sock, request.data() + off, request.size() - off, MSG_NOSIGNAL);
            if (n <= 0)
            {
                break;
            }
            off += static_cast<size_t>(n);
        }
        char buf[65536];
        while (true)
        {
            pollfd pfd {sock, POLLIN, 0};
            if (poll(&pfd, 1, 300) <= 0)
            {
                break;
            }
            auto n = recv(sock, buf, sizeof(buf), 0);
            if (n <= 0)
            {
                break;
            }
            got.append(buf, static_cast<size_t>(n));
        }
        /* then half-close and wait for the server to close the connection,
         * so the exchange (and its logs) ends when the server is done */
        shutdown(sock, SHUT_WR);
        while (true)
        {
            pollfd pfd {sock, POLLIN, 0};
            if (poll(&pfd, 1, 8000) <= 0)
            {
                break;
            }
            auto n = recv(sock, buf, sizeof(buf), 0);
            if (n <= 0)
            {
                break;
            }
            got.append(buf, static_cast<size_t>(n));
        }
    }
    close(sock);
    printHex("H", got.data(), got.size());
}

int main(int argc, char** argv)
{
    if (argc < 2 || harness_init(argv[1]) < 0)
    {
        fprintf(stderr, "usage: http_oracle <home>\n");
        return 1;
    }
    /* router_initialize(taggedLogFunction) */
    GS_LOG_FUNCTION = [](const modules_log_level_t level, const std::string& msg)
    { callbackLog(level, msg.c_str(), ":router"); };

    /* main.c */
    const char* routes[][2] = {
        {"GET", "/v1/agents/ids"},
        {"GET", "/v1/agents/ids/groups/:name"},
        {"GET", "/v1/agents/ids/groups"},
        {"GET", "/v1/agents/:agent_id/groups"},
        {"POST", "/v1/agents/summary"},
        {"GET", "/v1/agents/sync"},
        {"POST", "/v1/agents/sync"},
        {"POST", "/v1/agents/restartinfo"},
    };
    for (auto& r : routes)
    {
        router_register_api_endpoint("wazuh-db", "wdb-http.sock", r[0], r[1], (void*)&wdb_global_pre, (void*)&wdb_global_post);
    }
    router_start_api("wdb-http.sock");

    static char line[3 * 65536 + 64];
    while (fgets(line, sizeof(line), stdin))
    {
        line[strcspn(line, "\n")] = '\0';
        if (line[0] == 'H' && line[1] == ' ')
        {
            exchange(unhex(line + 2));
        }
        else
        {
            std::lock_guard<std::mutex> lock(OUT_MUTEX);
            harness_line(line);
        }
    }
    router_stop_api("wdb-http.sock");
    std::lock_guard<std::mutex> lock(OUT_MUTEX);
    harness_finish();
    return 0;
}
