// Oracle for siem-router's flatbuffers path: router.cpp's
// router_provider_send_fb_json / router_provider_send_fb (bodies copied
// verbatim, the provider's send replaced by a "D <hex>" line) over the real
// SchemaAdapter, flatbuffers 23.5.26 (Wazuh deps/54) and simdjson 3.13.0.
//
// stdin, one case per line, hex fields, '-' for NULL:
//   J <handle 0|1> <schema int> <agent_id|!> <agent_name> <agent_ip> <agent_version|-> <message|->
//   F <handle 0|1> <schema text|-> <message|->
// ('!' as agent_id passes a NULL agent context.) stdout per case:
//   M <level> <hex msg>   (logMessage)
//   D <hex data>          (the provider's send)
//   R <return value>

#include <cstdio>
#include <iostream>
#include <map>
#include <memory>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <vector>

#include "flatbuffers/idl.h"
#include "router.h"

void logMessage(modules_log_level_t level, const std::string& msg);

#include "schemaAdapter.hpp"
#include "rsync_schema.h"
#include "syscheck_deltas_schema.h"
#include "syscollector_deltas_schema.h"

static std::string hex(const char* p, size_t n)
{
    static const char* d = "0123456789abcdef";
    std::string s;
    for (size_t i = 0; i < n; i++)
    {
        s += d[(unsigned char)p[i] >> 4];
        s += d[(unsigned char)p[i] & 15];
    }
    return s;
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

void logMessage(modules_log_level_t level, const std::string& msg)
{
    if (!msg.empty())
    {
        // the module callback receives msg.c_str()
        const char* c = msg.c_str();
        std::cout << "M " << (int)level << " " << hex(c, strlen(c)) << "\n";
    }
}

static bool VALID_HANDLE;

struct FakeProvider
{
    void send(const std::vector<char>& data)
    {
        std::cout << "D " << hex(data.data(), data.size()) << "\n";
    }
};

struct Providers
{
    std::shared_ptr<FakeProvider> at(int)
    {
        if (!VALID_HANDLE)
        {
            throw std::out_of_range("map::at");
        }
        return std::make_shared<FakeProvider>();
    }
} PROVIDERS;
std::shared_mutex PROVIDERS_MUTEX;
typedef int ROUTER_PROVIDER_HANDLE_T;

std::map<msg_type, flatbuffers::Parser> initSchemaParsers()
{
    std::map<msg_type, flatbuffers::Parser> SCHEMA_PARSERS;
    std::map<msg_type, const char*> SCHEMA_MAP = {
        {MT_SYS_DELTAS, syscollector_deltas_SCHEMA},
        {MT_SYNC, rsync_SCHEMA},
        {MT_SYSCHECK_DELTAS, syscheck_deltas_SCHEMA},
    };

    for (const auto& [type, schema] : SCHEMA_MAP)
    {
        SCHEMA_PARSERS[type] = flatbuffers::Parser();
        SCHEMA_PARSERS[type].opts.skip_unexpected_fields_in_json = true;
        SCHEMA_PARSERS[type].opts.zero_on_float_to_int =
            true; // Avoids issues with float to int conversion, custom option made for Wazuh.

        if (!SCHEMA_PARSERS[type].Parse(schema))
        {
            throw std::runtime_error("Error parsing schema, " + std::string(SCHEMA_PARSERS[type].error_));
        }
    }
    return SCHEMA_PARSERS;
}

int router_provider_send_fb(ROUTER_PROVIDER_HANDLE_T handle, const char* message, const char* schema)
{
    int retVal = -1;
    try
    {
        if (!message)
        {
            throw std::runtime_error("Error sending message to provider. Message is empty");
        }
        else
        {
            flatbuffers::Parser parser;
            parser.opts.skip_unexpected_fields_in_json = true;
            parser.opts.zero_on_float_to_int =
                true; // Avoids issues with float to int conversion, custom option made for Wazuh.

            if (!parser.Parse(schema))
            {
                throw std::runtime_error("Error parsing schema, " + std::string(parser.error_));
            }

            if (!parser.Parse(message))
            {
                throw std::runtime_error("Error parsing message, " + std::string(parser.error_));
            }

            std::vector<char> data(parser.builder_.GetBufferPointer(),
                                   parser.builder_.GetBufferPointer() + parser.builder_.GetSize());
            std::shared_lock<std::shared_mutex> lock(PROVIDERS_MUTEX);
            PROVIDERS.at(handle)->send(data);
            retVal = 0;
        }
    }
    catch (const std::exception& e)
    {
        logMessage(modules_log_level_t::LOG_ERROR, std::string("Error sending message to provider: ") + e.what());
    }
    return retVal;
}

int router_provider_send_fb_json(ROUTER_PROVIDER_HANDLE_T handle,
                                 const char* message,
                                 const agent_ctx* agent_ctx,
                                 const msg_type schema)
{
    int retVal = -1;
    try
    {
        if (!message)
        {
            throw std::runtime_error("Error sending message to provider. Message is empty");
        }
        else
        {
            static thread_local auto parserMap = initSchemaParsers();
            static thread_local std::string buffer;

            auto& parser = parserMap.at(schema);
            parser.builder_.Clear();

            buffer.clear();

            SchemaAdapter::adaptJsonMessage(message, schema, agent_ctx, buffer);

            if (buffer.empty())
            {
                return 0;
            }

            if (!parser.Parse(buffer.c_str()))
            {
                logMessage(modules_log_level_t::LOG_ERROR, "JSON message: " + buffer);
                throw std::runtime_error("Error parsing message, " + std::string(parser.error_));
            }

            std::vector<char> data(parser.builder_.GetBufferPointer(),
                                   parser.builder_.GetBufferPointer() + parser.builder_.GetSize());
            std::shared_lock<std::shared_mutex> lock(PROVIDERS_MUTEX);
            PROVIDERS.at(handle)->send(data);
            retVal = 0;
        }
    }
    catch (const std::exception& e)
    {
        logMessage(modules_log_level_t::LOG_ERROR, std::string("Error sending message to provider: ") + e.what());
    }
    return retVal;
}

int main()
{
    std::ios::sync_with_stdio(false);
    std::string line;
    while (std::getline(std::cin, line))
    {
        std::vector<std::string> f;
        size_t p = 0;
        while (p <= line.size())
        {
            size_t q = line.find(' ', p);
            if (q == std::string::npos)
            {
                q = line.size();
            }
            f.push_back(line.substr(p, q - p));
            p = q + 1;
        }
        int r = 0;
        if (f[0] == "J" && f.size() == 8)
        {
            VALID_HANDLE = f[1] == "1";
            std::string id = unhex(f[3]), name = unhex(f[4]), ip = unhex(f[5]), version = unhex(f[6]),
                        msg = unhex(f[7]);
            agent_ctx ctx {id.c_str(), name.c_str(), ip.c_str(), f[6] == "-" ? nullptr : version.c_str()};
            r = router_provider_send_fb_json(
                0, f[7] == "-" ? nullptr : msg.c_str(), f[3] == "!" ? nullptr : &ctx, (msg_type)std::stoi(f[2]));
        }
        else if (f[0] == "F" && f.size() == 4)
        {
            VALID_HANDLE = f[1] == "1";
            std::string schema = unhex(f[2]), msg = unhex(f[3]);
            r = router_provider_send_fb(0, f[3] == "-" ? nullptr : msg.c_str(), schema.c_str());
        }
        else
        {
            std::cout << "bad line\n";
            continue;
        }
        std::cout << "R " << r << "\n";
        std::cout.flush();
    }
    return 0;
}
