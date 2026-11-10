/* Interop tool on Wazuh's real router (routerFacade.cpp and the utils socket
 * layer), run from a home directory (queue/router/ is relative):
 *   router_tool broker <secs>                   the registration server
 *   router_tool provide <topic> <secs> <msg>... a remote provider: waits for
 *                                               the connection, pushes, waits
 *   router_tool subscribe <topic> <id> <secs>   a remote subscriber; prints
 *                                               "CONNECTED" and "GOT <hex>"
 */
#include <chrono>
#include <cstdio>
#include <string>
#include <thread>
#include <atomic>

#include "routerFacade.hpp"

int main(int argc, char** argv)
{
    if (argc < 3)
    {
        return 2;
    }
    std::string mode = argv[1];
    setvbuf(stdout, nullptr, _IONBF, 0);
    if (mode == "broker")
    {
        RouterFacade::instance().initialize();
        printf("BROKER\n");
        std::this_thread::sleep_for(std::chrono::seconds(atoi(argv[2])));
        RouterFacade::instance().destroy();
    }
    else if (mode == "provide" && argc >= 4)
    {
        std::atomic<bool> connected {false};
        RouterFacade::instance().initProviderRemote(argv[2], [&]() { connected = true; });
        for (int i = 0; i < 100 && !connected; i++)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        printf(connected ? "CONNECTED\n" : "NOT CONNECTED\n");
        for (int i = 4; i < argc; i++)
        {
            std::string m = argv[i];
            RouterFacade::instance().push(argv[2], std::vector<char>(m.begin(), m.end()));
        }
        std::this_thread::sleep_for(std::chrono::seconds(atoi(argv[3])));
        RouterFacade::instance().removeProviderRemote(argv[2]);
    }
    else if (mode == "subscribe" && argc >= 5)
    {
        RouterFacade::instance().addSubscriberRemote(
            argv[2],
            argv[3],
            [](const std::vector<char>& d)
            {
                printf("GOT ");
                for (auto c : d)
                {
                    printf("%02x", static_cast<unsigned char>(c));
                }
                printf("\n");
            },
            []() { printf("CONNECTED\n"); });
        std::this_thread::sleep_for(std::chrono::seconds(atoi(argv[4])));
        RouterFacade::instance().removeSubscriberRemote(argv[2], argv[3]);
    }
    return 0;
}
