#ifndef CORE_MONITOR_SRC_MCP_HPP
#define CORE_MONITOR_SRC_MCP_HPP

#include "Json.hpp"
#include "Session.hpp"
#include <cstdint>
#include <iosfwd>
#include <mutex>
#include <string>

namespace Monitor {

class McpServer {
public:
    McpServer(Session& session, std::mutex& mutex, std::uint64_t pid);

    std::string Handle(const std::string& line);

private:
    Json handleRequest(const std::string& method, const Json* parameters);
    Json callTool(const std::string& name, const Json& arguments);
    void ensureConnected();
    Json summary();
    Json imports(const Json& arguments);
    Json threads(const Json& arguments);
    Json slowCalls(const Json& arguments);
    Json frames(const Json& arguments);
    Json recentCalls(const Json& arguments);
    Json sample(const Json& arguments);

    Session& _session;
    std::mutex& _mutex;
    std::uint64_t _pid;
};

int RunMcp(Session& session, std::uint64_t pid, std::istream& in, std::ostream& out);

}

#endif
