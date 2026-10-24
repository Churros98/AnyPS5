#ifndef CORE_MONITOR_SRC_MCP_HPP
#define CORE_MONITOR_SRC_MCP_HPP

#include "Json.hpp"
#include "Memory.hpp"
#include "Session.hpp"
#include "Symbols.hpp"
#include <chrono>
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
    CommandResult awaitCommand(Telemetry::CommandKind kind, std::uint64_t first, std::uint64_t second, std::uint64_t third, std::chrono::milliseconds timeout);
    Symbols& symbols();
    ProcessMemory& memory();
    std::uint64_t address(const Json& value);
    Json describe(std::uint64_t address);
    Json summary();
    Json imports(const Json& arguments);
    Json threads(const Json& arguments);
    Json slowCalls(const Json& arguments);
    Json frames(const Json& arguments);
    Json recentCalls(const Json& arguments);
    Json sample(const Json& arguments);
    Json resolveAddress(const Json& arguments);
    Json listModules(const Json& arguments);
    Json sampleStacks(const Json& arguments);
    Json watchImport(const Json& arguments);
    Json watchedCalls(const Json& arguments);
    Json driverPhases(const Json& arguments);
    Json setSlowThreshold(const Json& arguments);
    Json saveSnapshot(const Json& arguments);
    Json listSnapshots();
    Json compareSnapshots(const Json& arguments);
    Json memoryRegions(const Json& arguments);
    Json readMemory(const Json& arguments);
    Json searchMemory(const Json& arguments);

    Session& _session;
    std::mutex& _mutex;
    std::uint64_t _pid;
    Symbols _symbols;
    ProcessMemory _memory;
};

int RunMcp(Session& session, std::uint64_t pid, std::istream& in, std::ostream& out);

}

#endif
