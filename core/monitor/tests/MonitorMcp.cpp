#include "Json.hpp"
#include "Mcp.hpp"
#include "Session.hpp"
#include "prx/libc/include/CallTrace.hpp"
#include "prx/libc/include/Telemetry.hpp"
#include "prx/libc/include/general/VabiMacros.hpp"
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <source_location>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using Monitor::Json;

static void Require(bool condition, std::source_location location = std::source_location::current()) {
    if (!condition) {
        std::fprintf(stderr, "Monitor MCP check failed at line %u\n", location.line());
        std::abort();
    }
}

static void APS5_VABI Nap(std::uint64_t milliseconds) {
    std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
}

static void SetVariable(const char* name, const char* value) {
#ifdef _WIN32
    Require(_putenv_s(name, value) == 0);
#else
    Require(setenv(name, value, 1) == 0);
#endif
}

static std::uint64_t ProcessId() {
#ifdef _WIN32
    return GetCurrentProcessId();
#else
    return static_cast<std::uint64_t>(getpid());
#endif
}

static bool Throws(const char* text) {
    try {
        Json::Parse(text);
    } catch (const std::runtime_error&) {
        return true;
    }
    return false;
}

static void CheckJson() {
    const Json value = Json::Parse(R"( {"a": [1, -0.5, 1e3, true, false, null], "b": "x\"\\\/\n\u00e9\ud83d\ude00", "c": {}} )");
    Require(value.Find("a")->Items().size() == 6 && value.Find("a")->Items()[2].AsNumber() == 1000 && value.Find("a")->Items()[5].IsNull());
    Require(value.Find("b")->AsString() == "x\"\\/\n\xc3\xa9\xf0\x9f\x98\x80");
    Require(value.Find("c")->Members().empty() && value.Find("missing") == nullptr);
    Require(value.Dump() == R"({"a":[1,-0.5,1000,true,false,null],"b":"x\"\\/\n)" "\xc3\xa9\xf0\x9f\x98\x80" R"(","c":{}})");
    Require(Json::Parse(value.Dump()).Dump() == value.Dump());
    Require(Json(std::string("\x01")).Dump() == R"("\u0001")");
    Require(Throws("[1,]") && Throws("{\"a\" 1}") && Throws("\"open") && Throws("\"\x01\"") && Throws("[1] 2") && Throws("\"\\ud800\"") && Throws("01x") && Throws(""));
    Require(Throws(std::string(65, '[').append(65, ']').c_str()) && !Throws(std::string(64, '[').append(64, ']').c_str()));
}

static Json Call(Monitor::McpServer& server, int id, const char* method, Json parameters) {
    const std::string line = Json::Object({{"jsonrpc", "2.0"}, {"id", id}, {"method", method}, {"params", std::move(parameters)}}).Dump();
    const Json response = Json::Parse(server.Handle(line));
    Require(response.Find("id")->AsNumber() == id && response.Find("jsonrpc")->AsString() == "2.0");
    return response;
}

static Json Tool(Monitor::McpServer& server, int id, const char* name, Json arguments = Json::Object()) {
    const Json response = Call(server, id, "tools/call", Json::Object({{"name", name}, {"arguments", std::move(arguments)}}));
    Require(response.Find("result") != nullptr);
    return *response.Find("result");
}

static int ErrorCode(const Json& response) {
    const Json* error = response.Find("error");
    return error == nullptr ? 0 : static_cast<int>(error->Find("code")->AsNumber());
}

static void CheckServer(Monitor::McpServer& server) {
    const Json initialized = Call(server, 1, "initialize", Json::Object({{"protocolVersion", "2025-06-18"}, {"capabilities", Json::Object()}}));
    const Json& info = *initialized.Find("result");
    Require(info.Find("protocolVersion")->AsString() == "2025-06-18" && info.Find("serverInfo")->Find("name")->AsString() == "anyps5-monitor");
    Require(info.Find("capabilities")->Find("tools") != nullptr && !info.Find("instructions")->AsString().empty());
    Require(Call(server, 2, "initialize", Json::Object({{"protocolVersion", "1999-01-01"}})).Find("result")->Find("protocolVersion")->AsString() == "2025-06-18");
    Require(server.Handle(R"({"jsonrpc":"2.0","method":"notifications/initialized"})").empty());
    Require(server.Handle("   ").empty());
    Require(Call(server, 3, "ping", Json::Object()).Find("result")->Members().empty());

    const Json listed = *Call(server, 4, "tools/list", Json::Object()).Find("result");
    std::vector<std::string> names;
    for (const Json& tool : listed.Find("tools")->Items()) {
        names.push_back(tool.Find("name")->AsString());
        Require(!tool.Find("description")->AsString().empty() && tool.Find("inputSchema")->Find("type")->AsString() == "object");
    }
    Require(names == std::vector<std::string>{"list_processes", "connect", "get_summary", "get_imports", "get_threads", "get_slow_calls", "get_frames", "get_recent_calls", "sample"});

    const Json parseError = Json::Parse(server.Handle("{oops"));
    Require(ErrorCode(parseError) == -32700 && parseError.Find("id")->IsNull());
    Require(ErrorCode(Call(server, 5, "resources/list", Json::Object())) == -32601);
    Require(ErrorCode(Call(server, 6, "tools/call", Json::Object({{"name", "missing"}}))) == -32602);
    Require(ErrorCode(Call(server, 7, "tools/call", Json::Object({{"name", "get_imports"}, {"arguments", Json::Object({{"sort_by", "nothing"}})}}))) == -32602);
    Require(ErrorCode(Call(server, 8, "tools/call", Json::Object({{"name", "get_frames"}, {"arguments", Json::Object({{"count", "many"}})}}))) == -32602);
    const Json missing = Tool(server, 9, "connect", Json::Object({{"pid", 4294967295.0}}));
    Require(missing.Find("isError")->AsBoolean() && missing.Find("content")->Items()[0].Find("text")->AsString().find("does not publish") != std::string::npos);

    const Json processes = *Tool(server, 10, "list_processes").Find("structuredContent");
    bool listedSelf = false;
    for (const Json& process : processes.Find("processes")->Items()) listedSelf = listedSelf || process.Find("pid")->AsNumber() == static_cast<double>(ProcessId());
    Require(listedSelf);
    Require(Tool(server, 11, "connect", Json::Object({{"pid", static_cast<double>(ProcessId())}})).Find("structuredContent")->Find("pid")->AsNumber() == static_cast<double>(ProcessId()));

    const Json sampled = Tool(server, 12, "sample", Json::Object({{"seconds", 1.2}}));
    Require(!sampled.Find("isError")->AsBoolean());
    const Json& sample = *sampled.Find("structuredContent");
    Require(Json::Parse(sampled.Find("content")->Items()[0].Find("text")->AsString()).Dump() == sample.Dump());
    Require(sample.Find("frames")->Find("count")->AsNumber() > 10 && sample.Find("frames")->Find("gpu_ms")->IsNull() && sample.Find("calls_profiled")->AsBoolean());
    Require(sample.Find("verdict")->Find("title")->AsString() == "Waiting in system calls");
    Require(sample.Find("imports")->Items()[0].Find("name")->AsString() == "Nap" && sample.Find("imports")->Items()[0].Find("exclusive_ms_per_s")->AsNumber() > 300);
    Require(!sample.Find("threads")->Items().empty() && !sample.Find("slow_calls")->Find("calls")->Items().empty());

    const Json summary = *Tool(server, 13, "get_summary").Find("structuredContent");
    Require(summary.Find("pid")->AsNumber() == static_cast<double>(ProcessId()) && !summary.Find("stale")->AsBoolean() && summary.Find("frames")->Find("fps")->AsNumber() > 0);

    const Json imports = *Tool(server, 14, "get_imports", Json::Object({{"sort_by", "calls"}, {"limit", 1}, {"filter", "NAP"}, {"window_seconds", 0.5}})).Find("structuredContent");
    Require(imports.Find("imports")->Items().size() == 1 && imports.Find("matching")->AsNumber() == 1 && imports.Find("window_seconds")->AsNumber() == 0.5);
    Require(Tool(server, 15, "get_imports", Json::Object({{"filter", "nothing like this"}})).Find("structuredContent")->Find("imports")->Items().empty());

    const Json slow = *Tool(server, 16, "get_slow_calls", Json::Object({{"min_ms", 5}})).Find("structuredContent");
    Require(slow.Find("threshold_us")->AsNumber() > 1900 && slow.Find("threshold_us")->AsNumber() < 2100 && !slow.Find("calls")->Items().empty());
    Require(slow.Find("calls")->Items().back().Find("caller")->AsString().starts_with("0x"));
    const double next = slow.Find("next_since")->AsNumber();
    Require(Tool(server, 17, "get_slow_calls", Json::Object({{"since", next}})).Find("structuredContent")->Find("calls")->Items().empty());

    Require(Tool(server, 18, "get_frames", Json::Object({{"count", 5}})).Find("structuredContent")->Find("frames")->Items().size() == 5);
    Require(!Tool(server, 19, "get_threads").Find("structuredContent")->Find("threads")->Items().empty());
    const Json recent = *Tool(server, 20, "get_recent_calls", Json::Object({{"limit", 3}})).Find("structuredContent");
    Require(recent.Find("calls")->Items().size() == 3 && recent.Find("calls")->Items().back().Find("name")->AsString() == "Nap");
}

static void CheckProcess(const char* monitor) {
    const auto requests = std::filesystem::temp_directory_path() / ("anyps5-monitor-mcp-" + std::to_string(ProcessId()) + ".jsonl");
    {
        std::ofstream file(requests, std::ios::binary);
        file << R"({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}})" << '\n';
        file << R"({"jsonrpc":"2.0","method":"notifications/initialized"})" << '\n';
        file << R"({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_summary"}})" << '\n';
    }
    const std::string command = "\"\"" + std::string(monitor) + "\" --mcp --pid " + std::to_string(ProcessId()) + " < \"" + requests.string() + "\"\"";
#ifdef _WIN32
    FILE* output = _popen(command.c_str(), "rb");
#else
    FILE* output = popen(command.substr(1, command.size() - 2).c_str(), "r");
#endif
    Require(output != nullptr);
    std::string text;
    char buffer[4096];
    while (std::fgets(buffer, sizeof(buffer), output) != nullptr) text += buffer;
#ifdef _WIN32
    const int status = _pclose(output);
#else
    const int status = pclose(output);
#endif
    std::filesystem::remove(requests);
    Require(status == 0 && text.find('\r') == std::string::npos);
    std::istringstream lines(text);
    std::vector<Json> responses;
    for (std::string line; std::getline(lines, line);) responses.push_back(Json::Parse(line));
    Require(responses.size() == 2 && responses[0].Find("id")->AsNumber() == 1 && responses[1].Find("id")->AsNumber() == 2);
    Require(responses[1].Find("result")->Find("structuredContent")->Find("pid")->AsNumber() == static_cast<double>(ProcessId()));
}

int main(int argc, char** argv) {
    CheckJson();
    SetVariable("APS5_TRACE_CALLS", "libTraced");
    SetVariable("APS5_PROFILE_CALLS", "3600");
    SetVariable("APS5_MONITOR_SLOW_US", "2000");
    const auto nap = reinterpret_cast<decltype(&Nap)>(TraceImport_nid_no_patch(reinterpret_cast<void*>(&Nap), "Nap", "libTraced.prx"));
    Require(TelemetryEnabled_nid_no_patch());

    std::atomic<bool> running{true};
    std::thread game([nap, &running] {
        while (running) {
            nap(10);
            const Telemetry::Present present{static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch()).count()), 0, 0, 0, 0, 0};
            TelemetryNotePresent_nid_no_patch(&present);
        }
    });

    Monitor::Session session;
    std::mutex mutex;
    Monitor::McpServer server(session, mutex, 0);
    CheckServer(server);

    std::istringstream in(R"({"jsonrpc":"2.0","id":1,"method":"ping"})" "\n" R"({"jsonrpc":"2.0","method":"notifications/initialized"})" "\n" R"({"jsonrpc":"2.0","id":2,"method":"tools/list"})" "\n");
    std::ostringstream out;
    Monitor::Session streamed;
    Require(Monitor::RunMcp(streamed, ProcessId(), in, out) == 0);
    std::istringstream lines(out.str());
    std::vector<std::string> responses;
    for (std::string line; std::getline(lines, line);) responses.push_back(line);
    Require(responses.size() == 2 && Json::Parse(responses[0]).Find("id")->AsNumber() == 1 && Json::Parse(responses[1]).Find("result")->Find("tools")->Items().size() == 9);

    if (argc == 2) CheckProcess(argv[1]);
    running = false;
    game.join();
}
