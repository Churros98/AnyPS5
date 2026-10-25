#include "Json.hpp"
#include "Mcp.hpp"
#include "Session.hpp"
#include "Snapshots.hpp"
#include "Symbols.hpp"
#include "prx/libc/include/CallTrace.hpp"
#include "prx/libc/include/Telemetry.hpp"
#include "prx/libc/include/general/ThreadName.hpp"
#include "prx/libc/include/general/VabiMacros.hpp"
#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#include <pthread.h>
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

static std::uint64_t ThreadId() {
#ifdef _WIN32
    return GetCurrentThreadId();
#else
    return static_cast<std::uint64_t>(gettid());
#endif
}

static void NameThread(const char* name) {
#ifdef _WIN32
    Require(SUCCEEDED(ThreadName::SetCurrent(name)));
#else
    Require(pthread_setname_np(pthread_self(), name) == 0);
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

template <typename TValue>
static void Put(std::vector<char>& image, std::size_t offset, TValue value) {
    std::memcpy(image.data() + offset, &value, sizeof(value));
}

static void CheckSymbols() {
    constexpr std::size_t Raw = 0x400;
    constexpr std::uint32_t Text = 0x1000;
    const auto file = [](std::uint32_t rva) { return Raw + (rva - Text); };
    std::vector<char> image(Raw + 0x2000, 0);
    Put<std::uint16_t>(image, 0, 0x5a4d);
    Put<std::uint32_t>(image, 0x3c, 0x40);
    Put<std::uint32_t>(image, 0x40, 0x4550);
    Put<std::uint16_t>(image, 0x44, 0x8664);
    Put<std::uint16_t>(image, 0x46, 1);
    Put<std::uint16_t>(image, 0x54, 240);
    Put<std::uint16_t>(image, 0x58, 0x20b);
    Put<std::uint32_t>(image, 0x58 + 112, 0x2000);
    Put<std::uint32_t>(image, 0x58 + 116, 0x80);
    Put<std::uint32_t>(image, 0x58 + 136, 0x2100);
    Put<std::uint32_t>(image, 0x58 + 140, 36);
    std::memcpy(image.data() + 0x148, ".text", 5);
    Put<std::uint32_t>(image, 0x148 + 8, 0x2000);
    Put<std::uint32_t>(image, 0x148 + 12, Text);
    Put<std::uint32_t>(image, 0x148 + 16, 0x2000);
    Put<std::uint32_t>(image, 0x148 + 20, Raw);
    Put<std::uint32_t>(image, 0x148 + 36, 0x60000020);
    Put<std::uint32_t>(image, file(0x2000) + 20, 2);
    Put<std::uint32_t>(image, file(0x2000) + 24, 2);
    Put<std::uint32_t>(image, file(0x2000) + 28, 0x2040);
    Put<std::uint32_t>(image, file(0x2000) + 32, 0x2050);
    Put<std::uint32_t>(image, file(0x2000) + 36, 0x2060);
    Put<std::uint32_t>(image, file(0x2040), 0x1000);
    Put<std::uint32_t>(image, file(0x2044), 0x1400);
    Put<std::uint32_t>(image, file(0x2050), 0x2070);
    Put<std::uint32_t>(image, file(0x2054), 0x2080);
    Put<std::uint16_t>(image, file(0x2060), 0);
    Put<std::uint16_t>(image, file(0x2062), 1);
    std::memcpy(image.data() + file(0x2070), "Exported", 8);
    std::memcpy(image.data() + file(0x2080), "Leaf", 4);
    const std::uint32_t functions[][3] = {{0x1000, 0x1010, 0x2200}, {0x1100, 0x1180, 0x2210}, {0x1180, 0x11a0, 0x2220}};
    for (std::size_t index = 0; index < 3; ++index) {
        for (std::size_t field = 0; field < 3; ++field) Put<std::uint32_t>(image, file(0x2100) + index * 12 + field * 4, functions[index][field]);
    }
    Put<std::uint8_t>(image, file(0x2200), 1);
    Put<std::uint8_t>(image, file(0x2210), 1);
    Put<std::uint8_t>(image, file(0x2220), 1 | (4 << 3));
    Put<std::uint32_t>(image, file(0x2224), 0x1100);
    Put<std::uint32_t>(image, file(0x2228), 0x1180);
    Put<std::uint32_t>(image, file(0x222c), 0x2210);
    const auto path = std::filesystem::temp_directory_path() / ("anyps5-monitor-image-" + std::to_string(ProcessId()) + ".dll");
    std::ofstream(path, std::ios::binary).write(image.data(), static_cast<std::streamsize>(image.size()));
    std::string error;
    const Monitor::PeImage parsed = Monitor::Symbols::ReadPeImage(path.string(), error);
    std::filesystem::remove(path);
    Require(error.empty() && parsed.functions.size() == 2 && parsed.ranges.size() == 3 && parsed.ranges[2].start == 0x1100);
    const Monitor::Location exported = Monitor::Symbols::Locate(parsed, 0x1005);
    Require(exported.function == "Exported" && exported.functionOffset == 5 && exported.functionStart == 0x1000);
    const Monitor::Location inner = Monitor::Symbols::Locate(parsed, 0x1150);
    Require(inner.function.empty() && inner.functionStart == 0x1100);
    const Monitor::Location chained = Monitor::Symbols::Locate(parsed, 0x1190);
    Require(chained.function.empty() && chained.functionStart == 0x1100);
    const Monitor::Location gap = Monitor::Symbols::Locate(parsed, 0x1050);
    Require(gap.function.empty() && !gap.functionStart);
    const Monitor::Location leaf = Monitor::Symbols::Locate(parsed, 0x1450);
    Require(leaf.function == "Leaf" && leaf.functionOffset == 0x50 && !leaf.functionStart);
    Monitor::Location named = chained;
    named.module = "test.dll";
    Require(Monitor::FormatLocation(named) == "test.dll+0x1190 (function at +0x1100)");
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
    Require(names == std::vector<std::string>{"list_processes", "connect", "get_summary", "get_imports", "get_threads", "get_slow_calls", "get_frames", "get_recent_calls", "sample", "resolve_address",
        "list_modules", "sample_stacks", "watch_import", "get_watched_calls", "get_driver_phases", "get_driver_report", "set_slow_threshold", "save_snapshot", "list_snapshots", "compare_snapshots", "list_memory_regions",
        "read_memory", "search_memory"});

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

[[gnu::noinline]] static std::uint64_t APS5_VABI Outer(std::uint64_t value) {
    return value * 3 + 1;
}

static std::string ModuleName() {
#ifdef _WIN32
    char path[MAX_PATH];
    Require(GetModuleFileNameA(nullptr, path, sizeof(path)) != 0);
    return std::filesystem::path(path).filename().string();
#else
    return std::filesystem::read_symlink("/proc/self/exe").filename().string();
#endif
}

static std::uint64_t ModuleBase() {
#ifdef _WIN32
    return reinterpret_cast<std::uint64_t>(GetModuleHandleA(nullptr));
#else
    Dl_info info{};
    Require(dladdr(reinterpret_cast<const void*>(&Outer), &info) != 0);
    return reinterpret_cast<std::uint64_t>(info.dli_fbase);
#endif
}

static std::string Hex(std::uint64_t value) {
    char buffer[24];
    std::snprintf(buffer, sizeof(buffer), "0x%llx", static_cast<unsigned long long>(value));
    return buffer;
}

static std::filesystem::path g_stackFile;

static bool FakeSampler(std::uint64_t, std::uint64_t, std::uint64_t, char* message, std::size_t capacity) {
    const std::string module = ModuleName();
    const std::uint64_t base = ModuleBase();
    const std::string outer = module + "+" + Hex(reinterpret_cast<std::uint64_t>(&Outer) - base + 1);
    const std::string leaf = module + "+" + Hex(reinterpret_cast<std::uint64_t>(&Nap) - base + 1);
    std::ofstream file(g_stackFile, std::ios::binary);
    file << "# rounds=10 threads=1 interval_us=1000 depth=4 duration_ms=10\n";
    file << "# module " << module << " " << Hex(base) << " 0x1000\n";
    file << "thread-77;[truncated];" << outer << ";" << leaf << " 7\n";
    file << "thread-77;" << outer << " 3\n";
    file << "thread-78;" << outer << " 5\n";
#ifdef _WIN32
    const HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    const auto wait = reinterpret_cast<std::uint64_t>(reinterpret_cast<void*>(GetProcAddress(ntdll, "NtWaitForSingleObject")));
    file << "thread-79;" << outer << ";ntdll.dll+" << Hex(wait - reinterpret_cast<std::uint64_t>(ntdll) + 4) << " 4\n";
#endif
    std::snprintf(message, capacity, "%s", g_stackFile.string().c_str());
    return true;
}

static bool HasText(const Json& value, const char* field, const char* part) {
    const Json* text = value.Find(field);
    return text != nullptr && text->Type() == Json::Kind::String && text->AsString().find(part) != std::string::npos;
}

static void CheckAgentTools(Monitor::McpServer& server) {
    const std::string module = ModuleName();
    const std::uint64_t base = ModuleBase();

    const Json modules = *Tool(server, 30, "list_modules", Json::Object({{"filter", module}})).Find("structuredContent");
    Require(modules.Find("modules")->Items().size() == 1 && std::strtoull(modules.Find("modules")->Items()[0].Find("base")->AsString().c_str(), nullptr, 16) == base);
    const std::string napAddress = Hex(reinterpret_cast<std::uint64_t>(&Nap) + 2);
    const std::string napOffset = module + "+" + Hex(reinterpret_cast<std::uint64_t>(&Nap) - base + 2);
    Json addresses = Json::Array();
    addresses.Push(napAddress);
    addresses.Push(napOffset);
    const Json located = Tool(server, 32, "resolve_address", Json::Object({{"addresses", addresses}}));
    Require(!located.Find("isError")->AsBoolean());
    for (const Json& entry : located.Find("structuredContent")->Find("addresses")->Items()) {
        Require(entry.Find("module")->AsString() == module && entry.Find("offset")->AsString().ends_with(Hex(reinterpret_cast<std::uint64_t>(&Nap) - base + 2).substr(2)));
#ifdef _WIN32
        Require(HasText(entry, "function", "Nap") && entry.Find("function_offset")->AsString() == "0x0000000000000002");
#endif
    }
    Require(ErrorCode(Call(server, 33, "tools/call", Json::Object({{"name", "resolve_address"}, {"arguments", Json::Object({{"addresses", Json::Array()}})}}))) == -32602);
    Json nowhere = Json::Array();
    nowhere.Push("nowhere.prx+0x10");
    Require(ErrorCode(Call(server, 34, "tools/call", Json::Object({{"name", "resolve_address"}, {"arguments", Json::Object({{"addresses", nowhere}})}}))) == -32602);

    const Json noSampler = Tool(server, 35, "sample_stacks", Json::Object({{"milliseconds", 10}}));
    Require(noSampler.Find("isError")->AsBoolean() && HasText(*noSampler.Find("content")->Items().begin(), "text", "no stack sampler"));
    g_stackFile = std::filesystem::temp_directory_path() / ("anyps5-monitor-mcp-stacks-" + std::to_string(ProcessId()) + ".txt");
    TelemetryRegisterStackSampler_nid_no_patch(&FakeSampler);
    const Json stacks = *Tool(server, 36, "sample_stacks", Json::Object({{"milliseconds", 10}, {"top", 3}})).Find("structuredContent");
    std::filesystem::remove(g_stackFile);
    Require(stacks.Find("samples")->AsNumber() == 15 && stacks.Find("threads")->Items().size() == 2);
#ifdef _WIN32
    Require(stacks.Find("waiting_samples_left_out")->AsNumber() == 4);
    const Json withWaits = *Tool(server, 64, "sample_stacks", Json::Object({{"milliseconds", 10}, {"include_waits", true}})).Find("structuredContent");
    std::filesystem::remove(g_stackFile);
    Require(withWaits.Find("samples")->AsNumber() == 19 && withWaits.Find("waiting_samples_left_out")->AsNumber() == 0 && withWaits.Find("threads")->Items().size() == 3);
#endif
    Require(stacks.Find("self")->Items()[0].Find("samples")->AsNumber() == 8 && stacks.Find("inclusive")->Items()[0].Find("samples")->AsNumber() == 15);
    Require(stacks.Find("stacks")->Items()[0].Find("samples")->AsNumber() == 7 && stacks.Find("stacks")->Items()[0].Find("frames_leaf_first")->Items().size() == 2);
#ifdef _WIN32
    Require(HasText(stacks.Find("self")->Items()[0], "function", "Outer") && HasText(stacks.Find("self")->Items()[1], "function", "Nap"));
    Require(HasText(stacks.Find("inclusive")->Items()[0], "function", "Outer"));
#endif
    const Json filtered = *Tool(server, 37, "sample_stacks", Json::Object({{"milliseconds", 10}, {"thread", 78}})).Find("structuredContent");
    std::filesystem::remove(g_stackFile);
    Require(filtered.Find("samples")->AsNumber() == 5);
    Require(ErrorCode(Call(server, 38, "tools/call", Json::Object({{"name", "sample_stacks"}, {"arguments", Json::Object({{"depth", 65}})}}))) == -32602);

    Require(Tool(server, 39, "watch_import", Json::Object({{"import", "Missing"}})).Find("isError")->AsBoolean());
    Require(ErrorCode(Call(server, 40, "tools/call", Json::Object({{"name", "watch_import"}, {"arguments", Json::Object({{"import", "Nap"}, {"count", 2000}})}}))) == -32602);
    const Json watching = *Tool(server, 41, "watch_import", Json::Object({{"import", "Nap"}, {"count", 3}})).Find("structuredContent");
    Require(HasText(watching, "message", "watching the next 3 calls"));
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    Json watched;
    do {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        watched = *Tool(server, 42, "get_watched_calls").Find("structuredContent");
    } while (watched.Find("calls")->Items().size() < 3 && std::chrono::steady_clock::now() < deadline);
    Require(watched.Find("calls")->Items().size() == 3);
    for (const Json& call : watched.Find("calls")->Items()) {
        Require(call.Find("import")->AsString() == "Nap" && call.Find("arguments")->Items()[0].AsString() == "0x000000000000000a" && call.Find("ms")->AsNumber() >= 9);
        Require(call.Find("caller")->Find("module")->AsString() == module);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    Require(Tool(server, 43, "get_watched_calls", Json::Object({{"since", watched.Find("next_since")->AsNumber()}})).Find("structuredContent")->Find("calls")->Items().empty());

    const Json noPhases = *Tool(server, 44, "get_driver_phases").Find("structuredContent");
    Require(noPhases.Find("phases")->Items().empty() && HasText(noPhases, "note", "APS5_TRACE_SUMMARY_EVERY"));
    const Telemetry::PhaseTotal first[] = {{"queue 0", "Driver.Packet", "draw", 1000000, 10, ThreadId()}, {"presenter", "Driver.Present", "", 2000000, 4, 0}};
    TelemetryPublishPhases_nid_no_patch(first, 2);
    std::this_thread::sleep_for(std::chrono::milliseconds(250));
    Require(!Tool(server, 63, "get_summary").Find("isError")->AsBoolean());
    const Telemetry::PhaseTotal second[] = {{"queue 0", "Driver.Packet", "draw", 301000000, 110, ThreadId()}, {"presenter", "Driver.Present", "", 2000000, 4, 0}};
    TelemetryPublishPhases_nid_no_patch(second, 2);
    std::this_thread::sleep_for(std::chrono::milliseconds(700));
    const Json phases = *Tool(server, 45, "get_driver_phases", Json::Object({{"filter", "queue"}})).Find("structuredContent");
    Require(phases.Find("phases")->Items().size() == 1);
    const Json& packet = phases.Find("phases")->Items()[0];
    Require(packet.Find("phase")->AsString() == "Driver.Packet.draw" && packet.Find("thread")->AsString() == "queue 0" && packet.Find("total_ms")->AsNumber() == 301 && packet.Find("count")->AsNumber() == 110);
    Require(packet.Find("thread_id")->AsNumber() == static_cast<double>(ThreadId()) && packet.Find("thread_name")->AsString() == "monitor mcp");
    Require(Tool(server, 64, "get_driver_phases", Json::Object({{"filter", "monitor mcp"}})).Find("structuredContent")->Find("phases")->Items().size() == 1);
    Require(packet.Find("ms_per_s")->AsNumber() > 100 && packet.Find("average_us")->AsNumber() > 2999 && packet.Find("average_us")->AsNumber() < 3001);

    const Json noReports = *Tool(server, 90, "get_driver_report").Find("structuredContent");
    Require(noReports.Find("reports")->Items().empty() && HasText(noReports, "note", "APS5_PROFILE_DRAW"));
    TelemetryPublishReport_nid_no_patch("[recipe] draw (10 s): hits 7; attaches 3");
    TelemetryPublishReport_nid_no_patch("[draws] 5 draws");
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    const Json reports = *Tool(server, 91, "get_driver_report", Json::Object({{"filter", "recipe"}})).Find("structuredContent");
    Require(reports.Find("reports")->Items().size() == 1);
    const Json& recipe = reports.Find("reports")->Items()[0];
    Require(recipe.Find("tag")->AsString() == "[recipe] draw" && recipe.Find("line")->AsString() == "[recipe] draw (10 s): hits 7; attaches 3" && recipe.Find("updates")->AsNumber() == 1 && recipe.Find("age_s")->AsNumber() < 5);
    Require(Tool(server, 92, "get_driver_report").Find("structuredContent")->Find("reports")->Items().size() == 2);

    const Json threshold = *Tool(server, 46, "set_slow_threshold", Json::Object({{"microseconds", 5000}})).Find("structuredContent");
    Require(threshold.Find("threshold_us")->AsNumber() == 5000 && threshold.Find("threshold_ticks")->AsNumber() > 0);
    const double slowUs = Tool(server, 47, "get_slow_calls").Find("structuredContent")->Find("threshold_us")->AsNumber();
    Require(slowUs > 4900 && slowUs < 5100);
    Require(ErrorCode(Call(server, 48, "tools/call", Json::Object({{"name", "set_slow_threshold"}, {"arguments", Json::Object()}}))) == -32602);

    const std::string before = "mcp-test-" + std::to_string(ProcessId()) + "-before";
    const std::string after = "mcp-test-" + std::to_string(ProcessId()) + "-after";
    Require(Tool(server, 49, "save_snapshot", Json::Object({{"name", before}, {"note", "test"}})).Find("structuredContent")->Find("imports")->AsNumber() >= 1);
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    Require(!Tool(server, 50, "save_snapshot", Json::Object({{"name", after}})).Find("isError")->AsBoolean());
    Require(ErrorCode(Call(server, 51, "tools/call", Json::Object({{"name", "save_snapshot"}, {"arguments", Json::Object({{"name", "../escape"}})}}))) == -32602);
    std::size_t listedSnapshots = 0;
    const Json snapshots = Tool(server, 52, "list_snapshots");
    for (const Json& snapshot : snapshots.Find("structuredContent")->Find("snapshots")->Items()) {
        if (snapshot.Find("name")->AsString() == before || snapshot.Find("name")->AsString() == after) ++listedSnapshots;
    }
    Require(listedSnapshots == 2);
    const Json compared = *Tool(server, 53, "compare_snapshots", Json::Object({{"before", before}, {"after", after}})).Find("structuredContent");
    Require(compared.Find("frames")->Find("fps")->Find("before")->AsNumber() > 0 && compared.Find("frames")->Find("fps")->Find("after")->AsNumber() > 0);
    Require(compared.Find("imports")->Items()[0].Find("name")->AsString() == "Nap" && compared.Find("imports")->Items()[0].Find("exclusive_ms_per_s")->Find("change") != nullptr);
    Require(Tool(server, 54, "compare_snapshots", Json::Object({{"before", before}, {"after", "mcp-test-missing"}})).Find("isError")->AsBoolean());
    std::filesystem::remove(Monitor::SnapshotDirectory() / (before + ".json"));
    std::filesystem::remove(Monitor::SnapshotDirectory() / (after + ".json"));

    static std::uint32_t values[4] = {1, 2, 3, 4};
    const std::string needle = "needle-" + std::to_string(ProcessId() * 7919 + 13);
    std::vector<char> buffer(needle.begin(), needle.end());
    buffer.push_back('\0');
    const auto bufferAddress = reinterpret_cast<std::uint64_t>(buffer.data());
    const Json regions = *Tool(server, 55, "list_memory_regions", Json::Object({{"limit", 100000}})).Find("structuredContent");
    bool covered = false;
    for (const Json& region : regions.Find("regions")->Items()) {
        const std::uint64_t start = std::strtoull(region.Find("base")->AsString().c_str(), nullptr, 16);
        covered = covered || (bufferAddress >= start && bufferAddress < start + static_cast<std::uint64_t>(region.Find("size")->AsNumber()));
    }
    Require(covered && regions.Find("committed_bytes")->AsNumber() > 0);
    Require(!Tool(server, 56, "list_memory_regions", Json::Object({{"module", module}})).Find("structuredContent")->Find("regions")->Items().empty());
    const Json text = *Tool(server, 57, "read_memory", Json::Object({{"address", Hex(bufferAddress)}, {"size", static_cast<double>(buffer.size())}, {"as", "string"}})).Find("structuredContent");
    Require(text.Find("value")->AsString() == needle && text.Find("read")->AsNumber() == static_cast<double>(buffer.size()) && text.Find("hex")->Items()[0].AsString().find("6e 65 65 64") != std::string::npos);
    const Json numbers = *Tool(server, 58, "read_memory", Json::Object({{"address", Hex(reinterpret_cast<std::uint64_t>(values))}, {"size", 16}, {"as", "u32"}})).Find("structuredContent");
    Require(numbers.Find("values")->Items().size() == 4 && numbers.Find("values")->Items()[3].AsNumber() == 4);
    Require(Tool(server, 59, "read_memory", Json::Object({{"address", "0x10"}, {"size", 16}})).Find("structuredContent")->Find("read")->AsNumber() == 0);
    const Json search = *Tool(server, 60, "search_memory", Json::Object({{"value", needle}, {"limit", 1000}, {"max_mb", 16384}})).Find("structuredContent");
    bool foundBuffer = false;
    for (const Json& match : search.Find("matches")->Items()) foundBuffer = foundBuffer || std::strtoull(match.Find("address")->AsString().c_str(), nullptr, 16) == bufferAddress;
    Require(foundBuffer);
    const Json integers = *Tool(server, 61, "search_memory", Json::Object({{"value", "0x0000000300000002"}, {"type", "u64"}, {"limit", 1000}, {"max_mb", 16384}})).Find("structuredContent");
    bool foundValues = false;
    for (const Json& match : integers.Find("matches")->Items()) foundValues = foundValues || std::strtoull(match.Find("address")->AsString().c_str(), nullptr, 16) == reinterpret_cast<std::uint64_t>(&values[1]);
    Require(foundValues);
    Require(ErrorCode(Call(server, 62, "tools/call", Json::Object({{"name", "search_memory"}, {"arguments", Json::Object({{"value", "zz"}, {"type", "bytes"}})}}))) == -32602);
    Require(Outer(1) == 4);
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
    NameThread("monitor mcp");
    CheckJson();
    CheckSymbols();
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
    CheckAgentTools(server);

    std::istringstream in(R"({"jsonrpc":"2.0","id":1,"method":"ping"})" "\n" R"({"jsonrpc":"2.0","method":"notifications/initialized"})" "\n" R"({"jsonrpc":"2.0","id":2,"method":"tools/list"})" "\n");
    std::ostringstream out;
    Monitor::Session streamed;
    Require(Monitor::RunMcp(streamed, ProcessId(), in, out) == 0);
    std::istringstream lines(out.str());
    std::vector<std::string> responses;
    for (std::string line; std::getline(lines, line);) responses.push_back(line);
    Require(responses.size() == 2 && Json::Parse(responses[0]).Find("id")->AsNumber() == 1 && Json::Parse(responses[1]).Find("result")->Find("tools")->Items().size() == 23);

    if (argc == 2) CheckProcess(argv[1]);
    running = false;
    game.join();
}
