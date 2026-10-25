#include "Mcp.hpp"
#include "Paths.hpp"
#include "Snapshots.hpp"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <istream>
#include <map>
#include <ostream>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <vector>

namespace Monitor {

namespace {

constexpr const char* ProtocolVersion = "2025-06-18";
constexpr const char* SupportedVersions[] = {"2025-06-18", "2025-03-26", "2024-11-05"};
constexpr auto PollInterval = std::chrono::milliseconds(50);

constexpr const char* Instructions =
    "Reads the performance telemetry of AnyPS5 titles running on this machine. The title must run with a build configured with "
    "-DAPS5_ENABLE_PROFILER=ON; import timings also need an executable converted with --trace-imports and APS5_PROFILE_CALLS "
    "unset or above 0, GPU time needs APS5_PROFILE_GPU=1 and agc driver time APS5_PROFILE_DRAW=1. "
    "Start with get_summary, then get_imports and get_slow_calls to find what fills the frame. When the time is not in imports, "
    "sample_stacks shows the hottest game and library functions. watch_import records the arguments of a suspicious import, "
    "get_driver_phases splits the agc driver time (needs APS5_TRACE_SUMMARY_EVERY), get_driver_report reads the agc driver's "
    "[recipe], [draws] and other report lines (needs APS5_PROFILE_DRAW), resolve_address names callers, and "
    "save_snapshot with compare_snapshots measures a change between two runs. Memory tools only read. Import names are NIDs "
    "when the monitor finds no NID database.";

class InvalidParameters : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class ToolFailure : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

double Number(const Json& arguments, std::string_view name, double fallback, double minimum, double maximum) {
    const Json* value = arguments.Find(name);
    if (value == nullptr || value->IsNull()) return fallback;
    if (value->Type() != Json::Kind::Number) throw InvalidParameters(std::string(name) + " must be a number");
    const double number = value->AsNumber();
    if (number < minimum || number > maximum) throw InvalidParameters(std::string(name) + " must be from " + std::to_string(minimum) + " to " + std::to_string(maximum));
    return number;
}

std::string Text(const Json& arguments, std::string_view name, std::string fallback) {
    const Json* value = arguments.Find(name);
    if (value == nullptr || value->IsNull()) return fallback;
    if (value->Type() != Json::Kind::String) throw InvalidParameters(std::string(name) + " must be a string");
    return value->AsString();
}

std::string Lower(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char character) { return static_cast<char>(character >= 'A' && character <= 'Z' ? character - 'A' + 'a' : character); });
    return text;
}

bool Matches(const std::string& filter, std::initializer_list<std::string_view> fields) {
    if (filter.empty()) return true;
    const std::string needle = Lower(filter);
    for (const std::string_view field : fields) {
        if (Lower(std::string(field)).find(needle) != std::string::npos) return true;
    }
    return false;
}

std::string Address(std::uint64_t address) {
    char buffer[24];
    std::snprintf(buffer, sizeof(buffer), "0x%016llx", static_cast<unsigned long long>(address));
    return buffer;
}

Json Strings(std::initializer_list<const char*> values) {
    Json array = Json::Array();
    for (const char* value : values) array.Push(value);
    return array;
}

Json Property(const char* type, const char* description) {
    return Json::Object({{"type", type}, {"description", description}});
}

Json Tool(const char* name, const char* description, Json properties) {
    return Json::Object({{"name", name}, {"description", description}, {"inputSchema", Json::Object({{"type", "object"}, {"properties", std::move(properties)}})}});
}

Json ToolList() {
    Json tools = Json::Array();
    tools.Push(Tool("list_processes", "List the processes on this machine that publish AnyPS5 telemetry, and which one the monitor reads.", Json::Object()));
    tools.Push(Tool("connect", "Read the telemetry of one process. Without pid, the only publishing process is chosen.", Json::Object({{"pid", Property("integer", "process id from list_processes")}})));
    tools.Push(Tool("get_summary", "Frame rate, frame time percentiles, GPU and agc driver time per frame and a verdict on what fills the frame, over the last second.", Json::Object()));
    tools.Push(Tool("get_imports", "Traced system library imports with exclusive and inclusive milliseconds per second, calls per second and per-call times over a sliding window.",
        Json::Object({{"sort_by", Json::Object({{"type", "string"}, {"enum", Strings({"exclusive", "inclusive", "calls", "average", "p99", "max", "total"})}, {"description", "column to sort by, default exclusive"}})},
            {"limit", Property("integer", "rows to return, 1 to 4096, default 20")},
            {"filter", Property("string", "case-insensitive part of the import name, NID or library")},
            {"window_seconds", Property("number", "rate window, 0.2 to 30 seconds, default 1")}})));
    tools.Push(Tool("get_threads", "Milliseconds per second each thread spends in traced imports, outside nested traced calls.", Json::Object({{"limit", Property("integer", "rows to return, default 32")}})));
    tools.Push(Tool("get_slow_calls", "Timed calls longer than APS5_MONITOR_SLOW_US, newest last. Pass the returned next_since to get only newer calls.",
        Json::Object({{"since", Property("integer", "index returned as next_since by the previous call, default 0")}, {"min_ms", Property("number", "shortest call to return, default 0")},
            {"limit", Property("integer", "newest calls to return, default 50")}, {"filter", Property("string", "case-insensitive part of the import name")}})));
    tools.Push(Tool("get_frames", "The intervals between the last presents with the GPU and agc driver time, draws and dispatches of each.", Json::Object({{"count", Property("integer", "frames to return, 1 to 1024, default 120")}})));
    tools.Push(Tool("get_recent_calls", "The newest traced calls with their thread and caller address.", Json::Object({{"limit", Property("integer", "calls to return, 1 to 64, default 64")}})));
    tools.Push(Tool("sample", "Measure for a number of seconds, then return the summary, the busiest imports and threads and the slow calls of the sample.",
        Json::Object({{"seconds", Property("number", "length of the sample, 0.2 to 30, default 2")}, {"limit", Property("integer", "import rows, default 15")}})));
    tools.Push(Tool("resolve_address", "Name the module, offset and nearest function of addresses of the connected process, such as callers of slow calls.",
        Json::Object({{"addresses", Json::Object({{"type", "array"}, {"items", Json::Object({{"type", "string"}})}, {"description", "addresses as 0x... or module+0x..."}})}})));
    tools.Push(Tool("list_modules", "Modules loaded in the connected process with their base, size and path.", Json::Object({{"filter", Property("string", "case-insensitive part of the name")}})));
    tools.Push(Tool("sample_stacks", "Sample the stacks of every thread of the title (agc driver on Windows) and return the hottest functions, by own and total samples, and the hottest stacks.",
        Json::Object({{"milliseconds", Property("integer", "length, 1 to 30000, default 2000")}, {"interval_us", Property("integer", "time between rounds, 100 to 100000, default 1000")},
            {"depth", Property("integer", "frames per stack, 1 to 64, default 32")}, {"top", Property("integer", "rows per list, default 15")}, {"thread", Property("integer", "keep only this thread")},
            {"include_waits", Property("boolean", "keep the samples of threads blocked in a system wait, default false")}})));
    tools.Push(Tool("watch_import", "Record the arguments (rdi, rsi, rdx, rcx, r8, r9), return value, duration and caller of the next calls of a timed import.",
        Json::Object({{"import", Property("string", "import name, NID or display name")}, {"count", Property("integer", "calls to record, 0 to 1024, default 16; 0 stops")}})));
    tools.Push(Tool("get_watched_calls", "Calls recorded by watch_import, newest last; pass next_since to get only newer calls.",
        Json::Object({{"since", Property("integer", "next_since of the previous call, default 0")}, {"limit", Property("integer", "calls to return, default 50")}, {"filter", Property("string", "part of the import name")}})));
    tools.Push(Tool("get_driver_phases", "agc driver PerformanceTimer scopes per thread with milliseconds per second and mean duration; needs APS5_TRACE_SUMMARY_EVERY.",
        Json::Object({{"limit", Property("integer", "rows, default 30")}, {"filter", Property("string", "part of the thread or scope name")}})));
    tools.Push(Tool("get_driver_report", "Latest line of each agc driver report ([recipe] draw, [draws], [pipecache] and others), one per tag, with its age; most print every 10 s with APS5_PROFILE_DRAW=1.",
        Json::Object({{"filter", Property("string", "part of the tag or of the line")}, {"limit", Property("integer", "rows, default 64")}})));
    tools.Push(Tool("set_slow_threshold", "Change the duration from which timed calls are published as slow calls.", Json::Object({{"microseconds", Property("integer", "1 to 60000000")}})));
    tools.Push(Tool("save_snapshot", "Store the current summary, import, thread and driver phase rates under a name, to compare runs before and after a change.",
        Json::Object({{"name", Property("string", "letters, digits, '-', '_' or '.'")}, {"note", Property("string", "what the run is, such as the commit or the switches")}})));
    tools.Push(Tool("list_snapshots", "Stored snapshots, oldest first.", Json::Object()));
    tools.Push(Tool("compare_snapshots", "Frame time changes and the imports, driver phases and threads that changed most between two snapshots.",
        Json::Object({{"before", Property("string", "snapshot name")}, {"after", Property("string", "snapshot name")}, {"limit", Property("integer", "rows per list, default 15")}})));
    tools.Push(Tool("list_memory_regions", "Committed memory regions of the connected process with protection, type and module. Read only.",
        Json::Object({{"module", Property("string", "keep only this module")}, {"readable_only", Property("boolean", "default true")}, {"min_size", Property("integer", "smallest region in bytes")},
            {"limit", Property("integer", "rows, default 200")}})));
    tools.Push(Tool("read_memory", "Read memory of the connected process as hex and ASCII, and optionally as values. Read only.",
        Json::Object({{"address", Property("string", "0x... or module+0x...")}, {"size", Property("integer", "bytes, 1 to 65536, default 256")},
            {"as", Json::Object({{"type", "string"}, {"enum", Strings({"hex", "u8", "u16", "u32", "u64", "i32", "i64", "f32", "f64", "pointer", "string", "utf16"})}, {"description", "default hex"}})}})));
    tools.Push(Tool("search_memory", "Find a value in the readable memory of the connected process. Read only.",
        Json::Object({{"value", Property("string", "value to find; hex bytes such as 'de ad be ef' for bytes")},
            {"type", Json::Object({{"type", "string"}, {"enum", Strings({"bytes", "string", "utf16", "u32", "u64", "i32", "i64", "f32", "f64"})}, {"description", "default string"}})},
            {"module", Property("string", "search only regions of this module")}, {"limit", Property("integer", "matches, default 50")}, {"max_mb", Property("integer", "bytes to scan, default 256")}})));
    return tools;
}

Json Response(const Json& id, Json result) {
    return Json::Object({{"jsonrpc", "2.0"}, {"id", id}, {"result", std::move(result)}});
}

Json Error(const Json& id, int code, const std::string& message) {
    return Json::Object({{"jsonrpc", "2.0"}, {"id", id}, {"error", Json::Object({{"code", code}, {"message", message}})}});
}

Json ToolResult(const Json& value, bool failed) {
    Json content = Json::Array();
    content.Push(Json::Object({{"type", "text"}, {"text", failed ? value.AsString() : value.Dump()}}));
    Json result = Json::Object({{"content", std::move(content)}, {"isError", failed}});
    if (!failed) result.Set("structuredContent", value);
    return result;
}

Json ImportRow(const Session& session, const ImportRate& rate) {
    return Json::Object({{"name", rate.name}, {"display_name", session.DisplayName(rate.name)}, {"library", rate.library}, {"calls", rate.calls}, {"timed_calls", rate.timedCalls},
        {"exclusive_ms_per_s", rate.exclusiveMsPerSecond}, {"inclusive_ms_per_s", rate.inclusiveMsPerSecond}, {"calls_per_s", rate.callsPerSecond}, {"average_us", rate.averageUs},
        {"p50_us", rate.p50Us}, {"p99_us", rate.p99Us}, {"max_us", rate.maxUs}, {"total_exclusive_ms", rate.totalExclusiveMs}});
}

}

McpServer::McpServer(Session& session, std::mutex& mutex, std::uint64_t pid) : _session(session), _mutex(mutex), _pid(pid) {}

std::string McpServer::Handle(const std::string& line) {
    if (line.find_first_not_of(" \t\r\n") == std::string::npos) return {};
    Json message;
    try {
        message = Json::Parse(line);
    } catch (const std::exception& error) {
        return Error(Json(), -32700, error.what()).Dump();
    }
    const Json* id = message.Find("id");
    const Json* method = message.Find("method");
    if (method == nullptr || method->Type() != Json::Kind::String) {
        if (id == nullptr) return {};
        return Error(*id, -32600, "a request needs a method").Dump();
    }
    if (id == nullptr) return {};
    try {
        return Response(*id, handleRequest(method->AsString(), message.Find("params"))).Dump();
    } catch (const InvalidParameters& error) {
        return Error(*id, -32602, error.what()).Dump();
    } catch (const std::invalid_argument& error) {
        return Error(*id, -32602, error.what()).Dump();
    } catch (const std::out_of_range& error) {
        return Error(*id, -32601, error.what()).Dump();
    }
}

Json McpServer::handleRequest(const std::string& method, const Json* parameters) {
    const Json empty = Json::Object();
    const Json& arguments = parameters != nullptr && parameters->Type() == Json::Kind::Object ? *parameters : empty;
    if (method == "initialize") {
        const std::string requested = Text(arguments, "protocolVersion", ProtocolVersion);
        const bool supported = std::find(std::begin(SupportedVersions), std::end(SupportedVersions), requested) != std::end(SupportedVersions);
        return Json::Object({{"protocolVersion", supported ? requested : ProtocolVersion}, {"capabilities", Json::Object({{"tools", Json::Object({{"listChanged", false}})}})},
            {"serverInfo", Json::Object({{"name", "anyps5-monitor"}, {"version", "1"}})}, {"instructions", Instructions}});
    }
    if (method == "ping") return Json::Object();
    if (method == "tools/list") return Json::Object({{"tools", ToolList()}});
    if (method == "tools/call") {
        const std::string name = Text(arguments, "name", "");
        const Json* given = arguments.Find("arguments");
        const Json& toolArguments = given != nullptr && given->Type() == Json::Kind::Object ? *given : empty;
        const Json tools = ToolList();
        if (std::none_of(tools.Items().begin(), tools.Items().end(), [&name](const Json& tool) { return tool.Find("name")->AsString() == name; })) throw InvalidParameters("unknown tool " + name);
        try {
            return ToolResult(callTool(name, toolArguments), false);
        } catch (const InvalidParameters&) {
            throw;
        } catch (const std::invalid_argument&) {
            throw;
        } catch (const std::exception& error) {
            return ToolResult(Json(error.what()), true);
        }
    }
    throw std::out_of_range("unknown method " + method);
}

void McpServer::ensureConnected() {
    if (_session.Connected()) return;
    if (_pid != 0) {
        if (!_session.Connect(_pid)) throw ToolFailure("process " + std::to_string(_pid) + " does not publish telemetry");
        return;
    }
    const auto found = Session::Discover();
    if (found.empty()) throw ToolFailure("no process publishes telemetry: run the title from a build configured with -DAPS5_ENABLE_PROFILER=ON");
    if (found.size() > 1) throw ToolFailure("several processes publish telemetry: call connect with one pid from list_processes");
    if (!_session.Connect(found.front())) throw ToolFailure("cannot open the telemetry of process " + std::to_string(found.front()));
}

Json McpServer::callTool(const std::string& name, const Json& arguments) {
    if (name == "list_processes") {
        const auto found = Session::Discover();
        std::scoped_lock lock(_mutex);
        Json processes = Json::Array();
        for (const std::uint64_t pid : found) processes.Push(Json::Object({{"pid", pid}, {"connected", _session.Connected() && _session.Pid() == pid}}));
        return Json::Object({{"processes", std::move(processes)}});
    }
    if (name == "connect") {
        const double pid = Number(arguments, "pid", 0, 0, 4294967295.0);
        std::scoped_lock lock(_mutex);
        if (pid != 0) {
            if (!_session.Connect(static_cast<std::uint64_t>(pid))) throw ToolFailure("process " + std::to_string(static_cast<std::uint64_t>(pid)) + " does not publish telemetry");
            _pid = static_cast<std::uint64_t>(pid);
        } else {
            _session.Disconnect();
            _pid = 0;
            ensureConnected();
        }
        return Json::Object({{"pid", _session.Pid()}, {"note", "rates need one window of data after connecting; call sample to wait for it"}});
    }
    if (name == "sample") return sample(arguments);
    if (name == "sample_stacks") return sampleStacks(arguments);
    if (name == "watch_import") return watchImport(arguments);
    if (name == "set_slow_threshold") return setSlowThreshold(arguments);
    if (name == "list_snapshots") return listSnapshots();
    if (name == "compare_snapshots") return compareSnapshots(arguments);
    std::scoped_lock lock(_mutex);
    if (name == "resolve_address") return resolveAddress(arguments);
    if (name == "list_modules") return listModules(arguments);
    if (name == "get_watched_calls") return watchedCalls(arguments);
    if (name == "get_driver_phases") return driverPhases(arguments);
    if (name == "get_driver_report") return driverReport(arguments);
    if (name == "save_snapshot") return saveSnapshot(arguments);
    if (name == "list_memory_regions") return memoryRegions(arguments);
    if (name == "read_memory") return readMemory(arguments);
    if (name == "search_memory") return searchMemory(arguments);
    if (name == "get_summary") {
        ensureConnected();
        _session.Poll();
        return summary();
    }
    if (name == "get_imports") return imports(arguments);
    if (name == "get_threads") return threads(arguments);
    if (name == "get_slow_calls") return slowCalls(arguments);
    if (name == "get_frames") return frames(arguments);
    return recentCalls(arguments);
}

Json McpServer::summary() {
    const Telemetry::Header& header = _session.Header();
    const FrameSummary frames = _session.Summarize(1.0);
    const Verdict verdict = _session.Judge();
    const double cost = header.ticksPerSecond == 0 ? 0 : static_cast<double>(header.overheadTicks) * 1e9 / static_cast<double>(header.ticksPerSecond);
    return Json::Object({{"pid", _session.Pid()}, {"stale", _session.Stale()}, {"publishes", header.publishes}, {"calls_profiled", header.ticksPerSecond != 0},
        {"profiler_cost_ns_per_call", cost}, {"rate_window_seconds", _session.WindowSeconds()},
        {"frames", Json::Object({{"count", static_cast<std::uint64_t>(frames.frames)}, {"fps", frames.fps}, {"average_ms", frames.averageMs}, {"p50_ms", frames.p50Ms}, {"p99_ms", frames.p99Ms},
            {"max_ms", frames.maxMs}, {"gpu_ms", frames.gpuTimed ? Json(frames.gpuMs) : Json()}, {"driver_ms", frames.driverTimed ? Json(frames.driverMs) : Json()}})},
        {"verdict", Json::Object({{"title", verdict.title}, {"detail", verdict.detail}})}});
}

Json McpServer::imports(const Json& arguments) {
    const std::string sortBy = Text(arguments, "sort_by", "exclusive");
    const auto limit = static_cast<std::size_t>(Number(arguments, "limit", 20, 1, 4096));
    const std::string filter = Text(arguments, "filter", "");
    const double window = Number(arguments, "window_seconds", _session.WindowSeconds(), 0.2, 30);
    static constexpr std::string_view Columns[] = {"exclusive", "inclusive", "calls", "average", "p99", "max", "total"};
    if (std::find(std::begin(Columns), std::end(Columns), sortBy) == std::end(Columns)) throw InvalidParameters("sort_by must be exclusive, inclusive, calls, average, p99, max or total");
    ensureConnected();
    _session.Poll();
    if (window != _session.WindowSeconds()) _session.SetWindow(window);
    const auto key = [&sortBy](const ImportRate& rate) -> double {
        if (sortBy == "exclusive") return rate.exclusiveMsPerSecond;
        if (sortBy == "inclusive") return rate.inclusiveMsPerSecond;
        if (sortBy == "calls") return rate.callsPerSecond;
        if (sortBy == "average") return rate.averageUs;
        if (sortBy == "p99") return rate.p99Us;
        if (sortBy == "max") return rate.maxUs;
        return rate.totalExclusiveMs;
    };
    std::vector<ImportRate> rows;
    for (const ImportRate& rate : _session.Imports()) {
        if (Matches(filter, {rate.name, _session.DisplayName(rate.name), rate.library})) rows.push_back(rate);
    }
    std::stable_sort(rows.begin(), rows.end(), [&key](const ImportRate& left, const ImportRate& right) { return key(left) > key(right); });
    Json list = Json::Array();
    for (std::size_t index = 0; index < std::min(limit, rows.size()); ++index) list.Push(ImportRow(_session, rows[index]));
    return Json::Object({{"window_seconds", _session.WindowSeconds()}, {"matching", static_cast<std::uint64_t>(rows.size())}, {"traced", static_cast<std::uint64_t>(_session.Imports().size())},
        {"imports", std::move(list)}});
}

Json McpServer::threads(const Json& arguments) {
    const auto limit = static_cast<std::size_t>(Number(arguments, "limit", 32, 1, 256));
    ensureConnected();
    _session.Poll();
    std::vector<ThreadRate> rows = _session.Threads();
    std::sort(rows.begin(), rows.end(), [](const ThreadRate& left, const ThreadRate& right) { return left.importMsPerSecond > right.importMsPerSecond; });
    Json list = Json::Array();
    for (std::size_t index = 0; index < std::min(limit, rows.size()); ++index) {
        list.Push(Json::Object({{"thread", rows[index].thread}, {"thread_name", rows[index].name}, {"import_ms_per_s", rows[index].importMsPerSecond}, {"calls_per_s", rows[index].callsPerSecond}}));
    }
    return Json::Object({{"window_seconds", _session.WindowSeconds()}, {"threads", std::move(list)}});
}

Json McpServer::slowCalls(const Json& arguments) {
    const auto since = static_cast<std::uint64_t>(Number(arguments, "since", 0, 0, 1e18));
    const double minimum = Number(arguments, "min_ms", 0, 0, 1e9);
    const auto limit = static_cast<std::size_t>(Number(arguments, "limit", 50, 1, 4096));
    const std::string filter = Text(arguments, "filter", "");
    ensureConnected();
    _session.Poll();
    std::vector<const SlowCallView*> rows;
    std::uint64_t next = since;
    for (const SlowCallView& call : _session.SlowCalls()) {
        next = std::max(next, call.index);
        if (call.index <= since || call.milliseconds < minimum || !Matches(filter, {call.import, _session.DisplayName(call.import)})) continue;
        rows.push_back(&call);
    }
    Json list = Json::Array();
    for (std::size_t index = rows.size() > limit ? rows.size() - limit : 0; index < rows.size(); ++index) {
        const SlowCallView& call = *rows[index];
        list.Push(Json::Object({{"index", call.index}, {"import", call.import}, {"display_name", _session.DisplayName(call.import)}, {"thread", call.thread}, {"thread_name", _session.ThreadName(call.thread)}, {"ms", call.milliseconds},
            {"caller", Address(call.returnAddress)}}));
    }
    const Telemetry::Header& header = _session.Header();
    const double threshold = header.ticksPerSecond == 0 ? 0 : static_cast<double>(header.slowTicks) * 1e6 / static_cast<double>(header.ticksPerSecond);
    return Json::Object({{"threshold_us", threshold}, {"next_since", next}, {"matching", static_cast<std::uint64_t>(rows.size())}, {"calls", std::move(list)}});
}

Json McpServer::frames(const Json& arguments) {
    const auto count = static_cast<std::size_t>(Number(arguments, "count", 120, 1, 1024));
    ensureConnected();
    _session.Poll();
    const auto& all = _session.Frames();
    Json list = Json::Array();
    for (std::size_t index = all.size() > count ? all.size() - count : 0; index < all.size(); ++index) {
        const FrameSample& frame = all[index];
        list.Push(Json::Object({{"frame_ms", frame.frameMs}, {"gpu_ms", frame.gpuTimed ? Json(frame.gpuMs) : Json()}, {"driver_ms", frame.driverTimed ? Json(frame.driverMs) : Json()},
            {"draws", frame.draws}, {"dispatches", frame.dispatches}}));
    }
    return Json::Object({{"frames", std::move(list)}});
}

Json McpServer::recentCalls(const Json& arguments) {
    const auto limit = static_cast<std::size_t>(Number(arguments, "limit", 64, 1, 64));
    ensureConnected();
    _session.Poll();
    const auto& all = _session.RecentCalls();
    Json list = Json::Array();
    for (std::size_t index = all.size() > limit ? all.size() - limit : 0; index < all.size(); ++index) {
        list.Push(Json::Object({{"thread", all[index].thread}, {"thread_name", _session.ThreadName(all[index].thread)}, {"caller", Address(all[index].returnAddress)}, {"library", all[index].library}, {"name", all[index].name},
            {"display_name", _session.DisplayName(all[index].name)}}));
    }
    return Json::Object({{"calls", std::move(list)}});
}

Json McpServer::sample(const Json& arguments) {
    const double seconds = Number(arguments, "seconds", 2, 0.2, 30);
    const double limit = Number(arguments, "limit", 15, 1, 4096);
    std::uint64_t since = 0;
    {
        std::scoped_lock lock(_mutex);
        ensureConnected();
        _session.Poll();
        if (!_session.SlowCalls().empty()) since = _session.SlowCalls().back().index;
    }
    std::this_thread::sleep_for(std::chrono::duration<double>(seconds));
    std::scoped_lock lock(_mutex);
    _session.Poll();
    Json result = summary();
    result.Set("sample_seconds", seconds);
    const Json importRows = imports(Json::Object({{"limit", limit}}));
    const Json threadRows = threads(Json::Object({{"limit", 8}}));
    result.Set("imports", *importRows.Find("imports"));
    result.Set("threads", *threadRows.Find("threads"));
    result.Set("slow_calls", slowCalls(Json::Object({{"since", since}, {"limit", 20}})));
    return result;
}

CommandResult McpServer::awaitCommand(Telemetry::CommandKind kind, std::uint64_t first, std::uint64_t second, std::uint64_t third, std::chrono::milliseconds timeout) {
    std::uint64_t index = 0;
    {
        std::scoped_lock lock(_mutex);
        ensureConnected();
        if (!_session.Writable()) throw ToolFailure("the monitor could open the telemetry of this process only for reading, so it cannot send commands");
        index = _session.Send(kind, first, second, third);
    }
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    for (;;) {
        {
            std::scoped_lock lock(_mutex);
            if (const auto result = _session.Result(index)) return *result;
        }
        if (std::chrono::steady_clock::now() > deadline) throw ToolFailure("the title did not answer in time: its telemetry thread reads commands every 100 ms");
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
}

Symbols& McpServer::symbols() {
    ensureConnected();
    if (_symbols.Pid() != _session.Pid()) {
        std::string error;
        if (!_symbols.Attach(_session.Pid(), error)) throw ToolFailure("cannot list the modules of process " + std::to_string(_session.Pid()) + ": " + error);
    }
    return _symbols;
}

ProcessMemory& McpServer::memory() {
    ensureConnected();
    if (_memory.Pid() != _session.Pid()) {
        std::string error;
        if (!_memory.Open(_session.Pid(), error)) throw ToolFailure("cannot read the memory of process " + std::to_string(_session.Pid()) + ": " + error);
    }
    return _memory;
}

std::uint64_t McpServer::address(const Json& value) {
    if (value.Type() == Json::Kind::Number) return static_cast<std::uint64_t>(value.AsNumber());
    if (value.Type() != Json::Kind::String) throw InvalidParameters("an address is a number, 0x... or module+0x...");
    if (const auto parsed = symbols().Parse(value.AsString())) return *parsed;
    throw InvalidParameters("cannot read the address " + value.AsString() + ": use 0x... or a loaded module+0x...");
}

Json McpServer::describe(std::uint64_t address) {
    Symbols& table = symbols();
    std::optional<Location> location = table.Resolve(address);
    if (!location) {
        std::string error;
        if (table.Attach(_session.Pid(), error)) location = table.Resolve(address);
    }
    if (!location) return Json::Object({{"address", Address(address)}, {"module", Json()}, {"text", Address(address)}});
    if (!location->function.empty()) location->function = _session.DisplayName(location->function);
    return Json::Object({{"address", Address(address)}, {"module", location->module}, {"offset", Address(location->offset)},
        {"function", location->function.empty() ? Json() : Json(location->function)}, {"function_offset", location->function.empty() ? Json() : Json(Address(location->functionOffset))},
        {"function_start", location->functionStart ? Json(Address(*location->functionStart)) : Json()}, {"text", FormatLocation(*location)}});
}

Json McpServer::resolveAddress(const Json& arguments) {
    const Json* list = arguments.Find("addresses");
    if (list == nullptr || list->Type() != Json::Kind::Array || list->Items().empty() || list->Items().size() > 256) throw InvalidParameters("addresses must be an array of 1 to 256 addresses");
    Json results = Json::Array();
    for (const Json& item : list->Items()) {
        Json entry = describe(address(item));
        entry.Set("input", item);
        results.Push(std::move(entry));
    }
    return Json::Object({{"pid", _session.Pid()}, {"addresses", std::move(results)}});
}

Json McpServer::listModules(const Json& arguments) {
    const std::string filter = Text(arguments, "filter", "");
    std::string error;
    Symbols& table = symbols();
    table.Attach(_session.Pid(), error);
    Json modules = Json::Array();
    for (const Symbols::Module& module : table.Modules()) {
        if (Matches(filter, {module.name})) modules.Push(Json::Object({{"name", module.name}, {"base", Address(module.base)}, {"size", module.size}, {"path", module.path}}));
    }
    return Json::Object({{"pid", _session.Pid()}, {"modules", std::move(modules)}});
}

Json McpServer::sampleStacks(const Json& arguments) {
    const auto milliseconds = static_cast<std::uint64_t>(Number(arguments, "milliseconds", 2000, 1, 30000));
    const auto interval = static_cast<std::uint64_t>(Number(arguments, "interval_us", 1000, 100, 100000));
    const auto depth = static_cast<std::uint64_t>(Number(arguments, "depth", 32, 1, 64));
    const auto top = static_cast<std::size_t>(Number(arguments, "top", 15, 1, 200));
    const auto thread = static_cast<std::uint64_t>(Number(arguments, "thread", 0, 0, 4294967295.0));
    const Json* waits = arguments.Find("include_waits");
    if (waits != nullptr && waits->Type() != Json::Kind::Boolean) throw InvalidParameters("include_waits must be a boolean");
    const bool includeWaits = waits != nullptr && waits->AsBoolean();
    const CommandResult result = awaitCommand(Telemetry::CommandKind::SampleStacks, milliseconds, interval, depth, std::chrono::milliseconds(milliseconds + 15000));
    if (!result.done) throw ToolFailure(result.message);
    std::ifstream file(PathFromUtf8(result.message), std::ios::binary);
    if (!file) throw ToolFailure("cannot read the stack file " + result.message);
    struct Stack {
        std::uint64_t thread = 0;
        std::uint64_t count = 0;
        std::vector<std::string> frames;
    };
    std::vector<Stack> stacks;
    std::string header;
    for (std::string line; std::getline(file, line);) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        if (line.front() == '#') {
            if (header.empty()) header = line.substr(2);
            continue;
        }
        const auto space = line.rfind(' ');
        if (space == std::string::npos || !line.starts_with("thread-")) continue;
        Stack stack;
        stack.count = std::strtoull(line.c_str() + space + 1, nullptr, 10);
        std::istringstream parts(line.substr(0, space));
        std::string part;
        std::getline(parts, part, ';');
        stack.thread = std::strtoull(part.c_str() + 7, nullptr, 10);
        if (thread != 0 && stack.thread != thread) continue;
        while (std::getline(parts, part, ';')) {
            if (part != "[truncated]") stack.frames.push_back(part);
        }
        if (!stack.frames.empty()) stacks.push_back(std::move(stack));
    }
    std::scoped_lock lock(_mutex);
    Symbols& table = symbols();
    std::map<std::string, std::string> names;
    const auto name = [&](const std::string& frame) -> const std::string& {
        auto found = names.find(frame);
        if (found != names.end()) return found->second;
        std::string text = frame;
        const auto plus = frame.rfind('+');
        if (plus != std::string::npos) {
            const auto location = table.ResolveModuleOffset(frame.substr(0, plus), std::strtoull(frame.c_str() + plus + 1, nullptr, 16));
            if (location && !location->function.empty()) text = location->module + "!" + _session.DisplayName(location->function);
            else if (location && location->functionStart) {
                char start[24];
                std::snprintf(start, sizeof(start), "+0x%llx", static_cast<unsigned long long>(*location->functionStart));
                text = location->module + "!" + start;
            }
        }
        return names.emplace(frame, std::move(text)).first->second;
    };
    static constexpr std::string_view WaitFunctions[] = {"!NtWaitFor", "!ZwWaitFor", "!NtDelayExecution", "!NtUserMsgWaitForMultipleObjectsEx", "!NtRemoveIoCompletion", "!NtWaitForAlertByThreadId",
        "!NtWaitForWorkViaWorkerFactory", "!NtSignalAndWaitForSingleObject"};
    const auto waiting = [&](const Stack& stack) {
        const std::string& leaf = name(stack.frames.back());
        return std::any_of(std::begin(WaitFunctions), std::end(WaitFunctions), [&leaf](std::string_view function) { return leaf.find(function) != std::string::npos; });
    };
    std::uint64_t waited = 0;
    if (!includeWaits) {
        std::vector<Stack> working;
        for (Stack& stack : stacks) {
            if (waiting(stack)) waited += stack.count;
            else working.push_back(std::move(stack));
        }
        stacks = std::move(working);
    }
    std::uint64_t total = 0;
    std::map<std::string, std::uint64_t> self;
    std::map<std::string, std::uint64_t> inclusive;
    std::map<std::uint64_t, std::uint64_t> perThread;
    for (const Stack& stack : stacks) {
        total += stack.count;
        perThread[stack.thread] += stack.count;
        self[name(stack.frames.back())] += stack.count;
        std::vector<std::string> seen;
        for (const std::string& frame : stack.frames) {
            const std::string& function = name(frame);
            if (std::find(seen.begin(), seen.end(), function) != seen.end()) continue;
            seen.push_back(function);
            inclusive[function] += stack.count;
        }
    }
    const auto ranked = [&](const std::map<std::string, std::uint64_t>& counts) {
        std::vector<std::pair<std::string, std::uint64_t>> rows(counts.begin(), counts.end());
        std::stable_sort(rows.begin(), rows.end(), [](const auto& left, const auto& right) { return left.second > right.second; });
        Json list = Json::Array();
        for (std::size_t index = 0; index < std::min(top, rows.size()); ++index) {
            list.Push(Json::Object({{"function", rows[index].first}, {"samples", rows[index].second}, {"percent", total == 0 ? 0.0 : static_cast<double>(rows[index].second) * 100.0 / static_cast<double>(total)}}));
        }
        return list;
    };
    std::stable_sort(stacks.begin(), stacks.end(), [](const Stack& left, const Stack& right) { return left.count > right.count; });
    Json hottest = Json::Array();
    for (std::size_t index = 0; index < std::min(top, stacks.size()); ++index) {
        Json frames = Json::Array();
        for (auto frame = stacks[index].frames.rbegin(); frame != stacks[index].frames.rend() && frames.Items().size() < 16; ++frame) frames.Push(name(*frame));
        hottest.Push(Json::Object({{"thread", stacks[index].thread}, {"thread_name", _session.ThreadName(stacks[index].thread)}, {"samples", stacks[index].count}, {"frames_leaf_first", std::move(frames)}}));
    }
    Json threadList = Json::Array();
    for (const auto& [id, samples] : perThread) threadList.Push(Json::Object({{"thread", id}, {"thread_name", _session.ThreadName(id)}, {"samples", samples}}));
    return Json::Object({{"file", result.message}, {"capture", header}, {"samples", total}, {"waiting_samples_left_out", waited}, {"threads", std::move(threadList)}, {"self", ranked(self)},
        {"inclusive", ranked(inclusive)}, {"stacks", std::move(hottest)}});
}

Json McpServer::watchImport(const Json& arguments) {
    const std::string name = Text(arguments, "import", "");
    if (name.empty()) throw InvalidParameters("import is required");
    const auto count = static_cast<std::uint64_t>(Number(arguments, "count", 16, 0, 1024));
    std::size_t index = 0;
    {
        std::scoped_lock lock(_mutex);
        ensureConnected();
        _session.Poll();
        const auto found = _session.FindImport(name);
        if (!found) throw ToolFailure("no traced import named " + name + "; get_imports lists them");
        index = *found;
    }
    const CommandResult result = awaitCommand(Telemetry::CommandKind::WatchImport, index, count, 0, std::chrono::seconds(3));
    if (!result.done) throw ToolFailure(result.message);
    return Json::Object({{"import", name}, {"index", static_cast<std::uint64_t>(index)}, {"count", count}, {"message", result.message}});
}

Json McpServer::watchedCalls(const Json& arguments) {
    const auto since = static_cast<std::uint64_t>(Number(arguments, "since", 0, 0, 1e18));
    const auto limit = static_cast<std::size_t>(Number(arguments, "limit", 50, 1, 1024));
    const std::string filter = Text(arguments, "filter", "");
    ensureConnected();
    _session.Poll();
    std::vector<const WatchedCallView*> rows;
    std::uint64_t next = since;
    for (const WatchedCallView& call : _session.WatchedCalls()) {
        next = std::max(next, call.index);
        if (call.index > since && Matches(filter, {call.import, _session.DisplayName(call.import)})) rows.push_back(&call);
    }
    Json list = Json::Array();
    for (std::size_t index = rows.size() > limit ? rows.size() - limit : 0; index < rows.size(); ++index) {
        const WatchedCallView& call = *rows[index];
        Json registers = Json::Array();
        for (const std::uint64_t value : call.arguments) registers.Push(Address(value));
        list.Push(Json::Object({{"index", call.index}, {"import", call.import}, {"display_name", _session.DisplayName(call.import)}, {"thread", call.thread}, {"thread_name", _session.ThreadName(call.thread)}, {"ms", call.milliseconds},
            {"arguments", std::move(registers)}, {"result", Address(call.result)}, {"result_signed", static_cast<double>(static_cast<std::int64_t>(call.result))}, {"caller", describe(call.returnAddress)}}));
    }
    return Json::Object({{"next_since", next}, {"note", "arguments are rdi, rsi, rdx, rcx, r8 and r9 as the import received them; floating-point arguments are not recorded"}, {"calls", std::move(list)}});
}

Json McpServer::driverPhases(const Json& arguments) {
    const auto limit = static_cast<std::size_t>(Number(arguments, "limit", 30, 1, 512));
    const std::string filter = Text(arguments, "filter", "");
    ensureConnected();
    _session.Poll();
    std::vector<PhaseRate> rows;
    for (const PhaseRate& phase : _session.Phases()) {
        if (Matches(filter, {phase.thread, phase.threadName, phase.name})) rows.push_back(phase);
    }
    std::stable_sort(rows.begin(), rows.end(), [](const PhaseRate& left, const PhaseRate& right) { return left.msPerSecond > right.msPerSecond; });
    Json list = Json::Array();
    for (std::size_t index = 0; index < std::min(limit, rows.size()); ++index) {
        list.Push(Json::Object({{"thread", rows[index].thread}, {"thread_id", rows[index].threadId}, {"thread_name", rows[index].threadName}, {"phase", rows[index].name}, {"ms_per_s", rows[index].msPerSecond}, {"average_us", rows[index].averageUs}, {"total_ms", rows[index].totalMs},
            {"count", rows[index].count}}));
    }
    Json result = Json::Object({{"window_seconds", _session.WindowSeconds()}, {"phases", std::move(list)}});
    if (_session.Phases().empty()) result.Set("note", "no driver phases: run the title with APS5_TRACE_SUMMARY_EVERY=<seconds> so that the agc driver keeps its PerformanceTimer totals");
    return result;
}

Json McpServer::driverReport(const Json& arguments) {
    const auto limit = static_cast<std::size_t>(Number(arguments, "limit", 64, 1, Telemetry::ReportCapacity));
    const std::string filter = Text(arguments, "filter", "");
    ensureConnected();
    _session.Poll();
    Json list = Json::Array();
    for (const DriverReport& report : _session.Reports()) {
        if (list.Items().size() >= limit) break;
        if (!Matches(filter, {report.tag, report.text})) continue;
        list.Push(Json::Object({{"tag", report.tag}, {"line", report.text}, {"age_s", report.ageSeconds}, {"updates", report.updates}}));
    }
    Json result = Json::Object({{"reports", std::move(list)}});
    if (_session.Reports().empty()) result.Set("note", "no driver reports yet: run the title with APS5_PROFILE_DRAW=1; most lines print every 10 s");
    return result;
}

Json McpServer::setSlowThreshold(const Json& arguments) {
    if (arguments.Find("microseconds") == nullptr) throw InvalidParameters("microseconds is required");
    const auto microseconds = static_cast<std::uint64_t>(Number(arguments, "microseconds", 1000, 1, 60000000));
    const CommandResult result = awaitCommand(Telemetry::CommandKind::SetSlowThreshold, microseconds, 0, 0, std::chrono::seconds(3));
    if (!result.done) throw ToolFailure(result.message);
    return Json::Object({{"threshold_us", microseconds}, {"threshold_ticks", result.value}});
}

Json McpServer::saveSnapshot(const Json& arguments) {
    const std::string name = Text(arguments, "name", "");
    const std::string note = Text(arguments, "note", "");
    ensureConnected();
    _session.Poll();
    const Json snapshot = CaptureSnapshot(_session, name, note);
    SaveSnapshot(snapshot);
    return Json::Object({{"name", name}, {"path", Utf8(SnapshotDirectory() / (name + ".json"))}, {"frames", *snapshot.Find("frames")},
        {"imports", static_cast<std::uint64_t>(snapshot.Find("imports")->Items().size())}, {"phases", static_cast<std::uint64_t>(snapshot.Find("phases")->Items().size())}});
}

Json McpServer::listSnapshots() {
    Json list = Json::Array();
    for (Json& snapshot : ListSnapshots()) list.Push(std::move(snapshot));
    return Json::Object({{"directory", Utf8(SnapshotDirectory())}, {"snapshots", std::move(list)}});
}

Json McpServer::compareSnapshots(const Json& arguments) {
    const std::string before = Text(arguments, "before", "");
    const std::string after = Text(arguments, "after", "");
    const auto limit = static_cast<std::size_t>(Number(arguments, "limit", 15, 1, 500));
    return CompareSnapshots(LoadSnapshot(before), LoadSnapshot(after), limit);
}

Json McpServer::memoryRegions(const Json& arguments) {
    const std::string module = Text(arguments, "module", "");
    const Json* readable = arguments.Find("readable_only");
    if (readable != nullptr && readable->Type() != Json::Kind::Boolean) throw InvalidParameters("readable_only must be a boolean");
    const bool readableOnly = readable == nullptr || readable->AsBoolean();
    const auto minimum = static_cast<std::uint64_t>(Number(arguments, "min_size", 0, 0, 1e18));
    const auto limit = static_cast<std::size_t>(Number(arguments, "limit", 200, 1, 100000));
    std::uint64_t committed = 0;
    std::uint64_t matching = 0;
    Json list = Json::Array();
    for (const Region& region : memory().Regions()) {
        committed += region.size;
        if ((readableOnly && !region.readable) || region.size < minimum || (!module.empty() && Lower(region.module) != Lower(module))) continue;
        ++matching;
        if (list.Items().size() < limit) {
            list.Push(Json::Object({{"base", Address(region.base)}, {"size", region.size}, {"protection", region.protection}, {"type", region.type}, {"module", region.module.empty() ? Json() : Json(region.module)}}));
        }
    }
    return Json::Object({{"pid", _session.Pid()}, {"committed_bytes", committed}, {"matching", matching}, {"regions", std::move(list)}});
}

Json McpServer::readMemory(const Json& arguments) {
    const Json* given = arguments.Find("address");
    if (given == nullptr) throw InvalidParameters("address is required");
    const auto size = static_cast<std::size_t>(Number(arguments, "size", 256, 1, 65536));
    const std::string as = Text(arguments, "as", "hex");
    static constexpr std::string_view Kinds[] = {"hex", "u8", "u16", "u32", "u64", "i32", "i64", "f32", "f64", "pointer", "string", "utf16"};
    if (std::find(std::begin(Kinds), std::end(Kinds), as) == std::end(Kinds)) throw InvalidParameters("as must be hex, u8, u16, u32, u64, i32, i64, f32, f64, pointer, string or utf16");
    const std::uint64_t start = address(*given);
    std::vector<std::uint8_t> bytes;
    const std::size_t read = memory().Read(start, size, bytes);
    Json lines = Json::Array();
    for (std::size_t offset = 0; offset < read; offset += 16) {
        std::string line = Address(start + offset) + ":";
        std::string text;
        for (std::size_t index = offset; index < offset + 16; ++index) {
            if (index < read) {
                char hex[4];
                std::snprintf(hex, sizeof(hex), " %02x", bytes[index]);
                line += hex;
                text += bytes[index] >= 0x20 && bytes[index] < 0x7f ? static_cast<char>(bytes[index]) : '.';
            } else {
                line += "   ";
            }
        }
        lines.Push(line + "  " + text);
    }
    Json result = Json::Object({{"address", describe(start)}, {"requested", static_cast<std::uint64_t>(size)}, {"read", static_cast<std::uint64_t>(read)}, {"hex", std::move(lines)}});
    if (read < size) result.Set("note", "the read stopped at the first page that is not readable");
    if (as == "string") {
        const auto end = std::find(bytes.begin(), bytes.end(), std::uint8_t{0});
        result.Set("value", std::string(bytes.begin(), end));
    } else if (as == "utf16") {
        std::string text;
        for (std::size_t index = 0; index + 1 < read; index += 2) {
            const std::uint16_t unit = static_cast<std::uint16_t>(bytes[index] | (bytes[index + 1] << 8));
            if (unit == 0) break;
            text += unit < 0x80 ? static_cast<char>(unit) : '?';
        }
        result.Set("value", text);
    } else if (as != "hex") {
        const std::size_t width = as == "u8" ? 1 : as == "u16" ? 2 : (as == "u32" || as == "i32" || as == "f32") ? 4 : 8;
        Json values = Json::Array();
        for (std::size_t offset = 0; offset + width <= read && values.Items().size() < 512; offset += width) {
            std::uint64_t raw = 0;
            std::memcpy(&raw, bytes.data() + offset, width);
            if (as == "f32") {
                float value = 0;
                std::memcpy(&value, &raw, sizeof(value));
                values.Push(static_cast<double>(value));
            } else if (as == "f64") {
                double value = 0;
                std::memcpy(&value, &raw, sizeof(value));
                values.Push(value);
            } else if (as == "i32") {
                values.Push(static_cast<double>(static_cast<std::int32_t>(raw)));
            } else if (as == "i64") {
                values.Push(static_cast<double>(static_cast<std::int64_t>(raw)));
            } else if (as == "pointer") {
                values.Push(describe(raw));
            } else {
                values.Push(width == 8 ? Json(Address(raw)) : Json(static_cast<double>(raw)));
            }
        }
        result.Set("values", std::move(values));
    }
    return result;
}

Json McpServer::searchMemory(const Json& arguments) {
    const std::string value = Text(arguments, "value", "");
    if (value.empty()) throw InvalidParameters("value is required");
    const std::string type = Text(arguments, "type", "string");
    const std::string module = Text(arguments, "module", "");
    const auto limit = static_cast<std::size_t>(Number(arguments, "limit", 50, 1, 1000));
    const auto maximum = static_cast<std::uint64_t>(Number(arguments, "max_mb", 256, 1, 16384)) << 20;
    std::vector<std::uint8_t> pattern;
    const auto append = [&pattern](const void* data, std::size_t size) {
        const auto* bytes = static_cast<const std::uint8_t*>(data);
        pattern.insert(pattern.end(), bytes, bytes + size);
    };
    char* end = nullptr;
    if (type == "string") {
        pattern.assign(value.begin(), value.end());
    } else if (type == "utf16") {
        for (const char character : value) {
            pattern.push_back(static_cast<std::uint8_t>(character));
            pattern.push_back(0);
        }
    } else if (type == "bytes") {
        std::string digits;
        for (const char character : value) {
            if (character != ' ') digits += character;
        }
        if (digits.empty() || digits.size() % 2 != 0) throw InvalidParameters("bytes are pairs of hex digits");
        for (std::size_t index = 0; index < digits.size(); index += 2) {
            const std::string pair = digits.substr(index, 2);
            const unsigned long byte = std::strtoul(pair.c_str(), &end, 16);
            if (*end != '\0') throw InvalidParameters("bytes are pairs of hex digits");
            pattern.push_back(static_cast<std::uint8_t>(byte));
        }
    } else if (type == "u32" || type == "u64" || type == "i32" || type == "i64") {
        const bool negative = value.starts_with('-');
        const std::uint64_t number = negative ? static_cast<std::uint64_t>(std::strtoll(value.c_str(), &end, 0)) : std::strtoull(value.c_str(), &end, 0);
        if (end == value.c_str() || *end != '\0') throw InvalidParameters("value is not an integer");
        append(&number, type.ends_with("32") ? 4 : 8);
    } else if (type == "f32" || type == "f64") {
        const double number = std::strtod(value.c_str(), &end);
        if (end == value.c_str() || *end != '\0') throw InvalidParameters("value is not a number");
        if (type == "f32") {
            const float single = static_cast<float>(number);
            append(&single, sizeof(single));
        } else {
            append(&number, sizeof(number));
        }
    } else {
        throw InvalidParameters("type must be bytes, string, utf16, u32, u64, i32, i64, f32 or f64");
    }
    std::uint64_t scanned = 0;
    const auto found = memory().Search(pattern, limit, maximum, module, scanned);
    Json matches = Json::Array();
    for (const std::uint64_t match : found) matches.Push(describe(match));
    return Json::Object({{"pattern_bytes", static_cast<std::uint64_t>(pattern.size())}, {"scanned_mb", static_cast<double>(scanned) / 1048576.0}, {"complete", found.size() < limit && scanned < maximum},
        {"matches", std::move(matches)}});
}

int RunMcp(Session& session, std::uint64_t pid, std::istream& in, std::ostream& out) {
    std::mutex mutex;
    McpServer server(session, mutex, pid);
    std::atomic<bool> running{true};
    std::thread poller([&] {
        while (running.load(std::memory_order_relaxed)) {
            {
                std::scoped_lock lock(mutex);
                session.Poll();
            }
            std::this_thread::sleep_for(PollInterval);
        }
    });
    std::string line;
    while (std::getline(in, line)) {
        const std::string response = server.Handle(line);
        if (!response.empty()) out << response << '\n' << std::flush;
    }
    running.store(false, std::memory_order_relaxed);
    poller.join();
    return 0;
}

}
