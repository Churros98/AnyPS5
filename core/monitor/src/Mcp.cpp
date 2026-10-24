#include "Mcp.hpp"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <istream>
#include <ostream>
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
    "Start with get_summary, then get_imports and get_slow_calls to find what fills the frame. Import names are NIDs when the "
    "monitor finds no NID database.";

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
    std::scoped_lock lock(_mutex);
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
        list.Push(Json::Object({{"thread", rows[index].thread}, {"import_ms_per_s", rows[index].importMsPerSecond}, {"calls_per_s", rows[index].callsPerSecond}}));
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
        list.Push(Json::Object({{"index", call.index}, {"import", call.import}, {"display_name", _session.DisplayName(call.import)}, {"thread", call.thread}, {"ms", call.milliseconds},
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
        list.Push(Json::Object({{"thread", all[index].thread}, {"caller", Address(all[index].returnAddress)}, {"library", all[index].library}, {"name", all[index].name},
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
