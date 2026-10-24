#include "Session.hpp"
#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iterator>
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace Monitor {

namespace {

constexpr std::size_t FrameHistory = 1024;
constexpr std::size_t SlowHistory = 4096;
constexpr auto StaleAfter = std::chrono::seconds(2);

double Percentile(const std::uint64_t (&histogram)[Telemetry::HistogramBuckets], std::uint64_t calls, double fraction) {
    if (calls == 0) return 0;
    const auto target = static_cast<std::uint64_t>(static_cast<double>(calls) * fraction);
    std::uint64_t seen = 0;
    for (std::size_t bucket = 0; bucket < Telemetry::HistogramBuckets; ++bucket) {
        seen += histogram[bucket];
        if (seen > target || bucket + 1 == Telemetry::HistogramBuckets) return bucket == 0 ? 1.0 : static_cast<double>(std::uint64_t{1} << bucket) * 1.5;
    }
    return 0;
}

double Quantile(std::vector<double> values, double fraction) {
    if (values.empty()) return 0;
    std::sort(values.begin(), values.end());
    const auto index = static_cast<std::size_t>(std::min<double>(static_cast<double>(values.size() - 1), std::floor(fraction * static_cast<double>(values.size()))));
    return values[index];
}

std::string Fixed(double value, int digits) {
    std::ostringstream stream;
    stream.setf(std::ios::fixed);
    stream.precision(digits);
    stream << value;
    return stream.str();
}

}

std::vector<std::uint64_t> Session::Discover() {
    std::vector<std::uint64_t> pids;
    std::error_code error;
    const auto directory = std::filesystem::temp_directory_path(error) / "anyps5-telemetry";
    if (error || !std::filesystem::is_directory(directory, error)) return pids;
    for (const auto& entry : std::filesystem::directory_iterator(directory, error)) {
        const std::string name = entry.path().filename().string();
        if (name.empty() || !std::all_of(name.begin(), name.end(), [](char character) { return character >= '0' && character <= '9'; })) continue;
        const std::uint64_t pid = std::strtoull(name.c_str(), nullptr, 10);
        Telemetry::Reader reader;
        if (reader.Open(pid)) pids.push_back(pid);
    }
    std::sort(pids.begin(), pids.end());
    return pids;
}

bool Session::Connect(std::uint64_t pid) {
    Disconnect();
    if (!_reader.Open(pid)) return false;
    _pid = pid;
    _header = _reader.ReadHeader();
    _connectedAt = Clock::now();
    _lastChange = _connectedAt;
    _lastPublishes = _header.publishes;
    _lastFrame = _header.framesWritten > Telemetry::FrameCapacity ? _header.framesWritten - Telemetry::FrameCapacity : 0;
    _lastSlow = _header.slowWritten > Telemetry::SlowCapacity ? _header.slowWritten - Telemetry::SlowCapacity : 0;
    Poll();
    return true;
}

void Session::Disconnect() {
    _reader.Close();
    _pid = 0;
    _header = {};
    _history.clear();
    _imports.clear();
    _threads.clear();
    _frames.clear();
    _slow.clear();
    _recent.clear();
    _importNames.clear();
    _watched.clear();
    _phases.clear();
    _lastFrame = _lastPresent = _lastGpu = _lastDriver = _lastDraws = _lastDispatches = _lastSlow = _lastWatched = 0;
}

bool Session::Connected() const {
    return _reader.IsOpen();
}

std::uint64_t Session::Pid() const {
    return _pid;
}

bool Session::Stale() const {
    return !Connected() || Clock::now() - _lastChange > StaleAfter;
}

void Session::SetWindow(double seconds) {
    _windowSeconds = std::clamp(seconds, 0.2, 30.0);
    computeRates();
}

double Session::WindowSeconds() const {
    return _windowSeconds;
}

void Session::LoadNames(const std::string& path) {
    std::ifstream file(path);
    if (!file) throw std::runtime_error("cannot read the NID names file " + path);
    std::string line;
    while (std::getline(file, line)) {
        if (line.size() >= 3 && static_cast<unsigned char>(line[0]) == 0xef && static_cast<unsigned char>(line[1]) == 0xbb && static_cast<unsigned char>(line[2]) == 0xbf) line.erase(0, 3);
        std::istringstream fields(line);
        std::string nid;
        std::string name;
        if (!(fields >> nid >> name) || nid.starts_with('#')) continue;
        nid = nid.substr(0, nid.find('#'));
        name = name.substr(0, name.find('#'));
        if (!nid.empty() && !name.empty()) _names.emplace(nid, name);
    }
}

std::filesystem::path Session::DefaultNamesPath() {
    if (const char* database = std::getenv("ANYPS5_NID_DB"); database != nullptr && *database != '\0') return database;
    std::error_code error;
    const auto directory = std::filesystem::temp_directory_path(error);
    return error ? std::filesystem::path() : directory / "anyps5-nid-db" / "aerolib.csv";
}

bool Session::LoadDefaultNames() {
    const auto path = DefaultNamesPath();
    std::error_code error;
    if (path.empty() || !std::filesystem::is_regular_file(path, error)) return false;
    LoadNames(path.string());
    return true;
}

std::string Session::DisplayName(const std::string& name) const {
    const auto found = _names.find(name);
    return found == _names.end() ? name : found->second;
}

double Session::milliseconds(std::uint64_t ticks) const {
    return _header.ticksPerSecond == 0 ? 0 : static_cast<double>(ticks) * 1e3 / static_cast<double>(_header.ticksPerSecond);
}

void Session::Poll() {
    if (!Connected()) return;
    const Clock::time_point now = Clock::now();
    _header = _reader.ReadHeader();
    if (_header.publishes != _lastPublishes || _history.empty()) {
        if (_header.publishes != _lastPublishes) _lastChange = now;
        _lastPublishes = _header.publishes;
        _history.push_back({now, _reader.ReadImports(), _reader.ReadThreads(), _reader.ReadPhases()});
        const auto horizon = now - std::chrono::duration_cast<Clock::duration>(std::chrono::duration<double>(30.0 + 1.0));
        while (_history.size() > 2 && _history[1].at < horizon) _history.pop_front();
        _importNames.resize(_history.back().imports.size());
        for (std::size_t index = 0; index < _history.back().imports.size(); ++index) {
            if (_history.back().imports[index].sequence != 0) _importNames[index] = _history.back().imports[index].name;
        }
        computeRates();
        _recent = _reader.ReadRecentCalls();
    }
    for (const Telemetry::Frame& frame : _reader.ReadFrames(_lastFrame)) {
        _lastFrame = frame.sequence / 2;
        if (_lastPresent != 0 && frame.presentNanoseconds > _lastPresent) {
            FrameSample sample;
            sample.frameMs = static_cast<double>(frame.presentNanoseconds - _lastPresent) / 1e6;
            sample.gpuTimed = (frame.flags & Telemetry::PresentGpuTimed) != 0;
            sample.driverTimed = (frame.flags & Telemetry::PresentDriverTimed) != 0;
            sample.gpuMs = sample.gpuTimed && frame.gpuNanoseconds >= _lastGpu ? static_cast<double>(frame.gpuNanoseconds - _lastGpu) / 1e6 : 0;
            sample.driverMs = sample.driverTimed && frame.driverNanoseconds >= _lastDriver ? static_cast<double>(frame.driverNanoseconds - _lastDriver) / 1e6 : 0;
            sample.draws = frame.draws >= _lastDraws ? static_cast<double>(frame.draws - _lastDraws) : 0;
            sample.dispatches = frame.dispatches >= _lastDispatches ? static_cast<double>(frame.dispatches - _lastDispatches) : 0;
            _frames.push_back(sample);
            if (_frames.size() > FrameHistory) _frames.pop_front();
        }
        _lastPresent = frame.presentNanoseconds;
        _lastGpu = frame.gpuNanoseconds;
        _lastDriver = frame.driverNanoseconds;
        _lastDraws = frame.draws;
        _lastDispatches = frame.dispatches;
    }
    for (const Telemetry::WatchedCall& call : _reader.ReadWatchedCalls(_lastWatched)) {
        _lastWatched = call.sequence / 2;
        WatchedCallView view;
        view.index = _lastWatched;
        view.import = call.import < _importNames.size() ? _importNames[call.import] : "#" + std::to_string(call.import);
        view.thread = call.thread;
        std::copy(std::begin(call.arguments), std::end(call.arguments), view.arguments);
        view.result = call.result;
        view.milliseconds = milliseconds(call.ticks);
        view.returnAddress = call.returnAddress;
        _watched.push_back(view);
        if (_watched.size() > Telemetry::WatchedCapacity) _watched.pop_front();
    }
    for (const Telemetry::SlowCall& call : _reader.ReadSlowCalls(_lastSlow)) {
        _lastSlow = call.sequence / 2;
        SlowCallView view;
        view.index = _lastSlow;
        view.import = call.import < _importNames.size() ? _importNames[call.import] : "#" + std::to_string(call.import);
        view.thread = call.thread;
        view.milliseconds = milliseconds(call.ticks);
        view.returnAddress = call.returnAddress;
        view.atSeconds = std::chrono::duration<double>(now - _connectedAt).count();
        _slow.push_back(view);
        if (_slow.size() > SlowHistory) _slow.pop_front();
    }
}

void Session::computeRates() {
    _imports.clear();
    _threads.clear();
    _phases.clear();
    if (_history.empty()) return;
    const Snapshot& newest = _history.back();
    const Snapshot* oldest = &_history.front();
    const auto target = newest.at - std::chrono::duration_cast<Clock::duration>(std::chrono::duration<double>(_windowSeconds));
    for (const Snapshot& snapshot : _history) {
        if (snapshot.at > target) break;
        oldest = &snapshot;
    }
    const double seconds = std::chrono::duration<double>(newest.at - oldest->at).count();
    const double perSecond = seconds > 0 ? 1.0 / seconds : 0;
    for (std::size_t index = 0; index < newest.imports.size(); ++index) {
        const Telemetry::Import& current = newest.imports[index];
        if (current.sequence == 0) continue;
        Telemetry::Import previous{};
        if (index < oldest->imports.size() && oldest->imports[index].sequence != 0 && oldest != &newest) previous = oldest->imports[index];
        Telemetry::Import delta = current;
        delta.calls -= std::min(previous.calls, current.calls);
        delta.timedCalls -= std::min(previous.timedCalls, current.timedCalls);
        delta.inclusiveTicks -= std::min(previous.inclusiveTicks, current.inclusiveTicks);
        delta.exclusiveTicks -= std::min(previous.exclusiveTicks, current.exclusiveTicks);
        for (std::size_t bucket = 0; bucket < Telemetry::HistogramBuckets; ++bucket) delta.histogram[bucket] -= std::min(previous.histogram[bucket], current.histogram[bucket]);
        ImportRate rate;
        rate.name = current.name;
        rate.library = current.library;
        rate.calls = current.calls;
        rate.timedCalls = current.timedCalls;
        rate.exclusiveMsPerSecond = milliseconds(delta.exclusiveTicks) * perSecond;
        rate.inclusiveMsPerSecond = milliseconds(delta.inclusiveTicks) * perSecond;
        rate.callsPerSecond = static_cast<double>(delta.calls) * perSecond;
        rate.averageUs = delta.timedCalls == 0 ? 0 : milliseconds(delta.inclusiveTicks) * 1e3 / static_cast<double>(delta.timedCalls);
        rate.p50Us = milliseconds(static_cast<std::uint64_t>(Percentile(delta.histogram, delta.timedCalls, 0.5))) * 1e3;
        rate.p99Us = milliseconds(static_cast<std::uint64_t>(Percentile(delta.histogram, delta.timedCalls, 0.99))) * 1e3;
        rate.maxUs = milliseconds(current.maxTicks) * 1e3;
        rate.totalExclusiveMs = milliseconds(current.exclusiveTicks);
        _imports.push_back(rate);
    }
    for (const Telemetry::Phase& current : newest.phases) {
        Telemetry::Phase previous{};
        if (oldest != &newest) {
            const auto found = std::find_if(oldest->phases.begin(), oldest->phases.end(), [&current](const Telemetry::Phase& phase) {
                return std::strcmp(phase.thread, current.thread) == 0 && std::strcmp(phase.name, current.name) == 0;
            });
            if (found != oldest->phases.end()) previous = *found;
        }
        PhaseRate rate;
        rate.thread = current.thread;
        rate.name = current.name;
        rate.totalMs = static_cast<double>(current.nanoseconds) / 1e6;
        rate.count = current.count;
        rate.msPerSecond = static_cast<double>(current.nanoseconds - std::min(previous.nanoseconds, current.nanoseconds)) / 1e6 * perSecond;
        const std::uint64_t calls = current.count - std::min(previous.count, current.count);
        rate.averageUs = calls == 0 ? 0 : static_cast<double>(current.nanoseconds - std::min(previous.nanoseconds, current.nanoseconds)) / 1e3 / static_cast<double>(calls);
        _phases.push_back(rate);
    }
    for (const Telemetry::Thread& current : newest.threads) {
        Telemetry::Thread previous{};
        if (oldest != &newest) {
            const auto found = std::find_if(oldest->threads.begin(), oldest->threads.end(), [&current](const Telemetry::Thread& thread) { return thread.thread == current.thread; });
            if (found != oldest->threads.end()) previous = *found;
        }
        ThreadRate rate;
        rate.thread = current.thread;
        rate.importMsPerSecond = milliseconds(current.topLevelTicks - std::min(previous.topLevelTicks, current.topLevelTicks)) * perSecond;
        rate.callsPerSecond = static_cast<double>(current.timedCalls - std::min(previous.timedCalls, current.timedCalls)) * perSecond;
        _threads.push_back(rate);
    }
}

const Telemetry::Header& Session::Header() const {
    return _header;
}

const std::vector<ImportRate>& Session::Imports() const {
    return _imports;
}

const std::vector<ThreadRate>& Session::Threads() const {
    return _threads;
}

const std::deque<FrameSample>& Session::Frames() const {
    return _frames;
}

const std::deque<SlowCallView>& Session::SlowCalls() const {
    return _slow;
}

const std::vector<Telemetry::RecentCall>& Session::RecentCalls() const {
    return _recent;
}

bool Session::Writable() const {
    return _reader.Writable();
}

std::uint64_t Session::Send(Telemetry::CommandKind kind, std::uint64_t first, std::uint64_t second, std::uint64_t third) {
    return Connected() ? _reader.SendCommand(kind, first, second, third) : 0;
}

std::optional<CommandResult> Session::Result(std::uint64_t index) const {
    Telemetry::Response response{};
    if (!Connected() || index == 0 || !_reader.ReadResponse(index, response)) return std::nullopt;
    return CommandResult{response.status == static_cast<std::uint64_t>(Telemetry::CommandStatus::Done), response.value, response.message};
}

std::optional<std::size_t> Session::FindImport(const std::string& name) const {
    if (_history.empty()) return std::nullopt;
    const auto& imports = _history.back().imports;
    for (std::size_t index = 0; index < imports.size(); ++index) {
        if (imports[index].sequence != 0 && (name == imports[index].name || name == DisplayName(imports[index].name))) return index;
    }
    return std::nullopt;
}

const std::deque<WatchedCallView>& Session::WatchedCalls() const {
    return _watched;
}

const std::vector<PhaseRate>& Session::Phases() const {
    return _phases;
}

FrameSummary Session::Summarize(double seconds) const {
    FrameSummary summary;
    std::vector<double> times;
    double total = 0;
    double gpu = 0;
    double driver = 0;
    for (auto frame = _frames.rbegin(); frame != _frames.rend() && total < seconds * 1e3; ++frame) {
        times.push_back(frame->frameMs);
        total += frame->frameMs;
        gpu += frame->gpuMs;
        driver += frame->driverMs;
        if (frame == _frames.rbegin()) {
            summary.gpuTimed = frame->gpuTimed;
            summary.driverTimed = frame->driverTimed;
        }
    }
    summary.frames = times.size();
    if (times.empty() || total <= 0) return summary;
    const auto count = static_cast<double>(times.size());
    summary.fps = count * 1e3 / total;
    summary.averageMs = total / count;
    summary.gpuMs = gpu / count;
    summary.driverMs = driver / count;
    summary.p50Ms = Quantile(times, 0.5);
    summary.p99Ms = Quantile(times, 0.99);
    summary.maxMs = *std::max_element(times.begin(), times.end());
    return summary;
}

Verdict Session::Judge() const {
    const FrameSummary frames = Summarize(1.0);
    if (frames.frames == 0) return {"No presents", "The title has not presented a frame since the monitor connected, or it does not present through the agc driver."};
    const double frame = frames.averageMs;
    const std::string budget = Fixed(frame, 1) + " ms frame (" + Fixed(frames.fps, 1) + " fps)";
    if (frames.gpuTimed && frames.gpuMs >= 0.85 * frame) return {"GPU-bound", "The GPU is busy " + Fixed(frames.gpuMs, 1) + " ms of each " + budget + "."};
    if (frames.driverTimed && frames.driverMs >= 0.85 * frame) return {"Driver-bound", "The agc packet workers spend " + Fixed(frames.driverMs, 1) + " ms in draw and dispatch packets per " + budget + "."};
    const auto busiest = std::max_element(_threads.begin(), _threads.end(), [](const ThreadRate& left, const ThreadRate& right) { return left.importMsPerSecond < right.importMsPerSecond; });
    if (busiest != _threads.end() && frames.fps > 0) {
        const double perFrame = busiest->importMsPerSecond / frames.fps;
        if (perFrame >= 0.5 * frame) {
            std::vector<ImportRate> top = _imports;
            std::sort(top.begin(), top.end(), [](const ImportRate& left, const ImportRate& right) { return left.exclusiveMsPerSecond > right.exclusiveMsPerSecond; });
            std::string names;
            for (std::size_t index = 0; index < std::min<std::size_t>(3, top.size()); ++index) names += (index == 0 ? "" : ", ") + DisplayName(top[index].name) + " (" + Fixed(top[index].exclusiveMsPerSecond, 1) + " ms/s)";
            return {"Waiting in system calls", "Thread " + std::to_string(busiest->thread) + " spends " + Fixed(perFrame, 1) + " ms of each " + budget + " in traced imports. Most exclusive time: " + names + "."};
        }
    }
    std::string missing;
    if (!frames.gpuTimed) missing += " Set APS5_PROFILE_GPU=1 to time the GPU.";
    if (!frames.driverTimed) missing += " Set APS5_PROFILE_DRAW=1 to time the agc driver.";
    if (_header.ticksPerSecond == 0) missing += " Convert the executable with --trace-imports and leave APS5_PROFILE_CALLS unset or above 0 to time the imports.";
    return {"Not explained by the GPU, the driver or imports", "No measured source fills the " + budget + "; the time is in game code or untraced work." + missing};
}

}
