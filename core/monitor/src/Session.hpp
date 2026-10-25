#ifndef CORE_MONITOR_SRC_SESSION_HPP
#define CORE_MONITOR_SRC_SESSION_HPP

#include "ThreadNames.hpp"
#include "prx/libc/include/TelemetryReader.hpp"
#include <chrono>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace Monitor {

struct ImportRate {
    std::string name;
    std::string library;
    std::uint64_t calls = 0;
    std::uint64_t timedCalls = 0;
    double exclusiveMsPerSecond = 0;
    double inclusiveMsPerSecond = 0;
    double callsPerSecond = 0;
    double averageUs = 0;
    double p50Us = 0;
    double p99Us = 0;
    double maxUs = 0;
    double totalExclusiveMs = 0;
};

struct ThreadRate {
    std::uint64_t thread = 0;
    std::string name;
    double importMsPerSecond = 0;
    double callsPerSecond = 0;
};

struct FrameSample {
    double frameMs = 0;
    double gpuMs = 0;
    double driverMs = 0;
    double draws = 0;
    double dispatches = 0;
    bool gpuTimed = false;
    bool driverTimed = false;
};

struct SlowCallView {
    std::uint64_t index = 0;
    std::string import;
    std::uint64_t thread = 0;
    double milliseconds = 0;
    std::uint64_t returnAddress = 0;
    double atSeconds = 0;
};

struct FrameSummary {
    std::size_t frames = 0;
    double fps = 0;
    double averageMs = 0;
    double p50Ms = 0;
    double p99Ms = 0;
    double maxMs = 0;
    double gpuMs = 0;
    double driverMs = 0;
    bool gpuTimed = false;
    bool driverTimed = false;
};

struct Verdict {
    std::string title;
    std::string detail;
};

struct WatchedCallView {
    std::uint64_t index = 0;
    std::string import;
    std::uint64_t thread = 0;
    std::uint64_t arguments[Telemetry::WatchedArguments]{};
    std::uint64_t result = 0;
    double milliseconds = 0;
    std::uint64_t returnAddress = 0;
};

struct PhaseRate {
    std::string thread;
    std::uint64_t threadId = 0;
    std::string threadName;
    std::string name;
    double msPerSecond = 0;
    double totalMs = 0;
    std::uint64_t count = 0;
    double averageUs = 0;
};

struct DriverReport {
    std::string tag;
    std::string text;
    double ageSeconds = 0;
    std::uint64_t updates = 0;
};

struct CommandResult {
    bool done = false;
    std::uint64_t value = 0;
    std::string message;
};

class Session {
public:
    using Clock = std::chrono::steady_clock;

    static std::vector<std::uint64_t> Discover();

    bool Connect(std::uint64_t pid);
    void Disconnect();
    bool Connected() const;
    std::uint64_t Pid() const;
    bool Stale() const;
    void Poll();
    void SetWindow(double seconds);
    void LoadNames(const std::string& path);
    static std::filesystem::path DefaultNamesPath();
    bool LoadDefaultNames();
    std::string DisplayName(const std::string& name) const;
    std::string ThreadName(std::uint64_t thread) const;

    const Telemetry::Header& Header() const;
    const std::vector<ImportRate>& Imports() const;
    const std::vector<ThreadRate>& Threads() const;
    const std::deque<FrameSample>& Frames() const;
    const std::deque<SlowCallView>& SlowCalls() const;
    const std::vector<Telemetry::RecentCall>& RecentCalls() const;
    FrameSummary Summarize(double seconds) const;
    Verdict Judge() const;
    double WindowSeconds() const;
    bool Writable() const;
    std::uint64_t Send(Telemetry::CommandKind kind, std::uint64_t first, std::uint64_t second = 0, std::uint64_t third = 0);
    std::optional<CommandResult> Result(std::uint64_t index) const;
    std::optional<std::size_t> FindImport(const std::string& name) const;
    const std::deque<WatchedCallView>& WatchedCalls() const;
    const std::vector<PhaseRate>& Phases() const;
    const std::vector<DriverReport>& Reports() const;

private:
    struct Snapshot {
        Clock::time_point at;
        std::vector<Telemetry::Import> imports;
        std::vector<Telemetry::Thread> threads;
        std::vector<Telemetry::Phase> phases;
    };

    void computeRates();
    double milliseconds(std::uint64_t ticks) const;

    Telemetry::Reader _reader;
    std::uint64_t _pid = 0;
    Telemetry::Header _header{};
    std::uint64_t _lastPublishes = 0;
    Clock::time_point _lastChange{};
    std::deque<Snapshot> _history;
    std::vector<ImportRate> _imports;
    std::vector<ThreadRate> _threads;
    std::deque<FrameSample> _frames;
    std::uint64_t _lastFrame = 0;
    std::uint64_t _lastPresent = 0;
    std::uint64_t _lastGpu = 0;
    std::uint64_t _lastDriver = 0;
    std::uint64_t _lastDraws = 0;
    std::uint64_t _lastDispatches = 0;
    std::deque<SlowCallView> _slow;
    std::uint64_t _lastSlow = 0;
    std::vector<Telemetry::RecentCall> _recent;
    std::deque<WatchedCallView> _watched;
    std::uint64_t _lastWatched = 0;
    std::vector<PhaseRate> _phases;
    std::vector<DriverReport> _reports;
    Clock::time_point _reportsRead{};
    std::vector<std::string> _importNames;
    std::unordered_map<std::string, std::string> _names;
    mutable ThreadNames _threadNames;
    double _windowSeconds = 1.0;
    Clock::time_point _connectedAt{};
};

}

#endif
