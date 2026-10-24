#if (defined(_WIN32) || defined(__linux__)) && defined(APS5_ENABLE_PROFILER)
#ifdef _WIN32
#include <windows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#endif
#include "prx/libc/include/CallProfile.hpp"
#include "prx/libc/include/CallTrace.hpp"
#include "prx/libc/include/CallTraceInternal.hpp"
#include "prx/libc/include/Telemetry.hpp"
#include "prx/libc/include/TelemetryReader.hpp"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

namespace {

constexpr auto PublishInterval = std::chrono::milliseconds(100);
constexpr std::uint64_t DefaultSlowMicroseconds = 1000;

std::once_flag g_once;
Telemetry::Block* g_block = nullptr;
std::filesystem::path g_discovery;
std::atomic<Telemetry::StackSampler> g_sampler{nullptr};
std::atomic<bool> g_sampling{false};
std::mutex g_phaseMutex;

std::uint64_t ProcessId() {
#ifdef _WIN32
    return GetCurrentProcessId();
#else
    return static_cast<std::uint64_t>(getpid());
#endif
}

Telemetry::Block* MapBlock(const std::string& name) {
#ifdef _WIN32
    const HANDLE mapping = CreateFileMappingA(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, static_cast<DWORD>(sizeof(Telemetry::Block)), name.c_str());
    if (mapping == nullptr) throw std::system_error(static_cast<int>(GetLastError()), std::system_category(), "telemetry: CreateFileMappingA");
    if (GetLastError() == ERROR_ALREADY_EXISTS) throw std::runtime_error("telemetry: " + name + " already exists");
    void* view = MapViewOfFile(mapping, FILE_MAP_WRITE, 0, 0, sizeof(Telemetry::Block));
    if (view == nullptr) throw std::system_error(static_cast<int>(GetLastError()), std::system_category(), "telemetry: MapViewOfFile");
    return static_cast<Telemetry::Block*>(view);
#else
    shm_unlink(name.c_str());
    const int file = shm_open(name.c_str(), O_CREAT | O_EXCL | O_RDWR, 0600);
    if (file < 0) throw std::system_error(errno, std::generic_category(), "telemetry: shm_open");
    if (ftruncate(file, sizeof(Telemetry::Block)) != 0) {
        const int code = errno;
        close(file);
        throw std::system_error(code, std::generic_category(), "telemetry: ftruncate");
    }
    void* view = mmap(nullptr, sizeof(Telemetry::Block), PROT_READ | PROT_WRITE, MAP_SHARED, file, 0);
    const int code = errno;
    close(file);
    if (view == MAP_FAILED) throw std::system_error(code, std::generic_category(), "telemetry: mmap");
    return static_cast<Telemetry::Block*>(view);
#endif
}

void RemoveDiscovery() {
    std::error_code ignored;
    std::filesystem::remove(g_discovery, ignored);
#ifndef _WIN32
    shm_unlink(Telemetry::MappingName(ProcessId()).c_str());
#endif
}

void WriteDiscovery(const std::string& name) {
    const std::filesystem::path directory = std::filesystem::temp_directory_path() / "anyps5-telemetry";
    std::filesystem::create_directories(directory);
    g_discovery = directory / std::to_string(ProcessId());
    std::ofstream file(g_discovery, std::ios::binary | std::ios::trunc);
    file << name << '\n';
    if (!file) throw std::runtime_error("telemetry: cannot write " + g_discovery.string());
    std::atexit(RemoveDiscovery);
}

void CopyName(char* destination, std::size_t capacity, const char* source) {
    std::strncpy(destination, source != nullptr ? source : "", capacity - 1);
    destination[capacity - 1] = '\0';
}

template <typename TEntry, typename TFill>
void PublishEntry(TEntry& entry, TFill fill) {
    const std::uint64_t sequence = Telemetry::Load(entry.sequence);
    Telemetry::Store(entry.sequence, sequence + 1);
    std::atomic_thread_fence(std::memory_order_release);
    fill(entry);
    Telemetry::Store(entry.sequence, sequence + 2);
}

template <typename TEntry, std::size_t Capacity, typename TFill>
void AppendEntry(TEntry (&ring)[Capacity], std::uint64_t& written, TFill fill) {
    const std::uint64_t index = std::atomic_ref<std::uint64_t>(written).fetch_add(1, std::memory_order_acq_rel) + 1;
    TEntry& entry = ring[index % Capacity];
    Telemetry::Store(entry.sequence, index * 2 - 1);
    std::atomic_thread_fence(std::memory_order_release);
    fill(entry);
    Telemetry::Store(entry.sequence, index * 2);
}

template <typename TEntry, std::size_t Capacity, typename TFill>
void WriteSlot(TEntry (&ring)[Capacity], std::uint64_t index, TFill fill) {
    TEntry& entry = ring[index % Capacity];
    Telemetry::Store(entry.sequence, index * 2 - 1);
    std::atomic_thread_fence(std::memory_order_release);
    fill(entry);
    Telemetry::Store(entry.sequence, index * 2);
}

void Respond(std::uint64_t index, Telemetry::CommandStatus status, std::uint64_t value, const std::string& message) {
    WriteSlot(g_block->responses, index, [&](Telemetry::Response& response) {
        response.status = static_cast<std::uint64_t>(status);
        response.value = value;
        CopyName(response.message, sizeof(response.message), message.c_str());
    });
}

void Execute(std::uint64_t index, const Telemetry::Command& command) {
    switch (static_cast<Telemetry::CommandKind>(command.kind)) {
        case Telemetry::CommandKind::WatchImport: {
            char message[Telemetry::MessageBytes] = "";
            const bool watched = CallProfileWatch_nid_no_patch(command.arguments[0], command.arguments[1], message, sizeof(message));
            Respond(index, watched ? Telemetry::CommandStatus::Done : Telemetry::CommandStatus::Failed, command.arguments[1], message);
            return;
        }
        case Telemetry::CommandKind::SetSlowThreshold: {
            const std::uint64_t ticks = CallProfileSetSlowMicroseconds_nid_no_patch(command.arguments[0]);
            if (ticks == 0) {
                Respond(index, Telemetry::CommandStatus::Failed, 0, "slow calls need APS5_PROFILE_CALLS and a threshold from 1 to 60000000 microseconds");
                return;
            }
            Telemetry::Store(g_block->header.slowTicks, ticks);
            Respond(index, Telemetry::CommandStatus::Done, ticks, "");
            return;
        }
        case Telemetry::CommandKind::SampleStacks: {
            const Telemetry::StackSampler sampler = g_sampler.load(std::memory_order_acquire);
            if (sampler == nullptr) {
                Respond(index, Telemetry::CommandStatus::Failed, 0, "no stack sampler: it is provided by the agc driver on Windows once the title presents");
                return;
            }
            if (command.arguments[0] == 0 || command.arguments[0] > 30000 || command.arguments[1] < 100 || command.arguments[1] > 100000 || command.arguments[2] == 0 || command.arguments[2] > 64) {
                Respond(index, Telemetry::CommandStatus::Failed, 0, "sampling takes 1 to 30000 ms, an interval of 100 to 100000 us and a depth of 1 to 64");
                return;
            }
            if (g_sampling.exchange(true, std::memory_order_acq_rel)) {
                Respond(index, Telemetry::CommandStatus::Failed, 0, "a stack sample is already running");
                return;
            }
            std::thread([index, command, sampler] {
                char message[Telemetry::MessageBytes] = "";
                const bool sampled = sampler(command.arguments[0], command.arguments[1], command.arguments[2], message, sizeof(message));
                g_sampling.store(false, std::memory_order_release);
                Respond(index, sampled ? Telemetry::CommandStatus::Done : Telemetry::CommandStatus::Failed, 0, message);
            }).detach();
            return;
        }
    }
    Respond(index, Telemetry::CommandStatus::Failed, 0, "unknown command " + std::to_string(command.kind));
}

void ProcessCommands(std::uint64_t& processed) {
    const std::uint64_t written = Telemetry::Load(g_block->header.commandsWritten);
    while (processed < written) {
        const std::uint64_t index = processed + 1;
        Telemetry::Command command{};
        if (!Telemetry::ReadEntry(g_block->commands[index % Telemetry::CommandCapacity], command, index * 2)) return;
        processed = index;
        Execute(index, command);
    }
}

void PublishLoop() {
    Telemetry::Header& header = g_block->header;
    std::vector<CallProfileThread> threads(Telemetry::ThreadCapacity);
    std::vector<CallTraceEntry> recent(Telemetry::RecentCapacity);
    std::uint64_t lastRecent = 0;
    std::uint64_t processed = Telemetry::Load(header.commandsWritten);
    for (;;) {
        ProcessCommands(processed);
        const double nanosecondsPerTick = CallProfileNanosecondsPerTick_nid_no_patch();
        Telemetry::Store(header.ticksPerSecond, nanosecondsPerTick > 0 ? static_cast<std::uint64_t>(1e9 / nanosecondsPerTick) : 0);
        Telemetry::Store(header.overheadTicks, CallProfileOverheadTicks_nid_no_patch());
        const std::size_t imports = std::min(CallProfileRecordCount_nid_no_patch(), Telemetry::ImportCapacity);
        for (std::size_t index = 0; index < imports; ++index) {
            CallProfileEntry entry{};
            if (!CallProfileReadRecord_nid_no_patch(index, &entry)) continue;
            PublishEntry(g_block->imports[index], [&entry](Telemetry::Import& target) {
                target.calls = entry.calls;
                target.timedCalls = entry.timedCalls;
                target.inclusiveTicks = entry.inclusiveTicks;
                target.exclusiveTicks = entry.exclusiveTicks;
                target.maxTicks = entry.maxTicks;
                std::copy(std::begin(entry.histogram), std::end(entry.histogram), target.histogram);
                CopyName(target.name, sizeof(target.name), entry.name);
                CopyName(target.library, sizeof(target.library), entry.library);
            });
        }
        Telemetry::Store(header.imports, imports);
        const std::size_t threadCount = CopyCallProfileThreads_nid_no_patch(threads.data(), threads.size());
        for (std::size_t index = 0; index < threadCount; ++index) {
            PublishEntry(g_block->threads[index], [&thread = threads[index]](Telemetry::Thread& target) {
                target.thread = thread.thread;
                target.timedCalls = thread.timedCalls;
                target.topLevelTicks = thread.topLevelTicks;
            });
        }
        Telemetry::Store(header.threads, threadCount);
        const std::size_t recentCount = CopyCallTrace_nid_no_patch(recent.data(), recent.size());
        for (std::size_t index = 0; index < recentCount; ++index) {
            const CallTraceEntry& call = recent[index];
            if (call.sequence <= lastRecent) continue;
            AppendEntry(g_block->recent, header.recentWritten, [&call](Telemetry::RecentCall& target) {
                target.thread = call.thread;
                target.returnAddress = call.returnAddress;
                CopyName(target.name, sizeof(target.name), call.name);
                CopyName(target.library, sizeof(target.library), call.library);
            });
            lastRecent = call.sequence;
        }
        Telemetry::Store(header.publishes, Telemetry::Load(header.publishes) + 1);
        std::this_thread::sleep_for(PublishInterval);
    }
}

void Create() {
    const std::string name = Telemetry::MappingName(ProcessId());
    Telemetry::Block* block = MapBlock(name);
    Telemetry::Header& header = block->header;
    header.version = Telemetry::Version;
    header.headerBytes = sizeof(Telemetry::Header);
    header.totalBytes = sizeof(Telemetry::Block);
    header.pid = ProcessId();
    Telemetry::Store(header.magic, Telemetry::Magic);
    g_block = block;
    WriteDiscovery(name);
    std::thread(PublishLoop).detach();
}

}

extern "C" {

bool TelemetryEnabled_nid_no_patch() {
    std::call_once(g_once, Create);
    return g_block != nullptr;
}

void TelemetryNotePresent_nid_no_patch(const Telemetry::Present* present) {
    if (present == nullptr || !TelemetryEnabled_nid_no_patch()) return;
    AppendEntry(g_block->frames, g_block->header.framesWritten, [present](Telemetry::Frame& target) {
        target.presentNanoseconds = present->presentNanoseconds;
        target.gpuNanoseconds = present->gpuNanoseconds;
        target.driverNanoseconds = present->driverNanoseconds;
        target.draws = present->draws;
        target.dispatches = present->dispatches;
        target.flags = present->flags;
    });
}

std::uint64_t CallTelemetrySlowTicks_nid_no_patch(double nanosecondsPerTick) {
    std::uint64_t microseconds = DefaultSlowMicroseconds;
    if (const char* value = std::getenv("APS5_MONITOR_SLOW_US"); value != nullptr && *value != '\0') {
        char* end = nullptr;
        microseconds = std::strtoull(value, &end, 10);
        if (end == value || *end != '\0' || microseconds == 0 || microseconds > 60000000) throw std::runtime_error("APS5_MONITOR_SLOW_US must be a whole number of microseconds from 1 to 60000000");
    }
    if (nanosecondsPerTick <= 0) return 0;
    const auto ticks = std::max<std::uint64_t>(1, static_cast<std::uint64_t>(static_cast<double>(microseconds) * 1e3 / nanosecondsPerTick));
    Telemetry::Store(g_block->header.slowTicks, ticks);
    return ticks;
}

void TelemetryRegisterStackSampler_nid_no_patch(Telemetry::StackSampler sampler) {
    g_sampler.store(sampler, std::memory_order_release);
}

void TelemetryPublishPhases_nid_no_patch(const Telemetry::PhaseTotal* totals, std::size_t count) {
    if (totals == nullptr || !TelemetryEnabled_nid_no_patch()) return;
    std::scoped_lock lock(g_phaseMutex);
    const std::size_t published = std::min(count, Telemetry::PhaseCapacity);
    for (std::size_t index = 0; index < published; ++index) {
        PublishEntry(g_block->phases[index], [&total = totals[index]](Telemetry::Phase& target) {
            target.nanoseconds = total.nanoseconds;
            target.count = total.count;
            CopyName(target.thread, sizeof(target.thread), total.thread);
            const std::string name = std::string(total.scope != nullptr ? total.scope : "") + (total.stage != nullptr && *total.stage != '\0' ? std::string(".") + total.stage : std::string());
            CopyName(target.name, sizeof(target.name), name.c_str());
        });
    }
    Telemetry::Store(g_block->header.phases, published);
    Telemetry::Store(g_block->header.phasesPublishes, Telemetry::Load(g_block->header.phasesPublishes) + 1);
}

void CallTelemetryNoteWatched_nid_no_patch(std::size_t import, std::uint64_t thread, const std::uint64_t* arguments, std::uint64_t result, std::uint64_t ticks, std::uint64_t returnAddress) {
    if (g_block == nullptr) return;
    AppendEntry(g_block->watched, g_block->header.watchedWritten, [&](Telemetry::WatchedCall& target) {
        target.import = import;
        target.thread = thread;
        std::copy(arguments, arguments + Telemetry::WatchedArguments, target.arguments);
        target.result = result;
        target.ticks = ticks;
        target.returnAddress = returnAddress;
    });
}

void CallTelemetryNoteSlow_nid_no_patch(std::size_t import, std::uint64_t ticks, std::uint64_t endTicks, std::uint64_t thread, std::uint64_t returnAddress) {
    if (g_block == nullptr) return;
    AppendEntry(g_block->slow, g_block->header.slowWritten, [=](Telemetry::SlowCall& target) {
        target.endTicks = endTicks;
        target.ticks = ticks;
        target.thread = thread;
        target.returnAddress = returnAddress;
        target.import = import;
    });
}

}

#endif
