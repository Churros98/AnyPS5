#ifndef CORE_LIBS_PRX_LIBC_INCLUDE_TELEMETRY_HPP
#define CORE_LIBS_PRX_LIBC_INCLUDE_TELEMETRY_HPP

#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace Telemetry {

constexpr std::uint64_t Magic = 0x4d4c5435535041ull;
constexpr std::uint32_t Version = 2;
constexpr std::size_t FrameCapacity = 1024;
constexpr std::size_t ImportCapacity = 4096;
constexpr std::size_t ThreadCapacity = 256;
constexpr std::size_t SlowCapacity = 4096;
constexpr std::size_t RecentCapacity = 64;
constexpr std::size_t HistogramBuckets = 32;
constexpr std::size_t NameBytes = 64;
constexpr std::size_t LibraryBytes = 48;
constexpr std::size_t CommandCapacity = 16;
constexpr std::size_t MessageBytes = 512;
constexpr std::size_t WatchedCapacity = 1024;
constexpr std::size_t WatchedArguments = 6;
constexpr std::size_t PhaseCapacity = 512;
constexpr std::size_t PhaseThreadBytes = 32;
constexpr std::size_t PhaseNameBytes = 64;

enum class CommandKind : std::uint64_t { WatchImport = 1, SetSlowThreshold = 2, SampleStacks = 3 };
enum class CommandStatus : std::uint64_t { Done = 1, Failed = 2 };

constexpr std::uint64_t PresentGpuTimed = 1;
constexpr std::uint64_t PresentDriverTimed = 2;
constexpr std::uint64_t PresentClearOnly = 4;

struct Header {
    std::uint64_t magic;
    std::uint32_t version;
    std::uint32_t headerBytes;
    std::uint64_t totalBytes;
    std::uint64_t pid;
    std::uint64_t ticksPerSecond;
    std::uint64_t overheadTicks;
    std::uint64_t slowTicks;
    std::uint64_t publishes;
    std::uint64_t imports;
    std::uint64_t threads;
    std::uint64_t framesWritten;
    std::uint64_t slowWritten;
    std::uint64_t recentWritten;
    std::uint64_t commandsWritten;
    std::uint64_t watchedWritten;
    std::uint64_t phases;
    std::uint64_t phasesPublishes;
};

struct Frame {
    std::uint64_t sequence;
    std::uint64_t presentNanoseconds;
    std::uint64_t gpuNanoseconds;
    std::uint64_t driverNanoseconds;
    std::uint64_t draws;
    std::uint64_t dispatches;
    std::uint64_t flags;
};

struct Import {
    std::uint64_t sequence;
    std::uint64_t calls;
    std::uint64_t timedCalls;
    std::uint64_t inclusiveTicks;
    std::uint64_t exclusiveTicks;
    std::uint64_t maxTicks;
    std::uint64_t histogram[HistogramBuckets];
    char name[NameBytes];
    char library[LibraryBytes];
};

struct Thread {
    std::uint64_t sequence;
    std::uint64_t thread;
    std::uint64_t timedCalls;
    std::uint64_t topLevelTicks;
};

struct SlowCall {
    std::uint64_t sequence;
    std::uint64_t endTicks;
    std::uint64_t ticks;
    std::uint64_t thread;
    std::uint64_t returnAddress;
    std::uint64_t import;
};

struct RecentCall {
    std::uint64_t sequence;
    std::uint64_t thread;
    std::uint64_t returnAddress;
    char name[NameBytes];
    char library[LibraryBytes];
};

struct Command {
    std::uint64_t sequence;
    std::uint64_t kind;
    std::uint64_t arguments[4];
};

struct Response {
    std::uint64_t sequence;
    std::uint64_t status;
    std::uint64_t value;
    char message[MessageBytes];
};

struct WatchedCall {
    std::uint64_t sequence;
    std::uint64_t import;
    std::uint64_t thread;
    std::uint64_t arguments[WatchedArguments];
    std::uint64_t result;
    std::uint64_t ticks;
    std::uint64_t returnAddress;
};

struct Phase {
    std::uint64_t sequence;
    std::uint64_t nanoseconds;
    std::uint64_t count;
    char thread[PhaseThreadBytes];
    char name[PhaseNameBytes];
};

struct Block {
    Header header;
    Frame frames[FrameCapacity];
    Import imports[ImportCapacity];
    Thread threads[ThreadCapacity];
    SlowCall slow[SlowCapacity];
    RecentCall recent[RecentCapacity];
    Command commands[CommandCapacity];
    Response responses[CommandCapacity];
    WatchedCall watched[WatchedCapacity];
    Phase phases[PhaseCapacity];
};

static_assert(std::is_standard_layout_v<Block> && std::is_trivially_copyable_v<Block>);

struct Present {
    std::uint64_t presentNanoseconds;
    std::uint64_t gpuNanoseconds;
    std::uint64_t driverNanoseconds;
    std::uint64_t draws;
    std::uint64_t dispatches;
    std::uint64_t flags;
};

struct PhaseTotal {
    const char* thread;
    const char* scope;
    const char* stage;
    std::uint64_t nanoseconds;
    std::uint64_t count;
};

using StackSampler = bool (*)(std::uint64_t milliseconds, std::uint64_t intervalMicroseconds, std::uint64_t depth, char* message, std::size_t capacity);

}

extern "C" {
bool TelemetryEnabled_nid_no_patch();
void TelemetryNotePresent_nid_no_patch(const Telemetry::Present* present);
void TelemetryPublishPhases_nid_no_patch(const Telemetry::PhaseTotal* totals, std::size_t count);
void TelemetryRegisterStackSampler_nid_no_patch(Telemetry::StackSampler sampler);
}

#endif
