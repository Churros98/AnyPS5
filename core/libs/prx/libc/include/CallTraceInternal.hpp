#ifndef CORE_LIBS_PRX_LIBC_INCLUDE_CALLTRACEINTERNAL_HPP
#define CORE_LIBS_PRX_LIBC_INCLUDE_CALLTRACEINTERNAL_HPP

#include "prx/libc/include/general/VabiMacros.hpp"
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string>

struct CallTraceImportRecord {
    void* target = nullptr;
    std::string name;
    std::string library;
    mutable std::atomic<std::uint64_t> calls{0};
};

using CallTraceReportWriter = void (*)(const char* text, std::size_t length);
using CallTraceModuleLookup = bool (*)(std::uint64_t address, char* name, std::size_t capacity, std::uint64_t* base);

extern "C" {
const CallTraceImportRecord* CallTraceRecords_nid_no_patch(std::size_t* count);
void CallTraceAllocateRing_nid_no_patch();
std::uint64_t CallTraceCurrentThread_nid_no_patch();
void APS5_VABI CallTraceRecord_nid_no_patch(const void* record, std::uint64_t returnAddress);
void CallTraceWriteReport_nid_no_patch(CallTraceReportWriter writer, CallTraceModuleLookup lookup);
#ifdef __linux__
void CallTraceInstallAbortReport_nid_no_patch();
void CallTraceSnapshotModules_nid_no_patch();
#endif
#ifdef APS5_ENABLE_PROFILER
bool CallProfileRequested_nid_no_patch();
bool CallProfileStart_nid_no_patch();
bool CallProfileTimes_nid_no_patch(const char* name, const char* library);
void CallProfileEnter_nid_no_patch();
void CallProfileExit_nid_no_patch();
std::uint64_t CallTelemetrySlowTicks_nid_no_patch(double nanosecondsPerTick);
void CallTelemetryNoteWatched_nid_no_patch(std::size_t import, std::uint64_t thread, const std::uint64_t* arguments, std::uint64_t result, std::uint64_t ticks, std::uint64_t returnAddress);
bool CallProfileWatch_nid_no_patch(std::uint64_t import, std::uint64_t count, char* message, std::size_t capacity);
std::uint64_t CallProfileSetSlowMicroseconds_nid_no_patch(std::uint64_t microseconds);
void CallTelemetryNoteSlow_nid_no_patch(std::size_t import, std::uint64_t ticks, std::uint64_t endTicks, std::uint64_t thread, std::uint64_t returnAddress);
#endif
}

#endif
