#ifndef CORE_LIBS_PRX_LIBC_INCLUDE_CALLPROFILE_HPP
#define CORE_LIBS_PRX_LIBC_INCLUDE_CALLPROFILE_HPP

#include <cstddef>
#include <cstdint>

constexpr std::size_t CallProfileHistogramBuckets = 32;

struct CallProfileEntry {
    const char* name;
    const char* library;
    std::uint64_t calls;
    std::uint64_t timedCalls;
    std::uint64_t inclusiveTicks;
    std::uint64_t exclusiveTicks;
    std::uint64_t maxTicks;
    std::uint64_t histogram[CallProfileHistogramBuckets];
};

extern "C" {
std::size_t CallProfileRecordCount_nid_no_patch();
bool CallProfileReadRecord_nid_no_patch(std::size_t index, CallProfileEntry* entry);
std::size_t CopyCallProfile_nid_no_patch(CallProfileEntry* entries, std::size_t capacity);
double CallProfileNanosecondsPerTick_nid_no_patch();
std::uint64_t CallProfileOverheadTicks_nid_no_patch();
}

#endif
