#if defined(_WIN32) || defined(__linux__)
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif
#include "prx/libc/include/CallTrace.hpp"
#include "prx/libc/include/CallTraceInternal.hpp"
#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>

namespace {

struct RingSlot {
    std::atomic<std::uint64_t> sequence{0};
    std::atomic<std::uint64_t> thread{0};
    std::atomic<std::uint64_t> returnAddress{0};
    std::atomic<const CallTraceImportRecord*> record{nullptr};
};

constexpr std::size_t RingCapacity = 65536;

std::atomic<RingSlot*> g_ring{nullptr};
std::atomic<std::uint64_t> g_sequence{0};

std::uint64_t CurrentThread() {
#ifdef _WIN32
    return GetCurrentThreadId();
#else
    return static_cast<std::uint64_t>(gettid());
#endif
}

}

extern "C" {

std::uint64_t CallTraceCurrentThread_nid_no_patch() {
    return CurrentThread();
}

void CallTraceAllocateRing_nid_no_patch() {
    g_ring.store(new RingSlot[RingCapacity], std::memory_order_release);
}

void APS5_VABI CallTraceRecord_nid_no_patch(const void* record, std::uint64_t returnAddress) {
    static_cast<const CallTraceImportRecord*>(record)->calls.fetch_add(1, std::memory_order_relaxed);
    const std::uint64_t sequence = g_sequence.fetch_add(1, std::memory_order_relaxed) + 1;
    RingSlot& slot = g_ring.load(std::memory_order_relaxed)[sequence % RingCapacity];
    slot.sequence.store(0, std::memory_order_release);
    slot.thread.store(CurrentThread(), std::memory_order_relaxed);
    slot.returnAddress.store(returnAddress, std::memory_order_relaxed);
    slot.record.store(static_cast<const CallTraceImportRecord*>(record), std::memory_order_relaxed);
    slot.sequence.store(sequence, std::memory_order_release);
}

std::size_t CopyCallTrace_nid_no_patch(CallTraceEntry* entries, std::size_t capacity) {
    const RingSlot* ring = g_ring.load(std::memory_order_acquire);
    if (entries == nullptr || capacity == 0 || ring == nullptr) return 0;
    const std::uint64_t last = g_sequence.load(std::memory_order_acquire);
    const std::uint64_t span = std::min<std::uint64_t>({last, capacity, RingCapacity});
    std::size_t count = 0;
    for (std::uint64_t sequence = last - span + 1; sequence <= last; ++sequence) {
        const RingSlot& slot = ring[sequence % RingCapacity];
        if (slot.sequence.load(std::memory_order_acquire) != sequence) continue;
        const auto* record = slot.record.load(std::memory_order_relaxed);
        const CallTraceEntry entry{sequence, slot.thread.load(std::memory_order_relaxed), slot.returnAddress.load(std::memory_order_relaxed), record->name.c_str(), record->library.c_str()};
        if (slot.sequence.load(std::memory_order_acquire) != sequence) continue;
        entries[count++] = entry;
    }
    return count;
}

std::size_t CopyThreadCallTrace_nid_no_patch(std::uint64_t thread, CallTraceEntry* entries, std::size_t capacity) {
    const RingSlot* ring = g_ring.load(std::memory_order_acquire);
    if (entries == nullptr || capacity == 0 || ring == nullptr) return 0;
    const std::uint64_t last = g_sequence.load(std::memory_order_acquire);
    const std::uint64_t span = std::min<std::uint64_t>(last, RingCapacity);
    std::size_t count = 0;
    for (std::uint64_t sequence = last; sequence > last - span && count < capacity; --sequence) {
        const RingSlot& slot = ring[sequence % RingCapacity];
        if (slot.sequence.load(std::memory_order_acquire) != sequence || slot.thread.load(std::memory_order_relaxed) != thread) continue;
        const auto* record = slot.record.load(std::memory_order_relaxed);
        const CallTraceEntry entry{sequence, thread, slot.returnAddress.load(std::memory_order_relaxed), record->name.c_str(), record->library.c_str()};
        if (slot.sequence.load(std::memory_order_acquire) != sequence) continue;
        entries[count++] = entry;
    }
    std::reverse(entries, entries + count);
    return count;
}

std::size_t CopyCallCounts_nid_no_patch(CallTraceCount* entries, std::size_t capacity, std::uint64_t* total) {
    if (total != nullptr) *total = g_sequence.load(std::memory_order_acquire);
    if (entries == nullptr || capacity == 0) return 0;
    std::size_t recorded = 0;
    const CallTraceImportRecord* records = CallTraceRecords_nid_no_patch(&recorded);
    std::size_t count = 0;
    for (std::size_t index = 0; index < recorded; ++index) {
        const CallTraceImportRecord& record = records[index];
        const std::uint64_t calls = record.calls.load(std::memory_order_relaxed);
        if (calls == 0 || (count == capacity && calls <= entries[count - 1].calls)) continue;
        std::size_t position = count < capacity ? count++ : count - 1;
        while (position > 0 && entries[position - 1].calls < calls) {
            entries[position] = entries[position - 1];
            --position;
        }
        entries[position] = {calls, record.name.c_str(), record.library.c_str()};
    }
    return count;
}

}

#endif
