#if defined(_WIN32) || defined(__linux__)
#include "prx/libc/include/CallTrace.hpp"
#include "prx/libc/include/CallTraceInternal.hpp"
#ifdef APS5_ENABLE_PROFILER
#include "prx/libc/include/CallProfile.hpp"
#endif
#include <cstddef>
#include <cstdint>
#include <iterator>

namespace {

class ReportLine {
public:
    explicit ReportLine(CallTraceReportWriter writer) : _writer(writer) {}

    ReportLine& Text(const char* text) {
        while (*text != '\0' && _length < sizeof(_buffer)) _buffer[_length++] = *text++;
        return *this;
    }

    ReportLine& Decimal(std::uint64_t value, std::size_t width = 0) {
        char digits[20];
        std::size_t count = 0;
        do {
            digits[count++] = static_cast<char>('0' + value % 10);
            value /= 10;
        } while (value != 0);
        for (std::size_t pad = count; pad < width; ++pad) Text(" ");
        while (count > 0 && _length < sizeof(_buffer)) _buffer[_length++] = digits[--count];
        return *this;
    }

    ReportLine& Hex(std::uint64_t value, std::size_t digits) {
        while (digits < 16 && (value >> (digits * 4)) != 0) ++digits;
        Text("0x");
        for (std::size_t index = digits; index > 0 && _length < sizeof(_buffer); --index) {
            _buffer[_length++] = "0123456789abcdef"[(value >> ((index - 1) * 4)) & 0xf];
        }
        return *this;
    }

    void Write() {
        Text("\n");
        _writer(_buffer, _length);
        _length = 0;
    }

private:
    CallTraceReportWriter _writer;
    char _buffer[512];
    std::size_t _length = 0;
};

void DescribeAddress(ReportLine& line, std::uint64_t address, CallTraceModuleLookup lookup) {
    line.Hex(address, 16);
    char name[260];
    std::uint64_t base = 0;
    if (!lookup(address, name, sizeof(name), &base)) return;
    line.Text(" ").Text(name).Text("+");
    line.Hex(address - base, 1);
}

}

extern "C" void CallTraceWriteReport_nid_no_patch(CallTraceReportWriter writer, CallTraceModuleLookup lookup) {
    static CallTraceEntry entries[64];
    static CallTraceCount counts[32];
    static CallTraceEntry own[32];
    ReportLine line(writer);
    const std::size_t count = CopyCallTrace_nid_no_patch(entries, std::size(entries));
    if (count == 0) return;
    line.Text("  last traced system library calls (APS5_TRACE_CALLS):").Write();
    for (std::size_t index = 0; index < count; ++index) {
        line.Text("    #").Decimal(entries[index].sequence).Text(" thread ").Decimal(entries[index].thread);
        line.Text(" ").Text(entries[index].library).Text(" ").Text(entries[index].name).Text(" from ");
        DescribeAddress(line, entries[index].returnAddress, lookup);
        line.Write();
    }
    const std::uint64_t thread = CallTraceCurrentThread_nid_no_patch();
    const std::size_t owned = CopyThreadCallTrace_nid_no_patch(thread, own, std::size(own));
    if (owned != 0) {
        line.Text("  last traced calls of thread ").Decimal(thread).Text(":").Write();
        for (std::size_t index = 0; index < owned; ++index) {
            line.Text("    #").Decimal(own[index].sequence).Text(" ").Text(own[index].library).Text(" ").Text(own[index].name).Text(" from ");
            DescribeAddress(line, own[index].returnAddress, lookup);
            line.Write();
        }
    }
    std::uint64_t total = 0;
    const std::size_t counted = CopyCallCounts_nid_no_patch(counts, std::size(counts), &total);
    if (counted == 0) return;
    line.Text("  most called traced imports (").Decimal(total).Text(" calls in total):").Write();
    for (std::size_t index = 0; index < counted; ++index) {
        line.Text("    ").Decimal(counts[index].calls, 12).Text(" ").Text(counts[index].library).Text(" ").Text(counts[index].name).Write();
    }
#ifdef APS5_ENABLE_PROFILER
    static CallProfileEntry expensive[16];
    const std::size_t profiled = CopyCallProfile_nid_no_patch(expensive, std::size(expensive));
    if (profiled == 0) return;
    const double microsecondsPerTick = CallProfileNanosecondsPerTick_nid_no_patch() / 1e3;
    line.Text("  most expensive traced imports (exclusive us, timed calls):").Write();
    for (std::size_t index = 0; index < profiled; ++index) {
        const auto microseconds = static_cast<std::uint64_t>(static_cast<double>(expensive[index].exclusiveTicks) * microsecondsPerTick);
        line.Text("    ").Decimal(microseconds, 12).Text(" ").Decimal(expensive[index].timedCalls, 12).Text(" ").Text(expensive[index].library).Text(" ").Text(expensive[index].name).Write();
    }
#endif
}

#endif
