#include "prx/libc/include/CallTrace.hpp"
#include "prx/libc/include/Telemetry.hpp"
#include "prx/libc/include/TelemetryReader.hpp"
#include "prx/libc/include/general/VabiMacros.hpp"
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <source_location>
#include <stdexcept>
#include <string_view>
#include <string>
#include <thread>
#include <vector>

static void Require(bool condition, std::source_location location = std::source_location::current()) {
    if (!condition) {
        std::fprintf(stderr, "Telemetry check failed at line %u\n", location.line());
        std::abort();
    }
}

static std::uint64_t APS5_VABI Integers(std::uint64_t a, std::uint64_t b) {
    return a + 2 * b;
}

static void APS5_VABI Nap(std::uint64_t milliseconds) {
    std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
}

template <typename TFunction>
static TFunction* Traced(TFunction* function, const char* name, const char* library) {
    return reinterpret_cast<TFunction*>(TraceImport_nid_no_patch(reinterpret_cast<void*>(function), name, library));
}

static void SetVariable(const char* name, const char* value) {
#ifdef _WIN32
    Require(_putenv_s(name, value) == 0);
#else
    Require(setenv(name, value, 1) == 0);
#endif
}

static std::uint64_t ProcessId() {
#ifdef _WIN32
    return GetCurrentProcessId();
#else
    return static_cast<std::uint64_t>(getpid());
#endif
}

static std::uint64_t CurrentThread() {
#ifdef _WIN32
    return GetCurrentThreadId();
#else
    return static_cast<std::uint64_t>(gettid());
#endif
}

static const Telemetry::Import* FindImport(const std::vector<Telemetry::Import>& imports, const char* name) {
    const auto found = std::find_if(imports.begin(), imports.end(), [name](const Telemetry::Import& import) { return std::strcmp(import.name, name) == 0; });
    return found == imports.end() ? nullptr : &*found;
}

int main(int argc, char** argv) {
    SetVariable("APS5_TRACE_CALLS", "libTraced");
    SetVariable("APS5_PROFILE_CALLS", "3600");
    SetVariable("APS5_MONITOR_SLOW_US", "2000");
    if (argc > 1 && std::strcmp(argv[1], "invalid-slow") == 0) {
        SetVariable("APS5_MONITOR_SLOW_US", "0");
        try {
            Traced(&Nap, "Nap", "libTraced.prx");
        } catch (const std::runtime_error& error) {
            Require(std::string_view(error.what()).find("APS5_MONITOR_SLOW_US") != std::string_view::npos);
            return 0;
        }
        Require(false);
    }
    if (argc > 1 && std::strcmp(argv[1], "counts-only") == 0) {
        SetVariable("APS5_PROFILE_CALLS", "0");
        const auto counted = Traced(&Integers, "Integers", "libTraced.prx");
        for (std::uint64_t call = 0; call < 10; ++call) Require(counted(call, 1) == call + 2);
        const Telemetry::Present present{16000000, 0, 0, 1, 0, 0};
        TelemetryNotePresent_nid_no_patch(&present);
        Telemetry::Reader counts;
        Require(counts.Open(ProcessId()));
        const std::uint64_t published = counts.ReadHeader().publishes;
        const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (counts.ReadHeader().publishes < published + 2 && std::chrono::steady_clock::now() < until) std::this_thread::sleep_for(std::chrono::milliseconds(10));
        const Telemetry::Header header = counts.ReadHeader();
        Require(header.ticksPerSecond == 0 && header.overheadTicks == 0 && header.slowTicks == 0);
        const auto imports = counts.ReadImports();
        const Telemetry::Import* import = FindImport(imports, "Integers");
        Require(import != nullptr && import->calls == 10 && import->timedCalls == 0 && import->inclusiveTicks == 0);
        Require(counts.ReadThreads().empty() && counts.ReadSlowCalls().empty());
        Require(counts.ReadFrames().size() == 1 && counts.ReadRecentCalls().size() == 10);
        return 0;
    }

    Telemetry::Reader closed;
    Require(!closed.Open(ProcessId()));
    const auto integers = Traced(&Integers, "Integers", "libTraced.prx");
    const auto nap = Traced(&Nap, "Nap", "libTraced.prx");
    Require(TelemetryEnabled_nid_no_patch());

    for (std::uint64_t call = 0; call < 100; ++call) Require(integers(call, 1) == call + 2);
    nap(3);
    nap(3);
    for (std::uint64_t frame = 1; frame <= 3; ++frame) {
        const Telemetry::Present present{frame * 16000000, frame * 1000, frame * 2000, frame * 10, frame, Telemetry::PresentGpuTimed};
        TelemetryNotePresent_nid_no_patch(&present);
    }

    Telemetry::Reader reader;
    Require(reader.Open(ProcessId()));
    const Telemetry::Header first = reader.ReadHeader();
    Require(first.version == Telemetry::Version && first.totalBytes == sizeof(Telemetry::Block) && first.pid == ProcessId());
    Require(first.slowTicks != 0);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (reader.ReadHeader().publishes < first.publishes + 2 && std::chrono::steady_clock::now() < deadline) std::this_thread::sleep_for(std::chrono::milliseconds(10));
    const Telemetry::Header header = reader.ReadHeader();
    Require(header.publishes >= first.publishes + 2);
    Require(header.ticksPerSecond != 0);

    const auto imports = reader.ReadImports();
    const Telemetry::Import* busy = FindImport(imports, "Integers");
    const Telemetry::Import* slept = FindImport(imports, "Nap");
    Require(busy != nullptr && busy->calls == 100 && busy->timedCalls == 100 && std::strcmp(busy->library, "libTraced.prx") == 0);
    Require(slept != nullptr && slept->timedCalls == 2);
    Require(static_cast<double>(slept->inclusiveTicks) / static_cast<double>(header.ticksPerSecond) >= 0.0059);

    const auto threads = reader.ReadThreads();
    const auto own = std::find_if(threads.begin(), threads.end(), [](const Telemetry::Thread& thread) { return thread.thread == CurrentThread(); });
    Require(own != threads.end() && own->timedCalls == 102);
    Require(own->topLevelTicks >= slept->inclusiveTicks);

    const auto slow = reader.ReadSlowCalls();
    Require(slow.size() == 2);
    for (const Telemetry::SlowCall& call : slow) {
        Require(call.thread == CurrentThread() && call.ticks >= header.slowTicks);
        Require(std::strcmp(imports[call.import].name, "Nap") == 0);
    }
    Require(reader.ReadSlowCalls(slow.back().sequence / 2).empty());

    const auto frames = reader.ReadFrames();
    Require(frames.size() == 3);
    for (std::size_t index = 0; index < frames.size(); ++index) {
        const std::uint64_t frame = index + 1;
        Require(frames[index].presentNanoseconds == frame * 16000000 && frames[index].gpuNanoseconds == frame * 1000 && frames[index].driverNanoseconds == frame * 2000);
        Require(frames[index].draws == frame * 10 && frames[index].dispatches == frame && frames[index].flags == Telemetry::PresentGpuTimed);
    }
    Require(reader.ReadFrames(2).size() == 1);

    const auto recent = reader.ReadRecentCalls();
    Require(recent.size() == 64 && std::strcmp(recent.back().name, "Nap") == 0 && recent.back().thread == CurrentThread());

    Require(Telemetry::ReportTag("[recipe] draw (10 s): hits 3") == "[recipe] draw");
    Require(Telemetry::ReportTag("[buffers] 12 uploads: import lookup 0.5") == "[buffers] # uploads");
    Require(Telemetry::ReportTag("[rescache] (cumulative): 4 hits") == "[rescache]");
    Require(Telemetry::ReportTag("[guestmem]\n") == "[guestmem]");
    Require(Telemetry::ReportTag("[dispatch] 16000 dispatches, phase totals: reap=0s") == "[dispatch] # dispatches");
    Require(Telemetry::ReportTag("Graphics.Draw 12 us").empty());
    TelemetryPublishReport_nid_no_patch("[recipe] draw (10 s): hits 1\n");
    TelemetryPublishReport_nid_no_patch("not a report line\n");
    TelemetryPublishReport_nid_no_patch("[buffers] 12 uploads: first\n");
    TelemetryPublishReport_nid_no_patch("[recipe] draw (10 s): hits 2\n");
    TelemetryPublishReport_nid_no_patch("[buffers] 7 uploads: second\n");
    auto reports = reader.ReadReports();
    Require(reports.size() == 2 && reader.ReadHeader().reports == 2);
    Require(std::strcmp(reports[0].tag, "[recipe] draw") == 0 && std::strcmp(reports[0].text, "[recipe] draw (10 s): hits 2") == 0 && reports[0].updates == 2);
    Require(std::strcmp(reports[1].tag, "[buffers] # uploads") == 0 && std::strcmp(reports[1].text, "[buffers] 7 uploads: second") == 0 && reports[1].updates == 2);
    Require(reports[1].nanoseconds >= reports[0].nanoseconds);
    for (std::size_t index = 0; index < Telemetry::ReportCapacity; ++index) {
        const std::string line = "[fill" + std::string(1, static_cast<char>('a' + index % 26)) + std::string(1, static_cast<char>('a' + index / 26)) + "] line";
        TelemetryPublishReport_nid_no_patch(line.c_str());
    }
    reports = reader.ReadReports();
    Require(reports.size() == Telemetry::ReportCapacity);
    Require(std::none_of(reports.begin(), reports.end(), [](const Telemetry::Report& report) { return std::strcmp(report.tag, "[recipe] draw") == 0 || std::strcmp(report.tag, "[buffers] # uploads") == 0; }));
    Require(std::any_of(reports.begin(), reports.end(), [](const Telemetry::Report& report) { return std::strcmp(report.tag, "[fillbc] line") == 0; }));

    const auto discovery = std::filesystem::temp_directory_path() / "anyps5-telemetry" / std::to_string(ProcessId());
    Require(std::filesystem::exists(discovery));

    if (argc == 3 && std::strcmp(argv[1], "monitor") == 0) {
        const std::string command = "\"\"" + std::string(argv[2]) + "\" --dump --pid " + std::to_string(ProcessId()) + " --seconds 0.5\"";
#ifdef _WIN32
        FILE* output = _popen(command.c_str(), "r");
#else
        FILE* output = popen(command.substr(1, command.size() - 2).c_str(), "r");
#endif
        Require(output != nullptr);
        std::string text;
        char buffer[4096];
        while (std::fgets(buffer, sizeof(buffer), output) != nullptr) text += buffer;
#ifdef _WIN32
        const int status = _pclose(output);
#else
        const int status = pclose(output);
#endif
        std::fputs(text.c_str(), stdout);
        Require(status == 0 || status == 2 || (status >> 8) == 2);
        Require(text.find("pid " + std::to_string(ProcessId())) != std::string::npos);
        Require(text.find("libTraced.prx Integers") != std::string::npos && text.find("libTraced.prx Nap") != std::string::npos);
        Require(text.find("slow calls (2,") != std::string::npos);
        Require(text.find("verdict:") != std::string::npos);
    }
}
