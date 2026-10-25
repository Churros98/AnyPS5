#include "Session.hpp"
#include "prx/libc/include/CallTrace.hpp"
#include "prx/libc/include/Telemetry.hpp"
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
#include <filesystem>
#include <fstream>
#include <source_location>
#include <string>
#include <thread>

static void Require(bool condition, std::source_location location = std::source_location::current()) {
    if (!condition) {
        std::fprintf(stderr, "Monitor session check failed at line %u\n", location.line());
        std::abort();
    }
}

static void APS5_VABI Nap(std::uint64_t milliseconds) {
    std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
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

static bool Contains(const std::string& text, const char* part) {
    return text.find(part) != std::string::npos;
}

static void Present(std::uint64_t& at, std::uint64_t frameMs, std::uint64_t& gpu, std::uint64_t gpuMs, std::uint64_t& driver, std::uint64_t driverMs, std::uint64_t flags) {
    at += frameMs * 1000000;
    gpu += gpuMs * 1000000;
    driver += driverMs * 1000000;
    const Telemetry::Present present{at, gpu, driver, 0, 0, flags};
    TelemetryNotePresent_nid_no_patch(&present);
}

static void WaitForPublishes(Monitor::Session& session, std::uint64_t count) {
    const std::uint64_t target = session.Header().publishes + count;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (session.Header().publishes < target && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        session.Poll();
    }
    Require(session.Header().publishes >= target);
}

int main() {
    SetVariable("APS5_TRACE_CALLS", "libTraced");
    SetVariable("APS5_PROFILE_CALLS", "3600");
    SetVariable("APS5_MONITOR_SLOW_US", "5000");

    const auto database = std::filesystem::temp_directory_path() / ("anyps5-monitor-names-" + std::to_string(ProcessId()) + ".csv");
    std::ofstream(database) << "AbCdEfGhIjK Nap\n";
    SetVariable("ANYPS5_NID_DB", database.string().c_str());
    Monitor::Session named;
    Require(Monitor::Session::DefaultNamesPath() == database && named.LoadDefaultNames());
    Require(named.DisplayName("AbCdEfGhIjK") == "Nap");
    std::filesystem::remove(database);
    Require(!named.LoadDefaultNames());
    SetVariable("ANYPS5_NID_DB", "");
    Require(Monitor::Session::DefaultNamesPath().filename() == "aerolib.csv");

    Monitor::Session session;
    Require(!session.Connect(ProcessId()));
    Require(!session.Connected() && session.Stale());
    const auto nap = reinterpret_cast<decltype(&Nap)>(TraceImport_nid_no_patch(reinterpret_cast<void*>(&Nap), "Nap", "libTraced.prx"));
    Require(TelemetryEnabled_nid_no_patch());
    const auto discovered = Monitor::Session::Discover();
    Require(std::find(discovered.begin(), discovered.end(), ProcessId()) != discovered.end());
    Require(session.Connect(ProcessId()) && session.Connected() && session.Pid() == ProcessId());
    Require(session.Judge().title == "No presents");

    std::uint64_t at = 1000000000;
    std::uint64_t gpu = 0;
    std::uint64_t driver = 0;
    for (int frame = 0; frame < 40; ++frame) Present(at, 32, gpu, 30, driver, 0, Telemetry::PresentGpuTimed);
    session.Poll();
    Require(session.Frames().size() == 39);
    const Monitor::FrameSummary steady = session.Summarize(1.0);
    Require(steady.frames == 32 && steady.p50Ms == 32 && steady.p99Ms == 32 && steady.maxMs == 32 && steady.gpuTimed && !steady.driverTimed);
    Require(steady.fps > 31.2 && steady.fps < 31.3 && steady.gpuMs == 30);
    Require(session.Judge().title == "GPU-bound");

    for (int frame = 0; frame < 40; ++frame) Present(at, 32, gpu, 0, driver, 31, Telemetry::PresentDriverTimed);
    session.Poll();
    Require(session.Judge().title == "Driver-bound");

    for (int frame = 0; frame < 60; ++frame) Present(at, frame % 2 == 0 ? 10 : 30, gpu, 0, driver, 0, 0);
    session.Poll();
    const Monitor::FrameSummary uneven = session.Summarize(1.0);
    Require(uneven.p50Ms == 30 && uneven.maxMs == 30 && uneven.averageMs == 20);
    const Monitor::Verdict unexplained = session.Judge();
    Require(unexplained.title == "Not explained by the GPU, the driver or imports");
    Require(Contains(unexplained.detail, "APS5_PROFILE_GPU=1") && Contains(unexplained.detail, "APS5_PROFILE_DRAW=1"));

    session.SetWindow(0.5);
    const auto end = std::chrono::steady_clock::now() + std::chrono::milliseconds(1500);
    while (std::chrono::steady_clock::now() < end) {
        nap(20);
        const Telemetry::Present present{static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch()).count()), 0, 0, 0, 0, 0};
        TelemetryNotePresent_nid_no_patch(&present);
        session.Poll();
    }
    WaitForPublishes(session, 1);
    const auto imports = session.Imports();
    const auto napped = std::find_if(imports.begin(), imports.end(), [](const Monitor::ImportRate& rate) { return rate.name == "Nap"; });
    Require(napped != imports.end() && napped->library == "libTraced.prx");
    Require(napped->callsPerSecond > 10 && napped->callsPerSecond < 70);
    Require(napped->exclusiveMsPerSecond > 500 && napped->averageUs >= 19000 && napped->p50Us > 0);
    Require(!session.Threads().empty() && session.Threads().front().importMsPerSecond > 500);
    const Monitor::Verdict waiting = session.Judge();
    Require(waiting.title == "Waiting in system calls" && Contains(waiting.detail, "Nap"));
    Require(!session.SlowCalls().empty() && session.SlowCalls().back().import == "Nap" && session.SlowCalls().back().milliseconds >= 19);
    Require(!session.RecentCalls().empty() && std::string(session.RecentCalls().back().name) == "Nap");
    Require(!session.Stale());

    const auto names = std::filesystem::temp_directory_path() / ("anyps5-monitor-names-" + std::to_string(ProcessId()) + ".txt");
    {
        std::ofstream file(names, std::ios::binary);
        file << "\xef\xbb\xbf" << "# nid name\n" << "Nap sceKernelUsleep\n" << "gNQ1V2vfXDE#suffix setjmp#suffix extra\n";
    }
    session.LoadNames(names.string());
    std::filesystem::remove(names);
    Require(session.DisplayName("Nap") == "sceKernelUsleep");
    Require(session.DisplayName("gNQ1V2vfXDE") == "setjmp");
    Require(session.DisplayName("unknown") == "unknown");
    Require(Contains(session.Judge().detail, "sceKernelUsleep"));

    session.Disconnect();
    Require(!session.Connected() && session.Frames().empty() && session.Imports().empty());
}
