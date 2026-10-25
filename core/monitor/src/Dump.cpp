#include "Monitor.hpp"
#include <algorithm>
#include <cstdio>
#include <thread>

namespace Monitor {

int Dump(Session& session, double seconds) {
    const auto end = Session::Clock::now() + std::chrono::duration_cast<Session::Clock::duration>(std::chrono::duration<double>(seconds));
    while (Session::Clock::now() < end) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        session.Poll();
    }
    const Telemetry::Header& header = session.Header();
    const double costNs = header.ticksPerSecond == 0 ? 0 : static_cast<double>(header.overheadTicks) * 1e9 / static_cast<double>(header.ticksPerSecond);
    std::printf("AnyPS5 monitor: pid %llu, telemetry version %u, %llu publishes%s, profiler cost %.0f ns per call\n", static_cast<unsigned long long>(session.Pid()), header.version,
        static_cast<unsigned long long>(header.publishes), session.Stale() ? " (stale)" : "", costNs);

    const FrameSummary frames = session.Summarize(seconds);
    std::printf("\nframes: %zu in the last %.1f s, %.1f fps, frame ms avg %.2f p50 %.2f p99 %.2f max %.2f", frames.frames, seconds, frames.fps, frames.averageMs, frames.p50Ms, frames.p99Ms, frames.maxMs);
    if (frames.gpuTimed) std::printf(", gpu %.2f ms", frames.gpuMs);
    if (frames.driverTimed) std::printf(", driver %.2f ms", frames.driverMs);
    std::printf("\n");

    const Verdict verdict = session.Judge();
    std::printf("\nverdict: %s\n  %s\n", verdict.title.c_str(), verdict.detail.c_str());

    std::vector<ImportRate> imports = session.Imports();
    std::sort(imports.begin(), imports.end(), [](const ImportRate& left, const ImportRate& right) { return left.exclusiveMsPerSecond > right.exclusiveMsPerSecond; });
    std::printf("\nimports over %.1f s (%zu traced):\n  %10s %10s %10s %9s %9s %9s %10s  %s\n", session.WindowSeconds(), imports.size(), "excl ms/s", "incl ms/s", "calls/s", "avg us", "p50 us", "p99 us", "calls",
        "import");
    for (std::size_t index = 0; index < std::min<std::size_t>(20, imports.size()); ++index) {
        const ImportRate& rate = imports[index];
        std::printf("  %10.3f %10.3f %10.0f %9.2f %9.2f %9.2f %10llu  %s %s\n", rate.exclusiveMsPerSecond, rate.inclusiveMsPerSecond, rate.callsPerSecond, rate.averageUs, rate.p50Us, rate.p99Us,
            static_cast<unsigned long long>(rate.calls), rate.library.c_str(), session.DisplayName(rate.name).c_str());
    }

    std::vector<ThreadRate> threads = session.Threads();
    std::sort(threads.begin(), threads.end(), [](const ThreadRate& left, const ThreadRate& right) { return left.importMsPerSecond > right.importMsPerSecond; });
    std::printf("\nthreads (%zu):\n  %10s %10s  %s\n", threads.size(), "import ms/s", "calls/s", "thread");
    for (std::size_t index = 0; index < std::min<std::size_t>(16, threads.size()); ++index) {
        std::printf("  %10.3f %10.0f  %llu\n", threads[index].importMsPerSecond, threads[index].callsPerSecond, static_cast<unsigned long long>(threads[index].thread));
    }

    const auto& slow = session.SlowCalls();
    std::printf("\nslow calls (%zu, threshold %.0f us):\n", slow.size(), header.ticksPerSecond == 0 ? 0.0 : static_cast<double>(header.slowTicks) * 1e6 / static_cast<double>(header.ticksPerSecond));
    for (std::size_t index = slow.size() > 10 ? slow.size() - 10 : 0; index < slow.size(); ++index) {
        std::printf("  %10.3f ms  thread %llu  from 0x%016llx  %s\n", slow[index].milliseconds, static_cast<unsigned long long>(slow[index].thread), static_cast<unsigned long long>(slow[index].returnAddress),
            session.DisplayName(slow[index].import).c_str());
    }

    const auto& recent = session.RecentCalls();
    std::printf("\nlast traced calls (%zu):\n", recent.size());
    for (std::size_t index = recent.size() > 10 ? recent.size() - 10 : 0; index < recent.size(); ++index) {
        std::printf("  thread %llu  from 0x%016llx  %s %s\n", static_cast<unsigned long long>(recent[index].thread), static_cast<unsigned long long>(recent[index].returnAddress), recent[index].library,
            session.DisplayName(recent[index].name).c_str());
    }
    return session.Stale() ? 2 : 0;
}

}
