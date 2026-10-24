#include "prx/libc/include/CallProfile.hpp"
#include "prx/libc/include/CallTrace.hpp"
#include "prx/libc/include/general/AsmMacros.hpp"
#include "prx/libc/include/general/VabiMacros.hpp"
#ifdef _WIN32
#include <windows.h>
#endif
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <source_location>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <vector>

struct Block {
    std::uint64_t words[4];
};

using SleepFunction = void (APS5_VABI*)(std::uint64_t);
using RecurseFunction = std::uint64_t (APS5_VABI*)(std::uint64_t);

static SleepFunction g_inner = nullptr;
static RecurseFunction g_recurse = nullptr;
static void* g_jump[5];

static void Require(bool condition, std::source_location location = std::source_location::current()) {
    if (!condition) {
        std::fprintf(stderr, "Call profile check failed at line %u\n", location.line());
        std::abort();
    }
}

static std::uint64_t APS5_VABI Integers(std::uint64_t a, std::uint64_t b, std::uint64_t c, std::uint64_t d, std::uint64_t e, std::uint64_t f, std::uint64_t g, std::uint64_t h) {
    return a + 2 * b + 3 * c + 4 * d + 5 * e + 6 * f + 7 * g + 8 * h;
}

static double APS5_VABI Doubles(double a, double b, double c, double d, double e, double f, double g, double h, double i, double j) {
    return a + 2 * b + 3 * c + 4 * d + 5 * e + 6 * f + 7 * g + 8 * h + 9 * i + 10 * j;
}

static double APS5_VABI Variadic(int count, ...) {
    __builtin_sysv_va_list arguments;
    __builtin_sysv_va_start(arguments, count);
    double sum = 0;
    for (int index = 0; index < count; ++index) {
        sum += static_cast<double>(__builtin_va_arg(arguments, std::uint64_t)) * (index + 1);
        sum += __builtin_va_arg(arguments, double) * (index + 1);
    }
    __builtin_sysv_va_end(arguments);
    return sum;
}

static Block APS5_VABI Blocks(std::uint64_t seed) {
    return {{seed, seed + 1, seed + 2, seed + 3}};
}

static void APS5_VABI Nap(std::uint64_t milliseconds) {
    std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
}

static void APS5_VABI Inner(std::uint64_t milliseconds) {
    std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
}

static void APS5_VABI Outer(std::uint64_t milliseconds) {
    g_inner(milliseconds);
    std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
}

static void APS5_VABI Leap(int) {
    __builtin_longjmp(g_jump, 1);
}

static int APS5_VABI SetjmpByName(int value) {
    return value + 1;
}

static int APS5_VABI SetjmpByNid(int value) {
    return value + 2;
}

static int APS5_VABI FiberRun(int value) {
    return value + 3;
}

static std::uint64_t APS5_VABI Recurse(std::uint64_t depth) {
    return depth == 0 ? 0 : 1 + g_recurse(depth - 1);
}

static std::uint64_t APS5_VABI Tailed(std::uint64_t value) {
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    return value + 1;
}

extern "C" void* g_tailTarget = nullptr;
extern "C" std::uint64_t APS5_VABI TailCaller(std::uint64_t value);

asm(".text\n"
    APS5_ASM_FUNCTION("TailCaller")
    "    jmp *g_tailTarget(%rip)\n"
    APS5_ASM_FUNCTION_END("TailCaller"));

template <typename TFunction>
static TFunction* Traced(TFunction* function, const char* name, const char* library) {
    return reinterpret_cast<TFunction*>(TraceImport_nid_no_patch(reinterpret_cast<void*>(function), name, library));
}

static CallProfileEntry Find(const char* name) {
    for (std::size_t index = 0; index < CallProfileRecordCount_nid_no_patch(); ++index) {
        CallProfileEntry entry{};
        Require(CallProfileReadRecord_nid_no_patch(index, &entry));
        if (std::strcmp(entry.name, name) == 0) return entry;
    }
    Require(false);
    return {};
}

static double Milliseconds(std::uint64_t ticks) {
    return static_cast<double>(ticks) * CallProfileNanosecondsPerTick_nid_no_patch() / 1e6;
}

[[gnu::noinline]] static void EscapeThrough(void (APS5_VABI* escape)(int)) {
    if (__builtin_setjmp(g_jump) == 0) escape(7);
}

static void SetVariable(const char* name, const char* value) {
#ifdef _WIN32
    Require(_putenv_s(name, value) == 0);
#else
    Require(setenv(name, value, 1) == 0);
#endif
}

int main(int argc, char** argv) {
    if (argc > 1 && std::strcmp(argv[1], "default") == 0) {
        SetVariable("APS5_TRACE_CALLS", "");
        SetVariable("APS5_PROFILE_CALLS", "");
        const auto sleep = Traced(&Nap, "Nap", "libTraced.prx");
        Require(sleep != &Nap);
        sleep(1);
        Require(Find("Nap").timedCalls == 1);
        return 0;
    }
    if (argc > 1 && std::strcmp(argv[1], "off") == 0) {
        SetVariable("APS5_TRACE_CALLS", "");
        SetVariable("APS5_PROFILE_CALLS", "0");
        Require(Traced(&Nap, "Nap", "libTraced.prx") == &Nap);
        return 0;
    }
    SetVariable("APS5_TRACE_CALLS", "libTraced,libSceFiber");
    SetVariable("APS5_PROFILE_CALLS", "3600");
    if (argc > 1 && std::strcmp(argv[1], "invalid") == 0) {
        SetVariable("APS5_PROFILE_CALLS", "86401");
        try {
            Traced(&Nap, "Nap", "libTraced.prx");
        } catch (const std::runtime_error& error) {
            Require(std::string_view(error.what()).find("APS5_PROFILE_CALLS") != std::string_view::npos);
            return 0;
        }
        Require(false);
    }
    if (argc > 1 && std::strcmp(argv[1], "abort") == 0) {
#ifdef _WIN32
        _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
#else
        Require(std::signal(SIGABRT, [](int) { _exit(3); }) != SIG_ERR);
#endif
        const auto sleep = Traced(&Nap, "Nap", "libTraced.prx");
        sleep(1);
        std::abort();
    }

    const auto integers = Traced(&Integers, "Integers", "libTraced.prx");
    const auto doubles = Traced(&Doubles, "Doubles", "libTraced.prx");
    const auto variadic = Traced(&Variadic, "Variadic", "libTraced.prx");
    const auto blocks = Traced(&Blocks, "Blocks", "libTraced.prx");
    Require(integers(1, 2, 3, 4, 5, 6, 7, 8) == 204);
    Require(doubles(1, 2, 3, 4, 5, 6, 7, 8, 9, 10) == 385);
    Require(variadic(2, std::uint64_t{3}, 0.5, std::uint64_t{4}, 0.25) == 12);
    const Block block = blocks(7);
    Require(block.words[0] == 7 && block.words[3] == 10);
    Require(CallProfileOverheadTicks_nid_no_patch() < 1000000);
    Require(Find("Integers").timedCalls == 1 && Find("Blocks").timedCalls == 1);

    const auto sleep = Traced(&Nap, "Nap", "libTraced.prx");
    for (int call = 0; call < 5; ++call) sleep(2);
    const CallProfileEntry slept = Find("Nap");
    Require(slept.calls == 5 && slept.timedCalls == 5);
    Require(Milliseconds(slept.inclusiveTicks) / 5 >= 1.9 && Milliseconds(slept.maxTicks) >= 1.9);
    Require(slept.exclusiveTicks == slept.inclusiveTicks);

    g_inner = Traced(&Inner, "Inner", "libTraced.prx");
    const auto outer = Traced(&Outer, "Outer", "libTraced.prx");
    outer(3);
    const CallProfileEntry nested = Find("Outer");
    const CallProfileEntry inner = Find("Inner");
    Require(nested.timedCalls == 1 && inner.timedCalls == 1);
    Require(Milliseconds(nested.inclusiveTicks) >= 5.9);
    Require(Milliseconds(nested.exclusiveTicks) >= 2.9);
    Require(nested.exclusiveTicks + inner.inclusiveTicks <= nested.inclusiveTicks + nested.inclusiveTicks / 100);

    const auto escape = Traced(&Leap, "Leap", "libTraced.prx");
    EscapeThrough(escape);
    Require(integers(1, 2, 3, 4, 5, 6, 7, 8) == 204);
    EscapeThrough(escape);
    Require(integers(1, 2, 3, 4, 5, 6, 7, 8) == 204);
    Require(Find("Leap").calls == 2 && Find("Leap").timedCalls == 0);
    Require(Find("Integers").timedCalls == 3);

    const auto byName = Traced(&SetjmpByName, "setjmp", "libTraced.prx");
    const auto byNid = Traced(&SetjmpByNid, "gNQ1V2vfXDE", "libTraced.prx");
    Require(byName(1) == 2 && byNid(1) == 3);
    Require(Find("setjmp").calls == 1 && Find("setjmp").timedCalls == 0);
    Require(Find("gNQ1V2vfXDE").calls == 1 && Find("gNQ1V2vfXDE").timedCalls == 0);
    const auto fiber = Traced(&FiberRun, "sceFiberRun", "libSceFiber.prx");
    Require(fiber(1) == 4);
    Require(Find("sceFiberRun").calls == 1 && Find("sceFiberRun").timedCalls == 0);

    g_recurse = Traced(&Recurse, "Recurse", "libTraced.prx");
    Require(g_recurse(299) == 299);
    const CallProfileEntry recursed = Find("Recurse");
    Require(recursed.calls == 300 && recursed.timedCalls == 256);
    Require(integers(1, 2, 3, 4, 5, 6, 7, 8) == 204);

    g_tailTarget = reinterpret_cast<void*>(Traced(&Tailed, "Tailed", "libTraced.prx"));
    const auto tail = Traced(&TailCaller, "TailCaller", "libTraced.prx");
    Require(tail(4) == 5 && tail(6) == 7);
    const CallProfileEntry tailCaller = Find("TailCaller");
    const CallProfileEntry tailed = Find("Tailed");
    Require(tailCaller.calls == 2 && tailCaller.timedCalls == 2 && Milliseconds(tailCaller.inclusiveTicks) >= 1.9);
    Require(tailed.calls == 2 && tailed.timedCalls == 0);

    constexpr std::uint64_t Workers = 4;
    constexpr std::uint64_t Calls = 20000;
    std::vector<std::thread> workers;
    for (std::uint64_t worker = 0; worker < Workers; ++worker) {
        workers.emplace_back([integers, worker] {
            for (std::uint64_t call = 0; call < Calls; ++call) Require(integers(worker, call, 1, 2, 3, 4, 5, 6) == Integers(worker, call, 1, 2, 3, 4, 5, 6));
        });
    }
    for (auto& worker : workers) worker.join();
    const CallProfileEntry busy = Find("Integers");
    Require(busy.timedCalls == 4 + Workers * Calls && busy.calls == busy.timedCalls);
    std::uint64_t histogram = 0;
    for (const std::uint64_t bucket : busy.histogram) histogram += bucket;
    Require(histogram == busy.timedCalls);

    CallProfileEntry top[3];
    const std::size_t count = CopyCallProfile_nid_no_patch(top, 3);
    Require(count == 3 && top[0].exclusiveTicks >= top[1].exclusiveTicks && top[1].exclusiveTicks >= top[2].exclusiveTicks);
    Require(std::strcmp(top[0].name, "Nap") == 0);
}
