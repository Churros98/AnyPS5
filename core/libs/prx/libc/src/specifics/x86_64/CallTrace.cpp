#if defined(_WIN32) || defined(__linux__)
#ifdef _WIN32
#include <windows.h>
#else
#include <cerrno>
#include <sys/mman.h>
#include <unistd.h>
#endif
#include "prx/libc/include/CallTrace.hpp"
#include "prx/libc/include/CallTraceInternal.hpp"
#ifdef APS5_ENABLE_PROFILER
#include "prx/libc/include/Telemetry.hpp"
#endif
#include "prx/libc/include/general/AsmMacros.hpp"
#include <atomic>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <stdexcept>
#include <string_view>
#include <system_error>
#include <unordered_map>

extern "C" void CallTraceEnter_nid_no_patch();

namespace {

constexpr std::size_t ThunkBytes = 24;
constexpr std::size_t ThunkAreaBytes = 1024 * 1024;
constexpr std::size_t RecordCapacity = ThunkAreaBytes / ThunkBytes;

std::mutex g_mutex;
std::unordered_map<void*, void*> g_thunkByTarget;
std::atomic<CallTraceImportRecord*> g_records{nullptr};
std::atomic<std::size_t> g_recordCount{0};
std::uint8_t* g_writable = nullptr;
std::uint8_t* g_executable = nullptr;
#ifdef APS5_ENABLE_PROFILER
bool g_profiling = false;
#endif

bool Selected(std::string_view library) {
    const char* value = std::getenv("APS5_TRACE_CALLS");
    if (value == nullptr || *value == '\0') {
#ifdef APS5_ENABLE_PROFILER
        return CallProfileRequested_nid_no_patch();
#else
        return false;
#endif
    }
    std::string_view rest(value);
    if (library.ends_with(".prx")) library.remove_suffix(4);
    while (!rest.empty()) {
        const auto comma = rest.find(',');
        auto token = rest.substr(0, comma);
        rest = comma == std::string_view::npos ? std::string_view{} : rest.substr(comma + 1);
        if (token.ends_with(".prx")) token.remove_suffix(4);
        if (token == "all" || token == library) return true;
    }
    return false;
}

#ifdef _WIN32
void MapThunkArea() {
    const HANDLE section = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_EXECUTE_READWRITE, 0, static_cast<DWORD>(ThunkAreaBytes), nullptr);
    if (section == nullptr) throw std::system_error(static_cast<int>(GetLastError()), std::system_category(), "call trace: CreateFileMappingW");
    g_writable = static_cast<std::uint8_t*>(MapViewOfFile(section, FILE_MAP_WRITE, 0, 0, ThunkAreaBytes));
    g_executable = static_cast<std::uint8_t*>(MapViewOfFile(section, FILE_MAP_READ | FILE_MAP_EXECUTE, 0, 0, ThunkAreaBytes));
    const DWORD code = GetLastError();
    CloseHandle(section);
    if (g_writable == nullptr || g_executable == nullptr) throw std::system_error(static_cast<int>(code), std::system_category(), "call trace: MapViewOfFile");
}
#else
void MapThunkArea() {
    const int file = memfd_create("aps5-call-trace", MFD_CLOEXEC);
    if (file < 0) throw std::system_error(errno, std::generic_category(), "call trace: memfd_create");
    void* writable = MAP_FAILED;
    void* executable = MAP_FAILED;
    if (ftruncate(file, ThunkAreaBytes) == 0) {
        writable = mmap(nullptr, ThunkAreaBytes, PROT_READ | PROT_WRITE, MAP_SHARED, file, 0);
        if (writable != MAP_FAILED) executable = mmap(nullptr, ThunkAreaBytes, PROT_READ | PROT_EXEC, MAP_SHARED, file, 0);
    }
    const int code = errno;
    close(file);
    if (writable == MAP_FAILED || executable == MAP_FAILED) {
        if (writable != MAP_FAILED) munmap(writable, ThunkAreaBytes);
        throw std::system_error(code, std::generic_category(), "call trace: mmap");
    }
    g_writable = static_cast<std::uint8_t*>(writable);
    g_executable = static_cast<std::uint8_t*>(executable);
}
#endif

std::uint64_t EntryHandler([[maybe_unused]] const CallTraceImportRecord& record) {
#ifdef APS5_ENABLE_PROFILER
    if (g_profiling && CallProfileTimes_nid_no_patch(record.name.c_str(), record.library.c_str())) return reinterpret_cast<std::uint64_t>(&CallProfileEnter_nid_no_patch);
#endif
    return reinterpret_cast<std::uint64_t>(&CallTraceEnter_nid_no_patch);
}

void* WriteThunk(const CallTraceImportRecord& record, const std::size_t index) {
    const std::size_t offset = index * ThunkBytes;
    const std::uint8_t prefix[] = {0x49, 0xbb};
    const std::uint8_t jump[] = {0xff, 0x25, 0, 0, 0, 0};
    const auto recordAddress = reinterpret_cast<std::uint64_t>(&record);
    const auto handler = EntryHandler(record);
    std::uint8_t* thunk = g_writable + offset;
    std::memcpy(thunk, prefix, sizeof(prefix));
    std::memcpy(thunk + 2, &recordAddress, sizeof(recordAddress));
    std::memcpy(thunk + 10, jump, sizeof(jump));
    std::memcpy(thunk + 16, &handler, sizeof(handler));
#ifdef _WIN32
    FlushInstructionCache(GetCurrentProcess(), g_executable + offset, ThunkBytes);
#else
    __builtin___clear_cache(reinterpret_cast<char*>(g_executable + offset), reinterpret_cast<char*>(g_executable + offset + ThunkBytes));
#endif
    return g_executable + offset;
}

}

static_assert(offsetof(CallTraceImportRecord, target) == 0);

extern "C" {

void* TraceImport_nid_no_patch(void* target, const char* name, const char* library) {
    if (target == nullptr || name == nullptr || library == nullptr || !Selected(library)) return target;
    std::lock_guard lock(g_mutex);
    if (g_records.load(std::memory_order_relaxed) == nullptr) {
        MapThunkArea();
        CallTraceAllocateRing_nid_no_patch();
        g_records.store(new CallTraceImportRecord[RecordCapacity], std::memory_order_release);
#ifdef __linux__
        CallTraceInstallAbortReport_nid_no_patch();
#endif
#ifdef APS5_ENABLE_PROFILER
        g_profiling = CallProfileStart_nid_no_patch();
        TelemetryEnabled_nid_no_patch();
#endif
    }
#ifdef __linux__
    CallTraceSnapshotModules_nid_no_patch();
#endif
    if (const auto existing = g_thunkByTarget.find(target); existing != g_thunkByTarget.end()) return existing->second;
    const std::size_t index = g_recordCount.load(std::memory_order_relaxed);
    if (index == RecordCapacity) throw std::runtime_error("call trace: thunk area exhausted");
    CallTraceImportRecord& record = g_records.load(std::memory_order_relaxed)[index];
    record.target = target;
    record.name = name;
    record.library = library;
    void* thunk = WriteThunk(record, index);
    g_thunkByTarget.emplace(target, thunk);
    g_recordCount.store(index + 1, std::memory_order_release);
    return thunk;
}

const CallTraceImportRecord* CallTraceRecords_nid_no_patch(std::size_t* count) {
    *count = g_recordCount.load(std::memory_order_acquire);
    return g_records.load(std::memory_order_acquire);
}

}

asm(".text\n"
    APS5_ASM_FUNCTION("CallTraceEnter_nid_no_patch")
    "    push %rdi\n"
    "    push %rsi\n"
    "    push %rdx\n"
    "    push %rcx\n"
    "    push %r8\n"
    "    push %r9\n"
    "    push %rax\n"
    "    push %r10\n"
    "    push %r11\n"
    "    sub $128, %rsp\n"
    "    movdqu %xmm0, 0(%rsp)\n"
    "    movdqu %xmm1, 16(%rsp)\n"
    "    movdqu %xmm2, 32(%rsp)\n"
    "    movdqu %xmm3, 48(%rsp)\n"
    "    movdqu %xmm4, 64(%rsp)\n"
    "    movdqu %xmm5, 80(%rsp)\n"
    "    movdqu %xmm6, 96(%rsp)\n"
    "    movdqu %xmm7, 112(%rsp)\n"
    "    mov %r11, %rdi\n"
    "    mov 200(%rsp), %rsi\n"
    "    call CallTraceRecord_nid_no_patch\n"
    "    movdqu 0(%rsp), %xmm0\n"
    "    movdqu 16(%rsp), %xmm1\n"
    "    movdqu 32(%rsp), %xmm2\n"
    "    movdqu 48(%rsp), %xmm3\n"
    "    movdqu 64(%rsp), %xmm4\n"
    "    movdqu 80(%rsp), %xmm5\n"
    "    movdqu 96(%rsp), %xmm6\n"
    "    movdqu 112(%rsp), %xmm7\n"
    "    add $128, %rsp\n"
    "    pop %r11\n"
    "    pop %r10\n"
    "    pop %rax\n"
    "    pop %r9\n"
    "    pop %r8\n"
    "    pop %rcx\n"
    "    pop %rdx\n"
    "    pop %rsi\n"
    "    pop %rdi\n"
    "    jmp *(%r11)\n"
    APS5_ASM_FUNCTION_END("CallTraceEnter_nid_no_patch"));
#endif
