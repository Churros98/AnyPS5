#ifdef __linux__
#include <cerrno>
#include <csignal>
#include <ctime>
#include <link.h>
#include <unistd.h>
#include "prx/libc/include/CallTraceInternal.hpp"
#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <limits>
#include <system_error>

namespace {

struct ModuleSegment {
    std::uint64_t start;
    std::uint64_t end;
    std::uint64_t base;
    char name[64];
};

struct ModuleMap {
    std::size_t count;
    std::uint64_t pageSize;
    ModuleSegment segments[256];
};

struct sigaction g_previousAbort{};
std::atomic<const ModuleMap*> g_modules{nullptr};
std::atomic<bool> g_reporting{false};
std::atomic<bool> g_reported{false};
unsigned long long g_moduleChanges = ~0ull;

void WriteStderr(const char* text, std::size_t length) {
    std::size_t written = 0;
    while (written < length) {
        const ssize_t result = ::write(STDERR_FILENO, text + written, length - written);
        if (result < 0 && errno == EINTR) continue;
        if (result <= 0) break;
        written += static_cast<std::size_t>(result);
    }
}

bool LookupModule(std::uint64_t address, char* name, std::size_t capacity, std::uint64_t* base) {
    const ModuleMap* modules = g_modules.load(std::memory_order_acquire);
    if (modules == nullptr) return false;
    for (std::size_t index = 0; index < modules->count; ++index) {
        const auto& segment = modules->segments[index];
        if (address < segment.start || address >= segment.end) continue;
        std::size_t length = 0;
        while (length < sizeof(segment.name) && length + 1 < capacity && segment.name[length] != '\0') {
            name[length] = segment.name[length];
            ++length;
        }
        name[length] = '\0';
        *base = segment.base;
        return true;
    }
    return false;
}

void ReportOnAbort(int number, siginfo_t* info, void* context) {
    const int savedErrno = errno;
    if (!g_reporting.exchange(true, std::memory_order_acq_rel)) {
        constexpr char header[] = "[libc] SIGABRT\n";
        WriteStderr(header, sizeof(header) - 1);
        CallTraceWriteReport_nid_no_patch(WriteStderr, LookupModule);
        g_reported.store(true, std::memory_order_release);
    } else {
        const timespec pause{0, 1000000};
        for (int waited = 0; waited < 2000 && !g_reported.load(std::memory_order_acquire); ++waited) nanosleep(&pause, nullptr);
    }
    errno = savedErrno;
    if ((g_previousAbort.sa_flags & SA_SIGINFO) != 0) {
        if (g_previousAbort.sa_sigaction != nullptr) g_previousAbort.sa_sigaction(number, info, context);
        return;
    }
    if (g_previousAbort.sa_handler == SIG_IGN) return;
    if (g_previousAbort.sa_handler != SIG_DFL) {
        g_previousAbort.sa_handler(number);
        return;
    }
    struct sigaction fallback{};
    fallback.sa_handler = SIG_DFL;
    sigemptyset(&fallback.sa_mask);
    sigaction(number, &fallback, nullptr);
    raise(number);
}

}

extern "C" {

void CallTraceSnapshotModules_nid_no_patch() {
    unsigned long long changes = 0;
    dl_iterate_phdr([](dl_phdr_info* info, std::size_t, void* data) {
        *static_cast<unsigned long long*>(data) = info->dlpi_adds + info->dlpi_subs;
        return 1;
    }, &changes);
    if (changes == g_moduleChanges) return;
    g_moduleChanges = changes;
    auto* map = new ModuleMap{};
    map->pageSize = static_cast<std::uint64_t>(sysconf(_SC_PAGESIZE));
    dl_iterate_phdr([](dl_phdr_info* info, std::size_t, void* data) {
        auto& modules = *static_cast<ModuleMap*>(data);
        const char* path = info->dlpi_name != nullptr && *info->dlpi_name != '\0' ? info->dlpi_name : program_invocation_short_name;
        const char* slash = std::strrchr(path, '/');
        const char* name = slash == nullptr ? path : slash + 1;
        std::uint64_t first = std::numeric_limits<std::uint64_t>::max();
        for (int index = 0; index < info->dlpi_phnum; ++index)
            if (info->dlpi_phdr[index].p_type == PT_LOAD) first = std::min<std::uint64_t>(first, info->dlpi_phdr[index].p_vaddr & ~(modules.pageSize - 1));
        for (int index = 0; index < info->dlpi_phnum && modules.count < std::size(modules.segments); ++index) {
            const auto& header = info->dlpi_phdr[index];
            if (header.p_type != PT_LOAD || header.p_memsz == 0) continue;
            auto& segment = modules.segments[modules.count++];
            segment.base = info->dlpi_addr + first;
            segment.start = info->dlpi_addr + header.p_vaddr;
            segment.end = segment.start + header.p_memsz;
            std::strncpy(segment.name, name, sizeof(segment.name) - 1);
        }
        return 0;
    }, map);
    g_modules.store(map, std::memory_order_release);
}

void CallTraceInstallAbortReport_nid_no_patch() {
    struct sigaction action{};
    action.sa_sigaction = ReportOnAbort;
    action.sa_flags = SA_SIGINFO;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGABRT, &action, &g_previousAbort) != 0) throw std::system_error(errno, std::generic_category(), "call trace: sigaction");
}

}

#endif
