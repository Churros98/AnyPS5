#include "ThreadNames.hpp"
#ifdef _WIN32
#include <windows.h>
#endif
#include <cstring>
#include <fstream>

namespace Monitor {

namespace {

constexpr auto RereadAfter = std::chrono::seconds(2);

#ifdef _WIN32
using GetThreadDescriptionFunction = HRESULT(WINAPI*)(HANDLE, PWSTR*);

GetThreadDescriptionFunction Describe() {
    static const GetThreadDescriptionFunction function = [] {
        GetThreadDescriptionFunction resolved = nullptr;
        const HMODULE kernel = GetModuleHandleW(L"Kernel32.dll");
        if (kernel == nullptr) return resolved;
        const FARPROC address = GetProcAddress(kernel, "GetThreadDescription");
        static_assert(sizeof(resolved) == sizeof(address));
        std::memcpy(&resolved, &address, sizeof(resolved));
        return resolved;
    }();
    return function;
}
#endif

}

void ThreadNames::Attach(std::uint64_t pid) {
    if (pid == _pid) return;
    _pid = pid;
    _names.clear();
}

std::string ThreadNames::Name(std::uint64_t thread) {
    if (_pid == 0 || thread == 0) return {};
    const auto now = std::chrono::steady_clock::now();
    const auto found = _names.find(thread);
    if (found != _names.end() && now - found->second.read < RereadAfter) return found->second.name;
    std::string name = Read(_pid, thread);
    _names[thread] = {name, now};
    return name;
}

std::string ThreadNames::Read([[maybe_unused]] std::uint64_t pid, std::uint64_t thread) {
#ifdef _WIN32
    const GetThreadDescriptionFunction describe = Describe();
    if (describe == nullptr) return {};
    const HANDLE handle = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(thread));
    if (handle == nullptr) return {};
    PWSTR description = nullptr;
    std::string name;
    if (SUCCEEDED(describe(handle, &description)) && description != nullptr) {
        const int bytes = WideCharToMultiByte(CP_UTF8, 0, description, -1, nullptr, 0, nullptr, nullptr);
        if (bytes > 1) {
            name.resize(static_cast<std::size_t>(bytes - 1));
            WideCharToMultiByte(CP_UTF8, 0, description, -1, name.data(), bytes, nullptr, nullptr);
        }
        LocalFree(description);
    }
    CloseHandle(handle);
    return name;
#else
    std::ifstream file("/proc/" + std::to_string(pid) + "/task/" + std::to_string(thread) + "/comm");
    std::string name;
    std::getline(file, name);
    return name;
#endif
}

}
