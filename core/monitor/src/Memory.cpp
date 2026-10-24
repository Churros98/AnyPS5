#include "Memory.hpp"
#include "Paths.hpp"
#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#else
#include <sys/uio.h>
#include <fstream>
#include <sstream>
#endif
#include <algorithm>
#include <cctype>
#include <filesystem>
#include <functional>

namespace Monitor {

namespace {

constexpr std::size_t Chunk = 1 << 20;

std::string Lower(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char character) { return static_cast<char>(std::tolower(character)); });
    return text;
}

#ifdef _WIN32
std::string Protection(DWORD protect) {
    switch (protect & 0xff) {
        case PAGE_NOACCESS: return "---";
        case PAGE_READONLY: return "r--";
        case PAGE_READWRITE: return "rw-";
        case PAGE_WRITECOPY: return "rc-";
        case PAGE_EXECUTE: return "--x";
        case PAGE_EXECUTE_READ: return "r-x";
        case PAGE_EXECUTE_READWRITE: return "rwx";
        case PAGE_EXECUTE_WRITECOPY: return "rcx";
        default: return "?";
    }
}
#endif

}

ProcessMemory::~ProcessMemory() {
    Close();
}

bool ProcessMemory::Open(std::uint64_t pid, std::string& error) {
    Close();
#ifdef _WIN32
    _process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, static_cast<DWORD>(pid));
    if (_process == nullptr) {
        error = "OpenProcess failed with " + std::to_string(GetLastError());
        return false;
    }
#else
    if (!std::filesystem::exists("/proc/" + std::to_string(pid) + "/maps")) {
        error = "no process " + std::to_string(pid);
        return false;
    }
#endif
    _pid = pid;
    return true;
}

void ProcessMemory::Close() {
#ifdef _WIN32
    if (_process != nullptr) CloseHandle(_process);
    _process = nullptr;
#endif
    _pid = 0;
}

std::uint64_t ProcessMemory::Pid() const {
    return _pid;
}

std::vector<Region> ProcessMemory::Regions() const {
    std::vector<Region> regions;
#ifdef _WIN32
    std::uint64_t address = 0;
    MEMORY_BASIC_INFORMATION memory{};
    while (VirtualQueryEx(_process, reinterpret_cast<LPCVOID>(address), &memory, sizeof(memory)) == sizeof(memory)) {
        const std::uint64_t base = reinterpret_cast<std::uint64_t>(memory.BaseAddress);
        if (memory.State == MEM_COMMIT) {
            Region region;
            region.base = base;
            region.size = memory.RegionSize;
            region.protection = Protection(memory.Protect) + ((memory.Protect & PAGE_GUARD) != 0 ? "g" : "");
            region.type = memory.Type == MEM_IMAGE ? "image" : memory.Type == MEM_MAPPED ? "mapped" : "private";
            region.readable = (memory.Protect & (PAGE_NOACCESS | PAGE_GUARD)) == 0 && region.protection.front() == 'r';
            if (memory.Type != MEM_PRIVATE) {
                wchar_t path[MAX_PATH * 4];
                if (K32GetMappedFileNameW(_process, memory.BaseAddress, path, static_cast<DWORD>(std::size(path))) != 0) region.module = Utf8(std::filesystem::path(path).filename());
            }
            regions.push_back(std::move(region));
        }
        const std::uint64_t next = base + memory.RegionSize;
        if (next <= address) break;
        address = next;
    }
#else
    std::ifstream maps("/proc/" + std::to_string(_pid) + "/maps");
    std::string line;
    while (std::getline(maps, line)) {
        std::istringstream fields(line);
        std::string range;
        std::string permissions;
        std::string offset;
        std::string device;
        std::string inode;
        std::string path;
        fields >> range >> permissions >> offset >> device >> inode;
        std::getline(fields >> std::ws, path);
        const auto dash = range.find('-');
        Region region;
        region.base = std::strtoull(range.substr(0, dash).c_str(), nullptr, 16);
        region.size = std::strtoull(range.substr(dash + 1).c_str(), nullptr, 16) - region.base;
        region.protection = permissions.substr(0, 3);
        region.type = path.empty() ? "private" : path.front() == '/' ? "image" : "mapped";
        region.module = path.empty() || path.front() != '/' ? path : std::filesystem::path(path).filename().string();
        region.readable = permissions.front() == 'r';
        regions.push_back(std::move(region));
    }
#endif
    return regions;
}

std::size_t ProcessMemory::Read(std::uint64_t address, std::size_t size, std::vector<std::uint8_t>& bytes) const {
    bytes.assign(size, 0);
    std::size_t done = 0;
    while (done < size) {
        const std::uint64_t at = address + done;
        const std::size_t page = std::min<std::size_t>(size - done, 0x1000 - (at & 0xfff));
#ifdef _WIN32
        SIZE_T read = 0;
        if (!ReadProcessMemory(_process, reinterpret_cast<LPCVOID>(at), bytes.data() + done, page, &read) || read != page) break;
#else
        iovec local{bytes.data() + done, page};
        iovec remote{reinterpret_cast<void*>(at), page};
        if (process_vm_readv(static_cast<pid_t>(_pid), &local, 1, &remote, 1, 0) != static_cast<ssize_t>(page)) break;
#endif
        done += page;
    }
    bytes.resize(done);
    return done;
}

std::vector<std::uint64_t> ProcessMemory::Search(const std::vector<std::uint8_t>& pattern, std::size_t limit, std::uint64_t maximumBytes, const std::string& module, std::uint64_t& scanned) const {
    std::vector<std::uint64_t> found;
    scanned = 0;
    if (pattern.empty()) return found;
    const std::string wanted = Lower(module);
    const std::boyer_moore_horspool_searcher searcher(pattern.begin(), pattern.end());
    std::vector<std::uint8_t> buffer;
    for (const Region& region : Regions()) {
        if (!region.readable || (!wanted.empty() && Lower(region.module) != wanted)) continue;
        for (std::uint64_t offset = 0; offset < region.size && found.size() < limit && scanned < maximumBytes;) {
            const std::size_t length = static_cast<std::size_t>(std::min<std::uint64_t>(region.size - offset, Chunk + pattern.size() - 1));
            const std::size_t read = Read(region.base + offset, length, buffer);
            const std::uint64_t accepted = read == length ? std::min<std::uint64_t>(read, Chunk) : read;
            scanned += accepted;
            for (auto at = std::search(buffer.begin(), buffer.end(), searcher); at != buffer.end() && found.size() < limit; at = std::search(at + 1, buffer.end(), searcher)) {
                const auto position = static_cast<std::uint64_t>(at - buffer.begin());
                if (position >= accepted) break;
                found.push_back(region.base + offset + position);
            }
            if (read == length) {
                offset += accepted;
            } else {
                const std::uint64_t failed = region.base + offset + read;
                offset = (failed & ~std::uint64_t{0xfff}) + 0x1000 - region.base;
            }
        }
        if (found.size() >= limit || scanned >= maximumBytes) break;
    }
    return found;
}

}
