#ifndef CORE_LIBS_PRX_LIBC_INCLUDE_TELEMETRYREADER_HPP
#define CORE_LIBS_PRX_LIBC_INCLUDE_TELEMETRYREADER_HPP

#include "prx/libc/include/Telemetry.hpp"
#ifdef _WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#endif
#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

namespace Telemetry {

inline std::uint64_t Load(const std::uint64_t& value) {
    return std::atomic_ref<std::uint64_t>(const_cast<std::uint64_t&>(value)).load(std::memory_order_acquire);
}

inline void Store(std::uint64_t& value, std::uint64_t next) {
    std::atomic_ref<std::uint64_t>(value).store(next, std::memory_order_release);
}

inline std::string MappingName(std::uint64_t pid) {
#ifdef _WIN32
    return "Local\\AnyPS5-Telemetry-" + std::to_string(pid);
#else
    return "/anyps5-telemetry-" + std::to_string(pid);
#endif
}

inline std::string ReportTag(std::string_view text) {
    if (text.empty() || text.front() != '[') return {};
    std::string tag;
    std::size_t words = 0;
    bool digits = false;
    for (std::size_t index = 0; index < text.size() && tag.size() + 1 < ReportTagBytes; ++index) {
        const char character = text[index];
        if (character == ':' || character == '\n' || (character == '(' && index != 0)) break;
        if (character == ' ') {
            if (++words == 3) break;
            digits = false;
            tag += ' ';
            continue;
        }
        if (character >= '0' && character <= '9') {
            if (!digits) tag += '#';
            digits = true;
            continue;
        }
        digits = false;
        tag += character;
    }
    while (!tag.empty() && (tag.back() == ' ' || tag.back() == ',' || tag.back() == ';')) tag.pop_back();
    return tag;
}

template <typename TEntry>
bool ReadEntry(const TEntry& source, TEntry& destination, std::uint64_t expected = 0) {
    for (int attempt = 0; attempt < 16; ++attempt) {
        const std::uint64_t before = Load(source.sequence);
        if (before == 0 || (before & 1) != 0) continue;
        std::atomic_thread_fence(std::memory_order_acquire);
        std::memcpy(&destination, &source, sizeof(TEntry));
        std::atomic_thread_fence(std::memory_order_acquire);
        if (Load(source.sequence) != before) continue;
        destination.sequence = before;
        return expected == 0 || before == expected;
    }
    return false;
}

template <typename TEntry, std::size_t Capacity>
std::vector<TEntry> ReadRing(const TEntry (&ring)[Capacity], std::uint64_t written, std::uint64_t after) {
    std::vector<TEntry> entries;
    const std::uint64_t first = written > Capacity ? written - Capacity + 1 : 1;
    for (std::uint64_t index = std::max(first, after + 1); index <= written; ++index) {
        TEntry entry{};
        if (ReadEntry(ring[index % Capacity], entry, index * 2)) entries.push_back(entry);
    }
    return entries;
}

class Reader {
public:
    Reader() = default;
    Reader(const Reader&) = delete;
    Reader& operator=(const Reader&) = delete;

    ~Reader() {
        Close();
    }

    bool Open(std::uint64_t pid) {
        Close();
        const std::string name = MappingName(pid);
#ifdef _WIN32
        _writable = true;
        _mapping = OpenFileMappingA(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, name.c_str());
        if (_mapping == nullptr) {
            _writable = false;
            _mapping = OpenFileMappingA(FILE_MAP_READ, FALSE, name.c_str());
        }
        if (_mapping == nullptr) return false;
        _block = static_cast<Block*>(MapViewOfFile(_mapping, _writable ? FILE_MAP_READ | FILE_MAP_WRITE : FILE_MAP_READ, 0, 0, sizeof(Block)));
#else
        _writable = true;
        int file = shm_open(name.c_str(), O_RDWR, 0);
        if (file < 0) {
            _writable = false;
            file = shm_open(name.c_str(), O_RDONLY, 0);
        }
        if (file < 0) return false;
        void* view = mmap(nullptr, sizeof(Block), _writable ? PROT_READ | PROT_WRITE : PROT_READ, MAP_SHARED, file, 0);
        close(file);
        _block = view == MAP_FAILED ? nullptr : static_cast<Block*>(view);
#endif
        if (_block != nullptr && _block->header.magic == Magic && _block->header.version == Version && _block->header.totalBytes == sizeof(Block)) return true;
        Close();
        return false;
    }

    void Close() {
#ifdef _WIN32
        if (_block != nullptr) UnmapViewOfFile(_block);
        if (_mapping != nullptr) CloseHandle(_mapping);
        _mapping = nullptr;
#else
        if (_block != nullptr) munmap(_block, sizeof(Block));
#endif
        _block = nullptr;
    }

    bool IsOpen() const {
        return _block != nullptr;
    }

    Header ReadHeader() const {
        Header header{};
        const Header& source = _block->header;
        header.magic = source.magic;
        header.version = source.version;
        header.headerBytes = source.headerBytes;
        header.totalBytes = source.totalBytes;
        header.pid = source.pid;
        header.ticksPerSecond = Load(source.ticksPerSecond);
        header.overheadTicks = Load(source.overheadTicks);
        header.slowTicks = Load(source.slowTicks);
        header.publishes = Load(source.publishes);
        header.imports = Load(source.imports);
        header.threads = Load(source.threads);
        header.framesWritten = Load(source.framesWritten);
        header.slowWritten = Load(source.slowWritten);
        header.recentWritten = Load(source.recentWritten);
        header.commandsWritten = Load(source.commandsWritten);
        header.watchedWritten = Load(source.watchedWritten);
        header.phases = Load(source.phases);
        header.phasesPublishes = Load(source.phasesPublishes);
        header.reports = Load(source.reports);
        return header;
    }

    bool Writable() const {
        return _block != nullptr && _writable;
    }

    std::uint64_t SendCommand(CommandKind kind, std::uint64_t first, std::uint64_t second = 0, std::uint64_t third = 0) {
        if (!Writable()) return 0;
        const std::uint64_t index = std::atomic_ref<std::uint64_t>(_block->header.commandsWritten).fetch_add(1, std::memory_order_acq_rel) + 1;
        Command& command = _block->commands[index % CommandCapacity];
        Store(command.sequence, index * 2 - 1);
        std::atomic_thread_fence(std::memory_order_release);
        command.kind = static_cast<std::uint64_t>(kind);
        command.arguments[0] = first;
        command.arguments[1] = second;
        command.arguments[2] = third;
        command.arguments[3] = 0;
        Store(command.sequence, index * 2);
        return index;
    }

    bool ReadResponse(std::uint64_t index, Response& response) const {
        return ReadEntry(_block->responses[index % CommandCapacity], response, index * 2);
    }

    std::vector<WatchedCall> ReadWatchedCalls(std::uint64_t after = 0) const {
        return ReadRing(_block->watched, Load(_block->header.watchedWritten), after);
    }

    std::vector<Phase> ReadPhases() const {
        std::vector<Phase> phases;
        const std::uint64_t count = std::min<std::uint64_t>(Load(_block->header.phases), PhaseCapacity);
        for (std::uint64_t index = 0; index < count; ++index) {
            Phase entry{};
            if (ReadEntry(_block->phases[index], entry)) phases.push_back(entry);
        }
        return phases;
    }

    std::vector<Report> ReadReports() const {
        std::vector<Report> reports;
        const std::uint64_t count = std::min<std::uint64_t>(Load(_block->header.reports), ReportCapacity);
        for (std::uint64_t index = 0; index < count; ++index) {
            Report entry{};
            if (ReadEntry(_block->reports[index], entry)) reports.push_back(entry);
        }
        return reports;
    }

    std::vector<Frame> ReadFrames(std::uint64_t after = 0) const {
        return ReadRing(_block->frames, Load(_block->header.framesWritten), after);
    }

    std::vector<SlowCall> ReadSlowCalls(std::uint64_t after = 0) const {
        return ReadRing(_block->slow, Load(_block->header.slowWritten), after);
    }

    std::vector<RecentCall> ReadRecentCalls() const {
        return ReadRing(_block->recent, Load(_block->header.recentWritten), 0);
    }

    std::vector<Import> ReadImports() const {
        std::vector<Import> imports;
        const std::uint64_t count = std::min<std::uint64_t>(Load(_block->header.imports), ImportCapacity);
        for (std::uint64_t index = 0; index < count; ++index) {
            Import entry{};
            if (!ReadEntry(_block->imports[index], entry)) entry = Import{};
            imports.push_back(entry);
        }
        return imports;
    }

    std::vector<Thread> ReadThreads() const {
        std::vector<Thread> threads;
        const std::uint64_t count = std::min<std::uint64_t>(Load(_block->header.threads), ThreadCapacity);
        for (std::uint64_t index = 0; index < count; ++index) {
            Thread entry{};
            if (ReadEntry(_block->threads[index], entry)) threads.push_back(entry);
        }
        return threads;
    }

private:
    Block* _block = nullptr;
    bool _writable = false;
#ifdef _WIN32
    HANDLE _mapping = nullptr;
#endif
};

}

#endif
