#ifndef CORE_MONITOR_SRC_MEMORY_HPP
#define CORE_MONITOR_SRC_MEMORY_HPP

#include <cstdint>
#include <string>
#include <vector>

namespace Monitor {

struct Region {
    std::uint64_t base = 0;
    std::uint64_t size = 0;
    std::string protection;
    std::string type;
    std::string module;
    bool readable = false;
};

class ProcessMemory {
public:
    ProcessMemory() = default;
    ProcessMemory(const ProcessMemory&) = delete;
    ProcessMemory& operator=(const ProcessMemory&) = delete;
    ~ProcessMemory();

    bool Open(std::uint64_t pid, std::string& error);
    void Close();
    std::uint64_t Pid() const;
    std::vector<Region> Regions() const;
    std::size_t Read(std::uint64_t address, std::size_t size, std::vector<std::uint8_t>& bytes) const;
    std::vector<std::uint64_t> Search(const std::vector<std::uint8_t>& pattern, std::size_t limit, std::uint64_t maximumBytes, const std::string& module, std::uint64_t& scanned) const;

private:
    std::uint64_t _pid = 0;
#ifdef _WIN32
    void* _process = nullptr;
#endif
};

}

#endif
