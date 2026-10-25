#ifndef CORE_MONITOR_SRC_THREADNAMES_HPP
#define CORE_MONITOR_SRC_THREADNAMES_HPP

#include <chrono>
#include <cstdint>
#include <string>
#include <unordered_map>

namespace Monitor {

class ThreadNames {
public:
    void Attach(std::uint64_t pid);
    std::string Name(std::uint64_t thread);

    static std::string Read(std::uint64_t pid, std::uint64_t thread);

private:
    struct Entry {
        std::string name;
        std::chrono::steady_clock::time_point read;
    };

    std::uint64_t _pid = 0;
    std::unordered_map<std::uint64_t, Entry> _names;
};

}

#endif
