#ifndef CORE_MONITOR_SRC_SYMBOLS_HPP
#define CORE_MONITOR_SRC_SYMBOLS_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace Monitor {

struct Location {
    std::string module;
    std::string path;
    std::uint64_t moduleBase = 0;
    std::uint64_t offset = 0;
    std::string function;
    std::uint64_t functionOffset = 0;
    std::optional<std::uint64_t> functionStart;
};

struct FunctionRange {
    std::uint64_t begin = 0;
    std::uint64_t end = 0;
    std::uint64_t start = 0;
};

struct PeImage {
    std::vector<std::pair<std::uint64_t, std::string>> functions;
    std::vector<FunctionRange> ranges;
};

class Symbols {
public:
    struct Module {
        std::string name;
        std::string path;
        std::uint64_t base = 0;
        std::uint64_t size = 0;
        bool parsed = false;
        std::string error;
        PeImage image;
    };

    bool Attach(std::uint64_t pid, std::string& error);
    std::uint64_t Pid() const;
    std::optional<Location> Resolve(std::uint64_t address);
    std::optional<Location> ResolveModuleOffset(const std::string& module, std::uint64_t offset);
    std::optional<std::uint64_t> Parse(const std::string& text);
    std::vector<Module>& Modules();

    static PeImage ReadPeImage(const std::string& path, std::string& error);
    static Location Locate(const PeImage& image, std::uint64_t offset);
    static std::string Demangle(const std::string& name);

private:
    Location locate(Module& module, std::uint64_t offset);

    std::uint64_t _pid = 0;
    std::vector<Module> _modules;
};

std::string FormatLocation(const Location& location);

}

#endif
