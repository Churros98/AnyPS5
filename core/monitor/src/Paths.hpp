#ifndef CORE_MONITOR_SRC_PATHS_HPP
#define CORE_MONITOR_SRC_PATHS_HPP

#include <filesystem>
#include <string>

namespace Monitor {

inline std::string Utf8(const std::filesystem::path& path) {
    const std::u8string text = path.u8string();
    return std::string(text.begin(), text.end());
}

inline std::filesystem::path PathFromUtf8(const std::string& text) {
    return std::filesystem::path(std::u8string(text.begin(), text.end()));
}

}

#endif
