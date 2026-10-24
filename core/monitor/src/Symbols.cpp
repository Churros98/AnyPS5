#include "Symbols.hpp"
#include "Paths.hpp"
#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#endif
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cxxabi.h>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <sstream>

namespace Monitor {

namespace {

template <typename TValue>
bool ReadAt(const std::vector<char>& file, std::size_t offset, TValue& value) {
    if (offset > file.size() || file.size() - offset < sizeof(TValue)) return false;
    std::memcpy(&value, file.data() + offset, sizeof(TValue));
    return true;
}

std::string Lower(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char character) { return static_cast<char>(std::tolower(character)); });
    return text;
}

struct Section {
    std::uint32_t virtualAddress;
    std::uint32_t virtualSize;
    std::uint32_t rawOffset;
    std::uint32_t rawSize;
    std::uint32_t characteristics;
};

std::optional<std::size_t> RvaToOffset(const std::vector<Section>& sections, std::uint32_t rva) {
    for (const Section& section : sections) {
        if (rva >= section.virtualAddress && rva < section.virtualAddress + std::max(section.virtualSize, section.rawSize)) return section.rawOffset + (rva - section.virtualAddress);
    }
    return std::nullopt;
}

std::string CString(const std::vector<char>& file, std::size_t offset) {
    if (offset >= file.size()) return {};
    const char* start = file.data() + offset;
    const void* end = std::memchr(start, '\0', file.size() - offset);
    return end == nullptr ? std::string() : std::string(start, static_cast<const char*>(end));
}

}

std::string Symbols::Demangle(const std::string& name) {
    const std::string mangled = name.starts_with("__Z") ? name.substr(1) : name;
    if (!mangled.starts_with("_Z")) return name;
    int status = 0;
    std::unique_ptr<char, decltype(&std::free)> demangled(abi::__cxa_demangle(mangled.c_str(), nullptr, nullptr, &status), &std::free);
    return status == 0 && demangled != nullptr ? std::string(demangled.get()) : name;
}

std::vector<std::pair<std::uint64_t, std::string>> Symbols::ReadPeFunctions(const std::string& path, std::string& error) {
    std::vector<std::pair<std::uint64_t, std::string>> functions;
    std::ifstream stream(PathFromUtf8(path), std::ios::binary);
    if (!stream) {
        error = "cannot read " + path;
        return functions;
    }
    const std::vector<char> file((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
    std::uint16_t magic = 0;
    std::uint32_t headerOffset = 0;
    std::uint32_t signature = 0;
    if (!ReadAt(file, 0, magic) || magic != 0x5a4d || !ReadAt(file, 0x3c, headerOffset) || !ReadAt(file, headerOffset, signature) || signature != 0x4550) {
        error = path + " is not a PE image";
        return functions;
    }
    const std::size_t fileHeader = headerOffset + 4;
    std::uint16_t sectionCount = 0;
    std::uint32_t symbolTable = 0;
    std::uint32_t symbolCount = 0;
    std::uint16_t optionalSize = 0;
    ReadAt(file, fileHeader + 2, sectionCount);
    ReadAt(file, fileHeader + 8, symbolTable);
    ReadAt(file, fileHeader + 12, symbolCount);
    ReadAt(file, fileHeader + 16, optionalSize);
    const std::size_t optional = fileHeader + 20;
    std::vector<Section> sections;
    for (std::uint16_t index = 0; index < sectionCount; ++index) {
        const std::size_t entry = optional + optionalSize + index * 40u;
        Section section{};
        if (!ReadAt(file, entry + 8, section.virtualSize) || !ReadAt(file, entry + 12, section.virtualAddress) || !ReadAt(file, entry + 16, section.rawSize) || !ReadAt(file, entry + 20, section.rawOffset) ||
            !ReadAt(file, entry + 36, section.characteristics)) {
            error = path + " has a truncated section table";
            return functions;
        }
        sections.push_back(section);
    }
    if (symbolTable != 0 && symbolCount != 0) {
        const std::size_t strings = symbolTable + static_cast<std::size_t>(symbolCount) * 18;
        for (std::uint32_t index = 0; index < symbolCount; ++index) {
            const std::size_t entry = symbolTable + static_cast<std::size_t>(index) * 18;
            std::uint32_t value = 0;
            std::int16_t sectionNumber = 0;
            std::uint16_t type = 0;
            std::uint8_t storage = 0;
            std::uint8_t auxiliary = 0;
            if (!ReadAt(file, entry + 8, value) || !ReadAt(file, entry + 12, sectionNumber) || !ReadAt(file, entry + 14, type) || !ReadAt(file, entry + 16, storage) || !ReadAt(file, entry + 17, auxiliary)) break;
            index += auxiliary;
            if (sectionNumber <= 0 || sectionNumber > static_cast<int>(sections.size()) || (storage != 2 && storage != 3)) continue;
            const Section& section = sections[static_cast<std::size_t>(sectionNumber - 1)];
            if ((section.characteristics & 0x20000000u) == 0 || ((type >> 4) != 2 && storage != 2)) continue;
            std::uint32_t zeroes = 0;
            std::string name;
            if (ReadAt(file, entry, zeroes) && zeroes == 0) {
                std::uint32_t offset = 0;
                ReadAt(file, entry + 4, offset);
                name = CString(file, strings + offset);
            } else {
                name.assign(file.data() + entry, strnlen(file.data() + entry, 8));
            }
            if (name.empty() || name.starts_with('.')) continue;
            functions.emplace_back(static_cast<std::uint64_t>(section.virtualAddress) + value, name);
        }
    }
    const bool plus = optionalSize >= 112 + 8;
    std::uint32_t exportRva = 0;
    if (plus && ReadAt(file, optional + 112, exportRva) && exportRva != 0) {
        if (const auto directory = RvaToOffset(sections, exportRva)) {
            std::uint32_t functionCount = 0;
            std::uint32_t nameCount = 0;
            std::uint32_t addresses = 0;
            std::uint32_t names = 0;
            std::uint32_t ordinals = 0;
            ReadAt(file, *directory + 20, functionCount);
            ReadAt(file, *directory + 24, nameCount);
            ReadAt(file, *directory + 28, addresses);
            ReadAt(file, *directory + 32, names);
            ReadAt(file, *directory + 36, ordinals);
            const auto addressTable = RvaToOffset(sections, addresses);
            const auto nameTable = RvaToOffset(sections, names);
            const auto ordinalTable = RvaToOffset(sections, ordinals);
            for (std::uint32_t index = 0; addressTable && nameTable && ordinalTable && index < nameCount; ++index) {
                std::uint32_t nameRva = 0;
                std::uint16_t ordinal = 0;
                std::uint32_t functionRva = 0;
                if (!ReadAt(file, *nameTable + index * 4u, nameRva) || !ReadAt(file, *ordinalTable + index * 2u, ordinal) || ordinal >= functionCount || !ReadAt(file, *addressTable + ordinal * 4u, functionRva)) continue;
                const auto nameOffset = RvaToOffset(sections, nameRva);
                if (nameOffset) functions.emplace_back(functionRva, CString(file, *nameOffset));
            }
        }
    }
    std::sort(functions.begin(), functions.end());
    functions.erase(std::unique(functions.begin(), functions.end(), [](const auto& left, const auto& right) { return left.first == right.first; }), functions.end());
    return functions;
}

bool Symbols::Attach(std::uint64_t pid, std::string& error) {
    _pid = 0;
    _modules.clear();
#ifdef _WIN32
    const HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, static_cast<DWORD>(pid));
    if (process == nullptr) {
        error = "OpenProcess failed with " + std::to_string(GetLastError());
        return false;
    }
    std::vector<HMODULE> handles(1024);
    DWORD needed = 0;
    if (!K32EnumProcessModulesEx(process, handles.data(), static_cast<DWORD>(handles.size() * sizeof(HMODULE)), &needed, LIST_MODULES_ALL)) {
        error = "EnumProcessModulesEx failed with " + std::to_string(GetLastError());
        CloseHandle(process);
        return false;
    }
    handles.resize(std::min<std::size_t>(handles.size(), needed / sizeof(HMODULE)));
    for (const HMODULE handle : handles) {
        MODULEINFO information{};
        wchar_t path[MAX_PATH * 4];
        if (!K32GetModuleInformation(process, handle, &information, sizeof(information)) || K32GetModuleFileNameExW(process, handle, path, static_cast<DWORD>(std::size(path))) == 0) continue;
        Module module;
        module.path = Utf8(std::filesystem::path(path));
        module.name = Utf8(std::filesystem::path(path).filename());
        module.base = reinterpret_cast<std::uint64_t>(information.lpBaseOfDll);
        module.size = information.SizeOfImage;
        _modules.push_back(std::move(module));
    }
    CloseHandle(process);
#else
    std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
    if (!maps) {
        error = "cannot read /proc/" + std::to_string(pid) + "/maps";
        return false;
    }
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
        if (path.empty() || path.front() != '/') continue;
        const auto dash = range.find('-');
        const std::uint64_t start = std::strtoull(range.substr(0, dash).c_str(), nullptr, 16);
        const std::uint64_t end = std::strtoull(range.substr(dash + 1).c_str(), nullptr, 16);
        auto found = std::find_if(_modules.begin(), _modules.end(), [&path](const Module& module) { return module.path == path; });
        if (found == _modules.end()) {
            Module module;
            module.path = path;
            module.name = std::filesystem::path(path).filename().string();
            module.base = start - std::strtoull(offset.c_str(), nullptr, 16);
            module.size = end - module.base;
            _modules.push_back(std::move(module));
        } else {
            found->size = std::max(found->size, end - found->base);
        }
    }
#endif
    std::sort(_modules.begin(), _modules.end(), [](const Module& left, const Module& right) { return left.base < right.base; });
    _pid = pid;
    return true;
}

std::uint64_t Symbols::Pid() const {
    return _pid;
}

std::vector<Symbols::Module>& Symbols::Modules() {
    return _modules;
}

Location Symbols::locate(Module& module, std::uint64_t offset) {
    if (!module.parsed) {
        module.parsed = true;
#ifdef _WIN32
        module.functions = ReadPeFunctions(module.path, module.error);
#else
        module.error = "function names are read from PE images only";
#endif
    }
    Location location{module.name, module.path, module.base, offset, {}, 0};
    const auto found = std::upper_bound(module.functions.begin(), module.functions.end(), offset, [](std::uint64_t value, const auto& function) { return value < function.first; });
    if (found != module.functions.begin()) {
        const auto& function = *std::prev(found);
        location.function = Demangle(function.second);
        location.functionOffset = offset - function.first;
    }
    return location;
}

std::optional<Location> Symbols::Resolve(std::uint64_t address) {
    for (Module& module : _modules) {
        if (address >= module.base && address < module.base + module.size) return locate(module, address - module.base);
    }
    return std::nullopt;
}

std::optional<Location> Symbols::ResolveModuleOffset(const std::string& name, std::uint64_t offset) {
    const std::string wanted = Lower(name);
    for (Module& module : _modules) {
        if (Lower(module.name) == wanted) return locate(module, offset);
    }
    return std::nullopt;
}

std::optional<std::uint64_t> Symbols::Parse(const std::string& text) {
    const auto plus = text.rfind('+');
    if (plus != std::string::npos && plus > 0) {
        const std::string module = text.substr(0, plus);
        char* end = nullptr;
        const std::string offsetText = text.substr(plus + 1);
        const std::uint64_t offset = std::strtoull(offsetText.c_str(), &end, 0);
        if (end == offsetText.c_str() || *end != '\0') return std::nullopt;
        const std::string wanted = Lower(module);
        for (const Module& candidate : _modules) {
            if (Lower(candidate.name) == wanted) return candidate.base + offset;
        }
        return std::nullopt;
    }
    char* end = nullptr;
    const std::uint64_t address = std::strtoull(text.c_str(), &end, 0);
    if (end == text.c_str() || *end != '\0') return std::nullopt;
    return address;
}

std::string FormatLocation(const Location& location) {
    char offset[32];
    std::snprintf(offset, sizeof(offset), "+0x%llx", static_cast<unsigned long long>(location.offset));
    std::string text = location.module + offset;
    if (!location.function.empty()) {
        std::snprintf(offset, sizeof(offset), "+0x%llx", static_cast<unsigned long long>(location.functionOffset));
        text += " (" + location.function + offset + ")";
    }
    return text;
}

}
