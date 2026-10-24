#include "Mcp.hpp"
#include "Monitor.hpp"
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>

namespace {

constexpr const char* Usage = "usage: anyps5-monitor [--pid <pid>] [--nid-names <file>] [--window <seconds>] [--dump [--seconds <seconds>] | --mcp]\n";

double ParseSeconds(std::string_view option, const char* value) {
    char* end = nullptr;
    const double seconds = std::strtod(value, &end);
    if (end == value || *end != '\0' || !(seconds >= 0.2 && seconds <= 30.0)) throw std::runtime_error(std::string(option) + " takes seconds from 0.2 to 30");
    return seconds;
}

Monitor::Options ParseOptions(int argc, char** argv) {
    Monitor::Options options;
    for (int index = 1; index < argc; ++index) {
        const std::string_view argument(argv[index]);
        const auto value = [&]() -> const char* {
            if (index + 1 >= argc) throw std::runtime_error(std::string(argument) + " needs a value\n" + Usage);
            return argv[++index];
        };
        if (argument == "--pid") {
            const char* text = value();
            char* end = nullptr;
            options.pid = std::strtoull(text, &end, 10);
            if (end == text || *end != '\0' || options.pid == 0) throw std::runtime_error("--pid takes a process id");
        } else if (argument == "--nid-names") {
            options.names = value();
        } else if (argument == "--window") {
            options.windowSeconds = ParseSeconds(argument, value());
        } else if (argument == "--dump") {
            options.dump = true;
        } else if (argument == "--mcp") {
            options.mcp = true;
        } else if (argument == "--seconds") {
            options.dumpSeconds = ParseSeconds(argument, value());
        } else if (argument == "--help") {
            std::fputs(Usage, stdout);
            std::exit(0);
        } else {
            throw std::runtime_error("unknown argument " + std::string(argument) + "\n" + Usage);
        }
    }
    if (options.dump && options.mcp) throw std::runtime_error("--dump and --mcp cannot be combined");
    return options;
}

}

int main(int argc, char** argv) {
    try {
        const Monitor::Options options = ParseOptions(argc, argv);
        Monitor::Session session;
        session.SetWindow(options.windowSeconds);
        if (!options.names.empty()) session.LoadNames(options.names);
        else if (!session.LoadDefaultNames()) std::fprintf(stderr, "anyps5-monitor: import names stay NIDs: no NID database at %s; run python3 tools/nid_names.py once to download it, or pass --nid-names\n", Monitor::Session::DefaultNamesPath().string().c_str());
        if (options.mcp) {
#ifdef _WIN32
            _setmode(_fileno(stdin), _O_BINARY);
            _setmode(_fileno(stdout), _O_BINARY);
#endif
            return Monitor::RunMcp(session, options.pid, std::cin, std::cout);
        }
        if (options.dump) {
            std::uint64_t pid = options.pid;
            if (pid == 0) {
                const auto found = Monitor::Session::Discover();
                if (found.size() != 1) throw std::runtime_error(found.empty() ? "no process publishes telemetry (run it from a build configured with -DAPS5_ENABLE_PROFILER=ON)" : "several processes publish telemetry; pass --pid");
                pid = found.front();
            }
            if (!session.Connect(pid)) throw std::runtime_error("cannot open the telemetry of process " + std::to_string(pid));
            return Monitor::Dump(session, options.dumpSeconds);
        }
        return Monitor::RunWindow(session, options);
    } catch (const std::exception& error) {
        std::fprintf(stderr, "anyps5-monitor: %s\n", error.what());
        return 1;
    }
}
