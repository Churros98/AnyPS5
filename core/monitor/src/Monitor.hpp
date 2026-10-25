#ifndef CORE_MONITOR_SRC_MONITOR_HPP
#define CORE_MONITOR_SRC_MONITOR_HPP

#include "Session.hpp"
#include <cstdint>
#include <string>

namespace Monitor {

struct Options {
    std::uint64_t pid = 0;
    std::string names;
    double windowSeconds = 1.0;
    bool dump = false;
    double dumpSeconds = 1.5;
};

int Dump(Session& session, double seconds);
int RunWindow(Session& session, const Options& options);
void DrawMonitor(Session& session);

}

#endif
