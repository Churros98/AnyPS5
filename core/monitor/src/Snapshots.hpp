#ifndef CORE_MONITOR_SRC_SNAPSHOTS_HPP
#define CORE_MONITOR_SRC_SNAPSHOTS_HPP

#include "Json.hpp"
#include "Session.hpp"
#include <cstddef>
#include <filesystem>
#include <string>
#include <vector>

namespace Monitor {

std::filesystem::path SnapshotDirectory();
Json CaptureSnapshot(const Session& session, const std::string& name, const std::string& note);
void SaveSnapshot(const Json& snapshot);
Json LoadSnapshot(const std::string& name);
std::vector<Json> ListSnapshots();
Json CompareSnapshots(const Json& before, const Json& after, std::size_t limit);

}

#endif
