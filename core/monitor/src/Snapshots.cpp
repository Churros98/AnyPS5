#include "Snapshots.hpp"
#include "Paths.hpp"
#include <algorithm>
#include <chrono>
#include <cmath>
#include <fstream>
#include <iterator>
#include <map>
#include <sstream>
#include <stdexcept>

namespace Monitor {

namespace {

void RequireName(const std::string& name) {
    const bool valid = !name.empty() && name.size() <= 64 && std::all_of(name.begin(), name.end(), [](char character) {
        return (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '-' || character == '_' || character == '.';
    }) && name.front() != '.';
    if (!valid) throw std::invalid_argument("a snapshot name has 1 to 64 letters, digits, '-', '_' or '.' and does not start with '.'");
}

std::filesystem::path PathOf(const std::string& name) {
    RequireName(name);
    return SnapshotDirectory() / (name + ".json");
}

double Number(const Json& object, const char* name) {
    const Json* value = object.Find(name);
    return value == nullptr || value->Type() != Json::Kind::Number ? 0.0 : value->AsNumber();
}

std::string Text(const Json& object, const char* name) {
    const Json* value = object.Find(name);
    return value == nullptr || value->Type() != Json::Kind::String ? std::string() : value->AsString();
}

Json Change(double before, double after) {
    return Json::Object({{"before", before}, {"after", after}, {"change", after - before}, {"change_percent", before == 0 ? Json() : Json((after - before) * 100.0 / before)}});
}

Json Differences(const Json& before, const Json& after, const char* list, const std::vector<const char*>& keys, const std::vector<const char*>& fields, const char* order, std::size_t limit) {
    struct Pair {
        const Json* before = nullptr;
        const Json* after = nullptr;
    };
    std::map<std::string, Pair> pairs;
    const auto key = [&keys](const Json& item) {
        std::string text;
        for (const char* part : keys) text += Text(item, part) + "\n";
        return text;
    };
    if (const Json* items = before.Find(list)) {
        for (const Json& item : items->Items()) pairs[key(item)].before = &item;
    }
    if (const Json* items = after.Find(list)) {
        for (const Json& item : items->Items()) pairs[key(item)].after = &item;
    }
    std::vector<std::pair<double, Json>> rows;
    for (const auto& [name, pair] : pairs) {
        const Json& identity = pair.after != nullptr ? *pair.after : *pair.before;
        Json row = Json::Object();
        for (const char* part : keys) row.Set(part, Text(identity, part));
        if (const Json* display = identity.Find("display_name")) row.Set("display_name", *display);
        row.Set("only_in", pair.before == nullptr ? Json("after") : pair.after == nullptr ? Json("before") : Json());
        double weight = 0;
        for (const char* field : fields) {
            const double first = pair.before != nullptr ? Number(*pair.before, field) : 0;
            const double second = pair.after != nullptr ? Number(*pair.after, field) : 0;
            row.Set(field, Change(first, second));
            if (std::string(field) == order) weight = std::abs(second - first);
        }
        rows.emplace_back(weight, std::move(row));
    }
    std::stable_sort(rows.begin(), rows.end(), [](const auto& left, const auto& right) { return left.first > right.first; });
    Json result = Json::Array();
    for (std::size_t index = 0; index < std::min(limit, rows.size()); ++index) result.Push(rows[index].second);
    return result;
}

}

std::filesystem::path SnapshotDirectory() {
    return std::filesystem::temp_directory_path() / "anyps5-telemetry" / "snapshots";
}

Json CaptureSnapshot(const Session& session, const std::string& name, const std::string& note) {
    RequireName(name);
    const FrameSummary frames = session.Summarize(1.0);
    const auto saved = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    Json imports = Json::Array();
    for (const ImportRate& rate : session.Imports()) {
        imports.Push(Json::Object({{"name", rate.name}, {"display_name", session.DisplayName(rate.name)}, {"library", rate.library}, {"exclusive_ms_per_s", rate.exclusiveMsPerSecond},
            {"inclusive_ms_per_s", rate.inclusiveMsPerSecond}, {"calls_per_s", rate.callsPerSecond}, {"average_us", rate.averageUs}, {"p99_us", rate.p99Us}}));
    }
    Json phases = Json::Array();
    for (const PhaseRate& phase : session.Phases()) {
        phases.Push(Json::Object({{"thread", phase.thread}, {"name", phase.name}, {"ms_per_s", phase.msPerSecond}, {"average_us", phase.averageUs}}));
    }
    Json threads = Json::Array();
    for (const ThreadRate& thread : session.Threads()) threads.Push(Json::Object({{"thread", std::to_string(thread.thread)}, {"import_ms_per_s", thread.importMsPerSecond}}));
    return Json::Object({{"name", name}, {"note", note}, {"saved_at", static_cast<double>(saved)}, {"pid", session.Pid()}, {"window_seconds", session.WindowSeconds()},
        {"frames", Json::Object({{"count", static_cast<std::uint64_t>(frames.frames)}, {"fps", frames.fps}, {"average_ms", frames.averageMs}, {"p50_ms", frames.p50Ms}, {"p99_ms", frames.p99Ms},
            {"max_ms", frames.maxMs}, {"gpu_ms", frames.gpuTimed ? Json(frames.gpuMs) : Json()}, {"driver_ms", frames.driverTimed ? Json(frames.driverMs) : Json()}})},
        {"verdict", session.Judge().title}, {"imports", std::move(imports)}, {"phases", std::move(phases)}, {"threads", std::move(threads)}});
}

void SaveSnapshot(const Json& snapshot) {
    const std::filesystem::path path = PathOf(snapshot.Find("name")->AsString());
    std::filesystem::create_directories(path.parent_path());
    const std::filesystem::path temporary = path.string() + ".tmp";
    {
        std::ofstream file(temporary, std::ios::binary | std::ios::trunc);
        file << snapshot.Dump() << '\n';
        if (!file) throw std::runtime_error("cannot write " + temporary.string());
    }
    std::error_code ignored;
    std::filesystem::remove(path, ignored);
    std::filesystem::rename(temporary, path);
}

Json LoadSnapshot(const std::string& name) {
    const std::filesystem::path path = PathOf(name);
    std::ifstream file(path, std::ios::binary);
    if (!file) throw std::runtime_error("no snapshot named " + name);
    const std::string text((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    return Json::Parse(text);
}

std::vector<Json> ListSnapshots() {
    std::vector<Json> snapshots;
    std::error_code error;
    if (!std::filesystem::is_directory(SnapshotDirectory(), error)) return snapshots;
    for (const auto& entry : std::filesystem::directory_iterator(SnapshotDirectory(), error)) {
        if (entry.path().extension() != ".json") continue;
        try {
            const Json snapshot = LoadSnapshot(entry.path().stem().string());
            snapshots.push_back(Json::Object({{"name", Text(snapshot, "name")}, {"note", Text(snapshot, "note")}, {"saved_at", Number(snapshot, "saved_at")}, {"pid", Number(snapshot, "pid")},
                {"fps", snapshot.Find("frames") != nullptr ? Number(*snapshot.Find("frames"), "fps") : 0.0}}));
        } catch (const std::exception&) {
            continue;
        }
    }
    std::sort(snapshots.begin(), snapshots.end(), [](const Json& left, const Json& right) { return Number(left, "saved_at") < Number(right, "saved_at"); });
    return snapshots;
}

Json CompareSnapshots(const Json& before, const Json& after, std::size_t limit) {
    const Json empty = Json::Object();
    const Json& first = before.Find("frames") != nullptr ? *before.Find("frames") : empty;
    const Json& second = after.Find("frames") != nullptr ? *after.Find("frames") : empty;
    Json frames = Json::Object();
    for (const char* field : {"fps", "average_ms", "p50_ms", "p99_ms", "max_ms", "gpu_ms", "driver_ms"}) frames.Set(field, Change(Number(first, field), Number(second, field)));
    return Json::Object({{"before", Text(before, "name")}, {"after", Text(after, "name")}, {"verdict_before", Text(before, "verdict")}, {"verdict_after", Text(after, "verdict")},
        {"frames", std::move(frames)},
        {"imports", Differences(before, after, "imports", {"name", "library"}, {"exclusive_ms_per_s", "calls_per_s", "average_us", "p99_us"}, "exclusive_ms_per_s", limit)},
        {"phases", Differences(before, after, "phases", {"thread", "name"}, {"ms_per_s", "average_us"}, "ms_per_s", limit)},
        {"threads", Differences(before, after, "threads", {"thread"}, {"import_ms_per_s"}, "import_ms_per_s", limit)}});
}

}
