#include "Monitor.hpp"
#include "imgui.h"
#include <algorithm>
#include <cctype>
#include <cfloat>
#include <cstdio>
#include <string>
#include <vector>

namespace Monitor {

namespace {

struct ViewState {
    char filter[128] = "";
    float windowSeconds = 1.0f;
    bool pauseSlow = false;
    float slowMinimumMs = 0.0f;
    std::vector<SlowCallView> frozenSlow;
    std::vector<std::uint64_t> processes;
};

ViewState& State() {
    static ViewState state;
    return state;
}

bool Contains(const std::string& text, const char* filter) {
    if (*filter == '\0') return true;
    std::string haystack = text;
    std::string needle = filter;
    std::transform(haystack.begin(), haystack.end(), haystack.begin(), [](unsigned char character) { return static_cast<char>(std::tolower(character)); });
    std::transform(needle.begin(), needle.end(), needle.begin(), [](unsigned char character) { return static_cast<char>(std::tolower(character)); });
    return haystack.find(needle) != std::string::npos;
}

void DrawConnection(Session& session) {
    ViewState& state = State();
    if (!session.Connected()) {
        ImGui::TextColored(ImVec4(1.0f, 0.6f, 0.2f, 1.0f), "Waiting for a process built with APS5_ENABLE_PROFILER=ON");
    } else if (session.Stale()) {
        ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "Process %llu stopped publishing: showing its last data", static_cast<unsigned long long>(session.Pid()));
    } else {
        ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.5f, 1.0f), "Connected to process %llu", static_cast<unsigned long long>(session.Pid()));
    }
    ImGui::SameLine();
    ImGui::SetNextItemWidth(140);
    const std::string current = session.Connected() ? std::to_string(session.Pid()) : "none";
    if (ImGui::BeginCombo("##process", current.c_str())) {
        if (ImGui::IsWindowAppearing()) state.processes = Session::Discover();
        for (const std::uint64_t pid : state.processes) {
            const std::string label = std::to_string(pid);
            if (ImGui::Selectable(label.c_str(), pid == session.Pid())) session.Connect(pid);
        }
        if (state.processes.empty()) ImGui::TextDisabled("no process");
        ImGui::EndCombo();
    }
    ImGui::SameLine();
    ImGui::SetNextItemWidth(160);
    if (ImGui::SliderFloat("rate window (s)", &state.windowSeconds, 0.2f, 30.0f, "%.1f")) session.SetWindow(state.windowSeconds);
    if (session.Connected()) {
        const Telemetry::Header& header = session.Header();
        const double cost = header.ticksPerSecond == 0 ? 0 : static_cast<double>(header.overheadTicks) * 1e9 / static_cast<double>(header.ticksPerSecond);
        ImGui::SameLine();
        ImGui::TextDisabled("profiler cost %.0f ns per call, %llu publishes", cost, static_cast<unsigned long long>(header.publishes));
    }
}

void Bar(const char* label, double value, double total, const char* unit) {
    const float fraction = total > 0 ? static_cast<float>(std::clamp(value / total, 0.0, 1.0)) : 0.0f;
    char overlay[96];
    std::snprintf(overlay, sizeof(overlay), "%.2f %s", value, unit);
    ImGui::TextUnformatted(label);
    ImGui::SameLine(220);
    ImGui::ProgressBar(fraction, ImVec2(-1, 0), overlay);
}

void DrawBudget(Session& session) {
    const Verdict verdict = session.Judge();
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.85f, 0.3f, 1.0f));
    ImGui::TextUnformatted(verdict.title.c_str());
    ImGui::PopStyleColor();
    ImGui::TextWrapped("%s", verdict.detail.c_str());
    ImGui::Separator();
    const FrameSummary frames = session.Summarize(1.0);
    Bar("frame", frames.averageMs, frames.averageMs, "ms");
    if (frames.gpuTimed) Bar("GPU (APS5_PROFILE_GPU)", frames.gpuMs, frames.averageMs, "ms");
    else ImGui::TextDisabled("GPU: not timed, set APS5_PROFILE_GPU=1");
    if (frames.driverTimed) Bar("agc driver (APS5_PROFILE_DRAW)", frames.driverMs, frames.averageMs, "ms");
    else ImGui::TextDisabled("agc driver: not timed, set APS5_PROFILE_DRAW=1");
    std::vector<ThreadRate> threads = session.Threads();
    std::sort(threads.begin(), threads.end(), [](const ThreadRate& left, const ThreadRate& right) { return left.importMsPerSecond > right.importMsPerSecond; });
    for (std::size_t index = 0; index < std::min<std::size_t>(4, threads.size()); ++index) {
        const std::string label = "thread " + std::to_string(threads[index].thread) + " in imports";
        Bar(label.c_str(), frames.fps > 0 ? threads[index].importMsPerSecond / frames.fps : 0, frames.averageMs, "ms");
    }
}

void DrawFrames(Session& session) {
    const FrameSummary summary = session.Summarize(1.0);
    ImGui::Text("%.1f fps   frame avg %.2f   p50 %.2f   p99 %.2f   max %.2f ms   (%zu presents in the last second)", summary.fps, summary.averageMs, summary.p50Ms, summary.p99Ms, summary.maxMs, summary.frames);
    std::vector<float> frame;
    std::vector<float> gpu;
    std::vector<float> driver;
    std::vector<float> draws;
    for (const FrameSample& sample : session.Frames()) {
        frame.push_back(static_cast<float>(sample.frameMs));
        gpu.push_back(static_cast<float>(sample.gpuMs));
        driver.push_back(static_cast<float>(sample.driverMs));
        draws.push_back(static_cast<float>(sample.draws));
    }
    if (frame.empty()) {
        ImGui::TextDisabled("no presents yet");
        return;
    }
    const float top = std::max(*std::max_element(frame.begin(), frame.end()), 1.0f) * 1.1f;
    const ImVec2 size(-1, 140);
    ImGui::PlotLines("frame ms", frame.data(), static_cast<int>(frame.size()), 0, nullptr, 0.0f, top, size);
    if (summary.gpuTimed) ImGui::PlotLines("GPU ms", gpu.data(), static_cast<int>(gpu.size()), 0, nullptr, 0.0f, top, size);
    if (summary.driverTimed) ImGui::PlotLines("driver ms", driver.data(), static_cast<int>(driver.size()), 0, nullptr, 0.0f, std::max(top, *std::max_element(driver.begin(), driver.end())), size);
    ImGui::PlotLines("draws", draws.data(), static_cast<int>(draws.size()), 0, nullptr, 0.0f, FLT_MAX, ImVec2(-1, 80));
}

void DrawImports(Session& session) {
    ViewState& state = State();
    ImGui::SetNextItemWidth(260);
    ImGui::InputTextWithHint("##filter", "filter by name or library", state.filter, sizeof(state.filter));
    std::vector<ImportRate> rows;
    for (const ImportRate& rate : session.Imports()) {
        if (Contains(session.DisplayName(rate.name), state.filter) || Contains(rate.name, state.filter) || Contains(rate.library, state.filter)) rows.push_back(rate);
    }
    ImGui::SameLine();
    ImGui::TextDisabled("%zu of %zu imports, rates over %.1f s", rows.size(), session.Imports().size(), session.WindowSeconds());
    const ImGuiTableFlags flags = ImGuiTableFlags_Sortable | ImGuiTableFlags_Resizable | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit;
    if (!ImGui::BeginTable("imports", 11, flags)) return;
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("import", ImGuiTableColumnFlags_WidthStretch);
    ImGui::TableSetupColumn("library");
    ImGui::TableSetupColumn("excl ms/s", ImGuiTableColumnFlags_DefaultSort | ImGuiTableColumnFlags_PreferSortDescending);
    ImGui::TableSetupColumn("incl ms/s", ImGuiTableColumnFlags_PreferSortDescending);
    ImGui::TableSetupColumn("calls/s", ImGuiTableColumnFlags_PreferSortDescending);
    ImGui::TableSetupColumn("avg us", ImGuiTableColumnFlags_PreferSortDescending);
    ImGui::TableSetupColumn("p50 us", ImGuiTableColumnFlags_PreferSortDescending);
    ImGui::TableSetupColumn("p99 us", ImGuiTableColumnFlags_PreferSortDescending);
    ImGui::TableSetupColumn("max us", ImGuiTableColumnFlags_PreferSortDescending);
    ImGui::TableSetupColumn("excl ms total", ImGuiTableColumnFlags_PreferSortDescending);
    ImGui::TableSetupColumn("calls", ImGuiTableColumnFlags_PreferSortDescending);
    ImGui::TableHeadersRow();
    if (const ImGuiTableSortSpecs* specs = ImGui::TableGetSortSpecs(); specs != nullptr && specs->SpecsCount > 0) {
        const ImGuiTableColumnSortSpecs& spec = specs->Specs[0];
        const auto key = [&session, column = spec.ColumnIndex](const ImportRate& rate) -> double {
            switch (column) {
                case 2: return rate.exclusiveMsPerSecond;
                case 3: return rate.inclusiveMsPerSecond;
                case 4: return rate.callsPerSecond;
                case 5: return rate.averageUs;
                case 6: return rate.p50Us;
                case 7: return rate.p99Us;
                case 8: return rate.maxUs;
                case 9: return rate.totalExclusiveMs;
                case 10: return static_cast<double>(rate.calls);
                default: return 0;
            }
        };
        const bool ascending = spec.SortDirection == ImGuiSortDirection_Ascending;
        std::stable_sort(rows.begin(), rows.end(), [&](const ImportRate& left, const ImportRate& right) {
            if (spec.ColumnIndex == 0) return ascending ? session.DisplayName(left.name) < session.DisplayName(right.name) : session.DisplayName(left.name) > session.DisplayName(right.name);
            if (spec.ColumnIndex == 1) return ascending ? left.library < right.library : left.library > right.library;
            return ascending ? key(left) < key(right) : key(left) > key(right);
        });
    }
    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(rows.size()));
    while (clipper.Step()) {
        for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
            const ImportRate& rate = rows[static_cast<std::size_t>(row)];
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            const std::string name = session.DisplayName(rate.name);
            ImGui::TextUnformatted(name.c_str());
            if (name != rate.name && ImGui::IsItemHovered()) ImGui::SetTooltip("%s", rate.name.c_str());
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(rate.library.c_str());
            ImGui::TableNextColumn();
            ImGui::Text("%.3f", rate.exclusiveMsPerSecond);
            ImGui::TableNextColumn();
            ImGui::Text("%.3f", rate.inclusiveMsPerSecond);
            ImGui::TableNextColumn();
            ImGui::Text("%.0f", rate.callsPerSecond);
            ImGui::TableNextColumn();
            ImGui::Text("%.2f", rate.averageUs);
            ImGui::TableNextColumn();
            ImGui::Text("%.2f", rate.p50Us);
            ImGui::TableNextColumn();
            ImGui::Text("%.2f", rate.p99Us);
            ImGui::TableNextColumn();
            ImGui::Text("%.2f", rate.maxUs);
            ImGui::TableNextColumn();
            ImGui::Text("%.1f", rate.totalExclusiveMs);
            ImGui::TableNextColumn();
            ImGui::Text("%llu", static_cast<unsigned long long>(rate.calls));
        }
    }
    ImGui::EndTable();
}

void DrawThreads(Session& session) {
    std::vector<ThreadRate> threads = session.Threads();
    std::sort(threads.begin(), threads.end(), [](const ThreadRate& left, const ThreadRate& right) { return left.importMsPerSecond > right.importMsPerSecond; });
    if (!ImGui::BeginTable("threads", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY)) return;
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("thread");
    ImGui::TableSetupColumn("ms/s in imports");
    ImGui::TableSetupColumn("timed calls/s");
    ImGui::TableHeadersRow();
    for (const ThreadRate& thread : threads) {
        ImGui::TableNextRow();
        ImGui::TableNextColumn();
        ImGui::Text("%llu", static_cast<unsigned long long>(thread.thread));
        ImGui::TableNextColumn();
        ImGui::ProgressBar(static_cast<float>(std::clamp(thread.importMsPerSecond / 1000.0, 0.0, 1.0)), ImVec2(-1, 0), (std::to_string(static_cast<int>(thread.importMsPerSecond)) + " ms/s").c_str());
        ImGui::TableNextColumn();
        ImGui::Text("%.0f", thread.callsPerSecond);
    }
    ImGui::EndTable();
}

void DrawSlowCalls(Session& session) {
    ViewState& state = State();
    if (ImGui::Checkbox("pause", &state.pauseSlow) && state.pauseSlow) state.frozenSlow.assign(session.SlowCalls().begin(), session.SlowCalls().end());
    ImGui::SameLine();
    ImGui::SetNextItemWidth(200);
    ImGui::SliderFloat("minimum ms", &state.slowMinimumMs, 0.0f, 100.0f, "%.1f");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(220);
    ImGui::InputTextWithHint("##slowfilter", "filter by import", state.filter, sizeof(state.filter));
    const std::vector<SlowCallView> live(session.SlowCalls().begin(), session.SlowCalls().end());
    const std::vector<SlowCallView>& calls = state.pauseSlow ? state.frozenSlow : live;
    if (!ImGui::BeginTable("slow", 5, ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable)) return;
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("seen at s");
    ImGui::TableSetupColumn("ms");
    ImGui::TableSetupColumn("thread");
    ImGui::TableSetupColumn("caller");
    ImGui::TableSetupColumn("import", ImGuiTableColumnFlags_WidthStretch);
    ImGui::TableHeadersRow();
    for (auto call = calls.rbegin(); call != calls.rend(); ++call) {
        const std::string name = session.DisplayName(call->import);
        if (call->milliseconds < state.slowMinimumMs || !(Contains(name, state.filter) || Contains(call->import, state.filter))) continue;
        ImGui::TableNextRow();
        ImGui::TableNextColumn();
        ImGui::Text("%.1f", call->atSeconds);
        ImGui::TableNextColumn();
        ImGui::Text("%.3f", call->milliseconds);
        ImGui::TableNextColumn();
        ImGui::Text("%llu", static_cast<unsigned long long>(call->thread));
        ImGui::TableNextColumn();
        ImGui::Text("0x%016llx", static_cast<unsigned long long>(call->returnAddress));
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(name.c_str());
    }
    ImGui::EndTable();
}

void DrawRecentCalls(Session& session) {
    const auto& calls = session.RecentCalls();
    if (!ImGui::BeginTable("recent", 4, ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY)) return;
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("thread");
    ImGui::TableSetupColumn("caller");
    ImGui::TableSetupColumn("library");
    ImGui::TableSetupColumn("import", ImGuiTableColumnFlags_WidthStretch);
    ImGui::TableHeadersRow();
    for (auto call = calls.rbegin(); call != calls.rend(); ++call) {
        ImGui::TableNextRow();
        ImGui::TableNextColumn();
        ImGui::Text("%llu", static_cast<unsigned long long>(call->thread));
        ImGui::TableNextColumn();
        ImGui::Text("0x%016llx", static_cast<unsigned long long>(call->returnAddress));
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(call->library);
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(session.DisplayName(call->name).c_str());
    }
    ImGui::EndTable();
}

}

void DrawMonitor(Session& session) {
    const ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(viewport->WorkPos);
    ImGui::SetNextWindowSize(viewport->WorkSize);
    ImGui::Begin("AnyPS5 monitor", nullptr, ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoBringToFrontOnFocus);
    DrawConnection(session);
    ImGui::Separator();
    if (ImGui::BeginTabBar("views")) {
        if (ImGui::BeginTabItem("Budget")) {
            DrawBudget(session);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Frames")) {
            DrawFrames(session);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Imports")) {
            DrawImports(session);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Threads")) {
            DrawThreads(session);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Slow calls")) {
            DrawSlowCalls(session);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Last calls")) {
            DrawRecentCalls(session);
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
    ImGui::End();
}

}
