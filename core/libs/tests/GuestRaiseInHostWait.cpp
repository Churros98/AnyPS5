#include "prx/libkernel/include/Api.hpp"
#include "SceTypes.hpp"
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <thread>

static constexpr int SigUsr1 = 30;
static constexpr int Rounds = 20;
static void Require(bool value) { if (!value) std::abort(); }

static std::mutex hostLock;
static std::atomic<int> round{0};
static std::atomic<int> waiting{0};
static std::atomic<int> acquired{0};
static std::atomic<int> deliveries{0};
static std::atomic<int> released{0};
static std::atomic<bool> stop{false};

static void APS5_VABI Handler(int, void*) {
    const auto delivery = deliveries.fetch_add(1) + 1;
    while (released.load() < delivery) std::this_thread::yield();
}

static void* APS5_VABI Locker(void*) {
    int seen = 0;
    while (!stop.load()) {
        if (round.load() == seen) {
            std::this_thread::yield();
            continue;
        }
        seen = round.load();
        waiting.fetch_add(1);
        hostLock.lock();
        acquired.fetch_add(1);
        hostLock.unlock();
    }
    return nullptr;
}

static void WaitFor(const std::atomic<int>& value, int target) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (value.load() < target) {
        if (std::chrono::steady_clock::now() > deadline) std::abort();
        std::this_thread::yield();
    }
}

int main() {
    std::atomic<bool> done{false};
    std::thread watchdog([&done] {
        for (int i = 0; i < 25000 && !done.load(); ++i) std::this_thread::sleep_for(std::chrono::milliseconds(1));
        if (!done.load()) std::abort();
    });
    Require(sceKernelInstallExceptionHandler(SigUsr1, reinterpret_cast<void*>(&Handler)) == 0);
    Pthread target = nullptr;
    Pthread other = nullptr;
    Require(scePthreadCreate(&target, nullptr, Locker, nullptr, "host waiter") == 0);
    Require(scePthreadCreate(&other, nullptr, Locker, nullptr, "second waiter") == 0);
    auto longest = std::chrono::steady_clock::duration::zero();
    for (int index = 1; index <= Rounds; ++index) {
        hostLock.lock();
        round.store(index);
        WaitFor(waiting, index * 2);
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        std::thread raiser([&] {
            const auto raisedAt = std::chrono::steady_clock::now();
            Require(sceKernelRaiseException(target, SigUsr1) == 0);
            longest = std::max(longest, std::chrono::steady_clock::now() - raisedAt);
        });
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        hostLock.unlock();
        WaitFor(acquired, index * 2);
        WaitFor(deliveries, index);
        released.store(index);
        raiser.join();
    }
    stop.store(true);
    round.store(Rounds + 1);
    Require(scePthreadJoin(target, nullptr) == 0);
    Require(scePthreadJoin(other, nullptr) == 0);
    Require(sceKernelRemoveExceptionHandler(SigUsr1) == 0);
    std::printf("longest raise: %.2f ms\n", std::chrono::duration<double, std::milli>(longest).count());
    done.store(true);
    watchdog.join();
}
