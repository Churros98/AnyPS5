#define SDL_MAIN_HANDLED
#include "Monitor.hpp"
#include "imgui.h"
#include "imgui_impl_vulkan.h"
#include "imgui_impl_sdl2.h"
#include <SDL.h>
#include <SDL_vulkan.h>
#include <algorithm>
#include <chrono>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace Monitor {

namespace {

constexpr std::uint32_t MinImageCount = 2;
constexpr auto PollInterval = std::chrono::milliseconds(50);
constexpr auto DiscoverInterval = std::chrono::seconds(1);

PFN_vkGetInstanceProcAddr vkGetInstanceProcAddr = nullptr;
PFN_vkEnumerateInstanceExtensionProperties vkEnumerateInstanceExtensionProperties = nullptr;
PFN_vkCreateInstance vkCreateInstance = nullptr;
PFN_vkDestroyInstance vkDestroyInstance = nullptr;
PFN_vkCreateDevice vkCreateDevice = nullptr;
PFN_vkDestroyDevice vkDestroyDevice = nullptr;
PFN_vkGetDeviceQueue vkGetDeviceQueue = nullptr;
PFN_vkCreateDescriptorPool vkCreateDescriptorPool = nullptr;
PFN_vkDestroyDescriptorPool vkDestroyDescriptorPool = nullptr;
PFN_vkGetPhysicalDeviceSurfaceSupportKHR vkGetPhysicalDeviceSurfaceSupportKHR = nullptr;
PFN_vkAcquireNextImageKHR vkAcquireNextImageKHR = nullptr;
PFN_vkWaitForFences vkWaitForFences = nullptr;
PFN_vkResetFences vkResetFences = nullptr;
PFN_vkResetCommandPool vkResetCommandPool = nullptr;
PFN_vkBeginCommandBuffer vkBeginCommandBuffer = nullptr;
PFN_vkCmdBeginRenderPass vkCmdBeginRenderPass = nullptr;
PFN_vkCmdEndRenderPass vkCmdEndRenderPass = nullptr;
PFN_vkEndCommandBuffer vkEndCommandBuffer = nullptr;
PFN_vkQueueSubmit vkQueueSubmit = nullptr;
PFN_vkQueuePresentKHR vkQueuePresentKHR = nullptr;
PFN_vkDeviceWaitIdle vkDeviceWaitIdle = nullptr;

void Check(VkResult result) {
    if (result < 0) throw std::runtime_error("Vulkan call failed with " + std::to_string(static_cast<int>(result)));
}

template <typename TFunction>
void Load(TFunction& function, VkInstance instance, const char* name) {
    function = reinterpret_cast<TFunction>(vkGetInstanceProcAddr(instance, name));
    if (function == nullptr) throw std::runtime_error(std::string("Vulkan function ") + name + " is missing");
}

struct Vulkan {
    VkInstance instance = VK_NULL_HANDLE;
    VkPhysicalDevice physicalDevice = VK_NULL_HANDLE;
    std::uint32_t queueFamily = 0;
    VkDevice device = VK_NULL_HANDLE;
    VkQueue queue = VK_NULL_HANDLE;
    VkDescriptorPool descriptorPool = VK_NULL_HANDLE;
    ImGui_ImplVulkanH_Window window{};
    bool rebuild = false;
};

PFN_vkVoidFunction LoadForImGui(const char* name, void* instance) {
    return vkGetInstanceProcAddr(static_cast<VkInstance>(instance), name);
}

void CreateInstance(Vulkan& vulkan, SDL_Window* window) {
    vkGetInstanceProcAddr = reinterpret_cast<PFN_vkGetInstanceProcAddr>(SDL_Vulkan_GetVkGetInstanceProcAddr());
    if (vkGetInstanceProcAddr == nullptr) throw std::runtime_error(std::string("SDL_Vulkan_GetVkGetInstanceProcAddr: ") + SDL_GetError());
    Load(vkEnumerateInstanceExtensionProperties, VK_NULL_HANDLE, "vkEnumerateInstanceExtensionProperties");
    Load(vkCreateInstance, VK_NULL_HANDLE, "vkCreateInstance");
    unsigned int count = 0;
    if (!SDL_Vulkan_GetInstanceExtensions(window, &count, nullptr)) throw std::runtime_error(SDL_GetError());
    std::vector<const char*> extensions(count);
    if (!SDL_Vulkan_GetInstanceExtensions(window, &count, extensions.data())) throw std::runtime_error(SDL_GetError());
    VkApplicationInfo application{};
    application.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    application.pApplicationName = "anyps5-monitor";
    application.apiVersion = VK_API_VERSION_1_0;
    VkInstanceCreateInfo info{};
    info.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    info.pApplicationInfo = &application;
    info.enabledExtensionCount = static_cast<std::uint32_t>(extensions.size());
    info.ppEnabledExtensionNames = extensions.data();
    Check(vkCreateInstance(&info, nullptr, &vulkan.instance));
    Load(vkDestroyInstance, vulkan.instance, "vkDestroyInstance");
    Load(vkCreateDevice, vulkan.instance, "vkCreateDevice");
    Load(vkDestroyDevice, vulkan.instance, "vkDestroyDevice");
    Load(vkGetDeviceQueue, vulkan.instance, "vkGetDeviceQueue");
    Load(vkCreateDescriptorPool, vulkan.instance, "vkCreateDescriptorPool");
    Load(vkDestroyDescriptorPool, vulkan.instance, "vkDestroyDescriptorPool");
    Load(vkGetPhysicalDeviceSurfaceSupportKHR, vulkan.instance, "vkGetPhysicalDeviceSurfaceSupportKHR");
    Load(vkAcquireNextImageKHR, vulkan.instance, "vkAcquireNextImageKHR");
    Load(vkWaitForFences, vulkan.instance, "vkWaitForFences");
    Load(vkResetFences, vulkan.instance, "vkResetFences");
    Load(vkResetCommandPool, vulkan.instance, "vkResetCommandPool");
    Load(vkBeginCommandBuffer, vulkan.instance, "vkBeginCommandBuffer");
    Load(vkCmdBeginRenderPass, vulkan.instance, "vkCmdBeginRenderPass");
    Load(vkCmdEndRenderPass, vulkan.instance, "vkCmdEndRenderPass");
    Load(vkEndCommandBuffer, vulkan.instance, "vkEndCommandBuffer");
    Load(vkQueueSubmit, vulkan.instance, "vkQueueSubmit");
    Load(vkQueuePresentKHR, vulkan.instance, "vkQueuePresentKHR");
    Load(vkDeviceWaitIdle, vulkan.instance, "vkDeviceWaitIdle");
    if (!ImGui_ImplVulkan_LoadFunctions(VK_API_VERSION_1_0, LoadForImGui, vulkan.instance)) throw std::runtime_error("ImGui could not load the Vulkan functions");
}

void CreateDevice(Vulkan& vulkan, VkSurfaceKHR surface, int width, int height) {
    vulkan.physicalDevice = ImGui_ImplVulkanH_SelectPhysicalDevice(vulkan.instance);
    if (vulkan.physicalDevice == VK_NULL_HANDLE) throw std::runtime_error("no Vulkan device");
    vulkan.queueFamily = ImGui_ImplVulkanH_SelectQueueFamilyIndex(vulkan.physicalDevice);
    if (vulkan.queueFamily == static_cast<std::uint32_t>(-1)) throw std::runtime_error("no Vulkan graphics queue");
    VkBool32 presents = VK_FALSE;
    Check(vkGetPhysicalDeviceSurfaceSupportKHR(vulkan.physicalDevice, vulkan.queueFamily, surface, &presents));
    if (presents != VK_TRUE) throw std::runtime_error("the Vulkan graphics queue cannot present to the window");
    const float priority = 1.0f;
    VkDeviceQueueCreateInfo queue{};
    queue.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    queue.queueFamilyIndex = vulkan.queueFamily;
    queue.queueCount = 1;
    queue.pQueuePriorities = &priority;
    const char* extensions[] = {VK_KHR_SWAPCHAIN_EXTENSION_NAME};
    VkDeviceCreateInfo info{};
    info.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    info.queueCreateInfoCount = 1;
    info.pQueueCreateInfos = &queue;
    info.enabledExtensionCount = 1;
    info.ppEnabledExtensionNames = extensions;
    Check(vkCreateDevice(vulkan.physicalDevice, &info, nullptr, &vulkan.device));
    vkGetDeviceQueue(vulkan.device, vulkan.queueFamily, 0, &vulkan.queue);
    VkDescriptorPoolSize size{VK_DESCRIPTOR_TYPE_COMBINED_IMAGE_SAMPLER, IMGUI_IMPL_VULKAN_MINIMUM_IMAGE_SAMPLER_POOL_SIZE};
    VkDescriptorPoolCreateInfo pool{};
    pool.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO;
    pool.flags = VK_DESCRIPTOR_POOL_CREATE_FREE_DESCRIPTOR_SET_BIT;
    pool.maxSets = size.descriptorCount;
    pool.poolSizeCount = 1;
    pool.pPoolSizes = &size;
    Check(vkCreateDescriptorPool(vulkan.device, &pool, nullptr, &vulkan.descriptorPool));
    vulkan.window.Surface = surface;
    const VkFormat formats[] = {VK_FORMAT_B8G8R8A8_UNORM, VK_FORMAT_R8G8B8A8_UNORM, VK_FORMAT_B8G8R8_UNORM, VK_FORMAT_R8G8B8_UNORM};
    vulkan.window.SurfaceFormat = ImGui_ImplVulkanH_SelectSurfaceFormat(vulkan.physicalDevice, surface, formats, static_cast<int>(std::size(formats)), VK_COLORSPACE_SRGB_NONLINEAR_KHR);
    const VkPresentModeKHR modes[] = {VK_PRESENT_MODE_FIFO_KHR};
    vulkan.window.PresentMode = ImGui_ImplVulkanH_SelectPresentMode(vulkan.physicalDevice, surface, modes, 1);
    ImGui_ImplVulkanH_CreateOrResizeWindow(vulkan.instance, vulkan.physicalDevice, vulkan.device, &vulkan.window, vulkan.queueFamily, nullptr, width, height, MinImageCount);
}

void Render(Vulkan& vulkan, ImDrawData* drawData) {
    ImGui_ImplVulkanH_Window& window = vulkan.window;
    VkSemaphore acquired = window.FrameSemaphores[window.SemaphoreIndex].ImageAcquiredSemaphore;
    VkSemaphore rendered = window.FrameSemaphores[window.SemaphoreIndex].RenderCompleteSemaphore;
    VkResult result = vkAcquireNextImageKHR(vulkan.device, window.Swapchain, UINT64_MAX, acquired, VK_NULL_HANDLE, &window.FrameIndex);
    if (result == VK_ERROR_OUT_OF_DATE_KHR || result == VK_SUBOPTIMAL_KHR) vulkan.rebuild = true;
    if (result == VK_ERROR_OUT_OF_DATE_KHR) return;
    if (result != VK_SUBOPTIMAL_KHR) Check(result);
    ImGui_ImplVulkanH_Frame& frame = window.Frames[window.FrameIndex];
    Check(vkWaitForFences(vulkan.device, 1, &frame.Fence, VK_TRUE, UINT64_MAX));
    Check(vkResetFences(vulkan.device, 1, &frame.Fence));
    Check(vkResetCommandPool(vulkan.device, frame.CommandPool, 0));
    VkCommandBufferBeginInfo begin{};
    begin.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    begin.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    Check(vkBeginCommandBuffer(frame.CommandBuffer, &begin));
    VkRenderPassBeginInfo pass{};
    pass.sType = VK_STRUCTURE_TYPE_RENDER_PASS_BEGIN_INFO;
    pass.renderPass = window.RenderPass;
    pass.framebuffer = frame.Framebuffer;
    pass.renderArea.extent.width = static_cast<std::uint32_t>(window.Width);
    pass.renderArea.extent.height = static_cast<std::uint32_t>(window.Height);
    pass.clearValueCount = 1;
    pass.pClearValues = &window.ClearValue;
    vkCmdBeginRenderPass(frame.CommandBuffer, &pass, VK_SUBPASS_CONTENTS_INLINE);
    ImGui_ImplVulkan_RenderDrawData(drawData, frame.CommandBuffer);
    vkCmdEndRenderPass(frame.CommandBuffer);
    Check(vkEndCommandBuffer(frame.CommandBuffer));
    const VkPipelineStageFlags stage = VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT;
    VkSubmitInfo submit{};
    submit.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    submit.waitSemaphoreCount = 1;
    submit.pWaitSemaphores = &acquired;
    submit.pWaitDstStageMask = &stage;
    submit.commandBufferCount = 1;
    submit.pCommandBuffers = &frame.CommandBuffer;
    submit.signalSemaphoreCount = 1;
    submit.pSignalSemaphores = &rendered;
    Check(vkQueueSubmit(vulkan.queue, 1, &submit, frame.Fence));
    VkPresentInfoKHR present{};
    present.sType = VK_STRUCTURE_TYPE_PRESENT_INFO_KHR;
    present.waitSemaphoreCount = 1;
    present.pWaitSemaphores = &rendered;
    present.swapchainCount = 1;
    present.pSwapchains = &window.Swapchain;
    present.pImageIndices = &window.FrameIndex;
    result = vkQueuePresentKHR(vulkan.queue, &present);
    if (result == VK_ERROR_OUT_OF_DATE_KHR || result == VK_SUBOPTIMAL_KHR) vulkan.rebuild = true;
    if (result == VK_ERROR_OUT_OF_DATE_KHR) return;
    if (result != VK_SUBOPTIMAL_KHR) Check(result);
    window.SemaphoreIndex = (window.SemaphoreIndex + 1) % window.SemaphoreCount;
}

void Reconnect(Session& session, const Options& options) {
    if (session.Connected() && !session.Stale()) return;
    if (options.pid != 0) {
        if (!session.Connected()) session.Connect(options.pid);
        return;
    }
    const auto found = Session::Discover();
    const auto other = std::find_if(found.rbegin(), found.rend(), [&session](std::uint64_t pid) { return pid != session.Pid(); });
    if (other != found.rend()) session.Connect(*other);
}

}

int RunWindow(Session& session, const Options& options) {
    SDL_SetMainReady();
    if (SDL_Init(SDL_INIT_VIDEO) != 0) throw std::runtime_error(std::string("SDL_Init: ") + SDL_GetError());
    const auto window = std::unique_ptr<SDL_Window, decltype(&SDL_DestroyWindow)>(
        SDL_CreateWindow("AnyPS5 monitor", SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED, 1280, 800, SDL_WINDOW_VULKAN | SDL_WINDOW_RESIZABLE | SDL_WINDOW_ALLOW_HIGHDPI), SDL_DestroyWindow);
    if (window == nullptr) throw std::runtime_error(std::string("SDL_CreateWindow: ") + SDL_GetError());
    Vulkan vulkan;
    CreateInstance(vulkan, window.get());
    VkSurfaceKHR surface = VK_NULL_HANDLE;
    if (!SDL_Vulkan_CreateSurface(window.get(), vulkan.instance, &surface)) throw std::runtime_error(std::string("SDL_Vulkan_CreateSurface: ") + SDL_GetError());
    int width = 0;
    int height = 0;
    SDL_GetWindowSize(window.get(), &width, &height);
    CreateDevice(vulkan, surface, width, height);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGui::GetIO().IniFilename = nullptr;
    ImGui::StyleColorsDark();
    ImGui_ImplSDL2_InitForVulkan(window.get());
    ImGui_ImplVulkan_InitInfo init{};
    init.ApiVersion = VK_API_VERSION_1_0;
    init.Instance = vulkan.instance;
    init.PhysicalDevice = vulkan.physicalDevice;
    init.Device = vulkan.device;
    init.QueueFamily = vulkan.queueFamily;
    init.Queue = vulkan.queue;
    init.DescriptorPool = vulkan.descriptorPool;
    init.RenderPass = vulkan.window.RenderPass;
    init.MinImageCount = MinImageCount;
    init.ImageCount = vulkan.window.ImageCount;
    init.MSAASamples = VK_SAMPLE_COUNT_1_BIT;
    init.CheckVkResultFn = Check;
    if (!ImGui_ImplVulkan_Init(&init)) throw std::runtime_error("ImGui_ImplVulkan_Init failed");

    auto polled = Session::Clock::now() - PollInterval;
    auto discovered = Session::Clock::now() - DiscoverInterval;
    for (bool running = true; running;) {
        SDL_Event event;
        while (SDL_PollEvent(&event)) {
            ImGui_ImplSDL2_ProcessEvent(&event);
            if (event.type == SDL_QUIT) running = false;
            if (event.type == SDL_WINDOWEVENT && event.window.event == SDL_WINDOWEVENT_CLOSE && event.window.windowID == SDL_GetWindowID(window.get())) running = false;
        }
        const auto now = Session::Clock::now();
        if (now - discovered >= DiscoverInterval) {
            Reconnect(session, options);
            discovered = now;
        }
        if (now - polled >= PollInterval) {
            session.Poll();
            polled = now;
        }
        if ((SDL_GetWindowFlags(window.get()) & SDL_WINDOW_MINIMIZED) != 0) {
            SDL_Delay(10);
            continue;
        }
        SDL_GetWindowSize(window.get(), &width, &height);
        if (width > 0 && height > 0 && (vulkan.rebuild || vulkan.window.Width != width || vulkan.window.Height != height)) {
            ImGui_ImplVulkan_SetMinImageCount(MinImageCount);
            ImGui_ImplVulkanH_CreateOrResizeWindow(vulkan.instance, vulkan.physicalDevice, vulkan.device, &vulkan.window, vulkan.queueFamily, nullptr, width, height, MinImageCount);
            vulkan.window.FrameIndex = 0;
            vulkan.rebuild = false;
        }
        ImGui_ImplVulkan_NewFrame();
        ImGui_ImplSDL2_NewFrame();
        ImGui::NewFrame();
        DrawMonitor(session);
        ImGui::Render();
        ImDrawData* drawData = ImGui::GetDrawData();
        if (drawData->DisplaySize.x > 0 && drawData->DisplaySize.y > 0) Render(vulkan, drawData);
    }

    Check(vkDeviceWaitIdle(vulkan.device));
    ImGui_ImplVulkan_Shutdown();
    ImGui_ImplSDL2_Shutdown();
    ImGui::DestroyContext();
    ImGui_ImplVulkanH_DestroyWindow(vulkan.instance, vulkan.device, &vulkan.window, nullptr);
    vkDestroyDescriptorPool(vulkan.device, vulkan.descriptorPool, nullptr);
    vkDestroyDevice(vulkan.device, nullptr);
    vkDestroyInstance(vulkan.instance, nullptr);
    SDL_Quit();
    return 0;
}

}
