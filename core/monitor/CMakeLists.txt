set(ANYPS5_IMGUI_DIR ${CMAKE_SOURCE_DIR}/3rdparty/imgui)
if(NOT EXISTS ${ANYPS5_IMGUI_DIR}/imgui.h)
    message(FATAL_ERROR "APS5_ENABLE_PROFILER builds anyps5-monitor, which needs 3rdparty/imgui: run git submodule update --init 3rdparty/imgui")
endif()

add_library(anyps5_imgui STATIC
        ${ANYPS5_IMGUI_DIR}/imgui.cpp
        ${ANYPS5_IMGUI_DIR}/imgui_draw.cpp
        ${ANYPS5_IMGUI_DIR}/imgui_tables.cpp
        ${ANYPS5_IMGUI_DIR}/imgui_widgets.cpp
        ${ANYPS5_IMGUI_DIR}/backends/imgui_impl_sdl2.cpp
        ${ANYPS5_IMGUI_DIR}/backends/imgui_impl_vulkan.cpp
)
target_include_directories(anyps5_imgui PUBLIC
        ${ANYPS5_IMGUI_DIR}
        ${ANYPS5_IMGUI_DIR}/backends
        ${ANYPS5_VULKAN_HEADERS_INCLUDE_DIR}
)
target_compile_definitions(anyps5_imgui PUBLIC IMGUI_IMPL_VULKAN_NO_PROTOTYPES VK_NO_PROTOTYPES)
target_link_libraries(anyps5_imgui PUBLIC SDL2-static)

add_library(anyps5_monitor_session STATIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src/Session.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/Json.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/Mcp.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/Memory.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/Snapshots.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/Symbols.cpp
)
target_include_directories(anyps5_monitor_session PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/core/libs)

add_executable(anyps5_monitor
        ${CMAKE_CURRENT_SOURCE_DIR}/src/Main.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/Dump.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/Window.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/Views.cpp
)
set_target_properties(anyps5_monitor PROPERTIES OUTPUT_NAME anyps5-monitor)
target_link_libraries(anyps5_monitor PRIVATE anyps5_monitor_session anyps5_imgui)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(anyps5_monitor_session PUBLIC rt)
endif()

if(BUILD_TESTING AND (WIN32 OR CMAKE_SYSTEM_NAME STREQUAL "Linux"))
    add_subdirectory(tests)
endif()
