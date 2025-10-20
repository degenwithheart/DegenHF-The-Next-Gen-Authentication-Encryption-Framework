cmake_minimum_required(VERSION 3.16)
project(DegenHF_SDL2_Auth VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(PkgConfig REQUIRED)
pkg_check_modules(SDL2 REQUIRED sdl2)
pkg_check_modules(SDL2_TTF REQUIRED SDL2_ttf)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Find nlohmann_json
find_package(nlohmann_json REQUIRED)

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${SDL2_INCLUDE_DIRS}
    ${SDL2_TTF_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
)

# Source files
set(SOURCES
    src/DegenHFECCAuthHandler.cpp
    src/DegenHFSDL2AuthIntegration.cpp
)

# Create library
add_library(degenhf_sdl2_auth ${SOURCES})

# Link libraries
target_link_libraries(degenhf_sdl2_auth
    ${SDL2_LIBRARIES}
    ${SDL2_TTF_LIBRARIES}
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
)

# Include current directory for headers
target_include_directories(degenhf_sdl2_auth PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

# Create example executable
add_executable(sdl2_auth_example examples/main.cpp)
target_link_libraries(sdl2_auth_example degenhf_sdl2_auth)

# Create test executable
add_executable(sdl2_auth_tests tests/test_auth.cpp)
target_link_libraries(sdl2_auth_tests degenhf_sdl2_auth)

# Installation
install(TARGETS degenhf_sdl2_auth
    EXPORT DegenHFSDL2AuthTargets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
    INCLUDES DESTINATION include
)

install(DIRECTORY include/
    DESTINATION include
    FILES_MATCHING PATTERN "*.hpp"
)

install(EXPORT DegenHFSDL2AuthTargets
    FILE DegenHFSDL2AuthTargets.cmake
    NAMESPACE DegenHF::
    DESTINATION lib/cmake/DegenHFSDL2Auth
)

# Create and install config file
include(CMakePackageConfigHelpers)
configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/DegenHFSDL2AuthConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/DegenHFSDL2AuthConfig.cmake
    INSTALL_DESTINATION lib/cmake/DegenHFSDL2Auth
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/DegenHFSDL2AuthConfig.cmake
    DESTINATION lib/cmake/DegenHFSDL2Auth
)

# Compiler warnings
if(MSVC)
    target_compile_options(degenhf_sdl2_auth PRIVATE /W4)
else()
    target_compile_options(degenhf_sdl2_auth PRIVATE -Wall -Wextra -Wpedantic)
endif()

# Build type specific options
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_definitions(degenhf_sdl2_auth PRIVATE DEBUG)
elseif(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_compile_options(degenhf_sdl2_auth PRIVATE -O3)
endif()

# Print configuration summary
message(STATUS "DegenHF SDL2 Auth Configuration:")
message(STATUS "  SDL2 Include: ${SDL2_INCLUDE_DIRS}")
message(STATUS "  SDL2 Libraries: ${SDL2_LIBRARIES}")
message(STATUS "  SDL2_TTF Include: ${SDL2_TTF_INCLUDE_DIRS}")
message(STATUS "  SDL2_TTF Libraries: ${SDL2_TTF_LIBRARIES}")
message(STATUS "  OpenSSL Include: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "  OpenSSL Libraries: ${OPENSSL_LIBRARIES}")
message(STATUS "  Build Type: ${CMAKE_BUILD_TYPE}")