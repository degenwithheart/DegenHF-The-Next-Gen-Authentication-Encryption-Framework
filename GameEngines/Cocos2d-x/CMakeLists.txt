# CMakeLists.txt for DegenHF Cocos2d-x ECC Authentication
cmake_minimum_required(VERSION 3.10)

# Set project name
project(DegenHF_Cocos2dx_Auth)

# Set C++ standard
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(RapidJSON REQUIRED RapidJSON)

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/Classes
    ${CMAKE_CURRENT_SOURCE_DIR}/cocos2d/extensions
    ${OPENSSL_INCLUDE_DIR}
    ${RapidJSON_INCLUDE_DIRS}
)

# Source files
set(DEGEN_HF_SOURCES
    Classes/DegenHF/ECCAuthHandler.cpp
    cocos2d/extensions/DegenHF/AuthExtension.cpp
)

set(DEGEN_HF_HEADERS
    Classes/DegenHF/ECCAuthHandler.h
    cocos2d/extensions/DegenHF/AuthExtension.h
)

# Optional sample files
set(SAMPLE_SOURCES
    Classes/DegenHF/AuthSampleScene.cpp
)

set(SAMPLE_HEADERS
    Classes/DegenHF/AuthSampleScene.h
)

# Create static library
add_library(degenhf_cocos2dx STATIC
    ${DEGEN_HF_SOURCES}
    ${DEGEN_HF_HEADERS}
)

# Create sample executable (optional)
option(BUILD_SAMPLES "Build sample applications" OFF)
if(BUILD_SAMPLES)
    add_executable(degenhf_sample
        ${SAMPLE_SOURCES}
        ${SAMPLE_HEADERS}
    )

    # Link with Cocos2d-x (you may need to adjust this based on your Cocos2d-x setup)
    # target_link_libraries(degenhf_sample
    #     cocos2d
    #     degenhf_cocos2dx
    # )
endif()

# Link libraries
target_link_libraries(degenhf_cocos2dx
    OpenSSL::SSL
    OpenSSL::Crypto
    ${RapidJSON_LIBRARIES}
)

# Compiler flags
if(MSVC)
    target_compile_options(degenhf_cocos2dx PRIVATE /W4)
else()
    target_compile_options(degenhf_cocos2dx PRIVATE -Wall -Wextra -pedantic)
endif()

# Installation
install(TARGETS degenhf_cocos2dx
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

install(FILES ${DEGEN_HF_HEADERS} DESTINATION include/DegenHF/Cocos2dx)
install(FILES ${SAMPLE_HEADERS} DESTINATION include/DegenHF/Cocos2dx/samples)

# Generate pkg-config file
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/degenhf-cocos2dx.pc.in
    ${CMAKE_CURRENT_BINARY_DIR}/degenhf-cocos2dx.pc
    @ONLY
)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/degenhf-cocos2dx.pc
    DESTINATION lib/pkgconfig
)