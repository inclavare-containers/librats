# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required(VERSION 3.1.4)
project(rats_wamr)

string(TOLOWER ${CMAKE_HOST_SYSTEM_NAME} WAMR_BUILD_PLATFORM)
if (APPLE)
  add_definitions(-DBH_PLATFORM_DARWIN)
endif ()

set(BUILD_SAMPLE ON CACHE BOOL
    "Enable to build sample.")

# Reset default linker flags
set(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")
set(CMAKE_SHARED_LIBRARY_LINK_CXX_FLAGS "")

# Get librats install dir
set(LIBRATS_ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../..)
list(APPEND CMAKE_MODULE_PATH ${LIBRATS_ROOT_DIR}/cmake)
include(CustomInstallDirs)

# Check if librats already installed
if(NOT EXISTS ${RATS_INSTALL_LIB_PATH}/librats_lib.so OR NOT EXISTS ${RATS_INSTALL_INCLUDE_PATH})
    message(FATAL_ERROR "Please install librats first")
endif()

include(FetchContent)
FetchContent_Declare(
    wamr
    GIT_REPOSITORY https://github.com/bytecodealliance/wasm-micro-runtime
    GIT_TAG main
)
FetchContent_GetProperties(wamr)
if(NOT wamr_POPULATED)
    message("-- Fetching wamr ..")
    FetchContent_Populate(wamr)
    include_directories(
        ${wamr_SOURCE_DIR}/core/iwasm/include
        ${wamr_SOURCE_DIR}/core/shared/utils
        )
    set(WAMR_BUILD_INTERP 1)
    set(WAMR_BUILD_AOT 1)
    set(WAMR_BUILD_JIT 0)
    set(WAMR_BUILD_LIBC_BUILTIN 1)
    set(WAMR_BUILD_FAST_INTERP 1)
    list(APPEND CMAKE_MODULE_PATH ${wamr_SOURCE_DIR}/build-scripts)
    include(runtime_lib)
    add_subdirectory(${wamr_SOURCE_DIR} ${wamr_BINARY_DIR} EXCLUDE_FROM_ALL)
endif()

# compiling and linking flags
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pie -fPIE")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wformat -Wformat-security")

# Build librats in wamr
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -rdynamic")
link_directories(${RATS_INSTALL_LIB_PATH})
add_library(${PROJECT_NAME} SHARED rats_api.c)
target_link_libraries(${PROJECT_NAME} rats_lib)

# Build sample
if (BUILD_SAMPLE)
    # Build vmlib
    add_library(vmlib ${WAMR_RUNTIME_LIB_SOURCE})
    include(${SHARED_DIR}/utils/uncommon/shared_uncommon.cmake)

    set(RUNTIME_SOURCE_ALL
        ${WAMR_ROOT_DIR}/product-mini/platforms/posix/main.c
        ${UNCOMMON_SHARED_SOURCE}
    )

    # Build iwasm
    add_executable(iwasm ${RUNTIME_SOURCE_ALL})
    target_link_libraries(iwasm vmlib -lpthread -lm -ldl)

    # Build sample
    add_subdirectory(sample)
endif()