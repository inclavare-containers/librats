# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required(VERSION 3.0)
project(sample)

set (CMAKE_C_LINK_FLAGS "")
set (CMAKE_CXX_LINK_FLAGS "")
if (APPLE)
    set (HAVE_FLAG_SEARCH_PATHS_FIRST 0)
endif ()

set (CMAKE_SYSTEM_PROCESSOR wasm32)
set (CMAKE_SYSROOT                  ${wamr_SOURCE_DIR}/wamr-sdk/app/libc-builtin-sysroot)

if (NOT DEFINED WASI_SDK_DIR)
    set (WASI_SDK_DIR               "/opt/wasi-sdk")
endif ()

set (CMAKE_C_FLAGS                  "-nostdlib")
set (CMAKE_C_COMPILER_TARGET        "wasm32")
set (CMAKE_C_COMPILER               "${WASI_SDK_DIR}/bin/clang")

set (CMAKE_EXE_LINKER_FLAGS
    "-Wl,--max-memory=131072 -z stack-size=8192   \
     -Wl,--no-entry,--strip-all                   \
     -Wl,--export=__main_argc_argv                \
     -Wl,--export=__heap_base,--export=__data_end \
     -Wl,--allow-undefined"
)

add_executable(test.wasm main.c)
set_target_properties(test.wasm PROPERTIES INCLUDE_DIRECTORIES ${CMAKE_SOURCE_DIR})
target_link_libraries(test.wasm)
