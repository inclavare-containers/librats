cmake_minimum_required(VERSION 3.5.1)
if(RATS_BUILD_MODE STREQUAL "wasm")
    set(CMAKE_TOOLCHAIN_FILE "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Emscripten.cmake")
endif()
project(librats)
set(RATS_LIB rats_lib)

# Software version
file(STRINGS "VERSION" RATS_VERSION)
set(VERSION ${RATS_VERSION})
string(REPLACE "." ";" VERSION_LIST ${RATS_VERSION})
list(GET VERSION_LIST 0 VERSION_MAJOR)
list(GET VERSION_LIST 1 VERSION_MINOR)
list(GET VERSION_LIST 2 VERSION_PATCH)

# Build options
option(SGX_HW "Run SGX on hardware, OFF for simulation" ON)

# Define build mode
set(RATS_BUILD_MODE "host"
    CACHE STRING "Select build mode for librats(host|occlum|sgx｜wasm)")

# Print build mode
message(STATUS "Build Mode: ${RATS_BUILD_MODE}")

# CMake modules path
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

# Bulid mode macro
#  normal: NORMAL
#  occlum: OCCLUM
#  sgx: SGX
if(RATS_BUILD_MODE STREQUAL "host")
    set(HOST 1)
    add_definitions(-DHOST)

    include(FindSgxDcapQuoteVerify)
    if(NOT SGXDCAPQV_FOUND)
        message(WARNING "libsgx_dcap_quoteverify.so not found in host mode")
    endif()
elseif(RATS_BUILD_MODE STREQUAL "occlum")
    set(OCCLUM 1)
    add_definitions(-DOCCLUM)
elseif(RATS_BUILD_MODE STREQUAL "sgx")
    include(FindSGX)
    if(NOT SGX_FOUND)
        message(FATAL_ERROR "Not found intel sgx sdk !")
    else()
        message(STATUS "Found intel sgx sdk.")
    endif()

    set(SGX 1)
    add_definitions(-DSGX)
elseif(RATS_BUILD_MODE STREQUAL "tdx")
    set(TDX 1)
    add_definitions(-DTDX)
elseif(RATS_BUILD_MODE STREQUAL "wasm")
    set(WASM 1)
    add_definitions(-DWASM)
else()
    message(FATAL_ERROR "Invalid build mode!")
endif()

# Default build type
set(RATS_BUILD_TYPE "debug"
    CACHE STRING "Select build type for rats(debug|prerelease|release)"
    )

# Print build type
message(STATUS "Build Type: ${RATS_BUILD_TYPE}")

# Build type macro
#  debug: DEBUG
#  prerelease: PRERELEASE
#  release: RELEASE
if(RATS_BUILD_TYPE STREQUAL "debug")
    set(DEBUG 1)
    set(SGX_DEBUG 1)
elseif(RATS_BUILD_TYPE STREQUAL "prerelease")
    set(PRERELEASE 1)
    set(SGX_PRERELEASE 1)
elseif(RATS_BUILD_TYPE STREQUAL "release")
    set(RELEASE 1)
    set(SGX_RELEASE 1)
else()
    message(FATAL_ERROR "Invalid build type!")
endif()

# Set include directory
set(INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/include)
if(SGX)
    list(APPEND INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/include/edl
                             ${CMAKE_BINARY_DIR}/tee/sgx/trust
                             )
elseif(WASM)
    list(APPEND INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/wasm/openssl/install/include)
endif()

# Include custom modules
include(CustomInstallDirs)
include(CompilerOptions)
if(SGX)
    include(SGXCommon)
endif()

include_directories(${INCLUDE_DIRS})

# Add third party and instance directory
if(NOT WASM)
    add_subdirectory(attesters)
endif()
add_subdirectory(verifiers)
if(SGX)
    add_subdirectory(tee)
endif()

# Set source file
set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/core/rats_common.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/cpu.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/rats_init.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/claim.c
    ${CMAKE_CURRENT_SOURCE_DIR}/api/librats_collect_evidence.c
    ${CMAKE_CURRENT_SOURCE_DIR}/api/librats_verify_evidence.c
    ${CMAKE_CURRENT_SOURCE_DIR}/attesters/api/rats_attester_register.c
    ${CMAKE_CURRENT_SOURCE_DIR}/attesters/internal/rats_attester.c
    ${CMAKE_CURRENT_SOURCE_DIR}/attesters/internal/rats_attester_load_all.c
    ${CMAKE_CURRENT_SOURCE_DIR}/attesters/internal/rats_attester_load_single.c
    ${CMAKE_CURRENT_SOURCE_DIR}/attesters/internal/rats_attester_select.c
    ${CMAKE_CURRENT_SOURCE_DIR}/verifiers/api/rats_verifier_register.c
    ${CMAKE_CURRENT_SOURCE_DIR}/verifiers/internal/rats_verifier.c
    ${CMAKE_CURRENT_SOURCE_DIR}/verifiers/internal/rats_verifier_load_all.c
    ${CMAKE_CURRENT_SOURCE_DIR}/verifiers/internal/rats_verifier_load_single.c
    ${CMAKE_CURRENT_SOURCE_DIR}/verifiers/internal/rats_verifier_select.c
    )
if(SGX)
    list(APPEND SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/tee/sgx/trust/sgx_ecdsa_ecalls.c
                        ${CMAKE_CURRENT_SOURCE_DIR}/tee/sgx/trust/sgx_dummy.c
                        ${CMAKE_CURRENT_SOURCE_DIR}/tee/sgx/trust/rats_syscalls.c
                        )
elseif(WASM)
    list(APPEND SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/wasm/wasm.cpp)
endif()

# Static library dependencies
if(SGX)
    set(DEPEND_TRUSTED_LIBS rats_edl_t
                            attester_nullattester
                            attester_sgx_ecdsa
                            attester_sgx_la
                            verifier_nullverifier
                            verifier_sgx_ecdsa
                            verifier_sgx_ecdsa_qve
                            verifier_sgx_la
                            )
elseif(WASM)
    set(DEPEND_LIBS verifier_nullverifier
                    verifier_sgx_ecdsa
                    verifier_sev
                    verifier_sev_snp
                    verifier_csv
                    )
    set(WASM_LINER_LIBRARIES "-L${WASM_BUILD_DIR} \
                              -L${CMAKE_CURRENT_SOURCE_DIR}/wasm/dcap/lib \
                              -L${CMAKE_CURRENT_SOURCE_DIR}/wasm/openssl/install/lib \
                              -lcrypto -lsgx_dcap_quoteverify \
                              -lsgx_dcap_qvl_attestation \
                              -lsgx_dcap_qvl_parser \
                              -ldcap_quoteprov \
                              -lsgx_default_qcnl_wrapper \
                              -lverifier_nullverifier \
                              -lverifier_sgx_ecdsa \
                              -lverifier_sev \
                              -lverifier_sev_snp \
                              -lverifier_csv"
                              )
    set(PRELOAD_FILE "--preload-file ${WASM_BUILD_DIR}/libverifier_nullverifier.so@${RATS_INSTALL_LIBV_PATH}/libverifier_nullverifier.so \
                      --preload-file ${WASM_BUILD_DIR}/libverifier_csv.so@${RATS_INSTALL_LIBV_PATH}/libverifier_csv.so \
                      --preload-file ${WASM_BUILD_DIR}/libverifier_sgx_ecdsa.so@${RATS_INSTALL_LIBV_PATH}/libverifier_sgx_ecdsa.so \
                      --preload-file ${WASM_BUILD_DIR}/libverifier_sev.so@${RATS_INSTALL_LIBV_PATH}/libverifier_sev.so \
                      --preload-file ${WASM_BUILD_DIR}/libverifier_sev_snp.so@${RATS_INSTALL_LIBV_PATH}/libverifier_sev_snp.so \
                      --preload-file ${CMAKE_BINARY_DIR}/${ASK_ARK_NAPLES_FILE}@${SEV_DEFAULT_DIR}/${ASK_ARK_NAPLES_FILE} \
                      --preload-file ${CMAKE_BINARY_DIR}/${ASK_ARK_ROME_FILE}@${SEV_DEFAULT_DIR}/${ASK_ARK_ROME_FILE} \
                      --preload-file ${CMAKE_BINARY_DIR}/${ASK_ARK_MILAN_FILE}@${SEV_DEFAULT_DIR}/${ASK_ARK_MILAN_FILE}"
                      )

    # Put dumped evidence.bin in ${CMAKE_CURRENT_SOURCE_DIR}/wasm if need to
    # test librats_wasm for evidence in file.
    if(DEBUG AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/wasm/evidence.bin")
        set(PRELOAD_FILE "${PRELOAD_FILE} --preload-file ${CMAKE_CURRENT_SOURCE_DIR}/wasm/evidence.bin@evidence.bin")
    endif()
endif()

# Generate library
if(SGX)
    add_trusted_library(${RATS_LIB} SRCS ${SOURCES} TRUSTED_LIBS ${DEPEND_TRUSTED_LIBS})
    add_dependencies(${RATS_LIB} ${DEPEND_TRUSTED_LIBS})
elseif(WASM)
    add_executable(${RATS_LIB} ${SOURCES})
    set_target_properties(${RATS_LIB} PROPERTIES
                          COMPILE_FLAGS "${WASM_MAIN_BASE_FLAGS}"
                          LINKER_LANGUAGE "C"
                          LINK_FLAGS "${WASM_MAIN_ASYNC_FLAGS} ${WASM_LINER_LIBRARIES} ${PRELOAD_FILE}"
                          SUFFIX ".js"
                          )
    add_dependencies(${RATS_LIB} ${DEPEND_LIBS})
    add_custom_command(TARGET ${RATS_LIB}
                       POST_BUILD
                       COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_BINARY_DIR}/${RATS_LIB}.* ${WASM_BUILD_DIR}
                       )
    if(DEBUG)
        add_custom_command(TARGET ${RATS_LIB}
                           POST_BUILD
                           COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/wasm/sample.html ${WASM_BUILD_DIR}
                           )
    else()
        add_custom_command(TARGET ${RATS_LIB}
                           POST_BUILD
                           COMMAND ${CMAKE_COMMAND} -E rm ${WASM_BUILD_DIR}/${RATS_LIB}.wasm.map
                           )
    endif()
else()
    add_library(${RATS_LIB} SHARED ${SOURCES})
    target_link_libraries(${RATS_LIB} ${RATS_LDFLAGS})
    set_target_properties(${RATS_LIB} PROPERTIES VERSION ${VERSION} SOVERSION ${VERSION_MAJOR})
endif()

# Install header
set(RATS_INCLUDE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/include/librats/api.h
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/librats/attester.h
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/librats/verifier.h
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/librats/core.h
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/librats/claim.h
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/librats/err.h
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/librats/log.h
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/librats/conf.h
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/librats/sgx.h
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/librats/evidence.h
                       )
if(SGX)
    list(APPEND RATS_INCLUDE_FILES ${CMAKE_CURRENT_BINARY_DIR}/tee/sgx/trust/rats_t.h
                                   ${CMAKE_CURRENT_BINARY_DIR}/tee/sgx/untrust/rats_u.h
                                   )
endif()

# Install lib
if(NOT WASM)
    install(TARGETS ${RATS_LIB} DESTINATION ${RATS_INSTALL_LIB_PATH})
    install(DIRECTORY DESTINATION ${RATS_INSTALL_INCLUDE_PATH}/librats)
    install(FILES ${RATS_INCLUDE_FILES} DESTINATION ${RATS_INSTALL_INCLUDE_PATH}/librats)
endif()
