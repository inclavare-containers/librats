cmake_minimum_required(VERSION 3.12.0)
if(RATS_BUILD_MODE STREQUAL "wasm")
    set(CMAKE_TOOLCHAIN_FILE "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Emscripten.cmake")
endif()
project(librats)
# For wasm mode, we need to set property TARGET_SUPPORTS_SHARED_LIBS to TRUE again here, since it has been set to FALSE by project()
if(RATS_BUILD_MODE STREQUAL "wasm")
    set_property(GLOBAL PROPERTY TARGET_SUPPORTS_SHARED_LIBS TRUE)
endif()

set(RATS_LIB rats_lib)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(RATS_SRC_PATH ${CMAKE_CURRENT_LIST_DIR})

# Software version
file(STRINGS "VERSION" RATS_VERSION)
set(VERSION ${RATS_VERSION})
string(REPLACE "." ";" VERSION_LIST ${RATS_VERSION})
list(GET VERSION_LIST 0 VERSION_MAJOR)
list(GET VERSION_LIST 1 VERSION_MINOR)
list(GET VERSION_LIST 2 VERSION_PATCH)

# Build options
if(NOT RATS_BUILD_MODE STREQUAL "wasm")
    option(BUILD_SAMPLES "Compile sample code along with libraries" ON)
endif()

option(SGX_HW "Run SGX on hardware, OFF for simulation" ON)

# Define build mode
set(RATS_BUILD_MODE "host"
    CACHE STRING "Select build mode for librats(host|occlum|sgx|tdx|wasm)")
set(SGX_ATTESTER "ecdsa"
    CACHE STRING "Select sgx attester(ecdsa|la|null)")


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
elseif(RATS_BUILD_MODE STREQUAL "occlum")
    set(OCCLUM 1)
    add_definitions(-DOCCLUM)
    if (SGX_ATTESTER STREQUAL "ecdsa")
        add_definitions(-DSGX_ECDSA)
    elseif(SGX_ATTESTER STREQUAL "la")
        add_definitions(-DSGX_LA)
    endif()
elseif(RATS_BUILD_MODE STREQUAL "sgx")
    include(FindSGX)
    if(NOT SGX_FOUND)
        reportSGXSDKNotFound()
    endif()

    set(SGX 1)
    add_definitions(-DSGX)
    if (SGX_ATTESTER STREQUAL "ecdsa")
        add_definitions(-DSGX_ECDSA)
    elseif(SGX_ATTESTER STREQUAL "la")
        add_definitions(-DSGX_LA)
    endif()
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

set(ENABLE_JSON ON CACHE BOOL
    "Enable to transform evidence to/from json.")

if(ENABLE_JSON)
    add_definitions(-DENABLE_JSON)
endif()

# Include custom modules
include(CustomInstallDirs)
include(CompilerOptions)
if(SGX)
    include(SGXCommon)
    include(SGXSSL)
endif()
include(LibCBOR)

# Set include directory
set(INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/include)
if(SGX)
    list(APPEND INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/include/edl
                             ${CMAKE_CURRENT_BINARY_DIR}/tee/sgx/trust
                             )
elseif(WASM)
    list(APPEND INCLUDE_DIRS ${WASM_SRCS_DIR}/openssl/install/include)
endif()


# Add third party and instance directory
if(NOT WASM)
    add_subdirectory(attesters)
endif()
add_subdirectory(verifiers)
if(SGX)
    add_subdirectory(tee)
endif()

# Add third party library required by crypto_wrappers
if(SGX)
    list(APPEND INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/external/sgx-ssl/intel-sgx-ssl/src/intel-sgx-ssl/Linux/package/include)
endif()

add_subdirectory(crypto_wrappers)

list(APPEND INCLUDE_DIRS ${LIBCBOR_INC_PATH}) # libcbor is need by core layer only 

include_directories(${INCLUDE_DIRS})

# Set source file
set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/core/rats_common.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/cpu.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/rats_init.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/claim.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/endorsement.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/dice.c
    ${CMAKE_CURRENT_SOURCE_DIR}/api/librats_collect_evidence.c
    ${CMAKE_CURRENT_SOURCE_DIR}/api/librats_verify_evidence.c
    ${CMAKE_CURRENT_SOURCE_DIR}/api/librats_get_attestation_certificate.c
    ${CMAKE_CURRENT_SOURCE_DIR}/api/librats_verify_attestation_certificate.c
    ${CMAKE_CURRENT_SOURCE_DIR}/attesters/api/rats_attester_register.c
    ${CMAKE_CURRENT_SOURCE_DIR}/attesters/internal/rats_attester.c
    ${CMAKE_CURRENT_SOURCE_DIR}/attesters/internal/rats_attester_post_init.c
    ${CMAKE_CURRENT_SOURCE_DIR}/attesters/internal/rats_attester_select.c
    ${CMAKE_CURRENT_SOURCE_DIR}/verifiers/api/rats_verifier_register.c
    ${CMAKE_CURRENT_SOURCE_DIR}/verifiers/internal/rats_verifier.c
    ${CMAKE_CURRENT_SOURCE_DIR}/verifiers/internal/rats_verifier_post_init.c
    ${CMAKE_CURRENT_SOURCE_DIR}/verifiers/internal/rats_verifier_select.c
    ${CMAKE_CURRENT_SOURCE_DIR}/crypto_wrappers/api/crypto_wrapper_register.c
    ${CMAKE_CURRENT_SOURCE_DIR}/crypto_wrappers/internal/crypto_wrapper.c
    ${CMAKE_CURRENT_SOURCE_DIR}/crypto_wrappers/internal/crypto_wrapper_post_init.c
    ${CMAKE_CURRENT_SOURCE_DIR}/crypto_wrappers/internal/crypto_wrapper_select.c
    ${CMAKE_CURRENT_SOURCE_DIR}/crypto_wrappers/api/crypto_wrapper_verify_certificate_extension.c
    )
if(SGX)
    list(APPEND SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/tee/sgx/trust/sgx_ecdsa_ecalls.c
                        ${CMAKE_CURRENT_SOURCE_DIR}/tee/sgx/trust/sgx_dummy.c
                        ${CMAKE_CURRENT_SOURCE_DIR}/tee/sgx/trust/rats_syscalls.c
                        )
endif()

if(WASM)
    list(APPEND SOURCES ${WASM_SRCS_DIR}/wasm.cpp)
endif()

if(NOT SGX)
    # Code for dynamically loading with dlopen()
    list(APPEND SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/attesters/internal/rats_attester_load_all.c
                        ${CMAKE_CURRENT_SOURCE_DIR}/verifiers/internal/rats_verifier_load_all.c
                        ${CMAKE_CURRENT_SOURCE_DIR}/crypto_wrappers/internal/crypto_wrapper_load_all.c
                        )
endif()

if(ENABLE_JSON)
    list(APPEND SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/core/base64.c
                        ${CMAKE_CURRENT_SOURCE_DIR}/core/cJSON.c)
endif()

# Static library dependencies
if(SGX)
    set(DEPEND_TRUSTED_LIBS rats_edl_t
                            intel-sgx-ssl
                            crypto_wrapper_nullcrypto
                            crypto_wrapper_openssl
                            attester_nullattester
                            attester_sgx_ecdsa
                            attester_sgx_la
                            verifier_nullverifier
                            verifier_sgx_ecdsa_qve
                            verifier_sgx_la
                            libcbor
                            )
elseif(WASM)
    set(DEPEND_LIBS verifier_nullverifier
                    verifier_sgx_ecdsa
                    verifier_sev
                    verifier_sev_snp
                    verifier_csv
                    libcbor
                    )
    set(WASM_LINER_LIBRARIES "-L${WASM_BUILD_DIR} \
                              -L${WASM_SRCS_DIR}/dcap/lib \
                              -L${WASM_SRCS_DIR}/openssl/install/lib \
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
                      --preload-file ${CMAKE_CURRENT_BINARY_DIR}/${ASK_ARK_NAPLES_FILE}@${SEV_DEFAULT_DIR}/${ASK_ARK_NAPLES_FILE} \
                      --preload-file ${CMAKE_CURRENT_BINARY_DIR}/${ASK_ARK_ROME_FILE}@${SEV_DEFAULT_DIR}/${ASK_ARK_ROME_FILE} \
                      --preload-file ${CMAKE_CURRENT_BINARY_DIR}/${ASK_ARK_MILAN_FILE}@${SEV_DEFAULT_DIR}/${ASK_ARK_MILAN_FILE}"
                      )

    # Put dumped evidence.bin in ${CMAKE_CURRENT_SOURCE_DIR}/wasm/emscripten if need to
    # test librats_wasm for evidence in file.
    if(DEBUG AND EXISTS "${WASM_SRCS_DIR}/evidence.bin")
        set(PRELOAD_FILE "${PRELOAD_FILE} --preload-file ${WASM_SRCS_DIR}/evidence.bin@evidence.bin")
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
                       COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_BINARY_DIR}/${RATS_LIB}.* ${WASM_BUILD_DIR}
                       )
    if(DEBUG)
        add_custom_command(TARGET ${RATS_LIB}
                           POST_BUILD
                           COMMAND ${CMAKE_COMMAND} -E copy ${WASM_SRCS_DIR}/sample.html ${WASM_BUILD_DIR}
                           )
    else()
        add_custom_command(TARGET ${RATS_LIB}
                           POST_BUILD
                           COMMAND ${CMAKE_COMMAND} -E rm ${WASM_BUILD_DIR}/${RATS_LIB}.wasm.map
                           )
    endif()
else()
    add_library(${RATS_LIB} SHARED ${SOURCES})
    add_dependencies(${RATS_LIB} libcbor)
    target_link_libraries(${RATS_LIB} ${RATS_LDFLAGS} ${LIBCBOR_LIB_FILES})
    set_target_properties(${RATS_LIB} PROPERTIES VERSION ${VERSION} SOVERSION ${VERSION_MAJOR})
endif()

# Install header
set(RATS_INCLUDE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/include/librats/api.h
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/librats/crypto_wrapper.h
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/librats/attester.h
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/librats/verifier.h
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/librats/core.h
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/librats/claim.h
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/librats/err.h
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/librats/log.h
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/librats/conf.h
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/librats/evidence.h
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/librats/hash.h
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/librats/endorsement.h
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/librats/cert.h
                       )

if(SGX)
    list(APPEND RATS_INCLUDE_FILES ${CMAKE_CURRENT_BINARY_DIR}/tee/sgx/trust/rats_t.h
                                   ${CMAKE_CURRENT_BINARY_DIR}/tee/sgx/untrust/rats_u.h
                                   ${CMAKE_CURRENT_SOURCE_DIR}/include/librats/rats_syscalls.h
                                   ${CMAKE_CURRENT_SOURCE_DIR}/include/edl/rats.edl
                                   ${CMAKE_CURRENT_SOURCE_DIR}/include/edl/rats_syscalls.edl
                                   ${CMAKE_CURRENT_SOURCE_DIR}/include/edl/sgx_dummy.edl
                                   ${CMAKE_CURRENT_SOURCE_DIR}/include/edl/sgx_ecdsa.edl
                                   ${CMAKE_CURRENT_SOURCE_DIR}/include/edl/sgx_la.edl
                                   )

    list(APPEND RATS_EDL_FILES     ${CMAKE_CURRENT_SOURCE_DIR}/include/edl/rats.edl
                                   ${CMAKE_CURRENT_SOURCE_DIR}/include/edl/rats_syscalls.edl
                                   ${CMAKE_CURRENT_SOURCE_DIR}/include/edl/sgx_dummy.edl
                                   ${CMAKE_CURRENT_SOURCE_DIR}/include/edl/sgx_ecdsa.edl
                                   ${CMAKE_CURRENT_SOURCE_DIR}/include/edl/sgx_la.edl
                                   )
endif()


if(NOT WASM)
    message(STATUS "Build Samples: ${BUILD_SAMPLES}")
    if(BUILD_SAMPLES)
        add_subdirectory(samples)
    endif()
endif()

# Install lib
if(NOT WASM)
    install(TARGETS ${RATS_LIB} DESTINATION ${RATS_INSTALL_LIB_PATH})
    install(DIRECTORY DESTINATION ${RATS_INSTALL_INCLUDE_PATH})
    install(FILES ${RATS_INCLUDE_FILES} DESTINATION ${RATS_INSTALL_INCLUDE_PATH})
    if(SGX)
        install(FILES ${RATS_EDL_FILES} DESTINATION ${RATS_INSTALL_INCLUDE_PATH}/edl)
    endif()
endif()
