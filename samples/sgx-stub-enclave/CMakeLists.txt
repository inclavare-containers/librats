# Project name
project(sgx-stub-enclave)

if(BUILD_SAMPLES)
    set(INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/../../include
                     ${CMAKE_CURRENT_SOURCE_DIR}/../../include/librats
                     ${CMAKE_CURRENT_SOURCE_DIR}/../../include/edl
                     ${CMAKE_CURRENT_SOURCE_DIR}/../../external/sgx-ssl/intel-sgx-ssl/src/intel-sgx-ssl/Linux/package/include
                     )

    set(LIBRARY_DIRS ${INTEL_SGXSSL_LIB_PATH}
                     ${LIBCBOR_LIB_PATH}
                     ${CMAKE_BINARY_DIR}
                     ${CMAKE_BINARY_DIR}/verifiers/nullverifier
                     ${CMAKE_BINARY_DIR}/verifiers/sgx-ecdsa
                     ${CMAKE_BINARY_DIR}/verifiers/sgx-ecdsa-qve
                     ${CMAKE_BINARY_DIR}/verifiers/sgx-la
                     ${CMAKE_BINARY_DIR}/attesters/nullattester
                     ${CMAKE_BINARY_DIR}/attesters/sgx-ecdsa
                     ${CMAKE_BINARY_DIR}/attesters/sgx-la
                     ${CMAKE_BINARY_DIR}/crypto_wrappers/nullcrypto
                     ${CMAKE_BINARY_DIR}/crypto_wrappers/openssl
                     )

    set(EDL_SEARCH_PATHS ${CMAKE_CURRENT_SOURCE_DIR}
                         ${CMAKE_CURRENT_SOURCE_DIR}/../../include/edl
                         )
else()
    list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
    include(CustomInstallDirs)
    include(FindLibRats)
    if(NOT RATS_FOUND)
        message(FATAL_ERROR "Failed to find librats!")
    endif()
    include(FindSGX)
    if(NOT SGX_FOUND)
        reportSGXSDKNotFound()
    endif()
    include(CompilerOptions)
    include(SGXCommon)

    set(INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/../../include
                     ${CMAKE_CURRENT_SOURCE_DIR}/../../include/librats
                     ${CMAKE_CURRENT_SOURCE_DIR}/../../include/edl)

    set(LIBRARY_DIRS ${RATS_INSTALL_LIB_PATH})

    set(EDL_SEARCH_PATHS ${CMAKE_CURRENT_SOURCE_DIR}/../../include/edl)
endif()

include_directories(${INCLUDE_DIRS})
link_directories(${LIBRARY_DIRS})

set(E_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/sgx_stub_ecall.c)
set(EDLS ${CMAKE_CURRENT_SOURCE_DIR}/sgx_stub.edl)
set(LDS ${CMAKE_CURRENT_SOURCE_DIR}/sgx_stub_enclave.lds)
set(DEPEND_TRUSTED_LIBS attester_nullattester
                        attester_sgx_ecdsa
                        attester_sgx_la
                        verifier_nullverifier
                        verifier_sgx_la
                        verifier_sgx_ecdsa_qve
                        crypto_wrapper_nullcrypto
                        crypto_wrapper_openssl
                        rats_lib
                        cbor
                        )

add_enclave_library(sgx_stub_enclave SRCS ${E_SRCS} EDL ${EDLS} TRUSTED_LIBS ${DEPEND_TRUSTED_LIBS} EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS} LDSCRIPT ${LDS})
enclave_sign(sgx_stub_enclave KEY sgx_stub_enclave.pem CONFIG sgx_stub_enclave.xml)
add_dependencies(sgx_stub_enclave rats_lib)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/sgx_stub_enclave.signed.so
        DESTINATION /usr/share/librats/samples)
