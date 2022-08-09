# Project name
project(verifier_sgx_ecdsa)

# Set include directory
list(APPEND INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR} ${SGXSDK_INSTALL_INCLUDE_PATH})
if(WASM)
    list(APPEND INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/../../wasm/dcap/SGXDataCenterAttestationPrimitives/QuoteVerification/dcap_quoteverify/inc
                             ${CMAKE_CURRENT_SOURCE_DIR}/../../wasm/dcap/SGXDataCenterAttestationPrimitives/QuoteGeneration/quote_wrapper/ql/inc
                             )
endif()
include_directories(${INCLUDE_DIRS})

# Set dependency library directory
set(LIBRARY_DIRS ${CMAKE_BINARY_DIR}
                 ${RATS_INSTALL_LIB_PATH}
                 )

# Set extra link library
if(OCCLUM)
    list(APPEND LIBRARY_DIRS ${SGXSDK_INSTALL_LIB_PATH})
else()
    set(EXTRA_LINK_LIBRARY sgx_dcap_quoteverify)
endif()

link_directories(${LIBRARY_DIRS})

# Set source file
set(SOURCES cleanup.c
            init.c
            main.c
            pre_init.c
            verify_evidence.c
            )

if(WASM)
    set(WASM_FETCH_FLAG -sASYNCIFY_IMPORTS=['sgx_qv_verify_quote'])
endif()

# Generate library
if(SGX)
    add_trusted_library(${PROJECT_NAME} SRCS ${SOURCES})
elseif(WASM)
    add_library(${PROJECT_NAME} SHARED ${SOURCES})
    target_link_libraries(${PROJECT_NAME} ${RATS_LDFLAGS} ${WASM_SIDE_ASYNC_FLAGS} ${WASM_FETCH_FLAG})
    add_custom_command(TARGET ${PROJECT_NAME}
                       POST_BUILD
                       COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_BINARY_DIR}/lib${PROJECT_NAME}.so ${WASM_BUILD_DIR}
                       )
    if(DEBUG)
        add_custom_command(TARGET ${PROJECT_NAME}
                           POST_BUILD
                           COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_BINARY_DIR}/lib${PROJECT_NAME}.so.map ${WASM_BUILD_DIR}
                           )
    endif()
else()
    add_library(${PROJECT_NAME} SHARED ${SOURCES})
    target_link_libraries(${PROJECT_NAME} ${EXTRA_LINK_LIBRARY} ${RATS_LDFLAGS} ${RATS_LIB})
    set_target_properties(${PROJECT_NAME} PROPERTIES VERSION ${VERSION} SOVERSION ${VERSION_MAJOR})
endif()

# Install library
if(NOT WASM)
    install(TARGETS ${PROJECT_NAME} DESTINATION ${RATS_INSTALL_LIBV_PATH})
endif()
