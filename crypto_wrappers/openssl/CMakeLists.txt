# Project name
project(crypto_wrapper_openssl)

# Set include directory
include_directories(${INCLUDE_DIRS})

# Set dependency library directory
set(LIBRARY_DIRS ${CMAKE_BINARY_DIR}/src
                 ${RATS_INSTALL_LIB_PATH}
                 )
if(SGX)
    list(APPEND LIBRARY_DIRS ${CMAKE_BINARY_DIR}/src/external/intel-sgx-ssl/lib)
endif()
link_directories(${LIBRARY_DIRS})

# Set source file
set(SOURCES cleanup.c
            gen_cert.c
            gen_hash.c
            gen_privkey.c
            get_pubkey_hash.c
            init.c
            main.c
            pre_init.c
            use_privkey.c
            verify_cert.c
            )

# Generate library
if(SGX)
    set(DEPEND_TRUSTED_LIBS sgx_tsgxssl_cryptod)
    add_trusted_library(${PROJECT_NAME} SRCS ${SOURCES} TRUSTED_LIBS ${DEPEND_TRUSTED_LIBS})
    add_dependencies(${PROJECT_NAME} intel-sgx-ssl)
elseif(WASM)
    add_library(${PROJECT_NAME} SHARED ${SOURCES})
    target_link_libraries(${PROJECT_NAME} ${RATS_LDFLAGS} ${WASM_SIDE_NORMAL_FLAGS})
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
    target_link_libraries(${PROJECT_NAME} ${RATS_LDFLAGS} ${RATS_LIB} crypto.so)
    set_target_properties(${PROJECT_NAME} PROPERTIES VERSION ${VERSION} SOVERSION ${VERSION_MAJOR})
endif()

# Install library
if(NOT WASM)
    install(TARGETS ${PROJECT_NAME} DESTINATION ${RATS_INSTALL_LIBCW_PATH})
endif()