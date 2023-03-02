# Project name
project(crypto_wrapper_nullcrypto)

# Set include directory
include_directories(${INCLUDE_DIRS})

# Set dependency library directory
set(LIBRARY_DIRS ${CMAKE_BINARY_DIR}/src
                 ${RATS_INSTALL_LIB_PATH}
                 )
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
    add_trusted_library(${PROJECT_NAME} SRCS ${SOURCES})
else()
    add_library(${PROJECT_NAME} SHARED ${SOURCES})
    target_link_libraries(${PROJECT_NAME} ${RATS_LDFLAGS} ${RATS_LIB})
    set_target_properties(${PROJECT_NAME} PROPERTIES VERSION ${VERSION} SOVERSION ${VERSION_MAJOR})
endif()

# Install library
install(TARGETS ${PROJECT_NAME}
	DESTINATION ${RATS_INSTALL_LIBCW_PATH})
