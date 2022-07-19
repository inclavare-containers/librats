# Project name
project(verifier_sgx_ecdsa)

# Set include directory
list(APPEND INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}
                         /usr/include
                         )
if(OCCLUM)
    list(APPEND INCLUDE_DIRS ${SGXSDK_INSTALL_INCLUDE_PATH})
endif()
include_directories(${INCLUDE_DIRS})

# Set dependency library directory
set(LIBRARY_DIRS ${CMAKE_BINARY_DIR}
                 ${RATS_INSTALL_LIB_PATH}
                 )

# Set extra link library
if(OCCLUM)
    list(APPEND LIBRARY_DIRS ${SGXSDK_INSTALL_LIB_PATH})
    set(EXTRA_LINK_LIBRARY dcap_quote pthread m)
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

# Generate library
if(SGX)
    add_trusted_library(${PROJECT_NAME} SRCS ${SOURCES})
else()
    add_library(${PROJECT_NAME} SHARED ${SOURCES})
    target_link_libraries(${PROJECT_NAME} ${EXTRA_LINK_LIBRARY} ${RATS_LDFLAGS} ${RATS_LIB})
    set_target_properties(${PROJECT_NAME} PROPERTIES VERSION ${VERSION} SOVERSION ${VERSION_MAJOR})
endif()

# Install library
install(TARGETS ${PROJECT_NAME}
	DESTINATION ${RATS_INSTALL_LIBV_PATH})
