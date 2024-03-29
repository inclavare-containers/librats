# Project name
project(attester_sgx_ecdsa)

# Set include directory
list(APPEND INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}
                         ${SGXSDK_INSTALL_INCLUDE_PATH}
                         )

if(OCCLUM)
    list(APPEND INCLUDE_DIRS ${SGXSDK_INSTALL_INCLUDE_PATH})
endif()
include_directories(${INCLUDE_DIRS})

# Set dependency library directory
set(LIBRARY_DIRS ${CMAKE_BINARY_DIR}
                 ${RATS_INSTALL_LIB_PATH}
                 )

if(OCCLUM)
    list(APPEND LIBRARY_DIRS ${SGXSDK_INSTALL_LIB_PATH})
endif()
link_directories(${LIBRARY_DIRS})

# Set source file
set(SOURCES cleanup.c
            collect_evidence.c
            collect_endorsements.c
            init.c
            main.c
            pre_init.c
            )

# Generate library
if(SGX)
    add_trusted_library(${PROJECT_NAME} SRCS ${SOURCES})
    add_dependencies(${PROJECT_NAME} rats_edl_t)
else()
    add_library(${PROJECT_NAME} SHARED ${SOURCES})
    target_link_libraries(${PROJECT_NAME} ${EXTRA_LINK_LIBRARY} ${RATS_LDFLAGS} ${RATS_LIB})
    set_target_properties(${PROJECT_NAME} PROPERTIES VERSION ${VERSION} SOVERSION ${VERSION_MAJOR})
endif()

# Install library
install(TARGETS ${PROJECT_NAME}
	DESTINATION ${RATS_INSTALL_LIBA_PATH})
