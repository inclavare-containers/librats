# Project name
project(rats_edl_t)

# Set include directory
include_directories(${INCLUDE_DIRS})

# Set source file
set(SOURCES sgx_dummy.c
            sgx_ecdsa_ecalls.c
            rats_syscalls.c
            )

# Generate library
set(EDL_SEARCH_PATHS ${CMAKE_CURRENT_SOURCE_DIR}/../../../include/edl)
set(RATS_EDL ${CMAKE_CURRENT_SOURCE_DIR}/../../../include/edl/rats.edl)
add_trusted_library(${PROJECT_NAME}
                    SRCS ${SOURCES}
                    EDL ${RATS_EDL}
                    EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS}
		    )

# Install library
install(TARGETS ${PROJECT_NAME}
	DESTINATION ${RATS_INSTALL_LIB_PATH})
