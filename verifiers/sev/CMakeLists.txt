# Project name
project(verifier_sev)

# Set include directory
set(INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/../../include
                 ${CMAKE_CURRENT_SOURCE_DIR}/../../include/librats
                 ${CMAKE_CURRENT_SOURCE_DIR}/../../include/internal
                 )
if(WASM)
    list(APPEND INCLUDE_DIRS ${WASM_SRCS_DIR}/openssl/install/include)
endif()
include_directories(${INCLUDE_DIRS})

# Set dependency library directory
set(LIBRARY_DIRS ${CMAKE_BINARY_DIR}
                 ${RATS_INSTALL_LIB_PATH}
                 )
link_directories(${LIBRARY_DIRS})

# Set source file
set(SOURCES cleanup.c
            init.c
            sev_utils.c
            sevcert.c
            amdcert.c
            main.c
            pre_init.c
            verify_evidence.c
            )

# Generate library
add_library(${PROJECT_NAME} SHARED ${SOURCES})
if(WASM)
    target_link_libraries(${PROJECT_NAME} ${RATS_LDFLAGS} ${WASM_SIDE_NORMAL_FLAGS})
    add_custom_command(TARGET ${PROJECT_NAME}
                       POST_BUILD
                       COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_BINARY_DIR}/lib${PROJECT_NAME}.so ${WASM_BUILD_DIR}
                       COMMAND wget ${ASK_ARK_PATH_SITE}/${ASK_ARK_NAPLES_FILE} -O ${CMAKE_BINARY_DIR}/${ASK_ARK_NAPLES_FILE}
                       COMMAND wget ${ASK_ARK_PATH_SITE}/${ASK_ARK_ROME_FILE} -O ${CMAKE_BINARY_DIR}/${ASK_ARK_ROME_FILE}
                       COMMAND wget ${ASK_ARK_PATH_SITE}/${ASK_ARK_MILAN_FILE} -O ${CMAKE_BINARY_DIR}/${ASK_ARK_MILAN_FILE}
                       )
    if(DEBUG)
      add_custom_command(TARGET ${PROJECT_NAME}
                         POST_BUILD
                         COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_BINARY_DIR}/lib${PROJECT_NAME}.so.map ${WASM_BUILD_DIR}
                         )
   endif()
else()
    target_link_libraries(${PROJECT_NAME} ${RATS_LDFLAGS} ${RATS_LIB} crypto curl)
    set_target_properties(${PROJECT_NAME} PROPERTIES VERSION ${VERSION} SOVERSION ${VERSION_MAJOR})
endif()

# Install library
if(NOT WASM)
    install(TARGETS ${PROJECT_NAME} DESTINATION ${RATS_INSTALL_LIBV_PATH})
endif()
