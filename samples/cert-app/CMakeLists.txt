project(cert-app)

if(NOT SGX)
    set(CMAKE_C_FLAGS "-fPIE ${CMAKE_C_FLAGS}")
endif()

if(SGX)
    list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
    include(CustomInstallDirs)
    include(FindLibRats)
    if(NOT RATS_FOUND)
        message(FATAL_ERROR "Failed to find librats!")
    endif()

    include(FindSGX)
    if(NOT SGX_FOUND)
        message(FATAL_ERROR "Failed to find sgx!")
    endif()

    include(CompilerOptions)
    include(SGXCommon)

    set(EDL_SEARCH_PATHS ${CMAKE_CURRENT_SOURCE_DIR}/../sgx-stub-enclave
                             ${CMAKE_CURRENT_SOURCE_DIR}/../../include/edl
			     )
    set(INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/../../include
                     ${CMAKE_CURRENT_SOURCE_DIR}/../../include/edl
                     ${CMAKE_CURRENT_SOURCE_DIR}/../../include/librats
                     )
    list(APPEND LIBRARY_DIRS ${CMAKE_BINARY_DIR}/tee/sgx/untrust
                             ${CMAKE_BINARY_DIR}/samples/sgx-stub-enclave
                             )
    set(EDL_SEARCH_PATHS ${CMAKE_CURRENT_SOURCE_DIR}/../sgx-stub-enclave
                         ${CMAKE_CURRENT_SOURCE_DIR}/../../include/edl
                         )
    set(DEPEND_UNTRUSTED_LIBS ${CMAKE_BINARY_DIR}/tee/sgx/untrust/librats_u.a)

else()
    set(INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/../../include
                     ${CMAKE_CURRENT_SOURCE_DIR}/../../include/edl
                     ${CMAKE_CURRENT_SOURCE_DIR}/../../include/librats
                     ${RATS_INSTALL_INCLUDE_PATH}
                     ${RATS_INSTALL_INCLUDE_PATH}/edl
                     ${RATS_INSTALL_INCLUDE_PATH}/librats
                     )
    set(LIBRARY_DIRS ${RATS_INSTALL_LIB_PATH})
endif()

include_directories(${INCLUDE_DIRS})
link_directories(${LIBRARY_DIRS})

set(SOURCES main.c)

if(SGX)
    set(EDLS ${CMAKE_CURRENT_SOURCE_DIR}/../sgx-stub-enclave/sgx_stub.edl)
    add_untrusted_executable(${PROJECT_NAME}
                             SRCS ${SOURCES}
                             UNTRUSTED_LIBS ${DEPEND_UNTRUSTED_LIBS}
                             EDL ${EDLS}
                             EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS})
    add_dependencies(${PROJECT_NAME} sgx_stub_enclave-sign)
else()

add_executable(${PROJECT_NAME} ${SOURCES})
    target_link_libraries(${PROJECT_NAME} rats_lib)
    target_link_libraries(${PROJECT_NAME} crypto)
endif()

install(TARGETS ${PROJECT_NAME}
	DESTINATION /usr/share/librats/samples)
