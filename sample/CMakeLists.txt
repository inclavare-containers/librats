cmake_minimum_required(VERSION 3.5.1)
project(librats-attester-verify-sample)

# /usr/local
set(RATS_INSTALL_PATH "/usr/local")
# include/rats
set(RATS_INSTALL_INCLUDE_PATH "${RATS_INSTALL_PATH}/include/")

# Set include directory
set(INCLUDE_DIRS ${RATS_INSTALL_INCLUDE_PATH})
include_directories(${INCLUDE_DIRS})

# lib/rats
set(RATS_INSTALL_LIB_PATH "${RATS_INSTALL_PATH}/lib/librats")
set(LIBRARY_DIRS ${RATS_INSTALL_LIB_PATH}
                 ${RATS_INSTALL_LIB_PATH}/verifiers
                 ${RATS_INSTALL_LIB_PATH}/attesters
                 )
# Set dependency library directory
link_directories(${LIBRARY_DIRS})

message(STATUS "${INCLUDE_DIRS}")

set(SOURCES main.c)

SET(CMAKE_BUILD_TYPE "Debug")
SET(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -g2 -ggdb")
SET(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -O3 -Wall")

add_executable(${PROJECT_NAME} ${SOURCES})
target_link_libraries(${PROJECT_NAME} librats_lib.so libverifier_tdx_ecdsa.so libattester_tdx_ecdsa.so)
