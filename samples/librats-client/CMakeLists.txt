cmake_minimum_required(VERSION 3.5.1)
project(librats-client)

include_directories(${RATS_INSTALL_INCLUDE_PATH})

link_directories(${RATS_INSTALL_LIB_PATH})

message(STATUS "${RATS_INSTALL_INCLUDE_PATH}")

set(SOURCES client.c)

SET(CMAKE_BUILD_TYPE "Debug")
SET(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -g2 -ggdb")
SET(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -O3 -Wall")

add_executable(${PROJECT_NAME} ${SOURCES})
target_link_libraries(${PROJECT_NAME} rats_lib)

install(TARGETS ${PROJECT_NAME}
	DESTINATION ${RATS_INSTALL_BIN_PATH})
