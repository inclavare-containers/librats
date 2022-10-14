include(CustomInstallDirs)
include(FindPackageHandleStandardArgs)

set(RATS_INCLUDE_DIR ${RATS_SRC_PATH}/src/include)

# Handle the QUIETLY and REQUIRED arguments and set RATS_FOUND to TRUE if all listed variables are TRUE.
find_package_handle_standard_args(RATS
    DEFAULT_MSG
    RATS_INCLUDE_DIR)

if(RATS_FOUND)
    set(RATS_INCLUDES ${RATS_INCLUDE_DIR})
else()
    set(RATS_LIBRARIES)
    set(RATS_INCLUDES)
endif()
