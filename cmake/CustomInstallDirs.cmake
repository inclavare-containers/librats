# Use CMAKE_INSTALL_PREFIX (/usr/local by default) as prefix of install path for librats

# lib/librats
set(RATS_INSTALL_LIB_PATH "${CMAKE_INSTALL_PREFIX}/lib/librats")

# librats/attesters
set(RATS_INSTALL_LIBA_PATH "${RATS_INSTALL_LIB_PATH}/attesters")

# librats/verifiers
set(RATS_INSTALL_LIBV_PATH "${RATS_INSTALL_LIB_PATH}/verifiers")

# librats/crypto_wrappers
set(RATS_INSTALL_LIBCW_PATH "${RATS_INSTALL_LIB_PATH}/crypto_wrappers")

# include/librats
set(RATS_INSTALL_INCLUDE_PATH "${CMAKE_INSTALL_PREFIX}/include/librats")

# sgx sdk
if(EXISTS $ENV{SGX_SDK})
    set(SGXSDK_INSTALL_PATH "$ENV{SGX_SDK}")
else()
    set(SGXSDK_INSTALL_PATH "/opt/intel/sgxsdk")
endif()

# sgx sdk library
set(SGXSDK_INSTALL_LIB_PATH "${SGXSDK_INSTALL_PATH}/lib64")

# sgx sdk include
set(SGXSDK_INSTALL_INCLUDE_PATH "${SGXSDK_INSTALL_PATH}/include")
