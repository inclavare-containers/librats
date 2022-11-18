# /usr/local
set(RATS_INSTALL_PATH "/usr/local" CACHE STRING "Install path for librats")

# lib/rats
set(RATS_INSTALL_LIB_PATH "${RATS_INSTALL_PATH}/lib/librats")

# rats/attesters
set(RATS_INSTALL_LIBA_PATH "${RATS_INSTALL_LIB_PATH}/attesters")

# rats/verifiers
set(RATS_INSTALL_LIBV_PATH "${RATS_INSTALL_LIB_PATH}/verifiers")

# include/rats
set(RATS_INSTALL_INCLUDE_PATH "${RATS_INSTALL_PATH}/include/")

# /usr/share/rats
set(RATS_INSTALL_BIN_PATH "/usr/share/librats/samples")

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
