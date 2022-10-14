add_subdirectory(cert-app)
if(SGX)
    add_subdirectory(sgx-stub-enclave)
endif()
