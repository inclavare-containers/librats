 # Building

 ## Build Requirements

 - git
 - make
 - autoconf
 - libtool
 - libcurl
 - gcc
 - g++
 - openssl-devel / libssl-dev
 - cargo (only needed in host mode)
 - python, bzip2 (only needed in wasm mode)
 - SGX driver, Intel SGX SDK & PSW: Please refer to this [guide](https://download.01.org/intel-sgx/sgx-linux/2.18/docs/Intel_SGX_SW_Installation_Guide_for_Linux.pdf) to install.
   - Requires Intel SGX SDK and PSW version >= 2.18
 - [SGX DCAP](https://github.com/intel/SGXDataCenterAttestationPrimitives): please download and install the packages from this [page](https://download.01.org/intel-sgx/sgx-dcap/#version#linux/distro).
   - ubuntu 18.04: `libsgx-dcap-quote-verify-dev`, `libsgx-dcap-ql-dev`, `libsgx-uae-service`
   - Requires Intel DCAP version >= 1.15
 - For TDX, please see the README in TDX MVP Stack. You need to download the packages and following TDX_E2E_attestation_software_stack_Installation_README-dcap-2021XXXX.txt to do step 2 & step 3 to setup build and dependence libraries.

 ## Build and Install

 Please follow the command to build librats from the latested source code on your system.

 1. Download the latest source code of librats

 ```shell
 mkdir -p "$WORKSPACE"
 cd "$WORKSPACE"
 git clone https://github.com/inclavare-containers/librats
 ```

 2. Build and install librats

 ```shell
 cd librats
 cmake -DBUILD_SAMPLES=on -H. -Bbuild
 make -C build install
 ```

 `cert-app` will be installed to `/usr/share/librats/samples/cert-app` on your system. All instances are placed in `/usr/local/lib/librats/`.

 If you want to build instances related to sgx(sgx\_ecdsa, sgx\_ecdsa\_qve, sgx\_la), please type the following command.

 ```shell
 cmake -DRATS_BUILD_MODE="sgx" -DBUILD_SAMPLES=on -H. -Bbuild
 make -C build install
 ```

 If you want to run instances on libos occlum, please type the following command.

 ```shell
 cmake -DRATS_BUILD_MODE="occlum" -DBUILD_SAMPLES=on -H. -Bbuild
 make -C build install
 ```

 If you want to run TDX instances, please type the following command.
 ```shell
 cmake -DRATS_BUILD_MODE="tdx" -DBUILD_SAMPLES=on -H. -Bbuild
 make -C build install
 ```

 Note that [SGX LVI mitigation](https://software.intel.com/security-software-guidance/advisory-guidance/load-value-injection) is enabled by default. You can set macro `SGX_LVI_MITIGATION` to `0` to disable SGX LVI mitigation.

 3. Wasm support

 Librats provides support for [WebAssembly](https://webassembly.org), which enables it to run in the browser and [WAMR](https://github.com/bytecodealliance/wasm-micro-runtime).

 If you want to run it in browser, please type the following command.
 ```shell
 source wasm/emscripten/pre_build.sh
 cmake -DRATS_BUILD_MODE="wasm"  -H. -Bbuild
 make -C build
 ```

 When the compilation is finished, you can find the results in build/wasm.

 If you want to run it in WAMR, please type the following command.
 ```shell
 # install librats in host mode first
 cmake -H. -Bbuild
 make -C build install

 # export librats APIs to wamr
 cd wasm/wamr
 cmake -H. -Bbuild
 make -C build

 # run the sample
 cd build
 ./iwasm --native-lib=librats_wamr.so sample/test.wasm
 ```
 
 # RUN

 Right now, Librats supports the following instance types:

 | Priority   |     Attester instances     |     Verifier instances     |
 | ---------- | -------------------------- | -------------------------- |
 | 0          | nullattester               | nullverifier               |
 | 15         | sgx\_la                    | sgx\_la                    |
 | 20         | csv                        | csv                        |
 | 35         | sev                        | sev                        |
 | 42         | sev\_snp                   | sev\_snp                   |
 | 42         | tdx\_ecdsa                 | tdx\_ecdsa                 |
 | 52         | sgx\_ecdsa                 | sgx\_ecdsa                 |
 | 53         | sgx\_ecdsa                 | sgx\_ecdsa\_qve            |

 For instance priority, the higher, the stronger. By default, Librats will select the **highest priority** instance to use.


 **Notice: special prerequisites for TDX remote attestation in bios configuration and hardware capability.**

 Check msr 0x503, return value must be 0:
 ```
 sudo rdmsr 0x503s
 ```

 Note that if you want to run SEV-SNP remote attestation, please refer to [link](https://github.com/AMDESE/AMDSEV/tree/sev-snp-devel) to set up the host and guest Linux kernel, qemu and ovmf bios used for launching SEV-SNP guest.

 **Notice: special prerequisites for SEV(-ES) remote attestation in software capability.**

 - Kernel support SEV(-ES) runtime attestation, please manually apply [these patches](https://github.com/haosanzi/attestation-evidence-broker/tree/master/hack/README.md).
 - Start the [attestation evidence broker](https://github.com/haosanzi/attestation-evidence-broker/blob/master/README.md) service in host.

**Notice: special prerequisites for CSV(2) remote attestation in software capability.**

- Kernel support CSV(2) runtime attestation, please manually apply [theses patches](https://gitee.com/anolis/cloud-kernel/pulls/412).

 ## Enable bootstrap debugging

 In the early bootstrap of librats, the debug message is mute by default. In order to enable it, please explicitly set the environment variable `RATS_GLOBAL_LOG_LEVEL=<log_level>`, where \<log_level\> is same as the values of the option `-l`.


 # Third Party Dependencies

 Direct Dependencies

 | Name | Repo URL | Licenses |
 | :--: | :-------:   | :-------: |
 | linux-sgx | https://github.com/intel/linux-sgx | BSD-3-clause |
 | SGXDataCenterAttestationPrimitives | https://github.com/intel/SGXDataCenterAttestationPrimitives | BSD-3-clause |
 | GNU C library | C library | GNU General Public License version 3 |
