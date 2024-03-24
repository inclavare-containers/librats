# librats
![](../../actions/workflows/pr_basic_compilation_check.yml/badge.svg)

<!-- TODO: add a License badge -->

[librats](https://github.com/inclavare-containers/librats) is a C library designed to facilitate remote attestation for secure computing environments. It provides a framework for attesting the integrity of computing environments remotely, enabling trust establishment between different Trusted Execution Environments (TEEs).


## How to start ?

We currently provide a sample app that uses librats named `cert-app`, which you can take a look at [here](samples/cert-app/README.md).

Also, for the functions exposed by librats, see the [include/librats/api.h](include/librats/api.h) file.


## Build from source

We are currently not providing a pre-built version of librats, and you have to manual compilation from the source. And we use cmake to build this project, which makes it easy to integrate.

### Build Requirements Installation

#### Use docker image

We've provided [docker images](https://hub.docker.com/r/runetest/compilation-testing/tags) of the librats build environment, which includes all the packages that need to be installed for building librats.

- `runetest/compilation-testing:anolis8.6`
- `runetest/compilation-testing:ubuntu20.04`


#### Install manually

- This project has been tested on the following platforms, it should also work on similar distributions.

  - Anolis OS 8.6 64bits
  - Ubuntu 22.04 LTS Server 64bits

- Install some necessary packages

  - On Anolis 8.6
    ```sh
    dnf install -y --nogpgcheck epel-release
    dnf --enablerepo=PowerTools install -y git wget \
        make cmake autoconf libtool gcc gcc-c++ \
        openssl-devel libcurl-devel dnf-utils patch \
        libcbor-devel
    ```

  - On Ubuntu 22.04
    ```sh
    echo "deb http://cz.archive.ubuntu.com/ubuntu bionic main" >> /etc/apt/sources.list
    apt-get update
    apt-get install -y libprotobuf10
    apt-get install -y make git vim clang-format-9 gcc \
        pkg-config protobuf-compiler debhelper cmake \
        wget net-tools curl file gnupg tree libcurl4-openssl-dev \
        libbinutils libseccomp-dev libssl-dev binutils-dev libprotoc-dev \
        libcbor-dev
    ```
- Install the Rust toolchain, which is needed by some dependencies of this project. You can install it by following the instructions at this [link](https://www.rust-lang.org/tools/install).

- (For SGX enclave) You may need to install the LVI mitigated toolchain to mitigate the Load Value Injection attack vulnerability of Intel SGX. For more infomation, see this [link](https://github.com/intel/linux-sgx).

  - On Anolis 8.6
    ```sh
    SGX_SDK_VERSION=2.23
    wget https://download.01.org/intel-sgx/sgx-linux/$SGX_SDK_VERSION/as.ld.objdump.r4.tar.gz && \
        tar -zxvf as.ld.objdump.r4.tar.gz && cp -rf external/toolset/anolis8.6/* /usr/local/bin/ && \
        rm -rf external && rm -rf as.ld.objdump.r4.tar.gz
    ```

  - On Ubuntu 22.04
    ```sh
    SGX_SDK_VERSION=2.23
    wget https://download.01.org/intel-sgx/sgx-linux/$SGX_SDK_VERSION/as.ld.objdump.r4.tar.gz && \
        tar -zxvf as.ld.objdump.r4.tar.gz && cp -rf external/toolset/ubuntu20.04/* /usr/local/bin/ && \
        rm -rf external && rm -rf as.ld.objdump.r4.tar.gz
    ```

- Install SGX SDK using the following steps, or refer to the "Intel® SGX Application Developer" section of this [guide](https://download.01.org/intel-sgx/sgx-linux/2.23/docs/Intel_SGX_SW_Installation_Guide_for_Linux.pdf) for installation instructions.
  > Note: Requires Intel SGX SDK version >= 2.23

  - On Anolis 8.6
    ```sh
    SGX_SDK_VERSION=2.23
    SGX_SDK_RELEASE_NUMBER=2.23.100.2
    wget https://download.01.org/intel-sgx/sgx-linux/$SGX_SDK_VERSION/distro/Anolis86/sgx_linux_x64_sdk_$SGX_SDK_RELEASE_NUMBER.bin && \
        chmod +x sgx_linux_x64_sdk_$SGX_SDK_RELEASE_NUMBER.bin && \
        echo -e 'n\n\/opt/intel\n' | ./sgx_linux_x64_sdk_$SGX_SDK_RELEASE_NUMBER.bin
    ```

  - On Ubuntu 22.04
    ```sh
    SGX_SDK_VERSION=2.23
    SGX_SDK_RELEASE_NUMBER=2.23.100.2
    wget https://download.01.org/intel-sgx/sgx-linux/$SGX_SDK_VERSION/distro/ubuntu20.04-server/sgx_linux_x64_sdk_$SGX_SDK_RELEASE_NUMBER.bin && \
        chmod +x sgx_linux_x64_sdk_$SGX_SDK_RELEASE_NUMBER.bin && \
        echo -e 'no\n/opt/intel\n' | ./sgx_linux_x64_sdk_$SGX_SDK_RELEASE_NUMBER.bin
    ```

- Install SGX DCAP using the following steps, or refer to the "Intel® SGX Application User" section of this [guide](https://download.01.org/intel-sgx/sgx-linux/2.23/docs/Intel_SGX_SW_Installation_Guide_for_Linux.pdf) for installation instructions.
  > Note: Requires Intel DCAP version >= 1.20

  - On Anolis 8.6

    a. Add repository to package manager of your distro.
      ```sh
      SGX_SDK_VERSION=2.23
      wget https://download.01.org/intel-sgx/sgx-linux/$SGX_SDK_VERSION/distro/Anolis86/sgx_rpm_local_repo.tgz && \
          tar zxvf sgx_rpm_local_repo.tgz && \
          dnf config-manager --add-repo sgx_rpm_local_repo
      dnf makecache
      ```

    b. Install DCAP related packages.
      ```sh
      SGX_SDK_VERSION=2.23
      SGX_DCAP_VERSION=1.20
      dnf install --nogpgcheck -y libsgx-headers-"$SGX_SDK_VERSION*" \
          libsgx-dcap-quote-verify-devel-"$SGX_DCAP_VERSION*" \
          libsgx-dcap-ql-devel-"$SGX_DCAP_VERSION*" \
          libsgx-dcap-default-qpl-"$SGX_DCAP_VERSION*"
      ```

  - On Ubuntu 22.04

    a. Add repository to package manager of your distro.
      ```sh
      echo "deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main" | tee /etc/apt/sources.list.d/intel-sgx.list && \
          wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add -
      apt-get update -y
      ```

    b. Install DCAP related packages.
      ```sh
      SGX_SDK_VERSION=2.23
      SGX_DCAP_VERSION=1.20
      apt-get install -y libsgx-headers="$SGX_SDK_VERSION*" \
          libsgx-dcap-quote-verify-dev="$SGX_DCAP_VERSION*" \
          libsgx-dcap-ql-dev="$SGX_DCAP_VERSION*" \
          libsgx-dcap-default-qpl="$SGX_DCAP_VERSION*"
      ```

- (For TDX attester) Install the TDX Attestation library
  - On Anolis 8.6
    ```sh
    SGX_DCAP_VERSION=1.20
    dnf install --nogpgcheck -y libtdx-attest-devel-"$SGX_DCAP_VERSION*"
    ```

  - On Ubuntu 22.04
    ```sh
    SGX_DCAP_VERSION=1.20
    apt-get install -y libtdx-attest-dev="$SGX_DCAP_VERSION*"
    ```

### Build and Install librats

Please follow the command to build librats from the latested source code on your system.

1. Download the latest source code of librats
    ```shell
    mkdir -p "$WORKSPACE"
    cd "$WORKSPACE"
    git clone https://github.com/inclavare-containers/librats
    ```

2. Build and install librats

    > Note that [SGX LVI mitigation](https://software.intel.com/security-software-guidance/advisory-guidance/load-value-injection) is enabled by default. You can set macro `SGX_LVI_MITIGATION` to `0` to disable SGX LVI mitigation.

    > Note: If you have the SGX SDK installed in a path other than the default path `/opt/intel`, please specify it using `-DSGX_SDK=<path-to-sdk>`.

    - If you want to build instances related to sgx(sgx\_ecdsa, sgx\_ecdsa\_qve, sgx\_la), please type the following command.

      ```shell
      cmake -DRATS_BUILD_MODE="sgx" -H. -Bbuild
      make -C build install
      ```

    - If you want to run instances on libos occlum, please type the following command.

      ```shell
      cmake -DRATS_BUILD_MODE="occlum" -H. -Bbuild
      make -C build install
      ```

    - If you want to run TDX instances, please type the following command.
      ```shell
      cmake -DRATS_BUILD_MODE="tdx" -H. -Bbuild
      make -C build install
      ```

    - If you want to run instances on AMD SEV/SEV-ES/SEV-SNP, CSV or non-TEE host, please type the following command.
      ```shell
      cmake -DRATS_BUILD_MODE="host" -H. -Bbuild
      make -C build install
      ```

3. Build and install librats sample apps

    You can just set `-DBUILD_SAMPLES=on` for also building samples of librats.

    The sample app `cert-app` will be installed to `/usr/share/librats/samples/cert-app` on your system. All instances are placed in `/usr/local/lib/librats/`.

4. Wasm support

    librats provides support for [WebAssembly](https://webassembly.org), which enables it to run in the browser and [WAMR](https://github.com/bytecodealliance/wasm-micro-runtime).

    - If you want to run it in browser, please read [this document](wasm/emscripten/README.md).

    - If you want to run it in WAMR, please type the following command.
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

## Run librats

Right now, librats supports the following instance types:

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

For instance priority, the higher, the stronger. By default, librats will select the **highest priority** instance to use.

### Some special notices

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

### Enable bootstrap debugging

In the early bootstrap of librats, the debug message is mute by default. In order to enable it, please explicitly set the environment variable `RATS_GLOBAL_LOG_LEVEL=<log_level>`, where \<log_level\> is same as the values of the option `-l`.


## Third Party Dependencies

Direct Dependencies

| Name | Repo URL | Licenses |
| :--: | :-------:   | :-------: |
| linux-sgx | https://github.com/intel/linux-sgx | BSD-3-clause |
| SGXDataCenterAttestationPrimitives | https://github.com/intel/SGXDataCenterAttestationPrimitives | BSD-3-clause |
| GNU C library | C library | GNU General Public License version 3 |
