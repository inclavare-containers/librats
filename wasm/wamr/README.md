# Librats for wamr

## Introduction
[WebAssembly Micro Runtime (WAMR)](https://github.com/bytecodealliance/wasm-micro-runtime) is a lightweight standalone WebAssembly (WASM) runtime with small footprint, high performance and highly configurable features for applications cross from embedded, IoT, edge to Trusted Execution Environment (TEE), smart contract, cloud native and so on.

Wamr support all build modes of librats (SGX mode is supported [here](https://github.com/bytecodealliance/wasm-micro-runtime/blob/main/samples/sgx-ra/README.md)).

## Preparation
Before staring, we need to download [WASI-SDK](https://github.com/WebAssembly/wasi-sdk/releases) and extract the archive to default path `/opt/wasi-sdk`.

## Build

```shell
$ cd wasm/wamr
$ cmake -Bbuild -H.
$ make -C build
```

## Run
You could run the sample by the following command when compilation is finished.
```shell
$ cd build
$ ./iwasm --native-lib=librats_wamr.so sample/test.wasm
```
