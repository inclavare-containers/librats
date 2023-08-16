# Build librats in wasm mode

## Introduction

We have introduced support for wasm in librats, which can be fully compiled into wasm code, with the help of [emscripten](https://emscripten.org/).

## Details

In wasm mode, we compile the core part of librats as a `Main module` and `verifiers`, `crypto_wrappers` as `Side modules`. They are [packaged](https://emscripten.org/docs/porting/files/packaging_files.html) into emscripten's virtual file system, and could be [dynamically linked](https://emscripten.org/docs/compiling/Dynamic-Linking.html#runtime-dynamic-linking-with-dlopen) with `dlopen()` at runtime.

For third-party libraries such as `dcap`(for verifiers/sgx_ecdsa) and `openssl`(for crypto_wrappers/openssl), we statically link them into the corresponding Side modules.

> Currently we don't support `attesters` in wasm mode.

## Build

please type the following command.
```shell
source wasm/emscripten/pre_build.sh
cmake -DRATS_BUILD_MODE="wasm"  -H. -Bbuild
make -C build
```

When the compilation is finished, you can find the results in build/wasm, which contain a sample html that can be opened in a browser.


