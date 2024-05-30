# cert-app

This is a sample application using the librats cert api.

This program will first generate the certificate in the TEE, copy it outside the TEE, then reload it into the TEE to verify the certificate.

Note: Running in host mode is not supported due to the need to generate certificates.

## Run cert-app

```sh
cd /usr/share/librats/samples
./cert-app
```

### Specify the instance type

The options of `cert-app` are as followed:

```sh
Options：

        --debug-enclave/-d            set to enable enclave debugging
        --no-privkey/-k               set to enable key pairs generation in librats
        --add-claim/-C key:val        add a user-defined custom claims.
        --attester/-a value   	      set the type of quote attester
        --verifier/-v value   	      set the type of quote verifier
        --crypto/-c value     	      set the type of crypto wrapper
        --log-level/-l                set the log level
        --help/-h                     show the usage
```

You can set command line parameters to specify different configurations.

For example:

```sh
./cert-app -a nullattester -v nullverifier
./cert-app -a sgx_ecdsa -v sgx_ecdsa_qve
./cert-app -a sgx_la -v sgx_la
./cert-app -c openssl
./cert-app -C "claim_0:value_0"
```

Librats's log level can be set through `-l` option with 6 levels: `off`, `fatal`, `error`, `warn`, `info`, and `debug`. The default level is error. The most verbose level is debug.

```
./cert-app -l debug
```

## Debug

### Inspecting generated cert

The generated certificate will be dumped to `/tmp/cert.der`. Here are some code snippets to let you parse the certificate manually from the command line:

- Get content of evidence extension in hex.

    ```sh
    openssl asn1parse -i -in /tmp/cert.der -inform der
    ```
    The hex dump is under the `2.23.133.5.4.9` object (`2.23.133.5.4.2` for endorsements).
    
    The data is a byte string of encoded tagged CBOR data, so you can copy and paste it to [cbor.me](https://cbor.me/) to view its contents.

- Calculate the hash value of the certificate public key.

    ```sh
    openssl x509 -inform der -in /tmp/cert.der -noout -pubkey | openssl asn1parse -noout -out - | openssl dgst -c -sha256
    ```
    The output is the sha256 hash of SubjectPublicKeyInfo field in the certificate. Now you can compare it manually with the value stored in the evidence extension.

- Set `RATS_GLOBAL_LOG_LEVEL=debug` at runtime if you need more log message.

### Debugging memory error

You can checking the memory errors with `AddressSanitizer`, which is supported by clang only. To enable it, compile librats with clang and some special options `-DCMAKE_C_COMPILER="/usr/bin/clang" -DCMAKE_C_FLAGS="-fsanitize=address -g"`.

For example:
```
rm -rf ./build/
cmake -DRATS_BUILD_MODE="tdx" -DCMAKE_C_COMPILER="/usr/bin/clang" -DCMAKE_C_FLAGS="-fsanitize=address -g" -H. -Bbuild
make -C build install
```

Then run `cert-app` as before to check for memory errors.
