# cert-app

This is a sample application using the librats cert api.

This program will first generate the certificate in the TEE, copy it outside the TEE, then reload it into the TEE to verify the certificate.

Note: Running in host mode is not supported due to the need to generate certificates.

## debug

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
