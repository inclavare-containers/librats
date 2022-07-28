#! /bin/bash
SOURCE_DIR="$(cd "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P)"
OPENSSL="openssl-1.1.1i"
OPENSSL_DIR=${SOURCE_DIR}/${OPENSSL}

cd ${SOURCE_DIR}

if [ "${1,,}" == "clean" ]; then
    rm -rf ${OPENSSL_DIR}
    rm -rf ${SOURCE_DIR}/install
    rm -f ${OPENSSL}.tar.gz
    exit 0
fi

trap 'onExit' SIGINT
function onExit () {
    rm -f ${OPENSSL}.tar.gz
    rm -rf ${SOURCE_DIR}/install
    rm -rf ${OPENSSL_DIR}
    exit 0
}

if [ -d ${SOURCE_DIR}/install ]; then
  rm -rf ${SOURCE_DIR}/install
fi
mkdir ${SOURCE_DIR}/install

if [ ! -d ${OPENSSL_DIR} ]; then
  wget https://www.openssl.org/source/${OPENSSL}.tar.gz
  tar xzvf ${OPENSSL}.tar.gz
  rm ${OPENSSL}.tar.gz
fi
cd ${OPENSSL_DIR} || exit 0

emconfigure ./Configure --prefix=${SOURCE_DIR}/install linux-x86 no-asm no-threads no-engine no-hw no-weak-ssl-ciphers no-dtls no-shared no-dso 
sed -i -e 's|^CROSS_COMPILE.*$|CROSS_COMPILE=|g' Makefile
sed -i -e '/^CFLAGS/ s/$/ -D__STDC_NO_ATOMICS__=1/' Makefile
sed -i -e '/^CXXFLAGS/ s/$/ -D__STDC_NO_ATOMICS__=1/' Makefile
emmake make -j$((`nproc`+1)) build_generated libssl.a libcrypto.a
emmake make install