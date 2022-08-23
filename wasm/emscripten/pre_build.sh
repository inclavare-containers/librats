SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EMSDK_DIR=${SOURCE_DIR}/emsdk
OPENSSL_DIR=${SOURCE_DIR}/openssl
DCAP_DIR=${SOURCE_DIR}/dcap

cd ${SOURCE_DIR}

if [ "${1,,}" == "clean" ]; then
    cd ${EMSDK_DIR} && ./build.sh clean
    cd ${OPENSSL_DIR} && ./build.sh clean
    cd ${DCAP_DIR} && ./build.sh clean
    exit 0
fi

cd ${EMSDK_DIR} && source build.sh
cd ${OPENSSL_DIR} && ./build.sh
cd ${DCAP_DIR} && ./build.sh

cd ${SOURCE_DIR}/../../