#! /bin/bash
SOURCE_DIR="$(cd "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P)"
DCAP_VERSION="DCAP_1.14"
DCAP_DIR="${SOURCE_DIR}/SGXDataCenterAttestationPrimitives"
LIB_DIR="${SOURCE_DIR}/lib"
PATCH_DIR="${SOURCE_DIR}/patch"

cd ${SOURCE_DIR}

if [ "${1,,}" == "clean" ]; then
    cd ${DCAP_DIR} && make clean
    rm -rf ${LIB_DIR}
    exit 0
fi


if [ -d "${LIB_DIR}" ]; then
  rm -rf ${LIB_DIR}
fi
mkdir -p "${LIB_DIR}"

# git pull and apply patch
if [ ! -d "${DCAP_DIR}" ]; then
  git clone -b ${DCAP_VERSION} --depth=1 https://github.com/intel/SGXDataCenterAttestationPrimitives || exit 1
  cd ${DCAP_DIR} || exit 1
  git config user.email "you@example.com" || exit 1
  git config user.name "Your Name" || exit 1
  git am ../patch/*.patch || exit 1
fi

# compile libraries
# if debug needed, add DEBUG=1 in emmake make ..
cd ${DCAP_DIR}/QuoteGeneration/qcnl/linux && emmake make  GEN_STATIC=1 GEN_DYNAMIC=0 WASM=1 && cp libsgx_default_qcnl_wrapper.a ${LIB_DIR}
cd ${DCAP_DIR}/QuoteGeneration/qpl/linux && emmake make  GEN_STATIC=1 GEN_DYNAMIC=0 WASM=1 && cp libdcap_quoteprov.a ${LIB_DIR}
cd ${DCAP_DIR}/QuoteVerification/dcap_quoteverify/linux && emmake make  GEN_STATIC=1 GEN_DYNAMIC=0 WASM=1 && cp libsgx_dcap* ${LIB_DIR}