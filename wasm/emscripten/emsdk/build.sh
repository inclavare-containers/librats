#! /bin/bash
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EMSDK_VERSION="3.1.17"
EMSDK_DIR=${SOURCE_DIR}/emsdk-${EMSDK_VERSION}
EMSCRIPTEN_DIR=${EMSDK_DIR}/upstream/emscripten

cd ${SOURCE_DIR}

if [ "${1,,}" == "clean" ]; then
    rm -rf ${EMSDK_DIR}
    exit 0
fi

# install emscripten
if [ ! -d ${EMSDK_DIR} ];then
    wget https://github.com/emscripten-core/emsdk/archive/refs/tags/${EMSDK_VERSION}.tar.gz
    tar xzvf ${EMSDK_VERSION}.tar.gz
    rm ${EMSDK_VERSION}.tar.gz
    cd ${EMSDK_DIR} && ./emsdk install ${EMSDK_VERSION} && ./emsdk activate ${EMSDK_VERSION}
    sed -i "s#TARGET_SUPPORTS_SHARED_LIBS FALSE#TARGET_SUPPORTS_SHARED_LIBS TRUE#g" ${EMSCRIPTEN_DIR}/cmake/Modules/Platform/Emscripten.cmake
fi

source ${EMSDK_DIR}/emsdk_env.sh
if [ `grep -c "${EMSDK_DIR}/emsdk_env.sh" $HOME/.bashrc` -eq '0' ];then
    echo "source ${EMSDK_DIR}/emsdk_env.sh >/dev/null 2>&1" >> $HOME/.bashrc
fi