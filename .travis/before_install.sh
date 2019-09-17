set -e
pushd ~

function llvm_version_triple() {
    if [ "$1" == "3.8" ]; then
        echo "3.8.1"
    elif [ "$1" == "3.9" ]; then
        echo "3.9.1"
    elif [ "$1" == "4.0" ]; then
        echo "4.0.1"
    elif [ "$1" == "5.0" ]; then
        echo "5.0.2"
    elif [ "$1" == "6.0" ]; then
        echo "6.0.1"
    elif [ "$1" == "7.0" ]; then
        echo "7.0.1"
    elif [ "$1" == "8.0" ]; then
        echo "8.0.1"
    fi
}

function llvm_download() {
    export LLVM_VERSION_TRIPLE=`llvm_version_triple ${LLVM_VERSION}`
    export LLVM=clang+llvm-${LLVM_VERSION_TRIPLE}-x86_64-$1

    wget http://llvm.org/releases/${LLVM_VERSION_TRIPLE}/${LLVM}.tar.xz
    mkdir llvm
    tar -xf ${LLVM}.tar.xz -C llvm --strip-components=1

    export LLVM_CONFIG_PATH=`pwd`/llvm/bin/llvm-config
}

llvm_download linux-gnu-ubuntu-16.04

popd
set +e
