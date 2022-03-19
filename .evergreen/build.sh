#!/bin/bash
# Installs libbson and compiles the default mongocrypt target.
# This script is useful to test compilation of libmongocrypt on platforms that are not necesary to test.
# For example, PHPC includes the source of libmongocrypt. It builds on Windows 32-bit. libmongocrypt does not test on 32-bit Windows.

set -o errexit

if [ ! -d "mongo-c-driver" ]; then
    echo "ERROR: expected mongo-c-driver directory to be in working directory but is not."
    exit 1
fi

if [ ! -d "libmongocrypt" ]; then
    echo "ERROR: expected libmongocrypt directory to be in working directory but is not."
    exit 1
fi

echo "build.sh ... begin"

evergreen_root="$(pwd)"
. ${evergreen_root}/libmongocrypt/.evergreen/setup-env.sh
. ${evergreen_root}/libmongocrypt/.evergreen/build_install_bson.sh # Sets ADDITIONAL_CMAKE_FLAGS.
cd $evergreen_root

# CMAKE should be set in build_install_bson.sh; this error should not occur
command -v $CMAKE || (echo "CMake could not be found...aborting!"; exit 1)

# Build and install libmongocrypt.
cd libmongocrypt
if [ -d "cmake-build" ]; then
    echo "Found directory: cmake-build. Removing."
    rm -rf cmake-build
fi
mkdir cmake-build
cd cmake-build

ADDITIONAL_CMAKE_FLAGS="$ADDITIONAL_CMAKE_FLAGS -DENABLE_MORE_WARNINGS_AS_ERRORS=ON"

$CMAKE -DCMAKE_BUILD_TYPE=RelWithDebInfo $ADDITIONAL_CMAKE_FLAGS "${LIBMONGOCRYPT_EXTRA_CMAKE_FLAGS}" -DCMAKE_C_FLAGS="${LIBMONGOCRYPT_EXTRA_CFLAGS}" -DCMAKE_PREFIX_PATH="${BSON_INSTALL_PREFIX}" ../
echo "Building libmongocrypt with native crypto ... begin"
$CMAKE --build . --target mongocrypt --config RelWithDebInfo
cd $evergreen_root
echo "Building libmongocrypt with native crypto ... end"

echo "build.sh ... end"