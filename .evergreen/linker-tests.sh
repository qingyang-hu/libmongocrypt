#!/bin/bash

set -o xtrace
# set -o errexit

# Use C driver helper script to find cmake binary, stored in $CMAKE.
if [ "$OS" == "Windows_NT" ]; then
    CMAKE=/cygdrive/c/cmake/bin/cmake
    ADDITIONAL_CMAKE_FLAGS="-Thost=x64 -A x64"
else
    chmod u+x ./.evergreen/find-cmake.sh
    . ./.evergreen/find-cmake.sh
fi

# TEMP
CMAKE=cmake

# Directory layout
# linker_tests
# -libmongocrypt-cmake-build (for artifacts build from libmongocrypt source)
# -mongo-c-driver
# --cmake-build
# -install
# --bson1
# --bson2
# --libmongocrypt
#   

if [ ! -e ./.evergreen ];
    echo "Error: run from libmongocrypt root"
    exit 1;
fi

libmongocrypt_root=$(pwd)
linker_tests_root=$(pwd)/linker_tests

rm -rf linker_tests
mkdir linker_tests
mkdir linker_tests/install
mkdir linker_tests/libmongocrypt-cmake-build
cd linker_tests

# Make libbson1 and libbson2
git clone git@github.com:mongodb/mongo-c-driver.git --depth=1 --config core.eol=lf --config core.autocrlf=false
cd mongo-c-driver
git apply $libmongocrypt_root/.evergreen/bson_patches/libbson1.patch
mkdir cmake-build
cd cmake-build
$CMAKE -DENABLE_MONGOC=OFF -DCMAKE_BUILD_TYPE=RelWithDebInfo $ADDITIONAL_CMAKE_FLAGS -DCMAKE_C_FLAGS="-fPIC" -DCMAKE_INSTALL_PREFIX=$linker_tests_root/install/bson1 ../
$CMAKE --build . --target install --config RelWithDebInfo
# Make libbson2
cd ..
git reset --hard
git apply $libmongocrypt_root/.evergreen/bson_patches/libbson2.patch
cd cmake-build
$CMAKE -DENABLE_MONGOC=OFF -DCMAKE_BUILD_TYPE=RelWithDebInfo $ADDITIONAL_CMAKE_FLAGS -DCMAKE_C_FLAGS="-fPIC" -DCMAKE_INSTALL_PREFIX=$linker_tests_root/install/bson2 ../
$CMAKE --build . --target install --config RelWithDebInfo

# Build libmongocrypt, static linking against libbson2
$CMAKE -DCMAKE_BUILD_TYPE=RelWithDebInfo $ADDITIONAL_CMAKE_FLAGS -DCMAKE_C_FLAGS="-fPIC" -DCMAKE_PREFIX_PATH="$linker_tests_root/install/bson2" "-DCMAKE_INSTALL_PREFIX=$linker_tests_root/install/libmongocrypt"  ../
$CMAKE --build . --target install --config RelWithDebInfo