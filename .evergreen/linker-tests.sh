#!/bin/bash

set -o xtrace


# Directory layout
# .evergreen
# -linker_tests_deps
# --app
# --bson_patches
#
# linker_tests (created by this script)
# -libmongocrypt-cmake-build (for artifacts build from libmongocrypt source)
# -app-cmake-build
# -mongo-c-driver
# --cmake-build
# -install
# --bson1
# --bson2
# --libmongocrypt
#   

if [ ! -e ./.evergreen ]; then
    echo "Error: run from libmongocrypt root"
    exit 1;
fi

libmongocrypt_root=$(pwd)
linker_tests_root=$(pwd)/linker_tests
linker_tests_deps_root=$(pwd)/.evergreen/linker_tests_deps

rm -rf linker_tests
mkdir linker_tests
mkdir linker_tests/install
mkdir linker_tests/libmongocrypt-cmake-build
mkdir linker_tests/app-cmake-build
cd linker_tests

# Make libbson1 and libbson2
git clone https://github.com/mongodb/mongo-c-driver.git --depth=1 --config core.eol=lf --config core.autocrlf=false
cd mongo-c-driver

# Use C driver helper script to find cmake binary, stored in $CMAKE.
if [ "$OS" == "Windows_NT" ]; then
    CMAKE=/cygdrive/c/cmake/bin/cmake
    ADDITIONAL_CMAKE_FLAGS="-Thost=x64 -A x64"
else
    chmod u+x ./.evergreen/find-cmake.sh
    . ./.evergreen/find-cmake.sh
fi

git apply --ignore-whitespace $linker_tests_deps_root/bson_patches/libbson1.patch
mkdir cmake-build
cd cmake-build
$CMAKE -DBUILD_VERSION=1.16.0-pre -DENABLE_MONGOC=OFF -DCMAKE_BUILD_TYPE=RelWithDebInfo $ADDITIONAL_CMAKE_FLAGS -DCMAKE_C_FLAGS="-fPIC" -DCMAKE_INSTALL_PREFIX=$linker_tests_root/install/bson1 ../
$CMAKE --build . --target install --config RelWithDebInfo
# Make libbson2
cd ..
git reset --hard
git apply --ignore-whitespace $linker_tests_deps_root/bson_patches/libbson2.patch
cd cmake-build
$CMAKE -DBUILD_VERSION=1.16.0-pre -DENABLE_MONGOC=OFF -DCMAKE_BUILD_TYPE=RelWithDebInfo $ADDITIONAL_CMAKE_FLAGS -DCMAKE_C_FLAGS="-fPIC" -DCMAKE_INSTALL_PREFIX=$linker_tests_root/install/bson2 ../
$CMAKE --build . --target install --config RelWithDebInfo

# Build libmongocrypt, static linking against libbson2
cd $linker_tests_root/libmongocrypt-cmake-build
$CMAKE -DCMAKE_BUILD_TYPE=RelWithDebInfo $ADDITIONAL_CMAKE_FLAGS -DCMAKE_C_FLAGS="-fPIC" -DCMAKE_PREFIX_PATH="$linker_tests_root/install/bson2" -DCMAKE_INSTALL_PREFIX="$linker_tests_root/install/libmongocrypt" $libmongocrypt_root
$CMAKE --build . --target install --config RelWithDebInfo

echo "Test case: Modelling libmongoc's use"
# app links against libbson1.so
# app links against libmongocrypt.so
cd $linker_tests_root/app-cmake-build
$CMAKE -DCMAKE_BUILD_TYPE=RelWithDebInfo $ADDITIONAL_CMAKE_FLAGS -DCMAKE_C_FLAGS="-fPIC" -DCMAKE_PREFIX_PATH="$linker_tests_root/install/bson1:$linker_tests_root/install/libmongocrypt" $linker_tests_deps_root/app
$CMAKE --build . --target app --config RelWithDebInfo

check_output () {
    if [ "$OS" == "Windows_NT" ]; then
        output="$(./RelWithDebInfo/app.exe)"
    else
        output="$(./app)"
    fi

    if [ "$output" != "$1" ]; then
        echo "got '$output', expecting '$1'"
        exit 1;
    fi
    echo "ok"
}
check_output ".calling bson_malloc0..from libbson1..calling mongocrypt_binary_new..from libbson2."
