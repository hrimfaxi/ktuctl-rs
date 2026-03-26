#!/bin/bash

export TOOLCHAIN=~/temp/openwrt-sdk-25.12.1-x86-64_gcc-14.3.0_musl.Linux-x86_64/staging_dir/toolchain-x86_64_gcc-14.3.0_musl/bin
export PATH=$TOOLCHAIN:$PATH

export CC_x86_64_unknown_linux_musl=$TOOLCHAIN/x86_64-openwrt-linux-musl-gcc
export CXX_x86_64_unknown_linux_musl=$TOOLCHAIN/x86_64-openwrt-linux-musl-g++
export AR_x86_64_unknown_linux_musl=$TOOLCHAIN/x86_64-openwrt-linux-musl-ar
export CARGO_TARGET_x86_64_UNKNOWN_LINUX_MUSL_LINKER=$TOOLCHAIN/x86_64-openwrt-linux-musl-gcc

cargo build --release --target x86_64-unknown-linux-musl
