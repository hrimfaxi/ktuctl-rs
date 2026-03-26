#!/bin/bash

export TOOLCHAIN=~/temp/openwrt-sdk-25.12.0-mediatek-filogic_gcc-14.3.0_musl.Linux-x86_64/staging_dir/toolchain-aarch64_cortex-a53_gcc-14.3.0_musl/bin
export PATH=$TOOLCHAIN:$PATH

export CC_aarch64_unknown_linux_musl=$TOOLCHAIN/aarch64-openwrt-linux-musl-gcc
export CXX_aarch64_unknown_linux_musl=$TOOLCHAIN/aarch64-openwrt-linux-musl-g++
export AR_aarch64_unknown_linux_musl=$TOOLCHAIN/aarch64-openwrt-linux-musl-ar
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=$TOOLCHAIN/aarch64-openwrt-linux-musl-gcc

cargo build --release --target aarch64-unknown-linux-musl
