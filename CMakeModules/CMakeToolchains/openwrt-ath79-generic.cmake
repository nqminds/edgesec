include("${CMAKE_CURRENT_LIST_DIR}/DefineOpenWRTSDKToolchain.cmake")

defineOpenwrtSDKToolchain(
    URL https://downloads.openwrt.org/releases/19.07.10/targets/ath79/generic/openwrt-sdk-19.07.10-ath79-generic_gcc-7.5.0_musl.Linux-x86_64.tar.xz
    # sha256 from https://downloads.openwrt.org/releases/19.07.10/targets/ath79/generic/sha256sums
    URL_HASH SHA256=aaf12a88e4ff4cb89ff3a6dae31ff9fc16e70f0e735ada892185f00129dc1cde
    TOOLCHAIN_DIR toolchain-mips_24kc_gcc-7.5.0_musl
    TARGET_DIR target-mips_24kc_musl
    GNU_TARGET mips-openwrt-linux-musl
    # normally this is the first word of $GNU_TARGET
    # This should be the ouput of `uname -m` when you run OpenWRT, e.g. arm
    SYSTEM_PROCESSOR mips
)
