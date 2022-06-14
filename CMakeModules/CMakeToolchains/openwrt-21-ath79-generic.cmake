include("${CMAKE_CURRENT_LIST_DIR}/DefineOpenWRTSDKToolchain.cmake")

defineOpenwrtSDKToolchain(
    URL https://downloads.openwrt.org/releases/21.02.3/targets/ath79/generic/openwrt-sdk-21.02.3-ath79-generic_gcc-8.4.0_musl.Linux-x86_64.tar.xz
    # sha256 from https://downloads.openwrt.org/releases/21.02.3/targets/ath79/generic/sha256sums
    URL_HASH SHA256=86fb6faa206e56c553538f438d16fe75476cc60c3b82413046a20a416479d8c6
    TOOLCHAIN_DIR toolchain-mips_24kc_gcc-8.4.0_musl
    TARGET_DIR target-mips_24kc_musl
    GNU_TARGET mips-openwrt-linux-musl
    # normally this is the first word of $GNU_TARGET
    # This should be the ouput of `uname -m` when you run OpenWRT, e.g. arm
    SYSTEM_PROCESSOR mips
)
