include("${CMAKE_CURRENT_LIST_DIR}/DefineOpenWRTSDKToolchain.cmake")

defineOpenwrtSDKToolchain(
    URL https://downloads.openwrt.org/releases/21.02.1/targets/bcm27xx/bcm2710/openwrt-sdk-21.02.1-bcm27xx-bcm2710_gcc-8.4.0_musl.Linux-x86_64.tar.xz
    # sha256 from https://downloads.openwrt.org/releases/21.02.1/targets/bcm27xx/bcm2710/sha256sums
    URL_HASH SHA256=de4cd5463db552b4eb8877daf90ae922833fd6ead598db58cc7ff4c71b229ef6
    TOOLCHAIN_DIR toolchain-aarch64_cortex-a53_gcc-8.4.0_musl
    TARGET_DIR target-aarch64_cortex-a53_musl
    GNU_TARGET aarch64-openwrt-linux-musl
    # normally this is the first word of $GNU_TARGET
    # This should be the ouput of `uname -m` when you run OpenWRT, e.g. arm
    SYSTEM_PROCESSOR aarch64
)
