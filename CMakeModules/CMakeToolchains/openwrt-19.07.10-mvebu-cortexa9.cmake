include("${CMAKE_CURRENT_LIST_DIR}/DefineOpenWRTSDKToolchain.cmake")

defineOpenwrtSDKToolchain(
    URL https://downloads.openwrt.org/releases/19.07.10/targets/mvebu/cortexa9/openwrt-sdk-19.07.10-mvebu-cortexa9_gcc-7.5.0_musl_eabi.Linux-x86_64.tar.xz
    # sha256 from https://downloads.openwrt.org/releases/19.07.10/targets/mvebu/cortexa9/sha256sums
    URL_HASH SHA256=17941f42e26d3c54a836f9897e78abaafcf66e5f0b28ffd8956378aa69c3a4d9
    TOOLCHAIN_DIR toolchain-arm_cortex-a9+vfpv3-d16_gcc-7.5.0_musl_eabi
    TARGET_DIR target-arm_cortex-a9+vfpv3-d16_musl_eabi
    GNU_TARGET arm-openwrt-linux-muslgnueabi
    # normally this is the first word of $GNU_TARGET
    # This should be the ouput of `uname -m` when you run OpenWRT, e.g. arm
    SYSTEM_PROCESSOR arm
)
