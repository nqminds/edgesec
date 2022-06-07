cmake_minimum_required(VERSION 3.9.0)

set(CMAKE_SYSTEM_NAME               Linux) # OpenWRT
set(CMAKE_SYSTEM_PROCESSOR          arm)

# Without that flag CMake is not able to pass test compilation check
set(CMAKE_TRY_COMPILE_TARGET_TYPE   STATIC_LIBRARY)

# equivalent to $(TOPDIR) in OpenWRT Makefiles
# downloaded from https://downloads.openwrt.org/releases/19.07.10/targets/mvebu/cortexa9/
if(NOT DEFINED openwrt_toolchain_location)
    include(FetchContent)
    # this is an awful way of doing this, is there not a better way, e.g. using a toolchain from "apt install?"
    FetchContent_Declare(
        openwrt_sdk_mvebu_cortexa9
        URL https://downloads.openwrt.org/releases/19.07.10/targets/mvebu/cortexa9/openwrt-sdk-19.07.10-mvebu-cortexa9_gcc-7.5.0_musl_eabi.Linux-x86_64.tar.xz
        # sha256 from https://downloads.openwrt.org/releases/19.07.10/targets/mvebu/cortexa9/sha256sums
        URL_HASH SHA256=17941f42e26d3c54a836f9897e78abaafcf66e5f0b28ffd8956378aa69c3a4d9
        # Make sure that that the toolchain location is indepent from CMAKE_BINARY_DIR/CMAKE_SOURCE_DIR
        # otherwise `check_include_file()` commands will redownload these files slowly
        PREFIX "${CMAKE_CURRENT_LIST_DIR}/build/openwrt_sdk_mvebu_cortexa9"
    )
    FetchContent_Populate(openwrt_sdk_mvebu_cortexa9)
    set(
        openwrt_toolchain_location "${openwrt_sdk_mvebu_cortexa9_SOURCE_DIR}"
        CACHE PATH "Path to OpenWRT SDK"
    )
endif(NOT DEFINED openwrt_toolchain_location)

# Replace this if you download a newer version of the OpenWRT SDK
set(gnu_target_name arm-openwrt-linux-muslgnueabi)
set(openwrt_toolchain_dir_name toolchain-arm_cortex-a9+vfpv3-d16_gcc-7.5.0_musl_eabi)
set(openwrt_target_dir_name target-arm_cortex-a9+vfpv3-d16_musl_eabi)

set(tools ${openwrt_toolchain_location}/staging_dir/${openwrt_toolchain_dir_name})
set(CMAKE_SYSROOT ${openwrt_toolchain_location}/staging_dir/${openwrt_target_dir_name})
set(CMAKE_STAGING_PREFIX "${CMAKE_SYSROOT}")
set(ENV{STAGING_DIR} "${CMAKE_STAGING_PREFIX}")
# need to add staging prefix to path, as dependencies use autoconf ./configure to find compilers
set(ENV{PATH} "$ENV{PATH}:${tools}/bin")

set(CMAKE_LIBRARY_ARCHITECTURE "${gnu_target_name}")

set(CROSS_COMPILE_PREFIX ${tools}/bin/${gnu_target_name}-) # used by lib/openssl.cmake only

set(CMAKE_AR                        ${tools}/bin/${gnu_target_name}-ar${CMAKE_EXECUTABLE_SUFFIX})
set(CMAKE_ASM_COMPILER              ${tools}/bin/${gnu_target_name}-gcc${CMAKE_EXECUTABLE_SUFFIX})
set(CMAKE_C_COMPILER                ${tools}/bin/${gnu_target_name}-gcc${CMAKE_EXECUTABLE_SUFFIX})
set(CMAKE_CXX_COMPILER              ${tools}/bin/${gnu_target_name}-g++${CMAKE_EXECUTABLE_SUFFIX})
set(CMAKE_LINKER                    ${tools}/bin/${gnu_target_name}-ld${CMAKE_EXECUTABLE_SUFFIX})
set(CMAKE_OBJCOPY                   ${tools}/bin/${gnu_target_name}-objcopy${CMAKE_EXECUTABLE_SUFFIX} CACHE INTERNAL "")
set(CMAKE_RANLIB                    ${tools}/bin/${gnu_target_name}-ranlib${CMAKE_EXECUTABLE_SUFFIX} CACHE INTERNAL "")
set(CMAKE_SIZE                      ${tools}/bin/${gnu_target_name}-size${CMAKE_EXECUTABLE_SUFFIX} CACHE INTERNAL "")
set(CMAKE_STRIP                     ${tools}/bin/${gnu_target_name}-strip${CMAKE_EXECUTABLE_SUFFIX} CACHE INTERNAL "")

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
# we use custom find_library() commands, so we can't use ONLY
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY BOTH)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE BOTH)
