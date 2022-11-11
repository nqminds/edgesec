#[=======================================================================[.rst:
DefineOpenWRTSDKToolchain
-------

Used to initialise a CMake Toolchain from an OpenWRT SDK

The general signature is
.. code-block:: cmake
   # call the following from your CMake Toolchain file
   include(DefineOpenWRTSDKToolchain)

   defineOpenwrtSDKToolchain(
        URL <https://downloads.openwrt.org/releases...0_musl_eabi.Linux-x86_64.tar.xz>
        URL_HASH <SHA256=...>
        # find this by opening up the ./staging_dir/ in your OpenWRT SDK
        TOOLCHAIN_DIR <toolchain-arm_cortex-..._musl_eabi>
        # find this by opening up the ./staging_dir/ in your OpenWRT SDK
        TARGET_DIR <target-arm_cortex-..._musl_eabi>
        # find this by opening up the ./${TOOLCHAIN_DIR}/bin/ in your OpenWRT SDK
        GNU_TARGET <arm-openwrt-linux-muslgnueabi>
        # normally this is the first word of $GNU_TARGET
        # This should be the ouput of `uname -m` when you run OpenWRT, e.g. arm
        SYSTEM_PROCESSOR <CPU_NAME>
   )

If the ``openwrt_toolchain_location`` cache variable or ``ENV{openwrt_toolchain_location}``
environment variable points to an already downloaded OpenWRT SDK location,
the download of the OpenWRT SDK is skipped. This is used to avoid re-downloading
the ``openwrt_toolchain_location`` in sub-processes.

If using `ExternalProject_Add()`, and are passing over a toolchain file,
please also pass ``CMAKE_CACHE_ARGS -Dopenwrt_toolchain_location:STRING=${openwrt_toolchain_location}``,
to avoid redownloading the OpenWRT SDK.

#]=======================================================================]
cmake_minimum_required(VERSION 3.9.0)
cmake_policy(VERSION 3.9.0...3.24.0)

function(defineOpenwrtSDKToolchain)
    set(
        openwrt_toolchain_location
        # this toolchain file is passed to sub-CMake processes.
        # to prevent redownloading the OpenWRT SDK, try to load the toolchain
        # location from an environment variable
        "$ENV{openwrt_toolchain_location}"
        CACHE PATH
        "Path to OpenWRT SDK. If this is empty, CMake will automatically download it."
    )

    set(oneValueArgs
        URL URL_HASH TOOLCHAIN_DIR TARGET_DIR GNU_TARGET SYSTEM_PROCESSOR
    )
    cmake_parse_arguments(
        PARSE_ARGV 0 OpenWRT_SDK "" "${oneValueArgs}" ""
    )

    if (NOT DEFINED OpenWRT_SDK_URL)
        message(FATAL_ERROR "OpenWRT SDK URL is not defined")
    elseif(NOT DEFINED OpenWRT_SDK_URL_HASH)
        message(FATAL_ERROR "OpenWRT SDK URL_HASH is not defined")
    elseif(NOT DEFINED OpenWRT_SDK_SYSTEM_PROCESSOR)
        message(FATAL_ERROR "OpenWRT SDK SYSTEM_PROCESSOR is not defined")
    endif()

    # equivalent to $(TOPDIR) in OpenWRT Makefiles
    # downloaded from https://downloads.openwrt.org/releases/19.07.10/targets/mvebu/cortexa9/
    if(openwrt_toolchain_location STREQUAL "" OR NOT IS_DIRECTORY "${openwrt_toolchain_location}")
        include(FetchContent)
        FetchContent_Declare(
            openwrt_sdk_download
            URL "${OpenWRT_SDK_URL}"
            URL_HASH "${OpenWRT_SDK_URL_HASH}"
            DOWNLOAD_DIR "${EP_DOWNLOAD_DIR}" # if empty string, uses default download dir
        )
        FetchContent_Populate(openwrt_sdk_download)
        set(
            openwrt_toolchain_location "${openwrt_sdk_download_SOURCE_DIR}"
            CACHE PATH "Path to OpenWRT SDK. If this is empty, CMake will automatically download it." FORCE
        )
    endif()


    # make sure we skip downloading the toolchain again for sub-CMake processes
    # Setting openwrt_toolchain_location should work for all sub-CMake processes
    set(ENV{openwrt_toolchain_location} "${openwrt_toolchain_location}")
    # setting CMAKE_REQUIRED_DEFINITIONS should be better for `check_include_file()`
    list(APPEND CMAKE_REQUIRED_DEFINITIONS "-Dopenwrt_toolchain_location=${openwrt_toolchain_location}")
    set(CMAKE_REQUIRED_DEFINITIONS "${CMAKE_REQUIRED_DEFINITIONS}" PARENT_SCOPE)

    set(tools "${openwrt_toolchain_location}/staging_dir/${OpenWRT_SDK_TOOLCHAIN_DIR}")
    if (NOT IS_DIRECTORY "${tools}")
        message(FATAL_ERROR "OpenWRT SDK toolchain directory TOOLCHAIN_DIR=${OpenWRT_SDK_TOOLCHAIN_DIR} is not found in ${openwrt_toolchain_location}/staging_dir")
    endif()

    set(target_dir "${openwrt_toolchain_location}/staging_dir/${OpenWRT_SDK_TARGET_DIR}")
    if (NOT IS_DIRECTORY "${target_dir}")
        message(FATAL_ERROR "OpenWRT SDK target directory TARGET_DIR=${OpenWRT_SDK_TARGET_DIR} is not found in ${openwrt_toolchain_location}/staging_dir")
    endif()

    set(CMAKE_SYSROOT "${target_dir}" PARENT_SCOPE)
    if (NOT DEFINED CMAKE_STAGING_PREFIX)
        # let ExternalProject override this
        set(CMAKE_STAGING_PREFIX "${target_dir}" PARENT_SCOPE)
    endif()
    set(ENV{STAGING_DIR} "${CMAKE_STAGING_PREFIX}")
    # need to add toolchain prefix to path, as dependencies use autoconf ./configure to find compilers
    set(ENV{PATH} "$ENV{PATH}:${tools}/bin")

    set(CMAKE_SYSTEM_NAME Linux PARENT_SCOPE) # OpenWRT
    set(CMAKE_LIBRARY_ARCHITECTURE "${OpenWRT_SDK_GNU_TARGET}" PARENT_SCOPE)
    set(CROSS_COMPILE_PREFIX "${tools}/bin/${OpenWRT_SDK_GNU_TARGET}-" PARENT_SCOPE) # used by lib/openssl.cmake only
    set(CMAKE_SYSTEM_PROCESSOR "${OpenWRT_SDK_SYSTEM_PROCESSOR}" PARENT_SCOPE)

    set(c_compiler "${tools}/bin/${OpenWRT_SDK_GNU_TARGET}-gcc${CMAKE_EXECUTABLE_SUFFIX}")
    if(NOT EXISTS "${c_compiler}")
        message(FATAL_ERROR "C compiler ${c_compiler} does not exist. Please make sure that you have set GNU_TARGET to the GNU target prefix in ${tools}/bin/")
    endif()

    set(CMAKE_AR                        "${tools}/bin/${OpenWRT_SDK_GNU_TARGET}-ar${CMAKE_EXECUTABLE_SUFFIX}" PARENT_SCOPE)
    set(CMAKE_ASM_COMPILER              "${tools}/bin/${OpenWRT_SDK_GNU_TARGET}-gcc${CMAKE_EXECUTABLE_SUFFIX}" PARENT_SCOPE)
    set(CMAKE_C_COMPILER                "${c_compiler}" PARENT_SCOPE)
    set(CMAKE_CXX_COMPILER              "${tools}/bin/${OpenWRT_SDK_GNU_TARGET}-g++${CMAKE_EXECUTABLE_SUFFIX}" PARENT_SCOPE)
    set(CMAKE_LINKER                    "${tools}/bin/${OpenWRT_SDK_GNU_TARGET}-ld${CMAKE_EXECUTABLE_SUFFIX}" PARENT_SCOPE)
    set(CMAKE_OBJCOPY                   "${tools}/bin/${OpenWRT_SDK_GNU_TARGET}-objcopy${CMAKE_EXECUTABLE_SUFFIX}" PARENT_SCOPE)
    set(CMAKE_RANLIB                    "${tools}/bin/${OpenWRT_SDK_GNU_TARGET}-ranlib${CMAKE_EXECUTABLE_SUFFIX}" PARENT_SCOPE)
    set(CMAKE_SIZE                      "${tools}/bin/${OpenWRT_SDK_GNU_TARGET}-size${CMAKE_EXECUTABLE_SUFFIX}" PARENT_SCOPE)
    set(CMAKE_STRIP                     "${tools}/bin/${OpenWRT_SDK_GNU_TARGET}-strip${CMAKE_EXECUTABLE_SUFFIX}" PARENT_SCOPE)

    # Without this flag CMake is not able to pass test compilation check
    set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY PARENT_SCOPE)

    set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM "NEVER" PARENT_SCOPE)
    # we use custom find_library() commands, so we can't use ONLY
    set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY "BOTH" PARENT_SCOPE)
    set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE "BOTH" PARENT_SCOPE)
endfunction()
