# Below replaced later with actual toolchaibn download and compile, which takes hours
set(cheribsd_toolchain_location "/home/alexandru/cheri/output/morello-sdk")
set(CheriBSD_SDK_TOOLCHAIN_DIR "bin")
set(CheriBSD_SDK_TARGET_DIR "sysroot-morello-purecap")
set(CheriBSD_SDK_GNU_TARGET "aarch64-unknown-freebsd")

# make sure we skip downloading the toolchain again for sub-CMake processes
# Setting cheribsd_toolchain_location should work for all sub-CMake processes
set(ENV{cheribsd_toolchain_location} "${cheribsd_toolchain_location}")
# setting CMAKE_REQUIRED_DEFINITIONS should be better for `check_include_file()`
list(APPEND CMAKE_REQUIRED_DEFINITIONS "-Dcheribsd_toolchain_location=${cheribsd_toolchain_location}")
set(CMAKE_REQUIRED_DEFINITIONS "${CMAKE_REQUIRED_DEFINITIONS}")


set(tools "${cheribsd_toolchain_location}/${CheriBSD_SDK_TOOLCHAIN_DIR}")
if (NOT IS_DIRECTORY "${tools}")
    message(FATAL_ERROR "CheriBSD SDK toolchain directory TOOLCHAIN_DIR=${CheriBSD_SDK_TOOLCHAIN_DIR} is not found in ${cheribsd_toolchain_location}")
endif()

set(target_dir "${cheribsd_toolchain_location}/${CheriBSD_SDK_TARGET_DIR}")
if (NOT IS_DIRECTORY "${target_dir}")
    message(FATAL_ERROR "CheriBSD SDK target directory TARGET_DIR=${CheriBSD_SDK_TARGET_DIR} is not found in ${cheribsd_toolchain_location}")
endif()

set(CMAKE_SYSROOT "${target_dir}")
if (NOT DEFINED CMAKE_STAGING_PREFIX)
    # let ExternalProject override this
    set(CMAKE_STAGING_PREFIX "${target_dir}")
endif()

set(ENV{STAGING_DIR} "${CMAKE_STAGING_PREFIX}")

# need to add toolchain prefix to path, as dependencies use autoconf ./configure to find compilers
set(ENV{PATH} "$ENV{PATH}:${tools}")

set(CMAKE_SYSTEM_NAME FreeBSD) # FreeBSD
set(CMAKE_LIBRARY_ARCHITECTURE "${CheriBSD_SDK_GNU_TARGET}")
set(CROSS_COMPILE_PREFIX "${tools}/${CheriBSD_SDK_GNU_TARGET}-") # used by lib/openssl.cmake only
#set(CMAKE_SYSTEM_PROCESSOR "${CheriBSD_SDK_SYSTEM_PROCESSOR}")

set(c_compiler "${tools}/${CheriBSD_SDK_GNU_TARGET}-cc${CMAKE_EXECUTABLE_SUFFIX}")
if(NOT EXISTS "${c_compiler}")
    message(FATAL_ERROR "C compiler ${c_compiler} does not exist. Please make sure that you have set GNU_TARGET to the GNU target prefix in ${tools}")
endif()

set(CMAKE_AR                        "${tools}/${CheriBSD_SDK_GNU_TARGET}-ar${CMAKE_EXECUTABLE_SUFFIX}")
set(CMAKE_ASM_COMPILER              "${tools}/${CheriBSD_SDK_GNU_TARGET}-cc${CMAKE_EXECUTABLE_SUFFIX}")
set(CMAKE_C_COMPILER                "${c_compiler}")
set(CMAKE_CXX_COMPILER              "${tools}/${CheriBSD_SDK_GNU_TARGET}-c++${CMAKE_EXECUTABLE_SUFFIX}")
set(CMAKE_LINKER                    "${tools}/${CheriBSD_SDK_GNU_TARGET}-ld${CMAKE_EXECUTABLE_SUFFIX}")
set(CMAKE_OBJCOPY                   "${tools}/${CheriBSD_SDK_GNU_TARGET}-objcopy${CMAKE_EXECUTABLE_SUFFIX}")
set(CMAKE_RANLIB                    "${tools}/${CheriBSD_SDK_GNU_TARGET}-ranlib${CMAKE_EXECUTABLE_SUFFIX}")
set(CMAKE_STRIP                     "${tools}/${CheriBSD_SDK_GNU_TARGET}-strip${CMAKE_EXECUTABLE_SUFFIX}")

# Without this flag CMake is not able to pass test compilation check
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM "NEVER")

# we use custom find_library() commands, so we can't use ONLY
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY "BOTH")
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE "BOTH")
