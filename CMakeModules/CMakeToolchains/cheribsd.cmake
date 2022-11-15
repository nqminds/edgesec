# Below replaced later with actual toolchaibn download and compile, which takes hours
set(cheribsd_toolchain_location "/home/alexandru/cheri/output/morello-sdk")
set(CheriBSD_SDK_TOOLCHAIN_DIR "bin")
set(CheriBSD_SDK_TARGET_DIR "sysroot-morello-purecap")

# make sure we skip downloading the toolchain again for sub-CMake processes
# Setting cheribsd_toolchain_location should work for all sub-CMake processes
set(ENV{cheribsd_toolchain_location} "${cheribsd_toolchain_location}")
# setting CMAKE_REQUIRED_DEFINITIONS should be better for `check_include_file()`
list(APPEND CMAKE_REQUIRED_DEFINITIONS "-Dcheribsd_toolchain_location=${cheribsd_toolchain_location}")
set(CMAKE_REQUIRED_DEFINITIONS "${CMAKE_REQUIRED_DEFINITIONS}" PARENT_SCOPE)


set(tools "${cheribsd_toolchain_location}/${CheriBSD_SDK_TOOLCHAIN_DIR}")
if (NOT IS_DIRECTORY "${tools}")
    message(FATAL_ERROR "CheriBSD SDK toolchain directory TOOLCHAIN_DIR=${CheriBSD_SDK_TOOLCHAIN_DIR} is not found in ${cheribsd_toolchain_location}")
endif()

set(target_dir "${cheribsd_toolchain_location}/${CheriBSD_SDK_TARGET_DIR}")
if (NOT IS_DIRECTORY "${target_dir}")
    message(FATAL_ERROR "CheriBSD SDK target directory TARGET_DIR=${CheriBSD_SDK_TARGET_DIR} is not found in ${cheribsd_toolchain_location}")
endif()

set(CMAKE_SYSROOT "${target_dir}" PARENT_SCOPE)
if (NOT DEFINED CMAKE_STAGING_PREFIX)
    # let ExternalProject override this
    set(CMAKE_STAGING_PREFIX "${target_dir}" PARENT_SCOPE)
endif()

#set(CMAKE_C_COMPILER clang)
#set(CMAKE_CXX_COMPILER clang++)
