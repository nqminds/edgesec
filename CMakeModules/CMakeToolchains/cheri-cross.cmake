# Below replaced later with actual toolchaibn download and compile, which takes hours
set(CheriBSD_output_location "/home/alexandru/cheri/output")
set(CheriBSD_toolchain_location "${CheriBSD_output_location}/morello-sdk")
set(CheriBSD_tools_location "${CheriBSD_toolchain_location}/bin")
set(CheriBSD_rootfs_location "${CheriBSD_output_location}/rootfs-morello-purecap")
set(CheriBSD_usr_location "${CheriBSD_rootfs_location}/usr")
set(CheriBSD_package_location "${CheriBSD_usr_location}/local/morello-purecap")
set(CheriBSD_pkgconfig_locations "${CheriBSD_usr_location}/libdata/pkgconfig")
set(CheriBSD_pkgconfig_locations "${CheriBSD_pkgconfig_locations}:${CheriBSD_usr_location}/local/morello-purecap/lib/pkgconfig")
set(CheriBSD_pkgconfig_locations "${CheriBSD_pkgconfig_locations}:${CheriBSD_usr_location}/local/morello-purecap/share/pkgconfig")
set(CheriBSD_pkgconfig_locations "${CheriBSD_pkgconfig_locations}:${CheriBSD_usr_location}/local/morello-purecap/libdata/pkgconfig")
set(CheriBSD_pkgconfig_locations "${CheriBSD_pkgconfig_locations}:${CheriBSD_usr_location}/local/lib/pkgconfig")
set(CheriBSD_pkgconfig_locations "${CheriBSD_pkgconfig_locations}:${CheriBSD_usr_location}/local/share/pkgconfig")
set(CheriBSD_pkgconfig_locations "${CheriBSD_pkgconfig_locations}:${CheriBSD_usr_location}/local/libdata/pkgconfig")

set(CheriBSD_SDK_GNU_TARGET "aarch64-unknown-freebsd")
set(CheriBSD_c_flags "-target ${CheriBSD_SDK_GNU_TARGET} --sysroot=${CheriBSD_rootfs_location} -B${CheriBSD_tools_location} -mcpu=rainier -march=morello+c64 -mabi=purecap -Xclang -morello-vararg=new")
set(CheriBSD_cxx_flags "-target ${CheriBSD_SDK_GNU_TARGET} --sysroot=${CheriBSD_rootfs_location} -B${CheriBSD_tools_location} -mcpu=rainier -march=morello+c64 -mabi=purecap -Xclang -morello-vararg=new")

if (NOT IS_DIRECTORY "${CheriBSD_tools_location}")
    message(FATAL_ERROR "CheriBSD SDK toolchain directory TOOLCHAIN_DIR=${CheriBSD_tools_location} is not found")
endif()

set(ENV{STAGING_DIR} "${CMAKE_STAGING_PREFIX}")

# need to add toolchain prefix to path, as dependencies use autoconf ./configure to find compilers
set(ENV{PATH} "$ENV{PATH}:${CheriBSD_tools_location}")

# setting CMAKE_REQUIRED_DEFINITIONS should be better for `check_include_file()`
list(APPEND CMAKE_REQUIRED_DEFINITIONS "-Dcheribsd_toolchain_location=${cheribsd_toolchain_location}")
set(CMAKE_REQUIRED_DEFINITIONS "${CMAKE_REQUIRED_DEFINITIONS}")

set(CMAKE_SYSROOT "${CheriBSD_rootfs_location}")

# where is the target environment
set(CMAKE_FIND_ROOT_PATH "${CheriBSD_rootfs_location}")

set(CMAKE_SYSTEM_NAME FreeBSD) # FreeBSD
set(CMAKE_LIBRARY_ARCHITECTURE "${CheriBSD_SDK_GNU_TARGET}")
set(CROSS_COMPILE_PREFIX "${CheriBSD_tools_location}/${CheriBSD_SDK_GNU_TARGET}-") # used by lib/openssl.cmake only
#set(CMAKE_SYSTEM_PROCESSOR "${CheriBSD_SDK_SYSTEM_PROCESSOR}")

set(c_compiler "${CheriBSD_tools_location}/${CheriBSD_SDK_GNU_TARGET}-cc${CMAKE_EXECUTABLE_SUFFIX}")
if(NOT EXISTS "${c_compiler}")
    message(FATAL_ERROR "C compiler ${c_compiler} does not exist. Please make sure that you have set GNU_TARGET to the GNU target prefix in ${CheriBSD_tools_location}")
endif()

set(CMAKE_AR                        "${CheriBSD_tools_location}/${CheriBSD_SDK_GNU_TARGET}-ar${CMAKE_EXECUTABLE_SUFFIX}")
set(CMAKE_ASM_COMPILER              "${CheriBSD_tools_location}/${CheriBSD_SDK_GNU_TARGET}-cc${CMAKE_EXECUTABLE_SUFFIX}")
set(CMAKE_C_COMPILER                "${c_compiler}")
set(CMAKE_CXX_COMPILER              "${CheriBSD_tools_location}/${CheriBSD_SDK_GNU_TARGET}-c++${CMAKE_EXECUTABLE_SUFFIX}")
set(CMAKE_LINKER                    "${CheriBSD_tools_location}/${CheriBSD_SDK_GNU_TARGET}-ld${CMAKE_EXECUTABLE_SUFFIX}")
set(CMAKE_OBJCOPY                   "${CheriBSD_tools_location}/${CheriBSD_SDK_GNU_TARGET}-objcopy${CMAKE_EXECUTABLE_SUFFIX}")
set(CMAKE_RANLIB                    "${CheriBSD_tools_location}/${CheriBSD_SDK_GNU_TARGET}-ranlib${CMAKE_EXECUTABLE_SUFFIX}")
set(CMAKE_STRIP                     "${CheriBSD_tools_location}/${CheriBSD_SDK_GNU_TARGET}-strip${CMAKE_EXECUTABLE_SUFFIX}")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${CheriBSD_c_flags}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CheriBSD_cxx_flags}")

# Without this flag CMake is not able to pass test compilation check
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

set(PKG_CONFIG_USE_CMAKE_PREFIX_PATH FALSE)

# PKG_CONFIG_LIBDIR overrides PKG_CONFIG_PATH
set(PKG_CONFIG_LIBDIR "${CheriBSD_pkgconfig_locations}")
set(ENV{PKG_CONFIG_LIBDIR} "${CheriBSD_pkgconfig_locations}")
set(PKG_CONFIG_SYSROOT_DIR ${CheriBSD_rootfs_location})
set(ENV{PKG_CONFIG_SYSROOT_DIR} ${CheriBSD_rootfs_location})
set(PKG_CONFIG_PATH "")
set(ENV{PKG_CONFIG_PATH} "")

# Use -pthread flag https://gitlab.kitware.com/cmake/cmake/issues/16920
set(THREADS_HAVE_PTHREAD_ARG TRUE)

# Ensure we search in the custom install prefix that we install everything to:
set(CMAKE_PREFIX_PATH "${CheriBSD_package_location};${CMAKE_PREFIX_PATH}")


# Standard propgrams like flex, etc
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)

# for libraries and headers in the target directories
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# Debug mode
# set(CMAKE_FIND_DEBUG_MODE TRUE)