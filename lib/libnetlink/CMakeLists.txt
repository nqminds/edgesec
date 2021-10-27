project(LIBNETLINK)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../../CMakeModules")

# at least v3.13 is required for install(x) where x is from add_subdirectory()
cmake_minimum_required(VERSION 3.13)
SET(LIBMNL_INSTALL_ROOT "" CACHE STRING "lib path")
SET(C_COMPILER "" CACHE STRING "c compiler")
SET(CXX_COMPILER "" CACHE STRING "c++ compiler")

message("LIBMNL_INSTALL_ROOT=${LIBMNL_INSTALL_ROOT}")
message("C_COMPILER=${C_COMPILER}")
message("CXX_COMPILER=${CXX_COMPILER}")

list(APPEND CMAKE_PREFIX_PATH ${LIBMNL_INSTALL_ROOT})
find_package(MNL REQUIRED)

# libmnl0 linking doesn't work properly, unless we setup RPATHs
SET(CMAKE_INSTALL_RPATH "$ORIGIN" "$<TARGET_LINKER_FILE_DIR:MNL::mnl>")
find_package(MNL REQUIRED)

set(CMAKE_BUILD_TYPE Debug)

if (C_COMPILER)
    set(CMAKE_C_COMPILER ${C_COMPILER})
endif ()

if (CXX_COMPILER)
    set(CMAKE_CXX_COMPILER ${CXX_COMPILER})
endif ()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_GNU_SOURCE")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DHAVE_LIBMNL")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DHAVE_SETNS")
# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DHAVE_ELF -I/usr/include/libelf")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DNEED_STRLCPY")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DHAVE_LIBCAP")

set(SRC_INCLUDE_DIR "${CMAKE_HOME_DIRECTORY}/include")
set(UAPI_INCLUDE_DIR "${CMAKE_HOME_DIRECTORY}/include/uapi")

add_subdirectory(lib)

install(TARGETS
    libnetlink utils ll_map rt_names color json_print json_writer
    LIBRARY PUBLIC_HEADER
)
