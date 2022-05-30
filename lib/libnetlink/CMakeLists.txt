# at least v3.13 is required for install(x) where x is from add_subdirectory()
cmake_minimum_required(VERSION 3.13)
project(LIBNETLINK)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../../CMakeModules")

if (NOT TARGET MNL::mnl)
    # declares MNL::mnl
    find_package(MNL REQUIRED)
endif()

# libmnl0 linking doesn't work properly, unless we setup RPATHs
SET(CMAKE_INSTALL_RPATH "$ORIGIN" "$<TARGET_LINKER_FILE_DIR:MNL::mnl>")

set(CMAKE_BUILD_TYPE Debug)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_GNU_SOURCE")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DHAVE_LIBMNL")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DHAVE_SETNS")
# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DHAVE_ELF -I/usr/include/libelf")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DNEED_STRLCPY")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DHAVE_LIBCAP")

set(SRC_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include")
set(UAPI_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include/uapi")

add_subdirectory(lib)
