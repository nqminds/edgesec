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

set(CMAKE_C_EXTENSIONS ON) # libnetlink uses a lot of GNU/Linux C extensions

# Set a default build type if none was specified
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  message(STATUS "Setting build type to 'Debug' as none was specified.")
  set(CMAKE_BUILD_TYPE Debug CACHE STRING "Choose the type of build." FORCE)
  # Set the possible values of build type for cmake-gui
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release"
    "MinSizeRel" "RelWithDebInfo")
endif()

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
