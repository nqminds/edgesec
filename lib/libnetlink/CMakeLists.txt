project(LIBNETLINK)

# at least v3.13 is required for install(x) where x is from add_subdirectory()
cmake_minimum_required(VERSION 3.13)
SET(LIB_PATH "" CACHE STRING "lib path")
SET(C_COMPILER "" CACHE STRING "c compiler")
SET(CXX_COMPILER "" CACHE STRING "c++ compiler")

message("LIB_PATH=${LIB_PATH}")
message("C_COMPILER=${C_COMPILER}")
message("CXX_COMPILER=${CXX_COMPILER}")

set(LIBMNL_INCLUDE_DIR "${LIB_PATH}/include")
find_library(LIBMNL_LIB NAMES mnl PATHS "${LIB_PATH}/lib")
if (LIBMNL_LIB)
    message("Found libmnl library: ${LIBMNL_LIB}")
else ()
    message(FATAL_ERROR "Could not find libmnl library.")
endif ()

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

install(TARGETS libnetlink DESTINATION lib)
install(TARGETS ll_map DESTINATION lib)
install(TARGETS utils DESTINATION lib)
install(TARGETS rt_names DESTINATION lib)
install(TARGETS ll_types DESTINATION lib)
install(TARGETS ll_proto DESTINATION lib)
