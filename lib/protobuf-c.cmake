# Compile protobuf-c
include(CheckLibraryExists)
include(ExternalProject)

if(BUILD_ONLY_DOCS)
  # skip
elseif(NOT BUILD_PROTOBUFC_LIB)
  find_package(protobuf-c MODULE REQUIRED)
  message("Found protobuf-c library: ${protobuf-c_LIBRARIES}")
else()
  # Download and Compile protobuf-c library at compile time using ExternalProject
  # (e.g. when running `cmake --build` or `make`)
  set(LIBPROTOBUFC_INSTALL_ROOT "${CMAKE_CURRENT_BINARY_DIR}/lib")
  set(LIBPROTOBUFC_INSTALL_DIR "${LIBPROTOBUFC_INSTALL_ROOT}/protobuf-c")

  set(CMAKE_CROSSCOMPILING_ARGS "")
  if(DEFINED CMAKE_TOOLCHAIN_FILE)
    list(APPEND CMAKE_CROSSCOMPILING_ARGS "-DCMAKE_TOOLCHAIN_FILE:STRING=${CMAKE_TOOLCHAIN_FILE}")
    if(DEFINED openwrt_toolchain_location)
      list(APPEND CMAKE_CROSSCOMPILING_ARGS "-Dopenwrt_toolchain_location:STRING=${openwrt_toolchain_location}")
    endif()
    if(DEFINED CMAKE_STAGING_PREFIX)
      list(APPEND CMAKE_CROSSCOMPILING_ARGS "-DCMAKE_STAGING_PREFIX:STRING=<INSTALL_DIR>")
    endif()
  endif()

  message("Downloading and compiling our own libprotobuf-c library")
  ExternalProject_Add(
    libprotobuf-c
    URL https://github.com/protobuf-c/protobuf-c/releases/download/v1.4.1/protobuf-c-1.4.1.tar.gz
    URL_HASH SHA256=4cc4facd508172f3e0a4d3a8736225d472418aee35b4ad053384b137b220339f
    INSTALL_DIR "${LIBPROTOBUFC_INSTALL_DIR}"
    SOURCE_SUBDIR ./build-cmake
    CMAKE_ARGS
      "-DCMAKE_INSTALL_PREFIX:STRING=<INSTALL_DIR>"
      "-DBUILD_PROTOC:BOOL=OFF"
      "-DBUILD_SHARED_LIBS:BOOL=${BUILD_SHARED_LIBS}"
      ${CMAKE_CROSSCOMPILING_ARGS}
  )
  ExternalProject_Get_Property(libprotobuf-c INSTALL_DIR)

  set(LIBPROTOBUFC_INSTALL_DIR "${INSTALL_DIR}")
  if(BUILD_SHARED_LIBS)
    set(LIBPROTOBUFC_LIB "${LIBPROTOBUFC_INSTALL_DIR}/lib/libprotobuf-c.so")
    add_library(protobufc::protobufc SHARED IMPORTED)
  else()
    set(LIBPROTOBUFC_LIB "${LIBPROTOBUFC_INSTALL_DIR}/lib/libprotobuf-c.a")
    add_library(protobufc::protobufc STATIC IMPORTED)
  endif()

  # folder might not yet exist if using ExternalProject_Add
  set(LIBPROTOBUFC_INCLUDE_DIR "${LIBPROTOBUFC_INSTALL_DIR}/include")
  file(MAKE_DIRECTORY "${LIBPROTOBUFC_INCLUDE_DIR}")
  set(LIBPROTOBUFC_LIB_DIR "${LIBPROTOBUFC_INSTALL_DIR}/lib")

  set_target_properties(protobufc::protobufc PROPERTIES
    IMPORTED_LOCATION "${LIBPROTOBUFC_LIB}"
    INTERFACE_INCLUDE_DIRECTORIES "${LIBPROTOBUFC_INCLUDE_DIR}"
  )

  # tell cmake that we can only use protobufc::protobufc after we compile it
  add_dependencies(protobufc::protobufc libprotobuf-c)
endif ()
