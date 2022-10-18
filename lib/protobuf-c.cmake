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

  if(BUILD_SHARED_LIBS)
    set(configure_args "--enable-shared" "--disable-static" "--disable-protoc")
  else()
    set(configure_args "--enable-static" "--disable-shared" "--disable-protoc")
  endif()

  message("Downloading and compiling our own libprotobuf-c library")
  ExternalProject_Add(
    libprotobuf-c
    URL https://github.com/protobuf-c/protobuf-c/releases/download/v1.4.1/protobuf-c-1.4.1.tar.gz
    INSTALL_DIR "${LIBPROTOBUFC_INSTALL_DIR}"
    CONFIGURE_COMMAND
        ${CMAKE_COMMAND} -E env "PATH=$ENV{PATH}"
        <SOURCE_DIR>/configure --prefix=<INSTALL_DIR> --with-pic=on ${configure_args}
        "CC=${CMAKE_C_COMPILER}" "CXX=${CMAKE_CXX_COMPILER}"
    BUILD_COMMAND
        ${CMAKE_COMMAND} -E env "PATH=$ENV{PATH}"
        $(MAKE)
    INSTALL_COMMAND
        ${CMAKE_COMMAND} -E env "PATH=$ENV{PATH}"
        $(MAKE) install
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
