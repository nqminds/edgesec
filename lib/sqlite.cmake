# Compile libsqlite
cmake_minimum_required(VERSION 3.14.0) # FindSQLite3.cmake is only in 3.14.0 and later
include(CheckLibraryExists)
include(ExternalProject)

if(BUILD_ONLY_DOCS)
  # skip
elseif(NOT BUILD_SQLITE_LIB)
  find_package(SQLite3 MODULE REQUIRED)
  message("Found libsqlite library: ${SQLite3_LIBRARIES}")
else()
  # Download and Compile SQLite3 library at compile time using ExternalProject
  # (e.g. when running `cmake --build` or `make`)
  set(LIBSQLITE_INSTALL_ROOT "${CMAKE_CURRENT_BINARY_DIR}/lib")
  set(LIBSQLITE_INSTALL_DIR "${LIBSQLITE_INSTALL_ROOT}/sqlite")

  message("Downloading and compiling our own libsqlite library")
  ExternalProject_Add(
    libsqlite
    URL https://www.sqlite.org/2021/sqlite-autoconf-3360000.tar.gz
    URL_HASH SHA256=bd90c3eb96bee996206b83be7065c9ce19aef38c3f4fb53073ada0d0b69bbce3
    INSTALL_DIR "${LIBSQLITE_INSTALL_DIR}"
    CONFIGURE_COMMAND autoreconf -f -i <SOURCE_DIR>
    COMMAND
      ${CMAKE_COMMAND} -E env "PATH=$ENV{PATH}"
      <SOURCE_DIR>/configure --prefix=<INSTALL_DIR> "--host=${CMAKE_LIBRARY_ARCHITECTURE}"
      # use position independent code, even for static lib, in case we want to make shared lib later
      --with-pic=on
    # need to manually specify PATH, so that make knows where to find cross-compiling GCC
    BUILD_COMMAND ${CMAKE_COMMAND} -E env "PATH=$ENV{PATH}" $(MAKE)
    INSTALL_COMMAND ${CMAKE_COMMAND} -E env "PATH=$ENV{PATH}" $(MAKE) install
  )
  ExternalProject_Get_Property(libsqlite INSTALL_DIR)

  set(LIBSQLITE_INSTALL_DIR "${INSTALL_DIR}")
  if(BUILD_SHARED_LIBS)
    set(LIBSQLITE_LIB "${LIBSQLITE_INSTALL_DIR}/lib/libsqlite3.so")
    add_library(SQLite::SQLite3 SHARED IMPORTED)
  else()
    set(LIBSQLITE_LIB "${LIBSQLITE_INSTALL_DIR}/lib/libsqlite3.a")
    add_library(SQLite::SQLite3 STATIC IMPORTED)
  endif()

  set(sqlite_link_libs "pthread" "dl")

  # Some compilers don't have -lm since it's always linked by default
  CHECK_LIBRARY_EXISTS(m sin "" HAVE_LIB_M)
  if (HAVE_LIB_M)
    list(APPEND sqlite_link_libs "m")
  endif(HAVE_LIB_M)

  # folder might not yet exist if using ExternalProject_Add
  set(LIBSQLITE_INCLUDE_DIR "${LIBSQLITE_INSTALL_DIR}/include")
  file(MAKE_DIRECTORY "${LIBSQLITE_INCLUDE_DIR}")
  set(LIBSQLITE_LIB_DIR "${LIBSQLITE_INSTALL_DIR}/lib")

  set_target_properties(SQLite::SQLite3 PROPERTIES
      IMPORTED_LOCATION "${LIBSQLITE_LIB}"
      INTERFACE_LINK_LIBRARIES "${sqlite_link_libs}"
      INTERFACE_INCLUDE_DIRECTORIES "${LIBSQLITE_INCLUDE_DIR}"
  )

  # tell cmake that we can only use SQLite::SQLite3 after we compile it
  add_dependencies(SQLite::SQLite3 libsqlite)
endif ()
