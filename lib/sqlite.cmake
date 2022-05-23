# Compile libsqlite
include(CheckLibraryExists)
include(ExternalProject)

if (BUILD_SQLITE_LIB AND NOT (BUILD_ONLY_DOCS))
  set(LIBSQLITE_INSTALL_ROOT "${CMAKE_CURRENT_BINARY_DIR}/lib")
  set(LIBSQLITE_INSTALL_DIR "${LIBSQLITE_INSTALL_ROOT}/sqlite")
  set(LIBSQLITE_LIB_DIR "${LIBSQLITE_INSTALL_DIR}/lib")

  find_library(LIBSQLITE_LIB NAMES libsqlite3.a sqlite3 PATHS NO_DEFAULT_PATH)
  if (LIBSQLITE_LIB)
    message("Found libsqlite library: ${LIBSQLITE_LIB}")
  ELSE ()
    message("Compiling own libsqlite library")
    ExternalProject_Add(
      libsqlite
      URL https://www.sqlite.org/2021/sqlite-autoconf-3360000.tar.gz
      URL_HASH SHA256=bd90c3eb96bee996206b83be7065c9ce19aef38c3f4fb53073ada0d0b69bbce3
      INSTALL_DIR "${LIBSQLITE_INSTALL_DIR}"
      CONFIGURE_COMMAND autoreconf -f -i <SOURCE_DIR>
      COMMAND
        <SOURCE_DIR>/configure --prefix=<INSTALL_DIR> "--host=${target_autoconf_triple}"
        # use position independent code, even for static lib, in case we want to make shared lib later
        --with-pic=on
      # cmake defaults to using `make` for the build command, when we have a custom configure_command
      # BUILD_COMMAND
    )
    ExternalProject_Get_Property(libsqlite INSTALL_DIR)

    set(LIBSQLITE_INSTALL_DIR "${INSTALL_DIR}")
    if(BUILD_SHARED_LIBS)
      set(LIBSQLITE_LIB "${LIBSQLITE_INSTALL_DIR}/lib/libsqlite3.so")
    else()
      set(LIBSQLITE_LIB "${LIBSQLITE_INSTALL_DIR}/lib/libsqlite3.a")
    endif()
  endif ()

  # static sqlite needs -lpthread -ldl -lm
  if (NOT TARGET SQLite::sqlite)
    add_library(SQLite::sqlite UNKNOWN IMPORTED)

    set(sqlite_link_libs "pthread" "dl")

    # Some compilers don't have -lm since it's always linked by default
    CHECK_LIBRARY_EXISTS(m sin "" HAVE_LIB_M)
    if (HAVE_LIB_M)
      list(APPEND sqlite_link_libs "m")
    endif(HAVE_LIB_M)

    # folder might not yet exist if using ExternalProject_Add
    set(LIBSQLITE_INCLUDE_DIR "${LIBSQLITE_INSTALL_DIR}/include")
    file(MAKE_DIRECTORY "${LIBSQLITE_INCLUDE_DIR}")

    set_target_properties(SQLite::sqlite PROPERTIES
        IMPORTED_LOCATION "${LIBSQLITE_LIB}"
        INTERFACE_LINK_LIBRARIES "${sqlite_link_libs}"
        INTERFACE_INCLUDE_DIRECTORIES "${LIBSQLITE_INCLUDE_DIR}"
    )

    if(TARGET libsqlite)
      # tell cmake that we can only use SQLite::sqlite after we compile it
      add_dependencies(SQLite::sqlite libsqlite)
    endif()
  endif(NOT TARGET SQLite::sqlite)
endif ()
