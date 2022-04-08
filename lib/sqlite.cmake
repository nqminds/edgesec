# Compile libsqlite
include(CheckLibraryExists)

if (BUILD_SQLITE_LIB AND NOT (BUILD_ONLY_DOCS))
  set(LIBSQLITE_INSTALL_ROOT "${CMAKE_CURRENT_BINARY_DIR}/lib")
  set(LIBSQLITE_INSTALL_DIR "${LIBSQLITE_INSTALL_ROOT}/sqlite")
  set(LIBSQLITE_INCLUDE_DIR "${LIBSQLITE_INSTALL_DIR}/include")
  set(LIBSQLITE_LIB_DIR "${LIBSQLITE_INSTALL_DIR}/lib")

  find_library(LIBSQLITE_LIB NAMES libsqlite3.a sqlite3 PATHS "${LIBSQLITE_LIB_DIR}" NO_DEFAULT_PATH)
  if (LIBSQLITE_LIB)
    message("Found libsqlite library: ${LIBSQLITE_LIB}")
  ELSE ()
    FetchContent_Declare(
      libsqlite
      URL https://www.sqlite.org/2021/sqlite-autoconf-3360000.tar.gz
      URL_HASH SHA256=bd90c3eb96bee996206b83be7065c9ce19aef38c3f4fb53073ada0d0b69bbce3
    )
    FetchContent_Populate(libsqlite)

    execute_process(COMMAND
      bash ${CMAKE_SOURCE_DIR}/lib/compile_sqlite.sh
      ${libsqlite_SOURCE_DIR}
      ${LIBSQLITE_INSTALL_ROOT}
      ${target_autoconf_triple}
    )
    find_library(LIBSQLITE_LIB NAMES libsqlite3.a sqlite3 PATHS "${LIBSQLITE_LIB_DIR}" NO_DEFAULT_PATH)
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


    set_target_properties(SQLite::sqlite PROPERTIES
        IMPORTED_LOCATION "${LIBSQLITE_LIB}"
        INTERFACE_LINK_LIBRARIES "${sqlite_link_libs}"
        INTERFACE_INCLUDE_DIRECTORIES "${LIBSQLITE_INCLUDE_DIR}"
    )
  endif(NOT TARGET SQLite::sqlite)
endif ()
