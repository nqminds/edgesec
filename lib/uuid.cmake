# Compile libuuid-1.0.3
if (BUILD_UUID_LIB AND NOT (BUILD_ONLY_DOCS))

  set(LIBUUID_INSTALL_ROOT "${CMAKE_CURRENT_BINARY_DIR}/lib")
  set(LIBUUID_INSTALL_DIR "${LIBUUID_INSTALL_ROOT}/uuid")
  set(LIBUUID_INCLUDE_DIR "${LIBUUID_INSTALL_DIR}/include")
  set(LIBUUID_LIB_DIR "${LIBUUID_INSTALL_DIR}/lib")

  find_library(LIBUUID_LIB NAMES uuid libuuid PATHS "${LIBUUID_LIB_DIR}" NO_DEFAULT_PATH)
  if (LIBUUID_LIB)
    message("Found libuuid library: ${LIBUUID_LIB}")
  ELSE ()
    FetchContent_Declare(
      util_linux
      URL https://github.com/karelzak/util-linux/archive/refs/tags/v2.37.2.tar.gz
      URL_HASH SHA3_256=d45c2b0ef0cca67ef9cbac1099503564d559fa1c52c0335dfd119546624b6bd0
    )

    FetchContent_Populate(util_linux)
    execute_process(COMMAND bash ${CMAKE_SOURCE_DIR}/lib/compile_uuid.sh ${util_linux_SOURCE_DIR} ${LIBUUID_INSTALL_ROOT})
    find_library(LIBUUID_LIB NAMES uuid libuuid PATHS "${LIBUUID_LIB_DIR}" NO_DEFAULT_PATH)
  endif ()
endif ()
