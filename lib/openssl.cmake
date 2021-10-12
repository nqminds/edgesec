if (BUILD_OPENSSL_LIB AND NOT (BUILD_ONLY_DOCS))
  add_compile_definitions(WITH_OPENSSL_SERVICE)
  set(LIBOPENSSL_INSTALL_ROOT "${CMAKE_CURRENT_BINARY_DIR}/lib")
  set(LIBOPENSSL_INSTALL_DIR "${LIBOPENSSL_INSTALL_ROOT}/openssl")
  set(LIBOPENSSL_INCLUDE_PATH ${LIBOPENSSL_INSTALL_DIR}/include)
  set(LIBOPENSSL_LIB_PATH ${LIBOPENSSL_INSTALL_DIR}/lib)
  find_library(LIBCRYPTO_LIB NAMES libcrypto.a PATHS "${LIBOPENSSL_LIB_PATH}" NO_DEFAULT_PATH)
  if (LIBCRYPTO_LIB)
    message("Found libcrypto library: ${LIBCRYPTO_LIB}")
  ELSE ()
    FetchContent_Declare(
      openssl_src
      URL https://github.com/openssl/openssl/archive/refs/tags/openssl-3.0.0-beta1.tar.gz
      URL_HASH SHA256=4ba637257737a3bcdf059ceb6db8424698afca89de7bed1c189853253097d0f2
    )
    FetchContent_Populate(openssl_src)

    if (CMAKE_CROSSCOMPILING)
      if (CMAKE_SYSTEM_NAME STREQUAL "Linux" AND CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
        set(openssl_config "linux-aarch64")
      else(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
        message(FATAL_ERROR "Could not figure out config for cross compiling openssl")
      endif (CMAKE_SYSTEM_NAME STREQUAL "Linux" AND CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
    endif (CMAKE_CROSSCOMPILING)

    execute_process(COMMAND bash ${CMAKE_SOURCE_DIR}/lib/compile_openssl.sh ${openssl_src_SOURCE_DIR} ${LIBOPENSSL_INSTALL_DIR} ${openssl_config})
    find_library(LIBCRYPTO_LIB NAMES libcrypto.a PATHS "${LIBOPENSSL_LIB_PATH}" NO_DEFAULT_PATH)
  endif ()
endif ()
