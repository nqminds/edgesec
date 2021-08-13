if (BUILD_OPENSSL_LIB AND NOT (BUILD_ONLY_DOCS))
  add_compile_definitions(WITH_OPENSSL_SERVICE)
  set(LIBOPENSSL_INSTALL_DIR "${CMAKE_CURRENT_BINARY_DIR}/lib/openssl")
  set(LIBOPENSSL_INCLUDE_PATH ${LIBOPENSSL_INSTALL_DIR}/include)
  set(LIBOPENSSL_LIB_PATH ${LIBOPENSSL_INSTALL_DIR}/lib)
  find_library(LIBCRYPTO_LIB NAMES crypto PATHS "${LIBOPENSSL_LIB_PATH}" NO_DEFAULT_PATH)
  if (LIBCRYPTO_LIB)
    message("Found libcrypto library: ${LIBCRYPTO_LIB}")
  ELSE ()
      FetchContent_Declare(
        openssl
        GIT_REPOSITORY https://github.com/openssl/openssl
        GIT_TAG        openssl-3.0.0-beta1
      )

      set(FETCHCONTENT_QUIET OFF)
      FetchContent_MakeAvailable(openssl)
      FetchContent_GetProperties(openssl SOURCE_DIR OPENSSL_SOURCE_DIR)
      message("Source dir: ${OPENSSL_SOURCE_DIR}")
      execute_process(
        COMMAND ./Configure --prefix=${LIBOPENSSL_INSTALL_DIR} --openssldir=${LIBOPENSSL_INSTALL_DIR} no-dtls no-dtls1 no-psk no-srp no-ec2m no-weak-ssl-ciphers --host=${COMPILE_CONFIG_HOST}
        WORKING_DIRECTORY "${OPENSSL_SOURCE_DIR}"
      )
      execute_process(
        COMMAND make
        WORKING_DIRECTORY "${OPENSSL_SOURCE_DIR}"
      )
      execute_process(
        COMMAND make install
        WORKING_DIRECTORY "${OPENSSL_SOURCE_DIR}"
      )
      find_library(LIBCRYPTO_LIB NAMES crypto PATHS "${LIBOPENSSL_LIB_PATH}" NO_DEFAULT_PATH)
  endif ()
endif ()
