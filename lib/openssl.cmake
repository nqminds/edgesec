if (BUILD_OPENSSL_LIB AND NOT (BUILD_ONLY_DOCS))
  add_compile_definitions(WITH_OPENSSL_SERVICE)

  include(ExternalProject)
  ExternalProject_Add(openssl_external
    URL https://github.com/openssl/openssl/archive/refs/tags/openssl-3.0.0-beta1.tar.gz
    CONFIGURE_COMMAND <SOURCE_DIR>/Configure --prefix=<INSTALL_DIR> --openssldir=<INSTALL_DIR> -lpthread no-dtls no-dtls1 no-psk no-srp no-ec2m no-weak-ssl-ciphers no-dso no-engine no-threads
    BUILD_IN_SOURCE true
  )
  ExternalProject_Get_Property(openssl_external install_dir)
  set(LIBOPENSSL_INSTALL_DIR "${install_dir}")
  set(LIBOPENSSL_INCLUDE_PATH "${LIBOPENSSL_INSTALL_DIR}/include")
  set(LIBOPENSSL_LIB_PATH "${LIBOPENSSL_INSTALL_DIR}/lib")
  add_library(LIBCRYPTO_LIB STATIC IMPORTED "${LIBOPENSSL_LIB_PATH}/libcrypto.a")

  message("LIBCRYPTO will be built at ${LIBCRYPTO_LIB}")
endif ()
