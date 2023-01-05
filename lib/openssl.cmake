include(FetchContent)

if (BUILD_OPENSSL_LIB AND NOT BUILD_ONLY_DOCS)
  if (CMAKE_CROSSCOMPILING)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
      if(CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
        set(openssl_config "linux-aarch64")
      elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "arm")
        # arm is such a massive spectrum of variants that it's not worth
        # trying to guess which one we're on.
        # just use generic 32-bit linux
        set(openssl_config "linux-generic32")
      elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
        set(openssl_config "linux-x86_64")
      endif()
    endif()

    if(NOT DEFINED openssl_config)
      message(FATAL_ERROR
        "Could not figure out config for cross compiling openssl. "
        "Please set openssl_config manually, by following the instructions in: "
        "https://github.com/openssl/openssl/blob/OpenSSL_1_1_1s/INSTALL"
      )
    endif ()

    list(APPEND OpenSSL_Configure_Args
      "${openssl_config}"
      "--cross-compile-prefix=${CROSS_COMPILE_PREFIX}"
    )
  endif (CMAKE_CROSSCOMPILING)

  list(APPEND OpenSSL_Configure_Args
    # install directory on the build system
    --prefix=<INSTALL_DIR>
    # install directory on the host/target system
    --openssldir=<INSTALL_DIR>
    # Set --libdir=lib, since otherwise sometimes OpenSSL installs in /lib64
    --libdir=lib
    -lpthread
    no-dtls no-dtls1 no-psk no-srp no-ec2m no-weak-ssl-ciphers
    no-dso no-engine no-threads no-unit-test
  )

  if ("${CMAKE_GENERATOR}" MATCHES "Makefiles")
    set(MAKE_COMMAND "$(MAKE)") # recursive make (uses the same make as the main project)
  else()
    # just run make in a subprocess. Will be very slow, since it's single-process.
    set(MAKE_COMMAND "make")
  endif ()

  set(LIBOPENSSL_INSTALL_ROOT "${CMAKE_CURRENT_BINARY_DIR}/lib")
  set(LIBOPENSSL_INSTALL_DIR "${LIBOPENSSL_INSTALL_ROOT}/openssl")
  ExternalProject_Add(
    openssl_src
    URL https://www.openssl.org/source/openssl-1.1.1s.tar.gz
    URL_HASH SHA256=c5ac01e760ee6ff0dab61d6b2bbd30146724d063eb322180c6f18a6f74e4b6aa
    DOWNLOAD_DIR "${EP_DOWNLOAD_DIR}" # if empty string, uses default download dir
    INSTALL_DIR "${LIBOPENSSL_INSTALL_DIR}"
    CONFIGURE_COMMAND
      ${CMAKE_COMMAND} -E env "PATH=$ENV{PATH}" "CC=${CMAKE_C_COMPILER}" "CXX=${CMAKE_CXX_COMPILER}"
      <SOURCE_DIR>/config ${OpenSSL_Configure_Args}
    LIST_SEPARATOR " " # expand ${OpenSSL_Configure_Args} to space-separated list
    # only install software, don't install or build docs
    INSTALL_COMMAND "${MAKE_COMMAND}" install_sw
  )

  set(LIBOPENSSL_INCLUDE_PATH "${LIBOPENSSL_INSTALL_DIR}/include")
  set(LIBOPENSSL_LIB_PATH "${LIBOPENSSL_INSTALL_DIR}/lib")
  file(MAKE_DIRECTORY "${LIBOPENSSL_INCLUDE_PATH}")

  if(BUILD_SHARED_LIBS)
    set(LIBOPENSSL_CRYPTO_LIBRARY "${LIBOPENSSL_LIB_PATH}/libcrypto.so")
    add_library(OpenSSL::Crypto SHARED IMPORTED)
    set(LIBOPENSSL_SSL_LIBRARY "${LIBOPENSSL_LIB_PATH}/libssl.so")
    add_library(OpenSSL::SSL SHARED IMPORTED)
  else()
    set(LIBOPENSSL_CRYPTO_LIBRARY "${LIBOPENSSL_LIB_PATH}/libcrypto.a")
    add_library(OpenSSL::Crypto STATIC IMPORTED)
    set(LIBOPENSSL_SSL_LIBRARY "${LIBOPENSSL_LIB_PATH}/libssl.a")
    add_library(OpenSSL::SSL STATIC IMPORTED)
    set(THREADS_PREFER_PTHREAD_FLAG ON)
    find_package(Threads REQUIRED)
    # equivalent to -ldl -lpthread
    # (taken from Libs.private of lib/openssl/lib/pkgconfig/libcrypto.pc)
    target_link_libraries(
      OpenSSL::Crypto INTERFACE Threads::Threads "${CMAKE_DL_LIBS}"
    )
    target_link_libraries(
      OpenSSL::SSL INTERFACE Threads::Threads "${CMAKE_DL_LIBS}"
    )
  endif(BUILD_SHARED_LIBS)

  set_target_properties(OpenSSL::Crypto PROPERTIES
    IMPORTED_LOCATION "${LIBOPENSSL_CRYPTO_LIBRARY}"
    # Check ./build/lib/pcap/lib/pkgconfig for linker dependencies
    INTERFACE_INCLUDE_DIRECTORIES "${LIBOPENSSL_INCLUDE_PATH}"
  )
  set_target_properties(OpenSSL::SSL PROPERTIES
    IMPORTED_LOCATION "${LIBOPENSSL_SSL_LIBRARY}"
    # Check ./build/lib/pcap/lib/pkgconfig for linker dependencies
    INTERFACE_INCLUDE_DIRECTORIES "${LIBOPENSSL_INCLUDE_PATH}"
  )

  add_dependencies(OpenSSL::Crypto openssl_src)
  add_dependencies(OpenSSL::SSL openssl_src)
endif ()
