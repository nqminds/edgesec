include(FetchContent)

if (USE_CRYPTO_SERVICE)
  add_compile_definitions(WITH_CRYPTO_SERVICE)
  if(BUILD_ONLY_DOCS)
    # pass
  elseif(BUILD_OPENSSL_LIB)
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
          "https://github.com/openssl/openssl/blob/openssl-3.0.0/INSTALL.md#manual-configuration"
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
      URL https://www.openssl.org/source/openssl-3.0.0.tar.gz
      URL_HASH SHA256=59eedfcb46c25214c9bd37ed6078297b4df01d012267fe9e9eee31f61bc70536
      INSTALL_DIR "${LIBOPENSSL_INSTALL_DIR}"
      CONFIGURE_COMMAND
        ${CMAKE_COMMAND} -E env "PATH=$ENV{PATH}" "CC=${CMAKE_C_COMPILER}" "CXX=${CMAKE_CXX_COMPILER}"
        <SOURCE_DIR>/Configure ${OpenSSL_Configure_Args}
      LIST_SEPARATOR " " # expand ${OpenSSL_Configure_Args} to space-separated list
      # only install software, don't install or build docs
      INSTALL_COMMAND "${MAKE_COMMAND}" install_sw
    )

    set(LIBOPENSSL_INCLUDE_PATH "${LIBOPENSSL_INSTALL_DIR}/include")
    set(LIBPPENSSL_LIB_PATH "${LIBOPENSSL_INSTALL_DIR}/lib")
    file(MAKE_DIRECTORY "${LIBOPENSSL_INCLUDE_PATH}")
    if(BUILD_SHARED_LIBS)
      set(OPENSSL_CRYPTO_LIBRARY "${LIBPPENSSL_LIB_PATH}/libcrypto.so")
      add_library(OpenSSL::Crypto SHARED IMPORTED)
    else()
      set(OPENSSL_CRYPTO_LIBRARY "${LIBPPENSSL_LIB_PATH}/libcrypto.a")
      add_library(OpenSSL::Crypto STATIC IMPORTED)

      set(THREADS_PREFER_PTHREAD_FLAG ON)
      find_package(Threads REQUIRED)
      # equivalent to -ldl -lpthread
      # (taken from Libs.private of lib/openssl/lib/pkgconfig/libcrypto.pc)
      target_link_libraries(
        OpenSSL::Crypto INTERFACE Threads::Threads "${CMAKE_DL_LIBS}"
      )
    endif()

    set_target_properties(OpenSSL::Crypto PROPERTIES
      IMPORTED_LOCATION "${OPENSSL_CRYPTO_LIBRARY}"
      # Check ./build/lib/pcap/lib/pkgconfig for linker dependencies
      INTERFACE_INCLUDE_DIRECTORIES "${LIBOPENSSL_INCLUDE_PATH}"
    )
    add_dependencies(OpenSSL::Crypto openssl_src)
  else()
    find_package(OpenSSL 3 MODULE REQUIRED COMPONENTS Crypto)
    message("Found OPENSSL_CRYPTO_LIBRARY: ${OPENSSL_CRYPTO_LIBRARY}")
  endif()
endif ()
