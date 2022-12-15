include(FetchContent)

if (USE_CRYPTO_SERVICE)
  add_compile_definitions(WITH_CRYPTO_SERVICE)
  if(BUILD_ONLY_DOCS)
    # pass
  elseif(BUILD_OPENSSL3_LIB)
    if (CMAKE_CROSSCOMPILING)
      if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        if(CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
          set(openssl3_config "linux-aarch64")
        elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "arm")
          # arm is such a massive spectrum of variants that it's not worth
          # trying to guess which one we're on.
          # just use generic 32-bit linux
          set(openssl3_config "linux-generic32")
        elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
          set(openssl3_config "linux-x86_64")
        endif()
      endif()

      if(NOT DEFINED openssl3_config)
        message(FATAL_ERROR
          "Could not figure out config for cross compiling openssl. "
          "Please set openssl3_config manually, by following the instructions in: "
          "https://github.com/openssl/openssl/blob/openssl-3.0.0/INSTALL.md#manual-configuration"
        )
      endif ()

      list(APPEND OpenSSL3_Configure_Args
        "${openssl3_config}"
        "--cross-compile-prefix=${CROSS_COMPILE_PREFIX}"
      )
    endif (CMAKE_CROSSCOMPILING)

    list(APPEND OpenSSL3_Configure_Args
      # install directory on the build system
      --prefix=<INSTALL_DIR>
      # install directory on the host/target system
      --openssldir=<INSTALL_DIR>
      # Set --libdir=lib, since otherwise sometimes OpenSSL 3 installs in /lib64
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

    set(LIBOPENSSL3_INSTALL_ROOT "${CMAKE_CURRENT_BINARY_DIR}/lib")
    set(LIBOPENSSL3_INSTALL_DIR "${LIBOPENSSL3_INSTALL_ROOT}/openssl3")
    ExternalProject_Add(
      openssl3_src
      URL https://www.openssl.org/source/openssl-3.0.0.tar.gz
      URL_HASH SHA256=59eedfcb46c25214c9bd37ed6078297b4df01d012267fe9e9eee31f61bc70536
      DOWNLOAD_DIR "${EP_DOWNLOAD_DIR}" # if empty string, uses default download dir
      INSTALL_DIR "${LIBOPENSSL3_INSTALL_DIR}"
      CONFIGURE_COMMAND
        ${CMAKE_COMMAND} -E env "PATH=$ENV{PATH}" "CC=${CMAKE_C_COMPILER}" "CXX=${CMAKE_CXX_COMPILER}"
        <SOURCE_DIR>/Configure ${OpenSSL3_Configure_Args}
      LIST_SEPARATOR " " # expand ${OpenSSL3_Configure_Args} to space-separated list
      # only install software, don't install or build docs
      INSTALL_COMMAND "${MAKE_COMMAND}" install_sw
    )

    set(LIBOPENSSL3_INCLUDE_PATH "${LIBOPENSSL3_INSTALL_DIR}/include")
    set(LIBOPENSSL3_LIB_PATH "${LIBOPENSSL3_INSTALL_DIR}/lib")
    file(MAKE_DIRECTORY "${LIBOPENSSL3_INCLUDE_PATH}")
    if(BUILD_SHARED_LIBS)
      set(OPENSSL3_CRYPTO_LIBRARY "${LIBOPENSSL3_LIB_PATH}/libcrypto.so")
      add_library(OpenSSL3::Crypto SHARED IMPORTED)
    else()
      set(OPENSSL3_CRYPTO_LIBRARY "${LIBOPENSSL3_LIB_PATH}/libcrypto.a")
      add_library(OpenSSL3::Crypto STATIC IMPORTED)

      set(THREADS_PREFER_PTHREAD_FLAG ON)
      find_package(Threads REQUIRED)
      # equivalent to -ldl -lpthread
      # (taken from Libs.private of lib/openssl/lib/pkgconfig/libcrypto.pc)
      target_link_libraries(
        OpenSSL3::Crypto INTERFACE Threads::Threads "${CMAKE_DL_LIBS}"
      )
    endif()

    set_target_properties(OpenSSL3::Crypto PROPERTIES
      IMPORTED_LOCATION "${OPENSSL3_CRYPTO_LIBRARY}"
      # Check ./build/lib/pcap/lib/pkgconfig for linker dependencies
      INTERFACE_INCLUDE_DIRECTORIES "${LIBOPENSSL3_INCLUDE_PATH}"
    )
    add_dependencies(OpenSSL3::Crypto openssl3_src)
  else()
    find_package(OpenSSL 3 MODULE REQUIRED COMPONENTS Crypto)
    message("Found OPENSSL3_CRYPTO_LIBRARY: ${OPENSSL3_CRYPTO_LIBRARY}")
  endif()
endif ()
