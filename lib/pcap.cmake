if (BUILD_PCAP_LIB AND NOT (BUILD_ONLY_DOCS))
  add_compile_definitions(WITH_PCAP_SERVICE)
  set(LIBPCAP_INSTALL_ROOT ${CMAKE_CURRENT_BINARY_DIR}/lib)
  set(LIBPCAP_INSTALL_DIR ${LIBPCAP_INSTALL_ROOT}/pcap)
  set(LIBPCAP_INCLUDE_PATH ${LIBPCAP_INSTALL_DIR}/include)
  set(LIBPCAP_LIB_DIR "${LIBPCAP_INSTALL_DIR}/lib")

  find_library(LIBPCAP_LIB NAMES libpcap.a pcap PATHS "${LIBPCAP_LIB_DIR}" NO_DEFAULT_PATH)
  if (LIBPCAP_LIB)
    message("Found libpcap library: ${LIBPCAP_LIB}")
  ELSE ()
    FetchContent_Declare(
      libpcap
      URL https://github.com/the-tcpdump-group/libpcap/archive/refs/tags/libpcap-1.10.1.tar.gz
      URL_HASH SHA3_256=9aedcbec09b7b3b01c78cc80822c505846d73928a72ae96eb907b1f467eee649
    )
    FetchContent_Populate(libpcap)
    execute_process(COMMAND ${CMAKE_COMMAND}
      -B build/ -S "${libpcap_SOURCE_DIR}"
      "-DCMAKE_INSTALL_PREFIX=${LIBPCAP_INSTALL_DIR}"
      # Pass C/CXX compiler for gcc/cross-compiling
      "-DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}"
      "-DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}"
      # Disable DBUS support (otherwise need to link dbus-1 when static linking)
      -DDISABLE_DBUS=ON
      # Disable RDMA support (otherwise need to link ibverbs when static linking)
      -DDISABLE_RDMA=ON
      WORKING_DIRECTORY "${libpcap_BINARY_DIR}"
    )
    execute_process(COMMAND ${CMAKE_COMMAND}
      --build build/
      WORKING_DIRECTORY "${libpcap_BINARY_DIR}"
    )
    execute_process(COMMAND ${CMAKE_COMMAND}
      --install build/
      WORKING_DIRECTORY "${libpcap_BINARY_DIR}"
    )

    find_library(LIBPCAP_LIB NAMES libpcap.a pcap PATHS "${LIBPCAP_LIB_DIR}" NO_DEFAULT_PATH)
  endif ()

  # static pcap needs -lnl-genl-3 -lnl-3 # maybe openssl and crypto too???
  if (NOT TARGET PCAP::pcap)
    add_library(PCAP::pcap UNKNOWN IMPORTED)

    # these two may have already been loaded in a custom location with nl.cmake
    find_library(LIBNL_LIBRARY NAMES nl nl-3 REQUIRED)
    find_library(LIBNL_GENL_LIBRARY NAMES nl-genl nl-genl-3 REQUIRED)

    set(pcap_link_libs ${LIBNL_LIBRARY} ${LIBNL_GENL_LIBRARY})

    set_target_properties(PCAP::pcap PROPERTIES
        IMPORTED_LOCATION "${LIBPCAP_LIB}"
        INTERFACE_LINK_LIBRARIES "${pcap_link_libs}"
        INTERFACE_INCLUDE_DIRECTORIES "${LIBPCAP_INCLUDE_PATH}"
    )
  endif(NOT TARGET PCAP::pcap)
endif ()
