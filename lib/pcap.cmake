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
    execute_process(COMMAND
      bash
      ${CMAKE_SOURCE_DIR}/lib/compile_pcap.sh
      "${libpcap_SOURCE_DIR}"
      "${libpcap_BINARY_DIR}"
      "${LIBPCAP_INSTALL_ROOT}"
      "${target_autoconf_triple}"
    )
    find_library(LIBPCAP_LIB NAMES libpcap.a pcap PATHS "${LIBPCAP_LIB_DIR}" NO_DEFAULT_PATH)
  endif ()

  # static pcap needs -libverbs -lnl-genl-3 -lnl-3  -ldbus-1
  if (NOT TARGET PCAP::pcap)
    add_library(PCAP::pcap UNKNOWN IMPORTED)

    set(pcap_link_libs "ibverbs" "nl-genl-3" "nl-3" "dbus-1")

    set_target_properties(PCAP::pcap PROPERTIES
        IMPORTED_LOCATION "${LIBPCAP_LIB}"
        INTERFACE_LINK_LIBRARIES "${pcap_link_libs}"
        INTERFACE_INCLUDE_DIRECTORIES "${LIBPCAP_INCLUDE_PATH}"
    )
  endif(NOT TARGET PCAP::pcap)

endif ()
