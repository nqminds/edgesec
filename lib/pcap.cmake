add_compile_definitions(WITH_PCAP_SERVICE)

if(BUILD_ONLY_DOCS)
  # skip
elseif(NOT BUILD_PCAP_LIB)
  find_package(PCAP MODULE REQUIRED)
  message("Found PCAP library: ${PCAP_LIBRARIES}")
else()
  FetchContent_Declare(
    libpcap
    # warning, libpcap 1.9.1 is the latest on OpenWRT 19.07 and Ubuntu 20.04
    URL https://github.com/the-tcpdump-group/libpcap/archive/refs/tags/libpcap-1.10.1.tar.gz
    URL_HASH SHA3_256=9aedcbec09b7b3b01c78cc80822c505846d73928a72ae96eb907b1f467eee649
    DOWNLOAD_DIR "${EP_DOWNLOAD_DIR}" # if empty string, uses default download dir
  )

  set(DISABLE_DBUS ON CACHE BOOL "Disable DBUS support (otherwise need to link dbus-1 when static linking)" FORCE)
  set(DISABLE_RDMA ON CACHE BOOL "Disable RDMA support (otherwise need to link ibverbs when static linking)" FORCE)
  set(BUILD_WITH_LIBNL OFF CACHE BOOL "Disable libnl support (otherwise need to link nl-3 when static linking)" FORCE)

  # create static lib using -fPIC, so we can make it into a sharedobject later
  set(CMAKE_POSITION_INDEPENDENT_CODE ON)

  set(CMAKE_C_EXTENSIONS ON) # libpcap uses non-POSIX C (e.g. BSD u_int)
  # declares the `pcap_static` target
  FetchContent_MakeAvailable(libpcap)

  # skip installing `libpcap` when running `make install`
  # we're compiling `libpcap` statically, so it's not needed
  # work around until https://gitlab.kitware.com/cmake/cmake/-/issues/20167 is fixed
  if(IS_DIRECTORY "${libpcap_SOURCE_DIR}")
    set_property(DIRECTORY ${libpcap_SOURCE_DIR} PROPERTY EXCLUDE_FROM_ALL YES)
  endif()

  # pcap_static does not declare include_directories, so we need to manually add them
  add_library(PCAP::pcap INTERFACE IMPORTED)
  target_link_libraries(PCAP::pcap INTERFACE pcap_static)
  target_include_directories(PCAP::pcap INTERFACE "${libpcap_SOURCE_DIR}")
endif ()
