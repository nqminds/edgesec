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
    URL https://github.com/the-tcpdump-group/libpcap/archive/refs/tags/libpcap-1.10.2.tar.gz
    URL_HASH SHA3_256=8962bccd636a93fa9f2a8ff447b2dfded5420ea1e12d368de0f2bab557f1f0a2
    DOWNLOAD_DIR "${EP_DOWNLOAD_DIR}" # if empty string, uses default download dir
  )

  set(DISABLE_DBUS ON CACHE BOOL "Disable DBUS support (otherwise need to link dbus-1 when static linking)" FORCE)
  set(DISABLE_RDMA ON CACHE BOOL "Disable RDMA support (otherwise need to link ibverbs when static linking)" FORCE)
  set(BUILD_WITH_LIBNL OFF CACHE BOOL "Disable libnl support (otherwise need to link nl-3 when static linking)" FORCE)

  # create static lib using -fPIC, so we can make it into a sharedobject later
  set(CMAKE_POSITION_INDEPENDENT_CODE ON)

  set(__tmp_cmake_c_extension "${CMAKE_C_EXTENSIONS}")
  set(CMAKE_C_EXTENSIONS ON) # libpcap uses non-POSIX C (e.g. BSD u_int)

  # declares the `pcap_static` target
  FetchContent_MakeAvailable(libpcap)

  set(CMAKE_C_EXTENSIONS "${__tmp_cmake_c_extension}")

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
  target_compile_definitions(
    # pcap requires BSD types to be defined, e.g. u_int/u_short/u_char
    # the following syntax works for uClibc, glibc, musl libc
    PCAP::pcap INTERFACE
      "_BSD_SOURCE" # deprecated in glibc >2.20
      "_DEFAULT_SOURCE" # only added in glibc >2.19, musl >=1.1.5
  )
endif ()
