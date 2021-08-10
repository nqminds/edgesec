if (BUILD_PCAP_LIB AND NOT (BUILD_ONLY_DOCS))
  add_compile_definitions(WITH_PCAP_SERVICE)
  set(LIBPCAP_PATH ${CMAKE_CURRENT_BINARY_DIR}/lib/pcap)
  set(LIBPCAP_INCLUDE_PATH ${LIBPCAP_PATH}/include)
  find_library(LIBPCAP_LIB NAMES pcap libpcap PATHS "${LIBPCAP_PATH}/lib" NO_DEFAULT_PATH)
  if (LIBPCAP_LIB)
    message("Found libpcap library: ${LIBPCAP_LIB}")
  ELSE ()
      FetchContent_Declare(
        pcap
        GIT_REPOSITORY https://github.com/the-tcpdump-group/libpcap
        GIT_TAG        libpcap-1.10.1
      )
      set(FETCHCONTENT_QUIET OFF)
      FetchContent_MakeAvailable(pcap)
      FetchContent_GetProperties(pcap SOURCE_DIR PCAP_SOURCE_DIR)
      message("Source dir: ${PCAP_SOURCE_DIR}")
      execute_process(
        COMMAND ./configure --prefix=${LIBPCAP_PATH}
        WORKING_DIRECTORY "${PCAP_SOURCE_DIR}"
      )
      execute_process(
        COMMAND make
        WORKING_DIRECTORY "${PCAP_SOURCE_DIR}"
      )
      execute_process(
        COMMAND make install
        WORKING_DIRECTORY "${PCAP_SOURCE_DIR}"
      )
      find_library(LIBPCAP_LIB NAMES pcap libpcap PATHS "${LIBPCAP_PATH}/lib" NO_DEFAULT_PATH)
  endif ()
endif ()
