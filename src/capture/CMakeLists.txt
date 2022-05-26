include_directories (
  "${EDGESEC_SOURCE_DIR}/src"
)

if (USE_CAPTURE_SERVICE)
  add_subdirectory(cleaner_middleware)
  add_subdirectory(header_middleware)
  add_subdirectory(pcap_middleware)

  add_library(pcap_service pcap_service.c)
  target_include_directories(pcap_service PRIVATE ${LIBPCAP_INCLUDE_PATH})
  target_link_libraries(pcap_service PRIVATE net log os PCAP::pcap)

  add_library(capture_service capture_service.c)
  target_include_directories(capture_service PRIVATE ${LIBPCAP_INCLUDE_PATH} ${LIBSQLITE_INCLUDE_DIR})
  target_link_libraries(capture_service PRIVATE capture_cleaner dns_decoder pcap_service sqlite_header_writer sqlite_pcap_writer pcap_queue packet_queue packet_decoder squeue eloop iface log os hashmap)
endif()
