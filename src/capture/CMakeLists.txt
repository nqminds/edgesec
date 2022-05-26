include_directories (
  "${EDGESEC_SOURCE_DIR}/src"
)

if (USE_CAPTURE_SERVICE)
  add_subdirectory(middleware)

  # we include packet_decoder.h, so need to include its dependencies
  add_library(mdns_decoder mdns_decoder.c)
  target_include_directories(mdns_decoder PUBLIC $<TARGET_PROPERTY:packet_decoder,INCLUDE_DIRECTORIES> $<TARGET_PROPERTY:iface,INCLUDE_DIRECTORIES>)
  target_link_libraries(mdns_decoder PRIVATE squeue log os hash PUBLIC packet_decoder)

  add_library(dns_decoder dns_decoder.c)
  target_include_directories(dns_decoder PRIVATE ${LIBPCAP_INCLUDE_PATH})
  target_link_libraries(dns_decoder PRIVATE log os hash)

  # packet_decoder.h has an #include <pcap.h>, so need to make it PUBLIC include
  add_library(packet_decoder packet_decoder.c)
  target_include_directories(packet_decoder PUBLIC ${LIBPCAP_INCLUDE_PATH})
  target_link_libraries(packet_decoder PUBLIC PCAP::pcap PRIVATE mdns_decoder dns_decoder hash net log os hashmap)

  add_library(pcap_service pcap_service.c)
  target_include_directories(pcap_service PRIVATE ${LIBPCAP_INCLUDE_PATH})
  target_link_libraries(pcap_service PRIVATE net log os PCAP::pcap)

  add_library(capture_service capture_service.c)
  target_include_directories(capture_service PRIVATE ${LIBPCAP_INCLUDE_PATH} ${LIBSQLITE_INCLUDE_DIR})
  target_link_libraries(capture_service PRIVATE capture_cleaner dns_decoder pcap_service sqlite_header_writer sqlite_pcap_writer pcap_queue packet_queue packet_decoder squeue eloop iface log os hashmap)
endif()
