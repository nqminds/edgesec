include_directories (
  "${EDGESEC_SOURCE_DIR}/src"
)

add_library(capture_config capture_config.c)
target_link_libraries(capture_config PRIVATE log os)

if (BUILD_CAPTURE_SERVICE)
  add_library(mdns_decoder mdns_decoder.c)
  target_link_libraries(mdns_decoder PRIVATE squeue log os hash iface PUBLIC packet_decoder)

  add_library(dns_decoder dns_decoder.c)
  target_link_libraries(dns_decoder PRIVATE log os hash packet_decoder)

  add_library(packet_decoder packet_decoder.c)

  # packet_decoder.h has an #include <pcap.h>, so need to make it PUBLIC include
  target_link_libraries(packet_decoder PUBLIC PCAP::pcap PRIVATE mdns_decoder dns_decoder hash net log os hashmap)

  add_library(packet_queue packet_queue.c)

  target_link_libraries(packet_queue PUBLIC packet_decoder PRIVATE log os)

  add_library(pcap_service pcap_service.c)
  target_link_libraries(pcap_service PUBLIC PCAP::pcap PRIVATE net log os)

  add_library(pcap_queue pcap_queue.c)

  target_link_libraries(pcap_queue PUBLIC PCAP::pcap PRIVATE log os)

  add_library(sqlite_header_writer sqlite_header_writer.c)

  target_link_libraries(sqlite_header_writer PRIVATE sqliteu squeue log os iface SQLite::SQLite3 packet_decoder)

  add_library(sqlite_pcap_writer sqlite_pcap_writer.c)

  target_link_libraries(sqlite_pcap_writer PRIVATE sqliteu log os SQLite::SQLite3)

  add_library(default_analyser default_analyser.c)
  target_link_libraries(default_analyser PUBLIC supervisor_config)

  add_library(capture_cleaner capture_cleaner.c)

  target_link_libraries(capture_cleaner PRIVATE sqlite_pcap_writer eloop log os SQLite::SQLite3)

  target_link_libraries(default_analyser PUBLIC PCAP::pcap PRIVATE dns_decoder pcap_service sqlite_header_writer sqlite_pcap_writer pcap_queue packet_queue packet_decoder squeue eloop iface log os hashmap domain)

  add_library(capture_service capture_service.c)

  target_link_libraries(capture_service PRIVATE capture_cleaner default_analyser log)
endif()
