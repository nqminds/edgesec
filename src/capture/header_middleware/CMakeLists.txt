include_directories (
  "${EDGESEC_SOURCE_DIR}/src"
)

# we include packet_decoder.h, so need to include its dependencies
add_library(mdns_decoder mdns_decoder.c)
target_include_directories(mdns_decoder PUBLIC $<TARGET_PROPERTY:iface,INCLUDE_DIRECTORIES>)
target_link_libraries(mdns_decoder PRIVATE squeue log os hash PUBLIC packet_decoder)

add_library(dns_decoder dns_decoder.c)
target_link_libraries(dns_decoder PUBLIC PCAP::pcap SQLite::SQLite3 PRIVATE log os hash)

# packet_decoder.h has an #include <pcap.h>, so need to make it PUBLIC include
add_library(packet_decoder packet_decoder.c)
target_link_libraries(packet_decoder PUBLIC PCAP::pcap PRIVATE mdns_decoder dns_decoder hash net log os hashmap)

add_library(packet_queue packet_queue.c)
target_link_libraries(packet_queue PUBLIC packet_decoder PRIVATE log os)

add_library(sqlite_header sqlite_header.c)
target_link_libraries(sqlite_header PUBLIC PCAP::pcap SQLite::SQLite3 PRIVATE sqliteu log os iface SQLite::SQLite3)

add_library(header_middleware header_middleware.c)
target_include_directories(header_middleware PRIVATE ${PROJECT_BINARY_DIR})
target_link_libraries(header_middleware PUBLIC PCAP::pcap SQLite::SQLite3 PRIVATE packet_queue sqlite_header eloop log os iface SQLite::SQLite3)
