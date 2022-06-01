include_directories (
  "${EDGESEC_SOURCE_DIR}/src"
)

add_library(packet_queue packet_queue.c)
target_link_libraries(packet_queue PRIVATE packet_decoder log os)

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

add_library(header_middleware header_middleware.c)
target_include_directories(header_middleware PRIVATE ${LIBPCAP_INCLUDE_PATH} ${LIBSQLITE_INCLUDE_DIR})
target_link_libraries(header_middleware PRIVATE sqliteu squeue log os iface SQLite::sqlite)
