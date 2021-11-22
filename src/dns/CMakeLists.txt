include_directories (
  "${EDGESEC_SOURCE_DIR}/src"
)

add_library(mdns_list mdns_list.c)
target_link_libraries(mdns_list PRIVATE os)

add_library(mdns_mapper mdns_mapper.c)
target_include_directories(mdns_mapper PUBLIC ${LIBPCAP_INCLUDE_PATH})
target_link_libraries(mdns_mapper PRIVATE mdns_list os)

add_library(mcast mcast.c)
target_link_libraries(mcast PRIVATE os)

add_library(reflection_list reflection_list.c)
target_link_libraries(reflection_list PRIVATE os log)

add_library(mdns_service mdns_service.c)
target_include_directories(mdns_service PRIVATE "${LIBSQLITE_INCLUDE_DIR}")
target_link_libraries(mdns_service PUBLIC packet_queue mdns_mapper PRIVATE pcap_service reflection_list mcast mdns_decoder domain eloop if os log)
