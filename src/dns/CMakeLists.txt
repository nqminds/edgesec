include_directories (
  "${EDGESEC_SOURCE_DIR}/src"
)

add_library(command_mapper command_mapper.c)
target_link_libraries(command_mapper PRIVATE os hash)

add_library(mdns_list mdns_list.c)
target_link_libraries(mdns_list PRIVATE os)

add_library(mdns_mapper mdns_mapper.c)
target_link_libraries(mdns_mapper PRIVATE mdns_list os)

add_library(mcast mcast.c)
target_link_libraries(mcast PRIVATE os)

add_library(reflection_list reflection_list.c)
target_link_libraries(reflection_list PRIVATE os log)

add_library(mdns_service mdns_service.c)
target_include_directories(mdns_service PRIVATE SQLite::SQLite3)
target_link_libraries(mdns_service PRIVATE iface_mapper packet_queue mdns_mapper PRIVATE command_mapper pcap_service reflection_list mcast mdns_decoder domain eloop squeue ifaceu net os log hashmap)
