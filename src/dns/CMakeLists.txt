include_directories (
  "${EDGESEC_SOURCE_DIR}/src"
)

add_library(command_mapper command_mapper.c)
target_link_libraries(command_mapper PRIVATE os hash)

# header-only library
add_library(dns_config INTERFACE)
target_link_libraries(dns_config INTERFACE utarray capture_config)

add_library(mdns_list mdns_list.c)
target_link_libraries(mdns_list PRIVATE os)

add_library(mdns_mapper mdns_mapper.c)
target_link_libraries(mdns_mapper PUBLIC mdns_decoder mdns_list os)

add_library(mcast mcast.c)
target_link_libraries(mcast PRIVATE os)

add_library(reflection_list reflection_list.c)
target_link_libraries(reflection_list PRIVATE os log)

add_library(mdns_service mdns_service.c)
target_include_directories(mdns_service PRIVATE SQLite::SQLite3)
target_link_libraries(mdns_service
  PUBLIC dns_config reflection_list mdns_mapper command_mapper
  PRIVATE
    uthash ifaceu net log eloop domain squeue hashmap iface_mapper mdns_decoder
    pcap_service packet_queue supervisor_config cmd_processor mcast
)
