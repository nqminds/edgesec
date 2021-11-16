include_directories (
  "${EDGESEC_SOURCE_DIR}/src"
)

add_library(mdns_list mdns_list.c)
target_link_libraries(mdns_list PRIVATE os)

add_library(ip_mapper ip_mapper.c)
target_link_libraries(ip_mapper PRIVATE mdns_list os)

add_library(mcast mcast.c)
target_link_libraries(mcast PRIVATE os)

add_library(reflection_list reflection_list.c)
target_link_libraries(reflection_list PRIVATE os log)

add_library(mdns_service mdns_service.c)
target_link_libraries(mdns_service PRIVATE ip_mapper reflection_list mcast mdns_decoder domain eloop if os log)
