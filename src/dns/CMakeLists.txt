include_directories (
  "${EDGESEC_SOURCE_DIR}/src"
)

add_library(mcast mcast.c)
target_link_libraries(mcast PRIVATE os)

add_library(reflection_list reflection_list.c)
target_link_libraries(reflection_list PRIVATE os log)

add_library(mdns_service mdns_service.c)
target_include_directories(mdns_service PRIVATE "${LIBSQLITE_INCLUDE_DIR}")
target_link_libraries(mdns_service PRIVATE reflection_list mcast mdns_decoder domain eloop if os log)
