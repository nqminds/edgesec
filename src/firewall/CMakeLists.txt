include_directories (
  "${EDGESEC_SOURCE_DIR}/src"
)

add_library(firewall_service firewall_service.c)
target_link_libraries(firewall_service PRIVATE log iface os hashmap)
