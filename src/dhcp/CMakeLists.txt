include_directories (
  "${EDGESEC_SOURCE_DIR}/src"
)

add_library(dnsmasq dnsmasq.c)
target_link_libraries(dnsmasq log os)

add_library(dhcp_service dhcp_service.c)
target_link_libraries(dhcp_service dnsmasq log os)
