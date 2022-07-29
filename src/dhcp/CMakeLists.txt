include_directories (
  "${PROJECT_SOURCE_DIR}/src"
)

add_library(dnsmasq dnsmasq.c)
target_link_libraries(dnsmasq PRIVATE log os)
if (USE_UCI_SERVICE)
    target_link_libraries(dnsmasq PRIVATE squeue uci_wrt)
endif ()


add_library(dhcp_service dhcp_service.c)
target_link_libraries(dhcp_service PRIVATE dnsmasq log os)
