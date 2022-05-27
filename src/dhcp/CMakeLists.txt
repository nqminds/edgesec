include_directories (
  "${EDGESEC_SOURCE_DIR}/src"
)

add_library(dnsmasq dnsmasq.c)
if (USE_UCI_SERVICE)
    target_link_libraries(dnsmasq PRIVATE log os squeue OpenWRT::LIBUCI)
else ()
  target_link_libraries(dnsmasq PRIVATE log os)
endif ()


add_library(dhcp_service dhcp_service.c)
target_link_libraries(dhcp_service PRIVATE dnsmasq log os)
