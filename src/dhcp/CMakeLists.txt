include_directories (
  "${PROJECT_SOURCE_DIR}/src"
)

add_library(dnsmasq dnsmasq.c)
# needed for fileno()
set_target_properties(dnsmasq PROPERTIES C_EXTENSIONS ON)
target_link_libraries(dnsmasq PUBLIC dhcp_config PRIVATE squeue log os)
if (USE_UCI_SERVICE)
    target_link_libraries(dnsmasq PRIVATE squeue uci_wrt)
endif ()


add_library(dhcp_service dhcp_service.c)
target_link_libraries(dhcp_service PUBLIC dhcp_config PRIVATE dnsmasq log os)

add_library(dhcp_config_utils dhcp_config_utils.c)
target_link_libraries(dhcp_config_utils
  PUBLIC
    dhcp_config
  PRIVATE
    LibUTHash::LibUTHash
    net
    os
)

add_library(dhcp_config INTERFACE)
set_target_properties(dhcp_config PROPERTIES PUBLIC_HEADER "dhcp_config.h")
target_link_libraries(dhcp_config INTERFACE LibUTHash::LibUTHash allocs os net)
