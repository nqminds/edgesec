include_directories (
  "${PROJECT_SOURCE_DIR}/src"
)

add_library(firewall_service firewall_service.c)
target_link_libraries(firewall_service
  PUBLIC LibUTHash::LibUTHash supervisor_config hashmap iface_mapper firewall_config
  PRIVATE log allocs os
)

add_library(firewall_config INTERFACE)
target_link_libraries(firewall_config INTERFACE LibUTHash::LibUTHash os hashmap iface_mapper)

if (USE_UCI_SERVICE)
  target_link_libraries(firewall_service PRIVATE uci_wrt)
  target_link_libraries(firewall_config INTERFACE uci_wrt)
else()
  target_link_libraries(firewall_service PRIVATE iptables)
  target_link_libraries(firewall_config INTERFACE iptables)
endif()
