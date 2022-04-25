include_directories (
  "${EDGESEC_SOURCE_DIR}/src"
)

add_library(firewall_service firewall_service.c)
target_include_directories(firewall_service PUBLIC ${LIBSQLITE_INCLUDE_DIR})
if (USE_UCI_SERVICE)
  target_link_libraries(firewall_service PRIVATE uci_wrt log iface os hashmap)
else()
  target_link_libraries(firewall_service PRIVATE iptables log iface os hashmap)
endif()
