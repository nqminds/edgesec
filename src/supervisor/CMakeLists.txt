include_directories (
  "${EDGESEC_SOURCE_DIR}/src"
)

add_library(bridge_list bridge_list.c)
target_link_libraries(bridge_list log os)

add_library(mac_mapper mac_mapper.c)
target_link_libraries(mac_mapper bridge_list log os)

add_library(cmd_processor cmd_processor.c)
target_link_libraries(cmd_processor log os)

add_library(domain_server domain_server.c)
target_link_libraries(domain_server log)

add_library(supervisor supervisor.c)
target_link_libraries(supervisor domain_server cmd_processor log iptables)
