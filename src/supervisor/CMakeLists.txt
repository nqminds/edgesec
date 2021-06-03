include_directories (
  "${EDGESEC_SOURCE_DIR}/src"
)

add_library(run_analyser run_analyser.c)
target_link_libraries(run_analyser capture_service log os)

add_library(bridge_list bridge_list.c)
target_link_libraries(bridge_list log os)

add_library(mac_mapper mac_mapper.c)
target_link_libraries(mac_mapper bridge_list log os)

add_library(network_commands network_commands.c)
target_link_libraries(network_commands run_analyser mac_mapper iptables log os)

add_library(cmd_processor cmd_processor.c)
target_link_libraries(cmd_processor network_commands mac_mapper domain log os iptables if)

add_library(supervisor supervisor.c)
target_link_libraries(supervisor cmd_processor domain log iptables)
