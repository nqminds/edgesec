include_directories (
  "${EDGESEC_SOURCE_DIR}/src"
)

add_library(bridge_list bridge_list.c)
target_link_libraries(bridge_list PRIVATE log os)

add_library(mac_mapper mac_mapper.c)
target_link_libraries(mac_mapper PRIVATE bridge_list net log os)

add_library(subscriber_events subscriber_events.c)
target_include_directories(subscriber_events PUBLIC $<TARGET_PROPERTY:iface,INCLUDE_DIRECTORIES>)
target_link_libraries(subscriber_events PRIVATE log os domain SQLite::sqlite)

add_library(sqlite_fingerprint_writer sqlite_fingerprint_writer.c)
target_link_libraries(sqlite_fingerprint_writer PRIVATE sqliteu squeue log os SQLite::sqlite)

add_library(sqlite_alert_writer sqlite_alert_writer.c)
target_link_libraries(sqlite_alert_writer PRIVATE sqliteu squeue log os SQLite::sqlite)

add_library(sqlite_macconn_writer sqlite_macconn_writer.c)
target_link_libraries(sqlite_macconn_writer PRIVATE sqliteu squeue log os SQLite::sqlite)

add_library(network_commands network_commands.c)
if (USE_CRYPTO_SERVICE)
  target_link_libraries(network_commands PRIVATE dhcp_service ap_service crypt_service sqlite_macconn_writer mac_mapper eloop firewall_service base64 net log os)
else ()
  target_link_libraries(network_commands PRIVATE dhcp_service ap_service sqlite_macconn_writer mac_mapper eloop firewall_service base64 net log os)
endif ()

add_library(monitor_commands monitor_commands.c)
target_link_libraries(monitor_commands PRIVATE mdns_mapper subscriber_events sqlite_alert_writer ap_service sqlite_macconn_writer mac_mapper eloop firewall_service base64 log os)

if (USE_CRYPTO_SERVICE)
  add_library(crypt_commands crypt_commands.c)
  target_link_libraries(crypt_commands PRIVATE ap_service crypt_service sqlite_macconn_writer mac_mapper eloop firewall_service base64 log os)
endif ()

add_library(system_commands system_commands.c)
target_link_libraries(system_commands PRIVATE subscriber_events ap_service sqlite_macconn_writer mac_mapper eloop firewall_service iface_mapper base64 log os)

add_library(cmd_processor cmd_processor.c)
if (USE_CRYPTO_SERVICE)
  target_link_libraries(cmd_processor PUBLIC supervisor_config PRIVATE system_commands crypt_commands monitor_commands network_commands sqlite_fingerprint_writer mac_mapper domain net log os firewall_service iface base64)
else ()
  target_link_libraries(cmd_processor PUBLIC supervisor_config PRIVATE system_commands monitor_commands network_commands sqlite_fingerprint_writer mac_mapper domain net log os firewall_service iface base64)
endif ()

add_library(supervisor_config INTERFACE)
set_target_properties(supervisor_config PROPERTIES PUBLIC_HEADER "supervisor_config.h")
target_link_libraries(supervisor_config INTERFACE SQLite::sqlite iface)

add_library(supervisor supervisor.c)
target_include_directories(supervisor PUBLIC $<TARGET_PROPERTY:iface,INCLUDE_DIRECTORIES>)
target_link_libraries(supervisor PRIVATE capture_config network_commands sqlite_alert_writer sqlite_fingerprint_writer cmd_processor domain log firewall_service)
