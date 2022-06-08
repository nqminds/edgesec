include_directories (
  "${EDGESEC_SOURCE_DIR}/src"
)

add_library(bridge_list bridge_list.c)
target_link_libraries(bridge_list PRIVATE log os)

add_library(mac_mapper mac_mapper.c)
target_link_libraries(mac_mapper PRIVATE bridge_list net log os)

add_library(subscriber_events subscriber_events.c)
target_link_libraries(subscriber_events PUBLIC supervisor_config PRIVATE log os domain SQLite::SQLite3)

add_library(sqlite_macconn_writer sqlite_macconn_writer.c)
target_link_libraries(sqlite_macconn_writer PRIVATE sqliteu squeue log os SQLite::SQLite3)

add_library(network_commands network_commands.c)
if (USE_CRYPTO_SERVICE)
  target_link_libraries(network_commands PRIVATE dhcp_service ap_service crypt_service sqlite_macconn_writer mac_mapper eloop firewall_service base64 net log os)
else ()
  target_link_libraries(network_commands PRIVATE dhcp_service ap_service sqlite_macconn_writer mac_mapper eloop firewall_service base64 net log os)
endif ()

if (USE_CRYPTO_SERVICE)
  add_library(crypt_commands crypt_commands.c)
  target_link_libraries(crypt_commands PRIVATE ap_service crypt_service sqlite_macconn_writer mac_mapper eloop firewall_service base64 log os)
endif ()

add_library(system_commands system_commands.c)
target_link_libraries(system_commands PRIVATE subscriber_events ap_service sqlite_macconn_writer mac_mapper eloop firewall_service iface_mapper base64 log os)

add_library(cmd_processor cmd_processor.c)
target_include_directories(cmd_processor PUBLIC ${LIBSQLITE_INCLUDE_DIR})
if (USE_CRYPTO_SERVICE)
  target_link_libraries(cmd_processor PRIVATE system_commands crypt_commands network_commands mac_mapper domain net log os firewall_service iface base64)
else ()
  target_link_libraries(cmd_processor PRIVATE system_commands network_commands mac_mapper domain net log os firewall_service iface base64)
endif ()

add_library(supervisor_config INTERFACE)
set_target_properties(supervisor_config PROPERTIES PUBLIC_HEADER "supervisor_config.h")
target_link_libraries(supervisor_config INTERFACE SQLite::SQLite3 iface)

add_library(supervisor supervisor.c)
target_include_directories(supervisor PUBLIC $<TARGET_PROPERTY:iface,INCLUDE_DIRECTORIES>)
target_link_libraries(supervisor PUBLIC supervisor_config PRIVATE capture_service network_commands cmd_processor domain log firewall_service)
