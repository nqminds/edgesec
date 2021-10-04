include_directories (
  "${EDGESEC_SOURCE_DIR}/src"
)

add_library(bridge_list bridge_list.c)
target_link_libraries(bridge_list PRIVATE log os)

add_library(mac_mapper mac_mapper.c)
target_link_libraries(mac_mapper PRIVATE bridge_list log os)

add_library(subscriber_events subscriber_events.c)
target_link_libraries(subscriber_events PRIVATE log os domain)

add_library(sqlite_fingerprint_writer sqlite_fingerprint_writer.c)
target_include_directories(sqlite_fingerprint_writer PRIVATE ${LIBSQLITE_INCLUDE_DIR})
target_link_libraries(sqlite_fingerprint_writer PRIVATE sqliteu squeue log os ${LIBSQLITE_LIB})

add_library(sqlite_alert_writer sqlite_alert_writer.c)
target_include_directories(sqlite_alert_writer PRIVATE ${LIBSQLITE_INCLUDE_DIR})
target_link_libraries(sqlite_alert_writer PRIVATE sqliteu squeue log os ${LIBSQLITE_LIB})

add_library(sqlite_macconn_writer sqlite_macconn_writer.c)
target_include_directories(sqlite_macconn_writer PRIVATE ${LIBSQLITE_INCLUDE_DIR})
target_link_libraries(sqlite_macconn_writer PRIVATE sqliteu squeue log os ${LIBSQLITE_LIB})

add_library(network_commands network_commands.c)
target_include_directories(network_commands PRIVATE ${LIBSQLITE_INCLUDE_DIR})
target_link_libraries(network_commands PRIVATE ap_service crypt_service capture_config sqlite_macconn_writer mac_mapper eloop iptables base64 log os)

add_library(monitor_commands monitor_commands.c)
target_include_directories(monitor_commands PRIVATE ${LIBSQLITE_INCLUDE_DIR})
target_link_libraries(monitor_commands PRIVATE subscriber_events sqlite_alert_writer ap_service crypt_service capture_config sqlite_macconn_writer mac_mapper eloop iptables base64 log os)

add_library(crypt_commands crypt_commands.c)
target_include_directories(crypt_commands PRIVATE ${LIBSQLITE_INCLUDE_DIR})
target_link_libraries(crypt_commands PRIVATE ap_service crypt_service capture_config sqlite_macconn_writer mac_mapper eloop iptables base64 log os)

add_library(system_commands system_commands.c)
target_include_directories(system_commands PRIVATE ${LIBSQLITE_INCLUDE_DIR})
target_link_libraries(system_commands PRIVATE subscriber_events ap_service crypt_service capture_config sqlite_macconn_writer mac_mapper eloop iptables base64 log os)

add_library(cmd_processor cmd_processor.c)
target_include_directories(cmd_processor PRIVATE ${LIBSQLITE_INCLUDE_DIR})
target_link_libraries(cmd_processor PRIVATE system_commands crypt_commands monitor_commands network_commands sqlite_fingerprint_writer mac_mapper domain log os iptables if base64)

add_library(supervisor supervisor.c)
target_include_directories(supervisor PRIVATE ${LIBSQLITE_INCLUDE_DIR})
target_link_libraries(supervisor PRIVATE network_commands sqlite_alert_writer sqlite_fingerprint_writer cmd_processor domain log iptables)
