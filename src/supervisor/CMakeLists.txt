include_directories (
  "${EDGESEC_SOURCE_DIR}/src"
)

add_library(bridge_list bridge_list.c)
target_link_libraries(bridge_list log os)

add_library(mac_mapper mac_mapper.c)
target_link_libraries(mac_mapper bridge_list log os)

add_library(sqlite_fingerprint_writer sqlite_fingerprint_writer.c)
target_include_directories(sqlite_fingerprint_writer PRIVATE ${LIBSQLITE_INCLUDE_DIR})
target_link_libraries(sqlite_fingerprint_writer sqliteu squeue log os ${LIBSQLITE_LIB})

add_library(sqlite_macconn_writer sqlite_macconn_writer.c)
target_include_directories(sqlite_macconn_writer PRIVATE ${LIBSQLITE_INCLUDE_DIR})
target_link_libraries(sqlite_macconn_writer sqliteu squeue log os ${LIBSQLITE_LIB})

add_library(network_commands network_commands.c)
target_link_libraries(network_commands crypt_service capture_config sqlite_macconn_writer mac_mapper eloop iptables log os)

add_library(cmd_processor cmd_processor.c)
target_link_libraries(cmd_processor network_commands sqlite_fingerprint_writer mac_mapper domain log os iptables if)

add_library(supervisor supervisor.c)
target_link_libraries(supervisor sqlite_fingerprint_writer cmd_processor domain log iptables)
