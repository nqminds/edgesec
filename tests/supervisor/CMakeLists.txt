include_directories(
  "${EDGESEC_SOURCE_DIR}/src"
  "${CMOCKA_INCLUDE_DIR}"
)

add_executable(test_bridge_list test_bridge_list.c)
target_link_libraries(test_bridge_list PRIVATE bridge_list log cmocka-static)

add_executable(test_domain_server test_domain_server.c)
target_link_libraries(test_domain_server PRIVATE domain os log cmocka-static)

add_executable(test_cmd_processor test_cmd_processor.c)
target_link_libraries(test_cmd_processor PRIVATE cmd_processor iptables log engine cmocka-static)

set_target_properties(test_cmd_processor
        PROPERTIES
        LINK_FLAGS  "-Wl,--wrap=write_domain_data -Wl,--wrap=accept_mac_cmd -Wl,--wrap=deny_mac_cmd -Wl,--wrap=add_nat_cmd -Wl,--wrap=remove_nat_cmd -Wl,--wrap=assign_psk_cmd -Wl,--wrap=set_ip_cmd -Wl,--wrap=add_bridge_cmd -Wl,--wrap=remove_bridge_cmd -Wl,--wrap=set_fingerprint_cmd -Wl,--wrap=query_fingerprint_cmd -Wl,--wrap=register_ticket_cmd -Wl,--wrap=clear_psk_cmd -Wl,--wrap=get_mac_mapper"
)

add_executable(test_mac_mapper test_mac_mapper.c)
target_link_libraries(test_mac_mapper PRIVATE log system_checks os mac_mapper cmocka-static)

add_executable(test_sqlite_fingerprint_writer test_sqlite_fingerprint_writer.c)
target_link_libraries(test_sqlite_fingerprint_writer PRIVATE sqlite_fingerprint_writer sqliteu os log cmocka-static)
set_target_properties(test_sqlite_fingerprint_writer
  PROPERTIES
  LINK_FLAGS  "-Wl,--wrap=sqlite3_open"
)

add_executable(test_sqlite_macconn_writer test_sqlite_macconn_writer.c)
target_link_libraries(test_sqlite_macconn_writer PRIVATE sqlite_macconn_writer sqliteu os log cmocka-static)
set_target_properties(test_sqlite_macconn_writer
  PROPERTIES
  LINK_FLAGS  "-Wl,--wrap=sqlite3_open"
)

add_test(NAME test_bridge_list COMMAND test_bridge_list)
set_tests_properties(test_bridge_list
  PROPERTIES
  WILL_FAIL FALSE)

add_test(NAME test_domain_server COMMAND test_domain_server)
set_tests_properties(test_domain_server
  PROPERTIES
  WILL_FAIL FALSE)

add_test(NAME test_cmd_processor COMMAND test_cmd_processor)
set_tests_properties(test_cmd_processor
  PROPERTIES
  WILL_FAIL FALSE)

add_test(NAME test_mac_mapper COMMAND test_mac_mapper)
set_tests_properties(test_mac_mapper
  PROPERTIES
  WILL_FAIL FALSE)
  
add_test(NAME test_sqlite_fingerprint_writer COMMAND test_sqlite_fingerprint_writer)
set_tests_properties(test_sqlite_fingerprint_writer
  PROPERTIES
  WILL_FAIL FALSE)

add_test(NAME test_sqlite_macconn_writer COMMAND test_sqlite_macconn_writer)
set_tests_properties(test_sqlite_macconn_writer
  PROPERTIES
  WILL_FAIL FALSE)
  