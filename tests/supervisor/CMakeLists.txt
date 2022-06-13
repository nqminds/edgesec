include_directories(
  "${EDGESEC_SOURCE_DIR}/src"
)

add_executable(test_bridge_list test_bridge_list.c)
target_link_libraries(test_bridge_list PRIVATE bridge_list log cmocka::cmocka)

add_executable(test_domain_server test_domain_server.c)
target_link_libraries(test_domain_server PRIVATE domain os log cmocka::cmocka)

add_executable(test_cmd_processor test_cmd_processor.c)
target_link_libraries(test_cmd_processor PRIVATE cmd_processor iptables log engine cmocka::cmocka)

set(TEST_CMD_PROPS "-Wl,--wrap=write_domain_data -Wl,--wrap=accept_mac_cmd -Wl,--wrap=deny_mac_cmd")
set(TEST_CMD_PROPS "${TEST_CMD_PROPS} -Wl,--wrap=write_domain_data -Wl,--wrap=accept_mac_cmd -Wl,--wrap=deny_mac_cmd")
set(TEST_CMD_PROPS "${TEST_CMD_PROPS} -Wl,--wrap=add_nat_cmd -Wl,--wrap=remove_nat_cmd -Wl,--wrap=assign_psk_cmd")
set(TEST_CMD_PROPS "${TEST_CMD_PROPS} -Wl,--wrap=set_ip_cmd -Wl,--wrap=add_bridge_mac_cmd -Wl,--wrap=add_bridge_ip_cmd")
set(TEST_CMD_PROPS "${TEST_CMD_PROPS} -Wl,--wrap=set_fingerprint_cmd -Wl,--wrap=query_fingerprint_cmd")
set(TEST_CMD_PROPS "${TEST_CMD_PROPS} -Wl,--wrap=clear_psk_cmd -Wl,--wrap=get_mac_mapper -Wl,--wrap=remove_bridge_cmd")
set(TEST_CMD_PROPS "${TEST_CMD_PROPS} -Wl,--wrap=clear_bridges_cmd -Wl,--wrap=subscribe_events_cmd -Wl,--wrap=register_ticket_cmd")

if (USE_CRYPTO_SERVICE)
  set(TEST_CMD_PROPS "${TEST_CMD_PROPS} -Wl,--wrap=gen_randkey_cmd -Wl,--wrap=gen_privkey_cmd -Wl,--wrap=gen_pubkey_cmd")
  set(TEST_CMD_PROPS "${TEST_CMD_PROPS} -Wl,--wrap=gen_cert_cmd -Wl,--wrap=put_crypt_cmd -Wl,--wrap=get_crypt_cmd")
  set(TEST_CMD_PROPS "${TEST_CMD_PROPS} -Wl,--wrap=encrypt_blob_cmd -Wl,--wrap=decrypt_blob_cmd -Wl,--wrap=sign_blob_cmd")
endif ()

set_target_properties(test_cmd_processor PROPERTIES LINK_FLAGS ${TEST_CMD_PROPS})

add_executable(test_mac_mapper test_mac_mapper.c)
target_link_libraries(test_mac_mapper PRIVATE log os mac_mapper cmocka::cmocka)

add_executable(test_sqlite_macconn_writer test_sqlite_macconn_writer.c)
target_link_libraries(test_sqlite_macconn_writer PRIVATE sqlite_macconn_writer sqliteu os log cmocka::cmocka)
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

add_test(NAME test_sqlite_macconn_writer COMMAND test_sqlite_macconn_writer)
set_tests_properties(test_sqlite_macconn_writer
  PROPERTIES
  WILL_FAIL FALSE)
