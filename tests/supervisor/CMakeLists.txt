include_directories(
  "${PROJECT_SOURCE_DIR}/src"
)

add_executable(test_bridge_list test_bridge_list.c)
target_link_libraries(test_bridge_list PRIVATE bridge_list net log cmocka::cmocka)

add_executable(test_supervisor_utils test_supervisor_utils.c)
target_link_libraries(test_supervisor_utils PRIVATE supervisor_utils bridge_list net log cmocka::cmocka)

add_executable(test_sockctl_server test_sockctl_server.c)
target_link_libraries(test_sockctl_server PRIVATE sockctl os log cmocka::cmocka)
if(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
  # Abstract Unix domain sockets are only supported on Linux, but save a bit of writing
  # to the disk
  target_compile_definitions(test_sockctl_server PRIVATE USE_ABSTRACT_UNIX_DOMAIN_SOCKETS)
endif()

add_executable(test_cmd_processor test_cmd_processor.c)
target_link_libraries(test_cmd_processor PRIVATE cmd_processor iptables log cmocka::cmocka)
target_link_options(test_cmd_processor PRIVATE
  "LINKER:--wrap=write_socket_data,--wrap=accept_mac_cmd,--wrap=deny_mac_cmd"
  "LINKER:--wrap=add_nat_cmd,--wrap=remove_nat_cmd,--wrap=assign_psk_cmd"
  "LINKER:--wrap=set_ip_cmd,--wrap=add_bridge_mac_cmd,--wrap=add_bridge_ip_cmd"
  "LINKER:--wrap=set_fingerprint_cmd,--wrap=query_fingerprint_cmd"
  "LINKER:--wrap=clear_psk_cmd,--wrap=get_mac_mapper,--wrap=remove_bridge_cmd"
  "LINKER:--wrap=clear_bridges_cmd,--wrap=subscribe_events_cmd,--wrap=register_ticket_cmd"
)

if (USE_CRYPTO_SERVICE)
  target_link_options(test_cmd_processor PRIVATE
    "LINKER:--wrap=gen_randkey_cmd,--wrap=gen_privkey_cmd,--wrap=gen_pubkey_cmd"
    "LINKER:--wrap=gen_cert_cmd,--wrap=put_crypt_cmd,--wrap=get_crypt_cmd"
    "LINKER:--wrap=encrypt_blob_cmd,--wrap=decrypt_blob_cmd,--wrap=sign_blob_cmd"
  )
endif ()

add_executable(test_mac_mapper test_mac_mapper.c)
target_link_libraries(test_mac_mapper PRIVATE log os mac_mapper cmocka::cmocka)

add_executable(test_sqlite_macconn_writer test_sqlite_macconn_writer.c)
target_link_libraries(test_sqlite_macconn_writer PRIVATE sqlite_macconn_writer sqliteu os log cmocka::cmocka)
target_link_options(test_sqlite_macconn_writer
  PRIVATE
  "LINKER:--wrap=sqlite3_open"
)

add_test(NAME test_supervisor_utils COMMAND test_supervisor_utils)
set_tests_properties(test_supervisor_utils
  PROPERTIES
  WILL_FAIL FALSE)

add_test(NAME test_bridge_list COMMAND test_bridge_list)
set_tests_properties(test_bridge_list
  PROPERTIES
  WILL_FAIL FALSE)

add_test(NAME test_sockctl_server COMMAND test_sockctl_server)
set_tests_properties(test_sockctl_server
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
