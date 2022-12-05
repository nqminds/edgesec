include_directories(
  "${PROJECT_SOURCE_DIR}/src"
)

add_cmocka_test(test_bridge_list
  SOURCES test_bridge_list.c
  LINK_LIBRARIES bridge_list net log cmocka::cmocka
)

add_cmocka_test(test_supervisor_utils
  SOURCES test_supervisor_utils.c
  LINK_LIBRARIES supervisor_utils net log cmocka::cmocka
)

add_cmocka_test(test_supervisor
  SOURCES test_supervisor.c
  LINK_LIBRARIES supervisor_utils sqlite_macconn_writer supervisor net log cmocka::cmocka
)

add_cmocka_test(test_sockctl_server
  SOURCES test_sockctl_server.c
  LINK_LIBRARIES sockctl os log cmocka::cmocka
)
if(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
  # Abstract Unix domain sockets are only supported on Linux, but save a bit of writing
  # to the disk
  target_compile_definitions(test_sockctl_server PRIVATE USE_ABSTRACT_UNIX_DOMAIN_SOCKETS)
endif()

add_cmocka_test(test_cmd_processor
  SOURCES test_cmd_processor.c
  LINK_LIBRARIES cmd_processor iptables log cmocka::cmocka
)
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

add_cmocka_test(test_mac_mapper
  SOURCES test_mac_mapper.c
  LINK_LIBRARIES log os mac_mapper cmocka::cmocka
)

add_cmocka_test(test_sqlite_macconn_writer
  SOURCES test_sqlite_macconn_writer.c
  LINK_LIBRARIES sqlite_macconn_writer sqliteu os log cmocka::cmocka
)
target_link_options(test_sqlite_macconn_writer
  PRIVATE
  "LINKER:--wrap=sqlite3_open"
)
