include_directories (
  "${EDGESEC_SOURCE_DIR}/src"
)

add_executable(test_capture_service test_capture_service.c)
target_link_libraries(test_capture_service PUBLIC PCAP::pcap SQLite::SQLite3 PRIVATE capture_service packet_queue os log cmocka::cmocka)
set_target_properties(test_capture_service
  PROPERTIES
  LINK_FLAGS  "-Wl,--wrap=open_sqlite_header_db -Wl,--wrap=open_sqlite_pcap_db -Wl,--wrap=free_sqlite_header_db -Wl,--wrap=free_sqlite_pcap_db -Wl,--wrap=run_pcap -Wl,--wrap=close_pcap -Wl,--wrap=eloop_init -Wl,--wrap=eloop_register_read_sock -Wl,--wrap=eloop_register_timeout -Wl,--wrap=eloop_run -Wl,--wrap=eloop_free -Wl,--wrap=run_register_db -Wl,--wrap=extract_packets -Wl,--wrap=push_packet_queue -Wl,--wrap=push_pcap_queue"
)

add_executable(test_packet_queue test_packet_queue.c)
target_link_libraries(test_packet_queue PUBLIC PCAP::pcap SQLite::SQLite3 PRIVATE packet_queue os log cmocka::cmocka)

add_executable(test_pcap_queue test_pcap_queue.c)
target_link_libraries(test_pcap_queue PRIVATE pcap_queue os log cmocka::cmocka)

add_executable(test_sqlite_pcap test_sqlite_pcap.c)
target_link_libraries(test_sqlite_pcap PUBLIC SQLite::SQLite3 PRIVATE sqlite_pcap sqliteu os log cmocka::cmocka)

add_executable(test_header_middleware test_header_middleware.c)
target_link_libraries(test_header_middleware PUBLIC PCAP::pcap SQLite::SQLite3 PRIVATE header_middleware sqliteu os log cmocka::cmocka)
set_target_properties(test_header_middleware
  PROPERTIES
  LINK_FLAGS  "-Wl,--wrap=sqlite3_open"
)

add_test(NAME test_capture_service COMMAND test_capture_service)
set_tests_properties(test_capture_service
  PROPERTIES
  WILL_FAIL FALSE)

add_test(NAME test_packet_queue COMMAND test_packet_queue)
set_tests_properties(test_packet_queue
  PROPERTIES
  WILL_FAIL FALSE)

add_test(NAME test_pcap_queue COMMAND test_pcap_queue)
set_tests_properties(test_pcap_queue
  PROPERTIES
  WILL_FAIL FALSE)

add_test(NAME test_sqlite_pcap COMMAND test_sqlite_pcap)
set_tests_properties(test_sqlite_pcap
  PROPERTIES
  WILL_FAIL FALSE)

add_test(NAME test_header_middleware COMMAND test_header_middleware)
set_tests_properties(test_header_middleware
  PROPERTIES
  WILL_FAIL FALSE)
