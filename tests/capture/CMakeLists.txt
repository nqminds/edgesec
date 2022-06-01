include_directories (
  "${EDGESEC_SOURCE_DIR}/src"
)

add_executable(test_capture_service test_capture_service.c)
target_include_directories(test_capture_service PRIVATE ${LIBPCAP_INCLUDE_PATH} ${LIBSQLITE_INCLUDE_DIR})
target_link_libraries(test_capture_service PRIVATE capture_service packet_queue os log cmocka::cmocka)
set_target_properties(test_capture_service
  PROPERTIES
  LINK_FLAGS  "-Wl,--wrap=open_sqlite_header_db -Wl,--wrap=open_sqlite_pcap_db -Wl,--wrap=free_sqlite_header_db -Wl,--wrap=free_sqlite_pcap_db -Wl,--wrap=run_pcap -Wl,--wrap=close_pcap -Wl,--wrap=eloop_init -Wl,--wrap=eloop_register_read_sock -Wl,--wrap=eloop_register_timeout -Wl,--wrap=eloop_run -Wl,--wrap=eloop_free -Wl,--wrap=run_register_db -Wl,--wrap=extract_packets -Wl,--wrap=push_packet_queue -Wl,--wrap=push_pcap_queue"
)

add_executable(test_packet_queue test_packet_queue.c)
target_include_directories(test_packet_queue PRIVATE ${LIBPCAP_INCLUDE_PATH})
target_link_libraries(test_packet_queue PRIVATE packet_queue os log cmocka::cmocka)

add_executable(test_pcap_queue test_pcap_queue.c)
target_include_directories(test_pcap_queue PRIVATE ${LIBPCAP_INCLUDE_PATH})
target_link_libraries(test_pcap_queue PRIVATE pcap_queue os log cmocka::cmocka)

add_executable(test_pcap_middleware test_pcap_middleware.c)
target_include_directories(test_pcap_middleware PRIVATE ${LIBSQLITE_INCLUDE_DIR})
target_link_libraries(test_pcap_middleware PRIVATE pcap_middleware sqliteu os log cmocka::cmocka)

add_executable(test_header_middleware test_header_middleware.c)
target_include_directories(test_header_middleware PRIVATE ${LIBPCAP_INCLUDE_PATH} ${LIBSQLITE_INCLUDE_DIR})
target_link_libraries(test_header_middleware PRIVATE header_middleware sqliteu os log cmocka::cmocka)
set_target_properties(test_header_middleware
  PROPERTIES
  LINK_FLAGS  "-Wl,--wrap=sqlite3_open"
)

add_test(NAME test_default_analyser COMMAND test_default_analyser)
set_tests_properties(test_default_analyser
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

add_test(NAME test_pcap_middleware COMMAND test_pcap_middleware)
set_tests_properties(test_pcap_middleware
  PROPERTIES
  WILL_FAIL FALSE)

add_test(NAME test_header_middleware COMMAND test_header_middleware)
set_tests_properties(test_header_middleware
  PROPERTIES
  WILL_FAIL FALSE)
