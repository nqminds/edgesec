include_directories(
  "${EDGESEC_SOURCE_DIR}/src"
  "${CMOCKA_INCLUDE_DIR}"
)

add_executable(test_default_analyser test_default_analyser.c)
target_link_libraries(test_default_analyser default_analyser packet_queue os log ${CMOCKA_LIB})
set_target_properties(test_default_analyser
  PROPERTIES
  LINK_FLAGS  "-Wl,--wrap=open_sqlite_header_db -Wl,--wrap=open_sqlite_pcap_db -Wl,--wrap=free_sqlite_header_db -Wl,--wrap=free_sqlite_pcap_db -Wl,--wrap=run_pcap -Wl,--wrap=close_pcap -Wl,--wrap=eloop_init -Wl,--wrap=eloop_register_read_sock -Wl,--wrap=eloop_register_timeout -Wl,--wrap=eloop_run -Wl,--wrap=eloop_destroy -Wl,--wrap=run_register_db -Wl,--wrap=extract_packets -Wl,--wrap=push_packet_queue -Wl,--wrap=push_pcap_queue"
)

add_executable(test_capture_service test_capture_service.c)
target_link_libraries(test_capture_service capture_service os log ${CMOCKA_LIB})

add_executable(test_sqlite_pcap_writer test_sqlite_pcap_writer.c)
target_link_libraries(test_sqlite_pcap_writer os log ${CMOCKA_LIB})

add_executable(test_sqlite_header_writer test_sqlite_header_writer.c)
target_link_libraries(test_sqlite_header_writer os log ${CMOCKA_LIB})

add_executable(test_pcap_service test_pcap_service.c)
target_link_libraries(test_pcap_service os log ${CMOCKA_LIB})

add_test(NAME test_default_analyser COMMAND test_default_analyser)
set_tests_properties(test_default_analyser
  PROPERTIES
  WILL_FAIL FALSE)

add_test(NAME test_sqlite_pcap_writer COMMAND test_sqlite_pcap_writer)
set_tests_properties(test_sqlite_pcap_writer
  PROPERTIES
  WILL_FAIL FALSE)

add_test(NAME test_capture_service COMMAND test_capture_service)
set_tests_properties(test_capture_service
  PROPERTIES
  WILL_FAIL FALSE)
  
add_test(NAME test_sqlite_header_writer COMMAND test_sqlite_header_writer)
set_tests_properties(test_sqlite_header_writer
  PROPERTIES
  WILL_FAIL FALSE)

add_test(NAME test_pcap_service COMMAND test_pcap_service)
set_tests_properties(test_pcap_service
  PROPERTIES
  WILL_FAIL FALSE)
  