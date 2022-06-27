add_subdirectory(./middlewares)

include_directories (
  "${EDGESEC_SOURCE_DIR}/src",
)

add_executable(test_capture_service test_capture_service.c)
target_link_libraries(test_capture_service PUBLIC PCAP::pcap SQLite::SQLite3 PRIVATE capture_service packet_decoder os log cmocka::cmocka)
set_target_properties(test_capture_service
  PROPERTIES
  LINK_FLAGS  "-Wl,--wrap=open_sqlite_header_db -Wl,--wrap=open_sqlite_pcap_db -Wl,--wrap=free_sqlite_header_db -Wl,--wrap=free_sqlite_pcap_db -Wl,--wrap=run_pcap -Wl,--wrap=close_pcap -Wl,--wrap=eloop_init -Wl,--wrap=eloop_register_read_sock -Wl,--wrap=eloop_register_timeout -Wl,--wrap=eloop_run -Wl,--wrap=eloop_free -Wl,--wrap=run_register_db -Wl,--wrap=extract_packets -Wl,--wrap=push_packet_queue -Wl,--wrap=push_pcap_queue"
)

add_test(NAME test_capture_service COMMAND test_capture_service)
set_tests_properties(test_capture_service
  PROPERTIES
  WILL_FAIL FALSE)
