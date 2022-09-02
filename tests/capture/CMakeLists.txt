add_subdirectory(./middlewares)

include_directories (
  "${PROJECT_SOURCE_DIR}/src"
)

add_executable(test_capture_service test_capture_service.c)
target_link_libraries(test_capture_service PUBLIC PCAP::pcap SQLite::SQLite3 PRIVATE capture_service packet_decoder os log cmocka::cmocka)
target_link_options(test_capture_service
  PRIVATE
  "LINKER:--wrap=open_sqlite_header_db,--wrap=open_sqlite_pcap_db,--wrap=free_sqlite_header_db,--wrap=free_sqlite_pcap_db,--wrap=run_pcap,--wrap=close_pcap,--wrap=eloop_init,--wrap=eloop_register_read_sock,--wrap=eloop_register_timeout,--wrap=eloop_run,--wrap=eloop_free,--wrap=run_register_db,--wrap=extract_packets,--wrap=push_packet_queue,--wrap=push_pcap_queue"
)

add_test(NAME test_capture_service COMMAND test_capture_service)
set_tests_properties(test_capture_service
  PROPERTIES
  WILL_FAIL FALSE)
