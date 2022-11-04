add_subdirectory(./middlewares)

include_directories (
  "${PROJECT_SOURCE_DIR}/src"
)

add_cmocka_test(test_capture_service
  SOURCES test_capture_service.c
  LINK_LIBRARIES PCAP::pcap SQLite::SQLite3 capture_service packet_decoder os log cmocka::cmocka
)
target_link_options(test_capture_service
  PRIVATE
  "LINKER:--wrap=open_sqlite_header_db,--wrap=open_sqlite_pcap_db,--wrap=free_sqlite_header_db,--wrap=free_sqlite_pcap_db,--wrap=run_pcap,--wrap=close_pcap,--wrap=eloop_init,--wrap=eloop_register_read_sock,--wrap=eloop_register_timeout,--wrap=eloop_run,--wrap=eloop_free,--wrap=run_register_db,--wrap=extract_packets,--wrap=push_packet_queue,--wrap=push_pcap_queue"
)
