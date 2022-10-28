add_executable(test_header_middleware test_header_middleware.c)
target_link_libraries(test_header_middleware PUBLIC PCAP::pcap SQLite::SQLite3 PRIVATE header_middleware sqliteu os log cmocka::cmocka)
target_link_options(test_header_middleware
  PRIVATE
  "LINKER:--wrap=sqlite3_open"
)

add_executable(test_protobuf_utils test_protobuf_utils.c)
target_link_libraries(test_protobuf_utils PUBLIC PCAP::pcap PRIVATE protobuf_utils sync.pb-c eth.pb-c os log cmocka::cmocka)

add_executable(test_sqlite_header test_sqlite_header.c)
target_link_libraries(test_sqlite_header PRIVATE sqlite_header os log Threads::Threads cmocka::cmocka SQLite::SQLite3)

add_executable(test_packet_queue test_packet_queue.c)
target_link_libraries(test_packet_queue PUBLIC PCAP::pcap SQLite::SQLite3 PRIVATE packet_queue os log cmocka::cmocka)

add_executable(test_pcap_queue test_pcap_queue.c)
target_link_libraries(test_pcap_queue PRIVATE pcap_queue os log cmocka::cmocka)

add_executable(test_sqlite_pcap test_sqlite_pcap.c)
target_link_libraries(test_sqlite_pcap PRIVATE sqlite_pcap sqliteu os log Threads::Threads cmocka::cmocka)

add_test(NAME test_header_middleware COMMAND test_header_middleware)
set_tests_properties(test_header_middleware
  PROPERTIES
  WILL_FAIL FALSE)

add_test(NAME test_protobuf_utils COMMAND test_protobuf_utils)
set_tests_properties(test_protobuf_utils
  PROPERTIES
  WILL_FAIL FALSE)

add_test(NAME test_sqlite_header COMMAND test_sqlite_header)
set_tests_properties(test_sqlite_header
  PROPERTIES
  WILL_FAIL FALSE
  ENVIRONMENT CMOCKA_TEST_ABORT='1' # these tests uses threading
)

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
