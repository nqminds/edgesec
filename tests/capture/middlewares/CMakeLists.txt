add_cmocka_test(test_header_middleware
  SOURCES test_header_middleware.c
  LINK_LIBRARIES PCAP::pcap SQLite::SQLite3 header_middleware sqliteu os log cmocka::cmocka
)
target_link_options(test_header_middleware
  PRIVATE
  "LINKER:--wrap=sqlite3_open"
)

if (USE_PROTOBUF_MIDDLEWARE)
  add_cmocka_test(test_protobuf_utils
    SOURCES test_protobuf_utils.c
    LINK_LIBRARIES PCAP::pcap protobuf_utils sync.pb-c eth.pb-c os log cmocka::cmocka
  )
endif()

add_cmocka_test(test_sqlite_header
  SOURCES test_sqlite_header.c
  LINK_LIBRARIES sqlite_header os log Threads::Threads cmocka::cmocka SQLite::SQLite3
)
set_tests_properties(test_sqlite_header
  PROPERTIES
  WILL_FAIL FALSE
  ENVIRONMENT CMOCKA_TEST_ABORT='1' # these tests uses threading
)

add_cmocka_test(test_packet_queue
  SOURCES test_packet_queue.c
  LINK_LIBRARIES PCAP::pcap SQLite::SQLite3 packet_queue os log cmocka::cmocka
)

add_cmocka_test(test_pcap_queue
  SOURCES test_pcap_queue.c
  LINK_LIBRARIES pcap_queue os log cmocka::cmocka
)

add_cmocka_test(test_sqlite_pcap
  SOURCES test_sqlite_pcap.c
  LINK_LIBRARIES sqlite_pcap sqliteu os log Threads::Threads cmocka::cmocka
)
