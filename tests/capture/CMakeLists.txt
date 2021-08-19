include_directories (
  "${EDGESEC_SOURCE_DIR}/src"
  "${CMAKE_CURRENT_BINARY_DIR}"
)

if (BUILD_NDPI_LIB)
  include_directories ("${LIBNDPI_INCLUDE_PATH}")
endif ()

if (BUILD_PCAP_LIB)
  include_directories ("${LIBPCAP_INCLUDE_PATH}")
endif ()

if (BUILD_SQLITE_LIB)
  include_directories ("${LIBSQLITE_INCLUDE_DIR}")
endif ()

add_executable(test_default_analyser test_default_analyser.c)
target_link_libraries(test_default_analyser PRIVATE default_analyser packet_queue os log cmocka-static)
set_target_properties(test_default_analyser
  PROPERTIES
  LINK_FLAGS  "-Wl,--wrap=open_sqlite_header_db -Wl,--wrap=open_sqlite_pcap_db -Wl,--wrap=free_sqlite_header_db -Wl,--wrap=free_sqlite_pcap_db -Wl,--wrap=run_pcap -Wl,--wrap=close_pcap -Wl,--wrap=eloop_init -Wl,--wrap=eloop_register_read_sock -Wl,--wrap=eloop_register_timeout -Wl,--wrap=eloop_run -Wl,--wrap=eloop_destroy -Wl,--wrap=run_register_db -Wl,--wrap=extract_packets -Wl,--wrap=push_packet_queue -Wl,--wrap=push_pcap_queue"
)

if (BUILD_NDPI_LIB)
  add_executable(test_ndpi_analyser test_ndpi_analyser.c)
  target_link_libraries(test_ndpi_analyser PRIVATE ndpi_analyser if os log cmocka-static)
  set_target_properties(test_ndpi_analyser
    PROPERTIES
    LINK_FLAGS  "-Wl,--wrap=pthread_mutex_init -Wl,--wrap=create_domain_client -Wl,--wrap=run_pcap -Wl,--wrap=pthread_create -Wl,--wrap=pthread_join -Wl,--wrap=close_domain -Wl,--wrap=capture_pcap_stop -Wl,--wrap=pthread_mutex_destroy"
  )
endif()

add_executable(test_packet_queue test_packet_queue.c)
target_link_libraries(test_packet_queue PRIVATE packet_queue os log cmocka-static)

add_executable(test_pcap_queue test_pcap_queue.c)
target_link_libraries(test_pcap_queue PRIVATE pcap_queue os log cmocka-static)

add_executable(test_capture_config test_capture_config.c)
target_link_libraries(test_capture_config PRIVATE capture_config os log cmocka-static)

add_executable(test_sqlite_pcap_writer test_sqlite_pcap_writer.c)
target_link_libraries(test_sqlite_pcap_writer PRIVATE sqlite_pcap_writer sqliteu os log cmocka-static)
set_target_properties(test_sqlite_pcap_writer
  PROPERTIES
  LINK_FLAGS  "-Wl,--wrap=sqlite3_open"
)

add_executable(test_sqlite_header_writer test_sqlite_header_writer.c)
target_link_libraries(test_sqlite_header_writer PRIVATE sqlite_header_writer sqliteu os log cmocka-static)
set_target_properties(test_sqlite_header_writer
  PROPERTIES
  LINK_FLAGS  "-Wl,--wrap=sqlite3_open"
)

add_test(NAME test_default_analyser COMMAND test_default_analyser)
set_tests_properties(test_default_analyser
  PROPERTIES
  WILL_FAIL FALSE)

if (BUILD_NDPI_LIB)
  add_test(NAME test_ndpi_analyser COMMAND test_ndpi_analyser)
  set_tests_properties(test_ndpi_analyser
    PROPERTIES
    WILL_FAIL FALSE)
endif ()

add_test(NAME test_packet_queue COMMAND test_packet_queue)
set_tests_properties(test_packet_queue
  PROPERTIES
  WILL_FAIL FALSE)

add_test(NAME test_pcap_queue COMMAND test_pcap_queue)
set_tests_properties(test_pcap_queue
  PROPERTIES
  WILL_FAIL FALSE)

add_test(NAME test_capture_config COMMAND test_capture_config)
set_tests_properties(test_capture_config
  PROPERTIES
  WILL_FAIL FALSE)

add_test(NAME test_sqlite_pcap_writer COMMAND test_sqlite_pcap_writer)
set_tests_properties(test_sqlite_pcap_writer
  PROPERTIES
  WILL_FAIL FALSE)

add_test(NAME test_sqlite_header_writer COMMAND test_sqlite_header_writer)
set_tests_properties(test_sqlite_header_writer
  PROPERTIES
  WILL_FAIL FALSE)