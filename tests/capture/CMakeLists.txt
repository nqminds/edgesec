include_directories(
  "${EDGESEC_SOURCE_DIR}/src"
  "${CMOCKA_INCLUDE_DIR}"
)

add_executable(test_capture_service test_capture_service.c)
target_link_libraries(test_capture_service os log ${CMOCKA_LIB})

add_executable(test_sqlite_pcap_writer test_sqlite_pcap_writer.c)
target_link_libraries(test_sqlite_pcap_writer os log ${CMOCKA_LIB})

add_executable(test_sqlite_header_writer test_sqlite_header_writer.c)
target_link_libraries(test_sqlite_header_writer os log ${CMOCKA_LIB})

add_executable(test_pcap_service test_pcap_service.c)
target_link_libraries(test_pcap_service os log ${CMOCKA_LIB})

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
  