include_directories(
  "${EDGESEC_SOURCE_DIR}/src"
)

add_executable(test_mdns_list test_mdns_list.c)
target_link_libraries(test_mdns_list PRIVATE mdns_list log cmocka::cmocka)

add_executable(test_mdns_mapper test_mdns_mapper.c)
target_link_libraries(test_mdns_mapper PRIVATE mdns_mapper log cmocka::cmocka)

add_test(NAME test_mdns_list COMMAND test_mdns_list)
set_tests_properties(test_mdns_list
  PROPERTIES
  WILL_FAIL FALSE)

add_test(NAME test_mdns_mapper COMMAND test_mdns_mapper)
set_tests_properties(test_mdns_mapper
  PROPERTIES
  WILL_FAIL FALSE)
