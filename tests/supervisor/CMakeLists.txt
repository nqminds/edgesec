include_directories(
  "${EDGESEC_SOURCE_DIR}/src"
  "${CMOCKA_INCLUDE_DIR}"
)

add_executable(test_bridge_list test_bridge_list.c)
target_link_libraries(test_bridge_list bridge_list log ${CMOCKA_LIB})

add_executable(test_domain_server test_domain_server.c)
target_link_libraries(test_domain_server domain_server log ${CMOCKA_LIB})

add_executable(test_cmd_processor test_cmd_processor.c)
target_link_libraries(test_cmd_processor cmd_processor log ${CMOCKA_LIB})

add_test(NAME test_bridge_list COMMAND test_bridge_list)
set_tests_properties(test_bridge_list
  PROPERTIES
  WILL_FAIL FALSE)

add_test(NAME test_domain_server COMMAND test_domain_server)
set_tests_properties(test_domain_server
  PROPERTIES
  WILL_FAIL FALSE)

add_test(NAME test_cmd_processor COMMAND test_cmd_processor)
set_tests_properties(test_cmd_processor
  PROPERTIES
  WILL_FAIL FALSE)
