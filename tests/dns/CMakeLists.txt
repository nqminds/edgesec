include_directories(
  "${PROJECT_SOURCE_DIR}/src"
)

add_executable(test_mdns_list test_mdns_list.c)
target_link_libraries(test_mdns_list PRIVATE os mdns_list log cmocka::cmocka)

add_executable(test_mdns_mapper test_mdns_mapper.c)
target_link_libraries(test_mdns_mapper PRIVATE mdns_mapper log cmocka::cmocka)

add_executable(test_command_mapper test_command_mapper.c)
target_link_libraries(test_command_mapper PRIVATE command_mapper log cmocka::cmocka)

add_executable(test_reflection_list test_reflection_list.c)
target_link_libraries(test_reflection_list PRIVATE os reflection_list log cmocka::cmocka)

if (USE_MDNS_SERVICE AND USE_CAPTURE_SERVICE)
  add_executable(test_mdns_service test_mdns_service.c)
  target_link_libraries(test_mdns_service PRIVATE mdns_service pcap_service log cmocka::cmocka)
  target_link_options(test_mdns_service
    PRIVATE
    "LINKER:--wrap=run_pcap,--wrap=eloop_register_read_sock,--wrap=eloop_init,--wrap=eloop_run,--wrap=eloop_free"
  )
endif ()

add_test(NAME test_mdns_list COMMAND test_mdns_list)
set_tests_properties(test_mdns_list
  PROPERTIES
  WILL_FAIL FALSE)

add_test(NAME test_mdns_mapper COMMAND test_mdns_mapper)
set_tests_properties(test_mdns_mapper
  PROPERTIES
  WILL_FAIL FALSE)

add_test(NAME test_command_mapper COMMAND test_command_mapper)
set_tests_properties(test_command_mapper
  PROPERTIES
  WILL_FAIL FALSE)

add_test(NAME test_reflection_list COMMAND test_reflection_list)
set_tests_properties(test_reflection_list
  PROPERTIES
  WILL_FAIL FALSE)

if (USE_MDNS_SERVICE AND USE_CAPTURE_SERVICE)
  add_test(NAME test_mdns_service COMMAND test_mdns_service)
  set_tests_properties(test_mdns_service
    PROPERTIES
    WILL_FAIL FALSE)
endif ()
