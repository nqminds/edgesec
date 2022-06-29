include_directories(
  "${PROJECT_SOURCE_DIR}/src"
)

add_executable(test_dnsmasq test_dnsmasq.c)
target_link_libraries(test_dnsmasq PRIVATE dnsmasq log cmocka::cmocka)
set_target_properties(test_dnsmasq
  PROPERTIES
  LINK_FLAGS  "-Wl,--wrap=kill_process -Wl,--wrap=run_process -Wl,--wrap=is_proc_running -Wl,--wrap=signal_process"
)

add_executable(test_dhcp_service test_dhcp_service.c)
target_link_libraries(test_dhcp_service PRIVATE dhcp_service dnsmasq log cmocka::cmocka)
set_target_properties(test_dhcp_service
  PROPERTIES
  LINK_FLAGS  "-Wl,--wrap=generate_dnsmasq_conf -Wl,--wrap=generate_dnsmasq_script -Wl,--wrap=run_dhcp_process -Wl,--wrap=kill_dhcp_process -Wl,--wrap=clear_dhcp_lease_entry"
)

add_test(NAME test_dnsmasq COMMAND test_dnsmasq)
set_tests_properties(test_dnsmasq
  PROPERTIES
  WILL_FAIL FALSE)

add_test(NAME test_dhcp_service COMMAND test_dhcp_service)
set_tests_properties(test_dhcp_service
  PROPERTIES
  WILL_FAIL FALSE)
