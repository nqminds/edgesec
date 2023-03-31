include_directories(
  "${PROJECT_SOURCE_DIR}/src"
)

add_cmocka_test(test_dhcp_config_utils
  SOURCES test_dhcp_config_utils.c
  LINK_LIBRARIES dhcp_config dhcp_config_utils cmocka::cmocka
)

add_cmocka_test(test_dnsmasq
  SOURCES test_dnsmasq.c
  LINK_LIBRARIES dhcp_config dhcp_config_utils dnsmasq log cmocka::cmocka
)
target_link_options(test_dnsmasq
  PRIVATE
  "LINKER:--wrap=kill_process,--wrap=run_process,--wrap=is_proc_running,--wrap=signal_process"
)
if (USE_UCI_SERVICE)
  target_link_libraries(test_dnsmasq PRIVATE __wrap_uwrt_init_context)
endif()

add_cmocka_test(test_dhcp_service
  SOURCES test_dhcp_service.c
  LINK_LIBRARIES dhcp_service dnsmasq log cmocka::cmocka
)
target_link_options(test_dhcp_service
  PRIVATE
  "LINKER:--wrap=generate_dnsmasq_conf,--wrap=generate_dnsmasq_script,--wrap=run_dhcp_process,--wrap=kill_dhcp_process,--wrap=clear_dhcp_lease_entry"
)
