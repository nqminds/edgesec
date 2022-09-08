include_directories(
  "${PROJECT_SOURCE_DIR}/src"
)

add_executable(test_hostapd test_hostapd.c)
target_link_libraries(test_hostapd PRIVATE hostapd iface os log cmocka::cmocka)
target_link_options(test_hostapd
  PRIVATE
  "LINKER:--wrap=kill_process,--wrap=signal_process,--wrap=reset_interface,--wrap=run_process,--wrap=list_dir,--wrap=check_sock_file_exists"
)

if (USE_UCI_SERVICE)
  target_link_libraries(test_hostapd PRIVATE __wrap_uwrt_init_context)
endif()

add_executable(test_ap_service test_ap_service.c)
target_link_libraries(test_ap_service PRIVATE ap_service hostapd iface os log cmocka::cmocka)
# sqlite3.h required by src/supervisor/supervisor_config.h
target_link_options(test_ap_service
  PRIVATE
  "LINKER:--wrap=close,--wrap=generate_vlan_conf,--wrap=run_ap_process,--wrap=generate_hostapd_conf,--wrap=signal_ap_process,--wrap=create_domain_client,--wrap=eloop_register_read_sock,--wrap=write_domain_data_s,--wrap=writeread_domain_data_str"
)

add_test(NAME test_hostapd COMMAND test_hostapd)
set_tests_properties(test_hostapd
  PROPERTIES
  WILL_FAIL FALSE)

add_test(NAME test_ap_service COMMAND test_ap_service)
set_tests_properties(test_ap_service
  PROPERTIES
  WILL_FAIL FALSE)
