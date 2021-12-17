include_directories(
  "${EDGESEC_SOURCE_DIR}/src"
)

add_executable(test_hostapd test_hostapd.c)
target_link_libraries(test_hostapd PRIVATE hostapd if os log cmocka::cmocka)
set_target_properties(test_hostapd
  PROPERTIES
  LINK_FLAGS  "-Wl,--wrap=kill_process -Wl,--wrap=signal_process -Wl,--wrap=reset_interface -Wl,--wrap=run_process -Wl,--wrap=list_dir -Wl,--wrap=check_sock_file_exists"
)

add_executable(test_ap_service test_ap_service.c)
target_link_libraries(test_ap_service PRIVATE ap_service hostapd if os log cmocka::cmocka)
# sqlite3.h required by src/supervisor/supervisor_config.h
target_include_directories(test_ap_service PUBLIC ${LIBSQLITE_INCLUDE_DIR})
set_target_properties(test_ap_service
  PROPERTIES
  LINK_FLAGS  "-Wl,--wrap=close -Wl,--wrap=generate_vlan_conf -Wl,--wrap=run_ap_process -Wl,--wrap=generate_hostapd_conf -Wl,--wrap=signal_ap_process -Wl,--wrap=create_domain_client -Wl,--wrap=eloop_register_read_sock -Wl,--wrap=write_domain_data_s -Wl,--wrap=writeread_domain_data_str"
)

add_test(NAME test_hostapd COMMAND test_hostapd)
set_tests_properties(test_hostapd
  PROPERTIES
  WILL_FAIL FALSE)

add_test(NAME test_ap_service COMMAND test_ap_service)
set_tests_properties(test_ap_service
  PROPERTIES
  WILL_FAIL FALSE)
