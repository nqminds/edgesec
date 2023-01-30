include_directories(
  "${PROJECT_SOURCE_DIR}/src"
)

add_cmocka_test(test_hostapd
  SOURCES test_hostapd.c
  LINK_LIBRARIES ap_config hostapd iface os log cmocka::cmocka
)
target_link_options(test_hostapd
  PRIVATE
  "LINKER:--wrap=kill_process,--wrap=signal_process,--wrap=reset_interface,--wrap=run_process,--wrap=list_dir,--wrap=check_sock_file_exists"
)

if (USE_UCI_SERVICE)
  target_link_libraries(test_hostapd PRIVATE __wrap_uwrt_init_context)
endif()

add_cmocka_test(test_ap_service
  SOURCES test_ap_service.c
  LINK_LIBRARIES ap_service hostapd iface os log cmocka::cmocka
)
target_link_options(test_ap_service
  PRIVATE
  "LINKER:--wrap=close,--wrap=generate_vlan_conf,--wrap=run_ap_process,--wrap=generate_hostapd_conf,--wrap=signal_ap_process,--wrap=create_domain_client,--wrap=edge_eloop_register_read_sock,--wrap=write_domain_data_s,--wrap=writeread_domain_data_str"
)

add_cmocka_test(test_ap_service_failure
  SOURCES test_ap_service_failure.c
  LINK_LIBRARIES ap_service cmocka::cmocka
)
target_link_options(test_ap_service_failure
  PRIVATE
  "LINKER:--wrap=writeread_domain_data_str,--wrap=malloc"
)
