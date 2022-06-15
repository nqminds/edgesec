include_directories (
  "${EDGESEC_SOURCE_DIR}/src"
)

if (USE_CAPTURE_SERVICE)
  add_subdirectory(capture)
endif ()

if (USE_CRYPTO_SERVICE)
  add_subdirectory(crypt)
endif ()

add_subdirectory(utils)
add_subdirectory(supervisor)
if (USE_RADIUS_SERVICE)
  add_subdirectory(radius)
endif ()
add_subdirectory(ap)
add_subdirectory(dhcp)
if (USE_MDNS_SERVICE)
  add_subdirectory(dns)
endif ()

add_executable(test_runctl test_runctl.c)
target_link_libraries(test_runctl PUBLIC SQLite::SQLite3 PRIVATE runctl log os mac_mapper cmocka::cmocka)
set(TEST_RUNCTL_PROPS "-Wl,--wrap=get_vlan_mapper -Wl,--wrap=eloop_run -Wl,--wrap=get_commands_paths -Wl,--wrap=hmap_str_keychar_get")
set(TEST_RUNCTL_PROPS "${TEST_RUNCTL_PROPS} -Wl,--wrap=fw_init_context -Wl,--wrap=fw_set_ip_forward")
if (USE_CRYPTO_SERVICE)
  target_link_libraries(test_runctl PRIVATE crypt_service)
  set(TEST_RUNCTL_PROPS "${TEST_RUNCTL_PROPS} -Wl,--wrap=load_crypt_service")
endif ()
set(TEST_RUNCTL_PROPS "${TEST_RUNCTL_PROPS} -Wl,--wrap=iface_get_vlan -Wl,--wrap=run_supervisor")
set(TEST_RUNCTL_PROPS "${TEST_RUNCTL_PROPS} -Wl,--wrap=run_ap -Wl,--wrap=run_dhcp")
if (USE_RADIUS_SERVICE)
  set(TEST_RUNCTL_PROPS "${TEST_RUNCTL_PROPS} -Wl,--wrap=run_radius")
endif()
if (USE_MDNS_SERVICE)
  set(TEST_RUNCTL_PROPS "${TEST_RUNCTL_PROPS} -Wl,--wrap=run_mdns_thread")
endif()

set_target_properties(test_runctl PROPERTIES LINK_FLAGS ${TEST_RUNCTL_PROPS})

add_test(NAME test_runctl COMMAND test_runctl)
set_tests_properties(test_runctl
  PROPERTIES
  WILL_FAIL FALSE)
