include_directories (
  "${PROJECT_SOURCE_DIR}/src"
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
target_link_libraries(test_runctl PUBLIC SQLite::SQLite3 LibUTHash::LibUTHash PRIVATE runctl log os supervisor_config mac_mapper cmocka::cmocka)

target_link_options(test_runctl PRIVATE
  "LINKER:--wrap=get_vlan_mapper,--wrap=eloop_run,--wrap=get_commands_paths,--wrap=hmap_str_keychar_get"
  "LINKER:--wrap=fw_init_context,--wrap=fw_set_ip_forward"
)

if (USE_CRYPTO_SERVICE)
  target_link_libraries(test_runctl PRIVATE crypt_service)
  target_link_options(test_runctl PRIVATE "LINKER:--wrap=load_crypt_service")
endif ()

target_link_options(test_runctl PRIVATE
  "LINKER:--wrap=iface_get_vlan,--wrap=run_supervisor"
  "LINKER:--wrap=run_ap,--wrap=run_dhcp"
)

if (USE_RADIUS_SERVICE)
  target_link_options(test_runctl PRIVATE "LINKER:--wrap=run_radius")
endif()
if (USE_MDNS_SERVICE)
  target_link_options(test_runctl PRIVATE "LINKER:--wrap=run_mdns_thread")
endif()

add_test(NAME test_runctl COMMAND test_runctl)
set_tests_properties(test_runctl
  PROPERTIES
  WILL_FAIL FALSE)
