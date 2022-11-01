# Error on all C/C++ warnings in the tests/ directory if making a Debug build
add_compile_options($<$<CONFIG:Debug>:-Werror>)

include_directories (
  "${PROJECT_SOURCE_DIR}/src"
)

if (USE_UCI_SERVICE)
  # tests may modify these files, so we only run on a copy
  file(COPY "${CMAKE_SOURCE_DIR}/tests/data/uci" DESTINATION "${CMAKE_BINARY_DIR}/tests/data")
  set(TEST_UCI_CONFIG_DIR "${CMAKE_BINARY_DIR}/tests/data/uci")
  add_compile_definitions(TEST_UCI_CONFIG_DIR="${TEST_UCI_CONFIG_DIR}")
  add_library(
    __wrap_uwrt_init_context OBJECT ./utils/__wrap_uwrt_init_context.c
  )
  target_link_libraries(__wrap_uwrt_init_context PRIVATE uci_wrt)
  target_link_options(__wrap_uwrt_init_context PUBLIC "-Wl,--wrap=uwrt_init_context")
endif ()

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

configure_file("${CMAKE_CURRENT_LIST_DIR}/test-config.ini.in" "${CMAKE_BINARY_DIR}/test-config.ini" @ONLY)
add_cmocka_test(test_config
  SOURCES test_config.c
  LINK_LIBRARIES cmocka::cmocka log config
)
target_compile_definitions(test_config PRIVATE TEST_CONFIG_INI_PATH="${CMAKE_BINARY_DIR}/test-config.ini")

add_cmocka_test(test_edgesec
  SOURCES test_edgesec.c
  LINK_LIBRARIES sockctl runctl cmocka::cmocka log config
)
target_compile_definitions(test_edgesec PRIVATE TEST_CONFIG_INI_PATH="${CMAKE_BINARY_DIR}/test-config.ini")

add_cmocka_test(test_runctl
  SOURCES test_runctl.c
  LINK_LIBRARIES SQLite::SQLite3 LibUTHash::LibUTHash runctl log os supervisor_config mac_mapper cmocka::cmocka
)

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
if (USE_UCI_SERVICE)
  target_link_libraries(test_runctl PUBLIC __wrap_uwrt_init_context)
endif()
