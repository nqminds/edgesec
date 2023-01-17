# Error on all C/C++ warnings in the tests/ directory if making a Debug build
add_compile_options($<$<CONFIG:Debug>:-Werror>)

# Link time optimization has some issues with linker `--wrap` (mocking) arg
# See https://gcc.gnu.org/bugzilla/show_bug.cgi?id=88643 and
# https://sourceware.org/bugzilla/show_bug.cgi?id=24415
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION OFF)
string(REPLACE "-flto=auto" "" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}") # might be set by debian build

include_directories (
  "${PROJECT_SOURCE_DIR}/src"
)

# tests may modify these files, so we only run on a copy
file(COPY "${CMAKE_SOURCE_DIR}/tests/data" DESTINATION "${CMAKE_BINARY_DIR}/tests")

if (USE_UCI_SERVICE)
  set(UCI_CONFIG_DIR "${CMAKE_BINARY_DIR}/tests/data/uci")
  add_compile_definitions(UCI_CONFIG_DIR="${UCI_CONFIG_DIR}")
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

if (TARGET hostapd::libeap)
  set(EAP_TEST_BINARY_DIR "${CMAKE_BINARY_DIR}/tests/data/eap")
endif ()

configure_file("${CMAKE_CURRENT_LIST_DIR}/test-config.ini.in" "${CMAKE_BINARY_DIR}/test-config.ini" @ONLY)
add_cmocka_test(test_config
  SOURCES test_config.c
  LINK_LIBRARIES cmocka::cmocka log config
)
target_compile_definitions(test_config PRIVATE TEST_CONFIG_INI_PATH="${CMAKE_BINARY_DIR}/test-config.ini")

if (USE_RADIUS_SERVICE)
  add_cmocka_test(test_edgesec
    SOURCES test_edgesec.c
    LINK_LIBRARIES os eloop sockctl radius_client cmocka::cmocka runctl config
  )
  target_compile_definitions(test_edgesec PRIVATE TEST_CONFIG_INI_PATH="${CMAKE_BINARY_DIR}/test-config.ini" _DEFAULT_SOURCE _BSD_SOURCE IEEE8021X_EAPOL)
  set_tests_properties(test_edgesec PROPERTIES TIMEOUT 10)
endif()

add_cmocka_test(test_runctl
  SOURCES test_runctl.c
  LINK_LIBRARIES SQLite::SQLite3 LibUTHash::LibUTHash runctl log os supervisor_config mac_mapper cmocka::cmocka
)

target_link_options(test_runctl PRIVATE
  "LINKER:--wrap=get_vlan_mapper,--wrap=eloop_run,--wrap=get_commands_paths,--wrap=hmap_str_keychar_get"
  "LINKER:--wrap=fw_init_context,--wrap=fw_set_ip_forward"
)

if (USE_CRYPTO_SERVICE)
  add_compile_definitions(WITH_CRYPTO_SERVICE)
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
  target_link_libraries(test_runctl PRIVATE __wrap_uwrt_init_context)
  target_link_libraries(test_edgesec PRIVATE __wrap_uwrt_init_context)
endif()

if (TARGET recap)
  add_test(
    NAME "test_recap_print_version"
    COMMAND recap -v
  )

  set(recap_expected_version_output)
  # need to escape regex special characters until https://gitlab.kitware.com/cmake/cmake/-/issues/21494
  string(REGEX REPLACE
    "([][+.*()^])" "\\\\\\1" # our version has `.` and `+` chars
    recap_expected_version_output_regex "recap app version ${PROJECT_VERSION}"
  )
  set_tests_properties("test_recap_print_version" PROPERTIES
    PASS_REGULAR_EXPRESSION "${recap_expected_version_output_regex}")

  set(RECAP_TEST_DB "/tmp/edgesec-test-recap-pcap.pcap")

  add_test(
    NAME "test_recap_read_pcap TRANS_TYPE=SINGLE_TRANSACTION"
    COMMAND
      recap -f "${RECAP_TEST_DB}" -p "${CMAKE_SOURCE_DIR}/tests/data/test.pcap" -t
  )
  set_tests_properties("test_recap_read_pcap TRANS_TYPE=SINGLE_TRANSACTION" PROPERTIES
    RESOURCE_LOCK "${RECAP_TEST_DB}")

  add_test(
    NAME "test_recap_read_pcap TRANS_TYPE=DISABLED"
    COMMAND recap -f "${RECAP_TEST_DB}" -p "${CMAKE_SOURCE_DIR}/tests/data/test.pcap" # will be very slow :(
  )
  set_tests_properties("test_recap_read_pcap TRANS_TYPE=DISABLED" PROPERTIES
    RESOURCE_LOCK "${RECAP_TEST_DB}")

  add_test(
    NAME "cleanup_recap_test_database"
    COMMAND "${CMAKE_COMMAND}" -E rm -f "${RECAP_TEST_DB}"
  )
  set(RECAP_TESTS_TO_CLEANUP # list of tests that need to be cleaned up afterwards
    "test_recap_read_pcap TRANS_TYPE=SINGLE_TRANSACTION"
    "test_recap_read_pcap TRANS_TYPE=DISABLED"
  )
  set_tests_properties(
    "cleanup_recap_test_database" PROPERTIES
    RESOURCE_LOCK "${RECAP_TEST_DB}"
    FIXTURES_CLEANUP "${RECAP_TESTS_TO_CLEANUP}"
  )
endif()
