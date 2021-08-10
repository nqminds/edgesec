include_directories(
  "${EDGESEC_SOURCE_DIR}/src"
  "${CMOCKA_INCLUDE_DIR}"
)

add_executable(test_hostapd test_hostapd.c)
target_link_libraries(test_hostapd hostapd if os log ${CMOCKA_LIB})
set_target_properties(test_hostapd
  PROPERTIES
  LINK_FLAGS  "-Wl,--wrap=kill_process -Wl,--wrap=reset_interface -Wl,--wrap=run_process -Wl,--wrap=list_dir -Wl,--wrap=check_sock_file_exists"
)

add_test(NAME test_hostapd COMMAND test_hostapd)
set_tests_properties(test_hostapd
  PROPERTIES
  WILL_FAIL FALSE)
