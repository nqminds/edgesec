include_directories (
  "${EDGESEC_SOURCE_DIR}/src"
  "${LibNL_INCLUDE_DIR}"
  "${CMOCKA_INCLUDE_DIR}"
)

add_subdirectory(utils)
add_subdirectory(supervisor)
add_subdirectory(radius)
add_subdirectory(hostapd)
add_subdirectory(dhcp)

add_executable(test_mac_mapper test_mac_mapper.c)
target_link_libraries(test_mac_mapper log system_checks os mac_mapper ${CMOCKA_LIB})

add_executable(test_system_checks test_system_checks.c)
target_link_libraries(test_system_checks log system_checks os hashmap ${CMOCKA_LIB})

add_executable(test_if_service test_if_service.c)
target_link_libraries(test_if_service log if iw os hashmap if_service ${CMOCKA_LIB})
set_target_properties(test_if_service
        PROPERTIES
        LINK_FLAGS  "-Wl,--wrap=iface_exists -Wl,--wrap=get_netiw_info -Wl,--wrap=iwace_isvlan -Wl,--wrap=create_interface -Wl,--wrap=set_interface_ip -Wl,--wrap=set_interface_state -Wl,--wrap=get_interfaces -Wl,--wrap=if_nametoindex"
)

add_test(NAME test_mac_mapper COMMAND test_mac_mapper)
set_tests_properties(test_mac_mapper
  PROPERTIES
  WILL_FAIL FALSE)

add_test(NAME test_system_checks COMMAND test_system_checks)
set_tests_properties(test_system_checks
  PROPERTIES
  WILL_FAIL FALSE)

add_test(NAME test_if_service COMMAND test_if_service)
set_tests_properties(test_if_service
  PROPERTIES
  WILL_FAIL FALSE)
