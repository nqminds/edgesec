include_directories(
  "${EDGESEC_SOURCE_DIR}/src"
)

add_executable(test_dnsmasq test_dnsmasq.c)
target_link_libraries(test_dnsmasq PRIVATE dnsmasq log cmocka::cmocka)

add_test(NAME test_dnsmasq COMMAND test_dnsmasq)
set_tests_properties(test_dnsmasq
  PROPERTIES
  WILL_FAIL FALSE)
