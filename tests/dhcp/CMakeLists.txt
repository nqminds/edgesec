include_directories(
  "${EDGESEC_SOURCE_DIR}/src"
  "${CMOCKA_INCLUDE_DIR}"
)

#add_executable(test_dnsmasq test_dnsmasq.c)
#target_link_libraries(test_dnsmasq dnsmasq log ${CMOCKA_LIB})

#add_test(NAME test_dnsmasq COMMAND test_dnsmasq)
#set_tests_properties(test_dnsmasq
#  PROPERTIES
#  WILL_FAIL FALSE)
