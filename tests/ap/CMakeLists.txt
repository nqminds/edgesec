include_directories(
  "${EDGESEC_SOURCE_DIR}/src"
  "${CMOCKA_INCLUDE_DIR}"
)

add_executable(test_config_generator test_config_generator.c)
target_link_libraries(test_config_generator hostapd log ${CMOCKA_LIB})

add_test(NAME test_config_generator COMMAND test_config_generator)
set_tests_properties(test_config_generator
  PROPERTIES
  WILL_FAIL FALSE)
