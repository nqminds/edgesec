include_directories (
  "${EDGESEC_SOURCE_DIR}/src"
  "${CMOCKA_INCLUDE_DIR}"
)

add_executable(test_system_checks test_system_checks.c)
target_link_libraries(test_system_checks PRIVATE log system_checks os hashmap cmocka-static)

add_test(NAME test_system_checks COMMAND test_system_checks)
set_tests_properties(test_system_checks
  PROPERTIES
  WILL_FAIL FALSE)
