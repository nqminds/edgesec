include_directories (
  "${PROJECT_SOURCE_DIR}/src"
)

add_cmocka_test(test_system_checks
  SOURCES test_system_checks.c
  LINK_LIBRARIES log system_checks os hashmap cmocka::cmocka
)
