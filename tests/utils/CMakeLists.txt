include_directories(
  "${EDGESEC_SOURCE_DIR}/src"
  "${CMOCKA_INCLUDE_DIR}"
)

add_executable(test_if test_if.c)
target_link_libraries(test_if if ${CMOCKA_LIB})

add_executable(test_os test_os.c)
target_link_libraries(test_os os ${CMOCKA_LIB})

add_executable(test_hashmap test_hashmap.c)
target_link_libraries(test_hashmap hashmap ${CMOCKA_LIB})

add_executable(test_utarray test_utarray.c)
target_link_libraries(test_utarray ${CMOCKA_LIB})

add_executable(test_minIni test_minIni.c)
target_link_libraries(test_minIni minIni ${CMOCKA_LIB})

add_executable(test_log_thread_safe test_log_thread_safe.c)
target_link_libraries(test_log_thread_safe log pthread)

add_executable(test_log_level test_log_level.c)
target_link_libraries(test_log_level PRIVATE log)

add_executable(test_log_err test_log_err.c)
target_link_libraries(test_log_err PRIVATE log)

add_test(NAME test_if COMMAND test_if)
set_tests_properties(test_if
 PROPERTIES
 WILL_FAIL FALSE)

add_test(NAME test_os COMMAND test_os)
set_tests_properties(test_os
  PROPERTIES
  WILL_FAIL FALSE)

add_test(NAME test_hashmap COMMAND test_hashmap)
set_tests_properties(test_hashmap
  PROPERTIES
  WILL_FAIL FALSE)

add_test(NAME test_utarray COMMAND test_utarray)
set_tests_properties(test_utarray
  PROPERTIES
  WILL_FAIL FALSE)

add_test(NAME test_minIni COMMAND test_minIni)
set_tests_properties(test_minIni
  PROPERTIES
  WILL_FAIL FALSE)

add_test(NAME test_log_thread_safe COMMAND test_log_thread_safe)
set_tests_properties(test_log_thread_safe
  PROPERTIES
  WILL_FAIL FALSE)

add_test(NAME test_log_level COMMAND test_log_level)
set_tests_properties(test_log_level
  PROPERTIES PASS_REGULAR_EXPRESSION ".+TRACE.+Hello world;.+DEBUG.+Hello world;.+INFO.+Hello world;.+WARN.+Hello world")

add_test(NAME test_log_err COMMAND test_log_err)
set_tests_properties(test_log_err
  PROPERTIES
  PASS_REGULAR_EXPRESSION ".+ERROR")

