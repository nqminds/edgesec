include_directories(
  "${PROJECT_SOURCE_DIR}/src"
)

if (USE_UCI_SERVICE)
  add_compile_definitions(TEST_UCI_CONFIG_DIR="${CMAKE_SOURCE_DIR}/tests/data/uci")
  add_executable(test_uci_wrt test_uci_wrt.c)
  target_link_libraries(test_uci_wrt PRIVATE uci_wrt cmocka::cmocka iface_mapper)
endif ()

add_executable(test_iface_mapper test_iface_mapper.c)
target_link_libraries(test_iface_mapper PRIVATE iface_mapper cmocka::cmocka)

add_executable(test_ifaceu test_ifaceu.c)
target_link_libraries(test_ifaceu PRIVATE ifaceu cmocka::cmocka)

add_executable(test_net test_net.c)
target_link_libraries(test_net PRIVATE net cmocka::cmocka)

add_executable(test_os test_os.c)
target_link_libraries(test_os PRIVATE os allocs hashmap cmocka::cmocka)

add_executable(test_sqliteu test_sqliteu.c)
target_link_libraries(test_sqliteu PRIVATE sqliteu cmocka::cmocka)

add_executable(test_hashmap test_hashmap.c)
target_link_libraries(test_hashmap PRIVATE hashmap cmocka::cmocka)

add_executable(test_utarray test_utarray.c)
target_link_libraries(test_utarray PRIVATE LibUTHash::LibUTHash cmocka::cmocka)

add_executable(test_minIni test_minIni.c)
target_link_libraries(test_minIni PRIVATE minIni cmocka::cmocka)

add_executable(test_squeue test_squeue.c)
target_link_libraries(test_squeue PRIVATE squeue os cmocka::cmocka)

add_executable(test_log_thread_safe test_log_thread_safe.c)
target_link_libraries(test_log_thread_safe log pthread)

add_executable(test_log_level test_log_level.c)
target_link_libraries(test_log_level PRIVATE log)

add_executable(test_log_err test_log_err.c)
target_link_libraries(test_log_err PRIVATE log)

add_library(wrap_log_error OBJECT wrap_log_error.c)
target_link_libraries(wrap_log_error PRIVATE log cmocka::cmocka)
target_link_options(wrap_log_error PUBLIC "LINKER:--wrap=log_levels")

add_executable(test_wrap_log_error test_wrap_log_error.c)
target_link_libraries(test_wrap_log_error PRIVATE log cmocka::cmocka wrap_log_error)

if (USE_NETLINK_SERVICE)
  add_executable(test_nl test_nl.c)
  target_link_libraries(test_nl PRIVATE cmocka::cmocka nl wrap_log_error)

  add_test(NAME test_nl COMMAND test_nl)
  set_tests_properties(test_nl
    PROPERTIES
    WILL_FAIL FALSE)
endif()

if (USE_UCI_SERVICE)
  add_test(NAME test_uci_wrt COMMAND test_uci_wrt)
  set_tests_properties(test_uci_wrt
   PROPERTIES
   WILL_FAIL FALSE)
endif ()

add_test(NAME test_ifaceu COMMAND test_ifaceu)
set_tests_properties(test_ifaceu
 PROPERTIES
 WILL_FAIL FALSE)

add_test(NAME test_net COMMAND test_net)
set_tests_properties(test_net
 PROPERTIES
 WILL_FAIL FALSE)

add_test(NAME test_os COMMAND test_os)
set_tests_properties(test_os
  PROPERTIES
  WILL_FAIL FALSE)

add_test(NAME test_sqliteu COMMAND test_sqliteu)
  set_tests_properties(test_sqliteu
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

add_test(NAME test_squeue COMMAND test_squeue)
set_tests_properties(test_squeue
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

add_test(NAME test_wrap_log_error COMMAND test_wrap_log_error)
set_tests_properties(test_wrap_log_error
  PROPERTIES
  WILL_FAIL FALSE)
