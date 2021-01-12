# CMake generated Testfile for 
# Source directory: /home/alexandru/Projects/EDGESec/tests/utils
# Build directory: /home/alexandru/Projects/EDGESec/build/tests/utils
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(test_if "/home/alexandru/Projects/EDGESec/build/tests/utils/test_if")
set_tests_properties(test_if PROPERTIES  WILL_FAIL "FALSE" _BACKTRACE_TRIPLES "/home/alexandru/Projects/EDGESec/tests/utils/CMakeLists.txt;30;add_test;/home/alexandru/Projects/EDGESec/tests/utils/CMakeLists.txt;0;")
add_test(test_os "/home/alexandru/Projects/EDGESec/build/tests/utils/test_os")
set_tests_properties(test_os PROPERTIES  WILL_FAIL "FALSE" _BACKTRACE_TRIPLES "/home/alexandru/Projects/EDGESec/tests/utils/CMakeLists.txt;35;add_test;/home/alexandru/Projects/EDGESec/tests/utils/CMakeLists.txt;0;")
add_test(test_hashmap "/home/alexandru/Projects/EDGESec/build/tests/utils/test_hashmap")
set_tests_properties(test_hashmap PROPERTIES  WILL_FAIL "FALSE" _BACKTRACE_TRIPLES "/home/alexandru/Projects/EDGESec/tests/utils/CMakeLists.txt;40;add_test;/home/alexandru/Projects/EDGESec/tests/utils/CMakeLists.txt;0;")
add_test(test_utarray "/home/alexandru/Projects/EDGESec/build/tests/utils/test_utarray")
set_tests_properties(test_utarray PROPERTIES  WILL_FAIL "FALSE" _BACKTRACE_TRIPLES "/home/alexandru/Projects/EDGESec/tests/utils/CMakeLists.txt;45;add_test;/home/alexandru/Projects/EDGESec/tests/utils/CMakeLists.txt;0;")
add_test(test_minIni "/home/alexandru/Projects/EDGESec/build/tests/utils/test_minIni")
set_tests_properties(test_minIni PROPERTIES  WILL_FAIL "FALSE" _BACKTRACE_TRIPLES "/home/alexandru/Projects/EDGESec/tests/utils/CMakeLists.txt;50;add_test;/home/alexandru/Projects/EDGESec/tests/utils/CMakeLists.txt;0;")
add_test(test_log_thread_safe "/home/alexandru/Projects/EDGESec/build/tests/utils/test_log_thread_safe")
set_tests_properties(test_log_thread_safe PROPERTIES  WILL_FAIL "FALSE" _BACKTRACE_TRIPLES "/home/alexandru/Projects/EDGESec/tests/utils/CMakeLists.txt;55;add_test;/home/alexandru/Projects/EDGESec/tests/utils/CMakeLists.txt;0;")
add_test(test_log_level "/home/alexandru/Projects/EDGESec/build/tests/utils/test_log_level")
set_tests_properties(test_log_level PROPERTIES  PASS_REGULAR_EXPRESSION ".+TRACE.+Hello world;.+DEBUG.+Hello world;.+INFO.+Hello world;.+WARN.+Hello world" _BACKTRACE_TRIPLES "/home/alexandru/Projects/EDGESec/tests/utils/CMakeLists.txt;60;add_test;/home/alexandru/Projects/EDGESec/tests/utils/CMakeLists.txt;0;")
add_test(test_log_err "/home/alexandru/Projects/EDGESec/build/tests/utils/test_log_err")
set_tests_properties(test_log_err PROPERTIES  PASS_REGULAR_EXPRESSION ".+ERROR" _BACKTRACE_TRIPLES "/home/alexandru/Projects/EDGESec/tests/utils/CMakeLists.txt;64;add_test;/home/alexandru/Projects/EDGESec/tests/utils/CMakeLists.txt;0;")
