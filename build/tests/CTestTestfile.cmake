# CMake generated Testfile for 
# Source directory: /home/alexandru/Projects/EDGESec/tests
# Build directory: /home/alexandru/Projects/EDGESec/build/tests
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(test_mac_mapper "/home/alexandru/Projects/EDGESec/build/tests/test_mac_mapper")
set_tests_properties(test_mac_mapper PROPERTIES  WILL_FAIL "FALSE" _BACKTRACE_TRIPLES "/home/alexandru/Projects/EDGESec/tests/CMakeLists.txt;25;add_test;/home/alexandru/Projects/EDGESec/tests/CMakeLists.txt;0;")
add_test(test_system_checks "/home/alexandru/Projects/EDGESec/build/tests/test_system_checks")
set_tests_properties(test_system_checks PROPERTIES  WILL_FAIL "FALSE" _BACKTRACE_TRIPLES "/home/alexandru/Projects/EDGESec/tests/CMakeLists.txt;30;add_test;/home/alexandru/Projects/EDGESec/tests/CMakeLists.txt;0;")
add_test(test_if_service "/home/alexandru/Projects/EDGESec/build/tests/test_if_service")
set_tests_properties(test_if_service PROPERTIES  WILL_FAIL "FALSE" _BACKTRACE_TRIPLES "/home/alexandru/Projects/EDGESec/tests/CMakeLists.txt;35;add_test;/home/alexandru/Projects/EDGESec/tests/CMakeLists.txt;0;")
subdirs("utils")
subdirs("supervisor")
subdirs("radius")
subdirs("hostapd")
