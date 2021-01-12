# CMake generated Testfile for 
# Source directory: /home/alexandru/Projects/EDGESec/tests/supervisor
# Build directory: /home/alexandru/Projects/EDGESec/build/tests/supervisor
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(test_bridge_list "/home/alexandru/Projects/EDGESec/build/tests/supervisor/test_bridge_list")
set_tests_properties(test_bridge_list PROPERTIES  WILL_FAIL "FALSE" _BACKTRACE_TRIPLES "/home/alexandru/Projects/EDGESec/tests/supervisor/CMakeLists.txt;15;add_test;/home/alexandru/Projects/EDGESec/tests/supervisor/CMakeLists.txt;0;")
add_test(test_domain_server "/home/alexandru/Projects/EDGESec/build/tests/supervisor/test_domain_server")
set_tests_properties(test_domain_server PROPERTIES  WILL_FAIL "FALSE" _BACKTRACE_TRIPLES "/home/alexandru/Projects/EDGESec/tests/supervisor/CMakeLists.txt;20;add_test;/home/alexandru/Projects/EDGESec/tests/supervisor/CMakeLists.txt;0;")
add_test(test_cmd_processor "/home/alexandru/Projects/EDGESec/build/tests/supervisor/test_cmd_processor")
set_tests_properties(test_cmd_processor PROPERTIES  WILL_FAIL "FALSE" _BACKTRACE_TRIPLES "/home/alexandru/Projects/EDGESec/tests/supervisor/CMakeLists.txt;25;add_test;/home/alexandru/Projects/EDGESec/tests/supervisor/CMakeLists.txt;0;")
