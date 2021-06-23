include_directories (
  "${EDGESEC_SOURCE_DIR}/src"
  "${LibNL_INCLUDE_DIR}"
  "${CMOCKA_INCLUDE_DIR}"
)

add_subdirectory(capture)
add_subdirectory(utils)
add_subdirectory(supervisor)
add_subdirectory(radius)
add_subdirectory(ap)
add_subdirectory(dhcp)
add_subdirectory(subnet)

add_executable(test_engine test_engine.c)
target_link_libraries(test_engine engine log system_checks os mac_mapper ${CMOCKA_LIB})

add_test(NAME test_engine COMMAND test_engine)
set_tests_properties(test_engine
  PROPERTIES
  WILL_FAIL FALSE)
