include_directories (
  "${EDGESEC_SOURCE_DIR}/src"
)

if (LIBPCAP_LIB)
  add_subdirectory(capture)
endif ()
add_subdirectory(crypt)
add_subdirectory(utils)
add_subdirectory(supervisor)
add_subdirectory(radius)
add_subdirectory(ap)
add_subdirectory(dhcp)
add_subdirectory(dns)
add_subdirectory(subnet)

add_executable(test_engine test_engine.c)
target_include_directories(test_engine PUBLIC ${LIBSQLITE_INCLUDE_DIR})
target_link_libraries(test_engine PRIVATE engine log system_checks os mac_mapper ${LIBSQLITE_LIB} cmocka::cmocka)

add_test(NAME test_engine COMMAND test_engine)
set_tests_properties(test_engine
  PROPERTIES
  WILL_FAIL FALSE)
