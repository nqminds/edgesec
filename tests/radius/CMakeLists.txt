include_directories(
  "${EDGESEC_SOURCE_DIR}/src"
)

add_library(ip_addr ip_addr.c)

add_library(radius_client radius_client.c)
target_link_libraries(radius_client ip_addr radius md5 wpabuf log os eloop)

add_executable(test_radius_server test_radius_server.c)
target_link_libraries(test_radius_server PRIVATE radius_client ip_addr radius radius_server md5 wpabuf log os eloop cmocka::cmocka)

add_test(NAME test_radius_server COMMAND test_radius_server)
set_tests_properties(test_radius_server
  PROPERTIES
  WILL_FAIL FALSE)
