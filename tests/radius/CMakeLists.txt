include_directories(
  "${PROJECT_SOURCE_DIR}/src"
)

add_library(ip_addr ip_addr.c)
target_link_libraries(ip_addr PRIVATE os allocs)

add_library(radius_client radius_client.c)
target_link_libraries(radius_client ip_addr radius md5 wpabuf log os eloop)

add_cmocka_test(test_radius_server
  SOURCES test_radius_server.c
  LINK_LIBRARIES radius_client ip_addr radius radius_server md5 wpabuf log os eloop cmocka::cmocka
)
