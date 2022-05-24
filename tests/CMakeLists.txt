include_directories (
  "${EDGESEC_SOURCE_DIR}/src"
)

if (USE_CAPTURE_SERVICE)
  add_subdirectory(capture)
endif ()

if (USE_CRYPTO_SERVICE)
  add_subdirectory(crypt)
endif ()

add_subdirectory(utils)
add_subdirectory(supervisor)
if (USE_RADIUS_SERVICE)
  add_subdirectory(radius)
endif ()
add_subdirectory(ap)
add_subdirectory(dhcp)
if (USE_MDNS_SERVICE)
  add_subdirectory(dns)
endif ()

add_executable(test_engine test_engine.c)
target_include_directories(test_engine PUBLIC ${LIBSQLITE_INCLUDE_DIR})
target_link_libraries(test_engine PRIVATE engine log os mac_mapper SQLite::sqlite cmocka::cmocka)

add_test(NAME test_engine COMMAND test_engine)
set_tests_properties(test_engine
  PROPERTIES
  WILL_FAIL FALSE)
