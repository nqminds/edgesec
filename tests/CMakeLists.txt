include_directories (
  "${EDGESEC_SOURCE_DIR}/src"
)

if (LIBPCAP_LIB)
  add_subdirectory(capture)
endif ()

if (USE_CRYPTO_SERVICE)
  add_subdirectory(crypt)
endif ()

add_subdirectory(utils)
add_subdirectory(supervisor)
add_subdirectory(radius)
add_subdirectory(ap)
add_subdirectory(dhcp)
add_subdirectory(dns)

add_executable(test_engine test_engine.c)
target_link_libraries(test_engine PUBLIC SQLite::SQLite3 PRIVATE engine log os mac_mapper cmocka::cmocka)

add_test(NAME test_engine COMMAND test_engine)
set_tests_properties(test_engine
  PROPERTIES
  WILL_FAIL FALSE)
