include_directories (
  "${EDGESEC_SOURCE_DIR}/src"
)

add_executable(test_sqlite_crypt_writer test_sqlite_crypt_writer.c)
target_include_directories(test_sqlite_crypt_writer PUBLIC ${LIBSQLITE_INCLUDE_DIR})
target_link_libraries(test_sqlite_crypt_writer PRIVATE sqlite_crypt_writer sqliteu os log ${LIBSQLITE_LIB} cmocka-static)
set_target_properties(test_sqlite_crypt_writer
  PROPERTIES
  LINK_FLAGS  "-Wl,--wrap=sqlite3_open"
)

add_executable(test_crypt_service test_crypt_service.c)
target_link_libraries(test_crypt_service PRIVATE crypt_service sqlite_crypt_writer sqliteu os log cmocka-static)
set_target_properties(test_crypt_service
  PROPERTIES
  LINK_FLAGS  "-Wl,--wrap=sqlite3_open -Wl,--wrap=sqlite3_close -Wl,--wrap=crypto_decrypt -Wl,--wrap=init_hsm"
)

add_test(NAME test_sqlite_crypt_writer COMMAND test_sqlite_crypt_writer)
set_tests_properties(test_sqlite_crypt_writer
  PROPERTIES
  WILL_FAIL FALSE)

if (BUILD_OPENSSL_LIB)
  add_test(NAME test_crypt_service COMMAND test_crypt_service)
  set_tests_properties(test_crypt_service
    PROPERTIES
    WILL_FAIL FALSE)
endif ()
