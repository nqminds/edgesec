include_directories (
  "${PROJECT_SOURCE_DIR}/src"
)

add_cmocka_test(
  test_sqlite_crypt_writer
  SOURCES test_sqlite_crypt_writer.c
  LINK_LIBRARIES sqlite_crypt_writer sqliteu os log SQLite::SQLite3 cmocka::cmocka
)
target_link_options(test_sqlite_crypt_writer
  PRIVATE
  "LINKER:--wrap=sqlite3_open"
)

add_cmocka_test(test_crypt_service
  SOURCES test_crypt_service.c
  LINK_LIBRARIES crypt_service sqlite_crypt_writer sqliteu os log cmocka::cmocka
)
target_link_options(test_crypt_service
  PRIVATE
  "LINKER:--wrap=crypto_decrypt,--wrap=init_hsm"
)
