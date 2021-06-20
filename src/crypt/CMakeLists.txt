include_directories (
  "${EDGESEC_SOURCE_DIR}/src"
)

add_library(sqlite_crypt_writer sqlite_crypt_writer.c)
target_link_libraries(sqlite_crypt_writer sqliteu log os ${LIBSQLITE3_LIB})

add_library(crypt_service crypt_service.c)
target_link_libraries(crypt_service sqlite_crypt_writer cryptou log os ${LIBCRYPTO_LIB})
