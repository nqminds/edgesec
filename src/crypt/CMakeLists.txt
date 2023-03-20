include_directories (
  "${PROJECT_SOURCE_DIR}/src"
)

add_library(sqlite_crypt_writer sqlite_crypt_writer.c)
target_link_libraries(sqlite_crypt_writer
  PUBLIC SQLite::SQLite3
  PRIVATE allocs os log sqliteu
)

add_library(generic_hsm_driver generic_hsm_driver.c)
if (USE_ZYMKEY4_HSM)
  add_library(zymkey4_driver zymkey4_driver.c)
  target_link_libraries(zymkey4_driver PRIVATE log os ${LIBZYMKEY4_LIB})
  target_link_libraries(generic_hsm_driver PRIVATE zymkey4_driver log os)
else ()
  target_link_libraries(generic_hsm_driver PRIVATE log os)
endif ()

add_library(crypt_service crypt_service.c)
target_link_libraries(crypt_service PUBLIC LibUTHash::LibUTHash SQLite::SQLite3 attributes PRIVATE generic_hsm_driver base64 sqlite_crypt_writer cryptou log os)
