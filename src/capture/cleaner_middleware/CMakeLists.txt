include_directories (
  "${EDGESEC_SOURCE_DIR}/src"
)

add_library(capture_cleaner capture_cleaner.c)
target_include_directories(capture_cleaner PRIVATE ${LIBSQLITE_INCLUDE_DIR})
target_link_libraries(capture_cleaner PRIVATE eloop log os)
