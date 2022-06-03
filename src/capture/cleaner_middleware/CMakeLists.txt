include_directories (
  "${EDGESEC_SOURCE_DIR}/src"
)

add_library(cleaner_middleware cleaner_middleware.c)
target_include_directories(cleaner_middleware PRIVATE ${LIBPCAP_INCLUDE_PATH} ${LIBSQLITE_INCLUDE_DIR} ${PROJECT_BINARY_DIR})
target_link_libraries(cleaner_middleware PRIVATE eloop log os)
