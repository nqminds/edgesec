include_directories (
  "${PROJECT_SOURCE_DIR}/src"
)

add_library(tap_middleware tap_middleware.c)
target_include_directories(tap_middleware PRIVATE ${PROJECT_BINARY_DIR})
target_link_libraries(tap_middleware PUBLIC SQLite::SQLite3 pcap_service eloop PRIVATE allocs os log squeue)
