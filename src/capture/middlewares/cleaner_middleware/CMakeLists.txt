include_directories (
  "${PROJECT_SOURCE_DIR}/src"
)

add_library(cleaner_middleware cleaner_middleware.c)
target_include_directories(cleaner_middleware PRIVATE ${PROJECT_BINARY_DIR})
target_link_libraries(cleaner_middleware PUBLIC middleware PCAP::pcap SQLite::SQLite3 LibUTHash::LibUTHash PRIVATE eloop::eloop log os)
