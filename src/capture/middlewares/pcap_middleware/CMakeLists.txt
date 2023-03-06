include_directories (
  "${PROJECT_SOURCE_DIR}/src"
)

add_library(pcap_queue pcap_queue.c)
target_link_libraries(pcap_queue PUBLIC PCAP::pcap eloop::list attributes PRIVATE log os)

add_library(sqlite_pcap sqlite_pcap.c)
target_link_libraries(sqlite_pcap PUBLIC PCAP::pcap squeue PRIVATE sqliteu log os SQLite::SQLite3)

add_library(pcap_middleware pcap_middleware.c)
target_include_directories(pcap_middleware PRIVATE ${PROJECT_BINARY_DIR})
target_link_libraries(pcap_middleware PUBLIC middleware PCAP::pcap PRIVATE pcap_service pcap_queue sqlite_pcap log os SQLite::SQLite3)
