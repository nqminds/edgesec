include_directories (
  "${EDGESEC_SOURCE_DIR}/src"
)

add_library(pcap_queue pcap_queue.c)
target_include_directories(pcap_queue PRIVATE ${LIBPCAP_INCLUDE_PATH})
target_link_libraries(pcap_queue PRIVATE log os)

add_library(sqlite_pcap sqlite_pcap.c)
target_include_directories(sqlite_pcap PRIVATE ${LIBPCAP_INCLUDE_PATH} ${LIBSQLITE_INCLUDE_DIR})
target_link_libraries(sqlite_pcap PRIVATE sqliteu log os SQLite::sqlite)

add_library(pcap_middleware pcap_middleware.c)
target_include_directories(pcap_middleware PRIVATE ${LIBSQLITE_INCLUDE_DIR} ${PROJECT_BINARY_DIR})
target_link_libraries(pcap_middleware PRIVATE pcap_service pcap_queue sqlite_pcap log os SQLite::sqlite)
