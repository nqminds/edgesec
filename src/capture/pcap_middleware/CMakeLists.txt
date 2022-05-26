include_directories (
  "${EDGESEC_SOURCE_DIR}/src"
)

add_library(pcap_queue pcap_queue.c)
target_include_directories(pcap_queue PRIVATE ${LIBPCAP_INCLUDE_PATH})
target_link_libraries(pcap_queue PRIVATE log os)

add_library(sqlite_pcap_writer sqlite_pcap_writer.c)
target_include_directories(sqlite_pcap_writer PRIVATE ${LIBPCAP_INCLUDE_PATH} ${LIBSQLITE_INCLUDE_DIR})
target_link_libraries(sqlite_pcap_writer PRIVATE sqliteu log os SQLite::sqlite)
