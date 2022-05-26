include_directories (
  "${EDGESEC_SOURCE_DIR}/src"
)

add_library(packet_queue packet_queue.c)
target_link_libraries(packet_queue PRIVATE packet_decoder log os)

add_library(pcap_queue pcap_queue.c)
target_include_directories(pcap_queue PRIVATE ${LIBPCAP_INCLUDE_PATH})
target_link_libraries(pcap_queue PRIVATE log os)

add_library(sqlite_header_writer sqlite_header_writer.c)
target_include_directories(sqlite_header_writer PRIVATE ${LIBPCAP_INCLUDE_PATH} ${LIBSQLITE_INCLUDE_DIR})
target_link_libraries(sqlite_header_writer PRIVATE sqliteu squeue log os iface SQLite::sqlite)

add_library(sqlite_pcap_writer sqlite_pcap_writer.c)
target_include_directories(sqlite_pcap_writer PRIVATE ${LIBPCAP_INCLUDE_PATH} ${LIBSQLITE_INCLUDE_DIR})
target_link_libraries(sqlite_pcap_writer PRIVATE sqliteu log os SQLite::sqlite)

add_library(capture_cleaner capture_cleaner.c)
target_include_directories(capture_cleaner PRIVATE ${LIBSQLITE_INCLUDE_DIR})
target_link_libraries(capture_cleaner PRIVATE eloop log os)
