include_directories (
  "${EDGESEC_SOURCE_DIR}/src"
)

add_library(pcap_queue pcap_queue.c)
target_include_directories(pcap_queue PRIVATE ${LIBPCAP_INCLUDE_PATH})
target_link_libraries(pcap_queue PRIVATE log os)

add_library(pcap_middleware pcap_middleware.c)
target_include_directories(pcap_middleware PRIVATE ${LIBPCAP_INCLUDE_PATH} ${LIBSQLITE_INCLUDE_DIR})
target_link_libraries(pcap_middleware PRIVATE sqliteu log os SQLite::sqlite)
