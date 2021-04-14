include_directories (
  "${EDGESEC_SOURCE_DIR}/src"
  "${CMAKE_CURRENT_BINARY_DIR}"
)

add_library(packet_queue packet_queue.c)
target_link_libraries(packet_queue log os)

add_library(pcap_service pcap_service.c)
target_link_libraries(pcap_service log os ${LIBPCAP_LIB})

add_library(pcap_queue pcap_queue.c)
target_link_libraries(pcap_queue log os)

add_library(packet_decoder packet_decoder.c)
target_link_libraries(packet_decoder hash if log os hashmap ${LIBPCAP_LIB})

add_library(sync_client sync_client.cc)
target_link_libraries(sync_client log sqlite_grpc_proto ${_REFLECTION} ${_GRPC_GRPCPP} ${_PROTOBUF_LIBPROTOBUF})

add_library(sqlite_header_writer sqlite_header_writer.c)
target_link_libraries(sqlite_header_writer sqliteu squeue log os ${LIBSQLITE3_LIB})

add_library(sqlite_meta_writer sqlite_meta_writer.c)
target_link_libraries(sqlite_meta_writer sqliteu log os ${LIBSQLITE3_LIB})

add_library(capture_service capture_service.c)
target_link_libraries(capture_service pcap_service sync_client sqlite_header_writer sqlite_meta_writer pcap_queue packet_queue packet_decoder eloop if log os hashmap)
