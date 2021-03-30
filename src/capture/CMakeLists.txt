include_directories (
  "${EDGESEC_SOURCE_DIR}/src"
  "${CMAKE_CURRENT_BINARY_DIR}"
)

add_library(sqlite_writer sqlite_writer.c)
target_link_libraries(sqlite_writer log os ${LIBSQLITE3_LIB})

add_library(packet_queue packet_queue.c)
target_link_libraries(packet_queue log os)

add_library(packet_decoder packet_decoder.c)
target_link_libraries(packet_decoder hash if log os hashmap ${LIBPCAP_LIB})

add_library(capture_service capture_service.c)
target_link_libraries(capture_service sqlite_writer packet_queue packet_decoder eloop if log os hashmap ${LIBPCAP_LIB})

# add_library(sqlite_sync.pb sqlite_sync.pb.cc)
# target_link_libraries(sqlite_sync.pb ${LIBGRPC++_REFLECTION_LIB} ${LIBGRPC++_LIB} ${LIBPROTOBUF_LIB})

# add_library(sqlite_sync.grpc.pb sqlite_sync.grpc.pb.cc)
# target_link_libraries(sqlite_sync.grpc.pb ${LIBGRPC++_REFLECTION_LIB} ${LIBGRPC++_LIB} ${LIBPROTOBUF_LIB})
