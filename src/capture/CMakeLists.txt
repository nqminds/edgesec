include_directories (
  "${EDGESEC_SOURCE_DIR}/src"
)

add_library(packet_decoder packet_decoder.c)
target_link_libraries(packet_decoder if log os hashmap ${LIBPCAP_LIB})

add_library(capture_service capture_service.c)
target_link_libraries(capture_service packet_decoder if log os hashmap ${LIBPCAP_LIB})
