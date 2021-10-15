include_directories (
  "${EDGESEC_SOURCE_DIR}/src"
)

add_library(capture_config capture_config.c)
target_link_libraries(capture_config PRIVATE log os)

if (BUILD_PCAP_LIB)
  add_library(mdns_decoder mdns_decoder.c)
  target_include_directories(mdns_decoder PRIVATE ${LIBPCAP_INCLUDE_PATH})
  target_link_libraries(mdns_decoder PRIVATE log os hash)

  add_library(dns_decoder dns_decoder.c)
  target_include_directories(dns_decoder PRIVATE ${LIBPCAP_INCLUDE_PATH})
  target_link_libraries(dns_decoder PRIVATE log os hash)

  add_library(packet_decoder packet_decoder.c)
  target_include_directories(packet_decoder PRIVATE ${LIBPCAP_INCLUDE_PATH})
  target_link_libraries(packet_decoder PRIVATE mdns_decoder dns_decoder hash if log os hashmap ${LIBPCAP_LIB})

  add_library(packet_queue packet_queue.c)
  target_include_directories(packet_queue PRIVATE ${LIBPCAP_INCLUDE_PATH})
  target_link_libraries(packet_queue PRIVATE packet_decoder log os)

  add_library(pcap_service pcap_service.c)
  target_include_directories(pcap_service PRIVATE ${LIBPCAP_INCLUDE_PATH})
  target_link_libraries(pcap_service PRIVATE if log os ${LIBPCAP_LIB})

  add_library(pcap_queue pcap_queue.c)
  target_include_directories(pcap_queue PRIVATE ${LIBPCAP_INCLUDE_PATH})
  target_link_libraries(pcap_queue PRIVATE log os)

  add_library(sqlite_header_writer sqlite_header_writer.c)
  target_include_directories(sqlite_header_writer PRIVATE ${LIBPCAP_INCLUDE_PATH} ${LIBSQLITE_INCLUDE_DIR})
  target_link_libraries(sqlite_header_writer PRIVATE sqliteu squeue log os if ${LIBSQLITE_LIB})

  add_library(sqlite_pcap_writer sqlite_pcap_writer.c)
  target_include_directories(sqlite_pcap_writer PRIVATE ${LIBPCAP_INCLUDE_PATH} ${LIBSQLITE_INCLUDE_DIR})
  target_link_libraries(sqlite_pcap_writer PRIVATE sqliteu log os ${LIBSQLITE_LIB})

  add_library(default_analyser default_analyser.c)
  target_include_directories(default_analyser PRIVATE ${LIBPCAP_INCLUDE_PATH} ${LIBSQLITE_INCLUDE_DIR})

  add_library(capture_cleaner capture_cleaner.c)
  target_include_directories(capture_cleaner PRIVATE ${LIBSQLITE_INCLUDE_DIR})
  target_link_libraries(capture_cleaner PRIVATE sqlite_pcap_writer eloop log os ${LIBSQLITE_LIB})
endif ()

if (BUILD_SQLSYNC_SERVICE)
  add_library(sync_client sync_client.cc)
  target_include_directories(sync_client PRIVATE ${PROJECT_BINARY_DIR})
  target_link_libraries(sync_client PRIVATE log sqlite_grpc_proto grpc++_reflection)
  target_link_libraries(default_analyser PRIVATE dns_decoder pcap_service sync_client sqlite_header_writer sqlite_pcap_writer pcap_queue packet_queue packet_decoder eloop if log os hashmap)
else ()
  if (BUILD_PCAP_LIB)
    target_link_libraries(default_analyser PRIVATE dns_decoder pcap_service sqlite_header_writer sqlite_pcap_writer pcap_queue packet_queue packet_decoder eloop if log os hashmap)
  endif()
endif ()

add_library(capture_service capture_service.c)
if (BUILD_PCAP_LIB)
  target_include_directories(capture_service PRIVATE ${LIBPCAP_INCLUDE_PATH} ${LIBSQLITE_INCLUDE_DIR})
endif ()

if (BUILD_NDPI_LIB)
  add_library(ndpi_serialiser ndpi_serialiser.c)
  target_include_directories(ndpi_serialiser PRIVATE ${LIBNDPI_INCLUDE_PATH})
  target_link_libraries(ndpi_serialiser PRIVATE hash os log ${LIBNDPI_LIB})

  add_library(ndpi_analyser ndpi_analyser.c)
  target_include_directories(ndpi_analyser PRIVATE ${LIBNDPI_INCLUDE_PATH} ${LIBPCAP_INCLUDE_PATH})
  target_link_libraries(ndpi_analyser PRIVATE ndpi_serialiser domain base64 os log pcap_service ${LIBNDPI_LIB} ${LIBPCAP_LIB} ${LIBPTHREAD_LIB} ${LIBM_LIB})
  target_link_libraries(capture_service PRIVATE capture_cleaner ndpi_analyser default_analyser log)
else ()
  if (BUILD_PCAP_LIB)
    target_link_libraries(capture_service PRIVATE capture_cleaner default_analyser log)
  else ()
    target_link_libraries(capture_service PRIVATE capture_cleaner log)
  endif ()
endif ()

