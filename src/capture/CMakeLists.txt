include_directories (
  "${EDGESEC_SOURCE_DIR}/src"
)

add_library(capture_config capture_config.c)
target_link_libraries(capture_config PRIVATE log os)

if (BUILD_PCAP_LIB)
  add_library(mdns_decoder mdns_decoder.c)
  # we include packet_decoder.h, so need to include its dependencies
  target_include_directories(mdns_decoder PUBLIC $<TARGET_PROPERTY:packet_decoder,INCLUDE_DIRECTORIES> $<TARGET_PROPERTY:iface,INCLUDE_DIRECTORIES>)
  target_link_libraries(mdns_decoder PRIVATE squeue log os hash PUBLIC packet_decoder)

  add_library(dns_decoder dns_decoder.c)
  target_include_directories(dns_decoder PRIVATE ${LIBPCAP_INCLUDE_PATH})
  target_link_libraries(dns_decoder PRIVATE log os hash)

  add_library(packet_decoder packet_decoder.c)
  # packet_decoder.h has an #include <pcap.h>, so need to make it PUBLIC include
  target_include_directories(packet_decoder PUBLIC ${LIBPCAP_INCLUDE_PATH})
  target_link_libraries(packet_decoder PUBLIC ${LIBPCAP_LIB} PRIVATE mdns_decoder dns_decoder hash net log os hashmap)

  add_library(packet_queue packet_queue.c)
  target_link_libraries(packet_queue PRIVATE packet_decoder log os)

  add_library(pcap_service pcap_service.c)
  target_include_directories(pcap_service PRIVATE ${LIBPCAP_INCLUDE_PATH})
  target_link_libraries(pcap_service PRIVATE net log os ${LIBPCAP_LIB})

  add_library(pcap_queue pcap_queue.c)
  target_include_directories(pcap_queue PRIVATE ${LIBPCAP_INCLUDE_PATH})
  target_link_libraries(pcap_queue PRIVATE log os)

  add_library(sqlite_header_writer sqlite_header_writer.c)
  target_include_directories(sqlite_header_writer PRIVATE ${LIBPCAP_INCLUDE_PATH} ${LIBSQLITE_INCLUDE_DIR})
  target_link_libraries(sqlite_header_writer PRIVATE sqliteu squeue log os iface ${LIBSQLITE_LIB})

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
  target_link_libraries(sync_client PRIVATE log sqlite_grpc_proto GRPC::grpc++_reflection)
  target_link_libraries(default_analyser PRIVATE dns_decoder pcap_service sync_client sqlite_header_writer sqlite_pcap_writer pcap_queue packet_queue packet_decoder squeue eloop iface log os hashmap domain)
else ()
  if (BUILD_PCAP_LIB)
    target_link_libraries(default_analyser PRIVATE dns_decoder pcap_service sqlite_header_writer sqlite_pcap_writer pcap_queue packet_queue packet_decoder squeue eloop iface log os hashmap domain)
  endif()
endif ()

add_library(capture_service capture_service.c)
if (BUILD_PCAP_LIB)
  target_include_directories(capture_service PRIVATE ${LIBPCAP_INCLUDE_PATH} ${LIBSQLITE_INCLUDE_DIR})
endif ()

if (BUILD_NDPI_LIB AND USE_PTHREAD_LIB AND USE_M_LIB)
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
