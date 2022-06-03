include_directories (
  "${EDGESEC_SOURCE_DIR}/src"
)

if (USE_CAPTURE_SERVICE)
  add_subdirectory(cleaner_middleware)
  add_subdirectory(header_middleware)
  add_subdirectory(pcap_middleware)

  configure_file(
    "middlewares.h.in"
    "${PROJECT_BINARY_DIR}/middlewares.h"
  )

  add_library(pcap_service pcap_service.c)
  target_include_directories(pcap_service PRIVATE ${LIBPCAP_INCLUDE_PATH})
  target_link_libraries(pcap_service PRIVATE net log os PCAP::pcap)

  add_library(capture_service capture_service.c)
  target_include_directories(capture_service PRIVATE ${LIBPCAP_INCLUDE_PATH} ${LIBSQLITE_INCLUDE_DIR} ${PROJECT_BINARY_DIR})
  target_link_libraries(capture_service PRIVATE dns_decoder pcap_service pcap_queue packet_queue packet_decoder squeue eloop iface log os hashmap)
  if (USE_CLEANER_MIDDLEWARE)
    target_link_libraries(capture_service PRIVATE cleaner_middleware)
  endif ()
  if (USE_HEADER_MIDDLEWARE)
    target_link_libraries(capture_service PRIVATE header_middleware)
  endif ()
  if (USE_PCAP_MIDDLEWARE)
    target_link_libraries(capture_service PRIVATE pcap_middleware)
  endif ()
endif()
