include_directories(
  "${PROJECT_BINARY_DIR}"
  "${LibNL_INCLUDE_DIR}"
  "${LIBNETLINK_INCLUDE_DIR}"
  "${LIBMICROHTTPD_INCLUDE_DIR}"
)

add_subdirectory(utils)
add_subdirectory(supervisor)
add_subdirectory(radius)
add_subdirectory(ap)
add_subdirectory(dhcp)
add_subdirectory(subnet)
add_subdirectory(system)
add_subdirectory(crypt)

if (BUILD_CAPTURE_SERVICE)
  add_subdirectory(capture)
endif ()

add_library(engine engine.c)
target_link_libraries(engine crypt_service log if os sqlite_macconn_writer sqlite_fingerprint_writer subnet_service system_checks eloop supervisor network_commands radius_service mac_mapper ap_service iptables dhcp_service)

add_library(config config.c)
target_link_libraries(config minIni mac_mapper)

add_executable(edgesec edgesec.c)
target_link_libraries(edgesec config engine minIni os hashmap)

if (BUILD_CAPTURE_SERVICE)
  add_executable(capsrv capsrv.c)
  target_link_libraries(capsrv capture_service config minIni os hashmap ${LIBPCAP_LIB})
endif ()

if (BUILD_REST_SERVER)
  add_executable(restsrv restsrv.c)
  target_link_libraries(restsrv crypto config minIni os hashmap cmd_processor ${LIBMICROHTTPD_LIB})
endif ()

if (BUILD_SQLSYNC_SERVICE)
  add_executable(sqlsyncsrv sqlsyncsrv.cc)
  target_link_libraries(sqlsyncsrv os sqlite_grpc_proto ${_REFLECTION} ${_GRPC_GRPCPP} ${_PROTOBUF_LIBPROTOBUF} ${LIBSQLITE3_LIB})
endif ()

if (BUILD_REVERSE_SERVICE)
  add_executable(revclient revclient.cc)
  target_link_libraries(revclient os log reverse_grpc_proto ${_REFLECTION} ${_GRPC_GRPCPP} ${_PROTOBUF_LIBPROTOBUF})

  add_executable(revsrv revsrv.cc)
  target_link_libraries(revsrv os log eloop domain reverse_grpc_proto ${_REFLECTION} ${_GRPC_GRPCPP} ${_PROTOBUF_LIBPROTOBUF})
endif ()