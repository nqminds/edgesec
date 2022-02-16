add_subdirectory(utils)
add_subdirectory(supervisor)
add_subdirectory(radius)
add_subdirectory(ap)
add_subdirectory(dhcp)
add_subdirectory(subnet)
add_subdirectory(system)
add_subdirectory(crypt)

add_subdirectory(dns)

add_subdirectory(capture)

add_library(engine engine.c)
if (BUILD_NL_LIB)
  target_include_directories(engine PRIVATE ${LIBNL_INCLUDE_DIR} ${LIBSQLITE_INCLUDE_DIR})
  target_link_libraries(engine crypt_service net log iface_mapper nl os sqlite_macconn_writer sqlite_fingerprint_writer subnet_service system_checks eloop supervisor network_commands radius_service mac_mapper ap_service iptables dhcp_service)
else ()
  target_include_directories(engine PRIVATE ${LIBSQLITE_INCLUDE_DIR})
  target_link_libraries(engine crypt_service net log iface_mapper os sqlite_macconn_writer sqlite_fingerprint_writer subnet_service system_checks eloop supervisor network_commands radius_service mac_mapper ap_service iptables dhcp_service)
endif ()

add_library(config config.c)
target_include_directories(config PUBLIC ${LIBSQLITE_INCLUDE_DIR})
target_link_libraries(config minIni mac_mapper)

if (BUILD_MDNS_SERVICE AND BUILD_CAPTURE_SERVICE)
  add_executable(mdnsf mdnsf.c)
  target_include_directories(mdnsf PRIVATE ${LIBPCAP_INCLUDE_PATH} ${PROJECT_BINARY_DIR})
  target_link_libraries(mdnsf PRIVATE mdns_service subnet_service config minIni squeue iface_mapper log os)
  # link time optimization
  set_target_properties(mdnsf PROPERTIES INTERPROCEDURAL_OPTIMIZATION TRUE)
endif ()

if (BUILD_CAPTURE_SERVICE)
  add_executable(capsrv capsrv.c)
  target_include_directories(capsrv PRIVATE ${LIBPCAP_INCLUDE_PATH} ${PROJECT_BINARY_DIR})
  target_link_libraries(capsrv capture_service capture_config config minIni os hashmap ${LIBPCAP_LIB})
  # link time optimization
  set_target_properties(capsrv PROPERTIES INTERPROCEDURAL_OPTIMIZATION TRUE)
endif ()

if (BUILD_REST_SERVER AND BUILD_MICROHTTPD_LIB)
  add_executable(restsrv restsrv.c)
  target_include_directories(restsrv PRIVATE ${LIBMICROHTTPD_INCLUDE_DIR} ${PROJECT_BINARY_DIR})
  target_link_libraries(restsrv config minIni base64 os hashmap ap_service cmd_processor ${LIBMICROHTTPD_LIB})
  # link time optimization
  set_target_properties(restsrv PROPERTIES INTERPROCEDURAL_OPTIMIZATION TRUE)
endif ()

if (BUILD_SQLSYNC_SERVICE)
  add_executable(sqlsyncsrv sqlsyncsrv.cc)
  target_include_directories(sqlsyncsrv PRIVATE ${PROJECT_BINARY_DIR} ${LIBSQLITE_INCLUDE_DIR})
  target_link_libraries(sqlsyncsrv PUBLIC sqlite_header_writer os sqlite_grpc_proto GRPC::grpc++_reflection ${LIBSQLITE_LIB})
  # link time optimization
  set_target_properties(sqlsyncsrv PROPERTIES INTERPROCEDURAL_OPTIMIZATION TRUE)
endif ()

if (BUILD_REVERSE_SERVICE)
  add_executable(revclient revclient.cc)
  target_include_directories(revclient PRIVATE ${PROJECT_BINARY_DIR} ${LIBSQLITE_INCLUDE_DIR})
  target_link_libraries(revclient PRIVATE base64 os log reverse_grpc_proto GRPC::grpc++_reflection ${LIBSQLITE_LIB})

  add_executable(revsrv revsrv.cc)
  target_include_directories(revsrv PRIVATE ${PROJECT_BINARY_DIR})
  target_link_libraries(revsrv os log eloop domain reverse_grpc_proto GRPC::grpc++_reflection)

  # link time optimization
  set_target_properties(revclient revsrv PROPERTIES INTERPROCEDURAL_OPTIMIZATION TRUE)
endif ()

add_executable(edgesec edgesec.c)
target_include_directories(edgesec PRIVATE ${PROJECT_BINARY_DIR} ${LIBOPENSSL_INCLUDE_PATH})
target_link_libraries(edgesec eloop config engine minIni os hashmap)
# link time optimization
set_target_properties(edgesec PROPERTIES INTERPROCEDURAL_OPTIMIZATION TRUE)
