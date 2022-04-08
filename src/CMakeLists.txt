add_subdirectory(utils)
add_subdirectory(supervisor)
add_subdirectory(radius)
add_subdirectory(ap)
add_subdirectory(dhcp)
add_subdirectory(firewall)
add_subdirectory(crypt)
add_subdirectory(dns)
add_subdirectory(capture)


add_library(sqlhook SHARED sqlhook.c)
target_include_directories(sqlhook PRIVATE ${LIBSQLITE_INCLUDE_DIR})
target_link_libraries(sqlhook PRIVATE SQLite::sqlite)

add_library(engine engine.c)
target_include_directories(engine PRIVATE ${LIBSQLITE_INCLUDE_DIR})
target_link_libraries(engine crypt_service net log iface_mapper os sqlite_macconn_writer sqlite_fingerprint_writer firewall_service eloop supervisor network_commands radius_service mac_mapper ap_service firewall_service dhcp_service)

add_library(config config.c)
target_include_directories(config PUBLIC $<TARGET_PROPERTY:iface,INCLUDE_DIRECTORIES> ${LIBSQLITE_INCLUDE_DIR})
target_link_libraries(config PRIVATE minIni os log)

if (BUILD_MDNS_SERVICE AND BUILD_CAPTURE_SERVICE)
  add_executable(mdnsf mdnsf.c)
  target_include_directories(mdnsf PRIVATE ${LIBPCAP_INCLUDE_PATH} ${PROJECT_BINARY_DIR} ${LIBSQLITE_INCLUDE_DIR})
  target_link_libraries(mdnsf PRIVATE mdns_service config minIni squeue iface_mapper log os)
  # link time optimization
  set_target_properties(mdnsf PROPERTIES INTERPROCEDURAL_OPTIMIZATION TRUE)
endif ()

if (BUILD_CAPTURE_SERVICE)
  add_executable(capsrv capsrv.c)
  target_include_directories(capsrv PRIVATE ${LIBPCAP_INCLUDE_PATH} ${PROJECT_BINARY_DIR} ${LIBSQLITE_INCLUDE_DIR})
  target_link_libraries(capsrv capture_service capture_config config minIni os hashmap PCAP::pcap)
  # link time optimization
  set_target_properties(capsrv PROPERTIES INTERPROCEDURAL_OPTIMIZATION TRUE)
endif ()

add_executable(edgesec edgesec.c)
target_include_directories(edgesec PRIVATE ${PROJECT_BINARY_DIR} ${LIBOPENSSL_INCLUDE_PATH} ${LIBSQLITE_INCLUDE_DIR})
target_link_libraries(edgesec PRIVATE eloop config engine minIni os hashmap)
# link time optimization
set_target_properties(edgesec PROPERTIES INTERPROCEDURAL_OPTIMIZATION TRUE)
