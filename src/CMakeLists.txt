add_subdirectory(utils)
add_subdirectory(supervisor)
add_subdirectory(radius)
add_subdirectory(ap)
add_subdirectory(dhcp)
add_subdirectory(firewall)
if (USE_CRYPTO_SERVICE)
  add_subdirectory(crypt)
endif ()
add_subdirectory(dns)
add_subdirectory(capture)


add_library(sqlhook SHARED sqlhook.c)
target_compile_options(sqlhook PRIVATE -fPIC)
target_link_libraries(sqlhook PRIVATE domain os SQLite::SQLite3)

add_library(engine engine.c)
if (USE_CRYPTO_SERVICE)
  target_link_libraries(engine PRIVATE crypt_service net log iface_mapper os sqlite_macconn_writer sqlite_fingerprint_writer firewall_service eloop supervisor network_commands radius_service mac_mapper ap_service firewall_service dhcp_service)
else ()
  target_link_libraries(engine PRIVATE net log iface_mapper os sqlite_macconn_writer sqlite_fingerprint_writer firewall_service eloop supervisor network_commands radius_service mac_mapper ap_service firewall_service dhcp_service)
endif ()

add_library(config config.c)
target_include_directories(config PUBLIC $<TARGET_PROPERTY:iface,INCLUDE_DIRECTORIES>)
target_link_libraries(config PUBLIC supervisor_config PRIVATE minIni os log)

if (BUILD_MDNS_SERVICE AND BUILD_CAPTURE_SERVICE)
  add_executable(mdnsf mdnsf.c)
  target_include_directories(mdnsf PRIVATE ${PROJECT_BINARY_DIR})
  target_link_libraries(mdnsf PRIVATE mdns_service config minIni squeue iface_mapper log os PCAP::pcap)
  # link time optimization
  set_target_properties(mdnsf PROPERTIES INTERPROCEDURAL_OPTIMIZATION TRUE)
endif ()

if (BUILD_CAPTURE_SERVICE)
  add_executable(capsrv capsrv.c)
  target_include_directories(capsrv PRIVATE ${PROJECT_BINARY_DIR})
  target_link_libraries(capsrv capture_service capture_config config minIni os hashmap PCAP::pcap)
  # link time optimization
  set_target_properties(capsrv PROPERTIES INTERPROCEDURAL_OPTIMIZATION TRUE)
endif ()

add_executable(edgesec edgesec.c)
if (USE_CRYPTO_SERVICE)
  target_include_directories(edgesec PRIVATE ${PROJECT_BINARY_DIR} ${LIBOPENSSL_INCLUDE_PATH})
else ()
  target_include_directories(edgesec PRIVATE ${PROJECT_BINARY_DIR})
endif ()
target_link_libraries(edgesec PRIVATE eloop config engine minIni os hashmap)
# link time optimization
set_target_properties(edgesec PROPERTIES INTERPROCEDURAL_OPTIMIZATION TRUE)
