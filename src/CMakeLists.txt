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
add_subdirectory(capture)

add_library(engine engine.c)
target_link_libraries(engine log if os subnet_service system_checks eloop supervisor radius_service mac_mapper ap_service iptables dhcp_service)

add_library(config config.c)
target_link_libraries(config minIni)

add_executable(edgesec edgesec.c)
target_link_libraries(edgesec config engine minIni os hashmap)

add_executable(restsrv restsrv.c)
target_link_libraries(restsrv config minIni os hashmap cmd_processor ${LIBMICROHTTPD_LIB})

add_executable(capsrv capsrv.c)
target_link_libraries(capsrv capture_service config minIni os hashmap ${LIBPCAP_LIB})