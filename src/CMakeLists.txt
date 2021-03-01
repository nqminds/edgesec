include_directories(
  "${PROJECT_BINARY_DIR}"
  "${LibNL_INCLUDE_DIR}"
  "${LIBNETLINK_INCLUDE_DIR}"
)

add_subdirectory(utils)
add_subdirectory(supervisor)
add_subdirectory(radius)
add_subdirectory(ap)
add_subdirectory(dhcp)

add_library(engine engine.c)
target_link_libraries(engine log if os if_service system_checks eloop supervisor radius_service mac_mapper ap_service iptables dhcp_service)

add_library(system_checks system_checks.c)
target_link_libraries(system_checks log if iw os hashmap)

add_library(if_service if_service.c)
target_link_libraries(if_service log if iw os hashmap log)

add_library(config config.c)
target_link_libraries(config minIni)

add_executable(edgesec edgesec.c)
target_link_libraries(edgesec config engine minIni os hashmap)