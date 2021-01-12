include_directories (
  "${EDGESEC_SOURCE_DIR}/src"
)

add_library(config_generator config_generator.c)
target_link_libraries(config_generator log os)

add_library(hostapd_service hostapd_service.c)
target_link_libraries(hostapd_service config_generator log os)
