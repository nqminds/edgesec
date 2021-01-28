include_directories (
  "${EDGESEC_SOURCE_DIR}/src"
)

add_library(hostapd_config hostapd_config.c)
target_link_libraries(hostapd_config log os)

add_library(hostapd_service hostapd_service.c)
target_link_libraries(hostapd_service hostapd_config log os)
