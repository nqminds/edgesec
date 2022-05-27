include_directories (
  "${EDGESEC_SOURCE_DIR}/src"
)

add_library(hostapd hostapd.c)
if (USE_UCI_SERVICE)
  target_link_libraries(hostapd PRIVATE log os iface OpenWRT::UCI)
else ()
  target_link_libraries(hostapd PRIVATE log os iface)
endif()

add_library(ap_service ap_service.c)
target_link_libraries(ap_service PUBLIC supervisor_config PRIVATE domain hostapd log os eloop)
