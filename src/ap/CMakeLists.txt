include_directories (
  "${PROJECT_SOURCE_DIR}/src"
)

add_library(ap_config INTERFACE) # header-only library
target_link_libraries(ap_config INTERFACE allocs os radius_server)

add_library(hostapd hostapd.c)
if (USE_UCI_SERVICE)
  target_link_libraries(hostapd PRIVATE log os iface OpenWRT::UCI)
else ()
  target_link_libraries(hostapd PRIVATE log os iface)
endif()

add_library(ap_service ap_service.c)
target_link_libraries(ap_service PUBLIC supervisor_config PRIVATE sockctl hostapd log os eloop)
