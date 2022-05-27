include_directories (
  "${EDGESEC_SOURCE_DIR}/src"
)

add_library(hostapd hostapd.c)
if (USE_UCI_SERVICE)
  target_include_directories(hostapd PRIVATE ${LIBUCI_INCLUDE_PATH})
  target_link_libraries(hostapd PRIVATE log os iface ${LIBUCI_STATIC_LIB})
else ()
  target_link_libraries(hostapd PRIVATE log os iface)
endif()

add_library(ap_service ap_service.c)
target_include_directories(ap_service PUBLIC $<TARGET_PROPERTY:iface,INCLUDE_DIRECTORIES>)
target_link_libraries(ap_service PUBLIC supervisor_config PRIVATE domain hostapd log os eloop)
