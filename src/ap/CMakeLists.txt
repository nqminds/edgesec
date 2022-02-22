include_directories (
  "${EDGESEC_SOURCE_DIR}/src"
)

add_library(hostapd hostapd.c)
target_link_libraries(hostapd PRIVATE log os iface)

add_library(ap_service ap_service.c)
target_include_directories(ap_service PRIVATE ${LIBSQLITE_INCLUDE_DIR} PUBLIC $<TARGET_PROPERTY:iface,INCLUDE_DIRECTORIES>)
target_link_libraries(ap_service PRIVATE domain hostapd log os eloop)
