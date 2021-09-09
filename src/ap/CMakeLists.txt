include_directories (
  "${EDGESEC_SOURCE_DIR}/src"
)

add_library(hostapd hostapd.c)
target_link_libraries(hostapd log os if)

add_library(ap_service ap_service.c)
target_include_directories(ap_service PRIVATE ${LIBSQLITE_INCLUDE_DIR})
target_link_libraries(ap_service hostapd log os)
