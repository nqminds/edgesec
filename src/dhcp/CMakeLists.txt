include_directories (
  "${EDGESEC_SOURCE_DIR}/src"
)

add_library(dnsmasq dnsmasq.c)
if (USE_UCI_SERVICE)
    target_include_directories(dnsmasq PRIVATE ${LIBUCI_INCLUDE_PATH})
    target_link_libraries(dnsmasq PRIVATE log os ${LIBUCI_STATIC_LIB})
else ()
  target_link_libraries(dnsmasq PRIVATE log os)
endif ()


add_library(dhcp_service dhcp_service.c)
target_link_libraries(dhcp_service PRIVATE dnsmasq log os)
