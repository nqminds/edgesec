include_directories (
  "${EDGESEC_SOURCE_DIR}/src"
)

add_library(md5_internal md5_internal.c)
target_link_libraries(md5_internal PRIVATE log os)

add_library(md5 md5.c)
target_link_libraries(md5 PRIVATE md5_internal os)

add_library(wpabuf wpabuf.c)
target_link_libraries(wpabuf PRIVATE log os)

add_library(radius radius.c)
target_link_libraries(radius PRIVATE wpabuf md5 md5_internal log os)

add_library(radius_server radius_server.c)
target_link_libraries(radius_server PRIVATE radius wpabuf log net os eloop)

add_library(radius_service radius_service.c)
target_link_libraries(radius_service PRIVATE radius_server)
