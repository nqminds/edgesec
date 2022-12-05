include_directories (
  "${PROJECT_SOURCE_DIR}/src"
)

add_library(md5_internal md5_internal.c)
target_link_libraries(md5_internal PRIVATE log os)

add_library(md5 md5.c)
target_link_libraries(md5 PRIVATE md5_internal os)

add_library(wpabuf wpabuf.c)
target_link_libraries(wpabuf PRIVATE log os)
# wpabuf.h has BSD functions like be16toh, see https://linux.die.net/man/3/be16toh
target_compile_definitions(wpabuf PUBLIC _DEFAULT_SOURCE _BSD_SOURCE)

add_library(radius radius.c)
target_link_libraries(radius PRIVATE wpabuf md5 md5_internal log os)

add_library(radius_server radius_server.c)
target_link_libraries(radius_server PUBLIC os eloop::eloop PRIVATE radius wpabuf log net)

add_library(radius_service radius_service.c)
target_link_libraries(radius_service PRIVATE radius_server)
