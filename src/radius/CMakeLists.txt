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
target_link_libraries(radius PRIVATE wpabuf md5 md5_internal os)

add_library(attr_mapper attr_mapper.c)
target_link_libraries(attr_mapper PRIVATE wpabuf radius os log)

add_library(radius_server radius_server.c)
add_library(radius_service radius_service.c)
if (BUILD_HOSTAPD_EAP_LIB)
  add_compile_definitions(WITH_EAP_LIB)
  target_link_libraries(radius_server PUBLIC eloop::eloop PRIVATE net radius wpabuf hostapd::libeap OpenSSL3::SSL OpenSSL3::Crypto SQLite::SQLite3)
  target_link_libraries(radius_service PRIVATE identity attr_mapper radius_server hostapd::libeap OpenSSL3::SSL OpenSSL3::Crypto)
else()
  target_link_libraries(radius_server PUBLIC os eloop::eloop PRIVATE attr_mapper radius wpabuf log net)
  target_link_libraries(radius_service PRIVATE identity radius_server)
endif ()
target_compile_definitions(radius_server PRIVATE _DEFAULT_SOURCE _BSD_SOURCE IEEE8021X_EAPOL CONFIG_TESTING_OPTIONS)
