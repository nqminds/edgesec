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

add_library(radius_config INTERFACE)
set_target_properties(radius_config PROPERTIES PUBLIC_HEADER "radius_config.h")
target_link_libraries(radius_config INTERFACE net os)

add_library(attr_mapper attr_mapper.c)
target_link_libraries(attr_mapper PRIVATE wpabuf radius os log)

add_library(radius_server radius_server.c)
target_link_libraries(radius_server PUBLIC eloop::eloop PRIVATE radius wpabuf)
target_compile_definitions(radius_server
  PRIVATE
    _DEFAULT_SOURCE _BSD_SOURCE IEEE8021X_EAPOL
    $<$<CONFIG:Debug>:CONFIG_TESTING_OPTIONS> # runs TLS tests on some magic EAP usernames
)

if (BUILD_EAP_LIB)
  target_compile_definitions(radius_server PRIVATE WITH_EAP_LIB)
  target_link_libraries(radius_server PUBLIC hostapd::libeap OpenSSL::SSL PRIVATE net SQLite::SQLite3)
else ()
  target_link_libraries(radius_server PUBLIC os PRIVATE log net)
endif ()

add_library(radius_service radius_service.c)
target_link_libraries(radius_service PRIVATE radius_server attr_mapper)
