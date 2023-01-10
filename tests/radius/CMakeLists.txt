include_directories(
  "${PROJECT_SOURCE_DIR}/src"
)

if (TARGET hostapd::libeap)
  set(EAP_TEST_DIR "${CMAKE_SOURCE_DIR}/tests/data/eap/")
  add_compile_definitions(EAP_TEST_DIR="${EAP_TEST_DIR}")

  add_library(eap_test_peer eap_test_peer.c)
  target_link_libraries(eap_test_peer PRIVATE hostapd::libeap)
  target_compile_definitions(eap_test_peer PRIVATE _DEFAULT_SOURCE _BSD_SOURCE IEEE8021X_EAPOL)

  add_library(eap_test_server eap_test_server.c)
  target_link_libraries(eap_test_server PRIVATE hostapd::libeap)
  target_compile_definitions(eap_test_server PRIVATE _DEFAULT_SOURCE _BSD_SOURCE IEEE8021X_EAPOL)

  add_cmocka_test(test_libeap
    SOURCES test_libeap.c
    LINK_LIBRARIES eap_test_peer eap_test_server hostapd::libeap cmocka::cmocka
  )
  target_compile_definitions(test_libeap PRIVATE _DEFAULT_SOURCE _BSD_SOURCE IEEE8021X_EAPOL)
endif ()

add_library(ip_addr ip_addr.c)
target_link_libraries(ip_addr PRIVATE os allocs)
# requires inet_aton, which is a non-standard glibc function, see https://linux.die.net/man/3/inet_aton
target_compile_definitions(ip_addr PRIVATE _DEFAULT_SOURCE _BSD_SOURCE)

add_library(radius_client radius_client.c)
target_link_libraries(radius_client PUBLIC ip_addr PRIVATE radius md5 wpabuf log os eloop)

add_cmocka_test(test_radius_server
  SOURCES test_radius_server.c
  LINK_LIBRARIES radius_client ip_addr radius_service log os eloop::eloop cmocka::cmocka
)
# requires inet_aton, which is a non-standard glibc function, see https://linux.die.net/man/3/inet_aton
target_compile_definitions(test_radius_server PRIVATE _DEFAULT_SOURCE _BSD_SOURCE)
