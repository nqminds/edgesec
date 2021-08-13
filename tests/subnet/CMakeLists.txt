include_directories (
  "${EDGESEC_SOURCE_DIR}/src"
  "${CMOCKA_INCLUDE_DIR}"
)

if (BUILD_NL_LIB)
  include_directories("${LIBNL_INCLUDE_DIR}")


  add_executable(test_subnet_service test_subnet_service.c)
  target_link_libraries(test_subnet_service PRIVATE log if iw os hashmap subnet_service cmocka-static)
  set_target_properties(test_subnet_service
         PROPERTIES
         LINK_FLAGS  "-Wl,--wrap=iface_exists -Wl,--wrap=get_netiw_info -Wl,--wrap=iwace_isvlan -Wl,--wrap=create_interface -Wl,--wrap=set_interface_ip -Wl,--wrap=set_interface_state -Wl,--wrap=get_interfaces -Wl,--wrap=if_nametoindex"
  )

  add_test(NAME test_subnet_service COMMAND test_subnet_service)
  set_tests_properties(test_subnet_service
   PROPERTIES
   WILL_FAIL FALSE)
endif ()

