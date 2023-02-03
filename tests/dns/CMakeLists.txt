include_directories(
  "${PROJECT_SOURCE_DIR}/src"
)

add_cmocka_test(test_mdns_list
  SOURCES test_mdns_list.c
  LINK_LIBRARIES os mdns_list log cmocka::cmocka
)

add_cmocka_test(test_mdns_mapper
  SOURCES test_mdns_mapper.c
  LINK_LIBRARIES mdns_mapper log cmocka::cmocka
)

add_cmocka_test(test_command_mapper
  SOURCES test_command_mapper.c
  LINK_LIBRARIES command_mapper log cmocka::cmocka
)

add_cmocka_test(test_reflection_list
  SOURCES test_reflection_list.c
  LINK_LIBRARIES os reflection_list log cmocka::cmocka
)

if (USE_MDNS_SERVICE AND USE_CAPTURE_SERVICE)
  add_cmocka_test(test_mdns_service
    SOURCES test_mdns_service.c
    LINK_LIBRARIES eloop::eloop mdns_service pcap_service log cmocka::cmocka
  )
  target_link_options(test_mdns_service
    PRIVATE
    "LINKER:--wrap=run_pcap,--wrap=edge_eloop_register_read_sock,--wrap=edge_eloop_init,--wrap=edge_eloop_run,--wrap=edge_eloop_free"
  )
endif ()
