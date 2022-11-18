add_compile_options(
  # Error on all C/C++ warnings in the src/ directory if making a Debug build
  $<$<CONFIG:Debug>:-Werror>
  # Warn/error if using a non-const pointer to a string literal
  $<$<COMPILE_LANGUAGE:C>:-Wwrite-strings>
)

add_subdirectory(utils)
add_subdirectory(supervisor)
add_subdirectory(ap)
add_subdirectory(dhcp)
add_subdirectory(firewall)
add_subdirectory(radius EXCLUDE_FROM_ALL)
if (USE_CRYPTO_SERVICE)
  add_subdirectory(crypt)
endif ()
if (USE_MDNS_SERVICE)
  add_subdirectory(dns)
endif ()
add_subdirectory(capture)


add_library(sqlhook SHARED sqlhook.c)
target_link_libraries(sqlhook PRIVATE sockctl os allocs SQLite::SQLite3 LibUTHash::LibUTHash)

add_library(runctl runctl.c)
target_include_directories(runctl PRIVATE SQLite::SQLite3)
if (USE_RADIUS_SERVICE)
  target_compile_definitions(runctl PUBLIC WITH_RADIUS_SERVICE)
  target_link_libraries(runctl PRIVATE radius_service)
endif ()
if (USE_CRYPTO_SERVICE)
  target_link_libraries(runctl PRIVATE crypt_service)
endif ()
if (USE_MDNS_SERVICE)
  target_compile_definitions(runctl PUBLIC WITH_MDNS_SERVICE)
  target_link_libraries(runctl PRIVATE mdns_service)
endif ()
target_link_libraries(runctl PRIVATE
  LibUTHash::LibUTHash capture_service net log iface_mapper os
  sqlite_macconn_writer firewall_service eloop::eloop supervisor
  network_commands mac_mapper ap_service firewall_service dhcp_service
  Threads::Threads
)

add_library(config config.c)
target_link_libraries(config PUBLIC supervisor_config LibUTHash::LibUTHash PRIVATE MinIni::minIni os log)

add_executable(edgesec edgesec.c)
if (USE_CRYPTO_SERVICE)
  add_compile_definitions(WITH_CRYPTO_SERVICE)
  target_include_directories(edgesec PRIVATE ${PROJECT_BINARY_DIR} ${LIBOPENSSL_INCLUDE_PATH})
else ()
  target_include_directories(edgesec PRIVATE ${PROJECT_BINARY_DIR})
endif ()
target_link_libraries(edgesec PRIVATE eloop::eloop config runctl os hashmap Threads::Threads)
# link time optimization
set_target_properties(edgesec PROPERTIES INTERPROCEDURAL_OPTIMIZATION TRUE)

if (USE_CAPTURE_SERVICE)
  add_executable(recap recap.c)
  target_link_libraries(recap PRIVATE capture_service protobuf_middleware packet_queue packet_decoder sqlite_header os log SQLite::SQLite3)
  target_include_directories(recap PRIVATE ${PROJECT_BINARY_DIR})
endif()
