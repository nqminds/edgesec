include_directories (
  "${PROJECT_SOURCE_DIR}/src"
)

add_library(identity identity.c)
target_link_libraries(identity PRIVATE log os)

add_library(sqlite_macconn_writer sqlite_macconn_writer.c)
target_link_libraries(sqlite_macconn_writer PUBLIC LibUTHash::LibUTHash mac_mapper PRIVATE sqliteu squeue log net os SQLite::SQLite3)

add_library(bridge_list bridge_list.c)
target_link_libraries(bridge_list PUBLIC LibUTHash::LibUTHash eloop::list PRIVATE log os)

add_library(mac_mapper mac_mapper.c)
target_link_libraries(mac_mapper
  PUBLIC LibUTHash::LibUTHash ap_config
  PRIVATE bridge_list net log os)

add_library(supervisor_utils supervisor_utils.c)
target_link_libraries(supervisor_utils PUBLIC supervisor_config PRIVATE mac_mapper sqlite_macconn_writer hash log os)

add_library(subscriber_events subscriber_events.c)
target_link_libraries(subscriber_events PUBLIC supervisor_config PRIVATE LibUTHash::LibUTHash log os sockctl SQLite::SQLite3)

add_library(network_commands network_commands.c)
target_link_libraries(network_commands
  PUBLIC supervisor_config
  PRIVATE capture_service dhcp_service ap_service sqlite_macconn_writer mac_mapper eloop::eloop firewall_service base64 net log os
)
if (USE_CRYPTO_SERVICE)
  target_link_libraries(network_commands PRIVATE crypt_service)
  target_link_libraries(supervisor_utils PRIVATE crypt_service)
endif()

if (USE_CRYPTO_SERVICE)
  add_library(crypt_commands crypt_commands.c)
  target_link_libraries(crypt_commands
    PRIVATE
      mac_mapper supervisor sqlite_macconn_writer network_commands
      ap_config ap_service crypt_service capture_service allocs os log base64 eloop::eloop
  )
endif ()

add_library(system_commands system_commands.c)
target_link_libraries(system_commands
  PUBLIC sockctl supervisor_config
  PRIVATE
    LibUTHash::LibUTHash
    supervisor_utils
    mac_mapper supervisor sqlite_macconn_writer network_commands subscriber_events
    ap_config ap_service #../ap/*
    capture_service #../capture/*
    allocs os log base64 eloop::eloop sockctl LibUTHash::LibUTHash iface_mapper #../utils/*
)

add_library(cmd_processor cmd_processor.c)
target_link_libraries(cmd_processor
  PUBLIC LibUTHash::LibUTHash sockctl supervisor_config
  PRIVATE
    mac_mapper network_commands system_commands
    allocs os log net base64 sockctl # the ./utils/
)
if (USE_CRYPTO_SERVICE)
  target_link_libraries(cmd_processor PRIVATE crypt_commands)
endif()

add_library(supervisor_config INTERFACE)
set_target_properties(supervisor_config PROPERTIES PUBLIC_HEADER "supervisor_config.h")
target_link_libraries(supervisor_config INTERFACE SQLite::SQLite3 iface ap_config dhcp_config)

add_library(supervisor supervisor.c)
target_include_directories(supervisor PUBLIC $<TARGET_PROPERTY:iface,INCLUDE_DIRECTORIES>)
target_link_libraries(supervisor PUBLIC identity supervisor_config PRIVATE LibUTHash::LibUTHash supervisor_utils capture_service network_commands cmd_processor sockctl log firewall_service)
