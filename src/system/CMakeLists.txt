include_directories (
  "${EDGESEC_SOURCE_DIR}/src"
)

add_library(system_checks system_checks.c)
target_link_libraries(system_checks log iface os hashmap)
