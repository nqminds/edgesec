include_directories (
  "${EDGESEC_SOURCE_DIR}/src"
)

add_library(subnet_service subnet_service.c)
target_link_libraries(subnet_service log if os hashmap log)