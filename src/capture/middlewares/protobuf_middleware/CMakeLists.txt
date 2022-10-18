include_directories (
  "${PROJECT_SOURCE_DIR}/src"
)

add_library(protobuf_middleware protobuf_middleware.c)
target_include_directories(protobuf_middleware PRIVATE ${PROJECT_BINARY_DIR})
target_link_libraries(protobuf_middleware PUBLIC protobufc::protobufc pcap_service eloop PRIVATE allocs os log)
