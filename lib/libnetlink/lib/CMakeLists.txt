include_directories(
  "${SRC_INCLUDE_DIR}"
  "${UAPI_INCLUDE_DIR}"
)
add_library(mpls_ntop mpls_ntop.c)
add_library(mpls_pton mpls_pton.c)

add_library(json_writer json_writer.c)
target_link_libraries(json_writer color)

add_library(json_print json_print.c)
target_link_libraries(json_print json_writer color)

add_library(color color.c)

add_library(ll_addr ll_addr.c)

add_library(rt_names SHARED rt_names.c)
target_link_libraries(rt_names utils)

add_library(utils SHARED utils.c)
target_link_libraries(utils color json_print mpls_ntop ll_addr mpls_pton)

add_library(libnetlink SHARED libnetlink.c)
target_link_libraries(libnetlink MNL::mnl)

add_library(ll_types SHARED ll_types.c)

add_library(ll_proto SHARED ll_proto.c)

add_library(ll_map SHARED ll_map.c)
target_link_libraries(ll_map utils libnetlink)
