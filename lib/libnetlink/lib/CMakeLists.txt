include_directories(
  "${SRC_INCLUDE_DIR}"
  "${UAPI_INCLUDE_DIR}"
)

add_library(json_writer json_writer.c)
target_link_libraries(json_writer color)
set_target_properties(json_writer
    PROPERTIES
    PUBLIC_HEADER "${SRC_INCLUDE_DIR}/json_writer.h"
)

add_library(json_print json_print.c)
target_link_libraries(json_print json_writer color)
set_target_properties(json_print
    PROPERTIES
    PUBLIC_HEADER "${SRC_INCLUDE_DIR}/json_print.h"
)

add_library(color color.c)
set_target_properties(color
    PROPERTIES
    PUBLIC_HEADER "${SRC_INCLUDE_DIR}/color.h"
)

add_library(rt_names SHARED rt_names.c ll_proto.c ll_types.c)
target_link_libraries(rt_names utils)
set_target_properties(rt_names
    PROPERTIES
    PUBLIC_HEADER "${SRC_INCLUDE_DIR}/rt_names.h"
)

add_library(utils SHARED utils.c mpls_ntop.c mpls_pton.c ll_addr.c)
target_link_libraries(utils color json_print)
list(APPEND utils_headers
  "${SRC_INCLUDE_DIR}/utils.h"
  "${SRC_INCLUDE_DIR}/libnetlink.h"
  "${SRC_INCLUDE_DIR}/ll_map.h"
  "${SRC_INCLUDE_DIR}/rtm_map.h"
  "${SRC_INCLUDE_DIR}/json_print.h"

)
set_target_properties(utils
    PROPERTIES
    PUBLIC_HEADER "${utils_headers}"
)

add_library(libnetlink SHARED libnetlink.c)
target_link_libraries(libnetlink MNL::mnl)
set_target_properties(libnetlink
    PROPERTIES
    PUBLIC_HEADER "${SRC_INCLUDE_DIR}/libnetlink.h"
)

add_library(ll_map SHARED ll_map.c)
target_link_libraries(ll_map utils libnetlink)
set_target_properties(ll_map
    PROPERTIES
    PUBLIC_HEADER "${SRC_INCLUDE_DIR}/ll_map.h"
)
