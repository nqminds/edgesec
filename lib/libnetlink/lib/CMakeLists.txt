add_library(json_writer STATIC json_writer.c)
target_link_libraries(json_writer color)
target_include_directories(json_writer PUBLIC "${SRC_INCLUDE_DIR}")
set_target_properties(json_writer
    PROPERTIES
    PUBLIC_HEADER "${SRC_INCLUDE_DIR}/json_writer.h"
    POSITION_INDEPENDENT_CODE ON
)

add_library(json_print STATIC json_print.c)
target_link_libraries(json_print json_writer color)
target_include_directories(json_print PUBLIC "${SRC_INCLUDE_DIR}")
set_target_properties(json_print
    PROPERTIES
    PUBLIC_HEADER "${SRC_INCLUDE_DIR}/json_print.h"
    POSITION_INDEPENDENT_CODE ON
)

add_library(color OBJECT color.c)
target_include_directories(color PUBLIC "${SRC_INCLUDE_DIR}")
set_target_properties(color
    PROPERTIES
    PUBLIC_HEADER "${SRC_INCLUDE_DIR}/color.h"
    POSITION_INDEPENDENT_CODE ON
)

add_library(rt_names STATIC rt_names.c ll_proto.c ll_types.c)
target_link_libraries(rt_names utils)
target_include_directories(rt_names PUBLIC "${SRC_INCLUDE_DIR}")
set_target_properties(rt_names
    PROPERTIES
    PUBLIC_HEADER "${SRC_INCLUDE_DIR}/rt_names.h"
    POSITION_INDEPENDENT_CODE ON
)

add_library(utils STATIC utils.c mpls_ntop.c mpls_pton.c ll_addr.c)
target_link_libraries(utils PRIVATE color PUBLIC ll_map libnetlink json_print)
target_include_directories(utils PUBLIC "${SRC_INCLUDE_DIR}")
list(APPEND utils_headers
  "${SRC_INCLUDE_DIR}/utils.h"
  "${SRC_INCLUDE_DIR}/rtm_map.h"
)
set_target_properties(utils
    PROPERTIES
    PUBLIC_HEADER "${utils_headers}"
)

add_library(libnetlink STATIC libnetlink.c)
target_link_libraries(libnetlink MNL::mnl)
target_include_directories(libnetlink PUBLIC "${SRC_INCLUDE_DIR}")
set_target_properties(libnetlink
    PROPERTIES
    PUBLIC_HEADER "${SRC_INCLUDE_DIR}/libnetlink.h"
)

add_library(ll_map STATIC ll_map.c)
target_link_libraries(ll_map utils libnetlink)
target_include_directories(ll_map PUBLIC "${SRC_INCLUDE_DIR}")
set_target_properties(ll_map
    PROPERTIES
    PUBLIC_HEADER "${SRC_INCLUDE_DIR}/ll_map.h"
)


set_target_properties(
    json_writer json_print color rt_names utils libnetlink ll_map
    PROPERTIES
    # allow compiling these static libs into a dynamic lib
    POSITION_INDEPENDENT_CODE ON
)
