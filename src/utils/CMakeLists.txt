include_directories(
  "${LIBNETLINK_UAPI_INCLUDE_DIR}"
  "${LIBNETLINK_INCLUDE_DIR}"
)

add_library(log log.c)

add_library(os os.c)
target_link_libraries(os log)

add_library(iptables iptables.c)
target_link_libraries(iptables os log)

add_library(if if.c)
target_link_libraries(if ${LibNL_LIBRARY} ${LibNL_GENL_LIBRARY} ${LIBNETLINK_LIB} ${LL_MAP_LIB} ${UTILS_LIB} ${RT_NAMES_LIB} ${LL_TYPES_LIB} log os)

add_library(iw iw.c)
target_link_libraries(iw ${LibNL_LIBRARY} ${LibNL_GENL_LIBRARY} ${LIBNETLINK_LIB} ${LL_MAP_LIB} ${UTILS_LIB} ${RT_NAMES_LIB} ${LL_TYPES_LIB} log)

add_library(hashmap hashmap.c)
target_link_libraries(hashmap log os)

add_library(minIni minIni.c)

add_library(eloop eloop.c)
target_link_libraries(eloop log os)
