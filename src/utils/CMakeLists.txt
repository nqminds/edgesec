add_library(log log.c)
add_library(allocs allocs.c)

add_library(cryptou cryptou.c)
target_include_directories(cryptou BEFORE PRIVATE ${LIBOPENSSL_INCLUDE_PATH})
target_link_libraries(cryptou PRIVATE base64 os log ${LIBCRYPTO_LIB})

add_library(base64 base64.c)
target_link_libraries(base64 os log)

add_library(os os.c)
target_include_directories(os PUBLIC ${LIBUUID_INCLUDE_DIR})
target_link_libraries(os PUBLIC allocs log ${LIBUUID_LIB})

add_library(iptables iptables.c)
target_link_libraries(iptables os log)

if (USE_NETLINK_LIB)
  add_library(nl nl.c)
  target_include_directories(nl PRIVATE ${LIBNETLINK_UAPI_INCLUDE_PATH} ${LIBNETLINK_INCLUDE_PATH})
  target_link_libraries(nl ${LIBNL_LIBRARY} ${LIBNL_GENL_LIBRARY} ${LIBNETLINK_LIB} MNL::mnl ${LL_MAP_LIB} ${UTILS_LIB} ${RT_NAMES_LIB} log os)
endif ()

add_library(if if.c)
if (USE_NETLINK_LIB)
  target_link_libraries(if nl log os)
else ()
  target_link_libraries(if log os)
endif ()

if (BUILD_NL_LIB)
  add_library(iw iw.c)
  target_include_directories(iw PRIVATE ${LIBNL_INCLUDE_DIR})
  target_link_libraries(iw ${LIBNL_LIBRARY} ${LIBNL_GENL_LIBRARY} ${LIBNETLINK_LIB} MNL::mnl ${LL_MAP_LIB} ${UTILS_LIB} ${RT_NAMES_LIB} log)
endif ()

add_library(hashmap hashmap.c)
target_link_libraries(hashmap log os)

add_library(minIni minIni.c)

add_library(eloop eloop.c)
target_link_libraries(eloop log os)

add_library(hash hash.c)
target_link_libraries(hash os)

add_library(squeue squeue.c)
target_link_libraries(squeue log os)

add_library(sqliteu sqliteu.c)
target_include_directories(sqliteu BEFORE PRIVATE ${LIBSQLITE_INCLUDE_DIR})
target_link_libraries(sqliteu log os ${LIBSQLITE_LIB})

add_library(domain domain.c)
target_link_libraries(domain log os)
