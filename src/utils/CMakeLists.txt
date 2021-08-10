if (BUILD_NETLINK_LIB)
  include_directories(
    "${LIBNETLINK_UAPI_INCLUDE_PATH}"
    "${LIBNETLINK_INCLUDE_PATH}"
  )
endif ()

if (BUILD_UUID_LIB)
  include_directories("${LIBUUID_INCLUDE_DIR}")
endif ()

if (BUILD_OPENSSL_LIB)
  include_directories("${LIBOPENSSL_INCLUDE_PATH}")
endif ()

if (BUILD_NL_LIB)
  include_directories("${LIBNL_INCLUDE_DIR}")
endif ()

if (BUILD_SQLITE_LIB)
 include_directories("${LIBSQLITE_INCLUDE_DIR}")
endif ()

add_library(log log.c)

add_library(cryptou cryptou.c)
target_link_libraries(cryptou base64 os log ${LIBCRYPTO_LIB})

add_library(base64 base64.c)
target_link_libraries(base64 os log)

add_library(os os.c)
target_link_libraries(os log ${LIBUUID_LIB})

add_library(iptables iptables.c)
target_link_libraries(iptables os log)

add_library(if if.c)
target_link_libraries(if ${LIBNL_LIBRARY} ${LIBNL_GENL_LIBRARY} ${LIBNETLINK_LIB} ${LL_MAP_LIB} ${UTILS_LIB} ${RT_NAMES_LIB} ${LL_TYPES_LIB} log os)

add_library(iw iw.c)
target_link_libraries(iw ${LIBNL_LIBRARY} ${LIBNL_GENL_LIBRARY} ${LIBNETLINK_LIB} ${LL_MAP_LIB} ${UTILS_LIB} ${RT_NAMES_LIB} ${LL_TYPES_LIB} log)

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
target_link_libraries(sqliteu log os ${LIBSQLITE_LIB})

add_library(domain domain.c)
target_link_libraries(domain log os)
