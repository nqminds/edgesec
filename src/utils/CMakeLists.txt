add_library(log log.c)
target_compile_options(log PRIVATE -fPIC)
add_library(allocs allocs.c)

if (USE_CRYPTO_SERVICE)
  add_library(cryptou cryptou.c)
  target_include_directories(cryptou BEFORE PRIVATE ${LIBOPENSSL_INCLUDE_PATH})
  target_link_libraries(cryptou PRIVATE base64 os log ${LIBCRYPTO_LIB})
endif ()

add_library(base64 base64.c)
target_link_libraries(base64 PRIVATE os log)

add_library(os os.c)
target_compile_options(os PRIVATE -fPIC)
target_link_libraries(os PRIVATE allocs log util_linux::uuid)

add_library(ifaceu ifaceu.c)
target_link_libraries(ifaceu PRIVATE log)

add_library(net net.c)
target_link_libraries(net PRIVATE log os)

add_library(iptables iptables.c)
target_link_libraries(iptables PRIVATE net os log)

add_library(iface_mapper iface_mapper.c)
target_link_libraries(iface_mapper PRIVATE net log os)

add_library(iface iface.c)
if (USE_NETLINK_SERVICE)
  add_library(nl nl.c)
  target_include_directories(nl PRIVATE ${LIBNETLINK_UAPI_INCLUDE_PATH} ${LIBNETLINK_INCLUDE_PATH} ${LIBNL_INCLUDE_DIR})
  target_link_libraries(nl PRIVATE ifaceu ${LIBNL_LIBRARY} ${LIBNL_GENL_LIBRARY} ${LIBNETLINK_LIB} MNL::mnl ${LL_MAP_LIB} ${UTILS_LIB} ${RT_NAMES_LIB} log os net)

  target_link_libraries(iface PRIVATE ifaceu nl net log os)
elseif (USE_UCI_SERVICE)
  add_library(uci_wrt uci_wrt.c)
  target_include_directories(uci_wrt PUBLIC ${LIBUCI_INCLUDE_PATH})
  target_link_libraries(uci_wrt PRIVATE squeue net os log ${LIBUCI_STATIC_LIB})

  target_link_libraries(iface PUBLIC ifaceu uci_wrt net log os)
elseif (USE_GENERIC_IP_SERVICE)
  add_compile_definitions(WITH_IP_GENERIC_SERVICE)
  add_library(ipgen ipgen.c)
  target_link_libraries(ipgen PRIVATE os log net)

  target_link_libraries(iface PUBLIC ifaceu ipgen net log os)
else ()
  target_link_libraries(iface PRIVATE ifaceu net log os)
endif ()

add_library(hashmap hashmap.c)
target_link_libraries(hashmap PRIVATE log os)

add_library(minIni minIni.c)

add_library(eloop eloop.c)
target_link_libraries(eloop PRIVATE log os)

add_library(hash hash.c)
target_link_libraries(hash PRIVATE os)

add_library(squeue squeue.c)
target_link_libraries(squeue PRIVATE log os)

add_library(sqliteu sqliteu.c)
target_include_directories(sqliteu BEFORE PRIVATE ${LIBSQLITE_INCLUDE_DIR})
target_link_libraries(sqliteu PRIVATE log os SQLite::sqlite)

add_library(domain domain.c)
target_link_libraries(domain PRIVATE log os)
