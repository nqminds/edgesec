add_library(log log.c)
set_property(TARGET log PROPERTY POSITION_INDEPENDENT_CODE ON)

add_library(allocs allocs.c)

if (USE_CRYPTO_SERVICE)
  add_library(cryptou cryptou.c)
  target_link_libraries(cryptou PRIVATE base64 os log OpenSSL::Crypto)
endif ()

add_library(base64 base64.c)
target_link_libraries(base64 PRIVATE os log)

add_library(hashmap hashmap.c)
target_link_libraries(hashmap PUBLIC LibUTHash::LibUTHash PRIVATE log os)

add_library(os os.c)
set_property(TARGET os PROPERTY POSITION_INDEPENDENT_CODE ON)
target_link_libraries(os PUBLIC LibUTHash::LibUTHash PRIVATE hashmap allocs log LibUUID::LibUUID)

add_library(ifaceu ifaceu.c)
target_link_libraries(ifaceu PRIVATE log)

add_library(net net.c)
target_link_libraries(net PUBLIC LibUTHash::LibUTHash PRIVATE log os)

add_library(iptables iptables.c)
target_link_libraries(iptables PUBLIC LibUTHash::LibUTHash PRIVATE net os log)

add_library(iface_mapper iface_mapper.c)
target_link_libraries(iface_mapper PUBLIC os LibUTHash::LibUTHash PRIVATE net log os)

add_library(iface iface.c)
target_link_libraries(iface PUBLIC os LibUTHash::LibUTHash PRIVATE ifaceu net log)
if (USE_NETLINK_SERVICE)
  add_library(nl nl.c)
  target_link_libraries(nl PUBLIC LibUTHash::LibUTHash PRIVATE ifaceu NL::core NL::genl libnetlink MNL::mnl ll_map utils rt_names log os net)

  target_link_libraries(iface PUBLIC nl)
elseif (USE_UCI_SERVICE)
  add_library(uci_wrt uci_wrt.c)
  target_link_libraries(uci_wrt PUBLIC OpenWRT::UCI LibUTHash::LibUTHash PRIVATE squeue net os log)
  target_link_libraries(iface PUBLIC uci_wrt)
elseif (USE_GENERIC_IP_SERVICE)
  add_library(ipgen ipgen.c)
  target_link_libraries(ipgen PRIVATE os log net)
  target_link_libraries(iface PUBLIC ipgen)
endif ()

add_library(minIni minIni.c)

add_library(eloop eloop.c)
# todo, add list
target_link_libraries(eloop PUBLIC allocs os PRIVATE log)

add_library(hash hash.c)
target_link_libraries(hash PRIVATE os)

add_library(squeue squeue.c)
target_link_libraries(squeue PRIVATE log os)

add_library(sqliteu sqliteu.c)
target_link_libraries(sqliteu PUBLIC SQLite::SQLite3 PRIVATE log os)

add_library(sockctl sockctl.c)
target_link_libraries(sockctl PRIVATE net log os)
