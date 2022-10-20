include_directories (
  "${PROJECT_SOURCE_DIR}/src"
)

add_library(eth.pb-c eth.pb-c.c)
target_link_libraries(eth.pb-c PUBLIC protobufc::protobufc)

add_library(arp.pb-c arp.pb-c.c)
target_link_libraries(arp.pb-c PUBLIC protobufc::protobufc)

add_library(ip4.pb-c ip4.pb-c.c)
target_link_libraries(ip4.pb-c PUBLIC protobufc::protobufc)

add_library(ip6.pb-c ip6.pb-c.c)
target_link_libraries(ip6.pb-c PUBLIC protobufc::protobufc)

add_library(tcp.pb-c tcp.pb-c.c)
target_link_libraries(tcp.pb-c PUBLIC protobufc::protobufc)

add_library(udp.pb-c udp.pb-c.c)
target_link_libraries(udp.pb-c PUBLIC protobufc::protobufc)

add_library(icmp4.pb-c icmp4.pb-c.c)
target_link_libraries(icmp4.pb-c PUBLIC protobufc::protobufc)

add_library(icmp6.pb-c icmp6.pb-c.c)
target_link_libraries(icmp6.pb-c PUBLIC protobufc::protobufc)

add_library(dns.pb-c dns.pb-c.c)
target_link_libraries(dns.pb-c PUBLIC protobufc::protobufc)

add_library(mdns.pb-c mdns.pb-c.c)
target_link_libraries(mdns.pb-c PUBLIC protobufc::protobufc)

add_library(dhcp.pb-c dhcp.pb-c.c)
target_link_libraries(dhcp.pb-c PUBLIC protobufc::protobufc)

add_library(protobuf_encoder protobuf_encoder.c)
target_link_libraries(protobuf_encoder PRIVATE eth.pb-c arp.pb-c ip4.pb-c ip6.pb-c)
target_link_libraries(protobuf_encoder PRIVATE tcp.pb-c udp.pb-c icmp4.pb-c)
target_link_libraries(protobuf_encoder PRIVATE icmp6.pb-c dns.pb-c mdns.pb-c dhcp.pb-c)
target_link_libraries(protobuf_encoder PUBLIC protobufc::protobufc PRIVATE allocs os log)

add_library(protobuf_middleware protobuf_middleware.c)
target_include_directories(protobuf_middleware PRIVATE ${PROJECT_BINARY_DIR})
target_link_libraries(protobuf_middleware PUBLIC pcap_service eloop PRIVATE protobuf_encoder allocs os log)
