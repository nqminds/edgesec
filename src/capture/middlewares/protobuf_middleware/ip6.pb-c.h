/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: ip6.proto */

#ifndef PROTOBUF_C_ip6_2eproto__INCLUDED
#define PROTOBUF_C_ip6_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1003000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1004001 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif

typedef struct Ip6__Ip6Schema Ip6__Ip6Schema;

/* --- enums --- */

/* --- messages --- */

struct Ip6__Ip6Schema {
  ProtobufCMessage base;
  /*
   * Packet id
   */
  char *id;
  /*
   * Packet 4 bits version, 8 bits TC, 20 bits flow-ID
   */
  uint32_t ip6_un1_flow;
  /*
   * Packet payload length
   */
  uint32_t ip6_un1_plen;
  /*
   * Packet next header
   */
  uint32_t ip6_un1_nxt;
  /*
   * Packet hop limit
   */
  uint32_t ip6_un1_hlim;
  /*
   * Packet 4 bits version, top 4 bits tclass
   */
  uint32_t ip6_un2_vfc;
  /*
   * Packet source address
   */
  char *ip6_src;
  /*
   * Packet destination address
   */
  char *ip6_dst;
};
#define IP6__IP6_SCHEMA__INIT                                                  \
  {                                                                            \
    PROTOBUF_C_MESSAGE_INIT(&ip6__ip6_schema__descriptor)                      \
    , (char *)protobuf_c_empty_string, 0, 0, 0, 0, 0,                          \
        (char *)protobuf_c_empty_string, (char *)protobuf_c_empty_string       \
  }

/* Ip6__Ip6Schema methods */
void ip6__ip6_schema__init(Ip6__Ip6Schema *message);
size_t ip6__ip6_schema__get_packed_size(const Ip6__Ip6Schema *message);
size_t ip6__ip6_schema__pack(const Ip6__Ip6Schema *message, uint8_t *out);
size_t ip6__ip6_schema__pack_to_buffer(const Ip6__Ip6Schema *message,
                                       ProtobufCBuffer *buffer);
Ip6__Ip6Schema *ip6__ip6_schema__unpack(ProtobufCAllocator *allocator,
                                        size_t len, const uint8_t *data);
void ip6__ip6_schema__free_unpacked(Ip6__Ip6Schema *message,
                                    ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*Ip6__Ip6Schema_Closure)(const Ip6__Ip6Schema *message,
                                       void *closure_data);

/* --- services --- */

/* --- descriptors --- */

extern const ProtobufCMessageDescriptor ip6__ip6_schema__descriptor;

PROTOBUF_C__END_DECLS

#endif /* PROTOBUF_C_ip6_2eproto__INCLUDED */
