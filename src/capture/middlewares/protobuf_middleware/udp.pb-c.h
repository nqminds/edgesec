/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: udp.proto */

#ifndef PROTOBUF_C_udp_2eproto__INCLUDED
#define PROTOBUF_C_udp_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1003000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1004001 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif

typedef struct Udp__UdpSchema Udp__UdpSchema;

/* --- enums --- */

/* --- messages --- */

struct Udp__UdpSchema {
  ProtobufCMessage base;
  /*
   * Packet id
   */
  char *id;
  /*
   * Packet source port
   */
  uint32_t source;
  /*
   * Packet destination port
   */
  uint32_t dest;
  /*
   * Packet udp length
   */
  uint32_t len;
  /*
   * Packet udp checksum
   */
  uint32_t check_p;
};
#define UDP__UDP_SCHEMA__INIT                                                  \
  {                                                                            \
    PROTOBUF_C_MESSAGE_INIT(&udp__udp_schema__descriptor)                      \
    , (char *)protobuf_c_empty_string, 0, 0, 0, 0                              \
  }

/* Udp__UdpSchema methods */
void udp__udp_schema__init(Udp__UdpSchema *message);
size_t udp__udp_schema__get_packed_size(const Udp__UdpSchema *message);
size_t udp__udp_schema__pack(const Udp__UdpSchema *message, uint8_t *out);
size_t udp__udp_schema__pack_to_buffer(const Udp__UdpSchema *message,
                                       ProtobufCBuffer *buffer);
Udp__UdpSchema *udp__udp_schema__unpack(ProtobufCAllocator *allocator,
                                        size_t len, const uint8_t *data);
void udp__udp_schema__free_unpacked(Udp__UdpSchema *message,
                                    ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*Udp__UdpSchema_Closure)(const Udp__UdpSchema *message,
                                       void *closure_data);

/* --- services --- */

/* --- descriptors --- */

extern const ProtobufCMessageDescriptor udp__udp_schema__descriptor;

PROTOBUF_C__END_DECLS

#endif /* PROTOBUF_C_udp_2eproto__INCLUDED */
