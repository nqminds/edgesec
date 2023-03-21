#define _GNU_SOURCE

#include <setjmp.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <cmocka.h>
#include <fcntl.h>
#include <inttypes.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "capture/middlewares/protobuf_middleware/eth.pb-c.h"
#include "capture/middlewares/protobuf_middleware/protobuf_utils.h"
#include "capture/middlewares/protobuf_middleware/sync.pb-c.h"
#include "utils/allocs.h"
#include "utils/log.h"
#include "utils/os.h"

uint64_t timestamp = 999;
char *id = "id";
char *ifname = "ifname";
char *ether_dhost = "ether_dhost";
char *ether_shost = "ether_shost";
uint32_t caplen = 3;
uint32_t length = 4;
uint32_t ether_type = 8;
char *header_id = "eth";

uint8_t encoded[] = {0x36, 0x12, 0x03, 0x65, 0x74, 0x68, 0x1A, 0x2F, 0x08, 0xE7,
                     0x07, 0x12, 0x02, 0x69, 0x64, 0x18, 0x03, 0x20, 0x04, 0x2A,
                     0x06, 0x69, 0x66, 0x6E, 0x61, 0x6D, 0x65, 0x32, 0x0B, 0x65,
                     0x74, 0x68, 0x65, 0x72, 0x5F, 0x64, 0x68, 0x6F, 0x73, 0x74,
                     0x3A, 0x0B, 0x65, 0x74, 0x68, 0x65, 0x72, 0x5F, 0x73, 0x68,
                     0x6F, 0x73, 0x74, 0x40, 0x08};

/**
 * @brief Create an example Eth__EthSchema protobuf message.
 *
 * @param[out] out - Where to store the pointer to the bytes.
 * Must be deallocated with `free()` when done.
 * @return The number of bytes allocated to `out`.
 */
static ssize_t serialize_protobuf(uint8_t **out) {
  Eth__EthSchema eth = ETH__ETH_SCHEMA__INIT;

  eth.timestamp = timestamp;
  eth.id = id;

  eth.caplen = caplen;
  eth.length = length;
  eth.ifname = ifname;
  eth.ether_dhost = ether_dhost;
  eth.ether_shost = ether_shost;
  eth.ether_type = ether_type;

  size_t packed_size = eth__eth_schema__get_packed_size(&eth);

  *out = os_malloc(packed_size);
  return eth__eth_schema__pack(&eth, *out);
}

static void test_protobuf_serialization(void **state) {
  (void)state; /* unused */

  uint8_t *out = NULL;
  ssize_t out_size = serialize_protobuf(&out);

  Eth__EthSchema *eth_unpacked = eth__eth_schema__unpack(NULL, out_size, out);
  os_free(out);

  assert_int_equal(eth_unpacked->timestamp, timestamp);
  assert_string_equal(eth_unpacked->id, id);
  assert_int_equal(eth_unpacked->caplen, caplen);
  assert_int_equal(eth_unpacked->length, length);
  assert_string_equal(eth_unpacked->ether_dhost, ether_dhost);
  assert_string_equal(eth_unpacked->ether_shost, ether_shost);
  assert_int_equal(eth_unpacked->ether_type, ether_type);

  eth__eth_schema__free_unpacked(eth_unpacked, NULL);
}

static void test_protobuf_c_message_del_pack(void **state) {
  (void)state;

  uint8_t *out_eth = NULL;
  ssize_t out_eth_size = serialize_protobuf(&out_eth);

  Tdx__VoltApi__Sync__V1__ProtobufSyncWrapper sync =
      TDX__VOLT_API__SYNC__V1__PROTOBUF_SYNC_WRAPPER__INIT;

  sync.header_lookup_case =
      TDX__VOLT_API__SYNC__V1__PROTOBUF_SYNC_WRAPPER__HEADER_LOOKUP_HEADER_ID;
  sync.header_id = header_id;
  sync.payload.len = out_eth_size;
  sync.payload.data = out_eth;

  uint8_t encoded_size = ARRAY_SIZE(encoded);

  size_t sync_length =
      protobuf_c_message_del_get_packed_size((const ProtobufCMessage *)&sync);
  assert_int_equal(sync_length, encoded_size);

  uint8_t *sync_buffer = os_malloc(sync_length);

  protobuf_c_message_del_pack((const ProtobufCMessage *)&sync, sync_buffer);

  assert_memory_equal(encoded, sync_buffer, sync_length);

  os_free(sync_buffer);
  os_free(out_eth);
}

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_protobuf_serialization),
      cmocka_unit_test(test_protobuf_c_message_del_pack)};

  return cmocka_run_group_tests(tests, NULL, NULL);
}
