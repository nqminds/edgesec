#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>

#include "utils/log.h"
#include "capture/middlewares/protobuf_middleware/eth.pb-c.h"
#include "capture/middlewares/protobuf_middleware/protobuf_encoder.h"

static void test_protobuf_serialization(void **state) {
  (void)state; /* unused */

  char *id = "test";
  char *ifname = "wlan";
  char *ether_dhost = "11:22:33:44:55:66";
  char *ether_shost = "AA:BB:CC:DD:EE:FF";

  Eth__EthSchema eth = ETH__ETH_SCHEMA__INIT;

  eth.timestamp = 12345;
  eth.id = id;

  eth.caplen = 1024;
  eth.length = 4096;
  eth.ifname = ifname;
  eth.ether_dhost = ether_dhost;
  eth.ether_shost = ether_shost;
  eth.ether_type = 0x8000;

  size_t estimated_size = sizeof(eth.timestamp) +
                          strlen(eth.id) + sizeof(eth.caplen) +
                          sizeof(eth.length) + strlen(eth.ifname) +
                          strlen(eth.ether_dhost) + strlen(eth.ether_shost) +
                          sizeof(eth.ether_type) + 1;
  size_t packed_size = eth__eth_schema__get_packed_size(&eth);

  assert_int_equal(packed_size, estimated_size);

  uint8_t *out = os_malloc(packed_size);
  size_t out_size = eth__eth_schema__pack(&eth, out);

  assert_int_equal(packed_size, out_size);

  Eth__EthSchema *eth_unpacked = eth__eth_schema__unpack(NULL, out_size, out);

  assert_int_equal(eth_unpacked->timestamp, 12345);
  assert_string_equal(eth_unpacked->id, id);
  assert_int_equal(eth_unpacked->caplen, 1024);
  assert_int_equal(eth_unpacked->length, 4096);
  assert_string_equal(eth_unpacked->ether_dhost, ether_dhost);
  assert_string_equal(eth_unpacked->ether_shost, ether_shost);
  assert_int_equal(eth_unpacked->ether_type, 0x8000);

  eth__eth_schema__free_unpacked(eth_unpacked, NULL);
  os_free(out);
}

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_protobuf_serialization)
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
