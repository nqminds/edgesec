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
#include "capture/middlewares/protobuf_middleware/sync.pb-c.h"
#include "capture/middlewares/protobuf_middleware/protobuf_encoder.h"

static void test_protobuf_serialization(void **state) {
  (void)state; /* unused */

  char *id = "id";
  char *ifname = "ifname";
  char *ether_dhost = "ether_dhost";
  char *ether_shost = "ether_shost";

  Eth__EthSchema eth = ETH__ETH_SCHEMA__INIT;

  eth.timestamp = 999;
  eth.id = id;

  eth.caplen = 3;
  eth.length = 4;
  eth.ifname = ifname;
  eth.ether_dhost = ether_dhost;
  eth.ether_shost = ether_shost;
  eth.ether_type = 8;

  size_t packed_size = eth__eth_schema__get_packed_size(&eth);

  uint8_t *out = os_malloc(packed_size);
  size_t out_size = eth__eth_schema__pack(&eth, out);

  assert_int_equal(packed_size, out_size);

  Eth__EthSchema *eth_unpacked = eth__eth_schema__unpack(NULL, out_size, out);
  os_free(out);

  assert_int_equal(eth_unpacked->timestamp, 999);
  assert_string_equal(eth_unpacked->id, id);
  assert_int_equal(eth_unpacked->caplen, 3);
  assert_int_equal(eth_unpacked->length, 4);
  assert_string_equal(eth_unpacked->ether_dhost, ether_dhost);
  assert_string_equal(eth_unpacked->ether_shost, ether_shost);
  assert_int_equal(eth_unpacked->ether_type, 8);

  eth__eth_schema__free_unpacked(eth_unpacked, NULL);
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
