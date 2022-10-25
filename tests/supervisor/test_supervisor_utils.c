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
#include "supervisor/supervisor_utils.h"

static const UT_icd config_ifinfo_icd = {sizeof(config_ifinfo_t), NULL, NULL,
                                         NULL};

static void test_allocate_vlan(void **state) {
  (void)state; /* unused */
  uint8_t mac_addr[6] = {0x04, 0xf0, 0x21, 0x5a, 0xf4, 0xc4};

  struct supervisor_context ctx = {};
  ctx.allocate_vlans = true;
  ctx.default_open_vlanid = 0;

  config_ifinfo_t el;
  utarray_new(ctx.config_ifinfo_array, &config_ifinfo_icd);

  for (int idx = 0; idx <= 10; idx ++) {
    el.vlanid = 0;
    utarray_push_back(ctx.config_ifinfo_array, &el);
  }

  int vlanid = allocate_vlan(&ctx, mac_addr);
  assert_in_range(vlanid, 0, 10);

  utarray_free(ctx.config_ifinfo_array);
}

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_allocate_vlan),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
