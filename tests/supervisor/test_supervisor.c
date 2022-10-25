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
#include "supervisor/supervisor.h"

static const UT_icd config_ifinfo_icd = {sizeof(config_ifinfo_t), NULL, NULL,
                                         NULL};

static void test_get_mac_conn_cmd(void **state) {
  (void)state; /* unused */
  uint8_t mac_addr[6] = {0x04, 0xf0, 0x21, 0x5a, 0xf4, 0xc4};
  uint8_t wpa_passphrase[4] = {0x1, 0x2, 0x3, 0x0};

  struct supervisor_context ctx = {};
  ctx.exec_capture = false;
  ctx.allow_all_nat = true;
  ctx.allow_all_connections = true;
  ctx.allocate_vlans = true;
  ctx.default_open_vlanid = 0;
  os_memcpy(ctx.wpa_passphrase, wpa_passphrase, 4);
  ctx.wpa_passphrase_len = 4;

  config_ifinfo_t el;
  utarray_new(ctx.config_ifinfo_array, &config_ifinfo_icd);

  for (int idx = 0; idx <= 10; idx ++) {
    el.vlanid = idx;
    utarray_push_back(ctx.config_ifinfo_array, &el);
  }
  // struct mac_conn_info info = 
  get_mac_conn_cmd(mac_addr, (void *)&ctx);
  utarray_free(ctx.config_ifinfo_array);
}

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_get_mac_conn_cmd),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
