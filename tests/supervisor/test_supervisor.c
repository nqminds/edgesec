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
#include "supervisor/supervisor_utils.h"
#include "supervisor/sqlite_macconn_writer.h"

#ifdef WITH_CRYPTO_SERVICE
#include "crypt/crypt_service.h"
#endif

static const UT_icd config_ifinfo_icd = {sizeof(config_ifinfo_t), NULL, NULL,
                                         NULL};
static const UT_icd mac_conn_icd = {sizeof(struct mac_conn), NULL, NULL, NULL};

static void test_get_mac_conn_cmd(void **state) {
  (void)state; /* unused */
  uint8_t mac_addr[6] = {0x04, 0xf0, 0x21, 0x5a, 0xf4, 0xc4};
  uint8_t wpa_passphrase[4] = {0x1, 0x2, 0x3, 0x0};

  struct supervisor_context ctx = {
      .exec_capture = false,
      .allow_all_nat = true,
      .allow_all_connections = true,
      .allocate_vlans = true,
      .default_open_vlanid = 0,
  };
  os_memcpy(ctx.wpa_passphrase, wpa_passphrase, ARRAY_SIZE(wpa_passphrase));
  ctx.wpa_passphrase_len = ARRAY_SIZE(wpa_passphrase);

#ifdef WITH_CRYPTO_SERVICE
  uint8_t secret[4] = {'s', 's', 'e', 'r'};
  ctx.crypt_ctx = load_crypt_service("", "key", secret, ARRAY_SIZE(secret));
  assert_non_null(ctx.crypt_ctx);
#endif

  config_ifinfo_t el = {0};
  utarray_new(ctx.config_ifinfo_array, &config_ifinfo_icd);

  for (int idx = 0; idx <= 10; idx++) {
    el.vlanid = idx;
    utarray_push_back(ctx.config_ifinfo_array, &el);
  }

  create_vlan_mapper(ctx.config_ifinfo_array, &ctx.vlan_mapper);
  open_sqlite_macconn_db(":memory:", &ctx.macconn_db);

  struct mac_conn_info info = get_mac_conn_cmd(mac_addr, (void *)&ctx);

  assert_int_equal(info.vlanid, 10);
  struct mac_conn_info info1;
  get_mac_mapper(&ctx.mac_mapper, mac_addr, &info1);

  assert_int_equal(info1.vlanid, 10);

  struct mac_conn *p = NULL;
  UT_array *rows;

  utarray_new(rows, &mac_conn_icd);

  get_sqlite_macconn_entries(ctx.macconn_db, rows);
  const struct mac_conn * p = (const struct mac_conn *)utarray_front(rows);
  assert_non_null(p);
  assert_memory_equal(p->mac_addr, mac_addr, ETHER_ADDR_LEN);
  assert_int_equal(p->info.vlanid, 10);
  utarray_free(rows);

  struct mac_conn conn;
  struct mac_conn_info info2;
  uint8_t mac_addr2[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

  info2.allow_connection = false;
  os_memcpy(conn.mac_addr, mac_addr2, ETHER_ADDR_LEN);
  os_memcpy(&conn.info, &info2, sizeof(struct mac_conn_info));

  assert_int_equal(save_mac_mapper(&ctx, conn), 0);

  struct mac_conn_info info3 = get_mac_conn_cmd(mac_addr2, (void *)&ctx);
  assert_int_equal(info3.vlanid, -1);

  utarray_free(ctx.config_ifinfo_array);
  free(ctx.crypt_ctx); // only needed if WITH_CRYPTO_SERVICE
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
