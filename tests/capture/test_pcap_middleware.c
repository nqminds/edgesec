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
#include <cmocka.h>

#include "utils/log.h"
#include "utils/sqliteu.h"
#include "capture/pcap_middleware/pcap_middleware.h"

static void test_open_sqlite_pcap_db(void **state) {
  (void)state; /* unused */
  sqlite3 *db;

  int ret = sqlite3_open(":memory:", &db);
  assert_int_equal(ret, SQLITE_OK);
  assert_int_equal(init_sqlite_pcap_db(db), 0);

  sqlite3_close(db);
}

static void test_save_sqlite_pcap_entry(void **state) {
  (void)state; /* unused */

  sqlite3 *db;

  int ret = sqlite3_open(":memory:", &db);
  assert_int_equal(ret, SQLITE_OK);

  assert_int_equal(init_sqlite_pcap_db(db), 0);
  assert_int_equal(
      save_sqlite_pcap_entry(db, "test", 12345, 10, 10, "wlan0", "port 80"), 0);
  sqlite3_close(db);
}
int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_open_sqlite_pcap_db),
      cmocka_unit_test(test_save_sqlite_pcap_entry)};

  return cmocka_run_group_tests(tests, NULL, NULL);
}
