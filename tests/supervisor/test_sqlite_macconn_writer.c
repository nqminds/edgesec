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
#include "supervisor/sqlite_macconn_writer.h"
#include "supervisor/mac_mapper.h"

static const UT_icd mac_conn_icd = {sizeof(struct mac_conn), NULL, NULL, NULL};

extern int __real_sqlite3_open(const char *filename, sqlite3 **ppDb);

int __wrap_sqlite3_open(const char *filename, sqlite3 **ppDb) {
  return __real_sqlite3_open(filename, ppDb);
}

static void test_open_sqlite_macconn_db(void **state) {
  (void)state; /* unused */
  sqlite3 *db;

  assert_int_equal(open_sqlite_macconn_db(":memory:", &db), 0);

  free_sqlite_macconn_db(db);
}

static void test_save_sqlite_macconn_entry(void **state) {
  (void)state; /* unused */

  sqlite3 *db;
  struct mac_conn conn = {{0x04, 0xf0, 0x21, 0x5a, 0xf4, 0xc4}, {}};
  os_memset(&conn.info, 0, sizeof(conn.info));

  assert_int_equal(open_sqlite_macconn_db(":memory:", &db), 0);
  assert_int_equal(save_sqlite_macconn_entry(db, &conn), 0);
  assert_int_equal(save_sqlite_macconn_entry(db, NULL), -1);
  assert_int_equal(save_sqlite_macconn_entry(NULL, &conn), -1);
  assert_int_equal(save_sqlite_macconn_entry(NULL, NULL), -1);
  free_sqlite_macconn_db(db);
}

static void test_get_sqlite_macconn_entries(void **state) {
  (void)state; /* unused */

  sqlite3 *db;
  uint8_t addr1[ETHER_ADDR_LEN] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
  struct mac_conn conn, *p = NULL;
  UT_array *rows;

  os_memset(&conn, 0, sizeof(struct mac_conn));
  os_memcpy(conn.mac_addr, addr1, ETHER_ADDR_LEN);

  utarray_new(rows, &mac_conn_icd);

  assert_int_equal(open_sqlite_macconn_db(":memory:", &db), 0);
  assert_int_equal(save_sqlite_macconn_entry(db, &conn), 0);
  assert_int_equal(get_sqlite_macconn_entries(db, rows), 0);
  p = (struct mac_conn *)utarray_next(rows, p);
  assert_non_null(p);
  assert_memory_equal(p->mac_addr, addr1, ETHER_ADDR_LEN);

  p = (struct mac_conn *)utarray_next(rows, p);
  assert_null(p);
  utarray_free(rows);
  free_sqlite_macconn_db(db);

  utarray_new(rows, &mac_conn_icd);
  assert_int_equal(open_sqlite_macconn_db(":memory:", &db), 0);
  assert_int_equal(get_sqlite_macconn_entries(db, rows), 0);
  p = (struct mac_conn *)utarray_next(rows, p);
  assert_null(p);
  utarray_free(rows);
  free_sqlite_macconn_db(db);
}

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_open_sqlite_macconn_db),
      cmocka_unit_test(test_save_sqlite_macconn_entry),
      cmocka_unit_test(test_get_sqlite_macconn_entries)};

  return cmocka_run_group_tests(tests, NULL, NULL);
}
