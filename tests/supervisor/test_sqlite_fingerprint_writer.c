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
#include "supervisor/sqlite_fingerprint_writer.h"

static const UT_icd fingerprint_icd = {sizeof(struct fingerprint_row), NULL,
                                       NULL, NULL};

int __wrap_sqlite3_open(const char *filename, sqlite3 **ppDb) {
  return __real_sqlite3_open(filename, ppDb);
}

static void test_open_sqlite_fingerprint_db(void **state) {
  (void)state; /* unused */
  sqlite3 *db;

  assert_int_equal(open_sqlite_fingerprint_db(":memory:", &db), 0);

  free_sqlite_fingerprint_db(db);
}

static void test_save_sqlite_fingerprint_row(void **state) {
  (void)state; /* unused */

  char *mac = "11:22:33:44:55:66";
  char *protocol = "IP";
  char *fingerprint = "12345";
  uint64_t timestamp = 12345;
  char *query = "port 80";

  struct fingerprint_row row = {.mac = mac,
                                .protocol = protocol,
                                .fingerprint = fingerprint,
                                .timestamp = timestamp,
                                .query = query};

  sqlite3 *db;

  assert_int_equal(open_sqlite_fingerprint_db(":memory:", &db), 0);
  assert_int_equal(save_sqlite_fingerprint_row(db, &row), 0);
  assert_int_equal(save_sqlite_fingerprint_row(db, NULL), -1);
  assert_int_equal(save_sqlite_fingerprint_row(NULL, &row), -1);
  assert_int_equal(save_sqlite_fingerprint_row(NULL, NULL), -1);
  free_sqlite_fingerprint_db(db);
}

static void test_get_sqlite_fingerprint_rows(void **state) {
  (void)state; /* unused */

  char *mac = "11:22:33:44:55:66";
  char *protocol = "IP";
  char *fingerprint = "12345";
  uint64_t timestamp = 12345;
  char *query = "port 80";
  char *op = "<=", *op1 = ">";
  UT_array *rows;
  struct fingerprint_row in = {.mac = mac,
                               .protocol = protocol,
                               .fingerprint = fingerprint,
                               .timestamp = timestamp,
                               .query = query},
                         *p = NULL;

  sqlite3 *db;
  utarray_new(rows, &fingerprint_icd);

  assert_int_equal(open_sqlite_fingerprint_db(":memory:", &db), 0);
  assert_int_equal(save_sqlite_fingerprint_row(db, &in), 0);
  assert_int_equal(
      get_sqlite_fingerprint_rows(db, mac, timestamp, op, protocol, rows), 0);
  p = (struct fingerprint_row *)utarray_next(rows, p);
  assert_non_null(p);

  assert_string_equal(p->mac, mac);
  assert_string_equal(p->protocol, protocol);
  assert_string_equal(p->fingerprint, fingerprint);
  assert_int_equal(p->timestamp, timestamp);
  assert_string_equal(p->query, query);

  p = (struct fingerprint_row *)utarray_next(rows, p);
  assert_null(p);
  free_sqlite_fingerprint_rows(rows);

  utarray_new(rows, &fingerprint_icd);
  assert_int_equal(
      get_sqlite_fingerprint_rows(db, mac, timestamp, op1, protocol, rows), 0);
  p = (struct fingerprint_row *)utarray_next(rows, p);
  assert_null(p);
  free_sqlite_fingerprint_rows(rows);

  free_sqlite_fingerprint_db(db);

  utarray_new(rows, &fingerprint_icd);
  assert_int_equal(open_sqlite_fingerprint_db(":memory:", &db), 0);
  assert_int_equal(
      get_sqlite_fingerprint_rows(db, mac, timestamp, op, protocol, rows), 0);
  p = (struct fingerprint_row *)utarray_next(rows, p);
  assert_null(p);
  free_sqlite_fingerprint_rows(rows);
  free_sqlite_fingerprint_db(db);
}

int main(int argc, char *argv[]) {
  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_open_sqlite_fingerprint_db),
      cmocka_unit_test(test_save_sqlite_fingerprint_row),
      cmocka_unit_test(test_get_sqlite_fingerprint_rows)};

  return cmocka_run_group_tests(tests, NULL, NULL);
}
