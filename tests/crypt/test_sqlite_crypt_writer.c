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
#include "crypt/sqlite_crypt_writer.h"

int __wrap_sqlite3_open(const char *filename, sqlite3 **ppDb)
{
  return __real_sqlite3_open(filename, ppDb);
}

static void test_open_sqlite_crypt_db(void **state)
{
  (void) state; /* unused */
  sqlite3* db;

  assert_int_equal(open_sqlite_crypt_db(":memory:", &db), 0);
  
  free_sqlite_crypt_db(db);
}

static void test_save_sqlite_store_entry(void **state)
{
  (void) state; /* unused */

  sqlite3* db;
  char *key = "key";
  char *value = "value";
  char *id = "id";
  char *iv = "iv";

  struct store_row row = {.key = key, .value = value, .id = id, .iv = iv};

  assert_int_equal(open_sqlite_crypt_db(":memory:", &db), 0);
  assert_int_equal(save_sqlite_store_entry(db, &row), 0);
  free_sqlite_crypt_db(db);
}

static void test_get_sqlite_store_row(void **state)
{
  (void) state; /* unused */

  sqlite3* db;
  char *key = "key";
  char *value = "value";
  char *id = "id";
  char *iv = "iv";

  struct store_row in = {.key = key, .value = value, .id = id, .iv = iv};
  struct store_row *out;

  assert_int_equal(open_sqlite_crypt_db(":memory:", &db), 0);
  assert_int_equal(save_sqlite_store_entry(db, &in), 0);
  out = get_sqlite_store_row(db, "key");
  assert_non_null(out);
  assert_string_equal(out->key, "key");
  assert_string_equal(out->id, "id");
  assert_string_equal(out->value, "value");
  assert_string_equal(out->iv, "iv");

  free_sqlite_store_row(out);
  out = NULL;
  out = get_sqlite_store_row(db, "key1");
  assert_non_null(out);
  assert_null(out->key);
  free_sqlite_store_row(out);

  in.key = "key2";
  in.value = NULL;

  assert_int_equal(save_sqlite_store_entry(db, &in), 0);
  out = get_sqlite_store_row(db, "key2");
  assert_non_null(out);
  assert_null(out->value);
  free_sqlite_store_row(out);
  free_sqlite_crypt_db(db);
}

static void test_save_sqlite_secrets_entry(void **state)
{
  (void) state; /* unused */

  sqlite3* db;
  char *salt = "salt";
  char *value = "value";
  char *id = "id";
  char *iv = "iv";

  struct secrets_row row = {.salt = salt, .value = value, .id = id, .iv = iv};

  assert_int_equal(open_sqlite_crypt_db(":memory:", &db), 0);
  assert_int_equal(save_sqlite_secrets_entry(db, &row), 0);
  free_sqlite_crypt_db(db);
}

static void test_get_sqlite_secrets_row(void **state)
{
  (void) state; /* unused */

  sqlite3* db;
  char *salt = "salt";
  char *value = "value";
  char *id = "id";
  char *iv = "iv";

  struct secrets_row in = {.salt = salt, .value = value, .id = id, .iv = iv};
  struct secrets_row *out;

  assert_int_equal(open_sqlite_crypt_db(":memory:", &db), 0);
  assert_int_equal(save_sqlite_secrets_entry(db, &in), 0);
  out = get_sqlite_secrets_row(db, "id");
  assert_non_null(out);
  assert_string_equal(out->salt, "salt");
  assert_string_equal(out->id, "id");
  assert_string_equal(out->value, "value");
  assert_string_equal(out->iv, "iv");

  free_sqlite_secrets_row(out);
  out = NULL;
  out = get_sqlite_secrets_row(db, "id1");
  assert_non_null(out);
  assert_null(out->id);
  free_sqlite_secrets_row(out);

  in.id = "id2";
  in.value = NULL;

  assert_int_equal(save_sqlite_secrets_entry(db, &in), 0);
  out = get_sqlite_secrets_row(db, "id2");
  assert_non_null(out);
  assert_null(out->value);
  free_sqlite_secrets_row(out);
  free_sqlite_crypt_db(db);
}

int main(int argc, char *argv[])
{  
  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_open_sqlite_crypt_db),
    cmocka_unit_test(test_save_sqlite_store_entry),
    cmocka_unit_test(test_get_sqlite_store_row),
    cmocka_unit_test(test_save_sqlite_secrets_entry),
    cmocka_unit_test(test_get_sqlite_secrets_row)
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}