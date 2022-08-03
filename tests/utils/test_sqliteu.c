#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "utils/sqliteu.h"

static void test_execute_sqlite_query(void **state) {
  (void)state; /* unused */

  sqlite3 *db = NULL;
  assert_int_equal(sqlite3_open(":memory:", &db), SQLITE_OK);

  // check whether invalid statemens fail
  assert_int_equal(execute_sqlite_query(db, "sqlite3 syntax error"), -1);

  // check whether a table is added due to the command being ran
  assert_int_equal(check_table_exists(db, "example"), 0);
  assert_int_equal(execute_sqlite_query(db, "CREATE TABLE example(column);"),
                   0);
  assert_int_equal(check_table_exists(db, "example"), 1);

  sqlite3_close(db);
}

static void test_check_table_exists(void **state) {
  (void)state; /* unused */

  sqlite3 *db = NULL;

  // should throw an error since db is null
  assert_int_equal(check_table_exists(db, "invalid-db"), -1);

  assert_int_equal(sqlite3_open("file::memory:?cache=shared", &db), SQLITE_OK);
  assert_int_equal(check_table_exists(db, "no-table"), 0);

  execute_sqlite_query(db, "CREATE TABLE example(column);");
  assert_int_equal(check_table_exists(db, "example"), 1);

  // should throw an error, since can't check_table_exists on locked database
  {
    sqlite3 *db_connection_2 = NULL;
    assert_int_equal(
        sqlite3_open("file::memory:?cache=shared", &db_connection_2),
        SQLITE_OK);

    assert_int_equal(
        execute_sqlite_query(db_connection_2, "BEGIN EXCLUSIVE TRANSACTION;"),
        0);
    assert_int_equal(check_table_exists(db, "example"), -1);
    assert_int_equal(
        execute_sqlite_query(db_connection_2, "COMMIT TRANSACTION;"), 0);

    sqlite3_close(db_connection_2);
  }

  // should throw an error since table name is too long
  {
    // limit table name to certain length

    int original_limit = sqlite3_limit(db, SQLITE_LIMIT_LENGTH, 1024);
    char super_long_table_name[2048];
    memset(super_long_table_name, 'a', 2048);
    super_long_table_name[2047] = '\n';
    assert_int_equal(check_table_exists(db, super_long_table_name), -1);
    sqlite3_limit(db, SQLITE_LIMIT_LENGTH, original_limit);
  }

  sqlite3_close(db);
}

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_check_table_exists),
      cmocka_unit_test(test_execute_sqlite_query),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
