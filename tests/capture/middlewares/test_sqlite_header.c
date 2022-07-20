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
#include <pthread.h>

#include "utils/log.h"
#include "utils/sqliteu.h"
#include "capture/middlewares/header_middleware/header_middleware.h"
#include "capture/middlewares/header_middleware/sqlite_header.h"

char *test_header_db = "/tmp/test_header.sqlite";

void *test_sqlite_header_thread(void *arg) {
  (void)arg;

  sqlite3 *db;

  assert_int_equal(sqlite3_open(test_header_db, &db), SQLITE_OK);
  assert_int_equal(init_sqlite_header_db(db), 0);
  sqlite3_close(db);
  return NULL;
}

static void test_init_sqlite_header_db(void **state) {
  (void)state;

  pthread_t id1, id2, id3;

  remove(test_header_db);

  assert_int_equal(pthread_create(&id1, NULL, test_sqlite_header_thread, NULL),
                   0);
  assert_int_equal(pthread_create(&id2, NULL, test_sqlite_header_thread, NULL),
                   0);
  assert_int_equal(pthread_create(&id3, NULL, test_sqlite_header_thread, NULL),
                   0);

  assert_int_equal(pthread_join(id1, NULL), 0);
  assert_int_equal(pthread_join(id2, NULL), 0);
  assert_int_equal(pthread_join(id3, NULL), 0);
}

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_init_sqlite_header_db)};

  return cmocka_run_group_tests(tests, NULL, NULL);
}
