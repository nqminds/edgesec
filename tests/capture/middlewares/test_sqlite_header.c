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
#include <pthread.h>
#include <sqlite3.h>

#include "utils/log.h"
#include "utils/sqliteu.h"
#include "capture/middlewares/header_middleware/header_middleware.h"
#include "capture/middlewares/header_middleware/sqlite_header.h"
#include "capture/capture_service.h"

char *test_capture_db = "file::memory:?cache=shared";

struct sqlite_thread_arg {
  char error_message[512];
};

void *sqlite_header_thread(void *arg) {
  // DO NOT USE CMocka assert_* in this function
  // CMocka and multi-threading do not go well together

  struct sqlite_thread_arg *retval = arg;
  *retval = (struct sqlite_thread_arg){0};

  sqlite3 *db;
  if (sqlite3_open(test_capture_db, &db) != SQLITE_OK) {
    snprintf(retval->error_message, sizeof(retval->error_message) - 1,
             "%s:%d: sqlite3_open: %s", __FILE__, __LINE__, sqlite3_errmsg(db));
    goto exit;
  }
  if (sqlite3_busy_timeout(db, DB_BUSY_TIMEOUT) != SQLITE_OK) {
    snprintf(retval->error_message, sizeof(retval->error_message) - 1,
             "%s:%d: sqlite3_busy_timeout: %s", __FILE__, __LINE__,
             sqlite3_errmsg(db));
    goto exit;
  }
  if (init_sqlite_header_db(db)) {
    snprintf(retval->error_message, sizeof(retval->error_message) - 1,
             "%s:%d: init_sqlite_header_db: %s", __FILE__, __LINE__,
             sqlite3_errmsg(db));
    goto exit;
  }

exit:
  sqlite3_close(db);
  return NULL;
}

static void test_init_sqlite_header_db(void **state) {
  (void)state;

  struct sqlite_thread_arg arg1, arg2, arg3;
  pthread_t id1, id2, id3;

  assert_int_equal(pthread_create(&id1, NULL, sqlite_header_thread, &arg1), 0);
  assert_int_equal(pthread_create(&id2, NULL, sqlite_header_thread, &arg2), 0);
  assert_int_equal(pthread_create(&id3, NULL, sqlite_header_thread, &arg3), 0);

  assert_int_equal(pthread_join(id1, NULL), 0);
  assert_string_equal(arg1.error_message, "");
  assert_int_equal(pthread_join(id2, NULL), 0);
  assert_string_equal(arg2.error_message, "");
  assert_int_equal(pthread_join(id3, NULL), 0);
  assert_string_equal(arg3.error_message, "");
}

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_init_sqlite_header_db)};

  return cmocka_run_group_tests(tests, NULL, NULL);
}
