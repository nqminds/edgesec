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
#include "capture/middlewares/pcap_middleware/sqlite_pcap.h"
#include "capture/capture_service.h"

char *test_capture_db = "/tmp/test_pcap.sqlite";

void *test_sqlite_pcap_thread(void *arg) {
  (void)arg;

  sqlite3 *db;

  assert_int_equal(sqlite3_open(test_capture_db, &db), SQLITE_OK);
  assert_int_equal(sqlite3_busy_timeout(db, DB_BUSY_TIMEOUT), 0);
  assert_int_equal(init_sqlite_pcap_db(db), 0);
  sqlite3_close(db);
  return NULL;
}

static void test_init_sqlite_pcap_db(void **state) {
  (void)state; /* unused */

  pthread_t id1, id2, id3;

  remove(test_capture_db);

  assert_int_equal(pthread_create(&id1, NULL, test_sqlite_pcap_thread, NULL),
                   0);
  assert_int_equal(pthread_create(&id2, NULL, test_sqlite_pcap_thread, NULL),
                   0);
  assert_int_equal(pthread_create(&id3, NULL, test_sqlite_pcap_thread, NULL),
                   0);

  assert_int_equal(pthread_join(id1, NULL), 0);
  assert_int_equal(pthread_join(id2, NULL), 0);
  assert_int_equal(pthread_join(id3, NULL), 0);
}

static void test_save_sqlite_pcap_entry(void **state) {
  (void)state; /* unused */

  sqlite3 *db;

  int ret = sqlite3_open(":memory:", &db);
  assert_int_equal(ret, SQLITE_OK);

  assert_int_equal(init_sqlite_pcap_db(db), 0);
  assert_int_equal(save_sqlite_pcap_entry(db, "test", 12345, 10, 10), 0);
  sqlite3_close(db);
}
int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_init_sqlite_pcap_db),
      cmocka_unit_test(test_save_sqlite_pcap_entry)};

  return cmocka_run_group_tests(tests, NULL, NULL);
}
