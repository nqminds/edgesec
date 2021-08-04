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
#include "capture/sqlite_header_writer.h"

int __wrap_sqlite3_open(const char *filename, sqlite3 **ppDb)
{
  return __real_sqlite3_open(filename, ppDb);
}

static void test_open_sqlite_header_db(void **state)
{
  (void) state; /* unused */
  sqlite3* db;

  assert_int_equal(open_sqlite_header_db(":memory:", NULL, NULL, &db), 0);
  
  free_sqlite_header_db(db);
}

static void test_save_packet_statement(void **state)
{
  (void) state; /* unused */

  sqlite3* db;
  uint8_t packet[100];
  struct tuple_packet tp;
  tp.mp.type = PACKET_ETHERNET;
  tp.packet = packet;
 
  assert_int_equal(open_sqlite_header_db(":memory:", NULL, NULL, &db), 0);
  assert_int_equal(save_packet_statement(db, &tp), 0);

  tp.mp.type = PACKET_ARP;
  assert_int_equal(save_packet_statement(db, &tp), 0);

  tp.mp.type = PACKET_IP4;
  assert_int_equal(save_packet_statement(db, &tp), 0);

  tp.mp.type = PACKET_IP6;
  assert_int_equal(save_packet_statement(db, &tp), 0);

  tp.mp.type = PACKET_TCP;
  assert_int_equal(save_packet_statement(db, &tp), 0);

  tp.mp.type = PACKET_UDP;
  assert_int_equal(save_packet_statement(db, &tp), 0);

  tp.mp.type = PACKET_ICMP4;
  assert_int_equal(save_packet_statement(db, &tp), 0);

  tp.mp.type = PACKET_ICMP6;
  assert_int_equal(save_packet_statement(db, &tp), 0);

  tp.mp.type = PACKET_DNS;
  assert_int_equal(save_packet_statement(db, &tp), 0);

  tp.mp.type = PACKET_MDNS;
  assert_int_equal(save_packet_statement(db, &tp), 0);

  tp.mp.type = PACKET_DHCP;
  assert_int_equal(save_packet_statement(db, &tp), 0);

  free_sqlite_header_db(db);
}

int main(int argc, char *argv[])
{  
  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_open_sqlite_header_db),
    cmocka_unit_test(test_save_packet_statement)
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}