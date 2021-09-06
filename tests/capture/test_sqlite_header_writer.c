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
  struct sqlite_header_context *ctx;

  assert_int_equal(open_sqlite_header_db(":memory:", NULL, NULL, &ctx), 0);
  free_sqlite_header_db(ctx);
}

static void test_save_packet_statement(void **state)
{
  (void) state; /* unused */

  struct sqlite_header_context *ctx;
  uint8_t packet[1000];
  struct tuple_packet tp;
  os_memset(packet, 0, 1000);
  tp.type = PACKET_ETHERNET;
  tp.packet = packet;
 
  assert_int_equal(open_sqlite_header_db(":memory:", NULL, NULL, &ctx), 0);
  assert_int_equal(save_packet_statement(ctx, &tp), 0);

  tp.type = PACKET_ARP;
  assert_int_equal(save_packet_statement(ctx, &tp), 0);

  tp.type = PACKET_IP4;
  assert_int_equal(save_packet_statement(ctx, &tp), 0);

  tp.type = PACKET_IP6;
  assert_int_equal(save_packet_statement(ctx, &tp), 0);

  tp.type = PACKET_TCP;
  assert_int_equal(save_packet_statement(ctx, &tp), 0);

  tp.type = PACKET_UDP;
  assert_int_equal(save_packet_statement(ctx, &tp), 0);

  tp.type = PACKET_ICMP4;
  assert_int_equal(save_packet_statement(ctx, &tp), 0);

  tp.type = PACKET_ICMP6;
  assert_int_equal(save_packet_statement(ctx, &tp), 0);

  tp.type = PACKET_DNS;
  assert_int_equal(save_packet_statement(ctx, &tp), 0);

  tp.type = PACKET_MDNS;
  assert_int_equal(save_packet_statement(ctx, &tp), 0);

  tp.type = PACKET_DHCP;
  assert_int_equal(save_packet_statement(ctx, &tp), 0);

  free_sqlite_header_db(ctx);
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