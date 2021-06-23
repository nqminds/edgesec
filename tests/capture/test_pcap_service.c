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

static void test_capture_pcap_start(void **state)
{
  (void) state; /* unused */
}

static void test_capture_pcap_stop(void **state)
{
  (void) state; /* unused */
}

static void test_get_pcap_datalink(void **state)
{
  (void) state; /* unused */
}

static void test_run_pcap(void **state)
{
  (void) state; /* unused */
}

static void test_capture_pcap_packet(void **state)
{
  (void) state; /* unused */
}

static void test_dump_file_pcap(void **state)
{
  (void) state; /* unused */
}

static void test_close_pcap(void **state)
{
  (void) state; /* unused */
}

int main(int argc, char *argv[])
{  
  log_set_quiet(true);

  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_capture_pcap_start),
    cmocka_unit_test(test_capture_pcap_stop),
    cmocka_unit_test(test_get_pcap_datalink),
    cmocka_unit_test(test_run_pcap),
    cmocka_unit_test(test_capture_pcap_packet),
    cmocka_unit_test(test_dump_file_pcap),
    cmocka_unit_test(test_close_pcap),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
