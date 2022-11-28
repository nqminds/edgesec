#define _GNU_SOURCE

#include <setjmp.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <cmocka.h>
#include <fcntl.h>
#include <inttypes.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "capture/middlewares/pcap_middleware/pcap_queue.h"
#include "utils/allocs.h"
#include "utils/log.h"
#include "utils/os.h"

static void test_push_pcap_queue(void **state) {
  (void)state; /* unused */
  struct pcap_pkthdr header;
  uint8_t packet[100];

  struct pcap_queue *queue = init_pcap_queue();

  os_memset(&header, 0, sizeof(struct pcap_pkthdr));
  assert_non_null(push_pcap_queue(queue, &header, packet));
  assert_int_equal(get_pcap_queue_length(queue), 1);

  assert_null(push_pcap_queue(queue, NULL, packet));
  assert_null(push_pcap_queue(queue, &header, NULL));
  assert_null(push_pcap_queue(queue, NULL, NULL));
  free_pcap_queue(queue);

  queue = NULL;
  assert_null(push_pcap_queue(queue, &header, packet));
  assert_int_equal(get_pcap_queue_length(queue), 0);
}

static void test_pop_pcap_queue(void **state) {
  (void)state; /* unused */

  struct pcap_pkthdr header1, header2;
  uint8_t packet1[100], packet2[100];

  struct pcap_queue *queue = init_pcap_queue();

  header1.caplen = 10;
  header2.caplen = 100;

  assert_non_null(push_pcap_queue(queue, &header1, packet1));
  assert_non_null(push_pcap_queue(queue, &header2, packet2));
  struct pcap_queue *pq = pop_pcap_queue(queue);
  assert_non_null(pq);
  assert_int_equal(pq->header.caplen, 10);

  free_pcap_queue_el(pq);
  pq = pop_pcap_queue(queue);
  assert_non_null(pq);
  assert_int_equal(pq->header.caplen, 100);
  assert_int_equal(get_pcap_queue_length(queue), 1);
  free_pcap_queue(queue);

  queue = init_pcap_queue();
  assert_null(pop_pcap_queue(queue));
  free_pcap_queue(queue);

  queue = NULL;
  assert_null(pop_pcap_queue(queue));
}

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  log_set_quiet(false);

  const struct CMUnitTest tests[] = {cmocka_unit_test(test_push_pcap_queue),
                                     cmocka_unit_test(test_pop_pcap_queue)};

  return cmocka_run_group_tests(tests, NULL, NULL);
}
