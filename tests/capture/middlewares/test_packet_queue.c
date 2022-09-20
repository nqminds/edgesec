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

#include "utils/log.h"
#include "capture/middlewares/header_middleware/packet_queue.h"

static void test_push_packet_queue(void **state) {
  (void)state; /* unused */
  struct tuple_packet tp = {0};
  struct packet_queue *queue = init_packet_queue();

  assert_non_null(push_packet_queue(queue, tp));
  assert_int_equal(get_packet_queue_length(queue), 1);

  free_packet_queue(queue);

  queue = NULL;
  assert_null(push_packet_queue(queue, tp));
  assert_int_equal(get_packet_queue_length(queue), 0);
}

static void test_pop_packet_queue(void **state) {
  (void)state; /* unused */

  struct tuple_packet tp1, tp2;
  struct packet_queue *queue = init_packet_queue();

  tp1.type = PACKET_ETHERNET;
  tp1.packet = os_malloc(100);

  tp2.type = PACKET_ARP;
  tp2.packet = os_malloc(100);

  assert_non_null(push_packet_queue(queue, tp1));
  assert_non_null(push_packet_queue(queue, tp2));
  struct packet_queue *pq = pop_packet_queue(queue);
  assert_non_null(pq);
  assert_int_equal(pq->tp.type, PACKET_ETHERNET);
  free_packet_tuple(&pq->tp);
  free_packet_queue_el(pq);
  pq = pop_packet_queue(queue);

  assert_non_null(pq);
  assert_int_equal(pq->tp.type, PACKET_ARP);
  assert_int_equal(get_packet_queue_length(queue), 1);
  free_packet_tuple(&pq->tp);
  free_packet_queue_el(pq);
  free_packet_queue(queue);

  queue = init_packet_queue();
  assert_null(pop_packet_queue(queue));
  free_packet_queue(queue);

  queue = NULL;
  assert_null(pop_packet_queue(queue));
}

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  log_set_quiet(false);

  const struct CMUnitTest tests[] = {cmocka_unit_test(test_push_packet_queue),
                                     cmocka_unit_test(test_pop_packet_queue)};

  return cmocka_run_group_tests(tests, NULL, NULL);
}
