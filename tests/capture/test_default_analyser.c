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

#include "utils/utarray.h"
#include "utils/log.h"
#include "utils/eloop.h"
#include "capture/default_analyser.h"
#include "capture/sqlite_header_writer.h"
#include "capture/sqlite_pcap_writer.h"
#include "capture/pcap_service.h"
#include "capture/pcap_queue.h"
#include "capture/packet_queue.h"

static const UT_icd tp_list_icd = {sizeof(struct tuple_packet), NULL, NULL, NULL};

int __wrap_open_sqlite_header_db(char *db_path, trace_callback_fn fn, void *trace_ctx, sqlite3 **sql)
{
  return 0;
}

int __wrap_open_sqlite_pcap_db(char *db_path, sqlite3** sql)
{
  return 0;
}

void __wrap_free_sqlite_header_db(sqlite3 *db)
{

}

void __wrap_free_sqlite_pcap_db(sqlite3 *db)
{

}

int __wrap_run_pcap(char *interface, bool immediate, bool promiscuous,
             int timeout, char *filter, bool nonblock, capture_callback_fn pcap_fn,
             void *fn_ctx, struct pcap_context** pctx)
{
  assert_string_equal(interface, "wlan0");
  assert_true(immediate);
  assert_true(promiscuous);
  assert_int_equal(timeout, 100);
  assert_string_equal(filter, "port 80");
  assert_true(nonblock);
  *pctx = os_zalloc(sizeof(struct pcap_context));
  return 0;
}

void __wrap_close_pcap(struct pcap_context *ctx)
{
  if (ctx != NULL)
    os_free(ctx);
}

int __wrap_eloop_init(void)
{
  return 0;
}

int __wrap_eloop_register_read_sock(int sock, eloop_sock_handler handler,
			     void *eloop_data, void *user_data)
{
  return 0;
}

int __wrap_eloop_register_timeout(unsigned long secs, unsigned long usecs,
			   eloop_timeout_handler handler,
			   void *eloop_data, void *user_data)
{
  return 0;
}

void __wrap_eloop_run(void)
{

}

void __wrap_eloop_destroy(void)
{

}

uint32_t __wrap_run_register_db(char *address, char *name)
{
  return 1;
}

int __wrap_extract_packets(const struct pcap_pkthdr *header, const uint8_t *packet,
                    char *interface, char *hostname, char *id, UT_array **tp_array)
{
  struct tuple_packet tp;
  utarray_new(*tp_array, &tp_list_icd);

  tp.packet = NULL;
  tp.type = PACKET_ETHERNET;

  utarray_push_back(*tp_array, &tp);

  return 1;
}

struct packet_queue* __wrap_push_packet_queue(struct packet_queue* queue, struct tuple_packet tp)
{
  assert_int_equal(tp.type, PACKET_ETHERNET);
  return queue;
}

struct pcap_queue* __wrap_push_pcap_queue(struct pcap_queue* queue, struct pcap_pkthdr *header, uint8_t *packet)
{
  assert_int_equal(header->caplen, 100);
  assert_int_equal(header->len, 100);

  return queue;
}

void capture_config(struct capture_conf *config)
{
  os_memset(config, 0, sizeof(struct capture_conf));

  strcpy(config->capture_bin_path, "./");
  strcpy(config->domain_server_path, "./test");
  strcpy(config->domain_command, "SET_FINGERPRINT");
  config->domain_delim = 0x20;
  strcpy(config->capture_interface, "wlan0");
  config->promiscuous = true;
  config->immediate = true;
  config->buffer_timeout = 100;
  config->process_interval = 1000;
  strcpy(config->analyser, "ndpi");
  config->file_write = true;
  config->db_write = true;
  config->db_sync = true;
  strcpy(config->db_path, "./db");
  strcpy(config->db_sync_address, "localhost");
  os_memset(config->ca_path, 0, MAX_OS_PATH_LEN);
  config->db_sync_port = 12345;
  strcpy(config->filter, "port 80");
}

static void test_start_default_analyser(void **state)
{
  (void) state; /* unused */

  struct capture_conf config;
  capture_config(&config);

  int ret = start_default_analyser(&config);
  assert_int_equal(ret, 0);
}

static void test_pcap_callback(void **state)
{
  (void) state; /* unused */

  struct capture_context context;
  struct pcap_pkthdr header;
  header.caplen = 100;
  header.len = 100;

  context.db_write = true;
  context.file_write = true;
  context.pqueue = init_packet_queue();
  context.cqueue = init_pcap_queue();

  pcap_callback((const void *)&context, &header, NULL);

  free_packet_queue(context.pqueue);
  free_pcap_queue(context.cqueue);
}

int main(int argc, char *argv[])
{  
  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_start_default_analyser),
    cmocka_unit_test(test_pcap_callback)
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
