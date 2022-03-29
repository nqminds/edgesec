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
#include <ndpi_api.h>
#include <ndpi_main.h>
#include <ndpi_typedefs.h>
#include <pcap.h>
#include "utils/log.h"
#include "capture/ndpi_analyser.h"
#include "capture/pcap_service.h"

int __wrap_pthread_mutex_init (pthread_mutex_t *__mutex, const pthread_mutexattr_t *__mutexattr)
{
  return 0;
}

int __wrap_run_pcap(char *interface, bool immediate, bool promiscuous,
             int timeout, char *filter, bool nonblock, capture_callback_fn pcap_fn,
             void *fn_ctx, struct pcap_context** pctx)
{
  return 0;
}

int __wrap_pthread_create(pthread_t *__restrict __newthread,
			   const pthread_attr_t *__restrict __attr,
			   void *(*__start_routine) (void *),
			   void *__restrict __arg)
{
  return 0;
}

int __wrap_pthread_join (pthread_t __th, void **__thread_return)
{
  return 0;
}

int __wrap_close_domain(int sfd)
{
    return 0;
}

void __wrap_capture_pcap_stop(struct pcap_context *ctx)
{

}

int __wrap_pthread_mutex_destroy(pthread_mutex_t *__mutex)
{
  return 0;
}

int __wrap_create_domain_client(char *socket_name)
{
  return 0;
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
  config->db_sync_port = 12345;
  strcpy(config->filter, "port 80");
}

static void test_start_ndpi_analyser(void **state)
{
  (void) state; /* unused */

  struct capture_conf config;
  capture_config(&config);

  int ret = start_ndpi_analyser(&config);
  assert_int_equal(ret, 0);
}

int main(int argc, char *argv[])
{  
  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_start_ndpi_analyser)
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
