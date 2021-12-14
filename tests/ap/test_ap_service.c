
#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <setjmp.h>
#include <cmocka.h>

#include "supervisor/supervisor_config.h"
#include "utils/log.h"
#include "utils/allocs.h"
#include "utils/os.h"
#include "utils/if.h"
#include "utils/eloop.h"
#include "ap/ap_service.h"
#include "ap/ap_config.h"
#include "ap/hostapd.h"

bool __wrap_generate_vlan_conf(char *vlan_file, char *interface)
{
  (void) vlan_file;
  (void) interface;

  return true;
}

int __wrap_run_ap_process(struct apconf *hconf)
{
  (void) hconf;

  return 0;
}

bool __wrap_generate_hostapd_conf(struct apconf *hconf, struct radius_conf *rconf)
{
  (void) hconf;
  (void) rconf;

  return true;
}

int __wrap_signal_ap_process(struct apconf *hconf)
{
  (void) hconf;

  return 0;
}

int __wrap_create_domain_client(char *addr)
{
  (void) addr;

  return 0;
}

int __wrap_eloop_register_read_sock(int sock, eloop_sock_handler handler,
			     void *eloop_data, void *user_data)
{
  (void) sock;
  (void) handler;
  (void) eloop_data;
  (void) user_data;

  return 0;
}

ssize_t __wrap_write_domain_data_s(int sock, char *data, size_t data_len, char *addr)
{
  (void) sock;
  (void) data;
  (void) addr;

  return data_len;
}

static void test_run_ap(void **state)
{
  (void) state; /* unused */
  
  struct supervisor_context context;

  assert_int_equal(run_ap(&context, true, false, NULL), 0);
}

int main(int argc, char *argv[])
{  
  (void) argc;
  (void) argv;

  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_run_ap),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
