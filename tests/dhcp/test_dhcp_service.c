#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <fcntl.h>
#include <ctype.h>
#include <unistd.h>
#include <pthread.h>
#include <stdbool.h>
#include <errno.h>
#include <net/if.h>
#include <libgen.h>
#include <setjmp.h>
#include <cmocka.h>

#include "utils/log.h"
#include "dhcp/dnsmasq.h"
#include "dhcp/dhcp_config.h"
#include "dhcp/dhcp_service.h"

char *dhcp_bin_path = "/tmp/sbin/dnsmasq";
char *dnsmasq_proc_name = "dnsmasq";

bool __wrap_generate_dnsmasq_conf(struct dhcp_conf *dconf,
                                  UT_array *dns_server_array) {
  (void)dconf;
  (void)dns_server_array;

  return true;
}

bool __wrap_generate_dnsmasq_script(char *dhcp_script_path,
                                    char *domain_server_path) {
  (void)dhcp_script_path;
  (void)domain_server_path;

  return true;
}

char *__wrap_run_dhcp_process(char *dhcp_bin_path, char *dhcp_conf_path) {
  (void)dhcp_bin_path;
  (void)dhcp_conf_path;

  return mock_type(char *);
}

bool __wrap_kill_dhcp_process(void) { return true; }

int __wrap_clear_dhcp_lease_entry(char *mac_addr, char *dhcp_leasefile_path) {
  (void)mac_addr;
  (void)dhcp_leasefile_path;

  return 0;
}

static void test_run_dhcp(void **state) {
  (void)state;

  struct dhcp_conf dconf = {.dhcp_bin_path = "/tmp/sbin/dnsmasq",
                            .wifi_interface = "wlan0"};
  UT_array *dns_server_array = NULL;

  will_return(__wrap_run_dhcp_process, dnsmasq_proc_name);
  assert_int_equal(run_dhcp(&dconf, dns_server_array, "/tmp/domain", true), 0);
}

static void test_close_dhcp(void **state) {
  (void)state;

  struct dhcp_conf dconf = {.dhcp_bin_path = "/tmp/sbin/dnsmasq",
                            .wifi_interface = "wlan0"};
  UT_array *dns_server_array = NULL;

  will_return(__wrap_run_dhcp_process, dnsmasq_proc_name);
  run_dhcp(&dconf, dns_server_array, "/tmp/domain", true);
  assert_true(close_dhcp());
}

static void test_clear_dhcp_lease(void **state) {
  (void)state;

  struct dhcp_conf dconf;

  assert_int_equal(clear_dhcp_lease("11:22:33:44:55:66", &dconf), 0);
}

int main(int argc, char *argv[]) {
  (void)argc; /* unused */
  (void)argv; /* unused */
  log_set_quiet(false);

  const struct CMUnitTest tests[] = {cmocka_unit_test(test_run_dhcp),
                                     cmocka_unit_test(test_close_dhcp),
                                     cmocka_unit_test(test_clear_dhcp_lease)};

  return cmocka_run_group_tests(tests, NULL, NULL);
}
