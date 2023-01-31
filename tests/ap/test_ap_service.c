
#define _GNU_SOURCE

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
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

#include <eloop.h>
#include "ap/ap_config.h"
#include "ap/ap_service.h"
#include "ap/hostapd.h"
#include "supervisor/supervisor_config.h"
#include "utils/allocs.h"
#include "utils/iface.h"
#include "utils/log.h"
#include "utils/os.h"

int __wrap_generate_vlan_conf(char *vlan_file, char *interface) {
  (void)vlan_file;
  (void)interface;

  return 0;
}

int __wrap_run_ap_process(struct apconf *hconf) {
  (void)hconf;

  return 0;
}

int __wrap_generate_hostapd_conf(struct apconf *hconf,
                                 struct radius_conf *rconf) {
  (void)hconf;
  (void)rconf;

  return 0;
}

int __wrap_signal_ap_process(struct apconf *hconf) {
  (void)hconf;

  return 0;
}

int __wrap_create_domain_client(char *addr) {
  (void)addr;

  return 0;
}

int __wrap_edge_eloop_register_read_sock(int sock, eloop_sock_handler handler,
                                         void *eloop_data, void *user_data) {
  (void)sock;
  (void)handler;
  (void)eloop_data;
  (void)user_data;

  return 0;
}

ssize_t __wrap_write_domain_data_s(int sock, char *data, size_t data_len,
                                   char *addr) {
  (void)sock;
  (void)data;
  (void)addr;

  return data_len;
}

int __wrap_writeread_domain_data_str(char *socket_path, char *write_str,
                                     char **reply) {
  (void)socket_path;
  (void)reply;

  *reply = NULL;

  if (write_str != NULL) {
    if (strcmp(write_str, PING_AP_COMMAND) == 0) {
      *reply = os_strdup(PING_AP_COMMAND_REPLY);
      return 0;
    }

    if (strstr(write_str, DENYACL_ADD_COMMAND) != NULL) {
      *reply = os_strdup(GENERIC_AP_COMMAND_OK_REPLY);
      return 0;
    }

    if (strstr(write_str, DENYACL_DEL_COMMAND) != NULL) {
      *reply = os_strdup(GENERIC_AP_COMMAND_OK_REPLY);
      return 0;
    }

    if (strstr(write_str, STA_AP_COMMAND) != NULL) {
      *reply = os_strdup("1");
      return 0;
    }
  }

  return 0;
}

int __wrap_close(int __fd) {
  (void)__fd;

  return 0;
}

static void test_run_ap(void **state) {
  (void)state; /* unused */

  struct supervisor_context context;

  assert_int_equal(run_ap(&context, true, false, NULL), 0);
}

static void test_close_ap(void **state) {
  (void)state;

  struct supervisor_context context;

  assert_int_equal(run_ap(&context, true, false, NULL), 0);
  assert_true(close_ap(&context));
}

static void test_denyacl_add_ap_command(void **state) {
  (void)state;

  struct apconf hconf;

  assert_int_equal(denyacl_add_ap_command(&hconf, "11:22:33:44:55:66"), 0);
}

static void test_denyacl_del_ap_command(void **state) {
  (void)state;

  struct apconf hconf;

  assert_int_equal(denyacl_del_ap_command(&hconf, "11:22:33:44:55:66"), 0);
}

static void test_disconnect_ap_command(void **state) {
  (void)state;

  struct apconf hconf;

  assert_int_equal(disconnect_ap_command(&hconf, "11:22:33:44:55:66"), 0);
}

static void test_check_sta_ap_command(void **state) {
  (void)state;

  struct apconf hconf;

  assert_int_equal(check_sta_ap_command(&hconf, "11:22:33:44:55:66"), 0);
}

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_run_ap),
      cmocka_unit_test(test_close_ap),
      cmocka_unit_test(test_denyacl_add_ap_command),
      cmocka_unit_test(test_denyacl_del_ap_command),
      cmocka_unit_test(test_disconnect_ap_command),
      cmocka_unit_test(test_check_sta_ap_command)};

  return cmocka_run_group_tests(tests, NULL, NULL);
}
