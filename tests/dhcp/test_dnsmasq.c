#define _GNU_SOURCE

#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <cmocka.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <unistd.h>

#include "dhcp/dhcp_config.h"
#include "dhcp/dnsmasq.h"
#include "utils/log.h"

static const UT_icd config_dhcpinfo_icd = {sizeof(config_dhcpinfo_t), NULL,
                                           NULL, NULL};

static char *wifi_interface = "wifi_if";
static char *interface_prefix = "eth_if";
static char *dns_server = "8.8.4.4,8.8.8.8";

static char *test_dhcp_conf_path = "/tmp/dnsmasq-test.conf";
static char *test_dhcp_script_path = "/tmp/dnsmasq_exec-test.sh";
static char *test_dhcp_leasefile_path = "/tmp/test_dnsmasq.leases";
static char *test_supervisor_control_path = "/tmp/edgesec-control-server";

#ifndef WITH_UCI_SERVICE
static char *test_dhcp_conf_wifi_if =
    "no-resolv\n"
    "server=8.8.4.4\n"
    "server=8.8.8.8\n"
    "dhcp-leasefile=/tmp/test_dnsmasq.leases\n"
    "dhcp-script=/tmp/dnsmasq_exec-test.sh\n"
    "dhcp-range=wifi_if,10.0.0.2,10.0.0.254,255.255.255.0,24h\n"
    "dhcp-range=wifi_if.1,10.0.1.2,10.0.1.254,255.255.255.0,24h\n"
    "dhcp-range=wifi_if.2,10.0.2.2,10.0.2.254,255.255.255.0,24h\n"
    "dhcp-range=wifi_if.3,10.0.3.2,10.0.3.254,255.255.255.0,24h\n";

static char *test_dhcp_conf_prefix_if =
    "no-resolv\n"
    "server=8.8.4.4\n"
    "server=8.8.8.8\n"
    "dhcp-leasefile=/tmp/test_dnsmasq.leases\n"
    "dhcp-script=/tmp/dnsmasq_exec-test.sh\n"
    "dhcp-range=eth_if0,10.0.0.2,10.0.0.254,255.255.255.0,24h\n"
    "dhcp-range=eth_if1,10.0.1.2,10.0.1.254,255.255.255.0,24h\n"
    "dhcp-range=eth_if2,10.0.2.2,10.0.2.254,255.255.255.0,24h\n"
    "dhcp-range=eth_if3,10.0.3.2,10.0.3.254,255.255.255.0,24h\n";
#endif

// why aren't we using amazing C++11 which has the R"(...) string literal??? 😭
static char *test_dhcp_script_content =
    "#!/bin/sh\n"
    "sockpath=\"/tmp/edgesec-control-server\"\n"
    "str=\"SET_IP $1 $2 $3\"\n"
    "\n"
    "nccheck=`nc -help 2>&1 >/dev/null | grep 'OpenBSD netcat'`\n"
    "if [ -z \"$nccheck\" ]\n"
    "then\n"
    "	echo \"Using socat\"\n"
    "	command=\"socat - UNIX-CLIENT:$sockpath\"\n"
    "else\n"
    "	echo \"Using netcat\"\n"
    "	command=\"nc -uU $sockpath -w2 -W1\"\n"
    "fi\n"
    "\n"
    "echo \"Sending $str ...\"\n"
    "echo $str | $command\n";

static char *test_dhcp_leasefile_content =
    "1635860140 11:22:33:44:55:66 10.0.1.10 pc 11:22:33:44:55:66\n"
    "1635860148 44:2a:60:db:f3:91 10.0.1.209 iMac 01:44:2a:60:db:f3:91\n"
    "1635860076 1c:bf:ce:17:1f:1c 10.0.2.178 * 01:1c:bf:ce:17:1f:1c\n";

bool __wrap_signal_process(char *proc_name, int sig) {
  (void)sig;

  check_expected(proc_name);

  return true;
}

int __wrap_is_proc_running(char *name) {
  check_expected(name);

  return 1;
}

bool __wrap_kill_process(char *proc_name) {
  check_expected(proc_name);

  return true;
}

int __wrap_run_process(char *argv[], pid_t *child_pid) {
  (void)argv;
  (void)child_pid;

  return 0;
}

static void test_define_dhcp_interface_name(void **state) {
  (void)state; /* unused */

  {
    const struct dhcp_conf dconf = {
        .bridge_prefix = "hello",
        .interface_prefix = "hello",
    };
    const int vlanid = 512;
    char ifname[IFNAMSIZ] = {0};
    assert_return_code(define_dhcp_interface_name(&dconf, vlanid, ifname), 0);
    assert_string_equal(ifname, "hello512");

    // should return -1 if inputs are NULL
    assert_int_equal(define_dhcp_interface_name(NULL, vlanid, ifname), -1);
    assert_int_equal(define_dhcp_interface_name(&dconf, vlanid, NULL), -1);
  }
  { // should truncate prefix to just 11 chars
    const struct dhcp_conf dconf = {
        .bridge_prefix = "abcdefghijklmno",
        .interface_prefix = "abcdefghijklmno",
    };
    const int vlanid = 512;
    char ifname[IFNAMSIZ] = {0};
    assert_return_code(define_dhcp_interface_name(&dconf, vlanid, ifname), 0);

    assert_string_equal(ifname, "abcdefghijk512");
  }

#ifndef WITH_UCI_SERVICE
  {
    const struct dhcp_conf dconf = {
        .wifi_interface = "hello",
    };
    int vlanid = 512;
    char ifname[IFNAMSIZ] = {0};
    assert_return_code(define_dhcp_interface_name(&dconf, vlanid, ifname), 0);
    assert_string_equal(ifname, "hello.512");

    vlanid = 0;
    assert_return_code(define_dhcp_interface_name(&dconf, vlanid, ifname), 0);
    assert_string_equal(ifname, "hello");
  }
  { // should truncate wifi interface to just 10 chars
    const struct dhcp_conf dconf = {
        .wifi_interface = "abcdefghijklmno",
    };
    int vlanid = 512;
    char ifname[IFNAMSIZ] = {0};
    assert_return_code(define_dhcp_interface_name(&dconf, vlanid, ifname), 0);
    assert_string_equal(ifname, "abcdefghij.512");

    // should return -1 if vlanid is over 4 digits in decimal
    assert_int_equal(define_dhcp_interface_name(&dconf, 12345, ifname), -1);
  }
#endif
}

bool get_config_dhcpinfo(char *info, config_dhcpinfo_t *el) {
  UT_array *info_arr;
  utarray_new(info_arr, &ut_str_icd);

  ssize_t count = split_string_array(info, ',', info_arr);

  log_trace("Number of substrings=%zd", count);

  if (!utarray_len(info_arr))
    goto err;

  char **p = NULL;
  p = (char **)utarray_next(info_arr, p);
  log_trace("vlanid=%s", *p);
  if (*p != NULL) {
    errno = 0;
    el->vlanid = (int)strtol(*p, NULL, 10);
    if (errno == EINVAL)
      goto err;
  } else
    goto err;

  p = (char **)utarray_next(info_arr, p);
  log_trace("ip_addr_low=%s", *p);
  if (*p != NULL) {
    strcpy(el->ip_addr_low, *p);
  } else
    goto err;

  p = (char **)utarray_next(info_arr, p);
  log_trace("ip_addr_upp=%s", *p);
  if (*p != NULL)
    strcpy(el->ip_addr_upp, *p);
  else
    goto err;

  p = (char **)utarray_next(info_arr, p);
  log_trace("subnet_mask=%s", *p);
  if (*p != NULL)
    strcpy(el->subnet_mask, *p);
  else
    goto err;

  p = (char **)utarray_next(info_arr, p);
  log_trace("lease_time=%s", *p);
  if (*p != NULL)
    strcpy(el->lease_time, *p);
  else
    goto err;

  utarray_free(info_arr);
  return true;

err:
  utarray_free(info_arr);
  return false;
}

static void test_generate_dnsmasq_conf(void **state) {
  (void)state;
  struct dhcp_conf dconf = {
      // must manually set bridge_prefix, otherwise we'll be working with
      // undefined memory
      .bridge_prefix = "",
  };
  utarray_new(dconf.config_dhcpinfo_array, &config_dhcpinfo_icd);

  UT_array *server_arr;
  utarray_new(server_arr, &ut_str_icd);

  strcpy(dconf.dhcp_conf_path, test_dhcp_conf_path);
  strcpy(dconf.dhcp_script_path, test_dhcp_script_path);
  strcpy(dconf.dhcp_leasefile_path, test_dhcp_leasefile_path);
  const size_t WIFI_INTERFACE_STR_LEN = ARRAY_SIZE(dconf.wifi_interface);

  strncpy(dconf.wifi_interface, wifi_interface, WIFI_INTERFACE_STR_LEN);
  assert_int_equal(dconf.wifi_interface[WIFI_INTERFACE_STR_LEN - 1], '\0');

  config_dhcpinfo_t el;
  assert_true(
      get_config_dhcpinfo("0,10.0.0.2,10.0.0.254,255.255.255.0,24h", &el));
  utarray_push_back(dconf.config_dhcpinfo_array, &el);
  assert_true(
      get_config_dhcpinfo("1,10.0.1.2,10.0.1.254,255.255.255.0,24h", &el));
  utarray_push_back(dconf.config_dhcpinfo_array, &el);
  assert_true(
      get_config_dhcpinfo("2,10.0.2.2,10.0.2.254,255.255.255.0,24h", &el));
  utarray_push_back(dconf.config_dhcpinfo_array, &el);
  assert_true(
      get_config_dhcpinfo("3,10.0.3.2,10.0.3.254,255.255.255.0,24h", &el));
  utarray_push_back(dconf.config_dhcpinfo_array, &el);

  split_string_array(dns_server, ',', server_arr);

  int ret = generate_dnsmasq_conf(&dconf, server_arr);
  assert_true(ret == 0);

#ifdef WITH_UCI_SERVICE
  // todo: add some tests for dnsmasq UCI conf
#else
  {
    char *fdata = NULL;
    assert_int_equal(read_file_string(test_dhcp_conf_path, &fdata), 0);

    assert_string_equal(fdata, test_dhcp_conf_wifi_if);

    os_free(fdata);
  }
#endif

  const size_t INTERFACE_PREFIX_STR_LEN = ARRAY_SIZE(dconf.interface_prefix);

  os_memset(dconf.wifi_interface, 0, WIFI_INTERFACE_STR_LEN);
  strncpy(dconf.interface_prefix, interface_prefix, INTERFACE_PREFIX_STR_LEN);

  ret = generate_dnsmasq_conf(&dconf, server_arr);
  assert_true(ret == 0);

#ifdef WITH_UCI_SERVICE
  // todo: add some tests for dnsmasq UCI conf
#else
  {
    char *fdata = NULL;
    assert_int_equal(read_file_string(test_dhcp_conf_path, &fdata), 0);

    assert_string_equal(fdata, test_dhcp_conf_prefix_if);

    os_free(fdata);
  }
#endif

  utarray_free(server_arr);
  utarray_free(dconf.config_dhcpinfo_array);
}

static void test_generate_dnsmasq_script(void **state) {
  (void)state;

  int ret = generate_dnsmasq_script(test_dhcp_script_path,
                                    test_supervisor_control_path);
  assert_true(ret == 0);

  FILE *fp = fopen(test_dhcp_script_path, "r");
  assert_non_null(fp);

  long lSize;
  char *buffer;

  fseek(fp, 0, SEEK_END);
  lSize = ftell(fp);
  rewind(fp);
  buffer = (char *)malloc(sizeof(char) * lSize);
  assert_non_null(buffer);

  size_t result = fread(buffer, 1, lSize, fp);
  assert_int_equal(result, strlen(test_dhcp_script_content));
  int cmp = memcmp(buffer, test_dhcp_script_content, result);
  assert_int_equal(cmp, 0);

  fclose(fp);
  free(buffer);
}

static void test_clear_dhcp_lease_entry(void **state) {
  (void)state;
  char *out = NULL;
  FILE *fp = fopen(test_dhcp_leasefile_path, "w");

  assert_non_null(fp);
  fprintf(fp, "%s", test_dhcp_leasefile_content);
  fclose(fp);

  assert_int_equal(clear_dhcp_lease_entry("", test_dhcp_leasefile_path), 0);

  assert_int_equal(
      clear_dhcp_lease_entry("11:22:33:44:55:66", test_dhcp_leasefile_path), 0);
  assert_int_equal(read_file_string(test_dhcp_leasefile_path, &out), 0);
  assert_null(strstr(out, "11:22:33:44:55:66"));
  assert_non_null(strstr(out, "44:2a:60:db:f3:91"));
  os_free(out);

  assert_int_equal(
      clear_dhcp_lease_entry("11:22:33:44:55:66", test_dhcp_leasefile_path), 0);
  assert_int_equal(read_file_string(test_dhcp_leasefile_path, &out), 0);
  assert_null(strstr(out, "11:22:33:44:55:66"));
  assert_non_null(strstr(out, "44:2a:60:db:f3:91"));
  os_free(out);

  assert_int_equal(
      clear_dhcp_lease_entry("44:2a:60:db:f3:91", test_dhcp_leasefile_path), 0);
  assert_int_equal(read_file_string(test_dhcp_leasefile_path, &out), 0);
  assert_null(strstr(out, "44:2a:60:db:f3:91"));
  assert_non_null(strstr(out, "1c:bf:ce:17:1f:1c"));
  os_free(out);

  assert_int_equal(
      clear_dhcp_lease_entry("1c:bf:ce:17:1f:1c", test_dhcp_leasefile_path), 0);
  assert_int_equal(read_file_string(test_dhcp_leasefile_path, &out), 0);
  assert_null(strstr(out, "1c:bf:ce:17:1f:1c"));
  os_free(out);
}

static void test_run_dhcp_process(void **state) {
  (void)state;

#ifdef WITH_UCI_SERVICE
  // todo: add some tests for dnsmasq UCI conf
#else
  expect_string(__wrap_kill_process, proc_name, "dnsmasq");
#endif
  expect_string(__wrap_is_proc_running, name, "dnsmasq");
  char *ret = run_dhcp_process("/tmp/sbin/dnsmasq", "/tmp/dnsmasq.conf");
  assert_non_null(ret);
  assert_string_equal(ret, "dnsmasq");
  expect_string(__wrap_kill_process, proc_name, "dnsmasq");
  assert_true(kill_dhcp_process());
}

static void test_kill_dhcp_process(void **state) {
  (void)state;

  assert_true(kill_dhcp_process());
}

static void test_signal_dhcp_process(void **state) {
  (void)state;
#ifdef WITH_UCI_SERVICE
  // signal_dhcp_process does nothing in UCI mode
#else
  expect_string(__wrap_signal_process, proc_name, "dnsmasq");
#endif
  assert_int_equal(signal_dhcp_process("/tmp/sbin/dnsmasq"), 0);
}

int main(int argc, char *argv[]) {
  (void)argc; /* unused */
  (void)argv; /* unused */
  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_define_dhcp_interface_name),
      cmocka_unit_test(test_generate_dnsmasq_conf),
      cmocka_unit_test(test_generate_dnsmasq_script),
      cmocka_unit_test(test_run_dhcp_process),
      cmocka_unit_test(test_kill_dhcp_process),
      cmocka_unit_test(test_signal_dhcp_process),
      cmocka_unit_test(test_clear_dhcp_lease_entry)};

  return cmocka_run_group_tests(tests, NULL, NULL);
}
