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

static const UT_icd config_dhcpinfo_icd = {sizeof(config_dhcpinfo_t), NULL, NULL, NULL};

static char *test_dhcp_conf_path = "/tmp/dnsmasq-test.conf";
static char *test_dhcp_script_path = "/tmp/dnsmasq_exec-test.sh";
static char *test_domain_server_path = "/tmp/edgesec-domain-server";
static char *test_dhcp_conf_content =
"no-resolv\n"
"server=8.8.4.4\n"
"server=8.8.8.8\n"
"dhcp-script=/tmp/dnsmasq_exec-test.sh\n"
"dhcp-range=wifi_if,10.0.0.2,10.0.0.254,255.255.255.0,24h\n"
"dhcp-range=wifi_if.1,10.0.1.2,10.0.1.254,255.255.255.0,24h\n"
"dhcp-range=wifi_if.2,10.0.2.2,10.0.2.254,255.255.255.0,24h\n"
"dhcp-range=wifi_if.3,10.0.3.2,10.0.3.254,255.255.255.0,24h\n";

static char *test_dhcp_script_content =
"#!/bin/sh\n"
"str=\"SET_IP $1 $2 $3\"\n"
"echo \"Sending $str ...\"\n"
"echo $str | nc -uU /tmp/edgesec-domain-server -w2 -W1\n";

static char *interface="wifi_if";
static char *dns_server="8.8.4.4,8.8.8.8";

bool get_config_dhcpinfo(char *info, config_dhcpinfo_t *el)
{
  UT_array *info_arr;
  utarray_new(info_arr, &ut_str_icd);

  split_string_array(info, ',', info_arr);

  if (!utarray_len(info_arr))
    goto err;

  char **p = NULL;
  p = (char**) utarray_next(info_arr, p);
  if (*p != NULL) {
    el->vlanid = (int) strtol(*p, NULL, 10);
    if (errno == EINVAL)
      goto err;
  } else
    goto err;

  p = (char**) utarray_next(info_arr, p);
  if (*p != NULL) {
    strcpy(el->ip_addr_low, *p);
  } else
    goto err;

  p = (char**) utarray_next(info_arr, p);
  if (*p != NULL)
    strcpy(el->ip_addr_upp, *p);
  else
    goto err;

  p = (char**) utarray_next(info_arr, p);
  if (*p != NULL)
    strcpy(el->subnet_mask, *p);
  else
    goto err;

  p = (char**) utarray_next(info_arr, p);
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

static void test_generate_dhcp_conf(void **state)
{
  (void) state; /* unused */
  struct dhcp_conf dconf;
  UT_array *server_arr;
  config_dhcpinfo_t el;

  utarray_new(dconf.config_dhcpinfo_array, &config_dhcpinfo_icd);
  utarray_new(server_arr, &ut_str_icd);

  strcpy(dconf.dhcp_conf_path, test_dhcp_conf_path);
  strcpy(dconf.dhcp_script_path, test_dhcp_script_path);

  get_config_dhcpinfo("0,10.0.0.2,10.0.0.254,255.255.255.0,24h", &el);
  utarray_push_back(dconf.config_dhcpinfo_array, &el);
  get_config_dhcpinfo("1,10.0.1.2,10.0.1.254,255.255.255.0,24h", &el);
  utarray_push_back(dconf.config_dhcpinfo_array, &el);
  get_config_dhcpinfo("2,10.0.2.2,10.0.2.254,255.255.255.0,24h", &el);
  utarray_push_back(dconf.config_dhcpinfo_array, &el);
  get_config_dhcpinfo("3,10.0.3.2,10.0.3.254,255.255.255.0,24h", &el);
  utarray_push_back(dconf.config_dhcpinfo_array, &el);

  split_string_array(dns_server, ',', server_arr);

  bool ret = generate_dnsmasq_conf(&dconf, interface, server_arr);
  assert_true(ret);

  FILE *fp = fopen(test_dhcp_conf_path, "r");
  assert_non_null(fp);

  long lSize;
  char * buffer;

  fseek(fp, 0 , SEEK_END);
  lSize = ftell(fp);
  rewind(fp);
  buffer = (char*) malloc(sizeof(char)*lSize);
  assert_non_null(buffer);

  size_t result = fread(buffer, 1, lSize, fp);
  assert_int_equal(result, strlen(test_dhcp_conf_content));
  int cmp = memcmp(buffer, test_dhcp_conf_content, result);
  assert_int_equal(cmp, 0);

  fclose(fp);
  free(buffer);

  utarray_free(server_arr);
  utarray_free(dconf.config_dhcpinfo_array);
}

static void test_generate_script_conf(void **state)
{
  (void) state; /* unused */

  bool ret = generate_dnsmasq_script(test_dhcp_script_path, test_domain_server_path);
  assert_true(ret);

  FILE *fp = fopen(test_dhcp_script_path, "r");
  assert_non_null(fp);

  long lSize;
  char * buffer;

  fseek(fp, 0 , SEEK_END);
  lSize = ftell(fp);
  rewind(fp);
  buffer = (char*) malloc(sizeof(char)*lSize);
  assert_non_null(buffer);

  size_t result = fread(buffer, 1, lSize, fp);
  assert_int_equal(result, strlen(test_dhcp_script_content));
  int cmp = memcmp(buffer, test_dhcp_script_content, result);
  assert_int_equal(cmp, 0);

  fclose(fp);
  free(buffer);
}

int main(int argc, char *argv[])
{  
  log_set_quiet(true);

  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_generate_dhcp_conf),
    cmocka_unit_test(test_generate_script_conf)
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
