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

#include "utils/log.h"
#include "utils/os.h"
#include "utils/if.h"
#include "ap/ap_config.h"
#include "ap/hostapd.h"

static char *test_hostapd_vlan_file = "/tmp/hostapd-test.vlan";
static char *test_hostapd_conf_file = "/tmp/hostapd-test.conf";
static char *test_hostapd_conf_content =
"interface=wlan0\n"
"bridge=br0\n"
"driver=nl80211\n"
"ssid=IOTH_IMX7\n"
"hw_mode=g\n"
"channel=11\n"
"wmm_enabled=1\n"
"auth_algs=1\n"
"wpa=2\n"
"wpa_key_mgmt=WPA-PSK\n"
"rsn_pairwise=CCMP\n"
"ctrl_interface=/var/run/hostapd\n"
"own_ip_addr=192.168.1.2\n"
"auth_server_addr=192.168.1.1\n"
"auth_server_port=1812\n"
"auth_server_shared_secret=radius\n"
"macaddr_acl=2\n"
"dynamic_vlan=1\n"
"vlan_bridge=br\n"
"vlan_file=/tmp/hostapd-test.vlan\n"
"logger_stdout=-1\n"
"logger_stdout_level=0\n"
"logger_syslog=-1\n"
"logger_syslog_level=0\n"
"ignore_broadcast_ssid=0\n"
"wpa_psk_radius=2\n";

static char *test_hostapd_vlan_content = "*\twlan0.#\n";

static char *test_ap_bin_path = "/tmp/hostapd";
static char *test_ap_log_path = "/tmp/hostapd.log";
static char *test_ctrl_if_path = "/var/run/hostapd/wlan0";

bool __wrap_kill_process(char *proc_name)
{
  log_trace("HERE");
  return true;
}

bool __wrap_reset_interface(char *if_name)
{
  return true;
}

int __wrap_run_process(char *argv[], pid_t *child_pid)
{
  return 0;
}

int __wrap_list_dir(char *dirpath, list_dir_fn fun, void *args)
{
  struct find_dir_type *dir_args = (struct find_dir_type *) args;
  dir_args->proc_running = 1;
  return 0;
}

int __wrap_check_sock_file_exists(char *path)
{
  return 0;
}


static void test_generate_hostapd_conf(void **state)
{
  (void) state; /* unused */
  struct apconf hconf;
  strcpy(hconf.ap_file_path, test_hostapd_conf_file);
  strcpy(hconf.interface, "wlan0");
  strcpy(hconf.ssid, "IOTH_IMX7");
  strcpy(hconf.wpa_passphrase, "1234554321");
  strcpy(hconf.bridge, "br0");
  strcpy(hconf.driver, "nl80211");
  strcpy(hconf.hw_mode, "g");
  hconf.channel = 11;
  hconf.wmm_enabled = 1;
  hconf.auth_algs = 1;
  hconf.wpa = 2;
  strcpy(hconf.wpa_key_mgmt, "WPA-PSK");
  strcpy(hconf.rsn_pairwise, "CCMP");
  strcpy(hconf.ctrl_interface, "/var/run/hostapd");
  hconf.macaddr_acl = 2;
  hconf.dynamic_vlan = 1;
  strcpy(hconf.vlan_bridge, "br");
  strcpy(hconf.vlan_file, "/tmp/hostapd-test.vlan");
  hconf.logger_stdout = -1;
  hconf.logger_stdout_level = 0;
  hconf.logger_syslog = -1;
  hconf.logger_syslog_level = 0;
  hconf.ignore_broadcast_ssid = 0;
  hconf.wpa_psk_radius = 2;
  strcpy(hconf.vlan_tagged_interface, "");
  
  struct radius_conf rconf;
  strcpy(rconf.radius_server_ip, "192.168.1.1");
  strcpy(rconf.radius_client_ip, "192.168.1.2");
  rconf.radius_port = 1812;
  strcpy(rconf.radius_secret, "radius");
  bool ret = generate_hostapd_conf(&hconf, &rconf);
  assert_true(ret);

  FILE *fp = fopen(test_hostapd_conf_file, "r");
  assert_non_null(fp);

  long lSize;
  char * buffer;

  fseek(fp, 0 , SEEK_END);
  lSize = ftell(fp);
  rewind(fp);
  buffer = (char*) malloc(sizeof(char)*lSize);
  assert_non_null(buffer);

  size_t result = fread(buffer, 1, lSize, fp);
  assert_int_equal(result, strlen(test_hostapd_conf_content));
  int cmp = memcmp(buffer, test_hostapd_conf_content, result);
  assert_int_equal(cmp, 0);

  fclose(fp);
  free(buffer);
}

static void test_generate_vlan_conf(void **state)
{
  (void) state; /* unused */

  bool ret = generate_vlan_conf(test_hostapd_vlan_file, "wlan0");

  assert_true(ret);

  FILE *fp = fopen(test_hostapd_vlan_file, "r");
  assert_non_null(fp);

  long lSize;
  char * buffer;

  fseek(fp, 0 , SEEK_END);
  lSize = ftell(fp);
  rewind(fp);
  buffer = (char*) malloc(sizeof(char)*lSize);
  assert_non_null(buffer);

  size_t result = fread(buffer, 1, lSize, fp);
  assert_int_equal(result, strlen(test_hostapd_vlan_content));

  int cmp = memcmp(buffer, test_hostapd_vlan_content, result);
  assert_int_equal(cmp, 0);

  fclose(fp);
  free(buffer);
}

static void test_run_ap_process(void **state)
{
  (void) state; /* unused */

  struct apconf hconf;

  strcpy(hconf.ap_bin_path, test_ap_bin_path);
  strcpy(hconf.ap_file_path, test_hostapd_conf_file);
  strcpy(hconf.ap_log_path, test_ap_log_path);
  
  int ret = run_ap_process(&hconf, test_ctrl_if_path);
  assert_int_equal(ret, 0);
}

int main(int argc, char *argv[])
{  
  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_generate_hostapd_conf),
    cmocka_unit_test(test_generate_vlan_conf),
    cmocka_unit_test(test_run_ap_process)
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
