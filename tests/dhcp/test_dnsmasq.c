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

#include "utils/log.h"
#include "dhcp/dnsmasq.h"

static char *test_dhcp_conf_path = "/tmp/dnsmasq.conf";
static char *test_dhcp_script_path = "/tmp/dnsmasq_exec.sh";
static char *test_dhcp_conf_content =
"no-resolv\n"
"bridge=br0\n"
"server=8.8.4.4\n"
"server=8.8.8.8\n"
"dhcp-script=/tmp/dnsmasq_exec.sh\n"
"dhcp-range=wifi_if,10.0.0.1,10.0.0.254,255.255.255.0,24h\n"
"dhcp-range=wifi_if.1,10.0.1.1,10.0.1.254,255.255.255.0,24h\n"
"dhcp-range=wifi_if.2,10.0.2.1,10.0.2.254,255.255.255.0,24h\n"
"dhcp-range=wifi_if.3,10.0.3.1,10.0.3.254,255.255.255.0,24h\n"
"wpa_psk_radius=2\n";

static char *test_hostapd_vlan_content = "*\twlan0.#\n";

static void test_generate_hostapd_conf(void **state)
{
  (void) state; /* unused */
  struct hostapd_conf hconf;
  strcpy(hconf.hostapd_file_path, test_hostapd_conf_file);
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

int main(int argc, char *argv[])
{  
  log_set_quiet(true);

  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_generate_hostapd_conf),
    cmocka_unit_test(test_generate_vlan_conf)
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
