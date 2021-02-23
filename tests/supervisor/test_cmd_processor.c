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

#include "supervisor/cmd_processor.h"

#include "utils/hashmap.h"
#include "utils/utarray.h"
#include "utils/log.h"
#include "engine.h"

typedef enum TEST_COMMANDS {
  TEST_PROCESS_ADD_BRIDGE_CMD_ONE = 0,
  TEST_PROCESS_REMOVE_BRIDGE_CMD_ONE,
  TEST_PROCESS_SET_IP_CMD_ONE,
  TEST_PROCESS_GET_ALL_CMD_ONE,
  TEST_PROCESS_GET_ALL_CMD_TWO,
  TEST_PROCESS_GET_ALL_CMD_THREE
} TEST_COMMANDS;

static const UT_icd config_ifinfo_icd = {sizeof(config_ifinfo_t), NULL, NULL, NULL};
static char ip_tables_mock_buf[255];

ssize_t __wrap_write_domain_data(int sock, char *data, size_t data_len, char *addr);
bool __wrap_add_bridge_rules(char *sip, char *sif, char *dip, char *dif);
bool __wrap_delete_bridge_rules(char *sip, char *sif, char *dip, char *dif);
bool __wrap_add_nat_rules(char *sip, char *sif, char *nif);
bool __wrap_delete_nat_rules(char *sip, char *sif, char *nif);

ssize_t __wrap_write_domain_data(int sock, char *data, size_t data_len, char *addr)
{
  switch (sock) {
    case TEST_PROCESS_ADD_BRIDGE_CMD_ONE:
      return data_len;
    case TEST_PROCESS_REMOVE_BRIDGE_CMD_ONE:
      return data_len;
    case TEST_PROCESS_SET_IP_CMD_ONE:
      return data_len;
    case TEST_PROCESS_GET_ALL_CMD_ONE:
      return data_len;
    case TEST_PROCESS_GET_ALL_CMD_TWO:
      return strcmp(data, "a,11:22:33:44:55:66,,1,0,\na,aa:bb:cc:dd:ee:ff,,3,0,\n");
    case TEST_PROCESS_GET_ALL_CMD_THREE:
      return strcmp(data, "a,11:22:33:44:55:66,10.0.1.23,1,0,\nd,aa:bb:cc:dd:ee:ff,,3,0,\n");
  }
  return 0;
}

bool __wrap_add_bridge_rules(char *sip, char *sif, char *dip, char *dif)
{
  memset(ip_tables_mock_buf, 0, 255);

  strcpy(ip_tables_mock_buf, "add_bridge");
  strcat(ip_tables_mock_buf, sip);
  strcat(ip_tables_mock_buf, sif);
  strcat(ip_tables_mock_buf, dip);
  strcat(ip_tables_mock_buf, dif);

  return true;
}

bool __wrap_delete_bridge_rules(char *sip, char *sif, char *dip, char *dif)
{
  memset(ip_tables_mock_buf, 0, 255);

  strcpy(ip_tables_mock_buf, "delete_bridge");
  strcat(ip_tables_mock_buf, sip);
  strcat(ip_tables_mock_buf, sif);
  strcat(ip_tables_mock_buf, dip);
  strcat(ip_tables_mock_buf, dif);

  return true;
}

bool __wrap_add_nat_rules(char *sip, char *sif, char *nif)
{
  memset(ip_tables_mock_buf, 0, 255);
  strcpy(ip_tables_mock_buf, "add_nat");
  strcat(ip_tables_mock_buf, sip);
  strcat(ip_tables_mock_buf, sif);
  strcat(ip_tables_mock_buf, nif);

  return true;
}

bool __wrap_delete_nat_rules(char *sip, char *sif, char *nif)
{
  memset(ip_tables_mock_buf, 0, 255);
  strcpy(ip_tables_mock_buf, "delete_nat");
  strcat(ip_tables_mock_buf, sip);
  strcat(ip_tables_mock_buf, sif);
  strcat(ip_tables_mock_buf, nif);

  return true;
}

void init_test_context(struct supervisor_context *context)
{
  struct app_config config;
  UT_array *config_ifinfo_arr;

  memset(&config, 0, sizeof(struct app_config));

  // Create the config interface
  utarray_new(config_ifinfo_arr, &config_ifinfo_icd);
  config.config_ifinfo_array = config_ifinfo_arr;

  config_ifinfo_t el;
  memset(&el, 0, sizeof(config_ifinfo_t));

  el.vlanid = 0;
  strcpy(el.ip_addr, "10.0.0.1");
  strcpy(el.brd_addr, "10.0.0.255");
  strcpy(el.subnet_mask, "255.255.255.0");
  utarray_push_back(config.config_ifinfo_array, &el);

  el.vlanid = 1;
  strcpy(el.ip_addr, "10.0.1.1");
  strcpy(el.brd_addr, "10.0.1.255");
  strcpy(el.subnet_mask, "255.255.255.0");
  utarray_push_back(config.config_ifinfo_array, &el);

  el.vlanid = 2;
  strcpy(el.ip_addr, "10.0.2.1");
  strcpy(el.brd_addr, "10.0.2.255");
  strcpy(el.subnet_mask, "255.255.255.0");
  utarray_push_back(config.config_ifinfo_array, &el);

  el.vlanid = 3;
  strcpy(el.ip_addr, "10.0.3.1");
  strcpy(el.brd_addr, "10.0.3.255");
  strcpy(el.subnet_mask, "255.255.255.0");
  utarray_push_back(config.config_ifinfo_array, &el);

  strcpy(config.hconfig.vlan_bridge, "br");
  config.allow_all_connections = false;
  config.default_open_vlanid = 0;
  strcpy(config.hconfig.wpa_passphrase, "12345");
  strcpy(config.nat_interface, "natif");

  init_context(&config, context);
}

void free_test_context(struct supervisor_context *context)
{
  utarray_free(context->config_ifinfo_array);
  free_mac_mapper(&context->mac_mapper);
  free_if_mapper(&context->if_mapper);
  free_bridge_list(context->bridge_list);
}

static void test_process_domain_buffer(void **state)
{
  (void) state; /* unused */  

  UT_array *arr;
  utarray_new(arr, &ut_str_icd);

  char buf1[5] = {'c', CMD_DELIMITER, 'a', CMD_DELIMITER, 'b'};

  bool ret = process_domain_buffer(buf1, 5, arr);

  assert_true(ret);

  char **p = NULL;
  p = (char**)utarray_next(arr, p);
  assert_string_equal(*p, "c");
  p = (char**)utarray_next(arr, p);
  assert_string_equal(*p, "a");
  p = (char**)utarray_next(arr, p);
  assert_string_equal(*p, "b");

  p = (char**)utarray_next(arr, p);
  assert_ptr_equal(p, NULL);

  utarray_free(arr);

  utarray_new(arr, &ut_str_icd);
  char buf2[4] = {'P', 'I', 'N', 'G'};
  ret = process_domain_buffer(buf2, 4, arr);

  assert_true(ret);

  p = (char**)utarray_next(arr, p);
  assert_string_equal(*p, "PING");

  utarray_free(arr);
}

static void test_process_add_bridge_cmd(void **state)
{
  (void) state; /* unused */
  char *client_addr = "127.0.0.1";
  uint8_t mac_addr_left[ETH_ALEN];
  uint8_t mac_addr_right[ETH_ALEN];

  struct supervisor_context context = {};
  UT_array *cmd_arr;
  utarray_new(cmd_arr, &ut_str_icd);

  hwaddr_aton2("11:22:33:44:55:66", mac_addr_left);
  hwaddr_aton2("aa:bb:cc:dd:ee:ff", mac_addr_right);

  init_test_context(&context);

  assert_int_not_equal(split_string_array("ACCEPT_MAC 11:22:33:44:55:66 1", CMD_DELIMITER, cmd_arr), -1);  
  ssize_t ret = process_accept_mac_cmd(TEST_PROCESS_ADD_BRIDGE_CMD_ONE, client_addr, &context, cmd_arr);
  assert_int_equal(ret, strlen(OK_REPLY));

  utarray_clear(cmd_arr);

  assert_int_not_equal(split_string_array("ACCEPT_MAC aa:bb:cc:dd:ee:ff 3", CMD_DELIMITER, cmd_arr), -1);  
  ret = process_accept_mac_cmd(TEST_PROCESS_ADD_BRIDGE_CMD_ONE, client_addr, &context, cmd_arr);
  assert_int_equal(ret, strlen(OK_REPLY));

  utarray_clear(cmd_arr);

  assert_int_not_equal(split_string_array("SET_IP add 11:22:33:44:55:66 10.0.1.23", CMD_DELIMITER, cmd_arr), -1);  
  ret = process_set_ip_cmd(TEST_PROCESS_ADD_BRIDGE_CMD_ONE, client_addr, &context, cmd_arr);
  assert_int_equal(ret, strlen(OK_REPLY));

  utarray_clear(cmd_arr);

  assert_int_not_equal(split_string_array("SET_IP add aa:bb:cc:dd:ee:ff 10.0.3.45", CMD_DELIMITER, cmd_arr), -1);  
  ret = process_set_ip_cmd(TEST_PROCESS_ADD_BRIDGE_CMD_ONE, client_addr, &context, cmd_arr);
  assert_int_equal(ret, strlen(OK_REPLY));

  utarray_clear(cmd_arr);

  assert_int_not_equal(split_string_array("ADD_BRIDGE 11:22:33:44:55:66 aa:bb:cc:dd:ee:ff", CMD_DELIMITER, cmd_arr), -1);  
  ret = process_add_bridge_cmd(TEST_PROCESS_ADD_BRIDGE_CMD_ONE, client_addr, &context, cmd_arr);
  assert_int_equal(ret, strlen(OK_REPLY));

  struct bridge_mac_list_tuple tuple = get_bridge_mac(context.bridge_list, mac_addr_left, mac_addr_right);
  assert_non_null(tuple.left_edge);
  assert_non_null(tuple.right_edge);

  assert_int_equal(strcmp(ip_tables_mock_buf, "add_bridge10.0.1.23br110.0.3.45br3"),0);

  utarray_clear(cmd_arr);

  memset(ip_tables_mock_buf, 0, 255);

  assert_int_not_equal(split_string_array("ADD_BRIDGE 1f:2f:3f:4f:5f:6f aa:bb:cc:dd:ee:ff", CMD_DELIMITER, cmd_arr), -1);  
  ret = process_add_bridge_cmd(TEST_PROCESS_ADD_BRIDGE_CMD_ONE, client_addr, &context, cmd_arr);
  assert_int_equal(ret, strlen(OK_REPLY));

  tuple = get_bridge_mac(context.bridge_list, mac_addr_left, mac_addr_right);
  assert_non_null(tuple.left_edge);
  assert_non_null(tuple.right_edge);

  assert_int_equal(strlen(ip_tables_mock_buf),0);

  utarray_clear(cmd_arr);

  assert_int_not_equal(split_string_array("ADD_BRIDGE 1f", CMD_DELIMITER, cmd_arr), -1);  
  ret = process_add_bridge_cmd(TEST_PROCESS_ADD_BRIDGE_CMD_ONE, client_addr, &context, cmd_arr);
  assert_int_equal(ret, strlen(FAIL_REPLY));

  utarray_free(cmd_arr);
  free_test_context(&context);
}

static void test_process_remove_bridge_cmd(void **state)
{
  (void) state; /* unused */

  char *client_addr = "127.0.0.1";
  uint8_t mac_addr_left[ETH_ALEN];
  uint8_t mac_addr_right[ETH_ALEN];

  struct supervisor_context context = {};
  UT_array *cmd_arr;
  utarray_new(cmd_arr, &ut_str_icd);

  hwaddr_aton2("11:22:33:44:55:66", mac_addr_left);
  hwaddr_aton2("aa:bb:cc:dd:ee:ff", mac_addr_right);

  init_test_context(&context);

  assert_int_not_equal(split_string_array("REMOVE_BRIDGE 11:22:33:44:55:66 aa:bb:cc:dd:ee:ff", CMD_DELIMITER, cmd_arr), -1);  
  ssize_t ret = process_remove_bridge_cmd(TEST_PROCESS_REMOVE_BRIDGE_CMD_ONE, client_addr, &context, cmd_arr);
  assert_int_equal(ret, strlen(FAIL_REPLY));

  utarray_clear(cmd_arr);

  assert_int_not_equal(split_string_array("ADD_BRIDGE 11:22:33:44:55:66 aa:bb:cc:dd:ee:ff", CMD_DELIMITER, cmd_arr), -1);  
  ret = process_add_bridge_cmd(TEST_PROCESS_ADD_BRIDGE_CMD_ONE, client_addr, &context, cmd_arr);
  assert_int_equal(ret, strlen(OK_REPLY));

  utarray_clear(cmd_arr);
  assert_int_not_equal(split_string_array("REMOVE_BRIDGE 11:22:33:44:55:66 aa:bb:cc:dd:ee:ff", CMD_DELIMITER, cmd_arr), -1);  
  ret = process_remove_bridge_cmd(TEST_PROCESS_REMOVE_BRIDGE_CMD_ONE, client_addr, &context, cmd_arr);
  assert_int_equal(ret, strlen(OK_REPLY));

  utarray_clear(cmd_arr);

  assert_int_not_equal(split_string_array("SET_IP add 11:22:33:44:55:66 10.0.1.23", CMD_DELIMITER, cmd_arr), -1);  
  ret = process_set_ip_cmd(TEST_PROCESS_ADD_BRIDGE_CMD_ONE, client_addr, &context, cmd_arr);
  assert_int_equal(ret, strlen(OK_REPLY));

  utarray_clear(cmd_arr);

  assert_int_not_equal(split_string_array("SET_IP add aa:bb:cc:dd:ee:ff 10.0.3.45", CMD_DELIMITER, cmd_arr), -1);  
  ret = process_set_ip_cmd(TEST_PROCESS_ADD_BRIDGE_CMD_ONE, client_addr, &context, cmd_arr);
  assert_int_equal(ret, strlen(OK_REPLY));

  utarray_clear(cmd_arr);

  assert_int_not_equal(split_string_array("ACCEPT_MAC 11:22:33:44:55:66 1", CMD_DELIMITER, cmd_arr), -1);  
  ret = process_accept_mac_cmd(TEST_PROCESS_ADD_BRIDGE_CMD_ONE, client_addr, &context, cmd_arr);
  assert_int_equal(ret, strlen(OK_REPLY));

  utarray_clear(cmd_arr);

  assert_int_not_equal(split_string_array("ACCEPT_MAC aa:bb:cc:dd:ee:ff 3", CMD_DELIMITER, cmd_arr), -1);  
  ret = process_accept_mac_cmd(TEST_PROCESS_ADD_BRIDGE_CMD_ONE, client_addr, &context, cmd_arr);
  assert_int_equal(ret, strlen(OK_REPLY));

  utarray_clear(cmd_arr);

  assert_int_not_equal(split_string_array("ADD_BRIDGE 11:22:33:44:55:66 aa:bb:cc:dd:ee:ff", CMD_DELIMITER, cmd_arr), -1);  
  ret = process_add_bridge_cmd(TEST_PROCESS_ADD_BRIDGE_CMD_ONE, client_addr, &context, cmd_arr);
  assert_int_equal(ret, strlen(OK_REPLY));

  utarray_clear(cmd_arr);

  assert_int_not_equal(split_string_array("REMOVE_BRIDGE 11:22:33:44:55:66 aa:bb:cc:dd:ee:ff", CMD_DELIMITER, cmd_arr), -1);  
  ret = process_remove_bridge_cmd(TEST_PROCESS_REMOVE_BRIDGE_CMD_ONE, client_addr, &context, cmd_arr);
  assert_int_equal(ret, strlen(OK_REPLY));
  assert_int_equal(strcmp(ip_tables_mock_buf, "delete_bridge10.0.1.23br110.0.3.45br3"),0);

  utarray_free(cmd_arr);
  free_test_context(&context);
}

static void test_process_set_ip_cmd(void **state)
{
  (void) state; /* unused */

  char *client_addr = "127.0.0.1";
  uint8_t mac_addr_left[ETH_ALEN];
  uint8_t mac_addr_right[ETH_ALEN];

  struct supervisor_context context = {};
  struct mac_conn_info info;
  UT_array *cmd_arr;
  utarray_new(cmd_arr, &ut_str_icd);

  hwaddr_aton2("11:22:33:44:55:66", mac_addr_left);
  hwaddr_aton2("aa:bb:cc:dd:ee:ff", mac_addr_right);

  init_test_context(&context);

  assert_int_not_equal(split_string_array("ACCEPT_MAC 11:22:33:44:55:66 1", CMD_DELIMITER, cmd_arr), -1);  
  ssize_t ret = process_accept_mac_cmd(TEST_PROCESS_SET_IP_CMD_ONE, client_addr, &context, cmd_arr);
  assert_int_equal(ret, strlen(OK_REPLY));

  utarray_clear(cmd_arr);

  assert_int_not_equal(split_string_array("ASSIGN_PSK 11:22:33:44:55:66 12345", CMD_DELIMITER, cmd_arr), -1);
  ret = process_assign_psk_cmd(TEST_PROCESS_SET_IP_CMD_ONE, client_addr, &context, cmd_arr);
  assert_int_equal(ret, strlen(OK_REPLY));

  utarray_clear(cmd_arr);

  assert_int_not_equal(split_string_array("ADD_NAT 11:22:33:44:55:66", CMD_DELIMITER, cmd_arr), -1);
  ret = process_add_nat_cmd(TEST_PROCESS_SET_IP_CMD_ONE, client_addr, &context, cmd_arr);
  assert_int_equal(ret, strlen(OK_REPLY));

  utarray_clear(cmd_arr);

  assert_int_not_equal(split_string_array("SET_IP add 11:22:33:44:55:66 10.0.1.23", CMD_DELIMITER, cmd_arr), -1);
  ret = process_set_ip_cmd(TEST_PROCESS_SET_IP_CMD_ONE, client_addr, &context, cmd_arr);
  assert_int_equal(ret, strlen(OK_REPLY));
  get_mac_mapper(&context.mac_mapper, mac_addr_left, &info);
  assert_int_equal(strcmp(info.ip_addr, "10.0.1.23"), 0);
  assert_int_equal(strcmp(info.pass, "12345"), 0);
  assert_true(info.nat);
  assert_int_equal(strcmp(ip_tables_mock_buf, "add_nat10.0.1.23br1natif"),0);

  utarray_clear(cmd_arr);

  assert_int_not_equal(split_string_array("SET_IP del 11:22:33:44:55:66 10.0.1.23", CMD_DELIMITER, cmd_arr), -1);
  ret = process_set_ip_cmd(TEST_PROCESS_SET_IP_CMD_ONE, client_addr, &context, cmd_arr);
  assert_int_equal(ret, strlen(OK_REPLY));
  get_mac_mapper(&context.mac_mapper, mac_addr_left, &info);
  assert_int_equal(strlen(info.ip_addr), 0);
  assert_int_equal(strcmp(info.pass, "12345"), 0);
  assert_true(info.nat);
  assert_int_equal(strcmp(ip_tables_mock_buf, "delete_nat10.0.1.23br1natif"),0);

  utarray_clear(cmd_arr);

  assert_int_not_equal(split_string_array("SET_IP add aa:bb:cc:dd:ee:ff 10.0.3.45", CMD_DELIMITER, cmd_arr), -1);
  ret = process_set_ip_cmd(TEST_PROCESS_SET_IP_CMD_ONE, client_addr, &context, cmd_arr);
  assert_int_equal(ret, strlen(OK_REPLY));
  get_mac_mapper(&context.mac_mapper, mac_addr_right, &info);
  assert_int_equal(strcmp(info.ip_addr, "10.0.3.45"), 0);
  assert_int_equal(info.pass_len, 0);
  assert_false(info.nat);

  utarray_clear(cmd_arr);

  split_string_array("SET_IP add 11:22:33:44:55:66 10.0.1.", CMD_DELIMITER, cmd_arr);
  ret = process_set_ip_cmd(TEST_PROCESS_SET_IP_CMD_ONE, client_addr, &context, cmd_arr);
  assert_int_equal(ret, strlen(FAIL_REPLY));

  utarray_clear(cmd_arr);

  split_string_array("SET_IP add 11:22:33:44:55:66 ", CMD_DELIMITER, cmd_arr);
  ret = process_set_ip_cmd(TEST_PROCESS_SET_IP_CMD_ONE, client_addr, &context, cmd_arr);
  assert_int_equal(ret, strlen(FAIL_REPLY));

  utarray_clear(cmd_arr);

  split_string_array("SET_IP add 11:22:33: 10.0.1.23", CMD_DELIMITER, cmd_arr);
  ret = process_set_ip_cmd(TEST_PROCESS_SET_IP_CMD_ONE, client_addr, &context, cmd_arr);
  assert_int_equal(ret, strlen(FAIL_REPLY));

  utarray_free(cmd_arr);
  free_test_context(&context);
}

static void test_process_get_all_cmd(void **state)
{
  (void) state; /* unused */

  char *client_addr = "127.0.0.1";
  uint8_t mac_addr_left[ETH_ALEN];
  uint8_t mac_addr_right[ETH_ALEN];

  struct supervisor_context context = {};
  UT_array *cmd_arr;
  utarray_new(cmd_arr, &ut_str_icd);

  hwaddr_aton2("11:22:33:44:55:66", mac_addr_left);
  hwaddr_aton2("aa:bb:cc:dd:ee:ff", mac_addr_right);

  init_test_context(&context);

  ssize_t ret = process_get_all_cmd(TEST_PROCESS_GET_ALL_CMD_ONE, client_addr, &context);
  assert_int_equal(ret, strlen(OK_REPLY));

  assert_int_not_equal(split_string_array("ACCEPT_MAC 11:22:33:44:55:66 1", CMD_DELIMITER, cmd_arr), -1);  
  ret = process_accept_mac_cmd(TEST_PROCESS_GET_ALL_CMD_ONE, client_addr, &context, cmd_arr);
  assert_int_equal(ret, strlen(OK_REPLY));

  utarray_clear(cmd_arr);

  assert_int_not_equal(split_string_array("ACCEPT_MAC aa:bb:cc:dd:ee:ff 3", CMD_DELIMITER, cmd_arr), -1);  
  ret = process_accept_mac_cmd(TEST_PROCESS_GET_ALL_CMD_ONE, client_addr, &context, cmd_arr);
  assert_int_equal(ret, strlen(OK_REPLY));

  ret = process_get_all_cmd(TEST_PROCESS_GET_ALL_CMD_TWO, client_addr, &context);
  assert_int_equal(ret, 0);

  utarray_clear(cmd_arr);

  split_string_array("SET_IP add 11:22:33:44:55:66 10.0.1.23", CMD_DELIMITER, cmd_arr);
  ret = process_set_ip_cmd(TEST_PROCESS_GET_ALL_CMD_ONE, client_addr, &context, cmd_arr);
  assert_int_equal(ret, strlen(OK_REPLY));

  utarray_clear(cmd_arr);

  assert_int_not_equal(split_string_array("DENY_MAC aa:bb:cc:dd:ee:ff", CMD_DELIMITER, cmd_arr), -1);
  ret = process_deny_mac_cmd(TEST_PROCESS_GET_ALL_CMD_ONE, client_addr, &context, cmd_arr);
  assert_int_equal(ret, strlen(OK_REPLY));

  ret = process_get_all_cmd(TEST_PROCESS_GET_ALL_CMD_THREE, client_addr, &context);
  assert_int_equal(ret, 0);

  utarray_free(cmd_arr);
  free_test_context(&context);
}

static void test_process_get_map_cmd(void **state)
{
  (void) state; /* unused */
  
}

int main(int argc, char *argv[])
{  
  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_process_domain_buffer),
    cmocka_unit_test(test_process_add_bridge_cmd),
    cmocka_unit_test(test_process_remove_bridge_cmd),
    cmocka_unit_test(test_process_set_ip_cmd),
    cmocka_unit_test(test_process_get_all_cmd)
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
