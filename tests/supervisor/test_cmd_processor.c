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
#include "utils/iptables.h"
#include "engine.h"

#define CMD_DELIMITER 0x20

ssize_t __wrap_write_domain_data(int sock, char *data, size_t data_len, char *addr)
{
  return data_len;
}

int __wrap_accept_mac_cmd(struct supervisor_context *context, uint8_t *mac_addr, int vlanid)
{
  check_expected(mac_addr);
  check_expected(vlanid);
  return 0;
}

int __wrap_deny_mac_cmd(struct supervisor_context *context, uint8_t *mac_addr)
{
  check_expected(mac_addr);
  return 0;
}

int __wrap_add_nat_cmd(struct supervisor_context *context, uint8_t *mac_addr)
{
  check_expected(mac_addr);
  return 0;
}

int __wrap_remove_nat_cmd(struct supervisor_context *context, uint8_t *mac_addr)
{
  check_expected(mac_addr);
  return 0;
}

int __wrap_assign_psk_cmd(struct supervisor_context *context, uint8_t *mac_addr, char *pass, int pass_len)
{
  check_expected(mac_addr);
  check_expected(pass);
  check_expected(pass_len);
  return 0;
}

int __wrap_set_ip_cmd(struct supervisor_context *context, uint8_t *mac_addr, char *ip_addr, bool add)
{

  check_expected(mac_addr);
  check_expected(ip_addr);
  check_expected(add);
  return 0;
}

int __wrap_add_bridge_cmd(struct supervisor_context *context, uint8_t *left_mac_addr, uint8_t *right_mac_addr)
{
  check_expected(left_mac_addr);
  check_expected(right_mac_addr);
  return 0;
}

int __wrap_remove_bridge_cmd(struct supervisor_context *context, uint8_t *left_mac_addr, uint8_t *right_mac_addr)
{
  check_expected(left_mac_addr);
  check_expected(right_mac_addr);
  return 0;
}

int __wrap_set_fingerprint_cmd(struct supervisor_context *context, char *mac_addr, char *protocol,
                        char *fingerprint, uint64_t timestamp, char *query)
{
  check_expected(mac_addr);
  check_expected(protocol);
  check_expected(fingerprint);
  check_expected(timestamp);
  check_expected(query);
  return 0;
}

ssize_t __wrap_query_fingerprint_cmd(struct supervisor_context *context, char *mac_addr, uint64_t timestamp,
                        char *op, char *protocol, char **out)
{
  check_expected(mac_addr);
  check_expected(timestamp);
  check_expected(op);
  check_expected(protocol);
  check_expected(out);
  return 0;
}

uint8_t* __wrap_register_ticket_cmd(struct supervisor_context *context, uint8_t *mac_addr, char *label,
                        int vlanid)
{
  check_expected(mac_addr);
  check_expected(label);
  check_expected(vlanid);
  return NULL;
}

int __wrap_clear_psk_cmd(struct supervisor_context *context, uint8_t *mac_addr)
{
  check_expected(mac_addr);
  return 0;
}
static void test_process_domain_buffer(void **state)
{
  (void) state; /* unused */  

  UT_array *arr;
  utarray_new(arr, &ut_str_icd);

  char buf1[5] = {'c', CMD_DELIMITER, 'a', CMD_DELIMITER, 'b'};

  bool ret = process_domain_buffer(buf1, 5, arr, CMD_DELIMITER);

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
  ret = process_domain_buffer(buf2, 4, arr, CMD_DELIMITER);

  assert_true(ret);

  p = (char**)utarray_next(arr, p);
  assert_string_equal(*p, "PING");

  utarray_free(arr);
}

static void test_process_accept_mac_cmd(void **state)
{
  (void) state; /* unused */
  uint8_t addr[ETH_ALEN] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
  UT_array *cmd_arr;

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("ACCEPT_MAC aa:bb:cc:dd:ee:ff 3", CMD_DELIMITER, cmd_arr), -1); 
  expect_memory(__wrap_accept_mac_cmd, mac_addr, addr, ETH_ALEN);
  expect_value(__wrap_accept_mac_cmd, vlanid, 3);
  assert_int_equal(process_accept_mac_cmd(0, NULL, NULL, cmd_arr), strlen(OK_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("ACCEPT_MAC aa:bb:cc:dd:ee: 3", CMD_DELIMITER, cmd_arr), -1); 
  assert_int_equal(process_accept_mac_cmd(0, NULL, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("ACCEPT_MAC aa:bb:cc:dd:ee:ff", CMD_DELIMITER, cmd_arr), -1); 
  assert_int_equal(process_accept_mac_cmd(0, NULL, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);
}

static void test_process_deny_mac_cmd(void **state)
{
  (void) state; /* unused */
  uint8_t addr[ETH_ALEN] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
  UT_array *cmd_arr;

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("DENY_MAC aa:bb:cc:dd:ee:ff", CMD_DELIMITER, cmd_arr), -1); 
  expect_memory(__wrap_deny_mac_cmd, mac_addr, addr, ETH_ALEN);
  assert_int_equal(process_deny_mac_cmd(0, NULL, NULL, cmd_arr), strlen(OK_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("DENY_MAC aa:bb:cc:dd:ee:", CMD_DELIMITER, cmd_arr), -1); 
  assert_int_equal(process_deny_mac_cmd(0, NULL, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);
}

static void test_process_add_nat_cmd(void **state)
{
  (void) state; /* unused */
  uint8_t addr[ETH_ALEN] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
  UT_array *cmd_arr;

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("ADD_NAT aa:bb:cc:dd:ee:ff", CMD_DELIMITER, cmd_arr), -1); 
  expect_memory(__wrap_add_nat_cmd, mac_addr, addr, ETH_ALEN);
  assert_int_equal(process_add_nat_cmd(0, NULL, NULL, cmd_arr), strlen(OK_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("ADD_NAT aa:bb:cc:dd:ee:", CMD_DELIMITER, cmd_arr), -1); 
  assert_int_equal(process_add_nat_cmd(0, NULL, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);
}

static void test_process_remove_nat_cmd(void **state)
{
  (void) state; /* unused */
  uint8_t addr[ETH_ALEN] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
  UT_array *cmd_arr;

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("REMOVE_NAT aa:bb:cc:dd:ee:ff", CMD_DELIMITER, cmd_arr), -1); 
  expect_memory(__wrap_remove_nat_cmd, mac_addr, addr, ETH_ALEN);
  assert_int_equal(process_remove_nat_cmd(0, NULL, NULL, cmd_arr), strlen(OK_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("REMOVE_NAT aa:bb:cc:dd:ee:", CMD_DELIMITER, cmd_arr), -1); 
  assert_int_equal(process_remove_nat_cmd(0, NULL, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);
}

// static void test_process_add_bridge_cmd(void **state)
// {
//   (void) state; /* unused */

  // char *client_addr = "127.0.0.1";
  // uint8_t mac_addr_left[ETH_ALEN];
  // uint8_t mac_addr_right[ETH_ALEN];

  // struct supervisor_context context = {};
  // UT_array *cmd_arr;
  // utarray_new(cmd_arr, &ut_str_icd);

  // hwaddr_aton2("11:22:33:44:55:66", mac_addr_left);
  // hwaddr_aton2("aa:bb:cc:dd:ee:ff", mac_addr_right);

  // init_test_context(&context);

  // assert_int_not_equal(split_string_array("ACCEPT_MAC 11:22:33:44:55:66 1", CMD_DELIMITER, cmd_arr), -1);  
  // ssize_t ret = process_accept_mac_cmd(TEST_PROCESS_ADD_BRIDGE_CMD_ONE, client_addr, &context, cmd_arr);
  // assert_int_equal(ret, strlen(OK_REPLY));

  // utarray_clear(cmd_arr);

  // assert_int_not_equal(split_string_array("ACCEPT_MAC aa:bb:cc:dd:ee:ff 3", CMD_DELIMITER, cmd_arr), -1);  
  // ret = process_accept_mac_cmd(TEST_PROCESS_ADD_BRIDGE_CMD_ONE, client_addr, &context, cmd_arr);
  // assert_int_equal(ret, strlen(OK_REPLY));

  // utarray_clear(cmd_arr);

  // assert_int_not_equal(split_string_array("SET_IP add 11:22:33:44:55:66 10.0.1.23", CMD_DELIMITER, cmd_arr), -1);  
  // ret = process_set_ip_cmd(TEST_PROCESS_ADD_BRIDGE_CMD_ONE, client_addr, &context, cmd_arr);
  // assert_int_equal(ret, strlen(OK_REPLY));

  // utarray_clear(cmd_arr);

  // assert_int_not_equal(split_string_array("SET_IP add aa:bb:cc:dd:ee:ff 10.0.3.45", CMD_DELIMITER, cmd_arr), -1);  
  // ret = process_set_ip_cmd(TEST_PROCESS_ADD_BRIDGE_CMD_ONE, client_addr, &context, cmd_arr);
  // assert_int_equal(ret, strlen(OK_REPLY));

  // utarray_clear(cmd_arr);

  // assert_int_not_equal(split_string_array("ADD_BRIDGE 11:22:33:44:55:66 aa:bb:cc:dd:ee:ff", CMD_DELIMITER, cmd_arr), -1);
  // ret = process_add_bridge_cmd(TEST_PROCESS_ADD_BRIDGE_CMD_ONE, client_addr, &context, cmd_arr);
  // assert_int_equal(ret, strlen(OK_REPLY));

  // struct bridge_mac_list_tuple tuple = get_bridge_mac(context.bridge_list, mac_addr_left, mac_addr_right);
  // assert_non_null(tuple.left_edge);
  // assert_non_null(tuple.right_edge);

  // assert_int_equal(strcmp(add_bridge_mock_buf, "10.0.1.23br110.0.3.45br3"),0);

  // utarray_clear(cmd_arr);

  // memset(add_bridge_mock_buf, 0, 255);

  // assert_int_not_equal(split_string_array("ADD_BRIDGE 1f:2f:3f:4f:5f:6f aa:bb:cc:dd:ee:ff", CMD_DELIMITER, cmd_arr), -1);  
  // ret = process_add_bridge_cmd(TEST_PROCESS_ADD_BRIDGE_CMD_ONE, client_addr, &context, cmd_arr);
  // assert_int_equal(ret, strlen(OK_REPLY));

  // tuple = get_bridge_mac(context.bridge_list, mac_addr_left, mac_addr_right);
  // assert_non_null(tuple.left_edge);
  // assert_non_null(tuple.right_edge);

  // assert_int_equal(strlen(add_bridge_mock_buf),0);

  // utarray_clear(cmd_arr);

  // assert_int_not_equal(split_string_array("ADD_BRIDGE 1f", CMD_DELIMITER, cmd_arr), -1);  
  // ret = process_add_bridge_cmd(TEST_PROCESS_ADD_BRIDGE_CMD_ONE, client_addr, &context, cmd_arr);
  // assert_int_equal(ret, strlen(FAIL_REPLY));

  // utarray_free(cmd_arr);
  // free_test_context(&context);
// }

// static void test_process_remove_bridge_cmd(void **state)
// {
//   (void) state; /* unused */

//   char *client_addr = "127.0.0.1";
//   uint8_t mac_addr_left[ETH_ALEN];
//   uint8_t mac_addr_right[ETH_ALEN];

//   struct supervisor_context context = {};
//   UT_array *cmd_arr;
//   utarray_new(cmd_arr, &ut_str_icd);

//   hwaddr_aton2("11:22:33:44:55:66", mac_addr_left);
//   hwaddr_aton2("aa:bb:cc:dd:ee:ff", mac_addr_right);

//   init_test_context(&context);

//   assert_int_not_equal(split_string_array("REMOVE_BRIDGE 11:22:33:44:55:66 aa:bb:cc:dd:ee:ff", CMD_DELIMITER, cmd_arr), -1);  
//   ssize_t ret = process_remove_bridge_cmd(TEST_PROCESS_REMOVE_BRIDGE_CMD_ONE, client_addr, &context, cmd_arr);
//   assert_int_equal(ret, strlen(FAIL_REPLY));

//   utarray_clear(cmd_arr);

//   assert_int_not_equal(split_string_array("ADD_BRIDGE 11:22:33:44:55:66 aa:bb:cc:dd:ee:ff", CMD_DELIMITER, cmd_arr), -1);  
//   ret = process_add_bridge_cmd(TEST_PROCESS_ADD_BRIDGE_CMD_ONE, client_addr, &context, cmd_arr);
//   assert_int_equal(ret, strlen(OK_REPLY));

//   utarray_clear(cmd_arr);
//   assert_int_not_equal(split_string_array("REMOVE_BRIDGE 11:22:33:44:55:66 aa:bb:cc:dd:ee:ff", CMD_DELIMITER, cmd_arr), -1);  
//   ret = process_remove_bridge_cmd(TEST_PROCESS_REMOVE_BRIDGE_CMD_ONE, client_addr, &context, cmd_arr);
//   assert_int_equal(ret, strlen(OK_REPLY));

//   utarray_clear(cmd_arr);

//   assert_int_not_equal(split_string_array("SET_IP add 11:22:33:44:55:66 10.0.1.23", CMD_DELIMITER, cmd_arr), -1);  
//   ret = process_set_ip_cmd(TEST_PROCESS_ADD_BRIDGE_CMD_ONE, client_addr, &context, cmd_arr);
//   assert_int_equal(ret, strlen(OK_REPLY));

//   utarray_clear(cmd_arr);

//   assert_int_not_equal(split_string_array("SET_IP add aa:bb:cc:dd:ee:ff 10.0.3.45", CMD_DELIMITER, cmd_arr), -1);  
//   ret = process_set_ip_cmd(TEST_PROCESS_ADD_BRIDGE_CMD_ONE, client_addr, &context, cmd_arr);
//   assert_int_equal(ret, strlen(OK_REPLY));

//   utarray_clear(cmd_arr);

//   assert_int_not_equal(split_string_array("ACCEPT_MAC 11:22:33:44:55:66 1", CMD_DELIMITER, cmd_arr), -1);  
//   ret = process_accept_mac_cmd(TEST_PROCESS_ADD_BRIDGE_CMD_ONE, client_addr, &context, cmd_arr);
//   assert_int_equal(ret, strlen(OK_REPLY));

//   utarray_clear(cmd_arr);

//   assert_int_not_equal(split_string_array("ACCEPT_MAC aa:bb:cc:dd:ee:ff 3", CMD_DELIMITER, cmd_arr), -1);  
//   ret = process_accept_mac_cmd(TEST_PROCESS_ADD_BRIDGE_CMD_ONE, client_addr, &context, cmd_arr);
//   assert_int_equal(ret, strlen(OK_REPLY));

//   utarray_clear(cmd_arr);

//   assert_int_not_equal(split_string_array("ADD_BRIDGE 11:22:33:44:55:66 aa:bb:cc:dd:ee:ff", CMD_DELIMITER, cmd_arr), -1);  
//   ret = process_add_bridge_cmd(TEST_PROCESS_ADD_BRIDGE_CMD_ONE, client_addr, &context, cmd_arr);
//   assert_int_equal(ret, strlen(OK_REPLY));

//   utarray_clear(cmd_arr);

//   assert_int_not_equal(split_string_array("REMOVE_BRIDGE 11:22:33:44:55:66 aa:bb:cc:dd:ee:ff", CMD_DELIMITER, cmd_arr), -1);  
//   ret = process_remove_bridge_cmd(TEST_PROCESS_REMOVE_BRIDGE_CMD_ONE, client_addr, &context, cmd_arr);
//   assert_int_equal(ret, strlen(OK_REPLY));
//   assert_int_equal(strcmp(delete_bridge_mock_buf, "10.0.1.23br110.0.3.45br3"),0);

//   utarray_free(cmd_arr);
//   free_test_context(&context);
// }

// static void test_process_set_ip_cmd(void **state)
// {
//   (void) state; /* unused */

//   char *client_addr = "127.0.0.1";
//   uint8_t mac_addr_left[ETH_ALEN];
//   uint8_t mac_addr_right[ETH_ALEN];

//   struct supervisor_context context = {};
//   struct mac_conn_info info;
//   UT_array *cmd_arr;
//   utarray_new(cmd_arr, &ut_str_icd);

//   hwaddr_aton2("11:22:33:44:55:66", mac_addr_left);
//   hwaddr_aton2("aa:bb:cc:dd:ee:ff", mac_addr_right);

//   init_test_context(&context);

//   assert_int_not_equal(split_string_array("ACCEPT_MAC 11:22:33:44:55:66 1", CMD_DELIMITER, cmd_arr), -1);  
//   ssize_t ret = process_accept_mac_cmd(TEST_PROCESS_SET_IP_CMD_ONE, client_addr, &context, cmd_arr);
//   assert_int_equal(ret, strlen(OK_REPLY));

//   utarray_clear(cmd_arr);

//   assert_int_not_equal(split_string_array("ASSIGN_PSK 11:22:33:44:55:66 12345", CMD_DELIMITER, cmd_arr), -1);
//   ret = process_assign_psk_cmd(TEST_PROCESS_SET_IP_CMD_ONE, client_addr, &context, cmd_arr);
//   assert_int_equal(ret, strlen(OK_REPLY));

//   utarray_clear(cmd_arr);

//   assert_int_not_equal(split_string_array("ADD_NAT 11:22:33:44:55:66", CMD_DELIMITER, cmd_arr), -1);
//   ret = process_add_nat_cmd(TEST_PROCESS_SET_IP_CMD_ONE, client_addr, &context, cmd_arr);
//   assert_int_equal(ret, strlen(OK_REPLY));

//   utarray_clear(cmd_arr);

//   assert_int_not_equal(split_string_array("SET_IP add 11:22:33:44:55:66 10.0.1.23", CMD_DELIMITER, cmd_arr), -1);
//   ret = process_set_ip_cmd(TEST_PROCESS_SET_IP_CMD_ONE, client_addr, &context, cmd_arr);
//   assert_int_equal(ret, strlen(OK_REPLY));
//   get_mac_mapper(&context.mac_mapper, mac_addr_left, &info);
//   assert_int_equal(strcmp(info.ip_addr, "10.0.1.23"), 0);
//   assert_int_equal(strcmp(info.pass, "12345"), 0);
//   assert_true(info.nat);
//   assert_int_equal(strcmp(add_nat_mock_buf, "10.0.1.23br1natif"),0);

//   utarray_clear(cmd_arr);

//   assert_int_not_equal(split_string_array("SET_IP del 11:22:33:44:55:66 10.0.1.23", CMD_DELIMITER, cmd_arr), -1);
//   ret = process_set_ip_cmd(TEST_PROCESS_SET_IP_CMD_ONE, client_addr, &context, cmd_arr);
//   assert_int_equal(ret, strlen(OK_REPLY));
//   get_mac_mapper(&context.mac_mapper, mac_addr_left, &info);
//   assert_int_equal(strlen(info.ip_addr), 0);
//   assert_int_equal(strcmp(info.pass, "12345"), 0);
//   assert_true(info.nat);
//   assert_int_equal(strcmp(delete_nat_mock_buf, "10.0.1.23br1natif"),0);

//   utarray_clear(cmd_arr);
//   memset(add_bridge_mock_buf, 0, 255);

//   assert_int_not_equal(split_string_array("ADD_BRIDGE 11:22:33:44:55:66 aa:bb:cc:dd:ee:ff", CMD_DELIMITER, cmd_arr), -1);  
//   ret = process_add_bridge_cmd(TEST_PROCESS_SET_IP_CMD_ONE, client_addr, &context, cmd_arr);
//   assert_int_equal(ret, strlen(OK_REPLY));
//   assert_int_equal(strlen(add_bridge_mock_buf), 0);

//   utarray_clear(cmd_arr);

//   assert_int_not_equal(split_string_array("SET_IP add aa:bb:cc:dd:ee:ff 10.0.3.45", CMD_DELIMITER, cmd_arr), -1);
//   ret = process_set_ip_cmd(TEST_PROCESS_SET_IP_CMD_ONE, client_addr, &context, cmd_arr);
//   assert_int_equal(ret, strlen(OK_REPLY));
//   get_mac_mapper(&context.mac_mapper, mac_addr_right, &info);
//   assert_int_equal(strcmp(info.ip_addr, "10.0.3.45"), 0);
//   assert_int_equal(info.pass_len, 0);
//   assert_false(info.nat);
//   assert_int_equal(strlen(add_bridge_mock_buf), 0);

//   utarray_clear(cmd_arr);

//   assert_int_not_equal(split_string_array("ACCEPT_MAC aa:bb:cc:dd:ee:ff 3", CMD_DELIMITER, cmd_arr), -1);  
//   ret = process_accept_mac_cmd(TEST_PROCESS_SET_IP_CMD_ONE, client_addr, &context, cmd_arr);
//   assert_int_equal(ret, strlen(OK_REPLY));

//   utarray_clear(cmd_arr);

//   assert_int_not_equal(split_string_array("SET_IP add 11:22:33:44:55:66 10.0.1.23", CMD_DELIMITER, cmd_arr), -1);
//   ret = process_set_ip_cmd(TEST_PROCESS_SET_IP_CMD_ONE, client_addr, &context, cmd_arr);
//   assert_int_equal(ret, strlen(OK_REPLY));
//   get_mac_mapper(&context.mac_mapper, mac_addr_left, &info);
//   assert_int_equal(strcmp(info.ip_addr, "10.0.1.23"), 0);
//   assert_int_equal(strcmp(info.pass, "12345"), 0);
//   assert_true(info.nat);
//   assert_int_equal(strcmp(add_nat_mock_buf, "10.0.1.23br1natif"),0);
//   assert_int_equal(strcmp(add_bridge_mock_buf, "10.0.1.23br110.0.3.45br3"),0);

//   utarray_clear(cmd_arr);

//   memset(add_bridge_mock_buf, 0, 255);
//   memset(delete_bridge_mock_buf, 0, 255);

//   assert_int_not_equal(split_string_array("SET_IP del aa:bb:cc:dd:ee:ff 10.0.3.45", CMD_DELIMITER, cmd_arr), -1);
//   ret = process_set_ip_cmd(TEST_PROCESS_SET_IP_CMD_ONE, client_addr, &context, cmd_arr);
//   assert_int_equal(ret, strlen(OK_REPLY));
//   get_mac_mapper(&context.mac_mapper, mac_addr_right, &info);
//   assert_int_equal(strlen(info.ip_addr), 0);
//   assert_int_equal(strlen(add_bridge_mock_buf), 0);
//   printf("%s\n", delete_bridge_mock_buf);
//   assert_int_equal(strcmp(delete_bridge_mock_buf, "10.0.3.45br310.0.1.23br1"),0);

//   utarray_clear(cmd_arr);

//   split_string_array("SET_IP add 11:22:33:44:55:66 10.0.1.", CMD_DELIMITER, cmd_arr);
//   ret = process_set_ip_cmd(TEST_PROCESS_SET_IP_CMD_ONE, client_addr, &context, cmd_arr);
//   assert_int_equal(ret, strlen(FAIL_REPLY));

//   utarray_clear(cmd_arr);

//   split_string_array("SET_IP add 11:22:33:44:55:66 ", CMD_DELIMITER, cmd_arr);
//   ret = process_set_ip_cmd(TEST_PROCESS_SET_IP_CMD_ONE, client_addr, &context, cmd_arr);
//   assert_int_equal(ret, strlen(FAIL_REPLY));

//   utarray_clear(cmd_arr);

//   split_string_array("SET_IP add 11:22:33: 10.0.1.23", CMD_DELIMITER, cmd_arr);
//   ret = process_set_ip_cmd(TEST_PROCESS_SET_IP_CMD_ONE, client_addr, &context, cmd_arr);
//   assert_int_equal(ret, strlen(FAIL_REPLY));

//   utarray_free(cmd_arr);
//   free_test_context(&context);
// }

// static void test_process_get_all_cmd(void **state)
// {
//   (void) state; /* unused */

//   char *client_addr = "127.0.0.1";
//   uint8_t mac_addr_left[ETH_ALEN];
//   uint8_t mac_addr_right[ETH_ALEN];

//   struct supervisor_context context = {};
//   UT_array *cmd_arr;
//   utarray_new(cmd_arr, &ut_str_icd);

//   hwaddr_aton2("11:22:33:44:55:66", mac_addr_left);
//   hwaddr_aton2("aa:bb:cc:dd:ee:ff", mac_addr_right);

//   init_test_context(&context);

//   ssize_t ret = process_get_all_cmd(TEST_PROCESS_GET_ALL_CMD_ONE, client_addr, &context, NULL);
//   assert_int_equal(ret, strlen(OK_REPLY));

//   assert_int_not_equal(split_string_array("ACCEPT_MAC 11:22:33:44:55:66 1", CMD_DELIMITER, cmd_arr), -1);  
//   ret = process_accept_mac_cmd(TEST_PROCESS_GET_ALL_CMD_ONE, client_addr, &context, cmd_arr);
//   assert_int_equal(ret, strlen(OK_REPLY));

//   utarray_clear(cmd_arr);

//   assert_int_not_equal(split_string_array("ACCEPT_MAC aa:bb:cc:dd:ee:ff 3", CMD_DELIMITER, cmd_arr), -1);  
//   ret = process_accept_mac_cmd(TEST_PROCESS_GET_ALL_CMD_ONE, client_addr, &context, cmd_arr);
//   assert_int_equal(ret, strlen(OK_REPLY));

//   ret = process_get_all_cmd(TEST_PROCESS_GET_ALL_CMD_TWO, client_addr, &context, NULL);
//   assert_int_equal(ret, 0);

//   utarray_clear(cmd_arr);

//   split_string_array("SET_IP add 11:22:33:44:55:66 10.0.1.23", CMD_DELIMITER, cmd_arr);
//   ret = process_set_ip_cmd(TEST_PROCESS_GET_ALL_CMD_ONE, client_addr, &context, cmd_arr);
//   assert_int_equal(ret, strlen(OK_REPLY));

//   utarray_clear(cmd_arr);

//   assert_int_not_equal(split_string_array("DENY_MAC aa:bb:cc:dd:ee:ff", CMD_DELIMITER, cmd_arr), -1);
//   ret = process_deny_mac_cmd(TEST_PROCESS_GET_ALL_CMD_ONE, client_addr, &context, cmd_arr);
//   assert_int_equal(ret, strlen(OK_REPLY));

//   ret = process_get_all_cmd(TEST_PROCESS_GET_ALL_CMD_THREE, client_addr, &context, NULL);
//   assert_int_equal(ret, 0);

//   utarray_free(cmd_arr);
//   free_test_context(&context);
// }

// static void test_process_get_map_cmd(void **state)
// {
//   (void) state; /* unused */

//   char *client_addr = "127.0.0.1";
//   uint8_t mac_addr_left[ETH_ALEN];
//   uint8_t mac_addr_right[ETH_ALEN];

//   struct supervisor_context context = {};
//   UT_array *cmd_arr;
//   utarray_new(cmd_arr, &ut_str_icd);

//   hwaddr_aton2("11:22:33:44:55:66", mac_addr_left);
//   hwaddr_aton2("aa:bb:cc:dd:ee:ff", mac_addr_right);

//   init_test_context(&context);

//   assert_int_not_equal(split_string_array("GET_MAP 11:22:33:44:55:66", CMD_DELIMITER, cmd_arr), -1);  
//   ssize_t ret = process_get_map_cmd(TEST_PROCESS_GET_MAP_CMD_ONE, client_addr, &context, cmd_arr);
//   assert_int_equal(ret, strlen(OK_REPLY));

//   utarray_clear(cmd_arr);

//   assert_int_not_equal(split_string_array("ACCEPT_MAC 11:22:33:44:55:66 1", CMD_DELIMITER, cmd_arr), -1);  
//   ret = process_accept_mac_cmd(TEST_PROCESS_GET_MAP_CMD_ONE, client_addr, &context, cmd_arr);
//   assert_int_equal(ret, strlen(OK_REPLY));

//   utarray_clear(cmd_arr);

//   assert_int_not_equal(split_string_array("GET_MAP 11:22:33:44:55:66", CMD_DELIMITER, cmd_arr), -1);  
//   ret = process_get_map_cmd(TEST_PROCESS_GET_MAP_CMD_TWO, client_addr, &context, cmd_arr);
//   assert_int_equal(ret, 0);

//   utarray_clear(cmd_arr);

//   assert_int_not_equal(split_string_array("ACCEPT_MAC aa:bb:cc:dd:ee:ff 3", CMD_DELIMITER, cmd_arr), -1);  
//   ret = process_accept_mac_cmd(TEST_PROCESS_GET_MAP_CMD_ONE, client_addr, &context, cmd_arr);
//   assert_int_equal(ret, strlen(OK_REPLY));

//   utarray_clear(cmd_arr);

//   assert_int_not_equal(split_string_array("ASSIGN_PSK aa:bb:cc:dd:ee:ff 12345", CMD_DELIMITER, cmd_arr), -1);
//   ret = process_assign_psk_cmd(TEST_PROCESS_GET_MAP_CMD_ONE, client_addr, &context, cmd_arr);
//   assert_int_equal(ret, strlen(OK_REPLY));

//   utarray_clear(cmd_arr);

//   assert_int_not_equal(split_string_array("GET_MAP aa:bb:cc:dd:ee:ff", CMD_DELIMITER, cmd_arr), -1);  
//   ret = process_get_map_cmd(TEST_PROCESS_GET_MAP_CMD_THREE, client_addr, &context, cmd_arr);
//   assert_int_equal(ret, 0);

//   utarray_free(cmd_arr);
//   free_test_context(&context);
// }

// static void test_process_assign_psk_cmd(void **state)
// {
//   (void) state; /* unused */

//   char *client_addr = "127.0.0.1";
//   uint8_t mac_addr[ETH_ALEN];

//   struct supervisor_context context = {};
//   UT_array *cmd_arr;
//   struct mac_conn_info info;
//   utarray_new(cmd_arr, &ut_str_icd);
//   hwaddr_aton2("aa:bb:cc:dd:ee:ff", mac_addr);

//   init_test_context(&context);

//   assert_int_not_equal(split_string_array("ASSIGN_PSK aa:bb:cc:dd:ee:ff ", CMD_DELIMITER, cmd_arr), -1);
//   ssize_t ret = process_assign_psk_cmd(TEST_PROCESS_ASSIGN_PSK_CMD_ONE, client_addr, &context, cmd_arr);
//   assert_int_equal(ret, strlen(FAIL_REPLY));

//   utarray_clear(cmd_arr);

//   assert_int_not_equal(split_string_array("ASSIGN_PSK aa:bb:cc:dd:ee:ff 12345", CMD_DELIMITER, cmd_arr), -1);
//   ret = process_assign_psk_cmd(TEST_PROCESS_ASSIGN_PSK_CMD_ONE, client_addr, &context, cmd_arr);
//   assert_int_equal(ret, strlen(OK_REPLY));
//   get_mac_mapper(&context.mac_mapper, mac_addr, &info);
//   assert_int_equal(strcmp(info.pass, "12345"), 0);
//   utarray_clear(cmd_arr);

//   utarray_free(cmd_arr);
//   free_test_context(&context);
// }

// static void test_process_remove_nat_cmd(void **state)
// {
//   (void) state; /* unused */

//   char *client_addr = "127.0.0.1";
//   uint8_t mac_addr[ETH_ALEN];

//   struct supervisor_context context = {};
//   UT_array *cmd_arr;
//   struct mac_conn_info info;
//   utarray_new(cmd_arr, &ut_str_icd);
//   hwaddr_aton2("aa:bb:cc:dd:ee:ff", mac_addr);

//   init_test_context(&context);

//   assert_int_not_equal(split_string_array("REMOVE_NAT aa:bb:cc:dd:ee:ff", CMD_DELIMITER, cmd_arr), -1);
//   ssize_t ret = process_remove_nat_cmd(TEST_PROCESS_REMOVE_NAT_CMD_ONE, client_addr, &context, cmd_arr);
//   assert_int_equal(ret, strlen(OK_REPLY));
//   get_mac_mapper(&context.mac_mapper, mac_addr, &info);
//   assert_false(info.nat);

//   utarray_clear(cmd_arr);

//   assert_int_not_equal(split_string_array("ADD_NAT aa:bb:cc:dd:ee:ff", CMD_DELIMITER, cmd_arr), -1);
//   ret = process_add_nat_cmd(TEST_PROCESS_REMOVE_NAT_CMD_ONE, client_addr, &context, cmd_arr);
//   assert_int_equal(ret, strlen(OK_REPLY));
//   get_mac_mapper(&context.mac_mapper, mac_addr, &info);
//   assert_true(info.nat);

//   utarray_clear(cmd_arr);

//   assert_int_not_equal(split_string_array("REMOVE_NAT aa:bb:cc:dd:ee:ff", CMD_DELIMITER, cmd_arr), -1);
//   ret = process_remove_nat_cmd(TEST_PROCESS_REMOVE_NAT_CMD_ONE, client_addr, &context, cmd_arr);
//   assert_int_equal(ret, strlen(OK_REPLY));
//   get_mac_mapper(&context.mac_mapper, mac_addr, &info);
//   assert_false(info.nat);

//   utarray_free(cmd_arr);
//   free_test_context(&context);
// }

// static void test_process_add_nat_cmd(void **state)
// {
//   (void) state; /* unused */

//   char *client_addr = "127.0.0.1";
//   uint8_t mac_addr[ETH_ALEN];

//   struct supervisor_context context = {};
//   UT_array *cmd_arr;
//   struct mac_conn_info info;
//   utarray_new(cmd_arr, &ut_str_icd);
//   hwaddr_aton2("aa:bb:cc:dd:ee:ff", mac_addr);

//   init_test_context(&context);

//   assert_int_not_equal(split_string_array("ACCEPT_MAC aa:bb:cc:dd:ee:ff 3", CMD_DELIMITER, cmd_arr), -1);  
//   ssize_t ret = process_accept_mac_cmd(TEST_PROCESS_ADD_NAT_CMD_ONE, client_addr, &context, cmd_arr);
//   assert_int_equal(ret, strlen(OK_REPLY));
//   get_mac_mapper(&context.mac_mapper, mac_addr, &info);
//   assert_false(info.nat);

//   utarray_clear(cmd_arr);

//   assert_int_not_equal(split_string_array("ADD_NAT aa:bb:cc:dd:ee:ff", CMD_DELIMITER, cmd_arr), -1);
//   ret = process_add_nat_cmd(TEST_PROCESS_ADD_NAT_CMD_ONE, client_addr, &context, cmd_arr);
//   assert_int_equal(ret, strlen(OK_REPLY));
//   get_mac_mapper(&context.mac_mapper, mac_addr, &info);
//   assert_true(info.nat);

//   utarray_free(cmd_arr);
//   free_test_context(&context);
// }

// static void test_process_deny_mac_cmd(void **state)
// {
//   (void) state; /* unused */

//   char *client_addr = "127.0.0.1";
//   uint8_t mac_addr[ETH_ALEN];

//   struct supervisor_context context = {};
//   UT_array *cmd_arr;
//   struct mac_conn_info info;
//   utarray_new(cmd_arr, &ut_str_icd);
//   hwaddr_aton2("aa:bb:cc:dd:ee:ff", mac_addr);

//   init_test_context(&context);

//   assert_int_not_equal(split_string_array("ACCEPT_MAC aa:bb:cc:dd:ee:ff 3", CMD_DELIMITER, cmd_arr), -1);  
//   ssize_t ret = process_accept_mac_cmd(TEST_PROCESS_DENY_MAC_CMD_ONE, client_addr, &context, cmd_arr);
//   assert_int_equal(ret, strlen(OK_REPLY));
//   get_mac_mapper(&context.mac_mapper, mac_addr, &info);
//   assert_true(info.allow_connection);

//   utarray_clear(cmd_arr);

//   assert_int_not_equal(split_string_array("DENY_MAC aa:bb:cc:dd:ee:ff", CMD_DELIMITER, cmd_arr), -1);  
//   ret = process_deny_mac_cmd(TEST_PROCESS_DENY_MAC_CMD_ONE, client_addr, &context, cmd_arr);
//   assert_int_equal(ret, strlen(OK_REPLY));
//   get_mac_mapper(&context.mac_mapper, mac_addr, &info);
//   assert_false(info.allow_connection);

//   utarray_free(cmd_arr);
//   free_test_context(&context);
// }

// static void test_process_get_bridges_cmd(void ** state)
// {
//   char *client_addr = "127.0.0.1";

//   struct supervisor_context context = {};
//   UT_array *cmd_arr;
//   utarray_new(cmd_arr, &ut_str_icd);

//   init_test_context(&context);

//   assert_int_not_equal(split_string_array("GET_BRIDGES", CMD_DELIMITER, cmd_arr), -1);  
//   ssize_t ret = process_get_bridges_cmd(TEST_PROCESS_GET_BRIDGES_CMD_ONE, client_addr, &context, NULL);
//   assert_int_equal(ret, strlen(OK_REPLY));

//   utarray_clear(cmd_arr);

//   assert_int_not_equal(split_string_array("ADD_BRIDGE 11:22:33:44:55:66 aa:bb:cc:dd:ee:ff", CMD_DELIMITER, cmd_arr), -1);  
//   ret = process_add_bridge_cmd(TEST_PROCESS_GET_BRIDGES_CMD_ONE, client_addr, &context, cmd_arr);
//   assert_int_equal(ret, strlen(OK_REPLY));

//   utarray_clear(cmd_arr);

//   assert_int_not_equal(split_string_array("GET_BRIDGES", CMD_DELIMITER, cmd_arr), -1);  
//   ret = process_get_bridges_cmd(TEST_PROCESS_GET_BRIDGES_CMD_TWO, client_addr, &context, NULL);
//   assert_int_equal(ret, 0);

//   utarray_clear(cmd_arr);

//   assert_int_not_equal(split_string_array("ADD_BRIDGE aa:bb:cc:dd:ee:ff ff:00:ff:00:ff:00", CMD_DELIMITER, cmd_arr), -1);  
//   ret = process_add_bridge_cmd(TEST_PROCESS_GET_BRIDGES_CMD_ONE, client_addr, &context, cmd_arr);
//   assert_int_equal(ret, strlen(OK_REPLY));

//   utarray_clear(cmd_arr);

//   assert_int_not_equal(split_string_array("GET_BRIDGES", CMD_DELIMITER, cmd_arr), -1);  
//   ret = process_get_bridges_cmd(TEST_PROCESS_GET_BRIDGES_CMD_THREE, client_addr, &context, NULL);
//   assert_int_equal(ret, 0);


//   utarray_free(cmd_arr);
//   free_test_context(&context);
// }

int main(int argc, char *argv[])
{  
  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_process_domain_buffer),
    cmocka_unit_test(test_process_accept_mac_cmd),
    cmocka_unit_test(test_process_deny_mac_cmd),
    cmocka_unit_test(test_process_add_nat_cmd),
    cmocka_unit_test(test_process_remove_nat_cmd),
    // cmocka_unit_test(test_process_add_bridge_cmd),
    // cmocka_unit_test(test_process_remove_bridge_cmd),
    // cmocka_unit_test(test_process_set_ip_cmd),
    // cmocka_unit_test(test_process_get_all_cmd),
    // cmocka_unit_test(test_process_get_map_cmd),
    // cmocka_unit_test(test_process_assign_psk_cmd),
    // cmocka_unit_test(test_process_get_bridges_cmd)
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
