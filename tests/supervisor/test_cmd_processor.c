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
#include "supervisor/system_commands.h"

#include "utils/hashmap.h"
#include "utils/utarray.h"
#include "utils/log.h"
#include "utils/iptables.h"
#include "engine.h"

#define CMD_DELIMITER 0x20

ssize_t __wrap_write_domain_data(int sock, char *data, size_t data_len, struct sockaddr_un *addr, int addr_len)
{
  (void) sock;
  (void) data;
  (void) addr;
  (void) addr_len;

  return data_len;
}

int __wrap_subscribe_events_cmd(struct supervisor_context *context, struct client_address *addr)
{
  (void) context;

  check_expected(addr);

  return 0;
}

int __wrap_accept_mac_cmd(struct supervisor_context *context, uint8_t *mac_addr, int vlanid)
{
  (void) context;

  check_expected(mac_addr);
  check_expected(vlanid);

  return 0;
}

int __wrap_deny_mac_cmd(struct supervisor_context *context, uint8_t *mac_addr)
{
  (void) context;

  check_expected(mac_addr);

  return 0;
}

int __wrap_add_nat_cmd(struct supervisor_context *context, uint8_t *mac_addr)
{
  (void) context;

  check_expected(mac_addr);

  return 0;
}

int __wrap_remove_nat_cmd(struct supervisor_context *context, uint8_t *mac_addr)
{
  (void) context;

  check_expected(mac_addr);

  return 0;
}

int __wrap_assign_psk_cmd(struct supervisor_context *context, uint8_t *mac_addr, char *pass, int pass_len)
{
  (void) context;

  check_expected(mac_addr);
  check_expected(pass);
  check_expected(pass_len);

  return 0;
}

int __wrap_set_ip_cmd(struct supervisor_context *context, uint8_t *mac_addr, char *ip_addr, enum DHCP_IP_TYPE ip_type)
{
  (void) context;

  check_expected(mac_addr);
  check_expected(ip_addr);
  check_expected(ip_type);

  return 0;
}

int __wrap_add_bridge_mac_cmd(struct supervisor_context *context, uint8_t *left_mac_addr, uint8_t *right_mac_addr)
{
  (void) context;

  check_expected(left_mac_addr);
  check_expected(right_mac_addr);

  return 0;
}

int __wrap_add_bridge_ip_cmd(struct supervisor_context *context, char *left_ip_addr, char *right_ip_addr)
{
  (void) context;

  check_expected(left_ip_addr);
  check_expected(right_ip_addr);

  return 0;
}

int __wrap_remove_bridge_cmd(struct supervisor_context *context, uint8_t *left_mac_addr, uint8_t *right_mac_addr)
{
  (void) context;

  check_expected(left_mac_addr);
  check_expected(right_mac_addr);

  return 0;
}

int __wrap_clear_bridges_cmd(struct supervisor_context *context, uint8_t *mac_addr)
{
  (void) context;

  check_expected(mac_addr);

  return 0;
}

int __wrap_set_fingerprint_cmd(struct supervisor_context *context, char *src_mac_addr,
                        char *dst_mac_addr, char *protocol, char *fingerprint,
                        uint64_t timestamp, char *query)
{
  (void) context;

  check_expected(src_mac_addr);
  check_expected(dst_mac_addr);
  check_expected(protocol);
  check_expected(fingerprint);
  check_expected(timestamp);
  check_expected(query);

  return 0;
}

ssize_t __wrap_query_fingerprint_cmd(struct supervisor_context *context, char *mac_addr, uint64_t timestamp,
                        char *op, char *protocol, char **out)
{
  (void) context;

  check_expected(mac_addr);
  check_expected(timestamp);
  check_expected(op);
  check_expected(protocol);
  *out = os_malloc(sizeof(char));

  return strlen(OK_REPLY);
}

uint8_t* __wrap_register_ticket_cmd(struct supervisor_context *context, uint8_t *mac_addr, char *label,
                        int vlanid)
{
  (void) context;

  check_expected(mac_addr);
  check_expected(label);
  check_expected(vlanid);

  return (uint8_t *)OK_REPLY;
}

int __wrap_clear_psk_cmd(struct supervisor_context *context, uint8_t *mac_addr)
{
  (void) context;

  check_expected(mac_addr);

  return 0;
}

int __wrap_put_crypt_cmd(struct supervisor_context *context, char *key, char *value)
{
  (void) context;

  check_expected(key);
  check_expected(value);

  return 0;
}

int __wrap_get_crypt_cmd(struct supervisor_context *context, char *key, char **value)
{
  (void) context;

  check_expected(key);
  *value = os_strdup(OK_REPLY);

  return 0;
}

int __wrap_gen_randkey_cmd(struct supervisor_context *context, char *keyid, int size)
{
  (void) context;

  check_expected(keyid);
  check_expected(size);

  return 0;
}

int __wrap_gen_privkey_cmd(struct supervisor_context *context, char *keyid, int size)
{
  (void) context;

  check_expected(keyid);
  check_expected(size);

  return 0;
}

int __wrap_gen_pubkey_cmd(struct supervisor_context *context, char *pubid, char *keyid)
{
  (void) context;

  check_expected(pubid);
  check_expected(keyid);

  return 0;
}

int __wrap_gen_cert_cmd(struct supervisor_context *context, char *certid, char *keyid,
                        struct certificate_meta *meta)
{
  (void) context;

  check_expected(certid);
  check_expected(keyid);
  check_expected(meta);

  return 0;
}

char* __wrap_encrypt_blob_cmd(struct supervisor_context *context, char *keyid, char *ivid, char *blob)
{
  (void) context;

  check_expected(keyid);
  check_expected(ivid);
  check_expected(blob);

  return os_strdup(OK_REPLY);
}

char* __wrap_decrypt_blob_cmd(struct supervisor_context *context, char *keyid, char *ivid, char *blob)
{
  (void) context;

  check_expected(keyid);
  check_expected(ivid);
  check_expected(blob);

  return os_strdup(OK_REPLY);
}

char* __wrap_sign_blob_cmd(struct supervisor_context *context, char *keyid, char *blob)
{
  (void) context;

  check_expected(keyid);
  check_expected(blob);

  return os_strdup(OK_REPLY);
}

int __wrap_get_mac_mapper(hmap_mac_conn **hmap, uint8_t mac_addr[ETH_ALEN], struct mac_conn_info *info)
{
  (void) hmap;

  check_expected(mac_addr);
  check_expected(info);

  return 1;
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

static void test_process_subscribe_events_cmd(void **state)
{
  (void) state; /* unused */

  UT_array *cmd_arr;
  struct client_address claddr;

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("SUBSCRIBE_EVENTS", CMD_DELIMITER, cmd_arr), -1); 
  expect_any(__wrap_subscribe_events_cmd, addr);
  assert_int_equal(process_subscribe_events_cmd(0, &claddr, NULL, cmd_arr), strlen(OK_REPLY));
  utarray_free(cmd_arr);
}

static void test_process_accept_mac_cmd(void **state)
{
  (void) state; /* unused */
  uint8_t addr[ETH_ALEN] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
  UT_array *cmd_arr;
  struct client_address claddr;

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("ACCEPT_MAC aa:bb:cc:dd:ee:ff 3", CMD_DELIMITER, cmd_arr), -1); 
  expect_memory(__wrap_accept_mac_cmd, mac_addr, addr, ETH_ALEN);
  expect_value(__wrap_accept_mac_cmd, vlanid, 3);
  assert_int_equal(process_accept_mac_cmd(0, &claddr, NULL, cmd_arr), strlen(OK_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("ACCEPT_MAC aa:bb:cc:dd:ee: 3", CMD_DELIMITER, cmd_arr), -1); 
  assert_int_equal(process_accept_mac_cmd(0, &claddr, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("ACCEPT_MAC aa:bb:cc:dd:ee:ff", CMD_DELIMITER, cmd_arr), -1); 
  assert_int_equal(process_accept_mac_cmd(0, &claddr, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);
}

static void test_process_deny_mac_cmd(void **state)
{
  (void) state; /* unused */
  uint8_t addr[ETH_ALEN] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
  UT_array *cmd_arr;
  struct client_address claddr;

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("DENY_MAC aa:bb:cc:dd:ee:ff", CMD_DELIMITER, cmd_arr), -1); 
  expect_memory(__wrap_deny_mac_cmd, mac_addr, addr, ETH_ALEN);
  assert_int_equal(process_deny_mac_cmd(0, &claddr, NULL, cmd_arr), strlen(OK_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("DENY_MAC aa:bb:cc:dd:ee:", CMD_DELIMITER, cmd_arr), -1); 
  assert_int_equal(process_deny_mac_cmd(0, &claddr, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);
}

static void test_process_add_nat_cmd(void **state)
{
  (void) state; /* unused */
  uint8_t addr[ETH_ALEN] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
  UT_array *cmd_arr;
  struct client_address claddr;

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("ADD_NAT aa:bb:cc:dd:ee:ff", CMD_DELIMITER, cmd_arr), -1); 
  expect_memory(__wrap_add_nat_cmd, mac_addr, addr, ETH_ALEN);
  assert_int_equal(process_add_nat_cmd(0, &claddr, NULL, cmd_arr), strlen(OK_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("ADD_NAT aa:bb:cc:dd:ee:", CMD_DELIMITER, cmd_arr), -1); 
  assert_int_equal(process_add_nat_cmd(0, &claddr, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);
}

static void test_process_remove_nat_cmd(void **state)
{
  (void) state; /* unused */
  uint8_t addr[ETH_ALEN] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
  UT_array *cmd_arr;
  struct client_address claddr;

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("REMOVE_NAT aa:bb:cc:dd:ee:ff", CMD_DELIMITER, cmd_arr), -1); 
  expect_memory(__wrap_remove_nat_cmd, mac_addr, addr, ETH_ALEN);
  assert_int_equal(process_remove_nat_cmd(0, &claddr, NULL, cmd_arr), strlen(OK_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("REMOVE_NAT aa:bb:cc:dd:ee:", CMD_DELIMITER, cmd_arr), -1); 
  assert_int_equal(process_remove_nat_cmd(0, &claddr, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);
}

static void test_process_assign_psk_cmd(void **state)
{
  (void) state; /* unused */

  uint8_t addr[ETH_ALEN] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
  uint8_t password[5] = {0x31, 0x32, 0x33, 0x34, 0x35};
  UT_array *cmd_arr;
  struct client_address claddr;

  utarray_new(cmd_arr, &ut_str_icd);

  assert_int_not_equal(split_string_array("ASSIGN_PSK 11:22:33:44:55:66 12345", CMD_DELIMITER, cmd_arr), -1);
  expect_memory(__wrap_assign_psk_cmd, mac_addr, addr, ETH_ALEN);
  expect_memory(__wrap_assign_psk_cmd, pass, password, 5);
  expect_value(__wrap_assign_psk_cmd, pass_len, 5);

  assert_int_equal(process_assign_psk_cmd(0, &claddr, NULL, cmd_arr), strlen(OK_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("ASSIGN_PSK 11:22:33:44:55: 12345", CMD_DELIMITER, cmd_arr), -1); 
  assert_int_equal(process_assign_psk_cmd(0, &claddr, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("ASSIGN_PSK 11:22:33:44:55:66", CMD_DELIMITER, cmd_arr), -1); 
  assert_int_equal(process_assign_psk_cmd(0, &claddr, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("ASSIGN_PSK 11:22:33:44:55:66 ", CMD_DELIMITER, cmd_arr), -1); 
  assert_int_equal(process_assign_psk_cmd(0, &claddr, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("ASSIGN_PSK 11:22:33:44:55: 12345", CMD_DELIMITER, cmd_arr), -1); 
  assert_int_equal(process_assign_psk_cmd(0, &claddr, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);
}


static void test_process_get_map_cmd(void **state)
{
  (void) state; /* unused */
  uint8_t addr[ETH_ALEN] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
  UT_array *cmd_arr;
  struct client_address claddr;
  struct supervisor_context context;
  os_memset(&context, 0, sizeof(struct supervisor_context));

  utarray_new(cmd_arr, &ut_str_icd);

  assert_int_not_equal(split_string_array("GET_MAP 11:22:33:44:55:66", CMD_DELIMITER, cmd_arr), -1);
  expect_memory(__wrap_get_mac_mapper, mac_addr, addr, ETH_ALEN);
  expect_any(__wrap_get_mac_mapper, info);

  int ret = process_get_map_cmd(0, &claddr, &context, cmd_arr);
  bool comp = ret > (int) (STRLEN("11:22:33:44:55:66"));
  assert_true(comp);
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("GET_MAP 11:22:33:44:55:", CMD_DELIMITER, cmd_arr), -1);
  assert_int_equal(process_get_map_cmd(0, &claddr, &context, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);
}

static void test_process_get_all_cmd(void **state)
{
  (void) state; /* unused */

  struct supervisor_context ctx;
  uint8_t addr1[ETH_ALEN] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
  uint8_t addr2[ETH_ALEN] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60};
  struct mac_conn p;
  UT_array *cmd_arr;
  struct client_address claddr;

  utarray_new(cmd_arr, &ut_str_icd);

  os_memset(&ctx, 0, sizeof(struct supervisor_context));

  assert_int_not_equal(split_string_array("GET_ALL", CMD_DELIMITER, cmd_arr), -1);
  assert_int_equal(process_get_all_cmd(0, &claddr, &ctx, cmd_arr), strlen(OK_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);

  assert_int_not_equal(split_string_array("GET_ALL", CMD_DELIMITER, cmd_arr), -1);
  os_memset(&p, 0, sizeof(struct mac_conn));
  os_memcpy(p.mac_addr, addr1, ETH_ALEN);
  put_mac_mapper(&(ctx.mac_mapper), p);

  os_memset(&p, 0, sizeof(struct mac_conn));
  os_memcpy(p.mac_addr, addr2, ETH_ALEN);
  put_mac_mapper(&(ctx.mac_mapper), p);

  int ret = process_get_all_cmd(0,&claddr, &ctx, cmd_arr);
  bool comp = ret > (int) (2 * STRLEN("11:22:33:44:55:66"));
  assert_true(comp);
  utarray_free(cmd_arr);
  free_mac_mapper(&(ctx.mac_mapper));
}

static void test_process_set_ip_cmd(void **state)
{
  (void) state; /* unused */

  uint8_t addr[ETH_ALEN] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
  char *ip = "10.0.1.23";
  UT_array *cmd_arr;
  struct client_address claddr;

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("SET_IP add 11:22:33:44:55:66 10.0.1.23", CMD_DELIMITER, cmd_arr), -1);
  expect_memory(__wrap_set_ip_cmd, mac_addr, addr, ETH_ALEN);
  expect_string(__wrap_set_ip_cmd, ip_addr, ip);
  expect_value(__wrap_set_ip_cmd, ip_type, DHCP_IP_NEW);
  assert_int_equal(process_set_ip_cmd(0, &claddr, NULL, cmd_arr), strlen(OK_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("SET_IP old 11:22:33:44:55:66 10.0.1.23", CMD_DELIMITER, cmd_arr), -1);
  expect_memory(__wrap_set_ip_cmd, mac_addr, addr, ETH_ALEN);
  expect_string(__wrap_set_ip_cmd, ip_addr, ip);
  expect_value(__wrap_set_ip_cmd, ip_type, DHCP_IP_OLD);  
  assert_int_equal(process_set_ip_cmd(0, &claddr, NULL, cmd_arr), strlen(OK_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("SET_IP del 11:22:33:44:55:66 10.0.1.23", CMD_DELIMITER, cmd_arr), -1);
  expect_memory(__wrap_set_ip_cmd, mac_addr, addr, ETH_ALEN);
  expect_string(__wrap_set_ip_cmd, ip_addr, ip);
  expect_value(__wrap_set_ip_cmd, ip_type, DHCP_IP_DEL);
  assert_int_equal(process_set_ip_cmd(0, &claddr, NULL, cmd_arr), strlen(OK_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("SET_IP 11:22:33:44:55:66 10.0.1.23", CMD_DELIMITER, cmd_arr), -1);
  assert_int_equal(process_set_ip_cmd(0, &claddr, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("SET_IP old 11:22:33:44:55: 10.0.1.23", CMD_DELIMITER, cmd_arr), -1);
  assert_int_equal(process_set_ip_cmd(0, &claddr, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("SET_IP old 11:22:33:44:55:65 a.0.1.23", CMD_DELIMITER, cmd_arr), -1);
  assert_int_equal(process_set_ip_cmd(0, &claddr, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);

}

static void test_process_add_bridge_cmd(void **state)
{
  (void) state; /* unused */

  uint8_t addr1[ETH_ALEN] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
  uint8_t addr2[ETH_ALEN] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
  UT_array *cmd_arr;
  struct client_address claddr;

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("ADD_BRIDGE 11:22:33:44:55:66 aa:bb:cc:dd:ee:ff", CMD_DELIMITER, cmd_arr), -1);
  expect_memory(__wrap_add_bridge_mac_cmd, left_mac_addr, addr1, ETH_ALEN);
  expect_memory(__wrap_add_bridge_mac_cmd, right_mac_addr, addr2, ETH_ALEN);
  assert_int_equal(process_add_bridge_cmd(0, &claddr, NULL, cmd_arr), strlen(OK_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("ADD_BRIDGE 11:22:33:44:55: aa:bb:cc:dd:ee:ff", CMD_DELIMITER, cmd_arr), -1);
  assert_int_equal(process_add_bridge_cmd(0, &claddr, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("ADD_BRIDGE 11:22:33:44:55:66 10.0.1.2", CMD_DELIMITER, cmd_arr), -1);
  assert_int_equal(process_add_bridge_cmd(0, &claddr, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("ADD_BRIDGE 11:22:33:44:55:66 aa:bb:cc:dd:ee:", CMD_DELIMITER, cmd_arr), -1);
  assert_int_equal(process_add_bridge_cmd(0, &claddr, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("ADD_BRIDGE 10.0.1.2 11:22:33:44:55:66", CMD_DELIMITER, cmd_arr), -1);
  assert_int_equal(process_add_bridge_cmd(0, &claddr, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("ADD_BRIDGE", CMD_DELIMITER, cmd_arr), -1);
  assert_int_equal(process_add_bridge_cmd(0, &claddr, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("ADD_BRIDGE 10.0.1.2 10.0.3.2", CMD_DELIMITER, cmd_arr), -1);
  expect_string(__wrap_add_bridge_ip_cmd, left_ip_addr, "10.0.1.2");
  expect_string(__wrap_add_bridge_ip_cmd, right_ip_addr, "10.0.3.2");
  assert_int_equal(process_add_bridge_cmd(0, &claddr, NULL, cmd_arr), strlen(OK_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("ADD_BRIDGE 10.0.1.2 10.0.3.", CMD_DELIMITER, cmd_arr), -1);
  assert_int_equal(process_add_bridge_cmd(0, &claddr, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("ADD_BRIDGE 10.0.1. 10.0.3.1", CMD_DELIMITER, cmd_arr), -1);
  assert_int_equal(process_add_bridge_cmd(0, &claddr, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);
}

static void test_process_remove_bridge_cmd(void **state)
{
  (void) state; /* unused */

  uint8_t addr1[ETH_ALEN] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
  uint8_t addr2[ETH_ALEN] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
  UT_array *cmd_arr;
  struct client_address claddr;

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("REMOVE_BRIDGE 11:22:33:44:55:66 aa:bb:cc:dd:ee:ff", CMD_DELIMITER, cmd_arr), -1);
  expect_memory(__wrap_remove_bridge_cmd, left_mac_addr, addr1, ETH_ALEN);
  expect_memory(__wrap_remove_bridge_cmd, right_mac_addr, addr2, ETH_ALEN);
  assert_int_equal(process_remove_bridge_cmd(0, &claddr, NULL, cmd_arr), strlen(OK_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("REMOVE_BRIDGE 11:22:33:44:55: aa:bb:cc:dd:ee:ff", CMD_DELIMITER, cmd_arr), -1);
  assert_int_equal(process_remove_bridge_cmd(0, &claddr, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("REMOVE_BRIDGE 11:22:33:44:55:66 aa:bb:cc:dd:ee:", CMD_DELIMITER, cmd_arr), -1);
  assert_int_equal(process_remove_bridge_cmd(0, &claddr, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("REMOVE_BRIDGE", CMD_DELIMITER, cmd_arr), -1);
  assert_int_equal(process_remove_bridge_cmd(0, &claddr, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);
}

static void test_process_clear_bridges_cmd(void **state)
{
  (void) state; /* unused */

  uint8_t addr1[ETH_ALEN] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
  UT_array *cmd_arr;
  struct client_address claddr;

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("CLEAR_BRIDGES 11:22:33:44:55:66", CMD_DELIMITER, cmd_arr), -1);
  expect_memory(__wrap_clear_bridges_cmd, mac_addr, addr1, ETH_ALEN);
  assert_int_equal(process_clear_bridges_cmd(0, &claddr, NULL, cmd_arr), strlen(OK_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("CLEAR_BRIDGES 11:22:33:44:55:", CMD_DELIMITER, cmd_arr), -1);
  assert_int_equal(process_clear_bridges_cmd(0, &claddr, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("CLEAR_BRIDGES", CMD_DELIMITER, cmd_arr), -1);
  assert_int_equal(process_clear_bridges_cmd(0, &claddr, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);
}

static void test_process_set_fingerprint_cmd(void **state)
{
  (void) state; /* unused */

  UT_array *cmd_arr;
  struct client_address claddr;

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("SET_FINGERPRINT 11:22:33:44:55:66 aa:bb:cc:dd:ee:ff IP 12345 test", CMD_DELIMITER, cmd_arr), -1);
  expect_string(__wrap_set_fingerprint_cmd, src_mac_addr, "11:22:33:44:55:66");
  expect_string(__wrap_set_fingerprint_cmd, dst_mac_addr, "aa:bb:cc:dd:ee:ff");
  expect_string(__wrap_set_fingerprint_cmd, protocol, "IP");
  expect_string(__wrap_set_fingerprint_cmd, fingerprint, "12345");
  expect_any(__wrap_set_fingerprint_cmd, timestamp);
  expect_string(__wrap_set_fingerprint_cmd, query, "test");
  assert_int_equal(process_set_fingerprint_cmd(0, &claddr, NULL, cmd_arr), strlen(OK_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("SET_FINGERPRINT 11:22:33:44:55: aa:bb:cc:dd:ee:ff IP 12345 test", CMD_DELIMITER, cmd_arr), -1);
  assert_int_equal(process_set_fingerprint_cmd(0, &claddr, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("SET_FINGERPRINT 11:22:33:44:55:66 aa:bb:cc:dd:ee: IP 12345 test", CMD_DELIMITER, cmd_arr), -1);
  assert_int_equal(process_set_fingerprint_cmd(0, &claddr, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("SET_FINGERPRINT 11:22:33:44:55:66 aa:bb:cc:dd:ee:ff 12345 test", CMD_DELIMITER, cmd_arr), -1);
  assert_int_equal(process_set_fingerprint_cmd(0, &claddr, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("SET_FINGERPRINT 11:22:33:44:55:66 aa:bb:cc:dd:ee:ff IP ", CMD_DELIMITER, cmd_arr), -1);
  assert_int_equal(process_set_fingerprint_cmd(0, &claddr, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);
}

static void test_process_query_fingerprint_cmd(void **state)
{
  (void) state; /* unused */

  UT_array *cmd_arr;
  struct client_address claddr;

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("QUERY_FINGERPRINT 11:22:33:44:55:66 12345 >= IP4", CMD_DELIMITER, cmd_arr), -1);
  expect_string(__wrap_query_fingerprint_cmd, mac_addr, "11:22:33:44:55:66");
  expect_value(__wrap_query_fingerprint_cmd, timestamp, 12345);
  expect_string(__wrap_query_fingerprint_cmd, op, ">=");
  expect_string(__wrap_query_fingerprint_cmd, protocol, "IP4");
  assert_int_equal(process_query_fingerprint_cmd(0, &claddr, NULL, cmd_arr), strlen(OK_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("QUERY_FINGERPRINT 11:22:33:44:55: 12345 >= IP4", CMD_DELIMITER, cmd_arr), -1);
  assert_int_equal(process_query_fingerprint_cmd(0, &claddr, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("QUERY_FINGERPRINT 11:22:33:44:55:66 a12345 >= IP4", CMD_DELIMITER, cmd_arr), -1);
  assert_int_equal(process_query_fingerprint_cmd(0, &claddr, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("QUERY_FINGERPRINT 11:22:33:44:55:66 12345 >== IP4", CMD_DELIMITER, cmd_arr), -1);
  assert_int_equal(process_query_fingerprint_cmd(0, &claddr, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("QUERY_FINGERPRINT 11:22:33:44:55:66 12345 >= 1234567812345678123456781234567812345678123456781234567812345678", CMD_DELIMITER, cmd_arr), -1);
  assert_int_equal(process_query_fingerprint_cmd(0, &claddr, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);
}

static void test_process_register_ticket_cmd(void **state)
{
  (void) state; /* unused */

  uint8_t addr[ETH_ALEN] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
  UT_array *cmd_arr;
  struct client_address claddr;

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("REGISTER_TICKET 11:22:33:44:55:66 test 23", CMD_DELIMITER, cmd_arr), -1);
  expect_memory(__wrap_register_ticket_cmd, mac_addr, addr, ETH_ALEN);
  expect_string(__wrap_register_ticket_cmd, label, "test");
  expect_value(__wrap_register_ticket_cmd, vlanid, 23);
  assert_int_equal(process_register_ticket_cmd(0, &claddr, NULL, cmd_arr), strlen(OK_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("REGISTER_TICKET 11:22:33:44:55: test 23", CMD_DELIMITER, cmd_arr), -1);
  assert_int_equal(process_register_ticket_cmd(0, &claddr, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("REGISTER_TICKET 11:22:33:44:55:66 23", CMD_DELIMITER, cmd_arr), -1);
  assert_int_equal(process_register_ticket_cmd(0, &claddr, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("REGISTER_TICKET 11:22:33:44:55:66 test 23f", CMD_DELIMITER, cmd_arr), -1);
  assert_int_equal(process_register_ticket_cmd(0, &claddr, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);
}

static void test_process_clear_psk_cmd(void **state)
{
  (void) state; /* unused */

  uint8_t addr[ETH_ALEN] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
  UT_array *cmd_arr;
  struct client_address claddr;

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("CLEAR_PSK 11:22:33:44:55:66", CMD_DELIMITER, cmd_arr), -1);
  expect_memory(__wrap_clear_psk_cmd, mac_addr, addr, ETH_ALEN);
  assert_int_equal(process_clear_psk_cmd(0, &claddr, NULL, cmd_arr), strlen(OK_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("CLEAR_PSK 11:22:33:44:55:", CMD_DELIMITER, cmd_arr), -1);
  assert_int_equal(process_clear_psk_cmd(0, &claddr, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);
}

static void test_process_put_crypt_cmd(void **state)
{
  (void) state; /* unused */

  UT_array *cmd_arr;
  struct client_address claddr;

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("PUT_CRYPT 12345 54321", CMD_DELIMITER, cmd_arr), -1);
  expect_string(__wrap_put_crypt_cmd, key, "12345");
  expect_string(__wrap_put_crypt_cmd, value, "54321");
  assert_int_equal(process_put_crypt_cmd(0, &claddr, NULL, cmd_arr), strlen(OK_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("PUT_CRYPT 12345 ", CMD_DELIMITER, cmd_arr), -1);
  assert_int_equal(process_put_crypt_cmd(0, &claddr, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("PUT_CRYPT ", CMD_DELIMITER, cmd_arr), -1);
  assert_int_equal(process_put_crypt_cmd(0, &claddr, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);
}

static void test_process_get_crypt_cmd(void **state)
{
  (void) state; /* unused */

  UT_array *cmd_arr;
  struct client_address claddr;

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("GET_CRYPT 12345", CMD_DELIMITER, cmd_arr), -1);
  expect_string(__wrap_get_crypt_cmd, key, "12345");
  assert_int_equal(process_get_crypt_cmd(0, &claddr, NULL, cmd_arr), strlen(OK_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("GET_CRYPT ", CMD_DELIMITER, cmd_arr), -1);
  assert_int_equal(process_get_crypt_cmd(0, &claddr, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);
}

static void test_process_gen_randkey_cmd(void **state)
{
  (void) state; /* unused */

  UT_array *cmd_arr;
  struct client_address claddr;

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("GEN_RANDKEY test 32", CMD_DELIMITER, cmd_arr), -1);
  expect_string(__wrap_gen_randkey_cmd, keyid, "test");
  expect_value(__wrap_gen_randkey_cmd, size, 32);
  assert_int_equal(process_gen_randkey_cmd(0, &claddr, NULL, cmd_arr), strlen(OK_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("GEN_RANDKEY ", CMD_DELIMITER, cmd_arr), -1);
  assert_int_equal(process_gen_randkey_cmd(0, &claddr, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("GEN_RANDKEY test ", CMD_DELIMITER, cmd_arr), -1);
  assert_int_equal(process_gen_randkey_cmd(0, &claddr, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("GEN_RANDKEY test 32a", CMD_DELIMITER, cmd_arr), -1);
  assert_int_equal(process_gen_randkey_cmd(0, &claddr, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);

}

static void test_process_gen_privkey_cmd(void **state)
{
  (void) state; /* unused */

  UT_array *cmd_arr;
  struct client_address claddr;

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("GEN_PRIVKEY test 32", CMD_DELIMITER, cmd_arr), -1);
  expect_string(__wrap_gen_privkey_cmd, keyid, "test");
  expect_value(__wrap_gen_privkey_cmd, size, 32);
  assert_int_equal(process_gen_privkey_cmd(0, &claddr, NULL, cmd_arr), strlen(OK_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("GEN_PRIVKEY ", CMD_DELIMITER, cmd_arr), -1);
  assert_int_equal(process_gen_privkey_cmd(0, &claddr, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("GEN_PRIVKEY test ", CMD_DELIMITER, cmd_arr), -1);
  assert_int_equal(process_gen_privkey_cmd(0, &claddr, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("GEN_PRIVKEY test 32a", CMD_DELIMITER, cmd_arr), -1);
  assert_int_equal(process_gen_privkey_cmd(0, &claddr, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);

}

static void test_process_gen_cert_cmd(void **state)
{
  (void) state; /* unused */

  UT_array *cmd_arr;
  struct client_address claddr;
  struct certificate_meta meta;

  os_memset(&meta, 0, sizeof(struct certificate_meta));
  meta.not_before = 0;
  meta.not_after = 31536000L;
  strcpy(meta.c, "IE");
  strcpy(meta.o, "nqmcyber");
  strcpy(meta.ou, "R&D");
  strcpy(meta.cn, "raspberrypi.local");

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("GEN_CERT certid keyid raspberrypi.local", CMD_DELIMITER, cmd_arr), -1);
  expect_string(__wrap_gen_cert_cmd, certid, "certid");
  expect_string(__wrap_gen_cert_cmd, keyid, "keyid");
  expect_memory(__wrap_gen_cert_cmd, meta, &meta, sizeof(struct certificate_meta));
  assert_int_equal(process_gen_cert_cmd(0, &claddr, NULL, cmd_arr), strlen(OK_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("GEN_CERT ", CMD_DELIMITER, cmd_arr), -1);
  assert_int_equal(process_gen_cert_cmd(0, &claddr, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("GEN_CERT test ", CMD_DELIMITER, cmd_arr), -1);
  assert_int_equal(process_gen_cert_cmd(0, &claddr, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);
}

static void test_process_gen_pubkey_cmd(void **state)
{
  (void) state; /* unused */

  UT_array *cmd_arr;
  struct client_address claddr;

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("GEN_PUBKEY pubid keyid", CMD_DELIMITER, cmd_arr), -1);
  expect_string(__wrap_gen_pubkey_cmd, pubid, "pubid");
  expect_string(__wrap_gen_pubkey_cmd, keyid, "keyid");
  assert_int_equal(process_gen_pubkey_cmd(0, &claddr, NULL, cmd_arr), strlen(OK_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("GEN_PUBKEY ", CMD_DELIMITER, cmd_arr), -1);
  assert_int_equal(process_gen_pubkey_cmd(0, &claddr, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("GEN_PUBKEY test ", CMD_DELIMITER, cmd_arr), -1);
  assert_int_equal(process_gen_pubkey_cmd(0, &claddr, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);
}

static void test_process_encrypt_blob(void **state)
{
  (void) state; /* unused */

  UT_array *cmd_arr;
  struct client_address claddr;

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("ENCRYPT_BLOB keyid ivid 12345", CMD_DELIMITER, cmd_arr), -1);
  expect_string(__wrap_encrypt_blob_cmd, keyid, "keyid");
  expect_string(__wrap_encrypt_blob_cmd, ivid, "ivid");
  expect_string(__wrap_encrypt_blob_cmd, blob, "12345");
  assert_int_equal(process_encrypt_blob_cmd(0, &claddr, NULL, cmd_arr), strlen(OK_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("ENCRYPT_BLOB keyid ivid", CMD_DELIMITER, cmd_arr), -1);
  assert_int_equal(process_encrypt_blob_cmd(0, &claddr, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("ENCRYPT_BLOB keyid", CMD_DELIMITER, cmd_arr), -1);
  assert_int_equal(process_encrypt_blob_cmd(0, &claddr, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("ENCRYPT_BLOB ", CMD_DELIMITER, cmd_arr), -1);
  assert_int_equal(process_encrypt_blob_cmd(0, &claddr, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);
}

static void test_process_decrypt_blob(void **state)
{
  (void) state; /* unused */

  UT_array *cmd_arr;
  struct client_address claddr;

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("DECRYPT_BLOB keyid ivid 12345", CMD_DELIMITER, cmd_arr), -1);
  expect_string(__wrap_decrypt_blob_cmd, keyid, "keyid");
  expect_string(__wrap_decrypt_blob_cmd, ivid, "ivid");
  expect_string(__wrap_decrypt_blob_cmd, blob, "12345");
  assert_int_equal(process_decrypt_blob_cmd(0, &claddr, NULL, cmd_arr), strlen(OK_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("DECRYPT_BLOB keyid ivid", CMD_DELIMITER, cmd_arr), -1);
  assert_int_equal(process_decrypt_blob_cmd(0, &claddr, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("DECRYPT_BLOB keyid", CMD_DELIMITER, cmd_arr), -1);
  assert_int_equal(process_decrypt_blob_cmd(0, &claddr, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("DECRYPT_BLOB ", CMD_DELIMITER, cmd_arr), -1);
  assert_int_equal(process_decrypt_blob_cmd(0, &claddr, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);
}

static void test_process_sign_blob(void **state)
{
  (void) state; /* unused */

  UT_array *cmd_arr;
  struct client_address claddr;

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("SIGN_BLOB keyid 12345", CMD_DELIMITER, cmd_arr), -1);
  expect_string(__wrap_sign_blob_cmd, keyid, "keyid");
  expect_string(__wrap_sign_blob_cmd, blob, "12345");
  assert_int_equal(process_sign_blob_cmd(0, &claddr, NULL, cmd_arr), strlen(OK_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("SIGN_BLOB ", CMD_DELIMITER, cmd_arr), -1);
  assert_int_equal(process_sign_blob_cmd(0, &claddr, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);

  utarray_new(cmd_arr, &ut_str_icd);
  assert_int_not_equal(split_string_array("SIGN_BLOB ", CMD_DELIMITER, cmd_arr), -1);
  assert_int_equal(process_sign_blob_cmd(0, &claddr, NULL, cmd_arr), strlen(FAIL_REPLY));
  utarray_free(cmd_arr);
}

int main(int argc, char *argv[])
{  
  (void) argc;
  (void) argv;
  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_process_domain_buffer),
    cmocka_unit_test(test_process_subscribe_events_cmd),
    cmocka_unit_test(test_process_accept_mac_cmd),
    cmocka_unit_test(test_process_deny_mac_cmd),
    cmocka_unit_test(test_process_add_nat_cmd),
    cmocka_unit_test(test_process_remove_nat_cmd),
    cmocka_unit_test(test_process_assign_psk_cmd),
    cmocka_unit_test(test_process_get_map_cmd),
    cmocka_unit_test(test_process_get_all_cmd),
    cmocka_unit_test(test_process_set_ip_cmd),
    cmocka_unit_test(test_process_add_bridge_cmd),
    cmocka_unit_test(test_process_remove_bridge_cmd),
    cmocka_unit_test(test_process_clear_bridges_cmd),
    cmocka_unit_test(test_process_set_fingerprint_cmd),
    cmocka_unit_test(test_process_query_fingerprint_cmd),
    cmocka_unit_test(test_process_register_ticket_cmd),
    cmocka_unit_test(test_process_clear_psk_cmd),
    cmocka_unit_test(test_process_put_crypt_cmd),
    cmocka_unit_test(test_process_get_crypt_cmd),
    cmocka_unit_test(test_process_gen_randkey_cmd),
    cmocka_unit_test(test_process_gen_privkey_cmd),
    cmocka_unit_test(test_process_gen_pubkey_cmd),
    cmocka_unit_test(test_process_gen_cert_cmd),
    cmocka_unit_test(test_process_encrypt_blob),
    cmocka_unit_test(test_process_decrypt_blob),
    cmocka_unit_test(test_process_sign_blob)
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
