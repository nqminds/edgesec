/**
 * @file
 * @author Alois Klink <alois@nquiringminds.com>
 * @date 2023-01-30
 * @copyright
 * SPDX-FileCopyrightText: © 2023 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief Tests for ap_service.c error handling
 *
 * Tests whether ap_service.c correctly handles errors
 */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <cmocka.h>

#include <errno.h>

#include "ap/ap_service.h"

/**
 * @brief mocked writeread_domain_data_str() function.
 *
 * @param socket_path - Unused.
 * @param write_str - Unused.
 * @param reply - Will be set to the string given by `will_return_ptr()`,
 * if the return code is 0.
 * @return - The value of `will_return()`.
 */
int __wrap_writeread_domain_data_str(char *socket_path, char *write_str,
                                     char **reply) {
  (void)socket_path;
  (void)write_str;

  const char *reply_str = mock_ptr_type(const char *);

  int rc = mock();

  if (rc == 0) {
    *reply = os_strdup(reply_str);
  }

  return rc;
}
/** Wraps around write_domain_data_s() to do nothing and return success */
int __wrap_write_domain_data_s(int sock, const char *data, size_t data_len,
                               const char *addr) {
  (void)sock;
  (void)data;
  (void)data_len;
  (void)addr;

  return mock();
}

/** Wraps generate_hostapd_conf() to do nothing and return success */
int __wrap_generate_hostapd_conf(struct apconf *hconf,
                                 struct radius_conf *rconf) {
  (void)hconf;
  (void)rconf;

  return 0;
}
/** Wraps generate_vlan_conf() to do nothing and return success */
int __wrap_generate_vlan_conf(char *vlan_file, char *interface) {
  (void)vlan_file;
  (void)interface;

  return 0;
}
/** Wraps run_ap_process() to do nothing and return success */
int __wrap_run_ap_process(struct apconf *hconf) {
  (void)hconf;

  function_called();

  return 0;
}

/** If set to true, every call to `malloc()` will fail and return NULL/ENOMEM */
static bool malloc_enomem = false;

int setup_malloc_enomem_to_false(void **state) {
  (void)state;
  malloc_enomem = false;
  return 0;
};

void *__real_malloc(size_t size);
/**
 * @brief mocked version of malloc()
 *
 * Use `will_return_ptr()` to control what this returns.
 * If you use `will_return_ptr(NULL)`, this will set `errno` to `ENOMEM`;
 *
 * @param size - bytes to allocate.
 * @return The value of `will_return()`.
 */
void *__wrap_malloc(size_t size) {
  if (malloc_enomem) {
    errno = ENOMEM;
    return NULL;
  }
  return __real_malloc(size);
}

static void test_ping_ap_command(void **state) {
  (void)state;

  struct apconf hconf = {
      .ctrl_interface_path = "unused",
  };

  // should succeed when writeread_domain_data_str succeeds!
  will_return_ptr(__wrap_writeread_domain_data_str, PING_AP_COMMAND_REPLY);
  will_return(__wrap_writeread_domain_data_str, 0);
  assert_return_code(ping_ap_command(&hconf), errno);

  // should error if writeread_domain_data_str returns an invalid PING response
  will_return_ptr(__wrap_writeread_domain_data_str, "invalid response");
  will_return(__wrap_writeread_domain_data_str, 0);
  assert_int_equal(ping_ap_command(&hconf), -1);

  // should error if writeread_domain_data_str errors
  will_return_ptr(__wrap_writeread_domain_data_str, PING_AP_COMMAND_REPLY);
  will_return(__wrap_writeread_domain_data_str, -1);
  assert_int_equal(ping_ap_command(&hconf), -1);
}

static void test_denyacl_ap_command(void **state) {
  (void)state;

  struct apconf hconf = {
      .ctrl_interface_path = "unused",
  };

  typedef int (*DenyaclApCommand)(struct apconf * hconf, const char *mac_addr);

  // both of denyacl_add_ap_command and denyacl_del_ap_command should react
  // the same way to erroneous writeread_domain_data_str() results
  const DenyaclApCommand denyacl_ap_command_functions_to_test[] = {
      denyacl_add_ap_command,
      denyacl_del_ap_command,
  };

  for (size_t i = 0; i < ARRAY_SIZE(denyacl_ap_command_functions_to_test);
       i++) {
    const DenyaclApCommand function_to_test =
        denyacl_ap_command_functions_to_test[i];

    log_debug("test_denyacl_ap_command: Testing function %zu", i);

    log_debug("should succeed when writeread_domain_data_str succeeds!");
    will_return_ptr(__wrap_writeread_domain_data_str,
                    GENERIC_AP_COMMAND_OK_REPLY);
    will_return(__wrap_writeread_domain_data_str, 0);
    assert_return_code(function_to_test(&hconf, "11:22:33:44:55:66"), errno);

    log_debug("should error if writeread_domain_data_str returns an invalid "
              "response");
    will_return_ptr(__wrap_writeread_domain_data_str, "invalid response");
    will_return(__wrap_writeread_domain_data_str, 0);
    assert_int_equal(function_to_test(&hconf, "11:22:33:44:55:66"), -1);

    log_debug("should error if writeread_domain_data_str errors");
    will_return_ptr(__wrap_writeread_domain_data_str,
                    GENERIC_AP_COMMAND_OK_REPLY);
    will_return(__wrap_writeread_domain_data_str, -1);
    assert_int_equal(function_to_test(&hconf, "11:22:33:44:55:66"), -1);

    log_debug("should fail when forcing malloc() to fail");
    malloc_enomem = true;
    assert_int_equal(function_to_test(&hconf, "11:22:33:44:55:66"), -1);
    malloc_enomem = false;
  }
}

static void test_disconnect_ap_command(void **state) {
  (void)state;
  struct apconf hconf = {
      .ctrl_interface_path = "unused",
  };

  log_debug("should succeed if both *add_ap_command and *del_ap_command pass");
  will_return_ptr(__wrap_writeread_domain_data_str,
                  GENERIC_AP_COMMAND_OK_REPLY);
  will_return(__wrap_writeread_domain_data_str, 0);
  will_return_ptr(__wrap_writeread_domain_data_str,
                  GENERIC_AP_COMMAND_OK_REPLY);
  will_return(__wrap_writeread_domain_data_str, 0);
  assert_return_code(disconnect_ap_command(&hconf, "11:22:33:44:55:66"), errno);

  log_debug("should fail if denyacl_add_ap_command fails");
  will_return_ptr(__wrap_writeread_domain_data_str,
                  "invalid denyacl_add_ap_command response");
  will_return(__wrap_writeread_domain_data_str, 0);
  assert_int_equal(disconnect_ap_command(&hconf, "11:22:33:44:55:66"), -1);

  log_debug("should fail if denyacl_del_ap_command fails");
  will_return_ptr(__wrap_writeread_domain_data_str,
                  GENERIC_AP_COMMAND_OK_REPLY);
  will_return(__wrap_writeread_domain_data_str, 0);
  will_return_ptr(__wrap_writeread_domain_data_str,
                  "invalid denyacl_del_ap_command response");
  will_return(__wrap_writeread_domain_data_str, 0);
  assert_int_equal(disconnect_ap_command(&hconf, "11:22:33:44:55:66"), -1);
}

static void test_check_sta_ap_command(void **state) {
  (void)state;
  struct apconf hconf = {
      .ctrl_interface_path = "unused",
  };

  log_debug("should succeed if writeread_domain_data_str returns something");
  will_return_ptr(__wrap_writeread_domain_data_str, "my_super_cool_sta");
  will_return(__wrap_writeread_domain_data_str, 0);
  assert_return_code(check_sta_ap_command(&hconf, "11:22:33:44:55:66"), errno);

  log_debug("should fail if malloc fails");
  malloc_enomem = true;
  assert_int_equal(check_sta_ap_command(&hconf, "11:22:33:44:55:66"), -1);
  malloc_enomem = false;

  log_debug("should error if writeread_domain_data_str errors");
  will_return_ptr(__wrap_writeread_domain_data_str,
                  GENERIC_AP_COMMAND_OK_REPLY);
  will_return(__wrap_writeread_domain_data_str, -1);
  assert_int_equal(check_sta_ap_command(&hconf, "11:22:33:44:55:66"), -1);

  log_debug("should error if writeread_domain_data_str "
            "returns " GENERIC_AP_COMMAND_FAIL_REPLY);
  will_return_ptr(__wrap_writeread_domain_data_str,
                  GENERIC_AP_COMMAND_FAIL_REPLY);
  will_return(__wrap_writeread_domain_data_str, 0);
  assert_int_equal(check_sta_ap_command(&hconf, "11:22:33:44:55:66"), -1);

  log_debug("should error if writeread_domain_data_str returns an empty "
            "string" GENERIC_AP_COMMAND_FAIL_REPLY);
  will_return_ptr(__wrap_writeread_domain_data_str, "");
  will_return(__wrap_writeread_domain_data_str, 0);
  assert_int_equal(check_sta_ap_command(&hconf, "11:22:33:44:55:66"), -1);
}

int setup_supervisor_context(void **state) {
  malloc_enomem = false;

  struct supervisor_context *context =
      malloc(sizeof(struct supervisor_context));
  assert_non_null(context);
  *context = (struct supervisor_context){
      .hconfig =
          {
              .ctrl_interface_path =
                  "/tmp/edgesec/this-file-should-not-be-created",
              .vlan_file = "/tmp/edgesec/this-file-should-not-be-created",
              .ap_file_path = "/tmp/edgesec/this-file-should-not-be-created",
              .ssid = "unused",
              .interface = "unused-interface",
              .ap_bin_path =
                  "/tmp/edgesec/this-hostapd-executable-should-not-exist",
          },
      .eloop = edge_eloop_init(),
  };
  assert_non_null(context->eloop);
  *state = context;
  return 0;
};

int teardown_supervisor_context(void **state) {
  struct supervisor_context *context = *state;
  close_ap(context);
  edge_eloop_free(context->eloop);
  free(context);
  return 0;
};

static void test_run_ap(void **state) {
  struct supervisor_context *context = *state;
  errno = 0;

  log_debug("should work with default test context");
  will_return_ptr(__wrap_writeread_domain_data_str, PING_AP_COMMAND_REPLY);
  will_return(__wrap_writeread_domain_data_str, 0);
  will_return(__wrap_write_domain_data_s, 0);
  assert_return_code(run_ap(context, false, false, NULL), errno);

  log_debug("should work (with warning) even if ping_ap_command fails");
  will_return_ptr(__wrap_writeread_domain_data_str,
                  "returns some other message");
  will_return(__wrap_writeread_domain_data_str, 0);
  will_return(__wrap_write_domain_data_s, 0);
  assert_return_code(run_ap(context, false, false, NULL), errno);

  log_debug("should work (with warning) even if register_ap_event fails");
  will_return_ptr(__wrap_writeread_domain_data_str, PING_AP_COMMAND_REPLY);
  will_return(__wrap_writeread_domain_data_str, 0);
  will_return(__wrap_write_domain_data_s, -1); // makes register_ap_event fail
  assert_return_code(run_ap(context, false, false, NULL), errno);

  log_debug("should call run_ap_process if exec_ap is `true`");
  expect_function_call(__wrap_run_ap_process);
  will_return_ptr(__wrap_writeread_domain_data_str, PING_AP_COMMAND_REPLY);
  will_return(__wrap_writeread_domain_data_str, 0);
  will_return(__wrap_write_domain_data_s, 0);
  bool exec_ap = true;
  assert_return_code(run_ap(context, exec_ap, false, NULL), errno);
}

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_ping_ap_command),
      cmocka_unit_test_setup(test_denyacl_ap_command,
                             setup_malloc_enomem_to_false),
      cmocka_unit_test_setup(test_disconnect_ap_command,
                             setup_malloc_enomem_to_false),
      cmocka_unit_test_setup(test_check_sta_ap_command,
                             setup_malloc_enomem_to_false),
      cmocka_unit_test_setup_teardown(test_run_ap, setup_supervisor_context,
                                      teardown_supervisor_context)};

  return cmocka_run_group_tests(tests, NULL, NULL);
}
