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
 * @param reply - Will be set to the string given by `will_return_ptr()`
 * @return - The value of `will_return()`.
 */
int __wrap_writeread_domain_data_str(char *socket_path, char *write_str,
                                     char **reply) {
  (void)socket_path;
  (void)write_str;

  *reply = os_strdup(mock_ptr_type(const char *));

  return mock();
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

    log_debug("test_denyacl_ap_command: Testing function %d", i);

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

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_ping_ap_command),
      cmocka_unit_test_setup(test_denyacl_ap_command,
                             setup_malloc_enomem_to_false)};

  return cmocka_run_group_tests(tests, NULL, NULL);
}
