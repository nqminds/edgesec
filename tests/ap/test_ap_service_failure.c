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

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  log_set_quiet(false);

  const struct CMUnitTest tests[] = {cmocka_unit_test(test_ping_ap_command)};

  return cmocka_run_group_tests(tests, NULL, NULL);
}
