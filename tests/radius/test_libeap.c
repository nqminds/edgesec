/**
 * @file
 * @author Alexandru Mereacre
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: Copyright (c) 2007, Jouni Malinen <j@w1.fi>
 * SPDX-License-Identifier: BSD license
 * @version hostapd-2.10
 * @brief Test showing how EAP peer and server code from
 * wpa_supplicant/hostapd can be used as a library for a EAP-TLS connection.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <cmocka.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <utils/includes.h>

#include <utils/common.h>

int eap_test_peer_init(void);
void eap_test_peer_deinit(void);
int eap_test_peer_step(bool *eapSuccess);

int eap_test_server_init(void);
void eap_test_server_deinit(void);
int eap_test_server_step(void);

static void test_libeap(void **state) {
  (void)state;
  int res_s, res_p;
  bool eapSuccess = false;

  wpa_debug_level = 0;

  int ret = eap_test_peer_init() < 0 || eap_test_server_init() < 0;
  assert_int_equal(ret, 0);

  do {
    printf("---[ server ]--------------------------------\n");
    res_s = eap_test_server_step();
    printf("---[ peer ]----------------------------------\n");
    res_p = eap_test_peer_step(&eapSuccess);
  } while (res_s || res_p);

  eap_test_peer_deinit();
  eap_test_server_deinit();

  assert_true(eapSuccess);
}

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  const struct CMUnitTest tests[] = {cmocka_unit_test(test_libeap)};

  return cmocka_run_group_tests(tests, NULL, NULL);
}
