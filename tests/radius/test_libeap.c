/*
 * Example application showing how EAP peer and server code from
 * wpa_supplicant/hostapd can be used as a library. This example program
 * initializes both an EAP server and an EAP peer entities and then runs
 * through an EAP-PEAP/MSCHAPv2 authentication.
 * Copyright (c) 2007, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
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
int eap_test_peer_step(void);

int eap_test_server_init(void);
void eap_test_server_deinit(void);
int eap_test_server_step(void);


static void test_libeap(void **state) {
	(void)state;
	// int res_s, res_p;

	wpa_debug_level = 0;

	int ret = eap_test_peer_init() < 0 || eap_test_server_init() < 0;
	assert_int_equal(ret, 0);

	// do {
	// 	printf("---[ server ]--------------------------------\n");
	// 	res_s = eap_example_server_step();
	// 	printf("---[ peer ]----------------------------------\n");
	// 	res_p = eap_example_peer_step();
	// } while (res_s || res_p);

	eap_test_peer_deinit();
	eap_test_server_deinit();
}

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  const struct CMUnitTest tests[] = {cmocka_unit_test(test_libeap)};

  return cmocka_run_group_tests(tests, NULL, NULL);
}
