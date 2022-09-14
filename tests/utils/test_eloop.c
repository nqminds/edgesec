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
#include <stdint.h>
#include <cmocka.h>

#include "utils/log.h"
#include "utils/eloop.h"
#include "utils/sockctl.h"

#define TMP_PFX "tdoms"
#define TEST_ELOOP_PARAM "param"
#define TEST_SEND_BUF_DATA "test"

void test_eloop_sock_handler_read(int sock, void *eloop_ctx, void *sock_ctx) {
  struct eloop_data *eloop = (struct eloop_data *)eloop_ctx;
  char *sock_ctx_data = (char *)sock_ctx;

  assert_non_null(eloop);
  assert_string_equal(sock_ctx_data, TEST_ELOOP_PARAM);

  struct client_address addr;
  char read_buf[100];

  os_memset(&addr, 0, sizeof(struct client_address));
  addr.type = SOCKET_TYPE_DOMAIN;
  read_socket_data(sock, read_buf, 100, &addr, 0);
  assert_string_equal(read_buf, TEST_SEND_BUF_DATA);

  eloop_terminate(eloop);
}

void test_eloop_sock_handler_unreg(int sock, void *eloop_ctx, void *sock_ctx) {
  (void)sock;
  (void)eloop_ctx;
  (void)sock_ctx;
}

void test_eloop_timeout_handler(void *eloop_ctx, void *user_ctx) {
  struct eloop_data *eloop = (struct eloop_data *)eloop_ctx;
  char *user_ctx_data = (char *)user_ctx;

  assert_non_null(eloop);
  strcpy(user_ctx_data, TEST_ELOOP_PARAM);
}

static void test_eloop_init(void **state) {
  (void)state; /* unused */

  struct eloop_data *eloop = eloop_init();

  assert_non_null(eloop);

  eloop_free(eloop);
}

static void test_eloop_register_read_sock(void **state) {
  (void)state; /* unused */
  char *send_buf = TEST_SEND_BUF_DATA;
  char *eloop_param = TEST_ELOOP_PARAM;
  struct sockaddr_un svaddr;
  char *server_file_path = tempnam(NULL, TMP_PFX);

  struct eloop_data *eloop = eloop_init();

  int ss = create_domain_server(server_file_path);

  assert_int_not_equal(ss, -1);

  int cs = create_domain_client(NULL);
  assert_int_not_equal(cs, -1);

  int eret = eloop_register_read_sock(eloop, ss, test_eloop_sock_handler_read,
                                      (void *)eloop, (void *)eloop_param);
  assert_int_not_equal(eret, -1);

  memset(&svaddr, 0, sizeof(struct sockaddr_un));
  svaddr.sun_family = AF_UNIX;
  strcpy(svaddr.sun_path, server_file_path);
  int buf_len = strlen(send_buf) + 1;
  ssize_t ret = sendto(cs, send_buf, buf_len, 0, (struct sockaddr *)&svaddr,
                       sizeof(struct sockaddr_un));
  assert_int_equal(ret, buf_len);

  eloop_run(eloop);

  close(ss);
  close(cs);
  os_free(server_file_path);
  eloop_free(eloop);
}

static void test_eloop_unregister_read_sock(void **state) {
  (void)state; /* unused */

  char *server_file_path = tempnam(NULL, TMP_PFX);
  struct eloop_data *eloop = eloop_init();
  int ss = create_domain_server(server_file_path);

  assert_int_not_equal(ss, -1);

  int ret = eloop_register_read_sock(eloop, ss, test_eloop_sock_handler_unreg,
                                     NULL, NULL);
  assert_int_not_equal(ret, -1);

  eloop_unregister_read_sock(eloop, ss);

  eloop_run(eloop);

  close(ss);
  eloop_free(eloop);
  os_free(server_file_path);
}

static void test_eloop_register_timeout(void **state) {
  (void)state; /* unused */

  char buf[100] = {0};
  struct eloop_data *eloop = eloop_init();
  int ret = eloop_register_timeout(eloop, 0, 0, test_eloop_timeout_handler,
                                   eloop, (void *)buf);

  assert_int_not_equal(ret, -1);
  eloop_run(eloop);
  assert_string_equal(buf, TEST_ELOOP_PARAM);
  eloop_free(eloop);
}

static void test_eloop_cancel_timeout(void **state) {
  (void)state; /* unused */

  char buf[100] = {0};
  struct eloop_data *eloop = eloop_init();
  int ret = eloop_register_timeout(eloop, 0, 0, test_eloop_timeout_handler,
                                   eloop, (void *)buf);

  assert_int_not_equal(ret, -1);

  ret = eloop_cancel_timeout(eloop, test_eloop_timeout_handler, eloop,
                             (void *)buf);
  eloop_run(eloop);
  assert_string_equal(buf, "");
  eloop_free(eloop);
}

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_eloop_init),
      cmocka_unit_test(test_eloop_register_read_sock),
      cmocka_unit_test(test_eloop_unregister_read_sock),
      cmocka_unit_test(test_eloop_register_timeout),
      cmocka_unit_test(test_eloop_cancel_timeout)};

  return cmocka_run_group_tests(tests, NULL, NULL);
}
