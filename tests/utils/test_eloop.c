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

struct test_state_t {
  struct eloop_data *eloop;
};

int setup(void **state) {
  struct test_state_t *test_state = calloc(1, sizeof(struct test_state_t));
  test_state->eloop = eloop_init();
  assert_non_null(test_state->eloop);
  *state = test_state;
  return 0;
}

int teardown(void **state) {
  struct test_state_t *test_state = *state;
  eloop_free(test_state->eloop);
  free(test_state);
  return 0;
}

static void eloop_timeout_handler_function(void *eloop_ctx, void *user_ctx) {
  check_expected(eloop_ctx);
  check_expected(user_ctx);
}

/**
 * @brief Should call eloop timeouts in order of timeout
 *
 * @param state CMocka test state created with setup() and closed with
 * teardown()
 */
static void test_eloop_timeout(void **state) {
  struct test_state_t *test_state = *state;

  char eloop_data[] = "this is eloop data";
  char user_data[] = "user data";

  // check if timeout is registered
  assert_false(eloop_is_timeout_registered(test_state->eloop,
                                           eloop_timeout_handler_function,
                                           eloop_data, user_data));
  expect_string(eloop_timeout_handler_function, eloop_ctx, eloop_data);
  expect_string(eloop_timeout_handler_function, user_ctx, user_data);
  assert_return_code(eloop_register_timeout(test_state->eloop, 0, 1,
                                            eloop_timeout_handler_function,
                                            eloop_data, user_data),
                     0);
  assert_true(eloop_is_timeout_registered(test_state->eloop,
                                          eloop_timeout_handler_function,
                                          eloop_data, user_data));

  // basic test
  char eloop_data1[] = "this is eloop data: run 1";
  char user_data1[] = "this is user data: run 1";
  expect_string(eloop_timeout_handler_function, eloop_ctx, eloop_data1);
  expect_string(eloop_timeout_handler_function, user_ctx, user_data1);
  assert_return_code(eloop_register_timeout(test_state->eloop, 0, 100,
                                            eloop_timeout_handler_function,
                                            eloop_data1, user_data1),
                     0);

  // test cancelling timeouts
  char eloop_data2[] = "this is eloop data: run 2";
  char user_data2[] = "this is user data: run 2";
  assert_return_code(eloop_register_timeout(test_state->eloop, 0, 200,
                                            eloop_timeout_handler_function,
                                            eloop_data2, user_data2),
                     0);
  assert_int_equal(
      eloop_cancel_timeout(test_state->eloop, eloop_timeout_handler_function,
                           eloop_data2, user_data2),
      1 // should cancel only all = one timeout
  );

  assert_return_code(eloop_register_timeout(test_state->eloop, 1, 0,
                                            eloop_timeout_handler_function,
                                            eloop_data2, user_data2),
                     0);
  assert_return_code(eloop_register_timeout(test_state->eloop, 2, 0,
                                            eloop_timeout_handler_function,
                                            eloop_data2, user_data2),
                     0);
  assert_return_code(eloop_register_timeout(test_state->eloop, 3, 0,
                                            eloop_timeout_handler_function,
                                            eloop_data2, user_data2),
                     0);

  struct os_reltime remaining = {0};
  assert_int_equal(eloop_cancel_timeout_one(
                       test_state->eloop, eloop_timeout_handler_function,
                       eloop_data2, user_data2, &remaining),
                   1 // should cancel only one timeout
  );
  assert_int_equal(
      eloop_cancel_timeout(test_state->eloop, eloop_timeout_handler_function,
                           eloop_data2, user_data2),
      2 // should cancel all = two timeouts
  );

  char eloop_data3[] = "this is eloop data: run 3";
  char user_data3[] = "this is user data: run 3";
  expect_string(eloop_timeout_handler_function, eloop_ctx, eloop_data3);
  expect_string(eloop_timeout_handler_function, user_ctx, user_data3);
  assert_return_code(eloop_register_timeout(test_state->eloop, 0, 300,
                                            eloop_timeout_handler_function,
                                            eloop_data3, user_data3),
                     0);

  // test depleting (shortening) timeouts
  char eloop_data4[] = "this is eloop data: run 4";
  expect_string(eloop_timeout_handler_function, eloop_ctx, eloop_data4);
  expect_string(eloop_timeout_handler_function, user_ctx, user_data);
  assert_return_code(eloop_register_timeout(test_state->eloop, 120,
                                            0, // super long time
                                            eloop_timeout_handler_function,
                                            eloop_data4, user_data),
                     0);
  assert_int_equal(eloop_deplete_timeout(
                       test_state->eloop, 100000, 0, // longer, so no change
                       eloop_timeout_handler_function, eloop_data4, user_data),
                   0);
  assert_int_equal(eloop_deplete_timeout(test_state->eloop, 1, 0,
                                         eloop_timeout_handler_function,
                                         "this data does not exist", user_data),
                   -1);
  assert_int_equal(eloop_deplete_timeout(test_state->eloop, 0, 400,
                                         eloop_timeout_handler_function,
                                         eloop_data4, user_data),
                   1);

  // test replenishing (lengthening) timeouts
  char eloop_data5[] = "this is eloop data: run 5";
  expect_string(eloop_timeout_handler_function, eloop_ctx, eloop_data5);
  expect_string(eloop_timeout_handler_function, user_ctx, user_data);
  assert_return_code(eloop_register_timeout(test_state->eloop, 0,
                                            2, // super short time
                                            eloop_timeout_handler_function,
                                            eloop_data5, user_data),
                     0);
  assert_int_equal(eloop_replenish_timeout(
                       test_state->eloop, 0, 1, // no change, should return 0
                       eloop_timeout_handler_function, eloop_data5, user_data),
                   0);
  assert_int_equal(eloop_replenish_timeout(test_state->eloop, 100000, 0,
                                           eloop_timeout_handler_function,
                                           "this data does not exist",
                                           user_data),
                   -1);
  assert_int_equal(eloop_replenish_timeout(test_state->eloop, 0, 500,
                                           eloop_timeout_handler_function,
                                           eloop_data5, user_data),
                   1);

  log_debug("Starting eloop");
  eloop_run(test_state->eloop);
  log_debug("Finished eloop");
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
      cmocka_unit_test(test_eloop_cancel_timeout),
      cmocka_unit_test_setup_teardown(test_eloop_timeout, setup, teardown)};

  return cmocka_run_group_tests(tests, NULL, NULL);
}
