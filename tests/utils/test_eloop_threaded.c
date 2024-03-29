/**
 * @file
 * @author Alois Klink
 * @date 2022
 * @copyright
 * SPDX-FileCopyrightText: © 2022 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief Tests for eloop when using multi-threading.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <cmocka.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <eloop.h>
#include <errno.h>
#include <sys/types.h>
#include <threads.h>
#include <utarray.h>

#include "utils/log.h"
#include "utils/sockctl.h"

struct test_state_t {
  struct eloop_data *eloop;
};

int setup(void **state) {
  struct test_state_t *test_state = calloc(1, sizeof(struct test_state_t));
  test_state->eloop = edge_eloop_init();
  assert_non_null(test_state->eloop);
  *state = test_state;
  return 0;
}

int teardown(void **state) {
  struct test_state_t *test_state = *state;
  edge_eloop_free(test_state->eloop);
  free(test_state);
  return 0;
}

static void test_basic_eloop(void **state) {
  struct test_state_t *test_state = *state;
  edge_eloop_run(test_state->eloop);

  edge_eloop_terminate(test_state->eloop);
  assert_true(edge_eloop_terminated(test_state->eloop));
}

struct test_eloop_sock_ctx {
  struct client_address serv_address;
  int client_socket_fd;
};
struct test_eloop_sock_user_ctx {
  const char *data;
  size_t length;
};
#define make_struct_test_eloop_sock_user_ctx(name, string)                     \
  struct test_eloop_sock_user_ctx name = {.data = string,                      \
                                          .length = sizeof(string)}

/**
 * @brief Sends the given data to the given socket.
 *
 * @param eloop_ctx Pointer to @p test_eloop_sock_ctx object, containing the
 * socket to send to.
 * @param user_ctx Pointer to @p user_ctx object, containing the data to send
 * to.
 */
static void send_data_to_sock(void *eloop_ctx, void *user_ctx) {
  struct test_eloop_sock_ctx *eloop_sock_ctx = eloop_ctx;
  struct test_eloop_sock_user_ctx *user_sock_ctx = user_ctx;

  log_debug("Sending %zd bytes to fd %d on port %" PRIu16 ", contents: %s",
            user_sock_ctx->length, eloop_sock_ctx->client_socket_fd,
            eloop_sock_ctx->serv_address.caddr.addr_in.sin_port,
            user_sock_ctx->data);
  ssize_t bytes_written =
      write_socket_data(eloop_sock_ctx->client_socket_fd, user_sock_ctx->data,
                        user_sock_ctx->length, &eloop_sock_ctx->serv_address);
  assert_int_equal(bytes_written, user_sock_ctx->length);
}

/**
 * @brief Handler for recievieng data on a socket.
 *
 * As this function does not in the main thread, we cannot use any cmocka code.
 *
 * @param sock The file descriptor of the socket.
 * @param eloop_ctx Pointer to @p eloop_data. Used to terminate the loop when
 * `STOP` is recieved.
 * @param user_ctx Pointer to string @p UT_array. Used to store packets.
 */
static void eloop_sock_handler_function(int sock, void *eloop_ctx,
                                        void *user_ctx) {
  struct eloop_data *eloop = eloop_ctx;
  UT_array *sock_handler_recieved_data = user_ctx;

  struct sockaddr_storage from;
  socklen_t fromlen = sizeof(from);
  char buf[4096];
  ssize_t res = recvfrom(sock, buf, sizeof(buf) - 1, 0,
                         (struct sockaddr *)&from, &fromlen);
  buf[res] = '\0';

  log_trace("Read %zd bytes from buffer, contents %s", res, buf);

  // UTarray doesn't support pushing string arrays, only string pointers
  // because it's some complex C-macros.
  char *pointer_to_buffer = buf;
  utarray_push_back(sock_handler_recieved_data, &pointer_to_buffer);

  if (strcmp(buf, "STOP") == 0) {
    edge_eloop_terminate(eloop);
  }
}

struct eloop_sock_handler_args {
  /** port to listen on */
  const unsigned int udp_port;
  /**
   * string @p UT_array that has all the data recevied by the UDP server.
   * Please remember to utarray_free() this array when done with it.
   */
  UT_array *sock_handler_recieved_data;
};

/**
 * @brief UDP server thread for testing eloop_sock_*
 *
 * @param[in, out] thread_ctx Pointer to struct eloop_sock_handler_args
 * @retval 0 On success
 * @retval -1 (Never), CMocka aborts on error.
 */
static int eloop_sock_handler_thread(void *thread_ctx) {
  struct eloop_sock_handler_args *args = thread_ctx;

  struct eloop_data *eloop = edge_eloop_init();
  assert_non_null(
      eloop); // might crash, since CMocka doesn't support multithreading

  log_debug("Hosting server on localhost:%d", args->udp_port);

  utarray_new(args->sock_handler_recieved_data, &ut_str_icd);
  // CMocka doesn't do well with threading, so this might not throw an error
  // on failure.
  assert_non_null(args->sock_handler_recieved_data);

  int server_socket = create_udp_server(args->udp_port);
  assert_return_code(edge_eloop_register_read_sock(
                         eloop, server_socket, eloop_sock_handler_function,
                         eloop, args->sock_handler_recieved_data),
                     0);

  log_debug("Starting server UDP eloop");
  edge_eloop_run(eloop);
  log_debug("Stopping server UDP eloop");
  log_debug("Recieved %d packets of data on port %d",
            utarray_len(args->sock_handler_recieved_data), args->udp_port);

  edge_eloop_free(eloop);
  close(server_socket);
  return 0;
}

/**
 * @brief eloop socket tests.
 *
 * Creates a background UDP thread that uses edge_eloop_register_read_sock()
 * to listen for UDP packets.
 *
 * The foreground client thread sends packets to the server, then sends `STOP`
 * to gracefully stop the server thread.
 *
 * On exit, the server thread returns the array of recieved packets, so we can
 * use CMocka to confirm that the packets arrived.
 */
static void test_eloop_sock(void **state) {
  struct test_state_t *test_state = *state;

  int client_socket = socket(AF_INET, SOCK_DGRAM, 0);
  assert_return_code(client_socket, 0);

  unsigned int udp_port = 8888;

  struct test_eloop_sock_ctx eloop_ctx = {
      .serv_address =
          {
              .caddr.addr_in =
                  {
                      .sin_family = AF_INET,
                      .sin_port = htons(udp_port),
                      .sin_addr.s_addr =
                          htonl(0x7F000001), // no place like 127.0.0.1 🏠
                  },
              .len = sizeof(struct sockaddr_in),
              .type = SOCKET_TYPE_UDP,
          },
      .client_socket_fd = client_socket,
  };

  UT_array *sent_data;
  utarray_new(sent_data, &ut_str_icd);

  uint64_t initial_delay_useconds =
      500000; // wait 0.5 seconds for server to start

  make_struct_test_eloop_sock_user_ctx(test1, "Hello World!");
  utarray_push_back(sent_data, &test1.data);
  assert_return_code(
      edge_eloop_register_timeout(test_state->eloop, 0, initial_delay_useconds,
                                  send_data_to_sock, &eloop_ctx, &test1),
      0);
  utarray_push_back(sent_data, &test1.data);
  assert_return_code(edge_eloop_register_timeout(
                         test_state->eloop, 0, initial_delay_useconds + 1,
                         send_data_to_sock, &eloop_ctx, &test1),
                     0);

  make_struct_test_eloop_sock_user_ctx(test2, "Foo bar!");
  utarray_push_back(sent_data, &test2.data);
  assert_return_code(edge_eloop_register_timeout(
                         test_state->eloop, 0, initial_delay_useconds + 2,
                         send_data_to_sock, &eloop_ctx, &test2),
                     0);

  // one million microseconds should rollover to 1 second
  make_struct_test_eloop_sock_user_ctx(
      test1Second, "CↈↃµs (one million in ancient roman numerals)");
  utarray_push_back(sent_data, &test1Second.data);
  assert_return_code(edge_eloop_register_timeout(test_state->eloop, 0, 1000000,
                                                 send_data_to_sock, &eloop_ctx,
                                                 &test1Second),
                     0);

  make_struct_test_eloop_sock_user_ctx(stop_packet, "STOP");
  utarray_push_back(sent_data, &stop_packet.data);
  assert_return_code(edge_eloop_register_timeout(test_state->eloop, 1, 1,
                                                 send_data_to_sock, &eloop_ctx,
                                                 &stop_packet),
                     0);

  struct eloop_sock_handler_args eloop_sock_handler_args = {
      .udp_port = udp_port,
      .sock_handler_recieved_data = NULL,
  };
  thrd_t server_thread;
  assert_int_equal(thrd_create(&server_thread, eloop_sock_handler_thread,
                               &eloop_sock_handler_args),
                   thrd_success);

  log_debug("Starting eloop");
  edge_eloop_run(test_state->eloop);
  log_debug("Finished eloop");

  assert_return_code(close(client_socket), 0);

  log_debug("Waiting for server to close");
  int server_thread_return_code;
  assert_int_equal(thrd_join(server_thread, &server_thread_return_code),
                   thrd_success);
  assert_return_code(server_thread_return_code, 0);

  log_debug("Server recieved %d packets",
            utarray_len(eloop_sock_handler_args.sock_handler_recieved_data));
  log_debug("Expected server to recieve %d packets", utarray_len(sent_data));
  assert_int_equal(
      utarray_len(eloop_sock_handler_args.sock_handler_recieved_data),
      utarray_len(sent_data));

  for (uint32_t i = 0; i < utarray_len(sent_data); i++) {
    char **actual_string = (char **)utarray_eltptr(
        eloop_sock_handler_args.sock_handler_recieved_data, i);
    char **expected_string = (char **)utarray_eltptr(sent_data, i);
    assert_string_equal(*actual_string, *expected_string);
  }
  utarray_free(eloop_sock_handler_args.sock_handler_recieved_data);
  utarray_free(sent_data);
}

/**
 * @brief This function has external linkage but isn't in eloop.h
 *
 * This is potentially a bug, but we can use it for improved tests, while
 * it's exposed!
 */
extern void eloop_destroy(struct eloop_data *eloop);

static void test_edge_eloop_destroy(void **state) {
  (void)state; /* unused */

  // test coverage changes if `now.usec == 0`
  // rerunning the tests after 1 microsecond should fix this issue
  for (int i = 0; i < 2; i++) {
    struct eloop_data *eloop = edge_eloop_init();

    assert_return_code(
        // make sure usec is 0, so that we have a
        // higher chance of hitting `timeout.usec < now.usec` branch
        edge_eloop_register_timeout(eloop, 120, 0, send_data_to_sock, eloop,
                                    NULL),
        errno);

    assert_false(dl_list_empty(&eloop->timeout));

    eloop_destroy(eloop);

    assert_true(dl_list_empty(&eloop->timeout));

    edge_eloop_free(eloop);

    thrd_sleep(&(struct timespec){.tv_nsec = 1000},
               NULL); // sleep 1 microsecond
  }
}

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
      cmocka_unit_test_setup_teardown(test_basic_eloop, setup, teardown),
      cmocka_unit_test_setup_teardown(test_eloop_sock, setup, teardown),
      cmocka_unit_test(test_edge_eloop_destroy),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
