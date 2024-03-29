#define _GNU_SOURCE

#include <setjmp.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <cmocka.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "utils/allocs.h"
#include "utils/hashmap.h"
#include "utils/log.h"
#include "utils/os.h"
#include "utils/sockctl.h"

#define TMP_PFX "tdoms"

int create_client(char *path) {
  struct sockaddr_un claddr;
  int sock;
  memset(&claddr, 0, sizeof(struct sockaddr_un));
  claddr.sun_family = AF_UNIX;
  strcpy(claddr.sun_path, path);

  sock = socket(AF_UNIX, SOCK_DGRAM, 0);
  if (sock == -1) {
    perror("socket");
    exit(1);
  }

  if (bind(sock, (struct sockaddr *)&claddr, sizeof(struct sockaddr_un)) ==
      -1) {
    perror("bind");
    exit(1);
  }

  return sock;
}

struct test_state {
  char *tmp_folder;
  char *client_file_path;
  char *server_file_path;
};

static int setup(void **state) {
  struct test_state *test_state = malloc(sizeof(struct test_state));
  assert_non_null(test_state);

  *test_state = (struct test_state){0};

  char tmp_folder_template[] = "/tmp/test_edgesec_sockctlXXXXXX";
  char *created_folder = mkdtemp(tmp_folder_template);
  assert_non_null(created_folder);

  test_state->tmp_folder = malloc(sizeof(tmp_folder_template));
  strcpy(test_state->tmp_folder, created_folder);

  test_state->client_file_path =
      concat_paths(test_state->tmp_folder, "client-socket");
  assert_non_null(test_state->client_file_path);
  test_state->server_file_path =
      concat_paths(test_state->tmp_folder, "server-socket");
  assert_non_null(test_state->server_file_path);

  *state = test_state;

  bool all_created = test_state->tmp_folder && test_state->client_file_path &&
                     test_state->server_file_path;
  return all_created ? 0 : -1;
}

static int teardown(void **state) {
  struct test_state *test_state = *state;
  if (0 == check_file_exists(test_state->client_file_path, NULL)) {
    assert_return_code(remove(test_state->client_file_path), errno);
  }
  if (0 == check_file_exists(test_state->server_file_path, NULL)) {
    assert_return_code(remove(test_state->server_file_path), errno);
  }
  if (test_state->tmp_folder != NULL) {
    // This function will fail if the directory is not empty
    assert_return_code(rmdir(test_state->tmp_folder), errno);
  }

  free(test_state->client_file_path);
  free(test_state->server_file_path);
  free(test_state->tmp_folder);
  free(test_state);

  return 0;
}

static void test_create_domain_server(void **state) {
  struct test_state *test_state = *state;

  assert_non_null(test_state->server_file_path);

  int sock = create_domain_server(test_state->server_file_path);
  assert_int_not_equal(sock, -1);

  close(sock);
}

static void test_create_domain_client(void **state) {
  struct test_state *test_state = *state;

  assert_non_null(test_state->client_file_path);

  int sock = create_domain_client(test_state->client_file_path);
  assert_int_not_equal(sock, -1);
  close(sock);

  sock = create_domain_client(NULL);
  assert_int_not_equal(sock, -1);
  close(sock);
}

static void test_read_domain_data_s(void **state) {
  struct test_state *test_state = *state;

  char *send_buf = "domain";

  int server_sock = create_domain_server(test_state->server_file_path);

  assert_int_not_equal(server_sock, -1);

  int client_sock = create_domain_client(test_state->client_file_path);
  assert_int_not_equal(client_sock, -1);

  struct sockaddr_un svaddr = {
      .sun_family = AF_UNIX,
  };
  strcpy(svaddr.sun_path, test_state->server_file_path);
  int buf_len = strlen(send_buf) + 1;
  ssize_t ret = sendto(client_sock, send_buf, buf_len, 0,
                       (struct sockaddr *)&svaddr, sizeof(struct sockaddr_un));
  assert_int_equal(ret, buf_len);

  char read_buf[100];
  char client_addr[108];
  ret = read_domain_data_s(server_sock, read_buf, 100, client_addr, 0);

  assert_int_equal(ret, buf_len);
  assert_string_equal(send_buf, read_buf);
  assert_string_equal(client_addr, test_state->client_file_path);

  client_sock = create_domain_client(NULL);
  assert_int_not_equal(client_sock, -1);

  ret = sendto(client_sock, send_buf, buf_len, 0, (struct sockaddr *)&svaddr,
               sizeof(struct sockaddr_un));
  assert_int_equal(ret, buf_len);

  {
    struct client_address addr = {
        .type = SOCKET_TYPE_DOMAIN,
    };
    ret = read_socket_data(server_sock, read_buf, 100, &addr, 0);
    assert_int_equal(ret, buf_len);
    assert_string_equal(send_buf, read_buf);

    ret = sendto(server_sock, send_buf, buf_len, 0,
                 (struct sockaddr *)&addr.caddr.addr_un, addr.len);
    assert_int_equal(ret, buf_len);
  }

  {
    struct client_address addr = {
        .type = SOCKET_TYPE_DOMAIN,
    };
    ret = read_socket_data(client_sock, read_buf, 100, &addr, 0);
    assert_int_equal(ret, buf_len);
    assert_string_equal(send_buf, read_buf);
  }

  close(client_sock);
  close(server_sock);
}

static void test_write_domain_data_s(void **state) {
  struct test_state *test_state = *state;

  char *send_buf = "domain";
  char read_buf[100];

  int server_sock = create_domain_server(test_state->server_file_path);
  assert_int_not_equal(server_sock, -1);

  int client_sock = create_domain_client(test_state->client_file_path);
  assert_int_not_equal(client_sock, -1);

  int buf_len = strlen(send_buf) + 1;
  ssize_t ret = write_domain_data_s(server_sock, send_buf, buf_len,
                                    test_state->client_file_path);
  assert_int_equal(ret, buf_len);

  socklen_t len = sizeof(struct sockaddr_un);
  struct sockaddr_un svaddr = {0};
  ret =
      recvfrom(client_sock, read_buf, 100, 0, (struct sockaddr *)&svaddr, &len);

  assert_int_equal(ret, buf_len);
  assert_string_equal(send_buf, read_buf);

  close(client_sock);

  client_sock = create_domain_client(NULL);
  assert_int_not_equal(client_sock, -1);

  struct client_address addr = {
      .caddr.addr_un = svaddr,
      .len = len,
      .type = SOCKET_TYPE_DOMAIN,
  };
  ret = write_socket_data(client_sock, send_buf, buf_len, &addr);
  assert_int_equal(ret, buf_len);

  len = sizeof(struct sockaddr_un);
  struct sockaddr_un claddr = {0};
  ret =
      recvfrom(server_sock, read_buf, 100, 0, (struct sockaddr *)&claddr, &len);
  assert_int_equal(ret, buf_len);
  assert_string_equal(send_buf, read_buf);

  close(client_sock);
  close(server_sock);
}

static void test_create_udp_server(void **state) {
  (void)state;

  int sock = create_udp_server(12345);

  assert_int_not_equal(sock, -1);

  close(sock);
}

static void test_write_socket_data(void **state) {
  (void)state; /* unused */

  int sfd = create_udp_server(12346);

  assert_int_not_equal(sfd, -1);

  int cfd = socket(AF_INET, SOCK_DGRAM, 0);
  assert_int_not_equal(cfd, -1);

  struct client_address caddr = {
      .caddr.addr_in =
          {
              .sin_family = AF_INET,
              .sin_port = htons(12346),
          },
      .len = sizeof(struct sockaddr_in),
      .type = SOCKET_TYPE_UDP,
  };
  assert_int_not_equal(
      inet_pton(AF_INET, "127.0.0.1", &caddr.caddr.addr_in.sin_addr), -1);

  char send_buf[] = "udp";
  assert_int_not_equal(
      write_socket_data(cfd, send_buf, sizeof(send_buf), &caddr), -1);

  struct client_address saddr = {
      .type = SOCKET_TYPE_UDP,
  };
  char read_buf[100];
  assert_int_not_equal(read_socket_data(sfd, read_buf, 100, &saddr, 0), -1);
  assert_int_equal(os_strnlen_s(read_buf, 100), strlen(send_buf));
  assert_int_equal(strncmp(send_buf, read_buf, 100), 0);
  close(sfd);
  close(cfd);
}

static void test_close_domain_socket(void **state) {
  struct test_state *test_state = *state;

  // close_domain_socket() should unlink the pathname in a pathname unix socket
  {
    int sock = create_domain_client(test_state->client_file_path);
    assert_return_code(sock, errno);

    assert_return_code(check_file_exists(test_state->client_file_path, NULL),
                       errno);

    assert_return_code(close_domain_socket(sock), errno);
    // should close the file descriptor
    assert_true(fcntl(sock, F_GETFD) == -1 && errno == EBADF);
    assert_int_equal(check_file_exists(test_state->client_file_path, NULL), -1);
  }

  // should handle _unnamed_ unix sockets
  {
    int sock = socket(AF_UNIX, SOCK_DGRAM, 0);
    assert_return_code(sock, errno);

    assert_return_code(close_domain_socket(sock), errno);
    // should close the file descriptor
    assert_true(fcntl(sock, F_GETFD) == -1 && errno == EBADF);
  }

  // should cleanup tmp unix sockets created via create_domain_client(NULL)
  {
    int sock = create_domain_client(NULL);
    assert_return_code(sock, errno);

    struct sockaddr_un sockaddr = {0};
    socklen_t address_len = sizeof(sockaddr);
    getsockname(sock, (struct sockaddr *)&sockaddr, &address_len);

#ifdef USE_ABSTRACT_UNIX_DOMAIN_SOCKETS
    assert_int_equal(sockaddr.sun_path[0], '\0');
    // abstract unix domain sockets don't have any temporary
    // folders in the file system to cleanup
    assert_return_code(close_domain_socket(sock), errno);
#else  /* USE_ABSTRACT_UNIX_DOMAIN_SOCKETS */
    assert_int_not_equal(sockaddr.sun_path[0], '\0');
    // test if temporary mkdtemp folder is properly cleaned up
    char folder[sizeof(sockaddr.sun_path)];
    strcpy(folder, sockaddr.sun_path);
    // converts the last `/` to a null char to terminate the string and find the
    // parent dir
    char *last_slash = strrchr(folder, '/');
    if (last_slash) {
      *last_slash = '\0';
    }
    // mkdtemp folder should exist before close_domain_socket
    assert_int_equal(exist_dir(folder), 1);

    assert_return_code(close_domain_socket(sock), errno);

    // mkdtemp folder should be deleted by close_domain_socket
    assert_int_equal(exist_dir(folder), 0);
#endif /* USE_ABSTRACT_UNIX_DOMAIN_SOCKETS */

    // should close the file descriptor
    assert_true(fcntl(sock, F_GETFD) == -1 && errno == EBADF);
  }

  // should report an error if the input file descriptor is not valid
  assert_int_equal(close_domain_socket(-1), -1);

  // should report an error if the given file descriptor is not an UNIX domain
  // socket
  {
    int sock = create_udp_server(0);
    assert_return_code(sock, errno);

    assert_int_equal(close_domain_socket(sock), -1);
    // cleanup
    assert_return_code(close(sock), errno);
  }

  // should throw an error if the unlink() command fails
  {
    int sock = create_domain_client(test_state->client_file_path);
    assert_return_code(sock, errno);

    assert_return_code(check_file_exists(test_state->client_file_path, NULL),
                       errno);
    assert_return_code(unlink(test_state->client_file_path), errno);

    // should fail, since unix domain socket path is already unlink()-ed
    assert_int_equal(close_domain_socket(sock), -1);
    assert_return_code(close(sock), errno);
  }
}

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
      cmocka_unit_test_setup_teardown(test_create_domain_server, setup,
                                      teardown),
      cmocka_unit_test_setup_teardown(test_create_domain_client, setup,
                                      teardown),
      cmocka_unit_test_setup_teardown(test_close_domain_socket, setup,
                                      teardown),
      cmocka_unit_test_setup_teardown(test_read_domain_data_s, setup, teardown),
      cmocka_unit_test_setup_teardown(test_write_domain_data_s, setup,
                                      teardown),
      cmocka_unit_test(test_create_udp_server),
      cmocka_unit_test(test_write_socket_data)};

  return cmocka_run_group_tests(tests, NULL, NULL);
}
