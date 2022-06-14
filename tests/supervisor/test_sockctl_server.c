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
#include <sys/un.h>
#include <sys/socket.h>
#include <ctype.h>

#include "utils/sockctl.h"
#include "utils/hashmap.h"
#include "utils/utarray.h"
#include "utils/log.h"
#include "utils/allocs.h"
#include "utils/os.h"

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

static void test_create_domain_server(void **state) {
  (void)state; /* unused */

  char *temp_file_path = tempnam(NULL, TMP_PFX);

  assert_non_null(temp_file_path);

  int sock = create_domain_server(temp_file_path);

  assert_int_not_equal(sock, -1);
  if (temp_file_path)
    os_free(temp_file_path);

  close(sock);
}

static void test_create_domain_client(void **state) {
  (void)state; /* unused */

  char *temp_file_path = tempnam(NULL, TMP_PFX);

  assert_non_null(temp_file_path);

  int sock = create_domain_client(temp_file_path);

  assert_int_not_equal(sock, -1);
  if (temp_file_path) {
    os_free(temp_file_path);
  }

  close(sock);

  sock = create_domain_client(NULL);
  assert_int_not_equal(sock, -1);
  close(sock);
}

static void test_read_domain_data_s(void **state) {
  (void)state; /* unused */

  struct client_address addr;
  struct sockaddr_un svaddr;
  char *send_buf = "domain";
  char read_buf[100];
  char client_addr[100];

  char *server_file_path = tempnam(NULL, TMP_PFX);
  char *client_file_path = tempnam(NULL, TMP_PFX);

  int server_sock = create_domain_server(server_file_path);

  assert_int_not_equal(server_sock, -1);

  int client_sock = create_domain_client(client_file_path);
  assert_int_not_equal(client_sock, -1);

  memset(&svaddr, 0, sizeof(struct sockaddr_un));
  svaddr.sun_family = AF_UNIX;
  strcpy(svaddr.sun_path, server_file_path);
  int buf_len = strlen(send_buf) + 1;
  ssize_t ret = sendto(client_sock, send_buf, buf_len, 0,
                       (struct sockaddr *)&svaddr, sizeof(struct sockaddr_un));
  assert_int_equal(ret, buf_len);

  ret = read_domain_data_s(server_sock, read_buf, 100, client_addr, 0);

  assert_int_equal(ret, buf_len);
  assert_string_equal(send_buf, read_buf);
  assert_string_equal(client_addr, client_file_path);

  os_free(client_file_path);

  client_sock = create_domain_client(NULL);
  assert_int_not_equal(client_sock, -1);

  ret = sendto(client_sock, send_buf, buf_len, 0, (struct sockaddr *)&svaddr,
               sizeof(struct sockaddr_un));
  assert_int_equal(ret, buf_len);

  os_memset(&addr, 0, sizeof(struct client_address));
  ret = read_socket_data(server_sock, read_buf, 100, &addr, 0);
  assert_int_equal(ret, buf_len);
  assert_string_equal(send_buf, read_buf);

  ret = sendto(server_sock, send_buf, buf_len, 0,
               (struct sockaddr *)&addr.addr_un, addr.len);
  assert_int_equal(ret, buf_len);

  os_memset(&addr, 0, sizeof(struct client_address));
  ret = read_socket_data(client_sock, read_buf, 100, &addr, 0);
  assert_int_equal(ret, buf_len);
  assert_string_equal(send_buf, read_buf);

  close(client_sock);

  os_free(server_file_path);
  close(server_sock);
}

static void test_write_domain_data(void **state) {
  (void)state; /* unused */

  struct client_address addr;
  struct sockaddr_un svaddr;
  struct sockaddr_un claddr;
  char *send_buf = "domain";
  char read_buf[100];

  char *server_file_path = tempnam(NULL, TMP_PFX);
  char *client_file_path = tempnam(NULL, TMP_PFX);

  int server_sock = create_domain_server(server_file_path);

  assert_int_not_equal(server_sock, -1);

  int client_sock = create_domain_client(client_file_path);
  assert_int_not_equal(client_sock, -1);

  int buf_len = strlen(send_buf) + 1;
  ssize_t ret =
      write_domain_data_s(server_sock, send_buf, buf_len, client_file_path);
  assert_int_equal(ret, buf_len);

  socklen_t len = sizeof(struct sockaddr_un);
  os_memset(&svaddr, 0, sizeof(struct sockaddr_un));
  ret =
      recvfrom(client_sock, read_buf, 100, 0, (struct sockaddr *)&svaddr, &len);

  assert_int_equal(ret, buf_len);
  assert_string_equal(send_buf, read_buf);

  os_free(client_file_path);
  close(client_sock);

  client_sock = create_domain_client(NULL);
  assert_int_not_equal(client_sock, -1);

  os_memcpy(&addr.addr_un, &svaddr, sizeof(struct sockaddr_un));
  addr.len = len;
  ret = write_socket_data(client_sock, send_buf, buf_len, &addr);
  assert_int_equal(ret, buf_len);

  len = sizeof(struct sockaddr_un);
  ret =
      recvfrom(server_sock, read_buf, 100, 0, (struct sockaddr *)&claddr, &len);
  assert_int_equal(ret, buf_len);
  assert_string_equal(send_buf, read_buf);

  close(client_sock);
  os_free(server_file_path);
  close(server_sock);
}

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_create_domain_server),
      cmocka_unit_test(test_create_domain_client),
      cmocka_unit_test(test_read_domain_data_s),
      cmocka_unit_test(test_write_domain_data)};

  return cmocka_run_group_tests(tests, NULL, NULL);
}
