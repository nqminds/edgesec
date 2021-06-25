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

#include "utils/domain.h"
#include "utils/hashmap.h"
#include "utils/utarray.h"
#include "utils/log.h"

#define TMP_PFX "tdoms"

int create_client(char *path)
{
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

  if (bind(sock, (struct sockaddr *) &claddr, sizeof(struct sockaddr_un)) == -1) {
    perror("bind");
    exit(1);
  }

  return sock;
}

static void test_create_domain_server(void **state)
{
  (void) state; /* unused */

  char *temp_file_path = tempnam(NULL, TMP_PFX);

  assert_non_null(temp_file_path);

  int sock = create_domain_server(temp_file_path);

  assert_int_not_equal(sock, -1);
  if (temp_file_path)
    free(temp_file_path);

  close(sock);
}

static void test_read_domain_data(void **state)
{
  (void) state; /* unused */

  struct sockaddr_un svaddr;
  char *send_buf = "domain";
  char read_buf[100];
  char client_addr[100];

  char *server_file_path = tempnam(NULL, TMP_PFX);
  char *client_file_path = tempnam(NULL, TMP_PFX);

  int server_sock = create_domain_server(server_file_path);

  assert_int_not_equal(server_sock, -1);

  int client_sock = create_client(client_file_path);
  assert_int_not_equal(client_sock, -1);

  memset(&svaddr, 0, sizeof(struct sockaddr_un));
  svaddr.sun_family = AF_UNIX;
  strcpy(svaddr.sun_path, server_file_path);
  int buf_len = strlen(send_buf) + 1; 
  ssize_t ret = sendto(client_sock, send_buf, buf_len, 0, (struct sockaddr *) &svaddr, sizeof(struct sockaddr_un));
  assert_int_equal(ret, buf_len);

  ret = read_domain_data(server_sock, read_buf, 100, client_addr, 0);

  assert_int_equal(ret, buf_len);
  assert_string_equal(send_buf, read_buf);
  assert_string_equal(client_addr, client_file_path);

  free(server_file_path);
  free(client_file_path);
  close(server_sock);
  close(client_sock);
}

static void test_write_domain_data(void **state)
{
  (void) state; /* unused */

  struct sockaddr_un svaddr;
  char *send_buf = "domain";
  char read_buf[100];

  char *server_file_path = tempnam(NULL, TMP_PFX);
  char *client_file_path = tempnam(NULL, TMP_PFX);

  int server_sock = create_domain_server(server_file_path);

  assert_int_not_equal(server_sock, -1);

  int client_sock = create_client(client_file_path);
  assert_int_not_equal(client_sock, -1);

  int buf_len = strlen(send_buf) + 1; 
  ssize_t ret = write_domain_data(server_sock, send_buf, buf_len, client_file_path);
  assert_int_equal(ret, buf_len);

  socklen_t len = sizeof(struct sockaddr_un);
  ret = recvfrom(client_sock, read_buf, 100, 0, (struct sockaddr *) &svaddr, &len);

  assert_int_equal(ret, buf_len);
  assert_string_equal(send_buf, read_buf);

  free(server_file_path);
  free(client_file_path);
  close(server_sock);
  close(client_sock);
}

int main(int argc, char *argv[])
{  
  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_create_domain_server),
    cmocka_unit_test(test_read_domain_data),
    cmocka_unit_test(test_write_domain_data)
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
