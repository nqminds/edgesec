#include <stdio.h>
#include <string.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>

void init_domain_addr(struct sockaddr_un *unaddr, char *addr)
{
  memset(unaddr, 0, sizeof(struct sockaddr_un));
  unaddr->sun_family = AF_UNIX;
  strncpy(unaddr->sun_path, addr, sizeof(unaddr->sun_path));
}

int main(void)
{
  char *str = "xyz";
  struct sockaddr_un claddr;
  int sock;

  char *server_path = "./tt.sock";
  char data[10];
  struct sockaddr_un unaddr;
  int addr_len = sizeof(struct sockaddr_un);
  ssize_t num_bytes;

  sock = socket(AF_UNIX, SOCK_DGRAM, 0);
  if (sock == -1) {
    printf("socket error\n");
    return -1;
  }

  memset(&claddr, 0, sizeof(struct sockaddr_un));
  claddr.sun_family = AF_UNIX;

  strncpy(&claddr.sun_path[1], str, strlen(str));

  if (bind(sock, (struct sockaddr *) &claddr, sizeof(sa_family_t) + strlen(str) + 1) == -1) {
    printf("bind error\n");
    return -1;
  }

  init_domain_addr(&unaddr, server_path);

  errno = 0;
  if ((num_bytes = sendto(sock, data, 1, 0, (struct sockaddr *) &unaddr, addr_len)) < 0) {
    printf("sendto error\n");
    return -1;
  }

  num_bytes = recvfrom(sock, data, 1, 0, (struct sockaddr *) &unaddr, &addr_len);
  if (num_bytes == -1) {
    printf("recvfrom error");
    return -1;
  }

  printf("num_bytes=%ld addr_len=%d", num_bytes, addr_len);

  close(sock);
  return 0;
}