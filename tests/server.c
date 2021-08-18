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
  struct sockaddr_un svaddr;
  int sfd;
  char *server_path = "./tt.sock";
  char data[10];
  struct sockaddr_un unaddr;
  int addr_len = sizeof(struct sockaddr_un);

  sfd = socket(AF_UNIX, SOCK_DGRAM, 0);       /* Create server socket */
  if (sfd == -1) {
    printf("socket error\n");
    return -1;
  }


  /* Construct well-known address and bind server socket to it */

  /* For an explanation of the following check, see the erratum note for
     page 1168 at http://www.man7.org/tlpi/errata/.
  */
  if (strlen(server_path) > sizeof(svaddr.sun_path) - 1) {
    printf("Server socket path too long: %s\n", server_path);
    return -1;
  }

  if (remove(server_path) == -1 && errno != ENOENT) {
    printf("remove-%s\n", server_path);
    return -1;
  }

  init_domain_addr(&svaddr, server_path);

  if (bind(sfd, (struct sockaddr *) &svaddr, sizeof(struct sockaddr_un)) == -1) {
    printf("bind error");
    return -1;
  }

  ssize_t num_bytes = recvfrom(sfd, data, 1, 0, (struct sockaddr *) &unaddr, &addr_len);
  if (num_bytes == -1) {
    printf("recvfrom error");
    return -1;
  }

  printf("num_bytes=%ld addr_len=%d", num_bytes, addr_len);

  errno = 0;
  if ((num_bytes = sendto(sfd, data, 1, 0, (struct sockaddr *) &unaddr, addr_len)) < 0) {
    printf("sendto error\n");
    return -1;
  }

  close(sfd);
  return 0;
}