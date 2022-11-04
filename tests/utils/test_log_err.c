#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <limits.h>

#include "utils/log.h"

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  log_errno("Hello %s", "world");

  errno = INT_MAX;
  log_errno("Should handle invalid errno value");

  exit(0);
}
