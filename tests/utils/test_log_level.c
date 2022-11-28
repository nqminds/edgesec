#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

#include "utils/log.h"

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  log_trace("Hello %s", "world");
  log_debug("Hello %s", "world");
  log_info("Hello %s", "world");
  log_warn("Hello %s", "world");
  exit(0);
}
