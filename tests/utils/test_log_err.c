#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "utils/log.h"

int main(int argc, char *argv[]) {
    log_err("Hello %s", "world");
    exit(0);
}
