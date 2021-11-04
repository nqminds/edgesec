/*
    This file is part of mDNS Reflector (mdns-reflector), a lightweight and performant multicast DNS (mDNS) reflector.
    Copyright (C) 2021 Yuxiang Zhu <me@yux.im>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <libgen.h>
#include <syslog.h>
#include <sys/param.h>

#include "../utils/log.h"
#include "../utils/eloop.h"

#include "options.h"
#include "reflection_list.h"
#include "reflector.h"

static int parse_args(const char *program, int argc, char *argv[], struct options *options) {
  int ch;
  unsigned int ifindex;
  const char *ifname;
  while ((ch = getopt(argc, argv, "hdfp:n64l:")) != -1) {
    switch (ch) {
      case 'h':
        options->help = true;
        break;
      case 'd':
        options->debug = true;
        options->log_level = LOG_DEBUG;
        break;
      case '6':
        options->ipv6_only = true;
        break;
      case '4':
        options->ipv4_only = true;
        break;
      case '?':
      default:
        errno = EINVAL;
        return -1;
    }
  }

  if (options->help)
    return 0;

  if (options->ipv6_only && options->ipv4_only) {
    fputs("ERROR: '-6' and '-4' are mutually exclusive.\n", stderr);
    return -1;
  }

  for (int i = 0; i < argc - optind; ++i) {
    ifname = argv[optind + i];
    if ((ifindex = if_nametoindex(ifname)) == 0) {
      log_debug("%s: unknown interface %s", program, ifname);
      return -1;
    }
    if (!options->ipv4_only) {
      // new IPv6 reflection interface
      if (push_reflection_list(options->rif6, ifindex, ifname) == NULL) {
        log_trace("push_reflection_list fail");
        return -1;
      }
    }
    if (!options->ipv6_only) {
      // new IPv4 reflection interface
      log_trace("Pushing ifname=%s ifindex=%d", ifname, ifindex);
      if (push_reflection_list(options->rif4, ifindex, ifname) == NULL) {
        log_trace("push_reflection_list fail");
        return -1;
      }
    }
  }

  return 0;
}

static void usage(const char *program, FILE *file) {
  fprintf(file, "mDNS Reflector version %s\n", "0.0.1-dev");
  fputs("Copyright (C) 2021 Yuxiang Zhu <me@yux.im>\n\n", file);
  fprintf(file, "usage: %s [OPTION]... <IFNAME> <IFNAME>...\n", program);
  fprintf(file, "   or: %s [OPTION]... <IFNAME> <IFNAME>... [-- <IFNAME> <IFNAME>...]...\n", program);
  fprintf(file, "Use '--' to separate reflection zones. A mDNS packet coming from an interface will only ");
  fprintf(file, "be reflected to other interfaces within the same zone.\n");
  fprintf(file, "\n");
  fprintf(file, "Examples:\n");
  fprintf(file, "  # Reflect between eth0 and eth1\n");
  fprintf(file, "  %s eth0 eth1\n", program);
  fprintf(file, "  # Reflect 2 zones. br-lan0, br-lan1 and br-lan2 are in one zone. br-lan3 br-lan4 are in the other zone.\n");
  fprintf(file, "  %s br-lan0 br-lan1 br-lan2 -- br-lan3 br-lan4\n", program);
  fprintf(file, "\n");
  fprintf(file, "Options\n");  // hdfp:n64l:
  fprintf(file, " -d\tdebug mode (implies -f -n -l debug)\n");
  fprintf(file, " -f\tforeground mode\n");
  fprintf(file, " -n\tdon't create PID file\n");
  fprintf(file, " -l\tset logging level (debug, info, warning, error; default is warning)\n");
  fprintf(file, " -4\tIPV4 only mode (disable IPv6 support)\n");
  fprintf(file, " -6\tIPV6 only mode (disable IPv4 support)\n");
  fprintf(file, " -h\tshow this help\n");
  fprintf(file, "\n");
  fprintf(file, "See https://github.com/vfreex/mdns-reflector for updates, bug reports, and answers\n");
}

int main(int argc, char *argv[]) {
  char program[MAXPATHLEN];
  struct options options;

  memset(&options, 0, sizeof(struct options));

  if (eloop_init() < 0) {
	fprintf(stderr, "Failed to initialize event loop");
	return EXIT_FAILURE;
  }

  log_set_quiet(false);
  log_set_level(0);

  if ((options.rif4 = init_reflection_list()) == NULL) {
    log_trace("init_reflection_list fail");
    eloop_destroy();
    return EXIT_FAILURE;
  }

  if ((options.rif6 = init_reflection_list()) == NULL) {
    log_trace("init_reflection_list fail");
    free_reflection_list(options.rif6);
    eloop_destroy();
    return EXIT_FAILURE;
  }

  snprintf(program, sizeof(program), "%s", basename(argv[0]));
  if (parse_args(program, argc, argv, &options) == -1) {
      fprintf(stderr, "\nRun '%s -h' for help.\n", program);
      free_reflection_list(options.rif4);
      free_reflection_list(options.rif6);
      eloop_destroy();
      return EXIT_FAILURE;
  }

  if (options.help) {
      usage(program, stdout);
      free_reflection_list(options.rif4);
      free_reflection_list(options.rif6);
      eloop_destroy();
      return EXIT_SUCCESS;
  }

  int r = run_event_loop(&options);

  free_reflection_list(options.rif4);
  free_reflection_list(options.rif6);
  eloop_destroy();
  return r;
}
