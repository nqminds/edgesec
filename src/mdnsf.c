/****************************************************************************
 * Copyright (C) 2021 by NQMCyber Ltd                                       *
 *                                                                          *
 * This file is part of EDGESec.                                            *
 *                                                                          *
 *   EDGESec is free software: you can redistribute it and/or modify it     *
 *   under the terms of the GNU Lesser General Public License as published  *
 *   by the Free Software Foundation, either version 3 of the License, or   *
 *   (at your option) any later version.                                    *
 *                                                                          *
 *   EDGESec is distributed in the hope that it will be useful,             *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of         *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the          *
 *   GNU Lesser General Public License for more details.                    *
 *                                                                          *
 *   You should have received a copy of the GNU Lesser General Public       *
 *   License along with EDGESec. If not, see <http://www.gnu.org/licenses/>.*
 ****************************************************************************/

/**
 * @file mdnsf.c 
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of the mdns forwarder.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <fcntl.h>
#include <ctype.h>
#include <unistd.h>
#include <pthread.h>
#include <stdbool.h>
#include <errno.h>
#include <linux/if.h>
#include <libgen.h>
#include <pcap.h>

#include "dns/dns_config.h"
#include "dns/mdns_service.h"
#include "config.h"
#include "version.h"
#include "utils/log.h"
#include "utils/allocs.h"
#include "utils/os.h"
#include "utils/minIni.h"
#include "utils/squeue.h"
#include "utils/iface_mapper.h"

static __thread char version_buf[10];

pthread_mutex_t log_lock;

void log_lock_fun(bool lock)
{
  if (lock) {
    pthread_mutex_lock(&log_lock);
  } else {
    pthread_mutex_unlock(&log_lock);
  }
}

char *get_static_version_string(uint8_t major, uint8_t minor, uint8_t patch)
{
  int ret = snprintf(version_buf, 10, "%d.%d.%d", major, minor, patch);

  if (ret < 0) {
    fprintf(stderr, "snprintf");
    return NULL;
  }

  return version_buf;
}

int show_app_version(void)
{
  fprintf(stdout, "mdnsf app version %s\n",
    get_static_version_string(MDNSF_VERSION_MAJOR,MDNSF_VERSION_MINOR,MDNSF_VERSION_PATCH));
  return 1;
}

int show_app_help(char *app_name)
{
  show_app_version();
  fprintf(stdout, "Usage:\n");
  fprintf(stdout, MDNS_USAGE_STRING, basename(app_name));
  fprintf(stdout, "\n%s", MDNS_DESCRIPTION);
  fprintf(stdout, "\nOptions:\n");
  fprintf(stdout, "%s", MDNS_OPT_DEFS);
  fprintf(stdout, "Copyright NQMCyber Ltd\n");
  return 1;
}

/* Diagnose an error in command-line arguments and terminate the process */
int log_cmdline_error(const char *format, ...)
{
    va_list argList;

    fflush(stdout);           /* Flush any pending stdout */

    fprintf(stdout, "Command-line usage error: ");
    va_start(argList, format);
    vfprintf(stdout, format, argList);
    va_end(argList);

    fflush(stderr);           /* In case stderr is not line-buffered */
    return -1;
}

int process_app_options(int argc, char *argv[], uint8_t *verbosity, const char **filename)
{
  int opt;

  while ((opt = getopt(argc, argv, MDNS_OPT_STRING)) != -1) {
    switch (opt) {
    case 'd':
      (*verbosity)++;
      break;
    case 'h':
      return show_app_help(argv[0]);
    case 'v':
      return show_app_version();
    case 'c':
      *filename = optarg;
      break;
    case ':':
      return log_cmdline_error("Missing argument for -%c\n", optopt);
    case '?':
      return log_cmdline_error("Unrecognized option -%c\n", optopt);
    default: 
      return show_app_help(argv[0]);
    }
  }

  return 0;
}

int init_mdns_context(struct app_config *config, struct mdns_context *context)
{
  os_memset(context, 0, sizeof(struct mdns_context));

  context->config = config->mdns_config;
  context->pctx_list = NULL;
  os_strlcpy(context->domain_server_path, config->domain_server_path, MAX_OS_PATH_LEN);
  context->domain_delim = config->domain_delim;
  context->command_mapper = NULL;
  context->sfd = 0;

  if (!create_vlan_mapper(config->config_ifinfo_array, &context->vlan_mapper)) {
    fprintf(stderr, "create_if_mapper fail");
    return -1;
  }

  os_strlcpy(context->filter, config->mdns_config.filter, MAX_FILTER_SIZE);

  generate_radom_uuid(context->cap_id);

  if (get_hostname(context->hostname) < 0) {
    fprintf(stderr, "get_hostname fail");
    return -1;
  }

  return 0;
}

int get_interface_list_str(UT_array *config_ifinfo_array, char **ifname)
{
  struct string_queue* squeue = NULL;
  config_ifinfo_t *p = NULL;

  *ifname = NULL;

  if ((squeue = init_string_queue(-1)) == NULL) {
    fprintf(stderr, "init_string_queue fail");
    return -1;
  }

  while((p = (config_ifinfo_t *) utarray_next(config_ifinfo_array, p)) != NULL) {
    if (push_string_queue(squeue, p->ifname) < 0) {
      fprintf(stderr, "push_string_queue fail");
      free_string_queue(squeue);
      return -1;
    }
    if (push_string_queue(squeue, ",") < 0) {
      fprintf(stderr, "push_string_queue fail");
      free_string_queue(squeue);
      return -1;
    }
  }

  if ((*ifname = concat_string_queue(squeue, -1)) == NULL) {
    fprintf(stderr, "concat_string_queue fail\n");
    free_string_queue(squeue);
    return -1;
  }

  free_string_queue(squeue);
  return 0;
}

int main(int argc, char *argv[])
{
  int ret;
  uint8_t verbosity = 0;
  uint8_t level = 0;
  const char *filename = NULL;
  struct app_config config;
  struct mdns_context context;

  // Init the mdns config struct
  memset(&config, 0, sizeof(struct mdns_conf));
  memset(&context, 0, sizeof(struct mdns_context));

  ret = process_app_options(argc, argv, &verbosity, &filename);

  if (ret < 0) {
    fprintf(stderr, "process_app_options fail");
    return EXIT_FAILURE;
  } else if (ret > 0) {
    return EXIT_SUCCESS;
  }

  if (optind <= 1) {
    show_app_help(argv[0]);
    return EXIT_SUCCESS;
  }

  if (verbosity > MAX_LOG_LEVELS) {
    level = 0;
  } else if (!verbosity) {
    level = MAX_LOG_LEVELS - 1;
  } else {
    level = MAX_LOG_LEVELS - verbosity;
  }

  log_set_lock(log_lock_fun);

  // Set the log level
  log_set_level(level);

  if (!load_system_config(filename, &config)) {
    fprintf(stderr, "load_system_config fail\n");
    return EXIT_FAILURE;
  }

  if (!load_supervisor_config(filename, &config)) {
    fprintf(stderr, "load_supervisor_config fail\n");
    return EXIT_FAILURE;
  }

  if(!load_mdns_conf(filename, &config)) {
    fprintf(stderr, "load_mdns_conf fail");
    return EXIT_FAILURE;
  }

  if(!load_interface_list(filename, &config)) {
    fprintf(stderr, "load_interface_list fail");
    return EXIT_FAILURE;
  }

  if (!load_ap_conf(filename, &config)) {
    fprintf(stderr, "load_ap_conf fail");
    return EXIT_FAILURE;
  }

  if (init_ifbridge_names(config.config_ifinfo_array, config.interface_prefix,
                          config.bridge_prefix) < 0)
  {
    fprintf(stderr, "init_ifbridge_names fail");
    return EXIT_FAILURE;
  }

  if (init_mdns_context(&config, &context) < 0) {
    fprintf(stderr, "init_mdns_context fail");
    utarray_free(config.config_ifinfo_array);
    free_vlan_mapper(&context.vlan_mapper);
    return EXIT_FAILURE;
  }

  if(get_interface_list_str(config.config_ifinfo_array, &context.ifname) < 0) {
    fprintf(stderr, "get_interface_list_str fail");
    utarray_free(config.config_ifinfo_array);
    free_vlan_mapper(&context.vlan_mapper);
    return EXIT_FAILURE;
  }

  if (pthread_mutex_init(&log_lock, NULL) != 0) {
    fprintf(stderr, "mutex init has failed\n");
    free_vlan_mapper(&context.vlan_mapper);
    utarray_free(config.config_ifinfo_array);
    os_free(context.ifname);
    return EXIT_FAILURE;
  }

  if (run_mdns(&context) < 0) {
    fprintf(stderr, "run_mdns has failed\n");
    free_vlan_mapper(&context.vlan_mapper);
    utarray_free(config.config_ifinfo_array);
    os_free(context.ifname);
    return EXIT_FAILURE;
  }

  pthread_mutex_destroy(&log_lock);
  utarray_free(config.config_ifinfo_array);
  free_vlan_mapper(&context.vlan_mapper);
  os_free(context.ifname);

  return EXIT_SUCCESS;
}