/**************************************************************************************************
*  Filename:        system_checks.c
*  Author:          Alexandru Mereacre (mereacre@gmail.com)
*  Revised:
*  Revision:
*
*  Description:     system_checks source file
*
*  Copyright (C) 2020 NQMCyber Ltd - http://www.nqmcyber.com/
*************************************************************************************************/

#include <inttypes.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <net/if.h>

#include "utils/utarray.h"
#include "utils/hashmap.h"
#include "utils/log.h"
#include "utils/if.h"
#include "utils/iw.h"
#include "utils/os.h"

hmap_str_keychar *check_systems_commands(char *commands[], UT_array *bin_path_arr, hmap_str_keychar *hmap_bin_hashes)
{
  if (commands == NULL) {
    log_debug("commands param NULL");
    return NULL;
  }

  hmap_str_keychar *hmap_bin_paths = hmap_str_keychar_new();
  
  for(uint8_t idx = 0; commands[idx] != NULL; idx ++) {
    log_debug("Checking %s command...", commands[idx]);
    char *path = get_secure_path(bin_path_arr, commands[idx], NULL);
    if (path == NULL) {
      log_debug("%s command not found", commands[idx]);
      free(path);
      return NULL;
    } else {
      log_debug("%s command found at %s", commands[idx], path);
      if(!hmap_str_keychar_put(&hmap_bin_paths, commands[idx], path)) {
        log_debug("hmap_str_keychar_put error");
        free(path);
        hmap_str_keychar_free(&hmap_bin_paths);
        return NULL;
      }
    }

    free(path);
  }

  return hmap_bin_paths;
}

void check_iptables(void)
{

}

void check_dnsmasq_service(void)
{

}
