/**************************************************************************************************
*  Filename:        supervisor.h
*  Author:          Alexandru Mereacre (mereacre@gmail.com)
*  Revised:
*  Revision:
*
*  Description:     supervisor include file
*
*  Copyright (C) 2020 NQMCyber Ltd - http://www.nqmcyber.com/
*************************************************************************************************/

#ifndef SUPERVISOR_H
#define SUPERVISOR_H

#include <stdbool.h>
#include "../hostapd/config_generator.h"
#include "../utils/if.h"

#include "mac_mapper.h"

#define MAX_DOMAIN_RECEIVE_DATA 1024


struct supervisor_context {
  hmap_mac_conn   *mac_mapper;
  hmap_if_conn    *if_mapper;
  bool            allow_all_connections;
  char            hostapd_ctrl_if_path[MAX_OS_PATH_LEN];
  char            wpa_passphrase[HOSTAPD_AP_SECRET_LEN];
  char            nat_interface[IFNAMSIZ];
  char            subnet_mask[IP_LEN];
  int             default_open_vlanid;
  UT_array        *config_ifinfo_array;
};

int run_supervisor(char *server_path, struct supervisor_context *context);
bool close_supervisor(int sock);

#endif