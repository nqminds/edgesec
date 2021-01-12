/**************************************************************************************************
*  Filename:        engine.c
*  Author:          Alexandru Mereacre (mereacre@gmail.com)
*  Revised:
*  Revision:
*
*  Description:     engine include file
*
*  Copyright (C) 2020 NQMCyber Ltd - http://www.nqmcyber.com/
*************************************************************************************************/

#ifndef ENGINE_H
#define ENGINE_H

#include <net/if.h>
#include <inttypes.h>
#include <stdbool.h>

#include "utils/utarray.h"
#include "utils/hashmap.h"
#include "utils/os.h"
#include "hostapd/config_generator.h"
#include "radius/radius_server.h"
#include "if_service.h"
#include "supervisor/mac_mapper.h"

struct app_config {
  UT_array            *bin_path_array;
  bool                ap_detect;
  bool                exec_hostapd;
  bool                exec_radius;
  char                nat_interface[IFNAMSIZ];
  bool                create_interfaces;
  bool                ignore_if_error;
  int                 default_open_vlanid;
  UT_array            *config_ifinfo_array;
  char                subnet_mask[IP_LEN];
  char                domain_server_path[MAX_OS_PATH_LEN];
  bool                allow_all_connections;
  UT_array            *connections;
  struct radius_conf  rconfig;
  struct hostapd_conf hconfig;
};

bool run_engine(struct app_config *app_config, uint8_t log_level);

#endif