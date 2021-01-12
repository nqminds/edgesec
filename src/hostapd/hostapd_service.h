/**************************************************************************************************
*  Filename:        hostapd_service.h
*  Author:          Alexandru Mereacre (mereacre@gmail.com)
*  Revised:
*  Revision:
*
*  Description:     hostapd_service include file
*
*  Copyright (C) 2020 NQMCyber Ltd - http://www.nqmcyber.com/
*************************************************************************************************/

#ifndef HOSTAPD_SERVICE_H
#define HOSTAPD_SERVICE_H

#include <sys/types.h>
#include <linux/if.h>
#include <stdbool.h>

#include "config_generator.h"
#include "../radius/radius_server.h"
#include "../utils/os.h"
#include "../utils/if.h"

int run_hostapd(struct hostapd_conf *hconf, struct radius_conf *rconf, bool exec_hostapd, char *ctrl_if_path);
bool close_hostapd(int sock);

#endif