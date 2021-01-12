/**************************************************************************************************
*  Filename:        if_service.h
*  Author:          Alexandru Mereacre (mereacre@gmail.com)
*  Revised:
*  Revision:
*
*  Description:     if_service include file
*
*  Copyright (C) 2020 NQMCyber Ltd - http://www.nqmcyber.com/
*************************************************************************************************/

#ifndef IF_SERVICE_H
#define IF_SERVICE_H

#include <inttypes.h>
#include <stdbool.h>

#include "utils/if.h"

bool create_subnet_ifs(UT_array *ifinfo_array, char *subnet_mask, bool ignore_error);

bool is_iw_vlan(const char *ap_interface);
char* get_valid_iw(char *if_buf);
bool get_nat_if_ip(const char *nat_interface, char **ip_buf);

#endif