/**************************************************************************************************
*  Filename:        system_checks.h
*  Author:          Alexandru Mereacre (mereacre@gmail.com)
*  Revised:
*  Revision:
*
*  Description:     system_checks include file
*
*  Copyright (C) 2020 NQMCyber Ltd - http://www.nqmcyber.com/
*************************************************************************************************/

#ifndef SYSTEM_CHECKS_H
#define SYSTEM_CHECKS_H

#include <inttypes.h>
#include <stdbool.h>

#include "utils/utarray.h"
#include "utils/hashmap.h"

hmap_str_keychar *check_systems_commands(char *commands[], UT_array *bin_path_arr, hmap_str_keychar *hmap_bin_hashes);

#endif