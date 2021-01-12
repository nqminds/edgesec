/**************************************************************************************************
*  Filename:        cmd_processor.h
*  Author:          Alexandru Mereacre (mereacre@gmail.com)
*  Revised:
*  Revision:
*
*  Description:     cmd_processor include file
*
*  Copyright (C) 2020 NQMCyber Ltd - http://www.nqmcyber.com/
*************************************************************************************************/

#ifndef CMD_PROCESSOR_H
#define CMD_PROCESSOR_H

#include <sys/types.h>
#include <stdbool.h>

#include "utils/utarray.h"

#define CMD_DELIMITER   		0x20

#define CMD_PING        		"PING"
#define CMD_HOSTAPD_CTRLIF  "HOSTAPD_IF"
#define CMD_ACCEPT_MAC			"ACCEPT_MAC"
#define CMD_DENY_MAC				"DENY_MAC"
#define CMD_ADD_NAT					"ADD_NAT"
#define CMD_REMOVE_NAT			"REMOVE_NAT"
#define CMD_ASSIGN_PSK			"ASSIGN_PSK"
#define CMD_GET_MAP					"GET_MAP"
#define CMD_GET_ALL					"GET_ALL"
#define CMD_SAVE_ALL				"SAVE_ALL"
#define CMD_SET_IP				  "SET_IP"
#define CMD_ADD_BRIDGE			"ADD_BRIDGE"
#define CMD_REMOVE_BRIDGE		"REMOVE_B RIDGE"

char *find_buffer_end(char *domain_buffer, size_t domain_buffer_len);

bool process_domain_buffer(char *domain_buffer, size_t domain_buffer_len, UT_array *cmd_arr);

#endif