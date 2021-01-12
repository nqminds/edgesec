/**************************************************************************************************
*  Filename:        iptables.h
*  Author:          Alexandru Mereacre (mereacre@gmail.com)
*  Revised:
*  Revision:
*
*  Description:     iptables include file
*
*  Copyright (C) 2020 NQMCyber Ltd - http://www.nqmcyber.com/
*************************************************************************************************/

#ifndef IPTABLES_H_
#define IPTABLES_H_

#include <inttypes.h>
#include <stdbool.h>

bool init_iptables(char *path, UT_array *ifinfo_array);
void free_iptables(void);

bool add_bridge_rules(char *sip, char *sif, char *dip, char *dif);
bool delete_bridge_rules(char *sip, char *sif, char *dip, char *dif);
bool add_nat_rules(char *sip, char *sif, char *nif);
bool delete_nat_rules(char *sip, char *sif, char *nif);

#endif