/**************************************************************************************************
*  Filename:        config_generator.h
*  Author:          Alexandru Mereacre (mereacre@gmail.com)
*  Revised:
*  Revision:
*
*  Description:     config_generator include file
*
*  Copyright (C) 2020 NQMCyber Ltd - http://www.nqmcyber.com/
*************************************************************************************************/

#ifndef CONFIG_GENERATOR_H
#define CONFIG_GENERATOR_H

#include <sys/types.h>
#include <net/if.h>
#include <stdbool.h>

#include "../utils/os.h"
#include "../radius/radius_server.h"

#define HOSTAPD_AP_NAME_LEN       32
#define HOSTAPD_AP_SECRET_LEN     64
#define HOSTAPD_DRIVE_LEN         20
#define HOSTAPD_HWMODE_LEN        4
#define HOSTAPD_WPA_KEY_MGMT_LEN  20
#define HOSTAPD_RSN_PAIRWISE_LEN  20

struct hostapd_conf {
  char hostapd_bin_path[MAX_OS_PATH_LEN];
  char hostapd_file_path[MAX_OS_PATH_LEN];
  char interface[IFNAMSIZ];
  char ssid[HOSTAPD_AP_NAME_LEN];
  char wpa_passphrase[HOSTAPD_AP_SECRET_LEN];
  char bridge[IFNAMSIZ];
  char driver[HOSTAPD_DRIVE_LEN];
  char hw_mode[HOSTAPD_HWMODE_LEN];
  int channel;
  int wmm_enabled;
  int auth_algs;
  int wpa;
  char wpa_key_mgmt[HOSTAPD_WPA_KEY_MGMT_LEN];
  char rsn_pairwise[HOSTAPD_RSN_PAIRWISE_LEN];
  char ctrl_interface[MAX_OS_PATH_LEN];
  int macaddr_acl;
  int dynamic_vlan;
  char vlan_bridge[IFNAMSIZ];
  char vlan_file[MAX_OS_PATH_LEN];
  int logger_stdout;
  int logger_stdout_level;
  int logger_syslog;
  int logger_syslog_level;
  int ignore_broadcast_ssid;
  int wpa_psk_radius;
};

bool generate_hostapd_conf(struct hostapd_conf *hconf, struct radius_conf *rconf);
bool generate_vlan_conf(char *vlan_file, char *interface);

#endif