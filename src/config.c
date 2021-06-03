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
 * @file config.c 
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of the app configuration utilities.
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

#include "utils/os.h"
#include "utils/minIni.h"
#include "utils/utarray.h"
#include "config.h"

bool get_config_dhcpinfo(char *info, config_dhcpinfo_t *el)
{
  UT_array *info_arr;
  utarray_new(info_arr, &ut_str_icd);

  split_string_array(info, ',', info_arr);

  if (!utarray_len(info_arr))
    goto err;

  char **p = NULL;
  p = (char**) utarray_next(info_arr, p);
  if (*p != NULL) {
    el->vlanid = (int) strtol(*p, NULL, 10);
    if (errno == EINVAL)
      goto err;
  } else
    goto err;

  p = (char**) utarray_next(info_arr, p);
  if (*p != NULL) {
    strcpy(el->ip_addr_low, *p);
  } else
    goto err;

  p = (char**) utarray_next(info_arr, p);
  if (*p != NULL)
    strcpy(el->ip_addr_upp, *p);
  else
    goto err;

  p = (char**) utarray_next(info_arr, p);
  if (*p != NULL)
    strcpy(el->subnet_mask, *p);
  else
    goto err;

  p = (char**) utarray_next(info_arr, p);
  if (*p != NULL)
    strcpy(el->lease_time, *p);
  else
    goto err;

  utarray_free(info_arr);
  return true;

err:
  utarray_free(info_arr);
  return false;
}

bool get_config_ifinfo(char *info, config_ifinfo_t *el)
{
  UT_array *info_arr;
  utarray_new(info_arr, &ut_str_icd);

  split_string_array(info, ',', info_arr);

  if (!utarray_len(info_arr))
    goto err;

  char **p = NULL;
  p = (char**) utarray_next(info_arr, p);
  if (*p != NULL) {
    el->vlanid = (int) strtol(*p, NULL, 10);
    if (errno == EINVAL)
      goto err;
  } else
    goto err;

  p = (char**) utarray_next(info_arr, p);
  if (*p != NULL) {
    strcpy(el->ip_addr, *p);
  } else
    goto err;

  p = (char**) utarray_next(info_arr, p);
  if (*p != NULL)
    strcpy(el->brd_addr, *p);
  else
    goto err;

  p = (char**) utarray_next(info_arr, p);
  if (*p != NULL)
    strcpy(el->subnet_mask, *p);
  else
    goto err;

  utarray_free(info_arr);
  return true;

err:
  utarray_free(info_arr);
  return false;
}

bool get_connection_info(char *info, struct mac_conn *el)
{
  UT_array *info_arr;
  utarray_new(info_arr, &ut_str_icd);

  split_string_array(info, ',', info_arr);

  if (!utarray_len(info_arr))
    goto err;

  char **p = NULL;

  p = (char**) utarray_next(info_arr, p);
  if (*p != NULL) {
    if (strcmp(*p, "a") == 0)
      el->info.allow_connection = true;
    else if (strcmp(*p, "d") == 0)
      el->info.allow_connection = false;
    else
      goto err;
  } else
    goto err;

  p = (char**) utarray_next(info_arr, p);
  if (*p != NULL) {
    if (hwaddr_aton2(*p, el->mac_addr) == -1) {
      goto err;
    }
  } else
    goto err;

  p = (char**) utarray_next(info_arr, p);
  if (*p != NULL) {
    el->info.vlanid = (int) strtol(*p, NULL, 10);
    if (errno == EINVAL)
      goto err;
  } else
    goto err;

  p = (char**) utarray_next(info_arr, p);
  if (*p != NULL) {
    el->info.nat = (bool) strtol(*p, NULL, 10);
    if (errno == EINVAL)
      goto err;    
  } else
    goto err;

  p = (char**) utarray_next(info_arr, p);
  if (*p != NULL) {
    strncpy(el->info.pass, *p, AP_SECRET_LEN);
    el->info.pass_len = strlen(el->info.pass);
  } else
    goto err;

  os_memset(el->info.ip_addr, 0x0, IP_LEN);
  
  utarray_free(info_arr);
  return true;

err:
  utarray_free(info_arr);
  return false;
}

bool load_interface_list(const char *filename, struct app_config *config)
{
  char *key = os_malloc(INI_BUFFERSIZE);
  int idx = 0;
  while(ini_getkey("interfaces", idx++, key, INI_BUFFERSIZE, filename) > 0) {
    char *value = os_malloc(INI_BUFFERSIZE);
    ini_gets("interfaces", key, "", value, INI_BUFFERSIZE, filename);
    if (strstr(key, "if") == (char *)key) {
      config_ifinfo_t el;
      if(!get_config_ifinfo(value, &el)) {
        os_free(value);
        os_free(key);
        return false;
      }
      utarray_push_back(config->config_ifinfo_array, &el);
    }
    os_free(value);
    os_free(key);
    key = os_malloc(INI_BUFFERSIZE);
  }

  os_free(key);
  return true;
}

bool load_dhcp_list(const char *filename, struct app_config *config)
{
  char *key = os_malloc(INI_BUFFERSIZE);
  int idx = 0;
  while(ini_getkey("dhcp", idx++, key, INI_BUFFERSIZE, filename) > 0) {
    char *value = os_malloc(INI_BUFFERSIZE);
    ini_gets("dhcp", key, "", value, INI_BUFFERSIZE, filename);
    if (strstr(key, "dhcpRange") == (char *)key) {
      config_dhcpinfo_t el;
      if(!get_config_dhcpinfo(value, &el)) {
        os_free(value);
        os_free(key);
        return false;
      }
      utarray_push_back(config->dhcp_config.config_dhcpinfo_array, &el);
    }
    os_free(value);
    os_free(key);
    key = os_malloc(INI_BUFFERSIZE);
  }

  os_free(key);
  return true;
}

bool load_connection_list(const char *filename, struct app_config *config)
{
  char *key = os_malloc(INI_BUFFERSIZE);
  int idx = 0;
  while(ini_getkey("connections", idx++, key, INI_BUFFERSIZE, filename) > 0) {
    char *value = os_malloc(INI_BUFFERSIZE);
    int count = ini_gets("connections", key, "", value, INI_BUFFERSIZE, filename);
    if (count) {
      struct mac_conn el;
      if(!get_connection_info(value, &el)) {
        os_free(value);
        os_free(key);
        return false;
      }

      utarray_push_back(config->connections, &el);
    }

    os_free(value);
    os_free(key);
    key = os_malloc(INI_BUFFERSIZE);
  }

  os_free(key);
  return true;
}
bool load_radius_conf(const char *filename, struct app_config *config)
{
  char *value = os_malloc(INI_BUFFERSIZE);

  // Load radius port
  config->rconfig.radius_port = (int) ini_getl("radius", "port", 1812, filename);

  // Load radius client ip
  value = os_malloc(INI_BUFFERSIZE);
  ini_gets("radius", "clientIP", "127.0.0.1", value, INI_BUFFERSIZE, filename);

  strncpy(config->rconfig.radius_client_ip, value, IP_LEN);
  os_free(value);

  // Load radius client mask
  config->rconfig.radius_client_mask = (int) ini_getl("radius", "clientMask", 32, filename);

  // Load radius server ip
  value = os_malloc(INI_BUFFERSIZE);
  ini_gets("radius", "serverIP", "127.0.0.1", value, INI_BUFFERSIZE, filename);

  strncpy(config->rconfig.radius_server_ip, value, IP_LEN);
  os_free(value);

  // Load radius server mask
  config->rconfig.radius_server_mask = (int) ini_getl("radius", "serverMask", 32, filename);

  // Load radius secret
  value = os_malloc(INI_BUFFERSIZE);
  ini_gets("radius", "secret", "", value, INI_BUFFERSIZE, filename);
  strncpy(config->rconfig.radius_secret, value, RADIUS_SECRET_LEN);
  os_free(value);

  return true;
}

bool load_ap_conf(const char *filename, struct app_config *config)
{
  char *value = os_malloc(INI_BUFFERSIZE);

  // Load ap file path
  int ret = ini_gets("ap", "apFilePath", "", value, INI_BUFFERSIZE, filename);
  if (!ret) {
    fprintf(stderr, "apFilePath was not specified\n");
    os_free(value);
    return false;
  }

  strncpy(config->hconfig.ap_file_path, value, MAX_OS_PATH_LEN);
  os_free(value);

  // Load ap bin path
  value = os_malloc(INI_BUFFERSIZE);
  ret = ini_gets("ap", "apBinPath", "", value, INI_BUFFERSIZE, filename);
  if (!ret) {
    fprintf(stderr, "apBinPath was not specified\n");
    os_free(value);
    return false;
  }

  strncpy(config->hconfig.ap_bin_path, value, MAX_OS_PATH_LEN);
  os_free(value);

  // Load ap log path
  value = os_malloc(INI_BUFFERSIZE);
  ret = ini_gets("ap", "apLogPath", "", value, INI_BUFFERSIZE, filename);
  strncpy(config->hconfig.ap_log_path, value, MAX_OS_PATH_LEN);
  os_free(value);

  // Load ap bridge
  value = os_malloc(INI_BUFFERSIZE);
  ret = ini_gets("ap", "bridge", "", value, INI_BUFFERSIZE, filename);
  if (!ret) {
    fprintf(stderr, "ap bridge was not specified\n");
    os_free(value);
    return false;
  }

  strncpy(config->hconfig.bridge, value, IFNAMSIZ);
  os_free(value);

  // Load AP name
  value = os_malloc(INI_BUFFERSIZE);
  ret = ini_gets("ap", "ssid", "", value, INI_BUFFERSIZE, filename);
  if (!ret) {
    fprintf(stderr, "ap ssid was not specified\n");
    os_free(value);
    return false;
  }

  strncpy(config->hconfig.ssid, value, AP_NAME_LEN);
  os_free(value);

  // Load AP password
  value = os_malloc(INI_BUFFERSIZE);
  ini_gets("ap", "wpaPassphrase", "", value, INI_BUFFERSIZE, filename);

  strncpy(config->hconfig.wpa_passphrase, value, AP_SECRET_LEN);
  os_free(value);

  // Load AP interface
  value = os_malloc(INI_BUFFERSIZE);
  ret = ini_gets("ap", "interface", "", value, INI_BUFFERSIZE, filename);
  if (!ret) {
    fprintf(stderr, "AP interface was not specified\n");
    os_free(value);
    return false;
  }

  strncpy(config->hconfig.interface, value, IFNAMSIZ);
  os_free(value);

  // Load vlan_tagged_interface
  value = os_malloc(INI_BUFFERSIZE);
  ini_gets("ap", "vlanTaggedInterface", "", value, INI_BUFFERSIZE, filename);
  strncpy(config->hconfig.vlan_tagged_interface, value, IFNAMSIZ);
  os_free(value);

  // Load ap driver
  value = os_malloc(INI_BUFFERSIZE);
  ini_gets("ap", "driver", "nl80211", value, INI_BUFFERSIZE, filename);
  strncpy(config->hconfig.driver, value, AP_DRIVE_LEN);
  os_free(value);

  // Load ap hw mode
  value = os_malloc(INI_BUFFERSIZE);
  ini_gets("ap", "hwMode", "g", value, INI_BUFFERSIZE, filename);
  strncpy(config->hconfig.hw_mode, value, AP_HWMODE_LEN);
  os_free(value);

  // Load ap channel
  config->hconfig.channel = (int) ini_getl("ap", "channel", 11, filename);

  // Load ap wmmEnabled
  config->hconfig.wmm_enabled = (int) ini_getl("ap", "wmmEnabled", 1, filename);

  // Load ap authAlgs
  config->hconfig.auth_algs = (int) ini_getl("ap", "authAlgs", 1, filename);

  // Load ap wpa
  config->hconfig.wpa = (int) ini_getl("ap", "wpa", 2, filename);

  // Load ap wpaKeyMgmt
  value = os_malloc(INI_BUFFERSIZE);
  ini_gets("ap", "wpaKeyMgmt", "WPA-PSK", value, INI_BUFFERSIZE, filename);
  strncpy(config->hconfig.wpa_key_mgmt, value, AP_WPA_KEY_MGMT_LEN);
  os_free(value);

  // Load ap rsnPairwise
  value = os_malloc(INI_BUFFERSIZE);
  ini_gets("ap", "rsnPairwise", "CCMP", value, INI_BUFFERSIZE, filename);
  strncpy(config->hconfig.rsn_pairwise, value, AP_RSN_PAIRWISE_LEN);
  os_free(value);
  
  // Load ap ctrlInterface
  value = os_malloc(INI_BUFFERSIZE);
  ini_gets("ap", "ctrlInterface", "/var/run/hostapd", value, INI_BUFFERSIZE, filename);
  strncpy(config->hconfig.ctrl_interface, value, MAX_OS_PATH_LEN);
  os_free(value);

  // Load ap macaddrAcl
  config->hconfig.macaddr_acl = (int) ini_getl("ap", "macaddrAcl", 2, filename);

  // Load ap dynamicVlan
  config->hconfig.dynamic_vlan = (int) ini_getl("ap", "dynamicVlan", 1, filename);

  // Load ap vlanBridge
  value = os_malloc(INI_BUFFERSIZE);
  ret = ini_gets("ap", "vlanBridge", "", value, INI_BUFFERSIZE, filename);
  if (!ret) {
    fprintf(stderr, "ap vlanBridge was not specified\n");
    os_free(value);
    return false;
  }

  strncpy(config->hconfig.vlan_bridge, value, IFNAMSIZ);
  os_free(value);

  // Load ap vlanFile
  value = os_malloc(INI_BUFFERSIZE);
  ret = ini_gets("ap", "vlanFile", "", value, INI_BUFFERSIZE, filename);
  if (!ret) {
    fprintf(stderr, "ap vlanFile was not specified\n");
    os_free(value);
    return false;
  }

  strncpy(config->hconfig.vlan_file, value, MAX_OS_PATH_LEN);
  os_free(value);

  // Load ap loggerStdout
  config->hconfig.logger_stdout = (int) ini_getl("ap", "loggerStdout", -1, filename);

  // Load ap loggerStdoutLevel
  config->hconfig.logger_stdout_level = (int) ini_getl("ap", "loggerStdoutLevel", 0, filename);

  // Load ap loggerSyslog
  config->hconfig.logger_syslog = (int) ini_getl("ap", "loggerSyslog", -1, filename);

  // Load ap loggerStdoutLevel
  config->hconfig.logger_syslog_level = (int) ini_getl("ap", "loggerSyslogLevel", 0, filename);

  // Load ap ignoreBroadcastSsid
  config->hconfig.ignore_broadcast_ssid = (int) ini_getl("ap", "ignoreBroadcastSsid", 0, filename);

  // Load ap wpaPskRadius
  config->hconfig.wpa_psk_radius = (int) ini_getl("ap", "wpaPskRadius", 2, filename);

  return true;
}

bool load_dns_conf(const char *filename, struct app_config *config)
{
  char *value = os_malloc(INI_BUFFERSIZE);

  // Load the DNS server addresses
  ini_gets("dns", "servers", "", value, INI_BUFFERSIZE, filename);
  split_string_array(value, ',', config->dns_config.server_array);
  os_free(value);

  return true;
}

bool load_dhcp_conf(const char *filename, struct app_config *config)
{
  char *value = os_malloc(INI_BUFFERSIZE);

  // Load dhpc config file path
  int ret = ini_gets("dhcp", "dhcpConfigPath", "", value, INI_BUFFERSIZE, filename);
  if (!ret) {
    fprintf(stderr, "dhcp dhcpConfigPath was not specified\n");
    os_free(value);
    return false;
  }

  strncpy(config->dhcp_config.dhcp_conf_path, value, MAX_OS_PATH_LEN);
  os_free(value);

  // Load dhpc script file path
  value = os_malloc(INI_BUFFERSIZE);
  ret = ini_gets("dhcp", "dhcpScriptPath", "", value, INI_BUFFERSIZE, filename);
  if (!ret) {
    fprintf(stderr, "dhcp dhcpScriptPath was not specified\n");
    os_free(value);
    return false;
  }

  strncpy(config->dhcp_config.dhcp_script_path, value, MAX_OS_PATH_LEN);
  os_free(value);

  // Load the dhcprange params
  if (!load_dhcp_list(filename, config)) {
    fprintf(stderr, "load_dhcp_list parsing error\n");
    return false;
  }
  return true;
}

char load_delim(const char *filename)
{
  return (char)ini_getl("supervisor", "delim", 32, filename);
}

bool load_capture_config(const char *filename, struct capture_conf *config)
{
  char *value = os_zalloc(INI_BUFFERSIZE);

  // Load domainServerPath
  ini_gets("supervisor", "domainServerPath", "", value, INI_BUFFERSIZE, filename);
  strncpy(config->domain_server_path, value, MAX_OS_PATH_LEN);
  os_free(value);

  // Load the domain command delimiter
  if ((config->domain_delim = load_delim(filename)) == 0) {
    fprintf(stderr, "delim parsing error");
    return false;
  }

  // Load capture bin path
  value = os_zalloc(INI_BUFFERSIZE);
  int ret = ini_gets("capture", "captureBinPath", "", value, INI_BUFFERSIZE, filename);
  strncpy(config->capture_bin_path, value, MAX_OS_PATH_LEN);
  os_free(value);

  // Load dhpc config file path
  value = os_zalloc(INI_BUFFERSIZE);
  ret = ini_gets("capture", "captureInterface", "", value, INI_BUFFERSIZE, filename);
  strncpy(config->capture_interface, value, IFNAMSIZ);
  os_free(value);

  // Load the domain command value
  value = os_zalloc(INI_BUFFERSIZE);
  ret = ini_gets("capture", "command", "", value, INI_BUFFERSIZE, filename);
  strncpy(config->domain_command, value, IFNAMSIZ);
  os_free(value);

  // Load filter param
  value = os_zalloc(INI_BUFFERSIZE);
  ret = ini_gets("capture", "filter", "", value, INI_BUFFERSIZE, filename);
  if (config->filter != NULL)
    os_free(config->filter);

  config->filter = value;

  // Load promiscuous param
  config->promiscuous = (int) ini_getbool("capture", "promiscuous", 0, filename);

  // Load immediate param
  config->immediate = (int) ini_getbool("capture", "immediate", 0, filename);

  // Load bufferTimeout param
  config->buffer_timeout = (uint16_t) ini_getl("capture", "bufferTimeout", 10, filename);

  // Load processInterval param
  config->process_interval = (uint16_t) ini_getl("capture", "processInterval", 10, filename);

  // Load analyser param
  value = os_zalloc(INI_BUFFERSIZE);
  ret = ini_gets("capture", "analyser", PACKET_ANALYSER_DEFAULT, value, INI_BUFFERSIZE, filename);
  strncpy(config->analyser, value, MAX_ANALYSER_NAME_SIZE - 1);
  os_free(value);

  // Load db param
  value = os_zalloc(INI_BUFFERSIZE);
  ret = ini_gets("capture", "dbPath", "./", value, INI_BUFFERSIZE, filename);
  strncpy(config->db_path, value, MAX_OS_PATH_LEN);
  os_free(value);

  // Load fileWrite param
  config->file_write = (int) ini_getbool("capture", "fileWrite", 0, filename);

  // Load dbWrite param
  config->db_write = (int) ini_getbool("capture", "dbWrite", 0, filename);

  // Load dbSync param
  config->db_sync = (int) ini_getbool("capture", "dbSync", 0, filename);

  // Load syncAddress param
  value = os_zalloc(INI_BUFFERSIZE);
  ini_gets("capture", "dbSyncAddress", "", value, INI_BUFFERSIZE, filename);
  strncpy(config->db_sync_address, value, MAX_WEB_PATH_LEN);
  os_free(value);

  // Load syncPort param
  config->db_sync_port = (uint16_t) ini_getl("capture", "dbSyncPort", 0, filename);

  return true;
}

bool load_app_config(const char *filename, struct app_config *config)
{
  FILE *fp = fopen(filename, "rb");

  if (fp == NULL) {
    fprintf(stderr, "Couldn't open %s config file.\n", filename);
    return false;
  }

  char *value = os_malloc(INI_BUFFERSIZE);

  // Load the bin paths array
  ini_gets("system", "binPath", "/bin", value, INI_BUFFERSIZE, filename);
  split_string_array(value, ':', config->bin_path_array);
  os_free(value);

  // Load create interfaces flag
  config->create_interfaces = ini_getbool("system", "createInterfaces", 0, filename);

  // Load ignore error on interface create
  config->ignore_if_error = ini_getbool("system", "ignoreErrorOnIfCreate", 0, filename);

  // Load the AP detect flag
  config->ap_detect = ini_getbool("system", "apDetect", 0, filename);

  // Load the exec ap flag
  config->exec_ap = ini_getbool("system", "execAp", 0, filename);

  // Load the exec radius flag
  config->exec_radius = ini_getbool("system", "execRadius", 0, filename);

  // Load the exec dhcp flag
  config->exec_dhcp = ini_getbool("system", "execDhcp", 0, filename);

  // Load the exec capture flag
  config->exec_capture = ini_getbool("system", "execCapture", 1, filename);

  // Load the default open vlanid
  config->default_open_vlanid = (int) ini_getl("system", "defaultOpenVlanId", 0, filename);

  // Load NAT interface
  value = os_malloc(INI_BUFFERSIZE);
  ini_gets("nat", "natInterface", "", value, INI_BUFFERSIZE, filename);

  strncpy(config->nat_interface, value, IFNAMSIZ);
  os_free(value);

  // Load domainServerPath
  value = os_malloc(INI_BUFFERSIZE);
  int ret = ini_gets("supervisor", "domainServerPath", "", value, INI_BUFFERSIZE, filename);
  if (!ret) {
    fprintf(stderr, "Domain server path was not specified\n");
    return false;
  }

  strncpy(config->domain_server_path, value, MAX_OS_PATH_LEN);
  os_free(value);

  if ((config->domain_delim = load_delim(filename)) == 0) {
    fprintf(stderr, "delim parsing error");
    return false;
  }

  // Load allow all connection flag
  config->allow_all_connections = ini_getbool("system", "allowAllConnections", 0, filename);

  // Load killRunningProcess flag
  config->kill_running_proc = ini_getbool("system", "killRunningProcess", 0, filename);

  // Load ap radius config params
  if(!load_radius_conf(filename, config)) {
    fprintf(stderr, "radius config parsing error.\n");
    return false;
  }

  // Load ap config params
  if(!load_ap_conf(filename, config)) {
    fprintf(stderr, "ap config parsing error.\n");
    return false;
  }

  // Load the DNS server configuration
  if(!load_dns_conf(filename, config)) {
    fprintf(stderr, "dns config parsing error.\n");
    return false;
  }

  // Load the DHCP server configuration
  if(!load_dhcp_conf(filename, config)) {
    fprintf(stderr, "dhcp config parsing error.\n");
    return false;
  }

  // Load the list of connections
  if(!load_connection_list(filename, config)) {
    fprintf(stderr, "Connection list parsing error.\n");
    return false;
  }

  // Load the list of interfaces
  if(!load_interface_list(filename, config)) {
    fprintf(stderr, "Interface list parsing error.\n");
    return false;
  }

  // Load the capture config
  if (!load_capture_config(filename, &config->capture_config)) {
    fprintf(stderr, "Capture parsing error.\n");
    return false;
  }
  return true;
}
