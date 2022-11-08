/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the implementation of the app configuration utilities.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <fcntl.h>
#include <ctype.h>
#include <unistd.h>
#include <stdbool.h>
#include <errno.h>
#include <minIni.h>

#include "utils/allocs.h"
#include "utils/os.h"
#include "config.h"

#include "supervisor/cmd_processor.h"

static const UT_icd config_ifinfo_icd = {sizeof(config_ifinfo_t), NULL, NULL,
                                         NULL};
static const UT_icd config_dhcpinfo_icd = {sizeof(config_dhcpinfo_t), NULL,
                                           NULL, NULL};

bool get_config_dhcpinfo(char *info, config_dhcpinfo_t *el) {
  UT_array *info_arr;
  utarray_new(info_arr, &ut_str_icd);

  if (split_string_array(info, ',', info_arr) < 0) {
    goto err;
  }

  if (!utarray_len(info_arr)) {
    goto err;
  }

  char **p = NULL;
  p = (char **)utarray_next(info_arr, p);
  if (*p != NULL) {
    errno = 0;
    el->vlanid = (int)strtol(*p, NULL, 10);
    if (errno == EINVAL)
      goto err;
  } else
    goto err;

  p = (char **)utarray_next(info_arr, p);
  if (*p != NULL) {
    os_strlcpy(el->ip_addr_low, *p, OS_INET_ADDRSTRLEN);
  } else
    goto err;

  p = (char **)utarray_next(info_arr, p);
  if (*p != NULL)
    os_strlcpy(el->ip_addr_upp, *p, OS_INET_ADDRSTRLEN);
  else
    goto err;

  p = (char **)utarray_next(info_arr, p);
  if (*p != NULL)
    os_strlcpy(el->subnet_mask, *p, OS_INET_ADDRSTRLEN);
  else
    goto err;

  p = (char **)utarray_next(info_arr, p);
  if (*p != NULL)
    os_strlcpy(el->lease_time, *p, DHCP_LEASE_TIME_SIZE);
  else
    goto err;

  utarray_free(info_arr);
  return true;

err:
  utarray_free(info_arr);
  return false;
}

bool get_config_ifinfo(char *info, config_ifinfo_t *el) {
  UT_array *info_arr;
  utarray_new(info_arr, &ut_str_icd);

  if (split_string_array(info, ',', info_arr) < 0) {
    goto err;
  }

  if (!utarray_len(info_arr)) {
    goto err;
  }

  char **p = NULL;
  p = (char **)utarray_next(info_arr, p);
  if (*p != NULL) {
    errno = 0;
    el->vlanid = (int)strtol(*p, NULL, 10);
    if (errno == EINVAL)
      goto err;
  } else
    goto err;

  p = (char **)utarray_next(info_arr, p);
  if (*p != NULL) {
    os_strlcpy(el->ip_addr, *p, OS_INET_ADDRSTRLEN);
  } else
    goto err;

  p = (char **)utarray_next(info_arr, p);
  if (*p != NULL)
    os_strlcpy(el->brd_addr, *p, OS_INET_ADDRSTRLEN);
  else
    goto err;

  p = (char **)utarray_next(info_arr, p);
  if (*p != NULL)
    os_strlcpy(el->subnet_mask, *p, OS_INET_ADDRSTRLEN);
  else
    goto err;

  utarray_free(info_arr);
  return true;

err:
  utarray_free(info_arr);
  return false;
}

bool load_interface_list(const char *filename, struct app_config *config) {
  char *key = os_malloc(INI_BUFFERSIZE);
  int idx = 0, ret = 0;
  UT_array *config_ifinfo_arr;

  if (config == NULL) {
    log_error("config param is NULL");
    return false;
  }

  ret =
      ini_gets("interfaces", "bridgePrefix", "", key, INI_BUFFERSIZE, filename);
  if (!ret) {
    log_error("bridge prefix was not specified\n");
    os_free(key);
    return false;
  }
  os_strlcpy(config->bridge_prefix, key, IF_NAMESIZE);
  os_free(key);

  // Load the interface prefix
  key = os_malloc(INI_BUFFERSIZE);
  ret = ini_gets("interfaces", "interfacePrefix", "", key, INI_BUFFERSIZE,
                 filename);
  if (!ret) {
    log_error("interface prefix was not specified\n");
    os_free(key);
    return false;
  }
  os_strlcpy(config->interface_prefix, key, IF_NAMESIZE);
  os_free(key);

  key = os_malloc(INI_BUFFERSIZE);
  config->config_ifinfo_array = NULL;
  utarray_new(config_ifinfo_arr, &config_ifinfo_icd);

  while (ini_getkey("interfaces", idx++, key, INI_BUFFERSIZE, filename) > 0) {
    char *value = os_malloc(INI_BUFFERSIZE);
    ini_gets("interfaces", key, "", value, INI_BUFFERSIZE, filename);
    if (strstr(key, "if") == (char *)key) {
      config_ifinfo_t el;
      if (!get_config_ifinfo(value, &el)) {
        utarray_free(config_ifinfo_arr);
        os_free(value);
        os_free(key);
        return false;
      }
      utarray_push_back(config_ifinfo_arr, &el);
    }
    os_free(value);
    os_free(key);
    key = os_malloc(INI_BUFFERSIZE);
  }

  config->config_ifinfo_array = config_ifinfo_arr;

  os_free(key);
  return true;
}

bool load_dhcp_list(const char *filename, struct app_config *config) {
  char *key = os_malloc(INI_BUFFERSIZE);
  int idx = 0;
  UT_array *config_dhcpinfo_arr;

  config->dhcp_config.config_dhcpinfo_array = NULL;

  utarray_new(config_dhcpinfo_arr, &config_dhcpinfo_icd);

  while (ini_getkey("dhcp", idx++, key, INI_BUFFERSIZE, filename) > 0) {
    char *value = os_malloc(INI_BUFFERSIZE);
    ini_gets("dhcp", key, "", value, INI_BUFFERSIZE, filename);
    if (strstr(key, "dhcpRange") == (char *)key) {
      config_dhcpinfo_t el;
      if (!get_config_dhcpinfo(value, &el)) {
        utarray_free(config_dhcpinfo_arr);
        os_free(value);
        os_free(key);
        return false;
      }
      utarray_push_back(config_dhcpinfo_arr, &el);
    }
    os_free(value);
    os_free(key);
    key = os_malloc(INI_BUFFERSIZE);
  }

  config->dhcp_config.config_dhcpinfo_array = config_dhcpinfo_arr;

  os_free(key);
  return true;
}

bool load_radius_conf(const char *filename, struct app_config *config) {
  char *value = os_malloc(INI_BUFFERSIZE);

  // Load radius port
  config->rconfig.radius_port = (int)ini_getl("radius", "port", 1812, filename);

  // Load radius client ip
  value = os_malloc(INI_BUFFERSIZE);
  ini_gets("radius", "clientIP", "127.0.0.1", value, INI_BUFFERSIZE, filename);

  os_strlcpy(config->rconfig.radius_client_ip, value, OS_INET_ADDRSTRLEN);
  os_free(value);

  // Load radius client mask
  config->rconfig.radius_client_mask =
      (int)ini_getl("radius", "clientMask", 32, filename);

  // Load radius server ip
  value = os_malloc(INI_BUFFERSIZE);
  ini_gets("radius", "serverIP", "127.0.0.1", value, INI_BUFFERSIZE, filename);

  os_strlcpy(config->rconfig.radius_server_ip, value, OS_INET_ADDRSTRLEN);
  os_free(value);

  // Load radius server mask
  config->rconfig.radius_server_mask =
      (int)ini_getl("radius", "serverMask", 32, filename);

  // Load radius secret
  value = os_malloc(INI_BUFFERSIZE);
  ini_gets("radius", "secret", "", value, INI_BUFFERSIZE, filename);
  os_strlcpy(config->rconfig.radius_secret, value, RADIUS_SECRET_LEN);
  os_free(value);

  return true;
}

bool load_ap_conf(const char *filename, struct app_config *config) {
  char *value = os_malloc(INI_BUFFERSIZE);

  // Load ap file path
  int ret = ini_gets("ap", "apFilePath", "", value, INI_BUFFERSIZE, filename);
  if (!ret) {
    log_error("apFilePath was not specified\n");
    os_free(value);
    return false;
  }

  os_strlcpy(config->hconfig.ap_file_path, value, MAX_OS_PATH_LEN);
  os_free(value);

  // Load ap bin path
  value = os_malloc(INI_BUFFERSIZE);
  ret = ini_gets("ap", "apBinPath", "", value, INI_BUFFERSIZE, filename);
  if (!ret) {
    log_error("apBinPath was not specified\n");
    os_free(value);
    return false;
  }

  os_strlcpy(config->hconfig.ap_bin_path, value, MAX_OS_PATH_LEN);
  os_free(value);

  // Load ap log path
  value = os_malloc(INI_BUFFERSIZE);
  ret = ini_gets("ap", "apLogPath", "", value, INI_BUFFERSIZE, filename);
  os_strlcpy(config->hconfig.ap_log_path, value, MAX_OS_PATH_LEN);
  os_free(value);

  // // Load ap bridge
  // value = os_malloc(INI_BUFFERSIZE);
  // ret = ini_gets("ap", "bridge", "", value, INI_BUFFERSIZE, filename);
  // os_strlcpy(config->hconfig.bridge, value, IF_NAMESIZE);
  // os_free(value);

  // Load AP name
  value = os_malloc(INI_BUFFERSIZE);
  ret = ini_gets("ap", "ssid", "", value, INI_BUFFERSIZE, filename);
  if (!ret) {
    log_error("ap ssid was not specified\n");
    os_free(value);
    return false;
  }

  os_strlcpy(config->hconfig.ssid, value, AP_NAME_LEN);
  os_free(value);

  // Load AP password
  value = os_malloc(INI_BUFFERSIZE);
  ini_gets("ap", "wpaPassphrase", "", value, INI_BUFFERSIZE, filename);

  os_strlcpy(config->hconfig.wpa_passphrase, value, AP_SECRET_LEN);
  os_free(value);

  // Load AP interface
  value = os_malloc(INI_BUFFERSIZE);
  ret = ini_gets("ap", "interface", "", value, INI_BUFFERSIZE, filename);
  if (os_strnlen_s(value, IF_NAMESIZE)) {
    os_strlcpy(config->hconfig.interface, value, IF_NAMESIZE);
  }

  os_strlcpy(config->hconfig.interface, value, IF_NAMESIZE);
  os_free(value);

  // Load device
  value = os_malloc(INI_BUFFERSIZE);
  ini_gets("ap", "device", "", value, INI_BUFFERSIZE, filename);
  os_strlcpy(config->hconfig.device, value, IF_NAMESIZE);
  os_free(value);

  // Load vlan_tagged_interface
  value = os_malloc(INI_BUFFERSIZE);
  ini_gets("ap", "vlanTaggedInterface", "", value, INI_BUFFERSIZE, filename);
  os_strlcpy(config->hconfig.vlan_tagged_interface, value, IF_NAMESIZE);
  os_free(value);

  // Load ap driver
  value = os_malloc(INI_BUFFERSIZE);
  ini_gets("ap", "driver", "nl80211", value, INI_BUFFERSIZE, filename);
  os_strlcpy(config->hconfig.driver, value, AP_DRIVE_LEN);
  os_free(value);

  // Load ap hw mode
  value = os_malloc(INI_BUFFERSIZE);
  ini_gets("ap", "hwMode", "g", value, INI_BUFFERSIZE, filename);
  os_strlcpy(config->hconfig.hw_mode, value, AP_HWMODE_LEN);
  os_free(value);

  // Load ap channel
  config->hconfig.channel = (int)ini_getl("ap", "channel", 11, filename);

  // Load ap wmmEnabled
  config->hconfig.wmm_enabled = (int)ini_getl("ap", "wmmEnabled", 1, filename);

  // Load ap authAlgs
  config->hconfig.auth_algs = (int)ini_getl("ap", "authAlgs", 1, filename);

  // Load ap wpa
  config->hconfig.wpa = (int)ini_getl("ap", "wpa", 2, filename);

  // Load ap wpaKeyMgmt
  value = os_malloc(INI_BUFFERSIZE);
  ini_gets("ap", "wpaKeyMgmt", "WPA-PSK", value, INI_BUFFERSIZE, filename);
  os_strlcpy(config->hconfig.wpa_key_mgmt, value, AP_WPA_KEY_MGMT_LEN);
  os_free(value);

  // Load ap rsnPairwise
  value = os_malloc(INI_BUFFERSIZE);
  ini_gets("ap", "rsnPairwise", "CCMP", value, INI_BUFFERSIZE, filename);
  os_strlcpy(config->hconfig.rsn_pairwise, value, AP_RSN_PAIRWISE_LEN);
  os_free(value);

  // Load ap ctrlInterface
  value = os_malloc(INI_BUFFERSIZE);
  ini_gets("ap", "ctrlInterface", "/var/run/hostapd", value, INI_BUFFERSIZE,
           filename);
  os_strlcpy(config->hconfig.ctrl_interface, value, MAX_OS_PATH_LEN);
  os_free(value);

  // Load ap macaddrAcl
  config->hconfig.macaddr_acl = (int)ini_getl("ap", "macaddrAcl", 2, filename);

  // Load ap dynamicVlan
  config->hconfig.dynamic_vlan =
      (int)ini_getl("ap", "dynamicVlan", 1, filename);

  // Load ap vlanFile
  value = os_malloc(INI_BUFFERSIZE);
  ret = ini_gets("ap", "vlanFile", "", value, INI_BUFFERSIZE, filename);
  if (!ret) {
    log_error("ap vlanFile was not specified\n");
    os_free(value);
    return false;
  }

  os_strlcpy(config->hconfig.vlan_file, value, MAX_OS_PATH_LEN);
  os_free(value);

  // Load ap loggerStdout
  config->hconfig.logger_stdout =
      (int)ini_getl("ap", "loggerStdout", -1, filename);

  // Load ap loggerStdoutLevel
  config->hconfig.logger_stdout_level =
      (int)ini_getl("ap", "loggerStdoutLevel", 0, filename);

  // Load ap loggerSyslog
  config->hconfig.logger_syslog =
      (int)ini_getl("ap", "loggerSyslog", -1, filename);

  // Load ap loggerStdoutLevel
  config->hconfig.logger_syslog_level =
      (int)ini_getl("ap", "loggerSyslogLevel", 0, filename);

  // Load ap ignoreBroadcastSsid
  config->hconfig.ignore_broadcast_ssid =
      (int)ini_getl("ap", "ignoreBroadcastSsid", 0, filename);

  // Load ap wpaPskRadius
  config->hconfig.wpa_psk_radius =
      (int)ini_getl("ap", "wpaPskRadius", 2, filename);

  return true;
}

bool load_dns_conf(const char *filename, struct app_config *config) {
  UT_array *server_arr;
  char *value = os_malloc(INI_BUFFERSIZE);

  config->dns_config.server_array = NULL;

  // Load the DNS server addresses
  utarray_new(server_arr, &ut_str_icd);

  ini_gets("dns", "servers", "", value, INI_BUFFERSIZE, filename);
  if (split_string_array(value, ',', server_arr) < 0) {
    utarray_free(server_arr);
    os_free(value);
    return false;
  }

  config->dns_config.server_array = server_arr;
  os_free(value);

  return true;
}

bool load_mdns_conf(const char *filename, struct app_config *config) {
  int ret;
  char *value = NULL;

  // Load mdnsReflectIp4 param
  config->mdns_config.reflect_ip4 =
      (int)ini_getbool("dns", "mdnsReflectIp4", 0, filename);

  // Load mdnsReflectIp6 param
  config->mdns_config.reflect_ip6 =
      (int)ini_getbool("dns", "mdnsReflectIp6", 0, filename);

  value = os_zalloc(INI_BUFFERSIZE);
  ret = ini_gets("dns", "mdnsFilter", "", value, INI_BUFFERSIZE, filename);
  if (!ret) {
    log_error("dns mdnsFilter was not specified\n");
    os_free(value);
    return false;
  }

  os_strlcpy(config->mdns_config.filter, value, MAX_OS_PATH_LEN);
  os_free(value);

  return true;
}

bool load_dhcp_conf(const char *filename, struct app_config *config) {
  char *value = os_malloc(INI_BUFFERSIZE);

  // Load dhpc config file path
  int ret =
      ini_gets("dhcp", "dhcpConfigPath", "", value, INI_BUFFERSIZE, filename);
  if (!ret) {
    log_error("dhcp dhcpConfigPath was not specified\n");
    os_free(value);
    return false;
  }

  os_strlcpy(config->dhcp_config.dhcp_conf_path, value, MAX_OS_PATH_LEN);
  os_free(value);

  // Load dhpc bin file path
  value = os_malloc(INI_BUFFERSIZE);
  ret = ini_gets("dhcp", "dhcpBinPath", "", value, INI_BUFFERSIZE, filename);
  if (!ret) {
    log_error("dhcp dhcpBinPath was not specified\n");
    os_free(value);
    return false;
  }

  os_strlcpy(config->dhcp_config.dhcp_bin_path, value, MAX_OS_PATH_LEN);
  os_free(value);

  // Load dhpc script file path
  value = os_malloc(INI_BUFFERSIZE);
  ret = ini_gets("dhcp", "dhcpScriptPath", "", value, INI_BUFFERSIZE, filename);
  if (!ret) {
    log_error("dhcp dhcpScriptPath was not specified\n");
    os_free(value);
    return false;
  }

  os_strlcpy(config->dhcp_config.dhcp_script_path, value, MAX_OS_PATH_LEN);
  os_free(value);

  // Load dhpc lease file path
  value = os_malloc(INI_BUFFERSIZE);
  ret = ini_gets("dhcp", "dhcpLeasefilePath", "", value, INI_BUFFERSIZE,
                 filename);
  if (!ret) {
    log_error("dhcp dhcpLeasefilePath was not specified\n");
    os_free(value);
    return false;
  }

  os_strlcpy(config->dhcp_config.dhcp_leasefile_path, value, MAX_OS_PATH_LEN);
  os_free(value);

  // Load the dhcprange params
  if (!load_dhcp_list(filename, config)) {
    log_error("load_dhcp_list parsing error\n");
    return false;
  }

  return true;
}

bool load_capture_config(const char *filename, struct capture_conf *config) {
  char *value = os_zalloc(INI_BUFFERSIZE);

  // Load captureDbParam param
  ini_gets("capture", "captureDbPath", "./", value, INI_BUFFERSIZE, filename);
  os_strlcpy(config->capture_db_path, value, MAX_OS_PATH_LEN);
  os_free(value);

  // Load filter param
  value = os_zalloc(INI_BUFFERSIZE);
  ini_gets("capture", "filter", "", value, INI_BUFFERSIZE, filename);

  os_strlcpy(config->filter, value, MAX_FILTER_SIZE);
  os_free(value);

  // Load middleware params
  char ini_buffer[INI_BUFFERSIZE] = "";
  ini_gets("capture", "middlewareParams", "", ini_buffer, INI_BUFFERSIZE,
           filename);

  os_strlcpy(config->middleware_params, ini_buffer, MAX_MIDDLEWARE_PARAMS_SIZE);

  // Load promiscuous param
  config->promiscuous = (int)ini_getbool("capture", "promiscuous", 0, filename);

  // Load immediate param
  config->immediate = (int)ini_getbool("capture", "immediate", 0, filename);

  // Load bufferTimeout param
  config->buffer_timeout =
      (uint16_t)ini_getl("capture", "bufferTimeout", 10, filename);

  return true;
}

bool load_system_config(const char *filename, struct app_config *config) {
  int ret;
  char *value;
  UT_array *bin_path_arr;

  config->bin_path_array = NULL;

  // Load create interfaces flag
  config->create_interfaces =
      ini_getbool("system", "createInterfaces", 0, filename);

  // Load ignore error on interface create
  config->ignore_if_error =
      ini_getbool("system", "ignoreErrorOnIfCreate", 0, filename);

  // Load the AP detect flag
  config->ap_detect = ini_getbool("system", "apDetect", 0, filename);

  // Load the IP forward flag
  config->set_ip_forward = ini_getbool("system", "setIpForward", 0, filename);

  // Load the exec ap flag
  config->exec_ap = ini_getbool("system", "execAp", 0, filename);

  // Load the generateSsid flag
  config->generate_ssid = ini_getbool("system", "generateSsid", 0, filename);

  // Load the exec radius flag
  config->exec_radius = ini_getbool("system", "execRadius", 0, filename);

  // Load the exec dhcp flag
  config->exec_dhcp = ini_getbool("system", "execDhcp", 0, filename);

  // Load the exec capture flag
  config->exec_capture = ini_getbool("system", "execCapture", 1, filename);

  // Load the exec mdns forward flag
  config->exec_mdns_forward =
      ini_getbool("system", "execMdnsForward", 0, filename);

  // Load the exec firewall flag
  config->exec_firewall = ini_getbool("system", "execFirewall", 1, filename);

  // Load the allocateVlans flag
  config->allocate_vlans = ini_getbool("system", "allocateVlans", 0, filename);

  // Load the default open vlanid
  config->default_open_vlanid =
      (int)ini_getl("system", "defaultOpenVlanId", 0, filename);

  // Load allow all connection flag
  config->allow_all_connections =
      ini_getbool("system", "allowAllConnections", 0, filename);

  // Load allow all nat connection flag
  config->allow_all_nat = ini_getbool("system", "allowAllNat", 0, filename);

  // Load connection db param
  value = os_zalloc(INI_BUFFERSIZE);
  ret = ini_gets("system", "connectionDbPath", "", value, INI_BUFFERSIZE,
                 filename);
  os_strlcpy(config->connection_db_path, value, MAX_OS_PATH_LEN);
  os_free(value);

#ifdef WITH_CRYPTO_SERVICE
  // Load the crypt db path param
  value = os_zalloc(INI_BUFFERSIZE);
  ret = ini_gets("system", "cryptDbPath", "", value, INI_BUFFERSIZE, filename);
  os_strlcpy(config->crypt_db_path, value, MAX_OS_PATH_LEN);
  if (!ret) {
    log_error("Crypt db path was not specified\n");
    os_free(value);
    return false;
  }
  os_free(value);
#endif

  // Load pidFilePath
  value = os_malloc(INI_BUFFERSIZE);
  ret = ini_gets("system", "pidFilePath", "", value, INI_BUFFERSIZE, filename);
  if (!ret) {
    log_error("pid file path was not specified\n");
    os_free(value);
    return false;
  }

  os_strlcpy(config->pid_file_path, value, MAX_OS_PATH_LEN);
  os_free(value);

  // Load the bin paths array
  utarray_new(bin_path_arr, &ut_str_icd);
  value = os_malloc(INI_BUFFERSIZE);
  ini_gets("system", "binPath", "/bin", value, INI_BUFFERSIZE, filename);
  if (split_string_array(value, ':', bin_path_arr) < 0) {
    utarray_free(bin_path_arr);
    os_free(value);
    return false;
  }
  os_free(value);
  config->bin_path_array = bin_path_arr;

  return true;
}

bool load_supervisor_config(const char *filename, struct app_config *config) {
  int ret;
  char *value;

  // Load the supervisor control port
  config->supervisor_control_port = (unsigned int)ini_getl(
      "supervisor", "supervisorControlPort", 0, filename);

  // Load supervisorControlPath
  value = os_malloc(INI_BUFFERSIZE);
  ret = ini_gets("supervisor", "supervisorControlPath", "", value,
                 INI_BUFFERSIZE, filename);
  if (!ret) {
    log_error("Supervisor control server path was not specified\n");
    os_free(value);
    return false;
  }
  os_strlcpy(config->supervisor_control_path, value, MAX_OS_PATH_LEN);
  os_free(value);

  return true;
}

bool load_nat_config(const char *filename, struct app_config *config) {
  char *value;

  // Load NAT bridge
  value = os_malloc(INI_BUFFERSIZE);
  ini_gets("nat", "natBridge", "", value, INI_BUFFERSIZE, filename);
  os_strlcpy(config->nat_bridge, value, IF_NAMESIZE);
  os_free(value);

  // Load NAT interface
  value = os_malloc(INI_BUFFERSIZE);
  ini_gets("nat", "natInterface", "", value, INI_BUFFERSIZE, filename);
  os_strlcpy(config->nat_interface, value, IF_NAMESIZE);
  os_free(value);

  return true;
}

bool load_firewall_config(const char *filename, struct firewall_conf *config) {
  char *value;

  // Load firewall bin path
  value = os_malloc(INI_BUFFERSIZE);
  ini_gets("firewall", "firewallBinPath", "", value, INI_BUFFERSIZE, filename);
  os_strlcpy(config->firewall_bin_path, value, MAX_OS_PATH_LEN);
  os_free(value);

  return true;
}

int load_app_config(const char *filename, struct app_config *config) {
  FILE *fp = fopen(filename, "rb");

  if (fp == NULL) {
    log_errno("Couldn't open %s config file.\n", filename);
    return -1;
  }
  fclose(fp);

  os_strlcpy(config->config_ini_path, filename, MAX_OS_PATH_LEN);

  if (!load_system_config(filename, config)) {
    log_error("load_system_config fail");
    return -1;
  }

  if (!load_supervisor_config(filename, config)) {
    log_error("load_supervisor_config fail");
    return -1;
  }

  if (!load_nat_config(filename, config)) {
    log_error("load_nat_config fail");
    return -1;
  }

  // Load ap radius config params
  if (!load_radius_conf(filename, config)) {
    log_error("radius config parsing error.\n");
    return -1;
  }

  // Load ap config params
  if (!load_ap_conf(filename, config)) {
    log_error("ap config parsing error.\n");
    return -1;
  }

  // Load the DNS server configuration
  if (!load_dns_conf(filename, config)) {
    log_error("dns config parsing error.\n");
    return -1;
  }

  // Load the mDNS server configuration
  if (!load_mdns_conf(filename, config)) {
    log_error("dns config parsing error.\n");
    return -1;
  }

  // Load the DHCP server configuration
  if (!load_dhcp_conf(filename, config)) {
    log_error("dhcp config parsing error.\n");
    return -1;
  }

  // Load the list of interfaces
  if (!load_interface_list(filename, config)) {
    log_error("Interface list parsing error.\n");
    return -1;
  }

  // Load the capture config
  if (!load_capture_config(filename, &config->capture_config)) {
    log_error("Capture parsing error.\n");
    return -1;
  }

  // Load the firewall config
  if (!load_firewall_config(filename, &config->firewall_config)) {
    log_error("Firewall parsing error.\n");
    return -1;
  }

  return 0;
}

void free_app_config(struct app_config *config) {
  if (config == NULL) {
    return;
  }

  if (config->bin_path_array != NULL) {
    utarray_free(config->bin_path_array);
  }

  if (config->config_ifinfo_array != NULL) {
    utarray_free(config->config_ifinfo_array);
  }

  if (config->dhcp_config.config_dhcpinfo_array != NULL) {
    utarray_free(config->dhcp_config.config_dhcpinfo_array);
  }

  if (config->dns_config.server_array != NULL) {
    utarray_free(config->dns_config.server_array);
  }
}
