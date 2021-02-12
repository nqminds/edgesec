/****************************************************************************
 * Copyright (C) 2020 by NQMCyber Ltd                                       *
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
 * @file config_generator.c
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of hostapd config generation utilities.
 */
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>

#include "hostapd_config.h"
#include "utils/log.h"

bool generate_vlan_conf(char *vlan_file, char *interface)
{
  // Delete the vlan config file if present
  int stat = unlink(vlan_file);

  if (stat == -1 && errno != ENOENT) {
    log_err("unlink");
    return false;
  }

  FILE *fp = fopen(vlan_file, "a+");

  if (fp == NULL) {
    log_err("fopen");
    return false;
  }

  log_trace("Writing into %s", vlan_file);

  fprintf(fp, "*\t%s.#\n", interface);

  fclose(fp);
  return true;
}

bool generate_hostapd_conf(struct hostapd_conf *hconf, struct radius_conf *rconf)
{
  // Delete the config file if present
  int stat = unlink(hconf->hostapd_file_path);

  if (stat == -1 && errno != ENOENT) {
    log_err("unlink");
    return false;
  }

  FILE *fp = fopen(hconf->hostapd_file_path, "a+");

  if (fp == NULL) {
    log_err("fopen");
    return false;
  }

  log_trace("Writing into %s", hconf->hostapd_file_path);

  fprintf(fp, "interface=%s\n", hconf->interface);
  fprintf(fp, "bridge=%s\n", hconf->bridge);
  fprintf(fp, "driver=%s\n", hconf->driver);
  fprintf(fp, "ssid=%s\n", hconf->ssid);
  fprintf(fp, "hw_mode=%s\n", hconf->hw_mode);
  fprintf(fp, "channel=%d\n", hconf->channel);
  fprintf(fp, "wmm_enabled=%d\n", hconf->wmm_enabled);
  fprintf(fp, "auth_algs=%d\n", hconf->auth_algs);
  fprintf(fp, "wpa=%d\n", hconf->wpa);
  fprintf(fp, "wpa_key_mgmt=%s\n", hconf->wpa_key_mgmt);
  fprintf(fp, "rsn_pairwise=%s\n", hconf->rsn_pairwise);
  fprintf(fp, "ctrl_interface=%s\n", hconf->ctrl_interface);
  fprintf(fp, "own_ip_addr=%s\n", rconf->radius_client_ip);
  fprintf(fp, "auth_server_addr=%s\n", rconf->radius_server_ip);
  fprintf(fp, "auth_server_port=%d\n", rconf->radius_port);
  fprintf(fp, "auth_server_shared_secret=%s\n", rconf->radius_secret);
  fprintf(fp, "macaddr_acl=%d\n", hconf->macaddr_acl);
  fprintf(fp, "dynamic_vlan=%d\n", hconf->dynamic_vlan);
  fprintf(fp, "vlan_bridge=%s\n", hconf->vlan_bridge);
  fprintf(fp, "vlan_file=%s\n", hconf->vlan_file);
  fprintf(fp, "logger_stdout=%d\n", hconf->logger_stdout);
  fprintf(fp, "logger_stdout_level=%d\n", hconf->logger_stdout_level);
  fprintf(fp, "logger_syslog=%d\n", hconf->logger_syslog);
  fprintf(fp, "logger_syslog_level=%d\n", hconf->logger_syslog_level);
  fprintf(fp, "ignore_broadcast_ssid=%d\n", hconf->ignore_broadcast_ssid);
  fprintf(fp, "wpa_psk_radius=%d\n", hconf->wpa_psk_radius);

  fclose(fp);
  return true;
}

bool construct_hostapd_ctrlif(char *ctrl_interface, char *interface, char *hostapd_ctrl_if_path)
{
  char *ctrl_if_path = construct_path(ctrl_interface, interface);
  if (ctrl_if_path == NULL) {
    log_trace("construct_path fail");
    return false;
  }

  strncpy(hostapd_ctrl_if_path, ctrl_if_path, HOSTAPD_AP_SECRET_LEN);
  free(ctrl_if_path);

  return true;
}

