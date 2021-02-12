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
 * @file engine.c 
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of the app configuration structure.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <fcntl.h>
#include <ctype.h>
#include <unistd.h>
#include <stdbool.h>

#include "utils/log.h"
#include "utils/hashmap.h"
#include "utils/utarray.h"
#include "utils/hashmap.h"
#include "utils/os.h"
#include "utils/eloop.h"
#include "utils/iptables.h"

#include "supervisor/supervisor.h"
#include "radius/radius_service.h"
#include "hostapd/hostapd_service.h"
#include "dhcp/dhcp_service.h"

#include "engine.h"
#include "system_checks.h"
#include "if_service.h"

static struct supervisor_context context;

bool init_mac_mapper_ifnames(UT_array *connections, hmap_vlan_conn **vlan_mapper)
{
  struct mac_conn *p = NULL;

  if (connections != NULL) {
    while(p = (struct mac_conn *) utarray_next(connections, p)) {
      int ret = get_vlan_mapper(vlan_mapper, p->info.vlanid, p->info.ifname);
      if (ret < 0) {
        log_trace("get_vlan_mapper fail");
        return false;
      } else if (ret == 0) {
        log_trace("vlan not in mapper");
        return false;
      }
    }
  }

  return true;
}

bool init_context(struct app_config *app_config, struct supervisor_context *ctx)
{
  os_memset(ctx, 0, sizeof(struct supervisor_context));

  if (!init_ifbridge_names(app_config->config_ifinfo_array, app_config->hconfig.vlan_bridge)) {
    log_trace("init_ifbridge_names fail");
    return false;
  }

  ctx->allow_all_connections = app_config->allow_all_connections;
  ctx->default_open_vlanid = app_config->default_open_vlanid;
  ctx->config_ifinfo_array = app_config->config_ifinfo_array;

  ctx->wpa_passphrase_len = strlen(app_config->hconfig.wpa_passphrase);
  memcpy(ctx->wpa_passphrase, app_config->hconfig.wpa_passphrase, ctx->wpa_passphrase_len);
  
  strncpy(ctx->nat_interface, app_config->nat_interface, IFNAMSIZ);

  log_info("Creating subnet to interface mapper...");
  if (!create_if_mapper(app_config->config_ifinfo_array, &ctx->if_mapper)) {
    log_debug("create_if_mapper fail");
    return false;
  }

  log_info("Creating VLAN ID to interface mapper...");
  if (!create_vlan_mapper(app_config->config_ifinfo_array, &ctx->vlan_mapper)) {
    log_debug("create_if_mapper fail");
    return false;
  }

  if (!init_mac_mapper_ifnames(app_config->connections, &ctx->vlan_mapper)) {
    log_debug("init_mac_mapper_ifnames fail");
    return false;
  }

  log_info("Adding default mac mappers...");
  if (!create_mac_mapper(app_config->connections, &ctx->mac_mapper)) {
    log_debug("create_mac_mapper fail");
    return false;
  }

  // Init the list of bridges
  ctx->bridge_list = init_bridge_list();
  return true;
}

bool run_engine(struct app_config *app_config, uint8_t log_level)
{
  struct radius_server_data *radius_srv = NULL;
  int domain_sock = -1;
  int hostapd_fd = -1;
  int dhcp_fd = -1;
  char *commands[] = {"ip", "iw", "iptables", "dnsmasq", NULL};
  char *nat_ip = NULL;

  // Set the log level
  log_set_level(log_level);

  if (!init_context(app_config, &context)) {
    log_trace("init_context fail");
    goto run_engine_fail;
  }

  log_info("AP name: %s", app_config->hconfig.ssid);
  log_info("AP interface: %s", app_config->hconfig.interface);

  log_info("Checking system commands...");
  hmap_str_keychar *hmap_bin_paths = check_systems_commands(
    commands, app_config->bin_path_array, NULL
  );
  if (hmap_bin_paths == NULL) {
    log_debug("check_systems_commands fail (no bin paths found)");
    goto run_engine_fail;
  }

  char *iptables_path = hmap_str_keychar_get(&hmap_bin_paths, "iptables");
  if (iptables_path == NULL) {
    log_debug("Couldn't find xtables-multi binary");
    goto run_engine_fail;
  }

  if (!init_iptables(iptables_path, app_config->config_ifinfo_array)) {
    log_debug("init_iptables fail");
    goto run_engine_fail;
  }

  log_info("Checking wifi interface...");
  if (!app_config->ap_detect) {
    if(!is_iw_vlan(app_config->hconfig.interface)) {
      log_debug("is_iw_vlan fail");
      goto run_engine_fail;
    }
  } else {
    if(get_valid_iw(app_config->hconfig.interface) == NULL) {
      log_debug("get_valid_iw fail");
      goto run_engine_fail;
    }
  }

  log_info("Found wifi interface %s", app_config->hconfig.interface);
  if(!construct_hostapd_ctrlif(app_config->hconfig.ctrl_interface, app_config->hconfig.interface, context.hostapd_ctrl_if_path)) {
    log_debug("construct_hostapd_ctrlif fail");
    goto run_engine_fail;
  }

  if (strlen(app_config->nat_interface)) {
    log_info("Checking nat interface %s", app_config->nat_interface);
    if (!get_nat_if_ip(app_config->nat_interface, &nat_ip)) {
      log_debug("get_nat_if_ip fail");
      goto run_engine_fail;
    }
    log_info("Found nat interface %s", app_config->nat_interface);
    if (nat_ip != NULL)
      log_info("Found nat IP %s", nat_ip);

  } else
    log_info("Not using any nat interface");

  if (app_config->create_interfaces) {
    log_info("Creating subnet interfaces...");
    if (!create_subnet_ifs(app_config->config_ifinfo_array, app_config->ignore_if_error)) {
      log_debug("create_subnet_ifs fail");
      goto run_engine_fail;
    }
  }

  if (eloop_init()) {
		log_debug("Failed to initialize event loop");
		goto run_engine_fail;
	}

  log_info("Creating supervisor on %s", app_config->domain_server_path);
  if ((domain_sock = run_supervisor(app_config->domain_server_path, &context)) == -1) {
    log_debug("run_supervisor fail");
    goto run_engine_fail;
  }

  if (app_config->exec_radius) {
    log_info("Creating the radius server on port %d with client ip %s",
      app_config->rconfig.radius_port, app_config->rconfig.radius_client_ip);

    radius_srv = run_radius(&app_config->rconfig, &context);
    if (radius_srv == NULL) {
      log_debug("run_radius fail");
      goto run_engine_fail;
    }
  }

  if (app_config->exec_dhcp) {
    log_info("Running the dhcp service...");
    char *dnsmasq_path = hmap_str_keychar_get(&hmap_bin_paths, "dnsmasq");
    if (dnsmasq_path == NULL) {
      log_debug("Couldn't find dnsmasq binary");
      goto run_engine_fail;
    }

    if ((hostapd_fd = run_dhcp(dnsmasq_path, &app_config->dhcp_config, app_config->hconfig.interface,
          app_config->dns_config.server_array, app_config->domain_server_path)) == -1) {
      log_debug("run_dhcp fail");
      goto run_engine_fail;
    }
  }

  if (app_config->exec_hostapd) {
    log_info("Running the hostapd service...");
    if ((hostapd_fd = run_hostapd(&app_config->hconfig, &app_config->rconfig, context.hostapd_ctrl_if_path)) == -1) {
      log_debug("run_hostapd fail");
      goto run_engine_fail;
    }
  }

  log_info("Running event loop");
  eloop_run();

  close_supervisor(domain_sock);
  close_hostapd(hostapd_fd);
  close_dhcp(dhcp_fd);
  close_radius(radius_srv);
  eloop_destroy();
  free(nat_ip);
  hmap_str_keychar_free(&hmap_bin_paths);
  free_iptables();
  free_mac_mapper(&context.mac_mapper);
  free_if_mapper(&context.if_mapper);
  free_vlan_mapper(&context.vlan_mapper);
  free_bridge_list(context.bridge_list);
  return true;

run_engine_fail:
  close_supervisor(domain_sock);
  close_hostapd(hostapd_fd);
  close_dhcp(dhcp_fd);
  close_radius(radius_srv);
  eloop_destroy();
  free(nat_ip);
  hmap_str_keychar_free(&hmap_bin_paths);
  free_iptables();
  free_mac_mapper(&context.mac_mapper);
  free_if_mapper(&context.if_mapper);
  free_vlan_mapper(&context.vlan_mapper);
  free_bridge_list(context.bridge_list);
  return false;
}