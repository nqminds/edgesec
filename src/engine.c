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
#include "utils/allocs.h"
#include "utils/os.h"
#include "utils/eloop.h"
#include "utils/iptables.h"

#include "supervisor/supervisor.h"
#include "supervisor/network_commands.h"
#include "supervisor/sqlite_fingerprint_writer.h"
#include "supervisor/sqlite_macconn_writer.h"
#include "radius/radius_service.h"
#include "ap/ap_service.h"
#include "dhcp/dhcp_service.h"
#include "crypt/crypt_service.h"

#include "engine.h"
#include "system/system_checks.h"
#include "subnet/subnet_service.h"
#include "utils/iw.h"
#include "config.h"

#define MACCONN_DB_NAME "macconn" SQLITE_EXTENSION

static const UT_icd mac_conn_icd = {sizeof(struct mac_conn), NULL, NULL, NULL};

bool init_mac_mapper_ifnames(UT_array *connections, hmap_vlan_conn **vlan_mapper)
{
  struct mac_conn *p = NULL;
  struct vlan_conn vlan_conn;

  if (connections != NULL) {
    while(p = (struct mac_conn *) utarray_next(connections, p)) {
      int ret = get_vlan_mapper(vlan_mapper, p->info.vlanid, &vlan_conn);
      os_memcpy(p->info.ifname, vlan_conn.ifname, IFNAMSIZ);
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

bool create_mac_mapper(struct supervisor_context *ctx)
{
  struct mac_conn *p = NULL;
  UT_array *mac_conn_arr;
  struct crypt_pair *pair;

  // Create the connections list
  utarray_new(mac_conn_arr, &mac_conn_icd);

  if (get_sqlite_macconn_entries(ctx->macconn_db, mac_conn_arr) < 0) {
    log_trace("get_sqlite_macconn_entries fail");
    utarray_free(mac_conn_arr);
    return false;
  }

  if (!init_mac_mapper_ifnames(mac_conn_arr, &ctx->vlan_mapper)) {
    log_debug("init_mac_mapper_ifnames fail");
    utarray_free(mac_conn_arr);
    return false;
  }
  
  if (mac_conn_arr != NULL) {
    while(p = (struct mac_conn *) utarray_next(mac_conn_arr, p)) {
      log_trace("Adding mac=" MACSTR " with id=%s vlanid=%d ifname=%s nat=%d allow=%d label=%s status=%d",
                MAC2STR(p->mac_addr), p->info.id, p->info.vlanid, p->info.ifname, p->info.nat,
                p->info.allow_connection, p->info.label, p->info.status);
      pair = get_crypt_pair(ctx->crypt_ctx, p->info.id);
      if (pair != NULL) {
        if (pair->value_size <= AP_SECRET_LEN) {
          p->info.pass_len = pair->value_size;
          os_memcpy(p->info.pass, pair->value, p->info.pass_len);
        } else
          log_trace("Unknown passphrase format for id=%s", p->info.id);

        free_crypt_pair(pair);
      }

      if (!put_mac_mapper(&ctx->mac_mapper, *p)) {
        log_trace("put_mac_mapper fail");
        free_mac_mapper(&ctx->mac_mapper);
        return false;
      }
    }
  }

  utarray_free(mac_conn_arr);
  return true;
}

bool init_context(struct app_config *app_config, struct supervisor_context *ctx)
{
  char *db_path = NULL;

  os_memset(ctx, 0, sizeof(struct supervisor_context));

  if (!init_ifbridge_names(app_config->config_ifinfo_array, app_config->hconfig.vlan_bridge)) {
    log_trace("init_ifbridge_names fail");
    return false;
  }

  ctx->hmap_bin_paths = NULL;
  ctx->radius_srv = NULL;
  ctx->crypt_ctx = NULL;
  ctx->ticket = NULL;
  ctx->iptables_ctx = NULL;
  ctx->fingeprint_db = NULL;
  ctx->domain_sock = -1;
  ctx->exec_capture = app_config->exec_capture;
  ctx->domain_delim = app_config->domain_delim;
  ctx->allow_all_connections = app_config->allow_all_connections;
  ctx->allow_all_nat = app_config->allow_all_nat;
  ctx->default_open_vlanid = app_config->default_open_vlanid;
  ctx->config_ifinfo_array = app_config->config_ifinfo_array;

  ctx->wpa_passphrase_len = os_strnlen_s(app_config->hconfig.wpa_passphrase, AP_SECRET_LEN);
  os_memcpy(ctx->wpa_passphrase, app_config->hconfig.wpa_passphrase, ctx->wpa_passphrase_len);
  
  os_memcpy(ctx->nat_interface, app_config->nat_interface, IFNAMSIZ);
  os_memcpy(ctx->db_path, app_config->db_path, MAX_OS_PATH_LEN);

  os_memcpy(&ctx->capture_config, &app_config->capture_config, sizeof(struct capture_conf));
  os_memcpy(&ctx->hconfig, &app_config->hconfig, sizeof(struct apconf));

  db_path = construct_path(ctx->db_path, MACCONN_DB_NAME);
  if (db_path == NULL) {
    log_debug("construct_path fail");
    return -1;
  }

  log_info("Opening the macconn db...");
  if (open_sqlite_macconn_db(db_path, &ctx->macconn_db) < 0) {
    os_free(db_path);
    log_debug("open_sqlite_macconn_db fail");
    return false;
  }

  os_free(db_path);

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

  // Init the list of bridges
  ctx->bridge_list = init_bridge_list();
  return true;
}

bool run_engine(struct app_config *app_config)
{
  struct supervisor_context context;

  char *commands[] = {"ip", "iw", "iptables", "dnsmasq", "sysctl", NULL};
  int ret;

  if (create_dir(app_config->db_path, S_IRWXU | S_IRWXG) < 0) {
    log_debug("create_dir fail");
    return false;
  }

  if (!init_context(app_config, &context)) {
    log_debug("init_context fail");
    goto run_engine_fail;
  }

  log_info("AP name: %s", app_config->hconfig.ssid);
  log_info("AP interface: %s", app_config->hconfig.interface);
  log_info("DB path: %s", context.db_path);

  log_info("Checking system commands...");
  if ((context.hmap_bin_paths = check_systems_commands(commands, app_config->bin_path_array, NULL)) == NULL) {
    log_debug("check_systems_commands fail (no bin paths found)");
    goto run_engine_fail;
  }

  char *iptables_path = hmap_str_keychar_get(&context.hmap_bin_paths, "iptables");
  if (iptables_path == NULL) {
    log_debug("Couldn't find xtables-multi binary");
    goto run_engine_fail;
  }

  if ((context.iptables_ctx = iptables_init(iptables_path, app_config->config_ifinfo_array, app_config->exec_iptables)) == NULL) {
    log_debug("iptables_init fail");
    goto run_engine_fail;
  }

  log_info("Loading crypt service...");
  if ((context.crypt_ctx = load_crypt_service(app_config->crypt_db_path, app_config->crypt_key_id,
                                              app_config->crypt_secret,
                                              os_strnlen_s(app_config->crypt_secret, MAX_USER_SECRET))) == NULL) {
    log_debug("load_crypt_service fail");
    goto run_engine_fail;
  }

  if (app_config->set_ip_forward) {
    log_debug("Setting the ip forward os system flag...");
    if (set_ip_forward() < 0) {
      log_debug("set_ip_forward fail");
      goto run_engine_fail;
    }
  }

  log_info("Adding default mac mappers...");
  if (!create_mac_mapper(&context)) {
    log_debug("create_mac_mapper fail");
    return false;
  }

  log_info("Checking wifi interface...");
  if (!app_config->ap_detect) {
#ifdef WITH_IW_SERVICE
    ret = is_iw_vlan(app_config->hconfig.interface);
    if(ret > 0) {
      log_debug("interface %s not VLAN capable", app_config->hconfig.interface);
      goto run_engine_fail;
    } else if (ret < 0) {
      log_debug("is_iw_vlan fail");
    }
#else
  log_warn("iw service not implemented");
#endif
  } else {
#ifdef WITH_IW_SERVICE
    if(get_valid_iw(app_config->hconfig.interface) == NULL) {
      log_debug("get_valid_iw fail");
      goto run_engine_fail;
    }
#else
  log_warn("iw service not implemented");
  goto run_engine_fail;
#endif
  }

  log_info("Found wifi interface %s", app_config->hconfig.interface);

  if (os_strnlen_s(app_config->nat_interface, IFNAMSIZ)) {
    log_info("Checking nat interface %s", app_config->nat_interface);
    if (!get_nat_if_ip(app_config->nat_interface, context.nat_ip)) {
      log_debug("get_nat_if_ip fail");
      goto run_engine_fail;
    }
    log_info("Found nat interface %s", app_config->nat_interface);
    if (validate_ipv4_string(context.nat_ip))
      log_info("Found nat IP %s", context.nat_ip);

  } else
    log_info("Not using any nat interface");

  if (app_config->create_interfaces) {
    log_info("Creating subnet interfaces...");
    if (!create_subnet_ifs(app_config->config_ifinfo_array, app_config->ignore_if_error)) {
      log_debug("create_subnet_ifs fail");
      goto run_engine_fail;
    }
  }

  log_info("Creating supervisor on %s", app_config->domain_server_path);
  if ((context.domain_sock = run_supervisor(app_config->domain_server_path, &context)) == -1) {
    log_debug("run_supervisor fail");
    goto run_engine_fail;
  }

  log_info("Running the ap service...");
  if (run_ap(&app_config->hconfig, &app_config->rconfig, app_config->exec_ap) < 0) {
    log_debug("run_ap fail");
    goto run_engine_fail;
  }

  if (app_config->exec_radius) {
    log_info("Creating the radius server on port %d with client ip %s",
      app_config->rconfig.radius_port, app_config->rconfig.radius_client_ip);

    if ((context.radius_srv = run_radius(&app_config->rconfig,
                                        (void*) get_mac_conn_cmd, &context)) == NULL) {
      log_debug("run_radius fail");
      goto run_engine_fail;
    }
  }

  if (app_config->exec_dhcp) {
    log_info("Running the dhcp service...");
    char *dnsmasq_path = hmap_str_keychar_get(&context.hmap_bin_paths, "dnsmasq");
    if (dnsmasq_path == NULL) {
      log_debug("Couldn't find dnsmasq binary");
      goto run_engine_fail;
    }

    if (run_dhcp(dnsmasq_path, &app_config->dhcp_config, app_config->hconfig.interface,
          app_config->dns_config.server_array, app_config->domain_server_path) == -1) {
      log_debug("run_dhcp fail");
      goto run_engine_fail;
    }
  }

  log_info("++++++++++++++++++");
  log_info("Running event loop");
  log_info("++++++++++++++++++");
  eloop_run();

  close_supervisor(context.domain_sock);
  close_ap();
  close_dhcp();
  close_radius(context.radius_srv);
  eloop_destroy();
  hmap_str_keychar_free(&context.hmap_bin_paths);
  iptables_free(context.iptables_ctx);
  free_mac_mapper(&context.mac_mapper);
  free_if_mapper(&context.if_mapper);
  free_vlan_mapper(&context.vlan_mapper);
  free_bridge_list(context.bridge_list);
  free_sqlite_fingerprint_db(context.fingeprint_db);
  free_sqlite_macconn_db(context.macconn_db);
  free_crypt_service(context.crypt_ctx);
  return true;

run_engine_fail:
  close_supervisor(context.domain_sock);
  close_ap();
  close_dhcp();
  close_radius(context.radius_srv);
  eloop_destroy();
  hmap_str_keychar_free(&context.hmap_bin_paths);
  iptables_free(context.iptables_ctx);
  free_mac_mapper(&context.mac_mapper);
  free_if_mapper(&context.if_mapper);
  free_vlan_mapper(&context.vlan_mapper);
  free_bridge_list(context.bridge_list);
  free_sqlite_fingerprint_db(context.fingeprint_db);
  free_sqlite_macconn_db(context.macconn_db);
  free_crypt_service(context.crypt_ctx);
  return false;
}