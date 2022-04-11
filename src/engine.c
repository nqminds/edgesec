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
#include <libgen.h>

#include "utils/log.h"
#include "utils/hashmap.h"
#include "utils/utarray.h"
#include "utils/hashmap.h"
#include "utils/allocs.h"
#include "utils/os.h"
#include "utils/net.h"
#include "utils/eloop.h"
#include "utils/iface_mapper.h"
#include "utils/ifaceu.h"
#include "utils/iface.h"

#include "supervisor/supervisor.h"
#include "supervisor/network_commands.h"
#include "supervisor/sqlite_fingerprint_writer.h"
#include "supervisor/sqlite_alert_writer.h"
#include "supervisor/sqlite_macconn_writer.h"
#include "radius/radius_service.h"
#include "ap/ap_service.h"
#include "dhcp/dhcp_service.h"
#include "dns/mdns_service.h"
#include "crypt/crypt_service.h"
#include "firewall/firewall_service.h"

#include "engine.h"
#include "config.h"

#define MACCONN_DB_NAME "macconn" SQLITE_EXTENSION

static const UT_icd mac_conn_icd = {sizeof(struct mac_conn), NULL, NULL, NULL};
static const UT_icd config_ifinfo_icd = {sizeof(config_ifinfo_t), NULL, NULL, NULL};

void copy_ifinfo(UT_array *in, UT_array *out)
{
  config_ifinfo_t *el = NULL;

  while((el = (config_ifinfo_t *) utarray_next(in, el)) != NULL) {
    utarray_push_back(out, el);
  }
}

/**
 * @brief Check if the system binaries are present and return their absolute paths
 *
 * @param commands Array of system binaries name strings
 * @param bin_path_arr Array of system binaries default fodler paths
 * @param hmap_bin_hashes Map of systems binaries to hashes
 * @return hmap_str_keychar* Map for binary to path
 */
hmap_str_keychar *check_systems_commands(char *commands[], UT_array *bin_path_arr, hmap_str_keychar *hmap_bin_hashes)
{
  (void) hmap_bin_hashes;

  if (commands == NULL) {
    log_debug("commands param NULL");
    return NULL;
  }

  hmap_str_keychar *hmap_bin_paths = hmap_str_keychar_new();

  for(uint8_t idx = 0; commands[idx] != NULL; idx ++) {
    log_debug("Checking %s command...", commands[idx]);
    char *path = get_secure_path(bin_path_arr, commands[idx], false);
    if (path == NULL) {
      log_debug("%s command not found", commands[idx]);
      free(path);
      return NULL;
    } else {
      log_debug("%s command found at %s", commands[idx], path);
      if(!hmap_str_keychar_put(&hmap_bin_paths, commands[idx], path)) {
        log_debug("hmap_str_keychar_put error");
        free(path);
        hmap_str_keychar_free(&hmap_bin_paths);
        return NULL;
      }
    }

    free(path);
  }

  return hmap_bin_paths;
}

bool init_mac_mapper_ifnames(UT_array *connections, hmap_vlan_conn **vlan_mapper)
{
  struct mac_conn *p = NULL;
  struct vlan_conn vlan_conn;

  if (connections != NULL) {
    while((p = (struct mac_conn *) utarray_next(connections, p)) != NULL) {
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
    while((p = (struct mac_conn *) utarray_next(mac_conn_arr, p)) != NULL) {
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

bool create_subnet_interfaces(struct iface_context *context, UT_array *ifinfo_array, bool ignore_error)
{
  int ret = 0;
  config_ifinfo_t *p = NULL;

  if (ifinfo_array == NULL) {
    log_trace("ifinfo_array param is NULL");
    return false;
  }

  while((p = (config_ifinfo_t*) utarray_next(ifinfo_array, p)) != NULL) {

    log_trace("Creating ifname=%s ip_addr=%s brd_addr=%s subnet_mask=%s", p->ifname, p->ip_addr, p->brd_addr, p->subnet_mask);
    ret = iface_create(context, p->brname, p->ifname, "bridge", p->ip_addr, p->brd_addr, p->subnet_mask);
    if (ret < 0 && ignore_error) {
      log_trace("iface_create fail, ignoring");
      continue;
    } else if (ret < 0 && !ignore_error) {
      log_trace("iface_create fail");
      return false;
    }
  }

  if (iface_commit(context) < 0) {
    log_debug("iface_commit fail");
    return false;
  }
  return true;
}

bool get_nat_if_ip(char *nat_interface, char *ip_buf)
{
  UT_array *interfaces = NULL;
  interfaces = iface_get(nat_interface);

  if (interfaces == NULL) {
    log_err("Interface %s not found", nat_interface);
    goto err;
  }

  netif_info_t *el = (netif_info_t*) utarray_back(interfaces);
  if (el == NULL) {
    log_err("Interface list empty");
    goto err;
  }

  os_strlcpy(ip_buf, el->ip_addr, OS_INET_ADDRSTRLEN);

  utarray_free(interfaces);
  return true;

err:
  if (interfaces != NULL) {
    utarray_free(interfaces);
  }
  return false;
}

bool construct_ap_ctrlif(char *ctrl_interface, char *interface, char *ap_ctrl_if_path)
{
  char *ctrl_if_path = construct_path(ctrl_interface, interface);
  if (ctrl_if_path == NULL) {
    log_trace("construct_path fail");
    return false;
  }

  os_strlcpy(ap_ctrl_if_path, ctrl_if_path, MAX_OS_PATH_LEN);
  os_free(ctrl_if_path);

  return true;
}

int init_context(struct app_config *app_config, struct supervisor_context *ctx)
{
  char *db_path = NULL;
  char *commands[] = {"ip", "iw", "iptables", "sysctl", NULL};

  os_memset(ctx, 0, sizeof(struct supervisor_context));

  log_info("Checking system commands...");
  if ((ctx->hmap_bin_paths = check_systems_commands(commands, app_config->bin_path_array, NULL)) == NULL) {
    log_debug("check_systems_commands fail (no bin paths found)");
    return -1;
  }

  char *ipcmd_path = hmap_str_keychar_get(&ctx->hmap_bin_paths, "ip");
  if (ipcmd_path == NULL) {
    log_debug("Couldn't find ip command");
    return -1;
  }

  utarray_new(ctx->config_ifinfo_array, &config_ifinfo_icd);
  copy_ifinfo(app_config->config_ifinfo_array, ctx->config_ifinfo_array);

  if (init_ifbridge_names(ctx->config_ifinfo_array, app_config->interface_prefix,
                  app_config->bridge_prefix) < 0)
  {
    log_trace("init_ifbridge_names fail");
    return -1;
  }

  ctx->subscribers_array = NULL;
  ctx->ap_sock = -1;
  ctx->radius_srv = NULL;
  ctx->crypt_ctx = NULL;
  ctx->iface_ctx = NULL;
  ctx->ticket = NULL;
  ctx->fw_ctx = NULL;
  ctx->fingeprint_db = NULL;
  ctx->alert_db = NULL;
  ctx->domain_sock = -1;
  ctx->exec_capture = app_config->exec_capture;
  ctx->domain_delim = app_config->domain_delim;
  ctx->allocate_vlans = app_config->allocate_vlans;
  ctx->allow_all_connections = app_config->allow_all_connections;
  ctx->allow_all_nat = app_config->allow_all_nat;
  ctx->default_open_vlanid = app_config->default_open_vlanid;
  ctx->quarantine_vlanid = app_config->quarantine_vlanid;
  ctx->risk_score = app_config->risk_score;
  ctx->wpa_passphrase_len = os_strnlen_s(app_config->hconfig.wpa_passphrase, AP_SECRET_LEN);
  os_memcpy(ctx->wpa_passphrase, app_config->hconfig.wpa_passphrase, ctx->wpa_passphrase_len);

  os_memcpy(ctx->nat_bridge, app_config->nat_bridge, IFNAMSIZ);
  os_memcpy(ctx->nat_interface, app_config->nat_interface, IFNAMSIZ);
  os_memcpy(ctx->db_path, app_config->db_path, MAX_OS_PATH_LEN);

  os_memcpy(&ctx->capture_config, &app_config->capture_config, sizeof(struct capture_conf));
  os_memcpy(&ctx->hconfig, &app_config->hconfig, sizeof(struct apconf));
  os_memcpy(&ctx->rconfig, &app_config->rconfig, sizeof(struct radius_conf));
  os_memcpy(&ctx->dconfig, &app_config->dhcp_config, sizeof(struct dhcp_conf));
  os_memcpy(&ctx->nconfig, &app_config->dns_config, sizeof(struct dns_conf));
  os_memcpy(&ctx->mconfig, &app_config->mdns_config, sizeof(struct mdns_conf));

  strcpy(ctx->dconfig.bridge_prefix, app_config->bridge_prefix);
  strcpy(ctx->dconfig.wifi_interface, app_config->hconfig.interface);
  strcpy(ctx->hconfig.vlan_bridge, app_config->interface_prefix);

  if (ctx->default_open_vlanid == ctx->quarantine_vlanid) {
    log_trace("default and quarantine vlans have the same id");
    return -1;
  }

  db_path = construct_path(ctx->db_path, MACCONN_DB_NAME);
  if (db_path == NULL) {
    log_debug("construct_path fail");
    return -1;
  }

  log_info("Opening the macconn db...");
  if (open_sqlite_macconn_db(db_path, &ctx->macconn_db) < 0) {
    os_free(db_path);
    log_debug("open_sqlite_macconn_db fail");
    return -1;
  }

  os_free(db_path);

  log_info("Creating subnet to interface mapper...");
  if ((ctx->iface_ctx = iface_init_context((char *)ipcmd_path)) == NULL) {
    log_debug("iface_init_context fail");
    return -1;
  }

  if (!create_if_mapper(ctx->config_ifinfo_array, &ctx->if_mapper)) {
    log_debug("create_if_mapper fail");
    return -1;
  }

  log_info("Creating VLAN ID to interface mapper...");
  if (!create_vlan_mapper(ctx->config_ifinfo_array, &ctx->vlan_mapper)) {
    log_debug("create_if_mapper fail");
    return -1;
  }

  // Init the list of bridges
  ctx->bridge_list = init_bridge_list();

  if (get_vlan_mapper(&ctx->vlan_mapper, ctx->default_open_vlanid, NULL) <= 0) {
    log_trace("default vlan id=%d doesn't exist", ctx->default_open_vlanid);
    return -1;
  }

  if (ctx->quarantine_vlanid >= 0) {
     if (get_vlan_mapper(&ctx->vlan_mapper, ctx->quarantine_vlanid, NULL) <= 0) {
       log_trace("quarantine vlan id=%d doesn't exist", ctx->quarantine_vlanid);
       return -1;
     }
  }

  return 0;
}

int run_mdns_forwarder(char *mdns_bin_path, char *config_ini_path)
{
  int ret;
  pid_t child_pid;
  char *proc_name;
  char *process_argv[5] = {NULL, NULL, NULL, NULL};
  process_argv[0] = mdns_bin_path;
  process_argv[1] = MDNS_OPT_CONFIG;
  process_argv[2] = config_ini_path;

  ret = run_process(process_argv, &child_pid);

  if ((proc_name = os_strdup(basename(process_argv[0]))) == NULL) {
    log_err("os_strdup");
    return -1;
  }

  if (is_proc_running(proc_name) <= 0) {
    log_trace("is_proc_running fail (%s)", proc_name);
    os_free(proc_name);
    return -1;
  }

  log_trace("Found mdns process running with pid=%d (%s)", child_pid, proc_name);
  os_free(proc_name);

  return ret;
}

bool run_engine(struct app_config *app_config)
{
  struct supervisor_context context;

  if (create_dir(app_config->db_path, S_IRWXU | S_IRWXG) < 0) {
    log_debug("create_dir fail");
    return false;
  }

  if (init_context(app_config, &context) < 0) {
    log_debug("init_context fail");
    goto run_engine_fail;
  }

  log_info("AP name: %s", context.hconfig.ssid);
  log_info("AP interface: %s", context.hconfig.interface);
  log_info("DB path: %s", context.db_path);

  if ((context.fw_ctx = fw_init_context(context.if_mapper, context.vlan_mapper,
                      context.hmap_bin_paths, context.config_ifinfo_array,
                      context.nat_bridge, context.nat_interface, app_config->exec_firewall,
                      app_config->firewall_config.firewall_bin_path)) == NULL)
  {
    log_debug("fw_init_context fail");
    goto run_engine_fail;
  }

  log_info("Loading crypt service...");
  if ((context.crypt_ctx = load_crypt_service(app_config->crypt_db_path, app_config->crypt_key_id,
                                              (uint8_t *)app_config->crypt_secret,
                                              os_strnlen_s(app_config->crypt_secret, MAX_USER_SECRET))) == NULL) {
    log_debug("load_crypt_service fail");
    goto run_engine_fail;
  }

  if (app_config->set_ip_forward) {
    log_debug("Setting the ip forward os system flag...");
    if (fw_set_ip_forward() < 0) {
      log_debug("set_ip_forward fail");
      goto run_engine_fail;
    }
  }

  log_info("Adding default mac mappers...");
  if (!create_mac_mapper(&context)) {
    log_debug("create_mac_mapper fail");
    return false;
  }

  if (app_config->ap_detect) {
    log_info("Looking for VLAN capable wifi interface...");
    if(iface_get_vlan(context.hconfig.interface) == NULL) {
      log_debug("iface_get_vlan fail");
      goto run_engine_fail;
    }
  }

  log_info("Using wifi interface %s", context.hconfig.interface);

  if(!construct_ap_ctrlif(context.hconfig.ctrl_interface, context.hconfig.interface,
                          context.hconfig.ctrl_interface_path)) {
    log_debug("construct_ap_ctrlif fail");
    goto run_engine_fail;
  }

  if (os_strnlen_s(context.nat_interface, IFNAMSIZ)) {
    log_info("Checking nat interface %s", context.nat_interface);
    if (!get_nat_if_ip(context.nat_interface, context.nat_ip)) {
      log_debug("get_nat_if_ip fail");
      goto run_engine_fail;
    }
    log_info("Found nat interface %s", context.nat_interface);
    if (validate_ipv4_string(context.nat_ip))
      log_info("Found nat IP %s", context.nat_ip);

  } else
    log_info("Not using any nat interface");

  if (app_config->create_interfaces) {
    log_info("Creating subnet interfaces...");
    if (!create_subnet_interfaces(context.iface_ctx, context.config_ifinfo_array,
        app_config->ignore_if_error))
    {
      log_debug("create_subnet_interfaces fail");
      goto run_engine_fail;
    }
  }

  log_info("Creating supervisor on %s", app_config->domain_server_path);
  if (run_supervisor(app_config->domain_server_path, &context) < 0) {
    log_debug("run_supervisor fail");
    goto run_engine_fail;
  }

  log_info("Running the ap service...");
  if (run_ap(&context, app_config->exec_ap, app_config->generate_ssid, ap_service_callback) < 0) {
    log_debug("run_ap fail");
    goto run_engine_fail;
  }

  if (app_config->exec_radius) {
    log_info("Creating the radius server on port %d with client ip %s",
      context.rconfig.radius_port, context.rconfig.radius_client_ip);

    if ((context.radius_srv = run_radius(&context.rconfig,
                                        (void*) get_mac_conn_cmd, &context)) == NULL) {
      log_debug("run_radius fail");
      goto run_engine_fail;
    }
  }

  log_info("Running the dhcp service...");
  if (run_dhcp(&context.dconfig, context.nconfig.server_array, app_config->domain_server_path,
        app_config->exec_dhcp) == -1) {
    log_debug("run_dhcp fail");
    goto run_engine_fail;
  }

  if (app_config->exec_mdns_forward) {
    log_info("Running the mdns forwarder service...");
    if (run_mdns_forwarder(app_config->mdns_config.mdns_bin_path, app_config->config_ini_path) < 0) {
      log_trace("run_mdns_forwarder fail");
      goto run_engine_fail;
    }
  }

  log_info("++++++++++++++++++");
  log_info("Running event loop");
  log_info("++++++++++++++++++");
  eloop_run();

  close_supervisor(&context);
  close_ap(&context);
  close_dhcp();
  close_radius(context.radius_srv);
  eloop_destroy();
  hmap_str_keychar_free(&context.hmap_bin_paths);
  fw_free_context(context.fw_ctx);
  free_mac_mapper(&context.mac_mapper);
  free_if_mapper(&context.if_mapper);
  free_vlan_mapper(&context.vlan_mapper);
  free_bridge_list(context.bridge_list);
  free_sqlite_macconn_db(context.macconn_db);
  free_crypt_service(context.crypt_ctx);
  iface_free_context(context.iface_ctx);
  utarray_free(context.config_ifinfo_array);

  return true;

run_engine_fail:
  close_supervisor(&context);
  close_ap(&context);
  close_dhcp();
  close_radius(context.radius_srv);
  eloop_destroy();
  hmap_str_keychar_free(&context.hmap_bin_paths);
  fw_free_context(context.fw_ctx);
  free_mac_mapper(&context.mac_mapper);
  free_if_mapper(&context.if_mapper);
  free_vlan_mapper(&context.vlan_mapper);
  free_bridge_list(context.bridge_list);
  free_sqlite_macconn_db(context.macconn_db);
  free_crypt_service(context.crypt_ctx);
  iface_free_context(context.iface_ctx);
  utarray_free(context.config_ifinfo_array);

  return false;
}