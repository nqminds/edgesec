/**
 * @file
 * @author Alexandru Mereacre
 * @date 2020
 * @copyright
 * SPDX-FileCopyrightText: © 2020 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */

/**
 * @file runctl.c
 * @author Alexandru Mereacre
 * @brief File containing the definition of the service runners.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <fcntl.h>
#include <ctype.h>
#include <unistd.h>
#include <stdbool.h>
#include <libgen.h>
#include <pthread.h>

#include "utils/log.h"
#include "utils/utarray.h"
#include "utils/hashmap.h"
#include "utils/allocs.h"
#include "utils/os.h"
#include "utils/net.h"
#include "utils/eloop.h"
#include "utils/iface_mapper.h"
#include "utils/ifaceu.h"
#include "utils/iface.h"

#include "capture/capture_service.h"

#include "supervisor/supervisor.h"
#include "supervisor/network_commands.h"
#include "supervisor/sqlite_macconn_writer.h"
#ifdef WITH_RADIUS_SERVICE
#include "radius/radius_service.h"
#endif
#include "ap/ap_service.h"
#include "dhcp/dhcp_service.h"
#include "dns/mdns_service.h"

#ifdef WITH_CRYPTO_SERVICE
#include "crypt/crypt_service.h"
#endif

#include "firewall/firewall_service.h"

#include "runctl.h"
#include "config.h"

static const UT_icd mac_conn_icd = {sizeof(struct mac_conn), NULL, NULL, NULL};
static const UT_icd config_ifinfo_icd = {sizeof(config_ifinfo_t), NULL, NULL,
                                         NULL};

void copy_ifinfo(UT_array *in, UT_array *out) {
  config_ifinfo_t *el = NULL;

  while ((el = (config_ifinfo_t *)utarray_next(in, el)) != NULL) {
    utarray_push_back(out, el);
  }
}

int init_mac_mapper_ifnames(UT_array *connections,
                            hmap_vlan_conn **vlan_mapper) {
  struct mac_conn *p = NULL;
  struct vlan_conn vlan_conn;

  if (connections != NULL) {
    while ((p = (struct mac_conn *)utarray_next(connections, p)) != NULL) {
      int ret = get_vlan_mapper(vlan_mapper, p->info.vlanid, &vlan_conn);
      os_memcpy(p->info.ifname, vlan_conn.ifname, IFNAMSIZ);
      if (ret < 0) {
        log_error("get_vlan_mapper fail");
        return -1;
      } else if (ret == 0) {
        log_error("vlan not in mapper");
        return -1;
      }
    }
  }

  return 0;
}

#ifdef WITH_CRYPTO_SERVICE
int get_crypt_wpa_passphrase(struct crypt_context *crypt_ctx,
                             struct mac_conn_info *info) {
  struct crypt_pair *pair = get_crypt_pair(crypt_ctx, info->id);

  if (pair != NULL) {
    if (pair->value_size <= AP_SECRET_LEN) {
      info->pass_len = pair->value_size;
      os_memcpy(info->pass, pair->value, info->pass_len);
    } else {
      log_error("Passphrase format for id=%s longer then %d", info->id,
                AP_SECRET_LEN);
      free_crypt_pair(pair);
      return -1;
    }
    free_crypt_pair(pair);
  }

  return 0;
}
#endif

int create_mac_mapper(struct supervisor_context *ctx) {
  struct mac_conn *p = NULL;
  UT_array *mac_conn_arr;

  // Create the connections list
  utarray_new(mac_conn_arr, &mac_conn_icd);

  if (get_sqlite_macconn_entries(ctx->macconn_db, mac_conn_arr) < 0) {
    log_error("get_sqlite_macconn_entries fail");
    utarray_free(mac_conn_arr);
    return -1;
  }

  if (init_mac_mapper_ifnames(mac_conn_arr, &ctx->vlan_mapper) < 0) {
    log_error("init_mac_mapper_ifnames fail");
    utarray_free(mac_conn_arr);
    return -1;
  }

  if (mac_conn_arr != NULL) {
    while ((p = (struct mac_conn *)utarray_next(mac_conn_arr, p)) != NULL) {
      log_debug(
          "Adding mac=" MACSTR
          " with id=%s vlanid=%d ifname=%s nat=%d allow=%d label=%s status=%d",
          MAC2STR(p->mac_addr), p->info.id, p->info.vlanid, p->info.ifname,
          p->info.nat, p->info.allow_connection, p->info.label, p->info.status);

#ifdef WITH_CRYPTO_SERVICE
      if (get_crypt_wpa_passphrase(ctx->crypt_ctx, &(p->info)) < 0) {
        log_error("get_wpa_passphrase fail");
        utarray_free(mac_conn_arr);
        return -1;
      }
#endif

      if (!put_mac_mapper(&ctx->mac_mapper, *p)) {
        log_error("put_mac_mapper fail");
        utarray_free(mac_conn_arr);
        return -1;
      }
    }
  }

  utarray_free(mac_conn_arr);
  return 0;
}

int create_subnet_interfaces(struct iface_context *context,
                             UT_array *ifinfo_array, bool ignore_error) {
  int ret = 0;
  config_ifinfo_t *p = NULL;

  if (ifinfo_array == NULL) {
    log_error("ifinfo_array param is NULL");
    return -1;
  }

  while ((p = (config_ifinfo_t *)utarray_next(ifinfo_array, p)) != NULL) {

    log_debug("Creating ifname=%s ip_addr=%s brd_addr=%s subnet_mask=%s",
              p->ifname, p->ip_addr, p->brd_addr, p->subnet_mask);
    ret = iface_create(context, p->brname, p->ifname, "bridge", p->ip_addr,
                       p->brd_addr, p->subnet_mask);
    if (ret < 0 && ignore_error) {
      log_warn("iface_create fail, ignoring");
      continue;
    } else if (ret < 0 && !ignore_error) {
      log_error("iface_create fail");
      return -1;
    }
  }

  if (iface_commit(context) < 0) {
    log_error("iface_commit fail");
    return -1;
  }
  return 0;
}

int construct_ap_ctrlif(char *ctrl_interface, char *interface,
                        char *ap_ctrl_if_path) {
  char *ctrl_if_path = construct_path(ctrl_interface, interface);
  if (ctrl_if_path == NULL) {
    log_error("construct_path fail");
    return -1;
  }

  os_strlcpy(ap_ctrl_if_path, ctrl_if_path, MAX_OS_PATH_LEN);
  os_free(ctrl_if_path);

  return 0;
}

int init_context(struct app_config *app_config,
                 struct supervisor_context *ctx) {
  char *commands[] = {"ip", "iw", "iptables", "sysctl", NULL};

  ctx->config_ifinfo_array = NULL;
  ctx->hmap_bin_paths = NULL;
  ctx->eloop = NULL;

  if (app_config->config_ifinfo_array == NULL) {
    log_error("config_ifinfo_array is NULL");
    return -1;
  }

  if ((ctx->eloop = (struct eloop_data *)eloop_init()) == NULL) {
    log_error("Failed to initialize event loop");
    return -1;
  }

  log_debug("Getting system commands paths");
  if (get_commands_paths(commands, app_config->bin_path_array,
                         &ctx->hmap_bin_paths) < 0) {
    log_error("check_systems_commands fail");
    return -1;
  }

  char *ipcmd_path = hmap_str_keychar_get(&ctx->hmap_bin_paths, "ip");
  if (ipcmd_path == NULL) {
    log_error("Couldn't find ip command");
    return -1;
  }

  utarray_new(ctx->config_ifinfo_array, &config_ifinfo_icd);
  copy_ifinfo(app_config->config_ifinfo_array, ctx->config_ifinfo_array);

  if (init_ifbridge_names(ctx->config_ifinfo_array,
                          app_config->interface_prefix,
                          app_config->bridge_prefix) < 0) {
    log_error("init_ifbridge_names fail");
    return -1;
  }

  ctx->subscribers_array = NULL;
  ctx->ap_sock = -1;
#ifdef WITH_RADIUS_SERVICE
  ctx->radius_srv = NULL;
#endif
#ifdef WITH_CRYPTO_SERVICE
  ctx->crypt_ctx = NULL;
#endif
  ctx->iface_ctx = NULL;
  ctx->ticket = NULL;
  ctx->fw_ctx = NULL;
  ctx->domain_sock = -1;
  ctx->exec_capture = app_config->exec_capture;
  ctx->allocate_vlans = app_config->allocate_vlans;
  ctx->allow_all_connections = app_config->allow_all_connections;
  ctx->allow_all_nat = app_config->allow_all_nat;
  ctx->default_open_vlanid = app_config->default_open_vlanid;
  ctx->quarantine_vlanid = app_config->quarantine_vlanid;
  ctx->wpa_passphrase_len =
      os_strnlen_s(app_config->hconfig.wpa_passphrase, AP_SECRET_LEN);
  os_memcpy(ctx->wpa_passphrase, app_config->hconfig.wpa_passphrase,
            ctx->wpa_passphrase_len);

  os_memcpy(ctx->nat_bridge, app_config->nat_bridge, IFNAMSIZ);
  os_memcpy(ctx->nat_interface, app_config->nat_interface, IFNAMSIZ);

  os_memcpy(&ctx->capture_config, &app_config->capture_config,
            sizeof(struct capture_conf));
  os_memcpy(&ctx->hconfig, &app_config->hconfig, sizeof(struct apconf));
  os_memcpy(&ctx->rconfig, &app_config->rconfig, sizeof(struct radius_conf));
  os_memcpy(&ctx->dconfig, &app_config->dhcp_config, sizeof(struct dhcp_conf));
  os_memcpy(&ctx->nconfig, &app_config->dns_config, sizeof(struct dns_conf));
  os_memcpy(&ctx->mconfig, &app_config->mdns_config, sizeof(struct mdns_conf));

  strcpy(ctx->dconfig.bridge_prefix, app_config->bridge_prefix);
  strcpy(ctx->dconfig.wifi_interface, app_config->hconfig.interface);
  strcpy(ctx->hconfig.vlan_bridge, app_config->interface_prefix);

  if (ctx->default_open_vlanid == ctx->quarantine_vlanid) {
    log_error("default and quarantine vlans have the same id");
    return -1;
  }

  log_debug("Opening the macconn db=%s", app_config->connection_db_path);
  if (open_sqlite_macconn_db(app_config->connection_db_path, &ctx->macconn_db) <
      0) {
    log_error("open_sqlite_macconn_db fail");
    return -1;
  }

  log_debug("Creating subnet to interface mapper...");
  if ((ctx->iface_ctx = iface_init_context((char *)ipcmd_path)) == NULL) {
    log_debug("iface_init_context fail");
    return -1;
  }

  if (!create_if_mapper(ctx->config_ifinfo_array, &ctx->if_mapper)) {
    log_error("create_if_mapper fail");
    return -1;
  }

  log_debug("Creating VLAN ID to interface mapper...");
  if (!create_vlan_mapper(ctx->config_ifinfo_array, &ctx->vlan_mapper)) {
    log_error("create_if_mapper fail");
    return -1;
  }

  // Init the list of bridges
  ctx->bridge_list = init_bridge_list();

  if (get_vlan_mapper(&ctx->vlan_mapper, ctx->default_open_vlanid, NULL) <= 0) {
    log_error("default vlan id=%d doesn't exist", ctx->default_open_vlanid);
    return -1;
  }

  if (ctx->quarantine_vlanid >= 0) {
    if (get_vlan_mapper(&ctx->vlan_mapper, ctx->quarantine_vlanid, NULL) <= 0) {
      log_error("quarantine vlan id=%d doesn't exist", ctx->quarantine_vlanid);
      return -1;
    }
  }

  return 0;
}

int run_mdns_forwarder(char *mdns_bin_path, char *config_ini_path) {
  int ret;
  pid_t child_pid;
  char *proc_name;
  char *process_argv[5] = {NULL, NULL, NULL, NULL};
  process_argv[0] = mdns_bin_path;
  process_argv[1] = MDNS_OPT_CONFIG;
  process_argv[2] = config_ini_path;

  ret = run_process(process_argv, &child_pid);

  if ((proc_name = os_strdup(basename(process_argv[0]))) == NULL) {
    log_errno("os_strdup");
    return -1;
  }

  if (is_proc_running(proc_name) <= 0) {
    log_error("is_proc_running fail (%s)", proc_name);
    os_free(proc_name);
    return -1;
  }

  log_debug("Found mdns process running with pid=%d (%s)", child_pid,
            proc_name);
  os_free(proc_name);

  return ret;
}

void close_capture_thread(const hmap_vlan_conn *vlan_mapper) {
  for (const hmap_vlan_conn *current = vlan_mapper; current != NULL;
       current = current->hh.next) {
    if (current->value.capture_pid == 0) {
      continue; // vlan has no capture thread running
    }
    if (pthread_join(current->value.capture_pid, NULL) != 0) {
      log_errno("pthread_join");
    }
  }
}

int run_ctl(struct app_config *app_config) {
  struct supervisor_context *context = NULL;

  if ((context = os_zalloc(sizeof(struct supervisor_context))) == NULL) {
    log_errno("os_zalloc");
    return -1;
  }

  if (init_context(app_config, context) < 0) {
    log_error("init_context fail");
    goto run_engine_fail;
  }

  log_info("AP name: %s", context->hconfig.ssid);
  log_info("AP interface: %s", context->hconfig.interface);

  if ((context->fw_ctx = fw_init_context(
           context->if_mapper, context->vlan_mapper, context->hmap_bin_paths,
           context->config_ifinfo_array, context->nat_bridge,
           context->nat_interface, app_config->exec_firewall,
           app_config->firewall_config.firewall_bin_path)) == NULL) {
    log_error("fw_init_context fail");
    goto run_engine_fail;
  }

#ifdef WITH_CRYPTO_SERVICE
  log_info("Loading crypt service...");
  if ((context->crypt_ctx = load_crypt_service(
           app_config->crypt_db_path, MAIN_CRYPT_KEY_ID,
           (uint8_t *)app_config->crypt_secret,
           os_strnlen_s(app_config->crypt_secret, MAX_USER_SECRET))) == NULL) {
    log_error("load_crypt_service fail");
    goto run_engine_fail;
  }
#endif

  if (app_config->set_ip_forward) {
    log_info("Setting the ip forward os system flag...");
    if (fw_set_ip_forward() < 0) {
      log_error("set_ip_forward fail");
      goto run_engine_fail;
    }
  }

  log_info("Adding default mac mappers...");
  if (create_mac_mapper(context) < 0) {
    log_error("create_mac_mapper fail");
    return false;
  }

  if (app_config->ap_detect) {
    log_info("Looking for VLAN capable wifi interface...");
    if (iface_get_vlan(context->hconfig.interface) == NULL) {
      log_error("iface_get_vlan fail");
      goto run_engine_fail;
    }
  }

  log_info("Using wifi interface %s", context->hconfig.interface);

  if (construct_ap_ctrlif(context->hconfig.ctrl_interface,
                          context->hconfig.interface,
                          context->hconfig.ctrl_interface_path) < 0) {
    log_error("construct_ap_ctrlif fail");
    goto run_engine_fail;
  }

  if (app_config->create_interfaces) {
    log_info("Creating subnet interfaces...");
    if (create_subnet_interfaces(context->iface_ctx,
                                 context->config_ifinfo_array,
                                 app_config->ignore_if_error) < 0) {
      log_error("create_subnet_interfaces fail");
      goto run_engine_fail;
    }
  }

  log_info("Creating supervisor on %s with port %d",
           app_config->supervisor_control_path,
           app_config->supervisor_control_port);

  if (run_supervisor(app_config->supervisor_control_path,
                     app_config->supervisor_control_port, context) < 0) {
    log_error("run_supervisor fail");
    goto run_engine_fail;
  }

  log_info("Running the ap service...");
  if (run_ap(context, app_config->exec_ap, app_config->generate_ssid,
             ap_service_callback) < 0) {
    log_error("run_ap fail");
    goto run_engine_fail;
  }

#ifdef WITH_RADIUS_SERVICE
  if (app_config->exec_radius) {
    log_info("Creating the radius server on port %d with client ip %s",
             context->rconfig.radius_port, context->rconfig.radius_client_ip);

    if ((context->radius_srv = run_radius(context->eloop, &context->rconfig,
                                          (void *)get_mac_conn_cmd, context)) ==
        NULL) {
      log_error("run_radius fail");
      goto run_engine_fail;
    }
  }
#endif

  log_info("Running the dhcp service...");
  if (run_dhcp(&context->dconfig, context->nconfig.server_array,
               app_config->supervisor_control_path,
               app_config->exec_dhcp) == -1) {
    log_error("run_dhcp fail");
    goto run_engine_fail;
  }

#ifdef WITH_MDNS_SERVICE
  pthread_t mdns_pid = 0;
  if (app_config->exec_mdns_forward) {
    log_info("Running the mdns forwarder service thread...");
    if (run_mdns_thread(&(app_config->mdns_config),
                        app_config->supervisor_control_path,
                        context->vlan_mapper, &mdns_pid) < 0) {
      log_error("run_mdns_thread fail");
      goto run_engine_fail;
    }
  }
#endif

  log_info("++++++++++++++++++");
  log_info("Running event loop");
  log_info("++++++++++++++++++");

  eloop_run(context->eloop);

  if (context->exec_capture) {
    close_capture_thread(context->vlan_mapper);
  }

#ifdef WITH_MDNS_SERVICE
  if (app_config->exec_mdns_forward && mdns_pid) {
    if (pthread_join(mdns_pid, NULL) != 0) {
      log_errno("pthread_join");
    }
  }
#endif

  close_supervisor(context);
  close_ap(context);
  close_dhcp();
#ifdef WITH_RADIUS_SERVICE
  close_radius(context->radius_srv);
#endif
  hmap_str_keychar_free(&context->hmap_bin_paths);
  fw_free_context(context->fw_ctx);
  free_mac_mapper(&context->mac_mapper);
  free_if_mapper(&context->if_mapper);
  free_vlan_mapper(&context->vlan_mapper);
  free_bridge_list(context->bridge_list);
  free_sqlite_macconn_db(context->macconn_db);
#ifdef WITH_CRYPTO_SERVICE
  free_crypt_service(context->crypt_ctx);
#endif
  iface_free_context(context->iface_ctx);
  utarray_free(context->config_ifinfo_array);
  eloop_free(context->eloop);
  os_free(context);

  return 0;

run_engine_fail:
  close_supervisor(context);
  close_ap(context);
  close_dhcp();
#ifdef WITH_RADIUS_SERVICE
  close_radius(context->radius_srv);
#endif
  hmap_str_keychar_free(&context->hmap_bin_paths);
  fw_free_context(context->fw_ctx);
  free_mac_mapper(&context->mac_mapper);
  free_if_mapper(&context->if_mapper);
  free_vlan_mapper(&context->vlan_mapper);
  free_bridge_list(context->bridge_list);
  free_sqlite_macconn_db(context->macconn_db);
#ifdef WITH_CRYPTO_SERVICE
  free_crypt_service(context->crypt_ctx);
#endif
  iface_free_context(context->iface_ctx);
  if (context->config_ifinfo_array != NULL) {
    utarray_free(context->config_ifinfo_array);
  }
  eloop_free(context->eloop);
  os_free(context);
  return -1;
}
