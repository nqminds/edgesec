/**
 * @file
 * @author Alexandru Mereacre
 * @date 2020
 * @copyright
 * SPDX-FileCopyrightText: © 2020 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the implementation of the hostapd service.
 *
 * Defines the functions to start and stop the acces point service (AP). It also
 * defines auxiliary commands to manage the acces control list for stations
 * connected to the AP.
 */
#include <errno.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "ap_config.h"
#include "ap_service.h"
#include "hostapd.h"

#include <eloop.h>
#include "../radius/radius_server.h"
#include "../supervisor/supervisor_config.h"
#include "../utils/allocs.h"
#include "../utils/iface.h"
#include "../utils/log.h"
#include "../utils/os.h"
#include "../utils/sockctl.h"

#define AP_STA_DISCONNECTED "AP-STA-DISCONNECTED"
#define AP_STA_CONNECTED "AP-STA-CONNECTED"

int ping_ap_command(struct apconf *hconf) {
  char *reply = NULL;

  if (writeread_domain_data_str(hconf->ctrl_interface_path, PING_AP_COMMAND,
                                &reply) < 0) {
    log_error("writeread_domain_data_str fail");
    return -1;
  }

  if (strcmp(reply, PING_AP_COMMAND_REPLY) != 0) {
    log_error(PING_AP_COMMAND_REPLY " reply doesn't match %s", reply);
    os_free(reply);
    return -1;
  }

  os_free(reply);
  return 0;
}

int denyacl_ap_command(struct apconf *hconf, const char *cmd,
                       const char *mac_addr) {
  char *buffer = NULL;
  char *reply = NULL;

  int return_code = -1;

  if (mac_addr == NULL) {
    log_error("mac_addr is NULL");
    goto error_cleanup;
  }

  buffer = malloc(strlen(cmd) + 1 /* space char */ + strlen(mac_addr) +
                  1 /* nul terminator */
  );
  if (buffer == NULL) {
    log_errno("malloc");
    goto error_cleanup;
  }

  sprintf(buffer, "%s %s", cmd, mac_addr);
  if (writeread_domain_data_str(hconf->ctrl_interface_path, buffer, &reply) <
      0) {
    log_error("writeread_domain_data_str fail");
    goto error_cleanup;
  }

  if (strcmp(reply, GENERIC_AP_COMMAND_OK_REPLY) != 0) {
    log_error(GENERIC_AP_COMMAND_OK_REPLY " reply doesn't match %s", reply);
    goto error_cleanup;
  }

  return_code = 0;
error_cleanup:
  // free(null_ptr) is perfectly safe and does nothing
  free(buffer);
  os_free(reply);

  return return_code;
}

int denyacl_add_ap_command(struct apconf *hconf, const char *mac_addr) {
  return denyacl_ap_command(hconf, DENYACL_ADD_COMMAND, mac_addr);
}

int denyacl_del_ap_command(struct apconf *hconf, const char *mac_addr) {
  return denyacl_ap_command(hconf, DENYACL_DEL_COMMAND, mac_addr);
}

int disconnect_ap_command(struct apconf *hconf, const char *mac_addr) {
  if (denyacl_add_ap_command(hconf, mac_addr) < 0) {
    log_error("denyacl_add_ap_command fail");
    return -1;
  }

  if (denyacl_del_ap_command(hconf, mac_addr) < 0) {
    log_error("denyacl_del_ap_command fail");
    return -1;
  }

  return 0;
}

int check_sta_ap_command(struct apconf *hconf, const char *mac_addr) {
  char *buffer = NULL;
  char *reply = NULL;

  int return_code = -1;

  if (mac_addr == NULL) {
    log_error("mac_addr is NULL");
    goto error_cleanup;
  }

  buffer = malloc(strlen(STA_AP_COMMAND) + 1 /* space char */ +
                  strlen(mac_addr) + 1 /* nul terminator */);
  if (buffer == NULL) {
    log_errno("malloc");
    goto error_cleanup;
  }

  sprintf(buffer, STA_AP_COMMAND " %s", mac_addr);
  if (writeread_domain_data_str(hconf->ctrl_interface_path, buffer, &reply) <
      0) {
    log_error("writeread_domain_data_str fail");
    goto error_cleanup;
  }

  if (strcmp(reply, GENERIC_AP_COMMAND_FAIL_REPLY) == 0) {
    log_error("no STA registered with mac=%s", mac_addr);
    goto error_cleanup;
  }

  if (!strlen(reply)) {
    log_error("no reply for mac=%s", mac_addr);
    goto error_cleanup;
  }

  return_code = 0;
error_cleanup:
  // free(NULL ptr) is safe and does nothing
  free(buffer);
  os_free(reply);
  return return_code;
}

/**
 * @brief Finds the stauts of the given access point
 *
 * @param ap_answer Response from ap socket.
 * @param[out] mac_addr The MAC address of the AP.
 * @param[out] status Outputs the the status of the AP to this variable.
 * @retval  0 Sucess.
 * @retval -1 Error. No valid AP status found in the @p ap_answer string.
 */
int find_ap_status(const char *ap_answer,
                   uint8_t mac_addr[static ETHER_ADDR_LEN],
                   enum AP_CONNECTION_STATUS *status) {
  UT_array *str_arr;
  utarray_new(str_arr, &ut_str_icd);

  int return_code = -1;

  if (split_string_array(ap_answer, 0x20, str_arr) <= 1) {
    goto cleanup;
  }

  char **status_string = (char **)utarray_front(str_arr);
  if (status_string == NULL || *status_string == NULL) {
    goto cleanup;
  }

  if (strstr(*status_string, AP_STA_CONNECTED) != NULL) {
    *status = AP_CONNECTED_STATUS;
  } else if (strstr(ap_answer, AP_STA_DISCONNECTED) != NULL) {
    *status = AP_DISCONNECTED_STATUS;
  } else {
    goto cleanup;
  }

  char **mac_address_string = (char **)utarray_next(str_arr, status_string);
  if (mac_address_string == NULL || *mac_address_string == NULL) {
    goto cleanup;
  }
  if (hwaddr_aton2(*mac_address_string, mac_addr) < 0) {
    goto cleanup;
  }

  return_code = 0;
cleanup:
  utarray_free(str_arr);
  return return_code;
}

void ap_sock_handler(int sock, void *eloop_ctx, void *sock_ctx) {
  struct supervisor_context *context = (struct supervisor_context *)sock_ctx;
  ap_service_fn fn =
      ((struct run_ap_callback_fn_struct *)eloop_ctx)->ap_service_fn;

  uint32_t bytes_available;
  if (ioctl(sock, FIONREAD, &bytes_available) == -1) {
    log_errno("ioctl");
    return;
  }

  char *rec_data = os_zalloc(bytes_available + 1);
  if (rec_data == NULL) {
    log_errno("os_zalloc");
    return;
  }

  if (read_domain_data_s(sock, rec_data, bytes_available,
                         context->hconfig.ctrl_interface_path,
                         MSG_DONTWAIT) < 0) {
    log_error("read_domain_data_s fail");
    os_free(rec_data);
    return;
  }

  char *trimmed = rtrim(rec_data, NULL);
  if (trimmed == NULL) {
    log_error("rtrim fail");
    os_free(rec_data);
    return;
  }

  enum AP_CONNECTION_STATUS status;
  uint8_t mac_addr[ETHER_ADDR_LEN];
  if (find_ap_status(trimmed, mac_addr, &status) > -1) {
    fn(context, mac_addr, status);
  }

  os_free(rec_data);
}

int register_ap_event(struct supervisor_context *context,
                      struct run_ap_callback_fn_struct *ap_callback_fn) {
  ssize_t cmd_len = (ssize_t)ARRAY_SIZE(ATTACH_AP_COMMAND);

  if ((context->ap_sock = create_domain_client(NULL)) == -1) {
    log_error("create_domain_client fail");
    return -1;
  }

  if (edge_eloop_register_read_sock(context->eloop, context->ap_sock,
                               ap_sock_handler, ap_callback_fn,
                               (void *)context) == -1) {
    log_error("edge_eloop_register_read_sock fail");
    return -1;
  }

  log_debug("Sending command %s to socket_path=%s", ATTACH_AP_COMMAND,
            context->hconfig.ctrl_interface_path);
  if (write_domain_data_s(context->ap_sock, ATTACH_AP_COMMAND, cmd_len,
                          context->hconfig.ctrl_interface_path) != cmd_len) {
    log_error("write_domain_data_s fail");
    return -1;
  }

  return 0;
}

int run_ap(struct supervisor_context *context, bool exec_ap, bool generate_ssid,
           struct run_ap_callback_fn_struct *ap_callback_fn) {
  if (generate_vlan_conf(context->hconfig.vlan_file,
                         context->hconfig.interface) < 0) {
    log_error("generate_vlan_conf fail");
    return -1;
  }

  if (generate_ssid) {
    char hostname[OS_HOST_NAME_MAX];
    if (get_hostname(hostname) < 0) {
      log_error("get_hostname fail");
      return -1;
    }
    os_strlcpy(context->hconfig.ssid, hostname, AP_NAME_LEN);
    log_debug("Regenerating SSID=%s", context->hconfig.ssid);
  }

  if (generate_hostapd_conf(&context->hconfig, &context->rconfig) < 0) {
    log_error("generate_hostapd_conf fail");
    return -1;
  }

  int res;
  if (exec_ap) {
    res = run_ap_process(&context->hconfig);
  } else {
    res = signal_ap_process(&context->hconfig);
  }

  if (!res && ping_ap_command(&context->hconfig) < 0) {
    log_warn("ping_ap_command fail");
  }

  if (register_ap_event(context, ap_callback_fn) < 0) {
    log_warn("register_ap_event fail");
  }

  return res;
}

bool close_ap(struct supervisor_context *context) {
  if (context->ap_sock != -1) {
    close_domain_socket(context->ap_sock);
    context->ap_sock = -1;
  }

  return kill_ap_process();
}
