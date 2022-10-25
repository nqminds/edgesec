/**
 * @file
 * @author Alexandru Mereacre
 * @date 2022
 * @copyright
 * SPDX-FileCopyrightText: © 2020 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the implementation of the supervisor utils.
 */

#include <inttypes.h>

#ifdef WITH_CRYPTO_SERVICE
#include "../crypt/crypt_service.h"
#endif

#include "../utils/os.h"

#include "sqlite_macconn_writer.h"
#include "supervisor_config.h"

int allocate_vlan(struct supervisor_context *context, uint8_t *mac_addr) {
  (void)mac_addr;
  int *vlan_arr = NULL;
  int vlanid, idx = 0, len;
  config_ifinfo_t *p = NULL;
  UT_array *config_ifinfo_array = context->config_ifinfo_array;

  if (!context->allocate_vlans) {
    return context->default_open_vlanid;
  }

  len = utarray_len(config_ifinfo_array);
  if (len <= 1) {
    return context->default_open_vlanid;
  }

  if ((vlan_arr = (int *)os_malloc(sizeof(int) * len)) == NULL) {
    log_errno("os_malloc");
    return -1;
  }

  while ((p = (config_ifinfo_t *)utarray_next(config_ifinfo_array, p)) !=
         NULL) {
    vlan_arr[idx++] = p->vlanid;
  }

  vlanid = vlan_arr[os_get_random_int_range(0, len)];
  os_free(vlan_arr);

  return vlanid;
}

#ifdef WITH_CRYPTO_SERVICE
int save_to_crypt(struct crypt_context *crypt_ctx, struct mac_conn_info *info) {
  struct crypt_pair pair;

  pair.key = info->id;
  pair.value = info->pass;
  pair.value_size = info->pass_len;

  if (put_crypt_pair(crypt_ctx, &pair) < 0) {
    log_trace("put_crypt_pair fail");
    return -1;
  }

  return 0;
}
#endif

int save_mac_mapper(struct supervisor_context *context, struct mac_conn conn) {
  if (!strlen(conn.info.id)) {
    generate_radom_uuid(conn.info.id);
  }

  if (!put_mac_mapper(&context->mac_mapper, conn)) {
    log_error("put_mac_mapper fail");
    return -1;
  }

#ifdef WITH_CRYPTO_SERVICE
  if (save_to_crypt(context->crypt_ctx, &(conn.info)) < 0) {
    log_error("save_to_crypt failure");
    return -1;
  }

  // Reset the plain password array so that it is not stored
  // in plain form in the sqlite db
  conn.info.pass_len = 0;
  os_memset(conn.info.pass, 0, AP_SECRET_LEN);
#endif

  if (save_sqlite_macconn_entry(context->macconn_db, &conn) < 0) {
    log_error("upsert_sqlite_macconn_entry fail");
    return -1;
  }

  return 0;
}
