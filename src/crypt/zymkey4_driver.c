/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the implementation of zymkey4 driver configuration
 * utilities.
 */

#include <sys/types.h>
#include <zymkey/zk_app_utils.h>

#include "../utils/log.h"
#include "../utils/allocs.h"
#include "../utils/os.h"

zkCTX *init_zymkey4(void) {
  zkCTX *context = os_zalloc(sizeof(zkCTX));
  if (context == NULL) {
    log_errno("os_zalloc");
    return NULL;
  }

  if (zkOpen(context) < 0) {
    log_trace("zkOpen fail");
    os_free(context);
    return NULL;
  }

  return context;
}

int close_zymkey4(zkCTX *ctx) {
  int ret = 0;
  if (ctx != NULL) {
    ret = zkClose(*ctx);
    os_free(ctx);
  }

  return ret;
}

int generate_zymkey4_key(zkCTX *ctx, uint8_t *key, size_t key_size) {
  uint8_t *rdata = NULL;

  if (zkGetRandBytes(*ctx, &rdata, (int)key_size) < 0) {
    log_trace("zkGetRandBytes fail");
    return -1;
  }

  if (rdata == NULL) {
    log_trace("zkGetRandBytes fail");
    return -1;
  }

  os_memcpy(key, rdata, key_size);
  os_free(rdata);

  return 0;
}

int encrypt_zymkey4_blob(zkCTX *ctx, uint8_t *in, size_t in_size, uint8_t **out,
                         size_t *out_size) {
  int ret = zkLockDataB2B(*ctx, in, (int)in_size, out, (int *)out_size, false);

  if (!ret && *out == NULL) {
    log_trace("zkLockDataB2B fail");
    return -1;
  }

  return ret;
}

int decrypt_zymkey4_blob(zkCTX *ctx, uint8_t *in, size_t in_size, uint8_t **out,
                         size_t *out_size) {
  int ret =
      zkUnlockDataB2B(*ctx, in, (int)in_size, out, (int *)out_size, false);

  if (!ret && *out == NULL) {
    log_trace("zkUnlockDataB2B fail");
    return -1;
  }

  return ret;
}
