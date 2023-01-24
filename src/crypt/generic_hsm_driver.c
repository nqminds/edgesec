/**
 * @file
 * @author Alexandru Mereacre
 * @date 2021
 * @copyright
 * SPDX-FileCopyrightText: © 2021 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the implementation of generic HSM driver configuration
 * utilities.
 */
#include <sys/types.h>

#ifdef WITH_ZYMKEY4_HSM
#include "zymkey4_driver.h"
#endif

#include "generic_hsm_driver.h"

#include "../utils/allocs.h"
#include "../utils/log.h"
#include "../utils/os.h"

struct hsm_context *init_hsm(void) {
  struct hsm_context *context = sys_zalloc(sizeof(struct hsm_context));

  if (context == NULL) {
    log_errno("sys_zalloc");
    return NULL;
  }

#ifdef WITH_ZYMKEY4_HSM
  zkCTX *zk_ctx = init_zymkey4();
  if (zk_ctx == NULL) {
    log_trace("init_zymkey4 fail");
    os_free(context);
    return NULL;
  }
  context->hsm_ctx = (void *)zk_ctx;

#else
  log_debug("No HSM implemented");
  os_free(context);
  return NULL;
#endif

  return context;
}

int close_hsm(struct hsm_context *context) {
  int ret = -1;

  if (context == NULL) {
    log_trace("context param is NULL");
    return -1;
  }

#ifdef WITH_ZYMKEY4_HSM
  ret = close_zymkey4((zkCTX *)context->hsm_ctx);
#else
  log_debug("No HSM implemented");
#endif

  os_free(context);
  return ret;
}

int generate_hsm_key(struct hsm_context *context, uint8_t *key,
                     size_t key_size) {
  if (context == NULL) {
    log_trace("context param is NULL");
    return -1;
  }

  if (key == NULL) {
    log_trace("key param is NULL");
    return -1;
  }

#ifdef WITH_ZYMKEY4_HSM
  return generate_zymkey4_key((zkCTX *)context->hsm_ctx, key, key_size);
#else
  (void)key_size;
  log_debug("No HSM implemented");
  return -1;
#endif
}

int encrypt_hsm_blob(struct hsm_context *context, uint8_t *in, size_t in_size,
                     uint8_t **out, size_t *out_size) {
  if (context == NULL) {
    log_trace("context param is NULL");
    return -1;
  }

  if (in == NULL) {
    log_trace("in param is NULL");
    return -1;
  }

  if (out == NULL) {
    log_trace("out param is NULL");
    return -1;
  }

  if (out_size == NULL) {
    log_trace("out_size param is NULL");
    return -1;
  }

#ifdef WITH_ZYMKEY4_HSM
  return encrypt_zymkey4_blob((zkCTX *)context->hsm_ctx, in, in_size, out,
                              out_size);
#else
  (void)in_size;
  log_debug("No HSM implemented");
  return -1;
#endif
}

int decrypt_hsm_blob(struct hsm_context *context, uint8_t *in, size_t in_size,
                     uint8_t **out, size_t *out_size) {
  if (context == NULL) {
    log_trace("context param is NULL");
    return -1;
  }

  if (in == NULL) {
    log_trace("in param is NULL");
    return -1;
  }

  if (out == NULL) {
    log_trace("out param is NULL");
    return -1;
  }

  if (out_size == NULL) {
    log_trace("out param is NULL");
    return -1;
  }

#ifdef WITH_ZYMKEY4_HSM
  return decrypt_zymkey4_blob((zkCTX *)context->hsm_ctx, in, in_size, out,
                              out_size);
#else
  (void)in_size;

  log_debug("No HSM implemented");
  return -1;
#endif
}
