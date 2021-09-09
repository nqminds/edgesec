/****************************************************************************
 * Copyright (C) 2021 by NQMCyber Ltd                                       *
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
 * @file generic_hsm_driver.c
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of generic HSM driver configuration utilities.
 */
#include <sys/types.h>

#ifdef WITH_ZYMKEY4_HSM
#include "zymkey4_driver.h"
#endif

#include "generic_hsm_driver.h"

#include "../utils/log.h"
#include "../utils/allocs.h"
#include "../utils/os.h"

struct hsm_context* init_hsm(void)
{
  struct hsm_context* context = os_zalloc(sizeof(struct hsm_context));

  if (context == NULL) {
    log_err("os_zalloc");
    return NULL;
  }

#ifdef WITH_ZYMKEY4_HSM
  zkCTX* zk_ctx = init_zymkey4();
  if (zk_ctx == NULL) {
    log_trace("init_zymkey4 fail");
    os_free(context);
    return NULL;
  }
  context->hsm_ctx = (void *)zk_ctx;

#else
    log_debug("No HSM found");
    os_free(context);
    return NULL;
#endif

  return context;
}

int close_hsm(struct hsm_context *context)
{
  int ret = 0;

  if (context != NULL) {
#ifdef WITH_ZYMKEY4_HSM
    ret = close_zymkey4((zkCTX *)context->hsm_ctx);
#endif
    os_free(context);
  }

  return ret;
}

int generate_hsm_key(struct hsm_context *context, uint8_t *key, size_t key_size)
{
  if (context != NULL) {
#ifdef WITH_ZYMKEY4_HSM
    return generate_zymkey4_key((zkCTX *)context->hsm_ctx, key, key_size);
#endif
  }

  return -1;
}

int encrypt_hsm_blob(struct hsm_context *context, uint8_t *in, size_t in_size, uint8_t **out, size_t *out_size)
{
  if (context != NULL) {
#ifdef WITH_ZYMKEY4_HSM
    return encrypt_zymkey4_blob((zkCTX *)context->hsm_ctx, in, in_size, out, out_size);
#endif
  }

  return -1;
}