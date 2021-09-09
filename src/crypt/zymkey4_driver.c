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
 * @file zymkey4_driver.c
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of zymkey4 driver configuration utilities.
 */

#include <sys/types.h>
#include <zymkey/zk_app_utils.h>

#include "../utils/log.h"
#include "../utils/allocs.h"
#include "../utils/os.h"

zkCTX* init_zymkey4(void)
{
  zkCTX* context = os_zalloc(sizeof(zkCTX));
  if (context == NULL) {
    log_err("os_zalloc");
    return NULL;
  }

  if (zkOpen(context) < 0) {
    log_trace("zkOpen fail");
    os_free(context);
    return NULL;
  }

  return context;
}

int close_zymkey4(zkCTX *ctx)
{
  int ret = 0;
  if (ctx != NULL) {
    ret = zkClose(*ctx);
    os_free(ctx);
  }

  return ret;
}

int generate_zymkey4_key(zkCTX *ctx, uint8_t *key, size_t key_size)
{
// if (zkGetRandBytes (
// zkCTX ctx,
// uint8_t ** rdata,
// int rdata_sz
// ) 
  return -1;
}