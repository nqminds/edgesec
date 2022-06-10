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
 * @file mdns_mapper.c
 * @author Alexandru Mereacre
 * @brief File containing the implementation of the mdns mapper utils.
 */

#include "mdns_list.h"
#include "mdns_mapper.h"

#include "../utils/os.h"
#include "../utils/utarray.h"
#include "../utils/uthash.h"
#include "../capture/header_middleware/mdns_decoder.h"

int put_mdns_info(hmap_mdns_conn **imap, uint8_t *ip,
                  struct mdns_list_info *info) {
  hmap_mdns_conn *s = NULL, *el = NULL;

  HASH_FIND(hh, *imap, ip, IP_ALEN, s); /* IP already in the hash? */

  if (s == NULL) {
    if ((el = (hmap_mdns_conn *)os_malloc(sizeof(hmap_mdns_conn))) == NULL) {
      log_errno("os_malloc");
      return -1;
    }

    os_memcpy(el->key, ip, IP_ALEN);

    if ((el->value = init_mdns_list()) == NULL) {
      log_trace("init_mdns_list fail");
      os_free(el);
      return -1;
    }
  } else {
    el = s;
  }

  if (push_mdns_list(el->value, info) < 0) {
    log_trace("push_mdns_list fail");
    if (el != NULL && s == NULL) {
      os_free(el);
    }
    return -1;
  }

  if (s == NULL) {
    HASH_ADD(hh, *imap, key[0], IP_ALEN, el);
  }

  return 0;
}

int put_mdns_query_mapper(hmap_mdns_conn **imap, uint8_t *ip,
                          struct mdns_query_entry *query) {
  struct mdns_list_info info;

  if (imap == NULL) {
    log_trace("imap param is NULL");
    return -1;
  }

  if (ip == NULL) {
    log_trace("ip param is NULL");
    return -1;
  }

  if (query == NULL) {
    log_trace("query param is NULL");
    return -1;
  }

  info.name = query->qname;
  info.qtype = query->qtype;
  info.request = MDNS_REQUEST_QUERY;

  if (put_mdns_info(imap, ip, &info) < 0) {
    log_trace("put_mdns_info fail");
    return -1;
  }

  return 0;
}

int put_mdns_answer_mapper(hmap_mdns_conn **imap, uint8_t *ip,
                           struct mdns_answer_entry *answer) {
  struct mdns_list_info info;

  if (imap == NULL) {
    log_trace("imap param is NULL");
    return -1;
  }

  if (ip == NULL) {
    log_trace("ip param is NULL");
    return -1;
  }

  if (answer == NULL) {
    log_trace("answer param is NULL");
    return -1;
  }

  info.name = answer->rrname;
  info.rrtype = answer->rrtype;
  info.ttl = answer->ttl;
  info.request = MDNS_REQUEST_ANSWER;

  if (put_mdns_info(imap, ip, &info) < 0) {
    log_trace("put_mdns_info fail");
    return -1;
  }

  return 0;
}

void free_mdns_mapper(hmap_mdns_conn **imap) {
  hmap_mdns_conn *current, *tmp;

  HASH_ITER(hh, *imap, current, tmp) {
    HASH_DEL(*imap, current);
    free_mdns_list(current->value);
    os_free(current);
  }
}

int check_mdns_mapper_req(hmap_mdns_conn **imap, uint8_t *ip,
                          enum MDNS_REQUEST_TYPE request) {
  hmap_mdns_conn *s = NULL;
  int ret;

  if (imap == NULL) {
    log_trace("imap param is NULL");
    return -1;
  }

  if (ip == NULL) {
    log_trace("ip param is NULL");
    return -1;
  }

  HASH_FIND(hh, *imap, ip, IP_ALEN, s); /* IP already in the hash? */

  if (s == NULL) {
    return 0;
  } else {
    ret = check_mdns_list_req(s->value, request);
    if (ret < 0) {
      log_trace("check_mdns_list_req fail");
      return -1;
    } else
      return ret;
  }
}
