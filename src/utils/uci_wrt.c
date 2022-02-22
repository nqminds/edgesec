/****************************************************************************
 * Copyright (C) 2022 by NQMCyber Ltd                                       *
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
 * @file uci.c
 * @author Alexandru Mereacre
 * @brief File containing the implementation of the uci utilities.
 */

#include <uci.h>

#include "uci_wrt.h"

#include "iface_mapper.h"
#include "utarray.h"
#include "squeue.h"
#include "allocs.h"
#include "log.h"

#define IFNAME_EXPR ".ifname="
#define IPADDR_EXPR ".ipaddr="

struct uci_type_list {
	unsigned int idx;
	const char *name;
	struct uci_type_list *next;
};

static const UT_icd netif_info_icd = {sizeof(netif_info_t), NULL, NULL, NULL};

void uwrt_print_error(struct uci_context *ctx, char *name)
{
  char *error = NULL;

  uci_get_errorstr(ctx, &error, NULL);

  if (error != NULL) {
    log_trace("%s fail: %s", name, error);
    os_free(error);
  } else {
    log_trace("uci_set_confdir fail");
  }
}

void uci_reset_typelist(struct uci_type_list *list)
{
	struct uci_type_list *type = NULL;

	while (list != NULL) {
    type = list;
		list = list->next;
		os_free(type);
	}
}

char* uci_lookup_section_ref(struct uci_section *s, struct uci_type_list *list, char **typestr)
{
	struct uci_type_list *ti = list;
	char *ret;
	int maxlen;

	/* look up in section type list */
	while (ti != NULL) {
		if (strcmp(ti->name, s->type) == 0) {
      break;
    }

		ti = ti->next;
	}

	if (ti == NULL) {
		if ((ti = os_calloc(1, sizeof(struct uci_type_list))) == NULL) {
      log_err("os_calloc");
      return NULL;
    }

		ti->next = list;
		list = ti;
		ti->name = s->type;
	}

	if (s->anonymous) {
		maxlen = strlen(s->type) + 1 + 2 + 10;
		if (*typestr == NULL) {
			if ((*typestr = os_malloc(maxlen)) == NULL) {
        log_err("os_malloc");
        return NULL;
      }
		} else {
			void *p = os_realloc(*typestr, maxlen);
			if (p == NULL) {
        log_err("os_realloc");
				os_free(*typestr);
				return NULL;
			}

			*typestr = p;
		}

		if (*typestr != NULL) {
			sprintf(*typestr, "@%s[%d]", ti->name, ti->idx);
    }

		ret = *typestr;
	} else {
		ret = s->e.name;
	}

	ti->idx++;

	return ret;
}

char* uwrt_get_option(struct uci_option *o)
{
	struct uci_element *e = NULL;
  char *vname = NULL;
  struct string_queue* squeue = NULL;

	switch(o->type) {
	case UCI_TYPE_STRING:
    if ((vname = os_strdup(o->v.string)) == NULL) {
      log_err("os_strdup");
      return NULL;
    }
    break;
	case UCI_TYPE_LIST:
    if ((squeue = init_string_queue(-1)) == NULL) {
      log_trace("init_string_queue fail");
      return NULL;
    }

		uci_foreach_element(&o->v.list, e) {
      if (push_string_queue(squeue, e->name) < 0) {
        log_trace("push_string_queue fail");
        free_string_queue(squeue);
        return NULL;
      }
		}

    if ((vname = concat_string_queue(squeue, -1)) == NULL) {
      log_trace("push_string_queue fail");
      free_string_queue(squeue);
      return NULL;
    }
    free_string_queue(squeue);
		break;
	default:
		log_trace("unknown uci type");
	}

  return vname;
}

int uwrt_lookup_option(struct uci_option *o, char *sref, UT_array *kv)
{
	char *cname = o->section->package->e.name;
	char *sname = (sref != NULL ? sref : o->section->e.name);
  char *oname = o->e.name;
  char *vname = NULL;
  char *kvstr = NULL;

  if ((vname = uwrt_get_option(o)) == NULL) {
    log_trace("uwrt_get_option fail");
    return -1;
  }

  if ((kvstr = os_zalloc(strlen(cname) + strlen(sname) + strlen(oname) + strlen(vname) + 4)) == NULL) {
    log_err("os_zalloc");
    os_free(vname);
    return -1;
  }

	sprintf(kvstr, "%s.%s.%s=%s", cname, sname, oname, vname);
  utarray_push_back(kv, &kvstr);
  os_free(vname);
  os_free(kvstr);

  return 0;
}

int uwrt_lookup_section(struct uci_section *s, char *sref, UT_array *kv)
{
	struct uci_element *e = NULL;
	char *cname = s->package->e.name;
	char *sname = (sref != NULL ? sref : s->e.name);
  char *vname = s->type;
  char *kvstr = NULL;

  if ((kvstr = os_zalloc(strlen(cname) + strlen(sname) + strlen(vname) + 3)) == NULL) {
    log_err("os_zalloc");
    return -1;
  }

	sprintf(kvstr, "%s.%s=%s", cname, sname, vname);
  utarray_push_back(kv, &kvstr);
  os_free(kvstr);

	uci_foreach_element(&s->options, e) {
		if (uwrt_lookup_option(uci_to_option(e), sref, kv) < 0) {
      log_trace("uwrt_lookup_option fail");
      return -1;
    }
	}

  return 0;
}

int uwrt_lookup_package(struct uci_package *p, UT_array *kv)
{
	struct uci_element *e = NULL;
  struct uci_type_list *list = NULL;
  char *typestr = NULL;
  char *sref = NULL;
  int ret = 0;

	uci_foreach_element(&p->sections, e) {
		struct uci_section *s = uci_to_section(e);
		if ((sref = uci_lookup_section_ref(s, list, &typestr)) == NULL) {
      log_trace("uci_lookup_section_ref fail");
      ret = -1;
      goto uwrt_lookup_package_fail;
    }
		if (uwrt_lookup_section(s, sref, kv) < 0) {
      log_trace("uwrt_lookup_section fail");
      ret = -1;
      goto uwrt_lookup_package_fail;
    }
	}

uwrt_lookup_package_fail:
	uci_reset_typelist(list);

	if (typestr != NULL) {
		os_free(typestr);
	}

  return ret;
}


int uwrt_lookup_key(struct uci_context *ctx, char *key, UT_array *kv)
{
	struct uci_element *e = NULL;
	struct uci_ptr ptr;
	int ret = -1;

	if (uci_lookup_ptr(ctx, &ptr, key, true) != UCI_OK) {
		uwrt_print_error(ctx, "uci_lookup_ptr");
		return -1;
	}

	e = ptr.last;
	if (!(ptr.flags & UCI_LOOKUP_COMPLETE)) {
		ctx->err = UCI_ERR_NOTFOUND;
	} else {
	  switch(e->type) {
	  	case UCI_TYPE_PACKAGE:
	  		if (uwrt_lookup_package(ptr.p, kv) < 0) {
          log_trace("uwrt_lookup_package fail");
          goto uwrt_lookup_fail;
        }
	  		break;
	  	case UCI_TYPE_SECTION:
	  		if (uwrt_lookup_section(ptr.s, NULL, kv) < 0) {
          log_trace("uwrt_lookup_section fail");
          goto uwrt_lookup_fail;
        }
	  		break;
	  	case UCI_TYPE_OPTION:
	  		if (uwrt_lookup_option(ptr.o, NULL, kv) < 0) {
          log_trace("uwrt_lookup_option fail");
          goto uwrt_lookup_fail;
        }
	  		break;
	  	default:
	  		/* should not happen */
	  		goto uwrt_lookup_fail;
	  }
  }

	ret = utarray_len(kv);

uwrt_lookup_fail:
	if (ptr.p != NULL) {
		uci_unload(ctx, ptr.p);
  }
	return ret;
}

char* uwrt_extract_value(char *str, char *key)
{
  char *value = NULL;

  if((value = strstr(str, key)) == NULL) {
    return NULL;
  }

  value += strlen(key);

  if (!strlen(value)) {
    return NULL;
  }

  return value;
}

int uwrt_get_net_if(UT_array *kv, netif_info_t *nif)
{
  char **ptr = NULL;
  char *value = NULL;

  os_memset(nif, 0, sizeof(netif_info_t));

  while ((ptr = (char**) utarray_next(kv, ptr))) {
    if ((value = uwrt_extract_value(*ptr, IFNAME_EXPR)) != NULL) {
      strcpy(nif->ifname, value);
    }

    if ((value = uwrt_extract_value(*ptr, IPADDR_EXPR)) != NULL) {
      strcpy(nif->ip_addr, value);
    }
  }

  return 0;
}

int uwrt_set_property(struct uci_context *ctx, char *property)
{
	struct uci_ptr ptr;

  log_trace("Setting property: %s", property);

  if (uci_lookup_ptr(ctx, &ptr, property, true) != UCI_OK) {
		uwrt_print_error(ctx, "uci_lookup_ptr");
		return -1;
	}

  if (uci_set(ctx, &ptr) != UCI_OK) {
		uwrt_print_error(ctx, "uci_set");
		return -1;
  }

  if (uci_save(ctx, ptr.p) != UCI_OK) {
		uwrt_print_error(ctx, "uci_save");
		return -1;
  }

  return 0;
}

void uwrt_free_context(struct uctx *context)
{
  if (context != NULL) {
    if (context->uctx != NULL) {
      uci_free_context(context->uctx);
    }
    os_free(context);
  }
}

struct uctx* uwrt_init_context(char *path)
{
  struct uctx *context = os_zalloc(sizeof(struct uctx));

  if (context == NULL) {
    log_err("os_zalloc");
    return NULL;
  }

  if ((context->uctx = uci_alloc_context()) == NULL) {
    log_trace("uci_alloc_context fail");
    uwrt_free_context(context);
    return NULL;
  }

  if (path != NULL) {
    strcpy(context->path, path);

    if (uci_set_confdir(context->uctx, context->path) != UCI_OK) {
      uwrt_print_error(context->uctx, "uci_set_confdir");
      uwrt_free_context(context);
      return NULL;
    }
  }
  return context;
}

UT_array *uwrt_get_interfaces(struct uctx *context, char *ifname)
{
  int ret, idx = 0;
  UT_array *kv = NULL;
  UT_array *interfaces = NULL;
  netif_info_t nif;
  char key[64];

  utarray_new(interfaces, &netif_info_icd);

  while(true) {
    if (ifname == NULL) {
      snprintf(key, 64, "network.@interface[%d]", idx++); 
    } else {
      snprintf(key, 64, "network.%s", ifname); 
    }

    utarray_new(kv, &ut_str_icd);
    ret = uwrt_lookup_key(context->uctx, key, kv);

    if (!ret) {
      utarray_free(kv);
      break;
    } else if (ret < 0) {
      log_trace("uwrt_lookup_key fail");
      utarray_free(kv);
      goto uwrt_get_fail;
    }

    if (uwrt_get_net_if(kv, &nif) < 0) {
      log_trace("uwrt_get_net_if fail");
      utarray_free(kv);
      goto uwrt_get_fail;
    }

    utarray_free(kv);
    utarray_push_back(interfaces, &nif);

    if (ifname != NULL && ret > 0) {
      break;
    }
  }

  return interfaces;

uwrt_get_fail:
  utarray_free(interfaces);
  return NULL;
}

int uwrt_create_interface(struct uctx *context, char *ifname, char *type,
                          char *ip_addr, char *brd_addr, char *netmask)
{
  char property[128];

  if (ifname == NULL) {
    log_trace("ifname param is NULL");
    return -1;
  }

  if (type == NULL) {
    log_trace("type param is NULL");
    return -1;
  }

  if (ip_addr == NULL) {
    log_trace("ip_addr param is NULL");
    return -1;
  }

  if (brd_addr == NULL) {
    log_trace("brd_addr param is NULL");
    return -1;
  }

  if (netmask == NULL) {
    log_trace("subnet_mask param is NULL");
    return -1;
  }

  sprintf(property, "network.%s=interface", ifname);
  if (uwrt_set_property(context->uctx, property) < 0) {
    log_trace("uwrt_set_property fail for %s", property);
    return -1;
  }

  sprintf(property, "network.%s.ifname=%s", ifname, ifname);
  if (uwrt_set_property(context->uctx, property) < 0) {
    log_trace("uwrt_set_property fail for %s", property);
    return -1;
  }

  sprintf(property, "network.%s.type=%s", ifname, type);
  if (uwrt_set_property(context->uctx, property) < 0) {
    log_trace("uwrt_set_property fail for %s", property);
    return -1;
  }

  sprintf(property, "network.%s.proto=static", ifname);
  if (uwrt_set_property(context->uctx, property) < 0) {
    log_trace("uwrt_set_property fail for %s", property);
    return -1;
  }

  sprintf(property, "network.%s.ipaddr=%s", ifname, ip_addr);
  if (uwrt_set_property(context->uctx, property) < 0) {
    log_trace("uwrt_set_property fail for %s", property);
    return -1;
  }

  sprintf(property, "network.%s.netmask=%s", ifname, netmask);
  if (uwrt_set_property(context->uctx, property) < 0) {
    log_trace("uwrt_set_property fail for %s", property);
    return -1;
  }

  return 0;
}

int uwrt_commit_interface(struct uctx *context)
{
  struct uci_ptr ptr;
  char *section = os_strdup("network");

	if (uci_lookup_ptr(context->uctx, &ptr, section, true) != UCI_OK) {
    os_free(section);
		uwrt_print_error(context->uctx, "uci_lookup_ptr");
		return -1;
	}

	if (uci_commit(context->uctx, &ptr.p, false) != UCI_OK) {
		uwrt_print_error(context->uctx, "uci_commit");
		os_free(section);
    return -1;
	}

  os_free(section);
  return 0;
}
