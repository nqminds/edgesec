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

#include "utarray.h"
#include "allocs.h"
#include "log.h"

enum UCI_COMMANDS {
	/* section cmds */
	CMD_GET,
	CMD_SET,
	CMD_ADD_LIST,
	CMD_DEL_LIST,
	CMD_DEL,
	CMD_RENAME,
	CMD_REVERT,
	CMD_REORDER,
	/* package cmds */
	CMD_SHOW,
	CMD_CHANGES,
	CMD_EXPORT,
	CMD_COMMIT,
	/* other cmds */
	CMD_ADD,
	CMD_IMPORT,
	CMD_HELP,
};

struct uci_type_list {
	unsigned int idx;
	const char *name;
	struct uci_type_list *next;
};

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
        log_err("malloc");
        return NULL;
      }
		} else {
			void *p = os_realloc(*typestr, maxlen);
			if (p == NULL) {
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

void uci_show_value(struct uci_option *o)
{
	struct uci_element *e;
	bool sep = false;

	switch(o->type) {
	case UCI_TYPE_STRING:
		printf("%s", o->v.string);
		printf("\n");
		break;
	case UCI_TYPE_LIST:
		uci_foreach_element(&o->v.list, e) {
			printf("%s", (sep ? " " : ""));
			printf("%s", e->name);
			sep = true;
		}
		printf("\n");
		break;
	default:
		printf("<unknown>\n");
		break;
	}
}

void uci_show_option(struct uci_option *o, char *sref)
{
	printf("%s.%s.%s=", o->section->package->e.name, (sref != NULL ? sref : o->section->e.name), o->e.name);
	uci_show_value(o);
}

void uci_show_section(struct uci_section *s, char *sref)
{
	struct uci_element *e;
	const char *cname;
	const char *sname;

	cname = s->package->e.name;
	sname = (sref != NULL ? sref : s->e.name);

	printf("%s.%s=%s\n", cname, sname, s->type);

	uci_foreach_element(&s->options, e) {
		uci_show_option(uci_to_option(e), sref);
	}
}

void uci_show_package(struct uci_package *p)
{
	struct uci_element *e = NULL;
  struct uci_type_list *list = NULL;
  char *typestr = NULL;
  char *sref = NULL;

	uci_foreach_element(&p->sections, e) {
		struct uci_section *s = uci_to_section(e);
		sref = uci_lookup_section_ref(s, list, &typestr);
		uci_show_section(s, sref);
	}

	uci_reset_typelist(list);

	if (typestr != NULL) {
		os_free(typestr);
	}
}


int package_cmd(struct uci_context *ctx, int cmd, char *tuple)
{
	struct uci_element *e = NULL;
	struct uci_ptr ptr;
	int ret = 1;

	if (uci_lookup_ptr(ctx, &ptr, tuple, true) != UCI_OK) {
		uwrt_print_error(ctx, "uci_lookup_ptr");
		return 1;
	}

	e = ptr.last;
	switch(cmd) {
	case CMD_COMMIT:
		// if (flags & CLI_FLAG_NOCOMMIT) {
		// 	ret = 0;
		// 	goto out;
		// }
		// if (uci_commit(ctx, &ptr.p, false) != UCI_OK) {
		// 	cli_perror();
		// 	goto out;
		// }
		break;
	case CMD_SHOW:
		if (!(ptr.flags & UCI_LOOKUP_COMPLETE)) {
			ctx->err = UCI_ERR_NOTFOUND;
      uwrt_print_error(ctx, "uci show error");
			goto out;
		}
		switch(e->type) {
			case UCI_TYPE_PACKAGE:
				uci_show_package(ptr.p);
				break;
			case UCI_TYPE_SECTION:
				uci_show_section(ptr.s, NULL);
				break;
			case UCI_TYPE_OPTION:
				uci_show_option(ptr.o, NULL);
				break;
			default:
				/* should not happen */
				goto out;
		}
		break;
	}

	ret = 0;

out:
	if (ptr.p != NULL) {
		uci_unload(ctx, ptr.p);
  }
	return ret;
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

UT_array *uwrt_get_interfaces(struct uctx *context, int if_id)
{
  (void) if_id;

  char *key = os_strdup("network.wan");
  package_cmd(context->uctx, CMD_SHOW, key);
  os_free(key);
  return NULL;
}
