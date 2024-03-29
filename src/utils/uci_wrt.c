/**
 * @file
 * @author Alexandru Mereacre
 * @date 2022
 * @copyright
 * SPDX-FileCopyrightText: © 2022 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the implementation of the uci utilities.
 * @details
 * Utility functions for working with UCI (Unified Configuration Interface),
 * which is most commonly used to configure OpenWRT services.
 *
 * Please see <https://openwrt.org/docs/guide-user/base-system/uci> for a
 * description of UCI data/object model.
 */

#include <arpa/inet.h>
#include <inttypes.h>
#include <string.h>
#include <uci.h>

#include "uci_wrt.h"

#include "allocs.h"
#include "iface_mapper.h"
#include "log.h"
#include "net.h"
#include "squeue.h"

#define IFNAME_EXPR ".ifname="
#define IPADDR_EXPR ".ipaddr="

#define IP_SECTION_STR "%d%d%d%d"

#include <uthash.h>

/**
 * @brief Hashmap that stores the count of all the seen section types.
 *
 * Use uci_clear_section_types_count() to clear this hashmap.
 */
struct uci_section_type_count {
  // the type of this section (stored on the heap)
  char *type;
  // how many times we've encounted this type already
  unsigned int idx;
  UT_hash_handle hh; /* makes this structure hashable */
};

static const UT_icd netif_info_icd = {sizeof(netif_info_t), NULL, NULL, NULL};

void uwrt_print_error(struct uci_context *ctx, const char *name) {
  char *error = NULL;

  uci_get_errorstr(ctx, &error, NULL);

  if (error != NULL) {
    log_trace("%s fail: %s", name, error);
    os_free(error);
  } else {
    log_trace("uci_set_confdir fail");
  }
}

/**
 * @brief Clears the given section type count hashmap.
 *
 * @param[in,out] section_types_count The head of the hashmap to clear. Will
 * be set to `NULL` when done.
 */
static void uci_clear_section_types_count(
    struct uci_section_type_count **section_types_count) {
  struct uci_section_type_count *current_type_count, *tmp;

  HASH_ITER(hh, *section_types_count, current_type_count, tmp) {
    HASH_DEL(*section_types_count,
             current_type_count); /* delete entry from hashmap */
    free(current_type_count->type);
    free(current_type_count);
  }
}

/**
 * @brief Find the reference to the given UCI section.
 *
 * UCI supports array-like references to UCI sections.
 *
 * For example, `system.@timeserver[0]` will be the first `timeserver` section
 * in `/etc/config/system`.
 *
 * @param s - The UCI section to find the reference to.
 * @param[in, out] list - UCI section type count hashmap.
 * Should contain the count of all the previous section types, and will be
 * updated to include the current section type.
 * @param[in, out] malloc_buffer - malloc()-ed buffer that can be realloc()-ed
 * as required, or `NULL`. Please `free()` this parameter after this function
 * has been called.
 * @return A reference to this section, e.g. `@timeserver[0]`.
 * This pointer may point to `malloc_buffer` (for anonymous sections)
 * (i.e. `@timeserver[0]`) or to `s->e.name` (for named sections), and so may
 * be invalid once either of them are `free()`-ed.
 */
static const char *
uci_lookup_section_ref(struct uci_section *s,
                       struct uci_section_type_count **section_types_count,
                       char **malloc_buffer) {

  struct uci_section_type_count *section_type_count;
  HASH_FIND_STR(*section_types_count, s->type, section_type_count);
  if (section_type_count == NULL) {
    section_type_count = os_malloc(sizeof(struct uci_section_type_count));
    if (section_type_count == NULL) {
      log_errno("os_malloc");
      return NULL;
    }
    *section_type_count = (struct uci_section_type_count){
        .idx = 0,
        .type = os_strdup(s->type),
    };
    if (section_type_count->type == NULL) {
      log_errno("os_strdup");
      free(section_type_count);
      return NULL;
    }
    HASH_ADD_KEYPTR(hh, *section_types_count, section_type_count->type,
                    strlen(section_type_count->type), section_type_count);
  }

  char *ret;

  if (s->anonymous) {
    int maxlen = strlen(s->type) + 1 + 2 + 10;
    {
      char *p = os_realloc(*malloc_buffer, maxlen);
      if (p == NULL) {
        log_errno("os_realloc");
        // don't free() *malloc_buffer, next call to uci_lookup_section_ref()
        // may reuse this value
        return NULL;
      }

      *malloc_buffer = p;
    }

    sprintf(*malloc_buffer, "@%s[%d]", s->type, section_type_count->idx);

    ret = *malloc_buffer;
  } else {
    ret = s->e.name;
  }

  section_type_count->idx++;

  return ret;
}

/**
 * @brief Gets the value of the given option.
 *
 * For list options, the value would be all the list entries concatenated
 * together.
 *
 * For example, given the following UCI file:
 *
 * ```uci
 * config rule
 *   option string_opt 'my-val'
 *   list list_open 'list-val-1'
 *   list list_open 'list-val-2'
 * ```
 *
 * - calling `uwrt_get_option()` on `string_opt` would return `my-val`
 * - calling `uwrt_get_option()` on `list_opt` would return
 * `list-val-1list-val-2`
 *
 * @param o The option to read.
 * @return The value of the option as a NUL-terminated string, or `NULL` on
 * error. Please free() the string when you're done with it.
 */
__must_free static char *uwrt_get_option(const struct uci_option *o) {
  const struct uci_element *e = NULL;
  char *vname = NULL;
  struct string_queue *squeue = NULL;

  switch (o->type) {
    case UCI_TYPE_STRING:
      if ((vname = os_strdup(o->v.string)) == NULL) {
        log_errno("os_strdup");
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

  log_trace("Option is %s", vname);

  return vname;
}

/**
 * @brief Adds a string for the UCI option to the given array.
 *
 * For the given UCI option, creates a configuration string, similar
 * to that from `uci show system`, e.g. `system.ntp.enabled=1`.
 *
 * Unlike `uci show system`, option values are **NOT** quoted, so are not valid
 * to pass to `uci set`. (list options are also mangled).
 *
 * @param o The UCI option struct.
 * @param sref The section reference to use. If this is NULL, uses the name
 * of the section (won't work if the section is anonymous and has no name).
 * @param[in, out] kv The array to store the output.
 * @retval  0 On success.
 * @retval -1 On failure.
 */
static int uwrt_lookup_option(const struct uci_option *o, const char *sref,
                              UT_array *kv) {
  const char *cname = o->section->package->e.name;
  const char *sname = (sref != NULL ? sref : o->section->e.name);
  const char *oname = o->e.name;
  char *vname = NULL;
  char *kvstr = NULL;

  if ((vname = uwrt_get_option(o)) == NULL) {
    log_trace("uwrt_get_option fail");
    return -1;
  }

  if ((kvstr = os_zalloc(strlen(cname) + strlen(sname) + strlen(oname) +
                         strlen(vname) + 4)) == NULL) {
    log_errno("os_zalloc");
    os_free(vname);
    return -1;
  }

  sprintf(kvstr, "%s.%s.%s=%s", cname, sname, oname, vname);
  utarray_push_back(kv, &kvstr);
  os_free(vname);
  os_free(kvstr);

  return 0;
}

/**
 * @brief Adds strings describing a UCI section into the given array.
 *
 * The output is similar to the result of using the UCI CLI command
 * `uci show <config>.<section>`, except option values are not quoted, see
 * uwrt_get_option().
 *
 * For example, given the below section:
 *
 * ```conf
 * # in file /etc/config/my_config
 * config rule 'section_name'
 *   option string_opt 'my-val'
 *   list list_opt 'list-val-1'
 *   list list_opt 'list-val-2'
 * ```
 *
 * The UT_array entries would look like:
 *
 * 1. `my_config.section_name=rule`
 * 2. `my_config.section_name.string_opt=my-val`
 * 3. `my_config.section_name.list_opt=list-val-1list-val-2`
 *
 * @param s The UCI section struct.
 * @param sref The section reference to use. If this is NULL, uses the name
 * of the section (won't work if the section is anonymous and has no name).
 * @param[in, out] kv The array to store the output.
 * @retval  0 On success.
 * @retval -1 On failure. The array may be partially filled in an error.
 */
static int uwrt_lookup_section(const struct uci_section *s, const char *sref,
                               UT_array *kv) {
  const struct uci_element *e = NULL;
  const char *cname = s->package->e.name;
  const char *sname = (sref != NULL ? sref : s->e.name);
  const char *vname = s->type;
  char *kvstr = NULL;

  if ((kvstr = os_zalloc(strlen(cname) + strlen(sname) + strlen(vname) + 3)) ==
      NULL) {
    log_errno("os_zalloc");
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

int uwrt_lookup_package(struct uci_package *p, UT_array *kv) {
  struct uci_element *e = NULL;
  /** Counts the section types we've already encountered */
  struct uci_section_type_count *section_types_count = NULL;

  char *malloc_buffer = NULL;
  int ret = 0;

  uci_foreach_element(&p->sections, e) {
    struct uci_section *s = uci_to_section(e);
    const char *sref =
        uci_lookup_section_ref(s, &section_types_count, &malloc_buffer);
    if (sref == NULL) {
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
  uci_clear_section_types_count(&section_types_count);

  if (malloc_buffer != NULL) {
    os_free(malloc_buffer);
  }

  return ret;
}

int uwrt_lookup_key(struct uci_context *ctx, char *key, UT_array *kv) {
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
    switch (e->type) {
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

const char *uwrt_extract_value(const char *str, const char *key) {
  // substr returns a non-const str, but it really should be a const char *
  const char *value = strstr(str, key);
  if (value == NULL) {
    return NULL;
  }

  value += strlen(key);

  if (!strlen(value)) {
    return NULL;
  }

  return value;
}

int uwrt_get_net_if(UT_array *kv, netif_info_t *nif) {
  char **ptr = NULL;

  os_memset(nif, 0, sizeof(netif_info_t));

  while ((ptr = (char **)utarray_next(kv, ptr))) {
    const char *ifname_value = uwrt_extract_value(*ptr, IFNAME_EXPR);
    if (ifname_value != NULL) {
      strcpy(nif->ifname, ifname_value);
    }

    const char *ip_addr_value = uwrt_extract_value(*ptr, IPADDR_EXPR);
    if (ip_addr_value != NULL) {
      nif->ifa_family = AF_INET;
      strcpy(nif->ip_addr, ip_addr_value);
    }
  }

  return 0;
}

// Warning, property string must **NOT** be constant
// uci_lookup_ptr will modify it
int uwrt_set_property(struct uci_context *ctx, char *property) {
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

/**
 * @brief Set multiple OpenWRT UCI properties at once
 * @param[in] ctx UCI context. The context ptr will be modified.
 * @param[in] properties Array of properties to set. Warning, strings may be
 * modified by UCI.
 * @retval  0 Success
 * @retval -1 Error
 */
int uwrt_set_properties(struct uci_context *ctx, UT_array *properties) {
  for (char *const *prop = (char **)utarray_front(properties); prop != NULL;
       prop = (char **)utarray_next(properties, prop)) {

    if (uwrt_set_property(ctx, *prop) < 0) {
      log_error("uwrt_set_property fail for %s", *prop);
      return -1;
    }
  }
  return 0;
}

int uwrt_add_list(struct uci_context *ctx, char *property) {
  struct uci_ptr ptr;

  log_trace("Add list property: %s", property);

  if (uci_lookup_ptr(ctx, &ptr, property, true) != UCI_OK) {
    uwrt_print_error(ctx, "uci_lookup_ptr");
    return -1;
  }

  if (uci_add_list(ctx, &ptr) != UCI_OK) {
    uwrt_print_error(ctx, "uci_add_list");
    return -1;
  }

  if (uci_save(ctx, ptr.p) != UCI_OK) {
    uwrt_print_error(ctx, "uci_save");
    return -1;
  }

  return 0;
}

/**
 * @brief Set multiple OpenWRT UCI list properties at once
 * @param[in] ctx UCI context. The context ptr will be modified.
 * @param[in] properties Array of list properties to set. Warning, strings may
 * be modified by UCI.
 * @retval  0 Success
 * @retval -1 Error
 */
int uwrt_add_list_properties(struct uci_context *ctx, UT_array *properties) {
  for (char *const *prop = (char **)utarray_front(properties); prop != NULL;
       prop = (char **)utarray_next(properties, prop)) {
    if (uwrt_add_list(ctx, *prop) < 0) {
      log_trace("uwrt_add_list fail for %s", *prop);
      return -1;
    }
  }
  return 0;
}

int uwrt_delete_property(struct uci_context *ctx, char *property) {
  struct uci_ptr ptr;

  log_trace("Delete property: %s", property);

  if (uci_lookup_ptr(ctx, &ptr, property, true) != UCI_OK) {
    uwrt_print_error(ctx, "uci_lookup_ptr");
    return -1;
  }

  if (uci_delete(ctx, &ptr) != UCI_OK) {
    uwrt_print_error(ctx, "uci_delete");
    return -1;
  }

  if (uci_save(ctx, ptr.p) != UCI_OK) {
    uwrt_print_error(ctx, "uci_save");
    return -1;
  }

  return 0;
}

/**
 * @brief Delete multiple OpenWRT UCI properties at once
 * Errors with uwrt_delete_property will be logged and ignored.
 * @param[in] ctx UCI context. The context ptr will be modified.
 * @param[in] properties Array of properties to delete. Warning, strings may
 * be modified by UCI.
 */
void uwrt_delete_properties(struct uci_context *ctx, UT_array *properties) {
  for (char *const *prop = (char **)utarray_front(properties); prop != NULL;
       prop = (char **)utarray_next(properties, prop)) {
    if (uwrt_delete_property(ctx, *prop) < 0) {
      log_trace("nothing to delete for %s", *prop);
    }
  }
}

void uwrt_free_context(struct uctx *context) {
  if (context != NULL) {
    if (context->uctx != NULL) {
      uci_free_context(context->uctx);
    }
    os_free(context);
  }
}

struct uctx *uwrt_init_context(const char *path) {
  struct uctx *context = os_zalloc(sizeof(struct uctx));

  if (context == NULL) {
    log_errno("os_zalloc");
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

UT_array *uwrt_get_interfaces(const struct uctx *context, const char *ifname) {
  int ret, idx = 0;
  UT_array *kv = NULL;
  UT_array *interfaces = NULL;
  netif_info_t nif;
  char key[128];

  utarray_new(interfaces, &netif_info_icd);

  while (true) {
    if (ifname == NULL) {
      snprintf(key, ARRAY_SIZE(key), "network.@interface[%d]", idx++);
    } else {
      snprintf(key, ARRAY_SIZE(key), "network.%s", ifname);
    }

    utarray_new(kv, &ut_str_icd);
    ret = uwrt_lookup_key(context->uctx, key, kv);

    if (ret == 0) {
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

    if (ifname != NULL) {
      break;
    }
  }

  return interfaces;

uwrt_get_fail:
  utarray_free(interfaces);
  return NULL;
}

int uwrt_set_interface_ip(const struct uctx *context, const char *ifname,
                          const char *ip_addr, const char *netmask) {
  if (context == NULL) {
    log_trace("context param is NULL");
    return -1;
  }

  if (ifname == NULL) {
    log_trace("ifname param is NULL");
    return -1;
  }

  if (ip_addr == NULL) {
    log_trace("ip_addr param is NULL");
    return -1;
  }

  if (netmask == NULL) {
    log_trace("subnet_mask param is NULL");
    return -1;
  }

  UT_array *properties;
  utarray_new(properties, &ut_str_icd);

  char property_buffer[128];
  const size_t property_size = ARRAY_SIZE(property_buffer);
  // utarray_push_back doesn't support arrays, only pointers, due to being
  // a C preprocessor macro
  char *const property = property_buffer;

  snprintf(property, property_size, "network.%s.ipaddr=%s", ifname, ip_addr);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "network.%s.netmask=%s", ifname, netmask);
  utarray_push_back(properties, &property);

  if (uwrt_set_properties(context->uctx, properties) < 0) {
    log_error("uwrt_set_interface_ip: failed to uwrt_set_properties");
    utarray_free(properties);
    return -1;
  }
  utarray_free(properties);

  return 0;
}

int uwrt_create_interface(const struct uctx *context, const char *ifname,
                          const char *type, const char *ip_addr,
                          const char *brd_addr, const char *netmask) {
  if (context == NULL) {
    log_trace("context param is NULL");
    return -1;
  }

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

  UT_array *properties;
  utarray_new(properties, &ut_str_icd);

  char property_buffer[128];
  const size_t property_size = ARRAY_SIZE(property_buffer);
  // utarray_push_back doesn't support arrays, only pointers, due to being
  // a C preprocessor macro
  char *const property = property_buffer;

  snprintf(property, property_size, "network.%s=interface", ifname);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "network.%s.ifname=%s", ifname, ifname);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "network.%s.enabled=1", ifname);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "network.%s.type=%s", ifname, type);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "network.%s.proto=static", ifname);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "network.%s.bridge_empty=1", ifname);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "network.%s.ip6assign=60", ifname);
  utarray_push_back(properties, &property);

  if (uwrt_set_properties(context->uctx, properties) < 0) {
    log_error("uwrt_create_interface: failed to uwrt_set_properties");
    utarray_free(properties);
    return -1;
  }
  utarray_free(properties);

  if (uwrt_set_interface_ip(context, ifname, ip_addr, netmask) < 0) {
    log_trace("uwrt_set_interface_ip fail for ifname=%s", ifname);
    return -1;
  }

  return 0;
}

int uwrt_commit_section(const struct uctx *context, const char *section) {
  struct uci_ptr ptr;
  char *psection = os_strdup(section);

  if (psection == NULL) {
    log_errno("os_strdup");
    return -1;
  }

  if (uci_lookup_ptr(context->uctx, &ptr, psection, true) != UCI_OK) {
    uwrt_print_error(context->uctx, "uci_lookup_ptr");
    os_free(psection);
    return -1;
  }

  if (uci_commit(context->uctx, &ptr.p, false) != UCI_OK) {
    uwrt_print_error(context->uctx, "uci_commit");
    os_free(psection);
    return -1;
  }

  os_free(psection);
  return 0;
}

int uwrt_gen_dnsmasq_instance(const struct uctx *context,
                              const struct string_queue *ifname_queue,
                              const UT_array *server_array,
                              const char *leasefile, const char *scriptfile) {
  char **p = NULL;
  struct string_queue *el = NULL;

  if (context == NULL) {
    log_trace("context param is NULL");
    return -1;
  }

  if (ifname_queue == NULL) {
    log_trace("ifname_queue param is NULL");
    return -1;
  }

  if (server_array == NULL) {
    log_trace("server_array param is NULL");
    return -1;
  }

  if (leasefile == NULL) {
    log_trace("server_array param is NULL");
    return -1;
  }

  if (scriptfile == NULL) {
    log_trace("scriptfile param is NULL");
    return -1;
  }

  UT_array *properties;
  utarray_new(properties, &ut_str_icd);

  char property_buffer[128];
  const size_t property_size = ARRAY_SIZE(property_buffer);
  // utarray_push_back doesn't support arrays, only pointers, due to being
  // a C preprocessor macro
  char *const property = property_buffer;

  snprintf(property, property_size, "dhcp.edgesec");
  if (uwrt_delete_property(context->uctx, property) < 0) {
    log_trace("nothing to delete for %s", property);
  }

  snprintf(property, property_size, "dhcp.edgesec=dnsmasq");
  utarray_push_back(properties, &property);

  // snprintf(property, property_size, "dhcp.edgesec.noresolv=1");
  // utarray_push_back(properties, &property);

  snprintf(property, property_size, "dhcp.edgesec.nonwildcard=1");
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "dhcp.edgesec.leasefile=%s", leasefile);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "dhcp.edgesec.dhcpscript=%s", scriptfile);
  utarray_push_back(properties, &property);

  if (uwrt_set_properties(context->uctx, properties) < 0) {
    log_error("uwrt_gen_dnsmasq_instance: failed to uwrt_set_properties");
    utarray_free(properties);
    return -1;
  }
  utarray_free(properties);

  dl_list_for_each(el, &ifname_queue->list, struct string_queue, list) {
    if (el != NULL) {
      snprintf(property, property_size, "dhcp.edgesec.interface=%s", el->str);
      if (uwrt_add_list(context->uctx, property) < 0) {
        log_trace("uwrt_add_list fail for %s", property);
        return -1;
      }
    }
  }

  // snprintf(property, property_size, "dhcp.edgesec.notinterface=loopback");
  // if (uwrt_add_list(context->uctx, property) < 0) {
  //   log_trace("uwrt_add_list fail for %s", property);
  //   return -1;
  // }

  while ((p = (char **)utarray_next(server_array, p)) != NULL) {
    snprintf(property, property_size, "dhcp.edgesec.server=%s", *p);
    if (uwrt_add_list(context->uctx, property) < 0) {
      log_trace("uwrt_add_list fail for %s", property);
      return -1;
    }
  }

  return 0;
}

int uwrt_add_dhcp_pool(const struct uctx *context, const char *ifname,
                       const char *ip_addr_low, const char *ip_addr_upp,
                       const char *subnet_mask, const char *lease_time) {
  uint32_t start, limit;

  if (context == NULL) {
    log_trace("context param is NULL");
    return -1;
  }

  if (ifname == NULL) {
    log_trace("ifname param is NULL");
    return -1;
  }

  if (ip_addr_low == NULL) {
    log_trace("ip_addr_low param is NULL");
    return -1;
  }

  if (ip_addr_upp == NULL) {
    log_trace("ip_addr_upp param is NULL");
    return -1;
  }

  if (subnet_mask == NULL) {
    log_trace("subnet_mask param is NULL");
    return -1;
  }

  if (lease_time == NULL) {
    log_trace("lease_time param is NULL");
    return -1;
  }

  if (get_ip_host(ip_addr_low, subnet_mask, &start) < 0) {
    log_trace("get_ip_host fail");
    return -1;
  }

  if (get_ip_host(ip_addr_upp, subnet_mask, &limit) < 0) {
    log_trace("get_ip_host fail");
    return -1;
  }

  limit = (limit < start) ? 0 : (limit - start) + 1;

  UT_array *properties;
  utarray_new(properties, &ut_str_icd);

  char property_buffer[128];
  const size_t property_size = ARRAY_SIZE(property_buffer);
  // utarray_push_back doesn't support arrays, only pointers, due to being
  // a C preprocessor macro
  char *const property = property_buffer;

  snprintf(property, property_size, "dhcp.%s=dhcp", ifname);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "dhcp.%s.interface=%s", ifname, ifname);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "dhcp.%s.networkid=br-%s", ifname, ifname);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "dhcp.%s.dhcpv4=server", ifname);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "dhcp.%s.instance=edgesec", ifname);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "dhcp.%s.ignore=0", ifname);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "dhcp.%s.force=1", ifname);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "dhcp.%s.start=%d", ifname, start);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "dhcp.%s.limit=%d", ifname, limit);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "dhcp.%s.leasetime=%s", ifname, lease_time);
  utarray_push_back(properties, &property);

  if (uwrt_set_properties(context->uctx, properties) < 0) {
    log_error("uwrt_add_dhcp_pool: failed to uwrt_set_properties");
    utarray_free(properties);
    return -1;
  }
  utarray_free(properties);

  return 0;
}

int uwrt_gen_hostapd_instance(const struct uctx *context,
                              const struct hostapd_params *params) {
  if (context == NULL) {
    log_trace("context param is NULL");
    return -1;
  }

  if (params == NULL) {
    log_trace("params param is NULL");
    return -1;
  }

  if (params->device == NULL) {
    log_trace("device param is NULL");
    return -1;
  }

  UT_array *properties;
  utarray_new(properties, &ut_str_icd);

  char property_buffer[128];
  const size_t property_size = ARRAY_SIZE(property_buffer);
  // utarray_push_back doesn't support arrays, only pointers, due to being
  // a C preprocessor macro
  char *const property = property_buffer;

  snprintf(property, property_size, "wireless.edgesec=wifi-iface");
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "wireless.edgesec.device=%s",
           params->device);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "wireless.edgesec.mode=ap");
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "wireless.edgesec.ssid=%s", params->ssid);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "wireless.edgesec.isolate=0");
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "wireless.edgesec.encryption=psk2");
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "wireless.edgesec.key=%s",
           params->wpa_passphrase);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "wireless.edgesec.dynamic_vlan=%d",
           params->dynamic_vlan);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "wireless.edgesec.vlan_bridge=%s",
           params->vlan_bridge);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "wireless.edgesec.vlan_file=%s",
           params->vlan_file);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "wireless.%s=wifi-device", params->device);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "wireless.%s.disabled=0", params->device);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "wireless.%s.channel=11", params->device);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "wireless.%s.band=2g", params->device);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "wireless.%s.htmode=HT20", params->device);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "wireless.%s.log_level=0", params->device);
  utarray_push_back(properties, &property);

  if (uwrt_set_properties(context->uctx, properties) < 0) {
    log_error("uwrt_gen_hostapd_instance: failed to uwrt_set_properties");
    utarray_free(properties);
    return -1;
  }
  utarray_free(properties);

  snprintf(property, property_size, "wireless.%s.hostapd_options",
           params->device);
  if (uwrt_delete_property(context->uctx, property) < 0) {
    log_trace("nothing to delete for %s", property);
  }

  UT_array *list_properties;
  utarray_new(list_properties, &ut_str_icd);

  snprintf(property, property_size, "wireless.%s.hostapd_options=auth_algs=%d",
           params->device, params->auth_algs);
  utarray_push_back(list_properties, &property);

  snprintf(property, property_size, "wireless.%s.hostapd_options=wpa=%d",
           params->device, params->wpa);
  utarray_push_back(list_properties, &property);

  snprintf(property, property_size,
           "wireless.%s.hostapd_options=wpa_key_mgmt=%s", params->device,
           params->wpa_key_mgmt);
  utarray_push_back(list_properties, &property);

  snprintf(property, property_size,
           "wireless.%s.hostapd_options=rsn_pairwise=%s", params->device,
           params->rsn_pairwise);
  utarray_push_back(list_properties, &property);

  snprintf(property, property_size,
           "wireless.%s.hostapd_options=own_ip_addr=%s", params->device,
           params->radius_client_ip);
  utarray_push_back(list_properties, &property);

  snprintf(property, property_size,
           "wireless.%s.hostapd_options=auth_server_addr=%s", params->device,
           params->radius_server_ip);
  utarray_push_back(list_properties, &property);

  snprintf(property, property_size,
           "wireless.%s.hostapd_options=auth_server_port=%d", params->device,
           params->radius_port);
  utarray_push_back(list_properties, &property);

  snprintf(property, property_size,
           "wireless.%s.hostapd_options=auth_server_shared_secret=%s",
           params->device, params->radius_secret);
  utarray_push_back(list_properties, &property);

  snprintf(property, property_size,
           "wireless.%s.hostapd_options=macaddr_acl=%d", params->device,
           params->macaddr_acl);
  utarray_push_back(list_properties, &property);

  snprintf(property, property_size, "wireless.%s.hostapd_options=vlan_file=%s",
           params->device, params->vlan_file);
  utarray_push_back(list_properties, &property);

  snprintf(property, property_size,
           "wireless.%s.hostapd_options=ignore_broadcast_ssid=%d",
           params->device, params->ignore_broadcast_ssid);
  utarray_push_back(list_properties, &property);

  snprintf(property, property_size,
           "wireless.%s.hostapd_options=wpa_psk_radius=%d", params->device,
           params->wpa_psk_radius);
  utarray_push_back(list_properties, &property);

  snprintf(property, property_size,
           "wireless.%s.hostapd_options=vlan_bridge=%s", params->device,
           params->vlan_bridge);
  utarray_push_back(list_properties, &property);

  if (uwrt_add_list_properties(context->uctx, list_properties) < 0) {
    log_error("uwrt_gen_hostapd_instance: failed to uwrt_add_list_properties");
    utarray_free(list_properties);
    return -1;
  }
  utarray_free(list_properties);

  return 0;
}

int uwrt_gen_firewall_zone(const struct uctx *context, const char *brname) {
  if (context == NULL) {
    log_trace("context param is NULL");
    return -1;
  }

  if (brname == NULL) {
    log_trace("brname param is NULL");
    return -1;
  }

  UT_array *properties;
  utarray_new(properties, &ut_str_icd);

  char property_buffer[256];
  const size_t property_size = ARRAY_SIZE(property_buffer);
  // utarray_push_back doesn't support arrays, only pointers, due to being
  // a C preprocessor macro
  char *const property = property_buffer;

  snprintf(property, property_size, "firewall.edgesec_%s=zone", brname);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "firewall.edgesec_%s.enabled=1", brname);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "firewall.edgesec_%s.name=%s", brname,
           brname);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "firewall.edgesec_%s.input=REJECT", brname);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "firewall.edgesec_%s.forward=REJECT",
           brname);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "firewall.edgesec_%s.output=ACCEPT",
           brname);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "firewall.edgesec_%s_icmp=rule", brname);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "firewall.edgesec_%s_icmp.enabled=1",
           brname);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "firewall.edgesec_%s_icmp.name=%s icmp",
           brname, brname);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "firewall.edgesec_%s_icmp.src=%s", brname,
           brname);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "firewall.edgesec_%s_icmp.proto=icmp",
           brname);
  utarray_push_back(properties, &property);

  snprintf(property, property_size,
           "firewall.edgesec_%s_icmp.icmp_type=echo-request", brname);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "firewall.edgesec_%s_icmp.family=ipv4",
           brname);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "firewall.edgesec_%s_icmp.target=ACCEPT",
           brname);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "firewall.edgesec_%s_dns=rule", brname);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "firewall.edgesec_%s_dns.enabled=1",
           brname);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "firewall.edgesec_%s_dns.name=%s dns",
           brname, brname);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "firewall.edgesec_%s_dns.src=%s", brname,
           brname);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "firewall.edgesec_%s_dns.proto=tcp udp",
           brname);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "firewall.edgesec_%s_dns.dest_port=53",
           brname);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "firewall.edgesec_%s_dns.target=ACCEPT",
           brname);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "firewall.edgesec_%s_dhcp=rule", brname);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "firewall.edgesec_%s_dhcp.enabled=1",
           brname);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "firewall.edgesec_%s_dhcp.name=%s dhcp",
           brname, brname);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "firewall.edgesec_%s_dhcp.src=%s", brname,
           brname);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "firewall.edgesec_%s_dhcp.proto=udp",
           brname);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "firewall.edgesec_%s_dhcp.src_port=67-68",
           brname);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "firewall.edgesec_%s_dhcp.dest_port=67-68",
           brname);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "firewall.edgesec_%s_dhcp.target=ACCEPT",
           brname);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "firewall.edgesec_%s_dhcp6=rule", brname);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "firewall.edgesec_%s_dhcp6.enabled=1",
           brname);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "firewall.edgesec_%s_dhcp6.name=%s dhcp6",
           brname, brname);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "firewall.edgesec_%s_dhcp6.src=%s", brname,
           brname);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "firewall.edgesec_%s_dhcp6.proto=udp",
           brname);
  utarray_push_back(properties, &property);

  snprintf(property, property_size,
           "firewall.edgesec_%s_dhcp6.src_ip=fe80::/10", brname);
  utarray_push_back(properties, &property);

  snprintf(property, property_size,
           "firewall.edgesec_%s_dhcp6.src_port=546-547", brname);
  utarray_push_back(properties, &property);

  snprintf(property, property_size,
           "firewall.edgesec_%s_dhcp6.dest_ip=fe80::/10", brname);
  utarray_push_back(properties, &property);

  snprintf(property, property_size,
           "firewall.edgesec_%s_dhcp6.dest_port=546-547", brname);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "firewall.edgesec_%s_dhcp6.family=ipv6",
           brname);
  utarray_push_back(properties, &property);

  snprintf(property, property_size, "firewall.edgesec_%s_dhcp6.target=ACCEPT",
           brname);
  utarray_push_back(properties, &property);

  if (uwrt_set_properties(context->uctx, properties) < 0) {
    log_error("uwrt_gen_firewall_zone: failed to uwrt_set_properties");
    utarray_free(properties);
    return -1;
  }
  utarray_free(properties);

  snprintf(property, property_size, "firewall.edgesec_%s.network", brname);
  if (uwrt_delete_property(context->uctx, property) < 0) {
    log_trace("nothing to delete for %s", property);
  }

  snprintf(property, property_size, "firewall.edgesec_%s.network=%s", brname,
           brname);
  if (uwrt_add_list(context->uctx, property) < 0) {
    log_trace("uwrt_add_list fail for %s", property);
    return -1;
  }

  return 0;
}

int uwrt_add_firewall_nat(const struct uctx *context, const char *brname,
                          const char *ip_addr, const char *nat_name) {
  uint8_t ip_buf[4];

  if (context == NULL) {
    log_trace("context param is NULL");
    return -1;
  }

  if (brname == NULL) {
    log_trace("brname param is NULL");
    return -1;
  }

  if (ip_addr == NULL) {
    log_trace("ip_addr param is NULL");
    return -1;
  }

  if (nat_name == NULL) {
    log_trace("nat_name param is NULL");
    return -1;
  }

  if (ip4_2_buf(ip_addr, ip_buf) < 0) {
    log_trace("ip4_2_buf fail");
    return -1;
  }

  UT_array *properties;
  utarray_new(properties, &ut_str_icd);

  char property_buffer[256];
  const size_t property_size = ARRAY_SIZE(property_buffer);
  // utarray_push_back doesn't support arrays, only pointers, due to being
  // a C preprocessor macro
  char *const property = property_buffer;

  snprintf(property, property_size,
           "firewall.edgesec_" IP_SECTION_STR "_dnat=nat", IP2STR(ip_buf));
  utarray_push_back(properties, &property);

  snprintf(property, property_size,
           "firewall.edgesec_" IP_SECTION_STR "_dnat.enabled=1",
           IP2STR(ip_buf));
  utarray_push_back(properties, &property);

  snprintf(property, property_size,
           "firewall.edgesec_" IP_SECTION_STR "_dnat.name=DNAT %s",
           IP2STR(ip_buf), ip_addr);
  utarray_push_back(properties, &property);

  snprintf(property, property_size,
           "firewall.edgesec_" IP_SECTION_STR "_dnat.src=%s", IP2STR(ip_buf),
           nat_name);
  utarray_push_back(properties, &property);

  snprintf(property, property_size,
           "firewall.edgesec_" IP_SECTION_STR "_dnat.src_ip=0.0.0.0",
           IP2STR(ip_buf));
  utarray_push_back(properties, &property);

  snprintf(property, property_size,
           "firewall.edgesec_" IP_SECTION_STR "_dnat.dest=%s", IP2STR(ip_buf),
           brname);
  utarray_push_back(properties, &property);

  snprintf(property, property_size,
           "firewall.edgesec_" IP_SECTION_STR "_dnat.dest_ip=%s",
           IP2STR(ip_buf), ip_addr);
  utarray_push_back(properties, &property);

  snprintf(property, property_size,
           "firewall.edgesec_" IP_SECTION_STR "_dnat.proto=all",
           IP2STR(ip_buf));
  utarray_push_back(properties, &property);

  snprintf(property, property_size,
           "firewall.edgesec_" IP_SECTION_STR "_dnat.target=DNAT",
           IP2STR(ip_buf));
  utarray_push_back(properties, &property);

  snprintf(property, property_size,
           "firewall.edgesec_" IP_SECTION_STR "_snat=nat", IP2STR(ip_buf));
  utarray_push_back(properties, &property);

  snprintf(property, property_size,
           "firewall.edgesec_" IP_SECTION_STR "_snat.enabled=1",
           IP2STR(ip_buf));
  utarray_push_back(properties, &property);

  snprintf(property, property_size,
           "firewall.edgesec_" IP_SECTION_STR "_snat.name=SNAT %s",
           IP2STR(ip_buf), ip_addr);
  utarray_push_back(properties, &property);

  snprintf(property, property_size,
           "firewall.edgesec_" IP_SECTION_STR "_snat.src=%s", IP2STR(ip_buf),
           brname);
  utarray_push_back(properties, &property);

  snprintf(property, property_size,
           "firewall.edgesec_" IP_SECTION_STR "_snat.src_ip=%s", IP2STR(ip_buf),
           ip_addr);
  utarray_push_back(properties, &property);

  snprintf(property, property_size,
           "firewall.edgesec_" IP_SECTION_STR "_snat.dest=%s", IP2STR(ip_buf),
           nat_name);
  utarray_push_back(properties, &property);

  snprintf(property, property_size,
           "firewall.edgesec_" IP_SECTION_STR "_snat.dest_ip=0.0.0.0",
           IP2STR(ip_buf));
  utarray_push_back(properties, &property);

  snprintf(property, property_size,
           "firewall.edgesec_" IP_SECTION_STR "_snat.proto=all",
           IP2STR(ip_buf));
  utarray_push_back(properties, &property);

  snprintf(property, property_size,
           "firewall.edgesec_" IP_SECTION_STR "_snat.target=SNAT",
           IP2STR(ip_buf));
  utarray_push_back(properties, &property);

  snprintf(property, property_size,
           "firewall.edgesec_" IP_SECTION_STR "_forward=rule", IP2STR(ip_buf));
  utarray_push_back(properties, &property);

  snprintf(property, property_size,
           "firewall.edgesec_" IP_SECTION_STR "_forward.enabled=1",
           IP2STR(ip_buf));
  utarray_push_back(properties, &property);

  snprintf(property, property_size,
           "firewall.edgesec_" IP_SECTION_STR "_forward.name=Forward %s",
           IP2STR(ip_buf), ip_addr);
  utarray_push_back(properties, &property);

  snprintf(property, property_size,
           "firewall.edgesec_" IP_SECTION_STR "_forward.src=%s", IP2STR(ip_buf),
           brname);
  utarray_push_back(properties, &property);

  snprintf(property, property_size,
           "firewall.edgesec_" IP_SECTION_STR "_forward.src_ip=%s",
           IP2STR(ip_buf), ip_addr);
  utarray_push_back(properties, &property);

  snprintf(property, property_size,
           "firewall.edgesec_" IP_SECTION_STR "_forward.dest=%s",
           IP2STR(ip_buf), nat_name);
  utarray_push_back(properties, &property);

  snprintf(property, property_size,
           "firewall.edgesec_" IP_SECTION_STR "_forward.proto=all",
           IP2STR(ip_buf));
  utarray_push_back(properties, &property);

  snprintf(property, property_size,
           "firewall.edgesec_" IP_SECTION_STR "_forward.target=ACCEPT",
           IP2STR(ip_buf));
  utarray_push_back(properties, &property);

  snprintf(property, property_size,
           "firewall.edgesec_" IP_SECTION_STR "_backward=rule", IP2STR(ip_buf));
  utarray_push_back(properties, &property);

  snprintf(property, property_size,
           "firewall.edgesec_" IP_SECTION_STR "_backward.enabled=1",
           IP2STR(ip_buf));
  utarray_push_back(properties, &property);

  snprintf(property, property_size,
           "firewall.edgesec_" IP_SECTION_STR "_backward.name=Backward %s",
           IP2STR(ip_buf), ip_addr);
  utarray_push_back(properties, &property);

  snprintf(property, property_size,
           "firewall.edgesec_" IP_SECTION_STR "_backward.src=%s",
           IP2STR(ip_buf), nat_name);
  utarray_push_back(properties, &property);

  snprintf(property, property_size,
           "firewall.edgesec_" IP_SECTION_STR "_backward.dest=%s",
           IP2STR(ip_buf), brname);
  utarray_push_back(properties, &property);

  snprintf(property, property_size,
           "firewall.edgesec_" IP_SECTION_STR "_backward.dest_ip=%s",
           IP2STR(ip_buf), ip_addr);
  utarray_push_back(properties, &property);

  snprintf(property, property_size,
           "firewall.edgesec_" IP_SECTION_STR "_backward.proto=all",
           IP2STR(ip_buf));
  utarray_push_back(properties, &property);

  snprintf(property, property_size,
           "firewall.edgesec_" IP_SECTION_STR "_backward.target=ACCEPT",
           IP2STR(ip_buf));
  utarray_push_back(properties, &property);

  if (uwrt_set_properties(context->uctx, properties) < 0) {
    log_error("uwrt_add_firewall_nat: failed to uwrt_set_properties");
    utarray_free(properties);
    return -1;
  }
  utarray_free(properties);

  return 0;
}

int uwrt_delete_firewall_nat(const struct uctx *context, const char *ip_addr) {
  uint8_t ip_buf[4];

  if (context == NULL) {
    log_trace("context param is NULL");
    return -1;
  }

  if (ip_addr == NULL) {
    log_trace("ip_addr param is NULL");
    return -1;
  }

  if (ip4_2_buf(ip_addr, ip_buf) < 0) {
    log_trace("ip4_2_buf fail");
    return -1;
  }

  UT_array *props_to_delete;
  utarray_new(props_to_delete, &ut_str_icd);

  char property_buffer[256];
  const size_t property_size = ARRAY_SIZE(property_buffer);
  // utarray_push_back doesn't support arrays, only pointers, due to being
  // a C preprocessor macro
  char *const property = property_buffer;

  snprintf(property, property_size,
           "firewall.edgesec_" IP_SECTION_STR "_backward", IP2STR(ip_buf));
  utarray_push_back(props_to_delete, &property);

  snprintf(property, property_size,
           "firewall.edgesec_" IP_SECTION_STR "_forward", IP2STR(ip_buf));
  utarray_push_back(props_to_delete, &property);

  snprintf(property, property_size, "firewall.edgesec_" IP_SECTION_STR "_snat",
           IP2STR(ip_buf));
  utarray_push_back(props_to_delete, &property);

  snprintf(property, property_size, "firewall.edgesec_" IP_SECTION_STR "_dnat",
           IP2STR(ip_buf));
  utarray_push_back(props_to_delete, &property);

  uwrt_delete_properties(context->uctx, props_to_delete);
  utarray_free(props_to_delete);

  return 0;
}

int uwrt_add_firewall_bridge(const struct uctx *context, const char *sip,
                             const char *sbr, const char *dip,
                             const char *dbr) {
  uint8_t sip_buf[4], dip_buf[4];

  if (context == NULL) {
    log_trace("context param is NULL");
    return -1;
  }

  if (sip == NULL) {
    log_trace("sip param is NULL");
    return -1;
  }

  if (sbr == NULL) {
    log_trace("sbr param is NULL");
    return -1;
  }

  if (dip == NULL) {
    log_trace("dip param is NULL");
    return -1;
  }

  if (dbr == NULL) {
    log_trace("dbr param is NULL");
    return -1;
  }

  if (ip4_2_buf(sip, sip_buf) < 0) {
    log_trace("ip4_2_buf fail");
    return -1;
  }

  if (ip4_2_buf(dip, dip_buf) < 0) {
    log_trace("ip4_2_buf fail");
    return -1;
  }

  UT_array *properties;
  utarray_new(properties, &ut_str_icd);

  char property_buffer[256];
  const size_t property_size = ARRAY_SIZE(property_buffer);
  // utarray_push_back doesn't support arrays, only pointers, due to being
  // a C preprocessor macro
  char *const property = property_buffer;

  snprintf(property, property_size,
           "firewall.edgesec_" IP_SECTION_STR "_" IP_SECTION_STR "=rule",
           IP2STR(sip_buf), IP2STR(dip_buf));
  utarray_push_back(properties, &property);

  snprintf(property, property_size,
           "firewall.edgesec_" IP_SECTION_STR "_" IP_SECTION_STR ".enabled=1",
           IP2STR(sip_buf), IP2STR(dip_buf));
  utarray_push_back(properties, &property);

  snprintf(property, property_size,
           "firewall.edgesec_" IP_SECTION_STR "_" IP_SECTION_STR
           ".name=Bridge %s->%s",
           IP2STR(sip_buf), IP2STR(dip_buf), sip, dip);
  utarray_push_back(properties, &property);

  snprintf(property, property_size,
           "firewall.edgesec_" IP_SECTION_STR "_" IP_SECTION_STR ".src=%s",
           IP2STR(sip_buf), IP2STR(dip_buf), sbr);
  utarray_push_back(properties, &property);

  snprintf(property, property_size,
           "firewall.edgesec_" IP_SECTION_STR "_" IP_SECTION_STR ".src_ip=%s",
           IP2STR(sip_buf), IP2STR(dip_buf), sip);
  utarray_push_back(properties, &property);

  snprintf(property, property_size,
           "firewall.edgesec_" IP_SECTION_STR "_" IP_SECTION_STR ".dest=%s",
           IP2STR(sip_buf), IP2STR(dip_buf), dbr);
  utarray_push_back(properties, &property);

  snprintf(property, property_size,
           "firewall.edgesec_" IP_SECTION_STR "_" IP_SECTION_STR ".dest_ip=%s",
           IP2STR(sip_buf), IP2STR(dip_buf), dip);
  utarray_push_back(properties, &property);

  snprintf(property, property_size,
           "firewall.edgesec_" IP_SECTION_STR "_" IP_SECTION_STR ".proto=all",
           IP2STR(sip_buf), IP2STR(dip_buf));
  utarray_push_back(properties, &property);

  snprintf(property, property_size,
           "firewall.edgesec_" IP_SECTION_STR "_" IP_SECTION_STR
           ".target=ACCEPT",
           IP2STR(sip_buf), IP2STR(dip_buf));
  utarray_push_back(properties, &property);

  snprintf(property, property_size,
           "firewall.edgesec_" IP_SECTION_STR "_" IP_SECTION_STR "=rule",
           IP2STR(dip_buf), IP2STR(sip_buf));
  utarray_push_back(properties, &property);

  snprintf(property, property_size,
           "firewall.edgesec_" IP_SECTION_STR "_" IP_SECTION_STR ".enabled=1",
           IP2STR(dip_buf), IP2STR(sip_buf));
  utarray_push_back(properties, &property);

  snprintf(property, property_size,
           "firewall.edgesec_" IP_SECTION_STR "_" IP_SECTION_STR
           ".name=Bridge %s->%s",
           IP2STR(dip_buf), IP2STR(sip_buf), dip, sip);
  utarray_push_back(properties, &property);

  snprintf(property, property_size,
           "firewall.edgesec_" IP_SECTION_STR "_" IP_SECTION_STR ".src=%s",
           IP2STR(dip_buf), IP2STR(sip_buf), dbr);
  utarray_push_back(properties, &property);

  snprintf(property, property_size,
           "firewall.edgesec_" IP_SECTION_STR "_" IP_SECTION_STR ".src_ip=%s",
           IP2STR(dip_buf), IP2STR(sip_buf), dip);
  utarray_push_back(properties, &property);

  snprintf(property, property_size,
           "firewall.edgesec_" IP_SECTION_STR "_" IP_SECTION_STR ".dest=%s",
           IP2STR(dip_buf), IP2STR(sip_buf), sbr);
  utarray_push_back(properties, &property);

  snprintf(property, property_size,
           "firewall.edgesec_" IP_SECTION_STR "_" IP_SECTION_STR ".dest_ip=%s",
           IP2STR(dip_buf), IP2STR(sip_buf), sip);
  utarray_push_back(properties, &property);

  snprintf(property, property_size,
           "firewall.edgesec_" IP_SECTION_STR "_" IP_SECTION_STR ".proto=all",
           IP2STR(dip_buf), IP2STR(sip_buf));
  utarray_push_back(properties, &property);

  snprintf(property, property_size,
           "firewall.edgesec_" IP_SECTION_STR "_" IP_SECTION_STR
           ".target=ACCEPT",
           IP2STR(dip_buf), IP2STR(sip_buf));
  utarray_push_back(properties, &property);

  if (uwrt_set_properties(context->uctx, properties) < 0) {
    log_error("uwrt_add_firewall_nat: failed to uwrt_set_properties");
    utarray_free(properties);
    return -1;
  }
  utarray_free(properties);

  return 0;
}

int uwrt_delete_firewall_bridge(const struct uctx *context, const char *sip,
                                const char *dip) {
  uint8_t sip_buf[4], dip_buf[4];

  if (context == NULL) {
    log_trace("context param is NULL");
    return -1;
  }

  if (sip == NULL) {
    log_trace("sip param is NULL");
    return -1;
  }

  if (dip == NULL) {
    log_trace("dip param is NULL");
    return -1;
  }

  if (ip4_2_buf(sip, sip_buf) < 0) {
    log_trace("ip4_2_buf fail");
    return -1;
  }

  if (ip4_2_buf(dip, dip_buf) < 0) {
    log_trace("ip4_2_buf fail");
    return -1;
  }

  UT_array *props_to_delete;
  utarray_new(props_to_delete, &ut_str_icd);

  char property_buffer[256];
  const size_t property_size = ARRAY_SIZE(property_buffer);
  // utarray_push_back doesn't support arrays, only pointers, due to being
  // a C preprocessor macro
  char *const property = property_buffer;

  snprintf(property, property_size,
           "firewall.edgesec_" IP_SECTION_STR "_" IP_SECTION_STR,
           IP2STR(sip_buf), IP2STR(dip_buf));
  utarray_push_back(props_to_delete, &property);

  snprintf(property, property_size,
           "firewall.edgesec_" IP_SECTION_STR "_" IP_SECTION_STR,
           IP2STR(dip_buf), IP2STR(sip_buf));
  utarray_push_back(props_to_delete, &property);

  uwrt_delete_properties(context->uctx, props_to_delete);
  utarray_free(props_to_delete);

  return 0;
}

int uwrt_cleanup_firewall(const struct uctx *context) {
  int ret;
  char **ptr = NULL, *fo = NULL, *p = NULL;
  UT_array *kv = NULL, *parray = NULL;
  char key[10], property[256];

  utarray_new(kv, &ut_str_icd);

  sprintf(key, "firewall");

  ret = uwrt_lookup_key(context->uctx, key, kv);

  if (!ret) {
    utarray_free(kv);
    return 0;
  } else if (ret < 0 && context->uctx->err != UCI_ERR_NOTFOUND) {
    log_trace("uwrt_lookup_key fail");
    utarray_free(kv);
    return -1;
  } else if (ret < 0 && context->uctx->err == UCI_ERR_NOTFOUND) {
    log_warn("%s key not found", key);
    utarray_free(kv);
    return 0;
  }

  utarray_new(parray, &ut_str_icd);
  p = &property[0];
  while ((ptr = (char **)utarray_next(kv, ptr))) {
    property[0] = '\0';

    if (strstr(*ptr, "edgesec_") != NULL) {
      fo = strstr(*ptr, "=zone");
      if (fo != NULL) {
        os_strlcpy(property, *ptr, (size_t)(fo - *ptr) + 1);
      }
      fo = strstr(*ptr, "=rule");
      if (fo != NULL) {
        os_strlcpy(property, *ptr, (size_t)(fo - *ptr) + 1);
      }

      fo = strstr(*ptr, "=nat");
      if (fo != NULL) {
        os_strlcpy(property, *ptr, (size_t)(fo - *ptr) + 1);
      }

      if (strlen(property)) {
        utarray_push_back(parray, &p);
      }
    }
  }

  uwrt_delete_properties(context->uctx, parray);

  utarray_free(kv);
  utarray_free(parray);
  return 0;
}
