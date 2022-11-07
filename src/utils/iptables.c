/**
 * @file
 * @author Alexandru Mereacre
 * @date 2020
 * @copyright
 * SPDX-FileCopyrightText: © 2020 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the implementation of the IP tables utilities.
 */

#include <stdbool.h>
#include <stdlib.h>
#include <limits.h>
#include <stdio.h>
#include <errno.h>

#include "iptables.h"
#include "allocs.h"
#include "os.h"
#include "log.h"
#include "iface_mapper.h"
#include "net.h"

struct iptables_columns {
  long num;
  char target[20];
  char in[IF_NAMESIZE];
  char out[IF_NAMESIZE];
  char source[OS_INET_ADDRSTRLEN];
  char destination[OS_INET_ADDRSTRLEN];
};

#define BASIC_FLUSH_COMMANDS                                                    \
  {                                                                             \
    {"-P", "INPUT", "ACCEPT", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL},  \
        {"-P", "FORWARD", "ACCEPT", NULL, NULL, NULL,                           \
         NULL, NULL,      NULL,     NULL, NULL},                                \
        {"-P", "OUTPUT", "ACCEPT", NULL, NULL, NULL,                            \
         NULL, NULL,     NULL,     NULL, NULL},                                 \
        {"-F", "-t", "nat", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL},    \
        {"-F", "-t", "mangle", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL}, \
        {"-F", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL},     \
        {"-X", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL},     \
        {"-A",    "FORWARD",     "-t", "filter", "--src", "224.0.0.0/4",        \
         "--dst", "224.0.0.0/4", "-j", "ACCEPT", NULL},                         \
        {NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL},     \
  }

// static char iptables_path[MAX_OS_PATH_LEN];
static const UT_icd iptables_icd = {sizeof(struct iptables_columns), NULL, NULL,
                                    NULL};
// static UT_array *rule_list;

struct iptables_columns process_rule_column(char *column) {
  struct iptables_columns row;

  os_memset(&row, 0, sizeof(struct iptables_columns));

  int state = 0;
  char **p = NULL;
  char *endptr;
  UT_array *column_arr;
  utarray_new(column_arr, &ut_str_icd);

  if (split_string_array(column, 0x20, column_arr) < 0) {
    log_error("split_string_array fail");
    utarray_free(column_arr);
    return row;
  }

  while ((p = (char **)utarray_next(column_arr, p)) != NULL) {
    if (strlen(*p)) {
      switch (state) {
        case 0:
          // Num column
          errno = 0;
          row.num = (long)strtol(*p, &endptr, 10);
          if ((errno == ERANGE &&
               (row.num == LONG_MAX || row.num == LONG_MIN)) ||
              (errno != 0 && row.num == 0))
            state = 10;
          else {
            if (endptr == *p)
              state = 10;
            else
              state = 1;
          }
          break;
        case 1:
          // pkts column
          state = 2;
          break;
        case 2:
          // bytes column
          state = 3;
          break;
        case 3:
          // target column
          os_strlcpy(row.target, *p, 20);
          state = 4;
          break;
        case 4:
          // prot column
          state = 5;
          break;
        case 5:
          // opt column
          state = 6;
          break;
        case 6:
          // in column
          os_strlcpy(row.in, *p, IF_NAMESIZE);
          state = 7;
          break;
        case 7:
          // out column
          os_strlcpy(row.out, *p, IF_NAMESIZE);
          state = 8;
          break;
        case 8:
          // source column
          os_strlcpy(row.source, *p, OS_INET_ADDRSTRLEN);
          state = 9;
          break;
        case 9:
          // destination column
          os_strlcpy(row.destination, *p, OS_INET_ADDRSTRLEN);
          state = 10;
          break;
      }
    }
  }

  utarray_free(column_arr);

  return row;
}

int process_rule_lines(struct iptables_context *ctx, char *rule_str) {
  char **p = NULL;
  UT_array *line_arr;
  ssize_t line_count;
  utarray_new(line_arr, &ut_str_icd);

  line_count = split_string_array(rule_str, '\n', line_arr);

  if (line_count < 0) {
    log_error("split_string_array fail");
    utarray_free(line_arr);
    return -1;
  } else if (line_count > 2) {
    p = (char **)utarray_next(line_arr, p);
    p = (char **)utarray_next(line_arr, p);

    while ((p = (char **)utarray_next(line_arr, p)) != NULL) {
      if (strlen(*p) > 1) {
        struct iptables_columns row = process_rule_column(*p);
        if (row.num) {
          utarray_push_back(ctx->rule_list, &row);
        } else {
          log_error("process_rule_column fail");
          utarray_free(line_arr);
          return -1;
        }
      }
    }
  }

  utarray_free(line_arr);
  return 0;
}

void list_rule_cb(void *ctx, void *buf, size_t count) {
  struct iptables_context *iptables_context = (struct iptables_context *)ctx;

  if (ctx == NULL) {
    log_error("ctx param is NULL");
    return;
  }

  char *out_str = os_malloc(count + 1);

  os_memcpy(out_str, buf, count);
  out_str[count] = '\0';

  utarray_clear(iptables_context->rule_list);

  if (process_rule_lines(iptables_context, out_str) < 0) {
    log_error("process_rule_lines fail");
    utarray_clear(iptables_context->rule_list);
  }
  os_free(out_str);
}

int run_iptables(struct iptables_context *ctx, char *argv[],
                 process_callback_fn fn) {
  return run_argv_command(ctx->iptables_path, argv, fn, (void *)ctx);
}

int flush_iptables(struct iptables_context *ctx) {
  char *basic_flush_rules[][11] = BASIC_FLUSH_COMMANDS;
  int rule_count = 0;

  while (basic_flush_rules[rule_count][0] != NULL) {
    if (run_iptables(ctx, basic_flush_rules[rule_count], NULL) < 0) {
      log_error("run_iptables fail");
      return -1;
    }

    rule_count++;
  }

  return 0;
}

int add_baseif_rules(struct iptables_context *ctx, UT_array *ifinfo_array) {
  char *reject_rule[9] = {"-A", "FORWARD", "-t",     "filter", "-i",
                          NULL, "-j",      "REJECT", NULL};

  config_ifinfo_t *p = NULL;
  if (ifinfo_array == NULL)
    return false;

  while ((p = (config_ifinfo_t *)utarray_next(ifinfo_array, p)) != NULL) {
    reject_rule[5] = p->ifname;
    if (run_iptables(ctx, reject_rule, NULL) < 0) {
      log_error("run_iptables fail");
      return -1;
    }
  }

  return 0;
}

void iptables_free(struct iptables_context *ctx) {
  if (ctx != NULL) {
    utarray_free(ctx->rule_list);
    os_free(ctx);
  }
}

struct iptables_context *iptables_init(char *path, UT_array *ifinfo_array,
                                       bool exec_iptables) {
  struct iptables_context *ctx = NULL;

  if (path == NULL) {
    log_error("path param is NULL");
    return NULL;
  }

  if (!strlen(path)) {
    log_error("path param is empty");
    return NULL;
  }

  ctx = (struct iptables_context *)os_zalloc(sizeof(struct iptables_context));

  ctx->exec_iptables = exec_iptables;
  os_strlcpy(ctx->iptables_path, path, MAX_OS_PATH_LEN);

  utarray_new(ctx->rule_list, &iptables_icd);

  if (flush_iptables(ctx) < 0) {
    log_error("flush_iptables fail");
    iptables_free(ctx);
    return NULL;
  }

  if (add_baseif_rules(ctx, ifinfo_array) < 0) {
    log_error("add_baseif_rules fail");
    iptables_free(ctx);
    return NULL;
  }

  return ctx;
}

int get_filter_rules(struct iptables_context *ctx) {
  char *list_rule[8] = {"-L", "FORWARD", "-t", "filter", "--line-numbers",
                        "-n", "-v",      NULL};

  if (run_iptables(ctx, list_rule, list_rule_cb) < 0) {
    log_error("run_iptables fail");
    return -1;
  }

  return utarray_len(ctx->rule_list) ? 0 : -1;
}

int get_nat_rules(struct iptables_context *ctx) {
  char *list_rule[8] = {"-L", "POSTROUTING", "-t", "nat", "--line-numbers",
                        "-n", "-v",          NULL};

  if (run_iptables(ctx, list_rule, list_rule_cb) < 0) {
    log_trace("run_iptables fail");
    return -1;
  }

  return utarray_len(ctx->rule_list) ? 0 : -1;
}

long find_rule(UT_array *rlist, char *sip, char *sif, char *dip, char *dif,
               char *target) {
  struct iptables_columns *el = NULL;
  while ((el = (struct iptables_columns *)utarray_next(rlist, el)) != NULL) {
    if (!strcmp(el->in, sif) && !strcmp(el->out, dif) &&
        !strcmp(el->source, sip) && !strcmp(el->destination, dip) &&
        !strcmp(el->target, target))
      return el->num;
  }

  return 0;
}

int delete_bridge_rule(struct iptables_context *ctx, char *sip, char *sif,
                       char *dip, char *dif) {
  char num_buf[10];

  char *bridge_rule[16] = {"-D", "FORWARD", NULL, "-t", "filter", NULL};

  if (get_filter_rules(ctx) < 0 && ctx->exec_iptables) {
    log_error("iptables rules empty");
    return -1;
  }

  long num = find_rule(ctx->rule_list, sip, sif, dip, dif, "ACCEPT");
  if (!num && ctx->exec_iptables) {
    log_trace("No bridge rule found");
    return 0;
  }

  sprintf(num_buf, "%ld", num);

  bridge_rule[2] = num_buf;

  if (run_iptables(ctx, bridge_rule, NULL) < 0) {
    log_error("run_iptables fail");
    return -1;
  }

  return 0;
}

int iptables_delete_bridge(struct iptables_context *ctx, char *sip, char *sif,
                           char *dip, char *dif) {
  if (delete_bridge_rule(ctx, sip, sif, dip, dif) < 0) {
    log_error("delete_bridge_rule fail");
    return -1;
  }

  if (delete_bridge_rule(ctx, dip, dif, sip, sif) < 0) {
    log_error("delete_bridge_rule fail");
    return -1;
  }

  return 0;
}

long find_baseif_rulenum(UT_array *rlist, char *ifname) {
  struct iptables_columns *el = NULL;
  while ((el = (struct iptables_columns *)utarray_next(rlist, el)) != NULL) {
    if (!strcmp(el->in, ifname) && !strcmp(el->out, "*") &&
        !strcmp(el->target, "REJECT"))
      return el->num;
  }

  return 0;
}

int add_bridge_rule(struct iptables_context *ctx, char *sip, char *sif,
                    char *dip, char *dif) {
  char num_buf[10];

  char *bridge_rule[16] = {"-I", "FORWARD", NULL,     "-t", "filter", "--src",
                           NULL, "--dst",   NULL,     "-i", NULL,     "-o",
                           NULL, "-j",      "ACCEPT", NULL};

  if (ctx == NULL) {
    log_error("ctx param is NULL");
    return -1;
  }

  if (!validate_ipv4_string(sip)) {
    log_error("Wrong source IP format %s", sip);
    return -1;
  }

  if (!validate_ipv4_string(dip)) {
    log_error("Wrong destination IP format %s", dip);
    return -1;
  }

  if (get_filter_rules(ctx) < 0 && ctx->exec_iptables) {
    log_error("iptables rules empty");
    return -1;
  }

  long num = find_baseif_rulenum(ctx->rule_list, sif);
  if (!num && ctx->exec_iptables) {
    log_trace("Rule not found for sif=%s", sif);
    num++;
  }

  sprintf(num_buf, "%ld", num);

  bridge_rule[2] = num_buf;
  bridge_rule[6] = sip;
  bridge_rule[8] = dip;
  bridge_rule[10] = sif;
  bridge_rule[12] = dif;

  if (run_iptables(ctx, bridge_rule, NULL) < 0) {
    log_error("run_iptables fail");
    return -1;
  }

  return 0;
}

int iptables_add_bridge(struct iptables_context *ctx, char *sip, char *sif,
                        char *dip, char *dif) {
  if (ctx == NULL) {
    log_error("ctx param is NULL");
    return -1;
  }

  // Delete bridge rules if present
  iptables_delete_bridge(ctx, sip, sif, dip, dif);

  if (add_bridge_rule(ctx, sip, sif, dip, dif) < 0) {
    log_error("add_bridge_rule fail");
    return -1;
  }

  if (add_bridge_rule(ctx, dip, dif, sip, sif) < 0) {
    log_error("add_bridge_rule fail");
    delete_bridge_rule(ctx, sip, sif, dip, dif);
    return -1;
  }

  return 0;
}

int iptables_delete_nat(struct iptables_context *ctx, char *sip, char *sif,
                        char *nif) {
  char *nat_rule[6] = {"-D", "POSTROUTING", NULL, "-t", "nat", NULL};
  char num_buf[10];

  if (ctx == NULL) {
    log_error("ctx param is NULL");
    return -1;
  }

  if (iptables_delete_bridge(ctx, sip, sif, "0.0.0.0/0", nif) < 0) {
    log_error("delete_bridge_rule fail for sip=%s sif=%s dip=0.0.0.0/0 dif=%s",
              sip, sif, nif);
    return -1;
  }

  if (get_nat_rules(ctx) < 0 && ctx->exec_iptables) {
    log_trace("iptables rules empty");
    return 0;
  }

  long num =
      find_rule(ctx->rule_list, sip, "*", "0.0.0.0/0", nif, "MASQUERADE");
  if (!num && ctx->exec_iptables) {
    log_trace("No bridge rule found");
    return 0;
  }

  sprintf(num_buf, "%ld", num);

  nat_rule[2] = num_buf;

  if (run_iptables(ctx, nat_rule, NULL) < 0) {
    log_error("run_iptables fail");
    return -1;
  }

  return 0;
}

int iptables_add_nat(struct iptables_context *ctx, char *sip, char *sif,
                     char *nif) {
  char *nat_rule[14] = {
      "-I",    "POSTROUTING", "1",  "-t", "nat", "--src",      NULL,
      "--dst", "0.0.0.0/0",   "-o", NULL, "-j",  "MASQUERADE", NULL};
  char *bridge_rule[16] = {
      "-I", "FORWARD", "1",  "-t", "filter", "--src", "0.0.0.0/0", "--dst",
      NULL, "-i",      NULL, "-o", NULL,     "-j",    "ACCEPT",    NULL};

  if (ctx == NULL) {
    log_error("ctx params is NULL");
    return -1;
  }

  // Delete nat rules if present
  if (iptables_delete_nat(ctx, sip, sif, nif) < 0) {
    log_error("iptables_delete_nat fail");
    return -1;
  }

  if (add_bridge_rule(ctx, sip, sif, "0.0.0.0/0", nif) < 0) {
    log_error("add_bridge_rule fail for sip=%s sif=%s dip=0.0.0.0/0 dif=%s",
              sip, sif, nif);
    return -1;
  }

  bridge_rule[8] = sip;
  bridge_rule[10] = nif;
  bridge_rule[12] = sif;

  if (run_iptables(ctx, bridge_rule, NULL) < 0) {
    log_error("run_iptables fail");
    iptables_delete_bridge(ctx, sip, sif, "0.0.0.0/0", nif);
    return -1;
  }

  nat_rule[6] = sip;
  nat_rule[10] = nif;

  if (run_iptables(ctx, nat_rule, NULL) < 0) {
    log_error("run_iptables fail");
    iptables_delete_bridge(ctx, sip, sif, "0.0.0.0/0", nif);
    return -1;
  }

  return 0;
}
