/**************************************************************************************************
*  Filename:        iptables.c
*  Author:          Alexandru Mereacre (mereacre@gmail.com)
*  Revised:
*  Revision:
*
*  Description:     iptables source file
*
*  Copyright (C) 2020 NQMCyber Ltd - http://www.nqmcyber.com/
*************************************************************************************************/
#include <stdbool.h>
#include <stdlib.h>
#include <limits.h>
#include <stdio.h>
#include <errno.h>

#include "utarray.h"
#include "os.h"
#include "log.h"
#include "if.h"

struct iptables_columns {
  long num;
  char target[20];
  char in[IFNAMSIZ];
  char out[IFNAMSIZ];
  char source[IP_LEN];
  char destination[IP_LEN];
};

#define BASIC_FLUSH_COMMANDS {\
    {"-P", "INPUT", "ACCEPT", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL},\
    {"-P", "FORWARD", "ACCEPT", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL},\
    {"-P", "OUTPUT", "ACCEPT", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL},\
    {"-F", "-t", "nat", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL},\
    {"-F", "-t", "mangle", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL},\
    {"-F", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL},\
    {"-X", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL},\
    {"-A", "FORWARD", "-t", "filter", "--src", "224.0.0.0/4", "--dst", "224.0.0.0/4", "-j", "ACCEPT", NULL},\
    {NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL},\
  }

static char iptables_path[MAX_OS_PATH_LEN];
static const UT_icd iptables_icd = {sizeof(struct iptables_columns), NULL, NULL, NULL};
static UT_array *rule_list;

void log_run_command(char *argv[], int arg_count)
{
  char buf[255];

  os_memset(buf, 0, 255);
  for (int i = 0; i < arg_count; i++) {
    strcat(buf, argv[i]);
    strcat(buf, " ");
  }

  log_trace("Running %s", buf);
}

struct iptables_columns process_rule_column(char *column)
{
  struct iptables_columns row;

  os_memset(&row, 0, sizeof(struct iptables_columns));

  int state = 0;
  char **p = NULL;
  char *endptr;
  UT_array *column_arr;
  utarray_new(column_arr, &ut_str_icd);

  split_string_array(column, 0x20, column_arr);

  while(p = (char **) utarray_next(column_arr, p)) {
    if (strlen(*p)) {
      switch(state) {
        case 0:
          // Num column
          errno = 0;
          row.num = (long) strtol(*p, &endptr, 10);
          if ((errno == ERANGE && (row.num == LONG_MAX || row.num == LONG_MIN)) ||
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
          //target column
          strncpy(row.target, *p, 10);
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
          strncpy(row.in, *p, IFNAMSIZ);
          state = 7;
          break;
        case 7:
          // out column
          strncpy(row.out, *p, IFNAMSIZ);
          state = 8;
          break;
        case 8:
          // source column
          strncpy(row.source, *p, IP_LEN);
          state = 9;
          break;
        case 9:
          // destination column
          strncpy(row.destination, *p, IP_LEN);
          state = 10;
          break;
      }
    }
  }

  utarray_free(column_arr);

  return row;
}

bool process_rule_lines(char *rule_str)
{
  char **p = NULL;
  UT_array *line_arr;
  utarray_new(line_arr, &ut_str_icd);

  size_t line_count = split_string_array(rule_str, '\n', line_arr);

  if (line_count > 2) {
    p = (char **) utarray_next(line_arr, p);
    p = (char **) utarray_next(line_arr, p);

    while(p = (char **) utarray_next(line_arr, p)) {
      if (strlen(*p) > 1) {
        struct iptables_columns row = process_rule_column(*p);
        if (row.num) {
          utarray_push_back(rule_list, &row);
        } else {
          log_trace("process_rule_column fail");
          utarray_free(line_arr);
          return true;
        }
      }
    }    
  }

  utarray_free(line_arr);
  return true;
}

void list_rule_cb(void *buf, size_t count)
{
  char *out_str = os_malloc(count + 1);

  memcpy(out_str, buf, count);
  out_str[count] = '\0';

  utarray_clear(rule_list);

  if (!process_rule_lines(out_str)) {
    log_trace("process_rule_lines fail");
    utarray_clear(rule_list);
  }
  os_free(out_str);
}

bool run_iptables(char *argv[], process_callback_fn fn)
{
  char **full_arg;
  int arg_count = 0, count = 0;

  if (argv == NULL)
    return false;
  
  while(argv[arg_count++] != NULL);
  
  full_arg = (char **) os_malloc(sizeof(char *) * (arg_count + 2));

  full_arg[0] = iptables_path;
  full_arg[1] = "iptables";
  while(count < arg_count - 1) {
    full_arg[count + 2] = argv[count];
    count ++;
  }

  full_arg[count + 2] = NULL;

  log_run_command(full_arg, arg_count + 1);

  int status = run_command(full_arg, NULL, fn);
  os_free(full_arg);
  return (!status);
}

bool flush_iptables(void)
{
  char *basic_flush_rules[][11] = BASIC_FLUSH_COMMANDS;
  int rule_count = 0;

  while(basic_flush_rules[rule_count][0] != NULL) {
    if (!run_iptables(basic_flush_rules[rule_count], NULL)) {
      log_trace("run_iptables fail");
      return false;
    }

    rule_count ++;
  }
  
  return true;
}

bool add_baseif_rules(UT_array *ifinfo_array)
{
  char *reject_rule[9] = {"-A", "FORWARD", "-t", "filter", "-i", NULL, "-j", "REJECT", NULL};

  config_ifinfo_t *p = NULL;
  if (ifinfo_array == NULL)
    return false;

  while(p = (config_ifinfo_t*) utarray_next(ifinfo_array, p)) {
    reject_rule[5] = p->ifname;
    if (!run_iptables(reject_rule, NULL)) {
      log_trace("run_iptables fail");
      return false;
    }
  }

  return true;
}

bool init_iptables(char *path, UT_array *ifinfo_array)
{
  if (path == NULL)
    return false;

  if (!strlen(path))
    return false;

  strncpy(iptables_path, path, MAX_OS_PATH_LEN);

  utarray_new(rule_list, &iptables_icd);

  if (!flush_iptables()) {
    log_trace("flush_iptables fail");
    return false;
  }

  if (!add_baseif_rules(ifinfo_array)) {
    log_trace("add_baseif_rules fail");
    return false;
  }

  return true;
}

void free_iptables(void)
{
  utarray_free(rule_list);
}

bool get_filter_rules(void)
{
  char *list_rule[8] = {"-L", "FORWARD", "-t", "filter", "--line-numbers", "-n", "-v", NULL};
 
  if (!run_iptables(list_rule, list_rule_cb)) {
    log_trace("run_iptables fail");
    return false;
  }

  return utarray_len(rule_list) ? true : false;
}

bool get_nat_rules(void)
{
  char *list_rule[8] = {"-L", "POSTROUTING", "-t", "nat", "--line-numbers", "-n", "-v", NULL};
 
  if (!run_iptables(list_rule, list_rule_cb)) {
    log_trace("run_iptables fail");
    return false;
  }

  return utarray_len(rule_list) ? true : false;
}

long find_rule(UT_array *rlist, char *sip, char *sif, char *dip, char *dif, char *target)
{
  struct iptables_columns *el = NULL;
  while(el = (struct iptables_columns *) utarray_next(rlist, el)) {
    if (!strcmp(el->in, sif) && !strcmp(el->out, dif) && !strcmp(el->source, sip) &&
        !strcmp(el->destination, dip) && !strcmp(el->target, target))
      return el->num;
  }

  return 0;
}

bool delete_bridge_rule(char *sip, char *sif, char *dip, char *dif)
{
  char num_buf[10];

  char *bridge_rule[16] = {"-D", "FORWARD", NULL, "-t", "filter", NULL};

  if (!get_filter_rules()) {
    log_trace("iptables rules empty");
    return false;
  }

  long num = find_rule(rule_list, sip, sif, dip, dif, "ACCEPT");
  if (!num) {
    log_trace("No bridge rule found");
    return false;
  }

  sprintf(num_buf, "%ld", num);

  bridge_rule[2] = num_buf;

  if (!run_iptables(bridge_rule, NULL)) {
    log_trace("run_iptables fail");
    return false;
  }

  return true;
}

bool delete_bridge_rules(char *sip, char *sif, char *dip, char *dif)
{
  if (!delete_bridge_rule(sip, sif, dip, dif)) {
    log_trace("delete_bridge_rule fail");
    return false;
  }

  if (!delete_bridge_rule(dip, dif, sip, sif)) {
    log_trace("delete_bridge_rule fail");
    return false;
  }

  return true;
}

long find_baseif_rulenum(UT_array *rlist, char *ifname)
{
  struct iptables_columns *el = NULL;
  while(el = (struct iptables_columns *) utarray_next(rlist, el)) {
    if (!strcmp(el->in, ifname) && !strcmp(el->out, "*") && !strcmp(el->target, "REJECT"))
      return el->num;
  }

  return 0;
}

bool add_bridge_rule(char *sip, char *sif, char *dip, char *dif)
{
  char num_buf[10];

  char *bridge_rule[16] = {"-I", "FORWARD", NULL, "-t", "filter", "--src",
    NULL, "--dst", NULL, "-i", NULL, "-o", NULL, "-j", "ACCEPT", NULL};

  if (!get_filter_rules()) {
    log_trace("iptables rules empty");
    return false;
  }

  long num = find_baseif_rulenum(rule_list, sif);
  if (!num) {
    log_trace("No base rule found");
    return false;
  }

  sprintf(num_buf, "%ld", num);

  bridge_rule[2] = num_buf;
  bridge_rule[6] = sip;
  bridge_rule[8] = dip;
  bridge_rule[10] = sif;
  bridge_rule[12] = dif;

  if (!run_iptables(bridge_rule, NULL)) {
    log_trace("run_iptables fail");
    return false;
  }

  return true;
}

bool add_bridge_rules(char *sip, char *sif, char *dip, char *dif)
{
  // Delete bridge rules if present
  delete_bridge_rules(sip, sif, dip, dif);

  if (!add_bridge_rule(sip, sif, dip, dif)) {
    log_trace("add_bridge_rule fail");
    return false;
  }

  if (!add_bridge_rule(dip, dif, sip, sif)) {
    log_trace("add_bridge_rule fail");
    delete_bridge_rule(sip, sif, dip, dif);
    return false;
  }

  return true;
}

bool delete_nat_rules(char *sip, char *sif, char *nif)
{
  char *nat_rule[6] = {"-D", "POSTROUTING", NULL, "-t", "nat", NULL};
  char num_buf[10];

  if (!delete_bridge_rules(sip, sif, "0.0.0.0/0", nif)) {
    log_trace("delete_bridge_rules fail");
    return false;
  }

  if (!get_nat_rules()) {
    log_trace("iptables rules empty");
    return false;
  }

  long num = find_rule(rule_list, sip, "*", "0.0.0.0/0", nif, "MASQUERADE");
  if (!num) {
    log_trace("No bridge rule found");
    return false;
  }

  sprintf(num_buf, "%ld", num);

  nat_rule[2] = num_buf;

  if (!run_iptables(nat_rule, NULL)) {
    log_trace("run_iptables fail");
    return false;
  }

  return true;
}

bool add_nat_rules(char *sip, char *sif, char *nif)
{
  char *nat_rule[14] = {"-I", "POSTROUTING", "1", "-t", "nat",
    "--src", NULL, "--dst", "0.0.0.0/0", "-o", NULL, "-j", "MASQUERADE", NULL};
  char *bridge_rule[16] = {"-I", "FORWARD", "1", "-t", "filter", "--src", "0.0.0.0/0", "--dst", NULL, "-i",
    NULL, "-o", NULL, "-j", "ACCEPT", NULL};

  // Delete nat rules if present
  delete_nat_rules(sip, sif, nif);

  if (!add_bridge_rule(sip, sif, "0.0.0.0/0", nif)) {
    log_trace("add_bridge_rule fail");
    return false;
  }

  bridge_rule[8] = sip;
  bridge_rule[10] = nif;
  bridge_rule[12] = sif;

  if (!run_iptables(bridge_rule, NULL)) {
    log_trace("run_iptables fail");
    delete_bridge_rules(sip, sif, "0.0.0.0/0", nif);
    return false;
  }

  nat_rule[6] = sip;
  nat_rule[10] = nif;

  if (!run_iptables(nat_rule, NULL)) {
    log_trace("run_iptables fail");
    delete_bridge_rules(sip, sif, "0.0.0.0/0", nif);
    return false;
  }

  return true;
}
