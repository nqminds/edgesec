/**
 * @file
 * @author Alexandru Mereacre
 * @date 2020
 * @copyright
 * SPDX-FileCopyrightText: © 2020 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the definition of the IP tables utilities.
 */

#ifndef IPTABLES_H_
#define IPTABLES_H_

#include <inttypes.h>
#include <stdbool.h>
#include <utarray.h>

#include "allocs.h"
#include "os.h"

/**
 * @brief iptables context structure definition
 *
 */
struct iptables_context {
  char iptables_path[MAX_OS_PATH_LEN]; /**< The iptables executable path */
  UT_array *rule_list;                 /**< Current iptables rules */
  bool exec_iptables;                  /**< Flag to execute iptables command */
};

/**
 * @brief Initialises the iptables rules list
 *
 * @param path The iptables binary path
 * @param ifinfo_array Array of interface configuration info structure
 * @param exec_iptables Execute the iptables command
 * @return struct iptables_context*, pointer to newly created iptables context,
 * NULL on failure
 */
struct iptables_context *iptables_init(char *path, UT_array *ifinfo_array,
                                       bool exec_iptables);

/**
 * @brief Free the iptables context
 *
 * @param ctx The iptables context
 */
void iptables_free(struct iptables_context *ctx);

/**
 * @brief Add a bridge rule to the list of rules
 *
 * @param ctx The iptables context
 * @param sip Source IP string
 * @param sif Source interface name string
 * @param dip Destination IP string
 * @param dif Destination interface name string
 * @return 0 on sucess, -1 on error
 */
int iptables_add_bridge(struct iptables_context *ctx, char *sip, char *sif,
                        char *dip, char *dif);

/**
 * @brief Delete a bridge rule
 *
 * @param ctx The iptables context
 * @param sip Source IP string
 * @param sif Source interface name string
 * @param dip Destination IP string
 * @param dif Destination interface name string
 * @return 0 on success, -1 on error
 */
int iptables_delete_bridge(struct iptables_context *ctx, char *sip, char *sif,
                           char *dip, char *dif);

/**
 * @brief Add a NAT rule
 *
 * @param ctx The iptables context
 * @param sip Source IP string
 * @param sif Source interface name string
 * @param nif NAT interface name string
 * @return 0 on success, -1 on error
 */
int iptables_add_nat(struct iptables_context *ctx, char *sip, char *sif,
                     char *nif);

/**
 * @brief Delete a NAT rule
 *
 * @param ctx The iptables context
 * @param sip Source IP string
 * @param sif Source interface name string
 * @param nif NAT interface name string
 * @return 0 on success, -1 on error
 */
int iptables_delete_nat(struct iptables_context *ctx, char *sip, char *sif,
                        char *nif);

#endif
