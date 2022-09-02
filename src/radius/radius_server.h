/*
 * RADIUS authentication server
 * Copyright (c) 2005-2009, 2011, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

/**
 * @file radius_server.h
 * @authors Jouni Malinen, Alexandru Mereacre
 * @brief RADIUS authentication server.
 */

#ifndef RADIUS_SERVER_H
#define RADIUS_SERVER_H

#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
// On FreeBSD, you must include `<netinet/in.h>` before `<netinet/if_ether.h>`
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <stdbool.h>

#include "../utils/os.h"
#include "../utils/eloop.h"
#include "radius_config.h"

/**
 * struct radius_server_counters - RADIUS server statistics counters
 */
struct radius_server_counters {
  uint32_t access_requests;
  uint32_t invalid_requests;
  uint32_t dup_access_requests;
  uint32_t access_accepts;
  uint32_t access_rejects;
  uint32_t access_challenges;
  uint32_t malformed_access_requests;
  uint32_t bad_authenticators;
  uint32_t packets_dropped;
  uint32_t unknown_types;
};

struct hostapd_radius_attr {
  uint8_t type;
  struct wpabuf *val;
  struct hostapd_radius_attr *next;
};

/**
 * struct radius_session - Internal RADIUS server data for a session
 */
struct radius_session {
  struct radius_session *next;
  struct radius_client *client;
  struct radius_server_data *server;
  unsigned int sess_id;
  char *username; /* from User-Name attribute */
  char *nas_ip;
  uint8_t mac_addr[ETH_ALEN]; /* from Calling-Station-Id attribute */

  struct radius_msg *last_msg;
  char *last_from_addr;
  int last_from_port;
  struct sockaddr_storage last_from;
  socklen_t last_fromlen;
  uint8_t last_identifier;
  struct radius_msg *last_reply;
  uint8_t last_authenticator[16];

  unsigned int macacl : 1;

  struct hostapd_radius_attr *accept_attr;
};

typedef struct mac_conn_info (*mac_conn_fn)(uint8_t mac_addr[],
                                            void *mac_conn_arg);
/**
 * struct radius_client - Internal RADIUS server data for a client
 */
struct radius_client {
  struct radius_client *next;
  struct in_addr addr;
  struct in_addr mask;
  char *shared_secret;
  int shared_secret_len;
  struct radius_session *sessions;
  struct radius_server_counters counters;

  mac_conn_fn conn_fn;
  void *mac_conn_arg;
  // int (*get_vlan_id)(uint8_t mac_addr[]);
  struct hostapd_tunnel_pass (*get_tunnel_pass)(uint8_t mac_addr[]);
};

/**
 * struct radius_server_data - Internal RADIUS server data
 */
struct radius_server_data {
  /**
   * eloop - The eloop context
   */
  struct eloop_data *eloop;

  /**
   * auth_sock - Socket for RADIUS authentication messages
   */
  int auth_sock;

  /**
   * clients - List of authorized RADIUS clients
   */
  struct radius_client *clients;

  /**
   * next_sess_id - Next session identifier
   */
  unsigned int next_sess_id;

  /**
   * num_sess - Number of active sessions
   */
  int num_sess;

  /**
   * start_time - Timestamp of server start
   */
  struct os_reltime start_time;

  /**
   * counters - Statistics counters for server operations
   *
   * These counters are the sum over all clients.
   */
  struct radius_server_counters counters;
};

struct radius_server_data *radius_server_init(struct eloop_data *eloop,
                                              int auth_port,
                                              struct radius_client *clients);
void radius_server_deinit(struct radius_server_data *data);
int radius_server_get_mib(struct radius_server_data *data, char *buf,
                          size_t buflen);
struct radius_client *init_radius_client(struct radius_conf *conf,
                                         void *mac_conn_fn, void *mac_conn_arg);
void radius_server_free_clients(struct radius_server_data *data,
                                struct radius_client *clients);
#endif /* RADIUS_SERVER_H */
