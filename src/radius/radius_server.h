/*
 * RADIUS authentication server
 * Copyright (c) 2005-2009, 2011, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef RADIUS_SERVER_H
#define RADIUS_SERVER_H

#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <linux/types.h>
#include <linux/posix_types.h>
#include <asm/types.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <net/if.h>

#include "../utils/if.h"

#define RADIUS_SECRET_LEN				255

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

	unsigned int macacl:1;

	struct hostapd_radius_attr *accept_attr;
};

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

	struct mac_conn_info (*get_mac_conn)(uint8_t mac_addr[]);
	int (*get_vlan_id)(uint8_t mac_addr[]);
	struct hostapd_tunnel_pass (*get_tunnel_pass)(uint8_t mac_addr[]);
};

/**
 * struct radius_server_data - Internal RADIUS server data
 */
struct radius_server_data {
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

struct radius_conf {
  int                 radius_port;
  char                radius_client_ip[IP_LEN];
	int									radius_client_mask;
  char                radius_server_ip[IP_LEN];
	int									radius_server_mask;
  char                radius_secret[RADIUS_SECRET_LEN];
};

struct radius_server_data *radius_server_init(int auth_port, struct radius_client *clients);
void radius_server_deinit(struct radius_server_data *data);
int radius_server_get_mib(struct radius_server_data *data, char *buf, size_t buflen);
struct radius_client *init_radius_client(struct radius_conf *conf,
		struct mac_conn_info (*get_mac_conn)(uint8_t mac_addr[]));
void radius_server_free_clients(struct radius_server_data *data, struct radius_client *clients);
#endif /* RADIUS_SERVER_H */
