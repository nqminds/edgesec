/*
 * RADIUS authentication server
 * Copyright (c) 2005-2009, 2011-2019, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

/**
 * @file radius_server.h 
 * @authors Jouni Malinen, Alexandru Mereacre
 * @brief RADIUS authentication server.
 */

#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <linux/types.h>
#include <linux/posix_types.h>
#include <asm/types.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <net/if.h>

#include "utils/eloop.h"
#include "utils/log.h"
#include "utils/os.h"
#include "utils/if.h"
#include "utils/list.h"
#include "../supervisor/mac_mapper.h"

#include "radius.h"
#include "radius_server.h"
#include "wpabuf.h"

/**
 * RADIUS_SESSION_TIMEOUT - Session timeout in seconds
 */
#define RADIUS_SESSION_TIMEOUT 60

/**
 * RADIUS_SESSION_MAINTAIN - Completed session expiration timeout in seconds
 */
#define RADIUS_SESSION_MAINTAIN 5

/**
 * RADIUS_MAX_SESSION - Maximum number of active sessions
 */
#define RADIUS_MAX_SESSION 1000

/**
 * RADIUS_MAX_MSG_LEN - Maximum message length for incoming RADIUS messages
 */
#define RADIUS_MAX_MSG_LEN 3000

// struct radius_server_data;


static void radius_server_session_timeout(void *eloop_ctx, void *timeout_ctx);
static void radius_server_session_remove_timeout(void *eloop_ctx,
						 void *timeout_ctx);

void srv_log(struct radius_session *sess, const char *fmt, ...)
PRINTF_FORMAT(2, 3);

void srv_log(struct radius_session *sess, const char *fmt, ...)
{
	va_list ap;
	char *buf;
	int buflen;

	va_start(ap, fmt);
	buflen = vsnprintf(NULL, 0, fmt, ap) + 1;
	va_end(ap);

	buf = os_malloc(buflen);
	if (buf == NULL)
		return;
	va_start(ap, fmt);
	vsnprintf(buf, buflen, fmt, ap);
	va_end(ap);

	log_trace("[0x%x %s] %s", sess->sess_id, sess->nas_ip, buf);

	os_free(buf);
}

void free_radius_attr(struct hostapd_radius_attr *attr)
{
	struct hostapd_radius_attr *prev;

	while (attr) {
		prev = attr;
		attr = attr->next;
		wpabuf_free(prev->val);
		os_free(prev);
	}
}

struct hostapd_radius_attr * get_password_attribute(const uint8_t *req_authenticator,
			     	const uint8_t *secret, size_t secret_len,
						const uint8_t *key, size_t key_len)
{
	struct hostapd_radius_attr *attr = NULL;
	uint16_t salt;
	size_t elen;
	uint8_t *buf, *pos;
	uint8_t tag_salt_len = 3;
	uint16_t packet_len = tag_salt_len + 1 + key_len + 15; //tag + salt + len + key_len + padding

	if (os_get_random((uint8_t *) &salt, sizeof(salt)) < 0) {
		log_trace("os_get_random fail");
		return NULL;
	}
	
	salt |= 0x8000;

	buf = os_malloc(packet_len);
	if (buf == NULL) {
		log_err("os_malloc");
		return 0;
	}

	pos = buf + 1;
	WPA_PUT_BE16(pos, salt);

	pos += 2;
	encrypt_ms_key(key, key_len, salt, req_authenticator, secret, secret_len, pos, &elen);

	attr = os_zalloc(sizeof(*attr));
	if (!attr) {
		log_err("os_zalloc");
		os_free(buf);
		return NULL;
	}

	attr->type = RADIUS_ATTR_TUNNEL_PASSWORD;
	attr->val = wpabuf_alloc_copy(buf, tag_salt_len + elen);

	os_free(buf);
	return attr;
}

struct hostapd_radius_attr * get_vlan_attribute(uint16_t vlan_id)
{
	char id_str[5];
	struct hostapd_radius_attr *attr, 
		*attr_medium_type, *attr_id;

#define RADIUS_ATTR_TUNNEL_VALUE 		13
#define RADIUS_ATTR_TUNNEL_MEDIUM_VALUE 6

	attr = os_zalloc(sizeof(*attr));
	if (!attr) {
		log_err("os_zalloc");
		return NULL;
	}

	attr->type = RADIUS_ATTR_TUNNEL_TYPE;
	attr->val = wpabuf_alloc(4);
	if (attr->val)
		wpabuf_put_be32(attr->val, RADIUS_ATTR_TUNNEL_VALUE);
	
	attr_medium_type = os_zalloc(sizeof(*attr_medium_type));
	if (!attr_medium_type) {
		log_err("os_zalloc");
		free_radius_attr(attr);
		return NULL;
	}
	attr_medium_type->type = RADIUS_ATTR_TUNNEL_MEDIUM_TYPE;
	attr_medium_type->val = wpabuf_alloc(4);
	if (attr_medium_type->val)
		wpabuf_put_be32(attr_medium_type->val, RADIUS_ATTR_TUNNEL_MEDIUM_VALUE);

	attr_id = os_zalloc(sizeof(*attr_id));
	if (!attr_id) {
		log_err("os_zalloc");
		free_radius_attr(attr);
		free_radius_attr(attr_medium_type);
		return NULL;
	}

	sprintf(id_str, "%d", vlan_id);
	attr_id->type = RADIUS_ATTR_TUNNEL_PRIVATE_GROUP_ID;
	attr_id->val = wpabuf_alloc_copy(id_str, strlen(id_str));

	attr->next = attr_medium_type;
	attr_medium_type->next = attr_id;
	attr_id->next = NULL;
	return attr;
}

static struct radius_client *
radius_server_get_client(struct radius_server_data *data, struct in_addr *addr)
{
	struct radius_client *client = data->clients;

	while (client) {
		if ((client->addr.s_addr & client->mask.s_addr) ==
		    (addr->s_addr & client->mask.s_addr)) {
			break;
		}

		client = client->next;
	}

	return client;
}


static struct radius_session *
radius_server_get_session(struct radius_client *client, unsigned int sess_id)
{
	struct radius_session *sess = client->sessions;

	while (sess) {
		if (sess->sess_id == sess_id) {
			break;
		}
		sess = sess->next;
	}

	return sess;
}


static void radius_server_session_free(struct radius_server_data *data,
				       struct radius_session *sess)
{
	eloop_cancel_timeout(radius_server_session_timeout, data, sess);
	eloop_cancel_timeout(radius_server_session_remove_timeout, data, sess);
	radius_msg_free(sess->last_msg);
	os_free(sess->last_from_addr);
	radius_msg_free(sess->last_reply);
	os_free(sess->username);
	os_free(sess->nas_ip);
	os_free(sess);
	if (data)
		data->num_sess--;
}


static void radius_server_session_remove(struct radius_server_data *data,
					 struct radius_session *sess)
{
	struct radius_client *client = sess->client;
	struct radius_session *session, *prev;

	eloop_cancel_timeout(radius_server_session_remove_timeout, data, sess);

	prev = NULL;
	session = client->sessions;
	while (session) {
		if (session == sess) {
			if (prev == NULL) {
				client->sessions = sess->next;
			} else {
				prev->next = sess->next;
			}
			radius_server_session_free(data, sess);
			break;
		}
		prev = session;
		session = session->next;
	}
}


static void radius_server_session_remove_timeout(void *eloop_ctx,
						 void *timeout_ctx)
{
	struct radius_server_data *data = eloop_ctx;
	struct radius_session *sess = timeout_ctx;
	log_trace("Removing completed session 0x%x", sess->sess_id);
	radius_server_session_remove(data, sess);
}


static void radius_server_session_timeout(void *eloop_ctx, void *timeout_ctx)
{
	struct radius_server_data *data = eloop_ctx;
	struct radius_session *sess = timeout_ctx;

	log_trace("Timing out authentication session 0x%x", sess->sess_id);
	radius_server_session_remove(data, sess);
}


static struct radius_session *
radius_server_new_session(struct radius_server_data *data,
			  struct radius_client *client)
{
	struct radius_session *sess;

	if (data->num_sess >= RADIUS_MAX_SESSION) {
		log_trace("Maximum number of existing session - no room for a new session");
		return NULL;
	}

	sess = os_zalloc(sizeof(*sess));
	if (sess == NULL)
		return NULL;

	sess->server = data;
	sess->client = client;
	sess->sess_id = data->next_sess_id++;
	sess->next = client->sessions;
	client->sessions = sess;
	eloop_register_timeout(RADIUS_SESSION_TIMEOUT, 0,
			       radius_server_session_timeout, data, sess);
	data->num_sess++;
	return sess;
}

static struct radius_session *
radius_server_get_new_session(struct radius_server_data *data,
			      struct radius_client *client,
			      struct radius_msg *msg, const char *from_addr)
{
	uint8_t *user, *id;
	size_t user_len, id_len;

	struct radius_session *sess;

	log_trace("Creating a new session");

	if (radius_msg_get_attr_ptr(msg, RADIUS_ATTR_USER_NAME, &user,
				    &user_len, NULL) < 0) {
		log_trace("Could not get User-Name");
		return NULL;
	}
	log_trace("User-Name length %ld", user_len);

	log_trace("Matching user entry found");
	sess = radius_server_new_session(data, client);
	if (sess == NULL) {
		log_trace("Failed to create a new session");
		return NULL;
	}

	sess->macacl = 1;
	sess->username = os_malloc(user_len * 4 + 1);
	if (sess->username == NULL) {
		radius_server_session_remove(data, sess);
		return NULL;
	}
	printf_encode(sess->username, user_len * 4 + 1, user, user_len);

	sess->nas_ip = os_strdup(from_addr);
	if (sess->nas_ip == NULL) {
		radius_server_session_remove(data, sess);
		return NULL;
	}

	if (radius_msg_get_attr_ptr(msg, RADIUS_ATTR_CALLING_STATION_ID, &id,
				    &id_len, NULL) == 0) {
		char buf[3 * ETH_ALEN];

		os_memset(buf, 0, sizeof(buf));
		if (id_len >= sizeof(buf))
			id_len = sizeof(buf) - 1;
		os_memcpy(buf, id, id_len);
		if (hwaddr_aton2(buf, sess->mac_addr) < 0)
			os_memset(sess->mac_addr, 0, ETH_ALEN);
		else
			log_trace("Calling-Station-Id: " MACSTR, MAC2STR(sess->mac_addr));
	}

	srv_log(sess, "New session created");

	log_trace("New session 0x%x initialized", sess->sess_id);

	return sess;
}

static struct radius_msg *
radius_server_macacl(struct radius_server_data *data,
		     struct radius_client *client,
		     struct radius_session *sess,
		     struct radius_msg *request)
{
	struct radius_msg *msg;
	int code;
	uint8_t *pw;
	size_t pw_len;
	struct hostapd_radius_attr *attr = NULL, *pass_attr = NULL;
	struct radius_hdr *hdr = radius_msg_get_hdr(request);
	struct mac_conn_info mac_conn = client->get_mac_conn(sess->mac_addr, client->mac_conn_arg);

	if (mac_conn.vlanid >= 0) {
		attr = get_vlan_attribute(mac_conn.vlanid);
		if (attr == NULL) {
			log_trace("Couldn't allocate attribute");
			return NULL;
		}

		pass_attr = get_password_attribute(hdr->authenticator,
			     	(uint8_t *) client->shared_secret, client->shared_secret_len,
						(uint8_t *) mac_conn.pass, (size_t) mac_conn.pass_len);

		if (pass_attr == NULL) {
			log_trace("Couldn't allocate attribute");
			free_radius_attr(attr);
			return NULL;
		}

		attr->next->next->next = pass_attr;
		pass_attr->next = NULL;

		code = RADIUS_CODE_ACCESS_ACCEPT;
	}	else {
		log_trace("RADIUS mac=" MACSTR " not accepted", MAC2STR(sess->mac_addr));
		code = RADIUS_CODE_ACCESS_REJECT;
	}

	if (radius_msg_get_attr_ptr(request, RADIUS_ATTR_USER_PASSWORD, &pw,
				    &pw_len, NULL) < 0) {
		log_trace("Could not get User-Password");
		code = RADIUS_CODE_ACCESS_REJECT;
	}

	msg = radius_msg_new(code, hdr->identifier);
	if (msg == NULL) {
		log_trace("Failed to allocate reply message");
		goto end;
	}

	if (radius_msg_copy_attr(msg, request, RADIUS_ATTR_PROXY_STATE) < 0) {
		log_trace("Failed to copy Proxy-State attribute(s)");
		radius_msg_free(msg);
		goto end;
	}

	if (code == RADIUS_CODE_ACCESS_ACCEPT) {
		struct hostapd_radius_attr *attr_iter;
		for (attr_iter = attr; attr_iter; attr_iter = attr_iter->next) {
			if (!radius_msg_add_attr(msg, attr_iter->type,
						 wpabuf_head(attr_iter->val),
						 wpabuf_len(attr_iter->val))) {
				log_trace("Could not add RADIUS attribute");
				radius_msg_free(msg);
				goto end;
			}
		}
	}

	if (radius_msg_finish_srv(msg, (uint8_t *) client->shared_secret,
				  client->shared_secret_len,
				  hdr->authenticator) < 0) {
		log_trace("Failed to add Message-Authenticator attribute");
	}

	if (attr != NULL)
		free_radius_attr(attr);
	return msg;

end:
	if (attr != NULL)
		free_radius_attr(attr);
	return NULL;	
}


static int radius_server_reject(struct radius_server_data *data,
				struct radius_client *client,
				struct radius_msg *request,
				struct sockaddr *from, socklen_t fromlen,
				const char *from_addr, int from_port)
{
	struct radius_msg *msg;
	int ret = 0;
	struct wpabuf *buf;
	struct radius_hdr *hdr = radius_msg_get_hdr(request);

	log_trace("Reject invalid request from %s:%d", from_addr, from_port);

	msg = radius_msg_new(RADIUS_CODE_ACCESS_REJECT, hdr->identifier);
	if (msg == NULL) {
		return -1;
	}

	if (radius_msg_copy_attr(msg, request, RADIUS_ATTR_PROXY_STATE) < 0) {
		log_trace("Failed to copy Proxy-State attribute(s)");
		radius_msg_free(msg);
		return -1;
	}

	if (radius_msg_finish_srv(msg, (uint8_t *) client->shared_secret,
				  client->shared_secret_len,
				  hdr->authenticator) <
	    0) {
		log_trace("Failed to add Message-Authenticator attribute");
	}

	radius_msg_dump(msg);

	data->counters.access_rejects++;
	client->counters.access_rejects++;
	buf = radius_msg_get_buf(msg);
	if (sendto(data->auth_sock, wpabuf_head(buf), wpabuf_len(buf), 0,
		   (struct sockaddr *) from, sizeof(*from)) < 0) {
		log_err("sendto[RADIUS SRV]");
		ret = -1;
	}

	radius_msg_free(msg);

	return ret;
}

static int radius_server_request(struct radius_server_data *data,
				 struct radius_msg *msg,
				 struct sockaddr *from, socklen_t fromlen,
				 struct radius_client *client,
				 const char *from_addr, int from_port,
				 struct radius_session *force_sess)
{
	int res, state_included = 0;
	uint8_t statebuf[4];
	unsigned int state;
	struct radius_session *sess;
	struct radius_msg *reply;
	int is_complete = 0;

	if (force_sess)
		sess = force_sess;
	else {
		res = radius_msg_get_attr(msg, RADIUS_ATTR_STATE, statebuf,
					  sizeof(statebuf));
		state_included = res >= 0;
		if (res == sizeof(statebuf)) {
			state = WPA_GET_BE32(statebuf);
			sess = radius_server_get_session(client, state);
		} else {
			sess = NULL;
		}
	}

	if (sess) {
		log_trace("Request for session 0x%x", sess->sess_id);
	} else if (state_included) {
		log_trace("State attribute included but no session found");
		radius_server_reject(data, client, msg, from, fromlen, from_addr, from_port);
		return -1;
	} else {
		sess = radius_server_get_new_session(data, client, msg, from_addr);
		if (sess == NULL) {
			log_trace("Could not create a new session");
			radius_server_reject(data, client, msg, from, fromlen, from_addr, from_port);
			return -1;
		}
	}

	if (sess->last_from_port == from_port &&
	    sess->last_identifier == radius_msg_get_hdr(msg)->identifier &&
	    os_memcmp(sess->last_authenticator,
		      radius_msg_get_hdr(msg)->authenticator, 16) == 0) {
		log_trace("Duplicate message from %s", from_addr);
		data->counters.dup_access_requests++;
		client->counters.dup_access_requests++;

		if (sess->last_reply) {
			struct wpabuf *buf;
			buf = radius_msg_get_buf(sess->last_reply);
			res = sendto(data->auth_sock, wpabuf_head(buf),
				     wpabuf_len(buf), 0,
				     (struct sockaddr *) from, fromlen);
			if (res < 0) {
				log_err("sendto[RADIUS SRV]");
			}
			return 0;
		}

		log_trace("No previous reply available for duplicate message");
		return -1;
	}

	reply = radius_server_macacl(data, client, sess, msg);
	if (reply == NULL) {
		log_trace("radius_server_macacl fail");
		return -1;
	}

send_reply:
	if (reply) {
		struct wpabuf *buf;
		struct radius_hdr *hdr;

		log_trace("Reply to %s:%d", from_addr, from_port);
		radius_msg_dump(reply);

		switch (radius_msg_get_hdr(reply)->code) {
		case RADIUS_CODE_ACCESS_ACCEPT:
			srv_log(sess, "Sending Access-Accept");
			data->counters.access_accepts++;
			client->counters.access_accepts++;
			break;
		case RADIUS_CODE_ACCESS_REJECT:
			srv_log(sess, "Sending Access-Reject");
			data->counters.access_rejects++;
			client->counters.access_rejects++;
			break;
		case RADIUS_CODE_ACCESS_CHALLENGE:
			data->counters.access_challenges++;
			client->counters.access_challenges++;
			break;
		}
		buf = radius_msg_get_buf(reply);
		res = sendto(data->auth_sock, wpabuf_head(buf),
			     wpabuf_len(buf), 0,
			     (struct sockaddr *) from, fromlen);
		if (res < 0) {
			log_err("sendto[RADIUS SRV]");
		}
		radius_msg_free(sess->last_reply);
		sess->last_reply = reply;
		sess->last_from_port = from_port;
		hdr = radius_msg_get_hdr(msg);
		sess->last_identifier = hdr->identifier;
		os_memcpy(sess->last_authenticator, hdr->authenticator, 16);
	} else {
		data->counters.packets_dropped++;
		client->counters.packets_dropped++;
	}

	if (is_complete) {
		log_trace("Removing completed session 0x%x after timeout", sess->sess_id);
		eloop_cancel_timeout(radius_server_session_remove_timeout,
				     data, sess);
		eloop_register_timeout(RADIUS_SESSION_MAINTAIN, 0,
				       radius_server_session_remove_timeout,
				       data, sess);
	}

	return 0;
}

static void radius_server_receive_auth(int sock, void *eloop_ctx,
				       void *sock_ctx)
{
	struct radius_server_data *data = eloop_ctx;
	uint8_t *buf = NULL;
	union {
		struct sockaddr_storage ss;
		struct sockaddr_in sin;
	} from;
	socklen_t fromlen;
	int len;
	struct radius_client *client = NULL;
	struct radius_msg *msg = NULL;
	char abuf[50];
	int from_port = 0;

	buf = os_malloc(RADIUS_MAX_MSG_LEN);
	if (buf == NULL) {
		goto fail;
	}

	fromlen = sizeof(from);
	len = recvfrom(sock, buf, RADIUS_MAX_MSG_LEN, 0,
		       (struct sockaddr *) &from.ss, &fromlen);
	if (len < 0) {
		log_err("recvfrom[radius_server]");
		goto fail;
	}

	os_strlcpy(abuf, inet_ntoa(from.sin.sin_addr), sizeof(abuf));
	from_port = ntohs(from.sin.sin_port);
	log_trace("Received %d bytes from %s:%d", len, abuf, from_port);

	client = radius_server_get_client(data, &from.sin.sin_addr);

	log_trace("Received data with length %ld", len);

	if (client == NULL) {
		log_trace("Unknown client %s - packet ignored", abuf);
		data->counters.invalid_requests++;
		goto fail;
	}

	msg = radius_msg_parse(buf, len);
	if (msg == NULL) {
		log_trace("Parsing incoming RADIUS frame failed");
		data->counters.malformed_access_requests++;
		client->counters.malformed_access_requests++;
		goto fail;
	}

	os_free(buf);
	buf = NULL;

	radius_msg_dump(msg);

	if (radius_msg_get_hdr(msg)->code != RADIUS_CODE_ACCESS_REQUEST) {
		log_trace("Unexpected RADIUS code %d", radius_msg_get_hdr(msg)->code);
		data->counters.unknown_types++;
		client->counters.unknown_types++;
		goto fail;
	}

	data->counters.access_requests++;
	client->counters.access_requests++;

	if (radius_msg_verify_msg_auth(msg, (uint8_t *) client->shared_secret,
				       client->shared_secret_len, NULL)) {
		log_trace("Invalid Message-Authenticator from %s", abuf);
		data->counters.bad_authenticators++;
		client->counters.bad_authenticators++;
		goto fail;
	}

	if (radius_server_request(data, msg, (struct sockaddr *) &from,
				  fromlen, client, abuf, from_port, NULL) ==
	    -2)
		return; /* msg was stored with the session */

fail:
	radius_msg_free(msg);
	os_free(buf);
}

static int radius_server_disable_pmtu_discovery(int s)
{
	int r = -1;
#if defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DONT)
	/* Turn off Path MTU discovery on IPv4/UDP sockets. */
	int action = IP_PMTUDISC_DONT;
	r = setsockopt(s, IPPROTO_IP, IP_MTU_DISCOVER, &action,
		       sizeof(action));
	if (r == -1)
		log_err("Failed to set IP_MTU_DISCOVER:");
#endif
	return r;
}


static int radius_server_open_socket(int port)
{
	int s;
	struct sockaddr_in addr;

	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		log_trace("RADIUS: socket");
		return -1;
	}

	radius_server_disable_pmtu_discovery(s);

	os_memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	if (bind(s, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		log_err("RADIUS: bind");
		close(s);
		return -1;
	}

	return s;
}

static void radius_server_free_sessions(struct radius_server_data *data,
					struct radius_session *sessions)
{
	struct radius_session *session, *prev;

	session = sessions;
	while (session) {
		prev = session;
		session = session->next;
		radius_server_session_free(data, prev);
	}
}


void radius_server_free_clients(struct radius_server_data *data,
				       struct radius_client *clients)
{
	struct radius_client *client, *prev;

	client = clients;
	while (client) {
		prev = client;
		client = client->next;

		radius_server_free_sessions(data, prev->sessions);
		os_free(prev->shared_secret);
		os_free(prev);
	}
}

struct radius_client *init_radius_client(struct radius_conf *conf,
	struct mac_conn_info (*get_mac_conn)(uint8_t mac_addr[], void *mac_conn_arg),
	void *mac_conn_arg)
{
	struct radius_client *entry;
	struct in_addr addr;
	unsigned int val = 0;

	if (inet_aton(conf->radius_client_ip, &addr) == 0) {
		log_trace("Invalid radius client ip address");
		return NULL;
	}

	entry = os_zalloc(sizeof(*entry));
	if (entry == NULL) {
		log_err("os_zalloc");
		return NULL;
	}

	entry->shared_secret = os_strdup(conf->radius_secret);
	if (entry->shared_secret == NULL) {
		log_err("os_strdup");
		os_free(entry);
		return NULL;
	}

	entry->shared_secret_len = strlen(entry->shared_secret);
	entry->addr.s_addr = addr.s_addr;
	for (int i = 0; i < conf->radius_client_mask; i++)
		val |= 1U << (31 - i);
	entry->mask.s_addr = htonl(val);

	entry->get_mac_conn = get_mac_conn;
	entry->mac_conn_arg = mac_conn_arg;
	return entry;
}

/**
 * radius_server_init - Initialize RADIUS server
 * @conf: Configuration for the RADIUS server
 * Returns: Pointer to private RADIUS server context or %NULL on failure
 *
 * This initializes a RADIUS server instance and returns a context pointer that
 * will be used in other calls to the RADIUS server module. The server can be
 * deinitialize by calling radius_server_deinit().
 */
struct radius_server_data *radius_server_init(int auth_port, struct radius_client *clients)
{
	struct radius_server_data *data;

	data = os_zalloc(sizeof(*data));
	if (data == NULL)
		return NULL;

	data->auth_sock = -1;
	os_get_reltime(&data->start_time);

	data->clients = clients;
	if (data->clients == NULL) {
		log_trace("No RADIUS clients configured");
		goto fail;
	}

	data->auth_sock = radius_server_open_socket(auth_port);
	if (data->auth_sock < 0) {
		log_trace("Failed to open UDP socket for RADIUS authentication server");
		goto fail;
	}
	if (eloop_register_read_sock(data->auth_sock, radius_server_receive_auth, data, NULL)) {
		goto fail;
	}

	return data;
fail:
	radius_server_deinit(data);
	return NULL;
}

/**
 * radius_server_deinit - Deinitialize RADIUS server
 * @data: RADIUS server context from radius_server_init()
 */
void radius_server_deinit(struct radius_server_data *data)
{
	if (data == NULL)
		return;

	if (data->auth_sock >= 0) {
		eloop_unregister_read_sock(data->auth_sock);
		close(data->auth_sock);
	}

	radius_server_free_clients(data, data->clients);

	os_free(data);
}


/**
 * radius_server_get_mib - Get RADIUS server MIB information
 * @data: RADIUS server context from radius_server_init()
 * @buf: Buffer for returning the MIB data in text format
 * @buflen: buf length in octets
 * Returns: Number of octets written into buf
 */
int radius_server_get_mib(struct radius_server_data *data, char *buf,
			  size_t buflen)
{
	int ret, uptime;
	unsigned int idx;
	char *end, *pos;
	struct os_reltime now;
	struct radius_client *cli;

	/* RFC 2619 - RADIUS Authentication Server MIB */

	if (data == NULL || buflen == 0)
		return 0;

	pos = buf;
	end = buf + buflen;

	os_get_reltime(&now);
	uptime = (now.sec - data->start_time.sec) * 100 +
		((now.usec - data->start_time.usec) / 10000) % 100;
	ret = snprintf(pos, end - pos,
			  "RADIUS-AUTH-SERVER-MIB\n"
			  "radiusAuthServIdent=hostapd\n"
			  "radiusAuthServUpTime=%d\n"
			  "radiusAuthServResetTime=0\n"
			  "radiusAuthServConfigReset=4\n",
			  uptime);
	if (snprintf_error(end - pos, ret)) {
		*pos = '\0';
		return pos - buf;
	}
	pos += ret;

	ret = snprintf(pos, end - pos,
			  "radiusAuthServTotalAccessRequests=%u\n"
			  "radiusAuthServTotalInvalidRequests=%u\n"
			  "radiusAuthServTotalDupAccessRequests=%u\n"
			  "radiusAuthServTotalAccessAccepts=%u\n"
			  "radiusAuthServTotalAccessRejects=%u\n"
			  "radiusAuthServTotalAccessChallenges=%u\n"
			  "radiusAuthServTotalMalformedAccessRequests=%u\n"
			  "radiusAuthServTotalBadAuthenticators=%u\n"
			  "radiusAuthServTotalPacketsDropped=%u\n"
			  "radiusAuthServTotalUnknownTypes=%u\n",
			  data->counters.access_requests,
			  data->counters.invalid_requests,
			  data->counters.dup_access_requests,
			  data->counters.access_accepts,
			  data->counters.access_rejects,
			  data->counters.access_challenges,
			  data->counters.malformed_access_requests,
			  data->counters.bad_authenticators,
			  data->counters.packets_dropped,
			  data->counters.unknown_types);
	if (snprintf_error(end - pos, ret)) {
		*pos = '\0';
		return pos - buf;
	}
	pos += ret;

	for (cli = data->clients, idx = 0; cli; cli = cli->next, idx++) {
		char abuf[50], mbuf[50];
		os_strlcpy(abuf, inet_ntoa(cli->addr), sizeof(abuf));
		os_strlcpy(mbuf, inet_ntoa(cli->mask), sizeof(mbuf));

		ret = snprintf(pos, end - pos,
				  "radiusAuthClientIndex=%u\n"
				  "radiusAuthClientAddress=%s/%s\n"
				  "radiusAuthServAccessRequests=%u\n"
				  "radiusAuthServDupAccessRequests=%u\n"
				  "radiusAuthServAccessAccepts=%u\n"
				  "radiusAuthServAccessRejects=%u\n"
				  "radiusAuthServAccessChallenges=%u\n"
				  "radiusAuthServMalformedAccessRequests=%u\n"
				  "radiusAuthServBadAuthenticators=%u\n"
				  "radiusAuthServPacketsDropped=%u\n"
				  "radiusAuthServUnknownTypes=%u\n",
				  idx,
				  abuf, mbuf,
				  cli->counters.access_requests,
				  cli->counters.dup_access_requests,
				  cli->counters.access_accepts,
				  cli->counters.access_rejects,
				  cli->counters.access_challenges,
				  cli->counters.malformed_access_requests,
				  cli->counters.bad_authenticators,
				  cli->counters.packets_dropped,
				  cli->counters.unknown_types);
		if (snprintf_error(end - pos, ret)) {
			*pos = '\0';
			return pos - buf;
		}
		pos += ret;
	}

	return pos - buf;
}
