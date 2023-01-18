/*
 * Example application using RADIUS client as a library
 * Copyright (c) 2007, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <cmocka.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <eloop.h>
#include "radius/radius.h"
#include "radius/radius_service.h"
#include "radius/radius_config.h"
#include "utils/allocs.h"
#include "utils/log.h"
#include "utils/os.h"

#include "radius_client.h"

#include "supervisor/mac_mapper.h"

#define VLAN_ID 34
static char *test_radius_conf_file = "/tmp/test-radius.conf";

static uint8_t addr[6] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};

static struct eloop_data *eloop = NULL;

struct radius_test_ctx {
  struct radius_client_data *radius;
  struct hostapd_radius_servers conf;
  uint8_t radius_identifier;
  struct in_addr own_ip_addr;
  uint8_t code;
  int untagged;
  int tagged[2];
};

struct mac_conn_info get_mac_conn(const uint8_t *identity, size_t identity_len,
                                  void *mac_conn_arg, struct radius_identity_info *iinfo) {
  (void)identity;
  (void)identity_len;
  (void)mac_conn_arg;
  (void)iinfo;

  struct mac_conn_info info = {.vlanid = VLAN_ID};
  log_trace("RADIUS requested mac=%.*s", identity_len, identity);
  return info;
}

/* Process the RADIUS frames from Authentication Server */
static RadiusRxResult receive_auth(struct radius_msg *msg,
                                   struct radius_msg *req,
                                   const uint8_t *shared_secret,
                                   size_t shared_secret_len, void *data) {
  (void)req;
  (void)shared_secret;
  (void)shared_secret_len;
  (void)data;

  struct radius_test_ctx *ctx = data;
  ctx->code = radius_msg_get_hdr(msg)->code;
  radius_msg_get_vlanid(msg, &ctx->untagged, 1,
                          ctx->tagged);
  log_trace("Received RADIUS Authentication message; code=%d", ctx->code);

  /* We're done for this example, so request eloop to terminate. */
  eloop_terminate(eloop);

  return RADIUS_RX_PROCESSED;
}

static void start_test(void *eloop_ctx, void *timeout_ctx) {
  (void)timeout_ctx;

  struct radius_test_ctx *ctx = eloop_ctx;
  struct radius_msg *msg;

  char buf[20];

  log_trace("Sending a RADIUS authentication message");

  ctx->radius_identifier = radius_client_get_id(ctx->radius);
  msg = radius_msg_new(RADIUS_CODE_ACCESS_REQUEST, ctx->radius_identifier);
  if (msg == NULL) {
    log_trace("Could not create net RADIUS packet");
    return;
  }

  radius_msg_make_authenticator(msg);

  sprintf(buf, "%02x%02x%02x%02x%02x%02x", MAC2STR(addr));
  if (!radius_msg_add_attr(msg, RADIUS_ATTR_USER_NAME, (uint8_t *)buf,
                           strlen(buf))) {
    log_trace("Could not add User-Name");
    radius_msg_free(msg);
    return;
  }

  sprintf(buf, "%02X-%02X-%02X-%02X-%02X-%02x", MAC2STR(addr));
  if (!radius_msg_add_attr(msg, RADIUS_ATTR_CALLING_STATION_ID, (uint8_t *)buf,
                           strlen(buf))) {
    log_trace("Could not add Calling-Station-Id");
    radius_msg_free(msg);
    return;
  }

  char user_password[COMPACT_MACSTR_LEN];
  sprintf(user_password, COMPACT_MACSTR, MAC2STR(addr));
  if (!radius_msg_add_attr_user_password(
          msg, (uint8_t *)user_password, strlen(user_password), ctx->conf.auth_server->shared_secret,
          ctx->conf.auth_server->shared_secret_len)) {
    log_trace("Could not add User-Password");
    radius_msg_free(msg);
    return;
  }

  if (!radius_msg_add_attr(msg, RADIUS_ATTR_NAS_IP_ADDRESS,
                           (uint8_t *)&ctx->own_ip_addr, 4)) {
    log_trace("Could not add NAS-IP-Address");
    radius_msg_free(msg);
    return;
  }

  if (radius_client_send(ctx->radius, msg, RADIUS_AUTH, addr) < 0) {
    radius_msg_free(msg);
    return;
  }
}

static void test_radius_server_init(void **state) {
  (void)state; /* unused */

  struct radius_conf rconf;
  os_memset(&rconf, 0, sizeof(struct radius_conf));

  strcpy(rconf.client_conf_path, test_radius_conf_file);

  strcpy(rconf.eap_ca_cert_path, EAP_TEST_DIR "ca.pem");
  strcpy(rconf.eap_server_cert_path, EAP_TEST_DIR "server.pem");
  strcpy(rconf.eap_server_key_path, EAP_TEST_DIR "server.key");
  strcpy(rconf.eap_dh_path, EAP_TEST_DIR "dh.pem");

  strcpy(rconf.radius_client_ip, "127.0.0.1");
  strcpy(rconf.radius_server_ip, "127.0.0.1");
  rconf.radius_client_mask = 32;
  rconf.radius_server_mask = 32;
  strcpy(rconf.radius_secret, "radius");
  rconf.radius_port = 12345;

  struct radius_test_ctx ctx;
  os_memset(&ctx, 0, sizeof(struct radius_test_ctx));

  inet_aton(rconf.radius_client_ip, &ctx.own_ip_addr);

  eloop = eloop_init();
  assert_non_null(eloop);

  struct hostapd_radius_server *srv;
  srv = os_zalloc(sizeof(*srv));
  assert_non_null(srv);

  srv->addr.af = AF_INET;
  srv->port = rconf.radius_port;
  int ret = (hostapd_parse_ip_addr(rconf.radius_client_ip, &srv->addr) >= 0);
  assert_true(ret);

  srv->shared_secret = (uint8_t *)strdup(rconf.radius_secret);
  srv->shared_secret_len = strlen(rconf.radius_secret);

  ctx.conf.auth_server = ctx.conf.auth_servers = srv;
  ctx.conf.num_auth_servers = 1;
  ctx.conf.msg_dumps = 1;

  ctx.radius = radius_client_init(eloop, &ctx, &ctx.conf);
  assert_non_null(ctx.radius);

  ret = radius_client_register(ctx.radius, RADIUS_AUTH, receive_auth, &ctx);
  assert_int_equal(ret, 0);

  struct radius_context *radius_srv_ctx = run_radius(eloop, &rconf, get_mac_conn, NULL);
  assert_non_null(radius_srv_ctx);

  eloop_register_timeout(eloop, 0, 0, start_test, &ctx, NULL);

  eloop_run(eloop);

  assert_int_equal(ctx.code, RADIUS_CODE_ACCESS_ACCEPT);
  assert_int_equal(ctx.untagged, VLAN_ID);

  radius_client_deinit(ctx.radius);
  close_radius(radius_srv_ctx);
  os_free(srv->shared_secret);
  os_free(srv);

  eloop_free(eloop);
}

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  log_set_quiet(false);

  const struct CMUnitTest tests[] = {cmocka_unit_test(test_radius_server_init)};

  return cmocka_run_group_tests(tests, NULL, NULL);
}
