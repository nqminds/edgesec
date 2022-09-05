/*
 * Example application using RADIUS client as a library
 * Copyright (c) 2007, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>

#include <setjmp.h>
#include <cmocka.h>

#include "utils/eloop.h"
#include "utils/allocs.h"
#include "utils/os.h"
#include "utils/log.h"
#include "radius/radius.h"
#include "radius/radius_server.h"

#include "radius_client.h"

#include "supervisor/mac_mapper.h"

static uint8_t addr[6] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
static uint8_t saved_addr[6];

static struct eloop_data *eloop = NULL;

struct radius_ctx {
  struct radius_client_data *radius;
  struct hostapd_radius_servers conf;
  uint8_t radius_identifier;
  struct in_addr own_ip_addr;
};

struct mac_conn_info get_mac_conn(uint8_t mac_addr[], void *mac_conn_arg) {
  (void)mac_conn_arg;

  struct mac_conn_info info = {.vlanid = 0};
  log_trace("RADIUS requested mac=%02x:%02x:%02x:%02x:%02x:%02x",
            MAC2STR(mac_addr));
  memcpy(saved_addr, mac_addr, 6);
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

  /* struct radius_ctx *ctx = data; */
  log_trace("Received RADIUS Authentication message; code=%d",
            radius_msg_get_hdr(msg)->code);

  /* We're done for this example, so request eloop to terminate. */
  eloop_terminate(eloop);

  return RADIUS_RX_PROCESSED;
}

static void start_test(void *eloop_ctx, void *timeout_ctx) {
  (void)timeout_ctx;

  struct radius_ctx *ctx = eloop_ctx;
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

  if (!radius_msg_add_attr_user_password(
          msg, (uint8_t *)"radius", 6, ctx->conf.auth_server->shared_secret,
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

  if (radius_client_send(ctx->radius, msg, RADIUS_AUTH, addr) < 0)
    radius_msg_free(msg);
}

static void test_radius_server_init(void **state) {
  (void)state; /* unused */

  struct radius_ctx ctx;
  struct hostapd_radius_server *srv = NULL;
  struct radius_conf conf;

  os_memset(&ctx, 0, sizeof(struct radius_ctx));
  os_memset(&conf, 0, sizeof(struct radius_conf));

  strcpy(conf.radius_client_ip, "127.0.0.1");
  conf.radius_client_mask = 32;
  strcpy(conf.radius_secret, "radius");

  struct radius_client *client = init_radius_client(&conf, get_mac_conn, NULL);
  struct radius_server_data *radius_srv = NULL;

  log_set_level(0);

  inet_aton(conf.radius_client_ip, &ctx.own_ip_addr);

  eloop = eloop_init();
  assert_non_null(eloop);

  srv = os_zalloc(sizeof(*srv));
  assert_non_null(srv);

  srv->addr.af = AF_INET;
  srv->port = 12345;
  int ret = (hostapd_parse_ip_addr(conf.radius_client_ip, &srv->addr) >= 0);
  assert_true(ret);

  srv->shared_secret = (uint8_t *)strdup(conf.radius_secret);
  srv->shared_secret_len = strlen(conf.radius_secret);

  ctx.conf.auth_server = ctx.conf.auth_servers = srv;
  ctx.conf.num_auth_servers = 1;
  ctx.conf.msg_dumps = 1;

  ctx.radius = radius_client_init(eloop, &ctx, &ctx.conf);
  assert_non_null(ctx.radius);

  ret = radius_client_register(ctx.radius, RADIUS_AUTH, receive_auth, &ctx);
  assert_int_equal(ret, 0);

  radius_srv = radius_server_init(eloop, srv->port, client);
  assert_non_null(radius_srv);

  eloop_register_timeout(eloop, 0, 0, start_test, &ctx, NULL);

  eloop_run(eloop);

  int cmp = memcmp(&saved_addr[0], &addr[0], 6);
  assert_int_equal(cmp, 0);

  radius_client_deinit(ctx.radius);
  radius_server_deinit(radius_srv);
  os_free(srv->shared_secret);
  os_free(srv);

  eloop_free(eloop);
}

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  log_set_quiet(true);

  const struct CMUnitTest tests[] = {cmocka_unit_test(test_radius_server_init)};

  return cmocka_run_group_tests(tests, NULL, NULL);
}
