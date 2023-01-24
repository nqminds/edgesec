#define _GNU_SOURCE

#include <setjmp.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <cmocka.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "config.h"
#include "runctl.h"

#include "ap/ap_service.h"
#include "radius/radius.h"
#include "radius/radius_client.h"
#include "supervisor/cmd_processor.h"
#include "supervisor/system_commands.h"
#include "utils/sockctl.h"

#define AP_CTRL_IFACE_PATH "/tmp/wifi0"
#define SUPERVISOR_CONTROL_PATH "/tmp/test-edgesec-control-server"

pthread_mutex_t log_lock;

void log_lock_fun(bool lock) {
  if (lock) {
    pthread_mutex_lock(&log_lock);
  } else {
    pthread_mutex_unlock(&log_lock);
  }
}

void ap_eloop(int sock, void *eloop_ctx, void *sock_ctx) {
  (void)eloop_ctx;
  (void)sock_ctx;

  uint32_t bytes_available = 0;

  assert_int_not_equal(ioctl(sock, FIONREAD, &bytes_available), -1);

  char *buf = os_malloc(bytes_available);

  struct client_address addr = {.type = SOCKET_TYPE_DOMAIN};
  read_socket_data(sock, buf, bytes_available, &addr, 0);

  if (strcmp(buf, PING_AP_COMMAND) == 0) {
    write_socket_data(sock, PING_AP_COMMAND_REPLY,
                      ARRAY_SIZE(PING_AP_COMMAND_REPLY), &addr);
  } else if (strcmp(buf, ATTACH_AP_COMMAND) == 0) {
    log_trace("RECEIVED ATTACH");
  } else {
    fail_msg("Uknown AP command received %s", buf);
  }
  os_free(buf);
}

void *ap_server_thread(void *arg) {
  struct eloop_data *eloop = (struct eloop_data *)arg;

  int fd = create_domain_server(AP_CTRL_IFACE_PATH);

  assert_int_not_equal(fd, -1);

  assert_int_not_equal(
      eloop_register_read_sock(eloop, fd, ap_eloop, (void *)eloop, NULL), -1);

  eloop_run(eloop);
  log_trace("AP server thread end");
  assert_int_equal(close_domain_socket(fd), 0);
  return NULL;
}

/* Process the RADIUS frames from Authentication Server */
static RadiusRxResult receive_auth(struct radius_msg *msg,
                                   struct radius_msg *req,
                                   const uint8_t *shared_secret,
                                   size_t shared_secret_len, void *data) {
  (void)req;
  (void)shared_secret;
  (void)shared_secret_len;
  struct eloop_data *eloop = (struct eloop_data *)data;

  uint8_t code = radius_msg_get_hdr(msg)->code;
  log_trace("Received RADIUS Authentication message; code=%d",
            radius_msg_get_hdr(msg)->code);
  assert_int_equal(code, RADIUS_CODE_ACCESS_ACCEPT);
  /* We're done for this example, so request eloop to terminate. */
  eloop_terminate(eloop);

  return RADIUS_RX_PROCESSED;
}

void *supervisor_client_thread(void *arg) {
  (void)arg;
  char socket_path[MAX_OS_PATH_LEN];
  char ping_reply[] = PING_REPLY;
  rtrim(ping_reply, NULL);
  strcpy(socket_path, SUPERVISOR_CONTROL_PATH);
  struct eloop_data *main_eloop = (struct eloop_data *)arg;

  int count = 10;
  char *reply = NULL;
  while (count--) {
    writeread_domain_data_str(socket_path, CMD_PING, &reply);
    if (reply != NULL) {
      if (strcmp(reply, ping_reply) == 0) {
        os_free(reply);
        break;
      }
    }
    sleep(1);
  }

  if (!count) {
    fail_msg("Couldn't ping supervisor");
  }

  struct radius_conf conf = {
      .radius_client_mask = 32,
      .radius_client_ip = "127.0.0.1",
      .radius_secret = "radius",
  };

  struct in_addr own_ip_addr;
  inet_aton(conf.radius_client_ip, &own_ip_addr);

  struct hostapd_radius_server server = {.addr = {.af = AF_INET},
                                         .port = 54321};
  int ret = (hostapd_parse_ip_addr(conf.radius_client_ip, &server.addr) >= 0);
  assert_true(ret);

  server.shared_secret = (uint8_t *)strdup(conf.radius_secret);
  server.shared_secret_len = strlen(conf.radius_secret);

  struct hostapd_radius_servers servers = {.auth_server = &server,
                                           .auth_servers = &server,
                                           .num_auth_servers = 1,
                                           .msg_dumps = 1};

  struct eloop_data *eloop = eloop_init();
  struct radius_client_data *radius =
      radius_client_init(eloop, /*ctx*/ eloop, &servers);
  assert_non_null(radius);

  ret =
      radius_client_register(radius, RADIUS_AUTH, receive_auth, /*ctx*/ eloop);
  assert_int_equal(ret, 0);

  char buf[20];
  uint8_t addr[6] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
  log_trace("Sending a RADIUS authentication message");

  uint8_t radius_identifier = radius_client_get_id(radius);
  struct radius_msg *msg =
      radius_msg_new(RADIUS_CODE_ACCESS_REQUEST, radius_identifier);
  assert_non_null(msg);

  radius_msg_make_authenticator(msg);

  sprintf(buf, "%02x%02x%02x%02x%02x%02x", MAC2STR(addr));
  assert_non_null(radius_msg_add_attr(msg, RADIUS_ATTR_USER_NAME,
                                      (uint8_t *)buf, strlen(buf)));

  sprintf(buf, "%02X-%02X-%02X-%02X-%02X-%02x", MAC2STR(addr));
  assert_non_null(radius_msg_add_attr(msg, RADIUS_ATTR_CALLING_STATION_ID,
                                      (uint8_t *)buf, strlen(buf)));

  char user_password[COMPACT_MACSTR_LEN];
  sprintf(user_password, COMPACT_MACSTR, MAC2STR(addr));

  assert_non_null(radius_msg_add_attr_user_password(
      msg, (uint8_t *)user_password, strlen(user_password),
      server.shared_secret, server.shared_secret_len));

  assert_non_null(radius_msg_add_attr(msg, RADIUS_ATTR_NAS_IP_ADDRESS,
                                      (uint8_t *)&own_ip_addr, 4));

  assert_int_not_equal(radius_client_send(radius, msg, RADIUS_AUTH, addr), -1);

  eloop_run(eloop);
  eloop_free(eloop);

  char command[128];
  snprintf(command, 128, "%s 00:01:02:03:04:05", CMD_GET_MAP);
  writeread_domain_data_str(socket_path, command, &reply);
  if (reply != NULL) {
    if (strstr(reply, "a,00:01:02:03:04:05,,,2,1,,") == NULL) {
      fail_msg("Wrong GET_MAP command reply");
    }
    os_free(reply);
  }

  eloop_terminate(main_eloop);

  // Send a PING command to terminate the eloop
  writeread_domain_data_str(socket_path, CMD_PING, &reply);
  if (reply != NULL) {
    os_free(reply);
  }

  return NULL;
}

/**
 * @brief Performs an integration test on edgesec
 */
static void test_edgesec(void **state) {
  (void)state; /* unused */

  struct app_config config = {0};

  assert_int_equal(load_app_config(TEST_CONFIG_INI_PATH, &config), 0);

#ifdef WITH_CRYPTO_SERVICE
  sys_strlcpy(config.crypt_secret, "test", MAX_USER_SECRET);
#endif

  os_init_random_seed();

  struct eloop_data *main_eloop = eloop_init();

  pthread_t ap_id = 0;
  struct eloop_data *ap_eloop = eloop_init();
  assert_int_equal(
      pthread_create(&ap_id, NULL, ap_server_thread, (void *)ap_eloop), 0);

  pthread_t supervisor_id = 0;
  assert_int_equal(pthread_create(&supervisor_id, NULL,
                                  supervisor_client_thread, (void *)main_eloop),
                   0);

  assert_int_equal(run_ctl(&config, main_eloop), 0);

  eloop_terminate(ap_eloop);

  eloop_free(ap_eloop);
  free_app_config(&config);
  pthread_mutex_destroy(&log_lock);
}

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  log_set_quiet(false);
  log_set_lock(log_lock_fun);

  const struct CMUnitTest tests[] = {cmocka_unit_test(test_edgesec)};

  return cmocka_run_group_tests(tests, NULL, NULL);
}
