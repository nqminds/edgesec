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
#include <signal.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdatomic.h>
#include <errno.h>
#include <threads.h>

#include "config.h"
#include "runctl.h"

#include "ap/ap_service.h"
#include "radius/radius.h"
#include "radius/radius_client.h"
#include "supervisor/cmd_processor.h"
#include "supervisor/system_commands.h"
#include "utils/attributes.h"
#include "utils/sockctl.h"

#define AP_CTRL_IFACE_PATH "/tmp/wifi0"
#define SUPERVISOR_CONTROL_PATH "/tmp/edgesec-control-server"

static mtx_t log_lock;

void log_lock_fun(bool lock) {
  if (lock) {
    mtx_lock(&log_lock);
  } else {
    mtx_unlock(&log_lock);
  }
}

/** Stores information about a thread that is running an eloop */
struct thread_context {
  struct eloop_data *eloop;
  thrd_t thread;
  /** Set this to `true` to stop the eloop from a different thread */
  atomic_bool should_die;
  char error_message[512];
  /**
   * Set to `true` if you want teardown_edgesec_test() to join
   * your thread (i.e. if you've haven't joined it in your CMocka test)
   */
  bool cleanup_thread;
};

void ap_eloop(int sock, __maybe_unused void *eloop_ctx, void *sock_ctx) {
  struct thread_context *thread_context = sock_ctx;
  uint32_t bytes_available = 0;

  assert_int_not_equal(ioctl(sock, FIONREAD, &bytes_available), -1);

  // allocate an extra byte, just in case the string isn't NUL-terminated
  char *buf = os_malloc(bytes_available + 1);
  buf[bytes_available] = '\0';

  struct client_address addr = {.type = SOCKET_TYPE_DOMAIN};
  read_socket_data(sock, buf, bytes_available, &addr, 0);

  if (strcmp(buf, PING_AP_COMMAND) == 0) {
    write_socket_data(sock, PING_AP_COMMAND_REPLY,
                      ARRAY_SIZE(PING_AP_COMMAND_REPLY), &addr);
  } else if (strcmp(buf, ATTACH_AP_COMMAND) == 0) {
    log_trace("RECEIVED ATTACH");
  } else {
    snprintf(thread_context->error_message,
             sizeof(thread_context->error_message) - 1, "Unknown command: %s",
             buf);
    os_free(buf);
    log_error("%s", thread_context->error_message);
    thrd_exit(EXIT_FAILURE);
  }
  os_free(buf);
}

int ap_server_thread(void *arg) {
  struct thread_context *thread_context = arg;
  struct eloop_data *eloop = thread_context->eloop;

  int fd = create_domain_server(AP_CTRL_IFACE_PATH);

  assert_int_not_equal(fd, -1);

  assert_int_not_equal(
      edge_eloop_register_read_sock(eloop, fd, ap_eloop, NULL, thread_context),
      -1);

  edge_eloop_run(eloop);
  log_trace("AP server thread end");
  assert_int_equal(close_domain_socket(fd), 0);
  return 0;
}

/* Process the RADIUS frames from Authentication Server */
static RadiusRxResult receive_auth(struct radius_msg *msg,
                                   __maybe_unused struct radius_msg *req,
                                   __maybe_unused const uint8_t *shared_secret,
                                   __maybe_unused size_t shared_secret_len,
                                   void *data) {
  struct eloop_data *eloop = (struct eloop_data *)data;

  log_trace("Received RADIUS Authentication message; code=%d",
            radius_msg_get_hdr(msg)->code);

  /* We're done for this example, so request eloop to terminate. */
  edge_eloop_terminate(eloop);

  return RADIUS_RX_PROCESSED;
}

int supervisor_client_thread(void *arg) {
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

  struct eloop_data *eloop = edge_eloop_init();
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

  assert_non_null(radius_msg_add_attr_user_password(msg, (uint8_t *)"radius", 6,
                                                    server.shared_secret,
                                                    server.shared_secret_len));

  assert_non_null(radius_msg_add_attr(msg, RADIUS_ATTR_NAS_IP_ADDRESS,
                                      (uint8_t *)&own_ip_addr, 4));

  assert_int_not_equal(radius_client_send(radius, msg, RADIUS_AUTH, addr), -1);

  edge_eloop_run(eloop);

  char command[128];
  snprintf(command, 128, "%s 00:01:02:03:04:05", CMD_GET_MAP);
  writeread_domain_data_str(socket_path, command, &reply);
  if (reply != NULL) {
    if (strstr(reply, "a,00:01:02:03:04:05,,,2,1,,") == NULL) {
      fail_msg("Wrong GET_MAP commadn reply");
    }
    os_free(reply);
  }

  edge_eloop_terminate(main_eloop);

  // Send a PING command to terminate the eloop
  writeread_domain_data_str(socket_path, CMD_PING, &reply);
  if (reply != NULL) {
    os_free(reply);
  }

  return 0;
}

/**
 * Terminates the current eloop if `should_die` is true.
 *
 * Otherwise, run this function again in 10ms.
 *
 * Our eloop implementation can only be terminated from within the eloop.
 * (e.g. calling `edge_eloop_terminate()` from another thread does nothing)
 * Therefore, this function runs every 10ms, and checks whether the given atomic
 * is `true`, and then stops the eloop for us.
 *
 * @param[in] eloop_ctx - Current eloop context.
 * @param[in] user_ctx - Pointer to a @c atomic_bool, which if `true`,
 * terminates the eloop.
 */
void check_if_should_terminate(void *eloop_ctx, void *user_ctx) {
  struct eloop_data *eloop = eloop_ctx;
  atomic_bool *should_die = user_ctx;
  if (*should_die) {
    edge_eloop_terminate(eloop);
  } else {
    edge_eloop_register_timeout(eloop, 0, 10000, check_if_should_terminate,
                                eloop, should_die);
  }
}

struct edgesec_test_context {
  struct thread_context ap_server;
  struct thread_context supervisor;
};

static int setup_edgesec_test(void **state) {
  struct edgesec_test_context *ctx =
      calloc(1, sizeof(struct edgesec_test_context));
  assert_non_null(ctx);

  *ctx = (struct edgesec_test_context){
      .ap_server =
          {
              .eloop = edge_eloop_init(),
              .should_die = false,
          },
      .supervisor =
          {
              .eloop = edge_eloop_init(),
              .should_die = false,
          },
  };

  assert_non_null(ctx->ap_server.eloop);
  assert_non_null(ctx->supervisor.eloop);

  assert_return_code(edge_eloop_register_timeout(ctx->ap_server.eloop, 0, 10000,
                                                 check_if_should_terminate,
                                                 ctx->ap_server.eloop,
                                                 &(ctx->ap_server.should_die)),
                     0);

  assert_return_code(edge_eloop_register_timeout(
                         ctx->supervisor.eloop, 0, 10000,
                         check_if_should_terminate, ctx->ap_server.eloop,
                         &(ctx->supervisor.should_die)),
                     0);

  *state = ctx;
  return 0;
}

static int teardown_edgesec_test(void **state) {
  struct edgesec_test_context *ctx = *state;

  int ap_server_thread_rc = 0;
  int supervisor_thread_rc = 0;

  if (ctx != NULL) {
    ctx->ap_server.should_die = true;
    ctx->supervisor.should_die = true;
    // don't free supervisor eloop, since it's freed by run_ctl() already

    if (ctx->ap_server.cleanup_thread) {
      log_info("Waiting for AP Server thread to finish");
      thrd_join(ctx->ap_server.thread, &ap_server_thread_rc);
    }

    if (ctx->supervisor.cleanup_thread) {
      log_info("Waiting for Supervisor thread to finish");
      thrd_join(ctx->supervisor.thread, &supervisor_thread_rc);
    }

    edge_eloop_free(ctx->ap_server.eloop);
  }

  free(ctx);
  // returns an error if any of the threads failed
  return ap_server_thread_rc && supervisor_thread_rc;
}

/**
 * @brief Performs an integration test on edgesec
 */
static void test_edgesec(void **state) {
  struct edgesec_test_context *ctx = *state;
  struct app_config config = {0};

  assert_int_equal(load_app_config(TEST_CONFIG_INI_PATH, &config), 0);

#ifdef WITH_CRYPTO_SERVICE
  os_strlcpy(config.crypt_secret, "test", MAX_USER_SECRET);
#endif

  os_init_random_seed();

  assert_int_equal(
      thrd_create(&ctx->ap_server.thread, ap_server_thread, &ctx->ap_server),
      thrd_success);
  ctx->ap_server.cleanup_thread = true;
  assert_int_equal(thrd_create(&ctx->supervisor.thread,
                               supervisor_client_thread, ctx->supervisor.eloop),
                   thrd_success);
  ctx->supervisor.cleanup_thread = true;

  assert_int_equal(run_ctl(&config, ctx->supervisor.eloop), 0);
}

/**
 * @brief Confirm that ap_server_thread errors for invalid AP commands
 *
 * This test is a bit slow, since we need to wait 10 seconds for
 * writeread_domain_data_str() to timeout.
 */
static void test_edgesec_ap_failure(void **state) {
  struct edgesec_test_context *ctx = *state;

  char socket_path[MAX_OS_PATH_LEN] = AP_CTRL_IFACE_PATH;

  assert_int_equal(
      thrd_create(&ctx->ap_server.thread, ap_server_thread, &ctx->ap_server),
      thrd_success);

  // send a PING command to confirm that server is online
  char *reply = NULL;
  sleep(1);
  assert_return_code(
      writeread_domain_data_str(socket_path, PING_AP_COMMAND, &reply), errno);
  assert_string_equal(reply, PING_AP_COMMAND_REPLY);

  // confirm that sending an invalid command results in an timeout error, since
  // we don't get a reply
  // TODO: we need to wait for 10 seconds until we get a timeout.
  // Can we somehow make this timeout faster, or use a different function?:
  assert_int_equal(
      writeread_domain_data_str(socket_path, "INVALID COMMAND", &reply), -1);

  int ap_server_thread_rc = 0;
  log_info("Waiting for AP Server thread to finish");
  thrd_join(ctx->ap_server.thread, &ap_server_thread_rc);

  assert_int_equal(ap_server_thread_rc, 1); // should be an error condition!
  assert_string_equal(ctx->ap_server.error_message,
                      "Unknown command: INVALID COMMAND");
}

int main(__maybe_unused int argc, __maybe_unused char *argv[]) {
  log_set_quiet(false);

  assert_return_code(mtx_init(&log_lock, mtx_plain), thrd_success);
  log_set_lock(log_lock_fun);

  const struct CMUnitTest tests[] = {
      cmocka_unit_test_setup_teardown(test_edgesec, setup_edgesec_test,
                                      teardown_edgesec_test),
      cmocka_unit_test_setup_teardown(
          test_edgesec_ap_failure, setup_edgesec_test, teardown_edgesec_test),
  };

  int rc = cmocka_run_group_tests(tests, NULL, NULL);

  mtx_destroy(&log_lock);

  return rc;
}
