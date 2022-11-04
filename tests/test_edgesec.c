#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>
#include <pthread.h>
#include <sys/ioctl.h>

#include "runctl.h"
#include "config.h"

#include "utils/sockctl.h"
#include "supervisor/cmd_processor.h"
#include "supervisor/system_commands.h"
#include "ap/ap_service.h"

#define AP_CTRL_IFACE_PATH "/tmp/wifi0"
#define SUPERVISOR_CONTROL_PATH "/tmp/edgesec-control-server"

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
  assert_int_equal(close_domain_socket(fd), 0);
  return NULL;
}

void *supervisor_client_thread(void *arg) {
  (void)arg;
  char socket_path[MAX_OS_PATH_LEN];
  char ping_reply[ARRAY_SIZE(PING_REPLY) + 1];
  strcpy(ping_reply, PING_REPLY);
  rtrim(ping_reply, NULL);
  strcpy(socket_path, SUPERVISOR_CONTROL_PATH);
  // struct eloop_data *eloop = (struct eloop_data *)arg;

  int count = 10;
  while (count--) {
    char *reply = NULL;
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

  // eloop_run(eloop);
  return NULL;
}

/**
 * @brief Performs an integration test on edgesec
 */
static void test_edgesec(void **state) {
  (void)state; /* unused */

  struct app_config config;

  // Init the app config struct
  memset(&config, 0, sizeof(struct app_config));

  assert_int_equal(load_app_config(TEST_CONFIG_INI_PATH, &config), 0);

  os_init_random_seed();

  pthread_t ap_id = 0;
  struct eloop_data *ap_eloop = eloop_init();
  assert_int_equal(
      pthread_create(&ap_id, NULL, ap_server_thread, (void *)ap_eloop), 0);

  pthread_t supervisor_id = 0;
  struct eloop_data *supervisor_eloop = eloop_init();
  assert_int_equal(pthread_create(&supervisor_id, NULL,
                                  supervisor_client_thread,
                                  (void *)supervisor_eloop),
                   0);

  assert_int_equal(run_ctl(&config), 0);

  assert_int_equal(pthread_join(ap_id, NULL), 0);
  assert_int_equal(pthread_join(supervisor_id, NULL), 0);

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
