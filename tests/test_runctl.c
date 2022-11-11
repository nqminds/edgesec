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

#include "supervisor/sqlite_macconn_writer.h"
#include "crypt/crypt_service.h"
#include "utils/hashmap.h"
#include "utils/log.h"
#include <utarray.h>

#include "supervisor/supervisor_config.h"
#include "runctl.h"

static const UT_icd config_ifinfo_icd = {sizeof(config_ifinfo_t), NULL, NULL,
                                         NULL};

int __wrap_get_vlan_mapper(hmap_vlan_conn **hmap, int vlanid,
                           struct vlan_conn *conn) {
  (void)hmap;
  (void)vlanid;
  (void)conn;

  return (int)mock();
}

void __wrap_eloop_run(struct eloop_data *eloop) { (void)eloop; }

int __wrap_get_commands_paths(char *commands[], UT_array *bin_path_arr,
                              hmap_str_keychar **hmap_bin_paths) {
  (void)commands;
  (void)bin_path_arr;
  (void)hmap_bin_paths;

  return (int)mock();
}

const char *__wrap_hmap_str_keychar_get(const hmap_str_keychar *hmap,
                                        char *keyptr) {
  (void)hmap;
  (void)keyptr;

  return mock_ptr_type(const char *);
}

#ifdef WITH_CRYPTO_SERVICE
struct crypt_context *__wrap_load_crypt_service(char *crypt_db_path,
                                                char *key_id,
                                                uint8_t *user_secret,
                                                int user_secret_size) {
  (void)crypt_db_path;
  (void)key_id;
  (void)user_secret;
  (void)user_secret_size;

  return (struct crypt_context *)mock();
}
#endif

int __wrap_fw_set_ip_forward(void) { return 0; }

char *__wrap_iface_get_vlan(char *buf) {
  (void)buf;

  return (char *)mock();
}
struct fwctx *__wrap_fw_init_context(hmap_if_conn *if_mapper,
                                     hmap_vlan_conn *vlan_mapper,
                                     hmap_str_keychar *hmap_bin_paths,
                                     UT_array *config_ifinfo_array,
                                     char *nat_bridge, char *nat_interface,
                                     bool exec_firewall, char *path) {
  (void)if_mapper;
  (void)vlan_mapper;
  (void)hmap_bin_paths;
  (void)config_ifinfo_array;
  (void)nat_bridge;
  (void)nat_interface;
  (void)exec_firewall;
  (void)path;

  return (struct fwctx *)mock();
}

int __wrap_run_supervisor(char *server_path,
                          struct supervisor_context *context) {
  (void)server_path;
  (void)context;

  return 0;
}

int __wrap_run_ap(struct supervisor_context *context, bool exec_ap,
                  bool generate_ssid, void *ap_callback_fn) {
  (void)context;
  (void)exec_ap;
  (void)generate_ssid;
  (void)ap_callback_fn;

  return 0;
}
#ifdef WITH_RADIUS_SERVICE
struct radius_server_data *__wrap_run_radius(struct eloop_data *eloop,
                                             struct radius_conf *rconf,
                                             void *radius_callback_fn,
                                             void *radius_callback_args) {
  (void)eloop;
  (void)rconf;
  (void)radius_callback_fn;
  (void)radius_callback_args;

  return (struct radius_server_data *)mock();
}
#endif

#ifdef WITH_MDNS_SERVICE
int __wrap_run_mdns_thread(struct mdns_conf *mdns_config,
                           char *supervisor_control_path,
                           hmap_vlan_conn *vlan_mapper, pthread_t *id) {
  (void)mdns_config;
  (void)supervisor_control_path;
  (void)vlan_mapper;
  (void)id;

  return 0;
}
#endif

int __wrap_run_dhcp(struct dhcp_conf *dconf, UT_array *dns_server_array,
                    char *supervisor_control_path, bool exec_dhcp) {
  (void)dconf;
  (void)dns_server_array;
  (void)supervisor_control_path;
  (void)exec_dhcp;

  return 0;
}
static void test_init_context(void **state) {
  (void)state; /* unused */
  struct supervisor_context context;
  UT_array *config_ifinfo_arr = NULL;
  utarray_new(config_ifinfo_arr, &config_ifinfo_icd);
  struct app_config app_config = {0,
                                  .default_open_vlanid = 0,
                                  .connection_db_path = ":memory:",
                                  .config_ifinfo_array = config_ifinfo_arr,
                                  .set_ip_forward = true,
                                  .ap_detect = true,
                                  .create_interfaces = true,
                                  .exec_ap = true,
                                  .exec_radius = true,
                                  .exec_dhcp = true,
                                  .exec_mdns_forward = true};

  // Load the bin paths array
  const char *paths[] = {"/usr/local/sbin", "/usr/local/bin", "/usr/sbin",
                         "/usr/bin",        "/sbin",          "/bin",
                         "/snap/bin"};

  utarray_new(app_config.bin_path_array, &ut_str_icd);
  for (size_t idx = 0; idx < sizeof(paths) / sizeof(paths[0]); idx++) {
    utarray_push_back(app_config.bin_path_array, &(paths[idx]));
  }
  utarray_new(app_config.config_ifinfo_array, &ut_str_icd);

  will_return_always(__wrap_get_vlan_mapper, 1);
  will_return_always(__wrap_get_commands_paths, 0);
  will_return_always(__wrap_hmap_str_keychar_get, ".");
  int context_error = init_context(&app_config, &context);

  assert_int_equal(context_error, 0);

  utarray_free(app_config.bin_path_array);
  utarray_free(app_config.config_ifinfo_array);
  free_bridge_list(context.bridge_list);
  free_sqlite_macconn_db(context.macconn_db);
  free_vlan_mapper(&context.vlan_mapper);
  free_if_mapper(&context.if_mapper);
  free_mac_mapper(&context.mac_mapper);
  fw_free_context(context.fw_ctx);
  hmap_str_keychar_free(&context.hmap_bin_paths);
#ifdef WITH_CRYPTO_SERVICE
  free_crypt_service(context.crypt_ctx);
#endif
  iface_free_context(context.iface_ctx);
  utarray_free(config_ifinfo_arr);
}

/**
 * @brief Tests whether the init_context function fails when the
 * config_ifinfo_array param is invalid. This should also log an error message
 * (not a debug/info message) (run test manually to see whether this appears in
 * your console)
 */
static void test_run_engine(void **state) {
  (void)state; /* unused */

#ifdef WITH_CRYPTO_SERVICE
  struct crypt_context *crypt_ctx =
      (struct crypt_context *)os_zalloc(sizeof(struct crypt_context));
#endif
#ifdef WITH_RADIUS_SERVICE
  struct radius_server_data *radius_srv =
      os_zalloc(sizeof(struct radius_server_data *));
#endif

  struct fwctx *fw_ctx = os_zalloc(sizeof(struct fwctx));
  UT_array *config_ifinfo_arr = NULL;
  utarray_new(config_ifinfo_arr, &config_ifinfo_icd);

  struct app_config app_config = {0,
                                  .default_open_vlanid = 0,
                                  .connection_db_path = ":memory:",
                                  .config_ifinfo_array = config_ifinfo_arr,
                                  .set_ip_forward = true,
                                  .ap_detect = true,
                                  .create_interfaces = true,
                                  .exec_ap = true,
                                  .exec_radius = true,
                                  .exec_dhcp = true,
                                  .exec_mdns_forward = true};
  will_return_always(__wrap_get_vlan_mapper, 1);
  will_return_always(__wrap_get_commands_paths, 0);
  will_return_always(__wrap_hmap_str_keychar_get, ".");
  will_return_always(__wrap_fw_init_context, fw_ctx);
  will_return_always(__wrap_iface_get_vlan, "wlan0");
#ifdef WITH_RADIUS_SERVICE
  will_return_always(__wrap_run_radius, radius_srv);
#endif
#ifdef WITH_CRYPTO_SERVICE
  will_return_always(__wrap_load_crypt_service, crypt_ctx);
#endif

  int ret = run_ctl(&app_config);
  assert_int_equal(ret, 0);
  utarray_free(config_ifinfo_arr);
}

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  log_set_quiet(false);

  const struct CMUnitTest tests[] = {cmocka_unit_test(test_init_context),
                                     cmocka_unit_test(test_run_engine)};

  return cmocka_run_group_tests(tests, NULL, NULL);
}
