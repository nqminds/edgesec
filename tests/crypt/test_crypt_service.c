#define _GNU_SOURCE

#include <setjmp.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <cmocka.h>
#include <fcntl.h>
#include <inttypes.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "crypt/crypt_service.h"
#include "utils/log.h"
#include "utils/sqliteu.h"

extern int __real_crypto_decrypt(uint8_t *in, int in_size, uint8_t *key,
                                 uint8_t *iv, uint8_t *out);

int __wrap_crypto_decrypt(uint8_t *in, int in_size, uint8_t *key, uint8_t *iv,
                          uint8_t *out) {
  function_called();
  return __real_crypto_decrypt(in, in_size, key, iv, out);
}

struct hsm_context *__wrap_init_hsm(void) {
  return NULL;
}

static void test_load_crypt_service(void **state) {
  (void)state; /* unused */
  uint8_t secret[4] = {'u', 's', 'e', 'r'};
  uint8_t secret1[4] = {'s', 's', 'e', 'r'};
  struct crypt_context *ctx1, *ctx;
  ctx = load_crypt_service("", "key", secret, 4);

  assert_non_null(ctx);

  free_crypt_service(ctx);

  ctx = load_crypt_service("", NULL, secret, 4);
  assert_null(ctx);

  ctx = load_crypt_service("", "key", secret, 0);
  assert_null(ctx);

  sqlite3 *db = NULL;
  int rc = sqlite3_open("file::memory:?cache=shared", &db);
  assert_int_equal(rc, 0);

  expect_function_call(__wrap_crypto_decrypt);
  ctx = load_crypt_service("file::memory:?cache=shared", "key", secret, 4);
  assert_non_null(ctx);

  expect_function_call(__wrap_crypto_decrypt);
  ctx1 = load_crypt_service("file::memory:?cache=shared", "key", secret, 4);
  assert_non_null(ctx1);
  free_crypt_service(ctx);
  free_crypt_service(ctx1);
  sqlite3_close(db);
  db = NULL;

  rc = sqlite3_open("file::memory:?cache=shared", &db);
  assert_int_equal(rc, 0);
  ignore_function_calls(__wrap_crypto_decrypt);
  ctx = load_crypt_service("file::memory:?cache=shared", "key", secret, 4);
  assert_non_null(ctx);

  ctx1 = load_crypt_service("file::memory:?cache=shared", "key", secret1, 4);
  assert_null(ctx1);
  free_crypt_service(ctx);
  free_crypt_service(ctx1);
  sqlite3_close(db);
  db = NULL;
}

static void test_put_crypt_pair(void **state) {
  (void)state; /* unused */
  uint8_t secret[4] = {'u', 's', 'e', 'r'};
  char *key = "key";
  char *value = "value";
  struct crypt_pair pair = {
      .key = key, .value = (uint8_t *)value, .value_size = strlen(value)};
  ignore_function_calls(__wrap_crypto_decrypt);
  struct crypt_context *ctx = load_crypt_service("", "key", secret, 4);

  assert_non_null(ctx);

  assert_int_equal(put_crypt_pair(ctx, &pair), 0);
  free_crypt_service(ctx);
}

static void test_get_crypt_pair(void **state) {
  (void)state; /* unused */
  uint8_t secret[4] = {'u', 's', 'e', 'r'};
  char *key = "key";
  char *value = "value";
  struct crypt_pair in = {.key = key,
                          .value = (uint8_t *)value,
                          .value_size = strlen(value)},
                    *out;
  ignore_function_calls(__wrap_crypto_decrypt);
  struct crypt_context *ctx = load_crypt_service("", "key", secret, 4);

  assert_non_null(ctx);

  assert_int_equal(put_crypt_pair(ctx, &in), 0);
  out = get_crypt_pair(ctx, key);
  assert_non_null(out);
  assert_memory_equal(out->value, value, strlen(value));
  free_crypt_service(ctx);
  free_crypt_pair(out);
}

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  log_set_quiet(false);

  const struct CMUnitTest tests[] = {cmocka_unit_test(test_load_crypt_service),
                                     cmocka_unit_test(test_put_crypt_pair),
                                     cmocka_unit_test(test_get_crypt_pair)};

  return cmocka_run_group_tests(tests, NULL, NULL);
}
