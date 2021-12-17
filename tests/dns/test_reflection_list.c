#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <fcntl.h>
#include <ctype.h>
#include <unistd.h>
#include <pthread.h>
#include <stdbool.h>
#include <errno.h>
#include <net/if.h>
#include <libgen.h>
#include <setjmp.h>
#include <cmocka.h>
#include <sys/socket.h>

#include "utils/log.h"
#include "utils/os.h"
#include "dns/reflection_list.h"

static void test_init_reflection_list(void **state)
{
  (void) state;

  struct reflection_list *list = NULL;
  
  list = init_reflection_list();
  assert_non_null(list);

  free_reflection_list(list);
}

static void test_push_reflection_list(void **state)
{
  (void) state;

  struct reflection_list *el;
  struct reflection_list *list = init_reflection_list();

  assert_int_equal(dl_list_len(&list->list), 0);
  assert_non_null(push_reflection_list(list, 0, "wlan0"));
  assert_int_equal(dl_list_len(&list->list), 1);
  el = dl_list_first(&list->list, struct reflection_list, list);
  assert_non_null(el);
  assert_string_equal(el->ifname, "wlan0");
  free_reflection_list(list);
}

int main(int argc, char *argv[])
{  
  (void) argc; /* unused */
  (void) argv; /* unused */

  log_set_quiet(false);

  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_init_reflection_list),
    cmocka_unit_test(test_push_reflection_list)
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
