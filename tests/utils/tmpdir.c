#define _XOPEN_SOURCE 700 /* mkdtemp() is part of POSIX 700 spec*/
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <cmocka.h>
// used to delete directory recursively
#include <ftw.h>

#include <stdlib.h>

#include "utils/log.h"

#include "tmpdir.h"

// recursively delete folder using ftw
static int rm_file(const char *pathname, const struct stat *sbuf, int type,
                   struct FTW *ftwb) {
  (void)sbuf;
  (void)type;
  (void)ftwb;

  if (remove(pathname) < 0) {
    log_errno("remove %s", pathname);
    return -1;
  }
  return 0;
}
static int rm_dir_recursive(const char *directory) {
  int ret_val = nftw(directory, rm_file, 10, FTW_DEPTH | FTW_MOUNT | FTW_PHYS);
  if (ret_val) {
    log_error("Error when trying to delete '%s'", directory);
  }
  return ret_val;
}

int setup_tmpdir(void **test_state) {
  struct tmpdir *state = test_malloc(sizeof(struct tmpdir));
  assert_non_null(state);

  // ignore return value if directory creation failed
  (void)mkdir("/tmp/edgesec_tests", 0755);

  *state = (struct tmpdir){.tmpdir = TMPDIR_MKDTEMP_TEMPLATE};
  assert_non_null(mkdtemp(state->tmpdir));

  *test_state = state;
  return 0;
}

int teardown_tmpdir(void **test_state) {
  struct tmpdir *state = *test_state;

  if (state == NULL) {
    return 0;
  }
  assert_string_not_equal(state->tmpdir, "");

  log_debug("Deleting directory recursively %s", state->tmpdir);
  int ret_val = rm_dir_recursive(state->tmpdir);
  assert_int_equal(ret_val, 0);

  test_free(state);

  *test_state = NULL;
  return 0;
}
