/**
 * @file __wrap_uwrt_init_context.c
 * @author Alois Klink
 * @date 2022
 * @copyright
 * SPDX-FileCopyrightText: © 2022 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief Unit test wrapper function for uwrt_init_context to use
 * TEST_UCI_CONFIG_DIR Link unit tests with `-Wl,--wrap=uwrt_init_context`
 */
#include "utils/uci_wrt.h"

extern struct uctx *__real_uwrt_init_context(const char *path);

struct uctx *__wrap_uwrt_init_context(const char *path) {
  const char *actual_path = path;
#ifdef TEST_UCI_CONFIG_DIR
  if (actual_path == NULL) {
    log_trace("Opening UCI Config in dir %s", TEST_UCI_CONFIG_DIR);
    actual_path = TEST_UCI_CONFIG_DIR;
  }
#endif
  return __real_uwrt_init_context(actual_path);
}
