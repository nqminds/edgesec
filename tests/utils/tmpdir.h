/**
 * @brief Contains CMocka setup/teardown functions for creating tmpdirs
 * @author Alois Klink
 * @date 2022
 * @copyright
 * SPDX-FileCopyrightText: © 2022 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */

#define TMPDIR_MKDTEMP_TEMPLATE "/tmp/edgesec_tests/tmpdir.XXXXXX"

struct tmpdir {
  char tmpdir[sizeof(TMPDIR_MKDTEMP_TEMPLATE)];
};

/**
 * @brief Sets up tmpdir object.
 *
 * Contains a temporary directory that will be deleted by cleanup_tmpdir()
 *
 * @param[out] test_state Will be set to the pointer to the created struct
 * tmpdir
 * @return Return code.
 */
int setup_tmpdir(void **test_state);

/**
 * @brief Deletes tmpdir and all contents
 *
 * @param[in, out] test_state Pointer to `struct tmpdir`. Will be set to NULL.
 * @return Return code.
 */
int teardown_tmpdir(void **test_state);
