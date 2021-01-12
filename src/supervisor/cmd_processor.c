/**************************************************************************************************
*  Filename:        cmd_processor.c
*  Author:          Alexandru Mereacre (mereacre@gmail.com)
*  Revised:
*  Revision:
*
*  Description:     cmd_processor source file
*
*  Copyright (C) 2020 NQMCyber Ltd - http://www.nqmcyber.com/
*************************************************************************************************/

#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "cmd_processor.h"

#include "utils/os.h"
#include "utils/log.h"
#include "utils/utarray.h"

bool process_domain_buffer(char *domain_buffer, size_t domain_buffer_len, UT_array *cmd_arr)
{
  if (domain_buffer == NULL || cmd_arr == NULL)
    return false;

  if (!domain_buffer_len)
    return false;

  char *cmd_line = os_malloc(domain_buffer_len + 1);
  if (cmd_line == NULL) {
    log_err_ex("malloc");
  }

  os_memcpy(cmd_line, domain_buffer, domain_buffer_len);
  cmd_line[domain_buffer_len] = '\0';

  if (split_string_array(cmd_line, CMD_DELIMITER, cmd_arr) == -1) {
    log_trace("split_string_array fail");
    os_free(cmd_line);
    return false;
  }

  os_free(cmd_line);
  return true;
}
