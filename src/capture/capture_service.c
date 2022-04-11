/****************************************************************************
 * Copyright (C) 2021 by NQMCyber Ltd                                       *
 *                                                                          *
 * This file is part of EDGESec.                                            *
 *                                                                          *
 *   EDGESec is free software: you can redistribute it and/or modify it     *
 *   under the terms of the GNU Lesser General Public License as published  *
 *   by the Free Software Foundation, either version 3 of the License, or   *
 *   (at your option) any later version.                                    *
 *                                                                          *
 *   EDGESec is distributed in the hope that it will be useful,             *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of         *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the          *
 *   GNU Lesser General Public License for more details.                    *
 *                                                                          *
 *   You should have received a copy of the GNU Lesser General Public       *
 *   License along with EDGESec. If not, see <http://www.gnu.org/licenses/>.*
 ****************************************************************************/

/**
 * @file capture_service.c
 * @author Alexandru Mereacre
 * @brief File containing the implementation of the capture service.
 */
#include <errno.h>

#include "default_analyser.h"
#include "capture_config.h"
#include "capture_service.h"
#include "capture_cleaner.h"

#include "../utils/log.h"
#include "../utils/allocs.h"
#include "../utils/os.h"

//sudo ./src/capsrv -i br3 -t 10 -n 10 -e -m -y default -q /tmp/edgesec-domain-server -x SET_ALERT -z 32 -f "src net 10.0 and dst net 10.0" -ddddddddd

int run_capture(struct capture_conf *config)
{
  if (strcmp(config->analyser, PACKET_ANALYSER_DEFAULT) == 0) {
    log_info("Running default_analyser_engine");
    return start_default_analyser(config);
  }

  return start_capture_cleaner(config);
}
