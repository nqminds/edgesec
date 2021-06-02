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

#ifdef WITH_NDPI_SERVICE
#include "ndpi_analyser.h"
#endif

#include "default_analyser.h"
#include "capture_config.h"

#include "../utils/log.h"

int run_capture(struct capture_conf *config)
{
  if (strcmp(config->analyser, PACKET_ANALYSER_DEFAULT) == 0) {
    log_info("Running default_analyser_engine");
    return start_default_analyser(config);
  } else if (strcmp(config->analyser, PACKET_ANALYSER_NDPI) == 0) {
#ifdef WITH_NDPI_SERVICE
    log_info("Running ndpi_analyser_engine");
    return start_ndpi_analyser(config);
#endif
  }

  return start_default_analyser(config);
}
