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
 * @file default_analyser.h 
 * @author Alexandru Mereacre 
 * @brief File containing the definition of the default analyser service.
 */

#ifndef NDPI_ANALYSER_H
#define NDPI_ANALYSER_H

#include "capture_config.h"

/**
 * @brief Starts the ndpi analyser engine
 * 
 * @param config The capture config structure
 * @return int 0 on success, -1 on failure
 */
int start_ndpi_analyser(struct capture_conf *config);

#endif