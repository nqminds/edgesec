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

#ifndef DEFAULT_ANALYSER_H
#define DEFAULT_ANALYSER_H

#include "capture_config.h"

/**
 * @brief Starts the default analyser engine
 * 
 * @param config The capture config structure
 * @return int 0 on success, -1 on failure
 */
int start_default_analyser(struct capture_conf *config);

#endif