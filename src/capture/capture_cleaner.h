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
 * @file capture_cleaner.h 
 * @author Alexandru Mereacre 
 * @brief File containing the definition of the capture cleaner service structures.
 * 
 * Defines the start function for the capturte cleaner service, which
 * removes the capture files from the database folder when it 
 * reaches a given size specified in the capture_conf structure. The
 * store size is give by the parameter capture_store_size in Kb.
 */

#ifndef CAPTURE_CLEANER_H
#define CAPTURE_CLEANER_H

#include "capture_config.h"

/**
 * @brief Executes the capture cleaner service
 * 
 * @param config The capture service config structure
 * @return int 0 on success, -1 on error
 */
int start_capture_cleaner(struct capture_conf *config);

#endif
