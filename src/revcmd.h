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
 * @file revcmd.h 
 * @author Alexandru Mereacre 
 * @brief File containing the definitions of the reverse commands.
 */

#ifndef REVCMD_H
#define REVCMD_H

enum REVERSE_COMMANDS {
  REVERSE_CMD_UNKNOWN = 0,
  REVERSE_CMD_LIST,
  REVERSE_CMD_GET,
  REVERSE_CMD_LIST_CLIENTS
};

#define REVERSE_CMD_STR_LIST              "LIST"
#define REVERSE_CMD_STR_GET               "GET"
#define REVERSE_CMD_STR_LIST_CLIENTS      "LISTC"
#endif

