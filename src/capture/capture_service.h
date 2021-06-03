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
 * @file capture_service.h 
 * @author Alexandru Mereacre 
 * @brief File containing the definition of the capture service structures.
 */

#ifndef CAPTURE_SERVICE_H
#define CAPTURE_SERVICE_H

#include "capture_config.h"

#define CAPTURE_MAX_OPT       26
#define CAPTURE_OPT_STRING    ":c:i:q:f:t:n:p:y:a:o:x:z:dvhmewus"
#define CAPTURE_USAGE_STRING  "\t%s [-c config] [-d] [-h] [-v] [-i interface] [-q domain]" \
                              "[-f filter] [-m] [-t timeout] [-n interval] " \
                              "[-e] [-y engine][-w] [-u] [-s] [-p path] [-a address] [-o port]\n"
#define CAPTURE_OPT_DEFS      "\t-c config\t Path to the config file name\n" \
                              "\t-q domain\t The UNIX domain path\n" \
                              "\t-x command\t The UNIX domain command\n" \
                              "\t-z delimiter\t The UNIX domain command delimiter\n" \
                              "\t-i interface\t The capture interface name\n" \
                              "\t-f filter\t The capture filter expression\n" \
                              "\t-t timeout\t The buffer timeout (milliseconds)\n" \
                              "\t-n interval\t The process interval (milliseconds)\n" \
                              "\t-y analyser\t Analyser\n" \
                              "\t-p path\t\t The db path\n" \
                              "\t-a address\t The db sync address\n" \
                              "\t-o port\t\t The db sync port\n" \
                              "\t-m\t\t Promiscuous mode\n" \
                              "\t-e\t\t Immediate mode\n" \
                              "\t-u\t\t Write to file\n" \
                              "\t-w\t\t Write to db\n" \
                              "\t-s\t\t Sync the db\n" \
                              "\t-d\t\t Verbosity level (use multiple -dd... to increase)\n" \
                              "\t-h\t\t Show help\n" \
                              "\t-v\t\t Show app version\n\n"

/**
 * @brief Translate a capture process option to a config structure value
 * 
 * @param key Capture process option key
 * @param opt Capture process option value
 * @param config The config structure
 * @return int 0 on success, -1 on error and 1 for an unknown option key
 */
int capture_opt2config(char key, char *value, struct capture_conf *config);

/**
 * @brief Transforms a config structure to opt string array
 * 
 * @param config The config structure
 * @return char** the opt string array, NULL on failure
 */
char** capture_config2opt(struct capture_conf *config);
/**
 * @brief Free opt string array
 * 
 * @param opt_str Opt string array
 */
void capture_freeopt(char **opt_str);

/**
 * @brief Executes the capture service
 * 
 * @param config The capture service config structure
 * @return int 0 on success, -1 on error
 */
int run_capture(struct capture_conf *config);

#endif
