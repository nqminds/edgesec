/****************************************************************************
 * Copyright (C) 2020 by NQMCyber Ltd                                       *
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
 * @file request.h 
 * @author Alexandru Mereacre 
 * @brief File containing the definition of the request utils functionalities.
 */
#ifndef REQUEST_H
#define REQUEST_H

/**
** \brief Get response buffer from an URL GET request
**
** \param url The url string
** \param out The returned buffer
** \return Sucess: the reponse size.
**         Failure: -1.
*/
ssize_t get_response(char *url, unsigned char **out);

/**
** \brief Get response string from an URL GET request
**
** \param url The url string
** \return Sucess: the reponse string.
**         Failure: NULL.
*/
char* get_response_str(char *url);

/**
** \brief Confirm the reponse from URL GET request
**
** \param url The url string
** \return Sucess: 0.
**         Failure: -1.
*/
int confirm_reponse(char *url);

#endif