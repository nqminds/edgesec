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
 * @file allocs.c
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of the allocs functionalities.
 */

#include <stddef.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>

#include "allocs.h"

void * os_zalloc(size_t size)
{
	void *n = os_malloc(size);
	if (n != NULL)
		os_memset(n, 0, size);
	return n;
}

void * os_memdup(const void *src, size_t len)
{
	void *r = os_malloc(len);

	if (r && src)
		os_memcpy(r, src, len);
	return r;
}

char * os_strdup(const char *s)
{
  char *dest = NULL;
  size_t len = strlen(s) + 1;

  if (s != NULL) {
  	dest = (char *) os_malloc(len);
	if (dest == NULL) {
      return NULL;
	}

	strcpy(dest, s);
  }

  return dest;
}
