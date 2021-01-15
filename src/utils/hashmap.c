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
 * @file hashmap.c
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of the hashmap utilities.
 */

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "os.h"
#include "log.h"
#include "hashmap.h"
#include "uthash.h"

hmap_str_keychar *hmap_str_keychar_new(void)
{
	return NULL;
}

char *hmap_str_keychar_get(hmap_str_keychar **hmap, char *keyptr)
{
	hmap_str_keychar *s;

	if(keyptr == NULL) {
		log_trace("keyptr is NULL");
		return NULL;
	}

	HASH_FIND_STR(*hmap, keyptr, s);

	if (s != NULL)
		return s->value;

	return NULL;
}

bool hmap_str_keychar_put(hmap_str_keychar **hmap, char *keyptr, char *value)
{
	hmap_str_keychar *s;

	if (keyptr == NULL) {
		log_trace("keyptr is NULL");
		return false;
	}

	if (strlen(keyptr) > HASH_KEY_CHAR_SIZE - 1) {
		log_trace("strlen(keyptr) is greater than key char size");
		return false;
	}

	HASH_FIND_STR(*hmap, keyptr, s); /* id already in the hash? */

  if (s == NULL) {
    s = (hmap_str_keychar *) os_malloc(sizeof(hmap_str_keychar));
		if (s == NULL) {
			log_err_ex("os_malloc");
		}

		// Copy the key
		strcpy(s->key, keyptr);
		s->value = allocate_string(value);

		HASH_ADD_STR(*hmap, key, s);
  } else {
		// Copy the value
		os_free(s->value);
    s->value = allocate_string(value);
	}

	return true;
}

void hmap_str_keychar_free(hmap_str_keychar **hmap)
{
	hmap_str_keychar *current, *tmp;

	HASH_ITER(hh, *hmap, current, tmp) {
    HASH_DEL(*hmap, current);  							/* delete it (users advances to next) */
		os_free(current->value);								/* free the value content */
    os_free(current);            						/* free it */
  }
}