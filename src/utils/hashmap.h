/**************************************************************************************************
*  Filename:        hashmap.h
*  Author:          Alexandru Mereacre (mereacre@gmail.com)
*  Revised:
*  Revision:
*
*  Description:     hashmap include file
*
*  Copyright (C) 2020 NQMCyber Ltd - http://www.nqmcyber.com/
*************************************************************************************************/

#ifndef HASHMAP_H_
#define HASHMAP_H_

#include <stdbool.h>

#include "uthash.h"

#define HASH_KEY_CHAR_SIZE  20

typedef struct hashmap_str_keychar {
    char key[HASH_KEY_CHAR_SIZE];       /* key (string is WITHIN the structure) */
    char *value;
    UT_hash_handle hh;         		    /* makes this structure hashable */
} hmap_str_keychar;

typedef struct hashmap_str_keyptr {
    char *key;             			    /* key (string is WITHIN the structure) */
    char *value;
    UT_hash_handle hh;         		    /* makes this structure hashable */
} hmap_str_keyptr;

hmap_str_keychar *hmap_str_keychar_new(void);
char *hmap_str_keychar_get(hmap_str_keychar **hmap, char *keyptr);
bool hmap_str_keychar_put(hmap_str_keychar **hmap, char *keyptr, char *value);
void hmap_str_keychar_free(hmap_str_keychar **hmap);

#endif