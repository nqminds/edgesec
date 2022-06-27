/**
 * @file
 * @author Alexandru Mereacre
 * @date 2020
 * @copyright
 * SPDX-FileCopyrightText: © 2020 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * @brief File containing the definition of the allocs functionalities.
 */
#ifndef ALLOCS_H
#define ALLOCS_H

#include <stddef.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>

/**
 * @brief Allocate and zero memory
 *
 * Caller is responsible for freeing the returned buffer with os_free().
 *
 * @param size Number of bytes to allocate
 * @return void* Pointer to allocated and zeroed memory or %NULL on failure
 */
void *os_zalloc(size_t size);

/**
 * @brief Allocate and zero memory for an array
 *
 * This function can be used as a wrapper for os_zalloc(nmemb * size) when an
 * allocation is used for an array. The main benefit over os_zalloc() is in
 * having an extra check to catch integer overflows in multiplication.
 *
 * Caller is responsible for freeing the returned buffer with os_free().
 *
 * @param nmemb Number of members in the array
 * @param size Number of bytes in each member
 * @return void* Pointer to allocated and zeroed memory or %NULL on failure
 */
static inline void *os_calloc(size_t nmemb, size_t size) {
  if (size && nmemb > (~(size_t)0) / size)
    return NULL;
  return os_zalloc(nmemb * size);
}

// void *os_malloc(size_t size);
// void os_free(void* ptr);

#ifndef os_malloc
#define os_malloc(s) malloc((s))
#endif

#ifndef os_realloc
#define os_realloc(p, s) realloc((p), (s))
#endif

#ifndef os_calloc
#define os_calloc(nm, s) calloc((nm), (s))
#endif

#ifndef os_free
#define os_free(p) free((p))
#endif

static inline void *os_realloc_array(void *ptr, size_t nmemb, size_t size) {
  if (size && nmemb > (~(size_t)0) / size)
    return NULL;
  return os_realloc(ptr, nmemb * size);
}

/**
 * @brief Allocate duplicate of passed memory chunk
 *
 * This function allocates a memory block like os_malloc() would, and
 * copies the given source buffer into it.
 *
 * @param src Source buffer to duplicate
 * @param len Length of source buffer
 * @return void* %NULL if allocation failed, copy of src buffer otherwise
 */
void *os_memdup(const void *src, size_t len);

#ifndef os_memcpy
#define os_memcpy(d, s, n) memcpy((d), (s), (n))
#endif
#ifndef os_memmove
#define os_memmove(d, s, n) memmove((d), (s), (n))
#endif
#ifndef os_memset
#define os_memset(s, c, n) memset(s, c, (n))
#endif
#ifndef os_memcmp
#define os_memcmp(s1, s2, n) memcmp((s1), (s2), (n))
#endif

/**
 * @brief Returns a pointer to a new string which is a duplicate of the string s
 *
 * @param s The input string
 * @return char* The dublicate string pointer, NULL on error
 */
char *os_strdup(const char *s);
#endif
