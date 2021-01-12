/**************************************************************************************************
*  Filename:        os.h
*  Author:          Alexandru Mereacre (mereacre@gmail.com)
*  Revised:
*  Revision:
*
*  Description:     os include file
*
*  Copyright (C) 2020 NQMCyber Ltd - http://www.nqmcyber.com/
*************************************************************************************************/

#ifndef OS_H
#define OS_H

#include <stddef.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "utarray.h"

/* Common costant defintions */
#define MAX_OS_PATH_LEN	255
#define IP_LEN 					20
#define ETH_ALEN 				6
#define LINK_TYPE_LEN 	64

#ifdef __GNUC__
#define STRUCT_PACKED __attribute__ ((packed))
#else
#define STRUCT_PACKED
#endif

#ifndef MAC2STR
#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"

/*
 * Compact form for string representation of MAC address
 * To be used, e.g., for constructing dbus paths for P2P Devices
 */
#define COMPACT_MACSTR "%02x%02x%02x%02x%02x%02x"
#endif

#ifndef BIT
#define BIT(x) (1U << (x))
#endif

typedef long os_time_t;

struct os_time {
	os_time_t sec;
	os_time_t usec;
};

struct os_reltime {
	os_time_t sec;
	os_time_t usec;
};

/**
 * os_get_time - Get current time (sec, usec)
 * @t: Pointer to buffer for the time
 * Returns: 0 on success, -1 on failure
 */
int os_get_time(struct os_time *t);

/**
 * os_get_reltime - Get relative time (sec, usec)
 * @t: Pointer to buffer for the time
 * Returns: 0 on success, -1 on failure
 */
int os_get_reltime(struct os_reltime *t);


/* Helpers for handling struct os_time */

static inline int os_time_before(struct os_time *a, struct os_time *b)
{
	return (a->sec < b->sec) ||
	       (a->sec == b->sec && a->usec < b->usec);
}


static inline void os_time_sub(struct os_time *a, struct os_time *b,
			       struct os_time *res)
{
	res->sec = a->sec - b->sec;
	res->usec = a->usec - b->usec;
	if (res->usec < 0) {
		res->sec--;
		res->usec += 1000000;
	}
}

/* Helpers for handling struct os_reltime */

static inline int os_reltime_before(struct os_reltime *a,
				    struct os_reltime *b)
{
	return (a->sec < b->sec) ||
	       (a->sec == b->sec && a->usec < b->usec);
}


static inline void os_reltime_sub(struct os_reltime *a, struct os_reltime *b,
				  struct os_reltime *res)
{
	res->sec = a->sec - b->sec;
	res->usec = a->usec - b->usec;
	if (res->usec < 0) {
		res->sec--;
		res->usec += 1000000;
	}
}


static inline void os_reltime_age(struct os_reltime *start,
				  struct os_reltime *age)
{
	struct os_reltime now;

	os_get_reltime(&now);
	os_reltime_sub(&now, start, age);
}


static inline int os_reltime_expired(struct os_reltime *now,
				     struct os_reltime *ts,
				     os_time_t timeout_secs)
{
	struct os_reltime age;

	os_reltime_sub(now, ts, &age);
	return (age.sec > timeout_secs) ||
	       (age.sec == timeout_secs && age.usec > 0);
}


static inline int os_reltime_initialized(struct os_reltime *t)
{
	return t->sec != 0 || t->usec != 0;
}

/**
 * os_get_random - Get cryptographically strong pseudo random data
 * @buf: Buffer for pseudo random data
 * @len: Length of the buffer
 * Returns: 0 on success, -1 on failure
 */
int os_get_random(unsigned char *buf, size_t len);

int hex2byte(const char *hex);
int hexstr2bin(const char *hex, uint8_t *buf, size_t len);
int hwaddr_aton2(const char *txt, uint8_t *addr);

bool is_number(const char *ptr);

void bin_clear_free(void *bin, size_t len);
void forced_memzero(void *ptr, size_t len);

/**
 * os_strlcpy - Copy a string with size bound and NUL-termination
 * @dest: Destination
 * @src: Source
 * @siz: Size of the target buffer
 * Returns: Total length of the target string (length of src) (not including
 * NUL-termination)
 *
 * This function matches in behavior with the strlcpy(3) function in OpenBSD.
 */
size_t os_strlcpy(char *dest, const char *src, size_t siz);

/**
 * os_zalloc - Allocate and zero memory
 * @size: Number of bytes to allocate
 * Returns: Pointer to allocated and zeroed memory or %NULL on failure
 *
 * Caller is responsible for freeing the returned buffer with os_free().
 */
void * os_zalloc(size_t size);

/**
 * os_calloc - Allocate and zero memory for an array
 * @nmemb: Number of members in the array
 * @size: Number of bytes in each member
 * Returns: Pointer to allocated and zeroed memory or %NULL on failure
 *
 * This function can be used as a wrapper for os_zalloc(nmemb * size) when an
 * allocation is used for an array. The main benefit over os_zalloc() is in
 * having an extra check to catch integer overflows in multiplication.
 *
 * Caller is responsible for freeing the returned buffer with os_free().
 */
static inline void * os_calloc(size_t nmemb, size_t size)
{
	if (size && nmemb > (~(size_t) 0) / size)
		return NULL;
	return os_zalloc(nmemb * size);
}

/**
 * os_memdup - Allocate duplicate of passed memory chunk
 * @src: Source buffer to duplicate
 * @len: Length of source buffer
 * Returns: %NULL if allocation failed, copy of src buffer otherwise
 *
 * This function allocates a memory block like os_malloc() would, and
 * copies the given source buffer into it.
 */
void * os_memdup(const void *src, size_t len);

#ifndef os_malloc
#define os_malloc(s) malloc((s))
#endif
#ifndef os_realloc
#define os_realloc(p, s) realloc((p), (s))
#endif
#ifndef os_free
#define os_free(p) free((p))
#endif

#ifndef os_memcpy
#define os_memcpy(d, s, n) memcpy((d), (s), (n))
#endif
#ifndef os_memmove
#define os_memmove(d, s, n) memmove((d), (s), (n))
#endif
#ifndef os_memset
#define os_memset(s, c, n) memset(s, c, n)
#endif
#ifndef os_memcmp
#define os_memcmp(s1, s2, n) memcmp((s1), (s2), (n))
#endif
#ifndef os_strdup
#define os_strdup(s) strdup(s)
#endif

static inline void * os_realloc_array(void *ptr, size_t nmemb, size_t size)
{
	if (size && nmemb > (~(size_t) 0) / size)
		return NULL;
	return os_realloc(ptr, nmemb * size);
}

/**
 * os_memcmp_const - Constant time memory comparison
 * @a: First buffer to compare
 * @b: Second buffer to compare
 * @len: Number of octets to compare
 * Returns: 0 if buffers are equal, non-zero if not
 *
 * This function is meant for comparing passwords or hash values where
 * difference in execution time could provide external observer information
 * about the location of the difference in the memory buffers. The return value
 * does not behave like os_memcmp(), i.e., os_memcmp_const() cannot be used to
 * sort items into a defined order. Unlike os_memcmp(), execution time of
 * os_memcmp_const() does not depend on the contents of the compared memory
 * buffers, but only on the total compared length.
 */
int os_memcmp_const(const void *a, const void *b, size_t len);

/*
 * gcc 4.4 ends up generating strict-aliasing warnings about some very common
 * networking socket uses that do not really result in a real problem and
 * cannot be easily avoided with union-based type-punning due to struct
 * definitions including another struct in system header files. To avoid having
 * to fully disable strict-aliasing warnings, provide a mechanism to hide the
 * typecast from aliasing for now. A cleaner solution will hopefully be found
 * in the future to handle these cases.
 */
void * __hide_aliasing_typecast(void *foo);
#define aliasing_hide_typecast(a,t) (t *) __hide_aliasing_typecast((a))

typedef void (*process_callback_fn)(void *buf, size_t count);

int run_command(char *const argv[], char *const envp[], process_callback_fn);

typedef void(*split_string_fn)(const char *, size_t, void *);

ssize_t split_string(const char *str, char sep, split_string_fn fun, void *data);
ssize_t split_string_array(const char *str, char sep, UT_array *arr);
char *allocate_string(char *src);

char *concat_paths(char *path_left, char *path_right);
char *get_valid_path(char *path);
char *construct_path(char *path_left, char *path_right);

char* get_secure_path(UT_array *bin_path_arr, char *filename, char *filehash);

typedef void(*list_dir_fn)(char *, void *args);
int list_dir(char *dirpath, list_dir_fn fun, void *args);

#endif /* OS_H */
