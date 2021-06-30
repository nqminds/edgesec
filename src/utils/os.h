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
 * @file os.h 
 * @author Alexandru Mereacre 
 * @brief File containing the definition of the os functionalities.
 */

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
#include "log.h"

/* Common costant defintions */
#define MAX_OS_PATH_LEN			4096
#define MAX_WEB_PATH_LEN		2048
#define IP_LEN 					20
#define LINK_TYPE_LEN 			64

#define MAX_RANDOM_UUID_LEN		37

#define MAX_SUPERVISOR_CMD_SIZE 40

#define SQLITE_EXTENSION              ".sqlite"
#define PCAP_EXTENSION                ".pcap"

#define MAX_UINT64_DIGITS		20

#ifdef __GNUC__
#define STRUCT_PACKED __attribute__ ((packed))
#else
#define STRUCT_PACKED
#endif

#ifndef MAC2STR
#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"
#define MACSTR_LEN	18		// Including the '\0' character
/*
 * Compact form for string representation of MAC address
 * To be used, e.g., for constructing dbus paths for P2P Devices
 */
#define COMPACT_MACSTR "%02x%02x%02x%02x%02x%02x"
#define COMPACT_MACSTR_LEN	13 // Including the '\0' character
#endif

#ifndef IP2STR
#define IP2STR(a) (a)[0], (a)[1], (a)[2], (a)[3]
#define IPSTR "%d.%d.%d.%d"
#endif

#ifndef IP62STR
#define IP62STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5], (a)[6], (a)[7], (a)[8], (a)[9], (a)[10], (a)[11], (a)[12], (a)[13], (a)[14], (a)[15]
#define IP6STR "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x"
#endif

#ifndef BIT
#define BIT(x) (1U << (x))
#endif

#define STRLEN(s) (sizeof(s)/sizeof(s[0]))

struct find_dir_type {
  int proc_running;
  char *proc_name;
};

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
 * @brief Get current time (sec, usec)
 * 
 * @param t Pointer to buffer for the time
 * @return int 0 on success, -1 on failure
 */
int os_get_time(struct os_time *t);

/**
 * @brief Get relative time (sec, usec)
 * 
 * @param t Pointer to buffer for the time
 * @return int 0 on success, -1 on failure
 */
int os_get_reltime(struct os_reltime *t);


/**
 * @brief Compares the seconds value of two time params
 * 
 * @param a struct os_reltime first param
 * @param b struct os_reltime second param
 * @return int true if a->sec < b->sec
 */
static inline int os_reltime_before(struct os_reltime *a,
				    struct os_reltime *b)
{
	return (a->sec < b->sec) ||
	       (a->sec == b->sec && a->usec < b->usec);
}

/**
 * @brief Subtracts the time value of two time params
 * 
 * @param a struct os_reltime first param
 * @param b struct os_reltime second param
 * @param res The resulting difference of the time params
 */
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

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief get the timestamp in microseconds from system time
 * 
 * @return uint64_t Timestamp in microseconds
 */
uint64_t os_get_timestamp(void);

/**
 * @brief get the timestamp in microseconds from struct timeval
 * 
 * @param ts The input struct timeval
 * @return uint64_t Timestamp in microseconds
 */
uint64_t os_to_timestamp(struct timeval ts);
#ifdef __cplusplus
}
#endif

/**
 * @brief Get cryptographically strong pseudo random data
 * 
 * @param buf Buffer for pseudo random data.
 * @param len Length of the buffer.
 * @return int 0 on success, -1 on failure
 */
int os_get_random(unsigned char *buf, size_t len);

/**
 * @brief Get a random number string
 * 
 * @param buf Buffer for the random string.
 * @param len Length of the buffer.
 * @return int 0 on success, -1 on failure
 */
int os_get_random_number_s(unsigned char *buf, size_t len);

/**
 * @brief Hex two char string to byte convertes 
 * 
 * @param hex Two char string
 * @return int Converted byte
 */
int hex2byte(const char *hex);

/**
 * @brief Convert ASCII hex string into binary data
 * 
 * @param hex ASCII hex string (e.g., "01ab")
 * @param buf Buffer for the binary data
 * @param len Length of the text to convert in bytes (of buf); hex will be double this size
 * @return int 0 on success, -1 on failure (invalid hex string)
 */
int hexstr2bin(const char *hex, uint8_t *buf, size_t len);

/**
 * @brief Convert ASCII string to MAC address (in any known format)
 * 
 * @param txt MAC address as a string (e.g., 00:11:22:33:44:55 or 0011.2233.4455)
 * @param addr Buffer for the MAC address (ETH_ALEN = 6 bytes)
 * @return int Characters used (> 0) on success, -1 on failure
 */
int hwaddr_aton2(const char *txt, uint8_t *addr);

#ifdef __cplusplus
extern "C" {
#endif
/**
 * @brief Check if a string is a number
 * 
 * @param ptr String pointer
 * @return true if numer, false otherwise
 */
bool is_number(const char *ptr);
#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Copy a string with size bound and NUL-termination
 * 
 * This function matches in behavior with the strlcpy(3) function in OpenBSD.
 * 
 * @param dest Destination string
 * @param src Source string
 * @param siz Size of the target buffer
 * @return size_t Total length of the target string (length of src) (not including NUL-termination)
 */
size_t os_strlcpy(char *dest, const char *src, size_t siz);

/**
 * @brief Returns the size of string with a give max length
 * 
 * @param str The string pointer
 * @param max_len The string max length
 * @return size_t Total length of the string
 */
size_t os_strnlen_s(char *str, size_t max_len);

#ifdef __cplusplus
}
#endif

/**
 * @brief Returns a pointer to a new string which is a duplicate of the string s
 * 
 * @param s The input string
 * @return char* The dublicate string pointer, NULL on error
 */
char * os_strdup(const char *s);

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Allocate and zero memory
 * 
 * Caller is responsible for freeing the returned buffer with os_free().
 * 
 * @param size Number of bytes to allocate
 * @return void* Pointer to allocated and zeroed memory or %NULL on failure
 */
void * os_zalloc(size_t size);
#ifdef __cplusplus
}
#endif


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
static inline void * os_calloc(size_t nmemb, size_t size)
{
	if (size && nmemb > (~(size_t) 0) / size)
		return NULL;
	return os_zalloc(nmemb * size);
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

static inline void * os_realloc_array(void *ptr, size_t nmemb, size_t size)
{
	if (size && nmemb > (~(size_t) 0) / size)
		return NULL;
	return os_realloc(ptr, nmemb * size);
}

/**
 * @brief Constant time memory comparison
 *
 * This function is meant for comparing passwords or hash values where
 * difference in execution time could provide external observer information
 * about the location of the difference in the memory buffers. The return value
 * does not behave like os_memcmp(), i.e., os_memcmp_const() cannot be used to
 * sort items into a defined order. Unlike os_memcmp(), execution time of
 * os_memcmp_const() does not depend on the contents of the compared memory
 * buffers, but only on the total compared length.
 *
 * @param a First buffer to compare
 * @param b Second buffer to compare
 * @param len Number of octets to compare
 * @return int 0 if buffers are equal, non-zero if not
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

typedef void (*process_callback_fn)(void *ctx, void *buf, size_t count);

/**
 * @brief Executes a command
 * 
 * @param argv The command arguments including the process path
 * @param envp The environment variables
 * @param process_callback_fn Callback function
 * @param ctx The callback function context
 * @return int excve status code
 */
int run_command(char *const argv[], char *const envp[], process_callback_fn, void *ctx);

/**
 * @brief Convert the string to upper case
 * 
 * @param s The input string
 */
void upper_string(char *s);

/**
 * @brief Replace a character in a string with a given characater
 * 
 * @param s The input string
 * @param in The character to be replaced
 * @param out The character to replace with
 */
void replace_string_char(char *s, char in, char out);

typedef int(*split_string_fn)(const char *, size_t, void *);

/**
 * @brief Splits a string into substrings (execute callback function)
 * 
 * @param str String to split
 * @param sep String separator
 * @param fun Callback function
 * @param data Param for callback function
 * @return ssize_t number of stubstrings
 */
ssize_t split_string(const char *str, char sep, split_string_fn fun, void *data);

/**
 * @brief Splits a string into substrings (save to array)
 * 
 * @param str String to split
 * @param sep String separator
 * @param arr Array to save the substrings
 * @return ssize_t number of stubstrings
 */
ssize_t split_string_array(const char *str, char sep, UT_array *arr);

/**
 * @brief Concatenate two string paths
 * 
 * @param path_left First string path
 * @param path_right Second string path
 * @return char* Concatenated paths
 */
char *concat_paths(char *path_left, char *path_right);

/**
 * @brief Get the valid path string
 * 
 * @param path Input string path
 * @return char* output valid path
 */
char *get_valid_path(char *path);

#ifdef __cplusplus
extern "C" {
#endif
/**
 * @brief Construct a valid path from two paths
 * 
 * @param path_left First path
 * @param path_right Second path
 * @return char* output valid path
 */
char *construct_path(char *path_left, char *path_right);
#ifdef __cplusplus
}
#endif

/**
 * @brief Get the secure path string of a binary
 * 
 * @param bin_path_arr The path string of binary
 * @param filename The binary name
 * @param filehash The binary hashstring
 * @return char* teh secure path
 */
char* get_secure_path(UT_array *bin_path_arr, char *filename, char *filehash);

#ifdef __cplusplus
extern "C" {
#endif

typedef bool(*list_dir_fn)(char *, void *args);

/**
 * @brief List the files in a directory
 * 
 * @param dirpath The directory path
 * @param fun The callback function
 * @param args The callback function arguments
 * @return int 
 */
int list_dir(char *dirpath, list_dir_fn fun, void *args);
#ifdef __cplusplus
}
#endif

/**
 * @brief Check if a process path from /proc folder contains the process name
 * 
 * @param path The process path from /proc fodler
 * @param proc_name The process name
 * @return long The process PID
 */
long is_proc_app(char *path, char *proc_name);

/**
 * @brief Kill a process by name
 * 
 * @param proc_name The process name
 * @return bool true on success, false otherwise 
 */
bool kill_process(char *proc_name);

/**
 * @brief Signal a process
 * 
 * @param proc_name The process name
 * @param sig The signal value
 * @return true on success, false on failure
 */
bool signal_process(char *proc_name, int sig);

/**
 * @brief Executes a process with an array of strign arguments
 * 
 * @param argv The array of string arguments terminated with NULL and the first argument is the absolute path of the process.
 * @param child_pid The returned child pid
 * @return int 1 if process started, 0 if the child specified by pid exist, but have not yet changed state, -1 on error
 */
int run_process(char *argv[], pid_t *child_pid);

/**
 * @brief Makes a file given by descriptor executable
 * 
 * @param fd File descriptor
 * @return int 0 on succes, -1 on error
 */
int make_file_exec_fd(int fd);

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Right trim the string
 * 
 * @param str The source string
 * @param seps The separator string, if NULL then the separator used is "\t\n\v\f\r "
 * @return char* The pointer to the source string
 */
char *rtrim(char *str, const char *seps);
#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Concatenates an array of strings into a single string
 * 
 * @param strings The array of string, the last element is NULL
 * @return char* The concatenated string
 */
char* string_array2string(char *strings[]);

/**
 * @brief Generates a random UUID string of MAX_RANDOM_UUID_LEN - 1 characters long not including '\0'
 * 
 * @param rid The output string of MAX_RANDOM_UUID_LEN bytes
 */
void generate_radom_uuid(char *rid);
#ifdef __cplusplus
}
#endif

/**
 * @brief Callback function for list_dir function to check if process running
 * 
 * @param path The process path
 * @param args The callback arguments of type struct find_dir_type
 * @return bool true if process running, false otherwise
 */
bool find_dir_proc_fn(char *path, void *args);

/**
 * @brief Check if folder exists
 * 
 * @param dirpath The folder path
 * @return bool true on success, false on failure 
 */
bool exist_dir(char *dirpath);
#endif /* OS_H */
