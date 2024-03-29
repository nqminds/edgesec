/**
 * @file
 * @author Alexandru Mereacre
 * @date 2020
 * @copyright
 * SPDX-FileCopyrightText: © 2020 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the definition of the os functionalities.
 */

#ifndef OS_H
#define OS_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/time.h> // required for `struct timeval`
#include <sys/types.h>
#include <unistd.h>
#include <utarray.h>

#include "hashmap.h"
#include "log.h"

/* Common costant definitions */
#define MAX_OS_PATH_LEN 4096
#define MAX_WEB_PATH_LEN 2048
#define MAX_RANDOM_UUID_LEN 37

#define OS_HOST_NAME_MAX 64

#ifndef BIT
#define BIT(x) (1U << (x))
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(s) (sizeof(s) / sizeof(s[0]))
#endif

#define BD_NO_CHDIR 01       /* Don't chdir("/") */
#define BD_NO_CLOSE_FILES 02 /* Don't close all open files */
#define BD_NO_REOPEN_STD_FDS                                                   \
  04                     /* Don't reopen stdin, stdout, and                    \
                            stderr to /dev/null */
#define BD_NO_UMASK0 010 /* Don't do a umask(0) */
#define BD_MAX_CLOSE                                                           \
  8192 /* Maximum file descriptors to close if                                 \
         sysconf(_SC_OPEN_MAX) is indeterminate */

#ifndef os_strlen
// Used by code taken from hostapd
#define os_strlen(s) strlen((s))
#endif

#ifndef os_snprintf
#define os_snprintf(s, maxlen, ...) snprintf((s), (maxlen), __VA_ARGS__)
#endif

#ifndef os_strncmp
#define os_strncmp(s1, s2, n) strncmp((s1), (s2), (n))
#endif

#ifndef os_strstr
/**
 * @brief Macro to strstr() for code taken from hostap.
 * @remarks strstr() is a type-generic function in C23 and might not return a
 * a `char *`.
 */
#define os_strstr(s1, s2) strstr((s1), (s2))
#endif

#ifndef os_strcmp
#define os_strcmp(s1, s2) strcmp((s1), (s2))
#endif

#ifndef os_strchr
/**
 * @brief Macro to strchr() for code taken from hostap.
 * @remarks strchr() is a type-generic function in C23, and might return a
 * `const char *` instead of a `char *`.
 */
#define os_strchr(s, c) strchr((s), (c))
#endif

struct find_dir_type {
  int proc_running;
  const char *proc_name;
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
 * @brief Becomes a daemon
 *
 * @copyright Michael Kerrisk, 2019.
 * @param flags Flags fpor deamon settings
 * @return int 0 on success, -1 on failure
 */
int become_daemon(int flags);

#define os_get_time(t) edge_os_get_time(t)

/**
 * @brief Get current time (sec, usec) in seconds since UNIX epoch.
 *
 * @param[out] t Pointer to buffer for the time
 * If there is a failure, may write invalid data.
 * @return int 0 on success, -1 on failure
 */
int edge_os_get_time(struct os_time *t);

/**
 * @brief Get relative time (sec, usec)
 *
 * Unlike edge_os_get_time(), the time from this function will never go
 * backwards (e.g. due to NTP).
 *
 * @param[out] t Pointer to buffer for the time.
 * If there is a failure, may write invalid data.
 * @return int 0 on success, -1 on failure
 */
int edge_os_get_reltime(struct os_reltime *t);

#ifndef os_get_reltime
#define os_get_reltime(t) edge_os_get_reltime((t))
#endif

/**
 * @brief Compares the seconds value of two time params
 *
 * @param a struct os_reltime first param
 * @param b struct os_reltime second param
 * @return int true if a->sec < b->sec
 */
static inline int os_reltime_before(const struct os_reltime *a,
                                    const struct os_reltime *b) {
  return (a->sec < b->sec) || (a->sec == b->sec && a->usec < b->usec);
}

/**
 * @brief Subtracts the time value of two time params
 *
 * @param[in] a struct os_reltime first param
 * @param[in] b struct os_reltime second param
 * @param[out] res The resulting difference of the time params
 */
static inline void os_reltime_sub(const struct os_reltime *a,
                                  const struct os_reltime *b,
                                  struct os_reltime *res) {
  *res = (struct os_reltime){
      .sec = a->sec - b->sec,
      .usec = a->usec - b->usec,
  };
  if (res->usec < 0) {
    res->sec--;
    res->usec += 1000000;
  }
}

/**
 * @brief get the timestamp in microseconds from system time
 *
 * @param[out] timestamp The returned timestamp
 * @return int 0 on success, -1 on failure
 */
int os_get_timestamp(uint64_t *timestamp);

/**
 * @brief get the timestamp in microseconds from struct timeval
 *
 * @param[in] ts The input struct timeval
 * @param[out] timestamp The returned timestamp
 */
void os_to_timestamp(struct timeval ts, uint64_t *timestamp);

#define os_get_random(buf, len) edge_os_get_random((buf), (len))

/**
 * @brief Get cryptographically strong pseudo random data
 *
 * @param buf Buffer for pseudo random data.
 * @param len Length of the buffer.
 * @return int 0 on success, -1 on failure
 */
int edge_os_get_random(unsigned char *buf, size_t len);

/**
 * @brief Return a random int from a give range
 *
 * @param low The range lower bound
 * @param up The range upper bound
 * @return int The returned random int
 */
int os_get_random_int_range(int low, int up);

/**
 * @brief Initialises the random seed
 *
 */
void os_init_random_seed(void);

/**
 * @brief Get a random number string
 *
 * @param buf Buffer for the random string.
 * @param len Length of the buffer.
 * @return int 0 on success, -1 on failure
 */
int os_get_random_number_s(unsigned char *buf, size_t len);

/**
 * @brief Hex char to number
 * @code{.c}
 * // returns 0x9 aka 9 aka '\x09'
 * hex2num('9')
 * @endcode
 * @param[in] c Hex char
 * @return Converted byte from 0-15, or `-1` on error.
 */
int8_t hex2num(char c);

/**
 * @brief Convert ASCII hex string into binary data
 *
 * @param hex ASCII hex string (e.g., "01ab")
 * @param buf Buffer for the binary data
 * @param len Length of the text to convert in bytes (of buf); hex will be
 * double this size
 * @return int 0 on success, -1 on failure (invalid hex string)
 */
int edge_hexstr2bin(const char *hex, uint8_t *buf, size_t len);

/**
 * @brief Check if a string is a number
 *
 * @param ptr String pointer
 * @return true if numer, false otherwise
 */
bool is_number(const char *ptr);

#define os_strlcpy(dest, src, siz) edge_os_strlcpy((dest), (src), (siz))

/**
 * @brief Copy a string with size bound and NUL-termination
 *
 * This function matches in behavior with the strlcpy(3) function in OpenBSD.
 *
 * @param dest Destination string
 * @param src Source string
 * @param siz Size of the target buffer
 * @return size_t Total length of the target string (length of src) (not
 * including NUL-termination)
 */
size_t edge_os_strlcpy(char *restrict dest, const char *restrict src,
                       size_t siz);

/**
 * @brief Returns the size of string with a give max length
 *
 * @param[in] str The string pointer
 * @param max_len The string max length
 * @return Total length of the string, or `max_len` if the string is
 * longer than `max_len`.
 */
size_t os_strnlen_s(const char *str, size_t max_len);

#define os_memcmp_const(a, b, len) edge_os_memcmp_const((a), (b), (len))

/**
 * @brief Constant time memory comparison
 *
 * This function is meant for comparing passwords or hash values where
 * difference in execution time could provide external observer information
 * about the location of the difference in the memory buffers. The return value
 * does not behave like os_memcmp(), i.e., edge_os_memcmp_const() cannot be used
 * to sort items into a defined order. Unlike os_memcmp(), execution time of
 * edge_os_memcmp_const() does not depend on the contents of the compared memory
 * buffers, but only on the total compared length.
 *
 * @param a First buffer to compare
 * @param b Second buffer to compare
 * @param len Number of octets to compare
 * @return int 0 if buffers are equal, non-zero if not
 */
int edge_os_memcmp_const(const void *a, const void *b, size_t len);

/*
 * gcc 4.4 ends up generating strict-aliasing warnings about some very common
 * networking socket uses that do not really result in a real problem and
 * cannot be easily avoided with union-based type-punning due to struct
 * definitions including another struct in system header files. To avoid having
 * to fully disable strict-aliasing warnings, provide a mechanism to hide the
 * typecast from aliasing for now. A cleaner solution will hopefully be found
 * in the future to handle these cases.
 */
void *__hide_aliasing_typecast(void *foo);
#define aliasing_hide_typecast(a, t) (t *)__hide_aliasing_typecast((a))

/**
 * @brief Callback function for run_command() and similar functions.
 * @param ctx - Context, passed to run_command().
 * @param buf - data from stdout. Warning, if this is a string, you may
 * have to add your own NUL-terminator.
 * @param count - Length of data from stdout.
 */
typedef void (*process_callback_fn)(void *ctx, void *buf, size_t count);

/**
 * @brief Makes a copy of argv
 *
 * When writing code, we normally define argv using `const char *` string
 * literals, e.g.: `const char * args[] {"hello", "world", NULL};`
 *
 * However, the C functions (e.g. execve()) expect `char * const *`,
 * aka the strings must be mallable (unsafe with string literals).
 *
 * This function makes a copy of argv so that we don't get undefined
 * behaviour by modifing `const` data.
 *
 * The entire argv array (and strings) is allocated as a single malloc()
 * so that you can use a single free() to release the memory when done.
 *
 * @param argv The NULL-terminated array of '\0'-terminated strings to copy.
 * @return A modifiable copy of argv, or @p NULL if malloc() failed.
 * @post Use `free()` when finished with the @p argv_copy.
 */
char **copy_argv(const char *const argv[]);

/**
 * @brief Executes a command
 *
 * @param argv The command arguments including the process path
 * @param envp The environment variables
 * @param fn Callback function
 * @param ctx The callback function context
 * @return int excve status code
 */
int run_command(char *const argv[], char *const envp[], process_callback_fn fn,
                void *ctx);

/**
 * @brief Executes a command with argument
 *
 * @param path The command path
 * @param argv The command arguments without the process path
 * @param fn Callback function
 * @param ctx The callback function context
 * @retval -1 Returns -1 on error.
 * @retval  0 Returns 0 on success.
 */
int run_argv_command(const char *path, const char *const argv[],
                     process_callback_fn fn, void *ctx);

/**
 * @brief Replace a character in a string with a given characater
 *
 * @param s The input string
 * @param in The character to be replaced
 * @param out The character to replace with
 */
void replace_string_char(char *s, char in, char out);

typedef int (*split_string_fn)(const char *, size_t, void *);

/**
 * @brief Splits a string into substrings (execute callback function)
 *
 * @param str String to split
 * @param sep String separator
 * @param fun Callback function
 * @param data Param for callback function
 * @return ssize_t number of stubstrings
 */
ssize_t split_string(const char *str, char sep, split_string_fn fun,
                     void *data);

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
 * @return Concatenated paths. Please `free()` the return value when done.
 * @retval NULL on memory allocation error.
 */
char *concat_paths(const char *path_left, const char *path_right);

/**
 * @brief Get the valid path string
 *
 * @param path Input string path
 * @return Output valid path. Please free() this string when done with it.
 * @retval NULL on memory allocation error.
 */
char *get_valid_path(const char *path);

/**
 * @brief Construct a valid path from two paths
 *
 * @param path_left First path
 * @param path_right Second path
 * @return The output valid path. Please free() this string when done with it.
 * @retval NULL on memory allocation error.
 */
char *construct_path(const char *path_left, const char *path_right);

/**
 * @brief Get the secure path string of a binary
 *
 * @param bin_path_arr The path string of binary
 * @param filename The binary name
 * @param real true to return the real link
 * @return The secure path, or NULL on error. Must be freed with os_free().
 */
char *get_secure_path(const UT_array *bin_path_arr, const char *filename,
                      bool real);

typedef bool (*list_dir_fn)(char *, void *args);

/**
 * @brief List the files in a directory
 *
 * @param dirpath The directory path
 * @param fun The callback function
 *            If this function ever returns `false`, list_dir will return `-1`.
 * @param args The callback function arguments
 * @retval  0 On success
 * @retval -1 On error
 */
int list_dir(const char *dirpath, list_dir_fn fun, void *args);

/**
 * @brief Check if the given process's basename matches proc_name.
 *
 * Checks both:
 * - the realpath (aka `/proc/[pid]/exe`), and
 * - the given argv0 (from `/proc/[pid]/cmdline`).
 *
 * As an example, if a process was started with `/usr/bin/gcc`,
 * which is a symlink to `/usr/bin/x86_64-linux-gnu-gcc-11`,
 * then both`is_proc_app(..., "gcc")` AND `is_proc_app(...,
 * "x86_64-linux-gnu-gcc-11")` will work.
 *
 * @param path The `/proc/[pid]` folder for the process
 * @param proc_name The process name to search for.
 * @return The process PID if the process's basename contains the given
 * `proc_name` string, or `0` if it doesn't.
 */
pid_t is_proc_app(const char *path, const char *proc_name);

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
 * @param[in] proc_name The process name
 * @param sig The signal value
 * @return true on success, false on failure
 */
bool signal_process(const char *proc_name, int sig);

/**
 * @brief Executes a background process with an array of string arguments.
 *
 * @param[in] argv The array of string arguments terminated with NULL and the
 * first argument is the absolute path of the process.
 * @param[out] child_pid The returned child pid
 * @retval     0 The child process has been created, and is either:
 *   - still running, OR
 *   - exited with exit code 0
 * @retval    -1 Error, please see `errno` for more details.
 * @retval 1-255 The child process has exited,
 *   and the return value is this non-zero/error exit code.
 */
int run_process(char *argv[], pid_t *child_pid);

/**
 * @brief Check if a process is running
 *
 * @param name The process name
 * @return int 1 if running, 0 otherwise, -1 on failure
 */
int is_proc_running(const char *name);

/**
 * @brief Makes a file given by descriptor executable
 *
 * @param fd File descriptor
 * @return int 0 on succes, -1 on error
 */
int make_file_exec_fd(int fd);

/**
 * @brief Right trim the string
 *
 * @param str The source string
 * @param seps The separator string, if NULL then the separator used is
 * "\t\n\v\f\r "
 * @return char* The pointer to the source string
 */
char *rtrim(char *str, const char *seps);

/**
 * @brief Concatenates an array of strings into a single string
 *
 * @param strings The array of string, the last element is NULL
 * @return The concatenated string, which must be `free()`-ed when done, or
 * `NULL` on error.
 */
char *string_array2string(const char *const strings[]);

/**
 * @brief Generates a random UUID string of MAX_RANDOM_UUID_LEN - 1 characters
 * long not including '\0'
 *
 * @param[out] rid The output string of MAX_RANDOM_UUID_LEN bytes
 */
void generate_radom_uuid(char rid[static MAX_RANDOM_UUID_LEN]);

/**
 * @brief Callback function for list_dir function to check if process running
 *
 * @param[in] path The process path
 * @param[in,out] args The callback arguments of type struct find_dir_type
 * @return bool true if process running, false otherwise
 */
bool find_dir_proc_fn(char *path, void *args);

/**
 * @brief Check if folder exists
 *
 * @param dirpath The folder path
 * @return int 1 if exists, 0 otherwise, -1 on failure
 */
int exist_dir(const char *dirpath);

/**
 * @brief Recurisvely create directories to the given path
 *
 * Creates the directories recursively to the given path.
 *
 * Does **NOT** create the final file, use create_dir()
 * if you want if you want to create the entire path
 * as dirs.
 *
 * Example:
 *
 * ```cpp
 * // will create the directories /var/run/exampledir/
 * make_dirs_to_path("/var/run/exampledir/example.pid", 0755);
 * ```
 *
 * @param[in] file_path The directories to create to the path.
 * @param mode The folder create mode.
 * @return 0 on success, -1 on failure.
 * @see Original source-code used under fair-use from
 *   https://stackoverflow.com/a/9210960
 */
int make_dirs_to_path(const char *file_path, mode_t mode);

/**
 * @brief Creates a folder recursively.
 *
 * If the parent folders do not exist, creates them too.
 *
 * @param[in] dirpath The folder path
 * @param mode The folder creation mode
 * @return 0 on success, -1 on failure
 */
int create_dir(const char *dirpath, mode_t mode);

/**
 * @brief Creates a FIFO pipe file.
 *
 * @param[in] path The path to the pipe file
 * @return 0 on success, -1 on failure
 */
int create_pipe_file(const char *path);

/**
 * @brief Check if a file exists
 *
 * @param[in] path The path to the file
 * @param[out] sb If non-NULL, stores the stats of the file.
 * @return 0 if it exists, -1 on failure
 */
int check_file_exists(const char *path, struct stat *sb);

/**
 * @brief Check if a socket file exists
 *
 * @param path The path to the socket file
 * @return 0 if it exists, -1 otherwise
 */
int check_sock_file_exists(const char *path);

/**
 * @brief Get the hostname of the running machine
 *
 * @param[out] buf Buffer to store the returned hostname.
 * Must be at least `OS_HOST_NAME_MAX` bytes long.
 * **Warning**, this string might not be NULL-terminated if it's
 * exactly `OS_HOST_NAME_MAX` bytes long.
 * @return int 0 on success, -1 on failure
 */
int get_hostname(char buf[static OS_HOST_NAME_MAX]);

/**
 * @brief Open/create the file named in 'pidFile', lock it, optionally set the
   close-on-exec flag for the file descriptor, write our PID into the file,
   and (in case the caller is interested) return the file descriptor
   referring to the locked file. The caller is responsible for deleting
   'pidFile' file (just) before process termination. 'progName' should be the
   name of the calling program (i.e., argv[0] or similar), and is used only for
   diagnostic messages. If we can't open 'pidFile', or we encounter some other
   error, then we print an appropriate diagnostic and terminate.
 *
 * @param pid_file The pid file path to create
 * @param flags The pid file open flags
 * @return int The pif file descriptor, -1 on failure
 */
int create_pid_file(const char *pid_file, int flags);

/**
 * @brief Read the entire file
 *
 * @param path The file path
 * @param[out] out Pointer to the output buffer, or NULL on error.
 * Will be `malloc()`-ed, so you must free() this when done.
 * @return ssize_t The file size, -1 on failure
 */
ssize_t read_file(const char *path, uint8_t **out);

/**
 * @brief Read the entire file into a string
 *
 * @param[in] path The file path
 * @param[out] out The pointer to the output string. You must `free()` this
 * variable if `read_file_string()` is successful.
 * @return 0 on success, -1 on failure
 */
int read_file_string(const char *path, char **out);

/**
 * @brief Opens a file for writing and write a
 * a buffer in nonblocking mode
 *
 * @param path[in] The file path
 * @param fd[in, out] The file descriptor.
 * If this is non-`0`, opens the file given by @p path,
 * and sets @p fd to the new file descriptor.
 * Otherwise, @p path is ignored, and @p fd is used.
 * Please close the created @p fd when done with it.
 * @param buffer[in] The buffer to write
 * @param length[in] The size of the buffer
 * @return number of bytes written, -1 on failure
 */
ssize_t open_write_nonblock(const char *path, int *fd, const uint8_t *buffer,
                            size_t length);

/**
 * @brief Returns the absolute path of system binaries
 *
 * @param[in] commands Array of system binaries name strings. The last entry
 * must be a `NULL` ptr.
 * @param[in] bin_path_arr Array of system binaries default search paths
 * @param[out] hmap_bin_paths The created map of system binary to absolute path.
 * @return int 0 on success, -1 on failure
 */
int get_commands_paths(const char *commands[], const UT_array *bin_path_arr,
                       hmap_str_keychar **hmap_bin_paths);

/**
 * @brief Append a character to a string and return the new string
 *
 * The returned pointer must be passed to `free()` to avoid a memory leak.
 *
 * @param[in] str The string to append to
 * @param character The character to append
 * @return The appended string on success, NULL on failure
 */
char *string_append_char(const char *str, char character);
#endif /* OS_H */
