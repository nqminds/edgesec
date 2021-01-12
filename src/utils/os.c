/**************************************************************************************************
*  Filename:        os.c
*  Author:          Alexandru Mereacre (mereacre@gmail.com)
*  Revised:
*  Revision:
*
*  Description:     os source file
*
*  Copyright (C) 2020 NQMCyber Ltd - http://www.nqmcyber.com/
*************************************************************************************************/

#define _GNU_SOURCE
#include <stdint.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdio.h>
#include <limits.h>
#include <libgen.h>
#include <string.h>
#include <stdbool.h>
#include <dirent.h>
#include <ctype.h>

#include "utarray.h"
#include "os.h"
#include "log.h"

#define MAX_64BIT_DIGITS 19

bool is_number(const char *ptr)
{
  if (ptr == NULL)
    return false;

  for (int i = 0; i < MAX_64BIT_DIGITS, ptr[i] != '\0'; i++) {
    if (!isdigit(ptr[i]))
      return false;
  }

  return (*ptr == '\0') ? false : true;
}

static int hex2num(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

int os_get_time(struct os_time *t)
{
	int res;
	struct timeval tv;
	res = gettimeofday(&tv, NULL);
	t->sec = tv.tv_sec;
	t->usec = tv.tv_usec;
	return res;
}

int os_get_reltime(struct os_reltime *t)
{
	int res;
	struct timeval tv;
	res = gettimeofday(&tv, NULL);
	t->sec = tv.tv_sec;
	t->usec = tv.tv_usec;
	return res;
}

int hex2byte(const char *hex)
{
	int a, b;
	a = hex2num(*hex++);
	if (a < 0)
		return -1;
	b = hex2num(*hex++);
	if (b < 0)
		return -1;
	return (a << 4) | b;
}

/**
 * hexstr2bin - Convert ASCII hex string into binary data
 * @hex: ASCII hex string (e.g., "01ab")
 * @buf: Buffer for the binary data
 * @len: Length of the text to convert in bytes (of buf); hex will be double
 * this size
 * Returns: 0 on success, -1 on failure (invalid hex string)
 */
int hexstr2bin(const char *hex, uint8_t *buf, size_t len)
{
	size_t i;
	int a;
	const char *ipos = hex;
	uint8_t *opos = buf;

	for (i = 0; i < len; i++) {
		a = hex2byte(ipos);
		if (a < 0)
			return -1;
		*opos++ = a;
		ipos += 2;
	}
	return 0;
}

/**
 * hwaddr_aton2 - Convert ASCII string to MAC address (in any known format)
 * @txt: MAC address as a string (e.g., 00:11:22:33:44:55 or 0011.2233.4455)
 * @addr: Buffer for the MAC address (ETH_ALEN = 6 bytes)
 * Returns: Characters used (> 0) on success, -1 on failure
 */
int hwaddr_aton2(const char *txt, uint8_t *addr)
{
	int i;
	const char *pos = txt;

	for (i = 0; i < 6; i++) {
		int a, b;

		while (*pos == ':' || *pos == '.' || *pos == '-')
			pos++;

		a = hex2num(*pos++);
		if (a < 0)
			return -1;
		b = hex2num(*pos++);
		if (b < 0)
			return -1;
		*addr++ = (a << 4) | b;
	}

	return pos - txt;
}

/* Try to prevent most compilers from optimizing out clearing of memory that
 * becomes unaccessible after this function is called. This is mostly the case
 * for clearing local stack variables at the end of a function. This is not
 * exactly perfect, i.e., someone could come up with a compiler that figures out
 * the pointer is pointing to memset and then end up optimizing the call out, so
 * try go a bit further by storing the first octet (now zero) to make this even
 * a bit more difficult to optimize out. Once memset_s() is available, that
 * could be used here instead. */
static void * (* const volatile memset_func)(void *, int, size_t) = memset;
static uint8_t forced_memzero_val;

void forced_memzero(void *ptr, size_t len)
{
	memset_func(ptr, 0, len);
	if (len)
		forced_memzero_val = ((uint8_t *) ptr)[0];
}

void bin_clear_free(void *bin, size_t len)
{
	if (bin) {
		forced_memzero(bin, len);
		os_free(bin);
	}
}

size_t os_strlcpy(char *dest, const char *src, size_t siz)
{
	const char *s = src;
	size_t left = siz;

	if (left) {
		/* Copy string up to the maximum size of the dest buffer */
		while (--left != 0) {
			if ((*dest++ = *s++) == '\0')
				break;
		}
	}

	if (left == 0) {
		/* Not enough room for the string; force NUL-termination */
		if (siz != 0)
			*dest = '\0';
		while (*s++)
			; /* determine total src string length */
	}

	return s - src - 1;
}

void * os_zalloc(size_t size)
{
	void *n = os_malloc(size);
	if (n)
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

int os_memcmp_const(const void *a, const void *b, size_t len)
{
	const uint8_t *aa = a;
	const uint8_t *bb = b;
	size_t i;
	uint8_t res;

	for (res = 0, i = 0; i < len; i++)
		res |= aa[i] ^ bb[i];

	return res;
}

int os_get_random(unsigned char *buf, size_t len)
{
	FILE *f;
	size_t rc;

	f = fopen("/dev/urandom", "rb");
	if (f == NULL) {
		log_err("Could not open /dev/urandom.");
		return -1;
	}

	rc = fread(buf, 1, len, f);
	fclose(f);

	return rc != len ? -1 : 0;
}

void * __hide_aliasing_typecast(void *foo)
{
	return foo;
}

int read_command_output(int fd, process_callback_fn fn)
{
  ssize_t read_bytes, count = 0;
  char *buf = os_malloc(PIPE_BUF);

  while((read_bytes = read(fd, buf, PIPE_BUF)) != 0) {
    if (read_bytes == -1 && errno == EAGAIN)
      continue;
    else if (read_bytes == -1 && errno != EAGAIN) {
      os_free(buf);
      return -1;
    } else if (read_bytes != -1) {
      count += read_bytes;
      if (fn != NULL)
        fn(buf, read_bytes);
    }
  }

  os_free(buf);
  return count;
}

int run_command(char *const argv[], char *const envp[], process_callback_fn fn)
{
  pid_t childPid;
  int status;
  int exit_code = 0;
  int pfd[2];                      /* Pipe file descriptors */

  if (argv ==  NULL) {
    log_trace("argv is NULL");
    return 1;
  }

  if (pipe(pfd) == -1)             /* Create pipe */
    log_err_ex("pipe");

  char *command = argv[0];

  log_trace("Running command %s", command);
  fflush(stdout);
  fflush(stderr);

  switch (childPid = fork()) {
  case -1:            /* fork() failed */
    log_err("fork");
    exit_code = 1;
    break;            /* Carry on to reset signal attributes */

  case 0:             /* Child: exec command */

    /* We ignore possible error returns because the only specified error
       is for a failed exec(), and because errors in these calls can't
       affect the caller of system() (which is a separate process) */
    if (close(pfd[0]) == -1)      /* Read end is unused */
      _exit(EXIT_FAILURE);

    if (pfd[1] != STDOUT_FILENO) {              /* Defensive check */
      if (dup2(pfd[1], STDOUT_FILENO) == -1)
        _exit(EXIT_FAILURE);
      if (close(pfd[1]) == -1)
        _exit(EXIT_FAILURE);
    }

    execve(command, argv, envp);

    _exit(EXIT_FAILURE);       /* We could not exec the command */

  default:  /* Parent: wait for our child to terminate */
    if (close(pfd[1]) == -1)   /* Write end is unused */
      log_err_ex("close");

    read_command_output(pfd[0], fn);

    /* We must use waitpid() for this task; using wait() could inadvertently
       collect the status of one of the caller's other children */
    while (waitpid(childPid, &status, 0) == -1) {
      if (errno != EINTR) {       /* Error other than EINTR */
        exit_code = 1;

        break;                    /* So exit loop */
      }
    }

    break;
  }

  if (close(pfd[0]) == -1)   /* Done with read end */
    log_err_ex("close");

  if (WIFEXITED(status)) {
    log_trace("excve status %d", WEXITSTATUS(status));
    return WEXITSTATUS(status);
  }

  return status;
}

void fn_split_string_array(const char *str, size_t len, void *data)
{
  UT_array *strs = (UT_array *) data;
  char *dest = (char *) os_malloc(len + 1);
  if (dest == NULL) {
    log_err_ex("os_malloc");
  }

  memset(dest, '\0', len + 1);
  strncpy(dest, str, len);
  utarray_push_back(strs, &dest);
  os_free(dest);
}

ssize_t split_string(const char *str, char sep, split_string_fn fun, void *data)
{
  size_t start = 0, stop, count = 0;

  if (fun == NULL) {
    log_trace("fun is NULL");
    return -1;
  }

  if (str == NULL) {
    log_trace("str is NULL");
    return -1;
  }

  for (stop = 0; str[stop]; stop++) {
      if (str[stop] == sep) {
          fun(str + start, stop - start, data);
          start = stop + 1;
          count++;
      }
  }

  if (stop - start < 0) {
    fun(str + start, 0, data);
  } else
    fun(str + start, stop - start, data);

  return (ssize_t)(count + 1);
}

ssize_t split_string_array(const char *str, char sep, UT_array *arr)
{
  if (arr == NULL) {
    log_trace("input arr is NULL");
    return -1;   
  }

  return split_string(str, sep, fn_split_string_array, (void *)arr);
}

char *allocate_string(char *src)
{
	char *dest = NULL;
	if (src) {
  	dest = (char *) os_malloc(strlen(src));
		if (dest == NULL) {
			log_err_ex("os_malloc");
		}

		strcpy(dest, src);
	}

	return dest;
}

char *concat_paths(char *path_left, char *path_right)
{
  size_t concat_len;

  if (path_left == NULL && path_right != NULL)
    concat_len = strlen(path_right) + 1;
  else if (path_left != NULL && path_right == NULL)
    concat_len = strlen(path_left) + 1;
  else if (path_left == NULL && path_right == NULL)
    concat_len = 1;
  else
   concat_len = strlen(path_left) + strlen(path_right) + 2;

  char *concat = os_malloc(concat_len);

  if (concat == NULL)
    log_err_ex("os_malloc");

  memset(concat, '\0', concat_len);
  if (path_left != NULL)
    strcat(concat, path_left);

  if (path_left != NULL && path_right != NULL) {
    if (strcmp(path_left, "/") != 0)
      strcat(concat, "/");
  }

  if (path_right != NULL)
    strcat(concat, path_right);

  return concat;
}

char *get_valid_path(char *path)
{
  if (path == NULL)
    return NULL;

  char *dup_dir = strdup(path);
  if (dup_dir == NULL && path != NULL)
    log_err_ex("strdup");
  
  char *dup_base = strdup(path);
  if (dup_base == NULL && path != NULL)
    log_err_ex("strdup");

  char *path_dirname = dirname(dup_dir);
  char *path_basename = basename(dup_base);

  char *concat;
  if (!strlen(path))
    concat = concat_paths(path_dirname, NULL);
  else if (strlen(path) &&
          (strcmp(path, ".") == 0 ||
           strcmp(path, "..") == 0 ||
           strcmp(path, "/") == 0||
           strcmp(path, "//") == 0))
    concat = concat_paths(path, NULL);
  else
    concat = concat_paths(path_dirname, path_basename);

  os_free(dup_dir);
  os_free(dup_base);

  return concat;
}

char *construct_path(char *path_left, char *path_right)
{
  if (path_left == NULL || path_right == NULL)
    return NULL;

  if (!strlen(path_right) && strlen(path_left))
    return get_valid_path(path_left);
  else if (strlen(path_right) && !strlen(path_left))
    return get_valid_path(path_right);
  else if (!strlen(path_right) && !strlen(path_left))
    return get_valid_path("");

  char *valid_left = get_valid_path(path_left);
  char *valid_right = get_valid_path(path_right);
  char *beg_right = valid_right;
  
  if (strlen(valid_right) >= 2) {
    if (valid_right[0] == '.' && valid_right[1] == '/')
      beg_right++;
  }

  char *concat = concat_paths(valid_left, beg_right);
  os_free(valid_left);
  os_free(valid_right);

  char *path = get_valid_path(concat);
  os_free(concat);

  return path;
}

bool check_file_hash(char *filename, const char *filehash)
{
  if (filehash == NULL)
    return true;
  else
    return false;
}

char* get_secure_path(UT_array *bin_path_arr, char *filename, char *filehash)
{
  char **p = NULL;

  if (bin_path_arr == NULL) {
    log_trace("bin_path_arr is NULL");
    return NULL;
  }

  if (filename == NULL) {
    log_trace("filename is NULL");
    return NULL;
  }

  while ((p = (char**) utarray_next(bin_path_arr, p))) {
    struct stat sb;
    char *path = construct_path(*p, filename);

    // Check if file exists
    if (stat(path, &sb) != -1) {
      // Get the real path of the needed path in case it is symbolic link
      char *real_path = realpath(path, NULL);
      log_trace("got real path %s", path);

      if (check_file_hash(real_path, filehash)) {
        os_free(path);
        return real_path;
      }

      os_free(real_path);
    }

    os_free(path);
  }

  return NULL;
}

int list_dir(char *dirpath, list_dir_fn fun, void *args)
{
  DIR *dirp;
  struct dirent *dp;

  /* Open the directory - on failure print an error and return */
  dirp = opendir(dirpath);
  if (dirp == NULL) {
    log_trace("opendir failed on '%s'", dirpath);
    return -1;
  }

  /* Look at each of the entries in this directory */
  for (;;) {
    errno = 0;              /* To distinguish error from end-of-directory */
    dp = readdir(dirp);
    if (dp == NULL)
      break;

    /* Skip . and .. */
    if (strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0)
      continue;

    /* Print directory + filename */
    char *path = construct_path(dirpath, dp->d_name);
    fun(path, args);
    os_free(path);
  }

  if (errno != 0) {
    log_err("readdir");
    return -1;
  }

  if (closedir(dirp) == -1) {
    log_err("closedir");
    return -1;
  }

  return 0;
}