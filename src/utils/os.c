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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <libgen.h>
#include <limits.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
// #include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <uuid/uuid.h>

#include "allocs.h"
#include "hashmap.h"
#include "log.h"
#include "os.h"

#define MAX_64BIT_DIGITS 19

struct proc_signal_arg {
  char *proc_name;
  int sig;
};

int become_daemon(int flags) {
  /* Become background process */
  switch (fork()) {
    case -1:
      return -1;
    case 0:
      break; /* Child falls through... */
    default:
      _exit(EXIT_SUCCESS); /* while parent terminates */
  }

  /* Become leader of new session */
  if (setsid() == -1) {
    return -1;
  }

  /* Ensure we are not session leader */
  switch (fork()) {
    case -1:
      return -1;
    case 0:
      break;
    default:
      _exit(EXIT_SUCCESS);
  }

  /* Clear file mode creation mask */
  if (!(flags & BD_NO_UMASK0)) {
    umask(0);
  }

  /* Change to root directory */
  if (!(flags & BD_NO_CHDIR)) {
    if (chdir("/") == -1) {
      return -1;
    }
  }

  /* Close all open files */
  if (!(flags & BD_NO_CLOSE_FILES)) {
    long maxfd = sysconf(_SC_OPEN_MAX);

    /* Limit is indeterminate... */
    if (maxfd == -1) {
      maxfd = BD_MAX_CLOSE; /* so take a guess */
    }
    int maxfd_int = maxfd > INT_MAX ? INT_MAX : (int)maxfd;

    for (int fd = 0; fd < maxfd_int; fd++) {
      close(fd);
    }
  }

  if (!(flags & BD_NO_REOPEN_STD_FDS)) {
    /* Reopen standard fd's to /dev/null */
    close(STDIN_FILENO);

    /* 'fd' should be 0 */
    if (open("/dev/null", O_RDWR) != STDIN_FILENO) {
      return -1;
    }

    if (dup2(STDIN_FILENO, STDOUT_FILENO) != STDOUT_FILENO) {
      return -1;
    }

    if (dup2(STDIN_FILENO, STDERR_FILENO) != STDERR_FILENO) {
      return -1;
    }
  }

  return 0;
}

bool is_number(const char *ptr) {
  int offset = 0;
  if (ptr == NULL)
    return false;

  if (ptr[0] == '-' || ptr[0] == '+')
    offset = 1;

  if (strlen(ptr) && offset && ptr[1] == '\0') {
    return false;
  }

  for (int i = offset; i < MAX_64BIT_DIGITS && ptr[i] != '\0'; i++) {
    if (!isdigit(ptr[i]))
      return false;
  }

  return (*ptr == '\0') ? false : true;
}

int8_t hex2num(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

int edge_os_get_time(struct os_time *t) {
  int res;
  struct timeval tv;
  res = gettimeofday(&tv, NULL);
  t->sec = tv.tv_sec;
  t->usec = tv.tv_usec;
  return res;
}

int edge_os_get_reltime(struct os_reltime *t) {
  int res;
  struct timeval tv;
  res = gettimeofday(&tv, NULL);
  t->sec = tv.tv_sec;
  t->usec = tv.tv_usec;
  return res;
}

/**
 * @brief ASCII hex character pair to byte
 * @code{.c}
 * // returns 0x91 aka 145 aka '\x91'
 * hex2byte("91")
 * @endcode
 *
 * @param hex Two char string
 * @return Converted byte, or `-1` on error.
 */
static inline int16_t hex2byte(const char hex[static 2]) {
  int_fast8_t a = hex2num(*hex++);
  if (a < 0)
    return -1;
  int_fast8_t b = hex2num(*hex++);
  if (b < 0)
    return -1;
  return (a << 4) | b;
}

int edge_hexstr2bin(const char *hex, uint8_t *buf, size_t len) {
  const char *ipos = hex;
  uint8_t *opos = buf;

  for (size_t i = 0; i < len; i++) {
    int_fast16_t a = hex2byte(ipos);
    if (a < 0)
      return -1;
    *opos++ = (uint8_t)a; // should always be between 0-255
    ipos += 2;
  }
  return 0;
}

size_t edge_os_strlcpy(char *restrict dest, const char *restrict src,
                       size_t siz) {
  /* Copy string up to the maximum size of the dest buffer */
  const char *char_after_NUL = memccpy(dest, src, '\0', siz);

  if (char_after_NUL != NULL) {
    return (size_t)(char_after_NUL - dest - 1);
  } else {
    /* Not enough room for the string; force NUL-termination */
    dest[siz - 1] = '\0';
    /* determine total src string length */
    return strlen(src);
  }
}

int edge_os_memcmp_const(const void *a, const void *b, size_t len) {
  const uint8_t *aa = a;
  const uint8_t *bb = b;
  size_t i;
  uint8_t res;

  for (res = 0, i = 0; i < len; i++)
    res |= aa[i] ^ bb[i];

  return res;
}

int edge_os_get_random(unsigned char *buf, size_t len) {
  FILE *f;
  size_t rc;

  f = fopen("/dev/urandom", "rb");
  if (f == NULL) {
    log_errno("Could not open /dev/urandom.");
    return -1;
  }

  rc = fread(buf, 1, len, f);
  fclose(f);

  return rc != len ? -1 : 0;
}

int os_get_random_int_range(int low, int up) {
  return rand() % (up - low + 1) + low;
}

void os_init_random_seed(void) {
  int_fast64_t current_time = time(NULL);
  srand((unsigned int)current_time);
}

int os_get_random_number_s(unsigned char *buf, size_t len) {
  size_t idx = 0;
  if (os_get_random(buf, len) < 0) {
    log_trace("os_get_random fail");
    return -1;
  }

  for (idx = 0; idx < len; idx++) {
    buf[idx] = (buf[idx] % 10) + '0';
  }

  return 0;
}

void *__hide_aliasing_typecast(void *foo) { return foo; }

int read_command_output(int fd, process_callback_fn fn, void *ctx) {
  ssize_t read_bytes, count = 0;
  char *buf = os_malloc(PIPE_BUF);

  errno = 0;
  while ((read_bytes = read(fd, buf, PIPE_BUF)) != 0) {
    if (read_bytes == -1 && errno == EAGAIN) {
      errno = 0;
      continue;
    } else if (read_bytes == -1 && errno != EAGAIN) {
      os_free(buf);
      return -1;
    } else if (read_bytes != -1) {
      count += read_bytes;
      if (fn != NULL)
        fn(ctx, buf, read_bytes);
    }
  }

  os_free(buf);
  return count;
}

char **copy_argv(const char *const argv[]) {
  if (argv == NULL) {
    log_error("argv param is NULL");
    return NULL;
  }

  // argc is the length of argv (excluding the NULL terminator)
  size_t argc = 0;
  while (argv[argc] != NULL) {
    argc++;
  }

  // calculate the new argv buffer size
  size_t argv_array_size = (argc + 1) * sizeof(char *);
  size_t strings_length = 0;
  for (size_t i = 0; i < argc; i++) {
    strings_length += (strlen(argv[i]) + 1);
  }

  /**
   * @brief Array of strings.
   *
   * The first part of the malloc-d data hold argv, which is an array of `char
   * *`. The second part of the malloc-d data is a buffer containing all the
   * string data (e.g. `char`).
   *
   * E.g., for example, a copy of
   * ```c
   * const char* argv[] = {"Hello", "World!", NULL};
   * ```
   * will look something like the following (for 64-bit ptrs):
   *
   * | **Address** |   0-7 |  8-15 | 16-23 |   24-29 |    30-36 |
   * | ----------- | ----: | ----: | ----: | ------- | -------- |
   * |  **CType**  | char* | char* | char* |  char[] |   char[] |
   * |  **Value**  |    24 |    30 |  NULL | "Hello" | "World!" |
   */
  char **const argv_copy = (char **)malloc(argv_array_size + strings_length);
  if (argv_copy == NULL) {
    log_errno("Failed to malloc %d bytes", argv_array_size + strings_length);
    return NULL;
  }

  /**
   * Pointer to beginning of string buffer within argv_copy.
   * This is a separate variable as it's a different type to `copy_argv[0]`
   * (char vs char *), and therefore pointer arthmetic gets complicated.
   */
  char *const argv_string_buffer = &((char *)argv_copy)[argv_array_size];

  // copy old argv into new argv buffer
  size_t string_bytes = 0;
  for (size_t i = 0; i < argc; i++) {
    // Set pointer to string
    argv_copy[i] = &(argv_string_buffer[string_bytes]);
    // Set string contents
    strcpy(argv_copy[i], argv[i]);
    string_bytes += (strlen(argv[i]) + 1);
  }
  // argv array must end with NULL terminator
  argv_copy[argc] = NULL;
  return argv_copy;
}

int run_command(char *const argv[], char *const envp[], process_callback_fn fn,
                void *ctx) {
  pid_t childPid;
  int status;
  int exit_code = 0;
  int pfd[2]; /* Pipe file descriptors */
  char *command = NULL;

  if (argv == NULL) {
    log_trace("argv is NULL");
    return 1;
  }

  command = argv[0];
  if (command == NULL) {
    log_trace("run command is NULL");
    return 1;
  }

  if (check_file_exists(command, NULL) < 0) {
    log_trace("check_file_exists fail");
    return -1;
  }

  /* Create pipe */
  if (pipe(pfd) == -1) {
    log_errno("pipe");
    return 1;
  }

  fflush(stdout);
  fflush(stderr);

  switch (childPid = fork()) {
    case -1: /* fork() failed */
      log_errno("fork");
      return 1;

    case 0: /* Child: exec command */

      if (fn == NULL) {
        /* redirect stdout, stdin and stderr to /dev/null */
        close(STDIN_FILENO);

        /* Reopen standard fd's to /dev/null */
        int fd = open("/dev/null", O_RDWR);

        if (fd != STDIN_FILENO) /* 'fd' should be 0 */
          _exit(EXIT_FAILURE);
        if (dup2(STDIN_FILENO, STDOUT_FILENO) != STDOUT_FILENO)
          _exit(EXIT_FAILURE);
        if (dup2(STDIN_FILENO, STDERR_FILENO) != STDERR_FILENO)
          _exit(EXIT_FAILURE);
      } else {
        /* We ignore possible error returns because the only specified error
           is for a failed exec(), and because errors in these calls can't
           affect the caller of system() (which is a separate process) */
        if (close(pfd[0]) == -1) /* Read end is unused */
          _exit(EXIT_FAILURE);

        if (pfd[1] != STDOUT_FILENO) { /* Defensive check */
          if (dup2(pfd[1], STDOUT_FILENO) == -1)
            _exit(EXIT_FAILURE);
          if (close(pfd[1]) == -1)
            _exit(EXIT_FAILURE);
        }
      }

      execve(command, argv, envp);

      _exit(EXIT_FAILURE); /* We could not exec the command */

    default: /* Parent: wait for our child to terminate */
      /* Write end is unused */
      if (close(pfd[1]) == -1) {
        log_errno("close");
        return 1;
      }

      read_command_output(pfd[0], fn, ctx);

      /* We must use waitpid() for this task; using wait() could inadvertently
         collect the status of one of the caller's other children */
      errno = 0;
      while (waitpid(childPid, &status, 0) == -1) {
        if (errno != EINTR && errno) { /* Error other than EINTR */
          exit_code = 1;

          break; /* So exit loop */
        }

        errno = 0;
      }

      break;
  }

  /* Done with read end */
  if (close(pfd[0]) == -1) {
    log_errno("close");
    return 1;
  }

  if (exit_code)
    return 1;

  if (WIFEXITED(status)) {
    log_trace("Command run %s excve status %d", command, WEXITSTATUS(status));
    return WEXITSTATUS(status);
  }

  return status;
}

/**
 * @brief Logs the given command.
 *
 * @param argv Array of command parameters.
 * @param arg_count Length of array (not including NULL terminator).
 */
void log_run_command(const char *const argv[], int arg_count) {
  char buf[255];

  os_memset(buf, 0, 255);
  for (int i = 0; i < arg_count; i++) {
    strcat(buf, argv[i]);
    strcat(buf, " ");
  }

  log_trace("Running %s", buf);
}

int run_argv_command(const char *path, const char *const argv[],
                     process_callback_fn fn, void *ctx) {

  if (path == NULL) {
    log_trace("path param is NULL");
    return -1;
  }

  if (argv == NULL) {
    log_trace("argv param is NULL");
    return -1;
  }

  // number of entries in argv (not including NULL terminator)
  size_t argc = 0;
  while (argv[argc] != NULL) {
    argc++;
  }

  // prepends `path` to the array of argv
  size_t full_argc = argc + 1;
  const char **full_arg = os_malloc(sizeof(char *) * (full_argc + 1));

  if (full_arg == NULL) {
    log_errno("Failed to malloc %d bytes", sizeof(char *) * (full_argc + 1));
    return -1;
  }

  full_arg[0] = path;
  // copy over entire argv (including NULL terminator)
  for (size_t count = 0; count < (argc + 1); count++) {
    full_arg[count + 1] = argv[count];
  }

  char **full_arg_copy = copy_argv(full_arg);
  os_free(full_arg);

  if (full_arg_copy == NULL) {
    log_errno("Failed to copy_argv");
    return -1;
  }

  log_run_command((const char **)full_arg_copy, full_argc);

  int status = run_command(full_arg_copy, NULL, fn, (void *)ctx);
  os_free(full_arg_copy);
  return (!status ? 0 : -1);
}

int fn_split_string_array(const char *str, size_t len, void *data) {
  UT_array *strs = (UT_array *)data;
  char *dest = (char *)os_malloc(len + 1);
  if (dest == NULL) {
    log_errno("os_malloc");
    return -1;
  }

  memset(dest, '\0', len + 1);
  strncpy(dest, str, len);
  utarray_push_back(strs, &dest);
  os_free(dest);
  return 0;
}

ssize_t split_string(const char *str, char sep, split_string_fn fun,
                     void *data) {
  ssize_t start = 0, stop, count = 0;

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
    if (fun(str + start, 0, data) < 0) {
      log_trace("fun fail");
      return -1;
    }
  } else {
    if (fun(str + start, stop - start, data) < 0) {
      log_trace("fun fail");
      return -1;
    }
  }

  return count + 1;
}

ssize_t split_string_array(const char *str, char sep, UT_array *arr) {
  if (arr == NULL) {
    log_trace("input arr is NULL");
    return -1;
  }

  return split_string(str, sep, fn_split_string_array, (void *)arr);
}

char *concat_paths(const char *path_left, const char *path_right) {
  size_t concat_len;

  if (path_left == NULL && path_right != NULL)
    concat_len = strlen(path_right) + 1;
  else if (path_left != NULL && path_right == NULL)
    concat_len = strlen(path_left) + 1;
  else if (path_left == NULL && path_right == NULL)
    concat_len = 1;
  else
    concat_len = strlen(path_left) + strlen(path_right) + 2;

  char *concat = os_zalloc(concat_len);

  if (concat == NULL) {
    log_errno("os_zalloc");
    return NULL;
  }

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

char *get_valid_path(const char *path) {
  char *concat = NULL;

  if (path == NULL)
    return NULL;

  char *dir = os_strdup(path);
  if (dir == NULL && path != NULL) {
    log_trace("strdup fail");
    return NULL;
  }

  char *base = os_strdup(path);
  if (base == NULL && path != NULL) {
    log_trace("strdup fail");
    os_free(dir);
    return NULL;
  }

  char *path_dirname = dirname(dir);
  char *path_basename = basename(base);

  if (!strlen(path)) {
    concat = concat_paths(path_dirname, NULL);
  } else if (strlen(path) &&
             (strcmp(path, ".") == 0 || strcmp(path, "..") == 0 ||
              strcmp(path, "/") == 0 || strcmp(path, "//") == 0)) {
    concat = concat_paths(path, NULL);
  } else {
    concat = concat_paths(path_dirname, path_basename);
  }

  os_free(dir);
  os_free(base);
  return concat;
}

char *construct_path(const char *path_left, const char *path_right) {
  char *path = NULL;
  if (path_left == NULL || path_right == NULL)
    return NULL;

  if (!strlen(path_right) && strlen(path_left)) {
    path = get_valid_path(path_left);
    return path;
  } else if (strlen(path_right) && !strlen(path_left)) {
    path = get_valid_path(path_right);
    return path;
  } else if (!strlen(path_right) && !strlen(path_left)) {
    path = get_valid_path("");
    return path;
  }

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

  path = get_valid_path(concat);
  os_free(concat);

  return path;
}

char *get_secure_path(const UT_array *bin_path_arr, const char *filename,
                      bool real) {
  char **p = NULL;

  if (bin_path_arr == NULL) {
    log_trace("bin_path_arr is NULL");
    return NULL;
  }

  if (filename == NULL) {
    log_trace("filename is NULL");
    return NULL;
  }

  while ((p = (char **)utarray_next(bin_path_arr, p))) {
    struct stat sb;
    char *path = construct_path(*p, filename);

    // Check if file exists
    if (stat(path, &sb) != -1) {
      // Get the real path of the needed path in case it is symbolic link
      if (real) {
        char *real_path = realpath(path, NULL);
        if (real_path == NULL) {
          log_errno("realpath");
          os_free(path);
          return NULL;
        }

        log_trace("got real path %s", real_path);
        os_free(path);
        return real_path;
      }

      return path;
    }

    os_free(path);
  }

  return NULL;
}

int is_proc_running(char *name) {
  struct find_dir_type dir_args = {.proc_running = 0, .proc_name = name};

  if (list_dir("/proc", find_dir_proc_fn, (void *)&dir_args) == -1) {
    log_trace("list_dir fail");
    return -1;
  }

  return dir_args.proc_running;
}

int list_dir(const char *dirpath, list_dir_fn fun, void *args) {
  /* Open the directory - on failure print an error and return */
  errno = 0;
  DIR *dirp = opendir(dirpath);
  if (dirp == NULL) {
    log_errno("opendir");
    return -1;
  }

  int returnValue = 0;

  /* Look at each of the entries in this directory */
  for (;;) {
    errno = 0; /* To distinguish error from end-of-directory */
    struct dirent *dp = readdir(dirp);
    if (dp == NULL)
      break;

    /* Skip . and .. */
    if (strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0)
      continue;

    /* Print directory + filename */
    char *path = construct_path(dirpath, dp->d_name);
    if (fun != NULL) {
      if (!fun(path, args)) {
        log_trace("list_dir callback fail");
        os_free(path);
        returnValue = -1;
        goto exit_list_dir;
      }
    }

    os_free(path);
  }

  if (errno != 0) {
    log_errno("readdir");
    returnValue = -1;
  }

exit_list_dir:
  if (closedir(dirp) == -1) {
    log_errno("closedir");
    return -1;
  }

  return returnValue;
}

/**
 * @brief Checks to see if the given `str` is in the given `/proc/.../cmdline`
 *
 * This will return `true` if the string is **anywhere** in the command line
 * for the function, including in the process arguments.
 *
 * @param filename - The filename to search in. Should be a `/proc/.../cmdline`
 * file.
 * @param str - The string to search for.
 * @return `true` is the string is in the `/proc/.../cmdline` file.
 * @see [man proc(5)](https://linux.die.net/man/5/proc) for details on the
 * `/proc/.../cmdline` format.
 */
static bool is_string_in_cmdline_file(const char *filename, const char *str) {
  FILE *fp = fopen(filename, "r");
  if (fp == NULL) {
    log_errno("fopen");
    return false;
  }

  // The output buffer for `getdelim()`, getdelim() will automatically realloc()
  // this if it's too small to hold the next line
  char *line = NULL;
  size_t len = 0;

  // /proc/.../cmdline files have arg0, arg1, arg2... delimited by NUL-chars
  // see man proc(5) https://linux.die.net/man/5/proc
  while (getdelim(&line, &len, '\0', fp) != -1) {
    if (strstr(line, str)) {
      free(line);
      fclose(fp);
      return true;
    }
  }

  free(line);
  fclose(fp);
  return false;
}

pid_t is_proc_app(const char *path, const char *proc_name) {
  pid_t pid;
  { // use a separate scope for this, to avoid allocating too much on the stack
    char pid_basename_buffer[MAX_OS_PATH_LEN];
    os_strlcpy(pid_basename_buffer, path, sizeof(pid_basename_buffer));
    const char *pid_string = basename(pid_basename_buffer);

    pid = strtoul(pid_string, NULL, 10);
  }

  char exe_path[MAX_OS_PATH_LEN];
  char cmdline_path[MAX_OS_PATH_LEN];
  char *resolved_path;

  if (errno != ERANGE && pid != 0) {
    snprintf(exe_path, MAX_OS_PATH_LEN - 1, "%s/exe", path);
    snprintf(cmdline_path, MAX_OS_PATH_LEN - 1, "%s/cmdline", path);
    if ((resolved_path = realpath(exe_path, NULL)) != NULL) {
      bool in_file = is_string_in_cmdline_file(cmdline_path, proc_name);
      if (strcmp(basename(resolved_path), proc_name) == 0 || in_file) {
        os_free(resolved_path);
        return pid;
      }
      os_free(resolved_path);
    }
  }

  return 0;
}

bool kill_dir_fn(char *path, void *args) {
  pid_t pid;
  pid_t current_pid = getpid();
  pid_t current_pid_group = getpgid(current_pid);
  if ((pid = is_proc_app(path, args)) != 0) {
    if (current_pid != pid && pid != current_pid_group) {
      log_trace("Found process pid=%d current_pid=%d current_pid_group=%d", pid,
                current_pid, current_pid_group);
      if (kill(pid, SIGTERM) == -1) {
        log_errno("kill");
        return false;
      } else
        log_trace("killed %s process with pid=%d", args, pid);
    }
  }

  return true;
}

bool signal_dir_fn(char *path, void *args) {
  struct proc_signal_arg *sarg = (struct proc_signal_arg *)args;

  pid_t pid;
  pid_t current_pid = getpid();
  pid_t current_pid_group = getpgid(current_pid);

  if ((pid = is_proc_app(path, sarg->proc_name)) != 0) {
    if (current_pid != pid && pid != current_pid_group) {
      log_trace("Found process pid=%d current_pid=%d current_pid_group=%d", pid,
                current_pid, current_pid_group);
      if (kill(pid, sarg->sig) == -1) {
        log_errno("kill");
        return false;
      } else
        log_trace("signalled %s process with pid=%d and sig=%d",
                  sarg->proc_name, pid, sarg->sig);
    }
  }

  return true;
}

bool signal_process(char *proc_name, int sig) {
  struct proc_signal_arg sarg = {.proc_name = proc_name, .sig = sig};

  if (proc_name == NULL) {
    log_error("proc_name is NULL");
    return false;
  }

  if (strcmp(proc_name, ".") == 0) {
    // may be caused by somebody calling basename(proc_name);
    log_error("proc_name is .");
    return false;
  }

  if (!os_strnlen_s(proc_name, MAX_OS_PATH_LEN)) {
    log_error("proc_name is empty");
    return false;
  }

  // Signal a process process if running
  log_debug("Signalling process %s with signal=%d", proc_name, sig);
  if (list_dir("/proc", signal_dir_fn, &sarg) == -1) {
    log_error("list_dir fail");
    return false;
  }

  return true;
}

bool kill_process(char *proc_name) {
  return signal_process(proc_name, SIGTERM);
}

char *string_array2string(char *strings[]) {
  int idx = 0;
  ssize_t total = 0;
  ssize_t len = 0;

  char *buf = NULL;

  if (strings == NULL) {
    log_trace("strings is NULL");
    return NULL;
  }

  while (strings[idx] != NULL && /*total <= size && */ len >= 0) {
    if (buf == NULL) {
      buf = os_malloc(strlen(strings[idx]) + 2);
    } else {
      buf = os_realloc(buf, total + strlen(strings[idx]) + 2);
    }

    len = sprintf(&buf[total], "%s ", strings[idx]);

    if (len >= 0) {
      total += len;
    } else {
      log_trace("snprintf fail");
      os_free(buf);
      return NULL;
    }

    idx++;
  }

  return buf; // total;
}

int run_process(char *argv[], pid_t *child_pid) {
  pid_t ret;
  int status;
  char *buf;

  if (argv == NULL) {
    log_trace("argv is NULL");
    return -1;
  }

  if (argv[0] == NULL) {
    log_trace("argv[0] is NULL");
    return -1;
  }

  if (!strlen(argv[0])) {
    log_trace("process name is empty");
    return -1;
  }

  if (check_file_exists(argv[0], NULL) < 0) {
    log_trace("check_file_exists fail for path=%s", argv[0]);
    return -1;
  }

  log_trace("Running process %s with params:", argv[0]);
  if ((buf = string_array2string(argv)) != NULL) {
    log_trace("\t %s", buf);
    os_free(buf);
  }

  switch (*child_pid = fork()) {
    case -1: /* fork() failed */
      log_errno("fork");
      return -1;

    case 0: /* Child: exec command */
      /* redirect stdout, stdin and stderr to /dev/null */
      close(STDIN_FILENO);

      /* Reopen standard fd's to /dev/null */
      int fd = open("/dev/null", O_RDWR);

      if (fd != STDIN_FILENO) /* 'fd' should be 0 */
        return -1;
      if (dup2(STDIN_FILENO, STDOUT_FILENO) != STDOUT_FILENO)
        return -1;
      if (dup2(STDIN_FILENO, STDERR_FILENO) != STDERR_FILENO)
        return -1;

      execv(argv[0], argv);

      log_errno("execv");
      return -1; /* We could not exec the command */
    default:
      log_trace("process child created with id=%d", *child_pid);
      log_trace("Checking process execution status...");

      ret = waitpid(*child_pid, &status, WNOHANG);
      if (ret == -1) {
        log_errno("waitpid");
        return -1;
      } else if (ret > 0 && WIFEXITED(status)) {
        log_trace("process with id=%d exited", *child_pid);
        return WEXITSTATUS(status);
      } else {
        log_trace("Process state with id=%d not changed", *child_pid);
      }
  }

  return 0;
}

int make_file_exec_fd(int fd) {
  struct stat sb;
  mode_t mode;

  if (fstat(fd, &sb) == -1) {
    log_errno("fstat");
    return -1;
  }

  // execute/search by owner ("search" applies for directories, and means that
  // entries within the directory can be accessed)
  mode = (sb.st_mode | S_IXUSR);

  if (fchmod(fd, mode) == -1) {
    log_errno("fchmod");
    return -1;
  }

  return 0;
}

char *rtrim(char *str, const char *seps) {
  int i;

  if (seps == NULL) {
    seps = "\t\n\v\f\r ";
  }

  if (str == NULL) {
    log_trace("str param is NULL");
    return NULL;
  }

  i = strlen(str) - 1;
  while (i >= 0 && strchr(seps, str[i]) != NULL) {
    str[i] = '\0';
    i--;
  }

  return str;
}

void upper_string(char *s) {
  int idx = 0;
  if (s) {
    while (s[idx] != '\0') {
      if (s[idx] >= 'a' && s[idx] <= 'z') {
        s[idx] = s[idx] - 32;
      }
      idx++;
    }
  }
}

void replace_string_char(char *s, char in, char out) {
  int idx = 0;
  if (s) {
    while (s[idx] != '\0') {
      if (s[idx] == in) {
        s[idx] = out;
      }
      idx++;
    }
  }
}

void os_to_timestamp(struct timeval ts, uint64_t *timestamp) {
  uint64_t sec, usec;
  sec = (uint64_t)1000000 * ts.tv_sec;
  usec = (uint64_t)ts.tv_usec;
  *timestamp = sec + usec;
}

int os_get_timestamp(uint64_t *timestamp) {
  struct timeval ts;
  int res = gettimeofday(&ts, NULL);
  *timestamp = 0;

  if (res == 0) {
    os_to_timestamp(ts, timestamp);
    return 0;
  };

  return -1;
}

void generate_radom_uuid(char *rid) {
  uuid_t id;
  uuid_generate(id);
  uuid_unparse_lower(id, rid);
}

size_t os_strnlen_s(char *str, size_t max_len) {
  char *end = (char *)memchr(str, '\0', max_len);

  if (end == NULL)
    return max_len;

  return end - str;
}

bool find_dir_proc_fn(char *path, void *args) {
  unsigned long pid;
  struct find_dir_type *dir_args = (struct find_dir_type *)args;

  if ((pid = is_proc_app(path, dir_args->proc_name)) != 0)
    dir_args->proc_running = 1;

  return true;
}

int exist_dir(const char *dirpath) {
  DIR *dirp;

  /* Open the directory - on failure print an error and return */
  errno = 0;
  if ((dirp = opendir(dirpath)) == NULL) {
    if (errno != ENOENT) {
      log_errno("opendir");
      return -1;
    }
    return 0;
  }

  closedir(dirp);
  return 1;
}

// Adapted from https://stackoverflow.com/a/9210960
// No need for license, since falls under fair use.
int make_dirs_to_path(const char *file_path, mode_t mode) {
  if (!(file_path && *file_path)) {
    log_trace("invalid file_path given to make_dirs_to_path");
    return -1;
  }

  char file_path_tmp[MAX_OS_PATH_LEN + 1];
  strcpy(file_path_tmp, file_path);

  // Loops over every "/" in file_path
  for (char *p = strchr(file_path_tmp + 1, '/'); p; p = strchr(p + 1, '/')) {
    *p = '\0';
    errno = 0;
    if (mkdir(file_path_tmp, mode) == -1) {
      if (errno != EEXIST) {
        log_errno("mkdir");
        *p = '/';
        return -1;
      }
    }
    *p = '/';
  }
  return 0;
}

int create_dir(const char *dirpath, mode_t mode) {
  int ret;
  ret = exist_dir(dirpath);
  if (ret < 0) {
    log_trace("dir path=%s open fail", dirpath);
    return -1;
  } else if (ret == 0) {
    log_trace("creating dir path=%s", dirpath);
    if (make_dirs_to_path(dirpath, mode) < 0) {
      log_trace("make_dirs_to_path fail");
      return -1;
    }
    // make_dirs_to_path doesn't create the final file, so make it ourselves
    errno = 0;
    if (mkdir(dirpath, mode) < 0) {
      if (errno != EEXIST) {
        log_errno("mkdir");
        return -1;
      }
    }
  }

  return 0;
}

int create_pipe_file(const char *path) {
  if (path == NULL) {
    log_error("path param is NULL");
    return -1;
  }

  mode_t prev = umask(0);
  errno = 0;
  if (mkfifo(path, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP) == -1 &&
      errno != EEXIST) {
    log_errno("mkfifo");
    umask(prev);
    return -1;
  }

  umask(prev);
  return 0;
}

int check_file_exists(char *path, struct stat *sb) {
  struct stat sb_in;
  int res;

  if (sb == NULL) {
    res = stat(path, &sb_in);
  } else {
    res = stat(path, sb);
  }

  return res;
}

int check_sock_file_exists(char *path) {
  struct stat sb;

  if (check_file_exists(path, &sb) < 0) {
    log_errno("stat %s", path);
    return -1;
  }

  if ((sb.st_mode & S_IFMT) != S_IFSOCK)
    return -1;

  return 0;
}

int get_hostname(char *buf) {
  if (gethostname(buf, OS_HOST_NAME_MAX) < 0) {
    log_errno("gethostname");
    return -1;
  }

  return 0;
}

static int lock_reg(int fd, int cmd, int type, int whence, int start,
                    off_t len) {
  struct flock fl;
  fl.l_type = type;
  fl.l_whence = whence;
  fl.l_start = start;
  fl.l_len = len;
  return fcntl(fd, cmd, &fl);
}

int lock_region(int fd, int type, int whence, int start, int len) {
  return lock_reg(fd, F_SETLK, type, whence, start, len);
}

int lock_region_block(int fd, int type, int whence, int start, int len) {
  return lock_reg(fd, F_SETLKW, type, whence, start, len);
}

int create_pid_file(const char *pid_file, int flags) {
  int fd;
  char buf[100];
  ssize_t write_bytes;
  fd = open(pid_file, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);

  if (fd == -1 && errno == ENOENT) {
    int ret = make_dirs_to_path(pid_file, 0755);
    if (ret) {
      log_errno("create_pid_file failed to create directories to path");
      return -1;
    }
    fd = open(pid_file, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
  }

  if (fd == -1) {
    log_errno("open");
    return -1;
  }

  if (flags & FD_CLOEXEC) {
    /* Set the close-on-exec file descriptor flag */
    /* Instead of the following steps, we could (on Linux) have opened the
       file with O_CLOEXEC flag. However, not all systems support open()
       O_CLOEXEC (which was standardized only in SUSv4), so instead we use
       fcntl() to set the close-on-exec flag after opening the file */
    flags = fcntl(fd, F_GETFD); /* Fetch flags */

    if (flags == -1) {
      log_errno("fcntl");
      close(fd);
      return -1;
    }

    flags |= FD_CLOEXEC;                   /* Turn on FD_CLOEXEC */
    if (fcntl(fd, F_SETFD, flags) == -1) { /* Update flags */
      log_errno("fcntl");
      close(fd);
      return -1;
    }
  }

  if (lock_region(fd, F_WRLCK, SEEK_SET, 0, 0) == -1) {
    if (errno == EAGAIN || errno == EACCES) {
      log_errno("PID file '%s' is locked", pid_file);
      close(fd);
      return -1;
    } else {
      log_errno("lock_region");
      close(fd);
      return -1;
    }
  }

  if (ftruncate(fd, 0) == -1) {
    log_errno("ftruncate");
    close(fd);
    return -1;
  }

  snprintf(buf, 100, "%ld\n", (long)getpid());
  if ((write_bytes = write(fd, buf, strlen(buf))) < 0) {
    log_errno("write");
    close(fd);
    return -1;
  }

  if ((size_t)write_bytes != strlen(buf)) {
    log_trace("write fail");
    close(fd);
    return -1;
  }

  return fd;
}

ssize_t read_file(char *path, uint8_t **out) {
  long int read_size;
  long int file_size;
  uint8_t *buffer;

  *out = NULL;

  errno = 0;

  FILE *fp = fopen(path, "rb");

  if (fp == NULL) {
    log_errno("fopen");
    return -1;
  }

  if (fseek(fp, 0, SEEK_END) < 0) {
    log_errno("fseek");
    fclose(fp);
    return -1;
  }

  if ((file_size = ftell(fp)) == -1L) {
    log_errno("ftell");
    fclose(fp);
    return -1;
  }

  rewind(fp);

  if ((buffer = (uint8_t *)os_malloc(sizeof(char) * file_size)) == NULL) {
    log_errno("os_malloc");
    fclose(fp);
    return -1;
  }

  read_size = (long int)fread(buffer, sizeof(char), file_size, fp);

  if (read_size != file_size) {
    log_trace("fread fail");
    os_free(buffer);
    fclose(fp);
  }

  *out = buffer;

  fclose(fp);
  return read_size;
}

int read_file_string(char *path, char **out) {
  uint8_t *data = NULL;
  ssize_t data_size = 0;
  char *buffer;

  *out = NULL;

  if ((data_size = read_file(path, &data)) < 0) {
    log_trace("read_file fail");
    return -1;
  }

  if ((buffer = (char *)os_zalloc(data_size + 1)) == NULL) {
    log_errno("os_zalloc");
    return -1;
  }

  os_memcpy(buffer, data, data_size);

  *out = buffer;

  os_free(data);
  return 0;
}

ssize_t open_write_nonblock(const char *path, int *fd, const uint8_t *buffer,
                            size_t length) {
  if (path == NULL) {
    log_error("path param is NULL");
    return -1;
  }

  if (fd == NULL) {
    log_error("fd param is NULL");
    return -1;
  }

  if (buffer == NULL) {
    log_error("buffer param is NULL");
    return -1;
  }

  if (*fd <= 0) {
    errno = 0;
    if ((*fd = open(path, O_WRONLY | O_NONBLOCK)) < 0) {
      log_errno("open");
      return -1;
    }
  }

  return write(*fd, buffer, length);
}

int get_commands_paths(const char *commands[], const UT_array *bin_path_arr,
                       hmap_str_keychar **hmap_bin_paths) {
  if (bin_path_arr == NULL) {
    log_error("bin_path_arr param NULL");
    return -1;
  }

  if (commands == NULL) {
    log_error("commands param NULL");
    return -1;
  }

  *hmap_bin_paths = NULL;

  for (uint8_t idx = 0; commands[idx] != NULL; idx++) {
    log_debug("Getting %s command...", commands[idx]);
    char *path = get_secure_path(bin_path_arr, commands[idx], false);
    if (path == NULL) {
      log_trace("%s command not found", commands[idx]);
    } else {
      log_debug("%s command found at %s", commands[idx], path);
      if (!hmap_str_keychar_put(hmap_bin_paths, commands[idx], path)) {
        log_error("hmap_str_keychar_put error");
        os_free(path);
        hmap_str_keychar_free(hmap_bin_paths);
        return -1;
      }
      os_free(path);
    }
  }

  return 0;
}

char *string_append_char(const char *str, char character) {
  if (str == NULL) {
    log_error("str param is NULL");
    return NULL;
  }
  size_t str_len = strlen(str);

  char *appended = os_malloc(str_len + 2);
  if (appended == NULL) {
    log_errno("os_zalloc");
    return NULL;
  }

  // first copy the str, without NULL terminator
  memcpy(appended, str, str_len);
  // set the char to append
  appended[str_len] = character;
  // set the string NULL terminator
  appended[str_len + 1] = 0;

  return appended;
}

// void *os_malloc(size_t size)
// {
//   void *ptr = malloc(size);
//   log_trace("malloc=%p", ptr);
//   return ptr;
// }

// void os_free( void* ptr ) {
//   log_trace("free=%p", ptr);
//   free(ptr);
// }
