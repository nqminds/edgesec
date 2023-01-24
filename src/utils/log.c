/*
 * Copyright (c) 2017 rxi
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

/**
 * @file log.h
 * @authors rxi, Alexandru Mereacre
 * @brief File containing the implementation of the logging functions.
 */

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <inttypes.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "log.h"
#include "time.h"

#define PRINT_COLOR(stream, time, color, name, err, file, line)                \
  fprintf(stream, "%s %s%-5s\x1b[0m%s\x1b[0m \x1b[90m%s:%d:\x1b[0m ", time,    \
          color, name, err, file, line)

#define PRINT_NO_COLOR(stream, time, color, name, err, file, line)             \
  fprintf(stream, "%s %-5s%s %s:%d: ", time, name, err, file, line)

static struct {
  log_lock_fn lock;
  uint8_t level;
  bool quiet;
  bool meta;
  bool color;
  FILE *logfp;
} L = {.lock = NULL,
       .level = 0,
       .quiet = false,
       .meta = true,
       .color = true,
       .logfp = NULL};

static const char *level_names[] = LEVEL_NAMES;
static const char *level_colors[] = LEVEL_COLORS;

/* Write time to buf in format YYYY-MM-DD HH:MM:SS.ms */
uint8_t time_to_str(char *buf) {
  struct timeval tv;
  struct tm *tm;

  gettimeofday(&tv, NULL);
  tm = localtime(&tv.tv_sec);

  /* Add 1900 to get the right year value read the manual page for localtime()
   */
  int year = tm->tm_year + 1900;

  /* Months are 0 indexed in struct tm */
  int month = tm->tm_mon + 1;
  int day = tm->tm_mday;
  int hour = tm->tm_hour;
  int minutes = tm->tm_min;
  int seconds = tm->tm_sec;
  uint16_t msec = (uint16_t)(tv.tv_usec / 1000);
  int len = sprintf(buf, "%04d-%02d-%02d %02d:%02d:%02d.%03d ", year, month,
                    day, hour, minutes, seconds, msec);
  buf[len] = '\0';
  return 0;
}

#ifdef __GNUC__               /* Prevent 'gcc -Wall' complaining  */
__attribute__((__noreturn__)) /* if we call this function as last */
#endif                        /* statement in a non-void function */
static void
terminate(bool use_exit3) {
  char *s;

  /* Dump core if EF_DUMPCORE environment variable is defined and
     is a nonempty string; otherwise call exit(3) or _exit(2),
     depending on the value of 'useExit3'. */

  s = getenv("EF_DUMPCORE");

  if (s != NULL && *s != '\0')
    abort();
  else if (use_exit3)
    exit(EXIT_FAILURE);
  else
    _exit(EXIT_FAILURE);
}

static void lock(void) {
  if (L.lock) {
    L.lock(true);
  }
}

static void unlock(void) {
  if (L.lock) {
    L.lock(false);
  }
}

void log_set_lock(log_lock_fn fn) { L.lock = fn; }

void log_set_level(uint8_t level) { L.level = level; }

void log_set_quiet(bool enable) { L.quiet = enable; }

void log_set_meta(bool enable) { L.meta = enable; }

void log_set_color(bool enable) { L.color = enable; }

int log_open_file(char *path) {
  mode_t m;

  log_set_color(false);

  m = umask(077);
  L.logfp = fopen(path, "a");
  umask(m);

  /* If opening the log fails we can't display a message... */
  if (L.logfp == NULL) {
    return -1;
  }

  /* Disable stdio buffering */
  setbuf(L.logfp, NULL);

  return 0;
}

void log_close_file(void) {
  if (L.logfp != NULL) {
    fclose(L.logfp);
    L.logfp = NULL;
  }
}

bool log_check_level(uint8_t level, bool ignore_level) {
  if (level < L.level && !ignore_level)
    return true;
  else if (L.quiet && !ignore_level)
    return true;
  else
    return false;
}

/**
 * @brief Get the error text object
 *
 * @param[out] buf String buffer of at least 30 chars
 * @param err `errno` value passed to strerror()
 * @return The number of bytes written to @p buf, or 0 if buf is empty.
 *
 * **Warning**, this function is non-threadsafe, as stderror() is not
 * guaranteed to be threadsafe. Please make sure to uses mutxes/locks
 * before calling this function.
 */
int get_error_text(char *buf, int err) {
  int ret = 0;
  if (err > 0) {
    ret = snprintf(buf, 30, "[%s(%d)]", strerror(err), err);
  } else {
    buf[0] = '\0';
  }

  return ret;
}

void print_to(uint8_t level, const char *file, uint32_t line, int err,
              const char *time_string, const char *err_text_buf,
              const char *format, va_list args) {
  FILE *stream = (L.logfp != NULL) ? L.logfp : stderr;

  if (L.meta) {
    if (L.color) {
      fprintf(stream, "%s %s%-5s\x1b[0m%s\x1b[0m \x1b[90m%s:%d:\x1b[0m ",
              time_string, level_colors[level], level_names[level],
              err_text_buf, file, line);
    } else {
      fprintf(stream, "%s %-5s%s %s:%d: ", time_string, level_names[level],
              err_text_buf, file, line);
    }
  }

  if (err > 0)
    fprintf(stream, "[%s] ", strerror(err));

  vfprintf(stream, format, args);
  fprintf(stream, "\n");
  fflush(stream);
}

void log_msg(uint8_t level, const char *file, uint32_t line, bool flush_std,
             bool ignore_level, int err, const char *format, va_list args) {
  (void)flush_std; /* unused */

  char time_string[25];
  char err_text_buf[30];

  if (log_check_level(level, ignore_level))
    return;

  /* Acquire lock */
  lock();

  get_error_text(err_text_buf, err);

  /* Get current time */
  time_to_str(time_string);

  /* Log to stream */
  if (!L.quiet) {
    print_to(level, file, line, err, time_string, err_text_buf, format, args);

    // if (flush_std)
    //   fflush(stdout);
  }

  /* Release lock */
  unlock();
}

void log_levels(uint8_t level, const char *file, uint32_t line,
                const char *format, ...) {
  va_list args;
  va_start(args, format);
  log_msg(level, file, line, false, false, 0, format, args);
  va_end(args);
}

/* Display error message including 'errno' diagnostic */
void log_errno_error(uint8_t level, const char *file, uint32_t line,
                     const char *format, ...) {
  int saved_errno = errno; /* In case we change it here */
  va_list args;

  va_start(args, format);
  log_msg(level, file, line, true, false, saved_errno, format, args);
  va_end(args);

  errno = saved_errno;
}

/* Display error message including 'errno' diagnostic, and
   terminate the process */
void log_error_exit(uint8_t level, const char *file, uint32_t line,
                    const char *format, ...) {
  int saved_errno = errno; /* In case we change it here */
  va_list args;

  va_start(args, format);
  log_msg(level, file, line, true, false, saved_errno, format, args);
  va_end(args);

  errno = saved_errno;

  terminate(true);
}

/* Display error message including 'errno' diagnostic, and
   terminate the process by calling _exit().

   The relationship between this function and log_error_exit() is analogous
   to that between _exit(2) and exit(3): unlike log_error_exit(), this
   function does not flush stdout and calls _exit(2) to terminate the
   process (rather than exit(3), which would cause exit handlers to be
   invoked).

   These differences make this function especially useful in a library
   function that creates a child process that must then terminate
   because of an error: the child must terminate without flushing
   stdio buffers that were partially filled by the caller and without
   invoking exit handlers that were established by the caller. */
void log_error_exit_proc(uint8_t level, const char *file, uint32_t line,
                         const char *format, ...) {
  int saved_errno = errno; /* In case we change it here */
  va_list args;

  va_start(args, format);
  log_msg(level, file, line, true, true, saved_errno, format, args);
  va_end(args);

  errno = saved_errno;

  terminate(false);
}

size_t printf_hex(char *buf, size_t buf_size, const uint8_t *data, size_t len,
                  int uppercase) {
  size_t i;
  char *pos = buf, *end = buf + buf_size;
  int ret;
  if (buf_size == 0)
    return 0;

  if (buf == NULL)
    return 0;

  if (data == NULL)
    return 0;

  for (i = 0; i < len; i++) {
    // guaranteed to be positive, since we return an error if writing fails
    size_t max_len = (size_t)(end - pos);
    ret = snprintf(pos, max_len, uppercase ? "%02X" : "%02x", data[i]);
    if (snprintf_error(max_len, ret)) {
      goto cleanup;
    }
    pos += ret;
  }

cleanup:
  end[-1] = '\0';
  return (size_t)(pos - buf);
}
