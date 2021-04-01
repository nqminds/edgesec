/**
 * Copyright (c) 2017 rxi
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See `log.c` for details.
 */

/**
 * @file log.h 
 * @authors rxi, Alexandru Mereacre 
 * @brief File containing the definition of the logging functions.
 */

#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <inttypes.h>
#include <stdbool.h>

#define LOG_VERSION     "0.1.0"
#define __FILENAME__    strrchr("/" __FILE__, '/') + 1
#define MAX_LOG_LEVELS  5

typedef void (*log_lock_fn)(bool lock);

enum {
  LOGC_TRACE,
  LOGC_DEBUG,
  LOGC_INFO,
  LOGC_WARN,
  LOGC_ERROR
};

#define LEVEL_NAMES {"TRACE", "DEBUG", "INFO", "WARN", "ERROR"}

#ifdef LOG_USE_COLOR
#define LEVEL_COLORS {"\x1b[94m", "\x1b[36m", "\x1b[32m", "\x1b[33m", "\x1b[31m"}

#define PRINT_LOG_TEXT(stream, time, color, name, err, file, line)    \
  fprintf(stream, "%s %s%-5s\x1b[0m%s\x1b[0m \x1b[90m%s:%d:\x1b[0m ", \
          time, color, name, err, file, line)
#else
#define LEVEL_COLORS {}

#define PRINT_LOG_TEXT(stream, time, color, name, err, file, line)    \
  fprintf(stream, "%s %-5s%s %s:%d: ", time, name, err, file, line)
#endif

#ifdef __GNUC__
#define PRINTF_FORMAT(a,b) __attribute__ ((format (printf, (a), (b))))
#else
#define PRINTF_FORMAT(a,b)
#endif

#ifdef __cplusplus
extern "C" {
#endif

static inline int snprintf_error(size_t size, int res)
{
	return res < 0 || (unsigned int) res >= size;
}

#define log_trace(...) log_levels(LOGC_TRACE, __FILENAME__, __LINE__, __VA_ARGS__)
#define log_debug(...) log_levels(LOGC_DEBUG, __FILENAME__, __LINE__, __VA_ARGS__)
#define log_info(...)  log_levels(LOGC_INFO,  __FILENAME__, __LINE__, __VA_ARGS__)
#define log_warn(...)  log_levels(LOGC_WARN,  __FILENAME__, __LINE__, __VA_ARGS__)
#define log_err(...) log_error(LOGC_ERROR, __FILENAME__, __LINE__, __VA_ARGS__)

#define log_err_ex(...) log_error_exit(LOGC_ERROR, __FILENAME__, __LINE__, __VA_ARGS__)
#define log_err_exp(...) log_error_exit_proc(LOGC_ERROR, __FILENAME__, __LINE__, __VA_ARGS__)

void log_set_udata(void *udata);
void log_set_lock(log_lock_fn fn);
void log_set_level(uint8_t level);
void log_set_quiet(bool enable);
void log_set_meta(bool enable);

void log_levels(uint8_t level, const char *file, uint32_t line, const char *format, ...);
void log_error(uint8_t level, const char *file, uint32_t line, const char *format, ...);
void log_error_exit(uint8_t level, const char *file, uint32_t line, const char *format, ...);
void log_error_exit_proc(uint8_t level, const char *file, uint32_t line, const char *format, ...);

void printf_encode(char *txt, size_t maxlen, const uint8_t *data, size_t len);
int printf_hex(char *buf, size_t buf_size, const uint8_t *data, size_t len, int uppercase);
#ifdef __cplusplus
}
#endif

#endif
