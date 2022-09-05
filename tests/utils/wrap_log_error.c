#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>

#include "./wrap_log_error.h"

#include "utils/log.h"

extern void __real_log_levels(uint8_t level, const char *file, uint32_t line,
                              const char *format, ...);
void __wrap_log_levels(uint8_t level, const char *file, uint32_t line,
                       const char *format, ...) {
  char message[512];

  va_list argptr;
  va_start(argptr, format);
  vsnprintf(message, sizeof(message), format, argptr);
  va_end(argptr);

  if (level == LOGC_ERROR) {
    _function_called("log_error", __FILE__, __LINE__);
    const char *error_message = message;
    check_expected_ptr(error_message);
  }
  return __real_log_levels(level, file, line, message);
}
