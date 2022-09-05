#include <stdint.h>

// Wraps log_levels so that we can use
// expect_string(__wrap_log_levels, error_message, "edgesec is great");
// and expect_function_call(log_error);
// to see what errors were logged.

/**
 * @brief Wrapper for `log_error()` macro
 *
 * Wraps log_levels so that we can use
 * @code
 * expect_string(__wrap_log_levels, error_message, "edgesec is great");`
 * @endcode
 * and
 * @code
 * expect_function_call(log_error);
 * @endcode
 * to see what errors were logged.
 *
 * See https://api.cmocka.org/group__cmocka__call__order.html
 * and https://api.cmocka.org/group__cmocka__param.html for
 * usage.
 */
void __wrap_log_levels(uint8_t level, const char *file, uint32_t line,
                       const char *format, ...);
