/**
 * @file
 * @author Alois Klink <alois@nquiringminds.com>
 * @date 2023
 * @copyright
 * SPDX-FileCopyrightText: © 2023 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: Expat
 * @brief File containing macros for compiler attributes, if they are supported.
 *
 * In the future, once we support C23, we can remove this header and just
 * use C23 attributes.
 */
#ifndef ATTRIBUTES_H
#define ATTRIBUTES_H

#ifndef __maybe_unused
#if defined __has_attribute
#if __has_attribute(unused)
/**
 * If used before a variable, tells the compiler that variable can be unused.
 * (e.g. does the same thing as casting to `(void)`, or `[[maybe_unused]]` in
 * C23).
 *
 * @see https://clang.llvm.org/docs/AttributeReference.html#maybe-unused-unused
 */
#define __maybe_unused __attribute__((unused))
#else
#define __maybe_unused
#endif /* __has_attribute(unused) */
#else
#define __maybe_unused
#endif /* defined __has_attribute */
#endif /* __maybe_unused */

#if defined __has_attribute
#if __has_attribute(packed)
#define STRUCT_PACKED __attribute__((packed))
#else
#define STRUCT_PACKED
#endif /* __has_attribute(packed) */
#else
#define STRUCT_PACKED
#endif /* defined __has_attribute */

#endif /* ATTRIBUTES_H */
