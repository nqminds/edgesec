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

#ifndef __must_check
#if defined __has_attribute
#if __has_attribute(__warn_unused_result__)
/**
 * If used before a function, tells compilers that the result of the function
 * should be used and not ignored.
 *
 * @see
 * https://clang.llvm.org/docs/AttributeReference.html#nodiscard-warn-unused-result
 */
#define __must_check __attribute__((__warn_unused_result__))
#else
#define __must_check
#endif /* __has_attribute(__warn_unused_result__) */
#else
#define __must_check
#endif /* defined __has_attribute */
#endif /* __has_attribute */

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
/**
 * Use as little memory as possible for the attributed `enum`, `struct`, or
 * `union`.
 *
 * @remarks Please be aware that this packing algorithm is platform specific.
 * Even using GCC on Windows has different results:
 * see https://gcc.gnu.org/onlinedocs/gcc/x86-Variable-Attributes.html
 *
 * @see https://clang.llvm.org/docs/AttributeReference.html#packed
 */
#define STRUCT_PACKED __attribute__((packed))
#else
#define STRUCT_PACKED
#endif /* __has_attribute(packed) */
#else
#define STRUCT_PACKED
#endif /* defined __has_attribute */

#endif /* ATTRIBUTES_H */
