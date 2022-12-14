/**
 * @file
 * @author Alexandru Mereacre
 * @date 2022
 * @copyright
 * SPDX-FileCopyrightText: © 2022 NQMCyber Ltd and edgesec contributors
 * SPDX-License-Identifier: LGPL-3.0-or-later
 * @brief File containing the common definitions used by radius and eap
 */

#ifndef COMMON_H
#define COMMON_H

#include <stddef.h>

#include "utils/log.h"

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;
typedef int64_t s64;
typedef int32_t s32;
typedef int16_t s16;
typedef int8_t s8;

/*
 * Definitions for sparse validation
 * (http://kernel.org/pub/linux/kernel/people/josh/sparse/)
 */
#ifdef __CHECKER__
#define __force __attribute__((force))
#undef __bitwise
#define __bitwise __attribute__((bitwise))
#else
#define __force
#undef __bitwise
#define __bitwise
#endif

typedef u16 __bitwise be16;
typedef u16 __bitwise le16;
typedef u32 __bitwise be32;
typedef u32 __bitwise le32;
typedef u64 __bitwise be64;
typedef u64 __bitwise le64;

#define wpa_printf(level, ...) log_levels(LOGC_TRACE, __FILENAME__, __LINE__, __VA_ARGS__)
#define wpa_snprintf_hex(buf, buf_size, data, len) printf_hex(buf, buf_size, data, len, 0)

#define  TEST_FAIL() 0
#endif
