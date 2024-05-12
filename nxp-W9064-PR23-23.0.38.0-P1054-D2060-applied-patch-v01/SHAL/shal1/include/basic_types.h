/** @file basic_types.h
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2018-2020 NXP
  *
  * This software file (the "File") is distributed by NXP
  * under the terms of the GNU General Public License Version 2, June 1991
  * (the "License").  You may use, redistribute and/or modify the File in
  * accordance with the terms and conditions of the License, a copy of which
  * is available by writing to the Free Software Foundation, Inc.,
  * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA or on the
  * worldwide web at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
  *
  * THE FILE IS DISTRIBUTED AS-IS, WITHOUT WARRANTY OF ANY KIND, AND THE
  * IMPLIED WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE
  * ARE EXPRESSLY DISCLAIMED.  The License provides additional details about
  * this warranty disclaimer.
  *
  */
#ifndef _BASIC_TYPES_H_
#define _BASIC_TYPES_H_

typedef unsigned long long u64;
typedef signed long long s64;
typedef unsigned long u32;
typedef signed long s32;
typedef unsigned short u16;
typedef signed short s16;
typedef unsigned char u8;
typedef signed char s8;
typedef int boolean;

typedef volatile unsigned char r8;
typedef volatile unsigned short r16;
typedef volatile unsigned int r32;

/* boolean values */
#ifdef FALSE
#undef FALSE
#endif
#define FALSE 0

#ifdef TRUE
#undef TRUE
#endif
#define TRUE 1

#define HAL_REGS32(x) (*(volatile unsigned long *)(x))
#define HAL_REGS16(x) (*(volatile unsigned short *)(x))
#define HAL_REGS8(x)  (*(volatile unsigned char *)(x))
#define HAL_REGS32_SETBITS(reg, val) (HAL_REGS32(reg) |= val)
#define HAL_REGS32_CLRBITS(reg, val) (HAL_REGS32(reg) = (HAL_REGS32(reg) & ~(val)))
#define HAL_READ_REGS32(reg, val)    ((val) = HAL_REGS32(reg))
#define HAL_WRITE_REGS32(reg, val)   (HAL_REGS32(reg) = val)
#define HAL_REGS16_SETBITS(reg, val) (HAL_REGS16(reg) |= val)
#define HAL_REGS16_CLRBITS(reg, val) (HAL_REGS16(reg) = (HAL_REGS16(reg) & ~(val)))
#define HAL_READ_REGS16(reg, val)    ((val) = HAL_REGS16(reg))
#define HAL_WRITE_REGS16(reg, val)   (HAL_REGS16(reg) = val)
#define HAL_WRITE_REGS8(reg, val)    (HAL_REGS8(reg) = val)
#define HAL_BIT(n) (1UL << n)
#define HAL_BITMAP(msb, lsb) ((HAL_BIT(msb+1) - HAL_BIT(lsb)) & 0xFF)

/*
 * Name for error code returned by most functions in the API.
 *
 * In general, API functions return either boolean or WL_STATUS
 * boolean API functions return TRUE when the function was
 * successful and return FALSE when the function failed.
 *
 * WL_STATUS API functions return WL_STATUS_OK when the function
 * was successful and return a error code that is less than 0
 * when the function failed.
 */
typedef enum {
	SUCCESS = 0,
	FAIL
} Status_e;

#define WL_STATUS Status_e

/* Generic status code */
#define WL_STATUS_OK        0
#define WL_STATUS_ERR       (-1)
#define WL_STATUS_BAD_PARAM (-2)

/* Value for NULL pointer */
#if defined(NULL)
#undef NULL
#endif
#define NULL ((void *)0)

/* Minimum and maximum values a 'signed long int' can hold */
#define LONG_MAX 2147483647L
#define LONG_MIN (-LONG_MAX-1)
/* Maximum value an 'unsigned long int' can hold (minimum is 0) */
#undef ULONG_MAX
#define ULONG_MAX (LONG_MAX * 2UL + 1)

#ifdef __GNUC__
#define PACK_START
#define PACK_END  __attribute__ ((packed))
#define PACK_STRUCT  __attribute__ ((packed))
#else
#define PACK_START   __packed
#define PACK_END
#endif

#define PACK PACK_END

#define PACK_STRUCT  __attribute__ ((packed))

#ifdef __GNUC__
#define ALIGN_START(x)
#define ALIGN_END(x) __attribute__ ((aligned(x)))
#else
#define ALIGN_START(x) __align(x)
#define ALIGN_END(x)
#endif

#ifdef __GNUC__
#define INLINE inline
#else
#define INLINE
#endif

#define BIT(x) (0x1<<x)

#define IEEEBYTES               6

#ifdef DEBUG_RATE_ADAPT
#ifndef DBG
#define EN_DBG_RATE_ADAPT_MSG    0x00000040
#define EN_DBG_MSG EN_DBG_RATE_ADAPT_MSG
extern u32 DebugFlag;
#endif
#endif

#ifdef DBG
/* The following is the configuration setting for debug message */
#define EN_DBG_ERR_MSG            0x00000001
#define EN_DBG_STA_MSG            0x00000002
#define EN_DBG_AP_MSG            0x00000004
#define EN_DBG_CMD_PATH_MSG        0x00000008
#define EN_DBG_TX_PATH_MSG        0x00000010
#define EN_DBG_RX_PATH_MSG        0x00000020
#define EN_DBG_RATE_ADAPT_MSG    0x00000040

/* EN_DBG_MSG can be changed to turn on/off specific debug message */
#define EN_DBG_MSG (EN_DBG_ERR_MSG | EN_DBG_STA_MSG | EN_DBG_AP_MSG | EN_DBG_CMD_PATH_MSG \
        | EN_DBG_TX_PATH_MSG | EN_DBG_RX_PATH_MSG | EN_DBG_RATE_ADAPT_MSG)

/*
 * This global variable can be used to check if the
 * specific category of debug message need to be
 * sent to driver
 */
extern u32 DebugFlag;
extern void DebugMsg(u8 * pMsg);
extern char DebugStr[];
#elif defined(DEBUG_PRINT)
#define DebugMsg(format, ...)    printf(format, ##__VA_ARGS__)
#else
#define DebugMsg(format, ...)    do {} while(0);
#endif

#endif /* _BASIC_TYPES_H_ */
