/** @file shal_util.h
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2014-2020 NXP
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

/**
 * @file
 * @brief Typedef data types for seamless portability.
 */

#ifndef _SHAL_UTIL_H_
#define _SHAL_UTIL_H_

#define SHAL_MIN(a, b)   (((a) < (b)) ? (a) : (b))
#define SHAL_MAX(a, b)   (((a) > (b)) ? (a) : (b))
#define SHAL_CEIL(a, b)  ((a)+(b)-1)/(b)
#define SHAL_FLOOR(a, b) ((a)/(b))
#define SHAL_UNUSED(x)   ((void)(x))

#ifdef BUILD_PFW
#include "mrvl_debug.h"
#define SHAL_ASSERT(condition)      MRVL_ASSERT(condition)
#else
#define SHAL_ASSERT(condition)
#endif

#define UTIL_write64(reg,val) (*(volatile U32 *)((U32)reg))    =(U32)(val);\
                              (*(volatile U32 *)((U32)reg + 4))=(U32)(val >> 32);
#define UTIL_write32(reg,val) (*(volatile U32 *)(reg))=(U32)(val)
#define UTIL_read32(reg)      (U32)(*(volatile U32 *)(reg))
#define UTIL_set32(reg,val)   (*(volatile U32 *)(reg))=(*(volatile U32 *)(reg)) | (val);
#define UTIL_clear32(reg,val) (*(volatile U32 *)(reg))=(*(volatile U32 *)(reg)) & ~(val);
#define UTIL_write8(reg,val)  (*(volatile U8 *)(reg))=(U8)(val)
#define UTIL_read8(reg,val)   (val)=(*(volatile U8 *)(reg))
#define UTIL_set8(reg,val)    (*(volatile U8 *)(reg))=(*(volatile U8 *)(reg)) | (val);
#define UTIL_clear8(reg,val)  (*(volatile U8 *)(reg))=(*(volatile U8 *)(reg)) & ~(val);
#define UTIL_BIT_GET8(src,offset,n)  (((U8)(src << (offset))) >> ( 8 - (n)))

static void
UTIL_macAddrCpy(U16 * dst, U16 * src)
{
	*dst++ = *src++;
	*dst++ = *src++;
	*dst = *src;
}

static SHAL_INLINE BOOL
UTIL_snAGtB(U16 snA, U16 snB)
{
	if (((U16) (snB - snA) & 0xFFF) < 0x7FF) {
		return FALSE;
	}
	return TRUE;
}

static SHAL_INLINE BOOL
UTIL_snALeB(U16 snA, U16 snB)
{
	if (((U16) (snB - snA) & 0xFFF) < 0x7FF) {
		return TRUE;
	}
	return FALSE;
}

#endif // _SHAL_UTIL_H_
