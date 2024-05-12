/** @file shal_util2.h
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2019-2020 NXP
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
 * @brief SMAC common utility function APIs.
 */

#ifndef _SHAL_UTIL2_H_
#define _SHAL_UTIL2_H_

// Used for the bit defintions of orgReg = intReg and no HW clear bits.
static SHAL_INLINE void UTIL_setRegInt(U32 orgRegAddr, U32 intRegAddr, U32 setBits)
{
	UTIL_set32(orgRegAddr, setBits);
	// Wait until the change is routed.
	while ((UTIL_read32(intRegAddr) | setBits) != setBits) ;
}

static SHAL_INLINE void UTIL_clrIRegInt(U32 orgRegAddr, U32 intRegAddr, U32 clrBits)
{
	UTIL_clear32(orgRegAddr, clrBits);
	// Wait until the change is routed.
	while ((UTIL_read32(intRegAddr) | clrBits) != 0) ;
}

// toggleBits = BIT(bitNum1) [ | BIT(bitNum2)...]
static SHAL_INLINE void UTIL_toggle32(U32 dstAddr, U32 orgVal, U32 toggleBits)
{
	UTIL_write32(dstAddr, (orgVal | toggleBits));
	__nop();
	__nop();
	UTIL_write32(dstAddr, (orgVal));
}

static SHAL_INLINE void UTIL_toggleRegInt(U32 orgRegAddr, U32 intRegAddr, U32 toggleBits)
{
	U32 orgVal = UTIL_read32(intRegAddr);

	UTIL_toggle32(orgRegAddr, orgVal, toggleBits);
	// Wait until the change is routed.
	while ((UTIL_read32(intRegAddr)) != orgVal) ;
}

#ifdef GPIO_ENABLED		// !!! DO NOT FORCE to ENABLE when check-in. Only local change for LA verification.
#define UTIL_GPIO_ADDR      0x90013f84
#define UTIL_INT_GPIO_ADDR  0	// TBD: internal register
#define UTIL_GPIO_SEMA      SEMA_AVL3_PRI0	// Use sema ID 5 for now
#endif

static SHAL_INLINE void UTIL_toggleGPIO(U32 toggleBits)
{
#ifdef UTIL_GPIO_ADDR
	SEMA_get(UTIL_GPIO_SEMA);

#if UTIL_INT_GPIO_ADDR
	UTIL_toggleRegInt(UTIL_GPIO_ADDR, UTIL_INT_GPIO_ADDR, toggleBits);
#else
	UTIL_toggle32(UTIL_GPIO_ADDR, UTIL_read32(UTIL_GPIO_ADDR), toggleBits);
#endif

	SEMA_rel(UTIL_GPIO_SEMA);
#endif
}

static SHAL_INLINE void UTIL_setGPIO(U32 setBits)
{
#ifdef UTIL_GPIO_ADDR
	SEMA_get(UTIL_GPIO_SEMA);
	UTIL_set32(UTIL_GPIO_ADDR, setBits);

#if UTIL_INT_GPIO_ADDR
	while ((UTIL_read32(UTIL_INT_GPIO_ADDR) | setBits) != setBits) ;
#endif

	SEMA_rel(UTIL_GPIO_SEMA);
#endif
}

static SHAL_INLINE void UTIL_clrGPIO(U32 clrBits)
{
#ifdef UTIL_GPIO_ADDR
	SEMA_get(UTIL_GPIO_SEMA);
	UTIL_clear32(UTIL_GPIO_ADDR, clrBits);

#if UTIL_INT_GPIO_ADDR
	while ((UTIL_read32(UTIL_INT_GPIO_ADDR) | clrBits) != 0) ;
#endif

	SEMA_rel(UTIL_GPIO_SEMA);
#endif
}

#endif				//_SHAL_UTIL2_H__
