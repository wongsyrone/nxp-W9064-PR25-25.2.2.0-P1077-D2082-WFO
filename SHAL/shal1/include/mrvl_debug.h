/** @file mrvl_debug.h
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
#ifndef MRVL_DEBUG_H__
#define MRVL_DEBUG_H__

/*******************************************************************************
 *
 * Assert features
 */

#if defined(MRVL_WITH_ASSERT)
#include <stdbool.h>

#define MRVL_ASSERT(condition) \
    do \
    { \
        bool c = (condition); \
        if (!(c)) \
        { \
            __disable_irq(); \
            while (!c); \
        } \
    } while(0)

#else

#define MRVL_ASSERT(condition)
#define ALARM_ASSERT  pfw_assert_msg
#endif /* #if defined(MRVL_WITH_ASSERT) */

extern void pfw_assert_msg(void);

/*******************************************************************************
 *                       MACROS related to Asserting.
 ******************************************************************************/

/**
 * Evaluates in a boolean expression, whose value is determined by the logic implication:
 * op1 => op2
 */
#define MRVL_IF_THEN(op1, op2)           ( (!(op1)) || (op2) )
/**
 * Evaluates in a boolean expression, whose value is determined by logic double-way implication:
 * op1 <=> op2
 */
#define MRVL_IF_AND_ONLY_IF(op1, op2)    ( (MRVL_IF_THEN(op1, op2)) && (MRVL_IF_THEN(op2, op1)) )

#define MRVL_ASSERT_IF(op1, op2)         MRVL_ASSERT( MRVL_IF_THEN(op1, op2) )
#define MRVL_ASSERT_IFF(op1, op2)        MRVL_ASSERT( MRVL_IF_AND_ONLY_IF(op1, op2) )
#endif /* MRVL_DEBUG_H__ */
