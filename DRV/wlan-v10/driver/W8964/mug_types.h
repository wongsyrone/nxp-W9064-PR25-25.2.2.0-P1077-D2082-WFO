/** @file mug_types.h
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

#ifndef MUG_TYPES_H__
#define MUG_TYPES_H__

#ifndef __KERNEL__
#include <stdint.h>
#include <stdbool.h>

typedef uint32_t u32;
typedef int32_t s32;
typedef uint16_t u16;
typedef int16_t s16;
typedef uint8_t u8;
typedef int8_t s8;
#endif

#ifdef __GNUC__

#ifndef PACK_STRUCT
#define PACK_STRUCT  __attribute__ ((packed))
#endif

#ifndef ALIGN32
#define ALIGN32 __attribute__((aligned(32)))	// Force cache alignment
#endif

#ifndef PACK_START
#define  PACK_START
#endif /* #ifndef PACK_START */

#ifndef PACK_END
#define PACK_END   __attribute__((__packed__))
#endif /* #ifndef PACK_END */

#ifndef ALIGN_START
#define ALIGN_START(x)
#endif /* #ifndef ALIGN_START */

#ifndef ALIGN_END
#define ALIGN_END(x)  __attribute__ ((aligned(x)))
#endif /* #ifndef ALIGN_END */

#endif /* #ifdef __GNUC__ */

#if defined(MRVL_MUG_ENABLE)
#include "mug_private.h"
#else
#define MUG_USER_INFO_PRIVATE
#define MUG_FWINFO_PRIVATE
#define MUG_FWINFO_FULL_SIZE    (sizeof(mug_fwinfo_t))
#endif

#define MUG_MAX_USERS           300
#define MUG_STAID_UNK           0
#define MUG_UIDX_UNSET          UINT16_MAX
#define MUG_MUSET_GID_UNSET     UINT8_MAX
#define MUG_STA_CEP_AGE_MAXED   UINT8_MAX

/* The number of pairs/triplets/... can be defined as all the possible groups of
 * k elements of the n users, that is:
 *
 * n! / (k! * (n - k)!)
 *
 * For the pairs:
 * n! / (2! x (n - 2)!) = 1/2 x n x (n - 1)
 *
 * For the triplets:
 * n! / (3! x (n - 3)!) = 1/6 x n x (n - 1) x (n - 2)
 */

#define MUG_MAX_PAIRS           ((MUG_MAX_USERS) * ((MUG_MAX_USERS) - 1) / 2)
#define MUG_MAX_TRIPLETS        ((MUG_MAX_USERS) * ((MUG_MAX_USERS) - 1) * ((MUG_MAX_USERS) - 2 ) / 6)

#define MUG_MAX_USERS_PER_GROUP 3

/* GID for MU from 1 to 62 */
#define MUG_MAX_MU_GROUPS       62

/* A single MU group candidate instance */
typedef struct {
	u16 staids[MUG_MAX_USERS_PER_GROUP];
	u16 score;
	u8 flags;
	u8 age;
	u8 bss_id;
} mug_group_t;

#define MU_GROUP_ACTIVE         (1 << 0)

/* All the information related to MU groups */
typedef struct {
	u16 n_group;
	mug_group_t group[MUG_MAX_MU_GROUPS];
} mug_group_info_t;

typedef PACK_START struct {
	struct {
		u32 size;
		int groups_only;
		u32 ts;
	} hdr;

	mug_group_info_t group_info;
 MUG_FWINFO_PRIVATE} PACK_END mug_fwinfo_t;

typedef struct mug_muset_s {
	u16 staids[MUG_MAX_USERS_PER_GROUP];
	u8 gid;			// GID used for iwpriv
	u8 index;		// index used for iwpriv
	u16 mug_group_idx;	// the corresponding mug group index.
	char dev_name[16];
} mug_muset_t;

typedef struct {
	u16 n_musets;
	mug_muset_t musets[62];
} mug_all_musets_t;

#endif /* MUG_TYPES_H__ */
