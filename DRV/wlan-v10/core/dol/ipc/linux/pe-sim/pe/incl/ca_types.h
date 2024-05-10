/** @file ca_types.h
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2019 NXP
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

#ifndef __CA_TYPES_H__
#define __CA_TYPES_H__

#include <linux/types.h>

#define CA_E_OK   0

typedef u8 ca_uint8_t;
typedef u16 ca_uint16_t;
typedef u32 ca_uint32_t;
typedef u64 ca_uint64_t;

typedef u8 ca_ipc_addr_t;
typedef u8 ca_status_t;
typedef u8 ca_ipc_session_id_t;

#endif /* __CA_TYPES_H__ */
