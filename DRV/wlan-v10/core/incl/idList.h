/** @file idList.h
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2003-2020 NXP
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

/*!
 * \file  idList.h
 * \brief aid & station id assignment to clients
 */

#if !defined(_IDLIST_H_)
#define _IDLIST_H_
#include "wl_hal.h"
typedef struct IdListElem_t
{
	struct IdListElem_t *nxt;
	struct IdListElem_t *prv;
	UINT16 Id;
} IdListElem_t;

WL_STATUS InitAidList(vmacApInfo_t * vmacSta_p);
UINT32 AssignAid(vmacApInfo_t * vmacSta_p);
void FreeAid(vmacApInfo_t * vmacSta_p, UINT32 Aid);

Status_e ResetAid(vmacApInfo_t * vmacSta_p, UINT16 StnId, UINT16 Aid);
WL_STATUS InitStnIdList(vmacApInfo_t * vmacSta_p);
UINT32 AssignStnId(vmacApInfo_t * vmacSta_p);
void FreeStnId(vmacApInfo_t * vmacSta_p, UINT32 StnId);
int FreeStnId_newdp(vmacApInfo_t * vmacSta_p, UINT32 StnId);

#endif /* _IDLIST_H_ */
