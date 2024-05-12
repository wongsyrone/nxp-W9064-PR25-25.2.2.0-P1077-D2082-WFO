/** @file qos_scheduler.c
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2002-2020 NXP
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
//todo for 2.6

#include "wltypes.h"
#include "IEEE_types.h"
#include "wl_macros.h"
#include "wl_mib.h"

#include "mib.h"
#include "osif.h"
#include "qos.h"
#include "ds.h"
#include "keyMgmtCommon.h"
#include "keyMgmt.h"
#include "tkip.h"
#include "StaDb.h"
#include "macmgmtap.h"
#include "macMgmtMlme.h"
#include "wlmac.h"
#include "wl_hal.h"

#define HW_SI_TIMER
UINT32 currentSI;		//var which tells what the current SI is
Status_e DelTxOpEntry(UINT32 Tid)
{
	return SUCCESS;
}

Status_e AddTxOpEntry(vmacApInfo_t * vmacSta_p, UINT32 Indx, UINT16 Aid, UINT8 ClientMode)
{
	return SUCCESS;
}
