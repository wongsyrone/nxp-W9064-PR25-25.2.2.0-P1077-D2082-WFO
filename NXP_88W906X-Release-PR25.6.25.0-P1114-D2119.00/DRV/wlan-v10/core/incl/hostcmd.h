/** @file hostcmd.h
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

/****************************************************************************
*
*  $HEADER$
*
*      File name: HostCmd.h
*
*      Purpose:
*
*      This file contains the function prototypes, data structure and defines for
*      all the host/station commands. Please check the Eagle 802.11 GUI/Driver/Station 
*      Interface Specification for detailed command information
*
*      Notes:
*
*****************************************************************************/
//
// $Id: //depot/MRVL/BBU_EC85_11n/Common/hostcmd.h#15 $
// $DateTime: 2005/12/05 16:57:03 $
// $Author: kaic $
// Component  : Common Headers
// Description: Driver/Firmware interface decleration
// Started    : 02/11/2005
// Environment: Kernel Mode
//

#ifndef __HOSTCMD__H
#define __HOSTCMD__H

#include "IEEE_types.h"
#include "hostcmdcommon.h"

#ifdef SOC_W906X
typedef struct offChanListItem {
	struct offChanListItem *nxt;
	struct offChanListItem *prv;
	offchan_desc_t offchan_desc;
	struct sk_buff *txSkb_p;
} offChanListItem;
#else				//906X off-channel
typedef struct ReqIdListItem {
	struct ReqIdListItem *nxt;
	struct ReqIdListItem *prv;
	UINT32 ReqId;
	struct sk_buff *txSkb_p;
} ReqIdListItem;
#endif				//906X off-channel

#define ACT_GET			HostCmd_ACT_GEN_GET
#define ACT_SET			HostCmd_ACT_GEN_SET
#define ACT_DEL			HostCmd_ACT_GEN_DEL

#endif				/* __HOSTCMD__H */
