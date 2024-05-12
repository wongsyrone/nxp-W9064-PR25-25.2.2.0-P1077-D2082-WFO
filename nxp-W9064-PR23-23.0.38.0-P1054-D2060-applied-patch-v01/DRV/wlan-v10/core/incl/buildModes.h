/** @file buildModes.h
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

#ifndef _BUILD_MODES_H_
#define _BUILD_MODES_H_

#define OEMSSID "NXPAP%1x%1x"	/* default SSID */
#define OEM_UR_SSID "NXP_AP"	/* default SSID of AP to connect UR */
#define MAX_PMAC 3
#include "smac_hal_inf.h"
#ifdef SOC_W906X
#define OEMCHANNEL 36/** default channel **/
#if defined(CLIENT_SUPPORT)
#define NUMOFAPS                SMAC_BSS_NUM	//(SMAC_BSS_NUM -1)
#else
#define NUMOFAPS                SMAC_BSS_NUM
#endif
#define MAX_STNS                SMAC_STA_NUM
#define DEF_STN_ID              MAX_STNS
#define MAX_TID                 SMAC_QID_PER_STA
#define QUEUE_STAOFFSET         (bss_num * SMAC_QID_PER_STA)
#else
#define OEMCHANNEL 6/** default channel **/
#define MAX_STNS  300 /** Maximum allow associated station **/
#define MAX_TID   8
#endif
#define MAX_AID                 (MAX_STNS * MAX_PMAC)

#define ENABLE_ERP_PROTECTION 1
#define ERP 1
#define DISABLE_B_AP_CHECK
#define CONSECTXFAILLIMIT		500	//Default value. Consecutive tx fail cnt > limit to kick out client. Zero to disable.
#define _CONSECTXFAILLIMIT		500	//Use this when enabling mcastproxy with mib_consectxfaillimit value set as default

#ifdef QOS_FEATURE
//#define RX_QOSDATA_SUPPORT 
//#define ETHER_RX_QOSDATA_SUPPORT
#ifdef UAPSD
#define WMM_PS_SUPPORT
#endif
#endif

#endif /* _BUILD_MODES_H_ */
