/** @file bsstm.c
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2017-2020 NXP
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
 * \file    bsstm.c
 * \brief   BSS Transition management
 */

/*=============================================================================
 *                               INCLUDE FILES
 *=============================================================================
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/wireless.h>
#include <linux/pci.h>
#include <linux/delay.h>
#include <linux/string.h>

#include "wl.h"
#include "wldebug.h"
#include "ap8xLnxApi.h"
#include "IEEE_types.h"
#include "wl_mib.h"
#include "macMgmtMlme.h"
#include "domain.h"
#include "StaDb.h"

#ifdef CLIENT_SUPPORT
#include "linkmgt.h"
#include "mlme.h"
#include "mlmeApi.h"
#endif

#if defined(AP_STEERING_SUPPORT)  && defined(IEEE80211K)
#include "bsstm.h"
#include "msan_report.h"

/*=============================================================================
 *                                DEFINITIONS
 *=============================================================================
*/
#define BSS_TM_DISASSOC_TIME_DEFAULT (50)

static Timer BssTMDisassocTimer;
#ifdef SOC_W8964
static IEEEtypes_MacAddr_t BssTM_STAaddr;
#endif
static UINT32 BssTMTime = 0;

/*=============================================================================
 *                         IMPORTED PUBLIC VARIABLES
 *=============================================================================
 */
/*=============================================================================
 *                          MODULE LEVEL VARIABLES
 *=============================================================================
 */

/*=============================================================================
 *                   PRIVATE PROCEDURES (ANSI Prototypes)
 *=============================================================================
 */

/*=============================================================================
 *                         CODED PROCEDURES
 *=============================================================================
 */

extern struct sk_buff *mlmeApiPrepMgtMsg2(UINT32 Subtype, IEEEtypes_MacAddr_t * DestAddr, IEEEtypes_MacAddr_t * SrcAddr, UINT16 size);

/*
 *Function Name:
 *
 *Parameters:
 *
 *Description:
 *
 *Returns:
 *
 */
static void bsstm_assocdenied_cb(UINT8 * data)
{
	macMgmtMlme_AssocDenied(IEEEtypes_STATUS_SUCCESS);
}

#ifdef SOC_W8964
static void bsstm_disassoc_cb(UINT8 * data)
{
	struct net_device *netdev = (struct net_device *)data;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	extStaDb_StaInfo_t *StaInfo;

	StaInfo = extStaDb_GetStaInfo(vmacSta_p, &BssTM_STAaddr, 1);
	if (StaInfo == NULL) {
		printk("Failed to get StaInfo...\n");
		return FALSE;
	}
	printk("BSS Disassoc StaInfo State:%d\n", StaInfo->State);
	if (StaInfo->State != ASSOCIATED) {
		return;
	}

	macMgmtMlme_SendDisassociateMsg(vmacSta_p, &BssTM_STAaddr, 0, IEEEtypes_REASON_DISASSOC_AP_BUSY);

}
#endif

static void bsstm_disassoc_timeoutHdlr(UINT8 * data)
{
	extStaDb_StaInfo_t *StaInfo_p = (extStaDb_StaInfo_t *) data;
	struct net_device *netdev = StaInfo_p->dev;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;

	if (StaInfo_p->State == ASSOCIATED)
		macMgmtMlme_SendDisassociateMsg(vmacSta_p, &StaInfo_p->Addr, StaInfo_p->StnId, IEEEtypes_REASON_DISASSOC_AP_BUSY);
}

void bsstm_set_disassoc_timer(vmacApInfo_t * vmacSta_p, IEEEtypes_MacAddr_t * destaddr, UINT16 disassoc_time)
{
	extStaDb_StaInfo_t *StaInfo_p = NULL;
	UINT32 timeout = 0;

	StaInfo_p = extStaDb_GetStaInfo(vmacSta_p, destaddr, STADB_DONT_UPDATE_AGINGTIME);
	if (StaInfo_p == NULL) {
		printk("Failed to get StaInfo when set BTM disassoc timer.\n");
		return;
	}

	if (StaInfo_p->State != ASSOCIATED) {
		printk("BSS Disassoc StaInfo State is not associated! (State=%d)\n", StaInfo_p->State);
		return;
	}

	TimerDisarm(&StaInfo_p->btmreq_disassocTimer);
	TimerInit(&StaInfo_p->btmreq_disassocTimer);

	timeout = disassoc_time * (*(vmacSta_p->Mib802dot11->mib_BcnPeriod));
	TimerFireInByJiffies(&StaInfo_p->btmreq_disassocTimer, 1, &bsstm_disassoc_timeoutHdlr, (UINT8 *) StaInfo_p, timeout * TIMER_1MS);
}

BOOLEAN bsstm_send_request(struct net_device * netdev, UINT8 * destaddr, struct IEEEtypes_BSS_TM_Request_t * btmreq_p)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	struct sk_buff *skb;
	UINT8 btm_len = 0;
	UINT8 NBListNum = 0;
	UINT8 *var_ptr;
	macmgmtQ_MgmtMsg2_t *MgmtResp_p;
	struct IEEEtypes_BSS_TM_Request_t *BSS_TM_Req_p;
	struct IEEEtypes_Neighbor_Report_Element_t *PrefList_p;
	struct IEEEtypes_Neighbor_Report_Element_t *NeighborReList_p = NULL;

	btm_len = sizeof(struct IEEEtypes_BSS_TM_Request_t);
	NBListNum = wlpptr->wlpd_p->nb_info.nb_elem_number;
	NeighborReList_p = wlpptr->wlpd_p->nb_info.nb_elem;
	if (NBListNum > 0) {
		btmreq_p->PrefCandiListInc = 1;
	}
	if (btmreq_p->PrefCandiListInc) {
		btm_len += (sizeof(struct IEEEtypes_Neighbor_Report_Element_t) + 3) * NBListNum;
//              btm_len += sizeof(struct IEEEtypes_Neighbor_Report_Element_t)  * NBListNum;
	}

	if ((skb = mlmeApiPrepMgtMsg2(IEEE_MSG_QOS_ACTION,
				      (IEEEtypes_MacAddr_t *) destaddr, (IEEEtypes_MacAddr_t *) & vmacSta_p->macStaAddr, 3 + btm_len))
	    == NULL) {
		printk("Failed to allocate buffer ...\n");
		return FALSE;
	}
	MgmtResp_p = (macmgmtQ_MgmtMsg2_t *) skb->data;
	MgmtResp_p->Body.Action.Category = AC_WNM;
	MgmtResp_p->Body.Action.Action = AF_WNM_BTM_REQUEST;
	if (wlpptr->wlpd_p->Global_DialogToken == 0) {
		wlpptr->wlpd_p->Global_DialogToken = (wlpptr->wlpd_p->Global_DialogToken + 1) % 63;
	}
	MgmtResp_p->Body.Action.DialogToken = wlpptr->wlpd_p->Global_DialogToken;
	wlpptr->wlpd_p->Global_DialogToken = (wlpptr->wlpd_p->Global_DialogToken + 1) % 63;
	BSS_TM_Req_p = (struct IEEEtypes_BSS_TM_Request_t *)
	    &MgmtResp_p->Body.Action.Data;
	memcpy(BSS_TM_Req_p, btmreq_p, sizeof(struct IEEEtypes_BSS_TM_Request_t));

//      PrefList_p = (struct IEEEtypes_Neighbor_Report_Element_t *) BSS_TM_Req_p->variable;
	var_ptr = BSS_TM_Req_p->variable;
	if (BSS_TM_Req_p->BSSTermiInc) {
		UINT16 *dur;

		memset(var_ptr, 0, 12);
		var_ptr[0] = 04;
		var_ptr[1] = 10;
		dur = (UINT16 *) (var_ptr + 10);
		*dur = 1;
		var_ptr += 12;
	}
	if (BSS_TM_Req_p->ESSDisassocImm) {
		var_ptr[0] = 0;
		var_ptr += 1;
	}

	if (BSS_TM_Req_p->PrefCandiListInc) {
		UINT8 i;

//              PrefList_p = (struct IEEEtypes_Neighbor_Report_Element_t *) BSS_TM_Req_p->variable;
//              var_ptr = BSS_TM_Req_p->variable;
		for (i = 0; i < NBListNum; i++) {
			PrefList_p = (struct IEEEtypes_Neighbor_Report_Element_t *)var_ptr;
			memcpy(PrefList_p, &NeighborReList_p[i], sizeof(struct IEEEtypes_Neighbor_Report_Element_t));
			var_ptr += sizeof(struct IEEEtypes_Neighbor_Report_Element_t);
			PrefList_p->Len += 3;
			var_ptr[0] = 03;
			var_ptr[1] = 01;
			var_ptr[2] = 255;
			var_ptr += 3;
		}
	}

	if (txMgmtMsg(vmacSta_p->dev, skb) != OS_SUCCESS) {
		wl_free_skb(skb);
//              printk("BTM Req failed\n");
		return FALSE;
	}

	if (BSS_TM_Req_p->disassoc_timer) {
		/* send disassociation frame after time-out */
		bsstm_set_disassoc_timer(vmacSta_p, (IEEEtypes_MacAddr_t *) destaddr, BSS_TM_Req_p->disassoc_timer);
	}
	return TRUE;
}

void bsstm_disassoc_timer_set(UINT32 disassoc_time)
{
	if (disassoc_time == 0) {
		BssTMTime = BSS_TM_DISASSOC_TIME_DEFAULT;
	} else {
		BssTMTime = disassoc_time * 10;
	}
}

void bsstm_disassoc_timer_del(void)
{
	TimerDisarm(&BssTMDisassocTimer);
}

void bsstm_AssocDenied(UINT32 disassoc_time)
{
	macMgmtMlme_AssocDenied(IEEEtypes_STATUS_ASSOC_DENIED_BUSY);

	TimerInit(&BssTMDisassocTimer);
	TimerDisarm(&BssTMDisassocTimer);
	TimerFireIn(&BssTMDisassocTimer, 1, &bsstm_assocdenied_cb, NULL, disassoc_time * 10);
}
#endif				//AP_STEERING_SUPPORT && IEEE80211K
