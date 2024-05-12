/** @file qos_back.c
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

/* This file contains function for Block Ack*/

#ifdef QOS_FEATURE

#include "wltypes.h"
#include "IEEE_types.h"
#include "mib.h"
#include "wl_mib.h"
#include "wl_hal.h"
#include "qos.h"
#include "ds.h"
#include "osif.h"
#include "keyMgmtCommon.h"
#include "keyMgmt.h"
#include "tkip.h"
#include "StaDb.h"
#include "macmgmtap.h"
#include "wlmac.h"

#include "wldebug.h"
#ifdef AP_MAC_LINUX
extern struct sk_buff *mlmeApiPrepMgtMsg2(UINT32 Subtype,
					  IEEEtypes_MacAddr_t * DestAddr,
					  IEEEtypes_MacAddr_t * SrcAddr,
					  UINT16 size);
#else
extern tx80211_MgmtMsg_t *mlmeApiPrepMgtMsg2(UINT32 Subtype,
					     IEEEtypes_MacAddr_t * DestAddr,
					     IEEEtypes_MacAddr_t * SrcAddr,
					     UINT16 size);
#endif

void
SendAddBAReq(vmacApInfo_t * vmacSta_p, IEEEtypes_MacAddr_t StaAddrA, UINT8 tsid,
	     IEEEtypes_QoS_BA_Policy_e BaPolicy, UINT32 SeqNo,
	     UINT8 DialogToken)
{
	//macmgmtQ_MgmtMsg_t * MgmtReq_p;
	//extStaDb_StaInfo_t StaInfo;
	//Mrvl_TSPEC_t *pTspec;
	//tx80211_MgmtMsg_t *TxMsg_p;
#ifdef AP_MAC_LINUX
	struct sk_buff *txSkb_p;
#endif
	macmgmtQ_MgmtMsg2_t *MgmtRsp_p;
	//extStaDb_StaInfo_t *pStaInfo;
	//WSM_DELTS_Req_t *pDelTSFrm;
	//IEEEtypes_ADDBA_Req_t2 *pAddBaReqFrm;
	IEEEtypes_ADDBA_Req_t *pAddBaReqFrm;
	//sba++
#ifdef SOC_W906X
	extStaDb_StaInfo_t *pStaInfo = NULL;
	UINT8 he_capable;
#endif

	if ((txSkb_p =
	     mlmeApiPrepMgtMsg2(IEEE_MSG_QOS_ACTION,
				(IEEEtypes_MacAddr_t *) StaAddrA,
				(IEEEtypes_MacAddr_t *) vmacSta_p->macBssId,
				sizeof(IEEEtypes_ADDBA_Req_t2))) == NULL) {
		WLDBG_INFO(DBG_LEVEL_0, "No more buffer !!!!!!!!!!!!\n");
		return;
	}

	if ((pStaInfo =
	     extStaDb_GetStaInfo(vmacSta_p, (IEEEtypes_MacAddr_t *) StaAddrA,
				 STADB_DONT_UPDATE_AGINGTIME)) == NULL) {
		printk("sta:%02x%02x%02x%02x%02x%02x not in StaDb\n",
		       StaAddrA[0], StaAddrA[1], StaAddrA[2], StaAddrA[3],
		       StaAddrA[4], StaAddrA[5]);
		return;
	}
#ifdef SOC_W906X
	if (pStaInfo->he_cap_ie != HE_CAPABILITIES_IE ||
	    (ismemzero
	     ((u8 *) & pStaInfo->he_mac_cap, sizeof(HE_Mac_Capabilities_Info_t))
	     && ismemzero((u8 *) & pStaInfo->he_phy_cap,
			  sizeof(HE_Phy_Capabilities_Info_t))))
		he_capable = 0;
	else
		he_capable = 1;
#endif

	MgmtRsp_p = (macmgmtQ_MgmtMsg2_t *) txSkb_p->data;
	pAddBaReqFrm = (IEEEtypes_ADDBA_Req_t *) & MgmtRsp_p->Body;

	//HACK FOR NOW FOO
	//WLDBG_DUMP_DATA(1, txSkb_p->data, txSkb_p->len);
	pAddBaReqFrm->Category = BlkAck;
	pAddBaReqFrm->Action = ADDBA_REQ;
	pAddBaReqFrm->DialogToken = DialogToken;
	pAddBaReqFrm->ParamSet.amsdu =
		(*(vmacSta_p->Mib802dot11->pMib_11nAggrMode) &
		 WL_MODE_AMSDU_TX_MASK) ? 1 : 0;
	pAddBaReqFrm->ParamSet.BA_policy = BaPolicy;
	pAddBaReqFrm->ParamSet.tid = tsid;
#ifdef SOC_W906X
	//sba++
	if (he_capable) {
		if ((*(vmacSta_p->Mib802dot11->mib_superBA) == 1) ||
		    (*(vmacSta_p->Mib802dot11->mib_superBA) == 2))
			pAddBaReqFrm->ParamSet.BufSize =
				MAX_BA_REORDER_BUF_SIZE;
		else
			pAddBaReqFrm->ParamSet.BufSize = 64;
	} else
#endif
		pAddBaReqFrm->ParamSet.BufSize = 64;

	//printk("%s(): BufSize=%u\n", __func__, pAddBaReqFrm->ParamSet.BufSize);

	pAddBaReqFrm->Timeout_val = 0x0;	//in sec
	pAddBaReqFrm->SeqControl.FragNo = 0;
	pAddBaReqFrm->SeqControl.Starting_Seq_No = SeqNo;
#ifdef MV_CPU_BE
	pAddBaReqFrm->ParamSet.u16_data =
		ENDIAN_SWAP16(pAddBaReqFrm->ParamSet.u16_data);
	pAddBaReqFrm->SeqControl.u16_data =
		ENDIAN_SWAP16(pAddBaReqFrm->SeqControl.u16_data);;
#endif

	/* Send mgt frame */
#ifdef AP_MAC_LINUX
	if (txMgmtMsg(vmacSta_p->dev, txSkb_p) != OS_SUCCESS) {
		wl_free_skb(txSkb_p);
		return;
	}
#endif
	return;
}

void
ProcessAddBAReq(macmgmtQ_MgmtMsg_t * pMgmtMsg)
{
	//The first condition finds if the dialog token matches...
	if (GetTspec
	    ((IEEEtypes_MacAddr_t *) pMgmtMsg->Hdr.SrcAddr,
	     pMgmtMsg->Body.AddBAResp.DialogToken) ||
	    (pMgmtMsg->Body.AddBAResp.StatusCode != 0)) {
		return;
	}
	//stop timer
	//Record data
}

void
SendDelBA(vmacApInfo_t * vmacSta_p, IEEEtypes_MacAddr_t StaAddr, UINT8 tsid)
{
	IEEEtypes_DELBA_t *pDelBA;
	//tx80211_MgmtMsg_t * TxMsg_p;
#ifdef AP_MAC_LINUX
	struct sk_buff *txSkb_p;
#endif
	macmgmtQ_MgmtMsg2_t *MgmtRsp_p;

	if ((txSkb_p =
	     mlmeApiPrepMgtMsg2(IEEE_MSG_QOS_ACTION,
				(IEEEtypes_MacAddr_t *) StaAddr,
				(IEEEtypes_MacAddr_t *) vmacSta_p->macBssId,
				sizeof(IEEEtypes_DELBA_t))) == NULL) {
		WLDBG_INFO(DBG_LEVEL_0, "No more buffer !!!!!!!!!!!!\n");
		return;
	}

	MgmtRsp_p = (macmgmtQ_MgmtMsg2_t *) txSkb_p->data;
	pDelBA = (IEEEtypes_DELBA_t *) & MgmtRsp_p->Body;

	pDelBA->Category = BlkAck;
	pDelBA->Action = DELBA;
	pDelBA->ParamSet.Resvd = 0;
#ifdef MV_CPU_BE
	pDelBA->ParamSet.Resvd1 = 0;
#endif
	pDelBA->ParamSet.Initiator = 1;
	pDelBA->ParamSet.tid = tsid;
	pDelBA->ReasonCode = 1;

	/* Send mgt frame */
	if (txMgmtMsg(vmacSta_p->dev, txSkb_p) != OS_SUCCESS) {
		wl_free_skb(txSkb_p);
		return;
	}
	//start timer
	//Do HouseKeeping
	return;
}

void
SendDelBA2(vmacApInfo_t * vmacSta_p, IEEEtypes_MacAddr_t StaAddr, UINT8 tsid)
{
	IEEEtypes_DELBA_t *pDelBA;
	//tx80211_MgmtMsg_t *TxMsg_p;
#ifdef AP_MAC_LINUX
	struct sk_buff *txSkb_p;
#endif
	macmgmtQ_MgmtMsg2_t *MgmtRsp_p;

	if ((txSkb_p =
	     mlmeApiPrepMgtMsg2(IEEE_MSG_QOS_ACTION,
				(IEEEtypes_MacAddr_t *) StaAddr,
				(IEEEtypes_MacAddr_t *) vmacSta_p->macBssId,
				sizeof(IEEEtypes_DELBA_t))) == NULL) {
		WLDBG_INFO(DBG_LEVEL_0, "No more buffer !!!!!!!!!!!!\n");
		return;
	}

	MgmtRsp_p = (macmgmtQ_MgmtMsg2_t *) txSkb_p->data;
	pDelBA = (IEEEtypes_DELBA_t *) & MgmtRsp_p->Body;

	pDelBA->Category = BlkAck;
	pDelBA->Action = DELBA;
	pDelBA->ParamSet.Resvd = 0;
#ifdef MV_CPU_BE
	pDelBA->ParamSet.Resvd1 = 0;
#endif
	pDelBA->ParamSet.Initiator = 0;
	pDelBA->ParamSet.tid = tsid;
	pDelBA->ReasonCode = 1;

	/* Send mgt frame */
	if (txMgmtMsg(vmacSta_p->dev, txSkb_p) != OS_SUCCESS) {
		wl_free_skb(txSkb_p);
		return;
	}
	//start timer
	//Do HouseKeeping
	return;

	//check to see if a BA has been established for this TS
	//return;
}

void
SendGroupIDMgmtframe(vmacApInfo_t * vmacSta_p, IEEEtypes_MacAddr_t StaAddr,
		     UINT8 gid, UINT8 userposition)
{
	IEEEtypes_GroupIDMgmt_t *pGroupIDMgmt;
	//tx80211_MgmtMsg_t *TxMsg_p;
#ifdef AP_MAC_LINUX
	struct sk_buff *txSkb_p;
#endif
	macmgmtQ_MgmtMsg2_t *MgmtRsp_p;

	if ((txSkb_p =
	     mlmeApiPrepMgtMsg2(IEEE_MSG_QOS_ACTION,
				(IEEEtypes_MacAddr_t *) StaAddr,
				(IEEEtypes_MacAddr_t *) vmacSta_p->macBssId,
				sizeof(IEEEtypes_GroupIDMgmt_t))) == NULL) {
		WLDBG_INFO(DBG_LEVEL_0, "No more buffer !!!!!!!!!!!!\n");
		return;
	}

	MgmtRsp_p = (macmgmtQ_MgmtMsg2_t *) txSkb_p->data;
	pGroupIDMgmt = (IEEEtypes_GroupIDMgmt_t *) & MgmtRsp_p->Body;

	pGroupIDMgmt->Category = VHT;
	pGroupIDMgmt->VHT_ACTION = 1;

	memset(&pGroupIDMgmt->MembershipStatusArray[0], 0, 8);
	memset(&pGroupIDMgmt->UserPositionArray[0], 0, 16);

	printk("Userid=%x Position=%x--------------------\n", gid,
	       userposition);

	if (gid < 64) {
		pGroupIDMgmt->MembershipStatusArray[gid / 8] = 1 << (gid % 8);
		pGroupIDMgmt->UserPositionArray[gid / 4] =
			(userposition) << (2 * (gid % 4));
	}

	/* Send mgt frame */
	if (txMgmtMsg(vmacSta_p->dev, txSkb_p) != OS_SUCCESS) {
		wl_free_skb(txSkb_p);
		return;
	}
	//start timer
	//Do HouseKeeping
	return;

	//check to see if a BA has been established for this TS
	//return;
}
#endif
