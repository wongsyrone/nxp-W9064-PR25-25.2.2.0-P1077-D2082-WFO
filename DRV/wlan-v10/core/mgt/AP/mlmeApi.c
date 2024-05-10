/** @file mlmeApi.c
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

#include "wltypes.h"
#include "IEEE_types.h"
#include "osif.h"

#include "mib.h"
#include "wl_mib.h"
#include "wl_hal.h"
#include "qos.h"
#include "wlmac.h"
#include "ds.h"
#include "keyMgmtCommon.h"
#include "keyMgmt.h"
#include "tkip.h"
#include "StaDb.h"
#include "macmgmtap.h"
#include "wlvmac.h"

#include "bcngen.h"
#include "macMgmtMlme.h"
#include "Fragment.h"
#include "wl_macros.h"
#include "wpa.h"
#include "keyMgmtSta.h"

#include "mhsm.h"
#include "mlme.h"
#include "smeMain.h"
#include "wldebug.h"
#include "ap8xLnxIntf.h"
#include "ap8xLnxFwcmd.h"
#include "mlmeApi.h"
#include "idList.h"
#ifndef SOC_W906X
#define	IEEE80211_ADDR_LEN	6
#endif
#define	IEEE80211_ADDR_LEN	6
struct ieee80211_frame {
	u_int8_t i_fc[2];
	u_int8_t i_dur[2];
	u_int8_t i_addr1[IEEE80211_ADDR_LEN];
	u_int8_t i_addr2[IEEE80211_ADDR_LEN];
	u_int8_t i_addr3[IEEE80211_ADDR_LEN];
	u_int8_t i_seq[2];
	u_int8_t i_addr4[IEEE80211_ADDR_LEN];
} PACK;

extern struct sk_buff *ieee80211_getmgtframe(UINT8 ** frm, unsigned int pktlen);
#ifdef SOC_W906X
struct sk_buff *ieee80211_getmgtframe_undefine_len(UINT8 ** frm,
						   unsigned int pktlen);
#endif
extern void FixedRateCtl(extStaDb_StaInfo_t * pStaInfo, PeerInfo_t * PeerInfo,
			 MIB_802DOT11 * mib);
extern void wlAcntCopyRateTbl(struct net_device *netdev, UINT8 * sta_addr,
			      UINT32 sta_id, UINT8 type);

#ifdef AP_MAC_LINUX
struct sk_buff *
mlmeApiPrepMgtMsg(UINT32 Subtype, IEEEtypes_MacAddr_t * DestAddr,
		  IEEEtypes_MacAddr_t * SrcAddr)
#else
tx80211_MgmtMsg_t *
mlmeApiPrepMgtMsg(UINT32 Subtype, IEEEtypes_MacAddr_t * DestAddr,
		  IEEEtypes_MacAddr_t * SrcAddr)
#endif
{
	macmgmtQ_MgmtMsg2_t *MgmtMsg_p;
	//tx80211_MgmtMsg_t * TxMsg_p;
	//UINT32 size;
#ifdef AP_MAC_LINUX
	struct sk_buff *skb;
	UINT8 *frm;

#ifdef SOC_W906X
	if ((skb =
	     ieee80211_getmgtframe_undefine_len(&frm,
						sizeof(struct ieee80211_frame) +
						1024)) != NULL)
#else
	if ((skb =
	     ieee80211_getmgtframe(&frm,
				   sizeof(struct ieee80211_frame) + 2)) != NULL)
#endif
	{
		//skb->len = 34;
		//skb->tail+= 34;
		WLDBG_INFO(DBG_LEVEL_8, "mlmeApiPrepMgtMsg length = %d \n",
			   skb->len);
#ifdef SOC_W906X
		skb_put(skb, sizeof(struct ieee80211_frame));
#endif
		MgmtMsg_p = (macmgmtQ_MgmtMsg2_t *) skb->data;
		MgmtMsg_p->Hdr.FrmCtl.Type = IEEE_TYPE_MANAGEMENT;
		MgmtMsg_p->Hdr.FrmCtl.Subtype = Subtype;
		MgmtMsg_p->Hdr.FrmCtl.Retry = 0;
		MgmtMsg_p->Hdr.Duration = 300;
		memcpy(&MgmtMsg_p->Hdr.DestAddr, DestAddr,
		       sizeof(IEEEtypes_MacAddr_t));
		memcpy(&MgmtMsg_p->Hdr.SrcAddr, SrcAddr,
		       sizeof(IEEEtypes_MacAddr_t));
		memcpy(&MgmtMsg_p->Hdr.BssId, SrcAddr,
		       sizeof(IEEEtypes_MacAddr_t));
	}

	return skb;
#else
#ifdef AP_BUFFER
	if ((TxMsg_p = (tx80211_MgmtMsg_t *) pool_GetBuf(txMgmtPoolId)) != NULL) {
		MgmtMsg_p = &TxMsg_p->MgmtFrame;
		MgmtMsg_p->Hdr.FrmCtl.Type = IEEE_TYPE_MANAGEMENT;
		MgmtMsg_p->Hdr.FrmCtl.Subtype = Subtype;
		MgmtMsg_p->Hdr.FrmCtl.Retry = 0;
		MgmtMsg_p->Hdr.Duration = 300;
		memcpy(&MgmtMsg_p->Hdr.DestAddr, DestAddr,
		       sizeof(IEEEtypes_MacAddr_t));
		memcpy(&MgmtMsg_p->Hdr.SrcAddr, SrcAddr,
		       sizeof(IEEEtypes_MacAddr_t));
		memcpy(&MgmtMsg_p->Hdr.BssId, SrcAddr,
		       sizeof(IEEEtypes_MacAddr_t));
	}
	return TxMsg_p;
#else
	return NULL;
#endif
#endif
}

#ifdef AP_MAC_LINUX
struct sk_buff *
mlmeApiPrepMgtMsg2(UINT32 Subtype, IEEEtypes_MacAddr_t * DestAddr,
		   IEEEtypes_MacAddr_t * SrcAddr, UINT16 size)
#else
tx80211_MgmtMsg_t *
mlmeApiPrepMgtMsg2(UINT32 Subtype, IEEEtypes_MacAddr_t * DestAddr,
		   IEEEtypes_MacAddr_t * SrcAddr, UINT16 size)
#endif
{
	macmgmtQ_MgmtMsg2_t *MgmtMsg_p;
	//tx80211_MgmtMsg_t * TxMsg_p;
	//UINT32 size;
#ifdef AP_MAC_LINUX
	struct sk_buff *skb;
	UINT8 *frm;

	if ((skb =
	     ieee80211_getmgtframe(&frm,
				   sizeof(struct ieee80211_frame) + size)) !=
	    NULL) {
		//skb->len = 34;
		//skb->tail+= 34;
		WLDBG_INFO(DBG_LEVEL_8, "mlmeApiPrepMgtMsg length = %d \n",
			   skb->len);
		MgmtMsg_p = (macmgmtQ_MgmtMsg2_t *) skb->data;
		MgmtMsg_p->Hdr.FrmCtl.Type = IEEE_TYPE_MANAGEMENT;
		MgmtMsg_p->Hdr.FrmCtl.Subtype = Subtype;
		MgmtMsg_p->Hdr.FrmCtl.Retry = 0;
		MgmtMsg_p->Hdr.Duration = 300;
		memcpy(&MgmtMsg_p->Hdr.DestAddr, DestAddr,
		       sizeof(IEEEtypes_MacAddr_t));
		memcpy(&MgmtMsg_p->Hdr.SrcAddr, SrcAddr,
		       sizeof(IEEEtypes_MacAddr_t));
		memcpy(&MgmtMsg_p->Hdr.BssId, SrcAddr,
		       sizeof(IEEEtypes_MacAddr_t));
	}

	return skb;
#else
#ifdef AP_BUFFER
	if ((TxMsg_p = (tx80211_MgmtMsg_t *) pool_GetBuf(txMgmtPoolId)) != NULL) {
		MgmtMsg_p = &TxMsg_p->MgmtFrame;
		MgmtMsg_p->Hdr.FrmCtl.Type = IEEE_TYPE_MANAGEMENT;
		MgmtMsg_p->Hdr.FrmCtl.Subtype = Subtype;
		MgmtMsg_p->Hdr.FrmCtl.Retry = 0;
		MgmtMsg_p->Hdr.Duration = 300;
		memcpy(&MgmtMsg_p->Hdr.DestAddr, DestAddr,
		       sizeof(IEEEtypes_MacAddr_t));
		memcpy(&MgmtMsg_p->Hdr.SrcAddr, SrcAddr,
		       sizeof(IEEEtypes_MacAddr_t));
		memcpy(&MgmtMsg_p->Hdr.BssId, SrcAddr,
		       sizeof(IEEEtypes_MacAddr_t));
	}
	return TxMsg_p;
#else
	return NULL;
#endif
#endif
}

#ifdef CLIENT_SUPPORT
UINT8 setClientPeerInfo(vmacEntry_t * vmacEntry_p, dot11MgtFrame_t * MgmtMsg_p,
			PeerInfo_t * pPeerInfo, extStaDb_StaInfo_t * StaInfo_p,
			UINT8 * QosInfo_p, MIB_802DOT11 * mib);
PeerInfo_t stationPeerInfo[NUM_OF_WLMACS];
extern int wlinitcnt;
void
InitClientPeerInfo(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacEntry_t *clientVMacEntry_p =
		(vmacEntry_t *) wlpptr->clntParent_priv_p;

	// Set the Peer info pointer.
	sme_SetClientPeerInfo(clientVMacEntry_p, &stationPeerInfo[wlinitcnt]);
	return;
}

#ifdef SOC_W906X
int
get_he_peer_nss(he_mcs_nss_support_t * mcs_nss_set_remote_p)
{
	int nss;
	int max_peer_nss_m1 = 0;

	for (nss = 0; nss < MAX_NSS; nss++) {
		switch (((mcs_nss_set_remote_p->max_mcs_set) >> (2 * nss)) & 3) {
		case HE_MCS_0_7:
			max_peer_nss_m1 = nss;
			break;
		case HE_MCS_0_9:
			max_peer_nss_m1 = nss;
			break;
		case HE_MCS_0_11:
			max_peer_nss_m1 = nss;
			break;
		case HE_NSS_NOT_SUPPORT:
			break;
		}
	}

	return max_peer_nss_m1;
}

#ifdef MULTI_AP_SUPPORT
void
InitClientInfo(UINT8 * macAddr_p, dot11MgtFrame_t * MgmtMsg_p,
	       vmacEntry_t * clientVMacEntry_p, BOOLEAN isApMrvl,
	       BOOLEAN isConnectbBSS)
#else
void
InitClientInfo(UINT8 * macAddr_p, dot11MgtFrame_t * MgmtMsg_p,
	       vmacEntry_t * clientVMacEntry_p, BOOLEAN isApMrvl)
#endif
{
	struct net_device *pStaDev =
		(struct net_device *)clientVMacEntry_p->privInfo_p;
	struct wlprivate *wlpptrSta = NETDEV_PRIV_P(struct wlprivate, pStaDev);
	vmacApInfo_t *vmacSta_p = wlpptrSta->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
	extStaDb_StaInfo_t *StaInfo_p = NULL;
	extStaDb_StaInfo_t *StaInfoRmAp_p = NULL;
	PeerInfo_t *pPeerInfo = NULL;
	//UINT32 Aid, StnId;
	UINT8 QosInfo = 0, wds = 0;
	UINT32 i = 0, staIdx;
	STA_SECURITY_MIBS *pStaSecurityMibs = NULL;
	WLAN_TX_RATE_HIST *txrate_histo_p;
	WLAN_SCHEDULER_HIST *sch_histo_p = NULL;

	if ((StaInfoRmAp_p =
	     extStaDb_GetStaInfo(wlpptrSta->vmacSta_p,
				 (IEEEtypes_MacAddr_t *) macAddr_p,
				 STADB_UPDATE_AGINGTIME)) == NULL) {
		if ((StaInfo_p =
		     wl_kmalloc(sizeof(extStaDb_StaInfo_t),
				GFP_ATOMIC)) == NULL) {
			printk("%s: Fail to allocate memory\n", __FUNCTION__);
			return;
		}

		memset(StaInfo_p, 0, sizeof(extStaDb_StaInfo_t));
		memcpy(&StaInfo_p->Addr, macAddr_p,
		       sizeof(IEEEtypes_MacAddr_t));
		staIdx = AssignStnId(wlpptrSta->vmacSta_p);
		if (staIdx >= sta_num) {
			wl_kfree(StaInfo_p);
			//printk("Error[%s:%d]: No Available resource AssignStnId Failed!!!\n", __func__, __LINE__);    
			return;
		}
		StaInfo_p->StnId = staIdx;
		StaInfo_p->AP = FALSE;
		StaInfo_p->Client = TRUE;
		StaInfo_p->mib_p = wlpptrSta->vmacSta_p->Mib802dot11;
		StaInfo_p->dev = pStaDev;
		extStaDb_AddSta(wlpptrSta->vmacSta_p, StaInfo_p);

		wl_kfree(StaInfo_p);

		if ((StaInfoRmAp_p =
		     extStaDb_GetStaInfo(wlpptrSta->vmacSta_p,
					 (IEEEtypes_MacAddr_t *) macAddr_p,
					 STADB_UPDATE_AGINGTIME)) == NULL) {
			printk("InitClientInfo: ERROR - cannot add host Client Remote AP to station database. \n");
			return;
		}
	}
	StaInfo_p = StaInfoRmAp_p;
	//StaInfo_p->Aid = MgmtMsg_p->Body.AssocRsp.AId; 
	StaInfo_p->Aid = AssignAid(wlpptrSta->vmacSta_p);

	// Set the Peer info.
	pPeerInfo = sme_GetClientPeerInfo(clientVMacEntry_p);

	// pass klocwork checking 
	if (pPeerInfo == NULL)
		return;

	memset(pPeerInfo, 0, sizeof(PeerInfo_t));

	setClientPeerInfo(clientVMacEntry_p, MgmtMsg_p, pPeerInfo, StaInfo_p,
			  &QosInfo, mib);

#ifdef SOC_W906X
	free_any_pending_ampdu_pck(pStaDev, StaInfo_p->StnId);
	for (i = 0; i < MAX_UP; i++)
				   /** Reset the ampdu reorder pck anyway **/
		wlpptrSta->wlpd_p->AmpduPckReorder[StaInfo_p->StnId].AddBaReceive[i] = FALSE;/** clear Ba flag **/
#else
	free_any_pending_ampdu_pck(pStaDev, StaInfo_p->Aid);
	for (i = 0; i < 3; i++)
			      /** Reset the ampdu reorder pck anyway **/
		wlpptrSta->wlpd_p->AmpduPckReorder[StaInfo_p->Aid].AddBaReceive[i] = FALSE;/** clear Ba flag **/
#endif /* SOC_W906X */
	if (*wlpptrSta->vmacSta_p->Mib802dot11->mib_AmpduTx) {
		memset(&StaInfo_p->aggr11n.startbytid[0], 0, 8);
		memset(&StaInfo_p->aggr11n.onbytid[0], 0, 8);
		StaInfo_p->aggr11n.type &= ~WL_WLAN_TYPE_AMPDU;
		AddHT_IE(vmacSta_p, &StaInfo_p->HtElem);
	}
	if ((*(wlpptrSta->vmacSta_p->Mib802dot11->pMib_11nAggrMode) &
	     WL_MODE_AMSDU_TX_MASK) == 0) {
		/* if AMSDU disabled locally then setup StaInfo_p accordingly */
		StaInfo_p->aggr11n.cap = 0;
	} else if ((*(wlpptrSta->vmacSta_p->Mib802dot11->pMib_11nAggrMode) &
		    WL_MODE_AMSDU_TX_MASK) == WL_MODE_AMSDU_TX_4K) {
		/* if AMSDU set to 4k locally then setup StaInfo_p as per this */
		StaInfo_p->aggr11n.cap = 1;
		if (!
		    (*(wlpptrSta->vmacSta_p->Mib802dot11->pMib_11nAggrMode) &
		     WL_MODE_AMPDU_TX)) {
			StaInfo_p->aggr11n.type |= WL_WLAN_TYPE_AMSDU;
		}
	}
	if (mib->Privacy->RSNEnabled && !mib->RSNConfigWPA2->WPA2OnlyEnabled) {
		pStaSecurityMibs = sme_GetStaSecurityMibsPtr(clientVMacEntry_p);
		if ((pStaSecurityMibs->thisStaRsnIE_p->ElemId == 221 ||
		     pStaSecurityMibs->thisStaRsnIE_p->ElemId == 48)
		    && (pStaSecurityMibs->thisStaRsnIE_p->PwsKeyCipherList[3] ==
			2)) {
			// TKIP disable non -NXP AP aggregation
			if (!isApMrvl) {
				StaInfo_p->aggr11n.threshold = 0;
				StaInfo_p->aggr11n.thresholdBackUp =
					StaInfo_p->aggr11n.threshold;
			}
		}
	}

	if (!isApMrvl && mib->Privacy->PrivInvoked) {
		StaInfo_p->aggr11n.threshold = 0;
		StaInfo_p->aggr11n.thresholdBackUp =
			StaInfo_p->aggr11n.threshold;
	}
	/* Update AP information into FW STADB */
#ifdef MULTI_AP_SUPPORT
	StaInfo_p->MultiAP_4addr = (isConnectbBSS) ? 1 : 0;
	if (isConnectbBSS) {
		wds = 4;
	}
#endif
	wlFwSetNewStn(pStaDev, macAddr_p, StaInfo_p->Aid, StaInfo_p->StnId,
		      StaInfoDbActionAddEntry, pPeerInfo, QosInfo,
		      StaInfo_p->IsStaQSTA, wds);

	wlFwSetSecurity(pStaDev, macAddr_p);
	/*Copy rate table rateinfo from fw to txRateHistogram so we can update counter correctly in SU */
	if (StaInfo_p->StnId < sta_num) {
		if ((txrate_histo_p =
		     (WLAN_TX_RATE_HIST *)
		     wl_kmalloc_autogfp(sizeof(WLAN_TX_RATE_HIST))) != NULL) {
			memset(txrate_histo_p, 0, sizeof(WLAN_TX_RATE_HIST));
			if (wlpptrSta->wlpd_p->
			    txRateHistogram[StaInfo_p->StnId] != NULL) {
				wl_kfree(wlpptrSta->wlpd_p->
					 txRateHistogram[StaInfo_p->StnId]);
				wlpptrSta->wlpd_p->txRateHistogram[StaInfo_p->
								   StnId] =
					NULL;
			}
			wlpptrSta->wlpd_p->txRateHistogram[StaInfo_p->StnId] =
				txrate_histo_p;

			wlAcntCopyRateTbl(pStaDev, (UINT8 *) & MgmtMsg_p->Hdr.BssId, StaInfo_p->StnId, SU_MIMO);	//SU for now
		} else
			printk("StaInfo_p->StnId:%d alloc WLAN_TX_RATE_HIST memory FAIL\n", StaInfo_p->StnId);

		if (wlpptrSta->wlpd_p->scheHistogram[StaInfo_p->StnId] != NULL)
			memset(wlpptrSta->wlpd_p->
			       scheHistogram[StaInfo_p->StnId], 0,
			       sizeof(WLAN_SCHEDULER_HIST));
		else {
			if ((sch_histo_p =
			     (WLAN_SCHEDULER_HIST *)
			     wl_kmalloc_autogfp(sizeof(WLAN_SCHEDULER_HIST))) !=
			    NULL) {
				memset(sch_histo_p, 0,
				       sizeof(WLAN_SCHEDULER_HIST));
				wlpptrSta->wlpd_p->scheHistogram[StaInfo_p->
								 StnId] =
					sch_histo_p;
			} else
				printk("StaInfo_p->StnId:%d alloc WLAN_SCHEDULER_HIST memory FAIL\n", StaInfo_p->StnId);
		}
	}
	StaInfo_p->State = ASSOCIATED;
	return;
}
#else
UINT8 initParentAp = 0;
UINT16 parentApAid = 0, parentApStnId = 0;
#ifdef V6FW
UINT16 ClientAid = 0, ClientStnId = 0;
#endif
#ifdef MULTI_AP_SUPPORT
void
InitClientInfo(UINT8 * macAddr_p, dot11MgtFrame_t * MgmtMsg_p,
	       vmacEntry_t * clientVMacEntry_p, BOOLEAN isApMrvl,
	       BOOLEAN isConnectbBSS)
#else
void
InitClientInfo(UINT8 * macAddr_p, dot11MgtFrame_t * MgmtMsg_p,
	       vmacEntry_t * clientVMacEntry_p, BOOLEAN isApMrvl)
#endif
{

	struct net_device *pStaDev =
		(struct net_device *)clientVMacEntry_p->privInfo_p;
	struct wlprivate *wlpptrSta = NETDEV_PRIV_P(struct wlprivate, pStaDev);
	vmacApInfo_t *vmacSta_p = wlpptrSta->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
	extStaDb_StaInfo_t *StaInfo = NULL;
	extStaDb_StaInfo_t *StaInfo_p = NULL;
	extStaDb_StaInfo_t *StaInfoRmAp_p = NULL;
#ifdef V6FW
	extStaDb_StaInfo_t *StaInfoClient_p = NULL;
#endif
	PeerInfo_t *pPeerInfo = NULL;
	//UINT32 Aid, StnId;
	UINT8 QosInfo = 0;
	UINT8 i = 0;
	STA_SECURITY_MIBS *pStaSecurityMibs = NULL;
	WLAN_TX_RATE_HIST *txrate_histo_p;

	/*Use dynamic memory to prevent frame size > 1024bytes warning during compilation
	 * extStaDb_StaInfo_t takes 1488bytes
	 */
	if ((StaInfo =
	     wl_kmalloc(sizeof(extStaDb_StaInfo_t), GFP_ATOMIC)) == NULL) {
		printk("%s: Fail to allocate memory\n", __FUNCTION__);
		return;
	}

	if (!initParentAp) {
		parentApAid = AssignAid(wlpptrSta->vmacSta_p);
		parentApStnId = AssignStnId(wlpptrSta->vmacSta_p);
		initParentAp = 1;
#ifdef V6FW
		ClientAid = AssignAid(wlpptrSta->vmacSta_p);
		ClientStnId = AssignStnId(wlpptrSta->vmacSta_p);
#endif
	}

	if ((StaInfoRmAp_p =
	     extStaDb_GetStaInfo(wlpptrSta->vmacSta_p,
				 (IEEEtypes_MacAddr_t *) macAddr_p,
				 1)) == NULL) {
		memset(StaInfo, 0, sizeof(extStaDb_StaInfo_t));
		memcpy(&StaInfo->Addr, macAddr_p, sizeof(IEEEtypes_MacAddr_t));
		StaInfo->StnId = parentApStnId;
		StaInfo->Aid = parentApAid;
		StaInfo->AP = FALSE;
		StaInfo->Client = TRUE;
		StaInfo->mib_p = wlpptrSta->vmacSta_p->Mib802dot11;
		StaInfo->dev = pStaDev;
		extStaDb_AddSta(wlpptrSta->vmacSta_p, StaInfo);

		if ((StaInfoRmAp_p =
		     extStaDb_GetStaInfo(wlpptrSta->vmacSta_p,
					 (IEEEtypes_MacAddr_t *) macAddr_p,
					 1)) == NULL) {
			printk("InitClientInfo: ERROR - cannot add host Client Remote AP to station database. \n");
			wl_kfree(StaInfo);
			return;
		}
	}
	StaInfo_p = StaInfoRmAp_p;

#ifdef V6FW
	if ((StaInfoClient_p =
	     extStaDb_GetStaInfo(wlpptrSta->vmacSta_p,
				 (IEEEtypes_MacAddr_t *) MgmtMsg_p->Hdr.
				 DestAddr, 1)) == NULL) {
		memset(StaInfo, 0, sizeof(extStaDb_StaInfo_t));
		memcpy(&StaInfo->Addr, MgmtMsg_p->Hdr.DestAddr,
		       sizeof(IEEEtypes_MacAddr_t));
		StaInfo->StnId = ClientStnId;
		StaInfo->Aid = ClientAid;
		StaInfo->AP = FALSE;
		StaInfo->Client = TRUE;
		StaInfo->mib_p = wlpptrSta->vmacSta_p->Mib802dot11;
		StaInfo->dev = pStaDev;
		extStaDb_AddSta(wlpptrSta->vmacSta_p, StaInfo);

		if ((StaInfoClient_p =
		     extStaDb_GetStaInfo(wlpptrSta->vmacSta_p,
					 (IEEEtypes_MacAddr_t *) MgmtMsg_p->Hdr.
					 DestAddr, 1)) == NULL) {
			printk("InitClientInfo: ERROR - Cannot add Host Client MAC to station database. \n");
			wl_kfree(StaInfo);
			return;
		}
	}
#endif
	wl_kfree(StaInfo);

	for (i = 0; i < 8; i++) {
		QosTsData[i].TidStatus = QOS_TS_ADMITTED;
		QosTsData[i].TidDowngrade = i;
		QosTsData[i].AccCategoryQ = AccCategoryQ[i];
		QosTsData[i].AccCategoryQDowngrade = QosTsData[i].AccCategoryQ;
	}

	// Set the Peer info.
	pPeerInfo = sme_GetClientPeerInfo(clientVMacEntry_p);
	memset(pPeerInfo, 0, sizeof(PeerInfo_t));
	setClientPeerInfo(clientVMacEntry_p, MgmtMsg_p, pPeerInfo, StaInfo_p,
			  &QosInfo, mib);
#ifdef V6FW
	setClientPeerInfo(clientVMacEntry_p, MgmtMsg_p, pPeerInfo,
			  StaInfoClient_p, &QosInfo, mib);
#endif

#ifdef AMPDU_SUPPORT
	free_any_pending_ampdu_pck(pStaDev, StaInfo_p->Aid);
	for (i = 0; i < 3; i++)
			      /** Reset the ampdu reorder pck anyway **/
		wlpptrSta->wlpd_p->AmpduPckReorder[StaInfo_p->Aid].AddBaReceive[i] = FALSE;/** clear Ba flag **/
#ifdef V6FW
	free_any_pending_ampdu_pck(pStaDev, StaInfoClient_p->Aid);
	for (i = 0; i < 3; i++)
			      /** Reset the ampdu reorder pck anyway **/
		wlpptrSta->wlpd_p->AmpduPckReorder[StaInfoClient_p->Aid].AddBaReceive[i] = FALSE;/** clear Ba flag **/
#endif

	if (*wlpptrSta->vmacSta_p->Mib802dot11->mib_AmpduTx) {
		memset(&StaInfo_p->aggr11n.startbytid[0], 0, 8);
		memset(&StaInfo_p->aggr11n.onbytid[0], 0, 8);
		StaInfo_p->aggr11n.type &= ~WL_WLAN_TYPE_AMPDU;
#ifdef V6FW
		memset(&StaInfoClient_p->aggr11n.startbytid[0], 0, 8);
		memset(&StaInfoClient_p->aggr11n.onbytid[0], 0, 8);
		StaInfoClient_p->aggr11n.type &= ~WL_WLAN_TYPE_AMPDU;
#endif
		AddHT_IE(vmacSta_p, &StaInfo_p->HtElem);
	}
#endif

	if ((*(wlpptrSta->vmacSta_p->Mib802dot11->pMib_11nAggrMode) &
	     WL_MODE_AMSDU_TX_MASK) == 0) {
		/* if AMSDU disabled locally then setup stainfo accordingly */
		StaInfo_p->aggr11n.threshold = 0;
		StaInfo_p->aggr11n.cap = 0;
#ifdef V6FW
		StaInfoClient_p->aggr11n.threshold = 0;
		StaInfoClient_p->aggr11n.cap = 0;
#endif
	} else if ((*(wlpptrSta->vmacSta_p->Mib802dot11->pMib_11nAggrMode) &
		    WL_MODE_AMSDU_TX_MASK) == WL_MODE_AMSDU_TX_4K) {
		/* if AMSDU set to 4k locally then setup stainfo as per this */
		StaInfo_p->aggr11n.cap = 1;
		if (!
		    (*(wlpptrSta->vmacSta_p->Mib802dot11->pMib_11nAggrMode) &
		     WL_MODE_AMPDU_TX)) {
			StaInfo_p->aggr11n.type |= WL_WLAN_TYPE_AMSDU;
		}
#ifdef V6FW
		StaInfoClient_p->aggr11n.cap = 1;
		if (!
		    (*(wlpptrSta->vmacSta_p->Mib802dot11->pMib_11nAggrMode) &
		     WL_MODE_AMPDU_TX))
			StaInfoClient_p->aggr11n.type |= WL_WLAN_TYPE_AMSDU;
#endif
	}

	if (mib->Privacy->RSNEnabled && !mib->RSNConfigWPA2->WPA2OnlyEnabled) {
		pStaSecurityMibs = sme_GetStaSecurityMibsPtr(clientVMacEntry_p);
		if ((pStaSecurityMibs->thisStaRsnIE_p->ElemId == 221 ||
		     pStaSecurityMibs->thisStaRsnIE_p->ElemId == 48)
		    && (pStaSecurityMibs->thisStaRsnIE_p->PwsKeyCipherList[3] ==
			2)) {
			// TKIP disable non -NXP AP aggregation
			if (!isApMrvl) {
				StaInfo_p->aggr11n.threshold = 0;
				StaInfo_p->aggr11n.thresholdBackUp =
					StaInfo_p->aggr11n.threshold;
#ifdef V6FW
				StaInfoClient_p->aggr11n.threshold = 0;
				StaInfoClient_p->aggr11n.thresholdBackUp =
					StaInfo_p->aggr11n.threshold;
#endif
			}
		}
	}

	if (!isApMrvl && mib->Privacy->PrivInvoked) {
		StaInfo_p->aggr11n.threshold = 0;
		StaInfo_p->aggr11n.thresholdBackUp =
			StaInfo_p->aggr11n.threshold;
#ifdef V6FW
		StaInfoClient_p->aggr11n.threshold = 0;
		StaInfoClient_p->aggr11n.thresholdBackUp =
			StaInfo_p->aggr11n.threshold;
#endif
	}

	/* First remove station even if not added to station database. */
	/* Remove AP entry into FW STADB */

#ifdef MULTI_AP_SUPPORT
	StaInfo_p->MultiAP_4addr = (isConnectbBSS) ? 1 : 0;
#endif

#ifdef MULTI_AP_SUPPORT
	if (isConnectbBSS)
		wlFwSetNewStn(pStaDev, (u_int8_t *) macAddr_p, parentApAid,
			      parentApStnId, 2, pPeerInfo, QosInfo,
			      StaInfo_p->IsStaQSTA, 4);
	else
#endif
		wlFwSetNewStn(pStaDev, (u_int8_t *) macAddr_p, parentApAid,
			      parentApStnId, 2, pPeerInfo, QosInfo,
			      StaInfo_p->IsStaQSTA, 0);
#ifdef V6FW
#ifdef MULTI_AP_SUPPORT
	if (isConnectbBSS)
		wlFwSetNewStn(pStaDev, (u_int8_t *) MgmtMsg_p->Hdr.DestAddr,
			      ClientAid, ClientStnId, 2, pPeerInfo, QosInfo,
			      StaInfoClient_p->IsStaQSTA, 4);
	else
#endif
		wlFwSetNewStn(pStaDev, (u_int8_t *) MgmtMsg_p->Hdr.DestAddr,
			      ClientAid, ClientStnId, 2, pPeerInfo, QosInfo,
			      StaInfoClient_p->IsStaQSTA, 0);
#endif

	/* Add AP entry into FW STADB */
#ifdef MULTI_AP_SUPPORT
	if (isConnectbBSS)
		wlFwSetNewStn(pStaDev, (u_int8_t *) macAddr_p, parentApAid,
			      parentApStnId, 0, pPeerInfo, QosInfo,
			      StaInfo_p->IsStaQSTA, 4);
	else
#endif
		wlFwSetNewStn(pStaDev, (u_int8_t *) macAddr_p, parentApAid,
			      parentApStnId, 0, pPeerInfo, QosInfo,
			      StaInfo_p->IsStaQSTA, 0);
#ifdef V6FW
#ifdef MULTI_AP_SUPPORT
	if (isConnectbBSS)
		wlFwSetNewStn(pStaDev, (u_int8_t *) MgmtMsg_p->Hdr.DestAddr, ClientAid, ClientStnId, 0, pPeerInfo, QosInfo, StaInfoClient_p->IsStaQSTA, 4);	// BHSTA
	else
#endif
		wlFwSetNewStn(pStaDev, (u_int8_t *) MgmtMsg_p->Hdr.DestAddr, ClientAid, ClientStnId, 0, pPeerInfo, QosInfo, StaInfoClient_p->IsStaQSTA, 0);	// BHSTA
#endif

	wlFwSetSecurity(pStaDev, macAddr_p);
#ifdef V6FW
	wlFwSetSecurity(pStaDev, (u_int8_t *) MgmtMsg_p->Hdr.DestAddr);
#endif

	/*Copy rate table rateinfo from fw to txRateHistogram so we can update counter correctly in SU */
	if (parentApStnId) {
		if ((txrate_histo_p =
		     (WLAN_TX_RATE_HIST *)
		     wl_kmalloc_autogfp(sizeof(WLAN_TX_RATE_HIST))) != NULL) {
			memset(txrate_histo_p, 0, sizeof(WLAN_TX_RATE_HIST));
			if (wlpptrSta->wlpd_p->
			    txRateHistogram[parentApStnId - 1] != NULL) {
				wl_kfree(wlpptrSta->wlpd_p->
					 txRateHistogram[parentApStnId - 1]);
				wlpptrSta->wlpd_p->
					txRateHistogram[parentApStnId - 1] =
					NULL;
			}
			wlpptrSta->wlpd_p->txRateHistogram[parentApStnId - 1] =
				txrate_histo_p;

			wlAcntCopyRateTbl(pStaDev, (UINT8 *) & MgmtMsg_p->Hdr.BssId, parentApStnId, SU_MIMO);	//SU for now
		} else
			printk("parentApStnId:%d alloc WLAN_TX_RATE_HIST memory FAIL\n", parentApStnId);
	}
	StaInfo_p->state = ASSOCIATED;
	return;
}
#endif /* SOC_W906X */

void
RemoveRemoteAPFw(UINT8 * apMacAddr_p, vmacEntry_t * clientVMacEntry_p)
{
	struct net_device *pStaDev =
		(struct net_device *)clientVMacEntry_p->privInfo_p;
	struct wlprivate *wlpptrSta = NETDEV_PRIV_P(struct wlprivate, pStaDev);
	extStaDb_StaInfo_t *StaInfo_p = NULL;

	if (!clientVMacEntry_p->active)
		wlFwRemoveMacAddr(pStaDev, &clientVMacEntry_p->vmacAddr[0]);

	if ((StaInfo_p =
	     extStaDb_GetStaInfo(wlpptrSta->vmacSta_p,
				 (IEEEtypes_MacAddr_t *) apMacAddr_p,
				 STADB_UPDATE_AGINGTIME)) != NULL) {
		extStaDb_DelSta(wlpptrSta->vmacSta_p,
				(IEEEtypes_MacAddr_t *) apMacAddr_p,
				STADB_DONT_UPDATE_AGINGTIME);
		wlFwSetNewStn(wlpptrSta->master, (u_int8_t *) apMacAddr_p,
			      StaInfo_p->Aid, StaInfo_p->StnId,
			      StaInfoDbActionRemoveEntry, NULL, 0, 0, 0);
		FreeAid(wlpptrSta->vmacSta_p, StaInfo_p->Aid);
		StaInfo_p->Aid = 0;
		FreeStnId(wlpptrSta->vmacSta_p, StaInfo_p->StnId);
	}

	return;
}
#endif
UINT8
setClientPeerInfo(vmacEntry_t * vmacEntry_p,
		  dot11MgtFrame_t * MgmtMsg_p,
		  PeerInfo_t * pPeerInfo,
		  extStaDb_StaInfo_t * StaInfo_p,
		  UINT8 * QosInfo_p, MIB_802DOT11 * mib)
{
	UINT8 *attrib_p;
	WME_param_elem_t *WME_param_elem = NULL;
	//PeerInfo_t PeerInfo, *pPeerInfo;
	IEEEtypes_SuppRatesElement_t *PeerSupportedRates_p;
	IEEEtypes_ExtSuppRatesElement_t *PeerExtSupportedRates_p;
	IEEEtypes_HT_Element_t *pHT;
	IEEEtypes_Add_HT_Element_t *pHTAdd;
	IEEEtypes_Generic_HT_Element_t *pHTGen;
	IEEEtypes_Generic_Add_HT_Element_t *pHTAddGen;
	MIB_802DOT11 *pMasterMIB;
	IEEEtypes_VhtCap_t *pVhtCap;
	IEEEtypes_VhOpt_t *pVhtOp;
	UINT32 vhtcap = 0;
#ifdef SOC_W906X
	vmacStaInfo_t *vStaInfo_p = NULL;
	IEEEtypes_InfoElementExtHdr_t *pIeExt;
#endif
#ifdef SUPPORTED_EXT_NSS_BW
	int ret = 0;
#endif
	struct net_device *dev;
	struct wlprivate *priv;
	vmacApInfo_t *vmacSta_p;
	he_mcs_nss_support_t *prx_he_mcs_80m = NULL;

	if (vmacEntry_p) {
		dev = (struct net_device *)vmacEntry_p->privInfo_p;
		priv = NETDEV_PRIV_P(struct wlprivate, dev);
		vmacSta_p = priv->vmacSta_p;
		pMasterMIB = vmacSta_p->master->Mib802dot11;
#ifdef SOC_W906X
		vStaInfo_p = (vmacStaInfo_t *) vmacEntry_p->info_p;
#endif
	} else
		return FALSE;

	StaInfo_p->ClientMode = BONLY_MODE;
	StaInfo_p->aggr11n.cap = 0;
	StaInfo_p->aggr11n.threshold = 0;
	StaInfo_p->IsStaQSTA = 0;

	memset((void *)pPeerInfo, 0, sizeof(PeerInfo_t));
#ifdef SOC_W906X
	if (vStaInfo_p)
		pPeerInfo->assocRSSI = vStaInfo_p->curRxInfo.RSSI;
#endif
	pPeerInfo->CapInfo = MgmtMsg_p->Body.AssocRsp.CapInfo;
	attrib_p = (UINT8 *) & MgmtMsg_p->Body.AssocRsp.AId;
	attrib_p += sizeof(IEEEtypes_AId_t);

	PeerSupportedRates_p =
		(IEEEtypes_SuppRatesElement_t *)
		syncSrv_ParseAttribWithinFrame(MgmtMsg_p, attrib_p,
					       SUPPORTED_RATES);

	PeerExtSupportedRates_p =
		(IEEEtypes_ExtSuppRatesElement_t *)
		syncSrv_ParseAttribWithinFrame(MgmtMsg_p, attrib_p,
					       EXT_SUPPORTED_RATES);

	if (PeerSupportedRates_p && PeerExtSupportedRates_p)
		StaInfo_p->ClientMode = GONLY_MODE;

	pPeerInfo->LegacyRateBitMap =
		GetAssocRespLegacyRateBitMap(PeerSupportedRates_p,
					     PeerExtSupportedRates_p);
	if (!(pPeerInfo->LegacyRateBitMap & 0x0f))
		StaInfo_p->ClientMode = AONLY_MODE;

	if ((pHT =
	     (IEEEtypes_HT_Element_t *)
	     syncSrv_ParseAttribWithinFrame(MgmtMsg_p, attrib_p, HT))) {
		pPeerInfo->HTCapabilitiesInfo = pHT->HTCapabilitiesInfo;
		pPeerInfo->MacHTParamInfo = pHT->MacHTParamInfo;
		pPeerInfo->HTRateBitMap =
			(pHT->
			 SupportedMCSset[0] | (pHT->
					       SupportedMCSset[1] << 8) | (pHT->
									   SupportedMCSset
									   [2]
									   <<
									   16) |
			 (pHT->SupportedMCSset[3] << 24));
		pPeerInfo->TxBFCapabilities = pHT->TxBFCapabilities;
		StaInfo_p->ClientMode = NONLY_MODE;
		StaInfo_p->aggr11n.threshold = 4;
		StaInfo_p->aggr11n.thresholdBackUp =
			StaInfo_p->aggr11n.threshold;
		if ((*(pMasterMIB->pMib_11nAggrMode) & WL_MODE_AMSDU_TX_MASK) &&
		    !(*(pMasterMIB->pMib_11nAggrMode) & WL_MODE_AMPDU_TX))
			StaInfo_p->aggr11n.type |= WL_WLAN_TYPE_AMSDU;
		if (pHT->HTCapabilitiesInfo.MaxAMSDUSize)
			StaInfo_p->aggr11n.cap = 2;
		else
			StaInfo_p->aggr11n.cap = 1;
		// Green Field not supported.
		pPeerInfo->HTCapabilitiesInfo.GreenField = 0;
		pPeerInfo->HTCapabilitiesInfo.RxSTBC = 0;
		pPeerInfo->HTCapabilitiesInfo.TxSTBC = 0;
	}
#ifdef CLIENT_SUPPORT
#ifdef CONFIG_IEEE80211W
	if (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_CLNT_INFRA) {
		IEEEtypes_RSN_IE_WPA2_t RsnIEWPA2_local;
		UINT8 mfpc_local = 0, mfpr_local = 0;
		IEEEtypes_RSN_IE_WPA2_t RsnIEWPA2;
		UINT8 mfpc = 0, mfpr = 0;

		StaInfo_p->Ieee80211wSta = 0;

		/* Get Local PMF capa */
		if ((vmacSta_p->RsnIESetByHost == 1) && (vmacSta_p->RsnIE)) {
			parsing_rsn_ie((UINT8 *) (vmacSta_p->RsnIE),
				       &RsnIEWPA2_local, &mfpc_local,
				       &mfpr_local);
			printk("%s: Local RSN mfpc=%d mfpr=%d\n", __func__,
			       mfpc_local, mfpr_local);
		}

		/* If Local support PMF, check Peer PMF capa */
		if ((mfpc_local + mfpr_local) >= 1) {
			if (vStaInfo_p) {
				parsing_rsn_ie((UINT8 *) &
					       (vStaInfo_p->bssDescProfile_p->
						Wpa2Element), &RsnIEWPA2, &mfpc,
					       &mfpr);
				if ((mfpc + mfpr) >= 1)
					StaInfo_p->Ieee80211wSta = 1;
				printk("%s: Peer RSN mfpc=%d mfpr=%d\n",
				       __func__, mfpc, mfpr);
			}
		}
		printk("%s StaInfo_p->Ieee80211wSta=%d\n", __func__,
		       StaInfo_p->Ieee80211wSta);
	}
#endif
#endif

	if ((pHTAdd =
	     (IEEEtypes_Add_HT_Element_t *)
	     syncSrv_ParseAttribWithinFrame(MgmtMsg_p, attrib_p, ADD_HT))) {
		pPeerInfo->AddHtInfo.ControlChan = pHTAdd->ControlChan;
		pPeerInfo->AddHtInfo.AddChan = pHTAdd->AddChan;
		pPeerInfo->AddHtInfo.OpMode = pHTAdd->OpMode;
		pPeerInfo->AddHtInfo.stbc = pHTAdd->stbc;
	}

	if ((pVhtCap =
	     (IEEEtypes_VhtCap_t *) syncSrv_ParseAttribWithinFrame(MgmtMsg_p,
								   attrib_p,
								   VHT_CAP))) {
		vhtcap = *((UINT32 *) & pVhtCap->cap);
		printk("VHT AP: vht_cap=%x, vht_RxMcs=%x, vht_TxMcs=%x\n",
		       (u_int32_t) vhtcap,
		       (u_int32_t) pVhtCap->SupportedRxMcsSet,
		       (u_int32_t) pVhtCap->SupportedTxMcsSet);

		memcpy((UINT8 *) & pPeerInfo->vht_cap, (UINT8 *) & pVhtCap->cap,
		       sizeof(IEEEtypes_VHT_Cap_Info_t));
		// Also need to update vhtCap.cap in StaIno which is needed for fw to set ampdu length
		memcpy((UINT8 *) & StaInfo_p->vhtCap.cap,
		       (UINT8 *) & pVhtCap->cap,
		       sizeof(IEEEtypes_VHT_Cap_Info_t));
		pPeerInfo->vht_MaxRxMcs = pVhtCap->SupportedRxMcsSet;

		if ((pVhtOp =
		     (IEEEtypes_VhOpt_t *)
		     syncSrv_ParseAttribWithinFrame(MgmtMsg_p, attrib_p,
						    VHT_OPERATION))) {
			switch (pVhtOp->ch_width) {
			case 0:
				if (pHTAdd &&
				    pHTAdd->AddChan.STAChannelWidth == 1)
					pPeerInfo->vht_RxChannelWidth = 1;
				else
					pPeerInfo->vht_RxChannelWidth = 0;
				break;
			case 1:
#ifdef SUPPORTED_EXT_NSS_BW
				printk("%s ", __FUNCTION__);

				if (1 ==
				    (ret =
				     isSupport160MhzByCenterFreq(priv,
								 VHT_EXTENDED_NSS_BW_CAPABLE,
								 pVhtOp->
								 center_freq0,
								 pVhtOp->
								 center_freq1,
								 (pHTAdd) ?
								 pHTAdd->OpMode.
								 center_freq2 :
								 0))) {

					pPeerInfo->vht_RxChannelWidth = 3;

				} else {
					if (ret == -1) {
						pPeerInfo->vht_RxChannelWidth =
							3;
					} else if (ret == 0) {
						pPeerInfo->vht_RxChannelWidth =
							2;
						printk("80MHz or less\n");
					}
				}
#else
				if (pVhtOp->center_freq1 == 0) {
					pPeerInfo->vht_RxChannelWidth = 2;
					printk("%s 80MHz or less\n",
					       __FUNCTION__);
				} else {
					UINT8 diff;
					if (pVhtOp->center_freq1 >
					    pVhtOp->center_freq0) {
						diff = pVhtOp->center_freq1 -
							pVhtOp->center_freq0;
					} else {
						diff = pVhtOp->center_freq0 -
							pVhtOp->center_freq1;
					}
					if (diff == 8) {
						printk("%s 160Mhz: center frequency of the 80 MHz channel segment that contains the primary channel = %d\n", __FUNCTION__, pVhtOp->center_freq0);
						printk("%s 160Mhz: center frequency of the 160 MHz channel = %d\n", __FUNCTION__, pVhtOp->center_freq1);
						pPeerInfo->vht_RxChannelWidth =
							3;
					} else if (diff > 8) {
#ifdef SOC_W906X
						isSupport80plus80Mhz(priv);
#else
						WLDBG_ERROR(DBG_LEVEL_1,
							    "80MHz + 80MHz, not support\n");
#endif

						pPeerInfo->vht_RxChannelWidth =
							3;
					} else {
						printk("%s reserved\n",
						       __FUNCTION__);
						pPeerInfo->vht_RxChannelWidth =
							2;
					}
				}
#endif
				break;
			case 2:
			case 3:
				pPeerInfo->vht_RxChannelWidth = 3;
				break;
			default:
				pPeerInfo->vht_RxChannelWidth = 2;
				break;
			}
		} else {
			/*In 2G, we check HT cap to decide peer bandwidth. Having VHT cap info not necessarily means can support 80 or 40MHz */
			if (mib->PhyDSSSTable->Chanflag.FreqBand ==
			    FREQ_BAND_2DOT4GHZ) {
				if (pPeerInfo->HTCapabilitiesInfo.SupChanWidth)
					pPeerInfo->vht_RxChannelWidth = 1;
				else
					pPeerInfo->vht_RxChannelWidth = 0;
			} else {
				/*If 160MHz or (160 and 80+80MHz) supported */
				if ((pVhtCap->cap.SupportedChannelWidthSet == 1)
				    || (pVhtCap->cap.SupportedChannelWidthSet ==
					2))
					pPeerInfo->vht_RxChannelWidth = 3;
				else
					pPeerInfo->vht_RxChannelWidth = 2;
			}
		}

	}
#ifdef SOC_W906X
	while ((pIeExt =
		(IEEEtypes_InfoElementExtHdr_t *)
		syncSrv_ParseAttribWithinFrame(MgmtMsg_p, attrib_p,
					       EXT_IE)) != NULL) {

		switch (pIeExt->ext) {
		case HE_CAPABILITIES_IE:
			memcpy((void *)&pPeerInfo->he_cap, (void *)pIeExt,
			       pIeExt->Len + 2);
			prx_he_mcs_80m =
				(he_mcs_nss_support_t *) ((void *)&vmacSta_p->
							  he_cap +
							  sizeof
							  (IEEEtypes_InfoElementExtHdr_t)
							  +
							  sizeof
							  (HE_Mac_Capabilities_Info_t)
							  +
							  sizeof
							  (HE_Phy_Capabilities_Info_t));

			if ((vmacSta_p->he_cap.phy_cap.
			     channel_width_set & HE_SUPPORT_160MHZ_BW_5G) &&
			    (pPeerInfo->he_cap.phy_cap.
			     channel_width_set & HE_SUPPORT_160MHZ_BW_5G)) {

				if ((&vmacSta_p->he_cap.rx_he_mcs_80m +
				     2)->max_mcs_set >
				    (&pPeerInfo->he_cap.tx_he_mcs_80m +
				     2)->max_mcs_set) {
					(&pPeerInfo->he_cap.tx_he_mcs_80m +
					 2)->max_mcs_set =
	     (prx_he_mcs_80m + 2)->max_mcs_set;
				}

				if ((vmacSta_p->he_cap.phy_cap.
				     channel_width_set &
				     HE_SUPPORT_80P80MHZ_BW_5G) &&
				    (pPeerInfo->he_cap.phy_cap.
				     channel_width_set &
				     HE_SUPPORT_80P80MHZ_BW_5G)) {

					if ((&vmacSta_p->he_cap.rx_he_mcs_80m +
					     4)->max_mcs_set >
					    (&pPeerInfo->he_cap.tx_he_mcs_80m +
					     4)->max_mcs_set) {
						(&pPeerInfo->he_cap.
						 tx_he_mcs_80m +
						 4)->max_mcs_set =
				     (prx_he_mcs_80m + 4)->max_mcs_set;
					}

					if (pPeerInfo->vht_RxChannelWidth == 3) {
						StaInfo_p->operating_mode.
							rxnss =
							get_he_peer_nss
							(&pPeerInfo->he_cap.
							 rx_he_mcs_80m + 4);
						StaInfo_p->operating_mode.
							tx_nsts =
							get_he_peer_nss
							(&pPeerInfo->he_cap.
							 tx_he_mcs_80m + 4);
					} else {
						StaInfo_p->operating_mode.
							rxnss =
							get_he_peer_nss
							(&pPeerInfo->he_cap.
							 rx_he_mcs_80m);
						StaInfo_p->operating_mode.
							tx_nsts =
							get_he_peer_nss
							(&pPeerInfo->he_cap.
							 tx_he_mcs_80m);
					}
				} else {
					if (pPeerInfo->vht_RxChannelWidth == 3) {
						StaInfo_p->operating_mode.
							rxnss =
							get_he_peer_nss
							(&pPeerInfo->he_cap.
							 rx_he_mcs_80m + 2);
						StaInfo_p->operating_mode.
							tx_nsts =
							get_he_peer_nss
							(&pPeerInfo->he_cap.
							 tx_he_mcs_80m + 2);
					} else {
						StaInfo_p->operating_mode.
							rxnss =
							get_he_peer_nss
							(&pPeerInfo->he_cap.
							 rx_he_mcs_80m);
						StaInfo_p->operating_mode.
							tx_nsts =
							get_he_peer_nss
							(&pPeerInfo->he_cap.
							 tx_he_mcs_80m);
					}
				}
			} else {
				StaInfo_p->operating_mode.rxnss =
					get_he_peer_nss(&pPeerInfo->he_cap.
							rx_he_mcs_80m);
				StaInfo_p->operating_mode.tx_nsts =
					get_he_peer_nss(&pPeerInfo->he_cap.
							tx_he_mcs_80m);
				if (mib->PhyDSSSTable->Chanflag.FreqBand ==
				    FREQ_BAND_5GHZ) {
					if (!
					    (pPeerInfo->he_cap.phy_cap.
					     channel_width_set &
					     HE_SUPPORT_40_80MHZ_BW_5G))
						pPeerInfo->vht_RxChannelWidth =
							0;
				}
			}

			StaInfo_p->operating_mode.chbw =
				pPeerInfo->vht_RxChannelWidth;
			StaInfo_p->operating_mode.ulmu_disable = 0;
			break;
		case HE_OPERATION_IE:
			memcpy((void *)&pPeerInfo->he_op, (void *)pIeExt,
			       pIeExt->Len + 2);
			break;
		case UORA_PARAMETERS:
			break;
		case MU_EDCA_PARAMETERS:
			break;
		case SPATIAL_REUSE_PARAMETERS:
			break;
		case NDP_FEEDBACK_REPORT_PARAMETERS:
			break;
		case BSS_COLOR_CHANGE_ANNOUNCEMENT:
			break;
		case QUIET_TIME_SETUP_PARAMETERS:
			break;
		default:
			break;
		}

		/* Process to the next element pointer. */
		attrib_p += (2 + *((UINT8 *) (attrib_p + 1)));
	}
#endif /* SOC_W906X */
	// Looks up Qos element.  This will be updated for Client station database entry.
	while ((attrib_p =
		(UINT8 *) syncSrv_ParseAttribWithinFrame(MgmtMsg_p, attrib_p,
							 PROPRIETARY_IE)) !=
	       NULL) {
		WME_param_elem = (WME_param_elem_t *) attrib_p;
		pHTGen = (IEEEtypes_Generic_HT_Element_t *) attrib_p;
		pHTAddGen = (IEEEtypes_Generic_Add_HT_Element_t *) attrib_p;
		//check if it is a WME/WSM Info Element.
		if (!memcmp(WME_param_elem->OUI.OUI, WiFiOUI, 3)) {
			//Check if it is a WME element
			if (WME_param_elem->OUI.Type == 2) {
				//check if it is a WME Param Element
				if (WME_param_elem->OUI.Subtype == 1) {
					AC_param_rcd_t *ac_Param_p =
						&WME_param_elem->AC_BE;
					UINT32 i;
					StaInfo_p->IsStaQSTA = TRUE;
#ifdef SOC_W906X
					memcpy(QosInfo_p,
					       &WME_param_elem->QoS_info, 1);
#endif
					/* Program queues with Qos settings. */
					for (i = 0; i < 4; i++) {
						/* If high performance mode use VI values for CWmin, AIFSN, and TXOP. */
						if (*(pMasterMIB->mib_optlevel)
						    && i == 0) {
							wlFwSetEdcaParam(dev, i,
									 ((0x01
									   <<
									   WME_param_elem->
									   AC_VI.
									   ECW_min_max.
									   ECW_min)
									  - 1),
									 ((0x01
									   <<
									   ac_Param_p->
									   ECW_min_max.
									   ECW_max)
									  - 1),
									 WME_param_elem->
									 AC_VI.
									 ACI_AIFSN.
									 AIFSN,
									 WME_param_elem->
									 AC_VI.
									 TXOP_lim);
						} else {
							wlFwSetEdcaParam(dev,
									 i,
									 ((0x01
									   <<
									   ac_Param_p->
									   ECW_min_max.
									   ECW_min)
									  - 1),
									 ((0x01
									   <<
									   ac_Param_p->
									   ECW_min_max.
									   ECW_max)
									  - 1),
									 ac_Param_p->
									 ACI_AIFSN.
									 AIFSN,
									 ac_Param_p->
									 TXOP_lim);
						}
#ifndef SOC_W906X
						if (ac_Param_p->ACI_AIFSN.ACM == 1 && *QosInfo_p == 0) {	/* This function will be called twice. Check QosInfo_p to avoid running the code segment below twice */
							switch (ac_Param_p->
								ACI_AIFSN.ACI) {
							case AC_BE_Q:
								QosTsData[0].
									TidStatus
									=
									QOS_TS_PENDING;
								QosTsData[3].
									TidStatus
									=
									QOS_TS_PENDING;
								break;
							case AC_VI_Q:
								QosTsData[4].
									TidStatus
									=
									QOS_TS_PENDING;
								QosTsData[5].
									TidStatus
									=
									QOS_TS_PENDING;
								break;
							case AC_VO_Q:
								QosTsData[6].
									TidStatus
									=
									QOS_TS_PENDING;
								QosTsData[7].
									TidStatus
									=
									QOS_TS_PENDING;
								break;
							case AC_BK_Q:
							default:
								break;
							}
						}
#endif
						ac_Param_p++;
					}
#ifndef SOC_W906X
					for (i = 0; i < 8 && *QosInfo_p == 0; i++) {	/* This function will be called twice. Check QosInfo_p to avoid running the code segment below twice *//* Downgrade AC and TID */
						if (QosTsData[i].TidStatus !=
						    QOS_TS_ADMITTED) {
							switch (i) {
								/* BE */
							case 0:
								QosTsData[i].
									TidDowngrade
									= 1;
								QosTsData[i].
									AccCategoryQDowngrade
									=
									AC_BK_Q;
								break;
							case 3:
								QosTsData[i].
									TidDowngrade
									= 2;
								QosTsData[i].
									AccCategoryQDowngrade
									=
									AC_BK_Q;
								break;
							case 4:
								QosTsData[i].
									TidDowngrade
									=
									QosTsData
									[0].
									TidDowngrade;
								QosTsData[i].
									AccCategoryQDowngrade
									=
									QosTsData
									[0].
									AccCategoryQDowngrade;
								break;
							case 5:
								QosTsData[i].
									TidDowngrade
									=
									QosTsData
									[3].
									TidDowngrade;
								QosTsData[i].
									AccCategoryQDowngrade
									=
									QosTsData
									[3].
									AccCategoryQDowngrade;
								break;
							case 6:
								QosTsData[i].
									TidDowngrade
									=
									QosTsData
									[4].
									TidDowngrade;
								QosTsData[i].
									AccCategoryQDowngrade
									=
									QosTsData
									[4].
									AccCategoryQDowngrade;
								break;
							case 7:
								QosTsData[i].
									TidDowngrade
									=
									QosTsData
									[5].
									TidDowngrade;
								QosTsData[i].
									AccCategoryQDowngrade
									=
									QosTsData
									[5].
									AccCategoryQDowngrade;
								break;
							default:
								break;
							}
						}

					}

					memcpy(QosInfo_p,
					       &WME_param_elem->QoS_info, 1);
#endif
				}
			}
		} else if ((pHT == NULL) &&
			   !memcmp(&pHTGen->OUI, B_COMP_OUI, 3)) {
			/* Look up high throughput elements using proprietary tag if not found with with HT tag. */
			if (pHTGen->OUIType == HT_PROP) {
				pPeerInfo->HTCapabilitiesInfo =
					pHTGen->HTCapabilitiesInfo;
				pPeerInfo->MacHTParamInfo =
					pHTGen->MacHTParamInfo;
				pPeerInfo->HTRateBitMap =
					(pHTGen->
					 SupportedMCSset[0] | (pHTGen->
							       SupportedMCSset
							       [1] << 8) |
					 (pHTGen->
					  SupportedMCSset[2] << 16) | (pHTGen->
								       SupportedMCSset
								       [3] <<
								       24));

				StaInfo_p->ClientMode = NONLY_MODE;
				StaInfo_p->aggr11n.threshold = 4;
				StaInfo_p->aggr11n.thresholdBackUp =
					StaInfo_p->aggr11n.threshold;
				if ((*(pMasterMIB->pMib_11nAggrMode) &
				     WL_MODE_AMSDU_TX_MASK) &&
				    !(*(pMasterMIB->pMib_11nAggrMode) &
				      WL_MODE_AMPDU_TX))
					StaInfo_p->aggr11n.type |=
						WL_WLAN_TYPE_AMSDU;
				if (pHTGen->HTCapabilitiesInfo.MaxAMSDUSize)
					StaInfo_p->aggr11n.cap = 2;
				else
					StaInfo_p->aggr11n.cap = 1;

				// Green Field not supported.
				pPeerInfo->HTCapabilitiesInfo.GreenField = 0;
				pPeerInfo->HTCapabilitiesInfo.RxSTBC = 0;
				pPeerInfo->HTCapabilitiesInfo.TxSTBC = 0;
			} else if (pHTAddGen->OUIType == ADD_HT_PROP) {
				pPeerInfo->AddHtInfo.ControlChan =
					pHTAddGen->ControlChan;
				pPeerInfo->AddHtInfo.AddChan =
					pHTAddGen->AddChan;
				pPeerInfo->AddHtInfo.OpMode = pHTAddGen->OpMode;
				pPeerInfo->AddHtInfo.stbc = pHTAddGen->stbc;
			}
		}
		//Now process to the next element pointer.
		attrib_p += (2 + *((UINT8 *) (attrib_p + 1)));
	}
	/* Check if QOS set, if not then set to best effort if N mode */
	if (!StaInfo_p->IsStaQSTA && (StaInfo_p->ClientMode == NONLY_MODE)) {
		StaInfo_p->IsStaQSTA = TRUE;
		*QosInfo_p = 0;
		/* Leave queue Qos settings default. */
	}
	FixedRateCtl(StaInfo_p, pPeerInfo, mib);
	return TRUE;
}

UINT32
GetAssocRespLegacyRateBitMap(IEEEtypes_SuppRatesElement_t * SuppRates,
			     IEEEtypes_ExtSuppRatesElement_t * ExtSuppRates)
{
	UINT16 i = 0, j = 0;
	UINT8 Rates[32] = { 0 };
	UINT32 SupportedLegacyIEEERateBitMap = 0;

	/* Get legacy rates */
	if (SuppRates) {
		for (i = 0; i < SuppRates->Len; i++) {
			Rates[i] = SuppRates->Rates[i];
		}
	}
	if (ExtSuppRates) {
		if (ExtSuppRates && ExtSuppRates->Len) {
			for (j = 0; j < ExtSuppRates->Len; j++) {
				Rates[i + j] = ExtSuppRates->Rates[j];
			}
		}
	}

	/* Get legacy rate bit map */
	for (i = 0; i < IEEEtypes_MAX_DATA_RATES_G; i++) {
		IEEEToMrvlRateBitMapConversion(Rates[i],
					       &SupportedLegacyIEEERateBitMap);
	}
	return SupportedLegacyIEEERateBitMap;
}

void
DeleteClientInfo(UINT8 * macAddr_p, vmacEntry_t * clientVMacEntry_p)
{
	struct net_device *pStaDev =
		(struct net_device *)clientVMacEntry_p->privInfo_p;
	struct wlprivate *wlpptrSta = NETDEV_PRIV_P(struct wlprivate, pStaDev);
	extStaDb_StaInfo_t *StaInfo_p = NULL;

	if ((StaInfo_p =
	     extStaDb_GetStaInfo(wlpptrSta->vmacSta_p,
				 (IEEEtypes_MacAddr_t *) macAddr_p,
				 STADB_UPDATE_AGINGTIME)) != NULL) {
		FreeAid(wlpptrSta->vmacSta_p, StaInfo_p->Aid);
		ResetAid(wlpptrSta->vmacSta_p, StaInfo_p->StnId,
			 StaInfo_p->Aid);
		FreeStnId(wlpptrSta->vmacSta_p, StaInfo_p->StnId);
		extStaDb_DelSta(wlpptrSta->vmacSta_p,
				(IEEEtypes_MacAddr_t *) macAddr_p,
				STADB_DONT_UPDATE_AGINGTIME);
		wlFwSetNewStn(wlpptrSta->master, (u_int8_t *) macAddr_p,
			      StaInfo_p->Aid, StaInfo_p->StnId,
			      StaInfoDbActionRemoveEntry, NULL, 0, 0, 0);
#ifndef SOC_W906X
		//only remove local address, when there is a BSSID entry.
		extStaDb_DelSta(wlpptrSta->vmacSta_p,
				(IEEEtypes_MacAddr_t *) clientVMacEntry_p->
				vmacAddr, STADB_DONT_UPDATE_AGINGTIME);
#endif
	}
}

int
wlset_rateSupport(MIB_802DOT11 * mib)
{
	if (*(mib->mib_ApMode) & AP_MODE_A_ONLY) {
		*(mib->BssBasicRateMask) = MRVL_BSSBASICRATEMASK_A;
		*(mib->NotBssBasicRateMask) = MRVL_NOTBSSBASICRATEMASK_A;
		*(mib->mib_shortSlotTime) = TRUE;
	} else if ((*(mib->mib_ApMode) & (AP_MODE_G_ONLY | AP_MODE_B_ONLY)) ==
		   (AP_MODE_G_ONLY | AP_MODE_B_ONLY)) {
		*(mib->BssBasicRateMask) = MRVL_BSSBASICRATEMASK_BGN;
		*(mib->NotBssBasicRateMask) = MRVL_NOTBSSBASICRATEMASK_BGN;
		*(mib->mib_shortSlotTime) = TRUE;
	} else if (*(mib->mib_ApMode) & AP_MODE_B_ONLY) {
		*(mib->BssBasicRateMask) = MRVL_BSSBASICRATEMASK_B;
		*(mib->NotBssBasicRateMask) = MRVL_NOTBSSBASICRATEMASK_B;
		*(mib->mib_shortSlotTime) = FALSE;
	} else if (*(mib->mib_ApMode) & AP_MODE_G_ONLY) {
		*(mib->BssBasicRateMask) = MRVL_BSSBASICRATEMASK_G;
		*(mib->NotBssBasicRateMask) = MRVL_NOTBSSBASICRATEMASK_G;
		*(mib->mib_shortSlotTime) = TRUE;
	} else {
		*(mib->BssBasicRateMask) = MRVL_BSSBASICRATEMASK_DEF;
		*(mib->NotBssBasicRateMask) = MRVL_NOTBSSBASICRATEMASK_DEF;
		*(mib->mib_shortSlotTime) = TRUE;
	}
	return 0;
}

int
wlset_mibChannel(vmacEntry_t * clientVMacEntry_p, UINT8 mib_STAMode)
{
	int rc = 0;
	//not sure the purpose of changing wdev0's mib, TODO
#ifndef MBSS
#ifndef SOC_W906X
	extern BOOLEAN force_5G_channel;
#endif
	mibMaster = vmacSta_p->master->ShadowMib802dot11;
	if ((mib_STAMode == CLIENT_MODE_N_5) || (mib_STAMode == CLIENT_MODE_A)
	    || (mib_STAMode == CLIENT_MODE_AUTO)) {
		channel = 64;
		*mibMaster->mib_ApMode = AP_MODE_5GHZ_Nand11AC;
	} else {
		channel = 6;
		*mibMaster->mib_ApMode = AP_MODE_2_4GHZ_11AC_MIXED;
	}

	wlset_rateSupport(mibMaster);

#ifdef SOC_W906X
	if (domainChannelValid
	    (channel, channel <= 14 ? FREQ_BAND_2DOT4GHZ : FREQ_BAND_5GHZ))
#else
	if (domainChannelValid
	    (channel,
	     force_5G_channel ? FREQ_BAND_5GHZ : (channel <=
						  14 ? FREQ_BAND_2DOT4GHZ :
						  FREQ_BAND_5GHZ)))
#endif
	{
		PhyDSSSTable->CurrChan = channel;
		/* Currentlly, 40M is not supported for channel 14 */
		if (PhyDSSSTable->CurrChan == 14) {
			if ((PhyDSSSTable->Chanflag.ChnlWidth == CH_AUTO_WIDTH)
			    || (PhyDSSSTable->Chanflag.ChnlWidth ==
				CH_40_MHz_WIDTH))
				PhyDSSSTable->Chanflag.ChnlWidth =
					CH_20_MHz_WIDTH;
		}
		//PhyDSSSTable->Chanflag.ChnlWidth=CH_40_MHz_WIDTH;
		PhyDSSSTable->Chanflag.ExtChnlOffset = EXT_CH_ABOVE_CTRL_CH;
		if (((PhyDSSSTable->Chanflag.ChnlWidth == CH_40_MHz_WIDTH) ||
		     (PhyDSSSTable->Chanflag.ChnlWidth == CH_80_MHz_WIDTH) ||
		     (PhyDSSSTable->Chanflag.ChnlWidth == CH_AUTO_WIDTH) ||
		     (PhyDSSSTable->Chanflag.ChnlWidth == CH_160_MHz_WIDTH))) {
			switch (PhyDSSSTable->CurrChan) {
			case 1:
			case 2:
			case 3:
			case 4:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 5:
				/* Now AutoBW use 5-1 instead of 5-9 for wifi cert convenience */
				/*if(*mib_extSubCh_p==0)
				   PhyDSSSTable->Chanflag.ExtChnlOffset=EXT_CH_ABOVE_CTRL_CH;
				   else if(*mib_extSubCh_p==1)
				   PhyDSSSTable->Chanflag.ExtChnlOffset=EXT_CH_BELOW_CTRL_CH;
				   else if(*mib_extSubCh_p==2)
				   PhyDSSSTable->Chanflag.ExtChnlOffset=EXT_CH_ABOVE_CTRL_CH;
				   break; */
			case 6:
			case 7:
			case 8:
			case 9:
			case 10:
				if (*mib_extSubCh_p == 0)
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_BELOW_CTRL_CH;
				else if (*mib_extSubCh_p == 1)
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_BELOW_CTRL_CH;
				else if (*mib_extSubCh_p == 2)
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_ABOVE_CTRL_CH;
				break;
			case 11:
			case 12:
			case 13:
			case 14:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
				/* for 5G */
			case 36:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 40:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
			case 44:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 48:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
			case 52:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 56:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
			case 60:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 64:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;

			case 68:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 72:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
			case 76:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 80:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
			case 84:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 88:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
			case 92:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 96:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;

			case 100:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 104:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
			case 108:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 112:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
			case 116:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 120:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
			case 124:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 128:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
			case 132:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 136:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
			case 140:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 144:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
			case 149:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 153:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
			case 157:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 161:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
			case 165:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 169:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
			case 173:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 177:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
			case 181:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					NO_EXT_CHANNEL;
				break;

			case 184:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 188:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
			case 192:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 196:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
			}
		}
#ifndef SOC_W906X
		if (force_5G_channel) {
			PhyDSSSTable->Chanflag.FreqBand = FREQ_BAND_5GHZ;
		} else {
#endif
			if (PhyDSSSTable->CurrChan <= 14)
				PhyDSSSTable->Chanflag.FreqBand =
					FREQ_BAND_2DOT4GHZ;
			else
				PhyDSSSTable->Chanflag.FreqBand =
					FREQ_BAND_5GHZ;
#ifdef SOC_W906X
		}
#endif
	} else
		WLDBG_INFO(DBG_LEVEL_1, "invalid channel %d\n", channel);
#endif
	return rc;
}

void
RemoveClientFw(UINT8 * macAddr_p, vmacEntry_t * clientVMacEntry_p)
{
	struct net_device *pStaDev =
		(struct net_device *)clientVMacEntry_p->privInfo_p;
	struct wlprivate *wlpptrSta = NETDEV_PRIV_P(struct wlprivate, pStaDev);
	extStaDb_StaInfo_t *StaInfo_p = NULL;

	if ((StaInfo_p =
	     extStaDb_GetStaInfo(wlpptrSta->vmacSta_p,
				 (IEEEtypes_MacAddr_t *) macAddr_p,
				 STADB_UPDATE_AGINGTIME)) != NULL) {
		FreeAid(wlpptrSta->vmacSta_p, StaInfo_p->Aid);
		ResetAid(wlpptrSta->vmacSta_p, StaInfo_p->StnId,
			 StaInfo_p->Aid);
		FreeStnId(wlpptrSta->vmacSta_p, StaInfo_p->StnId);
		extStaDb_DelSta(wlpptrSta->vmacSta_p,
				(IEEEtypes_MacAddr_t *) macAddr_p,
				STADB_DONT_UPDATE_AGINGTIME);
		wlFwSetNewStn(wlpptrSta->master, (u_int8_t *) macAddr_p,
			      StaInfo_p->Aid, StaInfo_p->StnId,
			      StaInfoDbActionRemoveEntry, NULL, 0, 0, 0);

	} else {
		wlFwSetNewStn(wlpptrSta->master, (u_int8_t *) macAddr_p, 0, 0,
			      StaInfoDbActionRemoveEntry, NULL, 0, 0, 0);
	}
}

#ifdef SOC_W906X
int
isSupport80plus80Mhz(struct wlprivate *wlpptr)
{

	switch (wlpptr->devid) {
	case SC5:
	case SCBT:
		return 1;
	case SC4:
	default:
		printk("device ID: %x, 80MHz + 80MHz mode is not supportted\n",
		       wlpptr->devid);
		return -1;
	}
}
#endif

#ifdef SUPPORTED_EXT_NSS_BW
//later need to add more input for these logic
int
isSupport160MhzByCenterFreq(struct wlprivate *wlpptr, UINT8 vhtExtNssBwCap,
			    UINT8 freq0, UINT8 freq1, UINT8 freq2)
{

	UINT8 diff, freqX = freq1;

	if (freq1 == 0) {

		if ((!freq2) || (!vhtExtNssBwCap))
			return 0;

		freqX = freq2;
	}

	diff = (freq0 > freqX) ? (freq0 - freqX) : (freqX - freq0);

	if (diff == 8) {
		printk("160Mhz: center frequency of the 80 MHz channel segment that contains the primary channel = %d\n", freq0);

		printk("160Mhz: center frequency of the 160 MHz channel = %d \n", freqX);

		return 1;
	} else if (diff > 8) {
#ifdef SOC_W906X
		return isSupport80plus80Mhz(wlpptr);
#else
		printk("80MHz + 80MHz, not support\n");
		return -1;
#endif
	} else {
		printk("reserved\n");
	}

	return -2;
}
#endif
