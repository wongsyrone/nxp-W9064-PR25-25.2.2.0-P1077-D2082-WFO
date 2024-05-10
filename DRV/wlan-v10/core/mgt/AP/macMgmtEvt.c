/** @file macMgmtEvt.c
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

/*
*
* Description:  Handle all the events coming in and out of the MLME State Machines
*
*/

#include "ap8xLnxIntf.h"
#include "wltypes.h"
#include "IEEE_types.h"

#include "mib.h"
#include "osif.h"
#include "timer.h"

#include "ds.h"

#include "keyMgmtCommon.h"
#include "keyMgmt.h"
#include "tkip.h"

#include "macmgmtap.h"

#include "StaDb.h"
#include "smeMain.h"
#include "qos.h"
#include "macMgmtMlme.h"

#include "mhsm.h"
#include "mlme.h"
#include "idList.h"
#include "IEEE_types.h"
#include "wldebug.h"

#ifdef DSP_TRIG_CMD
#include "ap8xLnxSwMimoTypes.h"
#include "ap8xLnxSwMimo.h"
#include "ieeetypescommon.h"
#endif

/* Global Declaration */
#ifdef AP_URPTR
extern UINT8 mib_wbMode;
#endif

extern Status_e
NotifyNewStn(IEEEtypes_MacAddr_t * MacAddr, UINT16 StnId)
{
	return FAIL;
};

extern void AuthRspSrvApCtor(AuthRspSrvAp * me);
extern void AssocSrvApCtor(AssocSrvAp * me);
extern void macMgmtMlme_QoSAct(vmacApInfo_t * vmacSta_p,
			       macmgmtQ_MgmtMsg3_t * MgmtMsg_p);
extern BOOLEAN macMgmtMlme_80211hAct(vmacApInfo_t * vmacSta_p,
				     macmgmtQ_MgmtMsg3_t * MgmtMsg_p);
#ifdef COEXIST_20_40_SUPPORT
extern BOOLEAN macMgmtMlme_80211PublicAction(vmacApInfo_t * vmacSta_p,
					     macmgmtQ_MgmtMsg3_t * MgmtMsg_p);
#endif
extern int wlFwSetNewStn(struct net_device *dev, u_int8_t * staaddr,
			 u_int16_t assocId, u_int16_t stnId, u_int16_t action,
			 PeerInfo_t * pPeerInfo, UINT8 Qosinfo, UINT8 isQosSta,
			 UINT8 wds);
extern int wlFwSetSecurity(struct net_device *netdev, u_int8_t * staaddr);
extern void macMgmtRemoveSta(vmacApInfo_t * vmacSta_p,
			     extStaDb_StaInfo_t * StaInfo_p);
extern void setStaPeerInfoApMode(struct wlprivate *wlpptr,
				 extStaDb_StaInfo_t * pStaInfo,
				 PeerInfo_t * pPeerInfo, UINT8 ApMode,
				 struct wds_port *pWdsPort);
#ifdef MBSS
extern vmacApInfo_t *vmacGetMBssByAddr(vmacApInfo_t * vmacSta_p,
				       UINT8 * macAddr_p);
#endif
#ifdef CONFIG_IEEE80211W
extern int validateRobustManagementframe(vmacApInfo_t * vmac_p,
					 extStaDb_StaInfo_t * StaInfo_p,
					 macmgmtQ_MgmtMsg3_t * mgtFrm);
#endif
//extern MIB_AUTH_ALG *mib_AuthAlg_p_p;
#ifdef DSP_TRIG_CMD
mu_config_t muConfig;
static u8 muBitmap[64] = { 0 };
#endif

#ifdef CCK_DESENSE
extern void cck_desense_ctrl(struct net_device *netdev, int state);
#endif /* CCK_DESENSE */

/*************************************************************************
* Function:
*
* Description:
*
* Input:
*
* Output:
*
**************************************************************************/
extern void
macMgtSyncSrvInit(vmacApInfo_t * vmacSta_p)
{
	/* Init the Synchronization state machines */
	SyncSrvCtor(&vmacSta_p->mgtSync);
	mhsm_initialize(&vmacSta_p->mgtSync.super, &vmacSta_p->mgtSync.sTop);

}

extern extStaDb_StaInfo_t *
macMgtStaDbInit(vmacApInfo_t * vmacSta_p, IEEEtypes_MacAddr_t * staMacAddr,
		IEEEtypes_MacAddr_t * apMacAddr)
{
	MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
	extStaDb_StaInfo_t *StaInfo = NULL;
	extStaDb_StaInfo_t *StaInfo_p = NULL;
	struct wlprivate *wlpptr =
		NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev);
	PeerInfo_t PeerInfo;

#ifdef DEBUG_PRINT
	printf("macMgtStaDbInit:: entered\n");
#endif
	WLDBG_ENTER(DBG_LEVEL_11);

	/*Use dynamic memory to prevent frame size > 1024bytes warning during compilation
	 * extStaDb_StaInfo_t takes 1488bytes
	 */
	if ((StaInfo =
	     wl_kmalloc(sizeof(extStaDb_StaInfo_t), GFP_ATOMIC)) == NULL) {
		printk("%s: Fail to allocate memory\n", __FUNCTION__);
		return NULL;
	}
	memset(StaInfo, 0, sizeof(extStaDb_StaInfo_t));

	/* Station not in Stn table, hence add */
	memcpy(&StaInfo->Addr, staMacAddr, sizeof(IEEEtypes_MacAddr_t));
	memcpy(&StaInfo->Bssid, apMacAddr, sizeof(IEEEtypes_MacAddr_t));

	StaInfo->State = UNAUTHENTICATED;
	StaInfo->PwrMode = PWR_MODE_ACTIVE;
	//StaInfo->StnId = AssignStnId(vmacSta_p);
	// move stnid assigment to associate state where the sta added to fw
	StaInfo->Aid = 0;
#ifdef SOC_W906X
	StaInfo->StnId = DEF_STN_ID;
#endif
	StaInfo->AP = FALSE;
#ifdef WDS_FEATURE
	StaInfo->wdsInfo = NULL;
	StaInfo->wdsPortInfo = NULL;
#endif
#ifdef CLIENT_SUPPORT
	StaInfo->Client = FALSE;
#endif
#ifdef APCFGUR
	StaInfo->UR = 0;
#endif
#ifdef STA_INFO_DB
	StaInfo->Sq1 = 0;
	StaInfo->Sq2 = 0;
	StaInfo->RSSI = 0;
	StaInfo->Rate = 0;
#endif
	StaInfo->ClientMode = 0;
	StaInfo->mib_p = mib;
	StaInfo->dev = vmacSta_p->dev;
	if (*(mib->mib_ApMode) == AP_MODE_AandG) {
		if (memcmp
		    (apMacAddr, vmacSta_p->macBssId,
		     sizeof(IEEEtypes_MacAddr_t))) {
			StaInfo->ApMode = MIXED_MODE;
		} else {
			StaInfo->ApMode = AONLY_MODE;
		}
	}
#ifdef AP_URPTR
	if (!mib_wbMode)
#endif
	{
		if (extStaDb_AddSta(vmacSta_p, StaInfo) != ADD_SUCCESS) {
			wl_kfree(StaInfo);
			return NULL;
		}
#ifdef NEW_OSIF_POWERSAVE
		psProcessNewStn(staMacAddr, StaInfo->StnId);
#else
		NotifyNewStn(staMacAddr, StaInfo->StnId);
#endif
		wl_kfree(StaInfo);
		StaInfo = NULL;
		if ((StaInfo_p =
		     extStaDb_GetStaInfo(vmacSta_p, staMacAddr,
					 STADB_UPDATE_AGINGTIME)) == NULL) {
			return NULL;
		}
		setStaPeerInfoApMode(wlpptr, StaInfo_p, &PeerInfo,
				     *(wlpptr->vmacSta_p->Mib802dot11->
				       mib_ApMode), NULL);

		/*Comment out below. No need to call wlFwSetNewStn here because Aid value is not obtained yet */
		//StaInfo_p->FwStaPtr = wlFwSetNewStn(vmacSta_p->dev, (u_int8_t *)staMacAddr, StaInfo_p->Aid, StaInfo_p->StnId, 0, &PeerInfo,0,0,0);  //add new station

		wlFwSetSecurity(vmacSta_p->dev, (u_int8_t *) staMacAddr);
		/* Init the state machines */
		/* Init Auth Request Srv SM */
		AuthReqSrvApCtor((AuthReqSrvAp *) & StaInfo_p->mgtAuthReq);
		mhsm_initialize(&StaInfo_p->mgtAuthReq.super,
				&StaInfo_p->mgtAuthReq.sTop);

		/* Init Auth Response Srv SM */
		AuthRspSrvApCtor((AuthRspSrvAp *) & StaInfo_p->mgtAuthRsp);
		mhsm_initialize(&StaInfo_p->mgtAuthRsp.super,
				&StaInfo_p->mgtAuthRsp.sTop);

		/* Init Association Srv SM */
		AssocSrvApCtor((AssocSrvAp *) & StaInfo_p->mgtAssoc);
		mhsm_initialize(&StaInfo_p->mgtAssoc.super,
				&StaInfo_p->mgtAssoc.sTop);

#ifdef APCFGUR
		/* Init remote control Srv SM */
		RemoteCtrlSrvCtor(&StaInfo_p->rmSrv);
		mhsm_initialize(&StaInfo_p->rmSrv.super,
				&StaInfo_p->rmSrv.sTop);
		StaInfo_p->rmSrv.userdata_p = (unsigned char *)StaInfo_p;
#endif
	}
	if (StaInfo != NULL)
		wl_kfree(StaInfo);
	StaInfo_p->mgtAssoc.userdata_p = (unsigned char *)StaInfo_p;
	StaInfo_p->mgtAuthReq.userdata_p = (unsigned char *)StaInfo_p;
	StaInfo_p->mgtAuthRsp.userdata_p = (unsigned char *)StaInfo_p;
	StaInfo_p->sbf_slot = 0xff;

	WLDBG_EXIT(DBG_LEVEL_11);
#ifdef CONFIG_IEEE80211W
	StaInfo_p->ptkCipherOuiType = CIPHER_OUI_TYPE_NONE;
	StaInfo_p->sa_query_timed_out = 0;
	StaInfo_p->sa_query_count = 0;
#endif
	return StaInfo_p;
}

/*************************************************************************
* Function:
*
* Description:
*
* Input:
*
* Output:
*
**************************************************************************/
extern IEEEtypes_MacAddr_t macAddrZero;
#ifdef AP_MAC_LINUX
extern SINT8
evtDot11MgtMsg(vmacApInfo_t * vmacSta_p, UINT8 * message, struct sk_buff *skb,
	       UINT32 rssi)
#endif
{
	MIB_AUTH_ALG *mib_AuthAlg_p = vmacSta_p->Mib802dot11->AuthAlg;
	MhsmEvent_t smMsg;
	macmgmtQ_MgmtMsg3_t *MgmtMsg_p;
	extStaDb_StaInfo_t *StaInfo_p;

	if (message == NULL) {
		return 1;
	}
	WLDBG_ENTER(DBG_LEVEL_11);
	MgmtMsg_p = (macmgmtQ_MgmtMsg3_t *) message;

#ifdef FILTER_BSSID
	if ((memcmp
	     (MgmtMsg_p->Hdr.DestAddr, vmacSta_p->macStaAddr,
	      sizeof(IEEEtypes_MacAddr_t)) ||
	     memcmp(MgmtMsg_p->Hdr.BssId, vmacSta_p->macBssId,
		    sizeof(IEEEtypes_MacAddr_t)))
	    && (MgmtMsg_p->Hdr.FrmCtl.Subtype != IEEE_MSG_PROBE_RQST))
#else
	if (memcmp
	    (MgmtMsg_p->Hdr.DestAddr, vmacSta_p->macStaAddr,
	     sizeof(IEEEtypes_MacAddr_t)) &&
	    memcmp(MgmtMsg_p->Hdr.DestAddr, vmacSta_p->macStaAddr2,
		   sizeof(IEEEtypes_MacAddr_t)) &&
	    (MgmtMsg_p->Hdr.FrmCtl.Subtype != IEEE_MSG_PROBE_RQST))
#endif
	{
		WLDBG_ENTER_INFO(DBG_LEVEL_11,
				 "mgt frame %d rxved %2x-%2x-%2x-%2x-%2x-%2x\n",
				 MgmtMsg_p->Hdr.FrmCtl.Subtype,
				 MgmtMsg_p->Hdr.DestAddr[0],
				 MgmtMsg_p->Hdr.DestAddr[1],
				 MgmtMsg_p->Hdr.DestAddr[2],
				 MgmtMsg_p->Hdr.DestAddr[3],
				 MgmtMsg_p->Hdr.DestAddr[4],
				 MgmtMsg_p->Hdr.DestAddr[5]);
		return 1;
	}
#ifndef MULTI_AP_SUPPORT
	if (isMacAccessList(vmacSta_p, &(MgmtMsg_p->Hdr.SrcAddr)) != SUCCESS) {
		return 1;
	}
#else /* MULTI_AP_SUPPORT */
	if ((MgmtMsg_p->Hdr.FrmCtl.Subtype != IEEE_MSG_AUTHENTICATE) &&
	    (isMacAccessList(vmacSta_p, &(MgmtMsg_p->Hdr.SrcAddr)) !=
	     SUCCESS)) {
		return 1;
	}
#endif /* MULTI_AP_SUPPORT */
	if ((StaInfo_p = extStaDb_GetStaInfo(vmacSta_p, &MgmtMsg_p->Hdr.SrcAddr,
					     STADB_DONT_UPDATE_AGINGTIME)) ==
	    NULL) {
		if (MgmtMsg_p->Hdr.FrmCtl.Subtype == IEEE_MSG_AUTHENTICATE) {
			//added call to check other VAP's StaInfo_p
			if ((StaInfo_p =
			     extStaDb_GetStaInfo(vmacSta_p,
						 &MgmtMsg_p->Hdr.SrcAddr,
						 STADB_SKIP_MATCH_VAP))) {
				vmacApInfo_t *vmacSta_temp = vmacSta_p;
#ifdef MBSS
				//StaInfo_p might locat at other VAP, need to find the correct VAP before del the STA
				if (memcmp
				    (&vmacSta_p->macBssId, &StaInfo_p->Bssid,
				     sizeof(IEEEtypes_MacAddr_t))) {
					//StaInfo_p and vmacSta_p current NOT point to the same vap
					if ((vmacSta_temp =
					     vmacGetMBssByAddr(vmacSta_p,
							       StaInfo_p->
							       Bssid)) ==
					    NULL) {
						WLDBG_ENTER_INFO(DBG_LEVEL_11,
								 "not found the VAP to which the STA point\n");
						return 1;
					}
				}
#endif
				macMgmtRemoveSta(vmacSta_temp, StaInfo_p);
			}
			if ((StaInfo_p =
			     macMgtStaDbInit(vmacSta_p, &MgmtMsg_p->Hdr.SrcAddr,
					     &MgmtMsg_p->Hdr.DestAddr)) ==
			    NULL) {
				WLDBG_ENTER_INFO(DBG_LEVEL_11,
						 "init data base fail\n");
				return 1;
			}
#ifdef SOC_W906X
			StaInfo_p->mgmt_seqNum = MgmtMsg_p->Hdr.SeqCtl >> 4;
#endif
		} else if ((MgmtMsg_p->Hdr.FrmCtl.Subtype != IEEE_MSG_PROBE_RQST) && !(MgmtMsg_p->Hdr.FrmCtl.Subtype == IEEE_MSG_ACTION && MgmtMsg_p->Body.data[0] == 4))	//Action Category = Public
		{
			if ((MgmtMsg_p->Hdr.FrmCtl.Subtype !=
			     IEEE_MSG_DEAUTHENTICATE) &&
			    (MgmtMsg_p->Hdr.FrmCtl.Subtype !=
			     IEEE_MSG_PROBE_RSP))
			{
				if (is_unicast_ether_addr
				    ((UINT8 *) & MgmtMsg_p->Hdr.SrcAddr)) {
#ifdef SOC_W906X
					macMgmtMlme_SendDeauthenticateMsg
						(vmacSta_p,
						 &MgmtMsg_p->Hdr.SrcAddr, 0,
						 IEEEtypes_REASON_CLASS2_NONAUTH,
						 TRUE);
#else
					macMgmtMlme_SendDeauthenticateMsg
						(vmacSta_p,
						 &MgmtMsg_p->Hdr.SrcAddr, 0,
						 IEEEtypes_REASON_CLASS2_NONAUTH);
#endif
				} else if (net_ratelimit()) {
					printk("mgt frame %d rxved %2x-%2x-%2x-%2x-%2x-%2x\n", MgmtMsg_p->Hdr.FrmCtl.Subtype, MgmtMsg_p->Hdr.SrcAddr[0], MgmtMsg_p->Hdr.SrcAddr[1], MgmtMsg_p->Hdr.SrcAddr[2], MgmtMsg_p->Hdr.SrcAddr[3], MgmtMsg_p->Hdr.SrcAddr[4], MgmtMsg_p->Hdr.SrcAddr[5]);
				}
			}
			return 1;
		}
	}
#ifdef SOC_W906X
	else {
#ifdef DSP_TRIG_CMD
		if (MgmtMsg_p->Hdr.FrmCtl.Subtype == IEEE_MSG_ACTION_NO_ACK) ;
		else
#endif
			/* skip seqNum check for PMF 4.3.3.4 */
		if ((!vmacSta_p->ieee80211w) &&
			    (StaInfo_p->mgmt_seqNum ==
				     (MgmtMsg_p->Hdr.SeqCtl >> 4))) {
			return 1;
		}
		StaInfo_p->mgmt_seqNum = (MgmtMsg_p->Hdr.SeqCtl >> 4);
	}
#endif
#ifdef AP_MAC_LINUX
	smMsg.devinfo = (void *)vmacSta_p;
#endif
#ifdef CONFIG_IEEE80211W
	if (validateRobustManagementframe(vmacSta_p, StaInfo_p, MgmtMsg_p)) {
		printk("drop bogus protected unicast frame\n");
		return 1;
	}
#endif
	switch (MgmtMsg_p->Hdr.FrmCtl.Subtype) {
	case IEEE_MSG_AUTHENTICATE:
		{
			AuthRspSrvApMsg authRspMsg;
			WLDBG_INFO(DBG_LEVEL_11,
				   "IEEE_MSG_AUTHENTICATE message received. \n");

#ifdef CCK_DESENSE
			cck_desense_ctrl(vmacSta_p->master->dev,
					 CCK_DES_AUTH_REQ);
#endif /* CCK_DESENSE */

			memcpy(authRspMsg.rspMac, MgmtMsg_p->Hdr.SrcAddr, 6);
			authRspMsg.arAlg_in = MgmtMsg_p->Body.Auth.AuthAlg;
			{
				if (mib_AuthAlg_p->Type ==
				    AUTH_OPEN_OR_SHARED_KEY) {
					authRspMsg.arAlg = authRspMsg.arAlg_in;
				} else {
					authRspMsg.arAlg = mib_AuthAlg_p->Type;
				}
			}
			authRspMsg.mgtMsg = (UINT8 *) MgmtMsg_p;
			smMsg.event = AuthOdd;
			smMsg.pBody = (unsigned char *)&authRspMsg;
#ifdef AP_MAC_LINUX
			smMsg.info = (void *)skb;
#endif

			if (StaInfo_p->mgtAuthRsp.super.pCurrent == NULL) {
				struct net_device *netdev = vmacSta_p->dev;
				struct wlprivate *wlpptr =
					NETDEV_PRIV_P(struct wlprivate, netdev);
				struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
				struct except_cnt *wlexcept_p =
					&wlpd_p->except_cnt;
				//printk("====>[WAR, %s], reconstruct mgtAuthRsp\n", StaInfo_p->dev->name);
				AuthRspSrvApCtor((AuthRspSrvAp *) & StaInfo_p->
						 mgtAuthRsp);
				mhsm_initialize(&StaInfo_p->mgtAuthRsp.super,
						&StaInfo_p->mgtAuthRsp.sTop);
				wlexcept_p->auth_war_cnt++;
			}
			mhsm_send_event((Mhsm_t *) & StaInfo_p->mgtAuthRsp.
					super, &smMsg);
		}
		break;

	case IEEE_MSG_ASSOCIATE_RQST:
		{
			WLDBG_INFO(DBG_LEVEL_11,
				   "IEEE_MSG_ASSOCIATE_RQST message received. \n");
			smMsg.event = AssocReq;
			smMsg.pBody = (unsigned char *)MgmtMsg_p;
#ifdef AP_MAC_LINUX
			smMsg.info = (void *)skb;
#endif
			if (!StaInfo_p)
				return 1;
			StaInfo_p->assocRSSI = rssi;
			if (StaInfo_p->mgtAssoc.super.pCurrent == NULL) {
				struct net_device *netdev = vmacSta_p->dev;
				struct wlprivate *wlpptr =
					NETDEV_PRIV_P(struct wlprivate, netdev);
				struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
				struct except_cnt *wlexcept_p =
					&wlpd_p->except_cnt;
				//printk("====>[WAR, %s], reconstruct mgtAuthRsp\n", StaInfo_p->dev->name);
				AssocSrvApCtor((AssocSrvAp *) & StaInfo_p->
					       mgtAssoc);
				mhsm_initialize(&StaInfo_p->mgtAssoc.super,
						&StaInfo_p->mgtAssoc.sTop);
				wlexcept_p->asso_war_cnt++;
			}
			mhsm_send_event((Mhsm_t *) & StaInfo_p->mgtAssoc.super,
					&smMsg);
		}
		break;

	case IEEE_MSG_REASSOCIATE_RQST:
		{
			WLDBG_INFO(DBG_LEVEL_11,
				   "IEEE_MSG_REASSOCIATE_RQST message received. \n");
			smMsg.event = ReAssocReq;
			smMsg.pBody = (unsigned char *)MgmtMsg_p;
#ifdef AP_MAC_LINUX
			smMsg.info = (void *)skb;
#endif
			if (!StaInfo_p)
				return 1;
			StaInfo_p->assocRSSI = rssi;
			if (StaInfo_p->mgtAssoc.super.pCurrent == NULL) {
				struct net_device *netdev = vmacSta_p->dev;
				struct wlprivate *wlpptr =
					NETDEV_PRIV_P(struct wlprivate, netdev);
				struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
				struct except_cnt *wlexcept_p =
					&wlpd_p->except_cnt;
				//printk("====>[WAR, %s], reconstruct mgtAuthRsp\n", StaInfo_p->dev->name);
				AssocSrvApCtor((AssocSrvAp *) & StaInfo_p->
					       mgtAssoc);
				mhsm_initialize(&StaInfo_p->mgtAssoc.super,
						&StaInfo_p->mgtAssoc.sTop);
				wlexcept_p->reasso_war_cnt++;
			}
			mhsm_send_event((Mhsm_t *) & StaInfo_p->mgtAssoc.super,
					&smMsg);
		}
		break;

	case IEEE_MSG_DISASSOCIATE:
		{
			WLDBG_INFO(DBG_LEVEL_11,
				   "IEEE_MSG_DISASSOCIATE message received. \n");
			smMsg.event = DisAssoc;
			smMsg.pBody = (unsigned char *)MgmtMsg_p;
#ifdef AP_MAC_LINUX
			smMsg.info = (void *)skb;
#endif
			if (StaInfo_p->mgtAssoc.super.pCurrent == NULL) {
				struct net_device *netdev = vmacSta_p->dev;
				struct wlprivate *wlpptr =
					NETDEV_PRIV_P(struct wlprivate, netdev);
				struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
				struct except_cnt *wlexcept_p =
					&wlpd_p->except_cnt;
				//printk("====>[WAR, %s], reconstruct mgtAuthRsp\n", StaInfo_p->dev->name);
				AssocSrvApCtor((AssocSrvAp *) & StaInfo_p->
					       mgtAssoc);
				mhsm_initialize(&StaInfo_p->mgtAssoc.super,
						&StaInfo_p->mgtAssoc.sTop);
				wlexcept_p->disasso_war_cnt++;
			}
			mhsm_send_event((Mhsm_t *) & StaInfo_p->mgtAssoc.super,
					&smMsg);
		}
		break;

	case IEEE_MSG_DEAUTHENTICATE:
		{
			WLDBG_INFO(DBG_LEVEL_11,
				   "IEEE_MSG_DEAUTHENTICATE message received. \n");
			smMsg.event = DeAuth;
			smMsg.pBody = (unsigned char *)MgmtMsg_p;
#ifdef AP_MAC_LINUX
			smMsg.info = (void *)skb;
#endif
			if (StaInfo_p->mgtAuthRsp.super.pCurrent != NULL) {
				mhsm_send_event((Mhsm_t *) & StaInfo_p->
						mgtAuthRsp.super, &smMsg);
			} else {
				struct net_device *netdev = vmacSta_p->dev;
				struct wlprivate *wlpptr =
					NETDEV_PRIV_P(struct wlprivate, netdev);
				struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
				struct except_cnt *wlexcept_p =
					&wlpd_p->except_cnt;
				//printk("====>[WAR, %s], reconstruct mgtAuthRsp\n", StaInfo_p->dev->name);
				AuthRspSrvApCtor((AuthRspSrvAp *) & StaInfo_p->
						 mgtAuthRsp);
				mhsm_initialize(&StaInfo_p->mgtAuthRsp.super,
						&StaInfo_p->mgtAuthRsp.sTop);
				mhsm_send_event((Mhsm_t *) & StaInfo_p->
						mgtAuthRsp.super, &smMsg);
				wlexcept_p->deauth_war_cnt++;
			}
		}
		break;

		/* Could be handled by HW */
	case IEEE_MSG_PROBE_RQST:
		{
			SyncSrvApMsg syncMsg;
			WLDBG_INFO(DBG_LEVEL_11,
				   "IEEE_MSG_PROBE_RQST message received. \n");
			syncMsg.opMode = infrastructure;
			syncMsg.mgtMsg = (UINT8 *) MgmtMsg_p;
			smMsg.event = ProbeReq;
			smMsg.pBody = (unsigned char *)&syncMsg;
#ifdef AP_MAC_LINUX
			smMsg.info = (void *)skb;
#endif
			mhsm_send_event((Mhsm_t *) & vmacSta_p->mgtSync.super,
					&smMsg);
		}
		break;

#if defined(QOS_FEATURE)||defined(IEEE80211H)
	case IEEE_MSG_QOS_ACTION:
		{
			WLDBG_INFO(DBG_LEVEL_11,
				   "IEEE_MSG_QOS_ACTION message received. \n");
#ifdef CONFIG_IEEE80211W
			if (MgmtMsg_p->Body.Action.Category ==
			    WLAN_ACTION_SA_QUERY) {
				extern void macMgmtMlme_SAQuery_Rsp(vmacApInfo_t
								    * vmacSta_p,
								    IEEEtypes_MacAddr_t
								    * Addr,
								    IEEEtypes_MacAddr_t
								    * SrcAddr,
								    UINT8 *
								    trans_id,
								    UINT32
								    stamode);
				IEEEtypes_SAQuery_Rsp_t *SARsp_p =
					(IEEEtypes_SAQuery_Rsp_t *) &
					MgmtMsg_p->Body;
				switch (MgmtMsg_p->Body.Action.Action) {
				case WLAN_SA_QUERY_REQUEST:
					WLDBG_INFO(DBG_LEVEL_0,
						   "IEEE_MSG_QOS_ACTION::: Rx WLAN_SA_QUERY_REQUEST trans_id=%02x-%02x\n",
						   SARsp_p->trans_id[0],
						   SARsp_p->trans_id[1]);
					macMgmtMlme_SAQuery_Rsp(vmacSta_p,
								&(MgmtMsg_p->
								  Hdr.SrcAddr),
								&(MgmtMsg_p->
								  Hdr.DestAddr),
								SARsp_p->
								trans_id, 0);
					break;
				case WLAN_SA_QUERY_RESPONSE:
					WLDBG_INFO(DBG_LEVEL_0,
						   "IEEE_MSG_QOS_ACTION::: Rx WLAN_SA_QUERY_RESPONSE trans_id=%02x-%02x\n",
						   SARsp_p->trans_id[0],
						   SARsp_p->trans_id[1]);
					TimerDisarm(&StaInfo_p->SA_Query_Timer);
					if (!StaInfo_p)
						return 1;
					StaInfo_p->sa_query_timed_out = 0;
					StaInfo_p->sa_query_count = 0;
					break;
				default:
					break;
				}
			} else
#endif

			if (MgmtMsg_p->Body.Action.Category == HT_CATEGORY) {
				if (StaInfo_p->HtElem.Len == 0)
					break;

				switch (MgmtMsg_p->Body.Action.Action) {
				case ACTION_SMPS:
					{
						extern int
							wlFwSetMimoPsHt(struct
									net_device
									*netdev,
									UINT8 *
									addr,
									UINT8
									enable,
									UINT8
									mode);
						IEEEtypes_SM_PwrCtl_t *p =
							(IEEEtypes_SM_PwrCtl_t
							 *) & MgmtMsg_p->Body.
							Act.Field.SmPwrCtl;
						WLDBG_INFO(DBG_LEVEL_11,
							   "IEEE_MSG_QOS_ACTION MIMO PS HT message received. \n");
						wlFwSetMimoPsHt(vmacSta_p->dev,
								(UINT8 *)
								MgmtMsg_p->Hdr.
								SrcAddr,
								p->Enable,
								p->Mode);
						break;
					}
#ifdef INTOLERANT40
				case ACTION_INFOEXCH:
					{
						extern void
							RecHTIntolerant
							(vmacApInfo_t *
							 vmacSta_p,
							 UINT8 enable);
						IEEEtypes_InfoExch_t *p =
							(IEEEtypes_InfoExch_t *)
							& MgmtMsg_p->Body.Act.
							Field.InfoExch;
						WLDBG_INFO(DBG_LEVEL_11,
							   "IEEE_MSG_QOS_ACTION Info Exch HT message received. \n");

						RecHTIntolerant(vmacSta_p,
								p->
								FortyMIntolerant);
						break;
					}
#endif //#ifdef INTOLERANT40
				default:
					break;
				}
				break;
			}
#ifdef IEEE80211H
			if (TRUE == macMgmtMlme_80211hAct(vmacSta_p, (macmgmtQ_MgmtMsg3_t *) MgmtMsg_p))	/* if it's mine frame, then return true */
				break;
#endif /* IEEE80211H */
#ifdef COEXIST_20_40_SUPPORT
			if (TRUE == macMgmtMlme_80211PublicAction(vmacSta_p, (macmgmtQ_MgmtMsg3_t *) MgmtMsg_p))	/* if it's mine frame, then return true */
				break;
#endif
#ifdef IEEE80211K
			if (TRUE ==
			    macMgmtMlme_RrmAct(vmacSta_p,
					       (macmgmtQ_MgmtMsg3_t *)
					       MgmtMsg_p))
				break;

			if (TRUE ==
			    macMgmtMlme_WNMAct(vmacSta_p,
					       (macmgmtQ_MgmtMsg3_t *)
					       MgmtMsg_p))
				break;
#endif
#ifdef QOS_FEATURE
			/*smMsg.event = QoSAction;
			   smMsg.pBody = MgmtMsg_p;
			   mhsm_send_event((Mhsm_t *)&wlpptr->vmacSta_p->mgtSync.super, &smMsg); */
			macMgmtMlme_QoSAct(vmacSta_p,
					   (macmgmtQ_MgmtMsg3_t *) MgmtMsg_p);
			break;
#endif /* QOS_FEATURE */
		}
#endif

#ifdef DSP_TRIG_CMD
	case IEEE_MSG_ACTION_NO_ACK:
		{
			extern u32 w81_count_num_ones(u32 bitmap);
			extern int wlDspTrigMu(struct net_device *netdev,
					       UINT8 index, UINT8 priority,
					       U8 * msg, int len);
			macmgmtQ_MgmtActionNoAck_t *MgmtActionNoAck_p =
				(macmgmtQ_MgmtActionNoAck_t *) MgmtMsg_p;
			U8 i;
			U32 tempNc;
			U8 *helpPtr;
			muset_t *pMUset;
			U8 muGID;
			IEEEtypes_VHT_MimoControl_t *MimoCtrl_p =
				&(MgmtActionNoAck_p->Body.CbfReport.Mimo);
			IEEEtypes_HE_MimoControl_t *HEMimoCtrl_p =
				&(MgmtActionNoAck_p->Body.CbfHEReport.Mimo);

			//WLDBG_INFO(DBG_LEVEL_11, "IEEE_MSG_ACTION_NO_ACK message received. \n");
			switch (MgmtActionNoAck_p->Body.CbfReport.Category) {
			case VHT_CATEGORY:
				switch (MgmtActionNoAck_p->Body.CbfReport.
					Action) {
				case 0:
					if (MimoCtrl_p->FbType == 1) {	//MU                                                       
						if (!StaInfo_p->mu_sta)
							return 1;
						if (StaInfo_p->mu_index >= 62)
							return 1;
						pMUset = StaInfo_p->MUset;
						if (pMUset == NULL)
							return 1;

						for (i = 0; i < pMUset->cnt;
						     i++) {
							if (!memcmp
							    (pMUset->
							     StaInfo[i]->Addr,
							     MgmtActionNoAck_p->
							     Hdr.SrcAddr, 6)) {
								muGID = StaInfo_p->mu_index + 1;
								muBitmap[muGID]
									=
									muBitmap
									[muGID]
									| (1 <<
									   i);
								tempNc = MgmtActionNoAck_p->Body.CbfReport.Mimo.NcIdx + 1;
								helpPtr =
									(U8 *)
									MgmtActionNoAck_p->
									Hdr.
									SrcAddr;
								//printk("User: %d, Nc:%d, MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",i,tempNc,helpPtr[0],helpPtr[1],helpPtr[2],helpPtr[3],helpPtr[4],helpPtr[5]);                                                                           
							}
						}

						if (pMUset->cnt ==
						    (w81_count_num_ones
						     (muBitmap[muGID]) & 0xff))
						{
							muConfig.Num_Users =
								pMUset->cnt;
							muConfig.muGID = muGID;
							muConfig.Pkttype = 2;	// this is only VHT for now
							//printk("Total Users: %d, VHT, group-ID %d\n",muConfig.Num_Users,muGID);                                                                       
							wlDspTrigMu(vmacSta_p->
								    dev, 0xff,
								    0,
								    (U8 *) &
								    muConfig,
								    sizeof
								    (mu_config_t));
							muBitmap[muGID] = 0;
						}
					} else {	//SU
					}
					break;

				default:
					break;
				}
				break;

			case HE_CATEGORY:
				switch (MgmtActionNoAck_p->Body.CbfHEReport.
					Action) {
				case 0:
					if (HEMimoCtrl_p->FbType == 1) {	//MU                                                     
						if (!StaInfo_p->mu_sta)
							return 1;
						if (StaInfo_p->mu_index >= 62)
							return 1;
						pMUset = StaInfo_p->MUset;
						if (pMUset == NULL)
							return 1;

						for (i = 0; i < pMUset->cnt;
						     i++) {
							if (!memcmp
							    (pMUset->
							     StaInfo[i]->Addr,
							     MgmtActionNoAck_p->
							     Hdr.SrcAddr, 6)) {
								muGID = StaInfo_p->mu_index + 1;
								muBitmap[muGID]
									=
									muBitmap
									[muGID]
									| (1 <<
									   i);
								tempNc = MgmtActionNoAck_p->Body.CbfHEReport.Mimo.NcIdx + 1;
								helpPtr =
									(U8 *)
									MgmtActionNoAck_p->
									Hdr.
									SrcAddr;
								//printk("User: %d, Nc:%d, MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",i,tempNc,helpPtr[0],helpPtr[1],helpPtr[2],helpPtr[3],helpPtr[4],helpPtr[5]);                                                                           
							}
						}

						if (pMUset->cnt ==
						    (w81_count_num_ones
						     (muBitmap[muGID]) & 0xff))
						{
							muConfig.Num_Users =
								pMUset->cnt;
							muConfig.muGID = muGID;
							muConfig.Pkttype = 3;	// for HE?
							//printk("Total Users: %d, HE, group-ID %d\n",muConfig.Num_Users,muGID);                                                                        
							wlDspTrigMu(vmacSta_p->
								    dev, 0xff,
								    0,
								    (U8 *) &
								    muConfig,
								    sizeof
								    (mu_config_t));
							muBitmap[muGID] = 0;
						}
					} else {	//SU
					}
					break;

				default:
					break;
				}
				break;

			default:
				break;
			}
		}
		break;
#endif

	default:
		break;
	}
	WLDBG_EXIT(DBG_LEVEL_11);

	return 0;
}

/*Originally in main.c for SC3*/
/* Counts the number of ones in the provided bitmap */
u32
w81_count_num_ones(u32 bitmap)
{
	u32 num_ones = 0;
	while (bitmap) {
		num_ones++;
		bitmap &= (bitmap - 1);
	}
	return num_ones;
}

/*************************************************************************
* Function:
*
* Description:
*
* Input:
*
* Output:
*
**************************************************************************/
extern SINT8
evtSmeCmdMsg(vmacApInfo_t * vmacSta_p, UINT8 * message)
{
	MhsmEvent_t smMsg;
	macmgmtQ_SmeCmd_t *smeCmd_p;
	extStaDb_StaInfo_t *StaInfo_p;

	WLDBG_ENTER(DBG_CLASS_INFO);
	if (message == NULL) {
		return 1;
	}
#ifdef AP_MAC_LINUX
	smMsg.devinfo = (void *)vmacSta_p;
#endif
	smeCmd_p = (macmgmtQ_SmeCmd_t *) message;
	switch (smeCmd_p->CmdType) {

	case SME_CMD_DISASSOCIATE:
		{
			WLDBG_INFO(DBG_LEVEL_11,
				   "evtSmeCmdMsg: SME_CMD_DISASSOCIATE message received. \n");
			if ((StaInfo_p =
			     extStaDb_GetStaInfo(vmacSta_p,
						 &smeCmd_p->Body.AssocCmd.
						 PeerStaAddr,
						 STADB_UPDATE_AGINGTIME)) ==
			    NULL) {
				return 1;
			}
			smMsg.event = MlmeDisAssoc_Req;
			smMsg.pBody = (UINT8 *) & (smeCmd_p->Body.AssocCmd);
			mhsm_send_event((Mhsm_t *) & StaInfo_p->mgtAssoc.super,
					&smMsg);
		}
		break;

	case SME_CMD_START:
		{
			SyncSrvApMsg syncMsg;
			WLDBG_INFO(DBG_LEVEL_11,
				   "evtSmeCmdMsg: SME_CMD_START message received. \n");
			syncMsg.opMode = infrastructure;
			syncMsg.mgtMsg = (UINT8 *) & (smeCmd_p->Body.StartCmd);
			smMsg.event = MlmeStart_Req;
			smMsg.pBody = (unsigned char *)&syncMsg;
			mhsm_send_event((Mhsm_t *) & vmacSta_p->mgtSync.super,
					&smMsg);
		}
		break;

	case SME_CMD_RESET:
		{
			SyncSrvApMsg syncMsg;
			WLDBG_INFO(DBG_LEVEL_11,
				   "evtSmeCmdMsg: SME_CMD_RESET message received. \n");
			syncMsg.mgtMsg = (UINT8 *) & (smeCmd_p->Body.ResetCmd);
			smMsg.event = ResetMAC;
			smMsg.pBody = (unsigned char *)&syncMsg;
			mhsm_send_event((Mhsm_t *) & vmacSta_p->mgtSync.super,
					&smMsg);
		}
		break;

#if defined(AP_SITE_SURVEY) || defined(AUTOCHANNEL)
	case SME_CMD_SCAN:
		{
			SyncSrvApMsg syncMsg;
			WLDBG_INFO(DBG_LEVEL_11,
				   "evtSmeCmdMsg: SME_CMD_SCAN message received. \n");
			syncMsg.mgtMsg = (UINT8 *) & (smeCmd_p->Body.ScanCmd);
			smMsg.event = MlmeScan_Req;
			smMsg.pBody = (unsigned char *)&syncMsg;
			mhsm_send_event((Mhsm_t *) & vmacSta_p->mgtSync.super,
					&smMsg);
		}
		break;
#endif /* AP_SITE_SURVEY */

#ifdef IEEE80211H
	case SME_CMD_MREQUEST:
		{
			SyncSrvApMsg syncMsg;
			WLDBG_INFO(DBG_LEVEL_11,
				   "evtSmeCmdMsg: SME_CMD_MREQUEST message received. \n");
			if (!IS_BROADCAST
			    (&smeCmd_p->Body.MrequestCmd.PeerStaAddr)) {
				if ((StaInfo_p =
				     extStaDb_GetStaInfo(vmacSta_p,
							 &smeCmd_p->Body.
							 MrequestCmd.
							 PeerStaAddr,
							 STADB_UPDATE_AGINGTIME))
				    == NULL) {
					WLDBG_INFO(DBG_LEVEL_11,
						   "evtSmeCmdMsg: SME_CMD_MREQUEST - no station found %x:%x:%x:%x:%x:%x] \n",
						   smeCmd_p->Body.MrequestCmd.
						   PeerStaAddr[0],
						   smeCmd_p->Body.MrequestCmd.
						   PeerStaAddr[1],
						   smeCmd_p->Body.MrequestCmd.
						   PeerStaAddr[2],
						   smeCmd_p->Body.MrequestCmd.
						   PeerStaAddr[3],
						   smeCmd_p->Body.MrequestCmd.
						   PeerStaAddr[4],
						   smeCmd_p->Body.MrequestCmd.
						   PeerStaAddr[5]);
					return 1;
				}
			}
			syncMsg.mgtMsg =
				(UINT8 *) & (smeCmd_p->Body.MrequestCmd);
			smMsg.event = MlmeMrequest_Req;
			smMsg.pBody = (unsigned char *)&syncMsg;
			mhsm_send_event((Mhsm_t *) & vmacSta_p->mgtSync.super,
					&smMsg);
		}
		break;

	case SME_CMD_MREPORT:
		{
			SyncSrvApMsg syncMsg;
			WLDBG_INFO(DBG_LEVEL_11,
				   "evtSmeCmdMsg: SME_CMD_MREPORT message received. \n");

			if ((StaInfo_p =
			     extStaDb_GetStaInfo(vmacSta_p,
						 &smeCmd_p->Body.MrequestCmd.
						 PeerStaAddr,
						 STADB_UPDATE_AGINGTIME)) ==
			    NULL) {
				WLDBG_INFO(DBG_LEVEL_11,
					   "evtSmeCmdMsg: SME_CMD_MREPORT - no station found %x:%x:%x:%x:%x:%x] \n",
					   smeCmd_p->Body.MrequestCmd.
					   PeerStaAddr[0],
					   smeCmd_p->Body.MrequestCmd.
					   PeerStaAddr[1],
					   smeCmd_p->Body.MrequestCmd.
					   PeerStaAddr[2],
					   smeCmd_p->Body.MrequestCmd.
					   PeerStaAddr[3],
					   smeCmd_p->Body.MrequestCmd.
					   PeerStaAddr[4],
					   smeCmd_p->Body.MrequestCmd.
					   PeerStaAddr[5]);

				return 1;
			}

			syncMsg.mgtMsg =
				(UINT8 *) & (smeCmd_p->Body.MreportCmd);
			smMsg.event = MlmeMreport_Req;
			smMsg.pBody = (unsigned char *)&syncMsg;
			mhsm_send_event((Mhsm_t *) & vmacSta_p->mgtSync.super,
					&smMsg);
		}
		break;

	case SMC_CMD_CHANNELSWITCH_REQ:
		{
			SyncSrvApMsg syncMsg;
			WLDBG_INFO(DBG_LEVEL_11,
				   "evtSmeCmdMsg: SMC_CMD_CHANNELSWITCH_REQ message received. \n");
			syncMsg.mgtMsg =
				(UINT8 *) & (smeCmd_p->Body.ChannelSwitchCmd);
			smMsg.event = MlmeChannelSwitch_Req;
			smMsg.pBody = (unsigned char *)&syncMsg;
			mhsm_send_event((Mhsm_t *) & vmacSta_p->mgtSync.super,
					&smMsg);
		}
		break;
#endif /* IEEE80211H */
	default:
		break;
	}
	WLDBG_EXIT(DBG_CLASS_INFO);
	return 0;
}

/*************************************************************************
* Function:
*
* Description:
*
* Input:
*
* Output:
*
**************************************************************************/
#ifdef NEW_OSIF_POWERSAVE
/* This is part of group NEW_OSIF_POWERSAVE */
extern SINT8
evtMlmePwMgmtMsg(UINT8 * dataFrameHeader, extStaDb_StaInfo_t * StaInfo_p)
{
	IEEEtypes_PwrMgmtMode_e PwrMode;
	IEEEtypes_GenHdr_t *Hdr_p;

	Hdr_p = (IEEEtypes_GenHdr_t *) dataFrameHeader;
	/*if ((StaInfo_p = extStaDb_GetStaInfo(vmacSta_p,&Hdr_p->Addr2, STADB_DONT_UPDATE_AGINGTIME)) != NULL ) */
	{
		PwrMode = StaInfo_p->PwrMode;

		if (PwrMode == PWR_MODE_ACTIVE) {
			if (Hdr_p->FrmCtl.PwrMgmt == 0) {
				/* no change in mode */
				return 1;
			} else {
				MhsmEvent_t msg;
				msg.event = PsIndicate;
				msg.pBody = (unsigned char *)StaInfo_p;
				StaInfo_p->PwrMode = PWR_MODE_PWR_SAVE;
				mhsm_send_event((Mhsm_t *) & StaInfo_p->
						pwrSvMon.super, &msg);
				return 1;

			}
		} else {
			if (Hdr_p->FrmCtl.PwrMgmt == 1) {
				/* no change in power mode */
				return 1;
			} else {
				MhsmEvent_t msg;
				msg.event = PsIndicate;
				msg.pBody = (unsigned char *)StaInfo_p;
				StaInfo_p->PwrMode = PWR_MODE_ACTIVE;
				mhsm_send_event((Mhsm_t *) & StaInfo_p->
						pwrSvMon.super, &msg);
				return 1;

			}
		}
	}
	return 0;
}
#endif /* NEW_OSIF_POWERSAVE */
