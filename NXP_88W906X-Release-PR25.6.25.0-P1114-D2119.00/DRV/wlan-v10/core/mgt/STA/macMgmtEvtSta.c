/** @file macMgmtEvtSta.c
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
/*******************************************************************************************
*
* File: macMgtEvtSta.c
*        Client MLME Events Module
* Description:  Handle all the events coming in and out of the Client MLME State Machines
*
*******************************************************************************************/
#include "wltypes.h"
#include "mhsm.h"
#include "mlmeSta.h"
#include "wl_mib.h"

#include "mlmeApi.h"
#include "wlvmac.h"
#ifdef STA_QOS
#include "qos.h"
#endif
#include "wldebug.h"

#include "wl_hal.h"
#include "ap8xLnxIntf.h"
#include "mlmeParent.h"
#include "ap8xLnxFwcmd.h"

#ifdef SC_PALLADIUM
#define ETH_DEBUG
#define eprintf printk
#endif

extern void station11hTimerCB(void *data_p);
extern void macMgmtMlme_StopDataTraffic(struct net_device *dev);
#ifdef WMON
static void MrequestIndProcess(vmacStaInfo_t * vmacSta_p, IEEEtypes_MRequestInd_t * MrequestInd_p);
#define WMON_MAX_RSSI_COUNT	0xffff
UINT8 g_wmon_rssi[WMON_MAX_RSSI_COUNT];
UINT32 g_wmon_rssi_count = 0;
void stationWMONTimerCB(void *data_p);
void InitiateAPScan(vmacStaInfo_t * vmacSta_p);
void WMONGetScanResult(vmacStaInfo_t * vStaInfo_p, char *APS);
extern UINT32 Rx_Traffic_FCS_Cnt(struct net_device *dev);
UINT32 WMONMedian(UINT32 * numbers, UINT32 number_count);
UINT32 g_wmon_videoTrafficRx = 0;
char g_wmon_DFSLog[512];
char g_wmon_PSELog[512];
UINT8 gScan = 0;
#endif				//WMON

void staMgmtMlme_QoSAct( /* vmacApInfo_t *vmacSta_p, */ vmacStaInfo_t * vStaInfo_p, dot11MgtFrame_t * MgmtMsg_p);
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
extern void macMgtSyncSrvStaInit(vmacStaInfo_t * vStaInfo_p)
{
	/* Init the Sync, Auth, and Assoc state machines */
	SyncSrvCtorSta(&vStaInfo_p->mgtStaSync);
	mhsm_initialize(&vStaInfo_p->mgtStaSync.super, &vStaInfo_p->mgtStaSync.sTop);
	authSrv_Reset(vStaInfo_p);
	assocSrv_Reset(vStaInfo_p);
}

/*************************************************************************
* Function:
*
* Description: Wrapper for 802.11 Mgt frame received
*
* Input:
*
* Output:
*
**************************************************************************/
#ifdef CONFIG_IEEE80211W
int validateRobustManagementframe_sta(vmacStaInfo_t * vStaInfo_p, dot11MgtFrame_t * mgtFrm, UINT8 * pIsUnprotectMgmt)
{
	extern int isRobustMgmtFrame(UINT16 Subtype);
	extern int isRobustQoSFrame(UINT16 qosCategory);

	vmacEntry_t *vmacEntry_p = (vmacEntry_t *) vStaInfo_p->vMacEntry_p;
	struct net_device *pStaDev = (struct net_device *)vmacEntry_p->privInfo_p;
	struct wlprivate *wlpptrSta = NETDEV_PRIV_P(struct wlprivate, pStaDev);
	vmacApInfo_t *vmacSta_p = wlpptrSta->vmacSta_p;
	extStaDb_StaInfo_t *StaInfo_p = extStaDb_GetStaInfo(vmacSta_p, &mgtFrm->Hdr.BssId, STADB_UPDATE_AGINGTIME);

	if (pIsUnprotectMgmt)
		*pIsUnprotectMgmt = FALSE;

	if (!StaInfo_p || !StaInfo_p->Ieee80211wSta)
		return 0;

	if (!isRobustMgmtFrame(mgtFrm->Hdr.FrmCtl.Subtype))
		return 0;

	if ((mgtFrm->Hdr.FrmCtl.Subtype == IEEE_MSG_QOS_ACTION) && !isRobustQoSFrame(mgtFrm->Body.Action.Category))
		return 0;

	if (!vmacSta_p->igtksaInstalled)
		return 1;

	if (IS_MULTICAST(mgtFrm->Hdr.DestAddr)) {
		extern int mgmtBipMicHandler(UINT8 bipType, UINT8 * igtk, macmgmtQ_MgmtMsg2_t * mgtFrm,
					     IEEEtypes_MMIE_Element_t * mmie_p, int payload_len, BOOLEAN isEnc);

		UINT8 *attrib_p = (UINT8 *) & mgtFrm->Hdr;
		IEEEtypes_MMIE_Element_t *mmie_p = NULL;
		int payload_len;

		switch (mgtFrm->Hdr.FrmCtl.Subtype) {
		case IEEE_MSG_DISASSOCIATE:
		case IEEE_MSG_DEAUTHENTICATE:
			attrib_p += sizeof(IEEEtypes_MgmtHdr_t) + sizeof(IEEEtypes_ReasonCode_t);
			mmie_p = (IEEEtypes_MMIE_Element_t *) syncSrv_ParseAttribWithinFrame(mgtFrm, attrib_p, MM_IE);
			if (!mmie_p) {
				if (pIsUnprotectMgmt)
					*pIsUnprotectMgmt = TRUE;
			}
			/* invalid reason code */
			if ((mgtFrm->Body.Deauth.ReasonCode > IEEEtypes_REASON_8021X_AUTH_FAIL) || !mmie_p)
				return 1;

			/* MIC check todo */
			payload_len = mgtFrm->Hdr.FrmBodyLen - sizeof(IEEEtypes_MgmtHdr_t);
			if (mgmtBipMicHandler(vmacSta_p->igtksaInstalled, vmacSta_p->igtk,
					      (macmgmtQ_MgmtMsg2_t *) & mgtFrm->Hdr.FrmCtl, mmie_p, payload_len, FALSE))
				return 1;

			break;
		}
	} else {
		//Ucast check
		if (!mgtFrm->Hdr.FrmCtl.Wep) {
			if ((mgtFrm->Hdr.FrmCtl.Subtype == IEEE_MSG_DISASSOCIATE) || (mgtFrm->Hdr.FrmCtl.Subtype == IEEE_MSG_DEAUTHENTICATE)) {
				if (pIsUnprotectMgmt)
					*pIsUnprotectMgmt = TRUE;
			}
			return 1;
		}
	}
	return 0;
}
#endif

#ifdef SOC_W8964
extern void *syncSrv_ParseAttrib(macmgmtQ_MgmtMsg_t * mgtFrame_p, UINT8 attrib, UINT16 len);
extern void syncSrv_SetNextChannel(vmacApInfo_t * vmacSta_p);
#endif
extern SINT8 evtDot11_StaMgtMsg(UINT8 * message, UINT8 * rfHdr_p, UINT8 * info_p)
{
	dot11MgtFrame_t *MgmtMsg_p;
	vmacStaInfo_t *vStaInfo_p = (vmacStaInfo_t *) info_p;
	vmacEntry_t *vmacEntry_p;
	MhsmEvent_t smMsg;
	UINT8 fForwardProbeRequestToAp = 0;
	UINT8 isUnprotectMgmt = FALSE;

	if (message == NULL) {
		return 1;
	}
	vmacEntry_p = (vmacEntry_t *) vStaInfo_p->vMacEntry_p;
	MgmtMsg_p = (dot11MgtFrame_t *) message;

	if ((memcmp(MgmtMsg_p->Hdr.DestAddr, &vmacEntry_p->vmacAddr[0], sizeof(IEEEtypes_MacAddr_t)) ||
	     memcmp(MgmtMsg_p->Hdr.BssId, vStaInfo_p->macMgmtMlme_ThisStaData.BssId, sizeof(IEEEtypes_MacAddr_t)))
	    && (MgmtMsg_p->Hdr.FrmCtl.Subtype != IEEE_MSG_PROBE_RQST)
	    && (MgmtMsg_p->Hdr.FrmCtl.Subtype != IEEE_MSG_PROBE_RSP)	/* added for UR */
	    &&(MgmtMsg_p->Hdr.FrmCtl.Subtype != IEEE_MSG_QOS_ACTION)
	    && (MgmtMsg_p->Hdr.FrmCtl.Subtype != IEEE_MSG_BEACON)
	    && (MgmtMsg_p->Hdr.FrmCtl.Subtype != IEEE_MSG_DEAUTHENTICATE)
	    && (MgmtMsg_p->Hdr.FrmCtl.Subtype != IEEE_MSG_DISASSOCIATE)) {
		return 1;
	}
#ifdef CONFIG_IEEE80211W
	if (validateRobustManagementframe_sta(vStaInfo_p, MgmtMsg_p, &isUnprotectMgmt)) {
#ifdef CFG80211
		U16 frmBodyLen = MgmtMsg_p->Hdr.FrmBodyLen - sizeof(MgmtMsg_p->Hdr.FrmBodyLen);
		if (isUnprotectMgmt) {
			/* Remove address4 */
			memmove(&(MgmtMsg_p->Hdr.Rsrvd), &(MgmtMsg_p->Body), frmBodyLen - sizeof(IEEEtypes_MgmtHdr3_t) + sizeof(UINT16));
			frmBodyLen -= ETH_ALEN;
			cfg80211_rx_unprot_mlme_mgmt((struct net_device *)(vmacEntry_p->privInfo_p), (u8 *) & (MgmtMsg_p->Hdr.FrmCtl), frmBodyLen);
		}
#endif
		printk("drop bogus protected frame\n");
		return 1;
	}
#endif

	switch (MgmtMsg_p->Hdr.FrmCtl.Subtype) {
	case IEEE_MSG_AUTHENTICATE:
#ifdef ETH_DEBUG
		eprintf("evtDot11_StaMgtMsg:: case IEEE_MSG_AUTHENTICATE \n");
#endif				/* ETH_DEBUG */
		//evtMlmeSmGen(AuthEven, message);
		smMsg.event = AuthEven;
		smMsg.pBody = message;
		smMsg.info = info_p;
		mhsm_send_event((Mhsm_t *) & vStaInfo_p->mgtStaAuthReq.super, &smMsg);
		break;

	case IEEE_MSG_DEAUTHENTICATE:
#ifdef ETH_DEBUG
		eprintf("evtDot11_StaMgtMsg:: case IEEE_MSG_DEAUTHENTICATE\n");
#endif				/* ETH_DEBUG */
		//evtMlmeSmGen(DeAuth, message);
		smMsg.event = DeAuth;
		smMsg.pBody = message;
		smMsg.info = info_p;
		mhsm_send_event((Mhsm_t *) & vStaInfo_p->mgtStaAuthReq.super, &smMsg);
		break;

	case IEEE_MSG_ASSOCIATE_RSP:
#ifdef ETH_DEBUG
		eprintf("evtDot11_StaMgtMsg:: case IEEE_MSG_ASSOCIATE_RSP\n");
#endif				/* ETH_DEBUG */
		//evtMlmeSmGen(AssocRsp, message);
		smMsg.event = AssocRsp;
		smMsg.pBody = message;
		smMsg.info = info_p;
#if defined(SOC_W906X) && defined(CLIENT_SUPPORT)
		memcpy(&vStaInfo_p->curRxInfo, rfHdr_p, sizeof(WLAN_RX_INFO));
#endif				/* CLIENT_SUPPORT */
		mhsm_send_event((Mhsm_t *) & vStaInfo_p->assocsrv.super, &smMsg);
		break;

	case IEEE_MSG_REASSOCIATE_RSP:
#ifdef ETH_DEBUG
		eprintf("evtDot11_StaMgtMsg:: case IEEE_MSG_REASSOCIATE_RSP\n");
#endif				/* ETH_DEBUG */
		smMsg.event = ReAssocRsp;
		smMsg.pBody = message;
		smMsg.info = info_p;
		mhsm_send_event((Mhsm_t *) & vStaInfo_p->assocsrv.super, &smMsg);
		break;

	case IEEE_MSG_PROBE_RSP:
#ifdef ETH_DEBUG
		eprintf("evtDot11_StaMgtMsg:: case IEEE_MSG_PROBE_RSP\n");
#endif				/* ETH_DEBUG */
		{
			SyncSrvStaMsg syncMsg;

			syncStaMsgInit(vStaInfo_p, &syncMsg, message);
			syncMsg.rfHdr_p = rfHdr_p;
			syncMsg.mgtFrame_p = message;
			syncMsg.cmdMsg_p = NULL;
			smMsg.event = ProbeRsp;
			smMsg.pBody = (UINT8 *) & syncMsg;
			smMsg.info = info_p;
			mhsm_send_event((Mhsm_t *) & vStaInfo_p->mgtStaSync.super, &smMsg);
#ifdef SOC_W8964
			// 5.2.48++
			if (vStaInfo_p->in_obss_scan == TRUE) {
				UINT16 len = MgmtMsg_p->Hdr.FrmBodyLen;
				IEEEtypes_DsParamSet_t *p_ds_param_elm = NULL;
				IEEEtypes_OVERLAP_BSS_SCAN_PARAMETERS_Element_t *p_obss_param_elm = NULL;
				IEEEtypes_20_40_BSS_COEXIST_Element_t *p_2040_coex_elm = NULL;
				IEEEtypes_VhtCap_t *pVhtCap = NULL;
				IEEEtypes_HT_Element_t *pHT = NULL;
				IEEEtypes_Add_HT_Element_t *pHTAdd = NULL;
				UINT8 chnl_num = 0;

				p_ds_param_elm =
				    (IEEEtypes_DsParamSet_t *) syncSrv_ParseAttrib((macmgmtQ_MgmtMsg_t *) (&MgmtMsg_p->Hdr), DS_PARAM_SET, len);
				p_obss_param_elm =
				    (IEEEtypes_OVERLAP_BSS_SCAN_PARAMETERS_Element_t *) syncSrv_ParseAttrib((macmgmtQ_MgmtMsg_t *) (&MgmtMsg_p->Hdr),
													    OVERLAPPING_BSS_SCAN_PARAMETERS, len);
				p_2040_coex_elm =
				    (IEEEtypes_20_40_BSS_COEXIST_Element_t *) syncSrv_ParseAttrib((macmgmtQ_MgmtMsg_t *) (&MgmtMsg_p->Hdr),
												  _20_40_BSSCOEXIST, len);
				pVhtCap = (IEEEtypes_VhtCap_t *) syncSrv_ParseAttrib((macmgmtQ_MgmtMsg_t *) (&MgmtMsg_p->Hdr), VHT_CAP, len);
				pHT = (IEEEtypes_HT_Element_t *) syncSrv_ParseAttrib((macmgmtQ_MgmtMsg_t *) (&MgmtMsg_p->Hdr), HT, len);
				pHTAdd = (IEEEtypes_Add_HT_Element_t *) syncSrv_ParseAttrib((macmgmtQ_MgmtMsg_t *) (&MgmtMsg_p->Hdr), ADD_HT, len);

				if (p_ds_param_elm != NULL) {
					chnl_num = p_ds_param_elm->CurrentChan;
				}

				if (((p_2040_coex_elm != NULL) && (p_2040_coex_elm->Coexist.FortyMhz_Intorant == 1)) ||	// AP with 40MHz Intorant exist
				    ((pVhtCap == NULL) && (pHT == NULL) && (pHTAdd == NULL))) {	// Legacy AP
					UINT8 i;
					//=> Found Legacy AP, vStaInfo_p->intolerant_chnl_size
					// Save the channel 
					for (i = 0; i < vStaInfo_p->intolerant_chnl_size; i++) {
						if (vStaInfo_p->intolerant_chnls[i] == chnl_num) {
							// Already exists, skip ...
							break;
						}
					}
					if (i == vStaInfo_p->intolerant_chnl_size) {
						printk(" => Adding channel[%d] to intorlant list\n", chnl_num);
						vStaInfo_p->intolerant_chnls[vStaInfo_p->intolerant_chnl_size++] = chnl_num;
					}
				}

			}
			// 5.2.48--
#endif				/* SOC_W8964 */
		}
		break;

	case IEEE_MSG_BEACON:
		{
			SyncSrvStaMsg syncMsg;

#ifdef ETH_DEBUG
			eprintf("evtDot11_StaMgtMsg:: case IEEE_MSG_BEACON\n");
#endif				/* ETH_DEBUG */
			syncStaMsgInit(vStaInfo_p, &syncMsg, message);
			syncMsg.rfHdr_p = rfHdr_p;
			syncMsg.mgtFrame_p = message;
			syncMsg.cmdMsg_p = NULL;
			smMsg.event = Beacon;
			smMsg.pBody = (UINT8 *) & syncMsg;
			smMsg.info = info_p;
			mhsm_send_event((Mhsm_t *) & vStaInfo_p->mgtStaSync.super, &smMsg);
		}
		break;

	case IEEE_MSG_DISASSOCIATE:
#ifdef ETH_DEBUG
		eprintf("evtDot11_StaMgtMsg:: case IEEE_MSG_DISASSOCIATE\n");
#endif				/* ETH_DEBUG */
		//evtMlmeSmGen(DisAssoc, message);
		smMsg.event = DisAssoc;
		smMsg.pBody = message;
		smMsg.info = info_p;
		mhsm_send_event((Mhsm_t *) & vStaInfo_p->assocsrv.super, &smMsg);
		break;

		/* SW handle the Probe Request:: Need to response ASAP, so don't go through the statemachine */
	case IEEE_MSG_PROBE_RQST:
#ifdef ETH_DEBUG
		eprintf("evtDot11_StaMgtMsg:: case IEEE_MSG_PROBE_REQ\n");
#endif				/* ETH_DEBUG */
		if (vStaInfo_p->mib_WB_p->opMode && vStaInfo_p->AssociatedFlag) {
			/* We are in Adhoc so Send Probe Response */
			syncSrv_ProbeReqRcvd(vStaInfo_p, (dot11MgtFrame_t *) message, rfHdr_p);
		} else {
			fForwardProbeRequestToAp = 1;
		}
		break;

#ifdef QOS_FEATURE
	case IEEE_MSG_QOS_ACTION:
		staMgmtMlme_QoSAct(vStaInfo_p, MgmtMsg_p);
		break;
#endif				/* STA_QOS */

	default:
#ifdef ETH_DEBUG
		eprintf("evtDot11_StaMgtMsg:: case default: sub-type =%x\n", MgmtMsg_p->Hdr.FrmCtl.Subtype);
#endif				/* ETH_DEBUG */
		break;
	}

	if (fForwardProbeRequestToAp)
		return 1;

	return 0;
}

/*************************************************************************
* Function:
*
* Description: Wrapper for SME Command Msg
*
* Input:
*
* Output:
*
**************************************************************************/
extern SINT8 evtSme_StaCmdMsg(UINT8 * message, UINT8 * dummy, UINT8 * info_p)
{
	macmgmtQ_CmdReq_t *smeCmd_p;
	SyncSrvStaMsg syncMsg;
	MhsmEvent_t smMsg;
	vmacStaInfo_t *vStaInfo_p = (vmacStaInfo_t *) info_p;

	if (message == NULL) {
		return 1;
	}
	smeCmd_p = (macmgmtQ_CmdReq_t *) message;
	switch (smeCmd_p->CmdType) {
	case MlmeScan_Req:
	case MlmeJoin_Req:
	case MlmeStart_Req:
#ifndef PORT_TO_LINUX_OS
	case MlmeReset_Req:
#endif				/* PORT_TO_LINUX_OS */
#ifdef ETH_DEBUG
		eprintf("evtSme_StaCmdMsg:: Sync Srv: event-> %d\n", smeCmd_p->CmdType);
#endif				/* ETH_DEBUG */
		if (smeCmd_p->CmdType == MlmeJoin_Req) {
			macMgtSyncSrvStaInit(vStaInfo_p);
		}
		syncStaMsgInit(vStaInfo_p, &syncMsg, message);
		syncMsg.scanMode = scan_active;
		syncMsg.rfHdr_p = NULL;
		syncMsg.mgtFrame_p = NULL;
		syncMsg.cmdMsg_p = (UINT8 *) & smeCmd_p->Body;
		smMsg.event = smeCmd_p->CmdType;
		smMsg.pBody = (UINT8 *) & syncMsg;
		smMsg.info = info_p;
		mhsm_send_event((Mhsm_t *) & vStaInfo_p->mgtStaSync.super, &smMsg);
		break;

	case MlmeAssoc_Req:
	case MlmeDisAssoc_Req:
	case MlmeReAssoc_Req:
#ifdef ETH_DEBUG
		eprintf("evtMlmeSmRecv:: Association Srv: event-> %d\n", smeCmd_p->CmdType);
#endif				/* ETH_DEBUG */
		assocSrv_Reset(vStaInfo_p);
		smMsg.event = smeCmd_p->CmdType;
		smMsg.pBody = (UINT8 *) & smeCmd_p->Body;
		smMsg.info = info_p;
		mhsm_send_event((Mhsm_t *) & vStaInfo_p->assocsrv.super, &smMsg);
		break;

	case MlmeAuth_Req:
	case MlmeDeAuth_Req:
#ifdef ETH_DEBUG
		eprintf("evtMlmeSmRecv:: Auth Req Srv: event-> %d\n", smeCmd_p->CmdType);
#endif				/* ETH_DEBUG */
		smMsg.event = smeCmd_p->CmdType;
		smMsg.pBody = (UINT8 *) & smeCmd_p->Body;
		smMsg.info = info_p;
		mhsm_send_event((Mhsm_t *) & vStaInfo_p->mgtStaAuthReq.super, &smMsg);
		break;

	case Tbcn:
#ifdef ETH_DEBUG
		eprintf("evtSme_StaCmdMsg:: Sync Srv: event-> %d\n", smeCmd_p->CmdType);
#endif				/* ETH_DEBUG */
		smMsg.event = smeCmd_p->CmdType;
		smMsg.pBody = NULL;
		smMsg.info = info_p;
		mhsm_send_event((Mhsm_t *) & vStaInfo_p->mgtStaSync.super, &smMsg);
		break;

	case MlmeScan_Cnfm:
	case MlmeJoin_Cnfm:
#ifdef ETH_DEBUG
		eprintf("evtSme_StaCmdMsg:: Sync Srv: event-> %d\n", smeCmd_p->CmdType);
#endif				/* ETH_DEBUG */
		syncMsg.rfHdr_p = NULL;
		syncMsg.mgtFrame_p = NULL;
		syncMsg.cmdMsg_p = NULL;
		syncMsg.statMsg_p = message /*(UINT8 *)mgmtMsg_p */ ;
		smMsg.event = smeCmd_p->CmdType;
		smMsg.pBody = (UINT8 *) & syncMsg;
		smMsg.info = info_p;
		mhsm_send_event((Mhsm_t *) & vStaInfo_p->mgtStaSync.super, &smMsg);
		break;

#ifdef PORT_TO_LINUX_OS
	case MlmeReset_Req:
#ifdef ETH_DEBUG
		eprintf("evtSme_StaCmdMsg:: MlmeReset_Req\n");
#endif				/* ETH_DEBUG */
		SyncSrvCtorSta(&vStaInfo_p->mgtStaSync);
		mhsm_initialize(&vStaInfo_p->mgtStaSync.super, &vStaInfo_p->mgtStaSync.sTop);
		syncSrv_ResetCmd(vStaInfo_p, (IEEEtypes_ResetCmd_t *) & smeCmd_p->Body);
		break;
#endif				/* PORT_TO_LINUX_OS */

	case MlmeAuth_Cnfm:
#ifdef ETH_DEBUG
		eprintf("evtSme_StaCmdMsg:: MlmeAuth_Cnfm\n");
#endif				/* ETH_DEBUG */
		authSrv_Reset(vStaInfo_p);
		smeStateMgr_AuthenticateCfrm(info_p, (macmgmtQ_CmdRsp_t *) message);
		break;

	case MlmeAuth_Ind:
#ifdef ETH_DEBUG
		eprintf("evtSme_StaCmdMsg:: MlmeAuth_Ind\n");
#endif				/* ETH_DEBUG */
		smeStateMgr_AuthenticateInd(info_p, (macmgmtQ_CmdRsp_t *) message);
		break;

	case MlmeDeAuth_Cnfm:
#ifdef ETH_DEBUG
		eprintf("evtSme_StaCmdMsg:: MlmeDeAuth_Cnfm\n");
#endif				/* ETH_DEBUG */
		smeStateMgr_DeauthenticateCfrm(info_p, (macmgmtQ_CmdRsp_t *) message);
		break;

	case MlmeDeAuth_Ind:
#ifdef ETH_DEBUG
		eprintf("evtSme_StaCmdMsg:: MlmeDeAuth_Ind\n");
#endif				/* ETH_DEBUG */
		smeStateMgr_DeauthenticateInd(info_p, (macmgmtQ_CmdRsp_t *) message);
		break;

	case MlmeAssoc_Cnfm:
#ifdef ETH_DEBUG
		eprintf("evtSme_StaCmdMsg:: MlmeAssoc_Cnfm\n");
#endif				/* ETH_DEBUG */
		smeStateMgr_AssociateCfrm(info_p, (macmgmtQ_CmdRsp_t *) message);
		break;

	case MlmeAssoc_Ind:
#ifdef ETH_DEBUG
		eprintf("evtSme_StaCmdMsg:: MlmeAssoc_Ind\n");
#endif				/* ETH_DEBUG */
		smeStateMgr_AssociateInd(info_p, (macmgmtQ_CmdRsp_t *) message);
		break;

	case MlmeReAssoc_Cnfm:
#ifdef ETH_DEBUG
		eprintf("evtSme_StaCmdMsg:: MlmeReAssoc_Cnfm\n");
#endif				/* ETH_DEBUG */
		smeStateMgr_ReassociateCfrm(info_p, (macmgmtQ_CmdRsp_t *) message);
		break;

	case MlmeReAssoc_Ind:
#ifdef ETH_DEBUG
		eprintf("evtSme_StaCmdMsg:: MlmeReAssoc_Ind\n");
#endif				/* ETH_DEBUG */
		smeStateMgr_ReassociateInd(info_p, (macmgmtQ_CmdRsp_t *) message);
		break;

	case MlmeDisAssoc_Cnfm:
#ifdef ETH_DEBUG
		eprintf("evtSme_StaCmdMsg:: MlmeDisAssoc_Cnfm\n");
#endif				/* ETH_DEBUG */
		smeStateMgr_DisassociateCfrm(info_p, (macmgmtQ_CmdRsp_t *) message);
		break;

	case MlmeDisAssoc_Ind:
#ifdef ETH_DEBUG
		eprintf("evtSme_StaCmdMsg:: MlmeDisAssoc_Ind\n");
#endif				/* ETH_DEBUG */
		smeStateMgr_DisassociateInd(info_p, (macmgmtQ_CmdRsp_t *) message);
		break;

	case MlmeReset_Cnfm:
#ifdef ETH_DEBUG
		eprintf("evtSme_StaCmdMsg:: MlmeReset_Cnfm\n");
#endif				/* ETH_DEBUG */
		smeStateMgr_ResetCfrm(info_p, (macmgmtQ_CmdRsp_t *) message);
		break;

	case MlmeStart_Cnfm:
#ifdef ETH_DEBUG
		eprintf("evtSme_StaCmdMsg:: MlmeStart_Cnfm\n");
#endif				/* ETH_DEBUG */
		smeStateMgr_StartCfrm(info_p, (macmgmtQ_CmdRsp_t *) message);
		break;

	default:
#ifdef ETH_DEBUG
		eprintf("evtSme_StaCmdMsg:: Default Handler\n");
#endif				/* ETH_DEBUG */
		break;
	}
	return 0;
}

/*************************************************************************
* Function:
*
* Description:	Generate events for MLME State Machine
*
* Input:
*
* Output:
*
**************************************************************************/
extern SINT8 syncStaMsgInit(vmacStaInfo_t * vStaInfo_p, SyncSrvStaMsg * syncMsg_p, UINT8 * message)
{
	if (vStaInfo_p->mib_WB_p->opMode) {
		syncMsg_p->opMode = independent;
	} else {
		syncMsg_p->opMode = infrastructure;
	}

	/* and other parameter later */
	/* like active or passive scan */
	/* and scan timeout value, etc */
	return 0;
}

/*************************************************************************
* Function:
*
* Description:	Generate events for MLME State Machine
*
* Input:
*
* Output:
*
**************************************************************************/
extern SINT32 evtMgtSrvTimeOut(vmacStaInfo_t * vStaInfo_p, UINT8 mgtSrvId)
{
	MhsmEvent_t smMsg;

	smMsg.event = Timeout;
	smMsg.pBody = NULL;
	switch (mgtSrvId) {
	case auth_req_srv:
		mhsm_send_event((Mhsm_t *) & vStaInfo_p->mgtStaAuthReq.super, &smMsg);
		break;
	case assoc_srv:
		mhsm_send_event((Mhsm_t *) & vStaInfo_p->assocsrv.super, &smMsg);
		break;
	case sync_srv:
		mhsm_send_event((Mhsm_t *) & vStaInfo_p->mgtStaSync.super, &smMsg);
		break;
	}
	return MLME_SUCCESS;
}

#ifdef QOS_FEATURE
void staMgmtMlme_QoSAct(vmacStaInfo_t * vStaInfo_p, dot11MgtFrame_t * MgmtMsg_p)
{
	vmacEntry_t *vmacEntry_p = (vmacEntry_t *) vStaInfo_p->vMacEntry_p;
	struct net_device *pStaDev = (struct net_device *)vmacEntry_p->privInfo_p;
	struct wlprivate *wlpptrSta = NETDEV_PRIV_P(struct wlprivate, pStaDev);
	vmacApInfo_t *vmacSta_p = wlpptrSta->vmacSta_p;
	UINT8 QosAct;
#ifdef SOC_W906X
	IEEEtypes_Action_QoS_Category_e QosCategory;
#else
	UINT32 QosCategory;
#endif
	dot11MgtFrame_t *MgmtRsp_p;
	extStaDb_StaInfo_t *pStaInfo;
	IEEEtypes_ADDBA_Req_t *pAddBaReqFrm;
	IEEEtypes_ADDBA_Rsp_t *pAddBaRspFrm;
	IEEEtypes_DELBA_t *pDelBaReqFrm;
	UINT8 amsdu_bitmap = 0;
	IEEEtypes_CSA_ACTION_t *pCSAAction = NULL;
	struct net_device *staDev = NULL;

	staDev = (struct net_device *)vmacEntry_p->privInfo_p;

#ifdef WMON
	smeQ_MgmtMsg_t *toSmeMsg = NULL;
#endif
	//check to see if interface up, only process 
	// the following frames when interface is up 
	if (!(staDev->flags & IFF_RUNNING))
		return;

	if (((UINT8 *) & MgmtMsg_p->Body) == NULL)
		return;
	QosCategory = ((UINT8 *) & MgmtMsg_p->Body)[0];	//get the QoS Action
	QosAct = ((UINT8 *) & MgmtMsg_p->Body)[1];	//get the QoS Action
	switch (QosCategory) {
#ifdef CONFIG_IEEE80211W
	case WLAN_ACTION_SA_QUERY:
		{
			extern void macMgmtMlme_SAQuery_Rsp(vmacApInfo_t * vmacSta_p, IEEEtypes_MacAddr_t * Addr, IEEEtypes_MacAddr_t * SrcAddr,
							    UINT8 * trans_id, UINT32 stamode);
			IEEEtypes_SAQuery_Rsp_t *SARsp_p = (IEEEtypes_SAQuery_Rsp_t *) & MgmtMsg_p->Body;

			switch (MgmtMsg_p->Body.Action.Action) {
			case WLAN_SA_QUERY_REQUEST:
				printk("IEEE_MSG_QOS_ACTION::: Rx WLAN_SA_QUERY_REQUEST trans_id=%02x-%02x\n",
				       SARsp_p->trans_id[0], SARsp_p->trans_id[1]);
				macMgmtMlme_SAQuery_Rsp(vmacSta_p, &(MgmtMsg_p->Hdr.SrcAddr), &(MgmtMsg_p->Hdr.DestAddr), SARsp_p->trans_id, 0);
				break;
			case WLAN_SA_QUERY_RESPONSE:
				printk("IEEE_MSG_QOS_ACTION::: Rx WLAN_SA_QUERY_RESPONSE trans_id=%02x-%02x\n",
				       SARsp_p->trans_id[0], SARsp_p->trans_id[1]);
				break;
			default:
				break;
			}
		}
		break;
#endif
	case SPECTRUM_MANAGEMENT:
		switch (QosAct) {
		case CHANNEL_SWITCH_ANNOUNCEMENT:
			pCSAAction = (IEEEtypes_CSA_ACTION_t *) & MgmtMsg_p->Body;
			if (pCSAAction == NULL)
				return;
			vStaInfo_p->station11hChannel = pCSAAction->Csa.Channel;
			if (pCSAAction->Csa.Count == 0) {
				WLDBG_INFO(DBG_LEVEL_7, "NOW SWITCH CHANNEL to %d\n", vStaInfo_p->station11hChannel);
				// TODO: how to set the second channel if receiving channle switch announcement
				mlmeApiSetRfChannel(vStaInfo_p, vStaInfo_p->station11hChannel, 1, FALSE);
				vStaInfo_p->JoinChannel = vStaInfo_p->station11hChannel;
				return;
			}

			if (vStaInfo_p->station11hTimerFired == 0) {
				vStaInfo_p->station11hTimerFired = 1;
				/*this station11hTimer never been inited, and once hit here, the system get into a deadlock since
				 *it tries to lock a null base->lock. We need to revisit the code regarding this init
				 *the fix here might just be temp solution. */
#if LINUX_VERSION_CODE >=KERNEL_VERSION(4,2,0)
				if (timer_pending(&vStaInfo_p->station11hTimer))
#else
				if (!(&vStaInfo_p->station11hTimer)->base)
#endif
					TimerInit(&vStaInfo_p->station11hTimer);

				TimerFireIn(&vStaInfo_p->station11hTimer, 1, station11hTimerCB, (unsigned char *)vStaInfo_p, pCSAAction->Csa.Count);
			} else {
				TimerRearm(&vStaInfo_p->station11hTimer, pCSAAction->Csa.Count);

			}
			/* If mode == 1, stop transmission, restart transmission after
			 * channel switch.
			 */
			if (pCSAAction->Csa.Mode == 1) {
				macMgmtMlme_StopDataTraffic(staDev);
			}
			break;
		case MEASUREMENT_REQUEST:
#ifdef WMON
			if ((toSmeMsg = wl_kmalloc(sizeof(smeQ_MgmtMsg_t), GFP_ATOMIC)) == NULL) {
				WLDBG_INFO(DBG_LEVEL_7, "staMgmtMlme_QoSAct : failed to alloc msg buffer\n");
				break;
			}
			memset(toSmeMsg, 0, sizeof(smeQ_MgmtMsg_t));
			toSmeMsg->MsgType = SME_NOTIFY_MREQUEST_IND;
			msgMrequestIndPack((IEEEtypes_MRequestInd_t *) & toSmeMsg->Msg.MrequestInd, MgmtMsg_p);
			MrequestIndProcess(vStaInfo_p, (IEEEtypes_MRequestInd_t *) & toSmeMsg->Msg.MrequestInd);
			wl_kfree((UINT8 *) toSmeMsg);
#endif
			break;
		default:
			break;
		}

		break;

	case QoS:
		//printk("staMgmtMlme_QoSAct: QosAct. \n");
		switch (QosAct) {
		case ADDTS_REQ:
			break;
		case DELTS:
			break;
		default:
			break;

		}
		break;
	case BlkAck:
		//printk("staMgmtMlme_QoSAct: BlkAck. \n");
		switch (QosAct) {
		case ADDBA_REQ:
			pStaInfo = extStaDb_GetStaInfo(vmacSta_p, &(MgmtMsg_p->Hdr.BssId), STADB_UPDATE_AGINGTIME);
			if (pStaInfo) {
				int i, tid;
				Ampdu_Pck_Reorder_t *baRxInfo;
				/* Build mgt frame */
				if ((MgmtRsp_p = mlmeApiAllocMgtMsg(vmacSta_p->VMacEntry.phyHwMacIndx)) == NULL) {
					return;
				}
				mlmePrepDefaultMgtMsg_Sta(vStaInfo_p,
							  MgmtRsp_p,
							  &MgmtMsg_p->Hdr.SrcAddr, IEEE_MSG_QOS_ACTION, &(vStaInfo_p->macMgmtMlme_ThisStaData.BssId));
				MgmtRsp_p->Hdr.FrmBodyLen = 0;
				MgmtRsp_p->Hdr.FrmBodyLen += sizeof(IEEEtypes_ADDBA_Rsp_t);

				pAddBaReqFrm = (IEEEtypes_ADDBA_Req_t *) & MgmtMsg_p->Body;
				pAddBaRspFrm = (IEEEtypes_ADDBA_Rsp_t *) & MgmtRsp_p->Body;

				pAddBaRspFrm->Category = pAddBaReqFrm->Category;
				pAddBaRspFrm->Action = ADDTS_RSP;  /** same enum as addba_resp **/
				pAddBaRspFrm->DialogToken = pAddBaReqFrm->DialogToken;
				if (!vmacSta_p->Ampdu_Rx_Disable_Flag) {
					pAddBaRspFrm->StatusCode = IEEEtypes_STATUS_SUCCESS;
				} else {
					pAddBaRspFrm->StatusCode = IEEEtypes_STATUS_REQUEST_DECLINED;
				}
				pAddBaRspFrm->ParamSet = pAddBaReqFrm->ParamSet;

				if (vmacSta_p->Amsdu_Rx_Disable_Flag)
					pAddBaRspFrm->ParamSet.amsdu = 0;
				else
					pAddBaRspFrm->ParamSet.amsdu = pAddBaReqFrm->ParamSet.amsdu;	//honor remote's setting

				pAddBaRspFrm->Timeout_val = pAddBaReqFrm->Timeout_val;
				if (!vmacSta_p->Ampdu_Rx_Disable_Flag) {
					tid = pAddBaReqFrm->ParamSet.tid;
#ifdef SOC_W906X
					baRxInfo = &wlpptrSta->wlpd_p->AmpduPckReorder[pStaInfo->StnId];

#if 0				//REORDER_2B_REMOVED
					baRxInfo->CurrentSeqNo[tid] = pAddBaReqFrm->SeqControl.Starting_Seq_No;
					baRxInfo->ReOrdering[tid] = FALSE;
#endif
					baRxInfo->AddBaReceive[tid] = TRUE;
					if (baRxInfo->timer_init[tid] == 0) {
						TimerInit(&baRxInfo->timer[tid]);
						baRxInfo->timer_init[tid] = 1;
					}

					/** Reset the current queue **/
#if 0				//REORDER_2B_REMOVED
					for (i = 0; i < MAX_AMPDU_REORDER_BUFFER; i++) {
						baRxInfo->ExpectedSeqNo[tid][i] = 0;
						if (baRxInfo->pFrame[tid][i] != NULL)
							wl_free_skb((struct sk_buff *)baRxInfo->pFrame[tid][i]);
						baRxInfo->pFrame[tid][i] = NULL;
					}

					baRxInfo->ExpectedSeqNo[tid][0] = baRxInfo->CurrentSeqNo[tid];
#endif
#else
					wlpptrSta->wlpd_p->AmpduPckReorder[pStaInfo->Aid].CurrentSeqNo[tid] =
					    pAddBaReqFrm->SeqControl.Starting_Seq_No;
					wlpptrSta->wlpd_p->AmpduPckReorder[pStaInfo->Aid].ReOrdering[tid] = FALSE;
					wlpptrSta->wlpd_p->AmpduPckReorder[pStaInfo->Aid].AddBaReceive[tid] = TRUE;
					if (wlpptrSta->wlpd_p->AmpduPckReorder[pStaInfo->Aid].timer_init[tid] == 0) {
						TimerInit(&wlpptrSta->wlpd_p->AmpduPckReorder[pStaInfo->Aid].timer[tid]);
						wlpptrSta->wlpd_p->AmpduPckReorder[pStaInfo->Aid].timer_init[tid] = 1;
					}

					/** Reset the current queue **/
					for (i = 0; i < MAX_AMPDU_REORDER_BUFFER; i++) {
						wlpptrSta->wlpd_p->AmpduPckReorder[pStaInfo->Aid].ExpectedSeqNo[tid][i] = 0;
						if (wlpptrSta->wlpd_p->AmpduPckReorder[pStaInfo->Aid].pFrame[tid][i] != NULL)
							wl_free_skb((struct sk_buff *)wlpptrSta->wlpd_p->AmpduPckReorder[pStaInfo->Aid].
								    pFrame[tid][i]);
						wlpptrSta->wlpd_p->AmpduPckReorder[pStaInfo->Aid].pFrame[tid][i] = NULL;
					}

					wlpptrSta->wlpd_p->AmpduPckReorder[pStaInfo->Aid].ExpectedSeqNo[tid][0] =
					    wlpptrSta->wlpd_p->AmpduPckReorder[pStaInfo->Aid].CurrentSeqNo[tid];

					baRxInfo = &wlpptrSta->wlpd_p->AmpduPckReorder[pStaInfo->Aid];
#endif				/* SOC_W906X */
					for (i = 0; i < MAX_BA_REORDER_BUF_SIZE; i++) {
						skb_queue_purge(&baRxInfo->ba[tid].AmsduQ[i].skbHead);
						baRxInfo->ba[tid].AmsduQ[i].state = 0;
					}

					baRxInfo->ba[tid].winStartB = pAddBaReqFrm->SeqControl.Starting_Seq_No;
#ifdef SOC_W906X

					baRxInfo->ba[tid].winSizeB =
					    (pAddBaReqFrm->ParamSet.BufSize <
					     MAX_BA_REORDER_BUF_SIZE) ? pAddBaRspFrm->ParamSet.BufSize : MAX_BA_REORDER_BUF_SIZE;
					//printk("%s:ADDBA_RSP: pAddBaRspFrm->ParamSet.BufSize:%u\n",__func__, pAddBaRspFrm->ParamSet.BufSize);
#else
					//baRxInfo->ba[tid].winSizeB =  (pAddBaRspFrm->ParamSet.BufSize > MAX_BA_REORDER_BUF_SIZE)? MAX_BA_REORDER_BUF_SIZE : pAddBaRspFrm->ParamSet.BufSize;
					baRxInfo->ba[tid].winSizeB = MAX_BA_REORDER_BUF_SIZE;
#endif
					baRxInfo->ba[tid].storedBufCnt = 0;
					baRxInfo->ba[tid].leastSeqNo = 0;
					baRxInfo->ba[tid].minTime = 0;
				}

				/* Send mgt frame */
				if (mlmeApiSendMgtMsg_Sta(vStaInfo_p, MgmtRsp_p, NULL) == MLME_FAILURE) {
					printk("staMgmtMlme_QoSAct: mlmeApiSendMgtMsg_Sta failed \n");
					return;
				}
#ifdef SOC_W906X
				if (pAddBaRspFrm->StatusCode == IEEEtypes_STATUS_SUCCESS)
					wlFwCreateBAStream(vmacSta_p->dev, pAddBaReqFrm->ParamSet.BufSize, pAddBaReqFrm->ParamSet.BufSize,
							   (u_int8_t *) & (MgmtMsg_p->Hdr.SrcAddr), 10, pAddBaReqFrm->ParamSet.tid, amsdu_bitmap, 1,
							   pStaInfo->HtElem.MacHTParamInfo, (u_int8_t *) & (MgmtMsg_p->Hdr.DestAddr),
							   pAddBaReqFrm->SeqControl.Starting_Seq_No, pStaInfo->vhtCap.cap.MaximumAmpduLengthExponent,
							   0, (u_int16_t) pStaInfo->StnId);
#else
				if (pAddBaRspFrm->StatusCode == IEEEtypes_STATUS_SUCCESS)
					wlFwCreateBAStream(vmacSta_p->dev, pAddBaReqFrm->ParamSet.BufSize, pAddBaReqFrm->ParamSet.BufSize,
							   (u_int8_t *) & (MgmtMsg_p->Hdr.SrcAddr), 10, pAddBaReqFrm->ParamSet.tid, amsdu_bitmap, 1,
							   pStaInfo->HtElem.MacHTParamInfo, (u_int8_t *) & (MgmtMsg_p->Hdr.DestAddr),
							   pAddBaReqFrm->SeqControl.Starting_Seq_No, pStaInfo->vhtCap.cap.MaximumAmpduLengthExponent,
							   0);
#endif
			}
			break;
		case DELBA:
			pStaInfo = extStaDb_GetStaInfo(vmacSta_p, &(MgmtMsg_p->Hdr.BssId), STADB_UPDATE_AGINGTIME);
			if (pStaInfo) {
				int i, tid;
				Ampdu_Pck_Reorder_t *baRxInfo;

				pDelBaReqFrm = (IEEEtypes_DELBA_t *) & MgmtMsg_p->Body;

				tid = pDelBaReqFrm->ParamSet.tid;
				if (pDelBaReqFrm->ParamSet.Initiator == 1) {
/** Initiator want to stop ampdu **/
#ifdef SOC_W906X
					baRxInfo = &wlpptrSta->wlpd_p->AmpduPckReorder[pStaInfo->StnId];
					//baRxInfo->ReOrdering[tid]  = FALSE;    REORDER_2B_REMOVED
					baRxInfo->AddBaReceive[tid] = FALSE;

					/** Reset the current queue **/

#if 0				//REORDER_2B_REMOVED
					for (i = 0; i < MAX_AMPDU_REORDER_BUFFER; i++) {
						baRxInfo->ExpectedSeqNo[tid][i] = 0;
						if (baRxInfo->pFrame[tid][i] != NULL)
							wl_free_skb((struct sk_buff *)baRxInfo->pFrame[tid][i]);
						baRxInfo->pFrame[tid][i] = NULL;
					}

					baRxInfo->ExpectedSeqNo[tid][0] = baRxInfo->CurrentSeqNo[tid];
#endif
#else
					wlpptrSta->wlpd_p->AmpduPckReorder[pStaInfo->Aid].ReOrdering[tid] = FALSE;
					wlpptrSta->wlpd_p->AmpduPckReorder[pStaInfo->Aid].AddBaReceive[tid] = FALSE;

					/** Reset the current queue **/

					for (i = 0; i < MAX_AMPDU_REORDER_BUFFER; i++) {
						wlpptrSta->wlpd_p->AmpduPckReorder[pStaInfo->Aid].ExpectedSeqNo[tid][i] = 0;
						if (wlpptrSta->wlpd_p->AmpduPckReorder[pStaInfo->Aid].pFrame[tid][i] != NULL)
							wl_free_skb((struct sk_buff *)wlpptrSta->wlpd_p->AmpduPckReorder[pStaInfo->Aid].
								    pFrame[tid][i]);
						wlpptrSta->wlpd_p->AmpduPckReorder[pStaInfo->Aid].pFrame[tid][i] = NULL;
					}

					wlpptrSta->wlpd_p->AmpduPckReorder[pStaInfo->Aid].ExpectedSeqNo[tid][0] =
					    wlpptrSta->wlpd_p->AmpduPckReorder[pStaInfo->Aid].CurrentSeqNo[tid];

					baRxInfo = &wlpptrSta->wlpd_p->AmpduPckReorder[pStaInfo->Aid];
#endif				/* SOC_W906X */
					for (i = 0; i < MAX_BA_REORDER_BUF_SIZE; i++) {
						skb_queue_purge(&baRxInfo->ba[tid].AmsduQ[i].skbHead);
						baRxInfo->ba[tid].AmsduQ[i].state = 0;
					}

					baRxInfo->ba[tid].winStartB = 0;
					baRxInfo->ba[tid].winSizeB = 0;
					baRxInfo->ba[tid].storedBufCnt = 0;
					baRxInfo->ba[tid].leastSeqNo = 0;
					baRxInfo->ba[tid].minTime = 0;
				} else {
/** Receiver want to stop us from doing ampdu **/

					/** check which stream is it for **/
					for (i = 0; i < MAX_SUPPORT_AMPDU_TX_STREAM_RUNNING; i++) {
						if (!MACADDR_CMP(wlpptrSta->wlpd_p->Ampdu_tx[i].MacAddr, &(MgmtMsg_p->Hdr.SrcAddr))) {
							/** they are equal **/
							if (wlpptrSta->wlpd_p->Ampdu_tx[i].AccessCat == pDelBaReqFrm->ParamSet.tid
							    && wlpptrSta->wlpd_p->Ampdu_tx[i].InUse == 1) {
								pStaInfo->aggr11n.type &= ~WL_WLAN_TYPE_AMPDU;
								wlFwUpdateDestroyBAStream(vmacSta_p->dev, 0, 0, i,
											  wlpptrSta->wlpd_p->Ampdu_tx[i].AccessCat,
											  wlpptrSta->wlpd_p->Ampdu_tx[i].MacAddr, pStaInfo->StnId);
								pStaInfo->aggr11n.onbytid[wlpptrSta->wlpd_p->Ampdu_tx[i].AccessCat] = 0;
								pStaInfo->aggr11n.startbytid[wlpptrSta->wlpd_p->Ampdu_tx[i].AccessCat] = 0;
								// Turn off aggregation until reconnect.
								pStaInfo->aggr11n.threshold = 0;
								pStaInfo->aggr11n.thresholdBackUp = pStaInfo->aggr11n.threshold;
								wlpptrSta->wlpd_p->Ampdu_tx[i].InUse = 0;
								wlpptrSta->wlpd_p->Ampdu_tx[i].TimeOut = 0;

							}
						}
					}
				}
			}
			break;
		case ADDBA_RESP:
			pStaInfo = extStaDb_GetStaInfo(vmacSta_p, &(MgmtMsg_p->Hdr.BssId), STADB_UPDATE_AGINGTIME);
			if (pStaInfo) {
				int i;
				pAddBaRspFrm = (IEEEtypes_ADDBA_Rsp_t *) & MgmtMsg_p->Body;

				printk("ADDBA_RESP from AP %s \n", mac_display((const UINT8 *)&MgmtMsg_p->Hdr.BssId));

				for (i = 0; i < MAX_SUPPORT_AMPDU_TX_STREAM_RUNNING; i++) {
					if (wlpptrSta->wlpd_p->Ampdu_tx[i].DialogToken == pAddBaRspFrm->DialogToken &&
					    wlpptrSta->wlpd_p->Ampdu_tx[i].InUse
					    && wlpptrSta->wlpd_p->Ampdu_tx[i].AccessCat == pAddBaRspFrm->ParamSet.tid) {
						if (MACADDR_CMP(wlpptrSta->wlpd_p->Ampdu_tx[i].MacAddr, &(MgmtMsg_p->Hdr.BssId)) == 0)
							break;
					}
				}
				if (i < MAX_SUPPORT_AMPDU_TX_STREAM_RUNNING) {
/** either stream 0 or 1 is equal **/
					if (pAddBaRspFrm->StatusCode == 0)	//success
					{
						if (pAddBaRspFrm->ParamSet.tid == wlpptrSta->wlpd_p->Ampdu_tx[i].AccessCat) {
							if (wlpptrSta->wlpd_p->Ampdu_tx[i].initTimer == 1)
								TimerDisarm(&wlpptrSta->wlpd_p->Ampdu_tx[i].timer);

							if (*(vmacSta_p->Mib802dot11->pMib_11nAggrMode) & WL_MODE_AMSDU_TX_MASK)
								amsdu_bitmap =
								    (pAddBaRspFrm->ParamSet.
								     amsdu) ? (*(vmacSta_p->Mib802dot11->
										 pMib_11nAggrMode) & WL_MODE_AMSDU_TX_MASK) : 0;
#ifdef SOC_W906X
							if ((wlFwCreateBAStream
							     (pStaDev, pAddBaRspFrm->ParamSet.BufSize, pAddBaRspFrm->ParamSet.BufSize,
							      (u_int8_t *) & (MgmtMsg_p->Hdr.SrcAddr), 10, wlpptrSta->wlpd_p->Ampdu_tx[i].AccessCat,
							      amsdu_bitmap, 0, pStaInfo->HtElem.MacHTParamInfo,
							      (u_int8_t *) & (MgmtMsg_p->Hdr.DestAddr), wlpptrSta->wlpd_p->Ampdu_tx[i].start_seqno,
							      pStaInfo->vhtCap.cap.MaximumAmpduLengthExponent, i,
							      (u_int16_t) pStaInfo->StnId)) == SUCCESS)
#else
							if ((wlFwCreateBAStream
							     (pStaDev, pAddBaRspFrm->ParamSet.BufSize, pAddBaRspFrm->ParamSet.BufSize,
							      (u_int8_t *) & (MgmtMsg_p->Hdr.SrcAddr), 10, wlpptrSta->wlpd_p->Ampdu_tx[i].AccessCat,
							      amsdu_bitmap, 0, pStaInfo->HtElem.MacHTParamInfo,
							      (u_int8_t *) & (MgmtMsg_p->Hdr.DestAddr), wlpptrSta->wlpd_p->Ampdu_tx[i].start_seqno,
							      pStaInfo->vhtCap.cap.MaximumAmpduLengthExponent, i)) == SUCCESS)
#endif
							{
								pStaInfo->aggr11n.type |= WL_WLAN_TYPE_AMPDU;
								//only doing amsdu over ampdu if peer supported
								if (pAddBaRspFrm->ParamSet.amsdu
								    && (*(vmacSta_p->Mib802dot11->pMib_11nAggrMode) & WL_MODE_AMSDU_TX_MASK)) {
									pStaInfo->aggr11n.type |= WL_WLAN_TYPE_AMSDU;
								} else {
									pStaInfo->aggr11n.type &= ~WL_WLAN_TYPE_AMSDU;
								}
							} else {
								/** FW is not ready to accept addba stream **/
								SendDelBASta(vmacSta_p, (UINT8 *) & wlpptrSta->wlpd_p->Ampdu_tx[0].MacAddr[0],
									     wlpptrSta->wlpd_p->Ampdu_tx[i].AccessCat);
								pStaInfo->aggr11n.type &= ~WL_WLAN_TYPE_AMPDU;
								wlpptrSta->wlpd_p->Ampdu_tx[i].InUse = 0;
								wlpptrSta->wlpd_p->Ampdu_tx[i].TimeOut = 0;
								//fall back to amsdu    
								if (*(vmacSta_p->Mib802dot11->pMib_11nAggrMode) & WL_MODE_AMSDU_TX_MASK) {
									pStaInfo->aggr11n.type |= WL_WLAN_TYPE_AMSDU;
								}
							}
							pStaInfo->aggr11n.type |= WL_WLAN_TYPE_AMPDU;
						} else {
							printk("Invalid block ack response \n");
						}
						wlpptrSta->wlpd_p->Ampdu_tx[i].AddBaResponseReceive = 1;
					} else {
						/** addba fail failure status code , clear the stream**/
						if (wlpptrSta->wlpd_p->Ampdu_tx[i].initTimer == 1)
							TimerDisarm(&wlpptrSta->wlpd_p->Ampdu_tx[i].timer);

						wlpptrSta->wlpd_p->Ampdu_tx[i].DialogToken = 0;
						wlpptrSta->wlpd_p->Ampdu_tx[i].InUse = 0;
						wlpptrSta->wlpd_p->Ampdu_tx[i].AccessCat = 0;
						wlpptrSta->wlpd_p->Ampdu_tx[i].TimeOut = 0;
					}
				}
			}
			break;

		default:
			break;
		}
		break;
	case DLP:
		//printk("staMgmtMlme_QoSAct QosCategory = DLP \n");
		switch (QosAct) {
		case DLP_REQ:
			break;
		case DLP_RESP:
			break;
		case DLP_TEAR_DOWN:
			break;
		default:
			break;
		}
		break;
	case VHT:
		{
			IEEEtypes_GroupIDMgmt_t *pGroupIDMgmtFrm;
			int i;
			UINT8 value, count;
			UINT32 usr_pos, GID;
			UINT16 aidset;
			pGroupIDMgmtFrm = (IEEEtypes_GroupIDMgmt_t *) & MgmtMsg_p->Body;
			//              pStaInfo = extStaDb_GetStaInfo(vmacSta_p, &(MgmtMsg_p->Hdr.BssId), STADB_UPDATE_AGINGTIME);
			//      if(pStaInfo)
			{
				printk("receive VHT action frame AID=%x\n", vStaInfo_p->aId);
			}
			aidset = vStaInfo_p->aId & 0x3fff;

			for (i = 0; i < 8; i++)
				printk("%x ", pGroupIDMgmtFrm->MembershipStatusArray[i]);
			printk("\n");
			for (i = 0; i < 16; i++)
				printk("%x ", pGroupIDMgmtFrm->UserPositionArray[i]);
			printk("\n");

			count = 0;
			for (i = 0; i < 8; i++) {
				if (pGroupIDMgmtFrm->MembershipStatusArray[i] != 0) {
					value = pGroupIDMgmtFrm->MembershipStatusArray[i];
					while (value > 0) {	// until all bits are zero
						if ((value & 1) == 1)	// check lower bit
							break;
						count++;
						value >>= 1;
					}
					break;
				}

			}
			GID = i * 8 + count;

			printk("GID=%x\n", GID);

			if (GID > 0 && GID < 63) {
				usr_pos = pGroupIDMgmtFrm->UserPositionArray[GID / 4] >> (2 * (GID % 4));
				printk("[%s]User_position=%x\n", staDev->name, usr_pos);
#ifdef SOC_W8964
				wlRegBB(vmacSta_p->dev, 1, 0x893, &GID);
				//      PciWriteMacReg(vmacSta_p->dev, 0x11a0, 0);
				//      PciWriteMacReg(vmacSta_p->dev, 0x11a0, aidset);
				PciWriteMacReg(vmacSta_p->dev, 0x300, 0xc002397e);	    /** temp WAR for MAC **/
				PciWriteMacReg(vmacSta_p->dev, 0xd78, 0xff);
				wlRegBB(vmacSta_p->dev, 1, 0x897, &usr_pos);
#endif

#ifdef SOC_W906X
				wlFwMuUserPosition(staDev, WL_SET, GID, usr_pos);
#endif
			} else
				printk("BAD GID!!\n");

		}
		break;
	default:
		break;
	}
}
#endif				/* QOS_FEATURE */

void SendAddBAReqSta(vmacApInfo_t * vmacSta_p, IEEEtypes_MacAddr_t StaAddrA, UINT8 tsid,
		     IEEEtypes_QoS_BA_Policy_e BaPolicy, UINT32 SeqNo, UINT8 DialogToken)
{
	dot11MgtFrame_t *MgmtRsp_p;
	IEEEtypes_ADDBA_Req_t *pAddBaReqFrm;
	vmacStaInfo_t *vStaInfo_p = NULL;
	UINT8 macIndex = vmacSta_p->VMacEntry.phyHwMacIndx;
#ifdef SOC_W906X
	//sba++
	HE_Capabilities_IE_t *phe = NULL;
	UINT8 he_capable = 0;
#endif

	if ((vStaInfo_p = (vmacStaInfo_t *) vmacGetVMacStaInfo(parentGetVMacId(macIndex))) == NULL) {
		return;
	}

	if ((MgmtRsp_p = mlmeApiAllocMgtMsg(macIndex)) == NULL) {
		return;
	}
#ifdef SOC_W906X
	//sba++
	phe = &vStaInfo_p->bssDescProfile_p->hecap;
	if (phe->hdr.ext == HE_CAPABILITIES_IE && *(vmacSta_p->Mib802dot11->mib_superBA) == 1 &&	//superBA enabled.
	    phe->hdr.Len > (sizeof(HE_Mac_Capabilities_Info_t) + sizeof(HE_Phy_Capabilities_Info_t))) {
		he_capable = 1;
		//printk("%s():he_capable=%u\n",__func__, he_capable);
	}
#endif

	mlmePrepDefaultMgtMsg_Sta(vStaInfo_p,
				  MgmtRsp_p,
				  &(vStaInfo_p->macMgmtMlme_ThisStaData.BssId), IEEE_MSG_QOS_ACTION, &(vStaInfo_p->macMgmtMlme_ThisStaData.BssId));

	MgmtRsp_p->Hdr.FrmBodyLen = 0;
	MgmtRsp_p->Hdr.FrmBodyLen += sizeof(IEEEtypes_ADDBA_Req_t);
	pAddBaReqFrm = (IEEEtypes_ADDBA_Req_t *) & MgmtRsp_p->Body;

	pAddBaReqFrm->Category = BlkAck;
	pAddBaReqFrm->Action = ADDBA_REQ;
	pAddBaReqFrm->DialogToken = DialogToken;
	pAddBaReqFrm->ParamSet.amsdu = (*(vmacSta_p->Mib802dot11->pMib_11nAggrMode) & WL_MODE_AMSDU_TX_MASK) ? 1 : 0;
	pAddBaReqFrm->ParamSet.BA_policy = BaPolicy;
	pAddBaReqFrm->ParamSet.tid = tsid;

#ifdef SOC_W906X
	//sba++     
	if (he_capable)
		pAddBaReqFrm->ParamSet.BufSize = MAX_BA_REORDER_BUF_SIZE;
	else
#endif
		pAddBaReqFrm->ParamSet.BufSize = 64;

	pAddBaReqFrm->Timeout_val = 0x0;	//in sec
	pAddBaReqFrm->SeqControl.FragNo = 0;
	pAddBaReqFrm->SeqControl.Starting_Seq_No = SeqNo;

	printk("ADDBA_REQ to AP %s , winsize:%u\n", mac_display((const UINT8 *)&vStaInfo_p->macMgmtMlme_ThisStaData.BssId),
	       pAddBaReqFrm->ParamSet.BufSize);

	/* Send mgt frame */
	if (mlmeApiSendMgtMsg_Sta(vStaInfo_p, MgmtRsp_p, NULL) == MLME_FAILURE) {
		printk("staMgmtMlme_QoSAct: mlmeApiSendMgtMsg_Sta failed \n");
		return;
	}
	return;
}

void SendDelBASta(vmacApInfo_t * vmacSta_p, IEEEtypes_MacAddr_t StaAddr, UINT8 tsid)
{
	IEEEtypes_DELBA_t *pDelBA;
	dot11MgtFrame_t *MgmtRsp_p;
	vmacStaInfo_t *vStaInfo_p = NULL;
	UINT8 macIndex = vmacSta_p->VMacEntry.phyHwMacIndx;

	if ((vStaInfo_p = (vmacStaInfo_t *) vmacGetVMacStaInfo(parentGetVMacId(macIndex))) == NULL) {
		return;
	}

	if ((MgmtRsp_p = mlmeApiAllocMgtMsg(macIndex)) == NULL) {
		return;
	}
	mlmePrepDefaultMgtMsg_Sta(vStaInfo_p,
				  MgmtRsp_p,
				  &(vStaInfo_p->macMgmtMlme_ThisStaData.BssId), IEEE_MSG_QOS_ACTION, &(vStaInfo_p->macMgmtMlme_ThisStaData.BssId));

	MgmtRsp_p->Hdr.FrmBodyLen = 0;
	MgmtRsp_p->Hdr.FrmBodyLen += sizeof(IEEEtypes_DELBA_t);

	pDelBA = (IEEEtypes_DELBA_t *) & MgmtRsp_p->Body;

	pDelBA->Category = BlkAck;
	pDelBA->Action = DELBA;
	pDelBA->ParamSet.Resvd = 0;
	pDelBA->ParamSet.Initiator = 1;
	pDelBA->ParamSet.tid = tsid;
	pDelBA->ReasonCode = 1;

	/* Send mgt frame */
	if (mlmeApiSendMgtMsg_Sta(vStaInfo_p, MgmtRsp_p, NULL) == MLME_FAILURE) {
		printk("staMgmtMlme_QoSAct: mlmeApiSendMgtMsg_Sta failed \n");
		return;
	}

	return;
}

#ifdef SOC_W8964
extern UINT8 getRegulatoryClass(vmacApInfo_t * vmacSta_p);
void Send2040CoexSta(vmacStaInfo_t * vStaInfo_p)
{
	dot11MgtFrame_t *MgmtRsp_p;
	IEEEtypes_20_40_Coexist_Act_t *p2040CoexFrm;
	UINT8 i, macIndex;
	vmacApInfo_t *vmacSta_p = (vmacApInfo_t *) vStaInfo_p->vMacEntry_p;;
	macIndex = vmacSta_p->VMacEntry.phyHwMacIndx;

	if ((vStaInfo_p = (vmacStaInfo_t *) vmacGetVMacStaInfo(parentGetVMacId(macIndex))) == NULL) {
		return;
	}

	if ((MgmtRsp_p = mlmeApiAllocMgtMsg(macIndex)) == NULL) {
		return;
	}

	mlmePrepDefaultMgtMsg_Sta(vStaInfo_p,
				  MgmtRsp_p,
				  &(vStaInfo_p->macMgmtMlme_ThisStaData.BssId), IEEE_MSG_QOS_ACTION, &(vStaInfo_p->macMgmtMlme_ThisStaData.BssId));
	MgmtRsp_p->Hdr.FrmBodyLen = 0;
	MgmtRsp_p->Hdr.FrmBodyLen += sizeof(IEEEtypes_20_40_Coexist_Act_t);
	p2040CoexFrm = (IEEEtypes_20_40_Coexist_Act_t *) & MgmtRsp_p->Body;

	p2040CoexFrm->Category = ACTION_PUBLIC;
	p2040CoexFrm->Action = COEX_2040;
	// 20/40 BSS Coexistance
	p2040CoexFrm->Coexist_Report.ElementId = _20_40_BSSCOEXIST;
	p2040CoexFrm->Coexist_Report.Len = sizeof(IEEEtypes_20_40_Coexist_t);
	memset(&p2040CoexFrm->Coexist_Report.Coexist, 0, sizeof(p2040CoexFrm->Coexist_Report.Coexist));
	p2040CoexFrm->Coexist_Report.Coexist.TwentyMhz_BSS_Width_Request = 1;

	p2040CoexFrm->Intolerant_Report.ElementId = _20_40_BSS_INTOLERANT_CHANNEL_REPORT;
	p2040CoexFrm->Intolerant_Report.Len = vStaInfo_p->intolerant_chnl_size + 1;
	p2040CoexFrm->Intolerant_Report.RegClass = getRegulatoryClass((vmacApInfo_t *) vStaInfo_p);
	for (i = 0; i < vStaInfo_p->intolerant_chnl_size; i++) {
		p2040CoexFrm->Intolerant_Report.ChanList[i] = vStaInfo_p->intolerant_chnls[i];
	}

	// Remove the unused channel list
	MgmtRsp_p->Hdr.FrmBodyLen -= (sizeof(p2040CoexFrm->Intolerant_Report.ChanList) - vStaInfo_p->intolerant_chnl_size);

	printk("Send 20/40 Coex Mgmt to AP %s, len=%d \n", mac_display((const UINT8 *)&vStaInfo_p->macMgmtMlme_ThisStaData.BssId),
	       MgmtRsp_p->Hdr.FrmBodyLen);

	/* Send mgt frame */
	if (mlmeApiSendMgtMsg_Sta(vStaInfo_p, MgmtRsp_p, NULL) == MLME_FAILURE) {
		printk("%s(): mlmeApiSendMgtMsg_Sta failed \n", __func__);
		return;
	}
	return;
}
#endif				/* SOC_W8964 */
#ifdef WMON
static void MrequestIndProcess(vmacStaInfo_t * vmacSta_p, IEEEtypes_MRequestInd_t * MrequestInd_p)
{
	vmacEntry_t *vmacEntry_p = (vmacEntry_t *) vmacSta_p->vMacEntry_p;
	struct net_device *staDev = (struct net_device *)vmacEntry_p->privInfo_p;
	IEEEtypes_MReportCmd_t *MreportCmd_p;
	UINT32 loop = 0;
	UINT16 duration = 0;
	UINT8 wmonStart = 0;

	MreportCmd_p = wl_kmalloc(sizeof(IEEEtypes_MReportCmd_t), GFP_ATOMIC);
	if (MreportCmd_p == NULL) {
		printk("NOT ENOUGH MEMORY\n");
		return;
	}
	memset(MreportCmd_p, 0, sizeof(IEEEtypes_MReportCmd_t));

	memcpy(MreportCmd_p->PeerStaAddr, &MrequestInd_p->PeerStaAddr, sizeof(IEEEtypes_MacAddr_t));

	/* identify the measurement transaction */
	MreportCmd_p->DiaglogToken = MrequestInd_p->DiaglogToken;

	MreportCmd_p->ReportItems = MrequestInd_p->RequestItems;

	for (loop = 0; loop < MreportCmd_p->ReportItems; loop++) {
		MreportCmd_p->MeasureRepSet[loop].MeasurementToken = MrequestInd_p->MeasureReqSet[loop].MeasurementToken;
		MreportCmd_p->MeasureRepSet[loop].Type = MrequestInd_p->MeasureReqSet[loop].Type;
		switch (MreportCmd_p->MeasureRepSet[loop].Type) {
		case TYPE_REQ_BASIC:
			break;
		case TYPE_REQ_CCA:
			break;
		case TYPE_REQ_RPI:
			MreportCmd_p->MeasureRepSet[loop].Report.Channel = 44;
			memset(&MreportCmd_p->MeasureRepSet[loop].Report.StartTime, 0, 8);
			memset(&MreportCmd_p->MeasureRepSet[loop].Report.Duration, 0, 2);
			MreportCmd_p->MeasureRepSet[loop].Report.data.RPI[0] = 255;
			MreportCmd_p->MeasureRepSet[loop].Report.data.RPI[1] = 0;
			MreportCmd_p->MeasureRepSet[loop].Report.data.RPI[2] = 0;
			MreportCmd_p->MeasureRepSet[loop].Report.data.RPI[3] = 0;
			MreportCmd_p->MeasureRepSet[loop].Report.data.RPI[4] = 0;
			MreportCmd_p->MeasureRepSet[loop].Report.data.RPI[5] = 0;
			MreportCmd_p->MeasureRepSet[loop].Report.data.RPI[6] = 0;
			MreportCmd_p->MeasureRepSet[loop].Report.data.RPI[7] = 0;
			break;
		case TYPE_REQ_APS:
			MreportCmd_p->MeasureRepSet[loop].Report.Channel = vmacSta_p->JoinChannel;
			memset(&MreportCmd_p->MeasureRepSet[loop].Report.StartTime, 0, 8);
			memset(&MreportCmd_p->MeasureRepSet[loop].Report.Duration, 0, 2);
			wmonStart = 1;
			gScan = 1;
			InitiateAPScan(vmacSta_p);
			break;
		case TYPE_REQ_RSS:
			MreportCmd_p->MeasureRepSet[loop].Report.Channel = vmacSta_p->JoinChannel;
			memset(&MreportCmd_p->MeasureRepSet[loop].Report.StartTime, 0, 8);
			memset(&MreportCmd_p->MeasureRepSet[loop].Report.Duration, 0, 2);
			wmonStart = 1;
			g_wmon_rssi_count = 0;
			break;
		case TYPE_REQ_NOI:
			MreportCmd_p->MeasureRepSet[loop].Report.Channel = vmacSta_p->JoinChannel;
			memset(&MreportCmd_p->MeasureRepSet[loop].Report.StartTime, 0, 8);
			memset(&MreportCmd_p->MeasureRepSet[loop].Report.Duration, 0, 2);
			wmonStart = 1;
			break;
		case TYPE_REQ_FCS:
			MreportCmd_p->MeasureRepSet[loop].Report.Channel = vmacSta_p->JoinChannel;
			memset(&MreportCmd_p->MeasureRepSet[loop].Report.StartTime, 0, 8);
			memset(&MreportCmd_p->MeasureRepSet[loop].Report.Duration, 0, 2);
			//Reset the FCS counter
			Rx_Traffic_FCS_Cnt(staDev);
			wmonStart = 1;
			break;
		case TYPE_REQ_DFS:
			MreportCmd_p->MeasureRepSet[loop].Report.Channel = vmacSta_p->JoinChannel;
			memset(&MreportCmd_p->MeasureRepSet[loop].Report.StartTime, 0, 8);
			memset(&MreportCmd_p->MeasureRepSet[loop].Report.Duration, 0, 2);
			g_wmon_DFSLog[0] = '\0';
			wmonStart = 1;
			break;
		case TYPE_REQ_PSE:
			MreportCmd_p->MeasureRepSet[loop].Report.Channel = vmacSta_p->JoinChannel;
			memset(&MreportCmd_p->MeasureRepSet[loop].Report.StartTime, 0, 8);
			memset(&MreportCmd_p->MeasureRepSet[loop].Report.Duration, 0, 2);
			g_wmon_PSELog[0] = '\0';
			wmonStart = 1;
			break;
		case TYPE_REQ_VRX:
			MreportCmd_p->MeasureRepSet[loop].Report.Channel = vmacSta_p->JoinChannel;
			memset(&MreportCmd_p->MeasureRepSet[loop].Report.StartTime, 0, 8);
			memset(&MreportCmd_p->MeasureRepSet[loop].Report.Duration, 0, 2);
			g_wmon_videoTrafficRx = 0;
			wmonStart = 1;
			break;
		default:
			printk("Not yet implemented\n");
		}
	}

	if (wmonStart) {
		if (vmacSta_p->stationWMONTimerFired == 0) {
			vmacSta_p->stationWMONTimerFired = 1;
			TimerFireIn(&vmacSta_p->stationWMONTimer, 1, stationWMONTimerCB, (unsigned char *)MreportCmd_p, 60);
		}
	}

	wl_kfree(MreportCmd_p);
	return;
}

void InitiateAPScan(vmacStaInfo_t * vmacSta_p)
{
	UINT8 bcAddr1[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };	/* BROADCAST BSSID */
	UINT8 ieBuf[48];
	UINT16 ieBufLen = 0;
	IEEEtypes_InfoElementHdr_t *IE_p;
	vmacEntry_t *vmacEntry_p = NULL;
	struct net_device *staDev = NULL;
	struct wlprivate *stapriv = NULL;
	MIB_802DOT11 *mib = NULL;
	UINT8 mlmeAssociatedFlag;
	UINT8 mlmeBssid[6];
	UINT8 currChnlIndex = 0;
	UINT8 chnlListLen = 0;
	UINT8 chnlScanList[IEEEtypes_MAX_CHANNELS + IEEEtypes_MAX_CHANNELS_A];
	UINT8 i = 0;
	MIB_PHY_DSSS_TABLE *PhyDSSSTable;
#ifdef FCC_UNII_2_EXT_SUPPORT
	UINT8 mainChnlList[IEEEtypes_MAX_CHANNELS + IEEEtypes_MAX_CHANNELS_A] =
	    { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0, 0, 0, 36, 40, 44, 48, 52, 56, 60, 64,
		100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 149, 153, 157, 161, 165
	};
#else
	UINT8 mainChnlList[IEEEtypes_MAX_CHANNELS + IEEEtypes_MAX_CHANNELS_A] =
	    { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0, 0, 0, 36, 40, 44, 48, 52, 56, 60, 64, 149, 153, 157, 161, 165, 0, 0, 0, 0, 0, 0 };
#endif

	//vmacEntry_p = sme_GetParentVMacEntry(vmacSta_p->VMacEntry.phyHwMacIndx);
	vmacEntry_p = (vmacEntry_t *) vmacSta_p->vMacEntry_p;
	staDev = (struct net_device *)vmacEntry_p->privInfo_p;
	stapriv = NETDEV_PRIV_P(struct wlprivate, staDev);
	vmacApInfo_t *vmacAPSta_p = stapriv->vmacSta_p;
	mib = vmacAPSta_p->Mib802dot11;

	memset(&chnlScanList[0], 0, (IEEEtypes_MAX_CHANNELS + IEEEtypes_MAX_CHANNELS_A));

	PhyDSSSTable = mib->PhyDSSSTable;

	/* Stop Autochannel on AP first */
	StopAutoChannel(vmacAPSta_p);

	/* get range to scan */
	domainGetInfo(mainChnlList);

	if ((*(mib->mib_STAMode) == CLIENT_MODE_AUTO) || (*(mib->mib_STAMode) == CLIENT_MODE_N)) {
		for (i = 0; i < IEEEtypes_MAX_CHANNELS; i++) {
			if (mainChnlList[i] > 0) {
				chnlScanList[currChnlIndex] = mainChnlList[i];
				currChnlIndex++;
			}
		}

		for (i = 0; i < IEEEtypes_MAX_CHANNELS_A; i++) {
			if (mainChnlList[i + IEEEtypes_MAX_CHANNELS] > 0) {
				chnlScanList[currChnlIndex] = mainChnlList[i + IEEEtypes_MAX_CHANNELS];
				currChnlIndex++;
			}
		}
		chnlListLen = currChnlIndex;
	} else if (*(mib->mib_STAMode) == CLIENT_MODE_N_24) {
		for (i = 0; i < IEEEtypes_MAX_CHANNELS; i++) {
			chnlScanList[i] = mainChnlList[i];
		}
		chnlScanList[i] = 0;
		chnlListLen = IEEEtypes_MAX_CHANNELS;
	} else if (*(mib->mib_STAMode) == CLIENT_MODE_N_5) {
		for (i = 0; i < IEEEtypes_MAX_CHANNELS_A; i++) {
			chnlScanList[i] = mainChnlList[i + IEEEtypes_MAX_CHANNELS];
		}
		chnlScanList[i] = 0;
		chnlListLen = IEEEtypes_MAX_CHANNELS_A;
	}

	ieBufLen = 0;
	/* Build IE Buf */
	IE_p = (IEEEtypes_InfoElementHdr_t *) & ieBuf[ieBufLen];

	/* SSID element */
	/* For scan all SSIDs to be scanned */
	/* DS_PARAM_SET element */
	IE_p->ElementId = DS_PARAM_SET;
	IE_p->Len = chnlListLen;
	ieBufLen += sizeof(IEEEtypes_InfoElementHdr_t);
	memcpy((char *)&ieBuf[ieBufLen], &chnlScanList[0], chnlListLen);

	ieBufLen += IE_p->Len;
	IE_p = (IEEEtypes_InfoElementHdr_t *) & ieBuf[ieBufLen];

	if ((vmacEntry_p = sme_GetParentVMacEntry(vmacSta_p->VMacEntry.phyHwMacIndx)) == NULL) {
		return;
	}
	if (!smeGetStaLinkInfo(vmacEntry_p->id, &mlmeAssociatedFlag, &mlmeBssid[0])) {
		return;
	}

	/* Set a flag indicating usr initiated scan */
	vmacSta_p->gUserInitScan = TRUE;

	if (!mlmeAssociatedFlag && (staDev->flags & IFF_RUNNING)) {
		//printk("stopping BSS \n");
		linkMgtStop(vmacEntry_p->phyHwMacIndx);
		smeStopBss(vmacEntry_p->phyHwMacIndx);
	}

	if (smeSendScanRequest(0, 0, 3, 200, &bcAddr1[0], &ieBuf[0], ieBufLen) == MLME_SUCCESS) {
		/*set the busy scanning flag */
		vmacAPSta_p->busyScanning = 1;
		return;
	} else {
		/* Reset a flag indicating usr initiated scan */
		vmacSta_p->gUserInitScan = FALSE;
		return;
	}
}

void stationWMONTimerCB(void *data_p)
{
	//    vmacStaInfo_t *vStaInfo_p = (vmacStaInfo_t *)data_p ;
	vmacStaInfo_t *vStaInfo_p = NULL;
	UINT32 loop;

	if ((vStaInfo_p = (vmacStaInfo_t *) vmacGetVMacStaInfo(parentGetVMacId(0))) == NULL) {
		return;
	}
	//      vmacEntry_p = sme_GetParentVMacEntry(0);
	vmacEntry_t *vmacEntry_p = (vmacEntry_t *) vStaInfo_p->vMacEntry_p;
	struct net_device *staDev = (struct net_device *)vmacEntry_p->privInfo_p;
	IEEEtypes_MReportCmd_t *MreportCmd_p = (IEEEtypes_MReportCmd_t *) data_p;

	WLDBG_INFO(DBG_LEVEL_1, "enter stationWMONTimerCB timeout handler\n");
	vStaInfo_p->stationWMONTimerFired = 0;
	for (loop = 0; loop < MreportCmd_p->ReportItems; loop++) {
		switch (MreportCmd_p->MeasureRepSet[loop].Type) {
		case TYPE_REP_APS:
			WMONGetScanResult(vStaInfo_p, MreportCmd_p->MeasureRepSet[loop].Report.data.APS);
			gScan = 0;
			break;
		case TYPE_REP_DFS:
			strcpy(MreportCmd_p->MeasureRepSet[loop].Report.data.DFS, g_wmon_DFSLog);
			break;
		case TYPE_REP_PSE:
			strcpy(MreportCmd_p->MeasureRepSet[loop].Report.data.PSE, g_wmon_PSELog);
			break;
		case TYPE_REP_RSS:
			MreportCmd_p->MeasureRepSet[loop].Report.data.RSSI = WMONMedian(g_wmon_rssi, g_wmon_rssi_count);
			break;
		case TYPE_REP_NOI:
			break;
		case TYPE_REP_FCS:
			MreportCmd_p->MeasureRepSet[loop].Report.data.FCS = Rx_Traffic_FCS_Cnt(staDev);
			break;
		case TYPE_REP_VRX:
			MreportCmd_p->MeasureRepSet[loop].Report.data.VRX = g_wmon_videoTrafficRx;
			break;
		default:
			break;
		}
	}
	WLDBG_INFO(DBG_LEVEL_7, "NOW SEND MREPORT\n");
	macMgmtMlme_MReportReq(staDev, vmacEntry_p->vmacAddr, MreportCmd_p);
}

void WMONGetScanResult(vmacStaInfo_t * vStaInfo_p, char *APS)
{
	scanDescptHdr_t *curDescpt_p = NULL;
	IEEEtypes_SsIdElement_t *ssidIE_p;
	IEEEtypes_DsParamSet_t *dsPSetIE_p;
	IEEEtypes_SuppRatesElement_t *PeerSupportedRates_p = NULL;
	IEEEtypes_ExtSuppRatesElement_t *PeerExtSupportedRates_p = NULL;
	IEEEtypes_HT_Element_t *pHT = NULL;
	IEEEtypes_Add_HT_Element_t *pHTAdd = NULL;
	IEEEtypes_Generic_HT_Element_t *pHTGen = NULL;
	UINT32 LegacyRateBitMap = 0;
	IEEEtypes_RSN_IE_t *RSN_p = NULL;
	IEEEtypes_RSN_IE_WPA2_t *wpa2IE_p = NULL;
	UINT8 scannedChannel = 0;
	UINT16 parsedLen = 0;
	UINT8 scannedSSID[33];
	UINT8 i = 0;
	UINT8 mdcnt = 0;
	UINT8 apType[6];
	UINT8 encryptType[10];
	UINT32 len = 0;
	UINT8 *buf_p;
	UINT16 bufSize = MAX_SCAN_BUF_SIZE;
	UINT8 numDescpt = 0;
	UINT8 wmonNumScanDesc = 0;

	if (smeGetScanResults(0, &numDescpt, &bufSize, &buf_p) != MLME_SUCCESS) {
		APS[0] = '\0';
		return;
	}
	wmonNumScanDesc = numDescpt;

	for (i = 0; i < wmonNumScanDesc; i++) {
		curDescpt_p = (scanDescptHdr_t *) (buf_p + parsedLen);

		memset(&scannedSSID[0], 0, sizeof(scannedSSID));
		memset(&apType[0], 0, sizeof(apType));
		sprintf(&encryptType[0], "None");
		mdcnt = 0;
		scannedChannel = 0;

		if ((ssidIE_p = (IEEEtypes_SsIdElement_t *) smeParseIeType(SSID,
									   (((UINT8 *) curDescpt_p) + sizeof(scanDescptHdr_t)),
									   curDescpt_p->length + sizeof(curDescpt_p->length) -
									   sizeof(scanDescptHdr_t))) != NULL) {
			memcpy(&scannedSSID[0], &ssidIE_p->SsId[0], ssidIE_p->Len);
		}
		if ((dsPSetIE_p = (IEEEtypes_DsParamSet_t *) smeParseIeType(DS_PARAM_SET,
									    (((UINT8 *) curDescpt_p) + sizeof(scanDescptHdr_t)),
									    curDescpt_p->length + sizeof(curDescpt_p->length) -
									    sizeof(scanDescptHdr_t))) != NULL) {
			scannedChannel = dsPSetIE_p->CurrentChan;
		}

		if (curDescpt_p->CapInfo.Privacy)
			sprintf(&encryptType[0], "Wep");

		PeerSupportedRates_p = (IEEEtypes_SuppRatesElement_t *) smeParseIeType(SUPPORTED_RATES,
										       (((UINT8 *) curDescpt_p) + sizeof(scanDescptHdr_t)),
										       curDescpt_p->length + sizeof(curDescpt_p->length) -
										       sizeof(scanDescptHdr_t));

		PeerExtSupportedRates_p = (IEEEtypes_ExtSuppRatesElement_t *) smeParseIeType(EXT_SUPPORTED_RATES,
											     (((UINT8 *) curDescpt_p) + sizeof(scanDescptHdr_t)),
											     curDescpt_p->length + sizeof(curDescpt_p->length) -
											     sizeof(scanDescptHdr_t));

		LegacyRateBitMap = GetAssocRespLegacyRateBitMap(PeerSupportedRates_p, PeerExtSupportedRates_p);

		if (scannedChannel <= 14) {
			if (LegacyRateBitMap & 0x0f)
				sprintf(&apType[mdcnt++], "B");
			if (PeerSupportedRates_p && PeerExtSupportedRates_p)
				sprintf(&apType[mdcnt++], "G");
		} else {
			if (LegacyRateBitMap & 0x1fe0)
				sprintf(&apType[mdcnt++], "A");
		}

		pHT = (IEEEtypes_HT_Element_t *) smeParseIeType(HT,
								(((UINT8 *) curDescpt_p) + sizeof(scanDescptHdr_t)),
								curDescpt_p->length + sizeof(curDescpt_p->length) - sizeof(scanDescptHdr_t));

		pHTAdd = (IEEEtypes_Add_HT_Element_t *) smeParseIeType(ADD_HT,
								       (((UINT8 *) curDescpt_p) + sizeof(scanDescptHdr_t)),
								       curDescpt_p->length + sizeof(curDescpt_p->length) - sizeof(scanDescptHdr_t));
		// If cannot find HT element then look for High Throughput elements using PROPRIETARY_IE.
		if (pHT == NULL) {
			pHTGen = linkMgtParseHTGenIe((((UINT8 *) curDescpt_p) + sizeof(scanDescptHdr_t)),
						     curDescpt_p->length + sizeof(curDescpt_p->length) - sizeof(scanDescptHdr_t));
		}

		if ((RSN_p = linkMgtParseWpaIe((((UINT8 *) curDescpt_p) + sizeof(scanDescptHdr_t)),
					       curDescpt_p->length + sizeof(curDescpt_p->length) - sizeof(scanDescptHdr_t))))
			sprintf(&encryptType[0], "WPA");

		if ((wpa2IE_p = (IEEEtypes_RSN_IE_WPA2_t *) smeParseIeType(RSN_IEWPA2,
									   (((UINT8 *) curDescpt_p) + sizeof(scanDescptHdr_t)),
									   curDescpt_p->length + sizeof(curDescpt_p->length) -
									   sizeof(scanDescptHdr_t)))) {
			// RSN_AES_ID, RSN_TKIP_ID
			if ((wpa2IE_p->GrpKeyCipher[3] == RSN_TKIP_ID) && (wpa2IE_p->PwsKeyCipherList[3] == RSN_AES_ID))
				sprintf(&encryptType[0], "WPA-WPA2");
			else
				sprintf(&encryptType[0], "WPA2");
		}

		if (pHT || pHTGen) {
			sprintf(&apType[mdcnt++], "N");
		}

		parsedLen += curDescpt_p->length + sizeof(curDescpt_p->length);

		len += sprintf(APS + len, "#%d SSID=%-32s %02x:%02x:%02x:%02x:%02x:%02x %d -%d %s %s\n",
			       i + 1,
			       (const char *)&scannedSSID[0],
			       curDescpt_p->bssId[0],
			       curDescpt_p->bssId[1],
			       curDescpt_p->bssId[2],
			       curDescpt_p->bssId[3],
			       curDescpt_p->bssId[4], curDescpt_p->bssId[5], scannedChannel, curDescpt_p->rssi, apType, encryptType);
		if ((len + 80) >= (MAX_WMON_APS_SIZE - 20)) {
			return;
		}
	}
}

UINT32 WMONMedian(UINT32 * numbers, UINT32 number_count)
{
	int i = 0, j = 0, temp;
	UINT32 median = 0;
	UINT32 median1, median2;

	for (i = (number_count - 1); i >= 0; i--) {
		for (j = 1; j <= i; j++) {
			if (numbers[j - 1] > numbers[j]) {
				temp = numbers[j - 1];
				numbers[j - 1] = numbers[j];
				numbers[j] = temp;
			}
		}
	}
	if (number_count % 2) {
		// odd number
		median = numbers[(number_count / 2)];
	} else {
		median1 = numbers[(number_count / 2) - 1];
		median2 = numbers[(number_count / 2)];
		median = (median1 + median2) / 2;
	}
	return median;
}
#endif				//WMON
