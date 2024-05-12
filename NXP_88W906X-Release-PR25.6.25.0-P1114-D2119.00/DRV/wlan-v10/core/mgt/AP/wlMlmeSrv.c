/** @file wlMlmeSrv.c
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

/*!
* \file    wlMlmeSrv.c
* \brief   the implementation of state machine service routines
*/

#include "mlme.h"
#include "IEEE_types.h"
#include "mib.h"
#include "ds.h"
#include "osif.h"
#include "keyMgmtCommon.h"
#include "keyMgmt.h"

#include "wldebug.h"
#include "tkip.h"
#include "StaDb.h"
#include "macmgmtap.h"
#include "qos.h"
#include "macMgmtMlme.h"
#ifdef CFG80211
#include "cfg80211.h"
#endif

extern SINT32 mlmeAuthDoOpenSys(vmacApInfo_t * vmacSta_p, AuthRspSrvApMsg * authRspMsg_p);
extern SINT32 mlmeAuthDoSharedKeySeq1(vmacApInfo_t * vmacSta_p, AuthRspSrvApMsg * authRspMsg_p);
extern SINT32 mlmeAuthDoSharedKeySeq3(vmacApInfo_t * vmacSta_p, AuthRspSrvApMsg * authRspMsg_p);
extern void macMgmtMlme_ChannelSwitchReq(vmacApInfo_t * vmacSta_p, Dfs_ChanSwitchReq_t * ChannelSwitchtCmd_p);
extern void macMgmtMlme_MReportReq(vmacApInfo_t * vmacSta_p, IEEEtypes_MReportCmd_t * MreportCmd_p);
extern void macMgmtMlme_MRequestReq(vmacApInfo_t * vmacSta_p, IEEEtypes_MRequestCmd_t * MrequestCmd_p);
extern void syncSrv_ScanCmd(vmacApInfo_t * vmacSta_p, IEEEtypes_ScanCmd_t * ScanCmd_p);
extern void mlmeAuthError(vmacApInfo_t * vmacSta_p, IEEEtypes_StatusCode_t statusCode, UINT16 arAlg_in, UINT8 * Addr);
extern void macMgmtRemoveSta(vmacApInfo_t * vmacSta_p, extStaDb_StaInfo_t * StaInfo_p);
/*!
* association serveice timeout handler 
*  
* @param data_p Pointer to user defined data
* @return MLME_SUCCESS, MLME_INPROCESS, MLME_FAIL
*/
int wl_MacMlme_AssocSrvTimeout(void *data_p)
{
	/*    extStaDb_StaInfo_t *StaInfo_p = (extStaDb_StaInfo_t*)data_p; */
	/*    StaInfo_p->State = AUTHENTICATED; */
	return (MLME_SUCCESS);
}

/*!
* received association request service routine 
*  
* @param data_p Pointer to user defined data
* @return MLME_SUCCESS, MLME_INPROCESS, MLME_FAIL
*/
int wl_MacMlme_AssocReq(vmacApInfo_t * vmacSta_p, void *data_p, UINT32 msgSize)
{
	macmgmtQ_MgmtMsg_t *MgmtMsg_p = (macmgmtQ_MgmtMsg_t *) data_p;
	macMgmtMlme_AssociateReq(vmacSta_p, (macmgmtQ_MgmtMsg3_t *) MgmtMsg_p, msgSize);
	return (MLME_SUCCESS);
}

/*!
* received re-association request service routine 
*  
* @param data_p Pointer to user defined data
* @return MLME_SUCCESS, MLME_INPROCESS, MLME_FAIL
*/
int wl_MacMlme_ReAssocReq(vmacApInfo_t * vmacSta_p, void *data_p, UINT32 msgSize)
{
	macmgmtQ_MgmtMsg_t *MgmtMsg_p = (macmgmtQ_MgmtMsg_t *) data_p;
	macMgmtMlme_ReassociateReq(vmacSta_p, (macmgmtQ_MgmtMsg3_t *) MgmtMsg_p, msgSize);
	return (MLME_SUCCESS);
}

/*!
* received dis-association request service routine 
*  
* @param data_p Pointer to user defined data
* @return MLME_SUCCESS, MLME_INPROCESS, MLME_FAIL
*/
int wl_MacMlme_DisAssocReq(vmacApInfo_t * vmacSta_p, void *data_p, UINT32 msgSize)
{
	macmgmtQ_MgmtMsg_t *MgmtMsg_p = (macmgmtQ_MgmtMsg_t *) data_p;
	macMgmtMlme_DisassociateMsg(vmacSta_p, (macmgmtQ_MgmtMsg3_t *) MgmtMsg_p, msgSize);
	return (MLME_SUCCESS);
}

/*!
* ds response 
*  
* @param data_p Pointer to user defined data
* @return MLME_SUCCESS, MLME_INPROCESS, MLME_FAIL
*/
int wl_MacMlme_DsResponse(void *data_p)
{
	/*    macmgmtQ_MgmtMsg_t *MgmtMsg_p = (macmgmtQ_MgmtMsg_t *)data_p; */
	return (MLME_SUCCESS);
}

/*!
* disassociation command service routine 
*  
* @param data_p Pointer to user defined data
* @return MLME_SUCCESS, MLME_INPROCESS, MLME_FAIL
*/
int wl_MacMlme_DisAssocCmd(vmacApInfo_t * vmacSta_p, void *data_p)
{
	IEEEtypes_DisassocCmd_t *DisassocCmd_p = (IEEEtypes_DisassocCmd_t *) data_p;
	macMgmtMlme_DisassociateCmd(vmacSta_p, DisassocCmd_p);
	return (MLME_SUCCESS);
}

/*!
* received authenticate request service routine 
*  
* @param data_p Pointer to user defined data
* @return MLME_SUCCESS, MLME_INPROCESS, MLME_FAIL
*/
int wl_MacMlme_AuthReq(void *data_p)
{
	return (MLME_SUCCESS);
}

/*!
* received authenticate sequence even service routine 
*  
* @param data_p Pointer to user defined data
* @return MLME_SUCCESS, MLME_INPROCESS, MLME_FAIL
*/
int wl_MacMlme_AuthEven(vmacApInfo_t * vmacSta_p, void *data_p)
{
	AuthRspSrvApMsg *authRspMsg_p = (AuthRspSrvApMsg *) data_p;
	int share_key = 1;
	if (share_key) {
		/*mlmeAuthDoSharedKey(authRspMsg_p); */
		return (MLME_INPROCESS);
	} else {
		mlmeAuthDoOpenSys(vmacSta_p, authRspMsg_p);
	}
	return (MLME_SUCCESS);
}

/*!
* received authenticate sequence 1 service routine 
*  
* @param data_p Pointer to user defined data
* @return MLME_SUCCESS, MLME_INPROCESS, MLME_FAIL
*/
int wl_MacMlme_AuthOdd1(vmacApInfo_t * vmacSta_p, void *data_p)
{
	AuthRspSrvApMsg *authRspMsg = (AuthRspSrvApMsg *) data_p;
#ifdef MRVL_80211R
	extStaDb_StaInfo_t *StaInfo_p;
	static const char tag_auth[] = "mlme-auth";
	UINT8 len, *msg = (UINT8 *) authRspMsg->mgtMsg;
	union iwreq_data wreq;
#endif
	MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
	if (extStaDb_entries(vmacSta_p, 0) + 1 > *(mib->mib_maxsta)) {
		if ((StaInfo_p = extStaDb_GetStaInfo(vmacSta_p, (IEEEtypes_MacAddr_t *) authRspMsg->rspMac, STADB_UPDATE_AGINGTIME)) == NULL) {
			macmgmtQ_MgmtMsg3_t *MgmtMsg_p;
			WLDBG_INFO(DBG_LEVEL_4, "wl_MacMlme_AuthOdd1:: max sta has been reached \n");
			MgmtMsg_p = (macmgmtQ_MgmtMsg3_t *) authRspMsg->mgtMsg;
			mlmeAuthError(vmacSta_p, IEEEtypes_STATUS_ASSOC_DENIED_BUSY, authRspMsg->arAlg, (UINT8 *) & MgmtMsg_p->Hdr.SrcAddr);
			return (MLME_FAILURE);
		}
		WLDBG_INFO(DBG_LEVEL_4, "%s: max sta has been reached, delete STA in StaDb, continue Auth\n", __func__);
		macMgmtRemoveSta(vmacSta_p, StaInfo_p);
	}
#ifdef MULTI_AP_SUPPORT
	{
		macmgmtQ_MgmtMsg3_t *MgmtMsg_p;
		MgmtMsg_p = (macmgmtQ_MgmtMsg3_t *) authRspMsg->mgtMsg;
		if (isMacAccessList(vmacSta_p, &(MgmtMsg_p->Hdr.SrcAddr)) != SUCCESS) {
			WLDBG_INFO(DBG_LEVEL_4, "wl_MacMlme_AuthOdd1:: SrcAddr not in access list\n");
			mlmeAuthError(vmacSta_p, IEEEtypes_STATUS_UNSPEC_FAILURE, authRspMsg->arAlg, (UINT8 *) & MgmtMsg_p->Hdr.SrcAddr);
			return (MLME_FAILURE);
		}
	}
#endif				/* MULTI_AP_SUPPORT */

	if (authRspMsg->arAlg_in == shared_key && authRspMsg->arAlg == shared_key) {
		WLDBG_INFO(DBG_LEVEL_4, "wl_MacMlme_AuthOdd1:: mlmeAuthDoSharedKeySeq1 \n");
		if (mlmeAuthDoSharedKeySeq1(vmacSta_p, authRspMsg) == MLME_SUCCESS) {
			return (MLME_INPROCESS);
		} else {
			return (MLME_FAILURE);
		}
	} else if (authRspMsg->arAlg_in == open_system && authRspMsg->arAlg == open_system) {
		WLDBG_INFO(DBG_LEVEL_4, "wl_MacMlme_AuthOdd1:: mlmeAuthDoOpenSys \n");
		mlmeAuthDoOpenSys(vmacSta_p, authRspMsg);
	}
#ifdef MRVL_80211R
	else if (authRspMsg->arAlg_in == 2) {
		UINT8 *buf = NULL;
		int buf_len = 1024;
#ifdef CFG80211
		macmgmtQ_MgmtMsg3_t *MgmtMsg_p = NULL;
#endif				/* CFG80211 */
		if ((StaInfo_p = extStaDb_GetStaInfo(vmacSta_p, (IEEEtypes_MacAddr_t *) authRspMsg->rspMac, STADB_UPDATE_AGINGTIME)) == NULL) {
			return (MLME_FAILURE);
		}

		buf = wl_kzalloc(buf_len, GFP_ATOMIC);
		if (!buf)
			return (MLME_FAILURE);

		if (StaInfo_p->State != ASSOCIATED)
			StaInfo_p->State = AUTHENTICATED;
		len = *(UINT16 *) msg;
		len -= 6;
		*(UINT16 *) msg = len;
		memcpy(buf, tag_auth, strlen(tag_auth));
		memcpy(&buf[strlen(tag_auth)], msg, 26);
		memcpy(&buf[strlen(tag_auth) + 26], msg + 32, len + 2 - 26);
		memset(&wreq, 0, sizeof(wreq));
		wreq.data.length = strlen(tag_auth) + len + sizeof(UINT16);
		if (vmacSta_p->dev->flags & IFF_RUNNING)
			wireless_send_event(vmacSta_p->dev, IWEVCUSTOM, &wreq, buf);
#ifdef CFG80211
		MgmtMsg_p = (macmgmtQ_MgmtMsg3_t *) (buf + strlen(tag_auth));
		mwl_cfg80211_rx_mgmt(vmacSta_p->dev, ((UINT8 *) MgmtMsg_p) + 2, MgmtMsg_p->Hdr.FrmBodyLen, 0);
#endif				/* CFG80211 */
		wl_kfree(buf);
	}
#endif
	else {
		macmgmtQ_MgmtMsg3_t *MgmtMsg_p;
		WLDBG_INFO(DBG_LEVEL_4, "wl_MacMlme_AuthOdd1:: unsupported authalg \n");
		MgmtMsg_p = (macmgmtQ_MgmtMsg3_t *) authRspMsg->mgtMsg;
		mlmeAuthError(vmacSta_p, IEEEtypes_STATUS_UNSUPPORTED_AUTHALG, authRspMsg->arAlg, (UINT8 *) & MgmtMsg_p->Hdr.SrcAddr);
		return (MLME_FAILURE);
	}

	return (MLME_SUCCESS);
}

/*!
* received authenticate sequence 3 service routine 
*  
* @param data_p Pointer to user defined data
* @return MLME_SUCCESS, MLME_INPROCESS, MLME_FAIL
*/
int wl_MacMlme_AuthOdd3(vmacApInfo_t * vmacSta_p, void *data_p)
{
	AuthRspSrvApMsg *authRspMsg = (AuthRspSrvApMsg *) data_p;

#ifdef MULTI_AP_SUPPORT
	macmgmtQ_MgmtMsg3_t *MgmtMsg_p;
	MgmtMsg_p = (macmgmtQ_MgmtMsg3_t *) authRspMsg->mgtMsg;
	if (isMacAccessList(vmacSta_p, &(MgmtMsg_p->Hdr.SrcAddr)) != SUCCESS) {
		WLDBG_INFO(DBG_LEVEL_4, "wl_MacMlme_AuthOdd3:: SrcAddr not in access list\n");
		mlmeAuthError(vmacSta_p, IEEEtypes_STATUS_UNSPEC_FAILURE, authRspMsg->arAlg, (UINT8 *) & MgmtMsg_p->Hdr.SrcAddr);
		return (MLME_FAILURE);
	}
#endif				/* MULTI_AP_SUPPORT */

	return (mlmeAuthDoSharedKeySeq3(vmacSta_p, authRspMsg));
}

/*!
* received deauthentication service routine 
*  
* @param data_p Pointer to user defined data
* @return MLME_SUCCESS, MLME_INPROCESS, MLME_FAIL
*/
int wl_MacMlme_DeAuth(vmacApInfo_t * vmacSta_p, void *data_p, UINT32 msgSize)
{
	macmgmtQ_MgmtMsg_t *MgmtMsg_p = (macmgmtQ_MgmtMsg_t *) data_p;
	macMgmtMlme_DeauthenticateMsg(vmacSta_p, (macmgmtQ_MgmtMsg3_t *) MgmtMsg_p, msgSize);
	return (MLME_SUCCESS);
}

/*!
* authenticate service timeout handler 
*  
* @param data_p Pointer to user defined data
* @return MLME_SUCCESS, MLME_INPROCESS, MLME_FAIL
*/
int wl_MacMlme_AuthSrvTimeout(void *data_p)
{
	extStaDb_StaInfo_t *StaInfo_p = (extStaDb_StaInfo_t *) data_p;
	StaInfo_p->State = UNAUTHENTICATED;
	return (MLME_SUCCESS);
}

/*!
* reset command service routine 
*  
* @param data_p Pointer to user defined data
* @return MLME_SUCCESS, MLME_INPROCESS, MLME_FAIL
*/
int wl_MacMlme_ResetCmd(vmacApInfo_t * vmacSta_p, void *data_p)
{
	SyncSrvApMsg *syncMsg = (SyncSrvApMsg *) data_p;
	macMgmtMlme_ResetCmd(vmacSta_p, (IEEEtypes_ResetCmd_t *) syncMsg->mgtMsg);
	return (MLME_SUCCESS);
}

/*!
* synchronization service timeout handler 
*  
* @param data_p Pointer to user defined data
* @return MLME_SUCCESS, MLME_INPROCESS, MLME_FAIL
*/
int wl_MacMlme_SyncSrvTimeout(void *data_p)
{
	return (MLME_SUCCESS);
}

/*!
* start command service routine 
*  
* @param data_p Pointer to user defined data
* @return MLME_SUCCESS, MLME_INPROCESS, MLME_FAIL
*/
int wl_MacMlme_StartCmd(vmacApInfo_t * vmacSta_p, void *data_p)
{
	SyncSrvApMsg *syncMsg = (SyncSrvApMsg *) data_p;
	macMgmtMlme_StartCmd(vmacSta_p, (IEEEtypes_StartCmd_t *) syncMsg->mgtMsg);
	return (MLME_SUCCESS);
}

/*!
* received probe request service routine 
*  
* @param data_p Pointer to user defined data
* @return MLME_SUCCESS, MLME_INPROCESS, MLME_FAIL
*/
int wl_MacMlme_ProbeReq(vmacApInfo_t * vmacSta_p, void *data_p)
{
	SyncSrvApMsg *syncMsg = (SyncSrvApMsg *) data_p;
	macMgmtMlme_ProbeRqst(vmacSta_p, (macmgmtQ_MgmtMsg3_t *) syncMsg->mgtMsg);
	return (MLME_SUCCESS);
}

#if defined(AP_SITE_SURVEY) || defined(AUTOCHANNEL)
/********************* Added for Site Survey on AP *******************************/
/*!
* Scan Request for Site Survey 
*  
* @param data_p Pointer to user defined data
* @return MLME_SUCCESS, MLME_INPROCESS, MLME_FAIL
*/
int wl_MacMlme_ScanReq(vmacApInfo_t * vmacSta_p, void *data_p)
{
	SyncSrvApMsg *syncMsg = (SyncSrvApMsg *) data_p;
	syncSrv_ScanCmd(vmacSta_p, (IEEEtypes_ScanCmd_t *) syncMsg->mgtMsg);
	return (MLME_SUCCESS);
}
#endif				/* AP_SITE_SURVEY */

#ifdef IEEE80211H
/********************* Support IEEE 802.11h *******************************/
/*!
* MREQUEST Request 
*  
* @param data_p Pointer to user defined data
* @return MLME_SUCCESS, MLME_INPROCESS, MLME_FAIL
*/
int wl_MacMlme_MRequestReq(vmacApInfo_t * vmacSta_p, void *data_p)
{
	SyncSrvApMsg *syncMsg = (SyncSrvApMsg *) data_p;
	macMgmtMlme_MRequestReq(vmacSta_p, (IEEEtypes_MRequestCmd_t *) syncMsg->mgtMsg);
	return (MLME_SUCCESS);
}

/*!
* MREPORT Request 
*  
* @param data_p Pointer to user defined data
* @return MLME_SUCCESS, MLME_INPROCESS, MLME_FAIL
*/
int wl_MacMlme_MReportReq(vmacApInfo_t * vmacSta_p, void *data_p)
{
	SyncSrvApMsg *syncMsg = (SyncSrvApMsg *) data_p;
	macMgmtMlme_MReportReq(vmacSta_p, (IEEEtypes_MReportCmd_t *) syncMsg->mgtMsg);
	return (MLME_SUCCESS);
}

/*!
* CHANNELSWITCH Request 
*  
* @param data_p Pointer to user defined data
* @return MLME_SUCCESS, MLME_INPROCESS, MLME_FAIL
*/
int wl_MacMlme_ChannelswitchReq(vmacApInfo_t * vmacSta_p, void *data_p)
{
	SyncSrvApMsg *syncMsg = (SyncSrvApMsg *) data_p;
	macMgmtMlme_ChannelSwitchReq(vmacSta_p, (Dfs_ChanSwitchReq_t *) syncMsg->mgtMsg);
	return (MLME_SUCCESS);
}
#endif				/* IEEE80211H */
#ifdef APCFGUR
int RmSrv_Timeout(UINT8 * data_p, UINT32 ptr)
{
	UINT8 *data;
	extStaDb_StaInfo_t *StaInfo_p = (extStaDb_StaInfo_t *) data_p;
	data = (UINT8 *) ptr;
	SendApiDataTo(&StaInfo_p->Addr, data);
	return (MLME_SUCCESS);
}
#endif
