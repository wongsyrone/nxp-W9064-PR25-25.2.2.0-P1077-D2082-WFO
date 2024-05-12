/** @file dfsSM.c
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2002-2021 NXP
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
* Description:  Implementation of the AP's DFS service 
*
*/
#ifdef MRVL_DFS

#include <linux/netdevice.h>
#include "mhsm.h"
#include "wltypes.h"
#include "wldebug.h"
#include "IEEE_types.h"
#include "ieeetypescommon.h"
#include "macmgmtap.h"
#include "macMgmtMlme.h"
#include "hostcmd.h"
#include "domain.h"
#include "timer.h"
#include "List.h"
#include "dfs.h"
#include "ap8xLnxIntf.h"

#define DFS_DEFAULT_CSAMODE 			1
#define DFS_DEFAULT_COUNTDOWN_NUMBER	20
#ifdef BARBADOS_DFS_TEST
extern UINT8 dfs_sim_evt;
extern BOOLEAN bForceToNonMonitorMode;
extern BOOLEAN dfs_clear_nol;
#endif
extern UINT8 dfs_test_mode;

extern void ListPutItemFILO(List * me, ListItem * Item);
extern int wlFwSetIEs(struct net_device *netdev);
UINT16 getCacTimerValue(UINT16 regionCode, UINT16 cacTimeout, UINT16 etsiTimeout, CHNL_FLAGS * pChanflag, UINT8 channel, UINT8 channel2);
void CACTimeoutHandler(void *data_p);
void CSATimeoutHandler(void *data_p);
static void NOCTimeoutHandler(void *data_p);
UINT8 DfsDetected80MhzGrpChan[4];
UINT8 DfsDetected160MhzGrpChan[8];
UINT8 NOLchannelList[DFS_MAX_CHANNELS];
UINT8 Grp80MhzNOLchanList[DFS_MAX_CHANNELS];
UINT8 Grp160MhzNOLchanList[DFS_MAX_CHANNELS];

#ifdef RADAR_SCANNER_SUPPORT
void set_dfs_status(DfsAp * dfs_ap, DFS_STATE state)
{
	if (dfs_ap->dfsApDesc.currState != state) {
		custom_tlv_t *tlv_buf;
		wlmgr_event_t *event_data;

		tlv_buf = (custom_tlv_t *) wl_kzalloc(IW_CUSTOM_MAX, GFP_ATOMIC);
		if (tlv_buf) {
			tlv_buf->tag = EVENT_TAG_WLMGR;
			event_data = (wlmgr_event_t *) tlv_buf->value;
			event_data->id = WLMGR_ID_COMMON;
			event_data->cmd = WLMGR_CMD_DEV_DFS;
			event_data->data[0] = state;
			tlv_buf->len = sizeof(wlmgr_event_t) + sizeof(UINT32) * 1;
			wl_send_event(dfs_ap->pNetDev, tlv_buf, TRUE, FALSE);
			wl_kfree(tlv_buf);
		}
	}
	dfs_ap->dfsApDesc.currState = state;
	return;
}

BOOLEAN cac_not_required(DfsChanInfo * chan_info)
{
	return chan_info->no_cac;
}

BOOLEAN do_csa(DfsChanInfo * chan_info)
{
	return chan_info->do_csa;
}

BOOLEAN have_dfs_scnr(struct wlprivate * wlpptr)
{
	return wlpptr->wlpd_p->ext_scnr_en;
}

#if 0
/* Below are for test purpose, 
     Real scanner CAC status should be maintained by MDE
*/
int scanner_subch_cac_done()
{
	extern int scnr_subch_cac_state;
	return scnr_subch_cac_state;
}

/* subch is maintained by MDE, TBD for how to get subch on AP side */
int get_scanner_subch()
{
	extern int scnr_subch;
	return scnr_subch;
}

/* CSA is required or not before quick switching to subch */
int need_csa()
{
	extern int do_csa;
	return do_csa;
}
#endif
#endif

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
MhsmEvent_t const *DfsAp_top(DfsAp * me, MhsmEvent_t * msg)
{
	PRINT1(INFO, "DfsAp_top:: Enter\n");

	if ((me == NULL) || (msg == NULL)) {
		PRINT1(INFO, "DfsAp_top:: error: NULL pointer\n");
		return 0;
	}

	switch (msg->event) {
	case MHSM_ENTER:
		mhsm_transition(&me->super, &me->Dfs_Ap);
		return 0;
	default:
		return msg;
	}
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
MhsmEvent_t const *Dfs_Ap_Handle(DfsAp * me, MhsmEvent_t * msg)
{
	PRINT1(INFO, "Dfs_Ap_Handle:: Enter\n");

	if ((me == NULL) || (msg == NULL)) {
		PRINT1(INFO, "Dfs_Ap_Handle:: error: NULL pointer\n");
		return 0;
	}

	switch (msg->event) {
	case MHSM_ENTER:
		mhsm_transition(&me->super, &me->Dfs_Init);
		return 0;
	default:
		return msg;
	}
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
MhsmEvent_t const *Dfs_Init_Handle(DfsAp * me, MhsmEvent_t * msg)
{
	DfsApMsg *dfsMsg_p = NULL;
	DfsApDesc *dfsDesc_p = NULL;
	struct net_device *dev = NULL;
	struct wlprivate *wlpptr = NULL;
	vmacApInfo_t *vmacSta_p = NULL;
	MIB_802DOT11 *mib = NULL;
	UINT16 mib_CACTimeOut = 0;

	PRINT1(INFO, "Dfs_Init_Handle:: Enter :%d\n", msg->event);

	if ((me == NULL) || (msg == NULL)) {
		PRINT1(INFO, "Dfs_Init_Handle:: error: NULL pointer\n");
		return 0;
	}
	dfsMsg_p = (DfsApMsg *) msg->pBody;
	dfsDesc_p = (DfsApDesc *) & me->dfsApDesc;
	dev = me->pNetDev;
	wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
	vmacSta_p = (vmacApInfo_t *) wlpptr->vmacSta_p;
	mib = vmacSta_p->Mib802dot11;

	switch (msg->event) {
	case MHSM_ENTER:
		set_dfs_status(me, DFS_STATE_INIT);
		dfsTrace(dev, DFS_STATE_INIT, (MHSM_ENTER & 0xf), &dfsDesc_p->currChanInfo, 0);
		return 0;
	case CHANNEL_CHANGE_EVT:
		{
			DfsChanInfo *chanInfo_p = (DfsChanInfo *) dfsMsg_p->mgtMsg;
			PRINT1(INFO, "Dfs_Init_Handle:: event-> CHANNEL_CHANGE_EVT\n");

			if (chanInfo_p == NULL) {
				dfsTrace(dev, DFS_STATE_INIT, CHANNEL_CHANGE_EVT, &dfsDesc_p->currChanInfo, 0);
				return 0;
			}
			memcpy(&dfsDesc_p->currChanInfo, chanInfo_p, sizeof(DfsChanInfo));
			/* First check if the given channel is within DFS range */
#ifdef CONCURRENT_DFS_SUPPORT
			if (DfsEnabledChannel(me->pNetDev, &dfsDesc_p->currChanInfo) && !cac_not_required(&dfsDesc_p->currChanInfo)) {
#else
			if (DfsEnabledChannel(me->pNetDev, &dfsDesc_p->currChanInfo)) {
#endif

				dfsTrace(dev, DFS_STATE_INIT, CHANNEL_CHANGE_EVT, &dfsDesc_p->currChanInfo, 0x10000000);
				mib_CACTimeOut = getCacTimerValue(*(mib->mib_regionCode), *(mib->mib_CACTimeOut), *(mib->mib_ETSICACTimeOut),
								  &mib->PhyDSSSTable->Chanflag, dfsDesc_p->currChanInfo.channel,
								  dfsDesc_p->currChanInfo.channel2);
				if (mib_CACTimeOut != 0) {
					DfsSetCACTimeOut(me, mib_CACTimeOut);
				}
				/* Start DFS radar SCAN */
				FireCACTimer(me);
				/* Stop data traffic */
				macMgmtMlme_StopDataTraffic(dev);
				/*Initiate Quiet mode radar detection */
#ifdef SOC_W906X
				mib->PhyDSSSTable->Chanflag.isDfsChan = dfsDesc_p->currChanInfo.chanflag.isDfsChan;
				mib->PhyDSSSTable->Chanflag.isDfsChan2 = dfsDesc_p->currChanInfo.chanflag.isDfsChan2;
#endif
				macMgmtMlme_StartRadarDetection(dev, DFS_QUIET_MODE);
				mhsm_transition(&me->super, &me->Dfs_Scan);
			} else {

				dfsTrace(dev, DFS_STATE_INIT, CHANNEL_CHANGE_EVT, &dfsDesc_p->currChanInfo, 0x11000000);

				WLDBG_INFO(DBG_LEVEL_1, "Dfs_Init_Handle  Become Operational \n");
				/* Switch off radar detection */
				macMgmtMlme_StopRadarDetection(dev, DFS_NORMAL_MODE);
				/* Become operational */
				mhsm_transition(&me->super, &me->Dfs_Operational);
			}
			return 0;
		}
	default:
		return 0;
	}
	return msg;
}

UINT8 useEtsiTimerValue(CHNL_FLAGS * pChanflag, UINT8 channel, UINT8 channel2)
{
#if 0
	if ((((pChanflag->ChnlWidth == CH_160_MHz_WIDTH) || (pChanflag->ChnlWidth == CH_AUTO_WIDTH)) && (channel >= 100 && channel <= 128)) ||
	    ((pChanflag->ChnlWidth == CH_80_MHz_WIDTH) && (channel >= 116 && channel <= 128)) ||
	    ((pChanflag->ChnlWidth == CH_40_MHz_WIDTH) && (channel >= 116 && channel <= 128)) ||
	    ((pChanflag->ChnlWidth == CH_20_MHz_WIDTH) && (channel >= 120 && channel <= 128)))
		return TRUE;
#else
	if (pChanflag->radiomode == RADIO_MODE_80p80) {
		if ((channel >= 116 && channel <= 128) || (channel2 >= 116 && channel2 <= 128))
			return TRUE;
	} else if (((pChanflag->ChnlWidth == CH_160_MHz_WIDTH) || (pChanflag->ChnlWidth == CH_AUTO_WIDTH)) && (channel >= 100 && channel <= 128))
		return TRUE;
	else if ((pChanflag->ChnlWidth == CH_80_MHz_WIDTH) && (channel >= 116 && channel <= 128))
		return TRUE;
	else if ((pChanflag->ChnlWidth == CH_40_MHz_WIDTH) && (channel >= 116 && channel <= 128))
		return TRUE;
	else if ((pChanflag->ChnlWidth == CH_20_MHz_WIDTH) && (channel >= 120 && channel <= 128))
		return TRUE;
#endif
	return FALSE;
}

UINT16 getCacTimerValue(UINT16 regionCode, UINT16 cacTimeout, UINT16 etsiTimeout, CHNL_FLAGS * pChanflag, UINT8 channel, UINT8 channel2)
{
	if (domainGetRegulatory(regionCode) == DOMAIN_CODE_ETSI) {
		if (useEtsiTimerValue(pChanflag, channel, channel2)) {
			return etsiTimeout;	// default 600 seconds
		} else {
			return cacTimeout;	// default 60 seconds
		}
	} else {
		return cacTimeout;	// default 60 seconds
	}
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
UINT32 dfs_updateNOL(DfsApDesc * dfsDesc_p)
{
#ifdef CONCURRENT_DFS_SUPPORT
	if (dfsDesc_p->currChanInfo.chanflag.ChnlWidth == CH_160_MHz_WIDTH) {
		if (UpdateNOL(dfsDesc_p, DFS_MAIN) == DFS_FAILURE) {
			return DFS_FAILURE;
		}
	} else {
		if (UpdateNOL(dfsDesc_p, dfsDesc_p->currChanInfo.from) == DFS_FAILURE) {
			return DFS_FAILURE;
		}
	}
#else
	if (UpdateNOL(dfsDesc_p) == DFS_FAILURE) {
		return DFS_FAILURE;
	}
#endif				/* CONCURRENT_DFS_SUPPORT */
	return DFS_SUCCESS;
}

MhsmEvent_t const *Dfs_Scan_Handle(DfsAp * me, MhsmEvent_t * msg)
{
	UINT8 channel;
	DfsApMsg *dfsMsg_p = NULL;
	DfsApDesc *dfsDesc_p = NULL;
	DfsChanInfo *chanInfo_p;
	struct net_device *dev = NULL;
	struct wlprivate *wlpptr = NULL;
	vmacApInfo_t *vmacSta_p = NULL;
	MIB_802DOT11 *mib;
	MIB_802DOT11 *mib_shadow;
	CHNL_FLAGS *pChanflag;
	UINT16 mib_CACTimeOut = 0;

	PRINT1(INFO, "Dfs_Scan_Handle:: Enter :%d\n", msg->event);

	if ((me == NULL) || (msg == NULL)) {
		PRINT1(INFO, "Dfs_Scan_Handle:: error: NULL pointer\n");
		return 0;
	}
	dev = me->pNetDev;
	wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
	vmacSta_p = (vmacApInfo_t *) wlpptr->vmacSta_p;
	mib = vmacSta_p->Mib802dot11;
	pChanflag = &mib->PhyDSSSTable->Chanflag;
	mib_shadow = vmacSta_p->ShadowMib802dot11;
	dfsMsg_p = (DfsApMsg *) msg->pBody;
	dfsDesc_p = (DfsApDesc *) & me->dfsApDesc;
	dfsDesc_p->me = (void *)me;

	switch (msg->event) {
	case MHSM_ENTER:
		set_dfs_status(me, DFS_STATE_SCAN);
		dfsDesc_p->cac_complete = 0;
		dfsDesc_p->vapcount = 0;
		dfsTrace(dev, DFS_STATE_SCAN, (MHSM_ENTER & 0xf), &dfsDesc_p->currChanInfo, 0x10000000);
		return 0;
	case RADAR_EVT:
		PRINT1(INFO, "Dfs_Scan_Handle:: event-> RADAR_EVT\n");

		dfsDesc_p->cac_complete = 0;
		dfsDesc_p->vapcount = 0;
		chanInfo_p = (DfsChanInfo *) dfsMsg_p->mgtMsg;
		dfsDesc_p->currChanInfo.from = chanInfo_p->from;

		/* Stops CAC timer */
#ifdef 	BARBADOS_DFS_TEST
		if (!dfs_test)
			DisarmCACTimer(me);

		/* Updated NOL */
		if (!dfs_probability) {
			if (dfs_monitor)
				return 0;

			if (dfs_updateNOL(dfsDesc_p) == DFS_FAILURE) {
				dfsTrace(dev, DFS_STATE_SCAN, RADAR_EVT, &dfsDesc_p->currChanInfo, 0x12000000);
				return 0;
			}
		}
#else
		if (!dfs_test_mode) {
			/* For W8764 DFS test mode do not enable CAC timer and do not add channel to NOL. */
			DisarmCACTimer(me);
			/* Updated NOL */
			DfsAddToNOL(dfsDesc_p, dfsDesc_p->currChanInfo.channel, &dfsDesc_p->currChanInfo.chanflag);
		}
#endif

#ifdef RADAR_SCANNER_SUPPORT
		if (have_dfs_scnr(wlpptr)) {
			dfsTrace(dev, DFS_STATE_SCAN, RADAR_EVT, &dfsDesc_p->currChanInfo, 0x20000000);
			macMgmtMlme_StopRadarDetection(dev, DFS_NORMAL_MODE);
#ifdef CONCURRENT_DFS_SUPPORT
			me->scnr_ctl_evt(dev, ScnrCtl_Radar_Detected, DFS_STATE_SCAN, 0);
#else
			me->scnr_send_evt(dev, ScnrCtl_Radar_Detected, DFS_STATE_SCAN);
#endif				/* CONCURRENT_DFS_SUPPORT */
			set_dfs_status(me, DFS_STATE_IDLE);
			return 0;
		}
#endif
#ifdef  BARBADOS_DFS_TEST
		if (dfs_test) {
			channel = dfsDesc_p->currChanInfo.channel;
		} else
#endif
		{
			/* decide a new target channel */
#ifdef CONCURRENT_DFS_SUPPORT
			channel = DfsDecideNewTargetChannel(dev, dfsDesc_p, FALSE, FALSE);
#else
			channel = DfsDecideNewTargetChannel(dev, dfsDesc_p, FALSE);
#endif				/* CONCURRENT_DFS_SUPPORT */
			if (channel == 0) {
				PRINT1(INFO, "No target channel found to switch to\n");
				dfsTrace(dev, DFS_STATE_SCAN, RADAR_EVT, &dfsDesc_p->currChanInfo, 0x12000000);
				return 0;
			}
		}

		dfsTrace(dev, DFS_STATE_SCAN, RADAR_EVT, &dfsDesc_p->currChanInfo, 0x13000000 | dfs_monitor);

		mib_shadow->PhyDSSSTable->CurrChan = dfsDesc_p->currChanInfo.channel;
		mib_shadow->PhyDSSSTable->SecChan = dfsDesc_p->currChanInfo.channel2;
		mib_shadow->PhyDSSSTable->Chanflag.isDfsChan = dfsDesc_p->currChanInfo.chanflag.isDfsChan;
		mib_shadow->PhyDSSSTable->Chanflag.isDfsChan2 = dfsDesc_p->currChanInfo.chanflag.isDfsChan2;

#ifdef 	BARBADOS_DFS_TEST
		if (!dfs_monitor)
			macMgmtMlme_SwitchChannel(dev, dfsDesc_p->currChanInfo.channel, dfsDesc_p->currChanInfo.channel2,
						  &dfsDesc_p->currChanInfo.chanflag);

		if (!dfs_test)
			DisarmCACTimer(me);
#else
		if (!dfs_test_mode) {
			/* For W8764 DFS test mode do not switch channel, CAC timer not enabled. */
			/* Switch to the target channel */
			macMgmtMlme_SwitchChannel(dev, dfsDesc_p->currChanInfo.channel, dfsDesc_p->currChanInfo.channel2,
						  &dfsDesc_p->currChanInfo.chanflag);
			/* Stops CAC timer */
			DisarmCACTimer(me);
		}
#endif
		if (DfsEnabledChannel(me->pNetDev, &dfsDesc_p->currChanInfo)) {
			if (dfs_test) {
				if (!dfs_probability) {
					dfsTrace(dev, DFS_STATE_SCAN, RADAR_EVT, &dfsDesc_p->currChanInfo, 0x14000000);
					/* Restart data traffic */
					macMgmtMlme_RestartDataTraffic(dev);
					macMgmtMlme_Reset(dev, dfsDesc_p->vaplist, &dfsDesc_p->vapcount);
					return 0;
				}
			}

			mib_CACTimeOut = getCacTimerValue(*(mib->mib_regionCode), *(mib->mib_CACTimeOut), *(mib->mib_ETSICACTimeOut),
							  pChanflag, dfsDesc_p->currChanInfo.channel, dfsDesc_p->currChanInfo.channel2);

			if (mib_CACTimeOut != 0) {
				DfsSetCACTimeOut(me, mib_CACTimeOut);
			}

			FireCACTimer(me);

			dfsTrace(dev, DFS_STATE_SCAN, RADAR_EVT, &dfsDesc_p->currChanInfo, 0x15000000);

			/* Need to restart the radar detection after a channel change */
#ifdef 	BARBADOS_DFS_TEST
			if (dfs_test == 0)
#endif
			{
				macMgmtMlme_StartRadarDetection(dev, DFS_QUIET_MODE);
			}
		} else {
			/* Switch off radar detection */
			dfsTrace(dev, DFS_STATE_SCAN, RADAR_EVT, &dfsDesc_p->currChanInfo, 0x16000000);
			macMgmtMlme_StopRadarDetection(dev, DFS_NORMAL_MODE);
			/* Restart data traffic */
			macMgmtMlme_RestartDataTraffic(dev);
			vmacSta_p->dfs_exclude_acs = 1;
			macMgmtMlme_Reset(dev, dfsDesc_p->vaplist, &dfsDesc_p->vapcount);
			dfsDesc_p->cac_complete = 2;	// Reset on Non DFS Channel
		}
		return 0;
	case CAC_EXPIRY_EVT:
		PRINT1(INFO, "Dfs_Scan_Handle:: event-> CAC_EXPIRY_EVT\n");
#ifdef RADAR_SCANNER_SUPPORT
		if (have_dfs_scnr(wlpptr)) {
#ifdef CONCURRENT_DFS_SUPPORT
			me->scnr_ctl_evt(dev, ScnrCtl_CAC_Done, DFS_STATE_SCAN, 0);
#else
			me->scnr_send_evt(dev, ScnrCtl_CAC_Done, DFS_STATE_SCAN);
#endif				/* CONCURRENT_DFS_SUPPORT */
		}
#endif
		dfsTrace(dev, DFS_STATE_SCAN, CAC_EXPIRY_EVT, &dfsDesc_p->currChanInfo, 0);
		/* Restart data traffic */
		macMgmtMlme_RestartDataTraffic(dev);
		vmacSta_p->dfsCacExp = 1;
		vmacSta_p->dfs_exclude_acs = 1;
		macMgmtMlme_Reset(dev, dfsDesc_p->vaplist, &dfsDesc_p->vapcount);
		dfsDesc_p->cac_complete = 1;	// Reset on DFS Channel
		return 0;
	case WL_RESET_EVT:
		PRINT1(INFO, "Dfs_Scan_Handle:: event-> WL_RESET_EVT\n");

		dfsTrace(dev, DFS_STATE_SCAN, WL_RESET_EVT, &dfsDesc_p->currChanInfo, 0x10000000 | dfsDesc_p->cac_complete);

		/* in wdevreset */
		if (wlpptr->wlpd_p->bfwreset) {
			DisarmCACTimer(me);
			/* Transit to OPERATIONAL state */
			mhsm_transition(&me->super, &me->Dfs_Operational);
			return 0;
		}

		if (dfsDesc_p->cac_complete > 0) {
			set_dfs_status(me, DFS_STATE_OPERATIONAL);
			macMgmtMlme_MBSS_Reset(dev, dfsDesc_p->vaplist, (dfsDesc_p->vapcount < bss_num) ? dfsDesc_p->vapcount : bss_num);

			mib->PhyDSSSTable->Chanflag.isDfsChan = dfsDesc_p->currChanInfo.chanflag.isDfsChan;
			mib->PhyDSSSTable->Chanflag.isDfsChan2 = dfsDesc_p->currChanInfo.chanflag.isDfsChan2;

			if (dfsDesc_p->cac_complete == 1) {
				macMgmtMlme_StartRadarDetection(dev, DFS_NORMAL_MODE);	/* Starts normal mode radar detection */
#ifdef SOC_W906X
				{
					int i;
					struct wlprivate *wlpptr1;
					extern IEEEtypes_MacAddr_t bcast;

					for (i = 0; i < bss_num; i++) {
						if (wlpptr->vdev[i]->flags & IFF_RUNNING) {
							wlpptr1 = NETDEV_PRIV_P(struct wlprivate, wlpptr->vdev[i]);
							macMgmtMlme_SendDeauthenticateMsg(wlpptr1->vmacSta_p, &bcast, sta_num,
											  IEEEtypes_REASON_DEAUTH_LEAVING, FALSE);
						}
					}
				}
#endif
			}
			wlpptr->wlpd_p->bStopBcnProbeResp = FALSE;
			dfsDesc_p->cac_complete = 0;
			dfsDesc_p->vapcount = 0;
			macMgmtMlme_RestartDataTraffic(dev);
			/* Transit to OPERATIONAL state */
			mhsm_transition(&me->super, &me->Dfs_Operational);
		}
		return 0;
	case CHANNEL_CHANGE_EVT:
		{
			DfsChanInfo *chanInfo_p = (DfsChanInfo *) dfsMsg_p->mgtMsg;

			PRINT1(INFO, "Dfs_Scan_Handle:: event-> CHANNEL_CHANGE_EVT\n");

			/* Stop data traffic */
			macMgmtMlme_StopDataTraffic(dev);
			/* Stops CAC timer */
			DisarmCACTimer(me);
			memcpy(&dfsDesc_p->currChanInfo, chanInfo_p, sizeof(DfsChanInfo));
			if (DfsEnabledChannel(me->pNetDev, &dfsDesc_p->currChanInfo)) {
				if (dfs_test) {
					if (!dfs_probability) {
						/* Restart data traffic */
						dfsTrace(dev, DFS_STATE_SCAN, CHANNEL_CHANGE_EVT, &dfsDesc_p->currChanInfo, 0x10000000);
						macMgmtMlme_RestartDataTraffic(dev);
						macMgmtMlme_Reset(dev, dfsDesc_p->vaplist, &dfsDesc_p->vapcount);
						return 0;
					}
				}
#ifdef RADAR_SCANNER_SUPPORT
				if (have_dfs_scnr(wlpptr)) {
					macMgmtMlme_SwitchChannel(dev, dfsDesc_p->currChanInfo.channel,
								  dfsDesc_p->currChanInfo.channel2, &dfsDesc_p->currChanInfo.chanflag);
					if (cac_not_required(chanInfo_p)) {
						dfsTrace(dev, DFS_STATE_SCAN, CHANNEL_CHANGE_EVT, &dfsDesc_p->currChanInfo, 0x20000000);
						macMgmtMlme_RestartDataTraffic(dev);
						vmacSta_p->dfsCacExp = 1;
						vmacSta_p->dfs_exclude_acs = 1;
						dfsDesc_p->cac_complete = 1;
						macMgmtMlme_Reset(dev, dfsDesc_p->vaplist, &dfsDesc_p->vapcount);
#ifdef CONCURRENT_DFS_SUPPORT
						me->scnr_ctl_evt(dev, ScnrCtl_Switched_to_subch, DFS_STATE_SCAN, 0);
#else
						me->scnr_send_evt(dev, ScnrCtl_Switched_to_subch, DFS_STATE_SCAN);
#endif				/* CONCURRENT_DFS_SUPPORT */
						mhsm_transition(&me->super, &me->Dfs_Operational);
						return 0;
					} else {
						dfsTrace(dev, DFS_STATE_SCAN, CHANNEL_CHANGE_EVT, &dfsDesc_p->currChanInfo, 0x21000000);
#ifdef CONCURRENT_DFS_SUPPORT
						me->scnr_ctl_evt(dev, ScnrCtl_Channel_switch_start_cac, DFS_STATE_SCAN, 0);
#else
						me->scnr_send_evt(dev, ScnrCtl_Channel_switch_start_cac, DFS_STATE_SCAN);
#endif				/* CONCURRENT_DFS_SUPPORT */

						macMgmtMlme_StartRadarDetection(dev, DFS_QUIET_MODE);
					}
				}
#endif
				dfsTrace(dev, DFS_STATE_SCAN, CHANNEL_CHANGE_EVT, &dfsDesc_p->currChanInfo, 0x11000000);
				mib_CACTimeOut = getCacTimerValue(*(mib->mib_regionCode), *(mib->mib_CACTimeOut), *(mib->mib_ETSICACTimeOut),
								  &mib->PhyDSSSTable->Chanflag, dfsDesc_p->currChanInfo.channel,
								  dfsDesc_p->currChanInfo.channel2);
				if (mib_CACTimeOut != 0) {
					DfsSetCACTimeOut(me, mib_CACTimeOut);
				}
				/* Restart the CAC timer */
				FireCACTimer(me);

			} else {
#ifdef RADAR_SCANNER_SUPPORT
				//Pete, this required?

				dfsTrace(dev, DFS_STATE_SCAN, CHANNEL_CHANGE_EVT, &dfsDesc_p->currChanInfo, 0x12000000);
				if (have_dfs_scnr(wlpptr)) {
					macMgmtMlme_SwitchChannel(dev, dfsDesc_p->currChanInfo.channel,
								  dfsDesc_p->currChanInfo.channel2, &dfsDesc_p->currChanInfo.chanflag);
				}
#endif
				/* Switch off radar detection */
				macMgmtMlme_StopRadarDetection(dev, DFS_NORMAL_MODE);
				/* Restart data traffic */
				macMgmtMlme_RestartDataTraffic(dev);
				vmacSta_p->dfs_exclude_acs = 1;
				macMgmtMlme_Reset(dev, dfsDesc_p->vaplist, &dfsDesc_p->vapcount);
				dfsDesc_p->cac_complete = 2;	//Reset on Non-DFS channel
			}
		}
		return 0;
	default:
		return 0;
	}
	return msg;
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
MhsmEvent_t const *Dfs_Operational_Handle(DfsAp * me, MhsmEvent_t * msg)
{
	UINT8 channel;
	Dfs_ChanSwitchReq_t chanSwitch;
	DfsApMsg *dfsMsg = NULL;
	DfsApDesc *dfsDesc_p = NULL;
	struct net_device *dev = NULL;
	DfsChanInfo *chanInfo_p;
	MIB_802DOT11 *mib_op;
#ifdef RADAR_SCANNER_SUPPORT
	MIB_802DOT11 *mib;
	struct wlprivate *wlpptr = NULL;
	vmacApInfo_t *vmacSta_p = NULL;
	MIB_PHY_DSSS_TABLE *PhyDSSSTable;
	UINT16 mib_CACTimeOut = 0;
#endif

	PRINT1(INFO, "Dfs_Operational_Handle:: Enter :%d\n", msg->event);

	if ((me == NULL) || (msg == NULL)) {
		PRINT1(INFO, "Dfs_Operational_Handle:: error: NULL pointer\n");
		return 0;
	}
	dfsMsg = (DfsApMsg *) msg->pBody;
	dfsDesc_p = (DfsApDesc *) & me->dfsApDesc;
	dfsDesc_p->me = (void *)me;
	dev = me->pNetDev;
#ifdef RADAR_SCANNER_SUPPORT
	wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
	vmacSta_p = (vmacApInfo_t *) wlpptr->vmacSta_p;
	mib = vmacSta_p->ShadowMib802dot11;
	PhyDSSSTable = mib->PhyDSSSTable;
#endif
	mib_op = vmacSta_p->Mib802dot11;

	switch (msg->event) {
	case MHSM_ENTER:
		dfsTrace(dev, DFS_STATE_OPERATIONAL, (MHSM_ENTER & 0xf), &dfsDesc_p->currChanInfo, 0);
		set_dfs_status(me, DFS_STATE_OPERATIONAL);
#ifdef RADAR_SCANNER_SUPPORT
		//Pete, to notify app ch become Operational
#ifdef CONCURRENT_DFS_SUPPORT
		me->scnr_ctl_evt(dev, ScnrCtl_Chan_Operational, DFS_STATE_OPERATIONAL, 0);
#else
		me->scnr_send_evt(dev, ScnrCtl_Chan_Operational, DFS_STATE_OPERATIONAL);
#endif				/* CONCURRENT_DFS_SUPPORT */
#endif
		return 0;
	case CHANNEL_CHANGE_EVT:
		PRINT1(INFO, "Dfs_Operational_Handle:: event-> POST_CHANNEL_CHANGE_EVT\n");
		chanInfo_p = (DfsChanInfo *) dfsMsg->mgtMsg;
		if (chanInfo_p == NULL) {
			PRINT1(INFO, "NULL ChanInfo received\n");
			dfsTrace(dev, DFS_STATE_OPERATIONAL, CHANNEL_CHANGE_EVT, &dfsDesc_p->currChanInfo, 0x10000000);
			return 0;
		}

		/* Decide if target channel is a DFS channel */
		if (DfsEnabledChannel(me->pNetDev, chanInfo_p)) {
			if (dfs_test) {
				if (!dfs_probability) {
					memcpy(&dfsDesc_p->currChanInfo, chanInfo_p, sizeof(DfsChanInfo));
					dfsTrace(dev, DFS_STATE_OPERATIONAL, CHANNEL_CHANGE_EVT, &dfsDesc_p->currChanInfo, 0x11000000);
					return 0;
				}
			}
			dfsTrace(dev, DFS_STATE_OPERATIONAL, CHANNEL_CHANGE_EVT, &dfsDesc_p->currChanInfo, 0x12000000);
#ifdef RADAR_SCANNER_SUPPORT
			if (have_dfs_scnr(wlpptr)) {	//Pete, how to know Channel change evt is from app?
				DisarmCACTimer(me);
				if (do_csa(chanInfo_p)) {
					dfsTrace(dev, DFS_STATE_OPERATIONAL, CHANNEL_CHANGE_EVT, &dfsDesc_p->currChanInfo, 0x20000000);
					macMgmtMlme_StopRadarDetection(dev, DFS_QUIET_MODE);
					macMgmtMlme_StopRadarDetection(dev, DFS_NORMAL_MODE);
					PhyDSSSTable->no_cac = chanInfo_p->no_cac;
#ifdef CONCURRENT_DFS_SUPPORT
					me->scnr_ctl_evt(dev, ScnrCtl_Starting_CSA, DFS_STATE_OPERATIONAL, 0);
#else
					me->scnr_send_evt(dev, ScnrCtl_Starting_CSA, DFS_STATE_OPERATIONAL);
#endif				/* CONCURRENT_DFS_SUPPORT */
					/* Insert Channel Switch Announcement IE in the beacon/probe-response
					 * and initiate countdown process */
					chanSwitch.ChannelSwitchCmd.Mode = DFS_DEFAULT_CSAMODE;
					chanSwitch.ChannelSwitchCmd.ChannelNumber = chanInfo_p->channel;
					chanSwitch.ChannelSwitchCmd.ChannelSwitchCount = DFS_DEFAULT_COUNTDOWN_NUMBER;
					chanSwitch.chInfo = dfsDesc_p->currChanInfo;
					macMgmtMlme_SendChannelSwitchCmd(dev, &chanSwitch);
					mhsm_transition(&me->super, &me->Dfs_Csa);
					return 0;
				} else {
					macMgmtMlme_SwitchChannel(dev, chanInfo_p->channel, chanInfo_p->channel2, &dfsDesc_p->currChanInfo.chanflag);
					if (cac_not_required(chanInfo_p)) {
						dfsTrace(dev, DFS_STATE_OPERATIONAL, CHANNEL_CHANGE_EVT, &dfsDesc_p->currChanInfo, 0x21000000);
						macMgmtMlme_RestartDataTraffic(dev);
						vmacSta_p->dfs_exclude_acs = 1;
						macMgmtMlme_Reset(dev, dfsDesc_p->vaplist, &dfsDesc_p->vapcount);
						vmacSta_p->dfsCacExp = 1;
#ifdef CONCURRENT_DFS_SUPPORT
						me->scnr_ctl_evt(dev, ScnrCtl_Switched_to_subch, DFS_STATE_OPERATIONAL, 0);
#else
						me->scnr_send_evt(dev, ScnrCtl_Switched_to_subch, DFS_STATE_OPERATIONAL);
#endif				/* CONCURRENT_DFS_SUPPORT */
						return 0;
					} else
						dfsTrace(dev, DFS_STATE_OPERATIONAL, CHANNEL_CHANGE_EVT, &dfsDesc_p->currChanInfo, 0x22000000);
#ifdef CONCURRENT_DFS_SUPPORT
					me->scnr_ctl_evt(dev, ScnrCtl_Channel_switch_start_cac, DFS_STATE_OPERATIONAL, 0);
#else
					me->scnr_send_evt(dev, ScnrCtl_Channel_switch_start_cac, DFS_STATE_OPERATIONAL);
#endif				/* CONCURRENT_DFS_SUPPORT */
				}
			}
#endif
			/* Switch on quiet mode radar detection */
			macMgmtMlme_StartRadarDetection(dev, DFS_QUIET_MODE);
			/* Stop data traffic */
			macMgmtMlme_StopDataTraffic(dev);
			memcpy(&dfsDesc_p->currChanInfo, chanInfo_p, sizeof(DfsChanInfo));
			mib_CACTimeOut = getCacTimerValue(*(mib->mib_regionCode), *(mib->mib_CACTimeOut), *(mib->mib_ETSICACTimeOut),
							  &mib->PhyDSSSTable->Chanflag, dfsDesc_p->currChanInfo.channel,
							  dfsDesc_p->currChanInfo.channel2);
			if (mib_CACTimeOut != 0) {
				DfsSetCACTimeOut(me, mib_CACTimeOut);
			}
			FireCACTimer(me);
			/* go to SCAN state */
			mhsm_transition(&me->super, &me->Dfs_Scan);
		} else {
			/* target channel is not dfs enabled */
			/* Switch off radar detection */

			wlFwSetIEs(dev);
			macMgmtMlme_StopRadarDetection(dev, DFS_NORMAL_MODE);
			memcpy(&dfsDesc_p->currChanInfo, chanInfo_p, sizeof(DfsChanInfo));

			/* trace should be placed after update currentChanInfo */
			dfsTrace(dev, DFS_STATE_OPERATIONAL, CHANNEL_CHANGE_EVT, &dfsDesc_p->currChanInfo, 0x13000000);
#ifdef RADAR_SCANNER_SUPPORT
			//Pete, to be reviewed. 
			if (have_dfs_scnr(wlpptr)) {
				dfsTrace(dev, DFS_STATE_OPERATIONAL, CHANNEL_CHANGE_EVT, &dfsDesc_p->currChanInfo, 0x23000000);
				macMgmtMlme_SwitchChannel(dev, chanInfo_p->channel, chanInfo_p->channel2, &dfsDesc_p->currChanInfo.chanflag);
				TimerDisarm(&dfsDesc_p->CACTimer);
				macMgmtMlme_RestartDataTraffic(dev);
				vmacSta_p->dfs_exclude_acs = 1;
				macMgmtMlme_Reset(dev, dfsDesc_p->vaplist, &dfsDesc_p->vapcount);
			}
#endif
		}
		return 0;

	case RADAR_EVT:
		PRINT1(INFO, "Dfs_Operational_Handle:: event-> RADAR_EVT on channel %d\n", dfsDesc_p->currChanInfo.channel);
		chanInfo_p = (DfsChanInfo *) dfsMsg->mgtMsg;

		dfsDesc_p->currChanInfo.from = chanInfo_p->from;

		if (DfsEnabledChannel(me->pNetDev, chanInfo_p)) {
#ifdef 	BARBADOS_DFS_TEST
			if (!dfs_monitor) {
				macMgmtMlme_StopDataTraffic(dev);
				/* Switch off radar detection */
				macMgmtMlme_StopRadarDetection(dev, DFS_NORMAL_MODE);
			}
			/* Updated NOL */
			if (!dfs_probability) {
				if (dfs_monitor) {
					dfsTrace(dev, DFS_STATE_OPERATIONAL, RADAR_EVT, &dfsDesc_p->currChanInfo, 0x10000000);
					return 0;
				}

				if (dfs_updateNOL(dfsDesc_p) == DFS_FAILURE) {
					dfsTrace(dev, DFS_STATE_OPERATIONAL, RADAR_EVT, &dfsDesc_p->currChanInfo, 0x12000000);
					return 0;
				}
			}
#else
			if (!dfs_test_mode) {
				/* Do not add channel to NOL in dfs test mode. */
				/* Stop data traffic */
				dfsTrace(dev, DFS_STATE_OPERATIONAL, RADAR_EVT, &dfsDesc_p->currChanInfo, 0x15000000);
				macMgmtMlme_StopDataTraffic(dev);
				/* Switch off radar detection */
				macMgmtMlme_StopRadarDetection(dev, DFS_NORMAL_MODE);
				/* Updated NOL */
				DfsAddToNOL(dfsDesc_p, dfsDesc_p->currChanInfo.channel, dfsDesc_p->currChanInfo.chanflag);
			}
#endif

#ifdef RADAR_SCANNER_SUPPORT
			if (have_dfs_scnr(wlpptr)) {
				dfsTrace(dev, DFS_STATE_OPERATIONAL, RADAR_EVT, &dfsDesc_p->currChanInfo, 0x20000000);
				TimerDisarm(&dfsDesc_p->CACTimer);
				//Pete, stop beacon and disable detection first. DFS_CTLR must react in time in CSA case. To be checked. 
				macMgmtMlme_StartRadarDetection(dev, DFS_QUIET_MODE);
				macMgmtMlme_StopRadarDetection(dev, DFS_NORMAL_MODE);
#ifdef CONCURRENT_DFS_SUPPORT
				me->scnr_ctl_evt(dev, ScnrCtl_Radar_Detected, DFS_STATE_OPERATIONAL, 0);
#else
				me->scnr_send_evt(dev, ScnrCtl_Radar_Detected, DFS_STATE_OPERATIONAL);
#endif				/* CONCURRENT_DFS_SUPPORT */
				PhyDSSSTable->no_cac = 0;
				set_dfs_status(me, DFS_STATE_IDLE);
				return 0;
			}
#endif

#ifdef  BARBADOS_DFS_TEST
			if (dfs_test) {
				channel = dfsDesc_p->currChanInfo.channel;
			} else
#endif
			{
				/* decide a new target channel */
#ifdef CONCURRENT_DFS_SUPPORT
				channel = DfsDecideNewTargetChannel(dev, dfsDesc_p, FALSE, FALSE);
#else
				channel = DfsDecideNewTargetChannel(dev, dfsDesc_p, FALSE);
#endif				/* CONCURRENT_DFS_SUPPORT */
				if (channel == 0) {
					dfsTrace(dev, DFS_STATE_OPERATIONAL, RADAR_EVT, &dfsDesc_p->currChanInfo, 0x17000000);
					return 0;
				}
				DfsEnabledChannel(dev, &dfsDesc_p->currChanInfo);

				mib->PhyDSSSTable->Chanflag.isDfsChan = dfsDesc_p->currChanInfo.chanflag.isDfsChan;
				mib->PhyDSSSTable->Chanflag.isDfsChan2 = dfsDesc_p->currChanInfo.chanflag.isDfsChan2;
			}
#ifdef CONCURRENT_DFS_SUPPORT
			PRINT1(INFO, "[1]New Target channel is : chan=%d chan2=%d isDfsChan=%d isDfsChan2=%d\n",
			       dfsDesc_p->currChanInfo.channel, dfsDesc_p->currChanInfo.channel2,
			       mib->PhyDSSSTable->Chanflag.isDfsChan, mib->PhyDSSSTable->Chanflag.isDfsChan2);
#else
			PRINT1(INFO, "New Target channel is : %d\n", channel);
#endif
			dfsTrace(dev, DFS_STATE_OPERATIONAL, RADAR_EVT, &dfsDesc_p->currChanInfo, 0x18000000);
			/* Insert Channel Switch Announcement IE in the beacon/probe-response
			 * and initiate countdown process */
			chanSwitch.ChannelSwitchCmd.Mode = DFS_DEFAULT_CSAMODE;
			chanSwitch.ChannelSwitchCmd.ChannelNumber = channel;
			chanSwitch.ChannelSwitchCmd.ChannelSwitchCount = DFS_DEFAULT_COUNTDOWN_NUMBER;
			chanSwitch.chInfo = dfsDesc_p->currChanInfo;
			macMgmtMlme_SendChannelSwitchCmd(dev, &chanSwitch);
#ifdef  BARBADOS_DFS_TEST
			if (!dfs_test)
#endif
			{
				mdelay(10);
				((SMAC_CTRL_BLK_st *) wlpptr->ioBase0)->config.txAcStop = 0xf;
				printk("[DFS] Stop SFW AC queue Tx ...\n");
			}
#ifdef 	BARBADOS_DFS_TEST
			if (!dfs_monitor)
				mhsm_transition(&me->super, &me->Dfs_Csa);	//Go to CSA state                            
#else
			if (!dfs_test_mode)	/* DFS test mode, stay in same state. */
				mhsm_transition(&me->super, &me->Dfs_Csa);	//Go to CSA state
#endif
		} else {
			/* Switch off radar detection */
			dfsTrace(dev, DFS_STATE_OPERATIONAL, RADAR_EVT, &dfsDesc_p->currChanInfo, 0x19000000);
			macMgmtMlme_StopRadarDetection(dev, DFS_NORMAL_MODE);
		}
		return 0;
#ifdef RADAR_SCANNER_SUPPORT
	case WL_RESET_EVT:
		//Pete, to be reviewed. 
		dfsTrace(dev, DFS_STATE_OPERATIONAL, WL_RESET_EVT, &dfsDesc_p->currChanInfo, 0x20000000);
		mib_op->PhyDSSSTable->Chanflag.isDfsChan = dfsDesc_p->currChanInfo.chanflag.isDfsChan;
		mib_op->PhyDSSSTable->Chanflag.isDfsChan2 = dfsDesc_p->currChanInfo.chanflag.isDfsChan2;

		if (mib->PhyDSSSTable->Chanflag.isDfsChan || mib->PhyDSSSTable->Chanflag.isDfsChan2) {
			macMgmtMlme_StartRadarDetection(dev, DFS_NORMAL_MODE);
		}
		macMgmtMlme_MBSS_Reset(dev, dfsDesc_p->vaplist, (dfsDesc_p->vapcount < bss_num) ? dfsDesc_p->vapcount : bss_num);
#ifdef CONCURRENT_DFS_SUPPORT
		me->scnr_ctl_evt(dev, ScnrCtl_Chan_Operational, DFS_STATE_OPERATIONAL, 0);
#else
		me->scnr_send_evt(dev, ScnrCtl_Chan_Operational, DFS_STATE_OPERATIONAL);
#endif				/* CONCURRENT_DFS_SUPPORT */
		set_dfs_status(me, DFS_STATE_OPERATIONAL);
		dfsDesc_p->cac_complete = 0;
		dfsDesc_p->vapcount = 0;
		return 0;
#endif
	default:
		return 0;
	}
	return msg;
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
MhsmEvent_t const *Dfs_Csa_Handle(DfsAp * me, MhsmEvent_t * msg)
{
	DfsApMsg *dfsMsg = NULL;
	DfsApDesc *dfsDesc_p = NULL;
	DfsChanInfo *chanInfo_p = NULL;
	struct wlprivate *wlpptr = NULL;
	vmacApInfo_t *vmacSta_p = NULL;
	struct net_device *dev = NULL;
	MIB_802DOT11 *mib;
	CHNL_FLAGS *pChanflag;
	UINT16 mib_CACTimeOut = 0;

	PRINT1(INFO, "Dfs_Csa_Handle:: Enter :%d\n", msg->event);
	if ((me == NULL) || (msg == NULL)) {
		PRINT1(INFO, "Dfs_Csa_Handle:: error: NULL pointer\n");
		return 0;
	}

	dev = me->pNetDev;
	wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
	vmacSta_p = (vmacApInfo_t *) wlpptr->vmacSta_p;
	mib = vmacSta_p->Mib802dot11;
	pChanflag = &mib->PhyDSSSTable->Chanflag;

	dfsMsg = (DfsApMsg *) msg->pBody;
	dfsDesc_p = (DfsApDesc *) & me->dfsApDesc;

	switch (msg->event) {
	case MHSM_ENTER:
		PRINT1(INFO, "Dfs_Csa_Handle:: event-> MHSM_ENTER\n");
		dfsTrace(dev, DFS_STATE_CSA, (MHSM_ENTER & 0xf), &dfsDesc_p->currChanInfo, 0);

		set_dfs_status(me, DFS_STATE_CSA);
		/* Start DFS CSA timer */
		TimerFireIn(&dfsDesc_p->CSATimer, 1, &CSATimeoutHandler, (unsigned char *)me, dfsDesc_p->CSATimeOut);
		return 0;
	case CHANNEL_CHANGE_EVT:
		{
			if (!dfsMsg) {
				PRINT1(INFO, "CSA::CHANNEL_CHANGE_EVT NULL dfsMsg\n");
				dfsTrace(dev, DFS_STATE_CSA, CHANNEL_CHANGE_EVT, &dfsDesc_p->currChanInfo, 0x10000000);
				return 0;
			}
			chanInfo_p = (DfsChanInfo *) dfsMsg->mgtMsg;
			/* Stops CSA timer */
			TimerDisarm(&dfsDesc_p->CSATimer);
			if (chanInfo_p == NULL) {
				dfsTrace(dev, DFS_STATE_CSA, CHANNEL_CHANGE_EVT, &dfsDesc_p->currChanInfo, 0x11000000);
				return 0;
			}
			memcpy(&dfsDesc_p->currChanInfo, chanInfo_p, sizeof(DfsChanInfo));
			/* Decide if target channel is a DFS channel */
			if (DfsEnabledChannel(me->pNetDev, &dfsDesc_p->currChanInfo)) {
				if (dfs_test) {
					if (!dfs_probability) {
						dfsTrace(dev, DFS_STATE_CSA, CHANNEL_CHANGE_EVT, &dfsDesc_p->currChanInfo, 0x12000000);
						/* Restart data traffic */
						macMgmtMlme_RestartDataTraffic(dev);
						/* go to OPERATIONAL state */
						mhsm_transition(&me->super, &me->Dfs_Operational);
						return 0;
					}
				}
#ifdef RADAR_SCANNER_SUPPORT
				if (cac_not_required(&dfsDesc_p->currChanInfo)) {
					macMgmtMlme_RestartDataTraffic(dev);
					vmacSta_p->dfs_exclude_acs = 1;
					macMgmtMlme_Reset(dev, dfsDesc_p->vaplist, &dfsDesc_p->vapcount);
#ifdef CONCURRENT_DFS_SUPPORT
					me->scnr_ctl_evt(dev, ScnrCtl_Switched_to_subch, DFS_STATE_CSA, 0);
#else
					me->scnr_send_evt(dev, ScnrCtl_Switched_to_subch, DFS_STATE_CSA);
#endif				/* CONCURRENT_DFS_SUPPORT */
					dfsTrace(dev, DFS_STATE_CSA, CHANNEL_CHANGE_EVT, &dfsDesc_p->currChanInfo, 0x20000000);
					return 0;
				}
#endif
				chanInfo_p = &dfsDesc_p->currChanInfo;

				mib_CACTimeOut = getCacTimerValue(*(mib->mib_regionCode), *(mib->mib_CACTimeOut), *(mib->mib_ETSICACTimeOut),
								  pChanflag, dfsDesc_p->currChanInfo.channel, dfsDesc_p->currChanInfo.channel2);

				if (mib_CACTimeOut != 0) {
					DfsSetCACTimeOut(me, mib_CACTimeOut);
				}
				dfsTrace(dev, DFS_STATE_CSA, CHANNEL_CHANGE_EVT, &dfsDesc_p->currChanInfo, 0x13000000);
				/* Start CAC timer from the beginning */
				FireCACTimer(me);

				mib->PhyDSSSTable->Chanflag.isDfsChan = chanInfo_p->chanflag.isDfsChan;
				mib->PhyDSSSTable->Chanflag.isDfsChan2 = chanInfo_p->chanflag.isDfsChan2;

				macMgmtMlme_StartRadarDetection(dev, DFS_QUIET_MODE);
				/* go to SCAN state */
				mhsm_transition(&me->super, &me->Dfs_Scan);
			} else {
				dfsTrace(dev, DFS_STATE_CSA, CHANNEL_CHANGE_EVT, &dfsDesc_p->currChanInfo, 0x14000000);
				/* Switch off radar detection */
				macMgmtMlme_StopRadarDetection(dev, DFS_NORMAL_MODE);
				/* Restart data traffic */
				macMgmtMlme_RestartDataTraffic(dev);
				vmacSta_p->dfs_exclude_acs = 1;
				macMgmtMlme_Reset(dev, dfsDesc_p->vaplist, &dfsDesc_p->vapcount);
				dfsDesc_p->cac_complete = 2;	// Reset on Non DFS Channel          
				/* go to OPERATIONAL state */
				printk("[DFS] currChan =%d secChan=%d radiomode=%d\n",
				       mib->PhyDSSSTable->CurrChan, mib->PhyDSSSTable->SecChan, mib->PhyDSSSTable->Chanflag.radiomode);
				mhsm_transition(&me->super, &me->Dfs_Operational);
			}
			return 0;
		}
	case CSA_EXPIRY_EVT:
		PRINT1(INFO, "Dfs_Csa_Handle:: event-> CSA_EXPIRY_EVT\n");
		dfsTrace(dev, DFS_STATE_CSA, CSA_EXPIRY_EVT, &dfsDesc_p->currChanInfo, 0x10000000);
		/* Restart data traffic */
		macMgmtMlme_RestartDataTraffic(dev);
		vmacSta_p->dfs_exclude_acs = 1;
		macMgmtMlme_Reset(dev, dfsDesc_p->vaplist, &dfsDesc_p->vapcount);
		/* go to OPERATIONAL state */
		mhsm_transition(&me->super, &me->Dfs_Operational);
		return 0;
#ifdef RADAR_SCANNER_SUPPORT
	case WL_RESET_EVT:
		dfsTrace(dev, DFS_STATE_CSA, WL_RESET_EVT, &dfsDesc_p->currChanInfo, 0x20000000);

		if (mib->PhyDSSSTable->Chanflag.isDfsChan || mib->PhyDSSSTable->Chanflag.isDfsChan2) {
			macMgmtMlme_StartRadarDetection(dev, DFS_NORMAL_MODE);
		}
		macMgmtMlme_MBSS_Reset(dev, dfsDesc_p->vaplist, (dfsDesc_p->vapcount < bss_num) ? dfsDesc_p->vapcount : bss_num);
		dfsDesc_p->cac_complete = 1;
		dfsDesc_p->vapcount = 0;
		mhsm_transition(&me->super, &me->Dfs_Operational);
		return 0;
#endif
	default:
		return 0;
	}
	return msg;
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
void DFSApCtor(struct net_device *pNetDev, DfsAp * me)
{
	mhsm_add(&me->sTop, NULL, (MhsmFcnPtr) DfsAp_top);
	mhsm_add(&me->Dfs_Ap, &me->sTop, (MhsmFcnPtr) Dfs_Ap_Handle);
	mhsm_add(&me->Dfs_Init, &me->Dfs_Ap, (MhsmFcnPtr) Dfs_Init_Handle);
	mhsm_add(&me->Dfs_Scan, &me->Dfs_Ap, (MhsmFcnPtr) Dfs_Scan_Handle);
	mhsm_add(&me->Dfs_Operational, &me->Dfs_Ap, (MhsmFcnPtr) Dfs_Operational_Handle);
	mhsm_add(&me->Dfs_Csa, &me->Dfs_Ap, (MhsmFcnPtr) Dfs_Csa_Handle);
	me->dropData = 0;
	memset(&me->dfsApDesc, 0, sizeof(DfsApDesc));
	TimerInit(&me->dfsApDesc.CACTimer);
	TimerInit(&me->dfsApDesc.NOCTimer);
	TimerInit(&me->dfsApDesc.CSATimer);
	ListInit(&me->dfsApDesc.NOCList);
	me->dfsApDesc.CACTimeOut = DFS_DEFAULT_CAC_TIMEOUT;
	me->dfsApDesc.CSATimeOut = DFS_DEFAULT_CSA_TIMEOUT;
	me->dfsApDesc.NOCTimeOut = DFS_DEFAULT_NOC_TIMEOUT;

#ifdef CONCURRENT_DFS_SUPPORT
	TimerInit(&me->dfsApDesc.CtlCACTimer);
	me->dfsApDesc.CtlCACTimeOut = DFS_DEFAULT_CAC_TIMEOUT;
#endif				/* CONCURRENT_DFS_SUPPORT */
	TimerInit(&me->dfsApDesc.EMCACTimer);
	me->pNetDev = (struct net_device *)pNetDev;
}

void CACTimeoutHandler(void *data_p)
{
	MhsmEvent_t msg;
	DfsAp *me;
	struct net_device *dev;
	struct wlprivate *wlpptr = NULL;
	struct wlprivate_data *wlpd_p = NULL;
	MIB_802DOT11 *mib;

	WLDBG_INFO(DBG_LEVEL_1, "enter CAC timeout handler\n");
	me = (DfsAp *) data_p;
	dev = me->pNetDev;
	wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);

	mib = wlpptr->vmacSta_p->ShadowMib802dot11;

	if (*(mib->mib_rx_enable) == 0)
		*(u32 *) (&((SMAC_CTRL_BLK_st *) wlpptr->ioBase0)->config.rxEnable) = 0;

	wlpd_p = wlpptr->wlpd_p;
	wlpd_p->bCACTimerFired = FALSE;
	msg.event = CAC_EXPIRY_EVT;
	mhsm_send_event((Mhsm_t *) data_p, &msg);
}

void CSATimeoutHandler(void *data_p)
{
	MhsmEvent_t msg;
	msg.event = CSA_EXPIRY_EVT;
	WLDBG_INFO(DBG_LEVEL_1, "enter CSA timeout handler\n");

	mhsm_send_event((Mhsm_t *) data_p, &msg);
}

DFS_STATUS DfsEnabledChannel(struct net_device *pNetDev, DfsChanInfo * chanInfo_p)
{
	int i = 0, j = 0, dfsEnabledEntry = 0;
	UINT8 domainCode = 0;
	UINT8 domain = 0;
	UINT8 channel;

	if (!macMgmtMlme_DfsEnabled(pNetDev)) {
		PRINT1(INFO, "DFS is not enabled\n");
		return DFS_FAILURE;
	}
	if (chanInfo_p == NULL) {
		PRINT1(INFO, "NULL ChanInfo passed to DfsEnabledChannel function\n");
		return DFS_FAILURE;
	}
	if (chanInfo_p->chanflag.FreqBand != FREQ_BAND_5GHZ) {
		PRINT1(INFO, "This is not a 5GHz channel\n");
		return DFS_FAILURE;
	}
	chanInfo_p->chanflag.isDfsChan = FALSE;
	chanInfo_p->chanflag.isDfsChan2 = FALSE;
	domainCode = domainGetDomain();	// get current domain
	for (i = 0; i < domainGetSizeOfdfsEnabledChannels() / sizeof(DFS_CHANNEL_LIST); i++) {
		domain = dfsEnabledChannels[i].domainCode;
		if (domain != domainCode)
			continue;
		dfsEnabledEntry = i;
		for (j = 0; j < DFS_MAX_CHANNELS; j++) {

#ifdef CONCURRENT_DFS_SUPPORT
			if (chanInfo_p->channel2 && (chanInfo_p->chanflag.radiomode == RADIO_MODE_80p80) && !chanInfo_p->chanflag.isDfsChan2) {
				if (chanInfo_p->channel2 == dfsEnabledChannels[i].dfschannelEntry[j]) {
					chanInfo_p->chanflag.isDfsChan2 = TRUE;
				}
			}
#endif
			if (chanInfo_p->channel && !chanInfo_p->chanflag.isDfsChan
			    && (chanInfo_p->channel == dfsEnabledChannels[i].dfschannelEntry[j])) {
				chanInfo_p->chanflag.isDfsChan = TRUE;
			}
#ifdef CONCURRENT_DFS_SUPPORT
			if (chanInfo_p->chanflag.radiomode == RADIO_MODE_80p80) {
				if (chanInfo_p->chanflag.isDfsChan && chanInfo_p->chanflag.isDfsChan2)
					goto found;
			} else
#endif
			{
				if (chanInfo_p->chanflag.isDfsChan)
					goto found;
			}
		}
	}
	if (TRUE && (
#ifdef CONCURRENT_DFS_SUPPORT
			    ((chanInfo_p->chanflag.radiomode == RADIO_MODE_80p80) && chanInfo_p->chanflag.isDfsChan
			     && chanInfo_p->chanflag.isDfsChan2) || ((chanInfo_p->chanflag.radiomode != RADIO_MODE_80p80)
								     && chanInfo_p->chanflag.isDfsChan)))
#else
			    chanInfo_p->chanflag.isDfsChan))
#endif
	{
 found:
		return DFS_SUCCESS;
	}

	//Continue to check different BW combinations

#ifdef CONCURRENT_DFS_SUPPORT

	if (chanInfo_p->chanflag.radiomode == RADIO_MODE_80p80) {
		/* 80 primary */
		for (i = 0; i < domainGetSizeOfGrpChList80Mhz() / sizeof(GRP_CHANNEL_LIST_80Mhz); i++) {

			if (chanInfo_p->channel && (chanInfo_p->chanflag.isDfsChan == FALSE)) {
				if (channel_exists(chanInfo_p->channel, GrpChList80Mhz[i].channelEntry, 4)) {
					//Is this DFS group?
					for (j = 0; j < DFS_MAX_CHANNELS; j++) {
						channel = dfsEnabledChannels[dfsEnabledEntry].dfschannelEntry[j];
						if (channel_exists(channel, GrpChList80Mhz[i].channelEntry, 4)) {
							chanInfo_p->chanflag.isDfsChan = TRUE;
							break;
						}
					}
				}
			}
			if (chanInfo_p->channel2 && (chanInfo_p->chanflag.isDfsChan2 == FALSE)) {
				if (channel_exists(chanInfo_p->channel2, GrpChList80Mhz[i].channelEntry, 4)) {
					//Is this DFS group?
					for (j = 0; j < DFS_MAX_CHANNELS; j++) {
						channel = dfsEnabledChannels[dfsEnabledEntry].dfschannelEntry[j];
						if (channel_exists(channel, GrpChList80Mhz[i].channelEntry, 4)) {
							chanInfo_p->chanflag.isDfsChan2 = TRUE;
							break;
						}
					}
				}
			}
		}
		if (chanInfo_p->chanflag.isDfsChan || chanInfo_p->chanflag.isDfsChan2) {
			return DFS_SUCCESS;
		}
	} else
#endif
	if (chanInfo_p->chanflag.ChnlWidth == CH_160_MHz_WIDTH || chanInfo_p->chanflag.ChnlWidth == CH_AUTO_WIDTH) {
		for (i = 0; i < domainGetSizeOfGrpChList160Mhz() / sizeof(GRP_CHANNEL_LIST_160Mhz); i++) {
			if (channel_exists(chanInfo_p->channel, GrpChList160Mhz[i].channelEntry, 8)) {
				//Is this DFS group? 
				for (j = 0; j < DFS_MAX_CHANNELS; j++) {
					channel = dfsEnabledChannels[dfsEnabledEntry].dfschannelEntry[j];
					if (channel_exists(channel, GrpChList160Mhz[i].channelEntry, 8))
						return DFS_SUCCESS;
				}
			}
		}
	} else if (chanInfo_p->chanflag.ChnlWidth == CH_80_MHz_WIDTH) {
		for (i = 0; i < domainGetSizeOfGrpChList80Mhz() / sizeof(GRP_CHANNEL_LIST_80Mhz); i++) {
			if (channel_exists(chanInfo_p->channel, GrpChList80Mhz[i].channelEntry, 4)) {
				//Is this DFS group?
				for (j = 0; j < DFS_MAX_CHANNELS; j++) {
					channel = dfsEnabledChannels[dfsEnabledEntry].dfschannelEntry[j];
					if (channel_exists(channel, GrpChList80Mhz[i].channelEntry, 4))
						return DFS_SUCCESS;
				}
			}
		}
	} else if (chanInfo_p->chanflag.ChnlWidth == CH_40_MHz_WIDTH) {
		if (channel_exists(chanInfo_p->channel, GrpChList40Mhz[i].channelEntry, 2)) {
			//Is this DFS group?
			for (j = 0; j < DFS_MAX_CHANNELS; j++) {
				channel = dfsEnabledChannels[dfsEnabledEntry].dfschannelEntry[j];
				if (channel_exists(channel, GrpChList40Mhz[i].channelEntry, 2))
					return DFS_SUCCESS;
			}
		}
	}
	return DFS_FAILURE;
}

DFS_STATUS DfsAddToNOL(DfsApDesc * dfsDesc_p, UINT8 channel, CHNL_FLAGS * chanflag, unsigned long occurance)
{
	NOCListItem *nocListItem_p = NULL;
	NOCListItem *tmp = NULL;
	UINT8 firstItem = 0;

	if (dfsDesc_p == NULL)
		return DFS_FAILURE;

	if (DfsFindInNOL(&dfsDesc_p->NOCList, channel) == DFS_SUCCESS) {
		PRINT1(INFO, "Channel %d already in NOL\n", channel);
		return DFS_FAILURE;
	}

	if ((tmp = (NOCListItem *) ListGetItem(&dfsDesc_p->NOCList)) == NULL)
		firstItem = 1;
	else
		ListPutItemFILO(&dfsDesc_p->NOCList, (ListItem *) tmp);	//Put it back

	if ((nocListItem_p = wl_kmalloc(sizeof(NOCListItem), GFP_ATOMIC)) == NULL) {
		PRINT1(INFO, "Cannot allocate memory for NOCList\n");
		return DFS_FAILURE;
	}
	nocListItem_p->channel = channel;
	nocListItem_p->occurance = occurance;
	switch (chanflag->ChnlWidth) {
	case CH_20_MHz_WIDTH:
		nocListItem_p->BW = 20;
		break;
	case CH_40_MHz_WIDTH:
		nocListItem_p->BW = 40;
		break;
	case CH_80_MHz_WIDTH:
		nocListItem_p->BW = 80;
		break;
	case CH_160_MHz_WIDTH:
		nocListItem_p->BW = 160;
		break;
	case CH_AUTO_WIDTH:
		nocListItem_p->BW = 160;
		break;
	default:
		PRINT1(INFO, "unknown BW \n");
		break;
	}
	ListPutItem(&dfsDesc_p->NOCList, (ListItem *) nocListItem_p);

	/* Now initiate/update the NOCTimer */
	if (firstItem) {
#ifdef 	BARBADOS_DFS_TEST
		if (dfs_test)
			return DFS_SUCCESS;
#endif
		TimerFireIn(&dfsDesc_p->NOCTimer, 1, &NOCTimeoutHandler, (unsigned char *)dfsDesc_p, dfsDesc_p->NOCTimeOut);
	}
	return DFS_SUCCESS;
}

DFS_STATUS DfsRemoveFromNOL(DfsApDesc * dfsDesc_p)
{
	NOCListItem *nocListItem_p;
	SINT32 timeoutPeriod;
	unsigned long occurance;

	if (dfsDesc_p == NULL)
		return DFS_FAILURE;

	nocListItem_p = (NOCListItem *) ListGetItem(&dfsDesc_p->NOCList);
 here:
	if (nocListItem_p == NULL)
		return DFS_FAILURE;
	occurance = nocListItem_p->occurance;
	wl_kfree(nocListItem_p);
 next:
	nocListItem_p = (NOCListItem *) ListGetItem(&dfsDesc_p->NOCList);
	if (nocListItem_p != NULL) {
		if (nocListItem_p->occurance == occurance) {
			wl_kfree(nocListItem_p);
			goto next;
		}
	}
#ifdef 	BARBADOS_DFS_TEST
	//if (dfs_monitor || dfs_test || dfs_clear_nol)
	if (dfs_clear_nol) {
		if (nocListItem_p == NULL)
			return DFS_SUCCESS;
		else
			goto here;
	}
#endif
	if (nocListItem_p) {
		timeoutPeriod = dfsDesc_p->NOCTimeOut - (jiffies_to_msecs(jiffies - nocListItem_p->occurance) / 100);
		if (timeoutPeriod <= 0)
			TimerFireIn(&dfsDesc_p->NOCTimer, 1, &NOCTimeoutHandler, (unsigned char *)dfsDesc_p, 1);
		else
			TimerFireIn(&dfsDesc_p->NOCTimer, 1, &NOCTimeoutHandler, (unsigned char *)dfsDesc_p, timeoutPeriod);
		/* Put it back */
		ListPutItemFILO(&dfsDesc_p->NOCList, (ListItem *) nocListItem_p);
	}
	return DFS_SUCCESS;
}

#ifdef CONCURRENT_DFS_SUPPORT
DFS_STATUS UpdateNOL(DfsApDesc * dfsDesc_p, UINT8 IsFromAux)
#else
DFS_STATUS UpdateNOL(DfsApDesc * dfsDesc_p)
#endif				/* CONCURRENT_DFS_SUPPORT */
{
	UINT8 domainCode;
	int i = 0;
	UINT8 extChan = 0;
	UINT8 extChanOffset;
	UINT8 domainInd, domainInd_IEEERegion;
	unsigned long occurance;
	UINT8 bw;
	UINT16 ch;
	CHNL_FLAGS cf;

	if (!dfsDesc_p)
		return DFS_FAILURE;

	if (dfs_test || dfs_monitor)
		return DFS_SUCCESS;

	domainCode = domainGetDomain();	// get current domain
	for (i = 0; i < domainGetSizeOfdfsEnabledChannels(); i++)
		if (domainCode == dfsEnabledChannels[i].domainCode)
			break;

	if (i == domainGetSizeOfdfsEnabledChannels())
		return DFS_FAILURE;

	bw = dfsDesc_p->currChanInfo.chanflag.ChnlWidth;
	ch = dfsDesc_p->currChanInfo.channel;
	cf = dfsDesc_p->currChanInfo.chanflag;

#ifdef CONCURRENT_DFS_SUPPORT
	if (IsFromAux) {
		if (dfsDesc_p->currChanInfo.chanflag.radiomode == RADIO_MODE_80p80) {
			bw = dfsDesc_p->currChanInfo.chanflag.ChnlWidth2;
			ch = dfsDesc_p->currChanInfo.channel2;
		} else {
			bw = dfsDesc_p->CtlChanInfo.chanflag.ChnlWidth;
			ch = dfsDesc_p->CtlChanInfo.channel;
			cf = dfsDesc_p->CtlChanInfo.chanflag;
		}
	}
#endif				/* CONCURRENT_DFS_SUPPORT */

	domainInd = i;
	domainInd_IEEERegion = GetDomainIndxIEEERegion(domainCode);
	occurance = jiffies;
	if (bw == CH_40_MHz_WIDTH) {
		if (!channel_exists(ch, dfsEnabledChannels[domainInd].dfschannelEntry, DFS_MAX_CHANNELS))
			return DFS_SUCCESS;
		DfsAddToNOL(dfsDesc_p, ch, &cf, occurance);
		extChanOffset = macMgmtMlme_Get40MHzExtChannelOffset(ch);
		extChan = DFSGetExtensionChannelOfDFSChan(domainInd, extChanOffset, ch);
		DfsAddToNOL(dfsDesc_p, extChan, &cf, occurance);
	} else if (bw == CH_80_MHz_WIDTH) {
		if (!channel_exists(ch, dfsEnabledChannels[domainInd].dfschannelEntry, DFS_MAX_CHANNELS))
			return DFS_SUCCESS;

		GetDfs80MhzGrpChan(domainInd, ch, DfsDetected80MhzGrpChan);
		for (i = 0; i < 4; i++) {
			if (DfsDetected80MhzGrpChan[i] != 0)
				DfsAddToNOL(dfsDesc_p, DfsDetected80MhzGrpChan[i], &cf, occurance);
			else
				PRINT1(INFO, "ERROR: BW 80Mhz channel is ZERO \n");
		}
	} else if (bw == CH_160_MHz_WIDTH || bw == CH_AUTO_WIDTH) {
		GetDfs160MhzGrpChan(domainInd, ch, DfsDetected160MhzGrpChan);
		for (i = 0; i < 8; i++) {
			if (DfsDetected160MhzGrpChan[i] != 0) {
				if (channel_exists(DfsDetected160MhzGrpChan[i], dfsEnabledChannels[domainInd].dfschannelEntry, DFS_MAX_CHANNELS))
					DfsAddToNOL(dfsDesc_p, DfsDetected160MhzGrpChan[i], &cf, occurance);
			} else {
				PRINT1(INFO, "ERROR: BW 160Mhz channel is ZERO \n");
			}
		}
	} else {
		if (bw != CH_20_MHz_WIDTH)
			return DFS_FAILURE;

		if (channel_exists(ch, dfsEnabledChannels[domainInd].dfschannelEntry, DFS_MAX_CHANNELS))
			DfsAddToNOL(dfsDesc_p, ch, &cf, occurance);
		//DfsAddToNOL( dfsDesc_p, ch, cf, occurance);
	}
	return DFS_SUCCESS;
}

static void NOCTimeoutHandler(void *data_p)
{
	WLDBG_INFO(DBG_LEVEL_1, "enter NOC timeout handler\n");

	DfsRemoveFromNOL((DfsApDesc *) data_p);
	//wlReadyStart160MhzBcn((DfsApDesc *)data_p);
}

void GetDfs80MhzGrpChan(UINT8 domainInd, UINT8 channel, UINT8 * GrpChan)
{
	UINT8 tmpExtChnlOffset;
	UINT8 tmpextChan;
	UINT8 tmpChan;
	UINT8 i, j = 0;

	memset(GrpChan, 0, 4);
	tmpChan = channel;
	tmpExtChnlOffset = EXT_CH_ABOVE_CTRL_CH;

	for (i = 0; i < 4; i++) {
		tmpextChan = DFSGetExtensionChannelOfDFSChan(domainInd, tmpExtChnlOffset, tmpChan);
		if (tmpextChan) {
			GrpChan[j] = tmpextChan;
			tmpChan = tmpextChan;
			j++;;
		} else {
			tmpChan = channel;
			break;
		}
	}
	tmpExtChnlOffset = EXT_CH_BELOW_CTRL_CH;
	for (i = 0; i < 4; i++) {
		tmpextChan = DFSGetExtensionChannelOfDFSChan(domainInd, tmpExtChnlOffset, tmpChan);
		if (tmpextChan) {
			GrpChan[j] = tmpextChan;
			tmpChan = tmpextChan;
			j++;
		} else
			break;
	}
	GrpChan[j] = channel;
}

void DfsGetNOLChannelList(List * nocList_p, UINT8 * channel)
{
	NOCListItem *ptr = (NOCListItem *) nocList_p->head;

	while (ptr) {
		*channel = ptr->channel;
		channel++;
		ptr = ptr->nxt;
	}
	return;
}

void Get80MhzNOLchanList(UINT8 domainInd)
{
	UINT8 *ptr1, *ptr2;

	ptr1 = Grp80MhzNOLchanList;
	ptr2 = NOLchannelList;
	while (*ptr2 != 0) {
		GetDfs80MhzGrpChan(domainInd, *ptr2, ptr1);
		ptr1 += 4;
		ptr2++;
	}
}

void Get160MhzNOLchanList(UINT8 domainInd)
{
	UINT8 *ptr1, *ptr2;

	ptr1 = Grp160MhzNOLchanList;
	ptr2 = NOLchannelList;
	while (*ptr2 != 0) {
		GetDfs160MhzGrpChan(domainInd, *ptr2, ptr1);
		ptr1 += 8;
		ptr2++;
	}
}

#ifdef CONCURRENT_DFS_SUPPORT
void prepareNewTargetChannels(DfsApDesc * dfsDesc_p, u8 channel, U8 IsFromAux)
{
	if (dfsDesc_p->currChanInfo.chanflag.radiomode == RADIO_MODE_7x7p1x1) {
		if (IsFromAux) {
			dfsDesc_p->currChanInfo.channel2 = channel;
		} else {
			dfsDesc_p->currChanInfo.channel = channel;
		}
		return;
	}

	if (dfsDesc_p->currChanInfo.chanflag.ChnlWidth == CH_160_MHz_WIDTH) {
		extern u_int8_t GetSecondChannel(u_int8_t Channel, u_int8_t bw);
		//separate to two channels
		dfsDesc_p->currChanInfo.channel = channel;
		dfsDesc_p->currChanInfo.channel2 = GetSecondChannel(channel, CH_160_MHz_WIDTH);
	} else			//CH_80_MHz_WIDTH
	{
		if (dfsDesc_p->currChanInfo.from == DFS_AUX) {
			dfsDesc_p->currChanInfo.channel2 = channel;
		} else {
			dfsDesc_p->currChanInfo.channel = channel;
		}
	}
}

UINT8 DfsDecideNewTargetChannel(struct net_device *dev, DfsApDesc * dfsDesc_p, BOOLEAN bChkDFSgroup, UINT8 IsFromAux)
#else
UINT8 DfsDecideNewTargetChannel(struct net_device *dev, DfsApDesc * dfsDesc_p, BOOLEAN bChkDFSgroup)
#endif				/* CONCURRENT_DFS_SUPPORT */
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, dev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	MIB_PHY_DSSS_TABLE *PhyDSSSTable = mib->PhyDSSSTable;
	UINT8 domainCode;
	UINT8 randInd = 0;
	int i, j, count = 0;
	UINT8 testchannel;
	UINT8 chanList[IEEE_80211_MAX_NUMBER_OF_CHANNELS];
	UINT8 extChan = 0;
	UINT8 extChanOffset;
	UINT8 domainInd, domainInd_IEEERegion;
	UINT8 bw;
	UINT8 retChan;
	UINT16 ch;
	CHNL_FLAGS cf;
#ifdef CONCURRENT_DFS_SUPPORT
	UINT16 ch_another_path = 0;
#endif
	UINT8 dfs_en_ch = 0;

	if (!dfsDesc_p)
		return 0;

	bw = dfsDesc_p->currChanInfo.chanflag.ChnlWidth;
	ch = dfsDesc_p->currChanInfo.channel;
	cf = dfsDesc_p->currChanInfo.chanflag;

#ifdef CONCURRENT_DFS_SUPPORT
	if (dfsDesc_p->currChanInfo.chanflag.radiomode == RADIO_MODE_7x7p1x1) {
		ch_another_path = dfsDesc_p->CtlChanInfo.channel;

		if (IsFromAux) {
			bw = dfsDesc_p->CtlChanInfo.chanflag.ChnlWidth;
			ch = dfsDesc_p->CtlChanInfo.channel;
			cf = dfsDesc_p->CtlChanInfo.chanflag;
			ch_another_path = dfsDesc_p->currChanInfo.channel;
		}
	} else if (dfsDesc_p->currChanInfo.chanflag.radiomode == RADIO_MODE_80p80) {
		ch_another_path = dfsDesc_p->currChanInfo.channel2;
	}
#endif				/* CONCURRENT_DFS_SUPPORT */

	domainCode = domainGetDomain();	// get current domain
	for (i = 0; i < domainGetSizeOfdfsEnabledChannels(); i++)
		if (domainCode == dfsEnabledChannels[i].domainCode)
			break;
	if (i == domainGetSizeOfdfsEnabledChannels()) {
		PRINT1(INFO, "Could not find the domain\n");
		return 0;
	}
	domainInd = i;
	domainInd_IEEERegion = GetDomainIndxIEEERegion(domainCode);
	if (bw == CH_40_MHz_WIDTH) {
		extChanOffset = cf.ExtChnlOffset;
		extChan = DFSGetExtensionChannelOfDFSChan(domainInd, extChanOffset, ch);
	}

	/* Now create a list of eligible channels */
	if ((bw == CH_80_MHz_WIDTH) || (bw == CH_40_MHz_WIDTH) || (bw == CH_20_MHz_WIDTH)) {

		if (bw == CH_80_MHz_WIDTH)
			GetDfs80MhzGrpChan(domainInd, ch, DfsDetected80MhzGrpChan);

		for (j = 0; j < DFS_MAX_CHANNELS; j++) {
			if (priv->wlpd_p->dfs_ctl_chlist[0] != 0) {
				if (priv->wlpd_p->dfs_ctl_chlist[priv->wlpd_p->dfs_ctl_ch_index] == 0)
					priv->wlpd_p->dfs_ctl_ch_index = 0;
				dfs_en_ch = priv->wlpd_p->dfs_ctl_chlist[priv->wlpd_p->dfs_ctl_ch_index];
				priv->wlpd_p->dfs_ctl_ch_index++;
			} else {
				dfs_en_ch = dfsEnabledChannels[domainInd].dfschannelEntry[j];
			}

			if (dfs_en_ch == 0)
				continue;
			if (dfs_en_ch == ch)
				continue;
#ifdef CONCURRENT_DFS_SUPPORT
			if ((dfsDesc_p->currChanInfo.chanflag.radiomode == RADIO_MODE_7x7p1x1) ||
			    (dfsDesc_p->currChanInfo.chanflag.radiomode == RADIO_MODE_80p80)) {
				if (IsTheSameGroup(ch, dfs_en_ch, bw)) {
					continue;
				}
				if (IsTheSameGroup(ch_another_path, dfs_en_ch, bw)) {
					continue;
				}
			}
#endif				/* CONCURRENT_DFS_SUPPORT */
			if (bw == CH_40_MHz_WIDTH)
				if (extChan && dfs_en_ch == extChan)
					continue;

			testchannel = dfs_en_ch;
			if (bw == CH_40_MHz_WIDTH) {
				extChanOffset = macMgmtMlme_Get40MHzExtChannelOffset(testchannel);
				extChan = DFSGetExtensionChannelOfDFSChan(domainInd, extChanOffset, testchannel);
				if (!extChan)
					continue;
				if (DfsFindInNOL(&dfsDesc_p->NOCList, testchannel) == DFS_SUCCESS)
					continue;
				if (IsTestChannelHiddenInNOL_40MHz(dfsDesc_p, testchannel) == DFS_FAILURE)
					chanList[count++] = testchannel;
			} else if (bw == CH_80_MHz_WIDTH) {
				if (IsTestchannel80MzChannel(testchannel, domainInd_IEEERegion) == FALSE)
					continue;
				if (!dfs_probability)
					if (channel_exists(testchannel, DfsDetected80MhzGrpChan, 4))
						continue;
				if (DfsFindInNOL(&dfsDesc_p->NOCList, testchannel) == DFS_SUCCESS)
					continue;
				if (IsTestChannelHiddenInNOL_80MHz(dfsDesc_p, testchannel) == DFS_FAILURE)
					chanList[count++] = testchannel;
			} else if (bw == CH_20_MHz_WIDTH) {
				if (DfsFindInNOL(&dfsDesc_p->NOCList, testchannel) == DFS_FAILURE)
					chanList[count++] = testchannel;
			} else
				PRINT1(INFO, "unknown BW \n");
		}
	} else {
		extern UINT8 *GetRegionChanList(UINT8 domainInd_IEEERegion);
		UINT8 *pChanList = NULL;

		if (priv->wlpd_p->dfs_ctl_chlist[0] != 0)
			pChanList = priv->wlpd_p->dfs_ctl_chlist;
		else
			pChanList = GetRegionChanList(domainInd_IEEERegion);
		GetDfs160MhzGrpChan(domainInd, ch, DfsDetected160MhzGrpChan);
		for (j = 0; j < IEEE_80211_MAX_NUMBER_OF_CHANNELS; j++) {
			testchannel = pChanList[j];
			if (testchannel < 36 || testchannel >= 165)
				continue;
			if (testchannel == ch)
				continue;

#ifdef CONCURRENT_DFS_SUPPORT
			if (dfsDesc_p->currChanInfo.chanflag.radiomode == RADIO_MODE_80p80) {
				if (IsTheSameGroup(ch, testchannel, CH_160_MHz_WIDTH)) {
					continue;
				}
				if (IsTheSameGroup(ch_another_path, testchannel, CH_160_MHz_WIDTH)) {
					continue;
				}
			}
#endif				/* CONCURRENT_DFS_SUPPORT */

			if (Is160MzChannel(testchannel, domainInd_IEEERegion) == FALSE)
				continue;
			if (!dfs_probability) {
				if (!bChkDFSgroup)
					if (channel_exists(testchannel, DfsDetected160MhzGrpChan, 8))
						continue;
			}
			if (DfsFindInNOL(&dfsDesc_p->NOCList, testchannel) == DFS_SUCCESS)
				continue;
			if (IsTestChannelHiddenInNOL_160MHz(dfsDesc_p, testchannel) == DFS_FAILURE)
				chanList[count++] = testchannel;
		}
	}
	if (!count) {
		UINT8 fallbackCnt;
		UINT8 IEEERegionChannel_5G[IEEE_80211_MAX_NUMBER_OF_CHANNELS];
		UINT8 FallbackChannelList[IEEE_80211_MAX_NUMBER_OF_CHANNELS];

#ifdef CONCURRENT_DFS_SUPPORT
		if (dfsDesc_p->currChanInfo.chanflag.radiomode == RADIO_MODE_7x7p1x1) {
			if (IsFromAux) {
				return 36;
			}
		}
#endif

		memset(IEEERegionChannel_5G, 0, IEEE_80211_MAX_NUMBER_OF_CHANNELS);
		memset(FallbackChannelList, 0, IEEE_80211_MAX_NUMBER_OF_CHANNELS);
		Get5GChannelList(domainCode, IEEERegionChannel_5G);
		fallbackCnt = 0;
		for (i = 0; i < IEEE_80211_MAX_NUMBER_OF_CHANNELS; i++) {
			if (IEEERegionChannel_5G[i] >= 36 && IEEERegionChannel_5G[i] < 165) {
				if (DfsFindInNOL(&dfsDesc_p->NOCList, IEEERegionChannel_5G[i]) == DFS_SUCCESS)
					continue;
				if (ch == IEEERegionChannel_5G[i])
					continue;
#ifdef CONCURRENT_DFS_SUPPORT
				if ((dfsDesc_p->currChanInfo.chanflag.radiomode == RADIO_MODE_80p80) &&
				    (IsTheSameGroup(ch, IEEERegionChannel_5G[i], bw) ||
				     IsTheSameGroup(ch_another_path, IEEERegionChannel_5G[i], bw))) {
					continue;
				}
#endif
				FallbackChannelList[fallbackCnt] = IEEERegionChannel_5G[i];
				//PRINT1(INFO, "fallback ch %d \n", FallbackChannelList[fallbackCnt]);
				fallbackCnt++;
			}
		}
		if (!fallbackCnt) {
#ifdef CONCURRENT_DFS_SUPPORT
			if (dfsDesc_p->currChanInfo.chanflag.radiomode == RADIO_MODE_80p80) {
				dfsDesc_p->currChanInfo.chanflag.radiomode = RADIO_MODE_NORMAL;
				dfsDesc_p->currChanInfo.channel2 = 0;
				PhyDSSSTable->Chanflag.ChnlWidth2 = 0;
				PhyDSSSTable->SecChan = 0;
				PhyDSSSTable->Chanflag.radiomode = RADIO_MODE_NORMAL;
				retChan = 36;
				if (dfsDesc_p->currChanInfo.from == DFS_MAIN)
					goto fallbackchannel;
				else
					return 36;
			} else
#endif				/* CONCURRENT_DFS_SUPPORT */
				return 36;	//for now
		}

		if (bw == CH_80_MHz_WIDTH) {
			retChan = FindFallbackChannel(fallbackCnt, FallbackChannelList, CH_80_MHz_WIDTH);
			goto fallbackchannel;
		} else if ((bw == CH_160_MHz_WIDTH) || (bw == CH_AUTO_WIDTH)) {
#ifdef SADDLE_80MHz
			PhyDSSSTable->Chanflag.ChnlWidth = CH_80_MHz_WIDTH;
#else
			PhyDSSSTable->Chanflag.ChnlWidth = CH_20_MHz_WIDTH;
#endif
			PhyDSSSTable->Chanflag.ExtChnlOffset = EXT_CH_ABOVE_CTRL_CH;
			PhyDSSSTable->CurrChan = 36;
			dfsDesc_p->currChanInfo.channel = 36;
			memcpy(&dfsDesc_p->currChanInfo.chanflag, &PhyDSSSTable->Chanflag, sizeof(CHNL_FLAGS));
#ifdef SADDLE_80MHz
			PRINT1(INFO, "change to ch:36, BW 80MHz \n");
#else
			PRINT1(INFO, "change to ch:36, BW 20MHz \n");
#endif

#ifdef SOC_W906X
			dfsDesc_p->currChanInfo.chanflag.radiomode = RADIO_MODE_NORMAL;
			dfsDesc_p->currChanInfo.channel2 = 0;
			PhyDSSSTable->Chanflag.ChnlWidth2 = 0;
			PhyDSSSTable->SecChan = 0;
			PhyDSSSTable->Chanflag.radiomode = RADIO_MODE_NORMAL;
#endif
			return 36;

		} else if (bw == CH_40_MHz_WIDTH) {
			retChan = FindFallbackChannel(fallbackCnt, FallbackChannelList, CH_40_MHz_WIDTH);
			goto fallbackchannel;
		} else {
			//20 Mhz BW
			randInd = jiffies % fallbackCnt;
			retChan = FallbackChannelList[randInd];
			goto fallbackchannel;
		}
	}
	// pick a random channel that does not exist in the NOC
	randInd = jiffies % count;
	retChan = chanList[randInd];

 fallbackchannel:
	prepareNewTargetChannels(dfsDesc_p, retChan, IsFromAux);

	return retChan;
}

DFS_STATUS IsTestChannelHiddenInNOL_40MHz(DfsApDesc * dfsDesc_p, UINT8 testchannel)
{
	UINT8 i, j;

	for (i = 0; i < domainGetSizeOfGrpChList40Mhz() / sizeof(GRP_CHANNEL_LIST_40Mhz); i++) {
		if (channel_exists(testchannel, GrpChList40Mhz[i].channelEntry, 2))
			break;
	}
	for (j = 0; j < 2; j++) {
		if (DfsFindInNOL(&dfsDesc_p->NOCList, GrpChList40Mhz[i].channelEntry[j]) == DFS_SUCCESS)
			break;
	}
	if (j != 2)
		return DFS_SUCCESS;
	else
		return DFS_FAILURE;
}

DFS_STATUS IsTestChannelHiddenInNOL_80MHz(DfsApDesc * dfsDesc_p, UINT8 testchannel)
{
	UINT8 i, j;

	for (i = 0; i < domainGetSizeOfGrpChList80Mhz() / sizeof(GRP_CHANNEL_LIST_80Mhz); i++) {
		if (channel_exists(testchannel, GrpChList80Mhz[i].channelEntry, 4))
			break;
	}

	for (j = 0; j < 4; j++) {
		if (DfsFindInNOL(&dfsDesc_p->NOCList, GrpChList80Mhz[i].channelEntry[j]) == DFS_SUCCESS)
			break;
	}
	if (j != 4)
		return DFS_SUCCESS;
	else
		return DFS_FAILURE;
}

DFS_STATUS IsTestChannelHiddenInNOL_160MHz(DfsApDesc * dfsDesc_p, UINT8 testchannel)
{
	UINT8 i, j;

	for (i = 0; i < domainGetSizeOfGrpChList160Mhz() / sizeof(GRP_CHANNEL_LIST_160Mhz); i++) {
		if (channel_exists(testchannel, GrpChList160Mhz[i].channelEntry, 8))
			break;
	}

	for (j = 0; j < 8; j++) {
		if (DfsFindInNOL(&dfsDesc_p->NOCList, GrpChList160Mhz[i].channelEntry[j]) == DFS_SUCCESS)
			break;
	}
	if (j != 8)
		return DFS_SUCCESS;
	else
		return DFS_FAILURE;
}

DFS_STATUS DfsFindInNOL(List * nocList_p, UINT8 channel)
{
	NOCListItem *ptr = (NOCListItem *) nocList_p->head;

	if (dfs_test)
		return DFS_FAILURE;

	while (ptr) {
		if (ptr->channel == channel)
			return DFS_SUCCESS;
		ptr = ptr->nxt;
	}
	return DFS_FAILURE;
}

void DfsPrintNOLChannelDetails(DfsAp * me, char *NOLPrintStr_p, int maxLength)
{
	int len = 0;
	int copylen = 0;
	NOCListItem *nocListItem_p;
	List *list_p;
	char *buf = NULL;

	if (!me || !NOLPrintStr_p || maxLength == 0)
		return;

	if ((buf = wl_kmalloc(maxLength, GFP_KERNEL)) == NULL)
		return;

	list_p = &me->dfsApDesc.NOCList;
	len += sprintf(buf + len, "***** NOC LIST *******\n");
	nocListItem_p = (NOCListItem *) list_p->head;
	while (nocListItem_p) {
		len += sprintf(buf + len, "Channel:%d\t BW:%d MHz\tAge:%lu seconds\n",
			       nocListItem_p->channel, nocListItem_p->BW, (jiffies - nocListItem_p->occurance) / HZ);
		nocListItem_p = nocListItem_p->nxt;
	}
	copylen = len > maxLength ? maxLength : len;
	strncpy(NOLPrintStr_p, buf, copylen);
	NOLPrintStr_p[copylen] = '\0';
	wl_kfree(buf);
}

DFS_STATE DfsGetCurrentState(DfsAp * me)
{
#ifdef AP_MAC_LINUX
	struct net_device *dev;
#endif
	if (!me)
		return DFS_STATE_UNKNOWN;

#ifdef AP_MAC_LINUX
	dev = me->pNetDev;
#endif
	if (!macMgmtMlme_DfsEnabled(dev))
		return DFS_STATE_UNKNOWN;

	return me->dfsApDesc.currState;
}

DFS_STATUS DfsPresentInNOL(struct net_device * dev, UINT8 channel)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, dev);
	struct wlprivate_data *wlpd_p = priv->wlpd_p;
	DfsAp *me = wlpd_p->pdfsApMain;
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	MIB_PHY_DSSS_TABLE *PhyDSSSTable = mib->PhyDSSSTable;
	UINT8 domainCode, domainInd_IEEERegion;

	if (!me)
		return DFS_FAILURE;

	if (!macMgmtMlme_DfsEnabled(dev))
		return DFS_FAILURE;

	if ((DfsGetCurrentState(me)) == DFS_STATE_CSA)
		return DFS_SUCCESS;

	if (DfsFindInNOL(&me->dfsApDesc.NOCList, channel))
		return DFS_SUCCESS;

	domainCode = domainGetDomain();	// get current domain
	domainInd_IEEERegion = GetDomainIndxIEEERegion(domainCode);
	if (PhyDSSSTable->Chanflag.ChnlWidth == CH_20_MHz_WIDTH)
		return DFS_FAILURE;

	if (PhyDSSSTable->Chanflag.ChnlWidth == CH_40_MHz_WIDTH) {
		if (IsTestchannel40MzChannel(channel, domainInd_IEEERegion) == TRUE)
			return (IsTestChannelHiddenInNOL_40MHz(&me->dfsApDesc, channel));
		else
			return DFS_FAILURE;
	} else if (PhyDSSSTable->Chanflag.ChnlWidth == CH_80_MHz_WIDTH) {
		if (IsTestchannel80MzChannel(channel, domainInd_IEEERegion) == FALSE) {
			if (IsTestchannel40MzChannel(channel, domainInd_IEEERegion) == TRUE)
				return (IsTestChannelHiddenInNOL_40MHz(&me->dfsApDesc, channel));
			else
				return DFS_FAILURE;
		} else
			return (IsTestChannelHiddenInNOL_80MHz(&me->dfsApDesc, channel));
	} else if ((PhyDSSSTable->Chanflag.ChnlWidth == CH_AUTO_WIDTH) || (PhyDSSSTable->Chanflag.ChnlWidth == CH_160_MHz_WIDTH)) {
		if (Is160MzChannel(channel, domainInd_IEEERegion) == FALSE) {
			if (IsTestchannel80MzChannel(channel, domainInd_IEEERegion) == FALSE) {
				if (IsTestchannel40MzChannel(channel, domainInd_IEEERegion) == TRUE)
					return (IsTestChannelHiddenInNOL_40MHz(&me->dfsApDesc, channel));
				else
					return DFS_FAILURE;
			} else
				return (IsTestChannelHiddenInNOL_80MHz(&me->dfsApDesc, channel));
		} else
			return (IsTestChannelHiddenInNOL_160MHz(&me->dfsApDesc, channel));
	} else {
		PRINT1(INFO, "DfsPresentInNOL: error, unknown BW %d\n", PhyDSSSTable->Chanflag.ChnlWidth);
		return DFS_FAILURE;
	}
}

UINT16 DfsGetCACTimeOut(DfsAp * me)
{
	if (!me)
		return 0;
	return (me->dfsApDesc.CACTimeOut / 10);
}

UINT16 DfsGetNOCTimeOut(DfsAp * me)
{
	if (!me)
		return 0;
	return (me->dfsApDesc.NOCTimeOut / 10);
}

DFS_STATUS DfsSetCACTimeOut(DfsAp * me, UINT16 timeout)
{
	if (!me)
		return DFS_FAILURE;
	me->dfsApDesc.CACTimeOut = timeout * 10;	//timeout in seconds
	return DFS_SUCCESS;
}

DFS_STATUS DfsSetNOCTimeOut(DfsAp * me, UINT16 timeout)
{
	if (!me)
		return DFS_FAILURE;
	me->dfsApDesc.NOCTimeOut = timeout * 10;	// timeout in seconds
	return DFS_SUCCESS;
}

UINT8 DFSGetExtensionChannelOfDFSChan(UINT8 domain, UINT8 extChnlOffset, UINT8 channel)
{
	SINT8 extChanInd = 0;
	UINT8 extChan = 0;
	int j;

	if (extChnlOffset == EXT_CH_BELOW_CTRL_CH)
		extChanInd = -1;
	else
		extChanInd = 1;
	/* Find out the extension channel */
	for (j = 0; j < DFS_MAX_CHANNELS; j++) {
		if (extChanInd && (j + extChanInd >= 0) && ((j + extChanInd) < DFS_MAX_CHANNELS)) {
			if (dfsEnabledChannels[domain].dfschannelEntry[j] == channel) {
				extChan = dfsEnabledChannels[domain].dfschannelEntry[j + extChanInd];
				return extChan;
			}
		}
	}
	return 0;
}

UINT8 DFSGetCurrentRadarDetectionMode(DfsAp * me, UINT8 channel, UINT8 secChan, CHNL_FLAGS * chanFlag)
{
	DfsChanInfo chanInfo;
	UINT8 action = DR_DFS_DISABLE;

	chanInfo.channel = channel;
	chanInfo.channel2 = secChan;
	chanInfo.chanflag = *chanFlag;

	if (!me)
		return DR_DFS_DISABLE;

	if (!DfsEnabledChannel(me->pNetDev, &chanInfo))
		return DR_DFS_DISABLE;

	if ((DfsGetCurrentState(me) == DFS_STATE_OPERATIONAL))
		action = DR_IN_SERVICE_MONITOR_START;	//Normal mode radar detection
	else if ((DfsGetCurrentState(me) == DFS_STATE_SCAN))
		action = DR_CHK_CHANNEL_AVAILABLE_START;	//CAC mode radar detection
	else
		action = DR_DFS_DISABLE;
	return action;
}

extern void DisarmEMCACTimer(DfsAp * me);
void DFSApReset(DfsAp * me)
{
	NOCListItem *nocListItem_p = NULL;
	DfsApDesc *dfsDesc_p = NULL;

	if (!me)
		return;

	dfsDesc_p = &me->dfsApDesc;
	nocListItem_p = (NOCListItem *) ListGetItem(&dfsDesc_p->NOCList);

	DisarmCACTimer(me);
	DisarmAuxCACTimer(me);
	DisarmEMCACTimer(me);
	if ((DfsGetCurrentState(me)) == DFS_STATE_SCAN)
		TimerRemove(&dfsDesc_p->CACTimer);	/* Stops CAC timer */

	if (nocListItem_p == NULL) {
		memset(dfsDesc_p, 0, sizeof(DfsApDesc));
		return;
	}
	TimerRemove(&dfsDesc_p->NOCTimer);
	TimerRemove(&dfsDesc_p->CSATimer);
	wl_kfree(nocListItem_p);
	while ((nocListItem_p = (NOCListItem *) ListGetItem(&dfsDesc_p->NOCList)) != NULL) {
		wl_kfree(nocListItem_p);
	}
	memset(dfsDesc_p, 0, sizeof(DfsApDesc));
}

void FireCACTimer(DfsAp * me)
{
	DfsApDesc *dfsDesc_p = NULL;
	struct net_device *dev;
	struct wlprivate *wlpptr = NULL;
	struct wlprivate_data *wlpd_p = NULL;

	if (me == NULL) {
		PRINT1(INFO, "FireCACTimer: error: NULL pointer\n");
		return;
	}

	dev = me->pNetDev;
	wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
	wlpd_p = wlpptr->wlpd_p;

	*(u32 *) (&((SMAC_CTRL_BLK_st *) wlpptr->ioBase0)->config.rxEnable) = 1;

	dfsDesc_p = (DfsApDesc *) & me->dfsApDesc;
	TimerFireIn(&dfsDesc_p->CACTimer, 1, &CACTimeoutHandler, (unsigned char *)me, dfsDesc_p->CACTimeOut);
	wlpd_p->bCACTimerFired = TRUE;
	set_dfs_status(me, DFS_STATE_SCAN);
	return;
}

void DisarmCACTimer(DfsAp * me)
{
	DfsApDesc *dfsDesc_p = NULL;
	struct net_device *dev;
	struct wlprivate *wlpptr = NULL;
	struct wlprivate_data *wlpd_p = NULL;

	if (me == NULL) {
		PRINT1(INFO, "DisarmCACTimer: error: NULL pointer\n");
		return;
	}
	dev = me->pNetDev;
	wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
	wlpd_p = wlpptr->wlpd_p;
	dfsDesc_p = (DfsApDesc *) & me->dfsApDesc;
	TimerDisarm(&dfsDesc_p->CACTimer);
	wlpd_p->bCACTimerFired = FALSE;
}

#ifdef CONCURRENT_DFS_SUPPORT
void AuxCACTimeoutHandler(void *data_p)
{
	DfsAp *me;
	struct net_device *dev;
	struct wlprivate *wlpptr = NULL;
	struct wlprivate_data *wlpd_p = NULL;

	WLDBG_INFO(DBG_LEVEL_1, "enter Aux CAC timeout handler\n");
	me = (DfsAp *) data_p;
	dev = me->pNetDev;
	wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
	wlpd_p = wlpptr->wlpd_p;
	me->scnr_ctl_evt(dev, ScnrCtl_CAC_Done, DFS_STATE_OPERATIONAL, 1);
}

void FireAuxCACTimer(DfsAp * me)
{
	DfsApDesc *dfsDesc_p = NULL;
	struct net_device *dev;
	struct wlprivate *wlpptr = NULL;
	struct wlprivate_data *wlpd_p = NULL;
	vmacApInfo_t *vmacSta_p = NULL;
	MIB_802DOT11 *mib = NULL;

	if (me == NULL) {
		PRINT1(INFO, "FireAuxCACTimer: error: NULL pointer\n");
		return;
	}
	dev = me->pNetDev;
	wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
	wlpd_p = wlpptr->wlpd_p;
	dfsDesc_p = (DfsApDesc *) & me->dfsApDesc;
	vmacSta_p = wlpptr->vmacSta_p;
	mib = vmacSta_p->ShadowMib802dot11;
	macMgmtMlme_StartAuxRadarDetection(dev, DR_SCANNER_SERVICE_START);
	if (*(mib->mib_CACTimeOut))
		dfsDesc_p->CtlCACTimeOut = (*(mib->mib_CACTimeOut)) * 10;
	TimerFireIn(&dfsDesc_p->CtlCACTimer, 1, &AuxCACTimeoutHandler, (unsigned char *)me, dfsDesc_p->CtlCACTimeOut);
	me->scnr_ctl_evt(dev, ScnrCtl_Channel_switch_start_cac, DFS_STATE_SCAN, 1);
	return;
}

void DisarmAuxCACTimer(DfsAp * me)
{
	DfsApDesc *dfsDesc_p = NULL;
	struct net_device *dev;
	struct wlprivate *wlpptr = NULL;
	struct wlprivate_data *wlpd_p = NULL;

	if (me == NULL) {
		PRINT1(INFO, "DisarmAuxCACTimer: error: NULL pointer\n");
		return;
	}
	dev = me->pNetDev;
	wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
	wlpd_p = wlpptr->wlpd_p;
	dfsDesc_p = (DfsApDesc *) & me->dfsApDesc;
	TimerDisarm(&dfsDesc_p->CtlCACTimer);
}
#endif				/* CONCURRENT_DFS_SUPPORT */

#endif
