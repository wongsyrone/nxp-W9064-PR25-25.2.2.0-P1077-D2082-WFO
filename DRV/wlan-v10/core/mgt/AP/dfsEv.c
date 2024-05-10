/** @file dfsEv.c
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
* Description:  Handle all the events coming in and out of the DFS State Machines
*
*/
#ifdef MRVL_DFS

#include "wltypes.h"
#include "IEEE_types.h"

#include "mib.h"
#include "osif.h"
#include "timer.h"
#include "dfsMgmt.h"
#include "dfs.h"

#include "ds.h"
#include "smeMain.h"

#include "mhsm.h"
#include "IEEE_types.h"
#include "wldebug.h"
#include "dfsMgmt.h"
#include "dfs.h"
#include "ap8xLnxIntf.h"
#include "domain.h"

UINT32 dfsTraceLogIdx[NUM_OF_WLMACS] = { 0 };

dfsTraceLog_t dfsTraceData[NUM_OF_WLMACS][MAX_DFS_TRACE_LOG];

void
dfsTrace(struct net_device *netdev, UINT8 state, UINT8 event,
	 DfsChanInfo * pInfo, UINT32 tag)
{
	struct wlprivate *wlpptr;
	vmacApInfo_t *vmacSta_p;
	UINT8 intf;

	if (netdev == NULL)
		return;

	wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacSta_p = (vmacApInfo_t *) wlpptr->vmacSta_p;
	intf = vmacSta_p->VMacEntry.phyHwMacIndx;

	if (intf < NUM_OF_WLMACS) {
		dfsTraceData[intf][dfsTraceLogIdx[intf]].timestamp = jiffies;
		dfsTraceData[intf][dfsTraceLogIdx[intf]].state = state;
		dfsTraceData[intf][dfsTraceLogIdx[intf]].event = event;
		dfsTraceData[intf][dfsTraceLogIdx[intf]].tag = tag;

		if (pInfo) {
			dfsTraceData[intf][dfsTraceLogIdx[intf]].chanInfo = 1;
			dfsTraceData[intf][dfsTraceLogIdx[intf]].radiomode =
				pInfo->chanflag.radiomode;
			dfsTraceData[intf][dfsTraceLogIdx[intf]].bw =
				pInfo->chanflag.ChnlWidth;
			dfsTraceData[intf][dfsTraceLogIdx[intf]].chan =
				pInfo->channel;
			dfsTraceData[intf][dfsTraceLogIdx[intf]].isDfs =
				pInfo->chanflag.isDfsChan;
			dfsTraceData[intf][dfsTraceLogIdx[intf]].bw2 =
				pInfo->chanflag.ChnlWidth2;
			dfsTraceData[intf][dfsTraceLogIdx[intf]].chan2 =
				pInfo->channel2;
			dfsTraceData[intf][dfsTraceLogIdx[intf]].isDfs2 =
				pInfo->chanflag.isDfsChan2;
		} else {
			dfsTraceData[intf][dfsTraceLogIdx[intf]].chanInfo = 0;
		}
		dfsTraceLogIdx[intf]++;
		if (dfsTraceLogIdx[intf] >= MAX_DFS_TRACE_LOG) {
			dfsTraceLogIdx[intf] = 0;
		}
	}
}

void
dfsTraceLogPrint(UINT8 idx, DfsAp * pdfsApMain)
{
	UINT32 id, i, buffLen;
	UINT8 *pBuff;
	dfsTraceLog_t *temp;
	char stateStr[DFS_STATE_MAX][12] = {
		"UNKNOWN", "INIT", "LISTEN", "OPERATIONAL", "CSA",
#ifdef RADAR_SCANNER_SUPPORT
		"IDLE", "NOT_DFS_CH"
#endif
	};
	char eventStr[16][20] = {
		"CHANNEL_CHANGE_EVT", "RADAR_EVT", "CAC_EXPIRY_EVT",
			"WL_RESET_EVT",
		"CSA_EXPIRY_EVT", "Unknown", "Unknown", "Unknown",
		"Unknown", "Unknown", "Unknown", "Unknown",
		"Unknown", "Unknown", "EXIT", "ENTER"
	};

	if (idx < NUM_OF_WLMACS) {
		buffLen = sizeof(dfsTraceLog_t) * MAX_DFS_TRACE_LOG;
		if (buffLen < 4000)
			buffLen = 4000;

		pBuff = wl_kmalloc(buffLen, GFP_KERNEL);

		if (pBuff) {
			temp = (dfsTraceLog_t *) pBuff;

			id = dfsTraceLogIdx[idx];

			memcpy((void *)temp, (void *)&dfsTraceData[idx],
			       sizeof(dfsTraceLog_t) * MAX_DFS_TRACE_LOG);
			for (i = 0; i < MAX_DFS_TRACE_LOG; i++) {
				if ((temp[id].state == 0) &&
				    (temp[id].event == 0) &&
				    (temp[id].tag == 0)) {
					id++;
					if (id >= MAX_DFS_TRACE_LOG)
						id = 0;
					continue;
				}
				if (temp[id].state < DFS_STATE_MAX) {
					printk("[DFS-%d] ts=0x%08x state=%s event=%s tag=0x%08x\n", id, temp[id].timestamp, stateStr[temp[id].state], eventStr[temp[id].event], temp[id].tag);
				} else {
					printk("[DFS-%d] ts=0x%08x state=0x%x event=0x%x tag=0x%08x\n", id, temp[id].timestamp, temp[id].state, temp[id].event, temp[id].tag);
				}

				if (temp[id].chanInfo) {
					printk("[DFS-%d]     radiomode=%d bw=%d ch=%d isDfs=%d bw2=%d ch2=%d isDfs2=%d\n", id, temp[id].radiomode, temp[id].bw, temp[id].chan, temp[id].isDfs, temp[id].bw2, temp[id].chan2, temp[id].isDfs2);
				}
				printk("\n");
				id++;
				if (id >= MAX_DFS_TRACE_LOG)
					id = 0;
			}
			DfsPrintNOLChannelDetails(pdfsApMain, pBuff, 4000);
			printk("%s\n", (char *)pBuff);
			wl_kfree(pBuff);
		}
	}
}

void
DfsInit(struct net_device *pNetDev, struct wlprivate_data *wlpd_p)
{
	DfsAp *pdfsApMain = NULL;

	if (!wlpd_p)
		return;

	/* Init the DFS state machines */
	if ((pdfsApMain =
	     (DfsAp *) wl_kmalloc(sizeof(DfsAp), GFP_KERNEL)) == NULL) {
		PRINT1(INFO, "Cannot allocate memory for DFS SM\n");
		return;
	}
	wlpd_p->pdfsApMain = (DfsAp *) pdfsApMain;
#ifdef RADAR_SCANNER_SUPPORT
	//Pete, testing for now. 
	pdfsApMain->scnr_send_evt = dfs_controller_send_event;
#ifdef CONCURRENT_DFS_SUPPORT
	pdfsApMain->scnr_ctl_evt = concurrent_dfs_proc;
#endif /* CONCURRENT_DFS_SUPPORT */
#endif
	DFSApCtor(pNetDev, pdfsApMain);
	mhsm_initialize(&pdfsApMain->super, &pdfsApMain->sTop);
#ifdef CONCURRENT_DFS_SUPPORT
	DFSCtlInit(pNetDev);
#endif /* CONCURRENT_DFS_SUPPORT */
	return;
}

void
DfsDeInit(struct wlprivate_data *wlpd_p)
{
	/* DeInit the DFS state machines */
	if (!wlpd_p || !wlpd_p->pdfsApMain)
		return;
	DFSApReset(wlpd_p->pdfsApMain);
	wl_kfree(wlpd_p->pdfsApMain);
	wlpd_p->pdfsApMain = NULL;
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
SINT8
evtDFSMsg(struct net_device * dev, UINT8 * message)
{
	MhsmEvent_t dfsMsg;
	DfsCmd_t *dfsCmd_p;
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, dev);
	struct wlprivate_data *wlpd_p = priv->wlpd_p;
	DfsApMsg dfsApMsg;

	WLDBG_ENTER(DBG_CLASS_INFO);
	if (!message || !wlpd_p->pdfsApMain)
		return 1;

	dfsCmd_p = (DfsCmd_t *) message;
	switch (dfsCmd_p->CmdType) {
	case DFS_CMD_CHANNEL_CHANGE:
		WLDBG_INFO(DBG_LEVEL_15,
			   "evtDFSMsg: DFS_CMD_CHANNEL_CHANGE message received. \n");
		dfsApMsg.mgtMsg = (UINT8 *) (&(dfsCmd_p->Body.chInfo));
		dfsMsg.event = CHANNEL_CHANGE_EVT;
		dfsMsg.pBody = (unsigned char *)&dfsApMsg;
		mhsm_send_event(&wlpd_p->pdfsApMain->super, &dfsMsg);
		break;
	case DFS_CMD_RADAR_DETECTION:
		WLDBG_INFO(DBG_LEVEL_15,
			   "evtDFSMsg: DFS_CMD_RADAR_DETECTION message received. \n");
		dfsApMsg.mgtMsg = (UINT8 *) (&(dfsCmd_p->Body.chInfo));
		dfsMsg.event = RADAR_EVT;
		dfsMsg.pBody = (void *)&dfsApMsg;
		mhsm_send_event(&wlpd_p->pdfsApMain->super, &dfsMsg);
		break;
	case DFS_CMD_WL_RESET:
		WLDBG_INFO(DBG_LEVEL_15,
			   "evtDFSMsg: DFS_CMD_WL_RESET message received. \n");
//                      dfsApMsg.mgtMsg = (UINT8 *)(&(dfsCmd_p->Body.chInfo));
		dfsMsg.event = WL_RESET_EVT;
		dfsMsg.pBody = (unsigned char *)&dfsApMsg;
		mhsm_send_event(&wlpd_p->pdfsApMain->super, &dfsMsg);
		break;
	default:
		return 1;
	}
	return 1;
}

//Only apply to 5G band. 
void
verify_chan_bw(MIB_PHY_DSSS_TABLE * PhyDSSSTable)
{
	UINT8 domainCode, domainInd_IEEERegion;
	UINT8 channel = PhyDSSSTable->CurrChan;

	domainCode = domainGetDomain();	// get current domain
	domainInd_IEEERegion = GetDomainIndxIEEERegion(domainCode);
	switch (PhyDSSSTable->Chanflag.ChnlWidth) {
	case CH_40_MHz_WIDTH:
		if (IsTestchannel40MzChannel(channel, domainInd_IEEERegion) ==
		    FALSE)
			PhyDSSSTable->Chanflag.ChnlWidth = CH_20_MHz_WIDTH;
		break;
	case CH_80_MHz_WIDTH:
		if (IsTestchannel80MzChannel(channel, domainInd_IEEERegion) ==
		    FALSE) {
			if (IsTestchannel40MzChannel
			    (channel, domainInd_IEEERegion) == FALSE)
				PhyDSSSTable->Chanflag.ChnlWidth =
					CH_20_MHz_WIDTH;
			else
				PhyDSSSTable->Chanflag.ChnlWidth =
					CH_40_MHz_WIDTH;
		}
		break;
	case CH_160_MHz_WIDTH:
	case CH_AUTO_WIDTH:
		if (Is160MzChannel(channel, domainInd_IEEERegion) == FALSE) {
			if (IsTestchannel80MzChannel
			    (channel, domainInd_IEEERegion) == FALSE) {
				if (IsTestchannel40MzChannel
				    (channel, domainInd_IEEERegion) == FALSE)
					PhyDSSSTable->Chanflag.ChnlWidth =
						CH_20_MHz_WIDTH;
				else
					PhyDSSSTable->Chanflag.ChnlWidth =
						CH_40_MHz_WIDTH;
			} else
				PhyDSSSTable->Chanflag.ChnlWidth =
					CH_80_MHz_WIDTH;
		}
		break;
	}
}

#ifdef CONCURRENT_DFS_SUPPORT
void
dfs_proc_aux(struct net_device *dev,
	     SCANNER_CTL_EVENT event, DFS_STATE dfs_status, UINT8 IsFromAux)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
	DfsApDesc *dfsDesc_p;

	if (!wlpptr->wlpd_p || !wlpptr->wlpd_p->pdfsApMain) {
		printk("[%s] DFS not init yet! \n", dev->name);
		return;
	}
#ifdef RADAR_SCANNER_SUPPORT
	if (wlpptr->wlpd_p->ext_scnr_en) {
		return concurrent_dfs_proc(dev, event, dfs_status, IsFromAux);
	}
#endif

	dfsDesc_p = &wlpptr->wlpd_p->pdfsApMain->dfsApDesc;

	if (dfsDesc_p->currChanInfo.chanflag.radiomode == RADIO_MODE_80p80) {
		extern int wlRadarDetection(struct net_device *netdev,
					    UINT8 from);

		wlRadarDetection(wlpptr->netDev, DFS_AUX);
	}
}
#endif

#ifdef RADAR_SCANNER_SUPPORT
void
dfs_send_iwevcustom_event(struct net_device *dev, char *str)
{
	union iwreq_data iwrq;
	char buf[IW_CUSTOM_MAX];

	memset(&iwrq, 0, sizeof(union iwreq_data));
	memset(buf, 0, sizeof(buf));

	snprintf(buf, sizeof(buf) - 1, "%s", str);
	iwrq.data.pointer = buf;
	iwrq.data.length = strlen(buf) + 1;

	wireless_send_event(dev, IWEVCUSTOM, &iwrq, buf);
	return;
}

void
dfs_controller_send_event(struct net_device *dev,
			  SCANNER_CTL_EVENT event, DFS_STATE dfs_status)
{
	UINT8 evt_str[32], stat_str[32];
	char tmp[128];
	MIB_802DOT11 *mib;
	struct wlprivate *wlpptr = NULL;
	vmacApInfo_t *vmacSta_p = NULL;
	MIB_PHY_DSSS_TABLE *PhyDSSSTable;

	wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
	vmacSta_p = (vmacApInfo_t *) wlpptr->vmacSta_p;
	mib = vmacSta_p->ShadowMib802dot11;
	PhyDSSSTable = mib->PhyDSSSTable;

	switch (event) {
	case ScnrCtl_Radar_Detected:
		strcpy(evt_str, "EVENT_RADAR_DETECTED");
		break;
	case ScnrCtl_CAC_Done:
		strcpy(evt_str, "EVENT_CAC_DONE");
		break;
	case ScnrCtl_Switched_to_subch:
		strcpy(evt_str, "EVENT_SW_TO_SUBCH");
		break;
	case ScnrCtl_Channel_switch_start_cac:
		strcpy(evt_str, "EVENT_SW_CH_START_CAC");
		break;
	case ScnrCtl_Starting_CSA:
		strcpy(evt_str, "EVENT_STARTING_CSA");
		break;
	case ScnrCtl_Chan_Operational:
		strcpy(evt_str, "EVENT_CH_OP");
		break;
	default:
		strcpy(evt_str, "EVENT_UNKNOW");
	}

	switch (dfs_status) {
	case DFS_STATE_UNKNOWN:
		strcpy(stat_str, "STATE_UNKNOWN");
		break;
	case DFS_STATE_INIT:
		strcpy(stat_str, "STATE_INIT");
		break;
	case DFS_STATE_SCAN:
		strcpy(stat_str, "STATE_SCAN");
		break;
	case DFS_STATE_OPERATIONAL:
		strcpy(stat_str, "STATE_OPERATIONAL");
		break;
	case DFS_STATE_CSA:
		strcpy(stat_str, "STATE_CSA");
		break;
	case DFS_STATE_IDLE:
		strcpy(stat_str, "STATE_IDLE");
		break;
	case DFS_STATE_NOT_DFS_CH:
		strcpy(stat_str, "STATE_NOT_DFS_CH");
		break;
	default:
		strcpy(stat_str, "Unknown Status");
	}

	printk("\nDFS_CTL_EVENT: dev:[%s] Event:[%s] Status:[%s] Chan:[%d]\n",
	       dev->name, evt_str, stat_str, PhyDSSSTable->CurrChan);

	sprintf(tmp, "mrvl,w8964,%s,ch,%d,stat,%s,bw,%d",
		evt_str, PhyDSSSTable->CurrChan, stat_str,
		PhyDSSSTable->Chanflag.ChnlWidth);
	dfs_send_iwevcustom_event(dev, tmp);
}

DFS_STATUS
dfs_sme_channel_switch(struct net_device *dev,
		       UINT16 channel, UINT8 no_cac, UINT8 do_csa)
{
	smeQ_MgmtMsg_t *sme_msg = NULL;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
	vmacApInfo_t *vmacSta_p = (vmacApInfo_t *) wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	MIB_PHY_DSSS_TABLE *PhyDSSSTable = mib->PhyDSSSTable;

	sme_msg =
		(smeQ_MgmtMsg_t *) wl_kmalloc(sizeof(smeQ_MgmtMsg_t),
					      GFP_ATOMIC);
	if (!sme_msg) {
		PRINT1(INFO, "%s: Failed to allocate message buffer ...\n",
		       __func__);
		return DFS_FAILURE;
	}
	PhyDSSSTable->CurrChan = channel;
	verify_chan_bw(PhyDSSSTable);
	memset(sme_msg, 0, sizeof(smeQ_MgmtMsg_t));
	sme_msg->MsgType = SME_NOTIFY_CHANNELSWITCH_CFRM;
	sme_msg->Msg.ChanSwitchCfrm.result = 1;
	sme_msg->Msg.ChanSwitchCfrm.chInfo.channel = channel;
	sme_msg->Msg.ChanSwitchCfrm.chInfo.channel2 = PhyDSSSTable->SecChan;	//keep the old one
	sme_msg->Msg.ChanSwitchCfrm.chInfo.no_cac = no_cac;
	sme_msg->Msg.ChanSwitchCfrm.chInfo.do_csa = do_csa;
	memcpy(&sme_msg->Msg.ChanSwitchCfrm.chInfo.chanflag,
	       &PhyDSSSTable->Chanflag, sizeof(CHNL_FLAGS));
	sme_msg->vmacSta_p = vmacSta_p;
	smeQ_MgmtWriteNoBlock(sme_msg);
	wl_kfree((UINT8 *) sme_msg);
	return DFS_SUCCESS;
}

#ifdef CONCURRENT_DFS_SUPPORT
DFS_STATUS
IsTheSameGroup(UINT16 ch1, UINT16 ch2, UINT8 bw)
{
	UINT8 i = 0, range = 0, group_size;

	if (bw == CH_80_MHz_WIDTH) {
		range = GetNumOfChList80Mhz();
		group_size = 4;

		for (i = 0; i < range; i++) {
			if (channel_exists
			    (ch1, GrpChList80Mhz[i].channelEntry, group_size) &&
			    channel_exists(ch2, GrpChList80Mhz[i].channelEntry,
					   group_size))
				break;
		}
	} else if (bw == CH_40_MHz_WIDTH) {
		range = GetNumOfChList40Mhz();
		group_size = 2;

		for (i = 0; i < range; i++) {
			if (channel_exists
			    (ch1, GrpChList40Mhz[i].channelEntry, group_size) &&
			    channel_exists(ch2, GrpChList40Mhz[i].channelEntry,
					   group_size))
				break;
		}
	} else if (bw == CH_160_MHz_WIDTH) {
		range = GetNumOfChList160Mhz();
		group_size = 8;

		for (i = 0; i < range; i++) {
			if (channel_exists
			    (ch1, GrpChList160Mhz[i].channelEntry, group_size)
			    && channel_exists(ch2,
					      GrpChList160Mhz[i].channelEntry,
					      group_size))
				break;
		}
	} else if (bw == CH_20_MHz_WIDTH) {
		if (ch1 == ch2)
			return DFS_SUCCESS;
		else
			return DFS_FAILURE;
	}

	if (i == range)
		return DFS_FAILURE;

	return DFS_SUCCESS;
}

DFS_STATE
get_dfs_ctl_status(DfsApDesc * dfsDesc_p, UINT8 path)
{
	if (path == DFS_PATH_NORMAL)
		return dfsDesc_p->CtlOpState;
	else
		return dfsDesc_p->CtlAuxState;
}

void
set_dfs_ctl_status(DfsApDesc * dfsDesc_p, UINT8 path, DFS_STATE status)
{
	if (path == DFS_PATH_NORMAL)
		dfsDesc_p->CtlOpState = status;
	else
		dfsDesc_p->CtlAuxState = status;
}

void
add_dfs_ctl_ready_channel(DfsApDesc * dfsDesc_p, UINT16 channel)
{
	dfsDesc_p->CtlReadyCh = channel;
	//printk("[DFS] Ready Ch: %d\n", dfsDesc_p->CtlReadyCh);
}

UINT16
pop_dfs_ctl_ready_channel(DfsApDesc * dfsDesc_p)
{
	UINT16 readyCh = 0;

	if (dfsDesc_p == NULL || dfsDesc_p->CtlReadyCh == 0)
		return 0;
	else {
		readyCh = dfsDesc_p->CtlReadyCh;
		dfsDesc_p->CtlReadyCh = 0;
		return readyCh;
	}
}

void
remove_dfs_ctl_ready_channel(DfsApDesc * dfsDesc_p, UINT16 channel, UINT8 bw)
{
	if (IsTheSameGroup(channel, dfsDesc_p->CtlReadyCh, bw) == DFS_SUCCESS)
		dfsDesc_p->CtlReadyCh = 0;
}

DFS_STATUS
dfs_set_aux_ch(struct net_device *dev, UINT16 channel)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	DfsApDesc *dfsDesc_p;
	//MIB_PHY_DSSS_TABLE *PhyDSSSTable=mib->PhyDSSSTable;
	extern int wlchannelSet(struct net_device *netdev, int channel,
				int Channel2, CHNL_FLAGS chanflag,
				UINT8 initRateTable);
	extern BOOLEAN UpdateCurrentChannelInMIB(vmacApInfo_t * vmacSta_p,
						 UINT32 channel);

	dfsDesc_p = &wlpptr->wlpd_p->pdfsApMain->dfsApDesc;
#if 1
	mib->PhyDSSSTable->Chanflag.radiomode = RADIO_MODE_7x7p1x1;
	mib->PhyDSSSTable->Chanflag.FreqBand =
		dfsDesc_p->CtlChanInfo.chanflag.FreqBand;
	mib->PhyDSSSTable->Chanflag.ChnlWidth =
		dfsDesc_p->CtlChanInfo.chanflag.ChnlWidth;
	mib->PhyDSSSTable->Chanflag.FreqBand2 =
		dfsDesc_p->currChanInfo.chanflag.FreqBand;
	mib->PhyDSSSTable->Chanflag.ChnlWidth2 =
		dfsDesc_p->currChanInfo.chanflag.ChnlWidth;
	mib->PhyDSSSTable->CurrChan = dfsDesc_p->currChanInfo.channel;
	mib->PhyDSSSTable->SecChan = channel;
#endif
	if (UpdateCurrentChannelInMIB
	    (vmacSta_p, dfsDesc_p->currChanInfo.channel)) {
		mib_Update();

		if (wlchannelSet
		    (dev, channel, dfsDesc_p->currChanInfo.channel,
		     dfsDesc_p->CtlChanInfo.chanflag, 0)) {
			WLDBG_EXIT_INFO(DBG_LEVEL_15, "setting channel failed");
			return DFS_FAILURE;
		}
	}
	return DFS_SUCCESS;
}

DFS_STATUS
dfs_set_op_ch(struct net_device * dev, UINT16 channel)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	DfsApDesc *dfsDesc_p;
	//MIB_PHY_DSSS_TABLE *PhyDSSSTable=mib->PhyDSSSTable;
	extern int wlchannelSet(struct net_device *netdev, int channel,
				int Channel2, CHNL_FLAGS chanflag,
				UINT8 initRateTable);
	extern BOOLEAN UpdateCurrentChannelInMIB(vmacApInfo_t * vmacSta_p,
						 UINT32 channel);

	dfsDesc_p = &wlpptr->wlpd_p->pdfsApMain->dfsApDesc;
#if 1
	mib->PhyDSSSTable->Chanflag.radiomode = RADIO_MODE_7x7p1x1;
	mib->PhyDSSSTable->Chanflag.FreqBand =
		dfsDesc_p->CtlChanInfo.chanflag.FreqBand;
	mib->PhyDSSSTable->Chanflag.ChnlWidth =
		dfsDesc_p->CtlChanInfo.chanflag.ChnlWidth;
	mib->PhyDSSSTable->Chanflag.FreqBand2 =
		dfsDesc_p->currChanInfo.chanflag.FreqBand;
	mib->PhyDSSSTable->Chanflag.ChnlWidth2 =
		dfsDesc_p->currChanInfo.chanflag.ChnlWidth;
	mib->PhyDSSSTable->CurrChan = channel;
	mib->PhyDSSSTable->SecChan = dfsDesc_p->CtlChanInfo.channel;
#endif
	if (UpdateCurrentChannelInMIB(vmacSta_p, channel)) {
		mib_Update();

		if (wlchannelSet
		    (dev, dfsDesc_p->CtlChanInfo.channel, channel,
		     dfsDesc_p->CtlChanInfo.chanflag, 0)) {
			WLDBG_EXIT_INFO(DBG_LEVEL_15, "setting channel failed");
			return DFS_FAILURE;
		}
	}
	return DFS_SUCCESS;
}

void
dfs_set_channel_switch(struct net_device *dev,
		       UINT16 channel,
		       UINT8 no_cac, UINT8 do_csa, UINT8 IsFromAux)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
	UINT16 set_ch = 0;
	DfsApDesc *dfsDesc_p;

	dfsDesc_p = &wlpptr->wlpd_p->pdfsApMain->dfsApDesc;

	if (IsFromAux == DFS_PATH_DEDICATED) {
		if (channel == 0) {
			// decide a new channel
			set_ch = DfsDecideNewTargetChannel(dev, dfsDesc_p,
							   FALSE, IsFromAux);

			// restore the channel
			dfsDesc_p->CtlChanInfo.channel = set_ch;

			// switch to new channel
			dfs_set_aux_ch(dev, set_ch);
		} else {
			// restore the channel
			dfsDesc_p->CtlChanInfo.channel = channel;
			// switch to new channel
			dfs_set_aux_ch(dev, channel);
		}
		// Start Aux ch CAC
		if (channel != 36 && set_ch != 36)
			FireAuxCACTimer(wlpptr->wlpd_p->pdfsApMain);
		set_dfs_ctl_status(dfsDesc_p, DFS_PATH_DEDICATED,
				   DFS_STATE_SCAN);
	} else if (IsFromAux == DFS_PATH_NORMAL) {
		if (channel == 0) {
			// decide a new channel
			set_ch = DfsDecideNewTargetChannel(dev, dfsDesc_p,
							   FALSE, IsFromAux);
			// restore the channel
			dfsDesc_p->currChanInfo.channel = set_ch;

			// switch to new channel
			dfs_sme_channel_switch(dev, set_ch, no_cac, do_csa);
		} else {
			// restore the channel
			dfsDesc_p->currChanInfo.channel = channel;

			// switch to new channel
			dfs_sme_channel_switch(dev, channel, no_cac, do_csa);
		}
		//set_dfs_ctl_status(dfsDesc_p, DFS_PATH_NORMAL, DFS_STATE_SCAN);
	}
}

void
DFSCtlInit(struct net_device *pNetDev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, pNetDev);
	DfsApDesc *dfsDesc_p;
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	UINT16 channel = 0;

	dfsDesc_p = &wlpptr->wlpd_p->pdfsApMain->dfsApDesc;

	if (wlpptr->wlpd_p->ext_scnr_en) {
		// Turn on 3/7+1 mode
		mib->PhyDSSSTable->Chanflag.radiomode = RADIO_MODE_7x7p1x1;
		// follow up normal path's BW and Band 
		mib->PhyDSSSTable->Chanflag.FreqBand2 =
			mib->PhyDSSSTable->Chanflag.FreqBand;
		mib->PhyDSSSTable->Chanflag.ChnlWidth2 =
			mib->PhyDSSSTable->Chanflag.ChnlWidth;

		// Decide Aux's initial channel                 
		dfsDesc_p->CtlChanInfo.channel = mib->PhyDSSSTable->CurrChan;
		memcpy(&dfsDesc_p->CtlChanInfo.chanflag,
		       &mib->PhyDSSSTable->Chanflag, sizeof(CHNL_FLAGS));
		memcpy(&dfsDesc_p->currChanInfo.chanflag,
		       &mib->PhyDSSSTable->Chanflag, sizeof(CHNL_FLAGS));

		channel =
			DfsDecideNewTargetChannel(pNetDev, dfsDesc_p, FALSE,
						  TRUE);
		mib->PhyDSSSTable->SecChan = channel;

		// Store to CtlChanInfo
		dfsDesc_p->CtlChanInfo.channel = channel;
		dfsDesc_p->currChanInfo.channel = mib->PhyDSSSTable->CurrChan;

		// switch to new channel
		dfs_set_aux_ch(pNetDev, channel);
		// Start Aux Ch CAC
		FireAuxCACTimer(wlpptr->wlpd_p->pdfsApMain);
	} else if (mib->PhyDSSSTable->Chanflag.radiomode == RADIO_MODE_7x7p1x1) {
		// Set radio mode to normal
		mib->PhyDSSSTable->Chanflag.radiomode = RADIO_MODE_NORMAL;
		mib->PhyDSSSTable->SecChan = 0;
		mib->PhyDSSSTable->Chanflag.ChnlWidth2 = 0;
		mib->PhyDSSSTable->Chanflag.FreqBand2 = 0;
	}
}

extern void EM_update_cac_status(vmacApInfo_t * vmacSta_p, UINT8 ch,
				 UINT8 status, UINT32 indication);

void
concurrent_dfs_proc(struct net_device *dev,
		    SCANNER_CTL_EVENT event,
		    DFS_STATE dfs_status, UINT8 IsFromAux)
									//DfsApDesc *dfsDesc_p)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
	//vmacApInfo_t *vmacSta_p=(vmacApInfo_t *)wlpptr->vmacSta_p;
	//MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	//MIB_PHY_DSSS_TABLE *PhyDSSSTable = mib->PhyDSSSTable;
	extern void macMgmtMlme_StopAuxRadarDetection(struct net_device *dev,
						      UINT8 detectionMode);
	DfsApDesc *dfsDesc_p;
	UINT8 bw, path;
	UINT16 ch;

	if (!wlpptr->wlpd_p->ext_scnr_en)
		return;

	dfsDesc_p = &wlpptr->wlpd_p->pdfsApMain->dfsApDesc;

	if (IsFromAux) {
		bw = dfsDesc_p->CtlChanInfo.chanflag.ChnlWidth;
		ch = dfsDesc_p->CtlChanInfo.channel;
		path = DFS_PATH_DEDICATED;
	} else {
		bw = dfsDesc_p->currChanInfo.chanflag.ChnlWidth;
		ch = dfsDesc_p->currChanInfo.channel;
		path = DFS_PATH_NORMAL;
	}

	printk("[DFS] concurrent_dfs_proc: %s, Path:[%d] Event:[%d] Status:[%d] Channel:[%d] BW:[%d]\n", dev->name, path, event, dfs_status, ch, bw);

	// sync up bw, path A follow the normal path
	if (dfsDesc_p->CtlChanInfo.chanflag.ChnlWidth !=
	    dfsDesc_p->currChanInfo.chanflag.ChnlWidth) {

		// if new bw is larger than old one, the ready channel is not meaningful
		if (dfsDesc_p->CtlChanInfo.chanflag.ChnlWidth != 0 &&
		    dfsDesc_p->currChanInfo.chanflag.ChnlWidth >
		    dfsDesc_p->CtlChanInfo.chanflag.ChnlWidth) {
			remove_dfs_ctl_ready_channel(dfsDesc_p,
						     dfsDesc_p->CtlReadyCh,
						     dfsDesc_p->currChanInfo.
						     chanflag.ChnlWidth);
		}
		memcpy(&dfsDesc_p->CtlChanInfo.chanflag,
		       &dfsDesc_p->currChanInfo.chanflag, sizeof(CHNL_FLAGS));

	}

	switch (event) {
	case ScnrCtl_Radar_Detected:
		printk("[DFS] EVT_RADAR_DETECTED\n");
		if (path == DFS_PATH_DEDICATED) {
			// Stop monitor first 
			macMgmtMlme_StopAuxRadarDetection(dev,
							  DR_SCANNER_SERVICE_STOP);
			/* Update NOL, (path dedicated and path normal share the same NOL) */
			UpdateNOL(dfsDesc_p, IsFromAux);
			// remove the ch from ready channel
			remove_dfs_ctl_ready_channel(dfsDesc_p, ch, bw);
			// chose a target channel
			if (dfsDesc_p->EMCACState == DFS_STATE_EM_SCAN ||
			    dfsDesc_p->EMCACState == DFS_STATE_EM_SCAN_ALL) {
				EM_update_cac_status(wlpptr->vmacSta_p, ch,
						     1 /*radar channel */ ,
						     1 /*indecation */ );
			} else {
				dfs_set_channel_switch(dev, 0, 0, 0,
						       DFS_PATH_DEDICATED);
			}
		} else if (path == DFS_PATH_NORMAL) {
			/* Update NOL, (path dedicated and path normal share the same NOL)  */
			UpdateNOL(dfsDesc_p, IsFromAux);
			// remove the ch from ready channel     
			remove_dfs_ctl_ready_channel(dfsDesc_p, ch, bw);

			if ((get_dfs_ctl_status(dfsDesc_p, DFS_PATH_DEDICATED)
			     == DFS_STATE_OPERATIONAL) &&
			    (!IsTheSameGroup
			     (dfsDesc_p->currChanInfo.channel,
			      dfsDesc_p->CtlChanInfo.channel, bw))) {
				UINT16 readyCh = 0;
				if ((readyCh =
				     pop_dfs_ctl_ready_channel(dfsDesc_p)) !=
				    0) {
					dfs_set_channel_switch(dev, readyCh, 1,
							       0,
							       DFS_PATH_NORMAL);
					dfs_set_channel_switch(dev, 0, 0, 0,
							       DFS_PATH_DEDICATED);
				} else {	// OK channel is empty 
					dfs_set_channel_switch(dev, 0, 0, 1,
							       DFS_PATH_NORMAL);
					dfs_set_channel_switch(dev, 0, 0, 0,
							       DFS_PATH_DEDICATED);
				}
			} else {	// path A scanning, cac not done
				if (get_dfs_ctl_status
				    (dfsDesc_p,
				     DFS_PATH_NORMAL) == DFS_STATE_OPERATIONAL)
					dfs_set_channel_switch(dev, 0, 0, 1,
							       DFS_PATH_NORMAL);
				else
					dfs_set_channel_switch(dev, 0, 0, 0,
							       DFS_PATH_NORMAL);
			}
		}
		set_dfs_ctl_status(dfsDesc_p, path, dfs_status);
		break;
	case ScnrCtl_CAC_Done:
		printk("[DFS] EVT_CAC_DONE\n");
		if (path == DFS_PATH_DEDICATED)
			add_dfs_ctl_ready_channel(dfsDesc_p, ch);
		set_dfs_ctl_status(dfsDesc_p, path, dfs_status);
		//dfsDesc_p->CtlChanInfo.channel = ch;
		break;
	case ScnrCtl_Switched_to_subch:
		printk("[DFS] EVT_SW_TO_SUBCH\n");
		set_dfs_ctl_status(dfsDesc_p, path, dfs_status);
		break;
	case ScnrCtl_Channel_switch_start_cac:	// after SC4 doing iwconfig wdev0 commit will send out this event 
		printk("[DFS] EVT_SW_CH_START_CAC\n");
		set_dfs_ctl_status(dfsDesc_p, path, dfs_status);
		break;
	case ScnrCtl_Starting_CSA:
		printk("[DFS] EVT_STARTING_CSA\n");
		set_dfs_ctl_status(dfsDesc_p, path, dfs_status);
		break;
	case ScnrCtl_Chan_Operational:
		printk("[DFS] EVT_CH_OP\n");
		set_dfs_ctl_status(dfsDesc_p, path, dfs_status);
		//dfsDesc_p->CtlChanInfo.channel = ch;
		break;
	default:
		printk("[DFS] Not supported DFS mrvl event! %d\n", event);
		break;
	}

}
#endif /* CONCURRENT_DFS_SUPPORT */
#endif /* RADAR_SCANNER_SUPPORT */
#endif
