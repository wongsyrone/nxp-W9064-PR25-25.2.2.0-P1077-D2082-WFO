/** @file dol_core.c
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2019 NXP
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

#include <linux/timer.h>

#include "ap8xLnxVer.h"
#include "ap8xLnxIntf.h"
#include "ap8xLnxBQM.h"
#include "StaDb.h"
#include "ipc-ops.h"
#include "dol-ops.h"
#include "dol_cmd.h"
#include "pe_platform.h"
#include "dol_core.h"

#define DOL_VER_STR      DOL_VER
#define DOL_DESC         "NXP Wifi Data Off Load Module"

#define DOL_CMD_TIMEOUT  3000	/* ms */

static const u16 tx_q_size[2] = { 0x400, 0 };
static const u16 rel_q_size[4] = { 0x4000, 0x4000, 0x4000, 0 };
static const u16 bm_q_size[4] = { 0x400, 0x400, 0x400, 0 };
static const u16 bm_buf_size[4] = { 0x1000, 0x3000, 0x6400, 0 };	/* 4k,12k,25k */
static const u16 bm_buf_max_entries[4] = { 0x6000, 0x3000, 0x1000, 0 };

static char *
dol_core_get_cmd_string(u16 cmd)
{
	int max_entries = 0;
	int curr_cmd = 0;

	static const struct {
		u16 cmd;
		char *cmd_string;
	} cmds[] = {
		{
		DOL_CMD_CHECK_ACTIVE, "CheckActive"}, {
		DOL_CMD_GET_WFO_VERSION, "GetWFOVersion"}, {
		DOL_CMD_START_RADIO, "StartRadio"}, {
		DOL_CMD_STOP_RADIO, "StopRadio"}, {
		DOL_CMD_RADIO_DATA_CTRL, "RadioDataCtrl"}, {
		DOL_CMD_SUSPEND_RADIO, "SuspendRadio"}, {
		DOL_CMD_RADIO_TX_AMPDU_CTRL, "RadioTxAmpduCtrl"}, {
		DOL_CMD_RADIO_RETURN_BUFFER, "RadioReturnBuffer"}, {
		DOL_CMD_RADIO_GET_RX_INFO, "RadioGetRxInfo"}, {
		DOL_CMD_ADD_VIF, "AddVIF"}, {
		DOL_CMD_DEL_VIF, "DelVIF"}, {
		DOL_CMD_VIF_DATA_CTRL, "VIFDataCtrl"}, {
		DOL_CMD_VIF_SET_ISOLATE_GRP_ID, "VIFSetIsolateGrpId"}, {
		DOL_CMD_ADD_STA, "AddSTA"}, {
		DOL_CMD_DEL_STA, "DelSTA"}, {
		DOL_CMD_STA_DATA_CTRL, "STADataCtrl"}, {
		DOL_CMD_STA_TX_AMPDU_CTRL, "STATxAmpduCtrl"}, {
		DOL_CMD_SET_BA_INFO, "SetBaInfo"}, {
		DOL_CMD_SET_BA_REQ, "SetBaReq"}, {
		DOL_CMD_SET_DSCP_WMM_MAPPING, "SetDscpWMMMapping"}, {
		DOL_CMD_GET_STATS, "GetStats"}, {
	DOL_CMD_SET_DBG_CTRL, "SetDbgCtrl"},};

	max_entries = ARRAY_SIZE(cmds);

	for (curr_cmd = 0; curr_cmd < max_entries; curr_cmd++)
		if (cmd == cmds[curr_cmd].cmd)
			return cmds[curr_cmd].cmd_string;

	return "unknown";
}

static void
timer_routine(unsigned long data)
{
	struct wlprivate *wlpptr = (struct wlprivate *)data;
#ifdef DEBUG_DOL_CMD
	struct dolcmd_header *cmd_hdr;
#endif

	wlpptr->wlpd_p->dol.cmd_send_result = -ETIME;
#ifdef DEBUG_DOL_CMD
	cmd_hdr = (struct dolcmd_header *)wlpptr->wlpd_p->dol.cmd_buf;
	printk("command timeout: %04x %d %d\n", cmd_hdr->cmd, cmd_hdr->radio,
	       cmd_hdr->seq_no);
#endif
	up(&wlpptr->wlpd_p->dol.cmd_sema);
}

static void
dol_core_rcv_event(void *data, const void *event, u16 * event_size)
{
	struct wlprivate *wlpptr = (struct wlprivate *)data;
	struct dolevt_header *evt = (struct dolevt_header *)event;
	int i;

	switch (le16_to_cpu(evt->event)) {
	case DOL_EVT_STA_ACTIVE_NOTIFY:
		{
			extern vmacApInfo_t *vmacGetMBssByAddr(vmacApInfo_t *
							       vmacSta_p,
							       UINT8 *
							       macAddr_p);
			struct dol_evt_sta_active_notify *active_notify =
				(struct dol_evt_sta_active_notify *)event;
			IEEEtypes_MacAddr_t sta_addr;
			struct rssi_path_info rssi_path_info;
			struct rxppdu_airtime_evt rxppdu_airtime_evt;
			u64 tx_bytes = 0;
			u64 rx_bytes = 0;
			extStaDb_StaInfo_t *pStaInfo = NULL;
			vmacApInfo_t *vmactem_p;

			for (i = 0; i < active_notify->notify_sta_num; i++) {
				memcpy_fromio(&sta_addr,
					      &active_notify->sta_addr[i],
					      ETH_ALEN);
				memcpy_fromio(&rssi_path_info,
					      &(active_notify->
						rssi_path_info[i]),
					      sizeof(struct rssi_path_info));
				memcpy_fromio(&rxppdu_airtime_evt,
					      &(active_notify->
						rxppdu_airtime_evt[i]),
					      sizeof(struct
						     rxppdu_airtime_evt));
				memcpy_fromio(&tx_bytes,
					      &active_notify->tx_bytes[i],
					      sizeof(u64));
				memcpy_fromio(&rx_bytes,
					      &active_notify->rx_bytes[i],
					      sizeof(u64));

				extStaDb_UpdateAgingTime(wlpptr->vmacSta_p,
							 &sta_addr);
				pStaInfo =
					extStaDb_GetStaInfo(wlpptr->vmacSta_p,
							    &sta_addr,
							    STADB_SKIP_MATCH_VAP);
				if (!pStaInfo) {
					printk("%s(STA ACTIVE NOTIFY): can't find station: %pM\n", __func__, sta_addr);
					continue;
				}
				memcpy(&pStaInfo->RSSI_path, &rssi_path_info,
				       sizeof(struct rssi_path_info));
				memset(&pStaInfo->rxppdu_airtime, 0,
				       sizeof(rxppdu_airtime_t));
				pStaInfo->rxppdu_airtime.rx_tsf =
					ktime_get_ns();
				pStaInfo->rxppdu_airtime.rx_airtime =
					rxppdu_airtime_evt.rx_airtime;
				pStaInfo->rxppdu_airtime.rx_info_aux.ppdu_len =
					rxppdu_airtime_evt.aux_ppdu_len;
				pStaInfo->rxppdu_airtime.rx_info_aux.rxTs =
					rxppdu_airtime_evt.aux_rxTs;
				memcpy(&pStaInfo->rxppdu_airtime.rx_info_aux.
				       rate_info,
				       &rxppdu_airtime_evt.aux_rate_info,
				       sizeof(dbRateInfo_t));
				pStaInfo->rxppdu_airtime.dbg_sum_pktlen = 0;	//rxppdu_airtime_evt.dbg_sum_pktlen;
				pStaInfo->rxppdu_airtime.dbg_sum_pktcnt = 0;	//rxppdu_airtime_evt.dbg_sum_pktcnt;
				pStaInfo->rxppdu_airtime.dbg_su_pktcnt = 0;	//rxppdu_airtime_evt.dbg_su_pktcnt;
				pStaInfo->rxppdu_airtime.dbg_mu_pktcnt = 0;	//rxppdu_airtime_evt.dbg_mu_pktcnt;
				pStaInfo->rxppdu_airtime.dbg_nss =
					rxppdu_airtime_evt.dbg_nss;
				pStaInfo->rxppdu_airtime.dbg_mcs =
					rxppdu_airtime_evt.dbg_mcs;
				pStaInfo->rxppdu_airtime.dbg_bw =
					rxppdu_airtime_evt.dbg_bw;
				pStaInfo->rxppdu_airtime.dbg_gi_ltf =
					rxppdu_airtime_evt.dbg_gi_ltf;
				pStaInfo->rxppdu_airtime.dbg_Ndbps10x =
					rxppdu_airtime_evt.dbg_Ndbps10x;
				pStaInfo->rxppdu_airtime.sum_rx_airtime =
					rxppdu_airtime_evt.sum_rx_airtime;
				pStaInfo->rxppdu_airtime.sum_rx_pktcnt =
					(U64) (rxppdu_airtime_evt.
					       sum_rx_pktcnt);
				pStaInfo->rxppdu_airtime.sum_rx_pktlen =
					rxppdu_airtime_evt.sum_rx_pktlen;
				memcpy(&pStaInfo->rx_info_aux,
				       &pStaInfo->rxppdu_airtime.rx_info_aux,
				       sizeof(rx_info_aux_t));
				pStaInfo->tx_bytes = tx_bytes;
				pStaInfo->rx_bytes = rx_bytes;
				vmactem_p =
					vmacGetMBssByAddr(wlpptr->vmacSta_p,
							  pStaInfo->Bssid);
				if (vmactem_p)
					vmactem_p->dev->last_rx = jiffies;
			}
		}
		break;
	case DOL_EVT_AMPDU_CONTROL:
		{
			struct dol_evt_ampdu_control *ampdu_control =
				(struct dol_evt_ampdu_control *)event;
			extern void enableAmpduTx(vmacApInfo_t * vmacSta_p,
						  UINT8 * macaddr, UINT8 tid);
			UINT8 sta_addr[ETH_ALEN];
			extStaDb_StaInfo_t *pStaInfo = NULL;
			struct wlprivate *wlp;
			int i;

			memcpy_fromio(sta_addr, ampdu_control->sta_addr,
				      ETH_ALEN);

			pStaInfo =
				extStaDb_GetStaInfo(wlpptr->vmacSta_p,
						    (IEEEtypes_MacAddr_t *)
						    sta_addr,
						    STADB_SKIP_MATCH_VAP);
			if (!pStaInfo) {
				printk("%s(AMPDU CONTROL): can't find station: %pM\n", __func__, sta_addr);
				break;
			}

			for (i = 0; i < wlpptr->wlpd_p->vmacIndex; i++) {
				wlp = NETDEV_PRIV_P(struct wlprivate,
						    wlpptr->vdev[i]);
				if (!memcmp
				    (wlp->vmacSta_p->macBssId, pStaInfo->Bssid,
				     ETH_ALEN))
					break;
			}
			if (i == wlpptr->wlpd_p->vmacIndex) {
				printk("%s(AMPDU CONTROL): can't find VAP: %pM\n", __func__, sta_addr);
				break;
			}

			if (ampdu_control->enable)
				enableAmpduTx(wlp->vmacSta_p, sta_addr,
					      ampdu_control->tid);
			else
				disableAmpduTx(wlp->vmacSta_p, sta_addr,
					       ampdu_control->tid);
		}
		break;
	case DOL_EVT_FREE_BMQ13:
		{
			struct dol_evt_free_bmq13 *free_bmq13 =
				(struct dol_evt_free_bmq13 *)event;
			bm_pe_hw_t pe_hw;

			memcpy_fromio(&pe_hw, &free_bmq13->pe_hw,
				      sizeof(bm_pe_hw_t));
			wlRxBufFillBMEM_Q13(wlpptr->netDev, &pe_hw);
		}
		break;
	case DOL_EVT_OMI_CONTROL:
		{
			struct dol_evt_omi_event *omi;
			extStaDb_StaInfo_t *pStaInfo = NULL;
			IEEEtypes_AcontrolInfoOm_t acontrol_om;
			UINT8 *msg_buf;
			union iwreq_data wreq;
			UINT8 mac[6];

			omi = (struct dol_evt_omi_event *)event;
			acontrol_om.om_control = omi->om_control;

			memcpy_fromio(mac, omi->sta_addr, ETH_ALEN);

			if ((pStaInfo =
			     extStaDb_GetStaInfo(wlpptr->vmacSta_p,
						 (IEEEtypes_MacAddr_t *) mac,
						 STADB_SKIP_MATCH_VAP)) ==
			    NULL) {
				printk("OMI sta not found: %u\n", omi->stnid);
				break;
			}

			if (pStaInfo->operating_mode.ulmu_disable !=
			    acontrol_om.ulmu_disable) {
				msg_buf = wl_kmalloc(IW_CUSTOM_MAX, GFP_KERNEL);
				if (msg_buf == NULL) {
					printk("kmalloc failed for OMI event\n");
					return;
				}

				if (acontrol_om.ulmu_disable == 1) {
					printk("qos NULL,"
					       "acontrol_om.chbw %d acontrol_om.rxnss %d,"
					       "acontrol_om.tx_nsts %d,"
					       "acontrol_om.ulmu_disable %d\n",
					       acontrol_om.chbw,
					       acontrol_om.rxnss,
					       acontrol_om.tx_nsts,
					       acontrol_om.ulmu_disable);
					sprintf(msg_buf,
						"wlmgr: mumode ul_ofdma_disable stnid:%d",
						pStaInfo->StnId);
				} else {
					sprintf(msg_buf,
						"wlmgr: mumode ul_ofdma_enable stnid:%d",
						pStaInfo->StnId);
				}
				memset(&wreq, 0, sizeof(wreq));
				wreq.data.length = strlen(msg_buf);

				printk("%s\n", msg_buf);
				wireless_send_event(pStaInfo->dev, IWEVCUSTOM,
						    &wreq, msg_buf);
				wl_kfree(msg_buf);
			}

			if (pStaInfo->operating_mode.om_control !=
			    acontrol_om.om_control)
				pStaInfo->operating_mode.om_control =
					acontrol_om.om_control;

		}
		break;
	default:
		break;
	}
}

static void
dol_core_rcv_pkt(void *data, struct sk_buff *skb, bool is_data)
{
	struct wlprivate *wlpptr = (struct wlprivate *)data;

	if (is_data) {
		skb_queue_tail(&wlpptr->wlpd_p->recv_q_data, skb);
		wlpptr->RxQId = (1 << RX_Q_DATA);
	} else {
		printk("%s: received non data packet\n", __func__);
		wl_free_skb(skb);
	}

#ifdef USE_TASKLET
	tasklet_schedule(&wlpptr->wlpd_p->rxtask);
#else
	schedule_work(&wlpptr->wlpd_p->rxtask);
#endif
}

static void
dol_core_rcv_cmd(void *data, const void *msg, u16 * msg_size)
{
	struct wlprivate *wlpptr = (struct wlprivate *)data;
	struct dol_ctrl *ctrl;
	struct dolcmd_header *cmd_hdr, *cmd_reply;
	int hdr_size = sizeof(struct dolcmd_header);

	ctrl = &wlpptr->wlpd_p->dol;
	cmd_hdr = (struct dolcmd_header *)ctrl->cmd_buf;
	cmd_reply = (struct dolcmd_header *)msg;
	ctrl->cmd_send_result = 0;
	if (cmd_hdr->seq_no == cmd_reply->seq_no) {
		if (cmd_hdr->radio != cmd_reply->radio)
			ctrl->cmd_send_result = -ENODEV;
		if (cmd_hdr->cmd != cmd_reply->cmd)
			ctrl->cmd_send_result = -EINVAL;
		if (!ctrl->cmd_send_result)
			memcpy_fromio((u8 *) cmd_hdr + hdr_size,
				      (u8 *) cmd_reply + hdr_size,
				      *msg_size - hdr_size);
#ifdef DEBUG_DOL_CMD
		printk("command done: %04x %d %d\n", cmd_hdr->cmd,
		       cmd_hdr->radio, cmd_hdr->seq_no);
#endif
		up(&ctrl->cmd_sema);
	}
#ifdef DEBUG_DOL_CMD
	else
		printk("command out of sequence: send: %d, reply: %d\n",
		       cmd_hdr->seq_no, cmd_reply->seq_no);
#endif
}

static int
dol_core_exec_cmd(struct wlprivate *wlpptr, u16 cmd, bool wait_result)
{
	struct dol_ctrl *ctrl;
	struct dolcmd_header *cmd_hdr;
	int rc;

	might_sleep();

	ctrl = &wlpptr->wlpd_p->dol;
	cmd_hdr = (struct dolcmd_header *)ctrl->cmd_buf;
	cmd_hdr->seq_no = cpu_to_le16(ctrl->seq_no++);
	ctrl->cmd_buf_len = cmd_hdr->len;

	if (wlpptr->wlpd_p->smon.exceptionDolHangCause) {
		WLDBG_ERROR(DBG_LEVEL_0,
			    "HM is doing WFO/FW recovery, drop current command: %d %s!\n",
			    cmd, dol_core_get_cmd_string(cmd));
		return -EIO;
	}

	rc = ipc_send_cmd(wlpptr, ctrl->cmd_buf, ctrl->cmd_buf_len);

	if (rc)
		WLDBG_ERROR(DBG_LEVEL_0, "failed to send command: %d %s!\n",
			    cmd, dol_core_get_cmd_string(cmd));
	else {
#ifdef DEBUG_DOL_CMD
		printk("send cmd: %04x %d %d\n", cmd_hdr->cmd, cmd_hdr->radio,
		       cmd_hdr->seq_no);
#endif
		if (!wait_result)
			return rc;

		ctrl->cmd_send_result = 0;
		mod_timer(&ctrl->cmd_timeout, jiffies +
			  msecs_to_jiffies(DOL_CMD_TIMEOUT));
		down(&ctrl->cmd_sema);
		rc = ctrl->cmd_send_result;
		if ((rc != -ETIME) && timer_pending(&ctrl->cmd_timeout)) {
#ifdef DEBUG_DOL_CMD
			printk("delete timer: %04x %d %d\n", cmd_hdr->cmd,
			       cmd_hdr->radio, cmd_hdr->seq_no);
#endif
			del_timer_sync(&ctrl->cmd_timeout);
		}
		if (rc) {
			WLDBG_ERROR(DBG_LEVEL_0,
				    "(%d)send command (%04x:%s) error: %d!\n",
				    cmd_hdr->radio, cmd,
				    dol_core_get_cmd_string(cmd), rc);

			if (wlpptr->wlpd_p->bfwreset == FALSE)
				wlpptr->wlpd_p->smon.exceptionDolHangCause |= WFO_DOL_CMDTO;	//flag Dol cmd Timeout
		}
		//reset check counter
		wlpptr->wlpd_p->smon.DolCmdTOChkIvl = 0;

		if (cmd_hdr->result) {
			WLDBG_ERROR(DBG_LEVEL_0,
				    "(%d)command (%04x:%s) error: %d!\n",
				    cmd_hdr->radio, cmd,
				    dol_core_get_cmd_string(cmd),
				    le16_to_cpu(cmd_hdr->result));
			rc = -EREMOTEIO;
		}
	}

	return rc;
}

static void
dol_core_del_pkts_via_sta(struct wlprivate_data *wlpd_p, u8 * addr)
{
	struct sk_buff *skb, *tmp;
	unsigned long flags;

	spin_lock_irqsave(&wlpd_p->recv_q_data.lock, flags);
	skb_queue_walk_safe(&wlpd_p->recv_q_data, skb, tmp) {
		if (!memcmp(&skb->data[6], addr, ETH_ALEN)) {
			__skb_unlink(skb, &wlpd_p->recv_q_data);
			wl_free_skb(skb);
		}
	}
	spin_unlock_irqrestore(&wlpd_p->recv_q_data.lock, flags);
}

static int
dol_core_radio_return_buffer(struct wlprivate_data *wlpd_p,
			     struct trigger_cmd *delay_cmd)
{
	struct dol_cmd_radio_return_buffer *pcmd;
	struct dol_ctrl *dol = &wlpd_p->dol;
	struct trigger_cmd *cmd, *next;
	int return_num = 0;

	pcmd = (struct dol_cmd_radio_return_buffer *)&dol->cmd_buf[0];

	mutex_lock(&dol->cmd_mutex);

	memset(pcmd, 0x00, sizeof(*pcmd));
	pcmd->cmd_hdr.radio = cpu_to_le16(delay_cmd->rid);
	pcmd->cmd_hdr.cmd = cpu_to_le16(DOL_CMD_RADIO_RETURN_BUFFER);
	pcmd->cmd_hdr.len = cpu_to_le16(sizeof(*pcmd));
	pcmd->pkt_hdr_addr[return_num++] = cpu_to_le64(delay_cmd->pkt_hdr_addr);
	SPIN_LOCK_BH(&wlpd_p->locks.delayCmdLock);
	list_for_each_entry_safe(cmd, next, &wlpd_p->delay_cmd_list, list) {
		if (cmd->cmd == DOL_CMD_RADIO_RETURN_BUFFER) {
			pcmd->pkt_hdr_addr[return_num++] =
				cpu_to_le64(cmd->pkt_hdr_addr);
			list_del(&cmd->list);
			wl_kfree(cmd);
		}
		if (return_num >= MAX_RETURN_PKT_NUM)
			break;
	}
	SPIN_UNLOCK_BH(&wlpd_p->locks.delayCmdLock);
	pcmd->return_num = return_num;
	wlpd_p->bm_release_request_ipc += return_num;

	if (dol_core_exec_cmd
	    (wlpd_p->masterwlp, DOL_CMD_RADIO_RETURN_BUFFER, false)) {
		mutex_unlock(&dol->cmd_mutex);
		return -EIO;
	}

	mutex_unlock(&dol->cmd_mutex);

	return 0;
}

static int
dol_core_add_sta(struct wlprivate_data *wlpd_p, struct trigger_cmd *delay_cmd)
{
	struct dol_cmd_add_sta *pcmd;
	struct dol_ctrl *dol = &wlpd_p->dol;

	pcmd = (struct dol_cmd_add_sta *)&dol->cmd_buf[0];

	mutex_lock(&dol->cmd_mutex);

	memset(pcmd, 0x00, sizeof(*pcmd));
	pcmd->cmd_hdr.radio = cpu_to_le16(delay_cmd->rid);
	pcmd->cmd_hdr.cmd = cpu_to_le16(DOL_CMD_ADD_STA);
	pcmd->cmd_hdr.len = cpu_to_le16(sizeof(*pcmd));
	pcmd->vid = cpu_to_le32(delay_cmd->vid);
	memcpy(pcmd->sta_mac, delay_cmd->sta_addr, ETH_ALEN);

	if (dol_core_exec_cmd(wlpd_p->masterwlp, DOL_CMD_ADD_STA, true)) {
		mutex_unlock(&dol->cmd_mutex);
		return -EIO;
	}

	mutex_unlock(&dol->cmd_mutex);

	return 0;
}

static int
dol_core_del_sta(struct wlprivate_data *wlpd_p, struct trigger_cmd *delay_cmd)
{
	struct dol_cmd_del_sta *pcmd;
	struct dol_ctrl *dol = &wlpd_p->dol;

	pcmd = (struct dol_cmd_del_sta *)&dol->cmd_buf[0];

	mutex_lock(&dol->cmd_mutex);

	memset(pcmd, 0x00, sizeof(*pcmd));
	pcmd->cmd_hdr.radio = cpu_to_le16(delay_cmd->rid);
	pcmd->cmd_hdr.cmd = cpu_to_le16(DOL_CMD_DEL_STA);
	pcmd->cmd_hdr.len = cpu_to_le16(sizeof(*pcmd));
	pcmd->vid = cpu_to_le32(delay_cmd->vid);
	memcpy(pcmd->sta_mac, delay_cmd->sta_addr, ETH_ALEN);

	if (dol_core_exec_cmd(wlpd_p->masterwlp, DOL_CMD_DEL_STA, true)) {
		mutex_unlock(&dol->cmd_mutex);
		return -EIO;
	}

	mutex_unlock(&dol->cmd_mutex);

	return 0;
}

static int
dol_core_sta_data_ctrl(struct wlprivate_data *wlpd_p,
		       struct trigger_cmd *delay_cmd)
{
	struct dol_cmd_sta_data_ctrl *pcmd;
	struct dol_ctrl *dol = &wlpd_p->dol;

	pcmd = (struct dol_cmd_sta_data_ctrl *)&dol->cmd_buf[0];

	mutex_lock(&dol->cmd_mutex);

	memset(pcmd, 0x00, sizeof(*pcmd));
	pcmd->cmd_hdr.radio = cpu_to_le16(delay_cmd->rid);
	pcmd->cmd_hdr.cmd = cpu_to_le16(DOL_CMD_STA_DATA_CTRL);
	pcmd->cmd_hdr.len = cpu_to_le16(sizeof(*pcmd));
	pcmd->vid = cpu_to_le32(delay_cmd->vid);
	pcmd->stn_id = cpu_to_le16(delay_cmd->stn_id);
	memcpy(pcmd->sta_mac, delay_cmd->sta_addr, ETH_ALEN);
	pcmd->enable = delay_cmd->enable ? cpu_to_le32(1) : 0;

	if (dol_core_exec_cmd(wlpd_p->masterwlp, DOL_CMD_STA_DATA_CTRL, true)) {
		mutex_unlock(&dol->cmd_mutex);
		return -EIO;
	}

	mutex_unlock(&dol->cmd_mutex);

	return 0;
}

static int
dol_core_sta_tx_ampdu_ctrl(struct wlprivate_data *wlpd_p,
			   struct trigger_cmd *delay_cmd)
{
	struct dol_cmd_sta_tx_ampdu_ctrl *pcmd;
	struct dol_ctrl *dol = &wlpd_p->dol;
	int i;

	pcmd = (struct dol_cmd_sta_tx_ampdu_ctrl *)&dol->cmd_buf[0];

	mutex_lock(&dol->cmd_mutex);

	memset(pcmd, 0x00, sizeof(*pcmd));
	pcmd->cmd_hdr.radio = cpu_to_le16(delay_cmd->rid);
	pcmd->cmd_hdr.cmd = cpu_to_le16(DOL_CMD_STA_TX_AMPDU_CTRL);
	pcmd->cmd_hdr.len = cpu_to_le16(sizeof(*pcmd));
	pcmd->vid = cpu_to_le32(delay_cmd->vid);
	memcpy(pcmd->sta_mac, delay_cmd->sta_addr, ETH_ALEN);
	pcmd->threshold = cpu_to_le32(delay_cmd->threshold);
	for (i = 0; i < 8; i++)
		pcmd->startbytid[i] = delay_cmd->startbytid[i];

	if (dol_core_exec_cmd
	    (wlpd_p->masterwlp, DOL_CMD_STA_TX_AMPDU_CTRL, true)) {
		mutex_unlock(&dol->cmd_mutex);
		return -EIO;
	}

	mutex_unlock(&dol->cmd_mutex);

	return 0;
}

static int
dol_core_set_ba_info(struct wlprivate_data *wlpd_p,
		     struct trigger_cmd *delay_cmd)
{
	struct dol_cmd_set_ba_info *pcmd;
	struct dol_ctrl *dol = &wlpd_p->dol;

	pcmd = (struct dol_cmd_set_ba_info *)&dol->cmd_buf[0];

	mutex_lock(&dol->cmd_mutex);

	memset(pcmd, 0x00, sizeof(*pcmd));
	pcmd->cmd_hdr.radio = cpu_to_le16(delay_cmd->rid);
	pcmd->cmd_hdr.cmd = cpu_to_le16(DOL_CMD_SET_BA_INFO);
	pcmd->cmd_hdr.len = cpu_to_le16(sizeof(*pcmd));
	pcmd->type = cpu_to_le16(delay_cmd->ba_type);
	pcmd->stn_id = cpu_to_le16(delay_cmd->stn_id);
	pcmd->tid = cpu_to_le16(delay_cmd->ba_tid);
	pcmd->winStartB = cpu_to_le16(delay_cmd->winStartB);
	pcmd->winSizeB = cpu_to_le16(delay_cmd->winSizeB);

	if (dol_core_exec_cmd(wlpd_p->masterwlp, DOL_CMD_SET_BA_INFO, false)) {
		mutex_unlock(&dol->cmd_mutex);
		return -EIO;
	}

	mutex_unlock(&dol->cmd_mutex);

	return 0;
}

static int
dol_core_set_ba_req(struct wlprivate_data *wlpd_p,
		    struct trigger_cmd *delay_cmd)
{
	struct dol_cmd_set_ba_req *pcmd;
	struct dol_ctrl *dol = &wlpd_p->dol;

	pcmd = (struct dol_cmd_set_ba_req *)&dol->cmd_buf[0];

	mutex_lock(&dol->cmd_mutex);

	memset(pcmd, 0x00, sizeof(*pcmd));
	pcmd->cmd_hdr.radio = cpu_to_le16(delay_cmd->rid);
	pcmd->cmd_hdr.cmd = cpu_to_le16(DOL_CMD_SET_BA_REQ);
	pcmd->cmd_hdr.len = cpu_to_le16(sizeof(*pcmd));
	pcmd->vid = cpu_to_le16(delay_cmd->vid);
	pcmd->stn_id = cpu_to_le16(delay_cmd->stn_id);
	pcmd->tid = cpu_to_le16(delay_cmd->ba_tid);
	pcmd->seq = cpu_to_le16(delay_cmd->ba_seq);

	if (dol_core_exec_cmd(wlpd_p->masterwlp, DOL_CMD_SET_BA_REQ, false)) {
		mutex_unlock(&dol->cmd_mutex);
		return -EIO;
	}

	mutex_unlock(&dol->cmd_mutex);

	return 0;
}

static int
dol_core_del_vif(struct wlprivate_data *wlpd_p, struct trigger_cmd *delay_cmd)
{
	struct dol_cmd_del_vif *pcmd;
	struct dol_ctrl *dol = &wlpd_p->dol;

	pcmd = (struct dol_cmd_del_vif *)&dol->cmd_buf[0];

	mutex_lock(&dol->cmd_mutex);

	memset(pcmd, 0x00, sizeof(*pcmd));
	pcmd->cmd_hdr.radio = cpu_to_le16(delay_cmd->rid);
	pcmd->cmd_hdr.cmd = cpu_to_le16(DOL_CMD_DEL_VIF);
	pcmd->cmd_hdr.len = cpu_to_le16(sizeof(*pcmd));
	pcmd->vid = cpu_to_le32(delay_cmd->vid);

	if (dol_core_exec_cmd(wlpd_p->masterwlp, DOL_CMD_DEL_VIF, true)) {
		mutex_unlock(&dol->cmd_mutex);
		return -EIO;
	}

	mutex_unlock(&dol->cmd_mutex);

	return 0;
}

static void
dol_core_delay_cmd_handle(struct work_struct *work)
{
	struct wlprivate_data *wlpd_p = container_of(work,
						     struct wlprivate_data,
						     delay_cmd_handle);
	struct trigger_cmd *delay_cmd;

	do {
		SPIN_LOCK_BH(&wlpd_p->locks.delayCmdLock);
		delay_cmd = list_first_entry_or_null(&wlpd_p->delay_cmd_list,
						     struct trigger_cmd, list);
		if (!delay_cmd) {
			SPIN_UNLOCK_BH(&wlpd_p->locks.delayCmdLock);
			break;
		}
		list_del(&delay_cmd->list);
		SPIN_UNLOCK_BH(&wlpd_p->locks.delayCmdLock);
		switch (delay_cmd->cmd) {
		case DOL_CMD_RADIO_RETURN_BUFFER:
			dol_core_radio_return_buffer(wlpd_p, delay_cmd);
			break;
		case DOL_CMD_ADD_STA:
			dol_core_add_sta(wlpd_p, delay_cmd);
			break;
		case DOL_CMD_DEL_STA:
			dol_core_del_sta(wlpd_p, delay_cmd);
			break;
		case DOL_CMD_STA_DATA_CTRL:
			dol_core_sta_data_ctrl(wlpd_p, delay_cmd);
			break;
		case DOL_CMD_STA_TX_AMPDU_CTRL:
			dol_core_sta_tx_ampdu_ctrl(wlpd_p, delay_cmd);
			break;
		case DOL_CMD_SET_BA_INFO:
			dol_core_set_ba_info(wlpd_p, delay_cmd);
			break;
		case DOL_CMD_SET_BA_REQ:
			dol_core_set_ba_req(wlpd_p, delay_cmd);
			break;
		case DOL_CMD_DEL_VIF:
			dol_core_del_vif(wlpd_p, delay_cmd);
			break;
		default:
			break;
		}
		wl_kfree(delay_cmd);
	} while (1);

	wlpd_p->delay_cmd_trigger = false;
}

static int
__dol_core_init(void *ctrl)
{
	struct wlprivate *wlpptr = (struct wlprivate *)ctrl;
	int i;

	mutex_init(&wlpptr->wlpd_p->dol.cmd_mutex);
	sema_init(&wlpptr->wlpd_p->dol.cmd_sema, 0);
	setup_timer(&wlpptr->wlpd_p->dol.cmd_timeout, timer_routine,
		    (unsigned long)wlpptr);

	wlpptr->wlpd_p->dol.radio_status = DOL_RADIO_STOP;
	wlpptr->wlpd_p->dol.seq_no = 0;
	for (i = 0; i < NUMOFAPS; i++) {
		wlpptr->wlpd_p->dol.vif_added_to_pe[i] = 0;
		wlpptr->wlpd_p->dol.vif_isolate_grp_id[i] = 0;
	}
	ipc_register_cmd_rcv(wlpptr, dol_core_rcv_cmd, wlpptr);
	ipc_register_pkt_rcv(wlpptr, dol_core_rcv_pkt, wlpptr);
	ipc_register_event_rcv(wlpptr, dol_core_rcv_event, wlpptr);

	return 0;
}

static void
__dol_core_deinit(void *ctrl)
{
	struct wlprivate *wlpptr = (struct wlprivate *)ctrl;

	del_timer_sync(&wlpptr->wlpd_p->dol.cmd_timeout);
	ipc_register_cmd_rcv(wlpptr, NULL, 0);
	ipc_register_pkt_rcv(wlpptr, NULL, 0);
	ipc_register_event_rcv(wlpptr, NULL, 0);
}

static int
__dol_core_check_active(void *ctrl, int rid, bool * active)
{
	struct wlprivate *wlpptr = (struct wlprivate *)ctrl;
	struct dol_cmd_check_active *pcmd;
	struct dol_ctrl *dol = &wlpptr->wlpd_p->dol;

	pcmd = (struct dol_cmd_check_active *)&dol->cmd_buf[0];

	mutex_lock(&dol->cmd_mutex);

	memset(pcmd, 0x00, sizeof(*pcmd));
	pcmd->cmd_hdr.radio = cpu_to_le16(rid);
	pcmd->cmd_hdr.cmd = cpu_to_le16(DOL_CMD_CHECK_ACTIVE);
	pcmd->cmd_hdr.len = cpu_to_le16(sizeof(*pcmd));

	if (dol_core_exec_cmd(wlpptr, DOL_CMD_CHECK_ACTIVE, true)) {
		mutex_unlock(&dol->cmd_mutex);
		return -EIO;
	}

	*active = pcmd->active ? true : false;

	mutex_unlock(&dol->cmd_mutex);

	return 0;
}

static int
__dol_core_get_wfo_version(void *ctrl, int rid, u8 * ver)
{
	struct wlprivate *wlpptr = (struct wlprivate *)ctrl;
	struct dol_cmd_get_wfo_version *pcmd;
	struct dol_ctrl *dol = &wlpptr->wlpd_p->dol;

	pcmd = (struct dol_cmd_get_wfo_version *)&dol->cmd_buf[0];

	mutex_lock(&dol->cmd_mutex);

	memset(pcmd, 0x00, sizeof(*pcmd));
	pcmd->cmd_hdr.radio = cpu_to_le16(rid);
	pcmd->cmd_hdr.cmd = cpu_to_le16(DOL_CMD_GET_WFO_VERSION);
	pcmd->cmd_hdr.len = cpu_to_le16(sizeof(*pcmd));

	if (dol_core_exec_cmd(wlpptr, DOL_CMD_GET_WFO_VERSION, true)) {
		mutex_unlock(&dol->cmd_mutex);
		return -EIO;
	}

	strcpy(ver, pcmd->version);

	mutex_unlock(&dol->cmd_mutex);

	return 0;
}

static int
__dol_core_start_radio(void *ctrl, int rid)
{
	struct wlprivate *wlpptr = (struct wlprivate *)ctrl;
	struct wlprivate *parent_wlpptr = GET_PARENT_PRIV(wlpptr);
	SMAC_CONFIG_st *p_smac_cfg = &parent_wlpptr->smacconfig;
	struct dol_cmd_start_radio *pcmd;
	struct dol_ctrl *dol = &wlpptr->wlpd_p->dol;
	u16 dbg_ctrl;
	int i;

	if (dol->radio_status != DOL_RADIO_STOP)
		return 0;

	pcmd = (struct dol_cmd_start_radio *)&dol->cmd_buf[0];

	mutex_lock(&dol->cmd_mutex);

	memset(pcmd, 0x00, sizeof(*pcmd));
	pcmd->cmd_hdr.radio = cpu_to_le16(rid);
	pcmd->cmd_hdr.cmd = cpu_to_le16(DOL_CMD_START_RADIO);
	pcmd->cmd_hdr.len = cpu_to_le16(sizeof(*pcmd));
	pcmd->iobase0 = cpu_to_le64(wlpptr->ioBase0);
	pcmd->iobase1 = cpu_to_le64(wlpptr->ioBase1);
	pcmd->iobase0_phy = cpu_to_le32(wlpptr->ioBase0_phy);
	pcmd->iobase1_phy = cpu_to_le32(wlpptr->ioBase1_phy);
	pcmd->dev = cpu_to_le64(wlpptr->wlpd_p->dev);
	pcmd->smac_buf_hi_addr =
		cpu_to_le32(wlpptr->wlpd_p->reg.smac_buf_hi_addr);
	pcmd->devid = cpu_to_le16(wlpptr->devid);
	pcmd->chip_revision = cpu_to_le16(wlpptr->hwData.chipRevision);
	dbg_ctrl = 0;
#ifdef DBG_DUMP_DOL_COMMAND
	dbg_ctrl |= DBG_DUMP_DOL_CMD;
#endif
#ifdef DBG_PKT_TX_MGMT_FREE_TSF
	dbg_ctrl |= DBG_TX_MGMT_TIMESTAMP;
#endif
#ifdef DBG_PKT_RX_MGMT_TIMESTAMP
	dbg_ctrl |= DBG_RX_MGMT_TIMESTAMP;
#endif
#ifdef DBG_SEND_PKT_TO_HOST
	dbg_ctrl |= DBG_PKT_TO_HOST;
#endif
#ifdef DBG_DUMP_ETH_TRANSMIT_PKT
	dbg_ctrl |= DBG_DUMP_ETH_TX_PKT;
#endif
#ifdef DBG_ETH_LOOPBACK_RCV_PKT
	dbg_ctrl |= DBG_ETH_LOOPBACK_PKT;
#endif
#ifdef DBG_DISABLE_RCV_BA_REORDER
	dbg_ctrl |= DBG_DISABLE_BA_REORDER;
#endif
	dol->dbg_ctrl = dbg_ctrl;
	pcmd->dbg_ctrl = cpu_to_le16(dbg_ctrl);
	if (wlpptr->wlpd_p->acntRxInfoQueBaseAddr_v)
		pcmd->rx_info_phy_addr =
			cpu_to_le32(p_smac_cfg->acntRxInfoQueBaseAddr);
	else
		pcmd->rx_info_phy_addr = 0;
	pcmd->rx_info_que_size = cpu_to_le32(p_smac_cfg->acntRxInfoQueSize);
	pcmd->bss_num = bss_num;
	pcmd->rx_q_data = RX_Q_DATA;
	pcmd->rx_q_size = cpu_to_le16(RX_Q_SIZE);
	pcmd->tx_q_start = TX_Q_START;
	pcmd->tx_q_num = TX_Q_NUM;
	for (i = 0; i < 2; i++)
		pcmd->tx_q_size[i] = cpu_to_le16(tx_q_size[i]);
	pcmd->rel_q_start = REL_Q_START;
	pcmd->rel_q_num = REL_Q_NUM;
	for (i = 0; i < 4; i++)
		pcmd->rel_q_size[i] = cpu_to_le16(rel_q_size[i]);
	pcmd->bm_q_start = BM_Q_START;
	pcmd->bm_q_num = BM_Q_NUM;
	for (i = 0; i < 4; i++) {
		pcmd->bm_q_size[i] = cpu_to_le16(bm_q_size[i]);
		pcmd->bm_buf_size[i] = cpu_to_le16(bm_buf_size[i]);
	}

	if (dol_core_exec_cmd(wlpptr, DOL_CMD_START_RADIO, true)) {
		mutex_unlock(&dol->cmd_mutex);
		return -EIO;
	}

	dol->radio_status = DOL_RADIO_START;
	mutex_unlock(&dol->cmd_mutex);

	return 0;
}

static int
__dol_core_stop_radio(void *ctrl, int rid)
{
	struct wlprivate *wlpptr = (struct wlprivate *)ctrl;
	struct dol_cmd_stop_radio *pcmd;
	struct dol_ctrl *dol = &wlpptr->wlpd_p->dol;

	if (dol->radio_status == DOL_RADIO_STOP)
		return 0;
	pcmd = (struct dol_cmd_stop_radio *)&dol->cmd_buf[0];

	mutex_lock(&dol->cmd_mutex);

	memset(pcmd, 0x00, sizeof(*pcmd));
	pcmd->cmd_hdr.radio = cpu_to_le16(rid);
	pcmd->cmd_hdr.cmd = cpu_to_le16(DOL_CMD_STOP_RADIO);
	pcmd->cmd_hdr.len = cpu_to_le16(sizeof(*pcmd));

	if (dol_core_exec_cmd(wlpptr, DOL_CMD_STOP_RADIO, true)) {
		mutex_unlock(&dol->cmd_mutex);
		return -EIO;
	}

	dol->radio_status = DOL_RADIO_STOP;
	mutex_unlock(&dol->cmd_mutex);

	return 0;
}

static int
__dol_core_suspend_radio(void *ctrl, int rid, bool suspend)
{
	struct wlprivate *wlpptr = (struct wlprivate *)ctrl;
	struct dol_cmd_suspend_radio *pcmd;
	struct dol_ctrl *dol = &wlpptr->wlpd_p->dol;

	if (dol->radio_status == DOL_RADIO_STOP)
		return -EIO;

	pcmd = (struct dol_cmd_suspend_radio *)&dol->cmd_buf[0];

	mutex_lock(&dol->cmd_mutex);

	memset(pcmd, 0x00, sizeof(*pcmd));
	pcmd->cmd_hdr.radio = cpu_to_le16(rid);
	pcmd->cmd_hdr.cmd = cpu_to_le16(DOL_CMD_SUSPEND_RADIO);
	pcmd->cmd_hdr.len = cpu_to_le16(sizeof(*pcmd));
	pcmd->suspend = suspend ? cpu_to_le32(1) : 0;

	if (dol_core_exec_cmd(wlpptr, DOL_CMD_SUSPEND_RADIO, true)) {
		mutex_unlock(&dol->cmd_mutex);
		return -EIO;
	}

	mutex_unlock(&dol->cmd_mutex);

	return 0;
}

static int
__dol_core_radio_data_ctrl(void *ctrl, int rid, bool enable)
{
	struct wlprivate *wlpptr = (struct wlprivate *)ctrl;
	struct dol_cmd_radio_data_ctrl *pcmd;
	struct dol_ctrl *dol = &wlpptr->wlpd_p->dol;

	if (dol->radio_status == DOL_RADIO_STOP)
		return -EIO;

	pcmd = (struct dol_cmd_radio_data_ctrl *)&dol->cmd_buf[0];

	mutex_lock(&dol->cmd_mutex);

	memset(pcmd, 0x00, sizeof(*pcmd));
	pcmd->cmd_hdr.radio = cpu_to_le16(rid);
	pcmd->cmd_hdr.cmd = cpu_to_le16(DOL_CMD_RADIO_DATA_CTRL);
	pcmd->cmd_hdr.len = cpu_to_le16(sizeof(*pcmd));
	pcmd->enable = enable ? cpu_to_le32(1) : 0;

	if (dol_core_exec_cmd(wlpptr, DOL_CMD_RADIO_DATA_CTRL, true)) {
		mutex_unlock(&dol->cmd_mutex);
		return -EIO;
	}

	mutex_unlock(&dol->cmd_mutex);

	return 0;
}

static int
__dol_core_radio_tx_ampdu_ctrl(void *ctrl, int rid, u8 ampdu_tx)
{
	struct wlprivate *wlpptr = (struct wlprivate *)ctrl;
	struct dol_cmd_radio_tx_ampdu_ctrl *pcmd;
	struct dol_ctrl *dol = &wlpptr->wlpd_p->dol;

	if (dol->radio_status == DOL_RADIO_STOP)
		return -EIO;

	pcmd = (struct dol_cmd_radio_tx_ampdu_ctrl *)&dol->cmd_buf[0];

	mutex_lock(&dol->cmd_mutex);

	memset(pcmd, 0x00, sizeof(*pcmd));
	pcmd->cmd_hdr.radio = cpu_to_le16(rid);
	pcmd->cmd_hdr.cmd = cpu_to_le16(DOL_CMD_RADIO_TX_AMPDU_CTRL);
	pcmd->cmd_hdr.len = cpu_to_le16(sizeof(*pcmd));
	pcmd->ampdu_tx = ampdu_tx;

	if (dol_core_exec_cmd(wlpptr, DOL_CMD_RADIO_TX_AMPDU_CTRL, true)) {
		mutex_unlock(&dol->cmd_mutex);
		return -EIO;
	}

	mutex_unlock(&dol->cmd_mutex);

	return 0;
}

static void
__dol_core_radio_return_buffer(void *ctrl, int rid, u64 pkt_hdr_addr)
{
	struct wlprivate *wlpptr = (struct wlprivate *)ctrl;
	struct trigger_cmd *delay_cmd;

	delay_cmd = (struct trigger_cmd *)
		wl_kmalloc(sizeof(struct trigger_cmd), GFP_ATOMIC);
	if (!delay_cmd) {
		printk("%s: lack of memory\n", __func__);
		return;
	}

	delay_cmd->cmd = DOL_CMD_RADIO_RETURN_BUFFER;
	delay_cmd->rid = rid;
	delay_cmd->pkt_hdr_addr = pkt_hdr_addr;

	SPIN_LOCK_BH(&wlpptr->wlpd_p->locks.delayCmdLock);
	list_add_tail(&delay_cmd->list, &wlpptr->wlpd_p->delay_cmd_list);
	SPIN_UNLOCK_BH(&wlpptr->wlpd_p->locks.delayCmdLock);
	wlpptr->wlpd_p->bm_release_request_num++;

	if (!wlpptr->wlpd_p->delay_cmd_trigger) {
		wlpptr->wlpd_p->delay_cmd_trigger = true;
		schedule_work(&wlpptr->wlpd_p->delay_cmd_handle);
	}
}

static int
__dol_core_radio_get_rx_info(void *ctrl, int rid, bool clean)
{
	struct wlprivate *wlpptr = (struct wlprivate *)ctrl;
	struct dol_cmd_radio_get_rx_info *pcmd;
	struct dol_ctrl *dol = &wlpptr->wlpd_p->dol;
	DRV_RATE_HIST *rx_rate_histogram = &wlpptr->wlpd_p->drvrxRateHistogram;
	struct rx_rate_info *rate_info = NULL;
	int i, gi, index;

	if (dol->radio_status == DOL_RADIO_STOP)
		return 0;

	pcmd = (struct dol_cmd_radio_get_rx_info *)&dol->cmd_buf[0];

	mutex_lock(&dol->cmd_mutex);

	memset(pcmd, 0x00, sizeof(*pcmd));
	pcmd->first = 1;
	pcmd->clean = clean;
more_rx_rate_info:
	pcmd->cmd_hdr.radio = cpu_to_le16(rid);
	pcmd->cmd_hdr.cmd = cpu_to_le16(DOL_CMD_RADIO_GET_RX_INFO);
	pcmd->cmd_hdr.len = cpu_to_le16(sizeof(*pcmd));

	if (dol_core_exec_cmd(wlpptr, DOL_CMD_RADIO_GET_RX_INFO, true)) {
		mutex_unlock(&dol->cmd_mutex);
		return -EIO;
	}

	if (clean) {
		mutex_unlock(&dol->cmd_mutex);
		return 0;
	}

	for (i = 0; i < 3; i++)
		rx_rate_histogram->pkt_cnt[i] = le32_to_cpu(pcmd->pkt_cnt[i]);

	for (i = 0; i < pcmd->rate_num; i++) {
		rate_info = &pcmd->rate_info[i];
		index = rate_info->gi_idx & 0xF;
		gi = (rate_info->gi_idx & 0xF0) >> 4;
		switch (pcmd->rate_info[i].type) {
		case RATE_LEGACY:
			rx_rate_histogram->LegacyRates[index] =
				le32_to_cpu(rate_info->cnt);
			break;
		case RATE_HT:
			rx_rate_histogram->HtRates[rate_info->bw][gi][index] =
				le32_to_cpu(rate_info->cnt);
			break;
		case RATE_VHT:
			rx_rate_histogram->VHtRates[rate_info->nss][rate_info->
								    bw][gi]
				[index] = le32_to_cpu(rate_info->cnt);
			break;
		case RATE_HE:
			rx_rate_histogram->HERates[rate_info->nss][rate_info->
								   bw][gi]
				[index] = le32_to_cpu(rate_info->cnt);
			break;
		default:
			break;
		}
	}

	if (pcmd->more) {
		memset(pcmd, 0x00, sizeof(*pcmd));
		goto more_rx_rate_info;
	}

	mutex_unlock(&dol->cmd_mutex);

	return 0;
}

static int
__dol_core_add_vif(void *ctrl, int rid, int vid, u8 * bssid)
{
	struct wlprivate *wlpptr = (struct wlprivate *)ctrl;
	struct dol_cmd_add_vif *pcmd;
	struct dol_ctrl *dol = &wlpptr->wlpd_p->dol;

	if (dol->radio_status == DOL_RADIO_STOP)
		return -EIO;

	pcmd = (struct dol_cmd_add_vif *)&dol->cmd_buf[0];

	mutex_lock(&dol->cmd_mutex);

	memset(pcmd, 0x00, sizeof(*pcmd));
	pcmd->cmd_hdr.radio = cpu_to_le16(rid);
	pcmd->cmd_hdr.cmd = cpu_to_le16(DOL_CMD_ADD_VIF);
	pcmd->cmd_hdr.len = cpu_to_le16(sizeof(*pcmd));
	pcmd->vid = cpu_to_le32(vid);
	memcpy(pcmd->bssid, bssid, ETH_ALEN);

	if (dol_core_exec_cmd(wlpptr, DOL_CMD_ADD_VIF, true)) {
		mutex_unlock(&dol->cmd_mutex);
		return -EIO;
	}

	mutex_unlock(&dol->cmd_mutex);

	return 0;
}

static int
__dol_core_del_vif(void *ctrl, int rid, int vid)
{
	struct wlprivate *wlpptr = (struct wlprivate *)ctrl;
	struct trigger_cmd *delay_cmd;
	if (wlpptr->wlpd_p->dol.radio_status == DOL_RADIO_STOP)
		return -EIO;

	if (!in_atomic()) {
		struct dol_ctrl *dol = &wlpptr->wlpd_p->dol;
		struct dol_cmd_del_vif *pcmd =
			(struct dol_cmd_del_vif *)&dol->cmd_buf[0];

		mutex_lock(&dol->cmd_mutex);

		memset(pcmd, 0x00, sizeof(*pcmd));
		pcmd->cmd_hdr.radio = cpu_to_le16(rid);
		pcmd->cmd_hdr.cmd = cpu_to_le16(DOL_CMD_DEL_VIF);
		pcmd->cmd_hdr.len = cpu_to_le16(sizeof(*pcmd));
		pcmd->vid = cpu_to_le32(vid);

		if (dol_core_exec_cmd(wlpptr, DOL_CMD_DEL_VIF, true)) {
			mutex_unlock(&dol->cmd_mutex);
			return -EIO;
		}

		mutex_unlock(&dol->cmd_mutex);
	} else {
		delay_cmd = (struct trigger_cmd *)
			wl_kmalloc(sizeof(struct trigger_cmd), GFP_ATOMIC);
		if (!delay_cmd) {
			printk("%s: lack of memory\n", __func__);
			return -ENOMEM;
		}

		delay_cmd->cmd = DOL_CMD_DEL_VIF;
		delay_cmd->rid = rid;
		delay_cmd->vid = vid;

		SPIN_LOCK_BH(&wlpptr->wlpd_p->locks.delayCmdLock);
		list_add_tail(&delay_cmd->list,
			      &wlpptr->wlpd_p->delay_cmd_list);
		SPIN_UNLOCK_BH(&wlpptr->wlpd_p->locks.delayCmdLock);

		if (!wlpptr->wlpd_p->delay_cmd_trigger) {
			wlpptr->wlpd_p->delay_cmd_trigger = true;
			schedule_work(&wlpptr->wlpd_p->delay_cmd_handle);
		}
	}
	return 0;
}

static int
__dol_core_vif_data_ctrl(void *ctrl, int rid, int vid, bool enable)
{
	struct wlprivate *wlpptr = (struct wlprivate *)ctrl;
	struct dol_cmd_vif_data_ctrl *pcmd;
	struct dol_ctrl *dol = &wlpptr->wlpd_p->dol;

	if (dol->radio_status == DOL_RADIO_STOP)
		return -EIO;

	pcmd = (struct dol_cmd_vif_data_ctrl *)&dol->cmd_buf[0];

	mutex_lock(&dol->cmd_mutex);

	memset(pcmd, 0x00, sizeof(*pcmd));
	pcmd->cmd_hdr.radio = cpu_to_le16(rid);
	pcmd->cmd_hdr.cmd = cpu_to_le16(DOL_CMD_VIF_DATA_CTRL);
	pcmd->cmd_hdr.len = cpu_to_le16(sizeof(*pcmd));
	pcmd->vid = cpu_to_le32(vid);
	pcmd->enable = enable ? cpu_to_le32(1) : 0;

	if (dol_core_exec_cmd(wlpptr, DOL_CMD_VIF_DATA_CTRL, true)) {
		mutex_unlock(&dol->cmd_mutex);
		return -EIO;
	}

	mutex_unlock(&dol->cmd_mutex);

	return 0;
}

static int
__dol_core_vif_set_isolate_grp_id(void *ctrl, int rid, int vid, int group_id)
{
	struct wlprivate *wlpptr = (struct wlprivate *)ctrl;
	struct dol_cmd_vif_set_isolate_grp_id *pcmd;
	struct dol_ctrl *dol = &wlpptr->wlpd_p->dol;

	if (dol->radio_status == DOL_RADIO_STOP)
		return -EIO;

	pcmd = (struct dol_cmd_vif_set_isolate_grp_id *)&dol->cmd_buf[0];

	mutex_lock(&dol->cmd_mutex);

	memset(pcmd, 0x00, sizeof(*pcmd));
	pcmd->cmd_hdr.radio = cpu_to_le16(rid);
	pcmd->cmd_hdr.cmd = cpu_to_le16(DOL_CMD_VIF_SET_ISOLATE_GRP_ID);
	pcmd->cmd_hdr.len = cpu_to_le16(sizeof(*pcmd));
	pcmd->vid = cpu_to_le32(vid);
	pcmd->isolate_group_id = cpu_to_le32(group_id);

	if (dol_core_exec_cmd(wlpptr, DOL_CMD_VIF_SET_ISOLATE_GRP_ID, true)) {
		mutex_unlock(&dol->cmd_mutex);
		return -EIO;
	}

	mutex_unlock(&dol->cmd_mutex);

	return 0;
}

static int
__dol_core_add_sta(void *ctrl, int rid, int vid, u8 * addr)
{
	struct wlprivate *wlpptr = (struct wlprivate *)ctrl;
	struct trigger_cmd *delay_cmd;

	if (wlpptr->wlpd_p->dol.radio_status == DOL_RADIO_STOP)
		return -EIO;

	delay_cmd = (struct trigger_cmd *)
		wl_kmalloc(sizeof(struct trigger_cmd), GFP_ATOMIC);
	if (!delay_cmd) {
		printk("%s: lack of memory\n", __func__);
		return -ENOMEM;
	}

	delay_cmd->cmd = DOL_CMD_ADD_STA;
	delay_cmd->rid = rid;
	delay_cmd->vid = vid;
	memcpy(delay_cmd->sta_addr, addr, ETH_ALEN);

	SPIN_LOCK_BH(&wlpptr->wlpd_p->locks.delayCmdLock);
	list_add_tail(&delay_cmd->list, &wlpptr->wlpd_p->delay_cmd_list);
	SPIN_UNLOCK_BH(&wlpptr->wlpd_p->locks.delayCmdLock);

	if (!wlpptr->wlpd_p->delay_cmd_trigger) {
		wlpptr->wlpd_p->delay_cmd_trigger = true;
		schedule_work(&wlpptr->wlpd_p->delay_cmd_handle);
	}

	return 0;
}

static int
__dol_core_del_sta(void *ctrl, int rid, int vid, u8 * addr)
{
	struct wlprivate *wlpptr = (struct wlprivate *)ctrl;
	struct trigger_cmd *delay_cmd;

	if (wlpptr->wlpd_p->dol.radio_status == DOL_RADIO_STOP)
		return -EIO;

	delay_cmd = (struct trigger_cmd *)
		wl_kmalloc(sizeof(struct trigger_cmd), GFP_ATOMIC);
	if (!delay_cmd) {
		printk("%s: lack of memory\n", __func__);
		return -ENOMEM;
	}

	delay_cmd->cmd = DOL_CMD_DEL_STA;
	delay_cmd->rid = rid;
	delay_cmd->vid = vid;
	memcpy(delay_cmd->sta_addr, addr, ETH_ALEN);
	dol_core_del_pkts_via_sta(wlpptr->wlpd_p, addr);

	SPIN_LOCK_BH(&wlpptr->wlpd_p->locks.delayCmdLock);
	list_add_tail(&delay_cmd->list, &wlpptr->wlpd_p->delay_cmd_list);
	SPIN_UNLOCK_BH(&wlpptr->wlpd_p->locks.delayCmdLock);

	if (!wlpptr->wlpd_p->delay_cmd_trigger) {
		wlpptr->wlpd_p->delay_cmd_trigger = true;
		schedule_work(&wlpptr->wlpd_p->delay_cmd_handle);
	}

	return 0;
}

static int
__dol_core_sta_data_ctrl(void *ctrl, int rid, int vid,
			 u16 stn_id, u8 * addr, bool enable)
{
	struct wlprivate *wlpptr = (struct wlprivate *)ctrl;
	struct trigger_cmd *delay_cmd;

	if (wlpptr->wlpd_p->dol.radio_status == DOL_RADIO_STOP)
		return -EIO;

	delay_cmd = (struct trigger_cmd *)
		wl_kmalloc(sizeof(struct trigger_cmd), GFP_ATOMIC);
	if (!delay_cmd) {
		printk("%s: lack of memory\n", __func__);
		return -ENOMEM;
	}

	delay_cmd->cmd = DOL_CMD_STA_DATA_CTRL;
	delay_cmd->rid = rid;
	delay_cmd->vid = vid;
	delay_cmd->stn_id = stn_id;
	memcpy(delay_cmd->sta_addr, addr, ETH_ALEN);
	delay_cmd->enable = enable;

	SPIN_LOCK_BH(&wlpptr->wlpd_p->locks.delayCmdLock);
	list_add_tail(&delay_cmd->list, &wlpptr->wlpd_p->delay_cmd_list);
	SPIN_UNLOCK_BH(&wlpptr->wlpd_p->locks.delayCmdLock);

	if (!wlpptr->wlpd_p->delay_cmd_trigger) {
		wlpptr->wlpd_p->delay_cmd_trigger = true;
		schedule_work(&wlpptr->wlpd_p->delay_cmd_handle);
	}

	return 0;
}

static int
__dol_core_sta_tx_ampdu_ctrl(void *ctrl, int rid, int vid,
			     u8 * addr, u32 threshold, u8 * startbytid)
{
	struct wlprivate *wlpptr = (struct wlprivate *)ctrl;
	struct trigger_cmd *delay_cmd;
	int i;

	if (wlpptr->wlpd_p->dol.radio_status == DOL_RADIO_STOP)
		return -EIO;

	delay_cmd = (struct trigger_cmd *)
		wl_kmalloc(sizeof(struct trigger_cmd), GFP_ATOMIC);
	if (!delay_cmd) {
		printk("%s: lack of memory\n", __func__);
		return -ENOMEM;
	}

	delay_cmd->cmd = DOL_CMD_STA_TX_AMPDU_CTRL;
	delay_cmd->rid = rid;
	delay_cmd->vid = vid;
	memcpy(delay_cmd->sta_addr, addr, ETH_ALEN);
	delay_cmd->threshold = threshold;
	if (startbytid) {
		for (i = 0; i < 8; i++)
			delay_cmd->startbytid[i] = startbytid[i];
	} else
		memset(delay_cmd->startbytid, 0, 8);

	SPIN_LOCK_BH(&wlpptr->wlpd_p->locks.delayCmdLock);
	list_add_tail(&delay_cmd->list, &wlpptr->wlpd_p->delay_cmd_list);
	SPIN_UNLOCK_BH(&wlpptr->wlpd_p->locks.delayCmdLock);

	if (!wlpptr->wlpd_p->delay_cmd_trigger) {
		wlpptr->wlpd_p->delay_cmd_trigger = true;
		schedule_work(&wlpptr->wlpd_p->delay_cmd_handle);
	}

	return 0;
}

static void
__dol_set_ba_info(void *ctrl, int rid, u16 type, u16 stn_id,
		  u16 tid, u16 winStartB, u16 winSizeB)
{
	struct wlprivate *wlpptr = (struct wlprivate *)ctrl;
	struct trigger_cmd *delay_cmd;

	if (wlpptr->wlpd_p->dol.radio_status == DOL_RADIO_STOP)
		return;

	delay_cmd = (struct trigger_cmd *)
		wl_kmalloc(sizeof(struct trigger_cmd), GFP_ATOMIC);
	if (!delay_cmd) {
		printk("%s: lack of memory\n", __func__);
		return;
	}

	delay_cmd->cmd = DOL_CMD_SET_BA_INFO;
	delay_cmd->rid = rid;
	delay_cmd->ba_type = type;
	delay_cmd->stn_id = stn_id;
	delay_cmd->ba_tid = tid;
	delay_cmd->winStartB = winStartB;
	delay_cmd->winSizeB = winSizeB;

	SPIN_LOCK_BH(&wlpptr->wlpd_p->locks.delayCmdLock);
	list_add_tail(&delay_cmd->list, &wlpptr->wlpd_p->delay_cmd_list);
	SPIN_UNLOCK_BH(&wlpptr->wlpd_p->locks.delayCmdLock);

	if (!wlpptr->wlpd_p->delay_cmd_trigger) {
		wlpptr->wlpd_p->delay_cmd_trigger = true;
		schedule_work(&wlpptr->wlpd_p->delay_cmd_handle);
	}
}

static void
__dol_set_ba_req(void *ctrl, int rid, u16 vid, u16 stn_id, u16 tid, u16 seq)
{
	struct wlprivate *wlpptr = (struct wlprivate *)ctrl;
	struct trigger_cmd *delay_cmd;

	if (wlpptr->wlpd_p->dol.radio_status == DOL_RADIO_STOP)
		return;

	delay_cmd = (struct trigger_cmd *)
		wl_kmalloc(sizeof(struct trigger_cmd), GFP_ATOMIC);
	if (!delay_cmd) {
		printk("%s: lack of memory\n", __func__);
		return;
	}

	delay_cmd->cmd = DOL_CMD_SET_BA_REQ;
	delay_cmd->rid = rid;
	delay_cmd->vid = vid;
	delay_cmd->stn_id = stn_id;
	delay_cmd->ba_tid = tid;
	delay_cmd->ba_seq = seq;

	SPIN_LOCK_BH(&wlpptr->wlpd_p->locks.delayCmdLock);
	list_add_tail(&delay_cmd->list, &wlpptr->wlpd_p->delay_cmd_list);
	SPIN_UNLOCK_BH(&wlpptr->wlpd_p->locks.delayCmdLock);

	if (!wlpptr->wlpd_p->delay_cmd_trigger) {
		wlpptr->wlpd_p->delay_cmd_trigger = true;
		schedule_work(&wlpptr->wlpd_p->delay_cmd_handle);
	}
}

static int
__dol_core_xmit(void *ctrl, struct sk_buff *skb, wltxdesc_t * txcfg, int qid)
{
	return ipc_send_pkt(ctrl, skb, txcfg, qid);
}

static struct sk_buff *
__dol_core_recv(void *ctrl, bool data)
{
	struct wlprivate *wlpptr = (struct wlprivate *)ctrl;

	if (data) {
		if (skb_queue_len(&wlpptr->wlpd_p->recv_q_data))
			return (skb_dequeue(&wlpptr->wlpd_p->recv_q_data));
	} else {
		if (skb_queue_len(&wlpptr->wlpd_p->recv_q_mgmt))
			return (skb_dequeue(&wlpptr->wlpd_p->recv_q_mgmt));
	}

	return NULL;
}

static void
__dol_set_dscp_wmm_mapping(void *ctrl, int rid, u16 dscp_wmm_mapping)
{
	struct wlprivate *wlpptr = (struct wlprivate *)ctrl;
	struct dol_cmd_set_dscp_wmm_mapping *pcmd;
	struct dol_ctrl *dol = &wlpptr->wlpd_p->dol;

	if (dol->radio_status == DOL_RADIO_STOP)
		return;

	pcmd = (struct dol_cmd_set_dscp_wmm_mapping *)&dol->cmd_buf[0];

	mutex_lock(&dol->cmd_mutex);

	memset(pcmd, 0x00, sizeof(*pcmd));
	pcmd->cmd_hdr.radio = cpu_to_le16(rid);
	pcmd->cmd_hdr.cmd = cpu_to_le16(DOL_CMD_SET_DSCP_WMM_MAPPING);
	pcmd->cmd_hdr.len = cpu_to_le16(sizeof(*pcmd));
	pcmd->dscp_wmm_mapping = cpu_to_le16(dscp_wmm_mapping);

	dol_core_exec_cmd(wlpptr, DOL_CMD_SET_DSCP_WMM_MAPPING, false);

	mutex_unlock(&dol->cmd_mutex);
}

static int
__dol_core_get_stats(void *ctrl, int rid, int vid, u16 type,
		     void *stats, int stats_size, bool clear_after_read,
		     int *more)
{
	struct wlprivate *wlpptr = (struct wlprivate *)ctrl;
	struct dol_cmd_get_stats *pcmd;
	struct dol_ctrl *dol = &wlpptr->wlpd_p->dol;

	if (sizeof(*pcmd) > sizeof(dol->cmd_buf)) {
		printk("get stats cmd: %zu exceed cmd_buf: %zu\n",
		       sizeof(*pcmd), sizeof(dol->cmd_buf));
		return -ENOMEM;
	}

	switch (type) {
	case GET_STATS_NET_DEVICE:
		if (sizeof(struct netdev_stats) != stats_size)
			return -EINVAL;
		break;
	case GET_STATS_PKT_STATUS:
		if (sizeof(struct pkt_status) != stats_size)
			return -EINVAL;
		break;
	case GET_STATS_DBG_TX_CNT:
		if (sizeof(struct dbg_tx_cnt) != stats_size)
			return -EINVAL;
		break;
	case GET_STATS_DBG_REL_CNT:
		if (sizeof(struct dbg_rel_cnt) != stats_size)
			return -EINVAL;
		break;
	case GET_STATS_DBG_RX_CNT:
		if (sizeof(struct dbg_rx_cnt) != stats_size)
			return -EINVAL;
		break;
	case GET_STATS_DBG_PKT_CNT:
		if (sizeof(struct dbg_pkt_cnt) != stats_size)
			return -EINVAL;
		break;
	case GET_STATS_DBG_STA_CNT:
		if (sizeof(struct dbg_sta_cnt) != stats_size)
			return -EINVAL;
		break;
	case GET_STATS_HFRMQ_INFO:
		if (sizeof(struct dbg_hfrmq_info) != stats_size)
			return -EINVAL;
		break;
	default:
		return -EINVAL;
	}

	pcmd = (struct dol_cmd_get_stats *)&dol->cmd_buf[0];

	mutex_lock(&dol->cmd_mutex);

	memset(pcmd, 0x00, sizeof(*pcmd));
	pcmd->cmd_hdr.radio = cpu_to_le16(rid);
	pcmd->cmd_hdr.cmd = cpu_to_le16(DOL_CMD_GET_STATS);
	pcmd->cmd_hdr.len = cpu_to_le16(sizeof(*pcmd));
	pcmd->type = cpu_to_le16(type);
	pcmd->vid = vid;
	pcmd->clear_after_read = (clear_after_read) ? 1 : 0;

	if (type == GET_STATS_DBG_STA_CNT)
		pcmd->dbg_sta_cnt.more = *more;

	if (type == GET_STATS_HFRMQ_INFO) {
		struct dbg_hfrmq_info *hfrmq_info =
			(struct dbg_hfrmq_info *)stats;
		pcmd->dbg_hfrmq_info.qid = hfrmq_info->qid;
		pcmd->dbg_hfrmq_info.qoff = hfrmq_info->qoff;
	}

	if (dol_core_exec_cmd(wlpptr, DOL_CMD_GET_STATS, true)) {
		mutex_unlock(&dol->cmd_mutex);
		return -EIO;
	}

	switch (type) {
	case GET_STATS_NET_DEVICE:
		{
			struct netdev_stats *netdev_stats =
				(struct netdev_stats *)stats;

			netdev_stats->rx_packets =
				__le32_to_cpu(pcmd->netdev_stats.rx_packets);
			netdev_stats->tx_packets =
				__le32_to_cpu(pcmd->netdev_stats.tx_packets);
			netdev_stats->rx_bytes =
				__le32_to_cpu(pcmd->netdev_stats.rx_bytes);
			netdev_stats->tx_bytes =
				__le32_to_cpu(pcmd->netdev_stats.tx_bytes);
			netdev_stats->rx_errors =
				__le32_to_cpu(pcmd->netdev_stats.rx_errors);
			netdev_stats->tx_errors =
				__le32_to_cpu(pcmd->netdev_stats.tx_errors);
			netdev_stats->rx_dropped =
				__le32_to_cpu(pcmd->netdev_stats.rx_dropped);
			netdev_stats->tx_dropped =
				__le32_to_cpu(pcmd->netdev_stats.tx_dropped);
			netdev_stats->multicast =
				__le32_to_cpu(pcmd->netdev_stats.multicast);
			netdev_stats->collisions =
				__le32_to_cpu(pcmd->netdev_stats.collisions);
			netdev_stats->rx_length_errors =
				__le32_to_cpu(pcmd->netdev_stats.
					      rx_length_errors);
			netdev_stats->rx_over_errors =
				__le32_to_cpu(pcmd->netdev_stats.
					      rx_over_errors);
			netdev_stats->rx_crc_errors =
				__le32_to_cpu(pcmd->netdev_stats.rx_crc_errors);
			netdev_stats->rx_frame_errors =
				__le32_to_cpu(pcmd->netdev_stats.
					      rx_frame_errors);
			netdev_stats->rx_fifo_errors =
				__le32_to_cpu(pcmd->netdev_stats.
					      rx_fifo_errors);
			netdev_stats->rx_missed_errors =
				__le32_to_cpu(pcmd->netdev_stats.
					      rx_missed_errors);
			netdev_stats->tx_aborted_errors =
				__le32_to_cpu(pcmd->netdev_stats.
					      tx_aborted_errors);
			netdev_stats->tx_carrier_errors =
				__le32_to_cpu(pcmd->netdev_stats.
					      tx_carrier_errors);
		}
		break;
	case GET_STATS_PKT_STATUS:
		{
			struct pkt_status *pkt_status =
				(struct pkt_status *)stats;
			int i;

			pkt_status->pkt_hdr_free_num =
				__le32_to_cpu(pcmd->pkt_status.
					      pkt_hdr_free_num);
			pkt_status->pkt_from_host_num =
				__le32_to_cpu(pcmd->pkt_status.
					      pkt_from_host_num);
			for (i = 0; i < 4; i++) {
				pkt_status->pkt_bmq_free_num[i] =
					__le32_to_cpu(pcmd->pkt_status.
						      pkt_bmq_free_num[i]);
				pkt_status->pkt_from_eth_num[i] =
					__le32_to_cpu(pcmd->pkt_status.
						      pkt_from_eth_num[i]);
			}
		}
		break;
	case GET_STATS_DBG_TX_CNT:
		{
			struct dbg_tx_cnt *tx_cnt = (struct dbg_tx_cnt *)stats;
			int i;

			tx_cnt->data_pkt_from_host =
				__le32_to_cpu(pcmd->dbg_tx_cnt.
					      data_pkt_from_host);
			tx_cnt->mgmt_pkt_from_host =
				__le32_to_cpu(pcmd->dbg_tx_cnt.
					      mgmt_pkt_from_host);
			tx_cnt->unicast_pkt_from_eth =
				__le32_to_cpu(pcmd->dbg_tx_cnt.
					      unicast_pkt_from_eth);
			tx_cnt->bcmc_pkt_from_eth =
				__le32_to_cpu(pcmd->dbg_tx_cnt.
					      bcmc_pkt_from_eth);
			for (i = 0; i < 4; i++) {
				tx_cnt->ac_pkt[i] =
					__le32_to_cpu(pcmd->dbg_tx_cnt.
						      ac_pkt[i]);
				tx_cnt->ac_drop[i] =
					__le32_to_cpu(pcmd->dbg_tx_cnt.
						      ac_drop[i]);
			}
			tx_cnt->tx_drop_msg_err =
				__le32_to_cpu(pcmd->dbg_tx_cnt.tx_drop_msg_err);
			tx_cnt->tx_drop_vif_err =
				__le32_to_cpu(pcmd->dbg_tx_cnt.tx_drop_vif_err);
			tx_cnt->tx_drop_vif_disable =
				__le32_to_cpu(pcmd->dbg_tx_cnt.
					      tx_drop_vif_disable);
			tx_cnt->tx_drop_sta_err =
				__le32_to_cpu(pcmd->dbg_tx_cnt.tx_drop_sta_err);
			tx_cnt->tx_drop_sta_disable =
				__le32_to_cpu(pcmd->dbg_tx_cnt.
					      tx_drop_sta_disable);
			tx_cnt->tx_drop_no_pkt_hdr =
				__le32_to_cpu(pcmd->dbg_tx_cnt.
					      tx_drop_no_pkt_hdr);
			tx_cnt->tx_queue_full =
				__le32_to_cpu(pcmd->dbg_tx_cnt.tx_queue_full);
			tx_cnt->tx_queue_send =
				__le32_to_cpu(pcmd->dbg_tx_cnt.tx_queue_send);
		}
		break;
	case GET_STATS_DBG_REL_CNT:
		{
			struct dbg_rel_cnt *rel_cnt =
				(struct dbg_rel_cnt *)stats;
			int i;

			rel_cnt->tx_release =
				__le32_to_cpu(pcmd->dbg_rel_cnt.tx_release);
			rel_cnt->bm_release_from_host =
				__le32_to_cpu(pcmd->dbg_rel_cnt.
					      bm_release_from_host);
			for (i = 0; i < 4; i++)
				rel_cnt->bmq_release[i] =
					__le32_to_cpu(pcmd->dbg_rel_cnt.
						      bmq_release[i]);
			rel_cnt->bm10_poll =
				__le32_to_cpu(pcmd->dbg_rel_cnt.bm10_poll);
			rel_cnt->bm10_return_non_clone =
				__le32_to_cpu(pcmd->dbg_rel_cnt.
					      bm10_return_non_clone);
			rel_cnt->bm10_to_host =
				__le32_to_cpu(pcmd->dbg_rel_cnt.bm10_to_host);
			rel_cnt->bm10_return_host =
				__le32_to_cpu(pcmd->dbg_rel_cnt.
					      bm10_return_host);
			rel_cnt->bm10_to_eth =
				__le32_to_cpu(pcmd->dbg_rel_cnt.bm10_to_eth);
			rel_cnt->bm10_return_eth =
				__le32_to_cpu(pcmd->dbg_rel_cnt.
					      bm10_return_eth);
			rel_cnt->pe_hw_sig_err =
				__le32_to_cpu(pcmd->dbg_rel_cnt.pe_hw_sig_err);
			rel_cnt->pe_hw_phy_addr_err =
				__le32_to_cpu(pcmd->dbg_rel_cnt.
					      pe_hw_phy_addr_err);
			rel_cnt->pe_hw_bpid_err =
				__le32_to_cpu(pcmd->dbg_rel_cnt.pe_hw_bpid_err);
			rel_cnt->pe_hw_pkt_sig_err =
				__le32_to_cpu(pcmd->dbg_rel_cnt.
					      pe_hw_pkt_sig_err);
		}
		break;
	case GET_STATS_DBG_RX_CNT:
		{
			struct dbg_rx_cnt *rx_cnt = (struct dbg_rx_cnt *)stats;
			int i;

			rx_cnt->mgmt_pkt_to_host =
				__le32_to_cpu(pcmd->dbg_rx_cnt.
					      mgmt_pkt_to_host);
			rx_cnt->eapol_pkt_to_host =
				__le32_to_cpu(pcmd->dbg_rx_cnt.
					      eapol_pkt_to_host);
			rx_cnt->data_pkt_to_host =
				__le32_to_cpu(pcmd->dbg_rx_cnt.
					      data_pkt_to_host);
			rx_cnt->data_pkt_to_eth =
				__le32_to_cpu(pcmd->dbg_rx_cnt.data_pkt_to_eth);
			rx_cnt->rx_drop_mgmt_q_type_err =
				__le32_to_cpu(pcmd->dbg_rx_cnt.
					      rx_drop_mgmt_q_type_err);
			rx_cnt->rx_drop_data_q_type_err =
				__le32_to_cpu(pcmd->dbg_rx_cnt.
					      rx_drop_data_q_type_err);
			rx_cnt->rx_drop_vif_err =
				__le32_to_cpu(pcmd->dbg_rx_cnt.rx_drop_vif_err);
			rx_cnt->rx_drop_vif_disable =
				__le32_to_cpu(pcmd->dbg_rx_cnt.
					      rx_drop_vif_disable);
			rx_cnt->rx_drop_sta_err =
				le32_to_cpu(pcmd->dbg_rx_cnt.rx_drop_sta_err);
			rx_cnt->rx_drop_sta_disable =
				__le32_to_cpu(pcmd->dbg_rx_cnt.
					      rx_drop_sta_disable);
			rx_cnt->rx_drop_llc_err =
				__le32_to_cpu(pcmd->dbg_rx_cnt.rx_drop_llc_err);
			rx_cnt->rx_drop_msdu_err =
				__le32_to_cpu(pcmd->dbg_rx_cnt.
					      rx_drop_msdu_err);
			for (i = 0; i < 3; i++)
				rx_cnt->rx_bmq_refill_fail[i] =
					__le32_to_cpu(pcmd->dbg_rx_cnt.
						      rx_bmq_refill_fail[i]);
			rx_cnt->rx_cfh_ul_sig_err =
				__le32_to_cpu(pcmd->dbg_rx_cnt.
					      rx_cfh_ul_sig_err);
			rx_cnt->rx_cfh_ul_bpid_err =
				__le32_to_cpu(pcmd->dbg_rx_cnt.
					      rx_cfh_ul_bpid_err);
			rx_cnt->rx_cfh_ul_snap_err =
				__le32_to_cpu(pcmd->dbg_rx_cnt.
					      rx_cfh_ul_snap_err);
			rx_cnt->rx_cfh_ul_size_err =
				__le32_to_cpu(pcmd->dbg_rx_cnt.
					      rx_cfh_ul_size_err);
			rx_cnt->rx_cfh_ul_war =
				__le32_to_cpu(pcmd->dbg_rx_cnt.rx_cfh_ul_war);
		}
		break;
	case GET_STATS_DBG_PKT_CNT:
		{
			struct dbg_pkt_cnt *pkt_cnt =
				(struct dbg_pkt_cnt *)stats;
			int i;

			pkt_cnt->pkt_hdr_alloc =
				__le32_to_cpu(pcmd->dbg_pkt_cnt.pkt_hdr_alloc);
			pkt_cnt->pkt_hdr_free =
				__le32_to_cpu(pcmd->dbg_pkt_cnt.pkt_hdr_free);
			pkt_cnt->pkt_hdr_lack =
				__le32_to_cpu(pcmd->dbg_pkt_cnt.pkt_hdr_lack);
			pkt_cnt->pkt_bm_data_alloc =
				__le32_to_cpu(pcmd->dbg_pkt_cnt.
					      pkt_bm_data_alloc);
			pkt_cnt->pkt_bm_data_free =
				__le32_to_cpu(pcmd->dbg_pkt_cnt.
					      pkt_bm_data_free);
			for (i = 0; i < 3; i++) {
				pkt_cnt->pkt_bmq_alloc[i] =
					__le32_to_cpu(pcmd->dbg_pkt_cnt.
						      pkt_bmq_alloc[i]);
				pkt_cnt->pkt_bmq_free[i] =
					__le32_to_cpu(pcmd->dbg_pkt_cnt.
						      pkt_bmq_free[i]);
				pkt_cnt->pkt_bmq_lack_buf[i] =
					__le32_to_cpu(pcmd->dbg_pkt_cnt.
						      pkt_bmq_lack_buf[i]);
			}
			pkt_cnt->pkt_bm_data_clone =
				__le32_to_cpu(pcmd->dbg_pkt_cnt.
					      pkt_bm_data_clone);
			pkt_cnt->pkt_bm_data_clone_free =
				__le32_to_cpu(pcmd->dbg_pkt_cnt.
					      pkt_bm_data_clone_free);
			pkt_cnt->pkt_host_data_free =
				__le32_to_cpu(pcmd->dbg_pkt_cnt.
					      pkt_host_data_free);
			pkt_cnt->pkt_eth_data_free =
				__le32_to_cpu(pcmd->dbg_pkt_cnt.
					      pkt_eth_data_free);
			pkt_cnt->pkt_local_data_free =
				__le32_to_cpu(pcmd->dbg_pkt_cnt.
					      pkt_local_data_free);
			pkt_cnt->pkt_amsdu_free =
				__le32_to_cpu(pcmd->dbg_pkt_cnt.pkt_amsdu_free);
			pkt_cnt->pkt_amsdu_alloc =
				__le32_to_cpu(pcmd->dbg_pkt_cnt.
					      pkt_amsdu_alloc);
			pkt_cnt->pkt_amsdu_lack =
				__le32_to_cpu(pcmd->dbg_pkt_cnt.pkt_amsdu_lack);
		}
		break;
	case GET_STATS_DBG_STA_CNT:
		{
			struct dbg_sta_cnt *sta_cnt =
				(struct dbg_sta_cnt *)stats;
			int i;

			sta_cnt->stn_id =
				__le16_to_cpu(pcmd->dbg_sta_cnt.stn_id);
			memcpy(sta_cnt->mac_addr, pcmd->dbg_sta_cnt.mac_addr,
			       ETH_ALEN);
			sta_cnt->send_cnt =
				__le32_to_cpu(pcmd->dbg_sta_cnt.send_cnt);
			sta_cnt->rel_cnt =
				__le32_to_cpu(pcmd->dbg_sta_cnt.rel_cnt);
			sta_cnt->pend_cnt =
				__le32_to_cpu(pcmd->dbg_sta_cnt.pend_cnt);
			sta_cnt->drop_cnt =
				__le32_to_cpu(pcmd->dbg_sta_cnt.drop_cnt);
			for (i = 0; i < 8; i++)
				sta_cnt->txq_pend_cnt[i] =
					__le32_to_cpu(pcmd->dbg_sta_cnt.
						      txq_pend_cnt[i]);
			*more = __le16_to_cpu(pcmd->dbg_sta_cnt.more);
		}
		break;
	case GET_STATS_HFRMQ_INFO:
		{
			struct dbg_hfrmq_info *hfrmq_info =
				(struct dbg_hfrmq_info *)stats;
			if (hfrmq_info->qid == pcmd->dbg_hfrmq_info.qid &&
			    hfrmq_info->qoff == pcmd->dbg_hfrmq_info.qoff) {
				hfrmq_info->rdptr = pcmd->dbg_hfrmq_info.rdptr;
				hfrmq_info->wrptr = pcmd->dbg_hfrmq_info.wrptr;
			}
		}
		break;
	default:
		return -EINVAL;
	}

	mutex_unlock(&dol->cmd_mutex);

	return 0;
}

static void
__dol_set_dbg_ctrl(void *ctrl, int rid, u16 dbg_ctrl)
{
	struct wlprivate *wlpptr = (struct wlprivate *)ctrl;
	struct dol_cmd_set_dbg_ctrl *pcmd;
	struct dol_ctrl *dol = &wlpptr->wlpd_p->dol;

	pcmd = (struct dol_cmd_set_dbg_ctrl *)&dol->cmd_buf[0];

	mutex_lock(&dol->cmd_mutex);

	memset(pcmd, 0x00, sizeof(*pcmd));
	pcmd->cmd_hdr.radio = cpu_to_le16(rid);
	pcmd->cmd_hdr.cmd = cpu_to_le16(DOL_CMD_SET_DBG_CTRL);
	pcmd->cmd_hdr.len = cpu_to_le16(sizeof(*pcmd));
	pcmd->dbg_ctrl = cpu_to_le16(dbg_ctrl);

	dol_core_exec_cmd(wlpptr, DOL_CMD_SET_DBG_CTRL, false);

	mutex_unlock(&dol->cmd_mutex);
}

static struct mwl_dol_ops dol_ops = {
	.name = DOL_DESC,
	.version = DOL_VER_STR,
	.init = __dol_core_init,
	.deinit = __dol_core_deinit,
	.check_active = __dol_core_check_active,
	.get_wfo_version = __dol_core_get_wfo_version,
	.start_radio = __dol_core_start_radio,
	.stop_radio = __dol_core_stop_radio,
	.suspend_radio = __dol_core_suspend_radio,
	.radio_data_ctrl = __dol_core_radio_data_ctrl,
	.radio_tx_ampdu_ctrl = __dol_core_radio_tx_ampdu_ctrl,
	.radio_return_buffer = __dol_core_radio_return_buffer,
	.radio_get_rx_info = __dol_core_radio_get_rx_info,
	.add_vif = __dol_core_add_vif,
	.del_vif = __dol_core_del_vif,
	.vif_data_ctrl = __dol_core_vif_data_ctrl,
	.vif_set_isolate_grp_id = __dol_core_vif_set_isolate_grp_id,
	.add_sta = __dol_core_add_sta,
	.del_sta = __dol_core_del_sta,
	.sta_data_ctrl = __dol_core_sta_data_ctrl,
	.sta_tx_ampdu_ctrl = __dol_core_sta_tx_ampdu_ctrl,
	.set_ba_info = __dol_set_ba_info,
	.set_ba_req = __dol_set_ba_req,
	.xmit = __dol_core_xmit,
	.recv = __dol_core_recv,
	.set_dscp_wmm_mapping = __dol_set_dscp_wmm_mapping,
	.get_stats = __dol_core_get_stats,
	.set_dbg_ctrl = __dol_set_dbg_ctrl,
};

int
dol_core_init(struct wlprivate *wlpptr)
{
	if (wlpptr->wlpd_p->dol.ops)
		return -EBUSY;

	wlpptr->wlpd_p->dol.ops = &dol_ops;

	skb_queue_head_init(&wlpptr->wlpd_p->recv_q_data);
	skb_queue_head_init(&wlpptr->wlpd_p->recv_q_mgmt);
	INIT_WORK(&wlpptr->wlpd_p->delay_cmd_handle, dol_core_delay_cmd_handle);
	INIT_LIST_HEAD(&wlpptr->wlpd_p->delay_cmd_list);

	pe_platform_init(wlpptr);

	printk("%s\n", DOL_DESC);
	printk("version: %s\n", DOL_VER_STR);
	printk("%s(%d): command time out: %d ms, HZ: %d\n",
	       __func__, wlpptr->wlpd_p->ipc_session_id, DOL_CMD_TIMEOUT, HZ);

	return 0;
}

void
dol_core_deinit(struct wlprivate *wlpptr)
{
	wlpptr->wlpd_p->dol.ops = NULL;

	pe_platform_deinit(wlpptr);
}
