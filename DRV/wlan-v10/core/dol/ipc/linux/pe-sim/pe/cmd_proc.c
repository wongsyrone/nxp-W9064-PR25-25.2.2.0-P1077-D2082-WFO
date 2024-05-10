/** @file cmd_proc.c
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

#include "radio.h"
#include "ipc.h"
#include "ipc_msg.h"
#include "dbg.h"

static void
cmd_proc_reply(struct radio *radio, void *cmd, ca_uint16_t cmd_size)
{
	ca_ipc_pkt_t ipc_pkt;

	if (radio->pending_cmd_reply) {
		MFREE(radio->pending_cmd_reply);
		radio->pending_cmd_reply = NULL;
	}

	ipc_pkt.session_id = SYSADPT_MSG_IPC_SESSION;
	ipc_pkt.dst_cpu_id = SYSADPT_MSG_IPC_DST_CPU;
	ipc_pkt.priority = 0;
	ipc_pkt.msg_no = WFO_IPC_T2H_CMD_REPLY;
	ipc_pkt.msg_data = cmd;
	ipc_pkt.msg_size = cmd_size;

	if (ca_ipc_msg_async_send(&ipc_pkt)) {
		radio->pending_cmd_reply = (void *)MALLOC(sizeof(ca_ipc_pkt_t));
		memcpy(radio->pending_cmd_reply, &ipc_pkt,
		       sizeof(ca_ipc_pkt_t));
	}
}

static void
cmd_proc_check_active(struct radio *radio)
{
	struct dol_cmd_check_active *cmd =
		(struct dol_cmd_check_active *)radio->cmd_buf;

	cmd->active = (ca_uint32_t) pe_ready;
	cmd->cmd_hdr.result = 0;
	cmd_proc_reply(radio, cmd, radio->cmd_buf_len);
}

static void
cmd_proc_get_wfo_version(struct radio *radio)
{
	struct dol_cmd_get_wfo_version *cmd =
		(struct dol_cmd_get_wfo_version *)radio->cmd_buf;

	memcpy(cmd->version, WFO_VERSION, 32);
	cmd->cmd_hdr.result = 0;
	cmd_proc_reply(radio, cmd, radio->cmd_buf_len);
}

#ifdef CORTINA_TUNE_HW_CPY
void
__init_tx_descritpor(struct radio *radio, wltxdesc_t * txcfg)
{
	struct llc_snap *llc_snap;

	memset((void *)txcfg, 0, sizeof(wltxdesc_t));
	llc_snap = (struct llc_snap *)&txcfg->mpdu_ht_a_ctrl;
	llc_snap->llc_dsap = llc_snap->llc_ssap = LLC_SNAP_LSAP;
	llc_snap->control = LLC_UI;
	llc_snap->org_code[0] = 0;
	llc_snap->org_code[1] = 0;
	llc_snap->org_code[2] = 0;
	txcfg->hdr.cfh_length = sizeof(wltxdesc_t);
	txcfg->mpdu_flag = 0;
	txcfg->ndr = 1;
	txcfg->vtv = 0;
	txcfg->llt = 7;
	txcfg->len_ovr = 0;
	txcfg->mpdu_frame_ctrl = 0x40c5;
	txcfg->hdr.hi_byte_addr = radio->smac_buf_hi_addr;
	txcfg->hdr.bpid = radio->tx_q_start;
}
#endif

static void
cmd_proc_start_radio(struct radio *radio)
{
	struct dol_cmd_start_radio *cmd =
		(struct dol_cmd_start_radio *)radio->cmd_buf;
	int rc;
	ca_uint32_t rxinfo_aux_poll_size = 0;

	if (radio->rid != cmd->cmd_hdr.radio) {
		cmd->cmd_hdr.result = -EINVAL;
		goto cmd_reply;
	}
#ifdef LINUX_PE_SIM
	radio->iobase0 = (void __iomem *)cmd->iobase0;
	radio->iobase1 = (void __iomem *)cmd->iobase1;
	radio->dev = (void *)cmd->dev;
#else
	radio->iobase0 = (void __iomem *)PHYS_TO_VIRT(cmd->iobase0_phy);
	radio->iobase1 = (void __iomem *)PHYS_TO_VIRT(cmd->iobase1_phy);
#endif
	radio->smac_buf_hi_addr = cmd->smac_buf_hi_addr;
	radio->devid = cmd->devid;
	radio->chip_revision = cmd->chip_revision;
	radio->dbg_ctrl = cmd->dbg_ctrl;
	radio->rx_info_addr =
		(struct bbrx_rx_info *)PHYS_TO_VIRT(cmd->rx_info_phy_addr);
	radio->rx_info_que_size = cmd->rx_info_que_size;
	rxinfo_aux_poll_size =
		sizeof(struct rx_info_aux) * (radio->rx_info_que_size);
	radio->rxinfo_aux_poll =
		(struct rx_info_aux *)MALLOC(rxinfo_aux_poll_size);
	if (!radio->rxinfo_aux_poll) {
		printf("%s: MALLOC for rxinfo_aux_poll failed, size=%d, entry num=%d\n", __func__, rxinfo_aux_poll_size, radio->rx_info_que_size);
		cmd->cmd_hdr.result = -EINVAL;
		goto cmd_reply;
	}
	memset(radio->rxinfo_aux_poll, 0, rxinfo_aux_poll_size);
	memcpy(&radio->bss_num, &cmd->bss_num, 46);
	printf("\t <<PE radio %d>>\n", radio->rid);
	printf("\t dev id: %04x, chip revisioin: %04x\n",
	       radio->devid, radio->chip_revision);
	printf("\t iobase0: %p\n", radio->iobase0);
	printf("\t iobase1: %p\n", radio->iobase1);
	printf("\t hi addr: %08x\n", radio->smac_buf_hi_addr);
	printf("\t rx_info_addr: %p, phy addr: %08x\n", radio->rx_info_addr,
	       cmd->rx_info_phy_addr);
	printf("\t rxinfo_aux_poll: %p, rxinfo_aux_poll_size: %d, sizeof(struct rx_info_aux): %d, rx_info_que_size: %d\n", radio->rxinfo_aux_poll, rxinfo_aux_poll_size, sizeof(struct rx_info_aux), radio->rx_info_que_size);
	printf("\t bss number: %d\n", radio->bss_num);
	printf("\t rx: %d %d, tx: %d %d, bm: %d %d, rel: %d %d\n",
	       radio->rx_q_data, radio->rx_q_size,
	       radio->tx_q_start, radio->tx_q_num,
	       radio->bm_q_start, radio->bm_q_num,
	       radio->rel_q_start, radio->rel_q_num);
	printf("\t extra packet header: %d, extra bm buffer: %d %d %d\n",
	       SYSADPT_MAX_EXTRA_PKT_HDR,
	       SYSADPT_EXTRA_BM_BUF_NUM_Q10,
	       SYSADPT_EXTRA_BM_BUF_NUM_Q11, SYSADPT_EXTRA_BM_BUF_NUM_Q12);
	printf("\t command length: %u, dbg_ctrl: 0x%04x\n",
	       (ca_uint32_t) sizeof(*cmd), radio->dbg_ctrl);
	rc = pkt_init(radio->rid);
	if (rc) {
		cmd->cmd_hdr.result = rc;
		goto cmd_reply;
	}
	rc = BQM_init(radio->rid);
	if (rc) {
		cmd->cmd_hdr.result = rc;
		goto cmd_reply;
	}
#ifdef BA_REORDER
	rc = ba_init(radio->rid);
	if (rc) {
		cmd->cmd_hdr.result = rc;
		goto cmd_reply;
	}
#endif
#ifdef CORTINA_TUNE_HW_CPY_RX
	if (radio->rid == 1)
		radio->cfhul_amsdu.rxdesc =
			(wlrxdesc_t *) FAST_MEM_WIFI_RX_DESC_ARRAY;
	else
		radio->cfhul_amsdu.rxdesc =
			(wlrxdesc_t *) FAST_MEM_WIFI_RX_DESC1_ARRAY;
	rx_desc_now = NULL;
	rx_desc_end = NULL;
	rx_desc_async_wait = 0;
	if (radio->rid > 1)
		printf("error !! cannot support 2 radio or more now!!\n");
#endif
#ifdef CORTINA_TUNE_HW_CPY
	__init_tx_descritpor(radio, (wltxdesc_t *) FAST_MEM_WIFI_TX_DESC);
#endif
	eth_reg_recv_fun(tx_proc_eth_pkt);
	eth_reg_free_fun(rx_free_pkt_to_eth);
	radio->initialized = true;
	radio->enable = false;

	cmd->cmd_hdr.result = 0;

cmd_reply:
	cmd_proc_reply(radio, cmd, radio->cmd_buf_len);
}

static void
cmd_proc_stop_radio(struct radio *radio)
{
	struct dol_cmd_stop_radio *cmd =
		(struct dol_cmd_stop_radio *)radio->cmd_buf;

	if (radio->dbg_ctrl & DBG_DUMP_DOL_CMD)
		printf("\t %s(%d)\n", __func__, cmd->cmd_hdr.radio);

	if (radio->rid != cmd->cmd_hdr.radio) {
		cmd->cmd_hdr.result = -EINVAL;
		goto cmd_reply;
	}

	stadb_delsta_all(radio->rid);
	BQM_deinit(radio->rid);
	pkt_deinit(radio->rid);
#ifdef BA_REORDER
	ba_deinit(radio->rid);
#endif
	MFREE(radio->rxinfo_aux_poll);

	radio->initialized = false;
	radio->enable = false;

	cmd->cmd_hdr.result = 0;

cmd_reply:
	cmd_proc_reply(radio, cmd, radio->cmd_buf_len);
}

static void
cmd_proc_suspend_radio(struct radio *radio)
{
	struct dol_cmd_suspend_radio *cmd =
		(struct dol_cmd_suspend_radio *)radio->cmd_buf;

	if (radio->dbg_ctrl & DBG_DUMP_DOL_CMD)
		printf("\t %s(%d)\n", __func__, cmd->cmd_hdr.radio);

	if (radio->rid != cmd->cmd_hdr.radio) {
		cmd->cmd_hdr.result = -EINVAL;
		goto cmd_reply;
	}
	if (cmd->suspend)
		radio->suspend = true;
	else
		radio->suspend = false;
	cmd->cmd_hdr.result = 0;

cmd_reply:
	cmd_proc_reply(radio, cmd, radio->cmd_buf_len);
}

static void
cmd_proc_radio_data_ctrl(struct radio *radio)
{
	struct dol_cmd_radio_data_ctrl *cmd =
		(struct dol_cmd_radio_data_ctrl *)radio->cmd_buf;

	if (radio->dbg_ctrl & DBG_DUMP_DOL_CMD)
		printf("\t %s(%d): enable: %d\n", __func__,
		       cmd->cmd_hdr.radio, cmd->enable);

	if (radio->rid != cmd->cmd_hdr.radio) {
		cmd->cmd_hdr.result = -EINVAL;
		goto cmd_reply;
	}

	if (!radio->initialized) {
		cmd->cmd_hdr.result = -EPERM;
		goto cmd_reply;
	}

	radio->enable = cmd->enable;

	if (radio->enable)
		BQM_post_init_bq_idx(radio->rid);

	cmd->cmd_hdr.result = 0;

cmd_reply:
	cmd_proc_reply(radio, cmd, radio->cmd_buf_len);
}

static void
cmd_proc_radio_tx_ampdu_ctrl(struct radio *radio)
{
	struct dol_cmd_radio_tx_ampdu_ctrl *cmd =
		(struct dol_cmd_radio_tx_ampdu_ctrl *)radio->cmd_buf;

	if (radio->dbg_ctrl & DBG_DUMP_DOL_CMD)
		printf("\t %s(%d): ampdu_tx: %d\n", __func__,
		       cmd->cmd_hdr.radio, cmd->ampdu_tx);

	if (radio->rid != cmd->cmd_hdr.radio) {
		cmd->cmd_hdr.result = -EINVAL;
		goto cmd_reply;
	}

	if (!radio->initialized) {
		cmd->cmd_hdr.result = -EPERM;
		goto cmd_reply;
	}

	radio->ampdu_tx = cmd->ampdu_tx;

	cmd->cmd_hdr.result = 0;

cmd_reply:
	cmd_proc_reply(radio, cmd, radio->cmd_buf_len);
}

static void
cmd_proc_radio_return_buffer(struct radio *radio)
{
	struct dol_cmd_radio_return_buffer *cmd =
		(struct dol_cmd_radio_return_buffer *)radio->cmd_buf;
	int i;
	struct pkt_hdr *pkt_hdr;

	if (radio->rid != cmd->cmd_hdr.radio)
		return;

	if (!radio->initialized)
		return;

	for (i = 0; i < cmd->return_num; i++) {
#ifdef ENABLE_PKT_DATA_STATUS
		{
			struct pkt_data *pkt_data;

			pkt_data = (struct pkt_data *)
				(((struct pkt_hdr *)__PLATFORM_POINTER_TYPE__
				  cmd->pkt_hdr_addr)->buf_ptr[i] -
				 PKT_DATA_HEADROOM);
			pkt_data->status = PKT_DATA_ALLOC;
		}
#endif
		pkt_hdr =
			(struct pkt_hdr *)__PLATFORM_POINTER_TYPE__
			cmd->pkt_hdr_addr[i];
		if (!pkt_hdr->ref_cnt) {
			if (list_search_item(&radio->pkt_ctrl.pkt_hdr_free_list,
					     (struct list_item *)pkt_hdr) ==
			    NULL)
				printf("untracked packet header with zero reference count: %p\n", pkt_hdr);
		} else {
			reset_signature(((struct pkt_hdr *)
					 __PLATFORM_POINTER_TYPE__
					 cmd->pkt_hdr_addr[i])->data);
			pkt_free_data(radio->rid,
				      (struct pkt_hdr *)
				      __PLATFORM_POINTER_TYPE__
				      cmd->pkt_hdr_addr[i], __func__);
		}
		radio->dbg_cnt.rel_cnt.bm_release_from_host++;
	}
}

static void
cmd_proc_radio_get_rx_info(struct radio *radio)
{
	struct dol_cmd_radio_get_rx_info *cmd =
		(struct dol_cmd_radio_get_rx_info *)radio->cmd_buf;
	struct drv_rate_hist *rate_hist;
	ca_uint32_t cnt;

	if (radio->dbg_ctrl & DBG_DUMP_DOL_CMD)
		printf("\t %s(%d): clean: %d, first: %d\n", __func__,
		       cmd->cmd_hdr.radio, cmd->clean, cmd->first);

	if (radio->rid != cmd->cmd_hdr.radio) {
		cmd->cmd_hdr.result = -EINVAL;
		goto cmd_reply;
	}

	if (!radio->initialized) {
		cmd->cmd_hdr.result = -EPERM;
		goto cmd_reply;
	}

	rate_hist = &radio->rx_rate_hist;

	if (cmd->clean)
		memset(rate_hist, 0, sizeof(struct drv_rate_hist));
	else {
		if (cmd->first) {
			rate_hist->cur_type = 0;
			rate_hist->cur_nss = 0;
			rate_hist->cur_bw = 0;
			rate_hist->cur_gi = 0;
			rate_hist->cur_idx = 0;
		}
		cmd->rate_num = 0;
		while (rate_hist->cur_type < RATE_TYPE_MAX) {
			switch (rate_hist->cur_type) {
			case RATE_LEGACY:
				while (rate_hist->cur_idx < QS_MAX_DATA_RATES_G) {
					cnt = rate_hist->
						legacy_rates[rate_hist->
							     cur_idx];
					if (cnt) {
						cmd->rate_info[cmd->rate_num].
							type = RATE_LEGACY;
						cmd->rate_info[cmd->rate_num].
							gi_idx =
							rate_hist->cur_idx;
						cmd->rate_info[cmd->rate_num].
							cnt = cnt;
						cmd->rate_num++;
						if (cmd->rate_num >= 9)
							goto done;
					}
					rate_hist->cur_idx++;
				}
				break;
			case RATE_HT:
				while (rate_hist->cur_bw <
				       QS_NUM_SUPPORTED_11N_BW) {
					while (rate_hist->cur_gi <
					       QS_NUM_SUPPORTED_GI) {
						while (rate_hist->cur_idx <
						       QS_NUM_SUPPORTED_MCS) {
							cnt = rate_hist->
								ht_rates
								[rate_hist->
								 cur_bw]
								[rate_hist->
								 cur_gi]
								[rate_hist->
								 cur_idx];
							if (cnt) {
								cmd->rate_info
									[cmd->
									 rate_num].
									type =
									RATE_HT;
								cmd->rate_info
									[cmd->
									 rate_num].
									bw =
									rate_hist->
									cur_bw;
								cmd->rate_info
									[cmd->
									 rate_num].
									gi_idx =
									(rate_hist->
									 cur_gi
									 << 4) |
									rate_hist->
									cur_idx;
								cmd->rate_info
									[cmd->
									 rate_num].
									cnt =
									cnt;
								cmd->rate_num++;
								if (cmd->
								    rate_num >=
								    9)
									goto done;
							}
							rate_hist->cur_idx++;
						}
						rate_hist->cur_gi++;
						rate_hist->cur_idx = 0;
					}
					rate_hist->cur_bw++;
					rate_hist->cur_idx = 0;
					rate_hist->cur_gi = 0;
				}
				break;
			case RATE_VHT:
				while (rate_hist->cur_nss <
				       QS_NUM_SUPPORTED_11AC_NSS) {
					while (rate_hist->cur_bw <
					       QS_NUM_SUPPORTED_11AC_BW) {
						while (rate_hist->cur_gi <
						       QS_NUM_SUPPORTED_GI) {
							while (rate_hist->
							       cur_idx <
							       QS_NUM_SUPPORTED_11AC_MCS)
							{
								cnt = rate_hist->vht_rates[rate_hist->cur_nss][rate_hist->cur_bw][rate_hist->cur_gi][rate_hist->cur_idx];
								if (cnt) {
									cmd->rate_info[cmd->rate_num].type = RATE_VHT;
									cmd->rate_info[cmd->rate_num].nss = rate_hist->cur_nss;
									cmd->rate_info[cmd->rate_num].bw = rate_hist->cur_bw;
									cmd->rate_info[cmd->rate_num].gi_idx = (rate_hist->cur_gi << 4) | rate_hist->cur_idx;
									cmd->rate_info[cmd->rate_num].cnt = cnt;
									cmd->rate_num++;
									if (cmd->rate_num >= 9)
										goto done;
								}
								rate_hist->
									cur_idx++;
							}
							rate_hist->cur_gi++;
							rate_hist->cur_idx = 0;
						}
						rate_hist->cur_bw++;
						rate_hist->cur_idx = 0;
						rate_hist->cur_gi = 0;
					}
					rate_hist->cur_nss++;
					rate_hist->cur_idx = 0;
					rate_hist->cur_gi = 0;
					rate_hist->cur_bw = 0;
				}
				break;
			case RATE_HE:
				while (rate_hist->cur_nss <
				       QS_NUM_SUPPORTED_11AX_NSS) {
					while (rate_hist->cur_bw <
					       QS_NUM_SUPPORTED_11AX_BW) {
						while (rate_hist->cur_gi <
						       QS_NUM_SUPPORTED_11AX_GILTF)
						{
							while (rate_hist->
							       cur_idx <
							       QS_NUM_SUPPORTED_11AX_MCS)
							{
								cnt = rate_hist->he_rates[rate_hist->cur_nss][rate_hist->cur_bw][rate_hist->cur_gi][rate_hist->cur_idx];
								if (cnt) {
									cmd->rate_info[cmd->rate_num].type = RATE_HE;
									cmd->rate_info[cmd->rate_num].nss = rate_hist->cur_nss;
									cmd->rate_info[cmd->rate_num].bw = rate_hist->cur_bw;
									cmd->rate_info[cmd->rate_num].gi_idx = (rate_hist->cur_gi << 4) | rate_hist->cur_idx;
									cmd->rate_info[cmd->rate_num].cnt = cnt;
									cmd->rate_num++;
									if (cmd->rate_num >= 9)
										goto done;
								}
								rate_hist->
									cur_idx++;
							}
							rate_hist->cur_gi++;
							rate_hist->cur_idx = 0;
						}
						rate_hist->cur_bw++;
						rate_hist->cur_idx = 0;
						rate_hist->cur_gi = 0;
					}
					rate_hist->cur_nss++;
					rate_hist->cur_idx = 0;
					rate_hist->cur_gi = 0;
					rate_hist->cur_bw = 0;
				}
				break;
			default:
				break;
			}
			rate_hist->cur_type++;
			rate_hist->cur_nss = 0;
			rate_hist->cur_bw = 0;
			rate_hist->cur_gi = 0;
			rate_hist->cur_idx = 0;
		}
	}

done:
	if (cmd->rate_num >= 9) {
		rate_hist->cur_idx++;
		cmd->more = 1;
	}
	cmd->cmd_hdr.result = 0;

cmd_reply:
	cmd_proc_reply(radio, cmd, radio->cmd_buf_len);
}

static void
cmd_proc_add_vif(struct radio *radio)
{
	struct dol_cmd_add_vif *cmd = (struct dol_cmd_add_vif *)radio->cmd_buf;
	int vid;
	struct vif *vif_info;

	if (radio->dbg_ctrl & DBG_DUMP_DOL_CMD)
		printf("\t %s(%d): vid: %d, bssid: %pM\n", __func__,
		       cmd->cmd_hdr.radio, cmd->vid, cmd->bssid);

	if (radio->rid != cmd->cmd_hdr.radio) {
		cmd->cmd_hdr.result = -EINVAL;
		goto cmd_reply;
	}

	if (!radio->initialized) {
		cmd->cmd_hdr.result = -EPERM;
		goto cmd_reply;
	}

	vid = cmd->vid;
	if ((vid < 0) || (vid >= radio->bss_num)) {
		cmd->cmd_hdr.result = -EINVAL;
		goto cmd_reply;
	}

	vif_info = &radio->vif_info[vid];
	vif_info->eth_handle = eth_create_dev(radio->rid, vid);
	if (!vif_info->eth_handle) {
		cmd->cmd_hdr.result = -EPERM;
		goto cmd_reply;
	}
	vif_info->rid = radio->rid;
	vif_info->vid = vid;
	memcpy(vif_info->bssid, cmd->bssid, ETH_ALEN);
	vif_info->enable = false;
	vif_info->valid = true;

	cmd->cmd_hdr.result = 0;

cmd_reply:
	cmd_proc_reply(radio, cmd, radio->cmd_buf_len);
}

static void
cmd_proc_del_vif(struct radio *radio)
{
	struct dol_cmd_del_vif *cmd = (struct dol_cmd_del_vif *)radio->cmd_buf;
	int vid;
	struct vif *vif_info;

	if (radio->dbg_ctrl & DBG_DUMP_DOL_CMD)
		printf("\t %s(%d): vid: %d\n", __func__,
		       cmd->cmd_hdr.radio, cmd->vid);

	if (radio->rid != cmd->cmd_hdr.radio) {
		cmd->cmd_hdr.result = -EINVAL;
		goto cmd_reply;
	}

	if (!radio->initialized) {
		cmd->cmd_hdr.result = -EPERM;
		goto cmd_reply;
	}

	vid = cmd->vid;
	if ((vid < 0) || (vid >= radio->bss_num)) {
		cmd->cmd_hdr.result = -EINVAL;
		goto cmd_reply;
	}

	stadb_delsta_vif(radio->rid, vid);
	vif_info = &radio->vif_info[vid];
	if (vif_info->eth_handle)
		eth_destroy_dev(vif_info->eth_handle);
	memset(vif_info, 0, sizeof(struct vif));

	cmd->cmd_hdr.result = 0;

cmd_reply:
	cmd_proc_reply(radio, cmd, radio->cmd_buf_len);
}

static void
cmd_proc_vif_data_ctrl(struct radio *radio)
{
	struct dol_cmd_vif_data_ctrl *cmd =
		(struct dol_cmd_vif_data_ctrl *)radio->cmd_buf;
	int vid;
	struct vif *vif_info;

	if (radio->dbg_ctrl & DBG_DUMP_DOL_CMD)
		printf("\t %s(%d): vid: %d, enable: %d\n", __func__,
		       cmd->cmd_hdr.radio, cmd->vid, cmd->enable);

	if (radio->rid != cmd->cmd_hdr.radio) {
		cmd->cmd_hdr.result = -EINVAL;
		goto cmd_reply;
	}

	if (!radio->initialized) {
		cmd->cmd_hdr.result = -EPERM;
		goto cmd_reply;
	}

	vid = cmd->vid;
	if ((vid < 0) || (vid >= radio->bss_num)) {
		cmd->cmd_hdr.result = -EINVAL;
		goto cmd_reply;
	}

	vif_info = &radio->vif_info[vid];
	if (!vif_info->valid) {
		cmd->cmd_hdr.result = -EPERM;
		goto cmd_reply;
	}

	vif_info->enable = cmd->enable;

	cmd->cmd_hdr.result = 0;

cmd_reply:
	cmd_proc_reply(radio, cmd, radio->cmd_buf_len);
}

static void
cmd_proc_vif_set_isolate_grp_id(struct radio *radio)
{
	struct dol_cmd_vif_set_isolate_grp_id *cmd =
		(struct dol_cmd_vif_set_isolate_grp_id *)radio->cmd_buf;
	int vid;
	struct vif *vif_info;

	if (radio->dbg_ctrl & DBG_DUMP_DOL_CMD)
		printf("\t %s(%d): vid: %d, isolate_group_id: %d\n", __func__,
		       cmd->cmd_hdr.radio, cmd->vid, cmd->isolate_group_id);

	if (radio->rid != cmd->cmd_hdr.radio) {
		cmd->cmd_hdr.result = -EINVAL;
		goto cmd_reply;
	}

	if (!radio->initialized) {
		cmd->cmd_hdr.result = -EPERM;
		goto cmd_reply;
	}

	vid = cmd->vid;
	if ((vid < 0) || (vid >= radio->bss_num)) {
		cmd->cmd_hdr.result = -EINVAL;
		goto cmd_reply;
	}

	vif_info = &radio->vif_info[vid];
	if (!vif_info->valid) {
		cmd->cmd_hdr.result = -EPERM;
		goto cmd_reply;
	}

	vif_info->isolate_group_id = cmd->isolate_group_id;

	cmd->cmd_hdr.result = 0;

cmd_reply:
	cmd_proc_reply(radio, cmd, radio->cmd_buf_len);
}

static void
cmd_proc_add_sta(struct radio *radio)
{
	struct dol_cmd_add_sta *cmd = (struct dol_cmd_add_sta *)radio->cmd_buf;
	int vid;
	struct vif *vif_info;

	if (radio->dbg_ctrl & DBG_DUMP_DOL_CMD)
		printf("\t %s(%d): vid: %d, sta: %pM\n", __func__,
		       cmd->cmd_hdr.radio, cmd->vid, cmd->sta_mac);

	if (radio->rid != cmd->cmd_hdr.radio) {
		cmd->cmd_hdr.result = -EINVAL;
		goto cmd_reply;
	}

	if (!radio->initialized) {
		cmd->cmd_hdr.result = -EPERM;
		goto cmd_reply;
	}

	vid = cmd->vid;
	if ((vid < 0) || (vid >= radio->bss_num)) {
		cmd->cmd_hdr.result = -EINVAL;
		goto cmd_reply;
	}

	vif_info = &radio->vif_info[vid];
	if (!vif_info->valid) {
		cmd->cmd_hdr.result = -EPERM;
		goto cmd_reply;
	}

	stadb_addsta(radio->rid, vid, cmd->sta_mac);

	cmd->cmd_hdr.result = 0;

cmd_reply:
	cmd_proc_reply(radio, cmd, radio->cmd_buf_len);
}

static void
cmd_proc_del_sta(struct radio *radio)
{
	struct dol_cmd_del_sta *cmd = (struct dol_cmd_del_sta *)radio->cmd_buf;
	int vid;
	struct vif *vif_info;

	if (radio->dbg_ctrl & DBG_DUMP_DOL_CMD)
		printf("\t %s(%d): vid: %d, sta: %pM\n", __func__,
		       cmd->cmd_hdr.radio, cmd->vid, cmd->sta_mac);

	if (radio->rid != cmd->cmd_hdr.radio) {
		cmd->cmd_hdr.result = -EINVAL;
		goto cmd_reply;
	}

	if (!radio->initialized) {
		cmd->cmd_hdr.result = -EPERM;
		goto cmd_reply;
	}

	vid = cmd->vid;
	if ((vid < 0) || (vid >= radio->bss_num)) {
		cmd->cmd_hdr.result = -EINVAL;
		goto cmd_reply;
	}

	vif_info = &radio->vif_info[vid];
	if (!vif_info->valid) {
		cmd->cmd_hdr.result = -EPERM;
		goto cmd_reply;
	}

	stadb_delsta(radio->rid, cmd->sta_mac);

	cmd->cmd_hdr.result = 0;

cmd_reply:
	cmd_proc_reply(radio, cmd, radio->cmd_buf_len);
}

extern int omi_event_to_host(struct radio *radio, ca_uint16_t om_control,
			     ca_uint16_t stnid, ca_uint8_t * mac);

static void
cmd_proc_sta_data_ctrl(struct radio *radio)
{
	struct dol_cmd_sta_data_ctrl *cmd =
		(struct dol_cmd_sta_data_ctrl *)radio->cmd_buf;
	int vid;
	struct vif *vif_info;
	struct sta_info *sta_info;

	if (radio->dbg_ctrl & DBG_DUMP_DOL_CMD)
		printf("\t %s(%d): vid: %d, id: %d, sta: %pM, enable: %d\n",
		       __func__, cmd->cmd_hdr.radio, cmd->vid, cmd->stn_id,
		       cmd->sta_mac, cmd->enable);

	if (radio->rid != cmd->cmd_hdr.radio) {
		cmd->cmd_hdr.result = -EINVAL;
		goto cmd_reply;
	}

	if (!radio->initialized) {
		cmd->cmd_hdr.result = -EPERM;
		goto cmd_reply;
	}

	vid = cmd->vid;
	if ((vid < 0) || (vid >= radio->bss_num)) {
		cmd->cmd_hdr.result = -EINVAL;
		goto cmd_reply;
	}

	vif_info = &radio->vif_info[vid];
	if (!vif_info->valid) {
		cmd->cmd_hdr.result = -EPERM;
		goto cmd_reply;
	}

	sta_info = stadb_get_stainfo(radio->rid, cmd->sta_mac);
	if (!sta_info) {
		cmd->cmd_hdr.result = -EPERM;
		goto cmd_reply;
	}

	sta_info->stn_id = cmd->stn_id;
	sta_info->enable = cmd->enable;

	if (sta_info->enable == 1 && sta_info->om_control != 0) {
		printf("delay omi_control:%02x\n", sta_info->om_control);
		if (!omi_event_to_host
		    (radio, sta_info->om_control, sta_info->stn_id,
		     sta_info->mac_addr))
			sta_info->om_control = 0;
	}

	cmd->cmd_hdr.result = 0;

cmd_reply:
	cmd_proc_reply(radio, cmd, radio->cmd_buf_len);
}

static void
cmd_proc_sta_tx_ampdu_ctrl(struct radio *radio)
{
	struct dol_cmd_sta_tx_ampdu_ctrl *cmd =
		(struct dol_cmd_sta_tx_ampdu_ctrl *)radio->cmd_buf;
	int vid;
	struct vif *vif_info;
	struct sta_info *sta_info;
	int i;

	if (radio->dbg_ctrl & DBG_DUMP_DOL_CMD) {
		printf("\t %s(%d): vid: %d, sta: %pM, threshold: %d\n",
		       __func__, cmd->cmd_hdr.radio, cmd->vid, cmd->sta_mac,
		       cmd->threshold);
		printf("\tstartbytid: ");
		for (i = 0; i < SYSADPT_MAX_TID; i++)
			printf("%d ", cmd->startbytid[i]);
		printf("\n");
	}

	if (radio->rid != cmd->cmd_hdr.radio) {
		cmd->cmd_hdr.result = -EINVAL;
		goto cmd_reply;
	}

	if (!radio->initialized) {
		cmd->cmd_hdr.result = -EPERM;
		goto cmd_reply;
	}

	vid = cmd->vid;
	if ((vid < 0) || (vid >= radio->bss_num)) {
		cmd->cmd_hdr.result = -EINVAL;
		goto cmd_reply;
	}

	vif_info = &radio->vif_info[vid];
	if (!vif_info->valid) {
		cmd->cmd_hdr.result = -EPERM;
		goto cmd_reply;
	}

	sta_info = stadb_get_stainfo(radio->rid, cmd->sta_mac);
	if (!sta_info) {
		cmd->cmd_hdr.result = -EPERM;
		goto cmd_reply;
	}

	sta_info->threshold = cmd->threshold;
	for (i = 0; i < SYSADPT_MAX_TID; i++)
		sta_info->startbytid[i] = cmd->startbytid[i];

	cmd->cmd_hdr.result = 0;

cmd_reply:
	cmd_proc_reply(radio, cmd, radio->cmd_buf_len);
}

static void
cmd_proc_set_ba_info(struct radio *radio)
{
#ifdef BA_REORDER
	struct dol_cmd_set_ba_info *cmd =
		(struct dol_cmd_set_ba_info *)radio->cmd_buf;

	extern ca_uint16_t reorder_hold_time;

	if (radio->dbg_ctrl & DBG_DUMP_DOL_CMD)
		printf("\t %s(%d): ba_info: type: 0x%04x, stn_id: 0x%04x, tid: 0x%04x, winStartB: 0x%04x, winSizeB: 0x%04x\n", __func__, cmd->cmd_hdr.radio, cmd->type, cmd->stn_id, cmd->tid, cmd->winStartB, cmd->winSizeB);

	if (radio->rid != cmd->cmd_hdr.radio)
		return;

	if (!radio->initialized)
		return;

	switch (cmd->type) {
	case BA_INFO_ASSOC:
		ba_cmd_assoc(cmd->cmd_hdr.radio, cmd->stn_id);
		break;
	case BA_INFO_ADDBA:
		ba_cmd_addba(cmd->cmd_hdr.radio, cmd->stn_id, cmd->tid,
			     cmd->winStartB, cmd->winSizeB);
		break;
	case BA_INFO_DELBA:
		ba_cmd_delba(cmd->cmd_hdr.radio, cmd->stn_id, cmd->tid,
			     cmd->winStartB, cmd->winSizeB);
		break;
	case BA_INFO_CFG_FLUSHTIME:
		reorder_hold_time = (cmd->ba_reorder_hold_time) * (TIMER_1MS);
		printf("Set reorder_hold_time:%u ms\n", reorder_hold_time);
		break;
	default:
		printf("\t %s(%d): Unknown BA info type 0x%04x\n",
		       __func__, cmd->cmd_hdr.radio, cmd->type);
	}
#endif

	return;
}

static void
cmd_proc_set_ba_req(struct radio *radio)
{
#ifdef BA_REORDER
	struct dol_cmd_set_ba_req *cmd =
		(struct dol_cmd_set_ba_req *)radio->cmd_buf;
	int vid;
	struct vif *vif_info;

	if (radio->rid != cmd->cmd_hdr.radio)
		return;

	if (!radio->initialized)
		return;

	vid = cmd->vid;
	if ((vid < 0) || (vid >= radio->bss_num))
		return;

	vif_info = &radio->vif_info[vid];
	if (!vif_info->valid)
		return;

	ba_bar_proc(radio->rid, vif_info, cmd->stn_id, cmd->tid, cmd->seq);
#endif

	return;
}

static void
cmd_proc_set_dscp_wmm_mapping(struct radio *radio)
{
	struct dol_cmd_set_dscp_wmm_mapping *cmd =
		(struct dol_cmd_set_dscp_wmm_mapping *)radio->cmd_buf;

	if (radio->dbg_ctrl & DBG_DUMP_DOL_CMD)
		printf("\t %s(%d): dscp_wmm_mapping: %d\n", __func__,
		       cmd->cmd_hdr.radio, cmd->dscp_wmm_mapping);

	if (radio->rid != cmd->cmd_hdr.radio)
		return;

	if (!radio->initialized)
		return;

	radio->dscp_wmm_mapping = cmd->dscp_wmm_mapping;
}

static void
cmd_proc_get_stats(struct radio *radio)
{
	struct dol_cmd_get_stats *cmd =
		(struct dol_cmd_get_stats *)radio->cmd_buf;
	int i, j;

	if (sizeof(struct dol_cmd_get_stats) > sizeof(radio->cmd_buf)) {
		printf("stats cmd: %zu exceeded cmd_buf: %zu\n",
		       sizeof(struct dol_cmd_get_stats),
		       sizeof(radio->cmd_buf));
		cmd->cmd_hdr.result = -ENOMEM;
		goto cmd_reply;
	}

	if (radio->dbg_ctrl & DBG_DUMP_DOL_CMD)
		printf("\t %s(%d): type: %d\n", __func__,
		       cmd->cmd_hdr.radio, cmd->type);

	if (radio->rid != cmd->cmd_hdr.radio) {
		cmd->cmd_hdr.result = -EINVAL;
		goto cmd_reply;
	}

	if (!radio->initialized) {
		cmd->cmd_hdr.result = -EPERM;
		goto cmd_reply;
	}

	cmd->cmd_hdr.result = 0;
	switch (cmd->type) {
	case GET_STATS_NET_DEVICE:
		memcpy(&cmd->netdev_stats,
		       &radio->vif_info[cmd->vid].netdev_stats,
		       sizeof(struct netdev_stats));
		if (cmd->clear_after_read)
			memset(&radio->vif_info[cmd->vid].netdev_stats, 0,
			       sizeof(struct netdev_stats));
		break;
	case GET_STATS_PKT_STATUS:
		cmd->pkt_status.pkt_hdr_free_num =
			radio->pkt_ctrl.pkt_hdr_free_list.cnt;
		for (i = 0; i < 4; i++)
			cmd->pkt_status.pkt_bmq_free_num[i] =
				radio->pkt_ctrl.pkt_data_free_list[i].cnt;
		cmd->pkt_status.pkt_from_host_num =
			radio->pkt_ctrl.pkt_from_host_list.cnt;
		for (i = 0; i < 4; i++)
			cmd->pkt_status.pkt_from_eth_num[i] =
				radio->pkt_ctrl.pkt_from_eth_list[i].cnt;
		break;
	case GET_STATS_DBG_TX_CNT:
		memcpy(&cmd->dbg_tx_cnt, &radio->dbg_cnt.tx_cnt,
		       sizeof(struct dbg_tx_cnt));
		if (cmd->clear_after_read)
			memset(&radio->dbg_cnt.tx_cnt, 0,
			       sizeof(struct dbg_tx_cnt));
		break;
	case GET_STATS_DBG_REL_CNT:
		memcpy(&cmd->dbg_rel_cnt, &radio->dbg_cnt.rel_cnt,
		       sizeof(struct dbg_rel_cnt));
		if (cmd->clear_after_read)
			memset(&radio->dbg_cnt.rel_cnt, 0,
			       sizeof(struct dbg_rel_cnt));
		break;
	case GET_STATS_DBG_RX_CNT:
		memcpy(&cmd->dbg_rx_cnt, &radio->dbg_cnt.rx_cnt,
		       sizeof(struct dbg_rx_cnt));
		if (cmd->clear_after_read)
			memset(&radio->dbg_cnt.rx_cnt, 0,
			       sizeof(struct dbg_rx_cnt));
		break;
	case GET_STATS_DBG_PKT_CNT:
		memcpy(&cmd->dbg_pkt_cnt, &radio->dbg_cnt.pkt_cnt,
		       sizeof(struct dbg_pkt_cnt));
		if (cmd->clear_after_read)
			memset(&radio->dbg_cnt.pkt_cnt, 0,
			       sizeof(struct dbg_pkt_cnt));
		break;
	case GET_STATS_DBG_STA_CNT:
		{
			struct sta_item *sta_db;
			struct except_cnt *except_cnt;
			int stn_id;
			int qid;

			for (i = cmd->dbg_sta_cnt.more; i < SYSADPT_MAX_STA;
			     i++) {
				if (radio->stadb_ctrl->sta_db[i].sta_info.
				    enable) {
					sta_db = &radio->stadb_ctrl->sta_db[i];
					stn_id = sta_db->sta_info.stn_id;
					cmd->dbg_sta_cnt.stn_id = stn_id;
					memcpy(cmd->dbg_sta_cnt.mac_addr,
					       sta_db->sta_info.mac_addr,
					       ETH_ALEN);
					except_cnt = &radio->except_cnt;
					qid = (SYSADPT_MAX_TID * stn_id) +
						QUEUE_STAOFFSET;
					except_cnt->tx_sta_pend_cnt[stn_id] =
						except_cnt->
						tx_sta_send_cnt[stn_id] -
						except_cnt->
						tx_sta_rel_cnt[stn_id];
					cmd->dbg_sta_cnt.send_cnt =
						except_cnt->
						tx_sta_send_cnt[stn_id];
					cmd->dbg_sta_cnt.rel_cnt =
						except_cnt->
						tx_sta_rel_cnt[stn_id];
					cmd->dbg_sta_cnt.pend_cnt =
						except_cnt->
						tx_sta_pend_cnt[stn_id];
					cmd->dbg_sta_cnt.drop_cnt =
						except_cnt->
						tx_sta_drop_cnt[stn_id];
					for (j = 0; j < SYSADPT_MAX_TID; j++) {
						except_cnt->txq_pend_cnt[qid +
									 j] =
							except_cnt->
							txq_send_cnt[qid + j] -
							except_cnt->
							txq_rel_cnt[qid + j];
						cmd->dbg_sta_cnt.
							txq_pend_cnt[j] =
							except_cnt->
							txq_pend_cnt[qid + j];
					}
					break;
				}
			}
			if (i == SYSADPT_MAX_STA)
				cmd->dbg_sta_cnt.more = 0xffff;
			else
				cmd->dbg_sta_cnt.more = i + 1;
		}
		break;
	case GET_STATS_HFRMQ_INFO:
		cmd->dbg_hfrmq_info.rdptr = wlQueryRdPtr(radio->rid,
							 cmd->dbg_hfrmq_info.
							 qid,
							 cmd->dbg_hfrmq_info.
							 qoff);
		cmd->dbg_hfrmq_info.wrptr =
			wlQueryWrPtr(radio->rid, cmd->dbg_hfrmq_info.qid,
				     cmd->dbg_hfrmq_info.qoff);
		break;
	default:
		cmd->cmd_hdr.result = -EINVAL;
		break;
	}

cmd_reply:
	cmd_proc_reply(radio, cmd, radio->cmd_buf_len);
}

static void
cmd_proc_set_dbg_ctrl(struct radio *radio)
{
	struct dol_cmd_set_dbg_ctrl *cmd =
		(struct dol_cmd_set_dbg_ctrl *)radio->cmd_buf;

	if (radio->dbg_ctrl & DBG_DUMP_DOL_CMD)
		printf("\t %s(%d): dbg_ctrl: 0x%04x\n", __func__,
		       cmd->cmd_hdr.radio, cmd->dbg_ctrl);

	if (radio->rid != cmd->cmd_hdr.radio)
		return;

	if (!radio->initialized)
		return;

	radio->dbg_ctrl = cmd->dbg_ctrl;

	if (radio->dbg_ctrl & DBG_DUMP_VIF_STATUS)
		dbg_dump_vif_status(radio->rid);

	if (radio->dbg_ctrl & DBG_DUMP_RADIO_STATUS)
		dbg_dump_radio_status(radio->rid);
}

void
cmd_proc_commands(int rid, const void *cmd, ca_uint16_t cmd_size)
{
	struct radio *radio = &radio_info[rid - 1];
	struct dolcmd_header *hdr;

	if (cmd_size > sizeof(radio->cmd_buf)) {
		printf("cmd_size: %u exceed cmd_buf: %zu\n",
		       cmd_size, sizeof(radio->cmd_buf));
		return;
	}
	radio->cmd_buf_len = (cmd_size >= SYSADPT_MAX_CMD_BUF_LEN) ?
		SYSADPT_MAX_CMD_BUF_LEN : cmd_size;
	memcpy(radio->cmd_buf, cmd, radio->cmd_buf_len);

	hdr = (struct dolcmd_header *)radio->cmd_buf;

	switch (hdr->cmd) {
	case DOL_CMD_CHECK_ACTIVE:
		cmd_proc_check_active(radio);
		break;
	case DOL_CMD_GET_WFO_VERSION:
		cmd_proc_get_wfo_version(radio);
		break;
	case DOL_CMD_START_RADIO:
		cmd_proc_start_radio(radio);
		break;
	case DOL_CMD_STOP_RADIO:
		cmd_proc_stop_radio(radio);
		break;
	case DOL_CMD_SUSPEND_RADIO:
		cmd_proc_suspend_radio(radio);
		break;
	case DOL_CMD_RADIO_DATA_CTRL:
		cmd_proc_radio_data_ctrl(radio);
		break;
	case DOL_CMD_RADIO_TX_AMPDU_CTRL:
		cmd_proc_radio_tx_ampdu_ctrl(radio);
		break;
	case DOL_CMD_RADIO_RETURN_BUFFER:
		cmd_proc_radio_return_buffer(radio);
		break;
	case DOL_CMD_RADIO_GET_RX_INFO:
		cmd_proc_radio_get_rx_info(radio);
		break;
	case DOL_CMD_ADD_VIF:
		cmd_proc_add_vif(radio);
		break;
	case DOL_CMD_DEL_VIF:
		cmd_proc_del_vif(radio);
		break;
	case DOL_CMD_VIF_DATA_CTRL:
		cmd_proc_vif_data_ctrl(radio);
		break;
	case DOL_CMD_VIF_SET_ISOLATE_GRP_ID:
		cmd_proc_vif_set_isolate_grp_id(radio);
		break;
	case DOL_CMD_ADD_STA:
		cmd_proc_add_sta(radio);
		break;
	case DOL_CMD_DEL_STA:
		cmd_proc_del_sta(radio);
		break;
	case DOL_CMD_STA_DATA_CTRL:
		cmd_proc_sta_data_ctrl(radio);
		break;
	case DOL_CMD_STA_TX_AMPDU_CTRL:
		cmd_proc_sta_tx_ampdu_ctrl(radio);
		break;
	case DOL_CMD_SET_BA_INFO:
		cmd_proc_set_ba_info(radio);
		break;
	case DOL_CMD_SET_BA_REQ:
		cmd_proc_set_ba_req(radio);
		break;
	case DOL_CMD_SET_DSCP_WMM_MAPPING:
		cmd_proc_set_dscp_wmm_mapping(radio);
		break;
	case DOL_CMD_GET_STATS:
		cmd_proc_get_stats(radio);
		break;
	case DOL_CMD_SET_DBG_CTRL:
		cmd_proc_set_dbg_ctrl(radio);
		break;
	default:
		break;
	}
}
