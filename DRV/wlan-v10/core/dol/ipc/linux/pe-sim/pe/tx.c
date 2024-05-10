/** @file tx.c
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

#define AC_BK_Q              0
#define AC_BE_Q              1
#define AC_VI_Q              2
#define AC_VO_Q              3

#define CS0_IP_PRECEDENCE0   0
#define CS1_IP_PRECEDENCE1   1
#define CS2_IP_PRECEDENCE2   2
#define CS3_IP_PRECEDENCE3   3
#define CS4_IP_PRECEDENCE4   4
#define CS5_IP_PRECEDENCE5   5
#define CS6_IP_PRECEDENCE6   6
#define CS7_IP_PRECEDENCE7   7

static ca_uint8_t ac_que_mapping[8] =
	{ AC_BE_Q, AC_BK_Q, AC_BK_Q, AC_BE_Q, AC_VI_Q, AC_VI_Q, AC_VO_Q,
AC_VO_Q };

static inline int
tx_ampdu_control(struct radio *radio, ca_uint8_t enable, ca_uint8_t * sta_addr,
		 ca_uint8_t tid)
{
	struct dol_evt_ampdu_control dol_event;
	ca_ipc_pkt_t ipc_pkt;

	dol_event.evt.radio = radio->rid;
	dol_event.evt.event = DOL_EVT_AMPDU_CONTROL;
	dol_event.enable = enable;
	dol_event.tid = tid;
	memcpy(dol_event.sta_addr, sta_addr, ETH_ALEN);

	ipc_pkt.session_id = SYSADPT_MSG_IPC_SESSION;
	ipc_pkt.dst_cpu_id = SYSADPT_MSG_IPC_DST_CPU;
	ipc_pkt.priority = 0;
	ipc_pkt.msg_no = WFO_IPC_T2H_EVENT;
	ipc_pkt.msg_data = &dol_event;
	ipc_pkt.msg_size = sizeof(dol_event);

	return ca_ipc_msg_async_send(&ipc_pkt);
}

static inline void
tx_free_bmq13_to_host(struct radio *radio, bm_pe_hw_t * pe_hw)
{
	struct dol_evt_free_bmq13 dol_event;
	ca_ipc_pkt_t ipc_pkt;

	if (pe_hw) {
		dol_event.evt.radio = radio->rid;
		dol_event.evt.event = DOL_EVT_FREE_BMQ13;
		memcpy(&dol_event.pe_hw, pe_hw, sizeof(bm_pe_hw_t));

		ipc_pkt.session_id = SYSADPT_MSG_IPC_SESSION;
		ipc_pkt.dst_cpu_id = SYSADPT_MSG_IPC_DST_CPU;
		ipc_pkt.priority = 0;
		ipc_pkt.msg_no = WFO_IPC_T2H_EVENT;
		ipc_pkt.msg_data = &dol_event;
		ipc_pkt.msg_size = sizeof(dol_event);

		ca_ipc_msg_async_send(&ipc_pkt);
	}
}

static inline ca_uint8_t
ipv6_get_dsfield(IEEEtypes_IPv6_Hdr_t * ipv6h)
{
	return BE16_TO_CPU(*(const ca_uint16_t *)ipv6h) >> 4;
}

static inline ca_uint8_t
dscp_ip_precedence_mapping(struct radio *radio, ca_uint8_t dsfield)
{
	ca_uint8_t pri = (dsfield & 0xFC) >> 2;
	ca_uint8_t tid = 0;

	if (radio->dscp_wmm_mapping == DSCP_WMM_MAPPING_NEC) {
		switch (pri) {
		case 0x00:	/* 000000 */
			tid = CS0_IP_PRECEDENCE0;	/* WMM_AC_BE */
			break;
		case 0x08:	/* 001000 */
			tid = CS1_IP_PRECEDENCE1;	/* WMM_AC_BK */
			break;
		case 0x10:	/* 010000 */
			tid = CS2_IP_PRECEDENCE2;	/* WMM_AC_BK */
			break;
		case 0x18:	/* 011000 */
			tid = CS3_IP_PRECEDENCE3;	/* WMM_AC_BE */
			break;
		case 0x20:	/* 100000 */
			tid = CS4_IP_PRECEDENCE4;	/* WMM_AC_VI */
			break;
		case 0x28:	/* 101000 */
			tid = CS5_IP_PRECEDENCE5;	/* WMM_AC_VI */
			break;
		case 0x30:	/* 110000 */
			tid = CS6_IP_PRECEDENCE6;	/* WMM_AC_VO */
			break;
		case 0x38:	/* 111000 */
			tid = CS7_IP_PRECEDENCE7;	/* WMM_AC_VO */
			break;
		case 0x2E:	/* 101110 */
			tid = CS6_IP_PRECEDENCE6;	/* WMM_AC_VO */
			break;
		default:	/* Others */
			tid = 0;
			break;
		}
	} else {
		/* WFA spec */
		tid = (pri & 0x38) >> 3;
	}

	return tid;
}

static inline ca_uint8_t
qos_get_dscp_priority(struct radio *radio, ca_uint8_t * data_buf)
{
	struct ether_header *ether_header;
	IEEE802_1QTag_t *qos_tag = NULL;
	struct llc_snap *llc_snap = NULL;
	IEEEtypes_IPv4_Hdr_t *ipv4 = NULL;
	ca_uint16_t tag_control, pri, typelen, type;
	ca_uint8_t ac_pri = 0;

	ether_header = (struct ether_header *)data_buf;
	typelen = BE16_TO_CPU(ether_header->ether_type);

	if (typelen == IEEE802_11Q_TYPE) {
		/* First check for 802.1D tag */
		qos_tag = (IEEE802_1QTag_t *) (data_buf + (ETH_ALEN * 2));
		tag_control = BE16_TO_CPU(qos_tag->control);
		pri = (tag_control & 0xE000) >> 13;
		if ((pri >= 0) && (pri <= 7))
			ac_pri = pri;
		else
			ac_pri = 0;
	} else if (typelen == ETH_P_ARP) {
		ac_pri = CS6_IP_PRECEDENCE6;
	} else {
		if (typelen <= MAX_ETHER_PKT_SIZE) {
			/* pkt has LLC Header */
			llc_snap = (struct llc_snap *)(data_buf + ETH_HLEN);
			type = BE16_TO_CPU(llc_snap->ether_type);
			ipv4 = (IEEEtypes_IPv4_Hdr_t *) (data_buf + ETH_HLEN +
							 sizeof(struct
								llc_snap));
		} else {
			type = typelen;
			ipv4 = (IEEEtypes_IPv4_Hdr_t *) (data_buf + ETH_HLEN);
		}

		if (type == ETH_P_IP) {	/* IP packet */
			ac_pri = dscp_ip_precedence_mapping(radio, ipv4->tos);
		} else if (type == ETH_P_IPV6) {
			IEEEtypes_IPv6_Hdr_t *ipv6 =
				(IEEEtypes_IPv6_Hdr_t *) ipv4;
			ca_uint8_t dsfield = ipv6_get_dsfield(ipv6);
			if (ipv6->ver == 6)
				ac_pri = dscp_ip_precedence_mapping(radio,
								    dsfield);
		} else {
			ac_pri = 0;
		}
	}

	return ac_pri;
}

void
tx_proc_host_pkt(int rid, const void *msg, ca_uint16_t msg_size)
{
	struct radio *radio = &radio_info[rid - 1];
	h2t_pkt_send_t h2t_msg;
	struct pkt_hdr *pkt;
	ca_uint8_t *buf_virt_addr;
	ca_uint16_t frm_ctrl_data;
	IEEEtypes_FrameCtl_t *frm_ctrl;

	if (msg_size != sizeof(h2t_msg)) {
		radio->dbg_cnt.tx_cnt.tx_drop_msg_err++;
		return;
	}
	memcpy(&h2t_msg, msg, msg_size);

	if (!radio->initialized)
		goto return_host_pkt;

	pkt = pkt_alloc_hdr(rid);
	if (!pkt)
		goto return_host_pkt;

	pkt->orig_hdr = h2t_msg.skb_addr;
	pkt->data_type = PKT_DATA_FROM_HOST;

	buf_virt_addr = PHYS_TO_VIRT(h2t_msg.buf_phy_addr);
	pkt->data = buf_virt_addr;
	pkt->len = h2t_msg.buf_len;
#ifdef CORTINA_TUNE_SLIM_PKT_HDR
	frm_ctrl_data = h2t_msg.txcfg.mpdu_frame_ctrl;
	frm_ctrl = (IEEEtypes_FrameCtl_t *) & frm_ctrl_data;

	pkt->priority = h2t_msg.txcfg.qid;

	wlPktToCfhDl(rid, pkt, &h2t_msg.txcfg, radio->tx_q_start,
		     frm_ctrl->Type);
	if (h2t_msg.txcfg.mpdu_flag)
		radio->dbg_cnt.tx_cnt.mgmt_pkt_from_host++;
	else
		radio->dbg_cnt.tx_cnt.data_pkt_from_host++;
#else
	memcpy(&pkt->txcfg, &h2t_msg.txcfg, sizeof(wltxdesc_t));
	list_put_item(&radio->pkt_ctrl.pkt_from_host_list,
		      (struct list_item *)pkt);
	if (pkt->txcfg.mpdu_flag)
		radio->dbg_cnt.tx_cnt.mgmt_pkt_from_host++;
	else
		radio->dbg_cnt.tx_cnt.data_pkt_from_host++;
#endif
	return;

return_host_pkt:
	{
		t2h_pkt_send_done_t t2h_msg;
		ca_ipc_pkt_t ipc_pkt;

		t2h_msg.radio = rid;
		t2h_msg.skb_addr = h2t_msg.skb_addr;
		t2h_msg.buf_phy_addr = h2t_msg.buf_phy_addr;

		ipc_pkt.session_id = SYSADPT_MSG_IPC_SESSION;
		ipc_pkt.dst_cpu_id = SYSADPT_MSG_IPC_DST_CPU;
		ipc_pkt.priority = 0;
		ipc_pkt.msg_no = WFO_IPC_T2H_PKT_SEND_DONE;
		ipc_pkt.msg_data = &t2h_msg;
		ipc_pkt.msg_size = sizeof(t2h_msg);

		ca_ipc_msg_async_send(&ipc_pkt);
		radio->dbg_cnt.tx_cnt.tx_drop_no_pkt_hdr++;
	}
	return;
}

void
tx_proc_eth_pkt(int rid, int vid, void *pkt, ca_uint8_t * data, int len,
		int priority)
{
	struct radio *radio = &radio_info[rid - 1];
	int ac_que, pri;
	struct pkt_hdr *pkt_hdr;
	struct vif *vif;
	struct sta_info *sta_info = NULL;
	bool is_bcmc;
#ifdef DUPLICATE_MCBC_PER_RADIO
	int i;
#endif

	vif = &radio->vif_info[vid];
	if (!vif->valid || !vif->enable) {
		if (!vif->valid)
			radio->dbg_cnt.tx_cnt.tx_drop_vif_err++;
		else
			radio->dbg_cnt.tx_cnt.tx_drop_vif_disable++;
		vif->netdev_stats.tx_dropped++;
		vif->netdev_stats.tx_carrier_errors++;
		goto free_pkt;
	}

	if ((priority >= 0) && (priority <= 7))
		pri = priority;
	else
		pri = qos_get_dscp_priority(radio, data);

	ac_que = ac_que_mapping[pri];

	if (radio->pkt_ctrl.pkt_from_eth_list[ac_que].cnt >=
	    SYSADPT_AC_QUEUE_DROP_THRESHOLD) {
		/* Drop packet first, maybe stop/start of NIC driver
		 * can be added later if needed.
		 */
		radio->dbg_cnt.tx_cnt.ac_drop[ac_que]++;
		vif->netdev_stats.tx_dropped++;
		goto free_pkt;
	}

	if (IS_MULTICAST_ADDR(data)) {
#ifdef DUPLICATE_MCBC_PER_RADIO	/* MCBC packets should be handled by upper layer */
		for (i = 0; i < radio->bss_num; i++) {
			if (i == vid)
				continue;
			if (radio->vif_info[i].enable &&
			    radio->vif_info[i].valid) {
				pkt_hdr = pkt_alloc_hdr(rid);
				if (!pkt_hdr) {
					radio->dbg_cnt.tx_cnt.
						tx_drop_no_pkt_hdr++;
					vif->netdev_stats.tx_dropped++;
					vif->netdev_stats.tx_errors++;
					goto free_pkt;
				}
				pkt_hdr->vif_info = &radio->vif_info[i];
				pkt_hdr->sta_info = NULL;
				pkt_hdr->is_bcmc = true;
				pkt_hdr->priority = pri;
				pkt_hdr->data_type = PKT_DATA_FROM_LOCAL;
				pkt_hdr->buf_ptr = MALLOC(len + PKT_INFO_SIZE);
				pkt_hdr->data =
					pkt_hdr->buf_ptr + PKT_INFO_SIZE;
				memcpy(pkt_hdr->data, data, len);
				pkt_hdr->len = len;
				list_put_item(&radio->pkt_ctrl.
					      pkt_from_eth_list[ac_que],
					      (struct list_item *)pkt_hdr);
			}
		}
#endif
		is_bcmc = true;
	} else {
		sta_info = stadb_get_stainfo(rid, data);
		if (!sta_info) {
			radio->dbg_cnt.tx_cnt.tx_drop_sta_err++;
			vif->netdev_stats.tx_dropped++;
			vif->netdev_stats.tx_aborted_errors++;
			goto free_pkt;
		}
		if (!sta_info->enable) {
			radio->dbg_cnt.tx_cnt.tx_drop_sta_disable++;
			vif->netdev_stats.tx_dropped++;
			vif->netdev_stats.tx_aborted_errors++;
			goto free_pkt;
		}
		vif = &radio->vif_info[sta_info->vid];
		if (vif->vid != vid) {
			radio->dbg_cnt.tx_cnt.tx_drop_sta_err++;
			vif->netdev_stats.tx_dropped++;
			vif->netdev_stats.tx_aborted_errors++;
			goto free_pkt;
		}
		is_bcmc = false;
	}

	pkt_hdr = pkt_alloc_hdr(rid);
	if (!pkt_hdr) {
		radio->dbg_cnt.tx_cnt.tx_drop_no_pkt_hdr++;
		vif->netdev_stats.tx_dropped++;
		vif->netdev_stats.tx_errors++;
		goto free_pkt;
	}
	pkt_hdr->vif_info = vif;
	pkt_hdr->sta_info = sta_info;
	pkt_hdr->is_bcmc = is_bcmc;
	pkt_hdr->priority = pri;
	pkt_hdr->orig_hdr = (ca_uint64_t) (__PLATFORM_POINTER_TYPE__ pkt);
	pkt_hdr->data_type = PKT_DATA_FROM_ETH;
	pkt_hdr->data = data;
	pkt_hdr->len = len;
	list_put_item(&radio->pkt_ctrl.pkt_from_eth_list[ac_que],
		      (struct list_item *)pkt_hdr);

	if (is_bcmc)
		radio->dbg_cnt.tx_cnt.bcmc_pkt_from_eth++;
	else
		radio->dbg_cnt.tx_cnt.unicast_pkt_from_eth++;
	return;

free_pkt:

	eth_free_pkt(pkt);
	return;
}

void
tx_poll(int rid)
{
	struct radio *radio = &radio_info[rid - 1];
	struct pkt_ctrl *ctrl = &radio->pkt_ctrl;
	struct pkt_hdr *pkt;
	int i, work_done;
	struct ether_header *eth_hdr;
	struct llc_snap *llc_snap;
	int macid, tx_priority;
	wltxdesc_t *txcfg;
#ifndef CORTINA_TUNE_SLIM_PKT_HDR
	int type;
	/* process host packets */
	while (1) {
		pkt = (struct pkt_hdr *)list_get_item(&ctrl->
						      pkt_from_host_list);
		if (pkt) {
			type = pkt->txcfg.mpdu_flag ?
				IEEE_TYPE_MANAGEMENT : IEEE_TYPE_DATA;
			if (type == IEEE_TYPE_DATA) {
				pkt->sta_info =
					stadb_get_stainfo(rid, pkt->data);
				if (pkt->sta_info && pkt->sta_info->threshold) {
					if (radio->ampdu_tx == 1) {
						/* Only mode 1 is supported.
						 * No dynamic BA and ampducfg support
						 */
						if (!pkt->sta_info->
						    startbytid[pkt->priority]) {
							if (!tx_ampdu_control
							    (radio, 1,
							     pkt->sta_info->
							     mac_addr,
							     pkt->priority))
								pkt->sta_info->
									startbytid
									[pkt->
									 priority]
									= true;
						}
					}
				}
			}
			pkt->priority = pkt->txcfg.qid;
			wlPktToCfhDl(rid, pkt, &pkt->txcfg, radio->tx_q_start,
				     type);
		} else
			break;
	}
#endif
	/* process packets from nic driver */
	work_done = 0;
	for (i = 3; i >= 0; i--) {	/* list 3 has highest priority */
		while (work_done < SYSADPT_MAX_TX_PACKET_PER_POLL) {
			pkt = (struct pkt_hdr *)
				list_get_item(&ctrl->pkt_from_eth_list[i]);
#ifdef CORTINA_TUNE_HW_CPY
			if (pkt) {
				tx_buff_now = FAST_MEM_WIFI_TX_BUFFER0;
				ca_dma_sync_copy(HW_DMA_COPY_WIFI_TX_DATA,
						 FAST_MEM_WIFI_TX_BUFFER0_PA,
						 VIRT_TO_PHYS(pkt->data),
						 TX_DATA_BUFFER_SIZE);
				eth_hdr =
					(struct ether_header *)
					FAST_MEM_WIFI_TX_BUFFER0;
			}
#endif

			if (pkt) {
				if (radio->drv_stats_val.txq_drv_sent_cnt -
				    radio->drv_stats_val.
				    txq_drv_release_cnt[3] -
				    (radio->except_cnt.tx_mgmt_send_cnt -
				     radio->except_cnt.tx_mgmt_rel_cnt) >
				    SYSADPT_MAX_TX_PENDING) {
					radio->except_cnt.
						tx_drop_over_max_pending++;
					pkt_free_data(rid, pkt, __func__);
					if (pkt->vif_info)
						pkt->vif_info->netdev_stats.
							tx_dropped++;
					break;
				}
#ifdef CORTINA_TUNE_HW_CPY
				txcfg = (wltxdesc_t *) FAST_MEM_WIFI_TX_DESC;
				llc_snap =
					(struct llc_snap *)&txcfg->
					mpdu_ht_a_ctrl;
				llc_snap->ether_type = eth_hdr->ether_type;
#else
				eth_hdr = (struct ether_header *)pkt->data;
				txcfg = &pkt->txcfg;
				llc_snap = (struct llc_snap *)&(pkt->cb[16]);

				llc_snap->llc_dsap = llc_snap->llc_ssap =
					LLC_SNAP_LSAP;
				llc_snap->control = LLC_UI;
				llc_snap->org_code[0] = 0;
				llc_snap->org_code[1] = 0;
				llc_snap->org_code[2] = 0;
				llc_snap->ether_type = eth_hdr->ether_type;
#endif
				if (pkt->sta_info && pkt->sta_info->threshold) {
					if (radio->ampdu_tx == 1) {
						/* Only mode 1 is supported.
						 * No dynamic BA and ampducfg support
						 */
						if (!pkt->sta_info->
						    startbytid[pkt->priority]) {
							if (!tx_ampdu_control
							    (radio, 1,
							     pkt->sta_info->
							     mac_addr,
							     pkt->priority))
								pkt->sta_info->
									startbytid
									[pkt->
									 priority]
									= true;
						}
					}
				}
				macid = pkt->vif_info->vid;
				if (pkt->is_bcmc) {
					if ((eth_hdr->ether_dhost[0] == 0xFF)
					    && (eth_hdr->ether_dhost[1] == 0xFF)
					    && (eth_hdr->ether_dhost[2] == 0xFF)
					    && (eth_hdr->ether_dhost[3] == 0xFF)
					    && (eth_hdr->ether_dhost[4] == 0xFF)
					    && (eth_hdr->ether_dhost[5] ==
						0xFF)) {
						/* broadcast uses q[3] for bc rate */
						tx_priority =
							macid *
							SYSADPT_MAX_TID + 3;
					} else {
						/* multicast uses q[0] for mc rate */
						tx_priority =
							macid * SYSADPT_MAX_TID;
					}
				} else {
					if (pkt->sta_info)
						tx_priority =
							(SYSADPT_MAX_TID *
							 pkt->sta_info->
							 stn_id) +
							QUEUE_STAOFFSET +
							pkt->priority;
					else
						tx_priority =
							macid * SYSADPT_MAX_TID;
				}
				pkt->priority = tx_priority;

				wlInitCFHDL(rid, txcfg, pkt);
				wlPktToCfhDl(rid, pkt, txcfg, radio->tx_q_start,
					     IEEE_TYPE_DATA);

				radio->dbg_cnt.tx_cnt.ac_pkt[i]++;
			} else
				break;
			work_done++;
		}
	}
}

void
tx_done(int rid)
{
	struct radio *radio = &radio_info[rid - 1];
	struct wldesc_data *wlqm;
	bm_pe_hw_t *pe_hw;
	struct pkt_hdr *pkt;
	int qid, tx_qid;
	int return_cnt;

	for (qid = radio->rel_q_start;
	     qid < radio->rel_q_start + radio->rel_q_num; qid++) {
		wlqm = &radio->desc_data[qid];
		wlqm->sq.wrinx = wlQueryWrPtr(rid, qid, SC5_SQ);

#ifdef CORTINA_TUNE_HW_CPY
		tx_buff_now = NULL;
#endif

		while (!isSQEmpty(&wlqm->sq)) {
			pe_hw = wlGetRelBufPe(rid, qid);
			if (!pe_hw) {
				printf("\t %s(%d): pe_hw is null\n", __func__,
				       rid);
				if ((radio->chip_revision != REV_Z1) &&
				    (radio->chip_revision != REV_Z2))
					continue;
				else
					break;
			}
			if (pe_hw->bpid == 13) {
				tx_free_bmq13_to_host(radio, pe_hw);
				radio->dbg_cnt.rel_cnt.bmq_release[3]++;
			} else {
				pkt = wlPeToPkt(rid, pe_hw);
				if (pkt) {
					if (radio->fw_desc_cnt-- <= 0)
						radio->fw_desc_cnt = 0;
					tx_qid = pkt->priority;
					radio->except_cnt.txq_rel_cnt[tx_qid]++;

					if (tx_qid < QUEUE_STAOFFSET) {
						if ((tx_qid %
						     SYSADPT_MAX_TID) >= 6)
							radio->except_cnt.
								tx_mgmt_rel_cnt++;
						else
							radio->except_cnt.
								tx_bcast_rel_cnt++;
					} else {
						ca_uint32_t stn_id;

						stn_id = (tx_qid -
							  QUEUE_STAOFFSET) /
							SYSADPT_MAX_TID;
						radio->except_cnt.
							tx_sta_rel_cnt
							[stn_id]++;
					}
					radio->drv_stats_val.
						txq_drv_release_cnt[3]++;
					pkt_free_data(rid, pkt, __func__);
				} else
					radio->drv_stats_val.
						txq_drv_release_cnt[2]++;
			}
		}

		wlUpdateRdPtr(rid, qid, SC5_SQ, wlqm->sq.rdinx);
	}

	if (radio->pending_cmd_reply) {
		if (!ca_ipc_msg_async_send
		    ((ca_ipc_pkt_t *) radio->pending_cmd_reply)) {
			MFREE(radio->pending_cmd_reply);
			radio->pending_cmd_reply = NULL;
		}
	}

	for (return_cnt = 0; return_cnt < SYSADPT_MAX_RETURN_HOST_PKT_NUM;
	     return_cnt++) {
		pkt = (struct pkt_hdr *)list_get_item(&radio->pkt_ctrl.
						      pkt_from_host_free_list);
		if (!pkt)
			break;
		if (!pkt_free_host_data(radio, pkt)) {
			list_put_item(&radio->pkt_ctrl.pkt_from_host_free_list,
				      (struct list_item *)pkt);
			break;
		}
	}
}

#ifdef CORTINA_TUNE_HW_CPY
int
pri_2_ac_map(int pri)
{
	return ac_que_mapping[pri];
}

static inline int
__wfo_tx_copy_and_send(struct radio *radio, struct vif *vif,
		       ca_uint8_t * data, int len, int pri)
{
	struct pkt_hdr *pkt_hdr;
	int ac_que = ac_que_mapping[pri];
	if (((radio->except_cnt.tx_bcast_send_cnt -
	      radio->except_cnt.tx_bcast_rel_cnt) +
	     radio->pkt_ctrl.pkt_from_eth_list[ac_que].cnt) >
	    SYSADPT_MAX_TX_PENDING) {
		// printf("pending too much %d\n", (radio->except_cnt.tx_bcast_send_cnt -
		// radio->except_cnt.tx_bcast_rel_cnt) + radio->pkt_ctrl.pkt_from_eth_list[ac_que].cnt));
		return -ENOMEM;
	}
	if (vif->enable && vif->valid) {
		pkt_hdr = pkt_alloc_hdr(radio->rid);
		if (!pkt_hdr) {
			radio->dbg_cnt.tx_cnt.tx_drop_no_pkt_hdr++;
			vif->netdev_stats.tx_dropped++;
			vif->netdev_stats.tx_errors++;
			return -ENOMEM;
		}
		pkt_hdr->vif_info = vif;
		pkt_hdr->sta_info = NULL;
		pkt_hdr->is_bcmc = true;
		pkt_hdr->priority = pri;
		pkt_hdr->data_type = PKT_DATA_FROM_LOCAL;
		pkt_hdr->buf_ptr = MALLOC(len + PKT_INFO_SIZE);
		if (pkt_hdr->buf_ptr == NULL) {
			printf("%s no enough memory!!\n", __func__);
			vif->netdev_stats.tx_dropped++;
			vif->netdev_stats.tx_errors++;
			pkt_free_hdr(radio, pkt_hdr);
			return -ENOMEM;
		}
		pkt_hdr->data = pkt_hdr->buf_ptr + PKT_INFO_SIZE;
		memcpy(pkt_hdr->data, data, len);
		pkt_hdr->len = len;
		list_put_item(&radio->pkt_ctrl.pkt_from_eth_list[ac_que],
			      (struct list_item *)pkt_hdr);
		return 0;
	}
	return -EEXIST;
}

static inline void
__wfo_tx_mc_all_vif(struct radio *radio, ca_uint8_t * data, int len, int pri,
		    int isolate_group_id)
{
	int i;
	struct vif *vif;

	if (radio->enable == 0)
		return;

	/* won't forward packet if there is no station associated */
	if (!radio->stadb_ctrl->sta_list.cnt)
		return;

	for (i = 0; i < radio->bss_num; i++) {
		vif = &radio->vif_info[i];

		/* won't forward packet if there is no station associated */
		if (!vif->sta_cnt)
			continue;

		if (vif->isolate_group_id != isolate_group_id)
			continue;
		__wfo_tx_copy_and_send(radio, vif, data, len, pri);
	}

	return;
}

void
wfo_tx_intra_mc_pkt(ca_uint8_t * data, int len, int pri, int isolate_group_id)
{
	int i;
	for (i = 0; i < SYSADPT_MAX_RADIO; i++) {
		__wfo_tx_mc_all_vif(&radio_info[i], data, len, pri,
				    isolate_group_id);
	}

	return;
}

void
wfo_tx_array_wifi(uint32 count, pe_ni_fast_array_t * rx_array)
{
	struct radio *radio;
	int ac_que, pri;
	struct pkt_hdr *pkt_hdr;
	struct vif *vif;
	struct sta_info *sta_info = NULL;
	int rid, vid, i;
	ca_uint8_t *data;
	int len;
	struct ether_header *eth_hdr;
	struct llc_snap *llc_snap;
	int tx_priority;
	wltxdesc_t *txcfg;
	int handle_count = 0;
	ca_uint16_t *tmp;
	ca_uint32_t isolate_group_id;

	tx_buff_next = (ca_uint8_t *) FAST_MEM_WIFI_TX_BUFFER0;
	tx_buff_now = (ca_uint8_t *) FAST_MEM_WIFI_TX_BUFFER0;

	if (tx_next_pkt != NULL) {
		printf("%s %d CORTINA_TUNE_HW_CPY something wrong ?? \n",
		       __func__, __LINE__);
	}

	while ((rx_array->len0 != 0) && (count > 0)) {
		if (tx_next_pkt) {
			/*if the pkt handle time is >= 230 cpu cycles, we can remove the following */
			ca_dma_poll_for_complete(HW_DMA_COPY_WIFI_TX_DATA);
			tx_buff_now = tx_buff_next;
			tx_next_pkt = NULL;
		} else {
			ca_dma_sync_copy(HW_DMA_COPY_WIFI_TX_DATA,
					 VIRT_TO_PHYS(tx_buff_now),
					 VIRT_TO_PHYS(rx_array->buf0),
					 TX_DATA_BUFFER_SIZE);
		}

		if ((rx_array[1].len0 != 0) && (count != 1)) {
			tx_next_pkt = (ca_uint8_t *) rx_array[1].buf0;
			if (tx_next_pkt != NULL) {
				if (tx_buff_next ==
				    ((ca_uint8_t *) FAST_MEM_WIFI_TX_BUFFER0)) {
					tx_buff_next =
						(ca_uint8_t *)
						FAST_MEM_WIFI_TX_BUFFER1;
					ca_dma_async_copy
						(HW_DMA_COPY_WIFI_TX_DATA,
						 (ca_uint8_t *)
						 FAST_MEM_WIFI_TX_BUFFER1_PA,
						 VIRT_TO_PHYS(rx_array[1].buf0),
						 TX_DATA_BUFFER_SIZE);
				} else {
					tx_buff_next =
						(ca_uint8_t *)
						FAST_MEM_WIFI_TX_BUFFER0;
					ca_dma_async_copy
						(HW_DMA_COPY_WIFI_TX_DATA,
						 (ca_uint8_t *)
						 FAST_MEM_WIFI_TX_BUFFER0_PA,
						 VIRT_TO_PHYS(rx_array[1].buf0),
						 TX_DATA_BUFFER_SIZE);
				}
			}
		}

		isolate_group_id = 0;
		eth_hdr = (struct ether_header *)tx_buff_now;
		if (eth_hdr->ether_type == 0x0081) {
			tmp = (ca_uint16_t *) & rx_array->buf0[ETH_ALEN * 2 +
							       2];
			isolate_group_id = BE16_TO_CPU(*tmp);
			WIFI_PRINT(CA_DBG_LVL_TRACE,
				   "send isolate_group_id %d pkt\n",
				   isolate_group_id);
			memcpy(&rx_array->buf0[4], tx_buff_now, ETH_ALEN * 2);
			rx_array->buf0 += 4;
			rx_array->len0 -= 4;
			memcpy(&tx_buff_now[ETH_ALEN * 2],
			       &tx_buff_now[ETH_ALEN * 2 + 4],
			       TX_DATA_BUFFER_SIZE - ETH_ALEN * 2);
		}

		data = rx_array->buf0;
		len = rx_array->len0;
		if (radio_info[0].dbg_ctrl & DBG_DISABLE_DSCP_PARSE)
			pri = rx_array->cos;
		else
			pri = qos_get_dscp_priority(&radio_info[0],
						    tx_buff_now);

		if (pri == 7)	//MMDU: priority 7 is reserved for eapol/mgmt frames that will be sent with basic rate.
			pri = 6;

		ac_que = ac_que_mapping[pri];
		if (radio_info[0].dbg_ctrl & DBG_DUMP_ETH_TX_PKT) {
			/* Dump conent of transmit packet to make sure WiFi
			 * driver transmits the correct packet to ethernet
			 * driver.
			 */
			hex_dump("WIFI_TX:", data, len);
		}

		if (IS_MULTICAST_ADDR(tx_buff_now)) {
			radio_info[0].dbg_cnt.tx_cnt.bcmc_pkt_from_eth++;
			wfo_tx_intra_mc_pkt(data, len, pri, isolate_group_id);

			ca_ni_rx_ptr_free((uint8 *) data);
			goto handle_next;
		} else {
			for (i = 0; i < SYSADPT_MAX_RADIO; i++) {
				if (radio_info[i].enable)
					sta_info =
						stadb_get_stainfo(radio_info[i].
								  rid,
								  tx_buff_now);
				if (sta_info)
					break;
			}
		}
		if (!sta_info) {
			radio_info[0].dbg_cnt.tx_cnt.tx_drop_sta_err++;
			ca_ni_rx_ptr_free((uint8 *) data);
			goto handle_next;
		}
		rid = sta_info->rid;
		vid = sta_info->vid;
		radio = &radio_info[rid - 1];
		vif = &radio->vif_info[vid];
		WIFI_PRINT(CA_DBG_LVL_TRACE,
			   "isolate_group_id %d sta_info %p rid %d vid %d \n",
			   isolate_group_id, sta_info, rid, vid);
		if (!sta_info->enable) {
			radio->dbg_cnt.tx_cnt.tx_drop_sta_disable++;
			vif->netdev_stats.tx_dropped++;
			vif->netdev_stats.tx_aborted_errors++;
			ca_ni_rx_ptr_free((uint8 *) data);
			goto handle_next;
		} else {

			struct except_cnt *pexcept;
			ca_uint16_t qid =
				(SYSADPT_MAX_TID * sta_info->stn_id) +
				QUEUE_STAOFFSET + pri;

			pexcept = &radio->except_cnt;
			if ((pexcept->txq_send_cnt[qid] -
			     pexcept->txq_rel_cnt[qid]) >
			    SYSADPT_MAX_TX_QID_PENDING) {
				radio->except_cnt.txq_drop_cnt[qid]++;
				radio->except_cnt.tx_sta_drop_cnt[sta_info->
								  stn_id]++;
				ca_ni_rx_ptr_free((uint8 *) data);
				goto handle_next;
			}
		}

		if (radio->drv_stats_val.txq_drv_sent_cnt -
		    radio->drv_stats_val.txq_drv_release_cnt[3] -
		    (radio->except_cnt.tx_mgmt_send_cnt -
		     radio->except_cnt.tx_mgmt_rel_cnt) >
		    SYSADPT_MAX_TX_PENDING) {
			radio->except_cnt.tx_drop_over_max_pending++;
			if (vif)
				vif->netdev_stats.tx_dropped++;
			ca_ni_rx_ptr_free((uint8 *) data);
			goto handle_next;
		}

		if (!vif->valid || !vif->enable) {
			if (!vif->valid)
				radio->dbg_cnt.tx_cnt.tx_drop_vif_err++;
			else
				radio->dbg_cnt.tx_cnt.tx_drop_vif_disable++;
			vif->netdev_stats.tx_dropped++;
			vif->netdev_stats.tx_carrier_errors++;
			ca_ni_rx_ptr_free((uint8 *) data);
			goto handle_next;
		}

		if (radio->pkt_ctrl.pkt_from_eth_list[ac_que].cnt >=
		    SYSADPT_AC_QUEUE_DROP_THRESHOLD) {
			/* Drop packet first, maybe stop/start of NIC driver
			 * can be added later if needed.
			 */
			radio->dbg_cnt.tx_cnt.ac_drop[ac_que]++;
			vif->netdev_stats.tx_dropped++;
			ca_ni_rx_ptr_free((uint8 *) data);
			goto handle_next;
		}

		pkt_hdr = pkt_alloc_hdr(rid);
		if (!pkt_hdr) {
			radio->dbg_cnt.tx_cnt.tx_drop_no_pkt_hdr++;
			vif->netdev_stats.tx_dropped++;
			vif->netdev_stats.tx_errors++;
			ca_ni_rx_ptr_free((uint8 *) data);
			goto handle_next;
		}
		pkt_hdr->vif_info = vif;
		pkt_hdr->sta_info = sta_info;
		pkt_hdr->is_bcmc = false;
		pkt_hdr->orig_hdr =
			(ca_uint64_t) ((ca_uint32_t) rx_array->buf0);
		pkt_hdr->data_type = PKT_DATA_FROM_ETH;
		pkt_hdr->data = data;
		pkt_hdr->len = len;
		radio->dbg_cnt.tx_cnt.unicast_pkt_from_eth++;

		WIFI_DUMP(CA_DBG_LVL_TRACE, "wifi tx dump content", data,
			  ETH_ALEN * 2 + 4);

		txcfg = (wltxdesc_t *) FAST_MEM_WIFI_TX_DESC;
		llc_snap = (struct llc_snap *)&txcfg->mpdu_ht_a_ctrl;
		llc_snap->ether_type = eth_hdr->ether_type;
		if (sta_info->threshold) {
			if (radio->ampdu_tx == 1) {
				/* Only mode 1 is supported.
				 * No dynamic BA and ampducfg support
				 */
				if (!sta_info->startbytid[pri]) {
					if (!tx_ampdu_control
					    (radio, 1, sta_info->mac_addr, pri))
						sta_info->startbytid[pri] =
							true;
				}
			}
		}

		if (sta_info)
			tx_priority = (SYSADPT_MAX_TID * sta_info->stn_id) +
				QUEUE_STAOFFSET + pri;
		else
			tx_priority = vid * SYSADPT_MAX_TID;

		pkt_hdr->priority = tx_priority;

		wlInitCFHDL(rid, txcfg, pkt_hdr);
		wlPktToCfhDl(rid, pkt_hdr, txcfg, radio->tx_q_start,
			     IEEE_TYPE_DATA);

		radio->dbg_cnt.tx_cnt.ac_pkt[ac_que]++;

handle_next:
		rx_array++;
		count--;
		handle_count++;
	}

	return;
}
#endif
