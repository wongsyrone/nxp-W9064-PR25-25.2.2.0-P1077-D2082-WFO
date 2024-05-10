/** @file stadb.c
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

/* there is no protection for these functions due to super loop */

int
stadb_init(ca_uint16_t rid)
{
	struct radio *radio = &radio_info[rid - 1];
	int i;

	if (!radio->stadb_ctrl) {
		radio->stadb_ctrl =
			(struct stadb_ctrl *)
			MALLOC_CACHE(sizeof(struct stadb_ctrl));

		if (!radio->stadb_ctrl) {
			printf("\t %s(%d): fail to alloc memory\n", __func__,
			       rid);
			return -ENOMEM;
		}
		memset(radio->stadb_ctrl, 0, sizeof(struct stadb_ctrl));
	}

	if (!radio->stadb_ctrl->sta_db) {
		radio->stadb_ctrl->sta_db = (struct sta_item *)
			MALLOC_CACHE(SYSADPT_MAX_STA * sizeof(struct sta_item));

		if (!radio->stadb_ctrl->sta_db) {
			printf("\t %s(%d): fail to alloc memory\n", __func__,
			       rid);
			MFREE(radio->stadb_ctrl);
			return -ENOMEM;
		}
		memset(radio->stadb_ctrl->sta_db, 0,
		       SYSADPT_MAX_STA * sizeof(struct sta_item));
	}

	for (i = 0; i < SYSADPT_MAX_STA; i++)
		radio->stadb_ctrl->sta_db_p[i] = NULL;

	list_init(&radio->stadb_ctrl->free_sta_list);
	list_init(&radio->stadb_ctrl->sta_list);

	for (i = 0; i < SYSADPT_MAX_STA; i++) {
		radio->stadb_ctrl->sta_db[i].nxt = NULL;
		radio->stadb_ctrl->sta_db[i].prv = NULL;
		radio->stadb_ctrl->sta_db[i].nxt_ht = NULL;
		radio->stadb_ctrl->sta_db[i].prv_ht = NULL;
		memset(&radio->stadb_ctrl->sta_db[i].sta_info.mac_addr, 0,
		       ETH_ALEN);
		radio->stadb_ctrl->sta_db[i].sta_info.enable = false;
		list_put_item(&radio->stadb_ctrl->free_sta_list,
			      (struct list_item *)
			      (radio->stadb_ctrl->sta_db + i));
	}

	radio->stadb_ctrl->initizliaed = true;
	radio->stadb_ctrl->max_sta_supported = SYSADPT_MAX_STA;

	return 0;
}

void
stadb_deinit(ca_uint16_t rid)
{
	struct radio *radio = &radio_info[rid - 1];

	MFREE(radio->stadb_ctrl->sta_db);
	MFREE(radio->stadb_ctrl);
	radio->stadb_ctrl = NULL;
}

void
stadb_list(ca_uint16_t rid)
{
	struct radio *radio = &radio_info[rid - 1];
	struct list_item *search;
	struct sta_item *search1;
	struct sta_info *sta_info;
	ca_uint8_t *addr;

	if (!radio->stadb_ctrl)
		return;

	if (!radio->stadb_ctrl->initizliaed)
		return;

	search = radio->stadb_ctrl->sta_list.head;
	while (search) {
		search1 = (struct sta_item *)search;
		sta_info = &search1->sta_info;
		addr = sta_info->mac_addr;
		printf("\t rid: %d, vid: %d, mac addr: %02x%02x%02x%02x%02x%02x, ", sta_info->rid, sta_info->vid, addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
		printf("\t enable: %d\n", sta_info->enable);
		search = search->nxt;
	}
}

extern int omi_event_to_host(struct radio *radio, ca_uint16_t om_control,
			     ca_uint16_t stnid, ca_uint8_t * mac);

void
stadb_active_notify(ca_uint16_t rid)
{
	struct radio *radio = &radio_info[rid - 1];
	struct list_item *search;
	struct sta_item *search1;
	struct sta_info *sta_info;
	struct dol_evt_sta_active_notify dol_event;
	ca_ipc_pkt_t ipc_pkt;
	int act_sta_num;

	if (!radio->stadb_ctrl)
		return;

	if (!radio->stadb_ctrl->initizliaed)
		return;

	dol_event.evt.radio = radio->rid;
	dol_event.evt.event = DOL_EVT_STA_ACTIVE_NOTIFY;

	ipc_pkt.session_id = SYSADPT_MSG_IPC_SESSION;
	ipc_pkt.dst_cpu_id = SYSADPT_MSG_IPC_DST_CPU;
	ipc_pkt.priority = 0;
	ipc_pkt.msg_no = WFO_IPC_T2H_EVENT;
	ipc_pkt.msg_data = &dol_event;
	ipc_pkt.msg_size = sizeof(dol_event);

	act_sta_num = 0;
	search = radio->stadb_ctrl->sta_list.head;
	while (search) {
		search1 = (struct sta_item *)search;
		sta_info = &search1->sta_info;
		if (sta_info->active_notify) {
			memcpy(&dol_event.sta_addr[act_sta_num],
			       sta_info->mac_addr, ETH_ALEN);
			memcpy(&dol_event.rssi_path_info[act_sta_num],
			       &sta_info->rssi_path_info,
			       sizeof(struct rssi_path_info));
			dol_event.rxppdu_airtime_evt[act_sta_num].rx_airtime =
				sta_info->rxppdu_airtime.rx_airtime;
			dol_event.rxppdu_airtime_evt[act_sta_num].aux_ppdu_len =
				sta_info->rxppdu_airtime.rx_info_aux.ppdu_len;
			dol_event.rxppdu_airtime_evt[act_sta_num].aux_rxTs =
				sta_info->rxppdu_airtime.rx_info_aux.rxTs;
			memcpy(&
			       (dol_event.rxppdu_airtime_evt[act_sta_num].
				aux_rate_info),
			       (ca_uint32_t *) & (sta_info->rxppdu_airtime.
						  rx_info_aux.rate_info),
			       sizeof(ca_uint32_t));
#if 0
			dol_event.rxppdu_airtime_evt[act_sta_num].
				dbg_sum_pktlen =
				sta_info->rxppdu_airtime.dbg_sum_pktlen;
			dol_event.rxppdu_airtime_evt[act_sta_num].
				dbg_sum_pktcnt =
				sta_info->rxppdu_airtime.dbg_sum_pktcnt;
			dol_event.rxppdu_airtime_evt[act_sta_num].
				dbg_su_pktcnt =
				sta_info->rxppdu_airtime.dbg_su_pktcnt;
			dol_event.rxppdu_airtime_evt[act_sta_num].
				dbg_mu_pktcnt =
				sta_info->rxppdu_airtime.dbg_mu_pktcnt;
#endif
			dol_event.rxppdu_airtime_evt[act_sta_num].dbg_nss =
				sta_info->rxppdu_airtime.dbg_nss;
			dol_event.rxppdu_airtime_evt[act_sta_num].dbg_mcs =
				sta_info->rxppdu_airtime.dbg_mcs;
			dol_event.rxppdu_airtime_evt[act_sta_num].dbg_bw =
				sta_info->rxppdu_airtime.dbg_bw;
			dol_event.rxppdu_airtime_evt[act_sta_num].dbg_gi_ltf =
				sta_info->rxppdu_airtime.dbg_gi_ltf;
			dol_event.rxppdu_airtime_evt[act_sta_num].dbg_Ndbps10x =
				sta_info->rxppdu_airtime.dbg_Ndbps10x;
			dol_event.rxppdu_airtime_evt[act_sta_num].
				sum_rx_airtime =
				sta_info->rxppdu_airtime.sum_rx_airtime;
			dol_event.rxppdu_airtime_evt[act_sta_num].
				sum_rx_pktcnt =
				sta_info->rxppdu_airtime.sum_rx_pktcnt;
			dol_event.rxppdu_airtime_evt[act_sta_num].
				sum_rx_pktlen =
				sta_info->rxppdu_airtime.sum_rx_pktlen;
			dol_event.tx_bytes[act_sta_num] = sta_info->tx_bytes;
			dol_event.rx_bytes[act_sta_num] = sta_info->rx_bytes;

			sta_info->active_notify = false;
			act_sta_num++;
		}

		if (act_sta_num >= MAX_STA_ACTIVE_NOTIFY_NUM) {
			dol_event.notify_sta_num = act_sta_num;
			ca_ipc_msg_async_send(&ipc_pkt);
			act_sta_num = 0;
		}

		if (sta_info->enable == 1 && sta_info->om_control != 0) {
			printf("delay omi_control:%02x\n",
			       sta_info->om_control);
			if (!omi_event_to_host
			    (radio, sta_info->om_control, sta_info->stn_id,
			     sta_info->mac_addr))
				sta_info->om_control = 0;
		}

		search = search->nxt;
	}

	if (act_sta_num) {
		dol_event.notify_sta_num = act_sta_num;
		ca_ipc_msg_async_send(&ipc_pkt);
	}
}
