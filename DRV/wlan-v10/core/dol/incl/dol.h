/** @file dol.h
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

#ifndef __DOL_H__
#define __DOL_H__

/* Should move to header file for system adaptation */
#define RX_Q_DATA            0
#define RX_Q_SIZE            (0x2000-1)
#define TX_Q_START           6
#define TX_Q_NUM             1
#define REL_Q_START          10
#define REL_Q_NUM            3
#define BM_Q_START           10
#define BM_Q_NUM             3

/* BA info type */
#define BA_INFO_ASSOC         0
#define BA_INFO_ADDBA         1
#define BA_INFO_DELBA         2
#define BA_INFO_CFG_FLUSHTIME 3

struct mwl_dol_ops {
	const char *name;

	const char *version;

	int (*init) (void *ctrl);

	void (*deinit) (void *ctrl);

	int (*check_active) (void *ctrl, int rid, bool * active);

	int (*get_wfo_version) (void *ctrl, int rid, u8 * ver);

	int (*start_radio) (void *ctrl, int rid);

	int (*stop_radio) (void *ctrl, int rid);

	int (*suspend_radio) (void *ctrl, int rid, bool suspend);

	int (*radio_data_ctrl) (void *ctrl, int rid, bool enable);

	int (*radio_tx_ampdu_ctrl) (void *ctrl, int rid, u8 ampdu_tx);

	void (*radio_return_buffer) (void *ctrl, int rid, u64 pkt_hdr_addr);

	int (*radio_get_rx_info) (void *ctrl, int rid, bool clean);

	int (*add_vif) (void *ctrl, int rid, int vid, u8 * bssid);

	int (*del_vif) (void *ctrl, int rid, int vid);

	int (*vif_data_ctrl) (void *ctrl, int rid, int vid, bool enable);

	int (*vif_set_isolate_grp_id) (void *ctrl, int rid, int vid,
				       int group_id);

	int (*add_sta) (void *ctrl, int rid, int vid, u8 * addr);

	int (*del_sta) (void *ctrl, int rid, int vid, u8 * addr);

	int (*sta_data_ctrl) (void *ctrl, int rid, int vid, u16 stn_id,
			      u8 * addr, bool enable);

	int (*sta_tx_ampdu_ctrl) (void *ctrl, int rid, int vid, u8 * addr,
				  u32 threshold, u8 * startbytid);

	void (*set_ba_info) (void *ctrl, int rid, u16 type, u16 stn_id,
			     u16 tid, u16 winStartB, u16 winSizeB);

	void (*set_ba_req) (void *ctrl, int rid, u16 vid, u16 stn_id,
			    u16 tid, u16 seq);

	int (*xmit) (void *ctrl, struct sk_buff * skb, wltxdesc_t * txcfg,
		     int qid);

	struct sk_buff *((*recv) (void *ctrl, bool data));

	void (*set_dscp_wmm_mapping) (void *ctrl, int rid,
				      u16 dscp_wmm_mapping);

	int (*get_stats) (void *ctrl, int rid, int vid, u16 type, void *stats,
			  int stats_size, bool clear_after_read, int *more);

	void (*set_dbg_ctrl) (void *ctrl, int rid, u16 dbg_ctrl);
};

#endif /* __DOL_H__ */
