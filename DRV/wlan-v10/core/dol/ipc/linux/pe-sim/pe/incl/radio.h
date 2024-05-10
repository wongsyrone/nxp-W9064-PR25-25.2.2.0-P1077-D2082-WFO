/** @file radio.h
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

#ifndef __RADIO_H__
#define __RADIO_H__

#include "ca_types.h"
#include "osal.h"
#include "sysadpt.h"
#include "ieeetypes.h"
#include "list.h"
#include "BQM.h"
#include "pkt.h"
#include "dol_cmd.h"
#include "stadb.h"
#include "ba.h"

#define WFO_VERSION "v1.0.28-20200417"

#ifdef LINUX_PE_SIM
#define __PLATFORM_POINTER_TYPE__				(ca_uint64_t)
#else
#define __PLATFORM_POINTER_TYPE__				(ca_uint32_t)
#endif

#define SC3                         0x2A55
#define SC4                         0x2B40
#define SC4P                        0x2B41
#define SC5                         0x2B50
#define SCBT                        0x2B55

#define REV_Z1	                    0
#define REV_Z2	                    1
#define REV_A0	                    2

#define SMAC_STA_QID_START          (SYSADPT_MAX_VIF * SYSADPT_MAX_STA)	/* QID for BSS: 0 ~ (SMAC_STA_QID_START-1) */
#define SMAC_QID_NUM                (SMAC_STA_QID_START + SYSADPT_MAX_STA * SYSADPT_MAX_TID)

#define BBTX_TMR_TSF                0x14AA0
#define BBTX_TMR_TSF_HI             0x14AA4
#define BBTX_TMR_FREE_TSF           0x14b20
#define BBTX_TMR_FREE_TSF_HI        0x14b24

#define QS_MAX_DATA_RATES_G         14
#define QS_NUM_SUPPORTED_11N_BW     2
#define QS_NUM_SUPPORTED_GI         2
#define QS_NUM_SUPPORTED_MCS        24
#define QS_NUM_SUPPORTED_11AC_NSS   8
#define QS_NUM_SUPPORTED_11AC_BW    4
#define QS_NUM_SUPPORTED_11AC_MCS   10
#define QS_NUM_SUPPORTED_11AX_NSS   8
#define QS_NUM_SUPPORTED_11AX_BW    5
#define QS_NUM_SUPPORTED_11AX_GILTF 4
#define QS_NUM_SUPPORTED_11AX_MCS   12

struct vif {
	ca_uint16_t rid;
	ca_uint16_t vid;
	ca_uint8_t bssid[ETH_ALEN];
	bool valid;
	bool enable;
	void *eth_handle;
	ca_uint32_t isolate_group_id;
	struct netdev_stats netdev_stats;
	ca_uint32_t sta_cnt;
};

struct wldesc_data {
	ca_uint8_t id;
	wl_qpair_rq_t rq;
	wl_qpair_sq_t sq;
};

/* Debug counters */
struct debug_cnt {
	struct dbg_tx_cnt tx_cnt;
	struct dbg_rel_cnt rel_cnt;
	struct dbg_rx_cnt rx_cnt;
	struct dbg_pkt_cnt pkt_cnt;
};

struct drv_stats {
	ca_uint32_t txq_drv_sent_cnt;
	ca_uint32_t txq_drv_release_cnt[4];
};

struct except_cnt {
	/* 0: fpkt lost, 1: middle lost 2: lpkt lost, 3: subframes over limit */
	ca_uint32_t cfhul_flpkt_lost[4];
	ca_uint32_t tx_drop_over_max_pending;	/* tx drop due to pending Tx over MAX_NUM_PENDING_TX */
	ca_uint32_t tx_mgmt_send_cnt;
	ca_uint32_t tx_mgmt_rel_cnt;
	ca_uint32_t tx_bcast_send_cnt;
	ca_uint32_t tx_bcast_rel_cnt;
	ca_uint32_t txq_send_cnt[SMAC_QID_NUM];
	ca_uint32_t txq_rel_cnt[SMAC_QID_NUM];
	ca_uint32_t txq_pend_cnt[SMAC_QID_NUM];
	ca_uint32_t txq_drop_cnt[SMAC_QID_NUM];
	ca_uint32_t tx_sta_send_cnt[SYSADPT_MAX_STA + 1];
	ca_uint32_t tx_sta_rel_cnt[SYSADPT_MAX_STA + 1];
	ca_uint32_t tx_sta_pend_cnt[SYSADPT_MAX_STA + 1];
	ca_uint32_t tx_sta_drop_cnt[SYSADPT_MAX_STA + 1];
};

struct drv_rate_hist {
	ca_uint8_t cur_type;
	ca_uint8_t cur_nss;
	ca_uint8_t cur_bw;
	ca_uint8_t cur_gi;
	ca_uint8_t cur_idx;
	ca_uint32_t pkt_cnt[3];	/* 0: Mgmt, 1: Ctrl, 2: Data, Ref: SMAC_ACNT_RX_PPDU_HDR_st */
	ca_uint32_t legacy_rates[QS_MAX_DATA_RATES_G];
	ca_uint32_t
		ht_rates[QS_NUM_SUPPORTED_11N_BW][QS_NUM_SUPPORTED_GI]
		[QS_NUM_SUPPORTED_MCS];
	ca_uint32_t
		vht_rates[QS_NUM_SUPPORTED_11AC_NSS][QS_NUM_SUPPORTED_11AC_BW]
		[QS_NUM_SUPPORTED_GI][QS_NUM_SUPPORTED_11AC_MCS];
	ca_uint32_t
		he_rates[QS_NUM_SUPPORTED_11AX_NSS][QS_NUM_SUPPORTED_11AX_BW]
		[QS_NUM_SUPPORTED_11AX_GILTF][QS_NUM_SUPPORTED_11AX_MCS];
};

struct bbrx_rx_info {
	/* 0x00 rx_info_0 */
	ca_uint32_t rx_sig:8;
	ca_uint32_t vhtsigbSig:23;
	ca_uint32_t rx_info_0_resv:1;
	/* 0x04 rx_info_1 */
	ca_uint32_t rx_nf:8;
	ca_uint32_t rx_rssi:8;
	ca_uint32_t lenRssiNf:16;
	/*  0x08 rx_info_2 htsig1/vhtsiga1[31:8], usr[7:6], bw_misc[4:0] */
	ca_uint32_t hesiga1:2;
	ca_uint32_t user_id_3:1;
	ca_uint32_t dup_likely_bw:2;
	ca_uint32_t user_id_2_0:3;
	ca_uint32_t htsig1_vhtsiga1_hesiga1:24;
	/* 0x0C rx_info_3 pkt_misc[31:28]{2nd,info}, sig_misc[27:24]{lsig_rsvd,parity,badP,htBadCrc}, htsig2/vhtsiga2[17:0] */
	ca_uint32_t htsig2_vhtsiga2_hesiga2:20;
	ca_uint32_t resv_rx_info_3:4;
	ca_uint32_t sig_misc:4;
	ca_uint32_t pkt_misc:4;
	/* rx_info_4 ~ rx_info_12 */
	ca_uint32_t rsv_1[9];
	/* 0x34 rx_info_13 0x0000_0000 pm rssi dbm c/d rx_info_13 */
	ca_uint32_t info_13_resv:15;
	ca_uint32_t rx_mode:4;
	ca_uint32_t rx_preamble_11b:1;
	ca_uint32_t mu_cq_valid:4;
	ca_uint32_t info_13_rx_resv:4;
	ca_uint32_t info_13_resv_1:4;
	/* rx_info_14 - rx_info_21 */
	ca_uint32_t rsv_2[8];
	/* 0x58 rx_info_22 */
	ca_uint32_t hesigb:31;
	ca_uint32_t resv_rx_info_22:1;
	/* rx_info_23 - rx_info_27 */
	ca_uint32_t rsv_3[5];
	/* 0x70 rx_info_28 rx timestamp[31:0] */
	ca_uint32_t rxTs;
	/* 0x74 rx_info_29 rx timestamp[39:32] */
	ca_uint32_t rxTsH;
	/* rx_info_30 - rx_info_63 */
	ca_uint32_t rsv_4[34];
} __packed;

/* Rx Side band Info, ref: smac_rx_sideband_info.msg */
struct rx_sideband_info {
	/* DWORD_0 ~ 3 */
	ca_uint32_t rsv_0[4];
	/* DWORD_4 */
	ca_uint32_t rssi_dbm_a:12;
	ca_uint32_t rssi_dbm_b:12;
	ca_uint32_t rsv_rssi_ab:8;
	/* DWORD_5 */
	ca_uint32_t rssi_dbm_c:12;
	ca_uint32_t rssi_dbm_d:12;
	ca_uint32_t rsv_rssi_cd:8;
	/* DWORD_6 */
	ca_uint32_t nf_dbm_a:12;
	ca_uint32_t nf_dbm_b:12;
	ca_uint32_t rsv_nf_ab:8;
	/* DWORD_7 */
	ca_uint32_t nf_dbm_c:12;
	ca_uint32_t nf_dbm_d:12;
	ca_uint32_t rsv_nf_cd:8;
	/* DWORD_8 */
	ca_uint32_t rssi_dbm_e:12;
	ca_uint32_t rssi_dbm_f:12;
	ca_uint32_t rsv_rssi_ef:8;
	/* DWORD_9 ~ 14 */
	ca_uint32_t rsv_1[6];
	/* DWORD_15 */
	ca_uint32_t rssi_dbm_g:12;
	ca_uint32_t rssi_dbm_h:12;
	ca_uint32_t rsv_rssi_gh:8;
	/* DWORD_16 */
	ca_uint32_t nf_dbm_e:12;
	ca_uint32_t nf_dbm_f:12;
	ca_uint32_t rsv_nf_ef:8;
	/* DWORD_17 */
	ca_uint32_t nf_dbm_g:12;
	ca_uint32_t nf_dbm_h:12;
	ca_uint32_t rsv_nf_gh:8;
	/* DWORD_18 ~ 27 */
	ca_uint32_t rsv_2[10];
	/* DWORD_28 */
	ca_uint32_t rxTs;	/* rx_info_28, rx timestamp[31:0]  */
	/* DWORD_29 */
	ca_uint32_t rxTsH;	/* rx_info_29, rx timestamp[39:32] */
	/* DWORD_30 */
	ca_uint32_t txTs;	/* rx_info_30, tx timestamp[31:0]  */
	/* DWORD_31 */
	ca_uint32_t rxCq;	/* rx_info_31, [31:24]: reserved, [23:0]:rx_cq[23:0] */
	/* DWORD 32 ~ 63 */
	ca_uint32_t rsv_3[32];
} __packed;

struct radio {
	ca_uint16_t rid;
	bool initialized;
	bool enable;
	bool suspend;
	void __iomem *iobase0;
	void __iomem *iobase1;
	void *dev;
	ca_uint32_t pre_poll_us;
	bool stop_wifi_polling;
	ca_uint8_t ampdu_tx;
	ca_uint32_t pre_active_notify_jiffies;
	ca_uint16_t devid;
	ca_uint16_t chip_revision;
	ca_uint32_t smac_buf_hi_addr;
	ca_uint16_t dbg_ctrl;
	ca_uint16_t dscp_wmm_mapping;
	ca_uint8_t cmd_buf[SYSADPT_MAX_CMD_BUF_LEN];
	ca_uint16_t cmd_buf_len;
	void *pending_cmd_reply;
	struct vif vif_info[SYSADPT_MAX_VIF];
	struct stadb_ctrl *stadb_ctrl;
	struct pkt_ctrl pkt_ctrl;
	struct wldesc_data desc_data[SYSADPT_NUM_OF_HW_DESC_DATA];
	wl_cfhul_amsdu_t cfhul_amsdu;
	int fw_desc_cnt;
	struct drv_stats drv_stats_val;
	struct debug_cnt dbg_cnt;
	struct except_cnt except_cnt;
	struct drv_rate_hist rx_rate_hist;
	ca_uint32_t last_rx_info_idx;
	struct bbrx_rx_info *rx_info_addr;
	ca_uint32_t rx_info_que_size;
	struct rx_info_aux *rxinfo_aux_poll;
	ca_uint8_t bss_num;
	ca_uint8_t rx_q_data;
	ca_uint16_t rx_q_size;
	ca_uint8_t tx_q_start;
	ca_uint8_t tx_q_num;
	ca_uint16_t tx_q_size[2];
	ca_uint8_t rel_q_start;
	ca_uint8_t rel_q_num;
	ca_uint16_t rel_q_size[4];
	ca_uint8_t bm_q_start;
	ca_uint8_t bm_q_num;
	ca_uint16_t bm_q_size[4];
	ca_uint16_t bm_buf_size[4];
	ca_uint16_t bm_buf_max_entries[4];
#ifdef BA_REORDER
	struct ampdu_pkt_reorder ampdu_ba_reorder[SYSADPT_MAX_STA + 1];
	struct ba_msdu_pkt *ba_msdu_pkt_p;
	struct list ba_msdu_pkt_free_list;
#endif
};

extern bool pe_ready;
extern struct radio radio_info[];

/* cmd_proc.c */

void cmd_proc_commands(int rid, const void *cmd, ca_uint16_t cmd_size);

/* tx.c */

void tx_proc_host_pkt(int rid, const void *msg, ca_uint16_t msg_size);

void tx_proc_eth_pkt(int rid, int vid, void *pkt, ca_uint8_t * data, int len,
		     int priority);

void tx_poll(int rid);

void tx_done(int rid);

/* rx.c */

void wlSendPktToHost(struct radio *radio, struct pkt_hdr *pkt, bool data,
		     wlrxdesc_t * cfh_ul);

void rx_rel_pkt_to_host(int rid, const void *msg, ca_uint16_t msg_size);

void rx_free_pkt_to_eth(int rid, void *pkt);

void rx_poll(int rid);

void rx_refill(int rid);

#include "stadb_inline.h"
#include "pkt_inline.h"
#include "BQM_inline.h"

#endif /* __RADIO_H__ */
