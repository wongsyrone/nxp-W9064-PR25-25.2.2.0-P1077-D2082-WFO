/** @file dol_cmd.h
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

#ifndef __DOL_CMD_H__
#define __DOL_CMD_H__

/* 16 bit dol command code */
#define DOL_CMD_CHECK_ACTIVE                    0x0001
#define DOL_CMD_GET_WFO_VERSION                 0x0002
#define DOL_CMD_START_RADIO                     0x0010
#define DOL_CMD_STOP_RADIO                      0x0011
#define DOL_CMD_RADIO_DATA_CTRL                 0x0012
#define DOL_CMD_RADIO_TX_AMPDU_CTRL             0x0013
#define DOL_CMD_RADIO_RETURN_BUFFER             0x0014
#define DOL_CMD_RADIO_GET_RX_INFO               0x0015
#define DOL_CMD_SUSPEND_RADIO                   0x0016
#define DOL_CMD_ADD_VIF                         0x0020
#define DOL_CMD_DEL_VIF                         0x0021
#define DOL_CMD_VIF_DATA_CTRL                   0x0022
#define DOL_CMD_VIF_SET_ISOLATE_GRP_ID          0x0023
#define DOL_CMD_ADD_STA                         0x0030
#define DOL_CMD_DEL_STA                         0x0031
#define DOL_CMD_STA_DATA_CTRL                   0x0032
#define DOL_CMD_STA_TX_AMPDU_CTRL               0x0033
#define DOL_CMD_SET_BA_INFO                     0x0034
#define DOL_CMD_SET_BA_REQ                      0x0035
#define DOL_CMD_SET_DSCP_WMM_MAPPING            0x00E0
#define DOL_CMD_GET_STATS                       0x00F0
#define DOL_CMD_SET_DBG_CTRL                    0x00F1

/* 16 bit dol event code */
#define DOL_EVT_STA_ACTIVE_NOTIFY               0x0001
#define DOL_EVT_AMPDU_CONTROL                   0x0002
#define DOL_EVT_OMI_CONTROL                     0x0003
#define DOL_EVT_FREE_BMQ13                      0x00F0

/* Rate type */
#define RATE_LEGACY                             0
#define RATE_HT                                 1
#define RATE_VHT                                2
#define RATE_HE                                 3

/* The way to map DSCP to WMM AC */
#define DSCP_WMM_MAPPING_IP_PRECEDENCE          0
#define DSCP_WMM_MAPPING_NEC                    1

/* Specify what kind of statistics/counters should be accessed */
#define GET_STATS_NET_DEVICE                    0
#define GET_STATS_PKT_STATUS                    1
#define GET_STATS_DBG_TX_CNT                    2
#define GET_STATS_DBG_REL_CNT                   3
#define GET_STATS_DBG_RX_CNT                    4
#define GET_STATS_DBG_PKT_CNT                   5
#define GET_STATS_DBG_STA_CNT                   6
#define GET_STATS_HFRMQ_INFO                    7

/* 16 bit debug control */
#define DBG_DUMP_DOL_CMD                        0x0001
#define DBG_TX_MGMT_TIMESTAMP                   0x0002
#define DBG_RX_MGMT_TIMESTAMP                   0x0004
#define DBG_PKT_TO_HOST                         0x0008
#define DBG_DUMP_ETH_TX_PKT                     0x0010
#define DBG_ETH_LOOPBACK_PKT                    0x0020
#define DBG_DISABLE_BA_REORDER                  0x0040
#define DBG_ENABLE_CLIENT_RSSI                  0x0080
#define DBG_DUMP_VIF_STATUS                     0x4000
#define DBG_DUMP_RADIO_STATUS                   0x8000

#define MAX_STA_ACTIVE_NOTIFY_NUM               1

#define MAX_RETURN_PKT_NUM                      11

/* General dol command header */
struct dolcmd_header {
	__le16 radio;
	__le16 cmd;
	__le16 len;
	__le16 seq_no;
	__le16 result;
	__le16 rsvd;
} __packed;

/* DOL_CMD_CHECK_ACTIVE */
struct dol_cmd_check_active {
	struct dolcmd_header cmd_hdr;
	__le32 active;
} __packed;

/* DOL_CMD_GET_WFO_VERSION */
struct dol_cmd_get_wfo_version {
	struct dolcmd_header cmd_hdr;
	u8 version[32];
} __packed;

/* DOL_CMD_START_RADIO */
struct dol_cmd_start_radio {
	struct dolcmd_header cmd_hdr;
	__le64 iobase0;
	__le64 iobase1;
	__le32 iobase0_phy;
	__le32 iobase1_phy;
	__le64 dev;
	__le32 smac_buf_hi_addr;
	__le16 devid;
	__le16 chip_revision;
	__le16 dbg_ctrl;
	__le32 rx_info_phy_addr;
	__le32 rx_info_que_size;
	u8 bss_num;
	u8 rx_q_data;
	__le16 rx_q_size;
	u8 tx_q_start;
	u8 tx_q_num;
	__le16 tx_q_size[2];
	u8 rel_q_start;
	u8 rel_q_num;
	__le16 rel_q_size[4];
	u8 bm_q_start;
	u8 bm_q_num;
	__le16 bm_q_size[4];
	__le16 bm_buf_size[4];
} __packed;

/* DOL_CMD_STOP_RADIO */
struct dol_cmd_stop_radio {
	struct dolcmd_header cmd_hdr;
} __packed;

/* DOL_CMD_SUSPEND_RADIO */
struct dol_cmd_suspend_radio {
	struct dolcmd_header cmd_hdr;
	__le32 suspend;
} __packed;

/* DOL_CMD_RADIO_DATA_CTRL */
struct dol_cmd_radio_data_ctrl {
	struct dolcmd_header cmd_hdr;
	__le32 enable;
} __packed;

/* DOL_CMD_RADIO_TX_AMPDU_CTRL */
struct dol_cmd_radio_tx_ampdu_ctrl {
	struct dolcmd_header cmd_hdr;
	u8 ampdu_tx;
} __packed;

/* DOL_CMD_RADIO_RETURN_BUFFER */
struct dol_cmd_radio_return_buffer {
	struct dolcmd_header cmd_hdr;
	__le32 return_num;
	__le64 pkt_hdr_addr[MAX_RETURN_PKT_NUM];
} __packed;

/* DOL_CMD_RADIO_GET_RX_INFO */
struct rx_rate_info {
	u8 type;
	u8 nss;
	u8 bw;
	u8 gi_idx;
	__le32 cnt;
} __packed;

struct dol_cmd_radio_get_rx_info {
	struct dolcmd_header cmd_hdr;
	u8 clean;
	u8 first;
	u8 more;
	u8 rate_num;
	__le32 pkt_cnt[3];
	struct rx_rate_info rate_info[9];
} __packed;

/* DOL_CMD_ADD_VIF */
struct dol_cmd_add_vif {
	struct dolcmd_header cmd_hdr;
	__le32 vid;
	u8 bssid[ETH_ALEN];
} __packed;

/* DOL_CMD_DEL_VIF */
struct dol_cmd_del_vif {
	struct dolcmd_header cmd_hdr;
	__le32 vid;
} __packed;

/* DOL_CMD_VIF_DATA_CTRL */
struct dol_cmd_vif_data_ctrl {
	struct dolcmd_header cmd_hdr;
	__le32 vid;
	__le32 enable;
} __packed;

/* DOL_CMD_VIF_SET_ISOLATE_GRP_ID */
struct dol_cmd_vif_set_isolate_grp_id {
	struct dolcmd_header cmd_hdr;
	__le32 vid;
	__le32 isolate_group_id;
} __packed;

/* DOL_CMD_ADD_STA */
struct dol_cmd_add_sta {
	struct dolcmd_header cmd_hdr;
	__le32 vid;
	u8 sta_mac[ETH_ALEN];
} __packed;

/* DOL_CMD_DEL_STA */
struct dol_cmd_del_sta {
	struct dolcmd_header cmd_hdr;
	__le32 vid;
	u8 sta_mac[ETH_ALEN];
} __packed;

/* DOL_CMD_STA_DATA_CTRL */
struct dol_cmd_sta_data_ctrl {
	struct dolcmd_header cmd_hdr;
	__le32 vid;
	__le32 enable;
	__le16 stn_id;
	u8 sta_mac[ETH_ALEN];
} __packed;

/* DOL_CMD_STA_TX_AMPDU_CTRL */
struct dol_cmd_sta_tx_ampdu_ctrl {
	struct dolcmd_header cmd_hdr;
	__le32 vid;
	u8 sta_mac[ETH_ALEN];
	__le32 threshold;
	u8 startbytid[8];
} __packed;

/* DOL_CMD_SET_BA_INFO */
struct dol_cmd_set_ba_info {
	struct dolcmd_header cmd_hdr;
	__le16 type;
	__le16 stn_id;
	__le16 tid;
	__le16 winStartB;
	__le16 winSizeB;
} __packed;

/* DOL_CMD_SET_BA_REQ */
struct dol_cmd_set_ba_req {
	struct dolcmd_header cmd_hdr;
	__le16 vid;
	__le16 stn_id;
	__le16 tid;
	__le16 seq;
} __packed;

/* DOL_CMD_SET_DSCP_WMM_MAPPING */
struct dol_cmd_set_dscp_wmm_mapping {
	struct dolcmd_header cmd_hdr;
	__le16 dscp_wmm_mapping;
} __packed;

/* DOL_CMD_GET_STATS */
struct netdev_stats {
	__le32 rx_packets;
	__le32 tx_packets;
	__le32 rx_bytes;
	__le32 tx_bytes;
	__le32 rx_errors;
	__le32 tx_errors;
	__le32 rx_dropped;
	__le32 tx_dropped;
	__le32 multicast;
	__le32 collisions;
	__le32 rx_length_errors;
	__le32 rx_over_errors;
	__le32 rx_crc_errors;
	__le32 rx_frame_errors;
	__le32 rx_fifo_errors;
	__le32 rx_missed_errors;
	__le32 tx_aborted_errors;
	__le32 tx_carrier_errors;
} __packed;

struct pkt_status {
	__le32 pkt_hdr_free_num;
	__le32 pkt_bmq_free_num[4];
	__le32 pkt_from_host_num;
	__le32 pkt_from_eth_num[4];
} __packed;

struct dbg_tx_cnt {
	__le32 data_pkt_from_host;
	__le32 mgmt_pkt_from_host;
	__le32 unicast_pkt_from_eth;
	__le32 bcmc_pkt_from_eth;
	__le32 ac_pkt[4];	/* 3 is the highest one */
	__le32 ac_drop[4];	/* 3 is the highest one */
	__le32 tx_drop_msg_err;
	__le32 tx_drop_vif_err;
	__le32 tx_drop_vif_disable;
	__le32 tx_drop_sta_err;
	__le32 tx_drop_sta_disable;
	__le32 tx_drop_no_pkt_hdr;
	__le32 tx_queue_full;
	__le32 tx_queue_send;
} __packed;

struct dbg_rel_cnt {
	__le32 tx_release;	/* tx release from tx queue (6) */
	__le32 bm_release_from_host;
	__le32 bmq_release[4];	/* rx drop: 10, 11, 12, 13 */
	__le32 bm10_poll;
	__le32 bm10_return_non_clone;
	__le32 bm10_to_host;
	__le32 bm10_return_host;
	__le32 bm10_to_eth;
	__le32 bm10_return_eth;
	__le32 pe_hw_sig_err;
	__le32 pe_hw_phy_addr_err;
	__le32 pe_hw_bpid_err;
	__le32 pe_hw_pkt_sig_err;
} __packed;

struct dbg_rx_cnt {
	__le32 mgmt_pkt_to_host;	/* it will also include ctrl packet */
	__le32 eapol_pkt_to_host;
	__le32 data_pkt_to_host;	/* if related debug flag is set */
	__le32 data_pkt_to_eth;
	__le32 rx_drop_mgmt_q_type_err;
	__le32 rx_drop_data_q_type_err;
	__le32 rx_drop_vif_err;
	__le32 rx_drop_vif_disable;
	__le32 rx_drop_sta_err;
	__le32 rx_drop_sta_disable;
	__le32 rx_drop_llc_err;
	__le32 rx_drop_msdu_err;
	__le32 rx_bmq_refill_fail[3];	/* 10, 11, 12 */
	__le32 rx_cfh_ul_sig_err;
	__le32 rx_cfh_ul_bpid_err;
	__le32 rx_cfh_ul_snap_err;
	__le32 rx_cfh_ul_size_err;
	__le32 rx_cfh_ul_war;
} __packed;

struct dbg_pkt_cnt {
	__le32 pkt_hdr_alloc;
	__le32 pkt_hdr_free;
	__le32 pkt_hdr_lack;
	__le32 pkt_bm_data_alloc;
	__le32 pkt_bm_data_free;
	__le32 pkt_bmq_alloc[3];	/* 10, 11, 12 */
	__le32 pkt_bmq_free[3];	/* 10, 11, 12 */
	__le32 pkt_bmq_lack_buf[3];	/* 10, 11, 12 */
	__le32 pkt_bm_data_clone;
	__le32 pkt_bm_data_clone_free;
	__le32 pkt_host_data_free;
	__le32 pkt_eth_data_free;
	__le32 pkt_local_data_free;
	__le32 pkt_amsdu_alloc;
	__le32 pkt_amsdu_free;
	__le32 pkt_amsdu_lack;
} __packed;

struct dbg_sta_cnt {
	__le16 more;
	__le16 stn_id;
	u8 mac_addr[ETH_ALEN];
	__le32 send_cnt;
	__le32 rel_cnt;
	__le32 pend_cnt;
	__le32 drop_cnt;
	__le32 txq_pend_cnt[8];
} __packed;

struct dbg_hfrmq_info {
	__le32 rdptr;
	__le32 wrptr;
	u8 qid;
	u8 qoff;
} __packed;

struct dol_cmd_get_stats {
	struct dolcmd_header cmd_hdr;
	__le16 type;
	u8 vid;
	u8 clear_after_read;
	union {
		struct netdev_stats netdev_stats;
		struct pkt_status pkt_status;
		struct dbg_tx_cnt dbg_tx_cnt;
		struct dbg_rel_cnt dbg_rel_cnt;
		struct dbg_rx_cnt dbg_rx_cnt;
		struct dbg_pkt_cnt dbg_pkt_cnt;
		struct dbg_sta_cnt dbg_sta_cnt;
		struct dbg_hfrmq_info dbg_hfrmq_info;
	};
} __packed;

/* DOL_CMD_SET_DBG_CTRL */
struct dol_cmd_set_dbg_ctrl {
	struct dolcmd_header cmd_hdr;
	__le16 dbg_ctrl;
} __packed;

/* General dol event header */
struct dolevt_header {
	__le16 radio;
	__le16 event;
} __packed;

/* DOL_EVT_STA_ACTIVE_NOTIFY */
struct rxppdu_airtime_evt {
	ca_uint32_t rx_airtime;
	ca_uint32_t aux_ppdu_len;
	ca_uint32_t aux_rxTs;
	ca_uint32_t aux_rate_info;
#if 0
	ca_uint32_t dbg_sum_pktlen;
	ca_uint32_t dbg_sum_pktcnt;
	ca_uint32_t dbg_su_pktcnt;
	ca_uint32_t dbg_mu_pktcnt;
#endif
	ca_uint32_t dbg_nss;
	ca_uint32_t dbg_mcs;
	ca_uint32_t dbg_bw;
	ca_uint32_t dbg_gi_ltf;
	ca_uint32_t dbg_Ndbps10x;
	ca_uint64_t sum_rx_airtime;
#if 0
	ca_uint64_t sum_rx_pktcnt;
#else
	ca_uint32_t sum_rx_pktcnt;
#endif
	ca_uint64_t sum_rx_pktlen;
} __packed;

/* rssi info to dump */
struct rssi_path_info {
	u32 a:12;
	u32 b:12;
	u32 rsv1:8;
	u32 c:12;
	u32 d:12;
	u32 rsv2:8;
	u32 e:12;
	u32 f:12;
	u32 rsv3:8;
	u32 g:12;
	u32 h:12;
	u32 rsv4:8;
};

struct dol_evt_sta_active_notify {
	struct dolevt_header evt;
	__le32 notify_sta_num;
	u8 sta_addr[MAX_STA_ACTIVE_NOTIFY_NUM][ETH_ALEN];
	u8 rsvd[2];		//Make it 4-byte alignment
	struct rssi_path_info rssi_path_info[MAX_STA_ACTIVE_NOTIFY_NUM];
	struct rxppdu_airtime_evt rxppdu_airtime_evt[MAX_STA_ACTIVE_NOTIFY_NUM];
	u64 tx_bytes[MAX_STA_ACTIVE_NOTIFY_NUM];
	u64 rx_bytes[MAX_STA_ACTIVE_NOTIFY_NUM];
} __packed;

/* DOL_EVT_AMPDU_CONTROL */
struct dol_evt_ampdu_control {
	struct dolevt_header evt;
	u8 enable;
	u8 tid;
	u8 sta_addr[ETH_ALEN];
} __packed;

/* DOL_EVT_FREE_BMQ13 */
struct dol_evt_free_bmq13 {
	struct dolevt_header evt;
	bm_pe_hw_t pe_hw;
} __packed;

struct dol_evt_omi_event {
	struct dolevt_header evt;
	u16 om_control;
	u16 stnid;
	u8 sta_addr[ETH_ALEN];
} __packed;

#endif /* __DOL_CMD_H__ */
