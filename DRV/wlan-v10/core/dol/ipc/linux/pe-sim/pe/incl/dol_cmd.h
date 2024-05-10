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
#define DOL_CMD_SUSPEND_RADIO			0x0016
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
#define RATE_TYPE_MAX                           4

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
#define DBG_DISABLE_DSCP_PARSE                  0x0100
#define DBG_DUMP_VIF_STATUS                     0x4000
#define DBG_DUMP_RADIO_STATUS                   0x8000

/* BA info type */
#define BA_INFO_ASSOC                           0
#define BA_INFO_ADDBA                           1
#define BA_INFO_DELBA                           2
#define BA_INFO_CFG_FLUSHTIME                   3

#define MAX_STA_ACTIVE_NOTIFY_NUM               1	//Make sure all elements of dol_evt_sta_active_notify are 4-byte aligned!!!

#define MAX_RETURN_PKT_NUM                      11

/* General dol command header */
struct dolcmd_header {
	ca_uint16_t radio;
	ca_uint16_t cmd;
	ca_uint16_t len;
	ca_uint16_t seq_no;
	ca_uint16_t result;
	ca_uint16_t rsvd;
} __packed;

/* DOL_CMD_CHECK_ACTIVE */
struct dol_cmd_check_active {
	struct dolcmd_header cmd_hdr;
	ca_uint32_t active;
} __packed;

/* DOL_CMD_GET_WFO_VERSION */
struct dol_cmd_get_wfo_version {
	struct dolcmd_header cmd_hdr;
	ca_uint8_t version[32];
} __packed;

/* DOL_CMD_START_RADIO */
struct dol_cmd_start_radio {
	struct dolcmd_header cmd_hdr;
	ca_uint64_t iobase0;
	ca_uint64_t iobase1;
	ca_uint32_t iobase0_phy;
	ca_uint32_t iobase1_phy;
	ca_uint64_t dev;
	ca_uint32_t smac_buf_hi_addr;
	ca_uint16_t devid;
	ca_uint16_t chip_revision;
	ca_uint16_t dbg_ctrl;
	ca_uint32_t rx_info_phy_addr;
	ca_uint32_t rx_info_que_size;
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
} __packed;

/* DOL_CMD_STOP_RADIO */
struct dol_cmd_stop_radio {
	struct dolcmd_header cmd_hdr;
} __packed;

/* DOL_CMD_RADIO_DATA_CTRL */
struct dol_cmd_radio_data_ctrl {
	struct dolcmd_header cmd_hdr;
	ca_uint32_t enable;
} __packed;

/* DOL_CMD_SUSPEND_RADIO */
struct dol_cmd_suspend_radio {
	struct dolcmd_header cmd_hdr;
	ca_uint32_t suspend;
} __packed;

/* DOL_CMD_RADIO_TX_AMPDU_CTRL */
struct dol_cmd_radio_tx_ampdu_ctrl {
	struct dolcmd_header cmd_hdr;
	ca_uint8_t ampdu_tx;
} __packed;

/* DOL_CMD_RADIO_RETURN_BUFFER */
struct dol_cmd_radio_return_buffer {
	struct dolcmd_header cmd_hdr;
	ca_uint32_t return_num;
	ca_uint64_t pkt_hdr_addr[MAX_RETURN_PKT_NUM];
} __packed;

/* DOL_CMD_RADIO_GET_RX_INFO */
struct rx_rate_info {
	ca_uint8_t type;
	ca_uint8_t nss;
	ca_uint8_t bw;
	ca_uint8_t gi_idx;
	ca_uint32_t cnt;
} __packed;

struct dol_cmd_radio_get_rx_info {
	struct dolcmd_header cmd_hdr;
	ca_uint8_t clean;
	ca_uint8_t first;
	ca_uint8_t more;
	ca_uint8_t rate_num;
	ca_uint32_t pkt_cnt[3];
	struct rx_rate_info rate_info[9];
} __packed;

/* DOL_CMD_ADD_VIF */
struct dol_cmd_add_vif {
	struct dolcmd_header cmd_hdr;
	ca_uint32_t vid;
	ca_uint8_t bssid[ETH_ALEN];
} __packed;

/* DOL_CMD_DEL_VIF */
struct dol_cmd_del_vif {
	struct dolcmd_header cmd_hdr;
	ca_uint32_t vid;
} __packed;

/* DOL_CMD_VIF_DATA_CTRL */
struct dol_cmd_vif_data_ctrl {
	struct dolcmd_header cmd_hdr;
	ca_uint32_t vid;
	ca_uint32_t enable;
} __packed;

/* DOL_CMD_VIF_SET_ISOLATE_GRP_ID */
struct dol_cmd_vif_set_isolate_grp_id {
	struct dolcmd_header cmd_hdr;
	ca_uint32_t vid;
	ca_uint32_t isolate_group_id;
} __packed;

/* DOL_CMD_ADD_STA */
struct dol_cmd_add_sta {
	struct dolcmd_header cmd_hdr;
	ca_uint32_t vid;
	ca_uint8_t sta_mac[ETH_ALEN];
} __packed;

/* DOL_CMD_DEL_STA */
struct dol_cmd_del_sta {
	struct dolcmd_header cmd_hdr;
	ca_uint32_t vid;
	ca_uint8_t sta_mac[ETH_ALEN];
} __packed;

/* DOL_CMD_STA_DATA_CTRL */
struct dol_cmd_sta_data_ctrl {
	struct dolcmd_header cmd_hdr;
	ca_uint32_t vid;
	ca_uint32_t enable;
	ca_uint16_t stn_id;
	ca_uint8_t sta_mac[ETH_ALEN];
} __packed;

/* DOL_CMD_STA_TX_AMPDU_CTRL */
struct dol_cmd_sta_tx_ampdu_ctrl {
	struct dolcmd_header cmd_hdr;
	ca_uint32_t vid;
	ca_uint8_t sta_mac[ETH_ALEN];
	ca_uint16_t threshold;
	ca_uint8_t startbytid[SYSADPT_MAX_TID];
} __packed;

/* DOL_CMD_SET_BA_INFO */
struct dol_cmd_set_ba_info {
	struct dolcmd_header cmd_hdr;
	ca_uint16_t type;
	union {
		ca_uint16_t stn_id;
		ca_uint16_t ba_reorder_hold_time;
	};
	ca_uint16_t tid;
	ca_uint16_t winStartB;
	ca_uint16_t winSizeB;
} __packed;

/* DOL_CMD_SET_BA_REQ */
struct dol_cmd_set_ba_req {
	struct dolcmd_header cmd_hdr;
	ca_uint16_t vid;
	ca_uint16_t stn_id;
	ca_uint16_t tid;
	ca_uint16_t seq;
} __packed;

/* DOL_CMD_SET_DSCP_WMM_MAPPING */
struct dol_cmd_set_dscp_wmm_mapping {
	struct dolcmd_header cmd_hdr;
	ca_uint16_t dscp_wmm_mapping;
} __packed;

/* DOL_CMD_GET_STATS */
struct netdev_stats {
	ca_uint32_t rx_packets;
	ca_uint32_t tx_packets;
	ca_uint32_t rx_bytes;
	ca_uint32_t tx_bytes;
	ca_uint32_t rx_errors;
	ca_uint32_t tx_errors;
	ca_uint32_t rx_dropped;
	ca_uint32_t tx_dropped;
	ca_uint32_t multicast;
	ca_uint32_t collisions;
	ca_uint32_t rx_length_errors;
	ca_uint32_t rx_over_errors;
	ca_uint32_t rx_crc_errors;
	ca_uint32_t rx_frame_errors;
	ca_uint32_t rx_fifo_errors;
	ca_uint32_t rx_missed_errors;
	ca_uint32_t tx_aborted_errors;
	ca_uint32_t tx_carrier_errors;
} __packed;

struct pkt_status {
	ca_uint32_t pkt_hdr_free_num;
	ca_uint32_t pkt_bmq_free_num[4];
	ca_uint32_t pkt_from_host_num;
	ca_uint32_t pkt_from_eth_num[4];
} __packed;

struct dbg_tx_cnt {
	ca_uint32_t data_pkt_from_host;
	ca_uint32_t mgmt_pkt_from_host;
	ca_uint32_t unicast_pkt_from_eth;
	ca_uint32_t bcmc_pkt_from_eth;
	ca_uint32_t ac_pkt[4];	/* 3 is the highest one */
	ca_uint32_t ac_drop[4];	/* 3 is the highest one */
	ca_uint32_t tx_drop_msg_err;
	ca_uint32_t tx_drop_vif_err;
	ca_uint32_t tx_drop_vif_disable;
	ca_uint32_t tx_drop_sta_err;
	ca_uint32_t tx_drop_sta_disable;
	ca_uint32_t tx_drop_no_pkt_hdr;
	ca_uint32_t tx_queue_full;
	ca_uint32_t tx_queue_send;
} __packed;

struct dbg_rel_cnt {
	ca_uint32_t tx_release;	/* tx release from tx queue (6) */
	ca_uint32_t bm_release_from_host;
	ca_uint32_t bmq_release[4];	/* rx drop: 10, 11, 12, 13 */
	ca_uint32_t bm10_poll;
	ca_uint32_t bm10_return_non_clone;
	ca_uint32_t bm10_to_host;
	ca_uint32_t bm10_return_host;
	ca_uint32_t bm10_to_eth;
	ca_uint32_t bm10_return_eth;
	ca_uint32_t pe_hw_sig_err;
	ca_uint32_t pe_hw_phy_addr_err;
	ca_uint32_t pe_hw_bpid_err;
	ca_uint32_t pe_hw_pkt_sig_err;
} __packed;

struct dbg_rx_cnt {
	ca_uint32_t mgmt_pkt_to_host;	/* it will also include ctrl packet */
	ca_uint32_t eapol_pkt_to_host;
	ca_uint32_t data_pkt_to_host;	/* if related debug flag is set */
	ca_uint32_t data_pkt_to_eth;
	ca_uint32_t rx_drop_mgmt_q_type_err;
	ca_uint32_t rx_drop_data_q_type_err;
	ca_uint32_t rx_drop_vif_err;
	ca_uint32_t rx_drop_vif_disable;
	ca_uint32_t rx_drop_sta_err;
	ca_uint32_t rx_drop_sta_disable;
	ca_uint32_t rx_drop_llc_err;
	ca_uint32_t rx_drop_msdu_err;
	ca_uint32_t rx_bmq_refill_fail[3];	/* 10, 11, 12 */
	ca_uint32_t rx_cfh_ul_sig_err;
	ca_uint32_t rx_cfh_ul_bpid_err;
	ca_uint32_t rx_cfh_ul_snap_err;
	ca_uint32_t rx_cfh_ul_size_err;
	ca_uint32_t rx_cfh_ul_war;
} __packed;

struct dbg_pkt_cnt {
	ca_uint32_t pkt_hdr_alloc;
	ca_uint32_t pkt_hdr_free;
	ca_uint32_t pkt_hdr_lack;
	ca_uint32_t pkt_bm_data_alloc;
	ca_uint32_t pkt_bm_data_free;
	ca_uint32_t pkt_bmq_alloc[3];	/* 10, 11, 12 */
	ca_uint32_t pkt_bmq_free[3];	/* 10, 11, 12 */
	ca_uint32_t pkt_bmq_lack_buf[3];	/* 10, 11, 12 */
	ca_uint32_t pkt_bm_data_clone;
	ca_uint32_t pkt_bm_data_clone_free;
	ca_uint32_t pkt_host_data_free;
	ca_uint32_t pkt_eth_data_free;
	ca_uint32_t pkt_local_data_free;
	ca_uint32_t pkt_amsdu_alloc;
	ca_uint32_t pkt_amsdu_free;
	ca_uint32_t pkt_amsdu_lack;
} __packed;

struct dbg_sta_cnt {
	ca_uint16_t more;
	ca_uint16_t stn_id;
	u8 mac_addr[ETH_ALEN];
	ca_uint32_t send_cnt;
	ca_uint32_t rel_cnt;
	ca_uint32_t pend_cnt;
	ca_uint32_t drop_cnt;
	ca_uint32_t txq_pend_cnt[8];
} __packed;

struct dbg_hfrmq_info {
	ca_uint32_t rdptr;
	ca_uint32_t wrptr;
	ca_uint8_t qid;
	ca_uint8_t qoff;
} __packed;

struct dol_cmd_get_stats {
	struct dolcmd_header cmd_hdr;
	ca_uint16_t type;
	ca_uint8_t vid;
	ca_uint8_t clear_after_read;
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
	ca_uint16_t dbg_ctrl;
} __packed;

/* General dol event header */
struct dolevt_header {
	ca_uint16_t radio;
	ca_uint16_t event;
} __packed;

/* DOL_EVT_STA_ACTIVE_NOTIFY */
struct dbRateInfo {
	UINT32 Format:2;	//0 = Legacy format, 1 = 11n format, 2 = 11ac format
	UINT32 Stbc:1;
	UINT32 Dcm:1;
	UINT32 Bandwidth:2;	//0 = Use 20 MHz channel,1 = Use 40 MHz channel, 2 = Use 80 MHz
	UINT32 ShortGI:2;	//0 = Use standard guard interval,1 = Use short guard interval, 2=11ax short short
	UINT32 RateIDMCS:7;
	UINT32 Preambletype:1;	//Preambletype 0= Long, 1= Short;
	UINT32 PowerId:6;
	UINT32 AdvCoding:1;	//ldpc
	UINT32 BF:1;
	UINT32 AntSelect:8;	//Bitmap to select one of the transmit antennae
};

struct rx_info_aux {
	ca_uint32_t ppdu_len;
	ca_uint32_t rxTs;	// rx_info_28 rx timestamp[31:0]
	ca_uint32_t rxTsH;	// rx_info_29 rx timestamp[39:32]
	union {
		struct {	// for ag packets
			OFDM_SIG ofdm_sig;
		};
		struct {	// for 11n packets
			HT_SIG1 ht_sig1;
			HT_SIG2 ht_sig2;
		};
		struct {	// for ac packets
			VHT_SIG_A1 vht_siga1;
			VHT_SIG_A2 vht_siga2;
			VHT_SIG_B vht_sigb;
		};
		struct {	// for he packets
			HE_SIG_A1 he_siga1;
			HE_SIG_A2 he_siga2;
			HE_SIG_B_USR hesigb;
		};
	};
	struct dbRateInfo rate_info;	// Saved parameters
	ca_uint8_t nss;		// dbRateInfo_t->AntSelect is bit maps => save to nss to avoid more calcuation
	ca_uint8_t rx_mode;
};

struct rxppdu_airtime {
	struct rx_info_aux rx_info_aux;

	ca_uint32_t rx_airtime;	// airtime of the ppdu
	ca_uint32_t rx_datlen;	// ppdu packet length, increasing

	// parameters, gotten from rxinfo, ppdu_pkt to calculate the air_time
	ca_uint32_t dbg_pktcnt, dbg_nss, dbg_mcs, dbg_bw,
		dbg_gi_ltf /*, dbg_sum_pktlen, dbg_sum_pktcnt */ ;
	ca_uint32_t dbg_Ndbps10x;
	//ca_uint32_t   dbg_su_pktcnt, dbg_mu_pktcnt;
	ca_uint64_t rx_tsf;
	ca_uint64_t sum_rx_airtime;
#if 0
	ca_uint64_t sum_rx_pktcnt;
#else
	ca_uint32_t sum_rx_pktcnt;
#endif
	ca_uint64_t sum_rx_pktlen;
};

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
	ca_uint32_t a:12;
	ca_uint32_t b:12;
	ca_uint32_t rsv1:8;
	ca_uint32_t c:12;
	ca_uint32_t d:12;
	ca_uint32_t rsv2:8;
	ca_uint32_t e:12;
	ca_uint32_t f:12;
	ca_uint32_t rsv3:8;
	ca_uint32_t g:12;
	ca_uint32_t h:12;
	ca_uint32_t rsv4:8;
};

struct dol_evt_sta_active_notify {
	struct dolevt_header evt;
	ca_uint32_t notify_sta_num;
	ca_uint8_t sta_addr[MAX_STA_ACTIVE_NOTIFY_NUM][ETH_ALEN];
	ca_uint8_t rsvd[2];	//MAX_STA_ACTIVE_NOTIFY_NUM=1, so make it 4-byte alignment
	struct rssi_path_info rssi_path_info[MAX_STA_ACTIVE_NOTIFY_NUM];
	struct rxppdu_airtime_evt rxppdu_airtime_evt[MAX_STA_ACTIVE_NOTIFY_NUM];
	ca_uint64_t tx_bytes[MAX_STA_ACTIVE_NOTIFY_NUM];
	ca_uint64_t rx_bytes[MAX_STA_ACTIVE_NOTIFY_NUM];
} __packed;

/* DOL_EVT_AMPDU_CONTROL */
struct dol_evt_ampdu_control {
	struct dolevt_header evt;
	ca_uint8_t enable;
	ca_uint8_t tid;
	ca_uint8_t sta_addr[ETH_ALEN];
} __packed;

/* DOL_EVT_FREE_BMQ13 */
struct dol_evt_free_bmq13 {
	struct dolevt_header evt;
	bm_pe_hw_t pe_hw;
} __packed;

struct dol_evt_omi_event {
	struct dolevt_header evt;
	ca_uint16_t om_control;
	ca_uint16_t stnid;
	ca_uint8_t sta_addr[ETH_ALEN];
} __packed;

#endif /* __DOL_CMD_H__ */
