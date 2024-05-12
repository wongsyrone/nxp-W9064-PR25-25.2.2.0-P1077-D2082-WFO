/** @file msan_report.h
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2017-2020 NXP
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

/*!
 * \file  msan_report.h
 * \brief
 */

#if !defined(_MSAN_REPORT_H_)
#define _MSAN_REPORT_H_

#include "vendor.h"		/* include the define "UNASSOC_METRICS_CHANNEL_MAX" */

#define OFFCHAN_GET_ID_FROM_FEATURE(feature, id) ((feature << 16) | ((id << 16) >> 16))
#define OFFCHAN_GET_FEATURE_FROM_ID(id) (id >> 16)

/* define features of offchan by priority, The larger the value, the higher the priority */
typedef enum {
	OFFCHAN_BY_LIST = 0,
	OFFCHAN_BY_UNASSOCSTA,
	OFFCHAN_BY_DCS,
	OFFCHAN_BY_VENDOR,
	OFFCHAN_BY_ACS,
	OFFCHAN_BY_CMD,
	OFFCHAN_FEATURE_END
} offchan_features_e;

#ifdef IEEE80211K

#define SCAN_BY_OFFCHAN     0
#define SCAN_BY_ACS         1

/* Find the same SSID in neighbor list, extend offchan time to avoid affecting tx/rx */
#define RRM_DEFAULT_TRIGGER_TIME                600000	// 10 mins
#define RRM_DEFAULT_INTERVAL_TIME               3000	// 3000 ms
#define RRM_DEFAULT_DWELL_TIME                  60	// 60 ms

/* No STA connected and no the same SSID neighbors */
#define RRM_NO_STA_NO_NEIGHBOR_TRIGGER_TIME     30000	// 30s
#define RRM_NO_STA_NO_NEIGHBOR_INTERVAL_TIME    300	// 300 ms
#define RRM_NO_STA_NO_NEIGHBOR_DWELL_TIME       140	// 140 ms

/* STAs connected,  but no the same SSID neighbors */
#define RRM_STA_NO_NEIGHBOR_TRIGGER_TIME        60000	// 60s
#define RRM_STA_NO_NEIGHBOR_INTERVAL_TIME       300	// 300 ms
#define RRM_STA_NO_NEIGHBOR_DWELL_TIME          90	// 90 ms

#define RRM_STOP_OFFCHAN_THRESHOLD              100	// tx + rx 100 ptkcnt

enum nr_chan_width {
	NR_CHAN_WIDTH_20 = 0,
	NR_CHAN_WIDTH_40 = 1,
	NR_CHAN_WIDTH_80 = 2,
	NR_CHAN_WIDTH_160 = 3,
	NR_CHAN_WIDTH_80P80 = 4,
};

enum unassocsta_track_mode {
	UNASSOCSTA_TRACK_MODE_CURRCHAN = 0,
	UNASSOCSTA_TRACK_MODE_OFFCHAN = 1,
	UNASSOCSTA_TRACK_MODE_NUM,
};

typedef struct nlist_bcn_buf_t {
	UINT32 len;
	UINT8 buf[];
} nlist_bcn_buf_t;

typedef struct neighbor_list_entrie_t {
	IEEEtypes_SsId_t SsId;
	UINT8 ssid_len;
	UINT8 not_found_count;
	SINT32 rssi;
	UINT8 bssid[IEEEtypes_ADDRESS_SIZE];
	IEEEtypes_Bssid_info_t bssid_info;
	UINT8 reg_class;
	UINT8 chan;
	UINT8 phy_type;
	SINT32 time_stamp;
	struct IEEEtypes_MOBILITY_DOMAIN_IE_t md_ie;
	UINT8 width;
	UINT16 sta_cnt;
	UINT8 channel_util;	/*channel utilization */
	SINT32 nf;
	UINT8 bw_2g_40_above;	/* 0: default bit(0):above bit(1):below */
	UINT8 encryptType[16];
	UINT8 cipherType[16];
	IEEEtypes_BcnInterval_t BcnInterval;
	UINT8 apType[10];
	nlist_bcn_buf_t *bcn_buf;
} PACK_END neighbor_list_entrie_t;

/* offchannel list, it filled from rrm = 1 or use the cmd "rrm_offchan_time" to set a offchannel list */
typedef struct offchan_node_t {
	BOOLEAN active;
	U32 trigger_time;	/* offchan trigger time(ms) */
	U32 interval_time;	/* offchan interval time(ms) */
	U32 dwell_time;		/* fw offchan time(ms) */
	BOOLEAN repeat;		/* Repeat the list after trigger_time timeout */
	UINT8 offchanlist[IEEE_80211_MAX_NUMBER_OF_CHANNELS];
	UINT8 ch_num;		/* number of channel in list */
	UINT8 ch_idx;		/* current offchan index in list */
} offchan_node_t;

typedef struct offchan_scan_t {
	offchan_status status;	/* OFFCHAN status */
	BOOLEAN init_flag;
	offchan_node_t rrm_offch;	/* for rrm feature */
	offchan_node_t user_offch;	/* for the cmd "rrm_offchan_time" to set a offchannel list */
	offchan_node_t next_offch;	/* next offchannel list, copy from rrm_offch or user_offch */
	UINT32 id;		/* offchannel id of current offcannel scan */
	Timer timer;		/* Provid timer for trigger_time, interval_time and dwell_time */
	BOOLEAN offchan_feature_active[OFFCHAN_FEATURE_END];
	struct completion offchan_complete;	/* wait current offchan scan done */
	BOOLEAN status_abnormal;
} offchan_scan_t;

typedef struct nb_info_t {
	/* Neighbor list */
	UINT32 nb_number;
	neighbor_list_entrie_t nb_list[NB_LIST_MAX_NUM];
	UINT32 nb_elem_number;
	IEEEtypes_Neighbor_Report_Element_t nb_elem[NB_LIST_MAX_NUM];
	UINT8 unassocsta_offchan_channel_number;
	UINT8 unassocsta_offchan_channel_list[UNASSOC_METRICS_CHANNEL_MAX];
	UINT32 unassocsta_offchan_channel;
	UINT32 unassocsta_offchan_id;
	SINT32 sysfs_query_nlist_idx;
} nb_info_t;

extern void MSAN_neighbor_add(struct net_device *netdev, struct neighbor_list_entrie_t *nlist, UINT8 * bcn_buf, UINT32 bcn_len);

extern UINT8 MSAN_get_neighbor_bySSID(struct net_device *netdev, struct IEEEtypes_SsIdElement_t *ssid);
extern UINT8 MSAN_get_neighbor_byDefault(struct net_device *netdev);
extern UINT8 MSAN_get_neighbor_byAddr(struct net_device *netdev, IEEEtypes_MacAddr_t * target_addr);
extern void MSAN_clean_neighbor_list(struct net_device *netdev);
extern void MSAN_clean_nb_list_All(struct net_device *netdev);

extern void MSAN_neighbor_bcnproc(struct net_device *netdev, void *BssData_p, UINT32 len, RssiPathInfo_t * prssiPaths, UINT8 scan_path);
extern void MSAN_update_neighbor_list(struct net_device *netdev);

extern void MSAN_neighbor_dump_list(struct net_device *netdev, UINT8 * ret_str, UINT8 * param1, UINT8 * param2);

extern void OffchannelScanDisable(struct net_device *netdev);
extern void OffchannelScanEnable(struct net_device *netdev);
extern void Restart_MSAN_timer(struct net_device *netdev);
extern void MSAN_rrm_ie(struct net_device *netdev, int enable);
extern UINT32 MSAN_get_channel_util(vmacApInfo_t * vmacSta_p);
#ifdef AUTOCHANNEL
extern void MSAN_get_ACS_db(vmacApInfo_t * vmacSta_p, UINT8 ch_list_num, UINT8 channel, UINT8 NF4rrm);
#endif				/* AUTOCHANNEL */
#endif				//IEEE80211K
#ifdef MULTI_AP_SUPPORT
extern int MSAN_unassocsta_offchan_init(struct net_device *netdev);
extern void MSAN_unassocsta_offchan_scan(struct net_device *netdev);
extern void MSAN_unassocsta_send_event(struct net_device *netdev);
extern void MSAN_unassocsta_offchan_cb(UINT8 * data);
extern void MSAN_unassocsta_offchan_done(struct net_device *netdev, u8 mode);
extern void MSAN_unassocsta_recv_proc(vmacApInfo_t * vmacSta_p, IEEEtypes_Frame_t * wlanMsg_p, UINT32 rssi);
extern void MSAN_update_avg_ptkcnt(struct net_device *netdev);
#endif				/* MULTI_AP_SUPPORT */

extern void offchan_scan_mgt_handler(struct work_struct *work);
extern void OffchannelScanSet(struct net_device *netdev, offchan_node_t * node, BOOLEAN is_rrm);

#endif				/* _MSAN_REPORT_H_ */
