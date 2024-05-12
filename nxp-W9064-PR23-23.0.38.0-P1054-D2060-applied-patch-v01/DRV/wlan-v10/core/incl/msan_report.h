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

#ifdef IEEE80211K

#define SCAN_BY_OFFCHAN     0
#define SCAN_BY_ACS         1

#define RRM_DEFAULT_TRIGGER_TIME	60000	// 60s
#define RRM_DEFAULT_INTERVAL_TIME	300	// 300 ms
#define RRM_DEFAULT_DWELL_TIME		120	// 120 ms

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

extern neighbor_list_entrie_t nlist_entry[];
extern int nlist_number;

extern void MSAN_neighbor_scan(struct net_device *netdev, int enable);
extern void MSAN_neighbor_add(struct net_device *netdev,
			      struct neighbor_list_entrie_t *nlist);

extern UINT8 MSAN_get_neighbor_bySSID(struct IEEEtypes_SsIdElement_t *ssid,
				      struct IEEEtypes_Neighbor_Report_Element_t
				      **nr_list);
extern UINT8 MSAN_get_neighbor_byDefault(struct
					 IEEEtypes_Neighbor_Report_Element_t
					 **nr_list);
extern UINT8 MSAN_get_neighbor_byAddr(IEEEtypes_MacAddr_t * target_addr,
				      struct IEEEtypes_Neighbor_Report_Element_t
				      **nr_list);
extern UINT8 MSAN_get_neighbor_list(struct IEEEtypes_Neighbor_Report_Element_t
				    **nr_list);
extern void MSAN_clean_neighbor_list(void);
extern void MSAN_clean_nb_list_All(void);

extern void MSAN_neighbor_bcnproc(struct net_device *netdev, void *BssData_p,
				  UINT32 len, RssiPathInfo_t * prssiPaths,
				  UINT8 scan_path);
extern void MSAN_update_neighbor_list(struct net_device *netdev);

extern void MSAN_neighbor_dump_list(struct net_device *netdev, UINT8 * ret_str,
				    UINT8 * param1, UINT8 * param2);

extern void Disable_MSAN_timer(struct net_device *netdev);
extern void Enable_MSAN_timer(struct net_device *netdev);

extern void MSAN_rrm_ie(struct net_device *netdev, int enable);
extern UINT32 MSAN_get_channel_util(vmacApInfo_t * vmacSta_p);
#ifdef AUTOCHANNEL
extern void MSAN_get_ACS_db(vmacApInfo_t * vmacSta_p, UINT8 ch_list_num,
			    UINT8 channel);
#endif /* AUTOCHANNEL */
#endif //IEEE80211K
#ifdef MULTI_AP_SUPPORT
extern int MSAN_unassocsta_offchan_init(struct net_device *netdev);
extern void MSAN_unassocsta_offchan_scan(struct net_device *netdev);
extern void MSAN_unassocsta_send_event(struct net_device *netdev);
extern void MSAN_unassocsta_offchan_cb(UINT8 * data);
extern void MSAN_unassocsta_offchan_done(struct net_device *netdev, u8 mode);
extern void MSAN_unassocsta_recv_proc(vmacApInfo_t * vmacSta_p,
				      IEEEtypes_Frame_t * wlanMsg_p,
				      UINT32 rssi);
#endif /* MULTI_AP_SUPPORT */
#endif /* _MSAN_REPORT_H_ */
