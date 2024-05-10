/** @file 1905.h
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
 * \file  1905.h
 * \brief
 */

#if !defined(_1905_H_)
#define _1905_H_

#ifdef MULTI_AP_SUPPORT

/* Multi-AP TLV type */
#define MAP_TLV_AP_LM_QUERY				0x93
#define MAP_TLV_AP_LM_RESP				0x94
#define MAP_TLV_STA_MAC_ADDR			0x95
#define MAP_TLV_STA_LM_RESP				0x96
#define MAP_TLV_UNASSOC_STA_LM_QUERY	0x97
#define MAP_TLV_UNASSOC_STA_LM_RESP		0x98
#define MAP_TLV_BEACON_LM_QUERY			0x99
#define MAP_TLV_BEACON_LM_RESP			0x9A
#define MAP_TLV_STA_TRAFFIC_STATS		0xA2
/* Multi-AP TLV type -- END*/

/*
 * IEEE Std 802.11-2016, Table 9-90 - Reporting Detail values
 */
enum beacon_report_detail {
	/* No fixed-length fields or elements */
	BEACON_REPORT_DETAIL_NONE = 0,
	/* All fixed-length fields and any requested elements in the Request
	 * element if present */
	BEACON_REPORT_DETAIL_REQUESTED_ONLY = 1,
	/* All fixed-length fields and elements (default, used when Reporting
	 * Detail subelement is not included in a Beacon request) */
	BEACON_REPORT_DETAIL_ALL_FIELDS_AND_ELEMENTS = 2,
};

typedef struct IEEEtypes_ReportingDetail_t {
	IEEEtypes_ElementId_t ElementId;
	IEEEtypes_Len_t Len;
	UINT8 reporting_detail_value;
	UINT8 variable[];
} PACK_END IEEEtypes_ReportingDetail_t;

typedef struct IEEEtypes_ESP_info_field_t {
#ifdef MV_CPU_LE
	UINT8 ACI:2;
	UINT8 rsvd:1;
	UINT8 DataFormat:2;
	UINT8 BA_WinSize:3;
#else
	UINT8 BA_WinSize:3;
	UINT8 DataFormat:2;
	UINT8 rsvd:1;
	UINT8 ACI:2;
#endif
	UINT8 ES_AirTime;
	UINT8 PPDU_Dur;
} PACK_END IEEEtypes_ESP_info_field_t;

typedef struct MultiAP_TLV_Element_t {
	UINT8 tlvType;
	UINT16 tlvLen;
} PACK_END MultiAP_TLV_Element_t;

/* 17.1.16 AP Metrics Query Message format */
typedef struct MultiAP_AP_LM_Query_Element_t {
	struct MultiAP_TLV_Element_t tlv;
	UINT8 BSSID_num;	/* Number of BSSIDs included in this TLV. (k) */
	IEEEtypes_MacAddr_t bssid[];	/* BSSID of a BSS operated by the MAP device 
					 * for which the metrics are to be reported.
					 * (repeated k-1 times) */
} PACK_END MultiAP_AP_LM_Query_Element_t;

typedef struct MultiAP_AP_LM_Resp_Element_t {
	struct MultiAP_TLV_Element_t tlv;
	IEEEtypes_MacAddr_t bssid;
	UINT8 channel_util;
	UINT16 STA_num;
#ifdef MV_CPU_LE
	UINT8 Reserved:4;
	UINT8 AC_VI:1;
	UINT8 AC_VO:1;
	UINT8 AC_BK:1;
	UINT8 AC_BE:1;
#else
	UINT8 AC_BE:1;
	UINT8 AC_BK:1;
	UINT8 AC_VO:1;
	UINT8 AC_VI:1;
	UINT8 Reserved:4;
#endif
	struct IEEEtypes_ESP_info_field_t AC_EST[];
} PACK_END MultiAP_AP_LM_Resp_Element_t;

/* 17.2.35 Associated STA Traffic Stats TLV */
typedef struct MultiAP_STA_TS_Value_t {
	IEEEtypes_MacAddr_t mac_addr;
	UINT32 BytesSent;
	UINT32 BytesReceived;
	UINT32 PacketsSent;
	UINT32 PacketsReceived;
	UINT32 TxPacketsErrors;
	UINT32 RxPacketsErrors;
	UINT32 RetransmissionCount;
} PACK_END MultiAP_STA_TS_Value_t;

typedef struct MultiAP_STA_TS_Resp_Element_t {
	struct MultiAP_TLV_Element_t tlv;
	struct MultiAP_STA_TS_Value_t value[];
} PACK_END MultiAP_STA_TS_Resp_Element_t;

typedef struct MultiAP_STA_LM_Query_Element_t {
	struct MultiAP_TLV_Element_t tlv;
	IEEEtypes_MacAddr_t mac_addr;	// MAC address of the associated STA.
} PACK_END MultiAP_STA_LM_Query_Element_t;

/* 17.2.24 Associated STA Link Metrics TLV format */
typedef struct MultiAP_STA_LM_Report_t {
	IEEEtypes_MacAddr_t bssid;	// BSSID of the BSS for which the STA is associated.
	UINT32 delta_ms;	/* The time delta in ms between the time at which the earliest 
				   measurement that contributed to the data rate estimates
				   were made, and the time at which this report was sent.
				 */
	UINT32 EST_downlink;	// Estimated MAC Data Rate in downlink (in Mb/s).
	UINT32 EST_uplink;	// Estimated MAC Data Rate in uplink (in Mb/s).
	UINT8 rssi_uplink;	// Measured uplink RSSI for STA (dBm)
} PACK_END MultiAP_STA_LM_Report_t;

typedef struct MultiAP_STA_LM_Value_t {
	IEEEtypes_MacAddr_t mac_addr;	// MAC address of the associated STA.
	UINT8 num_bssid;	// Number of BSSIDs reported for this STA.
	struct MultiAP_STA_LM_Report_t report[];
} PACK_END MultiAP_STA_LM_Value_t;

typedef struct MultiAP_STA_LM_Resp_Element_t {
	struct MultiAP_TLV_Element_t tlv;
	struct MultiAP_STA_LM_Value_t value[];
} PACK_END MultiAP_STA_LM_Resp_Element_t;

typedef struct MultiAP_Unassociated_STA_LM_Query_Element_t {
	struct MultiAP_TLV_Element_t tlv;
	UINT8 op_class;		// operating class
	UINT8 channel_num;	// Number of channels specified in the Channel List.
	UINT8 variable[];	// Channel List, Number of STA MAC addresses included in this TLV.
} PACK_END MultiAP_Unassociated_STA_LM_Query_Element_t;

typedef struct MultiAP_Unassociated_STA_LM_Report_t {
	IEEEtypes_MacAddr_t mac_addr;	// MAC addr of STA for which UL RSSI is being reported.
	UINT8 channel;		// A single channel number in Operating Class on which the RSSI measurement for STA was made.
	UINT32 delta_ms;	/* The time delta in ms between the time at which the RSSI
				   for STA was measured, and the time at which this report was sent.
				 */
	UINT8 rssi_uplink;	// Measured uplink RSSI for STA in dBm.
} PACK_END MultiAP_Unassociated_STA_LM_Report_t;

typedef struct MultiAP_Unassociated_STA_LM_Resp_Element_t {
	struct MultiAP_TLV_Element_t tlv;
	UINT8 op_class;		// operating class
	UINT8 STA_num;		// The number of STA entries included in this TLV.
	struct MultiAP_Unassociated_STA_LM_Report_t report[];
} PACK_END MultiAP_Unassociated_STA_LM_Resp_Element_t;

typedef struct MultiAP_Beacon_LM_Query_Element_t {
	struct MultiAP_TLV_Element_t tlv;
	IEEEtypes_MacAddr_t mac_addr;	// MAC address of the associated STA for which the Beacon report information is requested.
	UINT8 op_class;		// Operating Class field to be specified in the Beacon request.
	UINT8 channel_num;	// Channel Number field to be specified in the Beacon request.
	IEEEtypes_MacAddr_t bssid;	// BSSID field to be specified in the Beacon request.
	UINT8 report_detail;	// Reporting Detail value to be specified in the Beacon request.
	UINT8 variable[];	// SSID length / SSID / AP Channel Reports / Reporting Detail report...etc.
} PACK_END MultiAP_Beacon_LM_Query_Element_t;

typedef struct MultiAP_Beacon_LM_Resp_Element_t {
	struct MultiAP_TLV_Element_t tlv;
	IEEEtypes_MacAddr_t mac_addr;	// MAC address of the associated STA for which the Beacon report information is requested.
#ifdef MV_CPU_LE
	UINT8 Reserved:6;
	UINT8 status:2;
#else
	UINT8 status:2;
	UINT8 Reserved:6;
#endif
	UINT8 element_num;	// Number of measurement report elements included in this TLV.
	UINT8 variable[];	// Contains a Measurement Report element.
} PACK_END MultiAP_Beacon_LM_Resp_Element_t;

typedef struct cac_channel_scan_list {
	UINT8 op_class;
	UINT8 channel;
	SINT32 timestamp;	// timestamp for CAC was completed.
} PACK_END cac_channel_scan_list_t;

typedef struct cac_complete_indication {
	UINT8 dev_name[IFNAMSIZ];	//wdev0 or wdev1
	UINT8 op_class;
	UINT8 channel;
	UINT8 status;		//  0: Successful
	//  1: Radar detected
	//  2: CAC not supported as requested (capability mismatch)
	//  3: Radio too busy to perform CAC
	//  4: Request was considered to be non-conformant to regulations in the country in which the Multi-AP Agent is operating
	//  5: Other error
	//  6: CAC On-Going
	//  >6: Reserved
} PACK_END cac_complete_indication_t;

typedef struct cac_available_channel {
	UINT8 op_class;
	UINT8 channel;
	UINT16 minutes;		// Minutes since CAC was completed identifying Available Channel. Set to zero for non-DFS channels.
} PACK_END cac_available_channel_t;

typedef struct cac_radar_channel {
	UINT8 op_class;		// suggest 20 MHz bandwidth  operation class(i.e. 115,118,121,124,125)
	UINT8 channel;
	UINT16 seconds;		//Seconds remaining in the non-occupancy duration for the channel specified by the class/channel pair.
} PACK_END cac_radar_channel_t;

typedef struct cac_ongoing_channel {
	UINT8 op_class;
	UINT8 channel;
	UINT16 seconds;		// Seconds remaining to complete the CAC.
} PACK_END cac_ongoing_channel_t;	// when driver receive  "csc_start" command, it set this structure as current ongoing channel, after finish the CAC channel scan, set all "0".

typedef struct cac_available_channel_report {
	UINT8 num_of_available_channel;
	cac_available_channel_t available_channel_info[30];
} PACK_END cac_available_channel_report_t;

typedef struct cac_radar_channel_report {
	UINT8 num_of_radar_channel;
	cac_radar_channel_t radar_channel_info[30];
} PACK_END cac_radar_channel_report_t;

typedef struct cac_ongoing_channel_report {
	UINT8 num_of_ongoing_channel;
	cac_ongoing_channel_t ongoing_channel_info[10];
} PACK_END cac_ongoing_channel_report_t;

typedef struct cac_status {
	cac_available_channel_report_t available_channel_report;
	cac_radar_channel_report_t radar_channel_report;
	cac_ongoing_channel_report_t ongoing_channel_report;
} PACK_END cac_status_t;

extern void MAP_tlv_Query_process(vmacApInfo_t * vmacSta_p,
				  MultiAP_TLV_Element_t * map_tlv);
extern void MAP_tlv_Resp_process(vmacApInfo_t * vmacSta_p, void *msg_data,
				 IEEEtypes_MacAddr_t * sta_mac_addr_p,
				 UINT8 status);

extern SINT32 EM_get_cac_status(UINT8 * buf, UINT8 log);
extern void EM_CAC_Scan(vmacApInfo_t * vmacSta_p, UINT8 op_class, UINT8 ch,
			UINT8 enable);

#endif /* MULTI_AP_SUPPORT */

#endif /* _1905_H_ */
