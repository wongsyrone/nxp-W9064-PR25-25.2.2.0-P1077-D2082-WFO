/** @file ap8xLnxWls.h
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2018-2020 NXP
  *
  * NXP CONFIDENTIAL
  * The source code contained or described herein and all documents related to
  * the source code ("Materials") are owned by NXP, its
  * suppliers and/or its licensors. Title to the Materials remains with NXP,
  * its suppliers and/or its licensors. The Materials contain
  * trade secrets and proprietary and confidential information of NXP, its
  * suppliers and/or its licensors. The Materials are protected by worldwide copyright
  * and trade secret laws and treaty provisions. No part of the Materials may be
  * used, copied, reproduced, modified, published, uploaded, posted,
  * transmitted, distributed, or disclosed in any way without NXP's prior
  * express written permission.
  *
  * No license under any patent, copyright, trade secret or other intellectual
  * property right is granted to or conferred upon you by disclosure or delivery
  * of the Materials, either expressly, by implication, inducement, estoppel or
  * otherwise. Any license under such intellectual property rights must be
  * express and approved by NXP in writing.
  *
  */
#ifndef AP8X_WLS_H_
#define AP8X_WLS_H_

//#define  BBTX_TMR_TSF           0x14468
#define  BBTX_TMR_TSF      0x14AA0
#define  BBTX_TMR_TSF_SCBT      0x14AA0
#define  BBTX_TMR_TSF_HI_SCBT   0x14AA4

#define FTM_MAX_NEIGH_COUNT 2
#define FTM_RESP_MAX_BUF_SIZE 500
#define FTM_NEIGHBOR_REPORT_MAX_BUF_SIZE 800
#define LENGTH_LOC_CIVIC_UNKNOWN 6
#define DEFAULT_BURST_DURATION 128000
#define FTM_INVALID 0xDEAD
#define WLS_TIMER_PERIOD_IN_US (100)	/* microseconds */
#define US_TO_NS(x)     (x * 1E3L)
#define FTM_INI_SCAN_DURATION 2000000
#define ALLRTT_MAXLENGTH 50
#define MAX_NUM_RANGEREPORT_DEV 50
//#define FLOAT UINT32
typedef UINT32 FLOAT;

#define DOT11_FTM_PARAMETERS_ID  206
/* Public Action Field Values Table 8-293 in standard*/
#define PA_FTM_REQUEST           32
#define PA_FTM                   33

//Table 8-90 - Measurement Type definitions for measurement requests
typedef enum __attribute__ ((__packed__)) {
MEAS_TYPE_BASIC_REQ = 0,
	    MEAS_TYPE_CCA_REQ,
	    MEAS_TYPE_LCI_REQ = 8,
	    MEAS_TYPE_LOC_CIVIC_REQ = 11,
	    MEAS_TYPE_LOC_IDENTIFIER_REQ, MEAS_TYPE_FTM_RANGE = 16, MEAS_TYPE_MEAS_PAUSE = 255} IEEEtypes_MeasurementType_e;

//Figure 8-144 - Measurement Request Mode field
typedef PACK_START struct IEEEtypes_Measurement_Request_Mode_t {
	UINT8 Parallel:1;
	UINT8 Enable:1;
	UINT8 Request:1;
	UINT8 Report:1;
	UINT8 DurMandatory:1;
	UINT8 Reserverd:3;
} PACK_END IEEEtypes_Measurement_Request_Mode_t;

//Figure 8-143 - Measurement Request element format
typedef PACK_START struct IEEEtypes_Measurement_Request_t {
	UINT8 ElemID;
	UINT8 Length;
	UINT8 Token;
	IEEEtypes_Measurement_Request_Mode_t Mode;
	IEEEtypes_MeasurementType_e Type;
} PACK_END IEEEtypes_Measurement_Request_t;

//Table 8-102 - Location Subject field definition
typedef enum __attribute__ ((__packed__)) {
LOC_SUBJECT_LOCAL = 0, LOC_SUBJECT_REMOTE, LOC_SUBJECT_THIRD_PARTY} IEEEtypes_LocationSubject_e;

//Figure 8-162 - Measurement Request field format for LCI request
typedef PACK_START struct IEEEtypes_MeasurementReq_LCIReq_t {
	IEEEtypes_Measurement_Request_t MeasReq;
	IEEEtypes_LocationSubject_e LocationSubject;
} PACK_END IEEEtypes_MeasurementReq_LCIReq_t;

//Figure 8-178 - Measurement Request field format for Location Civic request
typedef PACK_START struct IEEEtypes_MeasurementReq_LocCivicReq_t {
	IEEEtypes_Measurement_Request_t MeasReq;
	IEEEtypes_LocationSubject_e LocationSubject;
	UINT8 Type;
	UINT8 ServiceIntervalUnits;
	UINT16 ServiceInterval;
} PACK_END IEEEtypes_MeasurementReq_LocCivicReq_t;

//Figure 8-188 - Measurement Report Mode field
typedef PACK_START struct IEEEtypes_Measurement_Report_Mode_t {
	UINT8 Late:1;
	UINT8 Incapable:1;
	UINT8 Refused:1;
	UINT8 Reserved:5;
} PACK_END IEEEtypes_Measurement_Report_Mode_t;

//Figure 8-187 - Measurement Report element format
typedef PACK_START struct IEEEtypes_Measurement_Report_t {
	UINT8 ElemID;
	UINT8 Length;
	UINT8 Token;
	IEEEtypes_Measurement_Report_Mode_t Mode;
	IEEEtypes_MeasurementType_e Type;
} PACK_END IEEEtypes_Measurement_Report_t;

//Table 8-124 - Subelement IDs for Location Configuration Information Report
typedef enum __attribute__ ((__packed__)) {
LCI_SUBELEM_LCI = 0,
	    LCI_SUBELEM_AZIMUTH,
	    LCI_SUBELEM_STA_MAC_ADDR,
	    LCI_SUBELEM_TGT_MAC_ADDR,
	    LCI_SUBELEM_Z,
	    LCI_SUBELEM_RELATIVE_LOC_ERROR,
	    LCI_SUBELEM_USAGE_RULES = 6, LCI_SUBELEM_COLOCATED_BSSID, LCI_SUBELEM_VENDOR_SPECIFIC = 255} IEEEtypes_LCIReport_Subelements_e;

//Figure 8-210 LCI subelement format and Figure 8-211 - LCI field format
typedef PACK_START struct IEEEtypes_Measurement_Report_LCI_t {
	IEEEtypes_Measurement_Report_t MeasReport;
	UINT8 SubelemID;
	UINT8 Length;
	UINT8 Latitude[5];
	UINT8 Longitude[5];
	UINT8 Altitude[5];

	UINT8 Datum:3;
	UINT8 RegLocAgreement:1;
	UINT8 RegLocDSE:1;
	UINT8 DependentSTA:1;
	UINT8 Version:2;
} PACK_END IEEEtypes_Measurement_Report_LCI_t;

//Figure 9-223 - Co-Located BSSID List subelement format
typedef PACK_START struct IEEEtypes_Measurement_Report_colocatedBSSID_t {
	UINT8 SubelemID;
	UINT8 Length;

	UINT8 MaxBSSIDindicator;
	// optional list of BSSIDs, added dynamically
	UINT8 colocADDR[FTM_MAX_NEIGH_COUNT][IEEEtypes_ADDRESS_SIZE];
} PACK_END IEEEtypes_Measurement_Report_colocatedBSSID_t;

//Figure 8-214 Z subelement format and Figure 8-215 - STA floor info field format
typedef PACK_START struct IEEEtypes_Measurement_Report_Z_t {
	UINT8 SubelemID;
	UINT8 Length;

	UINT8 STAfloorInfo;
	UINT16 STAfloorInfo_move:2;
	UINT16 STAfloorInfo_floorNumber:14;

	UINT16 STAheightAbovefloor;
	UINT8 STAheightAbovefloor_uncert;
} PACK_END IEEEtypes_Measurement_Report_Z_t;

//Figure 8-214 Z subelement format and Figure 8-215 - STA floor info field format
typedef PACK_START struct IEEEtypes_Measurement_Report_UsageRules_t {
	UINT8 SubelemID;
	UINT8 Length;

	UINT8 params_retrans:1;
	UINT8 params_expiryPresnt:1;
	UINT8 params_LocationPolicy:1;
	UINT8 params_reserved:5;

	//optional field: Retention Expires Relative: 0 or 2 bytes
	UINT16 relative;
} PACK_END IEEEtypes_Measurement_Report_UsageRules_t;

//Table 8-129 - Subelement IDs for Location Civic report
typedef enum __attribute__ ((__packed__)) {
LOC_CIVIC_SUBELEM_LC = 0,
	    LOC_CIVIC_SUBELEM_STA_MAC_ADDR,
	    LOC_CIVIC_SUBELEM_TGT_MAC_ADDR,
	    LOC_CIVIC_SUBELEM_LOC_REF,
	    LOC_CIVIC_SUBELEM_LOC_SHAPE,
	    LOC_CIVIC_SUBELEM_MAP_IMAGE = 5, LOC_CIVIC_SUBELEM_VENDOR_SPECIFIC = 255} IEEEtypes_LocCivicReport_Subelements_e;

typedef struct PACK_START LocationCivic_t {
	char countryCode[2];
	UINT8 CAtype;
	UINT8 CAlength;
} PACK_END LocationCivic_t;

//Figure 8-224 - Location Civic Report field format and Figure 8-225 - Location Civic subelement format
typedef PACK_START struct IEEEtypes_Meas_Report_LocCivic_t {
	IEEEtypes_Measurement_Report_t MeasReport;
	UINT8 Type;
	IEEEtypes_LocCivicReport_Subelements_e SubelemID;
	UINT8 Length;
	LocationCivic_t LocCivicField;
} PACK_END IEEEtypes_Meas_Report_LocCivic_t;

//Table 8-292 - Radio Measurement Action field values
typedef enum __attribute__ ((__packed__)) {
RADIO_MEAS_REQ = 0, RADIO_MEAS_REPORT, LINK_MEAS_REQ, LINK_MEAS_REPORT, NEIGHBOR_REPORT_REQ, NEIGHBOR_REPORT_RESP} IEEEtypes_Radio_Meas_Action_e;

//Table 8-114 - Optional subelement IDs for Fine Timing Measurement Range request
typedef enum __attribute__ ((__packed__)) {
FTMRANGE_SUBELEM_MAXAGE = 4, FTMRANGE_SUBELEM_VENDOR_SPECIFIC = 221} IEEEtypes_FTMRange_Req_Subelem_e;

//Figure 8-186 - Format of Maximum Age subelement
typedef PACK_START struct IEEEtypes_MaxAge_t {
	IEEEtypes_FTMRange_Req_Subelem_e SubElemID;
	UINT8 Length;
	UINT16 MaxAge;
} PACK_END IEEEtypes_MaxAge_t;

//Figure 8-291 - BSSID Information field
typedef PACK_START struct IEEEtypes_BSSID_Info_t {
	UINT16 APReachability:2;
	UINT16 Security:1;
	UINT16 KeyScope:1;
	UINT16 Capabilities:6;
	UINT16 MobDomain:1;
	UINT16 HT:1;
	UINT16 VHT:1;
	UINT16 FTM:1;
	UINT16 Reserved1:2;

	UINT16 Reserved2;
} PACK_END IEEEtypes_BSSID_Info_t;

//Figure 8-290 - Neighbor Report element format
typedef PACK_START struct IEEEtypes_Neighbor_Report_Elem_t {
	UINT8 ElemID;		// = DOT11_NEIGHBOR_ELEMENT_ID
	UINT8 Length;
	UINT8 BSSID[IEEEtypes_ADDRESS_SIZE];
	IEEEtypes_BSSID_Info_t BSSID_Info;
	UINT8 OpClass;
	UINT8 ChanNumber;
	UINT8 PhyType;
} PACK_END IEEEtypes_Neighbor_Report_Elem_t;

//Figure 8-628 - Radio Measurement Request frame Action field format
typedef PACK_START struct IEEEtypes_RadioMeas_Req_t {
	UINT8 Category;
	IEEEtypes_Radio_Meas_Action_e Action;
	UINT8 Token;
	UINT16 Repetitions;
	IEEEtypes_Measurement_Request_t meas;
} PACK_END IEEEtypes_RadioMeas_Req_t;

//Figure 8-185 - Measurement Request field for a Fine Timing Measurement Range
typedef PACK_START struct IEEEtypes_FTMRange_Req_t {
	IEEEtypes_RadioMeas_Req_t radioMeas;
	UINT16 Interval;
	UINT8 minAPcount;
} PACK_END IEEEtypes_FTMRange_Req_t;

//Figure 9-249 - Range Entry field format
typedef PACK_START struct IEEEtypes_FTMRangeEntry_field {
	UINT32 startTime;
	UINT8 BSSID[IEEEtypes_ADDRESS_SIZE];
	UINT8 range[3];
	UINT8 maxRangeErrorExpo;
	UINT8 reserved;
} PACK_END IEEEtypes_FTMRangeEntry_field;

//Table 8-127 - Error Code field values (for FTM range request)
typedef enum __attribute__ ((__packed__)) {
FTMRANGE_REQ_INCAPABLE = 2, FTMRANGE_REQ_FAILED = 3, FTMRANGE_TX_FAILED = 8} IEEEtypes_FTMErrorEntry_ErrorCode_e;

//Figure 8-247 - Error Entry field format
typedef PACK_START struct IEEEtypes_FTMErrorEntry_field {
	UINT32 startTime;
	UINT8 BSSID[IEEEtypes_ADDRESS_SIZE];
	IEEEtypes_FTMErrorEntry_ErrorCode_e errorCode;
} PACK_END IEEEtypes_FTMErrorEntry_field;

//Figure 9-248 - Measurement Report field format for a Fine Timing Measurement Range report
typedef PACK_START struct IEEEtypes_FTMRange_Report_elem {
	UINT8 entryCount;
} PACK_END IEEEtypes_FTMRange_Report_elem;

//Figure 8-639 - Radio Measurement Report frame Action field format and
//Figure 8-185 - Measurement Request field for a Fine Timing Measurement Range
typedef PACK_START struct IEEEtypes_FTMRange_Report_t {
	UINT8 Category;
	IEEEtypes_Radio_Meas_Action_e Action;
	UINT8 Token;
	IEEEtypes_Measurement_Request_t meas;
} PACK_END IEEEtypes_FTMRange_Report_t;

//Figure 8-642 - Neighbor Report Request frame Action field format. pg 1135
//Figure 8-643 - Neighbor Report Response frame Action field format
//mandatory fields of these two frames are same.
typedef PACK_START struct IEEEtypes_Neighbor_Report_ReqResp_t {
	UINT8 Category;
	IEEEtypes_Radio_Meas_Action_e Action;
	UINT8 Token;
	//For req: SSID, LCI req, Loc Civic req are optional and will be added dynamically
	//For resp: Neighbor Report elements will be added dynamically
} PACK_END IEEEtypes_Neighbor_Report_ReqResp_t;

//Figure 9-679 - Fine Timing Measurement Request
typedef PACK_START struct IEEEtypes_FTM_Request_t {
	UINT8 Category;
	UINT8 PublicAction;
	UINT8 Trigger;
} PACK_END IEEEtypes_FTM_Request_t;

//Figure 9-585 - FTM Synchronization Information element format
typedef PACK_START struct IEEEtypes_FTM_SynchInfoElement_t {
	UINT8 eid;
	UINT8 Len;
	UINT8 Extension;
	UINT32 TSF_Synch_Info;
} PACK_END IEEEtypes_FTM_SynchInfoElement_t;

//Figure 9-573 - Fine Timing Measurement Parameters
typedef PACK_START struct IEEEtypes_FTM_Param_t {
	UINT8 Element_ID;

	UINT8 Length;

	UINT8 StatusIndication:2;
	UINT8 Value:5;
	UINT8 Reserved1:1;

	UINT8 BurstExponent:4;
	UINT8 BurstDuration:4;

	UINT8 MinDeltaFTM;

	UINT16 PartialTSF;

	UINT8 pTSF_noPref:1;
	UINT8 ASAPCapable:1;
	UINT8 ASAP:1;
	UINT8 FTMPerBurst:5;

	UINT8 Reserved2:2;
	UINT8 FTMChanSpacing:6;

	UINT16 BurstPeriod;
} PACK_END IEEEtypes_FTM_Param_t;

//Figure 9-680 - Fine Timing Measurement
typedef PACK_START struct IEEEtypes_FTM_t {
	UINT8 Category;
	UINT8 PublicAction;
	UINT8 DialogToken;
	UINT8 FollowUpDialogToken;
	UINT8 TOD[6];
	UINT8 TOA[6];

	UINT16 TODError_exponent:5;
	UINT16 TODError_reserved:10;
	UINT16 TODnotContinuous:1;

	UINT16 TOAError_exponent:5;
	UINT16 TOAError_reserved:11;
} PACK_END IEEEtypes_FTM_t;

typedef struct PACK_START TxFTMBuf {
	IEEEtypes_MgmtHdr2_t Hdr;
	IEEEtypes_FTM_t measurement;
} PACK_END TxFTMBuf;

//Table 8-149 - Optional subelement IDs for neighbor report
typedef enum __attribute__ ((__packed__)) {
NEIGH_REPORT_SUBELEM_WIDE_BW_CHANNEL = 6} IEEEtypes_Neigh_Report_subelem_e;

typedef enum __attribute__ ((__packed__)) {
FTM_SESSION_NOT_STARTED = 0, FTM_SESSION_REQ_RCVD, FTM_SESSION_INIT_COMPLETE, FTM_SESSION_IN_BURST, FTM_SESSION_BURST_COMPLETE} ftm_session_state;

// Type 1 - AP  WLS
// Type 2 - STA WLS
// Type 3 - QUERY WLS Distance
// Type 4 - RM IE configuration
// Type 5 - Start testcase 4.2.6?
// Type 6 - Select Median Distance or Average Distance Reporting
// Type 7 - Enable / Disable PMF
// Type 8 - Set Colo BSSID
typedef enum __attribute__ ((__packed__)) {
	FTM_RESPONDER_SETTINGS = 1, FTM_INITIATOR_SETTINGS, FTM_QUERY_WLS_DISTANCE, RM_IE_SETTINGS = 4, FTM_RESPONDER_START_SETTINGS, FTM_WEP_ON_SETTING = 7, FTM_RESPONDER_COLOCATED_BSSID_SETTINGS, FTM_DEBUG, FTM_MAX_CONFIG	// couldn't exceed 12
} ftm_tlv_type;

typedef struct AoA_Output {
	IEEEtypes_MacAddr_t Addr;
	UINT16 angle;
	UINT32 ftm_rateCode;
} AoA_Output_st;

typedef struct WLS_FTM_CONFIG_st {
	struct net_device *netDev;
	IEEEtypes_MacAddr_t Addr1;
	IEEEtypes_MacAddr_t Addr2;
	ftm_tlv_type ftm_type;
	ftm_session_state session_state;
	UINT32 pgConfig_resp_LCI_known;
	UINT32 pgConfig_resp_Z_known;
	UINT32 pgConfig_resp_civic_known;
	UINT32 pgConfig_resp_civic_known_reduced;
	UINT32 pfConfig_APUT1_phytype;
	UINT32 minAPcount;
	UINT8 neighborADDR[FTM_MAX_NEIGH_COUNT][IEEEtypes_ADDRESS_SIZE];
	UINT8 colocADDR[FTM_MAX_NEIGH_COUNT][IEEEtypes_ADDRESS_SIZE];
	UINT32 pfConfig_neigh_chan[FTM_MAX_NEIGH_COUNT];
	UINT32 pfConfig_neigh_chanWidth[FTM_MAX_NEIGH_COUNT];
	UINT32 pfConfig_neigh_phytype[FTM_MAX_NEIGH_COUNT];
	UINT8 ftm_resp_rangeCmd_rcvd;
	UINT32 pgConfig_resp_colocatedBSSID_known;
	UINT32 ftm_repeated_measurement_capable;
	UINT32 ftm_range_report_capable;
	UINT32 ftm_lci_capable;
	UINT32 ftm_locCivic_capable;
	struct sk_buff *FTM_response_frame;
	IEEEtypes_FTM_Param_t *ftm_response_params;
	UINT8 dialogToken;
	UINT8 LastSuccessDialogToken;
	UINT8 ftm_resp_retryCount;
	UINT8 gPMF_Enabled;
	BOOLEAN isEnabled_minDeltaTimer;
	BOOLEAN isEnabled_resp_burstPeriodTimer;
	UINT32 number_of_bursts_accepted;
	UINT32 FTM_per_burst_completed;
	UINT32 number_of_bursts_completed;
	UINT32 minDeltaTimer;
	UINT32 resp_bkp_minDeltatTimer;
	UINT64 minDeltaTimerStartedAt_tsf;
	volatile UINT32 burstDurationTimer;
	UINT32 resp_burstPeriodTimer;
	UINT32 burstPeriodTimer;
	UINT32 pfconfig_resp_MinDeltaFTM;
	UINT32 pfconfig_resp_ASAPCapable;
	UINT32 pfconfig_resp_ASAP;
	UINT64 resp_iFTMR_tsf;
	UINT64 resp_ptsf_StartedAt_tsf;
	UINT32 burstDuration[16];
	UINT8 ftm_RangeReportCapableDevices[MAX_NUM_RANGEREPORT_DEV][IEEEtypes_ADDRESS_SIZE];
	struct hrtimer wlsTimer;
	ktime_t ktime;
	UINT64 wlsTimerDebug;
	UINT8 wlsFTMDebug;
	BOOLEAN wlsFTM_TriggerCsiEvent;
    /************ Initiator's preferences **************/
	UINT32 pfConfig_ini_BurstExponent;
	UINT32 pfConfig_ini_BurstDuration;
	UINT32 pfConfig_ini_BurstPeriod;
	UINT32 pfConfig_ini_MinDeltaFTM;
	UINT32 pfConfig_ini_ASAPCapable;
	UINT32 pfConfig_ini_ASAP;
	UINT32 pfConfig_ini_FTMPerBurst;
	UINT32 pfConfig_ini_FTMChanSpacing;
	UINT32 initiator_include_locCivic_req;
	UINT32 initiator_include_LCI_req;
	UINT32 pfConfig_ini_ptsfDelta;
	struct sk_buff *FTM_Req_frame;
	IEEEtypes_FTM_Param_t ftm_ini_acceptedParams;
	UINT64 ftm_peerTSF;
	UINT64 ftm_myTSF;
	UINT32 ftm_ini_scanTimer;
	BOOLEAN FTM_command_proc_started;
	BOOLEAN isEnabled_scanTimer;
	BOOLEAN ftm_ini_rangeReport_ongoing;
	BOOLEAN session_success;
	UINT32 session_success_count;
	UINT32 session_fail_count;
	UINT64 burstPeriodTimer_tsf;
	//testcase 4.2.5
	UINT32 pfConfig_APUT1_chan;
	//testcase 4.2.6
	UINT32 FTM_ini_minAPcount;
	UINT32 FTM_ini_currAPcount;
	struct sk_buff *ftm_rangeResp_skb;
	IEEEtypes_FTMRangeEntry_field *ftm_rangeResp_successEntryArray;
	IEEEtypes_FTMErrorEntry_field *ftm_rangeResp_errorEntryArray;
	IEEEtypes_Neighbor_Report_Elem_t *FTM_ini_rangeReport_neighbor;
	UINT8 ftm_ini_origChan;
	IEEEtypes_MacAddr_t ftm_ini_neighReport_aput2;
	UINT64 ftm_peerTSF_bkp;

	UINT32 ftm_rateCode;
	evt_prdcsi_t *prdcsi_data;

	UINT32 SignalBW;
	//UINT32 FTM_Packet_Type;
	UINT64 T1;
	UINT64 T2;
	UINT64 T3;
	UINT64 T4;
	SINT32 CSI_Distance[ALLRTT_MAXLENGTH];
	UINT32 CSI_Distance_ptr;
	SINT16 AoA_Angle[ALLRTT_MAXLENGTH];
	UINT32 AoA_Angle_ptr;

	BOOLEAN Enable_Median;
	UINT32 CSI_Distance_Store[ALLRTT_MAXLENGTH];
	UINT32 CSI_Distance_Store_ptr;
	UINT32 CSI_Distance_Current;
	UINT32 CSI_Distance_Store_Median[ALLRTT_MAXLENGTH];
	UINT32 CSI_Distance_Store_Median_ptr;
	UINT32 CSI_Distance_Current_Median;
	SINT16 AoA_Angle_Store_Median[ALLRTT_MAXLENGTH];
	AoA_Output_st AoA_Output_Data[ALLRTT_MAXLENGTH];
	UINT32 AoA_Angle_Store_Median_ptr;
	SINT16 AoA_Angle_Current_Median;

} WLS_FTM_CONFIG_st;

#endif				/* AP8X_WLS_H_ */
