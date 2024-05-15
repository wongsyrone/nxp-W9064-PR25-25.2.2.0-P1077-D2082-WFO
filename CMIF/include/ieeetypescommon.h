/** @file ieeetypescommon.h
 *
 * @brief This file contains WLAN driver specific defines etc.
 *
 * Copyright 2001-2020 NXP
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

/*****************************************************************************
 *
 * Purpose:
 *    This file contains definitions relating to messages specified in the
 *    IEEE 802.11 spec.
 *
 *****************************************************************************/

#ifndef _IEEETYPESCOMMON_H_
#define _IEEETYPESCOMMON_H_

#define AP_MODE_B_ONLY BIT(0)
#define AP_MODE_G_ONLY BIT(1)
#define AP_MODE_N_ONLY BIT(2)
#define AP_MODE_A_ONLY BIT(3)
#define AP_MODE_11AC BIT(4)
#define AP_MODE_11AX BIT(5)
#define AP_MODE_4_9G_5G_PUBLIC_SAFETY BIT(6) // Mode for 4.9G / 5G Japan Channels and Public Safety (bit 6)  CL38509

#define AP_MODE_MIXED (AP_MODE_G_ONLY | AP_MODE_B_ONLY)												// 0x03
#define AP_MODE_BandN (AP_MODE_N_ONLY | AP_MODE_B_ONLY)												// 0x05
#define AP_MODE_GandN (AP_MODE_N_ONLY | AP_MODE_G_ONLY)												// 0x06
#define AP_MODE_BandGandN (AP_MODE_N_ONLY | AP_MODE_G_ONLY | AP_MODE_B_ONLY)						// 0x07
#define AP_MODE_AandG (AP_MODE_A_ONLY | AP_MODE_G_ONLY)												// 0x0a
#define AP_MODE_AandN (AP_MODE_A_ONLY | AP_MODE_N_ONLY)												// 0x0c
#define AP_MODE_2_4GHZ_11AC_MIXED (AP_MODE_11AC | AP_MODE_N_ONLY | AP_MODE_G_ONLY | AP_MODE_B_ONLY) // 0x17
#define AP_MODE_5GHZ_11AC_ONLY (AP_MODE_11AC | AP_MODE_A_ONLY)										// 0x18
#define AP_MODE_5GHZ_Nand11AC (AP_MODE_11AC | AP_MODE_N_ONLY | AP_MODE_A_ONLY)						// 0x1c

#define AP_MODE_2_4GHZ_Nand11AX (AP_MODE_11AX | AP_MODE_N_ONLY | AP_MODE_G_ONLY | AP_MODE_B_ONLY) // 0x27
#define AP_MODE_5GHZ_11AX_ONLY (AP_MODE_11AX | AP_MODE_A_ONLY)									  // 0x28
#define AP_MODE_5GHZ_ACand11AX (AP_MODE_11AX | AP_MODE_11AC | AP_MODE_A_ONLY)					  // 0x38
#define AP_MODE_2_4GHZ_11AX_MIXED (AP_MODE_11AX | AP_MODE_2_4GHZ_11AC_MIXED)					  // 0x37
#define AP_MODE_5GHZ_NandACand11AX (AP_MODE_5GHZ_ACand11AX | AP_MODE_N_ONLY | AP_MODE_A_ONLY)	  // 0x3c

/*--------------------------------------------*/
/* Various sizes used in IEEE 802.11 messages */
/*--------------------------------------------*/
#define IEEE80211_ADDR_LEN 6
#define MAX_NR_IE 20
#define IEEEtypes_ADDRESS_SIZE 6
#define IEEEtypes_BITMAP_SIZE 251
#define IEEEtypes_CHALLENGE_TEXT_SIZE 253
#define IEEEtypes_CHALLENGE_TEXT_LEN 128
#define IEEEtypes_MAX_DATA_RATES 8
#define IEEEtypes_MAX_DATA_BODY_LEN 2312
#define IEEEtypes_MAX_MGMT_BODY_LEN 2312
#define IEEEtypes_SSID_SIZE 32
#define IEEEtypes_TIME_STAMP_SIZE 8
#if defined(SOC_W906X) || defined(SOC_W9068)
#define IEEE_80211_MAX_NUMBER_OF_CHANNELS 64
#else
#define IEEE_80211_MAX_NUMBER_OF_CHANNELS 100
#endif /* #if defined(SOC_W906X) || defined(SOC_W9068) */
#define IEEEtypes_MAX_CHANNELS 14
#define IEEEtypes_MAX_CHANNELS_A IEEE_80211_MAX_NUMBER_OF_CHANNELS - IEEEtypes_MAX_CHANNELS // 19
#define IEEEtypes_MAX_BSS_DESCRIPTS 128
#define W81_80211_HEADER_SIZE 32
#define IEEEtypes_MAX_DATA_RATES_G 14
#define IEEEtypes_MAX_DATA_RATES_A 9

#define HAL_MAX_SUPPORTED_MCS 32
#define RATE_SUPPORTED_11AC_RATES 20 // Value must be in sync with fw 11nrateadapt.h too

#define RATE_ADAPT_MAX_SUPPORTED_RATES \
	(IEEEtypes_MAX_DATA_RATES_G + HAL_MAX_SUPPORTED_MCS + RATE_SUPPORTED_11AC_RATES)

// can support upto 8 per 11ax spec., we shrink to 2 for fw memory reduction
#define ITWT_AGREEMENT_PER_STA 2 // 8

/*---------------------------------------------------------------------*/
/* Define masks used to extract fields from the capability information */
/* structure in a beacon message.                                      */
/*---------------------------------------------------------------------*/
#define IEEEtypes_CAP_INFO_ESS 1
#define IEEEtypes_CAP_INFO_IBSS 2
#define IEEEtypes_CAP_INFO_CF_POLLABLE 4
#define IEEEtypes_CAP_INFO_CF_POLL_RQST 8
#define IEEEtypes_CAP_INFO_PRIVACY 16
#define IEEEtypes_CAP_INFO_SHORT_PREAMB 32
#define IEEEtypes_CAP_INFO_PBCC 64
#define IEEEtypes_CAP_INFO_CHANGE_AGILITY 128
#define IEEEtypes_CAP_INFO_SPECTRUM_MGMT 0x0100
#define IEEEtypes_CAP_INFO_SHORT_SLOT_TIME 0x0400
#define IEEEtypes_CAP_INFO_RRM 0x1000
#define IEEEtypes_CAP_INFO_DSSS_OFDM 0x2000

/*---------------------------*/
/* Miscellaneous definitions */
/*---------------------------*/
#define IEEEtypes_PROTOCOL_VERSION 0

#define IEEEtypes_BASIC_RATE_FLAG 0x80
/* */
/* Used to determine which rates in a list are designated as basic rates */
/* */

#define IEEEtypes_BASIC_RATE_MASK 0x7F
/* */
/* Used to mask off the basic rate flag, if one exists, for given */
/* data rates */
/* */

#define IEEEtypes_RATE_MIN 2
/* */
/* The minimum allowable data rate in units of kb/s */
/* */

#define IEEEtypes_RATE_MAX 127
/* */
/* The maximum allowable data rate in units of kb/s */
/* */

#define IEEEtypes_TIME_UNIT 1024

#define IS_GROUP(macaddr) ((*(u8 *)macaddr & 0x01) == 0x01)

/* */
/* The number of microseconds in 1 time unit, as specified in the */
/* 802.11 spec */
/* */
#define WSC_BEACON_IE_MAX_LENGTH 96 /* 21Dec06 changed from 28 to 68 per customer request */
#define WSC_PROBERESP_IE_MAX_LENGTH 251
#define WSC_OUI_LENGTH 4

enum wsc_attribute
{
	WSC_VERSION_ATTRB = 0x104A,
	WSC_RESP_TYPE_ATTRB = 0x103B,
	WSC_VENDOR_EXTN_ATTRB = 0x1049,
};

#define WSC_VENDOR_ID 0x00372A;

#if defined(SOC_W906X) || defined(SOC_W9068)
#define MAX_BEACON_SIZE 600
#else
#define MAX_BEACON_SIZE 1024
#endif /* #if defined(SOC_W906X) || defined(SOC_W9068) */

/*============================================================================= */
/*                          PUBLIC TYPE DEFINITIONS */
/*============================================================================= */

/*---------------------------------------------------------------------------*/
/*                 Enumerated types used in 802.11 messages                  */
/*---------------------------------------------------------------------------*/
typedef enum
{
	IEEE_TYPE_MANAGEMENT = 0,
	IEEE_TYPE_CONTROL,
	IEEE_TYPE_DATA
} IEEEtypes_MsgType_e;
typedef u8 IEEEtypes_MsgType_t;
/* */
/* The 3 possible types of 802.11 messages */
/* */

typedef enum
{
	IEEE_MSG_ASSOCIATE_RQST = 0,
	IEEE_MSG_ASSOCIATE_RSP,
	IEEE_MSG_REASSOCIATE_RQST,
	IEEE_MSG_REASSOCIATE_RSP,
	IEEE_MSG_PROBE_RQST,
	IEEE_MSG_PROBE_RSP,
	IEEE_MSG_BEACON = 8,
	IEEE_MSG_ATIM,
	IEEE_MSG_DISASSOCIATE,
	IEEE_MSG_AUTHENTICATE,
	IEEE_MSG_DEAUTHENTICATE,
	IEEE_MSG_QOS_ACTION,
	IEEE_MSG_ACTION = 0x0d,
	IEEE_MSG_ACTION_NO_ACK = 0x0e
} IEEEtypes_MgmtSubType_e;
typedef u8 IEEEtypes_MgmtSubType_t;
/* */
/* The possible types of management messages */
/* */

typedef enum
{
	CTRL_TRIGGER = 2,
	BLK_ACK_REQ = 8,
	BLK_ACK,
	PS_POLL = 10,
	RTS,
	CTS,
	ACK,
	CF_END,
	CF_END_CF_ACK
} IEEEtypes_CtlSubType_e;
typedef u8 IEEEtypes_CtlSubType_t;
/* */
/* The possible types of control messages */
/* */

typedef enum
{
	DATA = 0,
	DATA_CF_ACK,
	DATA_CF_POLL,
	DATA_CF_ACK_CF_POLL,
	NULL_DATA,
	CF_ACK,
	CF_POLL,
	CF_ACK_CF_POLL,
	QoS_DATA = 8,
	QoS_DATA_CF_ACK,
	QoS_DATA_CF_POLL,
	QoS_DATA_CF_ACK_CF_POLL,
	QoS_NULL_DATA,
	QoS_CF_ACK,
	QoS_CF_POLL,
	QoS_CF_ACK_CF_POLL
} IEEEtypes_DataSubType_e;
typedef u8 IEEEtypes_DataSubType_t;
/* */
/* The possible types of data messages */
/* */

typedef enum
{
	SME_CMD_ASSOCIATE,
	SME_CMD_AUTHENTICATE,
	SME_CMD_DEAUTHENTICATE,
	SME_CMD_DISASSOCIATE,
	SME_CMD_JOIN,
	SME_CMD_REASSOCIATE,
	SME_CMD_RESET,
	SME_CMD_SCAN,
	SME_CMD_START,
	SME_CMD_MREQUEST,
	SME_CMD_MEASURE,
	SME_CMD_MREPORT,
	SME_CMD_TPCADPT,
	SMC_CMD_CHANNELSWITCH_REQ,
	SMC_CMD_CHANNELSWITCH_RSP
} IEEEtypes_SmeCmd_e;
typedef u8 IEEEtypes_SmeCmd_t;
/* */
/* The possible types of commands sent from the SME */
/* */

typedef enum
{
	SME_NOTIFY_PWR_MGMT_CFRM,
	SME_NOTIFY_SCAN_CFRM,
	SME_NOTIFY_JOIN_CFRM,
	SME_NOTIFY_AUTH_CFRM,
	SME_NOTIFY_AUTH_IND,
	SME_NOTIFY_DEAUTH_CFRM,
	SME_NOTIFY_DEAUTH_IND,
	SME_NOTIFY_ASSOC_CFRM,
	SME_NOTIFY_ASSOC_IND,
	SME_NOTIFY_REASSOC_CFRM,
	SME_NOTIFY_REASSOC_IND,
	SME_NOTIFY_DISASSOC_CFRM,
	SME_NOTIFY_DISASSOC_IND,
	SME_NOTIFY_RESET_CFRM,
	SME_NOTIFY_CHANNELSWITCH_CFRM,
	SME_NOTIFY_RADAR_DETECTION_IND,
	SME_NOTIFY_START_CFRM,
	SME_NOTIFY_MREQUEST_IND,
	SME_NOTIFY_MREQUEST_CFRM,
	SME_NOTIFY_MEASURE_CFRM,
	SME_NOTIFY_MREPORT_IND,
	SME_NOTIFY_MREPORT_CFRM,
	SME_NOTIFY_TPCADPT_CFRM,
	SMC_NOTIFY_CHANNELSWITCH_IND,
	SMC_NOTIFY_CHANNELSWITCH_CFRM
} IEEEtypes_SmeNotify_e;
typedef u8 IEEEtypes_SmeNotify_t;
/* */
/* The possible types of notifications sent from the SME */
/* */

/* */
/* The possible types of commands sent from the CB Processor */
/* */

typedef enum
{
	BSS_INFRASTRUCTURE = 1,
	BSS_INDEPENDENT,
	BSS_ANY
} IEEEtypes_Bss_e;
typedef u8 IEEEtypes_Bss_t;
/* */
/* The possible types of Basic Service Sets */
/* */

typedef enum
{
	SSID = 0,
	SUPPORTED_RATES,
	FH_PARAM_SET,
	DS_PARAM_SET,
	CF_PARAM_SET,
	TIM,
	IBSS_PARAM_SET,
	COUNTRY,
	QBSS_LOAD = 11,
	EDCA_PARAM_SET = 12,
	TSPEC = 13,
	TCLAS = 14,
	SCHEDULE = 15,
	CHALLENGE_TEXT = 16,
	PWR_CONSTRAINT = 32,
	PWR_CAP = 33,
	TPC_REQ = 34,
	TPC_REP = 35,
	SUPPORTED_CHANNEL = 36,
	CSA = 37,
	MEASUREMENT_REQ = 38,
	MEASUREMENT_REP = 39,
	QUIET = 40,
	IBSS_DFS = 41,
	ERP_INFO = 42,
	TS_DELAY = 43,
	TCLAS_PROCESSING = 44,
	HT = 45 /*51 */,
	QOS_ACTION = 45,
	QOS_CAPABILITY = 46,
	RSN_IEWPA2 = 48,
	EXT_SUPPORTED_RATES = 50,
	/* PROPRIETARY tags for HT and ADD_HT. */
	HT_PROP = 51,
	CHAN_REPORT = 51,
	ADD_HT_PROP = 52,
	NEIGHBOR_REPORT = 52,
	RCPI = 53,
	MD_IE = 54,
	FT_IE = 55,
	ADD_HT = 61 /* 52 */,
	SEC_CHAN_OFFSET = 62,
	WAPI_IE = 68,
	RRM_CAP_IE = 70,
	MULTI_BSSID = 71,
	_20_40_BSSCOEXIST = 72,
	_20_40_BSS_INTOLERANT_CHANNEL_REPORT = 73,
	OVERLAPPING_BSS_SCAN_PARAMETERS = 74,
	MM_IE = 76,
	NONTX_BSSID_CAP = 83,
	MBSSID_INDEX = 85,
	EXT_CAP_IE = 127,
	VHT_CAP = 191,
	VHT_OPERATION = 192,
	EXT_BSS_LOAD = 193,
	WIDE_BW_CHAN_SWITCH = 194,
	VHT_TRANSMIT_POW_ENV = 195,
	CHAN_SWITCH_WRAPPER = 196,
	AID = 197,
	QUIET_CHANNEL = 198,
	OP_MODE_NOTIFICATION = 199,
	TWT_IE = 216,
	PROPRIETARY_IE = 221,
	RSN_IE = 221,
	EXTENSION = 255,
	EXT_IE = 255
} IEEEtypes_ElementId_e;
typedef u8 IEEEtypes_ElementId_t;

typedef enum
{
	HE_CAPABILITIES_IE = 35,
	HE_OPERATION_IE = 36,
	UORA_PARAMETERS = 37,
	MU_EDCA_PARAMETERS = 38,
	SPATIAL_REUSE_PARAMETERS = 39,
	NDP_FEEDBACK_REPORT_PARAMETERS = 40,
	BSS_COLOR_CHANGE_ANNOUNCEMENT = 41,
	QUIET_TIME_SETUP_PARAMETERS = 42
} IEEEtypes_ElementIdExt_e;

typedef u8 IEEEtypes_ElementIdExt_t;

/* */
/* Variable length mandatory fields or optional frame body components */
/* within management messages are called information elements; these */
/* elements all have associated with them an Element ID. IDs 7 to 15 */
/* are reserved; IDs 17 to 31 are reserved for challenge text; IDs */
/* 32 to 255 are reserved. */
/* */
/* The KDE data types */

typedef enum
{
	KDE_DATA_TYPE_RESERVED,
	KDE_DATA_TYPE_GTK = 1,
	KDE_DATA_TYPE_RESERVED2,
	KDE_DATA_TYPE_MACADDR = 3,
	KDE_DATA_TYPE_PMKID = 4,
	KDE_DATA_TYPE_SMK = 5,
	KDE_DATA_TYPE_NONCE = 6,
	KDE_DATA_TYPE_LIFETIME = 7,
	KDE_DATA_TYPE_ERROR = 8,
	KDE_DATA_TYPE_IGTK = 9
} IEEEtypes_KDEDataType_e;

typedef enum
{
	PWR_MODE_ACTIVE = 1,
	PWR_MODE_PWR_SAVE
} IEEEtypes_PwrMgmtMode_e;
typedef u8 IEEEtypes_PwrMgmtMode_t;
/* */
/* The possible power management modes */
/* */

typedef enum
{
	SCAN_ACTIVE,
	SCAN_PASSIVE
} IEEEtypes_Scan_e;
typedef u8 IEEEtypes_Scan_t;
/* */
/* The possible methods to scan for APs */
/* */

typedef enum
{
	AUTH_OPEN_SYSTEM = 0,
	AUTH_SHARED_KEY,
	AUTH_OPEN_OR_SHARED_KEY,
	AUTH_SAE,
	AUTH_NOT_SUPPORTED
} IEEEtypes_AuthType_e;
typedef u8 IEEEtypes_AuthType_t;
/* */
/* The possible types of authentication */
/* */

typedef enum
{
	SCAN_RESULT_SUCCESS,
	SCAN_RESULT_INVALID_PARAMETERS,
	SCAN_RESULT_UNEXPECTED_ERROR
} IEEEtypes_ScanResult_e;
typedef u8 IEEEtypes_ScanResult_t;
/* */
/* The possible responses to a request to scan */
/* */

typedef enum
{
	JOIN_RESULT_SUCCESS,
	JOIN_RESULT_INVALID_PARAMETERS,
	JOIN_RESULT_TIMEOUT
} IEEEtypes_JoinResult_e;
typedef u8 IEEEtypes_JoinResult_t;
/* */
/* The possible responses to a request to join a BSS */
/* */

typedef enum
{
	AUTH_RESULT_SUCCESS,
	AUTH_RESULT_INVALID_PARAMETERS,
	AUTH_RESULT_TIMEOUT,
	AUTH_RESULT_TOO_MANY_SIMULTANEOUS_RQSTS,
	AUTH_RESULT_REFUSED,
	AUTH_RESULT_RESOURCE_ERROR
} IEEEtypes_AuthResult_e;
typedef u8 IEEEtypes_AuthResult_t;
/* */
/* The possible results to a request to authenticate */
/* */

typedef enum
{
	DEAUTH_RESULT_SUCCESS,
	DEAUTH_RESULT_INVALID_PARAMETERS,
	DEAUTH_RESULT_TOO_MANY_SIMULTANEOUS_RQSTS
} IEEEtypes_DeauthResult_e;
typedef u8 IEEEtypes_DeauthResult_t;
/* */
/* The possible results to a request to deauthenticate */
/* */

typedef enum
{
	ASSOC_RESULT_SUCCESS,
	ASSOC_RESULT_INVALID_PARAMETERS,
	ASSOC_RESULT_TIMEOUT,
	ASSOC_RESULT_REFUSED,
	ASSOC_RESULT_RETURN_LATER,
	ADDTS_RESULT_REFUSED
} IEEEtypes_AssocResult_e;
typedef u8 IEEEtypes_AssocResult_t;
/* */
/* The possible results to a request to associate */
/* */

typedef enum
{
	REASSOC_RESULT_SUCCESS,
	REASSOC_RESULT_INVALID_PARAMETERS,
	REASSOC_RESULT_TIMEOUT,
	REASSOC_RESULT_REFUSED
} IEEEtypes_ReassocResult_e;
typedef u8 IEEEtypes_ReassocResult_t;
/* */
/* The possible results to a request to reassociate */
/* */

typedef enum
{
	DISASSOC_RESULT_SUCCESS,
	DISASSOC_RESULT_INVALID_PARAMETERS,
	DISASSOC_RESULT_TIMEOUT,
	DISASSOC_RESULT_REFUSED
} IEEEtypes_DisassocResult_e;
typedef u8 IEEEtypes_DisassocResult_t;
/* */
/* The possible results to a request to disassociate */
/* */

typedef enum
{
	PWR_MGMT_RESULT_SUCCESS,
	PWR_MGMT_RESULT_INVALID_PARAMETERS,
	PWR_MGMT_RESULT_NOT_SUPPORTED
} IEEEtypes_PwrMgmtResult_e;
typedef u8 IEEEtypes_PwrMgmtResult_t;
/* */
/* The possible results to a request to change the power management mode */
/* */

typedef enum
{
	RESET_RESULT_SUCCESS
} IEEEtypes_ResetResult_e;
typedef u8 IEEEtypes_ResetResult_t;
/* */
/* The possible results to a request to reset */
/* */

typedef enum
{
	START_RESULT_SUCCESS,
	START_RESULT_INVALID_PARAMETERS,
	START_RESULT_BSS_ALREADY_STARTED_OR_JOINED
} IEEEtypes_StartResult_e;
typedef u8 IEEEtypes_StartResult_t;
/* */
/* The possible results to a request to start */
/* */

typedef enum
{
	MREQUEST_RESULT_SUCCESS,
	MREQUEST_RESULT_INVALID_PARAMETERS,
	MREQUEST_RESULT_UNSPECIFIED_FAILURE
} IEEEtypes_MRequestResult_e;
typedef u8 IEEEtypes_MRequestResult_t;

typedef enum
{
	MEASURE_RESULT_SUCCESS,
	MEASURE_RESULT_INVALID_PARAMETERS,
	MEASURE_RESULT_UNSPECIFIED_FAILURE
} IEEEtypes_MeasureResult_e;
typedef u8 IEEEtypes_MeasureResult_t;

typedef enum
{
	MREPORT_RESULT_SUCCESS,
	MREPORT_RESULT_INVALID_PARAMETERS,
	MREPORT_RESULT_UNSPECIFIED_FAILUR
} IEEEtypes_MReportResult_e;
typedef u8 IEEEtypes_MReportResult_t;

typedef enum
{
	CHANNELSWITCH_RESULT_SUCCESS,
	CHANNELSWITCH_INVALID_PARAMETERS,
	CHANNELSWITCH_UNSPECIFIED_FAILURE
} IEEEtypes_ChannelSwitchResult_e;
typedef u8 IEEEtypes_ChannelSwitchResult_t;

typedef enum
{
	TPCADAPT_RESULT_SUCCESS,
	TPCADAPT_INVALID_PARAMETERS,
	TPCADAPT_UNSPECIFID_FAILURE
} IEEEtypes_TPCAdaptResult_e;
typedef u8 IEEEtypes_TPCAdaptResult_t;

typedef enum
{
	STATE_IDLE,
	STATE_SCANNING,
	STATE_JOINING,
	STATE_JOINED,
	STATE_AUTHENTICATED_WITH_AP,
	STATE_ASSOCIATING,
	STATE_ASSOCIATED,
	STATE_REASSOCIATING,
	STATE_RESTORING_FROM_SCAN,
	STATE_IBSS_STARTED,
} IEEEtypes_MacMgmtStates_e;
typedef u8 IEEEtypes_MacMgmtStates_t;

/* */
/* The possible states the MAC Management Service Task can be in */
/* */

typedef enum
{
	TYPE_REQ_BASIC = 0,
	TYPE_REQ_CCA,
	TYPE_REQ_RPI,
	TYPE_REQ_BCN = 5,
	TYPE_REQ_APS = 10,
	TYPE_REQ_RSS,
	TYPE_REQ_NOI,
	TYPE_REQ_FCS,
	TYPE_REQ_DFS,
	TYPE_REQ_PSE,
	TYPE_REQ_VRX,
} IEEEtypes_MeasurementReqType_e;
typedef u8 IEEEtypes_MeasurementReqType_t;

typedef enum
{
	TYPE_REP_BASIC = 0,
	TYPE_REP_CCA,
	TYPE_REP_RPI,
	TYPE_REP_CHL,
	TYPE_REP_NH,
	TYPE_REP_BCN,
	TYPE_REP_APS = 10,
	TYPE_REP_RSS,
	TYPE_REP_NOI,
	TYPE_REP_FCS,
	TYPE_REP_DFS,
	TYPE_REP_PSE,
	TYPE_REP_VRX,
} IEEEtypes_MeasurementRepType_e;
typedef u8 IEEEtypes_MeasurementRepType_t;

enum
{
	CONTROL_ID_UMRS = 0,
	CONTROL_ID_OM,
	CONTROL_ID_HLA,
	CONTROL_ID_BSR,
	CONTROL_ID_UPH,
	CONTROL_ID_BQR,
	CONTROL_ID_CAS
};

/*---------------------------------------------------------------------------*/
/*           Types Used In IEEE 802.11 MAC Message Data Structures           */
/*---------------------------------------------------------------------------*/
typedef u8 IEEEtypes_Len_t;
/* */
/* Length type */
/* */
typedef u8 IEEEtypes_Addr_t;
/* */
/* Address type */
/* */
typedef IEEEtypes_Addr_t IEEEtypes_MacAddr_t[IEEEtypes_ADDRESS_SIZE];
/* */
/* MAC address type */
/* */
typedef u8 IEEEtypes_DataRate_t;
/* */
/* Type used to specify the supported data rates */
/* */
typedef u8 IEEEtypes_SsId_t[IEEEtypes_SSID_SIZE];
/* */
/* SS ID type */
/* */

/*---------------------------------------------------------------------------*/
/*                 IEEE 802.11 MAC Message Data Structures                   */
/*                                                                           */
/* Each IEEE 802.11 MAC message includes a MAC header, a frame body (which   */
/* can be empty), and a frame check sequence field. This section gives the   */
/* structures that used for the MAC message headers and frame bodies that    */
/* can exist in the three types of MAC messages - 1) Control messages,       */
/* 2) Data messages, and 3) Management messages.                             */
/*---------------------------------------------------------------------------*/
typedef struct IEEEtypes_FrameCtl_t
{
#ifdef MV_CPU_LE
	u16 ProtocolVersion : 2;
	u16 Type : 2;
	u16 Subtype : 4;
	u16 ToDs : 1;
	u16 FromDs : 1;
	u16 MoreFrag : 1;
	u16 Retry : 1;
	u16 PwrMgmt : 1;
	u16 MoreData : 1;
	u16 Wep : 1;
	u16 Order : 1;
#else // MV_CPU_BE
	u16 Subtype : 4;
	u16 Type : 2;
	u16 ProtocolVersion : 2;
	u16 Order : 1;
	u16 Wep : 1;
	u16 MoreData : 1;
	u16 PwrMgmt : 1;
	u16 Retry : 1;
	u16 MoreFrag : 1;
	u16 FromDs : 1;
	u16 ToDs : 1;
#endif
} PACK_END IEEEtypes_FrameCtl_t;

/* */
/* The frame control field in the header of a MAC message */
/* */

typedef struct IEEEtypes_GenHdr_t
{
	u16 FrmBodyLen;
	IEEEtypes_FrameCtl_t FrmCtl;
	u16 DurationId;
	IEEEtypes_MacAddr_t Addr1;
	IEEEtypes_MacAddr_t Addr2;
	IEEEtypes_MacAddr_t Addr3;
	u16 SeqCtl;
	IEEEtypes_MacAddr_t Addr4;
} PACK_END IEEEtypes_GenHdr_t;
/* */
/* The general header for MAC messages */
/* */

typedef struct IEEEtypes_Promiscuous_QoSHdr_t
{
	u16 FrmBodyLen;
	IEEEtypes_FrameCtl_t FrmCtl;
	u16 DurationId;
	IEEEtypes_MacAddr_t Addr1;
	IEEEtypes_MacAddr_t Addr2;
	IEEEtypes_MacAddr_t Addr3;
	u16 SeqCtl;
	u16 QosControl;
} PACK_END IEEEtypes_Promiscuous_QoSHdr_t;

typedef struct IEEEtypes_Promiscuous_WDS_QoSHdr_t
{
	u16 FrmBodyLen;
	IEEEtypes_FrameCtl_t FrmCtl;
	u16 DurationId;
	IEEEtypes_MacAddr_t Addr1;
	IEEEtypes_MacAddr_t Addr2;
	IEEEtypes_MacAddr_t Addr3;
	u16 SeqCtl;
	IEEEtypes_MacAddr_t Addr4;
	u16 QosControl;
} PACK_END IEEEtypes_Promiscuous_WDS_QoSHdr_t;

typedef struct IEEEtypes_Promiscuous_None_QoSHdr_t
{
	u16 FrmBodyLen;
	IEEEtypes_FrameCtl_t FrmCtl;
	u16 DurationId;
	IEEEtypes_MacAddr_t Addr1;
	IEEEtypes_MacAddr_t Addr2;
	IEEEtypes_MacAddr_t Addr3;
	u16 SeqCtl;
} PACK_END IEEEtypes_Promiscuous_None_QoSHdr_t;

typedef struct IEEEtypes_MgmtHdr_t
{
	u16 FrmBodyLen;
	IEEEtypes_FrameCtl_t FrmCtl;
	u16 Duration;
	IEEEtypes_MacAddr_t DestAddr;
	IEEEtypes_MacAddr_t SrcAddr;
	IEEEtypes_MacAddr_t BssId;
	u16 SeqCtl;
	IEEEtypes_MacAddr_t Rsrvd;
} PACK_END IEEEtypes_MgmtHdr_t;
/* */
/* The header for MAC management messages */
/* */

typedef struct IEEEtypes_MgmtHdr2_t
{
	IEEEtypes_FrameCtl_t FrmCtl;
	u16 Duration;
	IEEEtypes_MacAddr_t DestAddr;
	IEEEtypes_MacAddr_t SrcAddr;
	IEEEtypes_MacAddr_t BssId;
	u16 SeqCtl;
	IEEEtypes_MacAddr_t Rsrvd;
} PACK_END IEEEtypes_MgmtHdr2_t;

typedef struct IEEEtypes_MgmtHdr3_t
{
	u16 FrmBodyLen;
	IEEEtypes_FrameCtl_t FrmCtl;
	u16 Duration;
	IEEEtypes_MacAddr_t DestAddr;
	IEEEtypes_MacAddr_t SrcAddr;
	IEEEtypes_MacAddr_t BssId;
	u16 SeqCtl;
	IEEEtypes_MacAddr_t Rsrvd;
} PACK_END IEEEtypes_MgmtHdr3_t;

typedef struct IEEEtypes_ActionNoAcktHdr_t
{
	u16 FrmBodyLen;
	IEEEtypes_FrameCtl_t FrmCtl;
	u16 Duration;
	IEEEtypes_MacAddr_t DestAddr;
	IEEEtypes_MacAddr_t SrcAddr;
	IEEEtypes_MacAddr_t BssId;
	u16 SeqCtl;
} PACK_END IEEEtypes_ActionNoAcktHdr_t;

typedef struct IEEEtypes_PsPollHdr_t
{
	u16 FrmBodyLen;
	IEEEtypes_FrameCtl_t FrmCtl;
	u16 Aid;
	IEEEtypes_MacAddr_t BssId;
	IEEEtypes_MacAddr_t TxAddr;
} PACK_END IEEEtypes_PsPollHdr_t;
/* */
/* The header for power-save poll messages (the only control message */
/* processed by the MAC software) */
/* */

typedef struct IEEEtypes_CtlHdr_t
{
	u16 FrmBodyLen;
	IEEEtypes_FrameCtl_t FrmCtl;
	u16 Duration;
	IEEEtypes_MacAddr_t DestAddr;
	IEEEtypes_MacAddr_t SrcAddr;
} PACK_END IEEEtypes_CtlHdr_t;
/* */
/* The header for MAC Ctl messages */
/* */

typedef struct IEEEtypes_CtlFrame_t
{
	IEEEtypes_PsPollHdr_t Hdr;
	u32 FCS;
} PACK_END IEEEtypes_CtlFrame_t;
/* */
/* The structure for control frames (of which only the power-save */
/* poll is processed by the MAC software) */
/* */

typedef struct IEEEtypes_DataFrame_t
{
	IEEEtypes_GenHdr_t Hdr;
	u8 FrmBody[IEEEtypes_MAX_DATA_BODY_LEN];
	u32 FCS;
} PACK_END IEEEtypes_DataFrame_t;
/* */
/* The structure for data frames */
/* */

typedef struct IEEEtypes_htcHT_t
{
	u32 vht : 1;
	u32 ht_cControl_middle : 29;
	u32 ac_constraint : 1;
	u32 rdg : 1;
} PACK_END IEEEtypes_htcHT_t;

typedef struct IEEEtypes_htcVHT_t
{
	u32 vht : 1;
	u32 he : 1;
	u32 vht_cControl_middle : 28;
	u32 ac_constraint : 1;
	u32 rdg : 1;
} PACK_END IEEEtypes_htcVHT_t;

typedef struct IEEEtypes_AcontrolInfoOm_t
{
	union
	{
		u16 om_control;
		struct
		{
			u16 rxnss : 3;
			u16 chbw : 2;
			u16 ulmu_disable : 1;
			u16 tx_nsts : 3;
			u16 er_su_disable : 1;
			u16 dl_mu_mimo_resound : 1;
			u16 ul_mu_data_disable : 1;
			u16 na : 4; /* there are only 12 bits for Control Information subfield for OM Control */
		};
	};
} PACK_END IEEEtypes_AcontrolInfoOm_t;

typedef struct IEEEtypes_htcHE_t
{
	u32 vht : 1;
	u32 he : 1;
	u32 a_control : 30;
} PACK_END IEEEtypes_htcHE_t;

typedef struct IEEEtypes_htcField_t
{
	union
	{
		IEEEtypes_htcHT_t ht_variant;
		IEEEtypes_htcVHT_t vht_variant;
		IEEEtypes_htcHE_t he_variant;
	};
} PACK_END IEEEtypes_htcField_t;

typedef struct IEEEtypes_fullHdr_t
{
	IEEEtypes_FrameCtl_t FrmCtl;
	u16 DurationId;
	IEEEtypes_MacAddr_t Addr1;
	IEEEtypes_MacAddr_t Addr2;
	IEEEtypes_MacAddr_t Addr3;
	u16 SeqCtl;
	union
	{
		IEEEtypes_MacAddr_t Addr4;

		struct
		{
			IEEEtypes_MacAddr_t Addr4;
			u16 qos;
		} PACK_END wds_qos;

		struct
		{
			IEEEtypes_MacAddr_t Addr4;
			IEEEtypes_htcField_t htc;
		} PACK_END wds_htc;

		struct
		{
			IEEEtypes_MacAddr_t Addr4;
			u16 qos;
			IEEEtypes_htcField_t htc;
		} PACK_END wds_qos_htc;

		struct
		{
			u16 qos;
			IEEEtypes_htcField_t htc;
		} PACK_END qos_htc;

		u16 qos;
		IEEEtypes_htcField_t htc;
	};
} PACK_END IEEEtypes_fullHdr_t;

/*-------------------------------------------------*/
/* Management Frame Body Components - Fixed Fields */
/*-------------------------------------------------*/
typedef u16 IEEEtypes_AId_t;
/* */
/* Association ID assigned by an AP during the association process */
/* */

typedef u16 IEEEtypes_AuthAlg_t;
/* */
/* Number indicating the authentication algorithm used (it can take */
/* on the values given by IEEEtypes_AuthType_e): */
/*    0 = Open system */
/*    1 = Shared key */
/*    All other values reserved */
/* */

typedef u16 IEEEtypes_AuthTransSeq_t;
/* */
/* Authentication transaction sequence number that indicates the current */
/* state of progress through a multistep transaction */
/* */

typedef u16 IEEEtypes_BcnInterval_t;
/* */
/* Beacon interval that represents the number of time units between */
/* target beacon transmission times */
/* */

typedef u8 IEEEtypes_DtimPeriod_t;
/* */
/* Interval that represents the number of time units between DTIMs. */
/* */

typedef struct IEEEtypes_CapInfo_t
{
#ifdef MV_CPU_LE

	u16 Ess : 1;
	u16 Ibss : 1;
	u16 CfPollable : 1;
	u16 CfPollRqst : 1;
	u16 Privacy : 1;
	u16 ShortPreamble : 1;
	u16 Pbcc : 1;
	u16 ChanAgility : 1;
	u16 SpectrumMgmt : 1;
	u16 QoS : 1;
	u16 ShortSlotTime : 1;
	u16 APSD : 1;
	u16 Rrm : 1;
	u16 DsssOfdm : 1;
	u16 BlckAck : 1;
	u16 Rsrvd2 : 1;

#else // MV_CPU_BE

	u16 ChanAgility : 1;
	u16 Pbcc : 1;
	u16 ShortPreamble : 1;
	u16 Privacy : 1;
	u16 CfPollRqst : 1;
	u16 CfPollable : 1;
	u16 Ibss : 1;
	u16 Ess : 1;
	u16 Rsrvd2 : 1;
	u16 BlckAck : 1;
	u16 DsssOfdm : 1;
	u16 Rrm : 1;
	u16 APSD : 1;
	u16 ShortSlotTime : 1;
	u16 QoS : 1;
	u16 SpectrumMgmt : 1;

#endif
} PACK_END IEEEtypes_CapInfo_t;

/* */
/* Capability information used to indicate requested or advertised */
/* capabilities */
/* */

typedef u16 IEEEtypes_ListenInterval_t;
/* */
/* Listen interval to indicate to an AP how often a STA wakes to listen */
/* to beacon management frames */
/* */

typedef u16 IEEEtypes_ReasonCode_t;
/* */
/* Reason code to indicate the reason that an unsolicited notification */
/* management frame of type Disassociation or Deauthentication was */
/* generated */
/* */

typedef u16 IEEEtypes_StatusCode_t;
/* */
/* Status code used in a response management frame to indicate the */
/* success or failure of a requested operation */
/* */

typedef u8 IEEEtypes_TimeStamp_t[IEEEtypes_TIME_STAMP_SIZE];
/* */
/* Time stamp */
/* */
typedef struct IEEEtypes_QosCtl_t
{
	u16 QosControl;
} PACK_END IEEEtypes_QosCtl_t;
/*-------------------------------------------------------*/
/* Management Frame Body Components - Information Fields */
/*-------------------------------------------------------*/
typedef struct IEEEtypes_InfoElementHdr_t
{
	IEEEtypes_ElementId_t ElementId;
	IEEEtypes_Len_t Len;
} PACK_END IEEEtypes_InfoElementHdr_t;

typedef struct IEEEtypes_InfoElementExtHdr_t
{
	IEEEtypes_ElementId_t ElementId;
	IEEEtypes_Len_t Len;
	IEEEtypes_ElementIdExt_t ext;
} PACK_END IEEEtypes_InfoElementExtHdr_t;

typedef struct IEEEtypes_SsIdElement_t
{
	IEEEtypes_ElementId_t ElementId;
	IEEEtypes_Len_t Len;
	IEEEtypes_SsId_t SsId;
} PACK_END IEEEtypes_SsIdElement_t;
/* */
/* SSID element that idicates the identity of an ESS or IBSS */
/* */

typedef struct IEEEtypes_SuppRatesElement_t
{
	IEEEtypes_ElementId_t ElementId;
	IEEEtypes_Len_t Len;
	IEEEtypes_DataRate_t Rates[IEEEtypes_MAX_DATA_RATES];
} PACK_END IEEEtypes_SuppRatesElement_t;
/* */
/* Supported rates element that specifies the rates in the operational */
/* rate set in the MLME join request and the MLME start request */
/* */

typedef struct IEEEtypes_FhParamSet_t
{
	IEEEtypes_ElementId_t ElementId;
	IEEEtypes_Len_t Len;
	u16 DwellTime;
	u8 HopSet;
	u8 HopPattern;
	u8 HopIndex;
} PACK_END IEEEtypes_FhParamSet_t;
/* */
/* FH parameter set that conatins the set of parameters necessary to */
/* allow sychronization for stations using a frequency hopping PHY */
/* */

typedef struct IEEEtypes_DsParamSet_t
{
	IEEEtypes_ElementId_t ElementId;
	IEEEtypes_Len_t Len;
	u8 CurrentChan;
	//  u8 CurrentChan2;
} PACK_END IEEEtypes_DsParamSet_t;
/* */
/* DS parameter set that contains information to allow channel number */
/* identification for stations using a direct sequence spread spectrum PHY */
/* */

typedef struct IEEEtypes_CfParamSet_t
{
	IEEEtypes_ElementId_t ElementId;
	IEEEtypes_Len_t Len;
	u8 CfpCnt;
	u8 CfpPeriod;
	u16 CfpMaxDuration;
	u16 CfpDurationRemaining;
} PACK_END IEEEtypes_CfParamSet_t;
/* */
/* CF parameter set that contains the set of parameters necessary to */
/* support the PCF */
/* */

typedef struct IEEEtypes_Tim_t
{
	IEEEtypes_ElementId_t ElementId;
	IEEEtypes_Len_t Len;
	u8 DtimCnt;
	u8 DtimPeriod;
	u8 BitmapCtl;
	u8 PartialVirtualBitmap[IEEEtypes_BITMAP_SIZE];
} PACK_END IEEEtypes_Tim_t;
/* */
/* TIM, which contains: */
/* 1) DTIM count - how many beacons (including the current beacon */
/*    frame) appear before the next DTIM; a count of 0 indicates the */
/*    current TIM is the DTIM */
/* */
/* 2) DTIM period - indicates the number of beacon intervals between */
/*    successive DTIMs */
/* */
/* 3) Bitmap control - contains the traffic indicator bit associated */
/*    with association ID 0 - this is set to 1 for TIM elements with a */
/*    a value of 0 in the DTIM count field when one or more broadcast */
/*    or multicast frames are buffered at the AP. The remaining bits */
/*    of the field form the bitmap offset */
/* */
/* 4) Partial virtual bitmap - indicates which stations have messages */
/*    buffered at the AP, for which the AP is prepared to deliver at */
/*    the time the beacon frame is transmitted */

typedef struct IEEEtypes_IbssParamSet_t
{
	IEEEtypes_ElementId_t ElementId;
	IEEEtypes_Len_t Len;
	u16 AtimWindow;
} PACK_END IEEEtypes_IbssParamSet_t;
/* */
/* IBSS parameters necessary to support an IBSS */
/* */

typedef struct IEEEtypes_ChallengeText_t
{
	IEEEtypes_ElementId_t ElementId;
	IEEEtypes_Len_t Len;
	u8 Text[IEEEtypes_CHALLENGE_TEXT_SIZE];
} PACK_END IEEEtypes_ChallengeText_t;
/* */
/* The challenge text used in authentication exchanges */
/* */

/*-------------------------*/
/* Management Frame Bodies */
/*-------------------------*/
typedef union IEEEtypes_PhyParamSet_t
{
	IEEEtypes_FhParamSet_t FhParamSet;
	IEEEtypes_DsParamSet_t DsParamSet;
} PACK_END IEEEtypes_PhyParamSet_t;
/* */
/* The parameter set relevant to the PHY */
/* */

typedef union IEEEtypes_SsParamSet_t
{
	IEEEtypes_CfParamSet_t CfParamSet;
	IEEEtypes_IbssParamSet_t IbssParamSet;
} PACK_END IEEEtypes_SsParamSet_t;
/* */
/* Service set parameters - for a BSS supporting, PCF, the */
/* CF parameter set is used; for an independent BSS, the IBSS */
/* parameter set is used. */
/* */
typedef struct IEEEtypes_ExtSuppRatesElement_t
{
	IEEEtypes_ElementId_t ElementId;
	IEEEtypes_Len_t Len;
	IEEEtypes_DataRate_t Rates[IEEEtypes_MAX_DATA_RATES];
} PACK_END IEEEtypes_ExtSuppRatesElement_t;

typedef struct IEEEtypes_ERPInfo_t
{
#ifdef MV_CPU_LE
	u8 NonERPPresent : 1;
	u8 UseProtection : 1;
	u8 BarkerPreamble : 1;
	u8 reserved : 5;
#else
	u8 reserved : 5;
	u8 BarkerPreamble : 1;
	u8 UseProtection : 1;
	u8 NonERPPresent : 1;
#endif
} PACK_END IEEEtypes_ERPInfo_t;

typedef struct IEEEtypes_ERPInfoElement_t
{
	IEEEtypes_ElementId_t ElementId;
	IEEEtypes_Len_t Len;
	IEEEtypes_ERPInfo_t ERPInfo;
} PACK_END IEEEtypes_ERPInfoElement_t;

// Authentication Key Mgmt Suite Selector
#define IEEEtypes_RSN_AUTH_KEY_SUITE_RSVD 0
#define IEEEtypes_RSN_AUTH_KEY_SUITE_8021X 1
#define IEEEtypes_RSN_AUTH_KEY_SUITE_PSK 2

// Cipher Suite Selector
#define IEEEtypes_RSN_CIPHER_SUITE_NONE 0
#define IEEEtypes_RSN_CIPHER_SUITE_WEP40 1
#define IEEEtypes_RSN_CIPHER_SUITE_TKIP 2
#define IEEEtypes_RSN_CIPHER_SUITE_WRAP 3
#define IEEEtypes_RSN_CIPHER_SUITE_CCMP 4
#define IEEEtypes_RSN_CIPHER_SUITE_WEP104 5
#define IEEEtypes_RSN_CIPHER_SUITE_AES_CMAC 6
#define IEEEtypes_RSN_CIPHER_SUITE_GCMP 8
#define IEEEtypes_RSN_CIPHER_SUITE_GCMP_256 9
#define IEEEtypes_RSN_CIPHER_SUITE_CCMP_256 0xA
#define IEEEtypes_RSN_CIPHER_SUITE_BIP_GMAC_128 0xB
#define IEEEtypes_RSN_CIPHER_SUITE_BIP_GMAC_256 0xC
#define IEEEtypes_RSN_CIPHER_SUITE_BIP_CMAC_256 0xD
// #define MAX_SIZE_RSN_IE_BUF 32  // number of bytes

typedef struct IEEEtypes_RSN_IE_t
{
	u8 ElemId;
	u8 Len;
	u8 OuiType[4]; /*00:50:f2:01 */
	u8 Ver[2];
	u8 GrpKeyCipher[4];
	u8 PwsKeyCnt[2];
	u8 PwsKeyCipherList[4];
	u8 AuthKeyCnt[2];
	u8 AuthKeyList[4];
	// u8   RsnCap[2];
	u8 Reserved[4];
} IEEEtypes_RSN_IE_t;

typedef struct IEEEtypes_RSN_IE_WPAMixedMode_t
{
	u8 ElemId;
	u8 Len;
	u8 OuiType[4]; // 00:50:f2:01
	u8 Ver[2];
	u8 GrpKeyCipher[4];
	u8 PwsKeyCnt[2];
	u8 PwsKeyCipherList[4];
	u8 PwsKeyCipherList2[4];
	u8 AuthKeyCnt[2];
	u8 AuthKeyList[4];
	u8 RsnCap[2];
} PACK_END IEEEtypes_RSN_IE_WPAMixedMode_t;

typedef struct IEEEtypes_RSN_IE_WPA2_t
{
	u8 ElemId;
	u8 Len;
	u8 Ver[2];
	u8 GrpKeyCipher[4];
	u8 PwsKeyCnt[2];
	u8 PwsKeyCipherList[4];
	u8 AuthKeyCnt[2];
	u8 AuthKeyList[4];
	u8 AuthKeyList1[4];
	u8 RsnCap[2];
	u8 PMKIDCnt[2];
	u8 PMKIDList[16];
	u8 GrpMgtKeyCipher[4];
} PACK_END IEEEtypes_RSN_IE_WPA2_t;

typedef struct IEEEtypes_RSN_IE_WPA2MixedMode_singlepwcipher_t
{
	u8 ElemId;
	u8 Len;
	// u8   OuiType[4];    //00:50:f2:01
	u8 Ver[2];
	u8 GrpKeyCipher[4];
	u8 PwsKeyCnt[2];
	u8 PwsKeyCipherList[4];
	u8 AuthKeyCnt[2];
	u8 AuthKeyList[4];
	u8 RsnCap[2];
	u8 PMKIDCnt[2];
	u8 PMKIDList[16];
} PACK_END IEEEtypes_RSN_IE_WPA2MixedMode_singlepwcipher_t;

typedef struct IEEEtypes_RSN_IE_WPA2MixedMode_t
{
	u8 ElemId;
	u8 Len;
	// u8   OuiType[4];    //00:50:f2:01
	u8 Ver[2];
	u8 GrpKeyCipher[4];
	u8 PwsKeyCnt[2];
	u8 PwsKeyCipherList[4];
	u8 PwsKeyCipherList2[4];
	u8 AuthKeyCnt[2];
	u8 AuthKeyList[4];
	u8 RsnCap[2];
	u8 PMKIDCnt[2];
	u8 PMKIDList[16];
} PACK_END IEEEtypes_RSN_IE_WPA2MixedMode_t;

typedef struct IEEEtypes_MOBILITY_DOMAIN_IE_t
{
	u8 ElemId;
	u8 Len;
	u16 MDID;
	u8 FT_Cap;
} PACK_END IEEEtypes_MOBILITY_DOMAIN_IE_t;

#define IEEEtypes_WAPI_IE_MAX_LEN 128
typedef struct IEEEtypes_WAPI_IE_t
{
	IEEEtypes_ElementId_t ElementId;
	IEEEtypes_Len_t Len;
	u8 buf[IEEEtypes_WAPI_IE_MAX_LEN];
} PACK_END IEEEtypes_WAPI_IE_t;

struct nlmsghdr2
{
	u32 nlmsg_len;
	u16 nlmsg_type;
	u16 nlmsg_flags;
	u32 nlmsg_seq;
	u32 nlmsg_pid;
};

struct asso_mt_t
{
	struct nlmsghdr2 hdr;
	/**/ u16 type; /* Message Type */
	u16 data_len;  /* Message Length */
	u8 ap_mac[6];
	u8 pad1[2];
	u8 mac[6]; /* STA MAC address */
	u8 pad[2];
	u8 gsn[16];	 /* Mcast data index */
	u8 wie[256]; /* wapi IE */
};
typedef struct asso_mt_t asso_mt;

typedef struct _DomainCapabilityEntry
{
	u8 FirstChannelNo;
	u8 NoofChannel;
	u8 MaxTransmitPw;
} PACK_END DomainCapabilityEntry;

typedef struct IEEEtypes_PowerConstraintElement_t
{
	IEEEtypes_ElementId_t ElementId;
	IEEEtypes_Len_t Len;
	s8 value;
} PACK_END IEEEtypes_PowerConstraintElement_t;

typedef struct TransmitPowerInfo_t
{
	u8 LocalMaxTransPowCount : 3;
	u8 LocalMaxTransPowUnitInter : 3;
	u8 Reserved : 2;
} PACK_END TransmitPowerInfo_t;

typedef struct IEEEtypes_VHTTransmitPowerEnvelopeElement_t
{
	u8 eid;
	u8 Len;
	TransmitPowerInfo_t TransmitPowerInfo;
	u8 LocalMaxTransmitPower20Mhz;
	u8 LocalMaxTransmitPower40Mhz;
	u8 LocalMaxTransmitPower80Mhz;
	u8 LocalMaxTransmitPower160Mhz;
} PACK_END IEEEtypes_VHTTransmitPowerEnvelopeElement_t;

typedef struct IEEEtypes_COUNTRY_IE_t
{
	IEEEtypes_ElementId_t ElemId; // wyatth
	u8 Len;
	u8 CountryCode[3];
	u8 DomainEntry[100];
	/** give a big no for now **/
} PACK_END IEEEtypes_COUNTRY_IE_t;

typedef struct IEEEtypes_PowerCapabilityElement_t
{
	IEEEtypes_ElementId_t ElementId;
	IEEEtypes_Len_t Len;
	s8 MaxTxPwr;
	s8 MinTxPwr;
} PACK_END IEEEtypes_PowerCapabilityElement_t;

typedef struct IEEEtypes_TPCReqElement_t
{
	IEEEtypes_ElementId_t ElementId;
	IEEEtypes_Len_t Len;
} PACK_END IEEEtypes_TPCReqElement_t;

typedef struct IEEEtypes_TPCRepElement_t
{
	IEEEtypes_ElementId_t ElementId;
	IEEEtypes_Len_t Len;
	s8 TxPwr;
	s8 LinkMargin;
} PACK_END IEEEtypes_TPCRepElement_t;

typedef struct ChannelDesp_t
{
	u8 FisrtChannel;
	u8 NumberofChannel;
} PACK_END ChannelDesp_t;

typedef struct IEEEtypes_SupportedChannelElement_t
{
	IEEEtypes_ElementId_t ElementId;
	IEEEtypes_Len_t Len;
#define MAX_SUPPORTED_CHANNEL_TUPLE (IEEE_80211_MAX_NUMBER_OF_CHANNELS * 2)
	ChannelDesp_t SupportedChannel[MAX_SUPPORTED_CHANNEL_TUPLE];
} PACK_END IEEEtypes_SupportedChannelElement_t;

typedef struct IEEEtypes_ChannelSwitchAnnouncementElement_t
{
	IEEEtypes_ElementId_t ElementId;
	IEEEtypes_Len_t Len;
	u8 Mode;
	u8 Channel;
	u8 Count;
} PACK_END IEEEtypes_ChannelSwitchAnnouncementElement_t;

typedef struct IEEEtypes_SecondaryChannelOffsetElement_t
{
	IEEEtypes_ElementId_t ElementId;
	IEEEtypes_Len_t Len;
	u8 Offset;
} PACK_END IEEEtypes_SecondaryChannelOffsetElement_t;

typedef struct IEEEtypes_WideBWCS_Element_t
{
	IEEEtypes_ElementId_t ElementId;
	IEEEtypes_Len_t Len;
	u8 ch_width;
	u8 center_freq0;
	u8 center_freq1;
} PACK_END IEEEtypes_WideBWCS_Element_t;

/*********************802.11K Radio Resource Management*****************************/
typedef struct IEEEtypes_MeasurementReqMode_t
{
#ifdef MV_CPU_LE
	u8 Parallel : 1;
	u8 Enable : 1;
	u8 Request : 1;
	u8 Report : 1;
	u8 DurMand : 1;
	u8 Rsv1 : 3;
#else
	u8 Rsv1 : 3;
	u8 DurMand : 1;
	u8 Report : 1;
	u8 Request : 1;
	u8 Enable : 1;
	u8 Parallel : 1;
#endif
} PACK_END IEEEtypes_MeasurementReqMode_t;

typedef struct IEEEtypes_MeasurementReq_t
{
	u8 Channel;
	u8 StartTime[8];
	u16 Duration;
} PACK_END IEEEtypes_MeasurementReq_t;

typedef struct IEEEtypes_MeasurementRequestElement_t
{
	IEEEtypes_ElementId_t ElementId;
	IEEEtypes_Len_t Len;
	u8 Token;
	IEEEtypes_MeasurementReqMode_t Mode;
	IEEEtypes_MeasurementReqType_t Type;
	IEEEtypes_MeasurementReq_t Request;
} PACK_END IEEEtypes_MeasurementRequestElement_t;

typedef struct IEEEtypes_RM_Enable_Capabilities_Element_t
{
	u8 eid;
	u8 Len;
#ifdef MV_CPU_LE
	u8 LinkMeasCap : 1;
	u8 NeighRptCap : 1;
	u8 ParalMeasCap : 1;
	u8 RepetMeasCap : 1;
	u8 BcnPasMeasCap : 1;
	u8 BcnActMeasCap : 1;
	u8 BcnTabMeasCap : 1;
	u8 BcnMeasRptCondCap : 1;

	u8 FrameMeasCap : 1;
	u8 ChnlLoadMeasCap : 1;
	u8 NoiseHistMeasCap : 1;
	u8 StatMeasCap : 1;
	u8 LciMeasCap : 1;
	u8 LciAziCap : 1;
	u8 TranStrCatMeasCap : 1;
	u8 TriTranStrCatMeasCap : 1;

	u8 APChnlRptCap : 1;
	u8 RrmMibCap : 1;
	u8 OpChMaxMeasDur : 3;
	u8 NOpChMaxMeasDur : 3;

	u8 MeasPltCap : 3;
	u8 MeasPltTransInfoCap : 1;
	u8 NeighRptTsfOffCap : 1;
	u8 RCPIMeasCap : 1;
	u8 RSNIMeasCap : 1;
	u8 BSSAvgAccDelayCap : 1;

	u8 BSSAvgAdmCpcCap : 1;
	u8 AntInfoCap : 1;
	u8 Rsvd : 6;
#else
	u8 BcnMeasRptCondCap : 1;
	u8 BcnTabMeasCap : 1;
	u8 BcnActMeasCap : 1;
	u8 BcnPasMeasCap : 1;
	u8 RepetMeasCap : 1;
	u8 ParalMeasCap : 1;
	u8 NeighRptCap : 1;
	u8 LinkMeasCap : 1;

	u8 TriTranStrCatMeasCap : 1;
	u8 TranStrCatMeasCap : 1;
	u8 LciAziCap : 1;
	u8 LciMeasCap : 1;
	u8 StatMeasCap : 1;
	u8 NoiseHistMeasCap : 1;
	u8 ChnlLoadMeasCap : 1;
	u8 FrameMeasCap : 1;

	u8 NOpChMaxMeasDur : 3;
	u8 OpChMaxMeasDur : 3;
	u8 RrmMibCap : 1;
	u8 APChnlRptCap : 1;

	u8 BSSAvgAccDelayCap : 1;
	u8 RSNIMeasCap : 1;
	u8 RCPIMeasCap : 1;
	u8 NeighRptTsfOffCap : 1;
	u8 MeasPltTransInfoCap : 1;
	u8 MeasPltCap : 3;

	u8 Rsvd : 6;
	u8 AntInfoCap : 1;
	u8 BSSAvgAdmCpcCap : 1;
#endif
} PACK_END IEEEtypes_RM_Enable_Capabilities_Element_t;

typedef struct IEEEtypes_BeaconRequest_t
{
	u8 RegClass;
	u8 Channel;
	u16 RandInt;
	u16 Dur;
	u8 MeasMode;
	u8 Bssid[6];
	u8 OptSubElem[];
} PACK_END IEEEtypes_BeaconRequest_t;

typedef struct IEEEtypes_RadioMeasurementRequestElement_t
{
	IEEEtypes_ElementId_t ElementId;
	IEEEtypes_Len_t Len;
	u8 Token;
	IEEEtypes_MeasurementReqMode_t Mode;
	IEEEtypes_MeasurementReqType_t Type;
	union
	{
		IEEEtypes_BeaconRequest_t BcnReq;
	};
} PACK_END IEEEtypes_RadioMeasurementRequestElement_t;

typedef struct IEEEtypes_RadioMeasurementRequest_t
{
	u16 NoOfRepetitions;
	IEEEtypes_RadioMeasurementRequestElement_t RequestElement[MAX_NR_IE];
} PACK_END IEEEtypes_RadioMeasurementRequest_t;

typedef struct IEEEtypes_MeasurementRepMode_t
{
#ifdef MV_CPU_LE
	u8 Late : 1;
	u8 Incapable : 1;
	u8 Refused : 1;
	u8 Rsv1 : 5;
#else
	u8 Rsv1 : 5;
	u8 Refused : 1;
	u8 Incapable : 1;
	u8 Late : 1;
#endif
} PACK_END IEEEtypes_MeasurementRepMode_t;

typedef struct IEEEtypes_MeasurementRepMap_t
{
#ifdef MV_CPU_LE
	u8 BSS : 1;
	u8 OFDM : 1;
	u8 UnidentifiedSignal : 1;
	u8 Radar : 1;
	u8 Unmeasured : 1;
	u8 Rsv : 3;
#else
	u8 Rsv : 3;
	u8 Unmeasured : 1;
	u8 Radar : 1;
	u8 UnidentifiedSignal : 1;
	u8 OFDM : 1;
	u8 BSS : 1;
#endif
} PACK_END IEEEtypes_MeasurementRepMap_t;

#ifdef WMON
#define MAX_WMON_APS_SIZE 250
#endif
typedef struct IEEEtypes_MeasurementRep_t
{
	u8 Channel;
	u8 StartTime[8];
	u8 Duration[2];
	union
	{
		IEEEtypes_MeasurementRepMap_t Map;
		u8 BusyFraction;
		u8 RPI[8];
#ifdef WMON
		char APS[MAX_WMON_APS_SIZE];
		u8 RSSI;
		u32 FCS;
		char DFS[MAX_WMON_APS_SIZE];
		char PSE[MAX_WMON_APS_SIZE];
		u32 VRX;
#endif
	} data;
} PACK_END IEEEtypes_MeasurementRep_t;

typedef struct IEEEtypes_BeaconReport_t
{
	u8 RegClass;
	u8 Channel;
	u8 StartTime[8];
	u8 Duration[2];
	u8 FrameInfo;
	u8 RCPI_value;
	u8 RSNI_value;
	u8 Bssid[6];
	u8 AntennaId;
	u8 ParentTSF[4];
} PACK_END IEEEtypes_BeaconReport_t;

typedef struct IEEEtypes_MeasurementReportElement_t
{
	IEEEtypes_ElementId_t ElementId;
	IEEEtypes_Len_t Len;
	u8 MeasurementToken;
	IEEEtypes_MeasurementRepMode_t Mode;
	IEEEtypes_MeasurementRepType_t Type;
	union
	{
		IEEEtypes_MeasurementRep_t DefReport;
		IEEEtypes_BeaconReport_t BcnReport;
	} Report;
} PACK_END IEEEtypes_MeasurementReportElement_t;
/*********************802.11K Radio Resource Management End*****************************/

typedef struct IEEEtypes_QuietElement_t
{
	IEEEtypes_ElementId_t ElementId;
	IEEEtypes_Len_t Len;
	u8 Count;
	u8 Period;
	u16 Duration;
	u16 Offset;
} PACK_END IEEEtypes_QuietElement_t;

typedef struct IEEEtypes_IBSS_DFS_Eleement_t
{
	IEEEtypes_ElementId_t ElementId;
	IEEEtypes_Len_t Len;
	/*
	 * No implementation necessary when working as AP
	 */
} PACK_END IEEEtypes_IBSS_DFS_Eleement_t;

typedef struct IEEEtypes_HT_Cap_t
{
#ifdef MV_CPU_LE
	u16 AdvCoding : 1;
	u16 SupChanWidth : 1;
	u16 MIMOPwSave : 2;
	u16 GreenField : 1;
	u16 SGI20MHz : 1;
	u16 SGI40MHz : 1;
	u16 TxSTBC : 1;
	u16 RxSTBC : 2;
	u16 DelayedBA : 1;
	u16 MaxAMSDUSize : 1;
	u16 DssCck40MHz : 1;
	u16 PSMP : 1;
	u16 FortyMIntolerant : 1;
	u16 LSIGTxopProc : 1;
#else // MV_CPU_BE
	u16 TxSTBC : 1;
	u16 SGI40MHz : 1;
	u16 SGI20MHz : 1;
	u16 GreenField : 1;
	u16 MIMOPwSave : 2;
	u16 SupChanWidth : 1;
	u16 AdvCoding : 1;
	u16 LSIGTxopProc : 1;
	u16 FortyMIntolerant : 1;
	u16 PSMP : 1;
	u16 DssCck40MHz : 1;
	u16 MaxAMSDUSize : 1;
	u16 DelayedBA : 1;
	u16 RxSTBC : 2;
#endif
} PACK_END IEEEtypes_HT_Cap_t;

typedef struct IEEEtypes_HT_Element_t
{
	u8 ElementId;
	IEEEtypes_Len_t Len;
	IEEEtypes_HT_Cap_t HTCapabilitiesInfo;
	u8 MacHTParamInfo;
	u8 SupportedMCSset[16];
	u16 ExtHTCapabilitiesInfo;
	u32 TxBFCapabilities;
	u8 ASCapabilities;
} PACK_END IEEEtypes_HT_Element_t;

typedef PACK_START struct IEEEtypes_vht_cap_info_t
{
#ifdef MV_CPU_LE
	union
	{
		u32 u32_data;
		struct
		{
			u32 MaximumMPDULength : 2;
			u32 SupportedChannelWidthSet : 2;
			u32 RxLDPC : 1;
			u32 ShortGI80MHz : 1;
			u32 ShortGI16080and80MHz : 1;
			u32 TxSTBC : 1;
			u32 RxSTBC : 3;
			u32 SUBeamformerCapable : 1;
			u32 SUBeamformeeCapable : 1;
			u32 CompressedSteeringNumberofBeamformerAntennaSupported : 3;
			u32 NumberofSoundingDimensions : 3;
			u32 MUBeamformerCapable : 1;
			u32 MUBeamformeeCapable : 1;
			u32 VhtTxhopPS : 1;
			u32 HtcVhtCapable : 1;
			u32 MaximumAmpduLengthExponent : 3;
			u32 VhtLinkAdaptationCapable : 2;
			u32 RxAntennaPatternConsistency : 1;
			u32 TxAntennaPatternConsistency : 1;
#ifdef SUPPORTED_EXT_NSS_BW
			u32 ExtendedNssBwSupport : 2;
#else
			u32 Reserved : 2;
#endif
		};
	};
#else
	union
	{
		u32 u32_data;
		struct
		{
#ifdef SUPPORTED_EXT_NSS_BW
			u32 ExtendedNssBwSupport : 2;
#else
			u32 Reserved : 2;
#endif
			u32 TxAntennaPatternConsistency : 1;
			u32 RxAntennaPatternConsistency : 1;
			u32 VhtLinkAdaptationCapable : 2;
			u32 MaximumAmpduLengthExponent : 3;
			u32 HtcVhtCapable : 1;
			u32 VhtTxhopPS : 1;
			u32 MUBeamformeeCapable : 1;
			u32 MUBeamformerCapable : 1;
			u32 NumberofSoundingDimensions : 3;
			u32 CompressedSteeringNumberofBeamformerAntennaSupported : 3;
			u32 SUBeamformeeCapable : 1;
			u32 SUBeamformerCapable : 1;
			u32 RxSTBC : 3;
			u32 TxSTBC : 1;
			u32 ShortGI16080and80MHz : 1;
			u32 ShortGI80MHz : 1;
			u32 RxLDPC : 1;
			u32 SupportedChannelWidthSet : 2;
			u32 MaximumMPDULength : 2;
		};
	};
#endif
} PACK_END IEEEtypes_VHT_Cap_Info_t;

typedef struct IEEEtypes_vht_cap
{
	u8 id;
	u8 len;
	IEEEtypes_VHT_Cap_Info_t cap;
	u32 SupportedRxMcsSet;
	u32 SupportedTxMcsSet;
} PACK_END IEEEtypes_VhtCap_t;

typedef struct IEEEtypes_vht_opt
{
	u8 id;
	u8 len;
	u8 ch_width;
	u8 center_freq0;
	u8 center_freq1;
	u16 basic_mcs;
} PACK_END IEEEtypes_VhOpt_t;

typedef struct IEEEtypes_vht_operating_mode
{
#ifdef MV_CPU_LE
	u8 ChannelWidth : 2;
	u8 Reserved : 2;
	u8 RxNss : 3;
	u8 RxNssType : 1;
#else
	u8 RxNssType : 1;
	u8 RxNss : 3;
	u8 Reserved : 2;
	u8 ChannelWidth : 2;
#endif
} PACK_END IEEEtypes_VHT_operating_mode;

typedef struct IEEEtypes_vht_op_mode_action
{
	u8 Category;
	u8 Action;
	IEEEtypes_VHT_operating_mode OperatingMode;
} PACK_END IEEEtypes_VHT_op_mode_action_t;

typedef struct IEEEtypes_vht_op_mode
{
	u8 id;
	u8 len;
	IEEEtypes_VHT_operating_mode OperatingMode;
} PACK_END IEEEtypes_VHT_op_mode_t;

typedef struct IEEEtypes_mbssid_idx
{
	u8 ElementId;
	IEEEtypes_Len_t Len;
	u8 BssidIdx;   // BSSID index
	u8 DtimPeriod; // DTIM Period
	u8 DtimCnt;	   // DTIM Count
} PACK_END IEEEtypes_mbssid_idx_t;

typedef struct IEEEtypes_NonTransmitted_BSSID_Cap
{
	u8 ElementId;
	IEEEtypes_Len_t Len;
	IEEEtypes_CapInfo_t CapInfo;
} PACK_END IEEEtypes_NonTransmitted_BSSID_Cap_t;

#define NONTRANSMITTED_BSSID_PROFILE_SUBELM_ID 0
typedef struct IEEEtypes_NonTransmitted_BSSID_Profile
{
	u8 subElementId;
	IEEEtypes_Len_t Len;
	IEEEtypes_NonTransmitted_BSSID_Cap_t ntBssidCap;
	IEEEtypes_SsIdElement_t ssid;
	IEEEtypes_mbssid_idx_t mbssidIdx;
	/* FMS descriptor element is handled in PFW */
} PACK_END IEEEtypes_NonTransmitted_BSSID_Profile_t;

typedef struct IEEEtypes_Mbssid_Element_t
{
	u8 ElementId;
	IEEEtypes_Len_t Len;
	u8 MaxBssidIndictor;
	IEEEtypes_NonTransmitted_BSSID_Profile_t NonTxPf;

} PACK_END IEEEtypes_Mbssid_Element_t;

// twt
#ifdef AP_TWT
typedef enum
{ // 802.11ah 9.6.25.1
	TWT_SETUP = 6,
	TWT_TEARDOWN = 7,
	TWT_INFO = 11,
} IEEEtypes_S1G_Act_e;

typedef enum
{
	TWT_SETUP_CMD_REQUEST,
	TWT_SETUP_CMD_SUGGEST,
	TWT_SETUP_CMD_DEMAND,
	TWT_SETUP_CMD_GROUPING, // 3
	TWT_SETUP_CMD_ACCEPT,
	TWT_SETUP_CMD_ALTERNATE,
	TWT_SETUP_CMD_DICTATE,
	TWT_SETUP_CMD_REJECT, // 7
} twt_setup_cmd_e;

typedef struct
{
	u8 NDP_PagingIndicator : 1;
	u8 Responder_PM_Mode : 1;
	u8 NegoType : 2;
	u8 Reserved : 4;
} PACK_END twt_ctrl_fd_t;

typedef struct
{
	u16 ReqRsp : 1;				   // TWT Request
	u16 SetupCmd : 3;			   // TWT setup Cmd
	u16 Trigger : 1;			   // Trigger
	u16 Implicit_or_LBcast : 1;	   // Implicit / Last Broadcast Parameter set
	u16 FlowType : 1;			   // Flow Type
	u16 FlowID_or_Bcast_Recom : 3; // TWT flow ID / broadcast twt recommendation
	u16 WakeIvlExp : 5;			   // TWT wake interval Exponent
	u16 Protect : 1;			   // TWT protection
} PACK_END twt_reqtype_fd_t;

typedef struct
{
	u8 grpID : 7;			  // TWT group ID
	u8 ZeroOffsetPresent : 1; // Zero Offset Present
	u8 ZeroOffsetGrp[0];
} PACK_END twt_GrpAssign_fd_t;

typedef struct
{
	u8 ZeroOffsetGrp[6]; // Zero Offset Group
} PACK_END twt_GrpAssign_subfd0_t;

typedef struct
{
	u16 twtUnit : 4;	// TWT unit
	u16 twtOffset : 12; // TWT Offset
} PACK_END twt_GrpAssign_subfd1_t;

typedef struct
{
	twt_reqtype_fd_t ReqType;
	u64 TargetWakeTime;	  // TWT
	u8 NomMinWakeDur;	  // Nominal Minimum TWT wake duration
	u16 WakeInvlMantissa; // TWT wake interval Mantissa
	u8 channel;			  // TWT channel
	u32 NDP_Paging;
} PACK_END Individual_set_fd_t;

typedef struct
{
	twt_reqtype_fd_t ReqType; // Request Type
	u16 targetWakeTime;		  // Target WakeTime
	u8 NomMinWakeDur;		  // Nominal Minimum TWT wake duration
	u16 WakeInvlMantissa;	  // TWT wake interval Mantissa
	u16 BcastInfo;			  // Broadcast TWT Info
} PACK_END Broadcast_set_fd_t;

typedef struct
{
	u8 ElementId;
	IEEEtypes_Len_t Len;
	twt_ctrl_fd_t ctrl;
	union
	{
		Individual_set_fd_t IndvParamSet;
		Broadcast_set_fd_t BcastParamSet; // might have multiple broadcast sets. assume one for now.
	} info;
} PACK_END IEEEtypes_TWT_Element_t;

typedef struct
{
	u8 FlowID_or_Bcast_Recom : 5; // FlowID :3 bits, BcastID:5 bits
	u8 NegoType : 2;
	u8 Reserved : 1;
} PACK_END IEEEtypes_TWT_Flow_fd_t;

typedef struct
{
	u8 FlowID : 3;
	u8 Rsp_Req : 1;
	u8 NextTWT_Req : 1;
	u8 NextTWT_Subfd_Size : 2;
	u8 AllTWT : 1;
	u64 NextTWT;
} PACK_END IEEEtypes_TWT_Information_t;

typedef struct
{
	u8 Category;
	u8 Action;
	u8 DialogToken;
	IEEEtypes_TWT_Element_t twt;
} PACK_END IEEEtypes_twt_Req_t;

typedef struct PACK_START twt_param
{
	u64 Twt;	   // units of us
	u8 MinWakeDur; // units of 256us
	u8 Channel;
	u16 WakeInvlMantissa;
	u8 WakeInvlExpo : 5;
	u8 Trigger : 1;
	u8 FlowType : 1;
	u8 enterMinSP : 1; // used by PFW for state changed flag
} PACK_END twt_param_t;
#endif

typedef struct IEEEtypes_M_Element_t
{
	u8 ElementId;
	IEEEtypes_Len_t Len;
	u8 OUI[3];
	u8 OUIType;
	u8 OUISubType;
	u8 Version;
} PACK_END IEEEtypes_M_Element_t;
#define MAXRPTRDEVTYPESTR 32
typedef struct IEEEtypes_M_Rptr_Element_t
{
	u8 ElementId;
	IEEEtypes_Len_t Len;
	u8 OUI[3];
	u8 OUIType;
	u8 OUISubType;
	u8 Version;
	u8 RptrDeviceType[MAXRPTRDEVTYPESTR];
} PACK_END IEEEtypes_M_Rptr_Element_t;

#define MAX_VENDORSPEC_VHT_STR 96
typedef struct IEEEtypes_VendorSpec_VHT_Element_t
{
	u8 ElementId;
	IEEEtypes_Len_t Len;
	u8 OUI[3];
	u8 OUIType;
	u8 OUISubType;
	u8 VHTData[MAX_VENDORSPEC_VHT_STR];
} PACK_END IEEEtypes_VendorSpec_VHT_Element_t;

#ifdef MULTI_AP_SUPPORT
#define MultiAP_OUI_type 0x1B
#define MAP_ATTRIBUTE_DISABLE (0)
#define MAP_ATTRIBUTE_BACKHAUL_STA (1 << 7)
#define MAP_ATTRIBUTE_BACKHAUL_BSS (1 << 6)
#define MAP_ATTRIBUTE_FRONTHAUL_BSS (1 << 5)
#define MAP_ATTRIBUTE_TEARDOWN (1 << 4)
#define MAP_ATTRIBUTE_R1BSTA_DISALLOWED (1 << 3)
#define MAP_ATTRIBUTE_R2BSTA_DISALLOWED (1 << 2)

typedef struct IEEEtypes_MultiAP_ExtAttribute_t
{
	u8 Attribute;
	u8 Attribute_Len;
#ifdef MV_CPU_LE
	u8 Reserved : 2;
	u8 R2bSTAdisAllowed : 1;
	u8 R1bSTAdisAllowed : 1;
	u8 TearDown : 1;
	u8 FrontBSS : 1;
	u8 BackBSS : 1;
	u8 BackSTA : 1;
#else
	u8 BackSTA : 1;
	u8 BackBSS : 1;
	u8 FrontBSS : 1;
	u8 TearDown : 1;
	u8 R1bSTAdisAllowed : 1;
	u8 R2bSTAdisAllowed : 1;
	u8 Reserved : 2;
#endif
} PACK_END IEEEtypes_MultiAP_ExtAttribute_t;

typedef struct IEEEtypes_MultiAP_Version_t
{
	IEEEtypes_ElementId_t ElementId;
	IEEEtypes_Len_t Len;
	u8 value;
} PACK_END IEEEtypes_MultiAP_Version_t;

typedef struct IEEEtypes_MultiAP_Traffic_t
{
	IEEEtypes_ElementId_t ElementId;
	IEEEtypes_Len_t Len;
	u16 vid;
} PACK_END IEEEtypes_MultiAP_Traffic_t;

typedef struct IEEEtypes_MultiAP_Element_t
{
	u8 ElementId;
	IEEEtypes_Len_t Len;
	u8 OUI[3];
	u8 OUIType;
	IEEEtypes_MultiAP_ExtAttribute_t attributes;
	/* version subelement omitted by Multi-AP R1 devices. */
	u8 variable[];
	// u8 version[3];
} PACK_END IEEEtypes_MultiAP_Element_t;

#define MAP_R1_IE_SIZE sizeof(IEEEtypes_MultiAP_Element_t)
#define MAP_R1_IE_LEN (MAP_R1_IE_SIZE - 2)
#endif // MULTI_AP_SUPPORT

#ifdef MBO_SUPPORT
#define MBO_OUI_type 0x16

typedef struct IEEEtypes_MBO_Element_t
{
	UINT8 ElementId;
	IEEEtypes_Len_t Len;
	UINT8 OUI[3];
	UINT8 OUIType;
	u8 variable[];
} PACK_END IEEEtypes_MBO_Element_t;
#endif /* MBO_SUPPORT */

typedef struct IEEEtypes_Ext_Cap_t
{
#ifdef MV_CPU_LE
	u8 _20_40Coexistence_Support : 1; /*bit0 */
	u8 Reserved1 : 1;				  /*bit1 */
	u8 ExtChanSwitching : 1;		  /*bit2 */
	u8 Reserved2 : 1;				  /*bit3 */
	u8 PSMP_Cap : 1;				  /*bit4 */
	u8 Reserved3 : 1;				  /*bit5 */
	u8 SPSMP_Support : 1;			  /*bit6 */
	u8 Event : 1;					  /*bit7 */

	u8 Diagnotics : 1;				/*bit8 */
	u8 MulticastDiagnostics : 1;	/*bit9 */
	u8 LocationTracking : 1;		/*bit10 */
	u8 FMS : 1;						/*bit11 */
	u8 ProxyARPService : 1;			/*bit12 */
	u8 CollocatedIntfReporting : 1; /*bit13 */
	u8 CivicLocation : 1;			/*bit14 */
	u8 GioSpatialLocation : 1;		/*bit15 */

	u8 TFS : 1;				  /*bit16 */
	u8 WNMSleepMode : 1;	  /*bit17 */
	u8 TIMBroadcast : 1;	  /*bit18 */
	u8 BSSTransition : 1;	  /*bit19 */
	u8 QoSTrafficCap : 1;	  /*bit20 */
	u8 ACStationCount : 1;	  /*bit21 */
	u8 MultipleBSSID : 1;	  /*bit22 */
	u8 TimingMeasurement : 1; /*bit23 */

	u8 ChannelUsage : 1;		   /*bit24 */
	u8 SSIDList : 1;			   /*bit25 */
	u8 DMS : 1;					   /*bit26 */
	u8 UTCTSFOffset : 1;		   /*bit27 */
	u8 TDLSPeerUAPSDBufSTASup : 1; /*bit28 */
	u8 TDLSPeerPSMSupport : 1;	   /*bit29 */
	u8 TDLSChanSwitching : 1;	   /*bit30 */
	u8 Interworking : 1;		   /*bit31 */

	u8 QoSMap : 1;					 /*bit32 */
	u8 EBR : 1;						 /*bit33 */
	u8 SSPNInterface : 1;			 /*bit34 */
	u8 Reserved4 : 1;				 /*bit35 */
	u8 MSGCFCapibility : 1;			 /*bit36 */
	u8 TDLSSupport : 1;				 /*bit37 */
	u8 TDLSProhibited : 1;			 /*bit38 */
	u8 TDLSChanSwitchProhibited : 1; /*bit39 */

	u8 RejectUnadmittedFrame : 1;	/*bit40 */
	u8 ServIntervalGranularity : 3; /*bit41 - bit43 */
	u8 IdentifierLocation : 1;		/*bit44 */
	u8 UAPSDCoexistence : 1;		/*bit45 */
	u8 WNMNotification : 1;			/*bit46 */
	u8 Reserved5 : 1;				/*bit47 */

	u8 UTF8SSID : 1; /*bit48 */
#ifdef AP_TWT
	u8 QMFActivated : 1;	  /*bit49 */
	u8 QMFRecnfActivated : 1; /*bit50 */
#else
	u8 twt_requester_support : 1; /*bit49 */
	u8 twt_responder_support : 1; /*bit50 */
#endif
	u8 Reserved6 : 5; /*bit51 - bit55 */

	u8 Reserved7 : 5;					  /*bit56 - bit60 */
	u8 TDLSWiderBW : 1;					  /*bit61 */
	u8 OpModeNotification : 1;			  /*bit62 */
	u8 max_number_of_msdu_in_amsdu_1 : 1; /*bit63 */

	u8 max_number_of_msdu_in_amsdu_2 : 1;	   /* bit64 */
	u8 channel_schedule_management : 1;		   /* bit65 */
	u8 geodatabase_inband_enabling_signal : 1; /* bit66 */
	u8 network_channel_control : 1;			   /* bit67 */
	u8 white_space_map : 1;					   /* bit68 */
	u8 channel_availability_query : 1;		   /* bit69 */
	u8 fine_timing_measurement_responder : 1;  /* bit 70 */
	u8 fine_timing_measurement_initiator : 1;  /* bit 71 */

#ifdef AP_TWT
	u8 Reserved9 : 5;			  /*bit72~bit76 */
	u8 twt_requester_support : 1; /*bit77 */
	u8 twt_responder_support : 1; /*bit78 */
	u8 ObssNarrBand : 1;		  /*bit79 */
#endif
	u8 complete_nontxbss_profile : 1; /*bit80 */
	u8 Reserveda : 7;				  /*bit87~81 */
#else
	u8 Event : 1;					  /*bit7 */
	u8 SPSMP_Support : 1;			  /*bit6 */
	u8 Reserved3 : 1;				  /*bit5 */
	u8 PSMP_Cap : 1;				  /*bit4 */
	u8 Reserved2 : 1;				  /*bit3 */
	u8 ExtChanSwitching : 1;		  /*bit2 */
	u8 Reserved1 : 1;				  /*bit1 */
	u8 _20_40Coexistence_Support : 1; /*bit0 */

	u8 GioSpatialLocation : 1;		/*bit15 */
	u8 CivicLocation : 1;			/*bit14 */
	u8 CollocatedIntfReporting : 1; /*bit13 */
	u8 ProxyARPService : 1;			/*bit12 */
	u8 FMS : 1;						/*bit11 */
	u8 LocationTracking : 1;		/*bit10 */
	u8 MulticastDiagnostics : 1;	/*bit9 */
	u8 Diagnotics : 1;				/*bit8 */

	u8 TimingMeasurement : 1; /*bit23 */
	u8 MultipleBSSID : 1;	  /*bit22 */
	u8 ACStationCount : 1;	  /*bit21 */
	u8 QoSTrafficCap : 1;	  /*bit20 */
	u8 BSSTransition : 1;	  /*bit19 */
	u8 TIMBroadcast : 1;	  /*bit18 */
	u8 WNMSleepMode : 1;	  /*bit17 */
	u8 TFS : 1;				  /*bit16 */

	u8 Interworking : 1;		   /*bit31 */
	u8 TDLSChanSwitching : 1;	   /*bit30 */
	u8 TDLSPeerPSMSupport : 1;	   /*bit29 */
	u8 TDLSPeerUAPSDBufSTASup : 1; /*bit28 */
	u8 UTCTSFOffset : 1;		   /*bit27 */
	u8 DMS : 1;					   /*bit26 */
	u8 SSIDList : 1;			   /*bit25 */
	u8 ChannelUsage : 1;		   /*bit24 */

	u8 TDLSChanSwitchProhibited : 1; /*bit39 */
	u8 TDLSProhibited : 1;			 /*bit38 */
	u8 TDLSSupport : 1;				 /*bit37 */
	u8 MSGCFCapibility : 1;			 /*bit36 */
	u8 Reserved4 : 1;				 /*bit35 */
	u8 SSPNInterface : 1;			 /*bit34 */
	u8 EBR : 1;						 /*bit33 */
	u8 QoSMap : 1;					 /*bit32 */

	u8 Reserved5 : 1;				/*bit47 */
	u8 WNMNotification : 1;			/*bit46 */
	u8 UAPSDCoexistence : 1;		/*bit45 */
	u8 IdentifierLocation : 1;		/*bit44 */
	u8 ServIntervalGranularity : 3; /*bit41 - bit43 */
	u8 RejectUnadmittedFrame : 1;	/*bit40 */

	u8 Reserved6 : 7; /*bit49 - bit55 */
	u8 UTF8SSID : 1;  /*bit48 */

	u8 max_number_of_msdu_in_amsdu_1 : 1; /*bit63 */
	u8 OpModeNotification : 1;			  /*bit62 */
	u8 TDLSWiderBW : 1;					  /*bit61 */
	u8 Reserved7 : 5;					  /*bit56 - bit60 */

	u8 fine_timing_measurement_initiator : 1;  /* bit 71 */
	u8 fine_timing_measurement_responder : 1;  /* bit 70 */
	u8 channel_availability_query : 1;		   /* bit69 */
	u8 white_space_map : 1;					   /* bit68 */
	u8 network_channel_control : 1;			   /* bit67 */
	u8 geodatabase_inband_enabling_signal : 1; /* bit66 */
	u8 channel_schedule_management : 1;		   /* bit65 */
	u8 max_number_of_msdu_in_amsdu_2 : 1;	   /* bit64 */

#ifdef AP_TWT
	u8 ObssNarrBand : 1;		  /*bit79 */
	u8 twt_responder_support : 1; /*bit78 */
	u8 twt_requester_support : 1; /*bit77 */
	u8 Reserved9 : 5;			  /*bit72~bit76 */
#endif
	u8 Reserveda : 7;				  /*bit87~81 */
	u8 complete_nontxbss_profile : 1; /*bit80 */
#endif
} PACK_END IEEEtypes_Ext_Cap_t;

typedef struct IEEEtypes_Extended_Cap_Element
{
	u8 ElementId;
	IEEEtypes_Len_t Len;
	IEEEtypes_Ext_Cap_t ExtCap;
} PACK_END IEEEtypes_Extended_Cap_Element_t;

typedef struct IEEEtypes_20_40_Coexist
{
#ifdef MV_CPU_LE
	u8 Inform_Request : 1;
	u8 FortyMhz_Intorant : 1;
	u8 TwentyMhz_BSS_Width_Request : 1;
	u8 OBSS_Scanning_Exemption_Request : 1;
	u8 OBSS_Scanning_Exemption_Grant : 1;
	u8 Reserved : 3;
#else // MV_CPU_BE
	u8 Reserved : 3;
	u8 OBSS_Scanning_Exemption_Grant : 1;
	u8 OBSS_Scanning_Exemption_Request : 1;
	u8 TwentyMhz_BSS_Width_Request : 1;
	u8 FortyMhz_Intorant : 1;
	u8 Inform_Request : 1;
#endif
} PACK_END IEEEtypes_20_40_Coexist_t;

typedef struct IEEEtypes_20_40_BSS_COEXIST_Element
{
	u8 ElementId;
	IEEEtypes_Len_t Len;
	IEEEtypes_20_40_Coexist_t Coexist;
} PACK_END IEEEtypes_20_40_BSS_COEXIST_Element_t;

typedef struct IEEEtypes_OVERLAP_BSS_SCAN_PARAMETERS_Element
{
	u8 ElementId;
	IEEEtypes_Len_t Len;
	u16 Scan_Passive;
	u16 Scan_Active;
	u16 Channel_Width_Trigger_Scan_Interval;
	u16 Scan_Passive_Total_Per_Channel;
	u16 Scan_Active_Total_Per_Channel;
	u16 Width_Channel_Transition_Delay_Factor;
	u16 Scan_Activity_Threshold;

} PACK_END IEEEtypes_OVERLAP_BSS_SCAN_PARAMETERS_Element_t;

typedef struct IEEEtypes_20_40_INTOLERANT_CHANNEL_REPORT_Element
{
	IEEEtypes_ElementId_t ElementId;
	IEEEtypes_Len_t Len;
	u8 RegClass;
	u8 ChanList[IEEEtypes_MAX_CHANNELS + IEEEtypes_MAX_CHANNELS_A];
} PACK_END IEEEtypes_20_40_INTOLERANT_CHANNEL_REPORT_Element_t;

typedef struct IEEEtypes_20_40_Coexist_Act
{
	u8 Category;
	u8 Action;
	IEEEtypes_20_40_BSS_COEXIST_Element_t Coexist_Report;
	IEEEtypes_20_40_INTOLERANT_CHANNEL_REPORT_Element_t Intolerant_Report;

} PACK_END IEEEtypes_20_40_Coexist_Act_t;

/** currently b company use this oui for High thruput element 51 **/
typedef struct IEEEtypes_Generic_HT_Element_t
{
	u8 ElementId;
	IEEEtypes_Len_t Len;
	u8 OUI[3];
	u8 OUIType;
	IEEEtypes_HT_Cap_t HTCapabilitiesInfo;
	u8 MacHTParamInfo;
	u8 SupportedMCSset[16];
	u16 ExtHTCapabilitiesInfo;
	u32 TxBFCapabilities;
	u8 ASCapabilities;
} PACK_END IEEEtypes_Generic_HT_Element_t;

/** Just for I_COMP **/
typedef struct IEEEtypes_Generic_HT_Element_t2
{
	u8 ElementId;
	IEEEtypes_Len_t Len;
	u8 OUI[3];
	u8 OUIType;
	IEEEtypes_Len_t Len2;
	IEEEtypes_HT_Cap_t HTCapabilitiesInfo;
	u8 MacHTParamInfo;
	u8 SupportedMCSset[16];
	u16 ExtHTCapabilitiesInfo;
	u32 TxBFCapabilities;
	u8 ASCapabilities;
} PACK_END IEEEtypes_Generic_HT_Element_t2;

typedef struct IEEEtypes_Add_HT_Chan_t
{
#ifdef MV_CPU_LE
	u8 ExtChanOffset : 2;
	u8 STAChannelWidth : 1;
	u8 RIFSMode : 1;
	u8 PSMPStasOnly : 1;
	u8 SrvcIntvlGran : 3;
#else
	u8 SrvcIntvlGran : 3;
	u8 PSMPStasOnly : 1;
	u8 RIFSMode : 1;
	u8 STAChannelWidth : 1;
	u8 ExtChanOffset : 2;
#endif
} PACK_END IEEEtypes_Add_HT_Chan_t;

typedef struct IEEEtypes_Add_HT_OpMode_t
{
#ifdef MV_CPU_LE
	u16 OpMode : 2;
	u16 NonGFStaPresent : 1;
	u16 TransBurstLimit : 1;
	u16 NonHTStaPresent : 1;
#ifdef SUPPORTED_EXT_NSS_BW
	u16 center_freq2 : 8;
	u16 Rsrv : 3;
#else
	u16 Rsrv : 11;
#endif
#else
	u16 rsvd : 3;
	u16 NonHTStaPresent : 1;
	u16 TransBurstLimit : 1;
	u16 NonGFStaPresent : 1;
	u16 OpMode : 2;
	u16 Rsrv : 8;
#endif
} PACK_END IEEEtypes_Add_HT_OpMode_t;

typedef struct IEEEtypes_Add_HT_STBC_t
{
#ifdef MV_CPU_LE
	u16 BscSTBC : 7;
	u16 DualSTBCProc : 1;
	u16 ScdBcn : 1;
	u16 LSIGTxopProcFullSup : 1;
	u16 PCOActive : 1;
	u16 PCOPhase : 1;
	u16 Rsrv : 4;
#else // MV_CPU_BE
	u16 DualSTBCProc : 1;
	u16 BscSTBC : 7;
	u16 Rsrv : 4;
	u16 PCOPhase : 1;
	u16 PCOActive : 1;
	u16 LSIGTxopProcFullSup : 1;
	u16 ScdBcn : 1;
#endif
} PACK_END IEEEtypes_Add_HT_STBC_t;

typedef struct IEEEtypes_Generic_Add_HT_Element_t
{
	u8 ElementId;
	IEEEtypes_Len_t Len;
	u8 OUI[3];
	u8 OUIType;
	u8 ControlChan;
	IEEEtypes_Add_HT_Chan_t AddChan;
	IEEEtypes_Add_HT_OpMode_t OpMode;
	IEEEtypes_Add_HT_STBC_t stbc;
	u8 BscMCSSet[16];
} PACK_END IEEEtypes_Generic_Add_HT_Element_t;
typedef struct IEEEtypes_Generic_Add_HT_Element_t2
{
	u8 ElementId;
	IEEEtypes_Len_t Len;
	u8 OUI[3];
	u8 OUIType;
	IEEEtypes_Len_t Len2;
	u8 ControlChan;
	IEEEtypes_Add_HT_Chan_t AddChan;
	IEEEtypes_Add_HT_OpMode_t OpMode;
	IEEEtypes_Add_HT_STBC_t stbc;
	u8 BscMCSSet[16];
} PACK_END IEEEtypes_Generic_Add_HT_Element_t2;

typedef struct IEEEtypes_Add_HT_Element_t
{
	u8 ElementId;
	IEEEtypes_Len_t Len;
	u8 ControlChan;
	IEEEtypes_Add_HT_Chan_t AddChan;
	IEEEtypes_Add_HT_OpMode_t OpMode;
	IEEEtypes_Add_HT_STBC_t stbc;
	u8 BscMCSSet[16];
} PACK_END IEEEtypes_Add_HT_Element_t;

typedef struct IEEEtypes_Add_HT_INFO_t
{
	u8 ControlChan;
	IEEEtypes_Add_HT_Chan_t AddChan;
	IEEEtypes_Add_HT_OpMode_t OpMode;
	IEEEtypes_Add_HT_STBC_t stbc;
} PACK_END IEEEtypes_Add_HT_INFO_t;

#define BIP_MIC_SIZE_MAX 16
#define BIP_MIC_SIZE_CMAC_128 8

typedef struct IEEEtypes_MMIE_Element_t
{
	u8 ElementId;		 // id 76
	IEEEtypes_Len_t Len; // len 16
	u16 KeyID;
	u8 IPN[6];
	u8 MIC[BIP_MIC_SIZE_MAX];
} PACK_END IEEEtypes_MMIE_Element_t;
typedef struct IEEEtypes_TimeoutInterval_Element_t
{
	u8 ElementId;		 // id 56
	IEEEtypes_Len_t Len; // len 5
	u8 TIType;			 // Time Units(TUs)
	// 0, 4-255 reserved, 1-Reassociation deadline interval, 2-Key lifetime interval (seconds), 3-Association comebacktime
	u32 TIValue;
} PACK_END IEEEtypes_TimeoutInterval_Element_t;

typedef struct IEEEtypes_Bcn_t
{
	IEEEtypes_TimeStamp_t TimeStamp;
	IEEEtypes_BcnInterval_t BcnInterval;
	IEEEtypes_CapInfo_t CapInfo;
	IEEEtypes_SsIdElement_t SsId;
	IEEEtypes_SuppRatesElement_t SuppRates;
	IEEEtypes_PhyParamSet_t PhyParamSet;
	IEEEtypes_SsParamSet_t SsParamSet;
	IEEEtypes_RSN_IE_t RsnIE;
	IEEEtypes_Tim_t Tim;
	IEEEtypes_ERPInfoElement_t ERPInfo;
	IEEEtypes_ExtSuppRatesElement_t ExtSuppRates;
	IEEEtypes_COUNTRY_IE_t Country;
	IEEEtypes_PowerConstraintElement_t PwrCons;
	IEEEtypes_ChannelSwitchAnnouncementElement_t ChSwAnn;
	IEEEtypes_QuietElement_t Quiet;
	IEEEtypes_TPCRepElement_t TPCRep;
} PACK_END IEEEtypes_Bcn_t;
/* */
/* Beacon message body */
/* */

typedef struct IEEEtypes_DisAssoc_t
{
	IEEEtypes_ReasonCode_t ReasonCode;
	IEEEtypes_MMIE_Element_t mmie;
} PACK_END IEEEtypes_DisAssoc_t;
/* */
/* Disassociation message body */
/* */

typedef struct IEEEtypes_AssocRqst_t
{
	IEEEtypes_CapInfo_t CapInfo;
	IEEEtypes_ListenInterval_t ListenInterval;
	IEEEtypes_SsIdElement_t SsId;
	IEEEtypes_SuppRatesElement_t SuppRates;
	IEEEtypes_PowerCapabilityElement_t PwrCap;
	IEEEtypes_SupportedChannelElement_t Channels;
	IEEEtypes_ExtSuppRatesElement_t ExtSuppRates;
	IEEEtypes_RSN_IE_t RsnIE;
} PACK_END IEEEtypes_AssocRqst_t;

typedef struct
{
#ifdef MV_CPU_LE
	u16 traffic_type : 1;
	u16 tsid : 4;
	u16 direction : 2;
	u16 access_policy : 2;
	u16 aggregation : 1;
	u16 apsd : 1;
	u16 usr_priority : 3;
	u16 ts_info_ack_policy : 2;
	u8 sched : 1;
	u8 rsvd : 7;
#else // MV_CPU_BE
	union
	{
		u16 u16_data;
		struct
		{
			u16 ts_info_ack_policy : 2;
			u16 usr_priority : 3;
			u16 apsd : 1;
			u16 aggregation : 1;
			u16 access_policy : 2;
			u16 direction : 2;
			u16 tsid : 4;
			u16 traffic_type : 1;
		} PACK_END;
	};
	u8 rsvd : 7;
	u8 sched : 1;
#endif
} PACK_END IEEEtypes_TS_info_t;

typedef struct
{
#ifdef MV_CPU_LE
	u16 traffic_type : 1;
	u16 tsid : 4;
	u16 direction : 2;
	u16 access_policy : 2;
	u16 aggregation : 1;
	u16 apsd : 1;
	u16 usr_priority : 3;
	u16 ts_info_ack_policy : 2;
	u8 sched : 1;
	u8 rsvd : 7;
#else // MV_CPU_BE
	union
	{
		u16 u16_data;
		struct
		{
			u16 ts_info_ack_policy : 2;
			u16 usr_priority : 3;
			u16 apsd : 1;
			u16 aggregation : 1;
			u16 access_policy : 2;
			u16 direction : 2;
			u16 tsid : 4;
			u16 traffic_type : 1;
		};
	};
	u8 rsvd : 7;
	u8 sched : 1;
#endif
} Mrvl_TS_info_t;

typedef struct
{
	u8 ElementId;
	u8 Len;
	IEEEtypes_TS_info_t ts_info;
	u16 nom_msdu_size; /*nominal msdu size */
	u16 max_msdu_size;
	u32 min_SI;			 /*minimum service interval */
	u32 max_SI;			 /*maximum service interval */
	u32 inactive_intrvl; /*inactivity interval */
	u32 suspen_intrvl;	 /*Suspension interval */
	u32 serv_start_time; /*service start time */
	u32 min_data_rate;
	u32 mean_data_rate;
	u32 peak_data_rate;
	u32 max_burst_size;
	u32 delay_bound;
	u32 min_phy_rate;
	u16 srpl_bw_allow; /*Surplus bandwidth allowance */
	u16 med_time;	   /*medium time */
} PACK_END IEEEtypes_TSPEC_t;

typedef struct
{
	u8 ElementId;
	u8 Len;
	Mrvl_TS_info_t ts_info;
	// u8 ts_info[3];
	u16 nom_msdu_size; /*nominal msdu size */
	u16 max_msdu_size;
	u32 min_SI;			 /*minimum service interval */
	u32 max_SI;			 /*maximum service interval */
	u32 inactive_intrvl; /*inactivity interval */
	u32 suspen_intrvl;	 /*Suspension interval */
	u32 serv_start_time; /*service start time */
	u32 min_data_rate;
	u32 mean_data_rate;
	u32 peak_data_rate;
	u32 max_burst_size;
	u32 delay_bound;
	u32 min_phy_rate;
	u16 srpl_bw_allow; /*Surplus bandwidth allowance */
	u16 med_time;	   /*medium time */
} Mrvl_TSPEC_t;

typedef struct
{
	IEEEtypes_MacAddr_t src_addr;
	IEEEtypes_MacAddr_t dst_addr;
	u16 type;
} PACK_END Classif_type_0;

typedef struct
{
	u8 ver;
	u8 src_IP_addr[4];
	u8 dst_IP_addr[4];
	u16 src_port;
	u16 dst_port;
	u8 DSCP;
	u8 protocol;
	u8 rsvd;

} PACK_END Classif_type_1_IPv4;

typedef struct
{
	u8 ver;
	u8 src_IP_addr[4];
	u8 dst_IP_addr[4];
	u16 src_port;
	u16 dst_port;
	u8 flow_label[3];

} PACK_END Classif_type_1_IPv6;

typedef struct
{
	u16 eight02_dot_1_tag;
} PACK_END Classif_type_2;

typedef union
{
	Classif_type_0 classif_0;
	Classif_type_1_IPv4 classif_1_IPv4;
	Classif_type_1_IPv6 classif_1_IPv6;
	Classif_type_2 classif_0_IPv2;

} PACK_END Frm_Classif_Params_t;

typedef struct
{
	u8 classif_type;
	u8 classif_mask;
	Frm_Classif_Params_t classif_params;
} PACK_END Frm_classifier_t;

typedef struct
{
	u8 ElementId;
	u8 Len;
	u8 usr_priority;
	Frm_classifier_t frm_classifier;
} PACK_END TCLAS_t;

typedef struct
{
	u8 OUI[3];
	u8 Type;
	u8 Subtype;
} PACK_END OUI_t;

typedef struct
{
#ifdef MV_CPU_LE
	u8 EDCA_param_set_update_cnt : 4; // EDCA parameter set update count
#ifndef WMM_PS_SUPPORT
	u8 Q_ack : 1;
	u8 Q_req : 1;
	u8 TXOP_req : 1;
	u8 more_data_ack : 1;
#else
	u8 Reserved : 3;
	u8 U_APSD : 1;
#endif
#else // MV_CPU_BE
#ifndef WMM_PS_SUPPORT
	u8 more_data_ack : 1;
	u8 TXOP_req : 1;
	u8 Q_req : 1;
	u8 Q_ack : 1;
#else
	u8 U_APSD : 1;
	u8 Reserved : 3;
#endif
	u8 EDCA_param_set_update_cnt : 4;
#endif
} PACK_END QoS_Info_t;

#ifdef WMM_PS_SUPPORT
typedef struct
{
#ifdef MV_CPU_LE
	u8 EDCA_param_set_update_cnt : 4; // EDCA parameter set update count
	u8 Q_ack : 1;
	u8 Q_req : 1;
	u8 TXOP_req : 1;
	u8 more_data_ack : 1;
#else // MV_CPU_BE
	u8 more_data_ack : 1;
	u8 TXOP_req : 1;
	u8 Q_req : 1;
	u8 Q_ack : 1;
	u8 EDCA_param_set_update_cnt : 4;
#endif
} PACK_END QoS_Wsm_Info_t;
#endif

typedef struct
{
	u8 ElementId;
	u8 Len;
	OUI_t OUI;
	u8 version;
#ifdef WMM_PS_SUPPORT
	QoS_Wsm_Info_t QoS_info;
#else
	QoS_Info_t QoS_info;
#endif
} PACK_END WSM_QoS_Cap_Elem_t;
typedef struct
{
	u8 ElementId;
	u8 Len;
	OUI_t OUI;
	u8 version;
	IEEEtypes_TS_info_t ts_info;
	u16 nom_msdu_size; /*nominal msdu size */
	u16 max_msdu_size;
	u32 min_SI;			 /*minimum service interval */
	u32 max_SI;			 /*maximum service interval */
	u32 inactive_intrvl; /*inactivity interval */
	u32 suspen_intrvl;	 /*Suspension interval */
	u32 serv_start_time; /*service start time */
	u32 min_data_rate;
	u32 mean_data_rate;
	u32 peak_data_rate;
	u32 max_burst_size;
	u32 delay_bound;
	u32 min_phy_rate;
	u16 srpl_bw_allow; /*Surplus bandwidth allowance */
	u16 med_time;	   /*medium time */
} PACK_END WSM_TSPEC_t;

typedef struct
{
	u8 usr_priority;
	Frm_classifier_t frm_classifier;
} PACK_END WSM_Frm_classifier_t;

typedef struct
{
	u8 ElementId;
	u8 Len;
	OUI_t OUI;
	u8 version;
#ifdef STA_QOS
	WSM_Frm_classifier_t WSM_Frm_classifier;
#else
	u8 usr_priority;
	Frm_classifier_t frm_classifier;
#endif
} PACK_END WSM_TCLAS_Elem_t;

typedef struct
{
	u8 ElementId;
	u8 Len;
	OUI_t OUI;
	u8 version;
	IEEEtypes_TS_info_t ts_info;
} PACK WSM_TSInfo_t;

typedef struct
{
	u8 Category;
	u8 Action;
	WSM_TSInfo_t TSInfo;
	u16 ReasonCode;
} PACK WSM_DELTS_Req_t;

typedef struct
{
	u8 Category;
	u8 Action;
	u8 DialogToken;
	WSM_TSPEC_t TSpec;
	union
	{
		TCLAS_t TCLAS;
		WSM_TCLAS_Elem_t WSM_TCLAS_Elem;
	} TCLAS_u;
} PACK_END IEEEtypes_ADDTS_Req_t;

typedef struct
{
#ifdef MV_CPU_LE
	u16 aggr : 1; /*aggregation */
	u16 TSID : 4;
	u16 dir : 2;
	u16 rsvd : 9;
#else // MV_CPU_BE
	u16 rsvd1 : 1;
	u16 dir : 2;
	u16 TSID : 4;
	u16 aggr : 1; /*aggregation */
	u16 rsvd : 8;
#endif
} PACK_END Sched_Info_Field_t;

typedef struct
{
	u8 ElementId;
	u8 Len;
	Sched_Info_Field_t sched_info;
	u32 serv_start_time;
	u32 serv_intrvl;
	u16 max_serv_duration;
	u16 spec_intrvl; /*specification inverval */

} PACK_END IEEEtypes_Sched_Element_t;

typedef struct
{
	u8 ElementId;
	u8 Len;
	OUI_t OUI;
	u8 version;
	Sched_Info_Field_t sched_info;
	u32 serv_start_time;
	u32 serv_intrvl;
	u16 spec_intrvl; /*specification inverval */
} PACK_END WSM_Sched_Element_t;

typedef union
{
	IEEEtypes_Sched_Element_t Schedule; // check size
	WSM_Sched_Element_t WSM_Schedule;
} Schedule_u;

typedef struct
{
	u8 Category;
	u8 Action;
	u8 DialogToken;
	u16 StatusCode; // check size
	//  u8   TSDelay;     //check size
	WSM_TSPEC_t TSpec;
	union
	{
		Schedule_u Schedule; // check size
		TCLAS_t TCLAS;
		WSM_TCLAS_Elem_t WSM_TCLAS_Elem;
	} TCLAS_u;
	Schedule_u Schedule;
} PACK_END IEEEtypes_ADDTS_Rsp_t;

typedef struct
{
	u8 Category;
	u8 Action;
	IEEEtypes_TS_info_t TSInfo;
} PACK_END IEEEtypes_DELTS_Req_t;

#ifdef WMM_AC_EDCA
typedef struct
{
	u8 Category;
	u8 Action;
	u8 DialogToken;
	u8 StatusCode;
	WSM_TSPEC_t TSpec;
#if 0
	union {
		TCLAS_t TCLAS;
		WSM_TCLAS_Elem_t WSM_TCLAS_Elem;
	} TCLAS_u;
#endif
} PACK_END IEEEtypes_WFA_ADDTS_Req_t;

typedef struct
{
	u8 Category;
	u8 Action;
	u8 DialogToken;
	u8 StatusCode;
	WSM_TSPEC_t TSpec;
#if 0
	union {
		Schedule_u Schedule;	//check size
		TCLAS_t TCLAS;
		WSM_TCLAS_Elem_t WSM_TCLAS_Elem;
	} TCLAS_u;
	Schedule_u Schedule;
#endif
} PACK_END IEEEtypes_WFA_ADDTS_Rsp_t;

typedef struct
{
	u8 Category;
	u8 Action;
	u8 DialogToken;
	u8 StatusCode;
	WSM_TSPEC_t TSpec;
} PACK_END IEEEtypes_WFA_DELTS_Req_t;
#endif /* WMM_AC_EDCA */

typedef struct
{
#ifdef MV_CPU_LE
	u16 amsdu : 1;
	u16 BA_policy : 1;
	u16 tid : 4;
	u16 BufSize : 10;
#else
	union
	{
		u16 u16_data;
		struct
		{
			u16 BufSize : 10;
			u16 tid : 4;
			u16 BA_policy : 1;
			u16 amsdu : 1;
		};
	};
#endif
} PACK_END IEEEtypes_BA_ParamSet_t;

typedef struct
{
#ifdef MV_CPU_LE
	u16 FragNo : 4;
	u16 Starting_Seq_No : 12;
#else // MV_CPU_BE
	union
	{
		u16 u16_data;
		struct
		{
			u16 Starting_Seq_No : 12;
			u16 FragNo : 4;
		};
	};
#endif
} PACK_END IEEEtypes_BA_Starting_Seq_Control_t;

typedef struct
{
#ifdef MV_CPU_LE
	u16 Resvd : 11;
	u16 Initiator : 1;
	u16 tid : 4;
#else
	u16 Resvd : 8;
	u16 tid : 4;
	u16 Initiator : 1;
	u16 Resvd1 : 3;
#endif
} PACK_END IEEEtypes_DELBA_ParamSet_t;

typedef struct
{
	u8 Category;
	u8 Action;
	u8 DialogToken;
	IEEEtypes_BA_ParamSet_t ParamSet;
	u16 Timeout_val;
	IEEEtypes_BA_Starting_Seq_Control_t SeqControl;
	// u16 SeqControl;
} PACK_END IEEEtypes_ADDBA_Req_t;

typedef struct
{
	u8 Category;
	u8 Action;
	u8 DialogToken;
	u16 ParamSet;
	u16 Timeout_val;
	// IEEEtypes_BA_Starting_Seq_Control_t SeqControl;
	u16 SeqControl;
} PACK_END IEEEtypes_ADDBA_Req_t2;

typedef struct
{
	u8 Category;
	u8 Action;
	u8 DialogToken;
	u16 StatusCode; // check size
	IEEEtypes_BA_ParamSet_t ParamSet;
	u16 Timeout_val;
} PACK_END IEEEtypes_ADDBA_Rsp_t;

typedef struct
{
	u8 Category;
	u8 Action;
	IEEEtypes_DELBA_ParamSet_t ParamSet;
	u16 ReasonCode;
} PACK_END IEEEtypes_DELBA_t;

typedef struct
{
	u8 Category;
	u8 Action;
	IEEEtypes_MacAddr_t DstAddr;
	IEEEtypes_MacAddr_t SrcAddr;
	IEEEtypes_CapInfo_t macCapInfo; /* Save this from Start command */
	u16 Timeout_val;
	IEEEtypes_SuppRatesElement_t SuppRates;
} PACK_END IEEEtypes_DlpReq_t;

typedef struct
{
	u8 Category;
	u8 Action;
	u16 StatusCode;
	IEEEtypes_MacAddr_t DstAddr;
	IEEEtypes_MacAddr_t SrcAddr;
	IEEEtypes_CapInfo_t macCapInfo; /* Save this from Start command */
	u16 Timeout_val;
	IEEEtypes_SuppRatesElement_t SuppRates;
} PACK_END IEEEtypes_DlpResp_t;

typedef struct
{
	u8 Category;
	u8 Action;
	IEEEtypes_MacAddr_t DstAddr;
	IEEEtypes_MacAddr_t SrcAddr;
} PACK_END IEEEtypes_DlpTearDown_t;

typedef struct
{
#ifdef MV_CPU_LE
	u16 AckPolicy : 1;
	u16 MTID : 1;
	u16 CompressedBA : 1;
	u16 reserved : 9;
	u16 TID : 4;
#else
	u16 rsv0 : 5;
	u16 CompressedBA : 1;
	u16 MTID : 1;
	u16 AckPolicy : 1;
	u16 TID : 4;
	u16 reserved : 4;
#endif
} PACK_END BA_Cntrl_t;

typedef struct
{
#ifdef MV_CPU_LE
	u16 FragNo : 4;
	u16 StartSeqNo : 12;
#else
	union
	{
		u16 u16_data;
		struct
		{
			u16 StartSeqNo : 12;
			u16 FragNo : 4;
		};
	};
#endif
} PACK_END Sequence_Cntrl_t;

typedef struct
{
	IEEEtypes_FrameCtl_t FrmCtl;
	u16 Duration;
	IEEEtypes_MacAddr_t DestAddr;
	IEEEtypes_MacAddr_t SrcAddr;
	// u8 dummy[8+6];                  //comment out to rx BAR correctly
	BA_Cntrl_t BA_Ctrl;
	Sequence_Cntrl_t Seq_Ctrl;
} PACK_END IEEEtypes_BA_ReqFrame_t2;

typedef struct
{
	u8 Category;
	u8 Action;
	IEEEtypes_ChannelSwitchAnnouncementElement_t Csa;
} PACK_END IEEEtypes_CSA_ACTION_t;

typedef struct
{
	BA_Cntrl_t BA_Ctrl;
	u16 SeqCtl; // starting seq control
} PACK_END IEEEtypes_BA_Req_Body_t;

typedef struct
{
	IEEEtypes_CtlHdr_t Hdr;
	IEEEtypes_BA_Req_Body_t Body;
	u32 FCS;
} PACK_END IEEEtypes_BA_ReqFrame_t;

typedef struct
{
	BA_Cntrl_t BA_Ctrl;
	u16 SeqCtl; // starting seq control
	u8 BitMap[128];
} PACK_END IEEEtypes_BA_Rsp_Body_t;

typedef struct
{
	IEEEtypes_CtlHdr_t Hdr;
	IEEEtypes_BA_Rsp_Body_t Body;
	u32 FCS;
} PACK_END IEEEtypes_BA_RspFrame_t;

typedef struct
{
	u8 ElementId;
	u8 Len;
	u8 QoS_act;
	union
	{
		IEEEtypes_ADDTS_Req_t AddTSReq;
		IEEEtypes_ADDTS_Rsp_t AddTSRsp;
		IEEEtypes_DELTS_Req_t DelTSReq;

	} QoSAction_u;
} PACK_END IEEEtypes_QoSActElem_t; /*QoS action element */

/* */
/* Association request message body */
/* */

typedef struct IEEEtypes_AssocRsp_t
{
	IEEEtypes_CapInfo_t CapInfo;
	IEEEtypes_StatusCode_t StatusCode;
	IEEEtypes_AId_t AId;
	IEEEtypes_SuppRatesElement_t SuppRates;
	IEEEtypes_ExtSuppRatesElement_t ExtSuppRates;
	IEEEtypes_TimeoutInterval_Element_t TimeInterval;
#ifdef QOS_FEATURE_1
	IEEEtypes_QoSActElem_t QosActElem;
#endif
} PACK_END IEEEtypes_AssocRsp_t;
/* */
/* Association response message body */
/* */

typedef struct IEEEtypes_ReassocRqst_t
{
	IEEEtypes_CapInfo_t CapInfo;
	IEEEtypes_ListenInterval_t ListenInterval;
	IEEEtypes_MacAddr_t CurrentApAddr;
	IEEEtypes_SsIdElement_t SsId;
	IEEEtypes_SuppRatesElement_t SuppRates;
	IEEEtypes_PowerCapabilityElement_t PwrCap;
	IEEEtypes_SupportedChannelElement_t Channels;
	IEEEtypes_RSN_IE_t RsnIE;
	IEEEtypes_ExtSuppRatesElement_t ExtSuppRates;
	IEEEtypes_TimeoutInterval_Element_t TimeInterval;
} PACK_END IEEEtypes_ReassocRqst_t;
/* */
/* Reassociation request message body */
/* */

typedef struct IEEEtypes_ReassocRsp_t
{
	IEEEtypes_CapInfo_t CapInfo;
	IEEEtypes_StatusCode_t StatusCode;
	IEEEtypes_AId_t AId;
	IEEEtypes_SuppRatesElement_t SuppRates;
	IEEEtypes_ExtSuppRatesElement_t ExtSuppRates;
} PACK_END IEEEtypes_ReassocRsp_t;
/* */
/* Reassociation response message body */
/* */

typedef struct IEEEtypes_ProbeRqst_t
{
	IEEEtypes_SsIdElement_t SsId;
	IEEEtypes_SuppRatesElement_t SuppRates;
	IEEEtypes_ExtSuppRatesElement_t ExtSuppRates;
} PACK_END IEEEtypes_ProbeRqst_t;
/* */
/* Probe request message body */
/* */

typedef struct IEEEtypes_ProbeRsp_t
{
	IEEEtypes_TimeStamp_t TimeStamp;
	IEEEtypes_BcnInterval_t BcnInterval;
	IEEEtypes_CapInfo_t CapInfo;
	IEEEtypes_SsIdElement_t SsId;
	IEEEtypes_SuppRatesElement_t SuppRates;
	IEEEtypes_PhyParamSet_t PhyParamSet;
	IEEEtypes_SsParamSet_t SsParamSet;
	IEEEtypes_RSN_IE_t RsnIE;
	IEEEtypes_RSN_IE_WPA2_t RsnIEWPA2;
	IEEEtypes_Tim_t Tim;
	IEEEtypes_ERPInfoElement_t ERPInfo;
	IEEEtypes_ExtSuppRatesElement_t ExtSuppRates;

	IEEEtypes_COUNTRY_IE_t Country;
	IEEEtypes_PowerConstraintElement_t PwrCons;
	IEEEtypes_ChannelSwitchAnnouncementElement_t ChSwAnn;
	IEEEtypes_QuietElement_t Quiet;
	IEEEtypes_TPCRepElement_t TPCRep;
} PACK_END IEEEtypes_ProbeRsp_t;
/* */
/* Probe response message body */
/* */

typedef struct IEEEtypes_Auth_t
{
	IEEEtypes_AuthAlg_t AuthAlg;
	IEEEtypes_AuthTransSeq_t AuthTransSeq;
	IEEEtypes_StatusCode_t StatusCode;
	IEEEtypes_ChallengeText_t ChallengeText;
} PACK_END IEEEtypes_Auth_t;
/* */
/* Authentication message body */
/* */

typedef struct IEEEtypes_Deauth_t
{
	IEEEtypes_ReasonCode_t ReasonCode;
	IEEEtypes_MMIE_Element_t mmie;
} PACK_END IEEEtypes_Deauth_t;
/* */
/* Deauthentication message body */
/* */

#define WLAN_SA_QUERY_TR_ID_LEN 2
typedef struct
{
	u8 Category;
	u8 Action;
	u8 trans_id[WLAN_SA_QUERY_TR_ID_LEN];
} PACK_END IEEEtypes_SAQuery_Req_t;
typedef struct
{
	u8 Category;
	u8 Action;
	u8 trans_id[WLAN_SA_QUERY_TR_ID_LEN];
} PACK_END IEEEtypes_SAQuery_Rsp_t;

typedef u8 IEEEtypes_Category_t;
/* SA Query Action frame (IEEE 802.11w/D8.0, 7.4.9) */
#define WLAN_SA_QUERY_REQUEST 0
#define WLAN_SA_QUERY_RESPONSE 1

typedef enum
{
	MEASUREMENT_REQUEST = 0,
	MEASUREMENT_REPORT,
	TPC_REQUEST,
	TPC_REPORT,
	CHANNEL_SWITCH_ANNOUNCEMENT
} IEEEtypes_ActionFieldType_e;
typedef u8 IEEEtypes_ActionFieldType_t;

#define NB_LIST_MAX_NUM 256

#define BSSID_INFO_CAP_SM (1)
#define BSSID_INFO_CAP_QOS (1 << 1)
#define BSSID_INFO_CAP_APSD (1 << 2)
#define BSSID_INFO_CAP_RM (1 << 3)
#define BSSID_INFO_CAP_DLBA (1 << 4)
#define BSSID_INFO_CAP_IMBA (1 << 5)

typedef struct IEEEtypes_Bssid_info_t
{
#ifdef MV_CPU_LE
	u32 ApReachability : 2;
	u32 Security : 1;
	u32 KeyScope : 1;
	u32 Capa_SpectrumMgmt : 1;
	u32 Capa_QoS : 1;
	u32 Capa_APSD : 1;
	u32 Capa_Rrm : 1;
	u32 Capa_DBlckAck : 1;
	u32 Capa_IBlckAck : 1;
	u32 MobilityDomain : 1;
	u32 HT : 1;
	u32 VHT : 1;
	u32 Reserved : 19;
#else
	union
	{
		u32 u32_data;
		struct
		{
			u32 Reserved : 19;
			u32 VHT : 1;
			u32 HT : 1;
			u32 MobilityDomain : 1;
			u32 Capa_IBlckAck : 1;
			u32 Capa_DBlckAck : 1;
			u32 Capa_Rrm : 1;
			u32 Capa_APSD : 1;
			u32 Capa_QoS : 1;
			u32 Capa_SpectrumMgmt : 1;
			u32 KeyScope : 1;
			u32 Security : 1;
			u32 ApReachability : 2;
		};
	};
#endif
} PACK_END IEEEtypes_Bssid_info_t;

typedef struct IEEEtypes_BSS_TERM_DUR_Element_t
{
	IEEEtypes_ElementId_t ElementId;
	IEEEtypes_Len_t Len;
	u64 bss_term_tsf;
	u16 bss_term_dur;
} PACK_END IEEEtypes_BSS_TERM_DUR_Element_t;

typedef struct IEEEtypes_Neighbor_Report_Element_t
{
	IEEEtypes_ElementId_t ElementId;
	IEEEtypes_Len_t Len;
	u8 Bssid[6];
	IEEEtypes_Bssid_info_t BssidInfo;
	u8 RegulatoryClass;
	u8 Channel;
	u8 PhyType;
} PACK_END IEEEtypes_Neighbor_Report_Element_t;

enum dot11PhyType
{
	PHY_FHSS,
	PHY_DSSS,
	PHY_IRBASEBAND,
	PHY_OFDM,
	PHY_HRDSSS,
	PHY_ERP,
	PHY_HT,
	PHY_DMG,
	PHY_VHT
};

typedef struct neighbor_list_entrie_t
{
	IEEEtypes_SsId_t SsId;
	u8 ssid_len;
	u8 not_found_count;
	s32 rssi;
	u8 bssid[IEEEtypes_ADDRESS_SIZE];
	IEEEtypes_Bssid_info_t bssid_info;
	u8 reg_class;
	u8 chan;
	u8 phy_type;
	s32 time_stamp;
	struct IEEEtypes_MOBILITY_DOMAIN_IE_t md_ie;
	u8 width;
	u16 sta_cnt;
	u8 channel_util; /*channel utilization */
	s32 nf;
	u8 bw_2g_40_above; /* 0: default bit(0):above bit(1):below */
} PACK_END neighbor_list_entrie_t;

typedef struct IEEEtypes_BSS_TM_Query_t
{
	u8 QueryReason;
	u8 variable[];
} PACK_END IEEEtypes_BSS_TM_Query_t;

typedef struct IEEEtypes_BSS_TM_Request_t
{
#ifdef MV_CPU_LE
	u8 PrefCandiListInc : 1;
	u8 Abridged : 1;
	u8 DisassocImm : 1;
	u8 BSSTermiInc : 1;
	u8 ESSDisassocImm : 1;
	u8 Reserved : 3;
#else
	u8 Reserved : 3;
	u8 ESSDisassocImm : 1;
	u8 BSSTermiInc : 1;
	u8 DisassocImm : 1;
	u8 Abridged : 1;
	u8 PrefCandiListInc : 1;
#endif
	u16 disassoc_timer;
	u8 validity_interval;
	/* BSS Termination Duration (optional),
	 * Session Information URL (optional),
	 * BSS Transition Candidate List Entries */
	u8 variable[];
} PACK_END IEEEtypes_BSS_TM_Request_t;

typedef struct IEEEtypes_BSS_TM_Resp_t
{
	u8 StatusCode;
	u8 BSSTermiDelay;
	u8 variable[];
} PACK_END IEEEtypes_BSS_TM_Resp_t;

typedef struct IEEEtypes_ActionField_t
{
	IEEEtypes_Category_t Category;
	IEEEtypes_ActionFieldType_t Action;
	u8 DialogToken; /* for coding issue, add extra byte for channel switch action frame */
	union
	{
		IEEEtypes_MeasurementRequestElement_t
			MeasurementRequest[MAX_NR_IE];
		IEEEtypes_MeasurementReportElement_t
			MeasurementReport[MAX_NR_IE];
		IEEEtypes_TPCReqElement_t TPCRequest;
		IEEEtypes_TPCRepElement_t TPCReport;
		IEEEtypes_ChannelSwitchAnnouncementElement_t
			ChannelSwitchAnnouncement;
#ifdef IEEE80211K
		IEEEtypes_RadioMeasurementRequest_t RadioMeasReq;
		IEEEtypes_Neighbor_Report_Element_t
			NeighborReqportElemes[NB_LIST_MAX_NUM];
#endif
		IEEEtypes_BSS_TM_Query_t BSSTMQuery;
		IEEEtypes_BSS_TM_Request_t BSSTMRequest;
		IEEEtypes_BSS_TM_Resp_t BSSTMResponse;
#ifdef AP_TWT
		IEEEtypes_TWT_Element_t TwtElement;
		IEEEtypes_TWT_Information_t TwtInfo;
#endif

	} Data;
} PACK_END IEEEtypes_ActionField_t;

typedef struct IEEEtypes_MimoControl_t
{
#ifdef MV_CPU_LE
	u16 NcIndex : 2;
	u16 NrIndex : 2;
	u16 MimoBw : 1;
	u16 GroupingNg : 2;
	u16 CoeffSizeNb : 2;
	u16 CodeBookInfo : 2;
	u16 RemMatrixSeg : 3;
	u16 Resvd : 2;
#else // MV_CPU_BE
	union
	{
		u16 u16_data;
		struct
		{
			u16 Resvd : 2;
			u16 RemMatrixSeg : 3;
			u16 CodeBookInfo : 2;
			u16 CoeffSizeNb : 2;
			u16 GroupingNg : 2;
			u16 MimoBw : 1;
			u16 NrIndex : 2;
			u16 NcIndex : 2;
		};
	};
#endif
	u32 SoundingTmStp;
} PACK_END IEEEtypes_MimoControl_t;

typedef struct IEEEtypes_VHT_MimoControl_t
{
#ifdef MV_CPU_LE
	u32 NcIdx : 3;
	u32 NrIdx : 3;
	u32 ChanWidth : 2;
	u32 Ng : 2;
	u32 CodeBook : 1;
	u32 FbType : 1;
	u32 RemSeg : 3;
	u32 FstSeg : 1;
	u32 rsvd1 : 2;
	u32 token : 6;
	u32 rsvd2 : 8;
	u32 rsvd3 : 28;
#else // MV_CPU_BE
	u32 rsvd3 : 28;
	u32 rsvd2 : 8;
	u32 token : 6;
	u32 rsvd1 : 2;
	u32 FstSeg : 1;
	u32 RemSeg : 3;
	u32 FbType : 1;
	u32 CodeBook : 1;
	u32 Ng : 2;
	u32 ChanWidth : 2;
	u32 NrIdx : 3;
	u32 NcIdx : 3;
#endif
} PACK_END IEEEtypes_VHT_MimoControl_t;

typedef struct IEEEtypes_HE_MimoControl_t
{
#ifdef MV_CPU_LE
	u32 NcIdx : 3;
	u32 NrIdx : 3;
	u32 ChanWidth : 2;
	u32 Grouping : 1;
	u32 CodeBook : 1;
	u32 FbType : 2;
	u32 RemSeg : 3;
	u32 FstSeg : 1;
	u32 RuStartdIdx : 7;
	u32 RuEndIdx : 7;
	u32 DialogToken : 6;
	u32 SubchBitmapPres : 1;
	u32 rsvd1 : 3;
	u32 SubchBitmap : 8;
	u32 rsvd2 : 12;
#else
	u32 rsvd2 : 12;
	u32 SubchBitmap : 8;
	u32 rsvd1 : 3;
	u32 SubchBitmapPres : 1;
	u32 DialogToken : 6;
	u32 RuEndIdx : 7;
	u32 RuStartdIdx : 7;
	u32 FstSeg : 1;
	u32 RemSeg : 3;
	u32 FbType : 2;
	u32 CodeBook : 1;
	u32 Grouping : 1;
	u32 ChanWidth : 2;
	u32 NrIdx : 3;
	u32 NcIdx : 3;
#endif
} PACK_END IEEEtypes_HE_MimoControl_t;

typedef struct IEEEtypes_CSIReport_t
{
	IEEEtypes_Category_t Category;
	IEEEtypes_ActionFieldType_t Action;
	IEEEtypes_MimoControl_t Mimo;
	union
	{
		u8 Snr[64];
		u8 Data[64];
		u8 PhiLamda[64];
	} CSI;
} PACK_END IEEEtypes_CSIReport_t;

typedef struct IEEEtypes_CompBeamReportCode0_t
{
#ifdef MV_CPU_LE
	u8 psi : 1;
	u8 phi : 3;
//    u8 resv : 4; //Pete, check later?
#else
	//    u8 resv : 4;
	u8 phi : 3;
	u8 psi : 1;
#endif
} PACK_END IEEEtypes_CompBeamReportCode0_t;

typedef struct IEEEtypes_CompBeamReportCode1_t
{
#ifdef MV_CPU_LE
	u8 psi : 2;
	u8 phi : 4;
//    u8 resv : 2; //Pete, check later?
#else
	//    u8 resv : 2;
	u8 phi : 4;
	u8 psi : 2;
#endif
} PACK_END IEEEtypes_CompBeamReportCode1_t;

typedef struct IEEEtypes_CompBeamReportCode2_t
{
#ifdef MV_CPU_LE
	u8 psi : 3;
	u8 phi : 5;
#else
	u8 phi : 5;
	u8 psi : 3;
#endif
} PACK_END IEEEtypes_CompBeamReportCode2_t;

// not used?
typedef struct IEEEtypes_CompBeamReportCode3_t
{
#ifdef MV_CPU_LE
	u32 psi : 4;
	u32 phi : 6;
#else
	u32 phi : 6;
	u32 psi : 4;
#endif
} PACK_END IEEEtypes_CompBeamReportCode3_t;

typedef struct IEEEtypes_CompBeamReportCode4_t
{
#ifdef MV_CPU_LE
	u32 psi : 5;
	u32 phi : 7;
#else
	u32 phi : 7;
	u32 psi : 5;
#endif
} PACK_END IEEEtypes_CompBeamReportCode4_t;

typedef struct IEEEtypes_CompBeamReportCode5_t
{
#ifdef MV_CPU_LE
	u32 psi : 7;
	u32 phi : 9;
#else
	u32 phi : 9;
	u32 psi : 7;
#endif
} PACK_END IEEEtypes_CompBeamReportCode5_t;

typedef struct IEEEtypes_VHT_CompBeamReport_t
{
	IEEEtypes_Category_t Category;
	IEEEtypes_ActionFieldType_t Action;
	IEEEtypes_VHT_MimoControl_t Mimo;
	union
	{
		IEEEtypes_CompBeamReportCode1_t Code1[512];
		IEEEtypes_CompBeamReportCode3_t Code3[512];
		IEEEtypes_CompBeamReportCode3_t Code4[512];
		IEEEtypes_CompBeamReportCode3_t Code5[512];
	} Code;
} PACK_END IEEEtypes_VHT_CompBeamReport_t;

typedef struct IEEEtypes_HE_CompBeamReport_t
{
	IEEEtypes_Category_t Category;
	IEEEtypes_ActionFieldType_t Action;
	IEEEtypes_HE_MimoControl_t Mimo;
	union
	{
		IEEEtypes_CompBeamReportCode1_t Code1[512];
		IEEEtypes_CompBeamReportCode3_t Code3[512];
		IEEEtypes_CompBeamReportCode3_t Code4[512];
		IEEEtypes_CompBeamReportCode3_t Code5[512];
	} Code;
} PACK_END IEEEtypes_HE_CompBeamReport_t;

/*---------------------------------------------------------------------------*/
/*              IEEE 802.11 MLME SAP Interface Data Structures               */
/*                                                                           */
/* According to IEEE 802.11, services are provided by the MLME to the SME.   */
/* In the current architecture, the services are provided to the SME by the  */
/* MAC Management Service Task. This section describes data structures       */
/* needed for these services.                                                */
/*---------------------------------------------------------------------------*/

typedef struct
{
	IEEEtypes_InfoElementExtHdr_t hdr;
	u8 ColorSwitchCountDown;
	u8 NewBSSColor : 6;
	u8 Reserved : 2;
} PACK_END IEEEtypes_Color_Change_Ann_Element_t;

// Random Access Parameter Set (RAPS)
typedef struct
{
	IEEEtypes_InfoElementExtHdr_t hdr;
	u8 EOCWmin : 3;
	u8 EOCWmax : 3;
	u8 Reserved : 2;
} PACK_END IEEEtypes_RAPS_Element_t;

#define HE_SUPPORT_40MHZ_BW_24G 0x1
#define HE_SUPPORT_40_80MHZ_BW_5G 0x2
#define HE_SUPPORT_160MHZ_BW_5G 0x4
#define HE_SUPPORT_80P80MHZ_BW_5G 0x8
#define HE_SUPPORT_242TONE_24G 0x10
#define HE_SUPPORT_242TONE_5G 0x20

typedef struct
{
	u32 dual_band_support : 1;						   /* bit 0 */
	u32 channel_width_set : 7;						   /* bit 1-7 */
	u32 punctured_preamble_rx : 4;					   /* bit 8-11 */
	u32 device_class : 1;							   /* bit 12 */
	u32 ldpc_coding_in_payload : 1;					   /* bit 13 */
	u32 he_ltf_gi_for_he_ppdus : 1;					   /* bit 14 */
	u32 midamble_rx_max_nsts : 2;					   /* bit 15-16 */
	u32 ndp_with4x_he_ltf_3p2ms_gi : 1;				   /* bit 17 */
	u32 stbc_less_80mhz_tx : 1;						   /* bit 18 */
	u32 stbc_less_80mhz_rx : 1;						   /* bit 19 */
	u32 doppler_tx : 1;								   /* bit 20 */
	u32 doppler_rx : 1;								   /* bit 21 */
	u32 full_bw_ul_mu : 1;							   /* bit 22 */
	u32 partial_bw_ul_mu : 1;						   /* bit 23 */
	u32 dcm_max_constellation_tx : 2;				   /* bit 24-25 */
	u32 dcm_max_nss_tx : 1;							   /* bit 26 */
	u32 dcm_max_constellation_rx : 2;				   /* bit 27-28 */
	u32 dcm_max_nss_rx : 1;							   /* bit 29 */
	u32 rx_he_mu_ppdu_from_nonap_sta : 1;			   /* bit 30 */
	u32 su_beamformer : 1; /* bit 31 */				   /* DWORD 0 */
	u32 su_beamformee : 1;							   /* bit 32 */
	u32 mu_beamformer : 1;							   /* bit 33 */
	u32 beamformee_sts_le_80mhz : 3;				   /* bit 34-36 */
	u32 beamformee_sts_gt_80mhz : 3;				   /* bit 37-39 */
	u32 sounding_dimension_le_80mhz : 3;			   /* bit 40-42 */
	u32 sounding_dimension_gt_80mhz : 3;			   /* bit 43-45 */
	u32 ng_16_for_su_feedback : 1;					   /* bit 46 */
	u32 ng_16_for_mu_feedback : 1;					   /* bit 47 */
	u32 codebook_size_4_2_for_su : 1;				   /* bit 48 */
	u32 codebook_size_7_5_for_mu : 1;				   /* bit 49 */
	u32 triggered_su_beamforming_feedback : 1;		   /* bit 50 */
	u32 triggered_mu_beamforming_feedback : 1;		   /* bit 51 */
	u32 triggered_cqi_feedback : 1;					   /* bit 52 */
	u32 partial_bw_ext_range : 1;					   /* bit 53 */
	u32 partial_bw_dl_mu_mimo : 1;					   /* bit 54 */
	u32 ppe_threshold_present : 1;					   /* bit 55 */
	u32 srp_based_sr_support : 1;					   /* bit 56 */
	u32 power_boost_factor_support : 1;				   /* bit 57 */
	u32 he_su_and_mu_ppdu_4xhe_ltf : 1;				   /* bit 58 */
	u32 max_nc : 3;									   /* bit 59-61 */
	u32 stbc_greater_80m_tx : 1;					   /* bit 62 */
	u32 stbc_greater_80m_rx : 1;					   /* bit 63 */
	u8 he_er_su_ppdu_4xhe_ltf : 1;					   /* bit 64 */
	u8 he_20m_in_40m_ppdu_24g_band : 1;				   /* bit 65 */
	u8 he_20mhz_in_160mhz_ppdu : 1;					   /* bit 66 */
	u8 he_80mhz_in_160mhz_ppdu : 1;					   /* bit 67 */
	u8 he_er_su_ppdu_1xhe_ltf : 1;					   /* bit 68 */
	u8 midamble_rx_2x_1x_he_ltf : 1;				   /* bit 69 */
	u8 dcm_max_bw : 2;								   /* bit 70-71 */
	u16 longer_16sigb_ofdm_sym_support : 1;			   /* bit 72 */
	u16 non_triggered_cqi_feedback : 1;				   /* bit 73 */
	u16 tx_1024qam_lt_242tone_ru_Support : 1;		   /* bit 74 */
	u16 rx_1024qam_lt_242tone_ru_Support : 1;		   /* bit 75 */
	u16 rx_full_su_using_he_mu_with_comp_sigb : 1;	   /* bit 76 */
	u16 rx_full_su_using_he_mu_with_non_comp_sigb : 1; /* bit 77 */
	u16 nominal_packet_padding : 2;					   /* bit 78-79 */
	u16 reserved : 8;								   /* bit 80-87 */
} PACK_END HE_Phy_Capabilities_Info_t;

typedef struct
{
	u32 htc_he_support : 1;						   // bit 0
	u32 twt_request_support : 1;				   // bit 1
	u32 twt_responder_support : 1;				   // bit 2
	u32 frammentation_support : 2;				   // bit 3-4
	u32 max_fragmented_msdus : 3;				   // bit 5-7
	u32 min_fragment_size : 2;					   // bit 8-9
	u32 trigger_frame_mac_duration : 2;			   // bit 10-11
	u32 multi_tid_aggregation_support : 3;		   // bit 12-14
	u32 he_link_adaption : 2;					   // bit 15-16
	u32 all_ack_support : 1;					   // bit 17
	u32 ul_mu_resp_sched_suport : 1;			   // bit 18
	u32 a_bsr_support : 1;						   // bit 19
	u32 broadcast_twt_support : 1;				   // bit 20
	u32 ba_bitmap_support_32bit : 1;			   // bit 21
	u32 mu_cascade_support : 1;					   // bit 22
	u32 ack_multi_tid_aggr_support : 1;			   // bit 23
	u32 group_addr_multi_sta_ba_dl_mu : 1;		   // bit 24
	u32 omi_a_control_support : 1;				   // bit 25
	u32 ofmda_ra_support : 1;					   // bit 26
	u32 max_ampdu_exponent : 2;					   // bit 27-28
	u32 amsdu_fragmentation_support : 1;		   // bit 29
	u32 flexible_twt_sched_support : 1;			   // bit 30
	u32 rx_ctrl_frame_to_multibss : 1;			   // bit 31
	u16 bsrp_ampdu_aggregation : 1;				   /* bit 32 */
	u16 qtp_support : 1;						   /* bit 33 */
	u16 a_brq_support : 1;						   /* bit 34 */
	u16 sr_responder : 1;						   /* bit 35 */
	u16 ndp_feedback_report : 1;				   /* bit 36 */
	u16 ops : 1;								   /* bit 37 */
	u16 amsdu_in_ampdu : 1;						   /* bit 38 */
	u16 multi_tid_aggr_tx_support : 3;			   /* bit 39-41 */
	u16 he_subch_select_tx_support : 1;			   /* bit 42 */
	u16 ul_2x996tone_ru_support : 1;			   /* bit 43 */
	u16 om_ctrl_ul_mu_data_disable_rx_support : 1; /* bit 44 */
	u16 he_dynamic_sm_power_save : 1;			   /* bit 45 */
	u16 punctured_sounding_support : 1;			   /* bit 46 */
	u16 ht_and_vht_trigger_frame_rx_support : 1;   /* bit 47 */
} PACK_END HE_Mac_Capabilities_Info_t;

#define MAX_BW_MODE 5
#define MAX_NSS 8

typedef union
{
	u16 max_mcs_set;
	struct
	{
		u16 max_mcs_1ss : 2; /* bit 0-1 */
		u16 max_mcs_2ss : 2; /* bit 2-3 */
		u16 max_mcs_3ss : 2; /* bit 4-5 */
		u16 max_mcs_4ss : 2; /* bit 6-7 */
		u16 max_mcs_5ss : 2; /* bit 8-9 */
		u16 max_mcs_6ss : 2; /* bit 10-11 */
		u16 max_mcs_7ss : 2; /* bit 12-13 */
		u16 max_mcs_8ss : 2; /* bit 14-15 */
	};
} PACK_END he_mcs_nss_support_t;

#define MAX_RU_NUM 4
#define MAX_PPE_THRESHOLD_INFO_LENGTH ((7 + 2 * 3 * MAX_RU_NUM * MAX_NSS + 7) / 8)
#define MAX_TX_RX_HE_MCS_SUPPORT_FIELD_LENGTH 12

typedef struct
{
	u32 ppet0 : 3;
	u32 ppet1 : 3;
	u32 ppet2 : 3;
	u32 ppet3 : 3;
	u32 ppet4 : 3;
	u32 ppet5 : 3;
	u32 ppet6 : 3;
	u32 ppet7 : 3;
} PACK_END ppet8_ppe16_t;

typedef struct
{
	u16 nss_m1 : 3;
	u16 ru_idx_mask : 4;
	u16 ppet0 : 3;
	u16 ppet1 : 3;
	u16 ppet2 : 3;
} PACK_END ppe_threshold_info_t;

#define PPE_CONSTELLATION_BPSK 0
#define PPE_CONSTELLATION_QPSK 1
#define PPE_CONSTELLATION_16QAM 2
#define PPE_CONSTELLATION_64QAM 3
#define PPE_CONSTELLATION_256QAM 4
#define PPE_CONSTELLATION_1024QAM 5
#define PPE_CONSTELLATION_RESERVED 6
#define PPE_CONSTELLATION_NONE 7

#define BANDWIDTH_20MHZ 0x1
#define BANDWIDTH_40MHZ 0x2
#define BANDWIDTH_80MHZ 0x4
#define BANDWIDTH_80PLUS80MHZ 0x8
#define BANDWIDTH_160MHZ 0x10

#define SC5_5G_SUPPORTED_TX_BW (BANDWIDTH_20MHZ | BANDWIDTH_40MHZ | BANDWIDTH_80MHZ | BANDWIDTH_80PLUS80MHZ)
#define SC5_5G_SUPPORTED_RX_BW (BANDWIDTH_20MHZ | BANDWIDTH_40MHZ | BANDWIDTH_80MHZ | BANDWIDTH_80PLUS80MHZ)

#define MAX_RX_VHT_MCS_SET (VHT_MCS_0_9 | (VHT_MCS_0_9 << 2) |         \
							(VHT_MCS_0_9 << 4) | (VHT_MCS_0_9 << 6) |  \
							(VHT_MCS_0_9 << 8) | (VHT_MCS_0_9 << 10) | \
							(VHT_MCS_0_9 << 12) | (VHT_MCS_0_9 << 14))

#define MAX_TX_VHT_MCS_SET (VHT_MCS_0_9 | (VHT_MCS_0_9 << 2) |         \
							(VHT_MCS_0_9 << 4) | (VHT_MCS_0_9 << 6) |  \
							(VHT_MCS_0_9 << 8) | (VHT_MCS_0_9 << 10) | \
							(VHT_MCS_0_9 << 12) | (VHT_MCS_0_9 << 14))

#define SC5_HE_RX_80M_MCS_SET (HE_MCS_0_11 | (HE_MCS_0_11 << 2) |         \
							   (HE_MCS_0_11 << 4) | (HE_MCS_0_11 << 6) |  \
							   (HE_MCS_0_11 << 8) | (HE_MCS_0_11 << 10) | \
							   (HE_MCS_0_11 << 12) | (HE_MCS_0_11 << 14))

#define SC5_HE_TX_80M_MCS_SET (HE_MCS_0_11 | (HE_MCS_0_11 << 2) |         \
							   (HE_MCS_0_11 << 4) | (HE_MCS_0_11 << 6) |  \
							   (HE_MCS_0_11 << 8) | (HE_MCS_0_11 << 10) | \
							   (HE_MCS_0_11 << 12) | (HE_MCS_0_11 << 14))

#define SC5_HE_RX_160M_MCS_SET (HE_MCS_0_11 | (HE_MCS_0_11 << 2) |         \
								(HE_MCS_0_11 << 4) | (HE_MCS_0_11 << 6) |  \
								(HE_MCS_0_11 << 8) | (HE_MCS_0_11 << 10) | \
								(HE_MCS_0_11 << 12) | (HE_MCS_0_11 << 14))

#define SC5_HE_TX_160M_MCS_SET (HE_MCS_0_11 | (HE_MCS_0_11 << 2) |         \
								(HE_MCS_0_11 << 4) | (HE_MCS_0_11 << 6) |  \
								(HE_MCS_0_11 << 8) | (HE_MCS_0_11 << 10) | \
								(HE_MCS_0_11 << 12) | (HE_MCS_0_11 << 14))

#define SC5_HE_RX_80MP80M_MCS_SET (HE_MCS_0_11 | (HE_MCS_0_11 << 2) |         \
								   (HE_MCS_0_11 << 4) | (HE_MCS_0_11 << 6) |  \
								   (HE_MCS_0_11 << 8) | (HE_MCS_0_11 << 10) | \
								   (HE_MCS_0_11 << 12) | (HE_MCS_0_11 << 14))

#define SC5_HE_TX_80MP80M_MCS_SET (HE_MCS_0_11 | (HE_MCS_0_11 << 2) |         \
								   (HE_MCS_0_11 << 4) | (HE_MCS_0_11 << 6) |  \
								   (HE_MCS_0_11 << 8) | (HE_MCS_0_11 << 10) | \
								   (HE_MCS_0_11 << 12) | (HE_MCS_0_11 << 14))

#define SC5_HE_BASIC_MCS_SET (HE_MCS_0_7 | (HE_NSS_NOT_SUPPORT << 2) |                 \
							  (HE_NSS_NOT_SUPPORT << 4) | (HE_NSS_NOT_SUPPORT << 6) |  \
							  (HE_NSS_NOT_SUPPORT << 8) | (HE_NSS_NOT_SUPPORT << 10) | \
							  (HE_NSS_NOT_SUPPORT << 12) | (HE_NSS_NOT_SUPPORT << 14))

#define SC5_VHT_BASIC_MCS_SET (VHT_MCS_0_7 | (VHT_NSS_NOT_SUPPORT << 2) |                 \
							   (VHT_NSS_NOT_SUPPORT << 4) | (VHT_NSS_NOT_SUPPORT << 6) |  \
							   (VHT_NSS_NOT_SUPPORT << 8) | (VHT_NSS_NOT_SUPPORT << 10) | \
							   (VHT_NSS_NOT_SUPPORT << 12) | (VHT_NSS_NOT_SUPPORT << 14))

enum
{
	DCM_NOT_SUPPORTED,
	DCM_BPSK,
	DCM_QPSK,
	DCM_16QAM
};

enum
{
	DCM_MAX_BW_20M,
	DCM_MAX_BW_40M,
	DCM_MAX_BW_80M,
	DCM_MAX_BW_160M
};

#define HE_CLASS_A 1
#define HE_CLASS_B 0

typedef struct
{
	IEEEtypes_InfoElementExtHdr_t hdr;
	HE_Mac_Capabilities_Info_t mac_cap;
	HE_Phy_Capabilities_Info_t phy_cap;
	he_mcs_nss_support_t rx_he_mcs_80m;
	he_mcs_nss_support_t tx_he_mcs_80m;
	/* HE CAP IE has variable length. Reserve the max length */
	u8 hecap_ext[MAX_TX_RX_HE_MCS_SUPPORT_FIELD_LENGTH +
				 MAX_PPE_THRESHOLD_INFO_LENGTH -
				 2 * sizeof(he_mcs_nss_support_t)];
} PACK_END HE_Capabilities_IE_t; /* fix length part of HE CAP IE */

typedef struct
{
	u16 default_pe_duration : 3;		  /* bit 0-2 */
	u16 twt_required : 1;				  /* bit 3 */
	u16 txop_duration_rts_threshold : 10; /* bit 4-13 */
	u16 vht_op_info_present : 1;		  /* bit 14 */
	u16 co_located_bss : 1;				  /* bit 15 */
	u8 er_su_disable : 1;				  /* bit 16 */
	u8 six_g_op_info_present : 1;		  /* bit 17 */
	u8 reserved : 6;					  /* bit 18-23 */
} PACK_END He_operation_parameters_t;

typedef struct
{
	u8 bss_color : 6;		   /* bit 0-5 */
	u8 partial_bss_color : 1;  /* bit 6 */
	u8 bss_color_disabled : 1; /* bit 7 */
} PACK_END bss_color_info_t;

typedef struct
{
	u8 channel_width;
	u8 channel_center_freq_0;
	u8 channel_center_freq_1;
} PACK_END vht_operation_info_t;

#define VHT_MCS_0_7 0
#define VHT_MCS_0_8 1
#define VHT_MCS_0_9 2
#define VHT_NSS_NOT_SUPPORT 3

#define HE_MCS_0_7 0
#define HE_MCS_0_9 1
#define HE_MCS_0_11 2
#define HE_NSS_NOT_SUPPORT 3

typedef struct
{
	IEEEtypes_InfoElementExtHdr_t hdr;
	He_operation_parameters_t he_op_param;
	bss_color_info_t bss_color_info;
	he_mcs_nss_support_t basic_mcs_nss_set;
	u8 heop_ext[sizeof(vht_operation_info_t) + 1]; /* 1 byte for MaxBSSID Indicator */
} PACK_END HE_Operation_IE_t;

#ifndef AP_TWT
typedef struct
{
	u8 ndp_paging_indicator : 1;  // bit 0
	u8 responder_pm_mode : 1;	  // bit 1
	u8 broadcast : 1;			  // bit 2
	u8 wake_tbtt_negotiation : 1; // bit 3
	u8 reserved : 4;			  // bit 4-7
} PACK_END Twt_Control_t;

typedef struct
{
	u16 twt_request : 1;		   // bit 0
	u16 twt_setup_command : 3;	   // bit 1-3
	u16 trigger : 1;			   // bit 4
	u16 implicit : 1;			   // bit 5
	u16 flow_type : 1;			   // bit 6
	u16 twt_flow_id : 3;		   // bit 7-9
	u16 twt_wake_interval_exp : 5; // bit 10-14
	u16 twt_protection : 1;		   // bit 15
} PACK_END Twt_request_type_t;
#endif

typedef struct
{
	u8 ID;
	u8 length;
} PACK_END TWT_IE_t;

/*---------------------*/
/* BSS Description Set */
/*---------------------*/
#define STA_VENDOR_IE_BUF_MAX_LEN 384

typedef struct IEEEtypes_BssDesc_t
{
	IEEEtypes_MacAddr_t BssId;
	IEEEtypes_SsId_t SsId;
	IEEEtypes_Bss_t BssType;
	IEEEtypes_BcnInterval_t BcnPeriod;
	IEEEtypes_DtimPeriod_t DtimPeriod;
	IEEEtypes_TimeStamp_t Tstamp;
	IEEEtypes_TimeStamp_t StartTs;
	IEEEtypes_PhyParamSet_t PhyParamSet;
	IEEEtypes_SsParamSet_t SsParamSet;
	IEEEtypes_CapInfo_t Cap;
	IEEEtypes_DataRate_t DataRates[IEEEtypes_MAX_DATA_RATES_G];
	/* 11n related elements */
	IEEEtypes_HT_Element_t HTElement;
	IEEEtypes_Add_HT_Element_t ADDHTElement;
	/*11ac related element */
	IEEEtypes_VhtCap_t VHTCap;
	IEEEtypes_VhOpt_t VHTOp;
	/*11ax related element */
#if defined(SOC_W906X) || defined(SOC_W9068)
	HE_Capabilities_IE_t hecap;
	HE_Operation_IE_t heop;
#endif /* #if defined(SOC_W906X) || defined(SOC_W9068) */
	/* RSN (WPA2) */
	IEEEtypes_RSN_IE_WPA2_t Wpa2Element;
	/* Vendor Specific IEs */
	u8 vendorIENum;
	u8 vendorTotalLen;
	u8 vendorBuf[STA_VENDOR_IE_BUF_MAX_LEN];
	/* End Vendor Specific IEs */

} PACK_END IEEEtypes_BssDesc_t;
/* */
/* A description of a BSS, providing the following: */
/* BssId:        The ID of the BSS */
/* SsId:         The SSID of the BSS */
/* BssType:      The type of the BSS (INFRASTRUCTURE or INDEPENDENT) */
/* BcnPeriod:    The beacon period (in time units) */
/* DtimPeriod:   The DTIM period (in beacon periods) */
/* Tstamp:       Timestamp of a received frame from the BSS; this is an 8 */
/*                  byte string from a probe response or beacon */
/* StartTs:      The value of a station's timing synchronization function */
/*                  at the start of reception of the first octet of the */
/*                  timestamp field of a received frame (probe response or */
/*                  beacon) from a BSS; this is an 8 byte string */
/* PhyParamSet:  The parameter set relevant to the PHY (empty if not */
/*                  needed by the PHY) */
/* SsParamSet:   The service set parameters. These can consist of either */
/*                  the parameter set for CF periods or for an IBSS. */
/* Cap:          The advertised capabilities of the BSS */
/* DataRates:    The set of data rates that must be supported by all */
/*                  stations (the BSS basic rate set) */
/* */

typedef struct IEEEtypes_BssDescSet_t
{
	u8 NumSets;
	IEEEtypes_BssDesc_t BssDesc[IEEEtypes_MAX_BSS_DESCRIPTS];
} PACK_END IEEEtypes_BssDescSet_t;
/* */
/* The set of BSS descriptions */
/* */

/*-------------------*/
/* MLME SAP Messages */
/*-------------------*/
typedef struct IEEEtypes_RequestSet_t
{
	u8 MeasurementToken;
	IEEEtypes_MeasurementReqMode_t Mode;
	IEEEtypes_MeasurementReqType_t Type;
	IEEEtypes_MeasurementReq_t Request;
} IEEEtypes_RequestSet_t;

typedef struct IEEEtypes_ReportSet_t
{
	u8 MeasurementToken;
	IEEEtypes_MeasurementRepMode_t Mode;
	IEEEtypes_MeasurementRepType_t Type;
	IEEEtypes_MeasurementRep_t Report;
} IEEEtypes_ReportSet_t;

/*
 *  for request
 */

typedef struct IEEEtypes_MRequestCmd_t
{
	IEEEtypes_MacAddr_t PeerStaAddr;
	u8 DiaglogToken;
	u8 MeasureItems; /* number of IEs in MeasureReqSet */
	IEEEtypes_RequestSet_t MeasureReqSet[MAX_NR_IE];
} PACK_END IEEEtypes_MRequestCmd_t;

typedef struct IEEEtypes_MRequestCfrm_t
{
	IEEEtypes_MRequestResult_t Result;
} PACK_END IEEEtypes_MRequestCfrm_t;

typedef struct IEEEtypes_MRequestInd_t
{
	IEEEtypes_MacAddr_t PeerStaAddr;
	u8 DiaglogToken;
	u8 RequestItems; /* number of IEs in MeasureReqSet */
	IEEEtypes_RequestSet_t MeasureReqSet[MAX_NR_IE];
} PACK_END IEEEtypes_MRequestInd_t;

/*
 *  for measure
 */

typedef struct IEEEtypes_MeasureCmd_t
{
	IEEEtypes_MacAddr_t PeerStaAddr;
	u8 DiaglogToken;
	IEEEtypes_RequestSet_t MeasureReqSet[MAX_NR_IE];
} PACK_END IEEEtypes_MeasureCmd_t;

typedef struct IEEEtypes_MeasureCfrm_t
{
	IEEEtypes_MeasureResult_t Result;
	u8 DiaglogToken;
	IEEEtypes_ReportSet_t MeasureReqSet[MAX_NR_IE];
} PACK_END IEEEtypes_MeasureCfrm_t;

/*
 *  for report
 */

typedef struct IEEEtypes_MReportCmd_t
{
	IEEEtypes_MacAddr_t PeerStaAddr;
	u8 DiaglogToken;
	u8 ReportItems; /* number of IEs in MeasureReqSet */
	IEEEtypes_ReportSet_t MeasureRepSet[MAX_NR_IE];
} PACK_END IEEEtypes_MReportCmd_t;

typedef struct IEEEtypes_MReportCfrm_t
{
	IEEEtypes_MReportResult_t Result;
} PACK_END IEEEtypes_MReportCfrm_t;

typedef struct IEEEtypes_MReportInd_t
{
	IEEEtypes_MacAddr_t PeerStaAddr;
	u8 DiaglogToken;
	u8 ReportItems; /* number of IEs in MeasureReqSet */
	IEEEtypes_ReportSet_t MeasureRepSet[MAX_NR_IE];
} PACK_END IEEEtypes_MReportInd_t;

/*
 *  for channel switch
 */
typedef struct IEEEtypes_ChannelSwitchCmd_t
{
	u8 Mode;
	u8 ChannelNumber;
	u8 ChannelSwitchCount;
} PACK_END IEEEtypes_ChannelSwitchCmd_t;

typedef struct IEEEtypes_ChannelSwitchCfrm_t
{
	IEEEtypes_ChannelSwitchResult_t Result;
} PACK_END IEEEtypes_ChannelSwitchCfrm_t;

typedef struct IEEEtypes_ChannelSwitchInd_t
{
	IEEEtypes_MacAddr_t PeerStaAddr;
	u8 Mode;
	u8 ChannelNumber;
	u8 ChannelSwitchCount;
} PACK_END IEEEtypes_ChannelSwitchInd_t;

typedef struct IEEEtypes_ChannelSwitchResp_t
{
	u8 Mode;
	u8 ChannelNumber;
	u8 ChannelSwitchCount;
} PACK_END IEEEtypes_ChannelSwitchResp_t;

/*
 *  for TPC adaptive
 */

typedef struct IEEEtypes_TPCAdaptCmd_t
{
	IEEEtypes_MacAddr_t PeerStaAddr;
	u8 DiaglogToken;
} PACK_END IEEEtypes_TPCAdaptCmd_t;

typedef struct IEEEtypes_TPCAdaptCfrm_t
{
	IEEEtypes_TPCAdaptResult_t Result;
} PACK_END IEEEtypes_TPCAdaptCfrm_t;

/*
Data structure to hold the Cipher Suites of AP's while scanning
*/
typedef struct
{
	u8 MulticastCipher[4];
	u8 UnicastCipher[4];
} WPA_AP_Ciphers_t;

typedef struct IEEEtypes_PwrMgmtCmd_t
{
	IEEEtypes_PwrMgmtMode_t PwrMgmtMode;
	boolean WakeUp;
	boolean RcvDTIMs;
} PACK_END IEEEtypes_PwrMgmtCmd_t;
/* */
/* Power management request message from the SME */
/* */

typedef struct IEEEtypes_PwrMgmtCfrm_t
{
	IEEEtypes_PwrMgmtResult_t Result;
} PACK_END IEEEtypes_PwrMgmtCfrm_t;
/* */
/* Power management confirm message sent from the MLME as a result */
/* of a power management request; it is sent after the change has */
/* taken place */
/* */

typedef struct IEEEtypes_ScanCmd_t
{
	IEEEtypes_Bss_t BssType;
	IEEEtypes_MacAddr_t BssId;
	IEEEtypes_SsId_t SsId;
	IEEEtypes_Scan_t ScanType;
	u16 ProbeDelay;
	u8 ChanList[IEEEtypes_MAX_CHANNELS + IEEEtypes_MAX_CHANNELS_A];
	/*u8                Reserved; */
	u16 MinChanTime;
	u16 MaxChanTime;
} PACK_END IEEEtypes_ScanCmd_t;
/* */
/* Scan request message from the SME to determine if there are BSSs */
/* that can be joined */
/* */
/* Note: The "Reserved" field is inserted for alignment for */
/* commands coming from the host */
/* */

typedef struct IEEEtypes_ScanCfrm_t
{
	IEEEtypes_BssDescSet_t BssDescSet;
	IEEEtypes_ScanResult_t Result;
	IEEEtypes_COUNTRY_IE_t Country;
} PACK_END IEEEtypes_ScanCfrm_t;
/* */
/* Scan confirm message sent from the MLME as a result of a scan request; */
/* it reports the results of the scan */
/* */

typedef struct IEEEtypes_JoinCmd_t
{
	IEEEtypes_BssDesc_t BssDesc;
	u16 FailTimeout;
	u16 ProbeDelay;
#ifndef ERP
	IEEEtypes_DataRate_t OpRateSet[IEEEtypes_MAX_DATA_RATES];
#else
	IEEEtypes_DataRate_t OpRateSet[IEEEtypes_MAX_DATA_RATES_G];
#endif
} PACK_END IEEEtypes_JoinCmd_t;
/* */
/* Join request message from the SME to establish synchronization with */
/* a BSS */
/* */

typedef struct IEEEtypes_JoinCfrm_t
{
	IEEEtypes_JoinResult_t Result;
} PACK_END IEEEtypes_JoinCfrm_t;
/* */
/* Join confirm message sent from the MLME as a result of a join request; */
/* it reports the result of the join */
/* */

typedef struct IEEEtypes_AuthCmd_t
{
	IEEEtypes_MacAddr_t PeerStaAddr;
	u16 FailTimeout;
	IEEEtypes_AuthType_t AuthType;
} PACK_END IEEEtypes_AuthCmd_t;
/* */
/* Authenticate request message sent from the SME to establish */
/* authentication with a specified peer MAC entity */
/* */

typedef struct IEEEtypes_AuthCfrm_t
{
	IEEEtypes_MacAddr_t PeerStaAddr;
	IEEEtypes_AuthType_t AuthType;
	IEEEtypes_AuthResult_t Result;
} PACK_END IEEEtypes_AuthCfrm_t;
/* */
/* Authenticate confirm message sent from the MLME as a result of an */
/* authenticate request; it reports the result of the authentication */
/* */

typedef struct IEEEtypes_AuthInd_t
{
	IEEEtypes_MacAddr_t PeerStaAddr;
	IEEEtypes_AuthType_t AuthType;
} PACK_END IEEEtypes_AuthInd_t;
/* */
/* Authenticate indication message sent from the MLME to report */
/* authentication with a peer MAC entity that resulted from an */
/* authentication procedure that was initiated by that MAC entity */
/* */

typedef struct IEEEtypes_DeauthCmd_t
{
	IEEEtypes_MacAddr_t PeerStaAddr;
	IEEEtypes_ReasonCode_t Reason;
} PACK_END IEEEtypes_DeauthCmd_t;
/* */
/* Deauthenticate request message sent from the SME to invalidate */
/* authentication with a specified peer MAC entity */
/* */

typedef struct IEEEtypes_DeauthCfrm_t
{
	IEEEtypes_MacAddr_t PeerStaAddr;
	IEEEtypes_DeauthResult_t Result;
} PACK_END IEEEtypes_DeauthCfrm_t;
/* */
/* Deauthenticate confirm message sent from the MLME as a result of a */
/* deauthenticate request message; it reports the result of the */
/* deauthentication */
/* */

typedef struct IEEEtypes_DeauthInd_t
{
	IEEEtypes_MacAddr_t PeerStaAddr;
	IEEEtypes_ReasonCode_t Reason;
} PACK_END IEEEtypes_DeauthInd_t;
/* */
/* Deauthentication indication message sent from the MLME to report */
/* invalidation of an authentication with a peer MAC entity; the message */
/* is generated as a result of an invalidation of the authentication */
/* */

typedef struct IEEEtypes_AssocCmd_t
{
	IEEEtypes_MacAddr_t PeerStaAddr;
	IEEEtypes_SsId_t SsId;
	u16 FailTimeout;
	IEEEtypes_CapInfo_t CapInfo;
	IEEEtypes_ListenInterval_t ListenInterval;
	IEEEtypes_SupportedChannelElement_t SupportedChannel;
} PACK_END IEEEtypes_AssocCmd_t;
/* */
/* Association request message sent from the SME to establish an */
/* association with an AP */
/* */

typedef struct IEEEtypes_AssocCfrm_t
{
	IEEEtypes_AssocResult_t Result;
} PACK_END IEEEtypes_AssocCfrm_t;
/* */
/* Association confirm message sent from the MLME as a result of an */
/* association request message; it reports the result of the assoication */
/* */

typedef struct IEEEtypes_AssocInd_t
{
	IEEEtypes_MacAddr_t PeerStaAddr;
} PACK_END IEEEtypes_AssocInd_t;
/* */
/* Association indication message sent from the MLME to report an */
/* association with a specified peer MAC entity acting as an AP; the */
/* indication is the result of an association procedure that was */
/* initiated by the peer MAC entity */
/* */

typedef struct IEEEtypes_ReassocCmd_t
{
	IEEEtypes_MacAddr_t NewApAddr;
	IEEEtypes_SsId_t SsId;
	u16 FailTimeout;
	IEEEtypes_CapInfo_t CapInfo;
	IEEEtypes_ListenInterval_t ListenInterval;
	IEEEtypes_SupportedChannelElement_t SupportedChannel;
} PACK_END IEEEtypes_ReassocCmd_t;
/* */
/* Reassociation request message sent from the SME to change association */
/* to a specified new peer MAC entity acting as an AP */
/* */

typedef struct IEEEtypes_ReassocCfrm_t
{
	IEEEtypes_ReassocResult_t Result;
} PACK_END IEEEtypes_ReassocCfrm_t;
/* */
/* Reassociation confirm message sent from the MLME as the result of a */
/* reassociate request message; it reports the result of the reassociation */
/* */

typedef struct IEEEtypes_ReassocInd_t
{
	IEEEtypes_MacAddr_t PeerStaAddr;
} PACK_END IEEEtypes_ReassocInd_t;
/* */
/* Reassociate indication message sent from the MLME to report a */
/* reassociation with a specified peer MAC entity; the */
/* indication is the result of a reassociation procedure that was */
/* initiated by the peer MAC entity */
/* */

typedef struct IEEEtypes_DisassocCmd_t
{
	IEEEtypes_MacAddr_t PeerStaAddr;
	IEEEtypes_ReasonCode_t Reason;
} PACK_END IEEEtypes_DisassocCmd_t;
/* */
/* Disassociate request message sent from the SME to establish */
/* disassociation with an AP */
/* */

typedef struct IEEEtypes_DisassocCfrm_t
{
	IEEEtypes_DisassocResult_t Result;
} PACK_END IEEEtypes_DisassocCfrm_t;
/* */
/* Disassociate confirm message sent from the MLME as a result of a */
/* disassociate request message; it reports the result of the */
/* disassociation */
/* */

typedef struct IEEEtypes_DisassocInd_t
{
	IEEEtypes_MacAddr_t PeerStaAddr;
	IEEEtypes_ReasonCode_t Reason;
} PACK_END IEEEtypes_DisassocInd_t;
/* */
/* Disassociate indication message sent from the MLME to report the */
/* invalidation of an association relationship with a peer MAC entity; */
/* the message is generated as a result of an invalidation of an */
/* association relationship */
/* */

typedef struct IEEEtypes_ResetCmd_t
{
	IEEEtypes_MacAddr_t StaAddr;
	boolean SetDefaultMIB;
	boolean quiet;
	u32 mode;
} PACK_END IEEEtypes_ResetCmd_t;
/* */
/* Reset request message sent from the SME to reset the MAC to initial */
/* conditions; the reset must be used prior to a start command */
/* */

typedef struct IEEEtypes_ResetCfrm_t
{
	IEEEtypes_ResetResult_t Result;
} PACK_END IEEEtypes_ResetCfrm_t;
/* */
/* Reset confirm message sent from the MLME as a result of a reset */
/* request message; it reports the result of the reset */
/* */

/* */
/* Start request message sent from the SME to start a new BSS; the BSS */
/* may be either an infrastructure BSS (with the MAC entity acting as the */
/* AP) or an independent BSS (with the MAC entity acting as the first */
/* station in the IBSS) */
/* */

typedef struct IEEEtypes_StartCfrm_t
{
	IEEEtypes_StartResult_t Result;
} PACK_END IEEEtypes_StartCfrm_t;
/* */
/* Start confirm message sent from the MLME as a result of a start request */
/* message; it reports the results of the BSS creation procedure */
/* */

typedef struct IEEEtypes_Frame_t
{
	IEEEtypes_GenHdr_t Hdr;
	u8 Body[8];
} PACK_END IEEEtypes_Frame_t;

typedef struct
{
#ifdef MV_CPU_LE
	u16 tid : 4;
	u16 eosp : 1;
	u16 ack_policy : 2;
	u16 amsdu : 1;
	u16 var_data : 8; /*signifies TXOP limit or TXOP duration request or Q size */
#else				  // MV_CPU_BE
	u16 amsdu : 1;
	u16 ack_policy : 2;
	u16 eosp : 1;
	u16 tid : 4;
	u16 var_data : 8;
#endif
} PACK_END IEEEtypes_QoS_Ctl_t;

typedef struct
{
	u8 ElementId;
	u8 Len;
	u32 delay;
} PACK_END IEEEtypes_TS_Delay_t;

typedef struct
{
	u8 ElementId;
	u8 Len;
	OUI_t OUI;
	u8 version;
	u32 delay;
} PACK_END WSM_TS_Delay_t;

typedef union
{
	IEEEtypes_TS_Delay_t TsDealy; // check size
	WSM_TS_Delay_t WSM_TsDealy;
} TS_Delay_u;

typedef enum
{
	COEX_2040,
	DSE_Enable,

} IEEEtypes_Public_Act_e;

typedef enum
{
	NORMAL_ACK,
	NO_ACK,
	NO_EXPLICIT_ACK,
	BLCK_ACK
} IEEEtypes_AckPolicy_e;

typedef enum
{
	UPLINK,
	DOWNLINK,
	DIRECTLINK,
	BIDIRLINK
} Direction_e;

typedef enum
{
	ADDBA_REQ,
	ADDBA_RESP,
	DELBA
} IEEEtypes_BA_Act_e;

typedef enum
{
	DLP_REQ,
	DLP_RESP,
	DLP_TEAR_DOWN
} IEEEtypes_DLP_Act_e;

typedef enum
{
	VHT_COMPRESSED_BF,
	GROUP_ID_MGMT,
	OPERATING_MODE_NOTIFICATION
} IEEEtypes_VHT_Act_e;

typedef enum
{
	None,
	SPECTRUM_MANAGEMENT = 0,
	QoS,	// Traffic Stream Setup
	DLP,	// Direct link Protocol
	BlkAck, // Block Ack
	WLAN_ACTION_SA_QUERY = 8,
#ifdef WMM_AC_EDCA
	WFA = 17, // Reserved for WFA. It's used by AddTS/DelTS too.
#endif
	VHT = 21,
	// twt
	S1G = 22, // 802.11ah 9.4.1.11
} IEEEtypes_Action_QoS_Category_e,
	IEEEtypes_QoS_Category_e;

typedef enum
{
	DELAYED,
	IMMEDIATE
} IEEEtypes_QoS_BA_Policy_e;
typedef enum
{
	RSVD,
	EDCA,
	HCCA,
	BOTH
} IEEEtypes_QoS_Access_Policy_e;

typedef enum
{
	WSM_CAPABILITY = 5,
	WSM_TCLAS,
	WSM_TCLAS_PROCESSING,
	WSM_TS_DELAY,
	WSM_SCHED,
	WSM_ACTN_HDR
} WSM_OUI_SubType_e;

#ifdef STA_QOS
typedef enum
{
	TS_SETUP_EVT,
	TS_SETUP_THRU_ASSOCREQ_EVT,
	TS_SETUP_TIMEOUT_EVT,
	ADDTSRSP_EVT,
	DEL_TS_EVT
} TS_Setup_e;

typedef struct
{
#ifdef MV_CPU_LE
	u16 rsvd : 12;
	u16 TID : 4;
#else
	u16 rsvd : 8;
	u16 TID : 4;
	u16 rsv1 : 4;
#endif
} PACK_END IEEEtypes_BA_Cntrl_t;

typedef struct
{
	IEEEtypes_FrameCtl_t FrmCtl;
	u16 DurationId;
	IEEEtypes_MacAddr_t RA;
	IEEEtypes_MacAddr_t TA;
	IEEEtypes_BA_Cntrl_t BA_Cntrl;
	u16 Start_Seq_Cntrl;
	u8 bitmap[128];
} PACK_END IEEEtypes_Block_Ack_t;

typedef struct
{
	IEEEtypes_FrameCtl_t FrmCtl;
	u16 DurationId;
	IEEEtypes_MacAddr_t RA;
	IEEEtypes_MacAddr_t TA;
	IEEEtypes_BA_Cntrl_t BAR_Cntrl;
	u16 Start_Seq_Cntrl;
} PACK_END IEEEtypes_Block_Ack_Req_t;

typedef struct
{
	u8 ElementId;
	u8 Len;
	u16 sta_cnt;
	u8 channel_util;	 /*channel utilization */
	u16 avail_admit_cap; /*available admission capacity */
} PACK_END QBSS_load_t;
typedef struct
{
	u8 ElementId;
	u8 Len;
	u32 delay;
} PACK_END TS_delay_t;

typedef struct
{
	u8 ElementId;
	u8 Len;
	u8 processing;

} PACK_END TCLAS_Processing_t;

typedef struct
{
	u8 ElementId;
	u8 Len;
	QoS_Info_t QoS_info;

} PACK_END QoS_Cap_Elem_t;

typedef enum
{
	ADDTS_REQ,
	ADDTS_RSP,
	DELTS,
	QOS_SCHEDULE
} IEEEtypes_QoS_Act_e;

typedef enum
{
	ADDTS_REQ,
	ADDTS_RSP,
	DELTS,
	QOS_SCHEDULE
} IEEEtypes_QoS_Act_e;

#endif

typedef struct RetryCntQoS_S
{
	u8 retrycfgenable;
	u8 retrycntBK;
	u8 retrycntBE;
	u8 retrycntVI;
	u8 retrycntVO;
} RetryCntQoS_t;

#define SPECTRUM_MANAGE_CATEGOTY 0
#define ACTION_EXTCHANSWTANNO 4
#define RADIO_MEASURE_CATEGOTY 5
#define HT_CATEGORY 7
#define VHT_CATEGORY 21
#define HE_CATEGORY 30

#define ACTION_SMPS 1
#define ACTION_PSMP 2
#define ACTION_PCOPHA 3
#define ACTION_MIMO_CSI_REPORT 4
#define ACTION_MIMO_NONCOMP_REPORT 5
#define ACTION_MIMO_COMP_REPORT 6
#define ACTION_INFOEXCH 8
#ifdef COEXIST_20_40_SUPPORT
#define ACTION_NOTIFYCHANNELWIDTH 0
#define ACTION_PUBLIC 4
#endif
#define ACTION_SA_QUERY 8
#define ACTION_PROTECTED_DUAL_OF_PUBLIC_ACTION 9

#define PUBLIC_ACTION_GAS_INITIAL_REQ 10
#define PUBLIC_ACTION_GAS_INITIAL_RESP 11
#define PUBLIC_ACTION_GAS_COMEBACK_REQ 12
#define PUBLIC_ACTION_GAS_COMEBACK_RESP 13

/* Action field Category values */
typedef enum
{
	AC_RADIO_MEASUREMENT = 5,
	AC_WNM = 10
} IEEEtypes_Action_Category_e;

typedef enum
{
	AF_RM_MEASUREMENT_REQUEST = 0,
	AF_RM_MEASUREMENT_REPORT,
	AF_RM_LINK_REQUEST,
	AF_RM_LINK_REPORT,
	AF_RM_NEIGHBOR_REQUEST,
	AF_RM_NEIGHBOR_RESPONSE,
	AF_WNM_BTM_QUERY = 6,
	AF_WNM_BTM_REQUEST = 7,
	AF_WNM_BTM_RESPONSE = 8,
} IEEEtypes_RM_ActionFieldType_e;

typedef struct
{
#ifdef MV_CPU_LE
	u8 Enable : 1;
	u8 Mode : 1;
	u8 Rev : 6;
#else
	u8 Rev : 6;
	u8 Mode : 1;
	u8 Enable : 1;
#endif
} PACK_END IEEEtypes_SM_PwrCtl_t;

typedef struct
{
	u8 BandWidth;

} PACK_END IEEEtypes_BWCtl_t;

typedef struct
{
#ifdef MV_CPU_LE
	u8 InfoReq : 1;
	u8 FortyMIntolerant : 1;
	u8 ChWd : 1;
	u8 Rev : 5;
#else
	u8 Rev : 5;
	u8 ChWd : 1;
	u8 FortyMIntolerant : 1;
	u8 InfoReq : 1;
#endif
} PACK_END IEEEtypes_InfoExch_t;

typedef struct IEEEtypes_MeasurementReqBcn_t
{
	u8 RegClass;
	u8 ChanNum;
	u16 RandInterval;
	u16 Duration;
	u8 Mode;
	u8 BSSID[6];
	u8 ReportCondi;
	u8 Threshold_offset;
	u8 SSID[34];
} PACK_END IEEEtypes_MeasurementReqBcn_t;

typedef struct IEEEtypes_MeasurementRequestEL_t
{
	IEEEtypes_ElementId_t ElementId;
	IEEEtypes_Len_t Len;
	u8 Token;
	IEEEtypes_MeasurementReqMode_t Mode;
	IEEEtypes_MeasurementReqType_t Type;
	IEEEtypes_MeasurementReqBcn_t Request;
} PACK_END IEEEtypes_MeasurementRequestEl_t;

typedef struct IEEEtypes_ExtendChanSwitchAnnounceEl_t
{
	IEEEtypes_ElementId_t ElementId;
	IEEEtypes_Len_t Len;
	u8 Token;
	u8 ChanSwitchMode;
	u8 RegClass;
	u8 ChanNum;
	u8 ChanSwitchCount;
} PACK_END IEEEtypes_ExtendChanSwitchAnnounceEl_t;

/* This is for CateGory 5 struct */
typedef struct IEEEtypes_ManageActionFieldC5_t
{
	u8 DialogToken; /* for coding issue, add extra byte for channel switch action frame */
	u16 NumRepetition;
	union
	{
		IEEEtypes_MeasurementRequestEl_t MeasurementRequestEl;
	} Data;
} PACK_END IEEEtypes_ManageActionFieldC5_t;

typedef struct IEEEtypes_ManageActionField_t
{
	IEEEtypes_Category_t Category;
	IEEEtypes_ActionFieldType_t Action;
	union
	{
		IEEEtypes_ManageActionFieldC5_t Field5;
		IEEEtypes_ExtendChanSwitchAnnounceEl_t
			ExtendChanSwitchAnnounceEl;
		IEEEtypes_SM_PwrCtl_t SmPwrCtl;
		IEEEtypes_InfoExch_t InfoExch;
		IEEEtypes_BWCtl_t BWCtl;

	} Field;
} PACK_END IEEEtypes_ManageActionField_t;

typedef struct IEEEtypes_ChannelReportEL_t
{
	IEEEtypes_ElementId_t ElementId;
	IEEEtypes_Len_t Len;
	u8 RegClass;
	u8 ChanList[IEEEtypes_MAX_CHANNELS + IEEEtypes_MAX_CHANNELS_A];
} PACK_END IEEEtypes_ChannelReportEL_t;

#define MAX_SIZE_RSN_IE_BUF 64 /* number of bytes */
#define MAX_SIZE_DH_IE_BUF 128 /* number of bytes */

#ifdef MRVL_WSC
typedef struct
{
	u16 ID;
	u16 Len;
	u8 Version;
} PACK WSC_Version_Attribute_t;

typedef struct
{
	u16 ID;
	u16 Len;
	u8 ResponseType;
} PACK WSC_ResponseType_Attribute_t;

typedef struct
{
	u16 ID;
	u16 Len;
	u8 VendorID[3];
} PACK WSC_VendorExtn_Attribute_t;

typedef struct
{
	u8 ID;
	u8 Len;
	u8 Version2;
} PACK WSC_Version2_VendorExtn_t;

typedef struct
{
	u8 ElementId;
	u8 Len;
	u8 OUI[WSC_OUI_LENGTH];
	u8 WSCData[WSC_BEACON_IE_MAX_LENGTH];
} PACK WSC_BeaconIE_t;

typedef struct
{
	u8 ElementId;
	u8 Len;
	u8 OUI[WSC_OUI_LENGTH];
	u8 WSCData[WSC_PROBERESP_IE_MAX_LENGTH];
} PACK WSC_ProbeRespIE_t;

typedef struct
{
	u16 Len;
	u8 WSCData[WSC_BEACON_IE_MAX_LENGTH];
} PACK WSC_BeaconIEs_t, IEEEtypes_WSC_BeaconIE_t;

typedef struct
{
	u16 Len;
	u8 WSCData[WSC_PROBERESP_IE_MAX_LENGTH];
} PACK WSC_ProbeRespIEs_t, IEEEtypes_WSC_ProbeRespIE_t;

typedef union
{
	WSC_BeaconIEs_t beaconIE;
	WSC_ProbeRespIEs_t probeRespIE;
} PACK WSC_COMB_IE_t;

typedef struct
{
	u16 ElementId;
	u16 Len;
} PACK_END WSC_HeaderIE_t;

typedef struct
{
	u8 ElementId;
	u8 Len;
	u8 WSC_OUI[WSC_OUI_LENGTH];
	WSC_Version_Attribute_t Version;
	WSC_ResponseType_Attribute_t ResponseType;
	WSC_VendorExtn_Attribute_t VendorExtn;
	WSC_Version2_VendorExtn_t Version2;
} PACK_END AssocResp_WSCIE_t;
#endif // MRVL_WSC

#define WAPI_BEACON_IE_MAX_LENGTH 68
#define WAPI_PROBERESP_IE_MAX_LENGTH 251
typedef struct
{
	u16 Len;
	u8 WAPIData[WAPI_BEACON_IE_MAX_LENGTH];
} PACK WAPI_BeaconIEs_t;

typedef struct
{
	u16 Len;
	u8 WAPIData[WAPI_PROBERESP_IE_MAX_LENGTH];
} PACK WAPI_ProbeRespIEs_t;

typedef union
{
	WAPI_BeaconIEs_t beaconIE;
	WAPI_ProbeRespIEs_t probeRespIE;
} PACK WAPI_COMB_IE_t;

#ifdef MV_CPU_BE
#define IEEE_ETHERTYPE_PAE 0x888e /* EAPOL PAE/802.1x */
#define IEEE_ETHERTYPE_ARP 0x0806 /* Address Resolution packet     */
#define IEEE_QOS_CTL_AMSDU 0x8000
#define ETH_P_WAPI 0x88B4
#else
#define IEEE_QOS_CTL_AMSDU 0x80
#define IEEE_ETHERTYPE_PAE 0x8e88 /* EAPOL PAE/802.1x */
#define IEEE_ETHERTYPE_ARP 0x0608 /* Address Resolution packet     */
#define ETH_P_WAPI 0xB488
#endif

#ifdef SUPPORTED_EXT_NSS_BW
#define VHT_EXTENDED_NSS_BW_CAPABLE 1
#define VHT_EXTENDED_NSS_BW_CAPABLE_BIT (VHT_EXTENDED_NSS_BW_CAPABLE << 29)
#endif

typedef struct
{
	IEEEtypes_MacAddr_t da;
	IEEEtypes_MacAddr_t sa;
	u16 type;
} PACK_END ether_hdr_t;

typedef struct
{
	u8 Category;
	u8 VHT_ACTION;
	u8 MembershipStatusArray[8];
	u8 UserPositionArray[16];
} PACK_END IEEEtypes_GroupIDMgmt_t;

typedef struct
{
	u32 LegacyRateBitMap;
	u32 HTRateBitMap;
	IEEEtypes_CapInfo_t CapInfo;
	IEEEtypes_HT_Cap_t HTCapabilitiesInfo;
	u8 MacHTParamInfo;
	u8 MrvlSta;
	IEEEtypes_Add_HT_INFO_t AddHtInfo;
	u32 TxBFCapabilities;
	u32 vht_MaxRxMcs;
	u32 vht_cap;
	u8 vht_RxChannelWidth; // 0:20Mhz, 1:40Mhz, 2:80Mhz, 3:160 or 80+80Mhz
	RetryCntQoS_t retrycntQoS;
	u8 assocRSSI; // store RSSI when first assoc to determine which rate index to use in rate table
#if defined(SOC_W906X) || defined(SOC_W9068)
	HE_Capabilities_IE_t he_cap;
	HE_Operation_IE_t he_op;
#endif /* #if defined(SOC_W906X) || defined(SOC_W9068) */
} PACK_END PeerInfo_t;

typedef PACK_START struct ACI_AIFSN_field_t
{
#ifdef MV_CPU_LE
	u8 AIFSN : 4;
	u8 ACM : 1;
	u8 ACI : 2;
	u8 rsvd : 1;
#else
	u8 rsvd : 1;
	u8 ACI : 2;
	u8 ACM : 1;
	u8 AIFSN : 4;
#endif
} PACK_END ACI_AIFSN_field_t;

typedef PACK_START struct ECW_min_max_field_t
{
#ifdef MV_CPU_LE
	u8 ECW_min : 4;
	u8 ECW_max : 4;
#else
	u8 ECW_max : 4;
	u8 ECW_min : 4;
#endif
} PACK_END ECW_min_max_field_t;

typedef PACK_START struct AC_param_rcd_t
{
	ACI_AIFSN_field_t ACI_AIFSN;
	ECW_min_max_field_t ECW_min_max;
	u16 TXOP_lim;
} PACK_END AC_param_rcd_t;

typedef PACK_START struct
{
	u8 ElementId;
	u8 Len;
	OUI_t OUI;
	u8 version;
	QoS_Info_t QoS_info;
	u8 rsvd;
	AC_param_rcd_t AC_BE;
	AC_param_rcd_t AC_BK;
	AC_param_rcd_t AC_VI;
	AC_param_rcd_t AC_VO;
} PACK_END WME_param_elem_t;

typedef PACK_START struct
{
	u64 trigger_type : 4;
	u64 ul_length : 12;
	u64 more_flag : 1;
	u64 cs_required : 1;
	u64 ul_bw : 2;
	u64 gi_ltf_type : 2;
	u64 mumimo_ltf_mode : 1;
	u64 num_heltf_midamble : 3;
	u64 ul_stbc : 1;
	u64 ldpc_extra_symbol : 1;
	u64 ap_tx_power : 6;
	u64 ul_pkt_ext : 3;
	u64 ul_spatial_reuse : 16;
	u64 doppler : 1;
	u64 ul_hesig_a2_rsvd : 9;
	u64 rsvd : 1;
} PACK_END tf_commonInfo_t;

typedef PACK_START struct
{
	u32 aid : 12;
	u32 ru_alloc : 8;
	u32 ul_fec_coding_type : 1;
	u32 ul_mcs : 4;
	u32 ul_dcm : 1;
	u32 ss_alloc : 6;
	u8 ul_target_rssi : 7;
	u8 rsvd : 1;
} PACK_END tf_userInfo_base_t;

typedef PACK_START struct
{
	u8 mpdu_mu_spac_fac : 2;
	u8 tid_aggr_limit : 3;
	u8 rsvd1 : 1;
	u8 preferred_ac : 2;
} PACK_END tf_basic_variant_t;

typedef PACK_START struct
{
	u8 fb_bitmap;
} PACK_END tf_bfrp_variant_t;

typedef struct
{
	u8 aifsn : 4;
	u8 acm : 1;
	u8 aci : 2;
	u8 rsvd : 1;

	u8 ecw_min : 4;
	u8 ecw_max : 4;

	u8 timer;

} muedca_entry_t;

typedef PACK_START struct
{
	IEEEtypes_InfoElementExtHdr_t hdr;
	QoS_Info_t QoS_info;
	muedca_entry_t ac[4];
} PACK_END MU_EDCA_param_set_t;

typedef PACK_START struct
{
	u8 srp_disallowed : 1;
	u8 non_srg_obss_pd_sr_disallowed : 1;
	u8 non_srg_offset_present : 1;
	u8 srg_info_present : 1;
	u8 hesiga_spatial_reuse_val15_allowed : 1;
	u8 resv : 3;
} PACK_END SRP_CTRL;

typedef PACK_START struct
{
	IEEEtypes_InfoElementExtHdr_t hdr;
	SRP_CTRL srpc;

} PACK_END SRP_param_set_t;

#endif /* _IEEETYPESCOMMON_H_ */
