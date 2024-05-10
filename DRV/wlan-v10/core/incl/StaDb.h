/** @file StaDb.h
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2002-2020 NXP
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
*    This file contains data types and routines used in accessing the
*    external station information database. This database contains
*    information on other stations (or APs) in a network. The information
*    includes the entity type (AP or station), the MAC address, the power
*    mode, and the station of the entity with respect to the station
*    containing this table.
*
* Public Procedures:
*    extStaDb_AddSta      Add a station to the table
*    extStaDb_DelSta      Delete a station from the table
*    extStaDb_SetState    Set the state of an external station
*    extStaDb_GetState    Get the state of an external station
*    extStaDb_SetPwrMode  Set the power mode of an external station
*    extStaDb_GetPwrMode  Get the power mode of an external station
*
* Notes:
*    None.
*
*****************************************************************************/

#ifndef _STADB_H_
#define _STADB_H_

/*============================================================================= */
/*                               INCLUDE FILES */
/*============================================================================= */
#include "wltypes.h"
#include "IEEE_types.h"
#include "osif.h"

#include "mib.h"
#include "smeMain.h"
#include "util.h"
#include "mib.h"
#include "buildModes.h"
#include "qos.h"
#include "mlme.h"
#include "ds.h"
#include "keyMgmtCommon.h"
#include "keyMgmt.h"
#include "List.h"
#include "ap8xLnxIntf.h"

/*============================================================================= */
/*                          PUBLIC TYPE DEFINITIONS */
/*============================================================================= */
typedef enum {
	LOCATE_SUCCESS,
	ADD_SUCCESS,
	DEL_SUCCESS,
	POWER_SUCCESS,
	STATE_SUCCESS,
	NOT_INITIALIZED,
	LOCATE_FAILURE,
	STATION_EXISTS_ERROR,
	TABLE_ACCESS_ERROR,
	TABLE_FULL_ERROR,
	INVALID_STATE_ERROR,
	NOT_AUTHENTICATED,
	NOT_ASSOCIATED,
	ALREADY_AUTHENTICATED,
	ALREADY_ASSOCIATED,
	ALREADY_AUTHENTICATING,
	ALREADY_ASSOCIATING,
	ALREADY_DEASSOCIATING,
	ALREADY_REASSOCIATING,
#ifdef WPA
	RSN_IE_BUF_OVERFLOW,
#endif
} extStaDb_Status_e;
/* */
/* The set of possible status responses to operations performed on the table */
/* */

typedef enum {
	UNAUTHENTICATED = 0,
	SME_INIT_AUTHENTICATING,
	EXT_INIT_AUTHENTICATING,
	AUTHENTICATED,
	SME_INIT_DEAUTHENTICATING,
	EXT_INIT_DEAUTHENTICATING,
	SME_INIT_ASSOCIATING,
	EXT_INIT_ASSOCIATING,
	ASSOCIATED,
	SME_INIT_REASSOCIATING,
	EXT_INIT_REASSOCIATING,
	SME_INIT_DEASSOCIATING,
	EXT_INIT_DEASSOCIATING,
	/*Milind. 10/10/05. To maintain peer states for when the */
	/*WB associates/joins */
	WB_ASSOCIATED,
	WB_ADHOC_JOINED
} extStaDb_State_e;
typedef UINT8 extStaDb_State_t;
/* */
/* The possible states a station or AP can have with respect to the */
/* station containing the external station table */
/* */

typedef enum {
	BONLY_MODE,
	GONLY_MODE,
	MIXED_MODE,
	AONLY_MODE,
	NONLY_MODE,
	AC_1SS_MODE,
	AC_2SS_MODE,
	AC_3SS_MODE,
} extStaDb_ClientMode_e;

typedef enum {
	MYFALSE,
	MYTRUE
} Boolean;

typedef enum {
	BA_RODR_DROP_DUP,
	BA_RODR_DROP_OOR,
	BA_RODR_DROP_AMSDUENQ,
	BA_RODR_DROP_FLUSH,
	BA_RODR_DROP_TMO,
	BA_RODR_DROP_NUM,
} ba_rodr_drop_reason_e;

#ifdef IEEE80211H
typedef struct basic_info_t {
	BOOLEAN capability;
	UINT32 mToken;
	UINT8 measureStartTime[8];	/* indicates if the Sta is a QSTA */
	UINT16 measureDuration;	/* the duration in which the measurement takes place */
	UINT16 measuredChannel;	/* channel the station is currently measuring */
	IEEEtypes_MeasurementRepMap_t mMap;	/* the result of measurement report */
} basic_info;

typedef struct tcc_info_t {
	BOOLEAN capability;
	UINT32 mToken;
	UINT8 measureStartTime[8];	/* indicates if the Sta is a QSTA */
	UINT16 measureDuration;	/* the duration in which the measurement takes place */
	UINT16 measuredChannel;	/* channel the station is currently measuring */
} tcc_info;

typedef struct rpi_info_t {
	BOOLEAN capability;
	UINT32 mToken;
	UINT8 measureStartTime[8];	/* indicates if the Sta is a QSTA */
	UINT16 measureDuration;	/* the duration in which the measurement takes place */
	UINT16 measuredChannel;	/* channel the station is currently measuring */
} rpi_info;

typedef struct extStaDb_measurement_info_t {
	UINT32 DiaglogToken;
	basic_info mBasic;
	tcc_info mTcc;
	rpi_info mRpi;
} extStaDb_measurement_info_t;

#endif /* IEEE80211h */
typedef struct Frag11n_t {
	struct sk_buff *skb;
	UINT8 *curPosition_p;
	UINT8 status;
	UINT8 status_pre;
	UINT8 pad;
	UINT16 length;
	unsigned long jiffies;	/* should be same size as jiffies of the system */
} Frag11n;
#ifdef DYNAMIC_BA_SUPPORT
typedef struct txACInfo_t {
	UINT32 txa_avgpps;
	unsigned long txa_lastsample;	/* should be same size as jiffies of the system */
	UINT32 txa_pkts;
} txACInfo;
#endif
#define MAX_AGG_QUE 4
typedef struct Aggr11n_t {
	Frag11n Frag[MAX_AGG_QUE];
	UINT8 cap;
	UINT8 index;
	UINT8 on;
	UINT8 start;
	UINT32 txcnt;
	UINT16 threshold;
	UINT8 queon;
	UINT8 nextpktnoaggr;
	 DECLARE_LOCK(Lock);	/* used to protect aggregation */
	struct sk_buff_head txQ;
	UINT16 thresholdBackUp;
	UINT32 txcntbytid[8];
	UINT8 onbytid[8];
	UINT8 startbytid[8];
	UINT8 type;
#ifdef DYNAMIC_BA_SUPPORT
	txACInfo tx_ac_info[MAX_TID];
#endif
	UINT8 ampducfg;
} Aggr11n;
typedef struct {
	struct sk_buff *pFrame;
	UINT16 SeqNo;
	UINT8 FragNo;
} DeFragBufInfo_t;

#define RATEINFO_DWORD_SIZE	(sizeof(dbRateInfo_t) * 2)

/*List node to store all MU capable stations associated to AP*/
typedef struct MUCapStaNode_t {
	struct MUCapStaNode_t *nxt;	/* part of List Object node elments */
	struct MUCapStaNode_t *prv;
	struct extStaDb_StaInfo_t *StaInfo_p;
	UINT8 MUSet_created_flag;	//set to 1 if this station is in a MU group
	UINT8 MUStaList_idx;	//index to MUStaList[8] this node belongs to. VHT 0:20MHz, 1:40MHz, 2:80MHz, 3:160MHz and HE 4:20MHz, 5:40MHz, 6:80MHz, 7:160MHz
} MUCapStaNode_t;

typedef struct {		// Slot for BA re-ordering
	UINT16 SeqNr:12;
	UINT16 setFlag:4;
	UINT8 PN[16];		// 11i PN from Rx buffer
} rx_slot_t;

typedef struct rx_queue_s {	// Block ACK re-ordering state
	UINT16 SeqNr;		// Start of BA reordering Window
	UINT16 prevSeqNum;
	UINT8 RxPN[4][16];	// Next RxPN per Key Index 
	UINT8 InxPN;		// Key Index used by BitMapPN
	rx_slot_t Slots[MAX_BA_REORDER_BUF_SIZE];	// Reordering slots, index by SeqNr LSb
} rx_queue_t;

typedef struct rx_pn_info_s {
	UINT32 ucastBadCnt;
	UINT32 mcastBadCnt;
	UINT32 mgmtBadCnt;
	rx_queue_t ucRxQueues[MAX_TID + 1];	//(8 TID + Non-QoS)
	rx_queue_t mcRxQueues[MAX_TID + 1];	//(8 TID + Non-QoS) 
	rx_queue_t ucMgmtRxQueues;	//Ucast Mgmt for PMF
} rx_pn_info_t;

//rx BA reorder stats
typedef struct rx_ba_stat_s {
	UINT32 BA_Rodr2Host;	//Pkt sent to host count
	UINT32 BA_RodrDupDropCnt;	//Duplicate pkt drop count
	UINT32 BA_RodrOoRDropCnt;	//Out of range seqno drop count
	UINT32 BA_RodrRetryDropCnt;	//Retry drop count
	UINT32 BA_RodrAmsduEnQCnt;	//Enqueue AMSDU pkt error (to be dropped) count
	UINT32 BA_RodrFlushDropCnt;	//Flush any drop count within wEnd range
	UINT32 BA_RodrTMODropCnt;	//Timeout processing drop count
	UINT32 BA_RodrWinEndJumpCnt;	//winDelta > winEnd, winStartB moves cnt after wEnd
	ba_rodr_drop_reason_e BA_RodrLastDropReason;	//The last drop reason
} rx_ba_stat_t;

#ifdef AP_TWT
typedef struct {
	u8 ActFlowID;		//bitmap to present id 0~7
	IEEEtypes_TWT_Element_t twtE[8];
} twt_agreement_t;
#endif

/*
	The last rx ppdu information
*/
typedef struct _rxppdu_airtime_t {
	// rx_info of the last rx-ppdu
	//rx_info_ppdu_t rxinfo;                //  rx_info
	//U32           rxInfoIndex;            // Index of the rx_info
	rx_info_aux_t rx_info_aux;

	U32 rx_airtime;		// airtime of the ppdu
	U32 rx_datlen;		// ppdu packet length, increasing

	// parameters, gotten from rxinfo, ppdu_pkt to calculate the air_time
	U32 dbg_pktcnt, dbg_nss, dbg_mcs, dbg_bw, dbg_gi_ltf, dbg_sum_pktlen,
		dbg_sum_pktcnt;
	U32 dbg_Ndbps10x;
	U32 dbg_su_pktcnt, dbg_mu_pktcnt;
	U64 rx_tsf;
	U64 sum_rx_airtime;
	U64 sum_rx_pktcnt;
	U64 sum_rx_pktlen;
} rxppdu_airtime_t;

typedef struct assoc_req_msg_t {
	IEEEtypes_MgmtHdr_t Hdr;
	union {
		IEEEtypes_AssocRqst_t AssocRqst;
		IEEEtypes_ReassocRqst_t ReassocRqst;
	} Body;
	U32 len;
} assoc_req_msg_t;

typedef struct extStaDb_StaInfo_t {
	IEEEtypes_MacAddr_t Addr;
	IEEEtypes_MacAddr_t Bssid;
	BOOLEAN AP;
	BOOLEAN SmeInitiated;
	extStaDb_State_t State;
	IEEEtypes_PwrMgmtMode_t PwrMode;
	UINT16 StnId;
	UINT16 Aid;
	UINT32 FwStaPtr;
	UINT32 TimeStamp;
	UINT16 QueueToUse;
	UINT8 ClientMode;
	/* new State Machine housekeeping */
	AssocSrvSta mgtAssoc;
	AuthRspSrvSta mgtAuthRsp;
	AuthReqSrvSta mgtAuthReq;
	PowerSaveMonitor pwrSvMon;
	keyMgmthsk_hsm_t keyMgmtHskHsm;
#ifdef STA_INFO_DB
	UINT8 Sq2;		/* Signal Quality 2 */
	UINT8 Sq1;		/* Signal Quality 1 */
	UINT8 Rate;		/* rate at which frame was received */
	UINT8 RSSI;		/* RF Signal Strength Indicator */
#endif
	UINT8 ApMode;
#ifdef QOS_FEATURE
	UINT8 IsStaQSTA;	//indicates if the Sta is a QSTA
	UINT8 MoreDataAck;	//Sta can preocess Ack frames with MoreDataBit in FrmCtl to 1
#endif
#ifdef IEEE80211H
	UINT16 ListenInterval;	/* Listen interveal */
	BOOLEAN IsSpectrumMgmt;	/* Is capable to do spectrum management */
	extStaDb_measurement_info_t measureInfo;
#endif				/* IEEE80211H */
	keyMgmtInfo_t keyMgmtStateInfo;	//keyMgmtInfo;
#ifdef MBO_SUPPORT
	UINT8 AP_MBOIEBuf[12];
#endif				/* MBO_SUPPORT */
#ifdef OWE_SUPPORT
	UINT8 STA_DHIEBuf[MAX_SIZE_DH_IE_BUF];
	UINT8 AP_DHIEBuf[MAX_SIZE_DH_IE_BUF];
	UINT8 EXT_RsnIE[64];
//      struct sk_buff *owe_skb;
//      UINT8    owe_skb_rssi;
#endif				/* OWE_SUPPORT */
#if defined(OWE_SUPPORT) || defined(MBO_SUPPORT)
	struct sk_buff *assocReq_skb;
	UINT8 assocReq_skb_rssi;
#endif				/* OWE_SUPPORT ||  MBO_SUPPORT */
	//keyMgmt_StateInfo_t keyMgmtStateInfo;//keep this as the last element in this data structure
#ifdef APCFGUR
	RemoteCtrlSrv rmSrv;
	UINT8 UR;
#endif
#ifdef PPPoE_SUPPORT
	UINT16 Session_ID;
	//      UINT8   IamWaiting;
#endif
#ifdef WMM_PS_SUPPORT
	QoS_WmeInfo_Info_t Qosinfo;	/** store apsd qosinfo **/
#endif
	Aggr11n aggr11n;
	DeFragBufInfo_t DeFragBufInfo;
	IEEEtypes_HT_Element_t HtElem;
	IEEEtypes_Add_HT_Element_t AddHtElme;
	IEEEtypes_VhtCap_t vhtCap;
	dbRateInfo_t RateInfo;
#ifdef WDS_FEATURE
	void *wdsInfo;
	void *wdsPortInfo;
#endif
	BOOLEAN Client;
	UINT8 IsStaMSTA;
#ifdef MRVL_WSC			//MRVL_WSC_IE
	WSC_ProbeRespIE_t WscIEBuf;
	UINT8 WSCSta;
#endif
	MIB_802DOT11 *mib_p;
	struct net_device *dev;
	IEEEtypes_HT_Cap_t PeerHTCapabilitiesInfo;
	UINT8 StaType;
	UINT8 sbf_slot;
	UINT32 tx_packets;
	UINT32 rx_packets;
	UINT64 tx_bytes;
	UINT64 rx_bytes;
	UINT32 tx_err;
	UINT32 rx_err;
	RssiPathInfo_t RSSI_path;
	UINT8 vht_RxChannelWidth;
	UINT8 vht_peer_RxNss;
	UINT8 mu_sta;		//set 1 when MU group created
	UINT8 mu_index;		//mu grp index, this is not MU group id
	struct MUCapStaNode_t *MUStaListNode;	//points to a node in MUStaList that this sta belongs to
	struct muset *MUset;	//points to MUSetList this station belongs to
#ifdef CONFIG_IEEE80211W
	UINT8 Ieee80211wSta;
	UINT8 ptkCipherOuiType;
	int sa_query_count;	/* number of pending SA Query requests;
				 * 0 = no SA Query in progress */
	int sa_query_timed_out;
	UINT32 sa_query_start_time;
	struct timer_list SA_Query_Timer;
#endif
	UINT8 assocRSSI;	//store RSSI when first assoc to determine which rate index to use in rate table
#ifdef DUPLICATED_MGMT_DBG
	UINT16 pre_mgmt_seq;
#endif
	UINT16 mgmt_seqNum;
#ifdef MULTI_AP_SUPPORT
	UINT8 MultiAP_4addr;
#ifdef IEEE80211K
	struct IEEEtypes_RM_Enable_Capabilities_Element_t RRM_Cap_IE;
#endif				/* IEEE80211K */
#endif				/* MULTI_AP_SUPPORT */

#ifdef AP_STEERING_SUPPORT
	IEEEtypes_Extended_Cap_Element_t ExtCapElem;
	Timer btmreq_disassocTimer;
	UINT8 btmreq_count;
#endif				//AP_STEERING_SUPPORT

	UINT16 seqNum;
	struct sk_buff *pDefragSkBuff;
	rx_pn_info_t *pn;
	IEEEtypes_AcontrolInfoOm_t operating_mode;

#if defined(SOC_W906X) || defined(SOC_W9068)
	//only put partial HE Cap. IE here because it occupies large memory, but little usage of this IE.
	UINT8 he_cap_ie;
	HE_Mac_Capabilities_Info_t he_mac_cap;
	HE_Phy_Capabilities_Info_t he_phy_cap;

#ifdef AP_TWT
	//record to log twt agreement info.
	twt_agreement_t TwtAgree;
#endif

	HE_Capabilities_IE_t heCap;
#endif				/* #if defined(SOC_W906X) || defined(SOC_W9068) */

	rx_ba_stat_t rxBaStats[MAX_TID + 1];
	long last_connected;
#ifdef CB_SUPPORT
	UINT8 Qosinfo;
	PeerInfo_t PeerInfo;
#endif				//CB_SUPPORT

	//dbRateInfo_t          rx_rate_info;   // rate_info
	rxppdu_airtime_t rxppdu_airtime;
	rx_info_aux_t rx_info_aux;
	assoc_req_msg_t assocReqMsg;
	IEEEtypes_CapInfo_t CapInfo;
} extStaDb_StaInfo_t;

#define EXT_STA_TABLE_SIZE	MAX_STNS
#define EXT_STA_TABLE_SIZE_RUNNING	sta_num

typedef struct ExtStaInfoItem_t {
	struct ExtStaInfoItem_t *nxt;	/* part of List Object node elments */
	struct ExtStaInfoItem_t *prv;
	struct ExtStaInfoItem_t *nxt_ht;	/* for hashtable list */
	struct ExtStaInfoItem_t *prv_ht;
	extStaDb_StaInfo_t StaInfo;	/* information data */
} ExtStaInfoItem_t;

typedef struct eth_StaInfo_t {
	IEEEtypes_MacAddr_t Addr;
	struct extStaDb_StaInfo_t *pStaInfo_t;
	UINT32 TimeStamp;
} eth_StaInfo_t;

typedef struct EthStaItem_t {
	struct EthStaItem_t *nxt;	/* part of List Object node elments */
	struct EthStaItem_t *prv;
	struct EthStaItem_t *nxt_ht;	/* for hashtable list */
	struct EthStaItem_t *prv_ht;
	eth_StaInfo_t ethStaInfo;	/* information data */
} EthStaItem_t;

struct STADB_CTL {
	BOOLEAN Initialized;
	UINT16 MaxStaSupported;
	ExtStaInfoItem_t *ExtStaInfoDb;
	ExtStaInfoItem_t *ExtStaInfoDb_p[EXT_STA_TABLE_SIZE];
	List FreeStaList;
	List StaList;
	int aging_time_in_minutes;
	struct MUCapStaNode_t *MUStaDb;	//pointer to base memory addr for station MU capabilities
	List FreeMUStaList;	//linked list of memory that is free to be used for station MU capabilities
	 DECLARE_LOCK(dbLock);	/*used to protect db */
};

struct ETHSTADB_CTL {
	BOOLEAN eInitialized;
	EthStaItem_t *EthStaDb;
	EthStaItem_t *EthStaDb_p[EXT_STA_TABLE_SIZE];
	List FreeEthStaList;
	List EthStaList;
	int aging_time_in_minutes;
};

typedef struct muset {
	struct muset *nxt;
	struct muset *prv;
	int index;
	extStaDb_StaInfo_t *StaInfo[MU_MAX_USERS];
	UINT8 cnt;		//no. of users in this MU Set
	UINT8 antcnt;		//total antenna cnt in this MU Set
	char *dev_name;
} muset_t;

/* */
/* The information recorded for an external station: */
/* 1) Its MAC address */
/* 2) Whether or not it is an AP */
/* 3) The state with respect to the station containing this database */
/* 4) The power mode of the external station */
/* */
#define AGING_TIMER_VALUE_IN_SECONDS   10
/*============================================================================= */
/*                    PUBLIC PROCEDURES (ANSI Prototypes) */
/*============================================================================= */

/******************************************************************************
*
* Name: extStaDb_Init
*
* Description:
*    Routine to initial the structures used in the external stations table.
*
* Conditions For Use:
*    None.
*
* Arguments:
*    None.
*
* Return Value:
*    Status indicating success or failure.
*
* Notes:
*    None.
*
*****************************************************************************/
extern WL_STATUS extStaDb_Init(vmacApInfo_t * vmacSta_p, UINT16 MaxStns);

/******************************************************************************
*
* Name: extStaDb_AddSta
*
* Description:
*    This routine adds a station to the external station table.
*
* Conditions For Use:
*    External station table has been initialized.
*
* Arguments:
*    Arg1 (i  ): StaInfo - Pointer to a structure containing information
*                          about the station being added
*
* Return Value:
*    Status indicating the results of the operation.
*
* Notes:
*    None.
*
*****************************************************************************/
extern extStaDb_Status_e extStaDb_AddSta(vmacApInfo_t * vmacSta_p,
					 extStaDb_StaInfo_t * StaInfo_p);

/******************************************************************************
*
* Name: extStaDb_DelSta
*
* Description:
*    This routine deletes a station from the external station table.
*
* Conditions For Use:
*    External station table has been initialized.
*
* Arguments:
*    Arg1 (i  ): Addr_p  - Pointer to the MAC address of the station to be
*                          deleted
*
* Return Value:
*    Status indicating the results of the operation.
*
* Notes:
*    None.
*
*****************************************************************************/
extern extStaDb_Status_e extStaDb_DelSta(vmacApInfo_t * vmacSta_p,
					 IEEEtypes_MacAddr_t * Addr_p,
					 int option);

/******************************************************************************
*
* Name: extStaDb_GetStaInfo
*
* Description:
*    This routine attempts to retrieve the state for the given MAC address.
*
* Conditions For Use:
*    External station table has been initialized.
*
* Arguments:
*    Arg1 (i  ): Addr_p  - Pointer to the MAC address of the station for
*                          which the state is to be retrieved
*    Arg2 (  o): StaInfo_p - Pointer to the variable that will contain the
*                          requested station information
*
* Return Value:
*    Status indicating the results of the operation.
*
* Notes:
*    None.
*
*****************************************************************************/
extern extStaDb_Status_e extStaDb_GetState2(vmacApInfo_t * vmacSta_p,
					    IEEEtypes_MacAddr_t * Addr_p,
					    extStaDb_State_e * State_p);

extern extStaDb_StaInfo_t *extStaDb_GetStaInfo(vmacApInfo_t * vmacSta_p,
					       IEEEtypes_MacAddr_t * Addr_p,
					       int option);

UINT32 Wang32BitMix(UINT32 Key);
#ifdef SOC_W906X
#define STADB_DONT_UPDATE_AGINGTIME (0x1 << 0)
#define STADB_UPDATE_AGINGTIME      (0x1 << 1)
#define STADB_SKIP_MATCH_VAP        (0x1 << 2)	//STA_MAC may exist in other VAPs
#define STADB_NO_BLOCK              (0x1 << 3)
#else
#define STADB_DONT_UPDATE_AGINGTIME 0
#define STADB_UPDATE_AGINGTIME      1
#define STADB_SKIP_MATCH_VAP        2	//STA_MAC may exist in other VAPs
#define STADB_NO_BLOCK              3
#endif
#ifdef STADB_IN_CACHE
#define STADB_FIND_IN_CACHE         (0x1 << 16)
#define STADB_UPDATE_CACHE          (0x1 << 17)
#endif /* STADB_IN_CACHE */
/* We assume all Tx packets length is 1512. 
throughput under AGGRTHRESHOLD 2000 is about 8*1512*2000 = 24192000 bps */
#define AGGRTHRESHOLD              2000

#define AGGKEEPNUM 40
/******************************************************************************
*
* Name: extStaDb_SetPwrMode
*
* Description:
*    This routine attempts to set the given power mode for the given MAC
*    address.
*
* Conditions For Use:
*    External station table has been initialized.
*
* Arguments:
*    Arg1 (i  ): Addr_p  - Pointer to the MAC address of the station for
*                          which a power mode update is to be made
*    Arg2 (i  ): NewMode - The new power mode of the station
*
* Return Value:
*    Status indicating the results of the operation.
*
* Notes:
*    None.
*
*****************************************************************************/
extern extStaDb_Status_e extStaDb_SetPwrMode(vmacApInfo_t * vmacSta_p,
					     IEEEtypes_MacAddr_t * Addr_p,
					     IEEEtypes_PwrMgmtMode_e NewMode);

/******************************************************************************
*
* Name: extStaDb_GetPwrMode
*
* Description:
*    This routine attempts to retrieve the power mode for the given MAC
*    address.
*
* Conditions For Use:
*    External station table has been initialized.
*
* Arguments:
*    Arg1 (i  ): Addr_p - Pointer to the MAC address of the station for
*                         which the power mode is to be retrieved
*    Arg2 (  o): Mode_p - Pointer to the variable that will contain the
*                         requested power mode information
*
* Return Value:
*    Status indicating the results of the operation.
*
* Notes:
*    None.
*
*****************************************************************************/
extern extStaDb_Status_e extStaDb_GetPwrMode(vmacApInfo_t * vmacSta_p,
					     IEEEtypes_MacAddr_t * Addr_p,
					     IEEEtypes_PwrMgmtMode_e * Mode_p);

extern extStaDb_Status_e extStaDb_SetAid(vmacApInfo_t * vmacSta_p,
					 IEEEtypes_MacAddr_t * Addr_p,
					 UINT16 Aid);

extern extStaDb_Status_e extStaDb_GetStnId(vmacApInfo_t * vmacSta_p,
					   IEEEtypes_MacAddr_t * Addr_p,
					   UINT16 * StnId_p);
extern UINT16 extStaDb_entries(vmacApInfo_t * vmacSta_p, UINT8);
extern int set_sta_aging_time(vmacApInfo_t * vmacSta_p, int minutes);
extern void extStaDb_AgingTimerInit(vmacApInfo_t * vmacSta_p);
extern void extStaDb_ProcessKeepAliveTimerInit(vmacApInfo_t * vmacSta_p);
extern UINT16 extStaDb_list(vmacApInfo_t * vmacSta_p, UINT8 * buf, UINT8);

#ifdef WPA
extern extStaDb_Status_e extStaDb_SetRSNDataTrafficEnabled(vmacApInfo_t *
							   vmacSta_p,
							   IEEEtypes_MacAddr_t *
							   Addr_p, UINT8 value);
extStaDb_Status_e extStaDb_SetRSNPwk(vmacApInfo_t * vmacSta_p,
				     IEEEtypes_MacAddr_t * Addr_p,
				     UINT8 * pEncryptKey, UINT32 * pTxMICKey,
				     UINT32 * pRxMICKey);
extStaDb_Status_e extStaDb_SetRSNPwkAndDataTraffic(vmacApInfo_t * vmacSta_p,
						   IEEEtypes_MacAddr_t * Addr_p,
						   UINT8 * pEncryptKey,
						   UINT32 * pTxMICKey,
						   UINT32 * pRxMICKey);
extStaDb_Status_e extStaDb_GetRSNPwk(vmacApInfo_t * vmacSta_p,
				     IEEEtypes_MacAddr_t * Addr_p,
				     UINT8 * pEncryptKey, UINT32 * pTxMICKey,
				     UINT32 * pRxMICKey);
extStaDb_Status_e extStaDb_SetRSNPmk(vmacApInfo_t * vmacSta_p,
				     IEEEtypes_MacAddr_t * Addr_p,
				     UINT8 * pPMK);
extStaDb_Status_e extStaDb_GetKeyMgmtInfo(vmacApInfo_t * vmacSta_p,
					  IEEEtypes_MacAddr_t * Addr_p,
					  keyMgmtInfo_t * KeyMgmtInfo);
extStaDb_Status_e extStaDb_SetKeyMgmtInfo(vmacApInfo_t * vmacSta_p,
					  IEEEtypes_MacAddr_t * Addr_p,
					  keyMgmtInfo_t * KeyMgmtInfo);
//extStaDb_Status_e extStaDb_SetTimerData(IEEEtypes_MacAddr_t *Addr_p,
//                                        timer_Data_t *tData);
extStaDb_Status_e extStaDb_GetRSN_IE(vmacApInfo_t * vmacSta_p,
				     IEEEtypes_MacAddr_t * Addr_p,
				     UINT8 * RsnIE_p);
#ifdef MRVL_80211R
extStaDb_Status_e extStaDb_Get_11r_IEs(vmacApInfo_t * vmac_p,
				       IEEEtypes_MacAddr_t * Addr_p,
				       UINT8 * MDIE_p, UINT16 * ret_len,
				       UINT8 * reassoc);
#endif
extStaDb_Status_e extStaDb_SetRSN_IE(vmacApInfo_t * vmacSta_p,
				     IEEEtypes_MacAddr_t * Addr_p,
				     IEEEtypes_RSN_IE_t * RsnIE_p);
#ifdef MRVL_WSC
extStaDb_Status_e extStaDb_GetWSC_IE(vmacApInfo_t * vmacSta_p,
				     IEEEtypes_MacAddr_t * Addr_p,
				     UINT8 * WscIE_p);
#endif
extern extStaDb_Status_e extStaDb_GetPairwiseTSC(vmacApInfo_t * vmacSta_p,
						 IEEEtypes_MacAddr_t * Addr_p,
						 UINT32 * pTxIV32,
						 UINT16 * pTxIV16);
extern extStaDb_Status_e extStaDb_SetPairwiseTSC(vmacApInfo_t * vmacSta_p,
						 IEEEtypes_MacAddr_t * Addr_p,
						 UINT32 TxIV32, UINT16 TxIV16);
extStaDb_Status_e extStaDb_GetStaInfoAndKeys(vmacApInfo_t * vmacSta_p,
					     IEEEtypes_MacAddr_t * Addr_p,
					     extStaDb_StaInfo_t * StaInfo_p,
					     int AgingTimeMode,
					     PacketType_e mode);
extStaDb_Status_e extStaDb_GetStaInfoAndTxKeys(vmacApInfo_t * vmacSta_p,
					       IEEEtypes_MacAddr_t *,
					       extStaDb_StaInfo_t *, UINT32);
extStaDb_Status_e extStaDb_GetStaInfoAndRxKeys(vmacApInfo_t * vmacSta_p,
					       IEEEtypes_MacAddr_t *,
					       extStaDb_StaInfo_t *, UINT32);
//extStaDb_Status_e extStaDb_SetKeyMgmtState(IEEEtypes_MacAddr_t *Addr_p,
//        keyMgmtState_e State);
//extStaDb_Status_e extStaDb_SetTimerData(IEEEtypes_MacAddr_t *Addr_p,
//                                    timer_Data_t *tData);
extStaDb_Status_e extStaDb_SetPhase1Key(vmacApInfo_t * vmacSta_p,
					IEEEtypes_MacAddr_t * Addr_p,
					UINT16 * Phase1Key, PacketType_e mode,
					UINT32 RxIV32);
void extStaDb_SendGrpKeyMsgToAllSta(vmacApInfo_t * vmacSta_p);
void extStaDb_SetNewState4AllSta(vmacApInfo_t * vmacSta_p,
				 extStaDb_State_e NewState);
extStaDb_StaInfo_t *extStaDb_GetStaInfoWPA(vmacApInfo_t * vmacSta_p,
					   IEEEtypes_MacAddr_t * Addr_p,
					   UINT32 AgingTimeMode);
extern void extStaDb_ProcessAgeEvt(vmacApInfo_t * vmacSta_p);
extern extStaDb_Status_e extStaDb_SetQoSOptn(vmacApInfo_t * vmacSta_p,
					     IEEEtypes_MacAddr_t *, UINT8);
extern UINT8 extStaDb_GetQoSOptn(vmacApInfo_t * vmacSta_p,
				 IEEEtypes_MacAddr_t * Addr_p);
extern void extStaDb_RemoveAllStns(vmacApInfo_t * vmacSta_p, UINT16 Reason);
extern extStaDb_Status_e extStaDb_GetWMM_DeliveryEnableInfo(vmacApInfo_t *
							    vmacSta_p,
							    IEEEtypes_MacAddr_t
							    *, UINT8, UINT8 *,
							    UINT8 *);

extern UINT8 extStaDb_Check_Uapsd_Capability(vmacApInfo_t * vmacSta_p,
					     IEEEtypes_MacAddr_t *);
extern UINT8 extStaDb_Check_ALL_AC_DeliveryEnableInfo(vmacApInfo_t * vmacSta_p,
						      IEEEtypes_MacAddr_t *);
extern extStaDb_Status_e extStaDb_GetMeasurementInfo(vmacApInfo_t * vmacSta_p,
						     IEEEtypes_MacAddr_t *,
						     extStaDb_measurement_info_t
						     *);
extern extStaDb_Status_e extStaDb_SetMeasurementInfo(vmacApInfo_t * vmacSta_p,
						     IEEEtypes_MacAddr_t *,
						     extStaDb_measurement_info_t
						     *);

#endif
extern UINT16 extStaDb_AggrFrameCk(vmacApInfo_t * vmacSta_p, int force);
extern void Disable_extStaDb_ProcessKeepAliveTimer(vmacApInfo_t * vmacSta_p);
extern WL_STATUS ethStaDb_Init(vmacApInfo_t * vmacSta_p, UINT16 MaxStns);
extern extStaDb_Status_e ethStaDb_AddSta(vmacApInfo_t * vmac_p,
					 IEEEtypes_MacAddr_t * Addr_p,
					 extStaDb_StaInfo_t * StaInfo_p);
extern eth_StaInfo_t *ethStaDb_GetStaInfo(vmacApInfo_t * vmac_p,
					  IEEEtypes_MacAddr_t * Addr_p,
					  int option);
extern void ethStaDb_RemoveAllStns(vmacApInfo_t * vmac_p);
extern extStaDb_Status_e ethStaDb_RemoveSta(vmacApInfo_t * vmac_p,
					    IEEEtypes_MacAddr_t * Addr_p);
extern extStaDb_Status_e ethStaDb_RemoveStaPerWlan(vmacApInfo_t * vmac_p,
						   IEEEtypes_MacAddr_t *
						   Addr_p);
extern extStaDb_Status_e extStaDb_RemoveSta(vmacApInfo_t * vmac_p,
					    IEEEtypes_MacAddr_t * Addr_p);
#ifdef MULTI_AP_SUPPORT
typedef struct MultiAP_4Addr_Entry_t {
	struct MultiAP_4Addr_Entry_t *prvEntry;
	UINT8 head;
	UINT8 tar[6];
	UINT8 SA[6];
	struct MultiAP_4Addr_Entry_t *nxtEntry;
} MultiAP_4Addr_Entry_t;

#define MAX_4ADDR_TABLE_SIZE  2048

typedef struct {
	UINT8 index;
	MultiAP_4Addr_Entry_t entry[MAX_4ADDR_TABLE_SIZE];
} MultiAP_4Addrr_Table_t;

extern extStaDb_StaInfo_t *extStaDb_GetStaInfoStn(vmacApInfo_t * vmac_p,
						  UINT8 stnid);
extern void FourAddr_HashInit(void);
extern int FourAddr_SearchHashEntry(IEEEtypes_MacAddr_t * Addr_p,
				    MultiAP_4Addr_Entry_t ** entry, UINT8 type);
extern int FourAddr_AddHashEntry(MultiAP_4Addr_Entry_t ** currentEntry,
				 IEEEtypes_MacAddr_t * Addr2_p,
				 IEEEtypes_MacAddr_t * Addr4_p);
extern int FourAddr_ClearHashEntry(void);
extern int FourAddr_ClearHashEntrySTA(void);
#endif

static UINT8
ismemzero(UINT8 * mem, UINT32 size)
{
	UINT8 *ptr = mem;
	return ((*ptr == 0) && (memcmp(ptr, ptr + 1, size - 1) == 0));
}

#ifdef SOC_W906X
static inline u8
is_he_capable_sta(extStaDb_StaInfo_t * pStaInfo)
{
	if (pStaInfo->he_cap_ie != HE_CAPABILITIES_IE ||
	    (ismemzero
	     ((u8 *) & pStaInfo->he_mac_cap, sizeof(HE_Mac_Capabilities_Info_t))
	     && ismemzero((u8 *) & pStaInfo->he_phy_cap,
			  sizeof(HE_Phy_Capabilities_Info_t))))
		return 0;
	else
		return 1;
}
#else
static inline u8
is_he_capable_sta(extStaDb_StaInfo_t * pStaInfo)
{
	return 0;
}
#endif
extern extStaDb_Status_e extStaDb_UpdateAgingTime(vmacApInfo_t * vmac_p,
						  IEEEtypes_MacAddr_t * Addr_p);
#endif /* _STADB_H */
