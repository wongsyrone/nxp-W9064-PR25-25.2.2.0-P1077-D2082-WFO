/** @file macMgmtMlme.h
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
*    This file .
*
* Public Procedures:
*    macMgmtMlme_AssociateCmd      Process a cmd to associate with an AP
*    macMgmtMlme_AssociateRsp      Process an associate rsp from an AP
*    macMgmtMlme_Atim              Process an ATIM msg from another STA
*    macMgmtMlme_AuthenticateCmd   Process a cmd to authenticate with
*                                  another station or an AP
*    macMgmtMlme_AutheticateMsg    Process an authentication msg from a
*                                  station or an AP
*    macMgmtMlme_BeaconMsg         Process a beacon msg from an AP or a
*                                  station
*    macMgmtMlme_DeauthenticateMsg Process a deauthentication msg from a
*                                  station or an AP
*    macMgmtMlme_DisassociateCmd   Process a cmd to disassociate with an AP
*    macMgmtMlme_DisassociateMsg   Process a disassociation msg from an AP
*    macMgmtMlme_JoinCmd           Process a cmd to join a BSS
*    macMgmtMlme_ProbeRqst         Process a probe request from another
*                                  station in an IBSS
*    macMgmtMlme_ProbeRsp          Process a probe response from a station
*                                  or an AP
*    macMgmtMlme_ReassociateCmd    Process a cmd to reassociate with a new AP
*    macMgmtMlme_ReassociateRsp    Process a reassociation rsp from an AP
*    macMgmtMlme_ResetCmd          Process a cmd to peform a reset
*    macMgmtMlme_ScanCmd           Process a cmd to perform a scan for BSSs
*    macMgmtMlme_StartCmd          Process a cmd to start an IBSS
*    macMgmtMlme_Timeout           Process timeouts from previously set
*                                  timers
*
* Notes:
*    None.
*
*****************************************************************************/

#ifndef _MACMGMTMLME_H_
#define _MACMGMTMLME_H_

#include "wltypes.h"
#include "IEEE_types.h"
#include "mib.h"
#include "wl_hal.h"

#include "StaDb.h"
#include "qos.h"
#include "wlmac.h"

#include "ds.h"
#include "osif.h"
#include "keyMgmtCommon.h"
#include "keyMgmt.h"
#include "timer.h"
#include "tkip.h"

#include "smeMain.h"
#include "macmgmtap.h"
//=============================================================================
//                               INCLUDE FILES
//=============================================================================

//=============================================================================
//                            PUBLIC DEFINITIONS
//=============================================================================

#define ADD_TO_POLLING_LIST 1
#define DONOT_ADD_TO_POLLING_LIST 0
#define AID_PREFIX 0xC000
#ifdef ENABLE_RATE_ADAPTATION
#define RATE_ADAPT_STNCNT_THRESH   5
#endif
#define SLOT_TIME_MODE_SHORT 0
#define SLOT_TIME_MODE_LONG  1

#define NUM_MARGINS 6

#define MUSet_BLOCK			(1<<0)
#define MUSet_NO_BLOCK  	(1<<1)
#define MUSet_NO_STA_BLOCK	(1<<2)
#define MUSet_FW_DEL        (1<<3)
#define MUSet_NO_GID_FRAME  (1<<4)
#define MUSta_BLOCK			(1<<0)
#define MUSta_NO_BLOCK		(1<<1)

#define RateIndex5_1Mbps_BIT   0x00000001
#define RateIndex5_2Mbps_BIT   0x00000002
#define RateIndex5_5Mbps_BIT   0x00000004
#define RateIndex11Mbps_BIT    0x00000008
#define RateIndex22Mbps_BIT    0x00000010
#define RateIndex6Mbps_BIT     0x00000020
#define RateIndex9Mbps_BIT     0x00000040
#define RateIndex12Mbps_BIT    0x00000080
#define RateIndex18Mbps_BIT    0x00000100
#define RateIndex24Mbps_BIT    0x00000200
#define RateIndex36Mbps_BIT    0x00000400
#define RateIndex48Mbps_BIT    0x00000800
#define RateIndex54Mbps_BIT    0x00001000
#define ENDOFTBL 0xFF

#define RATE_BITMAP_B (RateIndex5_1Mbps_BIT | RateIndex5_2Mbps_BIT | RateIndex5_5Mbps_BIT | RateIndex11Mbps_BIT)

#define RATE_BITMAP_G (RateIndex6Mbps_BIT | RateIndex9Mbps_BIT | RateIndex12Mbps_BIT | RateIndex18Mbps_BIT	\
						| RateIndex24Mbps_BIT | RateIndex36Mbps_BIT | RateIndex48Mbps_BIT | RateIndex54Mbps_BIT)

//=============================================================================
//                          PUBLIC TYPE DEFINITIONS
//=============================================================================
//
// Structure used to store data given at the time of successful
// association
//
typedef struct AssocReqData_t {
	IEEEtypes_CapInfo_t CapInfo;
	IEEEtypes_ListenInterval_t ListenInterval;
	IEEEtypes_SuppRatesElement_t SuppRates;
	IEEEtypes_ExtSuppRatesElement_t ExtSuppRates;
	UINT32 SuppRateSetRegMap[IEEEtypes_MAX_DATA_RATES];
	UINT32 HighestRateIndex;
#ifdef ENABLE_RATE_ADAPTATION
	UINT32 RateToBeUsedForTx;
#ifdef ENABLE_RATE_ADAPTATION_BASEBAND
	UINT32 TxFailures;
	UINT32 InvAlpha;	//to get running average.
	UINT32 TxSuccess;	//For Rate Adaptation
	UINT32 TxRetry;		//For Rate Adaptation.
#ifdef ENABLE_OSCILLATION_CODE
	UINT32 OSC_FLAG;	//if 1, correction won't be decremented.
	SINT32 RSSI_Store;
	//Since recording the RSSI is not perfect, we will use this 
	UINT32 DisableOscFlagCounter;
#endif				//ENABLE_OSCILLATION_CODE
	//For maintaining the statistical counter for logging failures.
	UINT32 PktTxSinceFail;
	UINT32 TxFailuresStats;
	UINT32 RateIncreaseIncrement;
	UINT32 AvgRSSI;
	UINT32 TxPkts;
	UINT32 RA_per_timer;	//Keeps track of the time
	UINT32 RAIdleCnt;
	UINT32 AvgSADRSSI;
	UINT32 Power_Level;
	UINT32 BailOutRate;	//If 1 means taht we had to go down to BailOutRate
#endif				//ENABLE_RATE_ADAPTATION_BASEBAND
#endif				//ENABLE_RATE_ADAPTATION

#ifdef QOS_FEATURE
	Qos_Stn_Data_t Qos_Stn_Data;
#endif				//QOS_FEATURE
} AssocReqData_t;

#ifdef SOC_W906X
#define MAX_CHANNEL_NUM_IN_OPERATING_CLASS 30

typedef struct ap_radio_oper_class_t {
	UINT8 oper_class;
	UINT8 max_power;
	UINT8 num_of_non_operable_channels;
	UINT8 non_operable_channel_list[MAX_CHANNEL_NUM_IN_OPERATING_CLASS];
} PACK_END ap_radio_oper_class_t;

typedef struct ap_radio_basic_capa_rpt_t {
	UINT8 ruid[6];
	UINT8 maxNumBss;
	UINT8 num_of_operating_class;
	ap_radio_oper_class_t operatingClass[];
} PACK_END ap_radio_basic_capa_rpt_t;

#define AP_RADIO_BASIC_CAPA_SIZE \
	sizeof(ap_radio_basic_capa_rpt_t) + \
	sizeof(ap_radio_oper_class_t) * \
	MAX_CHANNEL_NUM_IN_OPERATING_CLASS
#endif

//=============================================================================
//                                PUBLIC DATA
//=============================================================================

extern AssocReqData_t AssocTable[MAX_AID + 1];
extern UINT32 HighestBasicRateIndex;
extern BOOLEAN macWepEnabled;
extern UINT32 AssocStationsCnt;
extern UINT32 macChangeSlotTimeModeTo;
extern UINT32 macCurSlotTimeMode;
extern UINT32 AssocStationsCnt;
extern UINT32 HighestBasicRateIndexB;
extern IEEEtypes_MacAddr_t bcast;	// = {0xff,0xff,0xff,0xff,0xff,0xff};

//=============================================================================
//                    PUBLIC PROCEDURES (ANSI Prototypes)
//=============================================================================

/******************************************************************************
*
* Name: macMgmtMlme_AssociateReq
*
* Description:
*   Routine to handle a received associate reqeust.
*
* Conditions For Use:
*   All software components have been initialized and started.
*
* Arguments:
*   Arg1 (i  ): MgmtMsg_p - Pointer to an associate request
*
* Return Value:
*   None.
*
* Notes:
*   None.
*
*****************************************************************************/
extern void macMgmtMlme_AssociateReq(vmacApInfo_t * vmacSta_p, macmgmtQ_MgmtMsg3_t * MgmtMsg_p, UINT32 msgSize);

/******************************************************************************
*
* Name: macMgmtMlme_AssociateRsp
*
* Description:
*   This routine handles a response from an AP to a prior associate request.
*
* Conditions For Use:
*   All software components have been initialized and started.
*
* Arguments:
*   Arg1 (i  ): MgmtMsg_p - Pointer to an 802.11 management message
*                           containing an associate response
*
* Return Value:
*   None.
*
* Notes:
*   None.
*
*****************************************************************************/
extern void macMgmtMlme_AssociateRsp(macmgmtQ_MgmtMsg_t * MgmtMsg_p);

/******************************************************************************
*
* Name: macMgmtMlme_Atim
*
* Description:
*   This routine handles an ATIM sent from another station in an IBSS.
*
* Conditions For Use:
*   All software components have been initialized and started.
*
* Arguments:
*   Arg1 (i  ): MgmtHdr_p - Pointer to an 802.11 management message header
*                           that contains an ATIM message
*
* Return Value:
*   None.
*
* Notes:
*   Only the 802.11 message header is input since the message body for an
*   ATIM message is empty.
*
*****************************************************************************/
extern void macMgmtMlme_Atim(IEEEtypes_MgmtHdr_t * MgmtHdr_p);

/******************************************************************************
*
* Name: macMgmtMlme_AuthenticateCmd
*
* Description:
*   Routine to handle a command to carry out an authentication with another
*   station or an AP.
*
* Conditions For Use:
*   All software components have been initialized and started.
*
* Arguments:
*   Arg1 (i  ): AuthCmd_p - Pointer to an authenticate command
*
* Return Value:
*   None.
*
* Notes:
*   None.
*
*****************************************************************************/
extern void macMgmtMlme_AuthenticateCmd(IEEEtypes_AuthCmd_t * AuthCmd_p);

/******************************************************************************
*
* Name: macMgmtMlme_AuthenticateMsg
*
* Description:
*   This routine handles a message from either another station of from an
*   AP relating to authentication; the message can be a request for
*   authentication or a response to a prior authentication message.
*
* Conditions For Use:
*   All software components have been initialized and started.
*
* Arguments:
*   Arg1 (i  ): MgmtMsg_p - Pointer to an 802.11 management message
*                           containing an authentication message
*
* Return Value:
*   None.
*
* Notes:
*   None.
*
*****************************************************************************/
extern void macMgmtMlme_AuthenticateMsg(macmgmtQ_MgmtMsg_t * MgmtMsg_p);

/******************************************************************************
*
* Name: macMgmtMlme_BeaconMsg
*
* Description:
*   This routine handles a beacon message received from an AP or station
*
* Conditions For Use:
*   All software components have been initialized and started.
*
* Arguments:
*   Arg1 (i  ): MgmtMsg_p - Pointer to an 802.11 management message
*                           containing an beacon message
*
* Return Value:
*   None.
*
* Notes:
*   None.
*
*****************************************************************************/
extern void macMgmtMlme_BeaconMsg(macmgmtQ_MgmtMsg_t * MgmtMsg_p);

/******************************************************************************
*
* Name: macMgmtMlme_DeauthenticateMsg
*
* Description:
*   This routine handles a deauthentication notification from another
*   station or an AP.
*
* Conditions For Use:
*   All software components have been initialized and started.
*
* Arguments:
*   Arg1 (i  ): MgmtMsg_p - Pointer to an 802.11 management message
*                           containing a deauthentication message
*
* Return Value:
*   None.
*
* Notes:
*   None.
*
*****************************************************************************/
extern void macMgmtMlme_DeauthenticateMsg(vmacApInfo_t * vmacSta_p, macmgmtQ_MgmtMsg3_t * MgmtMsg_p, UINT32 msgSize);

/******************************************************************************
*
* Name: macMgmtMlme_DisassociateCmd
*
* Description:
*   Routine to handle a command to carry out a disassociation with an AP.
*
* Conditions For Use:
*   All software components have been initialized and started.
*
* Arguments:
*   Arg1 (i  ): DisassocCmd_p - Pointer to a disassociate command
*
* Return Value:
*   None.
*
* Notes:
*   None.
*
*****************************************************************************/
extern void macMgmtMlme_DisassociateCmd(vmacApInfo_t * vmacSta_p, IEEEtypes_DisassocCmd_t * DisassocCmd_p);

/******************************************************************************
*
* Name: macMgmtMlme_DisassociateMsg
*
* Description:
*   This routine handles a disassociation notification from an AP.
*
* Conditions For Use:
*   All software components have been initialized and started.
*
* Arguments:
*   Arg1 (i  ): MgmtMsg_p - Pointer to an 802.11 management message
*                           containing a disassociation message
*
* Return Value:
*   None.
*
* Notes:
*   None.
*
*****************************************************************************/
extern void macMgmtMlme_DisassociateMsg(vmacApInfo_t * vmacSta_p, macmgmtQ_MgmtMsg3_t * MgmtMsg_p, UINT32 msgSize);

/******************************************************************************
*
* Name: macMgmtMlme_JoinCmd
*
* Description:
*   Routine to handle a command to join a BSS found during a scan.
*
* Conditions For Use:
*   All software components have been initialized and started.
*
* Arguments:
*   Arg1 (i  ): JoinCmd_p - Pointer to a join command
*
* Return Value:
*   None.
*
* Notes:
*   None.
*
*****************************************************************************/
extern void macMgmtMlme_JoinCmd(IEEEtypes_JoinCmd_t * JoinCmd_p);

/******************************************************************************
*
* Name: macMgmtMlme_ProbeRqst
*
* Description:
*   This routine handles a request from another station in an IBSS to
*   respond to a probe.
*
* Conditions For Use:
*   All software components have been initialized and started.
*
* Arguments:
*   Arg1 (i  ): MgmtMsg_p - Pointer to an 802.11 management message
*                           containing a probe request
* Return Value:
*   None.
*
* Notes:
*   None.
*
*****************************************************************************/
extern void macMgmtMlme_ProbeRqst(vmacApInfo_t * vmacSta_p, macmgmtQ_MgmtMsg3_t * MgmtMsg_p);

/******************************************************************************
*
* Name: macMgmtMlme_ProbeRsp
*
* Description:
*   This routine handles a response from another station in an IBSS or an
*   AP in a BSS to a prior probe request.
*
* Conditions For Use:
*   All software components have been initialized and started.
*
* Arguments:
*   Arg1 (i  ): MgmtMsg_p - Pointer to an 802.11 management message
*                           containing a probe response
*
* Return Value:
*   None.
*
* Notes:
*   None.
*
*****************************************************************************/
extern void macMgmtMlme_ProbeRsp(macmgmtQ_MgmtMsg_t * MgmtMsg_p);

/******************************************************************************
*
* Name: macMgmtMlme_ReassociateReq
*
* Description:
*   Routine to handle received reassociate request.
*
* Conditions For Use:
*   All software components have been initialized and started.
*
* Arguments:
*   Arg1 (i  ): MgmtMsg_p - Pointer to a reassociate reqeust
*
* Return Value:
*   None.
*
* Notes:
*   None.
*
*****************************************************************************/
extern void macMgmtMlme_ReassociateReq(vmacApInfo_t * vmacSta_p, macmgmtQ_MgmtMsg3_t * MgmtMsg_p, UINT32 msgSize);

/******************************************************************************
*
* Name: macMgmtMlme_ReassociateRsp
*
* Description:
*   This routine handles a response from an AP to a prior reassociate request.
*
* Conditions For Use:
*   All software components have been initialized and started.
*
* Arguments:
*   Arg1 (i  ): MgmtMsg_p - Pointer to an 802.11 management message
*                           containing a reassociate response
*
* Return Value:
*   None.
*
* Notes:
*   None.
*
*****************************************************************************/
extern void macMgmtMlme_ReassociateRsp(macmgmtQ_MgmtMsg_t * MgmtMsg_p);

/******************************************************************************
*
* Name: macMgmtMlme_ResetCmd
*
* Description:
*   Routine to handle a command to perform a reset, which resets the MAC
*   to initial conditions.
*
* Conditions For Use:
*   All software components have been initialized and started.
*
* Arguments:
*   Arg1 (i  ): ResetCmd_p - Pointer to a reset command
*
* Return Value:
*   None.
*
* Notes:
*   None.
*
*****************************************************************************/
extern void macMgmtMlme_ResetCmd(vmacApInfo_t * vmacSta_p, IEEEtypes_ResetCmd_t * ResetCmd_p);

/******************************************************************************
*
* Name: macMgmtMlme_ScanCmd
*
* Description:
*   Routine to handle a command to perform a scan of potential BSSs that
*   a station may later elect to join.
*
* Conditions For Use:
*   All software components have been initialized and started.
*
* Arguments:
*   Arg1 (i  ): ScanCmd_p - Pointer to a scan command
*
* Return Value:
*   None.
*
* Notes:
*   None.
*
*****************************************************************************/
extern void macMgmtMlme_ScanCmd(IEEEtypes_ScanCmd_t * ScanCmd_p);

/******************************************************************************
*
* Name: macMgmtMlme_StartCmd
*
* Description:
*   Routine to handle a command to start an IBSS.
*
* Conditions For Use:
*   All software components have been initialized and started.
*
* Arguments:
*   Arg1 (i  ): StartCmd_p - Pointer to a start command
*
* Return Value:
*   None.
*
* Notes:
*   None.
*
*****************************************************************************/
extern void macMgmtMlme_StartCmd(vmacApInfo_t * vmacSta_p, IEEEtypes_StartCmd_t * StartCmd_p);

/******************************************************************************
*
* Name: macMgmtMlme_Timeout
*
* Description:
*   Routine to handle timeouts that occur from previously set timers.
*
* Conditions For Use:
*   All software components have been initialized and started.
*
* Arguments:
*   Arg1 (i  ): TBD
*
* Return Value:
*   None.
*
* Notes:
*   None.
*
*****************************************************************************/
extern void macMgmtMlme_Timeout(macmgmtQ_TimerMsg_t * TimerMsg_p);

extern WL_STATUS macMgmtMlme_Init(vmacApInfo_t * vmacSta_p, UINT32 maxStns, IEEEtypes_MacAddr_t * stnMacAddr);
extern void macMgmtMlme_PsPollMsg(macmgmtQ_MgmtMsg3_t * MgmtMsg_p, UINT32 msgSize);
#ifdef SOC_W906X
extern void macMgmtMlme_SendDeauthenticateMsg(vmacApInfo_t * vmacSta_p, IEEEtypes_MacAddr_t * Addr, UINT16 StnId, UINT16 Reason, UINT8 sendCmd);
#else
extern void macMgmtMlme_SendDeauthenticateMsg(vmacApInfo_t * vmacSta_p, IEEEtypes_MacAddr_t * Addr, UINT16 StnId, UINT16 Reason);
#endif
extern void macMgmtMlme_SendDisassociateMsg(vmacApInfo_t * vmacSta_p, IEEEtypes_MacAddr_t * Addr, UINT16 StnId, UINT16 Reason);
#ifdef MULTI_AP_SUPPORT
extern void macMgmtMlme_SendDisassociateMsg4MAP(vmacApInfo_t * vmacSta_p, IEEEtypes_MacAddr_t * Addr, UINT16 StnId, UINT16 Reason);
#endif				/* MULTI_AP_SUPPORT */

#ifdef MRVL_80211R
int macMgmtMlme_SendAuthenticateMsg(vmacApInfo_t * vmacAP_p, IEEEtypes_MacAddr_t * staMac, UINT16 seq,
				    UINT16 status_code, UINT8 * optie, UINT8 optie_len);
#endif
SINT8 isMacAccessList(vmacApInfo_t * vmacSta_p, IEEEtypes_MacAddr_t * destAddr_p);
extern void macMgmtMlme_DecrBonlyStnCnt(vmacApInfo_t * vmacSta_p, UINT8);
extern void macMgmtMlme_IncrBonlyStnCnt(vmacApInfo_t * vmacSta_p, UINT8 option);
extern int channelSelected(vmacApInfo_t * vmacSta_p, int mode);
extern void macMgmtCleanUp(vmacApInfo_t * vmacSta_p, extStaDb_StaInfo_t * StaInfo_p);

#ifdef MRVL_DFS
void macMgmtMlme_StartRadarDetection(struct net_device *dev, UINT8 detectionMode);
void macMgmtMlme_StopRadarDetection(struct net_device *dev, UINT8 detectionMode);
#ifdef CONCURRENT_DFS_SUPPORT
void macMgmtMlme_StartAuxRadarDetection(struct net_device *dev, UINT8 detectionMode);
void macMgmtMlme_StopAuxRadarDetection(struct net_device *dev, UINT8 detectionMode);
#endif				/* CONCURRENT_DFS_SUPPORT */
void macMgmtMlme_SendChannelSwitchCmd(struct net_device *dev, Dfs_ChanSwitchReq_t * pChannelSwitchCmd);
void macMgmtMlme_SwitchChannel(struct net_device *dev, UINT8 channel, UINT8 channel2, CHNL_FLAGS * chanFlag_p);
void macMgmtMlme_Reset(struct net_device *dev, UINT8 * vaplist, UINT8 * vapcount_p);
void macMgmtMlme_MBSS_Reset(struct net_device *netdev, UINT8 * vaplist, UINT8 vapcount);
void macMgmtMlme_StopDataTraffic(struct net_device *dev);
void macMgmtMlme_RestartDataTraffic(struct net_device *dev);
BOOLEAN UpdateCurrentChannelInMIB(vmacApInfo_t * vmacSta_p, UINT32 channel);
BOOLEAN macMgmtMlme_DfsEnabled(struct net_device *dev);
void ApplyCSAChannel(struct net_device *netdev, UINT32 channel);
UINT8 macMgmtMlme_Get40MHzExtChannelOffset(UINT8 channel);
extern WL_STATUS SendChannelSwitchCmd(vmacApInfo_t * vmacSta_p, Dfs_ChanSwitchReq_t * ChannelSwitchCmd_p);
#endif				//MRVL_DFS

extern void StopAutoChannel(vmacApInfo_t * vmacSta_p);
void IEEEToMrvlRateBitMapConversion(UINT8 SupportedIEEERate, UINT32 * pMrvlLegacySupportedRateBitMap);
extern void DisableMacMgmtTimers(vmacApInfo_t *);
extern void MacMgmtMemCleanup(vmacApInfo_t * vmacSta_p);
extern void Disable_ScanTimerProcess(vmacApInfo_t * vmacSta_p);
extern void Disable_MonitorTimerProcess(vmacApInfo_t * vmacSta_p);
extern void scanControl(vmacApInfo_t * vmacSta_p);
extern void MonitorTimerInit(vmacApInfo_t * vmacSta_p);

#ifdef MRVL_WAPI
extern void macMgmtMlme_WAPI_event(struct net_device *dev, int event_type, u16 auth_type, IEEEtypes_MacAddr_t * sta_addr,
				   IEEEtypes_MacAddr_t * ap_addr, char *info);
#endif
UINT8 macMgmtMlme_Get80MHzPrimaryChannelOffset(UINT8 channel);

extern UINT8 macMgmtMlme_Get160MHzPrimaryChannelOffset(UINT8 channel);

extern int MUchecksta_SetList(vmacApInfo_t * vmac_p, extStaDb_StaInfo_t * pStaInfo);
extern int MUchecksta_StaList(vmacApInfo_t * vmac_p, extStaDb_StaInfo_t * pStaInfo);
extern void MUDisplayMUSetList(vmacApInfo_t * vmac_p);
#ifdef SOC_W906X
extern UINT8 MUCreateMUSet(vmacApInfo_t * vmac_p, extStaDb_StaInfo_t * pStaInfo[]);
#else
extern UINT8 MUCreateMUSet(vmacApInfo_t * vmacSta_p, extStaDb_StaInfo_t * pStaInfo0, extStaDb_StaInfo_t * pStaInfo1, extStaDb_StaInfo_t * pStaInfo2);
#endif
extern void MUDel_MUSetIndex(vmacApInfo_t * vmac_p, UINT8 muset_index);

extern BOOLEAN MUAddStaToMUStaList(vmacApInfo_t * vmac_p, extStaDb_StaInfo_t * StaInfo_p);
extern BOOLEAN MUDelStaFromMUStaList(vmacApInfo_t * vmac_p, MUCapStaNode_t * MUStaNode_p);
extern void MUAutoSet_Hdlr(struct net_device *netdev);
#ifdef SOC_W906X
extern BOOLEAN MUManualSet(vmacApInfo_t * vmac_p, extStaDb_StaInfo_t * pStaInfo[]);
#else
extern BOOLEAN MUManualSet(vmacApInfo_t * vmac_p, extStaDb_StaInfo_t * pStaInfo0, extStaDb_StaInfo_t * pStaInfo1, extStaDb_StaInfo_t * pStaInfo2);
#endif
extern BOOLEAN MUDel_MUSet(vmacApInfo_t * vmac_p, muset_t * muset_p, UINT8 option);
extern void MUDisplayMUStaList(vmacApInfo_t * vmac_p);

#ifdef WTP_SUPPORT
int macMgmtMlme_set_sta_authorized(vmacApInfo_t * vmacAP_p, IEEEtypes_MacAddr_t * staMac);
int macMgmtMlme_set_sta_associated(vmacApInfo_t * vmacAP_p, IEEEtypes_MacAddr_t * staMac,
				   UINT8 Aid, PeerInfo_t * PeerInfo, UINT8 QosInfo, UINT8 isQosSta, UINT8 rsnSta, UINT8 * rsnIE);

void macMgmtMlme_del_sta_entry(vmacApInfo_t * vmacSta_p, IEEEtypes_MacAddr_t * staMac);

extern void txWtpMgmtMsg(struct sk_buff *skb);
#endif
#if defined(MRVL_80211R) || defined(OWE_SUPPORT) || defined(MBO_SUPPORT)
void pending_assoc_timeout_handler(void *ctx);
void pending_assoc_timer_add(extStaDb_StaInfo_t * sta_info, UINT32 ticks);
void pending_assoc_timer_del(extStaDb_StaInfo_t * sta_info);
void pending_assoc_start_timer(extStaDb_StaInfo_t * sta_info);
#endif				/* MRVL_80211R || OWE_SUPPORT || MBO_SUPPORT */
#ifdef MRVL_80211R
void macMgmtMlme_SendAssocMsg(vmacApInfo_t * vmacSta_p, IEEEtypes_MacAddr_t * staMac, UINT8 * optie, UINT8 optie_len);
int macMgmtMlme_SendAuthenticateMsg(vmacApInfo_t * vmacAP_p, IEEEtypes_MacAddr_t * staMac, UINT16 seq,
				    UINT16 status_code, UINT8 * optie, UINT8 optie_len);
#endif				/* MRVL_80211R */
#ifdef IEEE80211K
int macMgmtMlme_RrmAct(vmacApInfo_t * vmacSta_p, macmgmtQ_MgmtMsg3_t * MgmtMsg_p);
int macMgmtMlme_WNMAct(vmacApInfo_t * vmacSta_p, macmgmtQ_MgmtMsg3_t * MgmtMsg_p);
void macMgmtMlme_RmBeaconRequest(struct net_device *netdev,
				 UINT8 * stamac,
				 UINT8 * bssid,
				 UINT8 RegDomain,
				 UINT8 ch,
				 UINT8 RandInt,
				 UINT8 MeasDur,
				 UINT8 MeasMode, UINT8 * ssid, UINT16 ReportCond, UINT8 ReportDetail, UINT8 MeasDurMand, UINT8 VoWiCase);

#endif
#ifdef CONFIG_IEEE80211W
int isRobustMgmtFrame(UINT16 Subtype);
int macMgmtBIP(vmacApInfo_t * vmac_p, macmgmtQ_MgmtMsg2_t * mgtFrm, int payload_len);
#endif

void macMgmtMlme_UpdateProbeRspInfo(vmacApInfo_t * vmacSta_p, UINT16 bcn_interval, UINT16 capinfo);
void macMgmtMlme_UpdateProbeRspExtraIes(vmacApInfo_t * vmacSta_p, UINT8 * iep, UINT16 length);
void macMgmtMlme_UpdateProbeRspBasicIes(vmacApInfo_t * vmacSta_p, UINT8 * iep, UINT16 length);
void macMgmtMlme_UpdateExistedProbeRspIE(vmacApInfo_t * vmacSta_p, UINT8 * iep, UINT16 length);
void macMgmtMlme_ResetProbeRspBuf(vmacApInfo_t * vmacSta_p);

#ifdef AP_STEERING_SUPPORT
void macMgmtMlme_AssocDenied(IEEEtypes_StatusCode_t statuscode);
#endif

#ifdef AUTOCHANNEL
extern UINT8 ACS_OpChanCheck(vmacApInfo_t * vmacSta_p, UINT8 channel);
extern void ACS_start_timer(vmacApInfo_t * vmacSta_p);
extern void ACS_stop_timer(vmacApInfo_t * vmacSta_p);
extern void ACS_set_unusable_channels(vmacApInfo_t * vmacSta_p, UINT8 band, s32 avg_nf);
#endif				/* AUTOCHANNEL */

#ifdef COEXIST_20_40_SUPPORT
extern void Disable_StartCoexisTimer(vmacApInfo_t * vmacSta_p);
#endif				/* COEXIST_20_40_SUPPORT */

#endif				/* _MACMGMTMLME_H_ */
