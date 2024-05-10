/** @file macMgmtMlme.c
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
*                                  timers
*
* Notes:
*    None.
*
*****************************************************************************/

/*============================================================================= */
/*                               INCLUDE FILES */
/*============================================================================= */
#include <linux/if_arp.h>
#include <linux/wireless.h>

#ifdef TP_PROFILE
#include <linux/if_ether.h>
#endif
#include "ap8xLnxIntf.h"

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
#include "macMgmtMlme.h"
#ifdef SUPPORTED_EXT_NSS_BW
#include "mlmeApi.h"
#endif
#include "bcngen.h"
#include "idList.h"
#include "wl_macros.h"
#include "wpa.h"
#include "buildModes.h"
#include "wldebug.h"
#include "ap8xLnxWlLog.h"
#include "ap8xLnxIntf.h"
#include "domain.h"
#include "ap8xLnxFwcmd.h"
#include "ap8xLnxIntf.h"
#include "dfs.h"
#include "keyMgmtSta.h"

#if defined(MRVL_MUG_ENABLE)
#include "ap8xLnxMug.h"
#endif

#ifdef CFG80211
#include "cfg80211.h"
#endif
#ifdef IEEE80211K
#include "msan_report.h"
#endif //IEEE80211K

#ifdef AP_STEERING_SUPPORT
#include "bsstm.h"
#endif //AP_STEERING_SUPPORT

#ifdef MULTI_AP_SUPPORT
#include "1905.h"
#endif //MULTI_AP_SUPPORT

#ifdef WIFI_DATA_OFFLOAD
#include "dol-ops.h"
#endif

#define MCBC_STN_ID         (sta_num)

#define MONITER_PERIOD_1SEC 10

#ifdef AP_SITE_SURVEY
#define AP_SITE_SURVEY_ENTRY_MAX   50
#endif

static UINT32 counterHtProt[NUM_OF_WLMACS] = { 0, 0, 0 };
static UINT8 legacyAPCount[NUM_OF_WLMACS] = { 0, 0, 0 };

#ifdef INTOLERANT40
static UINT32 sHt30minStaIntolerant = 0;
#endif
#ifdef AP_URPTR
#include "wlvmac.h"
extern UINT8 mib_urMode;
extern UINT8 mib_wbMode;
extern UINT8 mib_urModeConfig;
extern UINT8 mib_StaMode;
UINT8 g_urClientMode = GONLY_MODE;
#ifdef AP_URPTR_NEW_RATE
AssocReqData_t *g_urAssocInfo;	//ur_todo - rate info
UINT32 urAid;
#else
AssocReqData_t g_urAssocInfo;	//ur_todo - rate info
#endif
#endif

#ifdef CAP_MAX_RATE
u_int32_t MCSCapEnable = 0;
u_int32_t MCSCap;
#endif

//#define BARBADOS_DFS_TEST 1
#ifdef BARBADOS_DFS_TEST
extern UINT8 dfs_monitor;
extern UINT8 dfs_test;
extern UINT8 dfs_probability;
#endif
UINT8 dfs_test_mode = 0;

UINT16 RxBeaconMaxCnt;
UINT32 BStnAroundCnt = 0;
#define HIGHEST_11B_RATE_REG_INDEX   4

#define SET_ERP_PROTECTION 1
#define RESET_ERP_PROTECTION 0

#define AID_PREFIX 0xC000
#ifdef MRVL_DFS
extern int wlreset_mbss(struct net_device *netdev);
#ifdef SOC_W906X
extern int wlchannelSet(struct net_device *netdev, int channel, int Channel2,
			CHNL_FLAGS chanflag, UINT8 initRateTable);
//twt
#ifdef AP_TWT
void ProcessTWTsetup(vmacApInfo_t * vmacSta_p, macmgmtQ_MgmtMsg_t * MgmtMsg_p);
void ProcessTWTteardown(vmacApInfo_t * vmacSta_p,
			macmgmtQ_MgmtMsg_t * MgmtMsg_p);
#endif
#else
extern int wlchannelSet(struct net_device *netdev, int channel,
			CHNL_FLAGS chanflag, UINT8 initRateTable);
#endif /* SOC_W906X */
#endif
#ifdef MRVL_WSC			//MRVL_WSC_IE
static UINT8 WSC_OUI[4] = { 0x00, 0x50, 0xf2, 0x04 };
#endif

typedef enum {
	CMD_STATE_IDLE,
	CMD_STATE_AP
} CmdState_e;

extern UINT32 gMICFailRstTimerId;	//holds the timerID of the MIC failure reset timer

extern UINT32 gMICFailTimerId;	//holds the timerID of the MIC failure timer

void macMgmtRemoveSta(vmacApInfo_t * vmacSta_p, extStaDb_StaInfo_t * StaInfo_p);

#ifdef SOC_W906X
extern u32 ofdma_autogrp;
#endif

AssocReqData_t AssocTable[MAX_AID + 1];
UINT16 PhyRates[IEEEtypes_MAX_DATA_RATES_G] =
	{ 2, 4, 11, 22, 44, 12, 18, 24, 36, 48, 72, 96, 108, 144 };
UINT16 PhyRatesA[IEEEtypes_MAX_DATA_RATES_A] =
	{ 12, 18, 24, 36, 48, 72, 96, 108, 144 };

#if defined(AP_SITE_SURVEY) || defined(AUTOCHANNEL)
/* Added for Site Survey */

/*---------------------------------*/
/* Client MLME local Management Messages */
/*---------------------------------*/
struct ieee80211_frame {
	IEEEtypes_FrameCtl_t FrmCtl;
	UINT8 dur[2];
	UINT8 addr1[IEEEtypes_ADDRESS_SIZE];
	UINT8 addr2[IEEEtypes_ADDRESS_SIZE];
	UINT8 addr3[IEEEtypes_ADDRESS_SIZE];
	UINT8 seq[2];
	UINT8 addr4[IEEEtypes_ADDRESS_SIZE];
} PACK;

#ifndef SUPPORTED_EXT_NSS_BW
typedef struct dot11MgtFrame_t {
	void *priv_p;
	IEEEtypes_MgmtHdr_t Hdr;
	union {
		IEEEtypes_Bcn_t Bcn;
		IEEEtypes_DisAssoc_t DisAssoc;
		IEEEtypes_AssocRqst_t AssocRqst;
		IEEEtypes_AssocRsp_t AssocRsp;
		IEEEtypes_ReassocRqst_t ReassocRqst;
		IEEEtypes_ReassocRsp_t ReassocRsp;
		IEEEtypes_ProbeRqst_t ProbeRqst;
		IEEEtypes_ProbeRsp_t ProbeRsp;
		IEEEtypes_Auth_t Auth;
		IEEEtypes_Deauth_t Deauth;
#ifdef IEEE80211H
		IEEEtypes_ActionField_t Action;
#endif				/* IEEE80211H */
#ifdef QOS_FEATURE
		IEEEtypes_ADDTS_Req_t AddTSReq;
		IEEEtypes_ADDTS_Rsp_t AddTSRsp;
		IEEEtypes_DELTS_Req_t DelTSReq;
		WSM_DELTS_Req_t DelWSMTSReq;
		IEEEtypes_ADDBA_Req_t AddBAReq;
		IEEEtypes_ADDBA_Rsp_t AddBAResp;
		IEEEtypes_DELBA_t DelBA;
		IEEEtypes_DlpReq_t DlpReq;
		IEEEtypes_DlpResp_t DlpResp;
		IEEEtypes_DlpTearDown_t DlpTearDown;
#endif
	} Body;
	UINT32 FCS;
} dot11MgtFrame_t;
#endif

#define MAX_B_DATA_RATES    4
//static UINT8 scaningTimerInitialized =0;

#if defined(AP_SITE_SURVEY)
API_SURVEY_ENTRY siteSurveyInfo[AP_SITE_SURVEY_ENTRY_MAX];
extern void AccumulateSiteSurveyResults(void *BssData_p, UINT8 * rfHdr_p);
#endif /* AP_SITE_SURVEY */
#endif
/*============================================================================= */
/*                         IMPORTED PUBLIC VARIABLES */
/*============================================================================= */

UINT8 WiFiOUI[3] = { 0x00, 0x50, 0xf2 };
UINT8 B_COMP_OUI[3] = { 0x00, 0x90, 0x4c };
UINT8 I_COMP_OUI[3] = { 0x00, 0x17, 0x35 };

#ifdef MULTI_AP_SUPPORT
UINT8 MultiAP_OUI[3] = { 0x50, 0x6F, 0x9A };
#endif /*MULTI_AP_SUPPORT */
#ifdef INTOLERANT40
#define INTOLERANTCHEKCOUNTER	1500	//25 MIN
static UINT32 sMonitorcnt30min = 0;
#endif

IEEEtypes_DataRate_t OpRateSet[IEEEtypes_MAX_DATA_RATES_G];
IEEEtypes_DataRate_t BasicRateSet[IEEEtypes_MAX_DATA_RATES_G];
UINT32 BasicRateSetLen;
UINT32 OpRateSetLen;

static UINT8 OpRateSetIndex[IEEEtypes_MAX_DATA_RATES_G];

static UINT8 BasicRateSetIndex[IEEEtypes_MAX_DATA_RATES_G];
static UINT32 LowestBasicRate;
static UINT32 LowestBasicRateIndex;
static UINT32 HighestBasicRate;
UINT32 HighestBasicRateIndex;
static UINT32 HighestBasicRateB;
static UINT32 LowestBasicRateB;
UINT32 HighestBasicRateIndexB;
static UINT32 LowestBasicRateIndexB;

static UINT32 LowestOpRate;
static UINT32 LowestOpRateIndex;
static UINT32 HighestOpRate;
static UINT32 HighestOpRateIndex;

volatile UINT32 ResetDone = 0;

extern macmgmtQ_MgmtMsg_t *BcnBuffer_p;
#ifdef ENABLE_RATE_ADAPTATION
extern UINT32 AssocStationsCnt;
#endif

IEEEtypes_MacAddr_t bcast = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

#ifdef ENABLE_ERP_PROTECTION
UINT32 macErpProtModeEnabled = 1;
#else
UINT32 macErpProtModeEnabled = 0;
#endif

extern macmgmtQ_MgmtMsg_t *PrbRspBuf_p;
UINT32 macChangeSlotTimeModeTo = SLOT_TIME_MODE_SHORT;
UINT32 macCurSlotTimeMode = SLOT_TIME_MODE_LONG;

UINT8 BarkerPreambleSet = 0;
UINT8 PreviousBAroundStnCount;
extern UINT8 AGinterval;
extern UINT8 freq54g;
UINT8 RfSwitchChanA, RfSwitchChanG;
extern UINT32 AGintOffset;

typedef struct mu_temp_set {
	extStaDb_StaInfo_t *StaInfo[4];
	int cnt;
} mu_temp_set_t;
mu_temp_set_t temp_mu_set[4]; /** ldpc, BW **/

extern void disableAmpduTx(vmacApInfo_t * vmacSta_p, UINT8 * macaddr,
			   UINT8 tid);
#ifdef AP_STEERING_SUPPORT
static IEEEtypes_StatusCode_t G_AssocStatusCode = IEEEtypes_STATUS_SUCCESS;
#endif

/*============================================================================= */
/*                          MODULE LEVEL VARIABLES */
/*============================================================================= */
IEEEtypes_BssDesc_t BssDesc;

/* data for testing */
smeQ_MgmtMsg_t ResetCfrm;
/*============================================================================= */
/*                   PRIVATE PROCEDURES (ANSI Prototypes) */
/*============================================================================= */
WL_STATUS isSsIdMatch(IEEEtypes_SsIdElement_t * SsId1,
		      IEEEtypes_SsIdElement_t * SsId2);

WL_STATUS isCapInfoSupported(IEEEtypes_CapInfo_t * CapInfo1,
			     IEEEtypes_CapInfo_t * CapInfo2);
UINT32 GetHighestRateIndex(vmacApInfo_t * vmacSta_p,
			   IEEEtypes_SuppRatesElement_t * SuppRates,
			   IEEEtypes_ExtSuppRatesElement_t * ExtSuppRates,
			   BOOLEAN * gRatePresent);
WL_STATUS isBasicRatesSupported(IEEEtypes_SuppRatesElement_t * SuppRates,
				IEEEtypes_ExtSuppRatesElement_t * ExtSuppRates,
				BOOLEAN gRatePresent);
UINT32 SetSuppRateSetRegMap(vmacApInfo_t * vmacSta_p,
			    IEEEtypes_SuppRatesElement_t * SuppRates,
			    UINT32 * SuppRateSetRegMap);
void PrepareRateElements(vmacApInfo_t * vmacSta_p,
			 IEEEtypes_StartCmd_t * StartCmd_p);
void FixedRateCtl(extStaDb_StaInfo_t * pStaInfo, PeerInfo_t * PeerInfo,
		  MIB_802DOT11 * mib);
#ifdef BRS_SUPPORT
int isClientRateMatchAP(vmacApInfo_t * vmacSta_p, UINT8 * Rates);
#endif
#ifdef INTOLERANT40
static void HT40MIntolerantHandler(vmacApInfo_t * vmacSta_p, UINT8 soon);
BOOLEAN macMgmtMlme_SendBeaconReqMeasureReqAction(struct net_device *dev,
						  IEEEtypes_MacAddr_t * Addr);
BOOLEAN macMgmtMlme_SendExtChanSwitchAnnounceAction(struct net_device *dev,
						    IEEEtypes_MacAddr_t * Addr);
#endif
extern UINT32 CopySsId(UINT8 * SsId1, UINT8 * SsId2);
extern UINT8 RFInit(void);
extern void hw_Init(void);
extern void extStaDb_ProcessAgeTick(UINT8 * data);
#ifdef SOC_W906X
extern void macMgmtMlme_SendDeauthenticateMsg(vmacApInfo_t * vmacSta_p,
					      IEEEtypes_MacAddr_t * Addr,
					      UINT16 StnId, UINT16 Reason,
					      UINT8 sendCmd);
#else
extern void macMgmtMlme_SendDeauthenticateMsg(vmacApInfo_t * vmacSta_p,
					      IEEEtypes_MacAddr_t * Addr,
					      UINT16 StnId, UINT16 Reason);
#endif
extern void macMgmtMlme_SendDisassociateMsg(vmacApInfo_t * vmacSta_p,
					    IEEEtypes_MacAddr_t * Addr,
					    UINT16 StnId, UINT16 Reason);
extern void macMgmtCleanUp(vmacApInfo_t * vmacSta_p,
			   extStaDb_StaInfo_t * StaInfo_p);
#ifdef AP_MAC_LINUX
extern struct sk_buff *mlmeApiPrepMgtMsg(UINT32 Subtype,
					 IEEEtypes_MacAddr_t * DestAddr,
					 IEEEtypes_MacAddr_t * SrcAddr);
#else
extern tx80211_MgmtMsg_t *mlmeApiPrepMgtMsg(UINT32 Subtype,
					    IEEEtypes_MacAddr_t * DestAddr,
					    IEEEtypes_MacAddr_t * SrcAddr);
#endif
#ifdef AP_MAC_LINUX
extern struct sk_buff *mlmeApiPrepMgtMsg2(UINT32 Subtype,
					  IEEEtypes_MacAddr_t * DestAddr,
					  IEEEtypes_MacAddr_t * SrcAddr,
					  UINT16 size);
#else
extern tx80211_MgmtMsg_t *mlmeApiPrepMgtMsg2(UINT32 Subtype,
					     IEEEtypes_MacAddr_t * DestAddr,
					     IEEEtypes_MacAddr_t * SrcAddr,
					     UINT16 size);
#endif
extern void KeyMgmtHskCtor(vmacApInfo_t * vmacSta_p,
			   extStaDb_StaInfo_t * pStaInfo);
extern void ProcessAddBAReq(macmgmtQ_MgmtMsg_t *);
extern void ProcessDelBA(macmgmtQ_MgmtMsg_t *);
extern void ProcessDlpReq(vmacApInfo_t * vmacSta_p, macmgmtQ_MgmtMsg_t *);
extern void ProcessDlpTeardown(vmacApInfo_t * vmacSta_p, macmgmtQ_MgmtMsg_t *);
extern void ProcessDlpRsp(vmacApInfo_t * vmacSta_p, macmgmtQ_MgmtMsg_t *);
extern void hw_Init2(void);
extern UINT8 BBPInit(void);
extern void wlQosSetQAsCAPQ(UINT32);
extern BOOLEAN wlInitPHY(void);
extern void set_11a_mode(void);
extern void set_11g_mode(void);
extern UINT32 hw_GetPhyRateIndex(vmacApInfo_t *, UINT32);
extern UINT32 hw_GetPhyRateIndex2(UINT32);
extern BOOLEAN wlSet11aRFChan(UINT32);
extern BOOLEAN wlEnableReceiver(void);
#ifdef WMM_PS_SUPPORT
extern Status_e
NotifyPwrModeChange(IEEEtypes_MacAddr_t * mac, IEEEtypes_PwrMgmtMode_e mode,
		    UINT8 flag, UINT8 flag)
{
	return FAIL;
};
#else
extern Status_e
NotifyPwrModeChange(IEEEtypes_MacAddr_t * mac, IEEEtypes_PwrMgmtMode_e mode)
{
	return FAIL;
};
#endif
extern void DisableBlockTrafficMode(vmacApInfo_t * vmacSta_p);
extern UINT32 Rx_Traffic_Cnt(vmacApInfo_t * vmacSta_p);
extern UINT32 Rx_Traffic_Err_Cnt(vmacApInfo_t * vmacSta_p);

extern UINT32 Rx_Traffic_BBU(vmacApInfo_t * vmacSta_p);

extern void wlQosSetQosBackoffRegs(BOOLEAN);
#ifdef WMM_PS_SUPPORT
extern extStaDb_Status_e extStaDb_SetQosInfo(vmacApInfo_t * vmacSta_p,
					     IEEEtypes_MacAddr_t *,
					     QoS_WmeInfo_Info_t *);
#endif

extern Status_e NotifyAid(UINT16 StnId, UINT16 Aid, Boolean PollFlag);

extern void syncSrv_SetNextChannel(vmacApInfo_t * vmacSta_p);

//extern void apiSetHiPower();

extern WL_STATUS mlmeAuthInit(UINT16 NoStns);
extern void mlmeAuthCleanup(vmacApInfo_t * vmacSta_p);
extern void StnIdListCleanup(vmacApInfo_t * vmacSta_p);
extern void EnableBlockTrafficMode(vmacApInfo_t * vmacSta_p);
#ifdef AUTOCHANNEL
extern BOOLEAN wlUpdateAutoChan(vmacApInfo_t * vmacSta_p, UINT32 chan,
				UINT8 shadowMIB);
#endif
extern BOOLEAN isMcIdIE(UINT8 * data_p);
extern BOOLEAN isM_RptrIdIE(UINT8 * data_p);
extern void keyMgmt_msg(vmacApInfo_t * vmacSta_p, DistTaskMsg_t * pDistMsg);
extern int wlFwSetAPUpdateTim(struct net_device *, u_int16_t, Bool_e);
#ifdef SOC_W906X
extern int wlFwSetChannelSwitchIE(struct net_device *netdev, UINT16 nextChannel,
				  UINT16 secChan, UINT32 mode, UINT32 count,
				  CHNL_FLAGS Chanflag);
#else
extern int wlFwSetChannelSwitchIE(struct net_device *netdev, UINT32 nextChannel,
				  UINT32 mode, UINT32 count, UINT32 freq,
				  UINT32 bw);
#endif
extern UINT16 extStaDb_AggrCk(vmacApInfo_t * vmacSta_p);
extern void extStaDb_Cleanup(vmacApInfo_t * vmacSta_p);
extern UINT16 AddAddHT_IE(vmacApInfo_t * vmacSta_p,
			  IEEEtypes_Add_HT_Element_t * pNextElement);
extern void wlAcntCopyRateTbl(struct net_device *netdev, UINT8 * sta_addr,
			      UINT32 sta_id, UINT8 type);

int wlFwSetSecurity(struct net_device *netdev, u_int8_t * staaddr);
int wlFwSetHTGF(struct net_device *netdev, UINT32 mode);
void sendLlcExchangeID(struct net_device *dev, IEEEtypes_MacAddr_t * src);
void HandleNProtectionMode(vmacApInfo_t * vmacSta_p);
#ifdef COEXIST_20_40_SUPPORT
void Handle20_40_Channel_switch(vmacApInfo_t * vmacSta_p, UINT8);
extern int Check_40MHz_Affected_range(vmacApInfo_t *, int, int);
#define FortyMIntolerantRSSIThres	50	//RSSI threshold so AP is less sensitive to switch from 40 to 20MHz
#endif

void checkLegDevOutBSS(vmacApInfo_t * vmacSta_p);
#ifdef MBSS
extern vmacApInfo_t *vmacGetMBssByAddr(vmacApInfo_t * vmacSta_p,
				       UINT8 * macAddr_p);
#endif

#ifdef CCK_DESENSE
extern void cck_desense_ctrl(struct net_device *netdev, int state);
#endif /* CCK_DESENSE */

#if defined(SOC_W906X) && defined(CFG80211)
void fillStaInfo(struct net_device *netdev, struct station_info *pSinfo,
		 struct extStaDb_StaInfo_t *pStaInfo);
void fillApCapInfo(struct net_device *netdev, int mode, u8 * pApCap,
		   u32 * pLen);
void fillApRadioInfo(struct net_device *netdev,
		     struct ap_radio_basic_capa_rpt_t *pRpt);
#endif /* SOC_W906X */

extern u32 get_mbssid_profile(void *wlpd, u8 xmit_bssids);
extern u32 get_individual_bss(void *wlpd);

/** To be clean up later ftang **/
#define RX_CORE_ProModeEn (1)
#define RX_CORE_BSSIDFltMode (1<<1)
#define RX_CORE_BrdCstSSIDEn (1<<2)
#define RX_CORE_RxEn (1<<3)
#define RX_CORE_IgnoreFCS (1<<4)
#define RX_CORE_DnfBufOnly (1<<5)
#define RX_CORE_all_mcast (1<<6)
#define RX_CORE_all_ucast (1<<7)
#define RX_CORE_no_fwd_done (1<<8)
#define RX_CORE_no_defrag (1<<9)
#define RX_CORE_reserved (1<<10)
#define RX_CORE_sta_addr4 (1<<11)
#define RX_CORE_rx_beacon (1<<12)

static UINT32 GetLegacyRateBitMap(vmacApInfo_t * vmacSta_p,
				  IEEEtypes_SuppRatesElement_t * SuppRates,
				  IEEEtypes_ExtSuppRatesElement_t *
				  ExtSuppRates);
/*============================================================================= */
/*                         CODED PUBLIC PROCEDURES */
/*============================================================================= */
//static void dummy(void){}

extern int wlFwSetNProtOpMode(struct net_device *netdev, UINT8 mode);

extern int wlFwSetOfdma_Mode(struct net_device *netdev, UINT8 option,
			     UINT8 ru_mode, UINT32 max_delay, U32 max_sta);

extern WL_STATUS
macMgmtMlme_Init(vmacApInfo_t * vmacSta_p, UINT32 maxStns,
		 IEEEtypes_MacAddr_t * stnMacAddr)
{
	static int idlistinit = 0;
#ifdef ENABLE_RATE_ADAPTATION
	UINT32 i;
	for (i = 0; i <= MAX_AID; i++) {
		AssocTable[i].RateToBeUsedForTx = 1;	/* index of the Rate reg 0 */
		AssocTable[i].HighestRateIndex = 1;
	}
	AssocStationsCnt = 0;
#endif

	/*-----------------------------------------------------------*/
	/* Initialize the random number generator used in generating */
	/* challenge text.                                           */
	/*-----------------------------------------------------------*/
	if (idlistinit == 0) {
		if (mlmeAuthInit(maxStns) == OS_FAIL)
			return (OS_FAIL);
		idlistinit++;
	}
	if (InitAidList(vmacSta_p) == OS_FAIL)
		return (OS_FAIL);
	if (InitStnIdList(vmacSta_p) == OS_FAIL)
		return (OS_FAIL);

	memcpy(&vmacSta_p->macStaAddr, stnMacAddr, sizeof(IEEEtypes_MacAddr_t));
	memcpy(&vmacSta_p->macBssId, stnMacAddr, sizeof(IEEEtypes_MacAddr_t));

	memcpy(&vmacSta_p->macBssId2, stnMacAddr, sizeof(IEEEtypes_MacAddr_t));
	vmacSta_p->macBssId2[5] = vmacSta_p->macBssId2[5] + 1;
	return (OS_SUCCESS);
}

#ifdef CONFIG_IEEE80211W
typedef struct IEEE80211w_AAD_t {
	IEEEtypes_FrameCtl_t FrmCtl;
	IEEEtypes_MacAddr_t DestAddr;
	IEEEtypes_MacAddr_t SrcAddr;
	IEEEtypes_MacAddr_t BssId;
} PACK_END IEEE80211w_AAD_t;
int
add_MMIE(vmacApInfo_t * vmac_p, UINT8 * buf)
{
	int len = 0;
	IEEEtypes_MMIE_Element_t *mmie_p = (IEEEtypes_MMIE_Element_t *) buf;
	mmie_p->ElementId = 76;
	if (vmac_p->igtksaInstalled == WL_CIPHER_IGTK) {
		mmie_p->Len = 16;
		len = sizeof(IEEEtypes_MMIE_Element_t) - 8;
	} else if (vmac_p->igtksaInstalled == WL_CIPHER_AES_GMAC ||
		   vmac_p->igtksaInstalled == WL_CIPHER_AES_GMAC_256 ||
		   vmac_p->igtksaInstalled == WL_CIPHER_AES_CMAC_256) {
		mmie_p->Len = 24;
		len = sizeof(IEEEtypes_MMIE_Element_t);
	} else
		printk("error: unknown cipher type \n");

	mmie_p->KeyID = vmac_p->GN_igtk;	//4 //4 or 5

	vmac_p->pn[0]++;
	if (vmac_p->pn[0] == 0)
		vmac_p->pn[1]++;

	memcpy(mmie_p->IPN, &vmac_p->pn[0], 6);
	memset(mmie_p->MIC, 0, 16);
	return len;
}

int
add_MMIET(vmacApInfo_t * vmac_p, UINT8 * buf)
{
	int len = 0;
	IEEEtypes_MMIE_Element_t *mmie_p = (IEEEtypes_MMIE_Element_t *) buf;
	mmie_p->ElementId = 76;
	mmie_p->Len = 16;
	mmie_p->KeyID = 4;	//4 or 5
	mmie_p->IPN[0] = 4;
	memset(mmie_p->MIC, 0, 8);
	len = sizeof(IEEEtypes_MMIE_Element_t);
	return len;
}

extern int omac1_aes_128(const u8 * key, const u8 * data, size_t data_len,
			 u8 * mac);

int
isRobustMgmtFrame(UINT16 Subtype)
{
	if ((Subtype != IEEE_MSG_DISASSOCIATE) &&
	    (Subtype != IEEE_MSG_DEAUTHENTICATE) &&
	    (Subtype != IEEE_MSG_QOS_ACTION))
		return 0;
	return 1;
}

int
isRobustQoSFrame(UINT16 qosCategory)
{
	switch (qosCategory) {
	case 0:
	case 1:
	case 2:
	case 3:
	case 4:
	case 5:
	case 6:
	case 8:
	case 9:
	case 126:
		return 1;
	}
	return 0;
}

int
validateFrameContents(macmgmtQ_MgmtMsg3_t * mgtFrm)
{
	IEEEtypes_MMIE_Element_t *mmie_p;
	UINT8 *ptr = (UINT8 *) mgtFrm;
	UINT16 totallen = sizeof(IEEEtypes_MgmtHdr3_t);	/*init */
	UINT16 numofIEs = 0;
	int ret = 0;

	switch (mgtFrm->Hdr.FrmCtl.Subtype) {
	case IEEE_MSG_DISASSOCIATE:
	case IEEE_MSG_DEAUTHENTICATE:
		mmie_p = &mgtFrm->Body.Deauth.mmie;
		totallen += 2;	/* reason code 2 bytes */
		printk("subtype: %x reason: %x mmie_p->ElementId: %x\n",
		       mgtFrm->Hdr.FrmCtl.Subtype,
		       mgtFrm->Body.Deauth.ReasonCode, mmie_p->ElementId);
		while ((mgtFrm->Hdr.FrmBodyLen + 2) > totallen) {
			mmie_p = (IEEEtypes_MMIE_Element_t *) (ptr + totallen);	/* last IE */
			totallen += (2 + ptr[totallen + 1]);	/* IEId+IELen + IEBody */
			if (numofIEs++ > 20) {	/* in case of dead loop */
				ret = 1;
				printk("dead loop \n");
				break;
			}
		}
		printk("FrmBodyLen = %d totallen = %d\n",
		       mgtFrm->Hdr.FrmBodyLen, totallen);
		if (totallen != mgtFrm->Hdr.FrmBodyLen + 2)
			ret = 1;
		/* invalid reason code */
		if (mgtFrm->Body.Deauth.ReasonCode >
		    IEEEtypes_REASON_8021X_AUTH_FAIL)
			ret = 1;
		break;
	case IEEE_MSG_QOS_ACTION:
		break;
	}
	return ret;
}

int
validateRobustManagementframe(vmacApInfo_t * vmac_p,
			      extStaDb_StaInfo_t * StaInfo_p,
			      macmgmtQ_MgmtMsg3_t * mgtFrm)
{
	if (!StaInfo_p)
		return 0;
	if (!StaInfo_p->Ieee80211wSta)
		return 0;
	if (!isRobustMgmtFrame(mgtFrm->Hdr.FrmCtl.Subtype))
		return 0;
	if (StaInfo_p->ptkCipherOuiType == CIPHER_OUI_TYPE_NONE)
		return 0;

	if (IS_MULTICAST(mgtFrm->Hdr.DestAddr)) {
	} else {
		if (!mgtFrm->Hdr.FrmCtl.Wep)
			return 1;
		else
			return validateFrameContents(mgtFrm);
	}
	return 0;

}

extern int aes_gmac(const u8 * key, size_t key_len, const u8 * iv,
		    size_t iv_len, const u8 * aad, size_t aad_len, u8 * tag);
extern struct crypto_cipher *ieee80211_aes_cmac_key_setup(const u8 * key,
							  size_t key_len);
extern void ieee80211_aes_cmac_256(struct crypto_cipher *tfm, const u8 * aad,
				   const u8 * data, size_t data_len, u8 * mic);
extern void ieee80211_aes_cmac_key_free(struct crypto_cipher *tfm);

#define MMIE_AAD_LEN	sizeof(IEEE80211w_AAD_t)	//20

int
mgmtBipMicHandler(UINT8 bipType, UINT8 * igtk, macmgmtQ_MgmtMsg2_t * mgtFrm,
		  IEEEtypes_MMIE_Element_t * mmie_p,
		  int payload_len, BOOLEAN isEnc)
{
	IEEEtypes_MgmtHdr2_t header;
	IEEE80211w_AAD_t *aad_p;
	UINT8 mic[BIP_MIC_SIZE_MAX];
	UINT8 mic_bk[BIP_MIC_SIZE_MAX];
	int retCode = 0;
	int mic_len = BIP_MIC_SIZE_MAX;

	memcpy(&header, &mgtFrm->Hdr, sizeof(IEEEtypes_MgmtHdr2_t));
	aad_p = (IEEE80211w_AAD_t *) ((UINT8 *) mgtFrm + (sizeof(IEEEtypes_MgmtHdr2_t) - sizeof(IEEE80211w_AAD_t)));	//10
	aad_p->FrmCtl = header.FrmCtl;

	//memcpy((u8 *)(aad_p->DestAddr), (u8 *)(header.DestAddr), MMIE_AAD_LEN - sizeof(IEEEtypes_FrameCtl_t)); //18
	{			//for passing klocwork cretiria
		UINT8 *pdesc = aad_p->DestAddr;
		UINT8 *psrc = header.DestAddr;
		memcpy(pdesc, psrc, MMIE_AAD_LEN - sizeof(IEEEtypes_FrameCtl_t));	//18
	}

	aad_p->FrmCtl.Retry = 0;
	aad_p->FrmCtl.PwrMgmt = 0;
	aad_p->FrmCtl.MoreData = 0;

	if (bipType == WL_CIPHER_IGTK)
		mic_len = BIP_MIC_SIZE_CMAC_128;

	if (!isEnc) {
		memcpy(mic_bk, (UINT8 *) mmie_p->MIC, mic_len);
		memset((UINT8 *) mmie_p->MIC, 0x00, mic_len);
	}

	if (bipType == WL_CIPHER_IGTK) {
		omac1_aes_128((const UINT8 *)igtk,
			      (const UINT8 *)aad_p,
			      (size_t) (payload_len + MMIE_AAD_LEN), mic);
		memcpy((UINT8 *) mmie_p->MIC, mic, mic_len);
	} else if (bipType == WL_CIPHER_AES_GMAC ||
		   bipType == WL_CIPHER_AES_GMAC_256 ||
		   bipType == WL_CIPHER_AES_CMAC_256) {
		u8 nonce[12], *npos;
		size_t igtk_len = 32;

		if (bipType == WL_CIPHER_AES_GMAC)
			igtk_len = 16;

		if (bipType == WL_CIPHER_AES_CMAC_256) {
			struct crypto_cipher *tfm = 0;
			tfm = ieee80211_aes_cmac_key_setup((const UINT8 *)igtk,
							   igtk_len);
			if (tfm == 0) {
				printk("error: key setup fail for WL_CIPHER_AES_CMAC256");
				return 0;
			}
			ieee80211_aes_cmac_256(tfm, (const UINT8 *)aad_p,
					       (const u8 *)mgtFrm->Body.data,
					       (size_t) payload_len,
					       mmie_p->MIC);
			ieee80211_aes_cmac_key_free(tfm);
		} else {
			memcpy(nonce, &header.SrcAddr, ETH_ALEN);
			npos = nonce + ETH_ALEN;
			*npos++ = mmie_p->IPN[5];
			*npos++ = mmie_p->IPN[4];
			*npos++ = mmie_p->IPN[3];
			*npos++ = mmie_p->IPN[2];
			*npos++ = mmie_p->IPN[1];
			*npos++ = mmie_p->IPN[0];

			aes_gmac((const UINT8 *)igtk, igtk_len, nonce,
				 sizeof(nonce), (const UINT8 *)aad_p,
				 (size_t) (payload_len + MMIE_AAD_LEN),
				 mmie_p->MIC);
		}
	} else {
		printk("error: unknown cipher \n");
		return 0;
	}

	if (!isEnc) {
		//check MIC
		if (memcmp(mic_bk, mmie_p->MIC, mic_len))
			retCode = 1;
	}

	memcpy(&mgtFrm->Hdr, &header, sizeof(IEEEtypes_MgmtHdr2_t));
	printk("mgmtBipMicHandler:::: isEnc=%d processed payload_len=%d retCode=%d\n", isEnc, payload_len, retCode);
	if (isEnc)
		return payload_len;
	else
		return retCode;
}

int
macMgmtBIP(vmacApInfo_t * vmac_p, macmgmtQ_MgmtMsg2_t * mgtFrm, int payload_len)
{
	IEEEtypes_MMIE_Element_t *mmie_p;

	if (!vmac_p->ieee80211w)
		return 0;
	if (!vmac_p->igtksaInstalled)
		return 0;
	if (!IS_MULTICAST(mgtFrm->Hdr.DestAddr))
		return 0;

	if (!isRobustMgmtFrame(mgtFrm->Hdr.FrmCtl.Subtype))
		return 0;
	if ((mgtFrm->Hdr.FrmCtl.Subtype == IEEE_MSG_QOS_ACTION) &&
	    !isRobustQoSFrame(mgtFrm->Body.Action.Category))
		return 0;

	mmie_p = (IEEEtypes_MMIE_Element_t *) ((UINT8 *) & mgtFrm->Body +
					       payload_len);
	payload_len += add_MMIE(vmac_p, (UINT8 *) mmie_p);
	return mgmtBipMicHandler(vmac_p->igtksaInstalled, vmac_p->igtk, mgtFrm,
				 mmie_p, payload_len, TRUE);
}
#endif

#ifdef AUTOCHANNEL
static inline int
syncSrv_wifi_noise(vmacApInfo_t * vmacSta_p)
{
	int i = 0;
	while (vmacSta_p->ScanParams.ChanList[i]) {
		if (vmacSta_p->acs_db[i].bss_num &&
		    vmacSta_p->acs_db[i].raw_max_rssi >= -(rssi_threshold))
			return 1;
		i++;
	}
	return 0;
}

static void
syncSrv_channel_score(vmacApInfo_t * vmacSta_p)
{
	int i = 0;
	unsigned int ch_load, ch_nf;

	if ((vmacSta_p->acs_mode == 1) && vmacSta_p->acs_mode_nf_worst_score)
		vmacSta_p->acs_mode_nf_normalize_factor =
			10000 / vmacSta_p->acs_mode_nf_worst_score;

	while (vmacSta_p->ScanParams.ChanList[i]) {
		unsigned int max_rssi = 0xff;
		unsigned int rssi_bonus = rssi_threshold;
		ch_load =
			min((unsigned int)100,
			    (unsigned int)vmacSta_p->acs_db[i].ch_load);
		ch_nf = vmacSta_p->acs_db[i].noise_floor;
		max_rssi = max_rssi - vmacSta_p->acs_db[i].max_rssi;

		if (vmacSta_p->acs_mode == 0) {
			if (vmacSta_p->acs_db[i].bss_num)
				rssi_bonus =
					abs(rssi_threshold -
					    vmacSta_p->acs_db[i].rssi_ls);

			/* Compute the score baesd on weighted channel load and noise floor */
			if (!syncSrv_wifi_noise(vmacSta_p))
				vmacSta_p->acs_db[i].score =
					((100 -
					  ch_load) *
					 vmacSta_p->acs_ch_load_weight) +
					(abs(ch_nf) *
					 vmacSta_p->acs_ch_nf_weight) +
					max_rssi * vmacSta_p->acs_rssi_weight;
			else
				vmacSta_p->acs_db[i].score =
					rssi_bonus * vmacSta_p->acs_rssi_weight;

			if (vmacSta_p->ScanParams.ChanList[i] == 1 ||
			    vmacSta_p->ScanParams.ChanList[i] == 6 ||
			    vmacSta_p->ScanParams.ChanList[i] == 11) {
				printk("extra weight %d for chan: %u\n",
				       ext_weight_1611,
				       vmacSta_p->ScanParams.ChanList[i]);
				vmacSta_p->acs_db[i].score += ext_weight_1611;
			}

			/* Print the score info */
			if (!syncSrv_wifi_noise(vmacSta_p))
				printk("Channel %d NF: %d Load: %d Rssi: %d (%d), Score %d \n", vmacSta_p->ScanParams.ChanList[i], ch_nf, ch_load, vmacSta_p->acs_db[i].max_rssi, max_rssi, vmacSta_p->acs_db[i].score);
			else
				printk("Channel %d NF: %d Load: %d SUM Rssi: %d, Bss Num: %u, Score: %u (%u)\n", vmacSta_p->ScanParams.ChanList[i], ch_nf, ch_load, vmacSta_p->acs_db[i].rssi_ls, vmacSta_p->acs_db[i].bss_num, vmacSta_p->acs_db[i].score, rssi_bonus);
		} else if (vmacSta_p->acs_mode == 1) {
			printk("Pre Channel %d Score: %u %u (%u)\n",
			       vmacSta_p->ScanParams.ChanList[i],
			       vmacSta_p->acs_db[i].score,
			       100 -
			       ((vmacSta_p->acs_db[i].score *
				 vmacSta_p->acs_mode_nf_normalize_factor) /
				100), vmacSta_p->acs_mode_nf_worst_score);
			/* range is in 0 to 100, higher is better */
			vmacSta_p->acs_db[i].score =
				100 -
				((vmacSta_p->acs_db[i].score *
				  vmacSta_p->acs_mode_nf_normalize_factor) /
				 100);
			printk("Pre Channel %d Score: %u \n",
			       vmacSta_p->ScanParams.ChanList[i],
			       vmacSta_p->acs_db[i].score);
		}

		/* keep the 2 worst channel index */
		if (vmacSta_p->worst_channel_idx[0] == 0xFF)
			vmacSta_p->worst_channel_idx[0] = i;
		else if (vmacSta_p->acs_db[i].score <
			 vmacSta_p->acs_db[vmacSta_p->worst_channel_idx[0]].
			 score) {
			vmacSta_p->worst_channel_idx[1] =
				vmacSta_p->worst_channel_idx[0];
			vmacSta_p->worst_channel_idx[0] = i;
		} else if ((vmacSta_p->worst_channel_idx[1] == 0xFF) ||
			   (vmacSta_p->acs_db[i].score <
			    vmacSta_p->acs_db[vmacSta_p->worst_channel_idx[1]].
			    score))
			vmacSta_p->worst_channel_idx[1] = i;
		i++;
	}
	printk("worst channel (score): %u, %u\n",
	       vmacSta_p->worst_channel_idx[0],
	       vmacSta_p->worst_channel_idx[1]);

	for (i = 0; i < 2; i++) {
		int tmp_idx = vmacSta_p->worst_channel_idx[i];
		int tmp_channel =
			vmacSta_p->acs_db[vmacSta_p->worst_channel_idx[i]].
			channel;

		if (tmp_channel != 0) {
			if (domainChannelValid
			    (tmp_channel - 1, FREQ_BAND_2DOT4GHZ)) {
				printk("debug: change ch%d-1 ch_lod(%d->%d), nf(%d->%d)\n", vmacSta_p->acs_db[tmp_idx].channel, vmacSta_p->acs_db[tmp_idx - 1].ch_load, vmacSta_p->acs_db[tmp_idx].ch_load, vmacSta_p->acs_db[tmp_idx - 1].noise_floor, vmacSta_p->acs_db[tmp_idx].noise_floor);
				vmacSta_p->acs_db[tmp_idx - 1].ch_load =
					vmacSta_p->acs_db[tmp_idx].ch_load;
				vmacSta_p->acs_db[tmp_idx - 1].noise_floor =
					max(vmacSta_p->acs_db[tmp_idx].
					    noise_floor - 5,
					    vmacSta_p->acs_db[tmp_idx].
					    noise_floor);
			}
			if (domainChannelValid
			    (tmp_channel + 1, FREQ_BAND_2DOT4GHZ)) {
				printk("debug: change ch%d+1 ch_lod(%d->%d), nf(%d->%d)\n", vmacSta_p->acs_db[tmp_idx].channel, vmacSta_p->acs_db[tmp_idx + 1].ch_load, vmacSta_p->acs_db[tmp_idx].ch_load, vmacSta_p->acs_db[tmp_idx + 1].noise_floor, vmacSta_p->acs_db[tmp_idx].noise_floor);
				vmacSta_p->acs_db[tmp_idx + 1].ch_load =
					vmacSta_p->acs_db[tmp_idx].ch_load;
				vmacSta_p->acs_db[tmp_idx + 1].noise_floor =
					max(vmacSta_p->acs_db[tmp_idx].
					    noise_floor - 5,
					    vmacSta_p->acs_db[tmp_idx].
					    noise_floor);
			}
		}
	}

	return;
}

/*************************************************************************
* Function: syncSrv_RestorePreScanSettings
*
* Description:
*
* Input:
*
* Output:
*
**************************************************************************/
void
syncSrv_RestorePreScanSettings(vmacApInfo_t * vmacSta_p)
{
	/* Set MAC back to AP Mode */
#ifdef AUTOCHANNEL
	UINT8 cur_channel;
#ifdef COEXIST_20_40_SUPPORT
	if (*(vmacSta_p->ShadowMib802dot11->mib_HT40MIntoler) ||
	    *(vmacSta_p->ShadowMib802dot11->mib_autochannel))
#else
	if (*(vmacSta_p->ShadowMib802dot11->mib_autochannel))
#endif
	{
		MSAN_get_ACS_db(vmacSta_p, vmacSta_p->NumScanChannels, 0);
		syncSrv_channel_score(vmacSta_p);
		vmacSta_p->autochannelstarted = 1;
		cur_channel =
			channelSelected(vmacSta_p,
					(*(vmacSta_p->Mib802dot11->mib_ApMode) &
					 AP_MODE_BAND_MASK) >= AP_MODE_A_ONLY);
#ifdef MRVL_DFS
		if (DfsPresentInNOL(vmacSta_p->dev, cur_channel)) {
			cur_channel = 36;
		}
#endif
#ifdef COEXIST_20_40_SUPPORT
		if (*(vmacSta_p->ShadowMib802dot11->mib_autochannel)) {
			wlUpdateAutoChan(vmacSta_p, cur_channel, 1);
		}
#endif
#ifdef SOC_W8964
		wlSetOpModeMCU(vmacSta_p, MCU_MODE_AP);
#endif
		wlResetTask(vmacSta_p->dev);
		DisableBlockTrafficMode(vmacSta_p);
		complete(&vmacSta_p->scan_complete);
	}
#else
	MIB_PHY_DSSS_TABLE *PhyDSSSTable_p =
		vmacSta_p->Mib802dot11->PhyDSSSTable;
	wlSetRFChan(vmacSta_p, PhyDSSSTable_p->CurrChan);
#endif
#ifdef SOC_W8964
#ifdef AP_URPTR
	if (mib_wbMode == 1)
		wlSetOpModeMCU(vmacSta_p, MCU_MODE_STA_INFRA);
	else
#endif
#endif /* SOC_W8964 */
		}

		static unsigned int
			syncSrv_channel_score_calibration(vmacApInfo_t *
							  vmacSta_p,
							  unsigned int
							  channel_idx) {
		unsigned int calibrated_bss_bonus = 0;
		unsigned int calibrated_ch_bonus = 0;
		unsigned int bssb = 0;
		unsigned int ch_a = 0, ch_b = 0, m = 0;

		/* get distance to the worst 2 channel index (worst score) */
		calibrated_ch_bonus = vmacSta_p->acs_ch_distance_weight *
			(abs(channel_idx - vmacSta_p->worst_channel_idx[0]) +
			 abs(channel_idx - vmacSta_p->worst_channel_idx[1]) -
			 abs(abs(channel_idx - vmacSta_p->worst_channel_idx[0])
			     - abs(channel_idx -
				   vmacSta_p->worst_channel_idx[1])));

		printk("w0: %u, w1: %u, ch_idx: %u ch_dist_bonus: %u\n",
		       vmacSta_p->worst_channel_idx[0],
		       vmacSta_p->worst_channel_idx[1], channel_idx,
		       calibrated_ch_bonus);

		/* for case where bss is only found in a channel or no bss found in all channel */
		if (vmacSta_p->bss_channel_idx[0] == 0xFF) {
			ch_a = channel_idx;
			ch_b = channel_idx;
		} else if (vmacSta_p->bss_channel_idx[1] == 0xFF) {
			ch_a = vmacSta_p->bss_channel_idx[0];
			ch_b = channel_idx;
		} else {
			ch_a = vmacSta_p->bss_channel_idx[0];
			ch_b = vmacSta_p->bss_channel_idx[1];
			m = 1;
		}

		/* get distance to the worst 2 channel index (having more bss) */
		calibrated_bss_bonus = vmacSta_p->acs_bss_distance_weight *
			(abs(channel_idx - ch_a) + abs(channel_idx - ch_b) -
			 (m *
			  abs(abs(channel_idx - ch_a) -
			      abs(channel_idx - ch_b))));

		printk("b0: %u, b1: %u, m: %u, ch_idx: %u bss_dist_bonus: %u\n",
		       ch_a, ch_b, m, channel_idx, calibrated_bss_bonus);

		/* channel having less bss get some bonus */
		if (vmacSta_p->bss_channel_idx[0] != 0xFF) {
			calibrated_bss_bonus += (vmacSta_p->acs_bss_num_weight *
						 abs(vmacSta_p->
						     acs_db[vmacSta_p->
							    bss_channel_idx[0]].
						     bss_num -
						     vmacSta_p->
						     acs_db[channel_idx].
						     bss_num));
			bssb = vmacSta_p->acs_bss_num_weight *
				abs(vmacSta_p->
				    acs_db[vmacSta_p->bss_channel_idx[0]].
				    bss_num -
				    vmacSta_p->acs_db[channel_idx].bss_num);
		}

		printk("most bss: %u, %u, ch_idx: %u, bssb: %u, calscore: %u\n",
		       vmacSta_p->bss_channel_idx[0],
		       vmacSta_p->acs_db[vmacSta_p->bss_channel_idx[0]].bss_num,
		       channel_idx, bssb,
		       calibrated_bss_bonus + calibrated_ch_bonus);

		return calibrated_bss_bonus + calibrated_ch_bonus;
		}

	extern unsigned int ACS_channel_score_from_nf_reading(unsigned int
							      *NF_map);
	extern SINT32 syncSrv_ScanActTimeOut(UINT8 * data) {
		vmacApInfo_t *vmacSta_p = (vmacApInfo_t *) data;
#ifdef AUTOCHANNEL
		UINT32 t_cnt, bbu_cnt;
		int channel = 0;
		UINT32 ch_load;

		if (vmacSta_p->ChanIdx >= 0)
			channel =
				vmacSta_p->ScanParams.ChanList[vmacSta_p->
							       ChanIdx];
		if (channel) {
			if (vmacSta_p->acs_mode == 0) {
				/* Compute the score in Legacy Mode */
				t_cnt = Rx_Traffic_Cnt(vmacSta_p);
				bbu_cnt = Rx_Traffic_BBU(vmacSta_p);
				ch_load = wl_ch_load(vmacSta_p,
						     ktime_us_delta
						     (ktime_get_real(),
						      vmacSta_p->acs_scantime),
						     vmacSta_p->acs_chload,
						     100);
				vmacSta_p->acs_db[vmacSta_p->ChanIdx].channel =
					channel;
#ifdef SOC_W906X
				vmacSta_p->acs_db[vmacSta_p->ChanIdx].ch_load =
					ch_load;
				vmacSta_p->acs_db[vmacSta_p->ChanIdx].noise_floor = (vmacSta_p->acs_db[vmacSta_p->ChanIdx].noise_floor + wl_util_get_nf(vmacSta_p->dev, NULL, NULL)) >> 1;	/* avarage the 2 samples */
#else /* SOC_W906X */
				vmacSta_p->acs_db[vmacSta_p->ChanIdx].score =
					t_cnt * 100 + bbu_cnt;
#endif /* SOC_W906X */
				//        printk( "finished scanning channel %d, traffic cnt %d, bbu cnt %d\n", channel, (int)t_cnt, (int)bbu_cnt);
				printk("finished scanning channel %d, noise %ddb, ch_load %d\n", channel, vmacSta_p->acs_db[vmacSta_p->ChanIdx].noise_floor, ch_load);
			} else if (vmacSta_p->acs_mode == 1) {
				/* Compute the score in NF-reading Mode */
				vmacSta_p->acs_db[vmacSta_p->ChanIdx].channel =
					channel;
				vmacSta_p->acs_db[vmacSta_p->ChanIdx].score =
					ACS_channel_score_from_nf_reading
					(vmacSta_p->acs_db[vmacSta_p->ChanIdx].
					 nf_bin);
				vmacSta_p->acs_mode_nf_worst_score =
					max((unsigned int)vmacSta_p->
					    acs_mode_nf_worst_score,
					    (unsigned int)vmacSta_p->
					    acs_db[vmacSta_p->ChanIdx].score);
				printk("finished scanning channel %d, score %d\n", channel, vmacSta_p->acs_db[vmacSta_p->ChanIdx].score);
			}
		}
#endif /* AUTOCHANNEL */
		syncSrv_SetNextChannel(vmacSta_p);
		return 0;
	}

	extern void syncSrv_SetNextChannel(vmacApInfo_t * vmacSta_p) {
		/* Increment the index keeping track of which channel scanning for */
		vmacSta_p->ChanIdx++;

		if (vmacSta_p->ChanIdx >= vmacSta_p->NumScanChannels) {
			vmacSta_p->busyScanning = 0;
			syncSrv_RestorePreScanSettings(vmacSta_p);
			/* Reset Mac and Start AP Services */
#ifdef AP_MAC_LINUX
			Disable_ScanTimerProcess(vmacSta_p);
#else
			SendResetCmd(vmacSta_p, 0);
#endif

			return;
		}

		while ((vmacSta_p->ChanIdx < vmacSta_p->NumScanChannels) &&
		       (vmacSta_p->ScanParams.ChanList[vmacSta_p->ChanIdx] ==
			0)) {
			vmacSta_p->ChanIdx++;
		}

		//      etherBugSend("channel[%d] %d\n", ChanIdx, ScanParams.ChanList[ChanIdx]);
		/* Set the rf parameters */
		if (vmacSta_p->ChanIdx < vmacSta_p->NumScanChannels) {
			if (vmacSta_p->acs_mode == 0) {
				/* Start off channel in Legacy mode */
				if (wlSetRFChan
				    (vmacSta_p,
				     vmacSta_p->ScanParams.ChanList[vmacSta_p->
								    ChanIdx]) ==
				    FALSE) {
					vmacSta_p->busyScanning = 0;
					syncSrv_RestorePreScanSettings
						(vmacSta_p);
					/* Reset Mac and Start AP Services */
#ifdef AP_MAC_LINUX
					Disable_ScanTimerProcess(vmacSta_p);
#else
					SendResetCmd(vmacSta_p, 0);
#endif
					return;
				}
				Rx_Traffic_Cnt(vmacSta_p);
				Rx_Traffic_BBU(vmacSta_p);
#ifdef AUTOCHANNEL
				vmacSta_p->acs_db[vmacSta_p->ChanIdx].
					noise_floor =
					(SINT32) wl_util_get_nf(vmacSta_p->dev,
								NULL, NULL);
				vmacSta_p->acs_chload =
					wl_ch_load(vmacSta_p, 0, 0, 0);
				vmacSta_p->acs_scantime = ktime_get_real();
#endif /* AUTOCHANNEL */
			} else if (vmacSta_p->acs_mode == 1) {
				/* Start off channel in NF-reading mode */
				DOT11_OFFCHAN_REQ_t offchan;

				memset((UINT8 *) & offchan, 0x0,
				       sizeof(DOT11_OFFCHAN_REQ_t));
				offchan.channel =
					vmacSta_p->ScanParams.
					ChanList[vmacSta_p->ChanIdx];
				offchan.id = 1;
				offchan.req_type = OFFCHAN_TYPE_RX_NF;	/* NF-reading feedback */
				offchan.dwell_time = 500;
				printk("Offchan ch:%u, id:%u, dwell:%u\n",
				       (unsigned int)offchan.channel,
				       (unsigned int)offchan.id,
				       (unsigned int)offchan.dwell_time);
				wlFwNewDP_queue_OffChan_req(vmacSta_p->dev,
							    &offchan);
			}
		}

		/* Start the scan timer with duration of the maximum channel time */
		if (vmacSta_p->acs_mode == 0)
			TimerRearm(&vmacSta_p->scaningTimer, SCAN_TIME);

	}

	extern void resetautochanneldata(vmacApInfo_t * vmacSta_p) {
		vmacSta_p->autochannelstarted = 0;
		vmacSta_p->worst_channel_idx[0] = 0xFF;
		vmacSta_p->worst_channel_idx[1] = 0xFF;
		vmacSta_p->bss_channel_idx[0] = 0xFF;
		vmacSta_p->bss_channel_idx[1] = 0xFF;
		vmacSta_p->acs_mode_nf_worst_score = 0;
		memset(vmacSta_p->autochannel, 0,
		       sizeof(UINT32) * (IEEEtypes_MAX_CHANNELS +
					 IEEEtypes_MAX_CHANNELS_A));
#ifdef AUTOCHANNEL
		memset(vmacSta_p->acs_db, 0,
		       sizeof(acs_data_t) * (IEEEtypes_MAX_CHANNELS +
					     IEEEtypes_MAX_CHANNELS_A));
#endif /* AUTOCHANNEL */
	}
	extern int channelSelected(vmacApInfo_t * vmacSta_p, int mode) {
		int i;
		int channel = 0, t_channel = 0;
		UINT32 traffic = 0;
		UINT8 band = mode ? FREQ_BAND_5GHZ : FREQ_BAND_2DOT4GHZ;
		/* for AUTOCHANNEL_G_BAND_1_6_11 */
		UINT32 sum1 = 0, sum2 = 0, sum3 = 0;
		MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

#ifdef AP_URPTR
		if (mib_urMode == 1) {
			channel = urSelectedChannel();
			if (channel)
				return channel;
		}
#endif
		if (!vmacSta_p->autochannelstarted)
			return 0;
		i = 0;
		while (vmacSta_p->ScanParams.ChanList[i]) {
			if (*(mib->mib_autochannel) == 2 &&
			    ACS_OpChanCheck(vmacSta_p,
					    vmacSta_p->ScanParams.
					    ChanList[i]) == FAIL) {
				i++;
				continue;
			}
			if (vmacSta_p->ScanParams.ChanList[i] &&
			    domainChannelValid(vmacSta_p->ScanParams.
					       ChanList[i], band)) {
				if (vmacSta_p->autochannel[i] <
				    *(vmacSta_p->Mib802dot11->
				      mib_acs_threshold)) {
					if ((vmacSta_p->ScanParams.
					     ChanList[i] == 1) ||
					    (vmacSta_p->ScanParams.
					     ChanList[i] == 11)) {
						//give the priority to other channels other than low power 1 & 11
						vmacSta_p->autochannel[i] =
							*(vmacSta_p->
							  Mib802dot11->
							  mib_acs_threshold);
					}
					if ((vmacSta_p->ScanParams.
					     ChanList[i] >= 36) &&
					    (vmacSta_p->ScanParams.
					     ChanList[i] <= 48)) {
						//36, 40, 44, 48 power are low, give the other channels more priority
						vmacSta_p->autochannel[i] =
							*(vmacSta_p->
							  Mib802dot11->
							  mib_acs_threshold);
					}
					if ((vmacSta_p->ScanParams.ChanList[i] >
					     48) &&
					    (vmacSta_p->ScanParams.ChanList[i] <
					     149)) {
						//52  - 140 channel yield to 149 - 161, but prior to 36 - 48
						vmacSta_p->autochannel[i] =
							*(vmacSta_p->
							  Mib802dot11->
							  mib_acs_threshold) -
							1;
					}
				}

				/* do channel distance calibration */
				vmacSta_p->autochannel[i] =
					vmacSta_p->acs_db[i].score;
				if (acs_cal)
					vmacSta_p->autochannel[i] +=
						syncSrv_channel_score_calibration
						(vmacSta_p, i);

				if (vmacSta_p->autochannel[i] > traffic) {
					traffic = vmacSta_p->autochannel[i];
					channel =
						vmacSta_p->ScanParams.
						ChanList[i];
					WLDBG_INFO(DBG_LEVEL_7,
						   "%s channel %d rx traffic byte count=%d\n",
						   mode ? "A" : "G", channel,
						   traffic);
				}

				/* AUTOCHANNEL_G_BAND_1_6_11 */
				if (band == FREQ_BAND_2DOT4GHZ) {
					if ((vmacSta_p->ScanParams.
					     ChanList[i] >= 1) &&
					    (vmacSta_p->ScanParams.
					     ChanList[i] <= 5))
						sum1 += vmacSta_p->
							autochannel[i];
					if ((vmacSta_p->ScanParams.
					     ChanList[i] >= 4) &&
					    (vmacSta_p->ScanParams.
					     ChanList[i] <= 8))
						sum2 += vmacSta_p->
							autochannel[i];
					if ((vmacSta_p->ScanParams.
					     ChanList[i] >= 7) &&
					    (vmacSta_p->ScanParams.
					     ChanList[i] <= 11))
						sum3 += vmacSta_p->
							autochannel[i];
				}
			}
			i++;
		}

		/* to enable using only CH1,6, or 11 for ACS. ACSAUTOCHANNEL_G_BAND_1_6_11 */
		if (band == FREQ_BAND_2DOT4GHZ) {
			WLDBG_INFO(DBG_LEVEL_7,
				   "%s channel %d selected before G-Band 1/6/11 optimization, sum1=%d, sum2=%d, sum3=%d\n",
				   mode ? "A" : "G", channel, sum1, sum2, sum3);
			t_channel = channel;
			if ((sum1 >= sum2) && (sum1 >= sum3))
				channel = 1;
			else if ((sum2 >= sum1) && (sum2 >= sum3))
				channel = 6;
			else
				channel = 11;

			if (*(mib->mib_autochannel) == 2) {
				channel = t_channel;
			}
		}

		WLDBG_INFO(DBG_LEVEL_7, "%s channel %d selected\n",
			   mode ? "A" : "G", channel);
		// do not print for now
		//WLSYSLOG(WLSYSLOG_CLASS_ALL, WLSYSLOG_MSG_GEN_AUTOCHANNEL "%d\n", channel);
		return channel;
	}
#endif

#ifdef ERP
	extern void macMgmtMlme_IncrBarkerPreambleStnCnt(vmacApInfo_t *
							 vmacSta_p) {
		MIB_802DOT11 *mib;

		if (vmacSta_p->master)
			vmacSta_p = vmacSta_p->master;

		mib = vmacSta_p->Mib802dot11;
		if (*(mib->mib_ApMode) != AP_MODE_B_ONLY &&
		    !(*(mib->mib_ApMode) & AP_MODE_A_ONLY)) {
			vmacSta_p->BarkerPreambleStnCnt++;

			if (*(mib->mib_ErpProtEnabled) &&
			    (vmacSta_p->BarkerPreambleStnCnt == 1)) {
				bcngen_UpdateBeaconErpInfo(vmacSta_p,
							   SET_ERP_PROTECTION);
			}
		}

	}

	extern void macMgmtMlme_DecrBarkerPreambleStnCnt(vmacApInfo_t *
							 vmacSta_p) {
		MIB_802DOT11 *mib;

		if (vmacSta_p->master)
			vmacSta_p = vmacSta_p->master;
		mib = vmacSta_p->Mib802dot11;

		if (*(mib->mib_ApMode) != AP_MODE_B_ONLY &&
		    !(*(mib->mib_ApMode) & AP_MODE_A_ONLY)) {
			if (vmacSta_p->BarkerPreambleStnCnt > 0)
				vmacSta_p->BarkerPreambleStnCnt--;

			if (*(mib->mib_ErpProtEnabled) &&
			    !vmacSta_p->BarkerPreambleStnCnt) {
				bcngen_UpdateBeaconErpInfo(vmacSta_p,
							   RESET_ERP_PROTECTION);
			}
		}
	}

	extern void macMgmtMlme_IncrBonlyStnCnt(vmacApInfo_t * vmacSta_p,
						UINT8 option) {
		MIB_802DOT11 *mib;
		if (vmacSta_p->master)
			vmacSta_p = vmacSta_p->master;
		mib = vmacSta_p->Mib802dot11;

		if (*(mib->mib_ApMode) != AP_MODE_B_ONLY &&
		    *(mib->mib_ApMode) != AP_MODE_A_ONLY) {
			if (!option)
				vmacSta_p->bOnlyStnCnt++;
//FIX NOW ????  def FIX_LATER /* Remove for Sfly, need to inform firmware of protection mode change. */
#ifdef ENABLE_ERP_PROTECTION
			if (*(mib->mib_ErpProtEnabled) &&
			    (vmacSta_p->bOnlyStnCnt == 1 || BStnAroundCnt)) {
				bcngen_UpdateBeaconErpInfo(vmacSta_p,
							   SET_ERP_PROTECTION);
			}
#endif
			if (*(mib->mib_shortSlotTime) &&
			    (vmacSta_p->bOnlyStnCnt == 1 || BStnAroundCnt)) {
				macChangeSlotTimeModeTo = SLOT_TIME_MODE_LONG;
				//bcngen_EnableBcnFreeIntr();
			}
		}

	}
	extern void macMgmtMlme_DecrBonlyStnCnt(vmacApInfo_t * vmacSta_p,
						UINT8 option) {
		MIB_802DOT11 *mib;
		if (vmacSta_p->master)
			vmacSta_p = vmacSta_p->master;
		mib = vmacSta_p->Mib802dot11;

		if (*(mib->mib_ApMode) != AP_MODE_B_ONLY &&
		    *(mib->mib_ApMode) != AP_MODE_A_ONLY) {
			if (!option && vmacSta_p->bOnlyStnCnt)
				vmacSta_p->bOnlyStnCnt--;
#ifdef ENABLE_ERP_PROTECTION
			if (*(mib->mib_ErpProtEnabled) &&
			    !vmacSta_p->bOnlyStnCnt && !BStnAroundCnt) {
				bcngen_UpdateBeaconErpInfo(vmacSta_p,
							   RESET_ERP_PROTECTION);
			}
#endif
			if (*(mib->mib_shortSlotTime) && !vmacSta_p->bOnlyStnCnt
			    && !BStnAroundCnt) {
				macChangeSlotTimeModeTo = SLOT_TIME_MODE_SHORT;
				//bcngen_EnableBcnFreeIntr();
			}
			if (vmacSta_p->bOnlyStnCnt == 0)
				BarkerPreambleSet = 0;
		}
	}
#endif

#ifdef APCFGUR
	typedef struct IE_UR_Hdr_t {
		UINT8 ElemId;
		UINT8 Len;
		UINT8 OUI[3];	/*00:50:43 */
		UINT8 OUI_Type;
		UINT8 OUI_Subtype;
		UINT8 Version;
	} PACK_END IE_UR_Hdr_t;

	BOOLEAN isUrClientIE(UINT8 * data_p) {
		IE_UR_Hdr_t *ie;
		ie = (IE_UR_Hdr_t *) data_p;
		if (ie->ElemId != RSN_IE) {
			return FALSE;
		}
		if ((ie->OUI[0] != 0x00) || (ie->OUI[1] != 0x50) ||
		    (ie->OUI[2] != 0x43))
			return FALSE;
		if (ie->OUI_Type != 1)
			return FALSE;
		if (ie->OUI_Subtype != 1)
			return FALSE;
		if (ie->Version != 1)
			return FALSE;
		return TRUE;
	}
#endif

	BOOLEAN isVendorSpecVHTIE(UINT8 * data_p) {
		IEEEtypes_VendorSpec_VHT_Element_t *ie;
		ie = (IEEEtypes_VendorSpec_VHT_Element_t *) data_p;

		// Already checked by PROPRIETARY_IE in switch statement
		// if (ie->ElementId != RSN_IE)
		// {
		//     return FALSE;
		// }
		// Already Checked
		// if ((ie->OUI[0] != 0x00) || (ie->OUI[1] != 0x90) || (ie->OUI[2] != 0x4c))
		// {
		//     return FALSE;
		// }
		// if (ie->OUIType !=0x4)
		// {
		//     return FALSE;
		// }
		if (ie->OUISubType != 0x8) {
			return FALSE;
		}
		if (ie->VHTData[0] != 0xbf) {
			return FALSE;
		}
		return TRUE;
	}

#ifdef CONFIG_IEEE80211W
	int parsing_rsn_ie(UINT8 * pData, IEEEtypes_RSN_IE_WPA2_t * pRSNE,
			   UINT8 * mfpc, UINT8 * mfpr)
#else
	int parsing_rsn_ie(UINT8 * pData, IEEEtypes_RSN_IE_WPA2_t * pRSNE)
#endif
	{
		IEEEtypes_RSN_IE_WPA2_t *pIe =
			(IEEEtypes_RSN_IE_WPA2_t *) pData;
		UINT8 *ptr;
		UINT16 len, totalLen = pIe->Len + 2;
		SINT8 left = pIe->Len;

		len = &pIe->GrpKeyCipher[0] - pData;	//Fixed parameters

#ifdef CONFIG_IEEE80211W
		*mfpc = *mfpr = 0;
#endif
		memset((void *)pRSNE, 0x00, sizeof(IEEEtypes_RSN_IE_WPA2_t));
		memcpy((void *)pRSNE, (void *)pIe, len);
		ptr = &pIe->GrpKeyCipher[0];
		left -= sizeof(pRSNE->Ver);

		if ((ptr - pData) >= totalLen) {
			return 1;
		}
		//Group Data Cipher Suite
		memcpy(pRSNE->GrpKeyCipher, ptr, sizeof(pRSNE->GrpKeyCipher));
		ptr += sizeof(pRSNE->GrpKeyCipher);
		left -= sizeof(pRSNE->GrpKeyCipher);

		if ((ptr - pData) >= totalLen) {
			return 2;
		}
		pRSNE->PwsKeyCnt[0] = *ptr++;
		pRSNE->PwsKeyCnt[1] = *ptr++;
		left -= sizeof(pRSNE->PwsKeyCnt);
		if (left <
		    pRSNE->PwsKeyCnt[0] * sizeof(pRSNE->PwsKeyCipherList)) {
			return -1;
		}
		//Check Pairwise Cipher Suite List
		if (pRSNE->PwsKeyCnt[0] == 1) {
			memcpy(pRSNE->PwsKeyCipherList, ptr,
			       sizeof(pRSNE->PwsKeyCipherList));
			ptr += sizeof(pRSNE->PwsKeyCipherList);
		} else {
			printk("%s ::: PwsKeyCnt not correct, take first one only.\n", __FUNCTION__);
			if (pRSNE->PwsKeyCnt[0])
				memcpy(pRSNE->PwsKeyCipherList, ptr,
				       sizeof(pRSNE->PwsKeyCipherList));
			ptr += sizeof(pRSNE->PwsKeyCipherList) *
				pRSNE->PwsKeyCnt[0];
		}
		left -= sizeof(pRSNE->PwsKeyCipherList) * pRSNE->PwsKeyCnt[0];

		if ((ptr - pData) >= totalLen) {
			return 3;
		}
		//Check AKM Cipher Suite Count
		pRSNE->AuthKeyCnt[0] = *ptr++;
		pRSNE->AuthKeyCnt[1] = *ptr++;
		left -= sizeof(pRSNE->AuthKeyCnt);
		if ((pRSNE->AuthKeyCnt[0] == 0) ||
		    (left <
		     pRSNE->AuthKeyCnt[0] * sizeof(pRSNE->AuthKeyList))) {
			return -1;
		}
		//Check AKM Cipher Suite List
		if ((ptr - pData) >= totalLen) {
			return 4;
		}

		if (pRSNE->AuthKeyCnt[0] > 2)
			pRSNE->AuthKeyCnt[0] = 2;

		memcpy(pRSNE->AuthKeyList, ptr,
		       sizeof(pRSNE->AuthKeyList) * pRSNE->AuthKeyCnt[0]);
		ptr += sizeof(pRSNE->AuthKeyList) * pRSNE->AuthKeyCnt[0];
		left -= sizeof(pRSNE->AuthKeyList) * pRSNE->AuthKeyCnt[0];

		if ((ptr - pData) >= totalLen) {
			return 5;
		}
		//Check RSN Cap 
		pRSNE->RsnCap[0] = *ptr++;
		pRSNE->RsnCap[1] = *ptr++;
		left -= sizeof(pRSNE->RsnCap);

#ifdef CONFIG_IEEE80211W
		*mfpc = (pRSNE->RsnCap[0] & 0x80) ? 1 : 0;
		*mfpr = (pRSNE->RsnCap[0] & 0x40) ? 1 : 0;
#endif

		if ((ptr - pData) >= totalLen) {
			return 6;
		}

		if (left < sizeof(pRSNE->PMKIDCnt)) {
			return -1;
		}
		//Check PMKID Count 
		pRSNE->PMKIDCnt[0] = *ptr++;
		pRSNE->PMKIDCnt[1] = *ptr++;
		left -= sizeof(pRSNE->PMKIDCnt);
		if (left < pRSNE->PMKIDCnt[0] * sizeof(pRSNE->PMKIDList)) {
			return -1;
		}

		if ((ptr - pData) >= totalLen) {
			return 7;
		}

		if (pRSNE->PMKIDCnt[0] > 0) {
			memcpy(pRSNE->PMKIDList, ptr, sizeof(pRSNE->PMKIDList));
			ptr += sizeof(pRSNE->PMKIDList);
			left -= sizeof(pRSNE->PMKIDList);

			if ((ptr - pData) >= totalLen) {
				return 8;
			}
		}
#ifdef CONFIG_IEEE80211W
		memcpy(pRSNE->GrpMgtKeyCipher, ptr,
		       sizeof(pRSNE->GrpMgtKeyCipher));
#endif

		return 9;
	}

#ifdef CONFIG_IEEE80211W
	BOOLEAN RsnBIPcap(IEEEtypes_RSN_IE_WPA2_t * ie_p, UINT8 * mfpc,
			  UINT8 * mfpr) {
		UINT8 *data_p = (UINT8 *) ie_p;
		UINT8 offset = 8;	//skip Grp cipher suite
		UINT8 count;
		UINT8 cap;
		SINT16 len = ie_p->Len;

		*mfpc = 0;
		*mfpr = 0;

	/** pairwise cipher Suite ***/
		count = data_p[offset];
		offset += (count * 4 + 2);
		len -= (count * 4 + 2);
		if (!count || (len <= 0))
			return FALSE;

	/** AKM Suites **/
		count = data_p[offset];	//AKM suite count
		offset += (count * 4 + 2);
		len -= (count * 4 + 2);
		if (!count || (len <= 0))
			return FALSE;

	/** RSN CAP **/
		cap = data_p[offset];
		*mfpc = (cap & 0x80) ? 1 : 0;
		*mfpr = (cap & 0x40) ? 1 : 0;

		if (*mfpc)
			return TRUE;

		return FALSE;
	}

	void macMgmtMlme_SAQuery(vmacApInfo_t * vmacSta_p,
				 IEEEtypes_MacAddr_t * Addr,
				 IEEEtypes_MacAddr_t * SrcAddr, UINT32 stamode);
	void SAQueryMgmt_TimeoutHdlr(UINT8 * data) {
		extern extStaDb_Status_e extStaDb_RemoveSta(vmacApInfo_t *
							    vmac_p,
							    IEEEtypes_MacAddr_t
							    * Addr_p);
		extStaDb_StaInfo_t *StaInfo_p = (extStaDb_StaInfo_t *) data;
		struct net_device *netdev = StaInfo_p->dev;
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;

		if (StaInfo_p->sa_query_count++ >= 5) {
			StaInfo_p->sa_query_timed_out = 1;
			printk("%s (%p)\n", __FUNCTION__, StaInfo_p);
			macMgmtMlme_SendDisassociateMsg(vmacSta_p,
							&StaInfo_p->Addr,
							StaInfo_p->StnId,
							IEEEtypes_REASON_PRIOR_AUTH_INVALID);
			extStaDb_RemoveSta(vmacSta_p,
					   (IEEEtypes_MacAddr_t *) & StaInfo_p->
					   Addr);
#ifdef CFG80211
			mwl_cfg80211_disassoc_event(vmacSta_p->dev,
						    (uint8_t *) & StaInfo_p->
						    Addr);
#endif
		} else {
			macMgmtMlme_SAQuery(vmacSta_p, &StaInfo_p->Addr, NULL,
					    0);
			// send SAQuery per 0.2 second as the same hostapd SAQuery implematation
			TimerFireIn(&StaInfo_p->SA_Query_Timer, 1,
				    SAQueryMgmt_TimeoutHdlr,
				    (UINT8 *) StaInfo_p, 2);
		}

	}

	static BOOLEAN macMgmtMlme_WPA2PMF_Verify(vmacApInfo_t * vmacSta_p,
						  struct sk_buff *txSkb_p,
						  extStaDb_StaInfo_t *
						  StaInfo_p,
						  IEEEtypes_RSN_IE_WPA2_t *
						  RsnIEWPA2_p,
						  UINT8 * reconfig_rsn_ie) {
		MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
		UINT8 mfpc, mfpr;
		IEEEtypes_RSN_IE_WPA2_t RsnIEWPA2;
		IEEEtypes_RSN_IE_WPA2_t MibRsnIEWPA2;
		int ret, ret1;
		macmgmtQ_MgmtMsg2_t *MgmtRsp_p =
			(macmgmtQ_MgmtMsg2_t *) txSkb_p->data;

		*reconfig_rsn_ie = FALSE;
		mfpc = mfpr = 0;
		ret = ret1 = 0;
		memset(StaInfo_p->keyMgmtStateInfo.RsnIEBuf, 0,
		       MAX_SIZE_RSN_IE_BUF);
		if ((RsnIEWPA2_p->Len + 2) > MAX_SIZE_RSN_IE_BUF) {
			printk("%s[line %d] out of boundary (%d %d)\n",
			       __FUNCTION__, __LINE__, (RsnIEWPA2_p->Len + 2),
			       MAX_SIZE_RSN_IE_BUF);
			return FALSE;
		} else {
			memcpy(StaInfo_p->keyMgmtStateInfo.RsnIEBuf,
			       RsnIEWPA2_p, RsnIEWPA2_p->Len + 2);
		}
		ret1 = parsing_rsn_ie((UINT8 *) mib->thisStaRsnIEWPA2,
				      &MibRsnIEWPA2, &mfpc, &mfpr);
		ret = parsing_rsn_ie((UINT8 *) RsnIEWPA2_p, &RsnIEWPA2, &mfpc,
				     &mfpr);

		if (RsnIEWPA2.AuthKeyList[3] == 0x08 ||
		    RsnIEWPA2.AuthKeyList1[3] == 0x08) {
			if (mfpc == 0 && mfpr == 0) {
				MgmtRsp_p->Body.AssocRsp.StatusCode =
					IEEEtypes_STATUS_ASSOC_DENIED_INVALID_IE;
				if (txMgmtMsg(vmacSta_p->dev, txSkb_p) !=
				    OS_SUCCESS) {
					wl_free_skb(txSkb_p);
				}
				return FALSE;
			}
		}

		if (ret == -1) {
			MgmtRsp_p->Body.AssocRsp.StatusCode =
				IEEEtypes_STATUS_ASSOC_DENIED_INVALID_IE;
			if (txMgmtMsg(vmacSta_p->dev, txSkb_p) != OS_SUCCESS) {
				wl_free_skb(txSkb_p);
			}
			return FALSE;
		}

		if ((RsnIEWPA2.Ver[0] != 0x01) || (RsnIEWPA2.Ver[1] != 0x00)) {
			MgmtRsp_p->Body.AssocRsp.StatusCode =
				IEEEtypes_STATUS_ASSOC_DENIED_INVALID_IE;
			if (txMgmtMsg(vmacSta_p->dev, txSkb_p) != OS_SUCCESS) {
				wl_free_skb(txSkb_p);
			}
			return FALSE;
		}

		if ((ret > 1) && (ret1 > 1) &&
		    (memcmp
		     (mib->thisStaRsnIEWPA2->GrpKeyCipher,
		      RsnIEWPA2.GrpKeyCipher,
		      sizeof(RsnIEWPA2.GrpKeyCipher)))) {
			MgmtRsp_p->Body.AssocRsp.StatusCode =
				IEEEtypes_STATUS_ASSOC_DENIED_INVALID_GRP_CIPHER;
			if (txMgmtMsg(vmacSta_p->dev, txSkb_p) != OS_SUCCESS) {
				wl_free_skb(txSkb_p);
			}
			return FALSE;
		}

		if ((ret > 2) && (ret1 > 2) &&
		    (memcmp
		     (mib->thisStaRsnIEWPA2->PwsKeyCipherList,
		      RsnIEWPA2.PwsKeyCipherList,
		      sizeof(RsnIEWPA2.PwsKeyCipherList)))) {
			MgmtRsp_p->Body.AssocRsp.StatusCode =
				IEEEtypes_STATUS_ASSOC_DENIED_INVALID_PAIRWISE_CIPHER;
			if (txMgmtMsg(vmacSta_p->dev, txSkb_p) != OS_SUCCESS) {
				wl_free_skb(txSkb_p);
			}
			return FALSE;
		}

		if ((ret == 1) || (ret == 2)) {
			*reconfig_rsn_ie = TRUE;
		}

		if ((ret > 4) && (ret1 > 4)) {
			if ((MibRsnIEWPA2.AuthKeyCnt[0] == 1) &&
			    (RsnIEWPA2.AuthKeyCnt[0] == 1)) {
				if (memcmp
				    (MibRsnIEWPA2.AuthKeyList,
				     RsnIEWPA2.AuthKeyList,
				     sizeof(RsnIEWPA2.AuthKeyList))) {
					MgmtRsp_p->Body.AssocRsp.StatusCode =
						IEEEtypes_STATUS_ASSOC_DENIED_INVALID_AKMP;
					if (txMgmtMsg(vmacSta_p->dev, txSkb_p)
					    != OS_SUCCESS) {
						wl_free_skb(txSkb_p);
					}
					return FALSE;
				}
			}
		}

		if ((ret == 9) && (ret1 == 9)) {
			if (memcmp
			    (MibRsnIEWPA2.GrpMgtKeyCipher,
			     RsnIEWPA2.GrpMgtKeyCipher,
			     sizeof(RsnIEWPA2.GrpMgtKeyCipher))) {
				MgmtRsp_p->Body.AssocRsp.StatusCode =
					IEEEtypes_STATUS_ASSOC_DENIED_CIPHER_SUITE_REJECTED;
				if (txMgmtMsg(vmacSta_p->dev, txSkb_p) !=
				    OS_SUCCESS) {
					wl_free_skb(txSkb_p);
				}
				return FALSE;
			}
		}
#ifdef SOC_W906X
		RsnBIPcap(RsnIEWPA2_p, &mfpc, &mfpr);
#endif
		if ((mfpr == 1) && (vmacSta_p->ieee80211w == 0)) {
			printk("%s[line %d] Drop Packet because of PMF don't Enable\n", __FUNCTION__, __LINE__);
			wl_free_skb(txSkb_p);
			return FALSE;
		}

		if ((mfpr > mfpc) ||
		    ((mfpc != vmacSta_p->ieee80211w) &&
		     (mfpr != vmacSta_p->ieee80211wRequired))) {
			MgmtRsp_p->Body.AssocRsp.StatusCode =
				IEEEtypes_STATUS_ROBUST_MGMT_FRAME_POLICY_VIOLATION;
			if (txMgmtMsg(vmacSta_p->dev, txSkb_p) != OS_SUCCESS) {
				wl_free_skb(txSkb_p);
			}
			return FALSE;
		} else {
			if ((mfpc + mfpr + vmacSta_p->ieee80211w) > 1) {
				StaInfo_p->Ieee80211wSta = 1;
			} else {
				StaInfo_p->Ieee80211wSta = 0;
			}
		}
		return TRUE;
	}
#endif

/******************************************************************************
*
* Name: macMgmtMlme_AssociateReq
*
* Description:
*    This routine handles a response from an AP to a prior associate request.
*
* Conditions For Use:
*    All software components have been initialized and started.
*
* Arguments:
*    Arg1 (i  ): MgmtMsg_p - Pointer to an 802.11 management message
*                            containing an associate response
*
* Return Value:
*    None.
*
* Notes:
*    None.
*
* PDL:
*        Check if the state is authenticated
*        Check if the SSID matches with AP's SSID
*        Check if the Capability Info could be supported
*        Check if the Basic rates are in the Supported rates
*        Assign Aid and store the information
*        Send AssociateRsp message back 
* END PDL
*
*****************************************************************************/

#define OUT_OF_BOUNDARDY_MESSAGE(x, y) printk("%s[line %d] out of boundary (%d %d)\n", __FUNCTION__, __LINE__, x, y)

	static BOOLEAN macMgmtMlme_AssocReAssocIESanityCheck(UINT8 * buf,
							     SINT32 len) {
		SINT32 VarLen = 0;
		UINT8 *VariableElements_p = buf;
		UINT8 *end = (UINT8 *) (buf + len);

		while (VarLen < len) {
			VarLen += (2 + *(VariableElements_p + 1));	/* value in the length field */
			VariableElements_p += 1;
			VariableElements_p += *VariableElements_p;
			VariableElements_p += 1;
			if (VariableElements_p > end)
				return FALSE;
		}
		if (VarLen == len)
			return TRUE;
		return FALSE;
	}

#ifdef WFA_TKIP_NEGATIVE
	extern int allow_ht_tkip;
#endif

#ifdef SOC_W906X
	extern int auto_group_ofdma_mu(vmacApInfo_t * vmac_p);
#endif

	extern BOOLEAN WFA_PeerInfo_HE_CAP_1NSS;
	extern int wlFwSetOfdma_Mode(struct net_device *netdev, UINT8 option,
				     UINT8 ru_mode, UINT32 max_delay,
				     U32 max_sta);

#ifdef MULTI_AP_SUPPORT
	struct multiap_sta_assoc_event {
		SINT32 ie_len;
		IEEEtypes_FrameCtl_t FrmCtl;
		UINT16 Duration;
		IEEEtypes_MacAddr_t DestAddr;
		IEEEtypes_MacAddr_t SrcAddr;
		IEEEtypes_MacAddr_t BssId;
		UINT16 SeqCtl;
		IEEEtypes_CapInfo_t CapInfo;
		IEEEtypes_ListenInterval_t ListenInterval;
		UINT8 more_ies[0];
	} PACK_END;

	struct multiap_sta_reassoc_event {
		SINT32 ie_len;
		IEEEtypes_FrameCtl_t FrmCtl;
		UINT16 Duration;
		IEEEtypes_MacAddr_t DestAddr;
		IEEEtypes_MacAddr_t SrcAddr;
		IEEEtypes_MacAddr_t BssId;
		UINT16 SeqCtl;
		IEEEtypes_CapInfo_t CapInfo;
		IEEEtypes_ListenInterval_t ListenInterval;
		IEEEtypes_MacAddr_t CurrentApAddr;
		UINT8 more_ies[0];
	} PACK_END;
#endif /* MULTI_AP_SUPPORT */

	void macMgmtMlme_AssocReAssocReqHandler(vmacApInfo_t * vmacSta_p,
						macmgmtQ_MgmtMsg3_t * MgmtMsg_p,
						UINT32 msgSize, UINT32 flag) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev);
		MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
		MIB_PRIVACY_TABLE *mib_PrivacyTable_p =
			vmacSta_p->Mib802dot11->Privacy;
		MIB_RSNCONFIGWPA2 *mib_RSNConfigWPA2_p =
			vmacSta_p->Mib802dot11->RSNConfigWPA2;
		extStaDb_StaInfo_t *StaInfo_p;
		macmgmtQ_MgmtMsg2_t *MgmtRsp_p;
		UINT32 frameSize = 0;
		BOOLEAN ChangeAssocParam = FALSE;
		UINT32 Aid, i, staIdx;	//, VarLen;
		SINT32 VarLen;
		UINT8 *VariableElements_p;
#ifdef MULTI_AP_SUPPORT
		SINT32 IELen;
		UINT8 *IEBuf;
		UINT32 event_len;
#endif
		u8 addedExtcap = FALSE;
		IEEEtypes_SuppRatesElement_t *Rates_p = NULL;
		IEEEtypes_ExtSuppRatesElement_t *ExtRates_p =
			NULL, *TxExtRates_p = NULL;
		BOOLEAN gRatePresent;
		UINT32 HighestRate;
		IEEEtypes_SsIdElement_t *SsId_p = NULL;
		IEEEtypes_RSN_IE_t *RsnIE_p = NULL;
#ifdef AP_WPA2
		IEEEtypes_RSN_IE_WPA2_t *RsnIEWPA2_p = NULL;
		UINT8 reconfig_rsn_ie = FALSE;
#endif
#ifdef MRVL_80211R
		IEEEtypes_MOBILITY_DOMAIN_IE_t *MDIE_p = NULL;
		UINT8 *FTIE_p = NULL;
		UINT8 assoc_pending = 0;
#endif
		IEEEtypes_InfoElementHdr_t *InfoElemHdr_p;
		QoS_Cap_Elem_t *QosCapElem_p = NULL;
		WSM_QoS_Cap_Elem_t *WsmQosCapElem_p = NULL;
		WME_param_elem_t *pWMEParamElem = NULL;
		WME_info_elem_t *pWMEInfoElem = NULL;
#ifdef IEEE80211H
		IEEEtypes_PowerCapabilityElement_t *PowerCapability_p = NULL;
		IEEEtypes_SupportedChannelElement_t *SupportedChanne_p = NULL;
#endif /* IEEE80211H */
		DistTaskMsg_t DistMsg;
		DistTaskMsg_t *pDistMsg = &DistMsg;
		StaAssocStateMsg_t *pStaMsg;
		//UINT32 headroom;
		//UINT32 tailroom;
		// - 192: yield the resource
		unsigned char tempbuffer[1024 - 256];
		PeerInfo_t PeerInfo;
		int HTpresent = 0;
		UINT8 amsdu_bitmap = 0;
		UINT8 IE191Present = 0;
		UINT8 IE192Present = 0;
		UINT8 IE199Present = 0;
		UINT8 VendorSpecVHTPresent = 0;
		UINT8 ht_RxChannelWidth_IE61 = 0;
		UINT8 vht_RxChannelWidth_IE191 = 0;
		UINT8 vht_RxChannelWidth_IE192 = 0;	//In IE192, 0:20 or 40Mhz, 1:80Mhz, 2:160Mhz, 3: 80+80Mhz
		UINT8 vht_RxChannelWidth_IE199 = 0;
		UINT8 vht_center_freq0_IE192 = 0;
		UINT8 vht_center_freq1_IE192 = 0;
		UINT8 vht_RxNss_IE199 = 0;
		UINT8 vht_peer_RxNss = 1;	//1:Nss1, 2: Nss2, 3: Nss3 ...
		UINT16 vht_RxNss1 = 1;	//To copy bit0-bit1 of Nss1
		UINT16 vht_RxNssMask = 0;
		UINT32 vhtcap = 0;
		UINT8 *endofmessagelocation = (UINT8 *) MgmtMsg_p + msgSize;
#ifdef SOC_W906X
		int he_cap_present = 0;
		int he_op_present = 0;
		UINT8 wds = 0;
		WLAN_SCHEDULER_HIST *sch_histo_p = NULL;
#endif

#ifdef SOC_W8964
		unsigned long txRateHistoflags;
#endif
#ifdef CAP_MAX_RATE
		UINT8 shiftno;
		UINT8 mcscapmask;
#endif
#ifdef UAPSD_SUPPORT
		UINT8 QosInfo = 0;
		UINT8 isQosSta = 0;
#endif
#if defined(MRV_8021X) && !defined(ENABLE_WLSNDEVT)
		union iwreq_data wreq;	/* MRV_8021X */
#endif
		IEEEtypes_HT_Element_t *pHTIE;
		IEEEtypes_Add_HT_Element_t *pAddHTIE;
#ifdef COEXIST_20_40_SUPPORT
		MIB_PHY_DSSS_TABLE *PhyDSSSTable = mib->PhyDSSSTable;
#endif
#ifdef MRVL_WAPI
		IEEEtypes_WAPI_IE_t *WAPI_IE_p = NULL;
#endif
#ifdef MRVL_WPS2
		void *IE_p = NULL;
#endif
#ifdef SUPPORTED_EXT_NSS_BW
		int ret = 0;
#endif
		IEEEtypes_SuppRatesElement_t *SuppRateSet_p =
			&(vmacSta_p->SuppRateSet);
#ifdef ERP
		IEEEtypes_ExtSuppRatesElement_t *ExtSuppRateSet_p =
			&(vmacSta_p->ExtSuppRateSet);
#endif
#ifdef MULTI_AP_SUPPORT
		unsigned char buf[IW_CUSTOM_MAX] = { 0 };
		union iwreq_data wreq;
		static const char *tag = "1905A";
		UINT8 *capInfo_p = NULL;
		UINT8 *listenInterval_p = NULL;
		struct multiap_sta_assoc_event *multiap_sta_assoc_p;
		struct multiap_sta_reassoc_event *multiap_sta_reassoc_p;
#endif /* MULTI_AP_SUPPORT */
		UINT8 *DH_IE_p = NULL;

#ifdef AP_MAC_LINUX
		struct sk_buff *txSkb_p;
		int extra_size = 0;
#ifdef MRVL_WPS2
		WLAN_TX_RATE_HIST *txrate_histo_p;

#ifdef MULTI_AP_SUPPORT
		IEEEtypes_MultiAP_Element_t *MultiAP_IE_p = NULL;
		UINT16 MultiAP_size = 0;
#endif /* MULTI_AP_SUPPORT */

#ifndef SOC_W906X
		local_irq_disable();
#endif

		if (*(mib->mib_wpaWpa2Mode) > 3)
			extra_size += sizeof(AssocResp_WSCIE_t);
#endif
#ifdef SOC_W906X
		extra_size +=
			(sizeof(IEEEtypes_VhtCap_t) + sizeof(IEEEtypes_VhOpt_t))
			+ sizeof(HE_Capabilities_IE_t)
			+ sizeof(HE_Operation_IE_t);
#else
		extra_size +=
			(sizeof(IEEEtypes_VhtCap_t) +
			 sizeof(IEEEtypes_VhOpt_t));
#endif /* SOC_W906X */

#ifdef MULTI_AP_SUPPORT
		if (mib->multi_ap_attr) {
			MultiAP_size = Get_MultiAP_IE_Size(vmacSta_p);
			extra_size += MultiAP_size;
		}
#endif /* MULTI_AP_SUPPORT */

#ifdef OWE_SUPPORT
		/* OWE mode, adds the Diffie-Hellman Parameter element to association response. */
		if (((vmacSta_p->Mib802dot11->WPA2AuthSuites->AuthSuites[3]) ==
		     0x12)) {
//              extra_size += (sizeof(StaInfo_p->AP_DHIEBuf) + sizeof(StaInfo_p->EXT_RsnIE));
			extra_size += (MAX_SIZE_DH_IE_BUF + 64);
		}
#endif /* OWE_SUPPORT */

#ifdef MBO_SUPPORT
		if (mib->mib_mbo_enabled)
			extra_size += 12;	//sizeof(StaInfo_p->AP_MBOIEBuf);
#endif /* MBO_SUPPORT */

		WLDBG_INFO(DBG_LEVEL_7, "%sassoc rxed", flag ? "re" : "");
		if (wlpptr->wlpd_p->bStopBcnProbeResp &&
		    macMgmtMlme_DfsEnabled(vmacSta_p->dev))
			goto OUT;

		if (flag) {
			if ((txSkb_p =
			     mlmeApiPrepMgtMsg2(IEEE_MSG_REASSOCIATE_RSP,
						&MgmtMsg_p->Hdr.SrcAddr,
						&MgmtMsg_p->Hdr.DestAddr,
						sizeof(IEEEtypes_AssocRsp_t) -
						4 + extra_size)) == NULL)
				goto OUT;
		} else {
			if ((txSkb_p =
			     mlmeApiPrepMgtMsg2(IEEE_MSG_ASSOCIATE_RSP,
						&MgmtMsg_p->Hdr.SrcAddr,
						&MgmtMsg_p->Hdr.DestAddr,
						sizeof(IEEEtypes_AssocRsp_t) -
						4 + extra_size)) == NULL)
				goto OUT;
		}
		MgmtRsp_p = (macmgmtQ_MgmtMsg2_t *) txSkb_p->data;
#else
		/* Allocate space for response message */
		tx80211_MgmtMsg_t *TxMsg_p;

		if ((TxMsg_p =
		     mlmeApiPrepMgtMsg(IEEE_MSG_ASSOCIATE_RSP,
				       &MgmtMsg_p->Hdr.SrcAddr,
				       &MgmtMsg_p->Hdr.DestAddr)) == NULL) {
			goto OUT;
		}
#endif

#ifdef AP_STEERING_SUPPORT
		if (G_AssocStatusCode != IEEEtypes_STATUS_SUCCESS) {
			MgmtRsp_p->Body.AssocRsp.StatusCode = G_AssocStatusCode;
			if ((txMgmtMsg(vmacSta_p->dev, txSkb_p)) != OS_SUCCESS)
				wl_free_skb(txSkb_p);
			goto OUT;
		}
#endif

		/*Check if max sta limit per virtual interface is reached.  By default, it is 64 (MAX_STNS) but user can configure the max limit by
		 * using setcmd maxsta 
		 **/
		if (extStaDb_entries(vmacSta_p, 0) > *(mib->mib_maxsta)) {
			MgmtRsp_p->Body.AssocRsp.StatusCode =
				IEEEtypes_STATUS_ASSOC_DENIED_UNSPEC;
			if ((txMgmtMsg(vmacSta_p->dev, txSkb_p)) != OS_SUCCESS)
				wl_free_skb(txSkb_p);
			goto OUT;
		}

		memset((void *)&PeerInfo, 0, sizeof(PeerInfo_t));
		/* Fill the header and other values */
		if (vmacSta_p->probeRspBody.basic_ies) {
			// issue: short preamble bit incorrect between association response and Probe response 
			vmacSta_p->macCapInfo.ShortPreamble =
				((IEEEtypes_ProbeRsp_t *) vmacSta_p->
				 probeRspBody.basic_ies)->CapInfo.ShortPreamble;
		}
		MgmtRsp_p->Body.AssocRsp.CapInfo = vmacSta_p->macCapInfo;
		MgmtRsp_p->Body.AssocRsp.SuppRates.ElementId = SUPPORTED_RATES;
		MgmtRsp_p->Body.AssocRsp.SuppRates.Len = SuppRateSet_p->Len;
		memcpy((char *)&MgmtRsp_p->Body.AssocRsp.SuppRates.Rates,
		       (char *)&SuppRateSet_p->Rates, SuppRateSet_p->Len);

		//MgmtRsp_p->Hdr.FrmBodyLen = 6 + MgmtRsp_p->Body.AssocRsp.SuppRates.Len + 2;
		//frameSize = MgmtRsp_p->Body.AssocRsp.SuppRates.Len + 2;
		frameSize = 30 /* sizeof(struct ieee80211_frame) */  +
			sizeof(IEEEtypes_CapInfo_t) +
			sizeof(IEEEtypes_StatusCode_t) +
			sizeof(IEEEtypes_AId_t) +
			sizeof(IEEEtypes_InfoElementHdr_t) +
			MgmtRsp_p->Body.AssocRsp.SuppRates.Len;

#ifdef ERP
		if (ExtSuppRateSet_p->Len > 0) {
			TxExtRates_p =
				(IEEEtypes_ExtSuppRatesElement_t *) ((UINT8 *) &
								     MgmtRsp_p->
								     Body.
								     AssocRsp.
								     SuppRates +
								     sizeof
								     (IEEEtypes_InfoElementHdr_t)
								     +
								     SuppRateSet_p->
								     Len);
			TxExtRates_p->ElementId = ExtSuppRateSet_p->ElementId;
			TxExtRates_p->Len = ExtSuppRateSet_p->Len;
			memcpy((char *)&TxExtRates_p->Rates,
			       (char *)&ExtSuppRateSet_p->Rates,
			       ExtSuppRateSet_p->Len);
			//MgmtRsp_p->Hdr.FrmBodyLen += sizeof(IEEEtypes_InfoElementHdr_t) + ExtSuppRateSet.Len;
			frameSize +=
				sizeof(IEEEtypes_InfoElementHdr_t) +
				ExtSuppRateSet_p->Len;
		}
#endif

		if ((StaInfo_p =
		     extStaDb_GetStaInfo(vmacSta_p, &(MgmtMsg_p->Hdr.SrcAddr),
					 STADB_UPDATE_AGINGTIME)) == NULL ||
		    !(StaInfo_p->State == AUTHENTICATED ||
		      StaInfo_p->State == ASSOCIATED) ||
		    vmacSta_p->MIC_ErrordisableStaAsso != 0) {
#ifdef SERCOMM			/* Per FAE, Sercomm needs this. This flag is only for private build */
			/* Purpose - it was said that this is for WAG511 v1 issue */
			/* This is not confirmed, and may break standard protocol so keep as private flag */
			if (StaInfo_p->State == ASSOCIATED) {
				wl_free_skb(txSkb_p);
				goto OUT;
			}
#endif

			if (StaInfo_p == NULL)
				printk("AssocRsp.StatusCode=UNSPEC_FAILURE, StaInfo_p is NULL!\n");
			else
				printk("AssocRsp.StatusCode=UNSPEC_FAILURE, StaInfo_p->State=%d MIC_ErrordisableStaAsso=%d\n", StaInfo_p->State, vmacSta_p->MIC_ErrordisableStaAsso);
			MgmtRsp_p->Body.AssocRsp.StatusCode =
				IEEEtypes_STATUS_UNSPEC_FAILURE;
			//TxMsg_p->stnId = StaInfo_p->StnId;
			/* Send for tx */
			skb_trim(txSkb_p, frameSize);
			if (txMgmtMsg(vmacSta_p->dev, txSkb_p) != OS_SUCCESS)
				wl_free_skb(txSkb_p);
			goto OUT;

		}
#ifdef MRVL_80211R
		if (StaInfo_p->keyMgmtStateInfo.pending_assoc) {
			wl_free_skb(txSkb_p);
			goto OUT;
		}
#endif
#ifdef AP_STEERING_SUPPORT
		memset(&(StaInfo_p->ExtCapElem), 0,
		       sizeof(IEEEtypes_Extended_Cap_Element_t));
#endif /* AP_STEERING_SUPPORT */

#ifdef IEEE80211H
		StaInfo_p->ListenInterval =
			ENDIAN_SWAP16(MgmtMsg_p->Body.AssocRqst.ListenInterval);
#endif
#ifdef MRVL_WSC			//MRVL_WSC_IE
		memset(&StaInfo_p->WscIEBuf, 0, sizeof(WSC_ProbeRespIE_t));
#endif
/* move cleanupAmpduTx to send Del BA after response sent */
//      cleanupAmpduTx(vmacSta_p,(UINT8 *)&StaInfo_p->Addr);

		if (flag) {
			//re-assoc request has 6 bytes Current AP address after ListenInterval  
			VariableElements_p =
				(UINT8 *) & MgmtMsg_p->Body.AssocRqst.SsId +
				sizeof(IEEEtypes_MacAddr_t);
			/* Add 2 bytes to make up for BodyLen, ptr is adjusted to include but
			   message size does not include this. */
			VarLen = msgSize -
				sizeof(IEEEtypes_MgmtHdr3_t) -
				sizeof(IEEEtypes_CapInfo_t) -
				sizeof(IEEEtypes_ListenInterval_t) + 2 -
				sizeof(IEEEtypes_MacAddr_t);
		} else {
			VariableElements_p =
				(UINT8 *) & MgmtMsg_p->Body.AssocRqst.SsId;
			/* Add 2 bytes to make up for BodyLen, ptr is adjusted to include but
			   message size does not include this. */
			VarLen = msgSize -
				sizeof(IEEEtypes_MgmtHdr3_t) -
				sizeof(IEEEtypes_CapInfo_t) -
				sizeof(IEEEtypes_ListenInterval_t) + 2;
		}
#ifdef MULTI_AP_SUPPORT
		IEBuf = VariableElements_p;
		IELen = VarLen;
		capInfo_p = (UINT8 *) & MgmtMsg_p->Body.AssocRqst.CapInfo;
		listenInterval_p =
			(UINT8 *) & MgmtMsg_p->Body.AssocRqst.ListenInterval;
#endif
#ifdef ERP
		ExtRates_p = NULL;
#endif

		if (macMgmtMlme_AssocReAssocIESanityCheck
		    (VariableElements_p, VarLen) == FALSE) {
			skb_trim(txSkb_p, frameSize);
			/* below is to debug assoc problem, will remove if issue is clarified */
			{
				extern unsigned int dbg_class;
				printk("AssocRsp.StatusCode=UNSPEC_FAILURE, SanityCheck false (flag %d, VariableElements_p %p)!\n", flag, VariableElements_p);
				if (dbg_class & 0x80000000)
					print_hex_dump(KERN_INFO, "",
						       DUMP_PREFIX_ADDRESS, 16,
						       1, MgmtMsg_p, msgSize,
						       true);
			}
			MgmtRsp_p->Body.AssocRsp.StatusCode =
				IEEEtypes_STATUS_UNSPEC_FAILURE;
			if (txMgmtMsg(vmacSta_p->dev, txSkb_p) != OS_SUCCESS)
				wl_free_skb(txSkb_p);
			goto OUT;
		}

		if (!flag) {
			/* Assoc Req */
			memcpy(&StaInfo_p->assocReqMsg.Body.AssocRqst,
			       &MgmtRsp_p->Body.AssocRqst,
			       sizeof(IEEEtypes_AssocRqst_t));
			StaInfo_p->assocReqMsg.len =
				sizeof(IEEEtypes_AssocRqst_t);
		} else {
			/* ReAssoc Req */
			memcpy(&StaInfo_p->assocReqMsg.Body.ReassocRqst,
			       &MgmtRsp_p->Body.ReassocRqst,
			       sizeof(IEEEtypes_ReassocRqst_t));
			StaInfo_p->assocReqMsg.len =
				sizeof(IEEEtypes_ReassocRqst_t);
		}
		memcpy(&StaInfo_p->assocReqMsg.Hdr, &MgmtRsp_p->Hdr,
		       sizeof(IEEEtypes_MgmtHdr_t));

		while (VarLen > 0) {
			if (VariableElements_p >= endofmessagelocation) {
				break;
			}
			switch (*VariableElements_p) {
			case SSID:
				SsId_p = (IEEEtypes_SsIdElement_t *)
					VariableElements_p;
				VariableElements_p +=
					(sizeof(IEEEtypes_ElementId_t) +
					 sizeof(IEEEtypes_Len_t) + SsId_p->Len);
				VarLen -=
					(sizeof(IEEEtypes_ElementId_t) +
					 sizeof(IEEEtypes_Len_t) + SsId_p->Len);
				break;
			case SUPPORTED_RATES:
				Rates_p =
					(IEEEtypes_SuppRatesElement_t *)
					VariableElements_p;
				VariableElements_p +=
					(sizeof(IEEEtypes_ElementId_t) +
					 sizeof(IEEEtypes_Len_t) +
					 Rates_p->Len);
				VarLen -=
					(sizeof(IEEEtypes_ElementId_t) +
					 sizeof(IEEEtypes_Len_t) +
					 Rates_p->Len);
				break;
#ifdef ERP
			case EXT_SUPPORTED_RATES:
				ExtRates_p =
					(IEEEtypes_ExtSuppRatesElement_t *)
					VariableElements_p;
				VariableElements_p +=
					(sizeof(IEEEtypes_ElementId_t) +
					 sizeof(IEEEtypes_Len_t) +
					 ExtRates_p->Len);
				VarLen -=
					(sizeof(IEEEtypes_ElementId_t) +
					 sizeof(IEEEtypes_Len_t) +
					 ExtRates_p->Len);
				break;
#endif
#ifdef QOS_FEATURE
			case QOS_CAPABILITY:
				QosCapElem_p =
					(QoS_Cap_Elem_t *) VariableElements_p;
				VariableElements_p +=
					(sizeof(IEEEtypes_ElementId_t) +
					 sizeof(IEEEtypes_Len_t) +
					 QosCapElem_p->Len);
				VarLen -=
					(sizeof(IEEEtypes_ElementId_t) +
					 sizeof(IEEEtypes_Len_t) +
					 QosCapElem_p->Len);
				break;

#endif //QOS_FEATURE
			case PROPRIETARY_IE:
#ifdef APCFGUR
				if (isUrClientIE(VariableElements_p) == TRUE) {
					StaInfo_p->UR = 1;
				}
#endif
				if (isMcIdIE(VariableElements_p) == TRUE) {
					PeerInfo.MrvlSta = 1;
					StaInfo_p->IsStaMSTA = 1;
				}
				if ((isM_RptrIdIE(VariableElements_p) == TRUE)) {
					StaInfo_p->StaType |= 0x02;
				}
#ifdef MRVL_WSC			//MRVL_WSC_IE
				if (!memcmp
				    (&
				     ((WSC_ProbeRespIE_t *)
				      VariableElements_p)->OUI, WSC_OUI, 4)) {
					WSC_ProbeRespIE_t *WscIE_p =
						(WSC_ProbeRespIE_t *)
						VariableElements_p;
					if ((WscIE_p->Len + 2) >
					    sizeof(WSC_ProbeRespIE_t))
						OUT_OF_BOUNDARDY_MESSAGE((WscIE_p->Len + 2), (int)sizeof(WSC_ProbeRespIE_t));
					else
						memcpy(&StaInfo_p->WscIEBuf,
						       WscIE_p,
						       WscIE_p->Len + 2);
					StaInfo_p->WSCSta = TRUE;
					/* If any RSN IE is included then ignore the RSN IE when WSC IE is included */
					RsnIEWPA2_p = NULL;
				}
#endif //MRVL_WSC_IE
#ifdef INTEROP
				if (!memcmp
				    (&
				     ((IEEEtypes_Generic_HT_Element_t *)
				      VariableElements_p)->OUI, B_COMP_OUI,
				     3)) {
					// B_COMP VHT Cap
					if (((IEEEtypes_Generic_HT_Element_t *)
					     VariableElements_p)->OUIType ==
					    4) {
						if (isVendorSpecVHTIE
						    (VariableElements_p)) {
							IEEEtypes_VhtCap_t
								*tmp_p =
								(IEEEtypes_VhtCap_t
								 *) ((IEEEtypes_VendorSpec_VHT_Element_t *) VariableElements_p)->VHTData;
							StaInfo_p->vhtCap.id =
								tmp_p->id;
							StaInfo_p->vhtCap.len =
								tmp_p->len;
#ifdef MV_CPU_BE
							StaInfo_p->vhtCap.cap.
								u32_data =
								ENDIAN_SWAP32
								(tmp_p->cap.
								 u32_data);
#else
							memcpy((void *)
							       &StaInfo_p->
							       vhtCap,
							       &tmp_p->id,
							       sizeof
							       (IEEEtypes_VhtCap_t));
#endif
							StaInfo_p->vhtCap.
								SupportedRxMcsSet
								=
								ENDIAN_SWAP32
								(tmp_p->
								 SupportedRxMcsSet);
							StaInfo_p->vhtCap.
								SupportedTxMcsSet
								=
								ENDIAN_SWAP32
								(tmp_p->
								 SupportedTxMcsSet);
							memcpy((UINT8 *) &
							       PeerInfo.vht_cap,
							       (UINT8 *) &
							       tmp_p->cap,
							       sizeof
							       (IEEEtypes_VHT_Cap_Info_t));
							PeerInfo.vht_MaxRxMcs =
								tmp_p->
								SupportedRxMcsSet;
							vht_RxChannelWidth_IE191
								=
								tmp_p->cap.
								SupportedChannelWidthSet;

							VendorSpecVHTPresent =
								1;
						}
					} else if (((IEEEtypes_Generic_HT_Element_t *) VariableElements_p)->OUIType == 51) {
						IEEEtypes_Generic_HT_Element_t
							*tmp_p =
							(IEEEtypes_Generic_HT_Element_t
							 *) VariableElements_p;
						HTpresent = 1;
						PeerInfo.HTCapabilitiesInfo =
							tmp_p->
							HTCapabilitiesInfo;
						PeerInfo.MacHTParamInfo =
							tmp_p->MacHTParamInfo;
#ifdef EXPLICIT_BF
						PeerInfo.TxBFCapabilities =
							ENDIAN_SWAP32(tmp_p->
								      TxBFCapabilities);
#endif
						if (*(mib->mib_3x3Rate) == 1 &&
						    ((*(mib->mib_rxAntenna) ==
						      0) ||
						     (*(mib->mib_rxAntenna) ==
						      3))) {
						/** 3x3 configuration **/
#ifdef CAP_MAX_RATE
							if (MCSCapEnable) {	/*Enabled through mcscap debug cmd */
								if ((MCSCap < 8)
								    && (tmp_p->
									SupportedMCSset
									[0] !=
									0)) {
									shiftno = (MCSCap % 8) + 1;
									mcscapmask
										=
										0xff
										<<
										shiftno;
									tmp_p->SupportedMCSset[0] = ~(tmp_p->SupportedMCSset[0] & mcscapmask);
									tmp_p->SupportedMCSset[1] = 0;
									tmp_p->SupportedMCSset[2] = 0;
									tmp_p->SupportedMCSset[3] = 0;
								} else if ((MCSCap > 7) && (MCSCap < 16) && (tmp_p->SupportedMCSset[1] != 0)) {
									shiftno = (MCSCap % 8) + 1;
									mcscapmask
										=
										0xff
										<<
										shiftno;
									tmp_p->SupportedMCSset[1] = ~(tmp_p->SupportedMCSset[1] & mcscapmask);
									tmp_p->SupportedMCSset[2] = 0;	/*Higher MCSset[] set to 0, Lower MCSset[0] left as default */
									tmp_p->SupportedMCSset[3] = 0;
								} else if ((MCSCap > 15) && (MCSCap < 24) && (tmp_p->SupportedMCSset[2] != 0)) {
									shiftno = (MCSCap % 16) + 1;
									mcscapmask
										=
										0xff
										<<
										shiftno;
									tmp_p->SupportedMCSset[2] = ~(tmp_p->SupportedMCSset[2] & mcscapmask);
									tmp_p->SupportedMCSset[3] = 0;
								} else {
									printk("WRONG MCS cap value\n");
								}
								printk("MCSSet0:0x%x MCSSet1:0x%x MCSSet2:0x%x MCSSet3:0x%x \n", tmp_p->SupportedMCSset[0], tmp_p->SupportedMCSset[1], tmp_p->SupportedMCSset[2]
								       ,
								       tmp_p->
								       SupportedMCSset
								       [3]);
							}
#endif

							PeerInfo.HTRateBitMap =
								ENDIAN_SWAP32((tmp_p->SupportedMCSset[0] | (tmp_p->SupportedMCSset[1] << 8) | (tmp_p->SupportedMCSset[2] << 16) | (tmp_p->SupportedMCSset[3] << 24)));
						} else if (!
							   ((*
							     (mib->
							      mib_rxAntenna) ==
							     0) ||
							    (*
							     (mib->
							      mib_rxAntenna) ==
							     3) ||
							    (*
							     (mib->
							      mib_rxAntenna) ==
							     2)))
						{
						/** 1x1 configuration **/
#ifdef CAP_MAX_RATE
							if (MCSCapEnable) {
								if ((MCSCap < 8)
								    && (tmp_p->
									SupportedMCSset
									[0] !=
									0)) {
									shiftno = (MCSCap % 8) + 1;
									mcscapmask
										=
										0xff
										<<
										shiftno;
									tmp_p->SupportedMCSset[0] = ~(tmp_p->SupportedMCSset[0] & mcscapmask);
								} else {
									printk("WRONG MCS cap value\n");
								}
								printk("MCSSet0:0x%x \n", tmp_p->SupportedMCSset[0]);
							}
#endif

							PeerInfo.HTRateBitMap =
								ENDIAN_SWAP32((tmp_p->SupportedMCSset[0]));
						} else {
#ifdef CAP_MAX_RATE
							if (MCSCapEnable) {
								if ((MCSCap < 8)
								    && (tmp_p->
									SupportedMCSset
									[0] !=
									0)) {
									shiftno = (MCSCap % 8) + 1;
									mcscapmask
										=
										0xff
										<<
										shiftno;
									tmp_p->SupportedMCSset[0] = ~(tmp_p->SupportedMCSset[0] & mcscapmask);
									tmp_p->SupportedMCSset[1] = 0;
								} else if ((MCSCap > 7) && (MCSCap < 16) && (tmp_p->SupportedMCSset[1] != 0)) {
									shiftno = (MCSCap % 8) + 1;
									mcscapmask
										=
										0xff
										<<
										shiftno;
									tmp_p->SupportedMCSset[1] = ~(tmp_p->SupportedMCSset[1] & mcscapmask);
								} else {
									printk("WRONG MCS cap value\n");
								}
								printk("MCSSet0:0x%x MCSSet1:0x%x \n", tmp_p->SupportedMCSset[0], tmp_p->SupportedMCSset[1]);
							}
#endif

							PeerInfo.HTRateBitMap =
								ENDIAN_SWAP32((tmp_p->SupportedMCSset[0] | (tmp_p->SupportedMCSset[1] << 8)));
						}

						StaInfo_p->HtElem.ElementId =
							tmp_p->ElementId;
						StaInfo_p->HtElem.Len =
							tmp_p->Len;
						StaInfo_p->HtElem.
							MacHTParamInfo =
							tmp_p->MacHTParamInfo;
						StaInfo_p->HtElem.
							ASCapabilities =
							tmp_p->ASCapabilities;
						StaInfo_p->HtElem.
							ExtHTCapabilitiesInfo =
							ENDIAN_SWAP16(tmp_p->
								      ExtHTCapabilitiesInfo);
#ifdef EXPLICIT_BF
						StaInfo_p->HtElem.
							TxBFCapabilities =
							ENDIAN_SWAP32(tmp_p->
								      TxBFCapabilities);
#else
						StaInfo_p->HtElem.
							TxBFCapabilities =
							ENDIAN_SWAP16(tmp_p->
								      ExtHTCapabilitiesInfo);
#endif

						StaInfo_p->HtElem.
							HTCapabilitiesInfo =
							tmp_p->
							HTCapabilitiesInfo;
						memcpy(&
						       (StaInfo_p->HtElem.
							SupportedMCSset),
						       &(tmp_p->
							 SupportedMCSset), 16);

						if ((*
						     (vmacSta_p->Mib802dot11->
						      pMib_11nAggrMode) &
						     WL_MODE_AMSDU_TX_MASK) &&
						    !(*
						      (vmacSta_p->Mib802dot11->
						       pMib_11nAggrMode) &
						      WL_MODE_AMPDU_TX))
							StaInfo_p->aggr11n.
								type |=
								WL_WLAN_TYPE_AMSDU;
						StaInfo_p->aggr11n.threshold =
							AGGRTHRESHOLD;
#ifdef WIFI_DATA_OFFLOAD
						dol_sta_tx_ampdu_ctrl(wlpptr,
								      wlpptr->
								      wlpd_p->
								      ipc_session_id,
								      wlpptr->
								      vmacSta_p->
								      VMacEntry.
								      macId,
								      (u8 *)
								      StaInfo_p->
								      Addr,
								      AGGRTHRESHOLD,
								      NULL);
#endif
						if (*
						    (vmacSta_p->Mib802dot11->
						     mib_ApMode) & 0x4)
							StaInfo_p->ClientMode =
								NONLY_MODE;
						if (tmp_p->HTCapabilitiesInfo.
						    MaxAMSDUSize)
							StaInfo_p->aggr11n.cap =
								2;
						else
							StaInfo_p->aggr11n.cap =
								1;

						amsdu_bitmap =
							(*
							 (vmacSta_p->
							  Mib802dot11->
							  pMib_11nAggrMode) &
							 WL_MODE_AMSDU_TX_MASK);
						if (amsdu_bitmap ==
						    WL_MODE_AMSDU_TX_11K)
							amsdu_bitmap =
								WL_MODE_AMSDU_TX_8K;

						if (StaInfo_p->aggr11n.cap >
						    amsdu_bitmap) {
							StaInfo_p->aggr11n.cap =
								amsdu_bitmap;
							WLDBG_INFO(DBG_LEVEL_7,
								   "Mismatched Sta HTCapabilitiesInfo.MaxAMSDUSize=%x",
								   tmp_p->
								   HTCapabilitiesInfo.
								   MaxAMSDUSize);
						}
					} else if (((IEEEtypes_Generic_Add_HT_Element_t *) VariableElements_p)->OUIType == 52) {
						IEEEtypes_Generic_Add_HT_Element_t
							*tmp_p =
							(IEEEtypes_Generic_Add_HT_Element_t
							 *) VariableElements_p;

						StaInfo_p->AddHtElme.ElementId =
							tmp_p->ElementId;
						StaInfo_p->AddHtElme.Len =
							tmp_p->Len;
						PeerInfo.AddHtInfo.ControlChan =
							StaInfo_p->AddHtElme.
							ControlChan =
							tmp_p->ControlChan;
						PeerInfo.AddHtInfo.AddChan =
							StaInfo_p->AddHtElme.
							AddChan =
							tmp_p->AddChan;
						PeerInfo.AddHtInfo.OpMode =
							StaInfo_p->AddHtElme.
							OpMode = tmp_p->OpMode;
						PeerInfo.AddHtInfo.stbc =
							StaInfo_p->AddHtElme.
							stbc = tmp_p->stbc;

					}

					VarLen -= (sizeof(IEEEtypes_ElementId_t) + sizeof(IEEEtypes_Len_t) + *(VariableElements_p + 1));	/* value in the length field */
					VariableElements_p +=
						(sizeof(IEEEtypes_ElementId_t));
					VariableElements_p +=
						*VariableElements_p;
					VariableElements_p +=
						sizeof(IEEEtypes_Len_t);
					break;

				}

			/** FOR I_COMP ONLY, not use anymore **/
				if (!memcmp
				    (&
				     ((IEEEtypes_Generic_HT_Element_t2 *)
				      VariableElements_p)->OUI, I_COMP_OUI,
				     3)) {

					if (((IEEEtypes_Generic_HT_Element_t2 *)
					     VariableElements_p)->OUIType ==
					    51) {
						IEEEtypes_Generic_HT_Element_t2
							*tmp_p =
							(IEEEtypes_Generic_HT_Element_t2
							 *) VariableElements_p;
						HTpresent = 1;
						PeerInfo.HTCapabilitiesInfo =
							tmp_p->
							HTCapabilitiesInfo;
						PeerInfo.MacHTParamInfo =
							tmp_p->MacHTParamInfo;
#ifdef EXPLICIT_BF
						PeerInfo.TxBFCapabilities =
							ENDIAN_SWAP32(tmp_p->
								      TxBFCapabilities);
#endif

						if (*(mib->mib_3x3Rate) == 1)
							PeerInfo.HTRateBitMap =
								ENDIAN_SWAP32((tmp_p->SupportedMCSset[0] | (tmp_p->SupportedMCSset[1] << 8) | (tmp_p->SupportedMCSset[2] << 16) | (tmp_p->SupportedMCSset[3] << 24)));
						else
							PeerInfo.HTRateBitMap =
								ENDIAN_SWAP32((tmp_p->SupportedMCSset[0] | (tmp_p->SupportedMCSset[1] << 8)));

						StaInfo_p->HtElem.ElementId =
							tmp_p->ElementId;
						StaInfo_p->HtElem.Len =
							tmp_p->Len;
						StaInfo_p->HtElem.
							MacHTParamInfo =
							tmp_p->MacHTParamInfo;
						StaInfo_p->HtElem.
							ASCapabilities =
							tmp_p->ASCapabilities;
						StaInfo_p->HtElem.
							ExtHTCapabilitiesInfo =
							ENDIAN_SWAP16(tmp_p->
								      ExtHTCapabilitiesInfo);
#ifdef EXPLICIT_BF
						StaInfo_p->HtElem.
							TxBFCapabilities =
							ENDIAN_SWAP32(tmp_p->
								      TxBFCapabilities);
#else
						StaInfo_p->HtElem.
							TxBFCapabilities =
							ENDIAN_SWAP16(tmp_p->
								      ExtHTCapabilitiesInfo);
#endif
						StaInfo_p->HtElem.
							HTCapabilitiesInfo =
							tmp_p->
							HTCapabilitiesInfo;
						memcpy(&
						       (StaInfo_p->HtElem.
							SupportedMCSset),
						       &(tmp_p->
							 SupportedMCSset), 16);

						if ((*
						     (vmacSta_p->Mib802dot11->
						      pMib_11nAggrMode) &
						     WL_MODE_AMSDU_TX_MASK) &&
						    !(*
						      (vmacSta_p->Mib802dot11->
						       pMib_11nAggrMode) &
						      WL_MODE_AMPDU_TX))
							StaInfo_p->aggr11n.
								type |=
								WL_WLAN_TYPE_AMSDU;
						StaInfo_p->aggr11n.threshold = AGGRTHRESHOLD;	//foo hack 500;
#ifdef WIFI_DATA_OFFLOAD
						dol_sta_tx_ampdu_ctrl(wlpptr,
								      wlpptr->
								      wlpd_p->
								      ipc_session_id,
								      wlpptr->
								      vmacSta_p->
								      VMacEntry.
								      macId,
								      (u8 *)
								      StaInfo_p->
								      Addr,
								      AGGRTHRESHOLD,
								      NULL);
#endif
						if (*
						    (vmacSta_p->Mib802dot11->
						     mib_ApMode) & 0x4)
							StaInfo_p->ClientMode =
								NONLY_MODE;
						if (tmp_p->HTCapabilitiesInfo.
						    MaxAMSDUSize) {
							StaInfo_p->aggr11n.cap =
								2;
							WLDBG_INFO(DBG_LEVEL_7,
								   "Amsdu size=2");
						} else {
							StaInfo_p->aggr11n.cap =
								1;
							WLDBG_INFO(DBG_LEVEL_7,
								   "Amsdu size=1");
						}

						amsdu_bitmap =
							(*
							 (vmacSta_p->
							  Mib802dot11->
							  pMib_11nAggrMode) &
							 WL_MODE_AMSDU_TX_MASK);
						if (amsdu_bitmap ==
						    WL_MODE_AMSDU_TX_11K)
							amsdu_bitmap =
								WL_MODE_AMSDU_TX_8K;

						if (StaInfo_p->aggr11n.cap >
						    amsdu_bitmap) {
							StaInfo_p->aggr11n.cap =
								amsdu_bitmap;
							WLDBG_INFO(DBG_LEVEL_7,
								   "Mismatched Sta HTCapabilitiesInfo.MaxAMSDUSize=%x",
								   tmp_p->
								   HTCapabilitiesInfo.
								   MaxAMSDUSize);
						}
					} else if (((IEEEtypes_Generic_Add_HT_Element_t2 *) VariableElements_p)->OUIType == 52) {
						IEEEtypes_Generic_Add_HT_Element_t2
							*tmp_p =
							(IEEEtypes_Generic_Add_HT_Element_t2
							 *) VariableElements_p;

						StaInfo_p->AddHtElme.ElementId =
							tmp_p->ElementId;
						StaInfo_p->AddHtElme.Len =
							tmp_p->Len;
						PeerInfo.AddHtInfo.ControlChan =
							StaInfo_p->AddHtElme.
							ControlChan =
							tmp_p->ControlChan;
						PeerInfo.AddHtInfo.AddChan =
							StaInfo_p->AddHtElme.
							AddChan =
							tmp_p->AddChan;
						PeerInfo.AddHtInfo.OpMode =
							StaInfo_p->AddHtElme.
							OpMode = tmp_p->OpMode;
						PeerInfo.AddHtInfo.stbc =
							StaInfo_p->AddHtElme.
							stbc = tmp_p->stbc;

					}
					VarLen -= (sizeof(IEEEtypes_ElementId_t) + sizeof(IEEEtypes_Len_t) + *(VariableElements_p + 1));	/* value in the length field */
					VariableElements_p +=
						(sizeof(IEEEtypes_ElementId_t));
					VariableElements_p +=
						*VariableElements_p;
					VariableElements_p +=
						sizeof(IEEEtypes_Len_t);
					break;

				}
#endif /* INTEROP */

#ifdef MULTI_AP_SUPPORT
				if (!memcmp
				    (&
				     ((IEEEtypes_Generic_HT_Element_t2 *)
				      VariableElements_p)->OUI, MultiAP_OUI, 3)
				    && ((IEEEtypes_Generic_HT_Element_t2 *)
					VariableElements_p)->OUIType ==
				    MultiAP_OUI_type) {
					MultiAP_IE_p =
						(IEEEtypes_MultiAP_Element_t *)
						VariableElements_p;
					if (MultiAP_IE_p->attributes.BackSTA &&
					    (mib->
					     multi_ap_attr &
					     MAP_ATTRIBUTE_BACKHAUL_BSS)) {
						if (StaInfo_p) {
							StaInfo_p->
								MultiAP_4addr =
								1;
						}
					}
					VarLen -= (sizeof(IEEEtypes_ElementId_t) + sizeof(IEEEtypes_Len_t) + *(VariableElements_p + 1));	/* value in the length field */
					VariableElements_p +=
						(sizeof(IEEEtypes_ElementId_t));
					VariableElements_p +=
						*VariableElements_p;
					VariableElements_p +=
						sizeof(IEEEtypes_Len_t);
					break;
				}
#endif /*MULTI_AP_SUPPORT */

#ifdef QOS_WSM_FEATURE
				if (!memcmp
				    (&
				     ((WSM_QoS_Cap_Elem_t *)
				      VariableElements_p)->OUI, WiFiOUI, 3)) {
					if (((WSM_QoS_Cap_Elem_t *)
					     VariableElements_p)->OUI.Type ==
					    0x2) {
						if (((WSM_QoS_Cap_Elem_t *)
						     VariableElements_p)->OUI.
						    Subtype == 0) {
							//This is a WME Info Element
							pWMEInfoElem =
								(WME_info_elem_t
								 *)
								VariableElements_p;
							VariableElements_p +=
								(sizeof
								 (IEEEtypes_ElementId_t)
								 +
								 sizeof
								 (IEEEtypes_Len_t)
								 +
								 pWMEInfoElem->
								 Len);
							VarLen -=
								(sizeof
								 (IEEEtypes_ElementId_t)
								 +
								 sizeof
								 (IEEEtypes_Len_t)
								 +
								 pWMEInfoElem->
								 Len);

						} else if (((WSM_QoS_Cap_Elem_t
							     *)
							    VariableElements_p)->
							   OUI.Subtype == 5) {
							//this is the WSM QoS Element
							WsmQosCapElem_p =
								(WSM_QoS_Cap_Elem_t
								 *)
								VariableElements_p;
							VariableElements_p +=
								(sizeof
								 (IEEEtypes_ElementId_t)
								 +
								 sizeof
								 (IEEEtypes_Len_t)
								 +
								 WsmQosCapElem_p->
								 Len);
							VarLen -=
								(sizeof
								 (IEEEtypes_ElementId_t)
								 +
								 sizeof
								 (IEEEtypes_Len_t)
								 +
								 WsmQosCapElem_p->
								 Len);
						} else {
							InfoElemHdr_p =
								(IEEEtypes_InfoElementHdr_t
								 *)
								VariableElements_p;
							VariableElements_p +=
								(sizeof
								 (IEEEtypes_ElementId_t)
								 +
								 sizeof
								 (IEEEtypes_Len_t)
								 +
								 InfoElemHdr_p->
								 Len);
							VarLen -=
								(sizeof
								 (IEEEtypes_ElementId_t)
								 +
								 sizeof
								 (IEEEtypes_Len_t)
								 +
								 InfoElemHdr_p->
								 Len);
						}
						break;
					} else if (((IEEEtypes_RSN_IE_t *) VariableElements_p)->OuiType[3] == 0x1) {	//this is the WPA WiFI Element
						RsnIE_p =
							(IEEEtypes_RSN_IE_t *)
							VariableElements_p;
						VariableElements_p +=
							(sizeof
							 (IEEEtypes_ElementId_t)
							 +
							 sizeof(IEEEtypes_Len_t)
							 + RsnIE_p->Len);
						VarLen -=
							(sizeof
							 (IEEEtypes_ElementId_t)
							 +
							 sizeof(IEEEtypes_Len_t)
							 + RsnIE_p->Len);
						break;
					} else {
						InfoElemHdr_p =
							(IEEEtypes_InfoElementHdr_t
							 *) VariableElements_p;
						VariableElements_p +=
							(sizeof
							 (IEEEtypes_ElementId_t)
							 +
							 sizeof(IEEEtypes_Len_t)
							 + InfoElemHdr_p->Len);
						VarLen -=
							(sizeof
							 (IEEEtypes_ElementId_t)
							 +
							 sizeof(IEEEtypes_Len_t)
							 + InfoElemHdr_p->Len);
					}
				} else {
					InfoElemHdr_p =
						(IEEEtypes_InfoElementHdr_t *)
						VariableElements_p;
					VariableElements_p +=
						(sizeof(IEEEtypes_ElementId_t) +
						 sizeof(IEEEtypes_Len_t) +
						 InfoElemHdr_p->Len);
					VarLen -=
						(sizeof(IEEEtypes_ElementId_t) +
						 sizeof(IEEEtypes_Len_t) +
						 InfoElemHdr_p->Len);
				}
#else
				/*
				   RsnIE_p = (IEEEtypes_RSN_IE_t *)VariableElements_p;
				   VariableElements_p += (sizeof(IEEEtypes_ElementId_t) +
				   sizeof(IEEEtypes_Len_t) +
				   RsnIE_p->Len);
				   VarLen -= (sizeof(IEEEtypes_ElementId_t) +
				   sizeof(IEEEtypes_Len_t) +
				   RsnIE_p->Len);
				 */
				if (memcmp
				    (((IEEEtypes_RSN_IE_t *)
				      VariableElements_p)->OuiType, WPA_OUItype,
				     4) == 0) {
					RsnIE_p =
						(IEEEtypes_RSN_IE_t *)
						VariableElements_p;
					VariableElements_p +=
						(sizeof(IEEEtypes_ElementId_t) +
						 sizeof(IEEEtypes_Len_t) +
						 RsnIE_p->Len);
					VarLen -=
						(sizeof(IEEEtypes_ElementId_t) +
						 sizeof(IEEEtypes_Len_t) +
						 RsnIE_p->Len);
				} else {
					//RsnIE_p = NULL;
					RsnIE_Len =
						((IEEEtypes_RSN_IE_t *)
						 VariableElements_p)->Len;
					VariableElements_p +=
						(sizeof(IEEEtypes_ElementId_t) +
						 sizeof(IEEEtypes_Len_t) +
						 RsnIE_Len);
					VarLen -=
						(sizeof(IEEEtypes_ElementId_t) +
						 sizeof(IEEEtypes_Len_t) +
						 RsnIE_Len);
				}

#endif
				break;

#ifdef AP_WPA2
			case RSN_IEWPA2:
				RsnIEWPA2_p =
					(IEEEtypes_RSN_IE_WPA2_t *)
					VariableElements_p;
				VariableElements_p +=
					(sizeof(IEEEtypes_ElementId_t) +
					 sizeof(IEEEtypes_Len_t) +
					 RsnIEWPA2_p->Len);
				VarLen -=
					(sizeof(IEEEtypes_ElementId_t) +
					 sizeof(IEEEtypes_Len_t) +
					 RsnIEWPA2_p->Len);
				break;
#ifdef MRVL_80211R
			case MD_IE:
				MDIE_p = (IEEEtypes_MOBILITY_DOMAIN_IE_t *)
					VariableElements_p;
				VariableElements_p +=
					(sizeof(IEEEtypes_ElementId_t) +
					 sizeof(IEEEtypes_Len_t) + MDIE_p->Len);
				VarLen -=
					(sizeof(IEEEtypes_ElementId_t) +
					 sizeof(IEEEtypes_Len_t) + MDIE_p->Len);
				break;

			case FT_IE:
				FTIE_p = (UINT8 *) VariableElements_p;
				VariableElements_p +=
					(sizeof(IEEEtypes_ElementId_t) +
					 sizeof(IEEEtypes_Len_t) + FTIE_p[1]);
				VarLen -=
					(sizeof(IEEEtypes_ElementId_t) +
					 sizeof(IEEEtypes_Len_t) + FTIE_p[1]);
				break;
#endif
#endif

#ifdef MRVL_WAPI
			case WAPI_IE:
				WAPI_IE_p =
					(IEEEtypes_WAPI_IE_t *)
					VariableElements_p;
				VariableElements_p +=
					(sizeof(IEEEtypes_ElementId_t) +
					 sizeof(IEEEtypes_Len_t) +
					 WAPI_IE_p->Len);
				VarLen -=
					(sizeof(IEEEtypes_ElementId_t) +
					 sizeof(IEEEtypes_Len_t) +
					 WAPI_IE_p->Len);
				break;
#endif

#ifdef IEEE80211H
			case PWR_CAP:
				PowerCapability_p =
					(IEEEtypes_PowerCapabilityElement_t *)
					VariableElements_p;
				VariableElements_p +=
					(sizeof(IEEEtypes_ElementId_t) +
					 sizeof(IEEEtypes_Len_t) +
					 PowerCapability_p->Len);
				VarLen -=
					(sizeof(IEEEtypes_ElementId_t) +
					 sizeof(IEEEtypes_Len_t) +
					 PowerCapability_p->Len);
				break;

			case SUPPORTED_CHANNEL:
				SupportedChanne_p =
					(IEEEtypes_SupportedChannelElement_t *)
					VariableElements_p;
				VariableElements_p +=
					(sizeof(IEEEtypes_ElementId_t) +
					 sizeof(IEEEtypes_Len_t) +
					 SupportedChanne_p->Len);
				VarLen -=
					(sizeof(IEEEtypes_ElementId_t) +
					 sizeof(IEEEtypes_Len_t) +
					 SupportedChanne_p->Len);
				break;
#endif /* IEEE80211H */
			case HT:
				{
					IEEEtypes_HT_Element_t *tmp_p =
						(IEEEtypes_HT_Element_t *)
						VariableElements_p;
					HTpresent = 1;
					PeerInfo.HTCapabilitiesInfo =
						tmp_p->HTCapabilitiesInfo;
					PeerInfo.MacHTParamInfo =
						tmp_p->MacHTParamInfo;
#ifdef EXPLICIT_BF
					PeerInfo.TxBFCapabilities =
						ENDIAN_SWAP32(tmp_p->
							      TxBFCapabilities);
#endif
					if (*(mib->mib_3x3Rate) == 1 &&
					    ((*(mib->mib_rxAntenna) == 0) ||
					     (*(mib->mib_rxAntenna) == 3))) {
					/** 3x3 configuration **/

						PeerInfo.HTRateBitMap =
							ENDIAN_SWAP32((tmp_p->
								       SupportedMCSset
								       [0] |
								       (tmp_p->
									SupportedMCSset
									[1] <<
									8) |
								       (tmp_p->
									SupportedMCSset
									[2] <<
									16) |
								       (tmp_p->
									SupportedMCSset
									[3] <<
									24)));

					} else if (!
						   ((*(mib->mib_rxAntenna) == 0)
						    || (*(mib->mib_rxAntenna) ==
							3) ||
						    (*(mib->mib_rxAntenna) ==
						     2))) {
					/** 1x1 configuration **/

						PeerInfo.HTRateBitMap =
							ENDIAN_SWAP32((tmp_p->
								       SupportedMCSset
								       [0]));

					} else {
						PeerInfo.HTRateBitMap =
							ENDIAN_SWAP32((tmp_p->
								       SupportedMCSset
								       [0] |
								       (tmp_p->
									SupportedMCSset
									[1] <<
									8)));
					}

					if (PeerInfo.HTRateBitMap == 0x00)
						PeerInfo.HTRateBitMap = 0xFF;

					memcpy(&(StaInfo_p->HtElem), tmp_p,
					       sizeof(IEEEtypes_HT_Element_t));
					if ((*
					     (vmacSta_p->Mib802dot11->
					      pMib_11nAggrMode) &
					     WL_MODE_AMSDU_TX_MASK) &&
					    !(*
					      (vmacSta_p->Mib802dot11->
					       pMib_11nAggrMode) &
					      WL_MODE_AMPDU_TX))
						StaInfo_p->aggr11n.type |=
							WL_WLAN_TYPE_AMSDU;
					StaInfo_p->aggr11n.threshold =
						AGGRTHRESHOLD;
#ifdef WIFI_DATA_OFFLOAD
					dol_sta_tx_ampdu_ctrl(wlpptr,
							      wlpptr->wlpd_p->
							      ipc_session_id,
							      wlpptr->
							      vmacSta_p->
							      VMacEntry.macId,
							      (u8 *) StaInfo_p->
							      Addr,
							      AGGRTHRESHOLD,
							      NULL);
#endif
					if (*
					    (vmacSta_p->Mib802dot11->
					     mib_ApMode) & 0x4)
						StaInfo_p->ClientMode =
							NONLY_MODE;
					if (tmp_p->HTCapabilitiesInfo.
					    MaxAMSDUSize)
						StaInfo_p->aggr11n.cap = 2;
					else
						StaInfo_p->aggr11n.cap = 1;

					amsdu_bitmap =
						(*
						 (vmacSta_p->Mib802dot11->
						  pMib_11nAggrMode) &
						 WL_MODE_AMSDU_TX_MASK);
					if (amsdu_bitmap ==
					    WL_MODE_AMSDU_TX_11K)
						amsdu_bitmap =
							WL_MODE_AMSDU_TX_8K;

					if (StaInfo_p->aggr11n.cap >
					    amsdu_bitmap) {
						StaInfo_p->aggr11n.cap =
							amsdu_bitmap;
						WLDBG_INFO(DBG_LEVEL_7,
							   "Mismatched Sta HTCapabilitiesInfo.MaxAMSDUSize=%x",
							   tmp_p->
							   HTCapabilitiesInfo.
							   MaxAMSDUSize);
					}
					StaInfo_p->PeerHTCapabilitiesInfo =
						tmp_p->HTCapabilitiesInfo;
					vmacSta_p->NonGFSta = 0;
					if (!tmp_p->HTCapabilitiesInfo.
					    GreenField)
						vmacSta_p->NonGFSta++;
				}
				VarLen -= (sizeof(IEEEtypes_ElementId_t) + sizeof(IEEEtypes_Len_t) + *(VariableElements_p + 1));	/* value in the length field */
				VariableElements_p +=
					(sizeof(IEEEtypes_ElementId_t));
				VariableElements_p += *VariableElements_p;
				VariableElements_p += sizeof(IEEEtypes_Len_t);
				break;
			case ADD_HT:
				{
					IEEEtypes_Add_HT_Element_t *tmp_p =
						(IEEEtypes_Add_HT_Element_t *)
						VariableElements_p;
					memcpy(&(StaInfo_p->AddHtElme), tmp_p,
					       sizeof
					       (IEEEtypes_Add_HT_Element_t));
					PeerInfo.AddHtInfo.ControlChan =
						tmp_p->ControlChan;
					PeerInfo.AddHtInfo.AddChan =
						tmp_p->AddChan;
					PeerInfo.AddHtInfo.OpMode =
						tmp_p->OpMode;
					PeerInfo.AddHtInfo.stbc = tmp_p->stbc;
					ht_RxChannelWidth_IE61 =
						tmp_p->AddChan.STAChannelWidth;
				}
				VarLen -= (sizeof(IEEEtypes_ElementId_t) + sizeof(IEEEtypes_Len_t) + *(VariableElements_p + 1));	/* value in the length field */
				VariableElements_p +=
					(sizeof(IEEEtypes_ElementId_t));
				VariableElements_p += *VariableElements_p;
				VariableElements_p += sizeof(IEEEtypes_Len_t);
				break;
				//TODO: need more handling logic for IE 191&192
			case VHT_CAP:
				if (*(vmacSta_p->Mib802dot11->mib_ApMode) &
				    AP_MODE_11AC) {
					IEEEtypes_VhtCap_t *tmp_p =
						(IEEEtypes_VhtCap_t *)
						VariableElements_p;
					StaInfo_p->vhtCap.id = tmp_p->id;
					StaInfo_p->vhtCap.len = tmp_p->len;
#ifdef MV_CPU_BE
					StaInfo_p->vhtCap.cap.u32_data =
						ENDIAN_SWAP32(tmp_p->cap.
							      u32_data);
#else
					memcpy((void *)&StaInfo_p->vhtCap,
					       &tmp_p->id,
					       sizeof(IEEEtypes_VhtCap_t));
#endif
					StaInfo_p->vhtCap.SupportedRxMcsSet =
						ENDIAN_SWAP32(tmp_p->
							      SupportedRxMcsSet);
					StaInfo_p->vhtCap.SupportedTxMcsSet =
						ENDIAN_SWAP32(tmp_p->
							      SupportedTxMcsSet);
					memcpy((UINT8 *) & PeerInfo.vht_cap,
					       (UINT8 *) & tmp_p->cap,
					       sizeof
					       (IEEEtypes_VHT_Cap_Info_t));
					if (tmp_p->SupportedRxMcsSet == 0xffff)
						PeerInfo.vht_MaxRxMcs = 0xfffc;
					else
						PeerInfo.vht_MaxRxMcs =
							tmp_p->
							SupportedRxMcsSet;
					vht_RxChannelWidth_IE191 =
						tmp_p->cap.
						SupportedChannelWidthSet;
				}
				IE191Present = 1;
				vhtcap = *((UINT32 *) & StaInfo_p->vhtCap.cap);
				//printk("Received IE 191!! - vht_Cap = %x, vht_MaxRxMcs = %x\n", (unsigned int)vhtcap, (u_int32_t)PeerInfo.vht_MaxRxMcs);
				VarLen -= (sizeof(IEEEtypes_ElementId_t) + sizeof(IEEEtypes_Len_t) + *(VariableElements_p + 1));	/* value in the length field */
				VariableElements_p +=
					(sizeof(IEEEtypes_ElementId_t));
				VariableElements_p += *VariableElements_p;
				VariableElements_p += sizeof(IEEEtypes_Len_t);
				break;
			case VHT_OPERATION:
				{
					IEEEtypes_VhOpt_t *tmp_p =
						(IEEEtypes_VhOpt_t *)
						VariableElements_p;
					vht_RxChannelWidth_IE192 =
						tmp_p->ch_width;
					vht_center_freq0_IE192 =
						tmp_p->center_freq0;
					vht_center_freq1_IE192 =
						tmp_p->center_freq1;
				}
				IE192Present = 1;
				VarLen -= (sizeof(IEEEtypes_ElementId_t) + sizeof(IEEEtypes_Len_t) + *(VariableElements_p + 1));	/* value in the length field */
				VariableElements_p +=
					(sizeof(IEEEtypes_ElementId_t));
				VariableElements_p += *VariableElements_p;
				VariableElements_p += sizeof(IEEEtypes_Len_t);
				break;
			case OP_MODE_NOTIFICATION:
				{
					IEEEtypes_VHT_op_mode_t *tmp_p =
						(IEEEtypes_VHT_op_mode_t *)
						VariableElements_p;
					if (tmp_p->OperatingMode.RxNssType == 0) {
						vht_RxChannelWidth_IE199 =
							tmp_p->OperatingMode.
							ChannelWidth;
						vht_RxNss_IE199 = tmp_p->OperatingMode.RxNss + 1;	//In IE199, 0:Nss1, 1:Nss2....So we plus 1 to become 1:Nss1, 2:Nss2
					}
					/*Beamforming related matters */
					else {
						/*TODO: Hard coded for now to pass wifi 7/19/2013 */
						vht_RxChannelWidth_IE199 = 2;	//0:20Mhz, 1:40Mhz, 2:80Mhz, 3:160 or 80+80Mhz
						vht_RxNss_IE199 = 3;	//1:1Nss, 2:2Nss, 3:3Nss
					}
				}
				IE199Present = 1;
				VarLen -= (sizeof(IEEEtypes_ElementId_t) + sizeof(IEEEtypes_Len_t) + *(VariableElements_p + 1));	/* value in the length field */
				VariableElements_p +=
					(sizeof(IEEEtypes_ElementId_t));
				VariableElements_p += *VariableElements_p;
				VariableElements_p += sizeof(IEEEtypes_Len_t);
				break;
#ifdef SOC_W906X
			case EXT_IE:
				{
					IEEEtypes_InfoElementExtHdr_t *tmp_p =
						(IEEEtypes_InfoElementExtHdr_t
						 *) VariableElements_p;
					u8 ie_length;

					ie_length =
						tmp_p->Len +
						sizeof(IEEEtypes_ElementId_t) +
						sizeof(IEEEtypes_Len_t);
					DH_IE_p = VariableElements_p;

					switch (tmp_p->ext) {
					case HE_CAPABILITIES_IE:
						if (*
						    (vmacSta_p->Mib802dot11->
						     mib_ApMode) & AP_MODE_11AX)
						{
							u8 *ptr;

							if (ie_length <=
							    sizeof(PeerInfo.
								   he_cap))
								memcpy((void *)
								       &PeerInfo.
								       he_cap,
								       (void *)
								       tmp_p,
								       ie_length);

							StaInfo_p->he_cap_ie =
								tmp_p->ext;

							ptr = (u8 *) & tmp_p->
								ext;
							ptr += sizeof(tmp_p->
								      ext);
							memcpy((u8 *) &
							       StaInfo_p->
							       he_mac_cap, ptr,
							       sizeof
							       (HE_Mac_Capabilities_Info_t));
							ptr += sizeof
								(HE_Mac_Capabilities_Info_t);
							memcpy((u8 *) &
							       StaInfo_p->
							       he_phy_cap, ptr,
							       sizeof
							       (HE_Phy_Capabilities_Info_t));
							//printk("found HE_CAPABILITIES_IE\n");

							//ptr = &StaInfo_p->he_phy_cap;
							if (wfa_11ax_pf) {
								if (WFA_PeerInfo_HE_CAP_1NSS) {
									PeerInfo.
										he_cap.
										rx_he_mcs_80m.
										max_mcs_set
										=
										PeerInfo.
										he_cap.
										rx_he_mcs_80m.
										max_mcs_set
										|
										0xfffc;
									PeerInfo.
										he_cap.
										tx_he_mcs_80m.
										max_mcs_set
										=
										PeerInfo.
										he_cap.
										tx_he_mcs_80m.
										max_mcs_set
										|
										0xfffc;
								}
							}

							memcpy((u8 *) &
							       StaInfo_p->heCap,
							       (u8 *) &
							       PeerInfo.he_cap,
							       sizeof(PeerInfo.
								      he_cap));
						}
						he_cap_present = 1;
						break;
					case HE_OPERATION_IE:
						if (*
						    (vmacSta_p->Mib802dot11->
						     mib_ApMode) & AP_MODE_11AX)
						{
							if (ie_length <=
							    sizeof(PeerInfo.
								   he_op))
								memcpy((void *)
								       &PeerInfo.
								       he_op,
								       (void *)
								       tmp_p,
								       ie_length);
						}
						he_op_present = 1;
						break;
					default:
						break;
					}

					VarLen -= ie_length;
					VariableElements_p +=
						(sizeof(IEEEtypes_ElementId_t));
					VariableElements_p +=
						*VariableElements_p;
					VariableElements_p +=
						sizeof(IEEEtypes_Len_t);
				}
				break;
#else
			case EXTENSION:
				DH_IE_p = VariableElements_p;
				VarLen -= (sizeof(IEEEtypes_ElementId_t) + sizeof(IEEEtypes_Len_t) + *(VariableElements_p + 1));	/* value in the length field */
				VariableElements_p +=
					(sizeof(IEEEtypes_ElementId_t));
				VariableElements_p += *VariableElements_p;
				VariableElements_p += sizeof(IEEEtypes_Len_t);
				break;
#endif /* SOC_W906X */
#ifdef AP_STEERING_SUPPORT
			case EXT_CAP_IE:
				{
					IEEEtypes_Extended_Cap_Element_t *tmp_p
						=
						(IEEEtypes_Extended_Cap_Element_t
						 *) VariableElements_p;

					memcpy(&(StaInfo_p->ExtCapElem), tmp_p,
					       sizeof
					       (IEEEtypes_Extended_Cap_Element_t));
					VarLen -= (sizeof(IEEEtypes_ElementId_t) + sizeof(IEEEtypes_Len_t) + *(VariableElements_p + 1));	/* value in the length field */
					VariableElements_p +=
						(sizeof(IEEEtypes_ElementId_t));
					VariableElements_p +=
						*VariableElements_p;
					VariableElements_p +=
						sizeof(IEEEtypes_Len_t);
				}
				break;
#endif //AP_STEERING_SUPPORT
#if defined(MULTI_AP_SUPPORT)  && defined(IEEE80211K)
			case RRM_CAP_IE:
				{
					struct IEEEtypes_RM_Enable_Capabilities_Element_t *tmp_p = (IEEEtypes_RM_Enable_Capabilities_Element_t *) VariableElements_p;

					memcpy(&(StaInfo_p->RRM_Cap_IE), tmp_p,
					       sizeof
					       (IEEEtypes_RM_Enable_Capabilities_Element_t));
					VarLen -= (sizeof(IEEEtypes_ElementId_t) + sizeof(IEEEtypes_Len_t) + *(VariableElements_p + 1));	/* value in the length field */
					VariableElements_p +=
						(sizeof(IEEEtypes_ElementId_t));
					VariableElements_p +=
						*VariableElements_p;
					VariableElements_p +=
						sizeof(IEEEtypes_Len_t);
				}
				break;
#endif /* MULTI_AP_SUPPORT && IEEE80211K */

			default:
				VarLen -= (sizeof(IEEEtypes_ElementId_t) + sizeof(IEEEtypes_Len_t) + *(VariableElements_p + 1));	/* value in the length field */
				VariableElements_p +=
					(sizeof(IEEEtypes_ElementId_t));
				VariableElements_p += *VariableElements_p;
				VariableElements_p += sizeof(IEEEtypes_Len_t);
				break;
			}
		}

#ifdef CONFIG_IEEE80211W
		if ((StaInfo_p->Ieee80211wSta && StaInfo_p->Aid) &&
		    !((FTIE_p != NULL) && (flag))) {
			if (!StaInfo_p->sa_query_timed_out) {
				IEEEtypes_TimeoutInterval_Element_t *TIe_p =
					(IEEEtypes_TimeoutInterval_Element_t
					 *) ((UINT8 *) MgmtRsp_p + frameSize);

				MgmtRsp_p->Body.AssocRsp.StatusCode =
					IEEEtypes_STATUS_ASSOC_REJECTED_TEMPORARILY;
				TIe_p->ElementId = 56;
				TIe_p->Len = 5;
				TIe_p->TIType = 3;
				TIe_p->TIValue =
					vmacSta_p->assoc_sa_query_max_timeout;
				frameSize +=
					sizeof(IEEEtypes_InfoElementHdr_t) +
					TIe_p->Len;
				/* Send for tx */
				skb_trim(txSkb_p, frameSize);

				if (StaInfo_p->sa_query_count == 0) {
					if (txMgmtMsg(vmacSta_p->dev, txSkb_p)
					    != OS_SUCCESS)
						wl_free_skb(txSkb_p);

					StaInfo_p->sa_query_start_time =
						xxGetTimeStamp();
					TimerInit(&StaInfo_p->SA_Query_Timer);
					// send SAQuery per 0.2 second as the same hostapd SAQuery implematation
					SAQueryMgmt_TimeoutHdlr((UINT8 *)
								StaInfo_p);
					goto OUT;
				} else {
					UINT32 now = xxGetTimeStamp();
					UINT32 delta_time;

					delta_time =
						(now >
						 StaInfo_p->
						 sa_query_start_time) ? (now -
									 StaInfo_p->
									 sa_query_start_time)
						: ((0xFFFFFFFF -
						    StaInfo_p->
						    sa_query_start_time) + now);
					TIe_p->TIValue =
						vmacSta_p->
						assoc_sa_query_max_timeout -
						delta_time / 1024;

					if (txMgmtMsg(vmacSta_p->dev, txSkb_p)
					    != OS_SUCCESS)
						wl_free_skb(txSkb_p);

					printk("SAQueryMgmt_TimeoutHdlr is working and need to wait for timeout (%p)\n", StaInfo_p);
					goto OUT;
				}
			} else {
				if (StaInfo_p->ptkCipherOuiType !=
				    CIPHER_OUI_TYPE_NONE) {
					macMgmtMlme_SendDisassociateMsg
						(vmacSta_p,
						 &(MgmtMsg_p->Hdr.SrcAddr),
						 StaInfo_p->StnId,
						 IEEEtypes_REASON_PRIOR_AUTH_INVALID);
					StaInfo_p->ptkCipherOuiType =
						CIPHER_OUI_TYPE_NONE;
					wl_free_skb(txSkb_p);
					goto OUT;
				}
			}
		}
#endif

#ifdef MULTI_AP_SUPPORT
		/* backhaul only AP, allow only MAP backhaul STA to associate */
		if ((mib->multi_ap_attr & MAP_ATTRIBUTE_BACKHAUL_BSS) &&
		    !(mib->multi_ap_attr & MAP_ATTRIBUTE_FRONTHAUL_BSS)) {
			if ((MultiAP_IE_p == NULL) ||
			    ((MultiAP_IE_p != NULL) &&
			     !MultiAP_IE_p->attributes.BackSTA)) {
				skb_trim(txSkb_p, frameSize);
				printk("AssocRsp.StatusCode=UNSPEC_FAILURE, bBSS only allow bSTA to associate!\n");
				MgmtRsp_p->Body.AssocRsp.StatusCode =
					IEEEtypes_STATUS_UNSPEC_FAILURE;
				if (txMgmtMsg(vmacSta_p->dev, txSkb_p) !=
				    OS_SUCCESS)
					wl_free_skb(txSkb_p);

				goto OUT;
			}
		}

		/* Multi-AP R2 Specification, section 5.2, Backhaul STA onboarding procedure   *
		 * a. bBSS configured with "R1 Backhaul STA association disallowed",           *
		 *  indicate bBSS with R1 bSTA association disallowed                          *
		 * b. bBSS configured with "R2 and above Backhaul STA association disallowed", *
		 *  indicate bBSS with R2 and above bSTA association disallowed.               */
		if (mib->multi_ap_attr & MAP_ATTRIBUTE_BACKHAUL_BSS) {
			if (mib->
			    multi_ap_attr & MAP_ATTRIBUTE_R1BSTA_DISALLOWED) {
				if ((MultiAP_IE_p == NULL) ||
				    ((MultiAP_IE_p != NULL) &&
				     (MultiAP_IE_p->attributes.BackSTA == 1) &&
				     ((MultiAP_IE_p->Len == MAP_R1_IE_LEN) ||
				      ((MultiAP_IE_p->Len >=
					(MAP_R1_IE_LEN + 3)) &&
				       (((IEEEtypes_MultiAP_Version_t *)
					 MultiAP_IE_p->variable)->ElementId ==
					0x07) &&
				       (((IEEEtypes_MultiAP_Version_t *)
					 MultiAP_IE_p->variable)->Len == 0x01)
				       &&
				       (((IEEEtypes_MultiAP_Version_t *)
					 MultiAP_IE_p->variable)->value ==
					0x01))))) {
					skb_trim(txSkb_p, frameSize);
					printk("AssocRsp.StatusCode=UNSPEC_FAILURE, R1 bSTA association disallowed!\n");
					MgmtRsp_p->Body.AssocRsp.StatusCode =
						IEEEtypes_STATUS_UNSPEC_FAILURE;
					if (txMgmtMsg(vmacSta_p->dev, txSkb_p)
					    != OS_SUCCESS)
						wl_free_skb(txSkb_p);

					goto OUT;
				}
			}
			if (mib->
			    multi_ap_attr & MAP_ATTRIBUTE_R2BSTA_DISALLOWED) {
				if ((MultiAP_IE_p == NULL) ||
				    ((MultiAP_IE_p != NULL) &&
				     (MultiAP_IE_p->attributes.BackSTA == 1) &&
				     ((MultiAP_IE_p->Len >= (MAP_R1_IE_LEN + 3))
				      &&
				      (((IEEEtypes_MultiAP_Version_t *)
					MultiAP_IE_p->variable)->ElementId ==
				       0x07) &&
				      (((IEEEtypes_MultiAP_Version_t *)
					MultiAP_IE_p->variable)->Len == 0x01) &&
				      (((IEEEtypes_MultiAP_Version_t *)
					MultiAP_IE_p->variable)->value >=
				       0x02)))) {
					skb_trim(txSkb_p, frameSize);
					printk("AssocRsp.StatusCode=UNSPEC_FAILURE, R2 bSTA association disallowed!\n");
					MgmtRsp_p->Body.AssocRsp.StatusCode =
						IEEEtypes_STATUS_UNSPEC_FAILURE;
					if (txMgmtMsg(vmacSta_p->dev, txSkb_p)
					    != OS_SUCCESS)
						wl_free_skb(txSkb_p);

					goto OUT;
				}
			}
		}
#endif /* MULTI_AP_SUPPORT */

		StaInfo_p->aggr11n.thresholdBackUp =
			StaInfo_p->aggr11n.threshold;
#ifdef AP_STEERING_SUPPORT
		StaInfo_p->btmreq_count = 0;
#endif //AP_STEERING_SUPPORT

		/*If IE199 is present, we use its channel width and Nss info to update peer info */
		if (IE199Present) {
			PeerInfo.vht_RxChannelWidth = vht_RxChannelWidth_IE199;

			/*Determine peer no. of Rx Nss in IE192
			 * bit0-1: Nss1, bit2-3: Nss2, ..., bit14-15: Nss8. 0x3 means not supported for the Nss
			 */
			if ((PeerInfo.vht_MaxRxMcs & 0xc000) != 0xc000)
				vht_peer_RxNss = 8;
			else if ((PeerInfo.vht_MaxRxMcs & 0x3000) != 0x3000)
				vht_peer_RxNss = 7;
			else if ((PeerInfo.vht_MaxRxMcs & 0xc00) != 0xc00)
				vht_peer_RxNss = 6;
			else if ((PeerInfo.vht_MaxRxMcs & 0x300) != 0x300)
				vht_peer_RxNss = 5;
			else if ((PeerInfo.vht_MaxRxMcs & 0xc0) != 0xc0)
				vht_peer_RxNss = 4;
			else if ((PeerInfo.vht_MaxRxMcs & 0x30) != 0x30)
				vht_peer_RxNss = 3;
			else if ((PeerInfo.vht_MaxRxMcs & 0xc) != 0xc)
				vht_peer_RxNss = 2;

			StaInfo_p->vht_peer_RxNss = vht_peer_RxNss;
			/*If IE199 Rx Nss > IE192 Nss, we copy two bits from IE192 Nss1 to the new Nss bits */
			if (vht_peer_RxNss < vht_RxNss_IE199) {
				for (; vht_peer_RxNss < vht_RxNss_IE199;
				     vht_peer_RxNss++) {
					vht_RxNss1 = (UINT16) PeerInfo.vht_MaxRxMcs & 0x3;	//Copy Nss1 bits and use it in new Nss  
					vht_RxNss1 =
						(vht_RxNss1 <<
						 (vht_peer_RxNss * 2));

					vht_RxNssMask = ~(0x3 << (vht_peer_RxNss * 2));	//Set new Nss bits to zero
					PeerInfo.vht_MaxRxMcs =
						PeerInfo.
						vht_MaxRxMcs & vht_RxNssMask;
					PeerInfo.vht_MaxRxMcs =
						PeerInfo.
						vht_MaxRxMcs | vht_RxNss1;
				}
			} else if (vht_peer_RxNss > vht_RxNss_IE199) {
				for (; vht_peer_RxNss > vht_RxNss_IE199;
				     vht_peer_RxNss--) {
					vht_RxNssMask =
						0xc000 >> ((8 - vht_peer_RxNss)
							   * 2);
					PeerInfo.vht_MaxRxMcs =
						PeerInfo.
						vht_MaxRxMcs | vht_RxNssMask;
				}
			}
		} else {
			/*If IE192 channel width bit is 0, we use IE61 channel width bit to decide 20 or 40Mhz (11ac standard section 10.39.1) */
			if (IE192Present) {
				switch (vht_RxChannelWidth_IE192) {
				case 0:
					if (ht_RxChannelWidth_IE61 == 1)
						PeerInfo.vht_RxChannelWidth = 1;
					else
						PeerInfo.vht_RxChannelWidth = 0;
					break;
				case 1:
#ifdef SUPPORTED_EXT_NSS_BW
					printk("%s ", __FUNCTION__);
					if (1 ==
					    (ret =
					     isSupport160MhzByCenterFreq(wlpptr,
									 VHT_EXTENDED_NSS_BW_CAPABLE,
									 vht_center_freq0_IE192,
									 vht_center_freq1_IE192,
									 PeerInfo.
									 AddHtInfo.
									 OpMode.
									 center_freq2)))
					{

						PeerInfo.vht_RxChannelWidth = 3;

					} else {
						if (ret == -1) {
							PeerInfo.
								vht_RxChannelWidth
								= 3;
						} else if (ret == 0) {
							PeerInfo.
								vht_RxChannelWidth
								= 2;
							printk("80MHz or less\n");
						}
					}
#else

					if (vht_center_freq1_IE192 == 0) {
						PeerInfo.vht_RxChannelWidth = 2;
						//printk("%s 80MHz or less\n", __FUNCTION__);
					} else {
						UINT8 diff;
						if (vht_center_freq1_IE192 >
						    vht_center_freq0_IE192) {
							diff = vht_center_freq1_IE192 - vht_center_freq0_IE192;
						} else {
							diff = vht_center_freq0_IE192 - vht_center_freq1_IE192;
						}
						if (diff == 8) {
							PeerInfo.
								vht_RxChannelWidth
								= 3;
						} else if (diff > 8) {
#ifdef SOC_W906X
							isSupport80plus80Mhz
								(wlpptr);
#else
							WLDBG_ERROR(DBG_LEVEL_1,
								    "80MHz + 80MHz, not support\n");
#endif
							PeerInfo.
								vht_RxChannelWidth
								= 3;
						} else {
							//printk("%s reserved\n", __FUNCTION__);
							PeerInfo.
								vht_RxChannelWidth
								= 2;
						}
					}
#endif
					break;
				case 2:
				case 3:
					PeerInfo.vht_RxChannelWidth = 3;
					break;
				default:
					PeerInfo.vht_RxChannelWidth = 2;
					break;
				}
			} else {
				/*In 2G, we check HT cap to decide peer bandwidth. Having VHT cap info not necessarily means can support 80 or 40MHz */
				if (PhyDSSSTable->Chanflag.FreqBand ==
				    FREQ_BAND_2DOT4GHZ) {
					if (PeerInfo.HTCapabilitiesInfo.
					    SupChanWidth)
						PeerInfo.vht_RxChannelWidth = 1;
					else
						PeerInfo.vht_RxChannelWidth = 0;
				} else {
					/*If 160MHz or (160 and 80+80MHz) supported */
					if ((vht_RxChannelWidth_IE191 == 1) ||
					    (vht_RxChannelWidth_IE191 == 2))
						PeerInfo.vht_RxChannelWidth = 3;
					else
						PeerInfo.vht_RxChannelWidth = 2;	//HT client is not using vht_RxChannelWidth to determine its operating bw 

				}
			}
		}

		if (IE191Present) {
			if ((PeerInfo.vht_MaxRxMcs & 0xc000) != 0xc000)
				vht_peer_RxNss = 8;
			else if ((PeerInfo.vht_MaxRxMcs & 0x3000) != 0x3000)
				vht_peer_RxNss = 7;
			else if ((PeerInfo.vht_MaxRxMcs & 0xc00) != 0xc00)
				vht_peer_RxNss = 6;
			else if ((PeerInfo.vht_MaxRxMcs & 0x300) != 0x300)
				vht_peer_RxNss = 5;
			else if ((PeerInfo.vht_MaxRxMcs & 0xc0) != 0xc0)
				vht_peer_RxNss = 4;
			else if ((PeerInfo.vht_MaxRxMcs & 0x30) != 0x30)
				vht_peer_RxNss = 3;
			else if ((PeerInfo.vht_MaxRxMcs & 0xc) != 0xc)
				vht_peer_RxNss = 2;

			StaInfo_p->vht_RxChannelWidth =
				PeerInfo.vht_RxChannelWidth;
			StaInfo_p->vht_peer_RxNss = vht_peer_RxNss;

		}

		if (he_cap_present) {
			vht_peer_RxNss = 1;
			if ((PeerInfo.he_cap.rx_he_mcs_80m.
			     max_mcs_set & 0xc000) != 0xc000)
				vht_peer_RxNss = 8;
			else if ((PeerInfo.he_cap.rx_he_mcs_80m.
				  max_mcs_set & 0x3000) != 0x3000)
				vht_peer_RxNss = 7;
			else if ((PeerInfo.he_cap.rx_he_mcs_80m.
				  max_mcs_set & 0xc00) != 0xc00)
				vht_peer_RxNss = 6;
			else if ((PeerInfo.he_cap.rx_he_mcs_80m.
				  max_mcs_set & 0x300) != 0x300)
				vht_peer_RxNss = 5;
			else if ((PeerInfo.he_cap.rx_he_mcs_80m.
				  max_mcs_set & 0xc0) != 0xc0)
				vht_peer_RxNss = 4;
			else if ((PeerInfo.he_cap.rx_he_mcs_80m.
				  max_mcs_set & 0x30) != 0x30)
				vht_peer_RxNss = 3;
			else if ((PeerInfo.he_cap.rx_he_mcs_80m.
				  max_mcs_set & 0xc) != 0xc)
				vht_peer_RxNss = 2;
			StaInfo_p->vht_peer_RxNss = vht_peer_RxNss;
		}

		/* if not NXP station and Wep encryption then turn off aggregation  */
		if (!StaInfo_p->IsStaMSTA && mib_PrivacyTable_p->PrivInvoked) {
			if (StaInfo_p->aggr11n.threshold) {
				StaInfo_p->aggr11n.threshold = 0;
				StaInfo_p->aggr11n.thresholdBackUp =
					StaInfo_p->aggr11n.threshold;
#ifdef WIFI_DATA_OFFLOAD
				dol_sta_tx_ampdu_ctrl(wlpptr,
						      wlpptr->wlpd_p->
						      ipc_session_id,
						      wlpptr->vmacSta_p->
						      VMacEntry.macId,
						      (u8 *) StaInfo_p->Addr, 0,
						      NULL);
#endif
			}
		}

		skb_trim(txSkb_p, frameSize);

#ifdef WFA_TKIP_NEGATIVE
		/* If HT STA and AP mode is WPA-TKIP or WPA-AES, reject the association request */
		if (!allow_ht_tkip &&
		    ((HTpresent) &&
		     ((*(vmacSta_p->Mib802dot11->mib_wpaWpa2Mode) & 0x0F) ==
		      1))) {
			MgmtRsp_p->Body.AssocRsp.StatusCode =
				IEEEtypes_STATUS_CAPS_UNSUPPORTED;
			/* Send for tx */
			if (txMgmtMsg(vmacSta_p->dev, txSkb_p) != OS_SUCCESS)
				wl_free_skb(txSkb_p);
			goto OUT;
		}

		/* If HT STA and AP mode is mixed WPA2-AES and WPA-TKIP and 
		   if the STA associates as WPA-TKIP reject the request */
		if (!allow_ht_tkip && ((HTpresent) &&
				       (((*
					  (vmacSta_p->Mib802dot11->
					   mib_wpaWpa2Mode) & 0x0F) == 3) ||
					((*
					  (vmacSta_p->Mib802dot11->
					   mib_wpaWpa2Mode) & 0x0F) == 6)) &&
				       (RsnIE_p != NULL) &&
				       (RsnIE_p->PwsKeyCipherList[3] ==
					RSN_TKIP_ID))) {
			MgmtRsp_p->Body.AssocRsp.StatusCode =
				IEEEtypes_STATUS_CAPS_UNSUPPORTED;
			/* Send for tx */
			if (txMgmtMsg(vmacSta_p->dev, txSkb_p) != OS_SUCCESS)
				wl_free_skb(txSkb_p);
			goto OUT;
		}
#endif

		if ((!HTpresent)
		    && (*(vmacSta_p->Mib802dot11->mib_ApMode) ==
			AP_MODE_N_ONLY)) {
			MgmtRsp_p->Body.AssocRsp.StatusCode =
				IEEEtypes_STATUS_CAPS_UNSUPPORTED;
			/* Send for tx */
			if (txMgmtMsg(vmacSta_p->dev, txSkb_p) != OS_SUCCESS)
				wl_free_skb(txSkb_p);
			goto OUT;
		}

		if (!(isSsIdMatch(SsId_p, &vmacSta_p->macSsId) ==
		      OS_SUCCESS || isSsIdMatch(SsId_p, &vmacSta_p->macSsId2) ==
		      OS_SUCCESS)) {
			/* Build ASSOC_RSP msg with REFUSED status code */
			MgmtRsp_p->Body.AssocRsp.StatusCode =
				IEEEtypes_STATUS_ASSOC_DENIED_UNSPEC;
			/* Send for tx */
			if (txMgmtMsg(vmacSta_p->dev, txSkb_p) != OS_SUCCESS)
				wl_free_skb(txSkb_p);
			goto OUT;
		}
		if (isCapInfoSupported(&MgmtMsg_p->Body.AssocRqst.CapInfo,
				       &vmacSta_p->macCapInfo) != OS_SUCCESS) {
			/* Build ASSOC_RSP msg with cannot supp cap info (code 10) */
			MgmtRsp_p->Body.AssocRsp.StatusCode =
				IEEEtypes_STATUS_CAPS_UNSUPPORTED;

			/* Send for tx */
			if (txMgmtMsg(vmacSta_p->dev, txSkb_p) != OS_SUCCESS)
				wl_free_skb(txSkb_p);
			goto OUT;
		}

		if (*(vmacSta_p->Mib802dot11->mib_ApMode) ==
		    AP_MODE_5GHZ_11AC_ONLY) {
			if (!IE191Present) {
				/* Build ASSOC_RSP msg with REFUSED status code */
				MgmtRsp_p->Body.AssocRsp.StatusCode =
					IEEEtypes_STATUS_ASSOC_DENIED_UNSPEC;
				/* Send for tx */
				if (txMgmtMsg(vmacSta_p->dev, txSkb_p) !=
				    OS_SUCCESS)
					wl_free_skb(txSkb_p);
				goto OUT;
			}
		}
#ifdef SOC_W906X
		if (*(vmacSta_p->Mib802dot11->mib_ApMode) ==
		    AP_MODE_5GHZ_11AX_ONLY) {
			if (!he_cap_present) {
				/* Build ASSOC_RSP msg with REFUSED status code */
				MgmtRsp_p->Body.AssocRsp.StatusCode =
					IEEEtypes_STATUS_ASSOC_DENIED_UNSPEC;
				/* Send for tx */
				if (txMgmtMsg(vmacSta_p->dev, txSkb_p) !=
				    OS_SUCCESS)
					wl_free_skb(txSkb_p);
				return;
			}
		}
#endif /* SOC_W906X */
		PeerInfo.CapInfo = MgmtMsg_p->Body.AssocRqst.CapInfo;

		if (Rates_p) {
			PeerInfo.LegacyRateBitMap =
				ENDIAN_SWAP32(GetLegacyRateBitMap
					      (vmacSta_p, Rates_p, ExtRates_p));
			HighestRate =
				GetHighestRateIndex(vmacSta_p, Rates_p,
						    ExtRates_p, &gRatePresent);
		} else {
			/* Build ASSOC_RSP msg with basic rates not supported */
			MgmtRsp_p->Body.AssocRsp.StatusCode =
				IEEEtypes_STATUS_ASSOC_DENIED_RATES;

			/* Send for tx */
			if (txMgmtMsg(vmacSta_p->dev, txSkb_p) != OS_SUCCESS)
				wl_free_skb(txSkb_p);
			goto OUT;
		}

		if (StaInfo_p->ClientMode == NONLY_MODE) {
			//StaInfo_p->ClientMode = NONLY_MODE;
		} else if (!gRatePresent) {
			StaInfo_p->ClientMode = BONLY_MODE;
		} else {
			if (*(mib->mib_ApMode) == AP_MODE_B_ONLY) {
				StaInfo_p->ClientMode = BONLY_MODE;
			} else if (*(mib->mib_ApMode) == AP_MODE_A_ONLY) {
				StaInfo_p->ClientMode = AONLY_MODE;
			} else if (*(mib->mib_ApMode) == AP_MODE_G_ONLY) {
				StaInfo_p->ClientMode = GONLY_MODE;
			} else if ((*(mib->mib_ApMode) == AP_MODE_BandGandN) ||
				   (*(mib->mib_ApMode) ==
				    AP_MODE_2_4GHZ_11AC_MIXED) ||
#ifdef SOC_W906X
				   (*(mib->mib_ApMode) ==
				    AP_MODE_2_4GHZ_Nand11AX) ||
				   (*(mib->mib_ApMode) ==
				    AP_MODE_2_4GHZ_11AX_MIXED) ||
#endif
				   (*(mib->mib_ApMode) == AP_MODE_MIXED) ||
				   (*(mib->mib_ApMode) == AP_MODE_GandN)) {
				StaInfo_p->ClientMode = GONLY_MODE;
			} else if ((*(mib->mib_ApMode) == AP_MODE_AandN) ||
				   (*(mib->mib_ApMode) == AP_MODE_5GHZ_Nand11AC)
				   || (*(mib->mib_ApMode) ==
				       AP_MODE_5GHZ_11AC_ONLY)
#ifdef SOC_W906X
				   || (*(mib->mib_ApMode) ==
				       AP_MODE_5GHZ_11AX_ONLY)
#endif
				) {
				StaInfo_p->ClientMode = AONLY_MODE;
			} else {
				StaInfo_p->ClientMode = MIXED_MODE;
			}
		}
		FixedRateCtl(StaInfo_p, &PeerInfo, mib);

		if ((!gRatePresent && (*(mib->mib_ApMode) == AP_MODE_G_ONLY)) ||
		    (gRatePresent && (*(mib->mib_ApMode) == AP_MODE_B_ONLY))
#ifdef BRS_SUPPORT
		    || (!PeerInfo.LegacyRateBitMap)
#endif
			) {
			/* Build ASSOC_RSP msg with basic rates not supported */
			MgmtRsp_p->Body.AssocRsp.StatusCode =
				IEEEtypes_STATUS_ASSOC_DENIED_RATES;

			/* Send for tx */
			if (txMgmtMsg(vmacSta_p->dev, txSkb_p) != OS_SUCCESS)
				wl_free_skb(txSkb_p);
			goto OUT;
		}
#ifdef SOC_W906X
		if (!gRatePresent && (*(mib->mib_ApMode) == AP_MODE_G_ONLY ||
				      *(mib->mib_ApMode) == AP_MODE_A_ONLY ||
				      *(mib->mib_ApMode) == AP_MODE_AandN ||
				      *(mib->mib_ApMode) ==
				      AP_MODE_5GHZ_Nand11AC ||
				      *(mib->mib_ApMode) ==
				      AP_MODE_5GHZ_11AC_ONLY ||
				      *(mib->mib_ApMode) ==
				      AP_MODE_5GHZ_ACand11AX ||
				      *(mib->mib_ApMode) ==
				      AP_MODE_5GHZ_NandACand11AX ||
				      *(mib->mib_ApMode) ==
				      AP_MODE_5GHZ_11AX_ONLY))
#else
		if (!gRatePresent) {	/* only 11b supported rate */
			if (*(mib->mib_ApMode) == AP_MODE_G_ONLY ||
			    *(mib->mib_ApMode) == AP_MODE_A_ONLY ||
			    *(mib->mib_ApMode) == AP_MODE_N_ONLY ||
			    *(mib->mib_ApMode) == AP_MODE_GandN ||
			    *(mib->mib_ApMode) == AP_MODE_AandN ||
#ifdef SOC_W8864
			    *(mib->mib_ApMode) == AP_MODE_5GHZ_Nand11AC ||
			    *(mib->mib_ApMode) == AP_MODE_5GHZ_11AC_ONLY
#endif
				) {
				/* Build ASSOC_RSP msg with basic rates not supported */
				MgmtRsp_p->Body.AssocRsp.StatusCode =
					IEEEtypes_STATUS_ASSOC_DENIED_RATES;

				/* Send for tx */
				if (txMgmtMsg(vmacSta_p->dev, txSkb_p) !=
				    OS_SUCCESS)
					wl_free_skb(txSkb_p);
				goto OUT;
			}
		} else if (gRatePresent && !HTpresent) {	/* 11a or 11g supported rate */
			if (*(mib->mib_ApMode) == AP_MODE_B_ONLY ||
			    *(mib->mib_ApMode) == AP_MODE_N_ONLY ||
			    *(mib->mib_ApMode) == AP_MODE_5GHZ_11AC_ONLY ||
			    *(mib->mib_ApMode) == AP_MODE_11AC) {
				/* Build ASSOC_RSP msg with basic rates not supported */
				MgmtRsp_p->Body.AssocRsp.StatusCode =
					IEEEtypes_STATUS_ASSOC_DENIED_RATES;

				/* Send for tx */
				if (txMgmtMsg(vmacSta_p->dev, txSkb_p) !=
				    OS_SUCCESS)
					wl_free_skb(txSkb_p);
				goto OUT;

			}
		} else if (HTpresent && !IE191Present) {	/* HT supported rate */
			if (*(mib->mib_ApMode) == AP_MODE_B_ONLY ||
			    *(mib->mib_ApMode) == AP_MODE_G_ONLY ||
			    *(mib->mib_ApMode) == AP_MODE_MIXED ||
			    *(mib->mib_ApMode) == AP_MODE_A_ONLY ||
			    *(mib->mib_ApMode) == AP_MODE_AandG ||
			    *(mib->mib_ApMode) == AP_MODE_5GHZ_11AC_ONLY) {
				/* Build ASSOC_RSP msg with basic rates not supported */
				MgmtRsp_p->Body.AssocRsp.StatusCode =
					IEEEtypes_STATUS_ASSOC_DENIED_RATES;

				/* Send for tx */
				if (txMgmtMsg(vmacSta_p->dev, txSkb_p) !=
				    OS_SUCCESS)
					wl_free_skb(txSkb_p);
				goto OUT;

			}
		} else if (IE191Present) {	/* VHT supported */
			if (*(mib->mib_ApMode) == AP_MODE_A_ONLY ||
			    *(mib->mib_ApMode) == AP_MODE_N_ONLY)
#endif /* SOC_W906X */
			{
				/* Build ASSOC_RSP msg with basic rates not supported */
				MgmtRsp_p->Body.AssocRsp.StatusCode =
					IEEEtypes_STATUS_ASSOC_DENIED_RATES;

				/* Send for tx */
				if (txMgmtMsg(vmacSta_p->dev, txSkb_p) !=
				    OS_SUCCESS)
					wl_free_skb(txSkb_p);
				goto OUT;
			}
#ifndef SOC_W906X
		}
#endif
#ifdef IEEE80211H
		if ((*(mib->mib_ApMode) == AP_MODE_A_ONLY) ||
		    ((*(mib->mib_ApMode) == AP_MODE_AandG) &&
		     (StaInfo_p->ApMode == AONLY_MODE)))
			StaInfo_p->IsSpectrumMgmt =
				(MgmtMsg_p->Body.AssocRqst.CapInfo.
				 SpectrumMgmt) ? TRUE : FALSE;
		else
			StaInfo_p->IsSpectrumMgmt = FALSE;	/* stations are not in A mode */

		/* CH 11.5 */
		if (StaInfo_p->IsSpectrumMgmt == TRUE) {
#ifdef 	BARBADOS_DFS_TEST
			if (!dfs_test)
#else
			if (!dfs_test_mode)
#endif
			{
				/* Ignore for dfs testing - Veriwave does not have thest elements, need to tell Veriwave. */
				/* if station lacks two IEs */
				if ((PowerCapability_p == NULL) ||
				    (SupportedChanne_p == NULL)) {
					/* Build ASSOC_RSP msg with status code accordingly */
					if (PowerCapability_p == NULL)
						MgmtRsp_p->Body.AssocRsp.
							StatusCode =
							IEEEtypes_STATUS_ASSOC_PWE_CAP_REQUIRED;
					else
						MgmtRsp_p->Body.AssocRsp.
							StatusCode =
							IEEEtypes_STATUS_ASSOC_SUP_CHA_REQUIRED;;

					/* Send for tx */
					if (txMgmtMsg(vmacSta_p->dev, txSkb_p)
					    != OS_SUCCESS)
						wl_free_skb(txSkb_p);
					goto OUT;
				}

			}
		}
#endif /* IEEE80211H */

#ifdef MRVL_WSC
		/* WPS MSFT Patch require that the AP does not object if the station 
		 * does not include RSN IE even when the WPA(2) is enabled.
		 */
		if ((mib_PrivacyTable_p->RSNEnabled &&
		     !mib_RSNConfigWPA2_p->WPA2Enabled &&
		     !mib_RSNConfigWPA2_p->WPA2OnlyEnabled && (RsnIE_p != NULL)
		     &&
		     (memcmp
		      (RsnIE_p->OuiType, &(mib->thisStaRsnIE->OuiType),
		       mib->thisStaRsnIE->Len) != 0))
		    || (vmacSta_p->WPSOn == 0 &&
			mib_RSNConfigWPA2_p->WPA2Enabled && (RsnIEWPA2_p == NULL
							     && RsnIE_p ==
							     NULL))
		    || (vmacSta_p->WPSOn == 0 &&
			mib_RSNConfigWPA2_p->WPA2OnlyEnabled &&
			(RsnIEWPA2_p == NULL))) {
			// Build ASSOC_RSP msg with reason code
			MgmtRsp_p->Body.AssocRsp.StatusCode =
				IEEEtypes_REASON_INVALID_IE;
			/* Send for tx */
			if (txMgmtMsg(vmacSta_p->dev, txSkb_p) != OS_SUCCESS)
				wl_free_skb(txSkb_p);
			goto OUT;
		}
#endif //MRVL_WSC

#ifdef CONFIG_IEEE80211W
		StaInfo_p->Ieee80211wSta = 0;
#endif

		if (mib_PrivacyTable_p->RSNEnabled) {
			if (vmacSta_p->MIC_ErrordisableStaAsso) {
				MgmtRsp_p->Body.AssocRsp.StatusCode =
					IEEEtypes_REASON_MIC_FAILURE;

				/* Send for tx */
				if (txMgmtMsg(vmacSta_p->dev, txSkb_p) !=
				    OS_SUCCESS)
					wl_free_skb(txSkb_p);
				goto OUT;
			}

			pStaMsg = &pDistMsg->msg.StaAssocStateMsg;

			pDistMsg->MsgType = STA_ASSOMSGRECVD;
			memcpy(pStaMsg->staMACAddr, MgmtMsg_p->Hdr.SrcAddr, 6);
			pStaMsg->assocType = WPAEVT_STA_ASSOCIATED;

			// Init keyMgmt DB
			memset(&StaInfo_p->keyMgmtStateInfo, 0,
			       sizeof(keyMgmtInfo_t));
			// save the RSN IE into ext Sta DB
			if (mib_RSNConfigWPA2_p->WPA2OnlyEnabled) {
				if (RsnIEWPA2_p != NULL) {
					UINT8 mfpc, mfpr;
					IEEEtypes_RSN_IE_WPA2_t RsnIEWPA2;
					IEEEtypes_RSN_IE_WPA2_t MibRsnIEWPA2;
					int ret, ret1;

					memset(StaInfo_p->keyMgmtStateInfo.
					       RsnIEBuf, 0,
					       MAX_SIZE_RSN_IE_BUF);
					if ((RsnIEWPA2_p->Len + 2) >
					    MAX_SIZE_RSN_IE_BUF)
						OUT_OF_BOUNDARDY_MESSAGE((RsnIEWPA2_p->Len + 2), MAX_SIZE_RSN_IE_BUF);
					else
						memcpy(StaInfo_p->
						       keyMgmtStateInfo.
						       RsnIEBuf, RsnIEWPA2_p,
						       RsnIEWPA2_p->Len + 2);

#ifdef CONFIG_IEEE80211W
					ret1 = parsing_rsn_ie((UINT8 *) mib->
							      thisStaRsnIEWPA2,
							      &MibRsnIEWPA2,
							      &mfpc, &mfpr);
					ret = parsing_rsn_ie((UINT8 *)
							     RsnIEWPA2_p,
							     &RsnIEWPA2, &mfpc,
							     &mfpr);
#else
					ret1 = parsing_rsn_ie((UINT8 *) mib->
							      thisStaRsnIEWPA2,
							      &MibRsnIEWPA2);
					ret = parsing_rsn_ie((UINT8 *)
							     RsnIEWPA2_p,
							     &RsnIEWPA2);
#endif
					if (RsnIEWPA2.AuthKeyList[3] == 0x08 ||
					    RsnIEWPA2.AuthKeyList1[3] == 0x08) {
						if (mfpc == 0 && mfpr == 0) {
							MgmtRsp_p->Body.
								AssocRsp.
								StatusCode =
								IEEEtypes_STATUS_ASSOC_DENIED_INVALID_IE;

							if (txMgmtMsg
							    (vmacSta_p->dev,
							     txSkb_p) !=
							    OS_SUCCESS)
								wl_free_skb
									(txSkb_p);
							goto OUT;
						}
					}

					if (ret == -1) {
						MgmtRsp_p->Body.AssocRsp.
							StatusCode =
							IEEEtypes_STATUS_ASSOC_DENIED_INVALID_IE;

						if (txMgmtMsg
						    (vmacSta_p->dev,
						     txSkb_p) != OS_SUCCESS)
							wl_free_skb(txSkb_p);
						goto OUT;
					}

					if ((RsnIEWPA2.Ver[0] != 0x01) ||
					    (RsnIEWPA2.Ver[1] != 0x00)) {
						MgmtRsp_p->Body.AssocRsp.
							StatusCode =
							IEEEtypes_STATUS_ASSOC_DENIED_INVALID_IE;

						if (txMgmtMsg
						    (vmacSta_p->dev,
						     txSkb_p) != OS_SUCCESS)
							wl_free_skb(txSkb_p);
						goto OUT;
					}

					if ((ret > 1) && (ret1 > 1) &&
					    (memcmp
					     (mib->thisStaRsnIEWPA2->
					      GrpKeyCipher,
					      RsnIEWPA2.GrpKeyCipher,
					      sizeof(RsnIEWPA2.
						     GrpKeyCipher)))) {
						MgmtRsp_p->Body.AssocRsp.
							StatusCode =
							IEEEtypes_STATUS_ASSOC_DENIED_INVALID_GRP_CIPHER;

						if (txMgmtMsg
						    (vmacSta_p->dev,
						     txSkb_p) != OS_SUCCESS)
							wl_free_skb(txSkb_p);
						goto OUT;
					}

					if ((ret > 2) && (ret1 > 2) &&
					    (memcmp
					     (mib->thisStaRsnIEWPA2->
					      PwsKeyCipherList,
					      RsnIEWPA2.PwsKeyCipherList,
					      sizeof(RsnIEWPA2.
						     PwsKeyCipherList)))) {
						MgmtRsp_p->Body.AssocRsp.
							StatusCode =
							IEEEtypes_STATUS_ASSOC_DENIED_INVALID_PAIRWISE_CIPHER;

						if (txMgmtMsg
						    (vmacSta_p->dev,
						     txSkb_p) != OS_SUCCESS)
							wl_free_skb(txSkb_p);
						goto OUT;
					}

					if ((ret == 1) || (ret == 2)) {
						reconfig_rsn_ie = TRUE;
					}

					if ((ret > 4) && (ret1 > 4)) {
						if ((MibRsnIEWPA2.
						     AuthKeyCnt[0] == 1) &&
						    (RsnIEWPA2.AuthKeyCnt[0] ==
						     1)) {
							if (memcmp
							    (MibRsnIEWPA2.
							     AuthKeyList,
							     RsnIEWPA2.
							     AuthKeyList,
							     sizeof(RsnIEWPA2.
								    AuthKeyList)))
							{
								MgmtRsp_p->Body.
									AssocRsp.
									StatusCode
									=
									IEEEtypes_STATUS_ASSOC_DENIED_INVALID_AKMP;

								if (txMgmtMsg
								    (vmacSta_p->
								     dev,
								     txSkb_p) !=
								    OS_SUCCESS)
									wl_free_skb
										(txSkb_p);
								goto OUT;
							}
						}
					}

					if ((ret == 9) && (ret1 == 9)) {
						if (memcmp
						    (MibRsnIEWPA2.
						     GrpMgtKeyCipher,
						     RsnIEWPA2.GrpMgtKeyCipher,
						     sizeof(RsnIEWPA2.
							    GrpMgtKeyCipher))) {
							MgmtRsp_p->Body.
								AssocRsp.
								StatusCode =
								IEEEtypes_STATUS_ASSOC_DENIED_CIPHER_SUITE_REJECTED;

							if (txMgmtMsg
							    (vmacSta_p->dev,
							     txSkb_p) !=
							    OS_SUCCESS)
								wl_free_skb
									(txSkb_p);
							goto OUT;
						}
					}
#ifdef CONFIG_IEEE80211W
					TimerDisarm(&StaInfo_p->SA_Query_Timer);
					StaInfo_p->sa_query_count = 0;	// ### added for PMF TC-4.3.3.4

#ifdef SOC_W906X
					RsnBIPcap(RsnIEWPA2_p, &mfpc, &mfpr);
#endif

					if ((mfpr == 1) &&
					    (vmacSta_p->ieee80211w == 0)) {
						wl_free_skb(txSkb_p);
						goto OUT;	//No Action
					}

					if ((mfpr > mfpc) ||
					    ((mfpc != vmacSta_p->ieee80211w) &&
					     (mfpr !=
					      vmacSta_p->ieee80211wRequired))) {
						// Build ASSOC_RSP msg with reason code
						MgmtRsp_p->Body.AssocRsp.
							StatusCode =
							IEEEtypes_STATUS_ROBUST_MGMT_FRAME_POLICY_VIOLATION;
						/* Send for tx */
						if (txMgmtMsg
						    (vmacSta_p->dev,
						     txSkb_p) != OS_SUCCESS)
							wl_free_skb(txSkb_p);
						goto OUT;
					} else {
						if ((mfpc + mfpr +
						     vmacSta_p->ieee80211w) > 1)
							StaInfo_p->
								Ieee80211wSta =
								1;
						else
							StaInfo_p->
								Ieee80211wSta =
								0;
					}
#endif
#ifdef SOC_W906X
					/* If only WPA2 is enabled check that the group cipher is AES */
					if ((ret > 1) &&
					    (RsnIEWPA2_p->GrpKeyCipher[3] !=
					     RSN_AES_ID) &&
					    (RsnIEWPA2_p->GrpKeyCipher[3] !=
					     RSN_GCMP_ID) &&
					    (RsnIEWPA2_p->GrpKeyCipher[3] !=
					     RSN_GCMP_256_ID) &&
					    (RsnIEWPA2_p->GrpKeyCipher[3] !=
					     RSN_CCMP_256_ID)) {
						MgmtRsp_p->Body.AssocRsp.
							StatusCode =
							IEEEtypes_STATUS_ASSOC_DENIED_INVALID_GRP_CIPHER;

						if (txMgmtMsg
						    (vmacSta_p->dev,
						     txSkb_p) != OS_SUCCESS)
							wl_free_skb(txSkb_p);
						return;
					}
#endif /* SOC_W906X */
				}
			} else if (mib_RSNConfigWPA2_p->WPA2Enabled) {
				if (RsnIEWPA2_p != NULL) {
					memset(StaInfo_p->keyMgmtStateInfo.
					       RsnIEBuf, 0,
					       MAX_SIZE_RSN_IE_BUF);
					if ((RsnIEWPA2_p->Len + 2) >
					    MAX_SIZE_RSN_IE_BUF)
						OUT_OF_BOUNDARDY_MESSAGE((RsnIEWPA2_p->Len + 2), MAX_SIZE_RSN_IE_BUF);
					else
						memcpy(StaInfo_p->
						       keyMgmtStateInfo.
						       RsnIEBuf, RsnIEWPA2_p,
						       RsnIEWPA2_p->Len + 2);
					/* In mixed mode is STA is associating as a WPA2 STA check that group cipher is TKIP */
					if (HTpresent == 0 &&
					    RsnIEWPA2_p->GrpKeyCipher[3] !=
					    RSN_TKIP_ID) {
						MgmtRsp_p->Body.AssocRsp.
							StatusCode =
							IEEEtypes_STATUS_ASSOC_DENIED_INVALID_GRP_CIPHER;
						if (txMgmtMsg
						    (vmacSta_p->dev,
						     txSkb_p) != OS_SUCCESS)
							wl_free_skb(txSkb_p);
						goto OUT;
					}
					if (macMgmtMlme_WPA2PMF_Verify
					    (vmacSta_p, txSkb_p, StaInfo_p,
					     RsnIEWPA2_p,
					     &reconfig_rsn_ie) == FALSE) {
						goto OUT;
					}
				} else if (RsnIE_p != NULL) {
					memset(StaInfo_p->keyMgmtStateInfo.
					       RsnIEBuf, 0,
					       MAX_SIZE_RSN_IE_BUF);
					if ((RsnIE_p->Len + 2) >
					    MAX_SIZE_RSN_IE_BUF)
						OUT_OF_BOUNDARDY_MESSAGE((RsnIE_p->Len + 2), MAX_SIZE_RSN_IE_BUF);
					else
						memcpy(StaInfo_p->
						       keyMgmtStateInfo.
						       RsnIEBuf, RsnIE_p,
						       RsnIE_p->Len + 2);
					/* In mixed mode is STA is associating as a WPA STA check that unicast cipher is TKIP and group is TKIP */
					if (HTpresent == 0 &&
					    RsnIE_p->GrpKeyCipher[3] !=
					    RSN_TKIP_ID) {
						MgmtRsp_p->Body.AssocRsp.
							StatusCode =
							IEEEtypes_STATUS_ASSOC_DENIED_INVALID_GRP_CIPHER;
						if (txMgmtMsg
						    (vmacSta_p->dev,
						     txSkb_p) != OS_SUCCESS)
							wl_free_skb(txSkb_p);
						goto OUT;
					}
				}
			} else {
				if (RsnIE_p != NULL) {
					memset(StaInfo_p->keyMgmtStateInfo.
					       RsnIEBuf, 0,
					       MAX_SIZE_RSN_IE_BUF);
					if ((RsnIE_p->Len + 2) >
					    MAX_SIZE_RSN_IE_BUF)
						OUT_OF_BOUNDARDY_MESSAGE((RsnIE_p->Len + 2), MAX_SIZE_RSN_IE_BUF);
					else
						memcpy(StaInfo_p->
						       keyMgmtStateInfo.
						       RsnIEBuf, RsnIE_p,
						       RsnIE_p->Len + 2);
				}
			}
#ifdef MRVL_80211R
			if (MDIE_p != NULL) {
				if ((MDIE_p->Len + 2) > MAX_SIZE_MDIE_BUF)
					OUT_OF_BOUNDARDY_MESSAGE((MDIE_p->Len +
								  2),
								 MAX_SIZE_MDIE_BUF);
				else
					memcpy(StaInfo_p->keyMgmtStateInfo.
					       mdie_buf, MDIE_p,
					       (MDIE_p->Len + 2));
				if (FTIE_p != NULL) {
					if ((FTIE_p[1] + 2) > MAX_SIZE_FTIE_BUF)
						OUT_OF_BOUNDARDY_MESSAGE((FTIE_p
									  [1] +
									  2),
									 MAX_SIZE_FTIE_BUF);
					else
						memcpy(StaInfo_p->
						       keyMgmtStateInfo.
						       ftie_buf, FTIE_p,
						       (FTIE_p[1] + 2));
				}
				assoc_pending = 1;
			}
			if (RsnIEWPA2_p != NULL) {
				IEEEtypes_RSN_IE_WPA2_t RsnIEWPA2;

				memset((void *)&RsnIEWPA2, 0,
				       sizeof(IEEEtypes_RSN_IE_WPA2_t));
				memcpy((void *)&RsnIEWPA2, (void *)RsnIEWPA2_p,
				       (RsnIEWPA2_p->Len + 2));
				if (RsnIEWPA2.PMKIDCnt[0] != 0 &&
				    RsnIEWPA2.PMKIDCnt[1] != 0)
					assoc_pending = 1;
			}
#endif

#ifdef OWE_SUPPORT
			if (DH_IE_p) {
				if (*(DH_IE_p + 1) > MAX_SIZE_DH_IE_BUF) {
					printk("Not enough space for DH IE Buf. %d\n", *(DH_IE_p + 1));
					*(DH_IE_p + 1) = MAX_SIZE_DH_IE_BUF;
				}
				memcpy(StaInfo_p->STA_DHIEBuf, DH_IE_p,
				       (sizeof(IEEEtypes_ElementId_t) +
					sizeof(IEEEtypes_Len_t) + *(DH_IE_p +
								    1)));
			}
#endif /* OWE_SUPPORT */
		}
#ifdef SOC_W906X

#ifdef IEEE80211K
		if (vmacSta_p->macCapInfo.Rrm) {
			struct IEEEtypes_RM_Enable_Capabilities_Element_t
				RRM_ie;
			UINT8 rrm_ie_len;

			memset(&RRM_ie, 0,
			       sizeof(struct
				      IEEEtypes_RM_Enable_Capabilities_Element_t));
			RRM_ie.eid = RRM_CAP_IE;
			RRM_ie.Len = 5;
			RRM_ie.LinkMeasCap = 1;
			RRM_ie.NeighRptCap = 1;
			RRM_ie.BcnPasMeasCap = 1;
			RRM_ie.BcnActMeasCap = 1;
			RRM_ie.BcnTabMeasCap = 1;
			RRM_ie.BcnMeasRptCondCap = 1;
			RRM_ie.RCPIMeasCap = 1;
			RRM_ie.RSNIMeasCap = 1;
			rrm_ie_len = RRM_ie.Len + 2;
			if (skb_tailroom(txSkb_p) > rrm_ie_len) {
				//We have enough room at the tail
				memcpy(skb_put(txSkb_p, rrm_ie_len), &RRM_ie,
				       rrm_ie_len);
			} else if (skb_headroom(txSkb_p) > rrm_ie_len) {
				//we have enough at the head
				memcpy(&tempbuffer[0], &txSkb_p->data[0],
				       txSkb_p->len);
				memcpy(&tempbuffer[txSkb_p->len], &RRM_ie,
				       rrm_ie_len);
				memset(&txSkb_p->data[0], 0, txSkb_p->len);
				skb_push(txSkb_p, rrm_ie_len);
				memcpy(&txSkb_p->data[0], &tempbuffer[0],
				       txSkb_p->len);
			}
		}
#endif

		staIdx = AssignStnId(vmacSta_p);

		//only if get a valid stnid then set sta to fw
		if (staIdx >= sta_num) {
			skb_trim(txSkb_p, frameSize);
			MgmtRsp_p->Body.AssocRsp.StatusCode =
				IEEEtypes_STATUS_ASSOC_DENIED_BUSY;
			MgmtRsp_p->Body.AssocRsp.AId = 0;

			//printk("*** Station index table FULL StatusCode=%d mac=%02x%02x%02x%02x%02x%02x\n", 
			//    MgmtRsp_p->Body.AssocRsp.StatusCode, MgmtMsg_p->Hdr.SrcAddr[0],
			//    MgmtMsg_p->Hdr.SrcAddr[1], MgmtMsg_p->Hdr.SrcAddr[2], MgmtMsg_p->Hdr.SrcAddr[3],
			//    MgmtMsg_p->Hdr.SrcAddr[4], MgmtMsg_p->Hdr.SrcAddr[5]);

			if (txMgmtMsg(vmacSta_p->dev, txSkb_p) != OS_SUCCESS)
				wl_free_skb(txSkb_p);
			return;
		}
		StaInfo_p->StnId = staIdx;
		wlFwSetNewStn(vmacSta_p->dev, (u_int8_t *) & MgmtMsg_p->Hdr.SrcAddr, 0, 0, StaInfoDbActionRemoveEntry, NULL, 0, 0, 0);	//del station first
#endif /* SOC_W906X */

		/* Assign Aid */
		if (StaInfo_p->Aid) {
			Aid = StaInfo_p->Aid;
		} else {
			Aid = AssignAid(vmacSta_p);
			ChangeAssocParam = TRUE;
#ifdef CONFIG_IEEE80211W
			if (StaInfo_p->Ieee80211wSta == 0)
				vmacSta_p->Non80211wStaCnt++;
#endif
		}

	/********************************************/
		MgmtRsp_p->Body.AssocRsp.AId = ENDIAN_SWAP16(Aid | AID_PREFIX);
		MgmtRsp_p->Body.AssocRsp.StatusCode = IEEEtypes_STATUS_SUCCESS;
		StaInfo_p->State = ASSOCIATED;
#ifdef OPENWRT
		StaInfo_p->last_connected = ktime_get_seconds();
#endif
		StaInfo_p->Aid = Aid;
		StaInfo_p->mu_sta = 0;

#ifdef WIFI_DATA_OFFLOAD
		if (!mib_PrivacyTable_p->RSNEnabled)
			dol_sta_data_ctrl(wlpptr,
					  wlpptr->wlpd_p->ipc_session_id,
					  wlpptr->vmacSta_p->VMacEntry.macId,
					  StaInfo_p->StnId,
					  (u8 *) StaInfo_p->Addr, true);
#endif

#ifdef SOC_W906X
#ifdef WIFI_DATA_OFFLOAD
		dol_set_ba_info(wlpptr, wlpptr->wlpd_p->ipc_session_id,
				BA_INFO_ASSOC, StaInfo_p->StnId, 0xFFFF, 0xFFFF,
				0xFFFF);
#endif
		free_any_pending_ampdu_pck(vmacSta_p->dev, StaInfo_p->StnId);
		for (i = 0; i < MAX_UP; i++)
				   /** Reset the ampdu reorder pck anyway **/
			wlpptr->wlpd_p->AmpduPckReorder[StaInfo_p->StnId].AddBaReceive[i] = FALSE;
											  /** clear Ba flag **/
#else
		free_any_pending_ampdu_pck(vmacSta_p->dev, Aid);
		for (i = 0; i < 3; i++)
			      /** Reset the ampdu reorder pck anyway **/
			wlpptr->wlpd_p->AmpduPckReorder[Aid].AddBaReceive[i] = FALSE;
									     /** clear Ba flag **/
#endif /* SOC_W906X */
		for (i = 0; i < 8; i++) {
			StaInfo_p->aggr11n.onbytid[i] = 0;
			StaInfo_p->aggr11n.startbytid[i] = 0;
		}
#ifdef WIFI_DATA_OFFLOAD
		dol_sta_tx_ampdu_ctrl(wlpptr,
				      wlpptr->wlpd_p->ipc_session_id,
				      wlpptr->vmacSta_p->VMacEntry.macId,
				      (u8 *) StaInfo_p->Addr,
				      StaInfo_p->aggr11n.threshold, NULL);
#endif

		if (pWMEInfoElem != NULL && *(mib->QoSOptImpl)) {
#ifdef UAPSD_SUPPORT
			isQosSta = 1;
#endif

			if (skb_tailroom(txSkb_p) > WME_PARAM_LEN + 2) {
				//We have enough room at the tail
				pWMEParamElem =
					(WME_param_elem_t *) skb_put(txSkb_p,
								     WME_PARAM_LEN
								     + 2);
				QoS_AppendWMEParamElem(vmacSta_p,
						       (UINT8 *) pWMEParamElem);
			} else if (skb_headroom(txSkb_p) > WME_PARAM_LEN + 2) {
				//we have enough at the head
				memcpy(&tempbuffer[0], &txSkb_p->data[0],
				       txSkb_p->len);
				pWMEParamElem =
					(WME_param_elem_t *) &
					tempbuffer[txSkb_p->len];
				QoS_AppendWMEParamElem(vmacSta_p,
						       (UINT8 *) pWMEParamElem);
				memset(&txSkb_p->data[0], 0, txSkb_p->len);
				skb_push(txSkb_p, WME_PARAM_LEN + 2);
				memcpy(&txSkb_p->data[0], &tempbuffer[0],
				       txSkb_p->len);
				extStaDb_SetQoSOptn(vmacSta_p,
						    &MgmtMsg_p->Hdr.SrcAddr, 1);
			} else {
				WLDBG_INFO(DBG_LEVEL_7, "panic!!!!");

			}
			extStaDb_SetQoSOptn(vmacSta_p, &MgmtMsg_p->Hdr.SrcAddr,
					    1);
		} else {
			extStaDb_SetQoSOptn(vmacSta_p, &MgmtMsg_p->Hdr.SrcAddr,
					    0);
		}

		/* The else portion of code was coded such that all capabilities of assocresp 
		   are following client instead of AP capability. The 'else' code is not used 
		   for now due to unknown interop risk. The code was added per bug req 16029 by AE 
		   which later informed as not needed on 3/12/07 */

	/** Add Additional HT **/
		/* If client include IE45, following code should be involved, IE45 and IE61 should be added */
#ifdef COEXIST_20_40_SUPPORT
		if (*(vmacSta_p->ShadowMib802dot11->mib_HT40MIntoler)) {
			extern void Coexist_RearmTimer(vmacApInfo_t *
						       vmacSta_p);
			extern void Check20_40_Channel_switch(int option,
							      int *mode);
			MIB_PHY_DSSS_TABLE *PhyDSSSTable = mib->PhyDSSSTable;

			if (PhyDSSSTable->Chanflag.FreqBand ==
			    FREQ_BAND_2DOT4GHZ &&
			    (PhyDSSSTable->Chanflag.ChnlWidth == CH_AUTO_WIDTH
			     || PhyDSSSTable->Chanflag.ChnlWidth ==
			     CH_40_MHz_WIDTH))
			{

				if (PeerInfo.HTCapabilitiesInfo.
				    FortyMIntolerant)
					Handle20_40_Channel_switch(vmacSta_p,
								   0);

			/** start coexisttimer when one 40MHz client is connect **/
			/** this cover the case where initial 20/40 switch happen during AP scanning **/

				if (vmacSta_p->n40MClients == 1 && StaInfo_p->HtElem.HTCapabilitiesInfo.SupChanWidth) {
/** start timer only if there is 11n 40M sta **/

					if ((*(mib->USER_ChnlWidth) & 0x0f) == 0) {
/** we are at 20MHz mode **/
						Coexist_RearmTimer(vmacSta_p);
									/** restart timer, sta already reported intolerant **/
					}

				}
			}
		}
#endif

		if (HTpresent) {
		/** Add HT IE45 **/
			if (skb_tailroom(txSkb_p) >
			    26 /** len of add generic ht **/  + 2) {
				//We have enough room at the tail
				pHTIE = (IEEEtypes_HT_Element_t *)
					skb_put(txSkb_p,
						26 /** len of generic ht **/  +
						2);
				memset((void *)pHTIE, 0,
				       26 /** len of generic ht **/  + 2);
				//Add_Generic_AddHT_IE(pAddHTGenericIE);
				AddHT_IE(vmacSta_p, pHTIE);
			} else if (skb_headroom(txSkb_p) >
				   26 /** len of generic ht **/  + 2) {
				//we have enough at the head
				memcpy(&tempbuffer[0], &txSkb_p->data[0],
				       txSkb_p->len);
				pHTIE = (IEEEtypes_HT_Element_t *) &
					tempbuffer[txSkb_p->len];
				//Add_Generic_AddHT_IE(pHTGenericIE);
				AddHT_IE(vmacSta_p, pHTIE);
				memset(&txSkb_p->data[0], 0, txSkb_p->len);
				skb_push(txSkb_p,
					 26 /** len of generic ht **/  + 2);
				memcpy(&txSkb_p->data[0], &tempbuffer[0],
				       txSkb_p->len);
			} else {
				WLDBG_INFO(DBG_LEVEL_7,
					   "panic!!!!in interop buffer alloc");
			}

		/** Add Additional HT IE61 **/
			if (skb_tailroom(txSkb_p) >
			    22 /** len of add generic ht **/  + 2) {

				//We have enough room at the tail
				pAddHTIE =
					(IEEEtypes_Add_HT_Element_t *)
					skb_put(txSkb_p,
						22 /** len of generic ht **/  +
						2);
				memset((void *)pAddHTIE, 0,
				       22 /** len of generic ht **/  + 2);
				AddAddHT_IE(vmacSta_p, pAddHTIE);

			} else if (skb_headroom(txSkb_p) >
				   22 /** len of generic ht **/  + 2) {
				//we have enough at the head
				memcpy(&tempbuffer[0], &txSkb_p->data[0],
				       txSkb_p->len);
				pAddHTIE =
					(IEEEtypes_Add_HT_Element_t *) &
					tempbuffer[txSkb_p->len];
				//Add_Generic_AddHT_IE(pHTGenericIE);
				AddAddHT_IE(vmacSta_p, pAddHTIE);
				memset(&txSkb_p->data[0], 0, txSkb_p->len);
				skb_push(txSkb_p,
					 22 /** len of generic ht **/  + 2);
				memcpy(&txSkb_p->data[0], &tempbuffer[0],
				       txSkb_p->len);
			} else {
				WLDBG_INFO(DBG_LEVEL_7,
					   "panic!!!!in interop buffer alloc");
			}

#ifdef COEXIST_20_40_SUPPORT
			if (*(vmacSta_p->ShadowMib802dot11->mib_HT40MIntoler)) {
				if (PhyDSSSTable->Chanflag.FreqBand ==
				    FREQ_BAND_2DOT4GHZ &&
				    (PhyDSSSTable->Chanflag.ChnlWidth ==
				     CH_AUTO_WIDTH ||
				     PhyDSSSTable->Chanflag.ChnlWidth ==
				     CH_40_MHz_WIDTH)) {

				/** add OBSS Scan Parameter here here **/
					if (skb_tailroom(txSkb_p) >
					    14
					    /** len of OBSS Scan Parameter IE **/
					     + 2) {
						IEEEtypes_OVERLAP_BSS_SCAN_PARAMETERS_Element_t
							*pOverLapBSS;
						extern UINT16
							AddOverlap_BSS_Scan_Parameters_IE
							(vmacApInfo_t *
							 vmacSta_p,
							 IEEEtypes_OVERLAP_BSS_SCAN_PARAMETERS_Element_t
							 * pNextElement);

						pOverLapBSS =
							(IEEEtypes_OVERLAP_BSS_SCAN_PARAMETERS_Element_t
							 *) skb_put(txSkb_p,
								    14
								    /** len of OBSS Scan Parameter IE **/
								     + 2);
						memset((void *)pOverLapBSS, 0,
						       14
						       /** len of OBSS Scan Parameter IE **/
						        + 2);
						AddOverlap_BSS_Scan_Parameters_IE
							(vmacSta_p,
							 pOverLapBSS);

					} else if (skb_headroom(txSkb_p) >
						   14
						   /** len of OBSS Scan Parameter IE **/
						    + 2) {
						IEEEtypes_OVERLAP_BSS_SCAN_PARAMETERS_Element_t
							*pOverLapBSS;
						extern UINT16
							AddOverlap_BSS_Scan_Parameters_IE
							(vmacApInfo_t *
							 vmacSta_p,
							 IEEEtypes_OVERLAP_BSS_SCAN_PARAMETERS_Element_t
							 * pNextElement);

						//we have enough at the head
						memcpy(&tempbuffer[0],
						       &txSkb_p->data[0],
						       txSkb_p->len);
						pOverLapBSS =
							(IEEEtypes_OVERLAP_BSS_SCAN_PARAMETERS_Element_t
							 *) &
							tempbuffer[txSkb_p->
								   len];
						AddOverlap_BSS_Scan_Parameters_IE
							(vmacSta_p,
							 pOverLapBSS);
						memset(&txSkb_p->data[0], 0,
						       txSkb_p->len);
						skb_push(txSkb_p,
							 14
							 /** len of OBSS Scan Parameter IE **/
							  + 2);
						memcpy(&txSkb_p->data[0],
						       &tempbuffer[0],
						       txSkb_p->len);
					} else {
						WLDBG_INFO(DBG_LEVEL_7,
							   "panic!!!!in OBSS Scan parameter buffer alloc");
					}

				/** add Extended Cap IE here **/
					if (skb_tailroom(txSkb_p) >
					    sizeof
					    (IEEEtypes_Extended_Cap_Element_t))
					{
						extern UINT16
							AddExtended_Cap_IE
							(vmacApInfo_t *
							 vmacSta_p,
							 IEEEtypes_Extended_Cap_Element_t
							 * pNextElement);
						IEEEtypes_Extended_Cap_Element_t
							*pExtCap;

						pExtCap =
							(IEEEtypes_Extended_Cap_Element_t
							 *) skb_put(txSkb_p,
								    sizeof
								    (IEEEtypes_Extended_Cap_Element_t));
						memset((void *)pExtCap, 0,
						       sizeof
						       (IEEEtypes_Extended_Cap_Element_t));
						AddExtended_Cap_IE(vmacSta_p,
								   pExtCap);
						addedExtcap = TRUE;

					} else if (skb_headroom(txSkb_p) >
						   sizeof
						   (IEEEtypes_Extended_Cap_Element_t))
					{
						IEEEtypes_Extended_Cap_Element_t
							*pExtCap;
						extern UINT16
							AddExtended_Cap_IE
							(vmacApInfo_t *
							 vmacSta_p,
							 IEEEtypes_Extended_Cap_Element_t
							 * pNextElement);

						//we have enough at the head
						memcpy(&tempbuffer[0],
						       &txSkb_p->data[0],
						       txSkb_p->len);
						pExtCap =
							(IEEEtypes_Extended_Cap_Element_t
							 *) &
							tempbuffer[txSkb_p->
								   len];
						AddExtended_Cap_IE(vmacSta_p,
								   pExtCap);
						memset(&txSkb_p->data[0], 0,
						       txSkb_p->len);
						skb_push(txSkb_p,
							 sizeof
							 (IEEEtypes_Extended_Cap_Element_t));
						memcpy(&txSkb_p->data[0],
						       &tempbuffer[0],
						       txSkb_p->len);
						addedExtcap = TRUE;
					} else {
						WLDBG_INFO(DBG_LEVEL_7,
							   "panic!!!!in extended Cap IE buffer alloc");
					}

				}
			}
#ifdef WLS_FTM_SUPPORT
			if (*(vmacSta_p->ShadowMib802dot11->wls_ftm_enable) ==
			    1) {
				extern UINT16 AddRRM_Cap_IE(vmacApInfo_t *
							    vmacSta_p,
							    IEEEtypes_RM_Enable_Capabilities_Element_t
							    * pNextElement);
				IEEEtypes_RM_Enable_Capabilities_Element_t
					*pRMElement;
				if (skb_tailroom(txSkb_p) >
				    sizeof
				    (IEEEtypes_RM_Enable_Capabilities_Element_t))
				{
					pRMElement =
						(IEEEtypes_RM_Enable_Capabilities_Element_t
						 *) skb_put(txSkb_p,
							    sizeof
							    (IEEEtypes_RM_Enable_Capabilities_Element_t));
					AddRRM_Cap_IE(vmacSta_p, pRMElement);
				} else if (skb_headroom(txSkb_p) >
					   sizeof
					   (IEEEtypes_RM_Enable_Capabilities_Element_t))
				{
					//we have enough at the head
					memcpy(&tempbuffer[0],
					       &txSkb_p->data[0], txSkb_p->len);
					pRMElement =
						(IEEEtypes_RM_Enable_Capabilities_Element_t
						 *) & tempbuffer[txSkb_p->len];
					AddRRM_Cap_IE(vmacSta_p, pRMElement);
					memset(&txSkb_p->data[0], 0,
					       txSkb_p->len);
					skb_push(txSkb_p,
						 sizeof
						 (IEEEtypes_RM_Enable_Capabilities_Element_t));
					memcpy(&txSkb_p->data[0],
					       &tempbuffer[0], txSkb_p->len);
				} else
					printk("[%s]: panic!!!!in Radio Measurement IE buffer alloc \n", __FUNCTION__);
			}
#endif

			/*Always add Extended Cap if in 5Ghz and VHT mode to pass wifi vht operating mode test */
			if (!addedExtcap &&
			    Is5GBand(*(vmacSta_p->Mib802dot11->mib_ApMode)) &&
			    ((*(vmacSta_p->Mib802dot11->mib_ApMode) &
			      AP_MODE_11AX) ||
			     (*(vmacSta_p->Mib802dot11->mib_ApMode) &
			      AP_MODE_11AC))) {
			/** add Extended Cap IE here **/
				if (skb_tailroom(txSkb_p) >
				    sizeof(IEEEtypes_Extended_Cap_Element_t)) {
					extern UINT16
						AddExtended_Cap_IE(vmacApInfo_t
								   * vmacSta_p,
								   IEEEtypes_Extended_Cap_Element_t
								   *
								   pNextElement);
					IEEEtypes_Extended_Cap_Element_t
						*pExtCap;

					pExtCap =
						(IEEEtypes_Extended_Cap_Element_t
						 *) skb_put(txSkb_p,
							    sizeof
							    (IEEEtypes_Extended_Cap_Element_t));
					memset((void *)pExtCap, 0,
					       sizeof
					       (IEEEtypes_Extended_Cap_Element_t));
					AddExtended_Cap_IE(vmacSta_p, pExtCap);
				} else if (skb_headroom(txSkb_p) >
					   sizeof
					   (IEEEtypes_Extended_Cap_Element_t)) {
					IEEEtypes_Extended_Cap_Element_t
						*pExtCap;
					extern UINT16
						AddExtended_Cap_IE(vmacApInfo_t
								   * vmacSta_p,
								   IEEEtypes_Extended_Cap_Element_t
								   *
								   pNextElement);

					//we have enough at the head
					memcpy(&tempbuffer[0],
					       &txSkb_p->data[0], txSkb_p->len);
					pExtCap =
						(IEEEtypes_Extended_Cap_Element_t
						 *) & tempbuffer[txSkb_p->len];
					AddExtended_Cap_IE(vmacSta_p, pExtCap);
					memset(&txSkb_p->data[0], 0,
					       txSkb_p->len);
					skb_push(txSkb_p,
						 sizeof
						 (IEEEtypes_Extended_Cap_Element_t));
					memcpy(&txSkb_p->data[0],
					       &tempbuffer[0], txSkb_p->len);
				} else {
					WLDBG_INFO(DBG_LEVEL_7,
						   "panic!!!!in extended Cap IE buffer alloc");
				}
			}

		}
#endif

#ifdef SOC_W906X
		/* Shrink EXT_CAP_IE from 11 bytes to 8 bytes for assoc_rsp for non-HE STA */
		if (!he_cap_present || !(*(mib->mib_ApMode) & AP_MODE_11AX)) {
			extern void *FindIEWithinIEs(UINT8 * data_p,
						     UINT32 lenPacket,
						     UINT8 attrib, UINT8 * OUI);
			UINT8 ie_len = 0;
			UINT32 len_before_supprates =
				sizeof(MgmtRsp_p->Body.AssocRsp.CapInfo) +
				sizeof(MgmtRsp_p->Body.AssocRsp.StatusCode) +
				sizeof(MgmtRsp_p->Body.AssocRsp.AId);
			UINT8 *ie =
				FindIEWithinIEs(txSkb_p->data +
						sizeof(MgmtRsp_p->Hdr) +
						len_before_supprates,
						txSkb_p->len -
						sizeof(MgmtRsp_p->Hdr) -
						len_before_supprates,
						EXT_CAP_IE, NULL);
			if (ie) {
				ie_len = *((UINT8 *) (ie + 1));
				if (ie_len == 11) {	/* 11 = sizeof(IEEEtypes_Extended_Cap_Element_t) - 2 */
					UINT8 *ie_end = ie + 2 + ie_len;
					UINT8 *ie_end_new = ie_end - (11 - 8);
					memmove(ie_end_new, ie_end,
						skb_tail_pointer(txSkb_p) -
						ie_end);
					*(ie + 1) = 8;
					txSkb_p->tail -= (11 - 8);
					txSkb_p->len -= (11 - 8);
				}
			}
		}
#endif
		//add 11ac IEs
		if (*(vmacSta_p->Mib802dot11->mib_ApMode) & AP_MODE_11AC) {
			if (IE191Present) {
				if (skb_tailroom(txSkb_p) >
				    sizeof(IEEEtypes_VhtCap_t)) {
					//We have enough room at the tail
					IE_p = skb_put(txSkb_p,
						       sizeof
						       (IEEEtypes_VhtCap_t));
					if (IE_p != NULL) {
						UINT8 vhtRxNss =
							StaInfo_p->
							vht_peer_RxNss;
						UINT8 isEffective = 0;

						if (IE199Present)
							vhtRxNss =
								min(StaInfo_p->
								    vht_peer_RxNss,
								    vht_RxNss_IE199);
						if (wlpptr->devid == SCBT) {
							if (vhtRxNss > 4)
								vhtRxNss = 4;
							if (vhtRxNss < 3)
								vhtRxNss = 3;
						}
						isEffective = (!he_cap_present
							       && vhtRxNss);
						Build_IE_191(vmacSta_p,
							     (UINT8 *) IE_p,
							     isEffective,
							     vhtRxNss);
					}
				} else {
					printk("Assoc Response not enough space for IE191\n");
					WLDBG_INFO(DBG_LEVEL_7, "panic!!!!");
				}

			}

			if (IE199Present && !IE191Present &&
			    !Is5GBand(*(vmacSta_p->Mib802dot11->mib_ApMode))) {
				if (skb_tailroom(txSkb_p) >
				    sizeof(IEEEtypes_VhtCap_t)) {
					//We have enough room at the tail
					IE_p = skb_put(txSkb_p,
						       sizeof
						       (IEEEtypes_VhtCap_t));
					if (IE_p != NULL) {
						UINT8 vhtRxNss = 8;
						UINT8 isEffective = 0;
						if (wlpptr->devid == SCBT)
							vhtRxNss = 4;
						isEffective = (!he_cap_present
							       && vhtRxNss);
						// append vht cap in assoc resp when STA has IE199 in assoc req
						Build_IE_191(vmacSta_p,
							     (UINT8 *) IE_p,
							     isEffective,
							     vhtRxNss);
						if (!VendorSpecVHTPresent) {
							// generate STA vht cap from STA IE199
							memcpy(&StaInfo_p->
							       vhtCap,
							       (UINT8 *) IE_p,
							       sizeof
							       (IEEEtypes_VhtCap_t));
							vhtRxNss =
								min(vhtRxNss,
								    vht_RxNss_IE199);
							switch (vhtRxNss) {
							case 1:
								StaInfo_p->
									vhtCap.
									SupportedTxMcsSet
									=
									0xfffe;
								StaInfo_p->
									vhtCap.
									SupportedRxMcsSet
									=
									0xfffe;
								break;
							case 2:
								StaInfo_p->
									vhtCap.
									SupportedTxMcsSet
									=
									0xfffa;
								StaInfo_p->
									vhtCap.
									SupportedRxMcsSet
									=
									0xfffa;
								break;
							case 3:
								StaInfo_p->
									vhtCap.
									SupportedTxMcsSet
									=
									0xffea;
								StaInfo_p->
									vhtCap.
									SupportedRxMcsSet
									=
									0xffea;
								break;
							case 4:
								StaInfo_p->
									vhtCap.
									SupportedTxMcsSet
									=
									0xffaa;
								StaInfo_p->
									vhtCap.
									SupportedRxMcsSet
									=
									0xffaa;
								break;
							case 5:
								StaInfo_p->
									vhtCap.
									SupportedTxMcsSet
									=
									0xfeaa;
								StaInfo_p->
									vhtCap.
									SupportedRxMcsSet
									=
									0xfeaa;
								break;
							case 6:
								StaInfo_p->
									vhtCap.
									SupportedTxMcsSet
									=
									0xfaaa;
								StaInfo_p->
									vhtCap.
									SupportedRxMcsSet
									=
									0xfaaa;
								break;
							case 7:
								StaInfo_p->
									vhtCap.
									SupportedTxMcsSet
									=
									0xeaaa;
								StaInfo_p->
									vhtCap.
									SupportedRxMcsSet
									=
									0xeaaa;
								break;
							case 8:
								StaInfo_p->
									vhtCap.
									SupportedTxMcsSet
									=
									0xaaaa;
								StaInfo_p->
									vhtCap.
									SupportedRxMcsSet
									=
									0xaaaa;
								break;
							default:
								printk("Invalid RxNSS: %u\n", vhtRxNss);
								break;
							}
							PeerInfo.vht_MaxRxMcs =
								StaInfo_p->
								vhtCap.
								SupportedRxMcsSet;
							memcpy((UINT8 *) &
							       PeerInfo.vht_cap,
							       (UINT8 *) &
							       StaInfo_p->
							       vhtCap.cap,
							       sizeof
							       (IEEEtypes_VHT_Cap_Info_t));
						}
					}
				}
			}

			if (IE191Present || IE192Present) {
				if (skb_tailroom(txSkb_p) >
				    sizeof(IEEEtypes_VhOpt_t)) {
					//We have enough room at the tail
					IE_p = skb_put(txSkb_p,
						       sizeof
						       (IEEEtypes_VhOpt_t));
					if (IE_p != NULL)
						Build_IE_192(vmacSta_p,
							     (UINT8 *) IE_p);
				} else {
					printk("Assoc Response not enough space for IE192\n");
					WLDBG_INFO(DBG_LEVEL_7, "panic!!!!");
				}

			}
		}
#ifdef SOC_W906X
		/* add 11ax IEs */
		if (*(vmacSta_p->Mib802dot11->mib_ApMode) & AP_MODE_11AX) {
			if (he_cap_present) {
				/*If there is a VHT OP IE in the associate request,
				   use the peer's VHT OP IE to decide its RX channel width.
				   Otherwise, use the peer's HE CAP IE. */
				if (!IE192Present) {
					if (PhyDSSSTable->Chanflag.FreqBand ==
					    FREQ_BAND_2DOT4GHZ) {
						if (PeerInfo.he_cap.phy_cap.
						    channel_width_set &
						    HE_SUPPORT_40MHZ_BW_24G)
							PeerInfo.
								vht_RxChannelWidth
								= 1;
						else
							PeerInfo.
								vht_RxChannelWidth
								= 0;
					} else {
						if (PeerInfo.he_cap.phy_cap.
						    channel_width_set &
						    HE_SUPPORT_160MHZ_BW_5G)
							PeerInfo.
								vht_RxChannelWidth
								= 3;
						else if (PeerInfo.he_cap.
							 phy_cap.
							 channel_width_set &
							 HE_SUPPORT_40_80MHZ_BW_5G)
							PeerInfo.
								vht_RxChannelWidth
								= 2;
						else
							PeerInfo.
								vht_RxChannelWidth
								= 0;
					}
				}

				printk("PeerInfo.vht_RxChannelWidth %d\n",
				       PeerInfo.vht_RxChannelWidth);
				if (skb_tailroom(txSkb_p) >
				    sizeof(HE_Capabilities_IE_t)) {
					/* We have enough room at the tail */
					IE_p = skb_tail_pointer(txSkb_p);

					if (IE_p != NULL) {
						memcpy((void *)IE_p,
						       (void *)&vmacSta_p->
						       he_cap,
						       vmacSta_p->he_cap.hdr.
						       Len +
						       sizeof
						       (IEEEtypes_InfoElementHdr_t));
						skb_put(txSkb_p,
							vmacSta_p->he_cap.hdr.
							Len +
							sizeof
							(IEEEtypes_InfoElementHdr_t));
					}
				} else {
					printk("Assoc Response not enough space for HE CAP IE\n");
					WLDBG_INFO(DBG_LEVEL_7, "panic!!!!");
				}

				if (skb_tailroom(txSkb_p) >
				    sizeof(HE_Operation_IE_t)) {
					/* We have enough room at the tail */
					IE_p = skb_tail_pointer(txSkb_p);

					if (IE_p != NULL)
						skb_put(txSkb_p,
							Build_IE_HE_OP
							(vmacSta_p,
							 (UINT8 *) IE_p,
							 IE192Present));
				} else {
					printk("Assoc Response not enough space for HE OP IE\n");
					WLDBG_INFO(DBG_LEVEL_7, "panic!!!!");
				}
				if (vmacSta_p->VMacEntry.muedcaEnable) {
					/* We have enough room at the tail */
					IE_p = skb_tail_pointer(txSkb_p);

					if (IE_p != NULL)
						skb_put(txSkb_p,
							Build_IE_MU_EDCA
							(vmacSta_p,
							 (UINT8 *) IE_p));
					else
						printk("Error: no space in skb for mu edca ie\n");
				}

				if (skb_tailroom(txSkb_p) >
				    sizeof(SRP_param_set_t)) {
					/* We have enough room at the tail */
					IE_p = skb_tail_pointer(txSkb_p);

					if (IE_p != NULL)
						skb_put(txSkb_p,
							Build_IE_SRP(vmacSta_p,
								     (UINT8 *)
								     IE_p));
				} else {
					printk("Assoc Response not enough space for Spatial Reuse Parameter Set IE\n");
					WLDBG_INFO(DBG_LEVEL_7, "panic!!!!");
				}

				if (vmacSta_p->he_cap.rx_he_mcs_80m.
				    max_mcs_set >
				    PeerInfo.he_cap.tx_he_mcs_80m.max_mcs_set) {
					PeerInfo.he_cap.tx_he_mcs_80m.
						max_mcs_set =
						vmacSta_p->he_cap.rx_he_mcs_80m.
						max_mcs_set;
				}

				if ((vmacSta_p->he_cap.phy_cap.
				     channel_width_set &
				     HE_SUPPORT_160MHZ_BW_5G) &&
				    (PeerInfo.he_cap.phy_cap.
				     channel_width_set &
				     HE_SUPPORT_160MHZ_BW_5G)) {
					if ((&vmacSta_p->he_cap.rx_he_mcs_80m +
					     2)->max_mcs_set >
					    (&PeerInfo.he_cap.tx_he_mcs_80m +
					     2)->max_mcs_set) {
						(&PeerInfo.he_cap.
						 tx_he_mcs_80m +
						 2)->max_mcs_set =
				       (&vmacSta_p->he_cap.rx_he_mcs_80m +
					2)->max_mcs_set;
					}

					if ((vmacSta_p->he_cap.phy_cap.
					     channel_width_set &
					     HE_SUPPORT_80P80MHZ_BW_5G) &&
					    (PeerInfo.he_cap.phy_cap.
					     channel_width_set &
					     HE_SUPPORT_80P80MHZ_BW_5G)) {
						if ((&vmacSta_p->he_cap.
						     rx_he_mcs_80m +
						     4)->max_mcs_set >
						    (&PeerInfo.he_cap.
						     tx_he_mcs_80m +
						     4)->max_mcs_set) {
							(&PeerInfo.he_cap.
							 tx_he_mcs_80m +
							 4)->max_mcs_set =
					       (&vmacSta_p->he_cap.
						rx_he_mcs_80m + 4)->max_mcs_set;
						}
						if (PeerInfo.
						    vht_RxChannelWidth == 3) {
							StaInfo_p->
								operating_mode.
								rxnss =
								get_he_peer_nss
								(&PeerInfo.
								 he_cap.
								 rx_he_mcs_80m +
								 4);
							StaInfo_p->
								operating_mode.
								tx_nsts =
								get_he_peer_nss
								(&PeerInfo.
								 he_cap.
								 tx_he_mcs_80m +
								 4);
						} else {
							StaInfo_p->
								operating_mode.
								rxnss =
								get_he_peer_nss
								(&PeerInfo.
								 he_cap.
								 rx_he_mcs_80m);
							StaInfo_p->
								operating_mode.
								tx_nsts =
								get_he_peer_nss
								(&PeerInfo.
								 he_cap.
								 tx_he_mcs_80m);
						}

					} else {
						if (PeerInfo.
						    vht_RxChannelWidth == 3) {
							StaInfo_p->
								operating_mode.
								rxnss =
								get_he_peer_nss
								(&PeerInfo.
								 he_cap.
								 rx_he_mcs_80m +
								 2);
							StaInfo_p->
								operating_mode.
								tx_nsts =
								get_he_peer_nss
								(&PeerInfo.
								 he_cap.
								 tx_he_mcs_80m +
								 2);
						} else {
							StaInfo_p->
								operating_mode.
								rxnss =
								get_he_peer_nss
								(&PeerInfo.
								 he_cap.
								 rx_he_mcs_80m);
							StaInfo_p->
								operating_mode.
								tx_nsts =
								get_he_peer_nss
								(&PeerInfo.
								 he_cap.
								 tx_he_mcs_80m);
						}
					}
				} else {
					StaInfo_p->operating_mode.rxnss =
						get_he_peer_nss(&PeerInfo.
								he_cap.
								rx_he_mcs_80m);
					StaInfo_p->operating_mode.tx_nsts =
						get_he_peer_nss(&PeerInfo.
								he_cap.
								tx_he_mcs_80m);
				}

				StaInfo_p->operating_mode.chbw =
					PeerInfo.vht_RxChannelWidth;
				StaInfo_p->operating_mode.ulmu_disable = 0;
			}
		}
#endif /* SOC_W906X */

		if ((StaInfo_p->StaType & 0x02) == 0x02) {
			if (skb_tailroom(txSkb_p) > 38 + 2) {
				//We have enough room at the tail
				InfoElemHdr_p =
					(IEEEtypes_InfoElementHdr_t *)
					skb_put(txSkb_p, 38 + 2);
				AddM_Rptr_IE(vmacSta_p,
					     (IEEEtypes_HT_Element_t *)
					     InfoElemHdr_p);
			} else if (skb_headroom(txSkb_p) > 38 + 2) {
				//we have enough at the head
				memcpy(&tempbuffer[0], &txSkb_p->data[0],
				       txSkb_p->len);
				InfoElemHdr_p =
					(IEEEtypes_InfoElementHdr_t *) &
					tempbuffer[txSkb_p->len];
				AddM_Rptr_IE(vmacSta_p,
					     (IEEEtypes_HT_Element_t *)
					     InfoElemHdr_p);
				memset(&txSkb_p->data[0], 0, txSkb_p->len);
				skb_push(txSkb_p, 38 + 2);
				memcpy(&txSkb_p->data[0], &tempbuffer[0],
				       txSkb_p->len);
			} else {
				WLDBG_INFO(DBG_LEVEL_7, "panic!!!!");

			}
		}
#ifdef MULTI_AP_SUPPORT
		if ((MultiAP_IE_p != NULL) && mib->multi_ap_attr) {
			//add Multi-AP IE
			if (skb_tailroom(txSkb_p) > MultiAP_size) {
				//We have enough room at the tail
				InfoElemHdr_p =
					(IEEEtypes_InfoElementHdr_t *)
					skb_put(txSkb_p, MultiAP_size);
				Add_MultiAP_IE(vmacSta_p, InfoElemHdr_p,
					       WL_WLAN_TYPE_AP);
			} else if (skb_headroom(txSkb_p) > MultiAP_size) {
				//we have enough at the head
				memcpy(&tempbuffer[0], &txSkb_p->data[0],
				       txSkb_p->len);
				InfoElemHdr_p =
					(IEEEtypes_InfoElementHdr_t *) &
					tempbuffer[txSkb_p->len];
				Add_MultiAP_IE(vmacSta_p, InfoElemHdr_p,
					       WL_WLAN_TYPE_AP);
				memset(&txSkb_p->data[0], 0, txSkb_p->len);
				skb_push(txSkb_p, MultiAP_size);
				memcpy(&txSkb_p->data[0], &tempbuffer[0],
				       txSkb_p->len);
			}
		}
#endif /*MULTI_AP_SUPPORT */

#ifdef MRVL_WPS2
		if (vmacSta_p->WPSOn) {
			if (skb_tailroom(txSkb_p) > sizeof(AssocResp_WSCIE_t)) {
				//We have enough room at the tail
				IE_p = skb_put(txSkb_p,
					       sizeof(AssocResp_WSCIE_t));
				if (IE_p != NULL)
					Build_AssocResp_WSCIE(vmacSta_p,
							      (AssocResp_WSCIE_t
							       *) IE_p);
			} else {
				printk("Assoc Response not enough space for WSC IE\n");
				WLDBG_INFO(DBG_LEVEL_7, "panic!!!!");
			}
		}
#endif

		//put here temporally foo
#ifdef UAPSD_SUPPORT
		if (pWMEInfoElem != NULL) {
			memcpy(&QosInfo, &pWMEInfoElem->QoS_info, 1);
		}
#endif

		PeerInfo.assocRSSI = StaInfo_p->assocRSSI;
#ifdef SOC_W906X
#ifdef MULTI_AP_SUPPORT
		if (StaInfo_p->MultiAP_4addr && mib->multi_ap_attr) {
			wds = 4;
		}
#endif /* MULTI_AP_SUPPORT */
#ifdef CB_SUPPORT
		StaInfo_p->Qosinfo = QosInfo;
		memcpy(&StaInfo_p->PeerInfo, &PeerInfo, sizeof(PeerInfo_t));
#endif //CB_SUPPORT
		StaInfo_p->FwStaPtr = wlFwSetNewStn(vmacSta_p->dev, (u_int8_t *) & MgmtMsg_p->Hdr.SrcAddr, Aid, StaInfo_p->StnId, StaInfoDbActionAddEntry, &PeerInfo, QosInfo, isQosSta, wds);	//add new station
#else
#ifdef MULTI_AP_SUPPORT
		if (StaInfo_p->MultiAP_4addr && mib->multi_ap_attr) {
			wlFwSetNewStn(vmacSta_p->dev, (u_int8_t *) & MgmtMsg_p->Hdr.SrcAddr, 0, 0, 2, NULL, 0, 0, 4);	//del station first
		} else
#endif /* MULTI_AP_SUPPORT */
		{
			wlFwSetNewStn(vmacSta_p->dev, (u_int8_t *) & MgmtMsg_p->Hdr.SrcAddr, 0, 0, 2, NULL, 0, 0, 0);	//del station first
		}

		StaInfo_p->StnId = AssignStnId(vmacSta_p);
		//only if get a valid stnid then set sta to fw
		if (StaInfo_p->StnId) {
#ifdef MULTI_AP_SUPPORT
			if (StaInfo_p->MultiAP_4addr && mib->multi_ap_attr) {
				StaInfo_p->FwStaPtr = wlFwSetNewStn(vmacSta_p->dev, (u_int8_t *) & MgmtMsg_p->Hdr.SrcAddr, Aid, StaInfo_p->StnId, 0, &PeerInfo, QosInfo, isQosSta, 4);	//add new station     
			} else
#endif /* MULTI_AP_SUPPORT */
			{
				StaInfo_p->FwStaPtr = wlFwSetNewStn(vmacSta_p->dev, (u_int8_t *) & MgmtMsg_p->Hdr.SrcAddr, Aid, StaInfo_p->StnId, 0, &PeerInfo, QosInfo, isQosSta, 0);	//add new station     
			}
		}
#endif /* SOC_W906X */
		wlFwSetSecurity(vmacSta_p->dev,
				(u_int8_t *) & MgmtMsg_p->Hdr.SrcAddr);
#ifdef NPROTECTION
		extStaDb_entries(vmacSta_p, 0);
		HandleNProtectionMode(vmacSta_p);
#endif

#ifdef MRVL_WAPI
		/* inform wapid that wapi-sta associated (need to attach wie) */
		if (mib_PrivacyTable_p->WAPIEnabled)
			macMgmtMlme_WAPI_event(vmacSta_p->dev, IWEVASSOCREQIE,
					       0x00F1, &MgmtMsg_p->Hdr.SrcAddr,
					       &MgmtMsg_p->Hdr.DestAddr,
					       (char *)WAPI_IE_p);
#endif

		WLSYSLOG(vmacSta_p->dev, WLSYSLOG_CLASS_ALL,
			 WLSYSLOG_MSG_MLME_ASSOC_SUCCESS
			 "%02x%02x%02x%02x%02x%02x StnId=%d\n",
			 MgmtMsg_p->Hdr.SrcAddr[0], MgmtMsg_p->Hdr.SrcAddr[1],
			 MgmtMsg_p->Hdr.SrcAddr[2], MgmtMsg_p->Hdr.SrcAddr[3],
			 MgmtMsg_p->Hdr.SrcAddr[4], MgmtMsg_p->Hdr.SrcAddr[5],
			 StaInfo_p->StnId);

#ifdef MBO_SUPPORT
		if ((mib->mib_mbo_enabled) &&
		    (skb_tailroom(txSkb_p) > StaInfo_p->AP_MBOIEBuf[1] + 2)) {
			//We have enough room at the tail
			IE_p = skb_put(txSkb_p, StaInfo_p->AP_MBOIEBuf[1] + 2);
			if (IE_p != NULL) {
				memcpy(IE_p, &StaInfo_p->AP_MBOIEBuf[0],
				       StaInfo_p->AP_MBOIEBuf[1] + 2);
			}
		}
#endif /* MBO_SUPPORT */

#ifdef OWE_SUPPORT
		/* OWE mode, adds the Diffie-Hellman Parameter element to association response. */
		if (((vmacSta_p->Mib802dot11->WPA2AuthSuites->AuthSuites[3]) ==
		     0x12)) {
			if (skb_tailroom(txSkb_p) >
			    StaInfo_p->AP_DHIEBuf[1] + 2) {
				//We have enough room at the tail
				IE_p = skb_put(txSkb_p,
					       StaInfo_p->AP_DHIEBuf[1] + 2);
				if (IE_p != NULL) {
					memcpy(IE_p, &StaInfo_p->AP_DHIEBuf[0],
					       StaInfo_p->AP_DHIEBuf[1] + 2);
				}
			}

			if (StaInfo_p->EXT_RsnIE[0] == RSN_IEWPA2 &&
			    (StaInfo_p->EXT_RsnIE[1] + 2) <= 64 &&
			    skb_tailroom(txSkb_p) >
			    (StaInfo_p->EXT_RsnIE[1] + 2)) {
				IE_p = skb_put(txSkb_p,
					       StaInfo_p->EXT_RsnIE[1] + 2);
				if (IE_p != NULL)
					memcpy(IE_p, &StaInfo_p->EXT_RsnIE[0],
					       StaInfo_p->EXT_RsnIE[1] + 2);
			}
		}
#endif /* OWE_SUPPORT */

		/* Send for tx (send assoc event to upper layer first, then xmit assoc-resp) */
#ifdef MRVL_80211R
		if (assoc_pending && (*(mib->mib_wpaWpa2Mode) > 3)) {
			StaInfo_p->keyMgmtStateInfo.pending_assoc = 1;
			StaInfo_p->keyMgmtStateInfo.assoc = txSkb_p;
			StaInfo_p->keyMgmtStateInfo.reassoc = flag;
#if defined (MBO_SUPPORT) || defined (OWE_SUPPORT)
			if (StaInfo_p->assocReq_skb == NULL)
#endif /* defined (MBO_SUPPORT) || defined (OWE_SUPPORT) */
				pending_assoc_start_timer(StaInfo_p);
		} else
#endif
		{
			if (txMgmtMsg(vmacSta_p->dev, txSkb_p) != OS_SUCCESS)
				wl_free_skb(txSkb_p);

			cleanupAmpduTx(vmacSta_p, (UINT8 *) & StaInfo_p->Addr);
		}

		/*Delay to prevent EAPOL key sent out before assoc resp. Certain client may not like it and send Deauth, causing assoc failure */
		mdelay(1);

		if (wfa_11ax_pf && vmacSta_p->master) {
			if (vmacSta_p->master->dl_ofdma_para.postpone_time) {
				wlFwSetOfdma_Mode(vmacSta_p->master->dev,
						  0,
						  vmacSta_p->master->
						  dl_ofdma_para.ru_mode,
						  vmacSta_p->master->
						  dl_ofdma_para.max_delay,
						  vmacSta_p->master->
						  dl_ofdma_para.max_sta);
				vmacSta_p->master->dl_ofdma_para.started = 0;
			}
		}

		/* Send event to user space (hostapd) */
		WLSNDEVT(vmacSta_p->dev, IWEVREGISTERED,
			 &MgmtMsg_p->Hdr.SrcAddr, NULL);
#ifdef CFG80211
#ifdef CFG80211_COMPATIABLE
#ifdef MRVL_80211R
		if ((flag) && (StaInfo_p->keyMgmtStateInfo.pending_assoc))
			mwl_send_vendor_assoc_event(vmacSta_p->dev,
						    (uint8_t *) & MgmtMsg_p->
						    Hdr.SrcAddr);
		else
#endif /* MRVL_80211R */
			mwl_cfg80211_assoc_event(vmacSta_p->dev,
						 (uint8_t *) & MgmtMsg_p->Hdr.
						 SrcAddr);
#else
#ifdef SOC_W906X
#ifdef MRVL_80211R
		if ((flag) && (StaInfo_p->keyMgmtStateInfo.pending_assoc))
			mwl_send_vendor_assoc_event(vmacSta_p->dev,
						    (uint8_t *) & MgmtMsg_p->
						    Hdr.SrcAddr);
		else
#endif /* MRVL_80211R */
			mwl_cfg80211_assoc_event(vmacSta_p->dev,
						 (uint8_t *) & MgmtMsg_p->Hdr.
						 SrcAddr);
#else
		mwl_send_vendor_assoc_event(vmacSta_p->dev,
					    (uint8_t *) & MgmtMsg_p->Hdr.
					    SrcAddr);
#endif //SOC_W906X
#endif /* CFG80211_COMPATIABLE */
#endif /* CFG80211 */
		if (reconfig_rsn_ie == TRUE) {
			memcpy(StaInfo_p->keyMgmtStateInfo.RsnIEBuf,
			       mib->thisStaRsnIEWPA2, 14);
			StaInfo_p->keyMgmtStateInfo.RsnIEBuf[1] = 0x0C;
		}
#ifdef MULTI_AP_SUPPORT
		if ((mib->multi_ap_attr & MAP_ATTRIBUTE_FRONTHAUL_BSS) ||
		    (mib->multi_ap_attr & MAP_ATTRIBUTE_BACKHAUL_BSS)) {
			snprintf(buf, sizeof(buf), "%s", tag);
			if (MgmtMsg_p->Hdr.FrmCtl.Subtype ==
			    IEEE_MSG_ASSOCIATE_RQST) {
				event_len =
					strlen(tag) +
					sizeof(struct multiap_sta_assoc_event) +
					IELen;
				if (event_len <= IW_CUSTOM_MAX) {
					multiap_sta_assoc_p =
						(struct multiap_sta_assoc_event
						 *)(buf + strlen(tag));
					multiap_sta_assoc_p->ie_len =
						IELen +
						sizeof(struct
						       multiap_sta_assoc_event)
						-
						sizeof(multiap_sta_assoc_p->
						       ie_len);
					multiap_sta_assoc_p->FrmCtl =
						MgmtMsg_p->Hdr.FrmCtl;
					multiap_sta_assoc_p->Duration =
						MgmtMsg_p->Hdr.Duration;
					memcpy(multiap_sta_assoc_p->DestAddr,
					       MgmtMsg_p->Hdr.DestAddr,
					       sizeof(IEEEtypes_MacAddr_t));
					memcpy(multiap_sta_assoc_p->SrcAddr,
					       MgmtMsg_p->Hdr.SrcAddr,
					       sizeof(IEEEtypes_MacAddr_t));
					memcpy(multiap_sta_assoc_p->BssId,
					       MgmtMsg_p->Hdr.BssId,
					       sizeof(IEEEtypes_MacAddr_t));
					multiap_sta_assoc_p->SeqCtl =
						MgmtMsg_p->Hdr.SeqCtl;
					multiap_sta_assoc_p->CapInfo =
						MgmtMsg_p->Body.AssocRqst.
						CapInfo;
					multiap_sta_assoc_p->ListenInterval =
						MgmtMsg_p->Body.AssocRqst.
						ListenInterval;
					memcpy(multiap_sta_assoc_p->more_ies,
					       IEBuf, IELen);
					memset(&wreq, 0, sizeof(wreq));
					wreq.data.length = event_len;
					if (vmacSta_p->dev->flags & IFF_RUNNING)
						wireless_send_event(vmacSta_p->
								    dev,
								    IWEVCUSTOM,
								    &wreq, buf);
				}
			} else if (MgmtMsg_p->Hdr.FrmCtl.Subtype ==
				   IEEE_MSG_REASSOCIATE_RQST) {
				event_len =
					strlen(tag) +
					sizeof(struct multiap_sta_reassoc_event)
					+ IELen;
				if (event_len <= IW_CUSTOM_MAX) {
					multiap_sta_reassoc_p =
						(struct
						 multiap_sta_reassoc_event
						 *)(buf + strlen(tag));
					multiap_sta_reassoc_p->ie_len =
						IELen +
						sizeof(struct
						       multiap_sta_reassoc_event)
						-
						sizeof(multiap_sta_reassoc_p->
						       ie_len);
					multiap_sta_reassoc_p->FrmCtl =
						MgmtMsg_p->Hdr.FrmCtl;
					multiap_sta_reassoc_p->Duration =
						MgmtMsg_p->Hdr.Duration;
					memcpy(multiap_sta_reassoc_p->DestAddr,
					       MgmtMsg_p->Hdr.DestAddr,
					       sizeof(IEEEtypes_MacAddr_t));
					memcpy(multiap_sta_reassoc_p->SrcAddr,
					       MgmtMsg_p->Hdr.SrcAddr,
					       sizeof(IEEEtypes_MacAddr_t));
					memcpy(multiap_sta_reassoc_p->BssId,
					       MgmtMsg_p->Hdr.BssId,
					       sizeof(IEEEtypes_MacAddr_t));
					multiap_sta_reassoc_p->SeqCtl =
						MgmtMsg_p->Hdr.SeqCtl;
					multiap_sta_reassoc_p->CapInfo =
						MgmtMsg_p->Body.ReassocRqst.
						CapInfo;
					multiap_sta_reassoc_p->ListenInterval =
						MgmtMsg_p->Body.ReassocRqst.
						ListenInterval;
					memcpy(multiap_sta_reassoc_p->
					       CurrentApAddr,
					       MgmtMsg_p->Body.ReassocRqst.
					       CurrentApAddr,
					       sizeof(IEEEtypes_MacAddr_t));
					memcpy(multiap_sta_reassoc_p->more_ies,
					       IEBuf, IELen);
					memset(&wreq, 0, sizeof(wreq));
					wreq.data.length = event_len;
					if (vmacSta_p->dev->flags & IFF_RUNNING)
						wireless_send_event(vmacSta_p->
								    dev,
								    IWEVCUSTOM,
								    &wreq, buf);
				}
			}
#if defined(SOC_W906X) && defined(CFG80211)
			mwl_send_vendor_assoc_notification(vmacSta_p->dev,
							   (uint8_t *) &
							   MgmtMsg_p->Hdr.
							   SrcAddr,
							   (void *)&StaInfo_p->
							   assocReqMsg,
							   MgmtRsp_p->Body.
							   AssocRsp.StatusCode);
#endif /* SOC_W906X */
		}
#endif /* MULTI_AP_SUPPORT */

		/* Key Management initialized here due to station state synchronization. */
		if (mib_PrivacyTable_p->RSNEnabled) {
			if (*(mib->mib_wpaWpa2Mode) < 4) {	/* MRV_8021X For all PSK modes use internal WPA state machine */
				/* Delay to start key exchange state machine */
				/* default is defined in wldebug.c. Can be adjusted by command "iwpriv wdevx setcmd "debug eapol_m1_delay set val" */
				mdelay(debug_m1_delay);

				/*Initialize the keyMgmt state machine */
				KeyMgmtHskCtor(vmacSta_p, StaInfo_p);
				mhsm_initialize(&StaInfo_p->keyMgmtHskHsm.super,
						&StaInfo_p->keyMgmtHskHsm.sTop);
				//Process Key Management msg 
				keyMgmt_msg(vmacSta_p, pDistMsg);
			}
		}

		StaInfo_p->CapInfo = PeerInfo.CapInfo;
		if (!StaInfo_p->CapInfo.ShortPreamble &&
		    ChangeAssocParam == TRUE)
			macMgmtMlme_IncrBarkerPreambleStnCnt(vmacSta_p);

		if (!gRatePresent) {
			if (ChangeAssocParam == TRUE)
				macMgmtMlme_IncrBonlyStnCnt(vmacSta_p, 0);

			StaInfo_p->ClientMode = BONLY_MODE;
		}
#ifndef SOC_W906X
		local_irq_enable();
#endif

		sendLlcExchangeID(vmacSta_p->dev, &MgmtMsg_p->Hdr.SrcAddr);

#if defined(MRV_8021X) && !defined(ENABLE_WLSNDEVT)
		if (*(mib->mib_wpaWpa2Mode) > 3) {	/* All 8021x modes with external Authenticator */
			memset(&wreq, 0, sizeof(wreq));
			memcpy(wreq.addr.sa_data, &MgmtMsg_p->Hdr.SrcAddr, 6);
			wreq.addr.sa_family = ARPHRD_ETHER;
			if (vmacSta_p->dev->flags & IFF_RUNNING)
				wireless_send_event(vmacSta_p->dev,
						    IWEVREGISTERED, &wreq,
						    NULL);
#ifdef CFG80211
#ifdef CFG80211_COMPATIABLE
			mwl_cfg80211_assoc_event(vmacSta_p->dev,
						 &MgmtMsg_p->Hdr.SrcAddr);
#else
#ifdef SOC_W906X
			mwl_cfg80211_assoc_event(vmacSta_p->dev,
						 &MgmtMsg_p->Hdr.SrcAddr);
#else
			mwl_send_vendor_assoc_event(vmacSta_p->dev,
						    &MgmtMsg_p->Hdr.SrcAddr);
#endif //SOC_W906X
#endif /* CFG80211_COMPATIABLE */
#endif /* CFG80211 */
		}
#endif

#ifdef INTOLERANT40
		if (*(vmacSta_p->Mib802dot11->mib_HT40MIntoler)) {
			if (HTpresent) {
				/* Start 30 min timeer */
				sMonitorcnt30min = 1;

				macMgmtMlme_SendBeaconReqMeasureReqAction
					(vmacSta_p->dev,
					 (IEEEtypes_MacAddr_t *) MgmtMsg_p->Hdr.
					 SrcAddr);
				/* handle 40-20 switch */
				if ((PeerInfo.HTCapabilitiesInfo.
				     FortyMIntolerant) ||
				    (!StaInfo_p->HtElem.HTCapabilitiesInfo.
				     SupChanWidth)) {
					HT40MIntolerantHandler(vmacSta_p, 1);
					//printk("Assc:HT\n");
				}
			} else {
				HT40MIntolerantHandler(vmacSta_p, 1);
				//printk("Assc:Legacy\n");
			}
		}
#endif //#ifdef INTOLERANT40

		/*Copy rate table rateinfo from fw to txRateHistogram so we can update counter correctly in SU */
#ifdef SOC_W906X
		if (StaInfo_p->StnId < sta_num) {
			if ((txrate_histo_p =
			     (WLAN_TX_RATE_HIST *)
			     wl_kmalloc_autogfp(sizeof(WLAN_TX_RATE_HIST))) !=
			    NULL) {
				memset(txrate_histo_p, 0,
				       sizeof(WLAN_TX_RATE_HIST));
				if (wlpptr->wlpd_p->
				    txRateHistogram[StaInfo_p->StnId] != NULL) {
					wl_kfree(wlpptr->wlpd_p->
						 txRateHistogram[StaInfo_p->
								 StnId]);
					wlpptr->wlpd_p->
						txRateHistogram[StaInfo_p->
								StnId] = NULL;
				}

				wlpptr->wlpd_p->txRateHistogram[StaInfo_p->
								StnId] =
					txrate_histo_p;
				wlAcntCopyRateTbl(vmacSta_p->dev, (UINT8 *) & MgmtMsg_p->Hdr.SrcAddr, StaInfo_p->StnId, SU_MIMO);	//SU for now
			} else
				printk("staid:%d alloc WLAN_TX_RATE_HIST memory FAIL\n", StaInfo_p->StnId);

			if (wlpptr->wlpd_p->scheHistogram[StaInfo_p->StnId] !=
			    NULL)
				memset(wlpptr->wlpd_p->
				       scheHistogram[StaInfo_p->StnId], 0,
				       sizeof(WLAN_SCHEDULER_HIST));
			else {
				if ((sch_histo_p =
				     (WLAN_SCHEDULER_HIST *)
				     wl_kmalloc_autogfp(sizeof
							(WLAN_SCHEDULER_HIST)))
				    != NULL) {
					memset(sch_histo_p, 0,
					       sizeof(WLAN_SCHEDULER_HIST));
					wlpptr->wlpd_p->
						scheHistogram[StaInfo_p->
							      StnId] =
						sch_histo_p;
				} else
					printk("staid:%d alloc WLAN_SCHEDULER_HIST memory FAIL\n", StaInfo_p->StnId);
			}
		}
#else
		if ((StaInfo_p->StnId > 0) && (StaInfo_p->StnId <= sta_num)) {
			if ((txrate_histo_p =
			     (WLAN_TX_RATE_HIST *)
			     wl_kmalloc_autogfp(sizeof(WLAN_TX_RATE_HIST))) !=
			    NULL) {
				memset(txrate_histo_p, 0,
				       sizeof(WLAN_TX_RATE_HIST));

				SPIN_LOCK_IRQSAVE(&wlpptr->wlpd_p->
						  txRateHistoLock[StaInfo_p->
								  StnId - 1],
						  txRateHistoflags);

				if (wlpptr->wlpd_p->
				    txRateHistogram[StaInfo_p->StnId - 1] !=
				    NULL) {
					wl_kfree(wlpptr->wlpd_p->
						 txRateHistogram[StaInfo_p->
								 StnId - 1]);
					wlpptr->wlpd_p->
						txRateHistogram[StaInfo_p->
								StnId - 1] =
						NULL;
				}

				wlpptr->wlpd_p->txRateHistogram[StaInfo_p->
								StnId - 1] =
					txrate_histo_p;
				wlAcntCopyRateTbl(vmacSta_p->dev, (UINT8 *) & MgmtMsg_p->Hdr.SrcAddr, StaInfo_p->StnId, SU_MIMO);	//SU for now

				SPIN_UNLOCK_IRQRESTORE(&wlpptr->wlpd_p->
						       txRateHistoLock
						       [StaInfo_p->StnId - 1],
						       txRateHistoflags);
			} else
				printk("staid:%d alloc WLAN_TX_RATE_HIST memory FAIL\n", StaInfo_p->StnId);
		}
#endif /* SOC_W906X */
		/*If station is MU mimo capable, add to MUStaList */

#ifdef SOC_W906X
#if 0
		if (ofdma_autogrp == 1) {
			printk("MUBeamformeeCapable:%u, Nss:%u\n",
			       StaInfo_p->vhtCap.cap.MUBeamformeeCapable,
			       StaInfo_p->vht_peer_RxNss);
		}
#endif

		if (ofdma_autogrp && StaInfo_p) {
			if ((is_he_capable_sta(StaInfo_p)) ||	/* add HE STA into list */
			    (*((UINT32 *) & StaInfo_p->vhtCap.cap) &&	/* add VHT MU BFmer capable STA into list */
			     StaInfo_p->vhtCap.cap.MUBeamformeeCapable &&
			     (StaInfo_p->vht_peer_RxNss < 3)))
				MUAddStaToMUStaList(vmacSta_p, StaInfo_p);

			if (ofdma_autogrp == 2) {
				int num = auto_group_ofdma_mu(vmacSta_p);
				printk("%d STAs are grouped\n", num);
			}

			/* If auto MU grouping is enabled, attempt the MU grouping since the MU STA list may be updated */
			if (*(vmacSta_p->Mib802dot11->mib_mumimo_mgmt))
				MUAutoSet_Hdlr(vmacSta_p->dev);
		}
#ifdef CCK_DESENSE
		/* enable CCK-desense */
		cck_desense_ctrl(wlpptr->master, CCK_DES_ASSOC_RSP);
#endif /* CCK_DESENSE */
#else
		if (StaInfo_p && *((UINT32 *) & StaInfo_p->vhtCap.cap) &&
		    StaInfo_p->vhtCap.cap.MUBeamformeeCapable &&
		    (StaInfo_p->vht_peer_RxNss < 3)) {

			MUAddStaToMUStaList(vmacSta_p, StaInfo_p);
		}
#endif /* SOC_W906X */

		return;

OUT:
#ifndef SOC_W906X
		local_irq_enable();
#endif

		return;

	}

/******************************************************************************
*
* Name: macMgmtMlme_ReassociateReq
*
* Description:
*    This routine handles the Reassociation Request from a Station
*
* Conditions For Use:
*    All software components have been initialized and started.
*
* Arguments:
*    Arg1 (i  ): MgmtMsg_p - Pointer to an 802.11 management message
*                            containing an associate response
*
* Return Value:
*    None.
*
* Notes:
*    None.
*
* PDL:
*        Check to see if the Station is already associated with this
*        AP. If so, change the association parameters and send a response.
*        if the station is unauthenticated, send error response.
*        if the station is 
*        Check if the state is authenticated
*        Check if the SSID matches with AP's SSID
*        Check if the Capability Info could be supported
*        Check if the Basic rates are in the Supported rates
*        Assign Aid and store the information
*        Send AssociateRsp message back 
* END PDL
*
*****************************************************************************/
	void macMgmtMlme_AssociateReq(vmacApInfo_t * vmacSta_p,
				      macmgmtQ_MgmtMsg3_t * MgmtMsg_p,
				      UINT32 msgSize) {
		macMgmtMlme_AssocReAssocReqHandler(vmacSta_p, MgmtMsg_p,
						   msgSize, 0);
	}

	extern void macMgmtMlme_ReassociateReq(vmacApInfo_t * vmacSta_p,
					       macmgmtQ_MgmtMsg3_t * MgmtMsg_p,
					       UINT32 msgSize) {
		macMgmtMlme_AssocReAssocReqHandler(vmacSta_p, MgmtMsg_p,
						   msgSize, 1);
	}

#ifdef MULTI_AP_SUPPORT
	struct multiap_sta_disassoc_event {
		IEEEtypes_MacAddr_t bssid;
		IEEEtypes_MacAddr_t sta_mac;
		UINT16 reason;
		UINT32 tx_packets;
		UINT32 rx_packets;
		UINT32 tx_failed;
		UINT32 tx_retries;
		UINT32 rx_dropped_misc;
		UINT64 tx_bytes;
		UINT64 rx_bytes;
	} PACK_END;
#endif /* MULTI_AP_SUPPORT */

#ifdef SOC_W906X
	void macMgmtMlme_SendDeauthenticateMsg(vmacApInfo_t * vmacAP_p,
					       IEEEtypes_MacAddr_t * Addr,
					       UINT16 StnId, UINT16 Reason,
					       UINT8 sendCmd)
#else
	void macMgmtMlme_SendDeauthenticateMsg(vmacApInfo_t * vmacAP_p,
					       IEEEtypes_MacAddr_t * Addr,
					       UINT16 StnId, UINT16 Reason)
#endif
	{
		vmacApInfo_t *vmacSta_p = vmacAP_p;
		MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
		macmgmtQ_MgmtMsg2_t *MgmtMsg_p;
		//      tx80211_MgmtMsg_t *TxMsg_p;
		extStaDb_StaInfo_t *StaInfo_p = NULL;
		IEEEtypes_MacAddr_t SrcMacAddr;
#ifdef AP_MAC_LINUX
		struct sk_buff *txSkb_p;
#endif
#ifdef MULTI_AP_SUPPORT
		static const char *tag = "1905D";
		struct multiap_sta_disassoc_event *disassoc_event_p;
		struct station_info *sinfo = NULL;
		unsigned char buf[IW_CUSTOM_MAX] = { 0 };
		union iwreq_data wreq;
#endif
#ifndef SOC_W906X
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev);
#endif

		/* Deauth pkt will be sent when data pkts received from STA not in our database
		   if(!IS_GROUP(Addr))
		   if ((StaInfo_p = extStaDb_GetStaInfo(vmacSta_p,Addr, STADB_UPDATE_AGINGTIME)) == NULL)
		   {
		   return;
		   } */
		/*No need to send out any deauth if interface is down */
		if (!(vmacSta_p->dev->flags & IFF_RUNNING))
			return;
#ifndef SOC_W906X
		/* Block any deauth during CAC period */
		if (wlpptr->wlpd_p->bStopBcnProbeResp &&
		    macMgmtMlme_DfsEnabled(vmacSta_p->dev))
			return;
#endif

		calculate_err_count(vmacAP_p->dev);

		if (*(mib->mib_ApMode) != AP_MODE_AandG) {
			if ((StaInfo_p =
			     extStaDb_GetStaInfo(vmacSta_p, Addr,
						 STADB_UPDATE_AGINGTIME)) ==
			    NULL)
				memcpy(SrcMacAddr, &vmacSta_p->macStaAddr,
				       sizeof(IEEEtypes_MacAddr_t));
			else {
#ifdef MBSS
				vmacApInfo_t *vmactem_p;
				vmactem_p =
					vmacGetMBssByAddr(vmacSta_p,
							  (UINT8
							   *) (&StaInfo_p->
							       Bssid[0]));
				if (vmactem_p)
					vmacSta_p = vmactem_p;
				mib = vmacSta_p->Mib802dot11;
#endif
				memcpy(SrcMacAddr, &vmacSta_p->macStaAddr,
				       sizeof(IEEEtypes_MacAddr_t));
			}
		} else {
			if ((StaInfo_p =
			     extStaDb_GetStaInfo(vmacSta_p, Addr,
						 STADB_UPDATE_AGINGTIME)) ==
			    NULL)
				memcpy(SrcMacAddr, &vmacSta_p->macStaAddr,
				       sizeof(IEEEtypes_MacAddr_t));
			else {
#ifdef MBSS
				vmacApInfo_t *vmactem_p;
				vmactem_p =
					vmacGetMBssByAddr(vmacSta_p,
							  (UINT8
							   *) (&StaInfo_p->
							       Bssid[0]));
				if (vmactem_p)
					vmacSta_p = vmactem_p;
				mib = vmacSta_p->Mib802dot11;
#endif
				if (StaInfo_p->ApMode == AONLY_MODE) {
					memcpy(SrcMacAddr,
					       &vmacSta_p->macStaAddr,
					       sizeof(IEEEtypes_MacAddr_t));
				} else {
					memcpy(SrcMacAddr,
					       &vmacSta_p->macStaAddr2,
					       sizeof(IEEEtypes_MacAddr_t));
				}
			}
		}
#ifdef AP_MAC_LINUX
		if ((txSkb_p =
		     mlmeApiPrepMgtMsg(IEEE_MSG_DEAUTHENTICATE, Addr,
				       &SrcMacAddr)) == NULL)
			return;
		//TxMsg_p = (tx80211_MgmtMsg_t *) txSkb_p->data;
		MgmtMsg_p = (macmgmtQ_MgmtMsg2_t *) ((UINT8 *) txSkb_p->data);
		/*WLSYSLOG(vmacSta_p->dev,WLSYSLOG_CLASS_ALL, WLSYSLOG_MSG_MLME_DEAUTH_TOSTA "%02x%02x%02x%02x%02x%02x Reason %d\n", ((unsigned char *)Addr)[0],
		   ((unsigned char *)Addr)[1], ((unsigned char *)Addr)[2], ((unsigned char *)Addr)[3], 
		   ((unsigned char *)Addr)[4], ((unsigned char *)Addr)[5], ENDIAN_SWAP16(Reason)); */
		if (net_ratelimit()) {
			printk(KERN_INFO "WLAN(%s): ", vmacSta_p->dev->name);
			printk(WLSYSLOG_MSG_MLME_DEAUTH_TOSTA
			       "%02x%02x%02x%02x%02x%02x Reason %d\n",
			       ((unsigned char *)Addr)[0],
			       ((unsigned char *)Addr)[1],
			       ((unsigned char *)Addr)[2],
			       ((unsigned char *)Addr)[3],
			       ((unsigned char *)Addr)[4],
			       ((unsigned char *)Addr)[5],
			       ENDIAN_SWAP16(Reason));
		}
		/* Send event to user space */
		if ((StaInfo_p =
		     extStaDb_GetStaInfo(vmacSta_p, Addr,
					 STADB_UPDATE_AGINGTIME)) != NULL) {
			WLSNDEVT(vmacSta_p->dev, IWEVEXPIRED, Addr, NULL);

#ifdef CFG80211
#ifdef CFG80211_COMPATIABLE
			mwl_cfg80211_disassoc_event(vmacSta_p->dev,
						    (uint8_t *) Addr);
#else
#ifdef SOC_W906X
			mwl_cfg80211_disassoc_event(vmacSta_p->dev,
						    (uint8_t *) Addr);
#else
			mwl_send_vendor_disassoc_event(vmacSta_p->dev,
						       (uint8_t *) Addr);
#endif //SOC_W906X
#endif /* CFG80211_COMPATIABLE */
#endif /* CFG80211 */
#endif
#ifdef MULTI_AP_SUPPORT
			if ((mib->multi_ap_attr & MAP_ATTRIBUTE_FRONTHAUL_BSS)
			    || (mib->
				multi_ap_attr & MAP_ATTRIBUTE_BACKHAUL_BSS)) {
#if defined(SOC_W906X) && defined(CFG80211)
				sinfo = wl_kzalloc(sizeof(struct station_info),
						   GFP_ATOMIC);
				if (sinfo)
					fillStaInfo(vmacSta_p->dev, sinfo,
						    StaInfo_p);
#endif /* SOC_W906X */

				snprintf(buf, sizeof(buf), "%s", tag);
				disassoc_event_p =
					(struct multiap_sta_disassoc_event
					 *)(buf + strlen(tag));
				memcpy(disassoc_event_p->bssid,
				       vmacSta_p->macBssId,
				       sizeof(IEEEtypes_MacAddr_t));
				memcpy(disassoc_event_p->sta_mac, Addr,
				       sizeof(IEEEtypes_MacAddr_t));
				disassoc_event_p->reason = Reason;
#ifdef CFG80211
				disassoc_event_p->tx_packets =
					(sinfo) ? sinfo->
					tx_packets : StaInfo_p->tx_packets;
				disassoc_event_p->rx_packets =
					(sinfo) ? sinfo->
					rx_packets : StaInfo_p->rx_packets;
				disassoc_event_p->tx_bytes =
					(sinfo) ? sinfo->tx_bytes : StaInfo_p->
					tx_bytes;
				disassoc_event_p->rx_bytes =
					(sinfo) ? sinfo->rx_bytes : StaInfo_p->
					rx_bytes;
				disassoc_event_p->tx_failed =
					(sinfo) ? sinfo->tx_failed : 0;
				disassoc_event_p->tx_retries =
					(sinfo) ? sinfo->tx_retries : 0;
				disassoc_event_p->rx_dropped_misc =
					(sinfo) ? sinfo->rx_dropped_misc : 0;
#endif
				memset(&wreq, 0, sizeof(wreq));
				wreq.data.length =
					strlen(tag) +
					sizeof(struct
					       multiap_sta_disassoc_event);

				if (vmacSta_p->dev->flags & IFF_RUNNING)
					wireless_send_event(vmacSta_p->dev,
							    IWEVCUSTOM, &wreq,
							    buf);

				if (sinfo) {
#if defined(SOC_W906X) && defined(CFG80211)
					mwl_send_vendor_disassoc_notification
						(vmacSta_p->dev,
						 (uint8_t *) Addr, sinfo,
						 Reason);
#endif /* SOC_W906X */
					wl_kfree(sinfo);
				}
			}
#endif /* MULTI_AP_SUPPORT */
		}

		{
#ifdef SOC_W906X
			skb_put(txSkb_p,
				sizeof(MgmtMsg_p->Body.Deauth.ReasonCode));
#endif
			MgmtMsg_p->Body.Deauth.ReasonCode = Reason;
			if (txMgmtMsg(vmacSta_p->dev, txSkb_p) != OS_SUCCESS)
				wl_free_skb(txSkb_p);
#ifdef CONFIG_IEEE80211W
			if (StaInfo_p)
				StaInfo_p->ptkCipherOuiType =
					CIPHER_OUI_TYPE_NONE;
#endif
			/*only remove sta entry when non-splitmac mode */
			if (vmacSta_p->wtp_info.mac_mode !=
			    WTP_MAC_MODE_SPLITMAC) {
				if ((StaInfo_p =
				     extStaDb_GetStaInfo(vmacSta_p, Addr,
							 STADB_UPDATE_AGINGTIME))
				    != NULL)
					wlFwSetAPUpdateTim(vmacSta_p->dev,
							   StaInfo_p->Aid,
							   RESETBIT);

#ifdef SOC_W906X
				if (sendCmd && StaInfo_p &&
				    StaInfo_p->State != UNAUTHENTICATED) {
#else
				if (StaInfo_p &&
				    StaInfo_p->State != UNAUTHENTICATED) {
#endif
					wlFwSetNewStn(vmacSta_p->dev,
						      (u_int8_t *) Addr, 0, 0,
						      StaInfoDbActionRemoveEntry,
						      NULL, 0, 0, 0);
					StaInfo_p->State = UNAUTHENTICATED;
				}
			}

		}
	}
/******************************************************************************
*
* Name: macMgmtMlme_DeauthenticateMsg
*
* Description:
*    This routine handles a deauthentication notification from another
*    station or an AP.
*
* Conditions For Use:
*    All software components have been initialized and started.
*
* Arguments:
*    Arg1 (i  ): MgmtMsg_p - Pointer to an 802.11 management message
*                            containing a deauthentication message
*
* Return Value:
*    None.
*
* Notes:
*    None.
*
* PDL:
*    Remove from the External Station Info data store the entry for the
*       station that sent the message
*    Send a deauthentication indication to the SME with the reason code
* END PDL
*
*****************************************************************************/
	void macMgmtMlme_DeauthenticateMsg(vmacApInfo_t * vmacSta_p,
					   macmgmtQ_MgmtMsg3_t * MgmtMsg_p,
					   UINT32 msgSize) {
		//      MIB_STA_CFG  *mib_StaCfg_p=vmacSta_p->Mib802dot11->StationConfig;
		extStaDb_StaInfo_t *StaInfo_p;
		MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
#ifdef MULTI_AP_SUPPORT
		static const char *tag = "1905D";
		struct multiap_sta_disassoc_event *disassoc_event_p;
		struct station_info *sinfo = NULL;
		unsigned char buf[IW_CUSTOM_MAX] = { 0 };
		union iwreq_data wreq;
#endif
		if ((StaInfo_p =
		     extStaDb_GetStaInfo(vmacSta_p, &(MgmtMsg_p->Hdr.SrcAddr),
					 STADB_DONT_UPDATE_AGINGTIME)) ==
		    NULL) {
			/* Station not known, do nothing */
			return;
		}

		calculate_err_count(vmacSta_p->dev);

#ifdef QOS_FEATURE_REMOVE
		if (*(mib->QoSOptImpl) &&
		    extStaDb_GetQoSOptn(vmacSta_p,
					(IEEEtypes_MacAddr_t *) MgmtMsg_p->Hdr.
					SrcAddr)) {
			ClearQoSDB((IEEEtypes_MacAddr_t *) MgmtMsg_p->Hdr.
				   SrcAddr);
		}
#endif

		wlFwSetAPUpdateTim(vmacSta_p->dev, StaInfo_p->Aid, RESETBIT);
#ifdef CONFIG_IEEE80211W
		TimerDisarm(&StaInfo_p->SA_Query_Timer);
#endif
		/* free aid when sta state not associated 2 */
		FreeAid(vmacSta_p, StaInfo_p->Aid);
		StaInfo_p->Aid = 0;
		if (StaInfo_p->State == ASSOCIATED) {
#ifdef ENABLE_RATE_ADAPTATION_BASEBAND_REMOVE
			UpdateAssocStnData(StaInfo_p->Aid, StaInfo_p->ApMode);
#endif //ENABLE_RATE_ADAPTATION_BASEBAND
			cleanupAmpduTx(vmacSta_p, (UINT8 *) & StaInfo_p->Addr);
			/* remove the Mac address from the ethernet MAC address table */
			if (StaInfo_p->ClientMode == BONLY_MODE)
				macMgmtMlme_DecrBonlyStnCnt(vmacSta_p, 0);

			if (!StaInfo_p->CapInfo.ShortPreamble)
				macMgmtMlme_DecrBarkerPreambleStnCnt(vmacSta_p);

			if (StaInfo_p->PwrMode == PWR_MODE_PWR_SAVE) {
				if (vmacSta_p->PwrSaveStnCnt)
					vmacSta_p->PwrSaveStnCnt--;
				StaInfo_p->PwrMode = PWR_MODE_ACTIVE;

			}
		}
		StaInfo_p->State = UNAUTHENTICATED;
#ifdef WIFI_DATA_OFFLOAD
		{
			struct wlprivate *wlpptr =
				NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev);

			dol_sta_data_ctrl(wlpptr,
					  wlpptr->wlpd_p->ipc_session_id,
					  wlpptr->vmacSta_p->VMacEntry.macId,
					  StaInfo_p->StnId,
					  (u8 *) StaInfo_p->Addr, false);
		}
#endif
		StaInfo_p->mu_sta = 0;

#ifdef MULTI_AP_SUPPORT
		if ((mib->multi_ap_attr & MAP_ATTRIBUTE_FRONTHAUL_BSS) ||
		    (mib->multi_ap_attr & MAP_ATTRIBUTE_BACKHAUL_BSS)) {
#if defined(SOC_W906X) && defined(CFG80211)
			sinfo = wl_kzalloc(sizeof(struct station_info),
					   GFP_ATOMIC);
			if (sinfo)
				fillStaInfo(vmacSta_p->dev, sinfo, StaInfo_p);
#endif /* SOC_W906X */

			snprintf(buf, sizeof(buf), "%s", tag);
			disassoc_event_p =
				(struct multiap_sta_disassoc_event *)(buf +
								      strlen
								      (tag));
			memcpy(disassoc_event_p->bssid, vmacSta_p->macBssId,
			       sizeof(IEEEtypes_MacAddr_t));
			memcpy(disassoc_event_p->sta_mac, StaInfo_p->Addr,
			       sizeof(IEEEtypes_MacAddr_t));
			disassoc_event_p->reason =
				MgmtMsg_p->Body.Deauth.ReasonCode;
#ifdef CFG80211
			disassoc_event_p->tx_packets =
				(sinfo) ? sinfo->tx_packets : StaInfo_p->
				tx_packets;
			disassoc_event_p->rx_packets =
				(sinfo) ? sinfo->rx_packets : StaInfo_p->
				rx_packets;
			disassoc_event_p->tx_bytes =
				(sinfo) ? sinfo->tx_bytes : StaInfo_p->tx_bytes;
			disassoc_event_p->rx_bytes =
				(sinfo) ? sinfo->rx_bytes : StaInfo_p->rx_bytes;
			disassoc_event_p->tx_failed =
				(sinfo) ? sinfo->tx_failed : 0;
			disassoc_event_p->tx_retries =
				(sinfo) ? sinfo->tx_retries : 0;
			disassoc_event_p->rx_dropped_misc =
				(sinfo) ? sinfo->rx_dropped_misc : 0;
#endif
			memset(&wreq, 0, sizeof(wreq));
			wreq.data.length =
				strlen(tag) +
				sizeof(struct multiap_sta_disassoc_event);

			if (vmacSta_p->dev->flags & IFF_RUNNING)
				wireless_send_event(vmacSta_p->dev, IWEVCUSTOM,
						    &wreq, buf);

			if (sinfo) {
#if defined(SOC_W906X) && defined(CFG80211)
				mwl_send_vendor_disassoc_notification
					(vmacSta_p->dev,
					 (uint8_t *) & MgmtMsg_p->Hdr.SrcAddr,
					 sinfo,
					 MgmtMsg_p->Body.Deauth.ReasonCode);
#endif /* SOC_W906X */
				wl_kfree(sinfo);
			}
		}
#endif /* MULTI_AP_SUPPORT */

		//   FreePowerSaveQueue(StaInfo_p->StnId);
		FreeStnId(vmacSta_p, StaInfo_p->StnId);
		extStaDb_DelSta(vmacSta_p, &(MgmtMsg_p->Hdr.SrcAddr),
				STADB_DONT_UPDATE_AGINGTIME);
		wlFwSetNewStn(vmacSta_p->dev,
			      (u_int8_t *) & MgmtMsg_p->Hdr.SrcAddr,
			      StaInfo_p->Aid, StaInfo_p->StnId,
			      StaInfoDbActionRemoveEntry, NULL, 0, 0, 0);
		/* Send event to user space */
		WLSNDEVT(vmacSta_p->dev, IWEVEXPIRED, &MgmtMsg_p->Hdr.SrcAddr,
			 NULL);
#ifdef CFG80211
#ifdef CFG80211_COMPATIABLE
		mwl_cfg80211_disassoc_event(vmacSta_p->dev,
					    (uint8_t *) & MgmtMsg_p->Hdr.
					    SrcAddr);
#else
#ifdef SOC_W906X
		mwl_cfg80211_disassoc_event(vmacSta_p->dev,
					    (uint8_t *) & MgmtMsg_p->Hdr.
					    SrcAddr);
#else
		mwl_send_vendor_disassoc_event(vmacSta_p->dev,
					       (uint8_t *) & MgmtMsg_p->Hdr.
					       SrcAddr);
#endif //#ifdef SOC_W906X
#endif /* CFG80211_COMPATIABLE */
#endif /* CFG80211 */

		/* No need to free the Station Id, if there are any
		 * messages already queued, they  will not be removed*/
		/* Send indication to SME */
	}

/******************************************************************************
*
* Name: macMgmtMlme_DisassociateCmd
*
* Description:
*    Routine to handle a command to carry out a disassociation with an AP.
*
* Conditions For Use:
*    All software components have been initialized and started.
*
* Arguments:
*    Arg1 (i  ): DisassocCmd_p - Pointer to a disassociate command
*
* Return Value:
*    None.
*
* Notes:
*    None.
*
* PDL:
*    If any of the given disassociation parameters are invalid Then
*       Send a disassociation confirmation to the SME with the failure status
*    End If
*
*    Send a disassociate message to the indicated station
*    Update the External Station Info data store if to indicate
*       AUTHENTICATED with the indicated station
*    Send a disassociation confirm message to the SME task with the result
*       code
* END PDL
*
*****************************************************************************/
	void macMgmtMlme_DisassociateCmd(vmacApInfo_t * vmacSta_p,
					 IEEEtypes_DisassocCmd_t *
					 DisassocCmd_p) {
		MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
		macmgmtQ_MgmtMsg2_t *MgmtMsg_p;
		extStaDb_StaInfo_t *StaInfo_p;
		IEEEtypes_MacAddr_t SrcMacAddr;
#ifdef AP_MAC_LINUX
		struct sk_buff *txSkb_p;
#endif

		if (IS_BROADCAST(&DisassocCmd_p->PeerStaAddr)) {
			return;
		}

		if ((StaInfo_p =
		     extStaDb_GetStaInfo(vmacSta_p, &DisassocCmd_p->PeerStaAddr,
					 STADB_DONT_UPDATE_AGINGTIME)) ==
		    NULL) {
			return;
		}
		StaInfo_p->State = AUTHENTICATED;

#ifdef WIFI_DATA_OFFLOAD
		{
			struct wlprivate *wlpptr =
				NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev);

			dol_sta_data_ctrl(wlpptr,
					  wlpptr->wlpd_p->ipc_session_id,
					  wlpptr->vmacSta_p->VMacEntry.macId,
					  StaInfo_p->StnId,
					  (u8 *) StaInfo_p->Addr, false);
		}
#endif

#ifdef FIX_LATER
		bcngen_UpdateBitInTim(StaInfo_p->Aid, RESETBIT);
#endif

		wlFwSetAPUpdateTim(vmacSta_p->dev, StaInfo_p->Aid, RESETBIT);
		cleanupAmpduTx(vmacSta_p, (UINT8 *) & StaInfo_p->Addr);

		FreeAid(vmacSta_p, StaInfo_p->Aid);
		StaInfo_p->Aid = 0;
		/* allocate buffer for message */

		if (*(mib->mib_ApMode) != AP_MODE_AandG) {
			memcpy(SrcMacAddr, &vmacSta_p->macStaAddr,
			       sizeof(IEEEtypes_MacAddr_t));
		} else {

			if (StaInfo_p->ApMode == AONLY_MODE) {
				memcpy(SrcMacAddr, &vmacSta_p->macStaAddr,
				       sizeof(IEEEtypes_MacAddr_t));
			} else {
				memcpy(SrcMacAddr, &vmacSta_p->macStaAddr2,
				       sizeof(IEEEtypes_MacAddr_t));
			}
		}

#ifdef QOS_FEATURE
		if (*(mib->QoSOptImpl) &&
		    extStaDb_GetQoSOptn(vmacSta_p,
					(IEEEtypes_MacAddr_t *) DisassocCmd_p->
					PeerStaAddr)) {
			ClearQoSDB((IEEEtypes_MacAddr_t *) DisassocCmd_p->
				   PeerStaAddr);
		}
#endif
#ifdef AP_MAC_LINUX
		if ((txSkb_p =
		     mlmeApiPrepMgtMsg(IEEE_MSG_DISASSOCIATE,
				       &DisassocCmd_p->PeerStaAddr,
				       &SrcMacAddr)) == NULL)
			return;
		MgmtMsg_p = (macmgmtQ_MgmtMsg2_t *) txSkb_p->data;
#else
		if ((TxMsg_p =
		     mlmeApiPrepMgtMsg(IEEE_MSG_DISASSOCIATE,
				       &DisassocCmd_p->PeerStaAddr,
				       &SrcMacAddr)) != NULL)
#endif
		{
			MgmtMsg_p->Body.DisAssoc.ReasonCode =
				DisassocCmd_p->Reason;
			if (txMgmtMsg(vmacSta_p->dev, txSkb_p) != OS_SUCCESS)
				wl_free_skb(txSkb_p);
		}
	}

#ifdef MULTI_AP_SUPPORT
	void macMgmtMlme_SendDisassociateMsg4MAP(vmacApInfo_t * vmacSta_p,
						 IEEEtypes_MacAddr_t * Addr,
						 UINT16 StnId, UINT16 Reason) {
		macmgmtQ_MgmtMsg2_t *MgmtMsg_p;
		extStaDb_StaInfo_t *StaInfo_p = { 0 };
		IEEEtypes_MacAddr_t SrcMacAddr;
		MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
#ifdef AP_MAC_LINUX
		struct sk_buff *txSkb_p;
#endif
#ifdef MULTI_AP_SUPPORT
		static const char *tag = "1905D";
		struct multiap_sta_disassoc_event *disassoc_event_p;
		struct station_info *sinfo = NULL;
		unsigned char buf[IW_CUSTOM_MAX] = { 0 };
		union iwreq_data wreq;
#endif
		if (!IS_GROUP((UINT8 *) Addr)) {
			if ((StaInfo_p =
			     extStaDb_GetStaInfo(vmacSta_p, Addr, 1)) == NULL) {
				return;
			}
#ifdef CONFIG_IEEE80211W
			StaInfo_p->ptkCipherOuiType = CIPHER_OUI_TYPE_NONE;
#endif
		}
		if (StaInfo_p) {
			if ((mib->multi_ap_attr & MAP_ATTRIBUTE_FRONTHAUL_BSS)
			    || (mib->
				multi_ap_attr & MAP_ATTRIBUTE_BACKHAUL_BSS)) {
#if defined(SOC_W906X) && defined(CFG80211)
				sinfo = wl_kzalloc(sizeof(struct station_info),
						   GFP_ATOMIC);
				if (sinfo)
					fillStaInfo(vmacSta_p->dev, sinfo,
						    StaInfo_p);
#endif /* SOC_W906X */

				snprintf(buf, sizeof(buf), "%s", tag);
				disassoc_event_p =
					(struct multiap_sta_disassoc_event
					 *)(buf + strlen(tag));
				memcpy(disassoc_event_p->bssid,
				       vmacSta_p->macBssId,
				       sizeof(IEEEtypes_MacAddr_t));
				memcpy(disassoc_event_p->sta_mac, Addr,
				       sizeof(IEEEtypes_MacAddr_t));
				disassoc_event_p->reason = Reason;
#ifdef CFG80211
				disassoc_event_p->tx_packets =
					(sinfo) ? sinfo->
					tx_packets : StaInfo_p->tx_packets;
				disassoc_event_p->rx_packets =
					(sinfo) ? sinfo->
					rx_packets : StaInfo_p->rx_packets;
				disassoc_event_p->tx_bytes =
					(sinfo) ? sinfo->tx_bytes : StaInfo_p->
					tx_bytes;
				disassoc_event_p->rx_bytes =
					(sinfo) ? sinfo->rx_bytes : StaInfo_p->
					rx_bytes;
				disassoc_event_p->tx_failed =
					(sinfo) ? sinfo->tx_failed : 0;
				disassoc_event_p->tx_retries =
					(sinfo) ? sinfo->tx_retries : 0;
				disassoc_event_p->rx_dropped_misc =
					(sinfo) ? sinfo->rx_dropped_misc : 0;
#endif
				memset(&wreq, 0, sizeof(wreq));
				wreq.data.length =
					strlen(tag) +
					sizeof(struct
					       multiap_sta_disassoc_event);

				if (vmacSta_p->dev->flags & IFF_RUNNING)
					wireless_send_event(vmacSta_p->dev,
							    IWEVCUSTOM, &wreq,
							    buf);

				if (sinfo) {
#if defined(SOC_W906X) && defined(CFG80211)
					mwl_send_vendor_disassoc_notification
						(vmacSta_p->dev,
						 (uint8_t *) Addr, sinfo,
						 Reason);
#endif /* SOC_W906X */
					wl_kfree(sinfo);
				}
			}
		}
		memcpy(SrcMacAddr, &vmacSta_p->macStaAddr,
		       sizeof(IEEEtypes_MacAddr_t));
		if ((txSkb_p =
		     mlmeApiPrepMgtMsg(IEEE_MSG_DISASSOCIATE, Addr,
				       &SrcMacAddr)) == NULL)
			return;
		MgmtMsg_p = (macmgmtQ_MgmtMsg2_t *) txSkb_p->data;
		{
			MgmtMsg_p->Body.DisAssoc.ReasonCode = Reason;
			if (txMgmtMsg(vmacSta_p->dev, txSkb_p) != OS_SUCCESS)
				wl_free_skb(txSkb_p);
		}
		WLSYSLOG(vmacSta_p->dev, WLSYSLOG_CLASS_ALL,
			 WLSYSLOG_MSG_MLME_DISASSOC_TOSTA
			 "%02x%02x%02x%02x%02x%02x Reason %d\n",
			 ((unsigned char *)Addr)[0], ((unsigned char *)Addr)[1],
			 ((unsigned char *)Addr)[2], ((unsigned char *)Addr)[3],
			 ((unsigned char *)Addr)[4], ((unsigned char *)Addr)[5],
			 Reason);
	}
#endif /* MULTI_AP_SUPPORT */

	void macMgmtMlme_SendDisassociateMsg(vmacApInfo_t * vmacSta_p,
					     IEEEtypes_MacAddr_t * Addr,
					     UINT16 StnId, UINT16 Reason) {
		macmgmtQ_MgmtMsg2_t *MgmtMsg_p;
		extStaDb_StaInfo_t *StaInfo_p = { 0 };
		IEEEtypes_MacAddr_t SrcMacAddr;
#ifdef AP_MAC_LINUX
		struct sk_buff *txSkb_p;
#endif
		if (!IS_GROUP((UINT8 *) Addr)) {
			if ((StaInfo_p =
			     extStaDb_GetStaInfo(vmacSta_p, Addr,
						 STADB_UPDATE_AGINGTIME)) ==
			    NULL) {
				return;
			}
		}
		memcpy(SrcMacAddr, &vmacSta_p->macStaAddr,
		       sizeof(IEEEtypes_MacAddr_t));
		if ((txSkb_p =
		     mlmeApiPrepMgtMsg(IEEE_MSG_DISASSOCIATE, Addr,
				       &SrcMacAddr)) == NULL)
			return;
		MgmtMsg_p = (macmgmtQ_MgmtMsg2_t *) txSkb_p->data;
		{
#ifdef SOC_W906X
			skb_put(txSkb_p,
				sizeof(MgmtMsg_p->Body.DisAssoc.ReasonCode));
#endif
			MgmtMsg_p->Body.DisAssoc.ReasonCode = Reason;
			if (txMgmtMsg(vmacSta_p->dev, txSkb_p) != OS_SUCCESS)
				wl_free_skb(txSkb_p);
		}
#ifdef CONFIG_IEEE80211W
		if (StaInfo_p)
			StaInfo_p->ptkCipherOuiType = CIPHER_OUI_TYPE_NONE;
#endif
		WLSYSLOG(vmacSta_p->dev, WLSYSLOG_CLASS_ALL,
			 WLSYSLOG_MSG_MLME_DISASSOC_TOSTA
			 "%02x%02x%02x%02x%02x%02x Reason %d\n",
			 ((unsigned char *)Addr)[0], ((unsigned char *)Addr)[1],
			 ((unsigned char *)Addr)[2], ((unsigned char *)Addr)[3],
			 ((unsigned char *)Addr)[4], ((unsigned char *)Addr)[5],
			 Reason);
		/* Send event to user space */
		WLSNDEVT(vmacSta_p->dev, IWEVEXPIRED, Addr, NULL);

#ifdef CFG80211
#ifdef CFG80211_COMPATIABLE
		mwl_cfg80211_disassoc_event(vmacSta_p->dev, (uint8_t *) Addr);
#else
#ifdef SOC_W906X
		mwl_cfg80211_disassoc_event(vmacSta_p->dev, (uint8_t *) Addr);
#else
		mwl_send_vendor_disassoc_event(vmacSta_p->dev,
					       (uint8_t *) Addr);
#endif //SOC_W906X
#endif /* CFG80211_COMPATIABLE */
#endif /* CFG80211 */
	}
#if defined(MRVL_80211R) || defined(OWE_SUPPORT) || defined(MBO_SUPPORT)
	void pending_assoc_timeout_handler(void *ctx) {
		extStaDb_StaInfo_t *sta_info = ctx;

#ifdef MRVL_80211R
		if (sta_info->keyMgmtStateInfo.pending_assoc) {
			printk("Free pending assoc skb...\n");
			sta_info->keyMgmtStateInfo.pending_assoc = 0;
			sta_info->keyMgmtStateInfo.reassoc = 0;
			if (sta_info->keyMgmtStateInfo.assoc) {
				wl_free_skb(sta_info->keyMgmtStateInfo.assoc);
				sta_info->keyMgmtStateInfo.assoc = NULL;
			}
		}
#endif /* MRVL_80211R */

#if defined(OWE_SUPPORT) || defined(MBO_SUPPORT)
		if (sta_info->assocReq_skb) {
			wl_free_skb(sta_info->assocReq_skb);
			sta_info->assocReq_skb = NULL;
		}
#endif /* defined(OWE_SUPPORT) || defined(MBO_SUPPORT) */
	}

	void pending_assoc_timer_add(extStaDb_StaInfo_t * sta_info,
				     UINT32 ticks) {
		TimerFireIn(&sta_info->mgtAssoc.timer, 1,
			    &pending_assoc_timeout_handler, (UINT8 *) sta_info,
			    ticks);
	}

	void pending_assoc_timer_del(extStaDb_StaInfo_t * sta_info) {
		TimerRemove(&sta_info->mgtAssoc.timer);
	}

	void pending_assoc_start_timer(extStaDb_StaInfo_t * sta_info) {
		TimerInit(&sta_info->mgtAssoc.timer);
		pending_assoc_timer_del(sta_info);
		pending_assoc_timer_add(sta_info, 10);
	}
#endif /* defined(MRVL_80211R) || defined(OWE_SUPPORT) || defined(MBO_SUPPORT) */

#ifdef MRVL_80211R
	void macMgmtMlme_SendAssocMsg(vmacApInfo_t * vmacAP_p,
				      IEEEtypes_MacAddr_t * staMac,
				      UINT8 * optie, UINT8 optie_len) {
		extStaDb_StaInfo_t *StaInfo_p;
		UINT8 *addr = (char *)staMac;
		struct sk_buff *skb, *newskb;

		if ((StaInfo_p =
		     extStaDb_GetStaInfo(vmacAP_p, staMac,
					 STADB_DONT_UPDATE_AGINGTIME)) ==
		    NULL) {
			printk("STA-%02x:%02x:%02x:%02x:%02x:%02x not found in StaDB [%s] \n", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], __func__);
			return;
		}

		if (!StaInfo_p->keyMgmtStateInfo.pending_assoc) {
			printk("no pending assoc...\n");
			return;
		}

		skb = StaInfo_p->keyMgmtStateInfo.assoc;

		if (skb_tailroom(skb) < optie_len) {
			newskb = wl_alloc_skb(skb->len + optie_len +
					      MIN_BYTES_HEADROOM);
			if (newskb == NULL) {
				printk("FAIL to alloc new SKB...\n");
				return;
			}
			skb_reserve(newskb, MIN_BYTES_HEADROOM);
			memcpy(newskb->data, skb->data, skb->len);
			skb_put(newskb, skb->len);
			//memcpy(skb_put(skb, optie_len), optie, optie_len);
			newskb->dev = skb->dev;
			wl_free_skb(skb);
			skb = newskb;
		}
		memcpy(skb_put(skb, optie_len), optie, optie_len);

		if (txMgmtMsg(vmacAP_p->dev, skb) != OS_SUCCESS) {
			wl_free_skb(skb);
		}

		cleanupAmpduTx(vmacAP_p, (UINT8 *) & StaInfo_p->Addr);

		pending_assoc_timer_del(StaInfo_p);
		StaInfo_p->keyMgmtStateInfo.pending_assoc = 0;
		StaInfo_p->keyMgmtStateInfo.assoc = NULL;

#if defined(OWE_SUPPORT) || defined(MBO_SUPPORT)
		if (StaInfo_p->assocReq_skb) {
			wl_free_skb(StaInfo_p->assocReq_skb);
			StaInfo_p->assocReq_skb = NULL;
		}
#endif /* defined(OWE_SUPPORT) || defined(MBO_SUPPORT) */
	}

	int macMgmtMlme_SendAuthenticateMsg(vmacApInfo_t * vmacAP_p,
					    IEEEtypes_MacAddr_t * staMac,
					    UINT16 seq, UINT16 status_code,
					    UINT8 * optie, UINT8 optie_len) {
		extStaDb_StaInfo_t *StaInfo_p;
		UINT8 *addr = (char *)staMac;
		macmgmtQ_MgmtMsg2_t *MgmtMsg_p;
		struct sk_buff *skb;

		if (!vmacAP_p->InfUpFlag)
			return -1;

		if ((StaInfo_p =
		     extStaDb_GetStaInfo(vmacAP_p, staMac,
					 STADB_DONT_UPDATE_AGINGTIME)) ==
		    NULL) {
			printk("STA-%02x:%02x:%02x:%02x:%02x:%02x not found in StaDB [%s]\n", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], __func__);
			return -1;
		}

		if ((skb =
		     mlmeApiPrepMgtMsg2(IEEE_MSG_AUTHENTICATE,
					(IEEEtypes_MacAddr_t *) staMac,
					(IEEEtypes_MacAddr_t *) vmacAP_p->
					macBssId, optie_len + 6)) == NULL) {
			WLDBG_INFO(DBG_LEVEL_8,
				   "Send Auth Failed, skb=NULL...\n");
			return -1;
		}
		MgmtMsg_p = (macmgmtQ_MgmtMsg2_t *) skb->data;
		memset(&MgmtMsg_p->Body.Auth, 0, optie_len + 6);
		MgmtMsg_p->Body.Auth.AuthAlg = ENDIAN_SWAP16(2);	//Only for FT case?
		MgmtMsg_p->Body.Auth.AuthTransSeq = ENDIAN_SWAP16(seq);
		MgmtMsg_p->Body.Auth.StatusCode = status_code;
		memcpy((UINT8 *) & MgmtMsg_p->Body.Auth.ChallengeText, optie,
		       optie_len);

		if (txMgmtMsg(vmacAP_p->dev, skb) != OS_SUCCESS)
			wl_free_skb(skb);

		return 0;
	}
#endif /* MRVL_80211R */

/******************************************************************************
*
* Name: macMgmtMlme_DisassociateMsg
*
* Description:
*    This routine handles a disassociation notification from an AP.
*
* Conditions For Use:
*    All software components have been initialized and started.
*
* Arguments:
*    Arg1 (i  ): MgmtMsg_p - Pointer to an 802.11 management message
*                            containing a disassociation message
*
* Return Value:
*    None.
*
* Notes:
*    None.
*
* PDL:
*    Update the External Station Info data store if to indicate
*       AUTHENTICATED with the AP that sent the message
*    Send a disassociation indication message to the SME task with the
*       reason code
* END PDL
*
*****************************************************************************/
	extern void macMgmtMlme_DisassociateMsg(vmacApInfo_t * vmacSta_p,
						macmgmtQ_MgmtMsg3_t * MgmtMsg_p,
						UINT32 msgSize) {
		extStaDb_StaInfo_t *StaInfo_p;
		MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
#ifdef MULTI_AP_SUPPORT
		static const char *tag = "1905D";
		struct multiap_sta_disassoc_event *disassoc_event_p;
		struct station_info *sinfo = NULL;
		unsigned char buf[IW_CUSTOM_MAX] = { 0 };
		union iwreq_data wreq;
#endif
		StaInfo_p =
			extStaDb_GetStaInfo(vmacSta_p,
					    &(MgmtMsg_p->Hdr.SrcAddr),
					    STADB_DONT_UPDATE_AGINGTIME);
		if (!StaInfo_p)
			return;

		calculate_err_count(vmacSta_p->dev);

		WLSYSLOG(vmacSta_p->dev, WLSYSLOG_CLASS_ALL,
			 WLSYSLOG_MSG_MLME_DISASSOC_FROMSTA
			 "%02x%02x%02x%02x%02x%02x\n",
			 MgmtMsg_p->Hdr.SrcAddr[0], MgmtMsg_p->Hdr.SrcAddr[1],
			 MgmtMsg_p->Hdr.SrcAddr[2], MgmtMsg_p->Hdr.SrcAddr[3],
			 MgmtMsg_p->Hdr.SrcAddr[4], MgmtMsg_p->Hdr.SrcAddr[5]);
#ifdef MULTI_AP_SUPPORT
		if ((mib->multi_ap_attr & MAP_ATTRIBUTE_FRONTHAUL_BSS) ||
		    (mib->multi_ap_attr & MAP_ATTRIBUTE_BACKHAUL_BSS)) {
#if defined(SOC_W906X) && defined(CFG80211)
			sinfo = wl_kzalloc(sizeof(struct station_info),
					   GFP_ATOMIC);
			if (sinfo)
				fillStaInfo(vmacSta_p->dev, sinfo, StaInfo_p);
#endif /* SOC_W906X */

			snprintf(buf, sizeof(buf), "%s", tag);
			disassoc_event_p =
				(struct multiap_sta_disassoc_event *)(buf +
								      strlen
								      (tag));
			memcpy(disassoc_event_p->bssid, vmacSta_p->macBssId,
			       sizeof(IEEEtypes_MacAddr_t));
			memcpy(disassoc_event_p->sta_mac, StaInfo_p->Addr,
			       sizeof(IEEEtypes_MacAddr_t));
			disassoc_event_p->reason =
				MgmtMsg_p->Body.DisAssoc.ReasonCode;
#ifdef CFG80211
			disassoc_event_p->tx_packets =
				(sinfo) ? sinfo->tx_packets : StaInfo_p->
				tx_packets;
			disassoc_event_p->rx_packets =
				(sinfo) ? sinfo->rx_packets : StaInfo_p->
				rx_packets;
			disassoc_event_p->tx_bytes =
				(sinfo) ? sinfo->tx_bytes : StaInfo_p->tx_bytes;
			disassoc_event_p->rx_bytes =
				(sinfo) ? sinfo->rx_bytes : StaInfo_p->rx_bytes;
			disassoc_event_p->tx_failed =
				(sinfo) ? sinfo->tx_failed : 0;
			disassoc_event_p->tx_retries =
				(sinfo) ? sinfo->tx_retries : 0;
			disassoc_event_p->rx_dropped_misc =
				(sinfo) ? sinfo->rx_dropped_misc : 0;
#endif
			memset(&wreq, 0, sizeof(wreq));
			wreq.data.length =
				strlen(tag) +
				sizeof(struct multiap_sta_disassoc_event);

			if (vmacSta_p->dev->flags & IFF_RUNNING)
				wireless_send_event(vmacSta_p->dev, IWEVCUSTOM,
						    &wreq, buf);

			if (sinfo) {
#if defined(SOC_W906X) && defined(CFG80211)
				mwl_send_vendor_disassoc_notification
					(vmacSta_p->dev,
					 (uint8_t *) & MgmtMsg_p->Hdr.SrcAddr,
					 sinfo,
					 MgmtMsg_p->Body.DisAssoc.ReasonCode);
#endif /* SOC_W906X */
				wl_kfree(sinfo);
			}
		}
#endif /* MULTI_AP_SUPPORT */

		/* Send event to user space */
		WLSNDEVT(vmacSta_p->dev, IWEVEXPIRED, &MgmtMsg_p->Hdr.SrcAddr,
			 NULL);
#ifdef CFG80211
#ifdef CFG80211_COMPATIABLE
		mwl_cfg80211_disassoc_event(vmacSta_p->dev,
					    (uint8_t *) & MgmtMsg_p->Hdr.
					    SrcAddr);
#else
#ifdef SOC_W906X
		mwl_cfg80211_disassoc_event(vmacSta_p->dev,
					    (uint8_t *) & MgmtMsg_p->Hdr.
					    SrcAddr);
#else
		mwl_send_vendor_disassoc_event(vmacSta_p->dev,
					       (uint8_t *) & MgmtMsg_p->Hdr.
					       SrcAddr);
#endif //SOC_W906X
#endif /* CFG80211_COMPATIABLE */
#endif /* CFG80211 */

#ifdef CONFIG_IEEE80211W
		TimerDisarm(&StaInfo_p->SA_Query_Timer);
#endif
		StaInfo_p->State = AUTHENTICATED;

#ifdef WIFI_DATA_OFFLOAD
		{
			struct wlprivate *wlpptr =
				NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev);

			dol_sta_data_ctrl(wlpptr,
					  wlpptr->wlpd_p->ipc_session_id,
					  wlpptr->vmacSta_p->VMacEntry.macId,
					  StaInfo_p->StnId,
					  (u8 *) StaInfo_p->Addr, false);
		}
#endif

		if (!StaInfo_p->Aid)
			return;

#ifdef ERP
		if (StaInfo_p->ClientMode == BONLY_MODE)
			macMgmtMlme_DecrBonlyStnCnt(vmacSta_p, 0);

		if (!StaInfo_p->CapInfo.ShortPreamble)
			macMgmtMlme_DecrBarkerPreambleStnCnt(vmacSta_p);

#endif
		if (StaInfo_p->State == ASSOCIATED) {
			/*Rate Adaptation Function. */
#ifdef ENABLE_RATE_ADAPTATION_BASEBAND_REMOVE
			UpdateAssocStnData(StaInfo_p->Aid, StaInfo_p->ApMode);
#endif /*ENABLE_RATE_ADAPTATION_BASEBAND */
		}
#ifdef QOS_FEATURE
		if (*(vmacSta_p->Mib802dot11->QoSOptImpl) &&
		    extStaDb_GetQoSOptn(vmacSta_p,
					(IEEEtypes_MacAddr_t *) MgmtMsg_p->Hdr.
					SrcAddr)) {
			ClearQoSDB((IEEEtypes_MacAddr_t *) MgmtMsg_p->Hdr.
				   SrcAddr);
		}
#endif

		/* remove the Mac address from the ethernet MAC address table */
#ifdef FIX_LATER		/* Remove for Sfly, may not be needed. */
		bcngen_UpdateBitInTim(StaInfo_p->Aid, RESETBIT);
#endif

		wlFwSetAPUpdateTim(vmacSta_p->dev, StaInfo_p->Aid, RESETBIT);
		cleanupAmpduTx(vmacSta_p, (UINT8 *) & StaInfo_p->Addr);
#ifndef SOC_W906X
		wlFwSetNewStn(vmacSta_p->dev, (u_int8_t *) & StaInfo_p->Addr,
			      StaInfo_p->Aid, StaInfo_p->StnId, 2, NULL, 0, 0,
			      0);
#endif

		FreeAid(vmacSta_p, StaInfo_p->Aid);
		StaInfo_p->Aid = 0;
#ifdef NPROTECTION
		extStaDb_entries(vmacSta_p, 0);
		HandleNProtectionMode(vmacSta_p);
#endif
		if (wfa_11ax_pf) {
			/* WFA 11ax PF: ofdma dl: */
			vmacApInfo_t *vmacSta_master_p;
			int i;

			vmacSta_master_p = vmacSta_p->master;
			if ((vmacSta_master_p->dl_ofdma_para.max_sta > 0) &&
			    (vmacSta_master_p->dl_ofdma_para.sta_cnt > 0)) {
				for (i = 0; i < MAX_OFDMADL_STA; i++) {
					if (!memcmp
					    (StaInfo_p->Addr,
					     vmacSta_master_p->
					     ofdma_mu_sta_addr[i],
					     IEEEtypes_ADDRESS_SIZE))
						break;
				}
				if (i < MAX_OFDMADL_STA) {
					/* sta exist in the BA resp list */

					vmacSta_master_p->dl_ofdma_para.
						sta_cnt--;
					memset(vmacSta_master_p->
					       ofdma_mu_sta_addr[i], 0,
					       IEEEtypes_ADDRESS_SIZE);
					//mwl_hex_dump(StaInfo_p->Addr, IEEEtypes_ADDRESS_SIZE);
					printk("Disasso: ofdma.sta_cnt=%d\n",
					       vmacSta_master_p->dl_ofdma_para.
					       sta_cnt);
				}

				if (!vmacSta_master_p->dl_ofdma_para.sta_cnt) {
					vmacSta_master_p->dl_ofdma_para.option =
						0;
					vmacSta_master_p->dl_ofdma_para.
						ru_mode = 0;
					vmacSta_master_p->dl_ofdma_para.
						max_delay = 0;
					printk("Set ofdma fw cmd: option=%d ru_mode=%d max_delay=%d max_sta=%d sta_cnt=%d\n", vmacSta_master_p->dl_ofdma_para.option, vmacSta_master_p->dl_ofdma_para.ru_mode, vmacSta_master_p->dl_ofdma_para.max_delay, vmacSta_master_p->dl_ofdma_para.max_sta, vmacSta_master_p->dl_ofdma_para.sta_cnt);
					wlFwSetOfdma_Mode(vmacSta_master_p->dev,
							  vmacSta_master_p->
							  dl_ofdma_para.option,
							  vmacSta_master_p->
							  dl_ofdma_para.ru_mode,
							  vmacSta_master_p->
							  dl_ofdma_para.
							  max_delay,
							  vmacSta_master_p->
							  dl_ofdma_para.
							  max_sta);
					vmacSta_master_p->dl_ofdma_para.
						started = 0;
				}
			}
			if (vmacSta_master_p->dl_ofdma_para.all_connected &&
			    (vmacSta_master_p->dl_ofdma_para.sta_cnt <
			     vmacSta_master_p->dl_ofdma_para.max_sta))
				vmacSta_master_p->dl_ofdma_para.all_connected =
					0;
		}
		/* Send indication to SME */
		/* remove sta entry in StaDb */
		macMgmtRemoveSta(vmacSta_p, StaInfo_p);

#ifdef CCK_DESENSE
		{
			/* enable CCK-desense */
			struct wlprivate *wlpptr =
				NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev);

			cck_desense_ctrl(wlpptr->master, CCK_DES_DISASSOC);
		}
#endif /* CCK_DESENSE */

	}

#ifdef CONFIG_IEEE80211W
	extern void *probeRequest_ParseAttribWithinFrame(macmgmtQ_MgmtMsg3_t *
							 mgtFrame_p,
							 UINT8 * data_p,
							 UINT8 attrib) {
		UINT32 lenPacket, lenOffset = 0;

		lenPacket = mgtFrame_p->Hdr.FrmBodyLen + 2;

		lenOffset += data_p - (UINT8 *) mgtFrame_p;

		while (lenOffset <= lenPacket) {
			if (*(IEEEtypes_ElementId_t *) data_p == attrib) {
				return data_p;
			}

			lenOffset += (2 + *((UINT8 *) (data_p + 1)));
			data_p += (2 + *((UINT8 *) (data_p + 1)));
		}
		return NULL;
	}
#endif /* CONFIG_IEEE80211W */

	void macMgmtMlme_UpdateProbeRspInfo(vmacApInfo_t * vmacSta_p,
					    UINT16 bcn_interval, UINT16 capinfo)
	{
		IEEEtypes_ProbeRsp_t *probersp_p;

		if (!vmacSta_p->probeRspBody.basic_ies)
			vmacSta_p->probeRspBody.basic_ies =
				wl_kmalloc(MAX_BEACON_SIZE, GFP_ATOMIC);

		if (!vmacSta_p->probeRspBody.basic_ies)
			return;

		probersp_p =
			(IEEEtypes_ProbeRsp_t *) vmacSta_p->probeRspBody.
			basic_ies;

		memcpy((void *)&probersp_p->BcnInterval, (void *)&bcn_interval,
		       sizeof(bcn_interval));
		memcpy((void *)&probersp_p->CapInfo, (void *)&capinfo,
		       sizeof(capinfo));
	}

	void macMgmtMlme_UpdateProbeRspExtraIes(vmacApInfo_t * vmacSta_p,
						UINT8 * probeRspIe,
						UINT16 length) {
		if (!length)
			return;

		if (!vmacSta_p->probeRspBody.extra_ies)
			vmacSta_p->probeRspBody.extra_ies =
				wl_kmalloc(MAX_BEACON_SIZE, GFP_ATOMIC);

		if (!vmacSta_p->probeRspBody.extra_ies)
			return;

		memcpy((void *)vmacSta_p->probeRspBody.extra_ies,
		       (void *)probeRspIe, length);
		vmacSta_p->probeRspBody.extra_len = length;
	}

	void macMgmtMlme_UpdateProbeRspBasicIes(vmacApInfo_t * vmacSta_p,
						UINT8 * iep, UINT16 length) {
		IEEEtypes_ProbeRsp_t *probersp_p;

		if (!length)
			return;

		if (!vmacSta_p->probeRspBody.basic_ies)
			vmacSta_p->probeRspBody.basic_ies =
				wl_kmalloc(MAX_BEACON_SIZE, GFP_ATOMIC);

		if (!vmacSta_p->probeRspBody.basic_ies)
			return;
		if (MAX_BEACON_SIZE <
		    (vmacSta_p->probeRspBody.basic_len + length)) {
			return;
		}

		probersp_p =
			(IEEEtypes_ProbeRsp_t *) vmacSta_p->probeRspBody.
			basic_ies;

		memcpy((void *)((UINT8 *) & probersp_p->SsId +
				vmacSta_p->probeRspBody.basic_len), (void *)iep,
		       length);
		vmacSta_p->probeRspBody.basic_len += length;
	}

#ifdef SOC_W906X
	void macMgmtMlme_UpdateProbeRspCsaIes(vmacApInfo_t * vmacSta_p,
					      UINT8 * iep, UINT16 length) {
		if (!length)
			return;

		if (!vmacSta_p->probeRspBody.csa_ies)
			vmacSta_p->probeRspBody.csa_ies =
				wl_kmalloc(MAX_BEACON_SIZE, GFP_ATOMIC);

		if (!vmacSta_p->probeRspBody.csa_ies)
			return;

		if (length < MAX_BEACON_SIZE) {
			memcpy(vmacSta_p->probeRspBody.csa_ies, iep, length);
			vmacSta_p->probeRspBody.csa_len = length;
		} else {
			printk("Error: CSA IEs length %d larger than %d\n",
			       length, MAX_BEACON_SIZE);
			wl_kfree(vmacSta_p->probeRspBody.csa_ies);
			vmacSta_p->probeRspBody.csa_ies = NULL;
		}
	}
#endif

	void macMgmtMlme_ResetProbeRspBuf(vmacApInfo_t * vmacSta_p) {
		if (vmacSta_p->probeRspBody.extra_ies) {
			wl_kfree(vmacSta_p->probeRspBody.extra_ies);
			vmacSta_p->probeRspBody.extra_ies = NULL;
			vmacSta_p->probeRspBody.extra_len = 0;
		}

		if (vmacSta_p->probeRspBody.basic_ies) {
			wl_kfree(vmacSta_p->probeRspBody.basic_ies);
			vmacSta_p->probeRspBody.basic_ies = NULL;
			vmacSta_p->probeRspBody.basic_len = 0;
		}
#ifdef SOC_W906X
		if (vmacSta_p->probeRspBody.csa_ies) {
			wl_kfree(vmacSta_p->probeRspBody.csa_ies);
			vmacSta_p->probeRspBody.csa_ies = NULL;
			vmacSta_p->probeRspBody.csa_len = 0;
		}
#endif
	}

	extern vmacEntry_t *sme_GetParentVMacEntry(UINT8 phyMacIndx);

	int skb_check(struct sk_buff *txSkb_p, int len, u8 * dump_p,
		      int dump_len) {
		if (len > skb_tailroom(txSkb_p)) {
			printk("Len:%d, skb_tail:%d, skb_end:%d\n", len,
			       (unsigned int)txSkb_p->tail,
			       (unsigned int)txSkb_p->end);

			mwl_hex_dump(dump_p, dump_len);
			wl_free_skb(txSkb_p);
			return true;
		}
		return false;
	}

/******************************************************************************
*
* Name: macMgmtMlme_ProbeRqst
*
* Description:
*    This routine handles a request from another station in an IBSS to
*    respond to a probe.
*
* Conditions For Use:
*    All software components have been initialized and started.
*
* Arguments:
*    Arg1 (i  ): MgmtMsg_p - Pointer to an 802.11 management message
*                            containing a probe request
* Return Value:
*    None.
*
* Notes:
*    None.
*
* PDL:
*   
* END PDL
*
*****************************************************************************/
	void macMgmtMlme_ProbeRqst1(vmacApInfo_t * vmacSta_p,
				    macmgmtQ_MgmtMsg3_t * MgmtMsg_p) {
#ifdef SOC_W906X
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev);
		MIB_PHY_DSSS_TABLE *PhyDSSSTable =
			vmacSta_p->Mib802dot11->PhyDSSSTable;
		UINT32 regval;
		int len_before_ssid;
		IEEEtypes_SsIdElement_t *ssid_p;
		int in_ssid_len = 0;
		int out_ssid_len = 0;
		UINT8 *supprates_p;
		int supprates_len = 0;
		UINT8 *extsupprates_p;
		int extsupprates_len = 0;
		UINT8 Has_HE = 0;
#endif
		MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
		macmgmtQ_MgmtMsg2_t *MgmtRsp_p;
		UINT8 destmacaddr[6];
		UINT64 hwtsf64, bsstsf64;
#ifdef AP_MAC_LINUX
		struct sk_buff *txSkb_p;
#else
		UINT32 tsflow;
		UINT32 tsfhigh;
#endif
#ifdef MRVL_WSC
		static const char *tag = "mlme-probe_request";
#ifdef MRVL_WPS2
		/* some WPS STA (e.g. broadcom) send probe request with length > 256 */
#define IW_CUSTOM_MAX2 512
		unsigned char buf[IW_CUSTOM_MAX2] = { 0 };
#else
		unsigned char buf[IW_CUSTOM_MAX] = { 0 };
#endif
		union iwreq_data wreq;
#endif
		IEEEtypes_Add_HT_Element_t *add_ht = NULL;

		{
			// If MBSS is enabled, block the probe-request which is sent to the non-tx bss
			MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;

			u32 idvBSSmap = get_individual_bss(wlpptr->wlpd_p);
			u32 ToIfmap = (1 << vmacSta_p->VMacEntry.macId);
			u32 nonTxBSSmap = get_mbssid_profile(wlpptr->wlpd_p, 2);

			//printk("idvmap:%x, macid:%u, non-tx mbssid_profile:%x\n",idvBSSmap ,vmacSta_p->VMacEntry.macId, get_mbssid_profile(wlpptr->wlpd_p, 2));

			if ((*(mib->mib_mbssid) == 1) && (*(mib->mib_ApMode) & AP_MODE_11AX) && (!(ToIfmap & idvBSSmap)) &&	//for Individual BSSs. 
			    ((ToIfmap & nonTxBSSmap) && memcmp(MgmtMsg_p->Hdr.DestAddr, vmacSta_p->dev->dev_addr, sizeof(IEEEtypes_MacAddr_t)))	//is non-tx MBSSID BSSs, but RA is not for the non-tx BSS 
				) {
				//Block the prob-resp which for for the non-tx bssid, if the ra is not non-tx
				//printk("[%s], skip prob-resp, allowed now\n", vmacSta_p->dev->name);                  
				return;
			}
		}

		if (isSsIdMatch
		    (&MgmtMsg_p->Body.ProbeRqst.SsId,
		     &vmacSta_p->macSsId) != SUCCESS) {
			if (*(mib->mib_broadcastssid) == TRUE) {
				if ((MgmtMsg_p->Body.ProbeRqst.SsId.Len != 0) &&
				    (*(mib->mib_mbssid) == 0)) {
					//Need to send out the prob-resp, even ssid does not match (TD: If it's in the same group)
					return;
				}
			} else
				return;
		}
#ifdef MRVL_WSC
		/* Send an event to upper layer with the probe request */
		/* IWEVENT mechanism restricts the size to 256 bytes */
		/* Note that the Probe Request at this point is in 4 address format and without FCS */
		/* FrmBodyLen = actual len - 4 (FCS) + 6(4 address) = actual len + 2 */
		/* In addition the Mgmt message has a 2 byte Framebody len element */
		/* Hence the length to be passed to up is FrmBodyLen + 2  + sizeof tag */
#ifdef MRVL_WPS2
		if ((MgmtMsg_p->Hdr.FrmBodyLen + strlen(tag) +
		     sizeof(UINT16)) <= IW_CUSTOM_MAX2)
#else
		if ((MgmtMsg_p->Hdr.FrmBodyLen + strlen(tag) +
		     sizeof(UINT16)) <= IW_CUSTOM_MAX)
#endif
		{
			snprintf(buf, sizeof(buf), "%s", tag);

			MgmtMsg_p->Hdr.FrmBodyLen =
				MgmtMsg_p->Hdr.FrmBodyLen -
				sizeof(IEEEtypes_MacAddr_t);
			memcpy(&buf[strlen(tag)], (char *)MgmtMsg_p,
			       sizeof(IEEEtypes_MgmtHdr3_t) -
			       sizeof(IEEEtypes_MacAddr_t));
			MgmtMsg_p->Hdr.FrmBodyLen =
				MgmtMsg_p->Hdr.FrmBodyLen +
				sizeof(IEEEtypes_MacAddr_t);
			memcpy(&buf
			       [strlen(tag) + sizeof(IEEEtypes_MgmtHdr3_t) -
				sizeof(IEEEtypes_MacAddr_t)],
			       (char *)&MgmtMsg_p->Body,
			       MgmtMsg_p->Hdr.FrmBodyLen -
			       sizeof(IEEEtypes_MgmtHdr3_t) + sizeof(UINT16));

			memset(&wreq, 0, sizeof(wreq));
			wreq.data.length =
				strlen(tag) + MgmtMsg_p->Hdr.FrmBodyLen +
				sizeof(UINT16) - sizeof(IEEEtypes_MacAddr_t);

			if (vmacSta_p->dev->flags & IFF_RUNNING)
				wireless_send_event(vmacSta_p->dev, IWEVCUSTOM,
						    &wreq, buf);
			if (vmacSta_p->WPSOn) {
#ifdef CFG80211
#ifndef CFG80211_COMPATIABLE
				macmgmtQ_MgmtMsg3_t *Msg_p =
					(macmgmtQ_MgmtMsg3_t *) (buf +
								 strlen(tag));
				mwl_send_vendor_wps_req_event(vmacSta_p->dev,
							      ((UINT8 *) Msg_p)
							      + 2,
							      Msg_p->Hdr.
							      FrmBodyLen, 0);
#endif /* CFG80211_COMPATIABLE */
#endif /* CFG80211 */
			}
		} else
			WLDBG_INFO(DBG_LEVEL_7,
				   "Probe Request Frame larger than allowed event buffer");
#endif

		/* Allocate space for response message */
#ifdef AP_MAC_LINUX

#ifdef SOC_W906X
		if (((vmacSta_p->dev->flags & IFF_RUNNING) == 0) ||
		    (vmacSta_p->probeRspBody.basic_ies == NULL) ||
		    (vmacSta_p->probeRspBody.extra_ies == NULL))
			return;
#endif
		if ((txSkb_p = mlmeApiPrepMgtMsg(IEEE_MSG_PROBE_RSP,
						 &MgmtMsg_p->Hdr.SrcAddr,
						 &vmacSta_p->macBssId)) == NULL)
			return;

		MgmtRsp_p = (macmgmtQ_MgmtMsg2_t *) txSkb_p->data;

#ifndef SOC_W906X
		MgmtRsp_p->Body.ProbeRsp.TimeStamp[0] =
			vmacSta_p->VMacEntry.macId;
#else
		len_before_ssid = sizeof(IEEEtypes_TimeStamp_t) +
			sizeof(IEEEtypes_BcnInterval_t) +
			sizeof(IEEEtypes_CapInfo_t);

		if (skb_check
		    (txSkb_p, len_before_ssid,
		     (u8 *) vmacSta_p->probeRspBody.basic_ies,
		     len_before_ssid)) {
			printk("[%s] not enough space for TimeStamp,BcnInterval,CapInfo\n", __func__);
			return;
		}

		memcpy((void *)&MgmtRsp_p->Body.ProbeRsp,
		       (void *)vmacSta_p->probeRspBody.basic_ies,
		       len_before_ssid);

		ssid_p = (IEEEtypes_SsIdElement_t *) (vmacSta_p->probeRspBody.
						      basic_ies +
						      len_before_ssid);

//Need it or not?
//if (vmacSta_p->VMacEntry.macId == wlpptr->wlpd_p->mbssSet[0].primbss) {
		if (*(mib->mib_broadcastssid) && (ssid_p->ElementId == SSID)) {
			out_ssid_len = in_ssid_len =
				sizeof(IEEEtypes_InfoElementHdr_t) +
				ssid_p->Len;

			if (skb_check
			    (txSkb_p, len_before_ssid + out_ssid_len,
			     (u8 *) vmacSta_p->probeRspBody.basic_ies +
			     len_before_ssid, out_ssid_len)) {
				printk("[%s] not enough space for SSID\n",
				       __func__);
				return;
			}

			memcpy((void *)&MgmtRsp_p->Body.ProbeRsp +
			       len_before_ssid,
			       (void *)vmacSta_p->probeRspBody.basic_ies +
			       len_before_ssid, out_ssid_len);
		} else if ((MgmtMsg_p->Body.ProbeRqst.SsId.Len != 0)
			   && (MgmtMsg_p->Body.ProbeRqst.SsId.ElementId ==
			       SSID)) {
			out_ssid_len =
				sizeof(IEEEtypes_InfoElementHdr_t) +
				MgmtMsg_p->Body.ProbeRqst.SsId.Len;

			if (skb_check
			    (txSkb_p, len_before_ssid + out_ssid_len,
			     (u8 *) & MgmtMsg_p->Body.ProbeRqst.SsId,
			     out_ssid_len)) {
				printk("[%s] not enough space for SSID\n",
				       __func__);
				return;
			}

			memcpy((void *)&MgmtRsp_p->Body.ProbeRsp +
			       len_before_ssid,
			       (void *)&MgmtMsg_p->Body.ProbeRqst.SsId,
			       out_ssid_len);
		}
//} else {
//      // Not tx-bss => not adding SSID (need it or not??)
//      out_ssid_len = in_ssid_len = 0;
//}
		skb_put(txSkb_p, len_before_ssid + out_ssid_len);
		supprates_p =
			(UINT8 *) & MgmtRsp_p->Body.ProbeRsp + len_before_ssid +
			out_ssid_len;

		if (vmacSta_p->SuppRateSet.Len) {
			supprates_len = sizeof(IEEEtypes_InfoElementHdr_t) +
				vmacSta_p->SuppRateSet.Len;

			if (skb_check
			    (txSkb_p, supprates_len,
			     (u8 *) & vmacSta_p->SuppRateSet, supprates_len)) {
				printk("[%s] not enough space for SuppRateSet\n", __func__);
				return;
			}

			memcpy((void *)supprates_p,
			       (void *)&vmacSta_p->SuppRateSet, supprates_len);
			skb_put(txSkb_p, supprates_len);
		} else {
			supprates_len = 0;
		}

		if (skb_check
		    (txSkb_p, vmacSta_p->probeRspBody.basic_len - in_ssid_len,
		     (u8 *) ssid_p + in_ssid_len,
		     vmacSta_p->probeRspBody.basic_len - in_ssid_len)) {
			printk("[%s] not enough space for Basic IE\n",
			       __func__);
			return;
		}

		memcpy((void *)(supprates_p + supprates_len),
		       (void *)((UINT8 *) ssid_p + in_ssid_len),
		       vmacSta_p->probeRspBody.basic_len - in_ssid_len);

		skb_put(txSkb_p,
			vmacSta_p->probeRspBody.basic_len - in_ssid_len);

		extsupprates_p = supprates_p + supprates_len +
			vmacSta_p->probeRspBody.basic_len - in_ssid_len;

		if (vmacSta_p->ExtSuppRateSet.Len) {
			extsupprates_len = sizeof(IEEEtypes_InfoElementHdr_t) +
				vmacSta_p->ExtSuppRateSet.Len;

			if (skb_check
			    (txSkb_p, extsupprates_len,
			     (u8 *) & vmacSta_p->ExtSuppRateSet,
			     extsupprates_len)) {
				printk("[%s] not enough space for ExtSuppRateSet\n", __func__);
				return;
			}

			memcpy((void *)extsupprates_p,
			       (void *)&vmacSta_p->ExtSuppRateSet,
			       extsupprates_len);
			skb_put(txSkb_p, extsupprates_len);
		} else {
			extsupprates_len = 0;
		}

#ifdef IEEE80211K
		if (*(mib->mib_rrm)) {
			QBSS_load_t QBSSLoad_ie;

			QBSSLoad_ie.ElementId = QBSS_LOAD;
			QBSSLoad_ie.Len = 5;
			QBSSLoad_ie.sta_cnt = extStaDb_entries(vmacSta_p, 0);
#ifdef WMM_AC_EDCA
			QBSSLoad_ie.avail_admit_cap = GetChannelCapacity();
#else /* WMM_AC_EDCA */
			QBSSLoad_ie.avail_admit_cap = 0;
#endif /* WMM_AC_EDCA */
			QBSSLoad_ie.channel_util =
				MSAN_get_channel_util(vmacSta_p);

			if (skb_check
			    (txSkb_p, sizeof(QBSSLoad_ie), (u8 *) & QBSSLoad_ie,
			     sizeof(QBSSLoad_ie))) {
				printk("[%s] not enough space for QBSSLoad_ie\n", __func__);
				return;
			}

			memcpy((void *)((UINT8 *) extsupprates_p +
					extsupprates_len), (void *)&QBSSLoad_ie,
			       sizeof(QBSSLoad_ie));
			skb_put(txSkb_p, sizeof(QBSSLoad_ie));
			extsupprates_len += sizeof(QBSSLoad_ie);
		}
#endif /* IEEE80211K */

		if (skb_check
		    (txSkb_p, vmacSta_p->probeRspBody.extra_len,
		     (u8 *) vmacSta_p->probeRspBody.extra_ies,
		     vmacSta_p->probeRspBody.extra_len)) {
			printk("[%s] not enough space for extra_ies\n",
			       __func__);
			return;
		}

		if (wlpptr->devid == SCBT || wlpptr->devid == SC5) {
			UINT8 *pData = (UINT8 *) (&(MgmtMsg_p->Body.ProbeRqst));
			SINT32 VarLen =
				MgmtMsg_p->Hdr.FrmBodyLen + sizeof(UINT16) -
				sizeof(IEEEtypes_MgmtHdr3_t);
			IEEEtypes_InfoElementHdr_t *pIE = NULL;
			IEEEtypes_InfoElementExtHdr_t *pExtIE = NULL;
			HE_Capabilities_IE_t *pHeCap = NULL;
			IEEEtypes_VhtCap_t *pVhtCap = NULL;
			IEEEtypes_VHT_op_mode_t *pVhtOmn = NULL;
			UINT8 vhtCapNss = 0;
			UINT8 vhtOmnNss = 0;
			UINT8 peerVhtNss = 0;
			IEEEtypes_VhtCap_t *pVhtcapProbeRsp = NULL;
			IEEEtypes_VendorSpec_VHT_Element_t *pVendorSpecVht =
				NULL;
			UINT8 oui[3] = { 0x00, 0x90, 0x4c };
			UINT8 *pIEbody = NULL;
			UINT8 skip = FALSE;

			while (VarLen > 0) {
				pIE = (IEEEtypes_InfoElementHdr_t *) pData;
				switch (pIE->ElementId) {
				case EXT_IE:
					pExtIE = (IEEEtypes_InfoElementExtHdr_t
						  *) pIE;
					if (pExtIE->ext == HE_CAPABILITIES_IE) {
						Has_HE = 1;
						pHeCap = (HE_Capabilities_IE_t
							  *) (&pExtIE->ext);
					}
					break;
				case VHT_CAP:
					pVhtCap = (IEEEtypes_VhtCap_t *) pIE;
					if ((pVhtCap->
					     SupportedRxMcsSet & 0xc000) !=
					    0xc000)
						vhtCapNss = 8;
					else if ((pVhtCap->
						  SupportedRxMcsSet & 0x3000) !=
						 0x3000)
						vhtCapNss = 7;
					else if ((pVhtCap->
						  SupportedRxMcsSet & 0xc00) !=
						 0xc00)
						vhtCapNss = 6;
					else if ((pVhtCap->
						  SupportedRxMcsSet & 0x300) !=
						 0x300)
						vhtCapNss = 5;
					else if ((pVhtCap->
						  SupportedRxMcsSet & 0xc0) !=
						 0xc0)
						vhtCapNss = 4;
					else if ((pVhtCap->
						  SupportedRxMcsSet & 0x30) !=
						 0x30)
						vhtCapNss = 3;
					else if ((pVhtCap->
						  SupportedRxMcsSet & 0xc) !=
						 0xc)
						vhtCapNss = 2;
					break;
				case OP_MODE_NOTIFICATION:
					pVhtOmn =
						(IEEEtypes_VHT_op_mode_t *) pIE;
					vhtOmnNss =
						pVhtOmn->OperatingMode.RxNss +
						1;
					break;
				case PROPRIETARY_IE:
					pIEbody =
						(UINT8 *) pIE +
						sizeof
						(IEEEtypes_InfoElementHdr_t);
					if ((pIE->Len >= 5) && (memcmp(pIEbody, &oui[0], 3) == 0) &&	// Epigram
					    (pIEbody[3] == 0x4) &&	// VENDOR_VHT_TYPE
					    (pIEbody[4] == 0x8))	// VENDOR_VHT_SUBTYPE
						pVendorSpecVht =
							(IEEEtypes_VendorSpec_VHT_Element_t
							 *) pIE;
					break;
				default:
					break;
				}
				pData += sizeof(IEEEtypes_InfoElementHdr_t) +
					pIE->Len;
				VarLen -=
					sizeof(IEEEtypes_InfoElementHdr_t) +
					pIE->Len;
			}

			pData = (UINT8 *) vmacSta_p->probeRspBody.extra_ies;
			VarLen = vmacSta_p->probeRspBody.extra_len;

			while (VarLen > 0) {
				skip = FALSE;
				pIE = (IEEEtypes_InfoElementHdr_t *) pData;
				switch (pIE->ElementId) {
				case ADD_HT:
					add_ht = (IEEEtypes_Add_HT_Element_t *)
						pIE;
#ifdef COEXIST_20_40_SUPPORT
					if (*
					    (vmacSta_p->ShadowMib802dot11->
					     mib_HT40MIntoler)) {
						if (PhyDSSSTable->Chanflag.
						    FreqBand ==
						    FREQ_BAND_2DOT4GHZ &&
						    (PhyDSSSTable->Chanflag.
						     ChnlWidth == CH_AUTO_WIDTH
						     || PhyDSSSTable->Chanflag.
						     ChnlWidth ==
						     CH_40_MHz_WIDTH)) {
							if (wlpptr->wlpd_p->
							    BcnAddHtAddChannel
							    == 0) {
								add_ht->AddChan.
									STAChannelWidth
									= 0;
								add_ht->AddChan.
									ExtChanOffset
									= 0;
							} else {
								add_ht->AddChan.
									STAChannelWidth
									= 1;
								add_ht->AddChan.
									ExtChanOffset
									=
									vmacSta_p->
									ShadowMib802dot11->
									PhyDSSSTable->
									Chanflag.
									ExtChnlOffset;
							}
						}
					}
#endif
					if (PhyDSSSTable->Chanflag.FreqBand ==
					    FREQ_BAND_2DOT4GHZ)
						add_ht->OpMode.OpMode =
							(wlpptr->wlpd_p->
							 BcnAddHtOpMode & 0x3);
					break;
				case VHT_CAP:
					if (!pHeCap && pVhtCap)
						pVhtcapProbeRsp =
							(IEEEtypes_VhtCap_t
							 *) ((UINT8 *)
							     extsupprates_p +
							     extsupprates_len);
					break;
				case PROPRIETARY_IE:
					pIEbody =
						(UINT8 *) pIE +
						sizeof
						(IEEEtypes_InfoElementHdr_t);
					if (!pVendorSpecVht &&
					    (*(mib->mib_ApMode) & AP_MODE_11AC))
						if ((pIE->Len >= 5) && (memcmp(pIEbody, &oui[0], 3) == 0) &&	// Epigram
						    (pIEbody[3] == 0x4) &&	// VENDOR_VHT_TYPE
						    (pIEbody[4] == 0x8))	// VENDOR_VHT_SUBTYPE
							skip = TRUE;
					break;
				default:
					break;
				}
				if (!skip) {
					memcpy((void *)((UINT8 *) extsupprates_p
							+ extsupprates_len),
					       (void *)pIE,
					       sizeof
					       (IEEEtypes_InfoElementHdr_t) +
					       pIE->Len);
					extsupprates_len +=
						sizeof
						(IEEEtypes_InfoElementHdr_t) +
						pIE->Len;
					skb_put(txSkb_p,
						sizeof
						(IEEEtypes_InfoElementHdr_t) +
						pIE->Len);
				}
				pData += sizeof(IEEEtypes_InfoElementHdr_t) +
					pIE->Len;
				VarLen -=
					sizeof(IEEEtypes_InfoElementHdr_t) +
					pIE->Len;
			}

			if (pVhtcapProbeRsp) {
				peerVhtNss = vhtCapNss;
				if (pVhtOmn && vhtOmnNss)
					peerVhtNss = min(vhtCapNss, vhtOmnNss);
				if (peerVhtNss > 4)
					peerVhtNss = 4;
				if (peerVhtNss < 3)
					peerVhtNss = 3;
				pVhtcapProbeRsp->cap.
					CompressedSteeringNumberofBeamformerAntennaSupported
					= 0x3;
			}
		} else {
			memcpy((void *)((UINT8 *) extsupprates_p +
					extsupprates_len),
			       (void *)vmacSta_p->probeRspBody.extra_ies,
			       vmacSta_p->probeRspBody.extra_len);
			skb_put(txSkb_p, vmacSta_p->probeRspBody.extra_len);
			extsupprates_len += vmacSta_p->probeRspBody.extra_len;
		}

#ifdef SOC_W906X
		if (vmacSta_p->probeRspBody.csa_ies &&
		    vmacSta_p->probeRspBody.csa_len) {
			if (skb_check
			    (txSkb_p, vmacSta_p->probeRspBody.csa_len,
			     (u8 *) vmacSta_p->probeRspBody.csa_ies,
			     vmacSta_p->probeRspBody.csa_len)) {
				printk("[%s] not enough space for csa_ies %d bytes\n", __func__, vmacSta_p->probeRspBody.csa_len);
				return;
			}
			memcpy((void *)((UINT8 *) extsupprates_p +
					extsupprates_len),
			       vmacSta_p->probeRspBody.csa_ies,
			       vmacSta_p->probeRspBody.csa_len);

			skb_put(txSkb_p, vmacSta_p->probeRspBody.csa_len);
			extsupprates_len += vmacSta_p->probeRspBody.csa_len;
		}
#endif

	/** add Extended Cap IE here **/
		if ((*(vmacSta_p->Mib802dot11->mib_ApMode) & AP_MODE_11AC) &&
		    !Is5GBand(*(vmacSta_p->Mib802dot11->mib_ApMode))) {
			extern void *FindIEWithinIEs(UINT8 * data_p,
						     UINT32 lenPacket,
						     UINT8 attrib, UINT8 * OUI);
			if ((skb_tailroom(txSkb_p) >
			     sizeof(IEEEtypes_Extended_Cap_Element_t)) &&
			    FindIEWithinIEs(txSkb_p->data +
					    sizeof(MgmtRsp_p->Hdr) +
					    len_before_ssid,
					    txSkb_p->len -
					    sizeof(MgmtRsp_p->Hdr) -
					    len_before_ssid, EXT_CAP_IE,
					    NULL) == NULL) {
				extern UINT16 AddExtended_Cap_IE(vmacApInfo_t *
								 vmacSta_p,
								 IEEEtypes_Extended_Cap_Element_t
								 *
								 pNextElement);
				IEEEtypes_Extended_Cap_Element_t *pExtCap;

				pExtCap =
					(IEEEtypes_Extended_Cap_Element_t *)
					skb_put(txSkb_p,
						sizeof
						(IEEEtypes_Extended_Cap_Element_t));
				memset((void *)pExtCap, 0,
				       sizeof
				       (IEEEtypes_Extended_Cap_Element_t));
				AddExtended_Cap_IE(vmacSta_p, pExtCap);
				extsupprates_len +=
					sizeof
					(IEEEtypes_Extended_Cap_Element_t);
			}
		}
#ifdef SOC_W906X
		/* Some non-HE STA cannot scan this HE AP, this is to make EXP_CAP IE shrink from 11 bytes to 8 bytes, for those non-HE STA */
		if (!(*(mib->mib_ApMode) & AP_MODE_11AX) || !Has_HE) {
			extern void *FindIEWithinIEs(UINT8 * data_p,
						     UINT32 lenPacket,
						     UINT8 attrib, UINT8 * OUI);
			UINT8 ie_len = 0;
			UINT8 *ie =
				FindIEWithinIEs(txSkb_p->data +
						sizeof(MgmtRsp_p->Hdr) +
						len_before_ssid,
						txSkb_p->len -
						sizeof(MgmtRsp_p->Hdr) -
						len_before_ssid, EXT_CAP_IE,
						NULL);
			if (ie) {
				ie_len = *((UINT8 *) (ie + 1));
				if (ie_len == 11) {	/* 11 = sizeof(IEEEtypes_Extended_Cap_Element_t) - 2 */
					UINT8 *ie_end = ie + 2 + ie_len;
					UINT8 *ie_end_new = ie_end - (11 - 8);
					memmove(ie_end_new, ie_end,
						skb_tail_pointer(txSkb_p) -
						ie_end);
					*(ie + 1) = 8;
					txSkb_p->tail -= (11 - 8);
					txSkb_p->len -= (11 - 8);
				}
			}
		}
#endif

		memset(&MgmtRsp_p->Body.ProbeRsp.TimeStamp[0], 0,
		       sizeof(IEEEtypes_TimeStamp_t));

		if (vmacSta_p->BssTsfBase == 0) {
			tsf_info_t tsf;

			if (!wlFwGetTsf(vmacSta_p->dev, &tsf)) {
				vmacSta_p->BssTsfBase = tsf.BssTsfBase;
				printk("[BssTsfBase]: macid:%u: BssTsfBase:%16llx\n", vmacSta_p->VMacEntry.macId, vmacSta_p->BssTsfBase);
			}
		}

		regval = readl(wlpptr->ioBase1 + BBTX_TMR_TSF_HI);
		hwtsf64 = regval;
		regval = readl(wlpptr->ioBase1 + BBTX_TMR_TSF);
		hwtsf64 = ((hwtsf64 << 32) | regval);
		bsstsf64 = hwtsf64 - vmacSta_p->BssTsfBase;

		memcpy(&MgmtRsp_p->Body.ProbeRsp.TimeStamp[0], &bsstsf64,
		       sizeof(bsstsf64));
		//printk("probResp: hwtsf:%08llx, bsstsf:%08llx, bsstsfbase:%08llx\n",hwtsf64,bsstsf64,vmacSta_p->BssTsfBase);

#endif /* SOC_W906X */
#else
		if ((TxMsg_p = mlmeApiPrepMgtMsg(IEEE_MSG_PROBE_RSP,
						 &MgmtMsg_p->Hdr.SrcAddr,
						 &vmacSta_p->macBssId)) == NULL)
		{
			return;
		}
#endif

		memcpy(destmacaddr, MgmtMsg_p->Hdr.SrcAddr, 6);

#ifndef AP_MAC_LINUX

		memcpy(MgmtRsp_p, PrbRspBuf_p, PrbRspBuf_p->Hdr.FrmBodyLen + sizeof(IEEEtypes_GenHdr_t));
												 /** just do a copy from the probe response field **/

	/** get the current time stamp **/
		//WL_READ_WORD(TX_TSF_LO, tsflow);
		//WL_READ_WORD(TX_TSF_HI, tsfhigh);
		tsflow = 0;
		tsfhigh = 0;

		MgmtRsp_p->Body.ProbeRsp.TimeStamp[0] =
			(UINT8) ((tsflow & 0x000000ff));
		MgmtRsp_p->Body.ProbeRsp.TimeStamp[1] =
			(UINT8) ((tsflow & 0x0000ff00) >> 8);
		MgmtRsp_p->Body.ProbeRsp.TimeStamp[2] =
			(UINT8) ((tsflow & 0x00ff0000) >> 16);
		MgmtRsp_p->Body.ProbeRsp.TimeStamp[3] =
			(UINT8) ((tsflow & 0xff000000) >> 24);
		MgmtRsp_p->Body.ProbeRsp.TimeStamp[4] =
			(UINT8) ((tsfhigh & 0x000000ff));
		MgmtRsp_p->Body.ProbeRsp.TimeStamp[5] =
			(UINT8) ((tsfhigh & 0x0000ff00) >> 8);
		MgmtRsp_p->Body.ProbeRsp.TimeStamp[6] =
			(UINT8) ((tsfhigh & 0x00ff0000) >> 16);
		MgmtRsp_p->Body.ProbeRsp.TimeStamp[7] =
			(UINT8) ((tsfhigh & 0xff000000) >> 24);
#endif
		memcpy(MgmtRsp_p->Hdr.DestAddr, destmacaddr, 6);

		if (txMgmtMsg(vmacSta_p->dev, txSkb_p) != OS_SUCCESS)
			wl_free_skb(txSkb_p);
	}
	extern void macMgmtMlme_ProbeRqst(vmacApInfo_t * vmac_ap,
					  macmgmtQ_MgmtMsg3_t * MgmtMsg_p) {
		struct net_device *dev;
		struct wlprivate *wlpptr, *wlpptr1;
		vmacApInfo_t *vmacSta_p, *vmactem_p;
		UINT8 bctAddr[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
		int i = 0;
		if (vmac_ap->master)
			vmacSta_p = vmac_ap->master;
		else
			vmacSta_p = vmac_ap;
		wlpptr = NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev);
		if (memcmp(MgmtMsg_p->Hdr.DestAddr, bctAddr, 6) == 0) {
			while (i <= bss_num) {
				if (wlpptr->vdev[i]) {
					dev = wlpptr->vdev[i];
					wlpptr1 =
						NETDEV_PRIV_P(struct wlprivate,
							      dev);
					if (wlpptr1->vmacSta_p->VMacEntry.
					    modeOfService == VMAC_MODE_AP)
						if (isMacAccessList
						    (wlpptr1->vmacSta_p,
						     &(MgmtMsg_p->Hdr.
						       SrcAddr)) == SUCCESS)
							macMgmtMlme_ProbeRqst1
								(wlpptr1->
								 vmacSta_p,
								 MgmtMsg_p);
				}
				i++;
			}
		} else {
			vmactem_p =
				vmacGetMBssByAddr(vmacSta_p,
						  MgmtMsg_p->Hdr.DestAddr);
			if (vmactem_p) {
				vmacSta_p = vmactem_p;
			} else {
				return;
			}
			if (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_AP) {
				if (isMacAccessList
				    (vmacSta_p,
				     &(MgmtMsg_p->Hdr.SrcAddr)) == SUCCESS) {
					macMgmtMlme_ProbeRqst1(vmacSta_p,
							       MgmtMsg_p);
				}
			}
		}
	}

#ifdef MRVL_WAPI
/* send wapi event to user space: AP/STA MAC, type, WIE (WAPI IE) etc. */
	void macMgmtMlme_WAPI_event(struct net_device *dev, int event_type,
				    u16 auth_type,
				    IEEEtypes_MacAddr_t * sta_addr,
				    IEEEtypes_MacAddr_t * ap_addr, char *info) {
		asso_mt asso_mt_info;
		union iwreq_data wreq;
		int extra_len = 0;
		struct wlprivate *wlpptrSta =
			NETDEV_PRIV_P(struct wlprivate, dev);
		vmacApInfo_t *vmacSta_p = wlpptrSta->vmacSta_p;
		int i;

		asso_mt_info.type = auth_type;
		memcpy(asso_mt_info.mac, sta_addr, 6);
		memcpy(asso_mt_info.ap_mac, ap_addr, 6);
		memset(asso_mt_info.wie, 0, sizeof(asso_mt_info.wie));

		*(UINT32 *) & (asso_mt_info.gsn[0]) =
			*(UINT32 *) & (vmacSta_p->wapiPN_mc[12]);
		*(UINT32 *) & (asso_mt_info.gsn[4]) =
			*(UINT32 *) & (vmacSta_p->wapiPN_mc[8]);
		*(UINT32 *) & (asso_mt_info.gsn[8]) =
			*(UINT32 *) & (vmacSta_p->wapiPN_mc[4]);
		*(UINT32 *) & (asso_mt_info.gsn[12]) =
			*(UINT32 *) & (vmacSta_p->wapiPN_mc[0]);

		if (info) {
			IEEEtypes_WAPI_IE_t *p = (IEEEtypes_WAPI_IE_t *) info;
			extra_len = p->Len + 2;
			memcpy(asso_mt_info.wie, p, extra_len);
			WLDBG_INFO(DBG_LEVEL_7,
				   "### Driver (%s), extra len %d, ap mac %s,  len1=%d, len2=%d\n",
				   __FUNCTION__, extra_len,
				   mac_display((const UINT8 *)ap_addr),
				   sizeof(asso_mt_info),
				   sizeof(asso_mt_info.wie));
		}

		memset(&wreq, 0, sizeof(wreq));
		wreq.data.length =
			sizeof(asso_mt_info) - sizeof(asso_mt_info.wie) +
			extra_len;
		if (event_type == IWEVASSOCREQIE) {
			WLDBG_INFO(DBG_LEVEL_7,
				   "### Driver (%s),wreq.data.length=%d, event_type=%x, auth_type=%x\n",
				   __FUNCTION__, wreq.data.length, event_type,
				   auth_type);
		}

		if (vmacSta_p->dev->flags & IFF_RUNNING)
			wireless_send_event(dev, event_type, &wreq,
					    (char *)&asso_mt_info);
	}
#endif // MRVL_WPAI

#ifdef AP_TWT
#define MAX_TWT_FRAME_DEBUG_COUNTERS  12
	u16 debug_twt_frame_errors[MAX_TWT_FRAME_DEBUG_COUNTERS] = { 0 };
	u8 wfa_itwt_wakedur_early_end = 0;
	void ProcessTWTsetup(vmacApInfo_t * vmacSta_p,
			     macmgmtQ_MgmtMsg_t * MgmtMsg_p) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev);
		extStaDb_StaInfo_t *pStaInfo;
		//UINT8 QosAct;
		//IEEEtypes_Action_QoS_Category_e QosCategory;
		IEEEtypes_TWT_Element_t *ptwt;
		Individual_set_fd_t *pIdvl, *pIdvlDB;
		u8 flowid;
		IEEEtypes_TWT_Element_t *pflow;
		u32 errcode = 0;
		struct sk_buff *txSkb_p = NULL;
		macmgmtQ_MgmtMsg2_t *MgmtRsp_p;
		IEEEtypes_TWT_Element_t *ptwtResp;
		u64 curtsf = 0;
		u16 CmdReply = TWT_SETUP_CMD_REJECT;
		twt_param_t param;
		u16 twteLen = 0;
		u32 actLen = 0;
		tsf_info_t tsfInfo;
		struct net_device *netdev =
			(wlpptr->master) ? wlpptr->master : wlpptr->netDev;

		if ((pStaInfo =
		     extStaDb_GetStaInfo(vmacSta_p, &(MgmtMsg_p->Hdr.SrcAddr),
					 STADB_UPDATE_AGINGTIME)) == NULL)
			goto done;

		ptwt = (IEEEtypes_TWT_Element_t *) & (MgmtMsg_p->Body.Action.
						      Data.TwtElement);

		if (ptwt->ElementId != TWT_IE) {
			errcode = 1;
			goto done;
		}

		if (ptwt->ctrl.NegoType & 0x2) {
			printk("Not support Broadcast TWT for now. NegoType:%u\n", ptwt->ctrl.NegoType);
			errcode = 2;
			goto done;
		} else {
			pIdvl = (Individual_set_fd_t *) & ptwt->info.
				IndvParamSet;

			if (pIdvl->ReqType.ReqRsp == 0) {
				errcode = 3;
				goto done;
			}
			//setup cmds from requester
			if (pIdvl->ReqType.SetupCmd < TWT_SETUP_CMD_GROUPING) {

				flowid = pIdvl->ReqType.FlowID_or_Bcast_Recom;

				if (flowid == 0) {
					u32 idx = 1;
					u8 map = pStaInfo->TwtAgree.ActFlowID;

					for (idx = 1;
					     idx < ITWT_AGREEMENT_PER_STA;
					     idx++) {
						if (!(map & (1 << idx)))
							break;
					}

					if (idx == ITWT_AGREEMENT_PER_STA) {
						errcode = 9;
						goto done;
					}
					//find a free flow id
					//pStaInfo->TwtAgree.ActFlowID |= (1<<idx);  
					flowid = idx;
					pIdvl->ReqType.FlowID_or_Bcast_Recom =
						idx;
					printk("TWT assign FlowID: %u\n",
					       flowid);
				} else {
					//printk("[Warning]: nozero TWT FlowID in request frame: %u\n", flowid);
					if (flowid >= ITWT_AGREEMENT_PER_STA) {
						//printk("TWT support FlowID: %u out of supporting range:%u\n", flowid, ITWT_AGREEMENT_PER_STA); 
						errcode = 9;
						goto done;
					}
				}

				pflow = &pStaInfo->TwtAgree.twtE[flowid];
				memcpy((void *)pflow, (void *)ptwt,
				       ((ptwt->Len >
					 sizeof(IEEEtypes_TWT_Element_t) -
					 2) ? sizeof(IEEEtypes_TWT_Element_t)
					: (ptwt->Len + 2)));
				pIdvlDB = &pflow->info.IndvParamSet;

				if (wlFwGetTsf(netdev, &tsfInfo)) {
					errcode = 4;
					goto done;
				}
				curtsf = tsfInfo.BssTsfTime;

				switch (pIdvl->ReqType.SetupCmd) {
					//case TWT_SETUP_CMD_SUGGEST:
				case TWT_SETUP_CMD_REQUEST:
					{	//sta did not provide twt, accept and replay a twt to client
						if (curtsf) {
							pIdvlDB->TargetWakeTime = (curtsf & (~0xFLL)) + 200000;	//  curtsf + 200000;  //200ms later from now.
							CmdReply =
								TWT_SETUP_CMD_ACCEPT;
							printk("Driver provide TargetWakeTime: 0x%llx,	Current TSF:0x%llx\n", pIdvlDB->TargetWakeTime, curtsf);
						} else {
							pIdvlDB->
								TargetWakeTime =
								0;
							printk("Fail to Get TSF, set TargetWakeTime =0\n");
							errcode = 5;
							goto done;
						}
						if (wfa_11ax_pf) {
							//WAR for WFA TWT test case for let brcm early end uplink traffic.
							//pIdvlDB->NomMinWakeDur -= 10;
							pIdvlDB->
								NomMinWakeDur -=
								wfa_itwt_wakedur_early_end;
						}
					}
					break;
				case TWT_SETUP_CMD_SUGGEST:
				case TWT_SETUP_CMD_DEMAND:
					{
						//for WFA iTWT 4.56.1 
						//if( pIdvlDB->TargetWakeTime > curtsf   ) {
						if (1) {
							CmdReply =
								TWT_SETUP_CMD_ACCEPT;
							printk("Accept TWT %u cmd, tsf:0x%llx, Current TSF:0x%llx\n", pIdvl->ReqType.SetupCmd, pIdvlDB->TargetWakeTime, curtsf);
						} else {
							//requester expected twt time might be too early. suggest a new one. 
							pIdvlDB->
								TargetWakeTime =
								curtsf + 200000;
							CmdReply =
								TWT_SETUP_CMD_ALTERNATE;
						}

						//WAR for WFA TWT test case for let brcm early end uplink traffic.
						//=> This WAR will fail in the sniffer check for newer ucc script
						// pIdvlDB->NomMinWakeDur -= 10;
					}
					break;
				}

			} else {
				printk("Invalid twt setup cmd(%u) received by responder.\n", pIdvl->ReqType.SetupCmd);
				errcode = 6;
				goto done;
			}

			//not including NDP Paging field if indicator == 0 
			twteLen =
				((ptwt->ctrl.
				  NDP_PagingIndicator) ?
				 sizeof(Individual_set_fd_t)
				 : (sizeof(Individual_set_fd_t) - 4)) + 3;
			actLen = twteLen + 3;	//total length, action hdr (cat(1), action(1), token(1)))

			//prepare Reply cmd 
			if ((txSkb_p = mlmeApiPrepMgtMsg2(IEEE_MSG_QOS_ACTION,
							  &MgmtMsg_p->Hdr.
							  SrcAddr,
							  &vmacSta_p->macBssId,
							  actLen)) == NULL) {
				printk("%s(): mlmeApiPrepMgtMsg failed\n",
				       __func__);
				errcode = 7;
				goto done;
			}

			MgmtRsp_p = (macmgmtQ_MgmtMsg2_t *) txSkb_p->data;
			ptwtResp =
				(IEEEtypes_TWT_Element_t *) & (MgmtRsp_p->Body.
							       Action.Data.
							       TwtElement);
			MgmtRsp_p->Body.Action.Category = S1G;
			MgmtRsp_p->Body.Action.Action = TWT_SETUP;
						    /** same enum as addba_resp **/
			MgmtRsp_p->Body.Action.DialogToken =
				MgmtMsg_p->Body.Action.DialogToken;
			switch (CmdReply) {
			case TWT_SETUP_CMD_ACCEPT:
				{
					param.Twt = pIdvlDB->TargetWakeTime;
					param.MinWakeDur =
						pIdvlDB->NomMinWakeDur;
					param.WakeInvlMantissa =
						pIdvlDB->WakeInvlMantissa;
					param.WakeInvlExpo =
						pIdvlDB->ReqType.WakeIvlExp;
					param.Trigger =
						pIdvlDB->ReqType.Trigger;
					param.FlowType =
						pIdvlDB->ReqType.FlowType;
				}
			case TWT_SETUP_CMD_DICTATE:
			case TWT_SETUP_CMD_ALTERNATE:
			case TWT_SETUP_CMD_REJECT:
				{
					Individual_set_fd_t *pidv =
						&ptwtResp->info.IndvParamSet;

					memcpy((void *)ptwtResp, pflow,
					       twteLen);
					ptwtResp->Len = twteLen - 2;	// - eleID+len
					ptwtResp->ctrl.Responder_PM_Mode = 0;
					pidv->ReqType.ReqRsp = 0;	//response
					pidv->ReqType.SetupCmd = CmdReply;
				}
				break;
			}

			if (txMgmtMsg(vmacSta_p->dev, txSkb_p) != OS_SUCCESS) {
				wl_free_skb(txSkb_p);
				errcode = 8;
				goto done;
			} else {

				if (CmdReply == TWT_SETUP_CMD_ACCEPT) {
					u32 ivl = param.WakeInvlMantissa;

					ivl = (ivl << param.WakeInvlExpo);

					if (!wlFwTwtParam
					    (netdev, WL_SET,
					     (MgmtMsg_p->Hdr.SrcAddr), flowid,
					     &param)) {

						pStaInfo->TwtAgree.ActFlowID |=
							(1 << flowid);

						printk("Config PFW StaDB:%02X%02X%02X%02X%02X%02X TWT param success\n", MgmtMsg_p->Hdr.SrcAddr[0], MgmtMsg_p->Hdr.SrcAddr[1], MgmtMsg_p->Hdr.SrcAddr[2], MgmtMsg_p->Hdr.SrcAddr[3], MgmtMsg_p->Hdr.SrcAddr[4], MgmtMsg_p->Hdr.SrcAddr[5]);
						printk("twt:0x%llx, MinWakeDur:%u (256us unit), wakeivl:%u, trigger:%u, FlowType:%u, FlowId:%u\n", param.Twt, param.MinWakeDur, ivl, param.Trigger, param.FlowType, flowid);
					}
				}
				printk("%s(): Sent TWT setup cmd(%u)\n",
				       __func__, CmdReply);
			}

		}

done:
		if (errcode < MAX_TWT_FRAME_DEBUG_COUNTERS) {
			debug_twt_frame_errors[errcode]++;
			//printk("%s(): errcode:%u\n",__func__, errcode);
		}

		return;
	}

//twt
	void ProcessTWTteardown(vmacApInfo_t * vmacSta_p,
				macmgmtQ_MgmtMsg_t * MgmtMsg_p) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev);
		struct net_device *netdev =
			(wlpptr->master) ? wlpptr->master : wlpptr->netDev;
		u8 *p = (MgmtMsg_p->Hdr.SrcAddr);
		u8 flowid;
		extStaDb_StaInfo_t *pStaInfo;

		flowid = (((u8 *) & MgmtMsg_p->Body)[2] & 0x7);

		if (flowid >= ITWT_AGREEMENT_PER_STA) {
			printk("Given Teardown flowid:%u out of supporting range:%u\n", flowid, ITWT_AGREEMENT_PER_STA);
			goto done;
		}

		if (!wlFwTwtParam
		    (netdev, WL_RESET, MgmtMsg_p->Hdr.SrcAddr, flowid, NULL)) {

			pStaInfo =
				extStaDb_GetStaInfo(vmacSta_p,
						    &(MgmtMsg_p->Hdr.SrcAddr),
						    STADB_UPDATE_AGINGTIME);
			if (pStaInfo) {
				pStaInfo->TwtAgree.ActFlowID &=
					(~(1 << flowid));
				memset(&pStaInfo->TwtAgree.twtE[flowid], 0,
				       sizeof(IEEEtypes_TWT_Element_t));
			}

			printk("Tear down peer:%02x%02x%02x%02x%02x%02x, flowid:%u success\n", p[0], p[1], p[2], p[3], p[4], p[5], flowid);
		} else {
			printk("Tear down peer:%02x%02x%02x%02x%02x%02x, flowid:%u failure\n", p[0], p[1], p[2], p[3], p[4], p[5], flowid);
		}

done:

		return;
	}

//twt
	void ProcessTWTInformation(vmacApInfo_t * vmacSta_p,
				   macmgmtQ_MgmtMsg_t * MgmtMsg_p) {
		//struct wlprivate    *wlpptr   = NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev);
		//struct net_device *netdev = (wlpptr->master) ?  wlpptr->master : wlpptr->netDev; 
		//u8 *p = (MgmtMsg_p->Hdr.SrcAddr); 
		IEEEtypes_TWT_Information_t *ptwtinfo;
		//u8  info=0;
		u8 flowid;

		ptwtinfo =
			(IEEEtypes_TWT_Information_t *) &
			(((u8 *) & MgmtMsg_p->Body)[2]);
		flowid = ptwtinfo->FlowID;

		printk("TWT Info: flowid:%u, RspReq:%u, NextReq:%u, NextSubfieldSize:%u, AllTWT:%u, NextTwt:0x%llx", flowid, ptwtinfo->Rsp_Req, ptwtinfo->NextTWT_Req, ptwtinfo->NextTWT_Subfd_Size, ptwtinfo->AllTWT, ptwtinfo->NextTWT);

		/*  do it later.
		   if( !wlFwTwtParam(netdev, WL_RESET, MgmtMsg_p->Hdr.SrcAddr, flowid, NULL) ) {

		   printk("Tear down peer:%02x%02x%02x%02x%02x%02x, flowid:%u success\n",p[0],p[1],p[2],p[3],p[4],p[5], flowid);
		   }
		   else {
		   printk("Tear down peer:%02x%02x%02x%02x%02x%02x, flowid:%u failure\n",p[0],p[1],p[2],p[3],p[4],p[5], flowid);
		   }
		 */
		return;
	}

#endif

#ifdef QOS_FEATURE
/*
	Check if the input mac_address exists in the mac_pool
	Input:
		- chk_macaddr: The mac_address to be checked
		- macpool_p: mac address pool
	return:
		- TRUE: exist
		- FALSE: not exist
*/
	BOOLEAN _is_mac_exist(IEEEtypes_MacAddr_t chk_macaddr,
			      mac_pool * macpool_p) {
		BOOLEAN res = false;
		UINT8 i;
		for (i = 0; i < MAC_POOL_SIZE; i++) {
			if (!memcmp
			    (macpool_p->mac_pool[i], chk_macaddr,
			     sizeof(IEEEtypes_MacAddr_t))) {
				res = TRUE;
				break;
			}
		}

		return res;
	}

	UINT8 get_ampdu_rx_disable_flag(vmacApInfo_t * vmacSta_p,
					macmgmtQ_MgmtMsg3_t * MgmtMsg_p) {
		UINT8 Ampdu_Rx_Disable_Flag_l =
			vmacSta_p->Ampdu_Rx_Disable_Flag;

		// ampdu disabled => check if the sta in the accept list as a special case
		// ampdu enabled => check if the sta in the reject list as a special case
		BOOLEAN is_except = _is_mac_exist(MgmtMsg_p->Hdr.SrcAddr,
						  ((Ampdu_Rx_Disable_Flag_l ==
						    TRUE) ? (&vmacSta_p->
							     ampdu_acpt_pool)
						   : (&vmacSta_p->
						      ampdu_rejt_pool)));

		//printk("%s(), Ampdu_Rx_Disable_Flag_l=%u is_except: %u\n", __func__, 
		//      Ampdu_Rx_Disable_Flag_l,
		//      is_except);
		// If the sta in the list => this sta is an exception that it should have a different decision
		Ampdu_Rx_Disable_Flag_l =
			(is_except ==
			 TRUE) ? (!Ampdu_Rx_Disable_Flag_l) :
			Ampdu_Rx_Disable_Flag_l;

		//printk("%s(), final Ampdu_Rx_Disable_Flag: %u\n", __func__, Ampdu_Rx_Disable_Flag_l);
		return Ampdu_Rx_Disable_Flag_l;
	}

	extern void macMgmtMlme_QoSAct(vmacApInfo_t * vmacSta_p,
				       macmgmtQ_MgmtMsg3_t * MgmtMsg_p) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev);
		UINT8 QosAct;
#ifdef SOC_W906X
		IEEEtypes_Action_QoS_Category_e QosCategory;
#else
		IEEEtypes_QoS_Category_e QosCategory;
#endif
		macmgmtQ_MgmtMsg2_t *MgmtRsp_p;
		extStaDb_StaInfo_t *pStaInfo;
		WSM_DELTS_Req_t *pDelTSFrm;
		IEEEtypes_ADDTS_Rsp_t *pAddTsRspFrm;
		IEEEtypes_ADDTS_Req_t *pAddTsReqFrm;
		IEEEtypes_ADDBA_Req_t *pAddBaReqFrm;
		IEEEtypes_ADDBA_Rsp_t *pAddBaRspFrm;
		IEEEtypes_DELBA_t *pDelBaReqFrm;
		IEEEtypes_VHT_op_mode_action_t *pVHTOpMode;
		UINT8 vht_NewRxChannelWidth;
		UINT8 vht_NewRxNss;
		UINT32 Status, TspecDBindex;
		UINT8 amsdu_bitmap = 0;
#ifdef AP_MAC_LINUX
		struct sk_buff *txSkb_p;
#endif
		UINT16 MediumTime = 0;

#ifdef SOC_W906X
		UINT32 max_sta_num = sta_num;
#else
		UINT32 max_sta_num = MAX_AID + 1;
#endif

		QosCategory = ((UINT8 *) & MgmtMsg_p->Body)[0];	//get the QoS Action
		QosAct = ((UINT8 *) & MgmtMsg_p->Body)[1];	//get the QoS Action

		//If ADDTS Request, send the request to the Scheduler.
		//check is ADDTS Request
		switch (QosCategory) {
#ifdef WMM_AC_EDCA
		case WFA:
#if 0				//dbg
			printk("macMgmtMlme_QoSAct(): %d %d\n", QosCategory,
			       QosAct);
#endif
			switch (QosAct) {
			case ADDTS_REQ:
				{
					IEEEtypes_WFA_ADDTS_Rsp_t
						*pWfaAddTsRspFrm;
					IEEEtypes_WFA_ADDTS_Req_t
						*pWfaAddTsReqFrm;

					/* Get Aid */
					pStaInfo =
						extStaDb_GetStaInfo(vmacSta_p,
								    &
								    (MgmtMsg_p->
								     Hdr.
								     SrcAddr),
								    1);

					if (pStaInfo) {
						/* Allocate space for response message */
#ifdef AP_MAC_LINUX
						if ((txSkb_p =
						     mlmeApiPrepMgtMsg2
						     (IEEE_MSG_QOS_ACTION,
						      &MgmtMsg_p->Hdr.SrcAddr,
						      &vmacSta_p->macBssId,
						      sizeof
						      (IEEEtypes_WFA_ADDTS_Rsp_t)))
						    == NULL) {
							printk("macMgmtMlme_QoSAct(): mlmeApiPrepMgtMsg failed\n");
							return;
						}
						MgmtRsp_p =
							(macmgmtQ_MgmtMsg2_t *)
							txSkb_p->data;
#else
						if ((TxMsg_p =
						     mlmeApiPrepMgtMsg2
						     (IEEE_MSG_QOS_ACTION,
						      &MgmtMsg_p->Hdr.SrcAddr,
						      &vmacSta_p->macBssId,
						      sizeof
						      (IEEEtypes_WFA_ADDTS_Rsp_t)))
						    == NULL) {
							printk("macMgmtMlme_QoSAct(): mlmeApiPrepMgtMsg failed\n");
							return;
						}
#endif

						pWfaAddTsReqFrm =
							(IEEEtypes_WFA_ADDTS_Req_t
							 *) & MgmtMsg_p->Body;
						pWfaAddTsRspFrm =
							(IEEEtypes_WFA_ADDTS_Rsp_t
							 *) & MgmtRsp_p->Body;
#ifdef MV_CPU_BE
						pWfaAddTsReqFrm->TSpec.ts_info.
							u16_data =
							ENDIAN_SWAP16
							(pWfaAddTsReqFrm->TSpec.
							 ts_info.u16_data);
#endif
						/*If a TSpec with the same MAC Addr and TsId exists then
						   first delete it and then add a new one */
						Status = ProcessDELTSRequest
							(vmacSta_p,
							 (IEEEtypes_MacAddr_t *)
							 MgmtMsg_p->Hdr.SrcAddr,
							 pWfaAddTsReqFrm->TSpec.
							 ts_info.tsid);
						//Process ADDTS Request. Return a ADDTS Response.
						Status = ProcessADDTSRequest_WFA
							(vmacSta_p,
							 (IEEEtypes_WFA_ADDTS_Req_t
							  *) & MgmtMsg_p->Body,
							 &MgmtMsg_p->Hdr.
							 SrcAddr, pStaInfo->Aid,
							 &TspecDBindex,
							 pStaInfo->ClientMode,
							 &MediumTime);

#if 0				//dbg
						printk("pWfaAddTsReqFrm\n");
						printk("ts_info: traffic_type 0x%x, tsid 0x%x, direction 0x%x, access_policy 0x%x, aggregation 0x%x, apsd 0x%x, usr_priority 0x%x, ts_info_ack_policy 0x%x, sched 0x%x, rsvd 0x%x\n", pWfaAddTsReqFrm->TSpec.ts_info.traffic_type, pWfaAddTsReqFrm->TSpec.ts_info.tsid, pWfaAddTsReqFrm->TSpec.ts_info.direction, pWfaAddTsReqFrm->TSpec.ts_info.access_policy, pWfaAddTsReqFrm->TSpec.ts_info.aggregation, pWfaAddTsReqFrm->TSpec.ts_info.apsd, pWfaAddTsReqFrm->TSpec.ts_info.usr_priority, pWfaAddTsReqFrm->TSpec.ts_info.ts_info_ack_policy, pWfaAddTsReqFrm->TSpec.ts_info.sched, pWfaAddTsReqFrm->TSpec.ts_info.rsvd);
						printk("nom_msdu_size 0x%x, max_msdu_size 0x%x, min_SI 0x%x, max_SI 0x%x, inactive_intrvl 0x%x, suspen_intrvl 0x%x\n", pWfaAddTsReqFrm->TSpec.nom_msdu_size, pWfaAddTsReqFrm->TSpec.max_msdu_size, pWfaAddTsReqFrm->TSpec.min_SI, pWfaAddTsReqFrm->TSpec.max_SI, pWfaAddTsReqFrm->TSpec.inactive_intrvl, pWfaAddTsReqFrm->TSpec.suspen_intrvl);
						printk("serv_start_time 0x%x, min_data_rate 0x%x, mean_data_rate 0x%x, peak_data_rate 0x%x, max_burst_size 0x%x\n", pWfaAddTsReqFrm->TSpec.serv_start_time, pWfaAddTsReqFrm->TSpec.min_data_rate, pWfaAddTsReqFrm->TSpec.mean_data_rate, pWfaAddTsReqFrm->TSpec.peak_data_rate, pWfaAddTsReqFrm->TSpec.max_burst_size);
						printk("delay_bound 0x%x, min_phy_rate 0x%x, srpl_bw_allow 0x%x, med_time 0x%x\n", pWfaAddTsReqFrm->TSpec.delay_bound, pWfaAddTsReqFrm->TSpec.min_phy_rate, pWfaAddTsReqFrm->TSpec.srpl_bw_allow, pWfaAddTsReqFrm->TSpec.med_time);
#endif

						pWfaAddTsRspFrm->Category =
							pWfaAddTsReqFrm->
							Category;
						pWfaAddTsRspFrm->Action =
							ADDTS_RSP;
						pWfaAddTsRspFrm->DialogToken =
							pWfaAddTsReqFrm->
							DialogToken;
						if (Status !=
						    IEEEtypes_STATUS_SUCCESS) {
							pWfaAddTsRspFrm->StatusCode = 3;	//refused
						} else {
							pWfaAddTsRspFrm->StatusCode = Status;	//0 = success
						}

						// pWfaAddTsRspFrm->TSDelay = 0;
						memcpy(&pWfaAddTsRspFrm->TSpec, &pWfaAddTsReqFrm->TSpec, MgmtMsg_p->Hdr.FrmBodyLen - sizeof(IEEEtypes_MgmtHdr_t) - 3);	//- sizeof(RxSign_t) - 3);
						if (pWfaAddTsReqFrm->TSpec.
						    ts_info.access_policy ==
						    EDCA) {
							if (Status ==
							    IEEEtypes_STATUS_SUCCESS)
							{
								if (pWfaAddTsReqFrm->TSpec.ts_info.direction != DOWNLINK) {
									pWfaAddTsRspFrm->
										TSpec.
										med_time
										=
										ENDIAN_SWAP16
										(MediumTime);
								} else {	//DOWNLINK
									pWfaAddTsRspFrm->
										TSpec.
										med_time
										=
										0;
								}
							} else {
								pWfaAddTsRspFrm->
									TSpec.
									med_time
									= 0;
							}
						}
#if 0				//We don't support HCCA/BOTH mode so far
						else	//HCCA / BOTH
						{
							//Now append a Schedule Element to the Response only if status is successful.
							ProcessADDTSRequestSchedule
								(pWfaAddTsRspFrm,
								 TspecDBindex);
						}
#endif
#ifdef MV_CPU_BE
						pWfaAddTsRspFrm->TSpec.ts_info.
							u16_data =
							ENDIAN_SWAP16
							(pWfaAddTsRspFrm->TSpec.
							 ts_info.u16_data);
#endif
#if 0				//dbg
						printk("pWfaAddTsRspFrm\n");
						printk("ts_info: traffic_type 0x%x, tsid 0x%x, direction 0x%x, access_policy 0x%x, aggregation 0x%x, apsd 0x%x, usr_priority 0x%x, ts_info_ack_policy 0x%x, sched 0x%x, rsvd 0x%x\n", pWfaAddTsRspFrm->TSpec.ts_info.traffic_type, pWfaAddTsRspFrm->TSpec.ts_info.tsid, pWfaAddTsRspFrm->TSpec.ts_info.direction, pWfaAddTsRspFrm->TSpec.ts_info.access_policy, pWfaAddTsRspFrm->TSpec.ts_info.aggregation, pWfaAddTsRspFrm->TSpec.ts_info.apsd, pWfaAddTsRspFrm->TSpec.ts_info.usr_priority, pWfaAddTsRspFrm->TSpec.ts_info.ts_info_ack_policy, pWfaAddTsRspFrm->TSpec.ts_info.sched, pWfaAddTsRspFrm->TSpec.ts_info.rsvd);
						printk("nom_msdu_size 0x%x, max_msdu_size 0x%x, min_SI 0x%x, max_SI 0x%x, inactive_intrvl 0x%x, suspen_intrvl 0x%x\n", pWfaAddTsRspFrm->TSpec.nom_msdu_size, pWfaAddTsRspFrm->TSpec.max_msdu_size, pWfaAddTsRspFrm->TSpec.min_SI, pWfaAddTsRspFrm->TSpec.max_SI, pWfaAddTsRspFrm->TSpec.inactive_intrvl, pWfaAddTsRspFrm->TSpec.suspen_intrvl);
						printk("serv_start_time 0x%x, min_data_rate 0x%x, mean_data_rate 0x%x, peak_data_rate 0x%x, max_burst_size 0x%x\n", pWfaAddTsRspFrm->TSpec.serv_start_time, pWfaAddTsRspFrm->TSpec.min_data_rate, pWfaAddTsRspFrm->TSpec.mean_data_rate, pWfaAddTsRspFrm->TSpec.peak_data_rate, pWfaAddTsRspFrm->TSpec.max_burst_size);
						printk("delay_bound 0x%x, min_phy_rate 0x%x, srpl_bw_allow 0x%x, med_time 0x%x\n", pWfaAddTsRspFrm->TSpec.delay_bound, pWfaAddTsRspFrm->TSpec.min_phy_rate, pWfaAddTsRspFrm->TSpec.srpl_bw_allow, pWfaAddTsRspFrm->TSpec.med_time);
#endif
#ifdef AP_MAC_LINUX
						if (txMgmtMsg
						    (vmacSta_p->dev,
						     txSkb_p) != OS_SUCCESS) {
							wl_free_skb(txSkb_p);
							return;
						}
#endif
					}
				}
				break;

			case DELTS:
				{

					IEEEtypes_WFA_DELTS_Req_t *pDelTSFrm;

					pDelTSFrm =
						(IEEEtypes_WFA_DELTS_Req_t *) &
						MgmtMsg_p->Body;
#ifdef MV_CPU_BE
					pDelTSFrm->TSpec.ts_info.u16_data =
						ENDIAN_SWAP16(pDelTSFrm->TSInfo.
							      ts_info.u16_data);
#endif
#if 0				//dbg
					printk("DELTS tsid 0x%x\n",
					       pDelTSFrm->TSpec.ts_info.tsid);
#endif
					ProcessDELTSRequest(vmacSta_p,
							    &MgmtMsg_p->Hdr.
							    SrcAddr,
							    (UINT32) pDelTSFrm->
							    TSpec.ts_info.tsid);
				}
				break;

			default:
				break;
			}
			break;
#endif /* WMM_AC_EDCA */
		case QoS:
			switch (QosAct) {
			case ADDTS_REQ:
				/* Get Aid */
				pStaInfo =
					extStaDb_GetStaInfo(vmacSta_p,
							    &(MgmtMsg_p->Hdr.
							      SrcAddr),
							    STADB_UPDATE_AGINGTIME);

				if (pStaInfo) {
					/* Allocate space for response message */
#ifdef AP_MAC_LINUX
					if ((txSkb_p =
					     mlmeApiPrepMgtMsg
					     (IEEE_MSG_QOS_ACTION,
					      &MgmtMsg_p->Hdr.SrcAddr,
					      &vmacSta_p->macBssId)) == NULL)
						return;
					MgmtRsp_p =
						(macmgmtQ_MgmtMsg2_t *)
						txSkb_p->data;
#else
					if ((TxMsg_p =
					     mlmeApiPrepMgtMsg
					     (IEEE_MSG_QOS_ACTION,
					      &MgmtMsg_p->Hdr.SrcAddr,
					      &vmacSta_p->macBssId)) == NULL) {
						return;
					}
#endif

					pAddTsReqFrm =
						(IEEEtypes_ADDTS_Req_t *) &
						MgmtMsg_p->Body;
					pAddTsRspFrm =
						(IEEEtypes_ADDTS_Rsp_t *) &
						MgmtRsp_p->Body;
#ifdef MV_CPU_BE
					pAddTsReqFrm->TSpec.ts_info.u16_data =
						ENDIAN_SWAP16(pAddTsReqFrm->
							      TSpec.ts_info.
							      u16_data);
#endif
					/*If a TSpec with the same MAC Addr and TsId exists then
					   first delete it and then add a new one */
					Status = ProcessDELTSRequest(vmacSta_p,
								     (IEEEtypes_MacAddr_t
								      *)
								     MgmtMsg_p->
								     Hdr.
								     SrcAddr,
								     pAddTsReqFrm->
								     TSpec.
								     ts_info.
								     tsid);
					//Process ADDTS Request. Return a ADDTS Response.
					Status = ProcessADDTSRequest(vmacSta_p,
								     (IEEEtypes_ADDTS_Req_t
								      *) &
								     MgmtMsg_p->
								     Body,
								     &MgmtMsg_p->
								     Hdr.
								     SrcAddr,
								     pStaInfo->
								     Aid,
								     &TspecDBindex,
								     pStaInfo->
								     ClientMode,
								     &MediumTime);

					pAddTsRspFrm->Category =
						pAddTsReqFrm->Category;
					pAddTsRspFrm->Action = ADDTS_RSP;
					pAddTsRspFrm->DialogToken =
						pAddTsReqFrm->DialogToken;
					pAddTsRspFrm->StatusCode =
						ENDIAN_SWAP16(Status);

					// pAddTsRspFrm->TSDelay = 0;
					memcpy(&pAddTsRspFrm->TSpec, &pAddTsReqFrm->TSpec, MgmtMsg_p->Hdr.FrmBodyLen - sizeof(IEEEtypes_MgmtHdr_t) - 3);	//- sizeof(RxSign_t) - 3);
#ifdef WMM_AC_EDCA
					if (pAddTsReqFrm->TSpec.ts_info.
					    access_policy == EDCA) {
						if (Status ==
						    IEEEtypes_STATUS_SUCCESS) {
							if (pAddTsReqFrm->TSpec.
							    ts_info.direction !=
							    DOWNLINK) {
								pAddTsRspFrm->
									TSpec.
									med_time
									=
									ENDIAN_SWAP16
									(MediumTime);
							} else {	//DOWNLINK
								pAddTsRspFrm->
									TSpec.
									med_time
									= 0;
							}
						} else {
							pAddTsRspFrm->TSpec.
								med_time = 0;
						}
					} else	//HCCA / BOTH
					{
						//Now append a Schedule Element to the Response only if status is successful.
						ProcessADDTSRequestSchedule
							(pAddTsRspFrm,
							 TspecDBindex);
					}
#else /* WMM_AC_EDCA */
					//Now append a Schedule Element to the Response only if status is successful.
					ProcessADDTSRequestSchedule
						(pAddTsRspFrm, TspecDBindex);
#endif /* WMM_AC_EDCA */
#ifdef MV_CPU_BE
					pAddTsRspFrm->TSpec.ts_info.u16_data =
						ENDIAN_SWAP16(pAddTsRspFrm->
							      TSpec.ts_info.
							      u16_data);
#endif
#ifdef AP_MAC_LINUX
					if (txMgmtMsg(vmacSta_p->dev, txSkb_p)
					    != OS_SUCCESS) {
						wl_free_skb(txSkb_p);
						return;
					}
#endif
				}
				break;
			case DELTS:
				pDelTSFrm =
					(WSM_DELTS_Req_t *) & MgmtMsg_p->Body;
#ifdef MV_CPU_BE
				pDelTSFrm->TSInfo.ts_info.u16_data =
					ENDIAN_SWAP16(pDelTSFrm->TSInfo.ts_info.
						      u16_data);
#endif

				ProcessDELTSRequest(vmacSta_p,
						    &MgmtMsg_p->Hdr.SrcAddr,
						    (UINT32) pDelTSFrm->TSInfo.
						    ts_info.tsid);
				break;
			default:
				break;

			}
			break;
		case BlkAck:
			switch (QosAct) {
			case ADDBA_REQ:
#if defined(AP_MAC_LINUX)
				pStaInfo =
					extStaDb_GetStaInfo(vmacSta_p,
							    &(MgmtMsg_p->Hdr.
							      SrcAddr),
							    STADB_UPDATE_AGINGTIME);
				if (pStaInfo && (pStaInfo->StnId < max_sta_num)) {
					int i, tid;
					Ampdu_Pck_Reorder_t *baRxInfo;
					UINT8 Ampdu_Rx_Disable_Flag_l =
						get_ampdu_rx_disable_flag
						(vmacSta_p, MgmtMsg_p);

					/* Allocate space for response message */
					if ((txSkb_p =
					     mlmeApiPrepMgtMsg2
					     (IEEE_MSG_QOS_ACTION,
					      &MgmtMsg_p->Hdr.SrcAddr,
					      &MgmtMsg_p->Hdr.DestAddr,
					      sizeof(IEEEtypes_ADDBA_Rsp_t))) ==
					    NULL) {
						WLDBG_INFO(DBG_LEVEL_7,
							   "No more buffer !!!!!!!!!!!!\n");
						return;
					}
					//if ((txSkb_p = mlmeApiPrepMgtMsg(IEEE_MSG_QOS_ACTION,
					//&MgmtMsg_p->Hdr.SrcAddr, &vmacSta_p->macBssId)) == NULL)

					MgmtRsp_p =
						(macmgmtQ_MgmtMsg2_t *)
						txSkb_p->data;
					pAddBaReqFrm =
						(IEEEtypes_ADDBA_Req_t *) &
						MgmtMsg_p->Body;
					pAddBaRspFrm =
						(IEEEtypes_ADDBA_Rsp_t *) &
						MgmtRsp_p->Body;

					pAddBaRspFrm->Category =
						pAddBaReqFrm->Category;
					pAddBaRspFrm->Action = ADDTS_RSP;
								   /** same enum as addba_resp **/
					pAddBaRspFrm->DialogToken =
						pAddBaReqFrm->DialogToken;
					if (Ampdu_Rx_Disable_Flag_l) {
						pAddBaRspFrm->StatusCode =
							IEEEtypes_STATUS_REQUEST_DECLINED;
					} else {
						pAddBaRspFrm->StatusCode =
							IEEEtypes_STATUS_SUCCESS;

					}

					if (*
					    (vmacSta_p->Mib802dot11->
					     pMib_11nAggrMode) &
					    WL_MODE_AMSDU_TX_MASK)
						amsdu_bitmap =
							(pAddBaReqFrm->ParamSet.
							 amsdu) ? (*(vmacSta_p->
								     Mib802dot11->
								     pMib_11nAggrMode)
								   &
								   WL_MODE_AMSDU_TX_MASK)
							: 0;

#ifdef MV_CPU_BE
					pAddBaReqFrm->ParamSet.u16_data =
						ENDIAN_SWAP16(pAddBaReqFrm->
							      ParamSet.
							      u16_data);
					pAddBaReqFrm->SeqControl.u16_data =
						ENDIAN_SWAP16(pAddBaReqFrm->
							      SeqControl.
							      u16_data);
#endif
					pAddBaRspFrm->ParamSet =
						pAddBaReqFrm->ParamSet;
#ifdef SOC_W906X
					if (vmacSta_p->Amsdu_Rx_Disable_Flag)
						pAddBaRspFrm->ParamSet.amsdu =
							0;
					else
#endif
						pAddBaRspFrm->ParamSet.amsdu = pAddBaReqFrm->ParamSet.amsdu;	//honor remote's setting

#ifdef SOC_W906X
					if ((*
					     (vmacSta_p->Mib802dot11->
					      mib_superBA) == 1) ||
					    (*
					     (vmacSta_p->Mib802dot11->
					      mib_superBA) == 3))
						pAddBaRspFrm->ParamSet.BufSize =
							(pAddBaReqFrm->ParamSet.
							 BufSize <
							 MAX_BA_REORDER_BUF_SIZE)
							? 64 :
							MAX_BA_REORDER_BUF_SIZE;
					else
						// mib_superBA == 0 || 2
						pAddBaRspFrm->ParamSet.BufSize =
							64;
#else
					pAddBaRspFrm->ParamSet.BufSize = 64;
#endif //
					//printk("%s:ADDBA_RSP: pAddBaRspFrm->ParamSet.BufSize:%u\n",__func__, pAddBaRspFrm->ParamSet.BufSize);

					pAddBaRspFrm->Timeout_val = 0;	//Set 0 to improve thpt ramp up time by avoiding Intel6300 sending DELBA to itself after AMPDU traffic

					if (!Ampdu_Rx_Disable_Flag_l) {
						//      Priority= AccCategoryQ[pAddBaReqFrm->ParamSet.tid];
						tid = pAddBaReqFrm->ParamSet.
							tid;
#ifdef SOC_W906X
#ifdef WIFI_DATA_OFFLOAD
						dol_set_ba_info(wlpptr,
								wlpptr->wlpd_p->
								ipc_session_id,
								BA_INFO_ADDBA,
								pStaInfo->StnId,
								tid,
								pAddBaReqFrm->
								SeqControl.
								Starting_Seq_No,
								pAddBaRspFrm->
								ParamSet.
								BufSize);
#endif
						baRxInfo =
							&wlpptr->wlpd_p->
							AmpduPckReorder
							[pStaInfo->StnId];

#if 0				//REORDER_2B_REMOVED
						baRxInfo->CurrentSeqNo[tid] =
							pAddBaReqFrm->
							SeqControl.
							Starting_Seq_No;
						baRxInfo->ReOrdering[tid] =
							FALSE;
#endif
						baRxInfo->AddBaReceive[tid] =
							TRUE;
						if (baRxInfo->timer_init[tid] ==
						    0) {
							TimerInit(&baRxInfo->
								  timer[tid]);
							baRxInfo->
								timer_init[tid]
								= 1;
						}

					/** Reset the current queue **/
#if 0				//REORDER_2B_REMOVED
						for (i = 0;
						     i <
						     MAX_AMPDU_REORDER_BUFFER;
						     i++) {
							baRxInfo->
								ExpectedSeqNo
								[tid][i] = 0;
							if (baRxInfo >
							    pFrame[tid][i] !=
							    NULL)
								wl_free_skb((struct sk_buff *)baRxInfo->pFrame[tid][i]);
							baRxInfo->
								pFrame[tid][i] =
								NULL;
						}

						baRxInfo->
							ExpectedSeqNo[tid][0] =
							baRxInfo->
							CurrentSeqNo[tid];
#endif
#else
						wlpptr->wlpd_p->
							AmpduPckReorder
							[pStaInfo->Aid].
							CurrentSeqNo[tid] =
							pAddBaReqFrm->
							SeqControl.
							Starting_Seq_No;
						wlpptr->wlpd_p->
							AmpduPckReorder
							[pStaInfo->Aid].
							ReOrdering[tid] = FALSE;

						wlpptr->wlpd_p->
							AmpduPckReorder
							[pStaInfo->Aid].
							AddBaReceive[tid] =
							TRUE;
						if (wlpptr->wlpd_p->
						    AmpduPckReorder[pStaInfo->
								    Aid].
						    timer_init[tid] == 0) {
							TimerInit(&wlpptr->
								  wlpd_p->
								  AmpduPckReorder
								  [pStaInfo->
								   Aid].
								  timer[tid]);
							wlpptr->wlpd_p->
								AmpduPckReorder
								[pStaInfo->Aid].
								timer_init[tid]
								= 1;
						}

					/** Reset the current queue **/
						for (i = 0;
						     i <
						     MAX_AMPDU_REORDER_BUFFER;
						     i++) {
							wlpptr->wlpd_p->
								AmpduPckReorder
								[pStaInfo->Aid].
								ExpectedSeqNo
								[tid][i] = 0;
							if (wlpptr->wlpd_p->
							    AmpduPckReorder
							    [pStaInfo->Aid].
							    pFrame[tid][i] !=
							    NULL)
								wl_free_skb((struct sk_buff *)wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].pFrame[tid][i]);
							wlpptr->wlpd_p->
								AmpduPckReorder
								[pStaInfo->Aid].
								pFrame[tid][i] =
								NULL;
						}

						wlpptr->wlpd_p->
							AmpduPckReorder
							[pStaInfo->Aid].
							ExpectedSeqNo[tid][0] =
							wlpptr->wlpd_p->
							AmpduPckReorder
							[pStaInfo->Aid].
							CurrentSeqNo[tid];

						baRxInfo =
							&wlpptr->wlpd_p->
							AmpduPckReorder
							[pStaInfo->Aid];
#endif /* SOC_W906X */
						for (i = 0;
						     i <
						     MAX_BA_REORDER_BUF_SIZE;
						     i++) {
							skb_queue_purge
								(&baRxInfo->
								 ba[tid].
								 AmsduQ[i].
								 skbHead);
							baRxInfo->ba[tid].
								AmsduQ[i].
								state = 0;
						}

						baRxInfo->ba[tid].winStartB =
							pAddBaReqFrm->
							SeqControl.
							Starting_Seq_No;
#ifdef SOC_W906X
						baRxInfo->ba[tid].winSizeB =
							pAddBaRspFrm->ParamSet.
							BufSize;
#else
						//baRxInfo->ba[tid].winSizeB = (pAddBaRspFrm->ParamSet.BufSize > MAX_BA_REORDER_BUF_SIZE)? MAX_BA_REORDER_BUF_SIZE : pAddBaRspFrm->ParamSet.BufSize;
						baRxInfo->ba[tid].winSizeB =
							MAX_BA_REORDER_BUF_SIZE;
#endif
						baRxInfo->ba[tid].storedBufCnt =
							0;
						baRxInfo->ba[tid].leastSeqNo =
							0;
						baRxInfo->ba[tid].minTime = 0;

						DEBUG_REORDER_PRINT(("ADDBA seqno %d, tid %d\n", baRxInfo->ba[tid].winStartB, tid));
					}
#ifdef MV_CPU_BE
					pAddBaRspFrm->ParamSet.u16_data =
						ENDIAN_SWAP16(pAddBaRspFrm->
							      ParamSet.
							      u16_data);
#endif
					if (txMgmtMsg(vmacSta_p->dev, txSkb_p)
					    != OS_SUCCESS) {
						wl_free_skb(txSkb_p);
						return;
					}
#ifdef SOC_W906X
					if (pAddBaRspFrm->StatusCode ==
					    IEEEtypes_STATUS_SUCCESS)
						wlFwCreateBAStream(vmacSta_p->
								   dev,
								   pAddBaRspFrm->
								   ParamSet.
								   BufSize,
								   pAddBaRspFrm->
								   ParamSet.
								   BufSize,
								   (u_int8_t *)
								   &
								   (MgmtMsg_p->
								    Hdr.
								    SrcAddr),
								   10,
								   pAddBaReqFrm->
								   ParamSet.tid,
								   amsdu_bitmap,
								   1,
								   pStaInfo->
								   HtElem.
								   MacHTParamInfo,
								   (u_int8_t *)
								   &
								   (MgmtMsg_p->
								    Hdr.
								    DestAddr),
								   pAddBaReqFrm->
								   SeqControl.
								   Starting_Seq_No,
								   pStaInfo->
								   vhtCap.cap.
								   MaximumAmpduLengthExponent,
								   0,
								   (u_int16_t)
								   pStaInfo->
								   StnId);
#else
					wlFwCreateBAStream(vmacSta_p->dev,
							   pAddBaReqFrm->
							   ParamSet.BufSize,
							   pAddBaReqFrm->
							   ParamSet.BufSize,
							   (u_int8_t *) &
							   (MgmtMsg_p->Hdr.
							    SrcAddr), 10,
							   pAddBaReqFrm->
							   ParamSet.tid,
							   amsdu_bitmap, 1,
							   pStaInfo->HtElem.
							   MacHTParamInfo,
							   (u_int8_t *) &
							   (MgmtMsg_p->Hdr.
							    DestAddr),
							   pAddBaReqFrm->
							   SeqControl.
							   Starting_Seq_No,
							   pStaInfo->vhtCap.cap.
							   MaximumAmpduLengthExponent,
							   0);
#endif /* SOC_W906X */
				}
#endif
				break;
			case DELBA:
				pStaInfo =
					extStaDb_GetStaInfo(vmacSta_p,
							    &(MgmtMsg_p->Hdr.
							      SrcAddr),
							    STADB_UPDATE_AGINGTIME);
				WLDBG_INFO(DBG_LEVEL_7, "Inside delba_req\n");
				if (pStaInfo && (pStaInfo->StnId < max_sta_num)) {
					int i = 0, tid;
					Ampdu_Pck_Reorder_t *baRxInfo;

					pDelBaReqFrm =
						(IEEEtypes_DELBA_t *) &
						MgmtMsg_p->Body;
					//      pAddBaRspFrm = (IEEEtypes_ADDBA_Rsp_t*)&MgmtRsp_p->Body;

					//WLDBG_INFO(DBG_LEVEL_7,"**********************\n");
					//WLDBG_INFO(DBG_LEVEL_7,"Dialog Token %x, policy %x Bufsize %x tid %x Seqno %x\n",pAddBaReqFrm->DialogToken,pAddBaReqFrm->ParamSet.BA_policy,
					//      pAddBaReqFrm->ParamSet.BufSize,pAddBaReqFrm->ParamSet.tid,pAddBaReqFrm->SeqControl);
					// WLDBG_INFO(DBG_LEVEL_7,"Current seqno %d\n",pAddBaReqFrm->SeqControl.Starting_Seq_No);

					//WLDBG_INFO(DBG_LEVEL_7,"~~~~~~~~~~~~~~~~~~~~\n");

					//              Priority= AccCategoryQ[pDelBaReqFrm->ParamSet.tid];

					tid = pDelBaReqFrm->ParamSet.tid;

					if (pDelBaReqFrm->ParamSet.Initiator == 1) {
/** Initiator want to stop ampdu **/
#ifdef SOC_W906X
#ifdef WIFI_DATA_OFFLOAD
						dol_set_ba_info(wlpptr,
								wlpptr->wlpd_p->
								ipc_session_id,
								BA_INFO_DELBA,
								pStaInfo->StnId,
								tid, 0, 0);
#endif
						baRxInfo =
							&wlpptr->wlpd_p->
							AmpduPckReorder
							[pStaInfo->StnId];

						//baRxInfo->ReOrdering[tid]  = FALSE;      REORDER_2B_REMOVED
						baRxInfo->AddBaReceive[tid] =
							FALSE;
						//              WLDBG_INFO(DBG_LEVEL_0, " 4Value of Aid= %x Priority = %x addbareceive = %x \n",pStaInfo->Aid,Priority,AmpduPckReorder[pStaInfo->Aid].AddBaReceive[Priority]);

					/** Reset the current queue **/
#if 0				//REORDER_2B_REMOVED
						for (i = 0;
						     i <
						     MAX_AMPDU_REORDER_BUFFER;
						     i++) {
							baRxInfo->
								ExpectedSeqNo
								[tid][i] = 0;
							if (baRxInfo->
							    pFrame[tid][i] !=
							    NULL)
								wl_free_skb((struct sk_buff *)baRxInfo->pFrame[tid][i]);
							baRxInfo->
								pFrame[tid][i] =
								NULL;
						}
#endif

						wlFwUpdateDestroyBAStream
							(vmacSta_p->dev, 0, 1,
							 i,
							 pDelBaReqFrm->ParamSet.
							 tid,
							 (u_int8_t *) &
							 (MgmtMsg_p->Hdr.
							  SrcAddr),
							 pStaInfo->StnId);

						//baRxInfo->ExpectedSeqNo[tid][0] = baRxInfo->CurrentSeqNo[tid] ;     REORDER_2B_REMOVED
#else
						wlpptr->wlpd_p->
							AmpduPckReorder
							[pStaInfo->Aid].
							ReOrdering[tid] = FALSE;
						wlpptr->wlpd_p->
							AmpduPckReorder
							[pStaInfo->Aid].
							AddBaReceive[tid] =
							FALSE;
						//              WLDBG_INFO(DBG_LEVEL_0, " 4Value of Aid= %x Priority = %x addbareceive = %x \n",pStaInfo->Aid,Priority,AmpduPckReorder[pStaInfo->Aid].AddBaReceive[Priority]);

					/** Reset the current queue **/
#ifdef SOC_W8964		//REORDER_2B_REMOVED
						for (i = 0;
						     i <
						     MAX_AMPDU_REORDER_BUFFER;
						     i++) {
							wlpptr->wlpd_p->
								AmpduPckReorder
								[pStaInfo->Aid].
								ExpectedSeqNo
								[tid][i] = 0;
							if (wlpptr->wlpd_p->
							    AmpduPckReorder
							    [pStaInfo->Aid].
							    pFrame[tid][i] !=
							    NULL)
								wl_free_skb((struct sk_buff *)wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].pFrame[tid][i]);
							wlpptr->wlpd_p->
								AmpduPckReorder
								[pStaInfo->Aid].
								pFrame[tid][i] =
								NULL;
						}
#endif /* SOC_W8964 */

						wlFwUpdateDestroyBAStream
							(vmacSta_p->dev, 0, 1,
							 i,
							 pDelBaReqFrm->ParamSet.
							 tid,
							 (u_int8_t *) &
							 (MgmtMsg_p->Hdr.
							  SrcAddr),
							 pStaInfo->StnId);
						wlpptr->wlpd_p->
							AmpduPckReorder
							[pStaInfo->Aid].
							ExpectedSeqNo[tid][0] =
							wlpptr->wlpd_p->
							AmpduPckReorder
							[pStaInfo->Aid].
							CurrentSeqNo[tid];

						baRxInfo =
							&wlpptr->wlpd_p->
							AmpduPckReorder
							[pStaInfo->Aid];
#endif /* SOC_W906X */
						for (i = 0;
						     i <
						     MAX_BA_REORDER_BUF_SIZE;
						     i++) {
							skb_queue_purge
								(&baRxInfo->
								 ba[tid].
								 AmsduQ[i].
								 skbHead);
							baRxInfo->ba[tid].
								AmsduQ[i].
								state = 0;
						}

						*(UINT32 *) & baRxInfo->ba[tid].
							winStartB = 0;
						*(UINT32 *) & baRxInfo->ba[tid].
							storedBufCnt = 0;
						baRxInfo->ba[tid].minTime = 0;
					} else {
/** Receiver want to stop us from doing ampdu **/

					/** check which stream is it for **/
						for (i = 0;
						     i <
						     MAX_SUPPORT_AMPDU_TX_STREAM_RUNNING;
						     i++) {
							if (!MACADDR_CMP
							    (wlpptr->wlpd_p->
							     Ampdu_tx[i].
							     MacAddr,
							     &(MgmtMsg_p->Hdr.
							       SrcAddr))) {
							/** they are equal **/
								if (wlpptr->
								    wlpd_p->
								    Ampdu_tx[i].
								    AccessCat ==
								    pDelBaReqFrm->
								    ParamSet.tid
								    && wlpptr->
								    wlpd_p->
								    Ampdu_tx[i].
								    InUse ==
								    1) {
									WLDBG_INFO
										(DBG_LEVEL_0,
										 "del ba !!!! They match!!!!\n");
									/* Reset the flags so that stream can be started once traffic is back on */
									pStaInfo->
										aggr11n.
										onbytid
										[wlpptr->
										 wlpd_p->
										 Ampdu_tx
										 [i].
										 AccessCat]
										=
										0;
									pStaInfo->
										aggr11n.
										startbytid
										[wlpptr->
										 wlpd_p->
										 Ampdu_tx
										 [i].
										 AccessCat]
										=
										0;
#ifdef WIFI_DATA_OFFLOAD
									dol_sta_tx_ampdu_ctrl
										(wlpptr,
										 wlpptr->
										 wlpd_p->
										 ipc_session_id,
										 wlpptr->
										 vmacSta_p->
										 VMacEntry.
										 macId,
										 (u8
										  *)
										 pStaInfo->
										 Addr,
										 pStaInfo->
										 aggr11n.
										 threshold,
										 &pStaInfo->
										 aggr11n.
										 startbytid
										 [0]);
#endif
									pStaInfo->
										aggr11n.
										type
										&=
										~WL_WLAN_TYPE_AMPDU;
									wlFwUpdateDestroyBAStream
										(vmacSta_p->
										 dev,
										 0,
										 0,
										 i,
										 wlpptr->
										 wlpd_p->
										 Ampdu_tx
										 [i].
										 AccessCat,
										 wlpptr->
										 wlpd_p->
										 Ampdu_tx
										 [i].
										 MacAddr,
										 pStaInfo->
										 StnId);
									wlpptr->wlpd_p->Ampdu_tx[i].InUse = 0;
									wlpptr->wlpd_p->Ampdu_tx[i].TimeOut = 0;

								}
							}
						}
					}

					if (wfa_11ax_pf) {
						vmacApInfo_t *vmacSta_master_p;
						vmacSta_master_p =
							vmacSta_p->master;
						if (vmacSta_master_p->
						    dl_ofdma_para.max_sta > 0) {
							int idx = 0;
							UINT8 val[] =
								{ 0, 0, 0, 0, 0,
								  0 };

							for (i = 0;
							     i <
							     MAX_OFDMADL_STA;
							     i++) {
								if (!memcmp
								    (vmacSta_master_p->
								     ofdma_mu_sta_addr
								     [i], val,
								     IEEEtypes_ADDRESS_SIZE))
								{
									idx = i;
									continue;
								} else if
									(!memcmp
									 (pStaInfo->
									  Addr,
									  vmacSta_master_p->
									  ofdma_mu_sta_addr
									  [i],
									  IEEEtypes_ADDRESS_SIZE))
									break;
							}
							if (i <
							    vmacSta_master_p->
							    dl_ofdma_para.
							    max_sta) {
								vmacSta_master_p->
									dl_ofdma_para.
									sta_cnt--;
								memcpy(vmacSta_master_p->ofdma_mu_sta_addr[i], val, IEEEtypes_ADDRESS_SIZE);

								printk("DELBA: ofdma.sta_cnt=%d\n", vmacSta_master_p->dl_ofdma_para.sta_cnt);

								if (vmacSta_master_p->dl_ofdma_para.started) {
									printk("Set ofdma fw cmd: option=%d ru_mode=%d max_delay=%d max_sta=%d sta_cnt=%d\n", vmacSta_master_p->dl_ofdma_para.option, vmacSta_master_p->dl_ofdma_para.ru_mode, vmacSta_master_p->dl_ofdma_para.max_delay, vmacSta_master_p->dl_ofdma_para.max_sta, vmacSta_master_p->dl_ofdma_para.sta_cnt);
									printk("%s delba received\n", __FUNCTION__);
									wlFwSetOfdma_Mode
										(vmacSta_master_p->
										 dev,
										 0,
										 vmacSta_master_p->
										 dl_ofdma_para.
										 ru_mode,
										 vmacSta_master_p->
										 dl_ofdma_para.
										 max_delay,
										 vmacSta_master_p->
										 dl_ofdma_para.
										 max_sta);
								}
							}
						}
					}
				}
				break;
			case ADDBA_RESP:
				pStaInfo =
					extStaDb_GetStaInfo(vmacSta_p,
							    &(MgmtMsg_p->Hdr.
							      SrcAddr),
							    STADB_UPDATE_AGINGTIME);
				WLDBG_INFO(DBG_LEVEL_0,
					   "Inside AddBA Response receive\n");
				if (pStaInfo) {
					int i;
					vmacApInfo_t *vmacSta_master_p;

					WLDBG_INFO(DBG_LEVEL_0,
						   "Inside pStaInfo\n");

					pAddBaRspFrm =
						(IEEEtypes_ADDBA_Rsp_t *) &
						MgmtMsg_p->Body;

#ifdef MV_CPU_BE
					pAddBaRspFrm->ParamSet.u16_data =
						ENDIAN_SWAP16(pAddBaRspFrm->
							      ParamSet.
							      u16_data);
#endif
					WLDBG_INFO(DBG_LEVEL_0,
						   "**********************\n");

					WLDBG_INFO(DBG_LEVEL_0,
						   "Value of Category = %x\n",
						   pAddBaRspFrm->Category);
					WLDBG_INFO(DBG_LEVEL_0,
						   "Value of Action = %x\n",
						   pAddBaRspFrm->Action);
					WLDBG_INFO(DBG_LEVEL_0,
						   "Value of Dialog Token = %x\n",
						   pAddBaRspFrm->DialogToken);
					WLDBG_INFO(DBG_LEVEL_0,
						   "Value of StatusCode = %x\n",
						   pAddBaRspFrm->StatusCode);
					WLDBG_INFO(DBG_LEVEL_0,
						   "Value of ParamSet.BlockAckPolicy = %x, ParamSet.Tid = %x, BufferSize = %x\n",
						   pAddBaRspFrm->ParamSet.
						   BA_policy,
						   pAddBaRspFrm->ParamSet.tid,
						   pAddBaRspFrm->ParamSet.
						   BufSize);
					WLDBG_INFO(DBG_LEVEL_0,
						   "Value of Reason = %x\n",
						   pAddBaRspFrm->Timeout_val);

					for (i = 0;
					     i <
					     MAX_SUPPORT_AMPDU_TX_STREAM_RUNNING;
					     i++) {
						if (wlpptr->wlpd_p->Ampdu_tx[i].
						    DialogToken ==
						    pAddBaRspFrm->DialogToken &&
						    wlpptr->wlpd_p->Ampdu_tx[i].
						    InUse &&
						    wlpptr->wlpd_p->Ampdu_tx[i].
						    AccessCat ==
						    pAddBaRspFrm->ParamSet.
						    tid) {
							if (MACADDR_CMP
							    (wlpptr->wlpd_p->
							     Ampdu_tx[i].
							     MacAddr,
							     &(MgmtMsg_p->Hdr.
							       SrcAddr)) == 0)
								break;
						}
					}

					if (i < MAX_SUPPORT_AMPDU_TX_STREAM_RUNNING) {
/** either stream 0 or 1 is equal **/
						/*Check if a ADDBA response has been received earlier, if it has then drop the response */
						if (wlpptr->wlpd_p->Ampdu_tx[i].
						    AddBaResponseReceive == 1 &&
						    wlpptr->wlpd_p->Ampdu_tx[i].
						    DialogToken ==
						    pAddBaRspFrm->DialogToken) {
							break;
						}

						if (pAddBaRspFrm->StatusCode == 0)	//success
						{
							if (pAddBaRspFrm->
							    ParamSet.tid ==
							    wlpptr->wlpd_p->
							    Ampdu_tx[i].
							    AccessCat) {
								WLDBG_INFO
									(DBG_LEVEL_0,
									 "Creating blockack stream \n");
								if (wlpptr->
								    wlpd_p->
								    Ampdu_tx[i].
								    initTimer ==
								    1)
									TimerDisarm
										(&wlpptr->
										 wlpd_p->
										 Ampdu_tx
										 [i].
										 timer);

#ifdef SOC_W906X
								if ((*
								     (vmacSta_p->
								      Mib802dot11->
								      mib_ApMode)
								     &
								     AP_MODE_11AX)
								    &&
								    (pStaInfo->
								     he_cap_ie
								     ==
								     HE_CAPABILITIES_IE)
								    &&
								    ((*
								      (vmacSta_p->
								       Mib802dot11->
								       mib_superBA)
								      == 1) ||
								     (*
								      (vmacSta_p->
								       Mib802dot11->
								       mib_superBA)
								      == 3)) &&
								    (pAddBaRspFrm->
								     ParamSet.
								     BufSize >=
								     MAX_BA_REORDER_BUF_SIZE))
									pAddBaRspFrm->
										ParamSet.
										BufSize
										=
										MAX_BA_REORDER_BUF_SIZE;
								else if (pAddBaRspFrm->ParamSet.BufSize > 64)
									pAddBaRspFrm->
										ParamSet.
										BufSize
										=
										64;
#endif //

								if (pAddBaRspFrm->ParamSet.tid == 6)
									pAddBaRspFrm->
										ParamSet.
										BufSize
										=
										1;

								if (*
								    (vmacSta_p->
								     Mib802dot11->
								     pMib_11nAggrMode)
								    &
								    WL_MODE_AMSDU_TX_MASK)
									amsdu_bitmap
										=
										(pAddBaRspFrm->
										 ParamSet.
										 amsdu)
										?
										(*
										 (vmacSta_p->
										  Mib802dot11->
										  pMib_11nAggrMode)
										 &
										 WL_MODE_AMSDU_TX_MASK)
										:
										0;
#ifdef SOC_W906X
								/* Both TID 6 and TID 7 go to queue 6 so create BA stream with queue 6 for TID 7. */
								if (wlFwCreateBAStream(vmacSta_p->dev, pAddBaRspFrm->ParamSet.BufSize, pAddBaRspFrm->ParamSet.BufSize, (u_int8_t *) & (MgmtMsg_p->Hdr.SrcAddr), 10, wlpptr->wlpd_p->Ampdu_tx[i].AccessCat, amsdu_bitmap, 0, pStaInfo->HtElem.MacHTParamInfo, NULL, wlpptr->wlpd_p->Ampdu_tx[i].start_seqno, pStaInfo->vhtCap.cap.MaximumAmpduLengthExponent, i, (u_int16_t) pStaInfo->StnId) == SUCCESS)
#else
								if (wlFwCreateBAStream(vmacSta_p->dev, pAddBaRspFrm->ParamSet.BufSize, pAddBaRspFrm->ParamSet.BufSize, (u_int8_t *) & (MgmtMsg_p->Hdr.SrcAddr), 10, wlpptr->wlpd_p->Ampdu_tx[i].AccessCat, amsdu_bitmap, 0, pStaInfo->HtElem.MacHTParamInfo, NULL, wlpptr->wlpd_p->Ampdu_tx[i].start_seqno, pStaInfo->vhtCap.cap.MaximumAmpduLengthExponent, i) == SUCCESS)
#endif
								{
									pStaInfo->
										aggr11n.
										type
										|=
										WL_WLAN_TYPE_AMPDU;
									//only doing amsdu over ampdu if peer supported
									if ((pAddBaRspFrm->ParamSet.amsdu && (*(vmacSta_p->Mib802dot11->pMib_11nAggrMode) & WL_MODE_AMSDU_TX_MASK))
									    &&
									    (pAddBaRspFrm->
									     ParamSet.
									     tid
									     !=
									     6))
									{
										pStaInfo->
											aggr11n.
											type
											|=
											WL_WLAN_TYPE_AMSDU;
									} else {
										pStaInfo->
											aggr11n.
											type
											&=
											~WL_WLAN_TYPE_AMSDU;
									}
								} else {
								/** FW is not ready to accept addba stream **/
									//      printk("FW not ready to accept BA stream!!!\n");
									SendDelBA
										(vmacSta_p,
										 (UINT8
										  *)
										 &
										 wlpptr->
										 wlpd_p->
										 Ampdu_tx
										 [i].
										 MacAddr
										 [0],
										 wlpptr->
										 wlpd_p->
										 Ampdu_tx
										 [i].
										 AccessCat);
									pStaInfo->
										aggr11n.
										type
										&=
										~WL_WLAN_TYPE_AMPDU;
									wlpptr->wlpd_p->Ampdu_tx[i].InUse = 0;
									wlpptr->wlpd_p->Ampdu_tx[i].TimeOut = 0;
									pStaInfo->
										aggr11n.
										onbytid
										[wlpptr->
										 wlpd_p->
										 Ampdu_tx
										 [i].
										 AccessCat]
										=
										0;
									pStaInfo->
										aggr11n.
										startbytid
										[wlpptr->
										 wlpd_p->
										 Ampdu_tx
										 [i].
										 AccessCat]
										=
										0;
#ifdef WIFI_DATA_OFFLOAD
									dol_sta_tx_ampdu_ctrl
										(wlpptr,
										 wlpptr->
										 wlpd_p->
										 ipc_session_id,
										 wlpptr->
										 vmacSta_p->
										 VMacEntry.
										 macId,
										 (u8
										  *)
										 pStaInfo->
										 Addr,
										 pStaInfo->
										 aggr11n.
										 threshold,
										 &pStaInfo->
										 aggr11n.
										 startbytid
										 [0]);
#endif
									//fall back to amsdu    
									if (*
									    (vmacSta_p->
									     Mib802dot11->
									     pMib_11nAggrMode)
									    &
									    WL_MODE_AMSDU_TX_MASK)
									{
										pStaInfo->
											aggr11n.
											type
											|=
											WL_WLAN_TYPE_AMSDU;
									}
								}

								if (wfa_11ax_pf) {
									vmacSta_master_p
										=
										vmacSta_p->
										master;
									if (vmacSta_master_p->dl_ofdma_para.max_sta > 0) {
										int idx = 0;
										UINT8 val[] = { 0, 0, 0, 0, 0, 0 };

										for (i = 0; i < MAX_OFDMADL_STA; i++) {
											if (!memcmp(vmacSta_master_p->ofdma_mu_sta_addr[i], val, IEEEtypes_ADDRESS_SIZE)) {
												idx = i;
												continue;
											} else if (!memcmp(pStaInfo->Addr, vmacSta_master_p->ofdma_mu_sta_addr[i], IEEEtypes_ADDRESS_SIZE))
												break;
										}
										if (i >= MAX_OFDMADL_STA) {
											/* new sta with BA resp */

											vmacSta_master_p->
												dl_ofdma_para.
												sta_cnt++;

											if (vmacSta_master_p->dl_ofdma_para.sta_cnt <= vmacSta_master_p->dl_ofdma_para.max_sta) {
												memcpy(vmacSta_master_p->ofdma_mu_sta_addr[idx], pStaInfo->Addr, IEEEtypes_ADDRESS_SIZE);
												//      mwl_hex_dump(pStaInfo->Addr, IEEEtypes_ADDRESS_SIZE);
											}
										}

										printk("ADDBA_RESP: ofdma.sta_cnt=%d\n", vmacSta_master_p->dl_ofdma_para.sta_cnt);
										if (vmacSta_master_p->dl_ofdma_para.sta_cnt == vmacSta_master_p->dl_ofdma_para.max_sta) {
											printk("Set ofdma fw cmd: option=%d ru_mode=%d max_delay=%d max_sta=%d sta_cnt=%d\n", vmacSta_master_p->dl_ofdma_para.option, vmacSta_master_p->dl_ofdma_para.ru_mode, vmacSta_master_p->dl_ofdma_para.max_delay, vmacSta_master_p->dl_ofdma_para.max_sta, vmacSta_master_p->dl_ofdma_para.sta_cnt);

											vmacSta_master_p->
												dl_ofdma_para.
												all_connected
												=
												jiffies;

											if (!vmacSta_master_p->dl_ofdma_para.started && vmacSta_master_p->dl_ofdma_para.postpone_time == 0) {
												printk("%s\n", __FUNCTION__);
												wlFwSetOfdma_Mode
													(vmacSta_master_p->
													 dev,
													 vmacSta_master_p->
													 dl_ofdma_para.
													 option,
													 vmacSta_master_p->
													 dl_ofdma_para.
													 ru_mode,
													 vmacSta_master_p->
													 dl_ofdma_para.
													 max_delay,
													 vmacSta_master_p->
													 dl_ofdma_para.
													 max_sta);
												vmacSta_master_p->
													dl_ofdma_para.
													started
													=
													jiffies;
											} else if (vmacSta_master_p->dl_ofdma_para.started) {
												printk("%s\n", __FUNCTION__);
												wlFwSetOfdma_Mode
													(vmacSta_master_p->
													 dev,
													 vmacSta_master_p->
													 dl_ofdma_para.
													 option,
													 vmacSta_master_p->
													 dl_ofdma_para.
													 ru_mode,
													 vmacSta_master_p->
													 dl_ofdma_para.
													 max_delay,
													 vmacSta_master_p->
													 dl_ofdma_para.
													 max_sta);
											}
										}
									}
								}
							} else {
								WLDBG_INFO
									(DBG_LEVEL_0,
									 "Invalid block ack response \n");
							}
							wlpptr->wlpd_p->
								Ampdu_tx[i].
								AddBaResponseReceive
								= 1;
						} else {
						/** addba fail failure status code , clear the stream**/
							if (wlpptr->wlpd_p->
							    Ampdu_tx[i].
							    initTimer == 1)
								TimerDisarm
									(&wlpptr->
									 wlpd_p->
									 Ampdu_tx
									 [i].
									 timer);

							pStaInfo->aggr11n.
								startbytid
								[wlpptr->
								 wlpd_p->
								 Ampdu_tx[i].
								 AccessCat] = 1;
							wlpptr->wlpd_p->
								Ampdu_tx[i].
								DialogToken = 0;
							wlpptr->wlpd_p->
								Ampdu_tx[i].
								InUse = 0;
							wlpptr->wlpd_p->
								Ampdu_tx[i].
								AccessCat = 0;
							wlpptr->wlpd_p->
								Ampdu_tx[i].
								TimeOut = 0;
						}
					}
				}
				break;

			default:
				break;
			}
			break;
		case DLP:
			switch (QosAct) {
			case DLP_REQ:
				ProcessDlpReq(vmacSta_p,
					      (macmgmtQ_MgmtMsg_t *) MgmtMsg_p);
				break;
			case DLP_RESP:
				ProcessDlpRsp(vmacSta_p,
					      (macmgmtQ_MgmtMsg_t *) MgmtMsg_p);
				break;
			case DLP_TEAR_DOWN:
				ProcessDlpTeardown(vmacSta_p,
						   (macmgmtQ_MgmtMsg_t *)
						   MgmtMsg_p);
				break;
			default:
				break;
			}
			break;

		case VHT:
			switch (QosAct) {
			case OPERATING_MODE_NOTIFICATION:
				pStaInfo =
					extStaDb_GetStaInfo(vmacSta_p,
							    &(MgmtMsg_p->Hdr.
							      SrcAddr),
							    STADB_UPDATE_AGINGTIME);
				if (pStaInfo) {
					pVHTOpMode =
						(IEEEtypes_VHT_op_mode_action_t
						 *) & MgmtMsg_p->Body;

					if (pVHTOpMode->OperatingMode.
					    RxNssType == 0) {
						vht_NewRxChannelWidth =
							pVHTOpMode->
							OperatingMode.
							ChannelWidth;
						vht_NewRxNss = pVHTOpMode->OperatingMode.RxNss + 1;	//In IE199, 0:Nss1, 1:Nss2....So we plus 1 to become 1:Nss1, 2:Nss2
					}
					/*Beamforming related matters */
					else {
						/*TODO: Hard coded for now to pass wifi 7/19/2013 */
						vht_NewRxChannelWidth = 2;	//0:20Mhz, 1:40Mhz, 2:80Mhz, 3:160 or 80+80Mhz
						vht_NewRxNss = 3;	//1:1Nss, 2:2Nss, 3:3Nss
					}
#ifdef SOC_W906X
					wlFwSetVHTOpMode(vmacSta_p->dev,
							 pStaInfo->StnId,
							 vht_NewRxChannelWidth,
							 vht_NewRxNss);
#else
					wlFwSetVHTOpMode(vmacSta_p->dev,
							 &(MgmtMsg_p->Hdr.
							   SrcAddr),
							 vht_NewRxChannelWidth,
							 vht_NewRxNss);
#endif

				}
				break;
			default:
				break;
			}
			break;
			//twt
#ifdef AP_TWT
		case S1G:	//process twt
			//pStaInfo = extStaDb_GetStaInfo(vmacSta_p, &(MgmtMsg_p->Hdr.SrcAddr), STADB_UPDATE_AGINGTIME);
			printk("S1G Qos Action:%u\n", QosAct);
			switch (QosAct) {
			case TWT_SETUP:
				{
					ProcessTWTsetup(vmacSta_p,
							(macmgmtQ_MgmtMsg_t *)
							MgmtMsg_p);
				}
				break;
			case TWT_TEARDOWN:
				{
					ProcessTWTteardown(vmacSta_p,
							   (macmgmtQ_MgmtMsg_t
							    *) MgmtMsg_p);
				}
				break;
			case TWT_INFO:
				{
					ProcessTWTInformation(vmacSta_p,
							      (macmgmtQ_MgmtMsg_t
							       *) MgmtMsg_p);
				}
				break;
			default:
				printk("unhandled S1G Action type: %u\n",
				       QosAct);
				break;
			}
			break;
#endif
		default:
			break;
		}
	}
#endif //QOS_FEATURE

#ifdef IEEE80211K

	int macMgmtMlme_RrmAct(vmacApInfo_t * vmacSta_p,
			       macmgmtQ_MgmtMsg3_t * MgmtMsg_p) {
		MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
		struct IEEEtypes_InfoElementHdr_t *ie;
		macmgmtQ_MgmtMsg2_t *MgmtResp_p;
		struct IEEEtypes_Neighbor_Report_Element_t *NeighborRpt_Element;
		struct IEEEtypes_Neighbor_Report_Element_t *nlistbyssid = NULL;
		extStaDb_StaInfo_t *StaInfo;
		struct sk_buff *skb;
		neighbor_list_entrie_t **nlist = NULL;
		int nb_num = 0;

		if (MgmtMsg_p->Body.Action.Category != AC_RADIO_MEASUREMENT ||
		    !*(mib->mib_rrm))
			return FALSE;

		printk("Received RRM Action - :%d\n",
		       MgmtMsg_p->Body.Action.Action);
		/* Process WNM actions via Hostapd */
		if (mib->mib_conf_capab->rrm) {
			macmgmtQ_MgmtMsg3_t *msgbuf;

			if ((msgbuf =
			     (macmgmtQ_MgmtMsg3_t *) wl_kmalloc(MgmtMsg_p->Hdr.
								FrmBodyLen + 2,
								GFP_ATOMIC)) ==
			    NULL) {
				WLDBG_INFO(DBG_LEVEL_15,
					   "receiveWlanMsg: failed to alloc msg buffer\n");
			} else {
				memset((UINT8 *) msgbuf, 0,
				       MgmtMsg_p->Hdr.FrmBodyLen + 2);
				memcpy(&(msgbuf->Hdr), &(MgmtMsg_p->Hdr),
				       sizeof(IEEEtypes_MgmtHdr3_t));
				memcpy(&(msgbuf->Hdr.Rsrvd), &(MgmtMsg_p->Body),
				       MgmtMsg_p->Hdr.FrmBodyLen -
				       sizeof(IEEEtypes_MgmtHdr3_t) +
				       sizeof(UINT16));
				msgbuf->Hdr.FrmBodyLen -= ETH_ALEN;	// Remove Addr4 bssid length here.
#ifdef CFG80211
				mwl_cfg80211_rx_mgmt(vmacSta_p->dev,
						     &(msgbuf->Hdr.FrmCtl),
						     msgbuf->Hdr.FrmBodyLen, 0);
#else /* CFG80211 */
				mwl_wext_rx_mgmt(vmacSta_p->dev, msgbuf,
						 msgbuf->Hdr.FrmBodyLen +
						 sizeof(UINT16));
#endif /* CFG80211 */
				wl_kfree(msgbuf);
			}
			return TRUE;
		}

		switch (MgmtMsg_p->Body.Action.Action) {
		case AF_RM_NEIGHBOR_REQUEST:
			/* TO DO ... scan and generate neighbor report */
			printk("Received RRM Action - NEIGHBOR_REPORT REQUEST ...\n");
			StaInfo =
				extStaDb_GetStaInfo(vmacSta_p,
						    &(MgmtMsg_p->Hdr.SrcAddr),
						    1);
			if (StaInfo == NULL) {
				printk("Failed to get StaInfo...\n");
				return FALSE;
			}

			nlist = (neighbor_list_entrie_t **) nlist_entry;
			/* SSID is not checked fow now */
			if (MgmtMsg_p->Hdr.FrmBodyLen >
			    sizeof(IEEEtypes_MgmtHdr2_t) + 3) {
				ie = (struct IEEEtypes_InfoElementHdr_t *)
					&MgmtMsg_p->Body.Action.Data;
				if (ie != NULL) {
					switch (ie->ElementId) {
					case SSID:
						{
							struct IEEEtypes_SsIdElement_t *ssid = NULL;
							UINT8 scannedSSID
								[IEEEtypes_SSID_SIZE];

							ssid = (IEEEtypes_SsIdElement_t *) ie;
							if (ssid->Len >=
							    IEEEtypes_SSID_SIZE)
							{
								break;
							}
							memset(&scannedSSID[0],
							       0,
							       IEEEtypes_SSID_SIZE);
							memcpy(&scannedSSID[0],
							       &ssid->SsId[0],
							       ssid->Len);
							nb_num = MSAN_get_neighbor_bySSID(ssid, &nlistbyssid);
						}
						break;
					case PROPRIETARY_IE:
						printk("Neighbor Report_Req Proprietary_IE...\n");
					default:
						nb_num = MSAN_get_neighbor_byDefault(&nlistbyssid);
						break;
					}
				}
			}
			if ((skb = mlmeApiPrepMgtMsg2(IEEE_MSG_QOS_ACTION,
						      &MgmtMsg_p->Hdr.SrcAddr,
						      &MgmtMsg_p->Hdr.DestAddr,
						      3 +
						      (sizeof
						       (struct
							IEEEtypes_Neighbor_Report_Element_t)
						       * nb_num)))
			    == NULL) {
				WLDBG_INFO(DBG_LEVEL_7,
					   "Failed to allocate buffer ...\n");
				return FALSE;
			}
			MgmtResp_p = (macmgmtQ_MgmtMsg2_t *) skb->data;
			MgmtResp_p->Body.Action.Category = AC_RADIO_MEASUREMENT;
			MgmtResp_p->Body.Action.Action =
				AF_RM_NEIGHBOR_RESPONSE;
			MgmtResp_p->Body.Action.DialogToken =
				MgmtMsg_p->Body.Action.DialogToken;
			if (nb_num > 0) {
				NeighborRpt_Element =
					(struct
					 IEEEtypes_Neighbor_Report_Element_t *)
					&MgmtResp_p->Body.Action.Data.
					NeighborReqportElemes[0];
				memcpy(NeighborRpt_Element, nlistbyssid,
				       sizeof
				       (IEEEtypes_Neighbor_Report_Element_t) *
				       nb_num);
			}
			if (txMgmtMsg(vmacSta_p->dev, skb) != OS_SUCCESS) {
				wl_free_skb(skb);
				return FALSE;
			}
			break;

		case AF_RM_NEIGHBOR_RESPONSE:
			/* does not expect report resp for AP */
			printk("received RRM Action - neighbor report response ...\n");
			break;

		case AF_RM_MEASUREMENT_REQUEST:
			break;

		case AF_RM_MEASUREMENT_REPORT:
			{
				struct IEEEtypes_MeasurementReportElement_t
					*ie_p = NULL;
				UINT16 msg_len = 0;

				printk("Received RRM Action - AF_RM_MEASUREMENT_REPORT ...\n");
				ie_p = (struct
					IEEEtypes_MeasurementReportElement_t *)
					&MgmtMsg_p->Body.Action.Data.
					MeasurementReport[0];
				if (ie_p == NULL) {
					break;
				}
				msg_len =
					sizeof(struct IEEEtypes_MgmtHdr3_t) + 3;

#ifdef MULTI_AP_SUPPORT
				MAP_tlv_Resp_process(vmacSta_p,
						     (void *)MgmtMsg_p,
						     (IEEEtypes_MacAddr_t *) &
						     (MgmtMsg_p->Hdr.SrcAddr),
						     0);
#endif /* MULTI_AP_SUPPORT */

				while (msg_len < MgmtMsg_p->Hdr.FrmBodyLen) {
					if (ie_p == NULL) {
						break;
					}
					printk("msg_len (%d,%d) type:%d\n",
					       msg_len,
					       MgmtMsg_p->Hdr.FrmBodyLen,
					       ie_p->Type);
					if (ie_p->Mode.Refused) {
						break;
					}
					switch (ie_p->Type) {
					case TYPE_REP_BCN:
						{
							struct IEEEtypes_BeaconReport_t *bcn_rep = &ie_p->Report.BcnReport;

							printk("bcnreport bssid=0x%2x:0x%2x:0x%2x:0x%2x:0x%2x:0x%2x channel:%d RCPI:%d, RSNI:%d\n", bcn_rep->Bssid[0], bcn_rep->Bssid[1], bcn_rep->Bssid[2], bcn_rep->Bssid[3], bcn_rep->Bssid[4], bcn_rep->Bssid[5], bcn_rep->Channel, bcn_rep->RCPI_value, bcn_rep->RSNI_value);
						}
						break;
					default:
						break;
					}
					msg_len += ie_p->Len + 2;
					ie_p = (struct
						IEEEtypes_MeasurementReportElement_t
						*)((UINT8 *) ie_p + ie_p->Len +
						   2);
				}
			}
			break;
		default:
			break;
		}
		return TRUE;
	}

	int macMgmtMlme_WNMAct(vmacApInfo_t * vmacSta_p,
			       macmgmtQ_MgmtMsg3_t * MgmtMsg_p) {
		MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
		struct IEEEtypes_Neighbor_Report_Element_t __maybe_unused
			*nlistbyssid = NULL;
		extStaDb_StaInfo_t __maybe_unused *StaInfo;
		int __maybe_unused nb_num = 0;

		if (MgmtMsg_p->Body.Action.Category != AC_WNM)
			return FALSE;

		printk("Received WNM Action - :%d\n",
		       MgmtMsg_p->Body.Action.Action);

		switch (MgmtMsg_p->Body.Action.Action) {
#ifdef AP_STEERING_SUPPORT
		case AF_WNM_BTM_QUERY:
			{
				struct IEEEtypes_BSS_TM_Query_t *bss_tm_query_p
					= NULL;
				struct IEEEtypes_BSS_TM_Request_t BSS_TM_Req;

				printk("Received AF_WNM_BTM_QUERY ...\n");
				/* Process WNM actions via Hostapd */
				if (mib->mib_conf_capab->rrm) {
					break;
				}

				StaInfo =
					extStaDb_GetStaInfo(vmacSta_p,
							    &MgmtMsg_p->Hdr.
							    SrcAddr,
							    STADB_DONT_UPDATE_AGINGTIME);
				if (StaInfo == NULL) {
					printk("AF_WNM_BTM_QUERY Failed to get StaInfo...\n");
					break;
				}

				if (StaInfo->ExtCapElem.ExtCap.BSSTransition ==
				    0) {
					printk("AF_WNM_BTM_QUERY STA does not support BTM Transition, skip...\n");
					break;
				}

				bss_tm_query_p =
					(struct IEEEtypes_BSS_TM_Query_t *)
					&MgmtMsg_p->Body.Action.Data;
				if (bss_tm_query_p->QueryReason < 20) {
					UINT16 msg_len = MgmtMsg_p->Hdr.FrmBodyLen - sizeof(struct IEEEtypes_MgmtHdr3_t) + 2;	/* 2 is length size */
					UINT8 *var_ptr =
						bss_tm_query_p->variable;
					struct IEEEtypes_Neighbor_Report_Element_t *PrefList_p = (struct IEEEtypes_Neighbor_Report_Element_t *)var_ptr;

					/* Query Reason 19 is "Preferred BSS Transition Candidate List Included" */
					MSAN_clean_neighbor_list();
					var_ptr = bss_tm_query_p->variable;
					while (msg_len >=
					       sizeof(struct
						      IEEEtypes_Neighbor_Report_Element_t)
					       && (PrefList_p->ElementId ==
						   NEIGHBOR_REPORT)) {
						nb_num = MSAN_get_neighbor_byAddr((IEEEtypes_MacAddr_t *) PrefList_p->Bssid, &nlistbyssid);
						if (!nb_num) {
							printk("BTM_QUERY: Cannot found %s in neighbor list\n", mac_display(PrefList_p->Bssid));
						}
						msg_len -= PrefList_p->Len - 2;	/* 2 is Element ID & length size */
						var_ptr += PrefList_p->Len + 2;
						PrefList_p =
							(struct
							 IEEEtypes_Neighbor_Report_Element_t
							 *)var_ptr;
					}
				}
				if (!nb_num) {
					nb_num = MSAN_get_neighbor_bySSID
						(&vmacSta_p->macSsId,
						 &nlistbyssid);
					if (!nb_num) {
						printk("BTM_QUERY: Cannot found %s in neighbor list\n", vmacSta_p->macSsId.SsId);
					}
				}
				memset(&BSS_TM_Req, 0,
				       sizeof(struct
					      IEEEtypes_BSS_TM_Request_t));
				if (nb_num) {
					BSS_TM_Req.PrefCandiListInc = 1;
				}
				BSS_TM_Req.Abridged =
					mib->mib_BSSTMRequest->Abridged;
				BSS_TM_Req.DisassocImm =
					mib->mib_BSSTMRequest->DisassocImm;
				BSS_TM_Req.BSSTermiInc =
					mib->mib_BSSTMRequest->BSSTermiInc;
				BSS_TM_Req.ESSDisassocImm =
					mib->mib_BSSTMRequest->ESSDisassocImm;
				BSS_TM_Req.disassoc_timer =
					mib->mib_BSSTMRequest->disassoc_timer;
				BSS_TM_Req.validity_interval =
					mib->mib_BSSTMRequest->
					validity_interval;
				if (bsstm_send_request
				    (vmacSta_p->dev,
				     (UINT8 *) & MgmtMsg_p->Hdr.SrcAddr,
				     &BSS_TM_Req) == FALSE) {
					printk("BTM_QUERY send BTM REQ failed\n");
				}
			}
			break;

		case AF_WNM_BTM_RESPONSE:
			{
				IEEEtypes_BSS_TM_Resp_t *bss_tm_resp_p = NULL;
				static const char *tag = "1905_BTM";
				unsigned char buf[IW_CUSTOM_MAX] = { 0 };
				union iwreq_data wreq;
				UINT16 msg_len = 0;

				StaInfo =
					extStaDb_GetStaInfo(vmacSta_p,
							    &(MgmtMsg_p->Hdr.
							      SrcAddr), 1);
				if (StaInfo == NULL) {
					printk("BTM_RESPONSE Failed to get StaInfo...\n");
					return FALSE;
				}
				TimerDisarm(&StaInfo->btmreq_disassocTimer);
				StaInfo->btmreq_count = 0;
				bss_tm_resp_p =
					(struct IEEEtypes_BSS_TM_Resp_t *)
					&MgmtMsg_p->Body.Action.Data;
				msg_len =
					sizeof(struct IEEEtypes_BSS_TM_Resp_t);
				printk("Receive BTM_RESPONSE, Status Code:%d, ",
				       bss_tm_resp_p->StatusCode);
				if (bss_tm_resp_p->StatusCode == 0) {
					msg_len += sizeof(IEEEtypes_MacAddr_t);
					printk("Target BSS:%s",
					       mac_display(bss_tm_resp_p->
							   variable));
				}
				printk("\n");

				/* send BTM response to al_entity */
				snprintf(buf, sizeof(buf), "%s", tag);
				memcpy(&buf[strlen(tag)],
				       &(MgmtMsg_p->Hdr.SrcAddr),
				       sizeof(IEEEtypes_MacAddr_t));
				memcpy(&buf
				       [strlen(tag) +
					sizeof(IEEEtypes_MacAddr_t)],
				       bss_tm_resp_p, msg_len);
				memset(&wreq, 0, sizeof(wreq));
				wreq.data.length =
					strlen(tag) +
					sizeof(IEEEtypes_MacAddr_t) + msg_len;
				if (vmacSta_p->dev->flags & IFF_RUNNING) {
					wireless_send_event(vmacSta_p->dev,
							    IWEVCUSTOM, &wreq,
							    buf);
				}
			}
			break;
#endif //AP_STEERING_SUPPORT

		default:
			break;
		}

		return TRUE;
	}

#endif
/******************************************************************************
*
* Name: macMgmtMlme_ProbeRsp
*
* Description:
*    This routine handles a response from another station in an IBSS or an
*    AP in a BSS to a prior probe request.
*
* Conditions For Use:
*    All software components have been initialized and started.
*
* Arguments:
*    Arg1 (i  ): MgmtMsg_p - Pointer to an 802.11 management message
*                            containing a probe response
*
* Return Value:
*    None.
*
* Notes:
*    None.
*
* PDL:

* END PDL
*
*****************************************************************************/
	extern void macMgmtMlme_ProbeRsp(macmgmtQ_MgmtMsg_t * MgmtMsg_p) {
	}

/******************************************************************************
*
* Name: macMgmtMlme_ReassociateRsp
*
* Description:
*    This routine handles a response from an AP to a prior reassociate request.
*
* Conditions For Use:
*    All software components have been initialized and started.
*
* Arguments:
*    Arg1 (i  ): MgmtMsg_p - Pointer to an 802.11 management message
*                            containing a reassociate response
*
* Return Value:
*    None.
*
* Notes:
*    None.
*
* PDL:
* END PDL
*
*****************************************************************************/
	extern void macMgmtMlme_ReassociateRsp(macmgmtQ_MgmtMsg_t * MgmtMsg_p) {
	}

#define MAX_SUPP_RATE_SET_NUM	8

	void PrepareRateElements(vmacApInfo_t * vmacSta_p,
				 IEEEtypes_StartCmd_t * StartCmd_p) {
		MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;

		IEEEtypes_SuppRatesElement_t *SuppRateSet_p =
			&(vmacSta_p->SuppRateSet);
#ifdef ERP
		IEEEtypes_ExtSuppRatesElement_t *ExtSuppRateSet_p =
			&(vmacSta_p->ExtSuppRateSet);
#endif

		UINT32 i, j, k, l;
		UINT32 Index;
		UINT8 MaxRate;

		i = j = k = l = 0;
		LowestBasicRateIndex = 0;
		HighestBasicRateIndex = 0;
		LowestBasicRate = 108;	/* 54 Mbit */

		if (!Is5GBand(*(mib->mib_ApMode))) {
			MaxRate = IEEEtypes_MAX_DATA_RATES_G;
			HighestBasicRate = 2;	/* 1 Mbit */
		} else {
			MaxRate = IEEEtypes_MAX_DATA_RATES_A;
			HighestBasicRate = 12;
		}

		LowestBasicRateIndexB = 0;
		HighestBasicRateIndexB = 0;
		LowestBasicRateB = 22;
		HighestBasicRateB = 2;

		for (i = 0; i < MaxRate; i++) {
			if (StartCmd_p->BssBasicRateSet[i] > 1 &&
			    StartCmd_p->BssBasicRateSet[i] <= 127) {
				if ((Index =
				     hw_GetPhyRateIndex(vmacSta_p,
							StartCmd_p->
							BssBasicRateSet[i]))
				    < MaxRate)
					/* valid rate for the Phy */
				{

					BasicRateSetIndex[i] = Index;
					BasicRateSet[i] =
						StartCmd_p->BssBasicRateSet[i];

					if (BasicRateSet[i] <= LowestBasicRate) {
						LowestBasicRate =
							BasicRateSet[i];
						LowestBasicRateIndex = Index;
					}
					if (BasicRateSet[i] >= HighestBasicRate) {
						HighestBasicRate =
							BasicRateSet[i];
						HighestBasicRateIndex = Index;
					}

					if (!Is5GBand(*(mib->mib_ApMode))) {
						if (BasicRateSet[i] == 2 || BasicRateSet[i] == 4 || BasicRateSet[i] == 11 || BasicRateSet[i] == 22) {	/*It is B rate */
							if (BasicRateSet[i] <=
							    LowestBasicRateB) {
								LowestBasicRateB
									=
									BasicRateSet
									[i];
								LowestBasicRateIndexB
									= Index;
							}
							if (BasicRateSet[i] >=
							    HighestBasicRateB) {
								HighestBasicRateB
									=
									BasicRateSet
									[i];
								HighestBasicRateIndexB
									= Index;
							}
						}
					}
				} else {	/* the rate is not a valid state for the PHY */

					/* Send Invalid parameter reply */
				}
			} else {
				/* Send invalid parameters reply */
				break;
			}
		}
		BasicRateSetLen = i;
		LowestOpRateIndex = 0;
		HighestOpRateIndex = 0;

		LowestOpRate = 108;	/* 54 Mbit */

		if (!Is5GBand(*(mib->mib_ApMode)))
			HighestOpRate = 2;	/* 1 Mbit */
		else
			HighestOpRate = 12;	/* 6 Mbit */

		for (i = 0; i < MaxRate; i++) {
			if (StartCmd_p->OpRateSet[i] > 1 &&
			    StartCmd_p->OpRateSet[i] <= 127) {
				if ((Index =
				     hw_GetPhyRateIndex(vmacSta_p,
							StartCmd_p->
							OpRateSet[i]))
				    < MaxRate)
					/* valid rate for the Phy */
				{
					OpRateSetIndex[i] = Index;
					OpRateSet[i] = StartCmd_p->OpRateSet[i];

					if (OpRateSet[i] <= LowestOpRate) {
						LowestOpRate = OpRateSet[i];
						LowestOpRateIndex = Index;
					}
					if (OpRateSet[i] >= HighestOpRate) {
						HighestOpRate = OpRateSet[i];
						HighestOpRateIndex = Index;
					}
				} else {	/* the rate is not a valid state for the PHY */

					/* Send Invalid parameter reply */
				}
			} else {
				break;
			}
		}
		OpRateSetLen = i;

		/* Form the supported rate set, and Ext supp rate set for sending in assoc resp msg */
		SuppRateSet_p->ElementId = SUPPORTED_RATES;
		ExtSuppRateSet_p->ElementId = EXT_SUPPORTED_RATES;

		for (i = 0; i < OpRateSetLen; i++) {
			if (*(mib->mib_ApMode) == AP_MODE_B_ONLY) {
				if (hw_GetPhyRateIndex(vmacSta_p, OpRateSet[i])
				    > HIGHEST_11B_RATE_REG_INDEX)
					continue;
			}
			for (j = 0; j < BasicRateSetLen; j++) {
				if (OpRateSet[i] == BasicRateSet[j]) {
					if (k < MAX_SUPP_RATE_SET_NUM) {
						SuppRateSet_p->Rates[k++]
							= OpRateSet[i] |
							IEEEtypes_BASIC_RATE_FLAG;
					} else {
						ExtSuppRateSet_p->Rates[l++]
							= OpRateSet[i] |
							IEEEtypes_BASIC_RATE_FLAG;
					}
					break;
				}
			}
			if (j == BasicRateSetLen) {
				if (k < MAX_SUPP_RATE_SET_NUM) {
					SuppRateSet_p->Rates[k++] =
						OpRateSet[i];
				} else {
					ExtSuppRateSet_p->Rates[l++]
						= OpRateSet[i];
				}
			}
		}
		SuppRateSet_p->Len = k;
		ExtSuppRateSet_p->Len = l;
	}
/******************************************************************************
*
* Name: macMgmtMlme_ResetCmd
*
* Description:
*    Routine to handle a command to perform a reset, which resets the MAC
*    to initial conditions.
*
* Conditions For Use:
*    All software components have been initialized and started.
*
* Arguments:
*    Arg1 (i  ): ResetCmd_p - Pointer to a reset command
*
* Return Value:
*    None.
*
* Notes:
*    None.
*
* PDL:
*    Clear the External Station Info data store of all entries
*    Set the station MAC Management state to IDLE
*    Send a reset confirmation to the SME with the result status
* END PDL
*
*****************************************************************************/
	extern void macMgmtMlme_ResetCmd(vmacApInfo_t * vmacSta_p,
					 IEEEtypes_ResetCmd_t * ResetCmd_p) {

		if (ResetCmd_p->SetDefaultMIB) {
			/* reset the MIB */
		}
		extStaDb_RemoveAllStns(vmacSta_p,
				       IEEEtypes_REASON_DEAUTH_LEAVING);
		if (!ResetCmd_p->quiet) {
#ifdef SOC_W906X
			macMgmtMlme_SendDeauthenticateMsg(vmacSta_p, &bcast,
							  MCBC_STN_ID,
							  IEEEtypes_REASON_DEAUTH_LEAVING,
							  FALSE);
#else
			macMgmtMlme_SendDeauthenticateMsg(vmacSta_p, &bcast,
							  MCBC_STN_ID,
							  IEEEtypes_REASON_DEAUTH_LEAVING);
#endif
		}

		if (vmacSta_p->Mib802dot11->Privacy->RSNEnabled) {
			SendKeyMgmtInitEvent(vmacSta_p);
		} else {
			KeyMgmtReset(vmacSta_p);
		}

#ifdef QOS_FEATURE_REMOVE
		if (*(mib->QoSOptImpl)) {
			wlQosSetQAsCAPQ(CAP_VO_Q);
			wlQosSetQAsCAPQ(CAP_VI_Q);
		}
#endif

		vmacSta_p->bOnlyStnCnt = 0;
		vmacSta_p->BarkerPreambleStnCnt = 0;
		SendStartCmd(vmacSta_p);

		return;
	}

	void MonitorTimerInit(vmacApInfo_t * vmacSta_p) {
		extern void MonitorTimerProcess(UINT8 *);

		if (vmacSta_p->dev->flags & IFF_RUNNING) {
			TimerInit(&vmacSta_p->monTimer);
			TimerFireIn(&vmacSta_p->monTimer, 1,
				    &MonitorTimerProcess,
				    (unsigned char *)vmacSta_p,
				    MONITER_PERIOD_1SEC);
		}
	}

/******************************************************************************
*
* Name: macMgmtMlme_StartCmd
*
* Description:
*    Routine to handle a command to start a BSS.
*
* Conditions For Use:
*    All software components have been initialized and started.
*
* Arguments:
*    Arg1 (i  ): StartCmd_p - Pointer to a start command
*
* Return Value:
*    None.
*
* Notes:
*    None.
*
* PDL:
*    If any of the given start parameters are invalid Then
*       Send a start confirmation to the SME with the failure status
*    End If
*
* END PDL
*
*****************************************************************************/
	extern void macMgmtMlme_StartCmd(vmacApInfo_t * vmacSta_p,
					 IEEEtypes_StartCmd_t * StartCmd_p) {
		MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
		MIB_802DOT11 *mibshadow = vmacSta_p->ShadowMib802dot11;
		vmacSta_p->macSsId.ElementId = SSID;
		vmacSta_p->macSsId.Len =
			CopySsId(vmacSta_p->macSsId.SsId, StartCmd_p->SsId);

		vmacSta_p->macSsId2.ElementId = SSID;
		vmacSta_p->macSsId2.Len =
			CopySsId(vmacSta_p->macSsId2.SsId, StartCmd_p->SsId2);

		PrepareRateElements(vmacSta_p, StartCmd_p);

		/* Processing the Cap Info fields */
		vmacSta_p->macCapInfo = StartCmd_p->CapInfo;

		/* Make sure the reserved bits are zero */
#ifdef IEEE80211K
		if (*(mib->mib_rrm))
			vmacSta_p->macCapInfo.Rrm = 1;
		else
#endif
			vmacSta_p->macCapInfo.Rrm = 0;

		vmacSta_p->macCapInfo.Rsrvd2 = 0;
		vmacSta_p->macCapInfo.DsssOfdm = 0;
#ifndef QOS_FEATURE
		vmacSta_p->macCapInfo.Rsrvd3 = 0;
#endif
		if (vmacSta_p->macCapInfo.CfPollable == 1 &&
		    vmacSta_p->macCapInfo.CfPollRqst == 0) {
		}
		if (vmacSta_p->macCapInfo.CfPollable == 0 &&
		    vmacSta_p->macCapInfo.CfPollRqst == 1) {
		}
		/* Set the Cf parameter Set */
		if (StartCmd_p->SsParamSet.CfParamSet.ElementId == CF_PARAM_SET
		    && StartCmd_p->SsParamSet.CfParamSet.Len == 6) {
		}
		/* Set the Phy parameter set */

		/* Update the HW MAC registers with the new values */
		/* Copy SSID and BSSID registers */

		/* Set the specified channel  */

		if (StartCmd_p->PhyParamSet.DsParamSet.ElementId ==
		    DS_PARAM_SET) {
		}
		if (*(mib->mib_ApMode) != AP_MODE_B_ONLY &&
		    *(mib->mib_ApMode) != AP_MODE_A_ONLY) {
			if (*(mib->mib_forceProtectiondisable)) {
				*(mib->mib_ErpProtEnabled) = FALSE;
				*(mibshadow->mib_ErpProtEnabled) = FALSE;	//Update shadowmib too to prevent default shadowmib from overwriting mib during commit
			} else {
				*(mib->mib_ErpProtEnabled) = TRUE;
				*(mibshadow->mib_ErpProtEnabled) = TRUE;
			}
		}

		MonitorTimerInit(vmacSta_p);

		return;
	}

	void Disable_MonitorTimerProcess(vmacApInfo_t * vmacSta_p) {
		TimerRemove(&vmacSta_p->monTimer);
	}

/*============================================================================= */
/*                         CODED PRIVATE PROCEDURES */
/*============================================================================= */

/******************************************************************************
*
* Name: isSsIdMatch
*
* Description:
*
* Conditions For Use:
*    All software components have been initialized and started.
*
* Arguments:
*    Arg1 (i  ): 
* Return Value:
*    None.
*
* Notes:
*    None.
*
* PDL:

* END PDL
*
*****************************************************************************/
	WL_STATUS isSsIdMatch(IEEEtypes_SsIdElement_t * SsId1,
			      IEEEtypes_SsIdElement_t * SsId2) {
		if (SsId1 && SsId2) {
			if (SsId1->Len == SsId2->Len &&
			    !memcmp(SsId1->SsId, SsId2->SsId, SsId1->Len)) {
				return (OS_SUCCESS);
			} else {
				return (OS_FAIL);
			}
		} else
			return (OS_FAIL);
	}

/******************************************************************************
*
* Name: isCapInfoSupported
*
* Description:
*
* Conditions For Use:
*    All software components have been initialized and started.
*
* Arguments:
*    Arg1 (i  ): 
* Return Value:
*    None.
*
* Notes:
*    None.
*
* PDL:

* END PDL
*
*****************************************************************************/
	WL_STATUS isCapInfoSupported(IEEEtypes_CapInfo_t * CapInfo1,
				     IEEEtypes_CapInfo_t * CapInfo2) {
		if (CapInfo1->ShortPreamble == 0)
			BarkerPreambleSet = 1;
		return (OS_SUCCESS);
	}

	WL_STATUS isBasicRatesSupported(IEEEtypes_SuppRatesElement_t *
					SuppRates,
					IEEEtypes_ExtSuppRatesElement_t *
					ExtSuppRates, BOOLEAN gRatePresent) {
		UINT32 i, j;
		UINT32 RateSetLen;
		IEEEtypes_DataRate_t *RateSet;
		if (gRatePresent) {
			RateSetLen = BasicRateSetLen;
			RateSet = BasicRateSet;
		} else {
			RateSetLen = BasicRateSetLen;
			RateSet = BasicRateSet;
		}
		for (i = 0; i < RateSetLen; i++) {
			for (j = 0; j < SuppRates->Len; j++) {
				if ((SuppRates->
				     Rates[j] & IEEEtypes_BASIC_RATE_MASK)
				    == RateSet[i]) {

					break;	/* Basic rate is present, no more check for this rate */
				}
			}
			if (j < SuppRates->Len) {
				continue;	/* Continue for the next basic rate */
			} else {	/* Basuc rate not in supported rate set, check in Extended Supp rate set */

				for (j = 0;
				     (ExtSuppRates && j < ExtSuppRates->Len);
				     j++) {
					if ((ExtSuppRates->
					     Rates[j] &
					     IEEEtypes_BASIC_RATE_MASK)
					    == RateSet[i]) {

						break;	/* basic rate present in ext supp rate set */
					}
				}
				//if (j < ExtSuppRates->Len)  /* rate is present */
				if (ExtSuppRates && j < ExtSuppRates->Len) {
					continue;	/* go to the next basic rate */
				} else {	/* basic rate not present in ext rate set also */

					return (OS_SUCCESS);
					/*return OS_FAIL; */
				}
			}
		}
		return (OS_SUCCESS);
	}

/******************************************************************************
*
* Name: isRateSetValid
*
* Description:
*
* Conditions For Use:
*    All software components have been initialized and started.
*
* Arguments:
*    Arg1 (i  ): 
* Return Value:
*    None.
*
* Notes:
*    None.
*
* PDL:

* END PDL
*
*****************************************************************************/
	WL_STATUS isRateSetValid(UINT8 * RateSet) {
		int i;
		i = 0;
		while (i < IEEEtypes_MAX_DATA_RATES
		       && RateSet[i] > 1 && RateSet[i] <= 127) {
			i++;
		}
		/* it should have had atleast one valid value */
		if (!i)
			return (OS_SUCCESS);
		else
			return (OS_FAIL);
	}

	UINT32 GetHighestRateIndex(vmacApInfo_t * vmacSta_p,
				   IEEEtypes_SuppRatesElement_t * SuppRates,
				   IEEEtypes_ExtSuppRatesElement_t *
				   ExtSuppRates, BOOLEAN * gRatePresent) {
		MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
		UINT32 i, Index;
		UINT32 HighestRateIndex = 0, HighestOpRate;
		UINT8 MaxRate, isBandA;

		if (Is5GBand(*(mib->mib_ApMode))) {
			MaxRate = IEEEtypes_MAX_DATA_RATES_A;
			isBandA = TRUE;
		} else {
			MaxRate = IEEEtypes_MAX_DATA_RATES_G;
			isBandA = FALSE;
		}
		/*IEEEtypes_SuppRatesElement_t *SuppRates; */
		/*IEEEtypes_ExtSuppRatesElement_t *ExtSuppRates; */

		HighestOpRate = 0;
		*gRatePresent = FALSE;
		/*      SuppRates = &AssocTable[Aid].SuppRates; */
		/*      ExtSuppRates = &AssocTable[Aid].ExtSuppRates; */
		for (i = 0; i < SuppRates->Len && SuppRates->Rates[i]; i++) {
			if ((Index =
			     hw_GetPhyRateIndex(vmacSta_p,
						(SuppRates->
						 Rates[i] &
						 IEEEtypes_BASIC_RATE_MASK)))
			    < MaxRate)
				/* valid rate for the Phy */
			{
				if (isBandA ||
				    (Index > HIGHEST_11B_RATE_REG_INDEX))
					*gRatePresent = TRUE;
				if ((SuppRates->
				     Rates[i] & IEEEtypes_BASIC_RATE_MASK) >=
				    HighestOpRate) {
					HighestOpRate =
						(SuppRates->
						 Rates[i] &
						 IEEEtypes_BASIC_RATE_MASK);
					HighestRateIndex = Index;
				}
			} else {	/* the rate is not a valid state for the PHY */

			}
		}
		if (ExtSuppRates && ExtSuppRates->Len) {
			for (i = 0;
			     i < IEEEtypes_MAX_DATA_RATES &&
			     ExtSuppRates->Rates[i]; i++) {

				if ((Index =
				     hw_GetPhyRateIndex(vmacSta_p,
							(ExtSuppRates->
							 Rates[i] &
							 IEEEtypes_BASIC_RATE_MASK)))
				    < IEEEtypes_MAX_DATA_RATES_G)
					/* valid rate for the Phy */
				{

					if (Index > HIGHEST_11B_RATE_REG_INDEX)
						*gRatePresent = TRUE;
					if ((ExtSuppRates->
					     Rates[i] &
					     IEEEtypes_BASIC_RATE_MASK) >=
					    HighestOpRate) {
						HighestOpRate =
							(ExtSuppRates->
							 Rates[i] &
							 IEEEtypes_BASIC_RATE_MASK);
						HighestRateIndex = Index;
					}
				} else {	/* the rate is not a valid state for the PHY */

				}
			}
		}

		return (HighestRateIndex);
	}
	UINT32 SetSuppRateSetRegMap(vmacApInfo_t * vmacSta_p,
				    IEEEtypes_SuppRatesElement_t * SuppRates,
				    UINT32 * SuppRateSetRegMap) {
		UINT32 i, Index;
		UINT32 HighestRateIndex, HighestOpRate;

		HighestRateIndex = 0;
		HighestOpRate = 0;
		for (i = 0; i < SuppRates->Len; i++) {

			if ((Index =
			     hw_GetPhyRateIndex(vmacSta_p,
						(SuppRates->
						 Rates[i] &
						 IEEEtypes_BASIC_RATE_MASK)))
			    < IEEEtypes_MAX_DATA_RATES)
				/* valid rate for the Phy */
			{

				if (SuppRates->Rates[i] >= HighestOpRate) {
					HighestOpRate = SuppRates->Rates[i];
					HighestRateIndex = Index;
				}
				SuppRateSetRegMap[i] = Index;
			} else {	/* the rate is not a valid rate for the PHY */

				/* use one of the valid rates in this position */
				SuppRateSetRegMap[i] = 1;
			}
		}
		return (HighestRateIndex);

	}

	void macMgmtMlme_StepUpRate(UINT16 Aid, UINT8 LastPktRate) {
#ifdef ENABLE_RATE_ADAPTATION
		if (LastPktRate < (AssocTable[Aid].SuppRates.Len - 1)) {
			AssocTable[Aid].RateToBeUsedForTx = LastPktRate + 1;
		}
#endif
		/*CurrRateRegIndex = AssocTable[Aid].RateToBeUsedForTx; */
		/*for (i = 0; i < ;i++) */
		/*{ */
		/*    if ( CurrRateRegIndex == AssocTable[Aid].SuppRateSetRegMap[i]) */
		/*    { */
		/*        if ( i < AssocTable[Aid].SuppRates.Len - 1) */
		/*        { */
		/*            AssocTable[Aid].RateToBeUsedForTx = ++i; */
		/*        } */
		/*        else */
		/*        { */
		/* Rate remains the same */
		/*        } */
		/*        break; */
		/*    } */
		/*} */
		return;
	}
	void macMgmtMlme_StepDownRate(UINT16 Aid, UINT8 LastPktRate) {

#ifdef ENABLE_RATE_ADAPTATION
		if (LastPktRate > 0) {
			AssocTable[Aid].RateToBeUsedForTx = LastPktRate - 1;
		}		/*CurrRateRegIndex = AssocTable[Aid].RateToBeUsedForTx; */
#endif
		/*for (i = 0; i < AssocTable[Aid].SuppRates.Len;i++) */
		/*{ */
		/*    if ( CurrRateRegIndex == AssocTable[Aid].SuppRateSetRegMap[i]) */
		/*    { */
		/*        if ( i > 0) */
		/*        { */
		/*            AssocTable[Aid].RateToBeUsedForTx = --i; */
		/*        } */
		/*        else */
		/*        { */
		/* Rate remains the same */
		/*        } */
		/*        break; */
		/*    } */
		/*} */
		return;
	}

	void macMgmtCleanUp(vmacApInfo_t * vmacSta_p,
			    extStaDb_StaInfo_t * StaInfo_p) {
		if (StaInfo_p->State == ASSOCIATED) {
#ifdef ENABLE_RATE_ADAPTATION_BASEBAND_REMOVE
			UpdateAssocStnData(StaInfo_p->Aid, StaInfo_p->ApMode);
#endif /*ENABLE_RATE_ADAPTATION_BASEBAND */
#ifdef FIX_LATER
			bcngen_UpdateBitInTim(StaInfo_p->Aid, RESETBIT);
#endif

			wlFwSetAPUpdateTim(vmacSta_p->dev, StaInfo_p->Aid,
					   RESETBIT);
			cleanupAmpduTx(vmacSta_p, (UINT8 *) & StaInfo_p->Addr);

			/* remove the Mac address from the ethernet MAC address table */
			FreeAid(vmacSta_p, StaInfo_p->Aid);
			StaInfo_p->Aid = 0;
#ifdef ERP
			if (StaInfo_p->ClientMode == BONLY_MODE)
				macMgmtMlme_DecrBonlyStnCnt(vmacSta_p, 0);

			if (!StaInfo_p->CapInfo.ShortPreamble)
				macMgmtMlme_DecrBarkerPreambleStnCnt(vmacSta_p);
#endif
		}
	}
	void macMgmtRemoveSta(vmacApInfo_t * vmacSta_p,
			      extStaDb_StaInfo_t * StaInfo_p) {
		if (StaInfo_p->State == ASSOCIATED) {
			macMgmtCleanUp(vmacSta_p, StaInfo_p);
			StaInfo_p->State = AUTHENTICATED;
		}
		StaInfo_p->State = UNAUTHENTICATED;
#ifdef CONFIG_IEEE80211W
		StaInfo_p->ptkCipherOuiType = CIPHER_OUI_TYPE_NONE;
#endif
		FreeAid(vmacSta_p, StaInfo_p->Aid);
		StaInfo_p->Aid = 0;
		FreeStnId(vmacSta_p, StaInfo_p->StnId);
		extStaDb_DelSta(vmacSta_p,
				(IEEEtypes_MacAddr_t *) StaInfo_p->Addr,
				STADB_DONT_UPDATE_AGINGTIME);
		wlFwSetNewStn(vmacSta_p->dev, (u_int8_t *) StaInfo_p->Addr,
			      StaInfo_p->Aid, StaInfo_p->StnId,
			      StaInfoDbActionRemoveEntry, NULL, 0, 0, 0);
	}

#ifdef WTP_SUPPORT

	extern extStaDb_StaInfo_t *macMgtStaDbInit(vmacApInfo_t * vmacSta_p,
						   IEEEtypes_MacAddr_t *
						   staMacAddr,
						   IEEEtypes_MacAddr_t *
						   apMacAddr);

	int macMgmtMlme_set_sta_authorized(vmacApInfo_t * vmacAP_p,
					   IEEEtypes_MacAddr_t * staMac) {
		extStaDb_StaInfo_t *StaInfo_p;
		UINT8 __attribute__ ((unused)) * addr = (char *)staMac;

		if ((StaInfo_p =
		     extStaDb_GetStaInfo(vmacAP_p, staMac,
					 STADB_DONT_UPDATE_AGINGTIME)) ==
		    NULL) {
			//if STA exists in other VAP's db, remove it.
			if ((StaInfo_p =
			     extStaDb_GetStaInfo(vmacAP_p, staMac,
						 STADB_SKIP_MATCH_VAP))) {
				macMgmtRemoveSta(vmacAP_p, StaInfo_p);
			}
			if ((StaInfo_p =
			     macMgtStaDbInit(vmacAP_p, staMac,
					     &vmacAP_p->macStaAddr)) == NULL) {
				WLDBG_ENTER_INFO(DBG_LEVEL_11,
						 "Init DB in Ioctl APi failed ...\n");
				return -EUSERS;
			}
			StaInfo_p->State = AUTHENTICATED;	//bypass auth alg check for now.
			PRINT1(IOCTL,
			       "STA-%02x:%02x:%02x:%02x:%02x:%02x set authicanted ...\n",
			       addr[0], addr[1], addr[2], addr[3], addr[4],
			       addr[5]);
		} else {
			//Do nothing if the STA already exists...
			PRINT1(IOCTL,
			       "STA-%02x:%02x:%02x:%02x:%02x:%02x already exists ...\n",
			       addr[0], addr[1], addr[2], addr[3], addr[4],
			       addr[5]);
		}
		return 0;
	}

	int macMgmtMlme_set_sta_associated(vmacApInfo_t * vmacAP_p,
					   IEEEtypes_MacAddr_t * staMac,
					   UINT8 Aid, PeerInfo_t * PeerInfo,
					   UINT8 QosInfo, UINT8 isQosSta,
					   UINT8 rsnSta, UINT8 * rsnIE) {
		MIB_802DOT11 *mib = vmacAP_p->Mib802dot11;
		extStaDb_StaInfo_t *StaInfo_p;
		UINT8 __attribute__ ((unused)) * addr = (char *)staMac;
		UINT8 amsdu_bitmap;
		UINT32 staIdx;

#ifdef TP_PROFILE
		struct sk_buff *skb;
		struct ethhdr *eh;
		unsigned char broadcast_addr[] =
			{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate,
				      ((struct net_device *)vmacAP_p->dev));
#endif
		if ((StaInfo_p =
		     extStaDb_GetStaInfo(vmacAP_p, staMac,
					 STADB_DONT_UPDATE_AGINGTIME)) ==
		    NULL) {
			PRINT1(IOCTL,
			       "STA-%02x:%02x:%02x:%02x:%02x:%02x not found in StaDB ...\n",
			       addr[0], addr[1], addr[2], addr[3], addr[4],
			       addr[5]);
			return -ENXIO;
		} else {
			if (StaInfo_p->State != AUTHENTICATED) {
				PRINT1(IOCTL,
				       "STA-%02x:%02x:%02x:%02x:%02x:%02x Station has not authenticated! State = %x\n",
				       addr[0], addr[1], addr[2], addr[3],
				       addr[4], addr[5], StaInfo_p->State);
				return -EPERM;
			}
			if (Aid)
				StaInfo_p->Aid = Aid;
#if 0
			else {
				StaInfo_p->Aid = AssignAid(vmacAP_p);
			}
#endif
			if (rsnSta) {
				memcpy(StaInfo_p->keyMgmtStateInfo.RsnIEBuf,
				       rsnIE, rsnIE[1] + 2);
			}
			cleanupAmpduTx(vmacAP_p, (UINT8 *) & StaInfo_p->Addr);
			if (((PeerInfo->LegacyRateBitMap & 0xFFFFFFF0) == 0) ||
			    (*(mib->mib_ApMode) == AP_MODE_B_ONLY))
				StaInfo_p->ClientMode = BONLY_MODE;
			else if ((PeerInfo->HTRateBitMap) &&
				 (*(mib->mib_ApMode) & 0x4)) {
				StaInfo_p->ClientMode = NONLY_MODE;
				StaInfo_p->aggr11n.threshold = AGGRTHRESHOLD;
#ifdef WIFI_DATA_OFFLOAD
				dol_sta_tx_ampdu_ctrl(wlpptr,
						      wlpptr->wlpd_p->
						      ipc_session_id,
						      wlpptr->vmacSta_p->
						      VMacEntry.macId,
						      (u8 *) StaInfo_p->Addr,
						      AGGRTHRESHOLD, NULL);
#endif
				StaInfo_p->aggr11n.thresholdBackUp =
					StaInfo_p->aggr11n.threshold;
				StaInfo_p->aggr11n.cap =
					(PeerInfo->HTCapabilitiesInfo.
					 MaxAMSDUSize) ? 2 : 1;

				amsdu_bitmap =
					(*(mib->pMib_11nAggrMode) &
					 WL_MODE_AMSDU_TX_MASK);
				if (amsdu_bitmap == WL_MODE_AMSDU_TX_11K)
					amsdu_bitmap = WL_MODE_AMSDU_TX_8K;

				if (StaInfo_p->aggr11n.cap > amsdu_bitmap)
					StaInfo_p->aggr11n.cap = amsdu_bitmap;

				StaInfo_p->PeerHTCapabilitiesInfo =
					PeerInfo->HTCapabilitiesInfo;
				StaInfo_p->HtElem.HTCapabilitiesInfo =
					PeerInfo->HTCapabilitiesInfo;
				StaInfo_p->HtElem.MacHTParamInfo =
					PeerInfo->MacHTParamInfo;
				StaInfo_p->HtElem.TxBFCapabilities =
					PeerInfo->TxBFCapabilities;
			} else {
				if (*(mib->mib_ApMode) == AP_MODE_A_ONLY)
					StaInfo_p->ClientMode = AONLY_MODE;
				else if (*(mib->mib_ApMode) == AP_MODE_G_ONLY)
					StaInfo_p->ClientMode = GONLY_MODE;
				else if ((*(mib->mib_ApMode) ==
					  AP_MODE_BandGandN) ||
					 (*(mib->mib_ApMode) ==
					  AP_MODE_2_4GHZ_11AC_MIXED) ||
					 (*(mib->mib_ApMode) == AP_MODE_MIXED)
					 || (*(mib->mib_ApMode) ==
					     AP_MODE_GandN))
					StaInfo_p->ClientMode = GONLY_MODE;
				else if ((*(mib->mib_ApMode) == AP_MODE_AandN)
					 || (*(mib->mib_ApMode) ==
					     AP_MODE_5GHZ_Nand11AC) ||
					 (*(mib->mib_ApMode) ==
					  AP_MODE_5GHZ_11AC_ONLY)
#ifdef SOC_W906X
					 || (*(mib->mib_ApMode) ==
					     AP_MODE_5GHZ_ACand11AX) ||
					 (*(mib->mib_ApMode) ==
					  AP_MODE_5GHZ_NandACand11AX) ||
					 (*(mib->mib_ApMode) ==
					  AP_MODE_5GHZ_11AX_ONLY)
#endif
					)
					StaInfo_p->ClientMode = AONLY_MODE;
				else
					StaInfo_p->ClientMode = MIXED_MODE;
			}
			StaInfo_p->IsStaQSTA = isQosSta;
			wlFwSetNewStn(vmacAP_p->dev, (UINT8 *) staMac, 0, 0, StaInfoDbActionRemoveEntry, NULL, 0, 0, 0);	//del station first
			staIdx = AssignStnId(vmacAP_p);
#ifdef SOC_W906X
			if (staIdx >=
			    sta_num) { /*if only can get valid stnid */ ;
#else
			if (!staIdx) {	/*if only can get valid stnid */
#endif
				return -EAGAIN;
			}
			StaInfo_p->StnId = staIdx;
			StaInfo_p->FwStaPtr =
				wlFwSetNewStn(vmacAP_p->dev, (UINT8 *) staMac,
					      StaInfo_p->Aid, StaInfo_p->StnId,
					      StaInfoDbActionAddEntry, PeerInfo,
					      QosInfo, isQosSta, 0);
			wlFwSetSecurity(vmacAP_p->dev, (u_int8_t *) staMac);
			StaInfo_p->State = ASSOCIATED;
#ifdef OPENWRT
			StaInfo_p->last_connected = ktime_get_seconds();
#endif
		}

#ifdef TP_PROFILE
		if (wlpptr->wlpd_p->wl_tpprofile.mode) {
			skb = wl_alloc_skb(ETH_ZLEN);
			eh = (struct ethhdr *)skb->data;
			memcpy(eh->h_dest, broadcast_addr, ETH_ALEN);
			memcpy(eh->h_source, staMac, ETH_ALEN);
			eh->h_proto = ETH_P_ARP;
			skb_put(skb, ETH_ZLEN);
			skb->dev = vmacAP_p->dev;
			eth_type_trans(skb, skb->dev);
			wl_receive_skb(skb);
		}
#endif

		return 0;

	}

	void macMgmtMlme_del_sta_entry(vmacApInfo_t * vmacSta_p,
				       IEEEtypes_MacAddr_t * staMac) {
		extStaDb_StaInfo_t *StaInfo_p;
		if ((StaInfo_p =
		     extStaDb_GetStaInfo(vmacSta_p, staMac,
					 STADB_DONT_UPDATE_AGINGTIME)) ==
		    NULL) {
			return;	//Do nothing if STA is not in StaDB.
		}
#ifdef QOS_FEATURE_REMOVE
		if (*(mib->QoSOptImpl) &&
		    extStaDb_GetQoSOptn(vmacSta_p, staMac))
			ClearQoSDB(staMac);
#endif
		wlFwSetAPUpdateTim(vmacSta_p->dev, StaInfo_p->Aid, RESETBIT);
		FreeAid(vmacSta_p, StaInfo_p->Aid);
		ResetAid(vmacSta_p, StaInfo_p->StnId, StaInfo_p->Aid);
		StaInfo_p->Aid = 0;

		if (StaInfo_p->State == ASSOCIATED) {
#ifdef ENABLE_RATE_ADAPTATION_BASEBAND_REMOVE
			UpdateAssocStnData(StaInfo_p->Aid, StaInfo_p->ApMode);
#endif
			cleanupAmpduTx(vmacSta_p, (UINT8 *) & StaInfo_p->Addr);

			if (StaInfo_p->ClientMode == BONLY_MODE)
				macMgmtMlme_DecrBonlyStnCnt(vmacSta_p, 0);

			if (!StaInfo_p->CapInfo.ShortPreamble)
				macMgmtMlme_DecrBarkerPreambleStnCnt(vmacSta_p);

			if (StaInfo_p->PwrMode == PWR_MODE_PWR_SAVE) {
				if (vmacSta_p->PwrSaveStnCnt)
					vmacSta_p->PwrSaveStnCnt--;
				StaInfo_p->PwrMode = PWR_MODE_ACTIVE;

			}
		}
		StaInfo_p->State = UNAUTHENTICATED;
		FreeStnId(vmacSta_p, StaInfo_p->StnId);
		extStaDb_DelSta(vmacSta_p, staMac, STADB_DONT_UPDATE_AGINGTIME);
		wlFwSetNewStn(vmacSta_p->dev, (u_int8_t *) staMac,
			      StaInfo_p->Aid, StaInfo_p->StnId,
			      StaInfoDbActionRemoveEntry, NULL, 0, 0, 0);
		return;
	}

#endif

	UINT32 BAPCount = 0, ERPCount = 0;
#define BSTATION_AGECOUNT 3
#define BSTATION_AGECOUNT 3
#define BEACON_OFFSET_LEN 0x100
#define RX_BCN_BUFSIZE     (2 * 1024)

///////////////////////////////////////////////////////////////////////////////
// Check to make sure pStaInfo is valid before calling this function!!
///////////////////////////////////////////////////////////////////////////////
	void macMgmtMlme_UpdatePwrMode(vmacApInfo_t * vmacSta_p,
				       struct ieee80211_frame *Hdr_p,
				       extStaDb_StaInfo_t * pStaInfo) {
		if (pStaInfo->PwrMode == PWR_MODE_ACTIVE) {
			if (Hdr_p->FrmCtl.PwrMgmt == 1) {
				/* Station enters power save mode */
				pStaInfo->PwrMode = PWR_MODE_PWR_SAVE;

				vmacSta_p->PwrSaveStnCnt++;
			}
		} else {
			if (Hdr_p->FrmCtl.PwrMgmt == 0) {
				/* Station enters active mode */
				pStaInfo->PwrMode = PWR_MODE_ACTIVE;
				/* Inform the transmit module */
				if (vmacSta_p->PwrSaveStnCnt)
					vmacSta_p->PwrSaveStnCnt--;
			}
#ifdef WMM_PS_SUPPORT
			else {
/** powersave bit is still 1 **/

				if (*(mib->QoSOptImpl) && ((pStaInfo->Qosinfo.Uapsd_ac_vo &&
								     /** All AC enable **/
							    pStaInfo->Qosinfo.
							    Uapsd_ac_vi &&
							    pStaInfo->Qosinfo.
							    Uapsd_ac_be &&
							    pStaInfo->Qosinfo.
							    Uapsd_ac_bk) ||
				/** mixed case **/
							   (AccCategoryQ[Prio]
							    == AC_VO_Q &&
							    pStaInfo->Qosinfo.
							    Uapsd_ac_vo)
							   ||
							   (AccCategoryQ[Prio]
							    == AC_VI_Q &&
							    pStaInfo->Qosinfo.
							    Uapsd_ac_vi)
							   ||
							   (AccCategoryQ[Prio]
							    == AC_BE_Q &&
							    pStaInfo->Qosinfo.
							    Uapsd_ac_be)
							   ||
							   (AccCategoryQ[Prio]
							    == AC_BK_Q &&
							    pStaInfo->Qosinfo.
							    Uapsd_ac_bk)))

				{
					if (!TriggerFrameCnt(pStaInfo->StnId, 2)) {
/** no pending trigger frame for that station **/
						NotifyPwrModeChange(&Hdr_p->Addr2, PWR_MODE_PWR_SAVE, 1, Prio);
												       /** this is actually the trigger frame **/

					} else {
						TriggerFrameCnt(pStaInfo->StnId, 0);
									    /** decrement trigger frame cnt for that station **/
					}
				}
			}
#endif
		}
	}

#if defined(AP_SITE_SURVEY) || defined(AUTOCHANNEL)
/***************************** Added for Site Survey Start *******************************/

/*************************************************************************
* Function: syncSrv_ScanCmd
*
* Description:
*
* Input:
*
* Output:
*
**************************************************************************/
	extern void syncSrv_ScanCmd(vmacApInfo_t * vmacSta_p,
				    IEEEtypes_ScanCmd_t * ScanCmd_p) {

		/* provide list of channel to ScanParams */
		memcpy((UINT8 *) & vmacSta_p->ScanParams, (UINT8 *) ScanCmd_p,
		       sizeof(IEEEtypes_ScanCmd_t));

	/*-----------------------------------------*/
		/* Make sure channels to scan are provided */
	/*-----------------------------------------*/
		if (vmacSta_p->ScanParams.ChanList[0] == 0) {
			return;
		}

	/*--------------------------------------------------------*/
		/* Determine how many channels there are to scan from the */
		/* given list.                                            */
	/*--------------------------------------------------------*/
		vmacSta_p->NumScanChannels = 0;

		while (vmacSta_p->ScanParams.
		       ChanList[vmacSta_p->NumScanChannels]) {
			vmacSta_p->NumScanChannels++;
		}

		/* Prepare To Scan */
		/* Flush Station Database */
		extStaDb_RemoveAllStns(vmacSta_p,
				       IEEEtypes_REASON_DEAUTH_LEAVING);
		/* Broadcast DeAuth Msg */
#ifdef SOC_W906X
		macMgmtMlme_SendDeauthenticateMsg(vmacSta_p, &bcast, 0,
						  IEEEtypes_REASON_DEAUTH_LEAVING,
						  FALSE);
#else
		macMgmtMlme_SendDeauthenticateMsg(vmacSta_p, &bcast, 0,
						  IEEEtypes_REASON_DEAUTH_LEAVING);
#endif
		vmacSta_p->busyScanning = 1;
		vmacSta_p->ChanIdx = -1;
#if 0
//#ifdef COEXIST_20_40_SUPPORT
		if (!*(vmacSta_p->ShadowMib802dot11->mib_HT40MIntoler))
#endif
			EnableBlockTrafficMode(vmacSta_p);
#ifdef SOC_W8964
		wlSetOpModeMCU(vmacSta_p, MCU_MODE_STA_INFRA);
#endif
		//   wlSetRFChan(vmacSta_p,vmacSta_p->ScanParams.ChanList[ChanIdx]);
#ifdef AUTOCHANNEL
		resetautochanneldata(vmacSta_p);
#endif

		/* Get and start a scan timer with duration of the maximum channel time */
		TimerInit(&vmacSta_p->scaningTimer);
		TimerFireIn(&vmacSta_p->scaningTimer, 1,
			    &syncSrv_ScanActTimeOut, (unsigned char *)vmacSta_p,
			    SCAN_TIME);

	}
	void Disable_ScanTimerProcess(vmacApInfo_t * vmacSta_p) {
		TimerDisarm(&vmacSta_p->scaningTimer);
	}

/*************************************************************************
* Function: syncSrv_ParseAttrib
*
* Description:
*
* Input:
*
* Output:
*
**************************************************************************/
#endif

	extern void *syncSrv_ParseAttrib(macmgmtQ_MgmtMsg_t * mgtFrame_p,
					 UINT8 attrib, UINT16 len) {
		void *data_p;
		UINT32 lenPacket;
		UINT32 lenOffset;

		lenOffset = sizeof(IEEEtypes_MgmtHdr2_t)
			+ sizeof(IEEEtypes_TimeStamp_t)
			+ sizeof(IEEEtypes_BcnInterval_t)
			+ sizeof(IEEEtypes_CapInfo_t);
		lenPacket = len - lenOffset;
		data_p = (UINT8 *) mgtFrame_p + 2 + lenOffset;
		while (lenOffset < len) {
			if (*(UINT8 *) data_p == attrib) {
				return data_p;
			}

			lenOffset += 2 + *((UINT8 *) (data_p) + 1);
			data_p += 2 + *((UINT8 *) (data_p) + 1);
		}
		return NULL;
	}

#ifdef CONFIG_IEEE80211W
#ifdef SOC_W906X
	extern int wlxmit(struct net_device *netdev, struct sk_buff *skb,
			  UINT8 type, extStaDb_StaInfo_t * pStaInfo,
			  UINT32 bcast, BOOLEAN eap, UINT8 nullpkt);
#else
	extern int wlxmit(struct net_device *netdev, struct sk_buff *skb,
			  UINT8 type, extStaDb_StaInfo_t * pStaInfo,
			  UINT32 bcast, BOOLEAN eap);
#endif
	void macMgmtMlme_SAQuery(vmacApInfo_t * vmacSta_p,
				 IEEEtypes_MacAddr_t * Addr,
				 IEEEtypes_MacAddr_t * SrcAddr,
				 UINT32 stamode) {
#ifndef SOC_W906X
		unsigned long flags;
#endif
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev);
		macmgmtQ_MgmtMsg2_t *MgmtMsg_p;
		BOOLEAN sendResult = FALSE;
		struct sk_buff *txSkb_p;
		UINT8 trans_id[WLAN_SA_QUERY_TR_ID_LEN];
		UINT32 wep = stamode >> 31;
		UINT32 key = (stamode >> 30) & 0x01;

		WLDBG_ENTER(DBG_LEVEL_7);
		generateRand(trans_id, WLAN_SA_QUERY_TR_ID_LEN);
		if ((txSkb_p =
		     mlmeApiPrepMgtMsg2(IEEE_MSG_QOS_ACTION, Addr,
					&vmacSta_p->macStaAddr,
					sizeof(IEEEtypes_SAQuery_Req_t))) ==
		    NULL)
			return;

		MgmtMsg_p = (macmgmtQ_MgmtMsg2_t *) txSkb_p->data;
		if (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_CLNT_INFRA) {
			UINT8 *pbssid = NULL;
			extern UINT8 *GetParentStaBSSID(UINT8 macIndex);

			MgmtMsg_p->Hdr.FrmCtl.ToDs = 1;
			MgmtMsg_p->Hdr.FrmCtl.FromDs = 0;
			MACADDR_CPY(MgmtMsg_p->Hdr.DestAddr, Addr);
			MACADDR_CPY(MgmtMsg_p->Hdr.SrcAddr,
				    vmacSta_p->macStaAddr);

			if ((pbssid =
			     GetParentStaBSSID(vmacSta_p->VMacEntry.
					       phyHwMacIndx)) != NULL) {
				MACADDR_CPY(MgmtMsg_p->Hdr.BssId, pbssid);
			}
		}

		MgmtMsg_p->Body.SAQuery_Req.Category = WLAN_ACTION_SA_QUERY;
		MgmtMsg_p->Body.SAQuery_Req.Action = WLAN_SA_QUERY_REQUEST;
		memcpy(MgmtMsg_p->Body.SAQuery_Req.trans_id, trans_id,
		       WLAN_SA_QUERY_TR_ID_LEN);
		//   _hexdump(__FUNCTION__, txSkb_p->data, txSkb_p->len);
		if (stamode == 0) {
			if (txMgmtMsg(vmacSta_p->dev, txSkb_p) == OS_SUCCESS)
				sendResult = TRUE;
			else {
				wl_free_skb(txSkb_p);
			}
		} else {
			MgmtMsg_p->Hdr.FrmCtl.Wep = wep;
#ifdef SOC_W906X
			SPIN_LOCK_BH(&wlpptr->wlpd_p->locks.xmitLock);
			if (wlxmit
			    (vmacSta_p->dev, txSkb_p,
			     IEEE_TYPE_MANAGEMENT | (key << 7) | (1 << 6), NULL,
			     0, FALSE, 0))
#else
			SPIN_LOCK_IRQSAVE(&wlpptr->wlpd_p->locks.xmitLock,
					  flags);
			if (wlxmit
			    (vmacSta_p->dev, txSkb_p,
			     IEEE_TYPE_MANAGEMENT | (key << 7) | (1 << 6), NULL,
			     0, FALSE))
#endif
			{
				wl_free_skb(txSkb_p);
			}
#ifdef SOC_W906X
			SPIN_UNLOCK_BH(&wlpptr->wlpd_p->locks.xmitLock);
#else
			SPIN_UNLOCK_IRQRESTORE(&wlpptr->wlpd_p->locks.xmitLock,
					       flags);
#endif
		}

		WLDBG_EXIT(DBG_LEVEL_7);
	}
	void macMgmtMlme_SAQuery_Rsp(vmacApInfo_t * vmacSta_p,
				     IEEEtypes_MacAddr_t * Addr,
				     IEEEtypes_MacAddr_t * SrcAddr,
				     UINT8 * trans_id, UINT32 stamode) {
		macmgmtQ_MgmtMsg2_t *MgmtMsg_p;
		BOOLEAN sendResult = FALSE;
		struct sk_buff *txSkb_p;
		WLDBG_ENTER(DBG_LEVEL_7);

		if ((txSkb_p =
		     mlmeApiPrepMgtMsg2(IEEE_MSG_QOS_ACTION, Addr, SrcAddr,
					sizeof(IEEEtypes_SAQuery_Rsp_t))) ==
		    NULL)
			return;
		MgmtMsg_p = (macmgmtQ_MgmtMsg2_t *) txSkb_p->data;

		MgmtMsg_p->Body.SAQuery_Rsp.Category = WLAN_ACTION_SA_QUERY;
		MgmtMsg_p->Body.SAQuery_Rsp.Action = WLAN_SA_QUERY_RESPONSE;
		memcpy(MgmtMsg_p->Body.SAQuery_Rsp.trans_id, trans_id,
		       WLAN_SA_QUERY_TR_ID_LEN);

		if (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_CLNT_INFRA) {
			UINT8 *pbssid = NULL;
			extern UINT8 *GetParentStaBSSID(UINT8 macIndex);

			MgmtMsg_p->Hdr.FrmCtl.ToDs = 1;
			MgmtMsg_p->Hdr.FrmCtl.FromDs = 0;
			MACADDR_CPY(MgmtMsg_p->Hdr.DestAddr, Addr);
			MACADDR_CPY(MgmtMsg_p->Hdr.SrcAddr,
				    vmacSta_p->macStaAddr);

			if ((pbssid =
			     GetParentStaBSSID(vmacSta_p->VMacEntry.
					       phyHwMacIndx)) != NULL) {
				MACADDR_CPY(MgmtMsg_p->Hdr.BssId, pbssid);
			}
		}
		if (txMgmtMsg(vmacSta_p->dev, txSkb_p) == OS_SUCCESS)
			sendResult = TRUE;
		else {
			wl_free_skb(txSkb_p);
		}

		WLDBG_EXIT(DBG_LEVEL_7);
	}
#endif

#ifdef IEEE80211H
#if 0
	static WL_STATUS macMgmtMlme_asso_ind(vmacApInfo_t * vmacSta_p,
					      IEEEtypes_MacAddr_t * addr) {
		smeQ_MgmtMsg_t *toSmeMsg = NULL;
		WLDBG_ENTER(DBG_LEVEL_7);
		if ((toSmeMsg =
		     (smeQ_MgmtMsg_t *)
		     wl_kmalloc_autogfp(sizeof(smeQ_MgmtMsg_t))) == NULL) {
			WLDBG_INFO(DBG_LEVEL_7,
				   "macMgmtMlme_asso_ind: failed to alloc msg buffer\n");
			return WL_STATUS_ERR;
		}

		memset(toSmeMsg, 0, sizeof(smeQ_MgmtMsg_t));

		toSmeMsg->MsgType = SME_NOTIFY_ASSOC_IND;

		memcpy(&toSmeMsg->Msg.AssocInd.PeerStaAddr, addr,
		       sizeof(IEEEtypes_MacAddr_t));
		toSmeMsg->vmacSta_p = vmacSta_p;
		smeQ_MgmtWriteNoBlock(toSmeMsg);
		wl_kfree((UINT8 *) toSmeMsg);
		WLDBG_EXIT(DBG_LEVEL_7);
		return TRUE;
	}
#endif //0
/******************************************************************************
*
* Name: macMgmtMlme_DeauthenticateCmd
*
* Description:
*    Routine to handle a command to carry out a deauthentication with another
*    station or an AP.
*
* Conditions For Use:
*    All software components have been initialized and started.
*
* Arguments:
*    Arg1 (i  ): DeauthCmd_p - Pointer to a deauthenticate command
*
* Return Value:
*    None.
*
* Notes:
*    None.
*
* PDL:
*    If any of the given deauthentication parameters are invalid Then
*       Send a deauthentication confirmation to the SME with the failure
*          status
*    End If
*
*    Send a deauthentication message to the indicated station
*    Send a deauthentication confirm message to the SME task with the
*       result code
*    Set the state of the station to UNAUTHENTICATED
* END PDL
*
*****************************************************************************/

	void macMgmtMlme_MRequestReq(vmacApInfo_t * vmacSta_p,
				     IEEEtypes_MRequestCmd_t * MrequestCmd_p) {
		MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
		macmgmtQ_MgmtMsg2_t *MgmtMsg_p;
		extStaDb_StaInfo_t *StaInfo_p;
		IEEEtypes_MacAddr_t SrcMacAddr;
#ifdef AP_MAC_LINUX
		struct sk_buff *txSkb_p;
#else
		tx80211_MgmtMsg_t *TxMsg_p;
#endif
		WLDBG_ENTER(DBG_LEVEL_7);

		if ((*(mib->mib_ApMode) != AP_MODE_AandG) &&
		    (*(mib->mib_ApMode) != AP_MODE_A_ONLY)) {
			WLDBG_INFO(DBG_LEVEL_7,
				   "macMgmtMlme_MRequestReq: no need to sent in current AP mode(%d)\n",
				   *(mib->mib_ApMode));
			return;	/* No need for those stations not in A mode */
		}

		if (!IS_BROADCAST((UINT8 *) MrequestCmd_p->PeerStaAddr)) {
			if ((StaInfo_p =
			     extStaDb_GetStaInfo(vmacSta_p,
						 &MrequestCmd_p->PeerStaAddr,
						 STADB_DONT_UPDATE_AGINGTIME))
			    == NULL) {
				WLDBG_INFO(DBG_LEVEL_7,
					   "macMgmtMlme_MRequestReq: no station found\n");
				return;
			}

			if (StaInfo_p->ClientMode == AONLY_MODE)
				memcpy(SrcMacAddr, &vmacSta_p->macStaAddr,
				       sizeof(IEEEtypes_MacAddr_t));
			else {
				WLDBG_INFO(DBG_LEVEL_7,
					   "macMgmtMlme_MRequestReq: station is not in 11A mode(%d)\n\r",
					   StaInfo_p->ClientMode);
				return;
			}
		}

		/* allocate buffer for message */
#ifdef AP_MAC_LINUX
		if ((txSkb_p =
		     mlmeApiPrepMgtMsg(IEEE_MSG_QOS_ACTION,
				       &MrequestCmd_p->PeerStaAddr,
				       &SrcMacAddr)) == NULL)
			return;
		MgmtMsg_p = (macmgmtQ_MgmtMsg2_t *) txSkb_p->data;
#else
		if ((TxMsg_p =
		     mlmeApiPrepMgtMsg(IEEE_MSG_QOS_ACTION,
				       &MrequestCmd_p->PeerStaAddr,
				       &SrcMacAddr)) != NULL)
#endif
		{
			UINT32 loop;
			UINT32 len = 0;

			MgmtMsg_p->Body.Action.Category = SPECTRUM_MANAGEMENT;
			MgmtMsg_p->Body.Action.Action = MEASUREMENT_REQUEST;
			MgmtMsg_p->Body.Action.DialogToken =
				MrequestCmd_p->DiaglogToken;
			for (loop = 0; loop < MrequestCmd_p->MeasureItems;
			     loop++) {
				MgmtMsg_p->Body.Action.Data.
					MeasurementRequest[loop].ElementId =
					MEASUREMENT_REQ;
				MgmtMsg_p->Body.Action.Data.
					MeasurementRequest[loop].Len =
					3 + sizeof(IEEEtypes_MeasurementReq_t);
				MgmtMsg_p->Body.Action.Data.
					MeasurementRequest[loop].Token =
					MrequestCmd_p->MeasureReqSet[loop].
					MeasurementToken;
				MgmtMsg_p->Body.Action.Data.
					MeasurementRequest[loop].Mode =
					MrequestCmd_p->MeasureReqSet[loop].Mode;
				MgmtMsg_p->Body.Action.Data.
					MeasurementRequest[loop].Type =
					MrequestCmd_p->MeasureReqSet[loop].Type;
				MgmtMsg_p->Body.Action.Data.
					MeasurementRequest[loop].Request =
					MrequestCmd_p->MeasureReqSet[loop].
					Request;

				len += sizeof
					(IEEEtypes_MeasurementRequestElement_t);
			}

			//MgmtMsg_p->Hdr.FrmBodyLen = len + 3; /* length of Measurement IEs plus 3(Category+action+DialogToken)*/
			WLDBG_INFO(DBG_LEVEL_7,
				   "macMgmtMlme_MRequestReq: Tx action frame\n");
			if (txMgmtMsg(vmacSta_p->dev, txSkb_p) != OS_SUCCESS) {
				wl_free_skb(txSkb_p);
			}
		}

		WLDBG_EXIT(DBG_LEVEL_7);
	}

//void macMgmtMlme_MReportReq(vmacApInfo_t *vmacSta_p,IEEEtypes_MReportCmd_t *MreportCmd_p)
	void macMgmtMlme_MReportReq(struct net_device *staDev,
				    UINT8 * macStaAddr,
				    IEEEtypes_MReportCmd_t * MreportCmd_p) {
		macmgmtQ_MgmtMsg2_t *MgmtMsg_p;
		IEEEtypes_MacAddr_t SrcMacAddr;
#ifdef AP_MAC_LINUX
		struct sk_buff *txSkb_p;
#else
		tx80211_MgmtMsg_t *TxMsg_p;
#endif
		UINT32 ielen[20];
		UINT32 totalLen = 0;
		UINT32 loop;

		WLDBG_ENTER(DBG_LEVEL_7);

		memcpy(SrcMacAddr, macStaAddr, sizeof(IEEEtypes_MacAddr_t));
		for (loop = 0; loop < MreportCmd_p->ReportItems; loop++) {
			switch (MreportCmd_p->MeasureRepSet[loop].Type) {
#ifdef WMON
			case TYPE_REP_APS:
				ielen[loop] =
					3 + 11 +
					strlen(MreportCmd_p->
					       MeasureRepSet[loop].Report.data.
					       APS) + 1;
				break;
			case TYPE_REP_DFS:
				ielen[loop] =
					3 + 11 +
					strlen(MreportCmd_p->
					       MeasureRepSet[loop].Report.data.
					       DFS) + 1;
				break;
			case TYPE_REP_PSE:
				ielen[loop] =
					3 + 11 +
					strlen(MreportCmd_p->
					       MeasureRepSet[loop].Report.data.
					       PSE) + 1;
				break;
			case TYPE_REP_RSS:
				ielen[loop] = 3 + 11 + 1;
				break;
			case TYPE_REP_NOI:
				ielen[loop] = 3 + 11 + 8;
				break;
			case TYPE_REP_FCS:
			case TYPE_REP_VRX:
				ielen[loop] = 3 + 11 + 4;
				break;
#endif
			default:
				ielen[loop] = 0;
			}
			totalLen += ielen[loop];
		}
		/* allocate buffer for message */
#ifdef AP_MAC_LINUX
		//      if ((txSkb_p = mlmeApiPrepMgtMsg(IEEE_MSG_QOS_ACTION, &MreportCmd_p->PeerStaAddr, &SrcMacAddr)) == NULL)
		if ((txSkb_p =
		     mlmeApiPrepMgtMsg2(IEEE_MSG_QOS_ACTION,
					&MreportCmd_p->PeerStaAddr, &SrcMacAddr,
					totalLen)) == NULL)
			return;
		MgmtMsg_p = (macmgmtQ_MgmtMsg2_t *) txSkb_p->data;
#else
		if ((TxMsg_p =
		     mlmeApiPrepMgtMsg(IEEE_MSG_QOS_ACTION,
				       &MreportCmd_p->PeerStaAddr,
				       &SrcMacAddr)) != NULL)
#endif
		{
			UINT32 len = 0;
			IEEEtypes_MeasurementReportElement_t *IE_p;
			MgmtMsg_p->Body.Action.Category = SPECTRUM_MANAGEMENT;
			MgmtMsg_p->Body.Action.Action = MEASUREMENT_REPORT;
			MgmtMsg_p->Body.Action.DialogToken =
				MreportCmd_p->DiaglogToken;

			IE_p = MgmtMsg_p->Body.Action.Data.MeasurementReport;
			for (loop = 0; loop < MreportCmd_p->ReportItems; loop++) {
				UINT32 subLen = 0;

				IE_p->ElementId = MEASUREMENT_REP;
				IE_p->MeasurementToken =
					MreportCmd_p->MeasureRepSet[loop].
					MeasurementToken;
				IE_p->Mode =
					MreportCmd_p->MeasureRepSet[loop].Mode;
				IE_p->Type =
					MreportCmd_p->MeasureRepSet[loop].Type;

				if ((MreportCmd_p->MeasureRepSet[loop].Mode.Incapable) ||	/* problem to produce report result */
				    (MreportCmd_p->MeasureRepSet[loop].Mode.
				     Late) ||
				    (MreportCmd_p->MeasureRepSet[loop].Mode.
				     Refused))
					IE_p->Len = 3;
				else {
					memcpy(&IE_p->Report.DefReport,
					       &MreportCmd_p->
					       MeasureRepSet[loop].Report,
					       sizeof
					       (IEEEtypes_MeasurementRep_t));
				}
				/* this IE's length */
				IE_p->Len = ielen[loop];
				subLen = ielen[loop] + 2;

				/* point to starting address of next IE */
				IE_p = (IEEEtypes_MeasurementReportElement_t
					*) ((UINT8 *) IE_p + subLen);

				len += subLen;
			}

			txSkb_p->len = sizeof(struct ieee80211_frame) + len + 3;
			//MgmtMsg_p->Hdr.FrmBodyLen = len + 3; /* length of Measurement IEs plus 3(Category+action+DialogToken)*/
			WLDBG_INFO(DBG_LEVEL_7,
				   "macMgmtMlme_MReportReq: Tx action frame. \n");
			if (txMgmtMsg(staDev, txSkb_p) != OS_SUCCESS) {
				wl_free_skb(txSkb_p);
			}
		}
		WLDBG_EXIT(DBG_LEVEL_7);

	}

#ifdef IEEE80211K
	static UINT8 BcnRptToken = 1;
	UINT8 getDialogToken(void) {
		++BcnRptToken;
		if (BcnRptToken == 0)
			BcnRptToken = 1;
		return BcnRptToken;
	}

	void macMgmtMlme_RmBeaconRequest(struct net_device *netdev,
					 UINT8 * stamac,
					 UINT8 * bssid,
					 UINT8 RegDomain,
					 UINT8 ch,
					 UINT8 RandInt,
					 UINT8 MeasDur,
					 UINT8 MeasMode,
					 UINT8 * ssid,
					 UINT16 ReportCond,
					 UINT8 ReportDetail,
					 UINT8 MeasDurMand, UINT8 VoWiCase)
	{
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		macmgmtQ_MgmtMsg2_t *MgmtMsg_p;
		IEEEtypes_RadioMeasurementRequestElement_t *RequestElement;
		IEEEtypes_BeaconRequest_t *bcn_req;
		UINT8 *opt;
		UINT16 len = 0;
		struct sk_buff *skb;

		WLDBG_ENTER(DBG_LEVEL_7);

		skb = mlmeApiPrepMgtMsg2(IEEE_MSG_QOS_ACTION,
					 (IEEEtypes_MacAddr_t *) stamac,
					 (IEEEtypes_MacAddr_t *) netdev->
					 dev_addr, 200);
		if (skb == NULL) {
			return;
		}

		MgmtMsg_p = (macmgmtQ_MgmtMsg2_t *) skb->data;
		RequestElement = (IEEEtypes_RadioMeasurementRequestElement_t *)
			& MgmtMsg_p->Body.Action.Data.RadioMeasReq.
			RequestElement[0];
		{
			MgmtMsg_p->Body.Action.Category = AC_RADIO_MEASUREMENT;
			MgmtMsg_p->Body.Action.Action =
				AF_RM_MEASUREMENT_REQUEST;
			MgmtMsg_p->Body.Action.DialogToken =
				wlpptr->wlpd_p->Global_DialogToken;
			wlpptr->wlpd_p->Global_DialogToken =
				(wlpptr->wlpd_p->Global_DialogToken + 1) % 63;
			MgmtMsg_p->Body.Action.Data.RadioMeasReq.
				NoOfRepetitions = 0;

			RequestElement->ElementId = MEASUREMENT_REQ;
			RequestElement->Token = getDialogToken();

			*(UINT8 *) & RequestElement->Mode = 0;
			RequestElement->Mode.DurMand = MeasDurMand;
			RequestElement->Type = TYPE_REQ_BCN;

			bcn_req =
				(IEEEtypes_BeaconRequest_t *) & RequestElement->
				BcnReq;
			bcn_req->RegClass = RegDomain;
			bcn_req->Channel = ch;
			bcn_req->RandInt = RandInt;
			bcn_req->Dur = MeasDur;
			bcn_req->MeasMode = MeasMode;
			memcpy(bcn_req->Bssid, bssid, 6);

			opt = (UINT8 *) & bcn_req->OptSubElem;

			if (strcmp(ssid, "Wildcard") != 0) {
				opt[0] = 0;
				opt[1] = strlen(ssid);
				strcpy(&opt[2], ssid);
				len += (opt[1] + 2);
			} else {
				opt[0] = 0;
				opt[1] = 0;
				len += 2;
			}

/***** Beacon Reporting Information Start *******/
			opt[len] = 1;
			opt[len + 1] = 2;
			opt[len + 2] = (ReportCond & 0xFF00) >> 8;
			opt[len + 3] = (ReportCond & 0x00FF);
			len += 4;
/***** Beacon Reporting Information End *******/

/***** Reporting Detail Start *******/
			opt[len] = 2;
			opt[len + 1] = 1;
			opt[len + 2] = ReportDetail;
			len += 3;
/***** Reporting Detail End *******/
			switch (VoWiCase) {
			case 2:
				if (ch == 255) {
				/***** AP Channel Report Start *******/
					opt[len] = 51;
					opt[len + 1] = 3;
					opt[len + 2] = 12;
					opt[len + 3] = 1;
					opt[len + 4] = 6;
				/***** AP Channel Report End *******/
				/***** AP Channel Report Start *******/
					opt[len + 5] = 51;
					opt[len + 6] = 3;
					opt[len + 7] = 1;
					opt[len + 8] = 36;
					opt[len + 9] = 48;
				/***** AP Channel Report End *******/
					len += 10;
				}
			case 1:
			case 4:
				/* Request */
				opt[len] = 10;
				opt[len + 1] = 5;	/* Length */
				opt[len + 2] = 0;	/* SSID */
				opt[len + 3] = 48;	/* RSN */
				opt[len + 4] = 70;	/* RRM Capabilities */
				opt[len + 5] = 54;	/* Mobility Domain */
				opt[len + 6] = 221;	/* Vendor Specific */
				len += 7;
				break;
			default:
				break;
			}

			RequestElement->Len =
				3 + sizeof(IEEEtypes_BeaconRequest_t) + len;
			skb_trim(skb,
				 sizeof(struct ieee80211_frame) + 23 + len);

			WLDBG_INFO(DBG_LEVEL_7,
				   "macMgmtMlme_RmBeaconRequest: Tx action frame ... \n");

			if (txMgmtMsg(netdev, skb) != OS_SUCCESS)
				wl_free_skb(skb);
		}

		WLDBG_EXIT(DBG_LEVEL_7);

	}

#endif

	void getVhtBwFreqInfo(UINT16 FreqBand, UINT16 Chan, UINT16 Chan2,
			      UINT16 ChnlWidth, UINT8 radiomode,
			      UINT8 * ch_width, UINT8 * center_freq0,
			      UINT8 * center_freq1) {
		extern UINT32 GetCenterFreq(UINT32 ch, UINT32 bw);
		extern UINT32 ie192_version;

		if ((ChnlWidth == CH_40_MHz_WIDTH) ||
		    (ChnlWidth == CH_20_MHz_WIDTH) ||
		    (FreqBand == FREQ_BAND_2DOT4GHZ)) {
			*ch_width = 0;
		}
#ifdef SOC_W8964		//deprecated
		else if ((ChnlWidth == CH_160_MHz_WIDTH) ||
			 (ChnlWidth == CH_AUTO_WIDTH)) {
			*ch_width = 2;	//160MHz
		}
#endif
		else {
			*ch_width = 1;	//80 MHz or (80MHz+80MHz        is not support, ch_width = 1 for new, ch_width =3 for old)
		}
		if (*ch_width == 0) {
			/* Channel Center freq seg0 field is reserved in ht20 or ht40 */
			*center_freq0 = 0;
			*center_freq1 = 0;
		} else {
			if (ie192_version == 2) {
#ifdef SOC_W906X
				if (ChnlWidth == CH_80_MHz_WIDTH) {
					*center_freq0 =
						GetCenterFreq(Chan,
							      CH_80_MHz_WIDTH);
					if (radiomode == RADIO_MODE_80p80) {
						*center_freq1 = GetCenterFreq(Chan2, CH_80_MHz_WIDTH);	//80+80
					} else {
						*center_freq1 = 0;	//80
					}
				} else if (ChnlWidth == CH_160_MHz_WIDTH) {
					*center_freq0 = GetCenterFreq(Chan, CH_160_MHz_WIDTH);	//80+80
					*center_freq1 = 0;
				}
#else
				if (*ch_width == 1)	//80MHz
				{
					*center_freq0 =
						GetCenterFreq(Chan, ChnlWidth);
					*center_freq1 = 0;
					printk("getVhtFreqInfo::: 1 center_freq0=%d center_freq1=%d\n", *center_freq0, *center_freq1);
				}
				if (*ch_width == 2)	//160MHz 
				{
					*center_freq0 =
						GetCenterFreq(Chan,
							      CH_160_MHz_WIDTH);
					*center_freq1 = 0;
				}
#endif
			} else {
				*center_freq0 = GetCenterFreq(Chan, ChnlWidth);
				*center_freq1 = 0;
			}
		}

		if (ie192_version == 2)
			*ch_width = *ch_width ? 1 : 0;	//new ch_width = 1 for all 80, 160 and 80+80
	}

#ifdef SOC_W906X
	void macMgmtMlme_ChannelSwitchReq(vmacApInfo_t * vmacSta_p,
					  Dfs_ChanSwitchReq_t * pChanSwitch) {
		MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
		macmgmtQ_MgmtMsg2_t *MgmtMsg_p;
		UINT16 extraLen =
			sizeof(IEEEtypes_WideBWCS_Element_t) +
			sizeof(IEEEtypes_SecondaryChannelOffsetElement_t);
		UINT16 FrameLen =
			sizeof(IEEEtypes_Category_t) +
			sizeof(IEEEtypes_ActionFieldType_t) +
			sizeof(IEEEtypes_ChannelSwitchAnnouncementElement_t) +
			extraLen;

		IEEEtypes_SecondaryChannelOffsetElement_t *pIE;
		IEEEtypes_WideBWCS_Element_t *pWideIE;
#ifdef AP_MAC_LINUX
		struct sk_buff *txSkb_p;
#endif
		MIB_PHY_DSSS_TABLE *PhyDSSSTable = mib->PhyDSSSTable;

		UINT32 ChnlWidth = PhyDSSSTable->Chanflag.ChnlWidth;
		UINT32 FreqBand = PhyDSSSTable->Chanflag.FreqBand;

		WLDBG_ENTER(DBG_LEVEL_7);

		if (ChnlWidth == CH_AUTO_WIDTH) {
			if (FreqBand == FREQ_BAND_2DOT4GHZ) {
				ChnlWidth = CH_40_MHz_WIDTH;
			} else {
				if ((*(mib->mib_ApMode)) &
				    (AP_MODE_11AC | AP_MODE_11AX))
					ChnlWidth = CH_160_MHz_WIDTH;
				else
					ChnlWidth = CH_40_MHz_WIDTH;
			}
		}
#ifdef 	BARBADOS_DFS_TEST
		if (!dfs_monitor)
#else
		if (dfs_test_mode)	/* DFS test mode - Send CSA Action frame. */
#endif
		{
#ifdef AP_MAC_LINUX
			if ((txSkb_p =
			     mlmeApiPrepMgtMsg2(IEEE_MSG_QOS_ACTION, &bcast,
						&vmacSta_p->macStaAddr,
						FrameLen)) == NULL)
				return;
			MgmtMsg_p = (macmgmtQ_MgmtMsg2_t *) txSkb_p->data;
#else
			if ((TxMsg_p =
			     mlmeApiPrepMgtMsg(IEEE_MSG_QOS_ACTION, &bcast,
					       &vmacSta_p->macStaAddr)) != NULL)
#endif
			{
				IEEEtypes_ChannelSwitchAnnouncementElement_t
					*ChannelSwitchAnnouncementElement_p;

				WLDBG_INFO(DBG_LEVEL_7,
					   "macMgmtMlme_ChannelSwitchReq: Packing the ACTION frame\n");

				MgmtMsg_p->Body.Action.Category =
					SPECTRUM_MANAGEMENT;
				MgmtMsg_p->Body.Action.Action =
					CHANNEL_SWITCH_ANNOUNCEMENT;

				/* no token in action frame */
				ChannelSwitchAnnouncementElement_p =
					(IEEEtypes_ChannelSwitchAnnouncementElement_t
					 *) & MgmtMsg_p->Body.Action.
					DialogToken;

				ChannelSwitchAnnouncementElement_p->ElementId =
					CSA;
				ChannelSwitchAnnouncementElement_p->Len =
					sizeof(IEEEtypes_ChannelSwitchCmd_t);
				ChannelSwitchAnnouncementElement_p->Mode =
					pChanSwitch->ChannelSwitchCmd.Mode;
				ChannelSwitchAnnouncementElement_p->Count =
					pChanSwitch->ChannelSwitchCmd.
					ChannelSwitchCount;
				ChannelSwitchAnnouncementElement_p->Channel =
					pChanSwitch->ChannelSwitchCmd.
					ChannelNumber;
				if (*(mib->mib_ApMode) &
				    (AP_MODE_N_ONLY | AP_MODE_11AC |
				     AP_MODE_11AX)) {
					pIE = (IEEEtypes_SecondaryChannelOffsetElement_t *) (ChannelSwitchAnnouncementElement_p + 1);
			    /** HT: Secondary Channel Offset Element [3]
				    [1]ID: 62
				    [1]len: 1
				    [1]Secondary Channel Offset 
					    0: no secondary channel
					    1: above primary channel
					    3: below primary channel
					    2 and oters: reserved
			    **/
					pIE->ElementId = SEC_CHAN_OFFSET;
					pIE->Len = 1;
					if (ChnlWidth < CH_40_MHz_WIDTH)
						pIE->Offset = 0;
					else
						pIE->Offset =
							macMgmtMlme_Get40MHzExtChannelOffset
							(ChannelSwitchAnnouncementElement_p->
							 Channel);

					if (ChnlWidth > CH_40_MHz_WIDTH) {
						pWideIE =
							(IEEEtypes_WideBWCS_Element_t
							 *) (pIE + 1);

				/** VHT: Wide Bandwidth Channel Switch Element [5]
				        [1]ID: 194
				        [1]len:  3
			        	[1]New Channel Width 
					    0: 20/40
					    1: 80, 160, 80+80 
					    2: 160 (deprecated)
					    3: non-contiguous 80+80  (deprecated)
					    others: deprecated
				        [1]New Channel Cneter Frequency Segment 0
				        [1]New Channel Cneter Frequency Segment 1
			        **/
						pWideIE->ElementId =
							WIDE_BW_CHAN_SWITCH;
						pWideIE->Len = 3;

						getVhtBwFreqInfo(PhyDSSSTable->
								 Chanflag.
								 FreqBand,
								 pChanSwitch->
								 chInfo.channel,
								 pChanSwitch->
								 chInfo.
								 channel2,
								 PhyDSSSTable->
								 Chanflag.
								 ChnlWidth,
								 pChanSwitch->
								 chInfo.
								 chanflag.
								 radiomode,
								 &pWideIE->
								 ch_width,
								 &pWideIE->
								 center_freq0,
								 &pWideIE->
								 center_freq1);
					} else
						skb_trim(txSkb_p,
							 txSkb_p->len -
							 sizeof
							 (IEEEtypes_WideBWCS_Element_t));
				} else {
					skb_trim(txSkb_p,
						 txSkb_p->len - extraLen);
				}

				if (txMgmtMsg(vmacSta_p->dev, txSkb_p) !=
				    OS_SUCCESS) {
					WLDBG_INFO(DBG_LEVEL_7,
						   "macMgmtMlme_ChannelSwitchReq: Error sending out ACTION framee\n");
					wl_free_skb(txSkb_p);
				}
			}
		}

		if (1)		//sendResult == TRUE)        
		{
			/* update beacon 
			 * from system's perspective, code shouldn't be here,
			 * anyway, i just put it here
			 */

#ifdef MRVL_DFS
			{
				MIB_SPECTRUM_MGMT *mib_SpectrumMagament_p =
					vmacSta_p->ShadowMib802dot11->
					SpectrumMagament;
				/*Store the CSA Parameters in Shadow MIB */
				mib_SpectrumMagament_p->csaChannelNumber =
					pChanSwitch->chInfo.channel;
				mib_SpectrumMagament_p->csaCount =
					pChanSwitch->ChannelSwitchCmd.
					ChannelSwitchCount;
				mib_SpectrumMagament_p->csaMode =
					pChanSwitch->ChannelSwitchCmd.Mode;
			}
#ifdef 	BARBADOS_DFS_TEST
			if (!dfs_monitor)	/* DFS monitor mode - do not update channel list, stay in current channel. */
#else
			if (!dfs_test_mode)	/* DFS test mode - do not update channel list, stay in current channel. */
#endif
			{
				if (pChanSwitch->chInfo.channel2) {
					extern BOOLEAN
						UpdateSecondChannelInMIB
						(vmacApInfo_t * vmacSta_p,
						 UINT32 channel);

					UpdateSecondChannelInMIB(vmacSta_p,
								 pChanSwitch->
								 chInfo.
								 channel2);
				}

				UpdateCurrentChannelInMIB(vmacSta_p, pChanSwitch->chInfo.channel);	//macMgmtMlme_ChannelSwitchReq
				mib_Update();
			}
#ifdef DEBUG_PRINT
			WLDBG_INFO(DBG_LEVEL_0,
				   "RECEIVED A CHANNEL SWITCH ANNOUNCEMENT COMMAND :%d:%d:%d chan2=%d radiomode=%d\n",
				   pChanSwitch->chInfo.channel,
				   pChanSwitch->ChannelSwitchCmd.Mode,
				   pChanSwitch->ChannelSwitchCmd.
				   ChannelSwitchCount,
				   pChanSwitch->chInfo.channel2,
				   PhyDSSSTable->Chanflag.radiomode);
#endif
#endif //MRVL_DFS

			wlFwSetChannelSwitchIE(vmacSta_p->dev,
					       pChanSwitch->chInfo.channel,
					       pChanSwitch->chInfo.channel2,
					       pChanSwitch->ChannelSwitchCmd.
					       Mode,
					       pChanSwitch->ChannelSwitchCmd.
					       ChannelSwitchCount,
					       PhyDSSSTable->Chanflag);

			/* disable mgmt and data ISR */
			//WL_WRITE_WORD(MIR_INTR_MASK, WL_REGS32(MIR_INTR_MASK) & ~(MSK_DATA_BUF_RDY|MSK_MGMT_BUF_RDY));

			/* enbale beacon free ISR */
			//bcngen_EnableBcnFreeIntr();
		}

		WLDBG_EXIT(DBG_LEVEL_7);

	}
#else //SC4
	void macMgmtMlme_ChannelSwitchReq(vmacApInfo_t * vmacSta_p,
					  IEEEtypes_ChannelSwitchCmd_t *
					  ChannelSwitchtCmd_p) {
		MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
		macmgmtQ_MgmtMsg2_t *MgmtMsg_p;
		UINT16 FrameLen = sizeof(IEEEtypes_Category_t) +
			sizeof(IEEEtypes_ActionFieldType_t) +
			sizeof(IEEEtypes_ChannelSwitchAnnouncementElement_t);
#ifndef SOC_W906X
		UINT16 extraLen =
			sizeof(IEEEtypes_WideBWCS_Element_t) +
			sizeof(IEEEtypes_SecondaryChannelOffsetElement_t);
		IEEEtypes_SecondaryChannelOffsetElement_t *pIE;
		IEEEtypes_WideBWCS_Element_t *pWideIE;
#endif
#ifdef AP_MAC_LINUX
		struct sk_buff *txSkb_p;
#endif
		MIB_PHY_DSSS_TABLE *PhyDSSSTable = mib->PhyDSSSTable;

#ifndef SOC_W906X
		UINT32 ChnlWidth = PhyDSSSTable->Chanflag.ChnlWidth;
		UINT32 FreqBand = PhyDSSSTable->Chanflag.FreqBand;
#endif
		WLDBG_ENTER(DBG_LEVEL_7);

#ifndef SOC_W906X
		if (ChnlWidth == CH_AUTO_WIDTH) {
			if (FreqBand == FREQ_BAND_2DOT4GHZ) {
				ChnlWidth = CH_40_MHz_WIDTH;
			} else {
				if ((*(mib->mib_ApMode) >= AP_MODE_11AC) &&
				    (*(mib->mib_ApMode) <=
				     AP_MODE_5GHZ_Nand11AC))
					ChnlWidth = CH_160_MHz_WIDTH;
				else
					ChnlWidth = CH_40_MHz_WIDTH;
			}
		}
#endif /* SOC_W906X */
#ifdef 	BARBADOS_DFS_TEST
		if (!dfs_monitor)
#else
		if (dfs_test_mode)	/* DFS test mode - Send CSA Action frame. */
#endif
		{
#ifdef AP_MAC_LINUX
#ifndef SOC_W906X
			if ((txSkb_p =
			     mlmeApiPrepMgtMsg2(IEEE_MSG_QOS_ACTION, &bcast,
						&vmacSta_p->macStaAddr,
						FrameLen + extraLen)) == NULL)
#else
			if ((txSkb_p =
			     mlmeApiPrepMgtMsg2(IEEE_MSG_QOS_ACTION, &bcast,
						&vmacSta_p->macStaAddr,
						FrameLen)) == NULL)
#endif /* SOC_W906X */
				return;
			MgmtMsg_p = (macmgmtQ_MgmtMsg2_t *) txSkb_p->data;
#else
			if ((TxMsg_p =
			     mlmeApiPrepMgtMsg(IEEE_MSG_QOS_ACTION, &bcast,
					       &vmacSta_p->macStaAddr)) != NULL)
#endif
			{
				IEEEtypes_ChannelSwitchAnnouncementElement_t
					*ChannelSwitchAnnouncementElement_p;

				WLDBG_INFO(DBG_LEVEL_7,
					   "macMgmtMlme_ChannelSwitchReq: Packing the ACTION frame\n");

				MgmtMsg_p->Body.Action.Category =
					SPECTRUM_MANAGEMENT;
				MgmtMsg_p->Body.Action.Action =
					CHANNEL_SWITCH_ANNOUNCEMENT;

				/* no token in action frame */
				ChannelSwitchAnnouncementElement_p =
					(IEEEtypes_ChannelSwitchAnnouncementElement_t
					 *) & MgmtMsg_p->Body.Action.
					DialogToken;

				ChannelSwitchAnnouncementElement_p->ElementId =
					CSA;
				ChannelSwitchAnnouncementElement_p->Len =
					sizeof(IEEEtypes_ChannelSwitchCmd_t);
				ChannelSwitchAnnouncementElement_p->Mode =
					ChannelSwitchtCmd_p->Mode;
				ChannelSwitchAnnouncementElement_p->Channel =
					ChannelSwitchtCmd_p->ChannelNumber;
				ChannelSwitchAnnouncementElement_p->Count =
					ChannelSwitchtCmd_p->ChannelSwitchCount;

#ifndef SOC_W906X
				if (!(*(mib->mib_ApMode) == AP_MODE_B_ONLY
				      || *(mib->mib_ApMode) == AP_MODE_G_ONLY
				      || *(mib->mib_ApMode) == AP_MODE_MIXED
				      || *(mib->mib_ApMode) == AP_MODE_A_ONLY
				      || *(mib->mib_ApMode) == AP_MODE_AandG)) {
					pIE = (IEEEtypes_SecondaryChannelOffsetElement_t *) (ChannelSwitchAnnouncementElement_p + 1);
				/** HT: Secondary Channel Offset Element [3]
					[1]ID: 62
					[1]len: 1
					[1]Secondary Channel Offset 
						0: no secondary channel
						1: above primary channel
						3: below primary channel
						2 and oters: reserved
				**/
					pIE->ElementId = SEC_CHAN_OFFSET;
					pIE->Len = 1;
					if (ChnlWidth < CH_40_MHz_WIDTH)
						pIE->Offset = 0;
					else
						pIE->Offset =
							macMgmtMlme_Get40MHzExtChannelOffset
							(ChannelSwitchtCmd_p->
							 ChannelNumber);

					if (ChnlWidth > CH_40_MHz_WIDTH) {
						pWideIE =
							(IEEEtypes_WideBWCS_Element_t
							 *) (pIE + 1);

					/** VHT: Wide Bandwidth Channel Switch Element [5]
						[1]ID: 194
						[1]len:  3
						[1]New Channel Width 
							0: 20/40
							1: 80, 160, 80+80 
							2: 160 (deprecated)
							3: non-contiguous 80+80  (deprecated)
							others: deprecated
						[1]New Channel Cneter Frequency Segment 0
						[1]New Channel Cneter Frequency Segment 1
					**/
						pWideIE->ElementId =
							WIDE_BW_CHAN_SWITCH;
						pWideIE->Len = 3;

						getVhtBwFreqInfo(PhyDSSSTable->
								 Chanflag.
								 FreqBand,
								 ChannelSwitchtCmd_p->
								 ChannelNumber,
								 PhyDSSSTable->
								 Chanflag.
								 ChnlWidth,
								 &pWideIE->
								 ch_width,
								 &pWideIE->
								 center_freq0,
								 &pWideIE->
								 center_freq1);
					} else
						skb_trim(txSkb_p,
							 txSkb_p->len -
							 sizeof
							 (IEEEtypes_WideBWCS_Element_t));
				} else {
					skb_trim(txSkb_p,
						 txSkb_p->len - extraLen);
				}
#endif /* SOC_W906X */
				if (txMgmtMsg(vmacSta_p->dev, txSkb_p) !=
				    OS_SUCCESS) {
					WLDBG_INFO(DBG_LEVEL_7,
						   "macMgmtMlme_ChannelSwitchReq: Error sending out ACTION framee\n");
					wl_free_skb(txSkb_p);
				}
			}
		}

		if (1)		//sendResult == TRUE)        
		{
			/* update beacon 
			 * from system's perspective, code shouldn't be here,
			 * anyway, i just put it here
			 */
			IEEEtypes_ChannelSwitchAnnouncementElement_t
				channelSwitchAnnouncementIE;

			channelSwitchAnnouncementIE.Mode =
				ChannelSwitchtCmd_p->Mode;
			channelSwitchAnnouncementIE.Channel =
				ChannelSwitchtCmd_p->ChannelNumber;
			channelSwitchAnnouncementIE.Count =
				ChannelSwitchtCmd_p->ChannelSwitchCount;

#ifdef MRVL_DFS
			{
				MIB_SPECTRUM_MGMT *mib_SpectrumMagament_p =
					vmacSta_p->ShadowMib802dot11->
					SpectrumMagament;
				/*Store the CSA Parameters in Shadow MIB */
				mib_SpectrumMagament_p->csaChannelNumber =
					ChannelSwitchtCmd_p->ChannelNumber;
				mib_SpectrumMagament_p->csaCount =
					ChannelSwitchtCmd_p->ChannelSwitchCount;
				mib_SpectrumMagament_p->csaMode =
					ChannelSwitchtCmd_p->Mode;
			}
#ifdef 	BARBADOS_DFS_TEST
			if (!dfs_monitor)	/* DFS monitor mode - do not update channel list, stay in current channel. */
#else
			if (!dfs_test_mode)	/* DFS test mode - do not update channel list, stay in current channel. */
#endif
			{
				UpdateCurrentChannelInMIB(vmacSta_p,
							  ChannelSwitchtCmd_p->
							  ChannelNumber);
				mib_Update();
			}
#ifdef DEBUG_PRINT
			WLDBG_INFO(DBG_LEVEL_0,
				   "RECEIVED A CHANNEL SWITCH ANNOUNCEMENT COMMAND :%d:%d:%d\n",
				   ChannelSwitchtCmd_p->ChannelNumber,
				   ChannelSwitchtCmd_p->Mode,
				   ChannelSwitchtCmd_p->ChannelSwitchCount);
#endif
#endif //MRVL_DFS
			wlFwSetChannelSwitchIE(vmacSta_p->dev,
					       ChannelSwitchtCmd_p->
					       ChannelNumber,
#ifdef SOC_W906X
					       pChanSwitch->chInfo.channel2,
#endif
					       ChannelSwitchtCmd_p->Mode,
					       ChannelSwitchtCmd_p->
					       ChannelSwitchCount,
#ifdef SOC_W906X
					       PhyDSSSTable->Chanflag);
#else
					       FreqBand, ChnlWidth);
#endif

			/* disable mgmt and data ISR */
			//WL_WRITE_WORD(MIR_INTR_MASK, WL_REGS32(MIR_INTR_MASK) & ~(MSK_DATA_BUF_RDY|MSK_MGMT_BUF_RDY));

			/* enbale beacon free ISR */
			//bcngen_EnableBcnFreeIntr();
		}

		WLDBG_EXIT(DBG_LEVEL_7);

	}
#endif

	extern SINT8 BcnTxPwr;
	static void macMgmtMlme_TPCReport(vmacApInfo_t * vmacSta_p,
					  IEEEtypes_MacAddr_t * Addr,
					  UINT8 DialogToken, UINT8 RSSI) {
		macmgmtQ_MgmtMsg2_t *MgmtMsg_p;
		BOOLEAN sendResult = FALSE;
#ifdef AP_MAC_LINUX
		struct sk_buff *txSkb_p;
#else
		tx80211_MgmtMsg_t *TxMsg_p;
#endif
		WLDBG_ENTER(DBG_LEVEL_7);

#ifdef AP_MAC_LINUX
		if ((txSkb_p =
		     mlmeApiPrepMgtMsg(IEEE_MSG_QOS_ACTION, Addr,
				       &vmacSta_p->macStaAddr)) == NULL)
			return;
		MgmtMsg_p = (macmgmtQ_MgmtMsg2_t *) txSkb_p->data;
#else
		if ((TxMsg_p =
		     mlmeApiPrepMgtMsg(IEEE_MSG_QOS_ACTION, Addr,
				       &vmacSta_p->macStaAddr)) != NULL)
#endif
		{
			IEEEtypes_TPCRepElement_t *TPCRepElement_p;

			MgmtMsg_p->Body.Action.Category = SPECTRUM_MANAGEMENT;
			MgmtMsg_p->Body.Action.Action = TPC_REPORT;
			MgmtMsg_p->Body.Action.DialogToken = DialogToken;

			TPCRepElement_p =
				(IEEEtypes_TPCRepElement_t *) & MgmtMsg_p->Body.
				Action.Data.TPCReport;

			TPCRepElement_p->ElementId = TPC_REP;
			TPCRepElement_p->Len = 2;
			TPCRepElement_p->TxPwr = BcnTxPwr;	/* approx. value as the one with beacon frame */
			TPCRepElement_p->LinkMargin = RSSI / 10;

			//MgmtMsg_p->Hdr.FrmBodyLen = sizeof(IEEEtypes_TPCRepElement_t) + 3; /* length of Measurement IEs plus 3(Category+action+DiaglogToken) */    

			WLDBG_INFO(DBG_LEVEL_7,
				   "macMgmtMlme_TPCReport: send out the action frame\n");
			if (txMgmtMsg(vmacSta_p->dev, txSkb_p) == OS_SUCCESS)
				sendResult = TRUE;
			else {
				WLDBG_INFO(DBG_LEVEL_7,
					   "macMgmtMlme_TPCReport: Error sending out ACTION framee\n");
				wl_free_skb(txSkb_p);
			}
		}
		WLDBG_EXIT(DBG_LEVEL_7);
	}

	void msgMrequestIndPack(IEEEtypes_MRequestInd_t * MrequestInd_p,
				dot11MgtFrame_t * mgtFrame_p) {
		UINT32 lenBody;
		UINT32 loop_d, loop_s;
		UINT32 ieNum;

		/* cast it because the sourceInsight has problem to decode the structure definition
		 * and make the code more readable
		 */
		IEEEtypes_ActionField_t *Action_p = &mgtFrame_p->Body.Action;
		IEEEtypes_MeasurementRequestElement_t *MeasurementRequest_p =
			&Action_p->Data.MeasurementRequest[0];
		/* estimate the number of IE in this frame 
		 * the number of IE is easily be calculated because length of IE is constant in MREQUEST case
		 * checking the len is probably is needed
		 */
		lenBody =
			mgtFrame_p->Hdr.FrmBodyLen - 4 - 4 /*FCS*/ -
			sizeof(IEEEtypes_MgmtHdr_t) + 6 + 2;
		ieNum = (lenBody -
			 3) / sizeof(IEEEtypes_MeasurementRequestElement_t);

		/*peerstaAddr is the the station the frame coming from */
		memcpy(MrequestInd_p->PeerStaAddr, mgtFrame_p->Hdr.SrcAddr,
		       sizeof(IEEEtypes_MacAddr_t));

		/* take the dialog token
		 * the dialog token is the token associated with the action frame
		 */
		MrequestInd_p->DiaglogToken = Action_p->DialogToken;

		/* get the request command set */
		for (loop_d = loop_s = 0; loop_s < MIN(ieNum, MAX_NR_IE);
		     loop_d++, loop_s++) {
			/* a simple semantic check */
			if ((MeasurementRequest_p[loop_s].ElementId !=
			     MEASUREMENT_REQ) ||
			    (MeasurementRequest_p[loop_s].Len !=
			     3 + sizeof(IEEEtypes_MeasurementReq_t))) {
				loop_d--;
				continue;
			}

			/* pack it */
			MrequestInd_p->MeasureReqSet[loop_d].MeasurementToken =
				MeasurementRequest_p[loop_s].Token;
			MrequestInd_p->MeasureReqSet[loop_d].Mode =
				MeasurementRequest_p[loop_s].Mode;
			MrequestInd_p->MeasureReqSet[loop_d].Type =
				MeasurementRequest_p[loop_s].Type;
			MrequestInd_p->MeasureReqSet[loop_d].Request =
				MeasurementRequest_p[loop_s].Request;

			MrequestInd_p->RequestItems++;
		}

		return;
	}

	static void msgMreportIndPack(IEEEtypes_MReportInd_t * MReportInd_p,
				      macmgmtQ_MgmtMsg_t * MgmtMsg_p) {
		UINT32 idx = 0;
		SINT32 remainLen =
			MgmtMsg_p->Hdr.FrmBodyLen /*- sizeof(RxSign_t)*/  -
			sizeof(IEEEtypes_GenHdr_t) - 3;

		/* cast it because the sourceInsight has problem to decode the structure definition
		 * and make the code more readable
		 */
		IEEEtypes_ActionField_t *Action_p = &MgmtMsg_p->Body.Action;
		IEEEtypes_MeasurementReportElement_t *MeasurementReport_p =
			&Action_p->Data.MeasurementReport[0];

		/*peerstaAddr is the the station the frame coming from */
		memcpy(MReportInd_p->PeerStaAddr, MgmtMsg_p->Hdr.SrcAddr,
		       sizeof(IEEEtypes_MacAddr_t));

		/* take the dialog token
		 * the dialog token is the token associated with the action frame
		 */
		MReportInd_p->DiaglogToken = Action_p->DialogToken;

		/* get the request command set */
		while (remainLen > 0) {
			UINT32 ieLen = MeasurementReport_p->Len + 2;

			/* a simple semantic check */
			if (MeasurementReport_p->ElementId != MEASUREMENT_REP) {
				/* remaining IE's total length */
				remainLen -= ieLen;

				/* mov to next IE */
				MeasurementReport_p =
					(IEEEtypes_MeasurementReportElement_t
					 *) ((UINT8 *) MeasurementReport_p +
					     ieLen);
				continue;
			}

			/* pack it */
			MReportInd_p->MeasureRepSet[idx].MeasurementToken =
				MeasurementReport_p->MeasurementToken;
			MReportInd_p->MeasureRepSet[idx].Mode =
				MeasurementReport_p->Mode;
			MReportInd_p->MeasureRepSet[idx].Type =
				MeasurementReport_p->Type;
			MReportInd_p->MeasureRepSet[idx].Report =
				MeasurementReport_p->Report.DefReport;
			/* remaining IE's total length */
			remainLen -= ieLen;

			/* mov to next IE */
			MeasurementReport_p =
				(IEEEtypes_MeasurementReportElement_t
				 *) ((UINT8 *) MeasurementReport_p + ieLen);

			idx++;
		}

		MReportInd_p->ReportItems = idx;
		return;
	}

	static void msgChannelswitchIndPack(IEEEtypes_ChannelSwitchInd_t *
					    ChannelSwitchInd_p,
					    macmgmtQ_MgmtMsg_t * MgmtMsg_p) {
		/* cast it because the sourceInsight has problem to decode the structure definition
		 * and make the code more readable
		 */
		IEEEtypes_ActionField_t *Action_p = &MgmtMsg_p->Body.Action;
		IEEEtypes_ChannelSwitchAnnouncementElement_t *ChannelSwitch_p =
			&Action_p->Data.ChannelSwitchAnnouncement;

		/* a simple semantic check */
		if ((ChannelSwitch_p->ElementId != CHANNEL_SWITCH_ANNOUNCEMENT)
		    || (ChannelSwitch_p->Len != 3))
			return;

		/* 
		 * pack the indication parameters in the primitive
		 */
		/*peerstaAddr is the the station the frame coming from */
		memcpy(ChannelSwitchInd_p->PeerStaAddr, MgmtMsg_p->Hdr.SrcAddr,
		       sizeof(IEEEtypes_MacAddr_t));

		ChannelSwitchInd_p->Mode = ChannelSwitch_p->Mode;
		ChannelSwitchInd_p->ChannelNumber = ChannelSwitch_p->Channel;
		ChannelSwitchInd_p->ChannelSwitchCount = ChannelSwitch_p->Count;

		return;
	}

	extern BOOLEAN macMgmtMlme_80211hAct(vmacApInfo_t * vmacSta_p,
					     macmgmtQ_MgmtMsg3_t * MgmtMsg_p) {
		MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
		MIB_STA_CFG *mib_StaCfg_p =
			vmacSta_p->Mib802dot11->StationConfig;
		smeQ_MgmtMsg_t *toSmeMsg = NULL;

		WLDBG_ENTER(DBG_LEVEL_7);
		/* whether the action frame is for 802.11h */
		if (MgmtMsg_p->Body.Action.Category != SPECTRUM_MANAGEMENT)
			return FALSE;

		if (((*(mib->mib_ApMode) != AP_MODE_A_ONLY) &&
		     (*(mib->mib_ApMode) != AP_MODE_AandG)) ||
		    (mib_StaCfg_p->SpectrumManagementRequired != TRUE)) {
			WLDBG_INFO(DBG_LEVEL_7,
				   "macMgmtMlme_80211hAct : no need to do spectrum management\n");
			return TRUE;
		}

		if ((toSmeMsg =
		     (smeQ_MgmtMsg_t *)
		     wl_kmalloc_autogfp(sizeof(smeQ_MgmtMsg_t))) == NULL) {
			WLDBG_INFO(DBG_LEVEL_7,
				   "macMgmtMlme_80211hAct : failed to alloc msg buffer\n");
			return TRUE;
		}

		memset(toSmeMsg, 0, sizeof(smeQ_MgmtMsg_t));

		switch (MgmtMsg_p->Body.Action.Action) {
			/* only for MLME-MREQUEST.ind */
		case MEASUREMENT_REQUEST:
			toSmeMsg->MsgType = SME_NOTIFY_MREQUEST_IND;
			msgMrequestIndPack((IEEEtypes_MRequestInd_t *) &
					   toSmeMsg->Msg.MrequestInd,
					   (dot11MgtFrame_t *) MgmtMsg_p);
			break;

			/* only for MLME-REPORT.ind */
		case MEASUREMENT_REPORT:
			toSmeMsg->MsgType = SME_NOTIFY_MREPORT_IND;
			msgMreportIndPack((IEEEtypes_MReportInd_t *) &
					  toSmeMsg->Msg.MreportInd,
					  (macmgmtQ_MgmtMsg_t *) MgmtMsg_p);
			break;

			/* start TPC protocol and processed in MLME */
		case TPC_REQUEST:
			{
				//rx80211_MgmtMsg_t *RxBufPtr;

				//RxBufPtr = (rx80211_MgmtMsg_t *)((char *)MgmtMsg_p - sizeof(RxSign_t));

				/*
				 * Call TPC protocol sub-function here
				 */
				macMgmtMlme_TPCReport(vmacSta_p,
						      &MgmtMsg_p->Hdr.SrcAddr,
						      MgmtMsg_p->Body.Action.
						      DialogToken,
						      0
						      /*RxBufPtr->u.RxSign.RSSI */
						      );
			}
			/* no msg have to be sent to SME
			 * have to free the buffer
			 */
			wl_kfree((UINT8 *) toSmeMsg);
			return TRUE;
			break;

			/* start TPC protocol and processed in MLME */
		case TPC_REPORT:
			/*
			 * Call TPC protocol sub-function here
			 */

			/*
			 * send MLME-TPCADPT.cfm to SME
			 */
			wl_kfree((UINT8 *) toSmeMsg);
			return TRUE;
			break;

			/* only for MLME-CHANNELSWITCH.ind */
		case CHANNEL_SWITCH_ANNOUNCEMENT:
			toSmeMsg->MsgType = SMC_NOTIFY_CHANNELSWITCH_IND;
			msgChannelswitchIndPack((IEEEtypes_ChannelSwitchInd_t *)
						& toSmeMsg->Msg.MrequestInd,
						(macmgmtQ_MgmtMsg_t *)
						MgmtMsg_p);
			break;

		default:
			break;
		}
		toSmeMsg->vmacSta_p = vmacSta_p;
		smeQ_MgmtWriteNoBlock(toSmeMsg);
		wl_kfree((UINT8 *) toSmeMsg);
		WLDBG_EXIT(DBG_LEVEL_7);

		return TRUE;
	}
#endif /* IEEE80211H */
#ifdef COEXIST_20_40_SUPPORT
	extern BOOLEAN macMgmtMlme_80211PublicAction(vmacApInfo_t * vmacSta_p,
						     macmgmtQ_MgmtMsg3_t *
						     MgmtMsg_p) {

		MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
		MIB_PHY_DSSS_TABLE *PhyDSSSTable = mib->PhyDSSSTable;
		IEEEtypes_20_40_Coexist_Act_t *CoexistAction;
		UINT8 i;

		if (!(*(vmacSta_p->ShadowMib802dot11->mib_HT40MIntoler))) {
			printk("Not in 20 40 mode now\n");
			return FALSE;
		}

		if (!
		    (MgmtMsg_p->Body.Action.Category == ACTION_PUBLIC &&
		     MgmtMsg_p->Body.Action.Action == 0))
			return FALSE;

		if (!(PhyDSSSTable->Chanflag.FreqBand == FREQ_BAND_2DOT4GHZ
		      && (PhyDSSSTable->Chanflag.ChnlWidth == CH_AUTO_WIDTH ||
			  PhyDSSSTable->Chanflag.ChnlWidth == CH_40_MHz_WIDTH)))
			return FALSE;
				/** accept only in 2.4G mode **/

		CoexistAction =
			(IEEEtypes_20_40_Coexist_Act_t *) & MgmtMsg_p->Body.
			Action.Category;

		if (CoexistAction->Coexist_Report.ElementId !=
		    _20_40_BSSCOEXIST) {
			return FALSE;
		}

		if (CoexistAction->Coexist_Report.Coexist.FortyMhz_Intorant == 1
		    || CoexistAction->Coexist_Report.Coexist.
		    TwentyMhz_BSS_Width_Request == 1) {

			Handle20_40_Channel_switch(vmacSta_p, 0);
		}

		if (CoexistAction->Intolerant_Report.ElementId !=
		    _20_40_BSS_INTOLERANT_CHANNEL_REPORT) {
			printk("intolerant element %x does not exist\n",
			       CoexistAction->Intolerant_Report.ElementId);
			return FALSE;

		}

		for (i = 0; i < CoexistAction->Intolerant_Report.Len; i++) {

			if (CoexistAction->Intolerant_Report.ChanList[i] != 0) {
				extern int
					Check_40MHz_Affected_range(vmacApInfo_t
								   *, int, int);

				if (Check_40MHz_Affected_range
				    (vmacSta_p,
				     CoexistAction->Intolerant_Report.
				     ChanList[i], 0))
					Handle20_40_Channel_switch(vmacSta_p,
								   0);
				break;
			}

		}

		return TRUE;

	}
#endif

	UINT32 hw_GetPhyRateIndex(vmacApInfo_t * vmacSta_p, UINT32 Rate) {
		MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
		UINT32 i;
		UINT8 MaxRate;

		if (Is5GBand(*(mib->mib_ApMode))) {
			MaxRate = IEEEtypes_MAX_DATA_RATES_A;
		} else
			MaxRate = IEEEtypes_MAX_DATA_RATES_G;

		for (i = 0; i < MaxRate - 1; i++) {
			if (Is5GBand(*(mib->mib_ApMode))) {
				//add for fix klocwork defects. Should re-organize the function ???
				if (i < IEEEtypes_MAX_DATA_RATES_A) {
					if (PhyRatesA[i] == Rate)
						return i;
				}
			} else {
				if (PhyRates[i] == Rate)
					return i;
			}
		}
		return (MaxRate + 1);
	}

	UINT32 hw_GetPhyRateIndex2(UINT32 Rate) {
		UINT32 i;
		UINT8 MaxRate;

		MaxRate = IEEEtypes_MAX_DATA_RATES_G;

		for (i = 0; i < MaxRate - 1; i++) {
			{
				if (PhyRates[i] == Rate)
					return i;
			}

		}
		return (MaxRate + 1);

	}

	extern WL_STATUS pool_FreeBuf(char *ReturnedBuf_p) {
		/* Dummy for now. */
		return SUCCESS;
	}
	inline void MonitorErp(vmacApInfo_t * vmacSta_p) {
		if ((BStnAroundCnt == 3) &&
		    (PreviousBAroundStnCount != BStnAroundCnt)) {
			macMgmtMlme_IncrBonlyStnCnt(vmacSta_p, 1);
		} else if ((BStnAroundCnt == 0) &&
			   (PreviousBAroundStnCount != BStnAroundCnt)) {
			macMgmtMlme_DecrBonlyStnCnt(vmacSta_p, 1);
		}

		PreviousBAroundStnCount = BStnAroundCnt;

		if (BAPCount > 0 || ERPCount > 0) {
			BStnAroundCnt = BSTATION_AGECOUNT;
		} else {
			if (BStnAroundCnt != 0) {
				BStnAroundCnt--;
			}
		}
		BAPCount = 0;
		ERPCount = 0;
	}
	void MonitorTimerProcess(UINT8 * data) {
		vmacApInfo_t *vmacSta_p = (vmacApInfo_t *) data;
		extStaDb_AggrCk(vmacSta_p);
		if (vmacSta_p->monitorcnt++ % 3 == 0) {
			if (vmacSta_p->download == FALSE) {
				if (*vmacSta_p->Mib802dot11->mib_ErpProtEnabled)
					MonitorErp(vmacSta_p);
#ifdef NPROTECTION
				checkLegDevOutBSS(vmacSta_p);
#endif
			}
		}
#ifdef INTOLERANT40
		/* Check HT 40-20 switch in 30 min */
		if (sMonitorcnt30min) {
			/* Actually we set a 25 min timer */
			if (sMonitorcnt30min++ % INTOLERANTCHEKCOUNTER == 0) {
				HT40MIntolerantHandler(vmacSta_p, 0);
			}
		}
#endif

/* RTS protection check */
#ifdef SOC_W906X
		{
			extern int protect_dynamic;
			extern int protect_rx_rate_thres;
			extern int protect_tx_rate_thres;
			extern UINT32 wlFwSetProtectMode(struct net_device
							 *netdev, UINT32 action,
							 UINT32 * mode);
			struct wlprivate *wlpptr;
			int entries, ivap;
			long rxbps, txbps;
			int entries_total = 0;
			int do_check = 0;
			u32 mode;

			wlpptr = NETDEV_PRIV_P(struct wlprivate,
					       vmacSta_p->dev);

			if (protect_dynamic) {
				struct wlprivate *wlpptr_v;

				ivap = wlpptr->wlpd_p->NumOfAPs;
				if (wlpptr->vdev[ivap] != NULL &&
				    (wlpptr->vdev[ivap]->flags & IFF_RUNNING)) {
					wlpptr_v =
						NETDEV_PRIV_P(struct wlprivate,
							      wlpptr->
							      vdev[ivap]);
					if (wlpptr_v->vmacSta_p->OpMode ==
					    WL_OP_MODE_VSTA)
						do_check = 1;
				} else {
					for (ivap = 0;
					     ivap < wlpptr->wlpd_p->NumOfAPs;
					     ivap++) {
						if (wlpptr->vdev[ivap] != NULL
						    && (wlpptr->vdev[ivap]->
							flags & IFF_RUNNING)) {
							wlpptr_v =
								NETDEV_PRIV_P
								(struct
								 wlprivate,
								 wlpptr->
								 vdev[ivap]);

							if (wlpptr_v->
							    vmacSta_p->OpMode !=
							    WL_OP_MODE_VAP)
								continue;

							entries =
								extStaDb_entries
								(wlpptr_v->
								 vmacSta_p, 0);
							if (entries)
								entries_total +=
									entries;
						}
					}
					if (entries_total)
						do_check = 1;
				}

				if (do_check) {
					txbps = (wlpptr->netDevStats.tx_bytes -
						 vmacSta_p->tx_bytes_last) * 8;
					rxbps = (wlpptr->netDevStats.rx_bytes -
						 vmacSta_p->rx_bytes_last) * 8;

					vmacSta_p->tx_bytes_last =
						wlpptr->netDevStats.tx_bytes;
					vmacSta_p->rx_bytes_last =
						wlpptr->netDevStats.rx_bytes;

					if ((txbps >= protect_tx_rate_thres) &&
					    (rxbps < protect_rx_rate_thres)) {
						/* protect disable  for UDP */
						mode = FORCE_PROTECT_NONE;
						wlFwSetProtectMode(wlpptr->
								   netDev,
								   HostCmd_ACT_GEN_SET,
								   &mode);
					} else if ((txbps >=
						    protect_tx_rate_thres) &&
						   (rxbps >=
						    protect_rx_rate_thres)) {
						/* protect rts for TCP */
						mode = FORCE_PROTECT_RTS;
						wlFwSetProtectMode(wlpptr->
								   netDev,
								   HostCmd_ACT_GEN_SET,
								   &mode);
					}
				}
			}
		}
#endif /* SOC_W906X */

		TimerRearm(&vmacSta_p->monTimer, MONITER_PERIOD_1SEC);
	}

#ifdef SOC_W906X
	typedef struct _mbssid_ie_db {
		u8 mbssid_index;	//value in mbssid-index
		u8 rsvd[3];
		u16 ietable[256][4];	//lookup table for the mbssid_ie entry        
		u8 iebuf[260];
		struct _mbssid_ie_db *link;	//point to next mbssid with same mbssid-index 
		struct _mbssid_ie_db *next;	//point to next mbssid ie
	} PACK_END mbssid_ie_db_t;

	typedef struct _bcn_ie_db {
		u8 *ie[256];

		struct _bcn_ie_db *next;
	} PACK_END bcn_ie_db_t;

//retrieve mbssie-index from mbssid IE  
	int getMBSSID_index(IEEEtypes_Mbssid_Element_t * pmb) {
		IEEEtypes_NonTransmitted_BSSID_Profile_t *pNonTxPf;

		int idx = (int)(-1);
		int len;
		u8 *subie;

		if (pmb->ElementId != MULTI_BSSID)
			goto exit;

		pNonTxPf =
			(IEEEtypes_NonTransmitted_BSSID_Profile_t *) & pmb->
			NonTxPf;

		if (pNonTxPf->subElementId !=
		    NONTRANSMITTED_BSSID_PROFILE_SUBELM_ID)
			goto exit;

		subie = (u8 *) & pNonTxPf->ntBssidCap;
		len = pNonTxPf->Len;

		while (len > 0) {

			if (subie[0] == MBSSID_INDEX) {	//found 
				return (((IEEEtypes_mbssid_idx_t *) subie)->
					BssidIdx);
			}

			len -= (2 + subie[1]);
			subie += (2 + subie[1]);	//point to next subIE. 
		}

exit:
		return idx;

	}

//1. extract Multiple BSSID IEs from the native beacon.
//2. put a multiple BSSID IE to a mbssid_ie_db_t node
//3. parse the node and do subelement index in table
	u8 extract_mbssid_ies(void *attrib_p, int len, mbssid_ie_db_t ** phead) {
		IEEEtypes_Mbssid_Element_t *pmb;
		mbssid_ie_db_t *entry = NULL;
		int idx;
		u8 num = 0;	//num of mbssid IE with different BSSID-index
		u32 i;
		mbssid_ie_db_t *pnode = NULL;
		mbssid_ie_db_t *pnode_s = NULL;

		//extract each MULTIPLE BSSID IE and put it to a mbssid_ie_db_t.
		do {
			pmb = (IEEEtypes_Mbssid_Element_t *) attrib_p;

			//printk("IE:%u, len:%u\n",pmb->ElementId, len);

			if (pmb->ElementId != MULTI_BSSID)	//step to next ie 
				goto nextie;

			if (pmb->NonTxPf.subElementId != NONTRANSMITTED_BSSID_PROFILE_SUBELM_ID)	//step to next ie 
				goto nextie;

			if ((entry =
			     (mbssid_ie_db_t *)
			     wl_kmalloc(sizeof(mbssid_ie_db_t),
					GFP_ATOMIC)) == NULL) {
				printk("Fail to allocating mbssid_ie_db_t entry\n");
				goto exit;
			}

			memset((void *)entry, 0, sizeof(mbssid_ie_db_t));
			memcpy((u8 *) entry->iebuf, (u8 *) attrib_p,
			       (pmb->Len + 2));

			if ((idx = getMBSSID_index(pmb)) < 0) {
				//printk("invalid mbssid ie\n");
				wl_kfree(entry);
				entry = NULL;
				goto exit;
			}

			entry->mbssid_index = idx;
			//printk("mbssid-idx:%u\n", idx);

			if (!pnode) {
				pnode = entry;
				num++;
			} else {
				if (pnode->mbssid_index == entry->mbssid_index) {	//same mbssid
					mbssid_ie_db_t *temp = pnode;

					while (temp->next)
						temp = temp->next;

					temp->link = entry;	//chain the same mbssid together by 'link'
				} else {
					pnode->next = entry;	//next another mbssid
					pnode = pnode->next;
					num++;
				}
			}

			//chain head
			if (*phead == NULL) {
				(*phead) = entry;
			}

nextie:
			len -= (pmb->Len + 2);
			attrib_p += (pmb->Len + 2);	//step to next IE 
		} while (len > 0);

		//hash all IEs within the non-transmitted profile for facilitating to rebuild legacy bcn frame later.
		pnode = (*phead);
		for (i = 0; i < num; i++) {
			pnode_s = pnode;

			while (pnode) {
				u16 length = (pnode->iebuf[1] + 2);	//total length of mbssid ie in the pnode
				u8 *subie = &pnode->iebuf[5];	//first subie  mbssidie(1)+len(1)+indicator(1)+nontxpf subelement(1)+ len(1)
				u16 len1 = 3;	//
				u32 k;

				if (subie[0] != NONTX_BSSID_CAP) {
					printk("invalid first non-transmitted IE:%u\n", subie[0]);
					pnode = pnode->next;
					break;
				}

				while (length > len1) {

					for (k = 0;
					     k < 4 &&
					     pnode->ietable[subie[0]][k] != 0;
					     k++) ;

					if (k < 4) {
						pnode->ietable[subie[0]][k] = (subie - pnode->iebuf);	//iebuff index of this subie
						//printk("found subie in nontxpf:0x%x, offset:%u\n",subie[0],pnode->ietable[subie[0]][k]);
					}

					len1 += (subie[1] + 2);
					subie += (subie[1] + 2);	//move to next subie
				}

				pnode = pnode->link;
			}

			pnode = pnode_s ? pnode_s->next : NULL;
		}

exit:
		return num;
	}

#define BEACON_MAX_MBSSIE_CNT 32

	UINT8 decomposeMBSSID(struct net_device * dev, struct sk_buff * skb,
			      struct sk_buff_head * skbList) {
		//struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, dev);
		//vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
		IEEEtypes_Frame_t *wlanMsg_p;
		u8 num = 0;
		void *attrib_p = NULL;
		u32 len = skb->len;
		mbssid_ie_db_t *phead = NULL;
		u8 cnt;

		wlanMsg_p = (IEEEtypes_Frame_t *) ((UINT8 *) skb->data - 2);

		if (wlanMsg_p->Hdr.FrmCtl.Subtype != IEEE_MSG_BEACON &&
		    wlanMsg_p->Hdr.FrmCtl.Subtype != IEEE_MSG_PROBE_RSP)
			goto exit;

		wlanMsg_p->Hdr.FrmBodyLen = skb->len;

		if ((attrib_p =
		     syncSrv_ParseAttrib((macmgmtQ_MgmtMsg_t *) wlanMsg_p,
					 EXT_CAP_IE, len)) != NULL) {
			IEEEtypes_Extended_Cap_Element_t *pextie =
				(IEEEtypes_Extended_Cap_Element_t *) attrib_p;

			if (!
			    (pextie->Len > 0 &&
			     pextie->ExtCap.MultipleBSSID == 1)) {
				//printk("ExtCap.MultipleBSSID not enabled\n");
				goto exit;
			}
		} else {
			//printk("No ExtCap IE found\n");
			goto exit;
		}

		//printk("dump native beacon:\n");
		//mwl_hex_dump(skb->data, skb->len);

		if ((attrib_p =
		     syncSrv_ParseAttrib((macmgmtQ_MgmtMsg_t *) wlanMsg_p,
					 MULTI_BSSID, len)) != NULL) {
			//mbssid_ie_db_t  *pentry;
			int len2 =
				(skb->len -
				 (u32) ((u8 *) attrib_p - skb->data));

			//printk("MULTI_BSSID: len2:%u\n", len2);

			//mwl_hex_dump(attrib_p, len2);

			if ((num =
			     extract_mbssid_ies(attrib_p, len2, &phead)) == 0) {
				//printk("extract mbssid IEs fail..\n");
				goto exit;
			}
		}

		cnt = 0;

		//rebuild each beacon frame per bssid
		while (num > cnt) {
			mbssid_ie_db_t *pnode, *pnode_s;
			macmgmtQ_MgmtMsg_t *pmgmtf;
			macmgmtQ_MgmtMsg_t *pmgmtf_src;
			struct sk_buff *skb2 = NULL;
			IEEEtypes_Mbssid_Element_t *pmb;
			u8 mask = 0xff;
			u16 len, len1, i;
			u8 *iesrc, *iedst;
			u8 bssid_A;

			pnode = phead;
			phead = phead->next;
			pnode->next = 0;

			skb2 = skb_copy(skb, GFP_ATOMIC);

			pmgmtf_src =
				(macmgmtQ_MgmtMsg_t *) ((UINT8 *) skb->data -
							2);

			pmgmtf = (macmgmtQ_MgmtMsg_t *) ((UINT8 *) skb2->data -
							 2);
			pmgmtf->Hdr.FrmBodyLen = skb->len;

			len = skb2->len + 2;
			len1 = ((u8 *) & (pmgmtf->Body.Bcn.SsId) -
				(u8 *) pmgmtf);

			//get mbssid structure
			pmb = (IEEEtypes_Mbssid_Element_t *) pnode->iebuf;

			//recover bssid address
			mask = (mask >> (8 - pmb->MaxBssidIndictor));
			bssid_A = pmgmtf->Hdr.SrcAddr[5] & (~mask);
			pmgmtf->Hdr.SrcAddr[5] =
				(pmgmtf->Hdr.SrcAddr[5] +
				 pnode->mbssid_index) & mask;
			pmgmtf->Hdr.BssId[5] =
				(bssid_A | pmgmtf->Hdr.SrcAddr[5]);
			pmgmtf->Hdr.SrcAddr[5] = pmgmtf->Hdr.BssId[5];

			//check each IE entry and revovery to the right values
			iedst = (u8 *) & (pmgmtf->Body.Bcn.SsId);
			iesrc = (u8 *) & (pmgmtf_src->Body.Bcn.SsId);

			//rebuild non-transmitted bssid from primary bssid

			pnode_s = pnode;

			while (len > len1) {
				//printk("processing IE:%u\n", iesrc[0]);

				do {
					if (pnode->ietable[iesrc[0]][0] == 0) {	//no need to update

						if (iesrc[0] != MULTI_BSSID) {
							memcpy(iedst, iesrc, (2 + iesrc[1]));	//copy IE from src to dst
							iedst += (2 + iesrc[1]);
							//printk("Copy IE from org skb:%u:%u\n",iesrc[0], iesrc[1]);
						}
						//else {
						//      printk("Ignore IE:%u\n", iesrc[0]);
						//}

					} else {	//update the ie from mbssie db

						//printk("processing-1 IE:%u\n", iesrc[0]);
						for (i = 0;
						     i < 4 &&
						     pnode->
						     ietable[iesrc[0]][i];
						     i++) {
							//u16  idx = pnode->iebuf[pnode->ietable[iesrc[0]][i]];
							u16 idx = pnode->ietable[iesrc[0]][i];	//get start offset value of this IE in iebuf[]
							u8 *subie =
								&pnode->
								iebuf[idx];

							//copy this ie from mbssid ie 
							memcpy(iedst, subie,
							       subie[1] + 2);
							iedst += (subie[1] + 2);
							//printk("Copy IE from mbssid IE:%u:%u\n",subie[0], subie[1]);
						}

					}

					pnode = pnode->link;

				} while (pnode);

				pnode = pnode_s;

				//move src to next ie
				len1 += (2 + iesrc[1]);
				iesrc += (2 + iesrc[1]);	//step to next ie in iesrc
			}

			cnt++;
			while (pnode_s) {
				pnode_s = pnode->link;
				wl_kfree(pnode);	//free node memory allocated within extract_mbssid_ies
			}
			skb2->len = iedst - skb2->data;
			pmgmtf->Hdr.FrmBodyLen = skb2->len;

			//printk("non-transmitted bcn:\n");
			//mwl_hex_dump((void *)&pmgmtf->Hdr.FrmCtl, skb2->len);

			skb_queue_tail(skbList, skb2);

		}

exit:
		return num;

	}
#endif

	extern void RxBeacon(vmacApInfo_t * vmacSta_p, void *BssData_p,
			     UINT16 len, UINT32 rssi) {

		void *attrib_p = NULL;
		IEEEtypes_ERPInfoElement_t *ErpInfo_p;
#ifdef COEXIST_20_40_SUPPORT
		MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
		MIB_PHY_DSSS_TABLE *PhyDSSSTable = mib->PhyDSSSTable;
		IEEEtypes_DsParamSet_t *dsPSetIE_p;
		static UINT8 Scanbeacon = 0;
		IEEEtypes_HT_Element_t *htSetIE_p;
		UINT8 HTCap = 0, AddHtChannelOffset = 0;
#endif

		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev);

		{
			macmgmtQ_MgmtMsg_t *Beacon_p = NULL;
			Beacon_p = (macmgmtQ_MgmtMsg_t *) BssData_p;
			//printk("Rx Beacon from %s \n", mac_display(Beacon_p->Hdr.BssId));
		}

		if ((attrib_p =
		     syncSrv_ParseAttrib((macmgmtQ_MgmtMsg_t *) BssData_p,
					 EXT_SUPPORTED_RATES, len)) != NULL) {
			if (((IEEEtypes_SuppRatesElement_t *) attrib_p)->Len >
			    0) {
			} else
				BAPCount++;
		} else if ((attrib_p =
			    syncSrv_ParseAttrib((macmgmtQ_MgmtMsg_t *)
						BssData_p, SUPPORTED_RATES,
						len)) != NULL) {
			if (((IEEEtypes_SuppRatesElement_t *) attrib_p)->Len >
			    4) {
			} else
				BAPCount++;
		}
		if ((attrib_p =
		     syncSrv_ParseAttrib((macmgmtQ_MgmtMsg_t *) BssData_p,
					 ERP_INFO, len)) != NULL) {
			ErpInfo_p = (IEEEtypes_ERPInfoElement_t *) attrib_p;
			if (ErpInfo_p->ERPInfo.UseProtection == 1 &&
			    ErpInfo_p->ERPInfo.NonERPPresent == 1) {
				ERPCount++;
				BStnAroundCnt = BSTATION_AGECOUNT;
			}
		}
#ifdef NPROTECTION
		if ((attrib_p =
		     syncSrv_ParseAttrib((macmgmtQ_MgmtMsg_t *) BssData_p, HT,
					 len)) == NULL) {
			wlpptr->wlpd_p->legAPCount = 1;
		}

		if ((attrib_p =
		     syncSrv_ParseAttrib((macmgmtQ_MgmtMsg_t *) BssData_p,
					 ADD_HT, len)) != NULL) {
			if (((IEEEtypes_Add_HT_Element_t *) attrib_p)->OpMode.
			    NonHTStaPresent == 1)
				wlpptr->wlpd_p->legAPCount = 1;
		} else {
			wlpptr->wlpd_p->legAPCount = 1;
		}
#endif

#ifdef COEXIST_20_40_SUPPORT
		/*
		 * Drop during ACS scan
		 * BW is decided in wlUpdateAutoChan()
		 */
		if ((vmacSta_p->preautochannelfinished == 0) &&
		    (*(mib->mib_autochannel) != 0)) {
			return;
		}

		if (vmacSta_p->busyScanning)
			Scanbeacon = 1;

		if (PhyDSSSTable->Chanflag.FreqBand == FREQ_BAND_2DOT4GHZ && (vmacSta_p->busyScanning ||	/* Recv beacon during coex scan */
									      PhyDSSSTable->
									      Chanflag.
									      ChnlWidth
									      ==
									      CH_AUTO_WIDTH
									      ||
									      PhyDSSSTable->
									      Chanflag.
									      ChnlWidth
									      ==
									      CH_40_MHz_WIDTH)
		    /*&& (rssi <= FortyMIntolerantRSSIThres) */ ) {
			macmgmtQ_MgmtMsg_t *mgmt;
			extern int wlFwSet11N_20_40_Switch(struct net_device
							   *netdev, UINT8 mode);

			mgmt = (macmgmtQ_MgmtMsg_t *) BssData_p;
			if ((attrib_p =
			     syncSrv_ParseAttrib((macmgmtQ_MgmtMsg_t *)
						 BssData_p, HT, len)) != NULL) {
				htSetIE_p = (IEEEtypes_HT_Element_t *) attrib_p;

				HTCap = 1;
				if (htSetIE_p->HTCapabilitiesInfo.
				    FortyMIntolerant == 1) {
					Handle20_40_Channel_switch(vmacSta_p,
								   1);
				}

				if (htSetIE_p->HTCapabilitiesInfo.SupChanWidth) {
/** 40MHz channel capable AP found **/
					void *attrib_p2 = NULL;
					IEEEtypes_Add_HT_Element_t
						*AddhtSetIE_p;

					if ((attrib_p2 =
					     syncSrv_ParseAttrib((macmgmtQ_MgmtMsg_t *) BssData_p, ADD_HT, len)) != NULL) {
						HTCap = 1;
						AddhtSetIE_p =
							(IEEEtypes_Add_HT_Element_t
							 *) attrib_p2;

						if (AddhtSetIE_p->AddChan.
						    STAChannelWidth) {
							AddHtChannelOffset =
								AddhtSetIE_p->
								AddChan.
								ExtChanOffset;
						}
					}
				}
			}

			if ((attrib_p =
			     syncSrv_ParseAttrib((macmgmtQ_MgmtMsg_t *)
						 BssData_p, DS_PARAM_SET,
						 len)) != NULL) {
				dsPSetIE_p =
					(IEEEtypes_DsParamSet_t *) attrib_p;

			/** if it is a 11n beacon, check for primary and extension channel ap, if not,
			only check for primary channel **/
				if (dsPSetIE_p->CurrentChan !=
				    PhyDSSSTable->CurrChan) {
				/** check whether channel is in interferance path , if so, do a channel switch **/
					if (Check_40MHz_Affected_range
					    (vmacSta_p, dsPSetIE_p->CurrentChan,
					     0)) {
						Handle20_40_Channel_switch
							(vmacSta_p, 1);
					}
				} else {
					/* AP and Recv Beacon is Same channel */
					if (!HTCap ||
					    AddHtChannelOffset == 0 ||
					    AddHtChannelOffset ==
					    PhyDSSSTable->Chanflag.
					    ExtChnlOffset) {
						/* (20MHz AP) or (40MHz AP. ExtCh is same) */
					} else {
						if (Check_40MHz_Affected_range
						    (vmacSta_p,
						     dsPSetIE_p->CurrentChan,
						     0)) {
							Handle20_40_Channel_switch
								(vmacSta_p, 1);
							//printk(KERN_ERR "%s: Curr %dch, Recv %d ch beacon. Swith to 20MHz\n", __func__, PhyDSSSTable->CurrChan, dsPSetIE_p->CurrentChan);
						}
					}

				}
			}
		}
#endif

	}

/* DisableMacMgmtTimers - disable timers for removing module. */
	extern void Disable_stationAgingTimer(vmacApInfo_t * vmacSta_p);
	extern void Disable_GrpKeyTimer(vmacApInfo_t * vmacSta_p);

	void DisableMacMgmtTimers(vmacApInfo_t * vmacSta_p) {
		Disable_stationAgingTimer(vmacSta_p);
		Disable_MonitorTimerProcess(vmacSta_p);
		Disable_extStaDb_ProcessKeepAliveTimer(vmacSta_p);
		Disable_GrpKeyTimer(vmacSta_p);
#ifdef AUTOCHANNEL
		Disable_ScanTimerProcess(vmacSta_p);
#endif
	}

	void MacMgmtMemCleanup(vmacApInfo_t * vmacSta_p) {
		extStaDb_Cleanup(vmacSta_p);
		mlmeAuthCleanup(vmacSta_p);
		StnIdListCleanup(vmacSta_p);
	}

	typedef struct RateConversion_t {
		UINT16 IEEERate;
		UINT16 MrvlRateBitMap;
	} RateToRateBitMapConversion_t;

	RateToRateBitMapConversion_t IEEEToMrvlRateBitMapConversionTbl[] = {
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

		{2, RateIndex5_1Mbps_BIT},
		{4, RateIndex5_2Mbps_BIT},
		{11, RateIndex5_5Mbps_BIT},
		{22, RateIndex11Mbps_BIT},
		{44, RateIndex22Mbps_BIT},
		{12, RateIndex6Mbps_BIT},
		{18, RateIndex9Mbps_BIT},
		{24, RateIndex12Mbps_BIT},
		{36, RateIndex18Mbps_BIT},
		{48, RateIndex24Mbps_BIT},
		{72, RateIndex36Mbps_BIT},
		{96, RateIndex48Mbps_BIT},
		{108, RateIndex54Mbps_BIT},
		{ENDOFTBL, ENDOFTBL},
	};

	void IEEEToMrvlRateBitMapConversion(UINT8 SupportedIEEERate,
					    UINT32 *
					    pMrvlLegacySupportedRateBitMap) {
		UINT32 i = 0;

		// Remove the highest bit which indicate if it is a basic rate.
		SupportedIEEERate = SupportedIEEERate & 0x7F;

		while (IEEEToMrvlRateBitMapConversionTbl[i].IEEERate !=
		       ENDOFTBL) {
			if ((IEEEToMrvlRateBitMapConversionTbl[i].IEEERate ==
			     SupportedIEEERate)) {
				*pMrvlLegacySupportedRateBitMap =
					*pMrvlLegacySupportedRateBitMap |
					(IEEEToMrvlRateBitMapConversionTbl[i].
					 MrvlRateBitMap);
			}
			i++;
		}
	}

	static UINT32 GetLegacyRateBitMap(vmacApInfo_t * vmacSta_p,
					  IEEEtypes_SuppRatesElement_t *
					  SuppRates,
					  IEEEtypes_ExtSuppRatesElement_t *
					  ExtSuppRates) {
		UINT16 i, j;
		//the maximum size of Rates[] should be RateIE->len + ExtSuppRateIE->len
		//for not overflow Rates[]
		UINT8 Rates[512] = { 0 };
		UINT32 SupportedLegacyIEEERateBitMap = 0;

		/* Get legacy rates */
		for (i = 0; i < SuppRates->Len; i++) {
			Rates[i] = SuppRates->Rates[i];
		}

		if (ExtSuppRates && ExtSuppRates->Len) {
			for (j = 0; j < ExtSuppRates->Len; j++) {
				Rates[i + j] = ExtSuppRates->Rates[j];
			}
		}
#ifdef BRS_SUPPORT
		if (isClientRateMatchAP(vmacSta_p, Rates) == 0) {
			return 0;
		}
#endif
		/* Get legacy rate bit map */
		for (i = 0; i < IEEEtypes_MAX_DATA_RATES_G; i++) {
			IEEEToMrvlRateBitMapConversion(Rates[i],
						       &SupportedLegacyIEEERateBitMap);
		}

		//WLDBG_INFO(DBG_LEVEL_7,"SupportedLegacyIEEERateBitMap 0x%x\n", SupportedLegacyIEEERateBitMap);
		return SupportedLegacyIEEERateBitMap;
	}
#ifdef BRS_SUPPORT
	int isClientRateMatchAP(vmacApInfo_t * vmacSta_p, UINT8 * Rates) {
		UINT32 i, j, findRate;
		UINT32 rateMask;
		MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;

		/* Check that AP BSS Basic Rates need be supported by client all rates */
		rateMask = *(mib->BssBasicRateMask);
		i = 0;
		while (rateMask) {
			if (rateMask & 0x01) {
				j = 0;
				findRate = 0;
				if (mib->StationConfig->OpRateSet[i] != 0) {
					while (Rates[j]) {
						if (mib->StationConfig->
						    OpRateSet[i] ==
						    (Rates[j] & 0x7F)) {
							findRate = 1;
							break;
						}
						j++;
					}
					if (!findRate) {
						//WLDBG_INFO(DBG_LEVEL_7,"AP Basic match fail.\n");
						return 0;
					}
				}
			}
			rateMask >>= 1;
			i++;
		}

		/* Check that client BSS Basic Rates need be supported by AP all rates */
		i = 0;
		while (Rates[i]) {
			if (Rates[i] & 0x80) {
				j = 0;
				findRate = 0;
				rateMask =
					*(mib->BssBasicRateMask) | *(mib->
								     NotBssBasicRateMask);
				while (rateMask) {
					if (rateMask & 0x01) {
						if ((Rates[i] & 0x7F) ==
						    mib->StationConfig->
						    OpRateSet[j]) {
							findRate = 1;
							break;
						}
					}
					rateMask >>= 1;
					j++;
				}
				if (!findRate) {
					//WLDBG_INFO(DBG_LEVEL_7,"Client Basic match fail.\n");
					return 0;
				}
			}
			i++;
		}
		return 1;

	}
#endif

	void ClientStatistics(vmacApInfo_t * vmacSta_p,
			      extStaDb_StaInfo_t * pStaInfo) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev);

		if (pStaInfo->State == ASSOCIATED) {
			vmacSta_p->numClients++;
			if (pStaInfo->ClientMode == NONLY_MODE) {
				vmacSta_p->nClients++;
				wlpptr->wlpd_p->nClients++;
				if (pStaInfo->HtElem.HTCapabilitiesInfo.
				    SupChanWidth)
					vmacSta_p->n40MClients++;
				else {
					vmacSta_p->n20MClients++;
					wlpptr->wlpd_p->n20MClients++;
				}
				if (!pStaInfo->PeerHTCapabilitiesInfo.
				    GreenField) {
					vmacSta_p->NonGFSta++;
					wlpptr->wlpd_p->NonGFSta++;
				}
			} else {
				vmacSta_p->legClients++;
				wlpptr->wlpd_p->legClients++;
				if (pStaInfo->ClientMode == BONLY_MODE)
					vmacSta_p->bClients++;
				else
					vmacSta_p->gaClients++;
			}
		}
	}

	void CleanCounterClient(vmacApInfo_t * vmacSta_p) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev);
		vmacSta_p->numClients = 0;
		vmacSta_p->nClients = 0;
		vmacSta_p->legClients = 0;
		vmacSta_p->n40MClients = 0;
		vmacSta_p->n20MClients = 0;
		vmacSta_p->gaClients = 0;
		vmacSta_p->bClients = 0;
		vmacSta_p->NonGFSta = 0;
		wlpptr->wlpd_p->NonGFSta = 0;
		wlpptr->wlpd_p->legClients = 0;
		wlpptr->wlpd_p->n20MClients = 0;
		wlpptr->wlpd_p->nClients = 0;
	}
#ifdef COEXIST_20_40_SUPPORT
	void Coexist_TimeoutHdlr(void *pData) {
		extern int wlFwSet11N_20_40_Switch(struct net_device *netdev,
						   UINT8 mode);
		extern BOOLEAN
			macMgmtMlme_SendNotifyChannelWidthManagementAction
			(vmacApInfo_t * vmacSta_p, UINT8 mode);

		vmacApInfo_t *vmacSta_p = (vmacApInfo_t *) pData;
		MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
		MIB_PHY_DSSS_TABLE *PhyDSSSTable = mib->PhyDSSSTable;
		UINT8 BcnAddHtAddChannel = 0;

		if (*(vmacSta_p->ShadowMib802dot11->mib_HT40MIntoler)) {
			if (*(vmacSta_p->Mib802dot11->mib_ApMode) ==
			    AP_MODE_N_ONLY ||
			    *(vmacSta_p->Mib802dot11->mib_ApMode) ==
			    AP_MODE_BandN ||
			    *(vmacSta_p->Mib802dot11->mib_ApMode) ==
			    AP_MODE_GandN ||
			    *(vmacSta_p->Mib802dot11->mib_ApMode) ==
			    AP_MODE_2_4GHZ_11AC_MIXED ||
			    *(vmacSta_p->Mib802dot11->mib_ApMode) ==
			    AP_MODE_BandGandN) {
				int mode = 1;
			/** what to do if auto fktang **/
				if (PhyDSSSTable->Chanflag.ExtChnlOffset ==
				    EXT_CH_ABOVE_CTRL_CH)
					BcnAddHtAddChannel = 5;
				else if (PhyDSSSTable->Chanflag.ExtChnlOffset ==
					 EXT_CH_BELOW_CTRL_CH)
					BcnAddHtAddChannel = 7;

				macMgmtMlme_SendNotifyChannelWidthManagementAction
					(vmacSta_p, 1);
			/** 5 is for upper and 7 is for lower **/
				wlFwSet11N_20_40_Switch(vmacSta_p->dev,
							BcnAddHtAddChannel);
				*(mib->USER_ChnlWidth) = mode;
			}
		}   /** switch back to 40MHz here **/
		TimerDisarm(&vmacSta_p->CoexistTimer);
	}

	void Coexist_RearmTimer(vmacApInfo_t * vmacSta_p) {
		MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

		TimerRearm(&vmacSta_p->CoexistTimer,
			   *(mib->mib_Channel_Width_Trigger_Scan_Interval) *
			   (*(mib->mib_Channel_Transition_Delay_Factor)) * 10);
	}

	void StartCoexistTimer(vmacApInfo_t * vmacSta_p) {
		MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
		TimerRemove(&vmacSta_p->CoexistTimer);
		TimerInit(&vmacSta_p->CoexistTimer);

		/* Coexist  in seconds, base timer is 25s. */
		TimerFireIn(&vmacSta_p->CoexistTimer, 1, Coexist_TimeoutHdlr,
			    (unsigned char *)vmacSta_p,
			    *(mib->mib_Channel_Width_Trigger_Scan_Interval) *
			    (*(mib->mib_Channel_Transition_Delay_Factor)) * 10);

	}

	void Disable_StartCoexisTimer(vmacApInfo_t * vmacSta_p) {
		TimerRemove(&vmacSta_p->CoexistTimer);
	}

	int Check_40MHz_Affected_range(vmacApInfo_t * vmacSta_p, int curchannel,
				       int extchan) {
		// 40Mhz affected channel range = [ (fp+fs)/2-25MHz, (fp+fs)/2+25MHz]
		int lowchannel, highchannel, fp, fs = 0;
		MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
		MIB_PHY_DSSS_TABLE *PhyDSSSTable = mib->PhyDSSSTable;
		int channel[] =
			{ 2412, 2417, 2422, 2427, 2432, 2437, 2442, 2447, 2452,
			2457, 2462,
			2467, 2472, 2484
		};

		fp = channel[PhyDSSSTable->CurrChan - 1];

		if (PhyDSSSTable->Chanflag.ExtChnlOffset ==
		    EXT_CH_ABOVE_CTRL_CH)
			fs = channel[PhyDSSSTable->CurrChan + 4 - 1];
		else if ((PhyDSSSTable->Chanflag.ExtChnlOffset ==
			  EXT_CH_BELOW_CTRL_CH) && (PhyDSSSTable->CurrChan > 4))
			fs = channel[PhyDSSSTable->CurrChan - 4 - 1];

		lowchannel = (fp + fs) / 2 - 25;
		highchannel = (fp + fs) / 2 + 25;

		if (channel[curchannel - 1] >= lowchannel &&
		    channel[curchannel - 1] <= highchannel) {
			return 1;
		} else {
			return 0;
		}

	}
	void Handle20_40_Channel_switch(vmacApInfo_t * vmacSta_p,
					UINT8 Scanning) {
		MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
		UINT8 BcnAddHtAddChannel = 0;
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev);

		if (*(vmacSta_p->ShadowMib802dot11->mib_HT40MIntoler)
		    /*wlpptr->wlpd_p->BcnAddHtAddChannel!= BcnAddHtAddChannel */
		    ) {
			extern int wlFwSet11N_20_40_Switch(struct net_device
							   *netdev, UINT8 mode);
			extern BOOLEAN
				macMgmtMlme_SendNotifyChannelWidthManagementAction
				(vmacApInfo_t * vmacSta_p, UINT8 mode);

			if (((*(mib->USER_ChnlWidth)) & 0x0f) == 0x00) {
/** we are already at 20MHz mode **/
				StartCoexistTimer(vmacSta_p);
						       /** restart timer, sta already reported intolerant **/

				return;
			}

			printk("%s: HT2040 BW Switch: %u -> %u\n",
			       vmacSta_p->dev->name,
			       wlpptr->wlpd_p->BcnAddHtAddChannel,
			       BcnAddHtAddChannel);
			wlpptr->wlpd_p->BcnAddHtAddChannel = BcnAddHtAddChannel;

			wlFwSet11N_20_40_Switch(vmacSta_p->dev,
						BcnAddHtAddChannel);
		/** Start timer to switch back to 40MHz **/
			if (vmacSta_p->n40MClients)
						/** start timer only if there is 11n 40M sta **/
				StartCoexistTimer(vmacSta_p);
			if (Scanning)
				*(mib->USER_ChnlWidth) = 0x10;
						       /** bit 4 use to indicate bw change during scanning **/
			else
				*(mib->USER_ChnlWidth) = 0x0;

			macMgmtMlme_SendNotifyChannelWidthManagementAction
				(vmacSta_p, 0);
		}
	}

#endif

	void HandleNProtectionMode(vmacApInfo_t * vmacSta_p) {
		MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
		UINT8 BcnAddHtOpMode = 0;
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev);
		UINT8 TxGf = 0;

		if (vmacSta_p->OpMode >= WL_OP_MODE_STA) {
			//the following will not apply to station mode operation, simply return
			return;
		}

		if (*(mib->mib_ApMode) & 0x4) {
			/*      Draft 11, page 148, Line 65
			   The HT Protection field is set to non-HT mixed mode otherwise.
			 */
			if (wlpptr->wlpd_p->legClients) {
				BcnAddHtOpMode = 0x03;
			} else if (wlpptr->wlpd_p->nClients) {
				/*  Draft 11, page 148, Line 49-54
				   The HT Protection field may be set to non-member protection mode only if:
				   -A non-HT STA is detected in either the primary or the secondary channel or 
				   in both the primary and secondary channels, that is not known by the transmitting STA 
				   to be a member of this BSS, and
				   -All STAs that are known by the transmitting STA to be a member of this BSS are HT STAs */
				if (wlpptr->wlpd_p->legAPCount) {
					BcnAddHtOpMode = 0x01;
				}

				/* Draft 11, page 148, Line 57-63
				   The HT Protection field may be set to 20 MHz protection mode only if:
				   -All STAs detected in the primary and all STAs detected in the secondary channel are HT STAs and    
				   all STAs that are members of this BSS are HT STAs, and
				   -This BSS is a 20/40 MHz BSS, and
				   -There is at least one 20 MHz HT STA associated with this BSS
				 */
				else if (wlpptr->wlpd_p->n20MClients &&
					 ((*(mib->USER_ChnlWidth) & 0x0f) ==
					  1)) {
					BcnAddHtOpMode = 0x02;
				} else {
					/* The HT Protection field may be set to no protection mode only if the following are true:
					   ?All STAs detected (by any means) in the primary or the secondary channel are HT STAs, and
					   ?All STAs that are known by the transmitting STA to be a member of this BSS are either
					   ?20/40 MHz HT STAs in a 20/40 MHz BSS, or
					   ?20 MHz HT STAs in a 20 MHz BSS */

					BcnAddHtOpMode = 0x00;
				}
			} else {
				/*The HT Protection field may be set to nonmember protection mode only if the following are true:
				   ?A non-HT STA is detected (by any means) in either the primary or the secondary channel or in both
				   the primary and secondary channels, that is not known by the transmitting STA to be a member of
				   this BSS, and
				   ?All STAs that are known by the transmitting STA to be a member of this BSS are HT STAs */
				if (wlpptr->wlpd_p->legAPCount) {
					BcnAddHtOpMode = 0x01;
				} else
					BcnAddHtOpMode = 0x00;
			}

			if (*(mib->mib_HtGreenField)) {
				if ((!wlpptr->wlpd_p->NonGFSta) &&
				    ((!BcnAddHtOpMode) ||
				     (BcnAddHtOpMode == 2))) {
					TxGf = 1;
					BcnAddHtOpMode &= ~0x0004;	/* bit2 is non-GF present */
				} else
					BcnAddHtOpMode |= 0x0004;

				if (wlpptr->wlpd_p->TxGf != TxGf)
					wlFwSetHTGF(vmacSta_p->dev, TxGf);

				wlpptr->wlpd_p->TxGf = TxGf;
			} else {
				BcnAddHtOpMode |= 0x0004;
				wlFwSetHTGF(vmacSta_p->dev, TxGf);	/*Bug 46196: Added to handle disabled GF fw update */
			}
		}

		if (wlpptr->wlpd_p->BcnAddHtOpMode != BcnAddHtOpMode) {
			wlpptr->wlpd_p->BcnAddHtOpMode = BcnAddHtOpMode;
			wlFwSetNProtOpMode(vmacSta_p->dev, BcnAddHtOpMode);
		}
	}

	void checkLegDevOutBSS(vmacApInfo_t * vmacSta_p) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev);
		UINT8 HWIndex = vmacSta_p->VMacEntry.phyHwMacIndx;
		struct net_device *dev;
		struct wlprivate *wlpptr1;
		int i = 0;

		if ((legacyAPCount[HWIndex] != wlpptr->wlpd_p->legAPCount) || (counterHtProt[HWIndex]++ % 10 == 0)) {	/* 30s check */
			legacyAPCount[HWIndex] = wlpptr->wlpd_p->legAPCount;
			while (i <= bss_num) {
				if (wlpptr->vdev[i]) {
					dev = wlpptr->vdev[i];
					wlpptr1 =
						NETDEV_PRIV_P(struct wlprivate,
							      dev);
					if (wlpptr1->vmacSta_p != NULL &&
					    wlpptr1->vmacSta_p->VMacEntry.
					    modeOfService == VMAC_MODE_AP)
						if (dev->flags & IFF_RUNNING)
							HandleNProtectionMode
								(wlpptr1->
								 vmacSta_p);
				}
				i++;
			}
		}
		wlpptr->wlpd_p->legAPCount = 0;
	}

	BOOLEAN macMgmtMlme_SendMimoPsHtManagementAction(vmacApInfo_t *
							 vmacSta_p,
							 IEEEtypes_MacAddr_t *
							 Addr, UINT8 mode) {
		macmgmtQ_MgmtMsg2_t *MgmtMsg_p;
		struct sk_buff *txSkb_p;
		IEEEtypes_SM_PwrCtl_t *p;

		UINT16 FrameLen = sizeof(IEEEtypes_Category_t) +
			sizeof(IEEEtypes_ActionFieldType_t) +
			sizeof(IEEEtypes_SM_PwrCtl_t);

		if ((txSkb_p =
		     mlmeApiPrepMgtMsg2(IEEE_MSG_QOS_ACTION, Addr,
					(IEEEtypes_MacAddr_t *) & vmacSta_p->
					macStaAddr, FrameLen)) == NULL)
			return FALSE;

		MgmtMsg_p = (macmgmtQ_MgmtMsg2_t *) ((UINT8 *) txSkb_p->data);

		MgmtMsg_p->Body.Act.Category = HT_CATEGORY;
		MgmtMsg_p->Body.Act.Action = ACTION_SMPS;

		p = &MgmtMsg_p->Body.Act.Field.SmPwrCtl;

		p->Mode = mode;
		if (mode == 0x03) {
			p->Enable = 0;
			p->Mode = 0;
		} else
			p->Enable = 1;

		if (txMgmtMsg(vmacSta_p->dev, txSkb_p) != OS_SUCCESS) {
			wl_free_skb(txSkb_p);
			return FALSE;
		}

		return TRUE;
	}
#ifdef COEXIST_20_40_SUPPORT
	BOOLEAN macMgmtMlme_SendNotifyChannelWidthManagementAction(vmacApInfo_t
								   * vmacSta_p,
								   UINT8 mode) {
		macmgmtQ_MgmtMsg2_t *MgmtMsg_p;
		struct sk_buff *txSkb_p;
		IEEEtypes_BWCtl_t *p;
		IEEEtypes_MacAddr_t bcastMacAddr =
			{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

		UINT16 FrameLen = sizeof(IEEEtypes_Category_t) +
			sizeof(IEEEtypes_ActionFieldType_t) +
			sizeof(IEEEtypes_BWCtl_t);

		if ((txSkb_p =
		     mlmeApiPrepMgtMsg2(IEEE_MSG_QOS_ACTION, &bcastMacAddr,
					(IEEEtypes_MacAddr_t *) & vmacSta_p->
					macStaAddr, FrameLen)) == NULL)
			return FALSE;

		MgmtMsg_p = (macmgmtQ_MgmtMsg2_t *) ((UINT8 *) txSkb_p->data);

		MgmtMsg_p->Body.Act.Category = HT_CATEGORY;
		MgmtMsg_p->Body.Act.Action = ACTION_NOTIFYCHANNELWIDTH;

		p = &MgmtMsg_p->Body.Act.Field.BWCtl;

		p->BandWidth = mode;

		if (txMgmtMsg(vmacSta_p->dev, txSkb_p) != OS_SUCCESS) {
			wl_free_skb(txSkb_p);
			return FALSE;
		}

		return TRUE;
	}
#endif
#ifdef INTOLERANT40
	BOOLEAN macMgmtMlme_SendInfoExchHtManagementAction(struct net_device *
							   dev,
							   IEEEtypes_MacAddr_t *
							   Addr) {
		macmgmtQ_MgmtMsg2_t *MgmtMsg_p;
		struct sk_buff *txSkb_p;
		IEEEtypes_InfoExch_t *p;

		UINT16 FrameLen = sizeof(IEEEtypes_Category_t) +
			sizeof(IEEEtypes_ActionFieldType_t) +
			sizeof(IEEEtypes_InfoExch_t);

		if ((txSkb_p =
		     mlmeApiPrepMgtMsg2(IEEE_MSG_QOS_ACTION, Addr,
					(IEEEtypes_MacAddr_t *) & dev->dev_addr,
					FrameLen)) == NULL)
			return FALSE;

		MgmtMsg_p = (macmgmtQ_MgmtMsg2_t *) ((UINT8 *) txSkb_p->data);

		/* Send event to user space */
		WLSNDEVT(dev, IWEVEXPIRED, Addr, NULL);
#ifdef CFG80211
#ifdef CFG80211_COMPATIABLE
		mwl_cfg80211_disassoc_event(dev, Addr);
#else
		mwl_send_vendor_disassoc_event(dev, Addr);
#endif /* CFG80211_COMPATIABLE */
#endif /* CFG80211 */

		MgmtMsg_p->Body.Act.Category = HT_CATEGORY;;
		MgmtMsg_p->Body.Act.Action = ACTION_INFOEXCH;

		p = &MgmtMsg_p->Body.Act.Field.InfoExch;

		p->InfoReq = 1;

		if (txMgmtMsg(dev, txSkb_p) != OS_SUCCESS) {
			wl_free_skb(txSkb_p);
			return FALSE;
		}

		return TRUE;
	}

	BOOLEAN macMgmtMlme_SendBeaconReqMeasureReqAction(struct net_device *
							  dev,
							  IEEEtypes_MacAddr_t *
							  Addr) {
		extern UINT8 getRegulatoryClass(vmacApInfo_t * vmacSta_p);
		macmgmtQ_MgmtMsg2_t *MgmtMsg_p;
		struct sk_buff *txSkb_p;
		struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
		vmacApInfo_t *vmacSta_p = (vmacApInfo_t *) wlpptr->vmacSta_p;
		MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
		IEEEtypes_MeasurementRequestEl_t *p;

		UINT16 FrameLen = sizeof(IEEEtypes_Category_t) +
			sizeof(IEEEtypes_ActionFieldType_t) +
			sizeof(UINT8) +
			sizeof(UINT16) +
			sizeof(IEEEtypes_MeasurementRequestEl_t) -
			(34 - strlen(&(mib->StationConfig->DesiredSsId[0])));

		if ((txSkb_p =
		     mlmeApiPrepMgtMsg2(IEEE_MSG_QOS_ACTION, Addr,
					(IEEEtypes_MacAddr_t *) & dev->dev_addr,
					FrameLen)) == NULL)
			return FALSE;

		MgmtMsg_p = (macmgmtQ_MgmtMsg2_t *) ((UINT8 *) txSkb_p->data);

		MgmtMsg_p->Body.Act.Category = RADIO_MEASURE_CATEGOTY;
		MgmtMsg_p->Body.Act.Action = MEASUREMENT_REQUEST;
		MgmtMsg_p->Body.Act.Field.Field5.DialogToken = 0;
		MgmtMsg_p->Body.Act.Field.Field5.NumRepetition = 0;

		p = &MgmtMsg_p->Body.Act.Field.Field5.Data.MeasurementRequestEl;

		p->ElementId = MEASUREMENT_REQ;
		p->Token = 0;
		p->Mode.Enable = 1;
		p->Mode.Request = 1;
		p->Mode.Report = 0;
		p->Type = TYPE_REQ_BCN;

		p->Request.RegClass = getRegulatoryClass(vmacSta_p);
		memcpy(p->Request.BSSID, &vmacSta_p->macStaAddr,
		       sizeof(IEEEtypes_MacAddr_t));
		p->Request.ChanNum = 255;
		p->Request.RandInterval = 0;
		p->Request.Mode = 0;
		p->Request.Duration = 10;
		p->Request.ReportCondi = 254;
		p->Request.Threshold_offset = 1;
		memcpy(p->Request.SSID, &(mib->StationConfig->DesiredSsId[0]),
		       strlen(&(mib->StationConfig->DesiredSsId[0])));

		p->Len = 3 + sizeof(IEEEtypes_MeasurementReqBcn_t) - (34 -
								      strlen(&
									     (mib->
									      StationConfig->
									      DesiredSsId
									      [0])));

		if (txMgmtMsg(dev, txSkb_p) != OS_SUCCESS) {
			wl_free_skb(txSkb_p);
			return FALSE;
		}
		//printk("MEASUREMENT_REQ %d\n", MEASUREMENT_REQ);
		return TRUE;
	}

	BOOLEAN macMgmtMlme_SendExtChanSwitchAnnounceAction(struct net_device *
							    dev,
							    IEEEtypes_MacAddr_t
							    * Addr) {
		extern UINT8 getRegulatoryClass(vmacApInfo_t * vmacSta_p);
		macmgmtQ_MgmtMsg2_t *MgmtMsg_p;
		struct sk_buff *txSkb_p;
		struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
		vmacApInfo_t *vmacSta_p = (vmacApInfo_t *) wlpptr->vmacSta_p;
		MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
		IEEEtypes_ExtendChanSwitchAnnounceEl_t *p;

		UINT16 FrameLen = sizeof(IEEEtypes_Category_t) +
			sizeof(IEEEtypes_ActionFieldType_t) +
			sizeof(IEEEtypes_ExtendChanSwitchAnnounceEl_t);

		if ((txSkb_p =
		     mlmeApiPrepMgtMsg2(IEEE_MSG_QOS_ACTION, Addr,
					(IEEEtypes_MacAddr_t *) & dev->dev_addr,
					FrameLen)) == NULL)

			return FALSE;

		MgmtMsg_p = (macmgmtQ_MgmtMsg2_t *) ((UINT8 *) txSkb_p->data);

		MgmtMsg_p->Body.Act.Category = SPECTRUM_MANAGE_CATEGOTY;
		MgmtMsg_p->Body.Act.Action = ACTION_EXTCHANSWTANNO;

		p = &MgmtMsg_p->Body.Act.Field.ExtendChanSwitchAnnounceEl;

		p->ElementId = 60;	// Temp
		p->ChanSwitchMode = 1;
		p->RegClass = getRegulatoryClass(vmacSta_p);
		p->ChanNum = mib->PhyDSSSTable->CurrChan;
		p->ChanSwitchCount = 0;

		p->Len = 4;

		if (txMgmtMsg(dev, txSkb_p) != OS_SUCCESS) {
			wl_free_skb(txSkb_p);
			return FALSE;
		}
		//printk("ACTION_EXTCHANSWTANNO %d\n", ACTION_EXTCHANSWTANNO);
		return TRUE;
	}
#endif //#ifdef INTOLERANT40

#ifdef SOC_W906X
	BOOLEAN UpdateSecondChannelInMIB(vmacApInfo_t * vmacSta_p,
					 UINT32 channel) {
		extern BOOLEAN force_5G_channel;
		MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
		MIB_PHY_DSSS_TABLE *PhyDSSSTable = mib->PhyDSSSTable;

		if (domainChannelValid
		    (channel,
		     force_5G_channel ? FREQ_BAND_5GHZ : (channel <=
							  14 ?
							  FREQ_BAND_2DOT4GHZ :
							  FREQ_BAND_5GHZ))) {
			PhyDSSSTable->SecChan = channel;
			PhyDSSSTable->Chanflag.isDfsChan2 = 1;

		} else {
			WLDBG_INFO(DBG_LEVEL_15, "invalid channel %d\n",
				   channel);
			return FALSE;
		}
		return TRUE;
	}
#endif

/* This function updates the shadow MIB wth the given channel*/
	BOOLEAN UpdateCurrentChannelInMIB(vmacApInfo_t * vmacSta_p,
					  UINT32 channel) {
#ifndef SOC_W906X
		extern BOOLEAN force_5G_channel;
#endif
		MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
		MIB_PHY_DSSS_TABLE *PhyDSSSTable = mib->PhyDSSSTable;
		UINT8 *mib_extSubCh_p = mib->mib_extSubCh;

#ifdef SOC_W906X
		if (domainChannelValid
		    (channel,
		     channel <= 14 ? FREQ_BAND_2DOT4GHZ : FREQ_BAND_5GHZ))
#else
		if (domainChannelValid
		    (channel,
		     force_5G_channel ? FREQ_BAND_5GHZ : (channel <=
							  14 ?
							  FREQ_BAND_2DOT4GHZ :
							  FREQ_BAND_5GHZ)))
#endif
		{
			PhyDSSSTable->CurrChan = channel;

			/* Currentlly, 40M is not supported for channel 14 */
			if (PhyDSSSTable->CurrChan == 14) {
				if ((PhyDSSSTable->Chanflag.ChnlWidth ==
				     CH_AUTO_WIDTH) ||
				    (PhyDSSSTable->Chanflag.ChnlWidth ==
				     CH_40_MHz_WIDTH))
					PhyDSSSTable->Chanflag.ChnlWidth =
						CH_20_MHz_WIDTH;
			}
			//PhyDSSSTable->Chanflag.ChnlWidth=CH_40_MHz_WIDTH;
			PhyDSSSTable->Chanflag.ExtChnlOffset =
				EXT_CH_ABOVE_CTRL_CH;
			if (((PhyDSSSTable->Chanflag.ChnlWidth ==
			      CH_40_MHz_WIDTH) ||
			     (PhyDSSSTable->Chanflag.ChnlWidth ==
			      CH_80_MHz_WIDTH) ||
			     (PhyDSSSTable->Chanflag.ChnlWidth ==
			      CH_AUTO_WIDTH))) {
				switch (PhyDSSSTable->CurrChan) {
				case 1:
				case 2:
				case 3:
				case 4:
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_ABOVE_CTRL_CH;
					break;
				case 5:
					/* Now AutoBW use 5-1 instead of 5-9 for wifi cert convenience */
					/*if(*mib_extSubCh_p==0)
					   PhyDSSSTable->Chanflag.ExtChnlOffset=EXT_CH_ABOVE_CTRL_CH;
					   else if(*mib_extSubCh_p==1)
					   PhyDSSSTable->Chanflag.ExtChnlOffset=EXT_CH_BELOW_CTRL_CH;
					   else if(*mib_extSubCh_p==2)
					   PhyDSSSTable->Chanflag.ExtChnlOffset=EXT_CH_ABOVE_CTRL_CH;
					   break; */
				case 6:
				case 7:
				case 8:
				case 9:
				case 10:
					if (*mib_extSubCh_p == 0)
						PhyDSSSTable->Chanflag.
							ExtChnlOffset =
							EXT_CH_BELOW_CTRL_CH;
					else if (*mib_extSubCh_p == 1)
						PhyDSSSTable->Chanflag.
							ExtChnlOffset =
							EXT_CH_BELOW_CTRL_CH;
					else if (*mib_extSubCh_p == 2)
						PhyDSSSTable->Chanflag.
							ExtChnlOffset =
							EXT_CH_ABOVE_CTRL_CH;
					break;
				case 11:
				case 12:
				case 13:
				case 14:
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_BELOW_CTRL_CH;
					break;
					/* for 5G */
				case 36:
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_ABOVE_CTRL_CH;
					break;
				case 40:
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_BELOW_CTRL_CH;
					break;
				case 44:
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_ABOVE_CTRL_CH;
					break;
				case 48:
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_BELOW_CTRL_CH;
					break;
				case 52:
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_ABOVE_CTRL_CH;
					break;
				case 56:
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_BELOW_CTRL_CH;
					break;
				case 60:
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_ABOVE_CTRL_CH;
					break;
				case 64:
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_BELOW_CTRL_CH;
					break;

				case 68:
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_ABOVE_CTRL_CH;
					break;
				case 72:
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_BELOW_CTRL_CH;
					break;
				case 76:
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_ABOVE_CTRL_CH;
					break;
				case 80:
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_BELOW_CTRL_CH;
					break;
				case 84:
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_ABOVE_CTRL_CH;
					break;
				case 88:
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_BELOW_CTRL_CH;
					break;
				case 92:
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_ABOVE_CTRL_CH;
					break;
				case 96:
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_BELOW_CTRL_CH;
					break;

				case 100:
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_ABOVE_CTRL_CH;
					break;
				case 104:
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_BELOW_CTRL_CH;
					break;
				case 108:
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_ABOVE_CTRL_CH;
					break;
				case 112:
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_BELOW_CTRL_CH;
					break;
				case 116:
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_ABOVE_CTRL_CH;
					break;
				case 120:
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_BELOW_CTRL_CH;
					break;
				case 124:
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_ABOVE_CTRL_CH;
					break;
				case 128:
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_BELOW_CTRL_CH;
					break;
				case 132:
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_ABOVE_CTRL_CH;
					break;
				case 136:
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_BELOW_CTRL_CH;
					break;
				case 140:
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_ABOVE_CTRL_CH;
					break;
				case 144:
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_BELOW_CTRL_CH;
					break;
				case 149:
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_ABOVE_CTRL_CH;
					break;
				case 153:
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_BELOW_CTRL_CH;
					break;
				case 157:
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_ABOVE_CTRL_CH;
					break;
				case 161:
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_BELOW_CTRL_CH;
					break;

				case 165:
					if (*(mib->mib_regionCode) ==
					    DOMAIN_CODE_ALL) {
						PhyDSSSTable->Chanflag.
							ExtChnlOffset =
							EXT_CH_ABOVE_CTRL_CH;
					} else {
						PhyDSSSTable->Chanflag.
							ExtChnlOffset =
							EXT_CH_BELOW_CTRL_CH;
					}
					break;
				case 169:
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_BELOW_CTRL_CH;
					break;
				case 173:
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_ABOVE_CTRL_CH;
					break;
				case 177:
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_BELOW_CTRL_CH;
					break;
				case 181:
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						NO_EXT_CHANNEL;
					break;

				case 184:
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_ABOVE_CTRL_CH;
					break;
				case 188:
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_BELOW_CTRL_CH;
					break;
				case 192:
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_ABOVE_CTRL_CH;
					break;
				case 196:
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_BELOW_CTRL_CH;
					break;
				}
			}
#ifndef SOC_W906X
			if (force_5G_channel) {
				PhyDSSSTable->Chanflag.FreqBand =
					FREQ_BAND_5GHZ;
			} else {
#endif
				if (PhyDSSSTable->CurrChan <= 14)
					PhyDSSSTable->Chanflag.FreqBand =
						FREQ_BAND_2DOT4GHZ;
				else
					PhyDSSSTable->Chanflag.FreqBand =
						FREQ_BAND_5GHZ;
#ifndef SOC_W906X
			}
#endif
		} else {
			WLDBG_INFO(DBG_LEVEL_0, "invalid channel %d\n",
				   channel);
			return FALSE;
		}
		return TRUE;
	}

	void ApplyCSAChannel(struct net_device *netdev, UINT32 channel) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		vmacApInfo_t *syscfg = (vmacApInfo_t *) wlpptr->vmacSta_p;
		MIB_802DOT11 *mib = syscfg->ShadowMib802dot11;
#ifdef MRVL_DFS
		smeQ_MgmtMsg_t *toSmeMsg = NULL;
#endif
		MIB_PHY_DSSS_TABLE *PhyDSSSTable = mib->PhyDSSSTable;

		{
#ifdef MRVL_DFS
			if ((toSmeMsg =
			     (smeQ_MgmtMsg_t *)
			     wl_kmalloc(sizeof(smeQ_MgmtMsg_t),
					GFP_ATOMIC)) == NULL) {
				WLDBG_INFO(DBG_LEVEL_15,
					   "wlChannelSet: failed to alloc msg buffer\n");
				return;
			}

			memset(toSmeMsg, 0, sizeof(smeQ_MgmtMsg_t));

			toSmeMsg->vmacSta_p = wlpptr->vmacSta_p;

			toSmeMsg->MsgType = SME_NOTIFY_CHANNELSWITCH_CFRM;

			toSmeMsg->Msg.ChanSwitchCfrm.result = 1;
			toSmeMsg->Msg.ChanSwitchCfrm.chInfo.channel =
				PhyDSSSTable->CurrChan;
			toSmeMsg->Msg.ChanSwitchCfrm.chInfo.channel2 =
				PhyDSSSTable->SecChan;

			memcpy(&toSmeMsg->Msg.ChanSwitchCfrm.chInfo.chanflag,
			       &PhyDSSSTable->Chanflag, sizeof(CHNL_FLAGS));
#ifdef RADAR_SCANNER_SUPPORT
			toSmeMsg->Msg.ChanSwitchCfrm.chInfo.no_cac =
				PhyDSSSTable->no_cac;
			PhyDSSSTable->no_cac = 0;
#endif

			smeQ_MgmtWriteNoBlock(toSmeMsg);
			wl_kfree((UINT8 *) toSmeMsg);

#endif //MRVL_DFS
		}

	}

#ifdef MRVL_DFS
	void macMgmtMlme_StartRadarDetection(struct net_device *dev,
					     UINT8 detectionMode) {
		struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);

		if (detectionMode == DFS_QUIET_MODE) {
			wlpptr->wlpd_p->bStopBcnProbeResp = TRUE;
		}

		wlFwSetRadarDetection(dev,
				      detectionMode == DFS_NORMAL_MODE ? 3 : 1);
	}

	void macMgmtMlme_StopRadarDetection(struct net_device *dev,
					    UINT8 detectionMode) {
		wlFwSetRadarDetection(dev,
				      detectionMode == DFS_NORMAL_MODE ? 0 : 2);
	}

#ifdef CONCURRENT_DFS_SUPPORT
	void macMgmtMlme_StartAuxRadarDetection(struct net_device *dev,
						UINT8 detectionMode) {
		wlFwSetRadarDetection(dev, detectionMode);
	}

	void macMgmtMlme_StopAuxRadarDetection(struct net_device *dev,
					       UINT8 detectionMode) {
		wlFwSetRadarDetection(dev, detectionMode);
	}
#endif /* CONCURRENT_DFS_SUPPORT */

	void macMgmtMlme_SendChannelSwitchCmd(struct net_device *dev,
					      Dfs_ChanSwitchReq_t *
					      pChannelSwitchCmd) {
		int i;
		struct wlprivate *wlpptr = NULL;

		if (!dev || !pChannelSwitchCmd)
			return;

		wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);

		/* Send Channel Switch Command to all the AP virtual interfaces */
		for (i = 0; i <= bss_num; i++) {
			if (wlpptr->vdev[i] &&
			    wlpptr->vdev[i]->flags & IFF_RUNNING) {
				struct net_device *vdev = wlpptr->vdev[i];
				struct wlprivate *vpriv =
					NETDEV_PRIV_P(struct wlprivate, vdev);
				SendChannelSwitchCmd(vpriv->vmacSta_p,
						     pChannelSwitchCmd);
			}
		}

	}

	void macMgmtMlme_GetActiveVAPs(struct net_device *dev, UINT8 * vaplist,
				       UINT8 * vapcount_p) {
		UINT8 j = 0;
		UINT8 count = 0;
		struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);

		while (j <= bss_num && count < bss_num) {
			if (wlpptr->vdev[j] &&
			    (wlpptr->vdev[j]->flags & IFF_RUNNING)) {
				vaplist[count++] = j;
			}
			j++;
		}
		*vapcount_p = count;
	}

	void macMgmtMlme_Reset(struct net_device *dev, UINT8 * vaplist,
			       UINT8 * vapcount_p) {
		if (!dev || !vaplist || !vapcount_p)
			return;
		macMgmtMlme_GetActiveVAPs(dev, vaplist, vapcount_p);
		wlResetTask(dev);
	}

	void macMgmtMlme_MBSS_Reset(struct net_device *netdev, UINT8 * vaplist,
				    UINT8 vapcount) {
		int i = 0;
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);

		vapcount = min(vapcount, (UINT8) MAX_VMAC_AP);

		for (i = 0; i < vapcount; i++) {
			wlreset_mbss(wlpptr->vdev[vaplist[i]]);
		}
	}

	void macMgmtMlme_SwitchChannel(struct net_device *dev, UINT8 channel,
				       UINT8 channel2,
				       CHNL_FLAGS * chanFlag_p) {
		struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
		vmacApInfo_t *syscfg = (vmacApInfo_t *) wlpptr->vmacSta_p;
		MIB_802DOT11 *mib = syscfg->Mib802dot11;
		MIB_PHY_DSSS_TABLE *PhyDSSSTable = mib->PhyDSSSTable;

#ifdef CONCURRENT_DFS_SUPPORT
		if (wlpptr->wlpd_p->ext_scnr_en) {
			extern DFS_STATUS dfs_set_op_ch(struct net_device *dev,
							UINT16 channel);
			dfs_set_op_ch(dev, channel);
			return;
		}
#endif /* CONCURRENT_DFS_SUPPORT */

		if (UpdateCurrentChannelInMIB(syscfg, channel)) {
			mib_Update();
#ifdef SOC_W906X
			// TODO: check how to switch channel for 80+80MHZ
			if (wlchannelSet
			    (dev, channel, channel2, PhyDSSSTable->Chanflag, 0))
#else
			if (wlchannelSet
			    (dev, channel, PhyDSSSTable->Chanflag, 0))
#endif
			{
				WLDBG_EXIT_INFO(DBG_LEVEL_15,
						"setting channel failed");
				return;
			}

		}
		if (chanFlag_p) {
			memcpy(chanFlag_p, &PhyDSSSTable->Chanflag,
			       sizeof(CHNL_FLAGS));
		}
	}
	BOOLEAN macMgmtMlme_DfsEnabled(struct net_device *dev) {
		struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
		vmacApInfo_t *syscfg = (vmacApInfo_t *) wlpptr->vmacSta_p;
		MIB_802DOT11 *mib = syscfg->Mib802dot11;

		if (mib->SpectrumMagament->spectrumManagement)
			return TRUE;
		return FALSE;
	}

	void macMgmtMlme_StopDataTraffic(struct net_device *dev) {
		struct wlprivate *wlpptr = NULL;
		DfsAp *pdfsApMain = NULL;

		if (!dev)
			return;
		wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
		pdfsApMain = wlpptr->wlpd_p->pdfsApMain;

		dfsTrace(dev, 0xe, 0x1, NULL,
			 (0x10000000 | ((dev->flags & IFF_RUNNING) << 4) |
			  (pdfsApMain ? 1 : 0)));

		if (dev->flags & IFF_RUNNING) {
			netif_stop_queue(dev);
			netif_carrier_off(dev);
			dev->flags &= ~IFF_RUNNING;
		}
		// Data traffic will be dropped in the data path
		if (pdfsApMain) {
			pdfsApMain->dropData = 1;
			//Disbale AMPDU streams if any
			disableAmpduTxAll(wlpptr->vmacSta_p);
		}

		return;

	}

	void macMgmtMlme_RestartDataTraffic(struct net_device *dev) {

		struct wlprivate *wlpptr = NULL;
		DfsAp *pdfsApMain = NULL;
		if (!dev)
			return;

		wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
		pdfsApMain = wlpptr->wlpd_p->pdfsApMain;

		dfsTrace(dev, 0xe, 0x2, NULL,
			 (0x10000000 | ((dev->flags & IFF_RUNNING) << 4) |
			  (pdfsApMain ? 1 : 0)));

		/* infrom SFW to stop data traffic */
		((SMAC_CTRL_BLK_st *) wlpptr->ioBase0)->config.txAcStop = 0;
		printk("[DFS] Restart SFW AC queue Tx ...\n");

		if ((dev->flags & IFF_RUNNING) == 0) {
			netif_carrier_on(dev);
			netif_wake_queue(dev);
			dev->flags |= IFF_RUNNING;
		}

		if (pdfsApMain) {
			//Allow transmit traffic in the data path
			pdfsApMain->dropData = 0;
		}
	}

	UINT8 macMgmtMlme_Get40MHzExtChannelOffset(UINT8 channel) {
		UINT8 extChnlOffset = EXT_CH_ABOVE_CTRL_CH;
		switch (channel) {
		case 1:
		case 2:
		case 3:
		case 4:
			extChnlOffset = EXT_CH_ABOVE_CTRL_CH;
			break;
		case 5:
		case 6:
		case 7:
		case 8:
		case 9:
		case 10:
		case 11:
		case 12:
		case 13:
		case 14:
			extChnlOffset = EXT_CH_BELOW_CTRL_CH;
			break;
		case 36:
			extChnlOffset = EXT_CH_ABOVE_CTRL_CH;
			break;
		case 40:
			extChnlOffset = EXT_CH_BELOW_CTRL_CH;
			break;
		case 44:
			extChnlOffset = EXT_CH_ABOVE_CTRL_CH;
			break;
		case 48:
			extChnlOffset = EXT_CH_BELOW_CTRL_CH;
			break;
		case 52:
			extChnlOffset = EXT_CH_ABOVE_CTRL_CH;
			break;
		case 56:
			extChnlOffset = EXT_CH_BELOW_CTRL_CH;
			break;
		case 60:
			extChnlOffset = EXT_CH_ABOVE_CTRL_CH;
			break;
		case 64:
			extChnlOffset = EXT_CH_BELOW_CTRL_CH;
			break;

		case 68:
			extChnlOffset = EXT_CH_ABOVE_CTRL_CH;
			break;
		case 72:
			extChnlOffset = EXT_CH_BELOW_CTRL_CH;
			break;
		case 76:
			extChnlOffset = EXT_CH_ABOVE_CTRL_CH;
			break;
		case 80:
			extChnlOffset = EXT_CH_BELOW_CTRL_CH;
			break;
		case 84:
			extChnlOffset = EXT_CH_ABOVE_CTRL_CH;
			break;
		case 88:
			extChnlOffset = EXT_CH_BELOW_CTRL_CH;
			break;
		case 92:
			extChnlOffset = EXT_CH_ABOVE_CTRL_CH;
			break;
		case 96:
			extChnlOffset = EXT_CH_BELOW_CTRL_CH;
			break;

		case 100:
			extChnlOffset = EXT_CH_ABOVE_CTRL_CH;
			break;
		case 104:
			extChnlOffset = EXT_CH_BELOW_CTRL_CH;
			break;
		case 108:
			extChnlOffset = EXT_CH_ABOVE_CTRL_CH;
			break;
		case 112:
			extChnlOffset = EXT_CH_BELOW_CTRL_CH;
			break;
		case 116:
			extChnlOffset = EXT_CH_ABOVE_CTRL_CH;
			break;
		case 120:
			extChnlOffset = EXT_CH_BELOW_CTRL_CH;
			break;
		case 124:
			extChnlOffset = EXT_CH_ABOVE_CTRL_CH;
			break;
		case 128:
			extChnlOffset = EXT_CH_BELOW_CTRL_CH;
			break;
		case 132:
			extChnlOffset = EXT_CH_ABOVE_CTRL_CH;
			break;
		case 136:
			extChnlOffset = EXT_CH_BELOW_CTRL_CH;
			break;
		case 140:
			extChnlOffset = EXT_CH_ABOVE_CTRL_CH;
			break;
		case 144:
			extChnlOffset = EXT_CH_BELOW_CTRL_CH;
			break;
		case 149:
			extChnlOffset = EXT_CH_ABOVE_CTRL_CH;
			break;
		case 153:
			extChnlOffset = EXT_CH_BELOW_CTRL_CH;
			break;
		case 157:
			extChnlOffset = EXT_CH_ABOVE_CTRL_CH;
			break;
		case 161:
			extChnlOffset = EXT_CH_BELOW_CTRL_CH;
			break;
		case 165:
			extChnlOffset = EXT_CH_ABOVE_CTRL_CH;
			break;
		case 169:
			extChnlOffset = EXT_CH_BELOW_CTRL_CH;
			break;
		case 173:
			extChnlOffset = EXT_CH_ABOVE_CTRL_CH;
			break;
		case 177:
			extChnlOffset = EXT_CH_BELOW_CTRL_CH;
			break;
		case 181:
			extChnlOffset = NO_EXT_CHANNEL;
			break;

		case 184:
			extChnlOffset = EXT_CH_ABOVE_CTRL_CH;
			break;
		case 188:
			extChnlOffset = EXT_CH_BELOW_CTRL_CH;
			break;
		case 192:
			extChnlOffset = EXT_CH_ABOVE_CTRL_CH;
			break;
		case 196:
			extChnlOffset = EXT_CH_BELOW_CTRL_CH;
			break;
		default:
			extChnlOffset = EXT_CH_ABOVE_CTRL_CH;
		}
		return extChnlOffset;
	}

#endif //MRVL_DFS

#ifdef INTOLERANT40
	static void HT40MIntolerantHandler(vmacApInfo_t * vmacSta_p, UINT8 soon) {
		extern void extStaDb_SendBeaconReqMeasureReqAction(vmacApInfo_t
								   * vmac_p);
		MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
		MIB_802DOT11 *mibShadow = vmacSta_p->ShadowMib802dot11;
		UINT8 Addr[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

		//printk("ChnlWidth %d, USER_ChnlWidth %d\n", mib->PhyDSSSTable.Chanflag.ChnlWidth,mib->USER_ChnlWidth);

		if (!*(mib->mib_HT40MIntoler))
			return;

		if (!soon)
			extStaDb_SendBeaconReqMeasureReqAction(vmacSta_p);

		if (((mib->PhyDSSSTable->Chanflag.ChnlWidth == CH_40_MHz_WIDTH)
		     || (mib->PhyDSSSTable->Chanflag.ChnlWidth ==
			 CH_80_MHz_WIDTH) ||
		     (mib->PhyDSSSTable->Chanflag.ChnlWidth == CH_AUTO_WIDTH))
		    && ((*(mib->USER_ChnlWidth) == CH_40_MHz_WIDTH) ||
			(*(mib->USER_ChnlWidth) == CH_80_MHz_WIDTH) ||
			(*(mib->USER_ChnlWidth) == CH_AUTO_WIDTH))) {
			/* Switch from 40 to 20M */
			if (soon || sHt30minStaIntolerant) {
				macMgmtMlme_SendExtChanSwitchAnnounceAction
					(vmacSta_p->dev,
					 (IEEEtypes_MacAddr_t *) & Addr[0]);
				*(mibShadow->mib_FortyMIntolerant) = 1;
				mibShadow->PhyDSSSTable->Chanflag.ChnlWidth =
					CH_20_MHz_WIDTH;
				/* Start 30 min timer */
				sMonitorcnt30min = 1;

				wlResetTask(vmacSta_p->dev);
				//printk("to 20\n");
			}
		} else if ((mib->PhyDSSSTable->Chanflag.ChnlWidth ==
			    CH_20_MHz_WIDTH) &&
			   ((*(mib->USER_ChnlWidth) == CH_40_MHz_WIDTH) ||
			    (*(mib->USER_ChnlWidth) == CH_80_MHz_WIDTH) ||
			    (*(mib->USER_ChnlWidth) == CH_AUTO_WIDTH))) {
			/* Switch from 20 to 40M */
			if (!sHt30minStaIntolerant && !vmacSta_p->legClients &&
			    !vmacSta_p->n20MClients) {
				*(mibShadow->mib_FortyMIntolerant) = 0;
				mibShadow->PhyDSSSTable->Chanflag.ChnlWidth =
					CH_40_MHz_WIDTH;
				/* Start 30 min timeer */
				sMonitorcnt30min = 1;
				wlResetTask(vmacSta_p->dev);
				//printk("to 40\n");
			}
		} else if (*(mib->USER_ChnlWidth) == CH_20_MHz_WIDTH) {
			/* Close 30 min timeer */
			sMonitorcnt30min = 0;
		}
		//sHt30minStaIntolerant = 0;
	}

	void RecHTIntolerant(vmacApInfo_t * vmacSta_p, UINT8 enable) {
		MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;

		//printk("Rec:HT %d\n", enable);

		if (enable) {
			sHt30minStaIntolerant++;

			if (((mib->PhyDSSSTable->Chanflag.ChnlWidth ==
			      CH_40_MHz_WIDTH) ||
			     (mib->PhyDSSSTable->Chanflag.ChnlWidth ==
			      CH_80_MHz_WIDTH) ||
			     (mib->PhyDSSSTable->Chanflag.ChnlWidth ==
			      CH_AUTO_WIDTH)) &&
			    ((*(mib->USER_ChnlWidth) == CH_40_MHz_WIDTH) ||
			     (*(mib->USER_ChnlWidth) == CH_80_MHz_WIDTH) ||
			     (*(mib->USER_ChnlWidth) == CH_AUTO_WIDTH))) {
				sMonitorcnt30min = (INTOLERANTCHEKCOUNTER - 3);
			}
		} else {
			sMonitorcnt30min = 1;
			sHt30minStaIntolerant = 0;
		}
	}
#endif //#ifdef INTOLERANT40

	void FixedRateCtl(extStaDb_StaInfo_t * pStaInfo, PeerInfo_t * PeerInfo,
			  MIB_802DOT11 * mib) {
		if ((pStaInfo == NULL) || (*(mib->mib_enableFixedRateTx) == 0))
			return;
#if 0				/* wlan-v5-sc2 merges: TODO LATER - FIRMWARE DEPENDENT */
		switch (*(mib->mib_ApMode)) {
		case AP_MODE_B_ONLY:
			PeerInfo->StaMode = AP_MODE_B_ONLY;
			PeerInfo->IeeeRate = (UINT8) * (mib->mib_txDataRate);
			break;

		case AP_MODE_G_ONLY:
			PeerInfo->StaMode = AP_MODE_G_ONLY;
			PeerInfo->IeeeRate = (UINT8) * (mib->mib_txDataRateG);
			break;

		case AP_MODE_A_ONLY:
			PeerInfo->StaMode = AP_MODE_A_ONLY;
			PeerInfo->IeeeRate = (UINT8) * (mib->mib_txDataRateA);
			break;

		case AP_MODE_MIXED:
			if (pStaInfo->ClientMode == BONLY_MODE) {
				PeerInfo->StaMode = AP_MODE_B_ONLY;
				PeerInfo->IeeeRate =
					(UINT8) * (mib->mib_txDataRate);
			} else {
				PeerInfo->StaMode = AP_MODE_G_ONLY;
				PeerInfo->IeeeRate =
					(UINT8) * (mib->mib_txDataRateG);
			}
			break;

		case AP_MODE_N_ONLY:
			if (*(mib->mib_FixedRateTxType) == 1)
				PeerInfo->StaMode = AP_MODE_N_ONLY;
			else
				PeerInfo->StaMode = AP_MODE_G_ONLY;

			PeerInfo->IeeeRate = (UINT8) * (mib->mib_txDataRateN);
			break;

		case AP_MODE_BandN:
			if (pStaInfo->ClientMode == NONLY_MODE) {
				if (*(mib->mib_FixedRateTxType) == 1)
					PeerInfo->StaMode = AP_MODE_N_ONLY;
				else
					PeerInfo->StaMode = AP_MODE_B_ONLY;

				PeerInfo->IeeeRate =
					(UINT8) * (mib->mib_txDataRateN);
			} else {
				PeerInfo->StaMode = AP_MODE_B_ONLY;
				PeerInfo->IeeeRate =
					(UINT8) * (mib->mib_txDataRate);
			}
			break;

		case AP_MODE_GandN:
			if (pStaInfo->ClientMode == NONLY_MODE) {
				if (*(mib->mib_FixedRateTxType) == 1)
					PeerInfo->StaMode = AP_MODE_N_ONLY;
				else
					PeerInfo->StaMode = AP_MODE_G_ONLY;

				PeerInfo->IeeeRate =
					(UINT8) * (mib->mib_txDataRateN);
			} else {
				PeerInfo->StaMode = AP_MODE_G_ONLY;
				PeerInfo->IeeeRate =
					(UINT8) * (mib->mib_txDataRateG);
			}
			break;

		case AP_MODE_BandGandN:
			if (pStaInfo->ClientMode == NONLY_MODE) {
				if (*(mib->mib_FixedRateTxType) == 1)
					PeerInfo->StaMode = AP_MODE_N_ONLY;
				else
					PeerInfo->StaMode = AP_MODE_B_ONLY;

				PeerInfo->IeeeRate =
					(UINT8) * (mib->mib_txDataRateN);
			} else if (pStaInfo->ClientMode == BONLY_MODE) {
				PeerInfo->StaMode = AP_MODE_B_ONLY;
				PeerInfo->IeeeRate =
					(UINT8) * (mib->mib_txDataRate);
			} else {
				PeerInfo->StaMode = AP_MODE_G_ONLY;
				PeerInfo->IeeeRate =
					(UINT8) * (mib->mib_txDataRateG);
			}
			break;

		case AP_MODE_AandN:
			if (pStaInfo->ClientMode == NONLY_MODE) {
				if (*(mib->mib_FixedRateTxType) == 1)
					PeerInfo->StaMode = AP_MODE_N_ONLY;
				else
					PeerInfo->StaMode = AP_MODE_A_ONLY;

				PeerInfo->IeeeRate =
					(UINT8) * (mib->mib_txDataRateN);
			} else {
				PeerInfo->StaMode = AP_MODE_A_ONLY;
				PeerInfo->IeeeRate =
					(UINT8) * (mib->mib_txDataRateA);
			}
			break;

		default:
			if (pStaInfo->ClientMode == BONLY_MODE) {
				PeerInfo->StaMode = AP_MODE_B_ONLY;
				PeerInfo->IeeeRate =
					(UINT8) * (mib->mib_txDataRate);
			} else {
				PeerInfo->StaMode = AP_MODE_G_ONLY;
				PeerInfo->IeeeRate =
					(UINT8) * (mib->mib_txDataRateG);
			}
			break;
		}
#endif
	}

	UINT8 macMgmtMlme_Get80MHzPrimaryChannelOffset(UINT8 channel) {
		UINT8 act_primary = ACT_PRIMARY_CHAN_0;
		switch (channel) {
		case 36:
			act_primary = ACT_PRIMARY_CHAN_0;
			break;
		case 40:
			act_primary = ACT_PRIMARY_CHAN_1;
			break;
		case 44:
			act_primary = ACT_PRIMARY_CHAN_2;
			break;
		case 48:
			act_primary = ACT_PRIMARY_CHAN_3;
			break;
		case 52:
			act_primary = ACT_PRIMARY_CHAN_0;
			break;
		case 56:
			act_primary = ACT_PRIMARY_CHAN_1;
			break;
		case 60:
			act_primary = ACT_PRIMARY_CHAN_2;
			break;
		case 64:
			act_primary = ACT_PRIMARY_CHAN_3;
			break;

		case 68:
			act_primary = ACT_PRIMARY_CHAN_0;
			break;
		case 72:
			act_primary = ACT_PRIMARY_CHAN_1;
			break;
		case 76:
			act_primary = ACT_PRIMARY_CHAN_2;
			break;
		case 80:
			act_primary = ACT_PRIMARY_CHAN_3;
			break;

		case 84:
			act_primary = ACT_PRIMARY_CHAN_0;
			break;
		case 88:
			act_primary = ACT_PRIMARY_CHAN_1;
			break;
		case 92:
			act_primary = ACT_PRIMARY_CHAN_2;
			break;
		case 96:
			act_primary = ACT_PRIMARY_CHAN_3;
			break;

		case 100:
			act_primary = ACT_PRIMARY_CHAN_0;
			break;
		case 104:
			act_primary = ACT_PRIMARY_CHAN_1;
			break;
		case 108:
			act_primary = ACT_PRIMARY_CHAN_2;
			break;
		case 112:
			act_primary = ACT_PRIMARY_CHAN_3;
			break;

		case 116:
			act_primary = ACT_PRIMARY_CHAN_0;
			break;
		case 120:
			act_primary = ACT_PRIMARY_CHAN_1;
			break;
		case 124:
			act_primary = ACT_PRIMARY_CHAN_2;
			break;
		case 128:
			act_primary = ACT_PRIMARY_CHAN_3;
			break;

		case 132:
			act_primary = ACT_PRIMARY_CHAN_0;
			break;
		case 136:
			act_primary = ACT_PRIMARY_CHAN_1;
			break;
		case 140:
			act_primary = ACT_PRIMARY_CHAN_2;
			break;
		case 144:
			act_primary = ACT_PRIMARY_CHAN_3;
			break;

		case 149:
			act_primary = ACT_PRIMARY_CHAN_0;
			break;
		case 153:
			act_primary = ACT_PRIMARY_CHAN_1;
			break;
		case 157:
			act_primary = ACT_PRIMARY_CHAN_2;
			break;
		case 161:
			act_primary = ACT_PRIMARY_CHAN_3;
			break;

		case 165:
			act_primary = ACT_PRIMARY_CHAN_0;
			break;
		case 169:
			act_primary = ACT_PRIMARY_CHAN_1;
			break;
		case 173:
			act_primary = ACT_PRIMARY_CHAN_2;
			break;
		case 177:
			act_primary = ACT_PRIMARY_CHAN_3;
			break;
		}

		return act_primary;
	}

	UINT8 macMgmtMlme_Get160MHzPrimaryChannelOffset(UINT8 channel) {
		UINT8 act_primary = ACT_PRIMARY_CHAN_0;
		switch (channel) {
			/* Center frequency channel 50 */
		case 36:
			act_primary = ACT_PRIMARY_CHAN_0;
			break;
		case 40:
			act_primary = ACT_PRIMARY_CHAN_1;
			break;
		case 44:
			act_primary = ACT_PRIMARY_CHAN_2;
			break;
		case 48:
			act_primary = ACT_PRIMARY_CHAN_3;
			break;
		case 52:
			act_primary = ACT_PRIMARY_CHAN_4;
			break;
		case 56:
			act_primary = ACT_PRIMARY_CHAN_5;
			break;
		case 60:
			act_primary = ACT_PRIMARY_CHAN_6;
			break;
		case 64:
			act_primary = ACT_PRIMARY_CHAN_7;
			break;

			/* Center frequency channel 82 */
		case 68:
			act_primary = ACT_PRIMARY_CHAN_0;
			break;
		case 72:
			act_primary = ACT_PRIMARY_CHAN_1;
			break;
		case 76:
			act_primary = ACT_PRIMARY_CHAN_2;
			break;
		case 80:
			act_primary = ACT_PRIMARY_CHAN_3;
			break;
		case 84:
			act_primary = ACT_PRIMARY_CHAN_4;
			break;
		case 88:
			act_primary = ACT_PRIMARY_CHAN_5;
			break;
		case 92:
			act_primary = ACT_PRIMARY_CHAN_6;
			break;
		case 96:
			act_primary = ACT_PRIMARY_CHAN_7;
			break;

			/* Center frequency channel 114 */
		case 100:
			act_primary = ACT_PRIMARY_CHAN_0;
			break;
		case 104:
			act_primary = ACT_PRIMARY_CHAN_1;
			break;
		case 108:
			act_primary = ACT_PRIMARY_CHAN_2;
			break;
		case 112:
			act_primary = ACT_PRIMARY_CHAN_3;
			break;
		case 116:
			act_primary = ACT_PRIMARY_CHAN_4;
			break;
		case 120:
			act_primary = ACT_PRIMARY_CHAN_5;
			break;
		case 124:
			act_primary = ACT_PRIMARY_CHAN_6;
			break;
		case 128:
			act_primary = ACT_PRIMARY_CHAN_7;
			break;
			/* Center frequency channel 163 */
		case 149:
			act_primary = ACT_PRIMARY_CHAN_0;
			break;
		case 153:
			act_primary = ACT_PRIMARY_CHAN_1;
			break;
		case 157:
			act_primary = ACT_PRIMARY_CHAN_2;
			break;
		case 161:
			act_primary = ACT_PRIMARY_CHAN_3;
			break;
		case 165:
			act_primary = ACT_PRIMARY_CHAN_4;
			break;
		case 169:
			act_primary = ACT_PRIMARY_CHAN_5;
			break;
		case 173:
			act_primary = ACT_PRIMARY_CHAN_6;
			break;
		case 177:
			act_primary = ACT_PRIMARY_CHAN_7;
			break;

		}

		return act_primary;
	}

/*Function to check if station is in MUSetList*/
	int MUchecksta_SetList(vmacApInfo_t * vmac_p,
			       extStaDb_StaInfo_t * pStaInfo) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, vmac_p->dev);
		muset_t *tempnode;
		int i;

		tempnode = (muset_t *) wlpptr->wlpd_p->MUSetList.tail;	//start with first item added into list, new node is added to head

		while (tempnode != NULL) {
#ifdef SOC_W906X
			for (i = 0; i < 4; i++) {
#else
			for (i = 0; i < 3; i++) {
#endif
				if (tempnode->StaInfo[i] != NULL) {
					if (memcmp
					    (tempnode->StaInfo[i]->Addr,
					     pStaInfo->Addr, 6) == 0)
						return 1;
				}
			}
			tempnode = tempnode->prv;
		}
		return 0;
	}

/*Function to check if station is in MUStaList*/
	int MUchecksta_StaList(vmacApInfo_t * vmac_p,
			       extStaDb_StaInfo_t * pStaInfo) {
		MUCapStaNode_t *tempnode = NULL;
		u8 index;

		index = is_he_capable_sta(pStaInfo) * 4 +
			pStaInfo->vht_RxChannelWidth;
		tempnode = (MUCapStaNode_t *) vmac_p->MUStaList[index].tail;	//start with first item added into list, new node is added to head

		while (tempnode != NULL) {
			if (tempnode->StaInfo_p != NULL) {
				if (memcmp
				    (tempnode->StaInfo_p->Addr, pStaInfo->Addr,
				     6) == 0)
					return 1;
			}

			tempnode = tempnode->prv;
		}
		return 0;
	}

/*Function to check whether a MU set index is already used. If the index is used, return 1 else return 0*/
	int MUcheck_index(muset_t * headnode, int index) {
		while (headnode != NULL) {
			if (headnode->index == index)
				return 1;
			headnode = headnode->nxt;
		}
		return 0;
	}

/*Function to insert a MU set node into a MUSetList*/
#ifdef SOC_W906X
	int MUinsert_node(vmacApInfo_t * vmac_p, extStaDb_StaInfo_t * MUUsr[],
			  int index)
#else
	int MUinsert_node(vmacApInfo_t * vmac_p, extStaDb_StaInfo_t * pStaInfo0,
			  extStaDb_StaInfo_t * pStaInfo1,
			  extStaDb_StaInfo_t * pStaInfo2, int index)
#endif
	{
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, vmac_p->dev);
		muset_t *tempnode;
#ifndef SOC_W906X
		extStaDb_StaInfo_t *MUUsr[3];
#endif
		UINT8 i;

		tempnode = (muset_t *) wl_kmalloc(sizeof(muset_t), GFP_ATOMIC);

		if (tempnode == NULL)
			return 0;

		memset(tempnode, 0, sizeof(muset_t));
#ifndef SOC_W906X
		MUUsr[0] = pStaInfo0;
		MUUsr[1] = pStaInfo1;
		MUUsr[2] = pStaInfo2;
#endif

		tempnode->index = index;
		tempnode->dev_name = vmac_p->dev->name;

		for (i = 0; i < MU_MAX_USERS; i++) {
			if (MUUsr[i] != NULL) {
				tempnode->cnt++;
				tempnode->StaInfo[i] = MUUsr[i];
				tempnode->antcnt += MUUsr[i]->vht_peer_RxNss;
				MUUsr[i]->MUset = tempnode;
			}
		}

		wlpptr->wlpd_p->MUSetList.total_sta += tempnode->cnt;

		ListPutItem((List *) & wlpptr->wlpd_p->MUSetList,
			    (ListItem *) tempnode);

		return 1;

	}

/*Function to create MU Set with 3 station pointers as input. It will find availble MU set index to use and 
* get a memory as node to insert in MUSetList
*
* IMPORTANT: Make sure caller to this function has locked MUStaListLock and MUSetflags
*
*/
#ifdef SOC_W906X
	UINT8 MUCreateMUSet(vmacApInfo_t * vmac_p,
			    extStaDb_StaInfo_t * pStaInfo[])
#else
	UINT8 MUCreateMUSet(vmacApInfo_t * vmac_p,
			    extStaDb_StaInfo_t * pStaInfo0,
			    extStaDb_StaInfo_t * pStaInfo1,
			    extStaDb_StaInfo_t * pStaInfo2)
#endif
	{
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, vmac_p->dev);
		UINT16 stnid[MU_MAX_USERS];
		UINT8 i;
		UINT8 myGid = 0;
		unsigned long dbflags;
		vmacApInfo_t *vmacSta_master_p;
#ifndef SOC_W906X
		extStaDb_StaInfo_t *pStaInfo[3];
#else
		unsigned long MUSetflags;
#endif
		muset_t *muset_node = NULL;

#ifndef SOC_W906X
		BUG_ON(!spin_is_locked(&vmac_p->MUStaListLock.l));
		BUG_ON(!spin_is_locked(&wlpptr->wlpd_p->MUSetListLock.l));
#endif
		if (vmac_p->master)
			vmacSta_master_p = vmac_p->master;
		else
			vmacSta_master_p = vmac_p;

#ifdef SOC_W906X
		SPIN_LOCK_IRQSAVE(&wlpptr->wlpd_p->MUSetListLock, MUSetflags);
#endif
		/*Get available MU set index */
#ifdef SOC_W906X
		for (i = 0; i < 63; i++) {
			if (!MUcheck_index
			    ((muset_t *) wlpptr->wlpd_p->MUSetList.head, i))
				break;

		}

		//why ???  myGid is the group ID? but 0 & 63 represent SU.
#else
		for (i = 0; i < 62; i++) {
			if (!MUcheck_index
			    ((muset_t *) wlpptr->wlpd_p->MUSetList.head, i))
				break;

		}

		if (i >= 62) {
			return 0;
		}
#endif /* SOC_W906X */

		myGid = i + 1;

#ifndef SOC_W906X
		pStaInfo[0] = pStaInfo0;
		pStaInfo[1] = pStaInfo1;
		pStaInfo[2] = pStaInfo2;
#endif

		SPIN_LOCK_IRQSAVE(&vmacSta_master_p->StaCtl->dbLock, dbflags);

		/*Create node and put into MUSetList */
#ifdef SOC_W906X
		if (MUinsert_node(vmac_p, pStaInfo, i) == 0)
#else
		if (MUinsert_node(vmac_p, pStaInfo0, pStaInfo1, pStaInfo2, i) ==
		    0)
#endif
		{
			printk("NO memory availale for MUinsert_node\n");
			SPIN_UNLOCK_IRQRESTORE(&vmacSta_master_p->StaCtl->
					       dbLock, dbflags);
#ifdef SOC_W906X
			SPIN_UNLOCK_IRQRESTORE(&wlpptr->wlpd_p->MUSetListLock,
					       MUSetflags);
#endif
			return 0;
		}

		SPIN_UNLOCK_IRQRESTORE(&vmacSta_master_p->StaCtl->dbLock,
				       dbflags);
#ifdef SOC_W906X
		SPIN_UNLOCK_IRQRESTORE(&wlpptr->wlpd_p->MUSetListLock,
				       MUSetflags);
#endif

	/** index start with 0, GID = index+1 **/
	/** check available GID **/
		if (myGid != 0) {
			u32 cmd_option = 1;	/* 1 as default for VHT MU group */
			for (i = 0; i < MU_MAX_USERS; i++) {
				if (pStaInfo[i] != NULL) {
					if (!is_he_capable_sta(pStaInfo[i]))
						SendGroupIDMgmtframe(vmac_p,
								     pStaInfo
								     [i]->Addr,
								     myGid, i);
					else
						cmd_option = 2;	/* 2 for HE MU group */

					stnid[i] = pStaInfo[i]->StnId;
				} else
					stnid[i] = 0xffff;	//dummy
			}

#ifdef SOC_W906X
			if (wlFwSetMUSet
			    (vmac_p->dev, cmd_option, myGid, myGid - 1, stnid))
#else
			if (wlFwSetMUSet
			    (vmac_p->dev, cmd_option, myGid, myGid - 1,
			     stnid[0], stnid[1], stnid[2]))
#endif
			{
#ifdef SOC_W906X
				printk("Setting %s MU Set GID=%d Index=%d Stnid=", (cmd_option == 2) ? "HE" : "VHT", myGid, myGid - 1);
				for (i = 0;
				     (i < MU_MAX_USERS) && (stnid[i] != 0xffff);
				     i++)
					printk("%d ", stnid[i]);
				printk("\n");
#else
				printk("FW Set MU Set GID=%d Index=%d Stnid=%d %d %d\n", myGid, myGid - 1, stnid[0], stnid[1], stnid[2]);
#endif

				for (i = 0; i < MU_MAX_USERS; i++) {
					if (pStaInfo[i] != NULL) {
						pStaInfo[i]->mu_sta = 1;
						pStaInfo[i]->mu_index =
							myGid - 1;
					}
				}

#if defined(MRVL_MUG_ENABLE)
				mug_fill_active_musets(vmac_p->dev);
#endif
				return 1;
			}
			/*If fw cmd to create MU Set fail, remove MU set node created earlier in this function */
			else {
				printk("FAIL in fw cmd to create MU set...\n");
				for (i = 0; i < MU_MAX_USERS; i++) {
					if ((pStaInfo[i] != NULL) &&
					    (pStaInfo[i]->MUset != NULL)) {
						muset_node = pStaInfo[i]->MUset;
						break;
					}
				}
#ifdef SOC_W906X
				MUDel_MUSet(vmac_p, muset_node,
					    MUSet_BLOCK | MUSet_NO_STA_BLOCK);
#else
				MUDel_MUSet(vmac_p, muset_node, 0);
#endif /* SOC_W906X */
			}
			return 0;

		} else
			return 0;
	}

/*
* There are 2 MU lists:- 
* MUSetList: Linked list of all created MU sets. Each node points to extStaDb_StaInfo_t that is inside this MU set and vice versa
* MUStaList: Linked list of all MU capable sta. Each node points to extStaDb_StaInfo_t and vice versa
* 
* Everytime a MU capable sta assoc, it is added to MUStaList to enable faster selection of MU station when creating MU set automatically.
* extStaDb_StaInfo_t has pointers to both MUSetList and MUStaList
* 
*   [MUSetList node]                                          [MUStaList node]
*       - sta_p <-----> extStaDb_StaInfo_t <-----> -sta_p
*/

/*Function to link extStaDb_StaInfo_t and MUStaList.
* A new node is obtained from FreeMUStaList and added to MUStaList.
* Then link between extStaDb_StaInfo_t and this node.
*/
	BOOLEAN MUAddStaToMUStaList(vmacApInfo_t * vmac_p,
				    extStaDb_StaInfo_t * StaInfo_p) {
		MUCapStaNode_t *item_p = NULL;
		ListItem *tmp;
		vmacApInfo_t *vmacSta_master_p;

		unsigned long dbflags;
		unsigned long MUlistflags;
#ifndef SOC_W906X
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, vmac_p->dev);
		unsigned long MUSetflags;
#endif

		if (vmac_p->master)
			vmacSta_master_p = vmac_p->master;
		else
			vmacSta_master_p = vmac_p;

		if (!vmacSta_master_p->StaCtl->Initialized)
			return FALSE;

		/* To avoid SMP deadlocks be sure the locking order is:
		 *1. MUStaListLock, 2. MUSetListLock, 3. dbLock */
		SPIN_LOCK_IRQSAVE(&vmac_p->MUStaListLock, MUlistflags);
#ifndef SOC_W906X
		SPIN_LOCK_IRQSAVE(&wlpptr->wlpd_p->MUSetListLock, MUSetflags);
#endif
		SPIN_LOCK_IRQSAVE(&vmacSta_master_p->StaCtl->dbLock, dbflags);

		/*Make sure station is not inside list already */
		if (MUchecksta_StaList(vmac_p, StaInfo_p)) {

			/*If new station is already inside MUSetList, break the previous MUSet it was in and let auto grouping to regroup
			 * If it was in a MUSet, it must be a MUSta List. Therefore, we don't need to add it into MUSta list and return here.
			 *
			 * Note: do not transmit GID mgmt frame to avoid assert on stactl dblock locked twice.
			 */
			if (StaInfo_p->MUset != NULL)
#ifdef SOC_W906X
				MUDel_MUSet(vmac_p, StaInfo_p->MUset,
					    (MUSet_BLOCK | MUSet_NO_STA_BLOCK));
#else
				MUDel_MUSet(vmac_p, StaInfo_p->MUset,
					    MUSet_FW_DEL | MUSet_NO_GID_FRAME);
#endif

			SPIN_UNLOCK_IRQRESTORE(&vmacSta_master_p->StaCtl->
					       dbLock, dbflags);
#ifndef SOC_W906X
			SPIN_UNLOCK_IRQRESTORE(&wlpptr->wlpd_p->MUSetListLock,
					       MUSetflags);
#endif
			SPIN_UNLOCK_IRQRESTORE(&vmac_p->MUStaListLock,
					       MUlistflags);
			return FALSE;
		}

		/*Get a new node to fill info and put into list */
		tmp = ListGetItem(&vmacSta_master_p->StaCtl->FreeMUStaList);
		if (tmp) {
			item_p = (MUCapStaNode_t *) tmp;
			item_p->StaInfo_p = StaInfo_p;
			item_p->MUSet_created_flag = 0;
			item_p->MUStaList_idx =
				is_he_capable_sta(StaInfo_p) * 4 +
				StaInfo_p->vht_RxChannelWidth;
			if (wfa_11ax_pf) {
				if ((StaInfo_p->vht_RxChannelWidth == 3) &&
				    !(vmacSta_master_p->he_cap.phy_cap.
				      channel_width_set &
				      HE_SUPPORT_160MHZ_BW_5G))
					item_p->MUStaList_idx =
						is_he_capable_sta(StaInfo_p) *
						4 + 2;
			}

			StaInfo_p->MUStaListNode = item_p;
			ListPutItem((List *) & vmac_p->
				    MUStaList[item_p->MUStaList_idx],
				    (ListItem *) tmp);

		/*-------------------------------------------------------*/
			/* Finished - give back the semaphore and return status. */
		/*-------------------------------------------------------*/
			SPIN_UNLOCK_IRQRESTORE(&vmacSta_master_p->StaCtl->
					       dbLock, dbflags);
#ifndef SOC_W906X
			SPIN_UNLOCK_IRQRESTORE(&wlpptr->wlpd_p->MUSetListLock,
					       MUSetflags);
#endif
			SPIN_UNLOCK_IRQRESTORE(&vmac_p->MUStaListLock,
					       MUlistflags);
			return TRUE;
		} else {
		/*-------------------------------------------------------------*/
			/* There is no room in the table to add the station; give back */
			/* the semaphore and return status.                            */
		/*-------------------------------------------------------------*/

			SPIN_UNLOCK_IRQRESTORE(&vmacSta_master_p->StaCtl->
					       dbLock, dbflags);
#ifndef SOC_W906X
			SPIN_UNLOCK_IRQRESTORE(&wlpptr->wlpd_p->MUSetListLock,
					       MUSetflags);
#endif
			SPIN_UNLOCK_IRQRESTORE(&vmac_p->MUStaListLock,
					       MUlistflags);
			return FALSE;
		}
	}

/* Function to remove links between extStaDb_StaInfo_t and MUCapStaNode_t.
* The corresponding node in MUStaList is returned to FreeMUStaList.
*
* IMPORTANT: Make sure caller to this function has locked MUStaListLock and MUSetflags
*/
	BOOLEAN MUDelStaFromMUStaList(vmacApInfo_t * vmac_p,
				      MUCapStaNode_t * MUStaNode_p) {
		MUCapStaNode_t *item_p = NULL;
		//ListItem *tmp;
		vmacApInfo_t *vmacSta_master_p;
		extStaDb_StaInfo_t *StaInfo_p;
		UINT8 index;
#ifndef SOC_W906X
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, vmac_p->dev);
#else
		unsigned long MUlistflags;
#endif

#ifndef SOC_W906X
		BUG_ON(!spin_is_locked(&vmac_p->MUStaListLock.l));
		BUG_ON(!spin_is_locked(&wlpptr->wlpd_p->MUSetListLock.l));
#endif

		if (vmac_p->master)
			vmacSta_master_p = vmac_p->master;
		else
			vmacSta_master_p = vmac_p;
		if (!vmacSta_master_p->StaCtl->Initialized) {
			return FALSE;
		}

		/*Clean up and handle links between extStaDb_StaInfo_t and MUCapStaNode_t */
		if (MUStaNode_p != NULL) {
#ifdef SOC_W906X
			SPIN_LOCK_IRQSAVE(&vmac_p->MUStaListLock, MUlistflags);	//parent's interface dbLock is called by extStaDb_DelSta
#endif

			item_p = MUStaNode_p;
			StaInfo_p = item_p->StaInfo_p;

			/*Remove links and reset values */
			StaInfo_p->MUStaListNode = NULL;
			item_p->StaInfo_p = NULL;
			item_p->MUSet_created_flag = 0;
			index = item_p->MUStaList_idx;
			item_p->MUStaList_idx = 0;

			ListPutItem(&vmacSta_master_p->StaCtl->FreeMUStaList,
				    ListRmvItem((List *) & vmac_p->
						MUStaList[index],
						(ListItem *) item_p));

			if (vmac_p->MUStaList[index].taken_musta_cnt)
				vmac_p->MUStaList[index].taken_musta_cnt--;

#ifdef SOC_W906X
			SPIN_UNLOCK_IRQRESTORE(&vmac_p->MUStaListLock,
					       MUlistflags);
#endif
			return TRUE;
		}

		return FALSE;
	}

/*Function to remove station from MU set
*
*IMPORTANT: Make sure caller to this function has locked MUStaListLock and MUSetflags
*/
#ifdef SOC_W906X
	BOOLEAN MURemStaFromMUSet(vmacApInfo_t * vmac_p,
				  extStaDb_StaInfo_t * pStaInfo, UINT8 option)
#else
	BOOLEAN MURemStaFromMUSet(vmacApInfo_t * vmac_p,
				  extStaDb_StaInfo_t * pStaInfo)
#endif
	{
		UINT8 index;
#ifdef SOC_W906X
		unsigned long MUlistflags;
#else
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, vmac_p->dev);
#endif

		/* To avoid SMP deadlocks be sure the locking order is:
		 *1. MUStaListLock, 2. MUSetListLock, 3. dbLock */
#ifndef SOC_W906X
		BUG_ON(!spin_is_locked(&vmac_p->MUStaListLock.l));
		BUG_ON(!spin_is_locked(&wlpptr->wlpd_p->MUSetListLock.l));
#endif

		if (pStaInfo == NULL)
			return TRUE;

		pStaInfo->mu_sta = 0;
		pStaInfo->mu_index = 0;
		pStaInfo->MUset = NULL;

		/*Reset counter in MUStaListNode and MUStaList. Links between extStaDb_StaInfo_t and MUStaListNode
		 * are still retained. Sta is removed from MU set only.
		 */
		if (pStaInfo->MUStaListNode != NULL) {

#ifdef SOC_W906X
			if (option & MUSta_BLOCK)
				SPIN_LOCK_IRQSAVE(&vmac_p->MUStaListLock,
						  MUlistflags);
#endif
			pStaInfo->MUStaListNode->MUSet_created_flag = 0;
			index = pStaInfo->MUStaListNode->MUStaList_idx;

			if (vmac_p->MUStaList[index].taken_musta_cnt)
				vmac_p->MUStaList[index].taken_musta_cnt--;

#ifdef SOC_W906X
			if (option & MUSta_BLOCK)
				SPIN_UNLOCK_IRQRESTORE(&vmac_p->MUStaListLock,
						       MUlistflags);
#endif
		}

		return TRUE;
	}

/**
 * This function has 1 input:
 * - a list of MU Stations (MUStaList)
 * and 2 outputs (one excludes the other):
 * - pointer to a MU set that should be deleted (return value)
 * - the number of users of a new MU set to be created (MUUSrs_total).
 *
 * If there are stations in MUStaList not allocated in a MU Set, the function
 * will try at the same time to maximize the groups of 2 users groups and to
 * minimize the number of ungrouped stations. The strategy employed is in this order:
 *
 * a. group of 3 users present, and by breaking it we will end up with all groups of 2 users: break the 3 users group.
 * b. group of 3 users present, but condition at (b.) not satisfied: create a new group of 2 users.
   c. no groups of 3 users present, # unallocated STAs even or bigger than 3: create new group of 2 users.
 * d. no group of 3 users present, and # of unallocated STAs is 3: create a group of 3 users.
 *
 */
/*Function to find victim muset to break or create new muset without breaking a muset.
* It will try to group as many 2 usr muset as possible.
* Return pointer to MU set to break and total users to create via pass by ref return
* If pointer return is NULL, then create new group.
*/
	muset_t *MUPrefer2Usr(struct net_device * netdev,
			      MU_Sta_List * MUStaList, UINT32 * MUUsr_total,
			      UINT8 index) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		vmacApInfo_t *vmac_p = (vmacApInfo_t *) wlpptr->vmacSta_p;
		muset_t *muset_p = NULL;
		UINT32 free_MUUsr_cnt = 0;
		MUCapStaNode_t *item_p, *free_sta_p;

		free_MUUsr_cnt = MUStaList->cnt - MUStaList->taken_musta_cnt;
		if (free_MUUsr_cnt) {
			/*When there is 1 MU sta not grouped yet, find a muset to break it and regroup so all MU capable sta are grouped */
			if (free_MUUsr_cnt == 1) {

				muset_p = (muset_t *) wlpptr->wlpd_p->MUSetList.tail;	//get first item added to list from tail

				if (muset_p == NULL)
					return NULL;

				/*Look for the only client not grouped yet */
				free_sta_p = NULL;
				item_p = (MUCapStaNode_t *) vmac_p->MUStaList[index].tail;	//get first item added to list from tail        
				while (item_p != NULL) {
					if (!item_p->MUSet_created_flag) {
						free_sta_p = item_p;
						break;
					}

					item_p = item_p->prv;
				}

				/*Find 1st muset with 3 usr. Otherwise, get last muset node in list */
				while (muset_p != NULL) {
					if (muset_p->cnt == 3)
						break;

					if (muset_p->prv == NULL)
						break;

					muset_p = muset_p->prv;
				}

				/*Decide whether to break group */
				if (free_sta_p != NULL) {
#ifdef SOC_W906X
					if (((muset_p->antcnt == 8) &&
					     (muset_p->cnt == 2)) ||
					    ((muset_p->cnt == 2) &&
					     ((free_sta_p->StaInfo_p->
					       vht_peer_RxNss +
					       muset_p->antcnt) > 8))) {
						//((muset_p->antcnt==2) &&(muset_p->cnt==2) && (free_sta_p->StaInfo_p->vht_peer_RxNss==2))){
#else
					if (((muset_p->antcnt == 3) &&
					     (muset_p->cnt == 2)) ||
					    ((muset_p->antcnt == 2) &&
					     (muset_p->cnt == 2) &&
					     (free_sta_p->StaInfo_p->
					      vht_peer_RxNss == 2))) {
#endif
						*MUUsr_total = 0;
						return NULL;
					} else {
						return muset_p;
					}
				}
			} else {
				/*If total station in all muset are not divisible by 2, that means there is a muset that has 3 usrs
				 * Find this muset with 3 usrs and decide to break this muset or create new muset without breaking a muset
				 */
				if (wlpptr->wlpd_p->MUSetList.total_sta &&
				    ((wlpptr->wlpd_p->MUSetList.total_sta %
				      2) != 0)) {
					muset_p =
						(muset_t *) wlpptr->wlpd_p->
						MUSetList.tail;

					/*Find 1st muset with 3 usr */
					while (muset_p != NULL) {
						if (muset_p->cnt == 3)
							break;
						//if(muset_p->prv == NULL)
						//      break;

						muset_p = muset_p->prv;
					}
				}

				muset_p = NULL;	//hack so don't break group if more than 2 free users.

				/*If muset with 3 users are found, consider whether to break muset to re-group or just create new muset
				 * If 3 usrs muset + free MU sta give multiple of 2, break group to form 2usrs muset. Otherwise, just form new muset
				 */
				if ((muset_p != NULL) && (muset_p->cnt == 3)) {
					if (((muset_p->cnt +
					      free_MUUsr_cnt) % 2) == 0) {
						return muset_p;
					} else {
						*MUUsr_total = 2;
					}
				} else {
					if ((free_MUUsr_cnt % 2) == 0)
						*MUUsr_total = 2;
					else {
						if (free_MUUsr_cnt > 3)
							*MUUsr_total = 2;	//form 2usrs muset first as priority
						else
							*MUUsr_total = 3;
					}
				}

			}
		}

		return NULL;
	}

#if 0				/* will remove once the code is well verified */
/*Function to find victim muset to break or create new muset without breaking a muset.
* It will try to group as many 3 usr muset as possible.
* Return pointer to MU set to break and total users to create via pass by ref return
* If pointer return is NULL, then create new group.
*/
	muset_t *MUPrefer3Usr(struct net_device * netdev,
			      MU_Sta_List * MUStaList, UINT32 * MUUsr_total,
			      UINT8 index) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		vmacApInfo_t *vmac_p = (vmacApInfo_t *) wlpptr->vmacSta_p;
		muset_t *muset_p = NULL;
		//muset_t muset_victim, muset_nottaken;
		UINT32 free_MUUsr_cnt = 0;
		MUCapStaNode_t *item_p, *free_sta_p;

		free_MUUsr_cnt = MUStaList->cnt - MUStaList->taken_musta_cnt;
		if (free_MUUsr_cnt) {
			/*When there is 1 MU sta not grouped yet, find a muset to break it and regroup so all MU capable sta are grouped */
			if (free_MUUsr_cnt == 1) {

				muset_p = (muset_t *) wlpptr->wlpd_p->MUSetList.tail;	//get first item added to list from tail

				if (muset_p == NULL)
					return NULL;

				/*Look for the only client not grouped yet */
				free_sta_p = NULL;
				item_p = (MUCapStaNode_t *) vmac_p->MUStaList[index].tail;	//get first item added to list from tail        
				while (item_p != NULL) {
					if (!item_p->MUSet_created_flag) {
						free_sta_p = item_p;
						break;
					}

					item_p = item_p->prv;
				}

				/*Find 1st muset with 2 usr. Otherwise, get last muset node in list */
				while (muset_p != NULL) {
					if (muset_p->cnt == 2)
						break;

					if (muset_p->prv == NULL)
						break;

					muset_p = muset_p->prv;
				}

				/*Decide whether to break group */
				if (free_sta_p != NULL) {
#ifdef SOC_W906X
					if (((muset_p->antcnt == 8) &&
					     (muset_p->cnt == 2)) ||
					    ((muset_p->cnt == 2) &&
					     ((free_sta_p->StaInfo_p->
					       vht_peer_RxNss +
					       muset_p->antcnt) > 8))) {
						//((muset_p->antcnt==2) &&(muset_p->cnt==2) && (free_sta_p->StaInfo_p->vht_peer_RxNss==2))){
#else
					if (((muset_p->antcnt == 3) &&
					     (muset_p->cnt == 2)) ||
					    ((muset_p->antcnt == 2) &&
					     (muset_p->cnt == 2) &&
					     (free_sta_p->StaInfo_p->
					      vht_peer_RxNss == 2))) {
#endif
						*MUUsr_total = 0;
						return NULL;
					} else {
						return muset_p;
					}
				}

			} else {
				/*If total station in all muset are not divisible by 3, that means there is a muset that has 2 usrs
				 * Find this muset with 2 usrs and decide to break this muset or create new muset without breaking a muset
				 */
				if (wlpptr->wlpd_p->MUSetList.total_sta &&
				    ((wlpptr->wlpd_p->MUSetList.total_sta %
				      3) != 0)) {
					muset_p =
						(muset_t *) wlpptr->wlpd_p->
						MUSetList.tail;

					/*Find 1st muset with 2 usr */
					while (muset_p != NULL) {
						if (muset_p->cnt == 2)
							break;
						//if(muset_p->prv == NULL)
						//      break;

						muset_p = muset_p->prv;
					}
				}
				muset_p = NULL;	//hack so don't break group if more than 2 free users.

				/*If muset with 2 users are found, consider whether to break muset to re-group or just create new muset
				 * If 2 usrs muset + free MU sta give multiple of 3, break group to form 3usrs muset. Otherwise, just form new muset
				 */
				if ((muset_p != NULL) && (muset_p->cnt == 2)) {
					if (((muset_p->cnt +
					      free_MUUsr_cnt) % 3) == 0) {
						return muset_p;
					} else {
						if ((free_MUUsr_cnt % 3) == 0)
							*MUUsr_total = 3;
						else
							*MUUsr_total = 2;
					}
				} else {
					if ((free_MUUsr_cnt % 3) == 0)
						*MUUsr_total = 3;
					else {
						if (free_MUUsr_cnt > 4)
							*MUUsr_total = 3;	//form 3usrs muset first as priority
						else
							*MUUsr_total = 2;
					}
				}

			}
		}

		return NULL;
	}
#endif

/*Function to find victim muset to break or create new muset without breaking a muset.
* It will try to group as many 3 usr muset as possible.
* Return pointer to MU set to break and total users to create via pass by ref return
* If pointer return is NULL, then create new group.
*/
	muset_t *MUPreferNUsr(struct net_device * netdev,
			      MU_Sta_List * MUStaList, UINT32 * MUUsr_total,
			      UINT8 index, UINT32 n_user) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		vmacApInfo_t *vmac_p = (vmacApInfo_t *) wlpptr->vmacSta_p;
		muset_t *muset_p = NULL;
		UINT32 free_MUUsr_cnt = 0;
		MUCapStaNode_t *item_p, *free_sta_p;
		u32 mu_max_user;

		switch (wlpptr->devid) {
		case SC4:
			mu_max_user = 3;
			break;
		case SC5:
			mu_max_user = 8;
			break;
		case SCBT:
			mu_max_user = 4;
			break;
		default:
			mu_max_user = 3;
		}

		free_MUUsr_cnt = MUStaList->cnt - MUStaList->taken_musta_cnt;

		if (free_MUUsr_cnt) {
			/*When there is 1 MU sta not grouped yet, find a muset to break it and regroup so all MU capable sta are grouped */
			if (free_MUUsr_cnt == 1) {

				muset_p = (muset_t *) wlpptr->wlpd_p->MUSetList.tail;	//get first item added to list from tail

				if (muset_p == NULL)
					return NULL;

				/*Look for the only client not grouped yet */
				free_sta_p = NULL;
				item_p = (MUCapStaNode_t *) vmac_p->MUStaList[index].tail;	//get first item added to list from tail
				while (item_p != NULL) {
					if (!item_p->MUSet_created_flag) {
						free_sta_p = item_p;
						break;
					}
					item_p = item_p->prv;
				}

				/*Find 1st muset less than N usr. Otherwise, get last muset node in list */
				while (muset_p != NULL) {
					if (muset_p->cnt == (n_user - 1))
						break;
					if (muset_p->prv == NULL)
						break;
					muset_p = muset_p->prv;
				}

				/*Decide whether to break group */
				if (free_sta_p != NULL) {
#ifdef SOC_W906X
					if (((muset_p->antcnt == mu_max_user) &&
					     (muset_p->cnt == (n_user - 1))) ||
					    ((muset_p->cnt == (n_user - 1)) &&
					     ((free_sta_p->StaInfo_p->
					       vht_peer_RxNss +
					       muset_p->antcnt) >
					      mu_max_user))) {
						//((muset_p->antcnt==2) &&(muset_p->cnt==2) && (free_sta_p->StaInfo_p->vht_peer_RxNss==2))){
#else
					if (((muset_p->antcnt == 3) &&
					     (muset_p->cnt == 2)) ||
					    ((muset_p->antcnt == 2) &&
					     (muset_p->cnt == 2) &&
					     (free_sta_p->StaInfo_p->
					      vht_peer_RxNss == 2))) {
#endif
						*MUUsr_total = 0;
						return NULL;
					} else
						return muset_p;
				}
			} else {
				/*If total station in all muset are not divisible by 3, that means there is a muset that has 2 usrs
				 * Find this muset with 2 usrs and decide to break this muset or create new muset without breaking a muset
				 */
				if (wlpptr->wlpd_p->MUSetList.total_sta &&
				    ((wlpptr->wlpd_p->MUSetList.total_sta %
				      n_user) != 0)) {
					muset_p =
						(muset_t *) wlpptr->wlpd_p->
						MUSetList.tail;

					/*Find 1st muset with 2 usr */
					while (muset_p != NULL) {
						if (muset_p->cnt ==
						    (n_user - 1))
							break;
						//if(muset_p->prv == NULL)
						//      break;

						muset_p = muset_p->prv;
					}
				}
				muset_p = NULL;	//hack so don't break group if more than 2 free users.

				/*If muset with 2 users are found, consider whether to break muset to re-group or just create new muset
				 * If 2 usrs muset + free MU sta give multiple of 3, break group to form 3usrs muset. Otherwise, just form new muset
				 */
				if ((muset_p != NULL) &&
				    (muset_p->cnt == (n_user - 1))) {
					if (((muset_p->cnt +
					      free_MUUsr_cnt) % n_user) == 0)
						return muset_p;
					else {
						if ((free_MUUsr_cnt % n_user) ==
						    0)
							*MUUsr_total = n_user;
						else
							*MUUsr_total =
								n_user - 1;
					}
				} else {
					if ((free_MUUsr_cnt % n_user) == 0)
						*MUUsr_total = n_user;
					else {
						if (free_MUUsr_cnt >
						    (n_user + 1))
							*MUUsr_total = n_user;	//form n usrs muset first as priority
						else
							*MUUsr_total =
								n_user - 1;
					}
				}
			}
		}

		return NULL;
	}

/*Function to form MU Set automatically*/
	void MUAutoSet_Hdlr(struct net_device *netdev) {

		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		vmacApInfo_t *vmac_p = (vmacApInfo_t *) wlpptr->vmacSta_p;
		UINT32 MUUsr_cnt = 0, MUUsr_total = 0;
		UINT32 cnt, i, k, nooftxantenna = 0;
		extStaDb_StaInfo_t *MUUsr[MU_MAX_USERS];
		vmacApInfo_t *vmacSta_master_p;
		MUCapStaNode_t *item_p;
		muset_t *del_muset[8] = { NULL };
		UINT8 del_muset_cnt = 0;
		//unsigned long dbflags;
		unsigned long MUlistflags;
#ifndef SOC_W906X
		unsigned long MUSetflags;
#endif

		if (vmac_p->master)
			vmacSta_master_p = vmac_p->master;
		else
			vmacSta_master_p = vmac_p;
		if (!vmacSta_master_p->StaCtl->Initialized) {
			return;
		}

		for (i = 0; i < MU_MAX_USERS; i++)
			MUUsr[i] = NULL;

		/* To avoid SMP deadlocks be sure the locking order is:
		 *1. MUStaListLock, 2. MUSetListLock, 3. dbLock */
#ifndef SOC_W906X
		SPIN_LOCK_IRQSAVE(&vmac_p->MUStaListLock, MUlistflags);
		SPIN_LOCK_IRQSAVE(&wlpptr->wlpd_p->MUSetListLock, MUSetflags);
#endif

		/* Go through from 20MHz to 160MHz both VHT and HE */
		for (i = 0; i < ARRAY_SIZE(vmac_p->MUStaList); i++) {
#ifdef SOC_W906X
			SPIN_LOCK_IRQSAVE(&vmac_p->MUStaListLock, MUlistflags);

			if (vmac_p->MUStaList[i].head == NULL) {
				SPIN_UNLOCK_IRQRESTORE(&vmac_p->MUStaListLock,
						       MUlistflags);
				continue;
			}
#else
			if (vmac_p->MUStaList[i].head == NULL)
				continue;
#endif

			MUUsr_total = 0;
			if (vmac_p->MUSet_Prefer_UsrCnt == 2)
				del_muset[del_muset_cnt] =
					MUPrefer2Usr(netdev,
						     &vmac_p->MUStaList[i],
						     &MUUsr_total, i);
			else {
				if ((i < 4) &&
				    (vmac_p->MUSet_Prefer_UsrCnt > 4))
					del_muset[del_muset_cnt] =
						MUPreferNUsr(netdev,
							     &vmac_p->
							     MUStaList[i],
							     &MUUsr_total, i,
							     4);
				else
					del_muset[del_muset_cnt] =
						MUPreferNUsr(netdev,
							     &vmac_p->
							     MUStaList[i],
							     &MUUsr_total, i,
							     vmac_p->
							     MUSet_Prefer_UsrCnt);
			}
			if (del_muset[del_muset_cnt] != NULL) {
				del_muset_cnt++;	//found a muset to break, so continue and don't form group
#ifdef SOC_W906X
				SPIN_UNLOCK_IRQRESTORE(&vmac_p->MUStaListLock,
						       MUlistflags);
#endif
				continue;
			}

			if (MUUsr_total < 2) {
#ifdef SOC_W906X
				SPIN_UNLOCK_IRQRESTORE(&vmac_p->MUStaListLock,
						       MUlistflags);
#endif
				continue;
			}

			/*Go through list to find potential station to be grouped */
			MUUsr_cnt = 0;
			nooftxantenna = 0;

			for (k = 0; k < MU_MAX_USERS; k++)
				MUUsr[k] = NULL;

			item_p = (MUCapStaNode_t *) vmac_p->MUStaList[i].tail;	//get first item added to list from tail

			while ((item_p != NULL) && (item_p->StaInfo_p != NULL)) {
#ifdef SOC_W906X
				if (!item_p->MUSet_created_flag &&
				    (item_p->StaInfo_p->vht_peer_RxNss <= 4)) {
#else
				if (!item_p->MUSet_created_flag &&
				    (item_p->StaInfo_p->vht_peer_RxNss < 3)) {
#endif

#ifdef MUGRP_DELAY
					if (((item_p->StaInfo_p->aggr11n.
					      type & WL_WLAN_TYPE_AMPDU) == 0)
					    || (item_p->StaInfo_p->rx_packets ==
						0)) {
						// Postpone the MU grouping after ampdu==1 && rx_cnt > 0
						// Ref: cl#47513/47514                                  
						item_p = item_p->prv;
						continue;
					}
#endif
					if (MUUsr_cnt == 0) {
						nooftxantenna +=
							item_p->StaInfo_p->
							vht_peer_RxNss;
						MUUsr[MUUsr_cnt] = item_p->StaInfo_p;	//save pointer to sta for MU grouping decision later
						MUUsr_cnt++;
					} else {
#ifdef SOC_W906X
						if ((nooftxantenna +
						     item_p->StaInfo_p->
						     vht_peer_RxNss) <= 8) {
#else
						if ((nooftxantenna +
						     item_p->StaInfo_p->
						     vht_peer_RxNss) <= 3) {
#endif
							nooftxantenna +=
								item_p->
								StaInfo_p->
								vht_peer_RxNss;
							MUUsr[MUUsr_cnt] =
								item_p->
								StaInfo_p;
							MUUsr_cnt++;
						}
					}
				}
#ifdef SOC_W906X
				if (nooftxantenna >= 8)
#else
				if (nooftxantenna >= 3)
#endif
					break;
				if (MUUsr_cnt >= MUUsr_total)
					break;

				item_p = item_p->prv;
			}
#ifdef SOC_W906X
			SPIN_UNLOCK_IRQRESTORE(&vmac_p->MUStaListLock,
					       MUlistflags);
#endif

			/*We have found MU station to be grouped. Mark this node in list as created and create MU group */
#ifdef SOC_W906X
			if ((MUUsr_cnt >= 2) && (nooftxantenna <= 8))
#else
			if ((MUUsr_cnt >= 2) && (nooftxantenna <= 3))
#endif
			{
				printk("Creating MU %d users\n", MUUsr_cnt);
				//??? Need to rechecking the functions before enabling Auto groupping.
#ifdef SOC_W906X
				if (MUCreateMUSet(vmac_p, MUUsr)) {
#else
				if (MUCreateMUSet
				    (vmac_p, MUUsr[0], MUUsr[1], MUUsr[2])) {
#endif
					vmac_p->MUStaList[i].taken_musta_cnt +=
						MUUsr_cnt;

					/*Mark stations used to create MU group */
					cnt = MUUsr_cnt;
					while (cnt) {
						if (MUUsr[cnt - 1] != NULL) {
							if (MUUsr[cnt - 1]->
							    MUStaListNode !=
							    NULL)
								MUUsr[cnt -
								      1]->
								  MUStaListNode->
								  MUSet_created_flag
								  = 1;

						}

						cnt--;
					}
				} else
					printk("FAIL to create MU group\n");

			}

		}
#ifdef SOC_W906X
		//SPIN_UNLOCK_IRQRESTORE(&vmacSta_master_p->StaCtl->dbLock, dbflags);
		//SPIN_UNLOCK_IRQRESTORE(&vmac_p->MUStaListLock, MUlistflags);
#endif
		/*Check if there is any muset to be broken up. If yes, we break up muset and form muset in another timer routine */
		for (i = 0; i < del_muset_cnt; i++) {
			if (del_muset[i] != NULL) {
				//printk("MU break muset index:%d, cnt:%d\n", del_muset[i]->index, del_muset[i]->cnt);
#ifdef SOC_W906X
				MUDel_MUSet(vmac_p, del_muset[i], MUSet_BLOCK);	//break MUSet and let auto grouping to re-group
#else
				MUDel_MUSet(vmac_p, del_muset[i], MUSet_FW_DEL);	//break MUSet and let auto grouping to re-group
#endif
			}
		}
#ifndef SOC_W906X
		SPIN_UNLOCK_IRQRESTORE(&wlpptr->wlpd_p->MUSetListLock,
				       MUSetflags);
		SPIN_UNLOCK_IRQRESTORE(&vmac_p->MUStaListLock, MUlistflags);
#endif
		return;

	}

/*Function to form MU Set manually*/
#ifdef SOC_W906X
	BOOLEAN MUManualSet(vmacApInfo_t * vmac_p,
			    extStaDb_StaInfo_t * pStaInfo[])
#else
	BOOLEAN MUManualSet(vmacApInfo_t * vmac_p,
			    extStaDb_StaInfo_t * pStaInfo0,
			    extStaDb_StaInfo_t * pStaInfo1,
			    extStaDb_StaInfo_t * pStaInfo2)
#endif
	{
		UINT32 free_MUUsr_cnt = 0, MUUsr_cnt = 0;
		//UINT32 MUUsr_total=0;
		UINT32 cnt, i, index = 0;
		extStaDb_StaInfo_t *MUUsr[MU_MAX_USERS];
		vmacApInfo_t *vmacSta_master_p;
		//MUCapStaNode_t *item_p;
		//unsigned long dbflags;
		unsigned long MUlistflags;
#ifndef SOC_W906X
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, vmac_p->dev);
		unsigned long MUSetflags;
#endif
		UINT8 nooftxantenna = 0;

		if (vmac_p->master)
			vmacSta_master_p = vmac_p->master;
		else
			vmacSta_master_p = vmac_p;
		if (!vmacSta_master_p->StaCtl->Initialized) {
			return FALSE;
		}
		/* To avoid SMP deadlocks be sure the locking order is:
		 *1. MUStaListLock, 2. MUSetListLock, 3. dbLock */

		SPIN_LOCK_IRQSAVE(&vmac_p->MUStaListLock, MUlistflags);
#ifndef SOC_W906X
		SPIN_LOCK_IRQSAVE(&wlpptr->wlpd_p->MUSetListLock, MUSetflags);
#endif
		//SPIN_LOCK_IRQSAVE(&vmacSta_master_p->StaCtl->dbLock, dbflags);

#ifdef SOC_W906X
		for (i = 0; i < MU_MAX_USERS; i++)
			MUUsr[i] = pStaInfo[i];
#else
		MUUsr[0] = pStaInfo0;
		MUUsr[1] = pStaInfo1;
		MUUsr[2] = pStaInfo2;
#endif

		if (MUUsr[0]->MUStaListNode != NULL)
			index = MUUsr[0]->MUStaListNode->MUStaList_idx;

		free_MUUsr_cnt =
			vmac_p->MUStaList[index].cnt -
			vmac_p->MUStaList[index].taken_musta_cnt;

		/*Make sure at least 2 stations in list are not grouped */
		if (free_MUUsr_cnt >= 2) {
			for (i = 0; i < MU_MAX_USERS; i++) {
				if (MUUsr[i] != NULL) {
					MUUsr_cnt++;	//count no. of station to be grouped
					nooftxantenna +=
						MUUsr[i]->vht_peer_RxNss;
				}
			}

			/*Create MU set if stations > 2. 
			 * Then update taken_musta_cnt and MUSet_created_flag
			 */
#ifdef SOC_W906X
			if ((MUUsr_cnt >= 2) && (nooftxantenna <= 8))
#else
			if ((MUUsr_cnt >= 2) && (nooftxantenna <= 3))
#endif
			{
				printk("Creating %u users in MU set...\n",
				       MUUsr_cnt);
#ifdef SOC_W906X
				if (MUCreateMUSet(vmac_p, MUUsr)) {
#else
				if (MUCreateMUSet
				    (vmac_p, MUUsr[0], MUUsr[1], MUUsr[2])) {
#endif
					vmac_p->MUStaList[index].
						taken_musta_cnt += MUUsr_cnt;

					/*Mark stations used to create MU set */
					cnt = MUUsr_cnt;
					while (cnt) {
						if (MUUsr[cnt - 1] != NULL) {
							if (MUUsr[cnt - 1]->
							    MUStaListNode !=
							    NULL)
								MUUsr[cnt -
								      1]->
								  MUStaListNode->
								  MUSet_created_flag
								  = 1;
						}

						cnt--;
					}

					//SPIN_UNLOCK_IRQRESTORE(&vmacSta_master_p->StaCtl->dbLock, dbflags);
#ifndef SOC_W906X
					SPIN_UNLOCK_IRQRESTORE(&wlpptr->wlpd_p->
							       MUSetListLock,
							       MUSetflags);
#endif
					SPIN_UNLOCK_IRQRESTORE(&vmac_p->
							       MUStaListLock,
							       MUlistflags);
					return TRUE;
				} else
					printk("FAIL to create MU group\n");

			} else
				printk("FAIL to create MU group, no. of usr must be >=2 && total txantenna <=3\n");

		} else
			printk("FAIL to create MU group, no. of available usr < 2\n");

		//SPIN_UNLOCK_IRQRESTORE(&vmacSta_master_p->StaCtl->dbLock, dbflags);
#ifndef SOC_W906X
		SPIN_UNLOCK_IRQRESTORE(&wlpptr->wlpd_p->MUSetListLock,
				       MUSetflags);
#else
		SPIN_UNLOCK_IRQRESTORE(&vmac_p->MUStaListLock, MUlistflags);
#endif
		return FALSE;
	}

/*Function to delete a MU Set from MUSetList linked list.
* Stations tied to this MU Set will be removed from it.
* 
* IMPORTANT: Make sure caller to this function has locked MUStaListLock and MUSetflags
*/
	BOOLEAN MUDel_MUSet(vmacApInfo_t * vmac_p, muset_t * muset_p,
			    UINT8 option) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, vmac_p->dev);
		muset_t *delnode;
		UINT8 i;
		//extStaDb_StaInfo_t *StaInfo_p;

#ifdef SOC_W906X
		unsigned long MUSetflags;

		if (muset_p != NULL) {
			//printk("Del MUSet index:%d\n", muset_p->index);       
			if (wlFwSetMUSet(vmac_p->dev, 0, muset_p->index + 1, muset_p->index, NULL)) {	//when del, sta id not needed in fw

				if (option & MUSet_BLOCK)
					SPIN_LOCK_IRQSAVE(&wlpptr->wlpd_p->
							  MUSetListLock,
							  MUSetflags);

				/*Remove stations that are tied to this set */
				for (i = 0; i < MU_MAX_USERS; i++) {

					if (muset_p->StaInfo[i] != NULL) {
						if (option & MUSet_NO_STA_BLOCK)
							MURemStaFromMUSet
								(vmac_p,
								 muset_p->
								 StaInfo[i],
								 MUSta_NO_BLOCK);
						else
							MURemStaFromMUSet
								(vmac_p,
								 muset_p->
								 StaInfo[i],
								 MUSta_BLOCK);
						muset_p->StaInfo[i] = NULL;	//set to NULL only at the end after all been reset
					}
				}

				delnode =
					(muset_t *) ListRmvItem((List *) &
								wlpptr->wlpd_p->
								MUSetList.head,
								(ListItem *)
								muset_p);

				if (option & MUSet_BLOCK)
					SPIN_UNLOCK_IRQRESTORE(&wlpptr->wlpd_p->
							       MUSetListLock,
							       MUSetflags);
#else
		BUG_ON(!spin_is_locked(&vmac_p->MUStaListLock.l));
		BUG_ON(!spin_is_locked(&wlpptr->wlpd_p->MUSetListLock.l));

		if (muset_p != NULL) {
			//printk("Del MUSet index:%d\n", muset_p->index);       
			if (((option & MUSet_FW_DEL) == 0) || wlFwSetMUSet(vmac_p->dev, 0, muset_p->index + 1, muset_p->index, 0, 0, 0)) {	//when del, sta id not needed in fw

				vmacApInfo_t *vmacSta_master_p;

				if (vmac_p->master)
					vmacSta_master_p = vmac_p->master;
				else
					vmacSta_master_p = vmac_p;

				/*Remove stations that are tied to this set */
				for (i = 0; i < 3; i++) {
					if (muset_p->StaInfo[i] != NULL) {
						if ((option &
						     MUSet_NO_GID_FRAME) == 0) {
							BUG_ON(SPIN_LOCK_IS_LOCKED_BY_SAME_CORE(&vmacSta_master_p->StaCtl->dbLock));
							SendGroupIDMgmtframe
								(vmac_p,
								 muset_p->
								 StaInfo[i]->
								 Addr, 0, 0);
						}

						MURemStaFromMUSet(vmac_p,
								  muset_p->
								  StaInfo[i]);
						muset_p->StaInfo[i] = NULL;	//set to NULL only at the end after all been reset
					}
				}

				delnode =
					(muset_t *) ListRmvItem((List *) &
								wlpptr->wlpd_p->
								MUSetList.head,
								(ListItem *)
								muset_p);

#endif /* SOC_W906X */
#if defined(MRVL_MUG_ENABLE)
				mug_fill_active_musets(vmac_p->dev);
#endif

				if (delnode != NULL) {
					if (wlpptr->wlpd_p->MUSetList.
					    total_sta >= delnode->cnt)
						wlpptr->wlpd_p->MUSetList.
							total_sta -=
							delnode->cnt;

					wl_kfree(delnode);
					return TRUE;
				}
			} else {
				printk("fw cmd del MUSet index:%d fail\n",
				       muset_p->index);
			}

		}
		return FALSE;
	}

/*Function to delete a MU set by using index*/
	void MUDel_MUSetIndex(vmacApInfo_t * vmac_p, UINT8 muset_index) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, vmac_p->dev);
		muset_t *tempnode, *delnode, *foundnode = NULL;
		UINT8 i;
		unsigned long MUSetflags;
#ifndef SOC_W906X
		unsigned long MUlistflags;
#endif

		tempnode = (muset_t *) wlpptr->wlpd_p->MUSetList.tail;	//start with first item added into list, new node is added to head

		/* To avoid SMP deadlocks be sure the locking order is:
		 *1. MUStaListLock, 2. MUSetListLock, 3. dbLock */
#ifndef SOC_W906X
		SPIN_LOCK_IRQSAVE(&vmac_p->MUStaListLock, MUlistflags);
#endif
		SPIN_LOCK_IRQSAVE(&wlpptr->wlpd_p->MUSetListLock, MUSetflags);
		while (tempnode != NULL) {
			if (tempnode->index == muset_index) {
#ifdef SOC_W906X
				if (wlFwSetMUSet(vmac_p->dev, 0, muset_index + 1, muset_index, NULL)) {	//when del, sta id not needed in fw
#else
				if (wlFwSetMUSet(vmac_p->dev, 0, muset_index + 1, muset_index, 0, 0, 0)) {	//when del, sta id not needed in fw
					vmacApInfo_t *vmacSta_master_p;
					if (vmac_p->master)
						vmacSta_master_p =
							vmac_p->master;
					else
						vmacSta_master_p = vmac_p;
#endif

					/*Remove stations that are tied to this set */
					for (i = 0; i < MU_MAX_USERS; i++) {

						if (tempnode->StaInfo[i] !=
						    NULL) {
#ifdef SOC_W906X
							MURemStaFromMUSet
								(vmac_p,
								 tempnode->
								 StaInfo[i],
								 MUSta_BLOCK);
#else
							BUG_ON(SPIN_LOCK_IS_LOCKED_BY_SAME_CORE(&vmacSta_master_p->StaCtl->dbLock));
							SendGroupIDMgmtframe
								(vmac_p,
								 tempnode->
								 StaInfo[i]->
								 Addr, 0, 0);
							MURemStaFromMUSet
								(vmac_p,
								 tempnode->
								 StaInfo[i]);
#endif
							tempnode->StaInfo[i] = NULL;	//set to NULL only at the end after all been reset
						}
					}

					foundnode = tempnode;
					break;
				} else {
					printk("fw cmd del MUSet index:%d fail\n", muset_index);
				}
			}
			tempnode = tempnode->prv;
		}

		if (foundnode != NULL) {
			delnode =
				(muset_t *) ListRmvItem((List *) & wlpptr->
							wlpd_p->MUSetList.head,
							(ListItem *) foundnode);
			if (delnode) {
				if (wlpptr->wlpd_p->MUSetList.total_sta >=
				    delnode->cnt)
					wlpptr->wlpd_p->MUSetList.total_sta -=
						delnode->cnt;

				wl_kfree(delnode);
				printk("MU set index:%d deleted\n",
				       muset_index);
			}
#if defined(MRVL_MUG_ENABLE)
			mug_fill_active_musets(vmac_p->dev);
#endif
		} else
			printk("MU set to be deleted not found\n");

		SPIN_UNLOCK_IRQRESTORE(&wlpptr->wlpd_p->MUSetListLock,
				       MUSetflags);
#ifndef SOC_W906X
		SPIN_UNLOCK_IRQRESTORE(&vmac_p->MUStaListLock, MUlistflags);
#endif
	}

/*Function to display all MU capable stations, whether MU Set is created or not,  in MUStaList*/
	void MUDisplayMUStaList(vmacApInfo_t * vmac_p) {
		MUCapStaNode_t *item_p = NULL;
		UINT8 i, bw[4] = { 20, 40, 80, 160 };
		extStaDb_StaInfo_t *pStaInfo;
		unsigned long MUlistflags;

		/* To avoid SMP deadlocks be sure the locking order is:
		 *1. MUStaListLock, 2. MUSetListLock, 3. dbLock */
		SPIN_LOCK_IRQSAVE(&vmac_p->MUStaListLock, MUlistflags);

		for (i = 0; i < ARRAY_SIZE(vmac_p->MUStaList); i++) {

			if ((vmac_p->MUStaList[i].head != NULL)) {
				item_p = (MUCapStaNode_t *) vmac_p->MUStaList[i].tail;	//get first item added to list from tail

				printk("MUStaList: %s, %dMHz, total cnt:%d, isgrouped cnt:%d\n\n", (item_p->MUStaList_idx > 3) ? "HE" : "VHT", bw[item_p->MUStaList_idx % 4], vmac_p->MUStaList[i].cnt, vmac_p->MUStaList[i].taken_musta_cnt);

				while (item_p != NULL) {
					if (item_p->StaInfo_p != NULL) {
						UINT32 *capval;
						pStaInfo = item_p->StaInfo_p;
						capval = (UINT32 *) & pStaInfo->
							vhtCap.cap;
						printk("Mac address = %s \n",
						       mac_display(&pStaInfo->
								   Addr[0]));

						printk("Vhtcap=%x ", *capval);
						printk("MUBeamformeeCapable=%x VHTBW=%dMHz RxNss=%x\n", pStaInfo->vhtCap.cap.MUBeamformeeCapable, bw[pStaInfo->vht_RxChannelWidth], pStaInfo->vht_peer_RxNss);

						printk("staindx=%d mu_sta_flag=%d mu_created=%d, mu_index=%d\n", pStaInfo->StnId, pStaInfo->mu_sta, item_p->MUSet_created_flag, pStaInfo->mu_index);
						printk("---------------------------------------------------\n\n");

					}
					item_p = item_p->prv;
				}

			}
		}
		SPIN_UNLOCK_IRQRESTORE(&vmac_p->MUStaListLock, MUlistflags);
	}

/*Function to display all MU sets that have been created*/
	void MUDisplayMUSetList(vmacApInfo_t * vmac_p) {
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, vmac_p->dev);
		muset_t *muset;
		UINT8 i;
		unsigned long MUSetflags;

		SPIN_LOCK_IRQSAVE(&wlpptr->wlpd_p->MUSetListLock, MUSetflags);
		muset = (muset_t *) (wlpptr->wlpd_p->MUSetList.tail);	//start with first item added into list, new node is added to head
		printk("MU set total cnt: %d\n", wlpptr->wlpd_p->MUSetList.cnt);
		printk("Sta total cnt: %d\n\n",
		       wlpptr->wlpd_p->MUSetList.total_sta);

		while (muset != NULL) {
			printk("MU set index: %d, GID:%d\n", muset->index,
			       (muset->index + 1));
			for (i = 0; i < MU_MAX_USERS; i++) {
				if (muset->StaInfo[i] != NULL) {
					printk("sta %d:", i);
					printk(" Mac address = %s \n",
					       mac_display(&muset->StaInfo[i]->
							   Addr[0]));
				}

			}
			printk("---------------------------------------------------\n");
			muset = muset->prv;
		}
		SPIN_UNLOCK_IRQRESTORE(&wlpptr->wlpd_p->MUSetListLock,
				       MUSetflags);
	}

#ifdef AP_STEERING_SUPPORT
	void macMgmtMlme_AssocDenied(IEEEtypes_StatusCode_t statuscode) {
		G_AssocStatusCode = statuscode;
	}
#endif
#if defined(SOC_W906X) && defined(CFG80211)
	extern UINT16 getPhyRate(dbRateInfo_t * pRateTbl);
	extern UINT16 getNss(dbRateInfo_t * pRateTbl);
	void fillStaInfo(struct net_device *netdev, struct station_info *pSinfo,
			 struct extStaDb_StaInfo_t *pStaInfo) {
		SMAC_STA_STATISTICS_st StaStatsTbl;
		dbRateInfo_t RateInfo;
		s8 rssi;

		if (!netdev || !pSinfo || !pStaInfo)
			return;

		rssi = pStaInfo->RSSI ? -(pStaInfo->RSSI) : -(pStaInfo->
							      assocRSSI);

		pSinfo->signal = rssi;
		pSinfo->signal_avg = rssi;

		pSinfo->tx_bytes = pStaInfo->tx_bytes;
		pSinfo->tx_packets = pStaInfo->tx_packets;
		pSinfo->rx_bytes = pStaInfo->rx_bytes;
		pSinfo->rx_packets = pStaInfo->rx_packets;
		pSinfo->txrate.legacy =
			getPhyRate((dbRateInfo_t *) & (pStaInfo->RateInfo));
		pSinfo->txrate.nss =
			getNss((dbRateInfo_t *) & (pStaInfo->RateInfo));

		memcpy(&RateInfo, &(pStaInfo->rx_info_aux.rate_info),
		       sizeof(dbRateInfo_t));
		if (pStaInfo->rx_info_aux.nss > 0) {
			RateInfo.RateIDMCS |=
				((pStaInfo->rx_info_aux.nss - 1) & 0x7) << 4;
		}

		pSinfo->rxrate.legacy = getPhyRate(&RateInfo);
		pSinfo->rxrate.nss = pStaInfo->rx_info_aux.nss;

#ifdef OPENWRT
		pSinfo->connected_time =
			ktime_get_seconds() - pStaInfo->last_connected;
#else
		pSinfo->connected_time = 0;
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)
		pSinfo->inactive_time =
			jiffies_to_msecs(jiffies - netdev->last_rx);
#endif

		memset(&StaStatsTbl, 0, sizeof(SMAC_STA_STATISTICS_st));
		if (wlFwGetStaStats(netdev, pStaInfo->StnId, &StaStatsTbl) !=
		    SUCCESS) {
			WLDBG_INFO(DBG_LEVEL_7,
				   "cannot get StnId %d stats from fw%d\n",
				   pStaInfo->StnId);
			return;
		}

		pSinfo->tx_retries = StaStatsTbl.dot11RetryCount;
		pSinfo->tx_failed =
			StaStatsTbl.dot11MPDUCount -
			StaStatsTbl.dot11SuccessCount -
			StaStatsTbl.dot11RetryCount;
		pSinfo->rx_dropped_misc = StaStatsTbl.dot11FCSErrorCount;

		if (pSinfo->assoc_req_ies) {
			struct IEEEtypes_HT_Element_t *htCap = NULL;
			struct IEEEtypes_VhtCap_t *vhtCap = NULL;
			struct HE_Capabilities_IE_t *heCap = NULL;
			u32 len = 0;

			htCap = (struct IEEEtypes_HT_Element_t *)pSinfo->
				assoc_req_ies;
			len += sizeof(IEEEtypes_HT_Element_t);

			vhtCap = (struct IEEEtypes_VhtCap_t *)(pSinfo->
							       assoc_req_ies +
							       len);
			len += sizeof(IEEEtypes_VhtCap_t);

			heCap = (struct HE_Capabilities_IE_t *)(pSinfo->
								assoc_req_ies +
								len);
			len += sizeof(HE_Capabilities_IE_t);

			memcpy(htCap, &pStaInfo->HtElem,
			       sizeof(IEEEtypes_HT_Element_t));
			memcpy(vhtCap, &pStaInfo->vhtCap,
			       sizeof(IEEEtypes_VhtCap_t));
			memcpy(heCap, &pStaInfo->heCap,
			       sizeof(HE_Capabilities_IE_t));

			pSinfo->assoc_req_ies_len = len;
		}
	}

	void fillApCapInfo(struct net_device *netdev, int mode, u8 * pApCap,
			   u32 * pLen) {
		extern UINT16 AddHT_IE(vmacApInfo_t * vmacSta_p,
				       IEEEtypes_HT_Element_t * pNextElement);
		extern UINT16 Build_IE_191(vmacApInfo_t * vmacSta_p,
					   UINT8 * IE_p, UINT8 isEffective,
					   UINT8 nss);
		extern UINT16 Build_IE_HE_CAP(vmacApInfo_t * vmacSta_p,
					      UINT8 * IE_p);
		struct wlprivate *wlpriv =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		vmacApInfo_t *vmacSta_p = wlpriv->vmacSta_p;

		if (!netdev || !pApCap || !pLen)
			return;

		switch (mode) {
		case 0:
			//HT
			AddHT_IE(vmacSta_p, (IEEEtypes_HT_Element_t *) pApCap);
			*pLen = sizeof(IEEEtypes_HT_Element_t);
			break;
		case 1:
			//VHT
			Build_IE_191(vmacSta_p, pApCap, FALSE, 0);
			*pLen = sizeof(IEEEtypes_VhtCap_t);
			break;
		case 2:
			//HE
			Build_IE_HE_CAP(vmacSta_p, pApCap);
			*pLen = sizeof(HE_Capabilities_IE_t);
			break;
		default:
			break;
		}
	}

	void fillApRadioInfo(struct net_device *netdev,
			     struct ap_radio_basic_capa_rpt_t *pRpt) {
		extern void getOpClass(op_class_info_t * pOpClass);
		struct wlprivate *wlpriv =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		vmacApInfo_t *vmacSta_p = wlpriv->vmacSta_p;
		op_class_info_t *pOpc = NULL;
		u8 i = 0;

		if (!netdev || !pRpt)
			return;

		memset(pRpt, 0, sizeof(struct ap_radio_basic_capa_rpt_t));
		pRpt->maxNumBss = wlpriv->wlpd_p->NumOfAPs;
		memcpy(&pRpt->ruid, &vmacSta_p->VMacEntry.vmacAddr,
		       IEEEtypes_ADDRESS_SIZE);

		pOpc = wl_kmalloc(sizeof(op_class_info_t), GFP_ATOMIC);
		if (!pOpc)
			return;

		memset(pOpc, 0, sizeof(op_class_info_t));
		getOpClass(pOpc);

		for (i = 0; i < pOpc->op_class_nums; i++) {
			if (pOpc->op_class_tab[i].op_class > 84)
				break;
		}

		if (*(vmacSta_p->Mib802dot11->mib_ApMode) & AP_MODE_G_ONLY) {
			pRpt->num_of_operating_class = i;
			memcpy(&pRpt->operatingClass, &pOpc->op_class_tab,
			       sizeof(op_class_tab_t) * i);
		} else {
			pRpt->num_of_operating_class = pOpc->op_class_nums - i;
			memcpy(&pRpt->operatingClass, &pOpc->op_class_tab[i],
			       sizeof(op_class_tab_t) * (pOpc->op_class_nums -
							 i));
		}

		wl_kfree(pOpc);
	}
#endif /* SOC_W906X */
