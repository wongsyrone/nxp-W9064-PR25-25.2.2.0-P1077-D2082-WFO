/** @file ap8xLnxFwcmd.h
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2005-2020 NXP
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

#ifndef AP8X_FWCMD_H_
#define AP8X_FWCMD_H_

#include <asm/atomic.h>
#include <linux/types.h>
#include <linux/version.h>
#include <linux/delay.h>
#include <linux/netdevice.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/delay.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/init.h>

#include "ap8xLnxIntf.h"
#include "wltypes.h"
#include "IEEE_types.h"
#include "mib.h"
#include "util.h"

#include "osif.h"
#include "wl_mib.h"
#include "wl_hal.h"
#include "qos.h"
#include "wlmac.h"

#include "hostcmd.h"
#include "wl_macros.h"
#include "wldebug.h"
#include "StaDb.h"
#include "mhsm.h"
#include "dfsMgmt.h"		// MRVL_DFS
#include "domain.h"		// MRVL_DFS
#include "ap8xLnxIoctl.h"
typedef enum {
	WL_DISABLE = 0,
	WL_ENABLE = 1,
	WL_DISABLE_VMAC = 0x80,
} wlfacilitate_e;

typedef enum {
	WL_LONGSLOT = 0,
	WL_SHORTSLOT = 1,
} wlslot_e;

typedef enum {
	WL_RATE_AUTOSELECT = 0,
	WL_RATE_GAP = 0,
	WL_RATE_AP_EVALUATED = 1,
	WL_RATE_1_0MBPS = 2,
	WL_RATE_2_0MBPS = 4,
	WL_RATE_5_5MBPS = 11,
	WL_RATE_6_0MBPS = 12,
	WL_RATE_9_0MBPS = 18,
	WL_RATE_11_0MBPS = 22,
	WL_RATE_12_0MBPS = 24,
	WL_RATE_18_0MBPS = 36,
	WL_RATE_24_0MBPS = 48,
	WL_RATE_36_0MBPS = 72,
	WL_RATE_48_0MBPS = 96,
	WL_RATE_54_0MBPS = 108,
} wlrate_e;

typedef enum {
	WL_GET = 0,
	WL_SET = 1,
	WL_RESET = 2,
} wloperation_e;

typedef enum {
	WL_GET_RC4 = 0,		/* WEP & WPA/TKIP algorithm       */
	WL_SET_RC4 = 1,		/* WEP & WPA/TKIP algorithm       */
	WL_GET_AES = 2,		/* WPA/CCMP & WPA2/CCMP algorithm */
	WL_SET_AES = 3,		/* WPA/CCMP & WPA2/CCMP algorithm */
	WL_RESETKEY = 4,	/* reset key value to default     */
} wlkeyaction_e;

typedef enum {
	WL_BOOST_MODE_REGULAR = 0,
	WL_BOOST_MODE_WIFI = 1,
	WL_BOOST_MODE_DOUBLE = 2,
} wlboostmode_e;

typedef enum {
	WL_UNKNOWN_CLIENT_MODE = 0,
	WL_SINGLE_CLIENT_MODE = 1,
	WL_MULTIPLE_CLIENT_MODE = 2,
} wlboostclientmode_e;

typedef enum {
	WL_LONG_PREAMBLE = 1,
	WL_SHORT_PREAMBLE = 3,
	WL_AUTO_PREAMBLE = 5,
} wlpreamble_e;

typedef enum {
	WL_TX_POWERLEVEL_LOW = 5,
	WL_TX_POWERLEVEL_MEDIUM = 10,
	WL_TX_POWERLEVEL_HIGH = 15,
} wltxpowerlevel_e;

typedef enum {
	WL_ANTENNATYPE_RX = 1,
	WL_ANTENNATYPE_TX = 2,
	WL_ANTENNATYPE_TX2 = 3,
} wlantennatype_e;

typedef enum {
	WL_ANTENNAMODE_RX = 0xffff,
	WL_ANTENNAMODE_TX = 2,
} wlantennamode_e;

typedef enum {
	WL_MAC_TYPE_PRIMARY_CLIENT = 0,
	WL_MAC_TYPE_SECONDARY_CLIENT,
	WL_MAC_TYPE_PRIMARY_AP,
	WL_MAC_TYPE_SECONDARY_AP,
} wlmactype_e;

extern void wlFwCmdComplete(struct net_device *);
extern int wlFwGetHwSpecs(struct net_device *);
extern int wlFwSetRadio(struct net_device *, u_int16_t, wlpreamble_e);
extern int wlFwSetAntenna(struct net_device *, wlantennatype_e);
#ifdef WIFI_ZB_COEX_EXTERNAL_GPIO_TRIGGER
extern int wlFwSetCoexConfig(struct net_device *netdev, u8 * enable, u8 * gpioLevelDetect, u8 * gpioEdgeTrigger, u32 * gpioReqPin, u32 * gpioGrantPin,
			     u32 * gpioPriPin, u8 set);
#endif
extern int wlFwSetRTSThreshold(struct net_device *, int);
extern int wlFwSetInfraMode(struct net_device *);
extern int wlFwSetRate(struct net_device *, wlrate_e);
extern int wlFwSetSlotTime(struct net_device *, wlslot_e);
extern int wlFwSetTxPower(struct net_device *netdev, UINT8 flag, UINT32 powerLevel);
int wlFwGettxpower(struct net_device *netdev, UINT16 * powlist, UINT16 ch, UINT16 band, UINT16 width, UINT16 sub_ch);
extern int wlsetFwPrescan(struct net_device *);
extern int wlsetFwPostscan(struct net_device *, u_int8_t *, u_int8_t);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)
extern int wlFwSetMcast(struct net_device *, struct netdev_hw_addr *);
#else
extern int wlFwSetMcast(struct net_device *, struct dev_mc_list *);
#endif
extern int wlFwSetMacAddr(struct net_device *);
extern int wlFwSetAid(struct net_device *, u_int8_t *, u_int16_t);
#ifdef SOC_W906X
extern int wlFwSetChannel(struct net_device *, u_int8_t, u_int8_t, CHNL_FLAGS *, u_int8_t);
#else
extern int wlFwSetChannel(struct net_device *, u_int8_t, CHNL_FLAGS, u_int8_t);
#endif
extern int wlgetFwStatistics(struct net_device *);
extern int wlFwSetApBeacon(struct net_device *);
extern int wlFwSetAPBss(struct net_device *, wlfacilitate_e);
extern int wlFwSetAPUpdateTim(struct net_device *, u_int16_t, Bool_e);
extern int wlFwSetAPBcastSSID(struct net_device *, wlfacilitate_e);
extern int wlsetFwApWds(struct net_device *, wlfacilitate_e);
extern int wlsetFwApBurstMode(struct net_device *, wlfacilitate_e);
extern int wlFwSetGProt(struct net_device *, wlfacilitate_e);
int wlFwSetHTGF(struct net_device *netdev, UINT32 mode);
int wlFwSetRadarDetection(struct net_device *netdev, UINT32 action);
int wlFwGetAddrValue(struct net_device *netdev, UINT32 addr, UINT32 len, UINT32 * val, UINT16 set);
int wlFwGetAddrtable(struct net_device *netdev);
int wlFwGetEncrInfo(struct net_device *netdev, unsigned char *addr);
#ifdef FIPS_SUPPORT
int wlFwSendFipsTest(struct net_device *netdev, UINT32 encdec, UINT32 alg,
		     DataEntry_t * pKey, DataEntry_t * pNounce, DataEntry_t * pAAD, DataEntry_t * pData, DataEntry_t * pOutput);
int wlFwSendFipsTestAll(struct net_device *netdev);
#endif
#ifdef WDS_FEATURE
extern int wlFwSetWdsMode(struct net_device *netdev);
#endif
#ifdef WMM_AC_EDCA
extern int wlFwSetBssLoadAac(struct net_device *netdev, UINT16 aac);
#endif
int wlFwSetRegionCode(struct net_device *netdev, UINT16 regionCode);
#ifdef MRVL_WSC
extern int wlFwSetWscIE(struct net_device *netdev, u_int16_t ieType, WSC_COMB_IE_t * pWscIE);
#endif
#ifdef WTP_SUPPORT
int wlFwSetPropProbeIE(struct net_device *netdev, UINT8 * extProbeIE, UINT16 len);
#endif
#ifdef MRVL_WAPI
extern int wlFwSetWapiIE(struct net_device *netdev, UINT16 ieType, WAPI_COMB_IE_t * pAPPIE);
#endif
extern int wlFwSetIEs(struct net_device *netdev);
int wlFwApplyChannelSettings(struct net_device *netdev);
#ifdef SOC_W906X
int wlchannelSet(struct net_device *netdev, int channel, int Channel2, CHNL_FLAGS * chanflag, u_int8_t initRateTable);
#else
int wlchannelSet(struct net_device *netdev, int channel, CHNL_FLAGS chanflag, u_int8_t initRateTable);
#endif
int wlFwSetSecurity(struct net_device *netdev, u_int8_t * staaddr);
int wlFwGetNoiseLevel(struct net_device *netdev, UINT16 action, UINT8 * pNoise);
BOOLEAN wlFwGetHwStatsForWlStats(struct net_device *netdev, struct iw_statistics *pStats);
#ifdef V6FW
int wlFwSetDwdsStaMode(struct net_device *netdev, UINT32 enable);
#endif
int wlFwSetFwFlushTimer(struct net_device *netdev, UINT32 usecs);
#ifdef SSU_SUPPORT
int wlFwSetSpectralAnalysis(struct net_device *netdev, ssu_cmd_t * pCfg);

#endif
#ifdef WTP_SUPPORT
BOOLEAN wlFwGetWTPRadioStats(struct net_device *netdev, char *radiostats);
#endif

int wlFwGetSysLoad(struct net_device *netdev, radio_cpu_load_t * sys_load);

#define HostCmd_CMD_SET_WEP                    0x0013
#define HostCmd_CMD_802_11_PTK                 0x0034
#define HostCmd_CMD_802_11_GTK                 0x0035

#define HostCmd_CAPINFO_DEFAULT                0x0000
#define HostCmd_CAPINFO_ESS                    0x0001
#define HostCmd_CAPINFO_IBSS                   0x0002
#define HostCmd_CAPINFO_CF_POLLABLE            0x0004
#define HostCmd_CAPINFO_CF_REQUEST             0x0008
#define HostCmd_CAPINFO_PRIVACY                0x0010
#define HostCmd_CAPINFO_SHORT_PREAMBLE         0x0020
#define HostCmd_CAPINFO_PBCC                   0x0040
#define HostCmd_CAPINFO_CHANNEL_AGILITY        0x0080
#define HostCmd_CAPINFO_SHORT_SLOT             0x0400
#define HostCmd_CAPINFO_RRM                    0x1000
#define HostCmd_CAPINFO_DSSS_OFDM              0x2000

typedef struct RsnIE_t {
	u_int8_t ElemId;
	u_int8_t Len;
	u_int8_t OuiType[4];	/* 00:50:f2:01 */
	u_int8_t Ver[2];
	u_int8_t GrpKeyCipher[4];
	u_int8_t PwsKeyCnt[2];
	u_int8_t PwsKeyCipherList[4];
	u_int8_t AuthKeyCnt[2];
	u_int8_t AuthKeyList[4];
} __attribute__ ((packed)) RsnIE_t;

typedef struct Rsn48IE_t {
	u_int8_t ElemId;
	u_int8_t Len;
	u_int8_t Ver[2];
	u_int8_t GrpKeyCipher[4];
	u_int8_t PwsKeyCnt[2];
	u_int8_t PwsKeyCipherList[4];
	u_int8_t AuthKeyCnt[2];
	u_int8_t AuthKeyList[4];
	u_int8_t RsnCap[2];
	u_int8_t PMKIDCnt[2];
	u_int8_t PMKIDList[16];	//Should modify to 16 * S
	u_int8_t Reserved[8];
} __attribute__ ((packed)) Rsn48IE_t;

typedef struct CfParams_t {
	u_int8_t ElementId;
	u_int8_t Len;
	u_int8_t CfpCnt;
	u_int8_t CfpPeriod;
	u_int16_t CfpMaxDuration;
	u_int16_t CfpDurationRemaining;
} __attribute__ ((packed)) CfParams_t;

typedef struct IbssParams_t {
	u_int8_t ElementId;
	u_int8_t Len;
	u_int16_t AtimWindow;
} __attribute__ ((packed)) IbssParams_t;

typedef union SsParams_t {
	CfParams_t CfParamSet;
	IbssParams_t IbssParamSet;
} __attribute__ ((packed)) SsParams_t;

typedef struct FhParams_t {
	u_int8_t ElementId;
	u_int8_t Len;
	u_int16_t DwellTime;
	u_int8_t HopSet;
	u_int8_t HopPattern;
	u_int8_t HopIndex;
} __attribute__ ((packed)) FhParams_t;

typedef struct DsParams_t {
	u_int8_t ElementId;
	u_int8_t Len;
	u_int8_t CurrentChan;
} __attribute__ ((packed)) DsParams_t;

typedef union PhyParams_t {
	FhParams_t FhParamSet;
	DsParams_t DsParamSet;
} __attribute__ ((packed)) PhyParams_t;

typedef struct ChannelInfo_t {
	u_int8_t FirstChannelNum;
	u_int8_t NumOfChannels;
	u_int8_t MaxTxPwrLevel;
} __attribute__ ((packed)) ChannelInfo_t;

typedef struct Country_t {
	u_int8_t ElementId;
	u_int8_t Len;
	u_int8_t CountryStr[3];
	ChannelInfo_t ChannelInfo[40];
} __attribute__ ((packed)) Country_t;

typedef struct ACIAIFSN_field_t {
#ifdef MV_CPU_LE
	u_int8_t AIFSN:4;
	u_int8_t ACM:1;
	u_int8_t ACI:2;
	u_int8_t rsvd:1;
#else
	u_int8_t rsvd:1;
	u_int8_t ACI:2;
	u_int8_t ACM:1;
	u_int8_t AIFSN:4;
#endif
} __attribute__ ((packed)) ACIAIFSN_field_t;

typedef struct ECWmin_max_field_t {
#ifdef MV_CPU_LE
	u_int8_t ECW_min:4;
	u_int8_t ECW_max:4;
#else
	u_int8_t ECW_max:4;
	u_int8_t ECW_min:4;
#endif
} __attribute__ ((packed)) ECWmin_max_field_t;

typedef struct ACparam_rcd_t {
	ACIAIFSN_field_t ACI_AIFSN;
	ECWmin_max_field_t ECW_min_max;
	u_int16_t TXOP_lim;
} __attribute__ ((packed)) ACparam_rcd_t;

typedef struct WMM_param_elem_t {
	u_int8_t ElementId;
	u_int8_t Len;
	u_int8_t OUI[3];
	u_int8_t Type;
	u_int8_t Subtype;
	u_int8_t version;
	u_int8_t rsvd;
	ACparam_rcd_t AC_BE;
	ACparam_rcd_t AC_BK;
	ACparam_rcd_t AC_VI;
	ACparam_rcd_t AC_VO;
} __attribute__ ((packed)) WMM_param_elem_t;

#define IEEEtypes_MAX_DATA_RATES     8
#define IEEEtypes_MAX_DATA_RATES_G  14
#define IEEEtypes_SSID_SIZE	    32

typedef struct StartCmd_t {
	IEEEtypes_MacAddr_t StaMacAddr;
	u_int8_t SsId[IEEEtypes_SSID_SIZE];
	u_int8_t BssType;
	u_int16_t BcnPeriod;
	u_int8_t DtimPeriod;
	SsParams_t SsParamSet;
	PhyParams_t PhyParamSet;
	u_int16_t ProbeDelay;
	u_int16_t CapInfo;
	u_int8_t BssBasicRateSet[IEEEtypes_MAX_DATA_RATES_G];
	u_int8_t OpRateSet[IEEEtypes_MAX_DATA_RATES_G];
	RsnIE_t RsnIE;
	Rsn48IE_t Rsn48IE;
	WME_param_elem_t WMMParam;
	Country_t Country;
	u_int32_t ApRFType;	/* 0->B, 1->G, 2->Mixed, 3->A, 4->11J */
	u8 sae_pwe;
} __attribute__ ((packed)) StartCmd_t;

typedef struct tagHostCmd_AP_BEACON {
	FWCmdHdr CmdHdr;
	StartCmd_t StartCmd;
	IEEEtypes_RSN_IE_WPAMixedMode_t RsnMixedIE;
} __attribute__ ((packed)) HostCmd_DS_AP_BEACON;
int wlFwSetWpaTkipMode(struct net_device *netdev, u_int8_t * staaddr);
int wlFwSetWpaAesMode(struct net_device *netdev, u_int8_t * staaddr, u_int8_t ouiType);
int wlFwSetWpaAesMode_STA(struct net_device *netdev, u_int8_t * staaddr, u_int8_t ouiType);
int wlFwSetWpaTkipMode_STA(struct net_device *netdev, u_int8_t * staaddr);
int wlFwSetWpaAesGroupK_STA(struct net_device *netdev, UINT8 * macStaAddr_p, UINT8 * key_p, UINT8 index, UINT8 ouiType);
int wlFwSetWpaTkipGroupK_STA(struct net_device *netdev,
			     UINT8 * macStaAddr_p,
			     UINT8 * key_p,
			     UINT16 keyLength,
			     UINT8 * rxMicKey_p, UINT16 rxKeyLength, UINT8 * txMicKey_p, UINT16 txKeyLength, ENCR_TKIPSEQCNT TkipTsc, UINT8 keyIndex);
int wlFwSetWpaWpa2PWK_STA(struct net_device *netdev, extStaDb_StaInfo_t * StaInfo_p);
int wlFwSetWpaGroupK_rx(struct net_device *netdev, wlreq_key * wk);
int wlFwSetNewStn(struct net_device *dev, u_int8_t * staaddr, u_int16_t assocId, u_int16_t stnId, u_int16_t action, PeerInfo_t * pPeerInfo,
		  UINT8 Qosinfo, UINT8 isQosSta, UINT8 wds);

int wlFwSetSecurityKey(struct net_device *netdev, UINT16 action, UINT8 type,
		       UINT8 * pMacAddr, UINT8 keyIndex, UINT16 keyLen, UINT32 keyInfo, UINT8 * pKeyParam);
int wlFwSetWpaGroupK_rx(struct net_device *netdev, wlreq_key * wk);
int wlFwSetWpaWpa2PWK(struct net_device *netdev, extStaDb_StaInfo_t * StaInfo_p);

int wlFwSetNewStn(struct net_device *dev, u_int8_t * staaddr, u_int16_t assocId, u_int16_t stnId, u_int16_t action, PeerInfo_t * pPeerInfo,
		  UINT8 Qosinfo, UINT8 isQosSta, UINT8 wds);
int wlFwSetEdcaParam(struct net_device *netdev, u_int8_t Indx, u_int32_t CWmin, u_int32_t CWmax, u_int8_t AIFSN, u_int16_t TXOPLimit);
int wlFwAcMaxTolerableDelay(struct net_device *netdev, u_int8_t action, u_int8_t ac, u_int32_t * maxdelay);

extern int wlFwSetWep(struct net_device *netdev, u_int8_t * staaddr);
extern int wlFwUpdateDestroyBAStream(struct net_device *dev, u_int32_t ba_type, u_int32_t direction, u_int8_t stream,
				     u_int8_t tid, u_int8_t * Macaddr, u_int16_t staid);
#ifdef SOC_W906X
extern int wlFwCreateBAStream(struct net_device *dev, u_int32_t BarThrs, u_int32_t WindowSize, u_int8_t * Macaddr,
			      u_int8_t DialogToken, u_int8_t Tid, u_int32_t ba_type, u_int32_t direction, u_int8_t ParamInfo,
			      u_int8_t * SrcMacaddr, UINT16 seqNo, UINT32 vhtrxfactor, UINT32, u_int16_t staid);
#else
extern int wlFwCreateBAStream(struct net_device *dev, u_int32_t BarThrs, u_int32_t WindowSize, u_int8_t * Macaddr,
			      u_int8_t DialogToken, u_int8_t Tid, u_int32_t ba_type, u_int32_t direction, u_int8_t ParamInfo,
			      u_int8_t * SrcMacaddr, UINT16 seqNo, UINT32 vhtrxfactor, UINT32);
#endif
extern int wlFwSetMacAddr_Client(struct net_device *netdev, UINT8 * macAddr);
extern int wlFwRemoveMacAddr(struct net_device *netdev, UINT8 * macAddr);
extern int wlFwSetWpaWpa2PWK(struct net_device *netdev, extStaDb_StaInfo_t * StaInfo_p);
extern int wlFwSetWpaTkipGroupK(struct net_device *netdev, UINT8 index);
extern int wlFwSetWpaAesGroupK(struct net_device *netdev, UINT8 index, UINT8 ouiType);
extern int wlFwSetRadarDetection(struct net_device *netdev, UINT32 action);
extern int wlFwApplySettings(struct net_device *netdev);
extern int wlFwMultiBssApplySettings(struct net_device *netdev);

extern void PciWriteMacReg(struct net_device *netdev, UINT32 offset, UINT32 val);
extern UINT32 PciReadMacReg(struct net_device *netdev, UINT32 offset);
extern int wlFwGetHwStats(struct net_device *netdev, char *page);
extern int wlRegRF(struct net_device *netdev, UINT8 flag, UINT32 reg, UINT32 * val);
extern int wlRegBB(struct net_device *netdev, UINT8 flag, UINT32 reg, UINT32 * val);
extern int wlRegCAU(struct net_device *netdev, UINT8 flag, UINT32 reg, UINT32 * val);
extern int wlFwGetBeacon(struct net_device *netdev, UINT8 * pBcn, UINT16 * pLen);
extern int wlFwGetCalTable(struct net_device *netdev, UINT8 annex, UINT8 index);
#ifdef SOC_W906X
extern int wlFwSetAcntStop(struct net_device *netdev);
#endif
#ifdef SOC_W906X
extern int wlFwGetRateTable(struct net_device *netdev, UINT8 * addr, UINT8 * pRateInfo, UINT32 size, UINT8 type, UINT16);
extern int wlFwSetRateTable(struct net_device *netdev, UINT32 action, UINT8 * addr, UINT16 staid, UINT32 rateinfo);
#else
extern int wlFwGetRateTable(struct net_device *netdev, UINT8 * addr, UINT8 * pRateInfo, UINT32 size, UINT8 type);
extern int wlFwSetRateTable(struct net_device *netdev, UINT32 action, UINT8 * addr, UINT32 rateinfo);
#endif

#ifdef CLIENT_SUPPORT
extern int wlFwApplyClientSettings(struct net_device *netdev);
extern int wlFwSetBssForClientMode(struct net_device *netdev, wlfacilitate_e facility);
#endif
extern int wlFwSetHwSpecs(struct net_device *netdev);
extern int wlFwGetWatchdogbitmap(struct net_device *dev, u_int8_t * bitmap);
extern int wlFwGetSeqNoBAStream(struct net_device *, u_int8_t *, uint8_t, uint16_t *);
extern int wlFwCheckBAStream(struct net_device *, u_int32_t, u_int32_t, u_int8_t *, u_int8_t, u_int8_t, u_int32_t, int32_t, u_int8_t);
#ifdef RXPATHOPT
int wlFwSetRxPathOpt(struct net_device *netdev, UINT32 rxPathOpt);
#endif
#ifdef QUEUE_STATS
#ifdef SOC_W906X
extern int wlFwGetQueueStats(struct net_device *netdev, int option, UINT8 fromHM, char *sysfs_buff);
#else
extern int wlFwGetQueueStats(struct net_device *netdev, int option, char *sysfs_buff);
#endif
extern int wlFwResetQueueStats(struct net_device *netdev);
extern int wlFwSetMacSa(struct net_device *netdev, int n, UINT8 * addr);
#endif

extern int wlFwGetConsecTxFailAddr(struct net_device *netdev, IEEEtypes_MacAddr_t * addr);
extern int wlFwSetConsecTxFailLimit(struct net_device *netdev, UINT32 value);
extern int wlFwGetConsecTxFailLimit(struct net_device *netdev, UINT32 * value);
#ifdef SOC_W906X
extern int wlFwSetVHTOpMode(struct net_device *netdev, UINT16 staid, UINT8 vht_NewRxChannelWidth, UINT8 vht_NewRxNss);
#else
extern int wlFwSetVHTOpMode(struct net_device *netdev, IEEEtypes_MacAddr_t * staaddr, UINT8 vht_NewRxChannelWidth, UINT8 vht_NewRxNss);
#endif
extern int wlFwSetBWSignalType(struct net_device *netdev, UINT32 mode, UINT8 val);

/* AIRTIME_FAIRNESS */
extern int wlFwAtfEnable(struct net_device *netdev, UINT8 enable);
extern int wlFwAtfCfgSet(struct net_device *netdev, atf_info_t * atf_info);
extern int wlFwAtfCfgReset(struct net_device *netdev);
extern int wlFwAtfCfgGet(struct net_device *netdev, atf_info_t * atf_info);
/* end of AIRTIME_FAIRNESS */
extern int wlFwGetTLVSet(struct net_device *netdev, UINT8 act, UINT16 type, UINT16 len, UINT8 * tlvData, char *string_buff);
#ifdef WNC_LED_CTRL
extern int wlFwLedOn(struct net_device *netdev, UINT8 led_on);
#endif
extern int wlFwNewDP_Cmd(struct net_device *netdev, UINT8 ch, UINT8 width, UINT8 rates, UINT8 rate_type, UINT8 rate_bw, UINT8 rate_gi, UINT8 rate_ss);
extern int wlFwNewDP_RateDrop(struct net_device *netdev, UINT32 enabled, UINT32 rate_index, UINT32 staidx);
extern int wlFwNewDP_OffChannel_Start(struct net_device *netdev);
extern int wlFwNewDP_queue_OffChan_req(struct net_device *netdev, DOT11_OFFCHAN_REQ_t * pOffChan);
extern int wlFwNewDP_handle_OffChan_event(struct net_device *netdev);
extern int wlFwNewDP_config_prom(struct net_device *netdev, PROM_CNF_t * PromCnf);
extern int wlFwNewDP_sensorD_init(struct net_device *netdev, sensord_init_t * sensordinit, UINT8 action);
extern int wlFwNewDP_sensorD_cmd(struct net_device *netdev);
extern int wlFwNewDP_set_rx_mcast(struct net_device *netdev, rx_mcast_t * RxMcast);
extern int wlFwNewDP_wifiarb_post_req_intr(struct net_device *netdev);
extern int wlFwNewDP_sensord_set_blanking(struct net_device *netdev, u8 * blankingmask);
extern int wlFwNewDP_bfmr_config(struct net_device *netdev, bfmr_config_t * BFMRconfig, UINT8 action);
extern int wlFwNewDP_bfmr_sbf_open(struct net_device *netdev, wlcfg_sbf_open_t * WlcfgsbfOpen);
extern int wlFwNewDP_bfmr_sbf_close(struct net_device *netdev, wlcfg_sbf_close_t * WlcfgsbfClose);
extern int wlFwSetPowerPerRate(struct net_device *netdev);
#if defined(SOC_W906X) || defined(SOC_W9068)
extern int wlFwGetPowerPerRate(struct net_device *netdev, UINT32 RatePower, UINT16 * dBm, UINT8 * ant);
#else
extern int wlFwGetPowerPerRate(struct net_device *netdev, UINT32 RatePower, UINT8 * trpcid, UINT16 * dBm, UINT16 * ant);
#endif
extern int wlFwRadioStatusNotification(struct net_device *netdev, UINT32 action);
extern int wlFwSetTxContinuous(struct net_device *netdev, UINT8 mode, UINT32 rateinfo);
extern int wlFwNewDP_amsducfg(struct net_device *netdev, amsducfg_t * amsdu);
extern int wlFwNewDP_RxSOP(struct net_device *netdev, UINT8 params, UINT8 threshold1, UINT8 threshold2);
extern int wlFwNewDP_set_sku(struct net_device *netdev, UINT32 sku);
extern int wlFwNewDP_DMAThread_start(struct net_device *netdev);
extern int wlFwNewDP_eeprom(struct net_device *netdev, UINT32 offset, UINT8 * data, UINT32 len, UINT16 action);
extern int wlFwNewDP_EEPROM_access(struct net_device *netdev, UINT32 action);
extern int wlFwNewDP_Set_Offchanpwr(struct net_device *netdev, SINT8 pwr, UINT8 bitmap, UINT8 channel);
extern int wlFwNewDP_NDPA_UseTA(struct net_device *netdev, UINT32 enable);
#ifdef SOC_W906X
extern int wlFwSetMUSet(struct net_device *netdev, UINT8 Option, UINT8 GID, UINT8 Setindex, UINT16 * Stn);
extern int wlFwSetMBSSIDSet(struct net_device *netdev, UINT8 Option, UINT8 groupid, UINT8 primary, UINT32 members);
#else
extern int wlFwSetMUSet(struct net_device *netdev, UINT8 Option, UINT8 GID, UINT8 Setindex, UINT16 Stn1, UINT16 Stn2, UINT16 Stn3);
#endif
extern int wlFwSetMUDma(struct net_device *netdev, u_int32_t base, u_int32_t size);
extern int wlFwMUGEnable(struct net_device *netdev, int enable);
extern int wlFwGetPHYBW(struct net_device *netdev);

#if defined(SOC_W906X) || defined(SOC_W9068)
extern int wlFwOBW16_11b(struct net_device *netdev, u8 Enable);
#endif

#ifdef WTP_SUPPORT
extern int wlFwSetWtpMode(struct net_device *netdev);
#endif

int wlFwGet_Device_Region_Code(struct net_device *netdev, UINT32 * EEPROM_Region_Code);
int wlFwGet_Device_PwrTbl(struct net_device *netdev, channel_power_tbl_t * EEPROM_CH_PwrTbl, UINT8 * region_code, UINT8 * number_of_channels,
			  UINT32 channel_index);
int wlFwSetResetRateMode(struct net_device *netdev, u_int8_t ResetRateMode);
int wlFwSetRateUpdateTicks(struct net_device *netdev, UINT32 * n_ticks, UINT8 is_set);
int wlFwUseCustomRate(struct net_device *netdev, UINT32 * cust_rate, UINT8 is_set);

#ifdef AP_STEERING_SUPPORT
extern int wlFwGetQBSSLoad(struct net_device *netdev, UINT8 * ch_util, UINT16 * sta_cnt);
#endif				//AP_STEERING_SUPPORT

#if defined(EEPROM_REGION_PWRTABLE_SUPPORT)
int wlFwGet_EEPROM_Region_Code(struct net_device *netdev, UINT32 * EEPROM_Region_Code);
int wlFwGet_EEPROM_PwrTbl(struct net_device *netdev, channel_power_tbl_t * EEPROM_CH_PwrTbl, UINT8 * region_code, UINT8 * number_of_channels,
			  UINT32 channel_index);
#endif
int wlFwGetCoreDump(struct net_device *netdev, coredump_cmd_t * core_dump, char *buff);
int wlFwGetCoreSniff(struct net_device *netdev, coredump_cmd_t * core_dump, char *buff);
int wlFwDiagMode(struct net_device *netdev, UINT16 status);
int wlFwTxDropMode(struct net_device *netdev, UINT32 id, UINT16 flag, UINT16 enable);
#ifdef DSP_COMMAND
int wlDspCmd(struct net_device *netdev, UINT8 index, UINT8 priority, UINT32 * result);
int wlDspTrig(struct net_device *netdev, UINT8 index, UINT8 priority, UINT8 muGID, UINT8 numUsers, UINT8 pkttype);
int wlDspTrigMu(struct net_device *netdev, UINT8 index, UINT8 priority, U8 * msg, int len);
#endif
extern int wlFwSetMutexGet(struct net_device *netdev);
extern int wlFwSetMutexPut(struct net_device *netdev);
extern int wlFwSetMcastCtsToSelf(struct net_device *netdev, u8 * enable);
extern int wlFwMuUserPosition(struct net_device *netdev, u16 action, u8 gid, u8 usr_pos);

#ifdef IEEE80211K
extern int wlFwSetBcnChannelUtil(struct net_device *netdev, UINT8 ch_tril);
extern int wlFwSetQuiet(struct net_device *netdev, UINT8 enable, UINT8 period, UINT16 duration, UINT16 offset, UINT16 offset1, UINT8 txStop_en);
#endif				/* IEEE80211K */
#ifdef SOC_W906X
int wlFwOffChannel(struct net_device *netdev, u32 ch, u32 bw, u32 dwell, u8 req_type, struct sk_buff *skb, u16 * result);
int wlFwOffChannel_dbg(struct net_device *netdev, u32 * fw_offchan_state);
#endif

extern int wlFwGetRadioStatus(struct net_device *netdev, mvl_status_t * radio_status);
#ifdef SOC_W906X
int wlFw_SetFixedPe(struct net_device *netdev, UINT8 pe, UINT16 enable);
#endif
extern int wlFwSetBeamChange(struct net_device *netdev, u8 enable);

#ifdef SOC_W906X
int wlFwBcnGpio17Toggle(struct net_device *netdev, BOOLEAN action, u8 * enable);
int wlFwSendFrame(struct net_device *netdev, UINT16 staIdx, UINT8 reportId, UINT8 tid,
		  UINT32 rateInfo, UINT8 machdrLen, UINT16 payloadLen, UINT8 * pMacHdr, UINT8 * pData);
int wlFwGetCoreDumpAddrValue(struct net_device *netdev, UINT32 addr, UINT32 len, UINT32 * val, UINT16 set);
int wlFwGetTsf(struct net_device *netdev, tsf_info_t * ptsf);
#ifdef AP_TWT
int wlFwTwtParam(struct net_device *netdev, UINT8 action, UINT8 * mac, UINT8 agid, twt_param_t * param);
#endif
UINT32 wlFwSetMib(struct net_device *netdev, UINT32 action, UINT32 mibIdx, UINT32 * pValue, UINT32 * pNum);
UINT32 wlFwSentTriggerFrameCmd(struct net_device *netdev, UINT8 action, UINT8 type, UINT32 rateInfo, UINT32 period, UINT32 padNum, void *pData);

extern int wlFw_SetSR(struct net_device *netdev, UINT8 enable, SINT8 thresNonSrg, SINT8 thresSrg, UINT8 action, UINT8 * buf);

#endif

extern int wlFwGetTsf(struct net_device *netdev, tsf_info_t * ptsf);
extern int wlFwSetNewStn(struct net_device *dev, u_int8_t * staaddr, u_int16_t assocId, u_int16_t stnId, u_int16_t action,
			 PeerInfo_t * pPeerInfo, UINT8 Qosinfo, UINT8 isQosSta, UINT8 wds);
extern int wlFwSetSecurity(struct net_device *netdev, u_int8_t * staaddr);
extern int wlFwSetNoAck(struct net_device *netdev, UINT8 Enable, UINT8 be_enable, UINT8 bk_enable, UINT8 vi_enable, UINT8 vo_enable);

#ifdef CB_SUPPORT
extern int wlFwSetApCBMode(struct net_device *netdev, u8 mode);
extern int wlFwSetStaCBNoAck(struct net_device *netdev, u8 staid, u8 mode);
extern int wlFwGetStaCBParam(struct net_device *netdev, HostCmd_STA_CB_PARAMS_SYNC * psta_cb_param);
extern int wlFwSetStaCBParam(struct net_device *netdev, HostCmd_STA_CB_PARAMS_SYNC * psta_cb_param);
#endif				//CB_SUPPORT

#ifdef SOC_W906X
extern int wlFwSetOFDMASet(struct net_device *netdev, UINT8 enable, UINT8 sta_count, UINT16 * Stn);
extern int wlFwSetULMUSet(struct net_device *netdev, UINT8 Action, UINT32 RateInfo, UINT32 Flag, UINT8 GID, UINT8 Mode, UINT8 BandWidth, UINT8 StaNum,
			  ul_stnid_ru_t * StaList);
extern int wlFwSetAcntWithMu(struct net_device *netdev, UINT16 Action);
extern int wlFwDFSParams(struct net_device *netdev, UINT16 Action, UINT8 * fcc_min_radar_num_pri, UINT8 * etsi_min_radar_num_pri,
			 UINT8 * jpn_w53_min_radar_num_pri, UINT8 * jpn_w56_min_radar_num_pri, UINT8 * false_detect_th, UINT8 * fcc_zc_error_th,
			 UINT8 * etsi_zc_error_th, UINT8 * jp_zc_error_th, UINT8 * jpw53_zc_error_th);
#endif				//SOC_W906X

extern int wlFwGetStaStats(struct net_device *netdev, int staId, SMAC_STA_STATISTICS_st * sta_stats);
extern int wlFwSetEbfMaxSs(struct net_device *netdev, u_int8_t * staaddr, u_int8_t ebf_max_ss);
#endif				/* AP8X_FWCMD_H_ */
