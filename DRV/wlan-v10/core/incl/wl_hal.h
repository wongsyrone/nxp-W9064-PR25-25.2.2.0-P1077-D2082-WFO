/** @file wl_hal.h
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2003-2020 NXP
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
#ifndef _WL_HAL_H_
#define _WL_HAL_H_

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
#include <linux/net.h>
#include <linux/wireless.h>
#include <asm/atomic.h>
#include <linux/smp.h>

#include "wl_mib.h"
#include "wlvmac.h"

#include "mlme.h"

#include "List.h"

#ifdef CFG80211
#include <net/cfg80211.h>
#endif

#define SZ_PHY_ADDR 6		/*!< Number of bytes in ethernet MAC address */

/* mfg data struct*/
#define SZ_BOARD_NAME       8
#define SZ_BOOT_VERSION     12
#define SZ_PRODUCT_ID       58
#define SZ_INTERNAL_PA_CFG  14
#define SZ_EXTERNAL_PA_CFG  1
#define SZ_CCA_CFG          8
#define SZ_LED              4

#ifdef AP_TWT
typedef enum _twt_state {
	TWT_STATE_INIT,
	TWT_STATE_REQUEST,
	TWT_STATE_SUGGEST,
	TWT_STATE_DEMAND,
	TWT_STATE_GROUPING,
	TWT_STATE_ALTERNATE,
	TWT_STATE_DICTATE,
	TWT_STATE_ACCEPT,
} TWT_STATE;
#endif

#define DECLARE_LOCK(l) spinlock_t l
#define MUST_BE_LOCKED(l)
#define MUST_BE_UNLOCKED(l)
#define SPIN_LOCK_INIT(l) spin_lock_init(l)
#define SPIN_LOCK_IRQSAVE(l, f) spin_lock_irqsave(l, f)
#define SPIN_UNLOCK_IRQRESTORE(l, f) spin_unlock_irqrestore(l, f)
#define SPIN_LOCK_IS_LOCKED_BY_SAME_CORE(lk) 0
#define SPIN_LOCK_BH(l) spin_lock_bh(l)
#define SPIN_UNLOCK_BH(l) spin_unlock_bh(l)
#define SPIN_LOCK(l) spin_lock(l)
#define SPIN_UNLOCK(l) spin_unlock(l)

typedef struct _MFG_CAL_DATA {
	UINT8 BrdDscrpt[SZ_BOARD_NAME];	/* 8 byte ASCII to descript the type and version of the board */
	UINT8 Rev;
	UINT8 PAOptions;
	UINT8 ExtPA[SZ_EXTERNAL_PA_CFG];
	UINT8 Ant;
	UINT16 IntPA[SZ_INTERNAL_PA_CFG];
	UINT8 CCA[SZ_CCA_CFG];
	UINT16 Domain;		/* Wireless domain */
	UINT16 CstmrOpts;
	UINT8 LED[SZ_LED];
	UINT16 Xosc;
	UINT8 Reserved_1[2];
	UINT16 Magic;
	UINT16 ChkSum;
	UINT8 MfgMacAddr[SZ_PHY_ADDR];	/* Mfg mac address */
	UINT8 Reserved_2[4];
	UINT8 PID[SZ_PRODUCT_ID];	/* Production ID */
	UINT8 BootVersion[SZ_BOOT_VERSION];
} MFG_CAL_DATA;
typedef enum _WL_OP_MODE {
	WL_OP_MODE_AP,
	WL_OP_MODE_VAP,
	WL_OP_MODE_STA,
	WL_OP_MODE_VSTA,
#ifdef ENABLE_MONIF
	WL_OP_MODE_MONIF
#endif
} WL_OP_MODE;

typedef struct _WL_SYS_CFG_DATA {
	UINT8 Spi16AddrLen;
	UINT8 Rsrvd[3];
	MIB_802DOT11 Mib802dot11;
	MIB_802DOT11 ShadowMib802dot11;
} WL_SYS_CFG_DATA;
#ifdef WDS_FEATURE
struct wds_port {
	struct net_device *netDevWds;
#ifdef CFG80211
	struct wireless_dev wdev;
#endif
	UINT8 wdsMacAddr[6];
	void *pWdsDevInfo;
	UINT8 wdsPortMode;
	UINT8 active;
	BOOLEAN wdsPortRegistered;
};
#endif

#ifdef WTP_SUPPORT
typedef struct {
	UINT8 WTP_enabled;
	UINT8 RF_ID;
	UINT8 WLAN_ID;
	WTP_MAC_MODE mac_mode;
	WTP_FRAME_TUNNEL_MODE tunnel_mode;
	UINT8 extHtIE;
	UINT8 HTCapIE[128];
	UINT8 addHTIE[128];
	UINT8 extVhtIE;
	UINT8 vhtCapIE[32];
	UINT8 vhtInfoIE[32];
	UINT8 extPropIE;
	UINT8 propIE[128];
#ifdef SOC_W906X
	UINT8 extHeIE;
	UINT8 heCapIe[sizeof(HE_Capabilities_IE_t)];
	UINT8 heOpIe[sizeof(HE_Operation_IE_t)];
#endif
}
WTP_INFO;
#endif

/*
	Rx Side band Info, ref: smac_rx_sideband_info.msg
*/
typedef struct RxSidebandInfo_t {
	//DWORD_0 ~ 3
	UINT32 rsv_0[4];
	//DWORD_4
	UINT32 rssi_dbm_a:12;
	UINT32 rssi_dbm_b:12;
	UINT32 rsv_rssi_ab:8;
	//DWORD_5
	UINT32 rssi_dbm_c:12;
	UINT32 rssi_dbm_d:12;
	UINT32 rsv_rssi_cd:8;
	//DWORD_6
	UINT32 nf_dbm_a:12;
	UINT32 nf_dbm_b:12;
	UINT32 rsv_nf_ab:8;
	//DWORD_7
	UINT32 nf_dbm_c:12;
	UINT32 nf_dbm_d:12;
	UINT32 rsv_nf_cd:8;
	//DWORD_8
	UINT32 rssi_dbm_e:12;
	UINT32 rssi_dbm_f:12;
	UINT32 rsv_rssi_ef:8;
	//DWORD_9~14
	UINT32 rsv_1[6];
	//DWORD_15
	UINT32 rssi_dbm_g:12;
	UINT32 rssi_dbm_h:12;
	UINT32 rsv_rssi_gh:8;
	//DWORD_16
	UINT32 nf_dbm_e:12;
	UINT32 nf_dbm_f:12;
	UINT32 rsv_nf_ef:8;
	//DWORD_17
	UINT32 nf_dbm_g:12;
	UINT32 nf_dbm_h:12;
	UINT32 rsv_nf_gh:8;
	//DWORD_18~27
	UINT32 rsv_2[10];
	//DWORD_28
	UINT32 rxTs;		//rx_info_28, rx timestamp[31:0]
	//DWORD_29
	UINT32 rxTsH;		//rx_info_29,   rx timestamp[39:32]
	//DWORD_30
	UINT32 txTs;		//rx_info_30, tx timestamp[31:0]
	//DWORD_31
	UINT32 rxCq;		//rx_info_31    [31:24]: reserved, [23:0]:rx_cq[23:0]
} PACK RxSidebandInfo_t;

/*
	rssi info to dump
*/
typedef struct _rssi_path_val {
	union {
		struct {
			SINT16 fval:4;
			SINT16 ival:8;
		};
		SINT16 val;
	};
} RssiPathVal;
typedef struct RssiPathInfo_t {
	UINT32 a:12;
	UINT32 b:12;
	UINT32 rsv1:8;

	UINT32 c:12;
	UINT32 d:12;
	UINT32 rsv2:8;

	UINT32 e:12;
	UINT32 f:12;
	UINT32 rsv3:8;
	UINT32 g:12;
	UINT32 h:12;
	UINT32 rsv4:8;

} PACK RssiPathInfo_t;

typedef struct NfPathInfo_s {
	UINT32 a:12;
	UINT32 b:12;
	UINT32 rsv1:8;

	UINT32 c:12;
	UINT32 d:12;
	UINT32 rsv2:8;
#ifdef SOC_W906X
	UINT32 e:12;
	UINT32 f:12;
	UINT32 rsv3:8;
	UINT32 g:12;
	UINT32 h:12;
	UINT32 rsv4:8;
#endif				/* SOC_W906X */
} PACK NfPathInfo_t;

#ifdef SOC_W906X

typedef enum {			// pkt type of rate info
	rtinfo_pkt_legacy = 0,
	rtinfo_pkt_11n,
	rtinfo_pkt_11ac,
	rtinfo_pkt_11ax
} rate_info_pkt_type_t;

// Table 21-12 of 802.11-2016.pdf
enum {
	vht_bw_20 = 0,
	vht_bw_40,
	vht_bw_80,
	vht_bw_160_80p80
};

// Rate_Id of 11b,
// Ref: RateInfo_SC4.pdf
enum {
	rateid_b_1m = 0,	// 0 ~ 4, 11b
	rateid_b_2m,
	rateid_b_5p5m,
	rateid_b_11m,
	rateid_b_22m,
	rateid_ag_6m,		// 5 ~ 13, 11g/a
	rateid_ag_9m,
	rateid_ag_12m,
	rateid_ag_18m,
	rateid_ag_24m,
	rateid_ag_36m,
	rateid_ag_48m,
	rateid_ag_54m,
	rateid_ag_72m
};

typedef struct dbRateInfo_t {
#ifdef MV_CPU_LE
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
#else
	UINT32 ShortGI:2;	//0 = Use standard guard interval,1 = Use short guard interval, 2=11ax short short
	UINT32 Bandwidth:2;	//0 = Use 20 MHz channel,1 = Use 40 MHz channel, 2 = Use 80 MHz
	UINT32 Dcm:1;
	UINT32 Stbc:1;
	UINT32 Format:2;	//0 = Legacy format, 1 = 11n format, 2 = 11ac format
	UINT32 Preambletype:1;	//Preambletype 0= Long, 1= Short;
	UINT32 RateIDMCS:7;
	UINT32 BF:1;
	UINT32 AdvCoding:1;	//ldpc
	UINT32 PowerId:6;
	UINT32 AntSelect:8;	//Bitmap to select one of the transmit antennae
#endif
} dbRateInfo_t;
#else
typedef struct dbRateInfo_t {
#ifdef MV_CPU_LE
	UINT32 Format:2;	//0 = Legacy format, 1 = 11n format, 2 = 11ac format
	UINT32 Stbc:1;
	UINT32 Rsvd1:1;
	UINT32 Bandwidth:2;	//0 = Use 20 MHz channel,1 = Use 40 MHz channel, 2 = Use 80 MHz
	UINT32 ShortGI:1;	//0 = Use standard guard interval,1 = Use short guard interval
	UINT32 Rsvd2:1;
	UINT32 RateIDMCS:7;
	UINT32 Preambletype:1;	//Preambletype 0= Long, 1= Short;
	UINT32 PowerId:6;
	UINT32 AdvCoding:1;	//ldpc
	UINT32 BF:1;
	UINT32 AntSelect:8;	//Bitmap to select one of the transmit antennae
#else
	UINT32 Rsvd2:1;
	UINT32 ShortGI:1;	//0 = Use standard guard interval,1 = Use short guard interval
	UINT32 Bandwidth:2;	//0 = Use 20 MHz channel,1 = Use 40 MHz channel, 2 = Use 80 MHz
	UINT32 Rsvd1:1;
	UINT32 Stbc:1;
	UINT32 Format:2;	//0 = Legacy format, 1 = 11n format, 2 = 11ac format
	UINT32 Preambletype:1;	//Preambletype 0= Long, 1= Short;
	UINT32 RateIDMCS:7;
	UINT32 BF:1;
	UINT32 AdvCoding:1;	//ldpc
	UINT32 PowerId:6;
	UINT32 AntSelect:8;	//Bitmap to select one of the transmit antennae
#endif
} dbRateInfo_t;
#endif

struct probe_response_s {
	UINT8 *extra_ies;
	int extra_len;
	UINT8 *basic_ies;
	int basic_len;
#ifdef SOC_W906X
	UINT8 *csa_ies;
	int csa_len;
#endif
};

#ifdef SOC_W906X
struct dl_ofdma_parameter_s {
	unsigned long started;	/* time at which DL OFDAM started */
	unsigned long all_connected;	/* time at which all STA connected */
	unsigned long postpone_time;	/* time to postpone SetOfdma command */
	U32 max_delay;
	U32 sta_cnt;
	UINT8 option;
	UINT8 ru_mode;
	UINT8 max_sta;
};
#endif

#define RX_TIME_STATISTIC_MAX      6
#define RX_PKTCNT_STATISTIC_MAX    11

typedef struct RxTimeCntStat {
	ktime_t RxTask_t;
	UINT32 RxQuCnt;
	UINT32 RxMSDUCnt;
	UINT32 RxTaskCnt_t[RX_TIME_STATISTIC_MAX];
	UINT32 RxProcCnt_t[RX_TIME_STATISTIC_MAX];
	UINT32 RxQuStatCnt[RX_PKTCNT_STATISTIC_MAX];
	UINT32 RxMSDUStatCnt[RX_PKTCNT_STATISTIC_MAX];
} RxTimeCntStat;

#ifdef AUTOCHANNEL
/* Auto channel select data */
typedef struct acs_data_t {
	UINT8 channel;
	UINT16 bss_num;
	SINT32 min_rssi;
	SINT32 max_rssi;
	SINT32 noise_floor;
	UINT32 ch_load;
	UINT32 score;
	UINT8 is_2nd_ch;
	UINT8 bw;
	UINT8 bw_2g_40_above;
	UINT8 ht40avail;
	UINT32 rssi_ls;
	SINT32 raw_max_rssi;
	SINT32 raw_min_rssi;
	UINT32 nf_bin[MAX_NF_DBM_LEN];
} PACK_END acs_data_t;
#endif /* AUTOCHANNEL */

#define CH_LOAD_UNKNOWN     0
#define CH_LOAD_ACS         1
#define CH_LOAD_RRM         2
#define CH_LOAD_BANDSTEER   3

typedef struct ch_load_info_t {
	UINT8 started;
	UINT8 tag;
	UINT32 dur;
	UINT32 interval;
	UINT32 ignore_time;
	UINT32 loop_count;
	UINT32 prev_load_val;
	ktime_t prev_time;
	UINT8 ch_load;
	Timer timer;
	UINT8 *master;
	void *callback;
} PACK_END ch_load_info_t;

// The pool to save a bunch of mac_address
#define MAC_POOL_SIZE		8
typedef struct _mac_pool {
	UINT8 avail_id;		//The id whose item is available to be updated
	IEEEtypes_MacAddr_t mac_pool[MAC_POOL_SIZE];
} PACK_END mac_pool;

typedef struct vmacApInfo_t {
	vmacEntry_t VMacEntry;
	UINT32 OpMode;		/*!< Mode of operation: client or access point */
	UINT32 CpuFreq;		/* CPU frequency */
	MIB_802DOT11 *Mib802dot11;	/* Initial 802.11 MIB settings */
	MIB_802DOT11 *ShadowMib802dot11;	/* Initial 802.11 MIB settings */
	MFG_CAL_DATA *CalData;	/*!< Calibration data */
#ifdef NEWCALDATA
	MFG_HW_INFO *mfgHwData;
	UINT8 hwInfoRev;
#endif
	struct net_device *dev;
	WL_SYS_CFG_DATA *sysCfgData;
	Timer AgingTimer;
	Timer KeepAliveTimer;
	Timer monTimer;
	Timer scaningTimer;
	Timer reqMeasurementTimer;
	Timer MicTimer;
	Timer GrpKeytimer;
#ifdef COEXIST_20_40_SUPPORT
	Timer CoexistTimer;
#endif
	SyncSrvAp mgtSync;
	BOOLEAN download;
	IEEEtypes_MacAddr_t macStaAddr;
	IEEEtypes_MacAddr_t macStaAddr2;
	IEEEtypes_SsIdElement_t macSsId;
	IEEEtypes_SsIdElement_t macSsId2;
	IEEEtypes_MacAddr_t macBssId, macBssId2;
#ifdef AUTOCHANNEL
	UINT8 ChannelList[IEEE_80211_MAX_NUMBER_OF_CHANNELS];
	UINT32 autochannel[IEEEtypes_MAX_CHANNELS + IEEEtypes_MAX_CHANNELS_A];
	UINT8 autochannelstarted;
	int StopTraffic;
	UINT8 preautochannelfinished;
	ktime_t acs_scantime;
	acs_data_t acs_db[IEEEtypes_MAX_CHANNELS + IEEEtypes_MAX_CHANNELS_A];
	UINT8 OpChanList[IEEE_80211_MAX_NUMBER_OF_CHANNELS];
	UINT8 acs_cur_bcn;
	UINT32 acs_IntervalTime;
	UINT32 acs_chload;
	Timer acs_timer;
	ch_load_info_t acs_cload;
	unsigned char acs_ch_load_weight;
	unsigned char acs_ch_nf_weight;
	unsigned short acs_ch_distance_weight;
	unsigned short acs_bss_distance_weight;
	unsigned short acs_bss_num_weight;
	unsigned short acs_rssi_weight;
	unsigned char worst_channel_idx[2];
	unsigned char bss_channel_idx[2];
	unsigned char acs_mode;	/* 0: Legacy Mode, 1: NF-reading Mode */
	unsigned int acs_mode_nf_worst_score;
	unsigned int acs_mode_nf_normalize_factor;
#endif
#ifdef WDS_FEATURE
	struct wds_port wdsPort[6];
	BOOLEAN wdsActive[6];
	PeerInfo_t wdsPeerInfo[6];
	int CurrFreeWdsPort;
#endif
	BOOLEAN keyMgmtInitDone;
	UINT8 busyScanning;
	UINT8 gUserInitScan;
	UINT32 NumScanChannels;
	SINT32 ChanIdx;
	IEEEtypes_ScanCmd_t ScanParams;
	UINT32 PwrSaveStnCnt;
	struct STADB_CTL *StaCtl;
	UINT8 SmeState;
	IEEEtypes_CapInfo_t macCapInfo;
	UINT32 bOnlyStnCnt;
	UINT32 monitorcnt;
	UINT32 g_IV32;		// = 0;
	UINT16 g_IV16;		// = 0x0001;
	UINT16 ampduWindowSizeCap;
	UINT16 ampduDensityCap;
	UINT32 ampduBytesCap;
	Timer MIC_Errortimer;
	UINT8 MIC_Errorstatus;
	BOOLEAN MICCounterMeasureEnabled;	//indicates if counter Measures is enabled
	UINT32 MIC_ErrordisableStaAsso;	//1
	UINT8 numClients;
	UINT8 nClients;
	UINT8 legClients;
	UINT8 n40MClients;
	UINT8 n20MClients;
	UINT8 gaClients;
	UINT8 bClients;
	UINT8 txPwrTblLoaded;
	UINT8 regionCodeLoaded;
	UINT32 work_to_do;
	UINT32 txQLimit;
	UINT8 Ampdu_Rx_Disable_Flag;
	mac_pool ampdu_acpt_pool;
	mac_pool ampdu_rejt_pool;
	UINT8 Amsdu_Rx_Disable_Flag;
	BOOLEAN InfUpFlag;	//Interface, 0: down, 1: up
#ifdef MRVL_WSC
	WSC_BeaconIEs_t thisbeaconIEs;
	WSC_ProbeRespIEs_t thisprobeRespIEs;
	UINT8 WPSOn;
#endif
#ifdef MRVL_WAPI
	WAPI_BeaconIEs_t thisbeaconIEs;
	WAPI_ProbeRespIEs_t thisprobeRespIEs;
#endif
#ifdef CONFIG_IEEE80211W
	UINT8 ieee80211w;
	UINT8 ieee80211wRequired;
	/* dot11AssociationSAQueryMaximumTimeout (in TUs) */
	unsigned int assoc_sa_query_max_timeout;
	/* dot11AssociationSAQueryRetryTimeout (in TUs) */
	int assoc_sa_query_retry_timeout;
	BOOLEAN igtksaInstalled;
	UINT8 igtk[TK_SIZE_MAX];
	UINT8 pn[6];
	UINT16 GN_igtk;
	UINT16 Non80211wStaCnt;
#endif				/* CONFIG_IEEE80211W */
	struct vmacApInfo_t *master;
	UINT8 NonGFSta;
	struct ETHSTADB_CTL *EthStaCtl;
	UINT8 dfsCacExp;
#if defined(CONFIG_IEEE80211W) || defined(CONFIG_HS2)
	UINT8 RsnIE[64];
	UINT8 WpaIE[64];
	UINT8 RsnIESetByHost;
#endif				/* defined(CONFIG_IEEE80211W) || defined(CONFIG_HS2) */
#ifdef MRVL_WAPI
	UINT8 wapiPN[16];
	UINT8 wapiPN_mc[16];
#endif
#ifdef MRVL_80211R
	UINT8 MDIE[5];
#endif
	IEEEtypes_SuppRatesElement_t SuppRateSet;
	IEEEtypes_ExtSuppRatesElement_t ExtSuppRateSet;
#ifdef WTP_SUPPORT
	WTP_INFO wtp_info;
#endif
	RssiPathInfo_t RSSI_path;	//for STA mode use only
	bfmr_config_t BFMRconfig;
	BFMR_init_status_t BFMRinitstatus;
	BOOLEAN BFMRinitDone;
	BOOLEAN bBFMRconfigChanged;
#ifdef STADB_IN_CACHE
	struct extStaDb_StaInfo_t *lru_stadb;	/* the cached LRU stadb */
#endif
	UINT8 MUSet_Prefer_UsrCnt;
	MU_Sta_List MUStaList[8];	/* VHT 0:20MHz, 1:40MHz, 2:80MHz, 3:160MHz HE 4:20MHz, 5:40MHz, 6:80MHz, 7:160MHz */
	 DECLARE_LOCK(MUStaListLock);	//used to protect access to MUStaList
	struct probe_response_s probeRspBody;
#ifdef IEEE80211K
	UINT8 SepareNumScanChannels;
	UINT8 SepareChanIdx;
	Timer RRM_ScanTimer;
	ch_load_info_t rrm_cload;
#endif				//IEEE80211K
//#ifdef MULTI_AP_SUPPORT
//      IEEEtypes_MultiAP_Element_t MultiAP_IE;
//#endif //MULTI_AP_SUPPORT
#ifdef BAND_STEERING
	ch_load_info_t bandsteer_cload;
#endif				/* BAND_STEERING */
#ifdef SOC_W906X
	IEEEtypes_NonTransmitted_BSSID_Profile_t NonTxBssidProf;	//NonTransmitted BSSID Profile 
	struct dl_ofdma_parameter_s dl_ofdma_para;
#define MAX_OFDMADL_STA	4
	IEEEtypes_MacAddr_t ofdma_mu_sta_addr[MAX_OFDMADL_STA];
	sched_cfg_ul_ofdma_t ul_ofdma;
	HE_Capabilities_IE_t he_cap;
#endif
	//rx BA reorder stats
	UINT32 BA_Rodr2Host;	//Pkt sent to host count
	UINT32 BA_RodrDupDropCnt;	//Duplicate pkt drop count
	UINT32 BA_RodrOoRDropCnt;	//Out of range seqno drop count
	UINT32 BA_RodrRetryDropCnt;	//Retry drop count
	UINT32 BA_RodrAmsduEnQCnt;	//Enqueue AMSDU pkt error (to be dropped) count
	UINT32 BA_RodrFlushDropCnt;	//Flush any drop count within wEnd range
	UINT32 BA_RodrTMODropCnt;	//Timeout processing drop count
	UINT32 BA_RodrWinEndJumpCnt;	//winDelta > winEnd, winStartB moves cnt after wEnd

	//WAR for SMAC that did not fill in probResp timestamp value 
	UINT64 BssTsfBase;	//Base timestamp of the BSS. The timestamp in bcn is (hw tsf - BssTsfBase) since CL47774

	RxTimeCntStat Rx_StatInfo;
	struct kobject *tp_kobj;
	struct kobject *stat_kobj;
	struct kobject *hw_kobj;
	struct kobject *acs_kobj;
	struct kobject *mmdu_kobj;
	struct kobject *mem_kobj;
	struct kobject *vap_info_kobj;
	struct kobject *vap_stat_kobj;
	unsigned long tx_bytes_last;
	unsigned long rx_bytes_last;
	UINT8 UL_GroupSeq;
	UINT64 DL_GroupSet;
	UINT64 UL_GroupSet;
	Timer deauth_block_timer;
	u8 deauth_block;
	UINT32 BarkerPreambleStnCnt;
	struct completion scan_complete;
	unsigned int scan_timeout;
} vmacApInfo_t;

#ifdef CONFIG_IEEE80211W
#define WPA_IGTK_LEN TK_SIZE_MAX
struct wpa_igtk_kde {
	UINT8 keyid[2];
	UINT16 pn_low;
	UINT32 pn_high;
	UINT8 igtk[WPA_IGTK_LEN];
} PACK_END;
#endif /* CONFIG_IEEE80211W */

typedef struct _WLAN_RX_INFO {
	UINT8 resvd0;		/* reserved */
	UINT8 Sq2;		/* Signal Quality 2 */
	UINT16 resvd1;		/* reserved */
	UINT8 resvd2;		/* reserved */
	UINT8 Sq1;		/* Signal Quality 1 */
	UINT8 Rate;		/* rate at which frame was received */
	UINT8 RSSI;		/* RF Signal Strength Indicator */
	UINT16 QosControl;	/* QoS Control field */
	UINT16 resvd3;		/* reserved */
} PACK_END WLAN_RX_INFO;

typedef enum _MCU_OP_MODE {
	MCU_MODE_AP,
	MCU_MODE_STA_INFRA,
	MCU_MODE_STA_ADHOC
} MCU_OP_MODE;
extern BOOLEAN wlSetRFChan(vmacApInfo_t * vmacSta_p, UINT32 chan);
extern BOOLEAN wlSetOpModeMCU(vmacApInfo_t * vmacSta_p, UINT32 mode);
void wlDestroySysCfg(vmacApInfo_t * vmacSta_p);
#endif
