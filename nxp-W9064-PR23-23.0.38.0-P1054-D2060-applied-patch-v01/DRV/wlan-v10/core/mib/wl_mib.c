/** @file wl_mib.c
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

/*!
* \file    wl_mib.c
* \brief   802.11 MIB module
*/

#include "wltypes.h"
#include "IEEE_types.h"
#include "timer.h"
#include "mib.h"
#include "util.h"

#include "osif.h"
#include "wl_mib.h"
#include "wl_hal.h"
#include "qos.h"
#include "wlApi.h"
#include "domain.h"
#include "ap8xLnxIntf.h"
#include "mlmeApi.h"

#define DEFAULT_AP_SSID "MRVL-AP"	/* default SSID */
#define DEFAULT_AP_CHAN 11 /** default channel **/

#ifdef ENABLE_WEP

#define WEP_ENABLE      TRUE
#define WEP_TYPE        AUTH_SHARED_KEY
#define MIB_WEP         TRUE
#define PRIV_OPTION     TRUE
#define PRIV_INVOKED    TRUE

#else

#define WEP_ENABLE      FALSE
#define WEP_TYPE        AUTH_OPEN_SYSTEM
#define MIB_WEP         FALSE
#define PRIV_OPTION     FALSE
#define PRIV_INVOKED    FALSE

#endif

extern BOOLEAN hal_InitApMIB(MIB_802DOT11 * mib);
extern BOOLEAN hal_InitStaMIB(MIB_802DOT11 * mib);
struct MIB_s {
	MIB_PHY_DSSS_TABLE Mib_PhyBsssTable[MAX_CARDS_SUPPORT];
	MIB_TX_POWER_TABLE
		Mib_TXPowerTable[MAX_CARDS_SUPPORT]
		[IEEE_80211_MAX_NUMBER_OF_CHANNELS];
#ifdef IEEE80211H
	MIB_SPECTRUM_MGMT SpectrumMagament[MAX_CARDS_SUPPORT];
#endif				/* IEEE80211H */

#ifdef BRS_SUPPORT
	UINT32 BssBasicRateMask[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
	UINT32 NotBssBasicRateMask[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
#endif
	UINT16 mib_RtsThresh[MAX_CARDS_SUPPORT];
	UINT16 mib_BcnPeriod[MAX_CARDS_SUPPORT];
	UINT8 mib_ApMode[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
	UINT8 mib_shortSlotTime[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
	UINT8 QoSOptImpl[MAX_CARDS_SUPPORT];	//QoSOptionImplemented
	UINT8 mib_rxAntenna[MAX_CARDS_SUPPORT];
	UINT8 mib_rxAntBitmap[MAX_CARDS_SUPPORT];
	UINT8 mib_txAntenna[MAX_CARDS_SUPPORT];
	UINT16 mib_txAntenna2[MAX_CARDS_SUPPORT];
	UINT32 mib_CDD[MAX_CARDS_SUPPORT];
	UINT32 mib_acs_threshold[MAX_CARDS_SUPPORT];
	UINT8 mib_wlanfilterno[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
	UINT8 mib_wlanfiltermac[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE]
		[FILERMACNUM * 6];
	UINT8 mib_wlanfiltertype[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
	UINT8 mib_guardInterval[MAX_CARDS_SUPPORT];
	UINT8 mib_extSubCh[MAX_CARDS_SUPPORT];
	UINT32 mib_agingtime[MAX_CARDS_SUPPORT];
	UINT8 mib_PadAndSnap[MAX_CARDS_SUPPORT];
	UINT8 mib_autochannel[MAX_CARDS_SUPPORT];
	UINT8 mib_MaxTxPwr[MAX_CARDS_SUPPORT];
	UINT8 mib_enableFixedRateTx[MAX_CARDS_SUPPORT];
	UINT8 mib_FixedRateTxType[MAX_CARDS_SUPPORT];
#ifdef CONFIG_MC_BC_RATE
	UINT32 mib_mcDataRateInfo[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
	UINT32 mib_bcDataRateInfo[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
#endif
	UINT8 mib_txDataRate[MAX_CARDS_SUPPORT];
	UINT8 mib_txDataRateG[MAX_CARDS_SUPPORT];
	UINT8 mib_txDataRateA[MAX_CARDS_SUPPORT];
	UINT8 mib_txDataRateN[MAX_CARDS_SUPPORT];
	UINT8 mib_txDataRateVHT[MAX_CARDS_SUPPORT];
	UINT32 mib_txDataRateInfo[MAX_CARDS_SUPPORT];
	UINT8 mib_MulticastRate[MAX_CARDS_SUPPORT];
	UINT8 mib_MultiRateTxType[MAX_CARDS_SUPPORT];
	UINT8 mib_ManagementRate[MAX_CARDS_SUPPORT];
	UINT8 PowerTagetRateTable20M[MAX_CARDS_SUPPORT][PWTAGETRATETABLE20M];
	UINT8 PowerTagetRateTable40M[MAX_CARDS_SUPPORT][PWTAGETRATETABLE40M];
	UINT8 PowerTagetRateTable20M_5G[MAX_CARDS_SUPPORT]
		[PWTAGETRATETABLE20M_5G];
	UINT8 PowerTagetRateTable40M_5G[MAX_CARDS_SUPPORT]
		[PWTAGETRATETABLE40M_5G];
	UINT8 mib_rifsQNum[MAX_CARDS_SUPPORT];
	UINT8 mib_regionCode[MAX_CARDS_SUPPORT];
	UINT16 mib_maxsta[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];	/*User config max sta limit for each virtual interface, default is MAX_STNS */
	UINT32 mib_consectxfaillimit[MAX_CARDS_SUPPORT];	/*Limit to kick out client when consecutive tx failure cnt > limit */

#if defined (INTOLERANT40) || defined (COEXIST_20_40_SUPPORT)
	UINT8 mib_FortyMIntolerant[MAX_CARDS_SUPPORT];
	UINT8 USER_ChnlWidth[MAX_CARDS_SUPPORT];
	UINT8 mib_HT40MIntoler[MAX_CARDS_SUPPORT];
#endif
	UINT8 mib_htProtect[MAX_CARDS_SUPPORT];
	UINT8 mib_forceProtectiondisable[MAX_CARDS_SUPPORT];
#ifdef RXPATHOPT
	UINT32 mib_RxPathOpt[MAX_CARDS_SUPPORT];
#endif
	UINT8 mib_HtGreenField[MAX_CARDS_SUPPORT];
	UINT8 mib_HtStbc[MAX_CARDS_SUPPORT];
	UINT8 mib_3x3Rate[MAX_CARDS_SUPPORT];
	UINT16 mib_amsdu_flushtime[MAX_CARDS_SUPPORT];
#ifdef WDS_FEATURE
	UINT8 mib_wdsEnable[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
	UINT8 mib_wdsno[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
	UINT8 mib_wdsmac[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE][MAX_WDS_PORT
								   * 6];
	UINT8 mib_wdsBcastMode[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];	/* indicates how broadcast pks are sent over
										 * wds, ( broadcast or unicast to other APs */
#endif				// WDS_FEATURE

	MIB_STA_CFG StationConfig[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];	/* station configuration table */
	MIB_AUTH_ALG AuthAlg[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];	/* authentication algorithms table */
	MIB_WEP_DEFAULT_KEYS WepDefaultKeys[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE][4];	/* wep default keys table */
	MIB_PRIVACY_TABLE Privacy[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];	/* privacy table */
	MIB_OP_DATA OperationTable[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
	MIB_PHY_SUPP_DATA_RATES_TX
		SuppDataRatesTx[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE]
		[IEEEtypes_MAX_DATA_RATES_G];
	MIB_RSNCONFIG RSNConfig[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
	MIB_RSNCONFIG_UNICAST_CIPHERS
		UnicastCiphers[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
	MIB_RSNCONFIG_AUTH_SUITES
		RSNConfigAuthSuites[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
	MIB_RSNSTATS RSNStats[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
	IEEEtypes_RSN_IE_t
		thisStaRsnIE[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
#ifdef AP_WPA2
	MIB_RSNCONFIGWPA2
		RSNConfigWPA2[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
	MIB_RSNCONFIGWPA2_UNICAST_CIPHERS
		WPA2UnicastCiphers[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
	MIB_RSNCONFIGWPA2_UNICAST_CIPHERS
		WPA2UnicastCiphers2[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
	MIB_RSNCONFIGWPA2_AUTH_SUITES
		WPA2AuthSuites[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
	IEEEtypes_RSN_IE_WPA2_t
		thisStaRsnIEWPA2[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
	IEEEtypes_RSN_IE_WPA2MixedMode_t
		thisStaRsnIEWPA2MixedMode[MAX_CARDS_SUPPORT]
		[MAX_VMAC_MIB_INSTANCE];
#endif
	UINT8 mib_broadcastssid[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
	UINT8 mib_defaultkeyindex[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
	UINT8 mib_WPAPSKValueEnabled[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
	UINT8 mib_WPA2PSKValueEnabled[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
	UINT8 mib_cipherSuite[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
	UINT8 mib_wpaWpa2Mode[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
	UINT8 mib_intraBSS[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
	UINT8 mib_11nAggrMode[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
	UINT8 mib_wmmAckPolicy[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
	UINT8 mib_ampdu_factor[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
	UINT8 mib_ampdu_density[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
	UINT8 mib_amsdutx[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
	UINT16 mib_amsdu_maxsize[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
	UINT16 mib_amsdu_allowsize[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
	UINT8 mib_amsdu_pktcnt[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
#ifdef INTEROP
	UINT8 mib_interop[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
#endif
	UINT8 mib_optlevel[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
	UINT8 mib_RateAdaptMode[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
	UINT8 mib_CSMode[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
#ifdef WDS_FEATURE
#define MAX_WDS_PORT 6		// Also in wds.c
	IEEEtypes_MacAddr_t
		mib_WdsMacAddr[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE]
		[MAX_WDS_PORT];
#endif
	UINT8 mib_strictWepShareKey[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
	MRVL_MIB_RSN_GRP_KEY
		mib_MrvlRSN_GrpKey[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
	UINT32 mib_ErpProtEnabled[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
	UINT8 mib_disableAssoc[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
#ifdef PWRFRAC
	UINT8 mib_TxPwrFraction[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
#endif
	UINT8 mib_psHtManagementAct[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
#ifdef CLIENT_SUPPORT
	UINT8 mib_STAMode[MAX_CARDS_SUPPORT];
	UINT8 mib_STAAutoScan[MAX_CARDS_SUPPORT];
	UINT8 mib_STAMacCloneEnable[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
#endif
	UINT8 mib_AmpduTx[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
#ifdef MPRXY
	UINT8 mib_MCastPrxy[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
	UINT8 mib_IPMcastGrpCount[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
	MIB_IPMCAST_GRP_TBL
		mib_IPMcastGrpTbl[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE]
		[MAX_MULTICAST_ADDRESS];
	UINT32 mib_IPMFilteredAddress[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE]
		[MAX_MULTICAST_ADDRESS];
	UINT8 mib_IPMFilteredAddressIndex[MAX_CARDS_SUPPORT]
		[MAX_VMAC_MIB_INSTANCE];
#endif
	UINT8 mib_Rssi[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
#ifdef MRVL_DFS
	UINT16 mib_CACTimeOut[MAX_CARDS_SUPPORT];
	UINT16 mib_ETSICACTimeOut[MAX_CARDS_SUPPORT];
	UINT32 mib_NOPTimeOut[MAX_CARDS_SUPPORT];
#endif
#ifdef DYNAMIC_BA_SUPPORT
	/* Dynamic Ampdu strame bandwidth management status */
	UINT32 mib_ampdu_bamgmt;

	/* Minimum Number of packet Threshold for the AC to start Ampdu stream */
	UINT32 mib_ampdu_mintraffic[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE]
		[MAX_AC];

	/* Low threshold (PPS) for AC_XX AMPDU stream; This value is used to decide during eviction of same AC AMPDU streams  */
	UINT32 mib_ampdu_low_AC_thres[MAX_CARDS_SUPPORT][MAX_AC];
#endif
#ifdef COEXIST_20_40_SUPPORT
	UINT16 mib_Channel_Width_Trigger_Scan_Interval[MAX_CARDS_SUPPORT];  /**  value in second, as describe in 11.14.5 **/
	UINT16 mib_Channel_Transition_Delay_Factor[MAX_CARDS_SUPPORT];
#endif
	UINT8 mib_RptrMode[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
	UINT8 mib_RptrDeviceType[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE]
		[MAXRPTRDEVTYPESTR];
	UINT32 mib_agingtimeRptr[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
	UINT32 mib_bftype;
	UINT32 mib_bfmee;
#ifdef SOC_W8964
	UINT8 disable_aggr_for_vo;
#endif
	UINT8 enable_arp_for_vo;
	UINT8 disable_qosctl;
	UINT32 mib_bwSignaltype;
	UINT32 mib_weakiv_threshold;
	UINT8 mib_mu_bfmer;
	UINT8 mib_mu_bfmee;
#ifdef WTP_SUPPORT
	MIB_WTP_CFG mib_Wtp_Config[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
#endif
#ifdef IEEE80211K
	UINT8 mib_rrm[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
	UINT8 mib_quiet[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
#endif

	UINT32 mib_mumimo_mgmt[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
#ifdef SOC_W906X
	UINT32 mib_rx_enable;
	UINT32 mib_heldpc_enable;
	UINT32 mib_mbssid;
	UINT32 mib_superBA;	//++sba
	UINT32 mib_BAReorder_holdtime[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
#ifdef AP_TWT
	UINT32 mib_he_twt_activated;
#endif
	UINT32 mib_he_mu_bf;
	UINT32 mib_he_su_bf;
#endif
#ifdef AP_STEERING_SUPPORT
	UINT8 mib_btm_enabled[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
#endif				/* AP_STEERING_SUPPORT */
#ifdef BAND_STEERING
	UINT8 mib_bandsteer[MAX_CARDS_SUPPORT];
	UINT32 mib_bandsteer_handler[MAX_CARDS_SUPPORT];
	UINT32 mib_bandsteer_mode[MAX_CARDS_SUPPORT];
	UINT32 mib_bandsteer_timer_interval[MAX_CARDS_SUPPORT];
	UINT32 mib_bandsteer_rssi_threshold[MAX_CARDS_SUPPORT];
	UINT32 mib_bandsteer_sta_track_max_num[MAX_CARDS_SUPPORT];
	UINT32 mib_bandsteer_sta_track_max_age[MAX_CARDS_SUPPORT];
	UINT32 mib_bandsteer_sta_auth_retry_cnt[MAX_CARDS_SUPPORT];
#endif				/* BAND_STEERING */
#ifdef MULTI_AP_SUPPORT
	UINT8 mib_unassocsta_track_enabled[MAX_CARDS_SUPPORT];
	UINT32 mib_unassocsta_track_max_num[MAX_CARDS_SUPPORT];
	UINT32 mib_unassocsta_track_max_age[MAX_CARDS_SUPPORT];
	UINT32 mib_unassocsta_track_time[MAX_CARDS_SUPPORT];
#endif				/* MULTI_AP_SUPPORT */
#ifdef DOT11V_DMS
	UINT8 mib_dms[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
#endif
	UINT8 mib_reset_rate_mode[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
	UINT8 mib_eap_rate_fixed[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];

	UINT8 mib_beamChange_disable[MAX_CARDS_SUPPORT];
	MIB_HECONFIG HEConfig[MAX_CARDS_SUPPORT];
	mib_conf_capability
		mib_conf_capab[MAX_CARDS_SUPPORT][MAX_VMAC_MIB_INSTANCE];
#ifdef AIRTIME_FAIRNESS
	UINT32 mib_atf_enable;
	UINT16 mib_atf_cfg_vi;
	UINT16 mib_atf_cfg_be;
	UINT16 mib_atf_cfg_bk;
	UINT16 mib_atf_cfg_airtime;
#endif				/* AIRTIME_FAIRNESS */
#ifdef WLS_FTM_SUPPORT
	UINT8 wls_ftm_enable[MAX_CARDS_SUPPORT];
#endif
} MIB_s;

static struct MIB_s *wlanmib[2] = { NULL, NULL };	// mib of client / ap mode

#define DEF_HE_RTS_THRESHOLD		12	//1023
extern BOOLEAN
mib_InitAp(MIB_802DOT11 * mib, char *addr, int phyMacId, int vMacId, int shadow)
{
#ifdef SOC_W8964
	extern BOOLEAN force_5G_channel;
#endif
	MIB_STA_CFG *mib_StaCfg;
	MIB_OP_DATA *mib_OpData;
	MIB_WEP_DEFAULT_KEYS *mib_WepDefaultKeys;
	MIB_PHY_SUPP_DATA_RATES_TX *mib_PhySuppTxDataRates;
	MIB_SPECTRUM_MGMT *mib_SpectrumMagament_p;
	MIB_802DOT11 *mibSystem_p;
	MIB_PHY_DSSS_TABLE *PhyDSSSTable;
	UINT8 ssid[IEEEtypes_SSID_SIZE];
#ifdef MPRXY
	UINT32 index = 0;
#endif

	UINT8 i = 0;

	for (i = 0; i < 2; i++) {
		if (!wlanmib[i]) {
			wlanmib[i] =
				(struct MIB_s *)
				wl_vzalloc(sizeof(struct MIB_s));
			if (!wlanmib[i]) {
				printk("wl_vzalloc wlanmib[%d] fail", i);
				return FALSE;
			}
		}
	}

	mib->PhyDSSSTable = &wlanmib[shadow]->Mib_PhyBsssTable[phyMacId];

	for (index = 0; index < IEEE_80211_MAX_NUMBER_OF_CHANNELS; index++) {
		mib->PhyTXPowerTable[index] =
			&wlanmib[shadow]->Mib_TXPowerTable[phyMacId][index];
	}

	mib->SpectrumMagament = &wlanmib[shadow]->SpectrumMagament[phyMacId];
#ifdef BRS_SUPPORT
	mib->BssBasicRateMask =
		&wlanmib[shadow]->BssBasicRateMask[phyMacId][vMacId];
	mib->NotBssBasicRateMask =
		&wlanmib[shadow]->NotBssBasicRateMask[phyMacId][vMacId];
#endif
	mib->mib_RtsThresh = &wlanmib[shadow]->mib_RtsThresh[phyMacId];
	mib->mib_BcnPeriod = &wlanmib[shadow]->mib_BcnPeriod[phyMacId];
	mib->mib_ApMode = &wlanmib[shadow]->mib_ApMode[phyMacId][vMacId];
	mib->mib_shortSlotTime =
		&wlanmib[shadow]->mib_shortSlotTime[phyMacId][vMacId];
	mib->QoSOptImpl = &wlanmib[shadow]->QoSOptImpl[phyMacId];
	mib->mib_rxAntenna = &wlanmib[shadow]->mib_rxAntenna[phyMacId];
	mib->mib_rxAntBitmap = &wlanmib[shadow]->mib_rxAntBitmap[phyMacId];
	mib->mib_txAntenna = &wlanmib[shadow]->mib_txAntenna[phyMacId];
	mib->mib_txAntenna2 = &wlanmib[shadow]->mib_txAntenna2[phyMacId];
	mib->mib_CDD = &wlanmib[shadow]->mib_CDD[phyMacId];
	mib->mib_acs_threshold = &wlanmib[shadow]->mib_acs_threshold[phyMacId];
	mib->mib_wlanfilterno =
		&wlanmib[shadow]->mib_wlanfilterno[phyMacId][vMacId];
	mib->mib_wlanfiltermac =
		&wlanmib[shadow]->mib_wlanfiltermac[phyMacId][vMacId][0];
	mib->mib_wlanfiltertype =
		&wlanmib[shadow]->mib_wlanfiltertype[phyMacId][vMacId];
	mib->mib_guardInterval = &wlanmib[shadow]->mib_guardInterval[phyMacId];
	mib->mib_extSubCh = &wlanmib[shadow]->mib_extSubCh[phyMacId];
	mib->mib_agingtime = &wlanmib[shadow]->mib_agingtime[phyMacId];
	mib->mib_PadAndSnap = &wlanmib[shadow]->mib_PadAndSnap[phyMacId];
	mib->mib_autochannel = &wlanmib[shadow]->mib_autochannel[phyMacId];
	mib->mib_MaxTxPwr = &wlanmib[shadow]->mib_MaxTxPwr[phyMacId];
	mib->PowerTagetRateTable20M =
		&wlanmib[shadow]->PowerTagetRateTable20M[phyMacId][0];
	mib->PowerTagetRateTable40M =
		&wlanmib[shadow]->PowerTagetRateTable40M[phyMacId][0];
	mib->PowerTagetRateTable20M_5G =
		&wlanmib[shadow]->PowerTagetRateTable20M_5G[phyMacId][0];
	mib->PowerTagetRateTable40M_5G =
		&wlanmib[shadow]->PowerTagetRateTable40M_5G[phyMacId][0];
	mib->mib_rifsQNum = &wlanmib[shadow]->mib_rifsQNum[phyMacId];
	mib->mib_regionCode = &wlanmib[shadow]->mib_regionCode[phyMacId];
	mib->mib_maxsta = &wlanmib[shadow]->mib_maxsta[phyMacId][vMacId];
	mib->mib_consectxfaillimit =
		&wlanmib[shadow]->mib_consectxfaillimit[phyMacId];
#if defined ( INTOLERANT40)  || defined (COEXIST_20_40_SUPPORT)

	mib->mib_FortyMIntolerant =
		&wlanmib[shadow]->mib_FortyMIntolerant[phyMacId];
	mib->USER_ChnlWidth = &wlanmib[shadow]->USER_ChnlWidth[phyMacId];
	mib->mib_HT40MIntoler = &wlanmib[shadow]->mib_HT40MIntoler[phyMacId];
#endif
	mib->mib_htProtect = &wlanmib[shadow]->mib_htProtect[phyMacId];
	mib->mib_forceProtectiondisable =
		&wlanmib[shadow]->mib_forceProtectiondisable[phyMacId];
	mib->mib_amsdu_flushtime =
		&wlanmib[shadow]->mib_amsdu_flushtime[phyMacId];
#ifdef WDS_FEATURE
	mib->mib_wdsEnable = &wlanmib[shadow]->mib_wdsEnable[phyMacId][vMacId];
	mib->mib_wdsno = &wlanmib[shadow]->mib_wdsno[phyMacId][vMacId];
	mib->mib_wdsmac = &wlanmib[shadow]->mib_wdsmac[phyMacId][vMacId][0];
	mib->mib_wdsBcastMode = &wlanmib[shadow]->mib_wdsBcastMode[phyMacId][vMacId];	/* indicates how broadcast pks are sent over
											 * wds, ( broadcast or unicast to other APs */
#endif // WDS_FEATURE

	mib->StationConfig = &wlanmib[shadow]->StationConfig[phyMacId][vMacId];	/* station configuration table */
	mib->AuthAlg = &wlanmib[shadow]->AuthAlg[phyMacId][vMacId];	/* authentication algorithms table */
	mib->WepDefaultKeys = &wlanmib[shadow]->WepDefaultKeys[phyMacId][vMacId][0];	/* wep default keys table */
	mib->Privacy = &wlanmib[shadow]->Privacy[phyMacId][vMacId];	/* privacy table */

	mib->OperationTable =
		&wlanmib[shadow]->OperationTable[phyMacId][vMacId];
	mib->SuppDataRatesTx =
		&wlanmib[shadow]->SuppDataRatesTx[phyMacId][vMacId][0];
	mib->RSNConfig = &wlanmib[shadow]->RSNConfig[phyMacId][vMacId];
	mib->UnicastCiphers =
		&wlanmib[shadow]->UnicastCiphers[phyMacId][vMacId];
	mib->RSNConfigAuthSuites =
		&wlanmib[shadow]->RSNConfigAuthSuites[phyMacId][vMacId];
	mib->RSNStats = &wlanmib[shadow]->RSNStats[phyMacId][vMacId];
	mib->thisStaRsnIE = &wlanmib[shadow]->thisStaRsnIE[phyMacId][vMacId];
#ifdef AP_WPA2
	mib->RSNConfigWPA2 = &wlanmib[shadow]->RSNConfigWPA2[phyMacId][vMacId];
	mib->WPA2UnicastCiphers =
		&wlanmib[shadow]->WPA2UnicastCiphers[phyMacId][vMacId];
	mib->WPA2UnicastCiphers2 =
		&wlanmib[shadow]->WPA2UnicastCiphers2[phyMacId][vMacId];
	mib->WPA2AuthSuites =
		&wlanmib[shadow]->WPA2AuthSuites[phyMacId][vMacId];
	mib->thisStaRsnIEWPA2 =
		&wlanmib[shadow]->thisStaRsnIEWPA2[phyMacId][vMacId];
	mib->thisStaRsnIEWPA2MixedMode =
		&wlanmib[shadow]->thisStaRsnIEWPA2MixedMode[phyMacId][vMacId];
#endif
	mib->mib_broadcastssid =
		&wlanmib[shadow]->mib_broadcastssid[phyMacId][vMacId];
	mib->mib_defaultkeyindex =
		&wlanmib[shadow]->mib_defaultkeyindex[phyMacId][vMacId];
	mib->mib_enableFixedRateTx =
		&wlanmib[shadow]->mib_enableFixedRateTx[phyMacId];
	mib->mib_FixedRateTxType =
		&wlanmib[shadow]->mib_FixedRateTxType[phyMacId];
#ifdef CONFIG_MC_BC_RATE
	mib->mib_mcDataRateInfo =
		&wlanmib[shadow]->mib_mcDataRateInfo[phyMacId][vMacId];
	mib->mib_bcDataRateInfo =
		&wlanmib[shadow]->mib_bcDataRateInfo[phyMacId][vMacId];
#endif
	mib->mib_txDataRate = &wlanmib[shadow]->mib_txDataRate[phyMacId];
	mib->mib_txDataRateG = &wlanmib[shadow]->mib_txDataRateG[phyMacId];
	mib->mib_txDataRateA = &wlanmib[shadow]->mib_txDataRateA[phyMacId];
	mib->mib_txDataRateN = &wlanmib[shadow]->mib_txDataRateN[phyMacId];
	mib->mib_txDataRateVHT = &wlanmib[shadow]->mib_txDataRateVHT[phyMacId];
	mib->mib_txDataRateInfo =
		&wlanmib[shadow]->mib_txDataRateInfo[phyMacId];
	mib->mib_MulticastRate = &wlanmib[shadow]->mib_MulticastRate[phyMacId];
	mib->mib_MultiRateTxType =
		&wlanmib[shadow]->mib_MultiRateTxType[phyMacId];
	mib->mib_ManagementRate =
		&wlanmib[shadow]->mib_ManagementRate[phyMacId];
	mib->mib_WPAPSKValueEnabled =
		&wlanmib[shadow]->mib_WPAPSKValueEnabled[phyMacId][vMacId];
	mib->mib_WPA2PSKValueEnabled =
		&wlanmib[shadow]->mib_WPA2PSKValueEnabled[phyMacId][vMacId];
	mib->mib_cipherSuite =
		&wlanmib[shadow]->mib_cipherSuite[phyMacId][vMacId];
	mib->mib_wpaWpa2Mode =
		&wlanmib[shadow]->mib_wpaWpa2Mode[phyMacId][vMacId];
	mib->mib_intraBSS = &wlanmib[shadow]->mib_intraBSS[phyMacId][vMacId];
	mib->pMib_11nAggrMode =
		&wlanmib[shadow]->mib_11nAggrMode[phyMacId][vMacId];
	mib->mib_wmmAckPolicy =
		&wlanmib[shadow]->mib_wmmAckPolicy[phyMacId][vMacId];
	mib->mib_ampdu_factor =
		&wlanmib[shadow]->mib_ampdu_factor[phyMacId][vMacId];
	mib->mib_ampdu_density =
		&wlanmib[shadow]->mib_ampdu_density[phyMacId][vMacId];
	mib->mib_amsdutx = &wlanmib[shadow]->mib_amsdutx[phyMacId][vMacId];
	mib->mib_amsdu_maxsize =
		&wlanmib[shadow]->mib_amsdu_maxsize[phyMacId][vMacId];
	mib->mib_amsdu_allowsize =
		&wlanmib[shadow]->mib_amsdu_allowsize[phyMacId][vMacId];
	mib->mib_amsdu_pktcnt =
		&wlanmib[shadow]->mib_amsdu_pktcnt[phyMacId][vMacId];
#ifdef INTEROP
	mib->mib_interop = &wlanmib[shadow]->mib_interop[phyMacId][vMacId];
#endif
	mib->mib_optlevel = &wlanmib[shadow]->mib_optlevel[phyMacId][vMacId];
	mib->mib_RateAdaptMode =
		&wlanmib[shadow]->mib_RateAdaptMode[phyMacId][vMacId];
	mib->mib_CSMode = &wlanmib[shadow]->mib_CSMode[phyMacId][vMacId];
#ifdef WDS_FEATURE
	for (index = 0; index < MAX_WDS_PORT; index++)
		mib->mib_WdsMacAddr[index] =
			&wlanmib[shadow]->
			mib_WdsMacAddr[phyMacId][vMacId][index];
#endif
#ifdef IEEE80211K
	mib->mib_rrm = &wlanmib[shadow]->mib_rrm[phyMacId][vMacId];
	mib->mib_quiet = &wlanmib[shadow]->mib_quiet[phyMacId][vMacId];
#endif
	mib->mib_strictWepShareKey =
		&wlanmib[shadow]->mib_strictWepShareKey[phyMacId][vMacId];
	mib->mib_MrvlRSN_GrpKey =
		&wlanmib[shadow]->mib_MrvlRSN_GrpKey[phyMacId][vMacId];
	mib->mib_ErpProtEnabled =
		&wlanmib[shadow]->mib_ErpProtEnabled[phyMacId][vMacId];
	mib->mib_disableAssoc =
		&wlanmib[shadow]->mib_disableAssoc[phyMacId][vMacId];
#ifdef PWRFRAC
	mib->mib_TxPwrFraction =
		&wlanmib[shadow]->mib_TxPwrFraction[phyMacId][vMacId];
#endif
	mib->mib_psHtManagementAct =
		&wlanmib[shadow]->mib_psHtManagementAct[phyMacId][vMacId];
#ifdef CLIENT_SUPPORT
	mib->mib_STAMode = &wlanmib[shadow]->mib_STAMode[phyMacId];
	mib->mib_STAAutoScan = &wlanmib[shadow]->mib_STAAutoScan[phyMacId];
	mib->mib_STAMacCloneEnable =
		&wlanmib[shadow]->mib_STAMacCloneEnable[phyMacId][vMacId];
#endif
	mib->mib_AmpduTx = &wlanmib[shadow]->mib_AmpduTx[phyMacId][vMacId];
#ifdef MPRXY
	mib->mib_MCastPrxy = &wlanmib[shadow]->mib_MCastPrxy[phyMacId][vMacId];
	mib->mib_IPMcastGrpCount =
		&wlanmib[shadow]->mib_IPMcastGrpCount[phyMacId][vMacId];

	for (index = 0; index < MAX_MULTICAST_ADDRESS; index++) {
		mib->mib_IPMcastGrpTbl[index] =
			&wlanmib[shadow]->
			mib_IPMcastGrpTbl[phyMacId][vMacId][index];
		mib->mib_IPMFilteredAddress[index] =
			&wlanmib[shadow]->
			mib_IPMFilteredAddress[phyMacId][vMacId][index];
	}

	mib->mib_IPMFilteredAddressIndex =
		&wlanmib[shadow]->mib_IPMFilteredAddressIndex[phyMacId][vMacId];
#endif

	mib->mib_Rssi = &wlanmib[shadow]->mib_Rssi[phyMacId][vMacId];
#ifdef SOC_W906X
	mib->mib_rx_enable = &wlanmib[shadow]->mib_rx_enable;
	mib->mib_heldpc_enable = &wlanmib[shadow]->mib_heldpc_enable;
	mib->mib_mbssid = &wlanmib[shadow]->mib_mbssid;
	mib->mib_superBA = &wlanmib[shadow]->mib_superBA;
	mib->mib_BAReorder_holdtime =
		&wlanmib[shadow]->mib_BAReorder_holdtime[phyMacId][vMacId];
#ifdef AP_TWT
	mib->he_twt_activated = &wlanmib[shadow]->mib_he_twt_activated;
#endif
#ifdef WLS_FTM_SUPPORT
	mib->wls_ftm_enable = &wlanmib[shadow]->wls_ftm_enable[phyMacId];
#endif
	mib->he_mu_bf = &wlanmib[shadow]->mib_he_mu_bf;
	mib->he_su_bf = &wlanmib[shadow]->mib_he_su_bf;
#endif

#ifdef RXPATHOPT
	mib->mib_RxPathOpt = &wlanmib[shadow]->mib_RxPathOpt[phyMacId];
#endif
#ifdef DYNAMIC_BA_SUPPORT
	mib->mib_ampdu_bamgmt = &wlanmib[shadow]->mib_ampdu_bamgmt;

	mib->mib_ampdu_mintraffic[0] =
		&wlanmib[shadow]->mib_ampdu_mintraffic[phyMacId][vMacId][0];
	mib->mib_ampdu_mintraffic[1] =
		&wlanmib[shadow]->mib_ampdu_mintraffic[phyMacId][vMacId][1];
	mib->mib_ampdu_mintraffic[2] =
		&wlanmib[shadow]->mib_ampdu_mintraffic[phyMacId][vMacId][2];
	mib->mib_ampdu_mintraffic[3] =
		&wlanmib[shadow]->mib_ampdu_mintraffic[phyMacId][vMacId][3];

	mib->mib_ampdu_low_AC_thres[0] =
		&wlanmib[shadow]->mib_ampdu_low_AC_thres[phyMacId][0];
	mib->mib_ampdu_low_AC_thres[1] =
		&wlanmib[shadow]->mib_ampdu_low_AC_thres[phyMacId][1];
	mib->mib_ampdu_low_AC_thres[2] =
		&wlanmib[shadow]->mib_ampdu_low_AC_thres[phyMacId][2];
	mib->mib_ampdu_low_AC_thres[3] =
		&wlanmib[shadow]->mib_ampdu_low_AC_thres[phyMacId][3];
#endif
#ifdef COEXIST_20_40_SUPPORT
	mib->mib_Channel_Width_Trigger_Scan_Interval =
		&wlanmib[shadow]->
		mib_Channel_Width_Trigger_Scan_Interval[phyMacId];
	mib->mib_Channel_Transition_Delay_Factor =
		&wlanmib[shadow]->mib_Channel_Transition_Delay_Factor[phyMacId];
#endif
	mib->mib_HtGreenField = &wlanmib[shadow]->mib_HtGreenField[phyMacId];
	mib->mib_HtStbc = &wlanmib[shadow]->mib_HtStbc[phyMacId];
	mib->mib_3x3Rate = &wlanmib[shadow]->mib_3x3Rate[phyMacId];
	mib->mib_RptrMode = &wlanmib[shadow]->mib_RptrMode[phyMacId][vMacId];
	mib->mib_RptrDeviceType =
		&wlanmib[shadow]->mib_RptrDeviceType[phyMacId][vMacId][0];
	mib->mib_agingtimeRptr =
		&wlanmib[shadow]->mib_agingtimeRptr[phyMacId][vMacId];
	mib->mib_bftype = &wlanmib[shadow]->mib_bftype;
	mib->mib_bfmee = &wlanmib[shadow]->mib_bfmee;
#ifdef SOC_W8964
	mib->disable_aggr_for_vo = &wlanmib[shadow]->disable_aggr_for_vo;
#endif
	mib->enable_arp_for_vo = &wlanmib[shadow]->enable_arp_for_vo;
	mib->disable_qosctl = &wlanmib[shadow]->disable_qosctl;
	mib->mib_bwSignaltype = &wlanmib[shadow]->mib_bwSignaltype;
	mib->mib_weakiv_threshold = &wlanmib[shadow]->mib_weakiv_threshold;
	mib->mib_mu_bfmer = &wlanmib[shadow]->mib_mu_bfmer;
	mib->mib_mu_bfmee = &wlanmib[shadow]->mib_mu_bfmee;
#ifdef WTP_SUPPORT
	mib->mib_wtp_cfg = &wlanmib[shadow]->mib_Wtp_Config[phyMacId][vMacId];
#endif
	mib->mib_mumimo_mgmt =
		&wlanmib[shadow]->mib_mumimo_mgmt[phyMacId][vMacId];

#ifdef AIRTIME_FAIRNESS
	mib->mib_atf_enable = &wlanmib[shadow]->mib_atf_enable;
	mib->mib_atf_cfg_vi = &wlanmib[shadow]->mib_atf_cfg_vi;
	mib->mib_atf_cfg_be = &wlanmib[shadow]->mib_atf_cfg_be;
	mib->mib_atf_cfg_bk = &wlanmib[shadow]->mib_atf_cfg_bk;
	mib->mib_atf_cfg_airtime = &wlanmib[shadow]->mib_atf_cfg_airtime;
#endif /* AIRTIME_FAIRNESS */

	mibSystem_p = mib;
	PhyDSSSTable = mib->PhyDSSSTable;
	mib_SpectrumMagament_p = mib->SpectrumMagament;
	mib_StaCfg = mib->StationConfig;
	mib_OpData = mib->OperationTable;
	mib_WepDefaultKeys = mib->WepDefaultKeys;
	mib_PhySuppTxDataRates = mib->SuppDataRatesTx;
	mib->AuthAlg->Idx = 0;	/* not used */
	mib->AuthAlg->Enable = 0x0;
	mib->AuthAlg->Type = AUTH_OPEN_SYSTEM;

	PhyDSSSTable->CurrChan = OEMCHANNEL;
	PhyDSSSTable->SecChan = 0;	/* No second channel by default */
	PhyDSSSTable->Chanflag.ChnlWidth = CH_20_MHz_WIDTH;
	PhyDSSSTable->Chanflag.ExtChnlOffset = EXT_CH_ABOVE_CTRL_CH;

#ifdef RADAR_SCANNER_SUPPORT
	PhyDSSSTable->no_cac = 0;
#endif

	if (((PhyDSSSTable->Chanflag.ChnlWidth == CH_40_MHz_WIDTH) ||
	     (PhyDSSSTable->Chanflag.ChnlWidth == CH_AUTO_WIDTH))
	    && PhyDSSSTable->CurrChan > 0 && PhyDSSSTable->CurrChan < 8) {
		PhyDSSSTable->Chanflag.ExtChnlOffset = EXT_CH_ABOVE_CTRL_CH;
	} else if (((PhyDSSSTable->Chanflag.ChnlWidth == CH_40_MHz_WIDTH) ||
		    (PhyDSSSTable->Chanflag.ChnlWidth == CH_AUTO_WIDTH))
		   && PhyDSSSTable->CurrChan > 7 && PhyDSSSTable->CurrChan < 15) {
		PhyDSSSTable->Chanflag.ExtChnlOffset = EXT_CH_BELOW_CTRL_CH;
	}
	//need to be fixed later for 5G 40MHz
#ifdef SOC_W8964
	if (force_5G_channel) {
		PhyDSSSTable->Chanflag.FreqBand = FREQ_BAND_5GHZ;
	} else {
#endif
		if (PhyDSSSTable->CurrChan < 15)
			PhyDSSSTable->Chanflag.FreqBand = FREQ_BAND_2DOT4GHZ;
		else
			PhyDSSSTable->Chanflag.FreqBand = FREQ_BAND_5GHZ;
#ifdef SOC_W8964
	}
#endif
	PhyDSSSTable->CurrCcaMode = 1;

	//    mib_StaCfg->PwrMgtMode = 0x0; //PWR_MODE_ACTIVE;
	mib_StaCfg->DtimPeriod = 1;
	mib_StaCfg->CfPeriod = 2;
	mib_StaCfg->CfpMax = 0x0;
	mib_StaCfg->CfPollable = 0;
	mib_StaCfg->DesiredBssType = BSS_INFRASTRUCTURE;
	mib_StaCfg->PrivOption = FALSE;
	memset(mib_StaCfg->DesiredBSSId, 0, 6);

#ifdef BRS_SUPPORT
	mib_StaCfg->OpRateSet[0] = 2;	// | 0x80;
	mib_StaCfg->OpRateSet[1] = 4;	// | 0x80;
	mib_StaCfg->OpRateSet[2] = 11;	// | 0x80;
	mib_StaCfg->OpRateSet[3] = 22;	// | 0x80;
	mib_StaCfg->OpRateSet[4] = 44;
	mib_StaCfg->OpRateSet[5] = 12;	// | 0x80;
	mib_StaCfg->OpRateSet[6] = 18;
	mib_StaCfg->OpRateSet[7] = 24;	// | 0x80;
	mib_StaCfg->OpRateSet[8] = 36;
	mib_StaCfg->OpRateSet[9] = 48;	// | 0x80;
	mib_StaCfg->OpRateSet[10] = 72;
	mib_StaCfg->OpRateSet[11] = 96;
	mib_StaCfg->OpRateSet[12] = 108;
	mib_StaCfg->OpRateSet[13] = 0;
	mib_StaCfg->OpRateSet[14] = 0;
#else

	mib_StaCfg->OpRateSet[0] = 0x82;
	mib_StaCfg->OpRateSet[1] = 0x84;	//84
	mib_StaCfg->OpRateSet[2] = 0x8B;	//0xB;
	mib_StaCfg->OpRateSet[3] = 0x96;	//0x16;
	mib_StaCfg->OpRateSet[4] = 12 | 0x80;	//0xa4;   // 36 basic
	mib_StaCfg->OpRateSet[5] = 18;
	mib_StaCfg->OpRateSet[6] = 24 | 0x80;
	mib_StaCfg->OpRateSet[7] = 36;
	mib_StaCfg->OpRateSet[8] = 48 | 0x80;
	mib_StaCfg->OpRateSet[9] = 72;
	mib_StaCfg->OpRateSet[10] = 96;
	mib_StaCfg->OpRateSet[11] = 108;
	mib_StaCfg->OpRateSet[12] = 0;
	mib_StaCfg->OpRateSet[13] = 0;
#endif

#ifdef IEEE80211H
	mib_SpectrumMagament_p->spectrumManagement = 0;
	mib_SpectrumMagament_p->csaChannelNumber = 0;
	mib_SpectrumMagament_p->csaCount = 20;
	mib_SpectrumMagament_p->csaMode = 1;
	mib_SpectrumMagament_p->powerConstraint = 3;	/* default value is 3 dB */
	mib_SpectrumMagament_p->countryCode = 0x10;	/* FCC */
	mib_SpectrumMagament_p->multiDomainCapability = 0;
	mib_SpectrumMagament_p->powerCapabilityMax = 0;
	mib_SpectrumMagament_p->powerCapabilityMin = -100;
#endif /* IEEE80211H */

	mib_StaCfg->mib_preAmble = PREAMBLE_AUTO_SELECT;	//Default, auto

	/* Default Mac address, need to add read from flash. */
	mib_OpData->StaMacAddr[0] = addr[0];
	mib_OpData->StaMacAddr[1] = addr[1];
	mib_OpData->StaMacAddr[2] = addr[2];
	mib_OpData->StaMacAddr[3] = addr[3];
	mib_OpData->StaMacAddr[4] = addr[4];
	mib_OpData->StaMacAddr[5] = addr[5];

	/* Copy SSID including NULL character terminator */
	sprintf(ssid, OEMSSID, phyMacId, vMacId);
	util_CopyList(mib_StaCfg->DesiredSsId, ssid, IEEEtypes_SSID_SIZE);

	mib_OpData->MaxRxLife = 0x200;

	mib_OpData->MaxTxMsduLife = 0x200;

#ifdef SOC_W906X
	*(mib->mib_RtsThresh) = 0xFFFF;
#else
	*(mib->mib_RtsThresh) = 0x92B;
#endif /* SOC_W906X */
	mib_OpData->ShortRetryLim = 0x07;
	mib_OpData->LongRetryLim = 0x04;
	mib_OpData->FragThresh = 0x2300;
#ifdef ENABLE_WEP
	mib->Privacy->PrivInvoked = TRUE;
#else
	mib->Privacy->PrivInvoked = FALSE;
#endif
	mib->WepDefaultKeys[0].WepDefaultKeyIdx = 1;
	memcpy(mib->WepDefaultKeys[0].WepDefaultKeyValue, "ABCDEFGHIJKLM", 13);
	mib->WepDefaultKeys[1].WepDefaultKeyIdx = 2;
	memcpy(mib->WepDefaultKeys[1].WepDefaultKeyValue, "NOPQRSTUVWXYZ", 13);
	mib->WepDefaultKeys[2].WepDefaultKeyIdx = 3;
	memcpy(mib->WepDefaultKeys[2].WepDefaultKeyValue, "abcdefghijklm", 13);
	mib->WepDefaultKeys[3].WepDefaultKeyIdx = 4;
	memcpy(mib->WepDefaultKeys[3].WepDefaultKeyValue, "nopqrstuvwxyz", 13);

	mib->RSNConfig->Version = 0x0100;
	mib->RSNConfig->PairwiseKeysSupported = 256;
	mib->RSNConfig->MulticastCipher[0] = 0x00;
	mib->RSNConfig->MulticastCipher[1] = 0x50;
	mib->RSNConfig->MulticastCipher[2] = 0xF2;
	mib->RSNConfig->MulticastCipher[3] = 0x02;
	mib->RSNConfig->GroupRekeyMethod = 2;
	mib->RSNConfig->GroupRekeyTime = 24 * 60 * 60; /*once per day */ ;
	strcpy(mib->RSNConfig->PSKValue, "12345678901234567890123456789012");
	strcpy(mib->RSNConfig->PSKPassPhrase, "12345678");
	mib->RSNConfig->TSNEnabled = TRUE;
	mib->RSNConfig->GroupMasterRekeyTime = 7 * 24 * 60 * 60;	/*once per week */
	mib->RSNConfig->GroupUpdateTimeOut = 100;	/*100 ms */
	mib->RSNConfig->GroupUpdateCount = 3;	/*number of retries */
	mib->RSNConfig->PairwiseUpdateTimeOut = 100;
	mib->RSNConfig->PairwiseUpdateCount = 3;

	mib->UnicastCiphers->UnicastCipher[0] = 0x00;
	mib->UnicastCiphers->UnicastCipher[1] = 0x50;
	mib->UnicastCiphers->UnicastCipher[2] = 0xF2;
	mib->UnicastCiphers->UnicastCipher[3] = 0x02;
	mib->UnicastCiphers->Enabled = TRUE;

	mib->RSNConfigAuthSuites->AuthSuites[0] = 0x00;
	mib->RSNConfigAuthSuites->AuthSuites[1] = 0x50;
	mib->RSNConfigAuthSuites->AuthSuites[2] = 0xF2;
	mib->RSNConfigAuthSuites->AuthSuites[3] = 0x02;
	mib->RSNConfigAuthSuites->Enabled = TRUE;

#ifdef AP_WPA2
	mib->RSNConfigWPA2->Version = 0x0100;
	mib->RSNConfigWPA2->PairwiseKeysSupported = 256;
	mib->RSNConfigWPA2->MulticastCipher[0] = 0x00;
	mib->RSNConfigWPA2->MulticastCipher[1] = 0x0F;
	mib->RSNConfigWPA2->MulticastCipher[2] = 0xAC;
	mib->RSNConfigWPA2->MulticastCipher[3] = 0x04;
	mib->RSNConfigWPA2->GroupRekeyMethod = 2;
	mib->RSNConfigWPA2->GroupRekeyTime = 24 * 60 * 60; /*once per day */ ;
	strcpy(mib->RSNConfigWPA2->PSKValue,
	       "12345678901234567890123456789012");
	strcpy(mib->RSNConfigWPA2->PSKPassPhrase, "12345678");
	mib->RSNConfigWPA2->TSNEnabled = TRUE;
	mib->RSNConfigWPA2->GroupMasterRekeyTime = 7 * 24 * 60 * 60;	/*once per week */
	mib->RSNConfigWPA2->GroupUpdateTimeOut = 100;	/*100 ms */
	mib->RSNConfigWPA2->GroupUpdateCount = 3;	/*number of retries */
	mib->RSNConfigWPA2->PairwiseUpdateTimeOut = 100;
	mib->RSNConfigWPA2->PairwiseUpdateCount = 3;
	mib->RSNConfigWPA2->WPA2Enabled = 0;
	mib->RSNConfigWPA2->WPA2OnlyEnabled = 0;
	mib->RSNConfigWPA2->WPA2PreAuthEnabled = 0;

	mib->WPA2UnicastCiphers->UnicastCipher[0] = 0x00;
	mib->WPA2UnicastCiphers->UnicastCipher[1] = 0x0F;
	mib->WPA2UnicastCiphers->UnicastCipher[2] = 0xAC;
	mib->WPA2UnicastCiphers->UnicastCipher[3] = 0x04;
	mib->WPA2UnicastCiphers->Enabled = TRUE;

	mib->WPA2UnicastCiphers2->UnicastCipher[0] = 0x00;
	mib->WPA2UnicastCiphers2->UnicastCipher[1] = 0x0F;
	mib->WPA2UnicastCiphers2->UnicastCipher[2] = 0xAC;
	mib->WPA2UnicastCiphers2->UnicastCipher[3] = 0x04;
	mib->WPA2UnicastCiphers2->Enabled = TRUE;

	mib->WPA2AuthSuites->AuthSuites[0] = 0x00;
	mib->WPA2AuthSuites->AuthSuites[1] = 0x0F;
	mib->WPA2AuthSuites->AuthSuites[2] = 0xAC;
	mib->WPA2AuthSuites->AuthSuites[3] = 0x02;
	mib->WPA2AuthSuites->Enabled = TRUE;

	if (mib->Privacy->RSNEnabled && !mib->RSNConfigWPA2->WPA2Enabled &&
	    !mib->RSNConfigWPA2->WPA2OnlyEnabled) {
		mib->RSNConfig->MulticastCipher[3] = 0x02;	// TKIP=2; CCMP=4
		mib->UnicastCiphers->UnicastCipher[3] = 0x02;	// TKIP=2; CCMP=4
	} else if (mib->RSNConfigWPA2->WPA2Enabled &&
		   !mib->RSNConfigWPA2->WPA2OnlyEnabled) {
		mib->RSNConfig->MulticastCipher[3] = 0x02;	// TKIP=2; CCMP=4
		mib->UnicastCiphers->UnicastCipher[3] = 0x02;	// TKIP=2; CCMP=4

		mib->RSNConfigWPA2->MulticastCipher[3] = 0x02;	// TKIP=2; CCMP=4
		mib->WPA2UnicastCiphers->UnicastCipher[3] = 0x04;	// TKIP=2; CCMP=4
		mib->WPA2UnicastCiphers2->UnicastCipher[3] = 0x02;	// TKIP=2; CCMP=4
	} else if (mib->RSNConfigWPA2->WPA2OnlyEnabled) {
		mib->RSNConfigWPA2->MulticastCipher[3] = 0x04;	// TKIP=2; CCMP=4
		mib->WPA2UnicastCiphers->UnicastCipher[3] = 0x04;	// TKIP=2; CCMP=4
		mib->WPA2UnicastCiphers2->UnicastCipher[3] = 0x04;	// TKIP=2; CCMP=4
	}

	*(mibSystem_p->mib_WPAPSKValueEnabled) = 0;	//PSK_VALUE_TEST
	*(mibSystem_p->mib_WPA2PSKValueEnabled) = 0;	//PSK_VALUE_TEST

#endif
	mib->Privacy->RSNEnabled = FALSE;
	mib->Privacy->ApiUpdateWpa = FALSE;
	mib->Privacy->RSNLinkStatus = FALSE;
	mib->RSNConfig->Version = 0x0100;
	mib->RSNConfig->PairwiseKeysSupported = 256;	//???
	mib->RSNConfig->MulticastCipher[0] = 0x00;
	mib->RSNConfig->MulticastCipher[1] = 0x50;
	mib->RSNConfig->MulticastCipher[2] = 0xF2;
	mib->RSNConfig->MulticastCipher[3] = 0x02;	// TKIP
	mib->RSNConfig->GroupRekeyMethod = 2;	// time-based, once per day
	mib->RSNConfig->GroupRekeyTime = 24 * 60 * 60;	// once per day
	mib->RSNConfig->TSNEnabled = TRUE;
	mib->RSNConfig->GroupMasterRekeyTime = 7 * 86400;	//once per week
	mib->RSNConfig->GroupUpdateTimeOut = 100;	// 100 ms
	mib->RSNConfig->GroupUpdateCount = 3;	// number of retrys
	mib->RSNConfig->PairwiseUpdateTimeOut = 100;
	mib->RSNConfig->PairwiseUpdateCount = 3;

	mib->UnicastCiphers->UnicastCipher[0] = 0x00;
	mib->UnicastCiphers->UnicastCipher[1] = 0x50;
	mib->UnicastCiphers->UnicastCipher[2] = 0xF2;
	mib->UnicastCiphers->UnicastCipher[3] = 0x02;	// TKIP
	mib->UnicastCiphers->Enabled = TRUE;

	mib->RSNConfigAuthSuites->AuthSuites[0] = 0x00;
	mib->RSNConfigAuthSuites->AuthSuites[1] = 0x50;
	mib->RSNConfigAuthSuites->AuthSuites[2] = 0xF2;
	mib->RSNConfigAuthSuites->AuthSuites[3] = 0x02;	// Pre-shared key
	mib->RSNConfigAuthSuites->Enabled = TRUE;
	*(mib->mib_intraBSS) = 1;

	*(mib->mib_wmmAckPolicy) = 0;	// Auto
	*(mib->mib_guardInterval) = 0;	// Auto
	*(mib->mib_extSubCh) = 0;	// Auto
	*(mib->mib_agingtime) = 120 * 60;	//change from 3 mins to 2 hrs
	*(mib->mib_PadAndSnap) = TRUE;
	*(mib->mib_autochannel) = 0;	// 1:scan default 2:scan by ChannelList
	*(mib->mib_MaxTxPwr) = 0xff;
	*(mib->mib_rxAntenna) = 0;	/* 0:ABC(Auto), 1:A, 5:B, 4:C 2:AB, 3:ABC */
	*(mib->mib_rxAntBitmap) = 0;
	*(mib->mib_txAntenna) = 0;	/* this is bitmap: 0:AB(Auto), 1:A, 2:B */
#ifdef SOC_W906X
	*(mib->mib_CDD) = 0x1f;
#else
	*(mib->mib_CDD) = 0x13;
#endif
	*(mib->mib_acs_threshold) = 0;	//100000;
	*(mib->mib_htProtect) = 0;	// Disable/off
	*(mib->mib_ampdu_factor) = 3;	//0~3
	*(mib->mib_ampdu_density) = 5;	//change density to 4usec from 16usec 
	*(mib->mib_amsdutx) = 1;
	*(mib->mib_amsdu_maxsize) = 3300;
	*(mib->mib_amsdu_allowsize) = 1540;
	*(mib->mib_amsdu_flushtime) = 500;
#ifdef SOC_W906X
	*(mib->mib_amsdu_pktcnt) = 28;
#else
	*(mib->mib_amsdu_pktcnt) = 10;
#endif
	*(mib->mib_maxsta) = sta_num;
	*(mib->mib_consectxfaillimit) = CONSECTXFAILLIMIT;
#ifdef INTEROP
	*(mib->mib_interop) = 0;
#endif
	*(mib->mib_optlevel) = 1;
#ifdef PWRFRAC
	*(mib->mib_TxPwrFraction) = 0x0;	// 0:Max, 1:75%, 2:50%, 3:25%, 10:Min
#endif
	*(mib->mib_RateAdaptMode) = 0;	// 0:Indoor, 1:Outdoor
	*(mib->mib_CSMode) = LINKADAPT_CS_ADAPT_STATE_CONSERV;	// 0:CONSERV, 1:AGGR, 2:AUTO_ENABLED,3:AUTO_DISABLED  
#ifdef QOS_FEATURE
#ifdef SOC_W906X
	*(mib->QoSOptImpl) = TRUE;	//QoSOptionImplemented. Will be set through GUI
	*(mib->mib_rx_enable) = 0;
	*(mib->mib_heldpc_enable) = 1;
	*(mib->mib_mbssid) = 0;	//default disable mbssid for ax mode.
	*(mib->mib_superBA) = 0;	//default disable superBA
	*(mib->mib_BAReorder_holdtime) = MAX_REORDERING_HOLD_TIME;
#ifdef AP_TWT
	*(mib->he_twt_activated) = 1;	//default enable twt for ax mode.
#endif
#ifdef WLS_FTM_SUPPORT
	*(mib->wls_ftm_enable) = 0;	//default disable wls_ftm.
#endif
	*(mib->he_mu_bf) = 1;	//default enable MU BF for ax mode.
#else
	*(mib->QoSOptImpl) = FALSE;	//QoSOptionImplemented. Will be set through GUI
#endif
	mib_StaCfg->BlckAckOptImpl = FALSE;	//BlockAckOptionImplemented
	mib_StaCfg->DirectOptImpl = FALSE;	//DirectOptionimplemented
	mib_StaCfg->APSDOptImpl = FALSE;	//APSDOptionImplemented
	mib_StaCfg->QAckOptImpl = FALSE;	//QAckOptionImplemented
	mib_StaCfg->QBSSLoadOptImpl = FALSE;	//QBSSLoadOptionImplemented
	mib_StaCfg->QReqOptImpl = TRUE;	//QueueRequestOptionimplemented
	mib_StaCfg->TXOPReqOptImpl = TRUE;	//TXOPOptionImplemented
	mib_StaCfg->MoreDataAckOptImpl = FALSE;	//MoreDataAckOptionImplemented
	mib_StaCfg->AssocinNQBSS = TRUE;	//AssociateInNQBSS
#ifdef QOS_WSM_FEATURE
	mib_StaCfg->WSMQoSOptImpl = TRUE;	//WSM Implemented
#endif //QOS_WSM_FEATURE
#endif
#ifdef IEEE80211H
	mib_StaCfg->SpectrumManagementImplemented = TRUE;
	mib_StaCfg->SpectrumManagementRequired = FALSE;
#endif /* IEEE80211H */

#ifdef IEEE80211K
	*(mib->mib_rrm) = 0;
	*(mib->mib_quiet) = 0;
#endif

#ifdef AP_STEERING_SUPPORT
	mib->mib_BTM_rssi_low = 0;
	mib->mib_BTM_rssi_high = 0;
	mib->mib_btm_enabled = 0;
#endif
#ifdef MULTI_AP_SUPPORT
	mib->multi_ap_attr = 0;
	mib->multi_ap_ver = 0x02;
	mib->multi_ap_vid = 0;
#endif /* MULTI_AP_SUPPORT */
#ifdef MBO_SUPPORT
	mib->mib_mbo_enabled = 0;
	mib->mib_mbo_assoc_disallow = 0;
	mib->mib_mbo_wnm = 0;
	mib->Interworking = 0;
#endif /* MULTI_AP_SUPPORT */
	*(mibSystem_p->mib_broadcastssid) = TRUE;
	*(mibSystem_p->mib_defaultkeyindex) = 0;
	*(mibSystem_p->mib_strictWepShareKey) = 0;	//0:both, 1:share

	/* default in auto state */
	*(mibSystem_p->mib_txDataRate) = 3;
#ifdef CONFIG_MC_BC_RATE
	*(mibSystem_p->mib_mcDataRateInfo) = 0x0;
	*(mibSystem_p->mib_bcDataRateInfo) = 0x0;
#endif
	*(mibSystem_p->mib_forceProtectiondisable) = 1;
	*(mibSystem_p->mib_enableFixedRateTx) = 0;
	*(mibSystem_p->mib_FixedRateTxType) = 1;
	*(mibSystem_p->mib_txDataRateG) = 11;	/* Register index of the G rate, 54 M default */
	*(mibSystem_p->mib_txDataRateA) = 11;
	*(mibSystem_p->mib_txDataRateN) = 15;
	*(mibSystem_p->mib_txDataRateVHT) = 0x28;	/* 3 streams MCS8 */
	*(mibSystem_p->mib_txDataRateInfo) = 0x0F4F2962;	//Rateinfo, 2:VHT, 6:SGI & 80M, 9:MCS9, 2:Nss3
	*(mibSystem_p->mib_MulticastRate) = 2;	/* 1 Mbps */
	*(mibSystem_p->mib_MultiRateTxType) = 0;	/* G rate */
	*(mibSystem_p->mib_ManagementRate) = 2;	/* 1 Mbps */
	*(mibSystem_p->mib_ApMode) = AP_MODE_5GHZ_Nand11AC;
	*(mibSystem_p->mib_BcnPeriod) = 100;

#ifdef BRS_SUPPORT
	wlset_rateSupport(mibSystem_p);
#endif

#ifdef WDS_FEATURE
	*(mib->mib_wdsEnable) = WDS_MODE_DISABLE;
#endif
	*(mib->mib_disableAssoc) = FALSE;
	*(mib->mib_AmpduTx) = 0;	//0: Disable, 1: Auto, 2: Manual 
#ifdef DYNAMIC_BA_SUPPORT
	*(mib->mib_ampdu_bamgmt) = 0;

	*(mib->mib_ampdu_mintraffic[WME_AC_BK]) = 128;
	*(mib->mib_ampdu_mintraffic[WME_AC_BE]) = 0;	//64;
	*(mib->mib_ampdu_mintraffic[WME_AC_VO]) = 32;
	*(mib->mib_ampdu_mintraffic[WME_AC_VI]) = 32;

	*(mib->mib_ampdu_low_AC_thres[WME_AC_BK]) = 100;
	*(mib->mib_ampdu_low_AC_thres[WME_AC_BE]) = 50;
	*(mib->mib_ampdu_low_AC_thres[WME_AC_VO]) = 25;
	*(mib->mib_ampdu_low_AC_thres[WME_AC_VI]) = 25;
#endif

#ifdef COEXIST_20_40_SUPPORT
	*(mib->mib_Channel_Width_Trigger_Scan_Interval) = 180;/** default is actually 300 */
	*(mib->mib_Channel_Transition_Delay_Factor) = 5;
#endif

#ifdef QOS_FEATURE

	/* ACI is mapped to the index of the table */
	//Initializing the EDCA parameters.
	mib_QAPEDCATable[0].QAPEDCATblIndx = 1;
	mib_QAPEDCATable[0].QAPEDCATblCWmin = 12;	//BE_CWMIN;
	mib_QAPEDCATable[0].QAPEDCATblCWmax = 17;	//(4 * (BE_CWMIN +1))-1; //WL_REGS32(TX_CW0_MAX);
	mib_QAPEDCATable[0].QAPEDCATblAIFSN = 2;	//AIFSN_BE; 
	mib_QAPEDCATable[0].QAPEDCATblTXOPLimit = TXOP_LIMIT_BE;
	mib_QAPEDCATable[0].QAPEDCATblTXOPLimitBAP = TXOP_LIMIT_BE_BAP;

	//    mib_QAPEDCATable[0].QAPEDCATblMSDULifeTime = MSDU_LIFETIME;
	mib_QAPEDCATable[0].QAPEDCATblMandatory = ADMISSION_CONTROL;	//Admission Control not Mandatory

	//Initializing the EDCA parameters.
	mib_QAPEDCATable[1].QAPEDCATblIndx = 2;
	mib_QAPEDCATable[1].QAPEDCATblCWmin = BE_CWMIN;
	mib_QAPEDCATable[1].QAPEDCATblCWmax = BE_CWMAX;
	mib_QAPEDCATable[1].QAPEDCATblAIFSN = AIFSN_BK;
	mib_QAPEDCATable[1].QAPEDCATblTXOPLimit = TXOP_LIMIT_BK;
	mib_QAPEDCATable[1].QAPEDCATblTXOPLimitBAP = TXOP_LIMIT_BK_BAP;

	//    mib_QAPEDCATable[1].QAPEDCATblMSDULifeTime = MSDU_LIFETIME;
	mib_QAPEDCATable[1].QAPEDCATblMandatory = ADMISSION_CONTROL;	//Admission Control not Mandatory

	//Initializing the EDCA parameters.
	mib_QAPEDCATable[2].QAPEDCATblIndx = 3;
	mib_QAPEDCATable[2].QAPEDCATblCWmin = (BE_CWMIN >= 2) ?
		((BE_CWMIN + 1) >> 1) - 1 : 0;
	mib_QAPEDCATable[2].QAPEDCATblCWmax = BE_CWMIN;
	mib_QAPEDCATable[2].QAPEDCATblAIFSN = AIFSN_VI;
	mib_QAPEDCATable[2].QAPEDCATblTXOPLimit = TXOP_LIMIT_VI;
	mib_QAPEDCATable[2].QAPEDCATblTXOPLimitBAP = TXOP_LIMIT_VI_BAP;

	//    mib_QAPEDCATable[2].QAPEDCATblMSDULifeTime = MSDU_LIFETIME;
	mib_QAPEDCATable[2].QAPEDCATblMandatory = ADMISSION_CONTROL;	//Admission Control not Mandatory

	//Initializing the EDCA parameters.
	mib_QAPEDCATable[3].QAPEDCATblIndx = 4;
	mib_QAPEDCATable[3].QAPEDCATblCWmin = (BE_CWMIN >= 4) ?
		((BE_CWMIN + 1) >> 2) - 1 : 0;
	mib_QAPEDCATable[3].QAPEDCATblCWmax = (BE_CWMIN >= 2) ?
		((BE_CWMIN + 1) >> 1) - 1 : 1;
	mib_QAPEDCATable[3].QAPEDCATblAIFSN = AIFSN_VO;
	mib_QAPEDCATable[3].QAPEDCATblTXOPLimit = TXOP_LIMIT_VO;
	mib_QAPEDCATable[3].QAPEDCATblTXOPLimitBAP = TXOP_LIMIT_VO_BAP;

	//    mib_QAPEDCATable[3].QAPEDCATblMSDULifeTime = MSDU_LIFETIME;
	mib_QAPEDCATable[3].QAPEDCATblMandatory = ADMISSION_CONTROL;	//Admission Control not Mandatory

	//Sta EDCA Parameters Update
	//Initializing the EDCA parameters.
	/* ACI is mapped to the index of the table */
	mib_QStaEDCATable[0].QStaEDCATblIndx = 1;
	mib_QStaEDCATable[0].QStaEDCATblCWmin = BE_CWMIN;
	mib_QStaEDCATable[0].QStaEDCATblCWmax = BE_CWMAX;	//WL_REGS32(TX_CW0_MAX);
	mib_QStaEDCATable[0].QStaEDCATblAIFSN = AIFSN_BE;
	mib_QStaEDCATable[0].QStaEDCATblTXOPLimit = TXOP_LIMIT_BE;
	mib_QStaEDCATable[0].QStaEDCATblTXOPLimitBSta = TXOP_LIMIT_BE_BAP;

	mib_QStaEDCATable[0].QStaEDCATblMandatory = ADMISSION_CONTROL;

	//Initializing the EDCA parameters.
	mib_QStaEDCATable[1].QStaEDCATblIndx = 2;
	mib_QStaEDCATable[1].QStaEDCATblCWmin = BE_CWMIN;
	mib_QStaEDCATable[1].QStaEDCATblCWmax = BE_CWMAX;	//(4 * (BE_CWMIN +1))-1 ;
	mib_QStaEDCATable[1].QStaEDCATblAIFSN = AIFSN_BK;
	mib_QStaEDCATable[1].QStaEDCATblTXOPLimit = TXOP_LIMIT_BK;
	mib_QStaEDCATable[1].QStaEDCATblTXOPLimitBSta = TXOP_LIMIT_BK_BAP;

	mib_QStaEDCATable[1].QStaEDCATblMandatory = ADMISSION_CONTROL;

	//Initializing the EDCA parameters.
	mib_QStaEDCATable[2].QStaEDCATblIndx = 3;
	mib_QStaEDCATable[2].QStaEDCATblCWmin = (BE_CWMIN >= 2) ?
		((BE_CWMIN + 1) >> 1) - 1 : 0;
	mib_QStaEDCATable[2].QStaEDCATblCWmax = BE_CWMIN;
	mib_QStaEDCATable[2].QStaEDCATblAIFSN = AIFSN_VI + 1;
	mib_QStaEDCATable[2].QStaEDCATblTXOPLimit = TXOP_LIMIT_VI;
	mib_QStaEDCATable[2].QStaEDCATblTXOPLimitBSta = TXOP_LIMIT_VI_BAP;

	mib_QStaEDCATable[2].QStaEDCATblMandatory = ADMISSION_CONTROL;

	//Initializing the EDCA parameters.
	mib_QStaEDCATable[3].QStaEDCATblIndx = 4;
	mib_QStaEDCATable[3].QStaEDCATblCWmin = (BE_CWMIN >= 4) ?
		((BE_CWMIN + 1) >> 2) - 1 : 0;
	mib_QStaEDCATable[3].QStaEDCATblCWmax = (BE_CWMIN >= 2) ?
		((BE_CWMIN + 1) >> 1) - 1 : 1;
	mib_QStaEDCATable[3].QStaEDCATblAIFSN = AIFSN_VO + 1;
	mib_QStaEDCATable[3].QStaEDCATblTXOPLimit = TXOP_LIMIT_VO;
	mib_QStaEDCATable[3].QStaEDCATblTXOPLimitBSta = TXOP_LIMIT_VO_BAP;
	mib_QStaEDCATable[3].QStaEDCATblMandatory = ADMISSION_CONTROL;

#endif //QOS_FEATURE

#ifdef JAPAN_CHANNEL_SPACING_10_SUPPORT
	mib_channelspacing = 20;
#endif

#ifdef CLIENT_SUPPORT
	// default to CLIENT_MODE_DISABLE in order for AP auto channel to work.
	// there is a checking in SetupScan prevents autochannel functionality
	*(mibSystem_p->mib_STAMode) = CLIENT_MODE_DISABLE;
	*(mibSystem_p->mib_STAAutoScan) = 1;
	*(mibSystem_p->mib_STAMacCloneEnable) = 0;
#endif

#ifdef MPRXY
	*(mib->mib_MCastPrxy) = 0;	/*Disable */
	memset((char *)mib->mib_IPMcastGrpTbl[0], 0, (sizeof(MIB_IPMCAST_GRP_TBL) * MAX_MULTICAST_ADDRESS));	//Initialize to 0
#ifdef MPRXY_IGMP_QUERY
	/* Reserve the 1st entry for all hosts 224.0.0.1 */
	mib->mib_IPMcastGrpTbl[0]->mib_McastIPAddr = 0xE0000001;
	/* Set the counter for IPM groups to 1 */
	*(mib->mib_IPMcastGrpCount) = 1;
#endif
#endif	 /*MPRXY*/
		*(mib->mib_rifsQNum) = 0;
	*(mib->mib_regionCode) = DOMAIN_CODE_FCC;
#if defined ( INTOLERANT40)  || defined (COEXIST_20_40_SUPPORT)
	{
		if ((PhyDSSSTable->Chanflag.ChnlWidth == CH_AUTO_WIDTH) || (PhyDSSSTable->Chanflag.ChnlWidth == CH_160_MHz_WIDTH) || (PhyDSSSTable->Chanflag.ChnlWidth == CH_40_MHz_WIDTH) || (PhyDSSSTable->Chanflag.ChnlWidth == CH_80_MHz_WIDTH)) {	// TODO: Figure out if need a second USER_ChnlWidth for 80+80Mhz
			if (PhyDSSSTable->CurrChan == 14)
				*(mib->USER_ChnlWidth) = 0;
			else
				*(mib->USER_ChnlWidth) = 1;
		}
	}

	*(mib->mib_HT40MIntoler) = 1;	// 0:Disable
#endif
#ifdef RXPATHOPT
	*(mib->mib_RxPathOpt) = 100;
#endif
	*(mib->mib_HtGreenField) = 0;	//0: Disable, 1:enable 
	//currently, W8366 supports stbc. 
	*(mib->mib_HtStbc) = 0;	//0: Disable, 1:enable          
	*(mib->mib_3x3Rate) = 1;	//0: Disable, 1:enable
	hal_InitApMIB(mib);
#ifdef MRVL_DFS
	mib->mib_CACTimeOut = &wlanmib[shadow]->mib_CACTimeOut[phyMacId];
	mib->mib_NOPTimeOut = &wlanmib[shadow]->mib_NOPTimeOut[phyMacId];
	*(mib->mib_CACTimeOut) = 60;	// 60 seconds
	mib->mib_ETSICACTimeOut =
		&wlanmib[shadow]->mib_ETSICACTimeOut[phyMacId];
	*(mib->mib_ETSICACTimeOut) = 600;	// 600 seconds
	*(mib->mib_NOPTimeOut) = 1800;	// 1800 seconds
#endif
	*(mib->mib_RptrMode) = 0;	/* 0: Disable, 1:enable */
	memset(mib->mib_RptrDeviceType, 0, MAXRPTRDEVTYPESTR);
	*(mib->mib_agingtimeRptr) = 3 * 60;	//3 min
	*(mib->mib_bftype) = 6;	 /** auto bf **/
	*(mib->mib_bfmee) = 0;	 /** disabled **/
#ifdef SOC_W8964
	*(mib->disable_aggr_for_vo) = 0;
#endif
	*(mib->enable_arp_for_vo) = 0;
	*(mib->disable_qosctl) = 0;
	*(mib->mib_bwSignaltype) = 0;
	*(mib->mib_weakiv_threshold) = 1;	/* alert for every weakiv attack */
#ifdef WTP_SUPPORT
	mib->mib_wtp_cfg->wtp_enabled = 0;	//defalt disable;
	mib->mib_wtp_cfg->mac_mode = WTP_MAC_MODE_LOCALMAC;
	mib->mib_wtp_cfg->frame_tunnel_mode = WTP_TUNNEL_MODE_NATIVE_80211;
#endif
#ifdef SOC_W906X
	mib_StaCfg->SupportedTxVhtMcsSet = MAX_TX_VHT_MCS_SET & 0x0000ffff;	/* Default */
#ifdef SUPPORTED_EXT_NSS_BW
	mib_StaCfg->SupportedTxVhtMcsSet |= (VHT_EXTENDED_NSS_BW_CAPABLE_BIT);	//Default, enable Extended Nss Bw capability
#endif
	mib_StaCfg->supoorted_tx_he_80m_mcs_set = SC5_HE_TX_80M_MCS_SET;
	mib_StaCfg->supoorted_tx_he_160m_mcs_set = SC5_HE_TX_160M_MCS_SET;
	mib_StaCfg->supoorted_tx_he_80p80m_mcs_set = SC5_HE_TX_80MP80M_MCS_SET;
	mib_StaCfg->supoorted_rx_he_80m_mcs_set = SC5_HE_RX_80M_MCS_SET;
	mib_StaCfg->supoorted_rx_he_160m_mcs_set = SC5_HE_RX_160M_MCS_SET;
	mib_StaCfg->supoorted_rx_he_80p80m_mcs_set = SC5_HE_RX_80MP80M_MCS_SET;
#else
#ifdef SUPPORTED_EXT_NSS_BW
	mib_StaCfg->SupportedTxVhtMcsSet = 0xffea | (VHT_EXTENDED_NSS_BW_CAPABLE_BIT);	//Default, enable Extended Nss Bw capability
#else
	mib_StaCfg->SupportedTxVhtMcsSet = 0xffea;	//Default
#endif
#endif /* #ifdef SOC_W906X */

	//0:disable, 1:enable
#ifdef MRVL_MUG_ENABLE
	// Disable the auto MU-MIMO mgmt when using dyanmic MU grouping
	*(mib->mib_mumimo_mgmt) = 0;
#else
#ifdef SOC_W906X
	//default disable auto grp for now
	*(mib->mib_mumimo_mgmt) = 0;	//0:disable, 1:enable
#else
	*(mib->mib_mumimo_mgmt) = 1;
#endif
#endif //MRVL_MUG_ENABLE

	mib_StaCfg->bss_color = 1;

	mib_StaCfg->SupportedTxHtMCScfg.SupportedTxHtMCSset_0 = 0xff;
	mib_StaCfg->SupportedTxHtMCScfg.SupportedTxHtMCSset_1 = 0xff;
	mib_StaCfg->SupportedTxHtMCScfg.SupportedTxHtMCSset_2 = 0xff;
#ifdef SOC_W906X
	mib_StaCfg->SupportedTxHtMCScfg.SupportedTxHtMCSset_3 = 0xff;
#endif
	*(mib->mib_mu_bfmer) = 1;	//enable
	*(mib->mib_mu_bfmee) = 0;	//disable
#ifdef AP_STEERING_SUPPORT
	mib->mib_btm_enabled =
		&wlanmib[shadow]->mib_btm_enabled[phyMacId][vMacId];
	*(mib->mib_btm_enabled) = 1;	//enable
#endif /* AP_STEERING_SUPPORT */
#ifdef BAND_STEERING
	mib->mib_bandsteer = &wlanmib[shadow]->mib_bandsteer[phyMacId];
	mib->mib_bandsteer_handler =
		&wlanmib[shadow]->mib_bandsteer_handler[phyMacId];
	mib->mib_bandsteer_mode =
		&wlanmib[shadow]->mib_bandsteer_mode[phyMacId];
	mib->mib_bandsteer_timer_interval =
		&wlanmib[shadow]->mib_bandsteer_timer_interval[phyMacId];
	mib->mib_bandsteer_rssi_threshold =
		&wlanmib[shadow]->mib_bandsteer_rssi_threshold[phyMacId];
	mib->mib_bandsteer_sta_track_max_num =
		&wlanmib[shadow]->mib_bandsteer_sta_track_max_num[phyMacId];
	mib->mib_bandsteer_sta_track_max_age =
		&wlanmib[shadow]->mib_bandsteer_sta_track_max_age[phyMacId];
	mib->mib_bandsteer_sta_auth_retry_cnt =
		&wlanmib[shadow]->mib_bandsteer_sta_auth_retry_cnt[phyMacId];
	*(mib->mib_bandsteer) = 0;	//disable
	*(mib->mib_bandsteer_handler) = BAND_STEERING_HDL_BY_DRV;
	*(mib->mib_bandsteer_mode) = BAND_STEERING_MODE_FROM_2_4G_TO_5G;
	*(mib->mib_bandsteer_timer_interval) = (200 * HZ + 500) / 1000;	/* 200ms */
	*(mib->mib_bandsteer_rssi_threshold) = 100;
	*(mib->mib_bandsteer_sta_track_max_num) = 0;
	*(mib->mib_bandsteer_sta_track_max_age) = 120 * HZ;	/* 120s */
	*(mib->mib_bandsteer_sta_auth_retry_cnt) = 3;
#endif /* BAND_STEERING */
#ifdef MULTI_AP_SUPPORT
	mib->mib_unassocsta_track_enabled =
		&wlanmib[shadow]->mib_unassocsta_track_enabled[phyMacId];
	mib->mib_unassocsta_track_max_num =
		&wlanmib[shadow]->mib_unassocsta_track_max_num[phyMacId];
	mib->mib_unassocsta_track_max_age =
		&wlanmib[shadow]->mib_unassocsta_track_max_age[phyMacId];
	mib->mib_unassocsta_track_time =
		&wlanmib[shadow]->mib_unassocsta_track_max_age[phyMacId];
	*(mib->mib_unassocsta_track_enabled) = 0;
	*(mib->mib_unassocsta_track_max_num) = sta_num;
	*(mib->mib_unassocsta_track_max_age) = 120 * HZ;	/* 120s */
	*(mib->mib_unassocsta_track_time) = 120;	/* 120ms */
#endif /* MULTI_AP_SUPPORT */
#ifdef DOT11V_DMS
	mib->mib_dms = &wlanmib[shadow]->mib_dms[phyMacId][vMacId];
	*(mib->mib_dms) = 1;	//default: enable
#endif
	mib->mib_reset_rate_mode =
		&wlanmib[shadow]->mib_reset_rate_mode[phyMacId][vMacId];
	*(mib->mib_reset_rate_mode) = 0;	//default: RSSI

	mib->mib_eap_rate_fixed =
		&wlanmib[shadow]->mib_eap_rate_fixed[phyMacId][vMacId];
	*(mib->mib_eap_rate_fixed) = 0;

	mib->mib_beamChange_disable =
		&wlanmib[shadow]->mib_beamChange_disable[phyMacId];
	*(mib->mib_beamChange_disable) = 1;

	mib->HEConfig = &wlanmib[shadow]->HEConfig[phyMacId];
	mib->HEConfig->pe_type = MIB_PE_TYPE_AGGRESSIVE;

	mib->mib_conf_capab =
		&wlanmib[shadow]->mib_conf_capab[phyMacId][vMacId];
	memset(mib->mib_conf_capab, 0, sizeof(mib_conf_capability));	// initial value
#ifdef AIRTIME_FAIRNESS
	*(mib->mib_atf_enable) = 0;	/* default disable ATF */
	*(mib->mib_atf_cfg_vi) = 100;
	*(mib->mib_atf_cfg_be) = 20;
	*(mib->mib_atf_cfg_bk) = 10;
	*(mib->mib_atf_cfg_airtime) = 10;
#endif /* AIRTIME_FAIRNESS */
	mib->he_rts_threshold = DEF_HE_RTS_THRESHOLD;

	mib->DL_ofdma_enable = TRUE;
	mib->DL_mimo_enable = TRUE;
	mib->UL_ofdma_enable = TRUE;
	mib->UL_mimo_enable = TRUE;
	return (TRUE);
}

void
mib_Update(void)
{
	memcpy(wlanmib[0], wlanmib[1], sizeof(struct MIB_s));
}

void
mib_Free(void)
{
	UINT8 i = 0;

	for (i = 0; i < 2; i++) {
		if (wlanmib[i]) {
			wl_vfree(wlanmib[i]);
			wlanmib[i] = NULL;
		}
	}
}
