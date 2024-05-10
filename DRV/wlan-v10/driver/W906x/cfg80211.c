/** @file cfg80211.c
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2006-2020 NXP
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

/* Description:  This file implements cfg80211 related functions. */

#include <linux/ctype.h>
#include "bcngen.h"
#include "mlmeApi.h"
#include "macmgmtap.h"
#include "keyMgmtSta.h"
#include "ap8xLnxIntf.h"
#include "ap8xLnxFwcmd.h"
#include "linkmgt.h"
#include "wlApi.h"
#include "cfg80211.h"
#include "ioctl_cfg80211.h"
#include "vendor.h"

extern extStaDb_StaInfo_t *macMgtStaDbInit(vmacApInfo_t * vmacSta_p,
					   IEEEtypes_MacAddr_t * staMacAddr,
					   IEEEtypes_MacAddr_t * apMacAddr);
extern void macMgmtRemoveSta(vmacApInfo_t * vmacSta_p,
			     extStaDb_StaInfo_t * StaInfo_p);

static struct ieee80211_channel mwl_channels_24[] = {
	{.band = NL80211_BAND_2GHZ,.center_freq = 2412,.hw_value = 1,},
	{.band = NL80211_BAND_2GHZ,.center_freq = 2417,.hw_value = 2,},
	{.band = NL80211_BAND_2GHZ,.center_freq = 2422,.hw_value = 3,},
	{.band = NL80211_BAND_2GHZ,.center_freq = 2427,.hw_value = 4,},
	{.band = NL80211_BAND_2GHZ,.center_freq = 2432,.hw_value = 5,},
	{.band = NL80211_BAND_2GHZ,.center_freq = 2437,.hw_value = 6,},
	{.band = NL80211_BAND_2GHZ,.center_freq = 2442,.hw_value = 7,},
	{.band = NL80211_BAND_2GHZ,.center_freq = 2447,.hw_value = 8,},
	{.band = NL80211_BAND_2GHZ,.center_freq = 2452,.hw_value = 9,},
	{.band = NL80211_BAND_2GHZ,.center_freq = 2457,.hw_value = 10,},
	{.band = NL80211_BAND_2GHZ,.center_freq = 2462,.hw_value = 11,},
	{.band = NL80211_BAND_2GHZ,.center_freq = 2467,.hw_value = 12,},
	{.band = NL80211_BAND_2GHZ,.center_freq = 2472,.hw_value = 13,},
	{.band = NL80211_BAND_2GHZ,.center_freq = 2484,.hw_value = 14,},
};

static struct ieee80211_rate mwl_rates_24[] = {
	{.bitrate = 10,.hw_value = 2,},
	{.bitrate = 20,.hw_value = 4,},
	{.bitrate = 55,.hw_value = 11,},
	{.bitrate = 110,.hw_value = 22,},
	{.bitrate = 220,.hw_value = 44,},
	{.bitrate = 60,.hw_value = 12,},
	{.bitrate = 90,.hw_value = 18,},
	{.bitrate = 120,.hw_value = 24,},
	{.bitrate = 180,.hw_value = 36,},
	{.bitrate = 240,.hw_value = 48,},
	{.bitrate = 360,.hw_value = 72,},
	{.bitrate = 480,.hw_value = 96,},
	{.bitrate = 540,.hw_value = 108,},
};

static struct ieee80211_supported_band mwl_band_24 = {
	.channels = mwl_channels_24,
	.n_channels = ARRAY_SIZE(mwl_channels_24),
	.bitrates = mwl_rates_24,
	.n_bitrates = ARRAY_SIZE(mwl_rates_24),
};

static struct ieee80211_channel mwl_channels_50[] = {
	{.band = NL80211_BAND_5GHZ,.center_freq = 5180,.hw_value = 36,},
	{.band = NL80211_BAND_5GHZ,.center_freq = 5200,.hw_value = 40,},
	{.band = NL80211_BAND_5GHZ,.center_freq = 5220,.hw_value = 44,},
	{.band = NL80211_BAND_5GHZ,.center_freq = 5240,.hw_value = 48,},
	{.band = NL80211_BAND_5GHZ,.center_freq = 5260,.hw_value = 52,},
	{.band = NL80211_BAND_5GHZ,.center_freq = 5280,.hw_value = 56,},
	{.band = NL80211_BAND_5GHZ,.center_freq = 5300,.hw_value = 60,},
	{.band = NL80211_BAND_5GHZ,.center_freq = 5320,.hw_value = 64,},
	{.band = NL80211_BAND_5GHZ,.center_freq = 5500,.hw_value = 100,},
	{.band = NL80211_BAND_5GHZ,.center_freq = 5520,.hw_value = 104,},
	{.band = NL80211_BAND_5GHZ,.center_freq = 5540,.hw_value = 108,},
	{.band = NL80211_BAND_5GHZ,.center_freq = 5560,.hw_value = 112,},
	{.band = NL80211_BAND_5GHZ,.center_freq = 5580,.hw_value = 116,},
	{.band = NL80211_BAND_5GHZ,.center_freq = 5600,.hw_value = 120,},
	{.band = NL80211_BAND_5GHZ,.center_freq = 5620,.hw_value = 124,},
	{.band = NL80211_BAND_5GHZ,.center_freq = 5640,.hw_value = 128,},
	{.band = NL80211_BAND_5GHZ,.center_freq = 5660,.hw_value = 132,},
	{.band = NL80211_BAND_5GHZ,.center_freq = 5680,.hw_value = 136,},
	{.band = NL80211_BAND_5GHZ,.center_freq = 5700,.hw_value = 140,},
	{.band = NL80211_BAND_5GHZ,.center_freq = 5720,.hw_value = 144,},
	{.band = NL80211_BAND_5GHZ,.center_freq = 5745,.hw_value = 149,},
	{.band = NL80211_BAND_5GHZ,.center_freq = 5765,.hw_value = 153,},
	{.band = NL80211_BAND_5GHZ,.center_freq = 5785,.hw_value = 157,},
	{.band = NL80211_BAND_5GHZ,.center_freq = 5805,.hw_value = 161,},
	{.band = NL80211_BAND_5GHZ,.center_freq = 5825,.hw_value = 165,},
};

static struct ieee80211_rate mwl_rates_50[] = {
	{.bitrate = 60,.hw_value = 12,},
	{.bitrate = 90,.hw_value = 18,},
	{.bitrate = 120,.hw_value = 24,},
	{.bitrate = 180,.hw_value = 36,},
	{.bitrate = 240,.hw_value = 48,},
	{.bitrate = 360,.hw_value = 72,},
	{.bitrate = 480,.hw_value = 96,},
	{.bitrate = 540,.hw_value = 108,},
};

static struct ieee80211_supported_band mwl_band_50 = {
	.channels = mwl_channels_50,
	.n_channels = ARRAY_SIZE(mwl_channels_50),
	.bitrates = mwl_rates_50,
	.n_bitrates = ARRAY_SIZE(mwl_rates_50),
};

static struct ieee80211_iface_limit ap_if_limits[] = {
	{.max = MAX_VMAC_INSTANCE_AP,.types = BIT(NL80211_IFTYPE_AP)},
	{.max = 1,.types = BIT(NL80211_IFTYPE_STATION)},
};

static struct ieee80211_iface_combination ap_if_comb = {
	.limits = ap_if_limits,
	.n_limits = ARRAY_SIZE(ap_if_limits),
	.max_interfaces = MAX_VMAC_INSTANCE_AP,
	.num_different_channels = 1,
	.radar_detect_widths = BIT(NL80211_CHAN_WIDTH_20_NOHT) |
		BIT(NL80211_CHAN_WIDTH_20) |
		BIT(NL80211_CHAN_WIDTH_40) |
		BIT(NL80211_CHAN_WIDTH_80) | BIT(NL80211_CHAN_WIDTH_160),
};

struct region_code_mapping {
	const char *alpha2;
	u32 region_code;
};

struct mwl_sta_capability {
	struct ieee80211_sta_ht_cap htcap;
	struct ieee80211_sta_vht_cap vhtcap;
} __attribute__ ((packed));

#define MAX_SCAN_TIME (8*HZ)
static Timer scanTimer;
static bool scanTimerFlag = false;

static const struct region_code_mapping regmap[] = {
	{"US", 0x10},		/* US FCC */
	{"CA", 0x20},		/* Canada */
	{"EU", 0x30},		/* ETSI   */
	{"ES", 0x31},		/* Spain  */
	{"FR", 0x32},		/* France */
	{"JP", 0x40},		/* Japan  */
	{"TW", 0x80},		/* Taiwan */
	{"AU", 0x81},		/* Australia */
	{"CN", 0x90},		/* China (Asia) */
};

/* Supported crypto cipher suits to be advertised to cfg80211 */
static const u32 mwl_cipher_suites[] = {
	WLAN_CIPHER_SUITE_WEP40,
	WLAN_CIPHER_SUITE_WEP104,
	WLAN_CIPHER_SUITE_TKIP,
	WLAN_CIPHER_SUITE_CCMP,
	WLAN_CIPHER_SUITE_AES_CMAC,
	WLAN_CIPHER_SUITE_GCMP,
	WLAN_CIPHER_SUITE_GCMP_256,
	WLAN_CIPHER_SUITE_BIP_GMAC_128,
	WLAN_CIPHER_SUITE_BIP_GMAC_256,
	WLAN_CIPHER_SUITE_BIP_CMAC_256,
};

/* Supported mgmt frame types to be advertised to cfg80211 */
static const struct ieee80211_txrx_stypes
 mwl_mgmt_stypes[NUM_NL80211_IFTYPES] = {
	[NL80211_IFTYPE_STATION] = {
				    .tx = BIT(IEEE80211_STYPE_ACTION >> 4) |
				    BIT(IEEE80211_STYPE_PROBE_RESP >> 4),
				    .rx = BIT(IEEE80211_STYPE_ACTION >> 4) |
				    BIT(IEEE80211_STYPE_PROBE_REQ >> 4) |
				    BIT(IEEE80211_STYPE_AUTH >> 4),
				    },
	[NL80211_IFTYPE_AP] = {
			       .tx = BIT(IEEE80211_STYPE_ACTION >> 4) |
#if defined(OWE_SUPPORT) || defined(MBO_SUPPORT)
			       BIT(IEEE80211_STYPE_ASSOC_RESP >> 4) |
			       BIT(IEEE80211_STYPE_REASSOC_RESP >> 4) |
#endif /* OWE_SUPPORT || MBO_SUPPORT */
			       BIT(IEEE80211_STYPE_AUTH >> 4) |
			       BIT(IEEE80211_STYPE_PROBE_RESP >> 4),
			       .rx = BIT(IEEE80211_STYPE_ACTION >> 4) |
			       BIT(IEEE80211_STYPE_PROBE_REQ >> 4) |
#if defined(OWE_SUPPORT) || defined(MBO_SUPPORT)
			       BIT(IEEE80211_STYPE_ASSOC_REQ >> 4) |
			       BIT(IEEE80211_STYPE_REASSOC_REQ >> 4) |
#endif /* OWE_SUPPORT || MBO_SUPPORT */
			       BIT(IEEE80211_STYPE_AUTH >> 4),
			       },
};

extern UINT8 keymgmt_wlCipher2AesMode(UINT8 ik_type);
extern UINT16 getPhyRate(dbRateInfo_t * pRateTbl);
extern UINT16 getNss(dbRateInfo_t * pRateTbl);
#if defined(OWE_SUPPORT) || defined(MBO_SUPPORT)
extern SINT8 evtDot11MgtMsg(vmacApInfo_t * vmacSta_p, UINT8 * message,
			    struct sk_buff *skb, UINT32 rssi);
extern void *FindIEWithinIEs(UINT8 * data_p, UINT32 lenPacket, UINT8 attrib,
			     UINT8 * OUI);
#endif /* OWE_SUPPORT || MBO_SUPPORT */

static int
mwl_cfg80211_mgmt_tx(struct wiphy *wiphy, struct wireless_dev *wdev,
		     struct cfg80211_mgmt_tx_params *params, u64 * cookie)
{
	const u8 *buf = params->buf;
	size_t len = params->len;
	size_t alloc_len = 0;
	struct sk_buff *skb;
	struct wlprivate *priv = mwl_netdev_get_priv(wdev->netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
#if defined(OWE_SUPPORT) || defined(MBO_SUPPORT)
	IEEEtypes_Frame_t *wlanMsg_p = NULL;
	uint8_t *ptr = NULL;
	UINT8 wildcard_bssid[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
#endif /* OWE_SUPPORT || MBO_SUPPORT */

	if (vmacSta_p == NULL)
		return -EINVAL;

	if (!buf || !len) {
		printk("%s invalid buffer and length\n", __func__);
		return -EFAULT;
	}
#if defined(OWE_SUPPORT) || defined(MBO_SUPPORT)
	alloc_len = len + 6;
#else
	alloc_len = len;
#endif /* OWE_SUPPORT || MBO_SUPPORT */

	skb = wl_alloc_skb(alloc_len);

	if (!skb) {
		printk("%s allocate skb failed for management frame\n",
		       __func__);
		return -ENOMEM;
	}

	*cookie = prandom_u32() | 1;

#if defined(OWE_SUPPORT) || defined(MBO_SUPPORT)
	memcpy(skb->data, buf, 24);
	memcpy(skb->data + 30, &buf[24], len - 24);
	ptr = skb->data - 2;
	ptr[0] = (len + 6) >> 8;
	ptr[1] = (len + 6);
	skb_put(skb, len + 6);

	wlanMsg_p = (IEEEtypes_Frame_t *) ((UINT8 *) skb->data - 2);

	if (wlanMsg_p->Hdr.FrmCtl.Subtype == IEEE_MSG_AUTHENTICATE) {
		extStaDb_StaInfo_t *pStaInfo;
		macmgmtQ_MgmtMsg3_t *MgmtMsg_p =
			(macmgmtQ_MgmtMsg3_t *) wlanMsg_p;
		if ((pStaInfo =
		     extStaDb_GetStaInfo(vmacSta_p, &wlanMsg_p->Hdr.Addr1,
					 STADB_DONT_UPDATE_AGINGTIME)) ==
		    NULL) {
			//added call to check other VAP's pStaInfo
			if ((pStaInfo =
			     extStaDb_GetStaInfo(vmacSta_p,
						 &wlanMsg_p->Hdr.Addr1,
						 STADB_SKIP_MATCH_VAP)))
				macMgmtRemoveSta(vmacSta_p, pStaInfo);
			if ((pStaInfo =
			     macMgtStaDbInit(vmacSta_p, &wlanMsg_p->Hdr.Addr1,
					     (IEEEtypes_MacAddr_t *) vmacSta_p->
					     macBssId)) == NULL) {
				wl_free_skb(skb);
				WLDBG_ENTER_INFO(DBG_LEVEL_11,
						 "init data base fail\n");
				return -1;
			}
		}
		if (MgmtMsg_p->Body.Auth.AuthAlg == 0x03 &&
		    MgmtMsg_p->Body.Auth.AuthTransSeq == 0x02 &&
		    MgmtMsg_p->Body.Auth.StatusCode == 0x00) {
			if (pStaInfo->State != ASSOCIATED)
				pStaInfo->State = AUTHENTICATED;
		}
	}

	if ((wlanMsg_p->Hdr.FrmCtl.Subtype == IEEE_MSG_ASSOCIATE_RSP) ||
	    (wlanMsg_p->Hdr.FrmCtl.Subtype == IEEE_MSG_REASSOCIATE_RSP)) {
		IEEEtypes_Frame_t *Msg_p;
		UINT8 *temp_p = NULL;
#ifdef MBO_SUPPORT
		UINT8 MBO_OUI[4] = { 0x50, 0x6F, 0x9A, 0x16 };
#endif /* MBO_SUPPORT */
		extStaDb_StaInfo_t *pStaInfo;
		macmgmtQ_MgmtMsg3_t *MgmtMsg_p =
			(macmgmtQ_MgmtMsg3_t *) wlanMsg_p;

		pStaInfo =
			extStaDb_GetStaInfo(vmacSta_p, &wlanMsg_p->Hdr.Addr1,
					    STADB_DONT_UPDATE_AGINGTIME);
		if (pStaInfo == NULL) {
			wl_free_skb(skb);
			skb = wl_alloc_skb(len);
			if (skb) {
				memcpy(skb->data, buf, len);
				skb_put(skb, len);
				goto send;
			} else
				return 0;
		}
#ifdef MBO_SUPPORT
		memset(pStaInfo->AP_MBOIEBuf, 0, 12);
		temp_p = FindIEWithinIEs(&wlanMsg_p->Body[0] + 6,
					 len - 6 - sizeof(IEEEtypes_GenHdr_t) +
					 sizeof(UINT16), PROPRIETARY_IE,
					 MBO_OUI);
		if (temp_p)
			memcpy(&pStaInfo->AP_MBOIEBuf[0], temp_p,
			       *(temp_p + 1) + 2);
#endif /* MBO_SUPPORT */

#ifdef OWE_SUPPORT
		temp_p = FindIEWithinIEs(&wlanMsg_p->Body[0] + 6,
					 len - 6 - sizeof(IEEEtypes_GenHdr_t) +
					 sizeof(UINT16), EXTENSION, NULL);
		if (temp_p) {
			memcpy(&pStaInfo->AP_DHIEBuf[0], temp_p,
			       *(temp_p + 1) + 2);
		}

		memset(pStaInfo->EXT_RsnIE, 0, 64);
		temp_p = FindIEWithinIEs(&wlanMsg_p->Body[0] + 6,
					 len - 6 - sizeof(IEEEtypes_GenHdr_t) +
					 sizeof(UINT16), RSN_IEWPA2, NULL);
		if (temp_p) {
			memcpy(&pStaInfo->EXT_RsnIE[0], temp_p,
			       *(temp_p + 1) + 2);
		}
#endif /* OWE_SUPPORT */

		Msg_p = (IEEEtypes_Frame_t *) ((UINT8 *) pStaInfo->
					       assocReq_skb->data - 2);
		Msg_p->Hdr.FrmBodyLen = pStaInfo->assocReq_skb->len;

		if (MgmtMsg_p->Body.AssocRsp.StatusCode ==
		    IEEEtypes_STATUS_SUCCESS)
			evtDot11MgtMsg(vmacSta_p, (UINT8 *) Msg_p,
				       pStaInfo->assocReq_skb,
				       pStaInfo->assocReq_skb_rssi);

#ifdef MRVL_80211R
		if (!pStaInfo->keyMgmtStateInfo.pending_assoc) {
#endif /* MRVL_80211R */
			pending_assoc_timer_del(pStaInfo);

			wl_free_skb(pStaInfo->assocReq_skb);
			pStaInfo->assocReq_skb = NULL;

#ifdef MRVL_80211R
		}
#endif /* MRVL_80211R */

		if (MgmtMsg_p->Body.AssocRsp.StatusCode ==
		    IEEEtypes_STATUS_SUCCESS) {
			wl_free_skb(skb);
			return 0;
		}
	}
#else /* OWE_SUPPORT || MBO_SUPPORT */
	memcpy(skb->data, buf, len);
	skb_put(skb, len);
#endif /* OWE_SUPPORT || MBO_SUPPORT */

#if defined(OWE_SUPPORT) || defined(MBO_SUPPORT)
send:
#endif /* OWE_SUPPORT || MBO_SUPPORT */

#if defined(OWE_SUPPORT) || defined(MBO_SUPPORT)
	if (wlanMsg_p->Hdr.FrmCtl.Subtype == IEEE_MSG_ACTION &&
	    !memcmp(wlanMsg_p->Hdr.Addr3, wildcard_bssid,
		    IEEEtypes_ADDRESS_SIZE)) {
		wlFwSendFrame(vmacSta_p->dev, 0xFFFF, 0, 0, 0, 24, len - 24,
			      (UINT8 *) buf, (UINT8 *) & buf[24]);
		wl_free_skb(skb);
	} else
#endif /* OWE_SUPPORT || MBO_SUPPORT */
	{
		if (txMgmtMsg(vmacSta_p->dev, skb) != OS_SUCCESS) {
			wl_free_skb(skb);
			return -EINVAL;
		}
	}

	return 0;
}

static void
mwl_cfg80211_mgmt_frame_register(struct wiphy *wiphy, struct wireless_dev *wdev,
				 u16 frame_type, bool reg)
{
	return;
}

static int
mwl_cfg80211_set_antenna(struct wiphy *wiphy, u32 tx_ant, u32 rx_ant)
{
	struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib;

	if (vmacSta_p == NULL)
		return -EINVAL;

	mib = vmacSta_p->ShadowMib802dot11;

#ifdef SOC_W8764
	if (tx_ant < 0 || tx_ant > 0xf)
#else
	if (tx_ant > 7)
#endif
		return -EOPNOTSUPP;

	/* 0:AB(Auto), 1:A, 2:B, 3:AB, 7:ABC */
	*(mib->mib_txAntenna) = (uint8_t) tx_ant;

	if (rx_ant > 0x7)
		return -EOPNOTSUPP;

	*(mib->mib_rxAntenna) = (uint8_t) rx_ant;
	if (*(mib->mib_rxAntenna) == 4 || *(mib->mib_rxAntenna) == 0)
		*(mib->mib_rxAntBitmap) = 0xf;
	else if (*(mib->mib_rxAntenna) == 3)
		*(mib->mib_rxAntBitmap) = 7;
	else if (*(mib->mib_rxAntenna) == 2)
		*(mib->mib_rxAntBitmap) = 3;
	else
		*(mib->mib_rxAntBitmap) = 1;

	return 0;
}

static int
mwl_cfg80211_get_antenna(struct wiphy *wiphy, u32 * tx_ant, u32 * rx_ant)
{
	struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib;

	if (vmacSta_p == NULL)
		return -ENODATA;

	mib = vmacSta_p->ShadowMib802dot11;

	*tx_ant = (u32) * (mib->mib_txAntenna);
	*rx_ant = (u32) * (mib->mib_rxAntenna);

	return 0;
}

static int
mwl_cfg80211_sta_trigger_scan(struct wlprivate *priv)
{
	UINT8 bcAddr1[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };	/* BROADCAST BSSID */
	UINT8 ieBuf[2 + IEEE_80211_MAX_NUMBER_OF_CHANNELS];
	UINT16 ieBufLen = 0;
	IEEEtypes_InfoElementHdr_t *IE_p;
	vmacEntry_t *vmacEntry_p = NULL;
	struct net_device *staDev = NULL;
	struct wlprivate *stapriv = NULL;
	vmacApInfo_t *vmacSta_p = NULL;
	MIB_802DOT11 *mib = NULL;
	UINT8 mlmeAssociatedFlag;
	UINT8 mlmeBssid[6];
	UINT8 currChnlIndex = 0;
	UINT8 chnlListLen = 0;
	UINT8 chnlScanList[IEEEtypes_MAX_CHANNELS + IEEEtypes_MAX_CHANNELS_A];
	UINT8 i = 0;
	MIB_PHY_DSSS_TABLE *PhyDSSSTable;
	UINT8 mainChnlList[IEEEtypes_MAX_CHANNELS + IEEEtypes_MAX_CHANNELS_A];
#ifdef AP_SCAN_SUPPORT
	int clientDisable = 0;
#endif
#ifdef MRVL_WPS_CLIENT
	struct mwl_appie appie;
#endif /* MRVL_WPS_CLIENT */

	if ((vmacEntry_p =
	     sme_GetParentVMacEntry(((vmacApInfo_t *) priv->vmacSta_p)->
				    VMacEntry.phyHwMacIndx)) == NULL)
		return -EFAULT;
	staDev = (struct net_device *)vmacEntry_p->privInfo_p;
	stapriv = NETDEV_PRIV_P(struct wlprivate, staDev);
	vmacSta_p = stapriv->vmacSta_p;
	mib = vmacSta_p->Mib802dot11;
	//when this command issued on AP mode, system would crash because of no STA interface
	//so the following checking is necessary.
#ifdef AP_SCAN_SUPPORT
	if (*(mib->mib_STAMode) == CLIENT_MODE_DISABLE) {
		*(mib->mib_STAMode) = CLIENT_MODE_AUTO;
		clientDisable = 1;
	}
#else
	if (*(mib->mib_STAMode) == CLIENT_MODE_DISABLE) {
		rc = -EOPNOTSUPP;
		return rc;
	}
#endif

	memset(&mainChnlList[0], 0,
	       (IEEEtypes_MAX_CHANNELS + IEEEtypes_MAX_CHANNELS_A));
	memset(&chnlScanList[0], 0,
	       (IEEEtypes_MAX_CHANNELS + IEEEtypes_MAX_CHANNELS_A));

	PhyDSSSTable = mib->PhyDSSSTable;

	/* Stop Autochannel on AP first */
	if (priv->master) {
		struct wlprivate *wlMPrvPtr =
			NETDEV_PRIV_P(struct wlprivate, priv->master);
		StopAutoChannel(wlMPrvPtr->vmacSta_p);
	}
	/* get range to scan */
	domainGetInfo(mainChnlList);

	if ((*(vmacSta_p->Mib802dot11->mib_STAMode) == CLIENT_MODE_AUTO) ||
	    (*(vmacSta_p->Mib802dot11->mib_STAMode) == CLIENT_MODE_N)) {
		for (i = 0; i < IEEEtypes_MAX_CHANNELS; i++) {
			if (mainChnlList[i] > 0) {
				chnlScanList[currChnlIndex] = mainChnlList[i];
				currChnlIndex++;
			}
		}

		for (i = 0; i < IEEEtypes_MAX_CHANNELS_A; i++) {
			if (mainChnlList[i + IEEEtypes_MAX_CHANNELS] > 0) {
				chnlScanList[currChnlIndex] =
					mainChnlList[i +
						     IEEEtypes_MAX_CHANNELS];
				currChnlIndex++;
			}
		}
		chnlListLen = currChnlIndex;
	} else if (*(vmacSta_p->Mib802dot11->mib_STAMode) == CLIENT_MODE_N_24) {
		for (i = 0; i < IEEEtypes_MAX_CHANNELS; i++) {
			chnlScanList[i] = mainChnlList[i];
		}
		chnlScanList[i] = 0;
		chnlListLen = IEEEtypes_MAX_CHANNELS;
	} else if (*(vmacSta_p->Mib802dot11->mib_STAMode) == CLIENT_MODE_N_5) {
		for (i = 0; i < IEEEtypes_MAX_CHANNELS_A; i++) {
			chnlScanList[i] =
				mainChnlList[i + IEEEtypes_MAX_CHANNELS];
		}
		chnlScanList[i] = 0;
		chnlListLen = IEEEtypes_MAX_CHANNELS_A;
	}
#ifdef AP_SCAN_SUPPORT
	if (clientDisable)
		*(mib->mib_STAMode) = CLIENT_MODE_DISABLE;
#endif
	ieBufLen = 0;
	/* Build IE Buf */
	IE_p = (IEEEtypes_InfoElementHdr_t *) & ieBuf[ieBufLen];

	/* SSID element */
	/* For scan all SSIDs to be scanned */

	/* DS_PARAM_SET element */
	IE_p->ElementId = DS_PARAM_SET;
	IE_p->Len = chnlListLen;
	ieBufLen += sizeof(IEEEtypes_InfoElementHdr_t);
	memcpy((char *)&ieBuf[ieBufLen], &chnlScanList[0], chnlListLen);

	ieBufLen += IE_p->Len;
	IE_p = (IEEEtypes_InfoElementHdr_t *) & ieBuf[ieBufLen];

	if ((vmacEntry_p =
	     sme_GetParentVMacEntry(((vmacApInfo_t *) priv->vmacSta_p)->
				    VMacEntry.phyHwMacIndx)) == NULL)
		return -EFAULT;

	if (!smeGetStaLinkInfo
	    (vmacEntry_p->id, &mlmeAssociatedFlag, &mlmeBssid[0]))
		return -EFAULT;

#ifdef MRVL_WPS_CLIENT
	appie.type = WL_APPIE_FRAMETYPE_PROBE_REQUEST;
	appie.len = priv->request->ie_len;
	if (appie.len)
		memcpy(appie.buf, priv->request->ie, priv->request->ie_len);
	else {
		appie.len = IE_BUF_LEN;
		memset(appie.buf, 0, IE_BUF_LEN);
	}
	mwl_config_set_appie(staDev, (struct wlreq_set_appie *)&appie);
#endif

	/* Set a flag indicating usr initiated scan */
	vmacSta_p->gUserInitScan = TRUE;

	if (!mlmeAssociatedFlag && (staDev->flags & IFF_RUNNING)) {
		//printk("stopping BSS \n");
		linkMgtStop(vmacEntry_p->phyHwMacIndx);
		smeStopBss(vmacEntry_p->phyHwMacIndx);
	}

	if (smeSendScanRequest
	    (vmacEntry_p->phyHwMacIndx, 0, 3, 200, &bcAddr1[0], &ieBuf[0],
	     ieBufLen) == MLME_SUCCESS) {
		/*set the busy scanning flag */
		vmacSta_p->busyScanning = 1;
		return 0;
	} else {
		/* Reset a flag indicating usr initiated scan */
		vmacSta_p->gUserInitScan = FALSE;
		return -EALREADY;
	}
}

void
mwl_cfg80211_scan_done(UINT8 * data)
{
	struct wlprivate *priv = (struct wlprivate *)data;
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	struct cfg80211_scan_request *scan_request;
	struct cfg80211_bss *bss;

	scanDescptHdr_t *curDescpt_p = NULL;
	IEEEtypes_SsIdElement_t *ssidIE_p;
	IEEEtypes_DsParamSet_t *dsPSetIE_p;
	IEEEtypes_RSN_IE_t *RSN_p = NULL;
	IEEEtypes_RSN_IE_WPA2_t *wpa2IE_p = NULL;
	UINT16 parsedLen = 0;
	UINT8 i = 0;

	UINT8 bssid[ETH_ALEN];
	UINT64 timestamp = 0;
	struct ieee80211_channel chan;
	UINT16 beacon_period;
	UINT16 cap_info_bitmap;
	s32 rssi;
	u8 ie_buf[512];		//[150];
	size_t ie_len = 0;
	bool __maybe_unused aborted = false;

	for (i = 0; i < tmpNumScanDesc[vmacSta_p->VMacEntry.phyHwMacIndx]; i++) {
		curDescpt_p =
			(scanDescptHdr_t
			 *) (&tmpScanResults[vmacSta_p->VMacEntry.
					     phyHwMacIndx][0] + parsedLen);

		memset(&bssid[0], 0, ETH_ALEN);

		/* Configure band */
		chan.band = NL80211_BAND_5GHZ;

		memcpy(&bssid[0], &curDescpt_p->bssId[0], ETH_ALEN);
		timestamp = *(uint64_t *) curDescpt_p->TimeStamp;
		rssi = (-(s32) (curDescpt_p->rssi)) * 100;
		beacon_period = curDescpt_p->BcnInterval;
		cap_info_bitmap = *((UINT16 *) & (curDescpt_p->CapInfo));

		/* Fill in IE parameters required by scan dump */

		/* Set DSSS IE */
		if ((dsPSetIE_p =
		     (IEEEtypes_DsParamSet_t *) smeParseIeType(DS_PARAM_SET,
							       (((UINT8 *)
								 curDescpt_p) +
								sizeof
								(scanDescptHdr_t)),
							       curDescpt_p->
							       length +
							       sizeof
							       (curDescpt_p->
								length) -
							       sizeof
							       (scanDescptHdr_t)))
		    != NULL) {
			ie_buf[0] = dsPSetIE_p->ElementId;
			ie_buf[1] = dsPSetIE_p->Len;
			ie_buf[2] = dsPSetIE_p->CurrentChan;
			ie_len = dsPSetIE_p->Len + 2;
			if (dsPSetIE_p->CurrentChan > 0 &&
			    dsPSetIE_p->CurrentChan <= 14)
				chan.band = NL80211_BAND_2GHZ;
		}

		/* Set ESSID IE */
		if ((ssidIE_p = (IEEEtypes_SsIdElement_t *) smeParseIeType(SSID,
									   (((UINT8 *) curDescpt_p) + sizeof(scanDescptHdr_t)), curDescpt_p->length + sizeof(curDescpt_p->length) - sizeof(scanDescptHdr_t))) != NULL) {
			ie_buf[ie_len] = ssidIE_p->ElementId;
			ie_buf[ie_len + 1] = ssidIE_p->Len;
			memcpy(&ie_buf[ie_len + 2], &ssidIE_p->SsId[0],
			       ssidIE_p->Len);
			ie_len = ie_len + ssidIE_p->Len + 2;
		}

		/* Set WPA2 IE */
		if ((wpa2IE_p =
		     (IEEEtypes_RSN_IE_WPA2_t *) smeParseIeType(RSN_IEWPA2,
								(((UINT8 *)
								  curDescpt_p) +
								 sizeof
								 (scanDescptHdr_t)),
								curDescpt_p->
								length +
								sizeof
								(curDescpt_p->
								 length) -
								sizeof
								(scanDescptHdr_t))))
		{
			ie_buf[ie_len] = wpa2IE_p->ElemId;
			ie_buf[ie_len + 1] = wpa2IE_p->Len;
			memcpy(&ie_buf[ie_len + 2], &wpa2IE_p->Ver[0],
			       wpa2IE_p->Len);
			ie_len = ie_len + wpa2IE_p->Len + 2;
		}

		/* Set RSN IE */
		if ((RSN_p =
		     linkMgtParseWpaIe((((UINT8 *) curDescpt_p) +
					sizeof(scanDescptHdr_t)),
				       curDescpt_p->length +
				       sizeof(curDescpt_p->length) -
				       sizeof(scanDescptHdr_t)))) {
			ie_buf[ie_len] = RSN_p->ElemId;
			ie_buf[ie_len + 1] = RSN_p->Len;
			memcpy(&ie_buf[ie_len + 2], &RSN_p->OuiType[0],
			       RSN_p->Len);
			ie_len = ie_len + RSN_p->Len + 2;
		}
#ifdef MRVL_WPS_CLIENT
		/* Set WPS IE */
		if ((RSN_p =
		     linkMgtParseWpsIe((((UINT8 *) curDescpt_p) +
					sizeof(scanDescptHdr_t)),
				       curDescpt_p->length +
				       sizeof(curDescpt_p->length) -
				       sizeof(scanDescptHdr_t)))) {
			ie_buf[ie_len] = RSN_p->ElemId;
			ie_buf[ie_len + 1] = RSN_p->Len;
			memcpy(&ie_buf[ie_len + 2], &RSN_p->OuiType[0],
			       RSN_p->Len);
			ie_len = ie_len + RSN_p->Len + 2;
		}
#endif /* MRVL_WPS_CLIENT */

		bss = cfg80211_inform_bss(priv->wiphy,
					  &chan, CFG80211_BSS_FTYPE_UNKNOWN,
					  bssid, timestamp,
					  cap_info_bitmap, beacon_period,
					  ie_buf, ie_len, rssi, GFP_KERNEL);
		if (bss)
			cfg80211_put_bss(priv->wiphy, bss);

		parsedLen += curDescpt_p->length + sizeof(curDescpt_p->length);
	}

	scan_request = priv->request;
	if (scan_request) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(4,7,0)
		struct cfg80211_scan_info info = {
			.aborted = false,
		};
		cfg80211_scan_done(scan_request, &info);
#else
		cfg80211_scan_done(scan_request, aborted);
#endif
		priv->request = NULL;
	}
	scanTimerFlag = false;

}

static int
mwl_cfg80211_scan(struct wiphy *wiphy, struct cfg80211_scan_request *request)
{
	struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);
	int ret;
	priv->request = request;

	if (scanTimerFlag) {
		//mwl_cfg80211_scan_done((UINT8 *)priv);
#if LINUX_VERSION_CODE > KERNEL_VERSION(4,7,0)
		struct cfg80211_scan_info info = {
			.aborted = true,
		};
		cfg80211_scan_done(priv->request, &info);
#else
		cfg80211_scan_done(priv->request, 1);
#endif
		priv->request = NULL;
		return -EBUSY;
	}
	ret = mwl_cfg80211_sta_trigger_scan(priv);
	if (!ret) {
		TimerFireInByJiffies(&scanTimer, 1, &mwl_cfg80211_scan_done,
				     (UINT8 *) priv, MAX_SCAN_TIME);
		scanTimerFlag = true;
	}
	return ret;
}

static int
mwl_cfg80211_fill_chandef(CHNL_FLAGS Chanflag,
			  struct cfg80211_chan_def *chandef, UINT8 extSubCh)
{
	UINT16 center_freq = chandef->chan->center_freq;
	switch (Chanflag.ChnlWidth) {
	case CH_5_MHz_WIDTH:
		chandef->width = NL80211_CHAN_WIDTH_20_NOHT;
		chandef->center_freq1 = center_freq;
		chandef->center_freq2 = 0;
		break;
	case CH_10_MHz_WIDTH:
		chandef->width = NL80211_CHAN_WIDTH_20_NOHT;
		chandef->center_freq1 = center_freq;
		chandef->center_freq2 = 0;
		break;
	case CH_20_MHz_WIDTH:
		chandef->width = NL80211_CHAN_WIDTH_20;
		chandef->center_freq1 = center_freq;
		chandef->center_freq2 = 0;
		break;
	case CH_40_MHz_WIDTH:
		chandef->width = NL80211_CHAN_WIDTH_40;
		/* Use extSubCh to calc center_freq1 to conform to cfg80211 */
		if (1 == extSubCh) {
			chandef->center_freq1 = center_freq - 10;
		} else {
			chandef->center_freq1 = center_freq + 10;
		}
		chandef->center_freq2 = 0;
		break;
	case CH_80_MHz_WIDTH:
		chandef->width = NL80211_CHAN_WIDTH_80;
		/* Because we cannot get upper or lower channel in 80MHz, just fix a pattern to let cfg80211 pass through */
		chandef->center_freq1 = center_freq + 30;
		chandef->center_freq2 = 0;
		break;
	case CH_160_MHz_WIDTH:
		chandef->width = NL80211_CHAN_WIDTH_160;
		/* Because we cannot get upper or lower channel in 160MHz, just fix a pattern to let cfg80211 pass through */
		chandef->center_freq1 = center_freq + 70;
		chandef->center_freq2 = 0;
		break;
	default:
		chandef->width = NL80211_CHAN_WIDTH_20_NOHT;
		chandef->center_freq1 = center_freq;
		chandef->center_freq2 = 0;
		break;
	}
	return 0;
}

static int
mwl_cfg80211_get_channel(struct wiphy *wiphy, struct wireless_dev *wdev,
			 struct cfg80211_chan_def *chandef)
{

	UINT16 j;
	struct wlprivate *wlpptr = mwl_cfg80211_get_priv(wiphy);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	MIB_802DOT11 *mib;

	if (vmacSta_p == NULL)
		return -ENODATA;

	mib = vmacSta_p->ShadowMib802dot11;
	wlpptr->channel.hw_value = (UINT16) mib->PhyDSSSTable->CurrChan;

	for (j = 0; j < mwl_band_50.n_channels; j++) {
		if (wlpptr->channel.hw_value == mwl_channels_50[j].hw_value) {
			wlpptr->channel.band = NL80211_BAND_5GHZ;
			wlpptr->channel.center_freq =
				mwl_channels_50[j].center_freq;
			break;
		}
	}

	for (j = 0; j < mwl_band_24.n_channels; j++) {
		if (wlpptr->channel.hw_value == mwl_channels_24[j].hw_value) {
			wlpptr->channel.band = NL80211_BAND_2GHZ;
			wlpptr->channel.center_freq =
				mwl_channels_24[j].center_freq;
			break;
		}
	}
	chandef->chan = &(wlpptr->channel);
	mwl_cfg80211_fill_chandef(mib->PhyDSSSTable->Chanflag, chandef,
				  *(mib->mib_extSubCh));
	return 0;
}

static int
mwl_cfg80211_dump_station(struct wiphy *wiphy, struct net_device *dev, int idx,
			  u8 * mac, struct station_info *sinfo)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	u8 *sta_buf, *show_buf, buf1[256];
	int entries;
	extStaDb_StaInfo_t *pStaInfo;

	if (vmacSta_p == NULL)
		return -ENODATA;

	entries = extStaDb_entries(vmacSta_p, 0);

	sta_buf = buf1;
	extStaDb_list(vmacSta_p, sta_buf, 1);

	if (entries) {
		show_buf = sta_buf + sizeof(STA_INFO) * idx;

		if (NULL ==
		    (pStaInfo =
		     extStaDb_GetStaInfo(vmacSta_p,
					 (IEEEtypes_MacAddr_t *) show_buf,
					 STADB_DONT_UPDATE_AGINGTIME)))
			return -ENODATA;

		memcpy(mac, pStaInfo->Addr, sizeof(pStaInfo->Addr));
		sinfo->filled =
			BIT(NL80211_STA_INFO_TX_BITRATE) |
			BIT(NL80211_STA_INFO_SIGNAL) |
			BIT(NL80211_STA_INFO_SIGNAL_AVG);
		//sinfo->txrate.flags = BIT(0) | BIT(1) | BIT(2) | BIT(3) | BIT(5) | BIT(6);
		//sinfo->txrate.mcs = pStaInfo->RateInfo.RateIDMCS;
		sinfo->txrate.legacy =
			getPhyRate((dbRateInfo_t *) & (pStaInfo->RateInfo)) *
			10;
		sinfo->txrate.nss =
			getNss((dbRateInfo_t *) & (pStaInfo->RateInfo));
		sinfo->signal = -(pStaInfo->RSSI);
		sinfo->signal_avg = -(pStaInfo->RSSI);

		return 0;
	}

	return -ENODATA;
}

static int
mwl_cfg80211_set_ap_chanwidth(struct wiphy *wiphy, struct net_device *wdev,
			      struct cfg80211_chan_def *chandef)
{
	struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	printk("%s : %d\n", __func__, chandef->chan->hw_value);
	return mwl_config_set_channel(priv->netDev, chandef->chan->hw_value);
}

static int
marvell_set_ciphersuite(struct net_device *netdev, uint8_t wpamode,
			uint32_t cipher_pairwise, uint32_t cipher_group)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	if (wpamode == NL80211_WPA_VERSION_1) {	/* wpa */
		if (cipher_pairwise == WLAN_CIPHER_SUITE_TKIP) {
			*(mib->mib_cipherSuite) = 2;

			mib->RSNConfig->MulticastCipher[0] = 0x00;
			mib->RSNConfig->MulticastCipher[1] = 0x50;
			mib->RSNConfig->MulticastCipher[2] = 0xF2;
			mib->RSNConfig->MulticastCipher[3] = 0x02;	/* TKIP */

			mib->UnicastCiphers->UnicastCipher[0] = 0x00;
			mib->UnicastCiphers->UnicastCipher[1] = 0x50;
			mib->UnicastCiphers->UnicastCipher[2] = 0xF2;
			mib->UnicastCiphers->UnicastCipher[3] = 0x02;	/* TKIP */
			mib->UnicastCiphers->Enabled = TRUE;
		} else if (cipher_pairwise == WLAN_CIPHER_SUITE_CCMP) {
			*(mib->mib_cipherSuite) = 4;

			mib->RSNConfig->MulticastCipher[0] = 0x00;
			mib->RSNConfig->MulticastCipher[1] = 0x50;
			mib->RSNConfig->MulticastCipher[2] = 0xF2;
			mib->RSNConfig->MulticastCipher[3] = 0x04;	/* AES */

			mib->UnicastCiphers->UnicastCipher[0] = 0x00;
			mib->UnicastCiphers->UnicastCipher[1] = 0x50;
			mib->UnicastCiphers->UnicastCipher[2] = 0xF2;
			mib->UnicastCiphers->UnicastCipher[3] = 0x04;	/* AES */
			mib->UnicastCiphers->Enabled = TRUE;
		} else
			return -EFAULT;
	} else if (wpamode == NL80211_WPA_VERSION_2) {	/*wpa2 */
		*(mib->mib_cipherSuite) = cipher_pairwise | 0xff;

		mib->WPA2UnicastCiphers->UnicastCipher[0] = 0x00;
		mib->WPA2UnicastCiphers->UnicastCipher[1] = 0x0F;
		mib->WPA2UnicastCiphers->UnicastCipher[2] = 0xAC;
		mib->WPA2UnicastCiphers->UnicastCipher[3] =
			cipher_pairwise & 0xff;
		mib->WPA2UnicastCiphers->Enabled = TRUE;

		mib->RSNConfigWPA2->MulticastCipher[0] = 0x00;
		mib->RSNConfigWPA2->MulticastCipher[1] = 0x0F;
		mib->RSNConfigWPA2->MulticastCipher[2] = 0xAC;
		if (cipher_group)
			mib->RSNConfigWPA2->MulticastCipher[3] =
				cipher_group & 0xff;
		else
			mib->RSNConfigWPA2->MulticastCipher[3] =
				cipher_pairwise & 0xff;
	} else if (wpamode == (NL80211_WPA_VERSION_1 | NL80211_WPA_VERSION_2)) {	/* wpa/wpa2 mix */
		*(mib->mib_cipherSuite) = 4;

		mib->RSNConfig->MulticastCipher[0] = 0x00;
		mib->RSNConfig->MulticastCipher[1] = 0x50;
		mib->RSNConfig->MulticastCipher[2] = 0xF2;
		mib->RSNConfig->MulticastCipher[3] = cipher_group & 0xff;

		mib->UnicastCiphers->UnicastCipher[0] = 0x00;
		mib->UnicastCiphers->UnicastCipher[1] = 0x50;
		mib->UnicastCiphers->UnicastCipher[2] = 0xF2;
		mib->UnicastCiphers->UnicastCipher[3] = cipher_group & 0xff;
		mib->UnicastCiphers->Enabled = TRUE;

		mib->RSNConfigWPA2->MulticastCipher[0] = 0x00;
		mib->RSNConfigWPA2->MulticastCipher[1] = 0x0F;
		mib->RSNConfigWPA2->MulticastCipher[2] = 0xAC;
		mib->RSNConfigWPA2->MulticastCipher[3] = cipher_group & 0xff;

		mib->WPA2UnicastCiphers->UnicastCipher[0] = 0x00;
		mib->WPA2UnicastCiphers->UnicastCipher[1] = 0x0F;
		mib->WPA2UnicastCiphers->UnicastCipher[2] = 0xAC;
		mib->WPA2UnicastCiphers->UnicastCipher[3] =
			cipher_pairwise & 0xff;
		mib->WPA2UnicastCiphers->Enabled = TRUE;
	} else
		return -EFAULT;

	return 0;
}

static int
mwl_beacon_get_rsn(struct cfg80211_beacon_data beacon, u8 * beacon_akm)
{
	const u8 *rsn_ie;
	size_t rsn_ie_len;
	u16 cnt;

	if (!beacon.tail)
		return -EINVAL;

	rsn_ie = cfg80211_find_ie(WLAN_EID_RSN, beacon.tail, beacon.tail_len);
	if (!rsn_ie)
		return -EINVAL;

	rsn_ie_len = *(rsn_ie + 1);
	/* skip element id and length */
	rsn_ie += 2;

	/* skip version */
	if (rsn_ie_len < 2)
		return -EINVAL;
	rsn_ie += 2;
	rsn_ie_len -= 2;

	/* skip group cipher suite */
	if (rsn_ie_len < 4)
		return 0;
	rsn_ie += 4;
	rsn_ie_len -= 4;

	/* skip pairwise cipher suite */
	if (rsn_ie_len < 2)
		return 0;
	cnt = get_unaligned_le16(rsn_ie);
	rsn_ie += (2 + cnt * 4);
	rsn_ie_len -= (2 + cnt * 4);

	if (rsn_ie_len < 6)
		return 0;

	memcpy(beacon_akm, rsn_ie + 2, 4);

	return 0;
}

static int
mwl_beacon_get_wpa(struct cfg80211_beacon_data beacon, u8 * beacon_akm)
{
	IEEEtypes_RSN_IE_t *thisStaRsnIE_p = NULL;

	if (!beacon.tail)
		return -EINVAL;
	do {
		thisStaRsnIE_p =
			(IEEEtypes_RSN_IE_t *)
			cfg80211_find_ie(WLAN_EID_VENDOR_SPECIFIC, beacon.tail,
					 beacon.tail_len);
		if (thisStaRsnIE_p == NULL) {
			break;
		}
		/* Find WPA Version */
		if (thisStaRsnIE_p->Ver[0] == 0x01 &&
		    thisStaRsnIE_p->Ver[1] == 0x00) {
			break;
		}
	} while (thisStaRsnIE_p);

	if (!thisStaRsnIE_p)
		return -EINVAL;

	memcpy(beacon_akm, thisStaRsnIE_p->AuthKeyList, 4);
	return 0;
}

static int
mwl_parse_conn_params(struct net_device *dev,
		      struct cfg80211_connect_params *sme)
{
	struct wlprivate *priv = NULL;
	vmacApInfo_t *vmacSta_p = NULL;
	const u8 *rsn_ie = NULL;

	if (dev == NULL || sme == NULL) {
		printk(KERN_ERR "Invalid connect parameters\n");
		return -EINVAL;
	}
	priv = mwl_netdev_get_priv(dev);
	if (priv == NULL)
		return -EINVAL;
	vmacSta_p = priv->vmacSta_p;
	if (vmacSta_p == NULL)
		return -EINVAL;
	if (sme->ie == NULL || sme->ie_len == 0)
		return 0;
	memset(vmacSta_p->RsnIE, 0, sizeof(IEEEtypes_RSN_IE_WPA2_t));
	vmacSta_p->RsnIESetByHost = 0;
	rsn_ie = FindIEWithinIEs((UINT8 *) sme->ie, (UINT32) sme->ie_len,
				 RSN_IEWPA2, NULL);
	if (rsn_ie != NULL) {
		memcpy(vmacSta_p->RsnIE, rsn_ie, rsn_ie[1] + 2);
		vmacSta_p->RsnIESetByHost = 1;
	}
	// TBD: parse other IEs in sme->ie
	return 0;
}

static int
mwl_configura_wpa(struct net_device *dev,
		  struct cfg80211_crypto_settings crypto, u32 beacon_akm)
{
	struct wlprivate *priv = mwl_netdev_get_priv(dev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	u32 wpa_key_mgmt = 0;
#ifdef MRVL_WPS_CLIENT
	vmacEntry_t *vmacEntry_p = NULL;
	STA_SYSTEM_MIBS *pStaSystemMibs;
#endif

	/* TODO: should support mix akm_suites */
	if (0 == crypto.wpa_versions) {
		*(mib->mib_wpaWpa2Mode) = 0;
		mib->Privacy->RSNEnabled = 0;
		mib->Privacy->RSNLinkStatus = 0;
		mib->RSNConfigWPA2->WPA2Enabled = 0;
		mib->RSNConfigWPA2->WPA2OnlyEnabled = 0;

#ifdef MRVL_WPS_CLIENT
		if (priv->wpsProbeRequestIeLen > 0) {
			*(mib->mib_wpaWpa2Mode) = 4;
			if ((vmacEntry_p =
			     sme_GetParentVMacEntry(vmacSta_p->VMacEntry.
						    phyHwMacIndx)) != NULL) {
				pStaSystemMibs =
					sme_GetStaSystemMibsPtr(vmacEntry_p);
				if (pStaSystemMibs != NULL) {
					pStaSystemMibs->mib_StaCfg_p->
						wpawpa2Mode = 16;
				}
			}
		}
#endif
	} else {
		if (crypto.wpa_versions !=
		    (NL80211_WPA_VERSION_1 | NL80211_WPA_VERSION_2)
		    && crypto.n_ciphers_pairwise != 1)
			return -EINVAL;

		if (beacon_akm)
			wpa_key_mgmt = beacon_akm;
		else if (crypto.n_akm_suites == 1)
			wpa_key_mgmt = __be32_to_cpu(crypto.akm_suites[0]);
		else if (crypto.n_akm_suites == 2)
			wpa_key_mgmt = __be32_to_cpu(crypto.akm_suites[0]);
		else
			return -EINVAL;

		/*
		 * 0: iwpriv disable wpa/wpa2
		 * 1: iwpriv enable wpa-psk
		 * 2: iwpriv enable wpa2-psk
		 * 3: iwpriv enable wpa/wpa2-psk mix mode
		 * 4: hostapd config wpa/wpa2
		 */
		*(mib->mib_wpaWpa2Mode) = 4;
#ifdef MRVL_WPS_CLIENT
		if ((vmacEntry_p =
		     sme_GetParentVMacEntry(vmacSta_p->VMacEntry.
					    phyHwMacIndx)) != NULL) {
			pStaSystemMibs = sme_GetStaSystemMibsPtr(vmacEntry_p);
			if (pStaSystemMibs != NULL)
				pStaSystemMibs->mib_StaCfg_p->wpawpa2Mode = 4;
		}
#endif

		mib->Privacy->PrivInvoked = 0;
		mib->AuthAlg->Type = 0;
		mib->Privacy->RSNEnabled = 1;
		mib->Privacy->RSNLinkStatus = 0;
		*(mib->mib_WPAPSKValueEnabled) = 0;

		if ((crypto.wpa_versions & NL80211_WPA_VERSION_1) &&
		    !(crypto.wpa_versions & NL80211_WPA_VERSION_2)) {
			mib->RSNConfigWPA2->WPA2Enabled = FALSE;
			mib->RSNConfigWPA2->WPA2OnlyEnabled = FALSE;

			memcpy(mib->RSNConfigAuthSuites->AuthSuites,
			       &wpa_key_mgmt, 4);
			mib->RSNConfigAuthSuites->Enabled = TRUE;
		} else if (!(crypto.wpa_versions & NL80211_WPA_VERSION_1) &&
			   (crypto.wpa_versions & NL80211_WPA_VERSION_2)) {
			mib->RSNConfigWPA2->WPA2Enabled = TRUE;
			mib->RSNConfigWPA2->WPA2OnlyEnabled = TRUE;

			memcpy(mib->WPA2AuthSuites->AuthSuites, &wpa_key_mgmt,
			       4);
			mib->WPA2AuthSuites->Enabled = TRUE;
		} else if ((crypto.wpa_versions & NL80211_WPA_VERSION_1) &&
			   (crypto.wpa_versions & NL80211_WPA_VERSION_2)) {
			mib->RSNConfigWPA2->WPA2Enabled = TRUE;
			mib->RSNConfigWPA2->WPA2OnlyEnabled = FALSE;

			memcpy(mib->WPA2AuthSuites->AuthSuites, &wpa_key_mgmt,
			       4);
			mib->WPA2AuthSuites->Enabled = TRUE;
		}
		return marvell_set_ciphersuite(dev, crypto.wpa_versions,
					       crypto.ciphers_pairwise[0],
					       crypto.cipher_group);
	}

	return 0;
}

static int
mwl_cfg80211_start_ap(struct wiphy *wiphy, struct net_device *dev,
		      struct cfg80211_ap_settings *params)
{
	int ret = 0;
	struct wlprivate *priv = mwl_netdev_get_priv(dev);
	u32 beacon_akm = 0;

	if (params->beacon_interval)
		mwl_config_set_bcninterval(priv->master,
					   params->beacon_interval);

	if (params->ssid && params->ssid_len && params->ssid_len <= 32)
		mwl_config_set_essid(dev, params->ssid, params->ssid_len);

	if ((params->crypto.wpa_versions & NL80211_WPA_VERSION_1) &&
	    !(params->crypto.wpa_versions & NL80211_WPA_VERSION_2)) {
		mwl_beacon_get_wpa(params->beacon, (u8 *) & beacon_akm);
	} else {
		mwl_beacon_get_rsn(params->beacon, (u8 *) & beacon_akm);
	}
	ret = mwl_configura_wpa(dev, params->crypto, beacon_akm);
	if (ret)
		return ret;

	if (params->beacon.beacon_ies) {
		struct mwl_appie appie;
		appie.type = MWL_APPIE_FRAMETYPE_BEACON;
		appie.len = params->beacon.beacon_ies_len;
		if (appie.len)
			memcpy(appie.buf, params->beacon.beacon_ies,
			       params->beacon.beacon_ies_len);
		else {
			appie.len = IE_BUF_LEN;
			memset(appie.buf, 0, IE_BUF_LEN);
		}
		mwl_config_set_appie(dev, (struct wlreq_set_appie *)&appie);
	}
	if (params->beacon.proberesp_ies) {
		struct mwl_appie appie;
		appie.type = MWL_APPIE_FRAMETYPE_PROBE_RESP;
		appie.len = params->beacon.proberesp_ies_len;
		if (appie.len)
			memcpy(appie.buf, params->beacon.proberesp_ies,
			       params->beacon.proberesp_ies_len);
		else {
			appie.len = IE_BUF_LEN;
			memset(appie.buf, 0, IE_BUF_LEN);
		}
		mwl_config_set_appie(dev, (struct wlreq_set_appie *)&appie);
	}

	return 0;
}

static int
mwl_cfg80211_stop_ap(struct wiphy *wiphy, struct net_device *dev)
{
	struct mwl_appie appie;
	struct wlprivate *priv = mwl_netdev_get_priv(dev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	appie.len = IE_BUF_LEN;
	memset(appie.buf, 0, IE_BUF_LEN);
	mwl_config_set_appie(dev, (struct wlreq_set_appie *)&appie);

	*(mib->mib_wpaWpa2Mode) = 0;
	mib->Privacy->RSNEnabled = 0;
	mib->Privacy->RSNLinkStatus = 0;
	mib->RSNConfigWPA2->WPA2Enabled = 0;
	mib->RSNConfigWPA2->WPA2OnlyEnabled = 0;
	vmacSta_p->RsnIESetByHost = 0;

	mwl_config_set_wepkey(dev, NULL, 0, MWL_WEP_ENCODE_DISABLED, 0);

	return 0;
}

static int
mwl_cfg80211_connect(struct wiphy *wiphy, struct net_device *dev,
		     struct cfg80211_connect_params *sme)
{
	int ret = 0;
	struct wlprivate *priv = mwl_netdev_get_priv(dev);

	if (sme->ssid && sme->ssid_len && sme->ssid_len <= 32)
		mwl_config_set_essid(dev, sme->ssid, sme->ssid_len);

	if (sme->channel && sme->channel->center_freq) {
		u8 channel =
			ieee80211_frequency_to_channel(sme->channel->
						       center_freq);
		mwl_config_set_channel(priv->master, channel);
	}

	ret = mwl_parse_conn_params(dev, sme);
	ret = mwl_configura_wpa(dev, sme->crypto, 0);
	mwl_config_commit(dev);

	return ret;
}

static int
mwl_cfg80211_disconnect(struct wiphy *wiphy, struct net_device *dev,
			u16 reason_code)
{
	struct mwl_mlme mlme;
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, dev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	vmacEntry_t *vmacEntry_p =
		sme_GetParentVMacEntry(vmacSta_p->VMacEntry.phyHwMacIndx);

	if (priv->wdev.current_bss &&
	    priv->wdev.iftype == NL80211_IFTYPE_STATION)
		cfg80211_disconnected(dev, 0, NULL, 0, TRUE, GFP_KERNEL);

	if (vmacEntry_p != NULL) {
		vmacStaInfo_t *vStaInfo_p =
			(vmacStaInfo_t *) vmacEntry_p->info_p;
		memcpy(mlme.macaddr, vStaInfo_p->macMgmtMlme_ThisStaData.BssId,
		       ETH_ALEN);
		mlme.op = MWL_MLME_DEAUTH;
		mlme.reason = reason_code;

		return mwl_config_send_mlme(dev, (struct wlreq_mlme *)&mlme);
	} else
		return 0;
}

static int
mwl_cfg80211_add_key(struct wiphy *wiphy, struct net_device *netdev,
		     u8 key_index, bool pairwise, const u8 * mac_addr,
		     struct key_params *params)
{
	u8 cipher;
	int ret = 0;
	struct wlreq_key *wk =
		(struct wlreq_key *)wl_kmalloc(sizeof(struct wlreq_key),
					       GFP_KERNEL);
	if (!wk)
		return -ENOMEM;

	switch (params->cipher) {
	case WLAN_CIPHER_SUITE_WEP40:
	case WLAN_CIPHER_SUITE_WEP104:
		cipher = MWL_CIPHER_WEP104;
		break;
	case WLAN_CIPHER_SUITE_TKIP:
		cipher = MWL_CIPHER_TKIP;
		break;
	case WLAN_CIPHER_SUITE_CCMP:
		cipher = MWL_CIPHER_CCMP;
		break;
	case WLAN_CIPHER_SUITE_AES_CMAC:
		cipher = MWL_CIPHER_IGTK;
		break;
	case WLAN_CIPHER_SUITE_CCMP_256:
		cipher = MWL_CIPHER_CCMP_256;
		break;
	case WLAN_CIPHER_SUITE_GCMP:
		cipher = MWL_CIPHER_GCMP;
		break;
	case WLAN_CIPHER_SUITE_GCMP_256:
		cipher = MWL_CIPHER_GCMP_256;
		break;
	case WLAN_CIPHER_SUITE_BIP_CMAC_256:
		cipher = MWL_CIPHER_AES_CMAC_256;
		break;
	case WLAN_CIPHER_SUITE_BIP_GMAC_128:
		cipher = MWL_CIPHER_AES_GMAC;
		break;
	case WLAN_CIPHER_SUITE_BIP_GMAC_256:
		cipher = MWL_CIPHER_AES_GMAC_256;
		break;
	default:
		ret = -EINVAL;
		goto exit;
	}

	if (params->key_len > WLAN_MAX_KEY_LEN) {
		ret = -EINVAL;
		goto exit;
	} else
		wk->ik_keylen = params->key_len;

	wk->ik_flags = MWL_KEY_RECV | MWL_KEY_XMIT;
	if (mac_addr == NULL || is_broadcast_ether_addr(mac_addr)) {
		memset(wk->ik_macaddr, 0xff, ETH_ALEN);
		wk->ik_flags |= MWL_KEY_DEFAULT;
		wk->ik_keyix = (u16) key_index;
	} else {
		memcpy(wk->ik_macaddr, mac_addr, ETH_ALEN);
		wk->ik_keyix = MWL_KEYIX_NONE;
	}

	memset(wk->ik_keydata, 0, WLAN_MAX_KEY_LEN);
	memcpy(wk->ik_keydata, params->key, params->key_len);
#ifdef CONFIG_IEEE80211W
	memcpy(wk->ik_pn, params->seq, params->seq_len);
#endif
	memcpy(&wk->ik_keytsc, params->seq, params->seq_len);
	wk->ik_type = cipher;

	ret = mwl_config_set_key(netdev, wk);

exit:
	wl_kfree(wk);
	return ret;
}

static int
mwl_cfg80211_del_key(struct wiphy *wiphy, struct net_device *netdev,
		     u8 key_index, bool pairwise, const u8 * mac_addr)
{
	u8 macaddr[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	if (mac_addr)
		memcpy(macaddr, mac_addr, ETH_ALEN);

	return mwl_config_del_key(netdev, key_index, macaddr);
}

static int
mwl_cfg80211_set_default_key(struct wiphy *wiphy,
			     struct net_device *netdev,
			     u8 key_index, bool unicast, bool multicast)
{
	return 0;
}

static int
mwl_cfg80211_set_default_mgmt_key(struct wiphy *wiphy,
				  struct net_device *netdev, u8 key_index)
{
	return 0;
}

static int
mwl_cfg80211_add_station(struct wiphy *wiphy, struct net_device *dev,
			 const u8 * mac, struct station_parameters *params)
{
	return 0;
}

static int
mwl_cfg80211_del_station(struct wiphy *wiphy, struct net_device *dev,
			 struct station_del_parameters *params)
{
	struct mwl_mlme mlme;

#ifdef MULTI_AP_SUPPORT
	static const char *tag = "1905_FAIL_CONN";
	struct mwl_failed_connection *failed_connection_p;
	unsigned char buf[IW_CUSTOM_MAX] = { 0 };
	union iwreq_data wreq;
	u8 send_event_to_map = 0;
#endif

	if (params->mac == NULL || is_broadcast_ether_addr(params->mac))
		memset(mlme.macaddr, 0xff, ETH_ALEN);
	else {
		memcpy(mlme.macaddr, params->mac, ETH_ALEN);
#ifdef MULTI_AP_SUPPORT
		send_event_to_map = 1;
#endif
	}

	if (params->subtype == IEEE80211_STYPE_DISASSOC >> 4)
		mlme.op = MWL_MLME_DISASSOC;
	else {
		mlme.op = MWL_MLME_DEAUTH;
#ifdef MULTI_AP_SUPPORT
		if (send_event_to_map) {
			snprintf(buf, sizeof(buf), "%s", tag);
			failed_connection_p =
				(struct mwl_failed_connection *)(buf +
								 strlen(tag));
			memcpy(failed_connection_p->sta_mac_addr, params->mac,
			       ETH_ALEN);
			failed_connection_p->reason = params->reason_code;
			memset(&wreq, 0, sizeof(wreq));
			wreq.data.length =
				strlen(tag) +
				sizeof(struct mwl_failed_connection);
			if (dev->flags & IFF_RUNNING)
				wireless_send_event(dev, IWEVCUSTOM, &wreq,
						    buf);
		}
#endif
	}
	mlme.reason = params->reason_code;

	return mwl_config_send_mlme(dev, (struct wlreq_mlme *)&mlme);
}

static int
mwl_cfg80211_change_station(struct wiphy *wiphy, struct net_device *dev,
			    const u8 * mac, struct station_parameters *params)
{
	return 0;
}

static struct mwl_sta_capability sta_capa;
static int
mwl_cfg80211_get_station(struct wiphy *wiphy, struct net_device *dev,
			 const u8 * mac, struct station_info *sinfo)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	extStaDb_StaInfo_t *pStaInfo = NULL;

	pStaInfo =
		extStaDb_GetStaInfo(vmacSta_p, (IEEEtypes_MacAddr_t *) mac,
				    STADB_DONT_UPDATE_AGINGTIME);
	if (!pStaInfo)
		return -ENODATA;

	sinfo->filled |= BIT(NL80211_STA_INFO_TX_BITRATE) |
		BIT(NL80211_STA_INFO_SIGNAL) | BIT(NL80211_STA_INFO_SIGNAL_AVG);
	sinfo->txrate.legacy =
		getPhyRate((dbRateInfo_t *) & (pStaInfo->RateInfo));
	sinfo->txrate.nss = getNss((dbRateInfo_t *) & (pStaInfo->RateInfo));
	sinfo->signal = -(pStaInfo->RSSI);
	sinfo->signal_avg = -(pStaInfo->RSSI);

	sinfo->filled |= BIT(NL80211_STA_INFO_RX_BYTES) |
		BIT(NL80211_STA_INFO_TX_BYTES) |
		BIT(NL80211_STA_INFO_RX_PACKETS) |
		BIT(NL80211_STA_INFO_TX_PACKETS);
	sinfo->tx_bytes = pStaInfo->tx_bytes;
	sinfo->tx_packets = pStaInfo->tx_packets;
	sinfo->rx_bytes = pStaInfo->rx_bytes;
	sinfo->rx_packets = pStaInfo->rx_packets;

	sinfo->filled |= BIT(NL80211_STA_INFO_INACTIVE_TIME) |
		BIT(NL80211_STA_INFO_CONNECTED_TIME);
#ifdef OPENWRT
	sinfo->connected_time = ktime_get_seconds() - pStaInfo->last_connected;
#else
	sinfo->connected_time = 0;
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)
	sinfo->inactive_time = jiffies_to_msecs(jiffies - dev->last_rx);
#endif

	memset(&sta_capa, 0, sizeof(sta_capa));
	memcpy(&sta_capa.htcap.cap, &pStaInfo->HtElem.HTCapabilitiesInfo,
	       sizeof(u16));
	memcpy(&sta_capa.htcap.mcs, pStaInfo->HtElem.SupportedMCSset, 16);
	memcpy(&sta_capa.vhtcap.cap, &pStaInfo->vhtCap.cap, sizeof(u32));
	sta_capa.vhtcap.vht_mcs.rx_mcs_map =
		pStaInfo->vhtCap.SupportedRxMcsSet & 0xffff;
	sta_capa.vhtcap.vht_mcs.rx_highest =
		(pStaInfo->vhtCap.SupportedRxMcsSet >> 16) & 0xffff;
	sta_capa.vhtcap.vht_mcs.tx_mcs_map =
		pStaInfo->vhtCap.SupportedTxMcsSet & 0xffff;
	sta_capa.vhtcap.vht_mcs.tx_highest =
		(pStaInfo->vhtCap.SupportedTxMcsSet >> 16) & 0xffff;

	sinfo->assoc_req_ies = (const u8 *)&sta_capa;
	sinfo->assoc_req_ies_len = sizeof(sta_capa);

	return 0;
}

static int
mwl_cfg80211_get_key(struct wiphy *wiphy, struct net_device *dev,
		     u8 key_index, bool pairwise, const u8 * mac_addr,
		     void *cookie, void (*callback) (void *cookie,
						     struct key_params *))
{
	int ret = 0;
	uint8_t seqnum[6];
	struct key_params params;

	memset(&params, 0, sizeof(params));
	ret = mwl_config_get_seqnum(dev, seqnum);
	if (!ret) {
		params.seq = seqnum;
		callback(cookie, &params);
	}

	return ret;
}

static int
mwl_cfg80211_change_beacon(struct wiphy *wiphy,
			   struct net_device *dev,
			   struct cfg80211_beacon_data *data)
{
	if (data->beacon_ies) {
		struct mwl_appie appie;
		appie.type = MWL_APPIE_FRAMETYPE_BEACON;
		appie.len = data->beacon_ies_len;
		if (appie.len)
			memcpy(appie.buf, data->beacon_ies,
			       data->beacon_ies_len);
		else {
			appie.len = IE_BUF_LEN;
			memset(appie.buf, 0, IE_BUF_LEN);
		}
		mwl_config_set_appie(dev, (struct wlreq_set_appie *)&appie);
	}
	if (data->proberesp_ies) {
		struct mwl_appie appie;
		appie.type = MWL_APPIE_FRAMETYPE_PROBE_RESP;
		appie.len = data->proberesp_ies_len;
		if (appie.len)
			memcpy(appie.buf, data->proberesp_ies,
			       data->proberesp_ies_len);
		else {
			appie.len = IE_BUF_LEN;
			memset(appie.buf, 0, IE_BUF_LEN);
		}
		mwl_config_set_appie(dev, (struct wlreq_set_appie *)&appie);
	}

	return 0;

}

static int
mwl_cfg80211_dump_survey(struct wiphy *wiphy, struct net_device *dev,
			 int idx, struct survey_info *survey)
{
	struct wlprivate *priv = mwl_netdev_get_master_priv(dev);
	mvl_status_t tmp_status;

	if (idx != 0)
		return -ENOENT;

	memset(&tmp_status, 0, sizeof(tmp_status));
	wlFwGetRadioStatus(priv->netDev, &tmp_status);

	survey->filled = SURVEY_INFO_TIME |
		SURVEY_INFO_TIME_BUSY |
		SURVEY_INFO_TIME_RX |
		SURVEY_INFO_TIME_TX | SURVEY_INFO_NOISE_DBM;

	survey->channel = &(priv->channel);
	survey->time = 255;
	survey->time_busy = tmp_status.total_load;
	survey->time_ext_busy = 0;
	survey->time_rx = tmp_status.rxload;
	survey->time_tx = tmp_status.load - tmp_status.rxload;
	survey->noise = -tmp_status.noise;

	return 0;
}

/* station cfg80211 operations */
const struct cfg80211_ops mwlwifi_cfg80211_ops = {
#ifdef CONFIG_PM
	.suspend = NULL,
	.resume = NULL,
	.set_wakeup = NULL,
#endif
	.add_virtual_intf = NULL,
	.del_virtual_intf = NULL,
	.change_virtual_intf = NULL,
	.add_key = mwl_cfg80211_add_key,
	.get_key = mwl_cfg80211_get_key,
	.del_key = mwl_cfg80211_del_key,
	.set_default_key = mwl_cfg80211_set_default_key,
	.set_default_mgmt_key = mwl_cfg80211_set_default_mgmt_key,
	.start_ap = mwl_cfg80211_start_ap,
	.change_beacon = mwl_cfg80211_change_beacon,
	.stop_ap = mwl_cfg80211_stop_ap,
	.add_station = mwl_cfg80211_add_station,
	.del_station = mwl_cfg80211_del_station,
	.change_station = mwl_cfg80211_change_station,
	.get_station = mwl_cfg80211_get_station,
	.dump_station = mwl_cfg80211_dump_station,
	/* cfg80211 mesh ops */
	/*
	   .add_mpath = NULL,
	   .del_mpath = NULL,
	   .change_mpath = NULL,
	   .get_mpath = NULL,
	   .dump_mpath = NULL,
	   .get_mpp = NULL,
	   .dump_mpp = NULL,
	   .get_mesh_config = NULL,
	   .update_mesh_config = NULL,
	   .join_mesh = NULL,
	   .leave_mesh = NULL,
	 */
	.join_ocb = NULL,
	.leave_ocb = NULL,
	.change_bss = NULL,
	.set_txq_params = NULL,
	.set_monitor_channel = NULL,
	.scan = mwl_cfg80211_scan,
	.auth = NULL,
	.assoc = NULL,
	.deauth = NULL,
	.disassoc = NULL,
	.connect = mwl_cfg80211_connect,
	.disconnect = mwl_cfg80211_disconnect,
	.join_ibss = NULL,
	.leave_ibss = NULL,
	.set_mcast_rate = NULL,
	.set_wiphy_params = NULL,
	.set_tx_power = NULL,
	.get_tx_power = NULL,
	.set_wds_peer = NULL,
	.rfkill_poll = NULL,
	.set_bitrate_mask = NULL,
	.dump_survey = mwl_cfg80211_dump_survey,
	.set_pmksa = NULL,
	.del_pmksa = NULL,
	.flush_pmksa = NULL,
	.remain_on_channel = NULL,
	.cancel_remain_on_channel = NULL,
	.mgmt_tx = mwl_cfg80211_mgmt_tx,
	.mgmt_tx_cancel_wait = NULL,
	.set_power_mgmt = NULL,
	.set_cqm_rssi_config = NULL,
	.set_cqm_txe_config = NULL,
	.mgmt_frame_register = mwl_cfg80211_mgmt_frame_register,
	.set_antenna = mwl_cfg80211_set_antenna,
	.get_antenna = mwl_cfg80211_get_antenna,
	.sched_scan_start = NULL,
	.sched_scan_stop = NULL,
	.set_rekey_data = NULL,
	.tdls_mgmt = NULL,
	.tdls_oper = NULL,
	.probe_client = NULL,
	.set_noack_map = NULL,
	.get_channel = mwl_cfg80211_get_channel,
	.start_p2p_device = NULL,
	.stop_p2p_device = NULL,
	.set_mac_acl = NULL,
	.start_radar_detection = NULL,
	.update_ft_ies = NULL,
	.crit_proto_start = NULL,
	.crit_proto_stop = NULL,
	.set_coalesce = NULL,
	.channel_switch = NULL,
	.set_qos_map = NULL,
	.set_ap_chanwidth = mwl_cfg80211_set_ap_chanwidth,
	.add_tx_ts = NULL,
	.del_tx_ts = NULL,
	.tdls_channel_switch = NULL,
	.tdls_cancel_channel_switch = NULL,
};

int
mwl_cfg80211_vendor_config_wpa(struct net_device *netdev,
			       struct cfg80211_beacon_data beacon,
			       struct cfg80211_crypto_settings crypto,
			       u8 * ssid, size_t ssid_len)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	u32 beacon_akm = 0;

	*(mib->mib_wpaWpa2Mode) = 4;

	//if (ssid && ssid_len && ssid_len <= 32)
	//      mwl_config_set_essid(netdev, ssid, ssid_len);

	if ((crypto.wpa_versions & NL80211_WPA_VERSION_1) &&
	    !(crypto.wpa_versions & NL80211_WPA_VERSION_2)) {
		mwl_beacon_get_wpa(beacon, (u8 *) & beacon_akm);
	} else {
		mwl_beacon_get_rsn(beacon, (u8 *) & beacon_akm);
	}

	return mwl_configura_wpa(netdev, crypto, beacon_akm);
}

static int
mwl_cfg80211_set_ht_caps(struct ieee80211_supported_band *band)
{
	band->ht_cap.ht_supported = 1;
	band->ht_cap.cap |= IEEE80211_HT_CAP_MAX_AMSDU;
	band->ht_cap.cap |= IEEE80211_HT_CAP_LDPC_CODING;
	band->ht_cap.cap |= IEEE80211_HT_CAP_SUP_WIDTH_20_40;
	band->ht_cap.cap |= IEEE80211_HT_CAP_SM_PS;
	band->ht_cap.cap |= IEEE80211_HT_CAP_SGI_20;
	band->ht_cap.cap |= IEEE80211_HT_CAP_SGI_40;
	band->ht_cap.cap |= IEEE80211_HT_CAP_DSSSCCK40;

	band->ht_cap.ampdu_factor = IEEE80211_HT_MAX_AMPDU_64K;
	band->ht_cap.ampdu_density = IEEE80211_HT_MPDU_DENSITY_4;

	band->ht_cap.mcs.rx_mask[0] = 0xff;
	band->ht_cap.mcs.rx_mask[1] = 0xff;
	band->ht_cap.mcs.rx_mask[2] = 0xff;
	band->ht_cap.mcs.rx_mask[4] = 0x01;

	band->ht_cap.mcs.tx_params = IEEE80211_HT_MCS_TX_DEFINED;

	return 0;
}

static int
mwl_cfg80211_set_vht_caps(struct ieee80211_supported_band *band)
{
	band->vht_cap.vht_supported = 1;

	band->vht_cap.cap |= IEEE80211_VHT_CAP_MAX_MPDU_LENGTH_11454;
	band->vht_cap.cap |= IEEE80211_VHT_CAP_SHORT_GI_160;
	band->vht_cap.cap |= IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_160MHZ;
	band->vht_cap.cap |= IEEE80211_VHT_CAP_RXLDPC;
	band->vht_cap.cap |= IEEE80211_VHT_CAP_SHORT_GI_80;
	band->vht_cap.cap |= IEEE80211_VHT_CAP_RXSTBC_1;
	band->vht_cap.cap |= IEEE80211_VHT_CAP_SU_BEAMFORMER_CAPABLE;
	band->vht_cap.cap |= IEEE80211_VHT_CAP_SU_BEAMFORMEE_CAPABLE;
	band->vht_cap.cap |= IEEE80211_VHT_CAP_MAX_A_MPDU_LENGTH_EXPONENT_MASK;
	band->vht_cap.cap |= IEEE80211_VHT_CAP_RX_ANTENNA_PATTERN;
	band->vht_cap.cap |= IEEE80211_VHT_CAP_TX_ANTENNA_PATTERN;

	band->vht_cap.vht_mcs.rx_mcs_map = cpu_to_le16(0xffea);
	band->vht_cap.vht_mcs.tx_mcs_map = cpu_to_le16(0xffea);

	return 0;
}

int
mwl_cfg80211_create(struct wlprivate *wlpptr, struct device *dev)
{
	int ret;
	void *wdev_priv;
	struct wiphy *wiphy;

	/* create a new wiphy for use with cfg80211 */
	wiphy = wiphy_new(&mwlwifi_cfg80211_ops, sizeof(struct wlprivate *));

	if (!wiphy) {
		printk(KERN_ERR "%s: creating new wiphy %s\n", __func__,
		       wlpptr->netDev->name);
		return -ENOMEM;
	}

	/* marvell full mac driver have ap mlme */
	wiphy->flags |= WIPHY_FLAG_HAVE_AP_SME;
	wiphy->flags |= WIPHY_FLAG_IBSS_RSN;
	wiphy->flags |= WIPHY_FLAG_HAS_CHANNEL_SWITCH;
	wiphy->flags |= WIPHY_FLAG_SUPPORTS_TDLS;

	wiphy->signal_type = CFG80211_SIGNAL_TYPE_MBM;

	wiphy->max_scan_ssids = 4;
	wiphy->max_scan_ie_len = 2247;
	wiphy->available_antennas_tx = 0xF;
	wiphy->available_antennas_rx = 0xF;
	wiphy->mgmt_stypes = mwl_mgmt_stypes;

	wiphy->features |= NL80211_FEATURE_INACTIVITY_TIMER;

	wiphy->interface_modes = 0;
	wiphy->interface_modes |= BIT(NL80211_IFTYPE_AP);
	wiphy->interface_modes |= BIT(NL80211_IFTYPE_STATION);
	wiphy->interface_modes |= BIT(NL80211_IFTYPE_MONITOR);
	wiphy->interface_modes |= BIT(NL80211_IFTYPE_WDS);
	wiphy->iface_combinations = &ap_if_comb;
	wiphy->n_iface_combinations = 1;
	wiphy->addresses = (struct mac_address *)wlpptr->netDev->dev_addr;
	wiphy->n_addresses = 1;

	/* now the driver don't have band info, just difference with cardIndex */
	wiphy->bands[NL80211_BAND_5GHZ] = &mwl_band_50;
	/* Set parameters according to the requirement for iwinfo */
	mwl_cfg80211_set_ht_caps(wiphy->bands[NL80211_BAND_5GHZ]);
	mwl_cfg80211_set_vht_caps(wiphy->bands[NL80211_BAND_5GHZ]);
	if (wlpptr->devid == SCBT) {
		wiphy->bands[NL80211_BAND_2GHZ] = &mwl_band_24;
		/* Set parameters according to the requirement for iwinfo */
		mwl_cfg80211_set_ht_caps(wiphy->bands[NL80211_BAND_2GHZ]);
		mwl_cfg80211_set_vht_caps(wiphy->bands[NL80211_BAND_2GHZ]);
	}

	wiphy->regulatory_flags = REGULATORY_WIPHY_SELF_MANAGED;

	/* initialize cipher suits */
	wiphy->cipher_suites = mwl_cipher_suites;
	wiphy->n_cipher_suites = ARRAY_SIZE(mwl_cipher_suites);

	/* vendor commands/events support */
	mwl_set_vendor_commands(wiphy);

	/* set struct wlprivate pointer in wiphy_priv */
	wdev_priv = wiphy_priv(wiphy);
	*(unsigned long *)wdev_priv = (unsigned long)wlpptr;

	set_wiphy_dev(wiphy, dev);

	ret = wiphy_register(wiphy);
	if (ret < 0) {
		printk(KERN_ERR "%s: wiphy_register failed: %d\n", __func__,
		       ret);
		wiphy_free(wiphy);
		return ret;
	}
	wlpptr->wiphy = wiphy;
	TimerInit(&scanTimer);

	return ret;
}

void
mwl_cfg80211_destroy(struct wlprivate *wlpptr)
{
	wiphy_unregister(wlpptr->wiphy);
	wiphy_free(wlpptr->wiphy);
}

int
mwl_cfg80211_rx_mgmt(struct net_device *netdev, void *buf, size_t len,
		     uint8_t rssi)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);

	if ((netdev->flags & IFF_RUNNING) == 0)
		return 0;

	cfg80211_rx_mgmt(&priv->wdev, priv->channel.center_freq, rssi, buf, len,
			 0);

	return 0;
}

//TODO remove it

void
mwl_cfg80211_hex_dump(const char *title, uint8_t * buf, size_t len)
{
	int i;
	printk("%s - %s - hexdump(len=%lu):\n", "[cfg80211]", title,
	       (unsigned long)len);
	if (buf == NULL) {
		printk(" [NULL]");
	} else {
		for (i = 0; i < len; i++) {
			printk(" %02x", buf[i]);
			if ((i + 1) % 16 == 0)
				printk("\n");
		}
	}
	printk("\n");
}

void
mwl_cfg80211_hex_ascii_dump(const char *title, uint8_t * buf, size_t len)
{
	size_t i, llen;
	const uint8_t *pos = buf;
	const size_t line_len = 16;

	printk("%s - %s - hexdump_ascii(len=%lu):\n", "[cfg80211]", title,
	       (unsigned long)len);
	while (len) {
		llen = len > line_len ? line_len : len;
		printk("    ");
		for (i = 0; i < llen; i++)
			printk(" %02x", pos[i]);
		for (i = llen; i < line_len; i++)
			printk("   ");
		printk("   ");
		for (i = 0; i < llen; i++) {
			if (isprint(pos[i]))
				printk("%c", pos[i]);
			else
				printk("_");
		}
		for (i = llen; i < line_len; i++)
			printk(" ");
		printk("\n");
		pos += llen;
		len -= llen;
	}
}

int
mwl_cfg80211_assoc_event(struct net_device *netdev, uint8_t * macaddr)
{
	int ret;
	UINT16 ret_len = 0;
	struct station_info sinfo;
	struct wlreq_ie IEReq;

	if ((netdev->flags & IFF_RUNNING) == 0)
		return 0;

	IEReq.IEtype = RSN_IEWPA2;
	memcpy(IEReq.macAddr, macaddr, 6);
	ret = mwl_config_get_ie(netdev, &IEReq, &ret_len);
	if (!ret) {
		memset(&sinfo, 0, sizeof(sinfo));
		sinfo.assoc_req_ies = IEReq.IE;
		sinfo.assoc_req_ies_len = IEReq.IELen;
		cfg80211_new_sta(netdev, macaddr, &sinfo, GFP_ATOMIC);
	}

	return 0;
}

int
mwl_cfg80211_disassoc_event(struct net_device *netdev, uint8_t * macaddr)
{
	if ((netdev->flags & IFF_RUNNING) == 0)
		return 0;

	cfg80211_del_sta(netdev, macaddr, GFP_ATOMIC);

	return 0;
}

int
mwl_cfg80211_connect_result_event(struct net_device *netdev, uint8_t * macaddr,
				  uint8_t status)
{
	struct wireless_dev *wdev = netdev->ieee80211_ptr;

	if ((netdev->flags & IFF_RUNNING) == 0)
		return 0;

	if (cfg80211_get_bss
	    (wdev->wiphy, NULL, macaddr, wdev->ssid, wdev->ssid_len,
	     IEEE80211_BSS_TYPE_ESS, IEEE80211_PRIVACY_ANY))
		cfg80211_connect_result(netdev, macaddr, NULL, 0, NULL, 0,
					status, GFP_KERNEL);

	return 0;
}

int
mwl_cfg80211_ch_switch_notify(struct net_device *netdev)
{
	struct cfg80211_chan_def chandef;
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	int i;

	if (priv->master)
		return 0;
	if ((netdev->flags & IFF_RUNNING) == 0)
		return 0;

	mwl_cfg80211_get_channel(priv->wiphy, &(priv->wdev), &chandef);
	for (i = 0; i < bss_num; i++) {
		if ((priv->vdev[i]->flags & IFF_RUNNING) == 0)
			continue;
		cfg80211_ch_switch_notify(priv->vdev[i], &chandef);
	}

	return 0;
}
