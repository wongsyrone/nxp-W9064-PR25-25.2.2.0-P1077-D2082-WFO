/** @file vendor.c
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

/* Description:  This file implements vendor commands related functions. */

#include <net/netlink.h>
#include "ap8xLnxIntf.h"

#include "ap8xLnxApi.h"
#include "cfg80211.h"
#include "vendor.h"
#include "ioctl_cfg80211.h"
#include "macMgmtMlme.h"
#include "msan_report.h"

static const
struct nla_policy mwl_vendor_attr_policy[NUM_MWL_VENDOR_ATTR] = {
	[MWL_VENDOR_ATTR_APPIE] = {.type = NLA_BINARY,.len = 512},
	[MWL_VENDOR_ATTR_MLME] = {.type = NLA_BINARY,.len =
				  sizeof(struct mwl_mlme)},
#ifdef BAND_STEERING
	[MWL_VENDOR_ATTR_BANDSTEER] = {.type = NLA_U8},
#endif /* BAND_STEERING */
	[MWL_VENDOR_ATTR_RRM] = {.type = NLA_U8},
	[MWL_VENDOR_ATTR_WPAWPA2MODE] = {.type = NLA_U8},
	[MWL_VENDOR_ATTR_MGMT] = {.type = NLA_BINARY,.len = 512},
	[MWL_VENDOR_ATTR_SSID] = {.type = NLA_BINARY,.len = 512},
	[MWL_VENDOR_ATTR_WPA] = {.type = NLA_BINARY,.len = 512},
	[MWL_VENDOR_ATTR_MAC_ADDRESS] = {.type = NLA_BINARY,.len = ETH_ALEN},
	[MWL_VENDOR_ATTR_ASSOC_REQ_FRAME] = {.type = NLA_BINARY,.len =
					     sizeof(struct assoc_req_msg_t)},
	[MWL_VENDOR_ATTR_STATION_INFO] = {.type = NLA_BINARY,.len =
					  sizeof(struct station_info)},
	[MWL_VENDOR_ATTR_HT_CAPA] = {.type = NLA_BINARY,.len =
				     sizeof(IEEEtypes_HT_Element_t)}
	,
	[MWL_VENDOR_ATTR_VHT_CAPA] = {.type = NLA_BINARY,.len =
				      sizeof(IEEEtypes_VhtCap_t)}
	,
	[MWL_VENDOR_ATTR_HE_CAPA] = {.type = NLA_BINARY,.len =
				     sizeof(HE_Capabilities_IE_t)}
	,
	[MWL_VENDOR_ATTR_UTILIZATION] = {.type = NLA_BINARY,.len = NLA_U8}
	,
	[MWL_VENDOR_ATTR_UTIL_RX_SELF] = {.type = NLA_BINARY,.len = NLA_U8}
	,
	[MWL_VENDOR_ATTR_UTIL_RX_OTHER] = {.type = NLA_BINARY,.len = NLA_U8}
	,
	[MWL_VENDOR_ATTR_UTIL_TX] = {.type = NLA_BINARY,.len = NLA_U8}
	,
	[MWL_VENDOR_ATTR_UTIL_RX] = {.type = NLA_BINARY,.len = NLA_U8}
	,
	[MWL_VENDOR_ATTR_ESPI] = {.type = NLA_BINARY,.len =
				  sizeof(struct mwl_espi_info)},
	[MWL_VENDOR_ATTR_UNASSOCIATED_STA_LINK_METRICS_QUERY] = {.type =
								 NLA_BINARY,.
								 len =
								 sizeof(struct
									unassociated_sta_link_metrics_query)},
	[MWL_VENDOR_ATTR_UNASSOCIATED_STA_LINK_METRICS_RESP] = {.type =
								NLA_BINARY,.
								len =
								UNASSOC_RESP_SIZE},
	[MWL_VENDOR_ATTR_AP_RADIO_BASIC_CAPABILITIES] = {.type =
							 NLA_BINARY,.len =
							 AP_RADIO_BASIC_CAPA_SIZE},
};

static int
mwl_vendor_cmd_commit(struct wiphy *wiphy,
		      struct wireless_dev *wdev, const void *data, int data_len)
{
	return mwl_config_commit(wdev->netdev);
}

static int
mwl_vendor_cmd_send_mlme(struct wiphy *wiphy,
			 struct wireless_dev *wdev,
			 const void *data, int data_len)
{
	int ret;
	struct nlattr *tb[NUM_MWL_VENDOR_ATTR];
	struct wlreq_mlme *mlme;

	if (!data)
		return -EINVAL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,12,0)
	ret = nla_parse(tb, MAX_MWL_VENDOR_ATTR, data, data_len,
			mwl_vendor_attr_policy);
#else
	ret = nla_parse(tb, MAX_MWL_VENDOR_ATTR, data, data_len,
			mwl_vendor_attr_policy, NULL);
#endif
	if (ret)
		return ret;

	if (!tb[MWL_VENDOR_ATTR_MLME])
		return -EINVAL;

	mlme = (struct wlreq_mlme *)nla_data(tb[MWL_VENDOR_ATTR_MLME]);

	return mwl_config_send_mlme(wdev->netdev, mlme);
}

static int
mwl_vendor_cmd_set_appie(struct wiphy *wiphy,
			 struct wireless_dev *wdev,
			 const void *data, int data_len)
{
	int ret;
	struct nlattr *tb[NUM_MWL_VENDOR_ATTR];
	struct wlreq_set_appie *appie;

	if (!data)
		return -EINVAL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,12,0)
	ret = nla_parse(tb, MAX_MWL_VENDOR_ATTR, data, data_len,
			mwl_vendor_attr_policy);
#else
	ret = nla_parse(tb, MAX_MWL_VENDOR_ATTR, data, data_len,
			mwl_vendor_attr_policy, NULL);
#endif
	if (ret)
		return ret;

	if (!tb[MWL_VENDOR_ATTR_APPIE])
		return -EINVAL;

	appie = (struct wlreq_set_appie *)nla_data(tb[MWL_VENDOR_ATTR_APPIE]);

	return mwl_config_set_appie(wdev->netdev, appie);
}

#ifdef BAND_STEERING
int
mwl_drv_send_mgmt(struct net_device *netdev, struct mwl_mgmt *mgmt)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	IEEEtypes_Frame_t *wlanMsg_p;
	IEEEtypes_MacAddr_t bcastMacAddr =
		{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
	wlanMsg_p = (IEEEtypes_Frame_t *) mgmt;

	if (memcmp(wlanMsg_p->Hdr.Addr1, vmacSta_p->macBssId, 6) == 0 ||
	    memcmp(wlanMsg_p->Hdr.Addr1, bcastMacAddr, 6) == 0) {
		struct sk_buff *skb = wl_alloc_skb(mgmt->len + 6);
		if (skb == NULL) {
			printk("band steering alloc skb failed\n");
			return -ENOMEM;
		}

		memcpy(skb->data, mgmt->buf, 24);
		memcpy(skb->data + 30, &mgmt->buf[24], mgmt->len - 24);
		skb_put(skb, mgmt->len + 6);

		wlanMsg_p = (IEEEtypes_Frame_t *) ((UINT8 *) skb->data - 2);
		wlanMsg_p->Hdr.FrmBodyLen = mgmt->len + 6;

		switch (wlanMsg_p->Hdr.FrmCtl.Subtype) {
			extern SINT8 evtDot11MgtMsg(vmacApInfo_t * vmacSta_p,
						    UINT8 * message,
						    struct sk_buff *skb,
						    UINT32 rssi);

		case IEEE_MSG_PROBE_RQST:
			if (memcmp(wlanMsg_p->Hdr.Addr1, bcastMacAddr, 6) == 0)
				memcpy(wlanMsg_p->Hdr.Addr1,
				       vmacSta_p->macBssId, 6);

			macMgmtMlme_ProbeRqst(vmacSta_p,
					      (macmgmtQ_MgmtMsg3_t *)
					      wlanMsg_p);
			break;
		case IEEE_MSG_AUTHENTICATE:
			evtDot11MgtMsg(vmacSta_p, (UINT8 *) wlanMsg_p, skb, 0);
			break;
		default:
			break;
		}
		wl_free_skb(skb);
	}

	return 0;
}

static int
mwl_vendor_cmd_set_bandsteer(struct wiphy *wiphy,
			     struct wireless_dev *wdev,
			     const void *data, int data_len)
{
	struct wlprivate *priv = mwl_netdev_get_priv(wdev->netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	int ret;
	struct nlattr *tb[NUM_MWL_VENDOR_ATTR];
	UINT8 value;

	if (!data)
		return -EINVAL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,12,0)
	ret = nla_parse(tb, MAX_MWL_VENDOR_ATTR, data, data_len,
			mwl_vendor_attr_policy);
#else
	ret = nla_parse(tb, MAX_MWL_VENDOR_ATTR, data, data_len,
			mwl_vendor_attr_policy, NULL);
#endif
	if (ret)
		return ret;

	if (!tb[MWL_VENDOR_ATTR_BANDSTEER])
		return -EINVAL;

	value = nla_get_u8(tb[MWL_VENDOR_ATTR_BANDSTEER]);

	if (value == 1) {
		*(mib->mib_bandsteer) = value;
		*(mib->mib_bandsteer_handler) = BAND_STEERING_HDL_BY_HOST;
	} else {		//(value == 0)
		if ((*(mib->mib_bandsteer) == 0) ||
		    ((*(mib->mib_bandsteer) == 1) &&
		     (*(mib->mib_bandsteer_handler) ==
		      BAND_STEERING_HDL_BY_HOST))) {
			*(mib->mib_bandsteer) = value;
			*(mib->mib_bandsteer_handler) =
				BAND_STEERING_HDL_BY_DRV;
		}
	}

	return 0;
}

static int
mwl_vendor_cmd_send_mgmt(struct wiphy *wiphy,
			 struct wireless_dev *wdev,
			 const void *data, int data_len)
{
	int ret;
	struct nlattr *tb[NUM_MWL_VENDOR_ATTR];
	struct mwl_mgmt *mgmt;

	if (!data)
		return -EINVAL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,12,0)
	ret = nla_parse(tb, MAX_MWL_VENDOR_ATTR, data, data_len,
			mwl_vendor_attr_policy);
#else
	ret = nla_parse(tb, MAX_MWL_VENDOR_ATTR, data, data_len,
			mwl_vendor_attr_policy, NULL);
#endif
	if (ret)
		return ret;

	if (!tb[MWL_VENDOR_ATTR_MGMT])
		return -EINVAL;

	mgmt = (struct mwl_mgmt *)nla_data(tb[MWL_VENDOR_ATTR_MGMT]);

	return mwl_drv_send_mgmt(wdev->netdev, mgmt);
}

#endif /* BAND_STEERING */

#ifdef IEEE80211K
static int
mwl_vendor_cmd_set_rrm(struct wiphy *wiphy,
		       struct wireless_dev *wdev,
		       const void *data, int data_len)
{
	struct wlprivate *priv = mwl_netdev_get_priv(wdev->netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	int ret;
	struct nlattr *tb[NUM_MWL_VENDOR_ATTR];

	if (!data)
		return -EINVAL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,12,0)
	ret = nla_parse(tb, MAX_MWL_VENDOR_ATTR, data, data_len,
			mwl_vendor_attr_policy);
#else
	ret = nla_parse(tb, MAX_MWL_VENDOR_ATTR, data, data_len,
			mwl_vendor_attr_policy, NULL);
#endif
	if (ret)
		return ret;

	if (!tb[MWL_VENDOR_ATTR_RRM])
		return -EINVAL;

	mib->mib_conf_capab->rrm = nla_get_u8(tb[MWL_VENDOR_ATTR_RRM]);

	return 0;
}

static int
mwl_vendor_cmd_get_rrm(struct wiphy *wiphy,
		       struct wireless_dev *wdev,
		       const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}
#endif

#ifdef AUTOCHANNEL
static int
mwl_vendor_cmd_do_acs(struct wiphy *wiphy,
		      struct wireless_dev *wdev, const void *data, int data_len)
{
	struct net_device *netdev = wdev->netdev;
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	struct wlprivate *priv_master;
	vmacApInfo_t *vmacSta_p;
	MIB_PHY_DSSS_TABLE *PhyDSSSTable;;

	if (priv->master)
		priv_master = mwl_netdev_get_priv(priv->master);
	else
		priv_master = priv;

	vmacSta_p = priv_master->vmacSta_p;
	PhyDSSSTable = vmacSta_p->ShadowMib802dot11->PhyDSSSTable;

	if (vmacSta_p->preautochannelfinished)
		mwl_send_vendor_acs_completed(netdev, PhyDSSSTable->CurrChan);

	return 0;
}
#endif

#ifdef MULTI_AP_SUPPORT
static int
mwl_vendor_cmd_get_multiap(struct wiphy *wiphy,
			   struct wireless_dev *wdev,
			   const void *data, int data_len)
{
	struct sk_buff *skb;
	uint8_t multiap;

	struct wlprivate *priv = mwl_netdev_get_priv(wdev->netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 8);
	if (skb == NULL)
		return -ENOMEM;

	multiap = mib->multi_ap_attr;

	if (nla_put_u8(skb, MWL_VENDOR_ATTR_MULTIAP, multiap)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}
#endif /* MULTI_AP_SUPPORT */

static int
mwl_vendor_cmd_set_wpawpa2mode(struct wiphy *wiphy,
			       struct wireless_dev *wdev,
			       const void *data, int data_len)
{
	struct wlprivate *priv = mwl_netdev_get_priv(wdev->netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	int ret;
	struct nlattr *tb[NUM_MWL_VENDOR_ATTR];

	if (!data)
		return -EINVAL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,12,0)
	ret = nla_parse(tb, MAX_MWL_VENDOR_ATTR, data, data_len,
			mwl_vendor_attr_policy);
#else
	ret = nla_parse(tb, MAX_MWL_VENDOR_ATTR, data, data_len,
			mwl_vendor_attr_policy, NULL);
#endif
	if (ret)
		return ret;

	if (!tb[MWL_VENDOR_ATTR_WPAWPA2MODE])
		return -EINVAL;

	/* Sync with mwl_configura_wpa to set wpaWpa2Mode as 4 if hostapd config wpa/wpa2 */
	*(mib->mib_wpaWpa2Mode) = 4;	//nla_get_u8(tb[MWL_VENDOR_ATTR_WPAWPA2MODE]);
	mib_Update();

	return 0;
}

extern int mwl_config_set_essid(struct net_device *netdev, const char *ssid,
				uint8_t ssid_len);
static int
mwl_vendor_cmd_set_ssid(struct wiphy *wiphy,
			struct wireless_dev *wdev,
			const void *data, int data_len)
{
	struct net_device *netdev = wdev->netdev;
	struct nlattr *tb[NUM_MWL_VENDOR_ATTR];
	uint8_t *ssid;
	int ssid_len;
	int ret;

	if (!data)
		return -EINVAL;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,12,0)
	ret = nla_parse(tb, MAX_MWL_VENDOR_ATTR, data, data_len,
			mwl_vendor_attr_policy);
#else
	ret = nla_parse(tb, MAX_MWL_VENDOR_ATTR, data, data_len,
			mwl_vendor_attr_policy, NULL);
#endif
	if (ret)
		return ret;

	if (!tb[MWL_VENDOR_ATTR_SSID])
		return -EINVAL;

	ssid = nla_data(tb[MWL_VENDOR_ATTR_SSID]);
	ssid_len = nla_len(tb[MWL_VENDOR_ATTR_SSID]);

	if (ssid && ssid_len && ssid_len <= 32)
		mwl_config_set_essid(netdev, ssid, ssid_len);

	return 0;
}

static int
mwl_vendor_cmd_get_ssid(struct wiphy *wiphy,
			struct wireless_dev *wdev,
			const void *data, int data_len)
{
	struct sk_buff *skb;
	struct wlprivate *priv = mwl_netdev_get_priv(wdev->netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	uint8_t ssid[32];
	int ssid_len;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 32);
	if (skb == NULL)
		return -ENOMEM;

	memset(ssid, 0, 32);
	ssid_len = strlen(&(mib->StationConfig->DesiredSsId[0]));
	ssid_len = (ssid_len > 32) ? 32 : ssid_len;
	memcpy(ssid, &(mib->StationConfig->DesiredSsId[0]), ssid_len);

	if (nla_put_string(skb, MWL_VENDOR_ATTR_SSID, ssid)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_config_wpa(struct wiphy *wiphy,
			  struct wireless_dev *wdev,
			  const void *data, int data_len)
{
	struct net_device *netdev = wdev->netdev;
	struct nlattr *tb[NUM_MWL_VENDOR_ATTR];
	struct mwl_ap_settings *ap_settings;
	struct cfg80211_beacon_data beacon;
	struct cfg80211_crypto_settings crypto;
	int ret;

	if (!data)
		return -EINVAL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,12,0)
	ret = nla_parse(tb, MAX_MWL_VENDOR_ATTR, data, data_len,
			mwl_vendor_attr_policy);
#else
	ret = nla_parse(tb, MAX_MWL_VENDOR_ATTR, data, data_len,
			mwl_vendor_attr_policy, NULL);
#endif
	if (ret)
		return ret;

	if (!tb[MWL_VENDOR_ATTR_WPA])
		return -EINVAL;

	ap_settings =
		(struct mwl_ap_settings *)nla_data(tb[MWL_VENDOR_ATTR_WPA]);

	memset(&beacon, 0, sizeof(struct cfg80211_beacon_data));
	beacon.tail = ap_settings->beacon.tail;
	memset(&crypto, 0, sizeof(struct cfg80211_crypto_settings));
	memcpy(&crypto, &ap_settings->crypto,
	       sizeof(struct mwl_crypto_settings));

	mwl_cfg80211_vendor_config_wpa(netdev, beacon, crypto,
				       ap_settings->ssid,
				       ap_settings->ssid_len);
	mib_Update();
	return 0;
}

extern void fillApCapInfo(struct net_device *netdev, int mode, u8 * pApCap,
			  u32 * pLen);
static int
mwl_vendor_cmd_get_band_capa(struct wiphy *wiphy,
			     struct wireless_dev *wdev,
			     const void *data, int data_len)
{
	struct wlprivate *priv = mwl_netdev_get_priv(wdev->netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	struct sk_buff *skb;
	//struct ieee80211_ht_cap ht_cap;
	IEEEtypes_HT_Element_t ht_cap;
	//struct ieee80211_vht_cap vht_cap;
	IEEEtypes_VhtCap_t vht_cap;
	HE_Capabilities_IE_t he_cap;
	size_t ht_cap_len = 0;
	size_t vht_cap_len = 0;
	size_t he_cap_len = 0;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy,
						  10 +
						  sizeof(IEEEtypes_HT_Element_t)
						  + sizeof(IEEEtypes_VhtCap_t) +
						  sizeof(HE_Capabilities_IE_t));
	if (skb == NULL)
		return -ENOMEM;

	memset(&ht_cap, 0, sizeof(IEEEtypes_HT_Element_t));
	memset(&vht_cap, 0, sizeof(IEEEtypes_VhtCap_t));
	memset(&he_cap, 0, sizeof(HE_Capabilities_IE_t));

	fillApCapInfo(wdev->netdev, 0, (u8 *) & ht_cap, (u32 *) & ht_cap_len);
	if (nla_put
	    (skb, MWL_VENDOR_ATTR_HT_CAPA, sizeof(IEEEtypes_HT_Element_t),
	     &ht_cap)) {
		kfree_skb(skb);
		return -EMSGSIZE;
	}

	if (*(mib->mib_ApMode) & AP_MODE_11AC) {
		fillApCapInfo(wdev->netdev, 1, (u8 *) & vht_cap,
			      (u32 *) & vht_cap_len);
		if (nla_put
		    (skb, MWL_VENDOR_ATTR_VHT_CAPA, sizeof(IEEEtypes_VhtCap_t),
		     &vht_cap)) {
			kfree_skb(skb);
			return -EMSGSIZE;
		}
	}

	if (*(mib->mib_ApMode) & AP_MODE_11AX) {
		fillApCapInfo(wdev->netdev, 2, (u8 *) & he_cap,
			      (u32 *) & he_cap_len);
		if (nla_put
		    (skb, MWL_VENDOR_ATTR_HE_CAPA, sizeof(HE_Capabilities_IE_t),
		     &he_cap)) {
			kfree_skb(skb);
			return -EMSGSIZE;
		}
	}
	//if (nla_put(skb, MWL_VENDOR_ATTR_HT_CAPA, sizeof(IEEEtypes_HT_Element_t), &ht_cap) ||
	//    nla_put(skb, MWL_VENDOR_ATTR_VHT_CAPA, sizeof(IEEEtypes_VhtCap_t), &vht_cap) ||
	//    nla_put(skb, MWL_VENDOR_ATTR_HE_CAPA, sizeof(HE_Capabilities_IE_t), &he_cap)) {
	//      kfree_skb(skb);
	//      return -EMSGSIZE;
	//}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_get_channel_util(struct wiphy *wiphy,
				struct wireless_dev *wdev,
				const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_netdev_get_priv(wdev->netdev);
	//vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	struct sk_buff *skb;
	/* TBD */
	uint8_t util = 0, util_rx_self = 0, util_rx_other = 0, util_tx = 0;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 8);
	if (skb == NULL)
		return -ENOMEM;

	if (nla_put_u8(skb, MWL_VENDOR_ATTR_UTILIZATION, util) ||
	    nla_put_u8(skb, MWL_VENDOR_ATTR_UTIL_RX_SELF, util_rx_self) ||
	    nla_put_u8(skb, MWL_VENDOR_ATTR_UTIL_RX_OTHER, util_rx_other) ||
	    nla_put_u8(skb, MWL_VENDOR_ATTR_UTIL_TX, util_tx)) {
		kfree_skb(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

extern void fillStaInfo(struct net_device *netdev, struct station_info *pSinfo,
			struct extStaDb_StaInfo_t *pStaInfo);
static int
mwl_vendor_cmd_get_station_info(struct wiphy *wiphy,
				struct wireless_dev *wdev,
				const void *data, int data_len)
{
	struct wlprivate *priv = mwl_netdev_get_priv(wdev->netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	struct sk_buff *skb;
	struct nlattr *tb[NUM_MWL_VENDOR_ATTR];
	uint8_t macaddr[ETH_ALEN];
	extStaDb_StaInfo_t *pStaInfo = NULL;
	/* TBD */
	uint8_t util_tx = 10, util_rx = 20;
	//struct station_info *sinfo = NULL;
	struct station_info sinfo;
	struct wlreq_ie IEReq;
	int ret;

	if (!data)
		return -EINVAL;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,12,0)
	ret = nla_parse(tb, MAX_MWL_VENDOR_ATTR, data, data_len,
			mwl_vendor_attr_policy);
#else
	ret = nla_parse(tb, MAX_MWL_VENDOR_ATTR, data, data_len,
			mwl_vendor_attr_policy, NULL);
#endif

	if (ret)
		return ret;

	if (!tb[MWL_VENDOR_ATTR_MAC_ADDRESS])
		return -EINVAL;

	memcpy((void *)macaddr,
	       (const void *)nla_data(tb[MWL_VENDOR_ATTR_MAC_ADDRESS]),
	       ETH_ALEN);
	//macaddr = nla_data(tb[MWL_VENDOR_ATTR_MAC_ADDRESS]);

	pStaInfo =
		extStaDb_GetStaInfo(vmacSta_p, (IEEEtypes_MacAddr_t *) macaddr,
				    STADB_DONT_UPDATE_AGINGTIME);
	if (!pStaInfo)
		return -ENODATA;

	sinfo.assoc_req_ies = IEReq.IE;
	fillStaInfo(vmacSta_p->dev, &sinfo, pStaInfo);

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy,
						  10 + ETH_ALEN +
						  sizeof(struct station_info) +
						  8);
	if (skb == NULL)
		return -ENOMEM;

	if (nla_put(skb, MWL_VENDOR_ATTR_MAC_ADDRESS, ETH_ALEN, macaddr) ||
	    nla_put(skb, MWL_VENDOR_ATTR_STATION_INFO,
		    sizeof(struct station_info), &sinfo) ||
	    nla_put_u8(skb, MWL_VENDOR_ATTR_UTIL_TX, util_tx) ||
	    nla_put_u8(skb, MWL_VENDOR_ATTR_UTIL_RX, util_rx)) {
		kfree_skb(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_get_espi(struct wiphy *wiphy,
			struct wireless_dev *wdev,
			const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_netdev_get_priv(wdev->netdev);
	//vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	struct sk_buff *skb;
	/* TBD */
	struct mwl_espi_info espi_info;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy,
						  10 +
						  sizeof(struct mwl_espi_info));
	if (skb == NULL)
		return -ENOMEM;

	/* TBD */
	memset(&espi_info, 0, sizeof(struct mwl_espi_info));

	if (nla_put
	    (skb, MWL_VENDOR_ATTR_ESPI, sizeof(struct mwl_espi_info),
	     &espi_info)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

extern void unassocsta_track_deinit(struct wlprivate *wlpptr);
void
mwl_vendor_cmd_get_unassociated_sta_timeout(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);

	if (!priv->wlpd_p->unassocSTA.unassocsta_query)
		return;

	/* unassociated STA tracking is completed, send event to upper layer */
	if (priv->wlpd_p->unassocSTA.isTrackCompleted)
		goto send_event;

	/* Triger new timer to wait unassociated STA tracking is completed */
	/* To avoid no response from FW when doing unassociated STA tracking,       *
	 * wait for more than 5 times, stop the track and send event to upper layer */
	if (++priv->wlpd_p->unassocSTA.wiatMaxCount > 5)
		goto send_event;

	/* offchan scan is not completed, wait more 200ms */
	TimerDisarm(&priv->wlpd_p->unassocSTA.waitTimer);
	TimerFireInByJiffies(&priv->wlpd_p->unassocSTA.waitTimer, 1,
			     &mwl_vendor_cmd_get_unassociated_sta_timeout,
			     (UINT8 *) netdev, 200 * TIMER_1MS);
	return;

send_event:
	MSAN_unassocsta_send_event(netdev);

	wl_kfree(priv->wlpd_p->unassocSTA.unassocsta_query);
	priv->wlpd_p->unassocSTA.unassocsta_query = NULL;

	/* for sysfs log, don't deinit unassocsta track list */
	//unassocsta_track_deinit(priv);
}

static int
mwl_vendor_cmd_get_unassociated_sta_link_metrics(struct wiphy *wiphy,
						 struct wireless_dev *wdev,
						 const void *data, int data_len)
{
	struct wlprivate *priv = mwl_netdev_get_priv(wdev->netdev);
	struct wlprivate *priv_master = NULL;
	//vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	vmacApInfo_t *vmacSta_p = NULL;
	struct net_device *netdev = NULL;
	MIB_802DOT11 *mib = NULL;
	struct nlattr *tb[NUM_MWL_VENDOR_ATTR];
	struct unassociated_sta_link_metrics_query *query;
	unsigned int Jiffies;
	int ret, i;

	if (!data)
		return -EINVAL;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,12,0)
	ret = nla_parse(tb, MAX_MWL_VENDOR_ATTR, data, data_len,
			mwl_vendor_attr_policy);
#else
	ret = nla_parse(tb, MAX_MWL_VENDOR_ATTR, data, data_len,
			mwl_vendor_attr_policy, NULL);
#endif

	if (ret)
		return ret;

	if (!tb[MWL_VENDOR_ATTR_UNASSOCIATED_STA_LINK_METRICS_QUERY])
		return -EINVAL;

	if (priv->master)
		priv_master = mwl_netdev_get_priv(priv->master);
	else
		priv_master = priv;

	if (!priv_master)
		return -ENOMEM;

	/* GET command is in process, return */
	if (priv_master->wlpd_p->unassocSTA.unassocsta_query)
		return -EINVAL;

	query = wl_kzalloc(sizeof(struct unassociated_sta_link_metrics_query),
			   GFP_ATOMIC);
	if (!query)
		return -ENOMEM;

	memcpy((void *)query,
	       (const void *)
	       nla_data(tb
			[MWL_VENDOR_ATTR_UNASSOCIATED_STA_LINK_METRICS_QUERY]),
	       sizeof(struct unassociated_sta_link_metrics_query));

	/* Pre-check query data */
	if ((query->num_of_channel == 0) ||
	    (query->num_of_channel > UNASSOC_METRICS_CHANNEL_MAX)) {
		wl_kfree(query);
		return -EINVAL;
	}

	for (i = 0; i < query->num_of_channel; i++) {
		if (query->unassociated_sta_info[i].num_of_sta >
		    UNASSOC_METRICS_STA_MAX) {
			wl_kfree(query);
			return -EINVAL;
		}
	}

	/* Keep necessary data for unassociated STA tracking */
	priv_master->wlpd_p->unassocSTA.netDev = priv->netDev;
	priv_master->wlpd_p->unassocSTA.unassocsta_query = query;

	vmacSta_p = priv_master->vmacSta_p;
	netdev = priv_master->netDev;
	mib = vmacSta_p->Mib802dot11;
	Jiffies =
		((*(mib->mib_unassocsta_track_time) +
		  300) * query->num_of_channel) * TIMER_1MS;

	TimerDisarm(&priv_master->wlpd_p->unassocSTA.scanTimer);
	TimerInit(&priv_master->wlpd_p->unassocSTA.scanTimer);

	priv_master->wlpd_p->unassocSTA.isTrackCompleted = 0;
	priv_master->wlpd_p->unassocSTA.wiatMaxCount = 0;
	priv_master->wlpd_p->unassocSTA.offChanIdx = 0;
	*(mib->mib_unassocsta_track_enabled) = 0;
	unassocsta_track_deinit(priv_master);

	ret = MSAN_unassocsta_offchan_init(netdev);
	if (ret) {
		wl_kfree(query);
		return -EINVAL;
	}

	/* Start offchan scan for unassociated STA */
	//if (query->unassociated_sta_info[0].channel != mib->PhyDSSSTable->CurrChan)
	MSAN_unassocsta_offchan_scan(netdev);
	//else {
	//priv_master->wlpd_p->unassocSTA.offChanIdx++;
	//      *(mib->mib_unassocsta_track_enabled) = 1;
	//      MSAN_unassocsta_offchan_done(netdev, UNASSOCSTA_TRACK_MODE_CURRCHAN);
	//}

	/* Trigger the timer to make sure final unassocSTA event will be sent */
	TimerDisarm(&priv_master->wlpd_p->unassocSTA.waitTimer);
	TimerInit(&priv_master->wlpd_p->unassocSTA.waitTimer);
	TimerFireInByJiffies(&priv_master->wlpd_p->unassocSTA.waitTimer, 1,
			     &mwl_vendor_cmd_get_unassociated_sta_timeout,
			     (UINT8 *) netdev, Jiffies);

	return 0;
}

extern void fillApRadioInfo(struct net_device *netdev,
			    struct ap_radio_basic_capa_rpt_t *pRpt);
static int
mwl_vendor_cmd_get_ap_radio_basic_capa(struct wiphy *wiphy,
				       struct wireless_dev *wdev,
				       const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_netdev_get_priv(wdev->netdev);
	//vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	struct sk_buff *skb;
	struct ap_radio_basic_capa_rpt_t *ap_radio_basic_capa;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy,
						  10 +
						  AP_RADIO_BASIC_CAPA_SIZE);
	if (skb == NULL)
		return -ENOMEM;

	ap_radio_basic_capa = wl_kzalloc(AP_RADIO_BASIC_CAPA_SIZE, GFP_ATOMIC);
	if (!ap_radio_basic_capa)
		return -ENOMEM;

	fillApRadioInfo(wdev->netdev, ap_radio_basic_capa);

	if (nla_put(skb, MWL_VENDOR_ATTR_AP_RADIO_BASIC_CAPABILITIES,
		    AP_RADIO_BASIC_CAPA_SIZE, ap_radio_basic_capa)) {
		wl_kfree(ap_radio_basic_capa);
		kfree_skb(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb)) {
		wl_kfree(ap_radio_basic_capa);
		return -EFAULT;
	}

	wl_kfree(ap_radio_basic_capa);
	return 0;
}

static const struct wiphy_vendor_command mwl_vendor_commands[] = {
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_COMMIT,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV | WIPHY_VENDOR_CMD_NEED_RUNNING,
	 .doit = mwl_vendor_cmd_commit,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SEND_MLME,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_send_mlme,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_APPIE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_appie,
	 },
#ifdef BAND_STEERING
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_BANDSTEER,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_bandsteer,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SEND_MGMT,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_send_mgmt,
	 },
#endif /* BAND_STEERING */
#ifdef IEEE80211K
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_RRM,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_rrm,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_RRM,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_rrm,
	 },
#endif
#ifdef AUTOCHANNEL
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_DO_ACS,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_do_acs,
	 },
#endif
#ifdef MULTI_AP_SUPPORT
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_MULTIAP,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_multiap,
	 },
#endif /* MULTI_AP_SUPPORT */
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_WPAWPA2MODE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_wpawpa2mode,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_SSID,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_ssid,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_SSID,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_ssid,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_CONFIG_WPA,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_config_wpa,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_BAND_CAPA,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_band_capa,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_CHANNEL_UTIL,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_channel_util,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_STATION_INFO,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_station_info,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_ESPI,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_espi,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_UNASSOCIATED_STA_LINK_METRICS,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_unassociated_sta_link_metrics,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_AP_RADIO_BASIC_CAPABILITIES,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_ap_radio_basic_capa,
	 },
};

static const struct nl80211_vendor_cmd_info mwl_vendor_events[] = {
	{
	 .vendor_id = MRVL_OUI,
	 .subcmd = MWL_VENDOR_EVENT_TEST,
	 },
	{
	 .vendor_id = MRVL_OUI,
	 .subcmd = MWL_VENDOR_EVENT_ASSOC,
	 },
	{
	 .vendor_id = MRVL_OUI,
	 .subcmd = MWL_VENDOR_EVENT_DISASSOC,
	 },
	{
	 .vendor_id = MRVL_OUI,
	 .subcmd = MWL_VENDOR_EVENT_PROBE_REQ,
	 },
	{
	 .vendor_id = MRVL_OUI,
	 .subcmd = MWL_VENDOR_EVENT_AUTH,
	 },
	{
	 .vendor_id = MRVL_OUI,
	 .subcmd = MWL_VENDOR_EVENT_WPS_REQ,
	 },
	{
	 .vendor_id = MRVL_OUI,
	 .subcmd = MWL_VENDOR_EVENT_ACS_COMPLETED,
	 },
	{
	 .vendor_id = MRVL_OUI,
	 .subcmd = MWL_VENDOR_EVENT_NEIGHBOR_LIST,
	 },
	{
	 .vendor_id = MRVL_OUI,
	 .subcmd = MWL_VENDOR_EVENT_ASSOC_NOTIFICATION,
	 },
	{
	 .vendor_id = MRVL_OUI,
	 .subcmd = MWL_VENDOR_EVENT_DISASSOC_NOTIFICATION,
	 },
	{
	 .vendor_id = MRVL_OUI,
	 .subcmd = MWL_VENDOR_EVENT_UNASSOCIATED_STA_LINK_METRICS,
	 },

};

void
mwl_set_vendor_commands(struct wiphy *wiphy)
{
	wiphy->vendor_commands = mwl_vendor_commands;
	wiphy->n_vendor_commands = ARRAY_SIZE(mwl_vendor_commands);
	wiphy->vendor_events = mwl_vendor_events;
	wiphy->n_vendor_events = ARRAY_SIZE(mwl_vendor_events);
}
