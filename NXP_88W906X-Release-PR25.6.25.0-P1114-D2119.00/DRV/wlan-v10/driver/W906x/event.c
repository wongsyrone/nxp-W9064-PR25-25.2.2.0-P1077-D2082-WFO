/** @file event.c
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

/* Description:  This file implements vendor event related functions. */

#include <net/netlink.h>

#include "ap8xLnxIntf.h"
#include "macmgmtap.h"

#include "cfg80211.h"
#include "vendor.h"
#include "ioctl_cfg80211.h"
#include "StaDb.h"

static int marvell_send_vendor_mgmt_event(struct net_device *netdev, uint16_t event_type, void *mgmt, size_t len, uint8_t rssi)
{
	struct wlprivate *vif = mwl_netdev_get_priv(netdev);
	struct sk_buff *skb;

	if ((netdev->flags & IFF_RUNNING) == 0)
		return 0;

	skb = cfg80211_vendor_event_alloc(vif->wiphy, &vif->wdev, 512, event_type, GFP_ATOMIC);

	if (skb == NULL)
		return -ENOMEM;

	if (nla_put_u8(skb, MWL_VENDOR_ATTR_RSSI, rssi) || nla_put(skb, MWL_VENDOR_ATTR_MGMT, len, mgmt)) {
		kfree_skb(skb);
		return -EMSGSIZE;
	}

	cfg80211_vendor_event(skb, GFP_ATOMIC);

	return 0;
}

int mwl_send_vendor_assoc_event(struct net_device *netdev, uint8_t * macaddr)
{
	int ret;
	struct wlprivate *vif = mwl_netdev_get_priv(netdev);
	struct sk_buff *skb;
	struct wlreq_ie IEReq;
	UINT16 ret_len = 0;

	if ((netdev->flags & IFF_RUNNING) == 0)
		return 0;

	IEReq.IEtype = RSN_IEWPA2;
	memcpy(IEReq.macAddr, macaddr, 6);
	ret = mwl_config_get_ie(netdev, &IEReq, &ret_len);

	if (!ret) {
		skb = cfg80211_vendor_event_alloc(vif->wiphy, &vif->wdev, 300, MWL_VENDOR_EVENT_ASSOC, GFP_ATOMIC);

		if (skb == NULL)
			return -ENOMEM;

		if (nla_put(skb, MWL_VENDOR_ATTR_IE_MAC, ETH_ALEN, macaddr) ||
		    nla_put_u16(skb, MWL_VENDOR_ATTR_IE_LEN, IEReq.IELen) ||
		    nla_put_u8(skb, MWL_VENDOR_ATTR_IE_REASSOC, IEReq.reassoc) || nla_put(skb, MWL_VENDOR_ATTR_IE_DATA, IEReq.IELen, IEReq.IE)) {
			kfree_skb(skb);
			return -EMSGSIZE;
		}

		cfg80211_vendor_event(skb, GFP_ATOMIC);
	}

	return 0;
}

int mwl_send_vendor_wps_req_event(struct net_device *netdev, void *mgmt, size_t len, uint8_t rssi)
{
	return marvell_send_vendor_mgmt_event(netdev, MWL_VENDOR_EVENT_WPS_REQ, mgmt, len, rssi);
}

int mwl_send_vendor_acs_completed(struct net_device *netdev, uint8_t channel)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	struct sk_buff *skb;

	/* only send vendor event acs completed to vap */
	if (priv->master == NULL)
		return 0;
	if ((netdev->flags & IFF_RUNNING) == 0)
		return 0;

	skb = cfg80211_vendor_event_alloc(priv->wiphy, &priv->wdev, 512, MWL_VENDOR_EVENT_ACS_COMPLETED, GFP_ATOMIC);

	if (skb == NULL)
		return -ENOMEM;

	if (nla_put_u8(skb, MWL_VENDOR_ATTR_CHANNEL, channel)) {
		kfree_skb(skb);
		return -EMSGSIZE;
	}

	cfg80211_vendor_event(skb, GFP_ATOMIC);

	return 0;
}

int mwl_send_vendor_neighbor_event(struct net_device *netdev, void *buf, size_t len, uint8_t add)
{
	return marvell_send_vendor_mgmt_event(netdev, MWL_VENDOR_EVENT_NEIGHBOR_LIST, buf, len, add);
}

int mwl_send_vendor_assoc_notification(struct net_device *netdev, uint8_t * macaddr, void *assocReqMsg, uint16_t reason_code)
{
	struct wlprivate *vif = mwl_netdev_get_priv(netdev);
	assoc_req_msg_t *assocReqFrame = (assoc_req_msg_t *) assocReqMsg;
	struct sk_buff *skb;
	size_t size = sizeof(assoc_req_msg_t);

	if ((netdev->flags & IFF_RUNNING) == 0)
		return 0;

	skb = cfg80211_vendor_event_alloc(vif->wiphy, &vif->wdev, (size + 20), MWL_VENDOR_EVENT_ASSOC_NOTIFICATION, GFP_ATOMIC);

	if (skb == NULL)
		return -ENOMEM;

	if (nla_put(skb, MWL_VENDOR_ATTR_MAC_ADDRESS, ETH_ALEN, macaddr) ||
	    nla_put(skb, MWL_VENDOR_ATTR_ASSOC_REQ_FRAME, size, assocReqFrame) || nla_put_u16(skb, MWL_VENDOR_ATTR_REASON_CODE, reason_code)) {
		kfree_skb(skb);
		return -EMSGSIZE;
	}

	cfg80211_vendor_event(skb, GFP_ATOMIC);

	return 0;
}

int mwl_send_vendor_disassoc_notification(struct net_device *netdev, uint8_t * macaddr, struct station_info *station_info, uint16_t reason_code)
{
	struct wlprivate *vif = mwl_netdev_get_priv(netdev);
	struct sk_buff *skb;
	size_t size = sizeof(struct station_info);

	if ((netdev->flags & IFF_RUNNING) == 0)
		return 0;

	skb = cfg80211_vendor_event_alloc(vif->wiphy, &vif->wdev, (size + 20), MWL_VENDOR_EVENT_DISASSOC_NOTIFICATION, GFP_ATOMIC);

	if (skb == NULL)
		return -ENOMEM;

	if (nla_put(skb, MWL_VENDOR_ATTR_MAC_ADDRESS, ETH_ALEN, macaddr) ||
	    nla_put(skb, MWL_VENDOR_ATTR_STATION_INFO, size, station_info) || nla_put_u16(skb, MWL_VENDOR_ATTR_REASON_CODE, reason_code)) {
		kfree_skb(skb);
		return -EMSGSIZE;
	}

	cfg80211_vendor_event(skb, GFP_ATOMIC);

	return 0;
}

int mwl_send_vendor_unassocsta_event(struct net_device *netdev, void *resp)
{
	struct wlprivate *vif = mwl_netdev_get_priv(netdev);
	struct unassociated_sta_link_metrics_resp *unassociated_resp = resp;
	struct sk_buff *skb;

	if ((netdev->flags & IFF_RUNNING) == 0)
		return 0;

	skb = cfg80211_vendor_event_alloc(vif->wiphy, &vif->wdev, (UNASSOC_RESP_SIZE + 20),
					  MWL_VENDOR_EVENT_UNASSOCIATED_STA_LINK_METRICS, GFP_ATOMIC);

	if (skb == NULL)
		return -ENOMEM;

	if (nla_put(skb, MWL_VENDOR_ATTR_UNASSOCIATED_STA_LINK_METRICS_RESP, UNASSOC_RESP_SIZE, unassociated_resp)) {
		kfree_skb(skb);
		return -EMSGSIZE;
	}

	cfg80211_vendor_event(skb, GFP_ATOMIC);

	return 0;
}

int mwl_send_vendor_multiapIE_event(struct net_device *netdev, uint8_t * macaddr, IEEEtypes_MultiAP_Element_t * multiapIE, UINT16 iesize)
{
	struct wlprivate *vif = mwl_netdev_get_priv(netdev);
	struct sk_buff *skb;
	size_t size = ETH_ALEN + iesize + 20;

	if ((netdev->flags & IFF_RUNNING) == 0)
		return 0;

	skb = cfg80211_vendor_event_alloc(vif->wiphy, &vif->wdev, size, MWL_VENDOR_EVENT_MULTIAP_IE, GFP_ATOMIC);

	if (skb == NULL)
		return -ENOMEM;

	if (nla_put(skb, MWL_VENDOR_ATTR_MAC_ADDRESS, ETH_ALEN, macaddr) || nla_put(skb, MWL_VENDOR_ATTR_MULTIAP_IE, iesize, multiapIE)) {
		kfree_skb(skb);
		return -EMSGSIZE;
	}

	cfg80211_vendor_event(skb, GFP_ATOMIC);

	return 0;
}
