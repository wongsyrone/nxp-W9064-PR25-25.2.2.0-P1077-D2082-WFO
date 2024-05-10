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
#include "drv_config.h"

int
mwl_send_vendor_test_event(struct net_device *netdev, uint8_t opmode)
{
	struct sk_buff *skb;
	struct wlprivate *vif = mwl_netdev_get_priv(netdev);
	uint8_t data[] = { 0x00, 0x50, 0x43 };

	if ((netdev->flags & IFF_RUNNING) == 0)
		return 0;

	skb = cfg80211_vendor_event_alloc(vif->wiphy, &vif->wdev, 20,
					  MWL_VENDOR_EVENT_TEST, GFP_ATOMIC);

	if (skb == NULL)
		return -ENOMEM;

	memcpy(skb->data, data, sizeof(data) / sizeof(uint8_t));
	skb_put(skb, sizeof(data) / sizeof(uint8_t));

	cfg80211_vendor_event(skb, GFP_ATOMIC);

	return 0;
}

int
mwl_send_vendor_assoc_event(struct net_device *netdev, uint8_t * macaddr)
{
	int ret;
	struct wlprivate *vif = mwl_netdev_get_priv(netdev);
	struct sk_buff *skb;
	uint8_t ie_type = RSN_IEWPA2;
	uint16_t ie_len;
	uint8_t reassoc;
	uint8_t ie[256];

	if ((netdev->flags & IFF_RUNNING) == 0)
		return 0;

	ret = mwl_drv_get_ie(netdev, ie_type, macaddr, &ie_len, &reassoc, ie);

#ifdef OWE_SUPPORT
	if (!ret) {
		uint16_t dh_ie_len = 0;

		ret = mwl_drv_get_ie(netdev, EXTENSION, macaddr, &dh_ie_len,
				     &reassoc, &ie[ie_len]);
		ie_len += dh_ie_len;
	}
#endif

	if (!ret) {
		skb = cfg80211_vendor_event_alloc(vif->wiphy, &vif->wdev, 300,
						  MWL_VENDOR_EVENT_ASSOC,
						  GFP_ATOMIC);

		if (skb == NULL)
			return -ENOMEM;

		if (nla_put(skb, MWL_VENDOR_ATTR_IE_MAC, ETH_ALEN, macaddr) ||
		    nla_put_u16(skb, MWL_VENDOR_ATTR_IE_LEN, ie_len) ||
		    nla_put_u8(skb, MWL_VENDOR_ATTR_IE_REASSOC, reassoc) ||
		    nla_put(skb, MWL_VENDOR_ATTR_IE_DATA, ie_len, ie)) {
			kfree_skb(skb);
			return -EMSGSIZE;
		}

		cfg80211_vendor_event(skb, GFP_ATOMIC);
	}

	return 0;
}

int
mwl_send_vendor_disassoc_event(struct net_device *netdev, uint8_t * macaddr)
{
	struct wlprivate *vif = mwl_netdev_get_priv(netdev);
	struct sk_buff *skb;

	if ((netdev->flags & IFF_RUNNING) == 0)
		return 0;

	skb = cfg80211_vendor_event_alloc(vif->wiphy, &vif->wdev, 12,
					  MWL_VENDOR_EVENT_DISASSOC,
					  GFP_ATOMIC);

	if (skb == NULL)
		return -ENOMEM;

	if (nla_put(skb, MWL_VENDOR_ATTR_MAC, ETH_ALEN, macaddr)) {
		kfree_skb(skb);
		return -EMSGSIZE;
	}

	cfg80211_vendor_event(skb, GFP_ATOMIC);

	return 0;
}

static int
marvell_send_vendor_mgmt_event(struct net_device *netdev,
			       uint16_t event_type, void *mgmt, size_t len,
			       uint8_t rssi)
{
	struct wlprivate *vif = mwl_netdev_get_priv(netdev);
	struct sk_buff *skb;

	if ((netdev->flags & IFF_RUNNING) == 0)
		return 0;

	skb = cfg80211_vendor_event_alloc(vif->wiphy, &vif->wdev, 512,
					  event_type, GFP_ATOMIC);

	if (skb == NULL)
		return -ENOMEM;

	if (nla_put_u8(skb, MWL_VENDOR_ATTR_RSSI, rssi) ||
	    nla_put(skb, MWL_VENDOR_ATTR_MGMT, len, mgmt)) {
		kfree_skb(skb);
		return -EMSGSIZE;
	}

	cfg80211_vendor_event(skb, GFP_ATOMIC);

	return 0;
}

int
mwl_send_vendor_probe_req_event(struct net_device *netdev, void *mgmt,
				size_t len, uint8_t rssi)
{
	return marvell_send_vendor_mgmt_event(netdev,
					      MWL_VENDOR_EVENT_PROBE_REQ, mgmt,
					      len, rssi);
}

int
mwl_send_vendor_auth_event(struct net_device *netdev, void *mgmt,
			   size_t len, uint8_t rssi)
{
	return marvell_send_vendor_mgmt_event(netdev, MWL_VENDOR_EVENT_AUTH,
					      mgmt, len, rssi);
}

int
mwl_send_vendor_wps_req_event(struct net_device *netdev, void *mgmt,
			      size_t len, uint8_t rssi)
{
	return marvell_send_vendor_mgmt_event(netdev, MWL_VENDOR_EVENT_WPS_REQ,
					      mgmt, len, rssi);
}

int
mwl_send_vendor_acs_completed(struct net_device *netdev, uint8_t channel)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	struct sk_buff *skb;

	/* only send vendor event acs completed to vap */
	if (priv->master == NULL)
		return 0;
	if ((netdev->flags & IFF_RUNNING) == 0)
		return 0;

	skb = cfg80211_vendor_event_alloc(priv->wiphy, &priv->wdev, 512,
					  MWL_VENDOR_EVENT_ACS_COMPLETED,
					  GFP_ATOMIC);

	if (skb == NULL)
		return -ENOMEM;

	if (nla_put_u8(skb, MWL_VENDOR_ATTR_CHANNEL, channel)) {
		kfree_skb(skb);
		return -EMSGSIZE;
	}

	cfg80211_vendor_event(skb, GFP_ATOMIC);

	return 0;
}
