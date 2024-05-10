/** @file cfg80211.h
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

/* Description:  This file defines cfg80211 related functions. */

#ifndef _MWL_CFG80211_H
#define _MWL_CFG80211_H

#include <net/cfg80211.h>

int mwl_cfg80211_create(struct wlprivate *wlpptr);

void mwl_cfg80211_destroy(struct wlprivate *wlpptr);

/*
 * This function retrieves the private structure from kernel wiphy structure.
 */
static inline void *
mwl_cfg80211_get_priv(struct wiphy *wiphy)
{
	return (void *)(*(unsigned long *)wiphy_priv(wiphy));
}

/*
 * This function retrieves the private structure from kernel net_device structure.
 */
static inline struct wlprivate *
mwl_netdev_get_priv(struct net_device *netdev)
{
	return (struct wlprivate *)netdev_priv(netdev);
}

int mwl_cfg80211_assoc_event(struct net_device *netdev, uint8_t * macaddr);
int mwl_cfg80211_disassoc_event(struct net_device *netdev, uint8_t * macaddr);
int mwl_cfg80211_connect_result_event(struct net_device *netdev,
				      uint8_t * macaddr, uint8_t status);
int mwl_cfg80211_ch_switch_notify(struct net_device *netdev);
void mwl_set_vendor_commands(struct wiphy *wiphy);
int mwl_send_vendor_test_event(struct net_device *netdev, uint8_t opmode);
int mwl_send_vendor_assoc_event(struct net_device *netdev, uint8_t * macaddr);
int mwl_send_vendor_disassoc_event(struct net_device *netdev,
				   uint8_t * macaddr);
int mwl_send_vendor_probe_req_event(struct net_device *netdev, void *mgmt,
				    size_t len, uint8_t rssi);
int mwl_send_vendor_auth_event(struct net_device *netdev, void *mgmt,
			       size_t len, uint8_t rssi);
int mwl_send_vendor_wps_req_event(struct net_device *netdev, void *mgmt,
				  size_t len, uint8_t rssi);

int mwl_cfg80211_rx_mgmt(struct net_device *netdev, void *buf,
			 size_t len, uint8_t rssi);
int mwl_send_vendor_acs_completed(struct net_device *netdev, uint8_t channel);

/*
 * cfg80211 dump function for debug usage
 */
void mwl_cfg80211_hex_dump(const char *title, uint8_t * buf, size_t len);
void mwl_cfg80211_hex_ascii_dump(const char *title, uint8_t * buf, size_t len);

#endif /* _MWL_CFG80211_H */
