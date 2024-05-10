/** @file ioctl_cfg80211.h
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
#ifndef	IOCTL_CFG80211_H_
#define	IOCTL_CFG80211_H_

#include "ap8xLnxIoctl.h"
#include "vendor.h"
#include "wltypes.h"

#define MWL_WEP_ENCODE_DISABLED	0x01	/* Encoding disabled */
#define MWL_WEP_ENCODE_RESTRICTED	0x02	/* Refuse non-encoded packets */
#define MWL_WEP_ENCODE_OPEN		0x04	/* Accept non-encoded packets */

int mwl_config_commit(struct net_device *netdev);
int mwl_config_set_channel(struct net_device *netdev, uint8_t channel);
int mwl_config_set_bcninterval(struct net_device *netdev, uint16_t bcninterval);
int mwl_config_set_essid(struct net_device *netdev, const char *ssid,
			 uint8_t ssid_len);
int mwl_config_set_appie(struct net_device *netdev,
			 struct wlreq_set_appie *appie);
int mwl_config_send_mlme(struct net_device *netdev, struct wlreq_mlme *mlme);
int mwl_config_set_key(struct net_device *netdev, struct wlreq_key *wk);
int mwl_config_del_key(struct net_device *netdev, uint16_t key_idx,
		       uint8_t * macaddr);
int mwl_config_get_seqnum(struct net_device *netdev, uint8_t * seqnum);
int mwl_config_get_ie(struct net_device *netdev, struct wlreq_ie *IEReq,
		      UINT16 * ret_len);
int mwl_config_set_wepkey(struct net_device *netdev, UINT8 * data, int key_len,
			  UINT8 encode, UINT16 key_index);

#endif
