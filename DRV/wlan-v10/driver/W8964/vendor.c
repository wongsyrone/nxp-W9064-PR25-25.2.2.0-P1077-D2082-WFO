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
#include "drv_config.h"

static const
struct nla_policy mwl_vendor_attr_policy[NUM_MWL_VENDOR_ATTR] = {
	[MWL_VENDOR_ATTR_VERSION] = {.type = NLA_STRING},
	[MWL_VENDOR_ATTR_OPMODE] = {.type = NLA_U8},
	[MWL_VENDOR_ATTR_SSID] = {.type = NLA_BINARY,.len =
				  IEEE80211_MAX_SSID_LEN},
	[MWL_VENDOR_ATTR_BSSID] = {.type = NLA_BINARY,.len = ETH_ALEN},
	[MWL_VENDOR_ATTR_BANDSTEER] = {.type = NLA_U32},
	[MWL_VENDOR_ATTR_APPIE] = {.type = NLA_BINARY,.len = 512},
	[MWL_VENDOR_ATTR_MLME] = {.type = NLA_BINARY,.len =
				  sizeof(struct mwl_mlme)},
	[MWL_VENDOR_ATTR_MGMT] = {.type = NLA_BINARY,.len = 512},
	[MWL_VENDOR_ATTR_COUNTERMEASURES] = {.type = NLA_U32},
};

static const
struct nla_policy mwl_vendor_attr_key_policy[NUM_MWL_VENDOR_ATTR_KEY] = {
	[MWL_VENDOR_ATTR_KEY_TYPE] = {.type = NLA_U8},
	[MWL_VENDOR_ATTR_KEY_INDEX] = {.type = NLA_U16},
	[MWL_VENDOR_ATTR_KEY_LEN] = {.type = NLA_U8},
	[MWL_VENDOR_ATTR_KEY_FLAG] = {.type = NLA_U8},
	[MWL_VENDOR_ATTR_KEY_MAC] = {.type = NLA_BINARY,.len = ETH_ALEN},
	[MWL_VENDOR_ATTR_KEY_RECV_SEQ] = {.type = NLA_U64},
	[MWL_VENDOR_ATTR_KEY_XMIT_SEQ] = {.type = NLA_U64},
	[MWL_VENDOR_ATTR_KEY_DATA] = {.type = NLA_BINARY,.len =
				      WLAN_MAX_KEY_LEN},
	[MWL_VENDOR_ATTR_KEY_PN] = {.type = NLA_BINARY,.len = 6},
};

static const
struct nla_policy mwl_vendor_attr_ie_policy[NUM_MWL_VENDOR_ATTR_IE] = {
	[MWL_VENDOR_ATTR_IE_TYPE] = {.type = NLA_U8},
	[MWL_VENDOR_ATTR_IE_MAC] = {.type = NLA_BINARY,.len = ETH_ALEN},
};

static int
mwl_vendor_cmd_get_version(struct wiphy *wiphy,
			   struct wireless_dev *wdev,
			   const void *data, int data_len)
{
	struct sk_buff *skb;
	char version[128];

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 128);
	if (skb == NULL)
		return -ENOMEM;

	mwl_drv_get_version(wdev->netdev, version);

	if (nla_put_string(skb, MWL_VENDOR_ATTR_VERSION, version)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_commit(struct wiphy *wiphy,
		      struct wireless_dev *wdev, const void *data, int data_len)
{
	return mwl_drv_commit(wdev->netdev);
}

static int
mwl_vendor_cmd_set_opmode(struct wiphy *wiphy,
			  struct wireless_dev *wdev,
			  const void *data, int data_len)
{
	uint8_t opmode;

	if (!data)
		return -EINVAL;

	opmode = *(uint8_t *) data;

	return mwl_drv_set_opmode(wdev->netdev, opmode);
}

static int
mwl_vendor_cmd_get_opmode(struct wiphy *wiphy,
			  struct wireless_dev *wdev,
			  const void *data, int data_len)
{
	struct sk_buff *skb;
	uint32_t opmode;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 8);
	if (skb == NULL)
		return -ENOMEM;

	opmode = mwl_drv_get_opmode(wdev->netdev);

	if (nla_put_u32(skb, MWL_VENDOR_ATTR_OPMODE, opmode)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_set_stamode(struct wiphy *wiphy,
			   struct wireless_dev *wdev,
			   const void *data, int data_len)
{
	uint8_t stamode;

	if (!data)
		return -EINVAL;

	stamode = *(uint8_t *) data;

	return mwl_drv_set_stamode(wdev->netdev, stamode);
}

static int
mwl_vendor_cmd_get_stamode(struct wiphy *wiphy,
			   struct wireless_dev *wdev,
			   const void *data, int data_len)
{
	struct sk_buff *skb;
	uint32_t stamode;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 8);
	if (skb == NULL)
		return -ENOMEM;

	stamode = mwl_drv_get_stamode(wdev->netdev);

	if (nla_put_u32(skb, MWL_VENDOR_ATTR_STAMODE, stamode)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_set_key(struct wiphy *wiphy,
		       struct wireless_dev *wdev,
		       const void *data, int data_len)
{
	int ret;
	struct nlattr *tb[NUM_MWL_VENDOR_ATTR_KEY];

	if (!data)
		return -EINVAL;

	mwl_cfg80211_hex_dump("set_key", (uint8_t *) data, data_len);

	ret = nla_parse(tb, MAX_MWL_VENDOR_ATTR_KEY, data, data_len,
			mwl_vendor_attr_key_policy);
	if (ret)
		return ret;

	if (!tb[MWL_VENDOR_ATTR_KEY_TYPE] ||
	    !tb[MWL_VENDOR_ATTR_KEY_INDEX] ||
	    !tb[MWL_VENDOR_ATTR_KEY_LEN] ||
	    !tb[MWL_VENDOR_ATTR_KEY_FLAG] ||
	    !tb[MWL_VENDOR_ATTR_KEY_MAC] ||
	    !tb[MWL_VENDOR_ATTR_KEY_RECV_SEQ] ||
	    !tb[MWL_VENDOR_ATTR_KEY_XMIT_SEQ] ||
	    !tb[MWL_VENDOR_ATTR_KEY_DATA] || !tb[MWL_VENDOR_ATTR_KEY_PN])
		return -EINVAL;

	return mwl_drv_set_key(wdev->netdev,
			       nla_get_u8(tb[MWL_VENDOR_ATTR_KEY_TYPE]),
			       nla_get_u16(tb[MWL_VENDOR_ATTR_KEY_INDEX]),
			       nla_get_u8(tb[MWL_VENDOR_ATTR_KEY_LEN]),
			       nla_get_u8(tb[MWL_VENDOR_ATTR_KEY_FLAG]),
			       nla_data(tb[MWL_VENDOR_ATTR_KEY_MAC]),
			       nla_get_u64(tb[MWL_VENDOR_ATTR_KEY_RECV_SEQ]),
			       nla_get_u64(tb[MWL_VENDOR_ATTR_KEY_XMIT_SEQ]),
			       nla_data(tb[MWL_VENDOR_ATTR_KEY_DATA]),
			       nla_data(tb[MWL_VENDOR_ATTR_KEY_PN]));
}

static int
mwl_vendor_cmd_del_key(struct wiphy *wiphy,
		       struct wireless_dev *wdev,
		       const void *data, int data_len)
{
	int ret;
	struct nlattr *tb[NUM_MWL_VENDOR_ATTR_KEY];

	if (!data)
		return -EINVAL;

	//mwl_cfg80211_hex_dump("del_key", data, data_len);

	ret = nla_parse(tb, MAX_MWL_VENDOR_ATTR_KEY, data, data_len,
			mwl_vendor_attr_key_policy);
	if (ret)
		return ret;

	if (!tb[MWL_VENDOR_ATTR_KEY_INDEX] || !tb[MWL_VENDOR_ATTR_KEY_MAC])
		return -EINVAL;

	if (nla_len(tb[MWL_VENDOR_ATTR_KEY_MAC]) != ETH_ALEN)
		return -EINVAL;

	return mwl_drv_del_key(wdev->netdev,
			       nla_get_u8(tb[MWL_VENDOR_ATTR_KEY_INDEX]),
			       nla_data(tb[MWL_VENDOR_ATTR_KEY_MAC]));
}

static int
mwl_vendor_cmd_set_wpawpa2mode(struct wiphy *wiphy,
			       struct wireless_dev *wdev,
			       const void *data, int data_len)
{
	uint8_t mode;

	if (!data)
		return -EINVAL;

	mode = *(uint8_t *) data;

	return mwl_drv_set_wpawpa2mode(wdev->netdev, mode);
}

static int
mwl_vendor_cmd_get_wpawpa2mode(struct wiphy *wiphy,
			       struct wireless_dev *wdev,
			       const void *data, int data_len)
{
	struct sk_buff *skb;
	uint32_t mode;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 8);
	if (skb == NULL)
		return -ENOMEM;

	mode = mwl_drv_get_wpawpa2mode(wdev->netdev);

	if (nla_put_u32(skb, MWL_VENDOR_ATTR_WPAWPA2MODE, mode)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_set_passphrase(struct wiphy *wiphy,
			      struct wireless_dev *wdev,
			      const void *data, int data_len)
{
	uint8_t mode;
	char p[64];
	int len;

	if (!data)
		return -EINVAL;

	mode = *(uint8_t *) data;
	len = data_len - 1;
	memcpy(p, (uint8_t *) (data + 1), len);

	return mwl_drv_set_passphrase(wdev->netdev, mode, p, len);
}

static int
mwl_vendor_cmd_get_passphrase(struct wiphy *wiphy,
			      struct wireless_dev *wdev,
			      const void *data, int data_len)
{
	struct sk_buff *skb;
	char p[142];

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + sizeof(p));
	if (skb == NULL)
		return -ENOMEM;

	mwl_drv_get_passphrase(wdev->netdev, p);

	if (nla_put_string(skb, MWL_VENDOR_ATTR_PASSPHRASE, p)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_set_ciphersuite(struct wiphy *wiphy,
			       struct wireless_dev *wdev,
			       const void *data, int data_len)
{
	uint8_t wpamode, cipher;

	if (!data)
		return -EINVAL;

	wpamode = *(uint8_t *) data;
	cipher = *(uint8_t *) (data + 1);

	return mwl_drv_set_ciphersuite(wdev->netdev, wpamode, cipher);
}

static int
mwl_vendor_cmd_get_ciphersuite(struct wiphy *wiphy,
			       struct wireless_dev *wdev,
			       const void *data, int data_len)
{
	struct sk_buff *skb;
	char p[128];

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + sizeof(p));
	if (skb == NULL)
		return -ENOMEM;

	mwl_drv_get_ciphersuite(wdev->netdev, p);

	if (nla_put_string(skb, MWL_VENDOR_ATTR_CIPHERSUITE, p)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_set_wmm(struct wiphy *wiphy,
		       struct wireless_dev *wdev,
		       const void *data, int data_len)
{
	uint8_t mode;

	if (!data)
		return -EINVAL;

	mode = *(uint8_t *) data;
	return mwl_drv_set_wmm(wdev->netdev, mode);
}

static int
mwl_vendor_cmd_get_wmm(struct wiphy *wiphy,
		       struct wireless_dev *wdev,
		       const void *data, int data_len)
{
	struct sk_buff *skb;
	uint32_t mode;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 8);
	if (skb == NULL)
		return -ENOMEM;

	mode = mwl_drv_get_wmm(wdev->netdev);

	if (nla_put_u32(skb, MWL_VENDOR_ATTR_WMM, mode)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_set_wmmedcaap(struct wiphy *wiphy,
			     struct wireless_dev *wdev,
			     const void *data, int data_len)
{
	uint32_t ac;

	if (!data)
		return -EINVAL;

	ac = *(uint32_t *) data;

	return mwl_drv_set_wmmedcaap(wdev->netdev, ac, (uint32_t *) data + 1);
}

static int
mwl_vendor_cmd_get_wmmedcaap(struct wiphy *wiphy,
			     struct wireless_dev *wdev,
			     const void *data, int data_len)
{
	struct sk_buff *skb;
	char *buff;
	size_t size = 1024;

	buff = kmalloc(size, GFP_KERNEL);
	if (buff == NULL)
		return -ENOMEM;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + size);
	if (skb == NULL) {
		kfree(buff);
		return -ENOMEM;
	}

	mwl_drv_get_wmmedcaap(wdev->netdev, buff);

	if (nla_put_string(skb, MWL_VENDOR_ATTR_WMMEDCAAP, buff)) {
		kfree(buff);
		nlmsg_free(skb);
		return -EMSGSIZE;
	}
	kfree(buff);

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_set_amsdu(struct wiphy *wiphy,
			 struct wireless_dev *wdev,
			 const void *data, int data_len)
{
	uint8_t value;

	if (!data)
		return -EINVAL;

	value = *(uint8_t *) data;

	return mwl_drv_set_amsdu(wdev->netdev, value);
}

static int
mwl_vendor_cmd_get_amsdu(struct wiphy *wiphy,
			 struct wireless_dev *wdev,
			 const void *data, int data_len)
{
	struct sk_buff *skb;
	uint32_t value;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 8);
	if (skb == NULL)
		return -ENOMEM;

	value = mwl_drv_get_amsdu(wdev->netdev);

	if (nla_put_u32(skb, MWL_VENDOR_ATTR_AMSDU, value)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_set_rxantenna(struct wiphy *wiphy,
			     struct wireless_dev *wdev,
			     const void *data, int data_len)
{
	uint8_t value;

	if (!data)
		return -EINVAL;

	value = *(uint8_t *) data;

	return mwl_drv_set_rxantenna(wdev->netdev, value);
}

static int
mwl_vendor_cmd_get_rxantenna(struct wiphy *wiphy,
			     struct wireless_dev *wdev,
			     const void *data, int data_len)
{
	struct sk_buff *skb;
	uint32_t value;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 8);
	if (skb == NULL)
		return -ENOMEM;

	value = mwl_drv_get_rxantenna(wdev->netdev);

	if (nla_put_u32(skb, MWL_VENDOR_ATTR_RXANTENNA, value)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_set_optlevel(struct wiphy *wiphy,
			    struct wireless_dev *wdev,
			    const void *data, int data_len)
{
	uint8_t value;

	if (!data)
		return -EINVAL;

	value = *(uint8_t *) data;

	return mwl_drv_set_optlevel(wdev->netdev, value);
}

static int
mwl_vendor_cmd_get_optlevel(struct wiphy *wiphy,
			    struct wireless_dev *wdev,
			    const void *data, int data_len)
{
	struct sk_buff *skb;
	uint32_t value;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 8);
	if (skb == NULL)
		return -ENOMEM;

	value = mwl_drv_get_optlevel(wdev->netdev);

	if (nla_put_u32(skb, MWL_VENDOR_ATTR_OPTLEVEL, value)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_set_macclone(struct wiphy *wiphy,
			    struct wireless_dev *wdev,
			    const void *data, int data_len)
{
	uint8_t enable;

	if (!data)
		return -EINVAL;

	enable = *(uint8_t *) data;

	return mwl_drv_set_macclone(wdev->netdev, enable);
}

static int
mwl_vendor_cmd_set_stascan(struct wiphy *wiphy,
			   struct wireless_dev *wdev,
			   const void *data, int data_len)
{
	uint8_t enable;

	if (!data)
		return -EINVAL;

	enable = *(uint8_t *) data;

	return mwl_drv_set_stascan(wdev->netdev, enable);
}

static int
mwl_vendor_cmd_get_stascan(struct wiphy *wiphy,
			   struct wireless_dev *wdev,
			   const void *data, int data_len)
{
	struct sk_buff *skb;
	char *buff;
	size_t size = 1280;

	buff = kmalloc(size, GFP_KERNEL);
	if (buff == NULL)
		return -ENOMEM;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + size);
	if (skb == NULL) {
		kfree(buff);
		return -ENOMEM;
	}

	mwl_drv_get_stascan(wdev->netdev, buff);

	if (nla_put_string(skb, MWL_VENDOR_ATTR_STASCAN, buff)) {
		kfree(buff);
		nlmsg_free(skb);
		return -EMSGSIZE;
	}
	kfree(buff);

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_set_fixrate(struct wiphy *wiphy,
			   struct wireless_dev *wdev,
			   const void *data, int data_len)
{
	uint8_t value;

	if (!data)
		return -EINVAL;

	value = *(uint8_t *) data;

	return mwl_drv_set_fixrate(wdev->netdev, value);
}

static int
mwl_vendor_cmd_get_fixrate(struct wiphy *wiphy,
			   struct wireless_dev *wdev,
			   const void *data, int data_len)
{
	struct sk_buff *skb;
	uint32_t value;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 8);
	if (skb == NULL)
		return -ENOMEM;

	value = mwl_drv_get_fixrate(wdev->netdev);

	if (nla_put_u32(skb, MWL_VENDOR_ATTR_FIXRATE, value)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_set_txrate(struct wiphy *wiphy,
			  struct wireless_dev *wdev,
			  const void *data, int data_len)
{
	uint16_t type, rate;

	if (!data)
		return -EINVAL;

	type = *(uint8_t *) data;
	rate = *(uint16_t *) (data + 1);

	return mwl_drv_set_txrate(wdev->netdev, type, rate);
}

static int
mwl_vendor_cmd_get_txrate(struct wiphy *wiphy,
			  struct wireless_dev *wdev,
			  const void *data, int data_len)
{
	struct sk_buff *skb;
	char *buff;
	size_t size = 1280;

	buff = kmalloc(size, GFP_KERNEL);
	if (buff == NULL)
		return -ENOMEM;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + size);
	if (skb == NULL) {
		kfree(buff);
		return -ENOMEM;
	}

	mwl_drv_get_txrate(wdev->netdev, buff);

	if (nla_put_string(skb, MWL_VENDOR_ATTR_TXRATE, buff)) {
		kfree(buff);
		nlmsg_free(skb);
		return -EMSGSIZE;
	}
	kfree(buff);

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_set_mcastproxy(struct wiphy *wiphy,
			      struct wireless_dev *wdev,
			      const void *data, int data_len)
{
	uint8_t value;

	if (!data)
		return -EINVAL;

	value = *(uint8_t *) data;

	return mwl_drv_set_mcastproxy(wdev->netdev, value);
}

static int
mwl_vendor_cmd_get_mcastproxy(struct wiphy *wiphy,
			      struct wireless_dev *wdev,
			      const void *data, int data_len)
{
	struct sk_buff *skb;
	uint32_t value;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 8);
	if (skb == NULL)
		return -ENOMEM;

	value = mwl_drv_get_mcastproxy(wdev->netdev);

	if (nla_put_u32(skb, MWL_VENDOR_ATTR_MCASTPROXY, value)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_set_11hstamode(struct wiphy *wiphy,
			      struct wireless_dev *wdev,
			      const void *data, int data_len)
{
	uint8_t value;

	if (!data)
		return -EINVAL;

	value = *(uint8_t *) data;

	return mwl_drv_set_11hstamode(wdev->netdev, value);
}

static int
mwl_vendor_cmd_get_11hstamode(struct wiphy *wiphy,
			      struct wireless_dev *wdev,
			      const void *data, int data_len)
{
	struct sk_buff *skb;
	uint32_t value;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 8);
	if (skb == NULL)
		return -ENOMEM;

	value = mwl_drv_get_11hstamode(wdev->netdev);

	if (nla_put_u32(skb, MWL_VENDOR_ATTR_11HSTAMODE, value)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_get_rssi(struct wiphy *wiphy,
			struct wireless_dev *wdev,
			const void *data, int data_len)
{
	struct sk_buff *skb;
	uint32_t value;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 8);
	if (skb == NULL)
		return -ENOMEM;

	value = mwl_drv_get_rssi(wdev->netdev);

	if (nla_put_u32(skb, MWL_VENDOR_ATTR_RSSI, value)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_get_linkstatus(struct wiphy *wiphy,
			      struct wireless_dev *wdev,
			      const void *data, int data_len)
{
	struct sk_buff *skb;
	uint32_t value;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 8);
	if (skb == NULL)
		return -ENOMEM;

	value = mwl_drv_get_linkstatus(wdev->netdev);

	if (nla_put_u32(skb, MWL_VENDOR_ATTR_LINKSTATUS, value)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_get_stalistext(struct wiphy *wiphy,
			      struct wireless_dev *wdev,
			      const void *data, int data_len)
{
	struct sk_buff *skb;
	char *buff;
	size_t size = 2560;

	buff = kmalloc(size, GFP_KERNEL);
	if (buff == NULL)
		return -ENOMEM;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + size);
	if (skb == NULL) {
		kfree(buff);
		return -ENOMEM;
	}

	mwl_drv_get_stalistext(wdev->netdev, buff);

	if (nla_put_string(skb, MWL_VENDOR_ATTR_STALISTEXT, buff)) {
		kfree(buff);
		nlmsg_free(skb);
		return -EMSGSIZE;
	}
	kfree(buff);

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_set_grouprekey(struct wiphy *wiphy,
			      struct wireless_dev *wdev,
			      const void *data, int data_len)
{
	uint32_t value;

	if (!data)
		return -EINVAL;

	value = *(uint32_t *) data;

	return mwl_drv_set_grouprekey(wdev->netdev, value);
}

static int
mwl_vendor_cmd_get_grouprekey(struct wiphy *wiphy,
			      struct wireless_dev *wdev,
			      const void *data, int data_len)
{
	struct sk_buff *skb;
	uint32_t value;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 8);
	if (skb == NULL)
		return -ENOMEM;

	value = mwl_drv_get_grouprekey(wdev->netdev);

	if (nla_put_u32(skb, MWL_VENDOR_ATTR_GROUPREKEY, value)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_set_wmmedcasta(struct wiphy *wiphy,
			      struct wireless_dev *wdev,
			      const void *data, int data_len)
{
	uint32_t ac;

	if (!data)
		return -EINVAL;

	ac = *(uint32_t *) data;

	return mwl_drv_set_wmmedcasta(wdev->netdev, ac, (uint32_t *) data + 1);
}

static int
mwl_vendor_cmd_get_wmmedcasta(struct wiphy *wiphy,
			      struct wireless_dev *wdev,
			      const void *data, int data_len)
{
	struct sk_buff *skb;
	char *buff;
	size_t size = 1024;

	buff = kmalloc(size, GFP_KERNEL);
	if (buff == NULL)
		return -ENOMEM;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + size);
	if (skb == NULL) {
		kfree(buff);
		return -ENOMEM;
	}

	mwl_drv_get_wmmedcasta(wdev->netdev, buff);

	if (nla_put_string(skb, MWL_VENDOR_ATTR_WMMEDCASTA, buff)) {
		kfree(buff);
		nlmsg_free(skb);
		return -EMSGSIZE;
	}
	kfree(buff);

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_set_htbw(struct wiphy *wiphy,
			struct wireless_dev *wdev,
			const void *data, int data_len)
{
	uint8_t value;

	if (!data)
		return -EINVAL;

	value = *(uint8_t *) data;

	return mwl_drv_set_htbw(wdev->netdev, value);
}

static int
mwl_vendor_cmd_get_htbw(struct wiphy *wiphy,
			struct wireless_dev *wdev,
			const void *data, int data_len)
{
	struct sk_buff *skb;
	uint32_t value;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 8);
	if (skb == NULL)
		return -ENOMEM;

	value = mwl_drv_get_htbw(wdev->netdev);

	if (nla_put_u32(skb, MWL_VENDOR_ATTR_HTBW, value)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_set_filter(struct wiphy *wiphy,
			  struct wireless_dev *wdev,
			  const void *data, int data_len)
{
	uint8_t value;

	if (!data)
		return -EINVAL;

	value = *(uint8_t *) data;

	return mwl_drv_set_filter(wdev->netdev, value);
}

static int
mwl_vendor_cmd_get_filter(struct wiphy *wiphy,
			  struct wireless_dev *wdev,
			  const void *data, int data_len)
{
	struct sk_buff *skb;
	uint32_t value;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 8);
	if (skb == NULL)
		return -ENOMEM;

	value = mwl_drv_get_filter(wdev->netdev);

	if (nla_put_u32(skb, MWL_VENDOR_ATTR_FILTER, value)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_add_filtermac(struct wiphy *wiphy,
			     struct wireless_dev *wdev,
			     const void *data, int data_len)
{
	char p[6];

	if ((!data) || (data_len != 6))
		return -EINVAL;

	memcpy(p, (uint8_t *) data, 6);

	return mwl_drv_add_filtermac(wdev->netdev, p, 6);
}

static int
mwl_vendor_cmd_del_filtermac(struct wiphy *wiphy,
			     struct wireless_dev *wdev,
			     const void *data, int data_len)
{
	if ((!data) || ((data_len != 6) && (data_len != 1)))
		return -EINVAL;

	return mwl_drv_del_filtermac(wdev->netdev, (char *)data, data_len);
}

static int
mwl_vendor_cmd_get_filtermac(struct wiphy *wiphy,
			     struct wireless_dev *wdev,
			     const void *data, int data_len)
{
	struct sk_buff *skb;
	char *buff;
	size_t size = 3072;

	buff = kmalloc(size, GFP_KERNEL);
	if (buff == NULL)
		return -ENOMEM;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + size);
	if (skb == NULL) {
		kfree(buff);
		return -ENOMEM;
	}

	mwl_drv_get_filtermac(wdev->netdev, buff);

	if (nla_put_string(skb, MWL_VENDOR_ATTR_FILTERMAC, buff)) {
		kfree(buff);
		nlmsg_free(skb);
		return -EMSGSIZE;
	}
	kfree(buff);

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_set_intrabss(struct wiphy *wiphy,
			    struct wireless_dev *wdev,
			    const void *data, int data_len)
{
	uint8_t intrabss;

	if (!data || data_len > sizeof(uint32_t))
		return -EINVAL;

	intrabss = *(uint8_t *) data;

	return mwl_drv_set_intrabss(wdev->netdev, intrabss);

}

static int
mwl_vendor_cmd_get_intrabss(struct wiphy *wiphy,
			    struct wireless_dev *wdev,
			    const void *data, int data_len)
{
	struct sk_buff *skb;
	uint32_t intrabss;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 8);
	if (skb == NULL)
		return -ENOMEM;

	intrabss = mwl_drv_get_intrabss(wdev->netdev);

	if (nla_put_u32(skb, MWL_VENDOR_ATTR_INTRABSS, intrabss)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_set_hidessid(struct wiphy *wiphy,
			    struct wireless_dev *wdev,
			    const void *data, int data_len)
{
	uint8_t hidessid;

	if (!data || data_len > sizeof(uint32_t))
		return -EINVAL;

	hidessid = *(uint8_t *) data;

	return mwl_drv_set_hidessid(wdev->netdev, hidessid);

}

static int
mwl_vendor_cmd_get_hidessid(struct wiphy *wiphy,
			    struct wireless_dev *wdev,
			    const void *data, int data_len)
{
	struct sk_buff *skb;
	uint32_t hidessid;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 8);
	if (skb == NULL)
		return -ENOMEM;

	hidessid = mwl_drv_get_hidessid(wdev->netdev);

	if (nla_put_u32(skb, MWL_VENDOR_ATTR_HIDESSID, hidessid)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_set_bcninterval(struct wiphy *wiphy,
			       struct wireless_dev *wdev,
			       const void *data, int data_len)
{
	uint16_t bcninterval;

	if (!data || data_len > sizeof(uint32_t))
		return -EINVAL;

	bcninterval = *(uint16_t *) data;

	return mwl_drv_set_bcninterval(wdev->netdev, bcninterval);
}

static int
mwl_vendor_cmd_get_bcninterval(struct wiphy *wiphy,
			       struct wireless_dev *wdev,
			       const void *data, int data_len)
{
	struct sk_buff *skb;
	uint32_t bcninterval;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 8);
	if (skb == NULL)
		return -ENOMEM;

	bcninterval = mwl_drv_get_bcninterval(wdev->netdev);

	if (nla_put_u32(skb, MWL_VENDOR_ATTR_BCNINTERVAL, bcninterval)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_set_dtim(struct wiphy *wiphy,
			struct wireless_dev *wdev,
			const void *data, int data_len)
{
	uint8_t dtim;

	if (!data || data_len > sizeof(uint32_t))
		return -EINVAL;

	dtim = *(uint8_t *) data;

	return mwl_drv_set_dtim(wdev->netdev, dtim);

}

static int
mwl_vendor_cmd_get_dtim(struct wiphy *wiphy,
			struct wireless_dev *wdev,
			const void *data, int data_len)
{
	struct sk_buff *skb;
	uint32_t dtim;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 8);
	if (skb == NULL)
		return -ENOMEM;

	dtim = mwl_drv_get_dtim(wdev->netdev);

	if (nla_put_u32(skb, MWL_VENDOR_ATTR_DTIM, dtim)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_set_gprotect(struct wiphy *wiphy,
			    struct wireless_dev *wdev,
			    const void *data, int data_len)
{
	uint8_t gprotect;

	if (!data || data_len > sizeof(uint32_t))
		return -EINVAL;

	gprotect = *(uint8_t *) data;

	return mwl_drv_set_gprotect(wdev->netdev, gprotect);
}

static int
mwl_vendor_cmd_get_gprotect(struct wiphy *wiphy,
			    struct wireless_dev *wdev,
			    const void *data, int data_len)
{
	struct sk_buff *skb;
	uint32_t gprotect;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 8);
	if (skb == NULL)
		return -ENOMEM;

	gprotect = mwl_drv_get_gprotect(wdev->netdev);

	if (nla_put_u32(skb, MWL_VENDOR_ATTR_GPROTECT, gprotect)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_set_preamble(struct wiphy *wiphy,
			    struct wireless_dev *wdev,
			    const void *data, int data_len)
{
	uint8_t preamble;

	if (!data || data_len > sizeof(uint32_t))
		return -EINVAL;

	preamble = *(uint8_t *) data;

	return mwl_drv_set_preamble(wdev->netdev, preamble);
}

static int
mwl_vendor_cmd_get_preamble(struct wiphy *wiphy,
			    struct wireless_dev *wdev,
			    const void *data, int data_len)
{
	struct sk_buff *skb;
	uint32_t preamble;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 8);
	if (skb == NULL)
		return -ENOMEM;

	preamble = mwl_drv_get_preamble(wdev->netdev);

	if (preamble == 0xFF)
		return -EFAULT;

	if (nla_put_u32(skb, MWL_VENDOR_ATTR_PREAMBLE, preamble)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_set_agingtime(struct wiphy *wiphy,
			     struct wireless_dev *wdev,
			     const void *data, int data_len)
{
	uint32_t agingtime;

	if (!data || data_len > sizeof(uint32_t))
		return -EINVAL;

	agingtime = *(uint32_t *) data;

	return mwl_drv_set_agingtime(wdev->netdev, agingtime);

}

static int
mwl_vendor_cmd_get_agingtime(struct wiphy *wiphy,
			     struct wireless_dev *wdev,
			     const void *data, int data_len)
{
	struct sk_buff *skb;
	uint32_t agingtime;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 8);
	if (skb == NULL)
		return -ENOMEM;

	agingtime = mwl_drv_get_agingtime(wdev->netdev);

	if (nla_put_u32(skb, MWL_VENDOR_ATTR_AGINGTIME, agingtime)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_set_ssid(struct wiphy *wiphy,
			struct wireless_dev *wdev,
			const void *data, int data_len)
{
	mwl_cfg80211_hex_dump("set_ssid", (uint8_t *) data, data_len);

	if (!data || data_len > 32)
		return -EINVAL;

	return mwl_drv_set_ssid(wdev->netdev, (const char *)data, data_len);
}

static int
mwl_vendor_cmd_get_ssid(struct wiphy *wiphy,
			struct wireless_dev *wdev,
			const void *data, int data_len)
{
	struct sk_buff *skb;
	uint8_t ssid[32];
	uint8_t ssid_len;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 32);
	if (skb == NULL)
		return -ENOMEM;

	ssid_len = mwl_drv_get_ssid(wdev->netdev, ssid);

	if (ssid_len) {
		if (nla_put(skb, MWL_VENDOR_ATTR_SSID, ssid_len, ssid)) {
			nlmsg_free(skb);
			return -EMSGSIZE;
		}
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_set_bssid(struct wiphy *wiphy,
			 struct wireless_dev *wdev,
			 const void *data, int data_len)
{
	uint8_t bssid[6];

	if (!data || data_len > 6)
		return -EINVAL;

	memcpy(bssid, (uint8_t *) data, 6);

	return mwl_drv_set_bssid(wdev->netdev, bssid);
}

static int
mwl_vendor_cmd_get_bssid(struct wiphy *wiphy,
			 struct wireless_dev *wdev,
			 const void *data, int data_len)
{
	struct sk_buff *skb;
	char bssid[30];

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + sizeof(bssid));
	if (skb == NULL)
		return -ENOMEM;

	mwl_drv_get_bssid(wdev->netdev, bssid);

	if (nla_put_string(skb, MWL_VENDOR_ATTR_BSSID, bssid)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_set_regioncode(struct wiphy *wiphy,
			      struct wireless_dev *wdev,
			      const void *data, int data_len)
{
	uint8_t regioncode;

	if (!data || data_len > sizeof(uint32_t))
		return -EINVAL;

	regioncode = *(uint8_t *) data;

	return mwl_drv_set_regioncode(wdev->netdev, regioncode);

}

static int
mwl_vendor_cmd_get_regioncode(struct wiphy *wiphy,
			      struct wireless_dev *wdev,
			      const void *data, int data_len)
{
	struct sk_buff *skb;
	uint32_t regioncode;
	uint8_t flag = 0;
	char output[40];

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + sizeof(output));
	if (skb == NULL)
		return -ENOMEM;

	regioncode = mwl_drv_get_regioncode(wdev->netdev, &flag);

	if (flag) {
		sprintf(output, "regioncode: 0x%02x(EEPROM)\n", regioncode);
	} else {
		sprintf(output, "regioncode: 0x%02x(NON_EEPROM)\n", regioncode);
	}

	if (nla_put_string(skb, MWL_VENDOR_ATTR_REGIONCODE, output)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_set_ratemode(struct wiphy *wiphy,
			    struct wireless_dev *wdev,
			    const void *data, int data_len)
{
	uint8_t ratemode;

	if (!data || data_len > sizeof(uint32_t))
		return -EINVAL;

	ratemode = *(uint8_t *) data;

	return mwl_drv_set_ratemode(wdev->netdev, ratemode);

}

static int
mwl_vendor_cmd_get_ratemode(struct wiphy *wiphy,
			    struct wireless_dev *wdev,
			    const void *data, int data_len)
{
	struct sk_buff *skb;
	uint32_t ratemode;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 8);
	if (skb == NULL)
		return -ENOMEM;

	ratemode = mwl_drv_get_ratemode(wdev->netdev);

	if (nla_put_u32(skb, MWL_VENDOR_ATTR_RATEMODE, ratemode)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_set_wdsmode(struct wiphy *wiphy,
			   struct wireless_dev *wdev,
			   const void *data, int data_len)
{
	uint8_t wdsmode;

	if (!data || data_len > sizeof(uint32_t))
		return -EINVAL;

	wdsmode = *(uint8_t *) data;

	return mwl_drv_set_wdsmode(wdev->netdev, wdsmode);

}

static int
mwl_vendor_cmd_get_wdsmode(struct wiphy *wiphy,
			   struct wireless_dev *wdev,
			   const void *data, int data_len)
{
	struct sk_buff *skb;
	uint32_t wdsmode;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 8);
	if (skb == NULL)
		return -ENOMEM;

	wdsmode = mwl_drv_get_wdsmode(wdev->netdev);

	if (nla_put_u32(skb, MWL_VENDOR_ATTR_WDSMODE, wdsmode)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_set_disableassoc(struct wiphy *wiphy,
				struct wireless_dev *wdev,
				const void *data, int data_len)
{
	uint8_t disableassoc;

	if (!data || data_len > sizeof(uint32_t))
		return -EINVAL;

	disableassoc = *(uint8_t *) data;

	return mwl_drv_set_disableassoc(wdev->netdev, disableassoc);

}

static int
mwl_vendor_cmd_get_disableassoc(struct wiphy *wiphy,
				struct wireless_dev *wdev,
				const void *data, int data_len)
{
	struct sk_buff *skb;
	uint32_t disableassoc;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 8);
	if (skb == NULL)
		return -ENOMEM;

	disableassoc = mwl_drv_get_disableassoc(wdev->netdev);

	if (nla_put_u32(skb, MWL_VENDOR_ATTR_DISABLEASSOC, disableassoc)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_set_wds(struct wiphy *wiphy,
		       struct wireless_dev *wdev,
		       const void *data, int data_len)
{
	uint8_t wds[8];

	if (!data || data_len > 8)
		return -EINVAL;

	memcpy(wds, (uint8_t *) data, 8);

	return mwl_drv_set_wds(wdev->netdev, wds);

}

static int
mwl_vendor_cmd_get_wds(struct wiphy *wiphy,
		       struct wireless_dev *wdev,
		       const void *data, int data_len)
{
	struct sk_buff *skb;
	char wds[500];

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + sizeof(wds));
	if (skb == NULL)
		return -ENOMEM;

	mwl_drv_get_wds(wdev->netdev, wds);

	if (nla_put_string(skb, MWL_VENDOR_ATTR_WDS, wds)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

#ifdef IEEE80211_DH
static int
mwl_vendor_cmd_set_11dmode(struct wiphy *wiphy,
			   struct wireless_dev *wdev,
			   const void *data, int data_len)
{
	uint8_t dmode;

	if (!data || data_len > sizeof(uint32_t))
		return -EINVAL;

	dmode = *(uint8_t *) data;

	return mwl_drv_set_11dmode(wdev->netdev, dmode);

}

static int
mwl_vendor_cmd_get_11dmode(struct wiphy *wiphy,
			   struct wireless_dev *wdev,
			   const void *data, int data_len)
{
	struct sk_buff *skb;
	uint32_t dmode;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 8);
	if (skb == NULL)
		return -ENOMEM;

	dmode = mwl_drv_get_11dmode(wdev->netdev);

	if (nla_put_u32(skb, MWL_VENDOR_ATTR_11DMODE, dmode)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_set_11hspecmgt(struct wiphy *wiphy,
			      struct wireless_dev *wdev,
			      const void *data, int data_len)
{

	uint8_t hspecmgt;

	if (!data || data_len > sizeof(uint32_t))
		return -EINVAL;

	hspecmgt = *(uint8_t *) data;

	return mwl_drv_set_11hspecmgt(wdev->netdev, hspecmgt);

}

static int
mwl_vendor_cmd_get_11hspecmgt(struct wiphy *wiphy,
			      struct wireless_dev *wdev,
			      const void *data, int data_len)
{
	struct sk_buff *skb;
	uint32_t hspecmgt;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 8);
	if (skb == NULL)
		return -ENOMEM;

	hspecmgt = mwl_drv_get_11hspecmgt(wdev->netdev);

	if (nla_put_u32(skb, MWL_VENDOR_ATTR_11HSPECMGT, hspecmgt)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_set_11hpwrconstr(struct wiphy *wiphy,
				struct wireless_dev *wdev,
				const void *data, int data_len)
{
	uint8_t hpwrconstr;

	if (!data || data_len > sizeof(uint32_t))
		return -EINVAL;

	hpwrconstr = *(uint8_t *) data;

	return mwl_drv_set_11hpwrconstr(wdev->netdev, hpwrconstr);

}

static int
mwl_vendor_cmd_get_11hpwrconstr(struct wiphy *wiphy,
				struct wireless_dev *wdev,
				const void *data, int data_len)
{
	struct sk_buff *skb;
	uint32_t hpwrconstr;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 8);
	if (skb == NULL)
		return -ENOMEM;

	hpwrconstr = mwl_drv_get_11hpwrconstr(wdev->netdev);

	if (nla_put_u32(skb, MWL_VENDOR_ATTR_11HPWRCONSTR, hpwrconstr)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_set_11hcsaMode(struct wiphy *wiphy,
			      struct wireless_dev *wdev,
			      const void *data, int data_len)
{
	uint8_t vendorData = 0;

	if (!data || data_len > sizeof(uint32_t))
		return -EINVAL;

	vendorData = *((uint8_t *) data);

	return mwl_drv_set_11hcsaMode(wdev->netdev, vendorData);
}

static int
mwl_vendor_cmd_get_11hcsaMode(struct wiphy *wiphy,
			      struct wireless_dev *wdev,
			      const void *data, int data_len)
{
	struct sk_buff *skb;
	uint32_t vendorData = 0;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 8);
	if (skb == NULL)
		return -ENOMEM;

	vendorData = mwl_drv_get_11hcsaMode(wdev->netdev);

	if (nla_put_u32(skb, MWL_VENDOR_ATTR_11HCSAMODE, vendorData)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_set_11hcsaCount(struct wiphy *wiphy,
			       struct wireless_dev *wdev,
			       const void *data, int data_len)
{
	uint8_t vendorData = 0;

	if (!data || data_len > sizeof(uint32_t))
		return -EINVAL;

	vendorData = *((uint8_t *) data);

	return mwl_drv_set_11hcsaCount(wdev->netdev, vendorData);
}

static int
mwl_vendor_cmd_get_11hcsaCount(struct wiphy *wiphy,
			       struct wireless_dev *wdev,
			       const void *data, int data_len)
{
	struct sk_buff *skb;
	uint32_t vendorData = 0;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 8);
	if (skb == NULL)
		return -ENOMEM;

	vendorData = mwl_drv_get_11hcsaCount(wdev->netdev);

	if (nla_put_u32(skb, MWL_VENDOR_ATTR_11HCSACOUNT, vendorData)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_set_11hdfsMode(struct wiphy *wiphy,
			      struct wireless_dev *wdev,
			      const void *data, int data_len)
{
	uint8_t vendorData = 0;

	if (!data || data_len > sizeof(uint32_t))
		return -EINVAL;

	vendorData = *((uint8_t *) data);

	return mwl_drv_set_11hdfsMode(wdev->netdev, vendorData);
}

static int
mwl_vendor_cmd_get_11hdfsMode(struct wiphy *wiphy,
			      struct wireless_dev *wdev,
			      const void *data, int data_len)
{
	struct sk_buff *skb;
	uint32_t vendorData = 0;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 8);
	if (skb == NULL)
		return -ENOMEM;

	vendorData = mwl_drv_get_11hdfsMode(wdev->netdev);

	if (nla_put_u32(skb, MWL_VENDOR_ATTR_11HDFSMODE, vendorData)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_set_11hcsaChan(struct wiphy *wiphy,
			      struct wireless_dev *wdev,
			      const void *data, int data_len)
{
	uint8_t vendorData = 0;

	if (!data || data_len > sizeof(uint32_t))
		return -EINVAL;

	vendorData = *((uint8_t *) data);

	return mwl_drv_set_11hcsaChan(wdev->netdev, vendorData);
}

static int
mwl_vendor_cmd_get_11hcsaChan(struct wiphy *wiphy,
			      struct wireless_dev *wdev,
			      const void *data, int data_len)
{
	struct sk_buff *skb;
	uint32_t vendorData = 0;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 8);
	if (skb == NULL)
		return -ENOMEM;

	vendorData = mwl_drv_get_11hcsaChan(wdev->netdev);

	if (nla_put_u32(skb, MWL_VENDOR_ATTR_11HCSACHAN, vendorData)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_set_11hcsaStart(struct wiphy *wiphy,
			       struct wireless_dev *wdev,
			       const void *data, int data_len)
{
	uint8_t vendorData = 0;

	if (!data || data_len > sizeof(uint32_t))
		return -EINVAL;

	vendorData = *((uint8_t *) data);

	return mwl_drv_set_11hcsaStart(wdev->netdev, vendorData);
}
#endif

#ifdef MRVL_DFS
static int
mwl_vendor_cmd_set_11hnopTimeout(struct wiphy *wiphy,
				 struct wireless_dev *wdev,
				 const void *data, int data_len)
{
	uint16_t vendorData = 0;

	if (!data || data_len > sizeof(uint32_t))
		return -EINVAL;

	vendorData = *((uint16_t *) data);
	return mwl_drv_set_11hnopTimeout(wdev->netdev, vendorData);
}

static int
mwl_vendor_cmd_get_11hnopTimeout(struct wiphy *wiphy,
				 struct wireless_dev *wdev,
				 const void *data, int data_len)
{
	struct sk_buff *skb;
	uint32_t vendorData = 0;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 8);
	if (skb == NULL)
		return -ENOMEM;

	vendorData = mwl_drv_get_11hnopTimeout(wdev->netdev);

	if (nla_put_u32(skb, MWL_VENDOR_ATTR_11HNOPTIMEOUT, vendorData)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_set_11hcacTimeout(struct wiphy *wiphy,
				 struct wireless_dev *wdev,
				 const void *data, int data_len)
{
	uint8_t vendorData = 0;

	if (!data || data_len > sizeof(uint32_t))
		return -EINVAL;

	vendorData = *((uint8_t *) data);
	return mwl_drv_set_11hcacTimeout(wdev->netdev, vendorData);
}

static int
mwl_vendor_cmd_get_11hcacTimeout(struct wiphy *wiphy,
				 struct wireless_dev *wdev,
				 const void *data, int data_len)
{
	struct sk_buff *skb;
	uint32_t vendorData = 0;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 8);
	if (skb == NULL)
		return -ENOMEM;

	vendorData = mwl_drv_get_11hcacTimeout(wdev->netdev);

	if (nla_put_u32(skb, MWL_VENDOR_ATTR_11HCACTIMEOUT, vendorData)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

#endif

static int
mwl_vendor_cmd_set_csMode(struct wiphy *wiphy,
			  struct wireless_dev *wdev,
			  const void *data, int data_len)
{
	uint8_t vendorData = 0;

	if (!data || data_len > sizeof(uint32_t))
		return -EINVAL;

	vendorData = *((uint8_t *) data);
	return mwl_drv_set_csMode(wdev->netdev, vendorData);
}

static int
mwl_vendor_cmd_get_csMode(struct wiphy *wiphy,
			  struct wireless_dev *wdev,
			  const void *data, int data_len)
{
	struct sk_buff *skb;
	uint32_t vendorData = 0;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 8);
	if (skb == NULL)
		return -ENOMEM;

	vendorData = mwl_drv_get_csMode(wdev->netdev);

	if (nla_put_u32(skb, MWL_VENDOR_ATTR_CSMODE, vendorData)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_set_guardIntv(struct wiphy *wiphy,
			     struct wireless_dev *wdev,
			     const void *data, int data_len)
{
	uint8_t vendorData = 0;

	if (!data || data_len > sizeof(uint32_t))
		return -EINVAL;

	vendorData = *((uint8_t *) data);
	return mwl_drv_set_guardIntv(wdev->netdev, vendorData);
}

static int
mwl_vendor_cmd_get_guardIntv(struct wiphy *wiphy,
			     struct wireless_dev *wdev,
			     const void *data, int data_len)
{
	struct sk_buff *skb;
	uint32_t vendorData = 0;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 8);
	if (skb == NULL)
		return -ENOMEM;

	vendorData = mwl_drv_get_guardIntv(wdev->netdev);

	if (nla_put_u32(skb, MWL_VENDOR_ATTR_GUARDINT, vendorData)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_set_extSubCh(struct wiphy *wiphy,
			    struct wireless_dev *wdev,
			    const void *data, int data_len)
{
	uint8_t vendorData = 0;

	if (!data || data_len > sizeof(uint32_t))
		return -EINVAL;

	vendorData = *((uint8_t *) data);
	return mwl_drv_set_extSubCh(wdev->netdev, vendorData);
}

static int
mwl_vendor_cmd_get_extSubCh(struct wiphy *wiphy,
			    struct wireless_dev *wdev,
			    const void *data, int data_len)
{
	struct sk_buff *skb;
	uint32_t vendorData = 0;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 8);
	if (skb == NULL)
		return -ENOMEM;

	vendorData = mwl_drv_get_extSubCh(wdev->netdev);

	if (nla_put_u32(skb, MWL_VENDOR_ATTR_EXTSUBCH, vendorData)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_set_htProtect(struct wiphy *wiphy,
			     struct wireless_dev *wdev,
			     const void *data, int data_len)
{
	uint8_t vendorData = 0;

	if (!data || data_len > sizeof(uint32_t))
		return -EINVAL;

	vendorData = *((uint8_t *) data);
	return mwl_drv_set_htProtect(wdev->netdev, vendorData);
}

static int
mwl_vendor_cmd_get_htProtect(struct wiphy *wiphy,
			     struct wireless_dev *wdev,
			     const void *data, int data_len)
{
	struct sk_buff *skb;
	uint32_t vendorData = 0;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 8);
	if (skb == NULL)
		return -ENOMEM;

	vendorData = mwl_drv_get_htProtect(wdev->netdev);

	if (nla_put_u32(skb, MWL_VENDOR_ATTR_HTPROTECT, vendorData)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_set_ampduFactor(struct wiphy *wiphy,
			       struct wireless_dev *wdev,
			       const void *data, int data_len)
{
	uint8_t vendorData = 0;

	if (!data || data_len > sizeof(uint32_t))
		return -EINVAL;

	vendorData = *((uint8_t *) data);
	return mwl_drv_set_ampduFactor(wdev->netdev, vendorData);
}

static int
mwl_vendor_cmd_get_ampduFactor(struct wiphy *wiphy,
			       struct wireless_dev *wdev,
			       const void *data, int data_len)
{
	struct sk_buff *skb;
	uint32_t vendorData = 0;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 8);
	if (skb == NULL)
		return -ENOMEM;

	vendorData = mwl_drv_get_ampduFactor(wdev->netdev);

	if (nla_put_u32(skb, MWL_VENDOR_ATTR_AMPDUFACTOR, vendorData)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_set_ampduDen(struct wiphy *wiphy,
			    struct wireless_dev *wdev,
			    const void *data, int data_len)
{
	uint8_t vendorData = 0;

	if (!data || data_len > sizeof(uint32_t))
		return -EINVAL;

	vendorData = *((uint8_t *) data);
	return mwl_drv_set_ampduDen(wdev->netdev, vendorData);
}

static int
mwl_vendor_cmd_get_ampduDen(struct wiphy *wiphy,
			    struct wireless_dev *wdev,
			    const void *data, int data_len)
{
	struct sk_buff *skb;
	uint32_t vendorData = 0;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 8);
	if (skb == NULL)
		return -ENOMEM;

	vendorData = mwl_drv_get_ampduDen(wdev->netdev);

	if (nla_put_u32(skb, MWL_VENDOR_ATTR_AMPDUDEN, vendorData)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

#ifdef AMPDU_SUPPORT
static int
mwl_vendor_cmd_set_ampduTx(struct wiphy *wiphy,
			   struct wireless_dev *wdev,
			   const void *data, int data_len)
{
	uint8_t vendorData = 0;

	if (!data || data_len > sizeof(uint32_t))
		return -EINVAL;

	vendorData = *((uint8_t *) data);
	return mwl_drv_set_ampduTx(wdev->netdev, vendorData);
}

static int
mwl_vendor_cmd_get_ampduTx(struct wiphy *wiphy,
			   struct wireless_dev *wdev,
			   const void *data, int data_len)
{
	struct sk_buff *skb;
	uint32_t vendorData = 0;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 8);
	if (skb == NULL)
		return -ENOMEM;

	vendorData = mwl_drv_get_ampduTx(wdev->netdev);

	if (nla_put_u32(skb, MWL_VENDOR_ATTR_AMPDUTX, vendorData)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

#endif

static int
mwl_vendor_cmd_set_txPower(struct wiphy *wiphy,
			   struct wireless_dev *wdev,
			   const void *data, int data_len)
{
	/* to do, not support right now */
	return -EINVAL;
}

static int
mwl_vendor_cmd_get_txPower(struct wiphy *wiphy,
			   struct wireless_dev *wdev,
			   const void *data, int data_len)
{
	/*
	   struct sk_buff *skb;
	   uint32_t vendorData = 0;

	   skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 8);
	   if (skb == NULL)
	   return -ENOMEM;

	   vendorData = mwl_drv_get_txPower(wdev->netdev);

	   if (nla_put_u32(skb, MWL_VENDOR_ATTR_TXPOWER, vendorData)) {
	   nlmsg_free(skb);
	   return -EMSGSIZE;
	   }

	   if (cfg80211_vendor_cmd_reply(skb))
	   return -EFAULT;

	   return 0;
	 */
	mwl_drv_get_txPower(wdev->netdev);

	return 0;
}

static int
mwl_vendor_cmd_get_fwStat(struct wiphy *wiphy,
			  struct wireless_dev *wdev,
			  const void *data, int data_len)
{
	return mwl_drv_get_fwStat(wdev->netdev);
}

static int
mwl_vendor_cmd_set_autoChannel(struct wiphy *wiphy,
			       struct wireless_dev *wdev,
			       const void *data, int data_len)
{
	uint8_t vendorData = 0;

	if (!data || data_len > sizeof(uint32_t))
		return -EINVAL;

	vendorData = *((uint8_t *) data);
	return mwl_drv_set_autoChannel(wdev->netdev, vendorData);
}

static int
mwl_vendor_cmd_get_autoChannel(struct wiphy *wiphy,
			       struct wireless_dev *wdev,
			       const void *data, int data_len)
{
	struct sk_buff *skb;
	uint32_t vendorData = 0;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 8);
	if (skb == NULL)
		return -ENOMEM;

	vendorData = mwl_drv_get_autoChannel(wdev->netdev);

	if (nla_put_u32(skb, MWL_VENDOR_ATTR_AUTOCHANNEL, vendorData)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_set_maxTxPower(struct wiphy *wiphy,
			      struct wireless_dev *wdev,
			      const void *data, int data_len)
{
	uint8_t vendorData = 0;

	if (!data || data_len > sizeof(uint32_t))
		return -EINVAL;

	vendorData = *((uint8_t *) data);
	return mwl_drv_set_maxTxPower(wdev->netdev, vendorData);
}

static int
mwl_vendor_cmd_get_maxTxPower(struct wiphy *wiphy,
			      struct wireless_dev *wdev,
			      const void *data, int data_len)
{
	struct sk_buff *skb;
	uint32_t vendorData = 0;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 8);
	if (skb == NULL)
		return -ENOMEM;

	vendorData = mwl_drv_get_maxTxPower(wdev->netdev);

	if (nla_put_u32(skb, MWL_VENDOR_ATTR_MAXTXPOWER, vendorData)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_del_wepKey(struct wiphy *wiphy,
			  struct wireless_dev *wdev,
			  const void *data, int data_len)
{
	uint8_t vendorData = 0;

	if (!data || data_len > sizeof(uint32_t))
		return -EINVAL;

	vendorData = *((uint8_t *) data);
	return mwl_drv_del_wepKey(wdev->netdev, vendorData);
}

static int
mwl_vendor_cmd_set_strictShared(struct wiphy *wiphy,
				struct wireless_dev *wdev,
				const void *data, int data_len)
{
	uint8_t vendorData = 0;

	if (!data || data_len > sizeof(uint32_t))
		return -EINVAL;

	vendorData = *((uint8_t *) data);
	return mwl_drv_set_strictShared(wdev->netdev, vendorData);
}

static int
mwl_vendor_cmd_get_strictShared(struct wiphy *wiphy,
				struct wireless_dev *wdev,
				const void *data, int data_len)
{
	struct sk_buff *skb;
	uint32_t vendorData = 0;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 8);
	if (skb == NULL)
		return -ENOMEM;

	vendorData = mwl_drv_get_strictShared(wdev->netdev);

	if (nla_put_u32(skb, MWL_VENDOR_ATTR_STRICTSHARED, vendorData)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

#ifdef PWRFRAC
static int
mwl_vendor_cmd_set_txPowerFraction(struct wiphy *wiphy,
				   struct wireless_dev *wdev,
				   const void *data, int data_len)
{
	uint8_t vendorData = 0;

	if (!data || data_len > sizeof(uint32_t))
		return -EINVAL;

	vendorData = *((uint8_t *) data);
	return mwl_drv_set_txPowerFraction(wdev->netdev, vendorData);
}

static int
mwl_vendor_cmd_get_txPowerFraction(struct wiphy *wiphy,
				   struct wireless_dev *wdev,
				   const void *data, int data_len)
{
	struct sk_buff *skb;
	uint32_t vendorData = 0;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 8);
	if (skb == NULL)
		return -ENOMEM;

	vendorData = mwl_drv_get_txPowerFraction(wdev->netdev);

	if (nla_put_u32(skb, MWL_VENDOR_ATTR_PWRFRACTION, vendorData)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

#endif

static int
mwl_vendor_cmd_set_mimops(struct wiphy *wiphy,
			  struct wireless_dev *wdev,
			  const void *data, int data_len)
{
	return mwl_drv_set_mimops(wdev->netdev, *(int *)data);
}

static int
mwl_vendor_cmd_get_mimops(struct wiphy *wiphy,
			  struct wireless_dev *wdev,
			  const void *data, int data_len)
{
	struct sk_buff *skb;
	uint32_t mimops;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 8);
	if (skb == NULL)
		return -ENOMEM;

	mimops = mwl_drv_get_mimops(wdev->netdev);

	if (nla_put_u32(skb, MWL_VENDOR_ATTR_MIMOPS, mimops)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_set_txantenna(struct wiphy *wiphy,
			     struct wireless_dev *wdev,
			     const void *data, int data_len)
{
	return mwl_drv_set_txantenna(wdev->netdev, *(int *)data);
}

static int
mwl_vendor_cmd_get_txantenna(struct wiphy *wiphy,
			     struct wireless_dev *wdev,
			     const void *data, int data_len)
{
	struct sk_buff *skb;
	uint32_t txantenna;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 8);
	if (skb == NULL)
		return -ENOMEM;

	txantenna = mwl_drv_get_txantenna(wdev->netdev);

	if (nla_put_u32(skb, MWL_VENDOR_ATTR_TXANTENNA, txantenna)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_set_htgf(struct wiphy *wiphy,
			struct wireless_dev *wdev,
			const void *data, int data_len)
{
	return mwl_drv_set_htgf(wdev->netdev, *(int *)data);
}

static int
mwl_vendor_cmd_get_htgf(struct wiphy *wiphy,
			struct wireless_dev *wdev,
			const void *data, int data_len)
{
	struct sk_buff *skb;
	uint32_t htgf;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 8);
	if (skb == NULL)
		return -ENOMEM;

	htgf = mwl_drv_get_htgf(wdev->netdev);

	if (nla_put_u32(skb, MWL_VENDOR_ATTR_HTGF, htgf)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_set_htstbc(struct wiphy *wiphy,
			  struct wireless_dev *wdev,
			  const void *data, int data_len)
{
	return mwl_drv_set_htstbc(wdev->netdev, *(int *)data);
}

static int
mwl_vendor_cmd_get_htstbc(struct wiphy *wiphy,
			  struct wireless_dev *wdev,
			  const void *data, int data_len)
{
	struct sk_buff *skb;
	uint32_t htstbc;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 8);
	if (skb == NULL)
		return -ENOMEM;

	htstbc = mwl_drv_get_htstbc(wdev->netdev);

	if (nla_put_u32(skb, MWL_VENDOR_ATTR_HTSTBC, htstbc)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_set_3x3rate(struct wiphy *wiphy,
			   struct wireless_dev *wdev,
			   const void *data, int data_len)
{
	return mwl_drv_set_3x3rate(wdev->netdev, *(int *)data);
}

static int
mwl_vendor_cmd_get_3x3rate(struct wiphy *wiphy,
			   struct wireless_dev *wdev,
			   const void *data, int data_len)
{
	struct sk_buff *skb;
	uint32_t rate;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 8);
	if (skb == NULL)
		return -ENOMEM;

	rate = mwl_drv_get_3x3rate(wdev->netdev);

	if (nla_put_u32(skb, MWL_VENDOR_ATTR_3X3RATE, rate)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_set_intolerant40(struct wiphy *wiphy,
				struct wireless_dev *wdev,
				const void *data, int data_len)
{
	return mwl_drv_set_intolerant40(wdev->netdev, (unsigned char *)data,
					data_len);
}

static int
mwl_vendor_cmd_set_txqlimit(struct wiphy *wiphy,
			    struct wireless_dev *wdev,
			    const void *data, int data_len)
{
	return mwl_drv_set_txqlimit(wdev->netdev, *(unsigned int *)data);
}

static int
mwl_vendor_cmd_get_txqlimit(struct wiphy *wiphy,
			    struct wireless_dev *wdev,
			    const void *data, int data_len)
{
	struct sk_buff *skb;
	uint32_t txqlimit;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 8);
	if (skb == NULL)
		return -ENOMEM;

	txqlimit = mwl_drv_get_txqlimit(wdev->netdev);

	if (nla_put_u32(skb, MWL_VENDOR_ATTR_TXQLIMIT, txqlimit)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_set_rifs(struct wiphy *wiphy,
			struct wireless_dev *wdev,
			const void *data, int data_len)
{
	return mwl_drv_set_rifs(wdev->netdev, *(unsigned char *)data);

}

int
mwl_vendor_cmd_set_bftype(struct wiphy *wiphy,
			  struct wireless_dev *wdev,
			  const void *data, int data_len)
{
	return mwl_drv_set_bftype(wdev->netdev, *(int *)data);

}

static int
mwl_vendor_cmd_set_bandsteer(struct wiphy *wiphy,
			     struct wireless_dev *wdev,
			     const void *data, int data_len)
{
	int ret;
	struct nlattr *tb[NUM_MWL_VENDOR_ATTR];

	if (!data)
		return -EINVAL;

	ret = nla_parse(tb, MAX_MWL_VENDOR_ATTR, data, data_len,
			mwl_vendor_attr_policy);
	if (ret)
		return ret;

	if (!tb[MWL_VENDOR_ATTR_BANDSTEER])
		return -EINVAL;

	return mwl_drv_set_bandsteer(wdev->netdev,
				     nla_get_u8(tb[MWL_VENDOR_ATTR_BANDSTEER]));
}

static int
mwl_vendor_cmd_get_bandsteer(struct wiphy *wiphy,
			     struct wireless_dev *wdev,
			     const void *data, int data_len)
{
	struct sk_buff *skb;
	uint32_t bandsteer;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 8);
	if (skb == NULL)
		return -ENOMEM;

	bandsteer = mwl_drv_get_bandsteer(wdev->netdev);

	if (nla_put_u32(skb, MWL_VENDOR_ATTR_BANDSTEER, bandsteer)) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	if (cfg80211_vendor_cmd_reply(skb))
		return -EFAULT;

	return 0;
}

static int
mwl_vendor_cmd_set_appie(struct wiphy *wiphy,
			 struct wireless_dev *wdev,
			 const void *data, int data_len)
{
	int ret;
	struct nlattr *tb[NUM_MWL_VENDOR_ATTR];
	struct mwl_appie *appie;

	if (!data)
		return -EINVAL;

	ret = nla_parse(tb, MAX_MWL_VENDOR_ATTR, data, data_len,
			mwl_vendor_attr_policy);
	if (ret)
		return ret;

	if (!tb[MWL_VENDOR_ATTR_APPIE])
		return -EINVAL;

	appie = (struct mwl_appie *)nla_data(tb[MWL_VENDOR_ATTR_APPIE]);

	return mwl_drv_set_appie(wdev->netdev, appie);
}

static int
mwl_vendor_cmd_get_ie(struct wiphy *wiphy,
		      struct wireless_dev *wdev, const void *data, int data_len)
{
	int ret;
	struct nlattr *tb[NUM_MWL_VENDOR_ATTR_IE];
	struct sk_buff *skb;
	uint16_t ie_len;
	uint8_t reassoc;
	uint8_t ie[256];

	if (!data)
		return -EINVAL;

	ret = nla_parse(tb, MAX_MWL_VENDOR_ATTR_IE, data, data_len,
			mwl_vendor_attr_ie_policy);
	if (ret)
		return ret;

	if (!tb[MWL_VENDOR_ATTR_IE_TYPE] || !tb[MWL_VENDOR_ATTR_IE_MAC])
		return -EINVAL;

	if (nla_len(tb[MWL_VENDOR_ATTR_IE_MAC]) != ETH_ALEN)
		return -EINVAL;

	ret = mwl_drv_get_ie(wdev->netdev,
			     nla_get_u8(tb[MWL_VENDOR_ATTR_IE_TYPE]),
			     nla_data(tb[MWL_VENDOR_ATTR_IE_MAC]), &ie_len,
			     &reassoc, ie);

	if (!ret) {
		skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 10 + 300);
		if (skb == NULL)
			return -ENOMEM;

		if (nla_put_u8(skb, MWL_VENDOR_ATTR_IE_LEN, ie_len) ||
		    nla_put_u8(skb, MWL_VENDOR_ATTR_IE_REASSOC, reassoc) ||
		    nla_put(skb, MWL_VENDOR_ATTR_IE_DATA, ie_len, ie)) {
			nlmsg_free(skb);
			return -EMSGSIZE;
		}

		if (cfg80211_vendor_cmd_reply(skb))
			return -EFAULT;
	}

	return ret;
}

static int
mwl_vendor_cmd_send_mlme(struct wiphy *wiphy,
			 struct wireless_dev *wdev,
			 const void *data, int data_len)
{
	int ret;
	struct nlattr *tb[NUM_MWL_VENDOR_ATTR];
	struct mwl_mlme *mlme;

	if (!data)
		return -EINVAL;

	ret = nla_parse(tb, MAX_MWL_VENDOR_ATTR, data, data_len,
			mwl_vendor_attr_policy);
	if (ret)
		return ret;

	if (!tb[MWL_VENDOR_ATTR_MLME])
		return -EINVAL;

	mlme = (struct mwl_mlme *)nla_data(tb[MWL_VENDOR_ATTR_MLME]);

	return mwl_drv_send_mlme(wdev->netdev, mlme);
}

static int
mwl_vendor_cmd_set_countermeasures(struct wiphy *wiphy,
				   struct wireless_dev *wdev,
				   const void *data, int data_len)
{
	int ret;
	struct nlattr *tb[NUM_MWL_VENDOR_ATTR];

	if (!data)
		return -EINVAL;

	ret = nla_parse(tb, MAX_MWL_VENDOR_ATTR, data, data_len,
			mwl_vendor_attr_policy);
	if (ret)
		return ret;

	if (!tb[MWL_VENDOR_ATTR_COUNTERMEASURES])
		return -EINVAL;

	return mwl_drv_set_countermeasures(wdev->netdev,
					   nla_get_u32(tb
						       [MWL_VENDOR_ATTR_COUNTERMEASURES]));
}

static int
mwl_vendor_cmd_get_seqnum(struct wiphy *wiphy,
			  struct wireless_dev *wdev,
			  const void *data, int data_len)
{
	int ret;
	struct sk_buff *skb;
	uint8_t seqnum[6];

	ret = mwl_drv_get_seqnum(wdev->netdev, seqnum);

	if (!ret) {
		skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 24);
		if (skb == NULL)
			return -ENOMEM;

		if (nla_put
		    (skb, MWL_VENDOR_ATTR_IE_DATA,
		     sizeof(seqnum) / sizeof(uint8_t), seqnum)) {
			nlmsg_free(skb);
			return -EMSGSIZE;
		}

		if (cfg80211_vendor_cmd_reply(skb))
			return -EFAULT;
	}

	return ret;
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

	ret = nla_parse(tb, MAX_MWL_VENDOR_ATTR, data, data_len,
			mwl_vendor_attr_policy);
	if (ret)
		return ret;

	if (!tb[MWL_VENDOR_ATTR_MGMT])
		return -EINVAL;

	mgmt = (struct mwl_mgmt *)nla_data(tb[MWL_VENDOR_ATTR_MGMT]);

	return mwl_drv_send_mgmt(wdev->netdev, mgmt);
}

static int
mwl_vendor_cmd_set_rts(struct wiphy *wiphy,
		       struct wireless_dev *wdev,
		       const void *data, int data_len)
{
	uint16_t rts;

	if (!data || data_len > 2)
		return -EINVAL;

	rts = *(uint16_t *) data;

	return mwl_drv_set_rts(wdev->netdev, rts);

}

static int
mwl_vendor_cmd_set_channel(struct wiphy *wiphy,
			   struct wireless_dev *wdev,
			   const void *data, int data_len)
{
	struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);
	uint8_t channel;

	if (!data || data_len > sizeof(uint32_t))
		return -EINVAL;

	channel = *(uint8_t *) data;

	return mwl_drv_set_channel(priv->netDev, channel);

}

static int
mwl_vendor_cmd_set_wepkey(struct wiphy *wiphy,
			  struct wireless_dev *wdev,
			  const void *data, int data_len)
{
	struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	if (!data)
		return -EINVAL;

	return mwl_drv_set_wepkey(priv->netDev, (uint8_t *) data, data_len - 1);
}

#ifdef MRVL_WAPI
static int
mwl_vendor_cmd_set_wapimode(struct wiphy *wiphy,
			    struct wireless_dev *wdev,
			    const void *data, int data_len)
{
	struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}

static int
mwl_vendor_cmd_get_wapimode(struct wiphy *wiphy,
			    struct wireless_dev *wdev,
			    const void *data, int data_len)
{
	struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}
#endif

static int
mwl_vendor_cmd_set_wmmackpolicy(struct wiphy *wiphy,
				struct wireless_dev *wdev,
				const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}

static int
mwl_vendor_cmd_get_wmmackpolicy(struct wiphy *wiphy,
				struct wireless_dev *wdev,
				const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}

static int
mwl_vendor_cmd_set_txantenna2(struct wiphy *wiphy,
			      struct wireless_dev *wdev,
			      const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}

static int
mwl_vendor_cmd_get_txantenna2(struct wiphy *wiphy,
			      struct wireless_dev *wdev,
			      const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}

static int
mwl_vendor_cmd_get_deviceinfo(struct wiphy *wiphy,
			      struct wireless_dev *wdev,
			      const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}

#ifdef INTEROP
static int
mwl_vendor_cmd_set_interop(struct wiphy *wiphy,
			   struct wireless_dev *wdev,
			   const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}

static int
mwl_vendor_cmd_get_interop(struct wiphy *wiphy,
			   struct wireless_dev *wdev,
			   const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}
#endif

static int
mwl_vendor_cmd_set_11hetsicac(struct wiphy *wiphy,
			      struct wireless_dev *wdev,
			      const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}

static int
mwl_vendor_cmd_get_11hetsicac(struct wiphy *wiphy,
			      struct wireless_dev *wdev,
			      const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}

static int
mwl_vendor_cmd_set_rxintlimit(struct wiphy *wiphy,
			      struct wireless_dev *wdev,
			      const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}

static int
mwl_vendor_cmd_get_rxintlimit(struct wiphy *wiphy,
			      struct wireless_dev *wdev,
			      const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}

#if defined ( INTOLERANT40) ||defined (COEXIST_20_40_SUPPORT)
static int
mwl_vendor_cmd_set_intoler(struct wiphy *wiphy,
			   struct wireless_dev *wdev,
			   const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}

static int
mwl_vendor_cmd_get_intoler(struct wiphy *wiphy,
			   struct wireless_dev *wdev,
			   const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}
#endif

#ifdef RXPATHOPT
static int
mwl_vendor_cmd_set_rxpathopt(struct wiphy *wiphy,
			     struct wireless_dev *wdev,
			     const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}

static int
mwl_vendor_cmd_get_rxpathopt(struct wiphy *wiphy,
			     struct wireless_dev *wdev,
			     const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}
#endif

static int
mwl_vendor_cmd_set_amsduft(struct wiphy *wiphy,
			   struct wireless_dev *wdev,
			   const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}

static int
mwl_vendor_cmd_get_amsduft(struct wiphy *wiphy,
			   struct wireless_dev *wdev,
			   const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}

static int
mwl_vendor_cmd_set_amsdums(struct wiphy *wiphy,
			   struct wireless_dev *wdev,
			   const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}

static int
mwl_vendor_cmd_get_amsdums(struct wiphy *wiphy,
			   struct wireless_dev *wdev,
			   const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}

static int
mwl_vendor_cmd_set_amsduas(struct wiphy *wiphy,
			   struct wireless_dev *wdev,
			   const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}

static int
mwl_vendor_cmd_get_amsduas(struct wiphy *wiphy,
			   struct wireless_dev *wdev,
			   const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}

static int
mwl_vendor_cmd_set_amsdupc(struct wiphy *wiphy,
			   struct wireless_dev *wdev,
			   const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}

static int
mwl_vendor_cmd_get_amsdupc(struct wiphy *wiphy,
			   struct wireless_dev *wdev,
			   const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}

static int
mwl_vendor_cmd_set_cdd(struct wiphy *wiphy,
		       struct wireless_dev *wdev,
		       const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}

static int
mwl_vendor_cmd_get_cdd(struct wiphy *wiphy,
		       struct wireless_dev *wdev,
		       const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}

static int
mwl_vendor_cmd_set_acsthrd(struct wiphy *wiphy,
			   struct wireless_dev *wdev,
			   const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}

static int
mwl_vendor_cmd_get_acsthrd(struct wiphy *wiphy,
			   struct wireless_dev *wdev,
			   const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}

static int
mwl_vendor_cmd_get_deviceid(struct wiphy *wiphy,
			    struct wireless_dev *wdev,
			    const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}

#ifdef IEEE80211K
static int
mwl_vendor_cmd_set_rrm(struct wiphy *wiphy,
		       struct wireless_dev *wdev,
		       const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
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

#ifdef CLIENT_SUPPORT
static int
mwl_vendor_cmd_set_autoscan(struct wiphy *wiphy,
			    struct wireless_dev *wdev,
			    const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}

static int
mwl_vendor_cmd_get_autoscan(struct wiphy *wiphy,
			    struct wireless_dev *wdev,
			    const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}
#endif

#ifdef DOT11V_DMS
static int
mwl_vendor_cmd_set_dms(struct wiphy *wiphy,
		       struct wireless_dev *wdev,
		       const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}

static int
mwl_vendor_cmd_get_dms(struct wiphy *wiphy,
		       struct wireless_dev *wdev,
		       const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}
#endif

static int
mwl_vendor_cmd_get_sysload(struct wiphy *wiphy,
			   struct wireless_dev *wdev,
			   const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}

#ifdef MRVL_DFS
static int
mwl_vendor_cmd_get_11hnoclist(struct wiphy *wiphy,
			      struct wireless_dev *wdev,
			      const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}
#endif

#if defined(CLIENT_SUPPORT) && defined (MRVL_WSC)
static int
mwl_vendor_cmd_get_bssprofile(struct wiphy *wiphy,
			      struct wireless_dev *wdev,
			      const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}
#endif

static int
mwl_vendor_cmd_get_tlv(struct wiphy *wiphy,
		       struct wireless_dev *wdev,
		       const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}

static int
mwl_vendor_cmd_get_chnls(struct wiphy *wiphy,
			 struct wireless_dev *wdev,
			 const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}

static int
mwl_vendor_cmd_set_scanchnls(struct wiphy *wiphy,
			     struct wireless_dev *wdev,
			     const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}

#ifdef WTP_SUPPORT
static int
mwl_vendor_cmd_set_wtp(struct wiphy *wiphy,
		       struct wireless_dev *wdev,
		       const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}

static int
mwl_vendor_cmd_set_wtpmacmode(struct wiphy *wiphy,
			      struct wireless_dev *wdev,
			      const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}

static int
mwl_vendor_cmd_set_wtptunnelmode(struct wiphy *wiphy,
				 struct wireless_dev *wdev,
				 const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}

static int
mwl_vendor_cmd_get_wtpcfg(struct wiphy *wiphy,
			  struct wireless_dev *wdev,
			  const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}

static int
mwl_vendor_cmd_get_radiostat(struct wiphy *wiphy,
			     struct wireless_dev *wdev,
			     const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}
#endif

#ifdef MFG_SUPPORT
static int
mwl_vendor_cmd_set_extfw(struct wiphy *wiphy,
			 struct wireless_dev *wdev,
			 const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}

static int
mwl_vendor_cmd_set_mfgfw(struct wiphy *wiphy,
			 struct wireless_dev *wdev,
			 const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}

static int
mwl_vendor_cmd_set_mfg(struct wiphy *wiphy,
		       struct wireless_dev *wdev,
		       const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}

static int
mwl_vendor_cmd_set_fwrev(struct wiphy *wiphy,
			 struct wireless_dev *wdev,
			 const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}
#endif

#ifdef AMPDU_SUPPORT
static int
mwl_vendor_cmd_set_addba(struct wiphy *wiphy,
			 struct wireless_dev *wdev,
			 const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}

static int
mwl_vendor_cmd_get_ampdustat(struct wiphy *wiphy,
			     struct wireless_dev *wdev,
			     const void *data, int data_len)
{
	struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	if (!data)
		return -EINVAL;

	return mwl_drv_get_ampdustat(priv->netDev);
}

static int
mwl_vendor_cmd_set_delba(struct wiphy *wiphy,
			 struct wireless_dev *wdev,
			 const void *data, int data_len)
{
	struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	uint8_t mac[6];
	uint8_t tid;

	if (!data)
		return -EINVAL;

	memcpy(mac, (uint8_t *) data, 6);
	tid = *(uint8_t *) (data + 6);

	return mwl_drv_set_delba(priv->netDev, mac, tid);
}

static int
mwl_vendor_cmd_set_del2ba(struct wiphy *wiphy,
			  struct wireless_dev *wdev,
			  const void *data, int data_len)
{
	struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	uint8_t mac[6];
	uint8_t tid;

	if (!data)
		return -EINVAL;

	memcpy(mac, (uint8_t *) data, 6);
	tid = *(uint8_t *) (data + 6);

	return mwl_drv_set_del2ba(priv->netDev, mac, tid);
}

static int
mwl_vendor_cmd_set_ampdurxdisable(struct wiphy *wiphy,
				  struct wireless_dev *wdev,
				  const void *data, int data_len)
{
	struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);
	uint8_t value;

	if (!data)
		return -EINVAL;

	value = *(uint8_t *) data;

	return mwl_drv_set_ampdurxdisable(priv->netDev, value);
}

static int
mwl_vendor_cmd_set_triggerscaninterval(struct wiphy *wiphy,
				       struct wireless_dev *wdev,
				       const void *data, int data_len)
{
	struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);
	uint16_t value;

	if (!data)
		return -EINVAL;

	value = *(uint16_t *) data;

	return mwl_drv_set_triggerscaninterval(priv->netDev, value);
}

#ifdef EXPLICIT_BF
static int
mwl_vendor_cmd_set_bf(struct wiphy *wiphy,
		      struct wireless_dev *wdev, const void *data, int data_len)
{
	struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	uint8_t p[7];

	if (!data)
		return -EINVAL;

	memcpy(p, (uint8_t *) data, 7);

	return mwl_drv_set_bf(priv->netDev, p);
}

static int
mwl_vendor_cmd_get_mumimomgmt(struct wiphy *wiphy,
			      struct wireless_dev *wdev,
			      const void *data, int data_len)
{
	if (!data)
		return -EINVAL;

	return mwl_drv_get_mumimomgmt(wdev->netdev);
}

static int
mwl_vendor_cmd_set_mumimomgmt(struct wiphy *wiphy,
			      struct wireless_dev *wdev,
			      const void *data, int data_len)
{
	uint32_t value;

	if (!data)
		return -EINVAL;

	value = *(uint32_t *) data;

	return mwl_drv_set_mumimomgmt(wdev->netdev, value);
}

static int
mwl_vendor_cmd_get_musta(struct wiphy *wiphy,
			 struct wireless_dev *wdev,
			 const void *data, int data_len)
{
	if (!data)
		return -EINVAL;

	return mwl_drv_get_musta(wdev->netdev);
}

static int
mwl_vendor_cmd_get_muset(struct wiphy *wiphy,
			 struct wireless_dev *wdev,
			 const void *data, int data_len)
{
	uint8_t value;

	if (!data)
		return -EINVAL;

	value = *(uint8_t *) data;

	return mwl_drv_get_muset(wdev->netdev, value);
}

static int
mwl_vendor_cmd_set_muset(struct wiphy *wiphy,
			 struct wireless_dev *wdev,
			 const void *data, int data_len)
{
	uint16_t *buf;
	uint16_t Stnid[3];

	if (!data)
		return -EINVAL;

	buf = (uint16_t *) data;
	Stnid[0] = buf[0];
	Stnid[1] = buf[1];
	Stnid[2] = buf[2];

	if (!data)
		return -EINVAL;

	return mwl_drv_set_muset(wdev->netdev, Stnid);
}

static int
mwl_vendor_cmd_del_muset(struct wiphy *wiphy,
			 struct wireless_dev *wdev,
			 const void *data, int data_len)
{
	uint8_t value;

	if (!data)
		return -EINVAL;

	value = *(uint8_t *) data;

	return mwl_drv_del_muset(wdev->netdev, value);
}

#ifdef MRVL_MUG_ENABLE
static int
mwl_vendor_cmd_set_mug_enable(struct wiphy *wiphy,
			      struct wireless_dev *wdev,
			      const void *data, int data_len)
{
	uint32_t value;

	if (!data)
		return -EINVAL;

	value = *(uint32_t *) data;

	return mwl_drv_set_mug_enable(wdev->netdev, value);
}

static int
mwl_vendor_cmd_get_muinfo(struct wiphy *wiphy,
			  struct wireless_dev *wdev,
			  const void *data, int data_len)
{
	uint8_t value;

	if (!data)
		return -EINVAL;

	value = *(uint8_t *) data;

	return mwl_drv_get_muinfo(wdev->netdev, value);
}

static int
mwl_vendor_cmd_get_mugroups(struct wiphy *wiphy,
			    struct wireless_dev *wdev,
			    const void *data, int data_len)
{
	uint8_t value;

	if (!data)
		return -EINVAL;

	value = *(uint8_t *) data;

	return mwl_drv_get_mugroups(wdev->netdev, value);
}

static int
mwl_vendor_cmd_set_muconfig(struct wiphy *wiphy,
			    struct wireless_dev *wdev,
			    const void *data, int data_len)
{
	uint32_t corr_thr_decimal;
	uint16_t sta_cep_age_thr;
	uint16_t period_ms;

	if (!data)
		return -EINVAL;

	corr_thr_decimal = *(uint32_t *) data;
	sta_cep_age_thr = *(uint16_t *) (data + 4);
	period_ms = *(uint16_t *) (data + 8);

	return mwl_drv_set_muconfig(wdev->netdev, corr_thr_decimal,
				    sta_cep_age_thr, period_ms);
}
#endif

static int
mwl_vendor_cmd_set_muautotimer(struct wiphy *wiphy,
			       struct wireless_dev *wdev,
			       const void *data, int data_len)
{
	uint8_t set;
	uint32_t value;
	uint32_t *pData = ((uint32_t *) data);

	if (!data)
		return -EINVAL;

	set = pData[0];
	value = pData[1];

	return mwl_drv_set_muautotimer(wdev->netdev, set, value);
}

static int
mwl_vendor_cmd_set_mupreferusrcnt(struct wiphy *wiphy,
				  struct wireless_dev *wdev,
				  const void *data, int data_len)
{
	uint8_t value;

	if (!data)
		return -EINVAL;

	value = *(uint8_t *) data;

	return mwl_drv_set_mupreferusrcnt(wdev->netdev, value);
}

static int
mwl_vendor_cmd_set_gid(struct wiphy *wiphy,
		       struct wireless_dev *wdev,
		       const void *data, int data_len)
{
	struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	uint8_t p[6];

	if (!data)
		return -EINVAL;

	memcpy(p, (uint8_t *) data, 6);

	return mwl_drv_set_gid(priv->netDev, p);
}

static int
mwl_vendor_cmd_set_noack(struct wiphy *wiphy,
			 struct wireless_dev *wdev,
			 const void *data, int data_len)
{
	struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);
	uint8_t value;

	if (!data)
		return -EINVAL;

	value = *(uint8_t *) data;

	return mwl_drv_set_noack(priv->netDev, value);
}

static int
mwl_vendor_cmd_set_nosteer(struct wiphy *wiphy,
			   struct wireless_dev *wdev,
			   const void *data, int data_len)
{
	struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);
	uint8_t value;

	if (!data)
		return -EINVAL;

	value = *(uint8_t *) data;

	return mwl_drv_set_nosteer(priv->netDev, value);
}

static int
mwl_vendor_cmd_set_txhop(struct wiphy *wiphy,
			 struct wireless_dev *wdev,
			 const void *data, int data_len)
{
	struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);
	uint8_t enable, txhopstatus;

	if (!data)
		return -EINVAL;

	enable = *(uint8_t *) data;
	txhopstatus = *(uint8_t *) (data + 1);

	return mwl_drv_set_txhop(priv->netDev, enable, txhopstatus);
}

static int
mwl_vendor_cmd_get_bftype(struct wiphy *wiphy,
			  struct wireless_dev *wdev,
			  const void *data, int data_len)
{
	struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	if (!data)
		return -EINVAL;

	return mwl_drv_get_bftype(priv->netDev);
}

static int
mwl_vendor_cmd_get_bwsignaltype(struct wiphy *wiphy,
				struct wireless_dev *wdev,
				const void *data, int data_len)
{
	struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	if (!data)
		return -EINVAL;

	return mwl_drv_get_bwsignaltype(priv->netDev);
}

static int
mwl_vendor_cmd_set_bwsignaltype(struct wiphy *wiphy,
				struct wireless_dev *wdev,
				const void *data, int data_len)
{
	struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);
	uint8_t type, bitmap;

	if (!data)
		return -EINVAL;

	type = *(uint8_t *) data;
	bitmap = *(uint8_t *) (data + 1);

	return mwl_drv_set_bwsignaltype(priv->netDev, type, bitmap);
}
#endif

static int
mwl_vendor_cmd_get_weakiv_threshold(struct wiphy *wiphy,
				    struct wireless_dev *wdev,
				    const void *data, int data_len)
{
	struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	if (!data)
		return -EINVAL;

	return mwl_drv_get_weakiv_threshold(priv->netDev);
}

static int
mwl_vendor_cmd_set_weakiv_threshold(struct wiphy *wiphy,
				    struct wireless_dev *wdev,
				    const void *data, int data_len)
{
	struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);
	uint32_t value;

	if (!data)
		return -EINVAL;

	value = *(uint32_t *) data;

	return mwl_drv_set_weakiv_threshold(priv->netDev, value);
}

#ifdef POWERSAVE_OFFLOAD
static int
mwl_vendor_cmd_set_tim(struct wiphy *wiphy,
		       struct wireless_dev *wdev,
		       const void *data, int data_len)
{
	struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);
	uint16_t aid;
	uint32_t set;
	uint32_t *pData = ((uint32_t *) data);

	if (!data)
		return -EINVAL;

	aid = pData[0];
	set = pData[1];

	return mwl_drv_set_tim(priv->netDev, aid, set);
}

static int
mwl_vendor_cmd_set_powersavestation(struct wiphy *wiphy,
				    struct wireless_dev *wdev,
				    const void *data, int data_len)
{
	struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);
	uint8_t noofstations;

	if (!data)
		return -EINVAL;

	noofstations = *(uint8_t *) data;

	return mwl_drv_set_powersavestation(priv->netDev, noofstations);
}

static int
mwl_vendor_cmd_get_tim(struct wiphy *wiphy,
		       struct wireless_dev *wdev,
		       const void *data, int data_len)
{
	struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	if (!data)
		return -EINVAL;

	return mwl_drv_get_tim(priv->netDev);
}
#endif
#endif

static int
mwl_vendor_cmd_get_bcn(struct wiphy *wiphy,
		       struct wireless_dev *wdev,
		       const void *data, int data_len)
{
	struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	if (!data)
		return -EINVAL;

	return mwl_drv_get_bcn(priv->netDev);
}

static int
mwl_vendor_cmd_set_annex(struct wiphy *wiphy,
			 struct wireless_dev *wdev,
			 const void *data, int data_len)
{
	struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);
	uint32_t annex, index;

	if (!data)
		return -EINVAL;

	annex = *(uint32_t *) data;
	index = *(uint32_t *) (data + 4);

	return mwl_drv_set_annex(priv->netDev, annex, index);
}

static int
mwl_vendor_cmd_set_readeepromhdr(struct wiphy *wiphy,
				 struct wireless_dev *wdev,
				 const void *data, int data_len)
{
	struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);
	uint32_t annex, index;

	if (!data)
		return -EINVAL;

	annex = *(uint32_t *) data;
	index = *(uint32_t *) (data + 4);

	return mwl_drv_set_readeepromhdr(priv->netDev, annex, index);
}

#if defined (SOC_W8366) || defined (SOC_W8364) || defined (SOC_W8764)
static int
mwl_vendor_cmd_get_or(struct wiphy *wiphy,
		      struct wireless_dev *wdev, const void *data, int data_len)
{
	struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	if (!data)
		return -EINVAL;

	return mwl_drv_get_or(priv->netDev);
}
#endif

static int
mwl_vendor_cmd_get_addrtable(struct wiphy *wiphy,
			     struct wireless_dev *wdev,
			     const void *data, int data_len)
{
	struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	if (!data)
		return -EINVAL;

	return mwl_drv_get_addrtable(priv->netDev);
}

static int
mwl_vendor_cmd_get_fwencrinfo(struct wiphy *wiphy,
			      struct wireless_dev *wdev,
			      const void *data, int data_len)
{
	struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	if (!data || data_len != 6)
		return -EINVAL;

	return mwl_drv_get_fwencrinfo(priv->netDev, (uint8_t *) data);

}

static int
mwl_vendor_cmd_set_reg(struct wiphy *wiphy,
		       struct wireless_dev *wdev,
		       const void *data, int data_len)
{
	struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);
	uint32_t regtype, reg, value;
	uint32_t *buf;

	if (!data)
		return -EINVAL;

	buf = (uint32_t *) data;
	regtype = buf[0];
	reg = buf[1];
	value = buf[2];

	return mwl_drv_set_reg(priv->netDev, regtype, reg, value);
}

static int
mwl_vendor_cmd_set_debug(struct wiphy *wiphy,
			 struct wireless_dev *wdev,
			 const void *data, int data_len)
{
	struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	if (!data)
		return -EINVAL;

	return mwl_drv_set_debug(priv->netDev, (uint32_t *) data, data_len);

}

static int
mwl_vendor_cmd_get_memdump(struct wiphy *wiphy,
			   struct wireless_dev *wdev,
			   const void *data, int data_len)
{
	struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	if (!data)
		return -EINVAL;

	return mwl_drv_get_memdump(priv->netDev, (uint32_t *) data);

}

static int
mwl_vendor_cmd_set_desire_bssid(struct wiphy *wiphy,
				struct wireless_dev *wdev,
				const void *data, int data_len)
{
	uint8_t desireBSSID[6];

	if (!data || data_len > 6)
		return -EINVAL;

	memcpy(desireBSSID, (uint8_t *) data, 6);

	return mwl_drv_set_desire_bssid(wdev->netdev, desireBSSID);

}

static int
mwl_vendor_cmd_get_ewbtable(struct wiphy *wiphy,
			    struct wireless_dev *wdev,
			    const void *data, int data_len)
{
	if (!data)
		return -EINVAL;

	return mwl_drv_get_ewbtable();

}

static int
mwl_vendor_cmd_set_ratetable(struct wiphy *wiphy,
			     struct wireless_dev *wdev,
			     const void *data, int data_len)
{
	uint8_t clear;
	uint8_t macaddr[6];
	uint32_t rateinfo;

	if (!data)
		return -EINVAL;

	clear = *(uint8_t *) data;
	memcpy(macaddr, (uint8_t *) (data + 1), 6);
	rateinfo = *(uint32_t *) (data + 7);

	return mwl_drv_set_ratetable(wdev->netdev, clear, macaddr, rateinfo);
}

static int
mwl_vendor_cmd_get_ratetable(struct wiphy *wiphy,
			     struct wireless_dev *wdev,
			     const void *data, int data_len)
{
	uint8_t mu;
	uint8_t macaddr[6];

	if (!data)
		return -EINVAL;

	mu = *(uint8_t *) (data);
	memcpy(macaddr, (uint8_t *) (data + 1), 6);

	return mwl_drv_get_ratetable(wdev->netdev, mu, macaddr);
}

static int
mwl_vendor_cmd_set_ampdu_bamgmt(struct wiphy *wiphy,
				struct wireless_dev *wdev,
				const void *data, int data_len)
{
	uint32_t val;

	if (!data)
		return -EINVAL;

	val = *(uint32_t *) data;

	return mwl_drv_set_ampdu_bamgmt(wdev->netdev, val);
}

static int
mwl_vendor_cmd_get_ampdu_bamgmt(struct wiphy *wiphy,
				struct wireless_dev *wdev,
				const void *data, int data_len)
{
	if (!data)
		return -EINVAL;

	return mwl_drv_get_ampdu_bamgmt(wdev->netdev);
}

static int
mwl_vendor_cmd_set_ampdu_mintraffic(struct wiphy *wiphy,
				    struct wireless_dev *wdev,
				    const void *data, int data_len)
{
	uint32_t bk, be, vi, vo;

	if (!data)
		return -EINVAL;

	bk = ((uint32_t *) data)[0];
	be = ((uint32_t *) data)[1];
	vi = ((uint32_t *) data)[2];
	vo = ((uint32_t *) data)[3];

	return mwl_drv_set_ampdu_mintraffic(wdev->netdev, bk, be, vi, vo);
}

static int
mwl_vendor_cmd_get_ampdu_mintraffic(struct wiphy *wiphy,
				    struct wireless_dev *wdev,
				    const void *data, int data_len)
{
	if (!data)
		return -EINVAL;

	return mwl_drv_get_ampdu_mintraffic(wdev->netdev);
}

static int
mwl_vendor_cmd_set_ampdu_ac_threshold(struct wiphy *wiphy,
				      struct wireless_dev *wdev,
				      const void *data, int data_len)
{
	uint32_t bk, be, vi, vo;

	if (!data)
		return -EINVAL;

	bk = ((uint32_t *) data)[0];
	be = ((uint32_t *) data)[1];
	vi = ((uint32_t *) data)[2];
	vo = ((uint32_t *) data)[3];

	return mwl_drv_set_ac_threshold(wdev->netdev, bk, be, vi, vo);
}

static int
mwl_vendor_cmd_get_ampdu_ac_threshold(struct wiphy *wiphy,
				      struct wireless_dev *wdev,
				      const void *data, int data_len)
{
	if (!data)
		return -EINVAL;

	return mwl_drv_get_ac_threshold(wdev->netdev);
}

static int
mwl_vendor_cmd_set_dfstest(struct wiphy *wiphy,
			   struct wireless_dev *wdev,
			   const void *data, int data_len)
{
	uint8_t testmode;

	if (!data)
		return -EINVAL;

	testmode = *(uint8_t *) data;

	return mwl_drv_set_dfstest(testmode);
}

static int
mwl_vendor_cmd_set_ipmcgrp(struct wiphy *wiphy,
			   struct wireless_dev *wdev,
			   const void *data, int data_len)
{
	uint8_t setmode;
	uint8_t ipaddr[16];
	uint8_t macaddr[13];

	if (!data)
		return -EINVAL;

	setmode = *(uint8_t *) data;

	if (setmode == MWL_SET_IPMCGRP_ADD || setmode == MWL_SET_IPMCGRP_DEL) {
		memcpy(ipaddr, &(((uint8_t *) data)[1]), 16);
		memcpy(macaddr, &(((uint8_t *) data)[17]), 13);
	} else if (setmode == MWL_SET_IPMCGRP_DELGRP ||
		   setmode == MWL_SET_IPMCGRP_DELGRP ||
		   setmode == MWL_SET_IPMCGRP_ADDIPMFILTER ||
		   setmode == MWL_SET_IPMCGRP_DELIPMFILTER ||
		   setmode == MWL_SET_IPMCGRP_GETGRP) {
		memcpy(ipaddr, &(((uint8_t *) data)[1]), 16);
		memset(macaddr, 0, 13);
	} else if (setmode == MWL_SET_IPMCGRP_GETALLGRPS ||
		   setmode == MWL_SET_IPMCGRP_GETIPMFILTER) {
		memset(ipaddr, 0, 16);
		memset(macaddr, 0, 13);
	} else
		return -EINVAL;

	return mwl_drv_set_ipmcgrp(wdev->netdev, setmode, ipaddr, macaddr);
}

static int
mwl_vendor_cmd_set_rptrmode(struct wiphy *wiphy,
			    struct wireless_dev *wdev,
			    const void *data, int data_len)
{
	uint8_t mode;
	uint8_t devicetype[32];
	uint8_t agingtime[6];
	uint8_t macaddr[13];

	if (!data)
		return -EINVAL;

	mode = *(uint8_t *) data;
	memset(devicetype, 0, 32);
	memset(macaddr, 0, 13);
	memset(agingtime, 0, 6);

	switch (mode) {
	case MWL_SET_RPTRMODE_NONE:
		break;
	case MWL_SET_RPTRMODE_ZERO:
		break;
	case MWL_SET_RPTRMODE_ONE:
		break;
	case MWL_SET_RPTRMODE_DEVICETYPE:
		if (data_len > 1)
			memcpy(devicetype, &((uint8_t *) data)[1],
			       data_len - 1);
		else
			return -EINVAL;
		break;
	case MWL_SET_IPMCGRP_AGINGTIME:
		memcpy(agingtime, &((uint8_t *) data)[1], data_len - 1);
		break;
	case MWL_SET_IPMCGRP_LISTMAC:
		break;
	case MWL_SET_IPMCGRP_ADDMAC:
		memcpy(macaddr, &((uint8_t *) data)[1], 13);
		break;
	case MWL_SET_IPMCGRP_DELMAC:
		memcpy(macaddr, &((uint8_t *) data)[1], 13);
		break;
	default:
		return -EINVAL;
	}

	return mwl_drv_set_rptrmode(wdev->netdev, mode, devicetype, agingtime,
				    macaddr);
}

static int
mwl_vendor_cmd_set_load_txpowertable(struct wiphy *wiphy,
				     struct wireless_dev *wdev,
				     const void *data, int data_len)
{
	uint8_t filename[100];

	if (!data)
		return -EINVAL;

	memcpy(filename, (uint8_t *) data, data_len);

	return mwl_drv_set_load_txpowertable(wdev->netdev, filename);
}

static int
mwl_vendor_cmd_get_txpowertable(struct wiphy *wiphy,
				struct wireless_dev *wdev,
				const void *data, int data_len)
{
	if (!data)
		return -EINVAL;

	return mwl_drv_get_txpowertable(wdev->netdev);

}

static int
mwl_vendor_cmd_set_linklost(struct wiphy *wiphy,
			    struct wireless_dev *wdev,
			    const void *data, int data_len)
{
	uint32_t macIndex;
	uint32_t numOfInterval;

	if (!data)
		return -EINVAL;

	macIndex = *(uint32_t *) data;
	if (macIndex > 1)
		return -EINVAL;

	numOfInterval = *(uint32_t *) (data + sizeof(macIndex));

	return mwl_drv_set_linklost(macIndex, numOfInterval);
}

#ifdef SSU_SUPPORT
static int
mwl_vendor_cmd_set_ssutest(struct wiphy *wiphy,
			   struct wireless_dev *wdev,
			   const void *data, int data_len)
{
	struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	if (!data)
		return -EINVAL;

	return mwl_drv_set_ssutest(priv, (uint32_t *) data);
}
#endif

static int
mwl_vendor_cmd_get_qstats(struct wiphy *wiphy,
			  struct wireless_dev *wdev,
			  const void *data, int data_len)
{
	uint8_t type = 0;
	uint32_t pktcount = 0;
	uint32_t staid = 0, enable = 0, staid1 = 0, staid2 = 0, staid3 =
		0, staid4 = 0, sumu = 0;
	uint8_t macaddr[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	if (!data)
		return -EINVAL;

	type = *(uint8_t *) data;
	switch (type) {
	case MWL_GET_QSTATS_PKTCOUNT:
		pktcount = *(uint32_t *) (data + 1);
		break;
	case MWL_GET_QSTATS_RETRY_HISTOGRAM:
		break;
	case MWL_GET_QSTATS_TXBA_HISTOGRAM:
		staid = *(uint32_t *) (data + 1);
		if (staid == 1) {
			enable = *(uint32_t *) (data + 5);
			staid1 = *(uint32_t *) (data + 9);
			staid2 = *(uint32_t *) (data + 13);
			staid3 = *(uint32_t *) (data + 17);
			sumu = *(uint32_t *) (data + 21);
		} else {
			staid4 = *(uint32_t *) (data + 5);
		}
		break;
	case MWL_GET_QSTATS_TXRATE_HISTOGRAM:
		staid = *(uint32_t *) (data + 1);
		if (staid == 1) {
			staid1 = *(uint32_t *) (data + 5);
		}
		break;
	case MWL_GET_QSTATS_RXRATE_HISTOGRAM:
		break;
	case MWL_GET_QSTATS_ADDRXMAC:
		memcpy(macaddr, (uint8_t *) (data + 1), 6);
		break;
	case MWL_GET_QSTATS_ADDTXMAC:
		memcpy(macaddr, (uint8_t *) (data + 1), 6);
		break;
	case MWL_GET_QSTATS_TXLATENCY:
		break;
	case MWL_GET_QSTATS_RXLATENCY:
		break;
	case MWL_GET_QSTATS_RESET:
		break;
	default:
		return -EINVAL;
	}

	return mwl_drv_get_qstats(wdev->netdev, type, pktcount, staid, enable,
				  staid1, staid2, staid3, sumu, staid4,
				  macaddr);
}

static int
mwl_vendor_cmd_set_rccal(struct wiphy *wiphy,
			 struct wireless_dev *wdev,
			 const void *data, int data_len)
{
	if (!data)
		return -EINVAL;

	return mwl_drv_set_rccal(wdev->netdev);

}

static int
mwl_vendor_cmd_get_temp(struct wiphy *wiphy,
			struct wireless_dev *wdev,
			const void *data, int data_len)
{
	if (!data)
		return -EINVAL;

	return mwl_drv_get_temp(wdev->netdev);
}

static int
mwl_vendor_cmd_set_maxsta(struct wiphy *wiphy,
			  struct wireless_dev *wdev,
			  const void *data, int data_len)
{
	uint32_t maxsta;

	if (!data)
		return -EINVAL;

	maxsta = *(uint32_t *) data;

	return mwl_drv_set_maxsta(wdev->netdev, maxsta);
}

static int
mwl_vendor_cmd_get_maxsta(struct wiphy *wiphy,
			  struct wireless_dev *wdev,
			  const void *data, int data_len)
{
	if (!data)
		return -EINVAL;

	return mwl_drv_get_maxsta(wdev->netdev);
}

static int
mwl_vendor_cmd_set_txfaillimit(struct wiphy *wiphy,
			       struct wireless_dev *wdev,
			       const void *data, int data_len)
{
	uint32_t txfaillimit;

	if (!data)
		return -EINVAL;

	txfaillimit = *(uint32_t *) data;

	return mwl_drv_set_txfaillimit(wdev->netdev, txfaillimit);
}

static int
mwl_vendor_cmd_get_txfaillimit(struct wiphy *wiphy,
			       struct wireless_dev *wdev,
			       const void *data, int data_len)
{
	if (!data)
		return -EINVAL;

	return mwl_drv_get_txfaillimit(wdev->netdev);
}

#ifdef MRVL_WAPI
static int
mwl_vendor_cmd_set_wapi(struct wiphy *wiphy,
			struct wireless_dev *wdev,
			const void *data, int data_len)
{
	uint8_t broadcast;
	uint8_t macaddr[6];

	if (!data)
		return -EINVAL;

	broadcast = *(uint8_t *) data;
	memset(macaddr, 0, 6);
	memcpy(macaddr, (uint8_t *) (data + 1), 6);

	return mwl_drv_set_wapi(wdev->netdev, broadcast, macaddr);
}
#endif

static int
mwl_vendor_cmd_set_led(struct wiphy *wiphy,
		       struct wireless_dev *wdev,
		       const void *data, int data_len)
{
	uint32_t onoff;

	if (!data)
		return -EINVAL;

	onoff = *(uint32_t *) data;

	return mwl_drv_set_led(wdev->netdev, onoff);
}

static int
mwl_vendor_cmd_set_fastreconnect(struct wiphy *wiphy,
				 struct wireless_dev *wdev,
				 const void *data, int data_len)
{
	uint32_t probereqontx;

	if (!data)
		return -EINVAL;

	probereqontx = *(uint32_t *) data;

	return mwl_drv_set_fastreconnect(probereqontx);
}

static int
mwl_vendor_cmd_set_newdp(struct wiphy *wiphy,
			 struct wireless_dev *wdev,
			 const void *data, int data_len)
{
	uint32_t ch, width, rates, rate_type, rate_bw, rate_gi, rate_ss;

	if (!data || data_len != sizeof(uint32_t) * 7)
		return -EINVAL;

	ch = ((uint32_t *) data)[0];
	width = ((uint32_t *) data)[1];
	rate_type = ((uint32_t *) data)[2];
	rates = ((uint32_t *) data)[3];
	rate_bw = ((uint32_t *) data)[4];
	rate_gi = ((uint32_t *) data)[5];
	rate_ss = ((uint32_t *) data)[6];

	return mwl_drv_set_newdp(wdev->netdev, ch, width, rates, rate_type,
				 rate_bw, rate_gi, rate_ss);
}

static int
mwl_vendor_cmd_set_txratectrl(struct wiphy *wiphy,
			      struct wireless_dev *wdev,
			      const void *data, int data_len)
{
	uint32_t type, val, staid = 0;

	if (!data ||
	    (data_len != sizeof(uint32_t) * 2 &&
	     data_len != sizeof(uint32_t) * 3))
		return -EINVAL;

	type = ((uint32_t *) data)[0];
	val = ((uint32_t *) data)[1];
	if (type == 4)
		staid = ((uint32_t *) data)[2];

	return mwl_drv_set_txratectrl(wdev->netdev, type, val, staid);
}

static int
mwl_vendor_cmd_get_newdpcnt(struct wiphy *wiphy,
			    struct wireless_dev *wdev,
			    const void *data, int data_len)
{
	if (!data)
		return -EINVAL;

	return mwl_drv_get_newdpcnt(wdev->netdev);
}

static int
mwl_vendor_cmd_set_newdpacntsize(struct wiphy *wiphy,
				 struct wireless_dev *wdev,
				 const void *data, int data_len)
{
	if (!data)
		return -EINVAL;

	return mwl_drv_set_newdpacntsize(wdev->netdev);
}

static int
mwl_vendor_cmd_get_newdpacnt(struct wiphy *wiphy,
			     struct wireless_dev *wdev,
			     const void *data, int data_len)
{
	if (!data)
		return -EINVAL;

	return mwl_drv_get_newdpacnt(wdev->netdev);
}

static int
mwl_vendor_cmd_set_newDpOffCh(struct wiphy *wiphy,
			      struct wireless_dev *wdev,
			      const void *data, int data_len)
{
	DOT11_OFFCHAN_REQ_t offchan;
	uint32_t *pData = ((uint32_t *) data);

	if (!data || (data_len != sizeof(uint32_t) * 3))
		return -EINVAL;

	memset((UINT8 *) & offchan, 0x0, sizeof(DOT11_OFFCHAN_REQ_t));
	offchan.channel = pData[0];
	offchan.id = pData[1];
	offchan.dwell_time = pData[2];

	printk("Offchan ch:%d, id:%d, dwell:%d\n", offchan.channel, offchan.id,
	       offchan.dwell_time);

	return mwl_drv_set_newdpOffch(wdev->netdev, &offchan);
}

static int
mwl_vendor_cmd_set_txContinuous(struct wiphy *wiphy,
				struct wireless_dev *wdev,
				const void *data, int data_len)
{
	uint8_t mode = 0;
	uint32_t rateinfo = 0;
	uint32_t *pData = ((uint32_t *) data);

	if (!data || (data_len > sizeof(uint32_t) * 2))
		return -EINVAL;

	mode = pData[0];

	if (mode == 0) {
		printk("Tx continuous disabled\n");
	} else if (mode == 1) {
		rateinfo = pData[1];
		printk("Tx continuous pkt, rateinfo 0x%x\n", rateinfo);
	} else if (mode == 2) {
		printk("Tx continuous carrier wave mode\n");
	} else {
		printk("txcontinuous [0:disable|1:pkt|2:cw mode] [32bits rateinfo]\n");
	}

	if ((mode >= 0) && (mode < 3))
		return mwl_drv_set_txContinuous(wdev->netdev, mode, rateinfo);

	return -EINVAL;
}

static int
mwl_vendor_cmd_set_rxSop(struct wiphy *wiphy,
			 struct wireless_dev *wdev,
			 const void *data, int data_len)
{
	uint8_t params, threshold1 = 0, threshold2 = 0;
	uint32_t *pData = ((uint32_t *) data);

	if (!data || (data_len > sizeof(uint32_t) * 3))
		return -EINVAL;

	params = pData[0];
	threshold1 = pData[1];

	if (params == 1)
		printk("rxsop param %d, threshold 0x%x\n", params, threshold1);
	else {
		threshold2 = pData[2];
		printk("CCA rxsop param %d, threshold hi 0x%x, thereshold lo 0x%x\n", params, threshold1, threshold2);
	}

	return mwl_drv_set_rxSop(wdev->netdev, params, threshold1, threshold2);
}

static int
mwl_vendor_cmd_set_pwrPerRate(struct wiphy *wiphy,
			      struct wireless_dev *wdev,
			      const void *data, int data_len)
{
	struct file *filp = NULL;
	mm_segment_t oldfs;
	char *path;

	if (!data)
		return -EINVAL;

	path = (char *)data;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	filp = filp_open(path, O_RDONLY, 0);
	// if (filp != NULL) // Note: this one doesn't work and will cause crash

	mwl_drv_set_pwrPerRate(wdev->netdev, filp, path);

	set_fs(oldfs);

	return 0;
}

static int
mwl_vendor_cmd_set_rateGrps(struct wiphy *wiphy,
			    struct wireless_dev *wdev,
			    const void *data, int data_len)
{
	struct file *filp = NULL;
	mm_segment_t oldfs;
	char *path;

	if (!data)
		return -EINVAL;

	path = (char *)data;

	oldfs = get_fs();
	set_fs(KERNEL_DS);

	filp = filp_open(path, O_RDONLY, 0);
	// if (filp != NULL) // Note: this one doesn't work and will cause crash

	mwl_drv_set_rateGrps(wdev->netdev, filp, path);

	set_fs(oldfs);

	return 0;
}

static int
mwl_vendor_cmd_set_pwrGrpsTbl(struct wiphy *wiphy,
			      struct wireless_dev *wdev,
			      const void *data, int data_len)
{
	struct file *filp = NULL;
	mm_segment_t oldfs;
	char *path;

	if (!data)
		return -EINVAL;

	path = (char *)data;

	oldfs = get_fs();
	set_fs(KERNEL_DS);

	filp = filp_open(path, O_RDONLY, 0);
	// if (filp != NULL) // Note: this one doesn't work and will cause crash

	mwl_drv_set_pwrGrpsTbl(wdev->netdev, filp, path);

	set_fs(oldfs);

	return -ENOTSUPP;
}

static int
mwl_vendor_cmd_set_perRatePwr(struct wiphy *wiphy,
			      struct wireless_dev *wdev,
			      const void *data, int data_len)
{
	struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);
	Info_rate_power_table_t *pInfo;
	UINT8 i;
	uint32_t *pData = ((uint32_t *) data);

	if (!data || (data_len != sizeof(uint32_t) * (2 + pData[1])))
		return -EINVAL;

	pInfo = (Info_rate_power_table_t *) priv->wlpd_p->descData[0].
		pInfoPwrTbl;

	pInfo->RatePwrTbl.channel = pData[0];
	pInfo->RatePwrTbl.NumOfEntry = pData[1];

	if (pInfo->RatePwrTbl.NumOfEntry > 16) {
		printk("max entry is 16 \n");
		return -EFAULT;
	}

	printk("channel =%d, NumberOfEntry =%d \n", pInfo->RatePwrTbl.channel,
	       pInfo->RatePwrTbl.NumOfEntry);
	for (i = 0; i < pInfo->RatePwrTbl.NumOfEntry; i++) {
		/*RatePower from bit0 onwards, format:2, stbc:1, bf:1, bw:2, resvd:2, mcs:6, nss:2, power:8, active_tx:8 */
		pInfo->RatePwrTbl.RatePower[i] = pData[2 + i];
		printk("perratepwr = 0x%X \n", pInfo->RatePwrTbl.RatePower[i]);
	}
	if (pInfo->DrvCnt != pInfo->FwCnt) {
		printk("fw is not ready\n");
		return -EAGAIN;
	} else {
		if (pInfo->DrvCnt == 0xFFFFFFFF) {
			pInfo->DrvCnt = 0;
		} else {
			pInfo->DrvCnt += 1;
		}
	}

	return mwl_drv_set_perRatePwr(wdev->netdev);
}

static int
mwl_vendor_cmd_get_perRatePwr(struct wiphy *wiphy,
			      struct wireless_dev *wdev,
			      const void *data, int data_len)
{
	UINT32 RatePower;	//From bit0 onwards, format:2, stbc:1, bf:1, bw:2, resvd:2, mcs:6, nss:2, power:8, active_tx:8
	UINT8 trpcid;
	UINT16 dBm;
	UINT16 ant;
	uint32_t *pData = ((uint32_t *) data);
	int rc = 0;

	if (!data || (data_len != sizeof(uint32_t) * 1))
		return -EINVAL;

	RatePower = pData[0];	//Only need to supply first 16bits, no need for power and active_tx

	rc = mwl_drv_get_perRatePwr(wdev->netdev, RatePower, &trpcid, &dBm,
				    &ant);

	printk("TrpcId: %d, dBm:%d, ant_bitmap:0x%x \n", trpcid, (SINT16) dBm,
	       ant);

	return rc;
}

static int
mwl_vendor_cmd_get_nf(struct wiphy *wiphy,
		      struct wireless_dev *wdev, const void *data, int data_len)
{
	return mwl_drv_get_nf(wdev->netdev);
}

static int
mwl_vendor_cmd_get_radioStatus(struct wiphy *wiphy,
			       struct wireless_dev *wdev,
			       const void *data, int data_len)
{
	return mwl_drv_get_radioStatus(wdev->netdev);
}

static int
mwl_vendor_cmd_set_ldpc(struct wiphy *wiphy,
			struct wireless_dev *wdev,
			const void *data, int data_len)
{
	uint32_t *pData = ((uint32_t *) data);
	uint8_t enable = 0;

	if (!data || (data_len != sizeof(uint32_t) * 1))
		return -EINVAL;

	enable = pData[0];
	return mwl_drv_set_ldpc(wdev->netdev, enable);

}

static int
mwl_vendor_cmd_set_tlv(struct wiphy *wiphy,
		       struct wireless_dev *wdev,
		       const void *data, int data_len)
{
	UINT16 type = 0, len = 0;
	UINT8 tlvData[MAX_TLV_LEN], i;
	char buff[120];
	uint32_t *pData = ((uint32_t *) data);

	if (!data || (data_len != sizeof(uint32_t) * (2 + pData[1])))
		return -EINVAL;

	memset(tlvData, 0x00, MAX_TLV_LEN);
	type = pData[0];
	len = pData[1];

	for (i = 0; i < len; i++)
		tlvData[i] = pData[i + 2];
	printk("SET tlv type=%d len=%d\n", type, len);

	for (i = 0; i < len; i++) {
		if ((i != 0) && !(i % 16)) {
			printk("\n");
			printk("%02x ", tlvData[i]);
		} else
			printk("%02x ", tlvData[i]);
	}
	printk("\n");

	return mwl_drv_set_tlv(wdev->netdev, 1, type, len, tlvData, buff);
}

static int
mwl_vendor_cmd_set_ampduCfg(struct wiphy *wiphy,
			    struct wireless_dev *wdev,
			    const void *data, int data_len)
{
	uint32_t *pData = ((uint32_t *) data);
	uint8_t cfg = 0;

	if (!data || (data_len != sizeof(uint32_t) * 1))
		return -EINVAL;

	cfg = pData[0];
	return mwl_drv_set_ampduCfg(wdev->netdev, cfg);
}

static int
mwl_vendor_cmd_set_amsduCfg(struct wiphy *wiphy,
			    struct wireless_dev *wdev,
			    const void *data, int data_len)
{
	struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	//usage:amsducfg client_addr enable/disable_amsducfg bitmap_tid amsdu_size
	//enable/disable_amsducfg: 0:disable, 1:enable
	//bitmap_tid: 0~7
	//amsdu_size: 0=disable amsdu, 1=4k, 2=8k, 3=11k, 0xff = *(mib->mib_amsdutx)
	//ex: iwpriv wdev0 setcmd "amsducfg 42504321bc2f 0x1 0x81 0x1"
	//client_addr=42504321bc2f, enable amsducfg operation in fw, amsdu on tid 7 and 0, size=4k
	amsducfg_t amsducfg;
	uint8_t *pData = ((uint8_t *) data);

	printk("amsdu, len is %d \n", data_len);
	if (!data || (data_len != (IEEEtypes_ADDRESS_SIZE + 3)))
		return -EINVAL;

	memcpy(amsducfg.peeraddr, pData, IEEEtypes_ADDRESS_SIZE);
	amsducfg.amsduCfgEnable = pData[IEEEtypes_ADDRESS_SIZE];	//when disable, bitmap_tid and amsdu_size don't care
	amsducfg.priority_aggr = pData[IEEEtypes_ADDRESS_SIZE + 1];

	amsducfg.size = pData[IEEEtypes_ADDRESS_SIZE + 2];
	if (amsducfg.size == 0xff)
		amsducfg.size = *(mib->mib_amsdutx);
	printk("amsdu size = %d \n", amsducfg.size);
	return mwl_drv_set_amsduCfg(wdev->netdev, &amsducfg);
}

static int
mwl_vendor_cmd_set_bbDbg(struct wiphy *wiphy,
			 struct wireless_dev *wdev,
			 const void *data, int data_len)
{
	uint32_t clientId = 0;
	char *para;
	uint8_t hasClientId = 0;

	if (data) {
		hasClientId = 1;
		para = (char *)data;
		clientId = atohex2(para);
	}

	return mwl_drv_set_bbDbg(wdev->netdev, hasClientId, clientId);
}

static int
mwl_vendor_cmd_set_mu_sm_cache(struct wiphy *wiphy,
			       struct wireless_dev *wdev,
			       const void *data, int data_len)
{
	UINT32 client_id = 0;
	char *para;
	uint8_t hasClientId = 0;

	if (data) {
		hasClientId = 1;
		para = (char *)data;
		client_id = atohex2(para) & 0xFF;
	}
	return mwl_drv_set_mu_sm_cache(wdev->netdev, hasClientId, client_id);
}

static int
mwl_vendor_cmd_set_sku(struct wiphy *wiphy,
		       struct wireless_dev *wdev,
		       const void *data, int data_len)
{
	UINT32 sku;
	char *para;

	if (!data)
		return -EINVAL;

	para = (char *)data;
	sku = atohex2(para);

	return mwl_drv_set_sku(wdev->netdev, sku);
}

static int
mwl_vendor_cmd_set_rxAntBitmap(struct wiphy *wiphy,
			       struct wireless_dev *wdev,
			       const void *data, int data_len)
{
	UINT32 bitmap = 0;
	char *para;
	uint8_t hasBitmap = 0;

	if (data) {
		hasBitmap = 1;
		para = (char *)data;
		bitmap = atohex2(para);
	}

	return mwl_drv_set_rxAntBitmap(wdev->netdev, hasBitmap, bitmap);
}

static int
mwl_vendor_cmd_set_retryCfgEnable(struct wiphy *wiphy,
				  struct wireless_dev *wdev,
				  const void *data, int data_len)
{
	uint32_t *pData = ((uint32_t *) data);
	uint8_t enable = 0;

	if (!data || (data_len != sizeof(uint32_t) * 1))
		return -EINVAL;

	enable = pData[0];

	return mwl_drv_set_retryCfgEnable(wdev->netdev, enable);
}

static int
mwl_vendor_cmd_set_retryCfg(struct wiphy *wiphy,
			    struct wireless_dev *wdev,
			    const void *data, int data_len)
{
	char mode[7];
	uint8_t param[4] = { 0 };

	if (!data || (data_len > 11))
		return -EINVAL;

	memcpy(param, data, sizeof(param));
	strcpy(mode, data + 4);

	return mwl_drv_set_retryCfg(wdev->netdev, mode, param);
}

static int
mwl_vendor_cmd_set_radioRatesCfg(struct wiphy *wiphy,
				 struct wireless_dev *wdev,
				 const void *data, int data_len)
{
	char mode[4];
	uint8_t *param;

	if (!data || (data_len > 7))
		return -EINVAL;

	strcpy(mode, data);
	param = (uint8_t *) (data + 4);

	return mwl_drv_set_radioRatesCfg(wdev->netdev, mode, param);
}

static int
mwl_vendor_cmd_set_eewr(struct wiphy *wiphy,
			struct wireless_dev *wdev,
			const void *data, int data_len)
{
	char *path;
	UINT32 *pData, offset, NumberOfEntry = 0;

	if (!data)
		return -EINVAL;

	pData = (uint32_t *) data;

	offset = pData[0];
	NumberOfEntry = pData[1];

	path = ((char *)&pData[2]);

	return mwl_drv_set_eewr(wdev->netdev, offset, NumberOfEntry, path);
}

static int
mwl_vendor_cmd_get_eerd(struct wiphy *wiphy,
			struct wireless_dev *wdev,
			const void *data, int data_len)
{
	char *path;
	UINT32 *pData, offset, NumberOfEntry = 0;

	if (!data)
		return -EINVAL;

	pData = (uint32_t *) data;

	offset = pData[0];
	NumberOfEntry = pData[1];

	path = ((char *)&pData[2]);

	return mwl_drv_get_eerd(wdev->netdev, offset, NumberOfEntry, path);
}

static int
mwl_vendor_cmd_set_eepromAccess(struct wiphy *wiphy,
				struct wireless_dev *wdev,
				const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}

static int
mwl_vendor_cmd_set_offChPwr(struct wiphy *wiphy,
			    struct wireless_dev *wdev,
			    const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}

static int
mwl_vendor_cmd_set_wdevReset(struct wiphy *wiphy,
			     struct wireless_dev *wdev,
			     const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}

static int
mwl_vendor_cmd_set_ndpa_useta(struct wiphy *wiphy,
			      struct wireless_dev *wdev,
			      const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}

#ifdef IEEE80211K
static int
mwl_vendor_cmd_set_sendBcnReport(struct wiphy *wiphy,
				 struct wireless_dev *wdev,
				 const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}

static int
mwl_vendor_cmd_get_nList(struct wiphy *wiphy,
			 struct wireless_dev *wdev,
			 const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}

static int
mwl_vendor_cmd_get_nListCfg(struct wiphy *wiphy,
			    struct wireless_dev *wdev,
			    const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}

static int
mwl_vendor_cmd_set_sendNlistRep(struct wiphy *wiphy,
				struct wireless_dev *wdev,
				const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}
#endif

#if 0
static int
mwl_vendor_cmd_set_enableScnr(struct wiphy *wiphy,
			      struct wireless_dev *wdev,
			      const void *data, int data_len)
{
	struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}

static int
mwl_vendor_cmd_set_dfsSetChanSw(struct wiphy *wiphy,
				struct wireless_dev *wdev,
				const void *data, int data_len)
{
	struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}

static int
mwl_vendor_cmd_set_radar_event(struct wiphy *wiphy,
			       struct wireless_dev *wdev,
			       const void *data, int data_len)
{
	struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}
#endif

static int
mwl_vendor_cmd_set_qosCtrl1(struct wiphy *wiphy,
			    struct wireless_dev *wdev,
			    const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}

static int
mwl_vendor_cmd_set_qosCtrl2(struct wiphy *wiphy,
			    struct wireless_dev *wdev,
			    const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}

static int
mwl_vendor_cmd_get_qosCtrl(struct wiphy *wiphy,
			   struct wireless_dev *wdev,
			   const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}

static int
mwl_vendor_cmd_set_mu_bfmer(struct wiphy *wiphy,
			    struct wireless_dev *wdev,
			    const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}

static int
mwl_vendor_cmd_set_fipsTest(struct wiphy *wiphy,
			    struct wireless_dev *wdev,
			    const void *data, int data_len)
{
	//struct wlprivate *priv = mwl_cfg80211_get_priv(wiphy);

	return -ENOTSUPP;
}

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

static const struct wiphy_vendor_command mwl_vendor_commands[] = {
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_VERSION,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_version,
	 },
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
		  .subcmd = MWL_VENDOR_CMD_SET_OPMODE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_opmode,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_OPMODE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_opmode,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_STAMODE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_stamode,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_STAMODE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_stamode,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_KEY,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_key,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_DEL_KEY,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_del_key,
	 },
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
		  .subcmd = MWL_VENDOR_CMD_GET_WPAWPA2MODE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_wpawpa2mode,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_PASSPHRASE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_passphrase,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_PASSPHRASE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_passphrase,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_CIPHERSUITE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_ciphersuite,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_CIPHERSUITE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_ciphersuite,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_WMM,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_wmm,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_WMM,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_wmm,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_WMMEDCAAP,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_wmmedcaap,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_WMMEDCAAP,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_wmmedcaap,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_AMSDU,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_amsdu,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_AMSDU,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_amsdu,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_RXANTENNA,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_rxantenna,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_RXANTENNA,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_rxantenna,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_OPTLEVEL,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_optlevel,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_OPTLEVEL,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_optlevel,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_MACCLONE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_macclone,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_STASCAN,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_stascan,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_STASCAN,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_stascan,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_FIXRATE,

		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_fixrate,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_FIXRATE,

		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_fixrate,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_TXRATE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_txrate,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_TXRATE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_txrate,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_MCASTPROXY,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_mcastproxy,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_MCASTPROXY,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_mcastproxy,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_11HSTAMODE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_11hstamode,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_11HSTAMODE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_11hstamode,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_RSSI,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_rssi,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_LINKSTATUS,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_linkstatus,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_STALISTEXT,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_stalistext,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_GROUPREKEY,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_grouprekey,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_GROUPREKEY,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_grouprekey,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_WMMEDCASTA,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_wmmedcasta,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_WMMEDCASTA,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_wmmedcasta,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_HTBW,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_htbw,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_HTBW,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_htbw,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_FILTER,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_filter,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_FILTER,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_filter,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_ADD_FILTERMAC,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_add_filtermac,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_DEL_FILTERMAC,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_del_filtermac,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_FILTERMAC,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_filtermac,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_INTRABSS,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_intrabss,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_INTRABSS,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_intrabss,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_HIDESSID,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_hidessid,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_HIDESSID,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_hidessid,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_BCNINTERVAL,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_bcninterval,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_BCNINTERVAL,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_bcninterval,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_DTIM,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_dtim,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_DTIM,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_dtim,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_GPROTECT,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_gprotect,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_GPROTECT,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_gprotect,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_PREAMBLE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_preamble,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_PREAMBLE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_preamble,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_AGINGTIME,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_agingtime,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_AGINGTIME,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_agingtime,
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
		  .subcmd = MWL_VENDOR_CMD_SET_BSSID,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_bssid,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_BSSID,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_bssid,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_REGIONCODE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_regioncode,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_REGIONCODE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_regioncode,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_RATEMODE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_ratemode,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_RATEMODE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_ratemode,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_WDSMODE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_wdsmode,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_WDSMODE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_wdsmode,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_DISABLEASSOC,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_disableassoc,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_DISABLEASSOC,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_disableassoc,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_WDS,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_wds,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_WDS,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_wds,
	 },
#ifdef IEEE80211_DH
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_11DMODE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_11dmode,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_11DMODE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_11dmode,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_11HSPECMGT,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_11hspecmgt,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_11HSPECMGT,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_11hspecmgt,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_11HPWRCONSTR,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_11hpwrconstr,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_11HPWRCONSTR,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_11hpwrconstr,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_11HCSAMODE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_11hcsaMode,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_11HCSAMODE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_11hcsaMode,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_11HCSACOUNT,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_11hcsaCount,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_11HCSACOUNT,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_11hcsaCount,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_11HDFSMODE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_11hdfsMode,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_11HDFSMODE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_11hdfsMode,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_11HCSACHAN,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_11hcsaChan,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_11HCSACHAN,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_11hcsaChan,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_11HCSASTART,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_11hcsaStart,
	 },
#endif
#ifdef MRVL_DFS
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_11HNOPTIMEOUT,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_11hnopTimeout,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_11HNOPTIMEOUT,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_11hnopTimeout,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_11HCACTIMEOUT,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_11hcacTimeout,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_11HCACTIMEOUT,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_11hcacTimeout,
	 },

#endif
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_CSMODE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_csMode,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_CSMODE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_csMode,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_GUARDINT,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_guardIntv,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_GUARDINT,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_guardIntv,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_EXTSUBCH,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_extSubCh,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_EXTSUBCH,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_extSubCh,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_HTPROTECT,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_htProtect,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_HTPROTECT,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_htProtect,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_AMPDUFACTOR,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_ampduFactor,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_AMPDUFACTOR,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_ampduFactor,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_AMPDUDEN,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_ampduDen,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_AMPDUDEN,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_ampduDen,
	 },

#ifdef AMPDU_SUPPORT
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_AMPDUTX,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_ampduTx,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_AMPDUTX,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_ampduTx,
	 },

#endif
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_TXPOWER,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_txPower,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_TXPOWER,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_txPower,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_FWSTAT,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_fwStat,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_AUTOCHANNEL,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_autoChannel,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_AUTOCHANNEL,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_autoChannel,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_MAXTXPOWER,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_maxTxPower,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_MAXTXPOWER,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_maxTxPower,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_DEL_WEPKEY,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_del_wepKey,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_STRICTSHARED,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_strictShared,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_STRICTSHARED,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_strictShared,
	 },

#ifdef PWRFRAC
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_PWRFRACTION,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_txPowerFraction,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_PWRFRACTION,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_txPowerFraction,
	 },

#endif
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_MIMOPS,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_mimops,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_MIMOPS,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_mimops,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_TXANTENNA,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_txantenna,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_TXANTENNA,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_txantenna,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_HTGF,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_htgf,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_HTGF,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_htgf,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_HTSTBC,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_htstbc,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_HTSTBC,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_htstbc,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_3X3RATE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_3x3rate,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_3X3RATE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_3x3rate,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_INTOLERANT40,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_intolerant40,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_TXQLIMIT,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_txqlimit,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_TXQLIMIT,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_txqlimit,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_RIFS,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_rifs,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_BFTYPE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_bftype,
	 },
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
		  .subcmd = MWL_VENDOR_CMD_GET_BANDSTEER,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_bandsteer,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_APPIE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_appie,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_IE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_ie,
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
		  .subcmd = MWL_VENDOR_CMD_SET_COUNTERMEASURES,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_countermeasures,
	 },
#ifdef CONFIG_IEEE80211W
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_SEQNUM,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_seqnum,
	 },
#endif
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SEND_MGMT,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_send_mgmt,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_RTS,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_rts,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_CHANNEL,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_channel,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_WEPKEY,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_wepkey,
	 },
#ifdef MRVL_WAPI
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_WAPIMODE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_wapimode,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_WAPIMODE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_wapimode,
	 },
#endif
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_WMMACKPOLICY,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_wmmackpolicy,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_WMMACKPOLICY,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_wmmackpolicy,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_TXANTENNA2,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_txantenna2,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_TXANTENNA2,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_txantenna2,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_DEVICEINFO,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_deviceinfo,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_OR,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_or,
	 },
#ifdef INTEROP
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_INTEROP,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_interop,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_INTEROP,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_interop,
	 },
#endif
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_11HETSICAC,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_11hetsicac,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_11HETSICAC,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_11hetsicac,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_RXINTLIMIT,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_rxintlimit,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_RXINTLIMIT,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_rxintlimit,
	 },
#if defined ( INTOLERANT40) ||defined (COEXIST_20_40_SUPPORT)
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_INTOLER,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_intoler,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_INTOLER,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_intoler,
	 },
#endif
#ifdef RXPATHOPT
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_RXPATHOPT,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_rxpathopt,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_RXPATHOPT,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_rxpathopt,
	 },
#endif
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_AMSDUFT,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_amsduft,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_AMSDUFT,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_amsduft,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_AMSDUMS,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_amsdums,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_AMSDUMS,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_amsdums,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_AMSDUAS,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_amsduas,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_AMSDUAS,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_amsduas,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_AMSDUPC,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_amsdupc,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_AMSDUPC,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_amsdupc,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_CDD,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_cdd,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_CDD,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_cdd,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_ACSTHRD,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_acsthrd,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_ACSTHRD,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_acsthrd,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_DEVICEID,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_deviceid,
	 },
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
#ifdef CLIENT_SUPPORT
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_AUTOSCAN,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_autoscan,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_AUTOSCAN,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_autoscan,
	 },
#endif
#ifdef DOT11V_DMS
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_DMS,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_dms,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_DMS,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_dms,
	 },
#endif
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_SYSLOAD,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_sysload,
	 },
#ifdef MRVL_DFS
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_11HNOCLIST,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_11hnoclist,
	 },
#endif
#if defined(CLIENT_SUPPORT) && defined (MRVL_WSC)
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_BSSPROFILE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_bssprofile,
	 },
#endif
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_TLV,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_tlv,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_CHNLS,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_chnls,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_SCANCHNL,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_scanchnls,
	 },
#ifdef WTP_SUPPORT
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_WTP,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_wtp,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_WTPMACMODE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_wtpmacmode,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_WTPTUNNELMODE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_wtptunnelmode,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_WTPCFG,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_wtpcfg,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_RADIOSTAT,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_radiostat,
	 },
#endif
#ifdef MFG_SUPPORT
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_EXTFW,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_extfw,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_MFGFW,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_mfgfw,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_MFG,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_mfg,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_FWREV,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_fwrev,
	 },
#endif
#ifdef AMPDU_SUPPORT
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_ADDBA,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_addba,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_AMPDUSTAT,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_ampdustat,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_DELBA,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_delba,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_DEL2BA,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_del2ba,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_AMPDURXDISABLE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_ampdurxdisable,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_TRIGGERSCANINTERVAL,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_triggerscaninterval,
	 },
#ifdef EXPLICIT_BF
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_BF,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_bf,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_MUMIMOMGMT,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_mumimomgmt,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_MUMIMOMGMT,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_mumimomgmt,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_MUSTA,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_musta,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_MUSET,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_muset,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_MUSET,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_muset,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_DEL_MUSET,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_del_muset,
	 },
#ifdef MRVL_MUG_ENABLE
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_MUG_ENABLE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_mug_enable,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_MUINFO,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_muinfo,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_MUGROUPS,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_mugroups,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_MUCONFIG,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_muconfig,
	 },
#endif
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_MUAUTOTIMER,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_muautotimer,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_MUPREFERUSRCNT,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_mupreferusrcnt,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_GID,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_gid,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_NOACK,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_noack,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_NOSTEER,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_nosteer,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_TXHOP,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_txhop,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_BFTYPE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_bftype,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_BWSIGNALTYPE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_bwsignaltype,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_BWSIGNALTYPE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_bwsignaltype,
	 },
#endif
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_WEAKIV_THRESHOLD,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_weakiv_threshold,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_WEAKIV_THRESHOLD,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_weakiv_threshold,
	 },
#ifdef POWERSAVE_OFFLOAD
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_TIM,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_tim,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_POWERSAVESTATION,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_powersavestation,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_TIM,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_tim,
	 },
#endif
#endif
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_BCN,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_bcn,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_ANNEX,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_annex,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_READEEPROMHDR,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_readeepromhdr,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_OR,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_or,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_ADDRTABLE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_addrtable,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_FWENCRINFO,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_fwencrinfo,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_REG,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_reg,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_DEBUG,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_debug,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_MEMDUMP,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_memdump,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_DESIRE_BSSID,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_desire_bssid,
	 },
#ifdef EWB
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_EWBTABLE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_ewbtable,
	 },
#endif
#if defined (SOC_W8366) || defined (SOC_W8364) || defined (SOC_W8764)
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_RATETABLE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_ratetable,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_RATETABLE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_ratetable,
	 },
#endif
#ifdef DYNAMIC_BA_SUPPORT
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_AMPDU_BAMGMT,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_ampdu_bamgmt,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_AMPDU_BAMGMT,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_ampdu_bamgmt,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_MINTRAFFIC,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_ampdu_mintraffic,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_MINTRAFFIC,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_ampdu_mintraffic,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_AMPDU_AC_THRESHOLD,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_ampdu_ac_threshold,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_AMPDU_AC_THRESHOLD,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_ampdu_ac_threshold,
	 },
#endif
#ifdef BARBADOS_DFS_TEST
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_DFSTEST,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_dfstest,
	 },
#endif
#ifdef MPRXY
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_IPMCGRP,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_ipmcgrp,
	 },
#endif
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_RPTRMODE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_rptrmode,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_LOAD_TXPWRTABLE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_load_txpowertable,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_TXPWRTABLE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_txpowertable,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_LINKLOST,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_linklost,
	 },
#ifdef SSU_SUPPORT
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_SSUTEST,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_ssutest,
	 },
#endif
#ifdef QUEUE_STATS
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_QSTATS,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_qstats,
	 },
#endif
#ifdef SOC_W8864
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_RCCAL,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_rccal,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_TEMP,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_temp,
	 },
#endif
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_MAXSTA,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_maxsta,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_MAXSTA,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_maxsta,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_TXFAILLIMIT,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_txfaillimit,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_TXFAILLIMIT,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_txfaillimit,
	 },
#ifdef MRVL_WAPI
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_WAPI,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_wapi,
	 },
#endif
#ifdef WNC_LED_CTRL
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_LED,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_led,
	 },
#endif
#ifdef CLIENT_SUPPORT
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_FASTRECONNECT,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_fastreconnect,
	 },
#endif
#ifdef NEW_DP
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_NEWDP,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_newdp,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_TXRATECTRL,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_txratectrl,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_NEWDPCNT,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_newdpcnt,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_NEWDPACNTSIZE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_newdpacntsize,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_NEWDPACNT,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_newdpacnt,
	 },
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_NEWDPOFFCH,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_newDpOffCh,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_TXCONTINUOUS,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_txContinuous,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_RXSOP,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_rxSop,
	 },
#endif
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_PWRPERRATE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_pwrPerRate,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_RATEGRPS,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_rateGrps,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_PWRGRPSTBL,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_pwrGrpsTbl,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_PERRATEPWR,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_perRatePwr,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_PERRATEPWR,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_perRatePwr,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_NF,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_nf,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_RADIOSTATUS,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_radioStatus,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_LDPC,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_ldpc,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_TLV,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_tlv,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_AMPDUCFG,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_ampduCfg,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_AMSDUCFG,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_amsduCfg,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_BBDBG,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_bbDbg,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_MU_SM_CACHE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_mu_sm_cache,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_SKU,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_sku,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_RXANTBITMAP,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_rxAntBitmap,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_RETRYCFGENABLE,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_retryCfgEnable,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_RETRYCFG,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_retryCfg,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_RADIORATESCFG,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_radioRatesCfg,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_EEWR,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_eewr,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_EERD,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_eerd,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_EEPROMACCESS,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_eepromAccess,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_OFFCHPWR,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_offChPwr,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_WDEVRESET,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_wdevReset,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_NDPA_USETA,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_ndpa_useta,
	 },

#ifdef IEEE80211K
	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_SENDBCNREPORT,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_sendBcnReport,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_NLIST,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_nList,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_NLISTCFG,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_nListCfg,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_SENDNLISTREP,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_sendNlistRep,
	 },
#endif

	/*
	   #ifdeANNER_SUPPORT
	   {
	   .info = {
	   .vendor_id = MRVL_OUI,
	   .subcmd = MWL_VENDOR_CMD_SET_ENABLESCNR,
	   },
	   .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	   .doit = mwl_vendor_cmd_set_enableScnr,
	   },

	   {
	   .info = {
	   .vendor_id = MRVL_OUI,
	   .subcmd = MWL_VENDOR_CMD_SET_DFSSETCHANSW,
	   },
	   .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	   .doit = mwl_vendor_cmd_set_dfsSetChanSw,
	   },

	   {
	   .info = {
	   .vendor_id = MRVL_OUI,
	   .subcmd = MWL_VENDOR_CMD_SET_RADAR_EVENT,
	   },
	   .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	   .doit = mwl_vendor_cmd_set_radar_event,
	   },
	   #end
	 */

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_QOSCTRL1,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_qosCtrl1,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_QOSCTRL2,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_qosCtrl2,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_GET_QOSCTRL,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_get_qosCtrl,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_MU_BFMER,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_mu_bfmer,
	 },

	{
	 .info = {
		  .vendor_id = MRVL_OUI,
		  .subcmd = MWL_VENDOR_CMD_SET_FIPSTEST,
		  },
	 .flags = WIPHY_VENDOR_CMD_NEED_NETDEV,
	 .doit = mwl_vendor_cmd_set_fipsTest,
	 },
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

};

void
mwl_set_vendor_commands(struct wiphy *wiphy)
{
	wiphy->vendor_commands = mwl_vendor_commands;
	wiphy->n_vendor_commands = ARRAY_SIZE(mwl_vendor_commands);
	wiphy->vendor_events = mwl_vendor_events;
	wiphy->n_vendor_events = ARRAY_SIZE(mwl_vendor_events);
}
