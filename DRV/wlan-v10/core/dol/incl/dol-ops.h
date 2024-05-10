/** @file dol-ops.h
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2019 NXP
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

#ifndef __DOL_OPS_H__
#define __DOL_OPS_H__

#include "dol.h"

static inline const char *
dol_get_name(struct wlprivate *wlpptr)
{
	if (wlpptr->wlpd_p->dol.disable)
		return NULL;

	return wlpptr->wlpd_p->dol.ops->name;
}

static inline const char *
dol_get_version(struct wlprivate *wlpptr)
{
	if (wlpptr->wlpd_p->dol.disable)
		return NULL;

	return wlpptr->wlpd_p->dol.ops->version;
}

static inline int
dol_init(struct wlprivate *wlpptr)
{
	if (wlpptr->wlpd_p->dol.disable)
		return -EPERM;

	if (wlpptr->wlpd_p->dol.ops->init)
		return wlpptr->wlpd_p->dol.ops->init(wlpptr);
	else
		return -ENOTSUPP;
}

static inline int
dol_deinit(struct wlprivate *wlpptr)
{
	if (wlpptr->wlpd_p->dol.disable)
		return -EPERM;

	if (wlpptr->wlpd_p->dol.ops->deinit)
		wlpptr->wlpd_p->dol.ops->deinit(wlpptr);
	else
		return -ENOTSUPP;

	return 0;
}

static inline int
dol_check_active(struct wlprivate *wlpptr, int rid, bool * active)
{
	if (wlpptr->wlpd_p->dol.disable)
		return -EPERM;

	if (wlpptr->wlpd_p->dol.ops->check_active)
		return wlpptr->wlpd_p->dol.ops->check_active(wlpptr, rid,
							     active);
	else
		return -ENOTSUPP;
}

static inline int
dol_get_wfo_version(struct wlprivate *wlpptr, int rid, u8 * ver)
{
	if (wlpptr->wlpd_p->dol.disable)
		return -EPERM;

	if (wlpptr->wlpd_p->dol.ops->get_wfo_version)
		return wlpptr->wlpd_p->dol.ops->get_wfo_version(wlpptr, rid,
								ver);
	else
		return -ENOTSUPP;
}

static inline int
dol_start_radio(struct wlprivate *wlpptr, int rid)
{
	if (wlpptr->wlpd_p->dol.disable)
		return -EPERM;

	if (wlpptr->wlpd_p->dol.ops->start_radio)
		return wlpptr->wlpd_p->dol.ops->start_radio(wlpptr, rid);
	else
		return -ENOTSUPP;
}

static inline int
dol_stop_radio(struct wlprivate *wlpptr, int rid)
{
	if (wlpptr->wlpd_p->dol.disable)
		return -EPERM;

	if (wlpptr->wlpd_p->dol.ops->stop_radio)
		return wlpptr->wlpd_p->dol.ops->stop_radio(wlpptr, rid);
	else
		return -ENOTSUPP;
}

static inline int
dol_suspend_radio(struct wlprivate *wlpptr, int rid, bool suspend)
{
	if (wlpptr->wlpd_p->dol.disable)
		return -EPERM;

	if (wlpptr->wlpd_p->dol.ops->suspend_radio)
		return wlpptr->wlpd_p->dol.ops->suspend_radio(wlpptr, rid,
							      suspend);
	else
		return -ENOTSUPP;
}

static inline int
dol_radio_data_ctrl(struct wlprivate *wlpptr, int rid, bool enable)
{
	if (wlpptr->wlpd_p->dol.disable)
		return -EPERM;

	if (wlpptr->wlpd_p->dol.ops->radio_data_ctrl)
		return wlpptr->wlpd_p->dol.ops->radio_data_ctrl(wlpptr, rid,
								enable);
	else
		return -ENOTSUPP;
}

static inline int
dol_radio_tx_ampdu_ctrl(struct wlprivate *wlpptr, int rid, u8 ampdu_tx)
{
	if (wlpptr->wlpd_p->dol.disable)
		return -EPERM;

	if (wlpptr->wlpd_p->dol.ops->radio_tx_ampdu_ctrl)
		return wlpptr->wlpd_p->dol.ops->radio_tx_ampdu_ctrl(wlpptr, rid,
								    ampdu_tx);
	else
		return -ENOTSUPP;
}

static inline void
dol_radio_return_buffer(struct wlprivate *wlpptr, int rid, u64 pkt_hdr_addr)
{
	if (wlpptr->wlpd_p->dol.disable)
		return;

	if (wlpptr->wlpd_p->dol.ops->radio_return_buffer)
		wlpptr->wlpd_p->dol.ops->radio_return_buffer(wlpptr, rid,
							     pkt_hdr_addr);
}

static inline int
dol_radio_get_rx_info(struct wlprivate *wlpptr, int rid, bool clean)
{
	if (wlpptr->wlpd_p->dol.disable)
		return -EPERM;

	if (wlpptr->wlpd_p->dol.ops->radio_get_rx_info)
		return wlpptr->wlpd_p->dol.ops->radio_get_rx_info(wlpptr, rid,
								  clean);
	else
		return -ENOTSUPP;
}

static inline int
dol_add_vif(struct wlprivate *wlpptr, int rid, int vid, u8 * bssid)
{
	if (wlpptr->wlpd_p->dol.disable)
		return -EPERM;

	if (wlpptr->wlpd_p->dol.ops->add_vif)
		return wlpptr->wlpd_p->dol.ops->add_vif(wlpptr, rid, vid,
							bssid);
	else
		return -ENOTSUPP;
}

static inline int
dol_del_vif(struct wlprivate *wlpptr, int rid, int vid)
{
	if (wlpptr->wlpd_p->dol.disable)
		return -EPERM;

	if (wlpptr->wlpd_p->dol.ops->del_vif)
		return wlpptr->wlpd_p->dol.ops->del_vif(wlpptr, rid, vid);
	else
		return -ENOTSUPP;
}

static inline int
dol_vif_data_ctrl(struct wlprivate *wlpptr, int rid, int vid, bool enable)
{
	if (wlpptr->wlpd_p->dol.disable)
		return -EPERM;

	if (wlpptr->wlpd_p->dol.ops->vif_data_ctrl)
		return wlpptr->wlpd_p->dol.ops->vif_data_ctrl(wlpptr, rid, vid,
							      enable);
	else
		return -ENOTSUPP;
}

static inline int
dol_vif_set_isolate_grp_id(struct wlprivate *wlpptr, int rid,
			   int vid, int group_id)
{
	if (wlpptr->wlpd_p->dol.disable)
		return -EPERM;

	if (wlpptr->wlpd_p->dol.ops->vif_set_isolate_grp_id)
		return wlpptr->wlpd_p->dol.ops->vif_set_isolate_grp_id(wlpptr,
								       rid, vid,
								       group_id);
	else
		return -ENOTSUPP;
}

static inline int
dol_add_sta(struct wlprivate *wlpptr, int rid, int vid, u8 * addr)
{
	if (wlpptr->wlpd_p->dol.disable)
		return -EPERM;

	if (wlpptr->wlpd_p->dol.ops->add_sta)
		return wlpptr->wlpd_p->dol.ops->add_sta(wlpptr, rid, vid, addr);
	else
		return -ENOTSUPP;
}

static inline int
dol_del_sta(struct wlprivate *wlpptr, int rid, int vid, u8 * addr)
{
	if (wlpptr->wlpd_p->dol.disable)
		return -EPERM;

	if (wlpptr->wlpd_p->dol.ops->del_sta)
		return wlpptr->wlpd_p->dol.ops->del_sta(wlpptr, rid, vid, addr);
	else
		return -ENOTSUPP;
}

static inline int
dol_sta_data_ctrl(struct wlprivate *wlpptr, int rid, int vid,
		  u16 stn_id, u8 * addr, bool enable)
{
	if (wlpptr->wlpd_p->dol.disable)
		return -EPERM;

	if (wlpptr->wlpd_p->dol.ops->sta_data_ctrl)
		return wlpptr->wlpd_p->dol.ops->sta_data_ctrl(wlpptr, rid, vid,
							      stn_id, addr,
							      enable);
	else
		return -ENOTSUPP;
}

static inline int
dol_sta_tx_ampdu_ctrl(struct wlprivate *wlpptr, int rid, int vid, u8 * addr,
		      u32 threshold, u8 * startbytid)
{
	if (wlpptr->wlpd_p->dol.disable)
		return -EPERM;

	if (wlpptr->wlpd_p->dol.ops->sta_tx_ampdu_ctrl)
		return wlpptr->wlpd_p->dol.ops->sta_tx_ampdu_ctrl(wlpptr, rid,
								  vid, addr,
								  threshold,
								  startbytid);
	else
		return -ENOTSUPP;
}

static inline void
dol_set_ba_info(struct wlprivate *wlpptr, int rid, u16 type,
		u16 stn_id, u16 tid, u16 winStartB, u16 winSizeB)
{
	if (wlpptr->wlpd_p->dol.disable)
		return;

	if (wlpptr->wlpd_p->dol.ops->set_ba_info)
		wlpptr->wlpd_p->dol.ops->set_ba_info(wlpptr, rid, type, stn_id,
						     tid, winStartB, winSizeB);
}

static inline void
dol_set_ba_req(struct wlprivate *wlpptr, int rid, u16 vid,
	       u16 stn_id, u16 tid, u16 seq)
{
	if (wlpptr->wlpd_p->dol.disable)
		return;

	if (wlpptr->wlpd_p->dol.ops->set_ba_req)
		wlpptr->wlpd_p->dol.ops->set_ba_req(wlpptr, rid, vid, stn_id,
						    tid, seq);
}

static inline int
dol_xmit(struct wlprivate *wlpptr, struct sk_buff *skb,
	 wltxdesc_t * txcfg, int qid)
{
	int rc;

	if (wlpptr->wlpd_p->dol.disable)
		rc = -EPERM;
	else {
		if (wlpptr->wlpd_p->dol.ops->xmit)
			return wlpptr->wlpd_p->dol.ops->xmit(wlpptr, skb, txcfg,
							     qid);
		else
			rc = -ENOTSUPP;
	}

	wl_free_skb(skb);

	return rc;
}

static inline struct sk_buff *
dol_recv(struct wlprivate *wlpptr, bool data)
{
	if (wlpptr->wlpd_p->dol.disable)
		return NULL;

	if (wlpptr->wlpd_p->dol.ops->recv)
		return wlpptr->wlpd_p->dol.ops->recv(wlpptr, data);
	else
		return NULL;
}

static inline void
dol_set_dscp_wmm_mapping(struct wlprivate *wlpptr, int rid,
			 u16 dscp_wmm_mapping)
{
	if (wlpptr->wlpd_p->dol.disable)
		return;

	if (wlpptr->wlpd_p->dol.ops->set_dscp_wmm_mapping)
		wlpptr->wlpd_p->dol.ops->set_dscp_wmm_mapping(wlpptr, rid,
							      dscp_wmm_mapping);
}

static inline int
dol_get_stats(struct wlprivate *wlpptr, int rid, int vid,
	      u16 type, void *stats, int stats_size, bool clear_after_read,
	      int *more)
{
	if (wlpptr->wlpd_p->dol.disable)
		return -EPERM;

	if (wlpptr->wlpd_p->dol.ops->get_stats)
		return wlpptr->wlpd_p->dol.ops->get_stats(wlpptr, rid, vid,
							  type, stats,
							  stats_size,
							  clear_after_read,
							  more);
	else
		return -ENOTSUPP;
}

static inline void
dol_set_dbg_ctrl(struct wlprivate *wlpptr, int rid, u16 dbg_ctrl)
{
	if (wlpptr->wlpd_p->dol.disable)
		return;

	if (wlpptr->wlpd_p->dol.ops->set_dbg_ctrl)
		wlpptr->wlpd_p->dol.ops->set_dbg_ctrl(wlpptr, rid, dbg_ctrl);
}

#endif /* __DOL_OPS_H__ */
