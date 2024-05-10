/** @file ipc-ops.h
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

#ifndef __IPC_OPS_H__
#define __IPC_OPS_H__

#include "ipc.h"

static inline const char *
ipc_get_name(struct wlprivate *wlpptr)
{
	if (wlpptr->wlpd_p->ipc.disable)
		return NULL;

	return wlpptr->wlpd_p->ipc.ops->name;
}

static inline const char *
ipc_get_version(struct wlprivate *wlpptr)
{
	if (wlpptr->wlpd_p->ipc.disable)
		return NULL;

	return wlpptr->wlpd_p->ipc.ops->version;
}

static inline int
ipc_init(struct wlprivate *wlpptr)
{
	if (wlpptr->wlpd_p->ipc.disable)
		return -EPERM;

	if (wlpptr->wlpd_p->ipc.ops->init)
		return wlpptr->wlpd_p->ipc.ops->init(wlpptr);
	else
		return -ENOTSUPP;
}

static inline int
ipc_deinit(struct wlprivate *wlpptr)
{
	if (wlpptr->wlpd_p->ipc.disable)
		return -EPERM;

	if (wlpptr->wlpd_p->ipc.ops->deinit)
		wlpptr->wlpd_p->ipc.ops->deinit(wlpptr);
	else
		return -ENOTSUPP;

	return 0;
}

static inline int
ipc_send_cmd(struct wlprivate *wlpptr, void *msg, u16 msg_size)
{
	if (wlpptr->wlpd_p->ipc.disable)
		return -EPERM;

	if (wlpptr->wlpd_p->ipc.ops->send_cmd)
		wlpptr->wlpd_p->ipc.ops->send_cmd(wlpptr, msg, msg_size);
	else
		return -ENOTSUPP;

	return 0;
}

static inline int
ipc_register_cmd_rcv(struct wlprivate *wlpptr,
		     void (*rcv_cmd) (void *data,
				      const void *msg,
				      u16 * msg_size), void *data)
{
	if (wlpptr->wlpd_p->ipc.disable)
		return -EPERM;

	if (wlpptr->wlpd_p->ipc.ops->register_cmd_rcv)
		wlpptr->wlpd_p->ipc.ops->register_cmd_rcv(wlpptr, rcv_cmd,
							  data);
	else
		return -ENOTSUPP;

	return 0;
}

static inline int
ipc_send_pkt(struct wlprivate *wlpptr, struct sk_buff *skb,
	     wltxdesc_t * txcfg, int qid)
{
	int rc = 0;

	if (wlpptr->wlpd_p->ipc.disable)
		rc = -EPERM;
	else {
		if (wlpptr->wlpd_p->ipc.ops->send_pkt)
			wlpptr->wlpd_p->ipc.ops->send_pkt(wlpptr, skb, txcfg,
							  qid);
		else
			rc = -ENOTSUPP;
	}

	if (rc)
		wl_free_skb(skb);

	return rc;
}

static inline int
ipc_register_pkt_rcv(struct wlprivate *wlpptr,
		     void (*rcv_pkt) (void *data,
				      struct sk_buff * skb,
				      bool is_data), void *data)
{
	if (wlpptr->wlpd_p->ipc.disable)
		return -EPERM;

	if (wlpptr->wlpd_p->ipc.ops->register_pkt_rcv)
		wlpptr->wlpd_p->ipc.ops->register_pkt_rcv(wlpptr, rcv_pkt,
							  data);
	else
		return -ENOTSUPP;

	return 0;
}

static inline int
ipc_register_event_rcv(struct wlprivate *wlpptr,
		       void (*rcv_event) (void *data,
					  const void *event,
					  u16 * event_size), void *data)
{
	if (wlpptr->wlpd_p->ipc.disable)
		return -EPERM;

	if (wlpptr->wlpd_p->ipc.ops->register_event_rcv)
		wlpptr->wlpd_p->ipc.ops->register_event_rcv(wlpptr, rcv_event,
							    data);
	else
		return -ENOTSUPP;

	return 0;
}

#endif /* __IPC_OPS_H__ */
