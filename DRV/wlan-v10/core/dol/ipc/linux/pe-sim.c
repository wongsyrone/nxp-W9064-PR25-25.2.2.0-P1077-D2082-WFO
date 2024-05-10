/** @file pe-sim.c
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

#include <linux/kthread.h>
#include <linux/err.h>

#include "ap8xLnxVer.h"
#include "ap8xLnxIntf.h"
#include "ap8xLnxBQM.h"
#include "wlmac.h"
#include "ipc.h"
#include "ipc_i.h"
#include "ipc_msg.h"

#define PE_SIM_IPC_VER    DOL_VER
#define PE_SIM_IPC_DESC   "NXP Wifi Data Off Load Packet Engine Simulator IPC"

static struct wlprivate *radio_priv[2];

static struct task_struct *pe_sim_task = NULL;

static int
pe_sim_thread(void *data)
{
	struct wlprivate *wlpptr = (struct wlprivate *)data;

	while (1) {
		set_current_state(TASK_UNINTERRUPTIBLE);
		if (kthread_should_stop())
			break;
		ipc_check_msg(wlpptr->wlpd_p->ipc_session_id);
		schedule_timeout(HZ / HZ);
	}

	return 0;
}

static int
__ipc_h2t_pkt_recv_rel(struct wlprivate *wlpptr, t2h_pkt_recv_t * t2h_msg)
{
	h2t_pkt_recv_rel_t h2t_msg;
	ca_ipc_pkt_t ipc_pkt;

	h2t_msg.radio = wlpptr->wlpd_p->ipc_session_id;
	h2t_msg.pkt_hdr_addr = t2h_msg->pkt_hdr_addr;

	ipc_pkt.session_id = wlpptr->wlpd_p->ipc_session_id;
	ipc_pkt.dst_cpu_id = 0;
	ipc_pkt.priority = 0;
	ipc_pkt.msg_no = WFO_IPC_H2T_PKT_RECV_REL;
	ipc_pkt.msg_data = &h2t_msg;
	ipc_pkt.msg_size = sizeof(h2t_msg);

	ca_ipc_msg_async_send(&ipc_pkt);

	return 0;
}

static int
__ipc_t2h_cmd_reply_handle(ca_ipc_addr_t peer, ca_uint16_t msg_no,
			   ca_uint16_t trans_id, const void *msg_data,
			   ca_uint16_t * msg_size)
{
	u16 radio;
	struct wlprivate *wlpptr;

	if (msg_no != WFO_IPC_T2H_CMD_REPLY)
		return -EINVAL;

	radio = *((u16 *) msg_data);

	if ((radio <= 0) || (radio > 2))
		return -EINVAL;

	wlpptr = radio_priv[radio - 1];
	if (wlpptr && wlpptr->wlpd_p->ipc.rcv_cmd)
		wlpptr->wlpd_p->ipc.rcv_cmd(wlpptr->wlpd_p->ipc.rcv_cmd_data,
					    msg_data, msg_size);

	return 0;
}

static int
__ipc_t2h_pkt_recv_handle(ca_ipc_addr_t peer, ca_uint16_t msg_no,
			  ca_uint16_t trans_id, const void *msg_data,
			  ca_uint16_t * msg_size)
{
	t2h_pkt_recv_t *t2h_msg;
	struct wlprivate *wlpptr;
	u8 *pkt_virt;
	struct sk_buff *rcv_skb;
	int rxcfg_len = sizeof(wlrxdesc_t), skb_len;

	if (msg_no != WFO_IPC_T2H_PKT_RECV)
		return -EINVAL;

	if (*msg_size != sizeof(*t2h_msg))
		return -EINVAL;

	t2h_msg = (t2h_pkt_recv_t *) msg_data;

	if ((t2h_msg->radio <= 0) || (t2h_msg->radio > 2))
		return -EINVAL;

	wlpptr = radio_priv[t2h_msg->radio - 1];
	skb_len = t2h_msg->buf_len;
	if (!t2h_msg->is_data)
		skb_len += rxcfg_len;
	rcv_skb = wl_alloc_skb(skb_len);
	if (!rcv_skb) {
		WLDBG_ERROR(DBG_LEVEL_0, "no skbuff available\n");
		return -ENOMEM;
	}
	pkt_virt = (u8 *) phys_to_virt(t2h_msg->buf_phy_addr);
	if (!t2h_msg->is_data) {
#ifdef DBG_PKT_RX_MGMT_TIMESTAMP
		wlrxdesc_t *rxcfg;
		IEEEtypes_FrameCtl_t *frm_ctrl;

		rxcfg = (wlrxdesc_t *) & t2h_msg->rxcfg[0];
		frm_ctrl = (IEEEtypes_FrameCtl_t *) & rxcfg->frame_ctrl;
		if ((frm_ctrl->Subtype == IEEE_MSG_AUTHENTICATE) ||
		    (frm_ctrl->Subtype == IEEE_MSG_ASSOCIATE_RQST) ||
		    (frm_ctrl->Subtype == IEEE_MSG_REASSOCIATE_RQST)) {
			printk("Host Rx->Mgmt(%x): timestamp=0x%04x, BBTX_TMR_FREE_TSF=0x%08x\n", frm_ctrl->Subtype, rxcfg->hdr.timestamp, readl(wlpptr->ioBase1 + BBTX_TMR_FREE_TSF));
		}
#endif
		memcpy(rcv_skb->data, &t2h_msg->rxcfg[0], rxcfg_len);
		memcpy(rcv_skb->data + sizeof(wlrxdesc_t), pkt_virt,
		       t2h_msg->buf_len);
	} else
		memcpy(rcv_skb->data, pkt_virt, t2h_msg->buf_len);
	skb_put(rcv_skb, skb_len);

	if (wlpptr && wlpptr->wlpd_p->ipc.rcv_pkt)
		wlpptr->wlpd_p->ipc.rcv_pkt(wlpptr->wlpd_p->ipc.rcv_pkt_data,
					    rcv_skb, t2h_msg->is_data);

	return __ipc_h2t_pkt_recv_rel(wlpptr, t2h_msg);
}

static int
__ipc_t2h_pkt_send_done_handle(ca_ipc_addr_t peer,
			       ca_uint16_t msg_no,
			       ca_uint16_t trans_id,
			       const void *msg_data, ca_uint16_t * msg_size)
{
	t2h_pkt_send_done_t *t2h_msg;
	struct wlprivate *wlpptr;
	struct sk_buff *rel_skb;

	if (msg_no != WFO_IPC_T2H_PKT_SEND_DONE)
		return -EINVAL;

	if (*msg_size != sizeof(*t2h_msg))
		return -EINVAL;

	t2h_msg = (t2h_pkt_send_done_t *) msg_data;

	if ((t2h_msg->radio <= 0) || (t2h_msg->radio > 2))
		return -EINVAL;

	wlpptr = radio_priv[t2h_msg->radio - 1];
	rel_skb = (struct sk_buff *)t2h_msg->skb_addr;

	wl_free_skb(rel_skb);

	return 0;
}

static int
__ipc_t2h_event_handle(ca_ipc_addr_t peer, ca_uint16_t msg_no,
		       ca_uint16_t trans_id, const void *msg_data,
		       ca_uint16_t * msg_size)
{
	u16 radio;
	struct wlprivate *wlpptr;

	if (msg_no != WFO_IPC_T2H_EVENT)
		return -EINVAL;

	radio = *((u16 *) msg_data);

	if ((radio <= 0) || (radio > 2))
		return -EINVAL;

	wlpptr = radio_priv[radio - 1];
	if (wlpptr && wlpptr->wlpd_p->ipc.rcv_event)
		wlpptr->wlpd_p->ipc.rcv_event(wlpptr->wlpd_p->ipc.
					      rcv_event_data, msg_data,
					      msg_size);

	return 0;
}

ca_ipc_msg_handle_t wfo_ipc_msg[WFO_IPC_T2H_MAX] = {
	{.msg_no = WFO_IPC_T2H_CMD_REPLY,.proc = __ipc_t2h_cmd_reply_handle}
	,
	{.msg_no = WFO_IPC_T2H_PKT_RECV,.proc = __ipc_t2h_pkt_recv_handle}
	,
	{.msg_no = WFO_IPC_T2H_PKT_SEND_DONE,.proc =
	 __ipc_t2h_pkt_send_done_handle}
	,
	{.msg_no = WFO_IPC_T2H_EVENT,.proc = __ipc_t2h_event_handle}
	,
};

static int
__pe_sim_init(void *ctrl)
{
	struct wlprivate *wlpptr = (struct wlprivate *)ctrl;

	return ca_ipc_msg_handle_register(wlpptr->wlpd_p->ipc_session_id,
					  wfo_ipc_msg, WFO_IPC_T2H_MAX);
}

static void
__pe_sim_deinit(void *ctrl)
{
	struct wlprivate *wlpptr = (struct wlprivate *)ctrl;

	ca_ipc_msg_handle_unregister(wlpptr->wlpd_p->ipc_session_id);
}

static void
__pe_sim_send_cmd(void *ctrl, void *msg, u16 msg_size)
{
	struct wlprivate *wlpptr = (struct wlprivate *)ctrl;
	ca_ipc_pkt_t ipc_pkt;

	ipc_pkt.session_id = wlpptr->wlpd_p->ipc_session_id;
	ipc_pkt.dst_cpu_id = 0;
	ipc_pkt.priority = 0;
	ipc_pkt.msg_no = WFO_IPC_H2T_CMD_SEND;
	ipc_pkt.msg_data = msg;
	ipc_pkt.msg_size = msg_size;

	ca_ipc_msg_async_send(&ipc_pkt);
}

static void
__pe_sim_register_cmd_rcv(void *ctrl,
			  void (*rcv_cmd) (void *data,
					   const void *msg,
					   u16 * msg_size), void *data)
{
	struct wlprivate *wlpptr = (struct wlprivate *)ctrl;

	wlpptr->wlpd_p->ipc.rcv_cmd = rcv_cmd;
	wlpptr->wlpd_p->ipc.rcv_cmd_data = data;
}

static void
__pe_sim_send_pkt(void *ctrl, struct sk_buff *skb, wltxdesc_t * txcfg, int qid)
{
	struct wlprivate *wlpptr = (struct wlprivate *)ctrl;
	h2t_pkt_send_t h2t_msg;
	ca_ipc_pkt_t ipc_pkt;

	h2t_msg.radio = wlpptr->wlpd_p->ipc_session_id;
	h2t_msg.qid = qid;
	h2t_msg.skb_addr = (u64) skb;
	h2t_msg.buf_phy_addr = virt_to_phys(skb->data);
	h2t_msg.buf_len = skb->len;
	memcpy(&h2t_msg.txcfg, txcfg, sizeof(*txcfg));

	ipc_pkt.session_id = wlpptr->wlpd_p->ipc_session_id;
	ipc_pkt.dst_cpu_id = 0;
	ipc_pkt.priority = 0;
	ipc_pkt.msg_no = WFO_IPC_H2T_PKT_SEND;
	ipc_pkt.msg_data = &h2t_msg;
	ipc_pkt.msg_size = sizeof(h2t_msg);

	ca_ipc_msg_async_send(&ipc_pkt);
}

static void
__pe_sim_register_pkt_rcv(void *ctrl,
			  void (*rcv_pkt) (void *data,
					   struct sk_buff * skb,
					   bool is_data), void *data)
{
	struct wlprivate *wlpptr = (struct wlprivate *)ctrl;

	wlpptr->wlpd_p->ipc.rcv_pkt = rcv_pkt;
	wlpptr->wlpd_p->ipc.rcv_pkt_data = data;
}

static void
__pe_sim_register_event_rcv(void *ctrl,
			    void (*rcv_event) (void *data,
					       const void *event,
					       u16 * event_size), void *data)
{
	struct wlprivate *wlpptr = (struct wlprivate *)ctrl;

	wlpptr->wlpd_p->ipc.rcv_event = rcv_event;
	wlpptr->wlpd_p->ipc.rcv_event_data = data;
}

static struct mwl_ipc_ops pe_sim_ipc_ops = {
	.name = PE_SIM_IPC_DESC,
	.version = PE_SIM_IPC_VER,
	.init = __pe_sim_init,
	.deinit = __pe_sim_deinit,
	.send_cmd = __pe_sim_send_cmd,
	.register_cmd_rcv = __pe_sim_register_cmd_rcv,
	.send_pkt = __pe_sim_send_pkt,
	.register_pkt_rcv = __pe_sim_register_pkt_rcv,
	.register_event_rcv = __pe_sim_register_event_rcv,
};

int
pe_platform_init(struct wlprivate *wlpptr)
{
	int err;

	wlpptr->wlpd_p->ipc_session_id = ipc_fun_init();

	if (!wlpptr->wlpd_p->ipc_session_id)
		return -EBUSY;

	if (wlpptr->wlpd_p->ipc.ops)
		return -EBUSY;
	wlpptr->wlpd_p->ipc.vendor = IPC_LINUX_PE_SIM;
	wlpptr->wlpd_p->ipc.ops = &pe_sim_ipc_ops;

	if (!pe_sim_task) {
		pe_sim_task =
			kthread_create(pe_sim_thread, wlpptr, "pe_sim_task");
		if (IS_ERR(pe_sim_task)) {
			printk(KERN_ERR "Unable to start kernel thread.\n");
			err = PTR_ERR(pe_sim_task);
			pe_sim_task = NULL;
			return err;
		}
		wake_up_process(pe_sim_task);
	}

	radio_priv[wlpptr->wlpd_p->ipc_session_id - 1] = wlpptr;

	printk("%s\n", PE_SIM_IPC_DESC);
	printk("version: %s\n", PE_SIM_IPC_VER);

	return 0;
}

void
pe_platform_deinit(struct wlprivate *wlpptr)
{
	if (pe_sim_task) {
		kthread_stop(pe_sim_task);
		pe_sim_task = NULL;
	}

	if (wlpptr->wlpd_p->ipc.vendor == IPC_LINUX_PE_SIM) {
		wlpptr->wlpd_p->ipc.vendor = IPC_NOT_ASSIGN;
		wlpptr->wlpd_p->ipc.ops = NULL;
	}

	if (wlpptr->wlpd_p->ipc_session_id)
		ipc_fun_deinit(wlpptr->wlpd_p->ipc_session_id);

	radio_priv[wlpptr->wlpd_p->ipc_session_id - 1] = NULL;
	wlpptr->wlpd_p->ipc_session_id = 0;
}
