/** @file pkt_inline.h
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

#ifndef __PKT_INLINE_H__
#define __PKT_INLINE_H__

#include "ipc_msg.h"
#include "ipc.h"

static inline void
pkt_free_hdr(struct radio *radio, struct pkt_hdr *pkt_hdr)
{
	if (pkt_hdr && pkt_hdr->is_clone) {
		printf("\t %s(%d): can't free here (should call pkt_free_bm_data())\n", __func__, radio->rid);
		return;
	}

	if (pkt_hdr) {
#ifdef ENABLE_SIGNATURE_CHECK_PKT_HDR
		if (pkt_hdr->signature != PKT_HEADER_SIGNATURE)
			printf("\t %s(%d): %p %08x\n", __func__, radio->rid,
			       pkt_hdr, pkt_hdr->signature);
#endif

		if (pkt_hdr->ref_cnt)
			pkt_hdr->ref_cnt--;
		else
			printf("\t %s(%d): reference count is zero\n", __func__,
			       radio->rid);

		if (!pkt_hdr->ref_cnt)
			list_put_item(&radio->pkt_ctrl.pkt_hdr_free_list,
				      (struct list_item *)pkt_hdr);

		radio->dbg_cnt.pkt_cnt.pkt_hdr_free++;
	}
}

static inline bool
pkt_free_host_data(struct radio *radio, struct pkt_hdr *pkt)
{
	t2h_pkt_send_done_t t2h_msg;
	ca_ipc_pkt_t ipc_pkt;

	if (pkt) {
		t2h_msg.radio = radio->rid;
		t2h_msg.skb_addr = pkt->orig_hdr;
		t2h_msg.buf_phy_addr = (ca_uint32_t) VIRT_TO_PHYS(pkt->data);

		ipc_pkt.session_id = SYSADPT_MSG_IPC_SESSION;
		ipc_pkt.dst_cpu_id = SYSADPT_MSG_IPC_DST_CPU;
		ipc_pkt.priority = 0;
		ipc_pkt.msg_no = WFO_IPC_T2H_PKT_SEND_DONE;
		ipc_pkt.msg_data = &t2h_msg;
		ipc_pkt.msg_size = sizeof(t2h_msg);

		if (ca_ipc_msg_async_send(&ipc_pkt))
			return false;

		pkt_free_hdr(radio, pkt);
		radio->dbg_cnt.pkt_cnt.pkt_host_data_free++;
	}

	return true;
}

static inline void
pkt_free_eth_data(struct radio *radio, struct pkt_hdr *pkt)
{
	eth_free_pkt((void *)__PLATFORM_POINTER_TYPE__(pkt->orig_hdr));
	pkt_free_hdr(radio, pkt);
	radio->dbg_cnt.pkt_cnt.pkt_eth_data_free++;
}

static inline void
pkt_free_bm_data(struct radio *radio, struct pkt_hdr *pkt, const char *fun)
{
	struct pkt_ctrl *ctrl;
	struct pkt_hdr *clone_hdr;
	struct pkt_data *pkt_data;

	if (pkt) {
		if (pkt->is_clone) {
			clone_hdr = pkt->clone_pkt;
			list_remove_item(&clone_hdr->clone_list,
					 (struct list_item *)pkt);
			pkt->is_clone = false;
			pkt_free_hdr(radio, pkt);
			pkt = clone_hdr;
			if ((pkt->ref_cnt == 2) && (!pkt->is_rx_amsdu_hold))
				pkt->ref_cnt--;
			radio->dbg_cnt.pkt_cnt.pkt_bm_data_clone_free++;
		}
		if (pkt->ref_cnt > 1) {
			pkt->ref_cnt--;
			return;
		}
		if (!pkt->ref_cnt) {
			printf("\t %s(%d): free bm packet with reference count 0 (caller %s)\n", __func__, radio->rid, fun);
			return;
		}
#ifdef DBG_BM_BUF_MONITOR
		dbg_check_buf(radio->rid, pkt, __func__);
#endif
		ctrl = &radio->pkt_ctrl;
		pkt_data = (struct pkt_data *)
			(pkt->buf_ptr - PKT_DATA_HEADROOM);
#ifdef ENABLE_SIGNATURE_CHECK_DATA
		if (pkt_data->signature != PKT_DATA_SIGNATURE) {
			printf("\t %s(%d): %p %08x\n", __func__, radio->rid,
			       pkt_data, pkt_data->signature);
			printf("\t buff[%d] pkt %p data %p buf_ptr %p\n",
			       pkt->qid - radio->bm_q_start, pkt, pkt->data,
			       pkt->buf_ptr);
		}
#endif
#ifdef ENABLE_PKT_DATA_STATUS
		if (pkt_data->status == PKT_DATA_FREE) {
			printf("\t Packet data double free: %d %p %08x\n",
			       radio->rid, pkt_data, pkt_data->signature);
			printf("\t buff[%d] pkt %p data %p buf_ptr %p\n",
			       pkt->qid - radio->bm_q_start, pkt, pkt->data,
			       pkt->buf_ptr);
		} else if (pkt_data->status == PKT_DATA_FW_ASSIGNED) {
			printf("\t Packet data is owned by FW: %d %p %08x\n",
			       radio->rid, pkt_data, pkt_data->signature);
			printf("\t buff[%d] pkt %p data %p buf_ptr %p\n",
			       pkt->qid - radio->bm_q_start, pkt, pkt->data,
			       pkt->buf_ptr);
		} else
			pkt_data->status = PKT_DATA_FREE;
#endif
		list_put_item(&ctrl->
			      pkt_data_free_list[pkt->qid - radio->bm_q_start],
			      (struct list_item *)pkt_data);
		pkt_free_hdr(radio, pkt);
		radio->dbg_cnt.pkt_cnt.pkt_bm_data_free++;
		radio->dbg_cnt.pkt_cnt.pkt_bmq_free[pkt->qid -
						    radio->bm_q_start]++;
	}
}

static inline void
pkt_free_local_data(struct radio *radio, struct pkt_hdr *pkt)
{
	MFREE(pkt->buf_ptr);
	pkt_free_hdr(radio, pkt);
	radio->dbg_cnt.pkt_cnt.pkt_local_data_free++;
}

static inline void
__init_pkt_hdr(struct pkt_hdr *pkt)
{
	pkt->is_clone = 0;
	pkt->is_rx_amsdu_hold = 0;
}

static inline struct pkt_hdr *
pkt_alloc_hdr(int rid)
{
	struct radio *radio = &radio_info[rid - 1];
	struct pkt_hdr *pkt_hdr;

	pkt_hdr = (struct pkt_hdr *)
		list_get_item(&radio->pkt_ctrl.pkt_hdr_free_list);
	if (pkt_hdr) {
		/* memset(pkt_hdr, 0, sizeof(struct pkt_hdr)); */
		__init_pkt_hdr(pkt_hdr);
#ifdef ENABLE_SIGNATURE_CHECK_PKT_HDR
		pkt_hdr->signature = PKT_HEADER_SIGNATURE;
#endif
		list_init(&pkt_hdr->clone_list);
		pkt_hdr->ref_cnt = 1;
		radio->dbg_cnt.pkt_cnt.pkt_hdr_alloc++;
	} else
		radio->dbg_cnt.pkt_cnt.pkt_hdr_lack++;

	return pkt_hdr;
}

static inline struct pkt_hdr *
pkt_alloc_bm_data(int rid, int qid)
{
	struct radio *radio = &radio_info[rid - 1];
	struct pkt_hdr *pkt_hdr;
	struct pkt_data *pkt_data;
	struct pkt_ctrl *ctrl;
	int idx = qid - radio->bm_q_start;

	pkt_hdr = pkt_alloc_hdr(rid);
	if (pkt_hdr) {
		ctrl = &radio->pkt_ctrl;
		pkt_data = (struct pkt_data *)
			list_get_item(&ctrl->pkt_data_free_list[idx]);
		if (!pkt_data) {
			radio->dbg_cnt.pkt_cnt.pkt_bmq_lack_buf[idx]++;
			goto no_mem;
		}
#ifdef ENABLE_SIGNATURE_CHECK_DATA
		pkt_data->signature = PKT_DATA_SIGNATURE;
#endif
#ifdef ENABLE_PKT_DATA_STATUS
		pkt_data->status = PKT_DATA_ALLOC;
#endif
		pkt_hdr->buf_ptr = &pkt_data->data[0];
		pkt_hdr->buf_size = radio->bm_buf_size[idx] -
			PKT_DATA_HEADROOM - RXBUF_ALIGN;
		if (ctrl->pkt_buf_headroom)
			pkt_hdr->data =
				pkt_hdr->buf_ptr + ctrl->pkt_buf_headroom;
		else {
			pkt_hdr->data =
				pkt_hdr->buf_ptr + SYSADPT_BM_BUF_HEADROOM;

			if (!ADDR_ALIGNED((long)pkt_hdr->data, RXBUF_ALIGN))
				pkt_hdr->data =
					ALIGN_ADDR(pkt_hdr->data, RXBUF_ALIGN);

			ctrl->pkt_buf_headroom =
				pkt_hdr->data - pkt_hdr->buf_ptr;
		}
		pkt_hdr->data_type = PKT_DATA_FROM_BM;
		pkt_hdr->qid = qid;
		radio->dbg_cnt.pkt_cnt.pkt_bm_data_alloc++;
		radio->dbg_cnt.pkt_cnt.pkt_bmq_alloc[idx]++;
#ifdef DBG_BM_BUF_MONITOR
		dbg_check_buf(rid, pkt_hdr, __func__);
#endif
		return pkt_hdr;
	}

no_mem:
	if (pkt_hdr)
		pkt_free_hdr(radio, pkt_hdr);

	return NULL;
}

static inline struct pkt_hdr *
pkt_clone_bm_data(int rid, struct pkt_hdr *pkt)
{
	struct radio *radio = &radio_info[rid - 1];
	struct pkt_hdr *clone_hdr;

	if (pkt->is_clone) {
		printf("\t %s(%d): cloned packet can't be cloned\n",
		       __func__, rid);
		return NULL;
	}

	if (pkt->data_type != PKT_DATA_FROM_BM) {
		printf("\t %s(%d): only bm data can be cloned\n",
		       __func__, rid);
		return NULL;
	}

	clone_hdr = (struct pkt_hdr *)
		list_get_item(&radio->pkt_ctrl.pkt_hdr_free_list);
	if (clone_hdr) {
		memcpy(clone_hdr, pkt, sizeof(struct pkt_hdr));
		clone_hdr->is_clone = true;
		clone_hdr->clone_pkt = pkt;
		clone_hdr->ref_cnt = 1;
		pkt->ref_cnt++;
		list_put_item(&pkt->clone_list, (struct list_item *)clone_hdr);
		radio->dbg_cnt.pkt_cnt.pkt_bm_data_clone++;
	}

	return clone_hdr;
}

static inline void
pkt_free_data(int rid, struct pkt_hdr *pkt, const char *fun)
{
	struct radio *radio = &radio_info[rid - 1];

	switch (pkt->data_type) {
	case PKT_DATA_FROM_HOST:
		list_put_item(&radio->pkt_ctrl.pkt_from_host_free_list,
			      (struct list_item *)pkt);
		break;
	case PKT_DATA_FROM_ETH:
		pkt_free_eth_data(radio, pkt);
		break;
	case PKT_DATA_FROM_BM:
		pkt_free_bm_data(radio, pkt, fun);
		break;
	case PKT_DATA_FROM_LOCAL:
		pkt_free_local_data(radio, pkt);
		break;
	default:
		printf("\t %s(%d): unknown data type: %d\n",
		       __func__, rid, pkt->data_type);
		break;
	}
}

#endif /* __PKT_INLINE_H__ */
