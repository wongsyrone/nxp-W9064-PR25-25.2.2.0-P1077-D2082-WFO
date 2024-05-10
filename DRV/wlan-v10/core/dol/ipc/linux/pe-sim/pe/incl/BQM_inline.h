/** @file BQM_inline.h
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

#ifndef __BQM_INLINE_H__
#define __BQM_INLINE_H__

static void
reset_signature(ca_uint8_t * pkt_addr)
{
#if defined(ENABLE_PKT_SIGNATURE) || defined(ENABLE_SIGNATURE_CHECK_DATA)
	ca_uint8_t *pkt_hd = pkt_addr - PKT_INFO_SIZE;
	ca_uint32_t aligned_offset;
#ifdef LINUX_PE_SIM
	aligned_offset = ((ca_uint64_t) pkt_hd & 0x3);
#else
	aligned_offset = ((ca_uint32_t) pkt_hd & 0x3);
#endif

	pkt_hd -= aligned_offset;
	*((ca_uint32_t *) pkt_hd) = 0x55aa55aa;
#ifdef ENABLE_SIGNATURE_CHECK_DATA
	*((ca_uint32_t *) (pkt_hd + 4)) = 0xdeadbeef;
	*((ca_uint32_t *) (pkt_hd + 8)) = 0xabcd1234;
#endif
#endif
}

static inline ca_uint32_t
wlGetDescSize(struct radio *radio, ca_uint16_t qid, int qoff)
{
	ca_uint32_t qelm_size = 0;

	/* Input parameter checking */
	if ((SYSADPT_NUM_OF_HW_DESC_DATA <= qid) ||
	    ((qoff != SC5_RQ) && (qoff != SC5_SQ))) {
		printf("%s(%d): failed to find descriptor size (%u, %d)\n",
		       __func__, radio->rid, qid, qoff);
		return 0;
	}

	if (qoff == SC5_RQ) {
		if ((qid >= radio->tx_q_start) &&
		    (qid < radio->tx_q_start + radio->tx_q_num))
			qelm_size = sizeof(wltxdesc_t);

		if ((qid >= radio->bm_q_start) &&
		    (qid < radio->bm_q_start + radio->bm_q_num))
			qelm_size = sizeof(bm_pe_hw_t);
	}

	if (qoff == SC5_SQ) {
		if (qid == radio->rx_q_data)
			qelm_size = sizeof(wlrxdesc_t);

		if ((qid >= radio->rel_q_start) &&
		    (qid < radio->rel_q_start + radio->rel_q_num))
			qelm_size = sizeof(bm_pe_hw_t);
	}

	return qelm_size;
}

static inline bool
isRQFull(wl_qpair_rq_t * rq)
{
	if (((rq->wrinx + 1) % rq->qsize) == rq->rdinx)
		return true;

	return false;
}

static inline bool
isRQEmpty(wl_qpair_rq_t * rq)
{
	if (rq->wrinx == rq->rdinx)
		return true;

	return false;
}

static inline bool
isSQFull(wl_qpair_sq_t * sq)
{
	if (((sq->wrinx + 1) % sq->qsize) == sq->rdinx)
		return true;

	return false;
}

static inline bool
isSQEmpty(wl_qpair_sq_t * sq)
{
	if (sq->wrinx == sq->rdinx)
		return true;

	return false;
}

static inline bool
wlSQIndexGet(wl_qpair_sq_t * sq)
{
	if (!isSQEmpty(sq)) {
		sq->rdinx = (sq->rdinx + 1) % sq->qsize;
		return true;
	}

	return false;
}

static inline bool
wlSQIndexPut(wl_qpair_sq_t * sq)
{
	if (!isSQFull(sq)) {
		sq->wrinx = (sq->wrinx + 1) % sq->qsize;
		return true;
	}

	return false;
}

static inline bool
wlRQIndexGet(wl_qpair_rq_t * rq)
{
	if (!isRQEmpty(rq)) {
		rq->rdinx = (rq->rdinx + 1) % rq->qsize;
		return true;
	}

	return false;
}

static inline bool
wlRQIndexPut(wl_qpair_rq_t * rq)
{
	if (!isRQFull(rq)) {
		rq->wrinx = (rq->wrinx + 1) % rq->qsize;
		return true;
	}

	return false;
}

static inline ca_uint32_t
wlQueryRdPtr(int rid, int qid, int qoff)
{
	struct radio *radio = &radio_info[rid - 1];
	struct wldesc_data *wlqm;
	ca_uint32_t regval;
	ca_uint32_t desc_size = wlGetDescSize(radio, qid, qoff);
	ca_uint32_t orig_rdinx;
	ca_uint32_t idx_val, qsize;

	wlqm = &radio->desc_data[qid];
	if (qoff == SC5_RQ) {
		orig_rdinx = wlqm->rq.rdinx;
		regval = read32(radio->iobase1 + SC5_RQ_RDPTR_REG(qid));
		qsize = wlqm->rq.qsize;
	} else {
		orig_rdinx = wlqm->sq.rdinx;
		regval = read32(radio->iobase1 + SC5_SQ_RDPTR_REG(qid));
		qsize = wlqm->sq.qsize;
	}
	if (regval == 0xffffffff)
		return orig_rdinx;

	if (!desc_size)
		return orig_rdinx;

	/* Make sure index is valid */
	idx_val = ((regval & 0xffff0000) >> 12) / desc_size;
	if (idx_val >= qsize)
		printf("%s(%d): incorrect %s(%d) rd_idx = %u", __func__,
		       rid, ((qoff == SC5_RQ) ? "RQ" : "SQ"), qid, idx_val);

	return idx_val;
}

static inline void
wlUpdateRdPtr(int rid, int qid, int qoff, ca_uint32_t rdinx)
{
	struct radio *radio = &radio_info[rid - 1];
	u32 ptval, desc_size = wlGetDescSize(radio, qid, qoff);

	/* smac_hf_reg_rq_wr_ptr_rq10.rq10 = temp_hframe_bman_wp[19:4];
	 * hframe format last 4 bits truncated
	 */
	ptval = ((rdinx * desc_size) & 0xffff0) << 12;

	if (qoff == SC5_RQ)
		write32(ptval, (radio->iobase1 + SC5_RQ_RDPTR_REG(qid)));
	else
		write32(ptval, (radio->iobase1 + SC5_SQ_RDPTR_REG(qid)));
}

static inline ca_uint32_t
wlQueryWrPtr(int rid, int qid, int qoff)
{
	struct radio *radio = &radio_info[rid - 1];
	struct wldesc_data *wlqm;
	ca_uint32_t regval;
	ca_uint32_t desc_size = wlGetDescSize(radio, qid, qoff);
	ca_uint32_t orig_wrinx;
	ca_uint32_t idx_val, qsize;

	wlqm = &radio->desc_data[qid];
	if (qoff == SC5_RQ) {
		orig_wrinx = wlqm->rq.wrinx;
		regval = read32(radio->iobase1 + SC5_RQ_WRPTR_REG(qid));
		qsize = wlqm->rq.qsize;
	} else {
		orig_wrinx = wlqm->sq.wrinx;
		regval = read32(radio->iobase1 + SC5_SQ_WRPTR_REG(qid));
		qsize = wlqm->sq.qsize;
	}
	if (regval == 0xffffffff)
		return orig_wrinx;

	if (!desc_size)
		return orig_wrinx;

	idx_val = ((regval & 0xffff0000) >> 12) / desc_size;
	if (idx_val >= qsize)
		printf("%s(%d): incorrect %s(%d) rd_idx = %u", __func__,
		       rid, ((qoff == SC5_RQ) ? "RQ" : "SQ"), qid, idx_val);

	return idx_val;
}

static inline void
wlUpdateWrPtr(int rid, int qid, int qoff, ca_uint32_t wrinx)
{
	struct radio *radio = &radio_info[rid - 1];
	ca_uint32_t ptval, desc_size = wlGetDescSize(radio, qid, qoff);

	ptval = ((wrinx * desc_size) & 0xffff0) << 12;

	if (qoff == SC5_RQ)
		write32(ptval, (radio->iobase1 + SC5_RQ_WRPTR_REG(qid)));
	else
		write32(ptval, (radio->iobase1 + SC5_SQ_WRPTR_REG(qid)));
}

static inline bool
wlSQEmpty(int rid, ca_uint8_t qid)
{
	struct radio *radio = &radio_info[rid - 1];
	struct wldesc_data *wlqm;

	wlqm = &radio->desc_data[qid];
	wlqm->sq.wrinx = wlQueryWrPtr(rid, qid, SC5_SQ);
	return isSQEmpty(&wlqm->sq);
}

static inline bool
wlSQFull(int rid, ca_uint8_t qid)
{
	struct radio *radio = &radio_info[rid - 1];
	struct wldesc_data *wlqm;

	wlqm = &radio->desc_data[qid];
	wlqm->sq.wrinx = wlQueryWrPtr(rid, qid, SC5_SQ);
	return isSQFull(&wlqm->sq);
}

static inline bool
wlRQFull(int rid, ca_uint8_t qid)
{
	struct radio *radio = &radio_info[rid - 1];
	struct wldesc_data *wlqm;

	wlqm = &radio->desc_data[qid];
	if (isRQFull(&wlqm->rq)) {
		wlqm->rq.rdinx = wlQueryRdPtr(rid, qid, SC5_RQ);
		if (isRQFull(&wlqm->rq))
			return true;
	}
	return false;
}

static inline void
wlResetCfhUl(wlrxdesc_t * cfh_ul)
{
#ifdef ENABLE_SIGNATURE_CHECK_DATA
	/* invalidat some memory so we can check for new data */
	cfh_ul->hdr.used_signature = BMBUF_SIGNATURE;
	cfh_ul->hdr.length = USED_BUFLEN;
	cfh_ul->nss_hdr[2] = HF_OWN_SIGNATURE;
#endif
}

#ifdef CORTINA_TUNE_HW_CPY_RX
static inline void
wlTriggerAsyncCopyCfhUL(struct wldesc_data *wlqm,
			wlrxdesc_t * dst_cfh_ul, ca_uint32_t count)
{
	wlrxdesc_t *next_cfh_ul_hw;
	ca_uint32_t next_index;
	ca_uint32_t delta_i;
	next_index = (wlqm->sq.rdinx + 1) % wlqm->sq.qsize;

	if (next_index != wlqm->sq.wrinx) {
		if (count != 1) {
			if (next_index < wlqm->sq.wrinx)
				delta_i = wlqm->sq.wrinx - next_index;
			else
				delta_i = wlqm->sq.qsize - next_index;
			if (count > delta_i)
				count = delta_i;
		}
		next_cfh_ul_hw = (wlrxdesc_t *)
			(wlqm->sq.virt_addr + next_index * sizeof(wlrxdesc_t));
		rx_desc_now = (ca_uint8_t *) dst_cfh_ul;
		rx_desc_end = rx_desc_now + sizeof(wlrxdesc_t) * count;
		ca_dma_async_copy(HW_DMA_COPY_WIFI_RX_CHF,
				  VIRT_TO_PHYS(rx_desc_now),
				  VIRT_TO_PHYS(next_cfh_ul_hw),
				  sizeof(wlrxdesc_t) * count);
		rx_desc_async_wait = 1;
	}
}
#endif

static inline void
wl_free_cfhul_lo(ca_uint32_t tmp_lodword_addr, int rid, ca_uint32_t bpid)
{
	struct radio *radio = &radio_info[rid - 1];
	struct pkt_hdr *pkt;
	ca_uint8_t *pkt_addr = NULL;
	ca_uint32_t aligned_offset;

	if (tmp_lodword_addr == 0xffffffff || tmp_lodword_addr == 0) {
		printf("%s(%d): invalid lo_dword_addr\n", __func__, rid);
		goto exit;
	}

	if ((bpid < radio->bm_q_start) ||
	    ((radio->bm_q_start + radio->bm_q_num) <= bpid)) {
		printf("%s(%d): invalid bpid %d\n", __func__, rid, bpid);
		goto exit;
	}

	pkt_addr = PHYS_TO_VIRT(tmp_lodword_addr);

#ifdef LINUX_PE_SIM
	aligned_offset = ((ca_uint64_t) (pkt_addr - PKT_INFO_SIZE) & 0x3);
#else
	aligned_offset = ((ca_uint32_t) (pkt_addr - PKT_INFO_SIZE) & 0x3);
#endif

#if defined(ENABLE_PKT_SIGNATURE) || defined(ENABLE_SIGNATURE_CHECK_DATA)
	if (*((ca_uint32_t *) (pkt_addr - PKT_INFO_SIZE - aligned_offset)) !=
	    PKT_SIGNATURE) {
		printf("%s(%d): invalid signature %08x\n", __func__,
		       rid,
		       *((ca_uint32_t *) (pkt_addr - PKT_INFO_SIZE -
					  aligned_offset)));
		goto exit;
	} else
#endif
	{
		pkt = *(struct pkt_hdr **)
			(pkt_addr - PKT_POINTER_OFFSET - aligned_offset);
		pkt_free_data(rid, pkt, __func__);
	}
exit:

	return;
}

static inline wlrxdesc_t *
wlGetCfhUl(int rid, int qid, wlrxdesc_t * cfh_ul)
{
	struct radio *radio = &radio_info[rid - 1];
	struct wldesc_data *wlqm;
	wlrxdesc_t *cfh_ul_hw;
	IEEEtypes_FrameCtl_t *frame_ctlp;
	ca_uint16_t *snap_aaaa;

	wlqm = &radio->desc_data[qid];
	cfh_ul_hw = (wlrxdesc_t *)
		(wlqm->sq.virt_addr + wlqm->sq.rdinx * sizeof(wlrxdesc_t));
#ifdef CORTINA_TUNE_HW_CPY_RX
	if (rx_desc_now == cfh_ul) {
		if (rx_desc_async_wait == 1) {
			ca_dma_poll_for_complete(HW_DMA_COPY_WIFI_RX_CHF);
			rx_desc_async_wait = 0;
		}
		rx_desc_now = rx_desc_now + sizeof(wlrxdesc_t);
		if (rx_desc_now == rx_desc_end) {
			rx_desc_now = rx_desc_end = NULL;
		}
	} else {
		ca_dma_sync_copy(HW_DMA_COPY_WIFI_RX_CHF,
				 VIRT_TO_PHYS((ca_uint8_t *) cfh_ul),
				 VIRT_TO_PHYS(cfh_ul_hw), sizeof(wlrxdesc_t));
		rx_desc_now = NULL;
	}

	if ((rx_desc_now == NULL) && (cfh_ul->lpkt != 1))
		wlTriggerAsyncCopyCfhUL(wlqm,
					(ca_uint8_t *) cfh_ul +
					sizeof(wlrxdesc_t), 1);
#else
	memcpy(cfh_ul, cfh_ul_hw, sizeof(wlrxdesc_t));
#endif
	wlResetCfhUl(cfh_ul_hw);
	if (cfh_ul->hdrFormat == 1) {
		/* Bypass this packets by Powei's mail on 2018/10/9,
		 * "RX packet forward to host with MIC/ICV or other error.
		 *      Since packet is bad, we will use RxAMSDU bypass mode
		 * to generate CFH-UL without parsing the data. In this case,
		 * RxAMSDU will just copy CFH-TEMP and set Fpkt/Lpkt=1/1"
		 */

		//Todo: Need to OMI here for wifi 6 cert.
		wl_nullpkt_hndl(rid, cfh_ul);

		wl_free_cfhul_lo(cfh_ul->hdr.lo_dword_addr, rid,
				 cfh_ul->hdr.bpid);
		return NULL;
	}
#ifdef ENABLE_SIGNATURE_CHECK_DATA
	/* Return if CFH-UL not been updated yet */
	if (cfh_ul->nss_hdr[2] == HF_OWN_SIGNATURE ||
	    cfh_ul->hdr.length == USED_BUFLEN ||
	    cfh_ul->hdr.used_signature == BMBUF_SIGNATURE) {
		radio->dbg_cnt.rx_cnt.rx_cfh_ul_sig_err++;
		return NULL;
	}

	if ((cfh_ul->hdr.bpid < radio->bm_q_start) ||
	    ((radio->bm_q_start + radio->bm_q_num) <= cfh_ul->hdr.bpid)) {
		radio->dbg_cnt.rx_cnt.rx_cfh_ul_bpid_err++;
		return NULL;
	}
#endif

	frame_ctlp = (IEEEtypes_FrameCtl_t *) & cfh_ul->frame_ctrl;
	/* SNAP check will break fragmented data traffic. Skip check for fragmented pkt */
	/* Skip SNAP check for mic_err, icv_err pkt. */
	if ((frame_ctlp->Type == IEEE_TYPE_DATA) &&
	    (!frame_ctlp->MoreFrag && !(cfh_ul->hdr.seqnum & 0xF) &&
	     (cfh_ul->hdrFormat != 1))) {
		/* Check the 0xAAAA of SNAP in data MSDU header
		 */
		snap_aaaa = (ca_uint16_t *) cfh_ul->nss_hdr;
		if ((qid == radio->rx_q_data) && (snap_aaaa[7] != 0xAAAA)) {
			radio->dbg_cnt.rx_cnt.rx_cfh_ul_snap_err++;
			return NULL;
		}
	}
#ifdef ENABLE_SIGNATURE_CHECK_DATA
	{
		struct wldesc_data *wlqm_tmp;

		wlqm_tmp = &radio->desc_data[cfh_ul->hdr.bpid];
		if (cfh_ul->hdr.length > wlqm_tmp->rq.bm.buf_size) {
			radio->dbg_cnt.rx_cnt.rx_cfh_ul_size_err++;
			return NULL;
		}

		if ((radio->devid == SC5 && radio->chip_revision == REV_Z1) &&
		    !(cfh_ul->fpkt == 1 && cfh_ul->lpkt == 1))
			return NULL;
	}
#endif

	return cfh_ul;
}

static inline struct pkt_hdr *
wlCfhUlToPkt(int rid, wlrxdesc_t * cfh_ul, int rx_qid)
{
	struct radio *radio = &radio_info[rid - 1];
	struct pkt_hdr *pkt, *pkt_c;
	struct wldesc_data *wlqm;
	bm_pe_t *pe;
	ca_uint8_t *pkt_addr = NULL;
	ca_uint32_t aligned_offset;

	if ((cfh_ul->hdr.bpid < radio->bm_q_start) ||
	    ((radio->bm_q_start + radio->bm_q_num) <= cfh_ul->hdr.bpid)) {
		printf("%s(%d): invalid bpid %d\n", __func__, rid,
		       cfh_ul->hdr.bpid);
		goto destroy;
	}

	wlqm = &radio->desc_data[cfh_ul->hdr.bpid];
	pe = (bm_pe_t *) (wlqm->rq.bm.pe + 0);

	if (cfh_ul->hdr.lo_dword_addr == 0xffffffff ||
	    cfh_ul->hdr.lo_dword_addr == 0) {
		printf("%s(%d): invalid lo_dword_addr\n", __func__, rid);
		goto destroy;
	}

	/* Get pkt from cfhul */
	if (cfh_ul->fpkt == 1) {	/* first packet */
		pkt_addr = PHYS_TO_VIRT(cfh_ul->hdr.lo_dword_addr);
#ifdef ENABLE_PKT_DATA_STATUS
		{
			struct pkt_data *pkt_data;

			pkt_data = (struct pkt_data *)
				(pkt_addr - PKT_DATA_HEADROOM -
				 radio->pkt_ctrl.pkt_buf_headroom);
			if (pkt_data->signature != PKT_DATA_SIGNATURE)
				printf("\t %s(%d): packet corrupt: %p %p %08x %08x\n", __func__, radio->rid, pkt_addr, pkt_data, cfh_ul->hdr.lo_dword_addr, pkt_data->signature);
			if (pkt_data->status != PKT_DATA_FW_ASSIGNED)
				printf("\t Receive packet data is not owned by FW: %d %d %p %08x\n", radio->rid, pkt_data->status, pkt_data, pkt_data->signature);
			pkt_data->status = PKT_DATA_ALLOC;
		}
#endif

#ifdef LINUX_PE_SIM
		aligned_offset =
			((ca_uint64_t) (pkt_addr - PKT_INFO_SIZE) & 0x3);
#else
		aligned_offset =
			((ca_uint32_t) (pkt_addr - PKT_INFO_SIZE) & 0x3);
#endif

#if defined(ENABLE_PKT_SIGNATURE) || defined(ENABLE_SIGNATURE_CHECK_DATA)
		if (*
		    ((ca_uint32_t *) (pkt_addr - PKT_INFO_SIZE -
				      aligned_offset)) != PKT_SIGNATURE) {
			printf("%s(%d): invalid signature %08x\n", __func__,
			       rid,
			       *((ca_uint32_t *) (pkt_addr - PKT_INFO_SIZE -
						  aligned_offset)));
			goto destroy;
		} else
#endif
		{
			pkt = *(struct pkt_hdr **)
				(pkt_addr - PKT_POINTER_OFFSET -
				 aligned_offset);
		}
		if (pe->pkt) {
			pe->pkt->is_rx_amsdu_hold = false;
			if (!pe->pkt->clone_list.cnt) {
				if ((pkt->data_type == PKT_DATA_FROM_BM) &&
				    (pkt->qid == 10))
					radio->dbg_cnt.rel_cnt.
						bm10_return_non_clone++;
				pkt_free_data(rid, pe->pkt, __func__);
			}
		}
		pkt->is_rx_amsdu_hold = true;
		pe->pkt = pkt;
		reset_signature(pkt_addr);
		if ((pkt->data_type == PKT_DATA_FROM_BM) && (pkt->qid == 10))
			radio->dbg_cnt.rel_cnt.bm10_poll++;
#ifdef DBG_BM_BUF_MONITOR
		dbg_check_buf(rid, pkt, __func__);
#endif

	} else
		pkt = pe->pkt;

	if (!pkt) {
		printf("%s(%d): packet is NULL\n", __func__, rid);
		goto destroy;
	}

	/* wlGetCfhUl() already do the checking. keep here in Z1 stage for
	 * memory corrupt checking.
	 */
	if (cfh_ul->hdr.length > wlqm->rq.bm.buf_size) {
		printf("%s(%d): space is not enough %d\n", __func__, rid,
		       cfh_ul->hdr.length);
		goto destroy;
	}

	pkt_c = pkt_clone_bm_data(rid, pkt);
	if (!pkt_c) {
		printf("%s(%d): fail to clone packet\n", __func__, rid);
		goto destroy;
	}

	pkt_c->data = (ca_uint8_t *) PHYS_TO_VIRT(cfh_ul->hdr.lo_dword_addr);
	pkt_c->len = 0;

	if (rx_qid == radio->rx_q_data) {
		/* for Z2, sfw already added 14bytes to hdr.length  
		 * CFH length does not include 14bytes 802.3 hdr. Add here and will
		 * remove in decap logic (only for Z1)
		 */
		if ((radio->chip_revision == REV_Z1) && (radio->devid == SC5))
			cfh_ul->hdr.length += ETH_HLEN;
	} else {
		printf("%s(%d): unknown qid %d\n", __func__, rid, rx_qid);
		goto destroy;
	}

	/* Make sure the skb_c->data is valid */
	if ((pkt_c->data - pkt->data) >
	    radio->bm_buf_size[cfh_ul->hdr.bpid - radio->bm_q_start]) {
		printf("%s(%d): clone data has problem %llu\n", __func__,
		       rid, (ca_uint64_t) (pkt_c->data - pkt->data));
		goto destroy;
	}

	if (pkt_c->buf_ptr > pkt_c->data) {
		printf("%s(%d): clone data has problem %p %p\n", __func__,
		       rid, pkt_c->buf_ptr, pkt_c->data);
		goto destroy;
	}

	pkt_c->len += cfh_ul->hdr.length;

	if (cfh_ul->lpkt == 1) {
		if (pe->pkt) {
			pe->pkt->is_rx_amsdu_hold = false;
			if (!pe->pkt->clone_list.cnt)
				pkt_free_data(rid, pe->pkt, __func__);
		}
		pe->pkt = NULL;
	}

	return pkt_c;

destroy:

	return NULL;
}

/*   Data format: ethernet packet
 *               [DA:6][SA:6][type:2][IP:20]...
 */
static inline void
wlInitCFHDL(int rid, wltxdesc_t * cfg, struct pkt_hdr *pkt)
{
	struct radio *radio = &radio_info[rid - 1];
#ifdef CORTINA_TUNE_HW_CPY
	ca_uint8_t *pkt_data = tx_buff_now;
	ca_uint8_t *tmp;
	wltxdesc_t *txcfg;
	struct wldesc_data *wlqm;
#else
	ca_uint8_t da_id = 0;

	memset(cfg, 0, sizeof(*cfg));
#endif

	cfg->hdr.length = pkt->len - (ETH_HLEN);
	if (cfg->hdr.length < TXDESC_IPHDR_SIZE)
		cfg->hdr.length = TXDESC_IPHDR_SIZE;
	cfg->hdr.timestamp = JIFFIES;
	cfg->hdr.lo_dword_addr =
		(ca_uint32_t) VIRT_TO_PHYS(pkt->data + ETH_HLEN);
	cfg->qid = pkt->priority;

	/* mail from Richard Chung on Sat 3/4/2017 8:20 AM:
	 * DA MAC address is 00:11:22:33:44:55
	 * Using your example:
	 *
	 * DA0=0x1100
	 * DA1=0x55443322
	 * SA0=0x33221100
	 * SA1=0x5544
	 */
#ifdef CORTINA_TUNE_HW_CPY
	/*
	   #replace the following code
	   cfg->da0 = *(ca_uint16_t *)(&pkt_data[da_id]);

	   tmp = &cfg->da1;
	   tmp[0] = pkt_data[2];
	   tmp[1] = pkt_data[3];
	   tmp[2] = pkt_data[4];
	   tmp[3] = pkt_data[5];

	   cfg->sa0 = (*(ca_uint32_t *)(&pkt_data[da_id + 4]) >> 16)
	   + (*(ca_uint32_t *)(&pkt_data[da_id + 8]) << 16);
	   cfg->sa1 = (*(ca_uint32_t *)(&pkt_data[da_id + 8]) >> 16);
	 */
	tmp = (ca_uint8_t *) & cfg->da1;
	memcpy(tmp - 2, &pkt_data[0], ETH_ALEN * 2);

	wlqm = &radio->desc_data[radio->tx_q_start];
	txcfg = (wltxdesc_t *) (wlqm->rq.virt_addr +
				wlqm->rq.wrinx * sizeof(wltxdesc_t));
	ca_dma_async_copy(HW_DMA_COPY_WIFI_TX,
			  VIRT_TO_PHYS(txcfg),
			  (ca_uint8_t *) FAST_MEM_WIFI_TX_DESC_PA,
			  sizeof(wltxdesc_t) - TXDESC_IPHDR_SIZE);
	ca_dma_async_copy(HW_DMA_COPY_WIFI_TX_HDR,
			  VIRT_TO_PHYS(&txcfg->ip_hdr),
			  VIRT_TO_PHYS(&pkt_data[ETH_HLEN]), TXDESC_IPHDR_SIZE);
#else
	cfg->hdr.hi_byte_addr = radio->smac_buf_hi_addr;
	cfg->hdr.bpid = radio->tx_q_start;
	cfg->hdr.cfh_length = sizeof(wltxdesc_t);
	cfg->mpdu_flag = 0;
	cfg->ndr = 1;
	cfg->vtv = 0;
	cfg->llt = 7;
	cfg->len_ovr = 0;
	cfg->mpdu_frame_ctrl = 0x40c5;

	cfg->da0 = *(ca_uint16_t *) (&pkt->data[da_id]);
	cfg->da1 = (*(ca_uint32_t *) (&pkt->data[da_id]) >> 16)
		+ (*(ca_uint32_t *) (&pkt->data[da_id + 4]) << 16);
	cfg->sa0 = (*(ca_uint32_t *) (&pkt->data[da_id + 4]) >> 16)
		+ (*(ca_uint32_t *) (&pkt->data[da_id + 8]) << 16);
	cfg->sa1 = (*(ca_uint32_t *) (&pkt->data[da_id + 8]) >> 16);

	cfg->mpdu_ht_a_ctrl = *(ca_uint32_t *) & pkt->cb[16];
	cfg->snap1 = *(ca_uint32_t *) & pkt->cb[16 + 4];

	if (cfg->hdr.length < TXDESC_IPHDR_SIZE) {
		memcpy(&cfg->ip_hdr, &pkt->data[ETH_HLEN], cfg->hdr.length);
		cfg->hdr.length = TXDESC_IPHDR_SIZE;
	} else
		memcpy(&cfg->ip_hdr, &pkt->data[ETH_HLEN], TXDESC_IPHDR_SIZE);
#endif
}

static inline wltxdesc_t *
wlPktToCfhDl(int rid, struct pkt_hdr *pkt, wltxdesc_t * txcfg,
	     int qid, int type)
{
	struct radio *radio = &radio_info[rid - 1];
	struct wldesc_data *wlqm;
	wltxdesc_t *txdesc = NULL;
	ca_uint32_t aligned_offset;
	const char eapol_llc_snap[8] =
		{ 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e };

	/* remove ethernet header and add LLC(for MMDU case) */
	if (type == IEEE_TYPE_DATA) {
		if (pkt->sta_info) {
			pkt->sta_info->active_notify = true;
			pkt->sta_info->tx_bytes += pkt->len;
		}
		pkt->len -= ETH_HLEN;
		pkt->data += ETH_HLEN;

		if (txcfg->mpdu_flag) {
			pkt->len += 8;
			pkt->data -= 8;
			memcpy(pkt->data, &eapol_llc_snap[0], 8);
			txcfg->hdr.length += 8;
		}
	}
	wlqm = &radio->desc_data[qid];

	if (!wlRQFull(rid, qid)) {
		txdesc = (wltxdesc_t *) (wlqm->rq.virt_addr +
					 wlqm->rq.wrinx * sizeof(wltxdesc_t));
#ifdef CORTINA_TUNE_HW_CPY
		if (pkt->data_type == PKT_DATA_FROM_HOST)
#endif
			memcpy(txdesc, txcfg, sizeof(wltxdesc_t));

		if (!ADDR_ALIGNED((long)pkt->data, TXBUF_ALIGN)) {
			if (((radio->devid == SC5) &&
			     ((radio->chip_revision == REV_Z1) ||
			      (radio->chip_revision == REV_Z2)))) {
				/* must be aligned for SC5 Z1 or Z2,
				 * this job will be done by host driver if
				 * packet is from host.
				 */
				printf("%s(%d): data address is not aligned %p\n", __func__, rid, pkt->data);
			}
		}

		{
			ca_uint32_t max_tx_pend_cnt;
			ca_uint32_t stn_id;

			radio->except_cnt.txq_pend_cnt[txcfg->qid] =
				radio->except_cnt.txq_send_cnt[txcfg->qid] -
				radio->except_cnt.txq_rel_cnt[txcfg->qid];

			if (txcfg->qid < QUEUE_STAOFFSET) {
				if ((txcfg->qid % SYSADPT_MAX_TID) >= 6)
					max_tx_pend_cnt =
						SYSADPT_MAX_TX_PEND_CNT_PER_MGMT_Q;
				else
					max_tx_pend_cnt =
						SYSADPT_MAX_TX_PEND_CNT_PER_BCAST_Q;

				if (radio->except_cnt.
				    txq_pend_cnt[txcfg->qid] >=
				    max_tx_pend_cnt) {
					radio->except_cnt.txq_drop_cnt[txcfg->
								       qid]++;
					goto drop_tx_pkt;
				}
			} else {
				max_tx_pend_cnt = SYSADPT_MAX_TX_PEND_CNT_PER_Q;

				stn_id = (txcfg->qid -
					  QUEUE_STAOFFSET) / SYSADPT_MAX_TID;
				radio->except_cnt.tx_sta_pend_cnt[stn_id] =
					radio->except_cnt.
					tx_sta_send_cnt[stn_id] -
					radio->except_cnt.
					tx_sta_rel_cnt[stn_id];

				if ((radio->except_cnt.
				     txq_pend_cnt[txcfg->qid] >=
				     max_tx_pend_cnt) ||
				    (radio->except_cnt.
				     tx_sta_pend_cnt[stn_id] >=
				     SYSADPT_MAX_TX_PEND_CNT_PER_STA)) {
					radio->except_cnt.txq_drop_cnt[txcfg->
								       qid]++;
					radio->except_cnt.
						tx_sta_drop_cnt[stn_id]++;
					goto drop_tx_pkt;
				}
			}
		}
#ifdef LINUX_PE_SIM
		aligned_offset =
			((ca_uint64_t) (pkt->data - PKT_INFO_SIZE) & 0x3);
#else
		aligned_offset =
			((ca_uint32_t) (pkt->data - PKT_INFO_SIZE) & 0x3);
#endif
#if defined(ENABLE_PKT_SIGNATURE) || defined(ENABLE_SIGNATURE_CHECK_DATA)
		*((ca_uint32_t *) (pkt->data - PKT_INFO_SIZE -
				   aligned_offset)) = PKT_SIGNATURE;
#endif
		*(struct pkt_hdr **)(pkt->data - PKT_POINTER_OFFSET -
				     aligned_offset) = pkt;
#ifdef LINUX_PE_SIM
		txdesc->hdr.lo_dword_addr =
			dma_map_single(radio->dev, pkt->data, pkt->len,
				       DMA_TO_DEVICE);
#else
#ifdef CORTINA_TUNE_HW_CPY
		if (pkt->data_type == PKT_DATA_FROM_HOST)
#endif
			txdesc->hdr.lo_dword_addr =
				(ca_uint32_t) VIRT_TO_PHYS(pkt->data);
#endif
		if (wlRQIndexPut(&wlqm->rq)) {
			if (radio->dbg_ctrl & DBG_TX_MGMT_TIMESTAMP) {
				ca_uint16_t frm_ctrl_data =
					txdesc->mpdu_frame_ctrl;
				IEEEtypes_FrameCtl_t *frm_ctrl =
					(IEEEtypes_FrameCtl_t *) &
					frm_ctrl_data;

				if ((frm_ctrl->Subtype == IEEE_MSG_AUTHENTICATE)
				    || (frm_ctrl->Subtype ==
					IEEE_MSG_ASSOCIATE_RSP) ||
				    (frm_ctrl->Subtype ==
				     IEEE_MSG_REASSOCIATE_RSP)) {
					printf("PE->Mgmt(%x): BBTX_TMR_FREE_TSF=0x%08x, BBTX_TMR_FREE_TSF_HI=0x%08x\n", frm_ctrl->Subtype, read32(radio->iobase1 + BBTX_TMR_FREE_TSF), read32(radio->iobase1 + BBTX_TMR_FREE_TSF_HI));
				}
			}
#ifdef CORTINA_TUNE_HW_CPY
			if (pkt->data_type != PKT_DATA_FROM_HOST) {
				ca_dma_poll_for_complete(HW_DMA_COPY_WIFI_TX);
				ca_dma_poll_for_complete
					(HW_DMA_COPY_WIFI_TX_HDR);
			}
			/*to test more!! */
			//if (tx_next_pkt == NULL)
			wlUpdateWrPtr(rid, qid, SC5_RQ, wlqm->rq.wrinx);
#else
			wlUpdateWrPtr(rid, qid, SC5_RQ, wlqm->rq.wrinx);
#endif
			if (pkt->vif_info) {
				pkt->vif_info->netdev_stats.tx_packets++;
				pkt->vif_info->netdev_stats.tx_bytes +=
					pkt->len;
			}
			radio->dbg_cnt.tx_cnt.tx_queue_send++;
			radio->except_cnt.txq_send_cnt[txcfg->qid]++;

			if (txcfg->qid < QUEUE_STAOFFSET) {
				if ((txcfg->qid % SYSADPT_MAX_TID) >= 6)
					radio->except_cnt.tx_mgmt_send_cnt++;
				else
					radio->except_cnt.tx_bcast_send_cnt++;
			} else {
				ca_uint32_t stn_id;

				stn_id = (txcfg->qid -
					  QUEUE_STAOFFSET) / SYSADPT_MAX_TID;
				radio->except_cnt.tx_sta_send_cnt[stn_id]++;
			}
			radio->drv_stats_val.txq_drv_sent_cnt++;
		} else {
			radio->dbg_cnt.tx_cnt.tx_queue_full++;
			goto drop_tx_pkt;
		}
	} else {
		radio->dbg_cnt.tx_cnt.tx_queue_full++;
		goto drop_tx_pkt;
	}

	radio->fw_desc_cnt++;

	return txdesc;

drop_tx_pkt:

	pkt_free_data(rid, pkt, __func__);
	if (pkt->vif_info)
		pkt->vif_info->netdev_stats.tx_dropped++;
	return NULL;
}

static inline bm_pe_hw_t *
wlGetRelBufPe(int rid, int qid)
{
	struct radio *radio = &radio_info[rid - 1];
	struct wldesc_data *wlqm;
	bm_pe_hw_t *pe_hw_src;
	ca_uint8_t bpid;
	bool invalid_pe = false;

	wlqm = &radio->desc_data[qid];
	pe_hw_src = (bm_pe_hw_t *)
		(wlqm->sq.virt_addr + wlqm->sq.rdinx * sizeof(bm_pe_hw_t));
#ifdef CORTINA_TUNE_HW_CPY
	int delta_i = 0;
	if (tx_buff_now == NULL) {
		if (wlqm->sq.rdinx < wlqm->sq.wrinx)
			delta_i = wlqm->sq.wrinx - wlqm->sq.rdinx;
		else
			delta_i = wlqm->sq.qsize - wlqm->sq.rdinx;

		ca_dma_sync_copy(HW_DMA_COPY_WIFI_DONE,
				 (ca_uint8_t *) FAST_MEM_WIFI_TX_DONE_ARRAY_PA,
				 VIRT_TO_PHYS(pe_hw_src), sizeof(bm_pe_hw_t));

		if (delta_i > 1) {
			/*
			 * DMA_LSO max copy length is 4096
			 */
			if (delta_i > 257) {
				delta_i = 257;
			}
			ca_dma_async_copy(HW_DMA_COPY_WIFI_DONE,
					  (ca_uint8_t *)
					  FAST_MEM_WIFI_TX_DONE_ARRAY_PA +
					  sizeof(bm_pe_hw_t),
					  VIRT_TO_PHYS(pe_hw_src) +
					  sizeof(bm_pe_hw_t),
					  sizeof(bm_pe_hw_t) * (delta_i - 1));
		}
		tx_buff_now = FAST_MEM_WIFI_TX_DONE_ARRAY;
		tx_buff_next =
			FAST_MEM_WIFI_TX_DONE_ARRAY +
			sizeof(bm_pe_hw_t) * (delta_i - 1);
	} else {
		tx_buff_now = tx_buff_now + sizeof(bm_pe_hw_t);
	}

#ifdef ENABLE_SIGNATURE_CHECK_DATA
	/* Put the signature to show that this buffer is clean */
	pe_hw_src->bgn_signature = pe_hw_src->end_signature = BMBUF_SIGNATURE;
#endif
	pe_hw_src = (bm_pe_hw_t *) tx_buff_now;
	if (tx_buff_now == tx_buff_next) {
		tx_buff_now = NULL;
		if (delta_i == 0)
			ca_dma_poll_for_complete(HW_DMA_COPY_WIFI_DONE);
	}
#endif

	bpid = REL_RX_BPID(pe_hw_src->bpid);

#ifdef ENABLE_SIGNATURE_CHECK_DATA
	/* Incorrect pe_hw conditions:
	 *  1. Signature is BMBUF_SIGNATURE => the pe_hw hasn't been updated
	 *  2. lo_dowrd == 0 or 0xffffffff
	 *  3. bpid is incorrect (not in:
	 *     [SC5_TXQ_START_INDEX ~ SC5_TXQ_START_INDEX+SC5_TXQ_NUM] &&
	 *     [SC5_BMQ_START_INDEX ~ SC5_BMQ_START_INDEX+SC5_BMQ_NUM]
	 */
	if ((pe_hw_src->bgn_signature == BMBUF_SIGNATURE) ||
	    (pe_hw_src->end_signature == BMBUF_SIGNATURE)) {
		radio->dbg_cnt.rel_cnt.pe_hw_sig_err++;
		invalid_pe = true;
	}
#endif
#if defined(ENABLE_PKT_SIGNATURE) || defined(ENABLE_SIGNATURE_CHECK_DATA)
	if (!pe_hw_src->pe0_lo_dword_addr) {
		printf("%s (%d): pe0_lo_dword_addr NULL\n", __func__, __LINE__);
		radio->dbg_cnt.rel_cnt.pe_hw_phy_addr_err++;
		invalid_pe = true;
	}
	if (pe_hw_src->pe0_lo_dword_addr == 0xffffffff) {
		printf("%s (%d): pe0_lo_dword_addr 0xffffffff\n", __func__,
		       __LINE__);
		radio->dbg_cnt.rel_cnt.pe_hw_phy_addr_err++;
		invalid_pe = true;
	}
#endif

	/* BMQ 13 should be returned to host driver */
	if (!(((radio->tx_q_start <= bpid) &&
	       (bpid < (radio->tx_q_start + radio->tx_q_num)))
	      || ((radio->bm_q_start <= bpid) &&
		  (bpid <= (radio->bm_q_start + radio->bm_q_num))))) {
		radio->dbg_cnt.rel_cnt.pe_hw_bpid_err++;
		invalid_pe = true;
	}

	if (invalid_pe)
		pe_hw_src = NULL;

	/* advance the rd index */
	wlqm->sq.rdinx = (wlqm->sq.rdinx + 1) % wlqm->sq.qsize;

	return pe_hw_src;
}

/* caller pass buffer pool elelent, and based on the phys address to find
 * the corresponding pkt and return
 */
static inline struct pkt_hdr *
wlPeToPkt(int rid, bm_pe_hw_t * pe_hw)
{
	struct radio *radio = &radio_info[rid - 1];
	struct pkt_hdr *pkt = NULL;
	unsigned char *pkt_virt;
	struct wldesc_data *wlqm;
	ca_uint8_t bpid = 0;
	ca_uint32_t aligned_offset;
	bm_pe_hw_t *pe_hw_ptr;

	pe_hw_ptr = pe_hw;

	/* bpid == 14 (ReleaseQ) for tx-done
	 * or SC5_BMQ_START_INDEX ~ (SC5_BMQ_START_INDEX + SC5_BMQ_NUM - 1)
	 * for rx-drop
	 */
	bpid = REL_RX_BPID(pe_hw_ptr->bpid);
	wlqm = &radio->desc_data[bpid];

	pkt_virt = (unsigned char *)PHYS_TO_VIRT(pe_hw_ptr->pe0_lo_dword_addr);
#ifdef LINUX_PE_SIM
	aligned_offset = ((ca_uint64_t) (pkt_virt - PKT_INFO_SIZE) & 0x3);
#else
	aligned_offset = ((ca_uint32_t) (pkt_virt - PKT_INFO_SIZE) & 0x3);
#endif
#if defined(ENABLE_PKT_SIGNATURE) || defined(ENABLE_SIGNATURE_CHECK_DATA)
	{
		ca_uint32_t signature;

		signature =
			*((ca_uint32_t *) (pkt_virt - PKT_INFO_SIZE -
					   aligned_offset));
		if (signature == PKT_SIGNATURE) {
			pkt = *(struct pkt_hdr **)(pkt_virt -
						   PKT_POINTER_OFFSET -
						   aligned_offset);
			/* Destroy the signature */
			reset_signature(pkt_virt);
		} else {
			printf("%s(%d): signature error: %08x\n", __func__, rid,
			       signature);
			radio->dbg_cnt.rel_cnt.pe_hw_pkt_sig_err++;
			return NULL;
		}
	}
#else
	pkt = *(struct pkt_hdr **)(pkt_virt - PKT_POINTER_OFFSET -
				   aligned_offset);
#endif

	if (pkt->data_type == PKT_DATA_FROM_BM) {
#ifdef LINUX_PE_SIM
		dma_unmap_single(radio->dev, pe_hw_ptr->pe0_lo_dword_addr,
				 pkt->buf_size, DMA_FROM_DEVICE);
#endif
		/* RX drop packets */
		pkt->data = pkt_virt;
		if (pkt->next && pkt->prev)
			reset_signature(pkt_virt);

#ifdef DBG_BM_BUF_MONITOR
		dbg_check_buf(rid, pkt, __func__);
#endif

#ifdef ENABLE_PKT_DATA_STATUS
		{
			struct pkt_data *pkt_data;

			pkt_data = (struct pkt_data *)
				(pkt->buf_ptr - PKT_DATA_HEADROOM);
			if (pkt_data->status != PKT_DATA_FW_ASSIGNED)
				printf("\t Free packet data is not owned by FW: %d %d %p %08x\n", radio->rid, pkt_data->status, pkt_data, pkt_data->signature);
			pkt_data->status = PKT_DATA_ALLOC;
		}
#endif

		/* Free the rx dropped packets */
		pkt_free_data(rid, pkt, __func__);
#ifndef CORTINA_TUNE_HW_CPY
		/* Put the signature to show that this buffer is clean */
		pe_hw->bgn_signature = pe_hw->end_signature = BMBUF_SIGNATURE;
#endif
		radio->dbg_cnt.rel_cnt.bmq_release[bpid - radio->bm_q_start]++;

		return NULL;
	}
#ifdef LINUX_PE_SIM
	dma_unmap_single(radio->dev, pe_hw_ptr->pe0_lo_dword_addr,
			 pkt->len, DMA_TO_DEVICE);
#endif
#ifndef CORTINA_TUNE_HW_CPY
	/* Put the signature to show that this buffer is clean */
	pe_hw->bgn_signature = pe_hw->end_signature = BMBUF_SIGNATURE;
#endif
	radio->dbg_cnt.rel_cnt.tx_release++;

	return pkt;
}

#endif /* __BQM_INLINE_H__ */
