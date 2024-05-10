/** @file BQM.c
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

#include "radio.h"

static int
BQM_rx_queue_init(struct radio *radio, int qid)
{
	struct wldesc_data *wlqm;
	ca_uint32_t smac_buf_hi_addr = radio->smac_buf_hi_addr;
	wlrxdesc_t *cfh_ul;
	int i;

	wlqm = &radio->desc_data[qid];
	wlqm->id = qid;
	wlqm->sq.qsize = radio->rx_q_size;
#ifdef LINUX_PE_SIM
	wlqm->sq.virt_addr = (void *)
		dma_alloc_coherent(radio->dev,
				   wlqm->sq.qsize * sizeof(wlrxdesc_t),
				   &wlqm->sq.phys_addr, GFP_KERNEL);
#else
	wlqm->sq.virt_addr = MALLOC(wlqm->sq.qsize * sizeof(wlrxdesc_t));
#endif
	if (!wlqm->sq.virt_addr) {
		printf("%s(%d): fail to alloc memory\n", __func__, radio->rid);
		return -ENOMEM;
	}
#ifndef LINUX_PE_SIM
	wlqm->sq.phys_addr = (ca_uint32_t) VIRT_TO_PHYS(wlqm->sq.virt_addr);
#endif

	for (i = 0, cfh_ul = (wlrxdesc_t *) wlqm->sq.virt_addr;
	     i < wlqm->sq.qsize; cfh_ul++, i++) {
		cfh_ul->nss_hdr[2] = HF_OWN_SIGNATURE;
		cfh_ul->hdr.length = USED_BUFLEN;
	}

	wlqm->sq.rdinx = 0;
	wlqm->sq.wrinx = 0;
	/* set CFH-UL descruptor queue size and start address. */
	write32((ca_uint32_t) wlqm->sq.phys_addr,
		(radio->iobase1 + SC5_Q_BASE_ADDR_REG(qid, SC5_SQ)));
	/* high address */
	write32(smac_buf_hi_addr,
		(radio->iobase1 + SC5_Q_BASE_ADDR_REG(qid, SC5_SQ) + 4));
	write32(((wlqm->sq.qsize * sizeof(wlrxdesc_t)) / 128) << 3,
		(radio->iobase1 + SC5_Q_SIZE_REG(qid, SC5_SQ)));

	return 0;
}

static void
BQM_rx_queue_cleanup(struct radio *radio)
{
	struct wldesc_data *wlqm;
	int qid;

	for (qid = 0; qid < SYSADPT_NUM_OF_HW_DESC_DATA; qid++) {
		if (qid == radio->rx_q_data) {
			wlqm = &radio->desc_data[qid];

			if (wlqm->sq.virt_addr) {
#ifdef LINUX_PE_SIM
				dma_free_coherent(radio->dev,
						  wlqm->sq.qsize *
						  sizeof(wlrxdesc_t),
						  wlqm->sq.virt_addr,
						  wlqm->sq.phys_addr);
#else
				MFREE(wlqm->sq.virt_addr);
#endif
				wlqm->sq.virt_addr = NULL;
			}
			/* reset descriptor queue size. */
			wlqm->sq.qsize = 0;
			write32(wlqm->sq.qsize,
				(radio->iobase1 + SC5_Q_SIZE_REG(qid, SC5_SQ)));
		}
	}
}

static int
BQM_tx_queue_init(struct radio *radio, int qid)
{
	struct wldesc_data *wlqm;
	ca_uint32_t smac_buf_hi_addr = radio->smac_buf_hi_addr;

	wlqm = &radio->desc_data[qid];
	wlqm->id = qid;
	wlqm->rq.qsize = radio->tx_q_size[qid - radio->tx_q_start];
#ifdef LINUX_PE_SIM
	wlqm->rq.virt_addr = (void *)
		dma_alloc_coherent(radio->dev,
				   wlqm->rq.qsize * sizeof(wltxdesc_t),
				   &wlqm->rq.phys_addr, GFP_KERNEL);
#else
	wlqm->rq.virt_addr = MALLOC(wlqm->rq.qsize * sizeof(wltxdesc_t));
#endif
	if (!wlqm->rq.virt_addr) {
		printf("%s(%d): fail to alloc memory\n", __func__, radio->rid);
		return -ENOMEM;
	}
#ifndef LINUX_PE_SIM
	wlqm->rq.phys_addr = (ca_uint32_t) VIRT_TO_PHYS(wlqm->rq.virt_addr);
#endif

	wlqm->rq.rdinx = 0;
	wlqm->rq.wrinx = 0;

	/* set CFH-DL descruptor queue size and start address. */
	write32((ca_uint32_t) wlqm->rq.phys_addr,
		(radio->iobase1 + SC5_Q_BASE_ADDR_REG(qid, SC5_RQ)));
	/* high address */
	write32(smac_buf_hi_addr,
		(radio->iobase1 + SC5_Q_BASE_ADDR_REG(qid, SC5_RQ)) + 4);
	write32(((wlqm->rq.qsize * sizeof(wltxdesc_t)) / 128) << 3,
		(radio->iobase1 + SC5_Q_SIZE_REG(qid, SC5_RQ)));

	return 0;
}

static void
BQM_tx_queue_cleanup(struct radio *radio)
{
	struct wldesc_data *wlqm;
	int qid;

	for (qid = radio->tx_q_start; qid < radio->tx_q_start + radio->tx_q_num;
	     qid++) {
		wlqm = &radio->desc_data[qid];

		if (wlqm->rq.virt_addr) {
#ifdef LINUX_PE_SIM
			dma_free_coherent(radio->dev,
					  wlqm->rq.qsize * sizeof(wltxdesc_t),
					  wlqm->rq.virt_addr,
					  wlqm->rq.phys_addr);
#else
			MFREE(wlqm->rq.virt_addr);
#endif
			wlqm->rq.virt_addr = NULL;
		}
		/* reset descruptor queue size. */
		wlqm->rq.qsize = 0;
		write32(wlqm->rq.qsize,
			(radio->iobase1 + SC5_Q_SIZE_REG(qid, SC5_RQ)));
	}
}

static int
BQM_buf_rel_queue_init(struct radio *radio, int qid)
{
	struct wldesc_data *wlqm;
	ca_uint32_t smac_buf_hi_addr = radio->smac_buf_hi_addr;
	bm_pe_hw_t *pehw;
	int i;

	wlqm = &radio->desc_data[qid];
	wlqm->id = qid;
	wlqm->sq.qsize = radio->rel_q_size[qid - radio->rel_q_start];
#ifdef LINUX_PE_SIM
	wlqm->sq.virt_addr = (void *)
		dma_alloc_coherent(radio->dev,
				   wlqm->sq.qsize * sizeof(bm_pe_hw_t),
				   &wlqm->sq.phys_addr, GFP_KERNEL);
#else
	wlqm->sq.virt_addr = MALLOC(wlqm->sq.qsize * sizeof(bm_pe_hw_t));
#endif
	if (!wlqm->sq.virt_addr) {
		printf("%s(%d): fail to alloc memory\n", __func__, radio->rid);
		return -ENOMEM;
	}
#ifndef LINUX_PE_SIM
	wlqm->sq.phys_addr = (ca_uint32_t) VIRT_TO_PHYS(wlqm->sq.virt_addr);
#endif

	/* Init the signature to the buffer desc */
	for (i = 0, pehw = (bm_pe_hw_t *) wlqm->sq.virt_addr;
	     i < wlqm->sq.qsize; i++, pehw++)
		pehw->bgn_signature = pehw->end_signature = BMBUF_SIGNATURE;

	wlqm->sq.rdinx = 0;
	wlqm->sq.wrinx = 0;

	/* set Release buffer descruptor queue size and start address. */
	write32(wlqm->sq.phys_addr,
		(radio->iobase1 + SC5_Q_BASE_ADDR_REG(qid, SC5_SQ)));
	/* high address */
	write32(smac_buf_hi_addr,
		(radio->iobase1 + SC5_Q_BASE_ADDR_REG(qid, SC5_SQ) + 4));
	write32(((wlqm->sq.qsize * sizeof(bm_pe_hw_t)) / 128) << 3,
		(radio->iobase1 + SC5_Q_SIZE_REG(qid, SC5_SQ)));

	/* set TX DONE interrupt threshold and timeout */
	write32(SC5_TXDONE_INT_THRESHOLD,
		(radio->iobase1 + SC5_Q_THRES_REG(qid, SC5_SQ)));
	printf("BMQ(%d),w_reg(iobase1+%xh) = %xh\n", qid,
	       SC5_Q_THRES_REG(qid, SC5_SQ),
	       read32(radio->iobase1 + SC5_Q_THRES_REG(qid, SC5_SQ)));

	write32(SQ5_MAC_CTRL_TIMEOUT(SC5_TXDONE_INT_TIMEOUT),
		(radio->iobase1 + SC5_Q_MAC_CTRL_REG(qid, SC5_SQ)));
	printf("BMQ(%d),w_reg(iobase1+%xh) = %xh\n", qid,
	       SC5_Q_MAC_CTRL_REG(qid, SC5_SQ),
	       read32(radio->iobase1 + SC5_Q_MAC_CTRL_REG(qid, SC5_SQ)));

	return 0;
}

static void
BQM_buf_rel_queue_cleanup(struct radio *radio)
{
	struct wldesc_data *wlqm;
	int qid;

	for (qid = radio->rel_q_start;
	     qid < radio->rel_q_start + radio->rel_q_num; qid++) {
		wlqm = &radio->desc_data[qid];

		if (wlqm->sq.virt_addr) {
#ifdef LINUX_PE_SIM
			dma_free_coherent(radio->dev,
					  wlqm->sq.qsize * sizeof(bm_pe_hw_t),
					  wlqm->sq.virt_addr,
					  wlqm->sq.phys_addr);
#else
			MFREE(wlqm->sq.virt_addr);
#endif
			wlqm->sq.virt_addr = NULL;
		}
		/* reset descruptor queue size. */
		wlqm->sq.qsize = 0;
		write32(wlqm->sq.qsize,
			(radio->iobase1 + SC5_Q_SIZE_REG(qid, SC5_SQ)));
	}
}

static int
BQM_rx_buf_init(struct radio *radio, int qid)
{
	struct wldesc_data *wlqm;
	struct pkt_hdr *pkt = NULL;
	bm_pe_t *pe;
	bm_pe_hw_t *pe_hw;
	struct pkt_hdr **pkt_addr;
	int index, entry, size;
	ca_uint32_t aligned_offset;

	wlqm = &radio->desc_data[qid];
	index = qid - radio->bm_q_start;
	wlqm->rq.bm.buf_size = radio->bm_buf_size[index];
	size = wlqm->rq.bm.buf_size;

	pe = (bm_pe_t *) MALLOC_CACHE(2 * sizeof(bm_pe_t));
	if (!pe) {
		printf("%s(%d): fail to alloc memory\n", __func__, radio->rid);
		return -ENOMEM;
	}
	wlqm->rq.bm.pe = pe;
	pe_hw = (bm_pe_hw_t *) wlqm->rq.virt_addr;

	for (entry = 0; entry < wlqm->rq.qsize; entry++) {
		pkt = pkt_alloc_bm_data(radio->rid, qid);
		if (!pkt) {
			printf("%s(%d): fail to alloc pkt, qid: %d\n",
			       __func__, radio->rid, qid);
			MFREE(pe);
			return -ENOMEM;
		}
#ifdef ENABLE_PKT_DATA_STATUS
		{
			struct pkt_data *pkt_data;

			pkt_data = (struct pkt_data *)
				(pkt->buf_ptr - PKT_DATA_HEADROOM);
			if (pkt_data->status != PKT_DATA_ALLOC)
				printf("\t Packet data is not allocated: %d %d %p %08x\n", radio->rid, pkt_data->status, pkt_data, pkt_data->signature);
			pkt_data->status = PKT_DATA_FW_ASSIGNED;
		}
#endif
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
		pkt_addr =
			(struct pkt_hdr **)(pkt->data - PKT_POINTER_OFFSET -
					    aligned_offset);
		*pkt_addr = pkt;
#ifdef LINUX_PE_SIM
		pe_hw->pe0_lo_dword_addr = dma_map_single(radio->dev, pkt->data,
							  pkt->buf_size,
							  DMA_FROM_DEVICE);
#else
		pe_hw->pe0_lo_dword_addr =
			(ca_uint32_t) VIRT_TO_PHYS(pkt->data);
#endif
		pe_hw->pe0_hi_byte_addr = radio->smac_buf_hi_addr;
		pe_hw->bpid = qid;

		pe_hw++;
	}
	pe = (bm_pe_t *) (wlqm->rq.bm.pe + 0);
	pe->pkt = NULL;

	wlqm->rq.rdinx = 0;
	/* WAR for h/w error that:
	 * "an hw bug that it writes to last 16k block of 96M bootmem could
	 * spill 4 bytes over to the address next to it"
	 *      WAR: Save one buffer to h/w
	 */
	wlqm->rq.wrinx = wlqm->rq.qsize - 1;

	return 0;
}

static void
BQM_rx_buf_cleanup(struct radio *radio, int qid)
{
}

static int
BQM_bm_queue_init(struct radio *radio, int qid)
{
	struct wldesc_data *wlqm;
	ca_uint32_t smac_buf_hi_addr = radio->smac_buf_hi_addr;
	bm_pe_hw_t *pehw;
	int i;

	wlqm = &radio->desc_data[qid];
	wlqm->id = qid;
	wlqm->rq.qsize = radio->bm_q_size[qid - radio->bm_q_start];
#ifdef LINUX_PE_SIM
	wlqm->rq.virt_addr = (void *)
		dma_alloc_coherent(radio->dev,
				   wlqm->rq.qsize * sizeof(bm_pe_hw_t),
				   &wlqm->rq.phys_addr, GFP_KERNEL);
#else
	wlqm->rq.virt_addr = MALLOC(wlqm->rq.qsize * sizeof(bm_pe_hw_t));
#endif
	if (!wlqm->rq.virt_addr) {
		printf("%s(%d): fail to alloc memory\n", __func__, radio->rid);
		return -ENOMEM;
	}
#ifndef LINUX_PE_SIM
	wlqm->rq.phys_addr = (ca_uint32_t) VIRT_TO_PHYS(wlqm->rq.virt_addr);
#endif

	/* Init the signature to the buffer desc */
	for (i = 0, pehw = (bm_pe_hw_t *) wlqm->rq.virt_addr;
	     i < wlqm->rq.qsize; i++, pehw++)
		pehw->bgn_signature = pehw->end_signature = BMBUF_SIGNATURE;
	/* set BMQ descruptor queue size and start address. */
	write32((ca_uint32_t) wlqm->rq.phys_addr,
		(radio->iobase1 + SC5_Q_BASE_ADDR_REG(qid, SC5_RQ)));
	/* High address */
	write32(smac_buf_hi_addr,
		(radio->iobase1 + SC5_Q_BASE_ADDR_REG(qid, SC5_RQ) + 4));
	/* Mail from Jerry on 13th Feb 2017:
	 *     "The size of queue must align to 128 bytes...."
	 */
	write32(((wlqm->rq.qsize * sizeof(bm_pe_hw_t)) / 128) << 3,
		(radio->iobase1 + SC5_Q_SIZE_REG(qid, SC5_RQ)));

	/* update rdinx and wrinx in wlRxBufInit */
	BQM_rx_buf_init(radio, qid);

	return 0;
}

static void
BQM_bm_queue_cleanup(struct radio *radio)
{
	struct wldesc_data *wlqm;
	int qid;

	for (qid = radio->bm_q_start; qid < radio->bm_q_start + radio->bm_q_num;
	     qid++) {
		wlqm = &radio->desc_data[qid];
		BQM_rx_buf_cleanup(radio, qid);

		if (wlqm->rq.virt_addr) {
#ifdef LINUX_PE_SIM
			dma_free_coherent(radio->dev,
					  wlqm->rq.qsize * sizeof(bm_pe_hw_t),
					  wlqm->rq.virt_addr,
					  wlqm->rq.phys_addr);
#else
			MFREE(wlqm->rq.virt_addr);
#endif
			wlqm->rq.virt_addr = NULL;
		}

		if (wlqm->rq.bm.pe != NULL) {
			MFREE(wlqm->rq.bm.pe);
			wlqm->rq.bm.pe = NULL;
		}

		/* reset descruptor queue size. */
		wlqm->rq.qsize = 0;
		write32(wlqm->rq.qsize,
			(radio->iobase1 + SC5_Q_SIZE_REG(qid, SC5_RQ)));
	}
}

int
BQM_init(int rid)
{
	struct radio *radio = &radio_info[rid - 1];
	int qid, rc;

	for (qid = 0; qid < SYSADPT_NUM_OF_HW_DESC_DATA; qid++) {
		if (qid == radio->rx_q_data) {
			rc = BQM_rx_queue_init(radio, qid);
			if (rc) {
				BQM_rx_queue_cleanup(radio);
				return rc;
			}
		}
	}

	for (qid = radio->tx_q_start; qid < radio->tx_q_start + radio->tx_q_num;
	     qid++) {
		rc = BQM_tx_queue_init(radio, qid);
		if (rc) {
			BQM_rx_queue_cleanup(radio);
			BQM_tx_queue_cleanup(radio);
			return rc;
		}
	}

	for (qid = radio->bm_q_start; qid < radio->bm_q_start + radio->bm_q_num;
	     qid++) {
		rc = BQM_bm_queue_init(radio, qid);
		if (rc) {
			BQM_rx_queue_cleanup(radio);
			BQM_tx_queue_cleanup(radio);
			BQM_buf_rel_queue_cleanup(radio);
			BQM_bm_queue_cleanup(radio);
			return rc;
		}
	}

	for (qid = radio->rel_q_start;
	     qid < radio->rel_q_start + radio->rel_q_num; qid++) {
		rc = BQM_buf_rel_queue_init(radio, qid);
		if (rc) {
			BQM_rx_queue_cleanup(radio);
			BQM_tx_queue_cleanup(radio);
			BQM_buf_rel_queue_cleanup(radio);
			return rc;
		}
	}

	/* SQ0, Rx data pkt queue */
	printf("BMQ(%d),w_reg(iobase1+%xh) = %xh\n", 0,
	       SC5_Q_THRES_REG(0, SC5_SQ),
	       read32(radio->iobase1 + SC5_Q_THRES_REG(0, SC5_SQ)));
	printf("BMQ(%d),w_reg(iobase1+%xh) = %xh\n", 0,
	       SC5_Q_MAC_CTRL_REG(0, SC5_SQ),
	       read32(radio->iobase1 + SC5_Q_MAC_CTRL_REG(0, SC5_SQ)));

	return 0;
}

void
BQM_post_init_bq_idx(int rid)
{
	struct radio *radio = &radio_info[rid - 1];
	struct wldesc_data *wlqm;
	int qid;

	for (qid = radio->bm_q_start; qid < radio->bm_q_start + radio->bm_q_num;
	     qid++) {
		wlqm = &radio->desc_data[qid];
		wlqm->rq.rdinx = wlQueryRdPtr(rid, qid, SC5_RQ);
		wlUpdateWrPtr(rid, qid, SC5_RQ, wlqm->rq.wrinx);
	}

	for (qid = 0; qid < SYSADPT_NUM_OF_HW_DESC_DATA; qid++) {
		if (qid == radio->rx_q_data) {
			wlqm = &radio->desc_data[qid];
			wlUpdateRdPtr(rid, qid, SC5_SQ, wlqm->sq.rdinx);
			wlqm->sq.wrinx = wlQueryWrPtr(rid, qid, SC5_SQ);
		}
	}

	for (qid = radio->tx_q_start; qid < radio->tx_q_start + radio->tx_q_num;
	     qid++) {
		wlqm = &radio->desc_data[qid];
		wlqm->rq.rdinx = wlQueryRdPtr(rid, qid, SC5_RQ);
		wlUpdateWrPtr(rid, qid, SC5_RQ, wlqm->rq.wrinx);
	}

	for (qid = radio->rel_q_start;
	     qid < radio->rel_q_start + radio->rel_q_num; qid++) {
		wlqm = &radio->desc_data[qid];
		wlUpdateRdPtr(rid, qid, SC5_SQ, wlqm->sq.rdinx);
		wlqm->sq.wrinx = wlQueryWrPtr(rid, qid, SC5_SQ);
	}

	for (qid = radio->bm_q_start; qid < radio->bm_q_start + radio->bm_q_num;
	     qid++) {
		wlqm = &radio->desc_data[qid];
		wlqm->rq.rdinx = wlQueryRdPtr(rid, qid, SC5_RQ);
	}
}

void
BQM_deinit(int rid)
{
	struct radio *radio = &radio_info[rid - 1];

	BQM_rx_queue_cleanup(radio);
	BQM_tx_queue_cleanup(radio);
	BQM_buf_rel_queue_cleanup(radio);
	BQM_bm_queue_cleanup(radio);
}

int
htc_he_find_control_id(IEEEtypes_htcField_t * htc, u8 in_controlid)
{
	u8 control_id;
	int shift_bits = 0, left_bits = 30;	/* Acontrol has maximum 30bits */

	control_id = htc->he_variant.a_control & 0xf;

	while ((control_id != in_controlid) && (shift_bits < left_bits)) {

		switch (control_id) {
		case CONTROL_ID_UMRS:
			shift_bits += 30;
			left_bits -= 30;
			break;
		case CONTROL_ID_OM:
			shift_bits += 16;
			left_bits -= 16;
			break;
		case CONTROL_ID_HLA:
			shift_bits += 30;
			left_bits -= 30;
			break;
		case CONTROL_ID_BSR:
			shift_bits += 30;
			left_bits -= 30;
			break;
		case CONTROL_ID_UPH:
			shift_bits += 12;
			left_bits -= 12;
			break;
		case CONTROL_ID_BQR:
			shift_bits += 14;
			left_bits -= 14;
			break;
		case CONTROL_ID_CAS:
			shift_bits += 12;
			left_bits -= 12;
			break;
		default:
			return 0;
		}

		control_id = (htc->he_variant.a_control >> shift_bits) & 0xf;
	}

	if (control_id != in_controlid)
		return 0;
	else
		return shift_bits + 4;	/* also shift the 4 bit control ID */
}

int omi_event_to_host(struct radio *radio, ca_uint16_t om_control,
		      ca_uint16_t stnid, ca_uint8_t * mac);

int
omi_event_to_host(struct radio *radio, ca_uint16_t om_control,
		  ca_uint16_t stnid, ca_uint8_t * mac)
{
	struct dol_evt_omi_event dol_event;
	ca_ipc_pkt_t ipc_pkt;

	dol_event.evt.radio = radio->rid;
	dol_event.evt.event = DOL_EVT_OMI_CONTROL;

	dol_event.om_control = om_control;
	dol_event.stnid = stnid;
	memcpy(dol_event.sta_addr, mac, ETH_ALEN);

	ipc_pkt.session_id = SYSADPT_MSG_IPC_SESSION;
	ipc_pkt.dst_cpu_id = SYSADPT_MSG_IPC_DST_CPU;
	ipc_pkt.priority = 0;
	ipc_pkt.msg_no = WFO_IPC_T2H_EVENT;
	ipc_pkt.msg_data = &dol_event;
	ipc_pkt.msg_size = sizeof(dol_event);

	return ca_ipc_msg_async_send(&ipc_pkt);
}

void
wl_nullpkt_hndl(int rid, wlrxdesc_t * cfh_ul)
{
	struct radio *radio = &radio_info[rid - 1];
	ca_uint8_t *ppayload =
		(ca_uint8_t *) PHYS_TO_VIRT(cfh_ul->hdr.lo_dword_addr);
	IEEEtypes_fullHdr_t *mac_hdr;
	IEEEtypes_FrameCtl_t *frame_ctlp;
	IEEEtypes_htcField_t htc;
	int shift_bits = 0;
	IEEEtypes_AcontrolInfoOm_t acontrol_om;

	if (ppayload == NULL)
		return;

	mac_hdr = (IEEEtypes_fullHdr_t *) (ppayload + 4);
	frame_ctlp = (IEEEtypes_FrameCtl_t *) & mac_hdr->FrmCtl;

	if (frame_ctlp->Order == 0)
		return;

	// Extract the HTC
	if (mac_hdr->FrmCtl.ToDs && mac_hdr->FrmCtl.FromDs) {
		if ((frame_ctlp->Type == IEEE_TYPE_DATA) && (mac_hdr->FrmCtl.Subtype & BIT(3)))	// QoS Packet
			memcpy(&htc, &mac_hdr->wds_qos_htc.htc,
			       sizeof(IEEEtypes_htcField_t));
		else
			memcpy(&htc, &mac_hdr->wds_htc.htc,
			       sizeof(IEEEtypes_htcField_t));
	} else if ((frame_ctlp->Type == IEEE_TYPE_DATA) && (mac_hdr->FrmCtl.Subtype & BIT(3)))	// QoS Packet
		memcpy(&htc, &mac_hdr->qos_htc.htc,
		       sizeof(IEEEtypes_htcField_t));
	else
		memcpy(&htc, &mac_hdr->htc, sizeof(IEEEtypes_htcField_t));

	if ((htc.he_variant.vht && htc.he_variant.he)) {	/* HTC  HE variant present */
		shift_bits = htc_he_find_control_id(&htc, CONTROL_ID_OM);
	}

	if (shift_bits) {
		struct sta_info *sta_info;

		acontrol_om.om_control =
			(htc.he_variant.a_control >> shift_bits) & 0xFFF;

		if ((sta_info =
		     stadb_get_stainfo(rid, &mac_hdr->addr2[0])) != NULL) {
			if (sta_info->enable == 0)	//keep om_control and will indicate OMI event after STA is enabled.
				sta_info->om_control = acontrol_om.om_control;
			else {
				if (omi_event_to_host
				    (radio, acontrol_om.om_control,
				     sta_info->stn_id, sta_info->mac_addr))
					sta_info->om_control =
						acontrol_om.om_control;
				else
					sta_info->om_control = 0;
			}
		}
	}

	return;
}
