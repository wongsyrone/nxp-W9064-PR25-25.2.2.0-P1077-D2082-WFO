/** @file ap8xLnxUtil.c
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2018-2020 NXP
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
/** include files **/
#include "ap8xLnxMalloc.h"
#include "ap8xLnxUtil.h"
#include "ap8xLnxIntf.h"
#include "ap8xLnxFwcmd.h"

#ifdef IEEE80211K
#include "msan_report.h"
#endif //IEEE80211K
/* default settings */

/** internal functions **/

/** public data **/
extern int rddelay;
extern int wrdelay;
extern int intmode;

/** private data **/

/** public functions **/
static void rxdbg_init(void *pobj, struct net_device *netdev);
static void rxdbg_act(void *pobj, BOOLEAN is_set_act);
static void rxdbg_showmsg(void *pobj);
static void rxdbg_push_errcfhul(void *pobj, wl_cfhul_amsdu * pcfhul_amsdu,
				wlrxdesc_t * pcfhul);
static wlrxdesc_t *rxdbg_pull_errcfhul(void *pobj);
static void rxdbg_push(void *pobj, wlrxdesc_t * pcfhul, int qid, u16 rdinx,
		       u16 wrinx);
static void rxdbg_chk(void *pobj);

static inline unsigned long
wl_global_page_state(enum zone_stat_item item)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
	return global_page_state(item);
#else
	return global_zone_page_state(item);
#endif
}

inline static u16
rxqid_2_aryid(u8 rxqid)
{
	switch (rxqid) {
	case SC5_RXQ_START_INDEX:
		return 0;
	case SC5_RXQ_PROMISCUOUS_INDEX:
		return 1;
	case SC5_RXQ_MGMT_INDEX:
		return 2;
	}
	return 0;
}

inline static u8
aryid_2_rxqid(u8 aryid)
{
	switch (aryid) {
	case 0:
		return SC5_RXQ_START_INDEX;
	case 1:
		return SC5_RXQ_PROMISCUOUS_INDEX;
	case 2:
		return SC5_RXQ_MGMT_INDEX;
	}
	return 0;
}

static void
rxdbg_init(void *pobj, struct net_device *netdev)
{
	rxdbg_db *prxdbg = (rxdbg_db *) pobj;
	U8 i;
	// Clear the records
	memset(prxdbg, 0, sizeof(rxdbg_db));
	// Disable by default
	for (i = 0; i < 3; i++) {
		rxdbg_queue *prxq = &(prxdbg->rxq_info[i]);
		prxq->rec_id = DRVDBG_ID_INVALID;
		prxq->rec_aft_err = DRVDBG_ID_INVALID;	//No error has been detected
	}
	prxdbg->netdev = netdev;
	prxdbg->showmsg_after_err = (U16) (FLPKT_LEN / 2);	//Def: continue save records after the problem is detected
}

static void
rxdbg_act(void *pobj, BOOLEAN is_set_act)
{
	rxdbg_db *prxdbg = (rxdbg_db *) pobj;
	if (is_set_act == TRUE) {	//Set active
		prxdbg->rxq_info[0].rec_id = prxdbg->rxq_info[1].rec_id =
			prxdbg->rxq_info[2].rec_id = 0;
		prxdbg->is_running = TRUE;
	} else {		// Set Inactive
		prxdbg->is_running = FALSE;
		//prxdbg->rxq_info[0].rec_id = prxdbg->rxq_info[1].rec_id = prxdbg->rxq_info[2].rec_id = DRVDBG_ID_INVALID;
	}
	return;
}

static void
rxdbg_showmsg_by_sq(rxdbg_db * prxdbg)
{
	u16 i, j;
	for (j = 0; j < 3; j++) {
		rxdbg_queue *pqinfo = &prxdbg->rxq_info[j];
		printk("chful from sq[%u], rec_id=%u\n", aryid_2_rxqid(j),
		       pqinfo->rec_id);
		for (i = 0; i < FLPKT_LEN; i++) {
			U16 id;
			rx_rawdat *prec;
			id = (pqinfo->rec_id + i) % FLPKT_LEN;
			prec = &pqinfo->records[id];
			if (prec->valid == rec_invalid) {
				// This record has not recorded anything
				continue;
			}
			// dumpping messages
			if (prec->valid == rec_error) {
				printk("=======> Error in here, reason: %xh\n",
				       prec->err_type);
			}
			printk("[%d], cfhul_ul from q(%d), (rd, wr)=(%u, %u)\n",
			       i, prec->qid, prec->rdinx, prec->wrinx);
			printk("cfhul, from %p\n", prec->pcfhul);
#if 0
			printk("Skip temporally\n");
#else
			mwl_hex_dump(&prec->cfh_ul, sizeof(wlrxdesc_t));
#endif //0
			printk("\t (bpid, fpkt, lpkt)=(%u, %u, %u)\n",
			       prec->cfh_ul.hdr.bpid, prec->cfh_ul.fpkt,
			       prec->cfh_ul.lpkt);
			printk("payload, from %p:\n", prec->ppayload);
#if 0
			printk("Skip temporally\n");
#else
			if (prec->cfh_ul.fpkt == 1) {
				printk("fpkt==1, dump the whole buffer: \n");
				mwl_hex_dump(prec->rawdat, SC5_BMQ10_POOL);
			} else {
				int len =
					(prec->cfh_ul.hdr.length <
					 SC5_BMQ10_POOL) ? (prec->cfh_ul.hdr.
							    length)
					: (SC5_BMQ10_POOL);
				printk("fpkt==0, dump the msdu: (%d)\n", len);
				mwl_hex_dump(prec->rawdat, len);
			}
#endif //1
		}
	}
	return;
}

// Display the records
static void
rxdbg_showmsg(void *pobj)
{
	rxdbg_db *prxdbg = (rxdbg_db *) pobj;
	int i, j;

	printk(" << Dump incorrect fpkt,lpkt seq in wlProcessMsdu() >>\n");
	if (prxdbg->next_err_rec_id > 0) {
		// dump the error amsdu
		for (i = 0; i < prxdbg->next_err_rec_id; i++) {
			wl_cfhul_amsdu *perr_cfhul_rec =
				&prxdbg->err_cfhul_rec[i];
			printk("======== Record[ %u ] (%u pkts) ========\n", i,
			       perr_cfhul_rec->idx);
			for (j = 0; j < perr_cfhul_rec->idx; j++) {
				printk("\t(%d)\n", j);
				mwl_hex_dump(&perr_cfhul_rec->rxdesc[j],
					     sizeof(wlrxdesc_t));
			}
		}
	} else {
		printk("No error records\n");
	}

	printk("++++++++++++++++++++++++++++++++\n");
	if ((prxdbg->rxq_info[0].rec_aft_err == DRVDBG_ID_INVALID) &&
	    (prxdbg->rxq_info[1].rec_aft_err == DRVDBG_ID_INVALID) &&
	    (prxdbg->rxq_info[2].rec_aft_err == DRVDBG_ID_INVALID)) {
		printk("No error found yet\n");
	}
	printk("Dump records by SQ sequence\n");
	rxdbg_showmsg_by_sq(prxdbg);
	printk("--------------------------------\n");

	return;
}

void
rxdbg_push_errcfhul(void *pobj, wl_cfhul_amsdu * pcfhul_amsdu,
		    wlrxdesc_t * pcfhul)
{
	rxdbg_db *prxdbg = (rxdbg_db *) pobj;
	u16 recid = prxdbg->next_err_rec_id;
	u16 i = 0;
	static const u_int32_t buf_pool_size[SC5_BMQ_NUM] =
		{ 0x1000, 0x3000, 0x6400, 0x2000 };

	if (recid >= 10) {
		// Already gotten the records we need
		return;
	}

	if (pcfhul_amsdu) {	// save L0 buffer Reassemble context
		memcpy(&prxdbg->err_cfhul_rec[recid], pcfhul_amsdu,
		       sizeof(wl_cfhul_amsdu));
		prxdbg->next_err_rec_id++;
	} else if (pcfhul) {	// reassemble cfhul
		u32 idx = 0;
		wl_cfhul_amsdu *cfhul_amsdu = NULL;
		u8 *cur_addr = (u8 *) phys_to_virt(pcfhul->hdr.lo_dword_addr);
		for (i = 0; i < prxdbg->next_err_rec_id; i++) {
			cfhul_amsdu = &prxdbg->err_cfhul_rec[i];
			idx = cfhul_amsdu->idx - 1;
			// skip finish-reassembled L0 buffer
			if (cfhul_amsdu->rxdesc[0].fpkt == 1 &&
			    cfhul_amsdu->rxdesc[0].lpkt == 0 &&
			    cfhul_amsdu->rxdesc[idx].fpkt == 0 &&
			    cfhul_amsdu->rxdesc[idx].lpkt == 1)
				continue;
			// check address range
			if (cfhul_amsdu->rxdesc[0].fpkt == 1 &&
			    cfhul_amsdu->rxdesc[0].lpkt == 0) {
				u8 *addr_end =
					(u8 *) phys_to_virt(cfhul_amsdu->
							    rxdesc[0].hdr.
							    lo_dword_addr) +
					buf_pool_size[cfhul_amsdu->rxdesc[0].
						      hdr.bpid -
						      SC5_BMQ_START_INDEX];
				if (cur_addr < addr_end)
					break;
			}
		}
		// put cfhul in L0 buffer reassemble context
		if (i < prxdbg->next_err_rec_id) {
			cfhul_amsdu = &prxdbg->err_cfhul_rec[i];
			idx = cfhul_amsdu->idx++;
			memcpy(&cfhul_amsdu->rxdesc[idx], pcfhul,
			       sizeof(wlrxdesc_t));
		}
	}
}

static wlrxdesc_t *
rxdbg_pull_errcfhul(void *pobj)
{
	u16 i = 0;
	u32 idx = 0;
	rxdbg_db *prxdbg = (rxdbg_db *) pobj;
	wl_cfhul_amsdu *cfhul_amsdu = NULL;

	for (i = 0; i < prxdbg->next_err_rec_id; i++) {
		cfhul_amsdu = &prxdbg->err_cfhul_rec[i];
		idx = cfhul_amsdu->idx - 1;
		if (cfhul_amsdu->rxdesc[0].fpkt == 1 &&
		    cfhul_amsdu->rxdesc[0].lpkt == 0 &&
		    cfhul_amsdu->rxdesc[idx].fpkt == 0 &&
		    cfhul_amsdu->rxdesc[idx].lpkt == 1)
			break;
	}
	if (i < prxdbg->next_err_rec_id) {
		prxdbg->next_err_rec_id -= 1;
		return &cfhul_amsdu->rxdesc[0];
	}
	return NULL;
}

// Push 1 record to the db
static void
rxdbg_push(void *pobj, wlrxdesc_t * pcfhul, int qid, u16 rdinx, u16 wrinx)
{
	rxdbg_db *prxdbg = (rxdbg_db *) pobj;
	U16 rec_id;
	rx_rawdat *prec;
	u16 payload_len;

	u8 aryid = rxqid_2_aryid(qid);
	rxdbg_queue *prxdbg_infoq = &prxdbg->rxq_info[aryid];

	//if (prxdbg_infoq->rec_id == DRVDBG_ID_INVALID) {
	if (prxdbg->is_running == FALSE) {
		// Disabled => do nothing
		return;
	}
	prxdbg->last_rxq = aryid;
	rec_id = prxdbg_infoq->rec_id;
	prec = &prxdbg_infoq->records[rec_id];
	// Save the cfhul 
	memcpy(&prec->cfh_ul, pcfhul, sizeof(wlrxdesc_t));
	prec->pcfhul = pcfhul;
	prec->rdinx = rdinx;
	prec->wrinx = wrinx;
	prec->qid = qid;
	prec->valid = rec_normal;

	// Save the payload
	prec->ppayload = (u8 *) phys_to_virt(pcfhul->hdr.lo_dword_addr);
	if (prec->cfh_ul.fpkt == 1) {
		// If fpkt == 1 => copy the whole buffer
		struct wlprivate *wlpptr =
			NETDEV_PRIV_P(struct wlprivate, prxdbg->netdev);
		struct wldesc_data *wlqm =
			&wlpptr->wlpd_p->descData[prec->cfh_ul.hdr.bpid];
		payload_len =
			(wlqm->rq.bm.buf_size <
			 sizeof(prec->rawdat)) ? (wlqm->rq.bm.
						  buf_size) : (sizeof(prec->
								      rawdat));
	} else {
		// If fpkt == 0 => Just copy the packet
		payload_len =
			(pcfhul->hdr.length <
			 SC5_BMQ10_POOL) ? (prec->cfh_ul.hdr.
					    length) : (SC5_BMQ10_POOL);
	}
	memset(prec->rawdat, 0, sizeof(prec->rawdat));
	memcpy(prec->rawdat, prec->ppayload, payload_len);

	// Update the index
	prxdbg_infoq->rec_id = (prxdbg_infoq->rec_id + 1) % FLPKT_LEN;

	return;
}

// ================================================================
// Error Detection
//
//
// - Check if the nss_hdr in cfhul == data content in L0 buffer
static rxdbg_err_type
rxdbg_chkerr__diff_cfhul_payload(rxdbg_db * prxdbg)
{
	rxdbg_queue *prxq = &prxdbg->rxq_info[prxdbg->last_rxq];
	U16 rec_id = (prxq->rec_id + (FLPKT_LEN - 1)) % FLPKT_LEN;
	rx_rawdat *prec = &prxq->records[rec_id];
	int len;
	rxdbg_err_type res = rxdbg_err_no;

	//printk("%s(), chking [%u], last_rxq=%u\n", __func__, rec_id, prxdbg->last_rxq);
	len = (prec->cfh_ul.hdr.length <
	       sizeof(U32) * 24) ? (prec->cfh_ul.hdr.length) : (sizeof(U32) *
								24);
	if (memcmp(prec->cfh_ul.nss_hdr, prec->rawdat, len)) {
		prec->valid = rec_error;
		//printk("%s(), error: %u, %p, %p\n", __func__, rec_id, prec->pcfhul, prec->ppayload);
		res = rxdbg_err_dat_diff;
		prec->err_type = rxdbg_err_dat_diff;
	}

	return res;
}

// - Check if pkt_size of cfhul is bigger than the size of the bqm_buffer
static rxdbg_err_type
rxdbg_chkerr__pkt_oversize(rxdbg_db * prxdbg)
{
	struct wlprivate *wlpptr =
		NETDEV_PRIV_P(struct wlprivate, prxdbg->netdev);
	rxdbg_queue *prxq = &prxdbg->rxq_info[prxdbg->last_rxq];
	U16 rec_id = (prxq->rec_id + (FLPKT_LEN - 1)) % FLPKT_LEN;
	rx_rawdat *prec = &prxq->records[rec_id];
	struct wldesc_data *wlqm =
		&wlpptr->wlpd_p->descData[prec->cfh_ul.hdr.bpid];
	rxdbg_err_type res = rxdbg_err_no;

	if (prec->cfh_ul.hdr.length > wlqm->rq.bm.buf_size) {
		//printk("%s(), error: %u, %p, %p\n", __func__, rec_id, prec->pcfhul, prec->ppayload);
		prec->valid = rec_error;
		res = rxdbg_err_over_size;
		prec->err_type = rxdbg_err_over_size;
	}

	return res;
}

//
// - Check if the (fpkt,lpkt) sequence is valid
// Check if the fpkt/lpkt valid.
// error:
//              1. last lpt==0, this fpt == 1   => lpkt missing
//              2. last lpt==1, this fpt == 0   => fpkt missing
static rxdbg_err_type
rxdbg_chk_flpkt_seq(rxdbg_db * prxdbg)
{
	rxdbg_err_type res = rxdbg_err_no;
	rxdbg_queue *prxq = &prxdbg->rxq_info[prxdbg->last_rxq];
	U16 this_recid = (prxq->rec_id + (FLPKT_LEN - 1)) % FLPKT_LEN;
	U16 last_recid = (prxq->rec_id + (FLPKT_LEN - 2)) % FLPKT_LEN;
	rx_rawdat *p_this_rec = &(prxq->records[this_recid]);
	rx_rawdat *p_last_rec = &(prxq->records[last_recid]);

	if (p_last_rec->valid == rec_invalid) {
		// Last record has not been set yet
		goto funcfinal;
	}
	if ((p_this_rec->cfh_ul.fpkt ^ p_last_rec->cfh_ul.lpkt) == 1) {
		// Error found~
		res = rxdbg_err_flpkt;
		p_this_rec->valid = rec_error;
		p_this_rec->err_type = rxdbg_err_flpkt;
		goto funcfinal;
	}

funcfinal:
	return res;
}

//If there are enough data => stop recording new datas
static void
rxdbg_chk(void *pobj)
{
	rxdbg_db *prxdbg = (rxdbg_db *) pobj;
	u16 is_error = 0;
	rxdbg_queue *prxq = &prxdbg->rxq_info[prxdbg->last_rxq];	// The latest updated rxq 
	U16 rec_id = (prxq->rec_id + (FLPKT_LEN - 1)) % FLPKT_LEN;
	rx_rawdat *prec = &prxq->records[rec_id];

	//if (prxq->rec_id == DRVDBG_ID_INVALID) {
	if (prxdbg->is_running == FALSE) {
		// Disabled => do nothing
		return;
	}
	// Has not gotten error: 
	//      - prxq->rec_aft_err == DRVDBG_ID_INVALID
	//
	prec->err_type = rxdbg_err_no;

	if (prec->cfh_ul.hdrFormat == 0) {	//Normal mode
		// Check if there are errors
		// => skip checking cfhul payload / oversize
		// => Open it later~
		is_error |= rxdbg_chkerr__diff_cfhul_payload(prxdbg);
		is_error |= rxdbg_chkerr__pkt_oversize(prxdbg);
		is_error |= rxdbg_chk_flpkt_seq(prxdbg);
	} else {		// bypass mode => It's always ok
		is_error = 0;
	}

	/*
	   a) Conditions:
	   - no error yet & get error   => Start error counting
	   - no error yet & no error => Nothing to do   
	   - has error & got error => keep counting
	   - has error & no error => keep counting
	   b) If has enough data => deactive this module
	 */
	if (prxq->rec_aft_err == DRVDBG_ID_INVALID) {
		if (is_error != rxdbg_err_no) {
			// No error before & an error is detected => start the error log
			prxq->rec_aft_err = 0;
		}
	} else {
		prxq->rec_aft_err++;
	}

	if ((prxq->rec_aft_err != DRVDBG_ID_INVALID) &&	//DRVDBG_ID_INVALID == 0xffff, always > prxdbg->showmsg_after_err
	    (prxq->rec_aft_err >= prxdbg->showmsg_after_err)) {
		// Enough data => deactivate the module
		rxdbg_act(prxdbg, FALSE);
		printk("%u, %u, deactivate the debug module, rec_id=%u\n",
		       prxq->rec_aft_err, prxdbg->showmsg_after_err,
		       prxq->rec_id);
	}

	return;
}

static void
rxdbg_init_dummy(void *pobj, struct net_device *netdev)
{
}

static void
rxdbg_act_dummy(void *pobj, BOOLEAN is_set_act)
{
}

static void
rxdbg_showmsg_dummy(void *pobj)
{
}

static void
rxdbg_push_errcfhul_dummy(void *pobj, wl_cfhul_amsdu * pcfhul_amsdu,
			  wlrxdesc_t * pcfhul)
{
}

static wlrxdesc_t *
rxdbg_pull_errcfhul_dummy(void *pobj)
{
	return NULL;
}

static void
rxdbg_push_dummy(void *pobj, wlrxdesc_t * pcfhul, int qid, u16 rdinx, u16 wrinx)
{
}

static void
rxdbg_chk_dummy(void *pobj)
{
}

void
set_rxdbg_func(rxdbg_intf * prxdbg_intr, submod_type mtype)
{
	switch (mtype) {
	case rxdbg_cfhul:
		prxdbg_intr->init = rxdbg_init;
		prxdbg_intr->active = rxdbg_act;
		prxdbg_intr->show_msg = rxdbg_showmsg;
		prxdbg_intr->rxdbg_push_errcfhul = rxdbg_push_errcfhul;
		prxdbg_intr->rxdbg_pull_errcfhul = rxdbg_pull_errcfhul;
		prxdbg_intr->rxdbg_push = rxdbg_push;
		prxdbg_intr->rxdbg_chk = rxdbg_chk;
		break;
	case rxdbg_dummp:
		prxdbg_intr->init = rxdbg_init_dummy;
		prxdbg_intr->active = rxdbg_act_dummy;
		prxdbg_intr->show_msg = rxdbg_showmsg_dummy;
		prxdbg_intr->rxdbg_push_errcfhul = rxdbg_push_errcfhul_dummy;
		prxdbg_intr->rxdbg_pull_errcfhul = rxdbg_pull_errcfhul_dummy;
		prxdbg_intr->rxdbg_push = rxdbg_push_dummy;
		prxdbg_intr->rxdbg_chk = rxdbg_chk_dummy;
		break;
	}
}

// ============================================================================================================================
// Recover if getting incorrect cfhul whose fpkt==1
// If the cfhul whose fpkt==1 and has problems => This cfhul will be drop. But the buffer (pkt) still needs to be free
// Tasks:
//      a) Keep a ring whose size == the size of SQ
//      b) Save the information (bpid, lo_buff) while this cfh-ul is returned, but before checking the error integrity
//              - If this cfhul is correct, clear the record (wl_clr_cfhul_buf_rec()) while this cfh-ul is being used
//      c) While the cfh-ul is returned in the next run, check the record. If it's not 0, there should be problems last time that this buffer is not free
//              => free it
//
void
wl_free_cfhul_lo(u_int32_t tmp_lodword_addr, struct net_device *netdev,
		 u32 bpid)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	struct except_cnt *wlexcept_p = &wlpd_p->except_cnt;
	struct wldesc_data *wlqm = &wlpptr->wlpd_p->descData[bpid];
	struct sk_buff *skb;
	u8 *skb_addr = (u8 *) phys_to_virt(tmp_lodword_addr);

	wlUnmapBuffer(netdev, (u8 *) skb_addr, wlqm->rq.bm.buf_size);
	if (likely(*((u32 *) (skb_addr - SKB_INFO_SIZE)) == SKB_SIGNATURE)) {
		// correct buffer
		skb = *(struct sk_buff **)(skb_addr - SKB_POINTER_OFFSET);
		if (unlikely(!virt_addr_valid(skb))) {
			wlpd_p->except_cnt.skb_invalid_addr_cnt++;
			wlexcept_p->free_err_pkts[1]++;
		} else {
			wlpd_p->drv_stats_val.bmqbuf_ret_cnt[bpid -
							     SC5_BMQ_START_INDEX]++;
			spin_lock(&wlpd_p->pend_skb_trace[PENDSKB_RX].lock);
			__skb_unlink(skb, &wlpd_p->pend_skb_trace[PENDSKB_RX]);
			spin_unlock(&wlpd_p->pend_skb_trace[PENDSKB_RX].lock);
			wl_free_skb(skb);
			wlexcept_p->free_err_pkts[0]++;
		}
	} else {
		wlexcept_p->free_err_pkts[2]++;
	}

	return;
}

void
wl_update_cfhul_buf_rec(cfhul_buf_pool * pcfhul_buf_pool,
			struct net_device *netdev, int qid, u32 rdinx,
			wlrxdesc_t * cfh_ul)
{
	u_int32_t tmp_lodword_addr;
	u16 ary_qid = rxqid_2_aryid(qid);
	cfhul_buf_info *pcfhul_buf_info =
		&pcfhul_buf_pool->rxq_info[ary_qid][rdinx];

	if (qid != SC5_RXQ_START_INDEX) {
		// Only tracking the data packets
		return;
	}

	/*
	   If the addr of the record != NULL 
	   => the cfhul in the last run has problems that the buffer is not free
	   => free the buffer & clear the record
	 */
	tmp_lodword_addr = pcfhul_buf_info->lo_dword_addr;
	if (unlikely(tmp_lodword_addr != 0)) {
		// Has some unfreed buffers
		wl_free_cfhul_lo(tmp_lodword_addr, netdev,
				 pcfhul_buf_info->bpid);
		pcfhul_buf_info->lo_dword_addr = 0;
	}
	if (unlikely(cfh_ul->fpkt == 1)) {
		// Record the info only if it's fpkt==1
		pcfhul_buf_info->bpid = cfh_ul->hdr.bpid;
		pcfhul_buf_info->lo_dword_addr = cfh_ul->hdr.lo_dword_addr;
	}

	return;
}

void
wl_clr_cfhul_buf_rec(cfhul_buf_pool * pcfhul_buf_pool, int qid, u32 rdinx,
		     wlrxdesc_t * pcfh_ul)
{
	if (unlikely(pcfh_ul->fpkt == 1)) {
		//This cfhul is correct => clear the record
		pcfhul_buf_pool->rxq_info[rxqid_2_aryid(qid)][rdinx].
			lo_dword_addr = 0;
	}
	return;
}

//
// Recovery if the last skb is not free
//      The skb will be free while getting cfhul whose lpkt ==1. If this cfhul has problems & dropped => this skb will not be free
//      a) Save the skb while getting a cfh-ul whose fpkt == 1
//      b) Clear the pointer while getting cfh-ul whose lpt == 1
//      c) Recover to free this skb if skb != NULL at #a
void
wl_save_last_rxskb(struct net_device *netdev, wlrxdesc_t * cfh_ul,
		   struct sk_buff *skb)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	u32 wlqm_id = cfh_ul->hdr.bpid;
	u32 wlqm_aryid = wlqm_id - SC5_BMQ_START_INDEX;
	struct wldesc_data *wlqm = &wlpd_p->descData[wlqm_id];

	if (unlikely(wlpd_p->last_skb[wlqm_aryid] != NULL)) {
		//The last lpkt should be missing => free the last skb
		rpkt_reuse_push(&wlqm->rq.skbTrace,
				wlpd_p->last_skb[wlqm_aryid]);
		wlpd_p->last_skb[wlqm_aryid] = NULL;
		wlpd_p->except_cnt.lpkt_miss[wlqm_aryid]++;
	}
	wlpd_p->last_skb[wlqm_aryid] = skb;
	return;
}

void
wl_clr_last_rxskb(struct net_device *netdev, u32 wlqm_aryid)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	wlpd_p->last_skb[wlqm_aryid] = NULL;
	return;
}

// CFH_UL exception handle function --

UINT32
wl_ch_load(vmacApInfo_t * vmacSta_p, UINT32 delta_time, UINT32 slotTickCnt,
	   UINT8 scale_mapping)
{
#ifdef SOC_W906X
	struct wlprivate *wlpptr =
		NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev);
	UINT8 slotTime = 9;	// (*(mib->mib_shortSlotTime)) ? 9 : 20;
	UINT32 idleTime, r_load;

	if ((*(vmacSta_p->Mib802dot11->mib_ApMode) & AP_MODE_BAND_MASK) <=
	    AP_MODE_B_ONLY) {
		slotTime = 20;
	}

	if (delta_time == 0) {
		return wlpptr->smacStatusAddr->slotTickCnt;
	} else {
		if (scale_mapping == 0) {
			scale_mapping = 100;
		}
		idleTime =
			(wlpptr->smacStatusAddr->slotTickCnt -
			 slotTickCnt) * slotTime;
		r_load = (delta_time >
			  idleTime) ? ((delta_time -
					idleTime) * scale_mapping) /
			delta_time : 1;

		return (r_load > 0) ? r_load : 1;
	}
#else /* SOC_W906X */
	return 0;
#endif /* SOC_W906X */
}

static void
ch_load_interval_cb(UINT8 * data)
{
	ch_load_info_t *ch_load_info = (ch_load_info_t *) data;
	vmacApInfo_t *vmacSta_p = (vmacApInfo_t *) ch_load_info->master;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	TimerDisarm(&ch_load_info->timer);
	if (!ch_load_info->started) {
		return;
	}
	TimerFireInByJiffies(&ch_load_info->timer, 1, ch_load_info->callback,
			     data, ch_load_info->dur * TIMER_1MS);
	ch_load_info->prev_load_val = wl_ch_load(vmacSta_p, 0, 0, 0);
	ch_load_info->prev_time = ktime_get_real();
	if (ch_load_info->tag == CH_LOAD_ACS && *(mib->mib_autochannel) != 0) {
		vmacSta_p->acs_cur_bcn = 1;
	}
}

void
wl_get_ch_load_by_timer(ch_load_info_t * ch_load_info)
{
	vmacApInfo_t *vmacSta_p = (vmacApInfo_t *) ch_load_info->master;

	TimerDisarm(&ch_load_info->timer);
	if (ch_load_info->dur == 0) {
		ch_load_info->started = 0;
		return;
	}
	TimerInit(&ch_load_info->timer);
	if (vmacSta_p->InfUpFlag && ch_load_info->started) {
		if (ch_load_info->interval == 0) {
			ch_load_interval_cb((UINT8 *) ch_load_info);
		} else {
			TimerFireInByJiffies(&ch_load_info->timer, 1,
					     &ch_load_interval_cb,
					     (UINT8 *) ch_load_info,
					     ch_load_info->interval *
					     TIMER_1MS);
		}
	} else {
		TimerDisarm(&ch_load_info->timer);
	}
}

void
wl_acs_ch_load_cb(UINT8 * data)
{
	struct wlprivate *priv = NULL;
	ch_load_info_t *ch_load_info = (ch_load_info_t *) data;
	vmacApInfo_t *vmacSta_p = NULL;
	MIB_802DOT11 *mib = NULL;
	MIB_PHY_DSSS_TABLE *PhyDSSSTable = NULL;
	UINT32 ch_load;
	UINT32 ch_idx;
	SINT16 tmp_nf = 0;

	if (!ch_load_info)
		return;
	vmacSta_p = (vmacApInfo_t *) ch_load_info->master;
	if (!vmacSta_p)
		return;
	mib = vmacSta_p->ShadowMib802dot11;
	PhyDSSSTable = mib->PhyDSSSTable;
	priv = NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev);
	vmacSta_p->acs_cur_bcn = 0;
	if (vmacSta_p->InfUpFlag && ch_load_info->started &&
	    *(mib->mib_autochannel) != 0) {
		for (ch_idx = 0;
		     ch_idx < IEEEtypes_MAX_CHANNELS + IEEEtypes_MAX_CHANNELS_A;
		     ch_idx++) {
			if (PhyDSSSTable->CurrChan ==
			    vmacSta_p->acs_db[ch_idx].channel) {
				break;
			}
		}
		if (ch_idx == IEEEtypes_MAX_CHANNELS + IEEEtypes_MAX_CHANNELS_A) {
			printk("acs cannot find current channel %d in ap_op_ch_list\n", PhyDSSSTable->CurrChan);
			return;
		} else {
			ch_load = wl_ch_load(vmacSta_p,
					     ktime_us_delta(ktime_get_real(),
							    ch_load_info->
							    prev_time),
					     ch_load_info->prev_load_val, 100);
			tmp_nf = wl_util_get_nf(vmacSta_p->dev, NULL, NULL);
			if (tmp_nf != 0) {
				vmacSta_p->acs_db[ch_idx].noise_floor =
					(SINT32) tmp_nf;
			}
			vmacSta_p->acs_db[ch_idx].ch_load = ch_load;

			MSAN_get_ACS_db(vmacSta_p, vmacSta_p->NumScanChannels,
					vmacSta_p->acs_db[ch_idx].channel);
		}
	}

	if (ch_load_info->loop_count == 1) {
		/* It's last time, stop timer */
		TimerDisarm(&ch_load_info->timer);
		return;
	} else if (ch_load_info->loop_count > 1) {
		ch_load_info->loop_count--;
	}

	wl_get_ch_load_by_timer(ch_load_info);
}

void
wl_rrm_ch_load_cb(UINT8 * data)
{
	ch_load_info_t *ch_load_info = (ch_load_info_t *) data;
	vmacApInfo_t *vmacSta_p = (vmacApInfo_t *) ch_load_info->master;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	if (vmacSta_p->InfUpFlag && ch_load_info->started && *(mib->mib_rrm)) {
		ch_load_info->ch_load = (UINT8) wl_ch_load(vmacSta_p,
							   ktime_us_delta
							   (ktime_get_real(),
							    ch_load_info->
							    prev_time),
							   ch_load_info->
							   prev_load_val, 255);
	}

	if (ch_load_info->loop_count == 1) {
		/* It's last time, stop timer */
		TimerDisarm(&ch_load_info->timer);
		return;
	} else if (ch_load_info->loop_count > 1) {
		ch_load_info->loop_count--;
	}

	wl_get_ch_load_by_timer(ch_load_info);
	wlFwSetBcnChannelUtil(vmacSta_p->dev, (UINT8) ch_load_info->ch_load);
}

void
wl_bandsteer_ch_load_cb(UINT8 * data)
{
	ch_load_info_t *ch_load_info = (ch_load_info_t *) data;
	vmacApInfo_t *vmacSta_p = (vmacApInfo_t *) ch_load_info->master;
	unsigned char buf[IW_CUSTOM_MAX] = { 0 };
	union iwreq_data wreq;
	static const char *tag = "BANDSTEER-ChannelLoad=";

	if (vmacSta_p->InfUpFlag && ch_load_info->started) {
		ch_load_info->ch_load =
			(UINT8) wl_ch_load(vmacSta_p,
					   ktime_us_delta(ktime_get_real(),
							  ch_load_info->
							  prev_time),
					   ch_load_info->prev_load_val, 100);
	}

	snprintf(buf, sizeof(buf), "%s%d", tag, ch_load_info->ch_load);
	memset(&wreq, 0, sizeof(wreq));
	wreq.data.length = strlen(buf);

	if (vmacSta_p->dev->flags & IFF_RUNNING)
		wireless_send_event(vmacSta_p->dev, IWEVCUSTOM, &wreq, buf);

	if (ch_load_info->loop_count == 1) {
		/* It's last time, stop timer */
		TimerDisarm(&ch_load_info->timer);
		return;
	} else if (ch_load_info->loop_count > 1) {
		ch_load_info->loop_count--;
	}

	wl_get_ch_load_by_timer(ch_load_info);
	wlFwSetBcnChannelUtil(vmacSta_p->dev, (UINT8) ch_load_info->ch_load);
}

#ifdef MEMORY_USAGE_TRACE

SINT32 WL_memfree;
mem_trace_func MemTraceFunc[WL_MEM_TRACE_FUNC_NUM];
mem_trace_db *MemTraceSkbDb;
mem_trace_unit MemTraceVzalloc[WL_MEM_TRACE_VZALLOC_NUM];
mem_trace_unit MemTraceKmalloc[WL_MEM_TRACE_KMALLOC_NUM];
mem_trace_unit MemTraceDmaalloc[WL_MEM_TRACE_DMAALLOC_NUM];

SINT32 MT_Skb_max = 0;
SINT32 MT_Vzalloc_max = 0;
SINT32 MT_Kmalloc_max = 0;
SINT32 MT_Dmaalloc_max = 0;

void
wl_get_meminfo_init(void)
{
	struct file *filp = NULL;
	SINT32 i = 0, j = 0;
	UINT8 *WL_meminfo, *pos;

	memset(MemTraceFunc, 0, sizeof(mem_trace_func) * WL_MEM_TRACE_FUNC_NUM);
	memset(MemTraceVzalloc, 0,
	       sizeof(mem_trace_unit) * WL_MEM_TRACE_VZALLOC_NUM);
	memset(MemTraceKmalloc, 0,
	       sizeof(mem_trace_unit) * WL_MEM_TRACE_KMALLOC_NUM);
	memset(MemTraceDmaalloc, 0,
	       sizeof(mem_trace_unit) * WL_MEM_TRACE_DMAALLOC_NUM);

	MemTraceSkbDb =
		(mem_trace_db *) wl_kmalloc(sizeof(mem_trace_db), GFP_KERNEL);
	memset(MemTraceSkbDb, 0, sizeof(mem_trace_db));

	filp = filp_open("/proc/meminfo", O_RDONLY, 0);

	if (!IS_ERR(filp)) {
		WL_meminfo = wl_kmalloc(4096, GFP_KERNEL);
		memset(WL_meminfo, 0, 4096);
		while ((j =
			kernel_read(filp, &WL_meminfo[i++], 0x01,
				    &filp->f_pos)) != 0) {
			if (i >= 4096) {
				printk("ERROR: MemInfo size exceeds image memory = 4096 bytes. \n");
				break;
			}
		}
		filp_close(filp, current->files);
		pos = strstr(WL_meminfo, "MemFree:");
		pos += 8;
		for (i = 0; i < 128 && *pos == ' '; i++, pos++) ;
		WL_memfree = simple_strtol(pos, NULL, 10);
		wl_kfree(WL_meminfo);
	}
}

void
wl_get_meminfo_deinit(void)
{
	mem_trace_db *tmp_skb_db = MemTraceSkbDb, *next;
	UINT32 i;

	while (tmp_skb_db) {
		next = tmp_skb_db->next;
		wl_kfree(tmp_skb_db);
		tmp_skb_db = next;
	}
	MemTraceSkbDb = NULL;

	for (i = 0; i < WL_MEM_TRACE_FUNC_NUM; i++) {
		if (MemTraceFunc[i].size != 0 &&
		    MemTraceFunc[i].type == MEM_SKB) {
			printk("%s line:%d wl_skb non-free size:%d\n",
			       MemTraceFunc[i].func, MemTraceFunc[i].line,
			       MemTraceFunc[i].size);
		} else if (MemTraceFunc[i].size != 0 &&
			   MemTraceFunc[i].type == MEM_KMALLOC) {
			printk("%s line:%d wl_kmalloc non-free size:%d\n",
			       MemTraceFunc[i].func, MemTraceFunc[i].line,
			       MemTraceFunc[i].size);
		} else if (MemTraceFunc[i].size != 0 &&
			   MemTraceFunc[i].type == MEM_DMAALLOC) {
			printk("%s line:%d wl_util_dma_alloc_coherent non-free size:%d\n", MemTraceFunc[i].func, MemTraceFunc[i].line, MemTraceFunc[i].size);
		}
	}
}

SINT32
wl_get_meminfo_stat(void)
{
	struct file *filp = NULL;
	SINT32 i = 0, j = 0, free_size = 0;
	UINT8 *WL_meminfo, *pos;

	filp = filp_open("/proc/meminfo", O_RDONLY, 0);

	if (!IS_ERR(filp)) {
		WL_meminfo = wl_kmalloc(4096, GFP_KERNEL);
		memset(WL_meminfo, 0, 4096);
		while ((j =
			kernel_read(filp, &WL_meminfo[i++], 0x01,
				    &filp->f_pos)) != 0) {
			if (i >= 4096) {
				printk("ERROR: MemInfo size exceeds image memory = 4096 bytes. \n");
				break;
			}
		}
		filp_close(filp, current->files);
		pos = strstr(WL_meminfo, "MemFree:");
		pos += 8;
		for (i = 0; i < 128 && *pos == ' '; i++, pos++) ;
		free_size = simple_strtol(pos, NULL, 10);
		wl_kfree(WL_meminfo);
	}
	return free_size;
}
#endif /* MEMORY_USAGE_TRACE */

void *
wl_util_alloc_skb(int len, const char *func, const int line)
{
#ifdef MEMORY_USAGE_TRACE
	mem_trace_db *tmp_skb_db = MemTraceSkbDb;
	struct sk_buff *skb = NULL;
	UINT32 i, fc_idx, t_max;

	skb = kernel_alloc_skb(len);
	if (skb) {
		for (fc_idx = 0; fc_idx < WL_MEM_TRACE_FUNC_NUM; fc_idx++) {
			if (MemTraceFunc[fc_idx].size != 0 &&
			    !strcmp(func, MemTraceFunc[fc_idx].func) &&
			    MemTraceFunc[fc_idx].line == line) {
				/* find the same position */
				break;
			} else if (MemTraceFunc[fc_idx].size == 0) {
				/* End of Func */
				memset(MemTraceFunc[fc_idx].func, 0, 64);
				memcpy(MemTraceFunc[fc_idx].func, func,
				       (strlen(func) < 64) ? strlen(func) : 64);
				MemTraceFunc[fc_idx].line = line;
				MemTraceFunc[fc_idx].type = MEM_SKB;
				break;
			}
		}
		if (fc_idx >= WL_MEM_TRACE_FUNC_NUM) {
			printk("%s fc_idx out of bound %d\n", __func__,
			       WL_MEM_TRACE_FUNC_NUM);
			goto mem_ret;
		}

		t_max = 0;
		while (1) {
			for (i = 0; i < 1800; i++) {
				t_max++;
				if (!tmp_skb_db->unit[i].addr) {
					tmp_skb_db->unit[i].func_idx = fc_idx;
					tmp_skb_db->unit[i].addr = skb->head;
					tmp_skb_db->unit[i].length = len;
					MemTraceFunc[fc_idx].size += len;
					tmp_skb_db->ispace++;
					break;
				}
			}
			if (i >= 1800) {
				if (tmp_skb_db->next == NULL) {
//                    printk("%s alloc new MemTraceSkbDB\n", __func__);
					tmp_skb_db->next =
						(mem_trace_db *)
						wl_kmalloc_autogfp(sizeof
								   (mem_trace_db));
					tmp_skb_db = tmp_skb_db->next;
					memset(tmp_skb_db, 0,
					       sizeof(mem_trace_db));
				} else {
					tmp_skb_db = tmp_skb_db->next;
				}
			} else {
				break;
			}
		}
		MT_Skb_max = MT_Skb_max > t_max ? MT_Skb_max : t_max;
	}
mem_ret:
	return skb;
#else /* MEMORY_USAGE_TRACE */
	return kernel_alloc_skb(len);
#endif /* MEMORY_USAGE_TRACE */
}

void
wl_util_free_skb(struct sk_buff *skb, const char *func, const int line)
{
#ifdef MEMORY_USAGE_TRACE
	mem_trace_db *tmp_skb_db = MemTraceSkbDb;
	UINT32 i, fc_idx;

	while (1) {
		for (i = 0; i < 1800; i++) {
			if (tmp_skb_db->unit[i].addr == skb->head) {
				fc_idx = tmp_skb_db->unit[i].func_idx;
				MemTraceFunc[fc_idx].size -=
					tmp_skb_db->unit[i].length;
				tmp_skb_db->ispace--;
				memset(&tmp_skb_db->unit[i], 0,
				       sizeof(mem_trace_unit));
				break;
			}
		}
		if (i == 1800) {
//            printk("wl_util_free_skb get next skb DB\n");
			if (tmp_skb_db->next == NULL) {
//                printk("wl_util_free_skb not found!!:%p\n", skb->head);
				break;
			} else {
				tmp_skb_db = tmp_skb_db->next;
			}
		} else {
			break;
		}
	}
	kernel_free_skb(skb);
#else /* MEMORY_USAGE_TRACE */
	kernel_free_skb(skb);
#endif /* MEMORY_USAGE_TRACE */
}

void
wl_util_receive_skb(struct sk_buff *skb, const char *func, const int line)
{
#ifdef MEMORY_USAGE_TRACE
	mem_trace_db *tmp_skb_db = MemTraceSkbDb;
	UINT32 i, fc_idx;

	while (1) {
		for (i = 0; i < 1800; i++) {
			if (tmp_skb_db->unit[i].addr == skb->head) {
				fc_idx = tmp_skb_db->unit[i].func_idx;
				MemTraceFunc[fc_idx].size -=
					tmp_skb_db->unit[i].length;
				tmp_skb_db->ispace--;
				memset(&tmp_skb_db->unit[i], 0,
				       sizeof(mem_trace_unit));
				break;
			}
		}
		if (i == 1800) {
			if (tmp_skb_db->next == NULL) {
				break;
			} else {
				tmp_skb_db = tmp_skb_db->next;
			}
		} else {
			break;
		}
	}
	kernel_receive_skb(skb);
#else /* MEMORY_USAGE_TRACE */
	kernel_receive_skb(skb);
#endif /* MEMORY_USAGE_TRACE */
}

void *
wl_util_vzalloc(size_t size, const char *func, const int line)
{
#ifdef MEMORY_USAGE_TRACE
	void *ptr = NULL;
	UINT32 i, fc_idx;

	ptr = kernel_vzalloc(size);
	if (ptr) {
		for (fc_idx = 0; fc_idx < WL_MEM_TRACE_FUNC_NUM; fc_idx++) {
			if (MemTraceFunc[fc_idx].size != 0 &&
			    !strcmp(func, MemTraceFunc[fc_idx].func) &&
			    MemTraceFunc[fc_idx].line == line) {
				/* find the same position */
				break;
			} else if (MemTraceFunc[fc_idx].size == 0) {
				/* End of Func */
				memset(MemTraceFunc[fc_idx].func, 0, 64);
				memcpy(MemTraceFunc[fc_idx].func, func,
				       (strlen(func) < 64) ? strlen(func) : 64);
				MemTraceFunc[fc_idx].line = line;
				MemTraceFunc[fc_idx].type = MEM_VZALLOC;
				break;
			}
		}
		if (fc_idx >= WL_MEM_TRACE_FUNC_NUM) {
			printk("%s fc_idx out of bound %d\n", __func__,
			       WL_MEM_TRACE_FUNC_NUM);
			goto mem_ret;
		}

		for (i = 0; i < WL_MEM_TRACE_VZALLOC_NUM; i++) {
			MT_Vzalloc_max =
				MT_Vzalloc_max >
				(i + 1) ? MT_Vzalloc_max : (i + 1);
			if (!MemTraceVzalloc[i].addr) {
				MemTraceVzalloc[i].func_idx = fc_idx;
				MemTraceVzalloc[i].addr = ptr;
				MemTraceVzalloc[i].length = size;
				MemTraceFunc[fc_idx].size += size;
				break;
			}
		}
		if (i >= WL_MEM_TRACE_VZALLOC_NUM) {
			printk("%s line:%d wl_util_vzalloc out of bound %d\n",
			       func, line, WL_MEM_TRACE_VZALLOC_NUM);
		}
	}
mem_ret:
	return ptr;
#else /* MEMORY_USAGE_TRACE */
	return kernel_vzalloc(size);
#endif /* MEMORY_USAGE_TRACE */
}

void
wl_util_vfree(const void *ptr, const char *func, const int line)
{
#ifdef MEMORY_USAGE_TRACE
	UINT32 i, fc_idx;

	for (i = 0; i < WL_MEM_TRACE_VZALLOC_NUM; i++) {
		if (MemTraceVzalloc[i].addr == ptr) {
			fc_idx = MemTraceVzalloc[i].func_idx;
			MemTraceFunc[fc_idx].size -= MemTraceVzalloc[i].length;
			memset(&MemTraceVzalloc[i], 0, sizeof(mem_trace_unit));
			break;
		}
	}
	if (i == WL_MEM_TRACE_VZALLOC_NUM) {
		printk("%s line:%d ptr:%p can not found ptr in wl_util_vfree!!\n", func, line, ptr);
	}
	kernel_vfree(ptr);
#else /* MEMORY_USAGE_TRACE */
	kernel_vfree(ptr);
#endif /* MEMORY_USAGE_TRACE */
}

void *
wl_util_kmalloc(size_t size, gfp_t flags, const char *func, const int line)
{
#ifdef MEMORY_USAGE_TRACE
	void *ptr = NULL;
	UINT32 i, fc_idx;

	ptr = kernel_kmalloc(size, flags);
	if (ptr) {
		for (fc_idx = 0; fc_idx < WL_MEM_TRACE_FUNC_NUM; fc_idx++) {
			if (MemTraceFunc[fc_idx].size != 0 &&
			    !strcmp(func, MemTraceFunc[fc_idx].func) &&
			    MemTraceFunc[fc_idx].line == line) {
				/* find the same position */
				break;
			} else if (MemTraceFunc[fc_idx].size == 0) {
				/* End of Func */
				memset(MemTraceFunc[fc_idx].func, 0, 64);
				memcpy(MemTraceFunc[fc_idx].func, func,
				       (strlen(func) < 64) ? strlen(func) : 64);
				MemTraceFunc[fc_idx].line = line;
				MemTraceFunc[fc_idx].type = MEM_KMALLOC;
				break;
			}
		}
		if (fc_idx >= WL_MEM_TRACE_FUNC_NUM) {
			printk("%s fc_idx out of bound %d\n", __func__,
			       WL_MEM_TRACE_FUNC_NUM);
			goto mem_ret;
		}

		for (i = 0; i < WL_MEM_TRACE_KMALLOC_NUM; i++) {
			MT_Kmalloc_max =
				MT_Kmalloc_max >
				(i + 1) ? MT_Kmalloc_max : (i + 1);
			if (!MemTraceKmalloc[i].addr) {
				MemTraceKmalloc[i].func_idx = fc_idx;
				MemTraceKmalloc[i].addr = ptr;
				MemTraceKmalloc[i].length = size;
				MemTraceFunc[fc_idx].size += size;
				break;
			}
		}
		if (i >= WL_MEM_TRACE_KMALLOC_NUM) {
			printk("%s line:%d wl_util_kmalloc out of bound %d\n",
			       func, line, WL_MEM_TRACE_KMALLOC_NUM);
		}
	}
mem_ret:
	return ptr;
#else /* MEMORY_USAGE_TRACE */
	return kernel_kmalloc(size, flags);
#endif /* MEMORY_USAGE_TRACE */
}

void *
wl_util_kzalloc(size_t size, gfp_t flags, const char *func, const int line)
{
#ifdef MEMORY_USAGE_TRACE
	void *ptr = NULL;
	UINT32 i, fc_idx;

	ptr = kernel_kzalloc(size, flags);
	if (ptr) {
		for (fc_idx = 0; fc_idx < WL_MEM_TRACE_FUNC_NUM; fc_idx++) {
			if (MemTraceFunc[fc_idx].size != 0 &&
			    !strcmp(func, MemTraceFunc[fc_idx].func) &&
			    MemTraceFunc[fc_idx].line == line) {
				/* find the same position */
				break;
			} else if (MemTraceFunc[fc_idx].size == 0) {
				/* End of Func */
				memset(MemTraceFunc[fc_idx].func, 0, 64);
				memcpy(MemTraceFunc[fc_idx].func, func,
				       (strlen(func) < 64) ? strlen(func) : 64);
				MemTraceFunc[fc_idx].line = line;
				MemTraceFunc[fc_idx].type = MEM_KMALLOC;
				break;
			}
		}
		if (fc_idx >= WL_MEM_TRACE_FUNC_NUM) {
			printk("%s fc_idx out of bound %d\n", __func__,
			       WL_MEM_TRACE_FUNC_NUM);
			goto mem_ret;
		}

		for (i = 0; i < WL_MEM_TRACE_KMALLOC_NUM; i++) {
			MT_Kmalloc_max =
				MT_Kmalloc_max >
				(i + 1) ? MT_Kmalloc_max : (i + 1);
			if (!MemTraceKmalloc[i].addr) {
				MemTraceKmalloc[i].func_idx = fc_idx;
				MemTraceKmalloc[i].addr = ptr;
				MemTraceKmalloc[i].length = size;
				MemTraceFunc[fc_idx].size += size;
				break;
			}
		}
		if (i >= WL_MEM_TRACE_KMALLOC_NUM) {
			printk("%s line:%d wl_util_kmalloc out of bound %d\n",
			       func, line, WL_MEM_TRACE_KMALLOC_NUM);
		}
	}
mem_ret:
	return ptr;
#else /* MEMORY_USAGE_TRACE */
	return kernel_kzalloc(size, flags);
#endif /* MEMORY_USAGE_TRACE */
}

void
wl_util_kfree(const void *ptr, const char *func, const int line)
{
#ifdef MEMORY_USAGE_TRACE
	UINT32 i, fc_idx;

	for (i = 0; i < WL_MEM_TRACE_KMALLOC_NUM; i++) {
		if (MemTraceKmalloc[i].addr == ptr) {
			fc_idx = MemTraceKmalloc[i].func_idx;
			MemTraceFunc[fc_idx].size -= MemTraceKmalloc[i].length;
			memset(&MemTraceKmalloc[i], 0, sizeof(mem_trace_unit));
			break;
		}
	}
	if (i == WL_MEM_TRACE_KMALLOC_NUM) {
		printk("%s line:%d ptr:%p can not found ptr in wl_util_kfree!!\n", func, line, ptr);
	}
	kernel_kfree(ptr);
#else /* MEMORY_USAGE_TRACE */
	kernel_kfree(ptr);
#endif /* MEMORY_USAGE_TRACE */
}

void *
wl_util_dma_alloc_coherent(struct device *dev, size_t size,
			   dma_addr_t * dma_handle, int flag, const char *func,
			   const int line)
{
#ifdef MEMORY_USAGE_TRACE
	void *ptr = NULL;
	UINT32 i, fc_idx;

	ptr = kernel_dma_alloc_coherent(dev, size, dma_handle, flag);
	if (ptr) {
		for (fc_idx = 0; fc_idx < WL_MEM_TRACE_FUNC_NUM; fc_idx++) {
			if (MemTraceFunc[fc_idx].size != 0 &&
			    !strcmp(func, MemTraceFunc[fc_idx].func) &&
			    MemTraceFunc[fc_idx].line == line) {
				/* find the same position */
				break;
			} else if (MemTraceFunc[fc_idx].size == 0) {
				/* End of Func */
				memset(MemTraceFunc[fc_idx].func, 0, 64);
				memcpy(MemTraceFunc[fc_idx].func, func,
				       (strlen(func) < 64) ? strlen(func) : 64);
				MemTraceFunc[fc_idx].line = line;
				MemTraceFunc[fc_idx].type = MEM_DMAALLOC;
				break;
			}
		}
		if (fc_idx >= WL_MEM_TRACE_FUNC_NUM) {
			printk("%s fc_idx out of bound %d\n", __func__,
			       WL_MEM_TRACE_FUNC_NUM);
			goto mem_ret;
		}

		for (i = 0; i < WL_MEM_TRACE_DMAALLOC_NUM; i++) {
			MT_Dmaalloc_max =
				MT_Dmaalloc_max >
				(i + 1) ? MT_Dmaalloc_max : (i + 1);
			if (!MemTraceDmaalloc[i].addr) {
				MemTraceDmaalloc[i].func_idx = fc_idx;
				MemTraceDmaalloc[i].addr = ptr;
				MemTraceDmaalloc[i].length = size;
				MemTraceFunc[fc_idx].size += size;
				break;
			}
		}
		if (i >= WL_MEM_TRACE_DMAALLOC_NUM) {
			printk("%s line:%d wl_util_dma_alloc_coherent out of bound %d\n", func, line, WL_MEM_TRACE_DMAALLOC_NUM);
		}
	}
mem_ret:
	return ptr;
#else /* MEMORY_USAGE_TRACE */
	return kernel_dma_alloc_coherent(dev, size, dma_handle, flag);
#endif /* MEMORY_USAGE_TRACE */
}

void
wl_util_dma_free_coherent(struct device *dev, size_t size, void *cpu_addr,
			  dma_addr_t dma_handle, const char *func,
			  const int line)
{
#ifdef MEMORY_USAGE_TRACE
	UINT32 i, fc_idx;

	for (i = 0; i < WL_MEM_TRACE_DMAALLOC_NUM; i++) {
		if (MemTraceDmaalloc[i].addr == cpu_addr) {
			fc_idx = MemTraceDmaalloc[i].func_idx;
			MemTraceFunc[fc_idx].size -= MemTraceDmaalloc[i].length;
			memset(&MemTraceDmaalloc[i], 0, sizeof(mem_trace_unit));
			break;
		}
	}
	if (i == WL_MEM_TRACE_DMAALLOC_NUM) {
		printk("%s line:%d ptr:%p can not found ptr in wl_util_dma_free_coherent!!\n", func, line, cpu_addr);
	}
	kernel_dma_free_coherent(dev, size, cpu_addr, dma_handle);
#else /* MEMORY_USAGE_TRACE */
	kernel_dma_free_coherent(dev, size, cpu_addr, dma_handle);
#endif /* MEMORY_USAGE_TRACE */
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
ssize_t
ap8x_kernel_read(struct file *file, void *buf, size_t count, loff_t * pos)
{
	mm_segment_t old_fs;
	ssize_t result;

	old_fs = get_fs();
	set_fs(get_ds());
	/* The cast to a user pointer is valid due to the set_fs() */
	result = vfs_read(file, (void __user *)buf, count, pos);
	set_fs(old_fs);
	return result;
}
#endif

u32
ap8x_get_free_sys_mem_info(void)
{
	unsigned long free_pages = wl_global_page_state(NR_FREE_PAGES);
	return (u32) ((free_pages * 100) / totalram_pages);
}

// ================================================================
#ifdef USE_TASKLET
void
mthread_init(m_thread * pparam)
{
	tasklet_init(&pparam->task_obj, pparam->handle_func,
		     pparam->phandle_param);
}

void
mthread_deinit(m_thread * pparam)
{
	tasklet_kill(&pparam->task_obj);
}

void
mthread_run(m_thread * pparam)
{
	tasklet_schedule(&pparam->task_obj);
}

#else
// USE_WORK_QUEUE
static void
mthread_wqfunc(struct work_struct *work)
{
	m_thread_obj *pparam = container_of(work, m_thread_obj, task_obj);
	pparam->handle_func(pparam->phandle_param);
	return;
}

void
mthread_init(m_thread * pparam)
{
	INIT_WORK(&pparam->task_obj, mthread_wqfunc);
}

void
mthread_deinit(m_thread * pparam)
{
	cancel_delayed_work(&pparam->task_obj);
	flush_workqueue(pparam->task_obj);
	destroy_workqueue(pparam->task_obj);
}

void
mthread_run(m_thread * pparam)
{
	schedule_work(&pparam->task_obj);
}

#endif //USE_TASKLET

/* if s_value == NULL, only return vag of nf */
SINT16
wl_util_get_nf(struct net_device *netdev, NfPathInfo_t * NF_path_p,
	       SINT16 * s_value)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	UINT8 i = 0, j = 0;
	UINT16 nf_value[MAX_RF_ANT_NUM] = { 0 };
	SINT16 nf_value_signed[MAX_RF_ANT_NUM] = { 0 };
	SINT16 signed_nf = 0;

	if (!priv) {
		return 0;
	}
	if (priv->master) {
		priv = NETDEV_PRIV_P(struct wlprivate, priv->master);
	}

	if (NF_path_p) {
		nf_value[0] = NF_path_p->a;
		nf_value[1] = NF_path_p->b;
		nf_value[6] = NF_path_p->g;
		nf_value[7] = NF_path_p->h;
		if (priv->devid == SCBT)	// W9064 is ABEF
		{
			nf_value[4] = NF_path_p->c;
			nf_value[5] = NF_path_p->d;
			nf_value[2] = NF_path_p->e;
			nf_value[3] = NF_path_p->f;
		} else {
			nf_value[2] = NF_path_p->c;
			nf_value[3] = NF_path_p->d;
			nf_value[4] = NF_path_p->e;
			nf_value[5] = NF_path_p->f;
		}

		for (i = 0; i < MAX_RF_ANT_NUM; i++) {
			if (nf_value[i] >= 2048) {
				nf_value_signed[i] =
					-((4096 - nf_value[i]) >> 4);
			} else {
				nf_value_signed[i] = nf_value[i] >> 4;
			}
			if (nf_value_signed[i] != 0) {
				signed_nf += nf_value_signed[i];
				j++;
			}
		}
		if (s_value) {
			memcpy(s_value, nf_value_signed,
			       sizeof(SINT16) * MAX_RF_ANT_NUM);
		}

		if (j) {
			signed_nf = do_div(signed_nf, j);
		} else {
			signed_nf = 0;
		}
	} else {
		u8 i;
		UINT32 val, temp = 0;
		for (i = 0; i < 8; i++) {
			/* read 8 times to get avarage value */
			wlRegBB(netdev, WL_GET, 0x67, (UINT32 *) & val);
			temp += val;
		}
		signed_nf = -(SINT16) (temp >> 3);
	}
	return signed_nf;
}

/* if s_value == NULL, only return vag of nf */
SINT16
wl_util_get_rssi(struct net_device * netdev, RssiPathInfo_t * RSSI_path_p,
		 SINT16 * s_value)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	UINT8 i = 0, j = 0;
	UINT16 rssi_value[MAX_RF_ANT_NUM] = { 0 };
	SINT16 rssi_value_signed[MAX_RF_ANT_NUM] = { 0 };
	SINT16 signed_rssi = 0;

	if (!priv) {
		return 0;
	}
	if (priv->master) {
		priv = NETDEV_PRIV_P(struct wlprivate, priv->master);
	}
	rssi_value[0] = RSSI_path_p->a;
	rssi_value[1] = RSSI_path_p->b;
	rssi_value[6] = RSSI_path_p->g;
	rssi_value[7] = RSSI_path_p->h;
	if (priv->devid == SCBT) {	// W9064 is ABEF
		rssi_value[4] = RSSI_path_p->c;
		rssi_value[5] = RSSI_path_p->d;
		rssi_value[2] = RSSI_path_p->e;
		rssi_value[3] = RSSI_path_p->f;
	} else {
		rssi_value[2] = RSSI_path_p->c;
		rssi_value[3] = RSSI_path_p->d;
		rssi_value[4] = RSSI_path_p->e;
		rssi_value[5] = RSSI_path_p->f;
	}

	signed_rssi = 0;
	i = 0;
	for (j = 0; j < MAX_RF_ANT_NUM; j++) {
		if (rssi_value[j] >= 2048)
			rssi_value_signed[j] = -((4096 - rssi_value[j]) >> 4);
		else
			rssi_value_signed[j] = rssi_value[j] >> 4;
		if (rssi_value_signed[j] != 0) {
			signed_rssi += rssi_value_signed[j];
			i++;
		}
	}
	if (s_value) {
		memcpy(s_value, rssi_value_signed,
		       sizeof(SINT16) * MAX_RF_ANT_NUM);
	}
	if (i) {
		do_div(signed_rssi, i);
	} else {
		signed_rssi = -96;
	}
	return signed_rssi;
}


void wl_util_lock(struct net_device *ndev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, ndev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;

	if (intmode == 0)
		return;
	spin_lock_irqsave(&wlpd_p->pcie_iolock, wlpd_p->ioflags);
}

void wl_util_unlock(struct net_device *ndev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, ndev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;

	if (intmode == 0)
		return;
	spin_unlock_irqrestore(&wlpd_p->pcie_iolock, wlpd_p->ioflags);
}

void wl_util_writel(struct net_device *ndev, u32 v, u32 *c)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, ndev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;

	if (intmode == 0) {
		writel(v, c);
		return;
	}
	spin_lock_irqsave(&wlpd_p->pcie_iolock, wlpd_p->ioflags);
	writel(v, c);
	if (wrdelay)
		udelay(wrdelay);
	spin_unlock_irqrestore(&wlpd_p->pcie_iolock, wlpd_p->ioflags);
}

u32 wl_util_readl(struct net_device *ndev, const volatile void *c)
{
	u32 v;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, ndev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;

	if (intmode == 0) {
		v = readl(c);
		return v;
	}
	spin_lock_irqsave(&wlpd_p->pcie_iolock, wlpd_p->ioflags);
	v = readl(c);
	if (rddelay)
		udelay(rddelay);
	spin_unlock_irqrestore(&wlpd_p->pcie_iolock, wlpd_p->ioflags);
	return v;
}

