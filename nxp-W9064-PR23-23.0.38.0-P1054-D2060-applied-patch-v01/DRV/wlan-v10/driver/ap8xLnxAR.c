/** @file ap8xLnxAR.c
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2019-2020 NXP
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
#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/wireless.h>
#include <linux/ieee80211.h>
#include <linux/ctype.h>

#include "ap8xLnxIntf.h"
#include "ap8xLnxAR.h"

//#define USE_NCBUF             1

// ================================================================
// TX AR
//

#if defined(TXACNT_REC) && defined (SOC_W906X)
// ================================================================
// << Tx accounting Record >>
// Ref: account_record_struct_v0.1.txt
//
typedef enum tx_ppdu_type {
	ppdu_host_gen_noack = 0,
	ppdu_host_gen_ack,
	ppdu_host_gen_ba,
	ppdu_sfw_gen,
	ppdu_txdone,
	ppdu_type_max
} TX_PPDU_TYPE;

typedef enum SMAC_ACNT_TXDONE_type {
	tacnt_txdone_ack = 0,
	tacnt_txdone_ba,
	tacnt_txdone_timeout,
	tacnt_txdone_type_max
} SMAC_ACNT_TXDONE_TYPE;

typedef struct {
	U32 msduPayloadAddr;
	U32 skbAddr;

	U32 userId:4;
	U32 rsvd1:28;

	//U32  rsvd2[2];
	U32 rsvd2;
} MSDU_RING_INFO_st;		//16 bytes

#endif //TXACNT_REC

#if defined(TXACNT_REC)
//#define TX_ACNT_PPDU_BUF_SIZE         32*(sizeof(SMAC_ACNT_TX_BUF_st))
//#define TX_ACNT_PPDU_BUF_SIZE         16*(sizeof(SMAC_ACNT_TX_BUF_st))
//#define TX_ACNT_PPDU_BUF_SIZE         8*(sizeof(SMAC_ACNT_TX_BUF_st))
#define TX_ACNT_PPDU_BUF_SIZE		(512*1024)

void
wlTAcntBufInit(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate *parent_wlpptr = GET_PARENT_PRIV(wlpptr);
	SMAC_CONFIG_st *p_smac_cfg = &parent_wlpptr->smacconfig;
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	dma_addr_t phys_addr;
	txacntppdu *ptxacntppdu = &(wlpd_p->acntTxAcntPpdu);

	wlpd_p->acntTxMsduRingSize = p_smac_cfg->acntTxMsduRingSize =
		SC5_TXQ_SIZE * sizeof(MSDU_RING_INFO_st);
	WLDBG_INFO(DBG_LEVEL_0, "%s(), acntTxMsduRingSize = %u\n", __func__,
		   p_smac_cfg->acntTxMsduRingSize);
#ifdef USE_NCBUF
	wlpd_p->acntTxMsduRingBaseAddr_v =
		(MSDU_RING_INFO_st *) wl_dma_alloc_coherent(wlpd_p->dev,
							    p_smac_cfg->
							    acntTxMsduRingSize,
							    &phys_addr,
							    wlpd_p->
							    dma_alloc_flags);
#else
	wlpd_p->acntTxMsduRingBaseAddr_v =
		(MSDU_RING_INFO_st *) wl_kmalloc(p_smac_cfg->acntTxMsduRingSize,
						 GFP_KERNEL);
	phys_addr =
		dma_map_single(wlpd_p->dev, wlpd_p->acntTxMsduRingBaseAddr_v,
			       p_smac_cfg->acntTxMsduRingSize, DMA_FROM_DEVICE);
#endif //USE_NCBUF
	p_smac_cfg->acntTxMsduRingBaseAddr = (U32) phys_addr;
	wlpd_p->acntTxMsduRingBaseAddr_p = (U32) phys_addr;
	WLDBG_INFO(DBG_LEVEL_0, "%s(), acntTxMsduRingBaseAddr = %x\n", __func__,
		   p_smac_cfg->acntTxMsduRingBaseAddr);

	// PPDU Tx Accounting Record
	ptxacntppdu->acntTxSize = p_smac_cfg->acntTxSize =
		TX_ACNT_PPDU_BUF_SIZE;

#ifdef USE_NCBUF
	// Using non-cacheable buffer
	ptxacntppdu->acntTxBaseAddr_v =
		(void *)wl_dma_alloc_coherent(wlpd_p->dev,
					      p_smac_cfg->acntTxSize,
					      &phys_addr,
					      wlpd_p->dma_alloc_flags);
#else
	// Using cacheable buffer
	ptxacntppdu->acntTxBaseAddr_v =
		(char *)wl_kmalloc(p_smac_cfg->acntTxSize, GFP_KERNEL);
	phys_addr =
		dma_map_single(wlpd_p->dev, ptxacntppdu->acntTxBaseAddr_v,
			       ptxacntppdu->acntTxSize, DMA_FROM_DEVICE);
#endif //

	ptxacntppdu->acntTxBaseAddr_p =
		p_smac_cfg->acntTxBaseAddr = (U32) phys_addr;

	WLDBG_INFO(DBG_LEVEL_0,
		   "%s(), acntTxBaseAddr (v, p)=(%p, %x), size=%x\n", __func__,
		   ptxacntppdu->acntTxBaseAddr_v, p_smac_cfg->acntTxBaseAddr,
		   p_smac_cfg->acntTxSize);

	ptxacntppdu->acntTxRdPtr_v = ptxacntppdu->acntTxBaseAddr_v;
	ptxacntppdu->acntTxRdPtr_p = &(parent_wlpptr->smacCfgAddr->acntTxRdPtr);
	// Initialize the buffer pointer
	p_smac_cfg->acntTxRdPtr = p_smac_cfg->acntTxWrPtr =
		p_smac_cfg->acntTxBaseAddr;
	return;
}

void
wlTAcntBufCleanUp(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	txacntppdu *ptxacntppdu = &(wlpd_p->acntTxAcntPpdu);

	if (ptxacntppdu->acntTxBaseAddr_v != NULL) {
#ifdef USE_NCBUF
		wl_dma_free_coherent(wlpd_p->dev,
				     ptxacntppdu->acntTxSize,
				     (void *)ptxacntppdu->acntTxBaseAddr_v,
				     ptxacntppdu->acntTxBaseAddr_p);
#else
		dma_unmap_single(wlpd_p->dev,
				 virt_to_phys(ptxacntppdu->acntTxBaseAddr_v),
				 ptxacntppdu->acntTxSize, DMA_FROM_DEVICE);
		wl_kfree(ptxacntppdu->acntTxBaseAddr_v);
#endif //USE_NCBUF
		WLDBG_INFO(DBG_LEVEL_0, "free acntRxInfoQueBaseAddr_v(%u)\n",
			   p_smac_cfg->acntRxInfoQueSize);
		ptxacntppdu->acntTxBaseAddr_v = NULL;
	}
	return;
}

#endif //defined(TXACNT_REC)
#if defined(TXACNT_REC)
extern unsigned int txacnt_idmsg;
#endif //defined(TXACNT_REC)

//#if defined(TXACNT_REC) && defined (SOC_W906X)
//static void _wlTAcnt(struct work_struct *work)
//{
//      struct wlprivate_data *wlpd_p = container_of(work, struct wlprivate_data, txtask);
//      struct wlprivate *wlpptr = wlpd_p->masterwlp;

//      wlTxPPDUAcntHndl(wlpptr->netDev);
//}
//#endif //#if defined(ACNT_REC) && defined (SOC_W906X)

#if defined(TXACNT_REC) && defined (SOC_W906X)
static void
wlTAcntHdlr(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	//tasklet_schedule(&wlpptr->wlpd_p->tacnttask);
	mthread_run(&wlpptr->wlpd_p->tacnttask);
	return;
}

#endif //#if defined(ACNT_REC) && defined (SOC_W906X)

#if defined(TXACNT_REC) && defined (SOC_W906X)
// Tx Accounting Record intr handler
irqreturn_t
wlSC5MSIX_TAcntRec(int irq, void *dev_id)
{
	struct msix_context *ctx = (struct msix_context *)dev_id;
	struct net_device *netdev = ctx->netDev;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p;
	unsigned int intStatus;
	int qid;
	UINT32 msg_id = ctx->msg_id;
	irqreturn_t retVal = IRQ_NONE;
	vmacSta_p = wlpptr->vmacSta_p;

	qid = msg_id >> 1;
	intStatus = 1 << qid;
	WLDBG_INFO(DBG_LEVEL_3,
		   "ISR: %s: qid %d %s, msg_id=%d, INTR_SHIFT=%d\n", __func__,
		   qid, (msg_id & 0x01) ? "SQ" : "RQ", msg_id,
		   wlpptr->wlpd_p->intr_shift);

	spin_lock(&wlpptr->wlpd_p->locks.intLock);
	wlpptr->TAcntQId |= intStatus;
	spin_unlock(&wlpptr->wlpd_p->locks.intLock);

	intStatus &= ~SC5_RX_MSIX_MASK;
	if ((msg_id & 0x01) == 0) {	//RQ = 0
		// ACNT handler...
		wlTAcntHdlr(netdev);
	}
	retVal = IRQ_HANDLED;

	return retVal;
}
#endif //#if defined(TXACNT_REC) && defined (SOC_W906X)

#if defined(TXACNT_REC)
extern unsigned int txacnt_msg;
extern unsigned int txacnt_idmsg;
inline void
wlTxAcntDbgMsg(struct wlprivate_data *wlpd_p, void *recbuf)
{
	txacntppdu *ptxacntppdu = &(wlpd_p->acntTxAcntPpdu);

	printk("Rec_Buf: %p\n", recbuf);
	printk("whole buffer (%p)\n", ptxacntppdu->acntTxBaseAddr_v);
	mwl_hex_dump(ptxacntppdu->acntTxBaseAddr_v, ptxacntppdu->acntTxSize);
	BUG_ON(1);
	return;
}

void
wlTxPPDUHdrHndl(struct net_device *netdev,
		SMAC_ACNT_TX_PPDU_HDR_st * ptxppdu_hdr)
{
	if (txacnt_msg > 0) {
		printk("SMAC_ACNT_TX_PPDU_HDR_st: (%p)\n", ptxppdu_hdr);
		mwl_hex_dump(ptxppdu_hdr, sizeof(SMAC_ACNT_TX_PPDU_HDR_st));
	}
	return;
}

void
wlTxPPDUUsrHndl(struct net_device *netdev,
		SMAC_ACNT_TX_HOST_USR_st * txppdu_usr)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	if (txacnt_msg > 0) {
		printk("SMAC_ACNT_TX_USER_HDR_st: (%p)\n", txppdu_usr);
		mwl_hex_dump(txppdu_usr, sizeof(SMAC_ACNT_TX_HOST_USR_st));
	}
	if (txppdu_usr->mpduHdr.userId >= TX_ACNT_USER_NUM) {
		printk("%s(), incorrect usr_id: %u, SMAC_ACNT_TX_HOST_USR_st=%p\n", __func__, txppdu_usr->mpduHdr.userId, txppdu_usr);
		wlTxAcntDbgMsg(wlpd_p, txppdu_usr);
	}
	return;
}

/*
	Function: wlTxPPDUTidHndle()
	- Record the pkt to be sent. 
	type:
		ppdu_host_gen_ack
		ppdu_host_gen_ba
*/
void
wlMacTxHostGenPPDUHndle(struct net_device *netdev,
			SMAC_ACNT_TX_MPDU_TID_INFO_st * txppdu_tidinfo,
			MSDU_RING_INFO_st ** pptx_msdu_info, U16 usrid, U8 type)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	U16 tid = txppdu_tidinfo->tid;
	U16 mpduid;

	if (tid >= DRV_TX_ACNT_MAX_NUM_TID) {
		printk("%s(), incorrect tid: %u, txppdu_tidinfo=%p\n", __func__,
		       tid, txppdu_tidinfo);
		wlTxAcntDbgMsg(wlpd_p, txppdu_tidinfo);
	}

	wlpd_p->startSeq[usrid][tid] = txppdu_tidinfo->startSeqCtrl;
	for (mpduid = 0; mpduid < TX_ACNT_MAX_NUM_AGGR; mpduid++) {
		U8 msduid;

		for (msduid = 0; msduid < txppdu_tidinfo->numMsdu[mpduid];
		     msduid++, (*pptx_msdu_info)++) {
			if ((U8 *) * pptx_msdu_info >=
			    ((U8 *) wlpd_p->acntTxMsduRingBaseAddr_v +
			     wlpd_p->acntTxMsduRingSize)) {
				// Out of the buffer size => reset it back
				*pptx_msdu_info =
					(MSDU_RING_INFO_st *) wlpd_p->
					acntTxMsduRingBaseAddr_v;
			}
			// If this skb has not been added to txacnt_skb_trace && it's not ppdu_host_gen_noack
		}
	}
	return;
}

/*
	wlMoveacntTxRdptr(): Update the read pointer
	- offset: offset to move
		>0 : move #offset forward
		<0 : Reset the pointer to base address
*/
inline void
wlMoveAcntTxRdptr(txacntppdu * ptxacntppdu, S32 offset)
{
	if (offset == RESET_ACNTRDPTR) {
		ptxacntppdu->acntTxRdPtr_v = ptxacntppdu->acntTxBaseAddr_v;
		*ptxacntppdu->acntTxRdPtr_p = ptxacntppdu->acntTxBaseAddr_p;
		goto funcfinal;
	}
	// Error checking
	if (((U32) (ptxacntppdu->acntTxRdPtr_v - ptxacntppdu->acntTxBaseAddr_v))
	    > ptxacntppdu->acntTxSize) {
		WLDBG_ERROR(DBG_LEVEL_0,
			    "(wlpd_p->acntTxRdPtr, base)=(%p, %p)is over limit %x, & not gettint reset mark (%x) => force to reset\n",
			    ptxacntppdu->acntTxRdPtr_v,
			    ptxacntppdu->acntTxBaseAddr_v,
			    ptxacntppdu->acntTxSize, PPDUACNT_END);
		WLDBG_ERROR(DBG_LEVEL_0, "wlpd_p->acntTxRdPtr_v = %x\n",
			    (*(U32 *) ptxacntppdu->acntTxRdPtr_v));

		ptxacntppdu->acntTxRdPtr_v = ptxacntppdu->acntTxBaseAddr_v;
		*ptxacntppdu->acntTxRdPtr_p = ptxacntppdu->acntTxBaseAddr_p;
	}
	// Move the rx-pointer
	ptxacntppdu->acntTxRdPtr_v = ptxacntppdu->acntTxRdPtr_v + offset;
	*ptxacntppdu->acntTxRdPtr_p = *ptxacntppdu->acntTxRdPtr_p + offset;
funcfinal:
	return;
}

/*
	Function:  wlMacTxDoneFreeMsdu()
	Description: Free all msdu of the mpdu in one [usr_id][tid]
*/
void
wlMacTxDoneFreeMsdu(struct wlprivate_data *wlpd_p, U16 usrid, U16 tid,
		    U8 bitmap[32])
{
	return;
}

/*
Function: wlMacTxDoneAckHndl()
	- SMAC TxAccount TxDone Handler, type=ACK
	
Condition: Confirmed by Allan on the mail at pm11:49 2018/7/6
For the Host tx with ACK conditions:
  - Retrying:
                 SMAC_ACNT_MPDU_BA_INFO_st->startSeqNum == 4095 (4095 AND numTimeout==0 is to indicate timeout, 4095 alone is a valid seqno)
  - Got Rx Acked:
                 SMAC_ACNT_MPDU_BA_INFO_st->numExpired == 0) && (SMAC_ACNT_MPDU_BA_INFO_st->startSeqNum == 0 (Correct)
  - No more retrying:
                 SMAC_ACNT_MPDU_BA_INFO_st->numExpired == 1 (Correct for timeout, startSeqNum will have the timeout seqno too)
*/
void
wlMacTxDoneAckHndl(struct wlprivate_data *wlpd_p,
		   SMAC_ACNT_MPDU_BA_INFO_st * txmpdu_bainfo, U16 usrid)
{
	U16 tid = txmpdu_bainfo->tid;
	if (tid >= DRV_TX_ACNT_MAX_NUM_TID) {	//==> Need to check
		printk("%s(), Invalid TID: %u, SMAC_ACNT_MPDU_BA_INFO_st=%p\n",
		       __func__, tid, txmpdu_bainfo);
		wlTxAcntDbgMsg(wlpd_p, txmpdu_bainfo);
	}
	// Got Rx Acked =>  free the packets
	if (txmpdu_bainfo->numExpired == 0) {
		U8 bitmap[32];
		memset(bitmap, 0xff, sizeof(bitmap));
		if (wlpd_p->startSeq[usrid][tid] != txmpdu_bainfo->startSeqNum) {
			txacntppdu *ptxacntppdu = &(wlpd_p->acntTxAcntPpdu);

			printk("(send, ack)=(%u, %u)\n",
			       wlpd_p->startSeq[usrid][tid],
			       txmpdu_bainfo->startSeqNum);
			mwl_hex_dump(txmpdu_bainfo,
				     sizeof(SMAC_ACNT_MPDU_BA_INFO_st));
			printk("%s(): Last (ppduinfo, txdone)=(%p, %p)\n",
			       __func__, wlpd_p->lastppduinfo,
			       wlpd_p->lasttxdoneinfo);
			printk("%s(), (%u, %u) (base, txmpdu_bainfo) = (%p, %p)\n", __func__, usrid, tid, ptxacntppdu->acntTxBaseAddr_v, txmpdu_bainfo);
			wlTxAcntDbgMsg(wlpd_p, txmpdu_bainfo);
		}
		wlMacTxDoneFreeMsdu(wlpd_p, usrid, tid, bitmap);
	}
	return;
}

/*
Function: wlMacTxDoneBAHndl()
	- SMAC TxAccount TxDone Handler, type=BA
	
Condition: Confirmed by Allan on the mail at pm11:49 2018/7/6
For the Host tx with ACK conditions:
  - Retrying:
                 SMAC_ACNT_MPDU_BA_INFO_st->numExpired == 0 (Correct, handled in baBitmap for Acked)
  - Got Rx BAed:
                 SMAC_ACNT_TX_MPDU_TID_INFO_st->startSeqCtrl = startSeqNum of SMAC_ACNT_MPDU_TID_INFO_st->startSeqNum
                                             => Need to check the bit map and free the acked packets (Correct)
  - No more retrying:
                 Pkt expired: txdone is timeout with numExpired to indicate no. of pkt has expired in baBitmap)
*/
void
wlMacTxDoneBAHndl(struct wlprivate_data *wlpd_p,
		  SMAC_ACNT_MPDU_BA_INFO_st * txmpdu_bainfo, U16 usrid)
{
	U16 tid = txmpdu_bainfo->tid;

	if (tid >= DRV_TX_ACNT_MAX_NUM_TID) {	//==> Need to check
		printk("%s(), Invalid TID: %u, SMAC_ACNT_MPDU_BA_INFO_st=%p\n",
		       __func__, tid, txmpdu_bainfo);
		wlTxAcntDbgMsg(wlpd_p, txmpdu_bainfo);
	}
#if 0
	// Retrying
	if (txmpdu_bainfo->numExpired == 0) {
		// Retrying, nothing to do
		return;
	} else
		// No more retrying =>  free the packets, will be handled in wlMacTxDoneTimeoutHndl()
	if (txmpdu_bainfo->numExpired == 1) {
	} else
#endif //0
		// Got Rx BA =>  free the packets
		// startSeqNum of BA may be different with the one of the tx pkt 
		/*
		   if (txmpdu_bainfo->startSeqNum != wlpd_p->startSeq[usrid][tid]) {
		   printk("%s, Inconsist startSeq: (%u, %u)\n", __func__,
		   txmpdu_bainfo->startSeqNum, wlpd_p->startSeq[usrid][tid]);
		   printk("%s(): Last (ppduinfo, txdone)=(%p, %p)\n", __func__, wlpd_p->lastppduinfo, wlpd_p->lasttxdoneinfo);
		   printk("[TXACNT] whole buffer (%p)\n", ptxacntppdu->acntTxBaseAddr_v);
		   mwl_hex_dump(ptxacntppdu->acntTxBaseAddr_v, ptxacntppdu->acntTxSize);
		   BUG_ON(1);
		   return;                              
		   } */

	if (txacnt_idmsg > 0) {
		U32 bitmap[4];
		memcpy(bitmap, txmpdu_bainfo->baBitmap, sizeof(U32) * 4);
		printk("%s(), BAed (startseq, bitmap)=(%u, %x - %x - %x - %x)\n", __func__, txmpdu_bainfo->startSeqNum, bitmap[3], bitmap[2], bitmap[1], bitmap[0]
			);
	}
	wlMacTxDoneFreeMsdu(wlpd_p, usrid, tid, txmpdu_bainfo->baBitmap);

	return;
}

void
wlMacTxDoneTimeoutHndl(struct wlprivate_data *wlpd_p,
		       SMAC_ACNT_MPDU_BA_INFO_st * txmpdu_bainfo, U16 usrid)
{
	U16 tid = txmpdu_bainfo->tid;

	// Retrying of ACKed pkt
	if ((txmpdu_bainfo->startSeqNum == 4095) &&
	    (txmpdu_bainfo->numExpired == 0)) {
		// Retrying, nothing to do
		return;
	}
	if (tid >= DRV_TX_ACNT_MAX_NUM_TID) {	//==> Need to check
		printk("%s(), Invalid TID: %u, SMAC_ACNT_MPDU_BA_INFO_st=%p\n",
		       __func__, tid, txmpdu_bainfo);
		wlTxAcntDbgMsg(wlpd_p, txmpdu_bainfo);
	}
	// Packet expired =>  free the packets
	if (txmpdu_bainfo->startSeqNum != wlpd_p->startSeq[usrid][tid]) {
		printk("%s(), Error, Inconsist start_seq (%u, %u)\n", __func__,
		       txmpdu_bainfo->startSeqNum,
		       wlpd_p->startSeq[usrid][tid]);
		printk("%s(): Last (ppduinfo, txdone)=(%p, %p)\n", __func__,
		       wlpd_p->lastppduinfo, wlpd_p->lasttxdoneinfo);
		wlTxAcntDbgMsg(wlpd_p, txmpdu_bainfo);
	}
	if (txacnt_idmsg > 0) {
		U32 bitmap[4];
		memcpy(bitmap, txmpdu_bainfo->baBitmap, sizeof(U32) * 4);
		printk("%s(), BAed (startseq, bitmap)=(%u, %x - %x - %x - %x)\n", __func__, txmpdu_bainfo->startSeqNum, bitmap[3], bitmap[2], bitmap[1], bitmap[0]
			);
	}
	wlMacTxDoneFreeMsdu(wlpd_p, usrid, tid, txmpdu_bainfo->baBitmap);

	return;
}

char *
ppdu_type_str(TX_PPDU_TYPE type)
{
	switch (type) {
	case ppdu_host_gen_noack:
		return "ppdu_host_gen_noack";
	case ppdu_host_gen_ack:
		return "ppdu_host_gen_ack";
	case ppdu_host_gen_ba:
		return "ppdu_host_gen_ba";
	case ppdu_sfw_gen:
		return "ppdu_sfw_gen";
	case ppdu_txdone:
		return "ppdu_txdone";
	default:
		return "";
	}
}

char *
mactxacnt_type_str(SMAC_ACNT_TXDONE_TYPE type)
{
	switch (type) {
	case tacnt_txdone_ack:
		return "tacnt_txdone_ack";
	case tacnt_txdone_ba:
		return "tacnt_txdone_ba";
	case tacnt_txdone_timeout:
		return "tacnt_txdone_timeout";
	default:
		return "";
	}
}

U32
wlGetTotalMsduIn_ppdu_tid(SMAC_ACNT_TX_MPDU_TID_INFO_st * txppdu_tidinfo,
			  U8 numTids)
{
	U16 tid;
	U32 mpduid;
	U32 totalNumMsdus = 0;

	for (tid = 0; tid < numTids; tid++, txppdu_tidinfo++) {
		for (mpduid = 0; mpduid < txppdu_tidinfo->numMpdu; mpduid++) {
			totalNumMsdus += txppdu_tidinfo->numMsdu[mpduid];
		}
	}
	return totalNumMsdus;
}

// tx ppdu accounting record handler (intr handler)
void
wlTxPPDUAcntHndl(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate *parent_wlpptr = GET_PARENT_PRIV(wlpptr);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	txacntppdu *ptxacntppdu = &(wlpd_p->acntTxAcntPpdu);
	SMAC_CONFIG_st *psmac_cfg = parent_wlpptr->smacCfgAddr;
	U8 *wrptr;
	U32 usedlen = 0;
	U16 tid;

	wl_util_lock(netdev);
	wrptr = ptxacntppdu->acntTxBaseAddr_v + (psmac_cfg->acntTxWrPtr -
						 ptxacntppdu->acntTxBaseAddr_p);
	
	if (txacnt_idmsg > 0) {
		printk("[TXACNT] ++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
		printk("[TXACNT] =>%s(), (base, rdptr, wrptr)=(%x, %x, %x) (%p, %p)\n", __func__, psmac_cfg->acntTxBaseAddr, psmac_cfg->acntTxRdPtr, psmac_cfg->acntTxWrPtr, ptxacntppdu->acntTxRdPtr_v, wrptr);
	}
	wl_util_unlock(netdev);
	while (ptxacntppdu->acntTxRdPtr_v != wrptr) {
		SMAC_ACNT_TX_PPDU_INFO_st *ptxppdu_info;
		SMAC_ACNT_TX_PPDU_HDR_st *ptxppdu_hdr;
		U16 usrid;

		if ((*(U32 *) ptxacntppdu->acntTxRdPtr_v) == PPDUACNT_END) {
			// The rest of the buffer is insufficient for next tx ppdu record => wr-ptr is resette
			if (txacnt_msg > 0) {
				wl_util_lock(netdev);
				printk("=> Get %x, at (%p, %x) reset rdptr\n",
				       PPDUACNT_END, ptxacntppdu->acntTxRdPtr_v,
				       psmac_cfg->acntTxRdPtr);
				wl_util_unlock(netdev);
			}

			wlMoveAcntTxRdptr(ptxacntppdu, RESET_ACNTRDPTR);
			usedlen = 0;
			continue;
		}
		// Touch the end of the buffer
		if ((U32)
		    (ptxacntppdu->acntTxRdPtr_v -
		     ptxacntppdu->acntTxBaseAddr_v) ==
		    ptxacntppdu->acntTxSize) {
			//Touch the end, reset the rd_ptr
			wlMoveAcntTxRdptr(ptxacntppdu, RESET_ACNTRDPTR);
			usedlen = 0;
			continue;
		}
		// Process 1 tx ppdu record
		ptxppdu_info =
			(SMAC_ACNT_TX_PPDU_INFO_st *) (ptxacntppdu->
						       acntTxRdPtr_v + usedlen);
		if (txacnt_idmsg > 0) {
			printk("=> Parsing at (%p), usedlen=%u\n", ptxppdu_info,
			       usedlen);
		}
		ptxppdu_hdr = &ptxppdu_info->hdr;
		usedlen += sizeof(SMAC_ACNT_TX_PPDU_HDR_st);

		// ToDo
		wlTxPPDUHdrHndl(netdev, ptxppdu_hdr);
		if (txacnt_idmsg > 0) {
			printk("[TXACNT] ==> numUsers == %d, SMAC_ACNT_TX_PPDU_HDR_st:(%p)\n", ptxppdu_hdr->numUsers, ptxppdu_hdr);
		}
		if ((ptxppdu_hdr->numUsers > 16) ||
		    (ptxppdu_hdr->numUsers == 0)) {
			printk("[TXACNT] Error ==> numUsers == %d, SMAC_ACNT_TX_PPDU_HDR_st:(%p)\n", ptxppdu_hdr->numUsers, ptxppdu_hdr);
			mwl_hex_dump(ptxppdu_hdr,
				     sizeof(SMAC_ACNT_TX_PPDU_HDR_st));
			printk("Last (ppduinfo, txdone)=(%p, %p)\n",
			       wlpd_p->lastppduinfo, wlpd_p->lasttxdoneinfo);
			wlTxAcntDbgMsg(wlpd_p, ptxppdu_hdr);
		}
		if (txacnt_idmsg > 0) {
			printk("ptxppdu_hdr->type: %u (%s)\n",
			       ptxppdu_hdr->type,
			       ppdu_type_str(ptxppdu_hdr->type));
		}
		wlpd_p->txacnt_ppdurec_cnt[ptxppdu_hdr->type]++;

		switch (ptxppdu_hdr->type) {
		case ppdu_host_gen_noack:
		case ppdu_host_gen_ack:
		case ppdu_host_gen_ba:
			{
				SMAC_ACNT_TX_HOST_PKT_st *pAcntTxHostPkt =
					(SMAC_ACNT_TX_HOST_PKT_st
					 *) (ptxacntppdu->acntTxRdPtr_v +
					     usedlen);
				MSDU_RING_INFO_st *ptx_msdu_info =
					(MSDU_RING_INFO_st *) ((U8 *) wlpd_p->
							       acntTxMsduRingBaseAddr_v
							       +
							       pAcntTxHostPkt->
							       msduWrPtr);
				usedlen +=
					offsetof(SMAC_ACNT_TX_HOST_PKT_st,
						 user);

				//DBG++
				wlpd_p->lastppduinfo = (U8 *) ptxppdu_hdr;
				//DBG--
				//printk("sizeof(wlpd_p->txacnt_skb)=%lu\n",sizeof(wlpd_p->txacnt_skb));
				for (usrid = 0; usrid < ptxppdu_hdr->numUsers;
				     usrid++) {
					SMAC_ACNT_TX_HOST_USR_st *txppdu_usr;
					U32 totalNumMsdus = 0;

					txppdu_usr =
						(SMAC_ACNT_TX_HOST_USR_st
						 *) (ptxacntppdu->
						     acntTxRdPtr_v + usedlen);
					usedlen +=
						offsetof
						(SMAC_ACNT_TX_HOST_USR_st,
						 mpduTid);

					// ToDo
					wlTxPPDUUsrHndl(netdev, txppdu_usr);
					if (txacnt_idmsg > 0) {
						printk("[TXACNT] (%p) UsrID:%u, tidCnt=%u\n", txppdu_usr, usrid, txppdu_usr->mpduHdr.numTids);
					}
					if ((txppdu_usr->mpduHdr.numTids > 8) ||
					    (txppdu_usr->mpduHdr.numTids ==
					     0)) {
						printk("[TXACNT] big tidCnt, SMAC_ACNT_TX_USER_HDR_st: (%p)\n", txppdu_usr);
						mwl_hex_dump(txppdu_usr,
							     sizeof
							     (SMAC_ACNT_TX_HOST_USR_st));
						printk("Last (ppduinfo, txdone)=(%p, %p)\n", wlpd_p->lastppduinfo, wlpd_p->lasttxdoneinfo);
						wlTxAcntDbgMsg(wlpd_p,
							       txppdu_usr);
					}

					if ((ptxppdu_hdr->type ==
					     ppdu_host_gen_noack) ||
					    (ptxppdu_hdr->type ==
					     ppdu_host_gen_ack) ||
					    (ptxppdu_hdr->type ==
					     ppdu_host_gen_ba)) {
						SMAC_ACNT_TX_MPDU_TID_INFO_st
							*txppdu_tidinfo;
						txppdu_tidinfo =
							(SMAC_ACNT_TX_MPDU_TID_INFO_st
							 *) (ptxacntppdu->
							     acntTxRdPtr_v +
							     usedlen);
						totalNumMsdus =
							wlGetTotalMsduIn_ppdu_tid
							(txppdu_tidinfo,
							 txppdu_usr->mpduHdr.
							 numTids);
						/*if (totalNumMsdus != txppdu_tidinfo->totalNumMsdus) {
						   //Debug checking => Make sure the totalNumMsdus is correct
						   printk("[TXACNT] (totalNumMsdus, tidinfo->totalNumMsdus)=(%u, %u), txppdu_tidinfo=%p\n", 
						   totalNumMsdus, txppdu_tidinfo->totalNumMsdus, txppdu_tidinfo);
						   printk("Last (ppduinfo, txdone)=(%p, %p)\n", wlpd_p->lastppduinfo, wlpd_p->lasttxdoneinfo);
						   wlTxAcntDbgMsg(wlpd_p, txppdu_tidinfo);
						   } */
						// Calculate the correct ptx_msdu_info
						ptx_msdu_info =
							(MSDU_RING_INFO_st
							 *) ((U8 *) wlpd_p->
							     acntTxMsduRingBaseAddr_v
							     +
							     ((pAcntTxHostPkt->
							       msduWrPtr +
							       wlpd_p->
							       acntTxMsduRingSize
							       -
							       totalNumMsdus *
							       sizeof
							       (MSDU_RING_INFO_st))
							      %
							      wlpd_p->
							      acntTxMsduRingSize));
						if (txacnt_idmsg > 0) {
							printk("[TXACNT] total: %u, [msduWrPtr, from]=[%u, %lu]\n", totalNumMsdus, pAcntTxHostPkt->msduWrPtr, ((pAcntTxHostPkt->msduWrPtr + wlpd_p->acntTxMsduRingSize - totalNumMsdus * sizeof(MSDU_RING_INFO_st)) % wlpd_p->acntTxMsduRingSize));
						}
					}
					for (tid = 0;
					     tid < txppdu_usr->mpduHdr.numTids;
					     tid++) {
						SMAC_ACNT_TX_MPDU_TID_INFO_st
							*txppdu_tidinfo;
						txppdu_tidinfo =
							(SMAC_ACNT_TX_MPDU_TID_INFO_st
							 *) (ptxacntppdu->
							     acntTxRdPtr_v +
							     usedlen);
						usedlen +=
							sizeof
							(SMAC_ACNT_TX_MPDU_TID_INFO_st);
						if (txacnt_idmsg > 0) {
							printk("[TXACNT] (%p) [%u], tid:%u, , type=%s(%u), startSeqNum=%u\n", txppdu_tidinfo, tid, txppdu_tidinfo->tid, ppdu_type_str(ptxppdu_hdr->type), ptxppdu_hdr->type, txppdu_tidinfo->startSeqCtrl);

						}
						if ((U8 *) ptx_msdu_info >=
						    ((U8 *) wlpd_p->
						     acntTxMsduRingBaseAddr_v +
						     wlpd_p->
						     acntTxMsduRingSize)) {
							// Out of the buffer size => reset it back
							ptx_msdu_info =
								(MSDU_RING_INFO_st
								 *) wlpd_p->
								acntTxMsduRingBaseAddr_v;
						}
						if (ptxppdu_hdr->type !=
						    ppdu_host_gen_noack) {
							wlMacTxHostGenPPDUHndle
								(netdev,
								 txppdu_tidinfo,
								 &ptx_msdu_info,
								 txppdu_usr->
								 mpduHdr.userId,
								 ptxppdu_hdr->
								 type);
						}

					}
				}
			}
			break;
		case ppdu_txdone:{
				for (usrid = 0; usrid < ptxppdu_hdr->numUsers;
				     usrid++) {
					SMAC_ACNT_TX_DONE_USR_st *txdone_usr =
						(SMAC_ACNT_TX_DONE_USR_st
						 *) (ptxacntppdu->
						     acntTxRdPtr_v + usedlen);
					usedlen +=
						offsetof
						(SMAC_ACNT_TX_DONE_USR_st,
						 baTid);
					//DBG++
					wlpd_p->lasttxdoneinfo =
						(U8 *) ptxppdu_hdr;
					//DBG--
					if (txdone_usr->userHdr.userId >=
					    TX_ACNT_USER_NUM) {
						printk("userId of ppdu_txdone is too big: %u\n", txdone_usr->userHdr.userId);
						wlTxAcntDbgMsg(wlpd_p,
							       txdone_usr);
					}
					wlpd_p->txacnt_txdone_cnt[txdone_usr->
								  userHdr.
								  userId]
						[txdone_usr->userHdr.type]++;
					if (txacnt_idmsg > 0) {
						printk("[TXACNT] TxDone, (%p) UsrID:%u, tidCnt=%u, type=%s(%u)\n", txdone_usr, txdone_usr->userHdr.userId, txdone_usr->userHdr.numTids, mactxacnt_type_str(txdone_usr->userHdr.type), txdone_usr->userHdr.type);
					}
					if ((txdone_usr->userHdr.numTids > 8) ||
					    (txdone_usr->userHdr.numTids ==
					     0)) {
						printk("[TXACNT] big tidCnt, SMAC_ACNT_TX_DONE_USR_st: (%p)\n", txdone_usr);
						mwl_hex_dump(txdone_usr,
							     sizeof
							     (SMAC_ACNT_TX_DONE_USR_st));
						printk("Last (ppduinfo, txdone)=(%p, %p)\n", wlpd_p->lastppduinfo, wlpd_p->lasttxdoneinfo);
						wlTxAcntDbgMsg(wlpd_p,
							       txdone_usr);
					}

					for (tid = 0;
					     tid < txdone_usr->userHdr.numTids;
					     tid++) {
						SMAC_ACNT_MPDU_BA_INFO_st
							*txmpdu_bainfo;

						txmpdu_bainfo =
							(SMAC_ACNT_MPDU_BA_INFO_st
							 *) (ptxacntppdu->
							     acntTxRdPtr_v +
							     usedlen);
						usedlen +=
							sizeof
							(SMAC_ACNT_MPDU_BA_INFO_st);
						if (txacnt_idmsg > 0) {
							printk("[TXACNT] TxDone, (%p) tid:%u, startSeqNum=%u, numExpired=%u\n", txmpdu_bainfo, tid, txmpdu_bainfo->startSeqNum, txmpdu_bainfo->numExpired);
							mwl_hex_dump
								(txmpdu_bainfo->
								 baBitmap,
								 sizeof(U8) *
								 32);
						}

						switch (txdone_usr->userHdr.
							type) {
						case tacnt_txdone_ack:
							wlMacTxDoneAckHndl
								(wlpd_p,
								 txmpdu_bainfo,
								 txdone_usr->
								 userHdr.
								 userId);
							break;
						case tacnt_txdone_ba:
							wlMacTxDoneBAHndl
								(wlpd_p,
								 txmpdu_bainfo,
								 txdone_usr->
								 userHdr.
								 userId);
							break;
						case tacnt_txdone_timeout:
							wlMacTxDoneTimeoutHndl
								(wlpd_p,
								 txmpdu_bainfo,
								 txdone_usr->
								 userHdr.
								 userId);
							break;
						default:
							printk("%s(), Error, Incorrect TxDone Type: %u\n", __func__, txdone_usr->userHdr.type);
							continue;
						}
					}
				}
			}
			break;
		case ppdu_sfw_gen:{
				usedlen +=
					offsetof(SMAC_ACNT_TX_FW_PKT_st, user);
				for (usrid = 0; usrid < ptxppdu_hdr->numUsers;
				     usrid++) {
					SMAC_ACNT_TX_FW_PKT_USR_st
						*txppdu_fw_usr;

					txppdu_fw_usr =
						(SMAC_ACNT_TX_FW_PKT_USR_st
						 *) (ptxacntppdu->
						     acntTxRdPtr_v + usedlen);
					usedlen +=
						offsetof
						(SMAC_ACNT_TX_FW_PKT_USR_st,
						 mpduInfo);

					{
						SMAC_ACNT_FW_PKT_INFO_st
							*txppdu_fwpkt_info;

						txppdu_fwpkt_info =
							(SMAC_ACNT_FW_PKT_INFO_st
							 *) (ptxacntppdu->
							     acntTxRdPtr_v +
							     usedlen);
						//usedlen += sizeof(SMAC_ACNT_FW_PKT_INFO_st);
						usedlen +=
							offsetof
							(SMAC_ACNT_FW_PKT_INFO_st,
							 Pkt80211) +
							txppdu_fwpkt_info->
							length;
						//if (txacnt_idmsg > 0) {
						//      printk("[TXACNT] usrId: %u, len=%u\n", 
						//              txppdu_fwpkt_info->userId, txppdu_fwpkt_info->length);
						//}
					}
				}
			}
			break;
		default:
			printk("====> Error, Unknown Tx Acnt Rec Type: %u\n",
			       ptxppdu_hdr->type);

		}

		// Update the rd-ptr
		wlMoveAcntTxRdptr(ptxacntppdu, usedlen);
		usedlen = 0;

		if (txacnt_msg > 0) {
			txacnt_msg--;
		}
	}

	if (txacnt_idmsg > 0) {
		wl_util_lock(netdev);
		printk("[TXACNT] <=%s(), (rd_v, wr_v)=(%p, %p), (rd_p, wr_p)=(%x, %x)\n", __func__, ptxacntppdu->acntTxRdPtr_v, wrptr, psmac_cfg->acntTxRdPtr, psmac_cfg->acntTxWrPtr);
		printk("[TXACNT] ----------------------------------------------------\n\n");
		wl_util_unlock(netdev);
		txacnt_idmsg--;
	}
	return;
}
#endif //#if defined(TXACNT_REC)

// ================================================================
// RX AR
//

/*
	wlMoveacntTxRdptr(): Update the read pointer
	- offset: offset to move
		>0 : move #offset forward
		<0 : Reset the pointer to base address
*/
inline void
wlMoveAcntRxRdptr(rxacntppdu * prxacntppdu, S32 offset)
{
	if (offset == RESET_ACNTRDPTR) {
		prxacntppdu->acntRxRdPtr_v = prxacntppdu->acntRxBaseAddr_v;
		*prxacntppdu->acntRxRdPtr_p = prxacntppdu->acntRxBaseAddr_p;
		goto funcfinal;
	}
	// Error checking
	if (((U32) (prxacntppdu->acntRxRdPtr_v - prxacntppdu->acntRxBaseAddr_v))
	    > prxacntppdu->acntRxSize) {
		WLDBG_ERROR(DBG_LEVEL_0,
			    "(wlpd_p->acntRxRdPtr, base)=(%p, %p)is over limit %x, & not gettint reset mark (%x) => force to reset\n",
			    prxacntppdu->acntRxRdPtr_v,
			    prxacntppdu->acntRxBaseAddr_v,
			    prxacntppdu->acntRxSize, PPDUACNT_END);
		WLDBG_ERROR(DBG_LEVEL_0, "wlpd_p->acntRxRdPtr_v = %x\n",
			    (*(U32 *) prxacntppdu->acntRxRdPtr_v));

		prxacntppdu->acntRxRdPtr_v = prxacntppdu->acntRxBaseAddr_v;
		*prxacntppdu->acntRxRdPtr_p = prxacntppdu->acntRxBaseAddr_p;
	}
	// Move the rx-pointer
	prxacntppdu->acntRxRdPtr_v = prxacntppdu->acntRxRdPtr_v + offset;
	*prxacntppdu->acntRxRdPtr_p = *prxacntppdu->acntRxRdPtr_p + offset;
funcfinal:
	return;
}

extern unsigned int rxacnt_idmsg;
void
wlRxPPDUAcntHndl(struct net_device *netdev)
{
#ifdef RXACNT_REC
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate *parent_wlpptr = GET_PARENT_PRIV(wlpptr);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	rxacntppdu *prxacntppdu = &(wlpd_p->acntRxAcntPpdu);
	DRV_RATE_HIST *prxRateHistogram = &wlpd_p->drvrxRateHistogram;
	SMAC_CONFIG_st *psmac_cfg = parent_wlpptr->smacCfgAddr;
	SMAC_CONFIG_st lsmac_cfg;
	U8 *wrptr;
	U32 usedlen = 0;
	U16 tid;
	U8 *bgn_rdpt = prxacntppdu->acntRxRdPtr_v;

	wl_util_lock(netdev);
	memcpy(&lsmac_cfg, psmac_cfg, sizeof(SMAC_CONFIG_st));
	wl_util_unlock(netdev);
	wrptr = prxacntppdu->acntRxBaseAddr_v + (psmac_cfg->acntRxWrPtr -
						 prxacntppdu->acntRxBaseAddr_p);

// test++
/*
	prxacntppdu->acntRxRdPtr_v = wrptr;
	*prxacntppdu->acntRxRdPtr_p = psmac_cfg->acntRxWrPtr;
	return;
*/
// test--

	if (rxacnt_idmsg > 0) {
		printk("[RXACNT] ++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
		wl_util_lock(netdev);
		printk("[RXACNT] =>%s(), (base, rdptr, wrptr)=(%x, %x, %x) (%p, %p)\n", __func__, psmac_cfg->acntRxBaseAddr, psmac_cfg->acntRxRdPtr, psmac_cfg->acntRxWrPtr, prxacntppdu->acntRxRdPtr_v, wrptr);
		wl_util_unlock(netdev);
		printk("[RXACNT] => lsmac: %x, %x\n", lsmac_cfg.acntRxRdPtr,
		       lsmac_cfg.acntRxWrPtr);
	}

	while (prxacntppdu->acntRxRdPtr_v != wrptr) {
		if ((*(U32 *) prxacntppdu->acntRxRdPtr_v) == PPDUACNT_END) {
			// The rest of the buffer is insufficient for next tx ppdu record => wr-ptr is resette
			if (rxacnt_idmsg > 0) {
				wl_util_lock(netdev);
				printk("=> Get %x, at (%p, %x) reset rdptr\n",
				       PPDUACNT_END, prxacntppdu->acntRxRdPtr_v,
				       psmac_cfg->acntRxRdPtr);
				wl_util_unlock(netdev);
			}

			wlMoveAcntRxRdptr(prxacntppdu, RESET_ACNTRDPTR);
			usedlen = 0;
			continue;
		}
		// Touch the end of the buffer
		if ((U32)
		    (prxacntppdu->acntRxRdPtr_v -
		     prxacntppdu->acntRxBaseAddr_v) ==
		    prxacntppdu->acntRxSize) {
			// Touch the end, reset the rd_ptr
			wlMoveAcntRxRdptr(prxacntppdu, RESET_ACNTRDPTR);
			usedlen = 0;
			continue;
		}

		{
			SMAC_ACNT_RX_PPDU_INFO_st *prxppdu_info;
			SMAC_ACNT_RX_PPDU_HDR_st *prxppdu_hdr;
			U16 usrid;
			// Process 1 rx ppdu record
			prxppdu_info =
				(SMAC_ACNT_RX_PPDU_INFO_st *) (prxacntppdu->
							       acntRxRdPtr_v +
							       usedlen);
			prxppdu_hdr = &prxppdu_info->ppduHdr;
			if (rxacnt_idmsg > 0) {
				printk("prxppdu_info: %p, prxppdu_hdr=%p usedlen=%x\n", prxppdu_info, prxppdu_hdr, usedlen);
			}
			usedlen += offsetof(SMAC_ACNT_RX_PPDU_INFO_st, user);
			if ((prxppdu_hdr->numUsers > 16) ||
			    (prxppdu_hdr->numUsers == 0)) {
				printk("[RXACNT] Error ==> numUsers == %d, SMAC_ACNT_RX_PPDU_HDR_st:(%p)\n", prxppdu_hdr->numUsers, prxppdu_hdr);
				mwl_hex_dump(prxppdu_info,
					     sizeof(SMAC_ACNT_RX_PPDU_INFO_st));
				//printk("Last (ppduinfo, txdone)=(%p, %p)\n", wlpd_p->lastppduinfo, wlpd_p->lasttxdoneinfo);
				//wlTxAcntDbgMsg(wlpd_p, ptxppdu_hdr);

				printk("Force to leave.....\n");
				printk("Buffer to check: (r, w)=(%p, %p)\n",
				       bgn_rdpt, wrptr);
				if (bgn_rdpt < wrptr) {
					mwl_hex_dump(bgn_rdpt,
						     (wrptr - bgn_rdpt));
				}
				prxacntppdu->acntRxRdPtr_v = wrptr;
				*prxacntppdu->acntRxRdPtr_p =
					lsmac_cfg.acntRxWrPtr;

				return;
			}
			if (rxacnt_idmsg > 0) {
				printk("usedlen: %u\n", usedlen);
				printk("prxppdu_hdr: %p, sizeof(SMAC_ACNT_RX_PPDU_HDR_st)=%lu\n", prxppdu_hdr, sizeof(SMAC_ACNT_RX_PPDU_HDR_st));
				mwl_hex_dump(prxppdu_hdr,
					     sizeof(SMAC_ACNT_RX_PPDU_HDR_st));
			}
			for (usrid = 0; usrid < prxppdu_hdr->numUsers; usrid++) {
				//SMAC_ACNT_RX_PPDU_USER_st *prxppdu_usr = &prxppdu_info->user[usrid];
				//usedlen += sizeof(SMAC_ACNT_RX_PPDU_USER_st);
				switch (prxppdu_hdr->mpduType) {
				case 0:{	// Mgmt
						SMAC_ACNT_RX_MGMT_MPDU_st
							*prxmpdu =
							(SMAC_ACNT_RX_MGMT_MPDU_st
							 *) (prxacntppdu->
							     acntRxRdPtr_v +
							     usedlen);
						//SMAC_ACNT_RX_MGMT_MPDU_st     *prxmpdu = &prxppdu_usr->u.mgmt;
						usedlen +=
							sizeof
							(SMAC_ACNT_RX_MGMT_MPDU_st);
						prxRateHistogram->pkt_cnt[0]++;
						// TBD: Processing SMAC_ACNT_RX_MGMT_MPDU_st
						if (rxacnt_idmsg > 0) {
							printk("Mgmt, prxmpdu: %p\n", prxmpdu);

							mwl_hex_dump(prxmpdu,
								     sizeof
								     (SMAC_ACNT_RX_MGMT_MPDU_st));
						}
					}
					break;
				case 1:{	// Ctrl
						SMAC_ACNT_RX_CTRL_MPDU_st
							*prxmpdu =
							(SMAC_ACNT_RX_CTRL_MPDU_st
							 *) (prxacntppdu->
							     acntRxRdPtr_v +
							     usedlen);
						//SMAC_ACNT_RX_CTRL_MPDU_st     *prxmpdu = &prxppdu_usr->u.ctrl;
						usedlen +=
							sizeof
							(SMAC_ACNT_RX_CTRL_MPDU_st);
						prxRateHistogram->pkt_cnt[1]++;
						// TBD: Processing SMAC_ACNT_RX_CTRL_MPDU_st
						if (rxacnt_idmsg > 0) {
							printk("Ctrl, prxmpdu: %p\n", prxmpdu);

							mwl_hex_dump(prxmpdu,
								     sizeof
								     (SMAC_ACNT_RX_CTRL_MPDU_st));
						}
					}
					break;
				case 2:{	// Data
						SMAC_ACNT_RX_DATA_MPDU_st
							*prxmpdu =
							(SMAC_ACNT_RX_DATA_MPDU_st
							 *) (prxacntppdu->
							     acntRxRdPtr_v +
							     usedlen);
						//SMAC_ACNT_RX_DATA_MPDU_st     *prxmpdu = &prxppdu_usr->u.data;
						usedlen +=
							offsetof
							(SMAC_ACNT_RX_DATA_MPDU_st,
							 mpduTid);
						prxRateHistogram->pkt_cnt[2]++;
						// TBD: Processing SMAC_ACNT_RX_DATA_MPDU_st
						for (tid = 0;
						     tid < prxmpdu->numTids;
						     tid++) {
							SMAC_ACNT_RX_MPDU_TID_INFO_st
								*prxmpdu_tid =
								&prxmpdu->
								mpduTid[tid];
							usedlen +=
								sizeof
								(SMAC_ACNT_RX_MPDU_TID_INFO_st);

							// TBD: Processing SMAC_ACNT_RX_MPDU_TID_INFO_st
							if (rxacnt_idmsg > 0) {
								printk("Dat[%u], prxmpdu_tid: %p\n", tid, prxmpdu_tid);
								mwl_hex_dump
									(prxmpdu_tid,
									 sizeof
									 (SMAC_ACNT_RX_MPDU_TID_INFO_st));
							}
						}
					}
					break;
				}
			}
		}

		if (rxacnt_idmsg > 0) {
			printk("[RXACNT] wlMoveAcntRxRdptr (rd_v, wr_v)=(%p, %p), move: %u\n", prxacntppdu->acntRxRdPtr_v, wrptr, usedlen);
			printk("[RXACNT] ----------------------------------------------------\n\n");
		}
		// Update the rd-ptr
		wlMoveAcntRxRdptr(prxacntppdu, usedlen);
		usedlen = 0;

	}

	if (rxacnt_idmsg > 0) {
		printk("[RXACNT] <=%s(), (rd_v, wr_v)=(%p, %p), (rd_p, wr_p)=(%x, %x)\n", __func__, prxacntppdu->acntRxRdPtr_v, wrptr, psmac_cfg->acntRxRdPtr, psmac_cfg->acntRxWrPtr);
		printk("[RXACNT] ----------------------------------------------------\n\n");
		rxacnt_idmsg--;
	}
#endif //RXACNT_REC
	return;
}

void
wlRxAcntPPDUBufInit(struct net_device *netdev)
{
#ifdef RXACNT_REC
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	struct wlprivate *parent_wlpptr = GET_PARENT_PRIV(wlpptr);
	SMAC_CONFIG_st *p_smac_cfg = &parent_wlpptr->smacconfig;
	dma_addr_t phys_addr;
	rxacntppdu *prxacntppdu = &(wlpd_p->acntRxAcntPpdu);

	// PPDU Rx Accounting Record
	prxacntppdu->acntRxSize = p_smac_cfg->acntRxSize =
		RX_ACNT_PPDU_BUF_SIZE;
#ifdef USE_NCBUF
	// Using non-cacheable buffer
	prxacntppdu->acntRxBaseAddr_v =
		(void *)wl_dma_alloc_coherent(wlpd_p->dev,
					      p_smac_cfg->acntRxSize,
					      &phys_addr,
					      wlpd_p->dma_alloc_flags);
#else
	// Using cacheable buffer
	prxacntppdu->acntRxBaseAddr_v =
		(char *)wl_kmalloc(p_smac_cfg->acntRxSize, GFP_KERNEL);
	phys_addr =
		dma_map_single(wlpd_p->dev, prxacntppdu->acntRxBaseAddr_v,
			       prxacntppdu->acntRxSize, DMA_FROM_DEVICE);
#endif //
	prxacntppdu->acntRxBaseAddr_p =
		p_smac_cfg->acntRxBaseAddr = (U32) phys_addr;
	WLDBG_INFO(DBG_LEVEL_0,
		   "%s(), acntRxBaseAddr (v, p)=(%p, %x), size=%x\n", __func__,
		   prxacntppdu->acntRxBaseAddr_v, p_smac_cfg->acntRxBaseAddr,
		   p_smac_cfg->acntRxSize);

	prxacntppdu->acntRxRdPtr_v = prxacntppdu->acntRxBaseAddr_v;
	prxacntppdu->acntRxRdPtr_p = &(parent_wlpptr->smacCfgAddr->acntRxRdPtr);
	// Initialize the buffer pointer
	p_smac_cfg->acntRxRdPtr = p_smac_cfg->acntRxWrPtr =
		p_smac_cfg->acntRxBaseAddr;

#endif //RXACNT_REC
	return;
}

void
wlRxAcntPPDUCleanup(struct net_device *netdev)
{
#ifdef RXACNT_REC
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	struct wlprivate *parent_wlpptr = GET_PARENT_PRIV(wlpptr);
	SMAC_CONFIG_st *p_smac_cfg = &parent_wlpptr->smacconfig;
	rxacntppdu *prxacntppdu = &(wlpd_p->acntRxAcntPpdu);

#ifdef RXACNT_REC
	if (prxacntppdu->acntRxBaseAddr_v != NULL) {
#ifdef USE_NCBUF
		// Using non-cacheable buffer
		wl_dma_free_coherent(wlpd_p->dev,
				     p_smac_cfg->acntRxSize,
				     prxacntppdu->acntRxBaseAddr_v,
				     prxacntppdu->acntRxBaseAddr_p);
#else
		// Using cacheable buffer
		dma_unmap_single(wlpd_p->dev, prxacntppdu->acntRxBaseAddr_p,
				 p_smac_cfg->acntRxSize, DMA_FROM_DEVICE);
		wl_kfree(prxacntppdu->acntRxBaseAddr_v);
#endif //
		WLDBG_INFO(DBG_LEVEL_0, "free acntRxBaseAddr_v(%u)\n",
			   p_smac_cfg->acntRxSize);
		prxacntppdu->acntRxBaseAddr_v = NULL;
	}
#endif //RXACNT_REC
#endif //RXACNT_REC
	return;
}

#ifdef RXACNT_REC
irqreturn_t
wlSC5MSIX_RAcntRec(int irq, void *dev_id)
{
	struct msix_context *ctx = (struct msix_context *)dev_id;
	struct net_device *netdev = ctx->netDev;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p;
	unsigned int intStatus;
	int qid;
	UINT32 msg_id = ctx->msg_id;
	irqreturn_t retVal = IRQ_NONE;
	vmacSta_p = wlpptr->vmacSta_p;

	qid = msg_id >> 1;
	intStatus = 1 << qid;
	WLDBG_INFO(DBG_LEVEL_3,
		   "ISR: %s: qid %d %s, msg_id=%d, INTR_SHIFT=%d\n", __func__,
		   qid, (msg_id & 0x01) ? "SQ" : "RQ", msg_id,
		   wlpptr->wlpd_p->intr_shift);

	spin_lock(&wlpptr->wlpd_p->locks.intLock);
	wlpptr->RAcntQId |= intStatus;
	spin_unlock(&wlpptr->wlpd_p->locks.intLock);

	intStatus &= ~SC5_RX_MSIX_MASK;
	if ((msg_id & 0x01) == 0) {	//RQ = 0
		// ACNT handler...
		wlRAcntHdlr(netdev);
	}
	retVal = IRQ_HANDLED;

	return retVal;
}
#endif // RXACNT_REC
