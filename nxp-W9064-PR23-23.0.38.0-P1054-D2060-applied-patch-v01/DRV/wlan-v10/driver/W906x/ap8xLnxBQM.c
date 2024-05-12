/** @file ap8xLnxBQM.c
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
#define TARGET_W9064	1
/** include files **/
#include "ap8xLnxDesc.h"
#include "ap8xLnxBQM.h"
#include "ap8xLnxIntf.h"
#include "ap8xLnxFwcmd.h"
#include "ap8xLnxUtil.h"
#include "ap8xLnxXmit.h"
#include "wldebug.h"
#include "ap8xLnxIoctl.h"
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/slab.h>
#include <linux/mm.h>		/* mmap related stuff */
#include <linux/workqueue.h>
#include "ap8xLnxRegs.h"
#include <linux/random.h>
#include <linux/ieee80211.h>
#include <linux/ip.h>
#include <linux/kmsg_dump.h>
#include <linux/of_address.h>
/* default settings */
#include "ap8xLnxRecv.h"
#include "wlApi.h"

u32 recovered_errcfhul = 0;

/** local definitions **/
#define BUF_ALIGNM                      128

//#ifdef SCBT_QM
#define SCBT_TXQ_START_INDEX     6
#define SCBT_TXQ_NUM             4
//#else
#define SC5_TXQ_START_INDEX     8
#define SC5_TXQ_NUM             2
//#endif

//#ifdef SCBT_QM
// SQ10, SQ11, SQ12, SQ13 are release buffer queue for SCBT.
#define SCBT_BMQ_RELEASE_INDEX   10
#define SCBT_BMQ_RELEASE_NUM     4
//#else  // SC5_QM
#define SC5_BMQ_RELEASE_INDEX   14
#define SC5_BMQ_RELEASE_NUM     1

#if defined(ACNT_REC)
#define RXACNTQ_INDEX				15
#define RXACNTQ_NUM					1
#endif //#if defined(ACNT_REC)
//#endif

//#ifdef SCBT_QM
#define SCBT_TX_MSIX_MASK                      0x000003C0
#define SCBT_BUF_RELEASE_MSIX_MASK             0x00003C00
//#else
#define SC5_TX_MSIX_MASK                      0x00000300
#define SC5_BUF_RELEASE_MSIX_MASK             0x00004000
#if defined(ACNT_REC)
#define RACNTQ_MSIX_MASK						0X00008000
#define RXACNT_INTRID							28
#endif //#if defined(ACNT_REC)
#if defined(TXACNT_REC)
#define	TXACNT_INTRID							30
#endif //TXACNT_REC
//#endif
//#define SC5_BMQ_LAST_Q   (SC5_BMQ_RELEASE_INDEX   + SC5_BMQ_RELEASE_NUM)

//PFW DMEM memory size. Extracted from shal_cpu.h
#define DMEM_SIZE_SC5_SCBT_A0          (1168 * 1024)
#define DMEM_SIZE_SCBT_Z0              (1088 * 1024)
#define DMEM_SIZE_SC5_Z0_Z1            (896 * 1024)

//Note: open it later when fw send correct mrvl header format
#define LONG_PKTSIZE    1500
#define ETHER_TYPE_LEN	2	/* length of the Ethernet type field */
#define ETHER_HDR_LEN	(IEEEtypes_ADDRESS_SIZE * 2 + ETHER_TYPE_LEN)
#define LLC_HDR_LEN		8
#define IP_HDR_LEN		20
#define ICMP_HDR_LEN	8

#define	BUF_8K			0x2000
#define	BUF_16K			0x4000
#define	BUF_2M			0x200000
#define	BUF_64M			0x4000000
#define	BUF_96M			0x6000000

#define MSGBIT_TXPKT	0x1
#define MSGBIT_TXDESC	0x2
#define MSGBIT_RXPKT	0x4
#define MSGBIT_RXDESC	0x8

//#define       TX_DELAY                1000

static bm_pe_hw_t g_last_pe;

#define pe_addr_valid(pa) (pfn_valid(pa >> PAGE_SHIFT) && (pa != 0))

/** external functions **/
void post_init_bq_idx(struct net_device *netdev, bool is_init);
void wlCfhDlDump(wltxdesc_t * cfh_dl);

//the structure store cloned skb that was tx to fw
//the skb entris will be free in txdone.
typedef struct _wl_cloned_skb_list {
	//struct list_head list;  //note: must be the first entry of the structure
	dma_addr_t bufaddr;
	dma_addr_t skbaddr[(NUMOFAPS + 1) * MAX_CARDS_SUPPORT];
	UINT32 AddIdx;
	UINT32 RmIdx;
} wl_cloned_skb_list;

extern unsigned int dbg_invalid_skb;

static void wlget_extmembuf(struct wlprivate *wlpptr,
			    struct _ext_membuf *pext_membuf);
static void wlclean_extmembuf(struct wlprivate *wlpptr,
			      struct _ext_membuf *pext_membuf);
void wl_show_pktcnt_stat(struct net_device *netdev, char *sysfs_buff);
static void wl_show_generic_info(struct net_device *netdev, char *sysfs_buff);
void wl_show_except_cnt(struct net_device *netdev, char *sysfs_buff);
static void wl_show_hframe_info(struct net_device *netdev, char *sysfs_buff);

extern void wlmon_log_bmq_buff_refill(struct net_device *netdev, UINT32 qid,
				      UINT32 refill_cnt);
extern unsigned int dbg_level;
/** internal functions **/

/** public data **/
UINT32 drv_self_test_qid_enable = 0;
UINT32 drv_self_test_qid = 0;
//UINT32 txq_drv_release_cnt[4] = { 0 };
//UINT32 bmq13_refill_cnt = 0;
//u32 qidcnt[3] = { 0, 0, 0 };
/** private data **/
static const u_int32_t rx_q_size[SC5_RXQ_NUM] =
	{ SC5_RXQ_SIZE, SC5_RXQ_SIZE, SC5_RXQ_SIZE, SC5_RXQ_SIZE, SC5_RXQ_SIZE,
	SC5_RXQ_SIZE, SC5_RXQ_SIZE, SC5_RXQ_SIZE, SC5_PROMQ_SIZE, SC5_RMGTQ_SIZE
};

static const u_int32_t scbt_tx_q_size[SCBT_TXQ_NUM] =
	{ SC5_TXQ_SIZE, SC5_TXQ_SIZE, SC5_TXQ_SIZE, SC5_TXQ_SIZE };
static const u_int32_t sc5_tx_q_size[SC5_TXQ_NUM] =
	{ SC5_TXQ_SIZE, SC5_TXQ_SIZE };
static const u_int32_t bm_q_size[SC5_BMQ_NUM] =
	{ SC5_BMQ_SIZE, SC5_BMQ_SIZE, SC5_BMQ_SIZE, SC5_BMQ13_SIZE };
static const u_int32_t scbt_relbuf_q_size[SCBT_BMQ_RELEASE_NUM] =
	{ SC5_RELQ_SIZE, SC5_RELQ_SIZE, SC5_RELQ_SIZE, SC5_RELQ_SIZE };
static const u_int32_t buf_pool_size[SC5_BMQ_NUM] = { 0x1000, 0x3000, 0x6400, BUF_8K };	// 4k, 12k, 25k 8k,
const u_int32_t buf_pool_max_entries[SC5_BMQ_NUM] =
	{ 0x6000, 0x3000, 0x1000, 0 };
static const u_int32_t sc5_relbuf_q_size[SC5_BMQ_RELEASE_INDEX] =
	{ SC5_RELQ_SIZE };

#if defined(ACNT_REC)
static const u_int32_t racnt_q_size[1] = { RACNTQ_SIZE };
#endif //#if defined(ACNT_REC)

u32 BF_Buf_Size = BUF_64M;
u32 L0L1_Buf_Size = BUF_96M;

/** private functions **/
static void check_queue_index(struct net_device *netdev, u16 qid, int qoff);
static int _wlRxBufFill(struct net_device *netdev, int qid);
static void reset_signature(u8 * skb_addr);
static void dbgskb_init(struct net_device *netdev);
static void dbgskb_deinit(struct net_device *netdev);
/*
	Destroy the signature of the skb
 */
static void
reset_signature(u8 * skb_addr)
{
	u8 *skb_hd = skb_addr - SKB_INFO_SIZE;

	*((u32 *) skb_hd) = 0x55aa55aa;
	*((u32 *) (skb_hd + 4)) = 0xdeadbeef;
	*((u32 *) (skb_hd + 8)) = 0xabcd1234;
}

BOOLEAN
wlSQIndexGet(wl_qpair_sq_t * sq)
{
	if (isSQEmpty(sq) == FALSE) {
		spin_lock_bh(&sq->inx_lock);
		sq->rdinx = (sq->rdinx + 1) % sq->qsize;
		spin_unlock_bh(&sq->inx_lock);
		return TRUE;
	}
	WLDBG_WARNING(DBG_LEVEL_0, "QINDEX: Get SQ is empty (%d, %d)\n",
		      sq->rdinx, sq->wrinx);
	return FALSE;
}

BOOLEAN
wlSQIndexPut(wl_qpair_sq_t * sq)
{
	if (isSQFull(sq) == FALSE) {
		spin_lock_bh(&sq->inx_lock);
		sq->wrinx = (sq->wrinx + 1) % sq->qsize;
		spin_unlock_bh(&sq->inx_lock);
		return TRUE;
	}
	WLDBG_WARNING(DBG_LEVEL_0, "QINDEX: Put SQ is full (%d, %d)\n",
		      sq->rdinx, sq->wrinx);
	return FALSE;
}

BOOLEAN
wlRQIndexGet(wl_qpair_rq_t * rq)
{
	if (isRQEmpty(rq) == FALSE) {
		spin_lock_bh(&rq->inx_lock);
		rq->rdinx = (rq->rdinx + 1) % rq->qsize;
		spin_unlock_bh(&rq->inx_lock);
		return TRUE;
	}
	WLDBG_WARNING(DBG_LEVEL_0, "QINDEX: Get RQ is empty (%d, %d)\n",
		      rq->rdinx, rq->wrinx);
	return FALSE;
}

BOOLEAN
wlRQIndexPut(u16 qid, wl_qpair_rq_t * rq)
{
	if (isRQFull(rq) == FALSE) {
		spin_lock_bh(&rq->inx_lock);
		rq->wrinx = (rq->wrinx + 1) % rq->qsize;
		spin_unlock_bh(&rq->inx_lock);
		return TRUE;
	}
	WLDBG_WARNING(DBG_LEVEL_0,
		      "QINDEX: Put RQ(%d) is full (rdinx, wrinx) = (%d, %d)\n",
		      qid, rq->rdinx, rq->wrinx);
	return FALSE;
}

static inline u32
wlGetDescSize(struct bqm_args *pbqm_args, u16 qid, int qoff)
{
	u32 qelm_size;

	// Input parameter checking
	if ((NUM_OF_HW_DESCRIPTOR_DATA <= qid) ||
	    (max_qpair <= (QPAIR) qoff) || (pbqm_args == NULL)) {
		//Fatal Error: Should not be here sinze the qid/qoff combination is unrecognized
		printk("Fatal Error: Failed to find descriptor size of the queue at (qid, type)=(%u, %d)\n", qid, qoff);
		WARN_ON(1);
		return INVALID_QSIZE;
	}
	qelm_size = pbqm_args->q_elmsize_tbl.elm_size[qid][qoff];
	if (qelm_size == INVALID_QSIZE) {
		//Fatal Error: Should not be here sinze the qid/qoff combination is unrecognized
		printk("Fatal Error: Failed to find descriptor size of the queue at %s(%u)\n", ((qoff == SC5_SQ) ? ("SQ") : ("RQ")), qid);

		WARN_ON(1);
	}
	return qelm_size;
}

u32
wlQueryRdPtr(struct net_device * netdev, int qid, int qoff)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	struct bqm_args *pbqm_args = &wlpd_p->bmq_args;

	struct wldesc_data *wlqm;
	u32 regval;
	u32 desc_size = wlGetDescSize(pbqm_args, (u16) qid, qoff);
	u32 orig_rdinx;
	u32 idx_val, qsize;

	WLDBG_INFO(DBG_LEVEL_5,
		   "QINDEX(%d), desc_size from wlGetDescSize() = %d\n", qid,
		   desc_size);

	wlqm = &wlpptr->wlpd_p->descData[qid];
	if (qoff == SC5_RQ) {
		orig_rdinx = wlqm->rq.rdinx;
		regval = wl_util_readl(netdev, wlpptr->ioBase1 + SC5_RQ_RDPTR_REG(qid));
		qsize = wlqm->rq.qsize;
		WLDBG_INFO(DBG_LEVEL_5,
			   "QINDEX: RQ(%d),r_reg(ioBase1+%xh) = %xh\n", qid,
			   SC5_RQ_RDPTR_REG(qid), regval);
	} else {
		orig_rdinx = wlqm->sq.rdinx;
		regval = wl_util_readl(netdev, wlpptr->ioBase1 + SC5_SQ_RDPTR_REG(qid));
		qsize = wlqm->sq.qsize;
		WLDBG_INFO(DBG_LEVEL_5,
			   "QINDEX: SQ(%d),r_reg(ioBase1+%xh) = %xh\n", qid,
			   SC5_SQ_RDPTR_REG(qid), regval);
	}
	if (regval == 0xffffffff) {
		WLDBG_ERROR(DBG_LEVEL_0, "Q(%d),r_reg(ioBase1+%xh) = %xh\n",
			    qid, SC5_SQ_RDPTR_REG(qid), regval);
		// Invalid index value => return the original value
		return orig_rdinx;
	}

	if (!desc_size)
		return orig_rdinx;

	WLDBG_INFO(DBG_LEVEL_5,
		   "QINDEX:  Queue(%d), rdinx=%d, from regval(%xh)\n", qid,
		   ((regval & 0xffff0000) >> 12) / desc_size, regval);

	// Make sure index is valid
	idx_val = ((regval & 0xffff0000) >> 12) / desc_size;
	if (idx_val >= qsize) {
		WLDBG_ERROR(DBG_LEVEL_0, "Incorrect %s(%d) rd_idx = %u",
			    ((qoff == SC5_RQ) ? "RQ" : "SQ"), qid, idx_val);
	}

	return idx_val;
}

#ifdef PDM_PCI
BOOLEAN
CheckSMACReady(struct net_device * netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate *parent_wlpptr = GET_PARENT_PRIV(wlpptr);
	const u32 regoff = 0x400;
	u32 loopcnt = 0;
	u32 regval;
	u8 i = 0;

	while (loopcnt++ < 1000) {
		regval = wl_util_readl(netdev, parent_wlpptr->ioBase0 + regoff);
		if (regval == 0x01010101) {
			break;
		}
		if (regval == 0xffffffff) {
			break;
		}

		for (i = 0; i < 64; i++) ;
	}

	if (regval != 0x01010101) {
		return FALSE;
	}

	return TRUE;
}
#else
BOOLEAN
CheckSMACReady(struct net_device * netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate *parent_wlpptr = GET_PARENT_PRIV(wlpptr);
	u32 loopcnt = 0;
	u32 regval;

	while (loopcnt++ < 1000) {
		wl_util_lock(netdev);
		regval = *(UINT32 *) parent_wlpptr->smacStatusAddr->smacRdy;
		wl_util_unlock(netdev);
		if (regval == 0x01010101) {
			break;
		}
		if (regval == 0xffffffff) {
			break;
		}
	}

	if (regval != 0x01010101) {
		return FALSE;
	}

	return TRUE;
}
#endif //

BOOLEAN
CheckIndexReady(struct net_device * netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	u32 loopcnt = 0;
	u32 regval;

	while (loopcnt++ < 1000) {
		regval = *(u32 *) (&((SMAC_CTRL_BLK_st *) wlpptr->ioBase0)->sfw.
				   ready);

		if (regval == 1) {
			break;
		}
		if (regval == 0xffffffff) {
			break;
		}
	}

	if (regval != 1) {
		WLDBG_ERROR(DBG_LEVEL_0,
			    "Failed to get H/W Index(SMAC_CTRL_BLK_st + 0x800) ready, regval=%xh\n",
			    regval);
		return TRUE;
	}

	return FALSE;

}

void
wlUpdateRdPtr(struct net_device *netdev, int qid, int qoff, u32 rdinx,
	      bool is_init)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	struct bqm_args *pbqm_args = &wlpd_p->bmq_args;
	u32 ptval, desc_size = wlGetDescSize(pbqm_args, (u16) qid, qoff);

	WLDBG_INFO(DBG_LEVEL_5,
		   "QINDEX(%d), desc_size from wlGetDescSize() = %d\n", qid,
		   desc_size);

	// smac_hf_reg_rq_wr_ptr_rq10.rq10= temp_hframe_bman_wp[19:4];
	// hframe format last 4 bits truncated
	ptval = ((rdinx * desc_size) & 0xffff0) << 12;
	WLDBG_INFO(DBG_LEVEL_5, "QINDEX(%d), rdinx=%d, to regval(%xh)\n", qid,
		   rdinx, ptval);

	if (qoff == SC5_RQ) {
		wl_util_writel(netdev, ptval, (wlpptr->ioBase1 + SC5_RQ_RDPTR_REG(qid)));
		WLDBG_INFO(DBG_LEVEL_5, "QINDEX(%d) RQ: w_reg(%p)=%xh\n",
			   (wlpptr->ioBase1 + SC5_RQ_RDPTR_REG(qid)), ptval);
	} else {
		wl_util_writel(netdev, ptval, (wlpptr->ioBase1 + SC5_SQ_RDPTR_REG(qid)));
		WLDBG_INFO(DBG_LEVEL_5, "QINDEX(%d) SQ: w_reg(%p)=%xh\n", qid,
			   (wlpptr->ioBase1 + SC5_SQ_RDPTR_REG(qid)), ptval);
	}

	return;
}

u32
wlQueryWrPtr(struct net_device * netdev, int qid, int qoff)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	struct bqm_args *pbqm_args = &wlpd_p->bmq_args;
	struct wldesc_data *wlqm;
	u32 regval;

	u32 desc_size = wlGetDescSize(pbqm_args, (u16) qid, qoff);
	u32 orig_wrinx;
	u32 idx_val, qsize;

	WLDBG_INFO(DBG_LEVEL_5,
		   "QINDEX(%d), desc_size from wlGetDescSize() = %d\n", qid,
		   desc_size);
	wlqm = &wlpptr->wlpd_p->descData[qid];
	if (qoff == SC5_RQ) {
		orig_wrinx = wlqm->rq.wrinx;
		regval = wl_util_readl(netdev, wlpptr->ioBase1 + SC5_RQ_WRPTR_REG(qid));
		qsize = wlqm->rq.qsize;
		WLDBG_INFO(DBG_LEVEL_5, "QINDEX(%d),r_reg(ioBase1+%xh) = %xh\n",
			   qid, SC5_RQ_WRPTR_REG(qid), regval);
	} else {
		orig_wrinx = wlqm->sq.wrinx;
		regval = wl_util_readl(netdev, wlpptr->ioBase1 + SC5_SQ_WRPTR_REG(qid));
		qsize = wlqm->sq.qsize;
		WLDBG_INFO(DBG_LEVEL_5, "QINDEX(%d),r_reg(ioBase1+%xh) = %xh\n",
			   qid, SC5_SQ_WRPTR_REG(qid), regval);
	}
	if (regval == 0xffffffff) {
		// Invalid index value => return the original value
		return orig_wrinx;
	}

	if (!desc_size)
		return orig_wrinx;

	WLDBG_INFO(DBG_LEVEL_5, "QINDEX(%d), wrinx=%d, from regval(%xh)\n", qid,
		   ((regval & 0xffff0000) >> 12) / desc_size, regval);

	idx_val = ((regval & 0xffff0000) >> 12) / desc_size;
	if (idx_val >= qsize) {
		WLDBG_ERROR(DBG_LEVEL_0, "Incorrect %s(%d) rd_idx = %u",
			    ((qoff == SC5_RQ) ? "RQ" : "SQ"), qid, idx_val);
	}
	return idx_val;
}

void
wlUpdateWrPtr(struct net_device *netdev, int qid, int qoff, u32 wrinx,
	      bool is_init)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	struct bqm_args *pbqm_args = &wlpd_p->bmq_args;
	u32 ptval, desc_size = wlGetDescSize(pbqm_args, (u16) qid, qoff);

	WLDBG_INFO(DBG_LEVEL_5,
		   "QINDEX(%d), desc_size from wlGetDescSize() = %d\n", qid,
		   desc_size);
	ptval = ((wrinx * desc_size) & 0xffff0) << 12;
	WLDBG_INFO(DBG_LEVEL_5, "QINDEX(%d), wrinx=%d, to regval(%xh)\n", qid,
		   wrinx, ptval);

	if (qoff == SC5_RQ) {
		wl_util_writel(netdev, ptval, (wlpptr->ioBase1 + SC5_RQ_WRPTR_REG(qid)));
		WLDBG_INFO(DBG_LEVEL_5, "QINDEX(%d),r_reg(ioBase1+%xh) = %xh\n",
			   qid, SC5_RQ_WRPTR_REG(qid), ptval);
	} else {
		wl_util_writel(netdev, ptval, (wlpptr->ioBase1 + SC5_SQ_WRPTR_REG(qid)));
		WLDBG_INFO(DBG_LEVEL_5, "QINDEX(%d),r_reg(ioBase1+%xh) = %xh\n",
			   qid, SC5_SQ_WRPTR_REG(qid), ptval);
	}

	return;
}

BOOLEAN
wlSQEmpty(struct net_device * netdev, u8 qid)
{

	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wldesc_data *wlqm;

	wlqm = &wlpptr->wlpd_p->descData[qid];
	WLDBG_INFO(DBG_LEVEL_5, "QINDEX(%d), SQ (rdinx, wrinx)=(%d, %d)\n", qid,
		   wlqm->sq.rdinx, wlqm->sq.wrinx);
	wlqm->sq.wrinx = wlQueryWrPtr(netdev, qid, SC5_SQ);
	return isSQEmpty(&wlqm->sq);
}

BOOLEAN
wlSQFull(struct net_device * netdev, u8 qid)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wldesc_data *wlqm;

	wlqm = &wlpptr->wlpd_p->descData[qid];
	WLDBG_INFO(DBG_LEVEL_5, "QINDEX(%d), SQ(rdinx, wrinx)=(%d, %d)\n", qid,
		   wlqm->sq.rdinx, wlqm->sq.wrinx);
	wlqm->sq.wrinx = wlQueryWrPtr(netdev, qid, SC5_SQ);
	return isSQFull(&wlqm->sq);
}

BOOLEAN
wlRQFull(struct net_device * netdev, u8 qid)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wldesc_data *wlqm;

	wlqm = &wlpptr->wlpd_p->descData[qid];
	WLDBG_INFO(DBG_LEVEL_5, "QINDEX(%d), RQ(rdinx, wrinx)=(%d, %d)\n", qid,
		   wlqm->rq.rdinx, wlqm->rq.wrinx);

	if (TRUE == isRQFull(&wlqm->rq)) {
		wlqm->rq.rdinx = wlQueryRdPtr(netdev, qid, SC5_RQ);
		if (isRQFull(&wlqm->rq))
			return TRUE;
	}

	return FALSE;
}

void
wlRxQueueCleanUp(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wldesc_data *wlqm;
	int qid;

	for (qid = SC5_RXQ_START_INDEX;
	     qid < (SC5_RXQ_START_INDEX + SC5_RXQ_NUM); qid++) {
		if (((1 << qid) & SC5_RXQ_MASK) == 0) {	// Not enabled
			continue;
		}

		wlqm = &wlpptr->wlpd_p->descData[qid];

		if (wlqm->sq.virt_addr != NULL) {
			wl_dma_free_coherent(wlpptr->wlpd_p->dev,
					     (wlqm->sq.qsize *
					      sizeof(wlrxdesc_t)),
					     wlqm->sq.virt_addr,
					     wlqm->sq.phys_addr);

			wlqm->sq.virt_addr = NULL;
		}
		// reset descruptor queue size.
		wlqm->sq.qsize = 0;
		wl_util_writel(netdev, wlqm->sq.qsize, (wlpptr->ioBase1 + SC5_Q_SIZE_REG(qid, SC5_SQ)));

		// Note: should not change the index, otherwise h/w will issue interrupt
		//wlqm->sq.rdinx = 0;
		//wlqm->sq.wrinx = 0;
		//wlUpdateRdPtr(netdev, qid, SC5_SQ, wlqm->sq.rdinx, false);

	}			// end of for
}

int
wlRxQueueInit(struct net_device *netdev, int qid)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wldesc_data *wlqm;
	int i;
	u32 smac_buf_hi_addr = wlpptr->wlpd_p->reg.smac_buf_hi_addr;
	wlrxdesc_t *cfh_ul;

	wlqm = &wlpptr->wlpd_p->descData[qid];
	wlqm->id = qid;
	wlqm->sq.qsize = rx_q_size[qid - SC5_RXQ_START_INDEX];
	wlqm->sq.virt_addr = wl_dma_alloc_coherent(wlpptr->wlpd_p->dev,
						   (wlqm->sq.qsize *
						    sizeof(wlrxdesc_t)),
						   &wlqm->sq.phys_addr,
						   wlpptr->wlpd_p->
						   dma_alloc_flags);
	WLDBG_INFO(DBG_LEVEL_0,
		   "RXQ(%d), sq (v, p)=(%p, %llxh) from dma_alloc_consistent\n",
		   qid, wlqm->sq.virt_addr, wlqm->sq.phys_addr);

	if ((void *)wlqm->sq.virt_addr == NULL) {
		WLDBG_ERROR(DBG_LEVEL_0, "no valid RX mem");
		return FAIL;
	}
	i = 0;
	if (qid == 0 || qid == 8 || qid == 9) {
		for (cfh_ul = (wlrxdesc_t *) wlqm->sq.virt_addr;
		     i < wlqm->sq.qsize; cfh_ul++, i++) {
			cfh_ul->nss_hdr[2] = HF_OWN_SIGNATURE;
			cfh_ul->hdr.length = USED_BUFLEN;
		}
	}

	wlqm->sq.rdinx = 0;
	wlqm->sq.wrinx = 0;
	spin_lock_init(&wlqm->sq.inx_lock);
	WLDBG_INFO(DBG_LEVEL_0, "RXQ(%d) qid = %d, CFH base = 0x%X \n", qid,
		   qid, wlqm->sq.phys_addr);
	// set CFH-UL descruptor queue size and start address.
	wl_util_writel(netdev, (u32)wlqm->sq.phys_addr, (wlpptr->ioBase1 + SC5_Q_BASE_ADDR_REG(qid, SC5_SQ)));
	WLDBG_INFO(DBG_LEVEL_0,
		   "RXQ(%d), SC5_Q_BASE_ADDR_REG w_reg(ioBase1+%xh) = %xh\n",
		   qid, SC5_Q_BASE_ADDR_REG(qid, SC5_SQ),
		   (u32) wlqm->sq.phys_addr);
	// high address
	wl_util_writel(netdev, smac_buf_hi_addr, (wlpptr->ioBase1 + SC5_Q_BASE_ADDR_REG(qid, SC5_SQ) + 4));
	WLDBG_INFO(DBG_LEVEL_0, "RXQ(%d),w_reg(ioBase1+%xh) = %xh\n", qid,
		   (SC5_Q_BASE_ADDR_REG(qid, SC5_SQ) + 4), smac_buf_hi_addr);

	wl_util_writel(netdev, ((wlqm->sq.qsize * sizeof(wlrxdesc_t)) / 128) << 3, (wlpptr->ioBase1 + SC5_Q_SIZE_REG(qid, SC5_SQ)));
	WLDBG_INFO(DBG_LEVEL_0,
		   "RXQ(%d) SQ, SC5_Q_SIZE_REG w_reg(ioBase1+%xh) = %xh, qsize=%d, sizeof(wlrxdesc_t)=%d\n",
		   qid, SC5_Q_SIZE_REG(qid, SC5_SQ),
		   ((wlqm->sq.qsize * sizeof(wlrxdesc_t)) / 128) << 3,
		   wlqm->sq.qsize, sizeof(wlrxdesc_t));

	return SUCCESS;
}

int
wlTxQueueInit(struct net_device *netdev, int qid)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	struct bqm_args *pbqm_args = &wlpd_p->bmq_args;
	struct wldesc_data *wlqm;
	u32 smac_buf_hi_addr = wlpd_p->reg.smac_buf_hi_addr;

	wlqm = &wlpptr->wlpd_p->descData[qid];
	wlqm->id = qid;

	wlqm->rq.qsize = pbqm_args->tx_q_size[qid - pbqm_args->txq_start_index];

	wlqm->rq.virt_addr = wl_dma_alloc_coherent(wlpd_p->dev,
						   (wlqm->rq.qsize *
						    sizeof(wltxdesc_t)),
						   &wlqm->rq.phys_addr,
						   wlpd_p->dma_alloc_flags);

	if (wlqm->rq.virt_addr == NULL) {
		WLDBG_ERROR(DBG_LEVEL_0, "no valid TXQ mem");
		return FAIL;
	}

	WLDBG_INFO(DBG_LEVEL_0,
		   "TXQ(%d), RQ (v, p)=(%p, %llxh) from dma_alloc_consistent\n",
		   qid, wlqm->rq.virt_addr, wlqm->rq.phys_addr);

	rpkt_reuse_init(&(wlqm->rq.skbTrace));

	wlqm->rq.rdinx = 0;
	wlqm->rq.wrinx = 0;

	spin_lock_init(&wlqm->rq.inx_lock);
	WLDBG_INFO(DBG_LEVEL_0, "TXQ(%d) qid = %d, CFH base = 0x%X \n", qid,
		   qid, wlqm->rq.phys_addr);

	// set CFH-DL descruptor queue size and start address.
	wl_util_writel(netdev, smac_buf_hi_addr, (wlpptr->ioBase1 + SC5_Q_BASE_ADDR_REG(qid, SC5_RQ)) + 4);
	WLDBG_INFO(DBG_LEVEL_0,
		   "TXQ(%d),RQ, SC5_Q_BASE_ADDR_REG w_reg(ioBase1+%xh) = %xh\n",
		   qid, SC5_Q_BASE_ADDR_REG(qid, SC5_RQ),
		   (u32) wlqm->rq.phys_addr);
	// high address
	wl_util_writel(netdev, smac_buf_hi_addr, (wlpptr->ioBase1 + SC5_Q_BASE_ADDR_REG(qid, SC5_RQ)) + 4);
	WLDBG_INFO(DBG_LEVEL_0, "TXQ(%d),w_reg(ioBase1+%xh) = %xh\n", qid,
		   (SC5_Q_BASE_ADDR_REG(qid, SC5_RQ) + 4), smac_buf_hi_addr);
	wl_util_writel(netdev, ((wlqm->rq.qsize * sizeof(wltxdesc_t)) / 128) << 3, (wlpptr->ioBase1 + SC5_Q_SIZE_REG(qid, SC5_RQ)));
	WLDBG_INFO(DBG_LEVEL_0,
		   "TXQ(%d),RQ, SC5_Q_SIZE_REG w_reg(ioBase1+%xh) = %xh, qsize=%d, sizeof(wltxdesc_t)=%d\n",
		   qid, SC5_Q_SIZE_REG(qid, SC5_RQ),
		   ((wlqm->rq.qsize * sizeof(wltxdesc_t)) / 128) << 3,
		   wlqm->rq.qsize, sizeof(wltxdesc_t));

	return SUCCESS;
}

void
wlTxQueueCleanUp(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	struct bqm_args *pbqm_args = &wlpd_p->bmq_args;
	struct wldesc_data *wlqm;
	int qid;

	for (qid = pbqm_args->txq_start_index;
	     qid < (pbqm_args->txq_start_index + pbqm_args->txq_num); qid++) {
		wlqm = &wlpptr->wlpd_p->descData[qid];

		if (wlqm->rq.virt_addr != NULL) {
			wl_dma_free_coherent(wlpd_p->dev,
					     (wlqm->rq.qsize *
					      sizeof(wltxdesc_t)),
					     wlqm->rq.virt_addr,
					     wlqm->rq.phys_addr);

			wlqm->rq.virt_addr = NULL;
		}
		// reset descruptor queue size.
		wlqm->rq.qsize = 0;
		wl_util_writel(netdev, wlqm->rq.qsize, (wlpptr->ioBase1 + SC5_Q_SIZE_REG(qid, SC5_RQ)));

		// Note: should not change the index, otherwise h/w will issue interrupt
		//wlqm->rq.rdinx = 0;
		//wlqm->rq.wrinx = 0;
		//wlUpdateWrPtr(netdev, qid, SC5_RQ, wlqm->rq.wrinx, false);

	}			// end of for
}

int
wlBmQueueInit(struct net_device *netdev, int qid)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	struct wldesc_data *wlqm;
	int i;

	u32 smac_buf_hi_addr = wlpptr->wlpd_p->reg.smac_buf_hi_addr;
	bm_pe_hw_t *ppehw;

	wlqm = &wlpptr->wlpd_p->descData[qid];
	wlqm->id = qid;
	if (qid == (SC5_BMQ_START_INDEX + SC5_BMQ_NUM - 1)) {	// Last queue => buffer for L0/L1
		wlqm->rq.qsize =
			wlpd_p->ext_membuf[1].buf_pool_size /
			buf_pool_size[qid - SC5_BMQ_START_INDEX];
	} else {
		wlqm->rq.qsize =
			bm_q_size[((U8) (qid - SC5_BMQ_START_INDEX) %
				   SC5_BMQ_NUM)];
	}
	WLDBG_INFO(DBG_LEVEL_0, "BMQ[%d] size = %d\n", qid, wlqm->rq.qsize);

	wlqm->rq.virt_addr = wl_dma_alloc_coherent(wlpptr->wlpd_p->dev,
						   (wlqm->rq.qsize *
						    sizeof(bm_pe_hw_t)),
						   &wlqm->rq.phys_addr,
						   wlpptr->wlpd_p->
						   dma_alloc_flags);
	WLDBG_INFO(DBG_LEVEL_0,
		   "BMQ(%d), RQ (v, p)=(%p, %llxh) from dma_alloc_consistent\n",
		   qid, wlqm->rq.virt_addr, wlqm->rq.phys_addr);

	if ((void *)wlqm->rq.virt_addr == NULL) {
		WLDBG_ERROR(DBG_LEVEL_0, "BMQ(%d)no valid BMQ mem \n", qid);
		return FAIL;
	}
	// Init the signature to the buffer desc
	for (i = 0, ppehw = (bm_pe_hw_t *) wlqm->rq.virt_addr;
	     i < wlqm->rq.qsize; i++, ppehw++) {
		ppehw->bgn_signature = ppehw->end_signature = BMBUF_SIGNATURE;
	}
	WLDBG_INFO(DBG_LEVEL_0, "BMQ(%d) qid = %d, BPE base = %xh\n", qid, qid,
		   wlqm->rq.phys_addr);
	// set BMQ descruptor queue size and start address.
	wl_util_writel(netdev, (u32)wlqm->rq.phys_addr, (wlpptr->ioBase1 + SC5_Q_BASE_ADDR_REG(qid, SC5_RQ)));
	WLDBG_INFO(DBG_LEVEL_0,
		   "BMQ(%d),RQ, SC5_Q_BASE_ADDR_REG w_reg(ioBase1+%llxh) = %xh\n",
		   qid, SC5_Q_BASE_ADDR_REG(qid, SC5_RQ),
		   (u64) wlqm->rq.phys_addr);

	// High address
	wl_util_writel(netdev, smac_buf_hi_addr, (wlpptr->ioBase1 + SC5_Q_BASE_ADDR_REG(qid, SC5_RQ) + 4));
	WLDBG_INFO(DBG_LEVEL_0, "BMQ(%d),w_reg(ioBase1+%xh) = %xh\n", qid,
		   (SC5_Q_BASE_ADDR_REG(qid, SC5_RQ) + 4), smac_buf_hi_addr);

	//
	// Mail from Jerry on 13th Feb 2017:
	//              "The size of queue must align to 128 bytes...."
	//
	wl_util_writel(netdev, ((wlqm->rq.qsize * sizeof(bm_pe_hw_t)) / 128) << 3, (wlpptr->ioBase1 + SC5_Q_SIZE_REG(qid, SC5_RQ)));
	WLDBG_INFO(DBG_LEVEL_0,
		   "BMQ(%d),RQ, SC5_Q_SIZE_REG w_reg(ioBase1+%xh) = %xh, qsize=%d, sizeof(bm_pe_hw_t)=%d\n",
		   qid, SC5_Q_SIZE_REG(qid, SC5_RQ),
		   ((wlqm->rq.qsize * sizeof(bm_pe_hw_t)) / 128) << 3,
		   wlqm->rq.qsize, sizeof(bm_pe_hw_t));

	// update rdinx and wrinx in wlRxBufInit
	wlRxBufInit(netdev, qid);
	wlpptr->smacconfig.bpReqInfo[qid - SC5_BMQ_START_INDEX].size =
		wlqm->rq.bm.buf_size / 16;
	wlpptr->smacconfig.bpReqInfo[qid - SC5_BMQ_START_INDEX].bpid = qid;
	wlpptr->smacconfig.bpReqInfo[qid - SC5_BMQ_START_INDEX].qid = qid;

	return SUCCESS;

}

void
wlBmBufDump(struct net_device *netdev, int qid)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wldesc_data *wlqm;
	struct sk_buff *skb;
	bm_pe_hw_t *pe_hw;
	bm_pe_t *pe;
	u32 rdinx;

	wlqm = &wlpptr->wlpd_p->descData[qid];

	WLDBG_INFO(DBG_LEVEL_4, "qid %x rqsize %x  buf_size %x   \n", qid,
		   wlqm->rq.qsize, wlqm->rq.bm.buf_size);
	WLDBG_INFO(DBG_LEVEL_4, "rq: rdinx %x wrinx %x \n", wlqm->rq.rdinx,
		   wlqm->rq.wrinx);

	pe_hw = (bm_pe_hw_t *) (wlqm->rq.virt_addr);
	pe = wlqm->rq.bm.pe;
	pe_hw += wlqm->rq.rdinx;
	pe += wlqm->rq.rdinx;
	skb = pe->skb;

	rdinx = wlqm->rq.rdinx;
	while (rdinx != wlqm->rq.wrinx) {
		WLDBG_INFO(DBG_LEVEL_4,
			   "rdinx %d  virt_addr %x phys_addr %x skb %p skb->data %p\n",
			   rdinx, ENDIAN_SWAP32(pe_hw->pe1_lo_dword_addr),
			   ENDIAN_SWAP32(pe_hw->pe0_lo_dword_addr), skb,
			   skb->data);
		rdinx = (rdinx + 1) % wlqm->rq.qsize;
		//pe_hw = (bm_pe_hw_t *)(wlqm->rq.virt_addr + rdinx * sizeof(bm_pe_hw_t));
		pe_hw = ((bm_pe_hw_t *) (wlqm->rq.virt_addr)) + rdinx;
		pe = (bm_pe_t *) (wlqm->rq.bm.pe + rdinx);
		skb = pe->skb;
	}			// end of while
}

void
wlReleaseBufDump(struct net_device *netdev, int qid)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wldesc_data *wlqm;

	bm_pe_hw_t *pe_hw;
	u32 rdinx;

	wlqm = &wlpptr->wlpd_p->descData[qid];

	WLDBG_INFO(DBG_LEVEL_4, "qid %x sqsize %x  buf_size %x \n", qid,
		   wlqm->sq.qsize, wlqm->sq.bm.buf_size);
	WLDBG_INFO(DBG_LEVEL_4, "sq: rdinx %x wrinx %x \n", wlqm->sq.rdinx,
		   wlqm->sq.wrinx);

	pe_hw = (bm_pe_hw_t *) (wlqm->sq.virt_addr);
	pe_hw += wlqm->sq.rdinx;

	rdinx = wlqm->sq.rdinx;
	while (rdinx != wlqm->sq.wrinx) {
		WLDBG_INFO(DBG_LEVEL_4, "rdinx %d  virt_addr %x phys_addr %x\n",
			   rdinx, ENDIAN_SWAP32(pe_hw->pe1_lo_dword_addr),
			   ENDIAN_SWAP32(pe_hw->pe0_lo_dword_addr));
		rdinx = (rdinx + 1) % wlqm->sq.qsize;
		pe_hw = (bm_pe_hw_t *) (wlqm->sq.virt_addr +
					rdinx * sizeof(bm_pe_hw_t));
	}			// end of while
}

void
wlRxBufCleanUp(struct net_device *netdev, int qid)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	struct wldesc_data *wlqm;

	wlqm = &wlpptr->wlpd_p->descData[qid];
	WLDBG_INFO(DBG_LEVEL_4, "qid %d rdinx %d wrinx  %d \n", qid,
		   wlqm->rq.rdinx, wlqm->rq.wrinx);

	// free buffer
	// Note: The queue buffer in BQM (q10 ~ 12) will be freed from the pending list (wlpd_p->pend_skb_trace[PENDSKB_RX])
	if (qid == (SC5_BMQ_START_INDEX + SC5_BMQ_NUM - 1)) {
		wlclean_extmembuf(wlpptr, &wlpd_p->ext_membuf[1]);
	}

	WLDBG_INFO(DBG_LEVEL_4, "free skb in skbTrace:\n");
	rpkt_reuse_flush(&wlqm->rq.skbTrace);
	WLDBG_INFO(DBG_LEVEL_4, "\t Done~\n");

}

int
wlRxBufInit(struct net_device *netdev, int qid)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	struct except_cnt *wlexcept_p = &wlpd_p->except_cnt;
	struct wldesc_data *wlqm;
	struct sk_buff *skb = NULL;
	dma_addr_t buff_phy_addr = (dma_addr_t) 0;
	bm_pe_t *pe;
	bm_pe_hw_t *pe_hw;
	int index, entry;
	size_t size;
	struct sk_buff **skb_addr;
	u8 *buf_virt_addr = NULL;

	wlqm = &wlpptr->wlpd_p->descData[qid];
	index = qid - SC5_BMQ_START_INDEX;
	wlqm->rq.bm.buf_size = buf_pool_size[index];
	size = wlqm->rq.bm.buf_size;
	rpkt_reuse_init(&(wlqm->rq.skbTrace));

	pe = (bm_pe_t *) wl_kmalloc((wlqm->rq.qsize * sizeof(bm_pe_t)),
				    GFP_KERNEL);
	if (!pe) {
		WLDBG_ERROR(DBG_LEVEL_0,
			    "PE memory allocation for qid(%d) fail \n");
		return -ENOMEM;
	}
	wlqm->rq.bm.pe = pe;
	WLDBG_INFO(DBG_LEVEL_0, "BMQ(%d) : pe address %p \n", qid, (void *)pe);
	pe_hw = (bm_pe_hw_t *) wlqm->rq.virt_addr;

	/*
	   mail from Sean Wed 3/22/2017 12:07 PM
	   MPDU len     CFH + HDR extraction
	   2K:                  640~700         128 + 96 * 10           (5Gbps 1us density MPDU to be pre-fetched)      - no required alignment
	   4K:                  1700            128 + 96 * 26           (Internet HTML MPDU)                                     - no required alignment
	   16K:         >1700           128 + 96 *32            (4K/8K/11K AMSDU)                                               - no required alignment
	   16K:         L0/L1           (No need for skb allocation)            - required 16KB alignment

	 */
	if (qid == (SC5_BMQ_START_INDEX + SC5_BMQ_NUM - 1)) {
		buf_virt_addr = wlpd_p->ext_membuf[1].vbuf_pool;
		buff_phy_addr = virt_to_phys(buf_virt_addr);
	}

	WLDBG_INFO(DBG_LEVEL_0, "BMQ(%d), allocating %u entris for qid:%u\n",
		   qid, wlqm->rq.qsize, qid);

	for (entry = 0; entry < wlqm->rq.qsize; entry++) {
		// Adding bytes for buffer alignment
		if (qid != (SC5_BMQ_START_INDEX + SC5_BMQ_NUM - 1)) {
			skb = wl_alloc_skb(size + 2 * SKB_INFO_SIZE + RXBUF_ALIGN);	//add tail signature check
			if (!skb) {
				wlpd_p->drv_stats_val.
					bmqbuf_alloc_fail_cnt[qid -
							      SC5_BMQ_START_INDEX]++;
				return -ENOMEM;
			}
			skb_queue_tail(&wlpd_p->pend_skb_trace[PENDSKB_RX],
				       skb);
			skb->dev = netdev;
			//skb_reserve(skb, SKB_INFO_SIZE);
			if (((U32) (skb->data - skb->head)) < SKB_INFO_SIZE) {
				// Make sure the headroom is sufficient
				wlexcept_p->sml_rx_hdroom_cnt++;
			}
			if (!IS_ALIGNED(((long)skb->data), RXBUF_ALIGN)) {
				// Make sure the buffer is aligned
				wlexcept_p->rxbuf_mis_align_cnt++;
				skb->data = PTR_ALIGN(skb->data, RXBUF_ALIGN);
			}
			*((u32 *) (skb->data - SKB_INFO_SIZE)) = SKB_SIGNATURE;
			skb_addr =
				(struct sk_buff **)(skb->data -
						    SKB_POINTER_OFFSET);
			*skb_addr = skb;

			//Add tail signature check
			*((u32 *) (skb->data + size +
				   SKB_TAIL_SIGNATURE_OFFSET)) =
				SKB_TAIL_SIGNATURE;

			buff_phy_addr =
				dma_map_single(wlpptr->wlpd_p->dev, skb->data,
					       size, DMA_FROM_DEVICE);

		}
		pe_hw->pe0_lo_dword_addr = buff_phy_addr;
		pe_hw->pe0_hi_byte_addr = wlpptr->wlpd_p->reg.smac_buf_hi_addr;
		pe_hw->bpid = qid;
		wlpd_p->drv_stats_val.enq_bmqbuf_cnt[qid -
						     SC5_BMQ_START_INDEX]++;

		pe->phy_addr = (dma_addr_t) (pe_hw->pe0_lo_dword_addr);
		if (qid != (SC5_BMQ_START_INDEX + SC5_BMQ_NUM - 1)) {
			pe->virt_addr = (u8 *) skb->data;
			pe->bpid = pe_hw->bpid;
			pe->skb = skb;

			//printk(KERN_ERR "BCM(%d): %d pe %p  pe_hw %p skb %p skb->data %p \n",qid, entry, pe, pe_hw, skb, skb->data);
		} else {
			pe->virt_addr = buf_virt_addr;
			pe->bpid = pe_hw->bpid;
			pe->skb = NULL;

			//printk(KERN_ERR "BCM(%d): %d pe %p  pe_hw %p \n",qid, entry, pe, pe_hw);
			buf_virt_addr +=
				buf_pool_size[qid - SC5_BMQ_START_INDEX];
			buff_phy_addr +=
				buf_pool_size[qid - SC5_BMQ_START_INDEX];
		}
		// printk(KERN_ERR "[RxBufInit] BCM( %d ): phy_addr %x virt_addr %p \n",qid, pe->phy_addr, pe->virt_addr);

		pe++;
		pe_hw++;
	}			// end entry
	wlqm->rq.rdinx = 0;
	// WAR for h/w error that:
	// "an hw bug that it writes to last 16k block of 96M bootmem could spill 4 bytes over to the address next to it"
	//      WAR: Save one buffer to h/w
	if (qid == (SC5_BMQ_START_INDEX + SC5_BMQ_NUM - 1)) {
		wlqm->rq.wrinx = wlqm->rq.qsize - 2;
	} else {
		wlqm->rq.wrinx = wlqm->rq.qsize - 1;
	}
	spin_lock_init(&wlqm->rq.inx_lock);

	return SUCCESS;
}

void
wlBmQueueCleanUp(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wldesc_data *wlqm;
	int qid;

	for (qid = SC5_BMQ_START_INDEX;
	     qid < (SC5_BMQ_START_INDEX + SC5_BMQ_NUM); qid++) {
		wlqm = &wlpptr->wlpd_p->descData[qid];
		wlRxBufCleanUp(netdev, qid);

		if ((void *)wlqm->rq.virt_addr != NULL) {
			wl_dma_free_coherent(wlpptr->wlpd_p->dev,
					     (wlqm->rq.qsize *
					      sizeof(bm_pe_hw_t)),
					     (void *)wlqm->rq.virt_addr,
					     wlqm->rq.phys_addr);

			wlqm->rq.virt_addr = NULL;
		}

		WLDBG_INFO(DBG_LEVEL_4, "free pe %p \n", wlqm->rq.bm.pe);
		if (wlqm->rq.bm.pe != NULL) {
			wl_kfree(wlqm->rq.bm.pe);
			wlqm->rq.bm.pe = NULL;
		}
		// reset descruptor queue size.
		wlqm->rq.qsize = 0;
		wl_util_writel(netdev, wlqm->rq.qsize, (wlpptr->ioBase1 + SC5_Q_SIZE_REG(qid, SC5_RQ)));

		// Note: should not change the index, otherwise h/w will issue interrupt
		//wlqm->rq.rdinx = 0;
		//wlqm->rq.wrinx = 0;
		//wlUpdateWrPtr(netdev, qid, SC5_RQ, wlqm->rq.wrinx, false);
	}			// end of for
}

int
wlBufReleaseQueueInit(struct net_device *netdev, int qid)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	struct bqm_args *pbqm_args = &wlpd_p->bmq_args;
	struct wldesc_data *wlqm;
	int i;
	u32 smac_buf_hi_addr = wlpd_p->reg.smac_buf_hi_addr;
	bm_pe_hw_t *ppehw;

	wlqm = &wlpptr->wlpd_p->descData[qid];
	wlqm->id = qid;
	wlqm->sq.qsize =
		pbqm_args->relbuf_q_size[qid - pbqm_args->bmq_release_index];

	wlqm->sq.virt_addr = wl_dma_alloc_coherent(wlpd_p->dev,
						   (wlqm->sq.qsize *
						    sizeof(bm_pe_hw_t)),
						   &wlqm->sq.phys_addr,
						   wlpd_p->dma_alloc_flags);
	WLDBG_INFO(DBG_LEVEL_0,
		   "BMQ(%d), sq(%d) (v, p)=(%p, %llxh) from dma_alloc_consistent\n",
		   qid, wlqm->sq.virt_addr, wlqm->sq.phys_addr);

	if ((void *)wlqm->sq.virt_addr == NULL) {
		WLDBG_ERROR(DBG_LEVEL_0,
			    "Qid %d no valid Buffer Release Pool Mem \n", qid);
		return FAIL;
	}
	// Init the signature to the buffer desc
	for (i = 0, ppehw = (bm_pe_hw_t *) wlqm->sq.virt_addr;
	     i < wlqm->sq.qsize; i++, ppehw++) {
		ppehw->bgn_signature = ppehw->end_signature = BMBUF_SIGNATURE;
	}

	wlqm->sq.rdinx = 0;
	wlqm->sq.wrinx = 0;
	// set Release buffer descruptor queue size and start address.
	wl_util_writel(netdev, wlqm->sq.phys_addr, (wlpptr->ioBase1 + SC5_Q_BASE_ADDR_REG(qid, SC5_SQ)));
	WLDBG_INFO(DBG_LEVEL_0,
		   "BMQ(%d), SQ, SC5_Q_BASE_ADDR_REG(%d): %p, phyaddr=%llxh\n",
		   qid, (wlpptr->ioBase1 + SC5_Q_BASE_ADDR_REG(qid, SC5_SQ)),
		   (u64) wlqm->sq.phys_addr);

	// high address
	wl_util_writel(netdev, smac_buf_hi_addr, (wlpptr->ioBase1 + SC5_Q_BASE_ADDR_REG(qid, SC5_SQ) + 4));
	WLDBG_INFO(DBG_LEVEL_0, "BMQ(%d),w_reg(ioBase1+%xh) = %xh\n", qid,
		   (SC5_Q_BASE_ADDR_REG(qid, SC5_SQ) + 4), smac_buf_hi_addr);

	wl_util_writel(netdev, ((wlqm->sq.qsize * sizeof(bm_pe_hw_t)) / 128) << 3, (wlpptr->ioBase1 + SC5_Q_SIZE_REG(qid, SC5_SQ)));
	WLDBG_INFO(DBG_LEVEL_0,
		   "BMQ(%d),SQ, SC5_Q_SIZE_REG w_reg(ioBase1+%xh) = %xh, qsize=%d, sizeof(bm_pe_hw_t)=%d\n",
		   qid, SC5_Q_SIZE_REG(qid, SC5_SQ),
		   ((wlqm->sq.qsize * sizeof(wlrxdesc_t)) / 128) << 3,
		   wlqm->sq.qsize, sizeof(bm_pe_hw_t));

	/* set TX DONE interrupt threshold and timeout */
	wl_util_writel(netdev, SC5_TXDONE_INT_THRESHOLD, (wlpptr->ioBase1 + SC5_Q_THRES_REG(qid, SC5_SQ)));
	WLDBG_INFO(DBG_LEVEL_0, "BMQ(%d),w_reg(ioBase1+%xh) = %xh\n", qid,
		   SC5_Q_THRES_REG(qid, SC5_SQ), 0x1);

	wl_util_writel(netdev, SQ5_MAC_CTRL_TIMEOUT(SC5_TXDONE_INT_TIMEOUT), (wlpptr->ioBase1 + SC5_Q_MAC_CTRL_REG(qid, SC5_SQ)));
	WLDBG_INFO(DBG_LEVEL_0, "BMQ(%d),w_reg(ioBase1+%xh) = %xh\n", qid,
		   SC5_Q_MAC_CTRL_REG(qid, SC5_SQ), SQ5_MAC_CTRL_TIMEOUT(0x10));

	return SUCCESS;

}

void
wlBufReleaseQueueCleanUp(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	struct bqm_args *pbqm_args = &wlpd_p->bmq_args;

	struct wldesc_data *wlqm;
	int qid;

	for (qid = pbqm_args->bmq_release_index;
	     qid < (pbqm_args->bmq_release_index + pbqm_args->bmq_release_num);
	     qid++) {
		wlqm = &wlpptr->wlpd_p->descData[qid];

		if ((void *)wlqm->sq.virt_addr != NULL) {
			wl_dma_free_coherent(wlpd_p->dev,
					     (wlqm->sq.qsize *
					      sizeof(bm_pe_hw_t)),
					     (void *)wlqm->sq.virt_addr,
					     wlqm->sq.phys_addr);

			wlqm->sq.virt_addr = NULL;
		}
		// reset descruptor queue size.
		wlqm->sq.qsize = 0;
		wl_util_writel(netdev, wlqm->sq.qsize, (wlpptr->ioBase1 + SC5_Q_SIZE_REG(qid, SC5_SQ)));

		// Note: should not change the index, otherwise h/w will issue interrupt
		//wlqm->sq.rdinx = 0;
		//wlqm->sq.wrinx = 0;
		//wlUpdateWrPtr(netdev, qid, SC5_RQ, wlqm->rq.wrinx, false);

	}			// end of for
}

#if defined(ACNT_REC)
//#define RX_ACNT_PPDU_BUF_SIZE         8*(sizeof(SMAC_ACNT_RX_BUF_st))
// 1M buffer for RxAcnt
#define RX_ACNT_PPDU_BUF_SIZE		(512*1024)
void
wlRAcntBufInit(struct net_device *netdev, int qid)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	struct bqm_args *pbqm_args = &wlpd_p->bmq_args;
	struct wlprivate *parent_wlpptr = GET_PARENT_PRIV(wlpptr);
	SMAC_CONFIG_st *p_smac_cfg = &parent_wlpptr->smacconfig;
	dma_addr_t phys_addr;

	p_smac_cfg->acntRxInfoQueSize =
		pbqm_args->racnt_q_size[qid - pbqm_args->racntq_index];
	WLDBG_INFO(DBG_LEVEL_0, "%s(), acntRxInfoQueSize = %u\n", __func__,
		   p_smac_cfg->acntRxInfoQueSize);
	wlpd_p->acntRxInfoQueBaseAddr_v =
		(rx_info_ppdu_t *) wl_dma_alloc_coherent(wlpd_p->dev,
							 (p_smac_cfg->
							  acntRxInfoQueSize *
							  sizeof
							  (rx_info_ppdu_t)),
							 &phys_addr,
							 wlpd_p->
							 dma_alloc_flags);
	p_smac_cfg->acntRxInfoQueBaseAddr = (U32) phys_addr;
	// Initial acntRxRdPtr/acntRxWrPtr
	WLDBG_INFO(DBG_LEVEL_0,
		   "%s(), acntRxInfoQueBaseAddr (v, p)=(%p, %x), %x, (phy=%llx)\n",
		   __func__, wlpd_p->acntRxInfoQueBaseAddr_v,
		   p_smac_cfg->acntRxInfoQueBaseAddr, (U32) phys_addr,
		   virt_to_phys(wlpd_p->acntRxInfoQueBaseAddr_v)
		);
	wlpd_p->rxinfo_aux_poll =
		(rx_info_aux_t *) wl_kmalloc(sizeof(rx_info_aux_t) *
					     p_smac_cfg->acntRxInfoQueSize,
					     GFP_KERNEL);
	return;
}

int
wlRAcntQueueInit(struct net_device *netdev, int qid)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	struct bqm_args *pbqm_args = &wlpd_p->bmq_args;
	struct wldesc_data *wlqm;
	int i;
	u32 smac_buf_hi_addr = wlpd_p->reg.smac_buf_hi_addr;
	rxacnt_rec *pq_entity;

	wlqm = &wlpptr->wlpd_p->descData[qid];
	wlqm->id = qid;
	wlqm->sq.qsize = pbqm_args->racnt_q_size[qid - pbqm_args->racntq_index];

	wlqm->sq.virt_addr = wl_dma_alloc_coherent(wlpd_p->dev,
						   (wlqm->sq.qsize *
						    sizeof(rxacnt_rec)),
						   &wlqm->sq.phys_addr,
						   wlpd_p->dma_alloc_flags);
	WLDBG_INFO(DBG_LEVEL_0,
		   "RxAcntQ(%d), sq(%d) (v, p)=(%p, %llxh) from dma_alloc_consistent\n",
		   qid, wlqm->sq.virt_addr, wlqm->sq.phys_addr);

	if ((void *)wlqm->sq.virt_addr == NULL) {
		WLDBG_ERROR(DBG_LEVEL_0,
			    "Qid %d no valid Buffer Release Pool Mem \n", qid);
		return FAIL;
	}
	// Init the signature to the buffer desc
	for (i = 0, pq_entity = (rxacnt_rec *) wlqm->sq.virt_addr;
	     i < wlqm->sq.qsize; i++, pq_entity++) {
		pq_entity->bgn_signature = pq_entity->end_signature =
			BMBUF_SIGNATURE;
	}

	wlqm->sq.rdinx = 0;
	wlqm->sq.wrinx = 0;
	// set Release buffer descruptor queue size and start address.
	wl_util_writel(netdev, wlqm->sq.phys_addr, (wlpptr->ioBase1 + SC5_Q_BASE_ADDR_REG(qid, SC5_SQ)));
	WLDBG_INFO(DBG_LEVEL_0,
		   "RxAcntQ(%d), SQ, SC5_Q_BASE_ADDR_REG(%d): %p, phyaddr=%llxh\n",
		   qid, (wlpptr->ioBase1 + SC5_Q_BASE_ADDR_REG(qid, SC5_SQ)),
		   (u64) wlqm->sq.phys_addr);

	// high address
	wl_util_writel(netdev, smac_buf_hi_addr, (wlpptr->ioBase1 + SC5_Q_BASE_ADDR_REG(qid, SC5_SQ) + 4));
	WLDBG_INFO(DBG_LEVEL_0, "RxAcntQ(%d),w_reg(ioBase1+%xh) = %xh\n", qid,
		   (SC5_Q_BASE_ADDR_REG(qid, SC5_SQ) + 4), smac_buf_hi_addr);

	wl_util_writel(netdev, ((wlqm->sq.qsize * sizeof(rxacnt_rec)) / 128) << 3,
	       (wlpptr->ioBase1 + SC5_Q_SIZE_REG(qid, SC5_SQ)));
	WLDBG_INFO(DBG_LEVEL_0,
		   "RxAcntQ(%d),SQ, SC5_Q_SIZE_REG w_reg(ioBase1+%xh) = %xh, qsize=%d, sizeof(rxacnt_rec)=%d\n",
		   qid, SC5_Q_SIZE_REG(qid, SC5_SQ),
		   ((wlqm->sq.qsize * sizeof(wlrxdesc_t)) / 128) << 3,
		   wlqm->sq.qsize, sizeof(rxacnt_rec));

	//Init the RxInfo
	wlRAcntBufInit(netdev, qid);
	return SUCCESS;

}

void
wlRAcntBufCleanUp(struct net_device *netdev, int qid)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	struct wlprivate *parent_wlpptr = GET_PARENT_PRIV(wlpptr);
	SMAC_CONFIG_st *p_smac_cfg = &parent_wlpptr->smacconfig;

	if (wlpd_p->acntRxInfoQueBaseAddr_v != NULL) {
		wl_dma_free_coherent(wlpd_p->dev,
				     (p_smac_cfg->acntRxInfoQueSize *
				      sizeof(rx_info_ppdu_t)),
				     (void *)wlpd_p->acntRxInfoQueBaseAddr_v,
				     p_smac_cfg->acntRxInfoQueBaseAddr);
		WLDBG_INFO(DBG_LEVEL_0, "free acntRxInfoQueBaseAddr_v(%u)\n",
			   p_smac_cfg->acntRxInfoQueSize);
		wlpd_p->acntRxInfoQueBaseAddr_v = NULL;
	}
	if (wlpd_p->rxinfo_aux_poll != NULL) {
		wl_kfree(wlpd_p->rxinfo_aux_poll);
		wlpd_p->rxinfo_aux_poll = NULL;
	}

	return;
}

void
wlRAcntQueueCleanUp(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	struct bqm_args *pbqm_args = &wlpd_p->bmq_args;

	struct wldesc_data *wlqm;
	int qid;

	for (qid = pbqm_args->racntq_index;
	     qid < (pbqm_args->racntq_index + pbqm_args->racntq_num); qid++) {
		wlqm = &wlpptr->wlpd_p->descData[qid];
		if ((void *)wlqm->sq.virt_addr != NULL) {
			wl_dma_free_coherent(wlpd_p->dev,
					     (wlqm->sq.qsize *
					      sizeof(rxacnt_rec)),
					     (void *)wlqm->sq.virt_addr,
					     wlqm->sq.phys_addr);

			wlqm->sq.virt_addr = NULL;
		}
		// reset descruptor queue size.
		wlqm->sq.qsize = 0;
		wl_util_writel(netdev, wlqm->sq.qsize, (wlpptr->ioBase1 + SC5_Q_SIZE_REG(qid, SC5_SQ)));
		wlRAcntBufCleanUp(netdev, qid);

		// Note: should not change the index, otherwise h/w will issue interrupt
		//wlqm->sq.rdinx = 0;
		//wlqm->sq.wrinx = 0;
		//wlUpdateWrPtr(netdev, qid, SC5_RQ, wlqm->rq.wrinx, false);

	}			// end of for
}

#endif //#if defined(ACNT_REC)
bm_pe_hw_t *
wlGetRelBufPe(struct net_device *netdev, int qid)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate *parent_wlpptr = GET_PARENT_PRIV(wlpptr);
	struct wlprivate_data *wlpd_p = parent_wlpptr->wlpd_p;
	struct bqm_args *pbqm_args = &wlpd_p->bmq_args;
	struct wldesc_data *wlqm;
	bm_pe_hw_t *pe_hw_src;
	bm_pe_hw_t pe_hw_mochi, *pe_hw;
	u8 bpid;
	int invalid_pe = 0;

	wlqm = &wlpptr->wlpd_p->descData[qid];
	pe_hw_src =
		(bm_pe_hw_t *) (wlqm->sq.virt_addr +
				wlqm->sq.rdinx * sizeof(bm_pe_hw_t));

	pe_hw = &pe_hw_mochi;
	memcpy(pe_hw, pe_hw_src, sizeof(bm_pe_hw_t));

	bpid = REL_RX_BPID(pe_hw->bpid);

	/* Incorrect pe_hw conditions:
	 *  1. Signature is BMBUF_SIGNATURE => the pe_hw hasn't been updated
	 *  2. lo_dowrd == 0 or 0xffffffff
	 *  3. bpid is incorrect (not in:
	 *              [SC5_TXQ_START_INDEX ~ SC5_TXQ_START_INDEX+SC5_TXQ_NUM] &&
	 *              [SC5_BMQ_START_INDEX ~ SC5_BMQ_START_INDEX+SC5_BMQ_NUM-1]
	 */
	if ((pe_hw->bgn_signature == BMBUF_SIGNATURE) ||
	    (pe_hw->end_signature == BMBUF_SIGNATURE)) {
		wlpd_p->except_cnt.buf_desc_not_updated++;
		invalid_pe = 1;
#ifdef ASSERT_MALBUF
		WLDBG_ERROR(DBG_LEVEL_0,
			    "Desc hasn't been updated: (%xh, %xh)\n",
			    pe_hw->bgn_signature, pe_hw->end_signature);
#endif
	}
	if (!pe_addr_valid(pe_hw->pe0_lo_dword_addr)) {
		wlpd_p->except_cnt.invalid_buf_addr++;
		invalid_pe = 1;
#ifdef ASSERT_MALBUF
		dbg_level = 0x1;
		wl_util_writel(netdev, 0xdeadbeef, wlpptr->ioBase1 + PCI_REG_SCRATCH14_REG);
		wl_dump_dbgrelq_info(netdev, 0x528, 0x52c);
		wl_dump_dbgrelq_info(netdev, 0x520, 0x524);
		wl_dump_dbgrelq_info(netdev, 0x518, 0x51c);
		WLDBG_ERROR(DBG_LEVEL_0, "pe0_lo_dword_addr == %xh",
			    pe_hw->pe0_lo_dword_addr);
		WL_ASSERT(FALSE,
			  ("pe0_lo_dword_addr == %xh",
			   pe_hw->pe0_lo_dword_addr));
#endif
	}

	if (!
	    (((pbqm_args->txq_start_index <= bpid) &&
	      (bpid < (pbqm_args->txq_start_index + pbqm_args->txq_num))) ||
	     ((SC5_BMQ_START_INDEX <= bpid) &&
	      (bpid < (SC5_BMQ_START_INDEX + SC5_BMQ_NUM))))) {
		wlpd_p->except_cnt.pe_invlid_bpid++;
		invalid_pe = 1;
#ifdef ASSERT_MALBUF
		dbg_level = 0x1;
		wl_util_writel(netdev, 0xdeadbeef, wlpptr->ioBase1 + PCI_REG_SCRATCH14_REG);
		wl_dump_dbgrelq_info(netdev, 0x528, 0x52c);
		wl_dump_dbgrelq_info(netdev, 0x520, 0x524);
		wl_dump_dbgrelq_info(netdev, 0x518, 0x51c);
		WL_ASSERT(FALSE, ("Invalid bpid: %d", pe_hw->bpid));
#endif
	}

	if (invalid_pe) {
#ifdef ASSERT_MALBUF
		/*The buffer is not ready yet=> Update the rdinx & leaving without touch anything */
		WLDBG_ERROR(DBG_LEVEL_0,
			    "Got unused/wrong desc at Q(%d), (rd, wr)=(%d, %d)\n",
			    qid, wlqm->sq.rdinx, wlqm->sq.wrinx);
		mwl_hex_dump((u8 *) pe_hw, sizeof(bm_pe_hw_t));
#endif
		pe_hw_src = NULL;
	}

	/* advance the rd index */
	wlqm->sq.rdinx = (wlqm->sq.rdinx + 1) % wlqm->sq.qsize;

	WLDBG_DATA(DBG_LEVEL_2, "RELQ(%d) wrinx %d rdind %d \n", qid,
		   wlqm->sq.wrinx, wlqm->sq.rdinx);

	return pe_hw_src;
}

/*
	Check the counter range:
	returned:
		1: Up too much
		0: safe
		-1: down too much
*/
CNT_RANGE
wlCheckCnterRange(SINT32 cntval, SINT32 * plastval, SINT32 diffval)
{
	CNT_RANGE result = CNT_RANGE_SAFE;
	SINT32 cnt_diff = cntval - *plastval;

	if (diffval < cnt_diff) {
		*plastval = cntval;
		result = CNT_RANGE_UP;
	} else if (cnt_diff < diffval * -1) {
		*plastval = cntval;
		result = CNT_RANGE_DOWN;
	}

	return result;
}

// Pkt payload: (using ping). Ref: log-0105-real_pkt.txt
/*
   ping 192.168.1.200
   mac: 80:e6:50:15:f7:d2

   64 bytes from 192.168.1.200: icmp_seq=1 ttl=64 time=48.8 ms
   => pkt (36)
   00000000: aa aa 03 00 00 00 08 06 00 01 08 00 06 04 00 01
   00000010: 80 e6 50 15 f7 d2 c0 a8 01 c8 00 00 00 00 00 00
   00000020: c0 a8 01 02

   => pkt (92)
   00000000: aa aa 03 00 00 00 08 00|45 00 00 54 56 f1 40 00
   00000010: 40 01 5f 3b|c0 a8 01 64|c0 a8 01 c8|08 00 d8 ca
   00000020: d8 0e 00 02 72 de 97 58 48 ea 09 00 08 09 0a 0b
   00000030: 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b
   00000040: 1c 1d 1e 1f 20 21 22 23 24 25 26 27 28 29 2a 2b
   00000050: 2c 2d 2e 2f 30 31 32 33 34 35 36 37

   64 bytes from 192.168.1.200: icmp_seq=2 ttl=64 time=33.2 ms
   => pkt (36)
   00000000: aa aa 03 00 00 00 08 06 00 01 08 00 06 04 00 01
   00000010: 80 e6 50 15 f7 d2 c0 a8 01 c8 00 00 00 00 00 00
   00000020: c0 a8 01 02

   => pkt (92)
   00000000: aa aa 03 00 00 00 08 00 45 00 00 54 56 f2 40 00
   00000010: 40 01 5f 3a c0 a8 01 64 c0 a8 01 c8 08 00 12 c5
   00000020: d8 0e 00 03 73 de 97 58 0d ef 09 00 08 09 0a 0b
   00000030: 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b
   00000040: 1c 1d 1e 1f 20 21 22 23 24 25 26 27 28 29 2a 2b
   00000050: 2c 2d 2e 2f 30 31 32 33 34 35 36 37

 */
wltxdesc_t *
wlSkbToCfhDl(struct net_device * netdev, struct sk_buff * skb,
	     wltxdesc_t * txcfg, int qid, int type)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	struct pkttype_info *wlpkt_typecnt_p = &wlpd_p->tpkt_type_cnt;
	struct wldesc_data *wlqm;
	wltxdesc_t *txdesc = NULL;
	int is_aligned;

#ifdef TP_PROFILE
	if (type == IEEE_TYPE_DATA) {
		if (wl_tp_profile_test(7, skb, netdev)) {
			wl_free_skb(skb);
			return 0;
		}
	}
#endif

	WLDBG_DATA(DBG_LEVEL_2, "=== orig skb (%d)====\n", skb->len);
	WLDBG_HEXDUMP(DBG_LEVEL_2, skb->data, skb->len);

	// remove ethernet header
	if (type == IEEE_TYPE_DATA)
		skb_pull(skb, ETHER_HDR_LEN);
	wlqm = &wlpptr->wlpd_p->descData[qid];

	if (wlRQFull(netdev, qid) == FALSE) {	// check rd/wr index to check queue is full or not
		txdesc = (wltxdesc_t *) (wlqm->rq.virt_addr +
					 wlqm->rq.wrinx * sizeof(wltxdesc_t));
		memcpy(txdesc, txcfg, sizeof(wltxdesc_t));

		is_aligned = IS_ALIGNED(((long)skb->data), TXBUF_ALIGN);

		if (!is_aligned)
			wlpd_p->except_cnt.cnt_tx_misalign++;

		//Check if mis-aligned packets work or not
		if (skb_cloned(skb)) {
			// Create and align the skb->data
			// => Need to align packet buffer only for SC5 Z1 or Z2
			struct sk_buff *skb_align =
				wl_alloc_skb(skb->len + TXBUF_ALIGN +
					     SKB_INFO_SIZE);
			if (!skb_align) {
				wl_free_skb(skb);
				return NULL;
			}
			skb_reserve(skb_align, SKB_INFO_SIZE);
			skb_put(skb_align, skb->len);
			skb_align->data =
				PTR_ALIGN(skb_align->data, TXBUF_ALIGN);
			memcpy(skb_align->data, skb->data, skb->len);
			skb_align->priority = skb->priority;
			wl_free_skb(skb);
			skb = skb_align;
		}

		*((u32 *) (skb->data - SKB_INFO_SIZE)) = SKB_SIGNATURE;
		*(struct sk_buff **)(skb->data - SKB_POINTER_OFFSET) = skb;

		txdesc->hdr.lo_dword_addr =
			dma_map_single(wlpptr->wlpd_p->dev, skb->data, skb->len,
				       DMA_TO_DEVICE);

		// Record the counter of pkt types
		{
			if (type != IEEE_TYPE_DATA) {
				// Mgmt / Ctrl pkt
				wl_pkttype_stat(wlpkt_typecnt_p,
						&wlpkt_typecnt_p->pkt_fc);
				memset(&wlpkt_typecnt_p->pkt_fc, 0,
				       sizeof(IEEEtypes_FrameCtl_t));
			} else {
				IEEEtypes_FrameCtl_t fc;
				fc.Type = type;
				wl_pkttype_stat(wlpkt_typecnt_p, &fc);
				wl_get_datpkt_prot(wlpkt_typecnt_p,
						   txcfg->snap1 >> 16,
						   (struct iphdr *)skb->data);
			}

		}
#if defined(TXACNT_REC)
		txdesc->hdr.skb_addr = virt_to_phys(skb);
		if ((type == IEEE_TYPE_DATA) && (txacnt_idmsg > 0)) {
			printk("[TXACNT]%s(), (skb, skb->dat)=(%p, %p)\n",
			       __func__, skb, skb->data);
		}
		memset(skb->cb, 0, sizeof(void *));
		*((struct sk_buff_head **)skb->cb) =
			&wlpd_p->pend_skb_trace[PENDSKB_TX];
#endif //#if defined(TXACNT_REC)

		{
			UINT32 max_tx_pend_cnt;
			UINT32 stnId;

			wlpd_p->except_cnt.txq_pend_cnt[txcfg->qid] =
				wlpd_p->except_cnt.txq_send_cnt[txcfg->qid] -
				wlpd_p->except_cnt.txq_rel_cnt[txcfg->qid];

			if (txcfg->qid < QUEUE_STAOFFSET) {
				if ((txcfg->qid % MAX_TID) >= 6) {
					max_tx_pend_cnt =
						dbg_max_tx_pend_cnt_per_mgmt_q;
				} else {
					max_tx_pend_cnt =
						dbg_max_tx_pend_cnt_per_bcast_q;
				}

				if (wlpd_p->except_cnt.
				    txq_pend_cnt[txcfg->qid] >=
				    max_tx_pend_cnt) {
					wlpd_p->except_cnt.txq_drop_cnt[txcfg->
									qid]++;
					goto error_to_send;
				}

			} else {
				max_tx_pend_cnt = dbg_max_tx_pend_cnt_per_q;

				stnId = (txcfg->qid -
					 QUEUE_STAOFFSET) / MAX_TID;
				wlpd_p->except_cnt.tx_sta_pend_cnt[stnId] =
					wlpd_p->except_cnt.
					tx_sta_send_cnt[stnId] -
					wlpd_p->except_cnt.
					tx_sta_rel_cnt[stnId];

				if ((wlpd_p->except_cnt.
				     txq_pend_cnt[txcfg->qid] >=
				     max_tx_pend_cnt) ||
				    (wlpd_p->except_cnt.
				     tx_sta_pend_cnt[stnId] >=
				     dbg_max_tx_pend_cnt_per_sta)) {
					wlpd_p->except_cnt.txq_drop_cnt[txcfg->
									qid]++;
					wlpd_p->except_cnt.
						tx_sta_drop_cnt[stnId]++;
					goto error_to_send;
				}
			}

		}

		WLDBG_DATA(DBG_LEVEL_4,
			   " skb before wlRQIndexPut(): (%p, %p, %p, %p)\n",
			   __func__, skb->head, skb->data, skb->end, skb->tail);
		wl_chk_drop_pkt(wlpd_p);
		if (wlRQIndexPut(qid, &wlqm->rq) == TRUE) {
			UINT32 tx_pend_cnt;
			spin_lock_bh(&wlpd_p->pend_skb_trace[PENDSKB_TX].lock);
			wlpd_p->tx_pend_skb_msg[tst_send][wlpd_p->
							  tx_pend_skb_msg_id
							  [tst_send]] = skb;
			wlpd_p->tx_pend_skb_msg_id[tst_send] =
				(wlpd_p->tx_pend_skb_msg_id[tst_send] +
				 1) % MAX_PENDSKBMSG;
			__skb_queue_tail(&wlpd_p->pend_skb_trace[PENDSKB_TX],
					 skb);
			spin_unlock_bh(&wlpd_p->pend_skb_trace[PENDSKB_TX].
				       lock);

			/* debug for invalid skb */
			if (unlikely
			    ((dbg_invalid_skb & dbg_ivalskb_tx) &&
			     wlpd_p->dbgskb.skb_send &&
			     !wlpd_p->dbgskb.skb_stop)) {
				dbg_skb *p = &wlpd_p->dbgskb;
				(p->skb_send + p->skb_send_idx)->pa =
					txdesc->hdr.lo_dword_addr;
				(p->skb_send + p->skb_send_idx)->va_data =
					skb->data;
				(p->skb_send + p->skb_send_idx)->va_skb =
					(u_int8_t *) skb;
				(p->skb_send + p->skb_send_idx)->wr =
					wlqm->rq.wrinx;
				ktime_get_ts(&(p->skb_send + p->skb_send_idx)->
					     ts);

				if (virt_to_pfn(skb->data) == 0) {
					WLDBG_ERROR(DBG_LEVEL_0,
						    "dbgskb: send skb %p skb->data %p pfn 0, ts %lu:%lu\n",
						    (p->skb_send +
						     p->skb_send_idx)->va_skb,
						    (p->skb_send +
						     p->skb_send_idx)->va_data,
						    (p->skb_send +
						     p->skb_send_idx)->ts.
						    tv_sec,
						    (p->skb_send +
						     p->skb_send_idx)->ts.
						    tv_nsec);
				}

				p->skb_send_idx =
					(p->skb_send_idx + 1) % DBG_SKB_MAX_NUM;

			}
			wlUpdateWrPtr(netdev, qid, SC5_RQ, wlqm->rq.wrinx,
				      false);
#ifdef TP_PROFILE
			logTPStats(&wlpd_p->drv_stats_val.cfhdltx_stat, 1,
				   skb->len);
			wlpd_p->wl_tpprofile.tx.packets += 1;
			wlpd_p->wl_tpprofile.tx.bytes += skb->len;
#endif

			wlpd_p->except_cnt.txq_send_cnt[txcfg->qid]++;

			if (txcfg->qid < QUEUE_STAOFFSET) {
				if ((txcfg->qid % MAX_TID) >= 6) {
					wlpd_p->except_cnt.tx_mgmt_send_cnt++;
				} else {
					wlpd_p->except_cnt.tx_bcast_send_cnt++;
				}
			} else {
				UINT32 stnId;
				stnId = (txcfg->qid -
					 QUEUE_STAOFFSET) / MAX_TID;
				wlpd_p->except_cnt.tx_sta_send_cnt[stnId]++;
			}

			wlpd_p->drv_stats_val.txq_drv_sent_cnt++;
			tx_pend_cnt =
				(wlpd_p->drv_stats_val.txq_drv_sent_cnt -
				 wlpd_p->drv_stats_val.txbuf_rel_cnt);

#ifdef TP_PROFILE
			logTPCounter(&wlpd_p->drv_stats_val.cfhdltx_stat,
				     tx_pend_cnt,
				     wlpd_p->drv_stats_val.txq_drv_sent_cnt,
				     wlpd_p->drv_stats_val.txq_full_cnt);
#endif
			wlpptr->netDevStats.tx_packets++;
			wlpptr->netDevStats.tx_bytes += skb->len;
			if (wlpptr->master) {
				((NETDEV_PRIV_P
				  (struct wlprivate,
				   wlpptr->master)))->netDevStats.tx_packets++;
				((NETDEV_PRIV_P
				  (struct wlprivate,
				   wlpptr->master)))->netDevStats.tx_bytes +=
			   skb->len;
			}

			{	//If the counter is over the level => print the warning message automatically
				SINT32 res =
					wlCheckCnterRange((SINT32) tx_pend_cnt,
							  &(wlpd_p->
							    drv_stats_val.
							    txpend_lastcnt),
							  BMQ_DIFFMSG_COUNT);
				if (res == CNT_RANGE_UP) {
					WLDBG_WARNING(DBG_LEVEL_0,
						      "tx-pending packets count reachs %d\n",
						      tx_pend_cnt);
				} else if (res == CNT_RANGE_DOWN) {
					WLDBG_WARNING(DBG_LEVEL_0,
						      "tx-pending packets count drops down to %d\n",
						      tx_pend_cnt);
				}
			}
		} else {
			WLDBG_WARNING(DBG_LEVEL_0,
				      "Queue is full, failed to send\n");
			goto error_to_send;
		}
	} else {
		// Queue is full => free the skb directly
		struct except_cnt *wlexcept_p = &wlpd_p->except_cnt;

		wlexcept_p->qfull_empty[qid][SC5_RQ]++;
		wlpd_p->drv_stats_val.txq_full_cnt++;

		wlpptr->netDevStats.tx_dropped++;
		if (wlpptr->master) {
			((NETDEV_PRIV_P(struct wlprivate, wlpptr->master)))->
				netDevStats.tx_dropped++;
		}

		wl_free_skb(skb);
		return NULL;
	}

	return txdesc;
error_to_send:
	dma_unmap_single(wlpptr->wlpd_p->dev, virt_to_phys(skb->data),
			 wlqm->rq.bm.buf_size, DMA_FROM_DEVICE);

	wlpptr->netDevStats.tx_dropped++;
	if (wlpptr->master) {
		((NETDEV_PRIV_P(struct wlprivate, wlpptr->master)))->
			netDevStats.tx_dropped++;
	}

	wl_free_skb(skb);
	return NULL;
}

typedef struct _smac_qminf {
	volatile u32 bpid;
	volatile u32 buf_addr;
} __attribute__ ((packed)) SMAC_QMINFO;

#define LOG_SIZE        2048
#define DUMP_SIZE       48
#define TRACEBACK_SIZE  32

/*
        This function is to dump the release bpid/buffer_pointer for debug purpose
        Procedure:
                - Get offset_base => Dmem offset of base address of the debug information table
                - Get offset_cnt => Dmem offset of item count of debug information table
 */
void
wl_dump_dbgrelq_info(struct net_device *netdev, u32 offset_base, u32 offset_cnt)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	unsigned int i, offset, j = 0;
	unsigned char *valbuf = NULL;
	volatile unsigned int baseptr =
		le32_to_cpu(*(volatile unsigned int *)
			    (priv->ioBase0 + offset_base));
	volatile unsigned int entrycnt =
		le32_to_cpu(*(volatile unsigned int *)
			    (priv->ioBase0 + offset_cnt));
	SMAC_QMINFO *pinfo;

	WLDBG_INFO(DBG_LEVEL_0, "Total cnt=%u\n", entrycnt);

	offset = baseptr - SMAC_DMEM_START;
	entrycnt &= (LOG_SIZE - 1);
	WLDBG_INFO(DBG_LEVEL_0, "offet=%x; cnt=%x\n", offset, entrycnt);
	if ((offset + entrycnt * sizeof(SMAC_QMINFO)) > (900 * 1024)) {
		WLDBG_ERROR(DBG_LEVEL_0, "Offset is too big: %xh %xh\n", offset,
			    entrycnt);
		return;
	}
	if (entrycnt == 0) {
		WLDBG_WARNING(DBG_LEVEL_0, "Entry count = %d\n", entrycnt);
		return;
	}

	/*
	   Allocate a memory to save the data, then dump the result to reduce the output latency
	 */
	valbuf = wl_kmalloc(sizeof(SMAC_QMINFO) * entrycnt, GFP_ATOMIC);
	if (valbuf == NULL) {
		WLDBG_ERROR(DBG_LEVEL_0, "Failed to allocate memory\n");
		return;
	}
	j = (entrycnt - TRACEBACK_SIZE) & (LOG_SIZE - 1);
	for (i = 0, pinfo = (SMAC_QMINFO *) valbuf; i < DUMP_SIZE; i++, pinfo++) {
		pinfo->bpid =
			le32_to_cpu(*(volatile unsigned int *)
				    (priv->ioBase0 + offset +
				     j * sizeof(SMAC_QMINFO) + 0));
		pinfo->buf_addr =
			le32_to_cpu(*(volatile unsigned int *)
				    (priv->ioBase0 + offset +
				     j * sizeof(SMAC_QMINFO) + 4));
		j++;
		j &= (LOG_SIZE - 1);
	}
	/*
	   Dump the result
	 */
	WLDBG_INFO(DBG_LEVEL_0, "================\n");
	WLDBG_INFO(DBG_LEVEL_0, "[%04xh %04xh Debug Log]\n\n", offset_base,
		   offset_cnt);
	j = (entrycnt - TRACEBACK_SIZE) & (LOG_SIZE - 1);
	for (i = 0, pinfo = (SMAC_QMINFO *) valbuf; i < DUMP_SIZE; i++, pinfo++) {
		WLDBG_INFO(DBG_LEVEL_0, "[%d], bpid=%d, buf_addr=%08xh\n", j,
			   pinfo->bpid, pinfo->buf_addr);
		j++;
		j &= (LOG_SIZE - 1);
	}
	WLDBG_INFO(DBG_LEVEL_0, "================\n");
	//WLDBG_INFO(DBG_LEVEL_0, "=========================================\n");
	//WLDBG_HEXDUMP(DBG_LEVEL_0, valbuf, sizeof(SMAC_QMINFO)*entrycnt);

	if (valbuf != NULL)
		wl_kfree(valbuf);

	return;
}

/* caller pass buffer pool elelent, and based on the phys address to find
   the corresponding skb and return */
struct sk_buff *
wlPeToSkb(struct net_device *netdev, bm_pe_hw_t * pe_hw)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	struct sk_buff *skb = NULL;
	unsigned char *skb_virt;
	u32 signature;
	struct wldesc_data *wlqm;
	u8 bmq_flag = 0;
	u8 bpid = 0;
	bm_pe_hw_t pe_hw_mochi, *pe_hw_ptr;

	if (IS_BUS_TYPE_MCI(wlpptr)) {
		pe_hw_ptr = &pe_hw_mochi;
		memcpy(&pe_hw_mochi, pe_hw, sizeof(bm_pe_hw_t));
	} else
		pe_hw_ptr = pe_hw;

	WLDBG_DATA(DBG_LEVEL_2,
		   "bpid: %d, SKB: pe_hw->pe0_lo_dword_addr = %x \n",
		   pe_hw_ptr->bpid, pe_hw_ptr->pe0_lo_dword_addr);

	// bpid == 14 (ReleaseQ) for tx-done
	//              or SC5_BMQ_START_INDEX ~ (SC5_BMQ_START_INDEX + SC5_BMQ_NUM - 1) for rx-drop
	bpid = REL_RX_BPID(pe_hw_ptr->bpid);
	wlqm = &wlpptr->wlpd_p->descData[bpid];
	if ((SC5_BMQ_START_INDEX <= bpid) &&
	    (bpid < (SC5_BMQ_START_INDEX + SC5_BMQ_NUM - 1)))
		bmq_flag = 1;

	dma_unmap_single(wlpptr->wlpd_p->dev, pe_hw_ptr->pe0_lo_dword_addr,
			 wlqm->rq.bm.buf_size,
			 ((bmq_flag) ? DMA_FROM_DEVICE : DMA_TO_DEVICE));

	skb_virt = (unsigned char *)phys_to_virt(pe_hw_ptr->pe0_lo_dword_addr);

	if (unlikely(!virt_addr_valid(skb_virt - SKB_INFO_SIZE))) {
		wlpd_p->except_cnt.invalid_buf_addr++;
		// Both tx (txdone) and rx (drop pkt) may reach in here. 
		if (dbg_invalid_skb != dbg_ivalskb_disable)
			WLDBG_ERROR(DBG_LEVEL_0,
				    "dbgskb: invalid skb signature va %p\n",
				    skb_virt - SKB_INFO_SIZE);
		return NULL;
	}
	signature = *((u32 *) (skb_virt - SKB_INFO_SIZE));

	/* debug for invalid skb */
	if (unlikely
	    ((dbg_invalid_skb & dbg_ivalskb_tx) && !bmq_flag &&
	     wlpd_p->dbgskb.skb_back && !wlpd_p->dbgskb.skb_stop)) {
		dbg_skb *p = &wlpd_p->dbgskb;

		(p->skb_back + p->skb_back_idx)->pa =
			pe_hw_ptr->pe0_lo_dword_addr;
		(p->skb_back + p->skb_back_idx)->va_data = skb_virt;
		(p->skb_back + p->skb_back_idx)->va_skb =
			*(u_int8_t **) (skb_virt - SKB_POINTER_OFFSET);
		(p->skb_back + p->skb_back_idx)->rd = wlqm->sq.rdinx;
		(p->skb_back + p->skb_back_idx)->bpid = bpid;
		(p->skb_back + p->skb_back_idx)->signature = signature;
		ktime_get_ts(&(p->skb_back + p->skb_back_idx)->ts);
		p->skb_back_idx = (p->skb_back_idx + 1) % DBG_SKB_MAX_NUM;

		if (p->skb_invalid == 1) {
			p->skb_back_stop_idx++;
			if (p->skb_back_stop_idx == 3) {
				p->skb_stop = 1;	//stop all skb in tx/rx
				WLDBG_ERROR(DBG_LEVEL_0,
					    "dbgskb: stop all skb tx/rx\n");

				disableSMACTx(netdev);
				disableSMACRx(netdev);

				if (dbg_invalid_skb & dbg_ivalskb_coredump) {
					triggerCoredump(netdev);
				}

			}
		}
	}

	if (signature == SKB_SIGNATURE) {
		skb = *(struct sk_buff **)(skb_virt - SKB_POINTER_OFFSET);
		if (!virt_addr_valid(skb)) {
			wlpd_p->except_cnt.invalid_buf_addr++;
			return NULL;
		}
		// Destroy the signature
		memset((skb_virt - SKB_INFO_SIZE), 0,
		       SKB_SIGNATURE_SIZE + sizeof(void *));
	} else {
		if (signature == USED_SIGNATURE) {
			wlpd_p->except_cnt.dup_txdone_cnt++;
		} else {
			wlpd_p->except_cnt.skb_invalid_signature_cnt++;
			if (unlikely(dbg_invalid_skb != dbg_ivalskb_disable)) {
				wlpd_p->dbgskb.skb_invalid = 1;	//first time invalid signature
				WLDBG_ERROR(DBG_LEVEL_0,
					    "invalid skb: signature %x skb_data %p\n",
					    signature, skb_virt);
			}
		}
#ifndef ASSERT_MALBUF
		//WLDBG_ERROR(DBG_LEVEL_0, "[skb_addr]skb signature is not correct %x. skb_virt:%p  pe0_lo_dword_addr:%x \n",
		//          signature, skb_virt, pe_hw->pe0_lo_dword_addr);
		return NULL;
#else
		dbg_level = 0x1;
		wl_util_writel(netdev, 0xdeadbeef, wlpptr->ioBase1 + PCI_REG_SCRATCH14_REG);
		wl_dump_dbgrelq_info(netdev, 0x528, 0x52c);
		wl_dump_dbgrelq_info(netdev, 0x520, 0x524);
		wl_dump_dbgrelq_info(netdev, 0x518, 0x51c);

		mwl_hex_dump(pe_hw_ptr, sizeof(bm_pe_hw_t));
		WL_ASSERT(FALSE,
			  ("[skb_addr]skb signature is not correct %x. skb_virt:%p  pe0_lo_dword_addr:%x \n",
			   signature, skb_virt, pe_hw->pe0_lo_dword_addr));
		return NULL;
#endif
	}
	//if (atomic_read(&skb_shinfo(skb)->dataref) == 1) {
	// Reset the signature after it (the buffer, not skb) is done
	//      *((u32*)(skb_virt - SKB_INFO_SIZE)) = USED_SIGNATURE;
	//}

	/*
	   RX drop packets, bpid = 
	   [SC5_BMQ_START_INDEX ~ SC5_BMQ_START_INDEX+SC5_BMQ_NUM]
	 */
	if (bmq_flag) {
		// RX drop packets
		WLDBG_INFO(DBG_LEVEL_0,
			   "Rx Drop Pkt, bpid=%d, pe0_lo_dword_addr:%p",
			   REL_RX_BPID(pe_hw->bpid), pe_hw->pe0_lo_dword_addr);

		// consuming 1 buffer => dropped by firmware
		//wlpd_p->drv_stats_val.enq_bmqbuf_cnt[REL_RX_BPID(pe_hw->bpid) - SC5_BMQ_START_INDEX]--;
		wlpd_p->drv_stats_val.rx_drop_cnt[bpid - SC5_BMQ_START_INDEX]++;
		wlpd_p->drv_stats_val.xx_buf_free_SQ14[bpid -
						       SC5_BMQ_START_INDEX]++;

		skb->data = skb_virt;
		if (skb->next && skb->prev)
			reset_signature(skb_virt);

		WLDBG_DATA(DBG_LEVEL_1,
			   "Txdone drop bpid:%u, cnt:%u %u %u %u\n",
			   REL_RX_BPID(pe_hw->bpid),
			   wlpd_p->drv_stats_val.xx_buf_free_SQ14[0],
			   wlpd_p->drv_stats_val.xx_buf_free_SQ14[1],
			   wlpd_p->drv_stats_val.xx_buf_free_SQ14[2],
			   wlpd_p->drv_stats_val.xx_buf_free_SQ14[3]);

		// Remove the skb from the pend_skb_trace[PENDSKB_RX],
		if (!skb->next || !skb->prev) {
			wlpd_p->except_cnt.skb_notlinked_cnt++;
			if (unlikely((dbg_invalid_skb & dbg_ivalskb_rx))) {
				WLDBG_ERROR(DBG_LEVEL_0,
					    "dbgskb: wlPeToSkb Rx bpid %d: skb %p not linked. skb_data va %p signature 0x%8x dump skb_data:\n",
					    bpid, skb, skb->data,
					    *((u32 *) (skb->data -
						       SKB_INFO_SIZE)));
				if (skb->data && skb->len)
					mwl_hex_dump(skb->data, skb->len);
			}
			return NULL;
		}
		spin_lock(&wlpd_p->pend_skb_trace[PENDSKB_RX].lock);
		__skb_unlink(skb, &wlpd_p->pend_skb_trace[PENDSKB_RX]);
		spin_unlock(&wlpd_p->pend_skb_trace[PENDSKB_RX].lock);
		// Free the rx dropped packets
		wl_free_skb(skb);

		// Put the signature to show that this buffer is clean;
		pe_hw->bgn_signature = pe_hw->end_signature = BMBUF_SIGNATURE;
		return NULL;
	}
	// Put the signature to show that this buffer is clean;
	pe_hw->bgn_signature = pe_hw->end_signature = BMBUF_SIGNATURE;

	WLDBG_DATA(DBG_LEVEL_4, "CFH_DL skb = %p \n", skb);
	return skb;
}

int
wlQMCleanUp(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;

	WLDBG_INFO(DBG_LEVEL_0, "%s wlQMCleanUp \n", netdev->name);
	wlRxQueueCleanUp(netdev);
#if defined(ACNT_REC)
	wlRAcntQueueCleanUp(netdev);
#endif //defined(ACNT_REC)
#if defined (RXACNT_REC)
	wlRxAcntPPDUCleanup(netdev);
#endif //RXACNT_REC
#if defined(TXACNT_REC)
	wlTAcntBufCleanUp(netdev);
#endif //defined(TXACNT_REC)
	wlTxQueueCleanUp(netdev);
	wlBmQueueCleanUp(netdev);
	wlBufReleaseQueueCleanUp(netdev);
	wlclean_extmembuf(wlpptr, &wlpd_p->ext_membuf[0]);

	{
		struct sk_buff *skb;
		while ((skb =
			skb_dequeue(&(wlpd_p->pend_skb_trace[PENDSKB_TX]))) !=
		       NULL) {
			wl_free_skb(skb);
		}
		while ((skb =
			skb_dequeue(&(wlpd_p->pend_skb_trace[PENDSKB_RX]))) !=
		       NULL) {
			wl_free_skb(skb);
		}
	}

	if (wlpptr->event_bufq_vaddr != NULL) {
		wl_dma_free_coherent(wlpptr->wlpd_p->dev,
				     EVENT_BUFFQ_NUM * EVENT_BUFFQ_SIZE,
				     wlpptr->event_bufq_vaddr,
				     wlpptr->event_bufq_paddr);
		wlpptr->event_bufq_vaddr = NULL;
	}
	// Cleanup the exception counters, since the firmware will be new
	memset(&wlpd_p->except_cnt, 0, sizeof(struct except_cnt));
	// Clean up the driver counters
	memset(&wlpd_p->drv_stats_val, 0, sizeof(struct drv_stats));

	wl_deinit_droppkt_info(netdev);
	dbgskb_deinit(netdev);
	if (wlpd_p->descData[0].pInfoPwrTbl) {
		wl_kfree(wlpd_p->descData[0].pInfoPwrTbl);
		wlpd_p->descData[0].pInfoPwrTbl = NULL;
	}

	return SUCCESS;
}

void
post_init_bq_idx(struct net_device *netdev, bool is_init)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	struct bqm_args *pbqm_args = &wlpd_p->bmq_args;

	int qid;
	struct wldesc_data *wlqm;

	WLDBG_INFO(DBG_LEVEL_0, "Updating rd/wr idx\n");

	WLDBG_INFO(DBG_LEVEL_0, "================= Bmq=============\n");
	// Init the rd/wr idx of BmQ
	for (qid = SC5_BMQ_START_INDEX;
	     qid < (SC5_BMQ_START_INDEX + SC5_BMQ_NUM); qid++) {
		wlqm = &wlpptr->wlpd_p->descData[qid];
		wlqm->rq.rdinx = wlQueryRdPtr(netdev, qid, SC5_RQ);
		wlUpdateWrPtr(netdev, qid, SC5_RQ, wlqm->rq.wrinx, is_init);
		WLDBG_INFO(DBG_LEVEL_0,
			   "Q(%d), rqsize=%d, (rinx, winx)=(%d, %d)\n", qid,
			   wlqm->rq.qsize, wlqm->rq.rdinx, wlqm->rq.wrinx);
	}

	WLDBG_INFO(DBG_LEVEL_0, "================= RxQ=============\n");
	// Init the rd/wr idx of RxQ
	for (qid = SC5_RXQ_START_INDEX;
	     qid < (SC5_RXQ_START_INDEX + SC5_RXQ_NUM); qid++) {
		if (((1 << qid) & SC5_RXQ_MASK) == 0) {	// Not enabled
			continue;
		}
		wlqm = &wlpptr->wlpd_p->descData[qid];
		wlUpdateRdPtr(netdev, qid, SC5_SQ, wlqm->sq.rdinx, is_init);
		wlqm->sq.wrinx = wlQueryWrPtr(netdev, qid, SC5_SQ);
		WLDBG_INFO(DBG_LEVEL_0,
			   "Q(%d), sqsize=%d, (rinx, winx)=(%d, %d)\n", qid,
			   wlqm->sq.qsize, wlqm->sq.rdinx, wlqm->sq.wrinx);
	}
	WLDBG_INFO(DBG_LEVEL_0, "================= TxQ =============\n");
	// Init the rd/wr idx of TxQ
	for (qid = pbqm_args->txq_start_index;
	     qid < (pbqm_args->txq_start_index + pbqm_args->txq_num); qid++) {
		WLDBG_INFO(DBG_LEVEL_0,
			   "Q(%d), qsize=%d, (rinx, winx)=(%d, %d)\n", qid,
			   wlqm->rq.qsize, wlqm->rq.rdinx, wlqm->rq.wrinx);
		wlqm = &wlpptr->wlpd_p->descData[qid];
		wlqm->rq.rdinx = wlQueryRdPtr(netdev, qid, SC5_RQ);
		wlUpdateWrPtr(netdev, qid, SC5_RQ, wlqm->rq.wrinx, is_init);
		WLDBG_INFO(DBG_LEVEL_0,
			   "Q(%d), rqsize=%d, (rinx, winx)=(%d, %d)\n", qid,
			   wlqm->rq.qsize, wlqm->rq.rdinx, wlqm->rq.wrinx);
	}
	WLDBG_INFO(DBG_LEVEL_0, "================= ReleaseQ =============\n");
	// Init the rd/wr idx of ReleaseQ
	for (qid = pbqm_args->bmq_release_index;
	     qid < (pbqm_args->bmq_release_index + pbqm_args->bmq_release_num);
	     qid++) {
		wlqm = &wlpptr->wlpd_p->descData[qid];
		wlUpdateRdPtr(netdev, qid, SC5_SQ, wlqm->sq.rdinx, is_init);
		wlqm->sq.wrinx = wlQueryWrPtr(netdev, qid, SC5_SQ);
		WLDBG_INFO(DBG_LEVEL_0,
			   "Q(%d), sqsize=%d, (rinx, winx)=(%d, %d)\n", qid,
			   wlqm->sq.qsize, wlqm->sq.rdinx, wlqm->sq.wrinx);
	}
	{
		int i;
		for (i = SC5_BMQ_START_INDEX;
		     i < SC5_BMQ_START_INDEX + SC5_BMQ_NUM; i++) {
			check_queue_index(netdev, i, SC5_RQ);
		}

	}
	return;
}

/*
   ping 192.168.0.200
   mac: 80:e6:50:15:f7:d2

   64 bytes from 192.168.0.200: icmp_seq=1 ttl=64 time=48.8 ms

   read pkt:

   BSSID: (from "iwpriv wdev0 getbssid")
   wdev0     getbssid:MAC 00:50:43:21:01:02
   STA: 01:23:45:67:80:ab

   => wlxmit(), pkt (92), ping_resp
   00000000: aa aa 03 00 00 00 08 00|45 00 00 54 3f 08 00 00
   00000010: 80 01 79 7f c0 a8 00 09 c0 a8 00 c8 00 00 97 20
   00000020: 9c 53 00 01 58 75 ef 08 00 01 9a 08 08 09 0a 0b
   00000030: 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b
   00000040: 1c 1d 1e 1f 20 21 22 23 24 25 26 27 28 29 2a 2b
   00000050: 2c 2d 2e 2f 30 31 32 33 34 35 36 37
 */
static char testllc[8] = {
	'\xaa', '\xaa', '\03', '\x00', '\x00', '\x00', '\x08', '\x00'
};

static char testpkt[LONG_PKTSIZE] = {
	// ethernet/802.3 header: 14 bytes
	'\x00', '\x50', '\x43', '\x20', '\x03', '\x04',
	'\x00', '\x50', '\x43', '\x21', '\x01', '\x02',
	'\x08', '\x00',
	// IP: 20 bytes
	'\x45', '\x00', '\x05', '\xDC', '\x54', '\x0D', '\x00', '\x00',
	'\x80', '\x01', '\x00', '\x00', '\xc0', '\xa8', '\x00', '\x09',
	'\xc0', '\xa8', '\x00', '\xc8',
	//ICMP: 8 bytes
	'\x08', '\x00', '\x6C', '\xBD', '\x00', '\x01', '\x00', '\xAE',
	//data: 1472 bytes
	//...
};

/*
   Add BA request
   d0 00 3a 01 00 03 7f 12 3e 67 00 10 18 f8 dd ed
   00 03 7f 12 3e 67 60 0a 03 00 d7 03 10 00 00 e0
   02
 */
void
pkt_init(char *pkt)
{
	int i;
	const int xheader = ETHER_HDR_LEN + IP_HDR_LEN + ICMP_HDR_LEN;	//ethernet+ip+icmp

	for (i = 0; i < LONG_PKTSIZE - xheader; i++) {
		pkt[i + xheader] = (0x08 + i) & 0xff;
	}
	//mwl_hex_dump(testpkt, sizeof(testpkt));
	return;
}

static u8 qm_own_mac[6];
static u8 qm_sta_mac[6];
#define DATDA_OFFSET            0
#define DATSA_OFFSET            6
#define DURATION_LEN            2
static const u8 mgmt_addr_base = sizeof(wl_frame_ctrl) + DURATION_LEN;
void
wl_set_da(UINT32 * sta_mac)
{
	memcpy(qm_sta_mac, sta_mac, sizeof(u8) * 6);
//      int i;
//      for (i=0 ; i<6 ; i++) {
//              qm_sta_mac[i] = sta_mac[i];
//              printk("%d, %xh\n", i, sta_mac[i]);
//      }
	WLDBG_INFO(DBG_LEVEL_0, "STA=%02x:%02x:%02x:%02x:%02x:%02x\n",
		   qm_sta_mac[0], qm_sta_mac[1], qm_sta_mac[2],
		   qm_sta_mac[3], qm_sta_mac[4], qm_sta_mac[5]);
	return;
}

void
wl_set_qm_sa(IEEEtypes_MacAddr_t StaMacAddr)
{
	int i;

	for (i = 0; i < 6; i++) {
		qm_own_mac[i] = StaMacAddr[i];
	}
	WLDBG_INFO(DBG_LEVEL_0, "OWN=%02x:%02x:%02x:%02x:%02x:%02x\n",
		   qm_own_mac[0], qm_own_mac[1], qm_own_mac[2],
		   qm_own_mac[3], qm_own_mac[4], qm_own_mac[5]);

	//printk("%s(), MAC_Addr:=%02x:%02x:%02x:%02x:%02x:%02x\n",__func__,
	//      netdev->dev_addr[0], netdev->dev_addr[1], netdev->dev_addr[2],
	//      netdev->dev_addr[3], netdev->dev_addr[4], netdev->dev_addr[5]);

	return;
}

void
InitCFHDLMgmt(struct net_device *netdev, struct bqm_args *pbqm_args,
	      wltxdesc_t * cfg, struct sk_buff *skb)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	u16 offset;
	wl_frame_ctrl *frm_ctrl;
	u8 da_id, sa_id;
	U8 wifi_header_size;

	memset(cfg, 0, sizeof(*cfg));
	cfg->hdr.hi_byte_addr = wlpptr->wlpd_p->reg.smac_buf_hi_addr;

	cfg->hdr.bpid = pbqm_args->txq_start_index;

	// length = skb->length - sizeof(802.11_header)
	cfg->hdr.cfh_length = 64;
	wifi_header_size = sizeof(struct ieee80211_hdr_3addr);	// not include address 4
	cfg->hdr.timestamp = jiffies;

	cfg->qid = skb->priority;
	//cfg->qid = 256;       //Qid is 256 after BSS in smac is enabled
	WLDBG_INFO(DBG_LEVEL_1, " cfg->qid = %d\n", cfg->qid);

	cfg->mpdu_flag = 1;
	cfg->ndr = 1;
	cfg->vtv = 0;
	cfg->llt = 7;
	cfg->len_ovr = 0;
	WLDBG_HEXDUMP(DBG_LEVEL_1, skb->data, skb->len);
	cfg->mpdu_frame_ctrl = *(u16 *) skb->data;
	frm_ctrl = (wl_frame_ctrl *) (skb->data);

	WLDBG_DATA(DBG_LEVEL_0, "mgmt_addr_base=%d, (toDS, fromDS)=(%d, %d)\n",
		   mgmt_addr_base, frm_ctrl->toDs, frm_ctrl->fromDs);
	if (frm_ctrl->toDs == 0 && frm_ctrl->fromDs == 0) {
		// DA: Address 1  SA: Address 2
		da_id = mgmt_addr_base;
		sa_id = mgmt_addr_base + IEEEtypes_ADDRESS_SIZE;
	} else if (frm_ctrl->toDs == 1 && frm_ctrl->fromDs == 0) {
		// DA: Address 3  SA: Address 2
		da_id = mgmt_addr_base + IEEEtypes_ADDRESS_SIZE * 2;
		sa_id = mgmt_addr_base + IEEEtypes_ADDRESS_SIZE;
	} else if (frm_ctrl->toDs == 0 && frm_ctrl->fromDs == 1) {
		// DA: Address 1  SA: Address 3
		da_id = mgmt_addr_base;
		sa_id = mgmt_addr_base + IEEEtypes_ADDRESS_SIZE * 2;
	} else {
		// DA: Address 3  SA: Address 4
		da_id = mgmt_addr_base + IEEEtypes_ADDRESS_SIZE * 2;
		sa_id = mgmt_addr_base + IEEEtypes_ADDRESS_SIZE * 3;
		wifi_header_size += IEEEtypes_ADDRESS_SIZE;	// add address 4 size
	}
	WLDBG_DATA(DBG_LEVEL_1, "(da_id, sa_id)=(%d, %d), fmctrl=%xh\n", da_id,
		   sa_id, cfg->mpdu_frame_ctrl);
	//
	// mail from Richard Chung on Sat 3/4/2017 8:20 AM:
	// DA MAC address is 00:11:22:33:44:55
	// Using your example:
	//
	// DA0=0x1100
	// DA1=0x55443322
	// SA0=0x33221100
	// SA1=0x5544
	//
	cfg->da0 = *(u16 *) (&skb->data[da_id]);
	cfg->da1 = *(u32 *) (&skb->data[da_id + 2]);
	cfg->sa0 = *(u32 *) (&skb->data[sa_id]);
	cfg->sa1 = *(u16 *) (&skb->data[sa_id + 4]);
	// if order[15] bit is 1, need fill HT aggregated control
	if (frm_ctrl->order) {
		if (frm_ctrl->toDs && frm_ctrl->fromDs)
			offset = HT_CTRL_OFFSET_WITH_ADDR4;
		else
			offset = HT_CTRL_OFFSET;
		wifi_header_size += sizeof(u32);	// HT CONTROL size
		cfg->mpdu_ht_a_ctrl = *(u32 *) & skb->data[offset];
		WLDBG_DATA(DBG_LEVEL_0, "ht control %x \n",
			   cfg->mpdu_ht_a_ctrl);
	} else {
		cfg->mpdu_ht_a_ctrl = 0x0;
	}
	cfg->hdr.length = skb->len - wifi_header_size;	//pktlen (Remove 802.11 header)
	// remove 802.11 header
	skb_pull(skb, wifi_header_size);

}

/*
        Data format: ethernet packet
                [DA:6][SA:6][type:2][IP:20]...
 */
void
InitCFHDL(struct net_device *netdev, struct bqm_args *pbqm_args,
	  wltxdesc_t * cfg, struct sk_buff *skb)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	u8 da_id = 0, sa_id = IEEEtypes_ADDRESS_SIZE;

	memset(cfg, 0, sizeof(*cfg));
	cfg->hdr.hi_byte_addr = wlpptr->wlpd_p->reg.smac_buf_hi_addr;
	cfg->hdr.bpid = pbqm_args->txq_start_index;
	cfg->hdr.length = skb->len - (ETHER_HDR_LEN);	//pktlen
	cfg->hdr.cfh_length = sizeof(wltxdesc_t);

	cfg->hdr.timestamp = jiffies;

	if (drv_self_test_qid_enable) {
		cfg->qid = drv_self_test_qid;
	} else {
		cfg->qid = skb->priority;
	}

	cfg->mpdu_flag = 0;
	cfg->ndr = 1;
	cfg->vtv = 0;
	cfg->llt = 7;
	cfg->len_ovr = 0;
	cfg->mpdu_frame_ctrl = 0x40c5;

	// mail from Richard Chung on Sat 3/4/2017 8:20 AM:
	// DA MAC address is 00:11:22:33:44:55
	// Using your example:
	//
	// DA0=0x1100
	// DA1=0x55443322
	// SA0=0x33221100
	// SA1=0x5544
	//
	cfg->da0 = *(u16 *) (&skb->data[da_id]);
	cfg->da1 = *(u32 *) (&skb->data[da_id + 2]);
	cfg->sa0 = *(u32 *) (&skb->data[sa_id]);
	cfg->sa1 = *(u16 *) (&skb->data[sa_id + 4]);
	WLDBG_DATA(DBG_LEVEL_1, "skb->cb[16]:\n");

	WLDBG_HEXDUMP(DBG_LEVEL_1, &skb->cb[16], 8);
	cfg->mpdu_ht_a_ctrl = *(u_int32_t *) & skb->cb[16];
	cfg->snap1 = *(u_int32_t *) & skb->cb[16 + 4];

	if (cfg->hdr.length < TXDESC_IPHDR_SIZE) {
		memcpy(&cfg->ip_hdr, &skb->data[ETHER_HDR_LEN],
		       cfg->hdr.length);
		cfg->hdr.length = TXDESC_IPHDR_SIZE;
	} else
		memcpy(&cfg->ip_hdr, &skb->data[ETHER_HDR_LEN],
		       TXDESC_IPHDR_SIZE);
	return;
}

static void
wlget_extmembuf(struct wlprivate *wlpptr, struct _ext_membuf *pext_membuf)
{
	char **varpt = __symbol_get(pext_membuf->extsym_name);	//symbol name (="bootmem_0", "bootmem_1")

	if (varpt != NULL) {
		// external buffer (bootmem_0/bootmem_1)(bootmem_2/bootmem_3) exist
		printk("=> %s(), using %s\n", __func__,
		       pext_membuf->extsym_name);
		pext_membuf->vbuf_pool = *varpt;
		if (PTR_ALIGN(pext_membuf->vbuf_pool, BUF_16K) !=
		    pext_membuf->vbuf_pool) {
			WLDBG_ERROR(DBG_LEVEL_0,
				    "%s(%p) is not 16K aligned...\n",
				    pext_membuf->extsym_name,
				    pext_membuf->vbuf_pool);
			pext_membuf->vbuf_pool =
				PTR_ALIGN(pext_membuf->vbuf_pool, BUF_16K);
			WLDBG_ERROR(DBG_LEVEL_0, "Align to (%p) \n",
				    pext_membuf->vbuf_pool);
		}

		pext_membuf->buf_pool_from_sys = TRUE;
		pext_membuf->pbuf_pool = virt_to_phys(pext_membuf->vbuf_pool);

	} else {
		/* Get reserved buffers: configured in kernel device-tree */
		struct device_node *nd;
		struct resource res;
		char memreg_name[20];
		int rsvd_buf_avail;
		int rc;

		if (!strcmp("bootmem_0", pext_membuf->extsym_name) ||
		    !strcmp("bootmem_1", pext_membuf->extsym_name))
			strcpy(memreg_name, "bootmem0");
		else if (!strcmp("bootmem_2", pext_membuf->extsym_name) ||
			 !strcmp("bootmem_3", pext_membuf->extsym_name))
			strcpy(memreg_name, "bootmem1");
		else
			strcpy(memreg_name, "bootmem2");

		nd = of_find_node_by_name(NULL, memreg_name);
		if (!nd) {
			printk("Node %s is not found\n", memreg_name);
			rsvd_buf_avail = 0;
		} else {
			rc = of_address_to_resource(nd,
						    pext_membuf->buf_pool_idx,
						    &res);
			if (rc) {
				printk("rsvd mem region %s idx %d address not assigned\n", memreg_name, pext_membuf->buf_pool_idx);
				rsvd_buf_avail = 0;
			} else {
				pext_membuf->pbuf_pool = res.start;
				pext_membuf->vbuf_pool =
					phys_to_virt(pext_membuf->pbuf_pool);

				/* use platform reserved memory size if mem_dbg is not specified
				 * do the memory size check as well
				 */
				if ((!mem_dbg) ||
				    (pext_membuf->buf_pool_size >
				     resource_size(&res)))
					pext_membuf->buf_pool_size =
						resource_size(&res);

				if (PTR_ALIGN(pext_membuf->vbuf_pool, BUF_16K)
				    != pext_membuf->vbuf_pool) {
					WLDBG_ERROR(DBG_LEVEL_0,
						    "%s(%p) is not 16K aligned...\n",
						    pext_membuf->extsym_name,
						    pext_membuf->vbuf_pool);
					pext_membuf->vbuf_pool =
						PTR_ALIGN(pext_membuf->
							  vbuf_pool, BUF_16K);
					WLDBG_ERROR(DBG_LEVEL_0,
						    "Align to (%p) \n",
						    pext_membuf->vbuf_pool);
				}

				pext_membuf->buf_pool_from_sys = TRUE;
				rsvd_buf_avail = 1;

				printk("=> %s(), using %s\nrsvd mem: pbuf=%llx vbuf=%p size=%llx\n", __func__, pext_membuf->extsym_name, pext_membuf->pbuf_pool, pext_membuf->vbuf_pool, (u64) pext_membuf->buf_pool_size);
			}
		}

		if (!rsvd_buf_avail) {
			// bootmem_0/bootmem_1 is undefined in this kernel => allocate a 2M memory (original implementation)
			pext_membuf->buf_pool_size = BUF_2M;
			pext_membuf->buf_pool_from_sys = FALSE;

			pext_membuf->vbuf_pool =
				wl_dma_alloc_coherent(wlpptr->wlpd_p->dev,
						      pext_membuf->
						      buf_pool_size,
						      &pext_membuf->pbuf_pool,
						      wlpptr->wlpd_p->
						      dma_alloc_flags);
		}

	}

	WLDBG_INFO(DBG_LEVEL_0,
		   "Buffer Pool, buf_virt_addr=%p buff_phy_addr=%llxh\n",
		   pext_membuf->vbuf_pool, (u64) pext_membuf->pbuf_pool);
	if (pext_membuf->vbuf_pool)
		memset(pext_membuf->vbuf_pool, 0, pext_membuf->buf_pool_size);
	return;
}

static void
wlclean_extmembuf(struct wlprivate *wlpptr, struct _ext_membuf *pext_membuf)
{
	if ((pext_membuf->buf_pool_from_sys == FALSE) &&
	    (pext_membuf->vbuf_pool != NULL)) {
		// The buffer pool of the last queue is from allocation => need to free it
		wl_dma_free_coherent(wlpptr->wlpd_p->dev,
				     pext_membuf->buf_pool_size,
				     pext_membuf->vbuf_pool,
				     pext_membuf->pbuf_pool);

		pext_membuf->vbuf_pool = NULL;
	}
	return;
}

// Initialize the element size in each queue to the table
static void
init_qelm_size_tbl(struct qelmsize_tbl *tbl, U32 size, U8 bgnid, U8 num_of_q,
		   QPAIR qpairs)
{
	u8 qid;

	if (qpairs == max_qpair) {
		WLDBG_ERROR(DBG_LEVEL_5, "Invalid q_pair id: %d\n", qpairs);
		return;
	}
	for (qid = bgnid; qid < bgnid + num_of_q; qid++) {
		// "qid%NUM_OF_HW_DESCRIPTOR_DATA" => Make klockwork happy...
		tbl->elm_size[qid % NUM_OF_HW_DESCRIPTOR_DATA][qpairs] = size;
	}
	return;
}

/*
	Init the const to initialize the internal data structure
*/
void
wl_init_const(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	struct bqm_args *pbqm_args = &wlpd_p->bmq_args;

#if defined(ACNT_REC)
	pbqm_args->racnt_q_size = (u_int32_t *) racnt_q_size;
	pbqm_args->racntq_index = RXACNTQ_INDEX;
	pbqm_args->racntq_num = RXACNTQ_NUM;
	pbqm_args->racntq_msix_mask = RACNTQ_MSIX_MASK;
	pbqm_args->rxacnt_intrid = RXACNT_INTRID;
#endif //defined(ACNT_REC)
#if defined(TXACNT_REC)
	pbqm_args->txacnt_intrid = TXACNT_INTRID;
#endif //defined(TXACNT_REC)
	switch (wlpptr->devid) {
	case SCBT:
		printk("Running on W9064\n");
		pbqm_args->tx_q_size = (u_int32_t *) scbt_tx_q_size;
		pbqm_args->txq_start_index = SCBT_TXQ_START_INDEX;
		pbqm_args->txq_num = SCBT_TXQ_NUM;
		pbqm_args->relbuf_q_size = (u_int32_t *) scbt_relbuf_q_size;
		pbqm_args->bmq_release_index = SCBT_BMQ_RELEASE_INDEX;
		pbqm_args->bmq_release_num = SCBT_BMQ_RELEASE_NUM;
		pbqm_args->tx_msix_mask = SCBT_TX_MSIX_MASK;
		pbqm_args->buf_release_msix_mask = SCBT_BUF_RELEASE_MSIX_MASK;
		break;
	case SC5:		//Use SC5 definition as default 
		printk("Running on W9068\n");
		// SC5 Ax chip => queue id == the definition of scbt
		pbqm_args->tx_q_size = (u_int32_t *) scbt_tx_q_size;
		pbqm_args->txq_start_index = SCBT_TXQ_START_INDEX;
		pbqm_args->txq_num = SCBT_TXQ_NUM;
		pbqm_args->relbuf_q_size = (u_int32_t *) scbt_relbuf_q_size;
		pbqm_args->bmq_release_index = SCBT_BMQ_RELEASE_INDEX;
		pbqm_args->bmq_release_num = SCBT_BMQ_RELEASE_NUM;
		pbqm_args->tx_msix_mask = SCBT_TX_MSIX_MASK;
		pbqm_args->buf_release_msix_mask = SCBT_BUF_RELEASE_MSIX_MASK;
		break;
	default:
		WLDBG_ERROR(DBG_LEVEL_0, "Unknow chip, devid=%xh\n",
			    wlpptr->devid);
	}
	// Initial the q_size
	memset(&pbqm_args->q_elmsize_tbl, INVALID_QSIZE,
	       sizeof(struct qelmsize_tbl));
	// RXQ
	init_qelm_size_tbl(&pbqm_args->q_elmsize_tbl,
			   sizeof(wlrxdesc_t),
			   SC5_RXQ_START_INDEX, SC5_RXQ_NUM, is_sq);
	// TXQ
	init_qelm_size_tbl(&pbqm_args->q_elmsize_tbl,
			   sizeof(wltxdesc_t),
			   pbqm_args->txq_start_index, pbqm_args->txq_num,
			   is_rq);
	// BMQ
	init_qelm_size_tbl(&pbqm_args->q_elmsize_tbl,
			   sizeof(bm_pe_hw_t),
			   SC5_BMQ_START_INDEX, SC5_BMQ_NUM, is_rq);
	// ReleaseQ
	init_qelm_size_tbl(&pbqm_args->q_elmsize_tbl,
			   sizeof(bm_pe_hw_t),
			   pbqm_args->bmq_release_index,
			   pbqm_args->bmq_release_num, is_sq);
#if defined(ACNT_REC)
	// AcntQ
	init_qelm_size_tbl(&pbqm_args->q_elmsize_tbl,
			   sizeof(rxacnt_rec),
			   pbqm_args->racntq_index, pbqm_args->racntq_num,
			   is_sq);
#endif //#if defined(ACNT_REC)
	// Using tasklet to send packets by default
	wlpd_p->tx_async = TRUE;
	return;
}

extern void wlmon_kumper_callback(struct net_device *netdev);
extern struct wlprivate_data *global_private_data[MAX_CARDS_SUPPORT];
static void
oops_do_dump(struct kmsg_dumper *dumper, enum kmsg_dump_reason reason)
{
	int i;
	printk("===> %s(), reason = %d\n", __func__, reason);

	for (i = 0; i < MAX_CARDS_SUPPORT; i++) {
		struct wlprivate_data *wlpdptr = global_private_data[i];
		struct net_device *netdev = wlpdptr->rootdev;
		struct wlprivate *wlpptr;
		SMAC_STATUS_st smacStatus;

//rxdbg_showmsg(&wlpdptr->vrxdbg_db, mds_by_sq);

		//stop HM and move log file from /tmp to /var 
#if 0
		wlmon_kumper_callback(netdev);
#endif
		if (&wlpdptr->kdumper != dumper) {
			continue;
		}

		if ((netdev) && (wlpdptr->downloadSuccessful == TRUE)) {
			printk("Disable MAC of %s\n", netdev->name);
			disableSMACRx(netdev);
		}

		if (netdev) {
			printk("[ Dump %s Info ]\n", netdev->name);
			wl_show_generic_info(netdev, NULL);
			wl_show_except_cnt(netdev, NULL);
			wl_show_hframe_info(netdev, NULL);
			wl_show_pktcnt_stat(netdev, NULL);
			wlpptr = wlpdptr->masterwlp;
			wl_util_lock(netdev);
			memcpy(&smacStatus, wlpptr->smacStatusAddr,
			       sizeof(SMAC_STATUS_st));
			wl_util_unlock(netdev);
			wl_show_smac_stat(netdev, &smacStatus, NULL);
		}
		printk("================================================================\n");
		wldump_txskb_info(netdev);
	}

	printk("Last PE:\n");
	mwl_hex_dump(&g_last_pe, sizeof(bm_pe_hw_t));

	return;
}

void
wl_register_dump_func(struct wlprivate_data *wlpd_p)
{
	int res;

	wlpd_p->kdumper.dump = oops_do_dump;
	res = kmsg_dump_register(&wlpd_p->kdumper);
	if (res != 0) {
		printk("====> Failed to register kdumper\n");
	} else {
		printk("====> Register kdumper successfully\n");
	}
	return;
}

void
wl_unregister_dump_func(struct wlprivate_data *wlpd_p)
{
	kmsg_dump_unregister(&wlpd_p->kdumper);
	return;
}

/*
	Initialize the TxD1 drop buffer
*/
void
wl_init_droppkt_info(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	DROPPKT_INFO *pdropbuf = &wlpd_p->droppkt_info;
	dma_addr_t phys_addr;

#ifdef USE_NCBUF
	// Using non-cacheable buffer
	// Allocate the buffer to save the txd1 drop records (cfh-dl)
	pdropbuf->TxD1DropBuf_v =
		(void *)wl_dma_alloc_coherent(wlpd_p->dev,
					      sizeof(wltxdesc_t) *
					      MAX_HWDROP_BUF, &phys_addr,
					      wlpd_p->dma_alloc_flags);
#else
	// Using cacheable buffer
	pdropbuf->TxD1DropBuf_v =
		(void *)wl_kmalloc(sizeof(wltxdesc_t) * MAX_HWDROP_BUF,
				   GFP_KERNEL);
	phys_addr =
		dma_map_single(wlpd_p->dev, pdropbuf->TxD1DropBuf_v,
			       sizeof(wltxdesc_t) * MAX_HWDROP_BUF,
			       DMA_FROM_DEVICE);
#endif //

	pdropbuf->TxD1DropBuf_p = phys_addr;
	// Initialize the txd1 drop registers
	*(volatile unsigned int *)(wlpptr->ioBase1 + TXD1_DDR_DROPBUF_CFG) =
		(pdropbuf->TxD1DropBuf_p >> 4) | 0xf0000000;
	*(volatile unsigned int *)(wlpptr->ioBase1 + TXD1_DDR_DROPBUF_RDPTR) =
		pdropbuf->TxD1DropBuf_p;
	*(volatile unsigned int *)(wlpptr->ioBase1 + TXD1_PUNT_CTRL) = PUNT_ALL;

	// Initialize the internal variables
	pdropbuf->TxD1DropBuf_WrCnt_reg =
		(U32 *) (wlpptr->ioBase1 + TXD1_DDR_DROP_WRITE_CNT);
	pdropbuf->TxD1DropBuf_wid = 0;

	return;
}

/*
	Deinitialize the TxD1 drop buffer
*/
void
wl_deinit_droppkt_info(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	DROPPKT_INFO *pdropbuf = &wlpd_p->droppkt_info;

	// Clean up the buffer for the txd1 drop records
	if (pdropbuf->TxD1DropBuf_v != NULL) {
#ifdef USE_NCBUF
		wl_dma_free_coherent(wlpd_p->dev,
				     sizeof(wltxdesc_t) * MAX_HWDROP_BUF,
				     (void *)pdropbuf->TxD1DropBuf_v,
				     pdropbuf->TxD1DropBuf_p);
#else
		dma_unmap_single(wlpptr->wlpd_p->dev, pdropbuf->TxD1DropBuf_p,
				 sizeof(wltxdesc_t) * MAX_HWDROP_BUF,
				 DMA_FROM_DEVICE);
		wl_kfree(pdropbuf->TxD1DropBuf_v);
#endif

		pdropbuf->TxD1DropBuf_v = NULL;
	}

	return;
}

static void
wl_push_droppkt_rec(DROPPKT_INFO * pdropbuf, wltxdesc_t * pcfhdl)
{
	u8 i;
	u8 rbit = 1;
	// Saved counter. It won't increase after the buffer is full (eldest will be dropped)
	if (pdropbuf->dropbuf_cnt < MAX_DROPBUF_CNT) {
		pdropbuf->dropbuf_cnt++;
	}
	// Save the records to the internal buffer for the post processing
	memcpy(&pdropbuf->dropbuf[pdropbuf->dropbuf_wid], pcfhdl,
	       sizeof(wltxdesc_t));
	for (i = 0; i < 8; i++, rbit <<= 1) {
		if (pcfhdl->txd1_drop_reason & rbit) {
			pdropbuf->drop_reason[pcfhdl->qid % SMAC_QID_NUM][i]++;
		}
	}

	// Update the write index
	pdropbuf->dropbuf_wid = (pdropbuf->dropbuf_wid + 1) % MAX_DROPBUF_CNT;
	return;
}

/*
	Check the drop buffer records. If new records exist, save them to internal buffer for post processing
*/
void
wl_chk_drop_pkt(struct wlprivate_data *wlpd_p)
{
	DROPPKT_INFO *pdropbuf;
	U32 dropcnt;
	U8 i;
	wltxdesc_t *txd1_bufpt;

	if (wlpd_p->is_txd1_drop == FALSE) {
		// "is_txd1_drop" is disabled => do nothing
		return;
	}
	pdropbuf = &wlpd_p->droppkt_info;
	dropcnt = *(pdropbuf->TxD1DropBuf_WrCnt_reg);
	if (dropcnt == 0) {
		// No pkts dropped yet
		return;
	}

	txd1_bufpt = (wltxdesc_t *) pdropbuf->TxD1DropBuf_v;
	// New records arrive
	if (dropcnt < MAX_HWDROP_BUF) {
		for (i = 0; i < dropcnt; i++) {
			wltxdesc_t *pcfhul =
				&txd1_bufpt[pdropbuf->TxD1DropBuf_wid];
			wl_push_droppkt_rec(pdropbuf, pcfhul);
			pdropbuf->TxD1DropBuf_wid =
				(pdropbuf->TxD1DropBuf_wid +
				 1) % MAX_HWDROP_BUF;
			wlpd_p->except_cnt.txq_txd1_drop_cnt[pcfhul->qid]++;
		}
	} else {
		// Overflow. Just save the latest records
		pdropbuf->TxD1DropBuf_wid =
			(pdropbuf->TxD1DropBuf_wid + dropcnt) % MAX_HWDROP_BUF;
		for (i = 0; i < MAX_HWDROP_BUF; i++) {
			wltxdesc_t *pcfhul =
				&txd1_bufpt[pdropbuf->TxD1DropBuf_wid];
			wl_push_droppkt_rec(pdropbuf, pcfhul);
			pdropbuf->TxD1DropBuf_wid =
				(pdropbuf->TxD1DropBuf_wid +
				 1) % MAX_HWDROP_BUF;
			wlpd_p->except_cnt.txq_txd1_drop_cnt[pcfhul->qid]++;
		}
	}
	return;
}

/* debug for invalid skb */
static void
dbgskb_init(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	dbg_skb *dbgskb_p;

	dbgskb_p = &wlpd_p->dbgskb;
	dbgskb_p->skb_send =
		(dbg_skb_send *) wl_kmalloc(DBG_SKB_MAX_NUM *
					    sizeof(dbg_skb_send), GFP_KERNEL);
	if (!dbgskb_p->skb_send) {
		WLDBG_ERROR(DBG_LEVEL_0, "dbgskb: skb_send mem alloc fail!\n");
	} else
		memset(dbgskb_p->skb_send, 0x0,
		       DBG_SKB_MAX_NUM * sizeof(dbg_skb_send));

	dbgskb_p->skb_back =
		(dbg_skb_back *) wl_kmalloc(DBG_SKB_MAX_NUM *
					    sizeof(dbg_skb_back), GFP_KERNEL);
	if (!dbgskb_p->skb_back) {
		WLDBG_ERROR(DBG_LEVEL_0, "sbgskb: skb_back mem alloc fail!\n");
	} else
		memset(dbgskb_p->skb_back, 0x0,
		       DBG_SKB_MAX_NUM * sizeof(dbg_skb_back));
}

static void
dbgskb_deinit(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	dbg_skb *dbgskb_p;

	dbgskb_p = &wlpd_p->dbgskb;
	if (dbgskb_p->skb_send)
		wl_kfree(dbgskb_p->skb_send);

	if (dbgskb_p->skb_back)
		wl_kfree(dbgskb_p->skb_back);

	memset(dbgskb_p, 0, sizeof(dbg_skb));

}

/* Initialize 16 Q and update Base address, queue size, read/write index to HW register */
int
wlQMInit(struct net_device *netdev)
{
	int qid, err;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	struct bqm_args *pbqm_args = &wlpd_p->bmq_args;
	UINT8 cardidx = wlpptr->cardindex;
	char buf_name[80];

	// Create a 64M/2M buffer to H/W ++
	// Disable it temporally
	unsigned int reg_evt_rdptr = wlpd_p->reg.evt_rdptr;
	unsigned int reg_evt_wrptr = wlpd_p->reg.evt_wrptr;

	skb_queue_head_init(&wlpd_p->pend_skb_trace[PENDSKB_TX]);
	skb_queue_head_init(&wlpd_p->pend_skb_trace[PENDSKB_RX]);

	if (wfa_11ax_pf) {
		int i;

		for (i = 0; i < MAX_OFDMADL_STA; i++) {
			skb_queue_head_init(&wlpd_p->txq_per_sta[i]);
		}
	}

	printk("%s(), Interrupt shift = %xh\n", __func__, wlpd_p->intr_shift);
	pkt_init(testpkt);

	if (mem_dbg) {
		BF_Buf_Size = ((2 * bss_num) + sta_num) * 160 * 1024;
		L0L1_Buf_Size =
			((bss_num + sta_num) * 256 * 1024) + 4 * 1024 * 1024;
	}
	// Get the external buffers
	sprintf(buf_name, "bootmem_%d", cardidx * 2);
	strcpy(wlpd_p->ext_membuf[0].extsym_name, buf_name);
	wlpd_p->ext_membuf[0].buf_pool_size = BF_Buf_Size;
	wlpd_p->ext_membuf[0].buf_pool_idx = 0;
	wlget_extmembuf(wlpptr, &wlpd_p->ext_membuf[0]);

	sprintf(buf_name, "bootmem_%d", cardidx * 2 + 1);
	strcpy(wlpd_p->ext_membuf[1].extsym_name, buf_name);
	wlpd_p->ext_membuf[1].buf_pool_size = L0L1_Buf_Size;
	wlpd_p->ext_membuf[1].buf_pool_idx = 1;
	wlget_extmembuf(wlpptr, &wlpd_p->ext_membuf[1]);

	wlpptr->smacconfig.smacBmBaseAddr =
		(UINT32) wlpd_p->ext_membuf[0].pbuf_pool;
	wlpptr->smacconfig.smacBmSize = wlpd_p->ext_membuf[0].buf_pool_size;
	wlpptr->smacconfig.ddrHighAddr = wlpd_p->reg.smac_buf_hi_addr;

	WLDBG_INFO(DBG_LEVEL_0, "w_reg(ioBase1+%xh) = %xh\n", 0x1a848,
		   wlpptr->smacconfig.ddrHighAddr);
	wl_util_writel(netdev, wlpptr->smacconfig.ddrHighAddr, wlpptr->ioBase1 + 0x1a848);//hack, smac_control_base_nss

	wlpptr->smac_base_vp = wlpd_p->ext_membuf[0].vbuf_pool;

	wlpptr->smacconfig.qIntAddr = wlpptr->wlpd_p->sysintr_frm.frm_base;
	// Pass the interrupt shift
	wlpptr->smacconfig.qIntOffset = wlpptr->wlpd_p->sysintr_frm.spi_num;
	printk("=> %s(), set qIntOffset = %xh\n", __func__,
	       wlpptr->smacconfig.qIntOffset);

	WLDBG_INFO(DBG_LEVEL_0, " ================= RxQ =============\n");
	for (qid = SC5_RXQ_START_INDEX;
	     qid < (SC5_RXQ_START_INDEX + SC5_RXQ_NUM); qid++) {
		if (((1 << qid) & SC5_RXQ_MASK) == 0) {	// Not enabled
			continue;
		}
		err = wlRxQueueInit(netdev, qid);
		if (err) {
			WLDBG_ERROR(DBG_LEVEL_0, "%s: Initialize Rx Q fail. \n",
				    netdev->name);
			wlRxQueueCleanUp(netdev);
			return FAIL;
		}
	}			// end of RXQ
	WLDBG_INFO(DBG_LEVEL_0, " ================= TxQ =============\n");

	for (qid = pbqm_args->txq_start_index;
	     qid < (pbqm_args->txq_start_index + pbqm_args->txq_num); qid++) {
		err = wlTxQueueInit(netdev, qid);
		if (err) {
			WLDBG_ERROR(DBG_LEVEL_0, "%s: Initialize Tx Q fail. \n",
				    netdev->name);
			wlTxQueueCleanUp(netdev);
			return FAIL;
		}
	}			// end of TXQ
	WLDBG_INFO(DBG_LEVEL_0, " ================= BmQ =============\n");

	for (qid = SC5_BMQ_START_INDEX;
	     qid < (SC5_BMQ_START_INDEX + SC5_BMQ_NUM); qid++) {
		err = wlBmQueueInit(netdev, qid);
		if (err) {
			WLDBG_ERROR(DBG_LEVEL_0, "%s: Initialize BM Q fail. \n",
				    netdev->name);
			wlBmQueueCleanUp(netdev);
			return FAIL;
		}
	}			// end of BM_POOL
	wlpptr->smacconfig.bpReqCnt = qid - SC5_BMQ_START_INDEX;
	WLDBG_INFO(DBG_LEVEL_0, " ================= ReleaseQ =============\n");
	for (qid = pbqm_args->bmq_release_index;
	     qid < (pbqm_args->bmq_release_index + pbqm_args->bmq_release_num);
	     qid++) {
		err = wlBufReleaseQueueInit(netdev, qid);
		if (err) {
			WLDBG_ERROR(DBG_LEVEL_0, "%s: Initialize BM Q fail. \n",
				    netdev->name);
			wlBufReleaseQueueCleanUp(netdev);
			return FAIL;
		}
	}			// end of BM_POOL
	wlpptr->smacconfig.bpRelQid = qid - 1;
#if defined(ACNT_REC)
	WLDBG_INFO(DBG_LEVEL_0, " ================= RxAcntQ =============\n");
	for (qid = pbqm_args->racntq_index;
	     qid < (pbqm_args->racntq_index + pbqm_args->racntq_num); qid++) {
		err = wlRAcntQueueInit(netdev, qid);
		if (err) {
			WLDBG_ERROR(DBG_LEVEL_0, "%s: Initialize BM Q fail. \n",
				    netdev->name);
			wlRAcntQueueCleanUp(netdev);
			return FAIL;
		}
	}			// end of RAcntQ
#endif //#if defined(ACNT_REC)
	// Allocate the event buffer queue
	wlpptr->event_bufq_vaddr =
		(void *)wl_dma_alloc_coherent(wlpd_p->dev,
					      EVENT_BUFFQ_NUM *
					      EVENT_BUFFQ_SIZE,
					      &wlpptr->event_bufq_paddr,
					      wlpd_p->dma_alloc_flags);

	wl_util_writel(netdev, 0, wlpptr->ioBase1 + reg_evt_rdptr);
	wl_util_writel(netdev, 0, wlpptr->ioBase1 + reg_evt_wrptr);

	WLDBG_DATA(DBG_LEVEL_3, "=> Event_buffer_q (v, p)=(%p, %x)\n",
		   wlpptr->event_bufq_vaddr, wlpptr->event_bufq_paddr);

	wlpd_p->descData[0].pInfoPwrTbl =
		wl_kmalloc(sizeof(Info_rate_power_table_t), GFP_KERNEL);
	wlpd_p->descData[0].pPhyInfoPwrTbl =
		virt_to_phys(wlpd_p->descData[0].pInfoPwrTbl);
	memset((void *)wlpd_p->descData[0].pInfoPwrTbl, 0,
	       sizeof(Info_rate_power_table_t));

	wl_init_droppkt_info(netdev);

	dbgskb_init(netdev);

	// CFHUL_DBG
	set_rxdbg_func(&wlpd_p->irxdbg_intr, rxdbg_dummp);
	wlpd_p->irxdbg_intr.init(&wlpd_p->vrxdbg_db, netdev);
	wlpd_p->irxdbg_intr.active(&wlpd_p->vrxdbg_db, TRUE);
	//CFHUL_DBG

	return SUCCESS;
}

void
wlCfhUlDump(wlrxdesc_t * cfh_ul)
{
	WLDBG_DATA(DBG_LEVEL_0, "CFH_UL: Addr %p \n", cfh_ul);
	WLDBG_DATA(DBG_LEVEL_0, "CFH_UL: Len %d \n", cfh_ul->hdr.length);
	WLDBG_DATA(DBG_LEVEL_0, "CFH_UL: Timestamp %x \n",
		   cfh_ul->hdr.timestamp);
	WLDBG_DATA(DBG_LEVEL_0, "CFH_UL: BPID %d \n", cfh_ul->hdr.bpid);
	WLDBG_DATA(DBG_LEVEL_0, "CFH_UL: Packet Address %xh \n",
		   cfh_ul->hdr.lo_dword_addr);
}

void
wlCfhDlDump(wltxdesc_t * cfh_dl)
{
	WLDBG_DATA(DBG_LEVEL_0, "CFH_DL: Addr %p \n", cfh_dl);
	WLDBG_DATA(DBG_LEVEL_0, "CFH_DL: Len %d \n", cfh_dl->hdr.length);
	WLDBG_DATA(DBG_LEVEL_0, "CFH_DL: Timestamp %x \n",
		   cfh_dl->hdr.timestamp);
	WLDBG_DATA(DBG_LEVEL_0, "CFH_DL: BPID %d \n", cfh_dl->hdr.bpid);
	WLDBG_DATA(DBG_LEVEL_0, "CFH_DL: QID  %d \n", cfh_dl->qid);
	WLDBG_DATA(DBG_LEVEL_0, "CFH_DL: Packet Address %xh \n",
		   cfh_dl->hdr.lo_dword_addr);
}

void
wlRxQDump(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wldesc_data *wlqm;
	int qid, i;
	u32 rdinx;
	void *addr[4];
	u32 value[4];
	wlrxdesc_t *cfh_ul;

	for (qid = SC5_RXQ_START_INDEX;
	     qid < (SC5_RXQ_START_INDEX + SC5_RXQ_NUM); qid++) {
		if (((1 << qid) & SC5_RXQ_MASK) == 0) {	// Not enabled
			continue;
		}

		WLDBG_INFO(DBG_LEVEL_3, "RXQ ID %d \n", qid);
		addr[0] = (wlpptr->ioBase1 + SC5_Q_BASE_ADDR_REG(qid, SC5_SQ));
		addr[1] = (wlpptr->ioBase1 + SC5_Q_SIZE_REG(qid, SC5_SQ));
		addr[2] = (wlpptr->ioBase1 + SC5_SQ_RDPTR_REG(qid));
		addr[3] = (wlpptr->ioBase1 + SC5_SQ_WRPTR_REG(qid));
		WLDBG_INFO(DBG_LEVEL_3,
			   "addr: base %p qsize %p rdptr %p wrptr %p \n",
			   addr[0], addr[1], addr[2], addr[3]);
		for (i = 0; i < 4; i++)
			value[i] = wl_util_readl(netdev, addr[i]);
		WLDBG_INFO(DBG_LEVEL_3,
			   "value: base %x qsize %x rdptr %x wrptr %x \n",
			   value[0], value[1], value[2], value[3]);
		wlqm = &wlpptr->wlpd_p->descData[qid];
		rdinx = wlqm->sq.rdinx;

		while (rdinx != wlqm->sq.wrinx) {
			cfh_ul = (wlrxdesc_t *) (wlqm->sq.virt_addr +
						 rdinx * sizeof(wlrxdesc_t));
			wlCfhUlDump(cfh_ul);
			rdinx = (rdinx + 1) % wlqm->sq.qsize;
		}		// end of while

		WLDBG_INFO(DBG_LEVEL_3, "\n\n\n\n\n");
		WLDBG_INFO(DBG_LEVEL_3,
			   "---------------------------------------------------------------\n");
		WLDBG_INFO(DBG_LEVEL_3, "\n\n\n\n\n");
	}
}

void
wlTxQDump(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	struct bqm_args *pbqm_args = &wlpd_p->bmq_args;
	struct wldesc_data *wlqm;
	int qid, i;
	u32 rdinx;
	void *addr[4];
	u32 value[4];
	wltxdesc_t *cfh_dl;

	for (qid = pbqm_args->txq_start_index;
	     qid < (pbqm_args->txq_start_index + pbqm_args->txq_num); qid++) {
		WLDBG_INFO(DBG_LEVEL_3, "TXQ ID %d \n", qid);
		addr[0] = (wlpptr->ioBase1 + SC5_Q_BASE_ADDR_REG(qid, SC5_RQ));
		addr[1] = (wlpptr->ioBase1 + SC5_Q_SIZE_REG(qid, SC5_RQ));
		addr[2] = (wlpptr->ioBase1 + SC5_RQ_RDPTR_REG(qid));
		addr[3] = (wlpptr->ioBase1 + SC5_RQ_WRPTR_REG(qid));
		WLDBG_INFO(DBG_LEVEL_3,
			   "addr: base %p qsize %p rdptr %p wrptr %p \n",
			   addr[0], addr[1], addr[2], addr[3]);
		for (i = 0; i < 4; i++)
			value[i] = wl_util_readl(netdev, addr[i]);
		WLDBG_INFO(DBG_LEVEL_3,
			   "value: base %x qsize %x rdptr %x wrptr %x \n",
			   value[0], value[1], value[2], value[3]);
		wlqm = &wlpptr->wlpd_p->descData[qid];
		rdinx = wlqm->rq.rdinx;

		while (rdinx != wlqm->rq.wrinx) {
			cfh_dl = (wltxdesc_t *) (wlqm->rq.virt_addr +
						 rdinx * sizeof(wltxdesc_t));
			wlCfhDlDump(cfh_dl);
			rdinx = (rdinx + 1) % wlqm->rq.qsize;
		}		// end of while

		WLDBG_INFO(DBG_LEVEL_3, "\n\n\n\n\n");
		WLDBG_INFO(DBG_LEVEL_3,
			   "---------------------------------------------------------------\n");
		WLDBG_INFO(DBG_LEVEL_3, "\n\n\n\n\n");

	}			// end of for loop
}

void
wlBmQDump(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	int qid, i;
	void *addr[4];
	u32 value[4];

	for (qid = SC5_BMQ_START_INDEX;
	     qid < (SC5_BMQ_START_INDEX + SC5_BMQ_NUM); qid++) {
		WLDBG_INFO(DBG_LEVEL_3, "BMQ ID %d \n", qid);
		addr[0] = (wlpptr->ioBase1 + SC5_Q_BASE_ADDR_REG(qid, SC5_RQ));
		addr[1] = (wlpptr->ioBase1 + SC5_Q_SIZE_REG(qid, SC5_RQ));
		addr[2] = (wlpptr->ioBase1 + SC5_RQ_RDPTR_REG(qid));
		addr[3] = (wlpptr->ioBase1 + SC5_RQ_WRPTR_REG(qid));
		WLDBG_INFO(DBG_LEVEL_3,
			   "addr: base %p qsize %p rdptr %p wrptr %p \n",
			   addr[0], addr[1], addr[2], addr[3]);
		for (i = 0; i < 4; i++)
			value[i] = wl_util_readl(netdev, addr[i]);
		WLDBG_INFO(DBG_LEVEL_3,
			   "value: base %x qsize %x rdptr %x wrptr %x \n",
			   value[0], value[1], value[2], value[3]);

		wlBmBufDump(netdev, qid);

		WLDBG_INFO(DBG_LEVEL_3, "\n\n\n\n\n");
		WLDBG_INFO(DBG_LEVEL_3,
			   "---------------------------------------------------------------\n");
		WLDBG_INFO(DBG_LEVEL_3, "\n\n\n\n\n");

	}			// end of for loop
}

void
wlReleaseQDump(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	struct bqm_args *pbqm_args = &wlpd_p->bmq_args;

	int qid, i;
	void *addr[4];
	u32 value[4];

	for (qid = pbqm_args->bmq_release_index;
	     qid < (pbqm_args->bmq_release_index + pbqm_args->bmq_release_num);
	     qid++) {
		struct wldesc_data *wlqm = &wlpptr->wlpd_p->descData[qid];

		WLDBG_INFO(DBG_LEVEL_3, "RELQ ID %d \n", qid);
		addr[0] = (wlpptr->ioBase1 + SC5_Q_BASE_ADDR_REG(qid, SC5_SQ));
		addr[1] = (wlpptr->ioBase1 + SC5_Q_SIZE_REG(qid, SC5_SQ));
		addr[2] = (wlpptr->ioBase1 + SC5_SQ_RDPTR_REG(qid));
		addr[3] = (wlpptr->ioBase1 + SC5_SQ_WRPTR_REG(qid));
		WLDBG_INFO(DBG_LEVEL_3,
			   "addr: base %p qsize %p rdptr %p wrptr %p \n",
			   addr[0], addr[1], addr[2], addr[3]);
		for (i = 0; i < 4; i++)
			value[i] = wl_util_readl(netdev, addr[i]);
		WLDBG_INFO(DBG_LEVEL_3,
			   "value: base %x qsize %x rdptr %x wrptr %x \n",
			   value[0], value[1], value[2], value[3]);

		wlqm->sq.wrinx = wlQueryWrPtr(netdev, qid, SC5_SQ);
		//wlBmBufDump(netdev, qid);
		wlReleaseBufDump(netdev, qid);

		WLDBG_INFO(DBG_LEVEL_3, "\n");
		WLDBG_INFO(DBG_LEVEL_3,
			   "---------------------------------------------------------------\n");
		WLDBG_INFO(DBG_LEVEL_3, "\n");

	}			// end of for loop
}

int
wlRxRingReInit(struct net_device *netdev)
{
	return SUCCESS;
}

/*
	Debug func: Check the buffer count which have been enqueued
	=> If over the threshold => dump the status automatically
*/
BOOLEAN
wlDbg_chk_bm_enq(struct net_device * netdev, UINT32 max_diff)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	CNT_RANGE res;
	BOOLEAN is_showmsg = FALSE;
	U16 buf_qid;
	SINT32 pendcnt;

	for (buf_qid = SC5_BMQ_START_INDEX;
	     buf_qid < (SC5_BMQ_START_INDEX + SC5_BMQ_NUM - 1); buf_qid++) {
		int offset = buf_qid - SC5_BMQ_START_INDEX;
		struct drv_stats *wldrvstat_p = &wlpd_p->drv_stats_val;

		pendcnt =
			wldrvstat_p->enq_bmqbuf_cnt[offset] -
			wldrvstat_p->xx_buf_free_SQ14[offset] -
			wldrvstat_p->bmqbuf_ret_cnt[offset];
		res = wlCheckCnterRange(pendcnt,
					&(wlpd_p->drv_stats_val.
					  enq_bmq_lastcnt[offset]),
					(SINT32) max_diff);
		if (res != CNT_RANGE_SAFE) {
			is_showmsg = TRUE;
		}
	}
#if 0
	if (is_showmsg == TRUE) {
		printk("Enqueued buffers over limit");
		wl_show_stat(netdev, drvstatsopt_geninfo, 0, NULL);
		wl_show_stat(netdev, drvstatsopt_warning, 0, NULL);

		printk("Level cnt: %d, %d, %d\n",
		       wlpd_p->drv_stats_val.enq_bmq_lastcnt[0],
		       wlpd_p->drv_stats_val.enq_bmq_lastcnt[1],
		       wlpd_p->drv_stats_val.enq_bmq_lastcnt[2]);
	}
#endif
	return is_showmsg;
}

BOOLEAN
wlDbg_chk_bm_enq_qid(struct net_device * netdev, U16 buf_qid, UINT32 max_diff)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	SINT32 pendcnt;
	U16 offset = (U16) ((buf_qid - SC5_BMQ_START_INDEX) % SC5_BMQ_NUM);
	struct drv_stats *wldrvstat_p = &wlpd_p->drv_stats_val;
	struct except_cnt *wlexcept_p = &wlpd_p->except_cnt;
	pendcnt =
		wldrvstat_p->enq_bmqbuf_cnt[offset] -
		wldrvstat_p->xx_buf_free_SQ14[offset] -
		wldrvstat_p->bmqbuf_ret_cnt[offset];

	if (pendcnt > max_diff) {
		wlexcept_p->skip_feed_starv[offset]++;
		return TRUE;
	} else
		return FALSE;
}

/*
	Rx Buffer Refill function
	If it's too slow to refill the buffer, SMAC may return cfhul with skb address = 0xffffffff
*/
int
wlRxBufFill(struct net_device *netdev)
{
	U16 buf_qid;
	int refill_cnt;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	struct wldesc_data *wlqm;

	for (buf_qid = SC5_BMQ_START_INDEX;
	     buf_qid < (SC5_BMQ_START_INDEX + SC5_BMQ_NUM - 1); buf_qid++) {
		int qid = buf_qid;
		int offset __attribute__ ((unused)) =
			buf_qid - SC5_BMQ_START_INDEX;
		struct drv_stats * __attribute__ ((unused)) wldrvstat_p =
			&wlpd_p->drv_stats_val;
		CNT_RANGE res;

		/* if the enqueue to this qid is too large, then skip
		 */
		if (wlDbg_chk_bm_enq_qid
		    (netdev, qid, buf_pool_max_entries[offset]) == TRUE) {
			continue;
		}

		wlqm = &wlpptr->wlpd_p->descData[qid];
		wlqm->rq.rdinx = wlQueryRdPtr(netdev, qid, SC5_RQ);
		for (refill_cnt = 0; refill_cnt < SC5_BMQ_SIZE; refill_cnt++) {
			int status;
			if (isRQFull(&wlqm->rq) == TRUE)
				break;

			if ((status = _wlRxBufFill(netdev, qid)) == FAIL)
				break;
		}

		//collect refill info for HM 
		wlmon_log_bmq_buff_refill(netdev, (UINT32) buf_qid,
					  (UINT32) refill_cnt);

		if (refill_cnt > 0) {
			wlUpdateWrPtr(netdev, qid, SC5_RQ, wlqm->rq.wrinx,
				      false);
			WLDBG_DATA(DBG_LEVEL_3,
				   "Fill in %d buffers to RQ(%d)\n", refill_cnt,
				   qid);
		}

		res = wlCheckCnterRange((SINT32)
					skb_queue_len(&wlqm->rq.skbTrace),
					&(wlpd_p->drv_stats_val.
					  trcq_lastcnt[buf_qid -
						       SC5_BMQ_START_INDEX]),
					BMQ_DIFFMSG_COUNT);
		if (res == CNT_RANGE_UP) {
			WLDBG_WARNING(DBG_LEVEL_0,
				      "Traced packets count to Q[%d] reachs %d\n",
				      buf_qid,
				      (wldrvstat_p->enq_bmqbuf_cnt[offset] -
				       wldrvstat_p->xx_buf_free_SQ14[offset] -
				       wldrvstat_p->bmqbuf_ret_cnt[offset]));
		} else if (res == CNT_RANGE_DOWN) {
			WLDBG_WARNING(DBG_LEVEL_0,
				      "Traced packets count to Q[%d] drops down to %d\n",
				      buf_qid,
				      (wldrvstat_p->enq_bmqbuf_cnt[offset] -
				       wldrvstat_p->xx_buf_free_SQ14[offset] -
				       wldrvstat_p->bmqbuf_ret_cnt[offset]));
		}

	}

	return SUCCESS;
}

#if 1
int
wlRxBufFillBMEM_Q13(struct net_device *netdev, bm_pe_hw_t * pehw)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	struct wldesc_data *wlqm;
	unsigned int size;
	bm_pe_hw_t *pe_hw;

	int qid = SC5_BMQ_START_INDEX + SC5_BMQ_NUM - 1;

	wlqm = &wlpptr->wlpd_p->descData[qid];
	size = wlqm->rq.bm.buf_size;
	WLDBG_DATA(DBG_LEVEL_0, "CFHUL: BMQid(%d) size %d \n", qid, size);

	pe_hw = (bm_pe_hw_t *) (wlqm->rq.virt_addr +
				wlqm->rq.wrinx * sizeof(bm_pe_hw_t));
	pe_hw->pe0_lo_dword_addr = pehw->pe0_lo_dword_addr;
	pe_hw->pe0_hi_byte_addr = wlpd_p->reg.smac_buf_hi_addr;
	pe_hw->bpid = pehw->bpid;

	WLDBG_DATA(DBG_LEVEL_0, "Refill BMQ13 with hw buffer addr:%x\n",
		   pe_hw->pe0_lo_dword_addr);
	wlqm->rq.rdinx = wlQueryRdPtr(netdev, qid, SC5_RQ);

	if (wlRQIndexPut(qid, &wlqm->rq) == TRUE) {
		// Buffer is not full
		wlpd_p->drv_stats_val.enq_bmqbuf_cnt[qid -
						     SC5_BMQ_START_INDEX]++;
		wlUpdateWrPtr(netdev, qid, SC5_RQ, wlqm->rq.wrinx, false);
	} else {
		WLDBG_WARNING(DBG_LEVEL_0, "Queue %d is full to fill", qid);
		return FAIL;
	}

	return SUCCESS;
}
#else
int
wlRxBufFillBMEM_Q13(struct net_device *netdev, bm_pe_hw_t * pehw)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	struct wldesc_data *wlqm;
	unsigned int size;

	int qid = SC5_BMQ_START_INDEX + SC5_BMQ_NUM - 1;

	wlqm = &wlpptr->wlpd_p->descData[qid];
	size = wlqm->rq.bm.buf_size;
	WLDBG_DATA(DBG_LEVEL_0, "CFHUL: BMQid(%d) size %d \n", qid, size);

	WLDBG_DATA(DBG_LEVEL_0, "Refill BMQ13 with hw buffer addr:%x\n",
		   pe_hw->pe0_lo_dword_addr);
	wlqm->rq.rdinx = wlQueryRdPtr(netdev, qid, SC5_RQ);
	while (isRQFull(&wlqm->rq) == FALSE) {
		if (wlRQIndexPut(qid, &wlqm->rq) == TRUE) {
			// Buffer is not full
			wlpd_p->drv_stats_val.enq_bmqbuf_cnt[qid -
							     SC5_BMQ_START_INDEX]++;
		} else {
			break;
		}
	}
	wlUpdateWrPtr(netdev, qid, SC5_RQ, wlqm->rq.wrinx, false);

	return SUCCESS;
}

#endif //0

static int
_wlRxBufFill(struct net_device *netdev, int qid)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	struct except_cnt *wlexcept_p = &wlpd_p->except_cnt;
	struct wldesc_data *wlqm;
	struct sk_buff *skb;
	dma_addr_t phy_addr;
	wl_bm_t *bm;
	bm_pe_hw_t *pe_hw;
	//bm_pe_t *pe;
	bool found = FALSE;
	unsigned int size, skb_size;
	struct sk_buff **skb_addr;

	wlqm = &wlpptr->wlpd_p->descData[qid];
	size = wlqm->rq.bm.buf_size;
	WLDBG_DATA(DBG_LEVEL_3, "CFHUL: BMQ(%d) size %d \n", qid, size);

	if (isRQEmpty(&wlqm->rq) == TRUE) {
		struct except_cnt *wlexcept_p = &wlpd_p->except_cnt;
		wlexcept_p->qfull_empty[qid][SC5_RQ]++;
	}

	WLDBG_INFO(DBG_LEVEL_2, "(skbTrace->next)=(%p)\n",
		   wlqm->rq.skbTrace.next);
	skb = rpkt_resue_get(&wlqm->rq.skbTrace);
	found = (skb != NULL) ? TRUE : FALSE;
	if (found == FALSE) {
		// Adding bytes for alignment
		skb_size = size + 2 * SKB_INFO_SIZE;	//add skb tail signature checking
		skb = wl_alloc_skb(skb_size + RXBUF_ALIGN);
		if (!skb) {
			wlpd_p->drv_stats_val.bmqbuf_alloc_fail_cnt[qid -
								    SC5_BMQ_START_INDEX]++;
			WLDBG_ERROR(DBG_LEVEL_0,
				    "Failed to allocate skb, size=%d\n",
				    skb_size);
			WL_ASSERT(FALSE,
				  ("Failed to allocate skb, size=%d\n",
				   skb_size));
			return FAIL;
		} else {
			WLDBG_DATA(DBG_LEVEL_3,
				   "Q(%d), rx_buf_fill alloc_size=%d\n", qid,
				   skb_size);
		}
		skb->dev = netdev;
		//skb_reserve(skb, SKB_INFO_SIZE);
		if (((U32) (skb->data - skb->head)) < SKB_INFO_SIZE) {
			// Make sure the headroom is sufficient
			wlexcept_p->sml_rx_hdroom_cnt++;
		}
		if (!IS_ALIGNED(((long)skb->data), RXBUF_ALIGN)) {
			// Make sure the buffer is aligned
			wlexcept_p->rxbuf_mis_align_cnt++;
			skb->data = PTR_ALIGN(skb->data, RXBUF_ALIGN);
		}
	}

	skb->dev = netdev;
	*((u32 *) (skb->data - SKB_INFO_SIZE)) = SKB_SIGNATURE;
	skb_addr = (struct sk_buff **)(skb->data - SKB_POINTER_OFFSET);
	*skb_addr = skb;

	//Add tail signature check
	*((u32 *) (skb->data + size + SKB_TAIL_SIGNATURE_OFFSET)) =
		SKB_TAIL_SIGNATURE;
	phy_addr =
		dma_map_single(wlpptr->wlpd_p->dev, skb->data, size,
			       DMA_FROM_DEVICE);

	pe_hw = (bm_pe_hw_t *) (wlqm->rq.virt_addr +
				wlqm->rq.wrinx * sizeof(bm_pe_hw_t));
	pe_hw->pe0_lo_dword_addr = phy_addr;
	pe_hw->pe0_hi_byte_addr = wlpd_p->reg.smac_buf_hi_addr;
	bm = &wlqm->rq.bm;

	WLDBG_DATA(DBG_LEVEL_3,
		   "CFHUL: [RxBufFill] RQ( %d ) wrinx %d virt_addr %p skb %p phy_addr %xh\n",
		   //qid, wlqm->rq.wrinx, pe->virt_addr, skb, pe->phy_addr);
		   qid, wlqm->rq.wrinx, skb->data, skb,
		   pe_hw->pe0_lo_dword_addr);
	spin_lock(&wlpd_p->pend_skb_trace[PENDSKB_RX].lock);
	__skb_queue_tail(&wlpd_p->pend_skb_trace[PENDSKB_RX], skb);
	spin_unlock(&wlpd_p->pend_skb_trace[PENDSKB_RX].lock);
	if (wlRQIndexPut(qid, &wlqm->rq) == TRUE) {
		// Buffer is not full
		wlpd_p->drv_stats_val.enq_bmqbuf_cnt[qid -
						     SC5_BMQ_START_INDEX]++;
	} else {
		WLDBG_WARNING(DBG_LEVEL_0, "Queue %d is full to fill", qid);
		return FAIL;
	}

	return SUCCESS;
}

extern int htc_he_find_control_id(IEEEtypes_htcField_t * htc, u8 in_controlid);
extern UINT32 wlFwSetSchedMode(struct net_device *netdev, UINT16 action,
			       UINT32 mode_selected, void *pCfg, UINT16 len,
			       UINT16 * pStatus);
void
wl_nullpkt_hndl(struct net_device *netdev, wlrxdesc_t * pcfh_ul)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;

	U8 *ppayload = (u8 *) phys_to_virt(pcfh_ul->hdr.lo_dword_addr);
	IEEEtypes_FrameCtl_t *frame_ctlp;
	IEEEtypes_fullHdr_t *mac_hdr;
	IEEEtypes_htcField_t htc;
	IEEEtypes_AcontrolInfoOm_t acontrol_om;
	extStaDb_StaInfo_t *pStaInfo = NULL;
	int shift_bits = 0;
	UINT32 ul_usr_num = 0;
	UINT32 mib_val = 0;
	UINT16 status = 0;
	struct wlprivate *vap_wlpptr = NULL;
	sched_cfg_ul_ofdma_t tf_cfg;
	UINT32 data_len[18] = { 0 };
	UINT8 *msg_buf;
	union iwreq_data wreq;

	if ((ppayload == NULL) || !virt_addr_valid(ppayload)) {
		// Invalid pointer
		return;
	}

	mac_hdr = (IEEEtypes_fullHdr_t *) (ppayload + 4);
	/*  skip 32-bit MPDU tag
	   Where 4 bytes are 32-bit MPDU tag:
	   type[31:28]: // Bit[3:2] = HE(3)/VHT(2)/HT(1)/Non-HT (0)
	   // Bit[1] = Aggregate Tag (VHT/HT/-Non-HT)
	   // Bit[0] = First MPDU tag (VHT/HT/Non-HT)
	   usrId[23:16]: 0-15 Rx user ID
	   len[15:0]: Rx MPDU length */

	frame_ctlp = &mac_hdr->FrmCtl;
	if (frame_ctlp->Order == 0) {
		// Ref: 9.2.4.1.10 +HTC/Order subfield of 11ax spec => HT Control filed does not exist
		return;
	}
	//printk("frame_ctrl:\n");
	//mwl_hex_dump(frame_ctlp, sizeof(IEEEtypes_FrameCtl_t));
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

	//printk("%s(), htc:\n", __func__);
	//mwl_hex_dump(&htc, sizeof(htc));
	if ((htc.he_variant.vht && htc.he_variant.he)) {	/* HTC  HE variant present */
		shift_bits = htc_he_find_control_id(&htc, CONTROL_ID_OM);
	}
	//printk("\t shift_bits: %d\n", shift_bits);
	if (shift_bits) {
		acontrol_om.om_control =
			(htc.he_variant.a_control >> shift_bits) & 0xFFF;
		if (wfa_11ax_pf)	/* Only print for WFA tests */
			printk("acontrol_om.chbw %d acontrol_om.rxnss %d, acontrol_om.tx_nsts %d, acontrol_om.ulmu_disable %d\n", acontrol_om.chbw, acontrol_om.rxnss, acontrol_om.tx_nsts, acontrol_om.ulmu_disable);
		if ((pStaInfo = extStaDb_GetStaInfo(vmacSta_p,
						    (IEEEtypes_MacAddr_t *) &
						    mac_hdr->Addr2,
						    STADB_SKIP_MATCH_VAP |
						    STADB_NO_BLOCK)) != NULL) {

			vap_wlpptr =
				NETDEV_PRIV_P(struct wlprivate, pStaInfo->dev);

			if (wfa_11ax_pf &&
			    (vap_wlpptr->vmacSta_p->ul_ofdma.period_tmr != 0)) {
				if (pStaInfo->operating_mode.tx_nsts !=
				    acontrol_om.tx_nsts) {
					ul_usr_num = 1;
					mib_val = acontrol_om.tx_nsts;
					wlFwSetMib(pStaInfo->dev,
						   HostCmd_ACT_GEN_SET,
						   MIB_TF_NSS, &mib_val,
						   &ul_usr_num);
					wlFwSetMib(pStaInfo->dev,
						   HostCmd_ACT_GEN_GET,
						   MIB_TF_DATA_LEN, data_len,
						   &ul_usr_num);
					data_len[0] =
						data_len[0] *
						(acontrol_om.tx_nsts +
						 1) /
						(pStaInfo->operating_mode.
						 tx_nsts + 1);
					ul_usr_num = 1;
					wlFwSetMib(pStaInfo->dev,
						   HostCmd_ACT_GEN_SET,
						   MIB_TF_DATA_LEN, data_len,
						   &ul_usr_num);
				}

				if (pStaInfo->operating_mode.ulmu_disable !=
				    acontrol_om.ulmu_disable) {

					if (acontrol_om.ulmu_disable == 1) {
						memcpy((void *)&tf_cfg,
						       (void *)&vap_wlpptr->
						       vmacSta_p->ul_ofdma,
						       sizeof
						       (sched_cfg_ul_ofdma_t));
						tf_cfg.period_tmr = 0;
						wlFwSetSchedMode(pStaInfo->dev,
								 HostCmd_ACT_GEN_SET,
								 MODE_SELECT_UL_OFDMA,
								 &tf_cfg,
								 sizeof
								 (sched_cfg_ul_ofdma_t),
								 &status);
					} else {
						wlFwSetSchedMode(pStaInfo->dev,
								 HostCmd_ACT_GEN_SET,
								 MODE_SELECT_UL_OFDMA,
								 (void *)
								 &vap_wlpptr->
								 vmacSta_p->
								 ul_ofdma,
								 sizeof
								 (sched_cfg_ul_ofdma_t),
								 &status);
					}
				}
			} else if (pStaInfo->operating_mode.ulmu_disable !=
				   acontrol_om.ulmu_disable) {
				msg_buf = wl_kmalloc(IW_CUSTOM_MAX, GFP_KERNEL);
				if (msg_buf == NULL) {
					printk("kmalloc failed for OMI event\n");
					return;
				}
				if (acontrol_om.ulmu_disable == 1) {
					printk("qos NULL,"
					       "acontrol_om.chbw %d acontrol_om.rxnss %d,"
					       "acontrol_om.tx_nsts %d,"
					       "acontrol_om.ulmu_disable %d\n",
					       acontrol_om.chbw,
					       acontrol_om.rxnss,
					       acontrol_om.tx_nsts,
					       acontrol_om.ulmu_disable);
					sprintf(msg_buf,
						"wlmgr: mumode ul_ofdma_disable stnid:%d",
						pStaInfo->StnId);
					memset(&wreq, 0, sizeof(wreq));
					wreq.data.length = strlen(msg_buf);
					wireless_send_event(pStaInfo->dev,
							    IWEVCUSTOM, &wreq,
							    msg_buf);
				} else {
					sprintf(msg_buf,
						"wlmgr: mumode ul_ofdma_enable stnid:%d",
						pStaInfo->StnId);
					wireless_send_event(pStaInfo->dev,
							    IWEVCUSTOM, &wreq,
							    msg_buf);
					memset(&wreq, 0, sizeof(wreq));
					wreq.data.length = strlen(msg_buf);
				}
				wl_kfree(msg_buf);
			}

			if ((pStaInfo->operating_mode.rxnss !=
			     acontrol_om.rxnss) ||
			    (pStaInfo->operating_mode.chbw !=
			     acontrol_om.chbw)) {
				wlFwSetVHTOpMode(pStaInfo->dev, pStaInfo->StnId,
						 acontrol_om.chbw,
						 acontrol_om.rxnss + 1);
			}

			if (wfa_11ax_pf &&
			    (vap_wlpptr->vmacSta_p->ul_ofdma.period_tmr != 0)) {
				if (pStaInfo->operating_mode.chbw !=
				    acontrol_om.chbw) {
					switch (acontrol_om.chbw) {
					case 3:
						ul_usr_num = 1;
						mib_val = 68;
						wlFwSetMib(pStaInfo->dev,
							   HostCmd_ACT_GEN_SET,
							   MIB_TF_RU_ALLOC,
							   &mib_val,
							   &ul_usr_num);
						break;
					case 2:
						ul_usr_num = 1;
						mib_val = 67;
						wlFwSetMib(pStaInfo->dev,
							   HostCmd_ACT_GEN_SET,
							   MIB_TF_RU_ALLOC,
							   &mib_val,
							   &ul_usr_num);
						break;
					case 1:
						ul_usr_num = 1;
						mib_val = 65;
						wlFwSetMib(pStaInfo->dev,
							   HostCmd_ACT_GEN_SET,
							   MIB_TF_RU_ALLOC,
							   &mib_val,
							   &ul_usr_num);
						break;
					case 0:
						ul_usr_num = 1;
						mib_val = 61;
						wlFwSetMib(pStaInfo->dev,
							   HostCmd_ACT_GEN_SET,
							   MIB_TF_RU_ALLOC,
							   &mib_val,
							   &ul_usr_num);
						break;
					default:
						break;
					}
					wlFwSetMib(pStaInfo->dev,
						   HostCmd_ACT_GEN_GET,
						   MIB_TF_DATA_LEN, data_len,
						   &ul_usr_num);
					data_len[0] =
						data_len[0] *
						(2 << acontrol_om.chbw) /
						(2 << pStaInfo->operating_mode.
						 chbw);
					ul_usr_num = 1;
					wlFwSetMib(pStaInfo->dev,
						   HostCmd_ACT_GEN_SET,
						   MIB_TF_DATA_LEN, data_len,
						   &ul_usr_num);
				}
			}

			if (pStaInfo->operating_mode.om_control !=
			    acontrol_om.om_control)
				pStaInfo->operating_mode.om_control =
					acontrol_om.om_control;
		}
	}

	return;
}

#ifdef MISC_ACTION
extern extStaDb_StaInfo_t *extStaDb_GetStaInfoStn(vmacApInfo_t * vmac_p,
						  UINT8 stnid);
extern vmacApInfo_t *vmacGetMBssByAddr(vmacApInfo_t * vmacSta_p,
				       UINT8 * macAddr_p);
extern void SendDelBASta(vmacApInfo_t * vmacSta_p, IEEEtypes_MacAddr_t StaAddr,
			 UINT8 tsid);

void
wl_reset_ba(struct net_device *netdev, extStaDb_StaInfo_t * pStaInfo,
	    UINT8 tsid)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	int i;

	for (i = 0; i < MAX_SUPPORT_AMPDU_TX_STREAM_RUNNING; i++) {
		if (!MACADDR_CMP
		    (wlpd_p->Ampdu_tx[i].MacAddr, &(pStaInfo->Addr))) {
			/** they are equal **/
			if (wlpd_p->Ampdu_tx[i].AccessCat == tsid &&
			    wlpd_p->Ampdu_tx[i].InUse == 1) {
				WLDBG_INFO(DBG_LEVEL_0,
					   "del ba !!!! They match!!!!\n");
				/* Reset the flags so that stream can be started once traffic is back on */
				pStaInfo->aggr11n.onbytid[wlpd_p->Ampdu_tx[i].
							  AccessCat] = 0;
				pStaInfo->aggr11n.startbytid[wlpd_p->
							     Ampdu_tx[i].
							     AccessCat] = 0;
				pStaInfo->aggr11n.type &= ~WL_WLAN_TYPE_AMPDU;
				wlFwUpdateDestroyBAStream(vmacSta_p->dev, 0, 0,
							  i,
							  wlpd_p->Ampdu_tx[i].
							  AccessCat,
							  wlpd_p->Ampdu_tx[i].
							  MacAddr,
							  pStaInfo->StnId);
				wlpd_p->Ampdu_tx[i].InUse = 0;
				wlpd_p->Ampdu_tx[i].TimeOut = 0;
			}
		}
	}
	return;
}

void
wl_ack_policy_mismatch(struct net_device *netdev, wlrxdesc_t * pcfh_ul)
{
	U8 *ppayload = (u8 *) phys_to_virt(pcfh_ul->hdr.lo_dword_addr);
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	extStaDb_StaInfo_t *StaInfo_p;
	u16 stnid;
	vmacApInfo_t *vmactem_p;
	IEEEtypes_MacAddr_t sta_macaddr;

	// Format of the packet: [Tag:4] + [wlan_fc:4] + [RA:6] + [TA:6]
	memcpy(sta_macaddr, &ppayload[14], sizeof(IEEEtypes_MacAddr_t));
	StaInfo_p =
		extStaDb_GetStaInfo(vmacSta_p,
				    (IEEEtypes_MacAddr_t *) & sta_macaddr,
				    STADB_SKIP_MATCH_VAP | STADB_FIND_IN_CACHE |
				    STADB_NO_BLOCK);
	if (StaInfo_p == NULL) {
		//printk("StaInfo_p is NULL \n");
		//mwl_hex_dump(pcfh_ul, sizeof(wlrxdesc_t));
		//printk("pkt: (%u)\n", pcfh_ul->hdr.length);
		//mwl_hex_dump(ppayload, pcfh_ul->hdr.length);

		return;
	}
	stnid = StaInfo_p->StnId;
	//printk("STA_MAC: %02x:%02x:%02x:%02x:%02x:%02xm stnid: %u \n", 
	//      sta_macaddr[0], sta_macaddr[1],sta_macaddr[2],sta_macaddr[3],sta_macaddr[4],sta_macaddr[5],
	//      stnid);

	vmactem_p = vmacGetMBssByAddr(vmacSta_p, StaInfo_p->Bssid);
	if (vmactem_p == NULL) {
		//printk("vmactem_p is NULL\n");
		return;
	}
	//printk("vmactem_p: %s\n", vmactem_p->dev->name);

	// => Send DelBA to teardown
	//printk("Sending DelBA: [%02x:%02x:%02x:%02x:%02x:%02x], tid=%u\n",
	//      sta_macaddr[0], sta_macaddr[1],sta_macaddr[2],sta_macaddr[3],ppayload[4],ppayload[5],
	//      pcfh_ul->hdr.miscVal);
	SendDelBA2(vmactem_p, sta_macaddr, pcfh_ul->hdr.miscVal);
	wl_reset_ba(netdev, StaInfo_p, pcfh_ul->hdr.miscVal);

	return;
}
#endif //MISC_ACTION

/* caller call this function to Rx Q and update rdinx
 */
wlrxdesc_t *
wlGetCfhUl(struct net_device * netdev, int qid, wlrxdesc_t * cfh_ul)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	struct wldesc_data *wlqm;
	struct wldesc_data *wlqm_tmp;
	wlrxdesc_t *cfh_ul_hw;
	struct except_cnt *wlexcept_p = &wlpd_p->except_cnt;
#ifdef ASSERT_MALBUF
	u32 cfhul_err = 0;
	u32 cfh_log[24];
#endif //ASSERT_MALBUF
	u16 *snap_aaaa;
	BOOLEAN cfhul_skb_recov = TRUE;
	IEEEtypes_FrameCtl_t *frame_ctlp;

	if (wfa_11ax_pf)
		cfhul_skb_recov = FALSE;
	wlqm = &wlpptr->wlpd_p->descData[qid];
	cfh_ul_hw =
		(wlrxdesc_t *) (wlqm->sq.virt_addr +
				wlqm->sq.rdinx * sizeof(wlrxdesc_t));

	memcpy(cfh_ul, cfh_ul_hw, sizeof(wlrxdesc_t));
	// Start processing
	if (cfhul_skb_recov == TRUE)
		wl_update_cfhul_buf_rec(&wlpd_p->icfhul_buf_pool, netdev, qid,
					wlqm->sq.rdinx, cfh_ul);
	wlpd_p->irxdbg_intr.rxdbg_push(&wlpd_p->vrxdbg_db, cfh_ul, qid,
				       wlqm->sq.rdinx, wlqm->sq.wrinx);
	wlpd_p->irxdbg_intr.rxdbg_chk(&wlpd_p->vrxdbg_db);

	if (qid == SC5_RXQ_START_INDEX)
		wlpd_p->except_cnt.cfhul_data_cnt += 1;
	if (cfh_ul->mic_err == 1) {
		wlexcept_p->rx_mic_err_cnt++;
	}
	if (cfh_ul->icv_err == 1) {
		wlexcept_p->rx_icv_err_cnt++;
	}
	if (cfh_ul->hdrFormat == 1) {
		// Bypass this packets by Powei's mail on 2018/10/9,
		// "RX packet forward to host with MIC/ICV or other error.
		//      Since packet is bad, we will use RxAMSDU bypass mode to generate CFH-UL without parsing the data. 
		// In this case, RxAMSDU will just copy CFH-TEMP and set Fpkt/Lpkt=1/1"
		wlexcept_p->rx_bypass_cnt++;
		if ((cfh_ul->mic_err == 0) && (cfh_ul->icv_err == 0)) {
#ifdef NULLPKT_DBG
			// Save the received null packet => for debugging purpose
			U16 pktlen;
			U8 *ppayload;
			int id = wlpd_p->rpkt_type_cnt.null_cnt % 10;

			pktlen = (cfh_ul->hdr.length <
				  1024) ? cfh_ul->hdr.length : 1024;
			ppayload =
				(u8 *) phys_to_virt(cfh_ul->hdr.lo_dword_addr);
			memcpy(&wlpd_p->nullpkt_cfhul[id], cfh_ul,
			       sizeof(wlrxdesc_t));
			memcpy(wlpd_p->last_null_pkt[id], ppayload, pktlen);
#endif //NULLPKT_DBG
			wl_nullpkt_hndl(netdev, cfh_ul);
			//NULL pkt
			wlpd_p->rpkt_type_cnt.null_cnt++;
			if (cfhul_skb_recov == FALSE) {
				wl_free_cfhul_lo(cfh_ul->hdr.lo_dword_addr,
						 netdev, cfh_ul->hdr.bpid);
				wl_clr_cfhul_buf_rec(&wlpd_p->icfhul_buf_pool,
						     qid, wlqm->sq.rdinx,
						     cfh_ul);
			}
			return NULL;
		}
	}
#ifdef MISC_ACTION
	if (cfh_ul->hdr.miscAction == 1) {
		// BAR mismatched in SMAC
		wl_ack_policy_mismatch(netdev, cfh_ul);
		return NULL;
	}
#endif //MISC_ACTION
	// Return if CFH-UL not been updated yet
	if (cfh_ul->nss_hdr[2] == HF_OWN_SIGNATURE ||
	    cfh_ul->hdr.length == USED_BUFLEN ||
	    cfh_ul->hdr.used_signature == BMBUF_SIGNATURE) {
		wlpd_p->except_cnt.cnt_cfhul_invalid_signature++;
#ifdef ASSERT_MALBUF
		WLDBG_WARNING(DBG_LEVEL_0, "ERROR: Invalid cfhul signature\n");
		cfhul_err = 1;
#else
		return NULL;
#endif
	}

	wlpd_p->drv_stats_val.rxq_rcv_cnt[qid]++;
#ifdef ASSERT_MALBUF
	memcpy(&cfh_log[0], cfh_ul, 24);
#endif /* ASSERT_MALBUF */

	if ((cfh_ul->hdr.bpid < SC5_BMQ_START_INDEX) ||
	    ((SC5_BMQ_START_INDEX + SC5_BMQ_NUM - 1) <= cfh_ul->hdr.bpid)) {
		wlpd_p->except_cnt.cnt_cfhul_error++;
#ifdef ASSERT_MALBUF
		WLDBG_WARNING(DBG_LEVEL_0,
			      "ERROR: Invalid bpid:%u from SQ(%u)\n",
			      cfh_ul->hdr.bpid, qid);
		cfhul_err = 1;
#else
		return NULL;
#endif
	}

	wlqm_tmp = &wlpptr->wlpd_p->descData[cfh_ul->hdr.bpid];

	frame_ctlp = (IEEEtypes_FrameCtl_t *) & cfh_ul->frame_ctrl;
	/* SNAP check will break fragmented data traffic. Skip check for fragmented pkt */
	/* Skip SNAP check for mic_err, icv_err pkt. */
	if ((frame_ctlp->Type == IEEE_TYPE_DATA) &&
	    (!frame_ctlp->MoreFrag && !(cfh_ul->hdr.seqNum & 0xF) &&
	     (cfh_ul->hdrFormat != 1))) {
		/* Check the 0xAAAA of SNAP in data MSDU header
		 */
		snap_aaaa = (u16 *) cfh_ul->nss_hdr;
		if ((qid == SC5_RXQ_START_INDEX) && (snap_aaaa[7] != 0xAAAA)) {
			wlpd_p->except_cnt.cnt_cfhul_snap_error++;
			return NULL;
		}
	}

	if (cfh_ul->hdr.length > wlqm_tmp->rq.bm.buf_size) {
		wlpd_p->except_cnt.cnt_cfhul_oversize++;
#ifdef ASSERT_MALBUF
		WLDBG_ERROR(DBG_LEVEL_0,
			    "ERROR: data size is over-size %d  bpid:%d from SQ(%u)\n",
			    cfh_ul->hdr.length, cfh_ul->hdr.bpid, qid);
		mwl_hex_dump((u8 *) cfh_ul, sizeof(wlrxdesc_t));
		cfhul_err = 1;
#else
		return NULL;
#endif
	}
#ifdef ASSERT_MALBUF
	memcpy(&cfh_log[6], cfh_ul, 24);
#endif /* ASSERT_MALBUF */

	//Z2 incorrect fpkt & lpkt WAR
	if (qid == 8 || qid == 9) {
		cfh_ul->fpkt = 1;
		cfh_ul->lpkt = 1;
	}
#ifdef ASSERT_MALBUF
	if (cfhul_err == 1) {
		u32 widx = wlQueryWrPtr(netdev, qid, SC5_SQ);
		memcpy(&cfh_log[12], cfh_ul, 24);
		printk("before: widx=%u, wlqm->sq.rdinx=%u\n", widx,
		       wlqm->sq.rdinx);
	}
#endif //ASSERT_MALBUF
	WLDBG_DATA(DBG_LEVEL_3, "CFHUL: SQ(%d) rdinx %d\n", qid,
		   wlqm->sq.rdinx);

#ifdef ASSERT_MALBUF
	if (cfhul_err == 1) {
		u32 widx;
		dbg_level = 0x1;
		WLDBG_ERROR(DBG_LEVEL_0, "ERROR Z1: Invalid CFHUL content");
		memcpy(&cfh_log[18], cfh_ul, 24);
		widx = wlQueryWrPtr(netdev, qid, SC5_SQ);
		printk("after: widx=%u, wlqm->sq.rdinx=%u\n", widx,
		       wlqm->sq.rdinx);
		//mwl_hex_dump((u8 *)cfh_ul, sizeof(wlrxdesc_t));
		//WLDBG_HEXDUMP(DBG_LEVEL_0, cfh_ul, sizeof(wlrxdesc_t));
		mwl_hex_dump((u8 *) cfh_log, 24);
		mwl_hex_dump((u8 *) & cfh_log[6], 24);
		mwl_hex_dump((u8 *) & cfh_log[12], 24);
		mwl_hex_dump((u8 *) & cfh_log[18], 24);
		printk("qidcnt SQ0:%u SQ8:%u SQ9:%u\n",
		       wlpd_p->drv_stats_val.rxq_rcv_cnt[0],
		       wlpd_p->drv_stats_val.rxq_rcv_cnt[8],
		       wlpd_p->drv_stats_val.rxq_rcv_cnt[9]);
		wl_util_writel(netdev, 0xdeadbeef, wlpptr->ioBase1 + PCI_REG_SCRATCH14_REG);
		wl_dump_dbgrelq_info(netdev, 0x528, 0x52c);
		wl_dump_dbgrelq_info(netdev, 0x520, 0x524);
		wl_dump_dbgrelq_info(netdev, 0x518, 0x51c);
		WL_ASSERT(FALSE, ("Assert with Invalid CFHUL content\n"));
		return NULL;
	}
#endif

	wl_clr_cfhul_buf_rec(&wlpd_p->icfhul_buf_pool, qid, wlqm->sq.rdinx,
			     cfh_ul);

	return cfh_ul;
}

// Spilt AMSDU to MSDU for workaround

wlrxdesc_t *
wlSpiltAMSDU(struct net_device * netdev, wlrxdesc_t * cfh_ul)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	wlrxdesc_t *cfh_ul_amsdu = NULL;
	//u16 len_offset = sizeof(IEEEtypes_MacAddr_t)*2;
	//u16 next_buf_off = 0;
	int i;
	u16 msdu_no = cfh_ul->hdrFormat;
	// Note: Expected frame  begin at lo_dword_addr with format
	//(da/sa/length/payload/padding)+(da/sa/length/payload/padding)+..
	// if not, need to re-init the offset.
	u32 msdu_start_offset = 0;
	u8 *amsdu_start = NULL;
	u8 *msdu_addr = NULL;
	u16 length;
	struct wldesc_data *wlqm =
		&wlpptr->wlpd_p->descData[(cfh_ul->hdr.bpid) & 0xf];

	//wlrxdesc_t *pcfh;

	if (msdu_no == 0) {
		WLDBG_ERROR(DBG_LEVEL_0,
			    "Total %u msdu subframes in this AMSDU frame\n",
			    cfh_ul->hdrFormat);
		return NULL;
	}
	WLDBG_DATA(DBG_LEVEL_3, "Total %u msdu subframes in this AMSDU frame\n",
		   cfh_ul->hdrFormat);
	amsdu_start = (u8 *) phys_to_virt(cfh_ul->hdr.lo_dword_addr);
	WLDBG_DATA(DBG_LEVEL_3, "AMSDU frame start at phy:%08xh,virt:%p \n",
		   cfh_ul->hdr.lo_dword_addr, amsdu_start);
	msdu_addr = amsdu_start + msdu_start_offset;

	dma_unmap_single(wlpptr->wlpd_p->dev, virt_to_phys(amsdu_start),
			 wlqm->rq.bm.buf_size, DMA_FROM_DEVICE);

	cfh_ul_amsdu =
		(wlrxdesc_t *) wl_kmalloc((msdu_no * sizeof(wlrxdesc_t)),
					  GFP_ATOMIC);

	for (i = 0; i < msdu_no; i++) {
		memcpy((u8 *) & cfh_ul_amsdu[i], (u8 *) cfh_ul,
		       sizeof(wlrxdesc_t));
		WLDBG_DATA(DBG_LEVEL_3,
			   "CFHUL_AMSDU: [%d]th msdu start at %p\n", i,
			   msdu_addr);
		if (i == 0) {	// first
			cfh_ul_amsdu[i].fpkt = 1;
			cfh_ul_amsdu[i].lpkt = 0;
			cfh_ul_amsdu[i].hdr.lo_dword_addr =
				cfh_ul->hdr.lo_dword_addr;
		} else {
			cfh_ul_amsdu[i].fpkt = 0;
			cfh_ul_amsdu[i].lpkt = 0;
			cfh_ul_amsdu[i].hdr.lo_dword_addr =
				(u32) virt_to_phys(msdu_addr);
		}

		if (i == (msdu_no - 1)) {	// last msdu
			cfh_ul_amsdu[i].lpkt = 1;
		}
		WLDBG_DATA(DBG_LEVEL_3,
			   "CFHUL_AMSDU: [%d] fpkt %d lpkt %d  phy addr %x\n",
			   i, cfh_ul_amsdu[i].fpkt, cfh_ul_amsdu[i].lpkt,
			   cfh_ul_amsdu[i].hdr.lo_dword_addr);
		// Expected frame  begin at lo_dword_addr with format   (da/sa/length/payload/padding)+(da/sa/length/payload/padding)+..
		// if not, need to do some adjustment ????
		length = (u16) msdu_addr[12];
		length = ((length << 8) | (u16) msdu_addr[13]);

		if (length > 1508 || length < (LLC_HDR_LEN + IP_HDR_LEN) ||
		    *((u16 *) & msdu_addr[14]) != 0xaaaa) {
			wlpd_p->except_cnt.cnt_invalid_amsdu_subframe_len++;
			WLDBG_WARNING(DBG_LEVEL_0,
				      "ERROR: Invalid AMSDU subframe length:%u ,cfh_ul->hdr.length:%u\n",
				      length, cfh_ul->hdr.length);
			//darlee
			WLDBG_HEXDUMP(DBG_LEVEL_0, amsdu_start,
				      cfh_ul->hdr.length);
			wl_kfree((const void *)cfh_ul_amsdu);
			return NULL;
		}

		cfh_ul_amsdu[i].hdr.length = length;

		length = roundup_MRVL((length + sizeof(ether_hdr_t)), 4);
		WLDBG_DATA(DBG_LEVEL_3, "[%d] subframes total length=%u\n", i,
			   length);

		msdu_addr = (msdu_addr + length);
	}			// end of for loop

	wlpd_p->except_cnt.cnt_amsdu_subframes += msdu_no;

	/*
	   pcfh = cfh_ul_amsdu;
	   for(i=0; i<3; i++, pcfh++)
	   {
	   printk("dump duplicated cfh_UL [%d]\n", i);
	   mwl_hex_dump(pcfh, sizeof(wlrxdesc_t));
	   }
	 */

	return cfh_ul_amsdu;
}

wlrxdesc_t *
wlProcessErrCfhul(struct net_device * netdev, u32 * msduNo)
{
	wl_cfhul_amsdu *pcfhul_amsdu = NULL;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;

	pcfhul_amsdu =
		(wl_cfhul_amsdu *) wlpd_p->irxdbg_intr.
		rxdbg_pull_errcfhul(&wlpd_p->vrxdbg_db);
	if (pcfhul_amsdu) {
		recovered_errcfhul += 1;
		*msduNo = pcfhul_amsdu->idx;
		return &pcfhul_amsdu->rxdesc[0];
	}
	return NULL;
}

/*
input: 
 	cfh_ul:  rxdescriptor
output: 
  	msduNO: # of subframes ready to upload. 

return: Accumulated wlrxdesc_t(subframes) for upload

Note: 
msduNO = 1, return != NULL.  It's single-MSDU. No AMSDU subframes ahead in accumulating pool(array)
msduNO = 0, return = NULL.  Accumulate this subframe into pool
msduNO > 1, return != NULL. all subframes of a AMSDU frames are received.
*/

wlrxdesc_t *
wlProcessMsdu(struct net_device * netdev, wlrxdesc_t * cfh_ul, u32 * msduNo,
	      u32 qid)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	//dralee
	wlrxdesc_t *cfh_ul_amsdu = &(wlpptr->cfhul_amsdu[qid].rxdesc[0]);
	u32 *pidx = &(wlpptr->cfhul_amsdu[qid].idx);

	wlrxdesc_t *ret = NULL;
	u8 FLpkt = 0;

	FLpkt = cfh_ul->fpkt;
	FLpkt = (FLpkt << 1) | cfh_ul->lpkt;

	*msduNo = 0;
	switch (FLpkt) {
	case 0:		//middle subframe
		{
			if (*pidx != 0) {	//middle frames arrives. put in acc pool
				memcpy((void *)&cfh_ul_amsdu[(*pidx)++],
				       (void *)cfh_ul, sizeof(wlrxdesc_t));
			} else {
				//error handling.  individual middle come along.
				wlpd_p->except_cnt.cfhul_flpkt_lost[0]++;
				//printk("missing fpkt...\n");
				wlpd_p->irxdbg_intr.
					rxdbg_push_errcfhul(&wlpd_p->vrxdbg_db,
							    NULL, cfh_ul);
			}

			wlpd_p->drv_stats_val.amsdu_frag[1]++;
		}
		break;
	case 1:		//last subframe
		{
			if (*pidx != 0) {	//01(last) arrives. all subframes of a amsdu are received.

				memcpy((void *)&cfh_ul_amsdu[(*pidx)++],
				       (void *)cfh_ul, sizeof(wlrxdesc_t));
				*msduNo = *pidx;
				*pidx = 0;	//init for next AMSDU.
				ret = &cfh_ul_amsdu[0];

			} else {	//01 arrives but accumulating pool is empty. 10 might be lost. 
				//error handling
				wlpd_p->except_cnt.cfhul_flpkt_lost[0]++;
				//printk("missing fpkt...\n");
				wlpd_p->irxdbg_intr.
					rxdbg_push_errcfhul(&wlpd_p->vrxdbg_db,
							    NULL, cfh_ul);
			}

			wlpd_p->drv_stats_val.amsdu_frag[2]++;
		}
		break;
	case 2:		//first subframe
		{
			if (*pidx == 0) {	//10(first) received, put in accu pool
				memcpy((void *)&cfh_ul_amsdu[(*pidx)++],
				       (void *)cfh_ul, sizeof(wlrxdesc_t));
			} else {	//10 arrives.  01 is lost in accumulating pool
				//error hanlding
				wlpd_p->except_cnt.cfhul_flpkt_lost[2]++;
				wlpd_p->irxdbg_intr.
					rxdbg_push_errcfhul(&wlpd_p->vrxdbg_db,
							    &wlpptr->
							    cfhul_amsdu[qid],
							    NULL);
				//printk("missing lpkt...\n");
				*pidx = 0;	//drop previous accumulationg 
				//restart accu from this subframe.
				memcpy((void *)&cfh_ul_amsdu[(*pidx)++],
				       (void *)cfh_ul, sizeof(wlrxdesc_t));
			}

			wlpd_p->drv_stats_val.amsdu_frag[0]++;
		}
		break;
	case 3:		//single-MSDU frame
		{
			if (*pidx != 0) {	//single-MSDU arrives, but 01(last) subframe is lost in accu pool 
				//error hanlding
				wlpd_p->except_cnt.cfhul_flpkt_lost[2]++;
				wlpd_p->irxdbg_intr.
					rxdbg_push_errcfhul(&wlpd_p->vrxdbg_db,
							    &wlpptr->
							    cfhul_amsdu[qid],
							    NULL);
				//printk("missing lpkt...\n");
				*pidx = 0;	//drop previous accumulating
			}
			wlpd_p->drv_stats_val.amsdu_frag[3]++;
			*msduNo = 1;
			ret = cfh_ul;
		}
		break;
	}

	//error handling in case total amsdu subframe numbers over driver rxdesc allocating size.
	if (*pidx == MAX_AMSDU_SUBFRAME) {
		//drop the accu 
		*pidx = 0;
		//subframes number over limit
		wlpd_p->except_cnt.cfhul_flpkt_lost[3]++;
	}

	return ret;
}

static void
check_queue_index(struct net_device *netdev, u16 qid, int qoff)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wldesc_data *wlqm = &wlpptr->wlpd_p->descData[qid];

	if (qoff == SC5_SQ) {
		wlqm->sq.wrinx = wlQueryWrPtr(netdev, qid, qoff);
		WLDBG_DATA(DBG_LEVEL_0,
			   "Index of SQ[%d] (wrinx, rdinx) = (%d, %d)\n", qid,
			   wlqm->sq.wrinx, wlqm->sq.rdinx);
	} else {
		wlqm->rq.rdinx = wlQueryRdPtr(netdev, qid, qoff);
		WLDBG_DATA(DBG_LEVEL_0,
			   "Index of RQ[%d] (wrinx, rdinx) = (%d, %d)\n", qid,
			   wlqm->rq.wrinx, wlqm->rq.rdinx);
	}
	return;
}

void
wlResetCfhUl(wlrxdesc_t * cfh_ul)
{
	/* invalidat some memory so we can check for new data */
	cfh_ul->hdr.used_signature = BMBUF_SIGNATURE;
	cfh_ul->hdr.length = USED_BUFLEN;
	cfh_ul->nss_hdr[2] = HF_OWN_SIGNATURE;
	return;
}

void
wldbg_aggr_stat(struct drv_stats *drvstat_p, wlrxdesc_t * cfh_ul)
{
	u32 qid = (u32) (cfh_ul->hdr.bpid);

	if (cfh_ul->fpkt == 1) {
		drvstat_p->rxq_midaggr[qid - SC5_BMQ_START_INDEX] = 1;
	} else {
		drvstat_p->rxq_midaggr[qid - SC5_BMQ_START_INDEX]++;
	}

	if ((cfh_ul->lpkt == 1) &&
	    (drvstat_p->rxq_midaggr[qid - SC5_BMQ_START_INDEX] > 1)) {
		// last fragment => record the result
		if (drvstat_p->rxq_midaggr[qid - SC5_BMQ_START_INDEX] <
		    AGGRCNT_ARYSIZE - 2) {
			drvstat_p->rxq_aggrcnt[qid -
					       SC5_BMQ_START_INDEX][drvstat_p->
								    rxq_midaggr
								    [qid -
								     SC5_BMQ_START_INDEX]
								    - 2]++;
		} else {
			drvstat_p->rxq_aggrcnt[qid -
					       SC5_BMQ_START_INDEX]
				[AGGRCNT_ARYSIZE - 1]++;
		}
	}
	return;
}

/*
	Check the pkt sequence of (fpkt,lpkt)
	Correct seq: 
		- (1, 1)
		- (1, 0), (0, 1)
		- (1, 0), (0, 0), (0, 1)
*/
static void
wldbg_chkrxpkt_seq(struct except_cnt *p_except, wlrxdesc_t * cfh_ul)
{
	//static BOOLEAN in_pkt[SC5_BMQ_NUM];
	//static U8             lastpkt_status[SC5_BMQ_NUM];
	U8 idx = cfh_ul->hdr.bpid - SC5_BMQ_START_INDEX;

	// Check fpkt:
	//              => 
	if (((cfh_ul->fpkt == 1) && (p_except->in_pkt[idx] == TRUE)) ||	// fpkt=1 & in the middle of pkt
	    ((cfh_ul->fpkt == 0) && (p_except->in_pkt[idx] == FALSE))) {	// pkt=0, has not sent pkt yet
		// Error cases
		p_except->cfhul_flpkt_error[idx]++;
		p_except->cfhul_flpkt_log[idx][0] =
			p_except->lastpkt_status[idx];
		p_except->cfhul_flpkt_log[idx][1] =
			cfh_ul->fpkt << 4 | cfh_ul->lpkt;
		return;
	}
	if (cfh_ul->fpkt == 1) {
		// pkt start
		p_except->in_pkt[idx] = TRUE;
	}
	// Check lpkt
	if ((cfh_ul->lpkt == 1) && (p_except->in_pkt[idx] == FALSE)) {	// lpt=1 & has not sent pkt yet
		// Error cases
		p_except->cfhul_flpkt_error[idx]++;
		p_except->cfhul_flpkt_log[idx][0] =
			p_except->lastpkt_status[idx];
		p_except->cfhul_flpkt_log[idx][1] =
			cfh_ul->fpkt << 4 | cfh_ul->lpkt;
		return;
	}
	if (cfh_ul->lpkt == 1) {
		// pkt end
		p_except->in_pkt[idx] = FALSE;
	}
	// Correct~
	// Log the (fpkt, lpkt)
	p_except->lastpkt_status[idx] = cfh_ul->fpkt << 4 | cfh_ul->lpkt;
	return;
}

void
wlUnmapBuffer(struct net_device *netdev, u8 * vaddr, u32 size)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);

	dma_unmap_single(wlpptr->wlpd_p->dev, virt_to_phys(vaddr),
			 size, DMA_FROM_DEVICE);
}

/*
	Save the tx packet counter and bytes per station
*/
void
wl_txdatpkt_stat_per_sta(extStaDb_StaInfo_t * pStaInfo, struct sk_buff *skb)
{
	if (!pStaInfo)
		return;

	if (skb && (skb->truesize > MAX_AGGR_SIZE))
		pStaInfo->tx_packets += skb->cb[0];
	else
		pStaInfo->tx_packets++;

	if (skb)
		pStaInfo->tx_bytes += skb->len;

	return;
}

/*
	Save the tx bcast/mcast bytes
*/
void
wl_txdatpkt_bcast_mcast(struct net_device *netdev, UINT8 * pAddr,
			struct sk_buff *skb)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);

	if (!skb)
		return;

	if (is_broadcast_ether_addr(pAddr))
		wlpptr->wlpd_p->privNdevStats.tx_bcast_bytes += skb->len;
	else if (is_multicast_ether_addr(pAddr))
		wlpptr->wlpd_p->privNdevStats.tx_mcast_bytes += skb->len;

	return;
}

/*
	Mgmt packets subtype
*/
void
wl_mpkt_subtype(struct pkttype_info *wlpkt_type, IEEEtypes_FrameCtl_t * fc)
{
	switch (fc->Subtype) {
	case IEEE_MSG_ASSOCIATE_RQST:
		wlpkt_type->assoc_req_cnt++;
		break;
	case IEEE_MSG_ASSOCIATE_RSP:
		wlpkt_type->assoc_resp_cnt++;
		break;
	case IEEE_MSG_REASSOCIATE_RQST:
		wlpkt_type->reassoc_req_cnt++;
		break;
	case IEEE_MSG_REASSOCIATE_RSP:
		wlpkt_type->reassoc_resp_cnt++;
		break;
	case IEEE_MSG_PROBE_RQST:
		wlpkt_type->prob_req_cnt++;
		break;
	case IEEE_MSG_PROBE_RSP:
		wlpkt_type->prob_resp_cnt++;
		break;
	case IEEE_MSG_BEACON:
		wlpkt_type->beacon_cnt++;
		break;
	case IEEE_MSG_ATIM:
		wlpkt_type->atim_cnt++;
		break;
	case IEEE_MSG_DISASSOCIATE:
		wlpkt_type->disassoc_cnt++;
		break;
	case IEEE_MSG_AUTHENTICATE:
		wlpkt_type->auth_cnt++;
		break;
	case IEEE_MSG_DEAUTHENTICATE:
		wlpkt_type->deauth_cnt++;
		break;

	}
	return;
}

/*
	Ctrl packets subtype
*/
void
wl_cpkt_subtype(struct pkttype_info *wlpkt_type, IEEEtypes_FrameCtl_t * fc)
{
	switch (fc->Subtype) {
	case BLK_ACK_REQ:
		wlpkt_type->ba_req_cnt++;
		break;
	case BLK_ACK:
		wlpkt_type->ba_cnt++;
		break;
	case PS_POLL:
		wlpkt_type->ps_poll_cnt++;
		break;
	case RTS:
		wlpkt_type->rts_cnt++;
		break;
	case CTS:
		wlpkt_type->cts_cnt++;
		break;
	case ACK:
		wlpkt_type->ack_cnt++;
		break;
	case CF_END:
		wlpkt_type->cf_end_cnt++;
		break;
	case CF_END_CF_ACK:
		wlpkt_type->cf_end_cf_ackt_cnt++;
		break;
	}
	return;
}

/*
	Save the data counter by different protocol
*/
void
wl_get_datpkt_prot(struct pkttype_info *wlpkt_type, U16 llc_type,
		   struct iphdr *iph)
{
	if (llc_type == 0x0008) {	//IPv4 pkt
		switch (iph->protocol) {
		case IPPROTO_UDP:
			wlpkt_type->udp_cnt++;
			break;
		case IPPROTO_TCP:
			wlpkt_type->tcp_cnt++;
			break;
		case IPPROTO_ICMP:
			wlpkt_type->icmp_cnt++;
			break;
		}
	} else if (llc_type == 0x0608) {	//ARP pkt
		wlpkt_type->arp_cnt++;
	} else if (llc_type == 0x8e88) {	//EAP
		wlpkt_type->eap_cnt++;
	} else {
		wlpkt_type->nipv4_cnt++;
	}
	return;
}

void
wl_pkttype_stat(struct pkttype_info *wlpkt_type, IEEEtypes_FrameCtl_t * fc)
{
	switch (fc->Type) {
	case IEEE_TYPE_DATA:
		wlpkt_type->data_cnt++;
		break;
	case IEEE_TYPE_MANAGEMENT:
		wlpkt_type->mgmt_cnt++;
		wl_mpkt_subtype(wlpkt_type, fc);
		break;
	case IEEE_TYPE_CONTROL:
		wlpkt_type->ctrl_cnt++;
		wl_cpkt_subtype(wlpkt_type, fc);
		break;
	}
	return;
}

void
pkt_statistics(struct net_device *netdev, int rxQid, struct sk_buff *skb_c)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	struct pkttype_info *wlpkt_typecnt_p = &wlpd_p->rpkt_type_cnt;

	if ((rxQid == SC5_RXQ_PROMISCUOUS_INDEX) ||
	    (rxQid == SC5_RXQ_MGMT_INDEX)) {
		mrvl_hdr_t *pmrvl = (mrvl_hdr_t *) skb_c->data;

		wl_pkttype_stat(wlpkt_typecnt_p, &pmrvl->FrmCtl);

		if (pmrvl->FrmCtl.Type == IEEE_TYPE_DATA) {
			wlpptr->wlpd_p->proms_data_cnt++;
			wl_get_datpkt_prot(wlpkt_typecnt_p,
					   ((llc_snap_hdr_t *) (&skb_c->
								data[sizeof
								     (mrvl_hdr_t)
								     +
								     ETHER_HDR_LEN]))->
					   Type,
					   (struct iphdr *)&skb_c->
					   data[sizeof(mrvl_hdr_t) +
						ETHER_HDR_LEN +
						sizeof(llc_snap_hdr_t)]);
		} else if (pmrvl->FrmCtl.Type == IEEE_TYPE_MANAGEMENT) {
			if (rxQid == SC5_RXQ_PROMISCUOUS_INDEX)
				wlpptr->wlpd_p->proms_mgmt_cnt++;
		} else if (pmrvl->FrmCtl.Type == IEEE_TYPE_CONTROL) {
			wlpptr->wlpd_p->proms_ctrl_cnt++;
		}
	} else {
		IEEEtypes_FrameCtl_t FrmCtl;
		FrmCtl.Type = IEEE_TYPE_DATA;
		wl_pkttype_stat(wlpkt_typecnt_p, &FrmCtl);
		wl_get_datpkt_prot(wlpkt_typecnt_p,
				   ((llc_snap_hdr_t *) (&skb_c->
							data[ETHER_HDR_LEN]))->
				   Type,
				   (struct iphdr *)&skb_c->data[ETHER_HDR_LEN +
								sizeof
								(llc_snap_hdr_t)]);
	}

	return;
}

u32
mrvl_hdr_2_80211_hdr_promisc(wlrxdesc_t * cfh_ul, struct sk_buff * skb_c)
{
	u32 offset = 0;
	//remove mrvl header for promiscusou mode
	mrvl_hdr_t *pmrvl = (mrvl_hdr_t *) skb_c->data;

	if (pmrvl->FrmCtl.Type == IEEE_TYPE_DATA) {
		//Data Frames, using ether frame format
		if ((pmrvl->FrmCtl.Subtype == QoS_DATA) ||
		    (pmrvl->FrmCtl.Subtype == QoS_NULL_DATA)) {
			if (pmrvl->FrmCtl.FromDs && pmrvl->FrmCtl.ToDs) {
				//remove HTC
				IEEEtypes_Promiscuous_WDS_QoSHdr_t *pHdr;
				skb_c->data +=
					sizeof(mrvl_hdr_t) -
					sizeof
					(IEEEtypes_Promiscuous_WDS_QoSHdr_t);
				pHdr = (IEEEtypes_Promiscuous_WDS_QoSHdr_t *)
					skb_c->data;

				memmove(&pHdr->FrmCtl, &pmrvl->FrmCtl,
					sizeof
					(IEEEtypes_Promiscuous_WDS_QoSHdr_t) -
					sizeof(((IEEEtypes_Promiscuous_WDS_QoSHdr_t *) 0)->FrmBodyLen));
				offset +=
					sizeof(mrvl_hdr_t) -
					sizeof
					(IEEEtypes_Promiscuous_WDS_QoSHdr_t);
			} else {
				//remove addr4, HTC
				IEEEtypes_Promiscuous_QoSHdr_t *pHdr;
				skb_c->data +=
					sizeof(mrvl_hdr_t) -
					sizeof(IEEEtypes_Promiscuous_QoSHdr_t);
				pHdr = (IEEEtypes_Promiscuous_QoSHdr_t *)
					skb_c->data;

				pHdr->QosControl = pmrvl->QoS;
				memmove(&pHdr->FrmCtl, &pmrvl->FrmCtl,
					sizeof
					(IEEEtypes_Promiscuous_None_QoSHdr_t) -
					sizeof(((IEEEtypes_Promiscuous_None_QoSHdr_t *) 0)->FrmBodyLen));
				offset +=
					sizeof(mrvl_hdr_t) -
					sizeof(IEEEtypes_Promiscuous_QoSHdr_t);
			}
		} else if (pmrvl->FrmCtl.FromDs && pmrvl->FrmCtl.ToDs) {
			//remove QoS, HTC
			IEEEtypes_GenHdr_t *pHdr;
			skb_c->data +=
				sizeof(mrvl_hdr_t) - sizeof(IEEEtypes_GenHdr_t);
			pHdr = (IEEEtypes_GenHdr_t *) skb_c->data;

			memmove(&pHdr->FrmCtl, &pmrvl->FrmCtl,
				sizeof(IEEEtypes_GenHdr_t) -
				sizeof(((IEEEtypes_GenHdr_t *) 0)->FrmBodyLen));
			offset +=
				sizeof(mrvl_hdr_t) - sizeof(IEEEtypes_GenHdr_t);
		} else {
			//remove addr4, QoS, HTC
			IEEEtypes_Promiscuous_None_QoSHdr_t *pHdr;
			skb_c->data +=
				sizeof(mrvl_hdr_t) -
				sizeof(IEEEtypes_Promiscuous_None_QoSHdr_t);
			pHdr = (IEEEtypes_Promiscuous_None_QoSHdr_t *) skb_c->
				data;

			memmove(&pHdr->FrmCtl, &pmrvl->FrmCtl,
				sizeof(IEEEtypes_Promiscuous_None_QoSHdr_t) -
				sizeof(((IEEEtypes_Promiscuous_None_QoSHdr_t *)
					0)->FrmBodyLen));
			offset +=
				sizeof(mrvl_hdr_t) -
				sizeof(IEEEtypes_Promiscuous_None_QoSHdr_t);
		}
	} else if (pmrvl->FrmCtl.Type == IEEE_TYPE_MANAGEMENT) {	//MGMT/CTRL frames, using IEEE frame       type
		/* Keep address 4 only for WDS MGMT frames in promiscuous mode */
		if (pmrvl->FrmCtl.FromDs && pmrvl->FrmCtl.ToDs) {
			//remove QoS, HTC
			IEEEtypes_GenHdr_t *pHdr;
			skb_c->data +=
				sizeof(mrvl_hdr_t) - sizeof(IEEEtypes_GenHdr_t);
			pHdr = (IEEEtypes_GenHdr_t *) skb_c->data;

			memmove(&pHdr->FrmCtl, &pmrvl->FrmCtl,
				sizeof(IEEEtypes_GenHdr_t) -
				sizeof(((IEEEtypes_GenHdr_t *) 0)->FrmBodyLen));
			offset +=
				sizeof(mrvl_hdr_t) - sizeof(IEEEtypes_GenHdr_t);
		} else {
			//remove addr4, QoS, HTC
			IEEEtypes_Promiscuous_None_QoSHdr_t *pHdr;
			skb_c->data +=
				sizeof(mrvl_hdr_t) -
				sizeof(IEEEtypes_Promiscuous_None_QoSHdr_t);
			pHdr = (IEEEtypes_Promiscuous_None_QoSHdr_t *) skb_c->
				data;

			memmove(&pHdr->FrmCtl, &pmrvl->FrmCtl,
				sizeof(IEEEtypes_Promiscuous_None_QoSHdr_t) -
				sizeof(((IEEEtypes_Promiscuous_None_QoSHdr_t *)
					0)->FrmBodyLen));
			offset +=
				sizeof(mrvl_hdr_t) -
				sizeof(IEEEtypes_Promiscuous_None_QoSHdr_t);
		}

		WLDBG_DATA(DBG_LEVEL_2,
			   "CFHUL: Mgmt/Ctrl Frame Type:%xh, Subtype:%xh\n",
			   pmrvl->FrmCtl.Type, pmrvl->FrmCtl.Subtype);
	} else if (pmrvl->FrmCtl.Type == IEEE_TYPE_CONTROL) {
		//remove addr3, seq, addr4, QoS, HTC
		IEEEtypes_CtlHdr_t *pHdr;
		skb_c->data += sizeof(mrvl_hdr_t) - sizeof(IEEEtypes_CtlHdr_t);
		pHdr = (IEEEtypes_CtlHdr_t *) skb_c->data;

		memmove(&pHdr->FrmCtl, &pmrvl->FrmCtl,
			sizeof(IEEEtypes_CtlHdr_t) -
			sizeof(((IEEEtypes_CtlHdr_t *) 0)->FrmBodyLen));
		offset += sizeof(mrvl_hdr_t) - sizeof(IEEEtypes_CtlHdr_t);
	}

	*(UINT16 *) skb_c->data =
		cfh_ul->hdr.length - offset -
		sizeof(((IEEEtypes_GenHdr_t *) 0)->FrmBodyLen);
	skb_c->data += sizeof(((IEEEtypes_GenHdr_t *) 0)->FrmBodyLen);
	offset += sizeof(((IEEEtypes_GenHdr_t *) 0)->FrmBodyLen);

	WLDBG_HEXDUMP(DBG_LEVEL_0, skb_c->data, cfh_ul->hdr.length - offset);

	return offset;
}

u32
mrvl_hdr_2_80211_hdr_mgmt(wlrxdesc_t * cfh_ul, struct sk_buff * skb_c)
{
	u32 offset = 0;
	mrvl_hdr_t *pmrvl = (mrvl_hdr_t *) skb_c->data;

	/* Keep address 4 for MGMT frames in normal mode */
	//remove QoS, HTC
	IEEEtypes_GenHdr_t *pHdr;
	skb_c->data += sizeof(mrvl_hdr_t) - sizeof(IEEEtypes_GenHdr_t);
	pHdr = (IEEEtypes_GenHdr_t *) skb_c->data;

	memmove(&pHdr->FrmCtl, &pmrvl->FrmCtl,
		sizeof(IEEEtypes_GenHdr_t) -
		sizeof(((IEEEtypes_GenHdr_t *) 0)->FrmBodyLen));
	offset += sizeof(mrvl_hdr_t) - sizeof(IEEEtypes_GenHdr_t);
	WLDBG_DATA(DBG_LEVEL_2,
		   "CFHUL: Mgmt/Ctrl Frame Type:%xh, Subtype:%xh\n",
		   pmrvl->FrmCtl.Type, pmrvl->FrmCtl.Subtype);

	*(UINT16 *) skb_c->data =
		cfh_ul->hdr.length - offset -
		sizeof(((IEEEtypes_GenHdr_t *) 0)->FrmBodyLen);
	skb_c->data += sizeof(((IEEEtypes_GenHdr_t *) 0)->FrmBodyLen);
	offset += sizeof(((IEEEtypes_GenHdr_t *) 0)->FrmBodyLen);

	WLDBG_HEXDUMP(DBG_LEVEL_0, skb_c->data, cfh_ul->hdr.length - offset);

	return offset;
}

/* convert cfhUL data buffer to skb data format.
   this function will check whether buffer is used up, if the buffer is used up
   will refill data buffer and move rdinx to next
   assume data payload as follows:
 */
struct sk_buff *
wlCfhUlToSkb(struct net_device *netdev, wlrxdesc_t * cfh_ul, int rxQid)
{
	struct sk_buff *skb, *skb_c;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	struct wldesc_data *wlqm;
	u32 wlqm_id;
	bm_pe_t *pe;
	u8 *skb_addr = NULL;
	u32 offset = 0;

	//wlGetCfhUl() already do the checking. keep here in Z1 stage for memory corrupt checking.
	if ((cfh_ul->hdr.bpid < SC5_BMQ_START_INDEX) ||
	    ((SC5_BMQ_START_INDEX + SC5_BMQ_NUM) <= cfh_ul->hdr.bpid)) {
		// Destroy the lo_dword_addr after used
		cfh_ul->hdr.used_signature = BMBUF_SIGNATURE;
		cfh_ul->hdr.length = USED_BUFLEN;
#ifdef ASSERT_MALBUF
		WLDBG_ERROR(DBG_LEVEL_0, "Invalid bpid: %d\n",
			    cfh_ul->hdr.bpid);
#endif //ASSERT_MALBUF
		wlpd_p->except_cnt.cfhul_bpid_err++;
		return NULL;
	}
	// cfh_ul->hdr.bpid == BQM
	wlqm = &wlpptr->wlpd_p->descData[cfh_ul->hdr.bpid];
	wlqm_id = cfh_ul->hdr.bpid;
	pe = (bm_pe_t *) (wlqm->rq.bm.pe + 0);
	WLDBG_DATA(DBG_LEVEL_3, "CFHUL: BMQ RQ( %d ) rdinx %d \n",
		   cfh_ul->hdr.bpid, wlqm->rq.rdinx);

	WLDBG_DATA(DBG_LEVEL_3, "CFHUL: address_31_0=%x\n",
		   cfh_ul->hdr.lo_dword_addr);
	if (cfh_ul->hdr.lo_dword_addr == 0xffffffff ||
	    cfh_ul->hdr.lo_dword_addr == 0) {
#ifdef ASSERT_MALBUF
		WLDBG_ERROR(DBG_LEVEL_0, "Invalid lo_dword_addr: %xh\n",
			    cfh_ul->hdr.lo_dword_addr);
#endif
		// Destroy the lo_dword_addr after used
		cfh_ul->hdr.used_signature = BMBUF_SIGNATURE;
		cfh_ul->hdr.length = USED_BUFLEN;
		wlpd_p->except_cnt.cfhul_hdr_loaddr_err++;
		return NULL;
	}

	skb_addr = (u8 *) phys_to_virt(cfh_ul->hdr.lo_dword_addr);

	if (cfh_ul->fpkt == 1)
		wlUnmapBuffer(netdev, (u8 *) skb_addr, wlqm->rq.bm.buf_size);

	// Get skb from cfhul
	WLDBG_DATA(DBG_LEVEL_3, "CFHUL: fpkt=%d, cfh_ul=%p\n", cfh_ul->fpkt,
		   cfh_ul);
	// check the rx pkt sequence (fpkt,lpkt)
	wldbg_chkrxpkt_seq(&wlpd_p->except_cnt, cfh_ul);

	if (cfh_ul->fpkt == 1) {	// first packet
		skb_addr = (u8 *) phys_to_virt(cfh_ul->hdr.lo_dword_addr);
		WLDBG_DATA(DBG_LEVEL_3, "CFHUL: skb_addr=%p\n", skb_addr);
		if ((*((u32 *) (skb_addr - SKB_INFO_SIZE)) != SKB_SIGNATURE) ||
		    (*
		     ((u32 *) (skb_addr + wlqm->rq.bm.buf_size +
			       SKB_TAIL_SIGNATURE_OFFSET)) !=
		     SKB_TAIL_SIGNATURE)) {
			skb = NULL;
			// consuming 1 buffer
			wlpd_p->except_cnt.rx_invalid_sig_cnt[wlqm_id -
							      SC5_BMQ_START_INDEX]++;

			if (unlikely((dbg_invalid_skb & dbg_ivalskb_rx))) {
				WLDBG_ERROR(DBG_LEVEL_0,
					    "Invalid signature: qid %u pa %x va %p skb %p sig: head %x tail %x dump cfh_ul:\n",
					    wlqm_id, cfh_ul->hdr.lo_dword_addr,
					    skb_addr,
					    (*(struct sk_buff **)
					     (skb_addr - SKB_POINTER_OFFSET)),
					    (*
					     ((u32 *) (skb_addr -
						       SKB_INFO_SIZE))),
					    (*
					     ((u32 *) (skb_addr +
						       wlqm->rq.bm.buf_size +
						       SKB_TAIL_SIGNATURE_OFFSET))));
				mwl_hex_dump((u8 *) cfh_ul, sizeof(wlrxdesc_t));

				WLDBG_ERROR(DBG_LEVEL_0,
					    "dbgskb: stop all skb tx/rx\n");
				disableSMACTx(netdev);
				disableSMACRx(netdev);

				if (dbg_invalid_skb & dbg_ivalskb_coredump) {
					triggerCoredump(netdev);
				}

				return NULL;
			}
		} else {
			skb = *(struct sk_buff **)(skb_addr -
						   SKB_POINTER_OFFSET);
			if (unlikely(!virt_addr_valid(skb))) {
				wlpd_p->except_cnt.skb_invalid_addr_cnt++;
				if ((dbg_invalid_skb & dbg_ivalskb_rx)) {
					WLDBG_ERROR(DBG_LEVEL_0,
						    "Invalid skb addr %p dump chf_ul\n",
						    skb);
					mwl_hex_dump((u8 *) cfh_ul,
						     sizeof(wlrxdesc_t));
				}
				return NULL;
			}
			// consuming 1 buffer
			//wlpd_p->drv_stats_val.enq_bmqbuf_cnt[wlqm_id - SC5_BMQ_START_INDEX]--;
			wlpd_p->drv_stats_val.bmqbuf_ret_cnt[wlqm_id -
							     SC5_BMQ_START_INDEX]++;
			wl_save_last_rxskb(netdev, cfh_ul, skb);

			if (skb != NULL) {
				if (!skb->next || !skb->prev) {
					wlpd_p->except_cnt.skb_notlinked_cnt++;
					if (unlikely
					    ((dbg_invalid_skb &
					      dbg_ivalskb_rx))) {
						WLDBG_ERROR(DBG_LEVEL_0,
							    "dbgskb: wlCfhUlToSkb qid %d: skb %p not linked. skb_data va %p signature 0x%8x dump skb_data:\n",
							    rxQid, skb,
							    skb->data,
							    *((u32 *) (skb->
								       data -
								       SKB_INFO_SIZE)));
						if (skb->data && skb->len)
							mwl_hex_dump(skb->data,
								     skb->len);
					}
					return NULL;
				}
				spin_lock(&wlpd_p->pend_skb_trace[PENDSKB_RX].
					  lock);
				__skb_unlink(skb,
					     &wlpd_p->
					     pend_skb_trace[PENDSKB_RX]);
				spin_unlock(&wlpd_p->pend_skb_trace[PENDSKB_RX].
					    lock);
			}
		}
		pe->skb = skb;
		if (skb != NULL) {
			reset_signature(skb_addr);
		}

	} else {		// Others
		WLDBG_DATA(DBG_LEVEL_3, "CFHUL: getting pe->skb\n");
		skb = pe->skb;
		if (unlikely(!virt_addr_valid(skb))) {
			wlpd_p->except_cnt.skb_invalid_addr_cnt++;
			if (dbg_invalid_skb & dbg_ivalskb_rx) {
				WLDBG_ERROR(DBG_LEVEL_0,
					    "Invalid skb addr %p dump chf_ul\n",
					    skb);
				mwl_hex_dump((u8 *) cfh_ul, sizeof(wlrxdesc_t));
			}
			return NULL;
		}

		WLDBG_DATA(DBG_LEVEL_3, "skb=%p\n", skb);
	}

	if (skb == NULL) {
#ifdef ASSERT_MALBUF
		WLDBG_ERROR(DBG_LEVEL_1,
			    "CFHUL: without skb, skb_addr:%p  hdr.lo_dword_addr:%x, cfh_ul->hdr.length:%u\n",
			    skb_addr, cfh_ul->hdr.lo_dword_addr,
			    cfh_ul->hdr.length);
#endif
		// Destroy the lo_dword_addr after used
		cfh_ul->hdr.used_signature = BMBUF_SIGNATURE;
		cfh_ul->hdr.length = USED_BUFLEN;
		return NULL;
	}

	WLDBG_DATA(DBG_LEVEL_3, "CFHUL: BMQ skb %p data %p \n", skb, skb->data);

	//wlGetCfhUl() already do the checking. keep here in Z1 stage for memory corrupt checking.
	if (cfh_ul->hdr.length > wlqm->rq.bm.buf_size) {
#ifdef ASSERT_MALBUF
		WLDBG_ERROR(DBG_LEVEL_0,
			    "data size is over-size %d  bpid %d \n",
			    cfh_ul->hdr.length, cfh_ul->hdr.bpid);
		mwl_hex_dump((u8 *) cfh_ul, sizeof(wlrxdesc_t));
#endif
		// Destroy the lo_dword_addr after used
		cfh_ul->hdr.used_signature = BMBUF_SIGNATURE;
		cfh_ul->hdr.length = USED_BUFLEN;
		wlpd_p->except_cnt.cfhul_hdrlen_err++;

		return NULL;
	}

	if (unlikely
	    (!virt_addr_valid(skb_shinfo(skb)) ||
	     !virt_addr_valid(skb->head))) {
		wlpd_p->except_cnt.skb_invalid_addr_cnt++;
		if (dbg_invalid_skb & dbg_ivalskb_rx) {
			WLDBG_ERROR(DBG_LEVEL_0,
				    "Invalid skb addr %p skb->head %p skb_shinfo %p dump chf_ul\n",
				    skb, skb->head, skb_shinfo(skb));
			mwl_hex_dump((u8 *) cfh_ul, sizeof(wlrxdesc_t));
		}
		return NULL;
	}

	skb_c = skb_clone(skb, GFP_ATOMIC);
	if (cfh_ul->fpkt == 1) {	// first packet
		// adjust skb point
		skb_c->data = (u8 *) phys_to_virt(cfh_ul->hdr.lo_dword_addr);
		WLDBG_DATA(DBG_LEVEL_3,
			   "CFHUL: [RxBufFetch] first skb_c->data %p , address_31_0 = %xh \n",
			   skb_c->data, cfh_ul->hdr.lo_dword_addr);
		if (skb_c->data != skb->data) {
			WLDBG_ERROR(DBG_LEVEL_0,
				    "1st pkt, (skb->data, skb_c->data)=(%p, %p)\n",
				    skb->data, skb_c->data);
		}
	} else {
		//skb_c->data = (void *)(pe_hw->pe1_0_31 + (cfh_ul->hdr.address_31_0 - addr_start));
		skb_c->data = (u8 *) phys_to_virt(cfh_ul->hdr.lo_dword_addr);
		WLDBG_DATA(DBG_LEVEL_3, "CFHUL: skb_c %p  \n", skb_c->data);
	}

	skb_reset_tail_pointer(skb_c);

	wldbg_aggr_stat(&wlpd_p->drv_stats_val, cfh_ul);

	pkt_statistics(netdev, rxQid, skb_c);
	if (rxQid == SC5_RXQ_START_INDEX) {
		skb_c->protocol |= WL_WLAN_TYPE_RX_FAST_DATA;
	} else if (rxQid == SC5_RXQ_MGMT_INDEX) {
		offset = mrvl_hdr_2_80211_hdr_mgmt(cfh_ul, skb_c);
	} else {
		// rxQid == SC5_RXQ_PROMISCUOUS_INDEX
		offset = mrvl_hdr_2_80211_hdr_promisc(cfh_ul, skb_c);
	}

	{
		// Make sure the skb_c->data is valid
		if ((skb_c->data - skb->data) >
		    buf_pool_size[cfh_ul->hdr.bpid - SC5_BMQ_START_INDEX]) {
			/*
			   // ToDo: Enable the message whenever needs to debug 
			   WLDBG_ERROR(DBG_LEVEL_0, "CFHUL: out_of_range (skb->data, skb_c->data, cfh_ul->hdr.length) = (%p, %p, %d)\n",
			   skb->data, skb_c->data, cfh_ul->hdr.length);
			   mwl_hex_dump(cfh_ul, sizeof(wlrxdesc_t));
			   WLDBG_ERROR(DBG_LEVEL_0, "Severe ERROR: cfh_ul->(fpkt lpkt): (%u, %u), skb_c->len=%u, skb->len=%u\n",
			   cfh_ul->fpkt, cfh_ul->lpkt, skb_c->len, skb->len);
			 */
			// Destroy the lo_dword_addr after used
			cfh_ul->hdr.used_signature = BMBUF_SIGNATURE;
			cfh_ul->hdr.length = USED_BUFLEN;
			wlpd_p->except_cnt.cfhul_buf_map_err++;
			return NULL;
		}
	}

	if (skb_c->head > skb_c->data) {	//Invalid skb structure => 
#ifndef SKB_OVER_PANIC_DBG	//"SKB_OVER_PANIC_DBG" needs to define to debug this problem
		// Destroy the lo_dword_addr after used
		cfh_ul->hdr.used_signature = BMBUF_SIGNATURE;
		cfh_ul->hdr.length = USED_BUFLEN;
		wlpd_p->except_cnt.skb_hddat_err++;
		return NULL;
#endif //SKB_OVER_PANIC_DBG
	}

	if (skb_c->tail + (cfh_ul->hdr.length - offset) > skb_c->end) {
		wlpd_p->except_cnt.skb_overpanic_cnt++;
		return NULL;
	} else {
		if (unlikely(skb_c->data_len)) {
			if (dbg_invalid_skb & dbg_ivalskb_rx) {
				WLDBG_ERROR(DBG_LEVEL_0,
					    "skb is nonlinear %p skb->data_len %u \n",
					    skb_c, skb_c->data_len);
			}
			wlpd_p->except_cnt.skb_nonlinear_cnt++;
			wl_free_skb(skb_c);
			return NULL;
		} else
			skb_put(skb_c, (cfh_ul->hdr.length - offset));
	}
	WLDBG_DATA(DBG_LEVEL_3, "CFHUL: Skb data length  %d  ", skb_c->len);

	if ((rxQid == SC5_RXQ_START_INDEX) &&
	    (*(u16 *) & skb_c->data[14] != 0xaaaa) &&
	    (*(u16 *) & skb_c->data[14] == *(u16 *) & skb_c->data[6])) {
		wlpd_p->except_cnt.cnt_invalid_mpdu_frames++;
	}

	if (cfh_ul->lpkt == 1) {	// free bit is on, last packet
		WLDBG_DATA(DBG_LEVEL_3,
			   "CFHUL: [RxDropBuf] last data  %p  len %d \n",
			   skb->data, skb_c->len);

		//wlqm->rq.rdinx = wlQueryRdPtr(netdev, wlqm_id, SC5_RQ);
		rpkt_reuse_push(&wlqm->rq.skbTrace, skb);
		wl_clr_last_rxskb(netdev, (wlqm_id - SC5_BMQ_START_INDEX));
		pe->skb = NULL;
	}

	return skb_c;
}

/*
        Show the rx statistics data/counter
 */
static void
wl_show_rx_stats(struct net_device *netdev, char *sysfs_buff)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	int qid, i;

	Sysfs_Printk("[Driver Rx statistics info]\n");
	Sysfs_Printk("rxq_intr_cnt:\n");

	for (qid = SC5_RXQ_START_INDEX;
	     qid < (SC5_RXQ_START_INDEX + SC5_RXQ_NUM); qid++) {
		if (((1 << qid) & SC5_RXQ_MASK) == 0) {	// Not enabled
			continue;
		}

		Sysfs_Printk("Q[%d]= %u, ", qid,
			     wlpd_p->drv_stats_val.rxq_intr_cnt[qid]);

		if (!((qid + 1) % 5))
			Sysfs_Printk("\n");
	}

	if (qid % 5)
		Sysfs_Printk("\n");

	Sysfs_Printk("rxq_rcv_cnt:\n");
	for (qid = SC5_RXQ_START_INDEX;
	     qid < (SC5_RXQ_START_INDEX + SC5_RXQ_NUM); qid++) {
		if (((1 << qid) & SC5_RXQ_MASK) == 0) {	// Not enabled
			continue;
		}

		Sysfs_Printk("Q[%d]= %u, ", qid,
			     wlpd_p->drv_stats_val.rxq_rcv_cnt[qid]);

		if (!((qid + 1) % 5))
			Sysfs_Printk("\n");
	}

	if (qid % 5)
		Sysfs_Printk("\n");

	Sysfs_Printk("rxq_drop_cnt:\n");
	for (qid = SC5_BMQ_START_INDEX; qid < SC5_BMQ_START_INDEX + SC5_BMQ_NUM;
	     qid++) {
		Sysfs_Printk("Q[%d] = %d, ", qid,
			     wlpd_p->drv_stats_val.rx_drop_cnt[qid -
							       SC5_BMQ_START_INDEX]);

		if (!((qid + 1) % 5))
			Sysfs_Printk("\n");
	}

	if (qid % 5)
		Sysfs_Printk("\n");

	Sysfs_Printk("aggr_statistics: (>0) \n");
	for (qid = SC5_BMQ_START_INDEX;
	     qid < SC5_BMQ_START_INDEX + SC5_BMQ_NUM - 1; qid++) {
		for (i = 0; i < AGGRCNT_ARYSIZE; i++) {
			if (wlpd_p->drv_stats_val.
			    rxq_aggrcnt[qid - SC5_BMQ_START_INDEX][i] == 0) {
				continue;
			}
			Sysfs_Printk("Q[%d], %d pkts %d times ", qid, i + 2,
				     wlpd_p->drv_stats_val.rxq_aggrcnt[qid -
								       SC5_BMQ_START_INDEX]
				     [i]);

			if (!((i + 1) % 3))
				Sysfs_Printk("\n");
		}
		if (i % 3)
			Sysfs_Printk("\n");
	}

	Sysfs_Printk("pn check data passed count: ucast=%d, mcast=%d\n",
		     wlpd_p->drv_stats_val.rx_data_ucast_pn_pass_cnt,
		     wlpd_p->drv_stats_val.rx_data_mcast_pn_pass_cnt);
	Sysfs_Printk("pn check mgmt passed count: ucast=%d, mcast=%d\n\n",
		     wlpd_p->drv_stats_val.rx_mgmt_ucast_pn_pass_cnt,
		     wlpd_p->drv_stats_val.rx_mgmt_mcast_pn_pass_cnt);

	Sysfs_Printk("promiscuous data frame count: %d\n",
		     wlpd_p->proms_data_cnt);
	Sysfs_Printk("promiscuous management frame count: %d\n",
		     wlpd_p->proms_mgmt_cnt);
	Sysfs_Printk("promiscuous control frame count: %d\n",
		     wlpd_p->proms_ctrl_cnt);

	return;
}

/*
        Show the tx scheduler data/counter
 */
static void
wl_show_scheduleinfo(struct net_device *netdev, int level, char *sysfs_buff)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	UINT32 fwDbgStateAddr;
	UINT32 *addr_val = wl_kmalloc(64 * sizeof(UINT32), GFP_KERNEL);

	wlFwGetQueueStats(netdev, QS_GET_TX_SCHEDULER_INFO, 0, sysfs_buff);

	if (level == 0 && (addr_val != NULL)) {
		fwDbgStateAddr = wl_util_readl(netdev, wlpptr->ioBase1 + wlpptr->wlpd_p->reg.FwDbgStateAddr);

		wlFwGetAddrValue(netdev, (fwDbgStateAddr + 0x134), 1, addr_val,
				 0);
		Sysfs_Printk("schedulercount  : 0x%X\n", addr_val[0]);
		wlFwGetAddrValue(netdev, (fwDbgStateAddr + 0x138), 1, addr_val,
				 0);
		Sysfs_Printk("schedulercount1 : 0x%X\n", addr_val[0]);
		wlFwGetAddrValue(netdev, (fwDbgStateAddr + 0x13C), 1, addr_val,
				 0);
		Sysfs_Printk("schedulercount2 : 0x%X\n", addr_val[0]);
		wlFwGetAddrValue(netdev, (fwDbgStateAddr + 0x140), 1, addr_val,
				 0);
		Sysfs_Printk("schedulercount3 : 0x%X\n", addr_val[0]);
		wlFwGetAddrValue(netdev, (fwDbgStateAddr + 0x144), 1, addr_val,
				 0);
		Sysfs_Printk("schedulercount4 : 0x%X\n", addr_val[0]);
		wlFwGetAddrValue(netdev, (fwDbgStateAddr + 0x148), 1, addr_val,
				 0);
		Sysfs_Printk("schedulercount5 : 0x%X\n", addr_val[0]);
		wlFwGetAddrValue(netdev, (fwDbgStateAddr + 0x14C), 1, addr_val,
				 0);
		Sysfs_Printk("schedulercount6 : 0x%X\n", addr_val[0]);
		wlFwGetAddrValue(netdev, (fwDbgStateAddr + 0x17C), 1, addr_val,
				 0);
		Sysfs_Printk("schedulercount7 : 0x%X\n", (addr_val[0] >> 16));
	}
	if (addr_val != NULL)
		wl_kfree(addr_val);
}

#ifdef TP_PROFILE
static void
wl_show_tx_profile(struct net_device *netdev, int level, char *sysfs_buff)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;

	calculateTpStats(&wlpd_p->drv_stats_val.cfhdltx_stat, level,
			 sysfs_buff);
}
#endif

/*
	Show the SMAC status:
		- pSMACStatus 
			NULL => Get the SMAC status & dump the messages
			valid addr => Just dump the messages
*/
static void
wl_show_generic_info(struct net_device *netdev, char *sysfs_buff)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	struct drv_stats *wldrvstat_p = &wlpd_p->drv_stats_val;
	SMAC_STATUS_st smacStatus;
	SMAC_STATUS_st *pSMACStatus = &smacStatus;
	extern UINT32 rx_r7_intr[6];
	int i;
	unsigned int reg_evt_rdptr = wlpd_p->reg.evt_rdptr;
	unsigned int reg_evt_wrptr = wlpd_p->reg.evt_wrptr;
	
	wl_util_lock(netdev);
	memcpy(pSMACStatus, wlpptr->smacStatusAddr, sizeof(SMAC_STATUS_st));
	wl_util_unlock(netdev);
	Sysfs_Printk("Drv_Info:\n");
	Sysfs_Printk("\t rx_count        = %lu\n",
		     wlpptr->netDevStats.rx_packets);
	Sysfs_Printk("\t buffer_full_cnt = %u\n",
		     wlpd_p->drv_stats_val.txq_full_cnt);
	Sysfs_Printk("\t sent_cnt        = %u\n",
		     wlpd_p->drv_stats_val.txq_drv_sent_cnt);
	Sysfs_Printk("\t tx_pend_list    = %u\n",
		     skb_queue_len(&wlpd_p->pend_skb_trace[PENDSKB_TX]));
	Sysfs_Printk("\t rx_pend_list    = %u\n",
		     skb_queue_len(&wlpd_p->pend_skb_trace[PENDSKB_RX]));

	for (i = SC5_BMQ_START_INDEX;
	     i < (SC5_BMQ_START_INDEX + SC5_BMQ_NUM - 1); i++) {
		struct wldesc_data *wlqm = &wlpptr->wlpd_p->descData[i];
		Sysfs_Printk("\t BMQ[%d] recycle len: %u\n", i,
			     skb_queue_len(&wlqm->rq.skbTrace));
	}

	Sysfs_Printk("========[BMQ buffer push_cnt]========\n");
	for (i = SC5_BMQ_START_INDEX; i < SC5_BMQ_START_INDEX + SC5_BMQ_NUM;
	     i++) {
		int offset = i - SC5_BMQ_START_INDEX;
		Sysfs_Printk("\t Q[%d] = %d, (eq=%d, drop=%d, ret=%d)\n", i,
			     (wldrvstat_p->enq_bmqbuf_cnt[offset] -
			      wldrvstat_p->xx_buf_free_SQ14[offset] -
			      wldrvstat_p->bmqbuf_ret_cnt[offset]),
			     wldrvstat_p->enq_bmqbuf_cnt[offset],
			     wldrvstat_p->xx_buf_free_SQ14[offset],
			     wldrvstat_p->bmqbuf_ret_cnt[offset]);
	}
	Sysfs_Printk("\n");
	Sysfs_Printk("EventQ\t\tRD ptr\t\tWR ptr\n");
	Sysfs_Printk(" \t\t%08x\t%08x\n",
		     wl_util_readl(netdev, wlpptr->ioBase1 + reg_evt_rdptr),
		     wl_util_readl(netdev, wlpptr->ioBase1 + reg_evt_wrptr));

	Sysfs_Printk("R7 interrupt#\n");
	for (i = 0; i < 4; i++) {
		Sysfs_Printk("%d\t\t%08x\n", i, rx_r7_intr[i]);
	}

	Sysfs_Printk("\n");
	Sysfs_Printk("txq_drv_release_cnt = %d - %d - %d - %d\n",
		     wlpd_p->drv_stats_val.txq_drv_release_cnt[0],
		     wlpd_p->drv_stats_val.txq_drv_release_cnt[1],
		     wlpd_p->drv_stats_val.txq_drv_release_cnt[2],
		     wlpd_p->drv_stats_val.txq_drv_release_cnt[3]);
#ifdef DUPLICATED_MGMT_DBG
	Sysfs_Printk("RX re-transmitted MGMT packet count = %d\n",
		     wlpptr->rx_retry_mgmt_cnt);
#endif

	Sysfs_Printk
		("AMSDU subframe typecnt (fpkt,mpkt,lpkt,single-msdu):%u,%u,%u,%u\n",
		 wlpd_p->drv_stats_val.amsdu_frag[0],
		 wlpd_p->drv_stats_val.amsdu_frag[1],
		 wlpd_p->drv_stats_val.amsdu_frag[2],
		 wlpd_p->drv_stats_val.amsdu_frag[3]);

	Sysfs_Printk("Dropped BAR: %u\n", wlpd_p->drv_stats_val.drop_bar);
	Sysfs_Printk("StaDB Query Cnt: %u\n",
		     wlpd_p->drv_stats_val.rxinfo_stadb_query_cnt);

	Sysfs_Printk("==========================\n");
	Sysfs_Printk("MAC STATUS:\n");
	Sysfs_Printk("\t sop_EvtMacHdr = %u\n", pSMACStatus->sop_EvtMacHdr);
	Sysfs_Printk("\t eop_EvtEuDone = %u\n", pSMACStatus->eop_EvtEuDone);
	Sysfs_Printk("\t eop2_Q2RxAmsdu     = %u\n",
		     pSMACStatus->eop2_Q2RxAmsdu);
	Sysfs_Printk("--------------------------\n");
	Sysfs_Printk("\t txInputCnt    = %u\n", pSMACStatus->txInputCnt);
	Sysfs_Printk("\t txSchedCnt    = %u\n", pSMACStatus->txSchedCnt);
	Sysfs_Printk("\t txBufRetCnt   = %u\n", pSMACStatus->txBufRetCnt);
	Sysfs_Printk("\t txEuDoneCnt   = %u\n", pSMACStatus->txEuDoneCnt);
	Sysfs_Printk("\t txMgmPktCnt   = %u\n", pSMACStatus->txMgmPktCnt);
	Sysfs_Printk("\t txProcCnt     = %u\n", pSMACStatus->txProcCnt);
	Sysfs_Printk("\t txBcnCnt     = %u\n", pSMACStatus->txBcnCnt);

#if 0
	if (sysfs_buff != NULL) {
		printk("len:%d\n", (int)strlen(sysfs_buff));
	}
#endif

	return;
}

static void
wl_show_hframe_info(struct net_device *netdev, char *sysfs_buff)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	struct bqm_args *pbqm_args = &wlpd_p->bmq_args;
	int qid;

	Sysfs_Printk("BMQ#\t\tRD ptr\t\tWR ptr\n");
	for (qid = SC5_BMQ_START_INDEX;
	     qid < (SC5_BMQ_START_INDEX + SC5_BMQ_NUM); qid++) {
		Sysfs_Printk("%d\t\t%08x\t%08x\n", qid,
			     wlQueryRdPtr(netdev, qid, SC5_RQ),
			     wlQueryWrPtr(netdev, qid, SC5_RQ));
	}
	Sysfs_Printk("\n");
	Sysfs_Printk("RxQ#\t\tRD ptr\t\tWR ptr\n");
	for (qid = SC5_RXQ_START_INDEX;
	     qid < (SC5_RXQ_START_INDEX + SC5_RXQ_NUM); qid++) {
		if (((1 << qid) & SC5_RXQ_MASK) == 0) {	// Not enabled
			continue;
		}
		Sysfs_Printk("%d\t\t%08x\t%08x\n", qid,
			     wlQueryRdPtr(netdev, qid, SC5_SQ),
			     wlQueryWrPtr(netdev, qid, SC5_SQ));
	}
	Sysfs_Printk("\n");
	Sysfs_Printk("TxQ#\t\tRD ptr\t\tWR ptr\n");
	for (qid = pbqm_args->txq_start_index;
	     qid < (pbqm_args->txq_start_index + pbqm_args->txq_num); qid++) {
		Sysfs_Printk("%d\t\t%08x\t%08x\n", qid,
			     wlQueryRdPtr(netdev, qid, SC5_RQ),
			     wlQueryWrPtr(netdev, qid, SC5_RQ));
	}
	Sysfs_Printk("\n");
	Sysfs_Printk("ReleaseQ#\tRD ptr\t\tWR ptr\n");
	for (qid = pbqm_args->bmq_release_index;
	     qid < (pbqm_args->bmq_release_index + pbqm_args->bmq_release_num);
	     qid++) {
		Sysfs_Printk("%d\t\t%08x\t%08x\n", qid,
			     wlQueryRdPtr(netdev, qid, SC5_SQ),
			     wlQueryWrPtr(netdev, qid, SC5_SQ));
	}
	Sysfs_Printk("\n");
	Sysfs_Printk("BuffPoll#\tRD ptr\t\tWR ptr\n");
	for (qid = SC5_BMQ_START_INDEX; qid < SC5_BMQ_START_INDEX + SC5_BMQ_NUM;
	     qid++) {
		Sysfs_Printk("%d\t\t%08x\t%08x\n", qid,
			     wlQueryRdPtr(netdev, qid, SC5_RQ),
			     wlQueryWrPtr(netdev, qid, SC5_RQ));
	}
	Sysfs_Printk("\n");
#if defined(ACNT_REC)
	Sysfs_Printk("RAccnt#\tRD ptr\t\tWR ptr\n");
	for (qid = pbqm_args->racntq_index;
	     qid < (pbqm_args->racntq_index + pbqm_args->racntq_num); qid++) {
		Sysfs_Printk("%d\t\t%08x\t%08x\n", qid,
			     wlQueryRdPtr(netdev, qid, SC5_SQ),
			     wlQueryWrPtr(netdev, qid, SC5_SQ));
	}
	Sysfs_Printk("\n");
#endif //#if defined(ACNT_REC)

	return;
}

void
wl_show_pfw_alive_counts(struct net_device *netdev, char *sysfs_buff)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	//struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	UINT32 newcnt[3];
	void *pfwdbgstate;
	UINT32 dmemaddr = 0;

	if (IS_BUS_TYPE_MCI(wlpptr)) {	//MOCHI 

		dmemaddr = wl_util_readl(netdev, wlpptr->ioBase1 + wlpptr->wlpd_p->reg.FwDbgStateAddr) - SMAC_DMEM_START;

		//check valid range 
		if (dmemaddr > DMEM_SIZE_SC5_SCBT_A0)
			goto err_exit;

		pfwdbgstate = (void *)(wlpptr->ioBase0 + dmemaddr);
		memcpy((void *)newcnt,
		       (void *)(pfwdbgstate + PFW_ALIVE_CNT_OFFSET),
		       sizeof(newcnt));
	} else {		//PCIE interface
		u8 *pbuf = NULL;

#define DMEM_DEBUG_START_OFFSET 0x123800
		if ((pbuf = (u8 *) wl_kmalloc(1024, GFP_KERNEL))) {

			if (!wlFwGetAddrValue
			    (netdev,
			     (SMAC_DMEM_START + DMEM_DEBUG_START_OFFSET), 64,
			     (u32 *) pbuf, 0)) {
				memcpy((void *)newcnt,
				       (void *)(pbuf + PFW_ALIVE_CNT_OFFSET),
				       sizeof(newcnt));
			} else {
				wl_kfree(pbuf);
				goto err_exit;
			}

			wl_kfree(pbuf);
		} else
			goto err_exit;
	}

	//supposedly there are 4 alives counters in PFW. Check PFW. upd_thread_alive did not use so far. 
	//so temporary ignore this count.
	Sysfs_Printk("\t ----------------------------\n");
	Sysfs_Printk("\t [PFW] cmd_thread_alive         = %u\n", newcnt[0]);
	Sysfs_Printk("\t [PFW] sche_thread_alive        = %u\n", newcnt[1]);
	Sysfs_Printk("\t [PFW] idle_thread_alive        = %u\n", newcnt[2]);

	return;
err_exit:
	if (IS_BUS_TYPE_MCI(wlpptr)) {
		Sysfs_Printk("%s(), Invalid FwDbgStateAddr, %u\n", __func__,
			     (dmemaddr + SMAC_DMEM_START));
	} else {
		Sysfs_Printk("%s(), Fail to access pfw alive counters...\n",
			     __func__);
	}
	return;
}

void
wl_show_smac_stat(struct net_device *netdev, SMAC_STATUS_st * pSMACStatus,
		  char *sysfs_buff)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	SMAC_STATUS_st smacStatus;
	UINT32 i, k;

	if (pSMACStatus == NULL) {
		// Get the SMAC status now
		pSMACStatus = &smacStatus;
		wl_util_lock(netdev);
		memcpy(pSMACStatus, wlpptr->smacStatusAddr,
		       sizeof(SMAC_STATUS_st));
		wl_util_unlock(netdev);
	}

	Sysfs_Printk("==========================\n");
	Sysfs_Printk("MAC STATUS:\n");

	Sysfs_Printk
		(" 0x420: txInputCnt %u\ttxSchedCnt %u\ttxProcCnt %u\ttxBufRetCnt %u\n",
		 pSMACStatus->txInputCnt, pSMACStatus->txSchedCnt,
		 pSMACStatus->txProcCnt, pSMACStatus->txBufRetCnt);

	Sysfs_Printk
		(" 0x430: txAcRingCnt %u\ttxCtlFrmCnt %u\ttxEuDoneCnt %u\ttxRdyDeassert %u\n",
		 pSMACStatus->txAcRingCnt, pSMACStatus->txCtlFrmCnt,
		 pSMACStatus->txEuDoneCnt, pSMACStatus->txRdyDeassert);

	Sysfs_Printk
		(" 0x440: sop_EvtMacHdr %u\teop_EvtEuDone %u\tfcs_EvtFcs %u\teop2_Q2RxAmsdu %u\n",
		 pSMACStatus->sop_EvtMacHdr, pSMACStatus->eop_EvtEuDone,
		 pSMACStatus->fcs_EvtFcs, pSMACStatus->eop2_Q2RxAmsdu);

	Sysfs_Printk
		(" 0x450: sop_EuPrgm %u\teopDrp_EuErr %u\tfcsDrp_FcsErr %u\teop2Drp_Cnt %u\n",
		 pSMACStatus->sop_EuPrgm, pSMACStatus->eopDrp_EuErr,
		 pSMACStatus->fcsDrp_FcsErr, pSMACStatus->eop2Drp_Cnt);

	Sysfs_Printk
		(" 0x460: uniPktCnt %u\tmultiPktCnt %u\tbman_GetBuf %u\tbman_RetBuf %u\n",
		 pSMACStatus->fcs_UniMCast[0], pSMACStatus->fcs_UniMCast[1],
		 pSMACStatus->bman_GetBuf, pSMACStatus->bman_RetBuf);

	Sysfs_Printk
		(" 0x470: slotTickCnt %u\tfirstSlotTickCnt %u\ttxMgmPktCnt %u\ttxBcnCnt %u\n",
		 pSMACStatus->slotTickCnt, pSMACStatus->firstSlotTickCnt,
		 pSMACStatus->txMgmPktCnt, pSMACStatus->txBcnCnt);

	Sysfs_Printk(" 0x480: debug log1:\n");
	for (i = 0, k = 0; i < 1; i++, k += 4) {
		Sysfs_Printk("%08x: %08x %08x %08x %08x\n", (i * 16),
			     pSMACStatus->sysRsvd1[k],
			     pSMACStatus->sysRsvd1[k + 1],
			     pSMACStatus->sysRsvd1[k + 2],
			     pSMACStatus->sysRsvd1[k + 3]);
	}

	Sysfs_Printk(" 0x490: TXD1 counts:\n");
	for (i = 0, k = 0; i < 1; i++, k += 4) {
		Sysfs_Printk("%08x: %08x %08x %08x %08x\n", (i * 16),
			     pSMACStatus->sysRsvd2[k],
			     pSMACStatus->sysRsvd2[k + 1],
			     pSMACStatus->sysRsvd2[k + 2],
			     pSMACStatus->sysRsvd2[k + 3]);
	}

	Sysfs_Printk(" 0x4a0: PGM %u, DONE %u, MSDU %u, MPDU %u\n",
		     pSMACStatus->sysRsvd3[0], pSMACStatus->sysRsvd3[1],
		     pSMACStatus->sysRsvd3[2], pSMACStatus->sysRsvd3[3]);

	Sysfs_Printk(" 0x4b0: TXD5 counts:\n");
	for (i = 0, k = 0; i < 1; i++, k += 4) {
		Sysfs_Printk("%08x: %08x %08x %08x %08x\n", (i * 16),
			     pSMACStatus->sysRsvd4[k],
			     pSMACStatus->sysRsvd4[k + 1],
			     pSMACStatus->sysRsvd4[k + 2],
			     pSMACStatus->sysRsvd4[k + 3]);
	}

	Sysfs_Printk(" 0x4c0: debug log2:\n");
	for (i = 0, k = 0; i < 1; i++, k += 4) {
		Sysfs_Printk("%08x: %08x %08x %08x %08x\n", (i * 16),
			     pSMACStatus->sysRsvd5[k],
			     pSMACStatus->sysRsvd5[k + 1],
			     pSMACStatus->sysRsvd5[k + 2],
			     pSMACStatus->sysRsvd5[k + 3]);
	}
	//mwl_hex_dump_to_sysfs(pSMACStatus->sysRsvd5, 16, sysfs_buff);

	Sysfs_Printk(" 0x4d0: sysRsvd6:\n");
	for (i = 0, k = 0; i < 3; i++, k += 4) {
		Sysfs_Printk("%08x: %08x %08x %08x %08x\n", (i * 16),
			     pSMACStatus->sysRsvd6[k],
			     pSMACStatus->sysRsvd6[k + 1],
			     pSMACStatus->sysRsvd6[k + 2],
			     pSMACStatus->sysRsvd6[k + 3]);
	}

	Sysfs_Printk(" 0x500: MAC status:\n");
	for (i = 0, k = 0; i < 3; i++, k += 4) {
		Sysfs_Printk("%08x: %08x %08x %08x %08x\n", (i * 16),
			     pSMACStatus->smacSts[k],
			     pSMACStatus->smacSts[k + 1],
			     pSMACStatus->smacSts[k + 2],
			     pSMACStatus->smacSts[k + 3]);
	}
	Sysfs_Printk("%08x: %08x %08x %08x %08x\n", (i * 16),
		     pSMACStatus->sysRsvd7[0], pSMACStatus->sysRsvd7[1],
		     pSMACStatus->txAcntNoADMA, pSMACStatus->rxAcntNoADMA);

	Sysfs_Printk
		(" 0x540: sopDrp_GiantPkt %u, txStopAck %u, lastTxInfoErr %u, bmanErr_GetBuf %u,%u,%u,%u\n",
		 pSMACStatus->sopDrp_GiantPkt, pSMACStatus->txStopAck,
		 pSMACStatus->lastTxInfoErr, pSMACStatus->bmanErr_GetBuf[0],
		 pSMACStatus->bmanErr_GetBuf[1], pSMACStatus->bmanErr_GetBuf[2],
		 pSMACStatus->bmanErr_GetBuf[3]);

	Sysfs_Printk(" 0x550: eopDrp_EmptyBuf %u\n",
		     pSMACStatus->eopDrp_EmptyBuf);
	Sysfs_Printk
		(" 0x560: txDataTxMsduCnt %u, txDataBufRetMsduCnt %u, txMgtTxMsduCnt %u, txMgtBufRetMsduCnt %u\n",
		 pSMACStatus->txDataTxMsduCnt, pSMACStatus->txDataBufRetMsduCnt,
		 pSMACStatus->txMgtTxMsduCnt, pSMACStatus->txMgtBufRetMsduCnt);

	Sysfs_Printk
		(" 0x570: bman_StsReqBp %u, maxSizeBcnbuf %u, rxSBinfoBaseAddr %xh, rxSBinfoUnitSize %u\n",
		 pSMACStatus->bman_StsReqBp, pSMACStatus->maxSizeBcnbuf,
		 pSMACStatus->rxSBinfoBaseAddr, pSMACStatus->rxSBinfoUnitSize);

	Sysfs_Printk(" 0x580: sysRsvd9:\n");
	for (i = 0, k = 0; i < 4; i++, k += 4) {
		Sysfs_Printk("%08x: %08x %08x %08x %08x\n", (i * 16),
			     pSMACStatus->sysRsvd9[k],
			     pSMACStatus->sysRsvd9[k + 1],
			     pSMACStatus->sysRsvd9[k + 2],
			     pSMACStatus->sysRsvd9[k + 3]);
	}

	Sysfs_Printk(" 0x5c0: sysRsvd10:\n");
	for (i = 0, k = 0; i < 5; i++, k += 4) {
		Sysfs_Printk("%08x: %08x %08x %08x %08x\n", (i * 16),
			     pSMACStatus->sysRsvd10[k],
			     pSMACStatus->sysRsvd10[k + 1],
			     pSMACStatus->sysRsvd10[k + 2],
			     pSMACStatus->sysRsvd10[k + 3]);
	}

	Sysfs_Printk(" 0x610: sysRsvdMU:\n");
	for (i = 0, k = 0; i < 3; i++, k += 4) {
		Sysfs_Printk("%08x: %08x %08x %08x %08x\n", (i * 16),
			     pSMACStatus->sysRsvdMU[k],
			     pSMACStatus->sysRsvdMU[k + 1],
			     pSMACStatus->sysRsvdMU[k + 2],
			     pSMACStatus->sysRsvdMU[k + 3]);
	}

	Sysfs_Printk(" 0x640: sysRsvd11:\n");
	for (i = 0, k = 0; i < 4; i++, k += 4) {
		Sysfs_Printk("%08x: %08x %08x %08x %08x\n", (i * 16),
			     pSMACStatus->sysRsvd11[k],
			     pSMACStatus->sysRsvd11[k + 1],
			     pSMACStatus->sysRsvd11[k + 2],
			     pSMACStatus->sysRsvd11[k + 3]);
	}

	Sysfs_Printk(" 0x680: sysRsvd12:\n");
	for (i = 0, k = 0; i < 1; i++, k += 4) {
		Sysfs_Printk("%08x: %08x %08x %08x %08x\n", (i * 16),
			     pSMACStatus->sysRsvd12[k],
			     pSMACStatus->sysRsvd12[k + 1],
			     pSMACStatus->sysRsvd12[k + 2],
			     pSMACStatus->sysRsvd12[k + 3]);
	}

	Sysfs_Printk(" 0x690: CSI Information:\n");
	Sysfs_Printk("CSI_Pkt_RAW_RSSI - AB: %d CD: %d EF: %d GH: %d\n",
		     pSMACStatus->CSI_RSSI_AB, pSMACStatus->CSI_RSSI_CD,
		     pSMACStatus->CSI_RSSI_EF, pSMACStatus->CSI_RSSI_GH);
	Sysfs_Printk("CSI_Pkt_MAC_Addr - %02x:%02x:%02x:%02x:%02x:%02x\n",
		     pSMACStatus->CSI_Pkt_MAC_Addr[0],
		     pSMACStatus->CSI_Pkt_MAC_Addr[1],
		     pSMACStatus->CSI_Pkt_MAC_Addr[2],
		     pSMACStatus->CSI_Pkt_MAC_Addr[3],
		     pSMACStatus->CSI_Pkt_MAC_Addr[4],
		     pSMACStatus->CSI_Pkt_MAC_Addr[5]);
	Sysfs_Printk("CSI_Pkt_Type - 0x%x\n", pSMACStatus->CSI_Pkt_Type);
	Sysfs_Printk("CSI_Pkt_SubType - 0x%x\n", pSMACStatus->CSI_Pkt_SubType);
	Sysfs_Printk("CSI_TX_Timestamp - 0x%x\n",
		     pSMACStatus->CSI_TX_Timestamp);
	Sysfs_Printk("CSI_RX_Timestamp_Lo - 0x%x\n",
		     pSMACStatus->CSI_RX_Timestamp_Lo);
	Sysfs_Printk("CSI_RX_Timestamp_Hi - 0x%x\n",
		     pSMACStatus->CSI_RX_Timestamp_Hi);
	Sysfs_Printk("CSI_CFO - 0x%x\n", pSMACStatus->CSI_CFO);
	Sysfs_Printk("CSI_reserved1 - 0x%x\n", pSMACStatus->CSI_reserved1);
	Sysfs_Printk("CSI_DTA - 0x%x\n", pSMACStatus->CSI_DTA);
	Sysfs_Printk("CSI_Valid - 0x%x\n", pSMACStatus->CSI_Valid);
	Sysfs_Printk("CSI_Count - 0x%x\n", pSMACStatus->CSI_Count);
	Sysfs_Printk("CSI_reserved2 - 0x%x\n", pSMACStatus->CSI_reserved2);

	Sysfs_Printk(" 0x6B8: CM3 Start / Stop Flag:\n");
	Sysfs_Printk("%08x %08x\n", pSMACStatus->cm3StartFlag,
		     pSMACStatus->cm3StopFlag);

	Sysfs_Printk(" 0x6c0: txBcnCntBss:\n");
	for (i = 0, k = 0; i < 4; i++, k += 8) {
		Sysfs_Printk
			("%08x: %04x %04x %04x %04x : %04x %04x %04x %04x\n",
			 (i * 16), pSMACStatus->txBcnCntBss[k],
			 pSMACStatus->txBcnCntBss[k + 1],
			 pSMACStatus->txBcnCntBss[k + 2],
			 pSMACStatus->txBcnCntBss[k + 3],
			 pSMACStatus->txBcnCntBss[k + 4],
			 pSMACStatus->txBcnCntBss[k + 5],
			 pSMACStatus->txBcnCntBss[k + 6],
			 pSMACStatus->txBcnCntBss[k + 7]);
	}

	Sysfs_Printk(" 0x700: lastCm3Event:\n");
	for (i = 0; i < 7; i++) {
		Sysfs_Printk("CM3-%d %02x\n", i, pSMACStatus->lastCm3Event[i]);
	}

	Sysfs_Printk("CM3-0 last event:\n");
	switch (pSMACStatus->lastCm3Event[0]) {
	case EVT_BITNUM(EVT_RX_BBIF_STRT_PPDU):
		Sysfs_Printk("EVT_RX_BBIF_STRT_PPDU\n");
		break;
	case EVT_BITNUM(EVT_RX_BBIF_HDR):
		Sysfs_Printk("EVT_RX_BBIF_HDR\n");
		break;
	case EVT_BITNUM(EVT_RX_BBIF_NDP):
		Sysfs_Printk("EVT_RX_BBIF_NDP\n");
		break;
	case EVT_BITNUM(EVT_RX_BBIF_END_PPDU_0):
		Sysfs_Printk("EVT_RX_BBIF_END_PPDU_0\n");
		break;
	case EVT_BITNUM(EVT_SW_MU_START):
		Sysfs_Printk("EVT_SW_MU_START\n");
		break;
	case EVT_BITNUM(EVT_EU_DONE_CTX0):
		Sysfs_Printk("EVT_EU_DONE_CTX0\n");
		break;
	case EVT_BITNUM(EVT_EU_DONE_CTX4):
		Sysfs_Printk("EVT_EU_DONE_CTX4\n");
		break;
	case EVT_BITNUM(EVT_EU_DONE_CTX8):
		Sysfs_Printk("EVT_EU_DONE_CTX8\n");
		break;
	case EVT_BITNUM(EVT_EU_DONE_CTX12):
		Sysfs_Printk("EVT_EU_DONE_CTX12\n");
		break;
	default:
		Sysfs_Printk("Uknown event %x\n", pSMACStatus->lastCm3Event[0]);
		break;
	}

	Sysfs_Printk("CM3-1 last event:\n");
	switch (pSMACStatus->lastCm3Event[1]) {
	case EVT_BITNUM(EVT_ADMA_RX_CFH_IRQ):
		Sysfs_Printk("EVT_ADMA_RX_CFH_IRQ\n");
		break;
	case EVT_BITNUM(EVT_RX_BBIF_STRT_PPDU_1):
		Sysfs_Printk("EVT_RX_BBIF_STRT_PPDU_1\n");
		break;
	case EVT_BITNUM(EVT_EU_RX_MPDU_DONE):
		Sysfs_Printk("EVT_EU_RX_MPDU_DONE\n");
		break;
	case EVT_BITNUM(EVT_SW_EOF_FROM_FCS):
		Sysfs_Printk("EVT_SW_EOF_FROM_FCS\n");
		break;
	case EVT_BITNUM(EVT_SW_MU_START):
		Sysfs_Printk("EVT_SW_MU_START\n");
		break;
	case EVT_BITNUM(EVT_EU_DONE_CTX0):
		Sysfs_Printk("EVT_EU_DONE_CTX0\n");
		break;
	case EVT_BITNUM(EVT_EU_DONE_CTX4):
		Sysfs_Printk("EVT_EU_DONE_CTX4\n");
		break;
	case EVT_BITNUM(EVT_EU_DONE_CTX8):
		Sysfs_Printk("EVT_EU_DONE_CTX8\n");
		break;
	case EVT_BITNUM(EVT_EU_DONE_CTX12):
		Sysfs_Printk("EVT_EU_DONE_CTX12\n");
		break;
	default:
		Sysfs_Printk("Uknown event %x\n", pSMACStatus->lastCm3Event[1]);
		break;
	}

	Sysfs_Printk("CM3-2 last event:\n");
	switch (pSMACStatus->lastCm3Event[2]) {
	case EVT_BITNUM(EVT_RX_BBIF_RX_INFO):
		Sysfs_Printk("EVT_RX_BBIF_RX_INFO\n");
		break;
	case EVT_BITNUM(EVT_RX_BBIF_SOF):
		Sysfs_Printk("EVT_RX_BBIF_SOF\n");
		break;
#if !defined(APMODE_ULOFDMA)
	case EVT_BITNUM(EVT_RX_BBIF_FCS):
		Sysfs_Printk("EVT_RX_BBIF_FCS\n");
		break;
#endif /* !APMODE_ULOFDMA */
	case EVT_BITNUM(EVT_RX_BBIF_EOF):
		Sysfs_Printk("EVT_RX_BBIF_EOF\n");
		break;
	case EVT_BITNUM(EVT_RX_BBIF_END_PPDU_2):
		Sysfs_Printk("EVT_RX_BBIF_END_PPDU_2\n");
		break;
	case EVT_BITNUM(EVT_SW_MU_START):
		Sysfs_Printk("EVT_SW_MU_START\n");
		break;
	case EVT_BITNUM(EVT_EU_DONE_CTX0):
		Sysfs_Printk("EVT_EU_DONE_CTX0\n");
		break;
	case EVT_BITNUM(EVT_EU_DONE_CTX4):
		Sysfs_Printk("EVT_EU_DONE_CTX4\n");
		break;
	case EVT_BITNUM(EVT_EU_DONE_CTX8):
		Sysfs_Printk("EVT_EU_DONE_CTX8\n");
		break;
	case EVT_BITNUM(EVT_EU_DONE_CTX12):
		Sysfs_Printk("EVT_EU_DONE_CTX12\n");
		break;
	default:
		Sysfs_Printk("Uknown event %x\n", pSMACStatus->lastCm3Event[2]);
		break;
	}

	Sysfs_Printk("CM3-3 last event:\n");
	switch (pSMACStatus->lastCm3Event[3]) {
	case EVT_BITNUM(EVT_TX_TIMR_MSLOT_TICK):
		Sysfs_Printk("EVT_TX_TIMR_MSLOT_TICK\n");
		break;
	case EVT_BITNUM(EVT_TX_TIMR_PROG_TIMR_2):
		Sysfs_Printk("EVT_TX_TIMR_PROG_TIMR_2\n");
		break;
	case EVT_BITNUM(EVT_TX_TIMR_BCN_TSF_MATCH):
		Sysfs_Printk("EVT_TX_TIMR_BCN_TSF_MATCH\n");
		break;
	case EVT_BITNUM(EVT_TX_TXPE_ASSERT):
		Sysfs_Printk("EVT_TX_TXPE_ASSERT\n");
		break;
	case EVT_BITNUM(EVT_TX_RDY_DEASSERT):
		Sysfs_Printk("EVT_TX_RDY_DEASSERT\n");
		break;
	case EVT_BITNUM(EVT_RX_BBIF_END_PPDU):
		Sysfs_Printk("EVT_RX_BBIF_END_PPDU\n");
		break;
	case EVT_BITNUM(EVT_SW_B2B_TX_FROM_FCS):
		Sysfs_Printk("EVT_SW_B2B_TX_FROM_FCS\n");
		break;
	case EVT_BITNUM(EVT_SW_MU_START):
		Sysfs_Printk("EVT_SW_MU_START\n");
		break;
	case EVT_BITNUM(EVT_EU_DONE_CTX0):
		Sysfs_Printk("EVT_EU_DONE_CTX0\n");
		break;
	case EVT_BITNUM(EVT_EU_DONE_CTX4):
		Sysfs_Printk("EVT_EU_DONE_CTX4\n");
		break;
	case EVT_BITNUM(EVT_EU_DONE_CTX8):
		Sysfs_Printk("EVT_EU_DONE_CTX8\n");
		break;
	case EVT_BITNUM(EVT_EU_DONE_CTX12):
		Sysfs_Printk("EVT_EU_DONE_CTX12\n");
		break;
	default:
		Sysfs_Printk("Uknown event %x\n", pSMACStatus->lastCm3Event[3]);
		break;
	}

	Sysfs_Printk("CM3-4 last event:\n");
	switch (pSMACStatus->lastCm3Event[4]) {
	case EVT_BITNUM(EVT_TXD2_DONE_0):
		Sysfs_Printk("EVT_TXD2_DONE_0\n");
		break;
	case EVT_BITNUM(EVT_TXD1_TRIGGER_BITMAP):
		Sysfs_Printk("EVT_TXD1_TRIGGER_BITMAP\n");
		break;
	case EVT_BITNUM(EVT_TX_TIMR_PROG_TIMR_3):
		Sysfs_Printk("EVT_TX_TIMR_PROG_TIMR_3\n");
		break;
	case EVT_BITNUM(EVT_PFW_2_SFW_MSG_TRIG):
		Sysfs_Printk("EVT_PFW_2_SFW_MSG_TRIG\n");
		break;
	default:
		Sysfs_Printk("Uknown event %x\n", pSMACStatus->lastCm3Event[4]);
		break;
	}

	Sysfs_Printk("CM3-5 last event:\n");
	switch (pSMACStatus->lastCm3Event[5]) {
	case EVT_BITNUM(EVT_RX_BBIF_STRT_PPDU_2):
		Sysfs_Printk("EVT_RX_BBIF_STRT_PPDU_2\n");
		break;
	case EVT_BITNUM(EVT_SW_TA_RDY_FROM_SOP):
		Sysfs_Printk("EVT_SW_TA_RDY_FROM_SOP\n");
		break;
	case EVT_BITNUM(EVT_SW_EOP2_FROM_EOP):
		Sysfs_Printk("EVT_SW_EOP2_FROM_EOP\n");
		break;
	case EVT_BITNUM(EVT_RX_BBIF_END_PPDU_2):
		Sysfs_Printk("EVT_RX_BBIF_END_PPDU_2\n");
		break;
#if defined(APMODE_ULOFDMA) && !defined(APMODE_ULOFDMA_WITH_8P2)
	case EVT_BITNUM(EVT_TX_TIMR_PROG_TIMR_0):
		Sysfs_Printk("EVT_TX_TIMR_PROG_TIMR_0\n");
#endif
	default:
		Sysfs_Printk("Uknown event %x\n", pSMACStatus->lastCm3Event[5]);
		break;
	}

	Sysfs_Printk("CM3-6 last event:\n");
	switch (pSMACStatus->lastCm3Event[6]) {
	case EVT_BITNUM(EVT_SW_BBTX_GRP_1):
		Sysfs_Printk("EVT_SW_BBTX_GRP_1\n");
		break;
	case EVT_BITNUM(EVT_SW_BBTX_GRP_23):
		Sysfs_Printk("EVT_SW_BBTX_GRP_23\n");
		break;
#if defined(APMODE_ULOFDMA)
	case EVT_BITNUM(EVT_RX_BBIF_FCS):
		Sysfs_Printk("EVT_RX_BBIF_FCS\n");
		break;
#endif /* APMODE_ULOFDMA */
	default:
		Sysfs_Printk("Uknown event %x\n", pSMACStatus->lastCm3Event[6]);
		break;
	}

	//show PFW alive counters
	wl_show_pfw_alive_counts(netdev, sysfs_buff);

	Sysfs_Printk("\t ----------------------------\n");
	Sysfs_Printk("\t [DRV] rx_count        = %lu\n",
		     wlpptr->netDevStats.rx_packets);
	Sysfs_Printk("\t [DRV] sent_cnt        = %u\n",
		     wlpd_p->drv_stats_val.txq_drv_sent_cnt);
	Sysfs_Printk("\n");
	return;
}

void
wl_show_except_cnt(struct net_device *netdev, char *sysfs_buff)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	struct except_cnt *wlexcept_p = &wlpd_p->except_cnt;
	struct drv_stats *wldrvstat_p = &wlpd_p->drv_stats_val;
	int i;

	Sysfs_Printk("========[BMQ buffer alloc_fail cnt]========\n");
	for (i = SC5_BMQ_START_INDEX; i < SC5_BMQ_START_INDEX + SC5_BMQ_NUM;
	     i++) {
		Sysfs_Printk("\t Q[%d] = %u\n", i,
			     wlpd_p->drv_stats_val.bmqbuf_alloc_fail_cnt[i -
									 SC5_BMQ_START_INDEX]);
	}
	Sysfs_Printk("\nRx info:\n");
	Sysfs_Printk("cfhul invalid signature: %u\n",
		     wlexcept_p->cnt_cfhul_invalid_signature);
	Sysfs_Printk("BMQ buffer fragmented:%u\n",
		     wlexcept_p->cnt_z1_frag_buffer);
	Sysfs_Printk("cfhul error:%u\n", wlexcept_p->cnt_cfhul_error);
	Sysfs_Printk("cfhul snap error:%u\n", wlexcept_p->cnt_cfhul_snap_error);
	Sysfs_Printk("cfhul oversize:%u\n", wlexcept_p->cnt_cfhul_oversize);
	Sysfs_Printk("cnt_invalid_mpdu_frames:%u\n",
		     wlexcept_p->cnt_invalid_mpdu_frames);
	Sysfs_Printk("cnt_invalid_amsdu_subframes:%u\n",
		     wlexcept_p->cnt_invalid_amsdu_subframe_len);
	Sysfs_Printk("amsdu subframes count:%u\n",
		     wlexcept_p->cnt_amsdu_subframes);
	Sysfs_Printk("rq.skbTrace queue re-init cnt:%u\n",
		     wlexcept_p->cnt_skbtrace_reset);

	Sysfs_Printk("rcvd pkts SQ0:%u SQ8:%u, SQ9:%u\n",
		     wlexcept_p->qidcnt[0], wlexcept_p->qidcnt[1],
		     wlexcept_p->qidcnt[2]);
	Sysfs_Printk
		("buffer free count by SQ14.  SQ[10]=%u, SQ[11]:%u, SQ[12]:%u, SQ[X]=%u\n",
		 wldrvstat_p->xx_buf_free_SQ14[0],
		 wldrvstat_p->xx_buf_free_SQ14[1],
		 wldrvstat_p->xx_buf_free_SQ14[2],
		 wldrvstat_p->xx_buf_free_SQ14[3]);
	Sysfs_Printk("BMQ13 buffer release/refill count:%u\n",
		     wldrvstat_p->bmq13_refill_cnt);
	Sysfs_Printk("Invalid skb addr cnt:%u\n",
		     wlexcept_p->skb_invalid_addr_cnt);

	Sysfs_Printk("\nTx info:\n");
	Sysfs_Printk("mis-alignment: %u\n", wlexcept_p->cnt_tx_misalign);
	Sysfs_Printk("drop - over max pending tx: %u\n",
		     wlexcept_p->tx_drop_over_max_pending);
	Sysfs_Printk("dup_txdone_cnt: %u\n", wlexcept_p->dup_txdone_cnt);
	Sysfs_Printk("skb_invalid_signature_cnt: %u\n",
		     wlexcept_p->skb_invalid_signature_cnt);
	Sysfs_Printk("small headroom cnt: %u\n", wlexcept_p->sml_hdroom_cnt);
	Sysfs_Printk("========[BMQ buffer invalid signature cnt]========\n");
	for (i = SC5_BMQ_START_INDEX; i < SC5_BMQ_START_INDEX + SC5_BMQ_NUM;
	     i++) {
		Sysfs_Printk("\t Q[%d] = %u\n", i,
			     wlexcept_p->rx_invalid_sig_cnt[i -
							    SC5_BMQ_START_INDEX]);
	}

	Sysfs_Printk("\nPe info:\n");
	Sysfs_Printk("Invalid bpid: %u\n", wlexcept_p->pe_invlid_bpid);
	Sysfs_Printk("Desciptor not updated:  %u\n",
		     wlexcept_p->buf_desc_not_updated);
	Sysfs_Printk("Invalid buffer address:  %u\n",
		     wlexcept_p->invalid_buf_addr);
	Sysfs_Printk("Skb not linked:  %u\n", wlexcept_p->skb_notlinked_cnt);

	Sysfs_Printk("\nCfhul info:\n");
	Sysfs_Printk("bpid_err: %u\n", wlexcept_p->cfhul_bpid_err);
	Sysfs_Printk("hdr.lo_addr_err: %u\n", wlexcept_p->cfhul_hdr_loaddr_err);
	for (i = SC5_BMQ_START_INDEX; i < SC5_BMQ_START_INDEX + SC5_BMQ_NUM;
	     i++) {
		int idx = i - SC5_BMQ_START_INDEX;
		Sysfs_Printk("q[%d](fpkt,lpkt)_error: %u\n", i,
			     wlexcept_p->cfhul_flpkt_error[idx]);
		if (wlexcept_p->cfhul_flpkt_error[idx] > 0) {
			Sysfs_Printk("\t\t err_cond: [%u, %u], [%u, %u]\n",
				     (wlexcept_p->cfhul_flpkt_log[idx][0] >> 4),
				     (wlexcept_p->
				      cfhul_flpkt_log[idx][0] & 0xf),
				     (wlexcept_p->cfhul_flpkt_log[idx][1] >> 4),
				     (wlexcept_p->
				      cfhul_flpkt_log[idx][1] & 0xf));
		}
	}
	Sysfs_Printk("hdrlen_err: %d\n", wlexcept_p->cfhul_hdrlen_err);
	Sysfs_Printk("cfhul_buf_map_err: %d\n", wlexcept_p->cfhul_buf_map_err);

	Sysfs_Printk("Lost AMSDU subframes (fpkt,midle,lpkt)=%u,%u,%u\n",
		     wlexcept_p->cfhul_flpkt_lost[0],
		     wlexcept_p->cfhul_flpkt_lost[1],
		     wlexcept_p->cfhul_flpkt_lost[2]);
	Sysfs_Printk("Recovered errcfhul %u\n", recovered_errcfhul);
	Sysfs_Printk("AMSDU subframe number over limit:%u\n",
		     wlexcept_p->cfhul_flpkt_lost[3]);
	Sysfs_Printk("Insufficient rx headroom: %u\n",
		     wlexcept_p->sml_rx_hdroom_cnt);
	Sysfs_Printk("Mis-aligned rx buffer: %u\n",
		     wlexcept_p->rxbuf_mis_align_cnt);
	Sysfs_Printk("Invalid defrag frame: %u\n", wlexcept_p->cnt_defrag_drop);
	Sysfs_Printk("Incorrect msdu frame: %u\n", wlexcept_p->msdu_err);
	Sysfs_Printk("Incorrect MIC  frame: %u\n", wlexcept_p->cnt_mic_err);
	Sysfs_Printk("Incorrect ICV  frame: %u\n", wlexcept_p->cnt_icv_err);
	Sysfs_Printk("Incorrect PN count: ucast = %u, mcast= %u, mgmt= %u\n",
		     wlexcept_p->badPNcntUcast, wlexcept_p->badPNcntMcast,
		     wlexcept_p->badPNcntMgmtcast);
	Sysfs_Printk("Invalid skb structure, (head > data): %u\n",
		     wlexcept_p->skb_hddat_err);
	Sysfs_Printk("Skb overpanic cnt:%u\n", wlexcept_p->skb_overpanic_cnt);
	Sysfs_Printk("Skb nonlinear cnt:%u\n", wlexcept_p->skb_nonlinear_cnt);
	Sysfs_Printk
		("Skip feeding the starving queue q(10, 11, 12, 13)=(%d, %d, %d, %d)\n",
		 wlexcept_p->skip_feed_starv[0], wlexcept_p->skip_feed_starv[1],
		 wlexcept_p->skip_feed_starv[2],
		 wlexcept_p->skip_feed_starv[3]);

	{
		struct bqm_args *pbqm_args = &wlpd_p->bmq_args;
		U16 qid;
		Sysfs_Printk("[q_full_empty]: Rx:\n");
		for (qid = SC5_RXQ_START_INDEX;
		     qid < SC5_RXQ_START_INDEX + SC5_RXQ_NUM; qid++) {
			if (((1 << qid) & SC5_RXQ_MASK) == 0) {	// Not enabled
				continue;
			}
			Sysfs_Printk("SQ[%u]: %u\n", qid,
				     wlexcept_p->qfull_empty[qid][SC5_SQ]);
		}

		Sysfs_Printk("[q_full_empty]: Tx:\n");
		for (qid = pbqm_args->txq_start_index;
		     qid < pbqm_args->txq_start_index + pbqm_args->txq_num;
		     qid++) {
			Sysfs_Printk("RQ[%u]: %u\n", qid,
				     wlexcept_p->qfull_empty[qid][SC5_RQ]);
		}

		Sysfs_Printk("[q_full_empty]: BMQQ:\n");
		for (qid = SC5_BMQ_START_INDEX;
		     qid < (SC5_BMQ_START_INDEX + SC5_BMQ_NUM); qid++) {
			Sysfs_Printk("RQ[%u]: %u\n", qid,
				     wlexcept_p->qfull_empty[i][SC5_RQ]);
		}

		Sysfs_Printk("[q_full_empty]: ReleaseQ:\n");
		for (qid = pbqm_args->bmq_release_index;
		     qid <
		     (pbqm_args->bmq_release_index +
		      pbqm_args->bmq_release_num); qid++) {
			Sysfs_Printk("SQ[%u]: %u\n", qid,
				     wlexcept_p->qfull_empty[qid][SC5_SQ]);
		}
	}
	Sysfs_Printk("Rx timestamp inconsistent: %u\n",
		     wlexcept_p->diff_tm_patch);
	Sysfs_Printk("Free pkts from err_cfhul: %u, %u, %u\n",
		     wlexcept_p->free_err_pkts[0], wlexcept_p->free_err_pkts[1],
		     wlexcept_p->free_err_pkts[2]);
	Sysfs_Printk("lpkt missing: %u, %u, %u\n", wlexcept_p->lpkt_miss[0],
		     wlexcept_p->lpkt_miss[1], wlexcept_p->lpkt_miss[2]);
	Sysfs_Printk("Invalid STN ID in Acnt Record: %u\n",
		     wlexcept_p->badAcntStnid);
	Sysfs_Printk("cfh-ul bypass cnt: %u\n", wlexcept_p->rx_bypass_cnt);
	Sysfs_Printk("cfh-ul mic_err cnt: %u\n", wlexcept_p->rx_mic_err_cnt);
	Sysfs_Printk("cfh-ul icv_err cnt: %u\n", wlexcept_p->rx_icv_err_cnt);
	Sysfs_Printk("Deauth war cnt: %u\n", wlexcept_p->deauth_war_cnt);
	Sysfs_Printk("Disasso war cnt: %u\n", wlexcept_p->disasso_war_cnt);
	Sysfs_Printk("Asso war cnt: %u\n", wlexcept_p->asso_war_cnt);
	Sysfs_Printk("Reasso war cnt: %u\n", wlexcept_p->reasso_war_cnt);
	Sysfs_Printk("Auth war cnt: %u\n", wlexcept_p->auth_war_cnt);
	Sysfs_Printk("Monitor fw auto recovery: 0x%x\n",
		     wlpd_p->except_cnt.mon_fw_recovery);
	Sysfs_Printk("Late rx_info interrupt cnt: %u out of %u\n",
		     wlexcept_p->late_rxinfo_cnt, wlexcept_p->total_rxinfo_cnt);
	return;
}

static void
wl_show_statusage(struct net_device *netdev, char *sysfs_buff)
{
	Sysfs_Printk("Options of show_stat\n");
	Sysfs_Printk("\t %d: drvstatsopt_geninfo\n", (int)drvstatsopt_geninfo);
	Sysfs_Printk("\t %d: drvstatsopt_warning\n", (int)drvstatsopt_warning);
	Sysfs_Printk("\t %d: drvstatsopt_rxinfo\n", (int)drvstatsopt_rxinfo);
	Sysfs_Printk("\t %d: drvstatsopt_scheduleinfo\n",
		     (int)drvstatsopt_scheduleinfo);
	Sysfs_Printk("\t %d: drvstatsopt_txprofile\n",
		     (int)drvstatsopt_txprofile);
	Sysfs_Printk("\t %d: drvstatsopt_mac\n", (int)drvstatsopt_smac);
	Sysfs_Printk("\t %d: drvstatsopt_hframe\n", (int)drvstatsopt_hframe);
	Sysfs_Printk("\t %d: drvstatsopt_pktcnt\n", (int)drvstatsopt_pktcnt);
	Sysfs_Printk("\t %d: drvstatsopt_dra_stat\n",
		     (int)drvstatsopt_dra_stat);
	Sysfs_Printk("\t %d: drvstatsopt_ba\n", (int)drvstatsopt_ba);
	return;
}

static void
wl_show_tx_mu_pkcnt_msg(struct net_device *netdev, char *sysfs_buff)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	UINT32 reg;
	UINT32 *pktcnt = wl_kmalloc(64 * sizeof(UINT32), GFP_KERNEL);
	if (!pktcnt)
		return;

	memset(pktcnt, 0, 64 * sizeof(UINT32));
	wl_util_lock(netdev);
	reg = wlpptr->smacStatusAddr->sysRsvdMU[3];
	wl_util_unlock(netdev);
	wlFwGetAddrValue(netdev, reg, 2, pktcnt, 0);

	Sysfs_Printk("Tx MU/SU cnt:\n");
	Sysfs_Printk("[MU]: addr 0x%x: %8u\n", reg, pktcnt[0]);
	Sysfs_Printk("[SU]: addr 0x%x: %8u\n", reg + 4, pktcnt[1]);
	wl_kfree(pktcnt);

	Sysfs_Printk("Tx MU-MIMO cnt:\n");
	wl_util_lock(netdev);
	Sysfs_Printk("[MU-MIMO]: %8u\n", wlpptr->smacStatusAddr->sysRsvdMU[11]);
	wl_util_unlock(netdev);

}

static void
wl_show_pktcnt_msg(struct pkttype_info *wlpkttype_p, char *sysfs_buff)
{
	Sysfs_Printk("pkt_data: %u, pkt_mgmt: %u, pkt_ctrl: %u\n",
		     wlpkttype_p->data_cnt, wlpkttype_p->mgmt_cnt,
		     wlpkttype_p->ctrl_cnt);
	Sysfs_Printk("[mgmt]:\n");
	Sysfs_Printk("\t auth: %u, assoc_req: %u, assoc_resp: %u\n",
		     wlpkttype_p->auth_cnt,
		     wlpkttype_p->assoc_req_cnt, wlpkttype_p->assoc_resp_cnt);
	Sysfs_Printk("\t re-assoc_req: %u, re-assoc_resp: %u\n",
		     wlpkttype_p->reassoc_req_cnt,
		     wlpkttype_p->reassoc_resp_cnt);

	Sysfs_Printk("\t disassoc: %u, deauth: %u\n",
		     wlpkttype_p->disassoc_cnt, wlpkttype_p->deauth_cnt);

	Sysfs_Printk("\t prob_req: %u, prob_resp: %u, beacon: %u\n",
		     wlpkttype_p->prob_req_cnt, wlpkttype_p->prob_resp_cnt,
		     wlpkttype_p->beacon_cnt);

	Sysfs_Printk("[ctrl]:\n");
	Sysfs_Printk("\t ba_req_cnt: %u, ba_req_cnt: %u\n",
		     wlpkttype_p->ba_req_cnt, wlpkttype_p->ba_cnt);

	Sysfs_Printk("[data]:\n");
	Sysfs_Printk("\t tcp: %u, udp: %u, icmp: %u, arp: %u\n",
		     wlpkttype_p->tcp_cnt, wlpkttype_p->udp_cnt,
		     wlpkttype_p->icmp_cnt, wlpkttype_p->arp_cnt);
	Sysfs_Printk("\t non-ipv4: %u\n", wlpkttype_p->nipv4_cnt);
	Sysfs_Printk("\t eap: %u\n", wlpkttype_p->eap_cnt);
	Sysfs_Printk("\t null: %u\n", wlpkttype_p->null_cnt);
}

void
wl_show_pktcnt_stat(struct net_device *netdev, char *sysfs_buff)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;

	Sysfs_Printk("\n======== [Drv rx] ========\n");
	wl_show_pktcnt_msg(&wlpd_p->rpkt_type_cnt, sysfs_buff);
	Sysfs_Printk("\n======== [Drv tx] ========\n");
	wl_show_pktcnt_msg(&wlpd_p->tpkt_type_cnt, sysfs_buff);
	wl_show_tx_mu_pkcnt_msg(netdev, sysfs_buff);
	return;
}

static void
wl_show_dra_stat(struct net_device *netdev, char *sysfs_buff)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	UINT32 dra_stat_cnt[20], tmp_data[24];
	void *pfwdbgstate;
	UINT32 dmemaddr, reg_pc;

	if (IS_BUS_TYPE_MCI(wlpptr)) {	//MOCHI 
		dmemaddr = wl_util_readl(netdev, wlpptr->ioBase1 + wlpptr->wlpd_p->reg.FwDbgStateAddr) - SMAC_DMEM_START;
		pfwdbgstate = (void *)(wlpptr->ioBase0 + dmemaddr);
		memcpy((void *)tmp_data,
		       (void *)(pfwdbgstate + (PFW_DRA_STAT_CNT_OFFSET - 0x10)),
		       sizeof(tmp_data));
	} else {		//PCIE interface
		u8 *pbuf = NULL;

#define DMEM_DEBUG_START_OFFSET 0x123800
		if ((pbuf = (u8 *) wl_kmalloc(1024, GFP_KERNEL))) {

			if (!wlFwGetAddrValue
			    (netdev,
			     (SMAC_DMEM_START + DMEM_DEBUG_START_OFFSET +
			      PFW_DRA_STAT_CNT_OFFSET - 0x10), 64, (u32 *) pbuf,
			     0)) {
				memcpy((void *)tmp_data, (void *)pbuf,
				       sizeof(tmp_data));
			} else {
				wl_kfree(pbuf);
				goto error_exit;
			}

			wl_kfree(pbuf);
		} else
			goto error_exit;
	}

	reg_pc = tmp_data[3];

	if (reg_pc >= 20) {
		Sysfs_Printk("\n======== DRA pc error ========\n");
		return;
	}
	memcpy(&dra_stat_cnt[0], &tmp_data[reg_pc + 4],
	       (20 - reg_pc) * sizeof(UINT32));
	if (reg_pc != 0) {
		memcpy(&dra_stat_cnt[20 - reg_pc], &tmp_data[4],
		       reg_pc * sizeof(UINT32));
	}

	Sysfs_Printk("\n======== [DRA statistics counters] ========\n");
	Sysfs_Printk
		("\n                         [1]      [2]      [3]      [4]      [5]\n");
	Sysfs_Printk(" [PFW] MPDUCount    = %8d %8d %8d %8d %8d\n",
		     dra_stat_cnt[0], dra_stat_cnt[4], dra_stat_cnt[8],
		     dra_stat_cnt[12], dra_stat_cnt[16]);
	Sysfs_Printk(" [PFW] SuccessCount = %8d %8d %8d %8d %8d\n",
		     dra_stat_cnt[1], dra_stat_cnt[5], dra_stat_cnt[9],
		     dra_stat_cnt[13], dra_stat_cnt[17]);
	Sysfs_Printk(" [PFW] RetryCount   = %8d %8d %8d %8d %8d\n",
		     dra_stat_cnt[2], dra_stat_cnt[6], dra_stat_cnt[10],
		     dra_stat_cnt[14], dra_stat_cnt[18]);
	Sysfs_Printk(" [PFW] PER          = %8d %8d %8d %8d %8d\n",
		     dra_stat_cnt[3], dra_stat_cnt[7], dra_stat_cnt[11],
		     dra_stat_cnt[15], dra_stat_cnt[19]);

	return;
error_exit:
	Sysfs_Printk("\n======== DRA error ========\n");
	return;

}

static void
wl_show_ba_reorder_stat(struct net_device *netdev, char *sysfs_buff)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	extStaDb_StaInfo_t *StaInfo_p = NULL;
	UINT32 entries = 0;
	UINT8 *staBuf = NULL;
	UINT8 *listBuf = NULL;

	Sysfs_Printk
		("\n============ [BA reorder statistics counters] ============\n");
	Sysfs_Printk(" Pkt sent to host count                        = %8d\n",
		     vmacSta_p->BA_Rodr2Host);
	Sysfs_Printk(" Duplicate pkt drop count                      = %8d\n",
		     vmacSta_p->BA_RodrDupDropCnt);
	Sysfs_Printk(" Out of range seqno drop count                 = %8d\n",
		     vmacSta_p->BA_RodrOoRDropCnt);
	Sysfs_Printk(" Enqueue AMSDU pkt error (to be dropped) count = %8d\n",
		     vmacSta_p->BA_RodrAmsduEnQCnt);
	Sysfs_Printk(" Flush any drop count                          = %8d\n",
		     vmacSta_p->BA_RodrFlushDropCnt);
	Sysfs_Printk(" Timeout processing drop count                 = %8d\n",
		     vmacSta_p->BA_RodrTMODropCnt);

	entries = extStaDb_entries(vmacSta_p, 0);
	if (entries == 0)
		return;

	staBuf = wl_kmalloc(entries * sizeof(STA_INFO), GFP_KERNEL);
	if (staBuf == NULL)
		return;

	Sysfs_Printk
		("\n======= [Per STA - BA reorder statistics counters] =======\n");
	extStaDb_list(vmacSta_p, staBuf, 1);
	if (entries) {
		int i;
		listBuf = staBuf;
		for (i = 0; i < entries; i++) {
			if ((StaInfo_p = extStaDb_GetStaInfo(vmacSta_p,
							     (IEEEtypes_MacAddr_t
							      *) listBuf,
							     STADB_DONT_UPDATE_AGINGTIME))
			    != NULL) {

				if (StaInfo_p->State == ASSOCIATED) {
					int i;
					Sysfs_Printk
						(" StnId: %d MAC Addr: %s\n",
						 StaInfo_p->StnId,
						 mac_display(StaInfo_p->Addr));
					Sysfs_Printk
						(" Pkt sent to host count:\n");
					for (i = 0; i < MAX_TID; i++)
						Sysfs_Printk(" tid#%d=%d", i,
							     StaInfo_p->
							     rxBaStats[i].
							     BA_Rodr2Host);
					Sysfs_Printk("\n");
					Sysfs_Printk
						(" Duplicate pkt drop count:\n");
					for (i = 0; i < MAX_TID; i++)
						Sysfs_Printk(" tid#%d = %d", i,
							     StaInfo_p->
							     rxBaStats[i].
							     BA_RodrDupDropCnt);
					Sysfs_Printk("\n");
					Sysfs_Printk
						(" Out of range seqno drop count:\n");
					for (i = 0; i < MAX_TID; i++)
						Sysfs_Printk(" tid#%d = %d", i,
							     StaInfo_p->
							     rxBaStats[i].
							     BA_RodrOoRDropCnt);
					Sysfs_Printk("\n");
					Sysfs_Printk
						(" Enqueue AMSDU pkt error (to be dropped) count:\n");
					for (i = 0; i < MAX_TID; i++)
						Sysfs_Printk(" tid#%d = %d", i,
							     StaInfo_p->
							     rxBaStats[i].
							     BA_RodrAmsduEnQCnt);
					Sysfs_Printk("\n");
					Sysfs_Printk
						(" Flush any drop count:\n");
					for (i = 0; i < MAX_TID; i++)
						Sysfs_Printk(" tid#%d = %d", i,
							     StaInfo_p->
							     rxBaStats[i].
							     BA_RodrFlushDropCnt);
					Sysfs_Printk("\n");
					Sysfs_Printk
						(" Timeout processing drop count:\n");
					for (i = 0; i < MAX_TID; i++)
						Sysfs_Printk(" tid#%d = %d", i,
							     StaInfo_p->
							     rxBaStats[i].
							     BA_RodrTMODropCnt);
					Sysfs_Printk("\n\n");
				}
				listBuf += sizeof(STA_INFO);
			}
		}
	}
	wl_kfree(staBuf);
}

extern BaR_Debug_t ba_debug_buf[];
extern UINT32 temp_index;
static void
wl_show_ba(struct net_device *netdev, char *sysfs_buff)
{
	UINT32 i;

	for (i = 0; i < 256; i++) {
		if (ba_debug_buf[i].lo_dword_addr != 0) {
			Sysfs_Printk
				("\t mac address of STA who sent the msdu   = %s\n",
				 mac_display(ba_debug_buf[i].Addr));
			Sysfs_Printk("\t station id                    = %u\n",
				     ba_debug_buf[i].StnId);
			Sysfs_Printk
				("\t BA reoder window starting seq number = %u\n",
				 ba_debug_buf[i].winStartB);
			Sysfs_Printk("\t Seq number in current mpdu    = %u\n",
				     ba_debug_buf[i].SeqNo);
			Sysfs_Printk("\t L0 buffer address             = %x\n",
				     (u32) ba_debug_buf[i].lo_dword_addr);
		}
	}
}

/*
        Show the statistics data/counter
 */
void
wl_show_stat(struct net_device *netdev, int option, int level, char *sysfs_buff)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);

	if (option == (int)drvstatsopt_geninfo) {
		if (level) {
			Sysfs_Printk("TBI\n");
		} else {
			wl_show_generic_info(netdev, sysfs_buff);
		}
	} else if (option == (int)drvstatsopt_warning) {
		wl_show_except_cnt(netdev, sysfs_buff);
	} else if (option == (int)drvstatsopt_rxinfo) {
		wl_show_rx_stats(netdev, sysfs_buff);
		wl_show_recv_info(netdev, sysfs_buff);
	} else if (option == (int)drvstatsopt_scheduleinfo) {
		wl_show_scheduleinfo(netdev, level, sysfs_buff);
	} else if (option == (int)drvstatsopt_txprofile) {
#ifdef TP_PROFILE
		wl_show_tx_profile(netdev, level, sysfs_buff);
#endif
	} else if (option == (int)drvstatsopt_smac) {
		SMAC_STATUS_st smacStatus;
		wl_util_lock(netdev);
		memcpy(&smacStatus, wlpptr->smacStatusAddr,
		       sizeof(SMAC_STATUS_st));
		wl_util_unlock(netdev);
		wl_show_smac_stat(netdev, &smacStatus, sysfs_buff);
	} else if (option == (int)drvstatsopt_hframe) {
		wl_show_hframe_info(netdev, sysfs_buff);
	} else if (option == (int)drvstatsopt_pktcnt) {
		wl_show_pktcnt_stat(netdev, sysfs_buff);
	} else if (option == (int)drvstatsopt_dra_stat) {
		wl_show_dra_stat(netdev, sysfs_buff);
	} else if (option == (int)drvstatsopt_ba) {
		wl_show_ba_reorder_stat(netdev, sysfs_buff);
		if (wfa_11ax_pf)
			wl_show_ba(netdev, sysfs_buff);
	} else {
		wl_show_statusage(netdev, sysfs_buff);
	}
	return;
}

int
wl_show_stat_cmd(struct net_device *netdev, char *info_item, char *info_level,
		 char *sysfs_buff)
{
	int option = (int)simple_strtol(info_item, NULL, 10);
	int level = 0;
	if ((option >= drvstatsopt_geninfo) && (option < drvstatsopt_end))
		level = 0;
	else {
		if (!strcmp(info_item, "geninfo"))
			option = drvstatsopt_geninfo;
		else if (!strcmp(info_item, "warn"))
			option = drvstatsopt_warning;
		else if (!strcmp(info_item, "drvrxinfo"))
			option = drvstatsopt_rxinfo;
		else if (!strcmp(info_item, "schinfo"))
			option = drvstatsopt_scheduleinfo;
		else if (!strcmp(info_item, "tp"))
			option = drvstatsopt_txprofile;
		else if (!strcmp(info_item, "mac"))
			option = drvstatsopt_smac;
		else if (!strcmp(info_item, "hframe"))
			option = drvstatsopt_hframe;
		else if (!strcmp(info_item, "pktcnt"))
			option = drvstatsopt_pktcnt;
		else if (!strcmp(info_item, "dra_stat"))
			option = drvstatsopt_dra_stat;
		else if (!strcmp(info_item, "bareorder"))
			option = drvstatsopt_ba;
		else
			return -EINVAL;

		if (!strcmp(info_level, "all"))
			level = 0;
		else if (!strcmp(info_level, "short"))
			level = 1;
		else
			level = 1;
	}

	wl_show_stat(netdev, option, level, sysfs_buff);

	return 0;
}

void
wlTxSkbTest_1(struct net_device *netdev, int pktcnt, int pktsize, int txqid,
	      int frameType)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	struct bqm_args *pbqm_args = &wlpd_p->bmq_args;
	struct wldesc_data *wlqm;
	int qid;
	size_t tx_buf_size;
//      struct sk_buff_head txQTrace;
	struct sk_buff *skb;
//      struct sk_buff *tmp;
	struct sk_buff *pskb;
	wltxdesc_t *cfh_dl;
	wltxdesc_t cfg;
	int i;
	u32 randnum = 0;
	u32 genRandflag = 0;
	int send_size;

	qid = pbqm_args->txq_start_index;
//      skb_queue_head_init(&txQTrace);
	wlqm = &wlpptr->wlpd_p->descData[qid];
	tx_buf_size = 1600;

	WLDBG_DATA(DBG_LEVEL_0, "wlTxSkbTest Start: testing %d pkts \n",
		   pktcnt);

	if (pktsize == 0) {
		genRandflag = 1;	//generate random size
		WLDBG_INFO(DBG_LEVEL_0, "Generating Random Size packet..\n");
	}
	// Allocate the skb to send
	for (i = 0; i < pktcnt; i++) {
		if (genRandflag) {
			randnum = 0;
			do {
				get_random_bytes(&randnum, sizeof(u32));
				randnum %= LONG_PKTSIZE;
			} while (randnum < 64);

			send_size = randnum;
			WLDBG_INFO(DBG_LEVEL_0,
				   "Generate random send size:%u\n", send_size);
		} else
			send_size =
				(pktsize <=
				 LONG_PKTSIZE) ? (pktsize) : LONG_PKTSIZE;

		if (send_size < ETHER_HDR_LEN + IP_HDR_LEN + ICMP_HDR_LEN) {
			send_size = ETHER_HDR_LEN + IP_HDR_LEN + ICMP_HDR_LEN;
		}

		if (frameType == IEEE_TYPE_MANAGEMENT) {
			extern extStaDb_StaInfo_t
				*extStaDb_GetVapStaInfoStn(vmacApInfo_t *
							   vmac_p, UINT8 stnid);
			extern struct sk_buff *mlmeApiPrepMgtMsg2(UINT32
								  Subtype,
								  IEEEtypes_MacAddr_t
								  * DestAddr,
								  IEEEtypes_MacAddr_t
								  * SrcAddr,
								  UINT16 size);
			extern WL_STATUS txMgmtMsg(struct net_device *dev,
						   struct sk_buff *skb);

			struct sk_buff *txSkb_p;
			extStaDb_StaInfo_t *pStaInfo;
			u8 destAddr[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
			u8 *pDestAddr = destAddr;
			u8 *pSrcAddr = vmacSta_p->macStaAddr;

			if (txqid >= 256) {
				pStaInfo =
					extStaDb_GetVapStaInfoStn(vmacSta_p,
								  (txqid -
								   256) / 8);
				if (pStaInfo) {
					pDestAddr = pStaInfo->Addr;
					pSrcAddr = pStaInfo->Bssid;
				}
			}
			txSkb_p =
				mlmeApiPrepMgtMsg2(IEEE_MSG_ASSOCIATE_RQST,
						   (IEEEtypes_MacAddr_t *)
						   pDestAddr,
						   &vmacSta_p->macStaAddr,
						   send_size);
			if (txSkb_p) {
				if ((txMgmtMsg(netdev, txSkb_p)) != OS_SUCCESS)
					wl_free_skb(txSkb_p);
			}
			continue;
		}
		//skb = wl_alloc_skb(tx_buf_size);
		skb = wl_alloc_skb(1600);
		WLDBG_DATA(DBG_LEVEL_4, " wl_alloc_skb(%xh)\n",
			   tx_buf_size + tx_buf_size);
		skb_reserve(skb, (SKB_INFO_SIZE + ETHER_HDR_LEN));	// reserve 8 bytes for skb virtual address and 14 bytes for ether hdr

		skb->data = PTR_ALIGN(skb->data, TXBUF_ALIGN);
		skb->data -= ETHER_HDR_LEN;

		skb_put(skb, send_size);
		//memcpy(skb->data, testpkt, sizeof(testpkt));
		memcpy(skb->data, testpkt, send_size);

		//init the packet
		if (send_size > (ETHER_HDR_LEN + IP_HDR_LEN + ICMP_HDR_LEN)) {
			u32 idx;
			u32 cnt =
				send_size - (ETHER_HDR_LEN + IP_HDR_LEN +
					     ICMP_HDR_LEN);
			u8 *p = (u8 *) (skb->data +
					(ETHER_HDR_LEN + IP_HDR_LEN +
					 ICMP_HDR_LEN));

			for (idx = 0; idx < cnt; idx++)
				p[idx] = (0x08 + idx) & 0xff;
		}
//              skb_queue_tail(&txQTrace, skb);
//              WLDBG_DATA(DBG_LEVEL_0, "%d  skb = %p \n", i, (void*)skb);
//      }

//      WLDBG_INFO(DBG_LEVEL_0, "wlSkbToCfhDl test  \n");

		// Enqueue to TXQ
//      skb_queue_walk_safe(&txQTrace, skb, tmp) {
//              pskb = skb_dequeue(&txQTrace);
		pskb = skb;
		pskb->priority = txqid;
		pskb->dev = netdev;

		memcpy(&pskb->cb[16], testllc, LLC_HDR_LEN);
		InitCFHDL(netdev, pbqm_args, &cfg, pskb);
		cfh_dl = wlSkbToCfhDl(netdev, pskb, &cfg, qid, IEEE_TYPE_DATA);

		// Dump rq, wrptr, rdptr ++
		{
			u32 regval;

			regval = wl_util_readl(netdev, (wlpptr->ioBase1 + SC5_RQ_WRPTR_REG(qid)));
			WLDBG_INFO(DBG_LEVEL_4,
				   "RQ, RQ_WRPTR_REG(%d): %p = %08xh\n", qid,
				   (wlpptr->ioBase1 + SC5_RQ_WRPTR_REG(qid)),
				   regval);
			regval = wl_util_readl(netdev, (wlpptr->ioBase1 + SC5_RQ_RDPTR_REG(qid)));
			WLDBG_INFO(DBG_LEVEL_4,
				   "RQ, RQ_RDPTR_REG(%d): %p = %08xh\n", qid,
				   (wlpptr->ioBase1 + SC5_RQ_RDPTR_REG(qid)),
				   regval);
		}
		// Dump rq, wrptr, rdptr --
		if (cfh_dl != NULL) {
			WLDBG_INFO(DBG_LEVEL_4,
				   "wrinx %d rdinx %d skb = %p ptx = %p cfh_dl %p phy_addr %x \n",
				   wlqm->rq.wrinx, wlqm->rq.rdinx, (void *)pskb,
				   (void *)cfh_dl, cfh_dl->hdr.lo_dword_addr);

		} else {
			WLDBG_WARNING(DBG_LEVEL_1, "Buffer already full...\n");
			wl_free_skb(pskb);
		}
	}

	WLDBG_INFO(DBG_LEVEL_1, "wlTxSkbTest Done \n");
}

void
idx_test(struct net_device *netdev, long pktcnt, long pkt_size, long txqid,
	 long frameType)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;

	wlpd_p->idx_test_arg.qid = txqid;
	wlpd_p->idx_test_arg.pkt_size = pkt_size;
	wlpd_p->idx_test_arg.pkt_cnt = pktcnt;
	wlpd_p->idx_test_arg.frameType = frameType;

	//wlTxSkbTest_1(netdev, pktcnt, pkt_size, txqid);
	wl_util_lock(netdev);
	WLDBG_INFO(DBG_LEVEL_0, "\t txInputCnt = %d\n",
		   wlpptr->smacStatusAddr->txInputCnt);
	WLDBG_INFO(DBG_LEVEL_0, "\t buf_ret_cnt = %d\n",
		   wlpptr->smacStatusAddr->txBufRetCnt);
	wl_util_unlock(netdev);
	WLDBG_INFO(DBG_LEVEL_0, "\t buffer_full_cnt = %d, sent_cnt=%d\n",
		   wlpd_p->drv_stats_val.txq_full_cnt,
		   wlpd_p->drv_stats_val.txq_drv_sent_cnt);
	return;
}

// Set reuse type to "no reuse" as the default value
rpkt_reuse_type g_rpkt_reuse_type = rpkt_reuse_recycle;
extern unsigned int max_recycle_cnt;
void
rpkt_reuse_init(struct sk_buff_head *pqueue)
{
	// => Always init the queue
	// => Remove it once "wlqm->rq.skbTrace" is removed permanently
	skb_queue_head_init(pqueue);

	return;
}

void
rpkt_reuse_push(struct sk_buff_head *pqueue, struct sk_buff *skb)
{
	if ((g_rpkt_reuse_type == rpkt_reuse_no) ||
	    (skb_queue_len(pqueue) > max_recycle_cnt)) {
		wl_free_skb(skb);
		return;
	}
	spin_lock(&pqueue->lock);
	__skb_queue_tail(pqueue, skb);
	spin_unlock(&pqueue->lock);

	return;
}

struct sk_buff *
rpkt_resue_get(struct sk_buff_head *pqueue)
{
	struct sk_buff *skb_tmp;
	struct sk_buff *skb = NULL;

	if (g_rpkt_reuse_type == rpkt_reuse_no) {
		return skb;
	}
	spin_lock(&pqueue->lock);
	skb_queue_walk(pqueue, skb_tmp) {
		if (atomic_read(&skb_shinfo(skb_tmp)->dataref) == 1) {
			__skb_unlink(skb_tmp, pqueue);
			skb = skb_tmp;
			WLDBG_DATA(DBG_LEVEL_3,
				   "CFHUL: find skb %p skb->data %p \n", skb,
				   skb->data);
			break;
		}
	}
	spin_unlock(&pqueue->lock);
	return skb;
}

void
rpkt_reuse_flush(struct sk_buff_head *pqueue)
{
	struct sk_buff *skb;

	if (g_rpkt_reuse_type == rpkt_reuse_no) {
		return;
	}
	while ((skb = skb_dequeue(pqueue)) != NULL) {
		WLDBG_INFO(DBG_LEVEL_4, "\t free skb(%p)\n", skb);
		wl_free_skb(skb);
	}
	return;
}

void
rpkt_reuse_free_resource(struct sk_buff_head *pqueue, u32 * plast_qlen,
			 u32 threshold)
{
	u8 i;
	u32 qlen = skb_queue_len(pqueue);

	if ((qlen > threshold) && (qlen < *plast_qlen)
		) {
		// Reduce the recycle_queue if:
		//      a) queue_length > threshold (= buf_pool_max_entries)
		//      b) queue_length < the last queue_length => No need to keep so man buffers
		//printk("%s(), (qlen_last, threshold, qlen)=(%u, %u, %u)\n", __func__, *plast_qlen, threshold, qlen);
		for (i = 0; i < (threshold >> 3); i++) {
			// Free buf_pool_max_entries[i-SC5_BMQ_NUM]/8 a time
			wl_free_skb(rpkt_resue_get(pqueue));
		}
	}
	*plast_qlen = qlen;
	return;
}
