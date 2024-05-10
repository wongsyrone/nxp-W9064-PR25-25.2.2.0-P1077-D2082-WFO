/** @file ba.c
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
#include "ipc.h"
#include "ipc_msg.h"
#include "ba.h"

#ifdef BA_REORDER

//#define DEBUG_BAREORDER

#ifdef DEBUG_BAREORDER
#define DBG_BAREORDER_SN_MASK    0x3
#define DBG_BAREORDER_OOR_MASK   0x3F

#define DEBUG_REORDER_PRINT(x)          printf x

#define DBG_BAREORDER_SN(i,t,l,b,s)    \
	{   \
		if(dbg_BAredr_id == i)  \
		{   \
			(dbg_BAredr_id == i)?(dbg_BAredr_SN[dbg_BAredr_SN_cnt++ & DBG_BAREORDER_SN_MASK] = (t<<28)|(l<<24)|(b<12)|s) : (t=t);  \
			dbg_BAredr_SN[dbg_BAredr_SN_cnt & DBG_BAREORDER_SN_MASK] = 0xdeadbeef; \
		}   \
	}

#define DBG_BAREORDER_OOR(i,t,l,b,s)   \
	{   \
	if(dbg_BAredr_id == i)  \
		{   \
		if(dbg_BAredr_OOR_cont && (dbg_BAredr_OOR_cnt < (DBG_BAREORDER_OOR_MASK-5))) \
		{   \
			dbg_BAredr_OOR[dbg_BAredr_OOR_cnt++ & DBG_BAREORDER_OOR_MASK] = (t<<28)|(b<<12)|(s);    \
			dbg_BAredr_OOR[dbg_BAredr_OOR_cnt++ & DBG_BAREORDER_OOR_MASK] = 0;                      \
			dbg_BAredr_OOR[dbg_BAredr_OOR_cnt++ & DBG_BAREORDER_OOR_MASK] = 0;                      \
			dbg_BAredr_OOR[dbg_BAredr_OOR_cnt++ & DBG_BAREORDER_OOR_MASK] = l;                      \
			dbg_BAredr_OOR[dbg_BAredr_OOR_cnt & DBG_BAREORDER_OOR_MASK] = 0xdeadbeef;               \
		}   \
		dbg_BAredr_OOR_cont = 0;    \
		}   \
	}

ca_uint32_t dbg_BAredr_id = 0;

//Log for incoming seqno for history keeping. Used in out of range BA reorder logging
ca_uint32_t dbg_BAredr_SN[DBG_BAREORDER_SN_MASK + 1];	//b31-28:tid, b27-24:location of code, b23-12: winStartB, b11-0:incoming seqno
ca_uint32_t dbg_BAredr_SN_cnt = 0;

//Log for out of range BA reorder, each record takes 4 DWORD
//1st DW: OOR of incoming, 2nd DW to 4th DW: previous seqno of last 3 incoming seqno
ca_uint32_t dbg_BAredr_OOR[DBG_BAREORDER_OOR_MASK + 1];
ca_uint32_t dbg_BAredr_OOR_cnt = 0;
ca_uint32_t dbg_BAredr_OOR_cont = 0;	//continous out of range count 
#else
#define DEBUG_REORDER_PRINT(x)
#define DBG_BAREORDER_SN(i,t,l,b,s)
#define DBG_BAREORDER_OOR(i,t,l,b,s)
#endif

struct list ba_timer_list;
int ba_msdu_pkt_num = 0;

ca_uint16_t reorder_hold_time = (200 * TIMER_1MS);	//(HZ / 2) //200ms   

void
ba_amsdu_head_init(struct list *pPktHead)
{
	list_init(pPktHead);

	return;
}

void
ba_amsdu_head_purge(ca_uint16_t rid, struct list *pPktHead)
{
	struct radio *radio = &radio_info[rid - 1];
	struct ba_msdu_pkt *ba_msdu;
	struct pkt_hdr *pkt;

	while ((ba_msdu =
		(struct ba_msdu_pkt *)list_get_item(pPktHead)) != NULL) {
		pkt = ba_msdu->pkt;
		list_put_item(&(radio->ba_msdu_pkt_free_list),
			      (struct list_item *)ba_msdu);
		radio->dbg_cnt.pkt_cnt.pkt_amsdu_free++;
		pkt_free_data(rid, pkt, __func__);
	}
	list_init(pPktHead);

	return;
}

void
ba_free_any_pending_ampdu_pkt(ca_uint16_t rid, ca_uint16_t stn_id)
{
	struct radio *radio = &radio_info[rid - 1];
	int i, j;
	struct ampdu_pkt_reorder *baRxInfo;

	baRxInfo = &radio->ampdu_ba_reorder[stn_id];
	for (i = 0; i < SYSADPT_MAX_TID; i++) {
		if (baRxInfo->ba[i].storedBufCnt != 0) {
			for (j = 0; j < MAX_BA_REORDER_BUF_SIZE; j++) {
				ba_amsdu_head_purge(rid,
						    &baRxInfo->ba[i].AmsduQ[j].
						    msdu_list);
				baRxInfo->ba[i].AmsduQ[i].state = 0;
			}
		}
		baRxInfo->ba[i].storedBufCnt = 0;
		baRxInfo->ba[i].leastSeqNo = 0;
		baRxInfo->ba[i].winStartB = 0;
		baRxInfo->ba[i].winSizeB = 0;
		baRxInfo->ba[i].minTime = 0;
	}
}

int
ba_init(ca_uint16_t rid)
{
	struct radio *radio = &radio_info[rid - 1];
	int i, j, k;

	for (i = 0; i < SYSADPT_MAX_STA; i++) {
		memset((void *)radio->ampdu_ba_reorder[i].ba, 0,
		       (SYSADPT_MAX_TID * sizeof(struct ba_rx_st)));
		memset((void *)radio->ampdu_ba_reorder[i].AddBaReceive, 0,
		       (SYSADPT_MAX_TID * sizeof(ca_uint8_t)));

		for (j = 0; j < SYSADPT_MAX_TID; j++) {
			for (k = 0; k < MAX_BA_REORDER_BUF_SIZE; k++)
				ba_amsdu_head_init(&radio->ampdu_ba_reorder[i].
						   ba[j].AmsduQ[k].msdu_list);
		}
	}

	list_init(&ba_timer_list);
	list_init(&(radio->ba_msdu_pkt_free_list));
	radio->dbg_cnt.pkt_cnt.pkt_amsdu_alloc = 0;
	radio->dbg_cnt.pkt_cnt.pkt_amsdu_free = 0;
	radio->dbg_cnt.pkt_cnt.pkt_amsdu_lack = 0;

	radio->ba_msdu_pkt_p =
		(struct ba_msdu_pkt *)MALLOC_CACHE(ba_msdu_pkt_num *
						   sizeof(struct ba_msdu_pkt));
	if (radio->ba_msdu_pkt_p) {
		for (i = 0; i < ba_msdu_pkt_num; i++) {
			memset((radio->ba_msdu_pkt_p + i), 0,
			       sizeof(struct ba_msdu_pkt));
			list_put_item(&(radio->ba_msdu_pkt_free_list),
				      (struct list_item *)(radio->
							   ba_msdu_pkt_p + i));
			radio->dbg_cnt.pkt_cnt.pkt_amsdu_free++;
		}
		printf("\t ba_msdu_pkt_free_list: %d, size: %d\n",
		       ba_msdu_pkt_num, (int)sizeof(struct ba_msdu_pkt));
	} else {
		goto no_mem;
	}

	return 0;

no_mem:
	printf("\t %s(%d): fail to alloc memory for ba_msdu_pkt_p, size = %d\n",
	       __func__, rid,
	       (int)(ba_msdu_pkt_num * sizeof(struct ba_msdu_pkt)));

	return -ENOMEM;
}

int
ba_deinit(ca_uint16_t rid)
{
	struct radio *radio = &radio_info[rid - 1];

	if (radio->ba_msdu_pkt_p) {
		MFREE(radio->ba_msdu_pkt_p);
	}

	return 0;
}

void
ba_cmd_assoc(ca_uint16_t rid, ca_uint16_t stn_id)
{
	struct radio *radio = &radio_info[rid - 1];
	int i;

	//printf("%s: rid = %d, stn_id = %d\n", __func__, rid, stn_id);

	ba_free_any_pending_ampdu_pkt(rid, stn_id);
	for (i = 0; i < SYSADPT_MAX_TID; i++) {
/** Reset the ampdu reorder pck anyway **/
		radio->ampdu_ba_reorder[stn_id].AddBaReceive[i] = false;  /** clear Ba flag **/
	}

	return;
}

void
ba_cmd_addba(ca_uint16_t rid, ca_uint16_t stn_id, ca_uint16_t tid,
	     ca_uint16_t winStartB, ca_uint16_t winSizeB)
{
	struct radio *radio = &radio_info[rid - 1];
	int i;
	struct ampdu_pkt_reorder *baRxInfo;

	//printf("%s: rid = %d, stn_id = %d, tid = %d, winStartB = %d, winSizeB = %d\n", __func__, rid, stn_id, tid, winStartB, winSizeB);

	baRxInfo = &radio->ampdu_ba_reorder[stn_id];

	baRxInfo->AddBaReceive[tid] = true;

	if (baRxInfo->timer_init[tid] == 0) {
		list_remove_item(&ba_timer_list,
				 (struct list_item *)&baRxInfo->timer[tid]);
		memset(&baRxInfo->timer[tid], 0, sizeof(struct ba_timer));
		baRxInfo->timer[tid].stn_id = stn_id;
		baRxInfo->timer[tid].tid = tid;
		baRxInfo->timer[tid].exp_time = 0;
		baRxInfo->timer[tid].vif = NULL;	//Will be filled in BA_TimerActivateCheck()

		baRxInfo->timer_init[tid] = 1;
	}

	for (i = 0; i < MAX_BA_REORDER_BUF_SIZE; i++) {
		ba_amsdu_head_purge(rid,
				    &baRxInfo->ba[tid].AmsduQ[i].msdu_list);
		baRxInfo->ba[tid].AmsduQ[i].state = 0;
	}

	baRxInfo->ba[tid].winStartB = winStartB;
	baRxInfo->ba[tid].winSizeB = winSizeB;
	baRxInfo->ba[tid].storedBufCnt = 0;
	baRxInfo->ba[tid].leastSeqNo = 0;
	baRxInfo->ba[tid].minTime = 0;

	DEBUG_REORDER_PRINT(("ADDBA seqno %d, tid %d\n",
			     baRxInfo->ba[tid].winStartB, tid));

	return;
}

void
ba_cmd_delba(ca_uint16_t rid, ca_uint16_t stn_id, ca_uint16_t tid,
	     ca_uint16_t winStartB, ca_uint16_t winSizeB)
{
	struct radio *radio = &radio_info[rid - 1];
	int i;
	struct ampdu_pkt_reorder *baRxInfo;

	//printf("%s: rid = %d, stn_id = %d, tid = %d, winStartB = %d, winSizeB = %d\n", __func__, rid, stn_id, tid, winStartB, winSizeB);

	baRxInfo = &radio->ampdu_ba_reorder[stn_id];

	baRxInfo->AddBaReceive[tid] = false;
	for (i = 0; i < MAX_BA_REORDER_BUF_SIZE; i++) {
		ba_amsdu_head_purge(rid,
				    &baRxInfo->ba[tid].AmsduQ[i].msdu_list);
		baRxInfo->ba[tid].AmsduQ[i].state = 0;
	}

	baRxInfo->ba[tid].winStartB = 0;
	baRxInfo->ba[tid].winSizeB = 0;
	baRxInfo->ba[tid].storedBufCnt = 0;
	baRxInfo->ba[tid].leastSeqNo = 0;
	baRxInfo->ba[tid].minTime = 0;

	return;
}

//Function to handle tasklet call for BA reorder
void
BA_TimerProcess(ca_uint16_t rid, struct ba_timer *tm)
{
	struct radio *radio = &radio_info[rid - 1];
	struct ampdu_pkt_reorder *baRxInfo;
	ca_uint32_t leastSeqNo, BufCnt, dropCnt;
	ca_uint16_t tid;
	ca_uint16_t stn_id;
	struct vif *vif;

	if (tm == NULL) {
		printf("%s: tm == NULL\n", __func__);
		return;
	}

	stn_id = tm->stn_id;
	if (stn_id >= SYSADPT_MAX_STA) {
		printf("%s: stn_id >= SYSADPT_MAX_STA\n", __func__);
		return;
	}

	baRxInfo = &radio->ampdu_ba_reorder[stn_id];
	tid = tm->tid;

	//SPIN_LOCK(&baRxInfo->ba[tid].BAreodrLock);

	if (JIFFIES - baRxInfo->ba[tid].minTime >=
	    (ca_uint32_t) reorder_hold_time) {
		leastSeqNo = baRxInfo->ba[tid].leastSeqNo & 0xFFFF;
		BufCnt = baRxInfo->ba[tid].storedBufCnt;

		if (BufCnt != 0) {
			if (baRxInfo->ba[tid].winStartB <= leastSeqNo) {
				dropCnt =
					leastSeqNo -
					baRxInfo->ba[tid].winStartB;
				//vmacSta_p->BA_RodrTMODropCnt += dropCnt;
				//ro_p->pStaInfo->rxBaStats[tid].BA_RodrTMODropCnt += dropCnt;
			} else {
				dropCnt =
					((BA_MAX_SEQ_NUM + 1) -
					 baRxInfo->ba[tid].winStartB) +
					leastSeqNo;
				//vmacSta_p->BA_RodrTMODropCnt += dropCnt;
				//ro_p->pStaInfo->rxBaStats[tid].BA_RodrTMODropCnt += dropCnt;
			}

			//Flush starting from least seqno in buf until 1st hole
			vif = tm->vif;
			baRxInfo->ba[tid].winStartB = BA_flushSequencialData(rid, vif, &baRxInfo->ba[tid], ((leastSeqNo << 16) | BufCnt)	/*, &ro_p->pStaInfo->pn->ucRxQueues[tid], 
																		   &wlexcept_p->badPNcntUcast,
																		   &wlpptr->wlpd_p->drv_stats_val.rx_data_ucast_pn_pass_cnt,
																		   tid */
									     );

			DBG_BAREORDER_SN(stn_id, tid, 7,
					 baRxInfo->ba[tid].winStartB,
					 leastSeqNo)
				//After flush still have pkt, trigger timer
				if (baRxInfo->ba[tid].storedBufCnt != 0) {
				baRxInfo->ba[tid].minTime = JIFFIES;

				//ba_timer_list must be in ascending order to the exp_time.
				baRxInfo->timer[tid].exp_time =
					JIFFIES + reorder_hold_time;
				list_put_item(&ba_timer_list,
					      (struct list_item *)&baRxInfo->
					      timer[tid]);
				//printf("%s: Add ba_timer #1: tid=%d, curr=%lu, exp_time=%lu\n", __func__, tid, JIFFIES, baRxInfo->timer[tid].exp_time);

				//SPIN_UNLOCK(&baRxInfo->ba[tid].BAreodrLock);
				return;
			} else {
				baRxInfo->ba[tid].minTime = 0;
			}
		} else {
			baRxInfo->ba[tid].minTime = 0;
		}
	} else {
		//ba_timer_list must be in ascending order to the exp_time.
		baRxInfo->timer[tid].exp_time = JIFFIES + reorder_hold_time;
		list_put_item(&ba_timer_list,
			      (struct list_item *)&baRxInfo->timer[tid]);
		//printf("%s: Add ba_timer #2: tid=%d, curr=%lu, exp_time=%lu\n", __func__, tid, JIFFIES, baRxInfo->timer[tid].exp_time);

		//SPIN_UNLOCK(&baRxInfo->ba[tid].BAreodrLock);
		return;
	}

	//SPIN_UNLOCK(&baRxInfo->ba[tid].BAreodrLock);

	return;
}

//Decide whether to add timer after a flush
//StoreFlag: 0-This function is called after a flush. 1-After a fresh skb store
void
BA_TimerActivateCheck(struct ampdu_pkt_reorder *baRxInfo,
		      ca_uint8_t tid, ca_uint32_t SeqNo, ca_uint8_t StoreFlag,
		      struct vif *vif)
{
	if (baRxInfo->ba[tid].storedBufCnt != 0) {
		if (StoreFlag) {
			//Update oldest time in buffer
			if (baRxInfo->ba[tid].minTime == 0) {
				baRxInfo->ba[tid].minTime = JIFFIES;
			} else if (JIFFIES < baRxInfo->ba[tid].minTime) {
				baRxInfo->ba[tid].minTime = JIFFIES;
			}
		} else {
			baRxInfo->ba[tid].minTime = JIFFIES;	//save current jiffies, but could be improved to find oldest pkt in buf. Just need more procesing
		}

		//If timer not called yet, add to timer
		if (list_search_item
		    (&ba_timer_list,
		     (struct list_item *)&baRxInfo->timer[tid]) == NULL) {
			//ba_timer_list must be in ascending order to the exp_time.
			baRxInfo->timer[tid].vif = vif;
			baRxInfo->timer[tid].exp_time =
				JIFFIES + reorder_hold_time;
			list_put_item(&ba_timer_list,
				      (struct list_item *)&baRxInfo->
				      timer[tid]);
			//printf("%s: Add ba_timer: tid=%d, curr=%lu, exp_time=%lu\n", __func__, tid, JIFFIES, baRxInfo->timer[tid].exp_time);
		}
	} else			//buffer has no more pkt
	{
		baRxInfo->ba[tid].minTime = 0;
		list_remove_item(&ba_timer_list,
				 (struct list_item *)&baRxInfo->timer[tid]);
	}

	return;
}

//Funtion to decide whether to move reorder window or drop pkt.
//Return 0 to drop
ca_uint32_t
BA_getSeqDelta(ca_uint32_t wEnd_endExt, ca_uint32_t winStartB,
	       ca_uint32_t seqNum, ca_uint32_t winSizeB_minus1)
{
	ca_uint32_t seqDelta = 0;	// Default Drop
	ca_uint32_t wEnd = (wEnd_endExt >> 16) & 0xFFFF;
	ca_uint32_t endExt = wEnd_endExt & 0xFFFF;

	if (wEnd < winStartB)	// (I) Window is wrapped and Extended Window is not wrapped
	{
		if (winStartB < seqNum)	// winStartB = SN filtered above // a) winStartB <= SN - OR -
		{
			seqDelta = seqNum - winStartB;
		} else if (seqNum <= wEnd)	// a) SN <= winEndB
		{
			seqDelta = seqNum + (1 + BA_MAX_SEQ_NUM) - winStartB;	// (SN+1)+(4095-winStartB)
		} else {
			if ((wEnd < seqNum) && (seqNum < endExt))	// b) winEndB < SN < winStartB+2^11
			{
				seqDelta = (seqNum - wEnd) + winSizeB_minus1;
			}
		}
	} else			// if (wEnd > wStart)  // (II) Window is NOT wrapped
	{
		if ((winStartB < seqNum) && (seqNum <= wEnd))	// a) winStartB <= SN <= winEndB
		{
			seqDelta = seqNum - winStartB;
		} else if (wEnd < endExt)	// Extended Window is not wrapped
		{
			if ((wEnd < seqNum) && (seqNum < endExt))	// b) winEndB < SN < winStartB+2^11
			{
				seqDelta = (seqNum - wEnd) + winSizeB_minus1;
			}
		} else		// Extended Window is wrapped
		{
			if (wEnd < seqNum)	// b) winEndB < SN  - OR -
			{
				seqDelta = (seqNum - wEnd) + winSizeB_minus1;
			} else if (seqNum < endExt)	// b) 0 <= SN < winStartB+2^11
			{
				seqDelta = (seqNum + (1 + BA_MAX_SEQ_NUM) - wEnd) + winSizeB_minus1;	// (SN+1)+(4095-wEnd)
			}
		}
	}

	//printf("seqDelta=%d\n", seqDelta);
	return seqDelta;
}

//Function to send pkt to host from reorder buffer
ca_uint32_t
BA_send2host(ca_uint16_t rid, struct vif * vif, struct pkt_hdr * pkt)
{
	struct radio *radio = &radio_info[rid - 1];

	if (pkt != NULL) {
		if (radio->dbg_ctrl & DBG_PKT_TO_HOST) {
			wlSendPktToHost(radio, pkt, true, NULL);
			radio->dbg_cnt.rx_cnt.data_pkt_to_host++;
		} else {
#ifdef DBG_BM_BUF_MONITOR
			dbg_check_buf(radio->rid, pkt, __func__);
#endif
			eth_xmit_pkt(vif->eth_handle, pkt, pkt->data, pkt->len);
			radio->dbg_cnt.rx_cnt.data_pkt_to_eth++;
		}
	} else {
		return 0;
	}
	return 1;
}

//Check duplicate pkt of an amsduQ buffer for BA reorder and store skb if needed
//state: 0, 1st msdu not received yet, expecting 1st msdu
//state: 1, 1st msdu already received, expecting mid or last msdu
//state: 2, last msdu already received, not expecting anymore msdu
//LMFbit: b2-Last msdu, b1-Mid msdu, b0-First msdu
ca_uint8_t
BA_CheckAmsduDup(ca_uint16_t rid, struct ba_rx_st * baRxInfo,
		 ca_uint16_t bufIndex, struct pkt_hdr * pkt,
		 ca_uint8_t LMFbit
		 /*, rx_queue_t *rq, UINT8 wep, UINT16 SeqNo, UINT8 *pn */ )
{
	struct radio *radio = &radio_info[rid - 1];
	struct ba_msdu_pkt *ba_msdu = NULL;

	//Last amsdu already encountered, all incoming is considered duplicate
	if (baRxInfo->AmsduQ[bufIndex].state == 2) {
		//printf("%s: 1\n", __func__);
		return 1;	//duplicate
	}
	//amsduQ buffer is empty and incoming is 1st msdu
	if ((baRxInfo->AmsduQ[bufIndex].state == 0) && (LMFbit & 0x1)) {
		if (LMFbit & 0x4)
			baRxInfo->AmsduQ[bufIndex].state = 2;	//last msdu received
		else
			baRxInfo->AmsduQ[bufIndex].state = 1;	//1st msdu received, expecting mid or last msdu

#if 0				//def RX_REPLAY_DETECTION
		if (wep && pn) {
			//Store PN values
			baRxInfo->pn_check_enabled = true;
			DOT11_SETPN(rq->Slots[bufIndex].PN, pn);
			rq->Slots[bufIndex].SeqNr = SeqNo;
		}
#endif

		//skb_queue_tail(&baRxInfo->AmsduQ[bufIndex].skbHead, skb);
		ba_msdu =
			(struct ba_msdu_pkt *)
			list_get_item(&(radio->ba_msdu_pkt_free_list));
		if (ba_msdu) {
			radio->dbg_cnt.pkt_cnt.pkt_amsdu_free--;
			radio->dbg_cnt.pkt_cnt.pkt_amsdu_alloc++;
			ba_msdu->pkt = pkt;
			list_put_item(&baRxInfo->AmsduQ[bufIndex].msdu_list,
				      (struct list_item *)ba_msdu);
		} else {
			radio->dbg_cnt.pkt_cnt.pkt_amsdu_lack++;
		}

		baRxInfo->storedBufCnt++;	//Only increase cnt if 1st msdu added to buffer

		//printf("%s: 0\n", __func__);
		return 0;
	}
	//amsduQ has 1st msdu and expecting mid or last msdu
	if ((baRxInfo->AmsduQ[bufIndex].state == 1) && (LMFbit & 0x6)) {
		if (LMFbit & 0x4)
			baRxInfo->AmsduQ[bufIndex].state = 2;	//last msdu received

		//skb_queue_tail(&baRxInfo->AmsduQ[bufIndex].skbHead, skb);    
		ba_msdu =
			(struct ba_msdu_pkt *)
			list_get_item(&(radio->ba_msdu_pkt_free_list));
		if (ba_msdu) {
			radio->dbg_cnt.pkt_cnt.pkt_amsdu_free--;
			radio->dbg_cnt.pkt_cnt.pkt_amsdu_alloc++;
			ba_msdu->pkt = pkt;
			list_put_item(&baRxInfo->AmsduQ[bufIndex].msdu_list,
				      (struct list_item *)ba_msdu);
		} else {
			radio->dbg_cnt.pkt_cnt.pkt_amsdu_lack++;
		}

		//printf("%s: 0\n", __func__);
		return 0;
	}
	//printf("%s: 1\n", __func__);
	return 1;		//duplicate pkt
}

//Function to flush msdu_list
void
BA_flushAmsduQ(ca_uint16_t rid, struct vif *vif, struct amsduQ_st *AmsduQ,
	       ca_uint8_t fwdPkt, ca_uint16_t index)
{
	struct radio *radio = &radio_info[rid - 1];
	struct ba_msdu_pkt *ba_msdu;
	struct pkt_hdr *pkt;

	while ((ba_msdu =
		(struct ba_msdu_pkt *)list_get_item(&AmsduQ->msdu_list)) !=
	       NULL) {
		pkt = ba_msdu->pkt;
		list_put_item(&(radio->ba_msdu_pkt_free_list),
			      (struct list_item *)ba_msdu);
		radio->dbg_cnt.pkt_cnt.pkt_amsdu_free++;

		if (fwdPkt) {
			BA_send2host(rid, vif, pkt);
		} else {
			pkt_free_data(rid, pkt, __func__);	//drop PN check failed pkt
		}
	}
	AmsduQ->state = 0;

#ifdef CORTINA_TUNE
	eth_xmit_pkt_flush();
#endif

	return;
}

//Function to flush reorder buffer starting from winStartB to the 1st encountered hole in buffer
ca_uint32_t
BA_flushSequencialData(ca_uint16_t rid, struct vif * vif,
		       struct ba_rx_st * baRxInfo,
		       ca_uint32_t winStartB_BufCnt
		       /*, rx_queue_t * rq, UINT32 *badPNcnt, UINT32 *passPNcnt, UINT8 tid */
		       )
{
	ca_uint32_t sendMpduNum = 0, cnt = 0;
	ca_uint16_t index, winStartB, storedBufCnt;
	ca_uint8_t fwdPkt = true;

	storedBufCnt = winStartB_BufCnt & 0xFFFF;
	winStartB = (winStartB_BufCnt >> 16) & 0xFFFF;

	if (storedBufCnt != 0) {
		index = winStartB % MAX_BA_REORDER_BUF_SIZE;

		while (baRxInfo->AmsduQ[index].state >= 2) {
#if 0				//def RX_REPLAY_DETECTION
			fwdPkt = pn_aggregate_check(pStaInfo, baRxInfo, rq,
						    index, badPNcnt, passPNcnt);
#endif
			BA_flushAmsduQ(rid, vif, &baRxInfo->AmsduQ[index],
				       fwdPkt, index);

			sendMpduNum++;
			if (index == (MAX_BA_REORDER_BUF_SIZE - 1)) {
				index = 0;
			} else {
				index++;
			}
		}
		storedBufCnt -= sendMpduNum;
		winStartB += sendMpduNum;
	}

	if (storedBufCnt == 0) {
		baRxInfo->storedBufCnt = 0;
	} else			// Find next available buffer's SN number
	{
		ca_uint16_t nextSN = winStartB;
		do {
			if (index == (MAX_BA_REORDER_BUF_SIZE - 1)) {
				index = 0;
			} else {
				index++;
			}
			nextSN++;

			if (++cnt > MAX_BA_REORDER_BUF_SIZE) {
				break;
			}
		} while (baRxInfo->AmsduQ[index].state == 0);

		//Protection in case storedBufCnt is not zero but there is no pkt in buf after looping all
		if (cnt > MAX_BA_REORDER_BUF_SIZE) {
			DEBUG_REORDER_PRINT(("BA rodr: FSeq no least seqno. Should not happen\n"));

			baRxInfo->storedBufCnt = 0;
			baRxInfo->leastSeqNo = 0;
		} else {
			baRxInfo->leastSeqNo = (nextSN & BA_MAX_SEQ_NUM);
			baRxInfo->storedBufCnt = storedBufCnt;
		}
	}

	return ((winStartB & BA_MAX_SEQ_NUM));
}

//Function to flush any pkt before seqno minus (winSizeB-1). Then flush from new winStartB to 1st encountered hole.
//The objective is move buffer window.
//Before: winStartB<----[64 buf]----->winEnd-----------seqno
//After:   -----------winStartB<----[64 buf or less]----->seqno
ca_uint32_t
BA_flushAnyData(ca_uint16_t rid, struct vif * vif, struct ba_rx_st * baRxInfo, ca_uint32_t BufCnt_least_winStartB, ca_uint32_t winSizeB_Delta	/*, rx_queue_t *rq,
																		   UINT32 *badPNcnt, UINT32 *passPNcnt,  UINT8 tid */ )
{
	ca_uint32_t storedMpduNum, leastSN;
	ca_uint32_t advanceDelta;
	ca_uint32_t sendMpduNum = 0, cnt = 0;
	ca_uint32_t winStartB, winSizeB, winDelta;
	ca_uint32_t index;
	ca_uint32_t fwdPkt = true;

	winStartB = BufCnt_least_winStartB & 0xFFF;
	leastSN = (BufCnt_least_winStartB >> 12) & 0xFFF;
	storedMpduNum = (BufCnt_least_winStartB >> 24) & 0xFF;

	winDelta = winSizeB_Delta & 0xFFFF;
	winSizeB = (winSizeB_Delta >> 16) & 0xFFFF;

	// get the start scanning SN based on the least SN of stored buffers
	if (winStartB > leastSN)	// rollover
	{
		advanceDelta = (BA_MAX_SEQ_NUM + 1) - winStartB + leastSN;
	} else {
		advanceDelta = leastSN - winStartB;
	}
	if (advanceDelta > winDelta)	// No available buffers up to New winStartB(inc.)
	{
		return (((winStartB + winDelta) & BA_MAX_SEQ_NUM));	// New winStartB
	}
	// Move starting SN to reduce unnecessary scan
	index = ((winStartB +
		  advanceDelta) & BA_MAX_SEQ_NUM) % MAX_BA_REORDER_BUF_SIZE;
	winStartB += winDelta;	// Advance to New winStartB to release winDelta register ASAP

	if ((storedMpduNum - 1) == 0)	// Only one
	{
		//if(baRxInfo->AmsduQ[index].state != 0)      //Not needed, just dequeue and flush
		{
#if 0				//def RX_REPLAY_DETECTION
			fwdPkt = pn_aggregate_check(pStaInfo, baRxInfo, rq,
						    index, badPNcnt, passPNcnt);
#endif
			BA_flushAmsduQ(rid, vif, &baRxInfo->AmsduQ[index],
				       fwdPkt, index);

			baRxInfo->storedBufCnt = 0;
			return ((winStartB & BA_MAX_SEQ_NUM));	// New winStartB
		}
	}

	if (advanceDelta < winDelta)	// there may be available buffers before New winStartB
	{
		ca_uint32_t scanNum;

		if (winDelta > winSizeB) {
			scanNum = winSizeB - advanceDelta;
		} else {
			scanNum = winDelta - advanceDelta;
		}
		while (scanNum--) {
			//For pkt in buffer from advance delta to win delta, just flush to host. No need to check whether rx last pkt of AMSDU (state 2)
			if (baRxInfo->AmsduQ[index].state != 0) {
#if 0				//def RX_REPLAY_DETECTION
				fwdPkt = pn_aggregate_check(pStaInfo, baRxInfo,
							    rq, index, badPNcnt,
							    passPNcnt);
#endif
				BA_flushAmsduQ(rid, vif,
					       &baRxInfo->AmsduQ[index], fwdPkt,
					       index);
				sendMpduNum++;

				if (--storedMpduNum == 0) {
					break;
				}
			} else {
				//vmacSta_p->BA_RodrFlushDropCnt++;
				//pStaInfo->rxBaStats[tid].BA_RodrFlushDropCnt++;
			}
			if (index == (MAX_BA_REORDER_BUF_SIZE - 1)) {
				index = 0;
			} else {
				index++;
			}
		}
	}
	// Now index is pointing new winStartB(winStartB + winDelta)
	if (storedMpduNum != 0)	// Still more left
	{
		ca_uint32_t sendMpduNum2 = 0;
		// Find next consecutive MPDU buffers
		index = (winStartB & BA_MAX_SEQ_NUM) % MAX_BA_REORDER_BUF_SIZE;

		while (baRxInfo->AmsduQ[index].state >= 2) {
#if 0				//def RX_REPLAY_DETECTION
			fwdPkt = pn_aggregate_check(pStaInfo, baRxInfo, rq,
						    index, badPNcnt, passPNcnt);
#endif
			BA_flushAmsduQ(rid, vif, &baRxInfo->AmsduQ[index],
				       fwdPkt, index);
			sendMpduNum2++;
			if (index == (MAX_BA_REORDER_BUF_SIZE - 1)) {
				index = 0;
			} else {
				index++;
			}
		}

		storedMpduNum -= sendMpduNum2;
		sendMpduNum += sendMpduNum2;
		winStartB += sendMpduNum2;
	}

	if (storedMpduNum == 0) {
		baRxInfo->storedBufCnt = 0;
	} else			// Find next available buffer's SN number
	{
		ca_uint32_t nextSN = winStartB & BA_MAX_SEQ_NUM;

		index = nextSN % MAX_BA_REORDER_BUF_SIZE;
		do {
			if (index == (MAX_BA_REORDER_BUF_SIZE - 1)) {
				index = 0;
			} else {
				index++;
			}
			nextSN++;

			if (++cnt > MAX_BA_REORDER_BUF_SIZE) {
				break;
			}
		} while (baRxInfo->AmsduQ[index].state == 0);

		//Protection in case storedBufCnt is not zero but there is no pkt in buf after looping all
		if (cnt > MAX_BA_REORDER_BUF_SIZE) {
			DEBUG_REORDER_PRINT(("BA rodr: FAny no least seqno. Should not happen\n"));

			baRxInfo->storedBufCnt = 0;
			baRxInfo->leastSeqNo = 0;
		} else {
			baRxInfo->leastSeqNo = (nextSN & BA_MAX_SEQ_NUM);
			baRxInfo->storedBufCnt = storedMpduNum;
		}
	}

	return ((winStartB & BA_MAX_SEQ_NUM));
}

// Check condition c) if winStartB+2^11 =< SN < winStartB in 802.11-2012 p.914
ca_uint8_t
BA_chkSnValid(ca_uint32_t SN, ca_uint32_t winStartB)
{
	if ((winStartB + 2048) > BA_MAX_SEQ_NUM)	// Round up
	{
		if ((SN >= ((winStartB + 2048) & BA_MAX_SEQ_NUM)) &&
		    (SN < winStartB))
			return 1;	// Drop
	} else if ((SN < winStartB) || (SN >= (winStartB + 2048))) {
		return 1;
	}
	return 0;
}

void
ba_reorder_proc(ca_uint16_t rid, struct vif *vif, ca_uint16_t stn_id,
		ca_uint16_t tid, ca_uint16_t seq, struct pkt_hdr *pkt,
		IEEEtypes_FrameCtl_t * frame_ctrl, ca_uint8_t LMFbit)
{
	struct radio *radio = &radio_info[rid - 1];
	ca_uint8_t isBcastPkt = false;	//TBD: for STA mode

#if 1
	struct ampdu_pkt_reorder *baRxInfo;

	baRxInfo = &radio->ampdu_ba_reorder[stn_id];

	//printf("tid=%d, seq=%d, LMF=%d, AddBaReceive=%d, Subtype=%d\n", tid, seq, LMFbit, baRxInfo->AddBaReceive[tid], frame_ctrl->Subtype);

	//If QoS station and ADDBA is done
	if ((tid < SYSADPT_MAX_TID) && (baRxInfo->AddBaReceive[tid] == true)) {
		//SPIN_LOCK(&baRxInfo->ba[tid].BAreodrLock);
		//Unicast and QoS pkt
		if (!isBcastPkt && ((frame_ctrl->Subtype == QoS_DATA) ||
				    (frame_ctrl->Subtype == QoS_DATA_CF_ACK) ||
				    (frame_ctrl->Subtype == QoS_DATA_CF_POLL) ||
				    (frame_ctrl->Subtype ==
				     QoS_DATA_CF_ACK_CF_POLL))) {
			ca_uint32_t winStartB, leastSeqNo;
			ca_uint32_t storedBufCnt, bufIndex;

			winStartB = baRxInfo->ba[tid].winStartB;
			leastSeqNo = baRxInfo->ba[tid].leastSeqNo;
			storedBufCnt = baRxInfo->ba[tid].storedBufCnt;

			//printf("winStartB=%d, leastSeqNo=%d, storedBufCnt=%d\n", winStartB, leastSeqNo, storedBufCnt);

			//Expected seqno matching incoming seqno, send to host. Should be getting till last msdu with same seqno sequentially
			if (winStartB == seq) {
				bufIndex = winStartB % MAX_BA_REORDER_BUF_SIZE;

				DBG_BAREORDER_OOR(stn_id, tid, 1, winStartB,
						  seq)
					//Check duplicate and store pkt to AmsduQ if needed
					if (BA_CheckAmsduDup
					    (rid, &baRxInfo->ba[tid], bufIndex,
					     pkt, LMFbit
					     /*, &pStaInfo->pn->ucRxQueues[tid], frame_ctlp->Wep, SeqNo, pn */
					     )) {
					//vmacSta_p->BA_RodrDupDropCnt++;
					//pStaInfo->rxBaStats[tid].BA_RodrDupDropCnt++;
					//SPIN_UNLOCK(&baRxInfo->ba[tid].BAreodrLock);
					//printf("err1\n");
					goto err;	// Drop packet due to duplicate   
				}
				storedBufCnt = baRxInfo->ba[tid].storedBufCnt;

				//Received last amsdu of winStartB, flush to host.
				if (baRxInfo->ba[tid].AmsduQ[bufIndex].state ==
				    2) {
					baRxInfo->ba[tid].winStartB = BA_flushSequencialData(rid, vif, &baRxInfo->ba[tid], ((winStartB << 16) | storedBufCnt)	/*, &pStaInfo->pn->ucRxQueues[tid], 
																				   &wlexcept_p->badPNcntUcast,
																				   &wlpptr->wlpd_p->drv_stats_val.rx_data_ucast_pn_pass_cnt,
																				   tid */
											     );
					storedBufCnt =
						baRxInfo->ba[tid].storedBufCnt;

					BA_TimerActivateCheck(baRxInfo, tid,
							      seq, 0, vif);

					DBG_BAREORDER_SN(stn_id, tid, 1,
							 baRxInfo->ba[tid].
							 winStartB, seq)
				} else {
					if (storedBufCnt == 1) {
						baRxInfo->ba[tid].leastSeqNo =
							seq;
					}

					DBG_BAREORDER_SN(stn_id, tid, 2,
							 baRxInfo->ba[tid].
							 winStartB, seq)
				}

				//SPIN_UNLOCK(&baRxInfo->ba[tid].BAreodrLock);
				pkt = NULL;
				//printf("out1\n");
				goto out;
			} else	//(winStartB != SeqNo)
			{
				ca_uint32_t seqDelta;
				ca_uint32_t wEnd;
				ca_uint32_t endExt;
				ca_uint32_t winSizeB_minus1;

				winSizeB_minus1 =
					baRxInfo->ba[tid].winSizeB - 1;
				wEnd = (winStartB +
					winSizeB_minus1) & BA_MAX_SEQ_NUM;
				endExt = (winStartB + 2048) & BA_MAX_SEQ_NUM;	// winStartB+2^11

				seqDelta =
					BA_getSeqDelta(((wEnd << 16) | endExt),
						       winStartB, seq,
						       winSizeB_minus1);

				// The SN is out of boundary(less then winStartB or greater equal than winStartB+2^11)
				if (seqDelta == 0) {
					//vmacSta_p->BA_RodrOoRDropCnt++;
					//pStaInfo->rxBaStats[tid].BA_RodrOoRDropCnt++;
					//SPIN_UNLOCK(&baRxInfo->ba[tid].BAreodrLock);

#ifdef DEBUG_BAREORDER
					if (stn_id == dbg_BAredr_id) {
						ca_uint32_t index;

						dbg_BAredr_OOR_cont++;
						if (dbg_BAredr_OOR_cont > 1) {
							dbg_BAredr_OOR_cont = 0xF;	//differentiate between 1st occurence of OOR and subsequent continous OOR
						}

						if (dbg_BAredr_OOR_cnt <
						    (DBG_BAREORDER_OOR_MASK -
						     5)) {
							dbg_BAredr_OOR
								[dbg_BAredr_OOR_cnt++
								 &
								 DBG_BAREORDER_OOR_MASK]
								=
								(tid << 28) |
								(dbg_BAredr_OOR_cont
								 << 24) |
								(winStartB <<
								 12) | (seq);

							//get previous 3 seqno history
							index = dbg_BAredr_SN_cnt;
							index = (index -
								 1) &
								DBG_BAREORDER_SN_MASK;
							dbg_BAredr_OOR
								[dbg_BAredr_OOR_cnt++
								 &
								 DBG_BAREORDER_OOR_MASK]
								=
								dbg_BAredr_SN
								[index];

							index = (index -
								 1) &
								DBG_BAREORDER_SN_MASK;
							dbg_BAredr_OOR
								[dbg_BAredr_OOR_cnt++
								 &
								 DBG_BAREORDER_OOR_MASK]
								=
								dbg_BAredr_SN
								[index];

							index = (index -
								 1) &
								DBG_BAREORDER_SN_MASK;
							dbg_BAredr_OOR
								[dbg_BAredr_OOR_cnt++
								 &
								 DBG_BAREORDER_OOR_MASK]
								=
								dbg_BAredr_SN
								[index];

							dbg_BAredr_OOR
								[dbg_BAredr_OOR_cnt
								 &
								 DBG_BAREORDER_OOR_MASK]
								= 0xdeadbeef;
						}
					}
#endif

					goto err;	// Drop packet
				}

				DBG_BAREORDER_OOR(stn_id, tid, 2, winStartB,
						  seq)
					//From winStartB to incoming seqno is more than winSizeB, so need to flush and move winStartB. 
					//In the end, winStartB + winSizeB -1 == seqno (total 64 count from winStartB to seqno)
					if ((seqDelta > winSizeB_minus1)) {
					ca_uint32_t winDelta = seqDelta - winSizeB_minus1;	// moving window
					ca_uint32_t temp;

					if (storedBufCnt != 0) {
						temp = ((storedBufCnt & 0xFF) <<
							24) | ((leastSeqNo &
								0xFFF) << 12) |
							(winStartB & 0xFFF);
						baRxInfo->ba[tid].winStartB = BA_flushAnyData(rid, vif, &baRxInfo->ba[tid], temp, (((baRxInfo->ba[tid].winSizeB) << 16) | winDelta)	/*, 
																							   &pStaInfo->pn->ucRxQueues[tid], &wlexcept_p->badPNcntUcast,
																							   &wlpptr->wlpd_p->drv_stats_val.rx_data_ucast_pn_pass_cnt,
																							   tid */
											      );
						//storedBufCnt = baRxInfo->ba[tid].storedBufCnt;
						leastSeqNo =
							baRxInfo->ba[tid].
							leastSeqNo;

						//If after flush, winStartB == SeqNo, flush to host
						if (baRxInfo->ba[tid].
						    winStartB == seq) {
							bufIndex =
								seq %
								MAX_BA_REORDER_BUF_SIZE;

							//Check duplicate and store skb to AmsduQ if needed
							if (BA_CheckAmsduDup(rid, &baRxInfo->ba[tid], bufIndex, pkt, LMFbit	/*, &pStaInfo->pn->ucRxQueues[tid], 
																   frame_ctlp->Wep, SeqNo, pn */
									     )) {
								//vmacSta_p->BA_RodrDupDropCnt++;
								//pStaInfo->rxBaStats[tid].BA_RodrDupDropCnt++;
								//SPIN_UNLOCK(&baRxInfo->ba[tid].BAreodrLock);

								DBG_BAREORDER_SN
									(stn_id,
									 tid, 3,
									 baRxInfo->
									 ba
									 [tid].
									 winStartB,
									 seq)
									//printf("err3\n");
									goto err;	// Drop packet due to duplicate   
							}
							storedBufCnt =
								baRxInfo->
								ba[tid].
								storedBufCnt;

							//Received last amsdu of winStartB, flush to host.
							if (baRxInfo->ba[tid].
							    AmsduQ[bufIndex].
							    state == 2) {
								baRxInfo->ba[tid].winStartB = BA_flushSequencialData(rid, vif, &baRxInfo->ba[tid], ((baRxInfo->ba[tid].winStartB << 16) | storedBufCnt)	/*, &pStaInfo->pn->ucRxQueues[tid], 
																									   &wlexcept_p->badPNcntUcast,
																									   &wlpptr->wlpd_p->drv_stats_val.rx_data_ucast_pn_pass_cnt,
																									   tid */
														     );
							} else {
								if (storedBufCnt
								    == 1) {
									baRxInfo->
										ba
										[tid].
										leastSeqNo
										=
										seq;
								}
							}

							BA_TimerActivateCheck
								(baRxInfo, tid,
								 seq, 0, vif);

							//SPIN_UNLOCK(&baRxInfo->ba[tid].BAreodrLock);
							pkt = NULL;

							DBG_BAREORDER_SN(stn_id,
									 tid, 4,
									 baRxInfo->
									 ba
									 [tid].
									 winStartB,
									 seq)
								//printf("out2\n");
								goto out;
						} else {
							DBG_BAREORDER_SN(stn_id,
									 tid, 5,
									 baRxInfo->
									 ba
									 [tid].
									 winStartB,
									 seq)
						}
					} else {
						baRxInfo->ba[tid].winStartB =
							(baRxInfo->ba[tid].
							 winStartB +
							 winDelta) &
							BA_MAX_SEQ_NUM;

						DBG_BAREORDER_SN(stn_id, tid, 6,
								 baRxInfo->
								 ba[tid].
								 winStartB, seq)
					}
				}

				bufIndex = seq % MAX_BA_REORDER_BUF_SIZE;

				//Check duplicate and store skb to buf if needed
				if (BA_CheckAmsduDup(rid, &baRxInfo->ba[tid], bufIndex, pkt, LMFbit	/*, &pStaInfo->pn->ucRxQueues[tid], 
													   frame_ctlp->Wep, SeqNo, pn */
						     )) {
					//vmacSta_p->BA_RodrDupDropCnt++;
					//pStaInfo->rxBaStats[tid].BA_RodrDupDropCnt++;
					//SPIN_UNLOCK(&baRxInfo->ba[tid].BAreodrLock);
					//printf("err4\n");
					goto err;	// Drop packet due to duplicate   
				}
				storedBufCnt = baRxInfo->ba[tid].storedBufCnt;

				if (storedBufCnt > MAX_BA_REORDER_BUF_SIZE) {
					DEBUG_REORDER_PRINT(("BA rodr: Store cnt > 64. Should not happen\n"));
				}
				//Update least seqno in buffer
				if (storedBufCnt == 0) {
					DEBUG_REORDER_PRINT(("AMSDU store conflict\n"));
					//vmacSta_p->BA_RodrAmsduEnQCnt++;
					//pStaInfo->rxBaStats[tid].BA_RodrAmsduEnQCnt++;
					//SPIN_UNLOCK(&baRxInfo->ba[tid].BAreodrLock);
					//printf("err5\n");
					goto err;	// Drop packet due to duplicate
				} else if (storedBufCnt == 1)	//only 1 amsdu is stored
				{
					baRxInfo->ba[tid].leastSeqNo = seq;
				} else {
					if ((ca_uint32_t)
					    (baRxInfo->ba[tid].leastSeqNo -
					     seq) <
					    baRxInfo->ba[tid].winSizeB) {
						baRxInfo->ba[tid].leastSeqNo =
							seq;
					}
				}

				BA_TimerActivateCheck(baRxInfo, tid, seq, 1,
						      vif);

				pkt = NULL;
				//SPIN_UNLOCK(&baRxInfo->ba[tid].BAreodrLock);
				//printf("out3\n");
				goto out;
			}	//end (winStartB != SeqNo)
#if 0				//def RX_REPLAY_DETECTION
			process_pn_check = FALSE;
#endif
		}
		//SPIN_UNLOCK(&baRxInfo->ba[tid].BAreodrLock);
	}
#if 0				//def RX_REPLAY_DETECTION
	//1. Mcast/Bcast or no-aggregrated 2. Legacy mode or not aggregated 
	if (process_pn_check) {
		UINT32 *badPNcnt, *staBadPNcnt, *passPNcnt;
		rx_queue_t *rq;

		if (frame_ctlp->Wep && pStaInfo && pn) {
			if (isBcastPkt)	//Mcast/Bcast
			{
				rq = &pStaInfo->pn->mcRxQueues[tid];
				badPNcnt = &wlexcept_p->badPNcntMcast;
				staBadPNcnt = &pStaInfo->pn->mcastBadCnt;
				passPNcnt =
					&wlpptr->wlpd_p->drv_stats_val.
					rx_data_mcast_pn_pass_cnt;
			} else {
				rq = &pStaInfo->pn->ucRxQueues[tid];
				badPNcnt = &wlexcept_p->badPNcntUcast;
				staBadPNcnt = &pStaInfo->pn->ucastBadCnt;
				passPNcnt =
					&wlpptr->wlpd_p->drv_stats_val.
					rx_data_ucast_pn_pass_cnt;
			}

			if (pn_replay_detection
			    (IEEE_TYPE_DATA, secMode, pn, rq, SeqNo, badPNcnt,
			     passPNcnt)) {
				(*staBadPNcnt)++;
				goto out;	//drop_packet 
			}
		}
	}
#endif

	//printf("%s: rx seq %d\n", __func__, seq);
	if (radio->dbg_ctrl & DBG_PKT_TO_HOST) {
		wlSendPktToHost(radio, pkt, true, NULL);
		radio->dbg_cnt.rx_cnt.data_pkt_to_host++;
	} else {
#ifdef DBG_BM_BUF_MONITOR
		dbg_check_buf(radio->rid, pkt, __func__);
#endif
		eth_xmit_pkt(vif->eth_handle, pkt, pkt->data, pkt->len);
		radio->dbg_cnt.rx_cnt.data_pkt_to_eth++;
	}
	pkt = NULL;

err:
out:
	if (pkt != NULL) {
		//wlpptr->netDevStats.rx_dropped++;
		pkt_free_data(rid, pkt, __func__);
	}

	return;
#else
	if (radio->dbg_ctrl & DBG_PKT_TO_HOST) {
		wlSendPktToHost(radio, pkt, true, NULL);
		radio->dbg_cnt.rx_cnt.data_pkt_to_host++;
	} else {
#ifdef DBG_BM_BUF_MONITOR
		dbg_check_buf(radio->rid, pkt, __func__);
#endif
		eth_xmit_pkt(vif->eth_handle, pkt, pkt->data, pkt->len);
		radio->dbg_cnt.rx_cnt.data_pkt_to_eth++;
	}
#endif

	return;
}

void
ba_check_timer(ca_uint16_t rid)
{
	struct ba_timer *tm;

	/* timer's exp_time must be in ascending order */
	while ((tm = (struct ba_timer *)list_peek_item(&ba_timer_list)) != NULL) {
		if (tm->exp_time < JIFFIES) {
			//Timer is expired
			list_remove_item(&ba_timer_list,
					 (struct list_item *)tm);
			//printf("Timer exp: stn_id=%d, tid=%d, curr=%lu, exp=%lu\n", tm->stn_id, tm->tid, JIFFIES, tm->exp_time);

			BA_TimerProcess(rid, tm);
		} else {
			break;
		}
	}

	return;
}

void
ba_bar_proc(ca_uint16_t rid, struct vif *vif, ca_uint16_t stn_id,
	    ca_uint16_t tid, ca_uint16_t seq)
{
	struct radio *radio = &radio_info[rid - 1];
	struct ampdu_pkt_reorder *baRxInfo;
	ca_uint32_t winStartB, storedBufCnt, winDelta;

	//printf("%s: rid=%d, stn_id=%d, tid=%d, seq=%d\n", __func__, rid, stn_id, tid, seq);

	baRxInfo = &radio->ampdu_ba_reorder[stn_id];
	//SPIN_LOCK(&baRxInfo->ba[Priority].BAreodrLock);

	winStartB = baRxInfo->ba[tid].winStartB;
	storedBufCnt = baRxInfo->ba[tid].storedBufCnt;

	if ((seq != winStartB) && (BA_chkSnValid(seq, winStartB) == 0)) {
		if (storedBufCnt != 0)	// Only if there is at least one saved reorder buffer
		{
			ca_uint32_t temp;

			if (winStartB > seq)	// rollover
			{
				winDelta =
					(BA_MAX_SEQ_NUM + 1) - winStartB + seq;
			} else {
				winDelta = seq - winStartB;
			}
			// Any complete Data Flush from winStartB to SSN(winDelta)                
			temp = ((baRxInfo->ba[tid].
				 storedBufCnt & 0xFF) << 24) | ((baRxInfo->
								 ba[tid].
								 leastSeqNo &
								 0xFFF) << 12) |
				(baRxInfo->ba[tid].winStartB & 0xFFF);
			baRxInfo->ba[tid].winStartB = BA_flushAnyData(rid, vif, &baRxInfo->ba[tid], temp, (((baRxInfo->ba[tid].winSizeB) << 16) | winDelta)	/*, 
																				   &pStaInfo->pn->ucRxQueues[Priority], &wlexcept_p->badPNcntUcast,
																				   &wlpptr->wlpd_p->drv_stats_val.rx_data_ucast_pn_pass_cnt,
																				   tid */
								      );
			storedBufCnt = baRxInfo->ba[tid].storedBufCnt;

			BA_TimerActivateCheck(baRxInfo, tid, seq, 0, vif);

			DBG_BAREORDER_SN(stn_id, tid, 8,
					 baRxInfo->ba[tid].winStartB, seq)
		} else {
			baRxInfo->ba[tid].winStartB = seq;

			DBG_BAREORDER_SN(stn_id, tid, 9,
					 baRxInfo->ba[tid].winStartB, seq)
		}
	}
	//SPIN_UNLOCK(&baRxInfo->ba[Priority].BAreodrLock);

	return;
}

#endif /* BA_REORDER */
