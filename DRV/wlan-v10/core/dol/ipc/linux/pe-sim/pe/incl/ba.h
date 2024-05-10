/** @file ba.h
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

#ifndef __BA_H__
#define __BA_H__

#include "ca_types.h"
#include "osal.h"
#include "sysadpt.h"
#include "list.h"
#include "radio.h"

#define MAX_BA_REORDER_BUF_SIZE		(64*2)
#define BA_MAX_SEQ_NUM				0xFFF
//Replace with global variable
//#define MAX_REORDERING_HOLD_TIME      (500 * TIMER_1MS) //(HZ / 2) //500ms

struct ba_timer {
	struct ba_timer *next;
	struct ba_timer *prev;
	ca_uint16_t stn_id;
	ca_uint16_t tid;
	ca_uint32_t exp_time;
	struct vif *vif;
};

struct amsduQ_st {
	ca_uint32_t state;	// 0: Empty, expecting 1st amsdu, 1: 1st amsdu received, expect mid or last, 2: last amsdu received, expect no more
	struct list msdu_list;	//all msdu in same amsdu list, share same seqno
};

struct ba_rx_st {
	ca_uint16_t storedBufCnt;	//number of amsdu added to buffer. E.g an amsdu with 3 msdu is counted as 1
	ca_uint16_t leastSeqNo;	//least seq no of pkt in buffer
	ca_uint16_t winStartB;	//expected incoming seqno
	ca_uint16_t winSizeB;	//size of buffer
	struct amsduQ_st AmsduQ[MAX_BA_REORDER_BUF_SIZE];
#if 0				//def RX_REPLAY_DETECTION
	ca_uint8_t pn_check_enabled;
#endif
	ca_uint32_t minTime;	//oldest time of pkt stays in buffer, in jiffies
	//DECLARE_LOCK(BAreodrLock);    
	//struct tasklet_struct BArodertask;
};

struct ampdu_pkt_reorder {
	ca_uint8_t AddBaReceive[SYSADPT_MAX_TID];
	struct ba_timer timer[SYSADPT_MAX_TID];
	ca_uint8_t timer_init[SYSADPT_MAX_TID];
	struct ba_rx_st ba[SYSADPT_MAX_TID];
};

struct ba_msdu_pkt {
	struct ba_msdu_pkt *next;
	struct ba_msdu_pkt *prev;
	struct pkt_hdr *pkt;
};

extern int ba_msdu_pkt_num;

extern int ba_init(ca_uint16_t rid);

extern int ba_deinit(ca_uint16_t rid);

extern void ba_cmd_assoc(ca_uint16_t rid, ca_uint16_t stn_id);

extern void ba_cmd_addba(ca_uint16_t rid, ca_uint16_t stn_id, ca_uint16_t tid,
			 ca_uint16_t winStartB, ca_uint16_t winSizeB);

extern void ba_cmd_delba(ca_uint16_t rid, ca_uint16_t stn_id, ca_uint16_t tid,
			 ca_uint16_t winStartB, ca_uint16_t winSizeB);

extern void ba_reorder_proc(ca_uint16_t rid, struct vif *vif,
			    ca_uint16_t stn_id, ca_uint16_t tid,
			    ca_uint16_t seq, struct pkt_hdr *pkt,
			    IEEEtypes_FrameCtl_t * frame_ctrl,
			    ca_uint8_t LMFbit);

extern void ba_check_timer(ca_uint16_t rid);

extern void ba_bar_proc(ca_uint16_t rid, struct vif *vif, ca_uint16_t stn_id,
			ca_uint16_t tid, ca_uint16_t seq);

extern ca_uint32_t BA_flushSequencialData(ca_uint16_t rid, struct vif *vif,
					  struct ba_rx_st *baRxInfo,
					  ca_uint32_t winStartB_BufCnt
					  /*, rx_queue_t * rq, UINT32 *badPNcnt, UINT32 *passPNcnt, UINT8 tid */
					  );

#endif /* __BA_H__ */
