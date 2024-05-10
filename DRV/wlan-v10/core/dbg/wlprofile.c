/** @file wlprofile.c
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2017-2020 NXP
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

#include "wlprofile.h"
#include "wldebug.h"
//#include <linux/timekeeping.h>
#include <asm/div64.h>

#ifdef TP_PROFILE
#include "ap8xLnxIntf.h"
#endif

u64
xxGetTimeStamp(void)
{
#if 1
	//us resolution
	struct timeval tv;

	do_gettimeofday(&tv);

	return (UINT64) ((UINT64) (tv.tv_sec) * 1000000LL +
			 (UINT64) (tv.tv_usec));
#else
	//ns resolution
	struct timespec64 tv;

	getnstimeofday64(&tv);

	return (UINT64) ((UINT64) (tv.tv_sec) * 1000000000LL +
			 (UINT64) (tv.tv_nsec));
#endif
}

/*
convert timestamp us to [sec.ms.us] format.
use do_div() for both 
*/
void
convert_tscale(UINT64 tick, UINT64 * sec, UINT64 * ms, UINT64 * us)
{
	UINT64 rem;

	if (sec) {
		rem = do_div(tick, 1000000LL);
		*sec = tick;
		if (ms) {
			tick = rem;
			rem = do_div(tick, 1000LL);
			*ms = tick;
			if (us)
				*us = rem;
		} else if (us)
			*us = rem;
	} else if (ms) {
		rem = do_div(tick, 1000LL);
		*ms = tick;

		if (us)
			*us = rem;
	} else if (us) {
		//No convert
		*us = tick;
	}
}

//log packets
//cnt: #packet to log 
//size: total length of the packets 
void
logTPStats(TP_STATS * ptpstats, u32 cnt, u32 size)
{
	u64 tick = xxGetTimeStamp();
	u16 idx = ptpstats->idx;
	u32 duration;

	if (ptpstats->basetime == 0) {
		ptpstats->basetime = tick;
	}

	duration = (u32) (tick - ptpstats->basetime);

	//if( (ptpstats->basetime + TP_LOG_MAX_DURATION) < tick ) //move to next record
	if (duration > TP_LOG_MAX_DURATION) {
		u32 i;

		idx++;
		if (idx >= TP_TRACE_POINTS_MAX)
			idx = 0;

		ptpstats->basetime = tick;
		ptpstats->idx = idx;
		memset((void *)&ptpstats->tp_records[idx], 0, sizeof(TP_RECORD));	//clear next record.
		for (i = 0; i < NUM_INDIVIDUAL_COUNTERS; i++)	//set min to -1
			ptpstats->tp_records[idx].idvcnt[i][1] = (u32) - 1;
	}

	ptpstats->tp_records[idx].pktcnt += cnt;
	ptpstats->tp_records[idx].totalsize += size;
	ptpstats->tp_records[idx].duration = duration;	//current record duration till now
}

void
logTPCounter(TP_STATS * ptpstats, u32 idv0, u32 idv1, u32 idv2)
{
	u16 idx = ptpstats->idx;
	u32 idv[NUM_INDIVIDUAL_COUNTERS];
	u32 i;

	idv[0] = idv0;
	idv[1] = idv1;
	idv[2] = idv2;

	for (i = 0; i < NUM_INDIVIDUAL_COUNTERS; i++) {
		if (idv[i] != (u32) (-1)) {
			u32 *pmax = &ptpstats->tp_records[idx].idvcnt[i][0];	//max
			u32 *pmin = &ptpstats->tp_records[idx].idvcnt[i][1];	//min

			if (idv[i] > *pmax)	//get max
				*pmax = idv[i];

			if (idv[i] < *pmin)	//get min
				*pmin = idv[i];

			ptpstats->tp_records[idx].idvcnt[i][2] += idv[i];	//sum
		}
	}

}

void
calculateTpStats(TP_STATS * ptpstats, int level, char *sysfs_buff)
{
	u32 idx = ptpstats->idx;	//currnet index
	u32 i;
	u32 duration;

	for (i = 0; i < TP_TRACE_POINTS_MAX - 1; i++) {
		if (idx == 0)
			idx = TP_TRACE_POINTS_MAX - 1;
		else
			idx--;

		//caculate pps
		duration = ptpstats->tp_records[idx].duration;	//usec

		if (duration) {
			u32 pktcnt = ptpstats->tp_records[idx].pktcnt;
			u32 totalsize = ptpstats->tp_records[idx].totalsize;

			u32 tsec = duration / 1000000;
			u32 tms = duration / 1000;
			u32 temp = 0;
			u64 temp64 = 0;

			Sysfs_Printk("TS[%u]: ", (TP_TRACE_POINTS_MAX - i));

			temp64 = 0;
			if (tms) {
				temp64 = (u64) totalsize *8;
				do_div(temp64, tms);
			}

			if (level == 0) {	//full log
				Sysfs_Printk
					("%u frames in ivl %u usec, PPS:%u, Rate:%llu Kbps\n",
					 pktcnt, duration,
					 ((tsec) ? (pktcnt / tsec) : pktcnt),
					 temp64);
			} else {
				Sysfs_Printk("PPS:%u, Rate:%llu Kbps\n",
					     ((tsec) ? (pktcnt / tsec) :
					      pktcnt), temp64);
			}

			if (pktcnt)
				temp = ptpstats->tp_records[idx].idvcnt[0][2] /
					pktcnt;

			if (level == 0)	//full log
			{
				Sysfs_Printk
					("  Pkt pending counts, Max:%u, Min:%u, Avg:%u\n",
					 ptpstats->tp_records[idx].idvcnt[0][0],
					 ptpstats->tp_records[idx].idvcnt[0][1],
					 temp);
				Sysfs_Printk
					("  Last [txq_drv_sent_cnt] value:%u \n",
					 ptpstats->tp_records[idx].
					 idvcnt[1][0]);
				Sysfs_Printk
					("  Last [txq_full_cnt] value:%u \n",
					 ptpstats->tp_records[idx].
					 idvcnt[2][0]);
			}
		}
	}
}

#ifdef TP_PROFILE
int
wl_tp_profile_test(int tp_point, struct sk_buff *skb, struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;

	if (tp_point != 0 && wlpd_p->wl_tpprofile.tp_point == tp_point) {
		if (IS_TX_TP(tp_point)) {
			UINT32 tx_pend_cnt = 0;

			wlpd_p->wl_tpprofile.tx.bytes += skb->len;
			wlpd_p->wl_tpprofile.tx.packets += 1;
			logTPStats(&wlpd_p->drv_stats_val.cfhdltx_stat, 1,
				   skb->len);
			logTPCounter(&wlpd_p->drv_stats_val.cfhdltx_stat,
				     tx_pend_cnt,
				     wlpd_p->drv_stats_val.txq_drv_sent_cnt,
				     wlpd_p->drv_stats_val.txq_full_cnt);
		} else {
			wlpd_p->wl_tpprofile.rx.bytes += skb->len;
			wlpd_p->wl_tpprofile.rx.packets += 1;
		}

		return 1;
	}

	return 0;

}
#endif
