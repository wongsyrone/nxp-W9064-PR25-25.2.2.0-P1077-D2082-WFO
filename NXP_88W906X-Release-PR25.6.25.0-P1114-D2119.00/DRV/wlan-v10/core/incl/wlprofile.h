/** @file wlprofile.h
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
#ifndef WL_PROFILE_H_
#define WL_PROFILE_H_

#include "IEEE_types.h"
#include "wltypes.h"
#include <linux/skbuff.h>

typedef enum {
	TX_TRACE_START = 0,
	TX_TRACE_RELEASE,
	TX_TRACE_INTERVAL,
	TX_TRACE_POINTS,
	TX_TRACE_wlDataTx
} TX_TRACE_LOC;

typedef enum {
	RX_TRACE_START = 0,
	RX_TRACE_INDICATE,
	RX_TRACE_INTERVAL,
	RX_TRACE_POINTS
} RX_TRACE_LOC;

#define SKB_TP_OFFSET     32

#define NUM_INDIVIDUAL_COUNTERS 3
typedef struct _tp_record {
	u32 pktcnt;
	u32 totalsize;
	u32 duration;
	u32 idvcnt[NUM_INDIVIDUAL_COUNTERS][3];

} TP_RECORD;

#define TP_TRACE_POINTS_MAX     60
#define TP_LOG_MAX_DURATION     1000000	//usec

typedef struct _tp_stats {
	TP_RECORD tp_records[TP_TRACE_POINTS_MAX];
	u64 basetime;		//usec
	//u16 maxivl;                //record max period  usec
	u16 idx;		//log index of tp_records

} TP_STATS;

//extern TP_STATS tx_tp_stats;

//#define TP_PROFILING_FW_TURN_AROUND

extern u64 xxGetTimeStamp(void);
extern void calculateTpStats(TP_STATS * ptpstats, int level, char *sysfs_buff);
extern void logTPStats(TP_STATS * ptpstats, u32 cnt, u32 size);
extern void logTPCounter(TP_STATS * ptpstats, u32 idv0, u32 idv1, u32 idv2);
extern void convert_tscale(UINT64 tick, UINT64 * sec, UINT64 * ms, UINT64 * us);

#ifdef TP_PROFILE
extern int wl_tp_profile_test(int tp_point, struct sk_buff *skb, struct net_device *netdev);
#endif

static inline unsigned long get_cyclecount(void)
{
	unsigned long value;

	// Read CCNT Register
	asm volatile ("MRS %0, PMCCNTR_EL0\t\n":"=r" (value));
	return value;
}

static inline void init_perfcounters(int32_t do_reset, int32_t enable_divider)
{
	// in general enable all counters (including cycle counter)
	int32_t value = 1;

	// peform reset:
	if (do_reset) {
		value |= 2;	// reset all counters to zero.
		value |= 4;	// reset cycle counter to zero.
	}

	if (enable_divider)
		value |= 8;	// enable "by 64" divider for CCNT.

	value |= 16;

	// program the performance-counter control-register:
	asm volatile ("MSR PMCR_EL0, %0\t\n"::"r" (value));

	// enable all counters:
	asm volatile ("MSR  PMCNTENSET_EL0, %0\t\n"::"r" (0x8000000f));

	// clear overflows:
	asm volatile ("MSR PMOVSCLR_EL0, %0\t\n"::"r" (0x8000000f));
}

#endif
