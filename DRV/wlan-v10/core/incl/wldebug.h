/** @file wldebug.h
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2002-2020 NXP
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

#ifndef WL_DB_H
#define WL_DB_H
#include "wltypes.h"

#define DBG_LEVEL_0 (1<<0)
#define DBG_LEVEL_1 (1<<1)
#define DBG_LEVEL_2 (1<<2)
#define DBG_LEVEL_3 (1<<3)
#define DBG_LEVEL_4 (1<<4)
#define DBG_LEVEL_5 (1<<5)
#define DBG_LEVEL_6 (1<<6)
#define DBG_LEVEL_7 (1<<7)
#define DBG_LEVEL_8 (1<<8)
#define DBG_LEVEL_9 (1<<9)
#define DBG_LEVEL_10 (1<<10)
#define DBG_LEVEL_11 (1<<11)
#define DBG_LEVEL_12 (1<<12)
#define DBG_LEVEL_13 (1<<13)
#define DBG_LEVEL_14 (1<<14)
#define DBG_LEVEL_15 (1<<15)
#define DBG_LEVEL_ALL (0xFFFF)

#define DBG_CLASS_PANIC (1<<16)
#define DBG_CLASS_ERROR (1<<17)
#define DBG_CLASS_WARNING (1<<18)
#define DBG_CLASS_ENTER (1<<19)
#define DBG_CLASS_EXIT (1<<20)
#define DBG_CLASS_INFO (1<<21)
#define DBG_CLASS_DATA (1<<22)
#define DBG_CLASS_IOCTL (1<<23)
#define DBG_CLASS_8 (1<<24)	/* reserve to dump promiscuous frames */
#define DBG_CLASS_9 (1<<25)
#define DBG_CLASS_10 (1<<26)
#define DBG_CLASS_11 (1<<27)
#define DBG_CLASS_12 (1<<28)
#define DBG_CLASS_13 (1<<29)
#define DBG_CLASS_14 (1<<30)
#define DBG_CLASS_15 (1<<31)
#define DBG_CLASS_ALL (0xffff0000)

#define DBG_CLASS_PROMISCUOUS DBG_CLASS_8

#define DEFAULT_WLDBG_LEVELS 	(\
	0)
#define DEFAULT_WLDBG_CLASSES  ( \
	DBG_CLASS_PANIC   | \
	DBG_CLASS_ERROR   | \
	DBG_CLASS_WARNING| \
	DBG_CLASS_INFO| \
	DBG_CLASS_DATA| \
	DBG_CLASS_ENTER   | \
	DBG_CLASS_EXIT   | \
	DBG_CLASS_IOCTL	 | \
	DBG_CLASS_10)

extern void wlPrintData(UINT32 classlevel, const char *func, const void *data,
			int len, const char *format, ...);
extern void wlPrint(UINT32 classlevel, const char *func, const char *format,
		    ...);
extern const char *mac_display(const UINT8 * mac);
extern void wlHexDump(UINT32 classlevel, const void *data, size_t len);
extern int disableSMACRx(struct net_device *netdev);
extern int disableSMACTx(struct net_device *netdev);
extern void triggerCoredump(struct net_device *netdev);
extern int wldbgCoreDump(struct notifier_block *nb, unsigned long action,
			 void *data);
extern void wldbgCoreMonitor(struct net_device *netdev, UINT32 enable,
			     UINT32 bitmap, UINT32 format);
extern u64 dump_file(UINT8 * valbuf, UINT32 length, UINT8 * fname,
		     UINT32 append);
extern void dbg_coredump(struct net_device *netdev);

#ifdef WL_DEBUG

#define WLDBG_HEXDUMP(classlevel, data, len)              \
    wlHexDump(classlevel|DBG_CLASS_DATA, data, len)

#define WLDBG_DUMP_DATA(classlevel, data, len)                                \
    wlPrintData(classlevel|DBG_CLASS_DATA,  __FUNCTION__,                           \
                 	data, len, NULL)

#define WLDBG_ENTER(classlevel)                                          \
    wlPrint(classlevel|DBG_CLASS_ENTER,  __FUNCTION__,   NULL)

#define WLDBG_ENTER_INFO(classlevel, ... )                               \
    wlPrint(classlevel|DBG_CLASS_ENTER,  __FUNCTION__,   __VA_ARGS__)

#define WLDBG_EXIT(classlevel)                                           \
    wlPrint(classlevel|DBG_CLASS_EXIT,  __FUNCTION__,   NULL)

#define WLDBG_EXIT_INFO(classlevel, ... )                                \
    wlPrint(classlevel|DBG_CLASS_EXIT,  __FUNCTION__,   __VA_ARGS__)

#define WLDBG_INFO(classlevel, ... )                                     \
    wlPrint(classlevel|DBG_CLASS_INFO,  __FUNCTION__,   __VA_ARGS__)

#define WLDBG_WARNING(classlevel, ... )                                     \
    wlPrint(classlevel|DBG_CLASS_WARNING,  __FUNCTION__,   __VA_ARGS__)

#define WLDBG_ERROR(classlevel, ... )                                    \
    wlPrint(classlevel|DBG_CLASS_ERROR,  __FUNCTION__,   __VA_ARGS__)

#define WLDBG_PANIC(classlevel, ... )                                \
    wlPrint(classlevel|DBG_CLASS_PANIC,  __FUNCTION__,   __VA_ARGS__)

#define WLDBG_IOCTL(classlevel, ... )                                \
    wlPrint(classlevel|DBG_CLASS_IOCTL,  __FUNCTION__,   __VA_ARGS__)

#define WLDBG_DATA(classlevel, ... )                                \
    wlPrint(classlevel|DBG_CLASS_DATA,  __FUNCTION__,   __VA_ARGS__)

#define WLDBG_PROMISCUOUS_DUMP(classlevel, data, len)              \
    wlHexDump(classlevel|DBG_CLASS_PROMISCUOUS, data, len)

#define PRINT0(class,msg...) WLDBG_##class(DBG_LEVEL_0, (char*)msg)
#define PRINT1(class,msg...) WLDBG_##class(DBG_LEVEL_1, (char*)msg)

#define ap8x_dbg_print(class,msg...) WLDBG_##class(DBG_LEVEL_ALL, (char*) msg)

#ifdef ASSERT_MALBUF
#define WL_ASSERT(condition, msg) do {	\
	if (unlikely(!(condition))) {	\
		printk msg;	\
		BUG();	\
	}	\
} while (0)
#else
#define WL_ASSERT(condition, msg)
#endif

#else
#define WLDBG_HEXDUMP(classlevel, data, len)
#define WLDBG_DUMP_DATA(classlevel, data, len)
#define WLDBG_ENTER(classlevel)
#define WLDBG_ENTER_INFO(classlevel, ... )
#define WLDBG_EXIT(classlevel)
#define WLDBG_EXIT_INFO(classlevel, ... )
#define WLDBG_INFO(classlevel, ... )
#define WLDBG_DATA(classlevel, ... )
#define WLDBG_WARNING(classlevel, ... )
#define WLDBG_ERROR(classlevel, ... )                                    \
    wlPrint(classlevel|DBG_CLASS_ERROR,  __FUNCTION__,   __VA_ARGS__)
#define WLDBG_PANIC(classlevel, ... )
#define PRINT0(class,msg...)
#if defined(IOCTL_LOG) || defined(FWCMD_LOG)
#define PRINT1(class,msg...) WLDBG_##class(DBG_LEVEL_0, (char*)msg)
#else
#define PRINT1(class,msg...)
#endif
#define WL_ASSERT(condition, msg)
#define WLDBG_PROMISCUOUS_DUMP(classlevel, data, len)
#endif /* WL_DB_H */

#ifdef IOCTL_LOG
#define WLDBG_IOCTL(classlevel, ... )                                \
	wlPrint(classlevel|DBG_CLASS_IOCTL,  __FUNCTION__,	 __VA_ARGS__)
#else
#define WLDBG_IOCTL(classlevel, ... )
#endif

#ifdef FWCMD_LOG
#define WLDBG_FWCMD(classlevel, ... )                                \
	wlPrint(classlevel|DBG_CLASS_IOCTL,  __FUNCTION__,	 __VA_ARGS__)

#define WLDBG_FWCMD_HEXDUMP(classlevel, data, len)              \
    wlHexDump(classlevel|DBG_CLASS_IOCTL, data, len)
#else
#define WLDBG_FWCMD(classlevel, ... )
#define WLDBG_FWCMD_HEXDUMP(classlevel, data, len)
#endif

#ifdef QUEUE_STATS
// Packet stats
typedef struct _wldbgPktStats {
#ifdef QUEUE_STATS_LATENCY
	u_int32_t TxPktLatency_Min;
	u_int32_t TxPktLatency_Max;
	u_int32_t TxPktLatency_Mean;
#endif
#ifdef QUEUE_STATS_CNT_HIST
	u_int32_t TxDfsDropCnt;
	u_int32_t TxIffDropCnt;
	u_int32_t TxTxqDropCnt;
	u_int32_t TxErrorCnt;
	u_int32_t TxOkCnt;
	u_int32_t UDPCnt;
	u_int32_t TCPCnt;
	u_int32_t ICMPCnt;
	u_int32_t SMARTBITS_UDPCnt;
	u_int32_t txQdepth;
#endif
} wldbgPktStats_t;

#ifdef QUEUE_STATS_LATENCY
typedef struct basic_stats_t {
	u_int32_t Min;
	u_int32_t Max;
	u_int32_t Mean;
} basic_stats_t;

typedef struct rx_qs_latency_t {
	basic_stats_t TotalLatency;
	basic_stats_t DrvLatency;
	basic_stats_t FwToDrvLatency;
} rx_qs_latency_t;

typedef struct rx_stats_q_stats_t {
	rx_qs_latency_t Latency;
} rx_stats_q_stats_t;		//Initialized by wlInit

extern UINT8 rx_initCnt[3];
extern rx_stats_q_stats_t rx_QueueStats;

//BASIC_STATS_OBJS ID
#define BSO_FWToDRV_LATENCY  	0
#define BSO_DRV_LATENCY     	1
#define BSO_TOTAL_LATENCY 		2
#define RX_QS_LATENCY  rx_QueueStats.Latency

void wldbgRecRxMinMaxMean(UINT32, basic_stats_t *, UINT8 *);
#endif

#ifdef QUEUE_STATS_CNT_HIST
#define QS_TYPE_TX_EN_Q_CNT      0
#define QS_TYPE_TX_OK_CNT_CNT    1
#define QS_TYPE_TX_Q_DROPE_CNT   2

typedef struct _wldbgStaTxPktStats {
	UINT16 valid;
	UINT8 addr[6];
	u_int32_t TxEnQCnt;
	u_int32_t TxOkCnt;
	u_int32_t TxqDropCnt;
} wldbgStaTxPktStats_t;

typedef struct _wldbgStaRxPktStats {
	UINT16 valid;
	UINT8 addr[6];
	u_int32_t RxRecvPollCnt;
	u_int32_t Rx80211InputCnt;
	u_int32_t RxfwdCnt;
} wldbgStaRxPktStats_t;

extern wldbgStaTxPktStats_t txPktStats_sta[4];
extern wldbgStaRxPktStats_t rxPktStats_sta[4];
#endif

extern wldbgPktStats_t wldbgTxACxPktStats[4];
extern UINT32 dbgUdpSrcVal;
extern u_int32_t dbgUdpSrcVal1;
extern UINT8 qs_rxMacAddrSave[24];
extern int numOfRxSta;

void wldbgRecPktTime(u_int32_t, u_int32_t, int);
void wldbgPrintPktStats(int);
void wldbgSprintPktStats(char **p);
void wldbgRecPerStatxPktStats(UINT8 * addr, UINT8 type);
void wldbgResetQueueStats(void);
#endif

#ifdef QUEUE_STATS_CNT_HIST
/*
 *  4 Macro's to record various pkt counters base on priority.
 *  i: priority
 */
#define WLDBG_INC_DFS_DROP_CNT(x)   wldbgTxACxPktStats[x].TxDfsDropCnt++
#define WLDBG_INC_IFF_DROP_CNT(x)   wldbgTxACxPktStats[x].TxIffDropCnt++
#define WLDBG_INC_TXQ_DROP_CNT(x)   wldbgTxACxPktStats[x].TxTxqDropCnt++
#define WLDBG_INC_TX_ERROR_CNT(x)   wldbgTxACxPktStats[x].TxErrorCnt++
/*
 *  Macro to count pkts and classfy them to ICMP, TCP or UDP pkts.
 *  x: skb
 *  i: priority
 */
#define WLDBG_INC_TX_OK_CNT(x,i)   {\
        struct iphdr *iph = (struct iphdr *)(x->data+14);   \
        struct tcphdr *th = (struct tcphdr*)(x->data +14 + (iph->ihl * 4)); \
        struct udphdr *udph = (struct udphdr *)th;  \
    wldbgTxACxPktStats[i].TxOkCnt++;        \
    if((iph->protocol == IPPROTO_UDP) && (udph->source == htons(dbgUdpSrcVal1)))   \
        wldbgTxACxPktStats[i].SMARTBITS_UDPCnt++;         \
    if(iph->protocol == IPPROTO_UDP)        \
        wldbgTxACxPktStats[i].UDPCnt++;     \
    if(iph->protocol == IPPROTO_TCP)        \
        wldbgTxACxPktStats[i].TCPCnt++;     \
    if(iph->protocol == IPPROTO_ICMP)       \
		wldbgTxACxPktStats[i].ICMPCnt++;}
#define WLDBG_PRINT_QUEUE_STATS_COUNTERS wldbgPrintPktStats(0)

/*
 *  Macro's to record Rx pkt counters.
 *  
 */
#define WLDBG_INC_RX_RECV_POLL_CNT_STA(x) rxPktStats_sta[x].RxRecvPollCnt++
#define WLDBG_INC_RX_80211_INPUT_CNT_STA(x) rxPktStats_sta[x].Rx80211InputCnt++
#define WLDBG_INC_RX_FWD_CNT_STA(x) rxPktStats_sta[x].RxfwdCnt++

/*
 *  Macro to record Rx pkt @ieee80211_input() 
 *  x: wh; ieee80211_frame *
 */
#define WLDBG_REC_RX_80211_INPUT_PKTS(x)       \
    {                                          \
        int k;                                 \
        for(k=0; k<4; k++)                     \
        {                                      \
            if(rxPktStats_sta[k].valid)        \
            {                                  \
                if(x->FrmCtl.FromDs)           \
                {                              \
                    if((x->addr1[0]&0x3) == 0) \
                    {                          \
                        if (*(UINT32 *)(&x->addr3[2]) == *(UINT32 *)(&rxPktStats_sta[k].addr[2])) \
                        {                                        \
                            WLDBG_INC_RX_80211_INPUT_CNT_STA(k); \
                            break;                               \
                        }                                        \
                    }                                            \
                }                                                \
                else                                             \
                {                                                \
                    if((x->addr3[0]&0x3) == 0)                   \
                    {                                            \
                        if (*(UINT32 *)(&x->addr2[2]) == *(UINT32 *)(&rxPktStats_sta[k].addr[2])) \
                        {                                        \
                            WLDBG_INC_RX_80211_INPUT_CNT_STA(k); \
                            break;                               \
                        }                                        \
                    }                                            \
                }                                                \
            }                                                    \
        }                                                        \
    }

/*
 *  Macro to record Rx pkt @ForwardFrame() 
 *  x: eh; ether_header *
 */
#define WLDBG_REC_RX_FWD_PKTS(x)                 \
    {                                            \
        int i;                                   \
        for(i=0; i<4; i++)                       \
        {                                        \
            if(rxPktStats_sta[i].valid)          \
            {                                    \
                if((x->ether_dhost[0]&0x3) == 0) \
                {                                \
                    if(memcmp(x->ether_shost, rxPktStats_sta[i].addr, IEEEtypes_ADDRESS_SIZE) == 0) \
                    {                                \
                        WLDBG_INC_RX_FWD_CNT_STA(i); \
                        break;                       \
                    }                                \
                }                                    \
            }                                        \
        }                                            \
    }

/*
 *  Macro to record Tx pkt queue depth 
 *  x: queue depth
 *  i: priority
 */
#define WLDBG_REC_TX_Q_DEPTH(x, i) \
        if(wldbgTxACxPktStats[i].txQdepth < x) \
            wldbgTxACxPktStats[i].txQdepth = x;

#else
#define WLDBG_INC_DFS_DROP_CNT(i)
#define WLDBG_INC_IFF_DROP_CNT(i)
#define WLDBG_INC_TXQ_DROP_CNT(i)
#define WLDBG_INC_TX_ERROR_CNT(i)
#define WLDBG_INC_TX_OK_CNT(x, i)
#define WLDBG_PRINT_QUEUE_STATS_COUNTERS
#define WLDBG_INC_RX_RECV_POLL_CNT_STA(x)
#define WLDBG_INC_RX_80211_INPUT_CNT_STA(x)
#define WLDBG_INC_RX_FWD_CNT_STA(x)
#define WLDBG_REC_RX_80211_INPUT_PKTS(x)
#define WLDBG_REC_RX_FWD_PKTS(x)
#define WLDBG_REC_TX_Q_DEPTH(x, i)
#endif

#ifdef QUEUE_STATS_LATENCY
/*
 *  Macro to record pkt time
 *  x: skb
 *  TODO: need BBTX_TMR_TSF is low 32 bit, need HI 32 bit value (No supported on Z1/Z2. Available on SCBT.)
 */
#ifdef SOC_W906X
#define WLDBG_SET_PKT_TIMESTAMP(x) \
	{\
	    x->tstamp.tv64 = (s64)(readl(wlpptr->ioBase1 + BBTX_TMR_TSF));\
	}\

#else
#define WLDBG_SET_PKT_TIMESTAMP(x) \
	{\
		UINT32 *addr_val = wl_kmalloc( 64 * sizeof(UINT32), GFP_ATOMIC );\
		if( addr_val )\
		{\
			wlFwGetAddrValue(netdev, 0x8000a600, 4, addr_val, 0);\
		    x->tstamp.tv64 = (s64)addr_val[0];\
			wl_kfree(addr_val);\
		}\
	}\

#endif

/*
 *  Macro to record pkt driver portion of latency; and set the timestamps on 
 *  tx descriptor
 *  x: skb
 *  tm: current time
 *  y: pointer to tx descriptor
 *  i: priority
 */
#define WLDBG_REC_PKT_DELTA_TIME(x,tm,y,i) \
        wldbgRecPktTime((u_int32_t)x->tstamp.tv64, tm, i); \
        y->TimeStamp1=(u_int32_t)x->tstamp.tv64; \
        y->TimeStamp2=tm;

/*
MACROs for recording RX Fw-To-Drv, Drv and Total latency and produce min, max mean data 
 	x: wcb; TimeStamp2 is set to current time for use in calculation later as pkt moves 
*/
#define WLDBG_RX_REC_PKT_FWToDRV_TIME(x,curr_tm) \
     if((x->TimeStamp2 > 0) && (x->TimeStamp2 < curr_tm))  \
    {   \
        UINT32 tm = curr_tm - x->TimeStamp2;    \
	    wldbgRecRxMinMaxMean(tm, &RX_QS_LATENCY.FwToDrvLatency, &rx_initCnt[BSO_FWToDRV_LATENCY]); \
	    x->TimeStamp2 = curr_tm;	/*Set TimeStamp2 for drv latency calculation later*/		\
	}

#define WLDBG_RX_REC_PKT_DRV_TIME(x,curr_tm) \
     if((x->TimeStamp2 > 0) && (x->TimeStamp2 < curr_tm))  \
    {   \
        UINT32 tm = curr_tm - x->TimeStamp2;    \
	    wldbgRecRxMinMaxMean(tm, &RX_QS_LATENCY.DrvLatency, &rx_initCnt[BSO_DRV_LATENCY]); \
	}

#define WLDBG_RX_REC_PKT_TOTAL_TIME(x,curr_tm) \
     if((x->TimeStamp1 > 0) && (x->TimeStamp1 < curr_tm))  \
    {   \
        UINT32 tm = curr_tm - x->TimeStamp1;    \
	    wldbgRecRxMinMaxMean(tm, &RX_QS_LATENCY.TotalLatency, &rx_initCnt[BSO_TOTAL_LATENCY]); \
	}

#define WLDBG_PRINT_QUEUE_STATS_LATENCY  wldbgPrintPktStats(1)
#define WLDBG_PRINT_QUEUE_STATS_RX_LATENCY  wldbgPrintPktStats(2)

#else
#define WLDBG_SET_PKT_TIMESTAMP(x)
#define WLDBG_SET_FW_PKT_TIMESTAMP(x, y)
#define WLDBG_REC_PKT_DELTA_TIME(x,tm,y,i)
#define WLDBG_RX_REC_PKT_FWToDRV_TIME(x,curr_tm)
#define WLDBG_RX_REC_PKT_DRV_TIME(x,curr_tm)
#define WLDBG_RX_REC_PKT_TOTAL_TIME(x,curr_tm)
#define WLDBG_PRINT_QUEUE_STATS_LATENCY
#define WLDBG_PRINT_QUEUE_STATS_RX_LATENCY
#endif

UINT8 DebugCmdParse(struct net_device *netdev, UINT8 * str);
int DebugBitSet(UINT8 bit);
void wlDumpData(unsigned char *mark, const void *data, int len);

typedef struct TXD_TXQ_t {	//DW0
	UINT32 isShortAmsdu:1;	//0:normal AMSDU, 1:Short AMSDU
	UINT32 isBss:1;		//0:STA index, 1:BSS index
	UINT32 blk0Wrptr:30;	//L0 Write pointer
	//DW1
	UINT32 lowLatencyTrigStat:3;
	UINT32 blk1Wrptr:29;	//L1: write pointer
	//DW2
	UINT32 staBssIndex:9;
	UINT32 rsvd1:1;
	UINT32 l0SizeDw:22;	//[DWORD]
	//DW3
	UINT32 l0SizePkt:18;	//[packet]
	UINT32 pktInsertTsf:14;	// TSF[16:3] at last packet insert   
	//DW4
	UINT32 l0DropSizeDw:18;	//[DWORD]
	UINT32 l0DropSizePkt:14;	//[packet]
	//DW5
	UINT32 trigThresDw:8;	//[DWORD] mantissa(4b)+exponent(4b)
	UINT32 trigThresPkt:8;	//[packet]mantissa(4b)+exponent(4b)
	UINT32 markDropRate:8;	//
	UINT32 txLimitIndex:8;	//for Tx Limit Table
} TXD_TXQ_t;

typedef struct TXD_BSS_t {
	//DW0
	UINT32 taLow;		//BSS address
	//DW1
	UINT32 taHigh:16;	//
	UINT32 txLimitIndex:8;	//for Tx Limit Table
	UINT32 markDropRate:8;
	//DW2
	UINT32 l0SizeDw:32;	//[DWORD]
	//DW3
	UINT32 l0SizePkt:24;	//[packet]
	UINT32 rsvd1:8;
	//DW4
	UINT32 vlanId:12;	//our VID
	UINT32 vlanMode:2;	//0: VLAN tag never included in packet
	//    ignore CFH->vid
	//1: VLAN tag never included in packet
	//    error on CFH->VID != our VID
	//    error on CFI=1
	//2: VLAN tag included when CFH->CFI=1 or
	//                     when CFH->VID != our VID
	//3: VLAN tag included always
	UINT32 maxMtu:14;	//After header conversion,
	// so AMSDU subframe header->length > MTU, drop it.
	UINT32 forceSa:1;	//AMSDU subframe header->SA = TA
	UINT32 rsvd2:3;
} TXD_BSS_t;

typedef struct TXD_STA_t {
	//DW0
	UINT32 raLow;		//STA address
	//DW1
	UINT32 raHigh:16;	//
	UINT32 txLimitIndex:8;	//for Tx Limit Table
	UINT32 markDropRate:8;
	//DW2
	UINT32 l0SizeDw;	//[DWORD]
	//DW3
	UINT32 l0SizePkt:24;	//[packet]
	UINT32 bssIndex:8;
	//DW4
	UINT32 vlanId:12;	//our VID
	UINT32 vlanMode:2;	//0: VLAN tag never included in packet
	//    ignore CFH->vid
	//1: VLAN tag never included in packet
	//    error on CFH->VID != our VID
	//    error on CFI=1
	//2: VLAN tag included when CFH->CFI=1 or
	//                     when CFH->VID != our VID
	//3: VLAN tag included always
	UINT32 maxMtu:14;	//After header conversion,
	// so AMSDU subframe header->length > MTU, drop it.
	UINT32 forceDa:1;	//AMSDU subframe header->DA = RA
	UINT32 ecnEnable:1;	//Mark ECN instead of drop.
	UINT32 rsvd:2;
} TXD_STA_t;

typedef struct TXD_TXLIMIT_t {
	//DW0
	UINT32 l0MinUnit:12;	///< [512-byte]mantissa(8b)+exponent(4b)
	UINT32 l0MinPkt:12;	///< [packet]  mantissa(8b)+exponent(4b)
	UINT32 rsvd1:8;
	//DW1
	UINT32 l0MaxUnit:12;	///< [512-byte]mantissa(8b)+exponent(4b)
	UINT32 l0MaxPkt:12;	///< [packet]  mantissa(8b)+exponent(4b)
	UINT32 rsvd2:8;
} TXD_TXLIMIT_t;

#define Sysfs_Printk(x, ...)      {                                       \
	if (sysfs_buff != NULL) {                                             \
		if ( strlen(sysfs_buff) < (PAGE_SIZE - 128)) {                    \
			sprintf(sysfs_buff + strlen(sysfs_buff),x, ##__VA_ARGS__); }  \
	}                                                                      \
		else {printk(x, ##__VA_ARGS__);}                                   \
	}
extern unsigned long debug_m1_delay;
#endif /* WL_DB_H */
