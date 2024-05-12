/** @file ap8xLnxAcnt.h
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2014-2020 NXP
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

void wlAcntPeekRecds(struct net_device *netdev, u_int32_t * head,
		     u_int32_t * tail);
void wlAcntReadRecds(struct net_device *netdev, u_int32_t newTail,
		     u_int8_t * pBuf, u_int32_t * bufSize);
#if defined(SOC_W906X) || defined(NEWDP_ACNT_CHUNKS)
int wlAcntSetBufSize(struct net_device *netdev, SetAcntBufInfo_t * SetInfo);
void wlAcntProcess_chunks(struct net_device *netdev);
#else
int wlAcntSetBufSize(struct net_device *netdev, u_int32_t size);
void wlAcntProcess(struct net_device *netdev);
#endif /* #if defined(SOC_W906X) || defined(NEWDP_ACNT_CHUNKS) */

extern UINT8 TX_HISTO_PER_THRES[];
extern UINT32 RA_TX_ATTEMPT[2][6];

#ifdef SOC_W906X
#define NUM_INTERNAL_STAT 100
#define ACNT_TX_RECORD_MAX 20000
#define ACNT_MAX_STR_LEN (sizeof(acnt_tx_t) * 2)
#define ACNT_RA_MAX_STR_LEN (sizeof(acnt_RA_stats_t) * 3)
void dump_acnt_internal_stat(u32 entry);
void wl_free_scheHistogram(struct net_device *netdev);
void wl_enable_acnt_record_logging(struct net_device *netdev, UINT16 acnt_code);
void wl_disable_acnt_record_logging(struct net_device *netdev,
				    UINT16 acnt_code);
void wl_write_acnt_tx_record(struct net_device *netdev, char *filename);
void wl_dump_acnt_tx_record(struct net_device *netdev, UINT32 entry);
void wl_write_acnt_RA_stats(struct net_device *netdev, char *filename);
void wl_dump_acnt_RA_stats(struct net_device *netdev, UINT32 entry);
#endif /* SOC_W906X */

typedef struct acnt_s acnt_t;	// Baseline Accounting Record format
enum {				// Definition of accounting record codes
	acnt_code_busy = 0,	// Marked busy until filled in (never seen by Host)
	acnt_code_wrap,		// used to pad when wrapping (no TSF sometimes)
	acnt_code_drop,		// Count of dropped records (acnt_u32_t)
	acnt_code_tx_enqueue,	// TXINFO when added to TCQ (acnt_tx_t)
	acnt_code_rx_ppdu,	// RXINFO for each PPDu (acnt_rx_t)
	acnt_code_tx_flush,	// Flush Tx Queue (acnt_txflush_t)
	acnt_code_rx_reset,	// Channel Change / Rx Reset (acnt_u32_t)
	acnt_code_tx_reset,	// TCQ reset (acnt_u8_t)
	acnt_code_quota_level,	// Quota Level changes (acnt_u8_t)
	acnt_code_tx_done,	// Tx status when done (acnt_tx2_t)
	acnt_code_RA_stats,	// rateinfo PER (acnt_RA_stats_t)
	acnt_code_BA_stats,	// BA stats (acnt_BA_stats_t)
	acnt_code_BF_Mimo_Ctrl_Field_Log,	// BF Mimo Ctrl Field Log (acnt_BF_Mimo_Ctrl_Field_Log_t)
	acnt_code_tx_getNewTxq,	// internal_stat[] from getNewTxq() (acnt_tx3_t)
};

#ifndef SizeRoundScratch	// Haven't included newdp_local.h
typedef struct acnt_s acnt_t;	// Baseline Accounting Record format
typedef struct acnt_rx_s acnt_rx_t;	// Accounting Record for Rx PPDU
#endif

struct acnt_s {			// Baseline Accounting Record format
	u_int16_t Code;		// Unique code for each type
	u_int8_t Len;		// Length in DWORDS, including header
	u_int8_t pad;		// alignment for generic, but specific can reuse
	u_int32_t TSF;		// Timestamp for Entry (when len>1)
};

typedef struct {		// Accounting Record w/ single u8 value
	u_int16_t Code;		// Unique code for each type
	u_int8_t Len;		// Length in DWORDS, including header
	u_int8_t Value;		// User Value
	u_int32_t TSF;		// Timestamp for Entry (when len>1)
} acnt_u8_t;

typedef struct {		// Accounting Record w/ single u32 value
	u_int16_t Code;		// Unique code for each type
	u_int8_t Len;		// Length in DWORDS, including header
	u_int8_t pad;		// alignment for generic, but specific can reuse
	u_int32_t TSF;		// Timestamp for Entry (when len>1)
	u_int32_t Value;	// User Value
} acnt_u32_t;

#ifdef SOC_W906X
typedef struct {		// Accounting Record For Tx ()
	u_int16_t Code;		// Unique code for each type
	u_int8_t Len;		// Length in DWORDS, including header
	u_int8_t Ratetblindex;	// Rate table index for this TxInfo rate
	u_int32_t rateInfo;	// Rate Information (RI_*)
	u_int16_t StnId;	// Station ID
	u_int8_t Type:4;	// SU:0 or MU:1
	u_int8_t AggrType:4;
	u_int8_t Retries;	// Number of prior retries of oldest frame in AMPDU
	u_int32_t Txcnt;	// No. of pkt sent
	u_int32_t NumAmpdu;
	u_int32_t NumBytes;
	u_int32_t DelayTime;
	u_int16_t SchedulePeriod;
	u_int16_t Qid;
	u_int32_t AirTime;
	u_int32_t TimeStamp;
	u_int16_t PhyRate;	//Mbps
	u_int16_t revd1;
	u_int32_t revd2;
} acnt_tx_t;
#else
typedef struct {		// Accounting Record For Tx (at Enqueue time)
	u_int16_t Code;		// Unique code for each type
	u_int8_t Len;		// Length in DWORDS, including header
	u_int8_t TCQ;		// Which TCQ was used
	u_int32_t TSF;		// Timestamp for Entry (when len>1)
	// xxx ZDL/AggCode(2); -- Subset/compress TxINFO? Hdr(Len/DurID/A4)? Time(CSMA vs PPDU)? Latency? Client/QID? nRetry
	u_int64_t BitMap;	// Map of SeqNr when AMPDU
	u_int16_t AirTime;	// Air Time used by PPDU
	u_int16_t nPkts;	// Number of Descriptors sent (AMPDU&AMSDU)
	u_int16_t QID;		// Transmit Queue ID
	u_int16_t Latency;	// Latency of oldest frame in AMPDU (128us)
	u_int16_t Rate1;	// Rate Code for sending data
	u_int16_t Rate2;	// Rate Code for sending RTS/CTS protection
	u_int8_t Ratetblindex;	// Rate table index for this TxInfo rate
	u_int8_t Type;		// SU:0 or MU:1
	u_int8_t pad[1];	// Unused
	u_int8_t Retries;	// Number of prior retries of oldest frame in AMPDU
	u_int32_t Txcnt;	// No. of pkt sent
	tx_info_t TxINFO;	// Transmit parameters used for 1st MPDU in AMPDU
	dot11_t Hdr;		// Dot11 header used for 1st MPDU in AMPDU
	u_int8_t Payload[0];	// Variable Payload by use case
} acnt_tx_t;
#endif /* SOC_W906X */

typedef struct {		// Accounting Record For Tx (after Tx)
	u_int16_t Code;		// Unique code for each type
	u_int8_t Len;		// Length in DWORDS, including header
	u_int8_t pad;		// alignment for generic, but specific can reuse
	u_int32_t TSF;		// Timestamp for Entry (when len>1)
	u_int32_t TxTSF;	// Timestamp when sent
	u_int16_t ActFlags;	// Flags for type of Tx + Response (ActFlags_*)
	u_int8_t NumSent;	// Number of MPDU in AMPDU or TxOP or 1
	u_int8_t NumBad;	// Missing from BA bitmap (only when got BA)
	// xxx status:4? Match w/ Enqueue?
} acnt_tx2_t;

#ifdef SOC_W906X
typedef struct {		// Accounting Record For Tx (after Tx)
	u_int16_t Code;		// Unique code for each type
	u_int8_t Len;		// Length in DWORDS, including header
	u_int8_t pad;		// alignment for generic, but specific can reuse
	u_int32_t TSF;		// Timestamp for Entry (when len>1)
	u_int32_t stat[5 + 3];	// Direct mapping to internal_stat[]. CAUTION: AC_NUM=5. We need to update the array size when AC_NUM is changed!!
} acnt_tx3_t;
#endif /* SOC_W906X */

typedef struct acnt_rx_s acnt_rx_t;
struct acnt_rx_s {		// Accounting Record for Rx PPDU
	u_int16_t Code;		// Unique code for each type
	u_int8_t Len;		// Length in DWORDS, including header
	u_int8_t Flags;		// Flags (ACNTRX_*)
	u_int32_t TSF;		// Timestamp for Entry (when len>1)
	u_int64_t BitMap;	// Map of SeqNr when AMPDU
	u_int16_t AirTime;	// Air Time used by PPDU (no CSMA overhead)
	u_int16_t Rate;		// Rate Code for receiving data
	// xxx Subset/compress RxINFO? Client?
	rx_info_t RxINFO;	// Receive parameters from 1st valid MPDU in AMPDU
};
#define ACNTRX_SCF              0x01	// AMPDU w/ Fragments, Out of Window, Dup, etc
#define ACNTRX_CRC              0x02	// AMPDU Includes frames w/ CRC Errors

typedef struct {		// Accounting Record for Tx Queue Flush
	u_int16_t Code;		// Unique code for each type
	u_int8_t Len;		// Length in DWORDS, including header
	u_int8_t Reason;	// Reason for Flush (txq_rel_*)
	u_int32_t TSF;		// Timestamp for Entry (when len>1)
	u_int32_t nPkts;	// Number of Packets dropped
	u_int16_t QID;		// Transmit Queue ID
	u_int16_t pad;		// Unused
} acnt_txflush_t;

typedef struct {		// Accounting Record w/ rateinfo PER
	u_int16_t Code;		// Unique code for each type
	u_int8_t Len;		// Length in DWORDS, including header
	u_int8_t PER;		// PER for this rateinfo
	u_int32_t TSF;		// Timestamp for Entry (when len>1)
	u_int16_t StnId;	// sta index this rateinfo is tied to
	u_int8_t Type;		// SU:0 or MU:1
	u_int8_t Ratetblindex;	// ratetbl index 
	u_int32_t RateInfo;	// rateinfo for this ratetbl index
	u_int32_t Txattemptcnt;	// Total tx pkt during rate adapt interval
	u_int8_t state;		// state: evaluating or steady
	u_int8_t result;	// evaluate result
	u_int32_t per_threshold;	// PER threshold used for evaluation
	u_int32_t min_pkt_cnt_thres;	// Min pkt cnt threshold
	u_int16_t time_for_decrease;	// Track of time when to reset the variables for decreasing the rate
	u_int16_t time_for_increase;	// Track of the time for increasing the rate
	u_int16_t time_constant_for_increase;	//time_for_increase >= time_constant_for_increase, we will increase the rate
	u_int32_t tx_sent_cnt_raw;	// total tx pkt sent to the this sta
	u_int32_t tx_success_cnt_raw;	// total tx pkt sent successfully to this sta
	u_int32_t tx_failure_cnt_raw;	// total tx pkt sent failurely to this sta
} acnt_RA_stats_t;

#ifdef NEWDP_ACNT_BA
typedef struct {		// Accounting Record w/ rateinfo PER
	u_int16_t Code;		// Unique code for each type
	u_int8_t Len;		// Length in DWORDS, including header
	u_int8_t BAhole;	// Total missing pkt in a BA
	u_int32_t TSF;		// Timestamp for Entry (when len>1)
	u_int16_t StnId;	// sta index for this BA
	u_int8_t NoBA;		// No BA received
	u_int8_t BAexpected;	// Total expected pkt to be BA'd
	u_int8_t Type;		// SU:0 or MU:1
	u_int8_t pad[3];	// Unused
} acnt_BA_stats_t;
#endif

#ifdef BF_MIMO_CTRL_FIELD_LOGGING
typedef struct {		// Accounting Record w/ BF MIMO Control Field Data
	u_int16_t Code;		// Unique code for each type
	u_int8_t Len;		// Length in DWORDS, including header
	u_int8_t Type;		// SU:0, MU:1
	u_int32_t TSF;		// Timestamp for Entry (when len>1)
	u_int8_t Received_MAC[6];	// Received Packet Source MAC Address
	u_int16_t Pad;		// Padding
	u_int32_t MIMO_Ctrl_Field;	// BF MIMO Control Field Data
	u_int64_t Comp_BF_Rep_8Bytes;	// First 8 bytes of Compressed BF Report
} acnt_BF_Mimo_Ctrl_Field_Log_t;
#endif
