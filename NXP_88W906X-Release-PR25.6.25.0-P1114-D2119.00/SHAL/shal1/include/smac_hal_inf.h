/** @file smac_hal_inf.h
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

/**
 * @file
 * @brief Main SMAC API entry file.
 *
 * General definitions shared between SFW and external modules (PFW, host, etc.)
 *
 * @if Marvell_internal_doc
 * @note For features of a file to be properly documented by Doxygen, the file
 * itself has to be documented with a \@file block like this one.
 * @endif
 */

#ifndef _SMAC_HAL_INF_H_
#define _SMAC_HAL_INF_H_

/**
 * @brief SMAC HAL version
 */
#define SMAC_HAL_VERSION    0x0087U	///< SMAC HAL version 0.87

#define SHAL_BIT(n)         (1U << n)

#if defined(BOOL)
#undef BOOL
#endif
typedef unsigned int BOOL;

typedef unsigned long long U64;
typedef unsigned int U32;
typedef unsigned short U16;
typedef unsigned char U8;
typedef long long S64;
typedef int S32;
typedef short S16;
typedef signed char S8;

#define FALSE               0
#define TRUE                1
#ifndef NULL
#define NULL              (void *)0
#endif

#ifdef __GNUC__
#define SHAL_INLINE       inline
#else
#define SHAL_INLINE       __forceinline	///< For ARM CC
#endif
#define ALIGNED_START(x)    __align(x)

// ---------- Portability Start ---------
#define SMAC_DMEM_START         0x20000000	///<  PFW or Host modify address as needed

#if defined(BUILD_PFW)

#define SMAC_EVENT_BASE_ADDR    0x90860000	///<  PFW base address
#define SCFG_SEMA_BASE_ADDR     0x90860900	///<  PFW HW semaphore base address

#elif defined(BUILD_SFW)

#define SMAC_EVENT_BASE_ADDR    0x5FF80000	///<  SFW base address
#define SCFG_SEMA_BASE_ADDR     0x5FF80900	///<  SFW HW semaphore base address

#elif defined(BUILD_DFW)

#if defined(TARGET_W9064)

#define SMAC_EVENT_BASE_ADDR    0x91000000
#define SCFG_SEMA_BASE_ADDR     0x91000A00

#else

#define SMAC_EVENT_BASE_ADDR    0x91000000
#define SCFG_SEMA_BASE_ADDR     0x91000A00

#endif				/* #if defined(TARGET_W9064) */

#endif				/* #ifdef BUILD_PFW */
// ---------- Portability End ---------

extern U16 num_running_bss;
extern U16 num_running_sta;

// ---------- System Config Start ---------
#define SMAC_CPU_NUM             (7)

#define SMAC_CHANBAND_2G         0
#define SMAC_CHANBAND_5G         1

#if (!defined(MFG_FW) && !defined(DEFAULT_MFG_MODE))	// DEFAULT_MFG_MODE is used by the driver
#define SMAC_BSS_NUM            32
#define SMAC_STA_NUM            320	///< up to 320 QoS STA
#define SMAC_BSS_NUM_RUNNING	num_running_bss
#define SMAC_STA_NUM_RUNNING	num_running_sta
#else
#define SMAC_BSS_NUM            1
#define SMAC_STA_NUM            8	///< MFG Mode Reduce STA Number
#define SMAC_BSS_NUM_RUNNING    num_running_bss	// Defined in hal_defs.h -> sysinfo.h -> this file
#define SMAC_STA_NUM_RUNNING    num_running_sta	// Defined in main.c -> sysinfo.h -> this file
#endif
#define SMAC_QID_PER_STA        8

#define SMAC_STA_QID_START      (SMAC_BSS_NUM * SMAC_QID_PER_STA)	///< QID for BSS: 0 ~ (SMAC_STA_QID_START-1)
#define SMAC_STA_QID_START_RUNNING      (SMAC_BSS_NUM_RUNNING * SMAC_QID_PER_STA)

#define SMAC_QID_NUM            (SMAC_STA_QID_START + SMAC_STA_NUM * SMAC_QID_PER_STA)
#define SMAC_QID_NUM_RUNNING    (SMAC_STA_QID_START_RUNNING + SMAC_STA_NUM_RUNNING * SMAC_QID_PER_STA)

#if defined(SCFG_SUPERBA)
#define SMAC_MU_TX_NUM          16
#else
#define SMAC_MU_TX_NUM          16
#endif

#if defined(SCFG_SUPERBA)
#define SMAC_MU_RX_NUM          16
#else
#define SMAC_MU_RX_NUM          16
#endif

#define SMAC_TX_LIMIT_TBL_NUM   255

#define SMAC_MAX_BUF_POOL_CNT   8	///< max number of buffer pool count
#define SMAC_BAND_NUM           1	///< 1=single band    2=dual band
#define SMAC_SOFTREG_SIZE       1024
#define SMAC_MSGQ_MAX_ENTRIES   32
#define SMAC_MSGQ_ENTRY_MASK  (SMAC_MSGQ_MAX_ENTRIES - 1)
#define SMAC_MSGQ_BUFSIZE       128
#define DFW_MSGQ_BUFSIZE        64

#define FIPS_EU_TEST_DEC        2
#define FIPS_EU_TEST_ENC        3

#if defined(SCFG_SUPERBA)
#define SMAC_AGR_MPDU_NUM       128	///< up to 256 (except SC5 Z1/Z2: up to 255)
#else
#define SMAC_AGR_MPDU_NUM       64	///< up to 256 (except SC5 Z1/Z2: up to 255)
#endif
#define SMAC_L2_ENTRY_NUM       (SMAC_AGR_MPDU_NUM * 2)
#define SMAC_MU_GROUP_SIZE      64

#define SMAC_TXQ_2_GSTA_INDEX(x)     ((x)->qid >> 3)	//get gSta index from qid. gSta[0] to [31]: dummy bss sta, [>=32]: peer sta
#define SMAC_STA_INDEX_2_TXQ_ID(x)   ((SMAC_BSS_NUM_RUNNING + x) * SMAC_QID_PER_STA)
#define SMAC_GSTA_INDEX_OFFSET(x)    ((x) + SMAC_BSS_NUM_RUNNING)	//get peer sta gSta index from sta index (with base starting from 0)
#define SMAC_GSTA_2_STA_INDEX(x)     ((x) - SMAC_BSS_NUM_RUNNING)	//get peer sta index (with starting base 0) from gSta index

#define SMAC_MAX_OFDMA_USERS       18	///< Maximum number of OFDMA users

#define SMAC_TX_AMPDU_MIN_MPDU_SPACING   4	//2 us

#define RX_BA_SN_OVER_2K_CNT_THRES       2	//Threshold for consecutive rx sn > 2048 in PPDUs to move BA wStart. wStart moves after this cnt threshold

#define DBG_BA_SHIFT_BACK

/** In this feature, extra TCQ has been added to serve bufferred multicast/broadcast packets **/
//#define SCFG_MCQ_SUPPORT

// ---------- System Config End ---------

#ifndef DRV_SKIP_DEFINE		/* DRV got warnings from these portion since it's not used in DRV. So, skip in DRV */
#include "shal_util.h"		// forced
#include "shal_list.h"
#include "shal_stats.h"		// forced
#endif
#include "shal_event.h"		// required
#include "shal_txq.h"		// required
#ifndef DRV_SKIP_DEFINE
#include "shal_sta.h"		// required
#include "shal_bss.h"		// required
#include "shal_txinfo.h"	// required
#include "shal_sched.h"		// required

#include "shal_msg.h"		// required

#include "shal_api.h"		// required
#include "shal_ac.h"		// required

#include "shal_sema.h"		// required
#include "shal_sbf.h"		// required
#include "shal_util2.h"		// required
#else
#include "shal_sta.h"		// required
#include "shal_bss.h"		// required
#endif

//compiler flag shared by both pfw/sfw
/** MMDU Tx support for data and MGMT frames on station's 7th queue. **/
/** gMgmtTxq based legacy method will be used for handling MGMT frames if this flag is disabled **/
#define SCFG_MMDU_STA_QUE

/**
 * @struct SMAC_CONFIG_st
 * @brief SMAC global configuration
 *
 * This is the top-level data-structure used to set configuration of SFW.\n
 * The information is actually exchanges through a single instance of this data-structure,
 * located at the beginning of DMEM.
 *
 */
typedef struct SMAC_CONFIG_st {
	U32 magic;		///< 0x000: SHAL version
	U32 smacBmBaseAddr;	///< 0x004: DDR pointer for maximum 64MB memory space for SMAC FW only buffer mgmt
	U32 smacBmSize;		///< 0x008: actual size of DDR buffer

	// Buffer pool info
	U8 bpReqCnt;		///< 0x00C: Total number of buffer pool requests; max=8
	U8 bpRelQid;		///< 0x00D: buffer pool release qid to host.
	U8 ddrHighAddr;		///< 0x00E: upper 8 bit of DDR address
	U8 txAnt;		///< 0x00F: bitmap of TX antennas enabled: 0x0 - 0xF/0xFF

	U32 opMode;		///< 0x010: Operation mode set by SMAC_OPMODE definitions
	U32 txStop;		///< 0x014: bit control map to stop corresponding BSS. If any bit is 1: stop that BSS, 0: Tx allowed in that BSS
	U32 txAcStop;		///< 0x018
	U32 qIntAddr;		///< 0x01C

	U32 qIntOffset;		///< 0x020
	U32 bcnStop;		///< 0x024: bitmap of 32 BSS. 1: do not Tx beacons. 0: Tx beacons. This is independent of data Tx stop / start
	U32 euFlushOff;		///< 0x028: [3] rxAmsdu [2]: fifo, [1]: rx, [0]: tx. 1: off, 0: on
	U32 txEuFlushDly;	///< 0x02C

	U32 rxEnable;		///< 0x030: 1: Enable Rx by setting the rx_bbifc to 1. 0: disable Rx (default)
	U32 bfControl;		///< 0x034: BF internal mode control
	U32 baRodrTMOThres;	///< 0x038  Non zero enable BA reorder and acts as timeout threshold, 0: disable BA reorder
	U8 bpReleseQid[4];	///< 0x03C

	struct bpReqInfo {
		U16 size;	///<  unit of 16B, up to 1M.
		U8 bpid;	///<  host buffer pool id.
		U8 qid;		///<  10, 11, 12, 13, etc.
	} bpReqInfo[SMAC_MAX_BUF_POOL_CNT];	///< 0x040

	U8 dbcEnable;		///< 0x060: bit control map to set to more than single band.
	U8 dbcFreq;		///< 0x061: bit control map of band frequency setting. 0: 5GHz, 1: 2GHz

	// Notes: Used how to process management frame
	U16 rxMgmtSfwProcBm;	///< 0x062: (1 << Mgmt_Subtype) 0:to Host, 1:Processed by SFW
	U16 rxMgmt2PfwBm;	///< 0x064: (1 << Mgmt_Subtype) 0:Processed by SFW, 1:Forward to PFW(Only if rxMgmtSfwProcBm bit = 1)
	U16 timeBeforeTBtt;	///< 0x066: SFW will send message to PFW timeBeforeTBtt us before TBTT

	U32 amsduWaitPeriod;	///< 0x068

#ifdef DSP_COMMAND
	U16 dspIntMode;		///< 0x06C
	U16 rsvd3[1];		///< 0x06E
#else
	U16 rsvd3[2];		///< 0x06C
#endif

	S16 txpwr_abcd_therm_offset;	///< 0x070
	S16 txpwr_efgh_therm_offset;	///< 0x072

	U8 rxAnt;		///< 0x074: number of RX antenna enabled: 1 ~ 4/8
	U8 gpio17_bcn_toggle_en:1;	///< 0x075.0: Enable GPIO17 to follow beacon transmit. E.g. When Beacon is transmitting, GPIO17 is high, otherwise low.
	U8 phy_devbw:3;		///< 0x075[3:1]: PHY / Radio Device BW (see HAL_CHANWIDTH_x_MHZ)
	U8 legacy_dup_mode:3;	///< 0x075[6:4]: Legacy / Non-HT packet duplicate mode setting (see BBTX_ACT_SUB_PRIXXX in shal_txinfo.h)
	U8 en_6dB_boost:1;	///< 0x075[7]: Enable 6 dB Boost Mode

	U8 irToDelay;		///< 0x076 IR timeout delay in usec.
	U8 rsvd7;

	U32 eventq_addr;	///< 0x078 Event buffer queue address (base address of the buffer)
	U16 eventq_nums;	///< 0x07C Event buffer queue number (# of items
	U16 eventq_size;	///< 0x07E Event buffer queue size (size of each item)

	U32 maxNAV;		///< 0x080 //Max NAV timer value in us

	U32 cal_data_conf_phy_addr;	///< 0x084: Cal Data Conf File on Host: Host physical address for DMA
	U32 cal_data_conf_data;	///< 0x088: DMA Data
	U32 cal_data_conf_signature;	///< 0x08C: Ready Signature: STA_EE_SIGNATURE

	U32 staAid;		///< 0x090
	U32 txFrmDmemBaseAddr;
	U32 prd_csi_dma_ddr_addr;	///< 0x098: Temporary PRD_CSI_DMA DDR Address. Remove after full ring buffer hook up
	U32 txAmsduInSec;	///< 0x09C

	U8 rssiAbortEn;		///<0x0A0: rx abort based on rssi enable bit. Default disabled
	U8 rssiAbortThres;	///< rx abort rssi threshold (read as negative value, 70 means -70). Default set to 70
	U16 rssiAbortLenThres;	///< rx abort bytes length threshold. Abort only if rx len > threshold

	U8 srAbortEn;		///<0x0A4: Spatial reuse rx abort enable bit. Default disabled
	U8 srNonSrgEn;		///< 1:Non-SRG OBSS PD enabled, 0: disabled
	U8 srSrgEn;		///< 1:SRG OBSS PD enabled, 0: disabled
	U8 dbm_buf_num_pfw;

	U16 num_running_bss;	///< 0x0A8: number of running bss and sta
	U16 num_running_sta;
	S32 rtsCtsDurAdjust;	///< 0x0AC: RTS/CTS-self durtion adjustment

	U32 wfaConfig;		///< 0x0B0
	U8 bwSigCtrl;		///< 0x0B4 b0:BBTX_BW_SIG_STATIC, b1:DYNAMIC
	U8 enable_Rx_BA_Enh;	///< 0x0B5 TEMP - Enable Rx BA Enhancement. Turn on for non 11ax first.
	U8 BARRetryLimit;	///< 0x0B6 BAR frame retry limit
	U8 rsvd5[1];

	U32 pfwExceptionMode;	///< 0x0B8
	U32 rxProcCapa;		///< 0x0BC Unit: 1/8 usec

	U8 backoffMode;		///< 0x0C0
	U8 immRspCcaDetect;	///< 0x0C1
	U8 rsvd_int_cfg[2];	///< 0x0C2
	U32 ampduTxLifeTime;	///< 0x0C4
	U32 beaconRetryMax;	///< 0x0C8
#if defined(STAMODE_ULOFDMA)
	U32 rsvd6[10];		///< 0x0CC
	U32 stopSU;		///< 0x0F4
#else
	U32 rsvd6[11];		///< 0x0CC
#endif
	U32 ForceSU[2];		///< 0x0F8 Force GID stn to SU
	U32 acntTxMsduRingBaseAddr;	///< 0x100
	U32 acntTxMsduRingSize;	///< 0x104: number of ring entry
	U32 acntRxInfoQueBaseAddr;	///< 0x108
	U32 acntRxInfoQueSize;	///< 0x10C: number of queue entry

	U32 acntTxBaseAddr;	///< 0x110    tx accounting record base in DDR
	U32 acntTxSize;		///< 0x114    allocated memory size
	U32 acntTxRdPtr;	///< 0x118
	U32 acntTxWrPtr;	///< 0x11C

	U32 acntRxBaseAddr;	///< 0x120    rx accounting record base in DDR
	U32 acntRxSize;		///< 0x124    allocated memory size
	U32 acntRxRdPtr;	///< 0x128
	U32 acntRxWrPtr;	///< 0x12C

	U8 rsvd[SMAC_SOFTREG_SIZE - (16 * 17) - (sizeof(struct bpReqInfo) * SMAC_MAX_BUF_POOL_CNT)];

} SMAC_CONFIG_st;

/* De not change value of SMAC_OPMODE definitions */
#define SMAC_OPMODE_NORMAL          0x00000000
#define SMAC_OPMODE_M2M_LOOP_BACK   0x00000100
#define SMAC_OPMODE_PROMISC_MGMT    0x00000200
#define SMAC_OPMODE_PROMISC_CTRL    0x00000400
#define SMAC_OPMODE_PROMISC_DATA    0x00000800
#define SMAC_OPMODE_PROMISC         0x00000E00
#define SMAC_OPMODE_FCS_ERR_PASS    0x00001000
#define SMAC_OPMODE_MONITOR_ON      0x00002000	///<  Filtered by SMAC_OPMODE_PROMISC_XXXX
#define SMAC_OPMODE_DROP_MSDU_AGR   0x02000000
#define SMAC_OPMODE_DROP_BO_TX      0x04000000
#define SMAC_OPMODE_HOST_DROP_RX    0x20000000
#define SMAC_OPMODE_DBG_DROP_RX     0x40000000
#define SMAC_OPMODE_DEBUG_RSVD      0x80000000

#define SMAC_OPMODE_PROMISC_ERR_PASS    (SMAC_OPMODE_PROMISC | SMAC_OPMODE_FCS_ERR_PASS)

/** added pfw->smac txq reserved definitions  **/
#define PFW_SMAC_DROPMODE          0x00000001

/** bit field for SMAC_CAP **/
#define SMAC_CAP_MMDU_NOT_SUPPORT   1

/**
 * @struct SMAC_STATUS_st
 * @brief SMAC global status
 *
 * This is the top-level data-structure used to return SMAC global status
 */
typedef struct SMAC_STATUS_st {
	volatile U8 smacRdy[8];	///<  0x400: SMAC init done, ready
	U32 smacCap;		///<  0x408: BIT0 = MMDU_NOT_SUPPORT
	U16 smacDmemVer;	///<  0x40C: SMAC DMEM version (0x0001)
	U16 smacDmemLen;	///<  0x40E: SMAC DMEM length in KByte (scatter define)

	U32 verCtrl[4];		///<  0x410: SMAC FW version, SHAL version

	U32 txInputCnt;		///<  0x420: Received MSDU from HW (Data)
	U32 txSchedCnt;		///<  0x424: Scheduled PPDU by PFW
	U32 txProcCnt;		///<  0x428: Send/drop PPDU
	U32 txBufRetCnt;	///<  0x42C: Return buffer MSDU (Data/Mgmt)

	U32 txAcRingCnt;	///<  0x430: Tx MPDU AC ring insert (Data/Mgmt)
	U32 txCtlFrmCnt;	///<  0x434: Tx control frame count (inc. BCN)
	U32 txEuDoneCnt;	///<  0x438: Tx Eu done
	U32 txRdyDeassert;	///<  0x43C: Tx ready deassert

	U32 sop_EvtMacHdr;	///<  0x440: Receive from HW
	U32 eop_EvtEuDone;	///<  0x444: Process by EU
	U32 fcs_EvtFcs;		///<  0x448: HW FCS count
	U32 eop2_Q2RxAmsdu;	///<  0x44C: EOP2 send to host by queuing to RxAmsdu

	U32 sop_EuPrgm;		///<  0x450: RX Eu program
	U32 eopDrp_EuErr;	///<  0x454: RX Eu error and pkt will be dropped
	U32 fcsDrp_FcsErr;	///<  0x458: FCS err count
	U32 eop2Drp_Cnt;	///<  0x45C: EOP2 Drop count

	U32 fcs_UniMCast[2];	///<  0x460: uniPktCnt, 0x464: multiPktCnt
	U32 bman_GetBuf;	///<  0x468
	U32 bman_RetBuf;	///<  0x46C

	U32 slotTickCnt;	///<  0x470: Slot tick count
	U32 firstSlotTickCnt;	///<  0x474: first Slot tick count
	U32 txMgmPktCnt;	///<  0x478: tx mgmt pkt count
	U32 txBcnCnt;		///<  0x47C: Tx Beacon count

	U32 sysRsvd1[2];	///<  0x480: debug log1
	U32 navBlockCnt;	///<  0x488: TXD6 NAV block count
	U32 txBcnAbort;		///<  0x48C: Tx Beacon Abort count

	U32 sysRsvd2[4];	///<  0x490: TXD1 counts

	U32 sysRsvd3[4];	///<  0x4A0: TXD2 counts: PGM / DONE / MSDU / MPDU

	U32 sysRsvd4[4];	///<  0x4B0:

	U32 sysRsvd5[4];	///<  0x4C0: [2]Rssi rx abort counter

	U32 sysRsvd6[12];	///<  0x4D0

	volatile U32 smacSts[12];	///<  0x500: SMAC status
	U32 sysRsvd7[2];	///<  0x530
	U32 txAcntNoADMA;	///<  0x538: Tx acnt record, No ADMA to host due to dest buf or desc full
	U32 rxAcntNoADMA;	///<  0x53C: Rx acnt record, No ADMA to host due to dest buf or desc full

	U16 sopDrp_GiantPkt;	///<  0x540: bigger than 11KB MPDU
	U16 sopDrp_TinyPkt;	///<  0x542: smaller than 4B MPDU
	U32 txStopAck;		///<  0x544: bit status map to acknowledge the corresponding BSS TX stop configuration (SCFG.txStop)
	U32 lastTxInfoErr;	///<  0x548: last Tx Info error codes
	U8 bmanErr_GetBuf[4];	///<  0x54C: RX Empty buffer count

	U32 eopDrp_EmptyBuf;	///<  0x550: RX empty buffer drop count
	U32 txqSlotTxqEmpty;	///<  0x554: TX slot with empty txq list count
	U32 sysRsvd8[2];	///<  0x558 debug OFDMA UL stainfo download

	U32 txDataTxMsduCnt;	///<  0x560
	U32 txDataBufRetMsduCnt;
	U32 txMgtTxMsduCnt;
	U32 txMgtBufRetMsduCnt;

	U32 bman_StsReqBp;	///<  0x570
	U32 maxSizeBcnbuf;	///<  0x574 Max size of memory allocated to each beacon
	U32 rxSBinfoBaseAddr;	///<  0x578 RX Sideband info buffer base in DDR
	U32 rxSBinfoUnitSize;	///<  0x57C RX Sideband info buffer unit size for SB index in CFH-UL

	U32 sysRsvd9[16];	///<  0x580 [2]TxRTS [4]TxCTS 
	U32 sysRsvd10[8];	///<  0x5C0

	U32 TStxPeRise;		///<  0x5E0
	U32 TStxRdyFall;	///<  0x5E4
	U16 TStxSum_H;		///<  0x5E8
	U16 TSsys_H;		///<  0x5EA
	U32 TStxSum;		///<  0x5EC
	U32 sysRsvdBB[4];	///<  0x5F0 for PHY and BB

	U32 sysRsvdMU0[4];	///<  0x600 for MU
	U32 sysRsvdMU[12];	///<  0x610 for MU

	U32 sysRsvd11[16];	///<  0x640
	U32 sysRsvd12[4];	///<  0x680

	U32 CSI_RSSI_AB;	///<  0x690 - CSI Per Path RSSI Since BFINFO Per Path RSSI is legacy format
	U32 CSI_RSSI_CD;
	U32 CSI_RSSI_EF;
	U32 CSI_RSSI_GH;

	U8 CSI_Pkt_MAC_Addr[6];	///<  0x6A0 - CSI Packet MAC Address
	U8 CSI_Pkt_Type;	///<  0x6A6 - CSI Packet Type
	U8 CSI_Pkt_SubType;	///<  0x6A7 - CSI Packet Subtype
	U32 CSI_TX_Timestamp;	///<  0x6A8 - CSI TX Timestamp
	U32 CSI_RX_Timestamp_Lo;	///<  0x6AC - CSI RX Timestamp Lo bits

	U32 CSI_RX_Timestamp_Hi:8;	///<  0x6B0 - CSI RX Timestamp Hi bits
	U32 CSI_CFO:20;		///<        - CSI CFO
	U32 CSI_reserved1:4;	///<        - CSI reserved1

	U32 CSI_DTA:11;		///<  0x6B4 - CSI DTA
	U32 CSI_Valid:1;	///<        - CSI Valid
	U32 CSI_Count:15;	///<        - CSI Count
	U32 CSI_reserved2:5;	///<        - CSI reserved2

	volatile U32 cm3StartFlag;	///<  0x6B8 //bit[0]=1 to start CM3_0, and similar to bit[6:1] 
	volatile U32 cm3StopFlag;	///<  0x6BC //bit[0]=1 to stop CM3_0, and similar to bit[6:1]
	U16 txBcnCntBss[32];	///<  0x6C0

	U8 lastCm3Event[16];	// 0x700: last Cm3 event bit

	U32 dmaTime[4];		// 0X710: See TXL2_dmaEndTime()

	U32 txTime[2];		// 0x720: txTime (measure after grp1), 0x724: difference from previous
	U32 lastSwTxinfo;	// 0x728: pointer of gSwTxInfo
	U32 giantPktSize;	// 0x72c: max packet size bigger than 11KB MPDU

	U32 eop2_EvtTxCnt;	// 0x730: EOP2 event counts sent from EOP
	U32 eop2_EvtRxCnt;	// 0x734: EOP2 event counts received by EOP2
	U32 eop2Err_RxMpduNULL;	// 0x738: EOP2 event with rxMpdu==NULL
	U32 eop2Drp_CfhNotDone;	// 0x73C: EOP2 drop cnt for rx CFH ADMA not done for RxAmsdu to use

	U32 eopDrp_eofSent;	// 0x740:
	U32 eopDrp_8P2WAR;	// 0x744: EOP drop cnt for ignoring pkt due to 8.2 WAR. Not to save trailing rx pkt after txpe, thpt will impacted
	U32 sopErr_OutOfOrder;	// 0x748
	U32 eopDrp_EuDoneMiss;	// 0x74c

	U16 eop2Drp_Len0;	// 0x750: EOP2 drop cnt due to len==0 for RxAmsdu
	U16 eop2Drp_destDrop;	//        EOP2 drop for rxMpdu->destCode == DROP in RXD_dgrSetQcmd
	U16 eop2Drp_FcsNoVal;	// 0x754: EOP2 drop cnt for not determined fcsState==0. 
	U16 eop2Drp_FCSBuf;	//        EOP2 drop when fcsState0 buffer routine error
	U32 eop2Drp_StaPtrNull;	// 0x758: EOp2 drop cnt data pkt for staPtr==NULL
	U32 eop2Drp_FcsBad;	// 0x75c: EOP2 drop cnt for bad fcsState==2

	U32 eopDrp_EuErr2[4];	// 0x760

	U32 txTimingDbg1[10];	// 0x770: running when duplicate happens
	U16 gTxBusyErr1;
	U16 gTxBusyErr2;
	U32 gTxBusyTS;
	U32 txTimingDbg2[12];	// 0x7A0: what makes be duplicate

	U32 bmanErr_RelBadBpid;	// 0x7D0: release invalid bpid buffer.  Should NOT happen
	U32 eop2Drp_RxAmsduQFull;	// 0x7D4: EOP2 RxAmsdu all queues are full and return without releasing buf.  Should NOT happen
#ifdef RXINFO_WAR_EN
	U16 eop2Drp_RxAmsduBGQFull;	// 0x7D8: EOP2 background queue for RxAmsdu full. Should NOT happen
	U16 fcsErr_RxInfoIdxOoB;	// 0x7DA: RxInfo WAR index out of bound
#else
	U32 eop2Drp_RxAmsduBGQFull;	// 0x7D8: EOP2 background queue for RxAmsdu full. Should NOT happen
#endif
#ifdef DBG_BA_SHIFT_BACK
	U16 eop2Drp_AggNoBaAgrmnt;	// 0x7DC: EOP drop due to rx aggregate pkt without BA agreement
	U16 wStartShiftBack;
#else
	U32 eop2Drp_AggNoBaAgrmnt;	// 0x7DC: EOP drop due to rx aggregate pkt without BA agreement
#endif
	U32 fcsErr_eofNoFcsEvt;	// 0x7E0: FCS EOF has no FCS event
	U32 tf_detect_count;	// 0x7E4: number of Rx TF detect events seen by SFW
	U32 tf_done_count;	// 0x7E8: number of Rx TF done events seen by SFW
	U32 tf_detect_fcs_bad;	// 0x7EC: number of Rx TF with bad FCS seen by SFW

	U8 rsvd[SMAC_SOFTREG_SIZE - (63 * 16)];
} SMAC_STATUS_st;

// Histogram
typedef struct SMAC_STS_HISTO_st {
	U32 txDataUser[SMAC_MU_TX_NUM];	// Data histogram of TX users
	U32 txDataAck[SMAC_MU_TX_NUM];	// Data histogram of Rx Ack or BA from TX users
} SMAC_STS_HISTO_st;

#define SMAC_SFW_SIZE       (SMAC_SOFTREG_SIZE * 2)
#define SMAC_SFW_STS_SIZE   (0x200 + sizeof(SMAC_STS_HISTO_st))	// Add size info here

typedef struct SMAC_SFW_st {
	volatile U32 ready;	/* 0x800 */
	U32 adma2_4_ctr;
	U32 adma2_4_src;
	U32 cmd_debug;
	U32 cmd_val;		/* 0x810 */
	U32 phy_hal_state;	/* PHY HAL Operating State */
	U32 cmd_thread_alive;
	U32 sche_thread_alive;
	U32 idle_thread_alive;	/* 0x820 */
	U32 bad_vector_val;
	U32 bad_vector_fsr;
	U32 bad_vector_far;
	U32 diag_mode_regs[13];	/* 0x830 */
	U32 diag_mode_sp;
	U32 diag_mode_lr;
	U32 diag_mode_cpsr;
	U32 diag_mode_bv_pc;	/* 0x870 */
	U32 cm3_0_pc;
	U32 cm3_1_pc;
	U32 cm3_2_pc;
	U32 cm3_3_pc;		/* 0x880 */
	U32 cm3_4_pc;
	U32 cm3_5_pc;
	U32 cm3_6_pc;

	U32 irq_level;		/* 0x890 */
	U32 irq_err_save;
	U32 irq_save_cnt;
	U32 irq_restore_cnt;
	U32 irq_err_restore_max;	/* 0x8A0 */
	U32 irq_err_restore_min;
	U32 irq_state[8];	/* 0x8A8 */

	U32 rsvd4Pfw[(0x100 - 0xC8) / 4];	/* 0x8C8 */

	U32 irTxPeTO;		/* 0x900 */
	U32 rsvd4Single[(0x100 - 0x04) / 4];

	SMAC_STS_HISTO_st histo;	/* 0xA00 */

	U8 rsvd[SMAC_SFW_SIZE - SMAC_SFW_STS_SIZE];
} SMAC_SFW_st;

/**
 * @struct SMAC_CTRL_BLK_st
 * @brief Structure of control block in DMEM
 *
 */
// By means of scatter file, make sure fix address
typedef struct SMAC_CTRL_BLK_st {
	/////////////////////////////////////////////////////////////
	/// @name (1) Global SMAC configuration (From 0x2000_0000, 1KB)
	/// @{
	/////////////////////////////////////////////////////////////
	SMAC_CONFIG_st config;
	/// @}

	/////////////////////////////////////////////////////////////
	/// @name (2) Global SMAC status flags (From 0x2000_0400, 1KB)
	/// @{
	/////////////////////////////////////////////////////////////
	SMAC_STATUS_st status;
	/// @}

	/////////////////////////////////////////////////////////////
	/// @name (3) Fixed memory region for SFW (0x20000800 to 0x20001000)
	/// @{
	/////////////////////////////////////////////////////////////
	SMAC_SFW_st sfw;
	/// @}

#ifndef DRV_SKIP_DEFINE

	/////////////////////////////////////////////////////////////
	/// @name (4) Messaging between SFW and PFW/Host/etc.
	/// @{
	/////////////////////////////////////////////////////////////
	HAL_MSGQ_CTRL_st gMsgQuePfw2Sfw;	///< used by PFW to send commands to SFW
	HAL_MSGQ_CTRL_st gMsgQueSfw2Pfw;	///< used by SFW to send command response to PFW
	HAL_MSGQ_CTRL_st reserved[2];

	U8 gMsgBufPfw2Sfw[SMAC_MSGQ_MAX_ENTRIES][SMAC_MSGQ_BUFSIZE];	///< Message buffers
	U8 gMsgBufSfw2Pfw[SMAC_MSGQ_MAX_ENTRIES][SMAC_MSGQ_BUFSIZE];	///< Message buffers
	HAL_SFW_PWR_ANT_CFG_st *gsfw_pwr_ant_tblPtr;	///< SFW Power and Antenna Configuration Table for SFW Generated Packets
	HAL_SFW_DRA_NF_STATS_st gDRA_NF_Stats;
#ifdef MFG_FW
	SMAC_STA_ENTRY_st *gAllPurposeStaPtr_MFG;	///< MFG Beacon Control Pointer
	HAL_MFG_CFG_st *gmfg_cfg_ptr;	///< MFG General Configurations
	HAL_MFG_NDPA_NDP_CFG_st mfg_ndpa_ndp_cfg;	///< MFG NDPA / NDP Configuration for IBF Calibration
#endif
#if defined(MFG_FW) || defined(PRD_CSI_DMA)
	HAL_MFG_CSI_CFG_st mfg_csi_cfg;	///< MFG CSI Configuration for IBF Cal, AoA, CSI
#endif
	/// @}

	/////////////////////////////////////////////////////////////
	/// @name (5) Data structure base pointers
	/// @{
	/////////////////////////////////////////////////////////////

	SMAC_STA_ENTRY_st *staTbl;
	SMAC_STA_STATISTICS_st *statsTbl;
	SMAC_BSS_ENTRY_st *bssTbl;
	SMAC_TXQ_ENTRY_st *txqTbl;
	volatile SMAC_TXD_TXLIMIT_st *txqLimit;
	 SHAL_L2_SW_ENTRY_st(*l2CacheSwTbl)[SMAC_L2_ENTRY_NUM];
#if defined(DBG_SCHEDULER_TRACE)
	SCHEDTRACE_st *dbgSchedtrace;
	U32 *dbgPFWtrace;
#endif
	U32 *ulOFDMA_stats;
	/// @}

	/////////////////////////////////////////////////////////////
	/// @name (6) Transmit Category Queues
	/// @{
	/////////////////////////////////////////////////////////////
	AC_ENTRY_st *acBasePtr;
	TCQ_RING_st *tcqRingBasePtr;	///< UP mapping is the same as in  the AC lists
	HAL_BEACON_st *bcnBasePtr;
	U32 *prbBaseptr;
	U32 *tfBasicPtr;
	U32 *tfMuRtsPtr;
	/// @}

	/////////////////////////////////////////////////////////////
	/// @name (7) Older messaging interface between SFW and PFW/Host/etc.
	/// @{
	/////////////////////////////////////////////////////////////
	struct {
		SMAC_LBM_st *lbm;
		SMAC_MSQ_st *que;
	} msg[SMAC_BAND_NUM][2];	///< [0]=pfw_2_sfw        [1]=sfw_2_pfw
	/// @}

#ifdef DSP_COMMAND
#define PFW_DFW_MSGQ_MAX_ENTRIES        8
#define DFW_PFW_MSGQ_MAX_ENTRIES        16
#define DFW_MSGQ_BUFSIZE                64

	U32 dfwReady;
	U32 pfwEventCntProc0;
	U32 pfwEventCntProc1;
	U8 gMsgBufPfw2DfwLow[PFW_DFW_MSGQ_MAX_ENTRIES][DFW_MSGQ_BUFSIZE];	///< Message buffers
	//U8 gMsgBufPfw2DfwMid[PFW_DFW_MSGQ_MAX_ENTRIES][DFW_MSGQ_BUFSIZE]; ///< Message buffers
	U8 gMsgBufPfw2DfwHig[PFW_DFW_MSGQ_MAX_ENTRIES][DFW_MSGQ_BUFSIZE];	///< Message buffers
	U8 gMsgBufDfw2Pfw[DFW_PFW_MSGQ_MAX_ENTRIES][DFW_MSGQ_BUFSIZE];	///< Message buffers
	HAL_DFW_MSGQ_CTRL_st gMsgQuePfw2DfwLow;	///< used by PFW to send commands to DFW
	//HAL_DFW_MSGQ_CTRL_st gMsgQuePfw2DfwMid; ///< used by PFW to send commands to DFW
	HAL_DFW_MSGQ_CTRL_st gMsgQuePfw2DfwHig;	///< used by PFW to send commands to DFW
	HAL_DFW_MSGQ_CTRL_st gMsgQueDfw2Pfw;	///< used by DFW to send command response to PFW
#if defined(BUILD_SW_MIMO)
	U32 pBfSmTblBase;
	SMAC_SBF_ENTRY_st *pSbfBase;
#endif
#endif				/* DSP_COMMAND */

	U32 *srIntfRssi_ptr;	///<ptr to OBSS_PD interference RSSI log
#endif				/* DRV_SKIP_DEFINE */
} SMAC_CTRL_BLK_st;

#define RPT_ID_BY_MSG  0x80
#define RPT_ID_BY_FLG  0x40

#define RPT_ID_NONE           0x00
#define RPT_ID_OFF_CHAN      (0x01 | RPT_ID_BY_MSG)
#define RPT_ID_MFG_PFW_TX    (0x02 | RPT_ID_BY_MSG)
#define RPT_ID_FTM_TX_DONE   (0x03 | RPT_ID_BY_MSG)
#define RPT_ID_TF_BSRP       (0x04 | RPT_ID_BY_FLG)
#define RPT_ID_TF_BASIC      (0x05 | RPT_ID_BY_FLG)
#define RPT_ID_UL_GROUP      (0x06 | RPT_ID_BY_MSG)
#define RPT_ID_MASK           0xff

#define TX_ACNT_RCD         FALSE	//Tx accounting record
#define RX_ACNT_RCD         FALSE	//Rx accounting record

#define TX_ACNT_RCD_TEST    FALSE	//For testing purpose, to be removed once testing is done

#define TX_ACNT_INTRPT  30
#define RX_ACNT_INTRPT  28

#define TX_ACNT_USER_NUM        2	//todo... change to 16 users when dmem size allows

#define TX_ACNT_MAX_NUM_TID     1	//up to 8, but now only support 1 TID per AMPDU
#define TX_ACNT_MAX_NUM_AGGR    128	//up to 256

#define TX_ACNT_TYPE_HOST_NOACK     0	//host generated without ack/ba
#define TX_ACNT_TYPE_HOST_ACK       1	//host generated with ack
#define TX_ACNT_TYPE_HOST_BA        2	//host generated with ba
#define TX_ACNT_TYPE_SFW            3	//sfw generated
#define TX_ACNT_TYPE_DONE           4	//tx done (after rx ack/ba or timeout)

#define TX_ACNT_DONE_ACK            0	//Non AMPDU Ack
#define TX_ACNT_DONE_BA             1	//BA as ack
#define TX_ACNT_DONE_TMO            2	//Timeout, no ack received

#define TX_ACNT_MAX_BODY_LEN        2048

#define RX_ACNT_MAX_NUM_TID     1	// todo... increase to 8
#define RX_ACNT_USER_NUM        1	// todo... increase to 16
#define RX_ACNT_MAX_NUM_AGGR    128	// todo... increase to 256
#define RX_ACNT_BMAP_SIZE       (RX_ACNT_MAX_NUM_AGGR>>3)

#define RX_ACNT_TYPE_MGMT       0
#define RX_ACNT_TYPE_CTRL       1
#define RX_ACNT_TYPE_DATA       2

/******** Tx acnt common ********/
/*******************************/
typedef struct SMAC_ACNT_TX_PPDU_HDR_st {
	//DW0
	U8 version:4;		// 0
	U8 type:4;		// 0: host generated no ack/ba, 1: host with Ack, 2:host with BA, 3: SFW generated, 4: tx done
	U8 numUsers;		// 1 to 16
	U8 rsvd[2];

	//DW1
	U32 timestamp;		// low 32-bit TSF
} SMAC_ACNT_TX_PPDU_HDR_st;

/*** Tx accounting host generated ***/
/*******************************/
typedef struct SMAC_ACNT_TX_HOST_HDR_st {
	//DW0
	U8 userId:4;		//0~16
	U8 numTids:4;		//Total tid cnt used for this user
	U8 rsvd;
	U16 txPower;		//TBD format, txpwr_abcd:11bit and txpwr_efgh:11bit

	//DW1
	U32 txRate;		//TBD format      

	//DW2-10
	U32 Hdr80211[9];	//802.11 header of first MPDU, TBD format
} SMAC_ACNT_TX_HOST_HDR_st;

typedef struct SMAC_ACNT_TX_MPDU_TID_INFO_st {
	//DW0
	U32 tid:4;
	U32 rsvd:4;
	U32 numMpdu:8;		// 1-255,0=256: number of MPDU in this TID
	U32 startSeqCtrl:16;	//Start seqno of 1st MPDU, fragmentation not supported

	//DW1
	U32 totalLenMpdus:22;	//Total of (Mac hdr + sec hdr(if any) + payload(AMSDU) + 4B FCS) for each MPDU
	U32 rsvd2:10;

	//DW2-9           
	U32 seqNumBitmap[8];	//Bitmap is based on start seqno which is 1st MPDU in EU tx per tid, per user

	//DW10-41 (or 10-73 for 256 aggr)
	U8 numMsdu[TX_ACNT_MAX_NUM_AGGR];	//Total MSDUs in each MPDU, indexed by numMpdu
} SMAC_ACNT_TX_MPDU_TID_INFO_st;

typedef struct SMAC_ACNT_TX_HOST_USR_st {
	//DW0-10
	SMAC_ACNT_TX_HOST_HDR_st mpduHdr;

	//DW11-52
	SMAC_ACNT_TX_MPDU_TID_INFO_st mpduTid[TX_ACNT_MAX_NUM_TID];	//tid0 not always mapped to index0
} SMAC_ACNT_TX_HOST_USR_st;

typedef struct SMAC_ACNT_TX_HOST_PKT_st {
	//DW0
	U32 msduWrPtr;

	//DW1-53
	SMAC_ACNT_TX_HOST_USR_st user[TX_ACNT_USER_NUM];
} SMAC_ACNT_TX_HOST_PKT_st;

/*** Tx accounting SFW generated ***/
/*******************************/
typedef struct SMAC_ACNT_FW_PKT_INFO_st {
	U16 userId:4;		// 0 to 15
	U16 rsvd:12;
	U16 txPower;		// TBD format

	U32 txRate;		// TBD format

	U32 length;		// length of Pkt80211 upto 2048
	U8 Pkt80211[TX_ACNT_MAX_BODY_LEN];	// 802.11 header+Payload
} SMAC_ACNT_FW_PKT_INFO_st;

typedef struct SMAC_ACNT_TX_FW_PKT_USR_st {
	SMAC_ACNT_FW_PKT_INFO_st mpduInfo;

} SMAC_ACNT_TX_FW_PKT_USR_st;

typedef struct SMAC_ACNT_TX_FW_PKT_st {
	SMAC_ACNT_TX_FW_PKT_USR_st user[TX_ACNT_USER_NUM];
} SMAC_ACNT_TX_FW_PKT_st;

/****** Tx accounting tx done ******/
/*******************************/
typedef struct SMAC_ACNT_TX_DONE_USER_HDR_st {
	U8 userId:4;		// 0 to 15
	U8 numTids:4;		// number of TID in this PPDU: 1 to 8 -> T
	U8 type;		// 0 = ACK : no baTid info
	// 1 = BA
	// 2 = TIMEOUT : no baTid info

	U8 rsvd[2];
} SMAC_ACNT_TX_DONE_USER_HDR_st;

typedef struct SMAC_ACNT_MPDU_BA_INFO_st {
	//DW0
	U16 tid:4;		// 0 to 7, 0xF: non-QoS
	U16 startSeqNum:12;
	U16 numExpired;		//Total timeout pkt starting from startSeqNum (only updated in txdone timeout)

	//DW1-8
	U8 baBitmap[32];
} SMAC_ACNT_MPDU_BA_INFO_st;

typedef struct SMAC_ACNT_TX_DONE_USR_st {
	SMAC_ACNT_TX_DONE_USER_HDR_st userHdr;

	SMAC_ACNT_MPDU_BA_INFO_st baTid[TX_ACNT_MAX_NUM_TID];	//tid0 not always mapped to index0
} SMAC_ACNT_TX_DONE_USR_st;

typedef struct SMAC_ACNT_TX_DONE_st {
	//DW0-1
	SMAC_ACNT_TX_PPDU_HDR_st hdr;

	SMAC_ACNT_TX_DONE_USR_st user[TX_ACNT_USER_NUM];
} SMAC_ACNT_TX_DONE_st;

/******* Tx accounting PPDU *******/
/*******************************/
typedef struct SMAC_ACNT_TX_PPDU_INFO_st {
	//DW0-1
	SMAC_ACNT_TX_PPDU_HDR_st hdr;

	union {
		SMAC_ACNT_TX_HOST_PKT_st hostPkt;
		SMAC_ACNT_TX_FW_PKT_st fwPkt;
	} u;
} SMAC_ACNT_TX_PPDU_INFO_st;

/******* TX ACNT DONE BUF *******/
/*******************************/
typedef struct SMAC_ACNT_TX_DONE_BUF_st {
	U8 active:4;		// 1: currently waiting for ack/ba/timeout
	U8 flush:4;		//set 1 to flush to host
	U8 numUsers;
	U8 totalTidCnt;
	U8 rsvd;

	SMAC_ACNT_TX_DONE_st txDone;
} SMAC_ACNT_TX_DONE_BUF_st;

/********* TX ACNT BUF **********/
/*******************************/
typedef struct SMAC_ACNT_TX_BUF_st {
	U32 totalCnt[4];	//per CPU, host & txDone type: total tid, sfw type: total usr
	U32 totalLen[4];	//per CPU, sfw type: tota space needed for mpduInfo
	SMAC_ACNT_TX_PPDU_INFO_st ppduInfo;
} SMAC_ACNT_TX_BUF_st;

/******TX ACNT SIZE MACROS*****/
/*******************************/
//tx acnt common
#define SMAC_ACNT_TX_PPDU_HDR_SIZE      (sizeof(SMAC_ACNT_TX_PPDU_HDR_st))

//tx acnt sfw generated
#define SMAC_ACNT_TX_SFW_NONBODY_SIZE   ((sizeof(SMAC_ACNT_FW_PKT_INFO_st)-TX_ACNT_MAX_BODY_LEN))

//tx acnt host generated
#define SMAC_ACNT_TX_HOST_HDR_SIZE      (sizeof(SMAC_ACNT_TX_HOST_HDR_st))
#define SMAC_ACNT_MPDU_TID_INFO_SIZE    (sizeof(SMAC_ACNT_TX_MPDU_TID_INFO_st))

//tx acnt done
#define SMAC_ACNT_TXDONE_USR_HDR_SIZE   (sizeof(SMAC_ACNT_TX_DONE_USER_HDR_st))
#define SMAC_ACNT_TXDONE_BA_SIZE        (sizeof(SMAC_ACNT_MPDU_BA_INFO_st))

/******** Rx acnt common ********/
/*******************************/
typedef struct SMAC_ACNT_RX_PPDU_HDR_st {
	//DW0
	U8 version:4;		// 0
	U8 mpduType:4;		// 0: Mgmt, 1: Ctrl, 2: Data
	U8 numUsers;		// 1 to 16
	U16 rxInfoIndex;	//Rx_Info index

	//DW1
	U32 timestamp;		// low 32-bit TSF
} SMAC_ACNT_RX_PPDU_HDR_st;

/****** Rx acnt management*******/
/*******************************/
typedef struct SMAC_ACNT_RX_MGMT_MPDU_st {
	U32 mpduHdr[15];	// 60B: mpduHdr[0] bit 15:0 = MPDU length, 80211Hdr starts from [1]

	U32 userId:4;		// user ID
	U32 euStatus:1;		// MPDU's EU error indication (0: OK, 1: ERR)
	U32 fcsStatus:1;	// MPDU's FCS error indication (0: OK, 1: ERR)
	U32 rsvd:26;

	U32 rxBufPointer;	// NULL(0) if packet drop in SMAC
} SMAC_ACNT_RX_MGMT_MPDU_st;

/******** Rx acnt control**********/
/*******************************/
typedef struct SMAC_ACNT_RX_CTRL_MPDU_st {
	U32 mpduHdr[15];	// 60B: mpduHdr[0] bit 15:0 = MPDU length, 80211Hdr starts from [1]

	U32 userId:4;		// user ID
	U32 euStatus:1;		// MPDU's EU error indication (0: OK, 1: ERR)
	U32 fcsStatus:1;	// MPDU's FCS error indication (0: OK, 1: ERR)
	U32 rsvd:26;
} SMAC_ACNT_RX_CTRL_MPDU_st;

/********** Rx acnt data**********/
/*******************************/
typedef struct SMAC_ACNT_RX_MPDU_TID_INFO_st {
	U32 tid:4;		// 0 to 7, 0xF: non-QoS
	U32 rsvd:4;
	U32 numMpdu:8;		// 1-255,0=256: number of MPDU in this TID
	U32 startSeqControl:16;	// 12+4 (SeqNum+FragNum) 

	U32 totalLenMpdus:22;	// max 11k * 256 = 2816000 (0x2AF800)
	U32 numSeqNumOutWin:9;	// 0 to 256: number of SEQ_NUM dropped for out-of-window
	U32 drop:1;		// dropped in SFW

	U8 seqNumBitmap[RX_ACNT_BMAP_SIZE];
	U8 numMsdu[RX_ACNT_MAX_NUM_AGGR];	// number of MSDU in this MPDU, in RX order
} SMAC_ACNT_RX_MPDU_TID_INFO_st;

typedef struct SMAC_ACNT_RX_DATA_MPDU_st {
	U32 mpduHdr[15];	// 60B: mpduHdr[0] bit 15:0 = MPDU length, 80211Hdr starts from mpduHdr[1] onwards

	U8 userId:4;		// user ID
	U8 numTids:4;		// number of TIDs in this PPDU (0 = 16)
	U8 rsvd[3];

	U8 euBitmap[RX_ACNT_BMAP_SIZE];	// 256-bit for each MPDU's EU error indication (0: OK, 1: ERR)
	U8 fcsBitmap[RX_ACNT_BMAP_SIZE];	// 256-bit for each MPDU's FCS error indication (0: OK, 1: ERR)

	SMAC_ACNT_RX_MPDU_TID_INFO_st mpduTid[RX_ACNT_MAX_NUM_TID];	//tid0 not always mapped to index0
} SMAC_ACNT_RX_DATA_MPDU_st;

/******* Rx accounting PPDU *******/
/*******************************/
typedef struct SMAC_ACNT_RX_PPDU_USER_st {
	union {
		SMAC_ACNT_RX_MGMT_MPDU_st mgmt;
		SMAC_ACNT_RX_CTRL_MPDU_st ctrl;
		SMAC_ACNT_RX_DATA_MPDU_st data;
	} u;
} SMAC_ACNT_RX_PPDU_USER_st;

/******* Rx accounting PPDU *******/
/*******************************/
typedef struct SMAC_ACNT_RX_PPDU_INFO_st {
	SMAC_ACNT_RX_PPDU_HDR_st ppduHdr;
	SMAC_ACNT_RX_PPDU_USER_st user[RX_ACNT_USER_NUM];	//user0 not always mapped to index0
} SMAC_ACNT_RX_PPDU_INFO_st;

/********* RX ACNT BUF **********/
/*******************************/
typedef struct SMAC_ACNT_RX_BUF_st {
	U32 totalCnt[2];	//per SOP or EOP cpu. data type: total tid

	SMAC_ACNT_RX_PPDU_INFO_st ppduInfo;
} SMAC_ACNT_RX_BUF_st;

/******RX ACNT SIZE MACROS*****/
/*******************************/
//rx acnt common
#define SMAC_ACNT_RX_PPDU_HDR_SIZE      (sizeof(SMAC_ACNT_RX_PPDU_HDR_st))

//rx acnt host generated
#define SMAC_ACNT_RX_MPDU_TID_SIZE      (sizeof(SMAC_ACNT_RX_MPDU_TID_INFO_st))
#define SMAC_ACNT_RX_DATA_HDR_SIZE      ((sizeof(SMAC_ACNT_RX_DATA_MPDU_st)-(RX_ACNT_MAX_NUM_TID*SMAC_ACNT_RX_MPDU_TID_SIZE)))

#define SMAC_ACNT_RX_MGMT_SIZE          (sizeof(SMAC_ACNT_RX_MGMT_MPDU_st))
#define SMAC_ACNT_RX_CTRL_SIZE          (sizeof(SMAC_ACNT_RX_CTRL_MPDU_st))
#define SMAC_ACNT_RX_DATA_SIZE          (sizeof(SMAC_ACNT_RX_DATA_MPDU_st))

#endif				//_SMAC_HAL_IF_H_
