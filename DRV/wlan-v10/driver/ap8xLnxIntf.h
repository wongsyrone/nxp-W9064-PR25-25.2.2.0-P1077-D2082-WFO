/** @file ap8xLnxIntf.h
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
#ifndef AP8X_INTF_H_
#define AP8X_INTF_H_

#include <linux/version.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/dma-mapping.h>
#include <linux/pci.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/delay.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/init.h>
#include <linux/net.h>
#include <linux/wireless.h>
#include <linux/kmsg_dump.h>
#include <net/iw_handler.h>
#include "IEEE_types.h"
#include "wltypes.h"
#include "ap8xLnxDesc.h"
#include "ap8xLnxBQM.h"
#include "ap8xLnxUtil.h"
#include "ap8xLnxApi.h"
#include "ap8xLnxAR.h"
#include "ap8xLnxRxInfo.h"
#include "wl_mib.h"
#include "wl_hal.h"
#include "dfs.h"
#include "buildModes.h"
#include "ap8xLnxIoctl.h"
#include "idList.h"
#define __dsb
#include <linux/spinlock.h>
#include <asm/atomic.h>
#include <linux/interrupt.h>
#include <linux/smp.h>
#ifdef TP_PROFILE
#include "wlprofile.h"
#endif
#ifdef CFG80211
#include <net/cfg80211.h>
#endif
#include "ap8xLnxMonitor.h"

#ifdef CB_SUPPORT
#include "ap8xLnxCB.h"
#endif // #ifdef CB_SUPPORT
#if defined(MRVL_MUG_ENABLE)
#include "mug_types.h"
#endif /* #if defined(MRVL_MUG_ENABLE) */

#ifdef WIFI_DATA_OFFLOAD
#include "ipc.h"
#include "dol.h"
#endif

#if (defined WLS_FTM_SUPPORT) || (defined AOA_PROC_SUPPORT)
typedef struct WLS_FTM_CONFIG_st WLS_FTM_CONFIG_st;
typedef struct CSI_CONFIG_st CSI_CONFIG_st;
#endif

#define NUMOFCLIENTS 1
#define MAX_CARDS_SUPPORT 3
#define MAX_VMAC_INSTANCE_AP NUMOFAPS
#ifdef ENABLE_MONIF
#define NUM_OF_MONIF 1
#else
#define NUM_OF_MONIF 0
#endif

#define SME_CMD_BUF_Q_LIMIT 8

// Max number of repeating count to reset the bus
#define MAX_BUS_RESET 5

#define PCI_INTR_TYPE_DEFAULT 0
#define PCI_INTR_TYPE_MSI 1
#define INTR_TYPE_MSIX 2

#define MAX_VMAC_MIB_INSTANCE (NUMOFAPS + NUMOFCLIENTS + NUM_OF_MONIF) // Pete, add 1 for monitor if.
#define MONIF_INDEX (bss_num + NUMOFCLIENTS + NUM_OF_MONIF - 1)

#define NETDEV_PRIV(pre, dev) ((pre *)netdev_priv(dev))
#define NETDEV_PRIV_P(pre, dev) ((pre *)dev->ml_priv)
#define NETDEV_PRIV_S(dev) (dev->ml_priv)
#define GET_PARENT_PRIV(wlpptr) (wlpptr->wlpd_p->masterwlp)
/**
 * \def ARRAY_ELEMENTS(array)
 * Macro to get the number of elements of an array
 */
#define ARRAY_ELEMENTS(array) (sizeof(array) / sizeof((array)[0]))

#ifdef TP_PROFILE
#define RX_TP_START 11
#define IS_TX_TP(x) ((x > 0) && (x < RX_TP_START))
#endif

extern void WlSendDeauth(struct net_device *netdev);
extern void WlStopBeaconing(struct net_device *netdev);
extern void wlReadyStart160MhzBcn(DfsApDesc *dfsDesc_p);
extern void SimulateRadarDetect(struct net_device *);
extern int wlInit(struct net_device *, u_int16_t);
extern int wlDeinit(struct net_device *);
extern irqreturn_t wlSC5MSIX_r7(int irq, void *dev_id);
extern irqreturn_t wlSC5MSIX_tx(int irq, void *dev_id);
extern irqreturn_t wlSC5MSIX_rx(int irq, void *dev_id);
extern irqreturn_t wlSC5MSIX_rel(int irq, void *dev_id);
#if defined(ACNT_REC) && defined(SOC_W906X)
extern irqreturn_t wlSC5MSIX_RxInfo(int irq, void *dev_id);
extern irqreturn_t wlSC5MSIX_RAcntRec(int irq, void *dev_id);
#endif // defined(ACNT_REC) && defined (SOC_W906X)

extern irqreturn_t wlISR(int irq, void *dev_id);
extern void wlInterruptEnable(struct net_device *);
extern void wlInterruptDisable(struct net_device *);
extern void wlFwReset(struct net_device *);
extern int wlChkAdapter(struct net_device *);
extern void wlSendEvent(struct net_device *dev, int, IEEEtypes_MacAddr_t *,
						const char *);
extern void calculate_err_count(struct net_device *netdev);

#ifdef ENABLE_WLSNDEVT
#define WLSNDEVT(dev, cmd, Addr, info) wlSendEvent(dev, cmd, Addr, info)
#else
#define WLSNDEVT(dev, cmd, Addr, info)
#endif
#ifdef WDS_FEATURE
int wlstop_wds(struct net_device *netdev);
#endif
#ifdef MCAST_PS_OFFLOAD_SUPPORT
#define NUM_OF_DESCRIPTOR_DATA (4 + NUMOFAPS)
#define NUM_OF_DESCRIPTOR_DATA_QOS_CTRL 4
#else
#define NUM_OF_DESCRIPTOR_DATA 4
#endif
#define NUM_OF_TCP_ACK_Q 12

#define NUM_OF_TX_QUEUE 2
#define NUM_OF_RX_QUEUE 8
#define RX_QUEUE_START_ID 0
#define TX_QUEUE_START_ID 8
#define MAX_NUM_AGGR_BUFF 256
#ifdef NEW_DP
#define MAX_NUM_RX_DESC (1024 * 16)
#else
#define MAX_NUM_RX_DESC 256
#endif
/*3839 ~ 4k*/
#ifdef SSU_SUPPORT
#ifdef SOC_W906X
#define MAX_AGGR_SIZE 2048
#else
#define MAX_AGGR_SIZE 2700
#endif
#else
#define MAX_AGGR_SIZE 2700
#endif

#ifdef AIRTIME_FAIRNESS
#define MAX_NUM_TX_DESC 4096 // For ADP we need to have this number bigger
#else
#define MAX_NUM_TX_DESC 2048 // For ADP we need to have this number bigger
#endif

#define MIN_BYTES_HEADROOM 64 + 2
#define NUM_EXTRA_RX_BYTES (2 * MIN_BYTES_HEADROOM)

#define ENDIAN_SWAP32(_val) (cpu_to_le32(_val))
#define ENDIAN_SWAP16(_val) (cpu_to_le16(_val))

#define SC3 0x2A55
#define SC4 0x2B40
#define SC4P 0x2B41
#define SC5 0x2B50
#define SCBT 0x2B55
#define ACNT_BA_SIZE 1000
#ifdef SOC_W906X
#define DEFAULT_SIZE_CHUNK 0x800
#else
#define DEFAULT_SIZE_CHUNK 0x4000
#endif

#define SET_MODULE_OWNER(x)
#define CMD_BUF_SIZE 0x4000
#ifdef SSU_SUPPORT
/* SSU buffer size 32MB - currently larger than needed ~17MB for max 700*25000 100ms */
#define SSU_BUF_SIZE 0x200000
#endif
#ifdef DSP_COMMAND
#define DSP_CMD_BUF_SIZE 0x10000
#define DSP_DATA_BUF_SIZE 0x80000
#define DSP_BUF_SIZE (DSP_CMD_BUF_SIZE + DSP_DATA_BUF_SIZE)
#endif

#define MAX_ISR_ITERATION 1 // 10

// #define BARBADO_RESET

#ifdef BARBADO_RESET
#define WDEV0_RESET_PIN 16
#define WDEV1_RESET_PIN 24
#else
#define WDEV0_RESET_PIN 55
#define WDEV1_RESET_PIN 24
#endif

#ifdef FS_CAL_FILE_SUPPORT
#define EEPROM_ON_FILE_MAX_SIZE CAL_DATA_CONF_FILE_SIZE
#define STA_EE_SIGNATURE 0x38333058
#endif
struct wldesc_data
{
#ifdef SOC_W906X
	u_int8_t id;
	wl_qpair_rq_t rq;
	wl_qpair_sq_t sq;
#else
	dma_addr_t pPhysTxRing;	  /* ptr to first TX desc (phys.)    */
	wltxdesc_t *pTxRing;	  /* ptr to first TX desc (virt.)    */
	wltxdesc_t *pNextTxDesc;  /* next TX desc that can be used   */
	wltxdesc_t *pStaleTxDesc; /* the staled TX descriptor        */
	dma_addr_t pPhysRxRing;	  /* ptr to first RX desc (phys.)    */
	wlrxdesc_t *pRxRing;	  /* ptr to first RX desc (virt.)    */
	wlrxdesc_t *pNextRxDesc;  /* next RX desc that can be used   */
	unsigned int wcbBase;	  /* FW base offset for registers    */
	unsigned int rxDescWrite; /* FW descriptor write position    */
	unsigned int rxDescRead;  /* FW descriptor read position     */
	unsigned int rxBufSize;	  /* length of the RX buffers        */
#endif
#ifdef NEW_DP
	struct sk_buff *Rx_vBufList[MAX_NUM_RX_DESC];
#ifdef SOC_W906X
	struct sk_buff *Tx_vBufList[MAX_NUM_TX_DESC];
#else
	struct sk_buff *Tx_vBufList[MAX_TX_RING_SEND_SIZE * 8]; /* keept the skb owned by fw */
	u_int32_t TxSentTail;									/* index to the TX desc FW used    */
	u_int32_t TxSentHead;									/* index to next TX desc to be used    */
	u_int32_t TxDoneTail;									/* index to Tx Done queue tail    */
	u_int32_t Tx_vBufList_idx;								/* idx to empty slot in Tx_vBufList_idx */
	tx_ring_done_t *pTxRingDone;
	dma_addr_t pPhysTxRingDone; /* ptr to first TX done desc (phys.)     */
	u_int32_t TxRingDoneHead;	/* ptr to head of TX done desc (phys.)   */
	rx_ring_done_t *pRxRingDone;
	dma_addr_t pPhysRxRingDone; /* ptr to first RX done desc (phys.)      */
	u_int32_t RxRingDoneHead;	/* ptr to head of RX done desc (phys.)    */
	u_int32_t txDescBusyCnt;
#endif /* SOC_W906X */
#if defined(SOC_W906X) || defined(NEWDP_ACNT_CHUNKS)
	dma_addr_t pPhysAcntRing[ACNT_NCHUNK];
#else
	dma_addr_t pPhysAcntRing; /* ptr to first accounting record (phys.) */
#endif
	u_int8_t *pAcntRing; /* ptr to first accounting record         */
	u_int8_t *pAcntBuf;
	u_int32_t AcntRingSize;
	dma_addr_t pPhyInfoPwrTbl;
	u_int8_t *pInfoPwrTbl;
	dma_addr_t pPhysOffChReqRing;  /* ptr to first off channel req (phys.) */
	u_int8_t *pOffChReqRing;	   /* ptr to first off channel req         */
	dma_addr_t pPhysOffChDoneRing; /* ptr to first off channel req (phys.) */
	u_int8_t *pOffChDoneRing;	   /* ptr to first off channel req         */
	u_int32_t OffChanReqHead;
	u_int32_t OffChanReqTail;
	u_int32_t OffChanDoneHead;
	u_int32_t OffChanDoneTail;
	u_int8_t *poffchanshared;
	dma_addr_t pPhyoffchanshared;
#endif
};

struct wllocks
{
	DECLARE_LOCK(xmitLock); /* used to protect TX actions      */
	DECLARE_LOCK(fwLock);	/* used to protect FW commands     */
#ifdef SOC_W906X
	DECLARE_LOCK(offChanListLock); /* used to protect off chan req list       */
#endif
	DECLARE_LOCK(ReqidListLock); /* used to protect off chan reqid list     */
	DECLARE_LOCK(intLock);		 /* used to protect INT actions      */
	DECLARE_LOCK(HMLock);		 /* used to protect health monitor logging    */
#ifdef SYSFS_STADB_INFO
	DECLARE_LOCK(sysfsHdlListLock); /* used to protect off sysfs STA list   */
#endif								/* SYSFS_STADB_INFO */
#ifdef BAND_STEERING
	DECLARE_LOCK(bandSteerListLock); /* used to protect off band steering SKB list */
#endif								 /* BAND_STEERING */
#ifdef WIFI_DATA_OFFLOAD
	DECLARE_LOCK(delayCmdLock);
#endif /* WIFI_DATA_OFFLOAD */
};

/*
#define SC5_REVISION_Z1	1
#define SC5_REVISION_Z2	2
*/
#define REV_Z1 0
#define REV_Z2 1
#define REV_A0 2

struct wlhw_data
{
	u_int32_t fwReleaseNumber; /* MajNbr:MinNbr:SubMin:PatchLevel */
#ifdef SOC_W906X
	u_int32_t sfwReleaseNumber;
	u_int32_t smacReleaseNumber;
#endif								 /* SOC_W906X */
	u_int8_t hwVersion;				 /* plain number indicating version */
	u_int8_t hostInterface;			 /* plain number of interface       */
	u_int16_t maxNumTXdesc;			 /* max number of TX descriptors    */
	u_int16_t maxNumMCaddr;			 /* max number multicast addresses  */
	u_int16_t numAntennas;			 /* number antennas used            */
	u_int16_t regionCode;			 /* region (eg. 0x10 for USA FCC)   */
	unsigned char macAddr[ETH_ALEN]; /* well known -> AA:BB:CC:DD:EE:FF */
#ifdef SOC_W906X
	u_int16_t ulShalVersion; /* MajNbr:MinNbr */
	u_int8_t chipRevision;
#endif /* SOC_W906X */
};

struct wlpriv_stats
{
	u_int32_t skbheaderroomfailure;
	u_int32_t tsoframecount;
	u_int32_t weakiv_count;
	u_int32_t weakiv_threshold_count;
	u_int32_t tx_tcp_ack_drop_count;
};

struct wlpriv_net_device_stats
{
	unsigned long tx_mcast_bytes;
	unsigned long tx_bcast_bytes;
	unsigned long rx_mcast_bytes;
	unsigned long rx_bcast_bytes;
};

#ifdef AMPDU_SUPPORT_SBA
#ifndef NEW_DP
#define MAX_SUPPORT_AMPDU_TX_STREAM 4
#else
#ifdef SOC_W906X
#define MAX_SUPPORT_AMPDU_TX_STREAM (MAX_STNS * MAX_TID)
#define MAX_SUPPORT_AMPDU_TX_STREAM_RUNNING (sta_num * MAX_TID)
#else
#define MAX_SUPPORT_AMPDU_TX_STREAM (300 * 8) /** 300 STA and 8 tid **/
#endif										  /* SOC_W906X */
#endif
#else
#define MAX_SUPPORT_AMPDU_TX_STREAM 2
#endif

#define BA_MAX_SEQ_NUM 0xFFF

#ifdef SOC_W906X
#define MAX_BA_REORDER_BUF_SIZE (64 * 2)
#else
#define MAX_BA_REORDER_BUF_SIZE (64)
#endif

#define MAX_AMPDU_REORDER_BUFFER MAX_AID
#define MAX_AC 4
#define MAX_UP 8
#define MAX_AC_SEQNO 4096

/* WME stream classes */
#define WME_AC_BE 0 /* best effort */
#define WME_AC_BK 1 /* background */
#define WME_AC_VI 2 /* video */
#define WME_AC_VO 3 /* voice */

typedef struct
{
	vmacApInfo_t *vmacSta_p;
	UINT8 MacAddr[6];
	UINT8 AccessCat;
	UINT8 InUse;
	UINT8 DialogToken;
	Timer timer;
	UINT8 initTimer;
	UINT8 AddBaResponseReceive;
	unsigned long TimeOut; /* should be same size as jiffies of the system */
	UINT16 start_seqno;
#ifdef DYNAMIC_BA_SUPPORT
	UINT32 txa_avgpps;
	UINT32 txa_ac;
	UINT32 txa_pkts;
	unsigned long txa_lastsample; /* should be same size as jiffies of the system */
#endif
	unsigned long ReleaseTimestamp; /* should be same size as jiffies of the system */
} Ampdu_tx_t;

#define TID_TO_WME_AC(_tid) (                                           \
	((_tid) == 0 || (_tid) == 3) ? WME_AC_BE : ((_tid) < 3) ? WME_AC_BK \
										   : ((_tid) < 6)	? WME_AC_VI \
															: WME_AC_VO)

#define MAX_REORDERING_HOLD_TIME (200 * TIMER_1MS) //(HZ / 2) //200ms

// #define DEBUG_BAREORDER                       //remove comment to debug out of range BA reorder

#ifdef DEBUG_BAREORDER

// always (power of 2) minus 1
#define DBG_BAREORDER_SN_MASK 0x7F
#define DBG_BAREORDER_LOG_MASK 0x3FF

#define DBG_BAREORDER_TMO_EN_BIT (0x1U << 0)
#define DBG_BAREORDER_SN_EN_BIT (0x1U << 1)
#define DBG_BAREORDER_OOR_EN_BIT (0x1U << 2)
#define DBG_BAREORDER_OOR_RPT_EN_BIT (0x1U << 3)
#define DBG_BAREORDER_STORE_EN_BIT (0x1U << 4)
#define DBG_BAREORDER_WEND_EN_BIT (0x1U << 5)
#define DBG_BAREORDER_BAR_EN_BIT (0x1U << 6)

#define DBG_BAREORDER_MASK (DBG_BAREORDER_TMO_EN_BIT | DBG_BAREORDER_SN_EN_BIT | DBG_BAREORDER_OOR_EN_BIT |         \
							DBG_BAREORDER_OOR_RPT_EN_BIT | DBG_BAREORDER_STORE_EN_BIT | DBG_BAREORDER_WEND_EN_BIT | \
							DBG_BAREORDER_BAR_EN_BIT)

// max 8 locations for logging.
// bit31-28: (index minus 1) to dbg_BAredr_hist_log[ ]
// bit7-0: log enable mask to check againts dbg_BAredr_log_en_mask
#define DBG_BAREORDER_TAG_TMO (0x11111100 | DBG_BAREORDER_TMO_EN_BIT)
#define DBG_BAREORDER_TAG_SN (0x22222200 | DBG_BAREORDER_SN_EN_BIT)
#define DBG_BAREORDER_TAG_OOR (0x33333300 | DBG_BAREORDER_OOR_EN_BIT)
#define DBG_BAREORDER_TAG_OOR_RPT (0x44444400 | DBG_BAREORDER_OOR_RPT_EN_BIT)
#define DBG_BAREORDER_TAG_STORE (0x55555500 | DBG_BAREORDER_STORE_EN_BIT)
#define DBG_BAREORDER_TAG_WEND (0x66666600 | DBG_BAREORDER_WEND_EN_BIT)
#define DBG_BAREORDER_TAG_BAR (0x77777700 | DBG_BAREORDER_BAR_EN_BIT)

extern UINT32 dbg_BAredr_id;
extern UINT32 dbg_BAredr_cardindex;

extern UINT32 dbg_BAredr_SN[DBG_BAREORDER_SN_MASK + 1];
extern UINT32 dbg_BAredr_SN_cnt;

extern UINT32 dbg_BAredr_log[DBG_BAREORDER_LOG_MASK + 1];
extern UINT32 dbg_BAredr_log_cnt;

extern UINT32 dbg_BAredr_OOR_cont;

#define DEBUG_REORDER_PRINT(x) printk x

extern UINT32 dbg_BAredr_tag[7];
extern UINT8 dbg_BAredr_log_en_mask;
extern UINT8 dbg_BAredr_hist_log[7];

#define DBG_BAREORDER_SN(id, t, l, b, s)                                                                        \
	{                                                                                                           \
		if (((dbg_BAredr_cardindex << 16) | dbg_BAredr_id) == id)                                               \
		{                                                                                                       \
			dbg_BAredr_SN[dbg_BAredr_SN_cnt++ & DBG_BAREORDER_SN_MASK] = (t << 28) | (l << 24) | (b << 12) | s; \
			dbg_BAredr_SN[dbg_BAredr_SN_cnt & DBG_BAREORDER_SN_MASK] = 0xdeaddead;                              \
		}                                                                                                       \
	}

#else
#define DEBUG_REORDER_PRINT(x)
#define DBG_BAREORDER_SN(id, t, l, b, s)

#endif
#define REORDER_2B_REMOVED 0 // Search for this tag for rx reorder code to be removed

typedef struct AmsduQ_st
{
	UINT16 state; // 0: Empty, expecting 1st amsdu, 1: 1st amsdu received, expect mid or last, 2: last amsdu received, expect no more
	UINT16 seqNo;
	struct sk_buff_head skbHead; // all msdu in same amsdu list, share same seqno
} AmsduQ_st;

typedef struct BA_RX_st
{
	UINT16 storedBufCnt; // number of amsdu added to buffer. E.g an amsdu with 3 msdu in counterd as 1
	UINT16 leastSeqNo;	 // least seq no of pkt in buffer
	UINT16 winStartB;	 // expected incoming seqno
	UINT16 winSizeB;	 // size of buffer

	UINT8 overWExtNotFound; // 0: there is a SN>wExt event in current PPDU, 1: no SN>wExt evt.
	UINT8 overWExtCnt;		// count consecutive SN>wExt event of PPDU. After > threshold, jump wStart to follow up. Eg.PPDU SN 200,201,3000,3001 (considered 1 SN>wExt evt)
	UINT8 rsvd[2];

	AmsduQ_st AmsduQ[MAX_BA_REORDER_BUF_SIZE];
#ifdef RX_REPLAY_DETECTION
	UINT8 pn_check_enabled;
#endif
	unsigned long minTime; // oldest time of pkt stays in buffer, in jiffies
	DECLARE_LOCK(BAreodrLock);
	struct tasklet_struct BArodertask;
} BA_RX_st;

typedef struct
{
#ifdef SOC_W8964 // REORDER_2B_REMOVED
	struct sk_buff *pFrame[MAX_UP][MAX_AMPDU_REORDER_BUFFER];
	UINT16 ExpectedSeqNo[MAX_UP][MAX_AMPDU_REORDER_BUFFER];
	UINT16 CurrentSeqNo[MAX_UP];
	UINT16 ReOrdering[MAX_UP];
#endif /* SOC_W8964 */
	UINT8 AddBaReceive[MAX_UP];
#ifdef SOC_W8964				// REORDER_2B_REMOVED
	unsigned long Time[MAX_UP]; /* should be same size as jiffies of the system */
#endif							/* SOC_W8964 */
	Timer timer[MAX_UP];
	UINT8 timer_init[MAX_UP];
	BA_RX_st ba[MAX_UP];
} Ampdu_Pck_Reorder_t;

typedef struct
{
	IEEEtypes_MacAddr_t Addr; // mac address of STA who sent the msdu
	UINT32 StnId;			  // station id
	UINT32 winStartB;		  // BA reoder window starting seq number
	UINT32 SeqNo;			  // Seq number in current mpdu
	UINT32 lo_dword_addr;	  // L0 buffer address
} BaR_Debug_t;

#ifdef NEW_DP
typedef struct
{
	UINT32 fastDataCnt;
	UINT32 fastBadAmsduCnt;
	UINT32 slowNoqueueCnt;
	UINT32 slowNoRunCnt;
	UINT32 slowMcastCnt;
	UINT32 slowBadStaCnt;
	UINT32 slowBadMicCnt;
	UINT32 slowBadPNCnt;
	UINT32 slowMgmtCnt;
	UINT32 slowPromiscCnt;
	UINT32 dropCnt;
	UINT32 offchPromiscCnt;
	UINT32 mu_pktcnt;
} NewdpRxCounter_t;
#endif
typedef struct _mmap_info
{
	char *data; /* the data */
	dma_addr_t dataPhysicalLoc;
	struct dentry *file;
	int reference; /* how many times it is mmapped */
} mmap_info, *Pmmap_info;

typedef struct _mmap_info_acnt_chunk
{
	char *data; /* the data */
	dma_addr_t dataPhysicalLoc[ACNT_NCHUNK];
	struct dentry *file;
	int reference; /* how many times it is mmapped */
} mmap_info_acnt_chunk, *Pmmap_info_acnt_chunk;

typedef struct _post_req_sig_info_s
{
	int pid;
	struct dentry *file;
} post_req_sig_info_t, *Ppost_req_sig_info_t;

typedef struct mrvl_pri_shared_mem_s
{
	UINT8 *data; /* to use for struc drv_fw_shared_t */
	dma_addr_t dataPhysicalLoc;
} mrvl_pri_shared_mem_t;

typedef struct RetryCfgVAP_s
{

	UINT8 RetryLegacy[4];
	UINT8 Retry11n[4];
	UINT8 Retry11ac[4];

} PACK RetryCfgVAP_t;

//
// The follwoing for Cisco power table
//
typedef struct PerChanPwr_s
{
	BOOLEAN bValid;
	UINT8 channel;
	rate_power_table_t PerChanPwr;
} PACK PerChanPwr_t;

typedef struct txq_ac_stats_t
{
	U32 drop_dfs;
	U32 drop_qfl;
	U32 drop_iff;
	U32 drop_skb;
	U32 drop_cfh;
	U32 tx;
} txq_ac_stats_t;

#define AGGRCNT_ARYSIZE 8
struct drv_stats
{
	// rx statistics
	UINT32 rxq_intr_cnt[SC5_RXQ_NUM];
	UINT32 rxq_rcv_cnt[SC5_RXQ_NUM];

	UINT32 rxq_aggrcnt[SC5_BMQ_NUM - 1][AGGRCNT_ARYSIZE]; // =aggrcnt-2
	UINT32 rxq_midaggr[SC5_BMQ_NUM - 1];
	UINT32 rx_data_ucast_pn_pass_cnt;
	UINT32 rx_data_mcast_pn_pass_cnt;
	UINT32 rx_mgmt_ucast_pn_pass_cnt;
	UINT32 rx_mgmt_mcast_pn_pass_cnt;

	// tx statistics
	UINT32 txq_full_cnt;
	UINT32 txq_drv_sent_cnt;

	UINT32 txbuf_rel_cnt;

	// Message counter => If the difference > threshold => dump message automatically
	SINT32 txpend_lastcnt;				 // Last tx-pending count
	SINT32 trcq_lastcnt[SC5_BMQ_NUM];	 // Last Trace count
	SINT32 enq_bmq_lastcnt[SC5_BMQ_NUM]; // Last BM enqueue count

	// buffer statistics
	SINT32 enq_bmqbuf_cnt[SC5_BMQ_NUM];		   // Enqueued BMQ buffer count
	UINT32 bmqbuf_alloc_fail_cnt[SC5_BMQ_NUM]; // Fail count to allocate BMQ buffer
	UINT32 rx_drop_cnt[SC5_BMQ_NUM];

	UINT32 bmqbuf_ret_cnt[SC5_BMQ_NUM];	  // Buffer returned from BMQ(Q10~13)
	UINT32 xx_buf_free_SQ14[SC5_BMQ_NUM]; // Buffer returned from Q14

	UINT32 amsdu_frag[4]; // cnt for  fpkt, middle-pkt, lpkt, single-msdu,
#ifdef TP_PROFILE
	TP_STATS cfhdltx_stat;
#endif
	UINT32 bmq13_refill_cnt;
	UINT32 txq_drv_release_cnt[4];
	UINT32 rxinfo_stadb_query_cnt;
	struct txq_ac_stats_t txq_ac_stats[4]; // {BK, BE, VI, VO}
};

// Debug counters
struct except_cnt
{
	u32 cnt_cfhul_invalid_signature;
	u32 cnt_tx_misalign;
	u32 cnt_z1_frag_buffer;
	u32 cnt_cfhul_error;
	u32 cnt_cfhul_snap_error;
	u32 cnt_cfhul_oversize;
	u32 cnt_invalid_amsdu_subframe_len;
	u32 cnt_invalid_mpdu_frames;
	u32 cnt_amsdu_subframes;
	u32 cnt_skbtrace_reset;
	u32 cnt_mic_err;
	u32 cnt_icv_err;
	u32 cnt_defrag_drop;
	u32 cnt_defrag_drop_x[8];
	// Error counter
	UINT32 rx_invalid_sig_cnt[SC5_BMQ_NUM]; // Invalid Signature counter
	UINT32 dup_txdone_cnt;					// How many returned tx-pkts which has been returned before
	UINT32 sml_hdroom_cnt;					// How many tx pkts whose headroom are insufficient
	UINT32 sml_rx_hdroom_cnt;				// Chk how many small headroom => It should be 0
	UINT32 rxbuf_mis_align_cnt;				// How many mis-aligned rx-buffer
	UINT32 pe_invlid_bpid;
	UINT32 skb_invalid_signature_cnt;
	UINT32 skb_notlinked_cnt;
	UINT32 skb_overpanic_cnt;
	UINT32 skb_nonlinear_cnt;
	UINT32 skb_invalid_addr_cnt;

	UINT32 cfhul_bpid_err;		 // Incorrect bpid of cfhul
	UINT32 cfhul_hdr_loaddr_err; // Incorrect lo address of cfhul
	UINT8 cfhul_flpkt_log[SC5_BMQ_NUM][2];
	UINT32 cfhul_flpkt_error[SC5_BMQ_NUM]; // Incorrect (fpkt,lpkt) seq

	UINT32 cfhul_hdrlen_err;		 // Incorrect hdr.length
	UINT32 cfhul_buf_map_err;		 // Incorrect buf mapping
	UINT32 tx_drop_over_max_pending; // tx drop due to pending Tx over MAX_NUM_PENDING_TX
	UINT32 tx_mgmt_send_cnt;
	UINT32 tx_mgmt_rel_cnt;
	UINT32 txq_send_cnt[SMAC_QID_NUM];
	UINT32 txq_rel_cnt[SMAC_QID_NUM];
	UINT32 txq_pend_cnt[SMAC_QID_NUM];
	UINT32 txq_drop_cnt[SMAC_QID_NUM];
	UINT32 txq_txd1_drop_cnt[SMAC_QID_NUM];
	UINT32 tx_sta_send_cnt[MAX_STNS + 1];
	UINT32 tx_sta_rel_cnt[MAX_STNS + 1];
	UINT32 tx_sta_pend_cnt[MAX_STNS + 1];
	UINT32 tx_sta_drop_cnt[MAX_STNS + 1];
	UINT32 tx_bcast_send_cnt;
	UINT32 tx_bcast_rel_cnt;
	UINT32 tx_bcast_pend_cnt;
	UINT32 tx_bcast_drop_cnt;
	UINT32 buf_desc_not_updated; /* bufer decriptor is not updated */
	UINT32 invalid_buf_addr;	 /* physical address is not correct in bufer decriptor */
	UINT32 cfhul_flpkt_lost[4];	 // 0: fpkt lost, 1: middle lost 2: lpkt lost, 3: subframes over limit
	UINT32 qidcnt[3];

	BOOLEAN in_pkt[SC5_BMQ_NUM];
	U8 lastpkt_status[SC5_BMQ_NUM];
	UINT32 msdu_err;
	UINT32 skb_hddat_err;				 // skb->head > skb->data
	UINT32 skip_feed_starv[SC5_BMQ_NUM]; // Skip feeding more buffers to starving queue
	UINT32 badPNcntUcast;
	UINT32 badPNcntMcast;
	UINT32 badPNcntMgmtcast;
	UINT32 qfull_empty[NUM_OF_HW_DESCRIPTOR_DATA][2];
	UINT32 diff_tm_patch;
	UINT32 free_err_pkts[3];
	UINT32 lpkt_miss[SC5_BMQ_NUM];
	UINT32 badAcntStnid;
	UINT32 rx_bypass_cnt;
	UINT32 rx_mic_err_cnt, rx_icv_err_cnt;
	UINT32 deauth_war_cnt;
	UINT32 disasso_war_cnt;
	UINT32 asso_war_cnt;
	UINT32 reasso_war_cnt;
	UINT32 auth_war_cnt;
	UINT32 txdonediff[MAX_STNS + 1][4][1];
	UINT32 txdidx[MAX_STNS + 1][1];
	UINT32 mon_fw_recovery;
	UINT32 cfhul_data_cnt;
	UINT32 cfhuld[4][1];
	UINT32 rx_exception[4][1];
	UINT32 stat8_data_diff[4][1];
	UINT32 stat10_data_diff[4][1];
	UINT32 rxidx;
	UINT32 total_rxinfo_cnt; // Total rxinfo request cnt
	UINT32 late_rxinfo_cnt;	 // How many times rx_info is later than wlRecv()
};

struct idx_test_arg
{
	long pkt_cnt;
	long pkt_size;
	long qid;
	long frameType;
};

typedef struct AllChanPwrTbl_s
{
	// channel sequence in array = 1,2,3,4,5,6,7,8,9,10,11,12,13,14,36,40,44,48,52,56,60,64
	// 100,104,108,112,116,120,124,128,132,136,140,144,149,153,157,161,165,169,173,177,181
	PerChanPwr_t PerChanPwrTbl[IEEE_80211_MAX_NUMBER_OF_CHANNELS];

} PACK AllChanPwrTbl_t;

struct intr_frame
{
	u32 frm_base;
	u32 spi_num;
};

struct reg_value
{
	unsigned int h2a_int_events;
	unsigned int h2a_int_cause;
	unsigned int h2a_int_mask;
	unsigned int h2a_int_clear_sel;
	unsigned int h2a_int_status_mask;

	unsigned int a2h_int_events;
	unsigned int a2h_int_cause;
	unsigned int a2h_int_mask;
	unsigned int a2h_int_clear_sel;
	unsigned int a2h_int_status_mask;

	unsigned int gen_ptr;
	unsigned int int_code;
	unsigned int evt_rdptr;
	unsigned int evt_wrptr;

	unsigned int tx_send_head;
	unsigned int tx_send_tail;
	unsigned int tx_done_head;
	unsigned int tx_done_tail;

	unsigned int rx_desc_head;
	unsigned int rx_desc_tail;
	unsigned int rx_done_head;
	unsigned int FwDbgStateAddr;

	unsigned int acnt_head;
	unsigned int acnt_tail;

	unsigned int offch_req_head;
	unsigned int offch_req_tail;

	unsigned int smac_buf_hi_addr;
	unsigned int smac_ctrlbase_nss_hi_val_intr;

	unsigned int fw_int_event_offeset;
	unsigned int fw_len_offset;
	unsigned int fw_int_cause_offset;
	unsigned int fw_setup_int_trigger;
};

struct _ext_membuf
{
	char extsym_name[20];
	BOOLEAN buf_pool_from_sys; // Buffer poll is from system or allocated
	u32 buf_pool_idx;		   // indicate BMEM or L0/L1 buffer
	u32 buf_pool_size;		   // Buffer poll size
	u8 *vbuf_pool;
	dma_addr_t pbuf_pool;
};

#if defined(MRVL_MUG_ENABLE)
struct mug_wlprivate_data
{
	struct work_struct irq_task;
	void *dma_data;
	dma_addr_t dma_phys_data;
	unsigned int dma_data_size;
	mug_fwinfo_t *p_fwinfo_shadow;
	mug_all_musets_t *p_all_musets_shadow;
	spinlock_t refresh_lock;
	BOOLEAN refresh_allowed;
};
#endif /* #if defined(MRVL_MUG_ENABLE) */

typedef enum
{
	SHARE_NONE = 0,
	SHARE_VAP,
	SHARE_STA
} SHARE_IF_STATE;

#ifdef SOC_W906X
typedef struct mbss_set
{
	UINT32 primbss;	   // primary mbssid maci
	UINT32 mbssid_set; // bitmap of mbssset group
	// UINT32      bss_active;         //active bss within mbssid_set
} mbss_set_t;
#endif

#if defined(ACNT_REC) && defined(SOC_W906X)
typedef struct _rxacntppdu
{
	U8 *acntRxBaseAddr_v;
	U32 acntRxBaseAddr_p;
	U32 acntRxSize;

	U8 *acntRxRdPtr_v;
	U32 *acntRxRdPtr_p;
} rxacntppdu;
#endif // #if defined(ACNT_REC) && defined (SOC_W906X)
#define RESET_ACNTRDPTR -1

#if defined(ACNT_REC) && defined(SOC_W906X)
#define QS_NUM_SUPPORTED_11AC_NSS_BIG 8 // From p2544 of 802.11-2016.pdf, NSTS ==0~8 for VHT SU
#define QS_NUM_SUPPORTED_11AX_NSS 8
#define QS_NUM_SUPPORTED_11AX_BW 5
#define QS_NUM_SUPPORTED_11AX_GILTF 4
#define QS_NUM_SUPPORTED_11AX_GILTF_EXT (QS_NUM_SUPPORTED_11AX_GILTF + 1)
#define QS_NUM_SUPPORTED_11AX_MCS 12

typedef struct _DRV_RATE_HIST
{
	u32 pkt_cnt[3]; // 0: Mgmt, 1: Ctrl, 2: Data, Ref: SMAC_ACNT_RX_PPDU_HDR_st
	u32 LegacyRates[QS_MAX_DATA_RATES_G];
	u32 HtRates[QS_NUM_SUPPORTED_11N_BW][QS_NUM_SUPPORTED_GI]
			   [QS_NUM_SUPPORTED_MCS];
	u32 VHtRates[QS_NUM_SUPPORTED_11AC_NSS_BIG][QS_NUM_SUPPORTED_11AC_BW]
				[QS_NUM_SUPPORTED_GI][QS_NUM_SUPPORTED_11AC_MCS];
	u32 HERates[QS_NUM_SUPPORTED_11AX_NSS][QS_NUM_SUPPORTED_11AX_BW]
			   [QS_NUM_SUPPORTED_11AX_GILTF_EXT][QS_NUM_SUPPORTED_11AX_MCS];
} DRV_RATE_HIST;
#endif // defined(ACNT_REC) && defined (SOC_W906X)

// bit[31:28] of txd1_ddr_dropbuf_cfg == Number of CFH entries
//      => There are at most 16 records
#define MAX_HWDROP_BUF 16

#define MAX_DROPBUF_CNT 1000
#define MAX_DROP_REASON 8
typedef struct _droppkt_info
{
	// buffer for H/W to save the cfh-dl of txd1 drop buffer
	U8 *TxD1DropBuf_v;
	dma_addr_t TxD1DropBuf_p;
	// Register pointer/values
	U32 *TxD1DropBuf_WrCnt_reg;
	U8 TxD1DropBuf_wid;

	// --------------------------------
	// Saved Info below:
	// dropped cfhul
	U16 dropbuf_cnt;
	U16 dropbuf_wid;
	wltxdesc_t dropbuf[MAX_DROPBUF_CNT];

	// Statistics values: TBD
	U32 drop_reason[SMAC_QID_NUM][MAX_DROP_REASON];
} DROPPKT_INFO;
// Init the txd1 droppkt_info
void wl_init_droppkt_info(struct net_device *netdev);
// Deinit the txd1 droppkt_info
void wl_deinit_droppkt_info(struct net_device *netdev);
// Check and save the drop pkt records
void wl_chk_drop_pkt(struct wlprivate_data *wlpd_p);

typedef enum
{
	PENDSKB_TX = 0,
	PENDSKB_RX,
	PENDSKB_MAX
} PEND_SKBLIST_ID;

typedef enum
{
	dbg_ivalskb_disable = 0,
	dbg_ivalskb_coredump = 2,
	dbg_ivalskb_tx = 0x10,
	dbg_ivalskb_rx = 0x20
} DBG_INVAL_SKB_TYPE;

typedef enum
{
	dbg_ivalskb_class_0 = 0x0,		// skb: signature not valid
	dbg_ivalskb_class_1 = (1 << 8), // skb: addr not valid
	dbg_ivalskb_class_2 = (2 << 8), // skb: not linked
	dbg_ivalskb_class_3 = (4 << 8)	// skb: other cases- nonlinear, TBD
} DBG_INVAL_SKB_LEVEL;

#ifdef TP_PROFILE
struct wl_tp_stat
{
	unsigned long packets;
	unsigned long packets_last;
	unsigned long packets_rate;
	unsigned long bytes;
	unsigned long bytes_last;
	unsigned long bytes_rate;
};
struct wl_tp_profile
{
	struct wl_tp_stat tx;
	struct wl_tp_stat rx;
	unsigned int tp_point;
	unsigned int mode;
};
#endif

#ifdef BAND_STEERING
typedef struct _BandSteerInfo
{
	struct list_head sta_track_list;
	UINT32 sta_track_num;
	struct list_head sta_auth_list;
	UINT32 sta_auth_num;
	struct sk_buff_head skb_queue;
	Timer queued_timer;
	UINT32 queued_skb_num;
} BandSteerInfo;
#endif /* BAND_STEERING  */

#ifdef WIFI_DATA_OFFLOAD
#define DOL_RADIO_STOP 0
#define DOL_RADIO_DFS 1
#define DOL_RADIO_START 2

struct dol_ctrl
{
	const struct mwl_dol_ops *ops;
	bool disable;
	bool pci_reset;
	void (*rcv_pkt)(void *data, struct sk_buff *skb);
	void *rcv_pkt_data;
	u8 radio_status;
	u8 cmd_buf[128];
	u8 cmd_buf_len;
	int cmd_send_result;
	u16 seq_no;
	struct mutex cmd_mutex;
	struct semaphore cmd_sema;
	struct timer_list cmd_timeout;
	u32 vif_added_to_pe[NUMOFAPS];	  /* 0: not added, 1: added */
	u32 vif_isolate_grp_id[NUMOFAPS]; /* 0: not isolated n: isolate group n */
	u16 dscp_wmm_mapping;
	u16 dbg_ctrl;
	u32 pci_sw_sem_timeout;
};
struct ipc_ctrl
{
	enum ipc_vendor vendor;
	bool disable;
	const struct mwl_ipc_ops *ops;
	void (*rcv_cmd)(void *data, const void *msg, u16 *msg_size);
	void *rcv_cmd_data;
	void (*rcv_pkt)(void *data, struct sk_buff *skb, bool is_data);
	void *rcv_pkt_data;
	void (*rcv_event)(void *data, const void *event, u16 *event_size);
	void *rcv_event_data;
};
struct trigger_cmd
{
	struct list_head list;
	u16 cmd;
	int rid;
	int vid;
	u16 stn_id;
	u8 sta_addr[ETH_ALEN];
	bool enable;
	u32 threshold;
	u8 startbytid[8];
	u16 ba_type;
	u16 ba_tid;
	u16 ba_seq;
	u16 winStartB;
	u16 winSizeB;
	u64 pkt_hdr_addr;
};
#endif
#ifdef MULTI_AP_SUPPORT
typedef struct _UnassocSTA
{
	struct net_device *netDev;
	struct list_head sta_track_list;
	UINT32 sta_track_num;
	void *unassocsta_query;
	UINT8 isTrackCompleted;
	UINT8 wiatMaxCount;
	UINT8 offChanIdx;
	Timer scanTimer;
	Timer waitTimer;
} UnassocSTA;
#endif /* MULTI_AP_SUPPORT  */

#define MAX_PENDSKBMSG 1000
typedef enum
{
	tst_send = 0,
	tst_return,
	tst_max
} txpend_skb_trace_id;

struct wlprivate_data
{
	dma_addr_t pPhysCmdBuf; /* pointer to CmdBuf (physical) */
#ifdef SOC_W906X
	dma_addr_t pPhysFwDlBuf;					  /* pointer to FWDL (physical) */
#endif											  /* SOC_W906X */
	struct timer_list Timer;					  /* timer tick for Timer.c         */
	Bool_t isMtuChanged;						  /* change may interact with open */
	Bool_t isTxTimeout;							  /* timeout may collide with scan */
	Bool_t inReset;								  /* is chip currently resetting  */
	Bool_t inResetQ;							  /* is chip currently resetting  */
	struct wllocks locks;						  /* various spinlocks                    */
	struct wlpriv_stats privStats;				  /* wireless statistic data              */
	struct wlpriv_net_device_stats privNdevStats; /* private net_device statistics, add for EasyMesh data element */
	struct iw_statistics wStats;				  /* wireless statistic data      */
	struct sk_buff_head aggreQ;
	struct sk_buff_head txQ[NUM_OF_DESCRIPTOR_DATA];
	struct sk_buff_head tcp_ackQ[NUM_OF_TCP_ACK_Q];
	unsigned int tcp_ack_mod;
#ifdef SOC_W906X
	struct sk_buff_head txq_per_sta[MAX_OFDMADL_STA];		/* tx balance per STA */
	struct wldesc_data descData[NUM_OF_HW_DESCRIPTOR_DATA]; /* various descriptor data              */
#else
	struct wldesc_data descData[NUM_OF_DESCRIPTOR_DATA]; /* various descriptor data              */
	UINT8 isTxTaskScheduled;							 /*To keep scheduling status of a tx task */
#endif
#ifdef USE_TASKLET
	struct tasklet_struct txtask;
	struct tasklet_struct MUtask;		// Auto MU set creation tasklet
	struct tasklet_struct buf_rel_task; /* Process release buffer thru txdone */
#else
	struct work_struct txtask;
#endif

#ifdef USE_TASKLET
	struct tasklet_struct rxtask;
#else
	struct work_struct rxtask;
#endif
// A390/A385 platform supports only 16 interrupts => Use polling function instead
#ifdef USE_TASKLET
	struct tasklet_struct intrtask;
#else
	struct work_struct intrtask;
#endif

#if defined(ACNT_REC) && defined(SOC_W906X)
	m_thread rxinfotask;
#endif // #if defined(ACNT_REC) && defined (SOC_W906X)
#if defined(RXACNT_REC) && defined(SOC_W906X)
	m_thread racnttask;
#endif // RXACNT_REC
#if defined(TXACNT_REC) && defined(SOC_W906X)
	m_thread tacnttask;
#endif // #if defined(TXACNT_REC) && defined (SOC_W906X)

	struct tasklet_struct rx_refill_task;
	struct work_struct resettask;
#ifdef MRVL_DFS
	struct work_struct dfstask;
	struct work_struct csatask;
#ifdef CONCURRENT_DFS_SUPPORT
	struct work_struct dfstaskAux;
#endif /* CONCURRENT_DFS_SUPPORT */
#endif

	struct task_struct *wlmon_task;

	struct work_struct kickstatask;
#ifdef SOC_W906X
	struct work_struct offchantask;
#else  // 906X off-channel
	struct work_struct offchandonetask;
#endif // 906X off-channel
#ifdef SYSFS_STADB_INFO
	struct work_struct sysfstask;
#endif /* SYSFS_STADB_INFO */

	int SDRAMSIZE_Addr;
	int CardDeviceInfo;
	int fwDescCnt[NUM_OF_DESCRIPTOR_DATA]; /* number of descriptors owned by fw at any one time */
	int txDoneCnt;						   /* number of tx packet to call wlTXDONE() */
	int vmacIndex;
	Bool_t inSendCmd;
	vmacApInfo_t *vmacampdurxap_p;
	UINT8 ampdurxmacaddrset;
#ifdef SOC_W906X
	Ampdu_Pck_Reorder_t *AmpduPckReorder;
#else
	Ampdu_Pck_Reorder_t AmpduPckReorder[MAX_AID + 1];
#endif
	Ampdu_tx_t *Ampdu_tx;
	UINT8 Global_DialogToken;
	struct wlprivate *masterwlp;
#ifdef MRVL_DFS
	DfsAp *pdfsApMain;
#ifdef RADAR_SCANNER_SUPPORT
	UINT8 ext_scnr_en;
#endif
#endif // MRVL_DFS
	UINT8 TxGf;
	UINT8 NonGFSta;
	UINT8 BcnAddHtOpMode;
	UINT8 legClients;
	UINT8 n20MClients;
	UINT8 nClients;
	UINT8 legAPCount;
#ifdef COEXIST_20_40_SUPPORT
	UINT8 BcnAddHtAddChannel;
#endif
	UINT8 BcnErpVal;
	struct net_device *rootdev;

#ifdef SSU_SUPPORT
	dma_addr_t pPhysSsuBuf;
#endif
#ifdef DSP_COMMAND
	dma_addr_t pPhysDspBuf;
#endif
#ifdef NEW_DP
	NewdpRxCounter_t rxCnts;
	struct work_struct acnttask;
#endif

#if defined(MRVL_MUG_ENABLE)
	struct mug_wlprivate_data mug;
#endif

#if defined(AIRTIME_FAIRNESS)
	struct work_struct atf_irq_task;
#endif /* AIRTIME_FAIRNESS */

	mmap_info AllocSharedMeminfo;
	post_req_sig_info_t PostReqSiginfo;
	mrvl_pri_shared_mem_t MrvlPriSharedMem;
#if defined(SOC_W906X) || defined(NEWDP_ACNT_CHUNKS)
	mmap_info_acnt_chunk mmap_ACNTChunk[ACNT_NCHUNK];
	acnt_chunk_info_t AcntChunkInfo;
	UINT8 acntRecords[ACNT_NCHUNK * DEFAULT_SIZE_CHUNK];
#else
	mmap_info ACNTmemInfo;
	UINT8 acntRecords[DEFAULT_ACNT_RING_SIZE];
#endif
	BOOLEAN bBssStartEnable;
#if defined(ACNT_REC) && defined(SOC_W906X)
	DRV_RATE_HIST drvrxRateHistogram;
#endif // defined(ACNT_REC) && defined (SOC_W906X)
	WLAN_RATE_HIST rxRateHistogram;
	WLAN_TX_RATE_HIST *txRateHistogram[MAX_STNS + 1];
	// WLAN_SCHEDULER_HIST scheHistogram;
	WLAN_SCHEDULER_HIST *scheHistogram[MAX_STNS + 1];
	void *acnt_tx_record;
	UINT32 acnt_tx_record_idx;
	void *acnt_RA_stats;
	DECLARE_LOCK(txRateHistoLock[MAX_STNS + 1]);
#ifdef NEWDP_ACNT_BA
	WLAN_TX_BA_HIST txBAStats[3];
#endif
	RssiPathInfo_t rssi_path_info;
	NfPathInfo_t NF_path;
	rx_info_aux_t lst_rxinfo_aux;
	UINT8 ldpcdisable;
#ifdef SOC_W906X
	List offChanList;
	Timer offChanCooldownTimer;
#else  // 906X off-channel
	List ReqIdList;
#endif // 906X off-channel
#ifdef SYSFS_STADB_INFO
	List sysfsSTAHdlList;
#endif							   /* SYSFS_STADB_INFO */
	AllChanPwrTbl_t AllChanPwrTbl; // for Barbado
	char dev_running[MAX_VMAC_INSTANCE_AP + 1];
	struct platform_device *pDev;
	struct pci_dev *pPciDev;
	struct device *dev;
	UINT32 baseaddress0;
	UINT32 baseaddress2;
	UINT32 baseaddress4;
	BOOLEAN bfwreset;
	BOOLEAN bpreresetdone;
	UINT8 gpioresetpin;
	struct sk_buff_head txQueRecord;
	struct sk_buff_head rxSkbTrace;
	UINT8 fastdata_reordering_disable;
	List FreeStaIdList;
	List StaIdList;
	List FreeAIDList;
	List AIDList;
	IdListElem_t *AidList;
	IdListElem_t *StnIdList;
	BOOLEAN bStopBcnProbeResp;
	UINT8 repeaterUpdateChannelWidth;
	UINT8 MUcurVapidx;	   // current vap to process auto MU set creation
	UINT32 MUtimercnt;	   // time counter for auto MU set creation
	MU_Set_List MUSetList; // list for all created MU set
	DECLARE_LOCK(MUSetListLock);
	BOOLEAN bCACBWChanged;
	BOOLEAN bCACChannelChanged;
	BOOLEAN bCACTimerFired;
	UINT32 rxskbunlinkerror;
	UINT32 signatureerror;
	struct list_head TxCloneSkbHead;

	UINT32 TxDescLimit; // Limit tx desc to queue into fw, value get from fw via wlFwGetHwSpecs

	int proms_data_cnt;				/* counter for promiscuous data frame received */
	int proms_mgmt_cnt;				/* counter for promiscuous management frame received */
	int proms_ctrl_cnt;				/* counter for promiscuous control frame received */
	struct drv_stats drv_stats_val; // Statistics data
	struct except_cnt except_cnt;	// Exception counter
	struct bqm_args bmq_args;
	struct idx_test_arg idx_test_arg;
	struct intr_frame sysintr_frm;
	UINT32 pktmsg_ctrl;

	smac_mon smon; // structure for background monitor smac heartbits

	// Statistics of tx/rx pkt type
	struct pkttype_info tpkt_type_cnt, rpkt_type_cnt;
	unsigned int intr_shift;
	unsigned int msix_num;
	int bus_type;
	struct reg_value reg;
	gfp_t dma_alloc_flags;
	BOOLEAN tx_async;				  // Is sending tx packets synchroniclly
	struct _ext_membuf ext_membuf[2]; // External memory buffer for SMAC (USE_64M & USE_64M)

	// List of the skbs which have been passed down & has not returned yet
	//       - tx: skb has been passed to txq, not returned
	//       - rx: to bmq which have been taken by HW
	struct sk_buff_head pend_skb_trace[PENDSKB_MAX];

	struct sk_buff *tx_pend_skb_msg[tst_max][MAX_PENDSKBMSG];
	UINT32 tx_pend_skb_msg_id[tst_max];

	cfhul_buf_pool icfhul_buf_pool;
	struct sk_buff *last_skb[SC5_BMQ_NUM];
	rxdbg_db vrxdbg_db;
	rxdbg_intf irxdbg_intr;

	unsigned int downloadSuccessful; // Firmware download successfully

	UINT32 SharedBssState; // flag to denote bss_31 is occupied by the last vap or sta0 or none
	UINT32 NumOfAPs;	   // max number of APs of the device. This is a WAR before SC5 fix an DMA issue that resulted in one BSS less than W9064.
	UINT32 MonIfIndex;	   // sotre monif index of vdev[]. WAR for inconsitent MONIF index. Restore this WAR after SC5 DMA issue fixed.
	int mci_id;
#ifdef SOC_W906X
	UINT32 bss_inupdate;				// bitmap of mbss that are in update
	UINT32 bss_active;					// active MBSSID bitmap.
	mbss_set_t mbssSet[MAX_MBSSID_SET]; // MBSSID set info.
#endif
	coredump_t coredump; // store coredump regions info
	struct kmsg_dumper kdumper;
#if defined(ACNT_REC) && defined(SOC_W906X)
	rx_info_ppdu_t *acntRxInfoQueBaseAddr_v;
	rx_info_aux_t *rxinfo_aux_poll;
	BOOLEAN rxinfo_inused;
	rx_info_ppdu_t last_rxinfo;
	// generic_buf                   radio_info[RACNTQ_SIZE];
#endif // defined(ACNT_REC) && defined (SOC_W906X)
#if defined(TXACNT_REC) && defined(SOC_W906X)
	U16 startSeq[DRV_TX_ACNT_USER_NUM][DRV_TX_ACNT_MAX_NUM_TID];
	U32 txacnt_ppdurec_cnt[ppdu_type_max];
	U32 txacnt_txdone_cnt[DRV_TX_ACNT_USER_NUM][tacnt_txdone_type_max];

	U32 rxacnt_ppdurec_cnt[3];

	// Dbg++
	U8 *lastppduinfo;
	U8 *lasttxdoneinfo;
	// Dbg--

	U16 acntTxMsduRing_id;
	MSDU_RING_INFO_st *acntTxMsduRingBaseAddr_v;
	U32 acntTxMsduRingBaseAddr_p;
	U32 acntTxMsduRingSize;

	txacntppdu acntTxAcntPpdu;
#endif // defined(TXACNT_REC) && defined (SOC_W906X)
	// ----------------------------------------------------------------
	rxacntppdu acntRxAcntPpdu;
	// TxD1 Drop
	DROPPKT_INFO droppkt_info;
	BOOLEAN is_txd1_drop;

	AllChanGrpsPwrTbl_t AllChanGrpsPwrTbl;
	RateGrp_t RateGrpDefault[MAX_GROUP_PER_CHANNEL];
#ifdef NULLPKT_DBG
	wlrxdesc_t nullpkt_cfhul[10];
	U8 last_null_pkt[10][1024];
#endif // NULLPKT_DBG
#ifdef SOC_W906X
	/* debug for invalid skb */
	dbg_skb dbgskb;
#endif
#if (defined WLS_FTM_SUPPORT) || (defined AOA_PROC_SUPPORT)
	WLS_FTM_CONFIG_st *wls_ftm_config;
	CSI_CONFIG_st *csi_config;
#endif
#ifdef TP_PROFILE
	struct wl_tp_profile wl_tpprofile;
	struct timer_list tp_profile_timer;
#endif
#ifdef BAND_STEERING
	BandSteerInfo bandSteer;
#endif /* BAND_STEERING */
#ifdef MULTI_AP_SUPPORT
	UnassocSTA unassocSTA;
#endif /* MULTI_AP_SUPPORT  */
#ifdef PRD_CSI_DMA
	struct work_struct prd_csi_dma_done_wq;
#endif
#ifdef WIFI_DATA_OFFLOAD
	struct dol_ctrl dol;
	struct ipc_ctrl ipc;
	int ipc_session_id;
	struct sk_buff_head recv_q_data;
	struct sk_buff_head recv_q_mgmt;
	struct work_struct delay_cmd_handle;
	bool delay_cmd_trigger;
	/* Should be protected by delayCmdLock */
	struct list_head delay_cmd_list;
	u32 bm_release_request_num;
	u32 bm_release_request_ipc;
#endif
#ifdef SOC_W906X
	mmap_info smdata_mmap_info;
	UINT32 sta_tx_succ[MAX_STNS];
	UINT32 sta_keep_alive_tx_succ[MAX_STNS];
#endif					   /* SOC_W906X */
	U32 rrm_trigger_time;  // rrm trigger time(ms)
	U32 rrm_interval_time; // offchan interval time(ms)
	U32 rrm_dwell_time;	   // fw offchan time(ms)

	IEEEtypes_MacAddr_t mac_addr_sta_ta;
	unsigned int mmdu_mgmt_enable;
	unsigned int mmdu_data_enable;
};

typedef enum
{
	BUS_TYPE_MCI = 0,
	BUS_TYPE_PCI,
} BUS_TYPE;

typedef enum
{
	PLATFORM_ID_A3900_A7K = 0,
	PLATFORM_ID_A8K,
	PLATFORM_ID_A390,
	PLATFORM_ID_A380,
	PLATFORM_ID_MAX
} PLATFORM_ID;

struct intr_info
{
	unsigned int intr_shift;
	unsigned int msix_num;
};

#define SC5_MSIX_NUM 32

struct msix_context
{
	struct net_device *netDev;
	UINT32 msg_id;
	unsigned int irq_vec;
};

#ifdef CCK_DESENSE
/* STATE_BITMASK */
#define CCK_DES_STATE_ON BIT(0)
#define CCK_DES_STATE_ASSOC BIT(1)

/* OFF_REASON_BITMASK */
#define CCK_DES_OFF_TIMER BIT(0)
#define CCK_DES_OFF_NO_STA_CONNECTED BIT(1)
#define CCK_DES_OFF_LOW_TRAFFIC BIT(2)
#define CCK_DES_OFF_LOW_CCA BIT(3)

#define CCK_DES_POLLDATA_SIZE 10

typedef enum
{
	CCK_DES_OFF = 0,   // OFF
	CCK_DES_ON,		   // ON
	CCK_DES_RUN,	   // RUN thres recal
	CCK_DES_DISASSOC,  // STA disass
	CCK_DES_ASSOC_RSP, // STA resp
	CCK_DES_AUTH_REQ,  // STA auth request
} CCK_DESENSE_CTRL_CMD;

struct cck_des_config
{
	bool enable;
	u8 threshold;
	s8 threshold_ceiling;
	u8 rssi_margin;
};

struct cck_des_polldata
{
	u8 txbps_idx;
	u8 cca_idx;
	u32 tx_bytes;
	u32 txbps[CCK_DES_POLLDATA_SIZE];
	u32 cca[CCK_DES_POLLDATA_SIZE];
	u32 txbps_avg;
	u32 cca_avg;
};

struct cck_des_loadcfg
{
	bool enable;
	u8 polltimer_start;
	Timer polltimer;
	u32 poll_time_ms;
	struct cck_des_polldata data;
	u32 thres_tx;
	u32 thres_cca;
};

struct cck_desense
{
	u8 state;
	u8 cycles;
	u8 update_cycles;
	s8 rssi_min;
	Timer timer;
	u8 timer_start;
	u32 on_time_ms;
	u32 off_time_ms;
	u32 off_reason;
	u32 auth_cnt;
	u32 auth_time_ms;
	struct cck_des_config cck_des_conf;
	struct cck_des_config rx_abort_conf;
	struct cck_des_loadcfg loadcfg;
};
#endif /* CCK_DESENSE */

#define BMQ_DIFFMSG_COUNT 10000 // How big difference to show the message

#define EVENT_BUFFQ_NUM 256	 // Number of event buffer queue items
#define EVENT_BUFFQ_SIZE 256 // Size of one event buffer item

#include "ap8xLnxEvent.h"

typedef struct _tf_test_arg
{
	UINT8 type;
	UINT32 rate_info;
	UINT32 period;
	UINT32 pad_num;
	tf_basic_t tf;
} tf_test_arg_t;

#if (defined WLS_FTM_SUPPORT) || (defined AOA_PROC_SUPPORT)
#include "ap8xLnxWls.h"
#include "ap8xLnxCsi.h"
#endif
#ifdef CB_SUPPORT
#define SMAC_BCN_BUFSIZE 2048 ///< bytes
#endif						  // CB_SUPPORT
struct wlprivate
{
	struct net_device *netDev; /* the net_device struct        */
#ifdef NAPI
	struct napi_struct napi;
#endif
#ifdef CFG80211
	struct wiphy *wiphy;
	struct wireless_dev wdev;
	struct ieee80211_channel channel;
	struct cfg80211_scan_request *request;
#endif
	struct net_device_stats netDevStats; /* net_device statistics        */
	struct platform_device *pDev;
	void __iomem *ioBase0; /* MEM Base Address Register 0  */
	void __iomem *ioBase1; /* MEM Base Address Register 1  */
#ifdef WIFI_DATA_OFFLOAD
	unsigned long ioBase0_phy;
	unsigned long ioBase1_phy;
#endif
	void __iomem *ioBaseExt; /* Other regsions to check such as mochi */
	phys_addr_t phys_addr_start;
	phys_addr_t phys_addr_end;
	struct pci_dev *pPciDev; /* for access to pci cfg space  */
	void *ioBase2;			 /* MEM Base Address Register 2  */
	unsigned short *pCmdBuf; /* pointer to CmdBuf (virtual)  */
#ifdef SOC_W906X
	unsigned short *pFwDlBuf; /* pointer to FWDL (virtual)  */
#endif
	struct wlhw_data hwData; /* Adapter HW specific info     */
	vmacApInfo_t *vmacSta_p;
#ifdef CLIENT_SUPPORT
	void *clntParent_priv_p;
#ifdef MRVL_WPS_CLIENT
	UINT8 wpsProbeRequestIe[256];
	UINT8 wpsProbeRequestIeLen;
#endif
#endif /* CLIENT_SUPPORT */
	int (*wlreset)(struct net_device *netdev);
	struct net_device *master;
#ifdef ENABLE_MONIF
	struct net_device *vdev[MAX_VMAC_INSTANCE_AP + 2]; //+1 station +1 monitor intf
#else
	struct net_device *vdev[MAX_VMAC_INSTANCE_AP + 1]; //+1 station
#endif
	struct wlprivate_data *wlpd_p;
	UINT8 calTbl[200];
	UINT8 *FwPointer;
	UINT32 FwSize;
	UINT8 mfgEnable;
	UINT32 cmdFlags; /* Command flags */
	struct net_device *txNetdev_p;
	UINT32 nextBarNum;
	UINT32 chipversion;
	UINT32 mfgLoaded;
	UINT16 devid;
	UINT8 cardindex;
	UINT8 intr_type;
	UINT8 retrycfgenable;
	RetryCfgVAP_t retrycfgVAP;
#ifdef SSU_SUPPORT
	unsigned short *pSsuBuf;
	UINT32 ssuSize;
#endif
#ifdef WTP_SUPPORT
	struct sock *nl_socket;
#endif
#ifdef DSP_COMMAND
	int *pDspBuf;
	UINT32 dspSize;
#endif
	UINT32 RxQId;
	UINT32 TxQId;
	UINT32 BQId;
	UINT32 BQRelId;
#if defined(ACNT_REC) && defined(SOC_W906X)
	UINT32 RAcntQId;
#endif // defined(ACNT_REC) && defined (SOC_W906X)
#if defined(TXACNT_REC) && defined(SOC_W906X)
	UINT32 TAcntQId;
#endif // defined(ACNT_REC) && defined (SOC_W906X)

	unsigned int bgscan_period; // BG scan period. 0=disable BG_scan

	unsigned int num_vectors;
	struct msix_context msix_ctx[SC5_MSIX_NUM + SC5_MSIX_NUM]; // Allocate twice space for MSIX WAR
	void *hframe_virt_addr;
	dma_addr_t hframe_phy_addr;
	struct msix_entry *msix_entries;

	SMAC_STATUS_st *smacStatusAddr;
	SMAC_CONFIG_st *smacCfgAddr;
	SMAC_CONFIG_st smacconfig;

	// Variables for event buffer queue
	dma_addr_t event_bufq_paddr;
	void *event_bufq_vaddr;
	// RX Sideband info buffer base
	void *smac_base_vp;
	RxSidebandInfo_t *rxSBinfoBaseAddr_v;
#ifdef DUPLICATED_MGMT_DBG
	int rx_retry_mgmt_cnt;
#endif

	wl_cfhul_amsdu cfhul_amsdu[SC5_RXQ_NUM];
	u8 cmd_seqno;

#ifdef MBO_SUPPORT
	UINT8 mboProbeRequestIe[256];
	UINT8 mboProbeRequestIeLen;
	UINT8 mboAssocRequestIe[256];
	UINT8 mboAssocRequestIeLen;
#endif /* MBO_SUPPORT */
	offchan_status offchan_state;
#ifdef CCK_DESENSE
	struct cck_desense cck_des;
#endif /* CCK_DESENSE */
	IEEEtypes_MacAddr_t sndpkt_mac;
	UINT8 wfa_sndpkt_rate;
	UINT32 wfa_sndpkt_interval;
	bool is_wfa_testbed;
#ifdef PRD_CSI_DMA
	evt_prdcsi_t prdcsi_data;
#endif
	tf_test_arg_t tf_test_arg;
#ifdef CB_SUPPORT
	UINT8 cb_enable;
	UINT8 is_resp_mgmt;
	UINT8 vap_id;
	UINT32 bcnBasePtr;
	cbcallbk_intf cb_callbk_func;
	struct timer_list bnc_timer; /* timer tick for Timer.c     */
	UINT8 cust_ie[64];
	UINT8 custie_len;
#endif // CB_SUPPORT
	u32 auto_bw;
};

#ifdef ENABLE_MONIF
#define CLICK_WIFI_SCHEDULE_SIZE 2
#define CLICK_WIFI_RX_MAGIC 0x74
#define CLICK_WIFI_TX_MAGIC 0x96

struct click_wifi_extra
{
	uint8_t magic;
	uint8_t flags;
	uint8_t channel;
	uint8_t keyix;

	uint8_t rssi;
	uint8_t silence;
	uint8_t power;
	uint8_t retries;

	uint8_t max_tries[CLICK_WIFI_SCHEDULE_SIZE];
	uint8_t rates[CLICK_WIFI_SCHEDULE_SIZE];
	// XXX Cliff: for some reason things break if I make this a 12 byte structure, so
	// just get the free space at the end so that we can use other annotations that overlap
	uint8_t unused[4];
} __attribute__((packed));
#endif

#ifdef BAND_STEERING
struct sta_track_info
{
	struct list_head list;
	UINT8 addr[ETH_ALEN];
	unsigned long last_seen;
};

struct sta_auth_info
{
	struct list_head list;
	UINT8 addr[ETH_ALEN];
	UINT8 count;
};
#endif /* BAND_STEERING */

#ifdef MULTI_AP_SUPPORT
struct unassocsta_track_info
{
	struct list_head list;
	UINT8 addr[ETH_ALEN];
	UINT8 channel;
	UINT32 rssi;
	unsigned long last_seen;
};
#endif /* MULTI_AP_SUPPORT */

#ifdef MV_NSS_SUPPORT
extern struct sk_buff *wlAllocSkb(unsigned int length);
extern void wlFreeSkb(struct sk_buff *skb);
extern int wlReceiveSkb(struct sk_buff *skb);
#define SKB_DATA_FLAG 0
#define SKB_MNG_FLAG 1
#define MARK_DATA_SKB(skb) ((skb)->cb[0] = SKB_DATA_FLAG)
#define MARK_MNG_SKB(skb) ((skb)->cb[0] = SKB_MNG_FLAG)
#define IS_DATA_SKB(skb) ((skb)->cb[0] == SKB_DATA_FLAG)
#define IS_MNG_SKB(skb) ((skb)->cb[0] == SKB_MNG_FLAG)
#define wl_alloc_skb(length) (wlAllocSkb(length))
#define wl_free_skb(skb) (wlFreeSkb(skb))
#define wl_receive_skb(skb) (wlReceiveSkb(skb))
#else
extern void *wl_util_alloc_skb(int len, const char *func, const int line);
extern void wl_util_free_skb(struct sk_buff *skb, const char *func,
							 const int line);
extern void wl_util_receive_skb(struct sk_buff *skb, const char *func,
								const int line);

#define MARK_DATA_SKB(skb)
#define MARK_MNG_SKB(skb)

#define wl_alloc_skb(length) (wl_util_alloc_skb((length), __func__, __LINE__))
#define wl_free_skb(skb) (wl_util_free_skb(skb, __func__, __LINE__))
#define wl_receive_skb(skb) (wl_util_receive_skb(skb, __func__, __LINE__))
#endif

extern struct net_device *mainNetdev_p[NUM_OF_WLMACS];
extern int wlinitcnt;
extern UINT8 tmpScanResults[NUM_OF_WLMACS][MAX_SCAN_BUF_SIZE];
extern UINT8 tmpNumScanDesc[NUM_OF_WLMACS];
extern int wlResetTask(struct net_device *dev);
extern void wlLinkMgt(struct net_device *netdev, UINT8 phyIndex);
extern void wlVirtualInfDown(struct net_device *netdev);
extern void wlVirtualInfUp(struct net_device *netdev);
extern void AllocMrvlPriSharedMem(struct wlprivate *wlpptr);
extern void wlFwHardResetAndReInit(struct net_device *netdev, U8 halt);
#ifdef SOC_W906X
extern void update_mbss_status(struct wlprivate *wlpptr, u8 status);
#endif

#define FW_HIO_MB_SIZE (16 * 1024)
#define FW_CSI_BUF_SIZE (32 * 1024)
#define FW_IO_MB_SIZE (FW_HIO_MB_SIZE + FW_CSI_BUF_SIZE)
#define FW_IO_NUM_PAGE FW_IO_MB_SIZE / 4096

extern int platform_id;
#define IS_PLATFORM(x) (platform_id == PLATFORM_ID_##x)

#define IS_BUS_TYPE_MCI(wlpptr) 0

#ifdef SOC_W906X
void quiet_stop_allInf(struct net_device *netdev, boolean quiet);
extern void offChanDoneHdlr(struct net_device *netdev,
							offchan_status next_state);
int isSupport80plus80Mhz(struct wlprivate *wlpptr);

#ifdef CCK_DESENSE
#define CCK_DESENSE_THRESHOLD_CEILING (-58) // (-70)- Revert it from super high value 10 to a normal value to reactivate CCK Desense Threshold Ceiling cap.
#define CCK_DESENSE_RSSI_MARGIN 20
#define CCK_DESENSE_ON_DURATION_MS 2000
#define CCK_DESENSE_OFF_DURATION_MS 500
#define CCK_DESENSE_DYNAMIC_ENABLE 1
#define CCK_DESENSE_UPDATE_CYCLE_CNT 5
#define CCK_DESENSE_AUTH_DURATION_MS 100

#define RX_ABORT_THRESHOLD_CEILING (-58) // (-70)- Revert it from super high value 10 to a normal value to reactivate rx abort Threshold Ceiling cap.
#define RX_ABORT_RSSI_MARGIN 10
#define RX_ABORT_DYNAMIC_ENABLE 1

#define CCK_DESENSE_OPT_ENABLE 0
#define CCK_DESENSE_POLL_DURATION_MS 100
#define CCK_DESENSE_THRES_TX_KBPS 1000
#define CCK_DESENSE_THRES_CCA_LEVEL 30
#endif /* CCK_DESENSE */

#endif
extern unsigned int bss_num;
extern unsigned int sta_num;
extern unsigned int mem_dbg;
extern int wfa_11ax_pf;
extern unsigned int hm_gpio_trigger;
extern UINT32 dbg_class;
extern unsigned int dbg_max_tx_pend_cnt_per_q;
extern unsigned int dbg_max_tx_pend_cnt_per_mgmt_q;
extern unsigned int dbg_max_tx_pend_cnt_per_bcast_q;
extern unsigned int dbg_max_tx_pend_cnt_per_sta;
extern unsigned int dbg_stop_tx_pending;
extern unsigned int dbg_max_tx_pending;
extern unsigned int dbg_tcp_ack_drop_skip;
extern unsigned int dbg_tx_pend_cnt_ctrl;
extern unsigned int dbg_max_tx_pending_lo;
extern unsigned int dbg_max_tx_pend_cnt_per_q_lo;
extern unsigned int dbg_max_tx_pend_cnt_per_sta_lo;

extern int rssi_threshold;
extern int rssi_nf_delta;
extern int ext_weight_1611;
extern unsigned int chld_nf_delta;
extern unsigned int chld_ceil;
extern unsigned int abs_nf_floor;
extern unsigned int acs_cal;

#endif /* AP8X_INTF_H_ */
