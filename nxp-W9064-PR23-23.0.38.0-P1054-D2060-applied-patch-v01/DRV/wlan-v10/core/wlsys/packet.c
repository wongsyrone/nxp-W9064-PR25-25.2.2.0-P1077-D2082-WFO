/** @file packet.c
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
/*!
 * \file    packet.c
 * \brief   Sample packets processing routines
 */
#include <linux/version.h>
#include <linux/ip.h>
#include <linux/igmp.h>
#include "Fragment.h"

#include "keyMgmt_if.h"
#include "wldebug.h"
#include "ap8xLnxRegs.h"
#include "ap8xLnxDesc.h"
#include "ap8xLnxIntf.h"
#include "ap8xLnxXmit.h"
#include "ap8xLnxFwcmd.h"
#include "ap8xLnxWlLog.h"
#include "ap8xLnxRxInfo.h"
#include "wltypes.h"
#include "wl_macros.h"
#include "IEEE_types.h"
#include "wl_mib.h"
#include "wl_hal.h"
#include "StaDb.h"
#include "ds.h"
#include "ap8xLnxDma.h"
#include "buildModes.h"
#include "macmgmtap.h"
#include "macMgmtMlme.h"
#ifdef EWB
#include "ewb_packet.h"
#endif
#ifdef DYNAMIC_BA_SUPPORT
#include "wltypes.h"
#include "osif.h"
#include "timer.h"
#endif
#include "wds.h"
#include "mlmeApi.h"
#include "keyMgmtSta.h"
#include "linkmgt.h"
#ifdef MPRXY
#include "ap8xLnxMPrxy.h"
#endif

#ifdef IEEE80211K
#include "msan_report.h"
#endif //IEEE80211K

#include "shal_msg.h"

#define INTERNAL_FLUSH_TIMER

#ifndef AMSDUOVERAMPDU
struct mcsratemap_t {
	UINT16 rate2timesMbps[16];
} mcsratemap_t;

static struct mcsratemap_t macratemap[2] = {
	{{13, 26, 39, 52, 78, 104, 117, 130, 26, 52, 78, 104, 156, 208, 234,
	  260}},
	{{27, 54, 81, 108, 162, 216, 243, 270, 54, 108, 162, 216, 324, 432, 486,
	  540}}
};
#endif

#ifdef DEBUG_BAREORDER
UINT32 dbg_BAredr_id = 0;	//sta id for logging
UINT32 dbg_BAredr_cardindex = 0;	//wdev interface for logging

//Log for incoming seqno for history keeping. Used in out of range BA reorder logging
//UINT32 dbg_BAredr_Sta[DBG_BAREORDER_SN_MASK+1];     //b31-16: sta mac addr, 15-0: sta id
UINT32 dbg_BAredr_SN[DBG_BAREORDER_SN_MASK + 1];	//b31-28:tid, b27-24:location of code, b23-12: winStartB, b11-0:incoming seqno
UINT32 dbg_BAredr_SN_cnt = 0;

//Log for out of range BA reorder, each record takes 4 DWORD
//1st DW: OOR of incoming, 2nd DW to 4th DW: previous seqno of last 3 incoming seqno
//UINT32 dbg_BAredr_OOR_Sta[DBG_BAREORDER_OOR_MASK+1];    //b31-16: sta mac addr, 15-0: sta id
UINT32 dbg_BAredr_OOR[DBG_BAREORDER_OOR_MASK + 1];
UINT32 dbg_BAredr_OOR_cnt = 0;
UINT32 dbg_BAredr_OOR_cont = 0;	//continous out of range count 
#endif

#define BA_REORDER_FAST_DATA

#define ETHER_TYPE_LEN          2	/* length of the Ethernet type field */
#define ETHER_CRC_LEN           4	/* length of the Ethernet CRC */
#define ETHER_HDR_LEN           (IEEEtypes_ADDRESS_SIZE * 2 + ETHER_TYPE_LEN)
#define ETHER_MAX_LEN           1518

#define ETHERMTU        (ETHER_MAX_LEN - ETHER_HDR_LEN - ETHER_CRC_LEN)
#define IEEE80211_SEQ_SEQ_SHIFT                 4

//#define MAX_REORDERING_HOLD_TIME        (HZ / 2) //500ms
#ifdef SOC_W8964
#define DEBUG_REORDER()
#endif /* SOC_W8964 */

#ifdef RX_REPLAY_DETECTION
#define SMAC_CFHUL_MAC_HDR_OFFSET  48
#endif

BaR_Debug_t ba_debug_buf[256] = { 0 };

UINT32 temp_index = 0;

/*Once receive Probe Resp or JoinCmd in client mode, we set to 1 to monitor active tx traffic.
 * In client mode, we monitor active tx/ rx traffic so we don't send probe req during traffic.
 * But when AP suddenly goes away in UDP client->AP case, consecutive tx failure will reach limit and fw will inform host.
 * When host receives ISR for consecutive tx failure, we don't monitor active tx anymore so client mode send probe req out
 */
UINT8 ClientModeTxMonitor = 0;
UINT8 ProbeReqOnTx = 0;		// Client mode sends Probe Req during tx. 0: No, 1: Yes

struct ieee80211_frame_min {
	IEEEtypes_FrameCtl_t FrmCtl;
	UINT8 dur[2];
	UINT8 addr1[IEEEtypes_ADDRESS_SIZE];
	UINT8 addr2[IEEEtypes_ADDRESS_SIZE];
	/* FCS */
} PACK;

/*
 * Structure of a 10Mb/s Ethernet header.
 */
struct ether_header {
	UINT8 ether_dhost[IEEEtypes_ADDRESS_SIZE];
	UINT8 ether_shost[IEEEtypes_ADDRESS_SIZE];
	UINT16 ether_type;
};
struct ieee80211_qosframe {
	IEEEtypes_FrameCtl_t FrmCtl;
	UINT8 dur[2];
	UINT8 addr1[IEEEtypes_ADDRESS_SIZE];
	UINT8 addr2[IEEEtypes_ADDRESS_SIZE];
	UINT8 addr3[IEEEtypes_ADDRESS_SIZE];
	UINT8 seq[2];
	UINT8 qos[2];
	UINT8 addr4[IEEEtypes_ADDRESS_SIZE];
} PACK;

struct ieee80211_qosHtctlframe {
	IEEEtypes_FrameCtl_t FrmCtl;
	UINT8 dur[2];
	UINT8 addr1[IEEEtypes_ADDRESS_SIZE];
	UINT8 addr2[IEEEtypes_ADDRESS_SIZE];
	UINT8 addr3[IEEEtypes_ADDRESS_SIZE];
	UINT8 seq[2];
	UINT8 addr4[IEEEtypes_ADDRESS_SIZE];
	UINT8 qos[2];
	UINT8 htctl[4];
} PACK;

struct ieee80211_frame {
	IEEEtypes_FrameCtl_t FrmCtl;
	UINT8 dur[2];
	UINT8 addr1[IEEEtypes_ADDRESS_SIZE];
	UINT8 addr2[IEEEtypes_ADDRESS_SIZE];
	UINT8 addr3[IEEEtypes_ADDRESS_SIZE];
	UINT8 seq[2];
	UINT8 addr4[IEEEtypes_ADDRESS_SIZE];
} PACK;

#define IEEE80211_ADDR_COPY(dst, src)    memcpy(dst, src, IEEEtypes_ADDRESS_SIZE)
struct llc {
	UINT8 llc_dsap;
	UINT8 llc_ssap;
	union {
		struct {
			UINT8 control;
			UINT8 format_id;
			UINT8 class;
			UINT8 window_x2;
		} PACK type_u;
		struct {
			UINT8 num_snd_x2;
			UINT8 num_rcv_x2;
		} PACK type_i;
		struct {
			UINT8 control;
			UINT8 num_rcv_x2;
		} PACK type_s;
		struct {
			UINT8 control;
			/*
			 * We cannot put the following fields in a structure because
			 * the structure rounding might cause padding.
			 */
			UINT8 frmr_rej_pdu0;
			UINT8 frmr_rej_pdu1;
			UINT8 frmr_control;
			UINT8 frmr_control_ext;
			UINT8 frmr_cause;
		} PACK type_frmr;
		struct {
			UINT8 control;
			UINT8 org_code[3];
			UINT16 ether_type;
		} PACK type_snap;
		struct {
			UINT8 control;
			UINT8 control_ext;
		} PACK type_raw;
	} llc_un /* XXX PACK ??? */ ;
} PACK;
#define LLC_SNAP_LSAP   0xaa
#define LLC_UI          0x03

struct llc_rptr {
	struct llc llc;
	struct ether_header eh;
} PACK;

#define RPTR_ETHERTYPE  0x0003

#ifdef MPRXY
#define IS_IN_CLASSD(a)         ((((UINT32)(a)) & 0xf0000000) == 0xe0000000)
#define IS_IN_MULTICAST(a)              IS_IN_CLASSD(a)
#endif

#define IPQUAD(addr) \
	((unsigned char*)&addr)[3], \
	((unsigned char*)&addr)[2], \
	((unsigned char*)&addr)[1], \
	((unsigned char*)&addr)[0]

#define DECRYPT_ERR_MASK        0x80
#define GENERAL_DECRYPT_ERR     0xFF
#define TKIP_DECRYPT_MIC_ERR    0x02
#define WEP_DECRYPT_ICV_ERR     0x04
#define TKIP_DECRYPT_ICV_ERR    0x08

static UINT32 BA_send2host(struct net_device *dev, struct sk_buff *skb,
			   extStaDb_StaInfo_t * pStaInfo, UINT8 tid);

UINT32 dbg_pn_goodCnt[8];
UINT32 dbg_pn_badCnt[8];

typedef struct {
	UINT32 data[8];
} dbg_replay_attack_t;

#define DBG_REPLAY_ATTACK_MAX 32
UINT32 dbg_pn_idx = 0;
dbg_replay_attack_t *pDbgPnRec = NULL;
void
dbg_replay_attack_trace(UINT32 flag, UINT32 data0, UINT32 data1,
			UINT32 data2, UINT32 data3, UINT32 data4,
			UINT32 data5, UINT32 data6)
{
	if (dbg_pn_idx >= DBG_REPLAY_ATTACK_MAX)
		return;

	if (pDbgPnRec == NULL) {
		pDbgPnRec =
			wl_kmalloc(sizeof(dbg_replay_attack_t) *
				   DBG_REPLAY_ATTACK_MAX, GFP_ATOMIC);
	}
	if (pDbgPnRec) {
		pDbgPnRec[dbg_pn_idx].data[0] = flag;
		pDbgPnRec[dbg_pn_idx].data[1] = data0;
		pDbgPnRec[dbg_pn_idx].data[2] = data1;
		pDbgPnRec[dbg_pn_idx].data[3] = data2;
		pDbgPnRec[dbg_pn_idx].data[4] = data3;
		pDbgPnRec[dbg_pn_idx].data[5] = data4;
		pDbgPnRec[dbg_pn_idx].data[6] = data5;
		pDbgPnRec[dbg_pn_idx].data[7] = data6;
		dbg_pn_idx++;
		if (dbg_pn_idx >= DBG_REPLAY_ATTACK_MAX)
			dbg_pn_idx = 0;
		memset((void *)&pDbgPnRec[dbg_pn_idx], 0xff,
		       sizeof(dbg_replay_attack_t));
	}
}

void
dbg_replay_attack_print(void)
{
	int i;

	if (pDbgPnRec == NULL)
		return;

	printk("PN check failed records\n");

	for (i = 0; i < DBG_REPLAY_ATTACK_MAX; i++) {
		printk("flag=%08x   state=%08x   prev=%08x-%08x   curr=%08x-%08x   next=%08x-%08x\n", pDbgPnRec[i].data[0], pDbgPnRec[i].data[1], pDbgPnRec[i].data[2], pDbgPnRec[i].data[3], pDbgPnRec[i].data[4], pDbgPnRec[i].data[5], pDbgPnRec[i].data[6], pDbgPnRec[i].data[7]);
	}
}

static UINT16 EdcaSeqNum[MAX_STNS + 1][MAX_PRI + 1];
#define CurrentFrag(q) (pStaInfo->aggr11n.Frag[q])
#define NextFrag(q) (CurrentFrag(q).status = 0); \
	(CurrentFrag(q).curPosition_p = 0);
#define CurrentRdFrag(q) (pStaInfo->aggr11n.Frag[q])
#define REORDERING

extern void MrvlMICErrorHdl(vmacApInfo_t * vmacSta_p,
			    COUNTER_MEASURE_EVENT event);
extern void macMgmtMlme_UpdatePwrMode(vmacApInfo_t * vmacSta_p,
				      struct ieee80211_frame *Hdr_p,
				      extStaDb_StaInfo_t * pStaInfo);
#ifdef SOC_W906X
extern UINT8 decomposeMBSSID(struct net_device *dev, struct sk_buff *skb,
			     struct sk_buff_head *skbList);
#endif
static int ForwardFrame(struct net_device *dev, struct sk_buff *skb);
static int DeAmsduPck(struct net_device *netdev, struct sk_buff *skb);
static void McastProxyCheck(struct sk_buff *skb);
#ifdef SOC_W906X
int htc_he_find_control_id(IEEEtypes_htcField_t * htc, u8 in_controlid);
#endif
void log_cnt(unsigned char *name, int location);
void start_log(void);
UINT32 BA_flushSequencialData(struct net_device *dev,
			      extStaDb_StaInfo_t * pStaInfo,
			      BA_RX_st * baRxInfo, UINT32 winStartB_BufCnt,
			      rx_queue_t * rq, UINT32 * badPNcnt,
			      UINT32 * passPNcnt, UINT8 tid);
void BA_TimerHdlr(UINT8 * data);

int
send_11n_aggregation_skb(struct net_device *netdev,
			 extStaDb_StaInfo_t * pStaInfo, int force)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
#ifdef SOC_W8964
	unsigned long flags;
#endif
	struct sk_buff *skb = NULL;
	int i;
	int retval = 0;
	static int previous_aggregation_index;

#ifdef SOC_W8964
	SPIN_LOCK_IRQSAVE(&wlpptr->wlpd_p->locks.xmitLock, flags);
#else
	SPIN_LOCK_BH(&wlpptr->wlpd_p->locks.xmitLock);
#endif
#ifdef AGG_QUE
	while ((skb = skb_dequeue(&pStaInfo->aggr11n.txQ)) != NULL) {
		if (wlxmit(netdev, skb, IEEE_TYPE_DATA, pStaInfo, 0, FALSE)) {
			wlpptr->netDevStats.tx_errors++;
			wl_free_skb(skb);
#ifdef SOC_W8964
			SPIN_UNLOCK_IRQRESTORE(&wlpptr->wlpd_p->locks.xmitLock,
					       flags);
#else
			SPIN_UNLOCK_BH(&wlpptr->wlpd_p->locks.xmitLock);
#endif
			return retval;
		} else {
			retval++;
			//wlpptr->netDevStats.tx_bytes += skb->len;
		}
	}
	pStaInfo->aggr11n.queon = 0;
#endif
#ifndef AMSDUOVERAMPDU
	if (force && (CurrentRdFrag(previous_aggregation_index).status == 0))
		pStaInfo->aggr11n.nextpktnoaggr = 1;
#endif
	for (i = 0; i < MAX_AGG_QUE; i++) {
		if (CurrentRdFrag(i).status &&
		    (force ||
		     (jiffies >=
		      (CurrentRdFrag(i).jiffies +
		       HZ /
		       100)
		      /*CurrentRdFrag(i).status == CurrentRdFrag(i).status_pre */
		      ))) {
			previous_aggregation_index = i;

			skb = CurrentRdFrag(i).skb;
			if (SUCCESS ==
			    wlxmit(netdev, skb, IEEE_TYPE_DATA, pStaInfo, 0,
				   FALSE)) {
				retval++;
				wlpptr->netDevStats.tx_bytes += skb->len;
				NextFrag(i);
				if (pStaInfo->aggr11n.start == 0)
					pStaInfo->aggr11n.on = 0;
			}

		}
		CurrentRdFrag(i).status_pre = CurrentRdFrag(i).status;
	}
#ifdef SOC_W8964
	SPIN_UNLOCK_IRQRESTORE(&wlpptr->wlpd_p->locks.xmitLock, flags);
#else
	SPIN_UNLOCK_BH(&wlpptr->wlpd_p->locks.xmitLock);
#endif
	return retval;
}

#define WL_MAX_AMSDU_SIZE_8K 7935
#define WL_MAX_AMSDU_SIZE_4K 3839

#ifdef SOC_W8964
static struct sk_buff *
wlan_skbhdr_adjust(struct sk_buff *skb)
{
	struct sk_buff *tmp = skb;

	int need_headroom = sizeof(struct ieee80211_qosframe)
		+ sizeof(struct ether_header)
		+ 14;		// maximum (NBR_BYTES_ADD_TXFWINFO+wep_padding-qos_padding) is 14

	//int need_tailroom = 0;

	skb = skb_unshare(skb, GFP_ATOMIC);

	if (skb == NULL) {
		WLDBG_ERROR(DBG_LEVEL_9, "SKB unshare operation failed!\n");
		wl_free_skb(tmp);
	} else if (skb_headroom(skb) < need_headroom) {
		tmp = skb_realloc_headroom(skb, need_headroom);
		wl_free_skb(skb);

		if (tmp == NULL) {
			WLDBG_ERROR(DBG_LEVEL_9,
				    "SKB headroom not enough --- reallocate headroom!\n");
		}
		skb = tmp;
	}
	return skb;
}
#endif //SOC_W8964

#ifdef SC_PALLADIUM
#define ADDBA_PERIOD_1SEC 100	/* Increase timeout for Palladium */
#else
#define ADDBA_PERIOD_1SEC 10
#endif
static inline void enableAmpduTx(vmacApInfo_t * vmacSta_p, UINT8 * macaddr,
				 UINT8 tid);
void
AddbaTimerProcess(UINT8 * data)
{
	Ampdu_tx_t *Ampdu_p = (Ampdu_tx_t *) data;
	vmacApInfo_t *vmacSta_p = (vmacApInfo_t *) Ampdu_p->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
	extStaDb_StaInfo_t *pStaInfo = NULL;

	pStaInfo =
		extStaDb_GetStaInfo(vmacSta_p,
				    (IEEEtypes_MacAddr_t *) & (Ampdu_p->
							       MacAddr),
				    STADB_UPDATE_AGINGTIME);
	if (pStaInfo) {
		pStaInfo->aggr11n.onbytid[Ampdu_p->AccessCat] = 0;
		pStaInfo->aggr11n.startbytid[Ampdu_p->AccessCat] = 0;
	}
	Ampdu_p->InUse = 0;
	Ampdu_p->TimeOut = 0;

	switch (*(mib->mib_AmpduTx)) {
	case 2:
		enableAmpduTx(vmacSta_p, (UINT8 *) & (Ampdu_p->MacAddr),
			      Ampdu_p->AccessCat);
		break;
	case 1:
		if (pStaInfo)
			pStaInfo->aggr11n.type &= ~WL_WLAN_TYPE_AMPDU;
		break;
	default:
		break;
	}
}

struct reorder_t {
	struct net_device *dev;
#ifdef SOC_W906X
	extStaDb_StaInfo_t *pStaInfo;
#else
	UINT16 Aid;
#endif
	UINT8 tid;
	UINT16 SeqNo;
};

#ifdef SOC_W8964		//REORDER_2B_REMOVED
#ifdef SOC_W906X
extern void Ampdu_Flush_All_Pck_in_Reorder_queue(struct net_device *dev,
						 extStaDb_StaInfo_t * pStaInfo,
						 u_int8_t Priority);
#else
extern void Ampdu_Flush_All_Pck_in_Reorder_queue(struct net_device *dev,
						 u_int16_t Aid,
						 u_int8_t Priority);
#endif
void
ReorderingTimerProcess(UINT8 * data)
{
	struct reorder_t *ro_p = (struct reorder_t *)data;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, ro_p->dev);

#ifdef SOC_W906X
	Ampdu_Flush_All_Pck_in_Reorder_queue(ro_p->dev, ro_p->pStaInfo,
					     ro_p->tid);
	wlpptr->wlpd_p->AmpduPckReorder[ro_p->pStaInfo->StnId].ReOrdering[ro_p->
									  tid] =
		FALSE;
	wlpptr->wlpd_p->AmpduPckReorder[ro_p->pStaInfo->StnId].CurrentSeqNo[ro_p->tid] = (ro_p->SeqNo + 1) % MAX_AC_SEQNO;  /** assuming next pck **/
#else
	Ampdu_Flush_All_Pck_in_Reorder_queue(ro_p->dev, ro_p->Aid, ro_p->tid);
	wlpptr->wlpd_p->AmpduPckReorder[ro_p->Aid].ReOrdering[ro_p->tid] =
		FALSE;
	wlpptr->wlpd_p->AmpduPckReorder[ro_p->Aid].CurrentSeqNo[ro_p->tid] = (ro_p->SeqNo + 1) % MAX_AC_SEQNO;	/** assuming next pck **/
#endif
#ifdef AMPDU_DEBUG
	printk("reordering timer timeout at %d\n", (int)jiffies);
#endif
	wl_kfree(data);
}
#endif /* SOC_W8964 */

#ifdef CLIENT_SUPPORT
void
AddbaTimerProcessSta(UINT8 * data)
{
	Ampdu_tx_t *Ampdu_p = (Ampdu_tx_t *) data;
	vmacApInfo_t *vmacSta_p = (vmacApInfo_t *) Ampdu_p->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
	struct wlprivate *wlpptr =
		NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev);
	vmacEntry_t *vmacEntry_p = (vmacEntry_t *) wlpptr->clntParent_priv_p;
	extStaDb_StaInfo_t *pStaInfo = NULL;

	pStaInfo =
		extStaDb_GetStaInfo(vmacSta_p,
				    (IEEEtypes_MacAddr_t *)
				    GetParentStaBSSID(vmacEntry_p->
						      phyHwMacIndx),
				    STADB_UPDATE_AGINGTIME);
	if (pStaInfo) {
		pStaInfo->aggr11n.onbytid[Ampdu_p->AccessCat] = 0;
		pStaInfo->aggr11n.startbytid[Ampdu_p->AccessCat] = 0;
	}
	Ampdu_p->InUse = 0;
	Ampdu_p->TimeOut = 0;

	switch (*(mib->mib_AmpduTx)) {
	case 2:
		enableAmpduTx(vmacSta_p, (UINT8 *) & (Ampdu_p->MacAddr),
			      Ampdu_p->AccessCat);
		break;
	case 1:
		if (pStaInfo)
			pStaInfo->aggr11n.type &= ~WL_WLAN_TYPE_AMPDU;
		break;
	default:
		break;
	}
}
#endif

#define AMPDU_STREAM_NO_START  0
#define AMPDU_STREAM_NO_END    MAX_SUPPORT_AMPDU_TX_STREAM_RUNNING

#ifdef DYNAMIC_BA_SUPPORT
typedef struct mwlbainfo {
	UINT32 flag;
	UINT32 pps;
	Ampdu_tx_t *sp;
	UINT8 tid;
} mwlbainfo;

#define MAX_SECS_TO_RESET_PPS 5
/*
 * Traffic estimator support.  We estimate packets/sec for
 * each AC that is setup for AMPDU or will potentially be
 * setup for AMPDU.  The traffic rate can be used to decide
 * when AMPDU should be setup (according to a threshold)
 * and is available for drivers to do things like cache
 * eviction when only a limited number of BA streams are
 * available and more streams are requested than available.
 */

static void __inline
ieee80211_txampdu_update_pps(Ampdu_tx_t * tap)
{
	/* NB: scale factor of 2 was picked heuristically */
	tap->txa_avgpps = (((tap->txa_avgpps << 2) - tap->txa_avgpps + (tap->txa_pkts * 10)) >> 2);	//Multiply 10 to get avgpps per sec, in sync with ieee80211_txampdu_count_packet

}

/*
 * Count a packet towards the pps estimate.
 */
void __inline
ieee80211_txampdu_count_packet(Ampdu_tx_t * tap)
{
	if (jiffies - tap->txa_lastsample >= MAX_SECS_TO_RESET_PPS * HZ) {
		tap->txa_pkts = 1;
		tap->txa_avgpps = 0;
		tap->txa_lastsample = jiffies;
		return;
	}
	/* XXX bound loop/do more crude estimate? */
	while (jiffies - tap->txa_lastsample >= (HZ / 10)) {	//Make avgpps updated every 0.1sec
		ieee80211_txampdu_update_pps(tap);
		/* reset to start new sample interval */
		tap->txa_pkts = 0;
		if (tap->txa_avgpps == 0) {
			tap->txa_lastsample = jiffies;
			break;
		} else
			tap->txa_lastsample += (HZ / 10);
	}
	tap->txa_pkts++;
}

static void __inline
tx_update_pps(txACInfo * tap)
{
	/* NB: scale factor of 2 was picked heuristically */
	tap->txa_avgpps = (((tap->txa_avgpps << 2) - tap->txa_avgpps + (tap->txa_pkts * 10)) >> 2);	//Multiply 10 to get avgpps per sec, in sync with tx_count_packet
}

/*
 * Count a packet towards the pps estimate.
 */
void __inline
tx_count_packet(txACInfo * tap)
{
	if (jiffies - tap->txa_lastsample >= MAX_SECS_TO_RESET_PPS * HZ) {
		tap->txa_pkts = 1;
		tap->txa_avgpps = 0;
		tap->txa_lastsample = jiffies;
		return;
	}
	/* XXX bound loop/do more crude estimate? */
	while (jiffies - tap->txa_lastsample >= (HZ / 10)) {	//Make avgpps updated every 0.1sec
		tx_update_pps(tap);
		/* reset to start new sample interval */
		tap->txa_pkts = 0;
		if (tap->txa_avgpps == 0) {
			tap->txa_lastsample = jiffies;
			break;
		} else
			tap->txa_lastsample += (HZ / 10);
	}
	tap->txa_pkts++;
}

/*
 * Get the current pps estimate.  If the average is out of
 * date due to lack of traffic then we decay the estimate
 * to account for the idle time.
 */
static int __inline
ieee80211_txampdu_getpps(Ampdu_tx_t * tap)
{
	if (jiffies - tap->txa_lastsample >= MAX_SECS_TO_RESET_PPS * HZ) {
		tap->txa_avgpps = 0;
		tap->txa_lastsample = jiffies;
		return 0;
	}
	/* XXX bound loop/do more crude estimate? */
	while (jiffies - tap->txa_lastsample >= (HZ / 10)) {	//Make avgpps updated every 0.1sec
		ieee80211_txampdu_update_pps(tap);
		tap->txa_pkts = 0;
		if (tap->txa_avgpps == 0) {
			tap->txa_lastsample = jiffies;
			break;
		} else
			tap->txa_lastsample += (HZ / 10);
	}
	return tap->txa_avgpps;
}
#endif

/** Auto Addba function **/
static inline void
enableAmpduTx(vmacApInfo_t * vmacSta_p, UINT8 * macaddr, UINT8 tid)
{
	struct wlprivate *wlpptr =
		NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev);
	extStaDb_StaInfo_t *pStaInfo = NULL;
	int stream = -1;
	UINT8 *ampduMacAddr = macaddr;

#ifdef CLIENT_SUPPORT
	UINT8 AssociatedFlag = 0;
	UINT8 bssId[6];
#endif
#ifdef DYNAMIC_BA_SUPPORT
	SINT32 i;
#ifdef SOC_W8964
	MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
#endif
#if 0				//unused code
	UINT32 ac;

	/*To convert TID value to priority in ascending order. To be used in finding victim stream */
	/*Currently we treat BE TID0 and TID3 same. We can adjust this in future */
	/*TID1(BK)==0, TID0(BE)==1, TID4(VI)==2 and etc respectively */
	UINT8 tidpriority[MAX_TID] = { 1, 0, 0, 1, 2, 2, 3, 3 };

	UINT8 found_stream = 0;
	UINT8 victim_stream;
	Ampdu_tx_t *sp;

	mwlbainfo mwl_bainfo[MAX_TID];
#endif
#endif

#ifdef SOC_W8964
	if (*(mib->disable_aggr_for_vo) && (tid == 6 || tid == 7))
#else
	if (tid == 6 || tid == 7)	//VOICE traffic, no ampdu
#endif
		return;
	pStaInfo =
		extStaDb_GetStaInfo(vmacSta_p, (IEEEtypes_MacAddr_t *) macaddr,
				    STADB_DONT_UPDATE_AGINGTIME);

#ifdef AMPDU_SUPPORT_TX_CLIENT
	if (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_CLNT_INFRA) {
		if (!smeGetStaLinkInfo(vmacSta_p->VMacEntry.id,
				       &AssociatedFlag, &bssId[0])) {
			return;
		}
		if (AssociatedFlag) {
			ampduMacAddr = &bssId[0];
		} else
			return;
	}
#endif

#ifndef AMPDU_SUPPORT_SBA
	// 1. check if any stream are available
	// 2. if available continue, continue to addstream as per normal
	// 3. else, check if current tid is higer than any of current stream in use,
	// 4. if true, delete the current lower tid stream, wait ~ 3 second, before adding stream

	if (wlpptr->wlpd_p->Ampdu_tx[0].InUse && wlpptr->wlpd_p->Ampdu_tx[1].InUse) {  /** both stream are in use **/
		/** step 2 here **/
		if ((AccCategoryQ[tid] >
		     AccCategoryQ[wlpptr->wlpd_p->Ampdu_tx[0].AccessCat]) ||
		    (AccCategoryQ[tid] >
		     AccCategoryQ[wlpptr->wlpd_p->Ampdu_tx[1].AccessCat])) {

			//for stream 0
			if (AccCategoryQ[wlpptr->wlpd_p->Ampdu_tx[0].AccessCat]
			    <=
			    AccCategoryQ[wlpptr->wlpd_p->Ampdu_tx[1].
					 AccessCat]) {
				/** send delba for stream 0 **/
				if ((wlpptr->wlpd_p->Ampdu_tx[0].TimeOut != 0)
				    && (jiffies >
					wlpptr->wlpd_p->Ampdu_tx[0].TimeOut)) {
					//printk("TimeOut Occur for stream 0!!!!!!!!!!\n");
					wlpptr->wlpd_p->Ampdu_tx[0].TimeOut = 0;
					wlpptr->wlpd_p->Ampdu_tx[0].InUse = 0;
				} else {
					if (wlpptr->wlpd_p->Ampdu_tx[0].
					    TimeOut == 0 &&
					    wlpptr->wlpd_p->Ampdu_tx[1].
					    TimeOut == 0) {
						//      printk("Inside 2 value of 0 = %d va 1 = %d\n",AccCategoryQ[Ampdu_tx[0].AccessCat],AccCategoryQ[Ampdu_tx[1].AccessCat]);
						wlpptr->wlpd_p->Ampdu_tx[0].
							TimeOut = jiffies + 300;
#ifdef AMPDU_SUPPORT_TX_CLIENT
						if (vmacSta_p->VMacEntry.
						    modeOfService ==
						    VMAC_MODE_CLNT_INFRA)
							SendDelBASta(vmacSta_p,
								     (UINT8 *) &
								     wlpptr->
								     wlpd_p->
								     Ampdu_tx
								     [0].
								     MacAddr[0],
								     wlpptr->
								     wlpd_p->
								     Ampdu_tx
								     [0].
								     AccessCat);
						else
#endif
							SendDelBA(vmacSta_p,
								  (UINT8 *) &
								  wlpptr->
								  wlpd_p->
								  Ampdu_tx[0].
								  MacAddr[0],
								  wlpptr->
								  wlpd_p->
								  Ampdu_tx[0].
								  AccessCat);
						wlFwUpdateDestroyBAStream
							(vmacSta_p->dev, 0, 0,
							 0,
							 wlpptr->wlpd_p->
							 Ampdu_tx[0].AccessCat,
							 wlpptr->wlpd_p->
							 Ampdu_tx[0].MacAddr,
							 pStaInfo ? pStaInfo->
							 StnId : 0);
						if (pStaInfo) {
							pStaInfo->aggr11n.
								onbytid[tid] =
								0;
							pStaInfo->aggr11n.
								startbytid[tid]
								= 0;
							pStaInfo->aggr11n.
								type &=
								~WL_WLAN_TYPE_AMPDU;
						}
					}
				}
			} else {
				if ((wlpptr->wlpd_p->Ampdu_tx[1].TimeOut != 0)
				    && (jiffies >
					wlpptr->wlpd_p->Ampdu_tx[1].TimeOut)) {

					//      printk("TimeOut Occur for stream 1!!!!!!!!!!\n");
					wlpptr->wlpd_p->Ampdu_tx[1].TimeOut = 0;
					wlpptr->wlpd_p->Ampdu_tx[1].InUse = 0;
				} else {
					if (wlpptr->wlpd_p->Ampdu_tx[1].
					    TimeOut == 0 &&
					    wlpptr->wlpd_p->Ampdu_tx[1].
					    TimeOut == 0) {
						//      printk("Inside 2 value of 0 = %d va 1 = %d\n",AccCategoryQ[Ampdu_tx[0].AccessCat],AccCategoryQ[Ampdu_tx[1].AccessCat]);
						wlpptr->wlpd_p->Ampdu_tx[1].
							TimeOut = jiffies + 300;
#ifdef AMPDU_SUPPORT_TX_CLIENT
						if (vmacSta_p->VMacEntry.
						    modeOfService ==
						    VMAC_MODE_CLNT_INFRA)
							SendDelBASta(vmacSta_p,
								     (UINT8 *) &
								     wlpptr->
								     wlpd_p->
								     Ampdu_tx
								     [1].
								     MacAddr[0],
								     wlpptr->
								     wlpd_p->
								     Ampdu_tx
								     [1].
								     AccessCat);
						else
#endif
							SendDelBA(vmacSta_p,
								  (UINT8 *) &
								  wlpptr->
								  wlpd_p->
								  Ampdu_tx[1].
								  MacAddr[0],
								  wlpptr->
								  wlpd_p->
								  Ampdu_tx[1].
								  AccessCat);
						wlFwUpdateDestroyBAStream
							(vmacSta_p->dev, 0, 0,
							 1,
							 wlpptr->wlpd_p->
							 Ampdu_tx[1].AccessCat,
							 wlpptr->wlpd_p->
							 Ampdu_tx[1].MacAddr,
							 pStaInfo ? pStaInfo->
							 StnId : 0);
						if (pStaInfo) {
							pStaInfo->aggr11n.
								onbytid[tid] =
								0;
							pStaInfo->aggr11n.
								startbytid[tid]
								= 0;
							pStaInfo->aggr11n.
								type &=
								~WL_WLAN_TYPE_AMPDU;
						}
					}
				}
			}

		}
	}
#endif /* _AMPDU_SUPPORT_SBA */
#ifdef DYNAMIC_BA_SUPPORT
	/* Find Available Stream;
	   also Allocate S/W BA stream for AC_BK traffic first */
	if (TID_TO_WME_AC(tid) == WME_AC_BK) {
		for (i = (AMPDU_STREAM_NO_END - 1); i >= 0; i--) {
			if (wlpptr->wlpd_p->Ampdu_tx[i].InUse != 1) {
				stream = i;
				break;
			}
		}
	} else {
		for (i = 0; i < AMPDU_STREAM_NO_END; i++) {
			if (wlpptr->wlpd_p->Ampdu_tx[i].InUse != 1) {
				stream = i;
				break;
			}
		}
	}

	//klocwork
	if (stream == -1)
		return;

#if 0				//unused code.
	if (stream == -1) {
		/*
		 * No available stream, return 0 so no
		 * a-mpdu aggregation will be done.
		 */
		if (!(*(mib->mib_ampdu_bamgmt))) {
			return;
		} else {
			/*
			 * Check stats of current AMPDU streams to see whether it is possible to tear
			 * down an existing stream with low activities
			 */
			memset(mwl_bainfo, 0, sizeof(mwl_bainfo));

			for (i = 0; i < AMPDU_STREAM_NO_END; i++) {
				Ampdu_tx_t *t;
				t = &wlpptr->wlpd_p->Ampdu_tx[i];

				if (t->InUse != 1)
					continue;

				if ((t->ReleaseTimestamp > 0) &&
				    (jiffies - (t->ReleaseTimestamp)) >
				    5 * HZ) {
					mwl_bainfo[i].flag = 1;
					mwl_bainfo[i].sp = t;
					mwl_bainfo[i].pps =
						ieee80211_txampdu_getpps(t);
					mwl_bainfo[i].tid = t->AccessCat;
				}

				/*Find a victim stream to be evicted based on tid priority and pps in current AMPDU tcqs that are running > 5sec */
				/*We only consider streams that are well established and not keep deleting stream, thus >5sec criteria */
				/*As we go thru stream by stream, we make decision whether to use current or victim stream */

				/*We compare current tid priority with victim tid priority. 3 cases: current tid priority lower, higher or same */
				if (!found_stream) {	/*Assign first victim having flag==1. This victim is used later for comparison */
					if (mwl_bainfo[i].flag) {
						victim_stream = i;
						found_stream = 1;
						continue;
					}
				} else {
					/*One victim stream is found, compare curent with victim here */
					if (mwl_bainfo[i].flag) {
						if (tidpriority
						    [mwl_bainfo[i].tid] <
						    tidpriority[mwl_bainfo
								[victim_stream].
								tid]) {
							/*If victim stream has higher priority but pps==0, we use same victim stream */
							/*Otherwise, we use current stream with lower tid priority */
							if ((mwl_bainfo[i].
							     pps != 0) &&
							    (mwl_bainfo
							     [victim_stream].
							     pps == 0))
								continue;
							else
								victim_stream =
									i;
						} else if (tidpriority
							   [mwl_bainfo[i].tid] >
							   tidpriority
							   [mwl_bainfo
							    [victim_stream].
							    tid]) {
							/*If current stream has higher priority but pps==0, we use same current stream */
							/*Otherwise, we use victim stream with lower tid priority */
							if ((mwl_bainfo[i].
							     pps == 0) &&
							    (mwl_bainfo
							     [victim_stream].
							     pps != 0))
								victim_stream =
									i;
							else
								continue;
						} else if (tidpriority
							   [mwl_bainfo[i].
							    tid] ==
							   tidpriority
							   [mwl_bainfo
							    [victim_stream].
							    tid]) {
							/*If current stream same priority but lower or same pps than victim stream, we use current stream */
							/*Otherwise, we use victim stream */
							if (mwl_bainfo[i].pps <=
							    mwl_bainfo
							    [victim_stream].pps)
								victim_stream =
									i;
							else
								continue;
						}

					}
				}
			}

			sp = NULL;

			/*After found a victim stream, we have to compare incoming tid, then pps to make sure we don't simply evict */
			/*All running streams should have highest tid that have non-zero pps */

			if (!found_stream)
				return;
			else {
				ac = TID_TO_WME_AC(mwl_bainfo[victim_stream].
						   tid);

				/*Always evict victim when incoming stream has higher tid priority */
				if ((tidpriority[mwl_bainfo[victim_stream].tid])
				    < tidpriority[tid])
					sp = mwl_bainfo[victim_stream].sp;
				else if ((tidpriority
					  [mwl_bainfo[victim_stream].tid]) >
					 tidpriority[tid]) {
					/*If victim stream has higher tid priority than incoming but pps ==0, evict victim */
					/*We don't keep higher tid priority with pps==0 */
					if (mwl_bainfo[victim_stream].pps <
					    *(mib->
					      mib_ampdu_low_AC_thres[ac])) {
						if ((mwl_bainfo[victim_stream].
						     pps == 0))
							sp = mwl_bainfo
								[victim_stream].
								sp;
						else
							return;
					} else
						return;
				} else if ((tidpriority
					    [mwl_bainfo[victim_stream].tid]) ==
					   tidpriority[tid]) {
					/*If victim stream has same tid priority as incoming but pps==0, evict victim */
					/*To minimize impact on running traffic, we don't del if victim pps < incoming pps */
					if (mwl_bainfo[victim_stream].pps <
					    *(mib->
					      mib_ampdu_low_AC_thres[ac])) {
						if ((mwl_bainfo[victim_stream].
						     pps == 0))
							sp = mwl_bainfo
								[victim_stream].
								sp;
						else
							return;
					} else
						return;
				}
			}

			/* Cannot tear down existing stream. We simply run out of AMPDU streams! */
			if (sp == NULL)
				return;

			/* Evicts the unlucky one */
			sp->ReleaseTimestamp = jiffies;
			disableAmpduTx(vmacSta_p, &sp->MacAddr[0],
				       sp->AccessCat);
			return;
			/*
			 * Cannot reclaim the just released stream
			 * right here since FW needs some time to clean it up.
			 * So let  retries to takes care of it.
			 */
		}
	}
#endif //0

	/* Stream Allocated prepare rest of the information on the stream */
#else
	for (stream = AMPDU_STREAM_NO_START; stream < AMPDU_STREAM_NO_END;
	     stream++)
#endif
		if (wlpptr->wlpd_p->Ampdu_tx[stream].InUse != 1) {
			wlpptr->wlpd_p->Ampdu_tx[stream].MacAddr[0] =
				ampduMacAddr[0];
			wlpptr->wlpd_p->Ampdu_tx[stream].MacAddr[1] =
				ampduMacAddr[1];
			wlpptr->wlpd_p->Ampdu_tx[stream].MacAddr[2] =
				ampduMacAddr[2];
			wlpptr->wlpd_p->Ampdu_tx[stream].MacAddr[3] =
				ampduMacAddr[3];
			wlpptr->wlpd_p->Ampdu_tx[stream].MacAddr[4] =
				ampduMacAddr[4];
			wlpptr->wlpd_p->Ampdu_tx[stream].MacAddr[5] =
				ampduMacAddr[5];
			wlpptr->wlpd_p->Ampdu_tx[stream].AccessCat = tid;
			wlpptr->wlpd_p->Ampdu_tx[stream].InUse = 1;
			wlpptr->wlpd_p->Ampdu_tx[stream].TimeOut = 0;
			wlpptr->wlpd_p->Ampdu_tx[stream].AddBaResponseReceive =
				0;
			wlpptr->wlpd_p->Ampdu_tx[stream].ReleaseTimestamp =
				jiffies;
			wlpptr->wlpd_p->Ampdu_tx[stream].DialogToken =
				wlpptr->wlpd_p->Global_DialogToken;
			wlpptr->wlpd_p->Global_DialogToken =
				(wlpptr->wlpd_p->Global_DialogToken + 1) % 63;
#ifdef DYNAMIC_BA_SUPPORT
			wlpptr->wlpd_p->Ampdu_tx[stream].txa_ac =
				TID_TO_WME_AC(tid);
#endif
			if (wlpptr->wlpd_p->Ampdu_tx[stream].initTimer == 0) {
				TimerInit(&wlpptr->wlpd_p->Ampdu_tx[stream].
					  timer);
				wlpptr->wlpd_p->Ampdu_tx[stream].initTimer = 1;
			}
			TimerDisarm(&wlpptr->wlpd_p->Ampdu_tx[stream].timer);
			wlpptr->wlpd_p->Ampdu_tx[stream].vmacSta_p = vmacSta_p;
			wlFwGetSeqNoBAStream(vmacSta_p->dev, macaddr, tid,
					     (UINT16 *) & (wlpptr->wlpd_p->
							   Ampdu_tx[stream].
							   start_seqno));

#ifdef AMPDU_SUPPORT_TX_CLIENT
			if (vmacSta_p->VMacEntry.modeOfService ==
			    VMAC_MODE_CLNT_INFRA) {
				TimerFireIn(&wlpptr->wlpd_p->Ampdu_tx[stream].
					    timer, 1, &AddbaTimerProcessSta,
					    (UINT8 *) & wlpptr->wlpd_p->
					    Ampdu_tx[stream],
					    ADDBA_PERIOD_1SEC);
				SendAddBAReqSta(vmacSta_p, macaddr, tid, 1,
						wlpptr->wlpd_p->
						Ampdu_tx[stream].start_seqno,
						wlpptr->wlpd_p->
						Ampdu_tx[stream].DialogToken);
			} else
#endif
			{
				TimerFireIn(&wlpptr->wlpd_p->Ampdu_tx[stream].
					    timer, 1, &AddbaTimerProcess,
					    (UINT8 *) & wlpptr->wlpd_p->
					    Ampdu_tx[stream],
					    ADDBA_PERIOD_1SEC);
				SendAddBAReq(vmacSta_p, macaddr, tid, 1, wlpptr->wlpd_p->Ampdu_tx[stream].start_seqno, wlpptr->wlpd_p->Ampdu_tx[stream].DialogToken);/** Only support immediate ba **/
			}
			if (pStaInfo) {
				pStaInfo->aggr11n.type |= WL_WLAN_TYPE_AMPDU;
				pStaInfo->aggr11n.startbytid[tid] = 1;
			}

			return;
		}
}

void
disableAmpduTxMacAddr(vmacApInfo_t * vmacSta_p, UINT8 * macaddr)
{
	struct wlprivate *wlpptr =
		NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev);
	extStaDb_StaInfo_t *pStaInfo = NULL;
	int i, j, tid;
	UINT8 *ampduMacAddr = macaddr;

#ifdef CLIENT_SUPPORT
	UINT8 AssociatedFlag = 0;
	UINT8 bssId[6];
#endif
	pStaInfo =
		extStaDb_GetStaInfo(vmacSta_p, (IEEEtypes_MacAddr_t *) macaddr,
				    STADB_DONT_UPDATE_AGINGTIME);
#ifdef AMPDU_SUPPORT_TX_CLIENT
	if (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_CLNT_INFRA) {
		if (!smeGetStaLinkInfo(vmacSta_p->VMacEntry.id,
				       &AssociatedFlag, &bssId[0])) {
			return;
		}
		if (AssociatedFlag) {
			ampduMacAddr = &bssId[0];
		} else
			return;
	}
#endif

	for (i = AMPDU_STREAM_NO_START; i < AMPDU_STREAM_NO_END; i++) {
		//if(wlpptr->wlpd_p->Ampdu_tx[i].InUse == 1)
		{
			if (!MACADDR_CMP
			    (wlpptr->wlpd_p->Ampdu_tx[i].MacAddr,
			     ampduMacAddr)) {
				tid = wlpptr->wlpd_p->Ampdu_tx[i].AccessCat;
				wlpptr->wlpd_p->Ampdu_tx[i].InUse = 0;
				wlpptr->wlpd_p->Ampdu_tx[i].TimeOut = 0;
#ifdef AMPDU_SUPPORT_TX_CLIENT
				if (vmacSta_p->VMacEntry.modeOfService ==
				    VMAC_MODE_CLNT_INFRA)
					SendDelBASta(vmacSta_p, ampduMacAddr,
						     tid);
				else
#endif
					SendDelBA(vmacSta_p, ampduMacAddr, tid);
				wlFwUpdateDestroyBAStream(vmacSta_p->dev, 0, 0,
							  i, tid,
							  wlpptr->wlpd_p->
							  Ampdu_tx[i].MacAddr,
							  pStaInfo ? pStaInfo->
							  StnId : 0);
				if (pStaInfo) {
					pStaInfo->aggr11n.onbytid[tid] = 0;
					pStaInfo->aggr11n.startbytid[tid] = 0;
					pStaInfo->aggr11n.type &=
						~WL_WLAN_TYPE_AMPDU;
				}
				for (j = 0; j < 6; j++) {
					wlpptr->wlpd_p->Ampdu_tx[i].MacAddr[j] =
						0;
				}
				return;
			}
		}
	}
}

void
disableAmpduTx(vmacApInfo_t * vmacSta_p, UINT8 * macaddr, UINT8 tid)
{
	struct wlprivate *wlpptr =
		NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev);
	extStaDb_StaInfo_t *pStaInfo = NULL;
	int i, j;
	UINT8 *ampduMacAddr = macaddr;

#ifdef CLIENT_SUPPORT
	UINT8 AssociatedFlag = 0;
	UINT8 bssId[6];
#endif
	pStaInfo =
		extStaDb_GetStaInfo(vmacSta_p, (IEEEtypes_MacAddr_t *) macaddr,
				    STADB_DONT_UPDATE_AGINGTIME);
#ifdef AMPDU_SUPPORT_TX_CLIENT
	if (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_CLNT_INFRA) {
		if (!smeGetStaLinkInfo(vmacSta_p->VMacEntry.id,
				       &AssociatedFlag, &bssId[0])) {
			return;
		}
		if (AssociatedFlag) {
			ampduMacAddr = &bssId[0];
		} else
			return;
	}
#endif

	for (i = AMPDU_STREAM_NO_START; i < AMPDU_STREAM_NO_END; i++) {
		//if(wlpptr->wlpd_p->Ampdu_tx[i].InUse == 1)
		{
			if (!MACADDR_CMP
			    (wlpptr->wlpd_p->Ampdu_tx[i].MacAddr,
			     ampduMacAddr)) {
				/** they are equal **/
				if (wlpptr->wlpd_p->Ampdu_tx[i].AccessCat ==
				    tid
				    /*&& wlpptr->wlpd_p->Ampdu_tx[i].InUse==1 */
				    ) {
					wlpptr->wlpd_p->Ampdu_tx[i].InUse = 0;
					wlpptr->wlpd_p->Ampdu_tx[i].TimeOut = 0;
#ifdef AMPDU_SUPPORT_TX_CLIENT
					if (vmacSta_p->VMacEntry.
					    modeOfService ==
					    VMAC_MODE_CLNT_INFRA)
						SendDelBASta(vmacSta_p,
							     ampduMacAddr, tid);
					else
#endif
						SendDelBA(vmacSta_p,
							  ampduMacAddr, tid);
					wlFwUpdateDestroyBAStream(vmacSta_p->
								  dev, 0, 0, i,
								  tid,
								  wlpptr->
								  wlpd_p->
								  Ampdu_tx[i].
								  MacAddr,
								  pStaInfo ?
								  pStaInfo->
								  StnId : 0);
					if (pStaInfo) {
						pStaInfo->aggr11n.onbytid[tid] =
							0;
						pStaInfo->aggr11n.
							startbytid[tid] = 0;
						pStaInfo->aggr11n.type &=
							~WL_WLAN_TYPE_AMPDU;
					}
					for (j = 0; j < 6; j++) {
						wlpptr->wlpd_p->Ampdu_tx[i].
							MacAddr[j] = 0;

					}
					return;
				}
			}
		}
	}
}

void
cleanupAmpduTx(vmacApInfo_t * vmacSta_p, UINT8 * macaddr)
{
	int i;

	for (i = 0; i <= 7; i++)
		disableAmpduTx(vmacSta_p, macaddr, i);
}

void
disableAmpduTxAll(vmacApInfo_t * vmacSta_p)
{
	int i, j;
	struct wlprivate *wlpptr =
		NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev);
	extStaDb_StaInfo_t *pStaInfo = NULL;

	for (i = AMPDU_STREAM_NO_START; i < AMPDU_STREAM_NO_END; i++) {
		if (wlpptr->wlpd_p->Ampdu_tx[i].InUse == 1) {
			/** they are equal **/
			//      printk("They match in delba stream = %d!!!!tid==%d\n",i, tid);

			pStaInfo =
				extStaDb_GetStaInfo(wlpptr->wlpd_p->Ampdu_tx[i].
						    vmacSta_p,
						    (IEEEtypes_MacAddr_t *) &
						    wlpptr->wlpd_p->Ampdu_tx[i].
						    MacAddr[0],
						    STADB_DONT_UPDATE_AGINGTIME);

			SendDelBA(wlpptr->wlpd_p->Ampdu_tx[i].vmacSta_p,
				  wlpptr->wlpd_p->Ampdu_tx[i].MacAddr,
				  wlpptr->wlpd_p->Ampdu_tx[i].AccessCat);
			wlFwUpdateDestroyBAStream(wlpptr->wlpd_p->Ampdu_tx[i].
						  vmacSta_p->dev, 0, 0, i,
						  wlpptr->wlpd_p->Ampdu_tx[i].
						  AccessCat,
						  wlpptr->wlpd_p->Ampdu_tx[i].
						  MacAddr,
						  pStaInfo ? pStaInfo->
						  StnId : 0);
			wlpptr->wlpd_p->Ampdu_tx[i].InUse = 0;
			wlpptr->wlpd_p->Ampdu_tx[i].TimeOut = 0;

			if (pStaInfo) {
				pStaInfo->aggr11n.type &= ~WL_WLAN_TYPE_AMPDU;
				pStaInfo->aggr11n.startbytid[wlpptr->wlpd_p->
							     Ampdu_tx[i].
							     AccessCat] = 0;

			}

			for (j = 0; j < 6; j++) {
				wlpptr->wlpd_p->Ampdu_tx[i].MacAddr[j] = 0;
			}
		}
	}
}

void
disableAmpduTxstream(vmacApInfo_t * vmacSta_p, int stream)
{
	extStaDb_StaInfo_t *pStaInfo = NULL;
	struct wlprivate *wlpptr =
		NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev);

	if (wlpptr->wlpd_p->Ampdu_tx[stream].InUse == 1) {
		/** they are equal **/
		//      printk("They match in delba stream = %d!!!!tid==%d\n",i, tid);
		int j;

		pStaInfo =
			extStaDb_GetStaInfo(wlpptr->wlpd_p->Ampdu_tx[stream].
					    vmacSta_p,
					    (IEEEtypes_MacAddr_t *) & wlpptr->
					    wlpd_p->Ampdu_tx[stream].MacAddr[0],
					    STADB_DONT_UPDATE_AGINGTIME);

		SendDelBA(wlpptr->wlpd_p->Ampdu_tx[stream].vmacSta_p,
			  wlpptr->wlpd_p->Ampdu_tx[stream].MacAddr,
			  wlpptr->wlpd_p->Ampdu_tx[stream].AccessCat);
		wlFwUpdateDestroyBAStream(wlpptr->wlpd_p->Ampdu_tx[stream].
					  vmacSta_p->dev, 0, 0, stream,
					  wlpptr->wlpd_p->Ampdu_tx[stream].
					  AccessCat,
					  wlpptr->wlpd_p->Ampdu_tx[stream].
					  MacAddr,
					  pStaInfo ? pStaInfo->StnId : 0);

		wlpptr->wlpd_p->Ampdu_tx[stream].InUse = 0;
		wlpptr->wlpd_p->Ampdu_tx[stream].TimeOut = 0;

		if (pStaInfo) {
			pStaInfo->aggr11n.type &= ~WL_WLAN_TYPE_AMPDU;
			pStaInfo->aggr11n.startbytid[wlpptr->wlpd_p->
						     Ampdu_tx[stream].
						     AccessCat] = 0;

		}
		for (j = 0; j < 6; j++) {
			wlpptr->wlpd_p->Ampdu_tx[stream].MacAddr[j] = 0;
		}
	}
}

#ifdef MULTI_AP_SUPPORT
MultiAP_4Addrr_Table_t fourAddrTable;
MultiAP_4Addrr_Table_t fourAddrTableSTA;
#endif

#ifdef SOC_W906X
struct sk_buff *
ieee80211_encap(struct sk_buff *skb, struct net_device *netdev, BOOLEAN eap,
		void *pStaInfoIn)
#else
struct sk_buff *
ieee80211_encap(struct sk_buff *skb, struct net_device *netdev, BOOLEAN eap)
#endif
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
	struct ether_header eh;
	struct llc *llc;
	struct llc_rptr *llc_rptr = NULL;

#ifndef NEW_DP
	struct ieee80211_qosframe *wh;
#endif
	extStaDb_StaInfo_t *pStaInfo = NULL;
	UINT8 Priority = 0, tid;
	IEEEtypes_QoS_Ctl_t QosControl;
#ifdef CLIENT_SUPPORT
	vmacEntry_t *vmacEntry_p = (vmacEntry_t *) wlpptr->clntParent_priv_p;
	UINT8 AssociatedFlag = 0;
	UINT8 bssId[6];
#endif
	UINT8 *ampduMacAddr = NULL;
#ifdef WDS_FEATURE
	BOOLEAN wds = FALSE;
	struct wds_port *pWdsPort = NULL;
#endif
	eth_StaInfo_t *ethStaInfo_p;
	UINT8 __attribute__ ((unused)) ampdu_ready = 1;
#ifndef STADB_IN_CACHE
	int stadb_flag = STADB_UPDATE_AGINGTIME;
#else
#ifdef SOC_W906X
	int stadb_flag =
		STADB_FIND_IN_CACHE | STADB_UPDATE_CACHE |
		STADB_UPDATE_AGINGTIME | STADB_NO_BLOCK;
#else
	int stadb_flag =
		STADB_FIND_IN_CACHE | STADB_UPDATE_CACHE |
		STADB_UPDATE_AGINGTIME;
#endif
#endif /* STADB_IN_CACHE */
#ifdef SOC_W906X
#ifdef TP_PROFILE
	if (wl_tp_profile_test(5, skb, netdev)) {
		wl_free_skb(skb);
		return 0;
	}
#endif
#endif /* SOC_W906X */
#ifdef RD2_BOARD
	skb_trim(skb, skb->len - 2);
#endif
	//klocwork checking
	if (skb == NULL)
		goto bad;

	tid = Qos_GetDSCPPriority(skb->data);

#ifdef SOC_W8964
	if (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_CLNT_INFRA)
		tid = QosTsData[tid].TidDowngrade;
#endif

	skb->priority = (skb->priority & 0xfffffff8) | (tid & 0x7);

	memcpy(&eh, skb->data, sizeof(struct ether_header));

#ifdef SOC_W8964
	skb_pull(skb, sizeof(struct ether_header));

	skb = wlan_skbhdr_adjust(skb);
	if (skb == NULL) {
		goto bad;
	}
#endif

#ifdef CLIENT_SUPPORT
	if (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_CLNT_INFRA) {
		if (vmacEntry_p == NULL)
			goto bad;
		if (!vmacEntry_p->active) {
			if (*(mib->mib_STAMacCloneEnable) == 1) {
				UINT8 mlmeAssociatedFlag;
				UINT8 mlmeBssid[6];
				struct net_device *dev2;

				/* don't clone if packet (source mac) comes from itself or lan bridge */
				if (memcmp(eh.ether_shost, netdev->dev_addr, 6)
				    == 0) {
					// printk("### Debug %s, source MAC %s is same as %s\n", __func__, mac_display(eh.ether_shost), netdev->name);
					goto bad;
				}
#ifdef SOC_W906X
#ifdef OPENWRT
				if ((dev2 =
				     dev_get_by_name(&init_net,
						     "br-lan")) != NULL) {
#else
				if ((dev2 =
				     dev_get_by_name(&init_net,
						     "br0")) != NULL) {
#endif
					if (memcmp
					    (eh.ether_shost, dev2->dev_addr,
					     6) == 0) {
#else
				rcu_read_lock();
				for_each_netdev_rcu(&init_net, dev2) {
					if (dev2->priv_flags & IFF_EBRIDGE &&
					    memcmp(eh.ether_shost,
						   dev2->dev_addr, 6) == 0) {
#endif
						// printk("### Debug %s, source MAC %s is same as %s\n", __func__, mac_display(eh.ether_shost), dev2->name);
						goto bad;
					}
				}
#ifndef SOC_W906X
				rcu_read_unlock();
#endif

				smeGetStaLinkInfo(vmacEntry_p->id,
						  &mlmeAssociatedFlag,
						  &mlmeBssid[0]);

				/* if there was an entry in fw, from a previous association, remove it */
				wlFwRemoveMacAddr(vmacSta_p->dev,
						  &vmacEntry_p->vmacAddr[0]);

				if (mlmeAssociatedFlag) {
#ifdef AMPDU_SUPPORT_TX_CLIENT
					cleanupAmpduTx(vmacSta_p,
						       (UINT8 *) &
						       mlmeBssid[0]);
#endif
				}
				// This is a quick fix for setting parent client address.
				memcpy(&vmacEntry_p->vmacAddr[0],
				       eh.ether_shost, 6);

				wlFwSetMacAddr_Client(vmacSta_p->dev,
						      &vmacEntry_p->
						      vmacAddr[0]);

				printk("Cloned MAC address = %02x:%02x:%02x:%02x:%02x:%02x \n", vmacEntry_p->vmacAddr[0], vmacEntry_p->vmacAddr[1], vmacEntry_p->vmacAddr[2], vmacEntry_p->vmacAddr[3], vmacEntry_p->vmacAddr[4], vmacEntry_p->vmacAddr[5]);

				WLSYSLOG(netdev, WLSYSLOG_CLASS_ALL,
					 WLSYSLOG_MSG_CLIENT_CLONED
					 "%02x%02x%02x%02x%02x%02x\n",
					 vmacEntry_p->vmacAddr[0],
					 vmacEntry_p->vmacAddr[1],
					 vmacEntry_p->vmacAddr[2],
					 vmacEntry_p->vmacAddr[3],
					 vmacEntry_p->vmacAddr[4],
					 vmacEntry_p->vmacAddr[5]);

#ifdef MRVL_WPS_CLIENT
				WLSNDEVT(netdev, IWEVCUSTOM,
					 (IEEEtypes_MacAddr_t *) & vmacEntry_p->
					 vmacAddr[0],
					 WLSYSLOG_MSG_CLIENT_CLONED);
#endif //MRVL_WPS_CLIENT

#ifdef SOC_W906X
				memcpy(netdev->dev_addr,
				       &vmacEntry_p->vmacAddr[0], 6);
				memcpy(&wlpptr->hwData.macAddr[0],
				       &vmacEntry_p->vmacAddr[0], 6);
				memcpy(&vmacSta_p->macStaAddr[0],
				       &vmacEntry_p->vmacAddr[0], 6);
				memcpy(&vmacSta_p->macBssId[0],
				       &vmacEntry_p->vmacAddr[0], 6);
				memcpy(&vmacSta_p->VMacEntry.vmacAddr[0],
				       &vmacEntry_p->vmacAddr[0], 6);

				printk("Mac cloning enabled : Mac Client Addr = %s\n", mac_display(&vmacEntry_p->vmacAddr[0]));

				if (wlFwSetBssForClientMode(netdev, WL_ENABLE)) {
					WLDBG_ERROR(DBG_LEVEL_0,
						    "Falied to start the %d"
						    "th BSS for client mode\n",
						    vmacSta_p->VMacEntry.macId);
				}
#endif /* SOC_W906X */

				if (mlmeAssociatedFlag) {
					linkMgtReStart(vmacEntry_p->
						       phyHwMacIndx,
						       vmacEntry_p);
				} else
					wlLinkMgt(netdev,
						  vmacEntry_p->phyHwMacIndx);
			}
			vmacEntry_p->active = 1;
		} else {
			smeGetStaLinkInfo(vmacEntry_p->id,
					  &AssociatedFlag, &bssId[0]);
			if (!AssociatedFlag)
				goto bad;
#ifdef CLIENT_SUPPORT_MULTIPLECLIENT
			if ((pStaInfo =
			     extStaDb_GetStaInfo(vmacSta_p, &(eh.ether_shost),
						 stadb_flag)) == NULL) {
				printk("Client not in database %s start child session \n", mac_display(&(eh.ether_shost)));
				wlFwSetMacAddr_Client(sme_GetParentPrivInfo
						      (vmacEntry_p->
						       phyHwMacIndx),
						      &(eh.ether_shost));
				child_VMacEntry_p =
					smeStartChildSession(vmacEntry_p->
							     phyHwMacIndx,
							     &(eh.ether_shost),
							     0xf,
							     &wlStatusUpdate_clientParent,
							     1,
							     sme_GetParentPrivInfo
							     (vmacEntry_p->
							      phyHwMacIndx));
				goto bad;
			}
#endif
		}
		if (IS_GROUP((UINT8 *) & (eh.ether_dhost)) &&
		    (*(mib->mib_STAMacCloneEnable) == 2)) {
			if (ethStaDb_AddSta(vmacSta_p, &(eh.ether_shost), NULL)
			    == TABLE_FULL_ERROR)
				goto bad;
		}
	} else
#endif
	{
#ifdef WDS_FEATURE
		if (*(mib->mib_wdsEnable)) {
			pWdsPort = getWdsPortFromNetDev(wlpptr, netdev);
			if (pWdsPort != NULL)
				wds = TRUE;
			else if (*(mib->mib_disableAssoc))
				goto bad;
		}
#endif
	}
#ifdef WDS_FEATURE
	if (!IS_GROUP((UINT8 *) & (eh.ether_dhost)) || wds ||
	    (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_CLNT_INFRA)) {
		if (wds) {
			pStaInfo =
				extStaDb_GetStaInfo(vmacSta_p,
						    &(pWdsPort->wdsMacAddr),
						    stadb_flag);
		}
#ifdef MULTI_AP_SUPPORT
		else if ((mib->multi_ap_attr & MAP_ATTRIBUTE_BACKHAUL_BSS) &&
			 vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_AP) {
			UINT8 found = 0;
			MultiAP_4Addr_Entry_t *entry;

			if ((pStaInfo =
			     extStaDb_GetStaInfo(vmacSta_p, &(eh.ether_dhost),
						 stadb_flag)) == NULL) {
				found = FourAddr_SearchHashEntry((IEEEtypes_MacAddr_t *) eh.ether_dhost, &entry, 0);

				if (found == 1) {
					MACADDR_CPY(bssId, entry->tar);
					pStaInfo =
						extStaDb_GetStaInfo(vmacSta_p,
								    (IEEEtypes_MacAddr_t
								     *) &
								    bssId[0],
								    stadb_flag);
					if (pStaInfo == NULL)
						goto bad;
				} else {
					//printk("ieee80211_encap: target mac not found!!!\n");
				}
			}
		}
#endif
		else
#else
	if (!IS_GROUP((UINT8 *) & (eh.ether_dhost))) {
#endif
		{
#ifdef CLIENT_SUPPORT
			if (vmacSta_p->VMacEntry.modeOfService ==
			    VMAC_MODE_CLNT_INFRA)
				pStaInfo =
					extStaDb_GetStaInfo(vmacSta_p,
							    (IEEEtypes_MacAddr_t
							     *) & bssId[0],
							    stadb_flag);
			else
#endif
#ifdef SOC_W906X
			if (pStaInfoIn == NULL) {
#endif
				if ((pStaInfo =
				     extStaDb_GetStaInfo(vmacSta_p,
							 &(eh.ether_dhost),
							 stadb_flag)) == NULL) {
					if (*(mib->mib_RptrMode)) {
						if ((ethStaInfo_p =
						     ethStaDb_GetStaInfo
						     (vmacSta_p,
						      &(eh.ether_dhost),
						      1)) != NULL) {
							pStaInfo =
								ethStaInfo_p->
								pStaInfo_t;
							if (pStaInfo &&
							    (pStaInfo->
							     StaType & 0x02) !=
							    0x02)
								goto bad;
						} else {
							goto bad;
						}
					}
				}
#ifdef SOC_W906X
			} else {
				pStaInfo = (extStaDb_StaInfo_t *) pStaInfoIn;
			}
#endif

		}
		if (pStaInfo && pStaInfo->aggr11n.threshold) {
			pStaInfo->aggr11n.txcnt++;
			if (pStaInfo->aggr11n.on) {
			} else if (pStaInfo->aggr11n.start) {
				pStaInfo->aggr11n.on = 1;
			}
			if (!eap) {
				switch (*(mib->mib_AmpduTx)) {
				case 3:
					pStaInfo->aggr11n.
						txcntbytid[tid & 0x7]++;
					if (!
					    ((pStaInfo->aggr11n.
					      ampducfg) & (0x1 << tid))) {
						if (pStaInfo->aggr11n.
						    startbytid[tid & 0x07]) {
							disableAmpduTx
								(vmacSta_p,
								 pStaInfo->Addr,
								 tid);
							pStaInfo->aggr11n.
								startbytid[tid]
								= 0;
						}
						break;
					}
					if (pStaInfo->aggr11n.
					    startbytid[tid & 0x07] == 0) {
						if (pStaInfo->aggr11n.
						    onbytid[tid & 0x7]) {
							enableAmpduTx(vmacSta_p,
								      pStaInfo->
								      Addr,
								      tid);
							pStaInfo->aggr11n.
								startbytid[tid]
								= 1;
						}
					} else {
						if (!pStaInfo->aggr11n.
						    onbytid[tid & 0x7]) {
							disableAmpduTx
								(vmacSta_p,
								 pStaInfo->Addr,
								 tid);
							pStaInfo->aggr11n.
								startbytid[tid]
								= 0;
						}
					}
					break;
				case 1:
#ifdef DYNAMIC_BA_SUPPORT
					if ((*(mib->mib_ampdu_bamgmt)))
						tx_count_packet(&pStaInfo->
								aggr11n.
								tx_ac_info[(tid
									    &
									    0x07)]);
#endif
					if (!
					    ((pStaInfo->aggr11n.
					      ampducfg) & (0x1 << tid))) {
						if (pStaInfo->aggr11n.
						    startbytid[tid & 0x07]) {
							disableAmpduTx
								(vmacSta_p,
								 pStaInfo->Addr,
								 tid);
							pStaInfo->aggr11n.
								startbytid[tid]
								= 0;
						}
						break;
					}
					if (pStaInfo->aggr11n.threshold &&
					    pStaInfo->aggr11n.
					    startbytid[tid & 0x07] == 0) {
#ifdef DYNAMIC_BA_SUPPORT
						if ((!
						     (*(mib->mib_ampdu_bamgmt)))
						    || (pStaInfo->aggr11n.
							tx_ac_info[(tid &
								    0x07)].
							txa_avgpps >
							*(mib->
							  mib_ampdu_mintraffic
							  [TID_TO_WME_AC
							   (tid & 0x07)]))) {
#endif
							enableAmpduTx(vmacSta_p,
								      pStaInfo->
								      Addr,
								      tid);
#ifdef DYNAMIC_BA_SUPPORT
						}
#endif
					}
					break;
				default:
					break;
				}
			}
		}
	}
#ifdef CLIENT_SUPPORT
	if ((vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_CLNT_INFRA) &&
	    !(*(mib->mib_STAMacCloneEnable) == 2)
#ifdef MULTI_AP_SUPPORT
	    && (pStaInfo && pStaInfo->MultiAP_4addr == 0)
#endif
		) {
		if (memcmp(&vmacEntry_p->vmacAddr[0], eh.ether_shost, 6)) {
			goto bad;
		}
	}
#endif

	if ((pStaInfo && (pStaInfo->StaType & 0x02) == 0x02)
#ifdef CLIENT_SUPPORT
	    || ((*(mib->mib_STAMacCloneEnable) == 2) &&
		(vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_CLNT_INFRA))
#endif
		) {
#ifdef SOC_W906X
		llc_rptr = (struct llc_rptr *)&(skb->cb[16]);
#else
		llc_rptr =
			(struct llc_rptr *)skb_push(skb,
						    sizeof(struct llc_rptr));
#endif
		llc_rptr->llc.llc_dsap = llc_rptr->llc.llc_ssap = LLC_SNAP_LSAP;
		llc_rptr->llc.llc_un.type_u.control = LLC_UI;
		llc_rptr->llc.llc_un.type_snap.org_code[0] = 0x00;	/* Rptr OUI 0x004096 */
		llc_rptr->llc.llc_un.type_snap.org_code[1] = 0x40;
		llc_rptr->llc.llc_un.type_snap.org_code[2] = 0x96;
		llc_rptr->llc.llc_un.type_snap.ether_type =
			htons(RPTR_ETHERTYPE);
		IEEE80211_ADDR_COPY(llc_rptr->eh.ether_dhost, eh.ether_dhost);
		IEEE80211_ADDR_COPY(llc_rptr->eh.ether_shost, eh.ether_shost);
		llc_rptr->eh.ether_type = eh.ether_type;
	} else {
#ifdef SOC_W906X
		llc = (struct llc *)&(skb->cb[16]);
#else
		llc = (struct llc *)skb_push(skb, sizeof(struct llc));
#endif
		llc->llc_dsap = llc->llc_ssap = LLC_SNAP_LSAP;
		llc->llc_un.type_u.control = LLC_UI;
		llc->llc_un.type_snap.org_code[0] = 0;
		llc->llc_un.type_snap.org_code[1] = 0;
		llc->llc_un.type_snap.org_code[2] = 0;
		llc->llc_un.type_snap.ether_type = eh.ether_type;
	}

#ifdef NEW_DP
#ifdef SOC_W8964
	{
		struct ether_header *p;
		p = (struct ether_header *)skb_push(skb,
						    sizeof(struct
							   ether_header));
		IEEE80211_ADDR_COPY(p->ether_dhost, eh.ether_dhost);
		IEEE80211_ADDR_COPY(p->ether_shost, eh.ether_shost);
	}
#endif
#ifdef CLIENT_SUPPORT
	//moved counter to syncSrv_BncRecvAssociatedHandler
	//if ((!ProbeReqOnTx) && ClientModeTxMonitor && (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_CLNT_INFRA))
	//ClientModeDataCount[vmacSta_p->VMacEntry.phyHwMacIndx]++;
#endif
	/** todo check qos pri here **/
#ifdef WDS_FEATURE
	if (!IS_GROUP((UINT8 *) & (eh.ether_dhost)) || wds
#ifdef MULTI_AP_SUPPORT
	    || (pStaInfo && pStaInfo->MultiAP_4addr == 1)
#endif
	    || (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_CLNT_INFRA)) {
		if (((pStaInfo == NULL) ||
		     ((vmacSta_p->VMacEntry.modeOfService !=
		       VMAC_MODE_CLNT_INFRA) &&
		      (pStaInfo->State != ASSOCIATED)))
		    && !wds)
#else
	if (!IS_GROUP((UINT8 *) & (eh.ether_dhost))) {

		if ((pStaInfo == NULL) ||
		    ((vmacSta_p->VMacEntry.modeOfService !=
		      VMAC_MODE_CLNT_INFRA)) && (pStaInfo->State != ASSOCIATED))
#endif
		{
			wlpptr->netDevStats.tx_dropped++;
			wlpptr->netDevStats.tx_aborted_errors++;
			wl_free_skb(skb);
			return NULL;
		}
		if (*(mib->QoSOptImpl)) {
			/** Foo todo need to check if station is qos capable **/
			//klocwork checking
			if (pStaInfo && pStaInfo->IsStaQSTA) {
				UINT32 i __attribute__ ((unused));

				*(UINT16 *) & QosControl = 0;
#ifdef SOC_W906X
				Priority = AccCategoryQ[tid];
				QosControl.tid = tid;
#else
				Priority = QosTsData[tid].AccCategoryQDowngrade;
				QosControl.tid = Priority;
#endif

				//  printk("Value of priority = %d tx[0]= %d tx[1]=%d\n",Priority ,AccCategoryQ[wlpptr->wlpd_p->Ampdu_tx[0].AccessCat],AccCategoryQ[wlpptr->wlpd_p->Ampdu_tx[1].AccessCat]);
#ifdef AMPDU_SUPPORT_TX_CLIENT
				if (vmacSta_p->VMacEntry.modeOfService ==
				    VMAC_MODE_CLNT_INFRA)
					ampduMacAddr = &bssId[0];
				else
#endif
				if (pStaInfo &&
					    (pStaInfo->StaType & 0x02) == 0x02)
					ampduMacAddr = pStaInfo->Addr;
				else
					ampduMacAddr = eh.ether_dhost;
#ifdef WDS_FEATURE
				if (wds)
					ampduMacAddr = pWdsPort->wdsMacAddr;
#ifdef MULTI_AP_SUPPORT
				if (pStaInfo && pStaInfo->MultiAP_4addr == 1) {
					ampduMacAddr = &bssId[0];
				}
#endif
#endif
#ifndef AMPDU_SUPPORT_SBA
				if (!MACADDR_CMP
				    (wlpptr->wlpd_p->Ampdu_tx[0].MacAddr,
				     ampduMacAddr) &&
				    wlpptr->wlpd_p->Ampdu_tx[0].InUse) {
					if (!wlpptr->wlpd_p->Ampdu_tx[0].
					    AddBaResponseReceive)
						goto bad;

					if (tid ==
					    wlpptr->wlpd_p->Ampdu_tx[0].
					    AccessCat) {
						QosControl.ack_policy = 3;
					}
				}
				if (!MACADDR_CMP
				    (wlpptr->wlpd_p->Ampdu_tx[1].MacAddr,
				     ampduMacAddr) &&
				    wlpptr->wlpd_p->Ampdu_tx[1].InUse) {
					if (!wlpptr->wlpd_p->Ampdu_tx[1].
					    AddBaResponseReceive)
						goto bad;

					if (tid ==
					    wlpptr->wlpd_p->Ampdu_tx[1].
					    AccessCat) {
						QosControl.ack_policy = 3;
					}
				}
#else /* _AMPDU_SUPPORT_SBA */
#ifdef SOC_W8964
				for (i = AMPDU_STREAM_NO_START;
				     i < AMPDU_STREAM_NO_END; i++) {
					if (!MACADDR_CMP
					    (wlpptr->wlpd_p->Ampdu_tx[i].
					     MacAddr, ampduMacAddr) &&
					    wlpptr->wlpd_p->Ampdu_tx[i].InUse) {
						if (!wlpptr->wlpd_p->
						    Ampdu_tx[i].
						    AddBaResponseReceive) {
							ampdu_ready = 0;
							break;
						}
						if (tid ==
						    wlpptr->wlpd_p->Ampdu_tx[i].
						    AccessCat) {
							QosControl.ack_policy =
								3;
#ifdef DYNAMIC_BA_SUPPORT
							if ((*
							     (mib->
							      mib_ampdu_bamgmt)))
								ieee80211_txampdu_count_packet
									(&wlpptr->
									 wlpd_p->
									 Ampdu_tx
									 [i]);
#endif
							break;
						}
					}
				}
#endif /* SOC_W8964 */
#endif /* _AMPDU_SUPPORT_SBA */

				EdcaSeqNum[pStaInfo->StnId][Priority]++;
			}
		}
	}
#else //!NEW_DP
	wh = (struct ieee80211_qosframe *)skb_push(skb,
						   sizeof(struct
							  ieee80211_qosframe));

	*(UINT16 *) & wh->FrmCtl = 0;
	wh->FrmCtl.ProtocolVersion = IEEEtypes_PROTOCOL_VERSION;
	wh->FrmCtl.Type = IEEE_TYPE_DATA;

#ifdef CLIENT_SUPPORT
	//moved counter to syncSrv_BncRecvAssociatedHandler
	//if ((!ProbeReqOnTx) && ClientModeTxMonitor && (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_CLNT_INFRA))
	//      ClientModeDataCount[vmacSta_p->VMacEntry.phyHwMacIndx]++;
#endif

	*(UINT16 *) & wh->dur[0] = 0;
	/** todo check qos pri here **/
#ifdef WDS_FEATURE
	if (!IS_GROUP((UINT8 *) & (eh.ether_dhost)) || wds ||
	    (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_CLNT_INFRA)) {

		if (((pStaInfo == NULL) ||
		     ((vmacSta_p->VMacEntry.modeOfService !=
		       VMAC_MODE_CLNT_INFRA) &&
		      (pStaInfo->State != ASSOCIATED)))
		    && !wds)
#else
	if (!IS_GROUP((UINT8 *) & (eh.ether_dhost))) {

		if ((pStaInfo == NULL) ||
		    ((vmacSta_p->VMacEntry.modeOfService !=
		      VMAC_MODE_CLNT_INFRA)) && (pStaInfo->State != ASSOCIATED))
#endif
		{
			wlpptr->netDevStats.tx_dropped++;
			wlpptr->netDevStats.tx_aborted_errors++;
			wl_free_skb(skb);
			return NULL;
		}
		if (*(mib->QoSOptImpl)) {
			/** Foo todo need to check if station is qos capable **/
			if (pStaInfo->IsStaQSTA) {
				UINT8 i;
				Priority = AccCategoryQ[tid];

				*(UINT16 *) & QosControl = 0;
				QosControl.tid = tid;

				//      printk("Value of priority = %d tx[0]= %d tx[1]=%d\n",Priority ,AccCategoryQ[wlpptr->wlpd_p->Ampdu_tx[0].AccessCat],AccCategoryQ[wlpptr->wlpd_p->Ampdu_tx[1].AccessCat]);
#ifdef AMPDU_SUPPORT_TX_CLIENT
				if (vmacSta_p->VMacEntry.modeOfService ==
				    VMAC_MODE_CLNT_INFRA)
					ampduMacAddr = &bssId[0];
				else
#endif
				if (pStaInfo &&
					    (pStaInfo->StaType & 0x02) == 0x02)
					ampduMacAddr = pStaInfo->Addr;
				else
					ampduMacAddr = eh.ether_dhost;
#ifdef WDS_FEATURE
				if (wds)
					ampduMacAddr = pWdsPort->wdsMacAddr;
#endif
#ifndef AMPDU_SUPPORT_SBA
				if (!MACADDR_CMP
				    (wlpptr->wlpd_p->Ampdu_tx[0].MacAddr,
				     ampduMacAddr) &&
				    wlpptr->wlpd_p->Ampdu_tx[0].InUse) {
					if (!wlpptr->wlpd_p->Ampdu_tx[0].
					    AddBaResponseReceive)
						goto bad;

					if (tid ==
					    wlpptr->wlpd_p->Ampdu_tx[0].
					    AccessCat) {
						QosControl.ack_policy = 3;
					}
				}
				if (!MACADDR_CMP
				    (wlpptr->wlpd_p->Ampdu_tx[1].MacAddr,
				     ampduMacAddr) &&
				    wlpptr->wlpd_p->Ampdu_tx[1].InUse) {
					if (!wlpptr->wlpd_p->Ampdu_tx[1].
					    AddBaResponseReceive)
						goto bad;

					if (tid ==
					    wlpptr->wlpd_p->Ampdu_tx[1].
					    AccessCat) {
						QosControl.ack_policy = 3;
					}
				}
#else /* _AMPDU_SUPPORT_SBA */
				for (i = AMPDU_STREAM_NO_START;
				     i < AMPDU_STREAM_NO_END; i++) {
					if (!MACADDR_CMP
					    (wlpptr->wlpd_p->Ampdu_tx[i].
					     MacAddr, ampduMacAddr) &&
					    wlpptr->wlpd_p->Ampdu_tx[i].InUse) {
						if (!wlpptr->wlpd_p->
						    Ampdu_tx[i].
						    AddBaResponseReceive) {
							ampdu_ready = 0;
							break;
						}
						if (tid ==
						    wlpptr->wlpd_p->Ampdu_tx[i].
						    AccessCat) {
							QosControl.ack_policy =
								3;
#ifdef DYNAMIC_BA_SUPPORT
							if ((*
							     (mib->
							      mib_ampdu_bamgmt)))
								ieee80211_txampdu_count_packet
									(&wlpptr->
									 wlpd_p->
									 Ampdu_tx
									 [i]);
#endif
							break;
						}
					}
				}
#endif /* _AMPDU_SUPPORT_SBA */

				wh->FrmCtl.Subtype = QoS_DATA;
				*(UINT16 *) & wh->seq[0] =
					ENDIAN_SWAP16(EdcaSeqNum
						      [pStaInfo->
						       StnId][Priority] << 4);
				EdcaSeqNum[pStaInfo->StnId][Priority]++;
				if (pStaInfo->aggr11n.on &&
				    pStaInfo->aggr11n.nextpktnoaggr == 0 &&
				    !pStaInfo->aggr11n.type) {
					*(UINT16 *) & wh->qos[0] =
						(*(UINT16 *) & QosControl) |
						0x0080;
				} else
					*(UINT16 *) & wh->qos[0] =
						*(UINT16 *) & QosControl;
			} else {
				//non qos station
				wh->FrmCtl.Subtype = 0;
				*(UINT16 *) & wh->seq[0] =
					cpu_to_le16(0 <<
						    IEEE80211_SEQ_SEQ_SHIFT);
				*(UINT16 *) & wh->qos[0] = 0x0;

			}
		} else {
			wh->FrmCtl.Subtype = 0;
			*(UINT16 *) & wh->seq[0] =
				cpu_to_le16(0 << IEEE80211_SEQ_SEQ_SHIFT);
			*(UINT16 *) & wh->qos[0] = 0x0;
		}
	} else {
		wh->FrmCtl.Subtype = 0;
		*(UINT16 *) & wh->seq[0] =
			cpu_to_le16(0 << IEEE80211_SEQ_SEQ_SHIFT);
		*(UINT16 *) & wh->qos[0] = 0x0;
	}
	if (!eap) {
#ifdef MRVL_WAPI
		if (mib->Privacy->PrivInvoked || mib->Privacy->RSNEnabled ||
		    mib->Privacy->WAPIEnabled)
#else
		if (mib->Privacy->PrivInvoked || mib->Privacy->RSNEnabled)
#endif
			wh->FrmCtl.Wep = 1;
	}
#ifdef CLIENT_SUPPORT
	if (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_CLNT_INFRA) {
		wh->FrmCtl.ToDs = 1;
		IEEE80211_ADDR_COPY(wh->addr1, &bssId[0]);
		if (*(mib->mib_STAMacCloneEnable) == 1)
			IEEE80211_ADDR_COPY(wh->addr2, eh.ether_shost);
		else
			IEEE80211_ADDR_COPY(wh->addr2,
					    &vmacEntry_p->vmacAddr[0]);
		IEEE80211_ADDR_COPY(wh->addr3, eh.ether_dhost);
	} else
#endif
	{
		wh->FrmCtl.FromDs = 1;
		if (llc_rptr)
			IEEE80211_ADDR_COPY(wh->addr1, pStaInfo->Addr);
		else
			IEEE80211_ADDR_COPY(wh->addr1, eh.ether_dhost);
		IEEE80211_ADDR_COPY(wh->addr2, vmacSta_p->macStaAddr);
		IEEE80211_ADDR_COPY(wh->addr3, eh.ether_shost);
#ifdef WDS_FEATURE
		if (wds) {
			wh->FrmCtl.FromDs = 1;
			wh->FrmCtl.ToDs = 1;
			IEEE80211_ADDR_COPY(wh->addr4, wh->addr3);
			IEEE80211_ADDR_COPY(wh->addr3, wh->addr1);
			IEEE80211_ADDR_COPY(wh->addr1, pWdsPort->wdsMacAddr);
		}
#endif
	}
#ifdef QUEUE_STATS_CNT_HIST
	/* track per sta tx count */
	wldbgRecPerStatxPktStats(wh->addr1, QS_TYPE_TX_OK_CNT_CNT);
#endif

	if ((!eap) && (wh->FrmCtl.Subtype == QoS_DATA) && pStaInfo &&
	    (pStaInfo->aggr11n.type & WL_WLAN_TYPE_AMSDU) &&
	    pStaInfo->aggr11n.threshold) {
		//              Priority =0;
#ifndef AMSDUOVERAMPDU
		if (!pStaInfo->aggr11n.on) {
			return skb;
		}
		if (pStaInfo->aggr11n.nextpktnoaggr) {
			pStaInfo->aggr11n.nextpktnoaggr--;
			return skb;
		} else
#endif
		{
#ifndef NEW_DP			/* amsdu will be done in fw for newdp */
			if (ampdu_ready) {
				*(UINT16 *) & wh->qos[0] =
					(*(UINT16 *) & QosControl);
				skb = do_11n_aggregation(netdev, skb, pStaInfo,
							 &eh, Priority, wh);
			}
#endif
		}
	}
#endif //NEW_DP
	return skb;
bad:
	if (skb != NULL) {
		wlpptr->netDevStats.tx_dropped++;
		wl_free_skb(skb);
	}
	return NULL;
}

UINT32 dispRxPacket = 0;

#ifndef ALIGNED_POINTER
#define ALIGNED_POINTER(p, t)    1
#endif
static struct sk_buff *
ieee80211_decap(struct net_device *dev, struct sk_buff *skb,
		extStaDb_StaInfo_t * pStaInfo, u_int16_t stnid)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, dev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
	struct ether_header *eh;
	struct ieee80211_frame wh;
	struct llc *llc;
	struct llc_rptr *llc_rptr = NULL;
	UINT16 ether_type = 0;

#ifdef CLIENT_SUPPORT
	vmacEntry_t *VMacEntry_p;
	UINT8 AssociatedFlag = 0;
	UINT8 bssId[6];
#endif
#ifdef NEW_DP
	struct ether_header newDP_eh;

#ifdef TP_PROFILE
	if (wl_tp_profile_test(13, skb, dev)) {
		wl_free_skb(skb);
		return 0;
	}
#endif

	//for klocwork checking
	memset((UINT8 *) & newDP_eh, 0, sizeof(struct ether_header));
	memset((UINT8 *) & wh, 0, sizeof(struct ieee80211_frame));

	if (skb->protocol & WL_WLAN_TYPE_RX_FAST_DATA) {
		if (skb->len < sizeof(struct ether_header)) {
			goto dropPacket;
		}
		//check by klocwork a potential bugs 
		if (stnid == rxring_Ctrl_STAfromDS)
			wh.FrmCtl.FromDs = 1;

		IEEE80211_ADDR_COPY(&wh.addr1[0], &vmacSta_p->macStaAddr[0]);
		IEEE80211_ADDR_COPY(&wh.addr3[0], &skb->data[0]);
		IEEE80211_ADDR_COPY(&wh.addr2[0], &skb->data[6]);
		memcpy(&newDP_eh, &skb->data[0], sizeof(struct ether_header));

#ifdef WDS_FEATURE
		if (*(mib->mib_wdsEnable)) {
			// avoid crash when wlprivate is not master because of priv->vdev
			if (priv->master)
				priv = NETDEV_PRIV_P(struct wlprivate,
						     priv->master);
		}
		if (*(mib->mib_wdsEnable)) {
			struct wds_port *pWdsPort = NULL;
			int k;
			struct net_device *vDev = priv->vdev[0];
			struct wlprivate *myPriv =
				NETDEV_PRIV_P(struct wlprivate, vDev);

			for (k = 0; k < 6; k++) {
				if (myPriv->vmacSta_p->wdsPort[k].active) {
					pWdsPort =
						&myPriv->vmacSta_p->wdsPort[k];
					WLDBG_INFO(DBG_LEVEL_6,
						   "pWdsPort: %02x%02x%02x%02x%02x%02x\n",
						   pWdsPort->wdsMacAddr[0],
						   pWdsPort->wdsMacAddr[1],
						   pWdsPort->wdsMacAddr[2],
						   pWdsPort->wdsMacAddr[3],
						   pWdsPort->wdsMacAddr[4],
						   pWdsPort->wdsMacAddr[5]);

					if ((pStaInfo =
					     extStaDb_GetStaInfo(vmacSta_p,
								 &(pWdsPort->
								   wdsMacAddr),
								 STADB_UPDATE_AGINGTIME))
					    == NULL) {
						WLDBG_ERROR(DBG_LEVEL_6,
							    "drop1, extStaDb_GetStaInfo() == NULL\n");
						goto dropPacket;
					}
					if ((pStaInfo->StnId == stnid) ||
					    (skb->
					     protocol & WL_WLAN_TYPE_WDS)) {
						IEEE80211_ADDR_COPY(&wh.
								    addr4[0],
								    &skb->
								    data[6]);
						IEEE80211_ADDR_COPY(&wh.
								    addr2[0],
								    &pWdsPort->
								    wdsMacAddr
								    [0]);
						skb->protocol |=
							WL_WLAN_TYPE_WDS;
						skb->dev =
							(struct net_device *)
							pStaInfo->wdsInfo;
						WLDBG_INFO(DBG_LEVEL_6,
							   "ieee80211_decap: stnid:%xh\n",
							   stnid);
						break;
					}
				}
			}
		}
#ifdef MULTI_AP_SUPPORT
		else if (pStaInfo && pStaInfo->MultiAP_4addr) {
			//if(pStaInfo->StnId == stnid) { 
			IEEE80211_ADDR_COPY(&wh.addr4[0], &skb->data[6]);
			IEEE80211_ADDR_COPY(&wh.addr2[0], pStaInfo->Addr);
			skb->protocol |= WL_WLAN_TYPE_WDS;

			skb->dev = pStaInfo->dev;
			//}
		}
#endif
		else
#endif
		{
			if (*(mib->mib_STAMode) && !pStaInfo) {	/** check need to change for dual STA and AP mode **/
				IEEE80211_ADDR_COPY(&wh.addr1[0],
						    &skb->data[0]);
				IEEE80211_ADDR_COPY(&wh.addr3[0],
						    &skb->data[6]);
				if ((VMacEntry_p =
				     sme_GetParentVMacEntry(vmacSta_p->
							    VMacEntry.
							    phyHwMacIndx)) ==
				    NULL) {
					goto dropPacket;
				}
				smeGetStaLinkInfo(VMacEntry_p->id,
						  &AssociatedFlag, &bssId[0]);

				IEEE80211_ADDR_COPY(&wh.addr2[0], &bssId[0]);	//to change later

				skb->protocol |= WL_WLAN_TYPE_STA;

			} else {
				if ((pStaInfo =
				     extStaDb_GetStaInfo(vmacSta_p,
							 (IEEEtypes_MacAddr_t *)
							 & priv->wlpd_p->
							 mac_addr_sta_ta
							 /*&(wh.addr2) */ ,
							 STADB_UPDATE_AGINGTIME
							 | STADB_NO_BLOCK)) ==
				    NULL) {
					goto dropPacket;
				}
			}
		}
	} else
#endif
	{
		if (skb->len < sizeof(struct ieee80211_frame)) {
			goto dropPacket;
		}
		memcpy(&wh, skb->data, sizeof(struct ieee80211_frame));
	}

#ifdef SC_PALLADIUM
	if (dispRxPacket) {
		struct ieee80211_qosHtctlframe wh2;
		UINT32 j = 0;
		memcpy(&wh2, skb->data, sizeof(struct ieee80211_qosHtctlframe));
		printk("------------------------------------------------------------\n");
		printk("ieee80211_decap len = %d \n", skb->len);
		for (j = 0; j < skb->len; j++) {
			printk("%02x ", skb->data[j]);
			if ((j != 0) && !(j % 16))
				printk("\n");
		}
		printk("\n");
		printk("FrmCtl = %x \n", *((UINT16 *) & wh2.FrmCtl));
		printk("dur    = %x \n", *((UINT16 *) & wh2.dur));
		printk("addr1  = %s \n", mac_display(wh2.addr1));
		printk("addr2  = %s \n", mac_display(wh2.addr2));
		printk("addr3  = %s \n", mac_display(wh2.addr3));
		printk("seq    = %x \n", *((UINT16 *) & wh2.seq));
		printk("addr4  = %s \n", mac_display(wh2.addr4));
		printk("qos    = %x \n", *((UINT16 *) & wh2.qos));
		printk("htctl  = %x \n", *((UINT32 *) & wh2.htctl));
	}
#endif

#ifdef MULTI_AP_SUPPORT
	// insert MultiAP MAC serch table
	if ((pStaInfo && pStaInfo->MultiAP_4addr) && !pStaInfo->Client) {
		UINT8 found = 0;
		MultiAP_4Addr_Entry_t *entry;
		found = FourAddr_SearchHashEntry((IEEEtypes_MacAddr_t *) wh.
						 addr4, &entry, 0);

		if (found == 1) {
			MACADDR_CPY(entry->tar, wh.addr2);
		} else {
			FourAddr_AddHashEntry(&entry,
					      (IEEEtypes_MacAddr_t *) wh.addr2,
					      (IEEEtypes_MacAddr_t *) wh.addr4);
		}
	}
#endif

#ifdef CLIENT_SUPPORT

	if (skb->protocol & WL_WLAN_TYPE_STA) {
		if ((VMacEntry_p =
		     sme_GetParentVMacEntry(vmacSta_p->VMacEntry.
					    phyHwMacIndx)) == NULL)
			goto dropPacket;
		smeGetStaLinkInfo(VMacEntry_p->id, &AssociatedFlag, &bssId[0]);

		if (!AssociatedFlag ||
		    memcmp(bssId, wh.addr2, sizeof(IEEEtypes_MacAddr_t)))
			goto dropPacket;

		/* Check to see if broadcast packet from AP. */
		if (IS_GROUP((UINT8 *) & (wh.addr1))) {
			/* Verify that broadcast src address is not client */
			if ((VMacEntry_p =
			     vmacGetVMacEntryByAddr(wh.addr3)) != NULL)
				goto dropPacket;
#ifdef MULTI_AP_SUPPORT
			{
				UINT8 found = 0;
				MultiAP_4Addr_Entry_t *entry;

				found = FourAddr_SearchHashEntry((IEEEtypes_MacAddr_t *) wh.addr3, &entry, 1);
				if (found == 1) {
					goto dropPacket;
				}
			}
#endif
		} else {
			/* Unicast check if for client */
			if ((VMacEntry_p =
			     vmacGetVMacEntryByAddr(wh.addr1)) == NULL) {
				printk("drop packet\n");
				goto dropPacket;
			}
		}
	} else
#endif
	{
		if (memcmp(wh.addr1, vmacSta_p->macStaAddr, 6)) {
			wl_free_skb(skb);
			return NULL;
		}
#ifdef WDS_FEATURE
		if (pStaInfo == NULL)
			goto deauth;
		else if ((pStaInfo->State != ASSOCIATED) && !pStaInfo->AP
#ifdef MULTI_AP_SUPPORT
			 && (pStaInfo && pStaInfo->MultiAP_4addr == 0)
#endif
			)
			goto deauth;
#else
		if ((pStaInfo == NULL) || (pStaInfo->State != ASSOCIATED)) {
			WLDBG_INFO(DBG_LEVEL_9, "class3 frame from %x %d\n",
				   pStaInfo, pStaInfo ? pStaInfo->State : 0);
#ifdef SOC_W906X
			macMgmtMlme_SendDeauthenticateMsg(vmacSta_p,
							  &(wh.addr2), 0,
							  IEEEtypes_REASON_CLASS3_NONASSOC,
							  TRUE);
#else
			macMgmtMlme_SendDeauthenticateMsg(vmacSta_p,
							  &(wh.addr2), 0,
							  IEEEtypes_REASON_CLASS3_NONASSOC);
#endif
			wl_free_skb(skb);
			return NULL;
		}
#endif
	}

	if ((*(mib->mib_STAMacCloneEnable) == 2) &&
	    IS_GROUP((UINT8 *) & (wh.addr1)) && wh.FrmCtl.FromDs) {
		if (ethStaDb_GetStaInfo(vmacSta_p, &(wh.addr3), 1) != NULL) {
			wl_free_skb(skb);
			return NULL;
		}
	}
#ifdef NEW_DP
	if (skb->protocol & WL_WLAN_TYPE_RX_FAST_DATA) {
		llc = (struct llc *)skb_pull(skb, sizeof(struct ether_header));
	} else
#endif
	{
		llc = (struct llc *)skb_pull(skb,
					     sizeof(struct ieee80211_frame));
	}

	if (skb->len >= sizeof(struct llc) &&
	    llc->llc_dsap == LLC_SNAP_LSAP && llc->llc_ssap == LLC_SNAP_LSAP &&
	    llc->llc_un.type_u.control == LLC_UI &&
	    ((llc->llc_un.type_snap.org_code[0] == 0x00 &&
	      llc->llc_un.type_snap.org_code[1] == 0x40 &&
	      llc->llc_un.type_snap.org_code[2] == 0x96) ||
	     (llc->llc_un.type_snap.org_code[0] == 0x00 &&
	      llc->llc_un.type_snap.org_code[1] == 0x00 &&
	      llc->llc_un.type_snap.org_code[2] == 0x00))) {

		if (ntohs(llc->llc_un.type_snap.ether_type) == RPTR_ETHERTYPE) {
			llc_rptr = (struct llc_rptr *)llc;
			ether_type = llc_rptr->eh.ether_type;
			skb_pull(skb, sizeof(struct llc_rptr));
			llc = NULL;
		} else {
			ether_type = llc->llc_un.type_snap.ether_type;
			skb_pull(skb, sizeof(struct llc));
			llc = NULL;
		}
	}

	eh = (struct ether_header *)skb_push(skb, sizeof(struct ether_header));
#ifdef NEW_DP
	if ((skb->protocol & WL_WLAN_TYPE_RX_FAST_DATA) == 0) {
#endif
#ifdef CLIENT_SUPPORT
		if (skb->protocol & WL_WLAN_TYPE_STA) {
			if (llc_rptr) {
				IEEE80211_ADDR_COPY(eh->ether_dhost,
						    llc_rptr->eh.ether_dhost);
				IEEE80211_ADDR_COPY(eh->ether_shost,
						    llc_rptr->eh.ether_shost);
				llc_rptr = NULL;
			} else {
				IEEE80211_ADDR_COPY(eh->ether_dhost, wh.addr1);
				IEEE80211_ADDR_COPY(eh->ether_shost, wh.addr3);
			}
		} else
#endif
		{
#ifdef WDS_FEATURE
			if (!pStaInfo)
				goto deauth;
			if (pStaInfo->AP
#ifdef MULTI_AP_SUPPORT
			    || ((pStaInfo && pStaInfo->MultiAP_4addr) &&
				(wh.FrmCtl.FromDs == 1 && wh.FrmCtl.ToDs == 1))
#endif
				) {
				IEEE80211_ADDR_COPY(eh->ether_dhost, wh.addr3);
				IEEE80211_ADDR_COPY(eh->ether_shost, wh.addr4);
			} else
#endif
			if (wh.FrmCtl.ToDs) {
				if (llc_rptr) {
					IEEE80211_ADDR_COPY(eh->ether_dhost,
							    llc_rptr->eh.
							    ether_dhost);
					IEEE80211_ADDR_COPY(eh->ether_shost,
							    llc_rptr->eh.
							    ether_shost);
					llc_rptr = NULL;
					if ((pStaInfo->StaType & 0x02) == 0x02) {
						/* AP records ether peer to table */
						if (ethStaDb_AddSta
						    (vmacSta_p,
						     &(eh->ether_shost),
						     pStaInfo) ==
						    TABLE_FULL_ERROR) {
							wl_free_skb(skb);
							return NULL;
						}
					}
				} else {
					IEEE80211_ADDR_COPY(eh->ether_dhost,
							    wh.addr3);
					IEEE80211_ADDR_COPY(eh->ether_shost,
							    wh.addr2);
				}
			} else {
				WLDBG_ERROR(DBG_LEVEL_9,
					    "FromDS = %i, ToDs = %i",
					    wh.FrmCtl.FromDs, wh.FrmCtl.ToDs);
				wl_free_skb(skb);
				return NULL;
			}
		}
#ifdef NEW_DP
	} else {
		memcpy(skb->data, &newDP_eh, sizeof(struct ether_header));
	}
#endif
	if (!ALIGNED_POINTER(skb->data + sizeof(*eh), u_int32_t)) {
		struct sk_buff *n;

		n = skb_copy(skb, GFP_ATOMIC);
		n->protocol = skb->protocol;
		n->dev = skb->dev;
		wl_free_skb(skb);
		if (n == NULL)
			return NULL;
		skb = n;
		eh = (struct ether_header *)skb->data;
	}
	if (llc != NULL)
		eh->ether_type = htons(skb->len - sizeof(*eh));
	else
		eh->ether_type = ether_type;

#ifdef CLIENT_SUPPORT
	//moved counter to syncSrv_BncRecvAssociatedHandler
	//if (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_CLNT_INFRA)
	//ClientModeDataCount[vmacSta_p->VMacEntry.phyHwMacIndx]++;

#endif
	WLDBG_INFO(DBG_LEVEL_9, "ieee80211_decap: return pass\n");
	return skb;
#ifdef CLIENT_SUPPORT
dropPacket:
	WLDBG_WARNING(DBG_LEVEL_9, "ieee80211_decap: drop-out\n");
	wl_free_skb(skb);
	return NULL;
#endif
#ifdef WDS_FEATURE
deauth:
#endif
	{
		WLDBG_INFO(DBG_LEVEL_9, "class3 frame from %x %d\n", pStaInfo,
			   pStaInfo ? pStaInfo->State : 0);
#ifdef SOC_W906X
		macMgmtMlme_SendDeauthenticateMsg(vmacSta_p, &(wh.addr2), 0,
						  IEEEtypes_REASON_CLASS3_NONASSOC,
						  TRUE);
#else
		macMgmtMlme_SendDeauthenticateMsg(vmacSta_p, &(wh.addr2), 0,
						  IEEEtypes_REASON_CLASS3_NONASSOC);
#endif /* SOC_W906X */
		wl_free_skb(skb);

		WLDBG_WARNING(DBG_LEVEL_9, "ieee80211_decap: deauth-out\n");
		return NULL;
	}
}

#ifdef RX_REPLAY_DETECTION
static inline void
DOT11_SETPN(u8 * dst, u8 * src)
{
	(*(u16 *) & dst[0]) = (*(u16 *) & src[0]);
	(*(u32 *) & dst[2]) = (*(u32 *) & src[2]);
}

static inline int
DOT11_CMPPN_GE(u8 * dst, u8 * src)
{
	if ((*(u32 *) & dst[2]) == (*(u32 *) & src[2]))
		return ((*(u16 *) & dst[0]) >= (*(u16 *) & src[0]));
	return ((*(u32 *) & dst[2]) > (*(u32 *) & src[2]));
}

static inline void
DOT11_INCPN(u8 * dst)
{
	if (++(*(u16 *) & dst[0]) == 0)
		(*(u32 *) & dst[2])++;
}

static inline UINT32
GET_SEC_HDR_PN(UINT8 secMode, UINT8 * pSecHdr, UINT8 * PN, UINT8 * keyIdx)
{
	UINT32 retCode = 0;

	switch (secMode) {
	case SHAL_EU_MODE_CCMP:
	case SHAL_EU_MODE_GCMP:
		*(u16 *) & PN[0] = *(u16 *) & pSecHdr[0];
		*(u32 *) & PN[2] = *(u32 *) & pSecHdr[4];
		*keyIdx = pSecHdr[3] >> 6;
		return 0;
	case SHAL_EU_MODE_TKIP:
		PN[0] = pSecHdr[2];
		PN[1] = pSecHdr[0];
		*(u32 *) & PN[2] = *(u32 *) & pSecHdr[4];
		*keyIdx = pSecHdr[3] >> 6;
		return 0;
	default:
	case SHAL_EU_MODE_BYPASS:
	case SHAL_EU_MODE_WAPI:	//Not Support
		retCode = 1;
		break;
	}
	return retCode;
}

static int
pn_replay_detection(UINT8 frameType, UINT8 secMode, UINT8 * pSecHdr,
		    rx_queue_t * rq, UINT16 seqNum, UINT32 * badPNcnt,
		    UINT32 * passPNcnt)
{
	UINT8 keyIdx;
	rx_slot_t *slot = &rq->Slots[seqNum & (MAX_BA_REORDER_BUF_SIZE - 1)];

	if (frameType == IEEE_TYPE_DATA) {
		dbg_pn_goodCnt[0]++;
		if (GET_SEC_HDR_PN(secMode, pSecHdr, slot->PN, &keyIdx)) {
			slot->SeqNr = seqNum;
			goto Pass_PN_Check;	//No PN check needed
		} else
			goto Check_Legacy_PN;
	} else if (frameType == IEEE_TYPE_MANAGEMENT) {
		if ((secMode == SHAL_EU_MODE_CCMP) ||
		    (secMode == SHAL_EU_MODE_GCMP)) {
			*(u16 *) & slot->PN[0] = *(u16 *) & pSecHdr[0];
			*(u32 *) & slot->PN[2] = *(u32 *) & pSecHdr[4];
			slot->SeqNr = seqNum;
			keyIdx = (pSecHdr[3] >> 6) & 0x3;
			goto Check_Legacy_PN;
		}
	}

Pass_PN_Check:

	(*passPNcnt)++;
	dbg_pn_goodCnt[2]++;
	return 0;		//No PN check support

Check_Legacy_PN:

	if (keyIdx != rq->InxPN) {
		rq->InxPN = keyIdx;
	}
	//mwl_hex_dump(slot->PN, 16);
	//mwl_hex_dump(rq->RxPN[rq->InxPN], 16);        
	if ((pSecHdr[3] & 0x20) != 0x20) {
		(*badPNcnt)++;
		dbg_replay_attack_trace(0x10000000 | rq->InxPN,
					slot->setFlag,
					(rq->
					 prevSeqNum << 16) | (*(u16 *) & rq->
							      RxPN[rq->
								   InxPN][4]),
					*(u32 *) & rq->RxPN[rq->InxPN][0],
					(rq->SeqNr << 16) | (*(u16 *) & slot->
							     PN[4]),
					*(u32 *) & slot->PN[0],
					*(u32 *) & pSecHdr[4],
					*(u32 *) & pSecHdr[0]);
		dbg_pn_badCnt[0]++;
		slot->setFlag = 2;
		return 1;	//bad_PN                                                                              
	}

	if ((*(u16 *) & slot->PN[0] != 0) || (*(u32 *) & slot->PN[2] != 0)) {
		if (DOT11_CMPPN_GE(rq->RxPN[rq->InxPN], slot->PN)) {
			(*badPNcnt)++;
			dbg_replay_attack_trace(0x20000000 | rq->InxPN,
						slot->setFlag,
						(rq->
						 prevSeqNum << 16) | (*(u16 *) &
								      rq->
								      RxPN[rq->
									   InxPN]
								      [4]),
						*(u32 *) & rq->RxPN[rq->
								    InxPN][0],
						(rq->
						 SeqNr << 16) | (*(u16 *) &
								 slot->PN[4]),
						*(u32 *) & slot->PN[0],
						*(u32 *) & pSecHdr[4],
						*(u32 *) & pSecHdr[0]);
			slot->setFlag = 2;
			dbg_pn_badCnt[1]++;
			return 1;	//bad_PN                                                          
		}
	}
	DOT11_SETPN(rq->RxPN[rq->InxPN], slot->PN);
	rq->prevSeqNum = rq->SeqNr;
	rq->SeqNr = seqNum;
	slot->setFlag = 1;
	(*passPNcnt)++;
	dbg_pn_goodCnt[3]++;
	return 0;
}

static UINT32
mgmt_pn_replay_detect(struct net_device *dev, struct sk_buff *skb,
		      struct ieee80211_frame *wh,
		      UINT16 SeqNo, UINT8 machdrLen, UINT8 secMode, UINT8 * pn)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
	extStaDb_StaInfo_t *pStaInfo = NULL;
	struct except_cnt __maybe_unused *wlexcept_p =
		&wlpptr->wlpd_p->except_cnt;

#ifdef WDS_FEATURE
	struct wds_port *pWdsPort = NULL;
#endif

#ifdef WDS_FEATURE
	if (*(mib->mib_wdsEnable)) {
		pWdsPort = getWdsPortFromNetDev(wlpptr, dev);
		if (pWdsPort)
			pStaInfo =
				extStaDb_GetStaInfo(vmacSta_p,
						    &(pWdsPort->wdsMacAddr),
						    STADB_UPDATE_AGINGTIME);
	} else
#endif
#ifdef CLIENT_SUPPORT
	if (*(mib->mib_STAMode)) {
		pStaInfo = extStaDb_GetStaInfo(vmacSta_p,
					       (IEEEtypes_MacAddr_t *)
					       GetParentStaBSSID(vmacSta_p->
								 VMacEntry.
								 phyHwMacIndx),
					       STADB_UPDATE_AGINGTIME);
	} else
#endif
	{
		pStaInfo = extStaDb_GetStaInfo(vmacSta_p,
					       (IEEEtypes_MacAddr_t *) & (wh->
									  addr2),
					       STADB_UPDATE_AGINGTIME);
	}
#ifdef CONFIG_IEEE80211W
	if (pStaInfo && pStaInfo->Ieee80211wSta) {
		if (pn_replay_detection(IEEE_TYPE_MANAGEMENT, secMode, pn,
					&pStaInfo->pn->ucMgmtRxQueues, SeqNo,
					&wlexcept_p->badPNcntMgmtcast,
					&wlpptr->wlpd_p->drv_stats_val.
					rx_mgmt_ucast_pn_pass_cnt)) {
			pStaInfo->pn->mgmtBadCnt++;
			//printk("mgmt_pn_replay_detect:: drop packet - pn check fail\n");                                  
			return 1;	//drop pavket             
		}
		//printk("mgmt_pn_replay_detect:::: pn check pass\n");          
	}
#endif
	return 0;
}

static UINT32
data_pn_replay_detect(struct net_device *dev, struct sk_buff *skb,
		      IEEEtypes_FrameCtl_t * frame_ctlp, UINT16 ampdu_qos,
		      UINT16 SeqNo, UINT8 machdrLen, UINT8 secMode, UINT8 * pn)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
	extStaDb_StaInfo_t *pStaInfo = NULL;
	UINT8 tid;
	UINT32 *badPNcnt;
	UINT32 *passPNcnt;
	UINT32 *staBadPNcnt;
	rx_queue_t *rq;
	Ampdu_Pck_Reorder_t *baRxInfo;
	struct except_cnt *wlexcept_p;
#ifdef WDS_FEATURE
	struct wds_port *pWdsPort = NULL;
#endif

#ifdef WDS_FEATURE
	if (*(mib->mib_wdsEnable)) {
		pWdsPort = getWdsPortFromNetDev(wlpptr, dev);
		if (pWdsPort)
			pStaInfo =
				extStaDb_GetStaInfo(vmacSta_p,
						    &(pWdsPort->wdsMacAddr),
						    STADB_UPDATE_AGINGTIME);
	} else
#endif

#ifdef CLIENT_SUPPORT
	if (*(mib->mib_STAMode)) {
		pStaInfo = extStaDb_GetStaInfo(vmacSta_p,
					       (IEEEtypes_MacAddr_t *)
					       GetParentStaBSSID(vmacSta_p->
								 VMacEntry.
								 phyHwMacIndx),
					       STADB_UPDATE_AGINGTIME);
	} else
#endif
	{
		pStaInfo = extStaDb_GetStaInfo(vmacSta_p,
					       (IEEEtypes_MacAddr_t *) &
					       wlpptr->wlpd_p->
					       mac_addr_sta_ta
					       /*&skb->data[6] */ ,
					       STADB_UPDATE_AGINGTIME);
	}

	if (pStaInfo) {
		baRxInfo = &wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->StnId];
		wlexcept_p = &wlpptr->wlpd_p->except_cnt;

		if (frame_ctlp->Subtype & BIT(3))	//QoS Data Subtype
			tid = ampdu_qos & 0x7;
		else
			tid = MAX_TID;

		if ((tid == MAX_TID) || (baRxInfo->AddBaReceive[tid] == FALSE)) {
			rq = &pStaInfo->pn->ucRxQueues[tid];
			staBadPNcnt = &pStaInfo->pn->ucastBadCnt;
			badPNcnt = &wlexcept_p->badPNcntUcast;
			passPNcnt =
				&wlpptr->wlpd_p->drv_stats_val.
				rx_data_ucast_pn_pass_cnt;
			if (*(mib->mib_STAMode)) {
				if (IS_GROUP((UINT8 *) & skb->data[0])) {
					rq = &pStaInfo->pn->mcRxQueues[tid];
					staBadPNcnt =
						&pStaInfo->pn->mcastBadCnt;
					badPNcnt = &wlexcept_p->badPNcntMcast;
					passPNcnt =
						&wlpptr->wlpd_p->drv_stats_val.
						rx_data_mcast_pn_pass_cnt;
				}
			}

			if (pn_replay_detection
			    (IEEE_TYPE_DATA, secMode, pn, rq, SeqNo, badPNcnt,
			     passPNcnt)) {
				//printk("data_pn_replay_detect::: pn check fail\n");
				(*staBadPNcnt)++;
				return 1;	//drop_packet 
			}
			//printk("data_pn_replay_detect::: pn check pass\n");                       
		}
	}

	return 0;
}

static inline UINT8
pn_aggregate_check(extStaDb_StaInfo_t * pStaInfo, BA_RX_st * baRxInfo,
		   rx_queue_t * rq, UINT32 index, UINT32 * badPNcnt,
		   UINT32 * passPncnt)
{
	if (baRxInfo->pn_check_enabled) {
		UINT32 nextIdx, prevIdx;
		UINT16 tmpNext = (index + 1) & (MAX_BA_REORDER_BUF_SIZE - 1);
		UINT16 offset;

		nextIdx = tmpNext;
		if (baRxInfo->AmsduQ[nextIdx].state == 0)
			nextIdx = MAX_BA_REORDER_BUF_SIZE;

		prevIdx = (index - 1) & (MAX_BA_REORDER_BUF_SIZE - 1);
#if 0
		printk("state = %d-%d-%d flag=%d-%d-%d\n",
		       baRxInfo->AmsduQ[prevIdx].state,
		       baRxInfo->AmsduQ[index].state,
		       baRxInfo->AmsduQ[tmpNext].state,
		       rq->Slots[prevIdx].setFlag, rq->Slots[index].setFlag,
		       rq->Slots[tmpNext].setFlag);

		mwl_hex_dump(rq->Slots[prevIdx].PN, 16);
		mwl_hex_dump(rq->Slots[index].PN, 16);
		mwl_hex_dump(rq->Slots[tmpNext].PN, 16);
#endif

		if (rq->Slots[index].setFlag == 2) {
#if 0
			printk("pn_aggregate_check with self drop :: index=%d - %d - %d [%d]  seq=0x%04x - 0x%04x - 0x%04x [0x%04x] state=%d-%d-%d flag=%d-%d-%d\n", prevIdx, index, tmpNext, nextIdx, rq->Slots[prevIdx].SeqNr, rq->Slots[index].SeqNr, rq->Slots[tmpNext].SeqNr, rq->SeqNr, baRxInfo->AmsduQ[prevIdx].state, baRxInfo->AmsduQ[index].state, baRxInfo->AmsduQ[tmpNext].state, rq->Slots[prevIdx].setFlag, rq->Slots[index].setFlag, rq->Slots[tmpNext].setFlag);
			mwl_hex_dump(rq->RxPN[rq->InxPN], 16);

			mwl_hex_dump(rq->Slots[prevIdx].PN, 16);
			mwl_hex_dump(rq->Slots[index].PN, 16);
			mwl_hex_dump(rq->Slots[tmpNext].PN, 16);
#endif
			dbg_replay_attack_trace(0x30000000 | (rq->InxPN << 16) |
						(index << 8) | tmpNext,
						((baRxInfo->AmsduQ[prevIdx].
						  state << 20) | (rq->
								  Slots
								  [prevIdx].
								  setFlag <<
								  16)) |
						((baRxInfo->AmsduQ[index].
						  state << 12) | (rq->
								  Slots[index].
								  setFlag << 8))
						|
						((baRxInfo->AmsduQ[tmpNext].
						  state << 4) | rq->
						 Slots[tmpNext].setFlag),
						(rq->Slots[prevIdx].
						 SeqNr << 16) | (*(u16 *) & rq->
								 Slots[prevIdx].
								 PN[4]),
						*(u32 *) & rq->Slots[prevIdx].
						PN[0],
						(rq->Slots[index].
						 SeqNr << 16) | (*(u16 *) & rq->
								 Slots[index].
								 PN[4]),
						*(u32 *) & rq->Slots[index].
						PN[0],
						(rq->Slots[tmpNext].
						 SeqNr << 16) | (*(u16 *) & rq->
								 Slots[tmpNext].
								 PN[4]),
						*(u32 *) & rq->Slots[tmpNext].
						PN[0]);
			rq->Slots[index].setFlag = 0;
			(*badPNcnt)++;
			pStaInfo->pn->ucastBadCnt++;
			dbg_pn_badCnt[2]++;
			return FALSE;
		}

		if ((rq->Slots[prevIdx].setFlag == 1) &&
		    (rq->Slots[index].setFlag == 1) &&
		    DOT11_CMPPN_GE(rq->Slots[prevIdx].PN, rq->Slots[index].PN))
		{
#if 0
			printk("pn_aggregate_check with previous :: index=%d - %d - %d [%d]  seq=0x%04x - 0x%04x - 0x%04x [0x%04x] state=%d-%d-%d flag=%d-%d-%d\n", prevIdx, index, tmpNext, nextIdx, rq->Slots[prevIdx].SeqNr, rq->Slots[index].SeqNr, rq->Slots[tmpNext].SeqNr, rq->SeqNr, baRxInfo->AmsduQ[prevIdx].state, baRxInfo->AmsduQ[index].state, baRxInfo->AmsduQ[tmpNext].state, rq->Slots[prevIdx].setFlag, rq->Slots[index].setFlag, rq->Slots[tmpNext].setFlag);
			mwl_hex_dump(rq->RxPN[rq->InxPN], 16);

			mwl_hex_dump(rq->Slots[prevIdx].PN, 16);
			mwl_hex_dump(rq->Slots[index].PN, 16);
			mwl_hex_dump(rq->Slots[tmpNext].PN, 16);
#endif
			dbg_replay_attack_trace(0x40000000 | (rq->InxPN << 16) |
						(index << 8) | tmpNext,
						((baRxInfo->AmsduQ[prevIdx].
						  state << 20) | (rq->
								  Slots
								  [prevIdx].
								  setFlag <<
								  16)) |
						((baRxInfo->AmsduQ[index].
						  state << 12) | (rq->
								  Slots[index].
								  setFlag << 8))
						|
						((baRxInfo->AmsduQ[tmpNext].
						  state << 4) | rq->
						 Slots[tmpNext].setFlag),
						(rq->Slots[prevIdx].
						 SeqNr << 16) | (*(u16 *) & rq->
								 Slots[prevIdx].
								 PN[4]),
						*(u32 *) & rq->Slots[prevIdx].
						PN[0],
						(rq->Slots[index].
						 SeqNr << 16) | (*(u16 *) & rq->
								 Slots[index].
								 PN[4]),
						*(u32 *) & rq->Slots[index].
						PN[0],
						(rq->Slots[tmpNext].
						 SeqNr << 16) | (*(u16 *) & rq->
								 Slots[tmpNext].
								 PN[4]),
						*(u32 *) & rq->Slots[tmpNext].
						PN[0]);
			rq->Slots[index].setFlag = 0;
			(*badPNcnt)++;
			pStaInfo->pn->ucastBadCnt++;
			dbg_pn_badCnt[3]++;
			return FALSE;
		}
		if (nextIdx < MAX_BA_REORDER_BUF_SIZE) {
			//Compare with next one                     
			if (rq->Slots[index].SeqNr > rq->Slots[nextIdx].SeqNr) {
				offset = rq->Slots[index].SeqNr -
					rq->Slots[nextIdx].SeqNr + 1;
			} else {
				offset = 0x1000 - rq->Slots[nextIdx].SeqNr +
					rq->Slots[index].SeqNr + 1;
			}
			if (offset >= MAX_BA_REORDER_BUF_SIZE) {
				//new window no need to check
				dbg_pn_goodCnt[6]++;
				return TRUE;
			}
			if ((rq->Slots[nextIdx].setFlag == 1) &&
			    (DOT11_CMPPN_GE
			     (rq->Slots[prevIdx].PN, rq->Slots[nextIdx].PN))) {
				//rq->Slots[nextIdx].setFlag = 0; //no need to compare
				dbg_pn_goodCnt[7]++;
				return TRUE;
			}

			if ((rq->Slots[index].setFlag == 1) &&
			    (rq->Slots[nextIdx].setFlag == 1) &&
			    DOT11_CMPPN_GE(rq->Slots[index].PN,
					   rq->Slots[nextIdx].PN)) {
#if 0
				printk("pn_aggregate_check with next :: index=%d - %d - %d  seq=0x%04x - 0x%04x - 0x%04x [0x%04x]  state=%d-%d-%d flag=%d-%d-%d\n", prevIdx, index, nextIdx, rq->Slots[prevIdx].SeqNr, rq->Slots[index].SeqNr, rq->Slots[nextIdx].SeqNr, rq->SeqNr, baRxInfo->AmsduQ[prevIdx].state, baRxInfo->AmsduQ[index].state, baRxInfo->AmsduQ[nextIdx].state, rq->Slots[prevIdx].setFlag, rq->Slots[index].setFlag, rq->Slots[tmpNext].setFlag);
				mwl_hex_dump(rq->RxPN[rq->InxPN], 16);
				mwl_hex_dump(rq->Slots[prevIdx].PN, 16);
				mwl_hex_dump(rq->Slots[index].PN, 16);
				mwl_hex_dump(rq->Slots[nextIdx].PN, 16);
#endif
				dbg_replay_attack_trace(0x50000000 |
							(rq->
							 InxPN << 16) | (index
									 << 8) |
							nextIdx,
							((baRxInfo->
							  AmsduQ[prevIdx].
							  state << 20) | (rq->
									  Slots
									  [prevIdx].
									  setFlag
									  <<
									  16)) |
							((baRxInfo->
							  AmsduQ[index].
							  state << 12) | (rq->
									  Slots
									  [index].
									  setFlag
									  << 8))
							|
							((baRxInfo->
							  AmsduQ[nextIdx].
							  state << 4) | rq->
							 Slots[nextIdx].
							 setFlag),
							(rq->Slots[prevIdx].
							 SeqNr << 16) | (*(u16
									   *) &
									 rq->
									 Slots
									 [prevIdx].
									 PN[4]),
							*(u32 *) & rq->
							Slots[prevIdx].PN[0],
							(rq->Slots[index].
							 SeqNr << 16) | (*(u16
									   *) &
									 rq->
									 Slots
									 [index].
									 PN[4]),
							*(u32 *) & rq->
							Slots[index].PN[0],
							(rq->Slots[nextIdx].
							 SeqNr << 16) | (*(u16
									   *) &
									 rq->
									 Slots
									 [nextIdx].
									 PN[4]),
							*(u32 *) & rq->
							Slots[nextIdx].PN[0]);
				rq->Slots[index].setFlag = 0;
				pStaInfo->pn->ucastBadCnt++;
				(*badPNcnt)++;
				dbg_pn_badCnt[4]++;
				return FALSE;
			}
		}
		(*passPncnt)++;
		dbg_pn_goodCnt[4]++;
		rq->prevSeqNum = rq->SeqNr;
		rq->SeqNr = rq->Slots[index].SeqNr;
		DOT11_SETPN(rq->RxPN[rq->InxPN], rq->Slots[index].PN);
	}
	return TRUE;
}

#endif

void
ampdu_Init(struct net_device *dev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);

#ifdef REORDERING
	int i, j, k;
#ifdef SOC_W906X
#if 0				//REORDER_2B_REMOVED
	for (i = 0; i < MAX_STNS; i++) {
		for (j = 0; j < MAX_UP; j++) {
			for (k = 0; k < MAX_AMPDU_REORDER_BUFFER; k++) {
				wlpptr->wlpd_p->AmpduPckReorder[i].
					pFrame[j][k] = NULL;
				wlpptr->wlpd_p->AmpduPckReorder[i].
					ExpectedSeqNo[j][k] = 0;
			}
			wlpptr->wlpd_p->AmpduPckReorder[i].CurrentSeqNo[j] = 0;
			wlpptr->wlpd_p->AmpduPckReorder[i].ReOrdering[j] =
				FALSE;
			wlpptr->wlpd_p->AmpduPckReorder[i].AddBaReceive[j] =
				FALSE;
		}
	}
#endif

	for (i = 0; i < sta_num; i++) {
		memset((UINT8 *) wlpptr->wlpd_p->AmpduPckReorder[i].ba, 0,
		       (MAX_UP * sizeof(BA_RX_st)));
		memset((UINT8 *) wlpptr->wlpd_p->AmpduPckReorder[i].
		       AddBaReceive, 0, (MAX_UP * sizeof(UINT8)));

		for (j = 0; j < MAX_UP; j++) {
			for (k = 0; k < MAX_BA_REORDER_BUF_SIZE; k++)
				skb_queue_head_init(&wlpptr->wlpd_p->
						    AmpduPckReorder[i].ba[j].
						    AmsduQ[k].skbHead);
		}
	}
#else
	for (i = 0; i < MAX_AID; i++) {
		for (j = 0; j < MAX_AC; j++) {
			for (k = 0; k < MAX_AMPDU_REORDER_BUFFER; k++) {
				wlpptr->wlpd_p->AmpduPckReorder[i].
					pFrame[j][k] = NULL;
				wlpptr->wlpd_p->AmpduPckReorder[i].
					ExpectedSeqNo[j][k] = 0;
			}
			wlpptr->wlpd_p->AmpduPckReorder[i].CurrentSeqNo[j] = 0;
			wlpptr->wlpd_p->AmpduPckReorder[i].ReOrdering[j] =
				FALSE;
			wlpptr->wlpd_p->AmpduPckReorder[i].AddBaReceive[j] =
				FALSE;
		}
	}
#endif /* SOC_W906X */
#endif
	memset(&wlpptr->wlpd_p->Ampdu_tx[0], 0,
	       sizeof(Ampdu_tx_t) * MAX_SUPPORT_AMPDU_TX_STREAM_RUNNING);
}

#ifdef SOC_W906X
void
ampdu_ReInit(struct net_device *dev, u_int16_t StnId)
#else
void
ampdu_ReInit(struct net_device *dev, u_int16_t Aid)
#endif				/* SOC_W906X */
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
	int j, k;
#ifdef SOC_W8964
	int i = 0;
	struct sk_buff *skb;
#else
	Ampdu_Pck_Reorder_t *baRxInfo;
#endif /* SOC_W8964 */

#ifdef SOC_W906X
#if 0				//REORDER_2B_REMOVED
	for (j = 0; j < MAX_UP; j++) {
		for (k = 0; k < MAX_AMPDU_REORDER_BUFFER; k++) {
			skb = wlpptr->wlpd_p->AmpduPckReorder[StnId].
				pFrame[j][i];
			if (skb != NULL) {
				wlpptr->wlpd_p->AmpduPckReorder[StnId].
					pFrame[j][i] = NULL;
				wl_free_skb(skb);
			}

			wlpptr->wlpd_p->AmpduPckReorder[StnId].pFrame[j][k] =
				NULL;
			wlpptr->wlpd_p->AmpduPckReorder[StnId].
				ExpectedSeqNo[j][k] = 0;
		}
		wlpptr->wlpd_p->AmpduPckReorder[StnId].CurrentSeqNo[j] = 0;
		wlpptr->wlpd_p->AmpduPckReorder[StnId].ReOrdering[j] = FALSE;
		wlpptr->wlpd_p->AmpduPckReorder[StnId].AddBaReceive[j] = FALSE;
	}
#endif

	baRxInfo = &wlpptr->wlpd_p->AmpduPckReorder[StnId];

	for (j = 0; j < MAX_UP; j++) {
		for (k = 0; k < MAX_BA_REORDER_BUF_SIZE; k++) {
			skb_queue_purge(&baRxInfo->ba[j].AmsduQ[k].skbHead);
			baRxInfo->ba[j].AmsduQ[k].state = 0;
		}
		baRxInfo->ba[j].storedBufCnt = 0;
		baRxInfo->ba[j].leastSeqNo = 0;
		baRxInfo->ba[j].winStartB = 0;
		baRxInfo->ba[j].winSizeB = 0;
		baRxInfo->ba[j].minTime = 0;

		baRxInfo->AddBaReceive[j] = FALSE;
	}
#else
	for (j = 0; j < MAX_AC; j++) {
		for (k = 0; k < MAX_AMPDU_REORDER_BUFFER; k++) {
			skb = wlpptr->wlpd_p->AmpduPckReorder[Aid].pFrame[j][i];
			if (skb != NULL) {
				wlpptr->wlpd_p->AmpduPckReorder[Aid].
					pFrame[j][i] = NULL;
				wl_free_skb(skb);
			}

			wlpptr->wlpd_p->AmpduPckReorder[Aid].pFrame[j][k] =
				NULL;
			wlpptr->wlpd_p->AmpduPckReorder[Aid].
				ExpectedSeqNo[j][k] = 0;
		}
		wlpptr->wlpd_p->AmpduPckReorder[Aid].CurrentSeqNo[j] = 0;
		wlpptr->wlpd_p->AmpduPckReorder[Aid].ReOrdering[j] = FALSE;
		wlpptr->wlpd_p->AmpduPckReorder[Aid].AddBaReceive[j] = FALSE;
	}
#endif /* SOC_W906X */
}

#ifdef SOC_W8964		//REORDER_2B_REMOVED
void
blockack_reorder_pck(struct net_device *dev, int offset, u_int16_t Aid,
		     u_int8_t Priority)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
	int j;

#ifdef DEBUG_AMPDU_RECEIVE
	printk("In Blockack_reorder_pck\n");
#endif

	for (j = 0; j < MAX_AMPDU_REORDER_BUFFER - offset; j++) {
		if (wlpptr->wlpd_p->AmpduPckReorder[Aid].pFrame[Priority][j + offset] != NULL) {	//** I don't think we need to do this **/
			if (wlpptr->wlpd_p->AmpduPckReorder[Aid].
			    pFrame[Priority][j] != NULL)
				wl_free_skb(wlpptr->wlpd_p->
					    AmpduPckReorder[Aid].
					    pFrame[Priority][j]);
			wlpptr->wlpd_p->AmpduPckReorder[Aid].
				pFrame[Priority][j] =
				wlpptr->wlpd_p->AmpduPckReorder[Aid].
				pFrame[Priority][j + offset];
			wlpptr->wlpd_p->AmpduPckReorder[Aid].
				ExpectedSeqNo[Priority][j] =
				wlpptr->wlpd_p->AmpduPckReorder[Aid].
				ExpectedSeqNo[Priority][j + offset];
			wlpptr->wlpd_p->AmpduPckReorder[Aid].
				pFrame[Priority][j + offset] = NULL;
			wlpptr->wlpd_p->AmpduPckReorder[Aid].
				ExpectedSeqNo[Priority][j + offset] = 0;
		}

	}

}

/** Todo check this path again **/
#ifdef SOC_W906X
int
flush_blockack_pck(struct net_device *dev, int i, extStaDb_StaInfo_t * pStaInfo,
		   u_int8_t Priority)
{
	struct sk_buff *skb;
	u_int16_t Aid = pStaInfo->Aid;
	u_int16_t stnid = pStaInfo->StnId;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
	int cnt = 0;

	skb = wlpptr->wlpd_p->AmpduPckReorder[Aid].pFrame[Priority][i];
	wlpptr->wlpd_p->AmpduPckReorder[Aid].pFrame[Priority][i] = NULL;
	wlpptr->wlpd_p->AmpduPckReorder[Aid].ExpectedSeqNo[Priority][i] = 0;

	if (skb != NULL) {
		if (skb->protocol & WL_WLAN_TYPE_RX_FAST_DATA) {
			if ((skb->protocol & WL_WLAN_TYPE_STA) ||
			    (skb->protocol & WL_WLAN_TYPE_WDS)) {
				if (skb->protocol & WL_WLAN_TYPE_STA)
					stnid = rxring_Ctrl_STAfromDS;
#ifdef MULTI_AP_SUPPORT
				if (pStaInfo && pStaInfo->MultiAP_4addr)
					skb = ieee80211_decap(dev, skb,
							      pStaInfo, stnid);
				else
					skb = ieee80211_decap(dev, skb, NULL,
							      stnid);
#else
				skb = ieee80211_decap(dev, skb, NULL, stnid);
#endif
				if (skb == NULL) {
					DEBUG_REORDER();
					return 1;
				}
				cnt = ForwardFrame(dev, skb);
			} else {
				dev = skb->dev;
				skb = ieee80211_decap(dev, skb, pStaInfo,
						      stnid);
				if (skb == NULL) {
					DEBUG_REORDER();
					return 1;
				}
				cnt = ForwardFrame(dev, skb);
			}
		} else {
			if (skb->protocol & WL_WLAN_TYPE_AMSDU) {
				DeAmsduPck(dev, skb);
				return 1;
			}
			skb = DeFragPck(dev, skb, &pStaInfo);
			if (skb == NULL) {
				return 1;
			}
			skb = ieee80211_decap(dev, skb, pStaInfo, 0);
			if (skb == NULL) {
				return 1;
			}
			//skb = ProcessEAPoL(skb, vmacSta_p, vmacEntry_p);
			cnt = ForwardFrame(dev, skb);
		}
	} else {
		return 0;
	}
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)
	dev->last_rx = jiffies;
#endif
	return 1;
}
#else
int
flush_blockack_pck(struct net_device *dev, int i, u_int16_t Aid,
		   u_int8_t Priority)
{
	struct sk_buff *skb;
	extStaDb_StaInfo_t *pStaInfo = NULL;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
	int cnt = 0;

	skb = wlpptr->wlpd_p->AmpduPckReorder[Aid].pFrame[Priority][i];
	wlpptr->wlpd_p->AmpduPckReorder[Aid].pFrame[Priority][i] = NULL;
	wlpptr->wlpd_p->AmpduPckReorder[Aid].ExpectedSeqNo[Priority][i] = 0;

	if (skb != NULL) {
		if (skb->protocol & WL_WLAN_TYPE_AMSDU) {
			DeAmsduPck(dev, skb);
			return 1;
		}
		skb = DeFragPck(dev, skb, &pStaInfo);
		if (skb == NULL) {
			return 1;
		}
		skb = ieee80211_decap(dev, skb, pStaInfo, 0);
		if (skb == NULL) {
			return 1;
		}
		//skb = ProcessEAPoL(skb, vmacSta_p, vmacEntry_p);
		cnt = ForwardFrame(dev, skb);
	} else {
		return 0;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)
	dev->last_rx = jiffies;
#endif

	return 1;
}
#endif

int
Ampdu_Check_Valid_Pck_in_Reorder_queue(struct net_device *dev, u_int16_t Aid,
				       u_int8_t Priority)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
	int i;

	for (i = 0; i < MAX_AMPDU_REORDER_BUFFER; i++) {
		if (wlpptr->wlpd_p->AmpduPckReorder[Aid].pFrame[Priority][i] !=
		    NULL) {
			return TRUE;
		}
	}
	return FALSE;

}

#ifdef SOC_W906X
void
Ampdu_Flush_All_Pck_in_Reorder_queue(struct net_device *dev,
				     extStaDb_StaInfo_t * pStaInfo,
				     u_int8_t Priority)
#else
void
Ampdu_Flush_All_Pck_in_Reorder_queue(struct net_device *dev, u_int16_t Aid,
				     u_int8_t Priority)
#endif
{
	int i;

	for (i = 0; i < MAX_AMPDU_REORDER_BUFFER; i++) {
		/** flush all subsequent pck until the next hole **/
#ifdef SOC_W906X
		flush_blockack_pck(dev, i, pStaInfo, Priority);
#else
		flush_blockack_pck(dev, i, Aid, Priority);
#endif
	}
}
#endif /* SOC_W8964 */

/** Use during assoc, deauth situation etc where we need to clear any pending queue **/
#ifdef SOC_W906X
void
free_any_pending_ampdu_pck(struct net_device *dev, u_int16_t StnId)
#else
void
free_any_pending_ampdu_pck(struct net_device *dev, u_int16_t Aid)
#endif				/* SOC_W906X */
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
	int i, j;
#ifdef SOC_W8964
	struct sk_buff *skb;
#else
	Ampdu_Pck_Reorder_t *baRxInfo;
#endif /* SOC_W8964 */

#ifdef SOC_W906X
#ifdef DEBUG_AMPDU_RECEIVE
	printk("Inside  free_any_pending_ampdu_pck %d\n", StnId);
#endif

#if 0				//REORDER_2B_REMOVED
	for (j = 0; j < MAX_AC; j++) {

		for (i = 0; i < MAX_AMPDU_REORDER_BUFFER; i++) {
			skb = wlpptr->wlpd_p->AmpduPckReorder[StnId].
				pFrame[j][i];
			if (skb != NULL) {
				wlpptr->wlpd_p->AmpduPckReorder[StnId].
					pFrame[j][i] = NULL;
				wl_free_skb(skb);
			}
		}

	}
#endif

	baRxInfo = &wlpptr->wlpd_p->AmpduPckReorder[StnId];
	for (i = 0; i < MAX_UP; i++) {
		if (baRxInfo->ba[i].storedBufCnt != 0) {
			for (j = 0; j < MAX_BA_REORDER_BUF_SIZE; j++) {
				skb_queue_purge(&baRxInfo->ba[i].AmsduQ[j].
						skbHead);
				baRxInfo->ba[i].AmsduQ[i].state = 0;
			}
		}
		*(UINT32 *) & baRxInfo->ba[i].storedBufCnt = 0;
		*(UINT32 *) & baRxInfo->ba[i].winStartB = 0;
		baRxInfo->ba[i].minTime = 0;
#ifdef RX_REPLAY_DETECTION
		baRxInfo->ba[i].pn_check_enabled = FALSE;
#endif /* RX_REPLAY_DETECTION */
	}
#else
#ifdef DEBUG_AMPDU_RECEIVE
	printk("Inside  free_any_pending_ampdu_pck %d\n", Aid);
#endif

	for (j = 0; j < MAX_AC; j++) {

		for (i = 0; i < MAX_AMPDU_REORDER_BUFFER; i++) {
			skb = wlpptr->wlpd_p->AmpduPckReorder[Aid].pFrame[j][i];
			if (skb != NULL) {
				wlpptr->wlpd_p->AmpduPckReorder[Aid].
					pFrame[j][i] = NULL;
				wl_free_skb(skb);
			}
		}

	}
#endif /* SOC_W906X */
}

void
flush_any_pending_ampdu_pck(struct net_device *dev,
			    extStaDb_StaInfo_t * pStaInfo)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
	int i, j;
	Ampdu_Pck_Reorder_t *baRxInfo;

	baRxInfo = &wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->StnId];

	for (i = 0; i < MAX_UP; i++) {
		if (baRxInfo->ba[i].storedBufCnt != 0) {
			for (j = 0; j < MAX_BA_REORDER_BUF_SIZE; j++) {
				//skb_queue_purge(&baRxInfo->ba[i].AmsduQ[j].skbHead);
				while (skb_queue_len
				       (&baRxInfo->ba[i].AmsduQ[j].skbHead)) {
					struct sk_buff *skb = NULL;
					skb = skb_dequeue(&baRxInfo->ba[i].
							  AmsduQ[j].skbHead);
					BA_send2host(dev, skb, pStaInfo, i);
				}
				baRxInfo->ba[i].AmsduQ[i].state = 0;
			}
		}
		*(UINT32 *) & baRxInfo->ba[i].storedBufCnt = 0;
		*(UINT32 *) & baRxInfo->ba[i].winStartB = 0;
		baRxInfo->ba[i].minTime = 0;
#ifdef RX_REPLAY_DETECTION
		baRxInfo->ba[i].pn_check_enabled = FALSE;
#endif /* RX_REPLAY_DETECTION */
	}
}

#ifdef SOC_W906X
//Function to handle tasklet call for BA reorder
void
BA_TimerProcess(UINT8 * data)
{
	struct reorder_t *ro_p = (struct reorder_t *)data;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, ro_p->dev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	struct except_cnt *wlexcept_p = &wlpptr->wlpd_p->except_cnt;
	Ampdu_Pck_Reorder_t *baRxInfo;
	UINT32 leastSeqNo, BufCnt, dropCnt;
	UINT8 tid, id, cardindex;
	MIB_802DOT11 *mib = wlpptr->vmacSta_p->Mib802dot11;
	extStaDb_StaInfo_t *pStaInfo = NULL;

	if (ro_p->pStaInfo->StnId >= sta_num)
		goto exit;

	if (wlpptr->master) {
		cardindex =
			((NETDEV_PRIV_P(struct wlprivate, wlpptr->master)))->
			cardindex;
	} else {
		cardindex = wlpptr->cardindex;
	}

	pStaInfo = ro_p->pStaInfo;
	baRxInfo = &wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->StnId];
	tid = ro_p->tid;

	SPIN_LOCK(&baRxInfo->ba[tid].BAreodrLock);

	if (jiffies - baRxInfo->ba[tid].minTime >=
	    *(mib->mib_BAReorder_holdtime)) {
		leastSeqNo = baRxInfo->ba[tid].leastSeqNo & 0xFFFF;
		BufCnt = baRxInfo->ba[tid].storedBufCnt;

		if (BufCnt != 0) {
			if (baRxInfo->ba[tid].winStartB <= leastSeqNo) {
				dropCnt =
					leastSeqNo -
					baRxInfo->ba[tid].winStartB;
				vmacSta_p->BA_RodrTMODropCnt += dropCnt;
				pStaInfo->rxBaStats[tid].BA_RodrTMODropCnt +=
					dropCnt;
			} else {
				dropCnt =
					((BA_MAX_SEQ_NUM + 1) -
					 baRxInfo->ba[tid].winStartB) +
					leastSeqNo;
				vmacSta_p->BA_RodrTMODropCnt += dropCnt;
				pStaInfo->rxBaStats[tid].BA_RodrTMODropCnt +=
					dropCnt;
			}

			//Flush starting from least seqno in buf until 1st hole
			baRxInfo->ba[tid].winStartB =
				BA_flushSequencialData(ro_p->dev, pStaInfo,
						       &baRxInfo->ba[tid],
						       ((leastSeqNo << 16) |
							BufCnt),
						       &pStaInfo->pn->
						       ucRxQueues[tid],
						       &wlexcept_p->
						       badPNcntUcast,
						       &wlpptr->wlpd_p->
						       drv_stats_val.
						       rx_data_ucast_pn_pass_cnt,
						       tid);

			id = pStaInfo->StnId;

			DBG_BAREORDER_SN(pStaInfo, ((cardindex << 16) | id),
					 tid, 12, baRxInfo->ba[tid].winStartB,
					 leastSeqNo)
				//After flush still have pkt, trigger timer
				if (baRxInfo->ba[tid].storedBufCnt != 0) {
				baRxInfo->ba[tid].minTime = jiffies;
				//reuse ro_p, no need to free the memory of ro_p
				TimerFireInByJiffies(&baRxInfo->timer[tid], 1,
						     &BA_TimerHdlr,
						     (UINT8 *) ro_p,
						     *(mib->
						       mib_BAReorder_holdtime));

				SPIN_UNLOCK(&baRxInfo->ba[tid].BAreodrLock);
				return;
			} else {
				baRxInfo->ba[tid].minTime = 0;
			}
		} else {
			baRxInfo->ba[tid].minTime = 0;
		}
	} else {
		TimerFireInByJiffies(&baRxInfo->timer[tid], 1, &BA_TimerHdlr,
				     (UINT8 *) ro_p,
				     *(mib->mib_BAReorder_holdtime));

		SPIN_UNLOCK(&baRxInfo->ba[tid].BAreodrLock);
		return;
	}

	SPIN_UNLOCK(&baRxInfo->ba[tid].BAreodrLock);

exit:
	wl_kfree(data);

}

//Function to handle BA reorder timeout
void
BA_TimerHdlr(UINT8 * data)
{
	struct reorder_t *ro_p = (struct reorder_t *)data;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, ro_p->dev);

	if (ro_p->pStaInfo->StnId >= sta_num)
		return;

	tasklet_init(&wlpptr->wlpd_p->AmpduPckReorder[ro_p->pStaInfo->StnId].
		     ba[ro_p->tid].BArodertask, (void *)BA_TimerProcess,
		     (unsigned long)ro_p);
	tasklet_schedule(&wlpptr->wlpd_p->
			 AmpduPckReorder[ro_p->pStaInfo->StnId].ba[ro_p->tid].
			 BArodertask);
}

//Decide whether to add timer after a flush
//StoreFlag: 0-This function is called after a flush. 1-After a fresh skb store
void
BA_TimerActivateCheck(struct net_device *dev, extStaDb_StaInfo_t * pStaInfo,
		      Ampdu_Pck_Reorder_t * baRxInfo, UINT8 tid, UINT32 SeqNo,
		      UINT8 StoreFlag)
{
	struct reorder_t *ro_p;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
	MIB_802DOT11 *mib = wlpptr->vmacSta_p->Mib802dot11;

	if (baRxInfo->ba[tid].storedBufCnt != 0) {

		if (StoreFlag) {
			//Update oldest time in buffer
			if (baRxInfo->ba[tid].minTime == 0) {
				baRxInfo->ba[tid].minTime = jiffies;
			} else if (jiffies < baRxInfo->ba[tid].minTime) {
				baRxInfo->ba[tid].minTime = jiffies;
			}
		} else {
			baRxInfo->ba[tid].minTime = jiffies;	//save current jiffies, but could be improved to find oldest pkt in buf. Just need more procesing
		}

		//If timer not called yet, add to timer
		if (!timer_pending(&baRxInfo->timer[tid])) {
			ro_p = wl_kmalloc_autogfp(sizeof(struct reorder_t));
			if (ro_p != NULL) {
				ro_p->dev = dev;
				ro_p->pStaInfo = pStaInfo;
				ro_p->tid = tid;
				ro_p->SeqNo = SeqNo;
				TimerFireInByJiffies(&baRxInfo->timer[tid], 1,
						     &BA_TimerHdlr,
						     (UINT8 *) ro_p,
						     *(mib->
						       mib_BAReorder_holdtime));
			}
		}
	} else			//buffer has no more pkt
	{
		baRxInfo->ba[tid].minTime = 0;
		TimerDisarmByJiffies(&baRxInfo->timer[tid], 1);
	}
}

//Funtion to decide whether to move reorder window or drop pkt.
//Return 0 to drop
INLINE UINT32
BA_getSeqDelta(UINT32 wEnd_endExt, UINT32 winStartB, UINT32 seqNum,
	       UINT32 winSizeB_minus1)
{
	UINT32 seqDelta = 0;	// Default Drop
	UINT16 wEnd = (wEnd_endExt >> 16) & 0xFFFF;
	UINT16 endExt = wEnd_endExt & 0xFFFF;

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
	return seqDelta;
}

//Function to send pkt to host from reorder buffer
static UINT32
BA_send2host(struct net_device *dev, struct sk_buff *skb,
	     extStaDb_StaInfo_t * pStaInfo, UINT8 tid)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	UINT16 stnid = pStaInfo->StnId;
	int cnt = 0;

	if (skb != NULL) {
		if (skb->protocol & WL_WLAN_TYPE_RX_FAST_DATA) {
			if ((skb->protocol & WL_WLAN_TYPE_STA) ||
			    (skb->protocol & WL_WLAN_TYPE_WDS)) {
				if (skb->protocol & WL_WLAN_TYPE_STA)
					stnid = rxring_Ctrl_STAfromDS;
#ifdef MULTI_AP_SUPPORT
				if (pStaInfo && pStaInfo->MultiAP_4addr)
					skb = ieee80211_decap(dev, skb,
							      pStaInfo, stnid);
				else
					skb = ieee80211_decap(dev, skb, NULL,
							      stnid);
#else
				skb = ieee80211_decap(dev, skb, NULL, stnid);
#endif
				if (skb == NULL) {
					return 1;
				}
				cnt = ForwardFrame(dev, skb);
			} else {
				dev = skb->dev;
				skb = ieee80211_decap(dev, skb, pStaInfo,
						      stnid);
				if (skb == NULL) {
					return 1;
				}
				cnt = ForwardFrame(dev, skb);
			}
			vmacSta_p->BA_Rodr2Host += cnt;
			if (pStaInfo) {
				pStaInfo->rx_packets++;
				pStaInfo->rx_bytes += skb->len;
			}
			pStaInfo->rxBaStats[tid].BA_Rodr2Host += cnt;
		} else {
			if (skb->protocol & WL_WLAN_TYPE_AMSDU) {
				DeAmsduPck(dev, skb);
				return 1;
			}
			skb = DeFragPck(dev, skb, &pStaInfo);
			if (skb == NULL) {
				return 1;
			}
			skb = ieee80211_decap(dev, skb, pStaInfo, 0);
			if (skb == NULL) {
				return 1;
			}
			//skb = ProcessEAPoL(skb, vmacSta_p, vmacEntry_p);
			cnt = ForwardFrame(dev, skb);
			vmacSta_p->BA_Rodr2Host += cnt;
			pStaInfo->rxBaStats[tid].BA_Rodr2Host += cnt;
			if (pStaInfo) {
				pStaInfo->rx_packets++;
				pStaInfo->rx_bytes += skb->len;
			}
		}
	} else {
		return 0;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)
	dev->last_rx = jiffies;
#endif

	return 1;
}

//Check duplicate pkt of an amsduQ buffer for BA reorder and store skb if needed
//state: 0, 1st msdu not received yet, expecting 1st msdu
//state: 1, 1st msdu already received, expecting mid or last msdu
//state: 2, last msdu already received, not expecting anymore msdu
//LMFbit: b2-Last msdu, b1-Mid msdu, b0-First msdu
INLINE UINT8
BA_CheckAmsduDup(BA_RX_st * baRxInfo, UINT32 bufIndex, struct sk_buff * skb,
		 UINT8 LMFbit, rx_queue_t * rq, UINT8 secMode, UINT16 SeqNo,
		 UINT8 * pn)
{
	//Last amsdu already encountered, all incoming is considered duplicate
	if (baRxInfo->AmsduQ[bufIndex].state == 2) {
		return 1;	//duplicate
	}
	//amsduQ buffer is empty and incoming is 1st msdu
	if ((baRxInfo->AmsduQ[bufIndex].state == 0) && (LMFbit & 0x1)) {
		if (LMFbit & 0x4)
			baRxInfo->AmsduQ[bufIndex].state = 2;	//last msdu received
		else
			baRxInfo->AmsduQ[bufIndex].state = 1;	//1st msdu received, expecting mid or last msdu

#ifdef RX_REPLAY_DETECTION
		{
			UINT8 keyIdx;
			UINT8 pnTemp[6];

			if (pn && !GET_SEC_HDR_PN(secMode, pn, pnTemp, &keyIdx)) {
				dbg_pn_goodCnt[1]++;
				//Store PN values
				if (wfa_11ax_pf) {
					baRxInfo->pn_check_enabled = FALSE;
				} else {
					baRxInfo->pn_check_enabled = TRUE;
				}
				DOT11_SETPN(rq->Slots[bufIndex].PN, pnTemp);
				rq->Slots[bufIndex].SeqNr = SeqNo;
				if ((pn[3] & 0x20) != 0x20)	//fill out keyidx
				{
					rq->Slots[bufIndex].setFlag = 2;	//drop
				} else {
					rq->Slots[bufIndex].setFlag = 1;
				}
			}
		}
#endif

		skb_queue_tail(&baRxInfo->AmsduQ[bufIndex].skbHead, skb);
		baRxInfo->storedBufCnt++;	//Only increase cnt if 1st msdu added to buffer
		return 0;
	}
	//amsduQ has 1st msdu and expecting mid or last msdu
	if ((baRxInfo->AmsduQ[bufIndex].state == 1) && (LMFbit & 0x6)) {
		if (LMFbit & 0x4)
			baRxInfo->AmsduQ[bufIndex].state = 2;	//last msdu received

		skb_queue_tail(&baRxInfo->AmsduQ[bufIndex].skbHead, skb);
		return 0;
	}

	return 1;		//duplicate pkt
}

//Function to flush skb queue
void
BA_flushAmsduQ(struct net_device *dev, extStaDb_StaInfo_t * pStaInfo,
	       AmsduQ_st * AmsduQ, UINT8 fwdPkt, UINT8 tid)
{
	struct sk_buff *skb;

	while ((skb = skb_dequeue(&AmsduQ->skbHead)) != NULL) {
		if (fwdPkt)
			BA_send2host(dev, skb, pStaInfo, tid);
		else
			wl_free_skb(skb);	//drop PN check failed pkt

	}
	AmsduQ->state = 0;
}

//Function to flush reorder buffer starting from winStartB to the 1st encountered hole in buffer
UINT32
BA_flushSequencialData(struct net_device *dev, extStaDb_StaInfo_t * pStaInfo,
		       BA_RX_st * baRxInfo, UINT32 winStartB_BufCnt,
		       rx_queue_t * rq, UINT32 * badPNcnt, UINT32 * passPNcnt,
		       UINT8 tid)
{
	UINT32 sendMpduNum = 0, cnt = 0;
	UINT32 index, winStartB, storedBufCnt;
	UINT8 fwdPkt = TRUE;

	storedBufCnt = winStartB_BufCnt & 0xFFFF;
	winStartB = (winStartB_BufCnt >> 16) & 0xFFFF;

	if (storedBufCnt != 0) {
		index = winStartB % MAX_BA_REORDER_BUF_SIZE;

		while (baRxInfo->AmsduQ[index].state >= 2) {
#ifdef RX_REPLAY_DETECTION
			fwdPkt = pn_aggregate_check(pStaInfo, baRxInfo, rq,
						    index, badPNcnt, passPNcnt);
#endif
			BA_flushAmsduQ(dev, pStaInfo, &baRxInfo->AmsduQ[index],
				       fwdPkt, tid);
			sendMpduNum++;
			if (index == (MAX_BA_REORDER_BUF_SIZE - 1))
				index = 0;
			else
				index++;
		}
		storedBufCnt -= sendMpduNum;
		winStartB += sendMpduNum;
	}

	if (storedBufCnt == 0) {
		baRxInfo->storedBufCnt = 0;
	} else			// Find next available buffer's SN number
	{
		UINT32 nextSN = winStartB;
		do {
			if (index == (MAX_BA_REORDER_BUF_SIZE - 1)) {
				index = 0;
			} else {
				index++;
			}
			nextSN++;

			if (++cnt > MAX_BA_REORDER_BUF_SIZE)
				break;
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
UINT32
BA_flushAnyData(struct net_device * dev, extStaDb_StaInfo_t * pStaInfo,
		BA_RX_st * baRxInfo, UINT32 BufCnt_least_winStartB,
		UINT32 winSizeB_Delta, rx_queue_t * rq, UINT32 * badPNcnt,
		UINT32 * passPNcnt, UINT8 tid)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;

	UINT32 storedMpduNum, leastSN;
	UINT32 advanceDelta;
	UINT32 sendMpduNum = 0, cnt = 0;
	UINT32 winStartB, winSizeB, winDelta;
	UINT32 index;
	UINT8 fwdPkt = TRUE;

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
#ifdef RX_REPLAY_DETECTION
			fwdPkt = pn_aggregate_check(pStaInfo, baRxInfo, rq,
						    index, badPNcnt, passPNcnt);
#endif
			BA_flushAmsduQ(dev, pStaInfo, &baRxInfo->AmsduQ[index],
				       fwdPkt, tid);

			baRxInfo->storedBufCnt = 0;
			return ((winStartB & BA_MAX_SEQ_NUM));	// New winStartB
		}
	}

	if (advanceDelta < winDelta)	// there may be available buffers before New winStartB
	{
		UINT32 scanNum;

		if (winDelta > winSizeB) {
			scanNum = winSizeB - advanceDelta;
		} else {
			scanNum = winDelta - advanceDelta;
		}
		while (scanNum--) {
			//For pkt in buffer from advance delta to win delta, just flush to host. No need to check whether rx last pkt of AMSDU (state 2)
			if (baRxInfo->AmsduQ[index].state != 0) {
#ifdef RX_REPLAY_DETECTION
				fwdPkt = pn_aggregate_check(pStaInfo, baRxInfo,
							    rq, index, badPNcnt,
							    passPNcnt);
#endif
				BA_flushAmsduQ(dev, pStaInfo,
					       &baRxInfo->AmsduQ[index], fwdPkt,
					       tid);
				sendMpduNum++;

				if (--storedMpduNum == 0)
					break;
			} else {
				vmacSta_p->BA_RodrFlushDropCnt++;
				pStaInfo->rxBaStats[tid].BA_RodrFlushDropCnt++;
			}
			if (index == (MAX_BA_REORDER_BUF_SIZE - 1))
				index = 0;
			else
				index++;
		}
	}
	// Now index is pointing new winStartB(winStartB + winDelta)
	if (storedMpduNum != 0)	// Still more left
	{
		UINT32 sendMpduNum2 = 0;
		// Find next consecutive MPDU buffers
		index = (winStartB & BA_MAX_SEQ_NUM) % MAX_BA_REORDER_BUF_SIZE;

		while (baRxInfo->AmsduQ[index].state >= 2) {
#ifdef RX_REPLAY_DETECTION
			fwdPkt = pn_aggregate_check(pStaInfo, baRxInfo, rq,
						    index, badPNcnt, passPNcnt);
#endif
			BA_flushAmsduQ(dev, pStaInfo, &baRxInfo->AmsduQ[index],
				       fwdPkt, tid);
			sendMpduNum2++;
			if (index == (MAX_BA_REORDER_BUF_SIZE - 1))
				index = 0;
			else
				index++;
		}

		storedMpduNum -= sendMpduNum2;
		sendMpduNum += sendMpduNum2;
		winStartB += sendMpduNum2;
	}

	if (storedMpduNum == 0) {
		baRxInfo->storedBufCnt = 0;
	} else			// Find next available buffer's SN number
	{
		UINT32 nextSN = winStartB & BA_MAX_SEQ_NUM;
		index = nextSN % MAX_BA_REORDER_BUF_SIZE;
		do {
			if (index == (MAX_BA_REORDER_BUF_SIZE - 1)) {
				index = 0;
			} else {
				index++;
			}
			nextSN++;

			if (++cnt > MAX_BA_REORDER_BUF_SIZE)
				break;
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
INLINE UINT8
BA_chkSnValid(UINT32 SN, UINT32 winStartB)
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
#endif /* SOC_W906X */

#ifdef MBSS
extern vmacApInfo_t *
vmacGetMBssByAddr(vmacApInfo_t * vmacSta_p, UINT8 * macAddr_p)
{
	struct net_device *dev;
	struct wlprivate *wlpptr, *wlpptr1;
	vmacApInfo_t *vmac_ap;
	UINT8 i = 0;
	UINT8 nullAddr[6] = { 0, 0, 0, 0, 0, 0 };

	if (memcmp(macAddr_p, nullAddr, 6) == 0) {
		return NULL;
	}
	if (vmacSta_p->master)
		vmac_ap = vmacSta_p->master;
	else
		vmac_ap = vmacSta_p;
	wlpptr = NETDEV_PRIV_P(struct wlprivate, vmac_ap->dev);

	if (macAddr_p[5] >= vmac_ap->macStaAddr[5])
		i = macAddr_p[5] - vmac_ap->macStaAddr[5];
	else
		i = macAddr_p[5] + 0x100 - vmac_ap->macStaAddr[5];

	if (i > 0 && i <= bss_num) {
		// mbss
		dev = wlpptr->vdev[i - 1];
	} else if (i == 0) {
		// cleint
		dev = wlpptr->vdev[bss_num];
	} else
		goto search_all;

	wlpptr1 = NETDEV_PRIV_P(struct wlprivate, dev);
	vmac_ap = wlpptr1->vmacSta_p;
	if (memcmp(macAddr_p, &vmac_ap->macStaAddr, IEEEtypes_ADDRESS_SIZE) ==
	    0) {
		return vmac_ap;
	}

search_all:
	i = 0;
	while (i <= bss_num) {
		if (wlpptr->vdev[i]) {
			dev = wlpptr->vdev[i];
			wlpptr1 = NETDEV_PRIV_P(struct wlprivate, dev);
			vmac_ap = wlpptr1->vmacSta_p;
			if (memcmp
			    (macAddr_p, &vmac_ap->macStaAddr,
			     IEEEtypes_ADDRESS_SIZE) == 0) {
				return vmac_ap;
			}
		}
		i++;
	}
	return NULL;
}
#endif
static struct sk_buff *
ProcessEAPoL(struct sk_buff *skb,
	     vmacApInfo_t * vmacSta_p, vmacEntry_t * vmacEntry_p)
{
	struct ether_header *eh = (struct ether_header *)skb->data;
	MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
#ifdef MULTI_AP_SUPPORT
	extStaDb_StaInfo_t *pStaInfo;
#endif

	/* With fastpath, when STA mode, it could point to wdev0 instead of wdev0sta0, hence refer   */
	/* to wrong here which could failed the 4-way handshaking when wdev0 has wpawpa2mode>4 even  */
	/* wdev0sta0 has correct setting with wpawpa2mode=2 */
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, skb->dev);

#ifdef MULTI_AP_SUPPORT
	eh = (struct ether_header *)skb->data;
//      pStaInfo = extStaDb_GetStaInfo(vmacSta_p,&(eh->ether_shost), STADB_DONT_UPDATE_AGINGTIME);
	pStaInfo =
		extStaDb_GetStaInfo(vmacSta_p,
				    (IEEEtypes_MacAddr_t *) & wlpptr->wlpd_p->
				    mac_addr_sta_ta,
				    STADB_DONT_UPDATE_AGINGTIME);
	if (pStaInfo && pStaInfo->MultiAP_4addr && pStaInfo->Client) {
		skb->dev = (struct net_device *)vmacEntry_p->privInfo_p;
		wlpptr = NETDEV_PRIV_P(struct wlprivate, skb->dev);
		mib = wlpptr->vmacSta_p->Mib802dot11;
	}
#endif

	if (skb->protocol & WL_WLAN_TYPE_STA) {
		skb->dev = (struct net_device *)vmacEntry_p->privInfo_p;
		wlpptr = NETDEV_PRIV_P(struct wlprivate, skb->dev);
		mib = wlpptr->vmacSta_p->Mib802dot11;
	}
#ifdef MRV_8021X
	if (*(mib->mib_wpaWpa2Mode) < 4)	/* For PSK modes use internal WPA state machine */
#endif
	{
		/* Process EAP packets. */
		if (eh->ether_type == IEEE_ETHERTYPE_PAE) {
#ifdef WPA_STA
			if (skb->protocol & WL_WLAN_TYPE_STA
#ifdef MULTI_AP_SUPPORT
			    || pStaInfo->Client
#endif
				) {
				ProcessEAPoLSta((IEEEtypes_8023_Frame_t *) eh,
						&eh->ether_dhost);
			} else
#endif
			{
#ifdef MULTI_AP_SUPPORT
				if (pStaInfo && pStaInfo->MultiAP_4addr) {
					struct wlprivate *wlpptr =
						NETDEV_PRIV_P(struct wlprivate,
							      skb->dev);
					vmacSta_p = wlpptr->vmacSta_p;
				}
#endif
				ProcessEAPoLAp(vmacSta_p,
					       (IEEEtypes_8023_Frame_t *) eh,
					       &eh->ether_shost);
			}
			wl_free_skb(skb);
			return NULL;
		}
	}
#ifdef MRVL_WPS_CLIENT
	else {			// we are bypassing the internal security module
		if (eh->ether_type == IEEE_ETHERTYPE_PAE &&
		    (skb->protocol & WL_WLAN_TYPE_STA)) {
			//Get the MAC address of the wdev0 interface
			MACADDR_CPY(eh->ether_dhost,
				    ((struct net_device *)vmacEntry_p->
				     privInfo_p)->dev_addr);
#ifdef MRVL_WPS_DEBUG
			printk("MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
			       eh->ether_dhost[0], eh->ether_dhost[1],
			       eh->ether_dhost[2], eh->ether_dhost[3],
			       eh->ether_dhost[4], eh->ether_dhost[5]);
#endif
		}
	}
#endif //MRVL_WPS_CLIENT
	return skb;
}

#ifdef SOC_W906X
#endif /* SOC_W906X */

#ifdef SOC_W906X
int
htc_he_find_control_id(IEEEtypes_htcField_t * htc, u8 in_controlid)
{
	u8 control_id;
	int shift_bits = 0, left_bits = 30;	/* Acontrol has maximum 30bits */

	control_id = htc->he_variant.a_control & 0xf;

	while ((control_id != in_controlid) && (shift_bits < left_bits)) {

		switch (control_id) {
		case CONTROL_ID_UMRS:
			shift_bits += 30;
			left_bits -= 30;
			break;
		case CONTROL_ID_OM:
			shift_bits += 16;
			left_bits -= 16;
			break;
		case CONTROL_ID_HLA:
			shift_bits += 30;
			left_bits -= 30;
			break;
		case CONTROL_ID_BSR:
			shift_bits += 30;
			left_bits -= 30;
			break;
		case CONTROL_ID_UPH:
			shift_bits += 12;
			left_bits -= 12;
			break;
		case CONTROL_ID_BQR:
			shift_bits += 14;
			left_bits -= 14;
			break;
		case CONTROL_ID_CAS:
			shift_bits += 12;
			left_bits -= 12;
			break;
		default:
			return 0;
		}

		control_id = (htc->he_variant.a_control >> shift_bits) & 0xf;
	}

	if (control_id != in_controlid)
		return 0;
	else
		return shift_bits + 4;	/* also shift the 4 bit control ID */
}

/*
	cfhul-template: Ref "typedef struct CFHS_RX_st" in sfw
*/
inline U8 *
get_cfhul_template(struct sk_buff * skb, wlrxdesc_t * pCfhul)
{
	IEEEtypes_FrameCtl_t *frame_ctlp =
		(IEEEtypes_FrameCtl_t *) & pCfhul->frame_ctrl;
	IEEEtypes_fullHdr_t *mac_hdr = NULL;
	UINT8 *cfhul_template = NULL;

	if ((pCfhul->fpkt != 1) ||
	    ((frame_ctlp->Type != IEEE_TYPE_DATA) &&
	     (frame_ctlp->Type != IEEE_TYPE_MANAGEMENT))) {
		// Only get cfhul-template if:
		//      1. It's the 1st packet
		//      2. It's DATA or MGMT frame
		return cfhul_template;
	}

	if (skb->protocol & WL_WLAN_TYPE_RX_FAST_DATA)
		cfhul_template = skb->data + pCfhul->cfh_offset;
	else
		cfhul_template =
			skb->data - SMAC_MGMT_EXTRA_BYTE + pCfhul->cfh_offset;

	mac_hdr =
		(IEEEtypes_fullHdr_t *) (cfhul_template + SMAC_MAC_HDR_OFFSET);

	return cfhul_template;
}

extern UINT32 wlFwSetSchedMode(struct net_device *netdev, UINT16 action,
			       UINT32 mode_selected, void *pCfg, UINT16 len,
			       UINT16 * pStatus);

//LMFbit: b2 -last, b1 -mid, b0 -1st msdu of an amsdu
// 001: 1st msdu
// 010: mid msdu
// 100: last msdu
// 101: single msdu since it is 1st and last
int
ieee80211_input(struct net_device *dev, struct sk_buff *skb, u_int32_t rssi,
		RssiPathInfo_t * prssiPaths, wlrxdesc_t * pCfhul,
		u_int8_t isFirstMsdu, u_int16_t stnid, u_int8_t LMFbit)
#else
int
ieee80211_input(struct net_device *dev, struct sk_buff *skb, u_int32_t rssi,
		u_int32_t rssiPaths, u_int8_t ampdu_qos, u_int32_t status1,
		u_int16_t stnid)
#endif				/* SOC_W906X */
{
	struct ieee80211_frame *wh;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);

	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
	int cnt = 0;
#ifdef SOC_W8964
	UINT16 SeqNo;
	int i;
#else
	UINT16 SeqNo = pCfhul->hdr.seqNum >> 4;
	UINT8 ampdu_qos = pCfhul->qos;
	IEEEtypes_FrameCtl_t *frame_ctlp =
		(IEEEtypes_FrameCtl_t *) & pCfhul->frame_ctrl;
	IEEEtypes_fullHdr_t *mac_hdr;
	IEEEtypes_htcField_t htc;
	int shift_bits = 0;
	IEEEtypes_AcontrolInfoOm_t acontrol_om;
	UINT8 *cfhul_template;
#endif /* SOC_W8964 */
	extStaDb_StaInfo_t *pStaInfo = NULL;
	struct except_cnt *wlexcept_p = &wlpptr->wlpd_p->except_cnt;
	u_int8_t tid = 0, isBcastPkt = FALSE;
	u_int8_t *pn = NULL;
#ifdef DUPLICATED_MGMT_DBG
	IEEEtypes_Frame_t *wlanMsg_p;
#endif

#ifdef WDS_FEATURE
	BOOLEAN wds = FALSE;
	struct net_device *wdsDev = NULL;
	struct wds_port *pWdsPort = NULL;
#endif
#ifdef CLIENT_SUPPORT
	vmacEntry_t *vmacEntry_p = NULL;
	struct wlprivate *stapriv;
#endif
	BOOLEAN stationPacket = FALSE;
#ifdef SOC_W8964
	u_int32_t status = status1 & 0xff;
	u_int32_t checkforus = status1 & 0xff00;
#else
	u_int32_t status = 0;	//status1 & 0xff; Not support
	u_int32_t checkforus = 0;	//status1 & 0xff00;  Not support
#endif /* SOC_W8964 */
#ifdef MULTI_AP_SUPPORT
	extStaDb_StaInfo_t *pStaInfo_multiAP = NULL;
#endif
#ifdef BA_REORDER_FAST_DATA
	struct ieee80211_frame wh_s;
#ifdef SOC_W8964
	u_int16_t seq = status1 >> 16;
#endif /* SOC_W8964 */
#endif

	u_int8_t isfastdatareorder = 0;

#ifdef RX_REPLAY_DETECTION
	UINT8 machdrLen = pCfhul->macHdrLen;
	UINT8 secMode = pCfhul->euMode;
	UINT8 process_pn_check = TRUE && (!wfa_11ax_pf);
#endif

	UINT32 ul_usr_num = 0;
	UINT32 mib_val = 0;
	UINT32 data_len[18] = { 0 };
	UINT16 cmd_status = 0;
	struct wlprivate *vap_wlpptr = NULL;
	sched_cfg_ul_ofdma_t tf_cfg;
	UINT8 *msg_buf;
	union iwreq_data wreq;

#ifdef CLIENT_SUPPORT
	if ((vmacEntry_p =
	     sme_GetParentVMacEntry(vmacSta_p->VMacEntry.phyHwMacIndx)) ==
	    NULL) {
		goto out;
	}
#endif //MRVL_WPS_CLIENT

	//klocwork checking
	if (skb == NULL)
		goto err;
#ifdef NEW_DP
#ifdef SOC_W906X

	cfhul_template = get_cfhul_template(skb, pCfhul);
#ifdef TP_PROFILE
	if (frame_ctlp->Type == IEEE_TYPE_DATA) {
		if (wl_tp_profile_test(12, skb, dev)) {
			wl_free_skb(skb);
			return 1;
		}
	}
#endif
	if ((cfhul_template != NULL) && (frame_ctlp->Order == 1)) {

		mac_hdr =
			(IEEEtypes_fullHdr_t *) (cfhul_template +
						 SMAC_MAC_HDR_OFFSET);
		if (!memcmp
		    (&pCfhul->frame_ctrl, &mac_hdr->FrmCtl,
		     sizeof(IEEEtypes_FrameCtl_t))) {
			if (mac_hdr->FrmCtl.ToDs && mac_hdr->FrmCtl.FromDs) {
				if ((frame_ctlp->Type == IEEE_TYPE_DATA) &&
				    (mac_hdr->FrmCtl.Subtype & BIT(3)))
					memcpy(&htc, &mac_hdr->wds_qos_htc.htc,
					       sizeof(IEEEtypes_htcField_t));
				else
					memcpy(&htc, &mac_hdr->wds_htc.htc,
					       sizeof(IEEEtypes_htcField_t));
			} else if ((frame_ctlp->Type == IEEE_TYPE_DATA) &&
				   (mac_hdr->FrmCtl.Subtype & BIT(3)))
				memcpy(&htc, &mac_hdr->qos_htc.htc,
				       sizeof(IEEEtypes_htcField_t));
			else
				memcpy(&htc, &mac_hdr->htc,
				       sizeof(IEEEtypes_htcField_t));

			if ((htc.he_variant.vht && htc.he_variant.he)) {	/* HTC  HE variant present */
				shift_bits =
					htc_he_find_control_id(&htc,
							       CONTROL_ID_OM);
			}

			if (shift_bits) {
				acontrol_om.om_control =
					(htc.he_variant.
					 a_control >> shift_bits) & 0x1FF;
				if (wfa_11ax_pf)	/* Only print for WFA tests */
					printk("qos_pkt, acontrol_om.chbw %d acontrol_om.rxnss %d, acontrol_om.tx_nsts %d, acontrol_om.ulmu_disable %d\n", acontrol_om.chbw, acontrol_om.rxnss, acontrol_om.tx_nsts, acontrol_om.ulmu_disable);
				if ((pStaInfo = extStaDb_GetStaInfo(vmacSta_p,
								    (IEEEtypes_MacAddr_t
								     *) &
								    mac_hdr->
								    Addr2,
								    STADB_SKIP_MATCH_VAP
								    |
								    STADB_NO_BLOCK))
				    != NULL) {
					vap_wlpptr =
						NETDEV_PRIV_P(struct wlprivate,
							      pStaInfo->dev);

					if (wfa_11ax_pf &&
					    (vap_wlpptr->vmacSta_p->ul_ofdma.
					     period_tmr != 0)) {

						if (pStaInfo->operating_mode.
						    tx_nsts !=
						    acontrol_om.tx_nsts) {
							ul_usr_num = 1;
							mib_val =
								acontrol_om.
								tx_nsts;
							wlFwSetMib(dev,
								   HostCmd_ACT_GEN_SET,
								   MIB_TF_NSS,
								   &mib_val,
								   &ul_usr_num);
							wlFwSetMib(dev,
								   HostCmd_ACT_GEN_GET,
								   MIB_TF_DATA_LEN,
								   data_len,
								   &ul_usr_num);
							data_len[0] =
								data_len[0] *
								(acontrol_om.
								 tx_nsts +
								 1) /
								(pStaInfo->
								 operating_mode.
								 tx_nsts + 1);
							ul_usr_num = 1;
							wlFwSetMib(dev,
								   HostCmd_ACT_GEN_SET,
								   MIB_TF_DATA_LEN,
								   data_len,
								   &ul_usr_num);
						}
						if (pStaInfo->operating_mode.
						    ulmu_disable !=
						    acontrol_om.ulmu_disable) {
							if (acontrol_om.
							    ulmu_disable == 1) {
								memcpy((void *)
								       &tf_cfg,
								       (void *)
								       &vap_wlpptr->
								       vmacSta_p->
								       ul_ofdma,
								       sizeof
								       (sched_cfg_ul_ofdma_t));
								tf_cfg.period_tmr = 0;
								wlFwSetSchedMode
									(pStaInfo->
									 dev,
									 HostCmd_ACT_GEN_SET,
									 MODE_SELECT_UL_OFDMA,
									 &tf_cfg,
									 sizeof
									 (sched_cfg_ul_ofdma_t),
									 &cmd_status);
							} else {
								wlFwSetSchedMode
									(pStaInfo->
									 dev,
									 HostCmd_ACT_GEN_SET,
									 MODE_SELECT_UL_OFDMA,
									 (void
									  *)
									 &vap_wlpptr->
									 vmacSta_p->
									 ul_ofdma,
									 sizeof
									 (sched_cfg_ul_ofdma_t),
									 &cmd_status);
							}
						}
					} else if (pStaInfo->operating_mode.
						   ulmu_disable !=
						   acontrol_om.ulmu_disable) {
						msg_buf =
							wl_kmalloc
							(IW_CUSTOM_MAX,
							 GFP_KERNEL);
						if (msg_buf == NULL) {
							printk("kmalloc failed for OMI event\n");
							goto err;
						}
						if (acontrol_om.ulmu_disable ==
						    1) {
							printk("qos_pkt,"
							       "acontrol_om.chbw %d acontrol_om.rxnss %d,"
							       "acontrol_om.tx_nsts %d,"
							       "acontrol_om.ulmu_disable %d\n",
							       acontrol_om.chbw,
							       acontrol_om.
							       rxnss,
							       acontrol_om.
							       tx_nsts,
							       acontrol_om.
							       ulmu_disable);
							sprintf(msg_buf,
								"wlmgr: mumode ul_ofdma_disable stnid:%d",
								pStaInfo->
								StnId);
							memset(&wreq, 0,
							       sizeof(wreq));
							wreq.data.length =
								strlen(msg_buf);
							wireless_send_event
								(pStaInfo->dev,
								 IWEVCUSTOM,
								 &wreq,
								 msg_buf);
						} else {
							sprintf(msg_buf,
								"wlmgr: mumode ul_ofdma_enable stnid:%d",
								pStaInfo->
								StnId);
							memset(&wreq, 0,
							       sizeof(wreq));
							wreq.data.length =
								strlen(msg_buf);
							wireless_send_event
								(pStaInfo->dev,
								 IWEVCUSTOM,
								 &wreq,
								 msg_buf);
						}
						wl_kfree(msg_buf);
					}

					if ((pStaInfo->operating_mode.rxnss !=
					     acontrol_om.rxnss) ||
					    (pStaInfo->operating_mode.chbw !=
					     acontrol_om.chbw)) {
						wlFwSetVHTOpMode(pStaInfo->dev,
								 pStaInfo->
								 StnId,
								 acontrol_om.
								 chbw,
								 acontrol_om.
								 rxnss + 1);
					}

					if (wfa_11ax_pf &&
					    (vap_wlpptr->vmacSta_p->ul_ofdma.
					     period_tmr != 0)) {

						if (pStaInfo->operating_mode.
						    chbw != acontrol_om.chbw) {
							switch (acontrol_om.
								chbw) {
							case 3:
								ul_usr_num = 1;
								mib_val = 68;
								wlFwSetMib
									(pStaInfo->
									 dev,
									 HostCmd_ACT_GEN_SET,
									 MIB_TF_RU_ALLOC,
									 &mib_val,
									 &ul_usr_num);
								break;
							case 2:
								ul_usr_num = 1;
								mib_val = 67;
								wlFwSetMib
									(pStaInfo->
									 dev,
									 HostCmd_ACT_GEN_SET,
									 MIB_TF_RU_ALLOC,
									 &mib_val,
									 &ul_usr_num);
								break;
							case 1:
								ul_usr_num = 1;
								mib_val = 65;
								wlFwSetMib
									(pStaInfo->
									 dev,
									 HostCmd_ACT_GEN_SET,
									 MIB_TF_RU_ALLOC,
									 &mib_val,
									 &ul_usr_num);
								break;
							case 0:
								ul_usr_num = 1;
								mib_val = 61;
								wlFwSetMib
									(pStaInfo->
									 dev,
									 HostCmd_ACT_GEN_SET,
									 MIB_TF_RU_ALLOC,
									 &mib_val,
									 &ul_usr_num);
								break;
							default:
								break;
							}
							wlFwSetMib(dev,
								   HostCmd_ACT_GEN_GET,
								   MIB_TF_DATA_LEN,
								   data_len,
								   &ul_usr_num);
							data_len[0] =
								data_len[0] *
								(2 <<
								 acontrol_om.
								 chbw) /
								(2 << pStaInfo->
								 operating_mode.
								 chbw);
							ul_usr_num = 1;
							wlFwSetMib(dev,
								   HostCmd_ACT_GEN_SET,
								   MIB_TF_DATA_LEN,
								   data_len,
								   &ul_usr_num);
						}
					}
					if (pStaInfo->operating_mode.
					    om_control !=
					    acontrol_om.om_control) {
						pStaInfo->operating_mode.
							om_control =
							acontrol_om.om_control;
					}
				}
			}
		}
	}
#ifdef CLIENT_SUPPORT
	if ((skb->protocol & WL_WLAN_TYPE_STA) && (prssiPaths != NULL)) {
		dev = (struct net_device *)vmacEntry_p->privInfo_p;
		stapriv = NETDEV_PRIV_P(struct wlprivate, dev);
		vmacSta_p = stapriv->vmacSta_p;
		memcpy(&vmacSta_p->RSSI_path, prssiPaths,
		       sizeof(RssiPathInfo_t));
	}
#endif
#endif /* SOC_W906X */

	if (skb->protocol & WL_WLAN_TYPE_RX_FAST_DATA) {
		extStaDb_StaInfo_t *pStaInfo = NULL;

		if (pCfhul->fpkt == 1 && pCfhul->lpkt == 1) {
			memcpy(&skb->data[0],
			       (u_int32_t *) & pCfhul->nss_hdr[0], 14);
		}
#ifdef MULTI_AP_SUPPORT
		if (skb->protocol & WL_WLAN_TYPE_WDS) {
#if 0
			if (cfhul_template != NULL) {
				mac_hdr =
					(IEEEtypes_fullHdr_t *) (cfhul_template
								 +
								 SMAC_MAC_HDR_OFFSET);
				pStaInfo_multiAP =
					extStaDb_GetStaInfo(vmacSta_p,
							    (IEEEtypes_MacAddr_t
							     *) & mac_hdr->
							    Addr2, 0);
			}
#endif
			pStaInfo_multiAP =
				extStaDb_GetStaInfoStn(vmacSta_p, stnid);
			if (pStaInfo_multiAP && pStaInfo_multiAP->MultiAP_4addr) {
#ifdef MBSS
				vmacApInfo_t *vmactem_p;
#endif /* MBSS */
				pStaInfo = pStaInfo_multiAP;
#ifdef MBSS
				if ((vmactem_p =
				     vmacGetMBssByAddr(vmacSta_p,
						       pStaInfo->Bssid)) !=
				    NULL) {
					vmacSta_p = vmactem_p;
					dev = vmacSta_p->dev;
					skb->dev = dev;
				}
#endif /* MBSS */
			}
		}
#endif /* MULTI_AP_SUPPORT */

		WLDBG_INFO(DBG_LEVEL_9,
			   "mib->mib_wdsEnable:%x, mib->mib_STAMode:%x, stnid == rxring_Ctrl_STAfromDS:%x\n",
			   *(mib->mib_wdsEnable), *(mib->mib_STAMode),
			   (stnid == rxring_Ctrl_STAfromDS) ? 1 : 0);

		if (*(mib->mib_wdsEnable)
#ifdef MULTI_AP_SUPPORT
		    || (pStaInfo && pStaInfo->MultiAP_4addr)
#endif /* MULTI_AP_SUPPORT */
		    || (*(mib->mib_STAMode) && (stnid == rxring_Ctrl_STAfromDS))) {	/** check for sta and wds mode might need to change for better **/
			//skb = ieee80211_decap( dev, skb, pStaInfo, stnid);
			//klocwork checking
#if 0
			skb = ieee80211_decap(dev, skb, pStaInfo, stnid);

			if (skb == NULL) {
				goto err;
			}
			cnt = ForwardFrame(dev, skb);
			return cnt;
#endif
#ifdef SOC_W8964

			skb = ieee80211_decap(dev, skb, pStaInfo, stnid);

			if (skb == NULL) {
				goto err;
			}
			cnt = ForwardFrame(dev, skb);
			WLDBG_INFO(DBG_LEVEL_9, "ForwardFrame cnt=%d\n", cnt);
#endif
			if (*(mib->mib_wdsEnable)) {
				// Fix WDS enable then AP send deauth packet to STA because of StaInfo_p->Bssid is not match vmac_p->macBssId
				// Found the correct vmacApInfo_t when WDS enable
				vmacApInfo_t *vmactem_p;
				if (skb->protocol & WL_WLAN_TYPE_WDS)
					pStaInfo =
						extStaDb_GetStaInfoStn
						(vmacSta_p, stnid);
				else
					pStaInfo =
						extStaDb_GetStaInfo(vmacSta_p,
								    (IEEEtypes_MacAddr_t
								     *) & skb->
								    data[6],
								    STADB_SKIP_MATCH_VAP
								    |
								    STADB_NO_BLOCK);
				if (pStaInfo) {
					if ((vmactem_p =
					     vmacGetMBssByAddr(vmacSta_p,
							       pStaInfo->
							       Bssid)) !=
					    NULL) {
						vmacSta_p = vmactem_p;
						dev = vmacSta_p->dev;
						skb->dev = dev;
					}
				}
			}
		} else {
#ifdef MBSS
			vmacApInfo_t *vmactem_p;

			if ((pStaInfo = extStaDb_GetStaInfo(vmacSta_p,
							    (IEEEtypes_MacAddr_t
							     *) & wlpptr->
							    wlpd_p->
							    mac_addr_sta_ta,
							    STADB_SKIP_MATCH_VAP
							    | STADB_NO_BLOCK))
			    == NULL) {
				goto err;
			}
			vmactem_p =
				vmacGetMBssByAddr(vmacSta_p, pStaInfo->Bssid);
			if (vmactem_p)
				vmacSta_p = vmactem_p;
			dev = vmacSta_p->dev;
			skb->dev = dev;
#endif

#ifdef SOC_W906X
		}
#ifdef BA_REORDER_FAST_DATA

		if (wfa_11ax_pf)
			wlpptr->wlpd_p->fastdata_reordering_disable = 1;

		if (!wlpptr->wlpd_p->fastdata_reordering_disable) {
			isfastdatareorder = 1;
			memset((UINT8 *) & wh_s, 0,
			       sizeof(struct ieee80211_frame));
			wh_s.FrmCtl = *frame_ctlp;
			if (stnid == rxring_Ctrl_STAfromDS) {
				wh_s.FrmCtl.FromDs = 1;
				stationPacket = TRUE;
				if (*(mib->mib_STAMode))
					isBcastPkt =
						IS_GROUP((UINT8 *) & skb->
							 data[0]);
			}
			IEEE80211_ADDR_COPY(&wh_s.addr1[0],
					    &vmacSta_p->macStaAddr[0]);
			IEEE80211_ADDR_COPY(&wh_s.addr3[0], &skb->data[0]);
			IEEE80211_ADDR_COPY(&wh_s.addr2[0], &skb->data[6]);
#ifdef MULTI_AP_SUPPORT
			if (pStaInfo && pStaInfo->MultiAP_4addr) {
				IEEE80211_ADDR_COPY(&wh_s.addr4[0],
						    &skb->data[6]);
				IEEE80211_ADDR_COPY(&wh_s.addr2[0],
						    pStaInfo->Addr);
				wh_s.FrmCtl.FromDs = 1;
				wh_s.FrmCtl.ToDs = 1;
				if (pStaInfo->Client) {
					stationPacket = TRUE;
					if (*(mib->mib_STAMode))
						isBcastPkt =
							IS_GROUP((UINT8 *) &
								 skb->data[0]);
				}
			}
#endif
			wh = &wh_s;
#ifdef SOC_W8964
			SeqNo = seq >> IEEE80211_SEQ_SEQ_SHIFT;
#endif /* SOC_W8964 */
#ifdef RX_REPLAY_DETECTION
			if (frame_ctlp->Wep) {
				if ((pCfhul->fpkt == 1) && cfhul_template) {
					pn = (UINT8 *) cfhul_template +
						SMAC_CFHUL_MAC_HDR_OFFSET +
						machdrLen;
				}
			}
#endif
			goto fastdatareorder;
		}
#endif

#ifdef RX_REPLAY_DETECTION
		if (frame_ctlp->Wep && (!wfa_11ax_pf)) {
			if ((pCfhul->fpkt == 1) && cfhul_template) {
				pn = (UINT8 *) cfhul_template +
					SMAC_CFHUL_MAC_HDR_OFFSET + machdrLen;
				if (data_pn_replay_detect
				    (dev, skb, frame_ctlp, ampdu_qos, SeqNo,
				     machdrLen, secMode, pn))
					goto out;	//drop_packet                             
			}
		}
#endif

fastdatareordercontinue:
		if (*(mib->mib_wdsEnable)
#ifdef MULTI_AP_SUPPORT
		    || (pStaInfo && pStaInfo->MultiAP_4addr)
#endif
		    || (*(mib->mib_STAMode) && (stnid == rxring_Ctrl_STAfromDS))) {	/** check for sta and wds mode might need to change for better **/
			//skb = ieee80211_decap( dev, skb, pStaInfo, stnid);
			//klocwork checking
#ifdef MULTI_AP_SUPPORT
			skb = ieee80211_decap(dev, skb, pStaInfo, stnid);
#else
			skb = ieee80211_decap(dev, skb, NULL, stnid);
#endif

			if (skb == NULL) {
				goto err;
			}
			cnt = ForwardFrame(dev, skb);
			WLDBG_INFO(DBG_LEVEL_9, "ForwardFrame cnt=%d\n", cnt);
		} else {
			if (prssiPaths != NULL && pStaInfo != NULL) {	// valid rssiPath
				pStaInfo->RSSI = rssi;
				memcpy(&pStaInfo->RSSI_path, prssiPaths,
				       sizeof(RssiPathInfo_t));
			}
#endif /* SOC_W906X */
			skb = ieee80211_decap(dev, skb, pStaInfo, stnid);
			if (skb == NULL) {
				goto err;
			}
			cnt = ForwardFrame(dev, skb);
		}

		if (pStaInfo) {
			pStaInfo->rx_packets++;
			pStaInfo->rx_bytes += skb->len;
		}

		return cnt;
	}
#endif
	if (skb->len < sizeof(struct ieee80211_frame_min)) {
		goto out;
	}

	wh = (struct ieee80211_frame *)skb->data;
	if (wh == NULL) {
		goto err;
	}
	switch (wh->FrmCtl.Type) {
	case IEEE_TYPE_DATA:
		/* For physical interfqace:  rx_packets is already counted before calling ieee80211_input() */
		// wlpptr->netDevStats.rx_packets++;
		// wlpptr->netDevStats.rx_bytes += skb->len;
#ifdef QUEUE_STATS_CNT_HIST
		/* Record the Rx pkts based on pre-set STA MAC address */
		WLDBG_REC_RX_80211_INPUT_PKTS(wh);
#endif

#ifdef AUTOCHANNEL
		if (vmacSta_p->StopTraffic)
			goto out;	//drop packet
#endif /* AUTOCHANNEL */

#ifdef MBSS
		{
			vmacApInfo_t *vmactem_p;
#ifdef MULTI_AP_SUPPORT
#if 0
			extStaDb_StaInfo_t *pTmpStaInfo = NULL;
			extern IEEEtypes_MacAddr_t brdcastAddr;

			if (!MACADDR_CMP(wh->addr1, brdcastAddr)) {
				vmactem_p =
					vmacGetMBssByAddr(vmacSta_p,
							  (IEEEtypes_MacAddr_t
							   *) & vmacEntry_p->
							  vmacAddr);
				if (vmactem_p)
					vmacSta_p = vmactem_p;
			} else
#endif
#endif
				vmactem_p =
					vmacGetMBssByAddr(vmacSta_p,
							  (UINT8 *) & (wh->
								       addr1));
			if (vmactem_p)
				vmacSta_p = vmactem_p;
			else if (checkforus)
				goto out;

			mib = vmacSta_p->Mib802dot11;
			dev = vmacSta_p->dev;
		}
#endif
#ifdef WDS_FEATURE
		if ((wh->FrmCtl.ToDs == 1) && (wh->FrmCtl.FromDs == 1)) {
#ifdef MULTI_AP_SUPPORT
			pStaInfo =
				extStaDb_GetStaInfo(vmacSta_p, &(wh->addr2),
						    STADB_UPDATE_AGINGTIME);
			if (!pStaInfo) {
				// peer not in database.
				goto out;
			}

			if (pStaInfo && pStaInfo->MultiAP_4addr) {
				skb->protocol |= WL_WLAN_TYPE_WDS;
				skb->dev =
					(struct net_device *)vmacEntry_p->
					privInfo_p;
			} else {
#endif
				if (!*(mib->mib_wdsEnable) ||
				    ((pStaInfo =
				      extStaDb_GetStaInfo(vmacSta_p,
							  &(wh->addr2),
							  STADB_UPDATE_AGINGTIME))
				     == NULL)) {
					// WDS AP Packet not in database.
					goto out;
				}
				if (pStaInfo && pStaInfo->AP) {
					wdsDev = (struct net_device *)pStaInfo->
						wdsInfo;
					pWdsPort =
						(struct wds_port *)pStaInfo->
						wdsPortInfo;
					if (!pWdsPort->active)
						goto out;
				} else
					goto out;
				skb->protocol |= WL_WLAN_TYPE_WDS;
				skb->dev =
					(struct net_device *)pStaInfo->wdsInfo;
				wds = TRUE;
#ifdef MULTI_AP_SUPPORT
			}
#endif
		} else
#endif
		if (!(wh->FrmCtl.ToDs == 1)) {
#ifdef CLIENT_SUPPORT
			if (wh->FrmCtl.FromDs == 1) {
				stationPacket = TRUE;
				skb->protocol |= WL_WLAN_TYPE_STA;
				dev = (struct net_device *)vmacEntry_p->
					privInfo_p;
				stapriv = NETDEV_PRIV_P(struct wlprivate, dev);
				vmacSta_p = stapriv->vmacSta_p;
				mib = vmacSta_p->Mib802dot11;
				/*Store RSSI */
				*(vmacSta_p->ShadowMib802dot11->mib_Rssi) =
					*(mib->mib_Rssi) = rssi;
			} else
#endif
				goto out;
		}
		/* check if status has a specific error bit (bit 7)set or indicates a general decrypt error */
		if ((status == (u_int32_t) GENERAL_DECRYPT_ERR) ||
		    (status & (u_int32_t) DECRYPT_ERR_MASK)) {
			wlpptr->netDevStats.rx_frame_errors++;

			/* check if status is not equal to 0xFF */
			/* the 0xFF check is for backward compatibility */
			if (status != (u_int32_t) GENERAL_DECRYPT_ERR) {
				/* If the status indicates it is a MIC error call the appropriate handler */
				/* also check that this is not an ICV error.                              */
				if (((status & (~DECRYPT_ERR_MASK)) &
				     TKIP_DECRYPT_MIC_ERR) &&
				    !((status &
				       (WEP_DECRYPT_ICV_ERR |
					TKIP_DECRYPT_ICV_ERR)))) {
#ifdef CLIENT_SUPPORT
					if (wh->FrmCtl.FromDs == 1) {
						MICCounterMeasureInvoke_Sta
							(vmacEntry_p,
							 IS_GROUP((UINT8 *) &
								  (wh->addr1)));
					} else
#endif
					{
						MrvlMICErrorHdl(vmacSta_p, 0);
					}
				}
			}
			goto err;
		}
#ifdef REORDERING
		SeqNo = le16_to_cpu(*(u_int16_t *) (wh->seq)) >>
			IEEE80211_SEQ_SEQ_SHIFT;
#ifdef BA_REORDER_FAST_DATA
fastdatareorder:
#endif
#ifdef CLIENT_SUPPORT
		if (!stationPacket) {
#endif
			if (*(mib->mib_wdsEnable) &&
			    (skb->protocol & WL_WLAN_TYPE_WDS))
				// WDS enable and SA adress is bridge Mac address, the bridge Mac address is different with wdevX Mac address
				pStaInfo =
					extStaDb_GetStaInfoStn(vmacSta_p,
							       stnid);
			else
				pStaInfo =
					extStaDb_GetStaInfo(vmacSta_p,
							    (IEEEtypes_MacAddr_t
							     *) & wlpptr->
							    wlpd_p->
							    mac_addr_sta_ta
							    /*&(wh->addr2) */ ,
							    STADB_UPDATE_AGINGTIME
							    | STADB_NO_BLOCK);
			if (pStaInfo) {
				if ((pStaInfo->State != ASSOCIATED) &&
				    !pStaInfo->AP) {
#ifdef MULTI_AP_SUPPORT
					if (pStaInfo->MultiAP_4addr == 0)
#endif
						goto deauth;
				}
			} else {
				goto deauth;
			}
#ifdef CLIENT_SUPPORT
		} else {
			/* station packet get StaInfo for remote Ap */
			if ((pStaInfo =
			     extStaDb_GetStaInfo(vmacSta_p,
						 (IEEEtypes_MacAddr_t *)
						 GetParentStaBSSID((vmacEntry_p)->phyHwMacIndx), STADB_UPDATE_AGINGTIME | STADB_NO_BLOCK)) == NULL)
				goto blkackoutcontinue;
		}
#endif
#ifdef MCAST_PS_OFFLOAD_SUPPORT
		macMgmtMlme_UpdatePwrMode(vmacSta_p, wh, pStaInfo);
#endif
#ifdef SOC_W906X
		if (prssiPaths != NULL) {	// valid rssiPath
			pStaInfo->RSSI = rssi;
			memcpy(&pStaInfo->RSSI_path, prssiPaths,
			       sizeof(RssiPathInfo_t));
		}

		if (frame_ctlp->Subtype & BIT(3))	//QoS Data Subtype
			tid = ampdu_qos & 0x7;
		else
			tid = MAX_TID;	//Non-QoS

#else
		pStaInfo->RSSI_path = *((RssiPathInfo_t *) & rssiPaths);
#endif /* SOC_W906X */

#ifdef AMPDU_DEBUG
		//printk("** blk ack pck received , SeqNo = %d ExpectedSqNo = %d ampdu_qos = %x\n", SeqNo, wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->StnId].CurrentSeqNo[tid], ampdu_qos);
#endif

		/*****************************************************************************************************************
		******************************************************************************************************************
		   START OF AMPDU RECEIVING!!

		******************************************************************************************************************
		*****************************************************************************************************************/
		{
#ifdef SOC_W906X
			Ampdu_Pck_Reorder_t *baRxInfo;

			baRxInfo =
				&wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->
								 StnId];

			//If QoS station and ADDBA is done
			if ((tid < MAX_TID) &&
			    (baRxInfo->AddBaReceive[tid] == TRUE)) {
				SPIN_LOCK(&baRxInfo->ba[tid].BAreodrLock);
				//Unicast and QoS pkt
				if (!isBcastPkt &&
				    ((wh->FrmCtl.Subtype == QoS_DATA) ||
				     (wh->FrmCtl.Subtype == QoS_DATA_CF_ACK) ||
				     (wh->FrmCtl.Subtype == QoS_DATA_CF_POLL) ||
				     (wh->FrmCtl.Subtype ==
				      QoS_DATA_CF_ACK_CF_POLL))) {

					UINT32 winStartB, leastSeqNo;
					UINT32 storedBufCnt, bufIndex;
					UINT32 id, cardindex;

					winStartB = baRxInfo->ba[tid].winStartB;
					leastSeqNo =
						baRxInfo->ba[tid].leastSeqNo;
					storedBufCnt =
						baRxInfo->ba[tid].storedBufCnt;

					id = pStaInfo->StnId;

					if (wlpptr->master) {
						cardindex =
							((NETDEV_PRIV_P
							  (struct wlprivate,
							   wlpptr->master)))->
							cardindex;
					} else {
						cardindex = wlpptr->cardindex;
					}

					//Expected seqno matching incoming seqno, send to host. Should be getting till last msdu with same seqno sequentially
					if (winStartB == SeqNo) {
						bufIndex =
							winStartB %
							MAX_BA_REORDER_BUF_SIZE;

						DBG_BAREORDER_OOR(pStaInfo,
								  ((cardindex <<
								    16) | id),
								  tid, 1,
								  winStartB,
								  SeqNo)
							//Check duplicate and store skb to AmsduQ if needed
							if (BA_CheckAmsduDup
							    (&baRxInfo->ba[tid],
							     bufIndex, skb,
							     LMFbit,
							     &pStaInfo->pn->
							     ucRxQueues[tid],
							     secMode, SeqNo,
							     pn)) {
							vmacSta_p->
								BA_RodrDupDropCnt++;
							pStaInfo->
								rxBaStats[tid].
								BA_RodrDupDropCnt++;
							DBG_BAREORDER_SN
								(pStaInfo,
								 ((cardindex <<
								   16) | id),
								 tid, 0,
								 baRxInfo->
								 ba[tid].
								 winStartB,
								 SeqNo)
								SPIN_UNLOCK
								(&baRxInfo->
								 ba[tid].
								 BAreodrLock);
							goto err;	// Drop packet due to duplicate   
						}
						storedBufCnt =
							baRxInfo->ba[tid].
							storedBufCnt;

						//Received last amsdu of winStartB, flush to host.
						if (baRxInfo->ba[tid].
						    AmsduQ[bufIndex].state ==
						    2) {
							baRxInfo->ba[tid].
								winStartB =
								BA_flushSequencialData
								(dev, pStaInfo,
								 &baRxInfo->
								 ba[tid],
								 ((winStartB <<
								   16) |
								  storedBufCnt),
								 &pStaInfo->pn->
								 ucRxQueues
								 [tid],
								 &wlexcept_p->
								 badPNcntUcast,
								 &wlpptr->
								 wlpd_p->
								 drv_stats_val.
								 rx_data_ucast_pn_pass_cnt,
								 tid);
							storedBufCnt =
								baRxInfo->
								ba[tid].
								storedBufCnt;

							BA_TimerActivateCheck
								(dev, pStaInfo,
								 baRxInfo, tid,
								 SeqNo, 0);

							DBG_BAREORDER_SN
								(pStaInfo,
								 ((cardindex <<
								   16) | id),
								 tid, 1,
								 baRxInfo->
								 ba[tid].
								 winStartB,
								 SeqNo)
						} else {
							if (storedBufCnt == 1) {
								baRxInfo->
									ba[tid].
									leastSeqNo
									= SeqNo;
							}

							DBG_BAREORDER_SN
								(pStaInfo,
								 ((cardindex <<
								   16) | id),
								 tid, 2,
								 baRxInfo->
								 ba[tid].
								 winStartB,
								 SeqNo)
						}

						cnt = 1;
						SPIN_UNLOCK(&baRxInfo->ba[tid].
							    BAreodrLock);
						skb = NULL;
						goto err;
					} else	//(winStartB != SeqNo)
					{
						UINT32 seqDelta;
						UINT32 wEnd;
						UINT32 endExt;
						UINT32 winSizeB_minus1;

						winSizeB_minus1 =
							baRxInfo->ba[tid].
							winSizeB - 1;
						wEnd = (winStartB +
							winSizeB_minus1) &
							BA_MAX_SEQ_NUM;
						endExt = (winStartB + 2048) & BA_MAX_SEQ_NUM;	// winStartB+2^11

						seqDelta =
							BA_getSeqDelta(((wEnd <<
									 16) |
									endExt),
								       winStartB,
								       SeqNo,
								       winSizeB_minus1);

						// The SN is out of boundary(less then winStartB or greater equal than winStartB+2^11)
						if (seqDelta == 0) {
							UINT32 dmemaddr = 0x63C;
							UINT32 val;

							if (wfa_11ax_pf) {
								val = cpu_to_le32(*(volatile unsigned int *)(wlpptr->ioBase0 + dmemaddr));
								*(volatile
								  unsigned int
								  *)(wlpptr->
								     ioBase0 +
								     dmemaddr) =
							       le32_to_cpu(val +
									   1);
							}
							vmacSta_p->
								BA_RodrOoRDropCnt++;
							pStaInfo->
								rxBaStats[tid].
								BA_RodrOoRDropCnt++;

#ifdef DEBUG_BAREORDER
							if (((dbg_BAredr_cardindex << 16) | dbg_BAredr_id) == ((cardindex << 16) | id)) {
								UINT32 index,
									OoR_idx;

								dbg_BAredr_OOR_cont++;
								if (dbg_BAredr_OOR_cont > 1) {
									dbg_BAredr_OOR_cont = 0xF;	//differentiate between 1st occurence of OOR and subsequent continous OOR
								}

								if (dbg_BAredr_OOR_cnt < (DBG_BAREORDER_OOR_MASK - 5)) {
									OoR_idx = dbg_BAredr_OOR_cnt++;
									dbg_BAredr_OOR
										[OoR_idx
										 &
										 DBG_BAREORDER_OOR_MASK]
										=
										(tid
										 <<
										 28)
										|
										(dbg_BAredr_OOR_cont
										 <<
										 24)
										|
										(winStartB
										 <<
										 12)
										|
										(SeqNo);
									//dbg_BAredr_OOR_Sta[OoR_idx & DBG_BAREORDER_OOR_MASK] = (pStaInfo->Addr[4]<<24) |(pStaInfo->Addr[5]<<16) | (id&0xFFFF);

									//get previous 3 seqno history
									index = dbg_BAredr_SN_cnt;
									index = (index - 1) & DBG_BAREORDER_SN_MASK;
									OoR_idx = dbg_BAredr_OOR_cnt++;
									dbg_BAredr_OOR
										[OoR_idx
										 &
										 DBG_BAREORDER_OOR_MASK]
										=
										dbg_BAredr_SN
										[index];
									//dbg_BAredr_OOR_Sta[OoR_idx & DBG_BAREORDER_OOR_MASK] = dbg_BAredr_Sta[index];

									index = (index - 1) & DBG_BAREORDER_SN_MASK;
									OoR_idx = dbg_BAredr_OOR_cnt++;
									dbg_BAredr_OOR
										[OoR_idx
										 &
										 DBG_BAREORDER_OOR_MASK]
										=
										dbg_BAredr_SN
										[index];
									//dbg_BAredr_OOR_Sta[OoR_idx & DBG_BAREORDER_OOR_MASK] = dbg_BAredr_Sta[index];

									index = (index - 1) & DBG_BAREORDER_SN_MASK;
									OoR_idx = dbg_BAredr_OOR_cnt++;
									dbg_BAredr_OOR
										[OoR_idx
										 &
										 DBG_BAREORDER_OOR_MASK]
										=
										dbg_BAredr_SN
										[index];
									//dbg_BAredr_OOR_Sta[OoR_idx & DBG_BAREORDER_OOR_MASK] = dbg_BAredr_Sta[index];

									OoR_idx = dbg_BAredr_OOR_cnt;
									dbg_BAredr_OOR
										[OoR_idx
										 &
										 DBG_BAREORDER_OOR_MASK]
										=
										0xdeadbeef;
									//dbg_BAredr_OOR_Sta[OoR_idx & DBG_BAREORDER_OOR_MASK] = 0xdeadbeef;
								}
							}
#endif
							if (wfa_11ax_pf) {

								//can add print here for winStartB, SeqNo, pStaInfo->StnId, pStaInfo->Addr

								ba_debug_buf
									[temp_index].
									winStartB
									=
									winStartB;
								ba_debug_buf
									[temp_index].
									SeqNo =
									SeqNo;
								ba_debug_buf
									[temp_index].
									StnId =
									pStaInfo->
									StnId;
								IEEE80211_ADDR_COPY
									(ba_debug_buf
									 [temp_index].
									 Addr,
									 pStaInfo->
									 Addr);
								ba_debug_buf
									[temp_index].
									lo_dword_addr
									=
									pCfhul->
									hdr.
									lo_dword_addr;

								temp_index++;
								if (temp_index
								    >= 256)
									temp_index
										=
										0;
							}
							///printk("winStartB:0x%X SeqNo:0x%X\n", winStartB, SeqNo);
							///printk("StnId:0x%X Addr:%s\n", pStaInfo->StnId, mac_display(pStaInfo->Addr));
							///printk("lo_dword_addr:0x%X\n", pCfhul->hdr.lo_dword_addr);

							SPIN_UNLOCK(&baRxInfo->
								    ba[tid].
								    BAreodrLock);
							goto err;	// Drop packet
						}

						DBG_BAREORDER_OOR(pStaInfo,
								  ((cardindex <<
								    16) | id),
								  tid, 2,
								  winStartB,
								  SeqNo)
							//From winStartB to incoming seqno is more than winSizeB, so need to flush and move winStartB. 
							//In the end, winStartB + winSizeB -1 == seqno (total 64 count from winStartB to seqno)
							if ((seqDelta >
							     winSizeB_minus1)) {
							UINT32 winDelta = seqDelta - winSizeB_minus1;	// moving window
							UINT32 temp;

							if (storedBufCnt != 0) {
								temp = ((storedBufCnt & 0xFF) << 24) | ((leastSeqNo & 0xFFF) << 12) | (winStartB & 0xFFF);
								baRxInfo->
									ba[tid].
									winStartB
									=
									BA_flushAnyData
									(dev,
									 pStaInfo,
									 &baRxInfo->
									 ba
									 [tid],
									 temp,
									 (((baRxInfo->ba[tid].winSizeB) << 16) | winDelta), &pStaInfo->pn->ucRxQueues[tid], &wlexcept_p->badPNcntUcast, &wlpptr->wlpd_p->drv_stats_val.rx_data_ucast_pn_pass_cnt, tid);
								//storedBufCnt = baRxInfo->ba[tid].storedBufCnt;
								leastSeqNo =
									baRxInfo->
									ba[tid].
									leastSeqNo;

								//If after flush, winStartB == SeqNo, flush to host
								if (baRxInfo->
								    ba[tid].
								    winStartB ==
								    SeqNo) {
									bufIndex = SeqNo % MAX_BA_REORDER_BUF_SIZE;

									//Check duplicate and store skb to AmsduQ if needed
									if (BA_CheckAmsduDup(&baRxInfo->ba[tid], bufIndex, skb, LMFbit, &pStaInfo->pn->ucRxQueues[tid], secMode, SeqNo, pn)) {
										vmacSta_p->
											BA_RodrDupDropCnt++;
										pStaInfo->
											rxBaStats
											[tid].
											BA_RodrDupDropCnt++;

										DBG_BAREORDER_SN
											(pStaInfo,
											 ((cardindex << 16) | id), tid, 3, baRxInfo->ba[tid].winStartB, SeqNo)
											SPIN_UNLOCK
											(&baRxInfo->
											 ba
											 [tid].
											 BAreodrLock);
										goto err;	// Drop packet due to duplicate   
									}
									storedBufCnt
										=
										baRxInfo->
										ba
										[tid].
										storedBufCnt;

									//Received last amsdu of winStartB, flush to host.
									if (baRxInfo->ba[tid].AmsduQ[bufIndex].state == 2) {
										baRxInfo->
											ba
											[tid].
											winStartB
											=
											BA_flushSequencialData
											(dev,
											 pStaInfo,
											 &baRxInfo->
											 ba
											 [tid],
											 ((baRxInfo->ba[tid].winStartB << 16) | storedBufCnt), &pStaInfo->pn->ucRxQueues[tid], &wlexcept_p->badPNcntUcast, &wlpptr->wlpd_p->drv_stats_val.rx_data_ucast_pn_pass_cnt, tid);
									} else {
										if (storedBufCnt == 1) {
											baRxInfo->
												ba
												[tid].
												leastSeqNo
												=
												SeqNo;
										}
									}

									BA_TimerActivateCheck
										(dev,
										 pStaInfo,
										 baRxInfo,
										 tid,
										 SeqNo,
										 0);

									cnt = 1;
									DBG_BAREORDER_SN
										(pStaInfo,
										 ((cardindex << 16) | id), tid, 4, baRxInfo->ba[tid].winStartB, SeqNo)
										SPIN_UNLOCK
										(&baRxInfo->
										 ba
										 [tid].
										 BAreodrLock);
									skb = NULL;
									goto err;
								} else {
									DBG_BAREORDER_SN
										(pStaInfo,
										 ((cardindex << 16) | id), tid, 5, baRxInfo->ba[tid].winStartB, SeqNo)
								}
							} else {
								baRxInfo->
									ba[tid].
									winStartB
									=
									(baRxInfo->
									 ba
									 [tid].
									 winStartB
									 +
									 winDelta)
									&
									BA_MAX_SEQ_NUM;

								DBG_BAREORDER_SN
									(pStaInfo,
									 ((cardindex << 16) | id), tid, 6, baRxInfo->ba[tid].winStartB, SeqNo)
							}
						}

						bufIndex =
							SeqNo %
							MAX_BA_REORDER_BUF_SIZE;

						//Check duplicate and store skb to buf if needed
						if (BA_CheckAmsduDup
						    (&baRxInfo->ba[tid],
						     bufIndex, skb, LMFbit,
						     &pStaInfo->pn->
						     ucRxQueues[tid], secMode,
						     SeqNo, pn)) {
							vmacSta_p->
								BA_RodrDupDropCnt++;
							pStaInfo->
								rxBaStats[tid].
								BA_RodrDupDropCnt++;

							DBG_BAREORDER_SN
								(pStaInfo,
								 ((cardindex <<
								   16) | id),
								 tid, 7,
								 baRxInfo->
								 ba[tid].
								 winStartB,
								 SeqNo)

								SPIN_UNLOCK
								(&baRxInfo->
								 ba[tid].
								 BAreodrLock);
							goto err;	// Drop packet due to duplicate   
						}
						storedBufCnt =
							baRxInfo->ba[tid].
							storedBufCnt;

						if (storedBufCnt >
						    MAX_BA_REORDER_BUF_SIZE) {
							DEBUG_REORDER_PRINT(("BA rodr: Store cnt > 64. Should not happen\n"));
						}

						//Update least seqno in buffer
						if (storedBufCnt == 0) {
							DEBUG_REORDER_PRINT(("AMSDU store conflict\n"));
							vmacSta_p->
								BA_RodrAmsduEnQCnt++;
							pStaInfo->
								rxBaStats[tid].
								BA_RodrAmsduEnQCnt++;

							DBG_BAREORDER_SN
								(pStaInfo,
								 ((cardindex <<
								   16) | id),
								 tid, 8,
								 baRxInfo->
								 ba[tid].
								 winStartB,
								 SeqNo)
								SPIN_UNLOCK
								(&baRxInfo->
								 ba[tid].
								 BAreodrLock);
							goto err;	// Drop packet due to duplicate
						} else if (storedBufCnt == 1)	//only 1 amsdu is stored
						{
							baRxInfo->ba[tid].
								leastSeqNo =
								SeqNo;
						} else {
							if ((UINT32)
							    (baRxInfo->ba[tid].
							     leastSeqNo -
							     SeqNo) <
							    baRxInfo->ba[tid].
							    winSizeB) {
								baRxInfo->
									ba[tid].
									leastSeqNo
									= SeqNo;
							}
						}
						DBG_BAREORDER_SN(pStaInfo,
								 ((cardindex <<
								   16) | id),
								 tid, 9,
								 baRxInfo->
								 ba[tid].
								 winStartB,
								 SeqNo)

							BA_TimerActivateCheck
							(dev, pStaInfo,
							 baRxInfo, tid, SeqNo,
							 1);

						cnt = 1;
						skb = NULL;
						SPIN_UNLOCK(&baRxInfo->ba[tid].
							    BAreodrLock);
						goto err;
					}	//end (winStartB != SeqNo)
#ifdef RX_REPLAY_DETECTION
					process_pn_check = FALSE;
#endif
				}
				SPIN_UNLOCK(&baRxInfo->ba[tid].BAreodrLock);
			}
#ifdef RX_REPLAY_DETECTION
			//1. Mcast/Bcast or no-aggregrated 2. Legacy mode or not aggregated 
			if (process_pn_check) {
				UINT32 *badPNcnt, *staBadPNcnt, *passPNcnt;
				rx_queue_t *rq;

				if (frame_ctlp->Wep && pStaInfo && pn) {
					if (isBcastPkt)	//Mcast/Bcast
					{
						rq = &pStaInfo->pn->
							mcRxQueues[tid];
						badPNcnt =
							&wlexcept_p->
							badPNcntMcast;
						staBadPNcnt =
							&pStaInfo->pn->
							mcastBadCnt;
						passPNcnt =
							&wlpptr->wlpd_p->
							drv_stats_val.
							rx_data_mcast_pn_pass_cnt;
					} else {
						rq = &pStaInfo->pn->
							ucRxQueues[tid];
						badPNcnt =
							&wlexcept_p->
							badPNcntUcast;
						staBadPNcnt =
							&pStaInfo->pn->
							ucastBadCnt;
						passPNcnt =
							&wlpptr->wlpd_p->
							drv_stats_val.
							rx_data_ucast_pn_pass_cnt;
					}

					if (pn_replay_detection
					    (IEEE_TYPE_DATA, secMode, pn, rq,
					     SeqNo, badPNcnt, passPNcnt)) {
						(*staBadPNcnt)++;
						//printk("data_pn_replay_detect in aggregration ::: drop packet pn check fail\n");
						goto out;	//drop_packet     
					}
				}
			}
#endif

#else //REORDER_2B_REMOVED
			//printk("input pStaInfo = %x Aid = %d IsStaQSTA = %x \n", pStaInfo, pStaInfo->Aid, pStaInfo->IsStaQSTA);
			if (pStaInfo->IsStaQSTA) {
				/* check if rx BA has been added */
				if (wlpptr->wlpd_p->
				    AmpduPckReorder[pStaInfo->Aid].
				    AddBaReceive[tid] == TRUE) {
					/* check if it is a unicast */
					if (!(wh->addr1[0] & 0x01)) {
						/* check if it is a QoS pkt */
						if ((wh->FrmCtl.Subtype ==
						     QoS_DATA) ||
						    (wh->FrmCtl.Subtype ==
						     QoS_DATA_CF_ACK) ||
						    (wh->FrmCtl.Subtype ==
						     QoS_DATA_CF_POLL) ||
						    (wh->FrmCtl.Subtype ==
						     QoS_DATA_CF_ACK_CF_POLL)) {
#ifdef AMPDU_DEBUG
							printk("** 11 blk ack pck received , SeqNo = %d ExpectedSqNo = %d ampdu_qos = %x\n", SeqNo, wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].CurrentSeqNo[tid], ampdu_qos);
#endif

							/** check for qos pck **/
							if (wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].ReOrdering[tid] == FALSE) {			/** previous pck is in order **/
								/*****************************************************************************************************************
								******************************************************************************************************************
								   Previous ampdu pck is in order!!

								******************************************************************************************************************
								*****************************************************************************************************************/
								if (SeqNo == wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].CurrentSeqNo[tid]) {	/** found the right one **/
									wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].Time[tid] = jiffies;
									wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].CurrentSeqNo[tid] = (wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].CurrentSeqNo[tid] + 1) % MAX_AC_SEQNO;
									goto blkackoutcontinue;	// go to normal path
								} else {			/** Out of Seq **/
#ifdef INTERNAL_FLUSH_TIMER
									//Added the following to handle packets delay problem when receiving out of order frames frequently
									if (jiffies - wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].Time[tid] > *(mib->mib_BAReorder_holdtime)) {
										wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].Time[tid] = jiffies;
										wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].CurrentSeqNo[tid] = (SeqNo + 1) % MAX_AC_SEQNO;	  /** assuming next pck **/
										goto blkackoutcontinue;
									}
#endif
									//      printk("Out of Seq 11!!\n");
									if (wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].CurrentSeqNo[tid] < SeqNo) {	/** Valid case **/
										if (SeqNo - wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].CurrentSeqNo[tid] > (MAX_AMPDU_REORDER_BUFFER - 1)) {
											/** overrun condition !!!!!!!!!!!**/
											/** too many pck is missing, time to reset the cnt **/
											//      printk("Error condition 1\n");
											//      printk("3.  SeqNo = %d Expected Seqno= %d \n",SeqNo, AmpduPckReorder[pStaInfo->Aid].CurrentSeqNo[Priority]);

											//no need       Ampdu_Flush_All_Pck_in_Reorder_queue(dev,pStaInfo->Aid, tid);
											wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].ReOrdering[tid] = FALSE;
											wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].CurrentSeqNo[tid] = (SeqNo + 1) % MAX_AC_SEQNO;	/**  assuming next pck **/
											goto blkackoutcontinue;
										}

										/** valid condition **/
										{
											int tempvalue = SeqNo - wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].CurrentSeqNo[tid];
											if (wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].pFrame[tid][tempvalue] != NULL) {
												DEBUG_REORDER
													();
												wl_free_skb
													(skb);
											} else
												wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].pFrame[tid][tempvalue] = skb;
										}
										//AmpduPckReorder[pStaInfo->Aid].pFrame[Priority][SeqNo-AmpduPckReorder[pStaInfo->Aid].CurrentSeqNo[Priority]]= skb;
										wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].ExpectedSeqNo[tid][SeqNo - wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].CurrentSeqNo[tid]] = SeqNo;
#ifdef INTERNAL_FLUSH_TIMER
										{
											struct reorder_t *ro_p = wl_kmalloc_autogfp(sizeof(struct reorder_t));
											ro_p->dev = dev;
#ifdef SOC_W906X
											ro_p->pStaInfo = pStaInfo;
#else
											ro_p->Aid = pStaInfo->Aid;
#endif /* SOC_W906X */
											ro_p->tid = tid;
											ro_p->SeqNo = SeqNo;
											TimerFireInByJiffies
												(&wlpptr->
												 wlpd_p->
												 AmpduPckReorder
												 [pStaInfo->
												  Aid].
												 timer
												 [tid],
												 1,
												 &ReorderingTimerProcess,
												 (UINT8
												  *)
												 ro_p,
												 *
												 (mib->
												  mib_BAReorder_holdtime));
										}
#endif
										skb = NULL;
										wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].ReOrdering[tid] = TRUE;
										wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].Time[tid] = jiffies;
										goto err;
									} else {
										int tempvalue;
										/** possible rollover condition **/
										tempvalue
											=
											MAX_AC_SEQNO
											-
											wlpptr->
											wlpd_p->
											AmpduPckReorder
											[pStaInfo->
											 Aid].
											CurrentSeqNo
											[tid]
											+
											SeqNo;
										if (tempvalue < MAX_AMPDU_REORDER_BUFFER) {
											if (wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].pFrame[tid][tempvalue] != NULL) {
												wl_free_skb
													(skb);
												DEBUG_REORDER
													();
											} else

												wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].pFrame[tid][tempvalue] = skb;
											wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].ExpectedSeqNo[tid][tempvalue] = SeqNo;

										} else {
											/** treat it as most likely overflow condition **/
											/** too many pck is missing, time to reset the cnt **/
#ifdef SOC_W906X
											Ampdu_Flush_All_Pck_in_Reorder_queue
												(dev,
												 pStaInfo,
												 tid);
#else
											Ampdu_Flush_All_Pck_in_Reorder_queue
												(dev,
												 pStaInfo->
												 Aid,
												 tid);
#endif /* SOC_W906X */

											wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].ReOrdering[tid] = FALSE;
											wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].CurrentSeqNo[tid] = (SeqNo + 1) % MAX_AC_SEQNO;	/**  assuming next pck **/
											TimerDisarmByJiffies
												(&wlpptr->
												 wlpd_p->
												 AmpduPckReorder
												 [pStaInfo->
												  Aid].
												 timer
												 [tid],
												 1);
											goto blkackoutcontinue;
										}
#ifdef INTERNAL_FLUSH_TIMER
										{
											struct reorder_t *ro_p = wl_kmalloc_autogfp(sizeof(struct reorder_t));
											ro_p->dev = dev;
#ifdef SOC_W906X
											ro_p->pStaInfo = pStaInfo;
#else
											ro_p->Aid = pStaInfo->Aid;
#endif /* SOC_W906X */
											ro_p->tid = tid;
											ro_p->SeqNo = SeqNo;
											TimerFireInByJiffies
												(&wlpptr->
												 wlpd_p->
												 AmpduPckReorder
												 [pStaInfo->
												  Aid].
												 timer
												 [tid],
												 1,
												 &ReorderingTimerProcess,
												 (UINT8
												  *)
												 ro_p,
												 *
												 (mib->
												  mib_BAReorder_holdtime));
										}
#endif
										skb = NULL;
										wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].ReOrdering[tid] = TRUE;
										wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].Time[tid] = jiffies;
										goto err;
									}

								}

							} else { /** reordering has happen **/
								//printk("Reordering has started\n");
								 /*****************************************************************************************************************
								 ******************************************************************************************************************
								    Previous ampdu pck reorder has started !!

								 ******************************************************************************************************************
								 *****************************************************************************************************************/
								if (SeqNo ==
								    wlpptr->
								    wlpd_p->
								    AmpduPckReorder
								    [pStaInfo->
								     Aid].
								    CurrentSeqNo
								    [tid]) {
									if (wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].pFrame[tid][0] != NULL) {
										wl_free_skb
											(wlpptr->
											 wlpd_p->
											 AmpduPckReorder
											 [pStaInfo->
											  Aid].
											 pFrame
											 [tid]
											 [0]);
										DEBUG_REORDER
											();
									}
									wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].pFrame[tid][0] = skb;
									skb = NULL;
									wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].ExpectedSeqNo[tid][0] = SeqNo;
									/** time to handle flushing for this pck **/
									for (i =
									     0;
									     i <
									     MAX_AMPDU_REORDER_BUFFER;
									     i++)
									{
										/** flush all subsequent pck until the next hole **/
#ifdef SOC_W906X
										if (flush_blockack_pck(dev, i, pStaInfo, tid) == 0) {
#else
										if (flush_blockack_pck(dev, i, pStaInfo->Aid, tid) == 0) {
#endif /* SOC_W906X */
											wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].CurrentSeqNo[tid] = (wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].CurrentSeqNo[tid] + i) % MAX_AC_SEQNO;
											blockack_reorder_pck
												(dev,
												 i,
												 pStaInfo->
												 Aid,
												 tid);
											break;
										}
									}

									if (Ampdu_Check_Valid_Pck_in_Reorder_queue(dev, pStaInfo->Aid, tid) == FALSE) {
										wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].ReOrdering[tid] = FALSE;
										TimerDisarmByJiffies
											(&wlpptr->
											 wlpd_p->
											 AmpduPckReorder
											 [pStaInfo->
											  Aid].
											 timer
											 [tid],
											 1);
									}
									goto err;

								} else { /** SeqNo not equal **/

									if ((jiffies - wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].Time[tid]) > *(mib->mib_BAReorder_holdtime)) {
#ifdef AMPDU_DEBUG
										printk("flushing pck due to timer expire\n");
#endif
#ifdef SOC_W906X
										Ampdu_Flush_All_Pck_in_Reorder_queue
											(dev,
											 pStaInfo,
											 tid);
#else
										Ampdu_Flush_All_Pck_in_Reorder_queue
											(dev,
											 pStaInfo->
											 Aid,
											 tid);
#endif /* SOC_W906X */
										wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].ReOrdering[tid] = FALSE;
										wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].CurrentSeqNo[tid] = (SeqNo + 1) % MAX_AC_SEQNO;	/** assuming next pck **/
										TimerDisarmByJiffies
											(&wlpptr->
											 wlpd_p->
											 AmpduPckReorder
											 [pStaInfo->
											  Aid].
											 timer
											 [tid],
											 1);
										goto blkackoutcontinue;
									}

									if (wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].CurrentSeqNo[tid] < SeqNo) {	/** Valid case **/
										//      printk("2.  SeqNo = %d Expected Seqno= %d put at %d\n",SeqNo, AmpduPckReorder[pStaInfo->Aid].CurrentSeqNo[Priority],SeqNo-AmpduPckReorder[pStaInfo->Aid].CurrentSeqNo[Priority]);
										// pFrame array index is from 0 -127 only. If SeqNo-CurrentSeqNo>=128, flush buffer so 128 is not used later as pFrame index
										if (SeqNo - wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].CurrentSeqNo[tid] >= MAX_AMPDU_REORDER_BUFFER) {
#ifdef SOC_W906X
											Ampdu_Flush_All_Pck_in_Reorder_queue
												(dev,
												 pStaInfo,
												 tid);
#else
											Ampdu_Flush_All_Pck_in_Reorder_queue
												(dev,
												 pStaInfo->
												 Aid,
												 tid);
#endif /* SOC_W906X */
											wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].ReOrdering[tid] = FALSE;
											wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].CurrentSeqNo[tid] = (SeqNo + 1) % MAX_AC_SEQNO;	/** assuming next pck **/
											TimerDisarmByJiffies
												(&wlpptr->
												 wlpd_p->
												 AmpduPckReorder
												 [pStaInfo->
												  Aid].
												 timer
												 [tid],
												 1);
											goto blkackoutcontinue;

										}
										if (wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].pFrame[tid][SeqNo - wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].CurrentSeqNo[tid]] != NULL) {
											wl_free_skb
												(skb);
											DEBUG_REORDER
												();
										} else

											wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].pFrame[tid][SeqNo - wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].CurrentSeqNo[tid]] = skb;
										wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].ExpectedSeqNo[tid][SeqNo - wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].CurrentSeqNo[tid]] = SeqNo;
										skb = NULL;
										goto err;
									} else {
										int tempvalue;
										tempvalue
											=
											MAX_AC_SEQNO
											-
											wlpptr->
											wlpd_p->
											AmpduPckReorder
											[pStaInfo->
											 Aid].
											CurrentSeqNo
											[tid]
											+
											SeqNo;
										if (tempvalue < MAX_AMPDU_REORDER_BUFFER) {
											if (wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].pFrame[tid][tempvalue] != NULL) {
												wl_free_skb
													(skb);
												DEBUG_REORDER
													();
											} else

												wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].pFrame[tid][tempvalue] = skb;
											wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].ExpectedSeqNo[tid][tempvalue] = SeqNo;
											skb = NULL;
											goto err;
										} else {
											/** treat it as most likely overflow condition **/
											/** too many pck is missing, time to reset the cnt **/
#ifdef AMPDU_DEBUG
											printk("Error condition 4\n");
#endif
#ifdef SOC_W906X
											Ampdu_Flush_All_Pck_in_Reorder_queue
												(dev,
												 pStaInfo,
												 tid);
#else
											Ampdu_Flush_All_Pck_in_Reorder_queue
												(dev,
												 pStaInfo->
												 Aid,
												 tid);
#endif
											wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].ReOrdering[tid] = FALSE;
											wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].CurrentSeqNo[tid] = (SeqNo + 1) % MAX_AC_SEQNO;	/** assuming next pck **/
											TimerDisarmByJiffies
												(&wlpptr->
												 wlpd_p->
												 AmpduPckReorder
												 [pStaInfo->
												  Aid].
												 timer
												 [tid],
												 1);
											goto blkackoutcontinue;

										}
									}
								}
							}
						}
					}
					//else
					{
						//      printk("Error condition 5\n");
					}
				} else {
					/** Receive Ampdu pck but not addba !!!!  ****/
				}
			} else {
#ifdef AMPDU_DEBUG
				printk("Not qos station\n");
#endif
			}

#endif

#endif // end of #ifdef REORDERING
blkackoutcontinue:
#ifdef SOC_W906X
			if (isfastdatareorder)
				goto fastdatareordercontinue;
#endif
			{
				extStaDb_StaInfo_t *pStaInfo = NULL;
				if (skb->protocol & WL_WLAN_TYPE_AMSDU) {
					cnt = DeAmsduPck(vmacSta_p->dev, skb);
					return cnt;
				}
				skb = DeFragPck(vmacSta_p->dev, skb, &pStaInfo);
				if (skb == NULL) {
					goto err;
				}
				skb = ieee80211_decap(vmacSta_p->dev, skb,
						      pStaInfo, 0);
				if (pStaInfo) {
					pStaInfo->rx_packets++;
					pStaInfo->rx_bytes += skb->len;
				}
			}
#ifdef REORDERING
		}
#endif
		if (skb == NULL) {
			goto err;
		}
		cnt = ForwardFrame(dev, skb);
		return cnt;
	case IEEE_TYPE_MANAGEMENT:
		WLDBG_INFO(DBG_LEVEL_11, "%s , ---IEEE_TYPE_MANAGEMENT---\n",
			   __func__);

#ifdef RX_REPLAY_DETECTION
		if (frame_ctlp->Wep && cfhul_template && (!wfa_11ax_pf)) {
			pn = (UINT8 *) cfhul_template +
				SMAC_CFHUL_MAC_HDR_OFFSET + machdrLen;

			if (mgmt_pn_replay_detect
			    (dev, skb, wh, SeqNo, machdrLen, secMode, pn))
				goto out;	//drop packet
		}
#endif
#ifdef AUTOCHANNEL
		if (*(vmacSta_p->Mib802dot11->mib_autochannel) &&
		    ((!vmacSta_p->preautochannelfinished) ||
		     vmacSta_p->acs_cur_bcn)) {
			struct IEEEtypes_Frame_t *wlanMsg_p =
				(IEEEtypes_Frame_t *) ((UINT8 *) skb->data - 2);

			wlanMsg_p->Hdr.FrmBodyLen = skb->len;
			if (wh->FrmCtl.Type == IEEE_TYPE_MANAGEMENT &&
			    wlanMsg_p->Hdr.FrmCtl.Subtype == IEEE_MSG_BEACON) {
				MSAN_neighbor_bcnproc(dev, wlanMsg_p, skb->len,
						      prssiPaths, SCAN_BY_ACS);
			}
		}

		if (vmacSta_p->StopTraffic) {
			struct IEEEtypes_Frame_t *wlanMsg_p =
				(IEEEtypes_Frame_t *) ((UINT8 *) skb->data - 2);

			//only let beacon pass for handling 20/40 coexisting
			if (wlanMsg_p->Hdr.FrmCtl.Subtype != IEEE_MSG_BEACON)
				goto out;	//drop packet
		}
#endif /* AUTOCHANNEL */
		if (checkforus) {
			goto out;
		}
#ifdef MBSS
		if (!IS_GROUP((UINT8 *) & (wh->addr1))) {
			vmacApInfo_t *vmactem_p;
			vmacApInfo_t *vmacwds_p;
			vmactem_p = vmacGetMBssByAddr(vmacSta_p, (UINT8 *) & (wh->addr3));	//If sent by client, addr3 is AP's bssid
#ifdef WDS_FEATURE
#ifdef DUPLICATED_MGMT_DBG
			{
#else
			if (wh->FrmCtl.Subtype == IEEE_MSG_QOS_ACTION) {
#endif
				/*Use vmac for extStaDb_GetStaInfo because vmac and parent can have different bssid */
				if (vmactem_p) {
					/*Action frame sent by client */
					pStaInfo =
						extStaDb_GetStaInfo(vmactem_p,
								    &(wh->
								      addr2),
								    STADB_DONT_UPDATE_AGINGTIME);
				} else {
					/*In WDS, if AP2 sends Action frame to AP1, addr3 is AP2's bssid, not AP1's bssid */
					/*So we use dest addr1 to find vmac in WDS case */
					vmacwds_p =
						vmacGetMBssByAddr(vmacSta_p,
								  (UINT8 *) &
								  (wh->addr1));
					if (vmacwds_p)
						pStaInfo =
							extStaDb_GetStaInfo
							(vmacwds_p,
							 &(wh->addr2),
							 STADB_DONT_UPDATE_AGINGTIME);
					else {
						/*If vmac is not found, we just use parent */
						pStaInfo =
							extStaDb_GetStaInfo
							(vmacSta_p,
							 &(wh->addr2),
							 STADB_DONT_UPDATE_AGINGTIME);
					}
				}

				if (pStaInfo && pStaInfo->wdsPortInfo) {
					pWdsPort =
						(struct wds_port *)pStaInfo->
						wdsPortInfo;
					if (pWdsPort->active)
						vmactem_p =
							vmacGetMBssByAddr
							(vmacSta_p,
							 (UINT8 *) & (wh->
								      addr1));

				}
			}
#endif
			if (vmactem_p)
				vmacSta_p = vmactem_p;
			else
				stationPacket = TRUE;
			mib = vmacSta_p->Mib802dot11;
#ifdef DUPLICATED_MGMT_DBG
			if (stationPacket)
				pStaInfo =
					extStaDb_GetStaInfo(vmacSta_p,
							    &(wh->addr1),
							    STADB_SKIP_MATCH_VAP);

			if (pStaInfo) {
				wlanMsg_p =
					(IEEEtypes_Frame_t *) ((UINT8 *) skb->
							       data - 2);
				if (pStaInfo->pre_mgmt_seq ==
				    wlanMsg_p->Hdr.SeqCtl) {
					if (wlanMsg_p->Hdr.FrmCtl.Retry) {
						wlpptr->rx_retry_mgmt_cnt++;
						WLDBG_ERROR(DBG_LEVEL_0,
							    "RX %d duplicated subtype: %x MGMT packets\n",
							    wlpptr->
							    rx_retry_mgmt_cnt,
							    wh->FrmCtl.Subtype);
					}
				} else if (pStaInfo->pre_mgmt_seq <
					   wlanMsg_p->Hdr.SeqCtl) {
					pStaInfo->pre_mgmt_seq =
						wlanMsg_p->Hdr.SeqCtl;
				}
			}
#endif
		} else {	//mark broadcast frame as Station packet (probe request & beacon)
			//the receiveWlanMsg will handle the packet accordingly
			stationPacket = TRUE;
		}
#endif
#ifdef AP_MAC_LINUX
		WLDBG_INFO(DBG_LEVEL_11, "**Entering receiveWlanMsg***\n");

		wlpptr->netDevStats.rx_packets++;
		wlpptr->netDevStats.rx_bytes += skb->len;
		if (dev != vmacSta_p->dev) {
			/*
			   "dev" == "vmacSta_p->dev" conditions: (rx_pkt == beacon) or (rx_pkt == prob_req)
			   Since it's 1 packet and is not specifying which vap is this packet for 
			   => only increase the counter of the master interface
			 */
			((NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev)))->
				netDevStats.rx_packets++;
			((NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev)))->
				netDevStats.rx_bytes += skb->len;
		}

#ifdef SOC_W906X
		//convert mbssid beacon to legacy beacon
		{
			struct sk_buff_head skbList;
			struct sk_buff *skb2;
			u8 num;

			skb_queue_head_init(&skbList);
			//destructure MBSSID beacon frame to legacy beacons. Keep native the MBSSID frame not changed. 
			num = decomposeMBSSID(vmacSta_p->dev, skb, &skbList);
			//still indicate the native frame
			receiveWlanMsg(vmacSta_p->dev, skb, rssi,
				       stationPacket);
			//indicate legacy bcn frames extracted from the native bcn frame. 
			if (num) {
				while ((skb2 = skb_dequeue(&skbList))) {
					receiveWlanMsg(vmacSta_p->dev, skb2,
						       rssi, stationPacket);
				}
			}
		}
#else
		receiveWlanMsg(vmacSta_p->dev, skb, rssi, stationPacket);
#endif //SOC_W906X

#endif //AP_MAC_LINUX

		return cnt;

	case IEEE_TYPE_CONTROL:
		{
			extStaDb_StaInfo_t *pStaInfo;
			IEEEtypes_BA_ReqFrame_t2 *BaReqFrm;
			u_int8_t Priority;
#ifdef SOC_W8964
			u_int8_t equal = 0;
#endif /* SOC_W8964 */
			Ampdu_Pck_Reorder_t *baRxInfo;
			u_int32_t SeqNo, winStartB, winDelta, storedBufCnt;

			u_int32_t id;

			if (checkforus)
				goto out;
#ifdef REORDERING
		/** Assume this is a BAR now, since this is the only one we pass up from the firmware **/
			pStaInfo = NULL;
			BaReqFrm = (IEEEtypes_BA_ReqFrame_t2 *) skb->data;

			if (BaReqFrm->FrmCtl.Subtype != BLK_ACK_REQ) {
								  /** it is not a bar frame **/
				goto err;		/** free the pck **/
			}
			// This is a BAR pkt.
			// => Drop it to to fix WSW-6518
			{
				struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
				wlpd_p->drv_stats_val.drop_bar++;
				goto err;		/** free the pck **/
			}
			pStaInfo =
				extStaDb_GetStaInfo(vmacSta_p,
						    &(BaReqFrm->SrcAddr),
						    STADB_SKIP_MATCH_VAP |
						    STADB_NO_BLOCK);
			if (pStaInfo) {
				if (pStaInfo->State != ASSOCIATED) {
					goto err;
				}
			} else {
				goto err;
			}

#ifdef MBSS
			{
				vmacApInfo_t *vmactem_p;
				vmactem_p =
					vmacGetMBssByAddr(vmacSta_p,
							  (UINT8 *) (&BaReqFrm->
								     DestAddr));
				if (vmactem_p)
					vmacSta_p = vmactem_p;
				dev = vmacSta_p->dev;
			}
#endif
			Priority = (BaReqFrm->BA_Ctrl.TID & 0x7);

		/** Need to flush everything here if any **/
		/** If a blockack req is received, all complete MSDUs with lower sequence numbers than the starting sequence number contained in the
		   blockack Req shall be indicated to the MAC client using the MA-UNIDATA.indication primitive.  Upon arrival of a blockackreq frame, the
		   recipient shall indicate the MSDUs starting with the Starting Sequence number sequentially until there is an incomplete MSDU in the buffer **/
#ifdef MV_CPU_BE
			//printk("[%04x]\n", BaReqFrm->Seq_Ctrl.u16_data);
			BaReqFrm->Seq_Ctrl.u16_data =
				le16_to_cpu(BaReqFrm->Seq_Ctrl.u16_data);
#endif

#ifdef SOC_W906X

			baRxInfo =
				&wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->
								 StnId];
			SPIN_LOCK(&baRxInfo->ba[Priority].BAreodrLock);

			SeqNo = BaReqFrm->Seq_Ctrl.StartSeqNo;
			winStartB = baRxInfo->ba[Priority].winStartB;
			storedBufCnt = baRxInfo->ba[Priority].storedBufCnt;

			id = pStaInfo->StnId;
			if ((SeqNo != winStartB) &&
			    (BA_chkSnValid(SeqNo, winStartB) == 0)) {
				UINT32 cardindex;
				if (wlpptr->master) {
					cardindex =
						((NETDEV_PRIV_P
						  (struct wlprivate,
						   wlpptr->master)))->cardindex;
				} else {
					cardindex = wlpptr->cardindex;
				}

				if (storedBufCnt != 0)	// Only if there is at least one saved reorder buffer
				{
					UINT32 temp;

					if (winStartB > SeqNo)	// rollover
					{
						winDelta =
							(BA_MAX_SEQ_NUM + 1) -
							winStartB + SeqNo;
					} else {
						winDelta = SeqNo - winStartB;
					}
					// Any complete Data Flush from winStartB to SSN(winDelta)                
					temp = ((baRxInfo->ba[Priority].
						 storedBufCnt & 0xFF) << 24) |
						((baRxInfo->ba[Priority].
						  leastSeqNo & 0xFFF) << 12) |
						(baRxInfo->ba[Priority].
						 winStartB & 0xFFF);
					baRxInfo->ba[Priority].winStartB =
						BA_flushAnyData(dev, pStaInfo,
								&baRxInfo->
								ba[Priority],
								temp,
								(((baRxInfo->
								   ba[Priority].
								   winSizeB) <<
								  16) |
								 winDelta),
								&pStaInfo->pn->
								ucRxQueues
								[Priority],
								&wlexcept_p->
								badPNcntUcast,
								&wlpptr->
								wlpd_p->
								drv_stats_val.
								rx_data_ucast_pn_pass_cnt,
								tid);
					storedBufCnt =
						baRxInfo->ba[Priority].
						storedBufCnt;

					BA_TimerActivateCheck(dev, pStaInfo,
							      baRxInfo,
							      Priority, SeqNo,
							      0);

					DBG_BAREORDER_SN(pStaInfo,
							 ((cardindex << 16) |
							  id), Priority, 10,
							 baRxInfo->ba[Priority].
							 winStartB, SeqNo)
				} else {
					baRxInfo->ba[Priority].winStartB =
						SeqNo;

					DBG_BAREORDER_SN(pStaInfo,
							 ((cardindex << 16) |
							  id), Priority, 11,
							 baRxInfo->ba[Priority].
							 winStartB, SeqNo)
				}
			}
			SPIN_UNLOCK(&baRxInfo->ba[Priority].BAreodrLock);

#else
			//printk("starting seq = %04x, [%04x]", BaReqFrm->Seq_Ctrl.StartSeqNo, BaReqFrm->Seq_Ctrl.u16_data);
			if (wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].
			    CurrentSeqNo[Priority] <
			    BaReqFrm->Seq_Ctrl.StartSeqNo) {
			/** Make sure it is not a rollover condition **/

				if (BaReqFrm->Seq_Ctrl.StartSeqNo -
				    wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->
								    Aid].
				    CurrentSeqNo[Priority] <
				    MAX_AMPDU_REORDER_BUFFER) {
				/** Need to free everything up to that point **/
				/** Need to start flushing from here till the next hole **/

					for (i = 0;
					     i <
					     BaReqFrm->Seq_Ctrl.StartSeqNo -
					     wlpptr->wlpd_p->
					     AmpduPckReorder[pStaInfo->Aid].
					     CurrentSeqNo[Priority]; i++) {
					/** Need to continue flushing until next pck **/
#ifdef SOC_W906X
						flush_blockack_pck(dev, i, pStaInfo, Priority);
											     /** there is a hole in the pck **/
#else
						flush_blockack_pck(dev, i, pStaInfo->Aid, Priority);
												  /** there is a hole in the pck **/
#endif /* SOC_W906X */
					}

					blockack_reorder_pck(dev, i,
							     pStaInfo->Aid,
							     Priority);

					wlpptr->wlpd_p->
						AmpduPckReorder[pStaInfo->Aid].
						CurrentSeqNo[Priority] =
						BaReqFrm->Seq_Ctrl.StartSeqNo;
					wlpptr->wlpd_p->
						AmpduPckReorder[pStaInfo->Aid].
						ExpectedSeqNo[Priority][0] =
						BaReqFrm->Seq_Ctrl.StartSeqNo;

					for (i = 0;
					     i < MAX_AMPDU_REORDER_BUFFER;
					     i++) {
					/** flush all subsequent pck until the next hole **/
#ifdef SOC_W906X
						if (flush_blockack_pck
						    (dev, i, pStaInfo,
						     Priority) == 0) {
#else
						if (flush_blockack_pck
						    (dev, i, pStaInfo->Aid,
						     Priority) == 0) {
#endif /* SOC_W906X */
							wlpptr->wlpd_p->
								AmpduPckReorder
								[pStaInfo->Aid].
								CurrentSeqNo
								[Priority] =
								(wlpptr->
								 wlpd_p->
								 AmpduPckReorder
								 [pStaInfo->
								  Aid].
								 CurrentSeqNo
								 [Priority] +
								 i) %
								MAX_AC_SEQNO;
							blockack_reorder_pck
								(dev, i,
								 pStaInfo->Aid,
								 Priority);
							break;
						}
					}

					if (Ampdu_Check_Valid_Pck_in_Reorder_queue(dev, pStaInfo->Aid, Priority) == FALSE) {
						wlpptr->wlpd_p->
							AmpduPckReorder
							[pStaInfo->Aid].
							ReOrdering[Priority] =
							FALSE;
					}

				} else {
					int tempvalue;
				/** check for error condition here **/

					tempvalue =
						MAX_AC_SEQNO -
						BaReqFrm->Seq_Ctrl.StartSeqNo +
						wlpptr->wlpd_p->
						AmpduPckReorder[pStaInfo->Aid].
						CurrentSeqNo[Priority];

					if (tempvalue > MAX_AMPDU_REORDER_BUFFER) {
										  /** invalid condition has happen **/
						//      printk("Invalid 1-1 current seq no %d, ba-seqno %d diff\n",AmpduPckReorder[pStaInfo->Aid].CurrentSeqNo[Priority] , BaReqFrm->Seq_Ctrl.StartSeqNo);

					} else {
						equal = 1;
					}

				/** rollover condition, current seq no is actually larger, eg, current seq 3 and ba seq is 4081 so nothing to do **/
				/** flush any pending pck **/
					//      printk("1-2\n");
					//      printk("1-2 current seq no %d, ba-seqno %d diff\n",wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].CurrentSeqNo[Priority] , BaReqFrm->Seq_Ctrl.StartSeqNo);
					//      Ampdu_Flush_All_Pck_in_Reorder_queue(dev,pStaInfo->Aid, Priority);
					//      wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].CurrentSeqNo[Priority]=BaReqFrm->Seq_Ctrl.StartSeqNo;
				}

			}
			//
			else if (wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].
				 CurrentSeqNo[Priority] >
				 BaReqFrm->Seq_Ctrl.StartSeqNo) {
				if (wlpptr->wlpd_p->
				    AmpduPckReorder[pStaInfo->Aid].
				    CurrentSeqNo[Priority] -
				    BaReqFrm->Seq_Ctrl.StartSeqNo <
				    MAX_AMPDU_REORDER_BUFFER) {
					equal = 1;
				} else {
					int tempvalue;

					tempvalue =
						MAX_AC_SEQNO -
						wlpptr->wlpd_p->
						AmpduPckReorder[pStaInfo->Aid].
						CurrentSeqNo[Priority] +
						BaReqFrm->Seq_Ctrl.StartSeqNo;

					if (tempvalue <
					    MAX_AMPDU_REORDER_BUFFER) {
						//      printk("2-1\n");
						//      printk("2-1 current seq no %d, ba-seqno %d diff=%d\n",AmpduPckReorder[pStaInfo->Aid].CurrentSeqNo[Priority] , BaReqFrm->Seq_Ctrl.StartSeqNo,
						//                      (AmpduPckReorder[pStaInfo->Aid].CurrentSeqNo[Priority] - BaReqFrm->Seq_Ctrl.StartSeqNo) );

						for (i = 0;
						     i <
						     (MAX_AC_SEQNO -
						      wlpptr->wlpd_p->
						      AmpduPckReorder[pStaInfo->
								      Aid].
						      CurrentSeqNo[Priority] +
						      BaReqFrm->Seq_Ctrl.
						      StartSeqNo); i++) {
						/** Need to continue flushing until next pck **/
#ifdef SOC_W906X
							flush_blockack_pck(dev, i, pStaInfo, Priority);
												     /** there is a hole in the pck **/
#else
							flush_blockack_pck(dev, i, pStaInfo->Aid, Priority);
													  /** there is a hole in the pck **/
#endif /* SOC_W906X */

						}

						blockack_reorder_pck(dev, i,
								     pStaInfo->
								     Aid,
								     Priority);

						//      for(j=0;j<64;j++)
						//      printk("2.  Expected seq no = %d %d\n",AmpduPckReorder[pStaInfo->Aid].ExpectedSeqNo[Priority][j],j);
						//     printk("2.  Expected seq no = %d, baseq = %d\n",AmpduPckReorder[pStaInfo->Aid].ExpectedSeqNo[Priority][0],BaReqFrm->Seq_Ctrl.StartSeqNo);
						wlpptr->wlpd_p->
							AmpduPckReorder
							[pStaInfo->Aid].
							CurrentSeqNo[Priority] =
							BaReqFrm->Seq_Ctrl.
							StartSeqNo;
						wlpptr->wlpd_p->
							AmpduPckReorder
							[pStaInfo->Aid].
							ExpectedSeqNo[Priority]
							[0] =
							BaReqFrm->Seq_Ctrl.
							StartSeqNo;
						wlpptr->wlpd_p->
							AmpduPckReorder
							[pStaInfo->Aid].
							CurrentSeqNo[Priority] =
							BaReqFrm->Seq_Ctrl.
							StartSeqNo;
						wlpptr->wlpd_p->
							AmpduPckReorder
							[pStaInfo->Aid].
							ExpectedSeqNo[Priority]
							[0] =
							BaReqFrm->Seq_Ctrl.
							StartSeqNo;

						for (i = 0;
						     i <
						     MAX_AMPDU_REORDER_BUFFER;
						     i++) {
						/** flush all subsequent pck until the next hole **/
#ifdef SOC_W906X
							if (flush_blockack_pck
							    (dev, i, pStaInfo,
							     Priority) == 0) {
#else
							if (flush_blockack_pck
							    (dev, i,
							     pStaInfo->Aid,
							     Priority) == 0) {
#endif /* SOC_W906X */
								wlpptr->wlpd_p->
									AmpduPckReorder
									[pStaInfo->
									 Aid].
									CurrentSeqNo
									[Priority]
									=
									(wlpptr->
									 wlpd_p->
									 AmpduPckReorder
									 [pStaInfo->
									  Aid].
									 CurrentSeqNo
									 [Priority]
									 +
									 i) %
									MAX_AC_SEQNO;
								blockack_reorder_pck
									(dev, i,
									 pStaInfo->
									 Aid,
									 Priority);
								break;
							}
						}

						if (Ampdu_Check_Valid_Pck_in_Reorder_queue(dev, pStaInfo->Aid, Priority) == FALSE) {
							wlpptr->wlpd_p->
								AmpduPckReorder
								[pStaInfo->Aid].
								ReOrdering
								[Priority] =
								FALSE;
						}

					} else {
						//printk("Invalid 2-1 current seq no %d, ba-seqno %d diff ignore, window already move\n",AmpduPckReorder[pStaInfo->Aid].CurrentSeqNo[Priority] , BaReqFrm->Seq_Ctrl.StartSeqNo);

						//ignore this invaild bar **/

					}

				}
			} else {
				equal = 1;
				//      printk("3, they are equal AmpduPckReorder[pStaInfo->Aid].CurrentSeqNo[Priority] = %d\n",wlpptr->wlpd_p->AmpduPckReorder[pStaInfo->Aid].CurrentSeqNo[Priority]);
			}

			if (!equal) {
				if ((Ampdu_Check_Valid_Pck_in_Reorder_queue
				     (dev, pStaInfo->Aid, Priority) == FALSE)) {
					wlpptr->wlpd_p->
						AmpduPckReorder[pStaInfo->Aid].
						ReOrdering[Priority] = FALSE;
				} else {
					wlpptr->wlpd_p->
						AmpduPckReorder[pStaInfo->Aid].
						ReOrdering[Priority] = TRUE;
				}
			}
#endif /* SOC_W906X */

			if (skb != NULL) {
				wlpptr->netDevStats.rx_dropped++;
				wl_free_skb(skb);
			}
			return cnt;
#endif
		}

	default:
		goto out;
	}
deauth:
	{
		WLDBG_INFO(DBG_LEVEL_9, "class3 frame from %x %d\n", pStaInfo,
			   pStaInfo ? pStaInfo->State : 0);
#ifdef SOC_W906X
		macMgmtMlme_SendDeauthenticateMsg(vmacSta_p, &(wh->addr2), 0,
						  IEEEtypes_REASON_CLASS3_NONASSOC,
						  TRUE);
#else
		macMgmtMlme_SendDeauthenticateMsg(vmacSta_p, &(wh->addr2), 0,
						  IEEEtypes_REASON_CLASS3_NONASSOC);
#endif
	}
err:
out:
	//      WLDBG_ERROR(DBG_LEVEL_9,"Type= %i, ToDs = %i", wh->FrmCtl.Type, wh->FrmCtl.ToDs);
	if (skb != NULL) {
		wlpptr->netDevStats.rx_dropped++;
		wl_free_skb(skb);
	}
	return cnt;
}

//#define roundup(x, y)   ((((x)+((y)-1))/(y))*(y))
struct sk_buff *
ieee80211_getmgtframe(UINT8 ** frm, unsigned int pktlen)
{
	const unsigned int align = sizeof(u_int32_t);
	struct sk_buff *skb;
	unsigned int len;

	len = roundup_MRVL(sizeof(struct ieee80211_frame) + pktlen, 4);
	skb = wl_alloc_skb(len + align - 1 + NUM_EXTRA_RX_BYTES);
	if (skb != NULL) {
		unsigned int off = ((unsigned long)skb->data) % align;
		if (off != 0)
			skb_reserve(skb, align - off);

		skb_reserve(skb, MIN_BYTES_HEADROOM);
		*frm = skb_put(skb, pktlen);
		memset(skb->data, 0, sizeof(struct ieee80211_frame));
	}
	return skb;
}

/* Don't assign skb length for variable length MGMT frames*/
struct sk_buff *
ieee80211_getmgtframe_undefine_len(UINT8 ** frm, unsigned int pktlen)
{
	const unsigned int align = sizeof(u_int32_t);
	struct sk_buff *skb;
	unsigned int len;

	len = roundup_MRVL(sizeof(struct ieee80211_frame) + pktlen, 4);
	skb = wl_alloc_skb(len + align - 1 + NUM_EXTRA_RX_BYTES);
	if (skb != NULL) {
		unsigned int off = ((unsigned long)skb->data) % align;
		if (off != 0)
			skb_reserve(skb, align - off);

		skb_reserve(skb, MIN_BYTES_HEADROOM);
		memset(skb->data, 0, sizeof(struct ieee80211_frame));
	}
	return skb;
}

struct sk_buff *
ieee80211_getDataframe(UINT8 ** frm, unsigned int pktlen)
{
	const unsigned int align = sizeof(u_int32_t);
	struct sk_buff *skb;
	unsigned int len;

	len = roundup_MRVL(pktlen, 4);
	skb = wl_alloc_skb(len + align - 1 + NUM_EXTRA_RX_BYTES);
	if (skb != NULL) {
		unsigned int off = ((unsigned long)skb->data) % align;
		if (off != 0)
			skb_reserve(skb, align - off);

		skb_reserve(skb, MIN_BYTES_HEADROOM);
		*frm = skb_put(skb, pktlen - sizeof(struct ieee80211_frame));
		skb_pull(skb, 6);
		memset(skb->data, 0, sizeof(struct ieee80211_frame));
	}
	return skb;
}

void
sendLlcExchangeID(struct net_device *dev, IEEEtypes_MacAddr_t * src)
{
	struct sk_buff *skb;
	/* send a LLC exchange ID */
	unsigned char *bufptr;

	skb = wl_alloc_skb((dev->mtu) + NUM_EXTRA_RX_BYTES);
	if (skb) {
		MARK_MNG_SKB(skb);
		skb_reserve(skb, MIN_BYTES_HEADROOM);
		bufptr = skb->data;
		skb_put(skb, 60);
		memcpy(bufptr, (unsigned char *)&bcast, sizeof(bcast));
		bufptr += sizeof(bcast);
		memcpy(bufptr, (unsigned char *)src, sizeof(*src));
		bufptr += sizeof(IEEEtypes_MacAddr_t);
		*(bufptr++) = 0x00;	/* Ieee802.3 length */
		*(bufptr++) = 0x06;	/* Ieee802.3 length */
		*(bufptr++) = 0x00;	/* Null DSAP */
		*(bufptr++) = 0x01;	/* Null SSAP */
		*(bufptr++) = 0xaf;	/* exchange ID */
		*(bufptr++) = 0x81;	/* LLC data */
		*(bufptr++) = 0x01;	/* LLC data */
		*(bufptr++) = 0x00;	/* LLC data */
		memset(bufptr, 0, 60 - (bufptr - skb->data));	/* pad */
		skb->dev = dev;
		skb->protocol = eth_type_trans(skb, dev);

		/*increment Rx packet counter per interface */
		((NETDEV_PRIV_P(struct wlprivate, skb->dev)))->netDevStats.
			rx_packets++;
		((NETDEV_PRIV_P(struct wlprivate, skb->dev)))->netDevStats.
			rx_bytes += skb->len;
		if (((NETDEV_PRIV_P(struct wlprivate, skb->dev)))->master) {
			((NETDEV_PRIV_P
			  (struct wlprivate,
			   ((NETDEV_PRIV_P(struct wlprivate, skb->dev)))->
			   master)))->netDevStats.rx_packets++;
			((NETDEV_PRIV_P
			  (struct wlprivate,
			   ((NETDEV_PRIV_P(struct wlprivate, skb->dev)))->
			   master)))->netDevStats.rx_bytes += skb->len;
		}
#ifdef NAPI
		wl_receive_skb(skb);
#else
//#ifdef CONFIG_SMP
		/* direct bridging part of Rx processing job to cpu1 for SMP platform */
//        smp_call_function_single(1, netif_rx_ni, (void *)skb, 0);
//#else
		wl_receive_skb(skb);
//#endif
#endif
	}
}

#ifdef MPRXY
void
McastProxyCheck(struct sk_buff *skb)
{
	struct ether_header *eh;
	IEEEtypes_IPv4_Hdr_t *IPv4_p = NULL;
	IEEEtypes_IPv6_Hdr_t *IPv6_p = NULL;
	UINT32 dIPAddr;

	/* check if IP packet, locate IP header check if IP address is multicast */
	eh = (struct ether_header *)skb->data;
	if (eh->ether_type == (UINT16) 0x0008) {	/* type 0x0800 */
		IPv4_p = (IEEEtypes_IPv4_Hdr_t *) ((UINT8 *) eh +
						   sizeof(ether_hdr_t));

		dIPAddr = WORD_SWAP(*((UINT32 *) IPv4_p->dst_IP_addr));

		//check if the pkt is IPv4 or IPV6
		if (IPv4_p->ver == IPV6_VERSION) {
			IPv6_p = (IEEEtypes_IPv6_Hdr_t *) IPv4_p;
			dIPAddr = WORD_SWAP(*((UINT32 *) IPv6_p->dst_IP_addr));
		}

		if (IS_IN_MULTICAST(dIPAddr)) {
			/* recreate multicast mac from multicast IP */
			eh->ether_dhost[0] = 0x01;
			eh->ether_dhost[1] = 0x00;
			eh->ether_dhost[2] = 0x5e;
			eh->ether_dhost[3] =
				(UINT8) ((dIPAddr & 0x007F0000) >> 16);
			eh->ether_dhost[4] =
				(UINT8) ((dIPAddr & 0x0000FF00) >> 8);
			eh->ether_dhost[5] = (UINT8) (dIPAddr & 0x000000FF);
		}
	}

}
#endif

/*This function goes through multicast proxy list to find matching sta addr to be removed.
 * This function is almost same as IGMP LEAVE section in ForwardFrame function
 */
BOOLEAN
McastProxyUCastAddrRemove(vmacApInfo_t * vmacSta_p, IEEEtypes_MacAddr_t * addr)
{
	MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
	MIB_802DOT11 *mibShadow = vmacSta_p->ShadowMib802dot11;
	UINT8 i, j, IPMcastGrpCount, MAddrCount;
	UINT8 retval = FALSE;
	UINT8 MCastGrpMovedUp = 0;	//Once a group is moved up , set to 1
	UINT8 *pAddr = (UINT8 *) addr;

	/* Check if IP Multicast group entry already exists */
	IPMcastGrpCount = *(mib->mib_IPMcastGrpCount);
	for (i = 0; i < IPMcastGrpCount; i++) {
		/*Once a group is moved up one slot, we have to inspect this group by going back one index behind after i++
		 * Otherwise, the newly moved up group will not be inspected as the index moves forward
		 */
		if (MCastGrpMovedUp && (i > 0)) {
			i--;
			MCastGrpMovedUp = 0;
		}

		/*Find the unicast address entry in the IP multicast group.
		 * To save time, skip this group if there is no item
		 */
		if (mib->mib_IPMcastGrpTbl[i]->mib_MAddrCount) {
			MAddrCount = mib->mib_IPMcastGrpTbl[i]->mib_MAddrCount;
			for (j = 0; j < MAddrCount; j++) {
				if (memcmp
				    ((char *)
				     &(mib->mib_IPMcastGrpTbl[i]->
				       mib_UCastAddr[j]), addr, 6) == 0) {
					printk("Mcast grp:%u.%u.%u.%u",
					       IPQUAD(mib->
						      mib_IPMcastGrpTbl[i]->
						      mib_McastIPAddr));
					printk(" del: %02x%02x%02x%02x%02x%02x\n", pAddr[0], pAddr[1], pAddr[2], pAddr[3], pAddr[4], pAddr[5]);

					/*decrement the count for unicast mac entries */
					mib->mib_IPMcastGrpTbl[i]->
						mib_MAddrCount--;
					/* update shadow MIB */
					mibShadow->mib_IPMcastGrpTbl[i]->
						mib_MAddrCount--;

					/*if this is the only entry, slot zero */
					if (mib->mib_IPMcastGrpTbl[i]->
					    mib_MAddrCount == 0) {
						/* set the entry to zero */
						memset((char *)&mib->
						       mib_IPMcastGrpTbl[i]->
						       mib_UCastAddr[j], 0, 6);
						/* update shadow MIB */
						memset((char *)&mibShadow->
						       mib_IPMcastGrpTbl[i]->
						       mib_UCastAddr[j], 0, 6);

						/* set the timestamp for the entry to zero */
						mib->mib_IPMcastGrpTbl[i]->
							mib_UcEntryTS[j] = 0;
						/* update shadow MIB */
						mibShadow->
							mib_IPMcastGrpTbl[i]->
							mib_UcEntryTS[j] = 0;

						/*IPM Grp table [0] is for 224.0.0.1 and we preserve this table by not deleting it.
						 *  It is created during initialization in wl_mib.c. Only upgrade from table[1] onwards
						 */
						if (i > 0) {
							/* Now that IPM Group table is empty remove this group */
							mib->mib_IPMcastGrpTbl
								[i]->
								mib_McastIPAddr
								= 0;
							mibShadow->
								mib_IPMcastGrpTbl
								[i]->
								mib_McastIPAddr
								= 0;

							/* Decrement the IP multicast group count */
							*(mib->
							  mib_IPMcastGrpCount) =
							   *(mib->
							     mib_IPMcastGrpCount)
							   - 1;
							/* Update shadow MIB */
							*(mibShadow->
							  mib_IPMcastGrpCount) =
						     *(mibShadow->
						       mib_IPMcastGrpCount) - 1;

							/* If this is NOT 1st instance of IPM Group table */
							if (*
							    (mib->
							     mib_IPMcastGrpCount)
							    > 1) {
								/* Move up entries to fill the empty spot */
								memcpy((char *)
								       mib->
								       mib_IPMcastGrpTbl
								       [i],
								       (char *)
								       mib->
								       mib_IPMcastGrpTbl
								       [i + 1],
								       sizeof
								       (MIB_IPMCAST_GRP_TBL)
								       *
								       (*
									(mib->
									 mib_IPMcastGrpCount)
									- i));
								/* Update shadow MIB */
								memcpy((char *)
								       mibShadow->
								       mib_IPMcastGrpTbl
								       [i],
								       (char *)
								       mibShadow->
								       mib_IPMcastGrpTbl
								       [i + 1],
								       sizeof
								       (MIB_IPMCAST_GRP_TBL)
								       *
								       (*
									(mibShadow->
									 mib_IPMcastGrpCount)
									- i));

								/* clear out the last instance of the IPM Grp table */
								memset((char *)
								       mib->
								       mib_IPMcastGrpTbl
								       [*
									(mib->
									 mib_IPMcastGrpCount)],
								       0,
								       sizeof
								       (MIB_IPMCAST_GRP_TBL));
								/* update shadow MIB */
								memset((char *)
								       mibShadow->
								       mib_IPMcastGrpTbl
								       [*
									(mibShadow->
									 mib_IPMcastGrpCount)],
								       0,
								       sizeof
								       (MIB_IPMCAST_GRP_TBL));

								MCastGrpMovedUp
									= 1;
							}
						}
						retval = TRUE;
						break;
					} else {
						/*if this is other than slot zero */
						/* set the entry to zero */
						memset((char *)&mib->
						       mib_IPMcastGrpTbl[i]->
						       mib_UCastAddr[j], 0, 6);
						/* Update the shadow MIB */
						memset((char *)&mibShadow->
						       mib_IPMcastGrpTbl[i]->
						       mib_UCastAddr[j], 0, 6);

						/* set the timestamp for the entry to zero */
						mib->mib_IPMcastGrpTbl[i]->
							mib_UcEntryTS[j] = 0;
						/* update shadow MIB */
						mibShadow->
							mib_IPMcastGrpTbl[i]->
							mib_UcEntryTS[j] = 0;

						/* move up entries to fill the vacant spot */
						memcpy((char *)&mib->
						       mib_IPMcastGrpTbl[i]->
						       mib_UCastAddr[j],
						       (char *)&mib->
						       mib_IPMcastGrpTbl[i]->
						       mib_UCastAddr[j + 1],
						       (mib->
							mib_IPMcastGrpTbl[i]->
							mib_MAddrCount -
							j) * 6);
						/*Update shadow MIB */
						memcpy((char *)&mibShadow->
						       mib_IPMcastGrpTbl[i]->
						       mib_UCastAddr[j],
						       (char *)&mibShadow->
						       mib_IPMcastGrpTbl[i]->
						       mib_UCastAddr[j + 1],
						       (mibShadow->
							mib_IPMcastGrpTbl[i]->
							mib_MAddrCount -
							j) * 6);

						/* clear the last unicast entry since all entries moved up by 1 */
						memset((char *)&mib->
						       mib_IPMcastGrpTbl[i]->
						       mib_UCastAddr[mib->
								     mib_IPMcastGrpTbl
								     [i]->
								     mib_MAddrCount],
						       0, 6);
						/* Update shadow MIB */
						memset((char *)&mibShadow->
						       mib_IPMcastGrpTbl[i]->
						       mib_UCastAddr[mibShadow->
								     mib_IPMcastGrpTbl
								     [i]->
								     mib_MAddrCount],
						       0, 6);

						retval = TRUE;
						MCastGrpMovedUp = 0;
						break;
					}
				}
			}
		}
	}
	return retval;
}

int
ForwardFrame(struct net_device *dev, struct sk_buff *skb)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
	MIB_802DOT11 *mibShadow = vmacSta_p->ShadowMib802dot11;
	int cnt = 0;
	struct sk_buff *newskb = NULL;

#ifdef CLIENT_SUPPORT
	struct net_device *staDev = NULL;
	vmacEntry_t *vmacEntry_p = NULL;
#endif
	struct ether_header *eh;
	extStaDb_StaInfo_t *pStaInfo;
#ifdef MPRXY_SNOOP
	struct iphdr *ipheader = NULL;
	struct igmphdr *igmpheader = NULL;
	struct igmpv3_report *igmpv3_report = NULL;
	UINT32 igmp_addr, igmp_addr_host;
	UINT8 igmpheadertype = 0;
	UINT8 i, j, IPMcastGrpCount, MAddrCount;
	BOOLEAN IPMcEntryExists = FALSE;
	BOOLEAN UcMACEntryExists = FALSE;
	UINT8 MCastGrpMovedUp = 0;	//Once a group is moved up , set to 1
#ifdef MPRXY_IGMP_QUERY
	BOOLEAN IGMPQueryEntry = FALSE;
#endif
#endif
	eth_StaInfo_t *ethStaInfo_p;

	WLDBG_ENTER(DBG_LEVEL_9);
	if (!skb) {
		WLDBG_ERROR(DBG_LEVEL_9, "skb == NULL\n");
		WLDBG_EXIT(DBG_LEVEL_9);
		return cnt;
	}
#ifdef TP_PROFILE
	if (wl_tp_profile_test(14, skb, dev)) {
		wl_free_skb(skb);
		return 1;
	}
#endif

	eh = (struct ether_header *)skb->data;
#ifdef QUEUE_STATS_CNT_HIST
	/* Record the Rx pkts based on pre-set STA MAC address */
	WLDBG_REC_RX_FWD_PKTS(eh);
#endif

#ifdef CLIENT_SUPPORT
	if ((vmacEntry_p =
	     sme_GetParentVMacEntry(vmacSta_p->VMacEntry.phyHwMacIndx)) ==
	    NULL) {
		return cnt;
	}
	skb = ProcessEAPoL(skb, vmacSta_p, vmacEntry_p);

#else
	skb = ProcessEAPoL(skb, vmacSta_p, NULL);
#endif

	if (skb == NULL) {
		return cnt;
	}
#ifdef CLIENT_SUPPORT
	if (!(skb->protocol & WL_WLAN_TYPE_STA)) {
#endif
		if (IS_GROUP((UINT8 *) & (eh->ether_dhost))) {
			wlpptr->netDevStats.multicast++;
			if (is_broadcast_ether_addr
			    ((UINT8 *) & (eh->ether_dhost)))
				wlpptr->wlpd_p->privNdevStats.rx_bcast_bytes +=
					skb->len;
			else
				wlpptr->wlpd_p->privNdevStats.rx_mcast_bytes +=
					skb->len;
			/* Intrabss packets get txed AP mode only */
			if (*(mib->mib_intraBSS) &&
			    (vmacSta_p->VMacEntry.modeOfService !=
			     VMAC_MODE_CLNT_INFRA)) {
				newskb = wl_alloc_skb(skb->len +
						      NUM_EXTRA_RX_BYTES);
				if (newskb) {
					skb_reserve(newskb, MIN_BYTES_HEADROOM);
					memcpy(newskb->data, skb->data,
					       skb->len);
					skb_put(newskb, skb->len);
					wlDataTx(newskb, vmacSta_p->dev);
				}
			}

		}
#ifdef CLIENT_SUPPORT
	}
#endif

	pStaInfo =
		extStaDb_GetStaInfo(vmacSta_p, &(eh->ether_dhost),
				    STADB_DONT_UPDATE_AGINGTIME);

	if (*(mib->mib_RptrMode) && *(mib->mib_intraBSS) &&
	    (vmacSta_p->VMacEntry.modeOfService != VMAC_MODE_CLNT_INFRA)) {
		if (!pStaInfo) {
			if ((ethStaInfo_p =
			     ethStaDb_GetStaInfo(vmacSta_p, &(eh->ether_dhost),
						 1)) != NULL) {
				pStaInfo = ethStaInfo_p->pStaInfo_t;
				if (pStaInfo &&
				    (pStaInfo->StaType & 0x02) != 0x02)
					pStaInfo = NULL;
			}
		}
	}
#ifdef CLIENT_SUPPORT
#ifdef WDS_FEATURE
	if (pStaInfo && (!(skb->protocol & WL_WLAN_TYPE_STA)) && !pStaInfo->AP
	    /* In Rptr STA-AP case, DB entry hold a sta itself which is not ASSOCIATED. handling it here */
	    && (pStaInfo->Client == FALSE))
#else
	if (pStaInfo && (!(skb->protocol & WL_WLAN_TYPE_STA)))
#endif /* WDS_FEATURE */
#else
#ifdef WDS_FEATURE
	if (pStaInfo && !pStaInfo->AP)
#else
	if (pStaInfo)
#endif /* WDS_FEATURE */
#endif /*CLIENT_SUPPORT */
	{
		if (pStaInfo->State == ASSOCIATED) {
			/* Intrabss packets get txed AP mode only */
			if (*(mib->mib_intraBSS) &&
			    (vmacSta_p->VMacEntry.modeOfService !=
			     VMAC_MODE_CLNT_INFRA)) {
				/*Need to set to 0x5 to pass WiFi 4.2.25. */
				skb->priority =
					(skb->priority & 0xfffffff8) | 0x5;

				wlDataTx(skb, vmacSta_p->dev);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)
				dev->last_rx = jiffies;
#endif
				return cnt;
			}
		} else
			goto err;
	}

	cnt++;
#ifdef CLIENT_SUPPORT
	if (!(skb->protocol & WL_WLAN_TYPE_STA)) {
#endif
		if (skb->protocol & WL_WLAN_TYPE_WDS) {
			;	//skb->dev = (struct net_device *) pStaInfo->wdsInfo;
#ifdef MULTI_AP_SUPPORT
			//skb->dev = vmacSta_p->dev;
#endif
		} else {
			skb->dev = vmacSta_p->dev;
		}

#ifndef MV_NSS_SUPPORT
		WLDBG_INFO(DBG_LEVEL_9,
			   "1B.skb->head,data,tail,end,len:%p %p %p %p %d\n",
			   skb->head, skb->data, skb->tail, skb->end, skb->len);

		skb->protocol = eth_type_trans(skb, skb->dev);

		WLDBG_INFO(DBG_LEVEL_9,
			   "1A.skb->head,data,tail,end,len:%p %p %p %p %d\n",
			   skb->head, skb->data, skb->tail, skb->end, skb->len);
#endif
#ifdef MPRXY_SNOOP
		if (*(mib->mib_MCastPrxy)) {
			ipheader =
				(struct iphdr *)((UINT8 *) eh +
						 sizeof(ether_hdr_t));

			/* Filter out non-IGMP traffic */
			if (ipheader->protocol != IPPROTO_IGMP)
				goto mprxycontinue;

			/* Get the pointer to the IGMP header and its data */
			igmpheader =
				(struct igmphdr *)((UINT8 *) ipheader +
						   ipheader->ihl * 4);

			/* Filter out unsupported IGMP messages */
			if ((igmpheader->type != IGMP_HOST_MEMBERSHIP_REPORT) &&
			    (igmpheader->type != IGMPV2_HOST_MEMBERSHIP_REPORT)
			    && (igmpheader->type !=
				IGMPV3_HOST_MEMBERSHIP_REPORT) &&
			    (igmpheader->type != IGMP_HOST_LEAVE_MESSAGE))
				goto mprxycontinue;

			/* Determine the group address based on IGMP V1/V2 or IGMP V3 */
			if (igmpheader->type == IGMPV3_HOST_MEMBERSHIP_REPORT) {
				igmpv3_report =
					(struct igmpv3_report *)igmpheader;
				/* Determine the IP multicast group address */
				igmp_addr = igmpv3_report->grec[0].grec_mca;
				igmp_addr_host =
					ntohl(igmpv3_report->grec[0].grec_mca);
			} else {	/* if IGMP V1 or V2 */
				igmp_addr = igmpheader->group;
				igmp_addr_host = ntohl(igmpheader->group);
			}

			/* Filter out non-multicast messages */
			if (!MULTICAST(igmp_addr)) {
				WLDBG_ERROR(DBG_LEVEL_9,
					    "\nIGMP snoop: Non-multicast group address in IGMP header\n");
				goto mprxycontinue;
			}

			/* According to "draft-ietf-magma-snoop-12.txt" local multicast messages (224.0.0.x) must be flooded to all ports */
			/* So, don't do anything with such messages */
			if (LOCAL_MCAST(igmp_addr)) {
				WLDBG_ERROR(DBG_LEVEL_9,
					    "\nIGMP snoop: Local IGMP messages (224.0.0.x) must be flooded \n");
				goto mprxycontinue;
			}

			/* According to RFC 2236 IGMP LEAVE messages should be sent to ALL-ROUTERS address (224.0.0.2) */
			if (igmpheader->type == IGMP_HOST_LEAVE_MESSAGE) {
				if (ntohl(ipheader->daddr) != 0xE0000002) {
					WLDBG_ERROR(DBG_LEVEL_9,
						    "\nIGMP snoop: Ignore IGMP LEAVE message sent to non-ALL-ROUTERS address (224.0.0.2) \n");
					goto mprxycontinue;
				}
			} else {
#if 0				/* this check needs to be reviewed, IGMPV3 messages are different */
				/* According to RFC 2236 Membership Report (JOIN) IGMP messages should be sent to the IGMP group address */
				if (ipheader->daddr != igmp_addr) {
					printk("\nIGMP snoop: Ignore IGMP JOIN message with different destination IP(%u.%u.%u.%u) and IGMP group address(%u.%u.%u.%u) \n", NIPQUAD(ipheader->daddr), NIPQUAD(igmp_addr));
					goto mprxycontinue;
				}
#endif
			}

			if (igmpheader->type == IGMPV3_HOST_MEMBERSHIP_REPORT) {
				/* Determine if IGMPV3 message is JOIN or LEAVE */
				/* If LEAVE message then store the header type as LEAVE */
				if ((igmpv3_report->grec[0].grec_type ==
				     IGMPV3_CHANGE_TO_INCLUDE) ||
				    (igmpv3_report->grec[0].grec_type ==
				     IGMPV3_BLOCK_OLD_SOURCES)) {
					igmpheadertype =
						IGMP_HOST_LEAVE_MESSAGE;
				} else if ((igmpv3_report->grec[0].grec_type ==
					    IGMPV3_CHANGE_TO_EXCLUDE) ||
					   (igmpv3_report->grec[0].grec_type ==
					    IGMPV3_ALLOW_NEW_SOURCES)) {
					igmpheadertype =
						IGMPV3_HOST_MEMBERSHIP_REPORT;
				}
			} else
				igmpheadertype = igmpheader->type;

			switch (igmpheadertype) {
			case IGMP_HOST_MEMBERSHIP_REPORT:
			case IGMPV2_HOST_MEMBERSHIP_REPORT:
			case IGMPV3_HOST_MEMBERSHIP_REPORT:

				WLDBG_INFO(DBG_LEVEL_9,
					   "IGMP Report:%u.%u.%u.%u",
					   IPQUAD(igmp_addr_host));
				WLDBG_INFO(DBG_LEVEL_9,
					   "   %02x%02x%02x%02x%02x%02x\n",
					   eh->ether_shost[0],
					   eh->ether_shost[1],
					   eh->ether_shost[2],
					   eh->ether_shost[3],
					   eh->ether_shost[4],
					   eh->ether_shost[5]);

				IPMcastGrpCount = *(mib->mib_IPMcastGrpCount);
				for (i = 0; i < IPMcastGrpCount; i++) {
					if (mib->mib_IPMcastGrpTbl[i]->
					    mib_McastIPAddr == igmp_addr_host) {
						IPMcEntryExists = TRUE;

						if (mib->mib_IPMcastGrpTbl[i]->
						    mib_MAddrCount <
						    MAX_UCAST_MAC_IN_GRP) {
							/*check if unicast adddress entry already exists in table */
							MAddrCount =
								mib->
								mib_IPMcastGrpTbl
								[i]->
								mib_MAddrCount;
							for (j = 0;
							     j < MAddrCount;
							     j++) {
								if (memcmp
								    ((char *)
								     &mib->
								     mib_IPMcastGrpTbl
								     [i]->
								     mib_UCastAddr
								     [j],
								     (char *)
								     &eh->
								     ether_shost,
								     6) == 0) {
									UcMACEntryExists
										=
										TRUE;
									/* update the timestamp for this entry */
									mib->mib_IPMcastGrpTbl[i]->mib_UcEntryTS[j] = jiffies;
									break;
								}
							}

							if (UcMACEntryExists ==
							    FALSE) {
								/* Add the MAC address into the table */
								memcpy((char *)
								       &mib->
								       mib_IPMcastGrpTbl
								       [i]->
								       mib_UCastAddr
								       [mib->
									mib_IPMcastGrpTbl
									[i]->
									mib_MAddrCount],
								       (char *)
								       &eh->
								       ether_shost,
								       6);

								/* Add the MAC address into shadow MIB table also */
								memcpy((char *)
								       &mibShadow->
								       mib_IPMcastGrpTbl
								       [i]->
								       mib_UCastAddr
								       [mibShadow->
									mib_IPMcastGrpTbl
									[i]->
									mib_MAddrCount],
								       (char *)
								       &eh->
								       ether_shost,
								       6);

								/* update the timestamp corresponding to the unicast entry */
								mib->mib_IPMcastGrpTbl[i]->mib_UcEntryTS[mib->mib_IPMcastGrpTbl[i]->mib_MAddrCount] = jiffies;

								/* Increment the number of MAC address in IPM table */
								mib->mib_IPMcastGrpTbl[i]->mib_MAddrCount++;
								mibShadow->
									mib_IPMcastGrpTbl
									[i]->
									mib_MAddrCount++;
#ifdef MPRXY_IGMP_QUERY
								/*check if unicast adddress entry already exists in table */
								MAddrCount =
									mib->
									mib_IPMcastGrpTbl
									[0]->
									mib_MAddrCount;
								for (j = 0;
								     j <
								     MAddrCount;
								     j++) {
									if (memcmp((char *)&(mib->mib_IPMcastGrpTbl[0]->mib_UCastAddr[j]), (char *)&eh->ether_shost, 6) == 0) {
										IGMPQueryEntry
											=
											TRUE;
										break;
									}
								}
								if (!IGMPQueryEntry) {
									/* Add the unicast entry in the IPM Grp table [0] */
									memcpy((char *)&(mib->mib_IPMcastGrpTbl[0]->mib_UCastAddr[mib->mib_IPMcastGrpTbl[0]->mib_MAddrCount]), (char *)&eh->ether_shost, 6);
									/* Update shadow MIB */
									memcpy((char *)&(mibShadow->mib_IPMcastGrpTbl[0]->mib_UCastAddr[mibShadow->mib_IPMcastGrpTbl[0]->mib_MAddrCount]), (char *)&eh->ether_shost, 6);

									/* increment unicast mac address count */
									mib->mib_IPMcastGrpTbl[0]->mib_MAddrCount++;
									/* Update shadow MIB */
									mibShadow->
										mib_IPMcastGrpTbl
										[0]->
										mib_MAddrCount++;
								}
#endif
								break;
							}
						} else {
							break;
						}
					}
				}

				/* if IP multicast group entry does not exist */
				if (IPMcEntryExists == FALSE) {
					/*check if space available in table */
					if (*(mib->mib_IPMcastGrpCount) <
					    MAX_IP_MCAST_GRPS) {
						/* Add the IPM entry into the table */
						mib->mib_IPMcastGrpTbl[*
								       (mib->
									mib_IPMcastGrpCount)]->
							mib_McastIPAddr =
							igmp_addr_host;
						/* Update Shadow MIB */
						mibShadow->
							mib_IPMcastGrpTbl[*
									  (mibShadow->
									   mib_IPMcastGrpCount)]->
							mib_McastIPAddr =
							igmp_addr_host;

						/* Add the MAC address into the table */
						i = *(mib->mib_IPMcastGrpCount);

						/* Add the unicast entry in the IPM Grp table */
						memcpy((char *)
						       &(mib->
							 mib_IPMcastGrpTbl[i]->
							 mib_UCastAddr[mib->
								       mib_IPMcastGrpTbl
								       [i]->
								       mib_MAddrCount]),
						       (char *)&eh->ether_shost,
						       6);

						/* Update shadow MIB */
						memcpy((char *)
						       &(mibShadow->
							 mib_IPMcastGrpTbl[i]->
							 mib_UCastAddr
							 [mibShadow->
							  mib_IPMcastGrpTbl[i]->
							  mib_MAddrCount]),
						       (char *)&eh->ether_shost,
						       6);

						/* Update the timestamp for the unicast entry */
						mib->mib_IPMcastGrpTbl[i]->
							mib_UcEntryTS[mib->
								      mib_IPMcastGrpTbl
								      [i]->
								      mib_MAddrCount]
							= jiffies;

						/* increment unicast mac address count */
						mib->mib_IPMcastGrpTbl[i]->
							mib_MAddrCount++;
						/* Update shadow MIB */
						mibShadow->
							mib_IPMcastGrpTbl[i]->
							mib_MAddrCount++;

						/*increment the IP multicast group slot by 1 */
						*(mib->mib_IPMcastGrpCount) =
							*(mib->
							  mib_IPMcastGrpCount) +
							1;
						/* Update shadow MIB */
						*(mibShadow->
						  mib_IPMcastGrpCount) =
					     *(mibShadow->mib_IPMcastGrpCount) +
					     1;
#ifdef MPRXY_IGMP_QUERY
						/*check if unicast adddress entry already exists in table */
						MAddrCount =
							mib->
							mib_IPMcastGrpTbl[0]->
							mib_MAddrCount;
						for (j = 0; j < MAddrCount; j++) {
							if (memcmp
							    ((char *)
							     &(mib->
							       mib_IPMcastGrpTbl
							       [0]->
							       mib_UCastAddr
							       [j]),
							     (char *)&eh->
							     ether_shost,
							     6) == 0) {
								IGMPQueryEntry =
									TRUE;
								break;
							}
						}
						if (!IGMPQueryEntry) {
							/* Add the unicast entry in the IPM Grp table [0] */
							memcpy((char *)
							       &(mib->
								 mib_IPMcastGrpTbl
								 [0]->
								 mib_UCastAddr
								 [mib->
								  mib_IPMcastGrpTbl
								  [0]->
								  mib_MAddrCount]),
							       (char *)&eh->
							       ether_shost, 6);

							/* Update shadow MIB */
							memcpy((char *)
							       &(mibShadow->
								 mib_IPMcastGrpTbl
								 [0]->
								 mib_UCastAddr
								 [mibShadow->
								  mib_IPMcastGrpTbl
								  [0]->
								  mib_MAddrCount]),
							       (char *)&eh->
							       ether_shost, 6);

							/* increment unicast mac address count */
							mib->mib_IPMcastGrpTbl
								[0]->
								mib_MAddrCount++;
							/* Update shadow MIB */
							mibShadow->
								mib_IPMcastGrpTbl
								[0]->
								mib_MAddrCount++;

						}
#endif

					} else {
						break;
					}
				}
				break;

			case IGMP_HOST_LEAVE_MESSAGE:
				WLDBG_INFO(DBG_LEVEL_9,
					   "IGMP Leave:%u.%u.%u.%u",
					   IPQUAD(igmp_addr_host));
				WLDBG_INFO(DBG_LEVEL_9,
					   "   %02x%02x%02x%02x%02x%02x\n",
					   eh->ether_shost[0],
					   eh->ether_shost[1],
					   eh->ether_shost[2],
					   eh->ether_shost[3],
					   eh->ether_shost[4],
					   eh->ether_shost[5]);

				/* check if IP Multicast group entry already exists */
				IPMcastGrpCount = *(mib->mib_IPMcastGrpCount);
				for (i = 0; i < IPMcastGrpCount; i++) {

					/*Once a group is moved up one slot, we have to inspect this group by going back one index behind after i++
					 * Otherwise, the newly moved up group will not be inspected as the index moves forward
					 */
					if (MCastGrpMovedUp && (i > 0)) {
						i--;
						MCastGrpMovedUp = 0;
					}

					/*match IP multicast grp address with entry */
					if (mib->mib_IPMcastGrpTbl[i]->
					    mib_McastIPAddr == igmp_addr_host) {

						/*Find the unicast address entry in the IP multicast group.
						 * To save time, skip this group if there is no item
						 */
						if (mib->mib_IPMcastGrpTbl[i]->
						    mib_MAddrCount) {
							/*find the unicast address entry in the IP multicast group */
							MAddrCount =
								mib->
								mib_IPMcastGrpTbl
								[i]->
								mib_MAddrCount;
							for (j = 0;
							     j < MAddrCount;
							     j++) {
								if (memcmp
								    ((char *)
								     &(mib->
								       mib_IPMcastGrpTbl
								       [i]->
								       mib_UCastAddr
								       [j]),
								     (char *)
								     &eh->
								     ether_shost,
								     6) == 0) {
									/*decrement the count for unicast mac entries */
									mib->mib_IPMcastGrpTbl[i]->mib_MAddrCount--;
									/* update shadow MIB */
									mibShadow->
										mib_IPMcastGrpTbl
										[i]->
										mib_MAddrCount--;

									/*if this is the only entry, slot zero */
									if (mib->mib_IPMcastGrpTbl[i]->mib_MAddrCount == 0) {
										/* set the entry to zero */
										memset((char *)&mib->mib_IPMcastGrpTbl[i]->mib_UCastAddr[j], 0, 6);
										/* update shadow MIB */
										memset((char *)&mibShadow->mib_IPMcastGrpTbl[i]->mib_UCastAddr[j], 0, 6);

										/* set the timestamp for the entry to zero */
										mib->mib_IPMcastGrpTbl[i]->mib_UcEntryTS[j] = 0;
										mibShadow->
											mib_IPMcastGrpTbl
											[i]->
											mib_UcEntryTS
											[j]
											=
											0;

										/*IPM Grp table [0] is for 224.0.0.1 and we preserve this table by not deleting it.
										 *  It is created during initialization in wl_mib.c. Only upgrade from table[1] onwards
										 */
										if (i > 0) {
											/* Now that IPM Group table is empty remove this group */
											mib->mib_IPMcastGrpTbl[i]->mib_McastIPAddr = 0;
											mibShadow->
												mib_IPMcastGrpTbl
												[i]->
												mib_McastIPAddr
												=
												0;

											/* Decrement the IP multicast group count */
											*(mib->mib_IPMcastGrpCount) = *(mib->mib_IPMcastGrpCount) - 1;
											/* Update shadow MIB */
											*(mibShadow->mib_IPMcastGrpCount) = *(mibShadow->mib_IPMcastGrpCount) - 1;

											/* If this is NOT 1st instance of IPM Group table */
											if (*(mib->mib_IPMcastGrpCount) > 1) {
												/* Move up entries to fill the empty spot */
												memcpy((char *)mib->mib_IPMcastGrpTbl[i], (char *)mib->mib_IPMcastGrpTbl[i + 1], sizeof(MIB_IPMCAST_GRP_TBL) * (*(mib->mib_IPMcastGrpCount) - i));
												/* Update shadow MIB */
												memcpy((char *)mibShadow->mib_IPMcastGrpTbl[i], (char *)mibShadow->mib_IPMcastGrpTbl[i + 1], sizeof(MIB_IPMCAST_GRP_TBL) * (*(mibShadow->mib_IPMcastGrpCount) - i));

												/* clear out the last instance of the IPM Grp table */
												memset((char *)mib->mib_IPMcastGrpTbl[*(mib->mib_IPMcastGrpCount)], 0, sizeof(MIB_IPMCAST_GRP_TBL));
												/* update shadow MIB */
												memset((char *)mibShadow->mib_IPMcastGrpTbl[*(mibShadow->mib_IPMcastGrpCount)], 0, sizeof(MIB_IPMCAST_GRP_TBL));

												MCastGrpMovedUp
													=
													1;
											}
										}
										break;
									} else {
										/*if this is other than slot zero */
										/* set the entry to zero */
										memset((char *)&mib->mib_IPMcastGrpTbl[i]->mib_UCastAddr[j], 0, 6);
										/* Update the shadow MIB */
										memset((char *)&mibShadow->mib_IPMcastGrpTbl[i]->mib_UCastAddr[j], 0, 6);

										/* set the timestamp for the entry to zero */
										mib->mib_IPMcastGrpTbl[i]->mib_UcEntryTS[j] = 0;
										mibShadow->
											mib_IPMcastGrpTbl
											[i]->
											mib_UcEntryTS
											[j]
											=
											0;

										/* move up entries to fill the vacant spot */
										memcpy((char *)&mib->mib_IPMcastGrpTbl[i]->mib_UCastAddr[j], (char *)&mib->mib_IPMcastGrpTbl[i]->mib_UCastAddr[j + 1], (mib->mib_IPMcastGrpTbl[i]->mib_MAddrCount - j) * 6);
										/*Update shadow MIB */
										memcpy((char *)&mibShadow->mib_IPMcastGrpTbl[i]->mib_UCastAddr[j], (char *)&mibShadow->mib_IPMcastGrpTbl[i]->mib_UCastAddr[j + 1], (mibShadow->mib_IPMcastGrpTbl[i]->mib_MAddrCount - j) * 6);

										/* clear the last unicast entry since all entries moved up by 1 */
										memset((char *)&mib->mib_IPMcastGrpTbl[i]->mib_UCastAddr[mib->mib_IPMcastGrpTbl[i]->mib_MAddrCount], 0, 6);
										/* Update shadow MIB */
										memset((char *)&mibShadow->mib_IPMcastGrpTbl[i]->mib_UCastAddr[mibShadow->mib_IPMcastGrpTbl[i]->mib_MAddrCount], 0, 6);

										MCastGrpMovedUp
											=
											0;
										break;
									}
								}
							}
						}
					}
				}
				break;

			default:
				break;
			}
		}
#endif /* MPRXY_SNOOP */
#ifdef CLIENT_SUPPORT
	} else {
#ifdef MPRXY
		if (*(mib->mib_MCastPrxy)) {
			McastProxyCheck(skb);
		}
#endif
#ifdef EWB
		if (!*(mib->mib_STAMacCloneEnable)) {
			/* WLAN recv of EWB */
#if 0				// MULTI_AP_SUPPORT
			struct net_device *dev;
			rcu_read_lock();
			for_each_netdev_rcu(&init_net, dev) {
				if (dev->priv_flags & IFF_EBRIDGE &&
				    memcmp(eh->ether_shost, dev->dev_addr,
					   6) == 0) {
					//printk("### Debug %s, source MAC %s is same as %s\n", __func__, mac_display(eh->ether_shost), dev->name);
					goto err;
				} else {
#endif
					ewbWlanRecv(skb, vmacSta_p->macStaAddr);
#if 0				// MULTI_AP_SUPPORT
				}
			}
			rcu_read_unlock();
#endif
		}
#endif
		vmacEntry_p =
			sme_GetParentVMacEntry(vmacSta_p->VMacEntry.
					       phyHwMacIndx);

		//for klocwork checking
		if (!vmacEntry_p)
			goto err;

		staDev = (struct net_device *)vmacEntry_p->privInfo_p;
		skb->dev = staDev;
#ifndef MV_NSS_SUPPORT
		WLDBG_INFO(DBG_LEVEL_9,
			   "2B.skb->head,data,tail,end,len:%p %p %p %p %d\n",
			   skb->head, skb->data, skb->tail, skb->end, skb->len);

		skb->protocol = eth_type_trans(skb, staDev);

		WLDBG_INFO(DBG_LEVEL_9,
			   "2A.skb->head,data,tail,end,len:%p %p %p %p %d\n",
			   skb->head, skb->data, skb->tail, skb->end, skb->len);
#endif
	}
#endif /* CLIENT_SUPPORT */
#ifdef MPRXY_SNOOP
mprxycontinue:
#endif

	/*increment Rx packet counter per interface (data packet) */
	if (skb->dev) {
		((NETDEV_PRIV_P(struct wlprivate, skb->dev)))->netDevStats.
			rx_packets++;
		((NETDEV_PRIV_P(struct wlprivate, skb->dev)))->netDevStats.
			rx_bytes += skb->len;
		if (((NETDEV_PRIV_P(struct wlprivate, skb->dev)))->master) {
			((NETDEV_PRIV_P
			  (struct wlprivate,
			   ((NETDEV_PRIV_P(struct wlprivate, skb->dev)))->
			   master)))->netDevStats.rx_packets++;
			((NETDEV_PRIV_P
			  (struct wlprivate,
			   ((NETDEV_PRIV_P(struct wlprivate, skb->dev)))->
			   master)))->netDevStats.rx_bytes += skb->len;
		}
	}
#ifdef TP_PROFILE
	if (wl_tp_profile_test(15, skb, dev)) {
		wl_free_skb(skb);
		return 1;
	}
#endif

#ifdef NAPI
	wl_receive_skb(skb);
#else
//#ifdef CONFIG_SMP
	/* direct bridging part of Rx processing job to cpu1 for SMP platform */
//                smp_call_function_single(1, netif_rx_ni, (void *)skb, 0);
//#else

	WLDBG_INFO(DBG_LEVEL_9, "ForwardFrame: skb->protocol:%04xh, len:%u\n",
		   skb->protocol, skb->len);
	WLDBG_HEXDUMP(DBG_LEVEL_9, skb->data, skb->len);

	wl_receive_skb(skb);
//#endif
#endif
#ifdef TP_PROFILE
	wlpptr->wlpd_p->wl_tpprofile.rx.bytes += skb->len;
	wlpptr->wlpd_p->wl_tpprofile.rx.packets += 1;
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)
	dev->last_rx = jiffies;
#endif
	WLDBG_EXIT(DBG_LEVEL_9);
	return cnt;

err:
	//      WLDBG_ERROR(DBG_LEVEL_9,"Type= %i, ToDs = %i", wh->FrmCtl.Type, wh->FrmCtl.ToDs);
	if (skb != NULL) {
		wlpptr->netDevStats.rx_dropped++;
		wl_free_skb(skb);
	}
	WLDBG_EXIT(DBG_LEVEL_9);
	return cnt;
}

int
DeAmsduPck(struct net_device *netdev, struct sk_buff *skb)
{
	int rxCount, length, length1 = 0, length2, headerlength =
		sizeof(struct ieee80211_frame);
	struct sk_buff *pRxSkBuff;
	void *pCurrentData, *pLoc;
	int cnt = 0;

	rxCount = skb->len;
	length1 = 0;
	pCurrentData = skb->data;
	while (rxCount - headerlength > length1) {
		pLoc = pCurrentData + headerlength + length1;
		length = (*(UINT16 *) ((unsigned long)pLoc + 12));
#ifdef AMSDU_BYTE_REORDER
#ifdef MV_CPU_LE
		length2 = ((length & 0xff00) >> 8) | ((length & 0x00ff) << 8);
		length = length2;
#endif
#endif
		if (length > rxCount) {
			wl_free_skb(skb);
			return cnt;
		}
		pRxSkBuff = wl_alloc_skb((netdev->mtu) + NUM_EXTRA_RX_BYTES);
		if (pRxSkBuff) {
			skb_reserve(pRxSkBuff, MIN_BYTES_HEADROOM);
			memcpy(pRxSkBuff->data, skb->data, headerlength);
#ifdef CLIENT_SUPPORT
			if (!(skb->protocol & WL_WLAN_TYPE_STA))
#endif
			{
				//need copy dst address from aggr header to 802.11 addr3
				memcpy(&pRxSkBuff->data[headerlength - 14],
				       pLoc, 6);
				//need copy src address from aggr header to 802.11 addr4 for wds
				if (skb->protocol & WL_WLAN_TYPE_WDS) {
					memcpy(&pRxSkBuff->
					       data[headerlength - 6], pLoc + 6,
					       6);
				}
			}
			pRxSkBuff->protocol = skb->protocol;
			pRxSkBuff->dev = skb->dev;

			//WLDBG_INFO(DBG_LEVEL_14,"aggregation skb_put len=%d", length + OFFS_RXFWBUFF_IEEE80211PAYLOAD - 8);
			if (skb_tailroom(pRxSkBuff) >= (length + headerlength)) {
				struct ether_header *eh;
				memcpy(&pRxSkBuff->data[headerlength],
				       pLoc + 14, length);
				skb_put(pRxSkBuff, length + headerlength);
				{
					extStaDb_StaInfo_t *pStaInfo = NULL;
					pRxSkBuff =
						DeFragPck(netdev, pRxSkBuff,
							  &pStaInfo);
					if (pRxSkBuff == NULL) {
						wl_free_skb(skb);
						return cnt;
					}
					pRxSkBuff =
						ieee80211_decap(netdev,
								pRxSkBuff,
								pStaInfo, 0);

					//klocwork checking
					if (pRxSkBuff == NULL) {
						return cnt;
					}

				}

				eh = (struct ether_header *)pRxSkBuff->data;
				cnt = ForwardFrame(netdev, pRxSkBuff);
			} else {
				wl_free_skb(pRxSkBuff);
				wl_free_skb(skb);
				return cnt;
			}

			length1 += roundup_MRVL(length + 14, 4);
		} else
			WLDBG_INFO(DBG_LEVEL_14, "out of skb\n");
	}
	wl_free_skb(skb);
	return cnt;
}

#ifdef ENABLE_MONIF
#ifdef NEW_DP
int
monif_handle_recv(struct wlprivate *wlpptr, rx_info_aux_t * prxinfo_aux,
		  struct sk_buff *skb, int promisc_data)
#else
int
monif_handle_recv(struct wlprivate *wlpptr, wlrxdesc_t * pCurrent,
		  struct sk_buff *skb)
#endif
{
	struct ieee80211_frame *wh = (struct ieee80211_frame *)skb->data;
	int val = 0;
#ifdef SOC_W906X
	UINT32 MonIfIndex = wlpptr->wlpd_p->MonIfIndex;
#else
	UINT32 MonIfIndex = MONIF_INDEX;
#endif
	//generic_buf* pbuf = *(generic_buf**)skb->cb;
	generic_buf *pbuf = &prxinfo_aux->radiotap;

	WLDBG_PROMISCUOUS_DUMP(DBG_LEVEL_15, skb->data, skb->len);
	if (!promisc_data)
		return 0;

	switch (wh->FrmCtl.Type) {
	case IEEE_TYPE_DATA:
	case IEEE_TYPE_MANAGEMENT:
	case IEEE_TYPE_CONTROL:{
			if ((pbuf != NULL) && (skb_headroom(skb) >= pbuf->size)) {
				//Append the radio_tap
				skb_push(skb, pbuf->size);
				memcpy(skb->data, pbuf->bufpt, pbuf->size);
			}

			skb->dev = wlpptr->vdev[MonIfIndex];
			skb->protocol = eth_type_trans(skb, skb->dev);

			((NETDEV_PRIV_P(struct wlprivate, skb->dev)))->
				netDevStats.rx_packets++;
			((NETDEV_PRIV_P(struct wlprivate, skb->dev)))->
				netDevStats.rx_bytes += skb->len;
			wl_receive_skb(skb);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)
			wlpptr->vdev[MonIfIndex]->last_rx = jiffies;
#endif
		}
		break;

	}

	return val;
}
#endif
