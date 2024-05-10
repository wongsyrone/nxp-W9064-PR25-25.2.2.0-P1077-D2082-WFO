/** @file ap8xLnxRecv.c
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

/** include files **/
#include <linux/bitops.h>
#include "wldebug.h"
#include "trace.h"
#include "ap8xLnxRegs.h"
#include "ap8xLnxDesc.h"
#include "ap8xLnxIntf.h"
#include "ap8xLnxXmit.h"
#include "ap8xLnxFwcmd.h"
#include "ap8xLnxRxInfo.h"
#include "IEEE_types.h"
#include "wl_mib.h"
#include "wl_hal.h"
#include "StaDb.h"
#include "ap8xLnxDma.h"
#include "ds.h"
#include "shal_msg.h"
#include "mlmeParent.h"
#include "keyMgmtSta.h"
#include "wds.h"
#include "mlmeApi.h"
#if defined(ACNT_REC)
#include "radiotap.h"
#endif //defined(ACNT_REC)

#ifdef IEEE80211K
#include "msan_report.h"
#endif //IEEE80211K

#ifdef WIFI_DATA_OFFLOAD
#include "dol-ops.h"
#endif

/** local definitions **/
struct ieee80211_frame {
	IEEEtypes_FrameCtl_t FrmCtl;
	UINT8 dur[2];
	UINT8 addr1[IEEEtypes_ADDRESS_SIZE];
	UINT8 addr2[IEEEtypes_ADDRESS_SIZE];
	UINT8 addr3[IEEEtypes_ADDRESS_SIZE];
	UINT8 seq[2];
	UINT8 addr4[IEEEtypes_ADDRESS_SIZE];
} PACK;

/* default settings */

/** external functions **/
extern u32 wlQueryWrPtr(struct net_device *netdev, int qid, int qoff);
extern void wlUpdateRdPtr(struct net_device *netdev, int qid, int qoff,
			  u32 rdinx, bool is_init);
extern wlrxdesc_t *wlSpiltAMSDU(struct net_device *netdev, wlrxdesc_t * cfh_ul);
extern void MrvlMICErrorHdl(vmacApInfo_t * vmacSta_p,
			    COUNTER_MEASURE_EVENT event);
#ifdef MBSS
extern vmacApInfo_t *vmacGetMBssByAddr(vmacApInfo_t * vmacSta_p,
				       UINT8 * macAddr_p);
#endif //MBSS

/** external data **/
u8 amsduSimPattern[] = {
	// da/sa/length - msdu1
	'\x00', '\x50', '\x43', '\x20', '\x03', '\x04',
	'\x00', '\x50', '\x43', '\x21', '\x01', '\x02',
	'\x00', '\x1c',
	// IP: 20 bytes
	'\x45', '\x00', '\x05', '\xDC', '\x54', '\x0D', '\x00', '\x00',
	'\x80', '\x01', '\x00', '\x00', '\xc0', '\xa8', '\x00', '\x09',
	'\xc0', '\xa8', '\x00', '\xc8',
	//ICMP: 8 bytes
	'\x08', '\x00', '\x6C', '\xBD', '\x00', '\x01', '\x00', '\xAE',
	//PADDing 4 bytes
	'\xFF', '\xFF',
	// da/sa/length - msdu2
	'\x00', '\x50', '\x43', '\x20', '\x03', '\x04',
	'\x00', '\x50', '\x43', '\x21', '\x01', '\x02',
	'\x00', '\x22',
	// IP: 20 bytes
	'\x45', '\x00', '\x05', '\xDC', '\x54', '\x0D', '\x00', '\x00',
	'\x80', '\x01', '\x00', '\x00', '\xc0', '\xa8', '\x00', '\x09',
	'\xc0', '\xa8', '\x00', '\xc8',
	//ICMP: 14 bytes
	'\x08', '\x00', '\x6C', '\xBD', '\x00', '\x01', '\x00', '\xAE',
	'\x11', '\x11', '\x11', '\x11', '\x11', '\x11',
	// da/sa/length - msdu3
	'\x00', '\x50', '\x43', '\x20', '\x03', '\x04',
	'\x00', '\x50', '\x43', '\x21', '\x01', '\x02',
	'\x00', '\x14',
	// IP: 20 bytes
	'\x45', '\x00', '\x05', '\xDC', '\x54', '\x0D', '\x00', '\x00',
	'\x80', '\x01', '\x00', '\x00', '\xc0', '\xa8', '\x00', '\x09',
	'\xc0', '\xa8', '\x22', '\x22',
};

//extern u32 qidcnt[3];
extern BOOLEAN bStartOffChanRx;

/** internal functions **/

/** public data **/
UINT32 OffChanRxCnt = 0;
/** private data **/

/** public functions **/
//#define roundup(x, y)   ((((x)+((y)-1))/(y))*(y))

#ifdef ENABLE_MONIF
#ifdef NEW_DP
int monif_handle_recv(struct wlprivate *wlpptr, rx_info_aux_t * prxinfo_aux,
		      struct sk_buff *skb, int promisc_data);
#else
extern int monif_handle_recv(struct wlprivate *wlpptr, wlrxdesc_t * pCurrent,
			     struct sk_buff *skb);
#endif
#endif
extern void wlResetCfhUl(wlrxdesc_t * cfh_ul);
extern void reset_deauth_block_timer(UINT8 * data);

static void
trace_func_delta_begin(vmacApInfo_t * vmacSta_p)
{
	RxTimeCntStat *RxInfo = &(vmacSta_p->Rx_StatInfo);
	ktime_t delta_t1, delta_t2;
	SINT32 delta_ms;

	/* The unit is ms */
	if (ktime_to_ns(RxInfo->RxTask_t) == 0) {
		RxInfo->RxTask_t = ktime_get_real();
		return;
	}
	delta_t2 = ktime_get_real();
	delta_t1 = ktime_sub(delta_t2, RxInfo->RxTask_t);
	RxInfo->RxTask_t = delta_t2;
	delta_ms = (SINT32) ktime_to_ms(delta_t1);

	if (delta_ms < 5) {
		/* < 5 ms */
		RxInfo->RxTaskCnt_t[0]++;
	} else if (delta_ms < 10) {
		/* 5 ms < delta time < 10 ms */
		RxInfo->RxTaskCnt_t[1]++;
	} else if (delta_ms < 100) {
		/* 10 ms < delta time < 100 ms */
		RxInfo->RxTaskCnt_t[2]++;
	} else if (delta_ms < 500) {
		/* 100 ms < delta time < 500 ms */
		RxInfo->RxTaskCnt_t[3]++;
	} else if (delta_ms < 1000) {
		/* 500 ms < delta time < 1000 ms */
		RxInfo->RxTaskCnt_t[4]++;
	} else {
		/* 1000 ms < delta time */
		RxInfo->RxTaskCnt_t[5]++;
	}
}

static void
trace_func_delta_end(vmacApInfo_t * vmacSta_p)
{
	RxTimeCntStat *RxInfo = &(vmacSta_p->Rx_StatInfo);
	ktime_t delta_t1;
	SINT32 delta_us;

	/* The unit is us */
	delta_t1 = ktime_sub(ktime_get_real(), RxInfo->RxTask_t);
	delta_us = (SINT32) ktime_to_us(delta_t1);

	if (delta_us < 50) {
		/* < 50 us */
		RxInfo->RxProcCnt_t[0]++;
	} else if (delta_us < 100) {
		/* 50 us < delta time < 100 us */
		RxInfo->RxProcCnt_t[1]++;
	} else if (delta_us < 300) {
		/* 100 us < delta time < 300 us */
		RxInfo->RxProcCnt_t[2]++;
	} else if (delta_us < 500) {
		/* 300 us < delta time < 500 us */
		RxInfo->RxProcCnt_t[3]++;
	} else {
		/* 500 us < delta time */
		RxInfo->RxProcCnt_t[4]++;
		if (delta_us > RxInfo->RxProcCnt_t[5]) {
			RxInfo->RxProcCnt_t[5] = delta_us;
		}
	}

	if ((RxInfo->RxQuCnt / 10) < 10) {
		RxInfo->RxQuStatCnt[RxInfo->RxQuCnt / 10]++;
	} else {
		RxInfo->RxQuStatCnt[10]++;
	}
	if ((RxInfo->RxMSDUCnt / 10) < 10) {
		RxInfo->RxMSDUStatCnt[RxInfo->RxMSDUCnt / 10]++;
	} else {
		RxInfo->RxMSDUStatCnt[10]++;
	}
}

/*
#if defined(ACNT_REC)
void wl_rxinfo_2_sbandinfo(RxSidebandInfo_t *prx_sband_info, rx_info_ppdu_t* prx_info)
{
	prx_sband_info->rssi_dbm_a = prx_info->bbrx_info.pm_rssi_dbm_a;
	prx_sband_info->rssi_dbm_b = prx_info->bbrx_info.pm_rssi_dbm_b;
	prx_sband_info->rssi_dbm_c = prx_info->bbrx_info.pm_rssi_dbm_c;
	prx_sband_info->rssi_dbm_d = prx_info->bbrx_info.pm_rssi_dbm_d;
	
	prx_sband_info->rssi_dbm_e = prx_info->bbrx_info.pm_rssi_dbm_e;
	prx_sband_info->rssi_dbm_f = prx_info->bbrx_info.pm_rssi_dbm_f;
	prx_sband_info->rssi_dbm_g = prx_info->bbrx_info.pm_rssi_dbm_g;
	prx_sband_info->rssi_dbm_h = prx_info->bbrx_info.pm_rssi_dbm_h;

	prx_sband_info->nf_dbm_a = prx_info->bbrx_info.pm_nf_dbm_a;
	prx_sband_info->nf_dbm_b = prx_info->bbrx_info.pm_nf_dbm_b;
	prx_sband_info->nf_dbm_c = prx_info->bbrx_info.pm_nf_dbm_c;
	prx_sband_info->nf_dbm_d = prx_info->bbrx_info.pm_nf_dbm_d;

	prx_sband_info->nf_dbm_e = prx_info->bbrx_info.pm_nf_dbm_e;
	prx_sband_info->nf_dbm_f = prx_info->bbrx_info.pm_nf_dbm_f;
	prx_sband_info->nf_dbm_g = prx_info->bbrx_info.pm_nf_dbm_g;
	prx_sband_info->nf_dbm_h = prx_info->bbrx_info.pm_nf_dbm_h;
	return; 
}

#endif //#if defined(ACNT_REC)
*/

int
wl_bad_mic_handler(struct wlprivate *wlpptr, UINT8 isUcast)
{
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;

	if ((vmacSta_p->OpMode == WL_OP_MODE_VSTA) ||
	    (vmacSta_p->OpMode == WL_OP_MODE_STA)) {
		vmacEntry_t *vmacEntry_p =
			vmacGetVMacEntryById(parentGetVMacId
					     (vmacSta_p->VMacEntry.
					      phyHwMacIndx));

		MICCounterMeasureInvoke_Sta(vmacEntry_p, isUcast);	//ucast for 11n-cert 5.2.17 //bcast for 11n-cert 5.2.18

		return 0;
	} else if (vmacSta_p->OpMode == WL_OP_MODE_VAP || vmacSta_p->OpMode == WL_OP_MODE_AP) {	//for 11n-cert 4.2.13
		/* disable N-4.2.13 case */
		MrvlMICErrorHdl(vmacSta_p, 0);
		//return 1;
		return 0;
	}

	return 0;
}

UINT32
wl_proc_mic_defrag(struct net_device * netdev, struct except_cnt * wlexcept_p,
		   wlrxdesc_t * pCfhul, struct sk_buff ** pRxSkBuff)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
	IEEEtypes_FrameCtl_t *frame_ctlp =
		(IEEEtypes_FrameCtl_t *) & pCfhul->frame_ctrl;
	extStaDb_StaInfo_t *pStaInfo = NULL;

	//DATA or MGMT frame
	if (pCfhul->icv_err || pCfhul->mic_err) {
		if (pCfhul->icv_err) {
			wlexcept_p->cnt_icv_err++;
		} else {
			if (pCfhul->euMode == SHAL_EU_MODE_TKIP) {
				/* check skb length to prevent false alarms */
				if ((*pRxSkBuff)->data[0] == (*pRxSkBuff)->len) {
					UINT8 isUcast =
						!IS_GROUP((UINT8 *) &
							  (*pRxSkBuff)->
							  data[0]);
					/* mwl_hex_dump((*pRxSkBuff)->data, (*pRxSkBuff)->len); */

					pStaInfo =
						extStaDb_GetStaInfo(vmacSta_p,
								    (IEEEtypes_MacAddr_t
								     *) &
								    (*pRxSkBuff)->
								    data[14],
								    STADB_SKIP_MATCH_VAP);
					if (pStaInfo) {
						vmacApInfo_t *vmactem_p = NULL;
						vmactem_p =
							vmacGetMBssByAddr
							(vmacSta_p,
							 pStaInfo->Bssid);
						if (vmactem_p) {
							wlpptr = NETDEV_PRIV_P
								(struct
								 wlprivate,
								 vmactem_p->
								 dev);
						}
					}
					wl_bad_mic_handler(wlpptr, isUcast);
				}
			}
			wlexcept_p->cnt_mic_err++;
		}
		wl_free_skb(*pRxSkBuff);
		*pRxSkBuff = NULL;
		return 1;	//continue                                    
	}
	if (frame_ctlp->MoreFrag || (pCfhul->hdr.seqNum & 0x000F)) {
		wlexcept_p->cnt_defrag_drop_x[0]++;	//total defrag processed
#ifdef CLIENT_SUPPORT
		if (*(mib->mib_STAMode))	//STA mode
		{
			pStaInfo = extStaDb_GetStaInfo(vmacSta_p,
						       (IEEEtypes_MacAddr_t *)
						       GetParentStaBSSID
						       (vmacSta_p->VMacEntry.
							phyHwMacIndx),
						       STADB_UPDATE_AGINGTIME);
		} else
#endif
#ifdef WDS_FEATURE
		if (*(mib->mib_wdsEnable))	//WDS mode
		{
			struct wds_port *pWdsPort;

			pWdsPort = getWdsPortFromNetDev(wlpptr, netdev);
			if (pWdsPort)
				pStaInfo =
					extStaDb_GetStaInfo(vmacSta_p,
							    &(pWdsPort->
							      wdsMacAddr),
							    STADB_UPDATE_AGINGTIME);
		} else
#endif
		{
			if (frame_ctlp->Type == IEEE_TYPE_DATA)
				pStaInfo =
					extStaDb_GetStaInfo(vmacSta_p,
							    (IEEEtypes_MacAddr_t
							     *) & (*pRxSkBuff)->
							    data[6],
							    STADB_SKIP_MATCH_VAP);
			else
				pStaInfo =
					extStaDb_GetStaInfo(vmacSta_p,
							    (IEEEtypes_MacAddr_t
							     *) & (*pRxSkBuff)->
							    data[10],
							    STADB_SKIP_MATCH_VAP);
		}
		if (pStaInfo) {
			if (((pCfhul->hdr.seqNum >> 4) !=
			     (pStaInfo->seqNum >> 4)) &&
			    pStaInfo->pDefragSkBuff) {
				if (pStaInfo->pDefragSkBuff) {
					wl_free_skb(pStaInfo->pDefragSkBuff);
					pStaInfo->pDefragSkBuff = NULL;
					wlexcept_p->cnt_defrag_drop++;
					wlexcept_p->cnt_defrag_drop_x[1]++;
				}
			}

			if ((pCfhul->hdr.seqNum & 0x000F) == 0)	//First frag packet
			{
				if (pStaInfo->pDefragSkBuff) {
					wl_free_skb(pStaInfo->pDefragSkBuff);
					wlexcept_p->cnt_defrag_drop++;
					wlexcept_p->cnt_defrag_drop_x[2]++;
				}
				pStaInfo->pDefragSkBuff = *pRxSkBuff;
				pStaInfo->seqNum = pCfhul->hdr.seqNum;
				*pRxSkBuff = NULL;
				return 1;	//continue;                                    
			} else {
				UINT32 leftLen;
				UINT32 new_cfh_offset, cur_cfh_offset;
				wlrxdesc_t *pTmpCfhul;

				if (pStaInfo->pDefragSkBuff == NULL) {
					wlexcept_p->cnt_defrag_drop++;
					wlexcept_p->cnt_defrag_drop_x[3]++;
					wl_free_skb(*pRxSkBuff);
					*pRxSkBuff = NULL;
					return 1;	//continue;                                                           
				}

				leftLen = skb_tailroom(pStaInfo->pDefragSkBuff);

				if (leftLen >
				    (pCfhul->cfh_offset + 16 +
				     sizeof(wlrxdesc_t))) {
					//increase space 
					UINT8 *ptr =
						skb_tail_pointer(pStaInfo->
								 pDefragSkBuff);
					UINT32 len, pktLen, offset;

					if (ptr != NULL) {
						if (frame_ctlp->Type ==
						    IEEE_TYPE_DATA) {
							offset = 14;	//DA+SA+Len
						} else {
							offset = pCfhul->macHdrLen - SMAC_HDR_LENGTH_BEFORE_MAC_HDR;	//4 BYTES                                                      
						}

						pktLen = ((*pRxSkBuff)->len -
							  offset);

						skb_put(pStaInfo->pDefragSkBuff,
							pktLen);
						memcpy(ptr,
						       &(*pRxSkBuff)->
						       data[offset], pktLen);

						if (frame_ctlp->Type ==
						    IEEE_TYPE_DATA) {
							len = SHORT_SWAP(*
									 ((UINT16 *) & pStaInfo->pDefragSkBuff->data[12])) + pktLen;
							*((UINT16 *) &
							  pStaInfo->
							  pDefragSkBuff->
							  data[12]) =
						   SHORT_SWAP(len);
						}
					} else {
						wlexcept_p->cnt_defrag_drop++;
						wlexcept_p->
							cnt_defrag_drop_x[4]++;
						wl_free_skb(*pRxSkBuff);
						*pRxSkBuff = NULL;

						wl_free_skb(pStaInfo->
							    pDefragSkBuff);
						pStaInfo->pDefragSkBuff = NULL;
						return 1;	//continue;                                                       
					}
				} else {
					wlexcept_p->cnt_defrag_drop++;
					wlexcept_p->cnt_defrag_drop_x[5]++;
					wl_free_skb(*pRxSkBuff);
					*pRxSkBuff = NULL;

					wl_free_skb(pStaInfo->pDefragSkBuff);
					pStaInfo->pDefragSkBuff = NULL;
					return 1;	//continue;                                                   
				}

				if (frame_ctlp->MoreFrag == 0)	//Last frag packet
				{
					U8 tempOffset = 0;

					new_cfh_offset =
						(pStaInfo->pDefragSkBuff->len +
						 16 + 0xF) & ~0xF;

					if (frame_ctlp->Type ==
					    IEEE_TYPE_MANAGEMENT)
						tempOffset =
							SMAC_MGMT_EXTRA_BYTE;

					cur_cfh_offset =
						pCfhul->cfh_offset - tempOffset;

					pTmpCfhul =
						(wlrxdesc_t *) & (*pRxSkBuff)->
						data[cur_cfh_offset];
					pTmpCfhul->cfh_offset = new_cfh_offset;
					pCfhul->cfh_offset =
						pTmpCfhul->cfh_offset;

					memcpy(&pStaInfo->pDefragSkBuff->
					       data[new_cfh_offset -
						    tempOffset],
					       &(*pRxSkBuff)->
					       data[cur_cfh_offset],
					       sizeof(wlrxdesc_t));

					wl_free_skb(*pRxSkBuff);
					*pRxSkBuff = pStaInfo->pDefragSkBuff;
					pStaInfo->pDefragSkBuff = NULL;

				} else	//Mid frag packet
				{
					wl_free_skb(*pRxSkBuff);
					*pRxSkBuff = NULL;
					return 1;	//continue;
				}
			}
		} else {
			wlexcept_p->cnt_defrag_drop++;
			wlexcept_p->cnt_defrag_drop_x[6]++;
			wl_free_skb(*pRxSkBuff);
			*pRxSkBuff = NULL;
			return 1;	//continue;                                           
		}
	}
	return 0;
}

#ifdef AP_TWT
u8 wfa_flag_5_60_1 = 0;
U32 wfa_mon_twt_rxtx = 0;	//0: Tx, 1:Rx. use U16 size 
u32 wfa_twt_rxing_flag_addr = 0;
u32 wfa_twt_rx_mon_time = 2000000;
u32 wfa_twt_tx_mon_time = 5000000;
u32 wfa_twt_rx_mon_length = 1400;

void
iTWT_monitor_Rx_start(struct wlprivate *wlpptr, u32 pktlen)
{
	static u64 twt_stick = 0;	//Long frame start timestamp  
	static u64 twt_stickS = 0;	//Short frame start timestamp

	static u32 twt_pktcntL = 0;	//Long frame count
	u64 curtime = 0;
	u64 diff;
	u32 cfg[64];
	static u32 itwtswcnt = 0;

	//volatile u32 *pfwFlag;

	//flag not enabled or FW flag address not initialized.
	if (wfa_flag_5_60_1 == 0 || wfa_twt_rxing_flag_addr == 0)
		goto exit;

	//start 5.60.1 testing

#if 0				//direct config PFW flag if the flag was located in DMEM area
	pfwFlag =
		(u32 *) (wlpptr->ioBase0 +
			 (wfa_twt_rxing_flag_addr - DMEM_BASE));
#endif
	curtime = xxGetTimeStamp();
	diff = curtime - twt_stick;

	if (pktlen > wfa_twt_rx_mon_length) {	//long frame

		//reset short Frame counting cycle
		twt_stickS = 0;

		if (wfa_mon_twt_rxtx == 1)	//already in Rx mode.
			goto exit;

		switch (twt_pktcntL) {
		case 0:
			twt_pktcntL++;
			twt_stick = curtime;
			break;
		case 1:
			if (diff < wfa_twt_rx_mon_time)	//500ms
				twt_pktcntL++;
			else {
				twt_pktcntL = 1;	//restart another counting cycle
				twt_stick = curtime;
			}
			break;
		case 2:
			if (diff < wfa_twt_rx_mon_time) {	//500ms
				wfa_mon_twt_rxtx = 1;
				/* We can also use iobase0 to access DMEM to configure PFW the flag directly. 
				   so, keep the code just in case we need to use later
				 */
#if 0
				//set PFW TWT Rx mode
				writel(1,
				       (wlpptr->ioBase0 +
					wfa_twt_rxing_flag_addr));
				printk("Set iTWT 5.60.1 Rx Mode:%u\n",
				       *pfwFlag);
				*pfwFlag = 1;
#else
				memset(cfg, 0, sizeof(cfg));
				cfg[0] = (TWT_WFA_RXMODE | TWT_WFA_CODEWORD <<
					  16 | ((++itwtswcnt) << 24));
				wlFwGetAddrValue(((wlpptr->master) ? wlpptr->
						  master : wlpptr->netDev),
						 wfa_twt_rxing_flag_addr, 4,
						 cfg, 1);
				printk("Set iTWT 5.60.1 Rx Mode\n");
#endif
				twt_pktcntL = 0;
				twt_stick = 0;
			} else {
				twt_pktcntL = 1;	//restart another counting cycle
				twt_stick = curtime;
			}
			break;
		}

	} else {		//short frame

		//if(pktlen > 1000) {
		//  printk("Rx mon length: %u\n", pktlen);
		//}

		if (twt_pktcntL) {	//there is existing Long frame counting cycle

			if (diff > wfa_twt_rx_mon_time) {	//reset long frame counting cycle
				twt_pktcntL = 0;
				twt_stick = 0;
				twt_stickS = 0;
			} else {
				twt_stickS = 0;
				goto exit;	//no count this in
			}
		}

		if (wfa_mon_twt_rxtx == 0) {	//not count short when fw is in Tx mode 
			twt_stickS = 0;
			goto exit;
		} else {	//FW in RX

			if (twt_stickS == 0)
				twt_stickS = curtime;
			else {

				if ((curtime - twt_stickS) > wfa_twt_tx_mon_time) {	//not long frame within 1 sec, UL traffic already stop
					//Toggle to TX mode
					wfa_mon_twt_rxtx = 0;
					//set PFW TWT Tx start
#if 1
					memset(cfg, 0, sizeof(cfg));
					cfg[0] = (TWT_WFA_NONRXMODE |
						  TWT_WFA_CODEWORD << 16 |
						  ((++itwtswcnt) << 24));
					if (!wlFwGetAddrValue
					    (((wlpptr->master) ? wlpptr->
					      master : wlpptr->netDev),
					     wfa_twt_rxing_flag_addr, 4, cfg,
					     1)) {
						printk("Clear iTWT 5.60.1 Rx Mode\n");
					} else {
						printk("Clear iTWT 5.60.1 Rx Mode fail..\n");
					}
#else
					//Code for use Iobase0 to direct access the flag. But the flag must be located in DMEM 
					writel(0,
					       (wlpptr->ioBase0 +
						wfa_twt_rxing_flag_addr));
					printk("Clear iTWT 5.60.1 Rx Mode:%u\n",
					       *pfwFlag);
					*pfwFlag = 0;
#endif
				}

			}
		}

	}

exit:
	return;

}

#endif

void
wlRecv(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	struct except_cnt *wlexcept_p = &wlpd_p->except_cnt;
	wlrxdesc_t *cfh_ul, cfh_ul_mem;

//#ifdef AMSDU_SPLIT
	wlrxdesc_t *cfh_ul_amsdu = NULL;
//#endif
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	struct sk_buff *pRxSkBuff = NULL;
	unsigned long flags;
	int work_done = 0;
	u_int32_t RxQs;
	u8 qid, qos;
	u32 msduNo = 0;
	int idx;
	u8 nullskb = FALSE;
	extStaDb_StaInfo_t *StaInfo_p;
	u16 stnid = rxring_Ctrl_STAfromDS;
	IEEEtypes_FrameCtl_t *frame_ctlp;
//#ifdef ENABLE_MONIF   
//      rx_info_t rx_info;
//#endif
	u_int32_t seq;
	//generic_buf *pgbuf = NULL;
#ifdef MULTI_AP_SUPPORT
	IEEEtypes_fullHdr_t *mac_hdr = NULL;
#endif
	trace_wlRecv_begin(netdev);

	trace_func_delta_begin(vmacSta_p);
	vmacSta_p->Rx_StatInfo.RxQuCnt = 0;
	vmacSta_p->Rx_StatInfo.RxMSDUCnt = 0;

	if (wlpptr->wlpd_p->bfwreset && !wlpptr->wlpd_p->bpreresetdone) {
		WLDBG_DATA(DBG_LEVEL_3,
			   "%s(), (bfwreset, bpreresetdone)=(%d, %d)\n",
			   __func__, wlpptr->wlpd_p->bfwreset,
			   wlpptr->wlpd_p->bpreresetdone);
		return;
	}

	local_irq_save(flags);
	RxQs = wlpptr->RxQId;
	wlpptr->RxQId = 0;
	local_irq_restore(flags);
	for_each_set_bit(qid, (unsigned long *)&RxQs, SC5_RXQ_NUM) {
		struct wldesc_data *wlqm = &wlpptr->wlpd_p->descData[qid];
		u32 wrinx;

#ifdef WIFI_DATA_OFFLOAD
		if (!wlpptr->wlpd_p->dol.disable && (qid == RX_Q_DATA)) {
			extern int ForwardFrame(struct net_device *dev,
						struct sk_buff *skb);

			while (1) {
				pRxSkBuff = dol_recv(wlpptr, true);
				if (pRxSkBuff) {
					vmacApInfo_t *vmactem_p;

					StaInfo_p =
						extStaDb_GetStaInfo(vmacSta_p,
								    (IEEEtypes_MacAddr_t
								     *) &
								    pRxSkBuff->
								    data[6],
								    STADB_SKIP_MATCH_VAP
								    |
								    STADB_NO_BLOCK);
					if (!StaInfo_p) {
						wl_free_skb(pRxSkBuff);
						continue;
					}
					vmactem_p =
						vmacGetMBssByAddr(vmacSta_p,
								  StaInfo_p->
								  Bssid);
					if (!vmactem_p) {
						wl_free_skb(pRxSkBuff);
						continue;
					}
					pRxSkBuff->dev = vmactem_p->dev;
					wlpptr = NETDEV_PRIV_P(struct wlprivate,
							       pRxSkBuff->dev);
					memcpy(&wlpptr->wlpd_p->mac_addr_sta_ta,
					       &pRxSkBuff->data[6],
					       IEEEtypes_ADDRESS_SIZE);
					ForwardFrame(vmactem_p->dev, pRxSkBuff);
				} else
					break;
			}
			continue;
		}
#endif

		if (((1 << qid) & SC5_RXQ_MASK) == 0) {	// Not enabled
			continue;
		}
		wlqm->sq.wrinx = wrinx = wlQueryWrPtr(netdev, qid, SC5_SQ);
		if (isSQFull(&wlqm->sq) == TRUE) {
			struct except_cnt *wlexcept_p = &wlpd_p->except_cnt;
			wlexcept_p->qfull_empty[qid][SC5_SQ]++;
		}
		WLDBG_INFO(DBG_LEVEL_3, "qid %d \n", qid);
		while ((wrinx != wlqm->sq.rdinx)
		       && (work_done < vmacSta_p->work_to_do)) {
			cfh_ul = wlGetCfhUl(netdev, qid, &cfh_ul_mem);
			if (cfh_ul == NULL) {
				// Update the rdindex => To keep receiving packets. Otherwise, the rx-path will block
				//wlqm->sq.rdinx++;
				//if (wlqm->sq.rdinx == qsize)
				//      wlqm->sq.rdinx = 0;
				wlSQIndexGet(&(wlqm->sq));
				break;
			}
			WLDBG_DATA(DBG_LEVEL_3, "org rxdesc:\n");
			WLDBG_HEXDUMP(DBG_LEVEL_3, cfh_ul, sizeof(wlrxdesc_t));
			vmacSta_p->Rx_StatInfo.RxQuCnt++;

			msduNo = 0;
			cfh_ul_amsdu =
				wlProcessMsdu(netdev, cfh_ul, &msduNo, qid);

			if (msduNo == 0 && cfh_ul_amsdu == NULL) {
				//down grade process error cfhul
				cfh_ul_amsdu =
					wlProcessErrCfhul(netdev, &msduNo);
				if (msduNo == 0 && cfh_ul_amsdu == NULL)
					//Amsdu subframe, keep collecting other subframes till lpkt is received.
					goto drop;
			}

			idx = 0;
			do {
				//RssiPathInfo_t                *prssi_path_info = NULL;
				wlrxdesc_t *pCurCfhul;
				u8 LMFbit;	//b2:last, b1:mid, b0:1st amsdu

				seq = (*(u_int32_t *) cfh_ul) & 0xffff0000;
				qos = cfh_ul->qos;
				if (cfh_ul_amsdu) {
					pCurCfhul = &cfh_ul_amsdu[idx];
					pRxSkBuff =
						wlCfhUlToSkb(netdev,
							     &cfh_ul_amsdu
							     [idx++], qid);
#ifdef MULTI_AP_SUPPORT
					if (pCurCfhul && (pCurCfhul->fpkt == 1)) {
						if (pRxSkBuff &&
						    (pRxSkBuff->
						     protocol &
						     WL_WLAN_TYPE_RX_FAST_DATA))
						{
							//cfhul_template = pRxSkBuff->data + pCurCfhul->cfh_offset;

							mac_hdr =
								(IEEEtypes_fullHdr_t
								 *) (pRxSkBuff->
								     data +
								     pCurCfhul->
								     cfh_offset
								     +
								     SMAC_MAC_HDR_OFFSET);
							memcpy(&wlpd_p->
							       mac_addr_sta_ta,
							       &mac_hdr->Addr2,
							       IEEEtypes_ADDRESS_SIZE);
						}
					}
#endif
				} else {
					pCurCfhul = cfh_ul;
					pRxSkBuff =
						wlCfhUlToSkb(netdev, cfh_ul,
							     qid);
				}
				if (pRxSkBuff == NULL) {
					// Something wrong in cfhul that skb can't be extracted successfully
					continue;
				}

				if (pCurCfhul)
					frame_ctlp =
						(IEEEtypes_FrameCtl_t *) &
						pCurCfhul->frame_ctrl;
				else {
					WLDBG_ERROR(DBG_LEVEL_0,
						    "pCurCfhul is NULL!\n");
					continue;
				}
#ifdef TP_PROFILE
				if (frame_ctlp->Type == IEEE_TYPE_DATA) {
					if (wl_tp_profile_test
					    (11, pRxSkBuff, netdev)) {
						wl_free_skb(pRxSkBuff);
						continue;
					}
				}
#endif
				if ((frame_ctlp->Type != IEEE_TYPE_CONTROL) &&
				    wl_proc_mic_defrag(netdev, wlexcept_p,
						       pCurCfhul, &pRxSkBuff)) {
					continue;
				}

				vmacSta_p->Rx_StatInfo.RxMSDUCnt++;
				LMFbit = (pCurCfhul->
					  lpkt << 2) |
					((~(pCurCfhul->lpkt | pCurCfhul->fpkt) &
					  0x1) << 1) | pCurCfhul->fpkt;
				if (pRxSkBuff == NULL) {
					wlCfhUlDump(pCurCfhul);
					WLDBG_WARNING(DBG_LEVEL_0,
						      "ERROR: RxQ SQ(%d) rdinx %x wrinx %x, skb is NULL\n",
						      qid, wlqm->sq.rdinx,
						      wlqm->sq.wrinx);
					nullskb = TRUE;
					wlexcept_p->msdu_err++;
					continue;
				}
				// rx_info processing
				wlrxinfo_notify_new_msdu(netdev, pCurCfhul, qid,
							 pRxSkBuff);

				if (qid == 0)
					wlexcept_p->qidcnt[0]++;
				else if (qid == 8)
					wlexcept_p->qidcnt[1]++;
				else if (qid == 9)
					wlexcept_p->qidcnt[2]++;

				WLDBG_DATA(DBG_LEVEL_3,
					   "dump [%u]th amsdu-subframe: len=%d\n",
					   ((idx) ? (idx - 1) : idx),
					   pRxSkBuff->len);
				WLDBG_HEXDUMP(DBG_LEVEL_3, pRxSkBuff->data,
					      pRxSkBuff->len);

#ifdef AP_TWT
				//TWT monitor for WFA                
				if (vmacSta_p->VMacEntry.phyHwMacIndx == 1) {
					//currently only work on SCBT. for SC5 later after PF7
					iTWT_monitor_Rx_start(wlpptr,
							      pRxSkBuff->len);
				}
#endif
				//add stnid
				if (qid == 0) {
					if ((frame_ctlp->FromDs == 0) &&
					    (frame_ctlp->ToDs == 0)) {
						wl_free_skb(pRxSkBuff);
						pRxSkBuff = NULL;
						wlexcept_p->msdu_err++;
						continue;
					} else if ((frame_ctlp->FromDs == 0) &&
						   (frame_ctlp->ToDs == 1)) {
						// Rx path, vmacSta_p is wdev0. Driver will match STA to VAP later
						//  TODO: Check if SFW can provide STA ID. Then we don't need to search STA INFO here
						if ((StaInfo_p =
						     extStaDb_GetStaInfo
						     (vmacSta_p,
						      (IEEEtypes_MacAddr_t *) &
						      wlpd_p->mac_addr_sta_ta,
						      STADB_SKIP_MATCH_VAP |
						      STADB_FIND_IN_CACHE |
						      STADB_NO_BLOCK)) ==
						    NULL) {
							// Failed to find StaInfo_p
							wl_free_skb(pRxSkBuff);
							pRxSkBuff = NULL;
							wlexcept_p->msdu_err++;
							continue;
						}
						stnid = StaInfo_p->StnId;
					} else if ((frame_ctlp->FromDs == 1) &&
						   (frame_ctlp->ToDs == 0)) {
						stnid = rxring_Ctrl_STAfromDS;
						pRxSkBuff->protocol |=
							WL_WLAN_TYPE_STA;
					} else if ((frame_ctlp->FromDs == 1) &&
						   (frame_ctlp->ToDs == 1)) {
						stnid = rxring_Ctrl_STAfromDS;
						pRxSkBuff->protocol |=
							WL_WLAN_TYPE_WDS;
#ifdef MULTI_AP_SUPPORT
						{
							extStaDb_StaInfo_t
								*pStaInfo =
								NULL;
							if (mac_hdr) {
								pStaInfo =
									extStaDb_GetStaInfo
									(vmacSta_p,
									 (IEEEtypes_MacAddr_t
									  *) &
									 mac_hdr->
									 Addr2,
									 STADB_SKIP_MATCH_VAP);
								if (pStaInfo)
									stnid = pStaInfo->StnId;
							}
						}
#endif
					}
					WLDBG_DATA(DBG_LEVEL_3, "stnid:%u\n",
						   stnid);
				}
				//Add to check skb buffer because some QA log shows panic in iperf process with virtual address at 0x3ffffbxxxxxxxx"
				if (qid == SC5_RXQ_PROMISCUOUS_INDEX) {

#ifdef ENABLE_MONIF
					if (((wlpptr->
					      vdev[wlpptr->wlpd_p->
						   MonIfIndex] != NULL) &&
					     (wlpptr->
					      vdev[wlpptr->wlpd_p->MonIfIndex]->
					      flags & IFF_RUNNING))) {
						//memset((void *)&rx_info, 0 ,sizeof(rx_info));
						if (pRxSkBuff != NULL) {
							//*(generic_buf**)pRxSkBuff->cb = pgbuf;
							//monif_handle_recv(wlpptr, &rx_info, pRxSkBuff, 1);
							monif_handle_recv
								(wlpptr,
								 &wlpd_p->
								 rxinfo_aux_poll
								 [pCurCfhul->
								  hdr.
								  rxInfoIndex],
								 pRxSkBuff, 1);
						}
					} else
#endif /* ENABLE_MONIF */
					{
						struct ieee80211_frame *wh =
							(struct ieee80211_frame
							 *)pRxSkBuff->data;
						struct IEEEtypes_Frame_t
							*wlanMsg_p =
							(IEEEtypes_Frame_t
							 *) ((UINT8 *)
							     pRxSkBuff->data -
							     2);

						wlanMsg_p->Hdr.FrmBodyLen =
							pRxSkBuff->len;
						if (wh->FrmCtl.Type ==
						    IEEE_TYPE_DATA) {
							if (wlpptr->
							    offchan_state ==
							    OFFCHAN_IDLE) {
								extStaDb_StaInfo_t
									*pStaInfo
									= NULL;
								vmacApInfo_t
									*vmactem_p
									= NULL;
								/* found vap from addr1 */
								vmactem_p =
									vmacGetMBssByAddr
									(vmacSta_p,
									 wh->
									 addr1);
								if (vmactem_p &&
								    (vmactem_p->
								     dev->
								     flags &
								     IFF_RUNNING))
								{
									pStaInfo = extStaDb_GetStaInfo(vmactem_p, (IEEEtypes_MacAddr_t *) (wh->addr2), STADB_UPDATE_AGINGTIME | STADB_NO_BLOCK);
									if ((pStaInfo == NULL || ((pStaInfo->State != ASSOCIATED) && !pStaInfo->AP))) {
#ifdef CB_SUPPORT
										struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, vmactem_p->dev);
										if (wlpptr->is_resp_mgmt == TRUE)
#endif //CB_SUPPORT
										{
											if (!vmactem_p->deauth_block) {
												vmactem_p->
													deauth_block
													=
													1;
												macMgmtMlme_SendDeauthenticateMsg
													(vmactem_p,
													 (IEEEtypes_MacAddr_t
													  *)
													 (wh->
													  addr2),
													 0,
													 IEEEtypes_REASON_CLASS3_NONASSOC,
													 TRUE);

												TimerFireIn
													(&vmactem_p->
													 deauth_block_timer,
													 1,
													 &reset_deauth_block_timer,
													 (unsigned
													  char
													  *)
													 vmactem_p,
													 1);
											}
										}
									}
								}
							}
#ifdef MULTI_AP_SUPPORT
							else {
								if (*
								    (vmacSta_p->
								     Mib802dot11->
								     mib_unassocsta_track_enabled))
									MSAN_unassocsta_recv_proc
										(vmacSta_p,
										 wlanMsg_p,
										 pCurCfhul->
										 hdr.
										 rssi);
							}
#endif /* MULTI_AP_SUPPORT */
						}
#ifdef IEEE80211K
						else if (wh->FrmCtl.Type ==
							 IEEE_TYPE_MANAGEMENT) {
							if (wlanMsg_p->Hdr.
							    FrmCtl.Subtype ==
							    IEEE_MSG_BEACON)
								MSAN_neighbor_bcnproc
									(netdev,
									 wlanMsg_p,
									 pRxSkBuff->
									 len,
									 &wlpd_p->
									 rssi_path_info,
									 SCAN_BY_OFFCHAN);
#ifdef MULTI_AP_SUPPORT
							else if (wlanMsg_p->Hdr.
								 FrmCtl.
								 Subtype ==
								 IEEE_MSG_PROBE_RQST)
							{
								if (*
								    (vmacSta_p->
								     Mib802dot11->
								     mib_unassocsta_track_enabled))
									MSAN_unassocsta_recv_proc
										(vmacSta_p,
										 wlanMsg_p,
										 pCurCfhul->
										 hdr.
										 rssi);
							}
#endif /* MULTI_AP_SUPPORT */
						}
#endif //IEEE80211K
						wl_free_skb(pRxSkBuff);
						wlpptr->netDevStats.
							rx_dropped++;
						pRxSkBuff = NULL;
						wlexcept_p->msdu_err++;
						continue;
					}
				} else {
					work_done +=
						ieee80211_input(netdev,
								pRxSkBuff,
								pCurCfhul->hdr.
								rssi,
								&wlpd_p->
								rssi_path_info,
								pCurCfhul,
								(idx ==
								 0 ? TRUE :
								 FALSE), stnid,
								LMFbit);
				}
				/*  Reset the cfh_ul signature to identify it's used */
				wlResetCfhUl(pCurCfhul);
				/* work_done+=ieee80211_input(netdev, pRxSkBuff,60,60,0,0,stnid); */
			} while (msduNo != idx);
drop:
			if (nullskb) {
				nullskb = FALSE;
				//break;
			}
			wlSQIndexGet(&(wlqm->sq));
		}		// end of while loop
		/* update write pointer */
		wlUpdateRdPtr(netdev, qid, SC5_SQ, wlqm->sq.rdinx, false);

	}			// end of RxQ loop

	trace_wlRecv_end(netdev);
	trace_func_delta_end(vmacSta_p);
	return;

}

void
wl_show_recv_info(struct net_device *netdev, char *sysfs_buff)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	RxTimeCntStat *RxInfo = &(wlpptr->vmacSta_p->Rx_StatInfo);
	UINT8 i;

	Sysfs_Printk("\nInterval Time of Rx Tasklet:\n");
	Sysfs_Printk
		(" | 0 ~ 5 ms | 5 ~ 10ms | 10 ~ 100ms | 100 ~ 500ms | 500 ~ 1s | 1s ~     |\n");
	Sysfs_Printk(" | %8d | %8d |   %8d |    %8d | %8d | %8d |\n",
		     RxInfo->RxTaskCnt_t[0], RxInfo->RxTaskCnt_t[1],
		     RxInfo->RxTaskCnt_t[2], RxInfo->RxTaskCnt_t[3],
		     RxInfo->RxTaskCnt_t[4], RxInfo->RxTaskCnt_t[5]);

	Sysfs_Printk("\nProcess Time of Rx Tasklet:\n");
	Sysfs_Printk
		(" | 0 ~ 50us | 50 ~ 100us | 100 ~ 300us | 300 ~ 500us | 500us ~  | max time    |\n");
	Sysfs_Printk(" | %8d |   %8d |    %8d |    %8d | %8d | %8d us |\n",
		     RxInfo->RxProcCnt_t[0], RxInfo->RxProcCnt_t[1],
		     RxInfo->RxProcCnt_t[2], RxInfo->RxProcCnt_t[3],
		     RxInfo->RxProcCnt_t[4], RxInfo->RxProcCnt_t[5]);

	Sysfs_Printk("\nReveive Queue Count:\n");
	for (i = 0; i < 10; i++) {
		Sysfs_Printk("~ %3d pkts: %8d\n", (i + 1) * 10,
			     RxInfo->RxQuStatCnt[i]);
	}
	Sysfs_Printk("> %3d pkts: %8d\n", i * 10, RxInfo->RxQuStatCnt[i]);

	Sysfs_Printk("\nReveive MSDU pkts Count:\n");
	for (i = 0; i < 10; i++) {
		Sysfs_Printk("~ %3d pkts: %8d\n", (i + 1) * 10,
			     RxInfo->RxMSDUStatCnt[i]);
	}
	Sysfs_Printk("> %3d pkts: %8d\n", i * 10, RxInfo->RxMSDUStatCnt[i]);

	memset(RxInfo, 0, sizeof(struct RxTimeCntStat));
}

void
reset_deauth_block_timer(UINT8 * data)
{
	vmacApInfo_t *vmacSta_p = (vmacApInfo_t *) data;

	if (vmacSta_p)
		vmacSta_p->deauth_block = 0;
}
