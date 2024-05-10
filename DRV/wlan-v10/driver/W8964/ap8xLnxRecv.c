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
#include "wldebug.h"
#include "ap8xLnxRegs.h"
#include "ap8xLnxDesc.h"
#include "ap8xLnxIntf.h"
#include "ap8xLnxXmit.h"
#include "ap8xLnxFwcmd.h"
#include "IEEE_types.h"
#include "wl_mib.h"
#include "wl_hal.h"
#include "StaDb.h"
#include "ap8xLnxDma.h"
#include "ds.h"
#include "keyMgmtSta.h"

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

#define W836X_RSSI_OFFSET 8

/* default settings */

/** external functions **/
/** external data **/

/** internal functions **/

/** public data **/

/** private data **/

/** public functions **/
//#define roundup(x, y)   ((((x)+((y)-1))/(y))*(y))

#ifdef ENABLE_MONIF
#ifdef NEW_DP
int monif_handle_recv(struct wlprivate *wlpptr, rx_info_t * pRxInfo,
		      struct sk_buff *skb, int promisc_data);
#else
extern int monif_handle_recv(struct wlprivate *wlpptr, wlrxdesc_t * pCurrent,
			     struct sk_buff *skb);
#endif
#endif

#ifdef NEW_DP
#define NEW_DP_ZERO_COPY
extern void wlTxDescriptorDump(struct net_device *netdev);

extern vmacEntry_t *sme_GetParentVMacEntry(UINT8 phyMacIndx);
extern void MICCounterMeasureInvoke_Sta(vmacEntry_t * vmacEntry_p,
					BOOLEAN isUnicast);

/*** new data path ***/
extern BOOLEAN bStartOffChanRx;
UINT32 OffChanRxCnt = 0;
extern STA_SYSTEM_MIBS *sme_GetStaSystemMibsPtr(vmacEntry_t * vmacEntry_p);
extern STA_SECURITY_MIBS *sme_GetStaSecurityMibsPtr(vmacEntry_t * vmacEntry_p);
int
wl_bad_mic_handler(struct wlprivate *wlpptr, vmacApInfo_t * vmacSta_p)
{
	vmacEntry_t *vmacEntry_p =
		sme_GetParentVMacEntry(vmacSta_p->VMacEntry.phyHwMacIndx);

	if ((vmacSta_p->OpMode == WL_OP_MODE_VSTA) ||
	    (vmacSta_p->OpMode == WL_OP_MODE_STA)) {
		struct net_device *pStaDev = wlpptr->vdev[MAX_VMAC_INSTANCE_AP];
		struct wlprivate *pStaPrv =
			NETDEV_PRIV_P(struct wlprivate, pStaDev);
		MIB_802DOT11 *pStaMib = pStaPrv->vmacSta_p->Mib802dot11;
		STA_SECURITY_MIBS *pStaSecurityMibs =
			sme_GetStaSecurityMibsPtr(vmacEntry_p);

		if (*(pStaMib->mib_cipherSuite) == IEEEtypes_RSN_CIPHER_SUITE_TKIP)	//for 11n-cert 5.2.17
			MICCounterMeasureInvoke_Sta(vmacEntry_p, TRUE);
		else if (pStaSecurityMibs->thisStaRsnIEWPA2_p->GrpKeyCipher[3] == RSN_TKIP_ID)	//for 11n-cert 5.2.18
			MICCounterMeasureInvoke_Sta(vmacEntry_p, FALSE);

		return 0;
	} else if (vmacSta_p->OpMode == WL_OP_MODE_VAP || vmacSta_p->OpMode == WL_OP_MODE_AP) {	//for 11n-cert 4.2.13
		/* disable N-4.2.13 case */
		//return 1;
		return 0;
	}

	return 0;
}

#ifdef NAPI
void wlInterruptUnMask(struct net_device *netdev, int mask);
int
wlRecvPoll(struct napi_struct *napi, int budget)
#else
void
wlRecv(struct net_device *netdev)
#endif
{
#ifdef NAPI
	struct wlprivate *wlpptr = container_of(napi, struct wlprivate, napi);
	struct net_device *netdev = wlpptr->netDev;
	int work_to_do = budget;
#else
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
#endif
	int work_done = 0;
	static Bool_e isFunctionBusy = WL_FALSE;
	struct sk_buff *pRxSkBuff = NULL;
	struct sk_buff *pRxSkBuff_tmp = NULL;
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
	u_int32_t rxDoneHead;
	u_int32_t rxDoneTail;
	u_int32_t rxDescHead;
	u_int32_t rxCnt = 0;
#ifdef ENABLE_MONIF
	int promisc_data = 0;
#endif
	int promisc_data_handle = 0;
	int removePN = 0;
	u_int16_t stnid;

	WLDBG_ENTER(DBG_LEVEL_14);

	if (wlpptr->wlpd_p->bfwreset && !wlpptr->wlpd_p->bpreresetdone)
		return;
	/* In a corner case the descriptors may be uninitialized and not usable, accessing these may cause a crash */
	if (isFunctionBusy /*|| (pCurrent == NULL) */ ) {
#ifdef NAPI
		napi_complete(napi);
		wlInterruptUnMask(netdev, MACREG_A2HRIC_BIT_RX_RDY);
#endif
		return
#ifdef NAPI
			1
#endif
			;
	}
	isFunctionBusy = WL_TRUE;

	rxDoneHead = readl(wlpptr->ioBase1 + MACREG_REG_RxDoneHead);
	rxDoneTail = readl(wlpptr->ioBase1 + MACREG_REG_RxDoneTail);
	rxDescHead = readl(wlpptr->ioBase1 + MACREG_REG_RxDescHead);
#ifdef NAPI
	while ((work_done < work_to_do) && rxDoneTail != rxDoneHead)
#else
	while (rxDoneTail != rxDoneHead && (work_done < vmacSta_p->work_to_do))
#endif
	{
		rx_ring_done_t *pRxRingDone;
		wlrxdesc_t *pRxDesc;
		rxCnt++;
		if (bStartOffChanRx) {
			OffChanRxCnt++;
		}
		pRxRingDone =
			&wlpptr->wlpd_p->descData[0].pRxRingDone[rxDoneTail++];
		wmb();
		pRxDesc =
			&wlpptr->wlpd_p->descData[0].pRxRing[pRxRingDone->
							     User & 0x3fff];
		if (pRxDesc->Data == 0)
			wlTxDescriptorDump(netdev);
		pRxSkBuff =
			wlpptr->wlpd_p->descData[0].Rx_vBufList[pRxRingDone->
								User & 0x3fff];
		wlpptr->netDevStats.rx_packets++;
		if (pRxSkBuff == NULL) {
			printk("skb is NULL");
			goto out;
		}
		if (*((UINT32 *) & pRxSkBuff->cb[16]) != 0xdeadbeef) {
			wlpptr->wlpd_p->signatureerror++;
			break;
		}
		if (((struct sk_buff *)pRxSkBuff)->next &&
		    ((struct sk_buff *)pRxSkBuff)->prev) {
			skb_unlink((struct sk_buff *)pRxSkBuff,
				   &wlpptr->wlpd_p->rxSkbTrace);
			*((UINT32 *) & pRxSkBuff->cb[16]) = 0xbeefdead;
		} else {
			wlpptr->wlpd_p->rxskbunlinkerror++;
			break;
		}
#ifdef NEW_DP_ZERO_COPY
		pci_unmap_single(wlpptr->pPciDev,
				 ENDIAN_SWAP32(pRxDesc->Data),
				 wlpptr->wlpd_p->descData[0].rxBufSize,
				 PCI_DMA_FROMDEVICE);
#endif
		removePN = 0;
		promisc_data_handle = 0;
		stnid = (ENDIAN_SWAP32(pRxRingDone->Ctrl) >>
			 rxring_Ctrl_STAshift) & rxring_Ctrl_STAmask;

		switch (ENDIAN_SWAP32(pRxRingDone->Ctrl) & rxring_Ctrl_CaseMask) {
		case rxring_Case_fast_data:
			{
				u_int16_t pktLen =
					(pRxSkBuff->data[12] << 8 | pRxSkBuff->
					 data[13]);
				if (skb_tailroom(pRxSkBuff) >= pktLen) {
					pktLen += sizeof(ether_hdr_t);
					skb_put(pRxSkBuff, pktLen);
				} else {
					wl_free_skb(pRxSkBuff);
					wlpptr->netDevStats.rx_dropped++;
					break;
				}
				if (stnid == rxring_Ctrl_STAfromDS) {
					pRxSkBuff->protocol |= WL_WLAN_TYPE_STA;
				}
				wlpptr->netDevStats.rx_bytes += pRxSkBuff->len;
				pRxSkBuff->protocol |=
					WL_WLAN_TYPE_RX_FAST_DATA;
				work_done +=
					ieee80211_input(netdev, pRxSkBuff, 60,
							60, 0, 0, stnid);
				wlpptr->wlpd_p->rxCnts.fastDataCnt++;
			}
			break;
		case rxring_Case_fast_bad_amsdu:
			wlpptr->wlpd_p->rxCnts.fastBadAmsduCnt++;
			wl_free_skb(pRxSkBuff);
			wlpptr->netDevStats.rx_dropped++;
			break;
		case rxring_Case_slow_bad_sta:
			wlpptr->wlpd_p->rxCnts.slowBadStaCnt++;
			wl_free_skb(pRxSkBuff);
			wlpptr->netDevStats.rx_dropped++;
			break;
		case rxring_Case_slow_del_done:
			if (FreeStnId_newdp(vmacSta_p, stnid) == 0)
				printk("invalid staid %d received\n", stnid);

			wl_free_skb(pRxSkBuff);
			wlpptr->netDevStats.rx_dropped++;
			break;
		case rxring_Case_drop:
			wlpptr->wlpd_p->rxCnts.dropCnt++;
			wl_free_skb(pRxSkBuff);
			wlpptr->netDevStats.rx_dropped++;
			break;
		case rxring_Case_slow_promisc:
			wlpptr->wlpd_p->rxCnts.slowPromiscCnt++;
			if (mib->PhyDSSSTable->CurrChan != pRxSkBuff->data[0]) {
				wlpptr->wlpd_p->rxCnts.offchPromiscCnt++;
			}
#ifdef ENABLE_MONIF
			if (wlpptr->vdev[MONIF_INDEX]->flags & IFF_RUNNING) {
				promisc_data = 1;
				goto do_rx_slowpath;
			} else {
				promisc_data_handle = 0x100;
				goto do_rx_slowpath;
			}
#else
			promisc_data_handle = 0x100;
			goto do_rx_slowpath;
			break;
#endif
		case rxring_Case_slow_bad_mic:
			wlpptr->wlpd_p->rxCnts.slowBadMicCnt++;

			if (wl_bad_mic_handler(wlpptr, vmacSta_p)) {
				/* by pass, assume decrypt err occurs and goto data path. Later will check mixed mode group key cipher */
				promisc_data_handle = 0x80 | 0x02;	//DECRYPT_ERR_MASK | TKIP_DECRYPT_MIC_ERR
				goto do_rx_slowpath;
			}
			wl_free_skb(pRxSkBuff);
			wlpptr->netDevStats.rx_dropped++;
			break;
		case rxring_Case_slow_bad_PN:
			wlpptr->wlpd_p->rxCnts.slowBadPNCnt++;
			wl_free_skb(pRxSkBuff);
			wlpptr->netDevStats.rx_dropped++;
			break;
		case rxring_Case_slow_noqueue:
			wlpptr->wlpd_p->rxCnts.slowNoqueueCnt++;
			removePN = 1;
			goto do_rx_slowpath;
		case rxring_Case_slow_norun:
			wlpptr->wlpd_p->rxCnts.slowNoRunCnt++;
			removePN = 1;
			goto do_rx_slowpath;
		case rxring_Case_slow_mcast:
			wlpptr->wlpd_p->rxCnts.slowMcastCnt++;
			goto do_rx_slowpath;
		case rxring_Case_slow_mgmt:
			wlpptr->wlpd_p->rxCnts.slowMgmtCnt++;
			removePN = 1;
do_rx_slowpath:
		default:
			{
				rx_info_t *pRxInfo;
				unsigned short frmLen;
				pRxSkBuff_tmp = pRxSkBuff;
				if (pRxSkBuff != NULL) {
					IEEEtypes_GenHdr_t *pHdr;
					u_int8_t *p;
					u_int16_t weplenadjust = 0;
					u_int16_t keyType;
					pRxInfo = (rx_info_t *) pRxSkBuff->data;
					wmb();
					p = (u_int8_t *) & pRxInfo->Hdr[0];
					pHdr = (IEEEtypes_GenHdr_t *) &
						pRxInfo->Hdr[0];
					frmLen = ENDIAN_SWAP16(pHdr->
							       FrmBodyLen);

					if (pHdr->FrmCtl.Wep && removePN) {
						keyType =
							(ENDIAN_SWAP32
							 (pRxRingDone->
							  Ctrl) >>
							 rxring_Ctrl_KEYshift) &
							rxring_Ctrl_KEYmask;

						if ((keyType == key_type_WEP40)
						    || (keyType ==
							key_type_WEP104)) {
							frmLen -= 4;
							weplenadjust = 4;
						} else {
							frmLen -= 8;
							weplenadjust = 8;
						}
					}

					if (frmLen > 0) {

						if (skb_tailroom(pRxSkBuff) >=
						    (frmLen +
						     sizeof(rx_info_t) +
						     sizeof
						     (IEEEtypes_GenHdr_t))) {
							skb_put(pRxSkBuff,
								(frmLen +
								 sizeof
								 (rx_info_t) +
								 sizeof
								 (IEEEtypes_GenHdr_t)));

							//remove framebodyLen 2 bytes and rxInfo and PN/IV
							p = (u_int8_t *) &
								pRxSkBuff->
								data[2 +
								     sizeof
								     (rx_info_t)];
							skb_pull(pRxSkBuff,
								 (2 +
								  sizeof
								  (rx_info_t) +
								  weplenadjust));
							if (weplenadjust &&
							    removePN) {
								int index;

								for (index =
								     (sizeof
								      (IEEEtypes_GenHdr_t)
								      - 3);
								     index >= 0;
								     index--) {
									p[index
									  +
									  weplenadjust]
									  =
									  p
									  [index];
								}
							}
						} else {
							wl_free_skb(pRxSkBuff);
							wlpptr->netDevStats.
								rx_dropped++;
							break;
						}
						wlpptr->netDevStats.rx_bytes +=
							pRxSkBuff->len;
#ifdef ENABLE_MONIF
						if (wlpptr->vdev[MONIF_INDEX]->
						    flags & IFF_RUNNING)
							monif_handle_recv
								(wlpptr,
								 pRxInfo,
								 pRxSkBuff,
								 promisc_data);

						if (!promisc_data)
#endif
							work_done +=
								ieee80211_input
								(netdev,
								 pRxSkBuff,
								 pRxInfo->
								 rssi_x,
								 pRxInfo->
								 rssi_x, 0,
								 promisc_data_handle,
								 stnid);

					} else	//frmlen <=0; 
					{
						wl_free_skb(pRxSkBuff);
						wlpptr->netDevStats.
							rx_dropped++;
						break;
					}
				} else {
					printk("skb is NULL");
				}
			}
		}
		pRxSkBuff = wl_alloc_skb(wlpptr->wlpd_p->descData[0].rxBufSize);
		if (pRxSkBuff != NULL) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
			if (skb_linearize(pRxSkBuff))
#else
			if (skb_linearize(pRxSkBuff, GFP_ATOMIC))
#endif
			{
				wl_free_skb(pRxSkBuff);
				printk(KERN_ERR "%s: Need linearize memory\n",
				       netdev->name);
				goto out;
			}

			skb_reserve(pRxSkBuff, MIN_BYTES_HEADROOM);
			pRxDesc->Data =
				ENDIAN_SWAP32(pci_map_single(wlpptr->pPciDev,
							     pRxSkBuff->data,
							     wlpptr->wlpd_p->
							     descData[0].
							     rxBufSize,
							     PCI_DMA_FROMDEVICE));
			wlpptr->wlpd_p->descData[0].Rx_vBufList[pRxRingDone->
								User & 0x3fff] =
				pRxSkBuff;
			*((UINT32 *) & pRxSkBuff->cb[16]) = 0xdeadbeef;
			skb_queue_tail(&wlpptr->wlpd_p->rxSkbTrace, pRxSkBuff);
#ifdef __aarch64__
			dmb(sy);
#else
			dmb();
#endif
			// for bringup
#if 0
			if (pRxSkBuff_tmp != NULL) {
				printk("*pRxSkBuff_tmp= %x * \n",
				       (u_int32_t) pRxSkBuff_tmp);
				dev_kfree_skb_any(pRxSkBuff_tmp);
			}
#endif
		}
out:
		if (rxDoneTail >= MAX_RX_RING_DONE_SIZE)
			rxDoneTail = 0;

		readl(wlpptr->ioBase1 + MACREG_REG_RxDoneHead);
	}

	rxDescHead += rxCnt;
	if (rxDescHead >= MAX_RX_RING_SEND_SIZE) {
		rxDescHead = rxDescHead - MAX_RX_RING_SEND_SIZE;
	}
	writel(rxDoneTail, wlpptr->ioBase1 + MACREG_REG_RxDoneTail);
	writel(rxDescHead, wlpptr->ioBase1 + MACREG_REG_RxDescHead);
	isFunctionBusy = WL_FALSE;
}
#else
/*** old data path ***/
#ifdef NAPI
void wlInterruptUnMask(struct net_device *netdev, int mask);
int
wlRecvPoll(struct napi_struct *napi, int budget)
#else
void
wlRecv(struct net_device *netdev)
#endif
{
#ifdef NAPI
	struct wlprivate *wlpptr = container_of(napi, struct wlprivate, napi);
	struct net_device *netdev = wlpptr->netDev;
	int work_to_do = budget;
#else
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
#endif
	int work_done = 0;
	wlrxdesc_t *pCurrent = wlpptr->wlpd_p->descData[0].pNextRxDesc;
	static Bool_e isFunctionBusy = WL_FALSE;
	int receivedHandled = 0;
	u_int32_t rxRdPtr;
	u_int32_t rxWrPtr;
	struct sk_buff *pRxSkBuff = NULL;
	void *pCurrentData;
	u_int8_t rxRate;
	int rxCount;
	int rssi;
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	u_int32_t status;
#ifdef SOC_W8764
	u_int32_t rssi_paths;
#endif
#ifdef QUEUE_STATS_LATENCY
	UINT32 curr_tm;		/*Used for Rx latency calculation */
#endif
#ifndef ZERO_COPY_RX
	int allocLen;
#endif
	WLDBG_ENTER(DBG_LEVEL_14);

	/* In a corner case the descriptors may be uninitialized and not usable, accessing these may cause a crash */
	if (isFunctionBusy || (pCurrent == NULL)) {
#ifdef NAPI
		napi_complete(napi);
		wlInterruptUnMask(netdev, MACREG_A2HRIC_BIT_RX_RDY);
#endif
		return
#ifdef NAPI
			1
#endif
			;
	}
	isFunctionBusy = WL_TRUE;

	rxRdPtr =
		readl(wlpptr->ioBase0 + wlpptr->wlpd_p->descData[0].rxDescRead);
	rxWrPtr =
		readl(wlpptr->ioBase0 +
		      wlpptr->wlpd_p->descData[0].rxDescWrite);

#ifdef NAPI
	while ((work_done < work_to_do) &&
	       pCurrent->RxControl == EAGLE_RXD_CTRL_DMA_OWN)
#else
	while ((pCurrent->RxControl == EAGLE_RXD_CTRL_DMA_OWN) &&
	       (work_done < vmacSta_p->work_to_do))
#endif
	{

#ifdef QUEUE_STATS
#ifdef QUEUE_STATS_LATENCY
		{
			/* Calculate fw-to-drv DMA latency */
			WLDBG_RX_REC_PKT_FWToDRV_TIME(pCurrent,
						      PciReadMacReg(netdev,
								    0x600));
		}
#endif
#ifdef QUEUE_STATS_CNT_HIST
		/* Count Rx packets based on matching Tag */
		if ((pCurrent->qsRxTag & 0xf0) == 0xA0) {
			WLDBG_INC_RX_RECV_POLL_CNT_STA((pCurrent->
							qsRxTag & 0x0f));
			pCurrent->qsRxTag = 0;
		}
#endif
#endif

#ifdef AUTOCHANNEL
		{
			if (vmacSta_p->StopTraffic)
				goto out;
		}
#endif

		rxCount = ENDIAN_SWAP16(pCurrent->PktLen);
#ifdef ZERO_COPY_RX
		pRxSkBuff = pCurrent->pSkBuff;
		if (pRxSkBuff == NULL) {
			goto out;
		}
		pci_unmap_single(wlpptr->pPciDev,
				 ENDIAN_SWAP32(pCurrent->pPhysBuffData),
				 wlpptr->wlpd_p->descData[0].rxBufSize,
				 PCI_DMA_FROMDEVICE);
#else
		// at least mtu size, otherwise defragment will fail 
		if (rxCount > netdev->mtu)
			allocLen = rxCount + NUM_EXTRA_RX_BYTES;
		else
			allocLen = netdev->mtu + NUM_EXTRA_RX_BYTES;
		pRxSkBuff = wl_alloc_skb(allocLen);
		if (pRxSkBuff == NULL) {
			WLDBG_INFO(DBG_LEVEL_14, "out of skb\n");
			goto out;
		}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
		if (skb_linearize(pRxSkBuff))
#else
		if (skb_linearize(pRxSkBuff, GFP_ATOMIC))
#endif
		{
			wl_free_skb(pRxSkBuff);
			printk(KERN_ERR "%s: Need linearize memory\n",
			       netdev->name);
			goto out;
		}
		//invalidate cashe for platiform with L2 cashe enabled.
		pCurrent->pPhysBuffData =
			ENDIAN_SWAP32(pci_map_single(wlpptr->pPciDev,
						     pCurrent->pSkBuff->data,
						     wlpptr->wlpd_p->
						     descData[0].rxBufSize,
						     PCI_DMA_FROMDEVICE));
		skb_reserve(pRxSkBuff, MIN_BYTES_HEADROOM);
#endif
		pCurrentData = pCurrent->pBuffData;
		rxRate = pCurrent->Rate;
		status = (u_int32_t) pCurrent->Status;
		pRxSkBuff->protocol = 0;
#ifdef WMON
		if (pCurrent->QosCtrl & 0x5) {
			g_wmon_videoTrafficRx++;
		}
#endif //WMON
#ifndef ZERO_COPY_RX
		memcpy(pRxSkBuff->data,
		       pCurrentData + OFFS_RXFWBUFF_IEEE80211HEADER,
		       NBR_BYTES_COMPLETE_IEEE80211HEADER);
#endif
		if (pCurrent->QosCtrl & IEEE_QOS_CTL_AMSDU) {
			pRxSkBuff->protocol |= WL_WLAN_TYPE_AMSDU;
		}
		rssi = (int)pCurrent->RSSI + W836X_RSSI_OFFSET;
#ifdef SOC_W8764
		rssi_paths = *((u_int32_t *) & pCurrent->HwRssiInfo);
#endif
#ifdef WMON
		if (g_wmon_rssi_count >= WMON_MAX_RSSI_COUNT) {
			g_wmon_rssi_count = 0;
		}
		g_wmon_rssi[g_wmon_rssi_count++] = rssi;
#endif
#ifdef ZERO_COPY_RX
		/*refer to CL#30682, catch the skb over panic issue */
		if (skb_tailroom(pRxSkBuff) >= rxCount) {
			skb_put(pRxSkBuff, rxCount);
			skb_pull(pRxSkBuff, 2);
		} else {
			printk("\nCritial error, skb->len=%d, rxCount=%d\n\n",
			       (int)pRxSkBuff->len, (int)rxCount);
			goto out;
		}
#else
		if (skb_tailroom(pRxSkBuff) >= (rxCount - 2)) {
			memcpy(&pRxSkBuff->
			       data[NBR_BYTES_COMPLETE_IEEE80211HEADER],
			       pCurrentData + OFFS_RXFWBUFF_IEEE80211PAYLOAD,
			       rxCount - OFFS_RXFWBUFF_IEEE80211PAYLOAD);
			skb_put(pRxSkBuff, rxCount - 2);	// 2 byte len + 6 bytes address
		} else {
			WLDBG_INFO(DBG_LEVEL_14,
				   "Not enough tail room =%x recvlen=%x, pCurrent=%x, pCurrentData=%x",
				   skb_tailroom(pRxSkBuff), rxCount, pCurrent,
				   pCurrentData);
			wl_free_skb(pRxSkBuff);
			goto out;
		}
#endif

		wlpptr->netDevStats.rx_packets++;

#ifdef ENABLE_MONIF
		if (wlpptr->vdev[MONIF_INDEX]->flags & IFF_RUNNING) {
			monif_handle_recv(wlpptr, pCurrent, pRxSkBuff);
		}
#endif

#ifdef AMPDU_SUPPORT
		if (pCurrent->HtSig2 & 0x8) {
			u_int8_t ampdu_qos;
			/** use bit 3 for ampdu flag, and 0,1,2,3 for qos so as to save a register **/
			ampdu_qos =
				8 | (ENDIAN_SWAP16(pCurrent->QosCtrl) & 0x7);
#ifdef SOC_W8764
			work_done +=
				ieee80211_input(netdev, pRxSkBuff, rssi,
						rssi_paths, ampdu_qos, status);
#else
			work_done +=
				ieee80211_input(netdev, pRxSkBuff, rssi,
						ampdu_qos, status);
#endif
		} else {
			u_int8_t ampdu_qos;
			/** use bit 3 for ampdu flag, and 0,1,2,3 for qos so as to save a register **/
			ampdu_qos =
				0 | (ENDIAN_SWAP16(pCurrent->QosCtrl) & 0x7);
#ifdef SOC_W8764
			work_done +=
				ieee80211_input(netdev, pRxSkBuff, rssi,
						rssi_paths, ampdu_qos, status);
#else
			work_done +=
				ieee80211_input(netdev, pRxSkBuff, rssi,
						ampdu_qos, status);
#endif
		}
#else
#ifdef SOC_W8764
		work_done +=
			ieee80211_input(netdev, pRxSkBuff, rssi, rssi_paths,
					status);
#else
		work_done += ieee80211_input(netdev, pRxSkBuff, rssi, status);
#endif
#endif
		//wlpptr->netDevStats.rx_bytes += pRxSkBuff->len;
#ifdef ZERO_COPY_RX
		{
			pCurrent->pSkBuff =
				wl_alloc_skb(wlpptr->wlpd_p->descData[0].
					     rxBufSize);
			if (pCurrent->pSkBuff != NULL) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
				if (skb_linearize(pCurrent->pSkBuff))
#else
				if (skb_linearize
				    (pCurrent->pSkBuff, GFP_ATOMIC))
#endif
				{
					wl_free_skb(pCurrent->pSkBuff);
					printk(KERN_ERR
					       "%s: Need linearize memory\n",
					       netdev->name);
					goto out;
				}

				skb_reserve(pCurrent->pSkBuff,
					    MIN_BYTES_HEADROOM);
				pCurrent->Status = EAGLE_RXD_STATUS_OK;
				pCurrent->QosCtrl = 0x0000;
				pCurrent->Channel = 0x00;
				pCurrent->RSSI = 0x00;
				pCurrent->SQ2 = 0x00;

				pCurrent->PktLen =
					6 * netdev->mtu + NUM_EXTRA_RX_BYTES;
				pCurrent->pBuffData = pCurrent->pSkBuff->data;
				pCurrent->pPhysBuffData =
					ENDIAN_SWAP32(pci_map_single
						      (wlpptr->pPciDev,
						       pCurrent->pSkBuff->data,
						       wlpptr->wlpd_p->
						       descData[0].
						       rxBufSize
						       /*+sizeof(struct skb_shared_info) */
						       ,
						       PCI_DMA_BIDIRECTIONAL));
			}
		}
#endif
out:

#ifdef QUEUE_STATS
#ifdef QUEUE_STATS_LATENCY
		/* Calculate drv latency and total latency from fw start to drv end */
		{
			curr_tm = PciReadMacReg(netdev, 0x600);
			WLDBG_RX_REC_PKT_DRV_TIME(pCurrent, curr_tm);
			WLDBG_RX_REC_PKT_TOTAL_TIME(pCurrent, curr_tm);
		}
#endif
#endif

		receivedHandled++;
		pCurrent->RxControl = EAGLE_RXD_CTRL_DRIVER_OWN;
		pCurrent->QosCtrl = 0;
		rxRdPtr = ENDIAN_SWAP32(pCurrent->pPhysNext);
		pCurrent = pCurrent->pNext;
	}
	writel(rxRdPtr,
	       wlpptr->ioBase0 + wlpptr->wlpd_p->descData[0].rxDescRead);
	wlpptr->wlpd_p->descData[0].pNextRxDesc = pCurrent;
	isFunctionBusy = WL_FALSE;
	WLDBG_EXIT(DBG_LEVEL_14);
#ifdef NAPI
	if (work_done < work_to_do || (!netif_running(netdev))) {
		napi_complete(napi);
		wlInterruptUnMask(netdev, MACREG_A2HRIC_BIT_RX_RDY);
	}
	/* notify upper layer about more work to do */
	return (work_done);
#endif
}
#endif
