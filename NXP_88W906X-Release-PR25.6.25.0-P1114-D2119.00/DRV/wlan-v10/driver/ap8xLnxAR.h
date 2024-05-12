/** @file ap8xLnxAR.h
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2019-2020 NXP
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
#ifndef AP8X_AR_H_
#define AP8X_AR_H_
#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ieee80211.h>

#if defined(TXACNT_REC) && defined (SOC_W906X)
typedef struct _txacntppdu {
	U8 *acntTxBaseAddr_v;
	U32 acntTxBaseAddr_p;
	U32 acntTxSize;

	U8 *acntTxRdPtr_v;
	U32 *acntTxRdPtr_p;
//      U32                                     acntTxLastRecLen;
} txacntppdu;

typedef struct _mactxacnt_ppduinfo {
	struct sk_buff *txacnt_skb[TX_ACNT_MAX_NUM_AGGR][8];	//usr:tid:mpdu_id;msdu_id
	U8 txacnt_numMsdu[TX_ACNT_MAX_NUM_AGGR];
} mactxacnt_ppduinfo;

// Copied from smac_hal_inf.h
#define DRV_TX_ACNT_USER_NUM        16
#define DRV_TX_ACNT_MAX_NUM_TID     8

#endif				//defined(TXACNT_REC) && defined (SOC_W906X)

#if defined(TXACNT_REC) && defined (SOC_W906X)
extern void wlTxPPDUAcntHndl(struct net_device *netdev);
extern void wlTAcntBufInit(struct net_device *netdev);
#endif				//defined(TXACNT_REC) && defined (SOC_W906X)
#if defined(TXACNT_REC) && defined (SOC_W906X)
extern irqreturn_t wlSC5MSIX_TAcntRec(int irq, void *dev_id);
#endif				// defined(ACNT_REC) && defined (SOC_W906X)

extern void wlRxPPDUAcntHndl(struct net_device *netdev);
extern void wlRxAcntPPDUBufInit(struct net_device *netdev);
extern void wlRxAcntPPDUCleanup(struct net_device *netdev);
extern irqreturn_t wlSC5MSIX_RAcntRec(int irq, void *dev_id);
#endif				//AP8X_AR_H_
