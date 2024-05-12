/** @file ap8xLnxDesc.c
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
#include "ap8xLnxDesc.h"
#include "ap8xLnxIntf.h"
#include "ap8xLnxFwcmd.h"
#include "wldebug.h"
#include "ap8xLnxIoctl.h"
#include	<linux/module.h>
#include	<linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/slab.h>
#include 	<linux/mm.h>	/* mmap related stuff */
#include "ap8xLnxRegs.h"
/* default settings */

#define DEFAULT_ACNT_RING_SIZE   0x10000

/** external functions **/

/** external data **/

/** internal functions **/

/** public data **/

/** private data **/

/** private functions **/

/** local definitions **/

/** public functions **/
int wlTxRingAlloc(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	UINT8 *mem = NULL;
	UINT32 i;
	//default acnt size= 64K, each chunk = 4K
	for (i = 0; i < ACNT_NCHUNK; i++) {
		mem = wl_dma_alloc_coherent(wlpptr->wlpd_p->dev,
					    DEFAULT_SIZE_CHUNK, &wlpptr->wlpd_p->descData[0].pPhysAcntRing[i], wlpptr->wlpd_p->dma_alloc_flags);

		wlpptr->wlpd_p->mmap_ACNTChunk[i].data = mem;
	}
	wlpptr->wlpd_p->AcntChunkInfo.NumChunk = ACNT_NCHUNK;
	wlpptr->wlpd_p->AcntChunkInfo.SizeOfChunk = DEFAULT_SIZE_CHUNK;
	wlpptr->wlpd_p->descData[0].AcntRingSize = ACNT_NCHUNK * DEFAULT_SIZE_CHUNK;

	return SUCCESS;
}

int wlTxRingInit(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	int i;

	for (i = 0; i < NUM_OF_DESCRIPTOR_DATA; i++) {
		skb_queue_head_init(&wlpptr->wlpd_p->txQ[i]);
	}
	for (i = 0; i < NUM_OF_TCP_ACK_Q; i++) {
		skb_queue_head_init(&wlpptr->wlpd_p->tcp_ackQ[i]);
	}
	wlpptr->wlpd_p->tcp_ack_mod = 0;
	wlpptr->wlpd_p->fwDescCnt[0] = 0;

	return SUCCESS;
}

//dralee++
void wlTxRingFree(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	int i;
	struct sk_buff *skb;
	WLDBG_ENTER(DBG_LEVEL_12);

	for (i = 0; i < ACNT_NCHUNK; i++) {
		if (wlpptr->wlpd_p->mmap_ACNTChunk[i].data != NULL) {
			wl_dma_free_coherent(wlpptr->wlpd_p->dev,
					     DEFAULT_SIZE_CHUNK,
					     wlpptr->wlpd_p->mmap_ACNTChunk[i].data, wlpptr->wlpd_p->descData[0].pPhysAcntRing[i]);
			wlpptr->wlpd_p->mmap_ACNTChunk[i].data = NULL;
		}

	}

	for (i = 0; i < NUM_OF_DESCRIPTOR_DATA; i++) {
		while ((skb = skb_dequeue(&wlpptr->wlpd_p->txQ[i])) != NULL) {
			wl_free_skb(skb);
		}
	}

	WLDBG_EXIT(DBG_LEVEL_12);
}

void wlTxRingCleanup(struct net_device *netdev)
{
	wlTxRingInit(netdev);
}
