/** @file ap8xLnxDesc.c
 * IMPORTANT
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
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/slab.h>
#include <linux/mm.h> /* mmap related stuff */
#ifndef VM_RESERVED
#define VM_RESERVED (VM_DONTEXPAND | VM_DONTDUMP)
#endif
#include "ap8xLnxRegs.h"
/* default settings */

/** external functions **/

/** external data **/

/** internal functions **/

/** public data **/

/** private data **/

/** private functions **/

/** local definitions **/

#define MAX_NUM_TX_RING_BYTES MAX_NUM_TX_DESC * sizeof(wltxdesc_t)
#define MAX_NUM_RX_RING_BYTES MAX_NUM_RX_DESC * sizeof(wlrxdesc_t)
#ifdef NEW_DP
#define MAX_NUM_TX_RING_DONE_BYTES MAX_NUM_TX_DESC * sizeof(tx_ring_done_t)
#define MAX_NUM_RX_RING_DONE_BYTES MAX_NUM_RX_DESC * sizeof(rx_ring_done_t)
#endif

#define FIRST_TXD(i) wlpptr->wlpd_p->descData[i].pTxRing[0]
#define CURR_TXD(i) wlpptr->wlpd_p->descData[i].pTxRing[currDescr]
#define NEXT_TXD(i) wlpptr->wlpd_p->descData[i].pTxRing[currDescr + 1]
#define LAST_TXD(i) wlpptr->wlpd_p->descData[i].pTxRing[MAX_NUM_TX_DESC - 1]

#define FIRST_RXD wlpptr->wlpd_p->descData[0].pRxRing[0]
#define CURR_RXD wlpptr->wlpd_p->descData[0].pRxRing[currDescr]
#define NEXT_RXD wlpptr->wlpd_p->descData[0].pRxRing[currDescr + 1]
#define LAST_RXD wlpptr->wlpd_p->descData[0].pRxRing[MAX_NUM_RX_DESC - 1]

/** public functions **/
#ifdef NEW_DP
void *pTestBuf;
dma_addr_t pPhysTestBuf;
#endif

int wlTxRingAlloc(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
#ifdef NEW_DP
	UINT8 *mem = (UINT8 *)pci_alloc_consistent(wlpptr->pPciDev,
											   MAX_NUM_TX_RING_BYTES,
											   &wlpptr->wlpd_p->descData[0].pPhysTxRing);

	WLDBG_ENTER_INFO(DBG_LEVEL_12, "allocating %i (0x%x) bytes",
					 MAX_NUM_TX_RING_BYTES, MAX_NUM_TX_RING_BYTES);
	wlpptr->wlpd_p->descData[0].pTxRing = (wltxdesc_t *)mem;
	wlpptr->wlpd_p->descData[0].pPhysTxRing =
		(dma_addr_t)((UINT32)wlpptr->wlpd_p->descData[0].pPhysTxRing);
	if (wlpptr->wlpd_p->descData[0].pTxRing == NULL)
	{
		WLDBG_ERROR(DBG_LEVEL_12, "can not alloc Tx ring");
		return FAIL;
	}
	memset(wlpptr->wlpd_p->descData[0].pTxRing, 0x00,
		   MAX_NUM_TX_RING_BYTES);
	WLDBG_EXIT_INFO(DBG_LEVEL_12, "TX ring vaddr: 0x%x paddr: 0x%x",
					wlpptr->wlpd_p->descData[0].pTxRing,
					wlpptr->wlpd_p->descData[0].pPhysTxRing);
	mem = (UINT8 *)pci_alloc_consistent(wlpptr->pPciDev,
										MAX_NUM_TX_RING_DONE_BYTES,
										&wlpptr->wlpd_p->descData[0].pPhysTxRingDone);

	wlpptr->wlpd_p->descData[0].pTxRingDone = (tx_ring_done_t *)mem;
	wlpptr->wlpd_p->descData[0].pPhysTxRingDone =
		(dma_addr_t)((UINT32)wlpptr->wlpd_p->descData[0].pPhysTxRingDone);
	if (wlpptr->wlpd_p->descData[0].pTxRingDone == NULL)
	{
		WLDBG_ERROR(DBG_LEVEL_12, "can not alloc Tx done ring");
		return FAIL;
	}
	memset(wlpptr->wlpd_p->descData[0].pTxRingDone, 0x00,
		   MAX_NUM_TX_RING_DONE_BYTES);
#ifdef NEWDP_ACNT_CHUNKS
	// default acnt size= 64K, each chunk = 4K
	for (i = 0; i < ACNT_NCHUNK; i++)
	{
		mem = (UINT8 *)pci_alloc_consistent(wlpptr->pPciDev,
											DEFAULT_SIZE_CHUNK,
											&wlpptr->wlpd_p->descData[0].pPhysAcntRing[i]);
		wlpptr->wlpd_p->mmap_ACNTChunk[i].data = mem;
	}
	wlpptr->wlpd_p->AcntChunkInfo.NumChunk = ACNT_NCHUNK;
	wlpptr->wlpd_p->AcntChunkInfo.SizeOfChunk = DEFAULT_SIZE_CHUNK;
	wlpptr->wlpd_p->descData[0].AcntRingSize =
		ACNT_NCHUNK * DEFAULT_SIZE_CHUNK;
#else
	mem = (UINT8 *)pci_alloc_consistent(wlpptr->pPciDev,
										DEFAULT_ACNT_RING_SIZE,
										&wlpptr->wlpd_p->descData[0].pPhysAcntRing);

	wlpptr->wlpd_p->descData[0].pAcntRing = (u_int8_t *)mem;
	if (wlpptr->wlpd_p->descData[0].pAcntRing == NULL)
	{
		WLDBG_ERROR(DBG_LEVEL_12,
					"** newTestDP: Can not alloc acnt ring\n");
		return FAIL;
	}
	wlpptr->wlpd_p->ACNTmemInfo.data = mem;
	wlpptr->wlpd_p->ACNTmemInfo.dataPhysicalLoc =
		wlpptr->wlpd_p->descData[0].pPhysAcntRing;

	wlpptr->wlpd_p->descData[0].pAcntBuf =
		(u_int8_t *)kmalloc(DEFAULT_ACNT_RING_SIZE, GFP_KERNEL);
	if (wlpptr->wlpd_p->descData[0].pAcntBuf == NULL)
	{
		WLDBG_ERROR(DBG_LEVEL_12,
					"** newTestDP: Can not alloc acnt buf\n");
		return FAIL;
	}

	wlpptr->wlpd_p->descData[0].AcntRingSize = DEFAULT_ACNT_RING_SIZE;
#endif

	mem = (UINT8 *)pci_alloc_consistent(wlpptr->pPciDev,
										sizeof(Info_rate_power_table_t),
										&wlpptr->wlpd_p->descData[0].pPhyInfoPwrTbl);

	wlpptr->wlpd_p->descData[0].pInfoPwrTbl = (u_int8_t *)mem;
	if (wlpptr->wlpd_p->descData[0].pInfoPwrTbl == NULL)
	{
		WLDBG_ERROR(DBG_LEVEL_12,
					"** newTestDP: Can not alloc Per Rate tx power table\n");
		return FAIL;
	}

	mem = (UINT8 *)pci_alloc_consistent(wlpptr->pPciDev,
										sizeof(offchan_shared_t),
										&wlpptr->wlpd_p->descData[0].pPhyoffchanshared);

	wlpptr->wlpd_p->descData[0].poffchanshared = (u_int8_t *)mem;
	if (wlpptr->wlpd_p->descData[0].poffchanshared == NULL)
	{
		WLDBG_ERROR(DBG_LEVEL_12,
					"** newTestDP: Can not alloc offchan shared\n");
		return FAIL;
	}
	memset(mem, 0, sizeof(offchan_shared_t));

#else
	int num;
	UINT8 *mem = (UINT8 *)pci_alloc_consistent(wlpptr->pPciDev,
											   MAX_NUM_TX_RING_BYTES *
												   NUM_OF_DESCRIPTOR_DATA,
											   &wlpptr->wlpd_p->descData[0].pPhysTxRing);
	for (num = 0; num < NUM_OF_DESCRIPTOR_DATA; num++)
	{

		WLDBG_ENTER_INFO(DBG_LEVEL_12, "allocating %i (0x%x) bytes",
						 MAX_NUM_TX_RING_BYTES, MAX_NUM_TX_RING_BYTES);
		wlpptr->wlpd_p->descData[num].pTxRing =
			(wltxdesc_t *)(mem + num * MAX_NUM_TX_RING_BYTES);
		wlpptr->wlpd_p->descData[num].pPhysTxRing =
			(dma_addr_t)((UINT32)wlpptr->wlpd_p->descData[0].pPhysTxRing +
						 num * MAX_NUM_TX_RING_BYTES);
		if (wlpptr->wlpd_p->descData[num].pTxRing == NULL)
		{
			WLDBG_ERROR(DBG_LEVEL_12, "can not alloc mem");
			return FAIL;
		}
		memset(wlpptr->wlpd_p->descData[num].pTxRing, 0x00,
			   MAX_NUM_TX_RING_BYTES);
		WLDBG_EXIT_INFO(DBG_LEVEL_12, "TX ring vaddr: 0x%x paddr: 0x%x",
						wlpptr->wlpd_p->descData[num].pTxRing,
						wlpptr->wlpd_p->descData[num].pPhysTxRing);
	}
#endif
	return SUCCESS;
}

#ifdef NEW_DP
int wlTxRingInit(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	int currDescr, i;

	for (i = 0; i < NUM_OF_DESCRIPTOR_DATA; i++)
	{
		skb_queue_head_init(&wlpptr->wlpd_p->txQ[i]);
	}
	wlpptr->wlpd_p->fwDescCnt[0] = 0;
	if (wlpptr->wlpd_p->descData[0].pTxRing != NULL)
	{
		for (currDescr = 0; currDescr < MAX_NUM_TX_DESC; currDescr++)
		{
			CURR_TXD(0).User = currDescr;
		}
		wlpptr->wlpd_p->descData[0].pStaleTxDesc = &FIRST_TXD(0);
		wlpptr->wlpd_p->descData[0].pNextTxDesc = &FIRST_TXD(0);
		wlpptr->wlpd_p->descData[0].txDescBusyCnt = 0;
	}
	skb_queue_head_init(&wlpptr->wlpd_p->txQueRecord);

	return SUCCESS;
}
#else
int wlTxRingInit(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	int currDescr;
#ifdef AMSDU_AGGREQ_FOR_8K
	struct sk_buff *newskb;
#endif
	int num;

	WLDBG_ENTER_INFO(DBG_LEVEL_12, "initializing %i descriptors",
					 MAX_NUM_TX_DESC);
	skb_queue_head_init(&wlpptr->wlpd_p->txQueRecord);
#ifdef AMSDU_AGGREQ_FOR_8K
	skb_queue_head_init(&wlpptr->wlpd_p->aggreQ);
	for (currDescr = 0; currDescr < MAX_NUM_AGGR_BUFF; currDescr++)
	{
		newskb = wl_alloc_skb(MAX_AGGR_SIZE);
		if (newskb)
		{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 20)
			if (skb_linearize(newskb))
#else
			if (skb_linearize(newskb, GFP_ATOMIC))
#endif
			{
				wl_free_skb(newskb);
				printk(KERN_ERR "%s: Need linearize memory\n",
					   netdev->name);
				return FAIL;
			}

			skb_queue_tail(&wlpptr->wlpd_p->aggreQ, newskb);
		}
		else
		{
			printk(KERN_ERR
				   "%s: Allocate TX buffer failed. Insufficient system memory\n",
				   netdev->name);
			return FAIL;
		}
	}
#endif
	for (num = 0; num < NUM_OF_DESCRIPTOR_DATA; num++)
	{
		skb_queue_head_init(&wlpptr->wlpd_p->txQ[num]);
		wlpptr->wlpd_p->fwDescCnt[num] = 0;
		if (wlpptr->wlpd_p->descData[num].pTxRing != NULL)
		{
			for (currDescr = 0; currDescr < MAX_NUM_TX_DESC;
				 currDescr++)
			{
				CURR_TXD(num).Status =
					ENDIAN_SWAP32(EAGLE_TXD_STATUS_IDLE);
				CURR_TXD(num).pNext = &NEXT_TXD(num);
				CURR_TXD(num).pPhysNext =
					ENDIAN_SWAP32((u_int32_t)wlpptr->wlpd_p->descData[num].pPhysTxRing +
								  ((currDescr +
									1) *
								   sizeof(wltxdesc_t)));
				WLDBG_INFO(DBG_LEVEL_12,
						   "txdesc: %i status: 0x%x (%i) vnext: 0x%p pnext: 0x%x",
						   currDescr, EAGLE_TXD_STATUS_IDLE,
						   EAGLE_TXD_STATUS_IDLE,
						   CURR_TXD(num).pNext,
						   ENDIAN_SWAP32(CURR_TXD(num).pPhysNext));
			}
			LAST_TXD(num).pNext = &FIRST_TXD(num);
			LAST_TXD(num).pPhysNext =
				ENDIAN_SWAP32((u_int32_t)wlpptr->wlpd_p->descData[num].pPhysTxRing);
			wlpptr->wlpd_p->descData[num].pStaleTxDesc =
				&FIRST_TXD(num);
			wlpptr->wlpd_p->descData[num].pNextTxDesc =
				&FIRST_TXD(num);

			WLDBG_EXIT_INFO(DBG_LEVEL_12,
							"last txdesc vnext: 0x%p pnext: 0x%x pstale 0x%x vfirst 0x%x",
							LAST_TXD(num).pNext,
							ENDIAN_SWAP32(LAST_TXD(num).pPhysNext),
							wlpptr->wlpd_p->descData[num].pStaleTxDesc,
							wlpptr->wlpd_p->descData[num].pNextTxDesc);
		}
		else
		{
			WLDBG_ERROR(DBG_LEVEL_12, "no valid TX mem");
			return FAIL;
		}
	}
	return SUCCESS;
}
#endif

void wlTxRingCleanup(struct net_device *netdev)
{
#ifdef NEW_DP
	wlTxRingInit(netdev);
#else
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	int cleanedTxDescr = 0;
	int currDescr;
	int num;

	WLDBG_ENTER(DBG_LEVEL_12);

	for (num = 0; num < NUM_OF_DESCRIPTOR_DATA; num++)
	{
		skb_queue_purge(&wlpptr->wlpd_p->txQ[num]);
		wlpptr->wlpd_p->fwDescCnt[num] = 0;
		if (wlpptr->wlpd_p->descData[num].pTxRing != NULL)
		{
			for (currDescr = 0; currDescr < MAX_NUM_TX_DESC;
				 currDescr++)
			{
				if (CURR_TXD(num).pSkBuff != NULL)
				{
					WLDBG_INFO(DBG_LEVEL_12,
							   "unmapped and free'd txdesc %i vaddr: 0x%p paddr: 0x%x",
							   currDescr,
							   CURR_TXD(num).pSkBuff->data,
							   ENDIAN_SWAP32(CURR_TXD(num).PktPtr));
					pci_unmap_single(wlpptr->pPciDev,
									 ENDIAN_SWAP32(CURR_TXD(num).PktPtr),
									 CURR_TXD(num).pSkBuff->len, PCI_DMA_TODEVICE);
#ifdef AMSDU_AGGREQ_FOR_8K
					if (CURR_TXD(num).pSkBuff->truesize >
						MAX_AGGR_SIZE)
					{
						skb_queue_tail(&wlpptr->wlpd_p->aggreQ,
									   CURR_TXD(num).pSkBuff);
					}
					else
#endif
					{
						wl_free_skb(CURR_TXD(num).pSkBuff);
					}
					CURR_TXD(num).Status =
						ENDIAN_SWAP32(EAGLE_TXD_STATUS_IDLE);
					CURR_TXD(num).pSkBuff = NULL;
					CURR_TXD(num).PktPtr = 0;
					CURR_TXD(num).PktLen = 0;
					cleanedTxDescr++;
				}
			}
		}
	}
#ifdef AMSDU_AGGREQ_FOR_8K
	skb_queue_purge(&wlpptr->wlpd_p->aggreQ);
#endif
	WLDBG_EXIT_INFO(DBG_LEVEL_12, "cleaned %i TX descr", cleanedTxDescr);
#endif
}

void wlRxDescriptorDump(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	u_int32_t rxDoneHead;
	u_int32_t rxDoneTail;
	u_int32_t rxDescHead, rxDescTail;
	rxDescHead = readl(wlpptr->ioBase1 + MACREG_REG_RxDescHead);
	rxDescTail = readl(wlpptr->ioBase1 + MACREG_REG_RxDescTail);
	rxDoneHead = readl(wlpptr->ioBase1 + MACREG_REG_RxDoneHead);
	rxDoneTail = readl(wlpptr->ioBase1 + MACREG_REG_RxDoneTail);
	printk("rx: DescHead=%i, DescTail=%i, DoneHead=%i, DoneTail=%i\n",
		   rxDescHead, rxDescTail, rxDoneHead, rxDoneTail);
	printk("rx: rxskbunlinkerror=%i, signatureerror=%i\n",
		   wlpptr->wlpd_p->rxskbunlinkerror,
		   wlpptr->wlpd_p->signatureerror);
	printk("txQueRecord: %i\n",
		   skb_queue_len(&wlpptr->wlpd_p->txQueRecord));
	printk("rxSkbTrace: %i\n", skb_queue_len(&wlpptr->wlpd_p->rxSkbTrace));
	printk("aggreQ: %i\n", skb_queue_len(&wlpptr->wlpd_p->aggreQ));

	{
		typedef PACK_START struct _ErrInfo_stats_t
		{
			UINT32 errInfo[64];
		} PACK_END ERRINFO_STATS_t;
		ERRINFO_STATS_t ei;
		UINT32 addr_val[3];
		wlFwGetAddrValue(netdev, 0, 3, &addr_val[0], 3);
		printk("dp_radio %x\n", addr_val[2]);
		if (wlFwGetAddrValue(netdev, addr_val[0],
							 (sizeof(ERRINFO_STATS_t) >> 2),
							 (UINT32 *)&ei, 0) == SUCCESS)
		{
			int k;
			for (k = 0; k < 64; k++)
			{
				if (ei.errInfo[k])
					printk("Counter%2d: \t%10u\n", k,
						   ENDIAN_SWAP32(ei.errInfo[k]));
			}
		}
	}
}

void wlTxDescriptorDump(struct net_device *netdev)
{
#ifndef NEW_DP
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	int currDescr;
	int num;
	char *p1 = NULL;
	char *p2 = NULL;
	char str1[12] = " <- CURR_TXD";
	char str2[14] = " <- Next_TXD";
	char blank[2] = " ";

	for (num = 0; num < NUM_OF_DESCRIPTOR_DATA; num++)
	{
		if (wlpptr->wlpd_p->descData[num].pTxRing != NULL)
		{
			for (currDescr = 0; currDescr < MAX_NUM_TX_DESC;
				 currDescr++)
			{
				p1 = blank;
				p2 = blank;
				if ((UINT32)&CURR_TXD(num) ==
					(UINT32)wlpptr->wlpd_p->descData[num].pStaleTxDesc)
				{
					p1 = str1;
				}
				if ((UINT32)&CURR_TXD(num) ==
					(UINT32)wlpptr->wlpd_p->descData[num].pNextTxDesc)
				{
					p2 = str2;
				}
				printk("TxDescriptor(%d.%d) Status=0x%x %s %s\n", num, currDescr, CURR_TXD(num).Status, p1, p2);
			}
		}
	}
#endif
}

int wlRxRingAlloc(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);

	WLDBG_ENTER_INFO(DBG_LEVEL_12, "allocating %i (0x%x) bytes",
					 MAX_NUM_RX_RING_BYTES, MAX_NUM_RX_RING_BYTES);

	wlpptr->wlpd_p->descData[0].pRxRing =
		(wlrxdesc_t *)pci_alloc_consistent(wlpptr->pPciDev,
										   MAX_NUM_RX_RING_BYTES,
										   &wlpptr->wlpd_p->descData[0].pPhysRxRing);
	if (wlpptr->wlpd_p->descData[0].pRxRing == NULL)
	{
		WLDBG_ERROR(DBG_LEVEL_12, "can not alloc mem");
		return FAIL;
	}
	memset(wlpptr->wlpd_p->descData[0].pRxRing, 0x00,
		   MAX_NUM_RX_RING_BYTES);
	WLDBG_EXIT_INFO(DBG_LEVEL_12, "RX ring vaddr: 0x%x paddr: 0x%x",
					wlpptr->wlpd_p->descData[0].pRxRing,
					wlpptr->wlpd_p->descData[0].pPhysRxRing);
#ifdef NEW_DP
	wlpptr->wlpd_p->descData[0].pRxRingDone =
		(rx_ring_done_t *)pci_alloc_consistent(wlpptr->pPciDev,
											   MAX_NUM_RX_RING_DONE_BYTES,
											   &wlpptr->wlpd_p->descData[0].pPhysRxRingDone);

	if (wlpptr->wlpd_p->descData[0].pRxRingDone == NULL)
	{
		WLDBG_ERROR(DBG_LEVEL_12, "can not alloc mem");
		return FAIL;
	}
	memset(wlpptr->wlpd_p->descData[0].pRxRingDone, 0x00,
		   MAX_NUM_RX_RING_DONE_BYTES);
	wmb();
#endif
	return SUCCESS;
}

#ifdef NEW_DP
int wlRxRingReInit(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	int currDescr;

	WLDBG_ENTER_INFO(DBG_LEVEL_12, "initializing %i descriptors",
					 MAX_NUM_RX_DESC);

	if (wlpptr->wlpd_p->descData[0].pRxRing != NULL)
	{
		for (currDescr = 0; currDescr < MAX_NUM_RX_DESC; currDescr++)
		{
			struct sk_buff *pSkBuff = NULL;

			pSkBuff =
				wlpptr->wlpd_p->descData[0].Rx_vBufList[currDescr];
			if (pSkBuff != NULL)
			{
				CURR_RXD.Data =
					ENDIAN_SWAP32(pci_map_single(wlpptr->pPciDev,
												 pSkBuff->data,
												 wlpptr->wlpd_p->descData[0].rxBufSize,
												 PCI_DMA_FROMDEVICE));
			}
			else
			{
				printk("rxringinit fail \n");
			}
		}

		writel(1023, wlpptr->ioBase1 + MACREG_REG_RxDescHead);

		return SUCCESS;
	}
	WLDBG_ERROR(DBG_LEVEL_12, "no valid RX mem");
	return FAIL;
}

int wlRxRingInit(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	int currDescr;

	WLDBG_ENTER_INFO(DBG_LEVEL_12, "initializing %i descriptors",
					 MAX_NUM_RX_DESC);
	skb_queue_head_init(&wlpptr->wlpd_p->rxSkbTrace);

	if (wlpptr->wlpd_p->descData[0].pRxRing != NULL)
	{
		wlpptr->wlpd_p->descData[0].rxBufSize = MAX_AGGR_SIZE;
		for (currDescr = 0; currDescr < MAX_NUM_RX_DESC; currDescr++)
		{
			struct sk_buff *pSkBuff = NULL;
			pSkBuff =
				wl_alloc_skb(wlpptr->wlpd_p->descData[0].rxBufSize);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 20)
			if (skb_linearize(pSkBuff))
#else
			if (skb_linearize(pSkBuff, GFP_ATOMIC))
#endif
			{
				wl_free_skb(pSkBuff);
				printk(KERN_ERR "%s: Need linearize memory\n",
					   netdev->name);
				return FAIL;
			}
#ifdef ZERO_COPY_RX
			skb_reserve(pSkBuff, MIN_BYTES_HEADROOM);
#endif
			CURR_RXD.User = currDescr;

			if (pSkBuff != NULL)
			{
				wlpptr->wlpd_p->descData[0].Rx_vBufList[currDescr] = pSkBuff;
				// CURR_RXD.pBuffData = CURR_RXD.pSkBuff->data;
				CURR_RXD.Data =
					ENDIAN_SWAP32(pci_map_single(wlpptr->pPciDev,
												 pSkBuff->data,
												 wlpptr->wlpd_p->descData[0].rxBufSize,
												 PCI_DMA_FROMDEVICE));
				*((UINT32 *)&pSkBuff->cb[16]) = 0xdeadbeef;
				skb_queue_tail(&wlpptr->wlpd_p->rxSkbTrace,
							   pSkBuff);
			}
			else
			{
				WLDBG_ERROR(DBG_LEVEL_12,
							"rxdesc %i: no skbuff available",
							currDescr);
				return FAIL;
			}
		}

		writel(1023, wlpptr->ioBase1 + MACREG_REG_RxDescHead);

		return SUCCESS;
	}
	WLDBG_ERROR(DBG_LEVEL_12, "no valid RX mem");
	return FAIL;
}

#else
int wlRxRingInit(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	int currDescr;

	WLDBG_ENTER_INFO(DBG_LEVEL_12, "initializing %i descriptors",
					 MAX_NUM_RX_DESC);

	if (wlpptr->wlpd_p->descData[0].pRxRing != NULL)
	{
		wlpptr->wlpd_p->descData[0].rxBufSize = MAX_AGGR_SIZE;
		for (currDescr = 0; currDescr < MAX_NUM_RX_DESC; currDescr++)
		{
			CURR_RXD.pSkBuff =
				wl_alloc_skb(wlpptr->wlpd_p->descData[0].rxBufSize);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 20)
			if (skb_linearize(CURR_RXD.pSkBuff))
#else
			if (skb_linearize(CURR_RXD.pSkBuff, GFP_ATOMIC))
#endif
			{
				wl_free_skb(CURR_RXD.pSkBuff);
				printk(KERN_ERR "%s: Need linearize memory\n",
					   netdev->name);
				return FAIL;
			}
#ifdef ZERO_COPY_RX
			skb_reserve(CURR_RXD.pSkBuff, MIN_BYTES_HEADROOM);
#endif
			CURR_RXD.RxControl = EAGLE_RXD_CTRL_DRIVER_OWN;
			CURR_RXD.Status = EAGLE_RXD_STATUS_OK;
			CURR_RXD.QosCtrl = 0x0000;
			CURR_RXD.Channel = 0x00;
			CURR_RXD.RSSI = 0x00;
			CURR_RXD.SQ2 = 0x00;

			if (CURR_RXD.pSkBuff != NULL)
			{
				CURR_RXD.PktLen =
					6 * netdev->mtu + NUM_EXTRA_RX_BYTES;
				CURR_RXD.pBuffData = CURR_RXD.pSkBuff->data;
				CURR_RXD.pPhysBuffData =
					ENDIAN_SWAP32(pci_map_single(wlpptr->pPciDev,
												 CURR_RXD.pSkBuff->data,
												 wlpptr->wlpd_p->descData[0].rxBufSize,
												 PCI_DMA_FROMDEVICE));
				CURR_RXD.pNext = &NEXT_RXD;
				CURR_RXD.pPhysNext =
					ENDIAN_SWAP32((u_int32_t)wlpptr->wlpd_p->descData[0].pPhysRxRing +
								  ((currDescr +
									1) *
								   sizeof(wlrxdesc_t)));
				WLDBG_INFO(DBG_LEVEL_12,
						   "rxdesc: %i status: 0x%x (%i) len: 0x%x (%i)",
						   currDescr, EAGLE_TXD_STATUS_IDLE,
						   EAGLE_TXD_STATUS_IDLE,
						   wlpptr->wlpd_p->descData[0].rxBufSize,
						   wlpptr->wlpd_p->descData[0].rxBufSize);
				WLDBG_INFO(DBG_LEVEL_12,
						   "rxdesc: %i vnext: 0x%p pnext: 0x%x",
						   currDescr, CURR_RXD.pNext,
						   ENDIAN_SWAP32(CURR_RXD.pPhysNext));
			}
			else
			{
				WLDBG_ERROR(DBG_LEVEL_12,
							"rxdesc %i: no skbuff available",
							currDescr);
				return FAIL;
			}
		}
		LAST_RXD.pPhysNext =
			ENDIAN_SWAP32((u_int32_t)wlpptr->wlpd_p->descData[0].pPhysRxRing);
		LAST_RXD.pNext = &FIRST_RXD;
		wlpptr->wlpd_p->descData[0].pNextRxDesc = &FIRST_RXD;

		WLDBG_EXIT_INFO(DBG_LEVEL_12,
						"last rxdesc vnext: 0x%p pnext: 0x%x vfirst 0x%x",
						LAST_RXD.pNext,
						ENDIAN_SWAP32(LAST_RXD.pPhysNext),
						wlpptr->wlpd_p->descData[0].pNextRxDesc);
		return SUCCESS;
	}
	WLDBG_ERROR(DBG_LEVEL_12, "no valid RX mem");
	return FAIL;
}
#endif

void wlRxRingCleanup(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	int currDescr;

	WLDBG_ENTER(DBG_LEVEL_12);

	if (wlpptr->wlpd_p->descData[0].pRxRing != NULL)
	{
		for (currDescr = 0; currDescr < MAX_NUM_RX_DESC; currDescr++)
		{
#ifdef NEW_DP
			if (wlpptr->wlpd_p->descData[0].Rx_vBufList[currDescr] != NULL)
			{
				pci_unmap_single(wlpptr->pPciDev,
								 ENDIAN_SWAP32(CURR_RXD.Data),
								 wlpptr->wlpd_p->descData[0].rxBufSize, PCI_DMA_FROMDEVICE);
				wl_free_skb(wlpptr->wlpd_p->descData[0].Rx_vBufList[currDescr]);
			}
#else
			if (CURR_RXD.pSkBuff != NULL)
			{
				if (skb_shinfo(CURR_RXD.pSkBuff)->nr_frags)
				{
					skb_shinfo(CURR_RXD.pSkBuff)->nr_frags =
						0;
				}
				if (skb_shinfo(CURR_RXD.pSkBuff)->frag_list)
				{
					skb_shinfo(CURR_RXD.pSkBuff)->frag_list = NULL;
				}
				pci_unmap_single(wlpptr->pPciDev,
								 ENDIAN_SWAP32(CURR_RXD.pPhysBuffData),
								 wlpptr->wlpd_p->descData[0].rxBufSize, PCI_DMA_FROMDEVICE);
				wl_free_skb(CURR_RXD.pSkBuff);
				WLDBG_INFO(DBG_LEVEL_12,
						   "unmapped+free'd rxdesc %i vaddr: 0x%p paddr: 0x%x len: %i",
						   currDescr, CURR_RXD.pBuffData,
						   ENDIAN_SWAP32(CURR_RXD.pPhysBuffData),
						   wlpptr->wlpd_p->descData[0].rxBufSize);
				CURR_RXD.pBuffData = NULL;
				CURR_RXD.pSkBuff = NULL;
			}
#endif
		}
	}
	WLDBG_EXIT(DBG_LEVEL_12);
}

void wlTxRingFree(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	int num;
	WLDBG_ENTER(DBG_LEVEL_12);
#ifndef NEW_DP
	if (wlpptr->wlpd_p->descData[0].pTxRing != NULL)
		pci_free_consistent(wlpptr->pPciDev,
							MAX_NUM_TX_RING_BYTES *
								NUM_OF_DESCRIPTOR_DATA,
							wlpptr->wlpd_p->descData[0].pTxRing,
							wlpptr->wlpd_p->descData[0].pPhysTxRing);
#else
	if (wlpptr->wlpd_p->descData[0].pTxRing != NULL)
	{

		pci_free_consistent(wlpptr->pPciDev,
							MAX_NUM_TX_RING_BYTES,
							wlpptr->wlpd_p->descData[0].pTxRing,
							wlpptr->wlpd_p->descData[0].pPhysTxRing);
	}
	if (wlpptr->wlpd_p->descData[0].pTxRingDone != NULL)
	{
		pci_free_consistent(wlpptr->pPciDev,
							MAX_NUM_TX_RING_DONE_BYTES,
							wlpptr->wlpd_p->descData[0].pTxRingDone,
							wlpptr->wlpd_p->descData[0].pPhysTxRingDone);
		wlpptr->wlpd_p->descData[0].pTxRingDone = NULL;
	}
#ifdef NEWDP_ACNT_CHUNKS
	for (i = 0; i < ACNT_NCHUNK; i++)
	{
		if (wlpptr->wlpd_p->mmap_ACNTChunk[i].data != NULL)
		{
			pci_free_consistent(wlpptr->pPciDev,
								DEFAULT_SIZE_CHUNK,
								wlpptr->wlpd_p->mmap_ACNTChunk[i].data,
								wlpptr->wlpd_p->descData[0].pPhysAcntRing[i]);
		}
	}
#else
	if (wlpptr->wlpd_p->descData[0].pAcntRing != NULL)
	{

		pci_free_consistent(wlpptr->pPciDev,
							DEFAULT_ACNT_RING_SIZE,
							wlpptr->wlpd_p->descData[0].pAcntRing,
							wlpptr->wlpd_p->descData[0].pPhysAcntRing);
	}
	if (wlpptr->wlpd_p->descData[0].pAcntBuf != NULL)
	{
		kfree(wlpptr->wlpd_p->descData[0].pAcntBuf);
	}
#endif

	if (wlpptr->wlpd_p->AllocSharedMeminfo.data != NULL)
	{

		pci_free_consistent(wlpptr->pPciDev,
							FW_IO_MB_SIZE,
							wlpptr->wlpd_p->AllocSharedMeminfo.data,
							wlpptr->wlpd_p->AllocSharedMeminfo.dataPhysicalLoc);
		wlpptr->wlpd_p->AllocSharedMeminfo.data = 0;
	}
	if (wlpptr->wlpd_p->MrvlPriSharedMem.data != NULL)
	{

		pci_free_consistent(wlpptr->pPciDev,
							sizeof(drv_fw_shared_t),
							wlpptr->wlpd_p->MrvlPriSharedMem.data,
							wlpptr->wlpd_p->MrvlPriSharedMem.dataPhysicalLoc);
		wlpptr->wlpd_p->MrvlPriSharedMem.data = 0;
	}
	if (wlpptr->wlpd_p->descData[0].pOffChReqRing != NULL)
	{
		pci_free_consistent(wlpptr->pPciDev,
							MAX_OFF_CHAN_REQ * sizeof(offchan_desc_t),
							wlpptr->wlpd_p->descData[0].pOffChReqRing,
							wlpptr->wlpd_p->descData[0].pPhysOffChReqRing);
		wlpptr->wlpd_p->descData[0].pOffChReqRing = 0;

		pci_free_consistent(wlpptr->pPciDev,
							MAX_OFF_CHAN_DONE *
								sizeof(offchan_done_stat_t),
							wlpptr->wlpd_p->descData[0].pOffChDoneRing,
							wlpptr->wlpd_p->descData[0].pPhysOffChDoneRing);
		wlpptr->wlpd_p->descData[0].pOffChDoneRing = 0;
	}
#endif
	for (num = 0; num < NUM_OF_DESCRIPTOR_DATA; num++)
	{
		if (wlpptr->wlpd_p->descData[num].pTxRing != NULL)
		{
			wlpptr->wlpd_p->descData[num].pTxRing = NULL;
		}
		wlpptr->wlpd_p->descData[num].pStaleTxDesc = NULL;
		wlpptr->wlpd_p->descData[num].pNextTxDesc = NULL;
	}
	WLDBG_EXIT(DBG_LEVEL_12);
}

void wlRxRingFree(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);

	WLDBG_ENTER(DBG_LEVEL_12);

	if (wlpptr->wlpd_p->descData[0].pRxRing != NULL)
	{
		wlRxRingCleanup(netdev);
		pci_free_consistent(wlpptr->pPciDev,
							MAX_NUM_RX_RING_BYTES,
							wlpptr->wlpd_p->descData[0].pRxRing,
							wlpptr->wlpd_p->descData[0].pPhysRxRing);
		wlpptr->wlpd_p->descData[0].pRxRing = NULL;
	}
	if (wlpptr->wlpd_p->descData[0].pRxRingDone != NULL)
	{
		pci_free_consistent(wlpptr->pPciDev,
							MAX_NUM_RX_RING_DONE_BYTES,
							wlpptr->wlpd_p->descData[0].pRxRingDone,
							wlpptr->wlpd_p->descData[0].pPhysRxRingDone);
		wlpptr->wlpd_p->descData[0].pRxRingDone = NULL;
	}
	wlpptr->wlpd_p->descData[0].pNextRxDesc = NULL;
	WLDBG_EXIT(DBG_LEVEL_12);
}
