/** @file ap8xLnxAcnt.c
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

/** include files **/
#include "wldebug.h"
#include "ap8xLnxRegs.h"
#include "ap8xLnxIntf.h"
#include "ap8xLnxAcnt.h"
#include "wltypes.h"
#include "StaDb.h"
#include "hostcmd.h"
/* default settings */

/** external functions **/
/** external data **/

/** internal functions **/

/** public data **/

/** private data **/

/** public functions **/
#if defined(SOC_W906X) || defined(NEWDP_ACNT_CHUNKS)
extern int wlFwNewDP_setAcntBufSize(struct net_device *netdev, u_int32_t * base,
				    u_int32_t size, u_int32_t ActionType);
#else
extern int wlFwNewDP_setAcntBufSize(struct net_device *netdev, u_int32_t base,
				    u_int32_t size);
#endif
#ifdef SOC_W906X
extern int wlFwGetRateTable(struct net_device *netdev, UINT8 * addr,
			    UINT8 * pRateInfo, UINT32 size, UINT8 type,
			    UINT16 staid);
#else
extern int wlFwGetRateTable(struct net_device *netdev, UINT8 * addr,
			    UINT8 * pRateInfo, UINT32 size, UINT8 type);
#endif

UINT32 RA_TX_ATTEMPT[2][6] = { {0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0} };	//[0:SU, 1:MU][6]
UINT8 TX_HISTO_PER_THRES[TX_RATE_HISTO_PER_CNT - 1] = { 6, 20, 40, 90 };
UINT8 BA_HISTO_STAID_MAP[10] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };	//staid map to txBAStats[]

#ifdef SOC_W906X
UINT32 acnt_tx_record_idx = 0;
UINT32 acnt_RA_stats_idx = 0;
UINT32 current_internal_stat = 0;
acnt_tx3_t acnt_internal_stat[NUM_INTERNAL_STAT] = { 0 };

acnt_tx3_t acnt_internal_stat_dump[NUM_INTERNAL_STAT];

void
dump_acnt_internal_stat(u32 entry)
{
	int i;
	int pos = current_internal_stat;

	memcpy(&(acnt_internal_stat_dump[0]), &(acnt_internal_stat[0]),
	       sizeof(acnt_tx3_t) * NUM_INTERNAL_STAT);
	for (i = 0; i < entry; i++) {
		pos--;
		if (pos < 0) {
			pos = NUM_INTERNAL_STAT - 1;
		}
		print_hex_dump(KERN_INFO, "", DUMP_PREFIX_OFFSET,
			       32, 4, &(acnt_internal_stat_dump[pos]),
			       sizeof(acnt_tx3_t), false);
	}

	return;
}
#endif /* SOC_W906X */

/*** new data path ***/
/*
* This function is used to allocate NewDP accounting buffer of multiple chunks. Each chunk is 1<<log2N
* INPUTS:
* size: Combined buffer size of chunks, must be >= 64k (0x1000)
*/
#if defined(SOC_W906X) || defined(NEWDP_ACNT_CHUNKS)
int
wlAcntSetBufSize(struct net_device *netdev, SetAcntBufInfo_t * SetInfo)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	UINT8 *mem;		//, *oldMem;
	UINT8 i;
	UINT32 oldSize = ACNT_NCHUNK * DEFAULT_SIZE_CHUNK, size, head;
	//dma_addr_t       pPhysAcntTmp[ACNT_NCHUNK];
	char *memTmp[ACNT_NCHUNK];
	BOOLEAN bAllocFailed = FALSE;
#ifdef SOC_W906X
	unsigned int reg_acnt_head = wlpptr->wlpd_p->reg.acnt_head;
	unsigned int reg_acnt_tail = wlpptr->wlpd_p->reg.acnt_tail;
#else
	unsigned int reg_acnt_head = MACREG_REG_AcntHead;
	unsigned int reg_acnt_tail = MACREG_REG_AcntTail;
#endif /* #ifdef SOC_W906X */

	size = SetInfo->size;

	if (SetInfo->ActionType == ACNT_PAUSE) {
		if (size % 0x10000) {
			printk("NOT acceptable size \n");
			return 0;
		} else {
			if (size != 0x10000) {
				if ((size / 0x10000) % 2) {
					printk("NOT acceptable size \n");
					return 0;
				}
			}
		}
		oldSize = wlpptr->wlpd_p->descData[0].AcntRingSize;
		if (oldSize == size) {
			printk(" size unchange \n");
			return 0;
		}
		wlFwNewDP_setAcntBufSize(netdev, NULL, 0, SetInfo->ActionType);
		return 1;
	} else if (SetInfo->ActionType == ACNT_SET_BUF) {
		for (i = 0; i < ACNT_NCHUNK; i++) {
#ifdef SOC_W906X
			wl_dma_free_coherent(wlpptr->wlpd_p->dev,
					     oldSize / ACNT_NCHUNK,
					     wlpptr->wlpd_p->mmap_ACNTChunk[i].
					     data,
					     wlpptr->wlpd_p->descData[0].
					     pPhysAcntRing[i]);
#else
			pci_free_consistent(wlpptr->pPciDev,
					    oldSize / ACNT_NCHUNK,
					    wlpptr->wlpd_p->mmap_ACNTChunk[i].
					    data,
					    wlpptr->wlpd_p->descData[0].
					    pPhysAcntRing[i]);
#endif
		}

		for (i = 0; i < ACNT_NCHUNK; i++) {
#ifdef SOC_W906X
			mem = wl_dma_alloc_coherent(wlpptr->wlpd_p->dev,
						    size / ACNT_NCHUNK,
						    &wlpptr->wlpd_p->
						    descData[0].
						    pPhysAcntRing[i],
						    wlpptr->wlpd_p->
						    dma_alloc_flags);
#else
			mem = (UINT8 *) pci_alloc_consistent(wlpptr->pPciDev,
							     size / ACNT_NCHUNK,
							     &wlpptr->wlpd_p->
							     descData[0].
							     pPhysAcntRing[i]);
#endif
			if (mem == NULL) {
				UINT8 j;

				printk("error: dma_alloc_consistent failed\n");

				for (j = 0; j < i; j++) {
#ifdef SOC_W906X
					wl_dma_free_coherent(wlpptr->wlpd_p->
							     dev,
							     size / ACNT_NCHUNK,
							     (void *)memTmp[j],
							     wlpptr->wlpd_p->
							     descData[0].
							     pPhysAcntRing[i]);
#else
					pci_free_consistent(wlpptr->pPciDev,
							    size / ACNT_NCHUNK,
							    memTmp[j],
							    &wlpptr->wlpd_p->
							    descData[0].
							    pPhysAcntRing[i]);
#endif
				}
				bAllocFailed = TRUE;
				break;
			}
			memTmp[i] = mem;
			wlpptr->wlpd_p->mmap_ACNTChunk[i].data = mem;
		}
		head = wl_util_readl(netdev, wlpptr->ioBase1 + reg_acnt_head);

		if (bAllocFailed) {
			//back to oldsize
			wl_util_writel(netdev, head & (oldSize/ACNT_NCHUNK -1), wlpptr->ioBase1 + reg_acnt_tail);
			wl_util_writel(netdev, head & (oldSize/ACNT_NCHUNK -1), wlpptr->ioBase1 + reg_acnt_head);
			for (i = 0; i < ACNT_NCHUNK; i++) {
#ifdef SOC_W906X
				mem = (UINT8 *) wl_dma_alloc_coherent(wlpptr->
								      wlpd_p->
								      dev,
								      oldSize /
								      ACNT_NCHUNK,
								      &wlpptr->
								      wlpd_p->
								      descData
								      [0].
								      pPhysAcntRing
								      [i],
								      wlpptr->
								      wlpd_p->
								      dma_alloc_flags);
#else
				mem = (UINT8 *) pci_alloc_consistent(wlpptr->
								     pPciDev,
								     oldSize /
								     ACNT_NCHUNK,
								     &wlpptr->
								     wlpd_p->
								     descData
								     [0].
								     pPhysAcntRing
								     [i]);
#endif
				wlpptr->wlpd_p->mmap_ACNTChunk[i].data = mem;
			}
			wlpptr->wlpd_p->AcntChunkInfo.SizeOfChunk =
				oldSize / ACNT_NCHUNK;
			wlpptr->wlpd_p->descData[0].AcntRingSize = oldSize;
			wlFwNewDP_setAcntBufSize(netdev,
						 (u_int32_t *) & wlpptr->
						 wlpd_p->descData[0].
						 pPhysAcntRing[0], oldSize,
						 SetInfo->ActionType);
			return 0;
		} else {
			wl_util_writel(netdev, head & (size/ACNT_NCHUNK -1), wlpptr->ioBase1 + reg_acnt_tail);
			wl_util_writel(netdev, head & (size/ACNT_NCHUNK -1), wlpptr->ioBase1 + reg_acnt_head);
			wlpptr->wlpd_p->AcntChunkInfo.SizeOfChunk =
				size / ACNT_NCHUNK;
			wlpptr->wlpd_p->descData[0].AcntRingSize = size;
			wlFwNewDP_setAcntBufSize(netdev,
						 (u_int32_t *) & wlpptr->
						 wlpd_p->descData[0].
						 pPhysAcntRing[0], size,
						 SetInfo->ActionType);
			return size;
		}

	} else {
		printk("unknown Action type \n");
		return 0;
	}

}
#else
int
wlAcntSetBufSize(struct net_device *netdev, u_int32_t size)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	UINT32 oldSize;
	//dma_addr_t       pPhysAcntTmp[ACNT_NCHUNK];
	//UINT32    memTmp[ACNT_NCHUNK];
	//BOOLEAN bAllocFailed = FALSE;

	u_int8_t *oldPtr = wlpptr->wlpd_p->descData[0].pAcntRing;
	dma_addr_t oldPhyAddr = wlpptr->wlpd_p->descData[0].pPhysAcntRing;
	oldSize = wlpptr->wlpd_p->descData[0].AcntRingSize;

	wlpptr->wlpd_p->descData[0].pAcntRing =
		(UINT8 *) pci_alloc_consistent(wlpptr->pPciDev, size,
					       &wlpptr->wlpd_p->descData[0].
					       pPhysAcntRing);
	wlpptr->wlpd_p->ACNTmemInfo.data =
		wlpptr->wlpd_p->descData[0].pAcntRing;
	wlpptr->wlpd_p->ACNTmemInfo.dataPhysicalLoc =
		wlpptr->wlpd_p->descData[0].pPhysAcntRing;

	if (wlpptr->wlpd_p->descData[0].pAcntRing == NULL) {
		WLDBG_ERROR(DBG_LEVEL_12,
			    "** newTestDP: Can not alloc acnt ring\n");
		return 0;
	}
	printk("acnt size = %d\n", size);
	wlpptr->wlpd_p->descData[0].AcntRingSize = size;

	wlFwNewDP_setAcntBufSize(netdev,
				 wlpptr->wlpd_p->descData[0].pPhysAcntRing,
				 size);

	// frree the old buffer
	pci_free_consistent(wlpptr->pPciDev, oldSize, oldPtr, oldPhyAddr);
	return size;
}
#endif /* #if defined(SOC_W906X) || defined(NEWDP_ACNT_CHUNKS) */

/*Function to find right location to add counter. SU uses rate tbl index as index to SU_rate to update
* MU uses rateinfo as reference. For fixed rate, it uses custom_rate to update
*/
void
wltxRateDecode(dbRateInfo_t * pRateInfo, UINT32 ratetblindex,
	       WLAN_TX_RATE_HIST * pRH, UINT8 type, UINT32 txcnt)
{
	UINT8 i, index, found = 0;
	UINT8 Nss_11ac = 0, Rate_11ac = 0;
	UINT16 ratemask;
	WLAN_TX_RATE_HIST_DATA *histo_p;

	if ((pRH == NULL) || (pRateInfo == NULL))
		return;

	if (type < 2)
		pRH->CurRateInfo[type] = *(UINT32 *) pRateInfo;

	/*Rate table index is valid */
	if (ratetblindex != 0xff) {
		if (type == MU_MIMO) {
			Rate_11ac = pRateInfo->RateIDMCS & 0xf;
			Nss_11ac = pRateInfo->RateIDMCS >> 4;
			if ((Nss_11ac < (QS_NUM_SUPPORTED_11AC_NSS - 1)) &&
			    (Rate_11ac < QS_NUM_SUPPORTED_11AC_MCS)) {
				pRH->MU_rate[Nss_11ac][pRateInfo->
						       Bandwidth][pRateInfo->
								  ShortGI]
					[Rate_11ac].rateinfo =
					*(UINT32 *) pRateInfo;
				pRH->MU_rate[Nss_11ac][pRateInfo->
						       Bandwidth][pRateInfo->
								  ShortGI]
					[Rate_11ac].cnt++;
				pRH->TotalTxCnt[type] += txcnt;
			}

		} else {
			histo_p = &pRH->SU_rate[0];

			if (ratetblindex >= RATE_ADAPT_MAX_SUPPORTED_RATES) {
#if 0
				printk("Severe error: %s():invalid ratetblindex:%u\n", __func__, ratetblindex);
#endif
				return;
			}

			/*If legacy, skip legacy preamble bit 15 */
			if ((histo_p[ratetblindex].rateinfo & 0x3) == 0)
				ratemask = 0xfff;
#ifdef SOC_W906X
			/* HE skip gi bit 6 & 7 */
			else if ((histo_p[ratetblindex].rateinfo & 0x3) == 3)
				ratemask = 0xff3f;
#endif
			else
				ratemask = 0xffff;

			if ((histo_p[ratetblindex].rateinfo & ratemask) ==
			    (*(UINT32 *) pRateInfo & ratemask)) {
				histo_p[ratetblindex].cnt++;
				pRH->TotalTxCnt[type] += txcnt;
			}

		}
	} else {
		if (type == MU_MIMO) {
			Rate_11ac = pRateInfo->RateIDMCS & 0xf;
			Nss_11ac = pRateInfo->RateIDMCS >> 4;
			if ((Nss_11ac < (QS_NUM_SUPPORTED_11AC_NSS - 1)) &&
			    (Rate_11ac < QS_NUM_SUPPORTED_11AC_MCS)) {
				pRH->MU_rate[Nss_11ac][pRateInfo->
						       Bandwidth][pRateInfo->
								  ShortGI]
					[Rate_11ac].rateinfo =
					*(UINT32 *) pRateInfo;
				pRH->MU_rate[Nss_11ac][pRateInfo->
						       Bandwidth][pRateInfo->
								  ShortGI]
					[Rate_11ac].cnt++;
				pRH->TotalTxCnt[type] += txcnt;
			}
		} else {
			histo_p = &pRH->SU_rate[0];
			/*If legacy, skip legacy preamble bit 15 */
			if ((*(UINT32 *) pRateInfo & 0x3) == 0)
				ratemask = 0xfff;
#ifdef SOC_W906X
			/* HE skip gi bit 6 & 7 */
			else if (ratetblindex < RATE_ADAPT_MAX_SUPPORTED_RATES) {
				if ((histo_p[ratetblindex].rateinfo & 0x3) == 3)
					ratemask = 0xff3f;
				else
					ratemask = 0xffff;
			}
#endif
			else
				ratemask = 0xffff;

			histo_p = &pRH->custom_rate[0];

			/*Go through non rate table buffer to see if any has been used. If all used up, recycle by using index 0 */
			for (i = 0; i < TX_RATE_HISTO_CUSTOM_CNT; i++) {
				if ((histo_p[i].rateinfo == 0) ||
				    ((histo_p[i].rateinfo & ratemask) ==
				     (*(UINT32 *) pRateInfo & ratemask))) {
					found = 1;
					break;
				}
			}

			if (found)
				index = i;
			else
				index = 0;	//reuse index 0 buffer

			histo_p[index].rateinfo = *(UINT32 *) pRateInfo;
			histo_p[index].cnt++;
			pRH->TotalTxCnt[type] += txcnt;
		}

	}

}

void
wltxRatePERDecode(dbRateInfo_t * pRateInfo, UINT32 ratetblindex, UINT8 PER,
		  WLAN_TX_RATE_HIST * pRH, UINT8 type)
{
	UINT8 i, index, PER_index, found = 0;
	UINT8 Nss_11ac = 0, Rate_11ac = 0;
	UINT16 ratemask;
	WLAN_TX_RATE_HIST_DATA *histo_p;

	if ((pRH == NULL) || (pRateInfo == NULL) || (type > 1))
		return;

#ifndef SOC_W906X
	if ((type == SU_MIMO) &&
	    (ratetblindex >= RATE_ADAPT_MAX_SUPPORTED_RATES) &&
	    (ratetblindex != 0xFF))
		return;
#endif

	if (PER >= TX_HISTO_PER_THRES[3])
		PER_index = 4;
	else if (PER >= TX_HISTO_PER_THRES[2])
		PER_index = 3;
	else if (PER >= TX_HISTO_PER_THRES[1])
		PER_index = 2;
	else if (PER >= TX_HISTO_PER_THRES[0])
		PER_index = 1;
	else
		PER_index = 0;

	/*Rate table index is valid */
	if (ratetblindex != 0xff) {

		if (type == MU_MIMO) {
			Rate_11ac = pRateInfo->RateIDMCS & 0xf;
			Nss_11ac = pRateInfo->RateIDMCS >> 4;
			if ((Nss_11ac < (QS_NUM_SUPPORTED_11AC_NSS - 1)) &&
			    (Rate_11ac < QS_NUM_SUPPORTED_11AC_MCS)) {
				pRH->MU_rate[Nss_11ac][pRateInfo->
						       Bandwidth][pRateInfo->
								  ShortGI]
					[Rate_11ac].rateinfo =
					*(UINT32 *) pRateInfo;
				pRH->MU_rate[Nss_11ac][pRateInfo->
						       Bandwidth][pRateInfo->
								  ShortGI]
					[Rate_11ac].per[PER_index]++;
			}

		} else {

			histo_p = &pRH->SU_rate[0];

			/*If legacy, skip legacy preamble bit 15 */
			if ((histo_p[ratetblindex].rateinfo & 0x3) == 0)
				ratemask = 0xfff;
#ifdef SOC_W906X
			/* HE skip gi bit 6 & 7 */
			else if ((histo_p[ratetblindex].rateinfo & 0x3) == 3)
				ratemask = 0xff3f;
#endif
			else
				ratemask = 0xffff;

			if ((histo_p[ratetblindex].rateinfo & ratemask) ==
			    (*(UINT32 *) pRateInfo & ratemask))
				histo_p[ratetblindex].per[PER_index]++;
		}

	} else {
		if (type == MU_MIMO) {
			Rate_11ac = pRateInfo->RateIDMCS & 0xf;
			Nss_11ac = pRateInfo->RateIDMCS >> 4;
			if ((Nss_11ac < (QS_NUM_SUPPORTED_11AC_NSS - 1)) &&
			    (Rate_11ac < QS_NUM_SUPPORTED_11AC_MCS)) {
				pRH->MU_rate[Nss_11ac][pRateInfo->
						       Bandwidth][pRateInfo->
								  ShortGI]
					[Rate_11ac].rateinfo =
					*(UINT32 *) pRateInfo;
				pRH->MU_rate[Nss_11ac][pRateInfo->
						       Bandwidth][pRateInfo->
								  ShortGI]
					[Rate_11ac].per[PER_index]++;
			}

		} else {
			histo_p = &pRH->SU_rate[0];
			/*If legacy, skip legacy preamble bit 15 */
			if ((*(UINT32 *) pRateInfo & 0x3) == 0)
				ratemask = 0xfff;
#ifdef SOC_W906X
			/* HE skip gi bit 6 & 7 */
			else if (ratetblindex < RATE_ADAPT_MAX_SUPPORTED_RATES) {
				if ((histo_p[ratetblindex].rateinfo & 0x3) == 3)
					ratemask = 0xff3f;
				else
					ratemask = 0xffff;
			}
#endif
			else
				ratemask = 0xffff;

			histo_p = &pRH->custom_rate[0];

			/*Go through non rate table buffer to see if any has been used. If all used up, recycle by using index 0 */
			for (i = 0; i < TX_RATE_HISTO_CUSTOM_CNT; i++) {
				if ((histo_p[i].rateinfo == 0) ||
				    ((histo_p[i].rateinfo & ratemask) ==
				     (*(UINT32 *) pRateInfo & ratemask))) {
					found = 1;
					break;
				}
			}

			if (found)
				index = i;
			else
				index = 0;	//reuse index 0 buffer

			histo_p[index].rateinfo = *(UINT32 *) pRateInfo;
			histo_p[index].per[PER_index]++;
		}

	}

}

#ifdef NEWDP_ACNT_BA
void
wltxBADecode(WLAN_TX_BA_HIST * pBAStats, acnt_BA_stats_t * pBA)
{
	if ((!pBAStats->StatsEnable) || (pBAStats->pBAStats == NULL) ||
	    (pBA == NULL))
		return;

	if ((pBAStats->Index < ACNT_BA_SIZE) && (pBAStats->Stnid == pBA->StnId)
	    && (pBAStats->Type == pBA->Type)) {
		pBAStats->pBAStats[pBAStats->Index].BAHole = pBA->BAhole;
		pBAStats->pBAStats[pBAStats->Index].BAExpected =
			pBA->BAexpected;
		pBAStats->pBAStats[pBAStats->Index].NoBA = pBA->NoBA;

		pBAStats->Index++;
		if (pBAStats->Index >= ACNT_BA_SIZE)
			printk("Staid:%d BA histo collection done\n",
			       pBA->StnId);
	}

}
#endif

#ifdef BF_MIMO_CTRL_FIELD_LOGGING
void
wl_BF_Mimo_Ctrl_Field_Log_Decode(acnt_BF_Mimo_Ctrl_Field_Log_t *
				 pBF_Mimo_Ctrl_Field_Log_Data)
{
	struct file *filp_BF_MCF_Data = NULL;
	char string_buff[256];

	// Pass back string to buffer for printing out to file
	sprintf(string_buff,
		"\nMAC: %02x.%02x.%02x.%02x.%02x.%02x\nSU_0_MU_1: %d\nMIMO_Ctrl_Field: 0x%x\nComp_BF_Report_First_8Bytes: 0x%llx\n",
		pBF_Mimo_Ctrl_Field_Log_Data->Received_MAC[0],
		pBF_Mimo_Ctrl_Field_Log_Data->Received_MAC[1],
		pBF_Mimo_Ctrl_Field_Log_Data->Received_MAC[2],
		pBF_Mimo_Ctrl_Field_Log_Data->Received_MAC[3],
		pBF_Mimo_Ctrl_Field_Log_Data->Received_MAC[4],
		pBF_Mimo_Ctrl_Field_Log_Data->Received_MAC[5],
		pBF_Mimo_Ctrl_Field_Log_Data->Type,
		pBF_Mimo_Ctrl_Field_Log_Data->MIMO_Ctrl_Field,
		pBF_Mimo_Ctrl_Field_Log_Data->Comp_BF_Rep_8Bytes);

	filp_BF_MCF_Data =
		filp_open("/tmp/BF_MIMO_Ctrl_Field_Output.txt",
			  O_RDWR | O_CREAT | O_TRUNC, 0);
	if (!IS_ERR(filp_BF_MCF_Data)) {
		__kernel_write(filp_BF_MCF_Data, string_buff,
			       strlen(string_buff), &filp_BF_MCF_Data->f_pos);
		filp_close(filp_BF_MCF_Data, current->files);
		printk("AoA data written to /tmp/BF_MIMO_Ctrl_Field_Output.txt\n");
	} else {
		printk("Error opening /tmp/BF_MIMO_Ctrl_Field_Output.txt! %x \n", (unsigned int)filp_BF_MCF_Data);
	}

	return;
}
#endif

#ifdef SOC_W906X
void
wl_free_scheHistogram(struct net_device *netdev)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	UINT16 i;

	for (i = 0; i < sta_num; i++) {
		if (priv->wlpd_p->scheHistogram[i] != NULL) {
			wl_kfree(priv->wlpd_p->scheHistogram[i]);
			priv->wlpd_p->scheHistogram[i] = NULL;
		}
	}
	wl_disable_acnt_record_logging(netdev, acnt_code_tx_enqueue);
	wl_disable_acnt_record_logging(netdev, acnt_code_RA_stats);
}

void
wl_enable_acnt_record_logging(struct net_device *netdev, UINT16 acnt_code)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);

	switch (acnt_code) {
	case acnt_code_tx_enqueue:
		{
			acnt_tx_t *acnt_tx_record = NULL;
			size_t size = (sizeof(acnt_tx_t) * ACNT_TX_RECORD_MAX);

			if (priv->wlpd_p->acnt_tx_record) {
				/* already allocate memory */
				break;
			}
			if ((acnt_tx_record =
			     (acnt_tx_t *) wl_kmalloc_autogfp(size)) != NULL) {
				memset(acnt_tx_record, 0, size);
				priv->wlpd_p->acnt_tx_record =
					(void *)acnt_tx_record;
				acnt_tx_record_idx = 0;
			} else
				printk("malloc failed on creating acnt_tx_record!\n");
			break;
		}
	case acnt_code_RA_stats:
		{
			acnt_RA_stats_t *acnt_RA_stats = NULL;
			size_t size =
				(sizeof(acnt_RA_stats_t) * ACNT_TX_RECORD_MAX);

			if (priv->wlpd_p->acnt_RA_stats) {
				/* already allocate memory */
				break;
			}
			if ((acnt_RA_stats =
			     (acnt_RA_stats_t *) wl_kmalloc_autogfp(size)) !=
			    NULL) {
				memset(acnt_RA_stats, 0, size);
				priv->wlpd_p->acnt_RA_stats =
					(void *)acnt_RA_stats;
				acnt_RA_stats_idx = 0;
			} else
				printk("malloc failed on creating acnt_RA_stats!\n");
			break;
		}
	default:
		{
			printk("wl_enable_acnt_record_logging-unknown acnt code!\n");
			break;
		}
	}
}

void
wl_disable_acnt_record_logging(struct net_device *netdev, UINT16 acnt_code)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);

	switch (acnt_code) {
	case acnt_code_tx_enqueue:
		if (priv->wlpd_p->acnt_tx_record != NULL) {
			wl_kfree(priv->wlpd_p->acnt_tx_record);
			priv->wlpd_p->acnt_tx_record = NULL;
		}
		break;
	case acnt_code_RA_stats:
		if (priv->wlpd_p->acnt_RA_stats != NULL) {
			wl_kfree(priv->wlpd_p->acnt_RA_stats);
			priv->wlpd_p->acnt_RA_stats = NULL;
		}
		break;
	default:
		printk("wl_disable_acnt_record_logging-unknown acnt code!\n");
		break;
	}
}

void
wl_copy_acnt_raw(void *acnt_records, void *recd, UINT16 acnt_code)
{
	switch (acnt_code) {
	case acnt_code_tx_enqueue:
		{
			acnt_tx_t *acnt_tx_records = (acnt_tx_t *) acnt_records;
			acnt_tx_t *acntRecd = (acnt_tx_t *) recd;

			if (!acnt_tx_records) {
				//printk("Scheduler Accounting Records is disabled!\n"
				//       "Please use iwpriv <vapif> setcmd \"gettxscheinfo enable\" to enable it!\n");
				return;
			}

			memcpy(&acnt_tx_records[acnt_tx_record_idx++], acntRecd,
			       sizeof(acnt_tx_t));

			if (acnt_tx_record_idx >= ACNT_TX_RECORD_MAX)
				acnt_tx_record_idx = 0;
			break;
		}
	case acnt_code_RA_stats:
		{
			acnt_RA_stats_t *acnt_RA_stats =
				(acnt_RA_stats_t *) acnt_records;
			acnt_RA_stats_t *acntRecd = (acnt_RA_stats_t *) recd;

			if (!acnt_RA_stats) {
				//printk("RA stats logging is disabled!\n"
				//       "Please use iwpriv <vapif> setcmd \"qstats rastats log_enable\" to enable it!\n");
				return;
			}

			memcpy(&acnt_RA_stats[acnt_RA_stats_idx++], acntRecd,
			       sizeof(acnt_RA_stats_t));

			if (acnt_RA_stats_idx >= ACNT_TX_RECORD_MAX)
				acnt_RA_stats_idx = 0;
			break;
		}
	}
}

void
wl_write_acnt_tx_record(struct net_device *netdev, char *filename)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	UINT32 idx = 0;
	UINT32 currIdx = (acnt_tx_record_idx == 0) ?
		(ACNT_TX_RECORD_MAX - 1) : (acnt_tx_record_idx - 1);
	acnt_tx_t *acnt_tx_record_write = NULL;
	acnt_tx_t *acnt_tx_record = (acnt_tx_t *) priv->wlpd_p->acnt_tx_record;
	size_t size = (sizeof(acnt_tx_t) * ACNT_TX_RECORD_MAX);

	struct file *filp_acnt_tx_record = NULL;
	char *string_buff = NULL, tmp_buff[ACNT_MAX_STR_LEN];

	if (!acnt_tx_record) {
		printk("Scheduler Accounting Records is disabled!\n"
		       "Please use iwpriv <vapif> setcmd \"gettxscheinfo enable\" to enable it!\n");
		return;
	}

	if ((acnt_tx_record_write =
	     (acnt_tx_t *) wl_kmalloc_autogfp(size)) != NULL) {
		memset(acnt_tx_record_write, 0, size);
		memcpy(&acnt_tx_record_write[0], &acnt_tx_record[0], size);
	} else {
		printk("Error allocate memory for acnt_tx_record_write\n");
		return;
	}

	if ((string_buff =
	     (char *)wl_kmalloc_autogfp(ACNT_MAX_STR_LEN *
					ACNT_TX_RECORD_MAX)) != NULL)
		memset(string_buff, 0, (ACNT_MAX_STR_LEN * ACNT_TX_RECORD_MAX));
	else {
		wl_kfree(acnt_tx_record_write);
		printk("Error allocate memory to display acnt_tx_record\n");
		return;
	}

	for (idx = 0; idx < ACNT_TX_RECORD_MAX; idx++) {
		memset(tmp_buff, 0, sizeof(tmp_buff));
		sprintf(tmp_buff,
			"%d 0x%x %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d\n",
			acnt_tx_record_write[currIdx].Ratetblindex,
			acnt_tx_record_write[currIdx].rateInfo,
			acnt_tx_record_write[currIdx].StnId,
			acnt_tx_record_write[currIdx].Type,
			acnt_tx_record_write[currIdx].AggrType,
			acnt_tx_record_write[currIdx].Retries,
			acnt_tx_record_write[currIdx].Txcnt,
			acnt_tx_record_write[currIdx].NumAmpdu,
			acnt_tx_record_write[currIdx].NumBytes,
			acnt_tx_record_write[currIdx].DelayTime,
			acnt_tx_record_write[currIdx].SchedulePeriod,
			acnt_tx_record_write[currIdx].Qid,
			acnt_tx_record_write[currIdx].AirTime,
			acnt_tx_record_write[currIdx].TimeStamp,
			acnt_tx_record_write[currIdx].PhyRate,
			acnt_tx_record_write[currIdx].revd1,
			acnt_tx_record_write[currIdx].revd2);

		strcat(string_buff, tmp_buff);

		if (currIdx == 0)
			currIdx = ACNT_TX_RECORD_MAX - 1;
		else
			currIdx--;
	}

	filp_acnt_tx_record =
		filp_open(filename, O_RDWR | O_CREAT | O_TRUNC, 0);
	if (!IS_ERR(filp_acnt_tx_record)) {
		__kernel_write(filp_acnt_tx_record, string_buff,
			       strlen(string_buff),
			       &filp_acnt_tx_record->f_pos);
		filp_close(filp_acnt_tx_record, current->files);
		printk("Scheduler Accounting Records written to %s\n",
		       filename);
	} else
		printk("Error opening %s!\n", filename);

	wl_kfree(string_buff);
	wl_kfree(acnt_tx_record_write);

	return;
}

void
wl_dump_acnt_tx_record(struct net_device *netdev, UINT32 entry)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	UINT32 idx = 0;
	UINT32 currIdx = (acnt_tx_record_idx == 0) ?
		(ACNT_TX_RECORD_MAX - 1) : (acnt_tx_record_idx - 1);
	acnt_tx_t *acnt_tx_record_dump = NULL;
	acnt_tx_t *acnt_tx_record = (acnt_tx_t *) priv->wlpd_p->acnt_tx_record;
	size_t size = (sizeof(acnt_tx_t) * ACNT_TX_RECORD_MAX);

	if (!acnt_tx_record) {
		printk("Scheduler Accounting Records is disabled!\n"
		       "Please use iwpriv <vapif> setcmd \"gettxscheinfo enable\" to enable it!\n");
		return;
	}

	if ((acnt_tx_record_dump =
	     (acnt_tx_t *) wl_kmalloc_autogfp(size)) != NULL) {
		memset(acnt_tx_record_dump, 0, size);
		memcpy(&acnt_tx_record_dump[0], &acnt_tx_record[0], size);
	} else {
		printk("Error allocate memory for acnt_tx_record_dump\n");
		return;
	}

	for (idx = 0; idx < entry; idx++) {
		printk("Ratetblindex: %d rateInfo: 0x%x StnId: %d Type: %d AggrType: %d Retries: %d Txcnt: %d NumAmpdu: %d NumBytes: %d DelayTime: %d SchedulePeriod: %d Qid: %d AirTime %d TimeStamp %d PhyRate %d revd1 %d revd2 %d\n", acnt_tx_record_dump[currIdx].Ratetblindex, acnt_tx_record_dump[currIdx].rateInfo, acnt_tx_record_dump[currIdx].StnId, acnt_tx_record_dump[currIdx].Type, acnt_tx_record_dump[currIdx].AggrType, acnt_tx_record_dump[currIdx].Retries, acnt_tx_record_dump[currIdx].Txcnt, acnt_tx_record_dump[currIdx].NumAmpdu, acnt_tx_record_dump[currIdx].NumBytes, acnt_tx_record_dump[currIdx].DelayTime, acnt_tx_record_dump[currIdx].SchedulePeriod, acnt_tx_record_dump[currIdx].Qid, acnt_tx_record_dump[currIdx].AirTime, acnt_tx_record_dump[currIdx].TimeStamp, acnt_tx_record_dump[currIdx].PhyRate, acnt_tx_record_dump[currIdx].revd1, acnt_tx_record_dump[currIdx].revd2);

		if (currIdx == 0)
			currIdx = ACNT_TX_RECORD_MAX - 1;
		else
			currIdx--;
	}

	wl_kfree(acnt_tx_record_dump);

	return;
}

void
wl_write_acnt_RA_stats(struct net_device *netdev, char *filename)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	UINT32 idx = 0;
	UINT32 currIdx = (acnt_RA_stats_idx == 0) ?
		(ACNT_TX_RECORD_MAX - 1) : (acnt_RA_stats_idx - 1);
	acnt_RA_stats_t *acnt_RA_stats_write = NULL;
	acnt_RA_stats_t *acnt_RA_stats =
		(acnt_RA_stats_t *) priv->wlpd_p->acnt_RA_stats;
	size_t size = (sizeof(acnt_RA_stats_t) * ACNT_TX_RECORD_MAX);

	struct file *filp_acnt_RA_stats = NULL;
	char *string_buff = NULL, tmp_buff[ACNT_RA_MAX_STR_LEN];

	if (!acnt_RA_stats) {
		printk("RA stats logging is disabled!\n"
		       "Please use iwpriv <vapif> setcmd \"qstats rastats log_enable\" to enable it!\n");
		return;
	}

	if ((acnt_RA_stats_write =
	     (acnt_RA_stats_t *) wl_kmalloc_autogfp(size)) != NULL) {
		memset(acnt_RA_stats_write, 0, size);
		memcpy(&acnt_RA_stats_write[0], &acnt_RA_stats[0], size);
	} else {
		printk("Error allocate memory for acnt_RA_stats_write\n");
		return;
	}

	if ((string_buff =
	     (char *)wl_kmalloc_autogfp(ACNT_RA_MAX_STR_LEN *
					ACNT_TX_RECORD_MAX)) != NULL)
		memset(string_buff, 0,
		       (ACNT_RA_MAX_STR_LEN * ACNT_TX_RECORD_MAX));
	else {
		wl_kfree(acnt_RA_stats_write);
		printk("Error allocate memory to display acnt_RA_stats\n");
		return;
	}

	for (idx = 0; idx < ACNT_TX_RECORD_MAX; idx++) {
		memset(tmp_buff, 0, sizeof(tmp_buff));
		sprintf(tmp_buff,
			"%d %d %d %d %d 0x%x %d %d %d %d %d %d %d %d %d %d %d\n",
			acnt_RA_stats_write[currIdx].PER,
			acnt_RA_stats_write[currIdx].TSF,
			acnt_RA_stats_write[currIdx].StnId,
			acnt_RA_stats_write[currIdx].Type,
			acnt_RA_stats_write[currIdx].Ratetblindex,
			acnt_RA_stats_write[currIdx].RateInfo,
			acnt_RA_stats_write[currIdx].Txattemptcnt,
			acnt_RA_stats_write[currIdx].state,
			acnt_RA_stats_write[currIdx].result,
			acnt_RA_stats_write[currIdx].per_threshold,
			acnt_RA_stats_write[currIdx].min_pkt_cnt_thres,
			acnt_RA_stats_write[currIdx].time_for_decrease,
			acnt_RA_stats_write[currIdx].time_for_increase,
			acnt_RA_stats_write[currIdx].time_constant_for_increase,
			acnt_RA_stats_write[currIdx].tx_sent_cnt_raw,
			acnt_RA_stats_write[currIdx].tx_success_cnt_raw,
			acnt_RA_stats_write[currIdx].tx_failure_cnt_raw);

		strcat(string_buff, tmp_buff);

		if (currIdx == 0)
			currIdx = ACNT_TX_RECORD_MAX - 1;
		else
			currIdx--;
	}

	filp_acnt_RA_stats = filp_open(filename, O_RDWR | O_CREAT | O_TRUNC, 0);
	if (!IS_ERR(filp_acnt_RA_stats)) {
		__kernel_write(filp_acnt_RA_stats, string_buff,
			       strlen(string_buff), &filp_acnt_RA_stats->f_pos);
		filp_close(filp_acnt_RA_stats, current->files);
		printk("Scheduler Accounting Records written to %s\n",
		       filename);
	} else
		printk("Error opening %s!\n", filename);

	wl_kfree(string_buff);
	wl_kfree(acnt_RA_stats_write);

	return;
}

void
wl_dump_acnt_RA_stats(struct net_device *netdev, UINT32 entry)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	UINT32 idx = 0;
	UINT32 currIdx = (acnt_RA_stats_idx == 0) ?
		(ACNT_TX_RECORD_MAX - 1) : (acnt_RA_stats_idx - 1);
	acnt_RA_stats_t *acnt_RA_stats_dump = NULL;
	acnt_RA_stats_t *acnt_RA_stats =
		(acnt_RA_stats_t *) priv->wlpd_p->acnt_RA_stats;
	size_t size = (sizeof(acnt_RA_stats_t) * ACNT_TX_RECORD_MAX);

	if (!acnt_RA_stats) {
		printk("RA stats logging is disabled!\n"
		       "Please use iwpriv <vapif> setcmd \"qstats rastats log_enable\" to enable it!\n");
		return;
	}

	if ((acnt_RA_stats_dump =
	     (acnt_RA_stats_t *) wl_kmalloc_autogfp(size)) != NULL) {
		memset(acnt_RA_stats_dump, 0, size);
		memcpy(&acnt_RA_stats_dump[0], &acnt_RA_stats[0], size);
	} else {
		printk("Error allocate memory for acnt_RA_stats_dump\n");
		return;
	}

	for (idx = 0; idx < entry; idx++) {
		printk("PER: %d TSF: %d StnId: %d Type: %d Ratetblindex: %d rateInfo: 0x%x Txattemptcnt: %d state: %d result: %d per_threshold: %d min_pkt_cnt_thres: %d time_for_decrease %d time_for_increase %d time_constant_for_increase %d tx_sent_cnt %d tx_success_cnt %d tx_failure_cnt %d\n", acnt_RA_stats_dump[currIdx].PER, acnt_RA_stats_dump[currIdx].TSF, acnt_RA_stats_dump[currIdx].StnId, acnt_RA_stats_dump[currIdx].Type, acnt_RA_stats_dump[currIdx].Ratetblindex, acnt_RA_stats_dump[currIdx].RateInfo, acnt_RA_stats_dump[currIdx].Txattemptcnt, acnt_RA_stats_dump[currIdx].state, acnt_RA_stats_dump[currIdx].result, acnt_RA_stats_dump[currIdx].per_threshold, acnt_RA_stats_dump[currIdx].min_pkt_cnt_thres, acnt_RA_stats_dump[currIdx].time_for_decrease, acnt_RA_stats_dump[currIdx].time_for_increase, acnt_RA_stats_dump[currIdx].time_constant_for_increase, acnt_RA_stats_dump[currIdx].tx_sent_cnt_raw, acnt_RA_stats_dump[currIdx].tx_success_cnt_raw, acnt_RA_stats_dump[currIdx].tx_failure_cnt_raw);

		if (currIdx == 0)
			currIdx = ACNT_TX_RECORD_MAX - 1;
		else
			currIdx--;
	}

	wl_kfree(acnt_RA_stats_dump);

	return;
}
#endif /* SOC_W906X */

UINT8
rate_GetRateID(UINT8 Rate)
{
	switch (Rate) {
	case 10:		// 1 Mbit/s or 12 Mbit/s
		return (0);

	case 20:		// 2 Mbit/s
		return (1);

	case 55:		// 5.5 Mbit/s
		return (2);

	case 110:		// 11 Mbit/s
		return (3);

	case 220:		// 22 Mbit/s
		return (4);

	case 0xb:		// 6 Mbit/s
		return (5);

	case 0xf:		// 9 Mbit/s
		return (6);

	case 0xe:		// 18 Mbit/s
		return (8);

	case 0x9:		// 24 Mbit/s
		return (9);

	case 0xd:		// 36 Mbit/s
		return (10);

	case 0x8:		// 48 Mbit/s
		return (11);

	case 0xc:		// 54 Mbit/s
		return (12);

	case 0x7:		// 72 Mbit/s
		return (13);
	}
	return (0);
}

void
wlrxRateDecode(rx_info_t * pRxInfo, WLAN_RATE_HIST * pRH)
{
	u32 mcs;
	switch ((pRxInfo->param >> 3) & 0x7) {
	case 0:
		//11a
		if ((pRxInfo->rate & 0xf) == 10)
			pRH->LegacyRates[7]++;	//12mbps
		else
			pRH->LegacyRates[rate_GetRateID(pRxInfo->rate & 0xf)]++;
		break;
	case 1:
		//11b
		if ((pRxInfo->rate & 0xf) == 10)
			pRH->LegacyRates[0]++;	//1mbps
		else
			pRH->LegacyRates[rate_GetRateID(pRxInfo->rate & 0xf)]++;
		break;
	case 2:
		//11n; [bw][gi][mcs]
		if ((pRxInfo->ht_sig1 & 0x3f) < 16) {
			pRH->HtRates[(pRxInfo->ht_sig1 >> 7) & 0x1][(pRxInfo->
								     ht_sig2 >>
								     7) &
								    0x1]
				[pRxInfo->ht_sig1 & 0xf]++;
		}
		break;
	case 4:
		//11ac; [NSS][bw][gi][mcs]
		mcs = (pRxInfo->ht_sig2 >> 4) & 0xf;
		if (mcs < 10) {
			u32 idx = ((pRxInfo->ht_sig1 >> 10) & 0x3);
			if (idx < QS_NUM_SUPPORTED_11AC_NSS)
				pRH->VHtRates[idx][pRxInfo->
						   ht_sig1 & 0x3][(pRxInfo->
								   ht_sig2 &
								   0x1)][mcs]++;
		}
		break;
	}
}

BOOLEAN
DecodeRecds(struct net_device *netdev, u8 * acntRecds, u32 bufSize)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	acnt_t *pAcnt;
	u8 *pStart;
	u8 *pEnd;
	u32 Cnt_rx_ppdu = 0, Cnt_tx_flush = 0, Cnt_tx_enqueue = 0, Cnt_drop = 0;
	u32 Cnt_busy = 0, Cnt_wrap = 0, Cnt_rx_reset = 0, Cnt_tx_reset = 0;
	BOOLEAN bUnknownCode = FALSE;

#ifdef SOC_W906X
	u16 loopcnt = 0;
	static u8 dbgprintOnce = 0;
#endif

	pStart = acntRecds;
	pEnd = pStart + bufSize;
	while (pStart < pEnd) {
#ifdef SOC_W906X
		if (loopcnt++ > 1000) {
			printk("accounting record error 1");
			break;
		}
#endif /* #ifdef SOC_W906X */

		pAcnt = (acnt_t *) pStart;
		if (pAcnt->Len == 0) {
			break;
		}
		switch (pAcnt->Code) {

		case acnt_code_rx_ppdu:	// RXINFO for each PPDu (Acnt_rx_t)
			{
				acnt_rx_t *pAcntrx;
				extStaDb_StaInfo_t *pStaInfo = NULL;
#ifndef SOC_W906X
				NewdpRxCounter_t *pNewDpCnts =
					(NewdpRxCounter_t *) & priv->wlpd_p->
					rxCnts;
#endif
				pAcntrx = (acnt_rx_t *) pStart;

				pStaInfo =
					extStaDb_GetStaInfo(vmacSta_p,
							    (IEEEtypes_MacAddr_t
							     *) ((dot11_t
								  *) (pAcntrx->
								      RxINFO.
								      Hdr))->
							    addr2,
							    STADB_SKIP_MATCH_VAP);
				if (pStaInfo) {
					pStaInfo->RSSI = pAcntrx->RxINFO.rssi_x;
					pStaInfo->RSSI_path.a =
						pAcntrx->RxINFO.pm_rssi_dbm_a;
					pStaInfo->RSSI_path.b =
						pAcntrx->RxINFO.pm_rssi_dbm_b;
					pStaInfo->RSSI_path.c =
						pAcntrx->RxINFO.pm_rssi_dbm_c;
					pStaInfo->RSSI_path.d =
						pAcntrx->RxINFO.pm_rssi_dbm_d;
				} else {
					if (vmacSta_p->OpMode == WL_OP_MODE_STA
					    || vmacSta_p->OpMode ==
					    WL_OP_MODE_VSTA) {
						vmacSta_p->RSSI_path.a =
							pAcntrx->RxINFO.
							pm_rssi_dbm_a;
						vmacSta_p->RSSI_path.b =
							pAcntrx->RxINFO.
							pm_rssi_dbm_b;
						vmacSta_p->RSSI_path.c =
							pAcntrx->RxINFO.
							pm_rssi_dbm_c;
						vmacSta_p->RSSI_path.d =
							pAcntrx->RxINFO.
							pm_rssi_dbm_d;
					}
				}

				priv->wlpd_p->NF_path.a =
					pAcntrx->RxINFO.pm_nf_dbm_a;
				priv->wlpd_p->NF_path.b =
					pAcntrx->RxINFO.pm_nf_dbm_b;
				priv->wlpd_p->NF_path.c =
					pAcntrx->RxINFO.pm_nf_dbm_c;
				priv->wlpd_p->NF_path.d =
					pAcntrx->RxINFO.pm_nf_dbm_d;

				wlrxRateDecode(&pAcntrx->RxINFO,
					       &priv->wlpd_p->rxRateHistogram);
#ifndef SOC_W906X
				if (pAcntrx->Rate & 0x1000)
					pNewDpCnts->mu_pktcnt++;
#endif /* #ifdef SOC_W906X */
				pStart += pAcntrx->Len * 4;
				Cnt_rx_ppdu++;
				break;
			}
		case acnt_code_tx_flush:	// Flush Tx Queue (Acnt_txflush_t)
			{
				acnt_txflush_t *pTxFlush;

				pTxFlush = (acnt_txflush_t *) pStart;
				pStart += pTxFlush->Len * 4;
				Cnt_tx_flush++;
				break;
			}
		case acnt_code_tx_enqueue:	// TXINFO when added to TCQ (Acnt_tx_t)
			{
#ifdef SOC_W906X
				acnt_tx_t *pAcnttx;
				pAcnttx = (acnt_tx_t *) pStart;

				if (priv->wlpd_p->acnt_tx_record)
					wl_copy_acnt_raw((acnt_tx_t *) priv->
							 wlpd_p->acnt_tx_record,
							 pAcnttx,
							 acnt_code_tx_enqueue);

				if (pAcnttx->StnId >= sta_num) {
					priv->wlpd_p->except_cnt.badAcntStnid++;

					if (!dbgprintOnce) {
#if 0
						printk("Severe error: %s(): got invalid stnid (%u)in Acnt record\n", __func__, pAcnttx->StnId);
#endif
						dbgprintOnce = 1;
					}
					goto error_skip;
				}

				wltxRateDecode((dbRateInfo_t *) & pAcnttx->
					       rateInfo, pAcnttx->Ratetblindex,
					       priv->wlpd_p->
					       txRateHistogram[pAcnttx->StnId],
					       pAcnttx->Type, pAcnttx->Txcnt);

				if (priv->wlpd_p->
				    scheHistogram[pAcnttx->StnId] == NULL)
					goto error_skip;

				if (pAcnttx->NumAmpdu > 64) {
					priv->wlpd_p->scheHistogram[pAcnttx->
								    StnId]->
						NumAmpdu[pAcnttx->
							 AggrType][64]++;
				} else if (pAcnttx->NumAmpdu > 0) {
					priv->wlpd_p->scheHistogram[pAcnttx->
								    StnId]->
						NumAmpdu[pAcnttx->
							 AggrType][pAcnttx->
								   NumAmpdu -
								   1]++;
				}
				if (pAcnttx->DelayTime < 1000) {
					priv->wlpd_p->scheHistogram[pAcnttx->
								    StnId]->
						Delay[pAcnttx->AggrType][0]++;
				} else if (pAcnttx->DelayTime < 10000) {
					priv->wlpd_p->scheHistogram[pAcnttx->
								    StnId]->
						Delay[pAcnttx->AggrType][1]++;
				} else if (pAcnttx->DelayTime < 100000) {
					priv->wlpd_p->scheHistogram[pAcnttx->
								    StnId]->
						Delay[pAcnttx->AggrType][2]++;
				} else if (pAcnttx->DelayTime < 300000) {
					priv->wlpd_p->scheHistogram[pAcnttx->
								    StnId]->
						Delay[pAcnttx->AggrType][3]++;
				} else
					priv->wlpd_p->scheHistogram[pAcnttx->
								    StnId]->
						Delay[pAcnttx->AggrType][4]++;

				if (pAcnttx->NumBytes < 1500) {
					priv->wlpd_p->scheHistogram[pAcnttx->
								    StnId]->
						NumBytes[pAcnttx->
							 AggrType][0]++;
				} else if (pAcnttx->NumBytes < 16000) {
					priv->wlpd_p->scheHistogram[pAcnttx->
								    StnId]->
						NumBytes[pAcnttx->
							 AggrType][1]++;
				} else if (pAcnttx->NumBytes < 32000) {
					priv->wlpd_p->scheHistogram[pAcnttx->
								    StnId]->
						NumBytes[pAcnttx->
							 AggrType][2]++;
				} else if (pAcnttx->NumBytes < 64000) {
					priv->wlpd_p->scheHistogram[pAcnttx->
								    StnId]->
						NumBytes[pAcnttx->
							 AggrType][3]++;
				} else if (pAcnttx->NumBytes < 128000) {
					priv->wlpd_p->scheHistogram[pAcnttx->
								    StnId]->
						NumBytes[pAcnttx->
							 AggrType][4]++;
				} else
					priv->wlpd_p->scheHistogram[pAcnttx->
								    StnId]->
						NumBytes[pAcnttx->
							 AggrType][5]++;

				{
					extStaDb_StaInfo_t *pStaInfo =
						extStaDb_GetStaInfoStn
						(vmacSta_p, pAcnttx->StnId);
					if (pStaInfo &&
					    (pStaInfo->StnId ==
					     pAcnttx->StnId)) {
						memcpy(&pStaInfo->RateInfo,
						       &pAcnttx->rateInfo,
						       sizeof(u_int32_t));
					}
				}
#else
				acnt_tx_t *pAcnttx;
				extStaDb_StaInfo_t *pStaInfo = NULL;
				pAcnttx = (acnt_tx_t *) pStart;
				pStaInfo =
					extStaDb_GetStaInfo(vmacSta_p,
							    (IEEEtypes_Addr_t(*)
							     [6]) & (pAcnttx->
								     Hdr.
								     addr1[0]),
							    2);
				if (pStaInfo && pStaInfo->StnId) {
					memcpy(&pStaInfo->RateInfo,
					       &pAcnttx->TxINFO.rateInfo,
					       sizeof(u_int32_t));

					wltxRateDecode((dbRateInfo_t *) &
						       pAcnttx->TxINFO.rateInfo,
						       pAcnttx->Ratetblindex,
						       priv->wlpd_p->
						       txRateHistogram
						       [pStaInfo->StnId - 1],
						       pAcnttx->Type,
						       pAcnttx->Txcnt);
				}
#endif /* SOC_W906X */
error_skip:
				pStart += pAcnttx->Len * 4;
				Cnt_tx_enqueue++;
				break;
			}
		case acnt_code_drop:	// Count of dropped records (Acnt_u32_t)
			{
				acnt_u32_t *pAcnt32;

				pAcnt32 = (acnt_u32_t *) pStart;
				pStart += pAcnt32->Len * 4;
				Cnt_drop++;
				break;
			}
		case acnt_code_busy:	// Marked busy until filled in (never seen by Host)
			{
				acnt_t *pCodeBusy;

				pCodeBusy = (acnt_t *) pStart;
				pStart += pCodeBusy->Len * 4;
				Cnt_busy++;

				break;
			}
		case acnt_code_wrap:	// used to pad when wrapping (no TSF sometimes)
			{
				acnt_t *pCodeWrap;

				pCodeWrap = (acnt_t *) pStart;
				pStart += pCodeWrap->Len * 4;
				Cnt_wrap++;
				break;
			}
		case acnt_code_rx_reset:	//Channel Change/Rx Reset(acnt_u32_t)
			{
				acnt_u32_t *pAcnt32;

				pAcnt32 = (acnt_u32_t *) pStart;
				pStart += pAcnt32->Len * 4;
				Cnt_rx_reset++;
				break;
			}
		case acnt_code_tx_reset:	//TCQ reset(acnt_u8_t)
			{
				acnt_u8_t *pAcnt8;

				pAcnt8 = (acnt_u8_t *) pStart;
				pStart += pAcnt8->Len * 4;
				Cnt_tx_reset++;
				break;
			}
		case acnt_code_RA_stats:
			{
				acnt_RA_stats_t *pRAstats;
#ifndef SOC_W906X
				unsigned long txRateHistoflags;
#endif

				pRAstats = (acnt_RA_stats_t *) pStart;

				if (priv->wlpd_p->acnt_RA_stats)
					wl_copy_acnt_raw((acnt_RA_stats_t *)
							 priv->wlpd_p->
							 acnt_RA_stats,
							 pRAstats,
							 acnt_code_RA_stats);

#ifndef SOC_W906X
				if ((pRAstats->StnId > 0) &&
				    (pRAstats->StnId < sta_num))
#endif
				{
					if (pRAstats->Type < 2) {
						if (pRAstats->Txattemptcnt >=
						    250)
							RA_TX_ATTEMPT[pRAstats->
								      Type]
								[5]++;
						else if (pRAstats->
							 Txattemptcnt >= 100)
							RA_TX_ATTEMPT[pRAstats->
								      Type]
								[4]++;
						else if (pRAstats->
							 Txattemptcnt >= 50)
							RA_TX_ATTEMPT[pRAstats->
								      Type]
								[3]++;
						else if (pRAstats->
							 Txattemptcnt >= 15)
							RA_TX_ATTEMPT[pRAstats->
								      Type]
								[2]++;
						else if (pRAstats->
							 Txattemptcnt >= 4)
							RA_TX_ATTEMPT[pRAstats->
								      Type]
								[1]++;
						else
							RA_TX_ATTEMPT[pRAstats->
								      Type]
								[0]++;
					}
#ifndef SOC_W906X
					SPIN_LOCK_IRQSAVE(&priv->wlpd_p->
							  txRateHistoLock
							  [pRAstats->StnId - 1],
							  txRateHistoflags);
#endif

					wltxRatePERDecode((dbRateInfo_t *) &
							  pRAstats->RateInfo,
							  pRAstats->
							  Ratetblindex,
							  pRAstats->PER,
							  priv->wlpd_p->
							  txRateHistogram
							  [pRAstats->StnId],
							  pRAstats->Type);

#ifndef SOC_W906X
					SPIN_UNLOCK_IRQRESTORE(&priv->wlpd_p->
							       txRateHistoLock
							       [pRAstats->
								StnId - 1],
							       txRateHistoflags);
#endif
				}

				pStart += pRAstats->Len * 4;
				break;
			}

#ifdef NEWDP_ACNT_BA
		case acnt_code_BA_stats:
			{
				acnt_BA_stats_t *pBAstats;

				pBAstats = (acnt_BA_stats_t *) pStart;

				if (pBAstats->StnId < 10) {
					wltxBADecode(&priv->wlpd_p->
						     txBAStats
						     [BA_HISTO_STAID_MAP
						      [pBAstats->StnId]],
						     pBAstats);
				}

				pStart += pBAstats->Len * 4;
				break;
			}
#endif

#ifdef BF_MIMO_CTRL_FIELD_LOGGING
		case acnt_code_BF_Mimo_Ctrl_Field_Log:
			{
				acnt_BF_Mimo_Ctrl_Field_Log_t
					*pBF_Mimo_Ctrl_Field_Log;

				pBF_Mimo_Ctrl_Field_Log =
					(acnt_BF_Mimo_Ctrl_Field_Log_t *)
					pStart;

				wl_BF_Mimo_Ctrl_Field_Log_Decode
					(pBF_Mimo_Ctrl_Field_Log);

				pStart += pBF_Mimo_Ctrl_Field_Log->Len * 4;
				break;
			}
#endif

#ifdef SOC_W906X
		case acnt_code_tx_getNewTxq:	//internal_stat[] from getNewTxq() (acnt_tx3_t)
			{
				acnt_tx3_t *pAcnttx3;

				pAcnttx3 = (acnt_tx3_t *) pStart;

#if 0
				//We use print for verification only
				print_hex_dump(KERN_INFO, "",
					       DUMP_PREFIX_OFFSET, 32, 4,
					       pAcnttx3, sizeof(acnt_tx3_t),
					       false);
#endif
				memcpy(&acnt_internal_stat
				       [current_internal_stat], pAcnttx3,
				       sizeof(acnt_tx3_t));
				current_internal_stat =
					(current_internal_stat +
					 1) % NUM_INTERNAL_STAT;

				pStart += pAcnttx3->Len * 4;
				break;
			}
#endif /* SOC_W906X */

		default:
			{
				//printk("unknown acnt code\n");
				bUnknownCode = TRUE;
				break;
			}

		}
		if (bUnknownCode) {
			//printk("Unknown code  stop decoding\n");
			break;
		}
		if (Cnt_busy > 1) {
			//printk("Acnt_code_busy  stop decoding\n");
			break;
		}
	}			//end of while
	return bUnknownCode;

}

#if defined(SOC_W906X) || defined(NEWDP_ACNT_CHUNKS)
void
wlAcntProcess_chunks(struct net_device *netdev)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	u32 ToBeReadAcntBufSize;
	//int status;
#ifdef SOC_W906X
	unsigned int reg_acnt_tail = priv->wlpd_p->reg.acnt_tail;
	u16 loopcnt = 0;
#else
	unsigned int reg_acnt_tail = MACREG_REG_AcntTail;
#endif
	u8 *acntRecds, *dst;
	u32 AcntRingBufSize;
	u8 *AcntBase[ACNT_NCHUNK];
	u8 NumChunk, i;
	u32 head, tail, Temp, off, size, ChunkSize;
	BOOLEAN bSameChunk;

	memset((void *)&AcntBase[0], 0, sizeof(AcntBase));
	for (i = 0; i < priv->wlpd_p->AcntChunkInfo.NumChunk; i++) {
		AcntBase[i] = priv->wlpd_p->mmap_ACNTChunk[i].data;
	}
	wlAcntPeekRecds(netdev, &head, &tail);
	if (head == tail) {
		return;
	}
	ChunkSize = priv->wlpd_p->AcntChunkInfo.SizeOfChunk;
	NumChunk = priv->wlpd_p->AcntChunkInfo.NumChunk;
#ifdef SOC_W906X
	AcntRingBufSize = priv->wlpd_p->descData[0].AcntRingSize;
	acntRecds = (u8 *) wl_kmalloc_autogfp(AcntRingBufSize);
	//Need to add protection here for malloc
	if (acntRecds == NULL) {
		printk("malloc failed on wlAcntProcess_chunks\n ");
		goto err_malloc;
	}
#else
	AcntRingBufSize =
		min(priv->wlpd_p->descData[0].AcntRingSize,
		    (ACNT_NCHUNK * DEFAULT_SIZE_CHUNK));
	acntRecds = priv->wlpd_p->acntRecords;
#endif
	memset(acntRecds, 0, AcntRingBufSize);
	dst = acntRecds;
	if (tail > head) {
		//printk("WrapAround: head =%d tail =%d \n", head, tail);

		ToBeReadAcntBufSize = AcntRingBufSize - tail + head;
		Temp = ToBeReadAcntBufSize;

		while (tail != head) {
#ifdef SOC_W906X
			if (loopcnt++ > 1000) {
				printk("accounting record error 2");
				goto err_malloc;
			}
#endif
			if (tail > head) {
				while (tail != (AcntRingBufSize)) {
					off = tail % (ChunkSize);
					size = ChunkSize - off;
					memcpy(dst,
					       (u8 *) AcntBase[tail /
							       ChunkSize] + off,
					       size);
					dst += size;
					tail += size;
#ifdef SOC_W906X
					if (loopcnt++ > 1000) {
						printk("accounting record error 3");
						goto err_malloc;
					}
#endif
				}
				tail = 0;
			} else {
				if ((tail / ChunkSize) == (head / ChunkSize)) {
					bSameChunk = TRUE;
				} else {
					bSameChunk = FALSE;
				}
				if (bSameChunk) {
					off = tail % ChunkSize;
					size = head - tail;
					memcpy(dst,
					       (u8 *) AcntBase[tail /
							       ChunkSize] + off,
					       size);
					dst += size;
					tail += size;
				} else {
					off = tail % (ChunkSize);
					size = ChunkSize - off;
					memcpy(dst,
					       (u8 *) AcntBase[tail /
							       ChunkSize] + off,
					       size);
					dst += size;
					tail += size;
				}
			}

		}

		DecodeRecds(netdev, acntRecds, ToBeReadAcntBufSize);
	} else {
		ToBeReadAcntBufSize = head - tail;
		while (tail != head) {
#ifdef SOC_W906X
			if (loopcnt++ > 1000) {
				printk("accounting record error 4");
				goto err_malloc;
			}
#endif
			if ((tail / ChunkSize) == (head / ChunkSize)) {
				bSameChunk = TRUE;
			} else {
				bSameChunk = FALSE;
			}
			if (bSameChunk) {
				off = tail % ChunkSize;
				size = head - tail;
				memcpy(dst,
				       (u8 *) AcntBase[tail / ChunkSize] + off,
				       size);
				dst += size;
				tail += size;
			} else {
				off = tail % ChunkSize;
				size = ChunkSize - off;
				memcpy(dst,
				       (u8 *) AcntBase[tail / ChunkSize] + off,
				       size);
				dst += size;
				tail += size;
			}

		}
		DecodeRecds(netdev, acntRecds, ToBeReadAcntBufSize);
	}
#ifdef SOC_W906X
err_malloc:
	if (acntRecds != NULL) {
		wl_kfree(acntRecds);
	}
#endif
	tail = head;
	wl_util_writel(netdev, tail, priv->ioBase1 + reg_acnt_tail);
}

#else

void
wlAcntProcess(struct net_device *netdev)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	//u_int8_t *acnBuf = NULL;
	u_int32_t head, tail;
	//u_int32_t maxSize = priv->wlpd_p->descData[0].AcntRingSize;
	u_int8_t NumChunk;
	u_int32_t AcntBufSize;
	u_int8_t *acntRecds;
	u_int32_t ToBeReadAcntBufSize;
	u_int32_t ChunkSize;
	//int i;
	//BOOLEAN unknowncode = FALSE;
	wlAcntPeekRecds(netdev, &head, &tail);

	ChunkSize = priv->wlpd_p->descData[0].AcntRingSize;
	NumChunk = 1;
	AcntBufSize =
		(u_int32_t) min((u_int32_t) (NumChunk * ChunkSize),
				(u_int32_t) DEFAULT_ACNT_RING_SIZE);
	acntRecds = priv->wlpd_p->acntRecords;

	if (tail == head)
		return;

	if (tail > head) {
		//printk("wrap around \n");
		ToBeReadAcntBufSize = AcntBufSize - tail + head;
		if (ToBeReadAcntBufSize > AcntBufSize)
			goto skip_process;
		memset(acntRecds, 0, AcntBufSize);
		memcpy(acntRecds, (u8 *) priv->wlpd_p->ACNTmemInfo.data + tail,
		       AcntBufSize - tail);
		memcpy(acntRecds + AcntBufSize - tail,
		       (u8 *) priv->wlpd_p->ACNTmemInfo.data, head);
		DecodeRecds(netdev, acntRecds, ToBeReadAcntBufSize);
	} else {
		//printk("normal \n");
		ToBeReadAcntBufSize = head - tail;
		if (ToBeReadAcntBufSize > AcntBufSize)
			goto skip_process;
		DecodeRecds(netdev,
			    (u8 *) priv->wlpd_p->ACNTmemInfo.data + tail,
			    ToBeReadAcntBufSize);
		//free(acntRecds);
	}

skip_process:
	tail = head;
	wl_util_writel(netdev, tail, priv->ioBase1 + MACREG_REG_AcntTail);
	/*
	   if ((priv->vmacSta_p->wtp_info.WTP_enabled == FALSE) || 
	   (priv->vmacSta_p->wtp_info.mac_mode != WTP_MAC_MODE_SPLITMAC)) {
	   printk("adjust tail \n");                            
	   writel(tail, priv->ioBase1 + MACREG_REG_AcntTail);
	   }
	 */
}
#endif

void
wlHandleAcnt(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	if (mib->mib_wtp_cfg->mac_mode == WTP_MAC_MODE_LOCALMAC) {
#if defined(SOC_W906X) || defined(NEWDP_ACNT_CHUNKS)
		wlAcntProcess_chunks(netdev);
#else
		wlAcntProcess(netdev);
#endif

	}

	WLSNDEVT(netdev, IWEVCUSTOM,
		 (IEEEtypes_MacAddr_t *) & wlpptr->hwData.macAddr[0],
		 "accounting record ready");

}

void
wlAcntPeekRecds(struct net_device *netdev, u_int32_t * head, u_int32_t * tail)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
#ifdef SOC_W906X
	unsigned int reg_acnt_head = wlpptr->wlpd_p->reg.acnt_head;
	unsigned int reg_acnt_tail = wlpptr->wlpd_p->reg.acnt_tail;
#else
	unsigned int reg_acnt_head = MACREG_REG_AcntHead;
	unsigned int reg_acnt_tail = MACREG_REG_AcntTail;
#endif

	*head = wl_util_readl(netdev, wlpptr->ioBase1 + reg_acnt_head);
	*tail = wl_util_readl(netdev, wlpptr->ioBase1 + reg_acnt_tail);
}

void
wlAcntReadRecds(struct net_device *netdev, u_int32_t newTail, u_int8_t * pBuf,
		u_int32_t * bufSize)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	u_int32_t Head, tail;
	int temSize;
	u_int32_t temBufSize = *bufSize;
	u_int32_t temBufSizeOrg = temBufSize;
#ifdef SOC_W906X
	unsigned int reg_acnt_head = wlpptr->wlpd_p->reg.acnt_head;
	unsigned int reg_acnt_tail = wlpptr->wlpd_p->reg.acnt_tail;
#else
	unsigned int reg_acnt_head = MACREG_REG_AcntHead;
	unsigned int reg_acnt_tail = MACREG_REG_AcntTail;
#endif

	Head = wl_util_readl(netdev, wlpptr->ioBase1 + reg_acnt_head);
	tail = wl_util_readl(netdev, wlpptr->ioBase1 + reg_acnt_tail);

	temSize = Head - tail;
	//no data or does not move the tail
	if ((temSize == 0) || (newTail == tail)) {
		*bufSize = 0;
		return;
	}

	if (temSize < 0) {
		// Handle ring wrap case
		temSize = wlpptr->wlpd_p->descData[0].AcntRingSize - tail;
		if (temSize < temBufSize) {
			memcpy(pBuf,
			       &wlpptr->wlpd_p->descData[0].pAcntRing[tail],
			       temSize);
			pBuf += temSize;
			temBufSize -= temSize;
		} else {
			memcpy(pBuf,
			       &wlpptr->wlpd_p->descData[0].pAcntRing[tail],
			       temBufSize);
			wl_util_writel(netdev, (tail+temBufSize), wlpptr->ioBase1 + reg_acnt_tail);
			return;
		}
		if (temBufSize > Head) {
			memcpy(pBuf, &wlpptr->wlpd_p->descData[0].pAcntRing[0],
			       Head);
			temBufSize -= Head;
			*bufSize = temBufSizeOrg - temBufSize;
			wl_util_writel(netdev, Head, wlpptr->ioBase1 + reg_acnt_tail);
			return;
		} else {
			memcpy(pBuf, &wlpptr->wlpd_p->descData[0].pAcntRing[0],
			       temBufSize);
			wl_util_writel(netdev, temBufSize, wlpptr->ioBase1 + reg_acnt_tail);
			return;
		}

	} else {
		if (temSize < temBufSize) {
			memcpy(pBuf,
			       &wlpptr->wlpd_p->descData[0].pAcntRing[tail],
			       temSize);
			*bufSize = temSize;
			wl_util_writel(netdev, (tail+temSize), wlpptr->ioBase1 + reg_acnt_tail);
			return;
		} else {
			memcpy(pBuf,
			       &wlpptr->wlpd_p->descData[0].pAcntRing[tail],
			       temBufSize);
			wl_util_writel(netdev, (tail+temBufSize), wlpptr->ioBase1 + reg_acnt_tail);
			return;
		}
	}
}

/*Function to copy rate table 32bit rateinfo to txratehistogram. This txratehistogram rateinfo is used
* as comparison before updating tx rate counter to make sure counter is updated correctly.
*/
void
wlAcntCopyRateTbl(struct net_device *netdev, UINT8 * sta_addr, UINT32 sta_id,
		  UINT8 type)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	UINT8 *pRateTable = NULL;
	UINT32 i, size;
	UINT32 *pTbl;
	WLAN_TX_RATE_HIST_DATA *histo_p;
	//extern const char* mac_display(const UINT8 *mac);

#ifdef SOC_W906X
	if (sta_id >= sta_num) {
		printk("Copy rate tbl, staid %d out of range %d, FAIL\n",
		       sta_id, sta_num);
#else
	if (sta_id == 0) {
		printk("Copy rate tbl, staid == 0, FAIL\n");
#endif
		return;
	}
	if (sta_addr == NULL) {
		printk("Copy rate tbl, sta_addr == NULL, FAIL \n");
		return;

	}
	if (type == MU_MIMO)
		return;
#ifdef SOC_W906X
	if (wlpptr->wlpd_p->txRateHistogram[sta_id] == NULL) {
#else
	if (wlpptr->wlpd_p->txRateHistogram[sta_id - 1] == NULL) {
#endif
		printk("txRateHistogram NULL, FAIL \n");
		return;
	}
	size = RATEINFO_DWORD_SIZE * RATE_ADAPT_MAX_SUPPORTED_RATES;

	if ((pRateTable = wl_kmalloc_autogfp(size)) == NULL) {
		printk("Alloc memory to copy rate tbl FAIL\n");
		return;
	}

	//mac_display(sta_addr);
	memset(pRateTable, 0, size);
#ifdef SOC_W906X
	wlFwGetRateTable(netdev, sta_addr, (UINT8 *) pRateTable, size, type, 0);
	histo_p =
		(WLAN_TX_RATE_HIST_DATA *) & wlpptr->wlpd_p->
		txRateHistogram[sta_id]->SU_rate[0];
#else
	wlFwGetRateTable(netdev, sta_addr, (UINT8 *) pRateTable, size, type);
	histo_p =
		(WLAN_TX_RATE_HIST_DATA *) & wlpptr->wlpd_p->
		txRateHistogram[sta_id - 1]->SU_rate[0];
#endif
	pTbl = (UINT32 *) pRateTable;
	i = 0;
	while (*(UINT32 *) pTbl != 0) {

		if (i < RATE_ADAPT_MAX_SUPPORTED_RATES) {
			histo_p[i].rateinfo = *(UINT32 *) pTbl;
		} else
			break;
		pTbl += 2;
		i++;
	}

	wl_kfree(pRateTable);
}
