/** @file ap8xLnxEvent.c
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
#include "ap8xLnxRegs.h"
#include "ap8xLnxDesc.h"
#include "ap8xLnxIntf.h"
#include "ap8xLnxXmit.h"
#include "ap8xLnxFwcmd.h"
#include "IEEE_types.h"
#include "wl_mib.h"
#include "wl_hal.h"
#include "StaDb.h"
#include "ap8xLnxEvent.h"
#include "ap8xLnxApi.h"
#if (defined WLS_FTM_SUPPORT) || (defined AOA_PROC_SUPPORT)
#include "ap8xLnxCsi.h"
#endif

#ifdef PRD_CSI_DMA
void
wl_WiFi_AoA_Decode(struct work_struct *work)
{
	struct wlprivate_data *wlpd_p =
		container_of(work, struct wlprivate_data, prd_csi_dma_done_wq);
	struct wlprivate *wlpptr = wlpd_p->masterwlp;
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	evt_prdcsi_t __maybe_unused *prdcsi_data = &wlpptr->prdcsi_data;

#ifdef WLS_FTM_SUPPORT
	{
		struct WLS_FTM_CONFIG_st *wls_ftm_config =
			wlpd_p->wls_ftm_config;
		if (wls_ftm_config->wlsFTM_TriggerCsiEvent == TRUE) {
			// CSI event is from wls FTM trigger and FTM process the CSI data
			hal_rx_csi_processing_buf(vmacSta_p->dev, prdcsi_data);
			return;
		}
	}
#endif

	{
#if !(defined WLS_FTM_SUPPORT) && !(defined AOA_PROC_SUPPORT)
#define MAX_CSI_PROCESSING_ARRAY_SIZE 17
#endif
		int CSI_Processing_Results_Array[MAX_CSI_PROCESSING_ARRAY_SIZE]
			= { 0 };
		int FirstPathDelay, PhaseRoll, Angle, weight1, weight2;
		int FirstPathDelayInt, PhaseRollInt, AngleInt, weight1Int,
			weight2Int;
		int AngleDec;
		char string_buff[512], sign;
		struct file *filp_AoA = NULL;
		UINT16 rssi_value[MAX_RF_ANT_NUM] = { 0 };
		SINT16 rssi_value_signed[MAX_RF_ANT_NUM] = { 0 };
		UINT8 rssi_iter = 0;
#ifdef AOA_PROC_SUPPORT
		hal_rx_csi_aoa_processing(vmacSta_p->dev, prdcsi_data,
					  CSI_Processing_Results_Array);
#endif

		PhaseRoll = CSI_Processing_Results_Array[0];
		FirstPathDelay = CSI_Processing_Results_Array[1];
		weight1 = CSI_Processing_Results_Array[4];
		weight2 = CSI_Processing_Results_Array[5];
		Angle = CSI_Processing_Results_Array[6];

		PhaseRollInt = (PhaseRoll * 1000) / (1 << 16);
		FirstPathDelayInt = (FirstPathDelay * 1000) / (1 << 16);
		weight1Int = (100 * weight1) / (1 << 16);
		weight2Int = (100 * weight2) / (1 << 16);
		AngleInt = (Angle * 360) / (1 << 12);

#ifdef AOA_PROC_SUPPORT
		printk("AoA Proc. Out - Phase_Roll: %d ns (0x%x)\n",
		       PhaseRollInt, PhaseRoll);
		printk("AoA Proc. Out - FirstPathDelay: %d ns (0x%x)\n",
		       FirstPathDelayInt, FirstPathDelay);
		//printk("AoA Proc. Out - FFTSizePointer: 0x%x\n", CSI_Processing_Results_Array[2]);
		printk("AoA Proc. Out - (packetType/sigBw/nTx/nRx/rxDevBw): %d|%d|%d|%d|%d\n", (CSI_Processing_Results_Array[2]) & 0x7, (CSI_Processing_Results_Array[2] >> 6) & 0x3, (CSI_Processing_Results_Array[2] >> 9) & 0x7, (CSI_Processing_Results_Array[2] >> 12) & 0x7, (CSI_Processing_Results_Array[2] >> 15) & 0x3);
		printk("AoA Proc. Out - DiffTSF: 0x%x\n",
		       CSI_Processing_Results_Array[3]);
		printk("AoA Proc. Out - Max weight 1: %d %% (0x%x)\n",
		       weight1Int, weight1);
		printk("AoA Proc. Out - Max weight 2: %d %% (0x%x)\n",
		       weight2Int, weight2);
		printk("AoA Proc. Out - Angle: %d deg. (0x%x)\n", AngleInt,
		       Angle);
		printk("AoA Proc. Out - Delay: 0x%x\n",
		       CSI_Processing_Results_Array[7]);
#endif

		if (Angle >= 0) {
			sign = '+';
		} else {
			sign = '-';
			Angle = -Angle;
		}
		AngleInt = (Angle * 360) / (1 << 12);
		AngleDec = (Angle * 3600) / (1 << 12) - AngleInt * 10;

		wl_util_lock(wlpptr->netDev);
		// Convert CSI RSSI
		rssi_value[0] = (wlpptr->smacStatusAddr->CSI_RSSI_AB >> 0) & 0xFFF;	// A
		rssi_value[1] = (wlpptr->smacStatusAddr->CSI_RSSI_AB >> 12) & 0xFFF;	// B
		rssi_value[2] = (wlpptr->smacStatusAddr->CSI_RSSI_CD >> 0) & 0xFFF;	// C
		rssi_value[3] = (wlpptr->smacStatusAddr->CSI_RSSI_CD >> 12) & 0xFFF;	// D
		rssi_value[4] = (wlpptr->smacStatusAddr->CSI_RSSI_EF >> 0) & 0xFFF;	// E
		rssi_value[5] = (wlpptr->smacStatusAddr->CSI_RSSI_EF >> 12) & 0xFFF;	// F
		rssi_value[6] = (wlpptr->smacStatusAddr->CSI_RSSI_GH >> 0) & 0xFFF;	// G
		rssi_value[7] = (wlpptr->smacStatusAddr->CSI_RSSI_GH >> 12) & 0xFFF;	// H

		for (rssi_iter = 0; rssi_iter < MAX_RF_ANT_NUM; rssi_iter++) {
			if (rssi_value[rssi_iter] >= 2048) {
				rssi_value_signed[rssi_iter] =
					-((4096 - rssi_value[rssi_iter]) >> 4);
			} else {
				rssi_value_signed[rssi_iter] =
					rssi_value[rssi_iter] >> 4;
			}
		}

		// Pass back string to buffer for printing out to file
		sprintf(string_buff,
			"\nAngle: %c%d.%d degrees\nDelay: %d ns\nLOS_Factor1: 0.%02d\nLOS_Factor2: 0.%02d\nPkt_MAC_Addr: %02x:%02x:%02x:%02x:%02x:%02x\nPkt_Type: 0x%x\nPkt_SubType: 0x%x\nRSSI_A: %d\nRSSI_B: %d\nRSSI_C: %d\nRSSI_D: %d\nRSSI_E: %d\nRSSI_F: %d\nRSSI_G: %d\nRSSI_H: %d\n",
			sign, AngleInt, AngleDec, FirstPathDelayInt, weight1Int,
			weight2Int, wlpptr->smacStatusAddr->CSI_Pkt_MAC_Addr[0],
			wlpptr->smacStatusAddr->CSI_Pkt_MAC_Addr[1],
			wlpptr->smacStatusAddr->CSI_Pkt_MAC_Addr[2],
			wlpptr->smacStatusAddr->CSI_Pkt_MAC_Addr[3],
			wlpptr->smacStatusAddr->CSI_Pkt_MAC_Addr[4],
			wlpptr->smacStatusAddr->CSI_Pkt_MAC_Addr[5],
			wlpptr->smacStatusAddr->CSI_Pkt_Type,
			wlpptr->smacStatusAddr->CSI_Pkt_SubType,
			rssi_value_signed[0], rssi_value_signed[1],
			rssi_value_signed[2], rssi_value_signed[3],
			rssi_value_signed[4], rssi_value_signed[5],
			rssi_value_signed[6], rssi_value_signed[7]);
		
		wl_util_unlock(wlpptr->netDev);
		filp_AoA =
			filp_open("/tmp/AoA_Output.txt",
				  O_RDWR | O_CREAT | O_TRUNC, 0);
		if (!IS_ERR(filp_AoA)) {
			__kernel_write(filp_AoA, string_buff,
				       strlen(string_buff), &filp_AoA->f_pos);
			filp_close(filp_AoA, current->files);
			printk("AoA data written to /tmp/AoA_Output.txt\n");
		} else {
			printk("Error opening /tmp/AoA_Output.txt! \n");
		}

		{
#define MFG_BFINFO_LEN_MASK        0X3FFF	// Bits [13:0]
#define MFG_CSI_LEN_MASK           0XFFFF	// Bits [16:0]
#define MFG_TDDE_LEN_MASK          0XFFFF	// Bits [16:0]
			struct net_device *netdev =
				(struct net_device *)vmacSta_p->dev;
			struct wlprivate *wlpptr =
				NETDEV_PRIV_P(struct wlprivate, netdev);
			UINT32 bfinfo_length = 0, csi_length = 0, length =
				0, offset = 0;
			UINT32 tdde_length = 0, lltf_length = 0;
			UINT32 *temp;
			UINT32 SizeInDw = 0;

			struct file *filp_AoA_CSI_Data = NULL;

			temp = (UINT32 *) wlpptr->pSsuBuf;	// Use virtual address instead of physical address
			bfinfo_length = temp[0] & MFG_BFINFO_LEN_MASK;
			csi_length =
				temp[bfinfo_length +
				     lltf_length] & MFG_CSI_LEN_MASK;
#ifdef WLS_TDDE_EN
			tdde_length =
				temp[bfinfo_length + lltf_length +
				     csi_length] & MFG_TDDE_LEN_MASK;
#endif
			length = bfinfo_length + lltf_length + csi_length +
				tdde_length;
			//offset = bfinfo_length + 1; // DWORDS, 1 is to don't dump the DWORD for the CSI length
			SizeInDw = (length - offset);

			filp_AoA_CSI_Data =
				filp_open("/tmp/AoA_Output.bin",
					  O_RDWR | O_CREAT | O_TRUNC, 0);
			if (!IS_ERR(filp_AoA_CSI_Data)) {
				__kernel_write(filp_AoA_CSI_Data, (UINT8 *) wlpptr->pSsuBuf, (SizeInDw * 4), &filp_AoA_CSI_Data->f_pos);	// Use virtual address instead of physical address
				filp_close(filp_AoA_CSI_Data, current->files);

				printk("AoA CSI Data saved to /tmp/AoA_Output.bin!\n");
			} else {
				printk("Error opening /tmp/AoA_Output.bin!\n");
			}
		}
	}
	return;
}
#endif

UINT32
wlEventHandler(vmacApInfo_t * vmacSta_p, void *vAddr)
{
	extern void idx_test(struct net_device *netdev, long pktcnt,
			     long pkt_size);
	host_evt_msg_t *pEvent = (host_evt_msg_t *) vAddr;
	struct net_device *netdev = (struct net_device *)vmacSta_p->dev;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpdptr = wlpptr->wlpd_p;

	pEvent->hdr.id = ENDIAN_SWAP16(pEvent->hdr.id);
	pEvent->hdr.len = ENDIAN_SWAP16(pEvent->hdr.len);
	pEvent->hdr.seqNum = ENDIAN_SWAP16(pEvent->hdr.seqNum);
	pEvent->hdr.status = ENDIAN_SWAP16(pEvent->hdr.status);

	//printk("%s: id=%d len=%d seq=%d status=%d\n", __func__,
	//      pEvent->hdr.id, pEvent->hdr.len, pEvent->hdr.seqNum, pEvent->hdr.status);
	//mwl_hex_dump(pEvent, pEvent->hdr.len);

	switch (pEvent->hdr.id) {
	case HOST_EVT_STA_DEL:
		FreeStnId_newdp(vmacSta_p, pEvent->b.sta_del.staIdx);
		break;
	case HOST_EVT_PRINTF:
		printk("FW Message: %s\n", pEvent->b.print_f.message);
		break;
	case HOST_EVT_IDX_TEST:
		idx_test(vmacSta_p->dev, pEvent->b.idx_test.packet_count,
			 pEvent->b.idx_test.packet_size);
		printk("FW Initiated idx_test\n");
		break;
	case HOST_EVT_EXCEPTION:
		{
			u32 is_sfw;
			wl_util_lock(netdev);
			is_sfw = (wlpptr->smacStatusAddr->smacSts[7] == 0x07390000);
			wlpptr->wlpd_p->smon.exceptionEvt_rcvd++;
			printk("%s %s exception event",
			       wlpptr->wlpd_p->rootdev->name,
			       is_sfw ? "SFW" : "PFW");

			if (is_sfw) {
				u8 *ptr =
					(u8 *) wlpptr->smacStatusAddr->smacSts;
				u8 cpuid = 0;
				u64 cpu_ind =
					(u64) wlpptr->smacStatusAddr->
					smacSts[11];
				cpu_ind =
					(cpu_ind << 32) | wlpptr->
					smacStatusAddr->smacSts[10];

				do {
					if (cpu_ind & 0xff)
						break;
					else
						cpu_ind = cpu_ind >> 8;
				} while (cpuid++ < 7 /* max number of CM3 */ );

				printk(" from CPU_%d (%#02x)\n", cpuid,
				       (u8) (cpu_ind & 0xff));
				print_hex_dump(KERN_INFO, "",
					       DUMP_PREFIX_OFFSET, 32, 4,
					       (void *)ptr, 64, false);
				
			} else
				printk("...\n");
			
			wl_util_unlock(netdev);
			if (wlpdptr->wlmon_task)
				wake_up_process(wlpdptr->wlmon_task);
		}
		break;
	case HOST_EVT_PARITY_ERR:
		{
			wlpptr->wlpd_p->smon.cpu_parity_check_status =
				pEvent->b.parity_err.cpu_parity_check_status;
			wlpptr->wlpd_p->smon.parityErrEvt_rcvd++;
		}
		break;
	case HOST_EVT_OFFCHAN:
		//printk("HOST_EVT_OFFCHAN, next_state = %d\n", pEvent->b.offchan.next_state);
		offChanDoneHdlr((struct net_device *)vmacSta_p->dev,
				(offchan_status) (pEvent->b.offchan.
						  next_state));
		break;
#ifdef PRD_CSI_DMA
	case HOST_EVT_PRD_CSI_DMA_DONE:
		{
			memcpy(&wlpptr->prdcsi_data, &pEvent->b.prdcsi,
			       sizeof(evt_prdcsi_t));
			schedule_work(&wlpptr->wlpd_p->prd_csi_dma_done_wq);
			//printk("HOST_EVT_PRD_CSI_DMA_DONE\n");
		}
		break;
#endif
	case HOST_EVT_PROBE_RSP_IES:
		{
			extern void
				macMgmtMlme_UpdateProbeRspCsaIes(vmacApInfo_t *
								 vmacSta_p,
								 UINT8 * iep,
								 UINT16 length);
			struct wlprivate *wlpptr1;
			evt_probe_rsp_t *pData = &pEvent->b.probe_rsp_ies;
			int i;
			/* copy to buffer */
			for (i = 0; i <= bss_num; i++) {
				if (wlpptr->vdev[i]->flags & IFF_RUNNING) {
					wlpptr1 =
						NETDEV_PRIV_P(struct wlprivate,
							      wlpptr->vdev[i]);
					macMgmtMlme_UpdateProbeRspCsaIes
						(wlpptr1->vmacSta_p,
						 (UINT8 *) pData->ies,
						 pData->length);
				}
			}
		}
		break;
#ifdef WLS_FTM_SUPPORT
	case HOST_EVT_FTM_TX_DONE:
		{
			struct WLS_FTM_CONFIG_st *wls_ftm_config =
				wlpdptr->wls_ftm_config;
			extern void wlsFTM_HandleTxDone(struct net_device
							*netdev,
							struct sk_buff *skb);

			if (wls_ftm_config->FTM_response_frame) {
				skb_pull(wls_ftm_config->FTM_response_frame,
					 sizeof(IEEEtypes_MgmtHdr2_t));
				wlsFTM_HandleTxDone(netdev,
						    wls_ftm_config->
						    FTM_response_frame);
				wl_free_skb(wls_ftm_config->FTM_response_frame);
			}
		}
		break;
#endif
	case HOST_EVT_BCNTX_COMPLETE:
		{
			UINT32 bssBitmap = (UINT32) pEvent->b.bssBitmap;
			struct wlprivate *wlpptr1 = NULL;
			int i;

			//printk("==> bcn tx done(%s), bssBitmap=%d bss_num=%d\n", netdev->name, bssBitmap, bss_num);

			for (i = 0; i < bss_num; i++) {
				if ((wlpptr->vdev[i]->flags & IFF_RUNNING) &&
				    (bssBitmap & (1 << i))) {
					wlpptr1 =
						NETDEV_PRIV_P(struct wlprivate,
							      wlpptr->vdev[i]);
					if (wlpptr1 && wlpptr1->vmacSta_p &&
					    (wlpptr1->vmacSta_p->MgmtTxWaitQ.
					     cnt > 0))
						tasklet_schedule(&wlpptr1->
								 vmacSta_p->
								 MgmtTxWaitTask);
				}
			}
		}
		break;
	default:
		break;
	}

	return 0;
}
