/** @file rx.c
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2019 NXP
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

#include "radio.h"
#include "ipc.h"
#include "ipc_msg.h"

#define roundup_MRVL(x, y)   ((((x) + ((y) - 1)) / (y)) * (y))

static inline wlrxdesc_t *
wlSpiltAMSDU(struct radio *radio, struct wldesc_data *wlqm, wlrxdesc_t * cfh_ul)
{
	wlrxdesc_t *cfh_ul_amsdu = NULL;
	int i, msdu_no = cfh_ul->hdrFormat;
	ca_uint32_t msdu_start_offset = 0;
	ca_uint8_t *amsdu_start = NULL, *msdu_addr = NULL;
	ca_uint16_t length;

	if (!msdu_no)
		return NULL;
	amsdu_start = (ca_uint8_t *) PHYS_TO_VIRT(cfh_ul->hdr.lo_dword_addr);
	msdu_addr = amsdu_start + msdu_start_offset;

#ifdef LINUX_PE_SIM
	dma_unmap_single(radio->dev, cfh_ul->hdr.lo_dword_addr,
			 wlqm->rq.bm.buf_size, DMA_FROM_DEVICE);
#endif

	cfh_ul_amsdu = (wlrxdesc_t *) MALLOC(msdu_no * sizeof(wlrxdesc_t));

	if (!cfh_ul_amsdu) {
		printf("%s(%d): fail to alloc memory\n", __func__, radio->rid);
		return NULL;
	}

	for (i = 0; i < msdu_no; i++) {
		memcpy((ca_uint8_t *) & cfh_ul_amsdu[i], (ca_uint8_t *) cfh_ul,
		       sizeof(wlrxdesc_t));
		if (!i) {	/* first msdu */
			cfh_ul_amsdu[i].fpkt = 1;
			cfh_ul_amsdu[i].lpkt = 0;
			cfh_ul_amsdu[i].hdr.lo_dword_addr =
				cfh_ul->hdr.lo_dword_addr;
		} else {
			cfh_ul_amsdu[i].fpkt = 0;
			cfh_ul_amsdu[i].lpkt = 0;
			cfh_ul_amsdu[i].hdr.lo_dword_addr =
				(ca_uint32_t) VIRT_TO_PHYS(msdu_addr);
		}

		if (i == (msdu_no - 1))	/* last msdu */
			cfh_ul_amsdu[i].lpkt = 1;
		length = (ca_uint16_t) msdu_addr[12];
		length = ((length << 8) | (ca_uint16_t) msdu_addr[13]);

		if (length > 1508 || length < (LLC_HDR_LEN + IP_HDR_LEN) ||
		    *((ca_uint16_t *) & msdu_addr[14]) != 0xaaaa) {
			MFREE(cfh_ul_amsdu);
			return NULL;
		}

		cfh_ul_amsdu[i].hdr.length = length;

		length = roundup_MRVL((length + ETH_HLEN), 4);

		msdu_addr = (msdu_addr + length);
	}

	return cfh_ul_amsdu;
}

#ifdef CORTINA_TUNE_HW_CPY_RX
static inline void
wlTriggerAsyncCopyRxData(wlrxdesc_t * cfh_ul)
{
	rx_buff_now = (ca_uint8_t *) FAST_MEM_WIFI_RX_BUFFER0;
	rx_next_pkt = (ca_uint8_t *) cfh_ul[0].hdr.lo_dword_addr;
	rx_buff_next = (ca_uint8_t *) FAST_MEM_WIFI_RX_BUFFER1;
	ca_dma_async_copy(HW_DMA_COPY_WIFI_RX_DATA,
			  (ca_uint8_t *) FAST_MEM_WIFI_RX_BUFFER1_PA,
			  (ca_uint8_t *) rx_next_pkt, TX_DATA_BUFFER_SIZE);
}
#endif

static inline wlrxdesc_t *
wlProcessMsdu(struct radio *radio, wlrxdesc_t * cfh_ul, ca_uint32_t * msdu_no)
{
	wlrxdesc_t *cfh_ul_amsdu = &radio->cfhul_amsdu.rxdesc[0];
	ca_uint32_t *pidx = &radio->cfhul_amsdu.idx;
	wlrxdesc_t *ret = NULL;
	ca_uint8_t FLpkt = 0;

	FLpkt = cfh_ul->fpkt;
	FLpkt = (FLpkt << 1) | cfh_ul->lpkt;

	*msdu_no = 0;
	switch (FLpkt) {
	case 0:		/* middle subframe */
		if (*pidx)	/* middle frames arrives. put in acc pool */
#ifdef CORTINA_TUNE_HW_CPY_RX
		{
			(*pidx)++;
		}
#else
			memcpy((void *)&cfh_ul_amsdu[(*pidx)++], (void *)cfh_ul,
			       sizeof(wlrxdesc_t));
#endif
		else		/* error handling. individual middle come along. */
			radio->except_cnt.cfhul_flpkt_lost[0]++;
		break;
	case 1:		/* last subframe */
		if (*pidx) {
			/* 01 (last) arrives. all subframes of a amsdu are
			 * received. 
			 */
#ifdef CORTINA_TUNE_HW_CPY_RX
			(*pidx)++;
#else
			memcpy((void *)&cfh_ul_amsdu[(*pidx)++], (void *)cfh_ul,
			       sizeof(wlrxdesc_t));
#endif
			*msdu_no = *pidx;
			*pidx = 0;	/* init for next AMSDU. */
			ret = &cfh_ul_amsdu[0];
		} else {
			/* 01 arrives but accumulating pool is empty. 10 might
			 * be lost. 
			 */
			/* error handling */
			radio->except_cnt.cfhul_flpkt_lost[0]++;
			radio->except_cnt.cfhul_flpkt_lost[1]++;
		}
		break;
	case 2:		/* first subframe */
		if (!*pidx) {
			/* 10(first) received, put in accu pool */
#ifdef CORTINA_TUNE_HW_CPY_RX
			wlTriggerAsyncCopyRxData(cfh_ul_amsdu);
			(*pidx)++;
#else
			memcpy((void *)&cfh_ul_amsdu[(*pidx)++], (void *)cfh_ul,
			       sizeof(wlrxdesc_t));
#endif
		} else {
			/* 10 arrives.  01 is lost in accumulating pool */
			/* error hanlding */
			radio->except_cnt.cfhul_flpkt_lost[2]++;
			*pidx = 0;	/* drop previous accumulationg */
			/* restart accu from this subframe. */
#ifdef CORTINA_TUNE_HW_CPY_RX
			(*pidx)++;
#else
			memcpy((void *)&cfh_ul_amsdu[(*pidx)++], (void *)cfh_ul,
			       sizeof(wlrxdesc_t));
#endif
		}
		break;
	case 3:		/* single-MSDU frame */
		if (*pidx) {
			/* single-MSDU arrives, but 01(last) subframe is
			 * lost in accu pool 
			 */
			radio->except_cnt.cfhul_flpkt_lost[2]++;
			*pidx = 0;	/* drop previous accumulating */
		}
		*msdu_no = 1;
		ret = cfh_ul;
		break;
	}

	/* error handling in case total amsdu subframe numbers over driver
	 * rxdesc allocating size.
	 */
	if (*pidx == MAX_AMSDU_SUBFRAME) {
		/* drop the accu */
		*pidx = 0;
		/* subframes number over limit */
		radio->except_cnt.cfhul_flpkt_lost[3]++;
	}

	return ret;
}

void
wlSendPktToHost(struct radio *radio, struct pkt_hdr *pkt, bool data,
		wlrxdesc_t * cfh_ul)
{
	t2h_pkt_recv_t t2h_msg;
	ca_ipc_pkt_t ipc_pkt;

	if (pkt) {
#ifdef DBG_BM_BUF_MONITOR
		dbg_check_buf(radio->rid, pkt, __func__);
#endif
#ifdef CORTINA_TUNE
		if (data) {
			memmove(pkt->data + LLC_HDR_LEN, pkt->data,
				ETH_ALEN * 2);
			pkt->data += LLC_HDR_LEN;
			pkt->len -= LLC_HDR_LEN;
		}
#endif
		t2h_msg.radio = radio->rid;
		t2h_msg.pkt_hdr_addr =
			(ca_uint64_t) __PLATFORM_POINTER_TYPE__ pkt;
		t2h_msg.buf_phy_addr = (ca_uint32_t) VIRT_TO_PHYS(pkt->data);
		t2h_msg.buf_len = pkt->len;
		t2h_msg.is_data = data;
		if (cfh_ul)
			memcpy(&t2h_msg.rxcfg[0], cfh_ul, 32);

		ipc_pkt.session_id = SYSADPT_MSG_IPC_SESSION;
		ipc_pkt.dst_cpu_id = SYSADPT_MSG_IPC_DST_CPU;
		ipc_pkt.priority = 0;
		ipc_pkt.msg_no = WFO_IPC_T2H_PKT_RECV;
		ipc_pkt.msg_data = &t2h_msg;
		ipc_pkt.msg_size = sizeof(t2h_msg);

		if ((pkt->data_type == PKT_DATA_FROM_BM) && (pkt->qid == 10))
			radio->dbg_cnt.rel_cnt.bm10_to_host++;

		ca_ipc_msg_async_send(&ipc_pkt);
	}
}

static inline ca_uint8_t
wl_getnss_frm_rxinfo(struct bbrx_rx_info *prxinfo)
{
	ca_uint8_t nss = 1, val;
	VHT_SIG_A1 vht_siga1;
	HE_SIG_A1 he_siga1;
	HE_SIG_A2 he_siga2;
	HE_SIG_B_USR hesigb;

	switch (prxinfo->rx_mode) {
	case BBRX_RM_A_G:	/* Basic rate */
		break;
	case BBRX_RM_AC:	/* AC mode */
		vht_siga1.vht_sig_a1 = prxinfo->htsig1_vhtsiga1_hesiga1;
		nss = vht_siga1.su.nsts + 1;
		break;
	case BBRX_RM_HE_SU:	/* he mode */
		he_siga1.he_sig_a1 =
			(prxinfo->hesiga1 << 24) | prxinfo->
			htsig1_vhtsiga1_hesiga1;
		he_siga2.he_sig_a2 = prxinfo->htsig2_vhtsiga2_hesiga2;
		if (he_siga2.su.doppler == 0)
			nss = he_siga1.su.nts_mid_pri + 1;
		else		/* doppler is 1 bit => it's "1" */
			nss = (he_siga1.su.nts_mid_pri & 0x3) + 1;
		break;
	case BBRX_RM_HE_EXT_SU:
		he_siga1.he_sig_a1 =
			(prxinfo->hesiga1 << 24) | prxinfo->
			htsig1_vhtsiga1_hesiga1;
		he_siga2.he_sig_a2 = prxinfo->htsig2_vhtsiga2_hesiga2;
		val = he_siga1.su.nts_mid_pri & 0x3;

		if (he_siga2.su.doppler == 0) {
			switch (he_siga1.su.nts_mid_pri) {
			case 0:
				if (he_siga2.su.stbc == 0)
					nss = 1;
				break;
			case 1:
				if (he_siga2.su.stbc == 1)
					nss = 2;
				break;
			default:
				break;
			}
		} else {	/* doppler is 1 bit => it's "1" */
			/* Valid combination */
			switch (val) {
			case 0:
				if (he_siga2.su.stbc == 0)
					nss = 1;
				break;
			case 1:
				if (he_siga2.su.stbc == 1)
					nss = 2;
				break;
			default:
				break;
			}
		}
		break;
	case BBRX_RM_HE_MU:	/* he mode */
		hesigb.he_sig_b = (prxinfo->hesigb >> 9) & 0x1fffff;
		nss = hesigb.nsts;
		break;
	default:
		break;
	}

	return nss;
}

static inline void
wlrxinfo_2_rxhisto(struct drv_rate_hist *pdrv_rx_hist,
		   struct bbrx_rx_info *prxinfo)
{
	ca_uint8_t nss, bw, gi, mcs;
	HT_SIG1 ht_sig1;
	HT_SIG2 ht_sig2;
	VHT_SIG_A1 vht_siga1;
	VHT_SIG_A2 vht_siga2;
	HE_SIG_A1 he_siga1;
	HE_SIG_A2 he_siga2;

	switch (prxinfo->rx_mode) {
	case BBRX_RM_A_G:
	case BBRX_RM_B:
	case BBRX_RM_GREEN_FIELD:
		/* Legacy rate */
		break;
	case BBRX_RM_N:
		ht_sig1.ht_sig1 = prxinfo->htsig1_vhtsiga1_hesiga1 & 0xffffff;
		ht_sig2.ht_sig2 = prxinfo->htsig2_vhtsiga2_hesiga2 & 0xffffff;
		bw = ht_sig1.bw;
		gi = ht_sig2.sgi;
		mcs = ht_sig1.mcs;
		pdrv_rx_hist->ht_rates[bw][gi][mcs]++;
		break;
	case BBRX_RM_AC:
		vht_siga1.vht_sig_a1 =
			prxinfo->htsig1_vhtsiga1_hesiga1 & 0xffffff;
		vht_siga2.vht_sig_a2 =
			prxinfo->htsig2_vhtsiga2_hesiga2 & 0xffffff;
		nss = wl_getnss_frm_rxinfo(prxinfo);
		bw = vht_siga1.su.bw;
		gi = vht_siga2.su.short_gi;
		mcs = vht_siga2.su.mcs;
		pdrv_rx_hist->vht_rates[nss - 1][bw][gi][mcs]++;
		break;
	case BBRX_RM_HE_SU:
	case BBRX_RM_HE_EXT_SU:
	case BBRX_RM_HE_MU:
	case BBRX_RM_HE_TRIG_BASED:
		/* HE rate */
		he_siga1.he_sig_a1 =
			(prxinfo->hesiga1 << 24) | prxinfo->
			htsig1_vhtsiga1_hesiga1;
		he_siga2.he_sig_a2 = prxinfo->htsig2_vhtsiga2_hesiga2;
		nss = wl_getnss_frm_rxinfo(prxinfo);
		switch (prxinfo->rx_mode) {
		case BBRX_RM_HE_SU:
		case BBRX_RM_HE_EXT_SU:
			bw = he_siga1.su.bandwidth % QS_NUM_SUPPORTED_11AX_BW;
			gi = he_siga1.su.gi_ltf % QS_NUM_SUPPORTED_11AX_GILTF;
			mcs = he_siga1.su.mcs % QS_NUM_SUPPORTED_11AX_MCS;
			break;
		case BBRX_RM_HE_MU:
			bw = he_siga1.mu.bandwidth % QS_NUM_SUPPORTED_11AX_BW;
			gi = he_siga1.mu.gi_ltf % QS_NUM_SUPPORTED_11AX_GILTF;
			mcs = he_siga1.mu.mcs % QS_NUM_SUPPORTED_11AX_MCS;
			break;
		case BBRX_RM_HE_TRIG_BASED:
		default:
			return;
		}
		pdrv_rx_hist->he_rates[nss - 1][bw][gi][mcs]++;
		break;
	default:
		break;
	}

}

#define IEEEtypes_MAX_DATA_RATES_G	14
#define NDBPS_FACTOR	4

const ca_uint32_t LEGACY_PHY_RATE[IEEEtypes_MAX_DATA_RATES_G] = {
	// ======== HR/DDS phy ========
	1000,			// Rate ID 0
	2000,			// Rate ID 1
	5500,			// Rate ID 2
	11000,			// Rate ID 3
	22000,			// Rate ID 4
	// ======== OFDM rate_id ========
	6000,			// Rate ID 5
	9000,			// Rate ID 6
	12000,			// Rate ID 7
	18000,			// Rate ID 8
	24000,			// Rate ID 9
	36000,			// Rate ID 10
	48000,			// Rate ID 11
	54000,			// Rate ID 12
	72000,			// Rate ID 13
};

#define RTBL_MAX_MCS_INDEX    33
const ca_uint32_t HT_PHY_RATE[RTBL_MAX_MCS_INDEX][2][2] = {
	{{6500, 7222}, {13500, 15000}},	// MCS 0
	{{13000, 14444}, {27000, 30000}},	// MCS 1
	{{19500, 21700}, {40500, 45000}},	// MCS 2
	{{26000, 28888}, {54000, 60000}},	// MCS 3
	{{39000, 43333}, {81000, 90000}},	// MCS 4
	{{52000, 57777}, {108000, 120000}},	// MCS 5
	{{58500, 65000}, {121500, 135000}},	// MCS 6
	{{65000, 72222}, {135000, 150000}},	// MCS 7
	{{13000, 14444}, {27000, 30000}},	// MCS 8
	{{26000, 28888}, {54000, 60000}},	// MCS 9
	{{39000, 43333}, {81000, 90000}},	// MCS 10
	{{52000, 57777}, {108000, 120000}},	// MCS 11
	{{78000, 86700}, {162000, 180000}},	// MCS 12
	{{104000, 115600}, {216000, 240000}},	// MCS 13
	{{117000, 130000}, {243000, 270000}},	// MCS 14
	{{130000, 144400}, {270000, 300000}},	// MCS 15
	{{19500, 21700}, {40500, 45000}},	// MCS 16
	{{39000, 43333}, {81000, 90000}},	// MCS 17
	{{58500, 65000}, {121500, 135000}},	// MCS 18
	{{78000, 86700}, {162000, 180000}},	// MCS 19
	{{117000, 130000}, {243000, 270000}},	// MCS 20
	{{156000, 173000}, {324000, 360000}},	// MCS 21
	{{175000, 195000}, {364500, 405000}},	// MCS 22
	{{195000, 216700}, {405000, 450000}},	// MCS 23
	{{26000, 28888}, {54000, 60000}},	// MCS 24
	{{52000, 57777}, {108000, 120000}},	// MCS 25
	{{78000, 86700}, {162000, 180000}},	// MCS 26
	{{104000, 115600}, {216000, 240000}},	// MCS 27
	{{156000, 173000}, {324000, 360000}},	// MCS 28
	{{208000, 231000}, {432000, 480000}},	// MCS 29
	{{234000, 260000}, {486000, 540000}},	// MCS 30
	{{260000, 288888}, {540000, 600000}},	// MCS 31
	{{6500, 7222}, {13500, 15000}},	// MCS dummy, copied from mcs0
};

#define VHT_PHYRATE_BW_MAX		4
#define VHT_PHYRATE_MCS_MAX		10
#define VHT_PHYRATE_NSS_MAX		4
#define VHT_PHYRATE_GI_MAX		2
//[20/40/80/160][MCS0:9][SS1:3][LGI/SGI]
const ca_uint32_t
	VHT_PHY_RATE[VHT_PHYRATE_BW_MAX][VHT_PHYRATE_MCS_MAX]
	[VHT_PHYRATE_NSS_MAX][VHT_PHYRATE_GI_MAX] = {
//20M
//        NSS1              NSS2             NSS3
//       LGI    SGI       LGI    SGI        LGI    SGI
	{{{6500, 7200}, {13000, 14400}, {19500, 21700}, {26000, 28900}},	// MCS0
	 {{13000, 14400}, {26000, 28900}, {39000, 43300}, {52000, 57800}},	// MCS1
	 {{19500, 21700}, {39000, 43300}, {58500, 65000}, {78000, 86701}},	// MCS2
	 {{26000, 28900}, {52000, 57800}, {78000, 86700}, {104000, 115601}},	// MCS3
	 {{39000, 43300}, {78000, 86700}, {117000, 130000}, {156000, 173301}},	// MCS4
	 {{52000, 57800}, {104000, 115600}, {156000, 173300}, {208000, 231100}},	// MCS5
	 {{58500, 65000}, {117000, 130000}, {175500, 195000}, {234000, 260001}},	// MCS6
	 {{65000, 72200}, {130000, 144400}, {195000, 216700}, {260000, 288901}},	// MCS7
	 {{78000, 86700}, {156000, 173300}, {234000, 260000}, {312000, 346700}},	// MCS8
	 {{0, 0}, {0, 0}, {260000, 288900}, {346700, 385200}}},	// MCS9
// 40M
//        NSS1              NSS2             NSS3
//       LGI    SGI       LGI    SGI        LGI    SGI
	{{{13500, 15000}, {27000, 30000}, {40500, 45000}, {54000, 60000}},	// MCS0
	 {{27000, 30000}, {54000, 60000}, {81000, 90000}, {108000, 120000}},	// MCS1
	 {{40500, 45000}, {81000, 90000}, {121500, 135000}, {162000, 180001}},	// MCS2
	 {{54000, 60000}, {108000, 120000}, {162000, 180000}, {216000, 240001}},	// MCS3
	 {{81000, 90000}, {162000, 180000}, {243000, 270000}, {324000, 360001}},	// MCS4
	 {{108000, 120000}, {216000, 240000}, {324000, 360000}, {432000, 480000}},	// MCS5
	 {{121500, 135000}, {243000, 270000}, {364500, 405000}, {486000, 540001}},	// MCS6
	 {{135000, 150000}, {270000, 300000}, {405000, 450000}, {540000, 600001}},	// MCS7
	 {{162000, 180000}, {324000, 360000}, {486000, 540000}, {648000, 720000}},	// MCS8
	 {{180000, 200000}, {360000, 400000}, {540000, 600000}, {720000, 800000}}},	// MCS9
// 80M
//        NSS1              NSS2             NSS3
//       LGI    SGI       LGI    SGI        LGI    SGI
	{{{29300, 32500}, {58500, 65000}, {87800, 97500}, {117000, 130000}},	// MCS0
	 {{58500, 65000}, {117000, 130000}, {175500, 195000}, {234000, 260000}},	// MCS1
	 {{87800, 97500}, {175500, 195000}, {263300, 292500}, {351000, 390001}},	// MCS2
	 {{117000, 130000}, {234000, 260000}, {351000, 390000}, {468000, 520001}},	// MCS3
	 {{175500, 195000}, {351000, 390000}, {526500, 585000}, {702000, 780001}},	// MCS4
	 {{234000, 260000}, {468000, 520000}, {702000, 780000}, {936000, 1040000}},	// MCS5
	 {{263300, 292500}, {526500, 585000}, {0, 0}, {1053000, 1170001}},	// MCS6
	 {{292500, 325000}, {585000, 650000}, {877500, 975000}, {1170000, 1300001}},	// MCS7
	 {{351000, 390000}, {702000, 780000}, {1053000, 1170000}, {1404000, 1560000}},	// MCS8
	 {{390000, 433300}, {780000, 866700}, {1170000, 1300000}, {1560000, 1733300}}},	// MCS9
// 160M
//        NSS1              NSS2             NSS3
//       LGI    SGI       LGI    SGI        LGI    SGI
	{{{58500, 65000}, {117000, 130000}, {175500, 195000}, {234000, 260000}},	// MCS0
	 {{117000, 130000}, {234000, 260000}, {351000, 390000}, {468000, 520000}},	// MCS1
	 {{175500, 195000}, {351000, 390000}, {526500, 585000}, {702000, 780000}},	// MCS2
	 {{234000, 260000}, {468000, 520000}, {702000, 780000}, {936000, 10400000}},	// MCS3
	 {{351000, 390000}, {702000, 780000}, {1053000, 1170000}, {1404000, 15600000}},	// MCS4
	 {{468000, 520000}, {936000, 1040000}, {1404000, 1560000}, {1872000, 2080000}},	// MCS5
	 {{526500, 585000}, {1053000, 1170000}, {1579500, 1755000}, {2106000, 2340000}},	// MCS6
	 {{585000, 650000}, {1170000, 1300000}, {1755000, 1950000}, {2340000, 2600000}},	// MCS7
	 {{702000, 780000}, {1404000, 1560000}, {2106000, 2340000}, {2808000, 3120000}},	// MCS8
	 {{780000, 866700}, {1560000, 1733300}, {2340000, 2600000}, {3120000, 3466700}}}	// MCS9
};

#define HE_MCS_MAX		12
#define HE_BWTYPE_MAX	4
const ca_uint32_t R10000xNbpsc[HE_MCS_MAX] =
	{ 5000, 10000, 15000, 20000, 30000, 40000, 45000, 50000, 60000, 66667,
75000, 83333 };
const ca_uint32_t R10000xNbpsc_ofdma[10] =
	{ 5000, 10000, 15000, 20000, 30000, 40000, 45000, 49999, 60000, 66664 };
const ca_uint16_t Nsd[HE_BWTYPE_MAX] = { 234, 468, 980, 1960 };
const ca_uint16_t Nsd_ofdma[3] = { 24, 48, 102 };	//up to ru size=3, Asssume 8 STAs

#define COPY_RSSI_VAL(id, d_val, s_val, rssi_comp) {\
	if (s_val->rssi_dbm_##id != 0) {\
		RssiPathVal	rssi_val;\
		rssi_val.val = s_val->rssi_dbm_##id;\
		rssi_val.ival -= rssi_comp;\
		d_val->id = rssi_val.val;\
	}\
}
static void
wl_set_rssi_info(RssiPathInfo_t * prssi_info, RxSidebandInfo_t * prx_sband_info)
{
	struct bbrx_rx_info *prx_info = (struct bbrx_rx_info *)prx_sband_info;
	int8 rssi_compensate;	// rssi compensation for TB-PPDB

	if (prx_info->rx_mode == BBRX_RM_HE_TRIG_BASED) {
		rssi_compensate = 6;
	} else {
		rssi_compensate = 0;
	}

	COPY_RSSI_VAL(a, prssi_info, prx_sband_info, rssi_compensate);
	COPY_RSSI_VAL(b, prssi_info, prx_sband_info, rssi_compensate);
	COPY_RSSI_VAL(c, prssi_info, prx_sband_info, rssi_compensate);
	COPY_RSSI_VAL(d, prssi_info, prx_sband_info, rssi_compensate);
	COPY_RSSI_VAL(e, prssi_info, prx_sband_info, rssi_compensate);
	COPY_RSSI_VAL(f, prssi_info, prx_sband_info, rssi_compensate);
	COPY_RSSI_VAL(g, prssi_info, prx_sband_info, rssi_compensate);
	COPY_RSSI_VAL(h, prssi_info, prx_sband_info, rssi_compensate);

	return;
}

static void
wl_set_nf_info(NfPathInfo_t * pnf_info, RxSidebandInfo_t * prx_sband_info)
{
	pnf_info->a = prx_sband_info->nf_dbm_a;
	pnf_info->b = prx_sband_info->nf_dbm_b;
	pnf_info->c = prx_sband_info->nf_dbm_c;
	pnf_info->d = prx_sband_info->nf_dbm_d;
	pnf_info->e = prx_sband_info->nf_dbm_e;
	pnf_info->f = prx_sband_info->nf_dbm_f;
	pnf_info->g = prx_sband_info->nf_dbm_g;
	pnf_info->h = prx_sband_info->nf_dbm_h;
	return;
}

static void
wlrxinfo_sync_rxinfoaux_b(struct rx_info_aux *prx_info_aux,
			  struct bbrx_rx_info *prxinfo)
{
	struct dbRateInfo *prate_info = &prx_info_aux->rate_info;
	// ================================================================
	// Sync the rx_info_aux_t->rate_info
	//
	memset(prate_info, 0, sizeof(struct dbRateInfo));
	switch (prxinfo->rx_sig) {
	case 10:		// 1 Mbp
		prate_info->RateIDMCS = rateid_b_1m;
		break;
	case 20:		// 2 Mb
		prate_info->RateIDMCS = rateid_b_2m;
		break;
	case 55:		// 5.5 Mb
		prate_info->RateIDMCS = rateid_b_5p5m;
		break;
	case 110:		// 11 Mb
		prate_info->RateIDMCS = rateid_b_11m;
		break;
	default:
		break;
	}
	prx_info_aux->nss = 1;
	return;
}

static void
wlrxinfo_sync_rxinfoaux_a_g(struct rx_info_aux *prx_info_aux,
			    struct bbrx_rx_info *prxinfo)
{
	OFDM_SIG *pofdm_sig = &prx_info_aux->ofdm_sig;
	struct dbRateInfo *prate_info = &prx_info_aux->rate_info;
	/*
	   id           rate    R1-R4   val(R4:R1)
	   =======================================
	   [0]          1M
	   [1]          2M
	   [2]          5.5M
	   [3]          11M
	   [4]          22M
	   [5]          6M              1101    11 & 7 = 3
	   [6]          9M              1111    15 & 7 = 7
	   [7]          12M             0101    10 & 7 = 2
	   [8]          18M             0111    14 & 7 = 6
	   [9]          24M             1001    9  & 7 = 1
	   [10] 36M             1011    13 & 7 = 5
	   [11] 48M             0001    8  & 7 = 0
	   [12] 54M             0011    12 & 7 = 4
	   [13] 72M
	 */
	//# OFDM: 20M/10/5-CS: B(6M),F(9),A(12),E(18),9(24),D(36),8(48),C(54)
	const ca_uint8_t dTblOfdmSignal2Rate[8] =	//signal & 0x7, id of "LEGACY_PHY_RATE" array
	{
		// SMAC Format
		rateid_ag_48m,	// 10,  // [0] 48Mb
		rateid_ag_24m,	// 8,   // [1] 24Mb
		rateid_ag_12m,	// 6,   // [2] 12Mb
		rateid_ag_6m,	// 3,   // [3]  6Mb
		rateid_ag_54m,	// 11,  // [4] 54Mb
		rateid_ag_36m,	// 9,   // [5] 36Mb
		rateid_ag_18m,	// 7,   // [6] 18Mb
		rateid_ag_9m,	// 4    // [7]  9Mb
	};

	// ================================================================
	// Sync the rx_info_aux_t->ofdm_sig
	//
	pofdm_sig->ofdm_sig = prxinfo->rx_sig;

	// ================================================================
	// Sync the rx_info_aux_t->rate_info
	//
	memset(prate_info, 0, sizeof(struct dbRateInfo));
	prate_info->Format = rtinfo_pkt_legacy;
	prate_info->RateIDMCS = dTblOfdmSignal2Rate[pofdm_sig->rate & 0x7];
	prx_info_aux->nss = 1;
	return;
}

static void
wlrxinfo_sync_rxinfoaux_n(struct rx_info_aux *prx_info_aux,
			  struct bbrx_rx_info *prxinfo)
{
	HT_SIG1 *pht_sig1 = &prx_info_aux->ht_sig1;
	HT_SIG2 *pht_sig2 = &prx_info_aux->ht_sig2;
	struct dbRateInfo *prate_info = &prx_info_aux->rate_info;

	// ================================================================
	// Sync the rx_info_aux_t->ht_sigX
	//
	pht_sig1->ht_sig1 = prxinfo->htsig1_vhtsiga1_hesiga1;
	pht_sig2->ht_sig2 = prxinfo->htsig2_vhtsiga2_hesiga2 & 0xffffff;

	// ================================================================
	// Sync the rx_info_aux_t->rate_info
	//
	prate_info->Format = rtinfo_pkt_11n;
	prate_info->Stbc = pht_sig2->stbc;
	prate_info->Dcm = 0;	//resv in n mode
	prate_info->Bandwidth = pht_sig1->bw;
	prate_info->ShortGI = pht_sig2->sgi;
	prate_info->RateIDMCS = pht_sig1->mcs;
	prate_info->BF = 0;
	prate_info->AdvCoding = 0;
	prx_info_aux->nss = 1;

	return;
}

static void
wlrxinfo_sync_rxinfoaux_ac(struct rx_info_aux *prx_info_aux,
			   struct bbrx_rx_info *prxinfo, bool is_su)
{
	VHT_SIG_A1 *pvht_siga1 = &prx_info_aux->vht_siga1;
	VHT_SIG_A2 *pvht_siga2 = &prx_info_aux->vht_siga2;
	VHT_SIG_B *pvht_sigb = &prx_info_aux->vht_sigb;
	struct dbRateInfo *prate_info = &prx_info_aux->rate_info;

	// ================================================================
	// Sync the rx_info_aux_t->vht_sigX
	//
	pvht_siga1->vht_sig_a1 = prxinfo->htsig1_vhtsiga1_hesiga1;
	pvht_siga2->vht_sig_a2 = prxinfo->htsig2_vhtsiga2_hesiga2;
	pvht_sigb->vht_sig_b = prxinfo->vhtsigbSig >> 8;

	// ================================================================
	// Sync the rx_info_aux_t->rate_info
	//
	prate_info->Format = rtinfo_pkt_11ac;
	prate_info->Stbc =
		(is_su == TRUE) ? (pvht_siga1->su.stbc) : (pvht_siga1->mu.stbc);
	prate_info->Dcm = 0;	//resv in ac mode
	prate_info->Bandwidth =
		(is_su == TRUE) ? (pvht_siga1->su.bw) : (pvht_siga1->mu.bw);
	prate_info->ShortGI =
		(is_su ==
		 TRUE) ? (pvht_siga2->su.short_gi) : (pvht_siga2->mu.short_gi);
	if (is_su == TRUE) {
		prate_info->RateIDMCS = pvht_siga2->su.mcs;
	} else {
		switch (prate_info->Bandwidth) {
		case vht_bw_20:
			prate_info->RateIDMCS = pvht_sigb->mu_20.mcs;
			break;
		case vht_bw_40:
			prate_info->RateIDMCS = pvht_sigb->mu_40.mcs;
			break;
		default:
			prate_info->RateIDMCS = pvht_sigb->mu_x.mcs;
			break;
		}
	}
	prate_info->BF = pvht_siga2->beamform;
	prate_info->AdvCoding =
		(is_su ==
		 TRUE) ? (pvht_siga2->su.coding) : (pvht_siga2->mu.coding);
	//Ref: p#2543 of 802.11-2016.pdf, Fig 21-18, 21-19, Table 21-12
	prx_info_aux->nss =
		(is_su ==
		 TRUE) ? (pvht_siga1->su.nsts + 1) : (pvht_siga1->mu.mu_0_nsts);
	prate_info->RateIDMCS |= ((prx_info_aux->nss - 1) & 0x7) << 4;
	return;
}

static void
wlrxinfo_sync_rxinfoaux_he(struct rx_info_aux *prx_info_aux,
			   struct bbrx_rx_info *prxinfo, bool is_su)
{
	HE_SIG_A1 *phe_siga1 = &prx_info_aux->he_siga1;
	HE_SIG_A2 *phe_siga2 = &prx_info_aux->he_siga2;
	HE_SIG_B_USR *phesigb = &prx_info_aux->hesigb;
	struct dbRateInfo *prate_info = &prx_info_aux->rate_info;

	// ================================================================
	// Sync the rx_info_aux_t->he_sigX
	//
	phe_siga1->he_sig_a1 =
		(prxinfo->hesiga1 << 24) | prxinfo->htsig1_vhtsiga1_hesiga1;
	phe_siga2->he_sig_a2 = prxinfo->htsig2_vhtsiga2_hesiga2;
	phesigb->he_sig_b = (prxinfo->hesigb >> 9) & 0x1fffff;

	// ================================================================
	// Sync the rx_info_aux_t->rate_info
	//
	prate_info->Format = rtinfo_pkt_11ax;
	prate_info->Stbc =
		(is_su == TRUE) ? (phe_siga2->su.stbc) : (phe_siga2->mu.stbc);
	prate_info->Dcm =
		(is_su == TRUE) ? (phe_siga1->su.dcm) : (phe_siga1->mu.dcm);
	/*
	   Bandwidth:
	   SU: B19-B20 of Table 27-19 in Draft P802.11ax_D4.0.pdf
	   0: 20MHz, 1:40MHz, 2:80MHz, 3: 160 / 80+80 MHz
	   MU: B15-B17 of Table 27-20 in Draft P802.11ax_D4.0.pdf
	   0: 20MHz, 1:40MHz, 2:80MHz, 3: 160 / 80+80 MHz
	 */
	prate_info->Bandwidth =
		(is_su ==
		 TRUE) ? (phe_siga1->su.bandwidth) : (phe_siga1->mu.bandwidth);
	if (prate_info->Stbc && prate_info->Dcm) {
		prate_info->ShortGI = 3;	// 4x+0.8
	} else {
		prate_info->ShortGI =
			(is_su ==
			 TRUE) ? (phe_siga1->su.gi_ltf) : (phe_siga1->mu.
							   gi_ltf);
	}
	prate_info->RateIDMCS =
		(is_su == TRUE) ? (phe_siga1->su.mcs) : (phe_siga1->mu.mcs);
	prate_info->BF =
		(is_su == TRUE) ? (phe_siga2->su.txbf) : (phesigb->tx_beamform);
	prate_info->AdvCoding =
		(is_su == TRUE) ? (phe_siga2->su.coding) : (phesigb->coding);
	if (is_su == TRUE) {
		if (phe_siga2->su.doppler == 0) {
			prx_info_aux->nss = phe_siga1->su.nts_mid_pri + 1;
		} else {	//doppler is 1 bit => it's "1"
			prx_info_aux->nss =
				(phe_siga1->su.nts_mid_pri & 0x3) + 1;
		}
	} else {		// MU
		prx_info_aux->nss = phesigb->nsts + 1;
	}
	prate_info->RateIDMCS |= ((prx_info_aux->nss - 1) & 0x7) << 4;
	return;
}

static void
wl_rx_info_aux_sync(struct rx_info_aux *prx_info_aux,
		    struct bbrx_rx_info *prxinfo)
{
	if (prx_info_aux->rxTs == prxinfo->rxTs) {
		// Already updated...
		return;
	}
	memset(prx_info_aux, 0, sizeof(struct rx_info_aux));
	// Sync rx_info_aux_t data from rx_info_ppdu_t
	prx_info_aux->ppdu_len = prxinfo->lenRssiNf;
	prx_info_aux->rx_mode = prxinfo->rx_mode;
	prx_info_aux->rxTs = prxinfo->rxTs;
	prx_info_aux->rxTsH = prxinfo->rxTsH;
	switch (prx_info_aux->rx_mode) {
	case BBRX_RM_B:
		wlrxinfo_sync_rxinfoaux_b(prx_info_aux, prxinfo);
		break;
	case BBRX_RM_A_G:	// ofdm
		wlrxinfo_sync_rxinfoaux_a_g(prx_info_aux, prxinfo);
		break;
	case BBRX_RM_N:	// N mode
		wlrxinfo_sync_rxinfoaux_n(prx_info_aux, prxinfo);
		break;
	case BBRX_RM_AC:	// AC mode
		wlrxinfo_sync_rxinfoaux_ac(prx_info_aux, prxinfo, TRUE);
		break;
	case BBRX_RM_HE_SU:	// he mode
	case BBRX_RM_HE_EXT_SU:
		wlrxinfo_sync_rxinfoaux_he(prx_info_aux, prxinfo, TRUE);
		break;
	case BBRX_RM_HE_MU:	// he mode
	case BBRX_RM_HE_TRIG_BASED:	// he mode
		wlrxinfo_sync_rxinfoaux_he(prx_info_aux, prxinfo, FALSE);
		break;
	default:		// Not supported mode
		break;
	}
	prx_info_aux->rate_info.AntSelect =
		(~(0xff << prx_info_aux->nss)) & 0xff;

	return;
}

static ca_uint32_t
get_HT_preamble(int mcs)
{
	if (mcs < 8)
		return 36;
	if (mcs < 16)
		return 40;
	if (mcs < 32)
		return 48;
	return 0;
}

static ca_uint32_t
get_VHT_preamble(int nss)
{
	if (nss == 1)
		return 40;
	if (nss == 2)
		return 44;
	if ((nss == 3) || (nss == 4))
		return 52;
	if ((nss == 5) || (nss == 6))
		return 60;
	if ((nss == 7) || (nss == 8))
		return 68;
	return 0;
}

static ca_uint32_t
get_HE_preamble_10x(ca_uint16_t nss_1, int gi, int ofdma)
{
	// gi_ltf:
	//              3 => ltf_type=4, gi=3.2
	//              2 => ltf_type=2, gi=1.6
	// su: 8+8+4+4+8+4+ Nltf*(3.2*LTF_type+ GI)
	const ca_uint32_t preamble32us[8] =
		{ 520, 680, 1000, 1000, 1320, 1320, 1640, 1640 };
	const ca_uint32_t preamble16us[8] =
		{ 440, 520, 600, 680, 760, 840, 920, 1000 };
	// mu: 8+8+4+4+8+ 4*Nsigb + 4 + Nltf*(3.2*LTF_type + GI)
	const ca_uint32_t preambe32usofdma[8] =
		{ 920, 1080, 1400, 1400, 1720, 1720, 2040, 2040 };
	const ca_uint32_t preambe16usofdma[8] =
		{ 840, 920, 1080, 1080, 1240, 1240, 1400, 1400 };

	if (!ofdma) {
		if (gi == 3) {
			return preamble32us[nss_1 & 0x07];
		} else {
			return preamble16us[nss_1 & 0x07];
		}
	} else {
		if (gi == 3) {
			return preambe32usofdma[nss_1 & 0x07];
		} else {
			return preambe16usofdma[nss_1 & 0x07];
		}
	}
}

static ca_uint32_t
wl_airtime_calc(struct rxppdu_airtime *prxppdu_airtm, ca_uint32_t pktlen)
{
	struct rx_info_aux *prx_info_aux = &prxppdu_airtm->rx_info_aux;
	ca_uint16_t nss;
	ca_uint8_t mcs, rate_id;
	ca_uint8_t bw;
	ca_uint8_t gi_ltf, sgi;
	ca_uint32_t Ndbps10x;
	ca_uint32_t airtime;

	//switch (prxinfo->bbrx_info.rx_mode) {
	switch (prx_info_aux->rx_mode) {
	case BBRX_RM_B:
		rate_id = prx_info_aux->rate_info.RateIDMCS;
		Ndbps10x =
			(LEGACY_PHY_RATE
			 [(rate_id & 0xf) % IEEEtypes_MAX_DATA_RATES_G] / 100) *
			NDBPS_FACTOR;
		//maxLen = (Ndbps10x*NSYM_LEGACY - 240)/80;
		if (Ndbps10x != 0) {
			airtime = (pktlen * 80 + 240) * 4 / Ndbps10x + 20;
		} else {
			// Abnormal
			airtime = 0;
		}
		break;
	case BBRX_RM_A_G:	// ofdm
		rate_id = prx_info_aux->rate_info.RateIDMCS;
		Ndbps10x =
			(LEGACY_PHY_RATE
			 [(rate_id & 0xf) % IEEEtypes_MAX_DATA_RATES_G] / 100) *
			NDBPS_FACTOR;
		//maxLen = (Ndbps10x*NSYM_LEGACY - 240)/80;
		if (Ndbps10x != 0) {
			airtime = (pktlen * 80 + 240) * 4 / Ndbps10x + 20;
		} else {
			// Abnormal
			airtime = 0;
		}
		break;
	case BBRX_RM_N:	// N mode
		mcs = prx_info_aux->rate_info.RateIDMCS;
		bw = prx_info_aux->rate_info.Bandwidth;
		sgi = prx_info_aux->rate_info.ShortGI;
		Ndbps10x =
			(HT_PHY_RATE[mcs % RTBL_MAX_MCS_INDEX][bw & 0x1][0] /
			 100) * NDBPS_FACTOR / 10;
		//maxLen = (Ndbps10x *((txop-get_HT_preamble(hw_rate_index))*10/(gi?36:40)) - 24)/8;
		//maxLen = MIN(maxLen, 65532);
		if (Ndbps10x != 0) {
			airtime =
				(pktlen * 8 +
				 24) / Ndbps10x * ((sgi ==
						    0) ? 36 : 40) / 10 +
				get_HT_preamble(mcs);
		} else {
			// Abnormal
			airtime = 0;
		}
		break;
	case BBRX_RM_AC:	// AC mode
		nss = prx_info_aux->nss;
		//Mike: this is a bug. Main branch should fix it later.
		mcs = (prx_info_aux->rate_info.RateIDMCS & 0xF);
		bw = prx_info_aux->rate_info.Bandwidth;
		sgi = prx_info_aux->rate_info.ShortGI;
		Ndbps10x =
			(VHT_PHY_RATE[bw % VHT_PHYRATE_BW_MAX]
			 [mcs % VHT_PHYRATE_MCS_MAX][(nss - 1) %
						     VHT_PHYRATE_NSS_MAX][0] /
			 100) * NDBPS_FACTOR / 10;
		//maxLen = (Ndbps10x *((txop-get_VHT_preamble(Nss+1))*10/(gi?36:40)) - ((Ndbps10x/216+10)/10)*6- 16)/8;
		if (Ndbps10x != 0) {
			airtime =
				(pktlen * 8 + 16 +
				 ((Ndbps10x / 216 +
				   10) / 10) * 6) / Ndbps10x * ((sgi ==
								 0) ? 36 : 40) /
				10 + get_VHT_preamble(nss);
		} else {
			// Abnormal
			airtime = 0;
		}
		break;
	case BBRX_RM_HE_SU:	// he mode
	case BBRX_RM_HE_EXT_SU:
	case BBRX_RM_HE_MU:
	case BBRX_RM_HE_TRIG_BASED:
		if ((prx_info_aux->rx_mode == BBRX_RM_HE_MU) ||
		    (prx_info_aux->rx_mode == BBRX_RM_HE_TRIG_BASED)) {
			//prxppdu_airtm->dbg_mu_pktcnt ++;
		} else {
			//prxppdu_airtm->dbg_su_pktcnt ++;
		}
		nss = prx_info_aux->nss;
		//Mike: this is a bug. Main branch should fix it later.
		mcs = (prx_info_aux->rate_info.RateIDMCS & 0xF);
		bw = prx_info_aux->rate_info.Bandwidth;
		gi_ltf = prx_info_aux->rate_info.ShortGI;
		Ndbps10x =
			((nss) * R10000xNbpsc[mcs % HE_MCS_MAX] *
			 Nsd[bw % HE_BWTYPE_MAX]) / 10000;
		//Nsym = (txop-get_HE_preamble_10x(Nss, gi_,0)/10)*10/(gi==3?160:144) - (Nss)/4;
		//maxLen = (Ndbps10x * Nsym - 24)/8;
		if (Ndbps10x != 0) {
			airtime =
				((pktlen * 8 + 24) / Ndbps10x +
				 nss / 4) * (gi_ltf ==
					     3 ? 160 : 144) / 10 +
				get_HE_preamble_10x((nss - 1), gi_ltf,
						    FALSE) / 10;
		} else {
			// Abnormal
			airtime = 0;
		}
		break;
	default:		// Not supported mode
		airtime = 0;
		break;
	}
	/*
	   Information for debugging. Can be removed later
	 */
	prxppdu_airtm->dbg_nss = nss;
	prxppdu_airtm->dbg_mcs = mcs;
	prxppdu_airtm->dbg_bw = bw;
	prxppdu_airtm->dbg_gi_ltf = gi_ltf;
	//prxppdu_airtm->dbg_sum_pktlen = pktlen;
	prxppdu_airtm->dbg_Ndbps10x = Ndbps10x;

	return airtime;
}

void static
wl_proc_rx_airtime(struct sta_info *StaInfo_p, wlrxdesc_t * pCurCfhul,
		   struct pkt_hdr *pRxSkBuff, struct rx_info_aux *prx_info_aux)
{
	IEEEtypes_FrameCtl_t *frame_ctlp =
		(IEEEtypes_FrameCtl_t *) & pCurCfhul->frame_ctrl;
	struct rxppdu_airtime *prxppdu_airtm;

	if (StaInfo_p == NULL) {
		// rx_airtime is per StaInfo 
		return;
	}
	if (!((frame_ctlp->FromDs == 0) && (frame_ctlp->ToDs == 1))) {
		// not ul pkt from a STA
		return;
	}
	prxppdu_airtm = &StaInfo_p->rxppdu_airtime;
	if (prxppdu_airtm->rx_info_aux.rxTs != pCurCfhul->hdr.timestamp) {
		// New rx ppdu arrives
		//      - Calculate the airtime of the saved ppdu
		if (prxppdu_airtm->rx_datlen > 0) {
			prxppdu_airtm->rx_airtime =
				wl_airtime_calc(prxppdu_airtm,
						prxppdu_airtm->rx_datlen);
			//prxppdu_airtm->dbg_sum_pktcnt = prxppdu_airtm->dbg_pktcnt;
			prxppdu_airtm->rx_tsf = 0;	//ktime_get_ns(); //rx_tsf will be filled at host driver
			prxppdu_airtm->sum_rx_airtime +=
				prxppdu_airtm->rx_airtime;
			prxppdu_airtm->sum_rx_pktcnt++;
			prxppdu_airtm->sum_rx_pktlen +=
				prxppdu_airtm->rx_datlen;
		}
		// New PPDU arrives, update the cached rx_info_aux
		memcpy(&prxppdu_airtm->rx_info_aux, prx_info_aux,
		       sizeof(struct rx_info_aux));

		prxppdu_airtm->rx_datlen = pRxSkBuff->len;
		prxppdu_airtm->dbg_pktcnt = 1;
	} else {
		// More msdu packets
		prxppdu_airtm->rx_datlen += pRxSkBuff->len;
		prxppdu_airtm->dbg_pktcnt++;
	}

	return;
}

static inline int
wlProcessCfhUl(struct radio *radio, int qid, wlrxdesc_t * cfh_ul, int msdu_no)
{
	int idx = 0, cnt = 0;
	wlrxdesc_t *cur_cfh_ul;
	struct pkt_hdr *pkt;
	IEEEtypes_FrameCtl_t *frame_ctrl;
	struct sta_info *sta_info;
	struct vif *vif;
	struct llc_snap *llc_snap;
	struct bbrx_rx_info *rx_info;
	struct rx_sideband_info *rx_sideband;
	struct rx_info_aux *prx_info_aux;
#ifdef CORTINA_TUNE
	ca_uint16_t *ether_type;
#else
	struct ether_header *ether_header;
#endif
#ifdef BA_REORDER
	ca_uint16_t seq;
	ca_uint8_t ampdu_qos;
	ca_uint16_t tid;
	ca_uint16_t stn_id;
	ca_uint8_t LMFbit = 0;
#endif

	if (!msdu_no)
		return 0;

	do {
		cur_cfh_ul = &cfh_ul[idx++];

		frame_ctrl = (IEEEtypes_FrameCtl_t *) & cur_cfh_ul->frame_ctrl;

		if (frame_ctrl->Type == IEEE_TYPE_DATA) {
			if ((cur_cfh_ul->fpkt == 1) && (cur_cfh_ul->lpkt == 1)) {
				memcpy(PHYS_TO_VIRT
				       (cur_cfh_ul->hdr.lo_dword_addr),
				       &cur_cfh_ul->nss_hdr[0], 14);
				radio->dbg_cnt.rx_cnt.rx_cfh_ul_war++;
			}
		}
#ifdef CORTINA_TUNE_HW_CPY_RX
		if (rx_next_pkt != NULL) {
			ca_dma_poll_for_complete(HW_DMA_COPY_WIFI_RX_DATA);
			rx_buff_now = rx_buff_next;
		} else {
			ca_dma_sync_copy(HW_DMA_COPY_WIFI_RX_DATA,
					 VIRT_TO_PHYS(rx_buff_now),
					 (ca_uint8_t *) cur_cfh_ul->hdr.
					 lo_dword_addr, TX_DATA_BUFFER_SIZE);
		}

		if (idx < (msdu_no - 1)) {
			rx_next_pkt =
				(ca_uint8_t *) cfh_ul[idx].hdr.lo_dword_addr;
			if (rx_buff_next ==
			    ((ca_uint8_t *) FAST_MEM_WIFI_RX_BUFFER0)) {
				rx_buff_next =
					(ca_uint8_t *) FAST_MEM_WIFI_RX_BUFFER1;
				ca_dma_async_copy(HW_DMA_COPY_WIFI_RX_DATA,
						  (ca_uint8_t *)
						  FAST_MEM_WIFI_RX_BUFFER1_PA,
						  (ca_uint8_t *) rx_next_pkt,
						  TX_DATA_BUFFER_SIZE);
			} else {
				rx_buff_next =
					(ca_uint8_t *) FAST_MEM_WIFI_RX_BUFFER0;
				ca_dma_async_copy(HW_DMA_COPY_WIFI_RX_DATA,
						  (ca_uint8_t *)
						  FAST_MEM_WIFI_RX_BUFFER0_PA,
						  (ca_uint8_t *) rx_next_pkt,
						  TX_DATA_BUFFER_SIZE);
			}
		} else
			rx_next_pkt = NULL;
#endif
		pkt = wlCfhUlToPkt(radio->rid, cur_cfh_ul, qid);
		if (!pkt) {
			printf("\t %s(%d): packet is NULL\n", __func__,
			       radio->rid);
			radio->dbg_cnt.rx_cnt.rx_drop_msdu_err++;
			goto next;
		}

		if (qid == radio->rx_q_data) {
			if (frame_ctrl->Type != IEEE_TYPE_DATA) {
				if (frame_ctrl->Type != IEEE_TYPE_CONTROL) {
					printf("\t %s(%d): type: %d subtype: %d\n", __func__, radio->rid, frame_ctrl->Type, frame_ctrl->Subtype);
					radio->dbg_cnt.rx_cnt.
						rx_drop_data_q_type_err++;
				}
				goto next;
			}

			if ((!frame_ctrl->FromDs) && (frame_ctrl->ToDs)) {
				ca_uint16_t *eth_type =
					(ca_uint16_t *) (pkt->data +
							 ETH_ALEN * 2 +
							 LLC_HDR_LEN);

				/* only AP mode is supported now */
#ifdef CORTINA_TUNE_HW_CPY_RX
				sta_info = stadb_get_stainfo(radio->rid,
							     &rx_buff_now
							     [ETH_ALEN]);
#else
				sta_info = stadb_get_stainfo(radio->rid,
							     &pkt->
							     data[ETH_ALEN]);
#endif
				if (!sta_info) {
					radio->dbg_cnt.rx_cnt.rx_drop_sta_err++;
					goto next;
				}
				vif = &radio->vif_info[sta_info->vid];
				if (!sta_info->enable &&
				    BE16_TO_CPU(*eth_type) !=
				    IEEE_ETHERTYPE_PAE) {
					radio->dbg_cnt.rx_cnt.
						rx_drop_sta_disable++;
					vif->netdev_stats.rx_dropped++;
					goto next;
				}
				if (!vif->valid) {
					radio->dbg_cnt.rx_cnt.rx_drop_vif_err++;
					vif->netdev_stats.rx_dropped++;
					goto next;
				}
				if (!vif->enable) {
					radio->dbg_cnt.rx_cnt.
						rx_drop_vif_disable++;
					vif->netdev_stats.rx_dropped++;
					goto next;
				}
#ifdef CORTINA_TUNE_HW_CPY_RX
				llc_snap =
					(struct llc_snap *)(rx_buff_now +
							    ETH_HLEN);
#else
				llc_snap =
					(struct llc_snap *)(pkt->data +
							    ETH_HLEN);
#endif
				if ((pkt->len - ETH_HLEN) < LLC_HDR_LEN) {
					radio->dbg_cnt.rx_cnt.rx_drop_llc_err++;
					vif->netdev_stats.rx_dropped++;
					vif->netdev_stats.rx_errors++;
					goto next;
				}
				if ((llc_snap->llc_dsap == LLC_SNAP_LSAP) &&
				    (llc_snap->llc_ssap == LLC_SNAP_LSAP) &&
				    (llc_snap->control == LLC_UI) &&
				    (!llc_snap->org_code[0] &&
				     !llc_snap->org_code[1] &&
				     !llc_snap->org_code[2])) {
#ifndef CORTINA_TUNE
					memmove(pkt->data + LLC_HDR_LEN,
						pkt->data, ETH_ALEN * 2);
					pkt->data += LLC_HDR_LEN;
					pkt->len -= LLC_HDR_LEN;
#endif
				} else {
					radio->dbg_cnt.rx_cnt.rx_drop_llc_err++;
					vif->netdev_stats.rx_dropped++;
					vif->netdev_stats.rx_errors++;
					goto next;
				}
				sta_info->active_notify = true;
				vif->netdev_stats.rx_packets++;
				vif->netdev_stats.rx_bytes += pkt->len;
				sta_info->rx_bytes += pkt->len;
				pkt->vif_info = vif;
				pkt->sta_info = sta_info;
				if (radio->dbg_ctrl & DBG_ENABLE_CLIENT_RSSI) {
					rx_info =
						&radio->
						rx_info_addr[cur_cfh_ul->hdr.
							     rxInfoIndex];
					prx_info_aux =
						&(radio->
						  rxinfo_aux_poll[cur_cfh_ul->
								  hdr.
								  rxInfoIndex]);
					if (cur_cfh_ul->hdr.timestamp !=
					    prx_info_aux->rxTs) {
						if (cur_cfh_ul->hdr.timestamp ==
						    rx_info->rxTs) {
							wl_rx_info_aux_sync
								(prx_info_aux,
								 rx_info);
						}
					}
					wl_proc_rx_airtime(sta_info, cur_cfh_ul,
							   pkt, prx_info_aux);

					if (cur_cfh_ul->hdr.timestamp ==
					    rx_info->rxTs) {
						if (cur_cfh_ul->hdr.
						    rxInfoIndex !=
						    radio->last_rx_info_idx) {
							wlrxinfo_2_rxhisto
								(&radio->
								 rx_rate_hist,
								 rx_info);
							rx_sideband =
								(struct
								 rx_sideband_info
								 *)rx_info;
							sta_info->
								rssi_path_info.
								a =
								rx_sideband->
								rssi_dbm_a;
							sta_info->
								rssi_path_info.
								b =
								rx_sideband->
								rssi_dbm_b;
							sta_info->
								rssi_path_info.
								c =
								rx_sideband->
								rssi_dbm_c;
							sta_info->
								rssi_path_info.
								d =
								rx_sideband->
								rssi_dbm_d;
							sta_info->
								rssi_path_info.
								e =
								rx_sideband->
								rssi_dbm_e;
							sta_info->
								rssi_path_info.
								f =
								rx_sideband->
								rssi_dbm_f;
							sta_info->
								rssi_path_info.
								g =
								rx_sideband->
								rssi_dbm_g;
							sta_info->
								rssi_path_info.
								h =
								rx_sideband->
								rssi_dbm_h;
							radio->last_rx_info_idx
								=
								cur_cfh_ul->hdr.
								rxInfoIndex;
						}
					}
				}
#ifdef CORTINA_TUNE
				if (IS_MULTICAST_ADDR(rx_buff_now))
					pkt->is_bcmc = 1;
				else {
					pkt->is_bcmc = 0;
					pkt->rx_sta_info =
						stadb_get_stainfo(radio->rid,
								  rx_buff_now);
				}
#ifdef CORTINA_TUNE_HW_CPY_RX
				ether_type =
					(ca_uint16_t *) (rx_buff_now +
							 ETH_ALEN * 2 +
							 LLC_HDR_LEN);
#else
				ether_type =
					(ca_uint16_t *) (pkt->data +
							 ETH_ALEN * 2 +
							 LLC_HDR_LEN);
#endif
				if (BE16_TO_CPU(*ether_type) ==
				    IEEE_ETHERTYPE_PAE) {
#else
				ether_header = (struct ether_header *)pkt->data;
				if (BE16_TO_CPU(ether_header->ether_type) ==
				    IEEE_ETHERTYPE_PAE) {
#endif

					/* EAPOL packet for host driver */
					wlSendPktToHost(radio, pkt, true, NULL);
					radio->dbg_cnt.rx_cnt.
						eapol_pkt_to_host++;
				} else {
					if (sta_info->enable) {
#ifdef BA_REORDER
						if (radio->
						    dbg_ctrl &
						    DBG_DISABLE_BA_REORDER) {
							if (radio->
							    dbg_ctrl &
							    DBG_PKT_TO_HOST) {
								wlSendPktToHost
									(radio,
									 pkt,
									 true,
									 NULL);
								radio->dbg_cnt.
									rx_cnt.
									data_pkt_to_host++;
							} else {
#ifdef DBG_BM_BUF_MONITOR
								dbg_check_buf
									(radio->
									 rid,
									 pkt,
									 __func__);
#endif
								eth_xmit_pkt
									(vif->
									 eth_handle,
									 pkt,
									 pkt->
									 data,
									 pkt->
									 len);
								radio->dbg_cnt.
									rx_cnt.
									data_pkt_to_eth++;
							}
						} else {
							seq = cur_cfh_ul->hdr.
								seqnum >>
								IEEE80211_SEQ_SHIFT;
							ampdu_qos =
								cur_cfh_ul->qos;
							if (frame_ctrl->Subtype & (1 << 3))	//QoS Data Subtype
							{
								tid = ampdu_qos
									& 0x7;
							} else {
								tid = SYSADPT_MAX_TID;	//Non-QoS
							}
							stn_id = sta_info->
								stn_id;
							LMFbit = (cur_cfh_ul->
								  lpkt << 2) |
								((~
								  (cur_cfh_ul->
								   lpkt |
								   cur_cfh_ul->
								   fpkt) & 0x1)
								 << 1) |
								cur_cfh_ul->
								fpkt;
							ba_reorder_proc(radio->
									rid,
									vif,
									stn_id,
									tid,
									seq,
									pkt,
									frame_ctrl,
									LMFbit);
						}
#else
						if (radio->
						    dbg_ctrl & DBG_PKT_TO_HOST)
						{
							wlSendPktToHost(radio,
									pkt,
									true,
									NULL);
							radio->dbg_cnt.rx_cnt.
								data_pkt_to_host++;
						} else {
#ifdef DBG_BM_BUF_MONITOR
							dbg_check_buf(radio->
								      rid, pkt,
								      __func__);
#endif
							eth_xmit_pkt(vif->
								     eth_handle,
								     pkt,
								     pkt->data,
								     pkt->len);
							radio->dbg_cnt.rx_cnt.
								data_pkt_to_eth++;
						}
#endif
					}
				}

				pkt = NULL;
			}
		}

next:
		if (pkt)
			pkt_free_data(radio->rid, pkt, __func__);

		cnt++;
	} while (msdu_no != idx);

#ifdef CORTINA_TUNE
	eth_xmit_pkt_flush();
#endif

	return cnt;
}

static inline int
wlRxBufFill(struct radio *radio, int qid)
{
	struct wldesc_data *wlqm;
	struct pkt_hdr *pkt;
	struct pkt_hdr **pkt_addr;
	ca_uint32_t aligned_offset;
	bm_pe_hw_t *pe_hw;

	wlqm = &radio->desc_data[qid];

	pkt = pkt_alloc_bm_data(radio->rid, qid);
	if (!pkt) {
		radio->dbg_cnt.rx_cnt.rx_bmq_refill_fail[qid -
							 radio->bm_q_start]++;
		return -ENOMEM;
	}
#ifdef ENABLE_PKT_DATA_STATUS
	{
		struct pkt_data *pkt_data;

		pkt_data = (struct pkt_data *)
			(pkt->buf_ptr - PKT_DATA_HEADROOM);
		if (pkt_data->status != PKT_DATA_ALLOC)
			printf("\t Packet data is not allocated: %d %d %p %08x\n", radio->rid, pkt_data->status, pkt_data, pkt_data->signature);
		pkt_data->status = PKT_DATA_FW_ASSIGNED;
	}
#endif
#ifdef LINUX_PE_SIM
	aligned_offset = ((ca_uint64_t) (pkt->data - PKT_INFO_SIZE) & 0x3);
#else
	aligned_offset = ((ca_uint32_t) (pkt->data - PKT_INFO_SIZE) & 0x3);
#endif
#if defined(ENABLE_PKT_SIGNATURE) || defined(ENABLE_SIGNATURE_CHECK_DATA)
	*((ca_uint32_t *) (pkt->data - PKT_INFO_SIZE - aligned_offset)) =
		PKT_SIGNATURE;
#endif
	pkt_addr =
		(struct pkt_hdr **)(pkt->data - PKT_POINTER_OFFSET -
				    aligned_offset);
	*pkt_addr = pkt;
	pe_hw = (bm_pe_hw_t *) (wlqm->rq.virt_addr +
				wlqm->rq.wrinx * sizeof(bm_pe_hw_t));
#ifdef LINUX_PE_SIM
	pe_hw->pe0_lo_dword_addr = dma_map_single(radio->dev, pkt->data,
						  pkt->buf_size,
						  DMA_FROM_DEVICE);
#else
	pe_hw->pe0_lo_dword_addr = (ca_uint32_t) VIRT_TO_PHYS(pkt->data);
#endif
	pe_hw->pe0_hi_byte_addr = radio->smac_buf_hi_addr;
	pe_hw->bpid = qid;

#ifdef DBG_BM_BUF_MONITOR
	dbg_check_buf(radio->rid, pkt, __func__);
#endif

	if (!wlRQIndexPut(&wlqm->rq)) {
		pkt_free_data(radio->rid, pkt, __func__);
		return -ENOSPC;
	}

	return 0;
}

void
rx_rel_pkt_to_host(int rid, const void *msg, ca_uint16_t msg_size)
{
	struct radio *radio = &radio_info[rid - 1];
	h2t_pkt_recv_rel_t h2t_msg;
	struct pkt_hdr *pkt;

	if (msg_size != sizeof(h2t_msg))
		return;
	memcpy(&h2t_msg, msg, msg_size);
	pkt = (struct pkt_hdr *)__PLATFORM_POINTER_TYPE__ h2t_msg.pkt_hdr_addr;

#ifdef DBG_BM_BUF_MONITOR
	dbg_check_buf(rid, pkt, __func__);
#endif

	if ((pkt->data_type == PKT_DATA_FROM_BM) && (pkt->qid == 10)) {
		struct pkt_hdr *pkt_hdr;

		radio->dbg_cnt.rel_cnt.bm10_return_host++;
		pkt_hdr = pkt;
		if (pkt_hdr->is_clone) {
			pkt_hdr = pkt_hdr->clone_pkt;
			if ((pkt_hdr->ref_cnt == 2) &&
			    (!pkt_hdr->is_rx_amsdu_hold))
				radio->dbg_cnt.rel_cnt.bm10_return_non_clone++;
		} else {
			if (pkt_hdr->ref_cnt == 1)
				radio->dbg_cnt.rel_cnt.bm10_return_non_clone++;
		}
	}
	pkt_free_data(radio->rid, pkt, __func__);
}

void
rx_free_pkt_to_eth(int rid, void *pkt)
{
	struct radio *radio = &radio_info[rid - 1];
	struct pkt_hdr *pkt_hdr = (struct pkt_hdr *)pkt;

#ifdef DBG_BM_BUF_MONITOR
	dbg_check_buf(rid, pkt, __func__);
#endif

	if ((pkt_hdr->data_type == PKT_DATA_FROM_BM) && (pkt_hdr->qid == 10)) {
		radio->dbg_cnt.rel_cnt.bm10_return_eth++;
		if (pkt_hdr->is_clone) {
			pkt_hdr = pkt_hdr->clone_pkt;
			if ((pkt_hdr->ref_cnt == 2) &&
			    (!pkt_hdr->is_rx_amsdu_hold))
				radio->dbg_cnt.rel_cnt.bm10_return_non_clone++;
		} else {
			if (pkt_hdr->ref_cnt == 1)
				radio->dbg_cnt.rel_cnt.bm10_return_non_clone++;
		}
	}
	pkt_free_data(rid, (struct pkt_hdr *)pkt, __func__);
}

void
rx_poll(int rid)
{
	struct radio *radio = &radio_info[rid - 1];
	struct wldesc_data *wlqm;
	int qid;
	ca_uint32_t wrinx;
	int work_done = 0;
#ifndef CORTINA_TUNE_HW_CPY_RX
	wlrxdesc_t cfh_ul_mem;
#endif
	wlrxdesc_t *cfh_ul;
	bool amsdu_deaggr_enable =
		((radio->chip_revision == REV_Z1) && (radio->devid == SC5)) ?
		true : false;
	int msdu_no = 0;
	wlrxdesc_t *cfh_ul_amsdu = NULL;

	qid = radio->rx_q_data;
	wlqm = &radio->desc_data[qid];
	wlqm->sq.wrinx = wrinx = wlQueryWrPtr(rid, qid, SC5_SQ);

#ifdef CORTINA_TUNE_HW_CPY
	if (rx_desc_async_wait == 1) {
		ca_dma_poll_for_complete(HW_DMA_COPY_WIFI_RX_CHF);
		rx_desc_async_wait = 0;
	}
#endif

	while ((wrinx != wlqm->sq.rdinx) &&
	       (work_done < SYSADPT_MAX_RX_PACKET_PER_POLL)) {
#ifdef CORTINA_TUNE_HW_CPY_RX
		cfh_ul = &radio->cfhul_amsdu.rxdesc[radio->cfhul_amsdu.idx];
		cfh_ul = wlGetCfhUl(rid, qid, (wlrxdesc_t *) cfh_ul);
#else
		cfh_ul = wlGetCfhUl(rid, qid, &cfh_ul_mem);
#endif
		if (!cfh_ul) {
			wlSQIndexGet(&(wlqm->sq));
			break;
		}
		if (amsdu_deaggr_enable) {
			/* for Z1 revision. drv amsdu deaggr */
			msdu_no = cfh_ul->hdrFormat;
			if (msdu_no > 1 && qid == radio->rx_q_data) {
				cfh_ul_amsdu = wlSpiltAMSDU(radio, wlqm,
							    cfh_ul);
				if (!cfh_ul_amsdu)
					goto drop;
			} else {
				msdu_no = 0;
				cfh_ul_amsdu = NULL;
			}
		} else {
			/* for Z2 AMSDU deaggr in sfw */
			msdu_no = 0;
			cfh_ul_amsdu = wlProcessMsdu(radio, cfh_ul, &msdu_no);
			if (!msdu_no && !cfh_ul_amsdu)
				goto drop;
		}

		/* process received packets */
		work_done += wlProcessCfhUl(radio, qid, cfh_ul_amsdu, msdu_no);

		if (cfh_ul_amsdu && amsdu_deaggr_enable)
			MFREE(cfh_ul_amsdu);
drop:
		wlSQIndexGet(&(wlqm->sq));
	}
	/* update write pointer */
	wlUpdateRdPtr(rid, qid, SC5_SQ, wlqm->sq.rdinx);
}

void
rx_refill(int rid)
{
	struct radio *radio = &radio_info[rid - 1];
	struct wldesc_data *wlqm;
	int qid, refill_cnt;

	for (qid = radio->bm_q_start; qid < radio->bm_q_start + radio->bm_q_num;
	     qid++) {
		wlqm = &radio->desc_data[qid];
		wlqm->rq.rdinx = wlQueryRdPtr(rid, qid, SC5_RQ);

		for (refill_cnt = 0;
		     refill_cnt < SYSADPT_MAX_RX_REFILL_PER_POLL;
		     refill_cnt++) {
			if (isRQFull(&wlqm->rq))
				break;

			if (wlRxBufFill(radio, qid))
				break;
		}

		if (refill_cnt > 0)
			wlUpdateWrPtr(rid, qid, SC5_RQ, wlqm->rq.wrinx);
	}
}
