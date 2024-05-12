/** @file ap8xLnxRxInfo.c
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2019-2021 NXP
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
#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/wireless.h>
#include <linux/ieee80211.h>
#include <linux/ctype.h>

#include "ap8xLnxIntf.h"
#include "ap8xLnxRxInfo.h"
#include "ap8xLnxBQM.h"
#include "radiotap.h"
#include "StaDb.h"
#include "wlmac.h"

/*
	Rate Id of L-SIG. Ref: Table 17-6 of 802.11-2016.pdf
*/
enum {
	sig_rate_6m = 0xb,	// [R1-R4]=0b1101, [R4:R1]=0B1011 = 0xb
	sig_rate_9m = 0xf,	// [R1-R4]=0b1111, [R4:R1]=0b1111 = 0xf
	sig_rate_12m = 0xa,	// [R1-R4]=0b0101, [R4:R1]=0b1010 = 0xa
	sig_rate_18m = 0xe,	// [R1-R4]=0b0111, [R4:R1]=0b1110 = 0xe
	sig_rate_24m = 0x9,	// [R1-R4]=0b1001, [R4:R1]=0b1001 = 0x9
	sig_rate_36m = 0xd,	// [R1-R4]=0b1011, [R4:R1]=0b1101 = 0xd
	sig_rate_48m = 0x8,	// [R1-R4]=0b0001, [R4:R1]=0b1000 = 0x8
	sig_rate_54m = 0xc	// [R1-R4]=0b0011, [R4:R1]=0b1100 = 0xc
};

#define NSS_UNKNOWN		0xFFFF
#pragma pack (push, 1)

typedef enum {
	HE_SU = 0,
	HE_EXT,
	HE_MU,
	HE_TRIG
} RADIOTAP_HEINFO_PPDU_FORMAT;

typedef struct _ieee80211_radiotap_he_info {
	// WORD#0:
	U16 kn_ppdu_format:2;
	U16 kn_bss_color:1;
	U16 kn_beam_change:1;

	U16 kn_ul_dl:1;
	U16 kn_data_mcs:1;
	U16 kn_data_dcm:1;
	U16 kn_coding:1;

	U16 kn_ldpc_extra_symbol_segment:1;
	U16 kn_stbc:1;
	U16 kn_spatial_reuse_1:1;
	U16 kn_spatial_reuse_2:1;

	U16 kn_spatial_reuse_3:1;
	U16 kn_spatial_reuse_4:1;
	U16 kn_data_bw_ru_allocation:1;
	U16 kn_doppler:1;
	// WORD#1:
	U16 kn_pri_sec_80_mhz:1;
	U16 kn_gi:1;
	U16 kn_ltf_symbols:1;
	U16 kn_pre_fec_padding_factor:1;

	U16 kn_txbf:1;
	U16 kn_pe_disambiguity:1;
	U16 kn_txop:1;
	U16 kn_midamble_periodicity:1;

	U16 ru_allocation_offset:6;
	U16 kn_ru_allocation_offset:1;
	U16 pri_sec_80_mhz:1;
	// WORD#2:
	U16 bss_color:6;
	U16 beam_change:1;
	U16 ul_dl:1;
	U16 data_mcs:4;
	U16 data_dcm:1;
	U32 coding:1;
	U32 ldpc_extra_symbol_segment:1;
	U32 stbc:1;
	// WORD#3:
	U16 spatial_reuse:4;
	U16 w3_resv:12;
	// DWORD#4:
	U16 data_bandwidth_ru_allocation:4;
	U16 gi:2;
	U16 w4_resv:2;

	U16 ltf_sym:3;
	U16 w4_resv_1:1;

	U16 pre_fec_pad:2;
	U16 txbf:1;
	U16 pe_disamb:1;
	// DWORD#5:
	U16 nsts:4;
	U16 dopler:1;
	U16 w5_resv:3;
	U16 txop:7;
	U16 midamble_periodicity:1;
} ieee80211_radiotap_he_info;

typedef struct _ieee80211_radiotap_vht_info {
	// WORD#0
	struct {
		U16 kn_stbc:1;
		U16 kn_txop_ps_not_allow:1;
		U16 kn_guard_intrl:1;
		U16 kn_sgi_nsym_disamb:1;
		U16 kn_ldpc_ext_ofdma:1;
		U16 kn_beamform:1;
		U16 kn_bandwidth:1;
		U16 kn_gid:1;
		U16 kn_p_aid:1;
	};
	// BYTE#2
	struct {
		U8 stbc:1;
		U8 txop_ps_not_allow:1;
		U8 guard_intrl:1;
		U8 sgi_nsym_disamb:1;
		U8 ldpc_ext_ofdma:1;
		U8 beamform:1;
	};
	// BYTE#3
	U8 bandwidth;
	// BYTE#4
	struct {
		U8 nss:4;
		U8 mcs:4;
	};
	// BYTE: 5~8
	U8 resv[3];
	struct {
		U8 coding:1;
	};
	// BYTE#9
	U8 gid;
	// BYTE:10, 11
	U16 part_aid;
} ieee80211_radiotap_vht_info;
#pragma pack(pop)

#define NSYM_LEGACY	((5484-20)/4)
#define NDBPS_FACTOR	4

/**
* Legacy index to PHY rate mapping in units of kbps.
*/
#define OFDM_BASEID	5	//begin from "Rate ID 5" below
const u32 LEGACY_PHY_RATE[IEEEtypes_MAX_DATA_RATES_G] = {
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

/**
* HT rate index and PHY rate mapping. PHY rate is
* in the units of kbps
* This is used for PDU factor calculation
*/
#define RTBL_MAX_MCS_INDEX    33
const u32 HT_PHY_RATE[RTBL_MAX_MCS_INDEX][2][2] = {
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
const u32 VHT_PHY_RATE[VHT_PHYRATE_BW_MAX][VHT_PHYRATE_MCS_MAX][VHT_PHYRATE_NSS_MAX][VHT_PHYRATE_GI_MAX] = {
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
	 {{86700, 96300}, {173300, 192600}, {260000, 288900}, {346700, 385200}}},	// MCS9
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

// ================================================================
static void wl_rx_info_aux_sync(rx_info_aux_t * prx_info_aux, rx_info_ppdu_t * prxinfo);

// ================================================================
// Usage:
//      COPY_RSSI_VAL(a, prx_sband_info, prssi_info, rssi_compensate)
// Info:
// Per-path RSSI is 12 bits with lower 4 bits representing the fractional part. So 1LSB = (1/16)dB. It is a signed 2's complement number.
// So -50dBm would be 0xCE0, and after subtracting 6dB it would be 0xC80
#define COPY_RSSI_VAL(id, d_val, s_val, rssi_comp) {\
	if (s_val->rssi_dbm_##id != 0) {\
		RssiPathVal	rssi_val;\
		rssi_val.val = s_val->rssi_dbm_##id;\
		rssi_val.ival -= rssi_comp;\
		d_val->id = rssi_val.val;\
	}\
}
static void wl_set_rssi_info(RssiPathInfo_t * prssi_info, RxSidebandInfo_t * prx_sband_info)
{
	rx_info_ppdu_t *prx_info = (rx_info_ppdu_t *) prx_sband_info;
	SINT8 rssi_compensate;	// rssi compensation for TB-PPDB

	if (prx_info->bbrx_info.rx_mode == BBRX_RM_HE_TRIG_BASED) {
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

static void wl_set_nf_info(NfPathInfo_t * pnf_info, RxSidebandInfo_t * prx_sband_info)
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

static void wlrxinfo_sync_rxinfoaux_b(rx_info_aux_t * prx_info_aux, rx_info_ppdu_t * prxinfo)
{
	dbRateInfo_t *prate_info = &prx_info_aux->rate_info;
	// ================================================================
	// Sync the rx_info_aux_t->rate_info
	//
	memset(prate_info, 0, sizeof(dbRateInfo_t));
	switch (prxinfo->bbrx_info.rx_sig) {
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

static void wlrxinfo_sync_rxinfoaux_a_g(rx_info_aux_t * prx_info_aux, rx_info_ppdu_t * prxinfo)
{
	OFDM_SIG *pofdm_sig = &prx_info_aux->ofdm_sig;
	dbRateInfo_t *prate_info = &prx_info_aux->rate_info;
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
	const U8 dTblOfdmSignal2Rate[8] =	//signal & 0x7, id of "LEGACY_PHY_RATE" array
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
	pofdm_sig->ofdm_sig = prxinfo->bbrx_info.rx_sig;

	// ================================================================
	// Sync the rx_info_aux_t->rate_info
	//
	memset(prate_info, 0, sizeof(dbRateInfo_t));
	prate_info->Format = rtinfo_pkt_legacy;
	prate_info->RateIDMCS = dTblOfdmSignal2Rate[pofdm_sig->rate & 0x7];
	prx_info_aux->nss = 1;
	return;
}

static void wlrxinfo_sync_rxinfoaux_n(rx_info_aux_t * prx_info_aux, rx_info_ppdu_t * prxinfo)
{
	HT_SIG1 *pht_sig1 = &prx_info_aux->ht_sig1;
	HT_SIG2 *pht_sig2 = &prx_info_aux->ht_sig2;
	dbRateInfo_t *prate_info = &prx_info_aux->rate_info;

	// ================================================================
	// Sync the rx_info_aux_t->ht_sigX
	//
	pht_sig1->ht_sig1 = prxinfo->bbrx_info.htsig1_vhtsiga1_hesiga1;
	pht_sig2->ht_sig2 = prxinfo->bbrx_info.htsig2_vhtsiga2_hesiga2 & 0xffffff;

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

static void wlrxinfo_sync_rxinfoaux_ac(rx_info_aux_t * prx_info_aux, rx_info_ppdu_t * prxinfo, BOOLEAN is_su)
{
	VHT_SIG_A1 *pvht_siga1 = &prx_info_aux->vht_siga1;
	VHT_SIG_A2 *pvht_siga2 = &prx_info_aux->vht_siga2;
	VHT_SIG_B *pvht_sigb = &prx_info_aux->vht_sigb;
	dbRateInfo_t *prate_info = &prx_info_aux->rate_info;

	// ================================================================
	// Sync the rx_info_aux_t->vht_sigX
	//
	pvht_siga1->vht_sig_a1 = prxinfo->bbrx_info.htsig1_vhtsiga1_hesiga1;
	pvht_siga2->vht_sig_a2 = prxinfo->bbrx_info.htsig2_vhtsiga2_hesiga2;
	pvht_sigb->vht_sig_b = prxinfo->bbrx_info.vhtsigbSig >> 8;

	// ================================================================
	// Sync the rx_info_aux_t->rate_info
	//
	prate_info->Format = rtinfo_pkt_11ac;
	prate_info->Stbc = (is_su == TRUE) ? (pvht_siga1->su.stbc) : (pvht_siga1->mu.stbc);
	prate_info->Dcm = 0;	//resv in ac mode
	prate_info->Bandwidth = (is_su == TRUE) ? (pvht_siga1->su.bw) : (pvht_siga1->mu.bw);
	prate_info->ShortGI = (is_su == TRUE) ? (pvht_siga2->su.short_gi) : (pvht_siga2->mu.short_gi);
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
	prate_info->AdvCoding = (is_su == TRUE) ? (pvht_siga2->su.coding) : (pvht_siga2->mu.coding);
	//Ref: p#2543 of 802.11-2016.pdf, Fig 21-18, 21-19, Table 21-12
	prx_info_aux->nss = (is_su == TRUE) ? (pvht_siga1->su.nsts + 1) : (pvht_siga1->mu.mu_0_nsts);
	prate_info->RateIDMCS |= ((prx_info_aux->nss - 1) & 0x7) << 4;
	return;
}

static void wlrxinfo_sync_rxinfoaux_he(rx_info_aux_t * prx_info_aux, rx_info_ppdu_t * prxinfo, BOOLEAN is_su)
{
	HE_SIG_A1 *phe_siga1 = &prx_info_aux->he_siga1;
	HE_SIG_A2 *phe_siga2 = &prx_info_aux->he_siga2;
	HE_SIG_B_USR *phesigb = &prx_info_aux->hesigb;
	dbRateInfo_t *prate_info = &prx_info_aux->rate_info;

	// ================================================================
	// Sync the rx_info_aux_t->he_sigX
	//
	phe_siga1->he_sig_a1 = (prxinfo->bbrx_info.hesiga1 << 24) | prxinfo->bbrx_info.htsig1_vhtsiga1_hesiga1;
	phe_siga2->he_sig_a2 = prxinfo->bbrx_info.htsig2_vhtsiga2_hesiga2;
	phesigb->he_sig_b = (prxinfo->bbrx_info.hesigb >> 9) & 0x1fffff;

	// ================================================================
	// Sync the rx_info_aux_t->rate_info
	//
	prate_info->Format = rtinfo_pkt_11ax;
	prate_info->Stbc = (is_su == TRUE) ? (phe_siga2->su.stbc) : (phe_siga2->mu.stbc);
	prate_info->Dcm = (is_su == TRUE) ? (phe_siga1->su.dcm) : (phe_siga1->mu.dcm);
	/*
	   Bandwidth:
	   SU: B19-B20 of Table 27-19 in Draft P802.11ax_D4.0.pdf
	   0: 20MHz, 1:40MHz, 2:80MHz, 3: 160 / 80+80 MHz
	   MU: B15-B17 of Table 27-20 in Draft P802.11ax_D4.0.pdf
	   0: 20MHz, 1:40MHz, 2:80MHz, 3: 160 / 80+80 MHz
	 */
	prate_info->Bandwidth = (is_su == TRUE) ? (phe_siga1->su.bandwidth) : (phe_siga1->mu.bandwidth);
	if (prate_info->Stbc && prate_info->Dcm) {
		prate_info->ShortGI = 3;	// 4x+0.8
	} else {
		prate_info->ShortGI = (is_su == TRUE) ? (phe_siga1->su.gi_ltf) : (phe_siga1->mu.gi_ltf);
	}
	prate_info->RateIDMCS = (is_su == TRUE) ? (phe_siga1->su.mcs) : (phe_siga1->mu.mcs);
	prate_info->BF = (is_su == TRUE) ? (phe_siga2->su.txbf) : (phesigb->tx_beamform);
	prate_info->AdvCoding = (is_su == TRUE) ? (phe_siga2->su.coding) : (phesigb->coding);
	if (is_su == TRUE) {
		if (phe_siga2->su.doppler == 0) {
			prx_info_aux->nss = phe_siga1->su.nts_mid_pri + 1;
		} else {	//doppler is 1 bit => it's "1"
			prx_info_aux->nss = (phe_siga1->su.nts_mid_pri & 0x3) + 1;
		}
	} else {		// MU
		prx_info_aux->nss = phesigb->nsts + 1;
	}
	prate_info->RateIDMCS |= ((prx_info_aux->nss - 1) & 0x7) << 4;
	return;
}

static void wl_set_radiotap_he_su_info(ieee80211_radiotap_he_info * he_info, rx_info_aux_t * prx_info_aux)
{
	HE_SIG_A1 *phe_siga1 = &prx_info_aux->he_siga1;
	HE_SIG_A2 *phe_siga2 = &prx_info_aux->he_siga2;

	he_info->kn_ppdu_format = HE_SU;

	he_info->kn_bss_color = 1;
	he_info->bss_color = phe_siga1->su.bss_color;

	he_info->kn_ul_dl = 1;
	he_info->ul_dl = phe_siga1->su.ul_dl;

	he_info->kn_data_mcs = 1;
	he_info->data_mcs = phe_siga1->su.mcs;

	he_info->kn_data_dcm = 1;
	he_info->data_dcm = phe_siga1->su.dcm;

	he_info->kn_coding = 1;
	he_info->coding = phe_siga2->su.coding;

	he_info->kn_stbc = 1;
	he_info->stbc = phe_siga2->su.stbc;

	he_info->kn_txbf = 1;
	he_info->txbf = phe_siga2->su.txbf;

	he_info->kn_data_bw_ru_allocation = 1;
	he_info->data_bandwidth_ru_allocation = phe_siga1->su.bandwidth;
	//Ref: p#405 B21-B22 of Table 28-18, HE-SIG-A of 802.11ax spec
	he_info->kn_gi = 1;
	he_info->kn_ltf_symbols = 1;
	switch (phe_siga1->su.gi_ltf) {
	case 0:
		he_info->gi = 0;
		he_info->ltf_sym = 0;
		break;
	case 1:
		he_info->gi = 0;
		he_info->ltf_sym = 1;
		break;
	case 2:
		he_info->gi = 1;
		he_info->ltf_sym = 1;
		break;
	case 3:
		if ((phe_siga1->su.dcm == 1) && (phe_siga2->su.stbc == 1)) {
			he_info->gi = 0;
			he_info->ltf_sym = 2;
		} else {
			he_info->gi = 2;
			he_info->ltf_sym = 2;
		}
		break;
	}
	return;
}

static void wl_set_radiotap_he_suext_info(ieee80211_radiotap_he_info * he_info, rx_info_aux_t * prx_info_aux)
{
	//HE_SIG_A1 *phe_siga1 = &prx_info_aux->he_siga1;
	//HE_SIG_A2 *phe_siga2 = &prx_info_aux->he_siga2;

	he_info->kn_ppdu_format = HE_EXT;
	// TBD
	return;
}

// Not tested yet
static void wl_set_radiotap_he_mu_info(ieee80211_radiotap_he_info * he_info, rx_info_aux_t * prx_info_aux)
{
	HE_SIG_A1 *phe_siga1 = &prx_info_aux->he_siga1;
	HE_SIG_A2 *phe_siga2 = &prx_info_aux->he_siga2;

	he_info->kn_ppdu_format = HE_MU;
	he_info->kn_bss_color = 1;
	he_info->bss_color = phe_siga1->mu.bss_color;

	he_info->kn_ul_dl = 1;
	he_info->ul_dl = phe_siga1->mu.ul_dl;

	he_info->kn_data_mcs = 1;
	he_info->data_mcs = phe_siga1->mu.mcs;

	he_info->kn_data_dcm = 1;
	he_info->data_dcm = phe_siga1->mu.dcm;

	//he_info->kn_coding = 1;
	//he_info->coding = he_siga2.mu.coding;

	he_info->kn_stbc = 1;
	he_info->stbc = phe_siga2->mu.stbc;

	he_info->kn_data_bw_ru_allocation = 1;
	he_info->data_bandwidth_ru_allocation = phe_siga1->mu.bandwidth;

	//Ref: p#408 B21-B22 of Table 28-19, HE-SIG-A of 802.11ax spec
	he_info->kn_gi = 1;
	he_info->kn_ltf_symbols = 1;
	switch (phe_siga1->mu.gi_ltf) {
	case 0:
		he_info->gi = 0;
		he_info->ltf_sym = 2;
		break;
	case 1:
		he_info->gi = 0;
		he_info->ltf_sym = 1;
		break;
	case 2:
		he_info->gi = 1;
		he_info->ltf_sym = 1;
		break;
	case 3:
		he_info->gi = 2;
		he_info->ltf_sym = 2;
		break;
	}
	return;
}

static void wl_set_radiotap_he_tb_info(ieee80211_radiotap_he_info * he_info, rx_info_aux_t * prx_info_aux)
{
	//HE_SIG_A1 *phe_siga1 = &prx_info_aux->he_siga1;
	//HE_SIG_A2 *phe_siga2 = &prx_info_aux->he_siga2;

	he_info->kn_ppdu_format = HE_TRIG;
	// TBD
	return;
}

static void wl_set_radiotap_vht_info(ieee80211_radiotap_vht_info * vht_info, rx_info_aux_t * prx_info_aux)
{
	VHT_SIG_A1 *pvht_siga1 = &prx_info_aux->vht_siga1;
	VHT_SIG_A2 *pvht_siga2 = &prx_info_aux->vht_siga2;

	vht_info->kn_stbc = 1;
	vht_info->stbc = pvht_siga1->su.stbc;

	vht_info->kn_txop_ps_not_allow = 1;
	vht_info->txop_ps_not_allow = pvht_siga1->su.txop_ps_not_allow;

	vht_info->kn_guard_intrl = 1;
	vht_info->guard_intrl = pvht_siga2->su.short_gi;

	vht_info->kn_sgi_nsym_disamb = 1;
	vht_info->sgi_nsym_disamb = pvht_siga2->su.sgi_nysm_disamb;

	vht_info->kn_ldpc_ext_ofdma = 1;
	vht_info->ldpc_ext_ofdma = pvht_siga2->su.ldpc_ext_ofdma;

	vht_info->kn_beamform = 1;
	vht_info->beamform = pvht_siga2->beamform;

	vht_info->kn_bandwidth = 1;
	vht_info->bandwidth = pvht_siga1->su.bw;
	switch (pvht_siga1->su.bw) {	//p@2544 of 802.11-2016.pdf, Table 21-12
	case 0:		//20MHz
		vht_info->bandwidth = 0;
		break;
	case 1:		//40MHz
		vht_info->bandwidth = 1;
		break;
	case 2:		//80MHz
		vht_info->bandwidth = 4;
		break;
	case 3:		//160 or 80+80MHz
		vht_info->bandwidth = 11;
		break;
	default:
		vht_info->bandwidth = 0;
	}
	vht_info->mcs = pvht_siga2->su.mcs;
	// nsts: p2544 of 802.11-2016.pdf, Table 21-12, 
	vht_info->nss = pvht_siga1->su.nsts + 1;
	vht_info->coding = pvht_siga2->su.coding;

	//printk("%s(), (bw: %u), (mcs: %u), (coding: %u), (nsts:%u)\n", __func__, 
	//      vht_info->bandwidth, vht_info->mcs, vht_info->coding, vht_info->nss);

	vht_info->kn_gid = 1;
	vht_info->gid = pvht_siga1->su.gid;

	vht_info->kn_p_aid = 1;
	vht_info->part_aid = pvht_siga1->su.part_aid;

	return;
}

static void wl_set_radiotap_lsig(struct ieee80211_radiotap_lsig *plsig, rx_info_aux_t * prx_info_aux)
{
	U32 length = prx_info_aux->ppdu_len;
	// Set to 6M for VHT_PPDU, Ref: 21.3.4.4 of 802.11-2016.pdf
	// Set to 6M for HE PPDU, Ref: 27.3.10.5 of Draft_P802.11ax_D4.0.pdf
	U8 datarate = sig_rate_6m;

	if ((prx_info_aux->rx_mode == BBRX_RM_B) || (prx_info_aux->rx_mode == BBRX_RM_A_G)) {
		datarate = prx_info_aux->ofdm_sig.rate;
	}
	memset(plsig, 0, sizeof(struct ieee80211_radiotap_lsig));
	plsig->data1 |= (IEEE80211_RADIOTAP_LSIG_DATA1_LENGTH_KNOWN | IEEE80211_RADIOTAP_LSIG_DATA1_RATE_KNOWN);
	plsig->data2 = (((length << 4) & IEEE80211_RADIOTAP_LSIG_DATA2_LENGTH) | (datarate & IEEE80211_RADIOTAP_LSIG_DATA2_RATE));
	return;
}

/*
	Transfer the parameters of rx_info to radio_tap 
*/
void wlrxinfo_2_radiotap(rx_info_aux_t * prx_info_aux, generic_buf * pbuf)
{
	struct ieee80211_radiotap_header *pradhdr = (struct ieee80211_radiotap_header *)pbuf->bufpt;
	U8 *pwkbuf;
	U32 *ppres_bit;
	const U32 bit_dbmsig = 1 << IEEE80211_RADIOTAP_DBM_ANTSIGNAL;
	const U32 bit_ant = 1 << IEEE80211_RADIOTAP_ANTENNA;
	const U32 bit_ext = (1 << IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE) | (1 << IEEE80211_RADIOTAP_EXT);
	U16 nss = prx_info_aux->nss;
	U16 nssid;

	// Clear the input buffer       
	memset(pbuf->bufpt, 0, sizeof(pbuf->bufpt));
	pbuf->size = 0;

	// Radio Header
	pbuf->size += sizeof(struct ieee80211_radiotap_header);
	pwkbuf = (U8 *) (pradhdr + 1);

	// NSS#
	for (nssid = 0, ppres_bit = &pradhdr->it_present; nssid < nss; nssid++, ppres_bit++) {
		if (nssid > 0) {
			// << Antenna info >>
			// dbm antenna signal
			// dbm antenna noise
			*ppres_bit = bit_dbmsig | bit_ant;
			pwkbuf += sizeof(U32);
			pbuf->size += sizeof(U32);
		} else {
			// << Generic Info Present, include antenna #1 info >>
			// << Antenna info >>
			// dbm antenna signal
			// dbm antenna noise
			*ppres_bit = bit_dbmsig | bit_ant;
			// Already included in header
			//pwkbuf += sizeof(U32);
			//pbuf->size += sizeof(U32);

			// TSF
			*ppres_bit |= 1 << IEEE80211_RADIOTAP_TSFT;
			// Flags
			//*ppres_bit |= 1 << IEEE80211_RADIOTAP_FLAGS;
			// Channel
			//*ppres_bit |= 1 << IEEE80211_RADIOTAP_CHANNEL;
			//// Channel+
			////*ppres_bit |= 1 << IEEE80211_RADIOTAP_CHANNEL;
			// AMPDU statu
			//*ppres_bit |= 1 << IEEE80211_RADIOTAP_AMPDU_STATUS;
			// VHT_Info, HE Info, HE MU Info
			if (prx_info_aux->rx_mode == BBRX_RM_AC) {
				*ppres_bit |= 1 << IEEE80211_RADIOTAP_VHT;
			} else if (prx_info_aux->rx_mode == BBRX_RM_HE_SU) {
				*ppres_bit |= 1 << IEEE80211_RADIOTAP_HE_INFO;
			} else if (prx_info_aux->rx_mode == BBRX_RM_HE_MU) {
				*ppres_bit |= 1 << IEEE80211_RADIOTAP_HE_INFO;
			}
			// L-SIG
			*ppres_bit |= 1 << IEEE80211_RADIOTAP_LSIG;
		}
		// Present bit
		*ppres_bit |= bit_ext;
	}
	*(ppres_bit - 1) &= ~bit_ext;
	if (pbuf->size % 8) {	//Alignment
		pbuf->size += sizeof(U32);
		pwkbuf += sizeof(U32);

	}
	//Note: "pbuf" is pointing at the optional field now

	// << Generic Info >>
	// TSFT
	//printk("rxTs: %x\n", prxinfo->bbrx_info.rxTs);
	*(U32 *) pwkbuf = prx_info_aux->rxTs;
	pwkbuf += sizeof(U32);
	//printk("rxTsH: %x\n", prxinfo->bbrx_info.rxTsH);
	*(U32 *) pwkbuf = prx_info_aux->rxTsH;
	pwkbuf += sizeof(U32);
	pbuf->size += 8;
	// Flags
	/*{
	   pwkbuf += sizeof(U8);
	   } */
	// Channel
	/*{
	   U32          *pchnl = (U32*)pwkbuf;

	   pwkbuf += sizeof(U8);
	   } */
	// << Antenna Info #0>>
	//Antenna signal:
	// Format of rssi_info.x: 12.8, format of antenna_signal of radiotap: s8
	*pwkbuf = prx_info_aux->rssi_info.a >> 4;
	pwkbuf++;
	pbuf->size++;
	//Antenna
	*pwkbuf = 1;
	pwkbuf++;
	pbuf->size++;

	// VHT_Info
	if (prx_info_aux->rx_mode == BBRX_RM_AC) {
		// Add the VHT Info
		ieee80211_radiotap_vht_info *vht_info = (ieee80211_radiotap_vht_info *) pwkbuf;

		wl_set_radiotap_vht_info(vht_info, prx_info_aux);

		pwkbuf += sizeof(ieee80211_radiotap_vht_info);
		pbuf->size += sizeof(ieee80211_radiotap_vht_info);
	} else if (prx_info_aux->rx_mode == BBRX_RM_HE_SU) {	// HE Info, HE SU pkts
		ieee80211_radiotap_he_info *he_info = (ieee80211_radiotap_he_info *) pwkbuf;

		wl_set_radiotap_he_su_info(he_info, prx_info_aux);
		he_info->nsts = nss;

		pwkbuf += sizeof(ieee80211_radiotap_he_info);
		pbuf->size += sizeof(ieee80211_radiotap_he_info);
	} else if (prx_info_aux->rx_mode == BBRX_RM_HE_EXT_SU) {	// HE Info, HE EU SU pkts
		ieee80211_radiotap_he_info *he_info = (ieee80211_radiotap_he_info *) pwkbuf;

		wl_set_radiotap_he_suext_info(he_info, prx_info_aux);
		he_info->nsts = nss;
		pwkbuf += sizeof(ieee80211_radiotap_he_info);
		pbuf->size += sizeof(ieee80211_radiotap_he_info);
	} else if (prx_info_aux->rx_mode == BBRX_RM_HE_MU) {	// HE Info, HE MU pkts
		ieee80211_radiotap_he_info *he_info = (ieee80211_radiotap_he_info *) pwkbuf;

		wl_set_radiotap_he_mu_info(he_info, prx_info_aux);
		he_info->nsts = nss;

		pwkbuf += sizeof(ieee80211_radiotap_he_info);
		pbuf->size += sizeof(ieee80211_radiotap_he_info);
	} else if (prx_info_aux->rx_mode == BBRX_RM_HE_TRIG_BASED) {	// HE Info, HE TB pkts
		ieee80211_radiotap_he_info *he_info = (ieee80211_radiotap_he_info *) pwkbuf;

		wl_set_radiotap_he_tb_info(he_info, prx_info_aux);
		he_info->nsts = nss;
		pwkbuf += sizeof(ieee80211_radiotap_he_info);
		pbuf->size += sizeof(ieee80211_radiotap_he_info);
	}
	// << L-SIG Info >>
	{
		wl_set_radiotap_lsig((struct ieee80211_radiotap_lsig *)pwkbuf, prx_info_aux);
		pwkbuf += sizeof(struct ieee80211_radiotap_lsig);
		pbuf->size += sizeof(struct ieee80211_radiotap_lsig);
	}

	// << Antenna Info >>
	for (nssid = 1; nssid < nss; nssid++) {
		//Antenna signal:
		//*pwkbuf = prxinfo->bbrx_info.pm_rssi_dbm_b;
		// Format of rssi_info.x: 12.8, format of antenna_signal of radiotap: s8
		*pwkbuf = prx_info_aux->rssi_info.b >> 4;
		pwkbuf++;
		pbuf->size++;
		//Antenna
		*pwkbuf = nssid + 1;
		pwkbuf++;
		pbuf->size++;
	}

	// Last: Fill the length of the header
	pradhdr->it_len = pbuf->size;
/*
if (prxinfo->bbrx_info.rx_mode == BBRX_RM_AC) {
	printk("RadioTap for VHT:\n");
	mwl_hex_dump(pbuf->bufpt, pbuf->size);
}*/
/*if (prxinfo->bbrx_info.rx_mode == BBRX_RM_HE_SU) {
	printk("RadioTap for HE:\n");
	mwl_hex_dump(pbuf->bufpt, pbuf->size);
}*/
	return;
}

static void wlrxinfo_2_rxhisto(DRV_RATE_HIST * pdrv_rx_hist, rx_info_aux_t * prx_info_aux)
{
	dbRateInfo_t *prate_info = &prx_info_aux->rate_info;
	U8 nssid, bwid, giltfid, mcsid;
	switch (prx_info_aux->rx_mode) {
	case BBRX_RM_A_G:
	case BBRX_RM_B:
	case BBRX_RM_GREEN_FIELD:
		// Legacy rate
		// TBD
		break;
	case BBRX_RM_N:
		bwid = (prate_info->Bandwidth) % QS_NUM_SUPPORTED_11N_BW;
		giltfid = (prate_info->ShortGI) % QS_NUM_SUPPORTED_GI;
		mcsid = prate_info->RateIDMCS % QS_NUM_SUPPORTED_MCS;
		pdrv_rx_hist->HtRates[bwid][giltfid][mcsid]++;
		//wlrxinfo_2_n_rxhisto(pdrv_rx_hist, prxinfo, msdu_cnt, name);
		break;
	case BBRX_RM_AC:
		nssid = (prx_info_aux->nss - 1) % QS_NUM_SUPPORTED_11AC_NSS_BIG;
		bwid = (prate_info->Bandwidth) % QS_NUM_SUPPORTED_11AC_BW;
		giltfid = (prate_info->ShortGI) % QS_NUM_SUPPORTED_GI;
		mcsid = prate_info->RateIDMCS & 0xf;
		pdrv_rx_hist->VHtRates[nssid][bwid][giltfid][mcsid]++;
		//wlrxinfo_2_ac_rxhisto(pdrv_rx_hist, prxinfo, msdu_cnt, name);
		break;
	case BBRX_RM_HE_SU:
	case BBRX_RM_HE_EXT_SU:
	case BBRX_RM_HE_MU:
		// HE rate
		nssid = (prx_info_aux->nss - 1) % QS_NUM_SUPPORTED_11AX_NSS;
		bwid = (prate_info->Bandwidth) % QS_NUM_SUPPORTED_11AX_BW;
		giltfid = (prate_info->ShortGI) % QS_NUM_SUPPORTED_11AX_GILTF_EXT;
		mcsid = prate_info->RateIDMCS & 0xf;
		pdrv_rx_hist->HERates[nssid][bwid][giltfid][mcsid]++;
		//wlrxinfo_2_he_rxhisto(pdrv_rx_hist, prxinfo, msdu_cnt, name);
		break;
	case BBRX_RM_HE_TRIG_BASED:
		// Note: sigb does not present in UL-TB packet
		//      => Set nss=1 (TBD: set the correct value)
		nssid = (0) % QS_NUM_SUPPORTED_11AX_NSS;
		bwid = (prate_info->Bandwidth) % QS_NUM_SUPPORTED_11AX_BW;
		giltfid = (prate_info->ShortGI) % QS_NUM_SUPPORTED_11AX_GILTF_EXT;
		mcsid = prate_info->RateIDMCS & 0xf;
		pdrv_rx_hist->HERates[nssid][bwid][giltfid][mcsid]++;
		break;
	}
	return;
}

// from: smac
static u32 get_HT_preamble(int mcs)
{
	if (mcs < 8)
		return 36;
	if (mcs < 16)
		return 40;
	if (mcs < 32)
		return 48;
	return 0;
}

// from: smac
static u32 get_VHT_preamble(int nss)
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

//R10000xNbpsc = coding_rate * bits_per_constellation * 10000
#define HE_MCS_MAX			12
const u32 R10000xNbpsc[HE_MCS_MAX] = { 5000, 10000, 15000, 20000, 30000, 40000, 45000, 50000, 60000, 66667, 75000, 83333 };
const u32 R10000xNbpsc_ofdma[10] = { 5000, 10000, 15000, 20000, 30000, 40000, 45000, 49999, 60000, 66664 };

#define HE_BWTYPE_MAX			4
// Nsd = # of data tones
const u16 Nsd[HE_BWTYPE_MAX] = { 234, 468, 980, 1960 };
const u16 Nsd_ofdma[3] = { 24, 48, 102 };	//up to ru size=3, Asssume 8 STAs

static u32 get_HE_preamble_10x(U16 nss_1, int gi, int ofdma)
{
	// gi_ltf:
	//              3 => ltf_type=4, gi=3.2
	//              2 => ltf_type=2, gi=1.6
	// su: 8+8+4+4+8+4+ Nltf*(3.2*LTF_type+ GI)
	const u32 preamble32us[8] = { 520, 680, 1000, 1000, 1320, 1320, 1640, 1640 };
	const u32 preamble16us[8] = { 440, 520, 600, 680, 760, 840, 920, 1000 };
	// mu: 8+8+4+4+8+ 4*Nsigb + 4 + Nltf*(3.2*LTF_type + GI)
	const u32 preambe32usofdma[8] = { 920, 1080, 1400, 1400, 1720, 1720, 2040, 2040 };
	const u32 preambe16usofdma[8] = { 840, 920, 1080, 1080, 1240, 1240, 1400, 1400 };

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

/*
	Sync rx_info to rx_info_aux_t
*/
static void wl_rx_info_aux_sync(rx_info_aux_t * prx_info_aux, rx_info_ppdu_t * prxinfo)
{
	if (prx_info_aux->rxTs == prxinfo->bbrx_info.rxTs) {
		// Already updated...
		return;
	}
	memset(prx_info_aux, 0, sizeof(rx_info_aux_t));
	// Sync rx_info_aux_t data from rx_info_ppdu_t
	prx_info_aux->ppdu_len = prxinfo->bbrx_info.lenRssiNf;
	prx_info_aux->rx_mode = prxinfo->bbrx_info.rx_mode;
	prx_info_aux->rxTs = prxinfo->bbrx_info.rxTs;
	prx_info_aux->rxTsH = prxinfo->bbrx_info.rxTsH;
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
	prx_info_aux->rate_info.AntSelect = (~(0xff << prx_info_aux->nss)) & 0xff;
	wl_set_rssi_info(&prx_info_aux->rssi_info, (RxSidebandInfo_t *) prxinfo);
	wl_set_nf_info(&prx_info_aux->nf_path, (RxSidebandInfo_t *) prxinfo);

	return;
}

/*
	Calculate the airtime from pktlen/mode/rx_info,
	Reference: tx_bytes2us() in PFW
*/
static U32 wl_airtime_calc(rxppdu_airtime_t * prxppdu_airtm, U32 pktlen)
{
	rx_info_aux_t *prx_info_aux = &prxppdu_airtm->rx_info_aux;
	U16 nss = 0;
	U8 mcs = 0, rate_id = 0;
	U8 bw = 0;
	U8 gi_ltf = 0, sgi = 0;
	u32 Ndbps10x = 0;
	U32 airtime = 0;

	//switch (prxinfo->bbrx_info.rx_mode) {
	switch (prx_info_aux->rx_mode) {
	case BBRX_RM_B:
		rate_id = prx_info_aux->rate_info.RateIDMCS;
		Ndbps10x = (LEGACY_PHY_RATE[(rate_id & 0xf) % IEEEtypes_MAX_DATA_RATES_G] / 100) * NDBPS_FACTOR;
		//maxLen = (Ndbps10x*NSYM_LEGACY - 240)/80;
		if (Ndbps10x != 0) {
			airtime = (pktlen * 80 + 240) * 4 / Ndbps10x + 20;
		} else {
			// Abnormal
			airtime = 0;
		}
		//printk("\t [b mode]: rateid: %u\n", rate_id);
		break;
	case BBRX_RM_A_G:	// ofdm
		rate_id = prx_info_aux->rate_info.RateIDMCS;
		Ndbps10x = (LEGACY_PHY_RATE[(rate_id & 0xf) % IEEEtypes_MAX_DATA_RATES_G] / 100) * NDBPS_FACTOR;
		//maxLen = (Ndbps10x*NSYM_LEGACY - 240)/80;
		if (Ndbps10x != 0) {
			airtime = (pktlen * 80 + 240) * 4 / Ndbps10x + 20;
		} else {
			// Abnormal
			airtime = 0;
		}
		//printk("\t [a/g mode]: rateid: %u\n", rate_id);
		break;
	case BBRX_RM_N:	// N mode
		mcs = prx_info_aux->rate_info.RateIDMCS;
		bw = prx_info_aux->rate_info.Bandwidth;
		sgi = prx_info_aux->rate_info.ShortGI;
		Ndbps10x = (HT_PHY_RATE[mcs % RTBL_MAX_MCS_INDEX][bw & 0x1][0] / 100) * NDBPS_FACTOR / 10;
		//maxLen = (Ndbps10x *((txop-get_HT_preamble(hw_rate_index))*10/(gi?36:40)) - 24)/8;
		//maxLen = MIN(maxLen, 65532);
		if (Ndbps10x != 0) {
			airtime = (pktlen * 8 + 24) / Ndbps10x * ((sgi == 0) ? 36 : 40) / 10 + get_HT_preamble(mcs);
		} else {
			// Abnormal
			airtime = 0;
		}
		//printk("\t [n mode]: (mcs, bw, sig): (%u, %u, %u)\n", mcs, bw, sgi);
		break;
	case BBRX_RM_AC:	// AC mode
		nss = prx_info_aux->nss;
		mcs = prx_info_aux->rate_info.RateIDMCS & 0xf;
		bw = prx_info_aux->rate_info.Bandwidth;
		sgi = prx_info_aux->rate_info.ShortGI;
		Ndbps10x =
		    (VHT_PHY_RATE[bw % VHT_PHYRATE_BW_MAX][mcs % VHT_PHYRATE_MCS_MAX][(nss - 1) % VHT_PHYRATE_NSS_MAX][0] / 100) * NDBPS_FACTOR / 10;
		//maxLen = (Ndbps10x *((txop-get_VHT_preamble(Nss+1))*10/(gi?36:40)) - ((Ndbps10x/216+10)/10)*6- 16)/8;
		if (Ndbps10x != 0) {
			airtime =
			    (pktlen * 8 + 16 + ((Ndbps10x / 216 + 10) / 10) * 6) / Ndbps10x * ((sgi == 0) ? 36 : 40) / 10 + get_VHT_preamble(nss);
		} else {
			// Abnormal
			airtime = 0;
		}
		//printk("\t [ac mode]: (nss, mcs, bw, sgi): (%u, %u, %u, %u)\n", nss, mcs, bw, sgi);
		break;
	case BBRX_RM_HE_SU:	// he mode
	case BBRX_RM_HE_EXT_SU:
	case BBRX_RM_HE_MU:
	case BBRX_RM_HE_TRIG_BASED:
		if ((prx_info_aux->rx_mode == BBRX_RM_HE_MU) || (prx_info_aux->rx_mode == BBRX_RM_HE_TRIG_BASED)) {
			prxppdu_airtm->dbg_mu_pktcnt++;
		} else {
			prxppdu_airtm->dbg_su_pktcnt++;
		}
		nss = prx_info_aux->nss;
		mcs = prx_info_aux->rate_info.RateIDMCS & 0xf;
		bw = prx_info_aux->rate_info.Bandwidth;
		gi_ltf = prx_info_aux->rate_info.ShortGI;
		Ndbps10x = ((nss) * R10000xNbpsc[mcs % HE_MCS_MAX] * Nsd[bw % HE_BWTYPE_MAX]) / 10000;
		//Nsym = (txop-get_HE_preamble_10x(Nss, gi_,0)/10)*10/(gi==3?160:144) - (Nss)/4;
		//maxLen = (Ndbps10x * Nsym - 24)/8;
		if (Ndbps10x != 0) {
			airtime =
			    ((pktlen * 8 + 24) / Ndbps10x + nss / 4) * (gi_ltf == 3 ? 160 : 144) / 10 + get_HE_preamble_10x((nss - 1), gi_ltf,
															    FALSE) / 10;
		} else {
			// Abnormal
			airtime = 0;
		}
		//printk("\t [he mode]: (nss, mcs, bw, gi_ltf): (%u, %u, %u, %u)\n", nss, mcs, bw, gi_ltf);
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
	prxppdu_airtm->dbg_sum_pktlen = pktlen;
	prxppdu_airtm->dbg_Ndbps10x = Ndbps10x;

	return airtime;
}

// rx air_time process
// 
void static wl_proc_rx_airtime(extStaDb_StaInfo_t * StaInfo_p, wlrxdesc_t * pCurCfhul, struct sk_buff *pRxSkBuff)
{
	IEEEtypes_FrameCtl_t *frame_ctlp = (IEEEtypes_FrameCtl_t *) & pCurCfhul->frame_ctrl;
	rxppdu_airtime_t *prxppdu_airtm;

	if (StaInfo_p == NULL) {
		// rx_airtime is per StaInfo 
		return;
	}
	if (!((frame_ctlp->FromDs == 0) && (frame_ctlp->ToDs == 1))) {
		// not ul pkt from a STA
		//printk("Not ul from sta (%u, %u)\n", frame_ctlp->FromDs, frame_ctlp->ToDs);
		return;
	}
	prxppdu_airtm = &StaInfo_p->rxppdu_airtime;
	if (prxppdu_airtm->rx_info_aux.rxTs != pCurCfhul->hdr.timestamp) {
		// New rx ppdu arrives
		//      - Calculate the airtime of the saved ppdu
		if (prxppdu_airtm->rx_datlen > 0) {
			prxppdu_airtm->rx_airtime = wl_airtime_calc(prxppdu_airtm, prxppdu_airtm->rx_datlen);
			prxppdu_airtm->dbg_sum_pktcnt = prxppdu_airtm->dbg_pktcnt;
			prxppdu_airtm->rx_tsf = ktime_get_ns();
			//printk("Update rx airtime: %u, datlen: %u, mode=%u\n", prxppdu_airtm->rx_airtime, prxppdu_airtm->rx_datlen,
			//      prxppdu_airtm->rxinfo.bbrx_info.rx_mode
			//      );
			prxppdu_airtm->sum_rx_airtime += prxppdu_airtm->rx_airtime;
			prxppdu_airtm->sum_rx_pktcnt++;
			prxppdu_airtm->sum_rx_pktlen += prxppdu_airtm->rx_datlen;
		}
		// New PPDU arrives, update the cached rx_info_aux
		memcpy(&prxppdu_airtm->rx_info_aux, &StaInfo_p->rx_info_aux, sizeof(rx_info_aux_t));

		prxppdu_airtm->rx_datlen = pRxSkBuff->len;
		prxppdu_airtm->dbg_pktcnt = 1;
		//printk("[new_pkt]: %u, id=%u\n", pRxSkBuff->len, prxppdu_airtm->rxInfoIndex);
	} else {
		// More msdu packets
		prxppdu_airtm->rx_datlen += pRxSkBuff->len;
		prxppdu_airtm->dbg_pktcnt++;
		//printk("\t[cont]: %u, %u\n", prxppdu_airtm->rx_datlen, pRxSkBuff->len);
	}

	return;
}

/*
	wlrxinfo_notify_new_msdu(): Process the RxInfo of the packet
	- output:
		- RssiPathInfo_t: rssi/nf from the RxInfo
		- generic_buf: radiotap
	- exceptions:
		- IF the time stamp does not match
			- RssiPathInfo_t: Will still use the last one since rssi/nf should be closed to the last one
			- radio_tap: empty once since each packets should have different one
		- If the index == the last one, this rxinf is identical => use the cached one
*/
void wlrxinfo_notify_new_msdu(struct net_device *netdev, wlrxdesc_t * pCurCfhul, u8 qid, struct sk_buff *pmsdu)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	struct drv_stats *wldrvstat_p = &wlpd_p->drv_stats_val;
	struct except_cnt *wlexcept_p = &wlpd_p->except_cnt;
	// Cache the last rxinfo
	//rx_info_aux_t *plst_rxinfo_idx = &wlpd_p->lst_rxinfo_aux;
	//rx_info_ppdu_t    * prxinfo = &wlpd_p->acntRxInfoQueBaseAddr_v[pCurCfhul->hdr.rxInfoIndex];
	U16 rxinfo_idx = pCurCfhul->hdr.rxInfoIndex;
	rx_info_aux_t *prx_info_aux = &wlpd_p->rxinfo_aux_poll[rxinfo_idx];
	rx_info_ppdu_t *prx_info = &wlpd_p->acntRxInfoQueBaseAddr_v[rxinfo_idx];
	generic_buf *pradiotap = &prx_info_aux->radiotap;
	IEEEtypes_FrameCtl_t *frame_ctlp = (IEEEtypes_FrameCtl_t *) & pCurCfhul->frame_ctrl;
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	extStaDb_StaInfo_t *StaInfo_p;

	// Will use the last rssi/nf, and will/won't update the values 
	//(*ppradiotap) = &wlpd_p->radio_info[pCurCfhul->hdr.rxInfoIndex];
	wlexcept_p->total_rxinfo_cnt++;
	if (pCurCfhul->hdr.timestamp != prx_info_aux->rxTs) {
		//WLDBG_ERROR(DBG_LEVEL_0, "Incorrect tm_stamp on cfhul/rx_info=(%x, %x)\n",
		//              pCurCfhul->hdr.timestamp, prxinfo->bbrx_info.rxTs);
		//printk("Incorrect tm_stamp on cfhul/rx_info=(%x, %x), %u\n",
		//              pCurCfhul->hdr.timestamp, prx_info_aux->rxTs, pCurCfhul->hdr.rxInfoIndex);
		if (pCurCfhul->hdr.timestamp == prx_info->bbrx_info.rxTs) {
			wlexcept_p->late_rxinfo_cnt++;
			//printk("Intr of SQ15 is later than SQ0 ==> recover it \n");
			// Interrupt of rx_info (SQ15) is later than SQ0 => update the rxinfo_aux in here
			wl_rx_info_aux_sync(prx_info_aux, prx_info);
		} else {
			// Reset the saved radio_tap
			//(*ppradiotap)->size = 0;
			pradiotap->size = 0;
			wlexcept_p->diff_tm_patch++;
			goto func_final;
		}
	}
	// Time-stamp matchs
	//if ((plst_rxinfo_idx->rxInfoIndex == pCurCfhul->hdr.rxInfoIndex) &&
	//      ((qid != SC5_RXQ_PROMISCUOUS_INDEX))){
	//      // Identical rx_info => Use the last data to save time
	//      plst_rxinfo_idx->msdu_ref_cnt++;
	//      return;
	//}
	// This is the new ppdu, updating the accounting info of the last ppdu
	wlrxinfo_2_rxhisto(&wlpd_p->drvrxRateHistogram, prx_info_aux);
	//plst_rxinfo_idx->msdu_ref_cnt = 1;

	// Update radio_info to the new one
	memcpy(&wlpd_p->rssi_path_info, &prx_info_aux->rssi_info, sizeof(RssiPathInfo_t));
	//wl_set_rssi_info(&wlpd_p->rssi_path_info, &plst_rxinfo_idx->rx_sband_info);
	memcpy(&wlpd_p->NF_path, &prx_info_aux->nf_path, sizeof(NfPathInfo_t));

	if (qid == SC5_RXQ_PROMISCUOUS_INDEX) {
		wlrxinfo_2_radiotap(prx_info_aux, &prx_info_aux->radiotap);
	}
	if (frame_ctlp->Type == IEEE_TYPE_DATA) {
		// Update the rx_info to stadb
		if ((prx_info_aux->StaInfo_p == NULL) || (memcmp(((extStaDb_StaInfo_t *) prx_info_aux->StaInfo_p)->Addr, (IEEEtypes_MacAddr_t *) & pmsdu->data[6], sizeof(IEEEtypes_MacAddr_t)))) {	// different mac address => MU
			// Query the StaDb if it has not been gotten
			prx_info_aux->StaInfo_p = (void *)extStaDb_GetStaInfo(vmacSta_p, (IEEEtypes_MacAddr_t *) & pmsdu->data[6],
									      STADB_SKIP_MATCH_VAP | STADB_FIND_IN_CACHE | STADB_NO_BLOCK);
			wldrvstat_p->rxinfo_stadb_query_cnt++;
		}
		StaInfo_p = (extStaDb_StaInfo_t *) prx_info_aux->StaInfo_p;
		if (StaInfo_p != NULL) {
			// Find the stadb => Cache the rx_info_aux to be used later
			memcpy(&StaInfo_p->rx_info_aux, prx_info_aux, sizeof(rx_info_aux_t));
			memcpy(&StaInfo_p->RSSI_path, &prx_info_aux->rssi_info, sizeof(RssiPathInfo_t));
			wl_proc_rx_airtime(StaInfo_p, pCurCfhul, pmsdu);
			memcpy(&StaInfo_p->nf_path[StaInfo_p->nf_path_id], &prx_info_aux->nf_path, sizeof(NfPathInfo_t));
			StaInfo_p->nf_path_id = (StaInfo_p->nf_path_id + 1) % NUM_NFPATH_BUF_MAX;
		} else {
			//printk("Can't find the stadb (%02x:%02x:%02x:%02x:%02x:%02x)\n",
			//      pmsdu->data[6], pmsdu->data[7], pmsdu->data[8],
			//      pmsdu->data[9], pmsdu->data[10], pmsdu->data[11]
			//      );
		}
	}

 func_final:
	return;
}

void wlrxinfo_qproc(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	struct bqm_args *pbqm_args = &wlpd_p->bmq_args;
	unsigned long flags;
	UINT32 RAcntQId;
	u8 qid;

	local_irq_save(flags);
	RAcntQId = wlpptr->RAcntQId;
	wlpptr->RAcntQId = 0;
	local_irq_restore(flags);

	for (qid = pbqm_args->racntq_index; qid < pbqm_args->racntq_index + pbqm_args->racntq_num; qid++) {
		struct wldesc_data *wlqm = &wlpptr->wlpd_p->descData[qid];
		u32 wrinx;
		wlqm->sq.wrinx = wrinx = wlQueryWrPtr(netdev, qid, SC5_SQ);
		WLDBG_DATA(DBG_LEVEL_3, "(rd, wr)=(%d, %d)\n", wlqm->sq.rdinx, wlqm->sq.wrinx);

		//printk("%s, (rd, wr)=(%d, %d)\n", netdev->name, wlqm->sq.rdinx, wlqm->sq.wrinx);
		if (wlqm->sq.wrinx == wlqm->sq.rdinx) {
			// Queue is empty => do nothing
			continue;
		}
		while (wrinx != wlqm->sq.rdinx) {
			// Process items one by one
			//printk("Updateing rxinfo[%u], %x\n", wlqm->sq.rdinx, wlpd_p->acntRxInfoQueBaseAddr_v[wlqm->sq.rdinx].bbrx_info.rxTs);
			wl_rx_info_aux_sync(&wlpd_p->rxinfo_aux_poll[wlqm->sq.rdinx], &wlpd_p->acntRxInfoQueBaseAddr_v[wlqm->sq.rdinx]
			    );
			// Update the rx_index
			wlSQIndexGet(&(wlqm->sq));
		}
		//wlqm->sq.rdinx = wlqm->sq.wrinx;
		wlUpdateRdPtr(netdev, qid, SC5_SQ, wlqm->sq.rdinx, false);
	}

	return;
}
