/** @file ap8xLnxRxInfo.h
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
#ifndef AP8X_RXINFO_H
#define AP8X_RXINFO_H
#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/wireless.h>
#include <linux/ieee80211.h>
#include "ap8xLnxBQM.h"
#include "wl_hal.h"

#define SMAC_CFHUL_MAC_HDR_OFFSET  48

#pragma pack (push, 1)
typedef struct BBRX_RX_INFO_st {
	union {
		U32 rx_info_0;	// 0x00 rx_info_0 vhtsigb[30:8], rx_sig[7:0]
		struct {
			U32 rx_sig:8;
			U32 vhtsigbSig:23;
			U32 rx_info_0_resv:1;
		};
	};

	union {
		U32 rx_info_1;	// 0x04 rx_info_1 len[31:16], rssi[15:8] noise floor[7:0]
		struct {
			U32 rx_nf:8;
			U32 rx_rssi:8;
			U32 lenRssiNf:16;
		};
	};

	union {
		U32 v_htsig1UsrBw;	// 0x08 rx_info_2 htsig1/vhtsiga1[31:8], usr[7:6], bw_misc[4:0]{
		struct {
			U32 hesiga1:2;
			U32 user_id_3:1;
			U32 dup_likely_bw:2;
			U32 user_id_2_0:3;
			U32 htsig1_vhtsiga1_hesiga1:24;
		};
	};
	union {
		U32 pktSigV_htsig2;	// 0x0C rx_info_3 pkt_misc[31:28]{2nd,info}, sig_misc[27:24]{lsig_rsvd,parity,badP,htBadCrc}, htsig2/vhtsiga2[17:0]
		struct {
			U32 htsig2_vhtsiga2_hesiga2:20;
			U32 resv_rx_info_3:4;
			U32 sig_misc:4;
			U32 pkt_misc:4;
		};
	};
	union {
		U32 rssiDbmAb;	// 0x10 rx_info_4 pm rssi dbm b[23:12], a[11:0]
		struct {
			U32 pm_rssi_dbm_a:12;
			U32 pm_rssi_dbm_b:12;
			U32 rx_bbifc_info_4_resv:8;
		};
	};
	union {
		U32 rssiDbmCd;	// 0x14 rx_info_5 pm rssi dbm d[23:12], c[11:0]
		struct {
			U32 pm_rssi_dbm_c:12;
			U32 pm_rssi_dbm_d:12;
			U32 rx_bbifc_info_5_resv:8;
		};
	};
	union {
		U32 nfDbmAb;	// 0x18 rx_info_6 0x0000_0000 pm noise flr dbm a/b rx_info_14
		struct {
			U32 pm_nf_dbm_a:12;
			U32 pm_nf_dbm_b:12;
			U32 rx_bbifc_info_6_resv:8;
		};
	};
	union {
		U32 nfDbmCd;	// 0x1C rx_info_7 0x0000_0000 pm noise flr dbm c/d rx_info_15
		struct {
			U32 pm_nf_dbm_c:12;
			U32 pm_nf_dbm_d:12;
			U32 rx_bbifc_info_7_resv:8;
		};
	};
	union {
		U32 ht_lltfphroll;	// 0x20 rx_info_8 0x0000_0000 gaincode a rx_info_8
		struct {
			U32 pm_rssi_dbm_e:12;
			U32 pm_rssi_dbm_f:12;
			U32 rx_bbifc_info_8_resv:8;
		};
	};
	U32 mucq0GaincodeA;	// 0x24 rx_info_9 0x0000_0000 gaincode a rx_info_8
	U32 gaincodeB;		// 0x28 rx_info_10 0x0000_0000 gaincode b rx_info_9
	U32 gaincodeC;		// 0x2C rx_info_11 0x0000_0000 gaincode c rx_info_10
	U32 gaincodeD;		// 0x30 rx_info_12 0x0000_0000 gaincode d rx_info_11
	union {
		U32 mcvalid11bMode;	// 0x34 rx_info_13 0x0000_0000 pm rssi dbm c/d rx_info_13
		struct {
			U32 info_13_resv:15;
			U32 rx_mode:4;
			U32 rx_preamble_11b:1;
			U32 mu_cq_valid:4;
			U32 info_13_rx_resv:4;
			U32 info_13_resv_1:4;
		};
	};
	U32 dtaCfo;		// 0x38 rx_info_14 0x0000_0000 pm noise flr dbm a/b rx_info_14
	union {
		U32 rx_info_15;
		struct {
			U32 pm_rssi_dbm_g:12;
			U32 pm_rssi_dbm_h:12;
			U32 rx_bbifc_info_15_resv:8;
		};
	};
	union {
		U32 rx_info_16;
		struct {
			U32 pm_nf_dbm_e:12;
			U32 pm_nf_dbm_f:12;
			U32 rx_bbifc_info_16_resv:8;

		};
	};
	union {
		U32 rx_info_17;
		struct {
			U32 pm_nf_dbm_g:12;
			U32 pm_nf_dbm_h:12;
			U32 rx_bbifc_info_17_resv:8;
		};
	};
	U32 rx_info_18;
	U32 rx_info_19;
	U32 rx_info_20;
	U32 rx_info_21;
	union {
		U32 rx_info_22;
		struct {
			U32 hesigb:31;
			U32 resv_rx_info_22:1;
		};
	};
	U32 rx_info_23;
	U32 rx_info_24;
	U32 rx_info_25;
	U32 rx_info_26;
	union {
		U32 rx_info_27;
		struct {
			U32 params:16;	// rx_info_27 [31:16]:symbol_num [15]:tx_timestamp_valid [14]:rx_timestamp_valid [13]:rx_cq_valid [12]:rx_rejected_pkt_ind [11]:pkt_end_ind [10]:rx_pkt_ind [9]:rx_packet_found [8]:ch_busy_ind [7]:cca_sec80_cnt [6]:cca_sec40_cnt [5]:cca_sec_cnt [4]:cca_pri_cnt [3]:cca_sec80 [2]:cca_sec40 [1]:cca_sec [0]:cca_pri
			U32 sym_num:16;
		};
	};
	U32 rxTs;		// rx_info_28 rx timestamp[31:0]
	U32 rxTsH;		// rx_info_29 rx timestamp[39:32]
	U32 txTs;		// rx_info_30 tx timestamp[31:0]
	U32 rxCq;		// rx_info_31 [31:24]:reserved [23:0]:rx_cq[23:0]
	U32 rxinfo_rsvd[16];	//rx_info_32~47
} BBRX_RX_INFO_st;
#pragma pack(pop)

typedef struct {
	BBRX_RX_INFO_st bbrx_info;
	u_int32_t resv[16];
} rx_info_ppdu_t;

typedef struct _generic_buf {
	u_int32_t size;		//Used length of the buffer
	u_int8_t bufpt[256];
} generic_buf;

#pragma pack (push, 1)
// Ref: 17.3.4.1 of 802.11-2016.pdf, Fig 17-5
typedef struct _OFDM_SIG {
	union {
		U32 ofdm_sig;
		struct {
			U32 rate:4;
			U32 r:1;
			U32 length:12;
			U32 p:1;
			U32 signal_tail:6;
		};
	};
} OFDM_SIG;

//Ref: p#2364 of 802.11-2016.pdf, Table 19-11, HT-SIG field
typedef struct _HT_SIG1 {
	union {
		U32 ht_sig1;
		struct {
			U32 mcs:7;
			U32 bw:1;
			U32 ht_len:16;
		};
	};
} HT_SIG1;

typedef struct _HT_SIG2 {
	union {
		U32 ht_sig2;
		struct {
			U32 smoothing:1;
			U32 not_sounding:1;
			U32 resv:1;
			U32 aggr:1;
			U32 stbc:2;
			U32 fec_code:1;
			U32 sgi:1;
			U32 ness:2;
			U32 crc:8;
			U32 tail:6;
		};
	};
} HT_SIG2;

//Ref: p#2543, of 802.11-2016.pdf, Fig 21-18 VHT-SIG-A1 structure
typedef struct _VHT_SIG_A1 {
	union {
		U32 vht_sig_a1;
		struct {
			U32 bw:2;
			U32 resv:1;
			U32 stbc:1;
			U32 gid:6;
			U32 nsts:3;
			U32 part_aid:9;
			U32 txop_ps_not_allow:1;
			U32 resv_1:1;
		} su;
		struct {
			U32 bw:2;
			U32 resv:1;
			U32 stbc:1;
			U32 gid:6;
			U32 mu_0_nsts:3;
			U32 mu_1_nsts:3;
			U32 mu_2_nsts:3;
			U32 mu_3_nsts:3;
			U32 txop_ps_not_allow:1;
			U32 resv_1:1;
		} mu;
	};
} VHT_SIG_A1;

//Ref: p#2543, of 802.11-2016.pdf, Fig 21-19 VHT-SIG-A2 structure
typedef struct _VHT_SIG_A2 {
	union {
		U32 vht_sig_a2;
		struct {
			union {
				struct {
					U8 short_gi:1;
					U8 sgi_nysm_disamb:1;
					U8 coding:1;
					U8 ldpc_ext_ofdma:1;
					U8 mcs:4;
				} su;
				struct {
					U8 short_gi:1;
					U8 sgi_nysm_disamb:1;
					U8 coding:1;
					U8 ldpc_ext_ofdma:1;
					U8 mu_1_coding:1;
					U8 mu_2_coding:1;
					U8 mu_3_coding:1;
					U8 resv:1;
				} mu;
			};
			U16 beamform:1;
			U16 resv:1;
			U16 crc:8;
			U16 tail:6;
		};
	};
} VHT_SIG_A2;

//Ref: p#2552, of 802.11-2016.pdf, Table 21-14 Fields in VHT-SIGB field
typedef struct _VHT_SIG_B {
	union {
		U32 vht_sig_b;
		struct {
			U32 length:16;
			U32 mcs:4;
		} mu_20;
		struct {
			U32 length:17;
			U32 mcs:4;
		} mu_40;
		struct {
			U32 length:19;
			U32 mcs:4;
		} mu_x;
		struct {
			U32 length:17;
		} su_20;
		struct {
			U32 length:19;
		} su_40;
		struct {
			U32 length:21;
		} su_x;
	};
} VHT_SIG_B;

typedef struct _HE_SIG_A1 {
	union {
		U32 he_sig_a1;
		struct {
			U32 format:1;
			U32 beam_change:1;
			U32 ul_dl:1;
			U32 mcs:4;
			U32 dcm:1;
			U32 bss_color:6;
			U32 resv:1;
			U32 sp_reuse:4;
			U32 bandwidth:2;
			U32 gi_ltf:2;
			U32 nts_mid_pri:3;
		} su;
		struct {
			U32 ul_dl:1;
			U32 mcs:3;
			U32 dcm:1;
			U32 bss_color:6;
			U32 sp_reuse:4;
			U32 bandwidth:3;
			U32 sigb_sym_mumimo_usr:4;
			U32 sigb_comp:1;
			U32 gi_ltf:2;
			U32 doppler:1;
		} mu;
		struct {
			U32 format:1;
			U32 bss_color:6;
			U32 sp_reuse_1:4;
			U32 sp_reuse_2:4;
			U32 sp_reuse_3:4;
			U32 sp_reuse_4:4;
			U32 resv:4;
			U32 bandwidth:2;
		} tb;
	};
} HE_SIG_A1;

typedef struct _HE_SIG_A2 {
	union {
		U32 he_sig_a2;
		struct {
			U32 txop:7;
			U32 coding:1;
			U32 ldpc_ext_sym:1;
			U32 stbc:1;
			U32 txbf:1;
			U32 pre_fec_pad:1;
			U32 pe_disamb:1;
			U32 resv:1;
			U32 doppler:1;
			U32 crc:4;
			U32 tail:6;
		} su;
		struct {
			U32 txop:7;
			U32 resv:1;
			U32 ltf_sym_mida_per:3;
			U32 ldpc_ext_sym:1;
			U32 stbc:1;
			U32 prefec_pad:2;
			U32 pe_disamb:1;
			U32 crc:4;
			U32 tail:6;
		} mu;
		struct {
			U32 txop:7;
			U32 resv:9;
			U32 crc:4;
			U32 tail:6;
		} tb;
	};
} HE_SIG_A2;

typedef struct _HE_SIG_B_USR {
	union {
		U32 he_sig_b;
		struct {
			U32 sta_id:11;
			U32 nsts:3;
			U32 tx_beamform:1;
			U32 mcs:4;
			U32 dcm:1;
			U32 coding:1;
		};
	};
} HE_SIG_B_USR;

// BBUD reg[0x200~0x2bc], same with rx_bbifc_info_0 ~ rx_bbifc_info_47
// Ref: SMAC_RX_Registers.html
// Copied from sfw/smac_fw1/include/bbrx.h
enum {
	BBRX_RM_A_G = 0,
	BBRX_RM_B,
	BBRX_RM_N,
	BBRX_RM_GREEN_FIELD,
	BBRX_RM_AC,
	BBRX_RM_HE_SU = 8,
	BBRX_RM_HE_EXT_SU,
	BBRX_RM_HE_MU,
	BBRX_RM_HE_TRIG_BASED
};
#pragma pack(pop)

/*	rx_info + aux info */
typedef struct {
	//U32                   rxInfoIndex;                            // Index of rx_info in the array
	//U16                   msdu_ref_cnt;                           // How many msdu is from this ppdu
	//union {                                                                       // rx_info itself
	//      rx_info_ppdu_t  rx_info;
	//      RxSidebandInfo_t        rx_sband_info;
	//};
	U32 ppdu_len;
	U8 rx_mode;
	U32 rxTs;		// rx_info_28 rx timestamp[31:0]
	U32 rxTsH;		// rx_info_29 rx timestamp[39:32]
	union {
		struct {	// for ag packets
			OFDM_SIG ofdm_sig;
		};
		struct {	// for 11n packets
			HT_SIG1 ht_sig1;
			HT_SIG2 ht_sig2;
		};
		struct {	// for ac packets
			VHT_SIG_A1 vht_siga1;
			VHT_SIG_A2 vht_siga2;
			VHT_SIG_B vht_sigb;
		};
		struct {	// for he packets
			HE_SIG_A1 he_siga1;
			HE_SIG_A2 he_siga2;
			HE_SIG_B_USR hesigb;
		};
	};
	dbRateInfo_t rate_info;	// Saved parameters
	U8 nss;			// dbRateInfo_t->AntSelect is bit maps => save to nss to avoid more calcuation

	RssiPathInfo_t rssi_info;	// rssi result from the sig
	NfPathInfo_t nf_path;	// nf result from sig
	generic_buf radiotap;	// radiotap result from sig
	void *StaInfo_p;
} rx_info_aux_t;

//void wl_proc_rx_airtime(struct net_device *netdev, wlrxdesc_t *pCurCfhul, struct sk_buff *pRxSkBuff);
void wlrxinfo_notify_new_msdu(struct net_device *netdev, wlrxdesc_t * pCurCfhul, u8 qid, struct sk_buff *pmsdu);
void wlrxinfo_2_radiotap(rx_info_aux_t * prx_info_aux, generic_buf * pbuf);
void wlrxinfo_qproc(struct net_device *netdev);

#endif				//AP8X_RXINFO_H
