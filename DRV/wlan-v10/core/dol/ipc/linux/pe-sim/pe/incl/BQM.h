/** @file BQM.h
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

#ifndef __BQM_H__
#define __BQM_H__

#define QUEUE_STAOFFSET            (radio->bss_num * SYSADPT_MAX_TID)

#define SC5_RQ                     0
#define SC5_SQ                     1

#define SC5_RQ_REG_OFFSET          0x00000000
#define SC5_SQ_REG_OFFSET          0x00000040

#define SC5_Q_ADDR_OFFSET          0x00020000
#define SC5_Q_SIZE_OFFSET          0x00020008
#define SC5_Q_THRESHOLD_OFFSET     0x00020018
#define SC5_Q_RDPTR_OFFSET         0x00020024
#define SC5_Q_WRPTR_OFFSET         0x00020028
#define SC5_Q_MAC_CTRL_OFFSET      0x00028000

#define SC5_RQ_RDPTR_OFFSET        0x00020024
#define SC5_RQ_WRPTR_OFFSET        0x00020028
#define SC5_SQ_WRPTR_OFFSET        0x00020064
#define SC5_SQ_RDPTR_OFFSET        0x00020068

#define SC5_Q_BASE_ADDR_REG(q, s)  ((SC5_Q_ADDR_OFFSET + s * SC5_SQ_REG_OFFSET) + ((q) << 8))
#define SC5_Q_SIZE_REG(q, s)       ((SC5_Q_SIZE_OFFSET + s * SC5_SQ_REG_OFFSET) + ((q) << 8))

#define SC5_TXDONE_INT_THRESHOLD   64
#define SC5_TXDONE_INT_TIMEOUT	   0xFF

#define SC5_Q_THRES_REG(q, s)      ((SC5_Q_THRESHOLD_OFFSET + s * SC5_SQ_REG_OFFSET) + ((q) << 8))
#define SC5_Q_MAC_CTRL_REG(q, s)   ((SC5_Q_MAC_CTRL_OFFSET + s * SC5_SQ_REG_OFFSET) + ((q) << 8))

#define SC5_RQ_WRPTR_REG(q)        ((SC5_RQ_WRPTR_OFFSET) + ((q) << 8))
#define SC5_RQ_RDPTR_REG(q)        ((SC5_RQ_RDPTR_OFFSET) + ((q) << 8))
#define SC5_SQ_WRPTR_REG(q)        ((SC5_SQ_WRPTR_OFFSET) + ((q) << 8))
#define SC5_SQ_RDPTR_REG(q)        ((SC5_SQ_RDPTR_OFFSET) + ((q) << 8))

#define REL_RX_BPID(x)             (x & 0x0f)

#define MRVL_HDR_MGMT_EXTRA_BYTES  (sizeof(((mrvl_hdr_t*)0)->QoS) + sizeof(((mrvl_hdr_t*)0)->HTC))	/* Qos + HTC */

#define SQ5_MAC_CTRL_TIMEOUT(t)    (0x003FC000 & (t<<14))

#define PKT_SIGNATURE_SIZE         4
#define PKT_POINTER_OFFSET         (8 + ETH_HLEN)
#define PKT_SIGNATURE_OFFSET       (8 + PKT_SIGNATURE_SIZE + ETH_HLEN)
#define PKT_INFO_SIZE              PKT_SIGNATURE_OFFSET
#define PKT_SIGNATURE              0x424B5324
#define PKT_TAIL_SIGNATURE         0x40454E44
#define PKT_TAIL_SIGNATURE_OFFSET  0x8

#define USED_SIGNATURE             0xdeadbeef
#define BMBUF_SIGNATURE            USED_SIGNATURE
#define HF_OWN_SIGNATURE           0xdeadcafe
#define USED_BUFLEN                0x8000

/* 11454(max mpdu size: 11k amsdu)/64(assuming min packet size is 64) */
#define MAX_AMSDU_SUBFRAME         178

#define HT_CTRL_OFFSET             24
#define HT_CTRL_OFFSET_WITH_ADDR4  30

#define TXBUF_ALIGN                16
#define RXBUF_ALIGN                16

/* BBUD reg[0x200~0x2bc], same with rx_bbifc_info_0 ~ rx_bbifc_info_47
 * Ref: SMAC_RX_Registers.html
 * Copied from sfw/smac_fw1/include/bbrx.h 
 */
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

typedef struct {
	/* DWORD 0 */
	union {
		ca_uint32_t pe0_lo_dword_addr;
		ca_uint32_t bgn_signature;
	};
	/* DWORD 1 */
	union {
		struct {
			ca_uint32_t pe0_hi_byte_addr:8;
			ca_uint32_t attr:8;
			ca_uint32_t resrv0:8;
			ca_uint32_t bpid:8;
		};
		ca_uint32_t end_signature;
	};
	/* DWORD 2 */
	ca_uint32_t pe1_lo_dword_addr;
	/* DWORD 3 */
	ca_uint32_t pe1_hi_byte_addr:8;
	ca_uint32_t resrev1:24;
} bm_pe_hw_t;

typedef struct {
	struct list list;
	ca_uint32_t phy_addr;
	ca_uint8_t *virt_addr;
	ca_uint8_t bpid;
	struct pkt_hdr *pkt;
} bm_pe_t;

typedef struct {
	struct list list;
	ca_uint32_t qlen;
} bm_pe_head_t;

typedef struct {
	/* DWORD 0 */
	ca_uint32_t length:16;
	ca_uint32_t seqnum:16;
	/* DWORD 1 */
	ca_uint32_t wr_offet:4;
	ca_uint32_t swqnum:8;
	ca_uint32_t reserv:1;
	ca_uint32_t qcv:1;
	ca_uint32_t host_int:1;
	ca_uint32_t wrap_null:1;
	ca_uint32_t cfh_length:8;
	ca_uint32_t cfh_format:4;
	ca_uint32_t tag3:4;
	/* DWORD 2 */
	ca_uint32_t l4_chksum:16;
	ca_uint32_t tdest:16;
	/* DWORD 3 */
	ca_uint32_t timestamp;
	/* DWORD 4 */
	union {
		ca_uint32_t lo_dword_addr;
		ca_uint32_t used_signature;
	};
	/* DWORD 5 */
	ca_uint32_t hi_byte_addr:8;
	ca_uint32_t tag4:8;
	ca_uint32_t vmid:8;
	ca_uint32_t bpid:8;
} cfh_header;

#define TXDESC_IPHDR_SIZE 12	/* size_of(ip_hdr0 + ip_hdr1 + ip_hdr2) below */

typedef struct _wltxdesc_t {
	struct {
		/* DWORD 0 */
		ca_uint32_t length:16;
		ca_uint32_t seqnum:16;
		/* DWORD 1 */
		ca_uint32_t wr_offet:4;
		ca_uint32_t swqnum:8;
		ca_uint32_t comm_reserv:1;
		ca_uint32_t qcv:1;
		ca_uint32_t host_int:1;
		ca_uint32_t wrap_null:1;
		ca_uint32_t cfh_length:8;
		ca_uint32_t cfh_format:4;
		ca_uint32_t tag3:4;
		/* DWORD 2 */
		union {
			struct {
				ca_uint32_t l4_chksum:16;
				ca_uint32_t tdest:16;
			};
			ca_uint32_t pkt_addr;
		};
		/* DWORD 3 */
		ca_uint32_t timestamp;
		/* DWORD 4 */
		union {
			ca_uint32_t lo_dword_addr;
			ca_uint32_t used_signature;
		};
		/* DWORD 5 */
		ca_uint32_t hi_byte_addr:8;
		ca_uint32_t tag4:8;
		ca_uint32_t vmid:8;
		ca_uint32_t bpid:8;
	} hdr;
	/* DWORD 6 */
	ca_uint32_t qid:13;
	ca_uint32_t mpdu_flag:1;
	ca_uint32_t ndr:1;
	ca_uint32_t vtv:1;
	ca_uint32_t llt:3;
	ca_uint32_t len_ovr:4;
	ca_uint32_t reserv:1;
	ca_uint32_t txd1_drop_reason:8;
	/* DWORD 7 */
	ca_uint32_t mpdu_frame_ctrl:16;
	ca_uint32_t da0:16;
	/* DWORD 8 */
	ca_uint32_t da1;
	/* DWORD 9 */
	ca_uint32_t sa0;
	/* DWORD 10 */
	ca_uint32_t sa1:16;
	ca_uint32_t pcp:3;
	ca_uint32_t cfi:1;
	ca_uint32_t vlan_id:12;
	/* DWORD 11 */
	ca_uint32_t mpdu_ht_a_ctrl;
	/* DWORD 12 */
	ca_uint32_t snap1;
	union {
		struct {
			/* DWORD 13 */
			ca_uint32_t ip_hdr0;
			/* DWORD 14 */
			ca_uint32_t ip_hdr1;
			/* DWORD 15 */
			ca_uint32_t ip_hdr2;
		};
		ca_uint32_t ip_hdr[3];
	};
} wltxdesc_t;

typedef struct _wlrxdesc_t {
	struct {
		/* DWORD 0 */
		ca_uint32_t length:16;
		ca_uint32_t seqnum:16;
		/* DWORD 1 */
		ca_uint32_t wr_offet:4;
		ca_uint32_t swqnum:8;
		ca_uint32_t reserv_0:1;
		ca_uint32_t qcv:1;
		ca_uint32_t host_int:1;
		ca_uint32_t wrap_null:1;
		ca_uint32_t cfh_length:8;
		ca_uint32_t cfh_format:4;
		ca_uint32_t tag3:4;
		/* DWORD 2 */
		union {
			struct {
				ca_uint32_t l4_chksum:16;
				ca_uint32_t tdest:16;
			};
			struct {
				ca_uint32_t rxInfoIndex:16;
				ca_uint32_t mpduInfoIndex:16;
			};
		};
		/* DWORD 3 */
		ca_uint32_t timestamp;
		/* DWORD 4 */
		union {
			ca_uint32_t lo_dword_addr;
			ca_uint32_t used_signature;
		};
		/* DWORD 5 */
		ca_uint32_t hi_byte_addr:8;
		ca_uint32_t tag4:8;
		ca_uint32_t vmid:8;
		ca_uint32_t bpid:8;
	} hdr;

	/* DWORD 6 */
	ca_uint16_t frame_ctrl;
	ca_uint16_t cfh_offset:15;
	ca_uint16_t fcs_state:1;
	/* DWORD 7 */
	ca_uint32_t mpdu_flag:1;
	ca_uint32_t qos:4;
	ca_uint32_t sb_index:11;
	ca_uint32_t fpkt:1;
	ca_uint32_t lpkt:1;
	ca_uint32_t hdrFormat:1;
	ca_uint32_t mic_err:1;
	ca_uint32_t icv_err:1;
	ca_uint32_t euMode:3;
	ca_uint32_t macHdrLen:8;
	/* DWORD 8-31 */
	ca_uint32_t nss_hdr[24];
} wlrxdesc_t;

typedef struct {
#ifdef CORTINA_TUNE_HW_CPY_RX
	wlrxdesc_t *rxdesc;
#else
	wlrxdesc_t rxdesc[MAX_AMSDU_SUBFRAME];
#endif
	ca_uint32_t idx;
} wl_cfhul_amsdu_t;

typedef struct {
	ca_uint32_t buf_size;
	bm_pe_t *pe;
	bm_pe_head_t pe_list;
} wl_bm_t;

/* there is one entry gap between wrinx and rdinx. */
typedef struct {
	void *virt_addr;
#ifdef LINUX_PE_SIM
	dma_addr_t phys_addr;
#else
	ca_uint32_t phys_addr;
#endif
	ca_uint32_t qsize;
	ca_uint32_t rdinx;	/* current index data not read yet */
	ca_uint32_t wrinx;	/* current index data just filled yet */
	wl_bm_t bm;
} wl_qpair_rq_t;

typedef struct {
	void *virt_addr;
#ifdef LINUX_PE_SIM
	dma_addr_t phys_addr;
#else
	ca_uint32_t phys_addr;
#endif
	ca_uint32_t qsize;
	ca_uint32_t rdinx;
	ca_uint32_t wrinx;
	wl_bm_t bm;
} wl_qpair_sq_t;

typedef struct {
	//DWORD_0 ~ 3
	ca_uint32_t rsv_0[4];
	//DWORD_4
	ca_uint32_t rssi_dbm_a:12;
	ca_uint32_t rssi_dbm_b:12;
	ca_uint32_t rsv_rssi_ab:8;
	//DWORD_5
	ca_uint32_t rssi_dbm_c:12;
	ca_uint32_t rssi_dbm_d:12;
	ca_uint32_t rsv_rssi_cd:8;
	//DWORD_6
	ca_uint32_t nf_dbm_a:12;
	ca_uint32_t nf_dbm_b:12;
	ca_uint32_t rsv_nf_ab:8;
	//DWORD_7
	ca_uint32_t nf_dbm_c:12;
	ca_uint32_t nf_dbm_d:12;
	ca_uint32_t rsv_nf_cd:8;
	//DWORD_8
	ca_uint32_t rssi_dbm_e:12;
	ca_uint32_t rssi_dbm_f:12;
	ca_uint32_t rsv_rssi_ef:8;
	//DWORD_9~14
	ca_uint32_t rsv_1[6];
	//DWORD_15
	ca_uint32_t rssi_dbm_g:12;
	ca_uint32_t rssi_dbm_h:12;
	ca_uint32_t rsv_rssi_gh:8;
	//DWORD_16
	ca_uint32_t nf_dbm_e:12;
	ca_uint32_t nf_dbm_f:12;
	ca_uint32_t rsv_nf_ef:8;
	//DWORD_17
	ca_uint32_t nf_dbm_g:12;
	ca_uint32_t nf_dbm_h:12;
	ca_uint32_t rsv_nf_gh:8;
	//DWORD_18~27
	ca_uint32_t rsv_2[10];
	//DWORD_28
	ca_uint32_t rxTs;	//rx_info_28, rx timestamp[31:0]
	//DWORD_29
	ca_uint32_t rxTsH;	//rx_info_29,   rx timestamp[39:32]
	//DWORD_30
	ca_uint32_t txTs;	//rx_info_30, tx timestamp[31:0]
	//DWORD_31
	ca_uint32_t rxCq;	//rx_info_31    [31:24]: reserved, [23:0]:rx_cq[23:0]
} __packed RxSidebandInfo_t;

typedef struct _rssi_path_val {
	union {
		struct {
			int16 fval:4;
			int16 ival:8;
		};
		int16 val;
	};
} RssiPathVal;

typedef struct {
	ca_uint32_t a:12;
	ca_uint32_t b:12;
	ca_uint32_t rsv1:8;

	ca_uint32_t c:12;
	ca_uint32_t d:12;
	ca_uint32_t rsv2:8;

	ca_uint32_t e:12;
	ca_uint32_t f:12;
	ca_uint32_t rsv3:8;
	ca_uint32_t g:12;
	ca_uint32_t h:12;
	ca_uint32_t rsv4:8;
} __packed RssiPathInfo_t;

typedef struct NfPathInfo_s {
	ca_uint32_t a:12;
	ca_uint32_t b:12;
	ca_uint32_t rsv1:8;

	ca_uint32_t c:12;
	ca_uint32_t d:12;
	ca_uint32_t rsv2:8;
	ca_uint32_t e:12;
	ca_uint32_t f:12;
	ca_uint32_t rsv3:8;
	ca_uint32_t g:12;
	ca_uint32_t h:12;
	ca_uint32_t rsv4:8;
} __packed NfPathInfo_t;

typedef enum {			// pkt type of rate info
	rtinfo_pkt_legacy = 0,
	rtinfo_pkt_11n,
	rtinfo_pkt_11ac,
	rtinfo_pkt_11ax
} rate_info_pkt_type_t;

enum {
	vht_bw_20 = 0,
	vht_bw_40,
	vht_bw_80,
	vht_bw_160_80p80
};

enum {
	rateid_b_1m = 0,	// 0 ~ 4, 11b
	rateid_b_2m,
	rateid_b_5p5m,
	rateid_b_11m,
	rateid_b_22m,
	rateid_ag_6m,		// 5 ~ 13, 11g/a
	rateid_ag_9m,
	rateid_ag_12m,
	rateid_ag_18m,
	rateid_ag_24m,
	rateid_ag_36m,
	rateid_ag_48m,
	rateid_ag_54m,
	rateid_ag_72m
};

typedef struct {
	ca_uint16_t len;
	ca_uint16_t tag;
	IEEEtypes_FrameCtl_t FrmCtl;
	ca_uint8_t dur[2];
	ca_uint8_t addr1[ETH_ALEN];
	ca_uint8_t addr2[ETH_ALEN];
	ca_uint8_t addr3[ETH_ALEN];
	ca_uint8_t seq[2];
	ca_uint8_t addr4[ETH_ALEN];
	ca_uint16_t QoS;
	ca_uint32_t HTC;
} __packed mrvl_hdr_t;

typedef struct _generic_buf {
	ca_uint32_t size;	//Used length of the buffer
	ca_uint8_t bufpt[256];
} __packed generic_buf;

typedef struct _OFDM_SIG {
	union {
		ca_uint32_t ofdm_sig;
		struct {
			ca_uint32_t rate:4;
			ca_uint32_t r:1;
			ca_uint32_t length:12;
			ca_uint32_t p:1;
			ca_uint32_t signal_tail:6;
		};
	};
} __packed OFDM_SIG;

typedef struct _HT_SIG1 {
	union {
		ca_uint32_t ht_sig1;
		struct {
			ca_uint32_t mcs:7;
			ca_uint32_t bw:1;
			ca_uint32_t ht_len:16;
		};
	};
} __packed HT_SIG1;

typedef struct _HT_SIG2 {
	union {
		ca_uint32_t ht_sig2;
		struct {
			ca_uint32_t smoothing:1;
			ca_uint32_t not_sounding:1;
			ca_uint32_t resv:1;
			ca_uint32_t aggr:1;
			ca_uint32_t stbc:2;
			ca_uint32_t fec_code:1;
			ca_uint32_t sgi:1;
			ca_uint32_t ness:2;
			ca_uint32_t crc:8;
			ca_uint32_t tail:6;
		};
	};
} __packed HT_SIG2;

typedef struct _VHT_SIG_B {
	union {
		ca_uint32_t vht_sig_b;
		struct {
			ca_uint32_t length:16;
			ca_uint32_t mcs:4;
		} mu_20;
		struct {
			ca_uint32_t length:17;
			ca_uint32_t mcs:4;
		} mu_40;
		struct {
			ca_uint32_t length:19;
			ca_uint32_t mcs:4;
		} mu_x;
		struct {
			ca_uint32_t length:17;
		} su_20;
		struct {
			ca_uint32_t length:19;
		} su_40;
		struct {
			ca_uint32_t length:21;
		} su_x;
	};
} __packed VHT_SIG_B;

typedef struct _VHT_SIG_A1 {
	union {
		ca_uint32_t vht_sig_a1;
		struct {
			ca_uint32_t bw:2;
			ca_uint32_t resv:1;
			ca_uint32_t stbc:1;
			ca_uint32_t gid:6;
			ca_uint32_t nsts:3;
			ca_uint32_t part_aid:9;
			ca_uint32_t txop_ps_not_allow:1;
			ca_uint32_t resv_1:1;
		} su;
		struct {
			ca_uint32_t bw:2;
			ca_uint32_t resv:1;
			ca_uint32_t stbc:1;
			ca_uint32_t gid:6;
			ca_uint32_t mu_0_nsts:3;
			ca_uint32_t mu_1_nsts:3;
			ca_uint32_t mu_2_nsts:3;
			ca_uint32_t mu_3_nsts:3;
			ca_uint32_t txop_ps_not_allow:1;
			ca_uint32_t resv_1:1;
		} mu;
	};
} __packed VHT_SIG_A1;

typedef struct _VHT_SIG_A2 {
	union {
		ca_uint32_t vht_sig_a2;
		struct {
			union {
				struct {
					ca_uint8_t short_gi:1;
					ca_uint8_t sgi_nysm_disamb:1;
					ca_uint8_t coding:1;
					ca_uint8_t ldpc_ext_ofdma:1;
					ca_uint8_t mcs:4;
				} su;
				struct {
					ca_uint8_t short_gi:1;
					ca_uint8_t sgi_nysm_disamb:1;
					ca_uint8_t coding:1;
					ca_uint8_t ldpc_ext_ofdma:1;
					ca_uint8_t mu_1_coding:1;
					ca_uint8_t mu_2_coding:1;
					ca_uint8_t mu_3_coding:1;
					ca_uint8_t resv:1;
				} mu;
			};
			ca_uint16_t beamform:1;
			ca_uint16_t resv:1;
			ca_uint16_t crc:8;
			ca_uint16_t tail:6;
		};
	};
} __packed VHT_SIG_A2;

typedef struct _HE_SIG_A1 {
	union {
		ca_uint32_t he_sig_a1;
		struct {
			ca_uint32_t format:1;
			ca_uint32_t beam_change:1;
			ca_uint32_t ul_dl:1;
			ca_uint32_t mcs:4;
			ca_uint32_t dcm:1;
			ca_uint32_t bss_color:6;
			ca_uint32_t resv:1;
			ca_uint32_t sp_reuse:4;
			ca_uint32_t bandwidth:2;
			ca_uint32_t gi_ltf:2;
			ca_uint32_t nts_mid_pri:3;
		} su;
		struct {
			ca_uint32_t ul_dl:1;
			ca_uint32_t mcs:3;
			ca_uint32_t dcm:1;
			ca_uint32_t bss_color:6;
			ca_uint32_t sp_reuse:4;
			ca_uint32_t bandwidth:3;
			ca_uint32_t sigb_sym_mumimo_usr:4;
			ca_uint32_t sigb_comp:1;
			ca_uint32_t gi_ltf:2;
			ca_uint32_t doppler:1;
		} mu;
		struct {
			ca_uint32_t format:1;
			ca_uint32_t bss_color:6;
			ca_uint32_t sp_reuse_1:4;
			ca_uint32_t sp_reuse_2:4;
			ca_uint32_t sp_reuse_3:4;
			ca_uint32_t sp_reuse_4:4;
			ca_uint32_t resv:4;
			ca_uint32_t bandwidth:2;
		} tb;
	};
} __packed HE_SIG_A1;

typedef struct _HE_SIG_A2 {
	union {
		ca_uint32_t he_sig_a2;
		struct {
			ca_uint32_t txop:7;
			ca_uint32_t coding:1;
			ca_uint32_t ldpc_ext_sym:1;
			ca_uint32_t stbc:1;
			ca_uint32_t txbf:1;
			ca_uint32_t pre_fec_pad:1;
			ca_uint32_t pe_disamb:1;
			ca_uint32_t resv:1;
			ca_uint32_t doppler:1;
			ca_uint32_t crc:4;
			ca_uint32_t tail:6;
		} su;
		struct {
			ca_uint32_t txop:7;
			ca_uint32_t resv:1;
			ca_uint32_t ltf_sym_mida_per:3;
			ca_uint32_t ldpc_ext_sym:1;
			ca_uint32_t stbc:1;
			ca_uint32_t prefec_pad:2;
			ca_uint32_t pe_disamb:1;
			ca_uint32_t crc:4;
			ca_uint32_t tail:6;
		} mu;
		struct {
			ca_uint32_t txop:7;
			ca_uint32_t resv:9;
			ca_uint32_t crc:4;
			ca_uint32_t tail:6;
		} tb;
	};
} __packed HE_SIG_A2;

typedef struct _HE_SIG_B_USR {
	union {
		ca_uint32_t he_sig_b;
		struct {
			ca_uint32_t sta_id:11;
			ca_uint32_t nsts:3;
			ca_uint32_t tx_beamform:1;
			ca_uint32_t mcs:4;
			ca_uint32_t dcm:1;
			ca_uint32_t coding:1;
		};
	};
} __packed HE_SIG_B_USR;

int BQM_init(int rid);

void BQM_post_init_bq_idx(int rid);

void BQM_deinit(int rid);

#endif /* __BQM_H__ */
