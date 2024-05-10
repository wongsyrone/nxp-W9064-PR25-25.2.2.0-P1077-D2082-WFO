/** @file shal_txinfo.h
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

/**
 * @file
 * @brief SMAC TX Info definitions.
 *
 * @if Marvell_internal_doc
 * @note The definitions in this file are shared with the System Team.
 * @endif
 */

#ifndef _SHAL_TXINFO_H_
#define _SHAL_TXINFO_H_

#define MAX_MUMIMO_USERS      8	///< Maximum number of MU-MIMO users
#define MAX_OFDMA_USERS       SMAC_MAX_OFDMA_USERS	///< Maximum number of OFDMA users

/// Maximum number of users. For now, MU-MIMO or OFDMA cannot be used at the
/// same time.
#define MAX_USERS             SHAL_MAX(MAX_MUMIMO_USERS, MAX_OFDMA_USERS-2)

/// txActSub
#define BBTX_ACT_SUB_PRI20M         0
#define BBTX_ACT_SUB_PRI40M         1
#define BBTX_ACT_SUB_PRI80M         2
#define BBTX_ACT_SUB_PRI160M        3
#define BBTX_ACT_SUB_PRI20M_DUP40M  5
#define BBTX_ACT_SUB_PRI20M_DUP80M  6
#define BBTX_ACT_SUB_PRI20M_DUP160M 7

/// Baseband TX mode
typedef enum {
	BB_MODE_OFDM = 0,	///< 11a mode
	BB_MODE_DSSS = 1,	///< 11b mode
	BB_MODE_HTMF = 2,	///< 11n mode
	BB_MODE_HTGF = 3,	///< 11n greenfield mode
	BB_MODE_VHT = 4,	///< 11ac mode
	BB_MODE_HE = 8,		///< 11ax SU mode
	BB_MODE_HE_EXT_SU = 9,	///< 11ax EXT_SU mode
	BB_MODE_HE_MU = 10,	///< 11ax MU mode
	BB_MODE_HE_TRIG_BASED = 11,	///< 11ax mode trigger based
	BB_MODE_MAX = BB_MODE_HE_TRIG_BASED,
} BB_MODE_t;

/// Bandwidth
typedef enum {
	BW_20MHz = 0,		///< 20 MHz
	BW_40MHz,		///< 40 MHz
	BW_80MHz,		///< 80 MHz
	BW_160MHz,		///< 160 MHz
	BW_MAX,			///< OUT_OF_RANGE        
} BW_t;

/// Forward error correction
typedef enum {
	FEC_BCC = 0,		///< BCC
	FEC_LDPC,		///< LDPC
} FEC_t;

/// Per non-OFDMA user information
typedef struct {
	U8 mcs;			///< MCS
	U8 fec_type;		///< FEC type. See ::FEC_t. set to U8 to reduce size
	U8 nss;			///< Number of spatial streams
	U8 rsvd1;
	U16 stnid;
	U16 rsvd2;
	U32 rateinfo;		///< for accounting record
	U32 rsvd3[2];
} USER_t;

/// Per OFDMA-user information
typedef struct {
	U8 MCS_OFDMA;		///< MCS
	U8 fec_type_OFDMA;	///< FEC type. See ::FEC_t. set to U8 to reduce size
	U8 nss_OFDMA;		///< Number of spatial streams
	U8 STBC_OFDMA;		///< 0: STBC disabled, 1: STBC enabled

	U8 DCM_OFDMA;		///< Dual Carrier Modulation. 0: Disabled, 1: Enabled
	U8 txbf_flag_OFDMA;	///< Set to 1 if a beamforming steering matrix is applied to the waveform
	U8 ru_alloc_size_OFDMA;	///< @todo Check in stdUtils.c to see how this is obtained from nTotalTones_OFDMA
	U8 OFDMA_user_RU;	///< Number of User in each RU when OFDMA is enabled

	U8 HESIGB_usercontent_chIdx_RU;	///< 1: RU belongs to channel 1, 2: RU belongs to channel 2,
	///< 12: RU is in both channel 1 and channel 2
	U8 ss_alloc;		///< Used for TB uplink

	U16 pwr_scaling;

	U16 sta_id;		//!< per user Station id 0-2047; if 2046 it is a null RU
	U16 stnid;

	U32 rateinfo;		///< for accounting record
} USER_OFDMA_t;

typedef struct {
	U8 gi;			///< GI mode. 0: Long, 1: Short
	U8 bw;			///< Bandwidth. See ::BW_t. set to U8 to reduce size
	U8 stbc;		///< 0: STBC disabled, 1: STBC enabled
	U8 imp_str;		///< Implicit Steering should come from SBF table
	///< 0: Don't steer, 1: Steer

	U8 txbf_flag;		///< Set to 1 if a beamforming steering matrix is applied
	///< to the waveform in an SU transmission, set to 0 otherwise
	U8 sndPktFlag;		///< 0: No sounding. 1: Sounding packet
	U8 tx_slp;		///< 0: Don't steer, 1: Steer legacy portion
	U8 INSUFFICIENT_NDP;	///< 1: If number of streams in NDP < Num TX antenna, 0 otherwise

	U8 IND_BW_MISC;
	U8 actSub;
	U8 tf_mac_pad_duration;
	U8 sw_force_extra_ldpc;	//For HE-MU/OFDMA cases SW can force extra ldpc symbol

	U32 phyRate;		///< phy rate to be used to current transmission
} SW_TXINFO_COMMON_st;

typedef struct {
	U8 groupID;		///< Group ID. 0/63 for SU, 1-62 for MU
	U8 vhtsigb_length_off;	///< 0 - SIGB LENGTH field set to packet length
	///< 1 - SIGB LENGTH field set to all ones.
	U8 rsvd1[2];

	U32 rsvd2[3];
} SW_TXINFO_VHT_COMMON_st;

typedef struct {
	U8 pkt_format;		///< 0: HE trigger-based PPDU, 1: HE SU PPDU
	U8 PE_mode;		///< Maximum packet extension duration.
	///< Corresponding to a_factor = {1,2,3,4},
	///< the actual PE duration is {0,0,4,8} for
	///< 11AX_MAX_PE_DURATION = 8, OR {4,8,12,16}
	///< for 11AX_MAX_PE_DURATION = 16
	U8 ext_range_mode;	///< Extended Range Mode.
	///< 0: disable, 1: 242 tones ext range pkt,
	///< 2: 106 tones ext range pkt
	U8 dcm;			///< Dual Carrier Modulation. 0: Disabled, 1: Enabled

	U8 is_uplink;		///< 1: Uplink, 0: Downlink
	U8 he_ltf_mode;
	U8 he_doppler;
	U8 midamble_period;

	U16 bss_color;
	U16 hesigbmcs;

	U32 rsvd2;

} SW_TXINFO_HE_COMMON_st;	// size should be same with SW_TXINFO_VHT_COMMON_st

typedef struct {
	U8 tf_bw;
	U8 tf_gi_ltf;
	U8 tf_mumimo_ltf_mode;
	U8 tf_stbc;
	U8 tf_ap_tx_power;

	U8 tf_no_heltf_sym;
	U8 tf_max_pe;
	U8 tf_a_factor_init;
	U8 tf_num_users;

	U8 tf_doppler;
	U8 tf_mu_rts;
	U16 tf_nsym_init;

	U8 tf_midamble_period;
	U8 tf_en_mdrhpf;
	U16 tf_hesiga_rsvd;

} SW_TXINFO_TF_COMMON_st;	// size should be same with SW_TXINFO_COMMON_st

typedef struct {
	U8 tf_ru_allocation;
	U8 tf_fec_type;
	U8 tf_mcs;
	U8 tf_start_ss;

	U8 tf_dcm;
	U8 tf_nss;
	U8 tf_target_rssi;
	U8 tf_rssi_delta;
	U8 tf_ru_alloc_idx;

	U32 tf_datalen;

} SW_TXINFO_TF_USER_st;

typedef enum {
	TONE_26,
	TONE_52,
	TONE_106,
	TONE_242,
	TONE_484,
	TONE_996,
	TONE_996_DOUBLE,
	TONE_MAX,
} OFDMA_TONE;

typedef enum {
	TF_BASIC = 0,
	TF_BFRP,
	TF_MU_BAR,
	TF_MU_RTS,
	TF_BSRP,
	//TF_GCR_MU_BAR,  //Not support yet
	//TF_BQRP,        //Not support yet
	//TF_NFRP,        //Not support yet
	TF_MAX
} TF_TYPE;

typedef struct MAC_TF_COMMON_INFO_st {
	union {
		struct {
			U64 triggerType:4;
			U64 ulLength:12;
			U64 moreTf:1;
			U64 csRequired:1;
			U64 ulBw:2;
			U64 giLtfType:2;
			U64 muMimoLtfMode:1;
			U64 numHeLtfSymMidAmblePeriod:3;
			U64 ulStbc:1;
			U64 ldpcExtraSymSeg:1;
			U64 apTxPower:6;
			U64 ulPktExt:3;
			U64 ulSpatialReuse:16;
			U64 doppler:1;
			U64 ulHeSigA2Rsvd:9;
			U64 rsvd:1;
		} __attribute__ ((packed)) field;

		U8 byte[8];
	} __attribute__ ((packed));
} __attribute__ ((packed)) MAC_TF_COMMON_INFO_st;

typedef struct MAC_TF_USER_INFO_st {
	union {
		struct {
			U32 aid12:12;
			U32 ruAllocation:8;
			U32 ulFecCoding:1;
			U32 ulMcs:4;
			U32 ulDcm:1;
			U32 ssAllocRaRuInfo:6;
			U8 ulTargetRssi:7;
			U8 rsvd:1;
		} __attribute__ ((packed)) field;

		U8 byte[5];
	} __attribute__ ((packed));
} __attribute__ ((packed)) MAC_TF_USER_INFO_st;

typedef struct MAC_TF_BASIC_st {
	MAC_TF_COMMON_INFO_st commonInfo;

	struct {
		MAC_TF_USER_INFO_st info;

		struct {
			U8 mpduMuSpacFac:2;
			U8 tidAggrLimit:3;
			U8 rsvd:1;
			U8 preferredAc:2;
		} __attribute__ ((packed)) basic;
	} __attribute__ ((packed)) user;

} MAC_TF_BASIC_st;

typedef struct MAC_TF_MUBAR_st {
	MAC_TF_COMMON_INFO_st commonInfo;

	struct {
		MAC_TF_USER_INFO_st info;

		U16 barCtrl;	//B15:12=TID, B11:5=rsvd, B4:1=barType, B0=BarAckPolicy
		U16 barInfo;	//B15:4=StartSeqNum, B3:0=FregNum
	} __attribute__ ((packed)) user[16];

} MAC_TF_MUBAR_st;

typedef struct MAC_TF_GEN_st {
	union {
		MAC_TF_BASIC_st basic[16];
		MAC_TF_MUBAR_st mubar;
	};
} MAC_TF_GEN_st;

#define MAX_MU_RTS_PAD  48
typedef struct MAC_TF_MU_RTS_st {
	MAC_TF_COMMON_INFO_st commonInfo;

	struct {
		MAC_TF_USER_INFO_st info;
	} __attribute__ ((packed)) user[16];
	U8 pad[MAX_MU_RTS_PAD];
} MAC_TF_MU_RTS_st;

#endif // _SHAL_TXINFO_H_
