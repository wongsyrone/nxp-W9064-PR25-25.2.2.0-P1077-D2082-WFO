/** @file shal_event.h
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
 * @brief SMAC Event function APIs.
 */

#ifndef SHAL_EVENT_H_
#define SHAL_EVENT_H_

/**rxInfo WAR to have SW managed index when resetting rx bb in SWAR_resetEUonTx**/
#define RXINFO_WAR_EN

//#ifdef MFG_FW
#define APMODE_ULOFDMA
#define APMODE_ULOFDMA_WITH_8P2	//UL-OFDMA with WAR 8.2, to drop all trailing rx pkt when txPE is high. Comment out to save trailing rx pkt in UL-OFDMA
//#define APMODE_MU_RTS
//#endif

//////////////////////////////////////////////////////
// Global Control Register for Events (Base Address)
//////////////////////////////////////////////////////

#define EVT_NUM_GRP_SIZE                    32	///< # of events per group
#define EVT_NUM_GRP                         6	///< # of groups
#define EVT_NUM_TOTAL                       (EVT_NUM_GRP * EVT_NUM_GRP_SIZE)	///< # of events total

//////////////////////////////////////////////////////////

// Tx Events
#define EVT_MAP_L0_L1_BUF_ALLOC_CMD_COMP    0
#define EVT_MAP_TXD1_RSVD0                  1
#define EVT_MAP_TXD1_INCOME_MSDU_SW_CMD     2
#define EVT_MAP_TXD1_RSVD1                  3
#define EVT_MAP_TXD1_RSVD2                  4
#define EVT_MAP_TXD1_RSVD3                  5
#define EVT_MAP_TXD1_RSVD4                  6
#define EVT_MAP_TXD1_TRIGGER_BITMAP         7
#define EVT_MAP_TXD1_RSVD5                  8
#define EVT_MAP_TXD2_DONE_0                 9
#define EVT_MAP_TXD2_DONE_1                 10

#define EVT_MAP_TXD_RSVD_0                  14

// SW_EVENT_0 12[26:15] - Reserved for TX MU CPU events
#define EVT_MAP_RX_FROM_FCS                 15
#define EVT_MAP_SW_RSVD_16                  16
#define EVT_MAP_SW_RSVD_17                  17
#define EVT_MAP_SW_RSVD_18                  18
#define EVT_MAP_SW_RSVD_19                  19
#define EVT_MAP_SW_RSVD_20                  20
#define EVT_MAP_SW_RSVD_21                  21
#define EVT_MAP_SW_RSVD_22                  22
#define EVT_MAP_SW_RSVD_23                  23
#define EVT_MAP_SW_RSVD_24                  24
#define EVT_MAP_SW_RSVD_25                  25
#ifdef STAMODE_ULOFDMA
#define EVT_MAP_SW_EVENT_PREPARE_UL         26
#else
#define EVT_MAP_SW_RSVD_26                  26
#endif

#define EVT_MAP_TXD4_DONE_0                 27
#define EVT_MAP_TXD4_DONE_1                 28
#define EVT_MAP_TXD4_DONE_2                 29
#define EVT_MAP_TXD4_DONE_3                 30
#define EVT_MAP_TXD4_DONE_4                 31
#define EVT_MAP_TXD5_DONE_0                 32
#define EVT_MAP_TXD5_DONE_1                 33
#define EVT_MAP_TXD5_DONE_2                 34
#define EVT_MAP_TXD5_DONE_3                 35
#define EVT_MAP_TXD5_DONE_4                 36	///< New TXD5 context 4 for SWAR_IP_REV_SCBT_Z1 and after

// SW_EVENT_1 11[47:37]
#define EVT_MAP_SW_TEST_UPDATE_BITMAP_REQ   37	///< Used in TxD2 tests only
#define EVT_MAP_SW_BBTX_GRP_1               38
#define EVT_MAP_SW_BBTX_GRP_23              39
#define EVT_MAP_DFW_2_PFW_MSG_TRIG          40
//#define EVT_MAP_PFW_2_DFW_MSG_TRIG_LP       41
#define EVT_MAP_SW_BF_RPC                   42
#define EVT_MAP_SFW_COREDUMP                43
#define EVT_MAP_SW_CM3_CTRL                 44
#define EVT_MAP_SW_EVENT_45                 45
#define EVT_MAP_SW_EVENT_46                 46
#if defined(APMODE_ULOFDMA)
#define EVT_MAP_SW_EVENT_FCS                47
#else
#define EVT_MAP_SW_EVENT_47                 47
#endif

#define EVT_MAP_TX_TIMR_MSLOT_TICK          48
#define EVT_MAP_TX_TXPE_ASSERT              49
#define EVT_MAP_TX_RDY_DEASSERT             50
#define EVT_MAP_TX_TIMR_BCN_TSF_MATCH       51
#define EVT_MAP_TX_TIMR_PROG_TIMR_0         52
#define EVT_MAP_TX_TIMR_PROG_TIMR_1         53
#define EVT_MAP_TX_TIMR_PROG_TIMR_2         54
#define EVT_MAP_TX_TIMR_PROG_TIMR_3         55
#define EVT_MAP_TX_TIMR_NAV                 56
#define EVT_MAP_TX_TIMR_NAV2                57

#define EVT_MAP_TX_TIMR_PPS_SYNC            58
#define EVT_MAP_TX_HCCA_DONE_FIRST          59
#define EVT_MAP_TX_RDY_FALL_ERROR           60

#define EVT_MAP_TX_TIMR_RSVD_1              61
//#define EVT_MAP_TX_TIMR_RSVD_2              62
#define EVT_MAP_PFW_2_DFW_MSG_TRIG_LP       62
//#define EVT_MAP_TX_TIMR_RSVD_3              63
#define EVT_MAP_PFW_2_DFW_MSG_TRIG_HP       63

// Rx Events
#define EVT_MAP_RX_BBIF_SOF                 64
#define EVT_MAP_RX_BBIF_SOP                 65
#define EVT_MAP_RX_BBIF_HDR                 66
#define EVT_MAP_RX_BBIF_AVL                 67
#define EVT_MAP_RX_BBIF_FCS                 68	// FCS done
#define EVT_MAP_RX_BBIF_FCS_VALID           69
#define EVT_MAP_RX_BBIF_EOP                 70
#define EVT_MAP_RX_BBIF_EOF                 71
#define EVT_MAP_RX_BBIF_NDP                 72
#define EVT_MAP_RX_BBIF_BBUD_RX_RDY_RISING  73
#define EVT_MAP_RX_BBIF_EU_TRAN_CYCLE_DONE  74
#define EVT_MAP_RX_BBIF_MPDU_SYMBL_BUF_FULL 75
#define EVT_MAP_RX_BBIF_STRT_PPDU           76	// Rx_rdy rising
#define EVT_MAP_RX_BBIF_END_PPDU            77	// Rx_rdy falling
#define EVT_MAP_RX_BBIF_INPUT_RATE_FIF_FULL 78
#define EVT_MAP_RX_BBIF_WATCH_DOG           79
#define EVT_MAP_RX_BBIF_RX_INFO             80
#define EVT_MAP_RX_BBIF_RX_INFO_DMA         81
#define EVT_MAP_RX_BBIF_RX_FCS_ABORT        82

#define EVT_MAP_RX_BBIF_RX_HW_ACCEL         83

#define EVT_MAP_RX_AMSDU_SINGLE_QCMD        84
#define EVT_MAP_RX_AMSDU_INPUT_DMA          85
#define EVT_MAP_RX_AMSDU_OUPUT_DMA          86
#define EVT_MAP_RX_AMSDU_BYPASS             87
#define EVT_MAP_RX_AMSDU_DEAGGR             88
#define EVT_MAP_RX_AMSDU_DEFRAG             89
#define EVT_MAP_RX_AMSDU_MULTI_QCMD         90
#define EVT_MAP_RX_AMSDU_DATA               91
#define EVT_MAP_RX_AMSDU_BPID               92
#define EVT_MAP_RX_AMSDU_HFRAME             93
#define EVT_MAP_RX_AMSDU_ERROR              94
#define EVT_MAP_RX_AMSDU_RSVD_1             95

#define EVT_MAP_RX_BMAN_BP0_REQ_DMA_DONE    96
#define EVT_MAP_RX_BMAN_BP1_REQ_DMA_DONE    97
#define EVT_MAP_RX_BMAN_BP2_REQ_DMA_DONE    98
#define EVT_MAP_RX_BMAN_BP3_REQ_DMA_DONE    99
#define EVT_MAP_RX_BMAN_BP4_REQ_DMA_DONE    100
#define EVT_MAP_RX_BMAN_BP5_REQ_DMA_DONE    101
#define EVT_MAP_RX_BMAN_BP6_REQ_DMA_DONE    102
#define EVT_MAP_RX_BMAN_BP7_REQ_DMA_DONE    103

// EU Events
#define EVT_MAP_EU_DONE_CTX8                104
#define EVT_MAP_EU_DONE_CTX9                105
#define EVT_MAP_EU_DONE_CTX10               106
#define EVT_MAP_EU_DONE_CTX11               107
#define EVT_MAP_EU_DONE_CTX12               108
#define EVT_MAP_EU_DONE_CTX13               109
#define EVT_MAP_EU_DONE_CTX14               110
#define EVT_MAP_EU_DONE_CTX15               111

#define EVT_MAP_EU_DONE_CTX0                112
#define EVT_MAP_EU_DONE_CTX1                113
#define EVT_MAP_EU_DONE_CTX2                114
#define EVT_MAP_EU_DONE_CTX3                115
#define EVT_MAP_EU_DONE_CTX4                116
#define EVT_MAP_EU_DONE_CTX5                117
#define EVT_MAP_EU_DONE_CTX6                118
#define EVT_MAP_EU_DONE_CTX7                119

#define EVT_MAP_EU_RX_MPDU_DONE             120
#define EVT_MAP_EU_POST_DONE                121
#define EVT_MAP_EU_PLD_DMA_DONE             122
#define EVT_MAP_EU_HDR_DMA_DONE             123

#define EVT_MAP_EU_TX_UNDERFLOW             124

// BF Events
#define EVT_MAP_BF_DMA_AOBRT_DONE           125
#define EVT_MAP_BF_EXP_DMA_DONE             126
#define EVT_MAP_BF_EXP_DMA_MU_DONE          127
#define EVT_MAP_BF_IMP_DMA_DONE             128
#define EVT_MAP_BF_IMP_LEN_RDY              129
#define EVT_MAP_BF_NDP_DMA_DONE             130
#define EVT_MAP_BF_NDP_LEN_RDY              131
#define EVT_MAP_BF_SSM_DMA_DONE             132
#define EVT_MAP_BF_CSI_DMA_DONE             133
#define EVT_MAP_BF_EXP_DOWNLOAD_DONE        134
#define EVT_MAP_BF_EXP_UPLOAD_DONE          135
#define EVT_MAP_BF_IMP_DOWNLOAD_DONE        136
#define EVT_MAP_BF_IMP_UPLOAD_DONE          137
#define EVT_MAP_BF_CSI_INFO_DONE            138
#define EVT_MAP_BF_CSI_LLTF_DONE            139
#define EVT_MAP_BF_CSI_DONE                 140
#define EVT_MAP_BF_EXP_DMA_ERROR            141
#define EVT_MAP_BF_IMP_DMA_ERROR            142
#define EVT_MAP_BF_NDP_DMA_ERROR            143
#define EVT_MAP_BF_CSI_DMA_ERROR            144
#define EVT_MAP_BF_SSM_DMA_ERROR            145

// DFS2 Events
#define EVT_MAP_DFS2_RECORD_READY           146
#define EVT_MAP_DFS2_RECORD_TIMEOUT         147
#define EVT_MAP_DFS2_RECORD_QUEUE_FULL      148
#define EVT_MAP_DFS2_RECORD_RSVD            149

// ADMA Events
#define EVT_MAP_ADMA_IRQ_0                  150
#define EVT_MAP_ADMA_IRQ_1                  151
#define EVT_MAP_ADMA_IRQ_2                  152
#define EVT_MAP_ADMA_IRQ_3                  153
#define EVT_MAP_ADMA_IRQ_4                  154
#define EVT_MAP_ADMA_IRQ_5                  155
#define EVT_MAP_ADMA_IRQ_6                  156
#define EVT_MAP_ADMA_IRQ_7                  157
#define EVT_MAP_ADMA_IRQ_8                  158
#define EVT_MAP_ADMA_IRQ_9                  159
#define EVT_MAP_ADMA_IRQ_10                 160
#define EVT_MAP_ADMA_IRQ_11                 161
#define EVT_MAP_ADMA_IRQ_12                 162
#define EVT_MAP_ADMA_IRQ_13                 163
#define EVT_MAP_ADMA_IRQ_14                 164
#define EVT_MAP_RX_TF_DETECT                165
#define EVT_MAP_RX_TF_DONE                  166

#define EVT_MAP_RX2_RSVD_0                  167
#define EVT_MAP_RX2_RSVD_1                  168
#define EVT_MAP_RX2_RSVD_2                  169

// MU Events //TODO
#define EVT_MAP_SW_MU_START                 170
#define EVT_MAP_SW_MU_START_1               171
#define EVT_MAP_SW_MU_START_2               172
#define EVT_MAP_SW_MU_START_3               173
#define EVT_MAP_SW_MU_NSYM_DONE             174

#define EVT_MAP_SW_MISS_EOF                 175

#define EVT_MAP_SMAC_RSVD_3                 176

#define EVT_MAP_AXI_MON                     177

#define EVT_MAP_DFS_RECORD_READY            178
#define EVT_MAP_DFS_RECORD_TIMEOUT          179
#define EVT_MAP_DFS_RECORD_QUEUE_FULL       180
#define EVT_MAP_DFS_RECORD_RSVD             181

// CPU to CPU events 2
// SW_EVENT_2 8[182:189]
//#define EVT_MAP_SW_IR_FROM_FCS            182
#define EVT_MAP_SW_B2B_TX_FROM_FCS          183
#define EVT_MAP_SW_EOP2_FROM_EOP            184
//#define EVT_MAP_SW_TA_REQ_FROM_FCS        185
#define EVT_MAP_SW_TA_RDY_FROM_SOP          186
#define EVT_MAP_SW_EOF_FROM_FCS             187
#define EVT_MAP_SFW_2_PFW_MSG_TRIG          188
#define EVT_MAP_PFW_2_SFW_MSG_TRIG          189

// CPU to HW
#define EVT_MAP_REQUEST_RX_MPDU_STATUS      190
#define EVT_MAP_FCS_REQ                     191

///////////////////////////////////////////////////////
// Event Control Register for each CPU (Base Address)
///////////////////////////////////////////////////////
// offset(s)
#define EVT_GEN_EBIT                        (SMAC_EVENT_BASE_ADDR + 0)
////////////////////////////////////////////////////////////////////////////////////////////////////////
// Offsets per CPU (identical offsets)
////////////////////////////////////////////////////////////////////////////////////////////////////////
// Control Registers
#define EVT_TIMEOUT                         (SMAC_EVENT_BASE_ADDR + 0x0700)
#define EVT_CONTROL                         (SMAC_EVENT_BASE_ADDR + 0x0704)
#define EVT_ALL                             (SMAC_EVENT_BASE_ADDR + 0x0708)

/// Generalize event register into struct based groups
typedef struct EVT_GRP_REG_BASE_st {
	U32 inMask;
	U32 outMask;
	U32 clr;
	U32 shield;
	U32 stat;
	U32 statShadow;
	U32 rsvd0;		///< for padding to next grp
	U32 rsvd1;		///< for padding to next grp
} EVT_GRP_REG_BASE_st;

#define EVT_GRP0_REG_BASE_PTR      (volatile EVT_GRP_REG_BASE_st *)(SMAC_EVENT_BASE_ADDR + 0x0800)
#define EVT_GRP1_REG_BASE_PTR      (volatile EVT_GRP_REG_BASE_st *)(SMAC_EVENT_BASE_ADDR + 0x0820)
#define EVT_GRP2_REG_BASE_PTR      (volatile EVT_GRP_REG_BASE_st *)(SMAC_EVENT_BASE_ADDR + 0x0840)
#define EVT_GRP3_REG_BASE_PTR      (volatile EVT_GRP_REG_BASE_st *)(SMAC_EVENT_BASE_ADDR + 0x0860)
#define EVT_GRP4_REG_BASE_PTR      (volatile EVT_GRP_REG_BASE_st *)(SMAC_EVENT_BASE_ADDR + 0x0880)
#define EVT_GRP5_REG_BASE_PTR      (volatile EVT_GRP_REG_BASE_st *)(SMAC_EVENT_BASE_ADDR + 0x08A0)

// For Event Group 0 (1st 32 bit register)
#define EVT_IN_MASK_GRP_0           (SMAC_EVENT_BASE_ADDR + 0x0800)
#define EVT_OUT_MASK_GRP_0          (SMAC_EVENT_BASE_ADDR + 0x0804)
#define EVT_CLR_GRP_0               (SMAC_EVENT_BASE_ADDR + 0x0808)
#define EVT_SHIELD_GRP_0            (SMAC_EVENT_BASE_ADDR + 0x080C)
#define EVT_STAT_GRP_0              (SMAC_EVENT_BASE_ADDR + 0x0810)
#define EVT_STAT_SHDW_GRP_0         (SMAC_EVENT_BASE_ADDR + 0x0814)
// For Event Group 1 (2nd 32 bit register)
#define EVT_IN_MASK_GRP_1           (SMAC_EVENT_BASE_ADDR + 0x0820)
#define EVT_OUT_MASK_GRP_1          (SMAC_EVENT_BASE_ADDR + 0x0824)
#define EVT_CLR_GRP_1               (SMAC_EVENT_BASE_ADDR + 0x0828)
#define EVT_SHIELD_GRP_1            (SMAC_EVENT_BASE_ADDR + 0x082C)
#define EVT_STAT_GRP_1              (SMAC_EVENT_BASE_ADDR + 0x0830)
#define EVT_STAT_SHDW_GRP_1         (SMAC_EVENT_BASE_ADDR + 0x0834)
// For Event Group 2 (3rd 32 bit register)
#define EVT_IN_MASK_GRP_2           (SMAC_EVENT_BASE_ADDR + 0x0840)
#define EVT_OUT_MASK_GRP_2          (SMAC_EVENT_BASE_ADDR + 0x0844)
#define EVT_CLR_GRP_2               (SMAC_EVENT_BASE_ADDR + 0x0848)
#define EVT_SHIELD_GRP_2            (SMAC_EVENT_BASE_ADDR + 0x084C)
#define EVT_STAT_GRP_2              (SMAC_EVENT_BASE_ADDR + 0x0850)
#define EVT_STAT_SHDW_GRP_2         (SMAC_EVENT_BASE_ADDR + 0x0854)
// For Event Group 3 (4th 32 bit register)
#define EVT_IN_MASK_GRP_3           (SMAC_EVENT_BASE_ADDR + 0x0860)
#define EVT_OUT_MASK_GRP_3          (SMAC_EVENT_BASE_ADDR + 0x0864)
#define EVT_CLR_GRP_3               (SMAC_EVENT_BASE_ADDR + 0x0868)
#define EVT_SHIELD_GRP_3            (SMAC_EVENT_BASE_ADDR + 0x086C)
#define EVT_STAT_GRP_3              (SMAC_EVENT_BASE_ADDR + 0x0870)
#define EVT_STAT_SHDW_GRP_3         (SMAC_EVENT_BASE_ADDR + 0x0874)
// For Event Group 4 (5th 32 bit register)
#define EVT_IN_MASK_GRP_4           (SMAC_EVENT_BASE_ADDR + 0x0880)
#define EVT_OUT_MASK_GRP_4          (SMAC_EVENT_BASE_ADDR + 0x0884)
#define EVT_CLR_GRP_4               (SMAC_EVENT_BASE_ADDR + 0x0888)
#define EVT_SHIELD_GRP_4            (SMAC_EVENT_BASE_ADDR + 0x088C)
#define EVT_STAT_GRP_4              (SMAC_EVENT_BASE_ADDR + 0x0890)
#define EVT_STAT_SHDW_GRP_4         (SMAC_EVENT_BASE_ADDR + 0x0894)
// For Event Group 5 (6th 32 bit register)
#define EVT_IN_MASK_GRP_5           (SMAC_EVENT_BASE_ADDR + 0x08A0)
#define EVT_OUT_MASK_GRP_5          (SMAC_EVENT_BASE_ADDR + 0x08A4)
#define EVT_CLR_GRP_5               (SMAC_EVENT_BASE_ADDR + 0x08A8)
#define EVT_SHIELD_GRP_5            (SMAC_EVENT_BASE_ADDR + 0x08AC)
#define EVT_STAT_GRP_5              (SMAC_EVENT_BASE_ADDR + 0x08B0)
#define EVT_STAT_SHDW_GRP_5         (SMAC_EVENT_BASE_ADDR + 0x08B4)

////////////////////////////////////////////////////////////////////////////////////////////////////////
// Macro to retrieve a single event status
#define EVT_GRPNUM(eventNum)            ((eventNum) / EVT_NUM_GRP_SIZE)
#define EVT_BITNUM(eventNum)            ((eventNum) % EVT_NUM_GRP_SIZE)
#define EVT_BIT(eventNum)               SHAL_BIT(((eventNum) % EVT_NUM_GRP_SIZE))
#define EVT_REMAP_NUM(group, bitNum)    ((group) * EVT_NUM_GRP_SIZE + (bitNum))
#define EVT_write32(reg,val)            (*(volatile U32 *)(reg))=(U32)(val)
#define EVT_read32(reg)                 (U32)(*(volatile U32 *)(reg))

#ifndef __KERNEL__

static SHAL_INLINE void
EVT_sendSingle(const U32 eventMapNum, U32 val)
{
	EVT_write32((SMAC_EVENT_BASE_ADDR + eventMapNum * 4), val);
}

static SHAL_INLINE U32
EVT_wakeOnGroup(const U32 grpNum)
{
	U32 evtGrpBits;
	evtGrpBits =
		EVT_read32((EVT_STAT_GRP_0 +
			    grpNum * sizeof(EVT_GRP_REG_BASE_st)));
	return evtGrpBits;
}

static SHAL_INLINE void
EVT_clrGroup(const U32 eventNum, U32 eventBits)
{
	EVT_write32((EVT_CLR_GRP_0 +
		     (eventNum / EVT_NUM_GRP_SIZE) *
		     sizeof(EVT_GRP_REG_BASE_st)), eventBits);
}

static SHAL_INLINE void
EVT_clrSingle(const U32 eventNum)
{
	EVT_write32((SMAC_EVENT_BASE_ADDR + eventNum * 4), 0);
}

static SHAL_INLINE U32
EVT_peekGroup(const U32 eventNum)
{
	return (EVT_read32
		((EVT_STAT_SHDW_GRP_0 +
		  (eventNum / EVT_NUM_GRP_SIZE) *
		  sizeof(EVT_GRP_REG_BASE_st))));
}

static SHAL_INLINE U32
EVT_peekSingle(const U32 eventNum)
{
	return (EVT_read32
		((EVT_STAT_SHDW_GRP_0 +
		  (eventNum / EVT_NUM_GRP_SIZE) *
		  sizeof(EVT_GRP_REG_BASE_st))) & EVT_BIT(eventNum));
}

static SHAL_INLINE void
EVT_wakeOnSingle(const U32 eventNum)
{
	EVT_read32((SMAC_EVENT_BASE_ADDR + eventNum * 4));
	__dsb(0xF);
}

static SHAL_INLINE void
EVT_unmaskPingPong(const U32 eventNum)
{
	U32 grpAddr =
		(EVT_SHIELD_GRP_0 +
		 (eventNum / EVT_NUM_GRP_SIZE) * sizeof(EVT_GRP_REG_BASE_st));
	EVT_write32(grpAddr,
		    (EVT_read32(grpAddr) & ~(0x3 << EVT_BITNUM(eventNum))));
}

static SHAL_INLINE void
EVT_maskPingPong(const U32 eventNum)
{
	U32 grpAddr =
		(EVT_SHIELD_GRP_0 +
		 (eventNum / EVT_NUM_GRP_SIZE) * sizeof(EVT_GRP_REG_BASE_st));
	EVT_write32(grpAddr,
		    (EVT_read32(grpAddr) | (0x3 << EVT_BITNUM(eventNum))));
}

static SHAL_INLINE void
EVT_unmaskSingle(const U32 eventNum)
{
	U32 grpAddr =
		(EVT_SHIELD_GRP_0 +
		 (eventNum / EVT_NUM_GRP_SIZE) * sizeof(EVT_GRP_REG_BASE_st));
	EVT_write32(grpAddr, (EVT_read32(grpAddr) & ~(EVT_BIT(eventNum))));
}

static SHAL_INLINE void
EVT_maskSingle(const U32 eventNum)
{
	U32 grpAddr =
		(EVT_SHIELD_GRP_0 +
		 (eventNum / EVT_NUM_GRP_SIZE) * sizeof(EVT_GRP_REG_BASE_st));
	EVT_write32(grpAddr, (EVT_read32(grpAddr) | (EVT_BIT(eventNum))));
}

#endif /* #ifndef __KERNEL__ */

//from U8 gEvtMuxTbl[0] =    //CPU0 : GRP0 - B00:15 TX
#define  EVT_EU_DONE_CTX15              EVT_REMAP_NUM(0, 2)
#define  EVT_EU_DONE_CTX11              EVT_REMAP_NUM(0, 3)
#define  EVT_EU_DONE_CTX7               EVT_REMAP_NUM(0, 4)
#define  EVT_EU_DONE_CTX3               EVT_REMAP_NUM(0, 5)
#define  EVT_SW_MU_START_3              EVT_REMAP_NUM(0, 6)
#define  EVT_TXD4_DONE_3                EVT_REMAP_NUM(0, 7)	///< if remap EVT_TXD4_DONE_1~3, update TXD4_prepareAmpdu()
#define  EVT_TX_TIMR_PROG_TIMR_2_G0     EVT_REMAP_NUM(0, 8)
#define  EVT_CM3_CTRL_0                 EVT_REMAP_NUM(0, 9)
#define  EVT_RX_BBIF_HDR                EVT_REMAP_NUM(0, 16)
#define  EVT_RX_BBIF_STRT_PPDU          EVT_REMAP_NUM(0, 17)	// For DRV backward compatibility
#define  EVT_RX_BBIF_BBUD_RX_RDY_RISING EVT_REMAP_NUM(0, 17)
#define  EVT_RX_BBIF_NDP                EVT_REMAP_NUM(0, 18)
#define  EVT_RX_BBIF_END_PPDU_0         EVT_REMAP_NUM(0, 19)
#define  EVT_PFW_2_DFW_MSG_TRIG_LP      EVT_REMAP_NUM(0, 15)

//from U8 gEvtMuxTbl[1] =    //CPU1 : GRP1 - B00:15 TX
#define  EVT_EU_DONE_CTX14              EVT_REMAP_NUM(1, 2)
#define  EVT_EU_DONE_CTX10              EVT_REMAP_NUM(1, 3)
#define  EVT_EU_DONE_CTX6               EVT_REMAP_NUM(1, 4)
#define  EVT_EU_DONE_CTX2               EVT_REMAP_NUM(1, 5)
#define  EVT_SW_MU_START_2              EVT_REMAP_NUM(1, 6)
#define  EVT_TXD4_DONE_2                EVT_REMAP_NUM(1, 7)
#define  EVT_TX_TIMR_PROG_TIMR_2_G1     EVT_REMAP_NUM(1, 8)
#define  EVT_CM3_CTRL_1                 EVT_REMAP_NUM(1, 9)
#define  EVT_EU_RX_MPDU_DONE            EVT_REMAP_NUM(1, 16)
#define  EVT_EU_POST_DONE               EVT_REMAP_NUM(1, 17)
#define  EVT_EU_PLD_DMA_DONE            EVT_REMAP_NUM(1, 18)
#define  EVT_EU_HDR_DMA_DONE            EVT_REMAP_NUM(1, 19)
#define  EVT_ADMA_RX_CFH_IRQ            EVT_REMAP_NUM(1, 20)	///< CFH_DMA
#define  EVT_SW_EOF_FROM_FCS            EVT_REMAP_NUM(1, 21)	///< EOF_Sync
#define  EVT_RX_BBIF_STRT_PPDU_1        EVT_REMAP_NUM(1, 22)
#define  EVT_PFW_2_DFW_MSG_TRIG_HP      EVT_REMAP_NUM(1, 23)
#define  EVT_DFS_RECORD_READY           EVT_REMAP_NUM(1, 24)
#define  EVT_DFS_RECORD_TIMEOUT         EVT_REMAP_NUM(1, 25)
#define  EVT_DFS_RECORD_QUEUE_FULL      EVT_REMAP_NUM(1, 26)
#define  EVT_DFS_RECORD_RSVD            EVT_REMAP_NUM(1, 27)
#define  EVT_DFS2_RECORD_READY          EVT_REMAP_NUM(1, 28)
#define  EVT_DFS2_RECORD_TIMEOUT        EVT_REMAP_NUM(1, 29)
#define  EVT_DFS2_RECORD_QUEUE_FULL     EVT_REMAP_NUM(1, 30)
#define  EVT_DFS2_RECORD_RSVD           EVT_REMAP_NUM(1, 31)

//from  U8 gEvtMuxTbl[2] =    //CPU2 : GRP2 - B00:15 TX
#define  EVT_EU_DONE_CTX13              EVT_REMAP_NUM(2, 2)
#define  EVT_EU_DONE_CTX9               EVT_REMAP_NUM(2, 3)
#define  EVT_EU_DONE_CTX5               EVT_REMAP_NUM(2, 4)
#define  EVT_EU_DONE_CTX1               EVT_REMAP_NUM(2, 5)
#define  EVT_SW_MU_START_1              EVT_REMAP_NUM(2, 6)
#define  EVT_TXD4_DONE_1                EVT_REMAP_NUM(2, 7)
#define  EVT_TX_TIMR_PROG_TIMR_2_G2     EVT_REMAP_NUM(2, 8)
#define  EVT_CM3_CTRL_2                 EVT_REMAP_NUM(2, 9)
#define  EVT_SW_MISS_EOF                EVT_REMAP_NUM(2, 13)
#if defined(RXINFO_WAR_EN)
#define  EVT_RX_BBIF_RX_INFO_DMA_1      EVT_REMAP_NUM(2, 14)
#endif

#define  EVT_RX_BBIF_RX_INFO            EVT_REMAP_NUM(2, 15)

#if !defined(APMODE_ULOFDMA)
#define  EVT_RX_BBIF_FCS                EVT_REMAP_NUM(2, 16)
#endif

#define  EVT_RX_BBIF_EOF                EVT_REMAP_NUM(2, 17)
#define  EVT_RX_BBIF_SOF                EVT_REMAP_NUM(2, 18)	///< EOP2 shared
#define  EVT_SW_EOP2_FROM_EOP           EVT_REMAP_NUM(2, 19)	///< EOP2 only
#define  EVT_SW_TA_RDY_FROM_SOP         EVT_REMAP_NUM(2, 20)	///< EOP2 only
#define  EVT_RX_BBIF_STRT_PPDU_2        EVT_REMAP_NUM(2, 21)
#define  EVT_RX_BBIF_END_PPDU_2         EVT_REMAP_NUM(2, 22)
#if !defined(APMODE_ULOFDMA)
#define  EVT_TX_TIMR_PROG_TIMR_0        EVT_REMAP_NUM(2, 23)
#endif
#define  EVT_TX_TIMR_PROG_TIMR_1        EVT_REMAP_NUM(2, 24)
#if defined(APMODE_ULOFDMA)
#define  EVT_RX_SW_EVENT_FCS            EVT_REMAP_NUM(2, 25)
#endif
#define  EVT_RX_AMSDU_BPID_1            EVT_REMAP_NUM(2, 28)

//from U8 gEvtMuxTbl[3] =    //CPU3 : GRP3 - B00:31
#define  EVT_EU_DONE_CTX12              EVT_REMAP_NUM(3, 2)
#define  EVT_EU_DONE_CTX8               EVT_REMAP_NUM(3, 3)
#define  EVT_EU_DONE_CTX4               EVT_REMAP_NUM(3, 4)
#define  EVT_EU_DONE_CTX0               EVT_REMAP_NUM(3, 5)
#define  EVT_SW_MU_START                EVT_REMAP_NUM(3, 6)
#define  EVT_TXD4_DONE_0                EVT_REMAP_NUM(3, 7)
#define  EVT_SW_B2B_TX_FROM_FCS         EVT_REMAP_NUM(3, 8)
#define  EVT_CM3_CTRL_3                 EVT_REMAP_NUM(3, 9)
#if defined(STAMODE_ULOFDMA)
#define  EVT_SW_EVENT_PREPARE_UL        EVT_REMAP_NUM(3, 10)
#endif
#define  EVT_RX_FROM_FCS                EVT_REMAP_NUM(3, 11)
#define  EVT_TX_TIMR_MSLOT_TICK         EVT_REMAP_NUM(3, 16)
#if defined(RXINFO_WAR_EN)
#define  EVT_RX_BBIF_RX_INFO_DMA_2      EVT_REMAP_NUM(3, 17)
#endif
#define  EVT_TX_TXPE_ASSERT             EVT_REMAP_NUM(3, 19)
#define  EVT_RX_BBIF_END_PPDU           EVT_REMAP_NUM(3, 20)
#define  EVT_TX_RDY_DEASSERT            EVT_REMAP_NUM(3, 21)
#define  EVT_RX_BBIF_SOF_2              EVT_REMAP_NUM(3, 22)
#define  EVT_TX_TIMR_BCN_TSF_MATCH      EVT_REMAP_NUM(3, 23)
#define  EVT_SFW_2_PFW_MSG_TRIG         EVT_REMAP_NUM(3, 24)
#define  EVT_SFW_COREDUMP               EVT_REMAP_NUM(3, 25)
#define  EVT_TX_TIMR_PROG_TIMR_2_G3     EVT_REMAP_NUM(3, 26)
#if defined(APMODE_ULOFDMA) && !defined(APMODE_ULOFDMA_WITH_8P2)
#define  EVT_TX_TIMR_PROG_TIMR_0        EVT_REMAP_NUM(3, 28)
#define  EVT_RX_BBIF_INPUT_RATE_FIF_FULL EVT_REMAP_NUM(3, 29)
#define  EVT_RX_TF_DETECT               EVT_REMAP_NUM(3, 30)
#else
#define  EVT_RX_TF_DETECT               EVT_REMAP_NUM(3, 27)
#endif

//from U8 gEvtMuxTbl[4] =    //CPU4 : GRP4 - B00:15, B16:31 for individual events only from CPU0-3
#define  EVT_TXD1_TRIGGER_BITMAP        EVT_REMAP_NUM(4, 0)
#define  EVT_TXD2_DONE_0                EVT_REMAP_NUM(4, 1)
#if defined(APMODE_ULOFDMA)
#define  EVT_RX_BBIF_FCS                EVT_REMAP_NUM(4, 2)
#endif
#define  EVT_SW_BBTX_GRP_1              EVT_REMAP_NUM(4, 3)
#define  EVT_SW_BBTX_GRP_23             EVT_REMAP_NUM(4, 4)
#define  EVT_TX_TIMR_MSLOT_TICK4        EVT_REMAP_NUM(4, 5)
#define  EVT_ADMA_TXD2_IRQ              EVT_REMAP_NUM(4, 6)
#define  EVT_SW_BF_RPC                  EVT_REMAP_NUM(4, 7)
#define  EVT_BF_EXP_DMA_DONE            EVT_REMAP_NUM(4, 8)
#define  EVT_BF_EXP_DMA_MU_DONE         EVT_REMAP_NUM(4, 9)
#define  EVT_BF_IMP_DMA_DONE            EVT_REMAP_NUM(4, 10)
#define  EVT_BF_NDP_DMA_DONE            EVT_REMAP_NUM(4, 11)
#define  EVT_BF_SSM_DMA_DONE            EVT_REMAP_NUM(4, 12)
#define  EVT_BF_CSI_DMA_DONE            EVT_REMAP_NUM(4, 13)
#define  EVT_BF_EXP_DOWNLOAD_DONE       EVT_REMAP_NUM(4, 14)
#define  EVT_BF_EXP_UPLOAD_DONE         EVT_REMAP_NUM(4, 15)
#define  EVT_BF_IMP_DOWNLOAD_DONE       EVT_REMAP_NUM(4, 16)
#define  EVT_BF_IMP_UPLOAD_DONE         EVT_REMAP_NUM(4, 17)
#define  EVT_BF_CSI_INFO_DONE           EVT_REMAP_NUM(4, 18)
#define  EVT_BF_CSI_LLTF_DONE           EVT_REMAP_NUM(4, 19)
#define  EVT_RX_TF_DETECT_6             EVT_REMAP_NUM(4, 20)
#define  EVT_BF_EXP_DMA_ERROR           EVT_REMAP_NUM(4, 21)
#define  EVT_BF_IMP_DMA_ERROR           EVT_REMAP_NUM(4, 22)
#define  EVT_BF_NDP_DMA_ERROR           EVT_REMAP_NUM(4, 23)
#define  EVT_BF_CSI_DMA_ERROR           EVT_REMAP_NUM(4, 24)
#define  EVT_BF_SSM_DMA_ERROR           EVT_REMAP_NUM(4, 25)
#define  EVT_TX_TIMR_PROG_TIMR_2        EVT_REMAP_NUM(4, 26)
#define  EVT_DFW_2_PFW_MSG_TRIG         EVT_REMAP_NUM(4, 27)
#define  EVT_TX_TIMR_PROG_TIMR_3        EVT_REMAP_NUM(4, 28)
#define  EVT_PFW_2_SFW_MSG_TRIG         EVT_REMAP_NUM(4, 29)
#define  EVT_CM3_CTRL_4                 EVT_REMAP_NUM(4, 30)
#define  EVT_RX_TF_DONE                 EVT_REMAP_NUM(4, 31)

//from U8 gEvtMuxTbl[5] =    //CPUx : GRP5 - B00:31 for individual events, all CPUs
#define  EVT_RX_BBIF_END_PPDU_5         EVT_REMAP_NUM(5, 0)
#define  EVT_ADMA_STA_INFO1_IRQ         EVT_REMAP_NUM(5, 1)
#define  EVT_ADMA_STA_INFO2_IRQ         EVT_REMAP_NUM(5, 2)
#define  EVT_BF_NDP_LEN_RDY             EVT_REMAP_NUM(5, 3)
#define  EVT_EU_TX_UNDERFLOW            EVT_REMAP_NUM(5, 4)
#define  EVT_TX_RDY_FALL_ERROR          EVT_REMAP_NUM(5, 5)
#define  EVT_BF_EXP_DOWNLOAD_DONE_2     EVT_REMAP_NUM(5, 6)	//track download done at CPU3

#define  EVT_RX_BBIF_AVL                EVT_REMAP_NUM(5, 11)
#define  EVT_ADMA_TEST_IRQ              EVT_REMAP_NUM(5, 13)
#define  EVT_ADMA_CHANNEL9_IRQ          EVT_REMAP_NUM(5, 14)
#define  EVT_SW_MU_NSYM_DONE            EVT_REMAP_NUM(5, 15)
#define  EVT_RX_BBIF_FCS_VALID          EVT_REMAP_NUM(5, 17)
#define  EVT_ADMA_TX0_IRQ               EVT_REMAP_NUM(5, 18)
#define  EVT_ADMA_TX1_IRQ               EVT_REMAP_NUM(5, 19)
#define  EVT_ADMA_TX2_IRQ               EVT_REMAP_NUM(5, 20)
#define  EVT_ADMA_TX3_IRQ               EVT_REMAP_NUM(5, 21)
#define  EVT_TEST_TRIG_BITMAP_REQ       EVT_REMAP_NUM(5, 22)
#define  EVT_RX_AMSDU_SINGLE_QCMD       EVT_REMAP_NUM(5, 23)
#define  EVT_RX_BBIF_RX_HW_ACCEL        EVT_REMAP_NUM(5, 24)

// Setup/Initialization routines
void EVT_init(U32 cpuId);
void EVT_mapCode(void);
void EVT_initCpu_0(void);
void EVT_initCpu_1(void);
void EVT_initCpu_2(void);
void EVT_initCpu_3(void);
void EVT_initCpu_4(void);
void EVT_initCpu_5(void);
void EVT_initCpu_6(void);
void EVT_initCpu_7(void);
void EVT_initCpu_8(void);
void EVT_initCpu_9(void);

////////////////////////////////////////////////////////
// For reference, group format layout for easy lookup
////////////////////////////////////////////////////////
/*
#      Grp     Bit
////////////////////
0   0   0
1   0   1
2   0   2
3   0   3
4   0   4
5   0   5
6   0   6
7   0   7
8   0   8
9   0   9
10  0   10
11  0   11
12  0   12
13  0   13
14  0   14
15  0   15
16  0   16
17  0   17
18  0   18
19  0   19
20  0   20
21  0   21
22  0   22
23  0   23
24  0   24
25  0   25
26  0   26
27  0   27
28  0   28
29  0   29
30  0   30
31  0   31
////////////////////
32  1   0
33  1   1
34  1   2
35  1   3
36  1   4
37  1   5
38  1   6
39  1   7
40  1   8
41  1   9
42  1   10
43  1   11
44  1   12
45  1   13
46  1   14
47  1   15
48  1   16
49  1   17
50  1   18
51  1   19
52  1   20
53  1   21
54  1   22
55  1   23
56  1   24
57  1   25
58  1   26
59  1   27
60  1   28
61  1   29
62  1   30
63  1   31
////////////////////
64  2   0
65  2   1
66  2   2
67  2   3
68  2   4
69  2   5
70  2   6
71  2   7
72  2   8
73  2   9
74  2   10
75  2   11
76  2   12
77  2   13
78  2   14
79  2   15
80  2   16
81  2   17
82  2   18
83  2   19
84  2   20
85  2   21
86  2   22
87  2   23
88  2   24
89  2   25
90  2   26
91  2   27
92  2   28
93  2   29
94  2   30
95  2   31
////////////////////
96  3   0
97  3   1
98  3   2
99  3   3
100 3   4
101 3   5
102 3   6
103 3   7
104 3   8
105 3   9
106 3   10
107 3   11
108 3   12
109 3   13
110 3   14
111 3   15
112 3   16
113 3   17
114 3   18
115 3   19
116 3   20
117 3   21
118 3   22
119 3   23
120 3   24
121 3   25
122 3   26
123 3   27
124 3   28
125 3   29
126 3   30
127 3   31
////////////////////
128     4       0
129     4       1
130     4       2
131     4       3
132     4       4
133     4       5
134     4       6
135     4       7
136     4       8
137     4       9
138     4       10
139     4       11
140     4       12
141     4       13
142     4       14
143     4       15
144     4       16
145     4       17
146     4       18
147     4       19
148     4       20
149     4       21
150     4       22
151     4       23
152     4       24
153     4       25
154     4       26
155     4       27
156     4       28
157     4       29
158     4       30
159     4       31
////////////////////
160     5       0
161     5       1
162     5       2
163     5       3
164     5       4
165     5       5
166     5       6
167     5       7
168     5       8
169     5       9
170     5       10
171     5       11
172     5       12
173     5       13
174     5       14
175     5       15
176     5       16
177     5       17
178     5       18
179     5       19
180     5       20
181     5       21
182     5       22
183     5       23
184     5       24
185     5       25
186     5       26
187     5       27
188     5       28
189     5       29
190     5       30
191     5       31
////////////////////

*/

#endif /*SHAL_EVENT_H_ */
