/** @file smac_ctrl.h
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
#ifndef _SMAC_CTRL_H_
#define _SMAC_CTRL_H_

#define SMAC_CTRL_IP_VERSION              (HAL_SMAC_CTRL_BASE + 0x00)
#define SMAC_CTRL_CLOCK_GATE_CTRL         (HAL_SMAC_CTRL_BASE + 0x04)
#define SMAC_SOFT_RST_CTRL                (HAL_SMAC_CTRL_BASE + 0x0C)
#define SMAC_CM3_DWNLD_BUS                (HAL_SMAC_CTRL_BASE + 0x10)
#define SMAC_CTRL_BASE_ADDR_DDR_LO        (HAL_SMAC_CTRL_BASE + 0x34)
#define SMAC_CTRL_BASE_ADDR_QMAN_LO       (HAL_SMAC_CTRL_BASE + 0x38)
#define SMAC_CTRL_BASE_ADDR_BMAN_LO       (HAL_SMAC_CTRL_BASE + 0x3C)
#define SMAC_CTRL_BASE_ADDR_NSS_HI        (HAL_SMAC_CTRL_BASE + 0x48)
#define SMAC_CTRL_BASE_ADDR_DDR_HI        (HAL_SMAC_CTRL_BASE + 0x4C)
#define SMAC_CTRL_BASE_ADDR_QMAN_HI       (HAL_SMAC_CTRL_BASE + 0x50)
#define SMAC_CTRL_BASE_ADDR_BMAN_HI       (HAL_SMAC_CTRL_BASE + 0x54)
#define SMAC_CTRL_BASE_ADDR_CM3_REMAP_WIN (HAL_SMAC_CTRL_BASE + 0x80)
#define SMAC_CTRL_BASE_ADDR_PTA_CTRL      (HAL_SMAC_CTRL_BASE + 0xDC)
#define SMAC_CTRL_BASE_ADDR_PTA_TX_CTRL   (HAL_SMAC_CTRL_BASE + 0x108)
#define SMAC_CTRL_BASE_ADDR_PTA_RX_CTRL   (HAL_SMAC_CTRL_BASE + 0x10C)

#ifndef _HAL_CIU_H_
// Copied from PFW hal_ciu.h
#define HAL_CIU_REG_PA_PE                 (HAL_CIU_CFG_BASE + 0xD4)
#define HAL_CIU_REG_MISC1                 (HAL_CIU_CFG_BASE + 0x44)
#endif

#define BBTX_TIMER2_DUR                   4	//For BBTX_TIMER2 duration, in usec

typedef struct SMAC_CTRL_PTA_CTRL_ST {
	U32 smac_bca_en:1;	// SMAC_BCA_EN - Enable BCA
	U32 bt_gnt_qual_cca:1;	// BT_Gnt_Qual_CCA - Artificial CCA when Bluetooth has been granted by BCA
	U32 mws_gnt_qual_cca:1;	// MWS_Gnt_Qual_CCA - Artificial CCA when MWS has been granted by BCA
	U32 bbud_pkt_end_ind_en:1;	// BBUD_Pkt_End_Ind_En - WLRx uses BBUD_PKT_END_IND input
	U32 pta_use_rx_pkt_ind:1;	// PTA_Use_Rx_Pkt_Ind - Enable BBUD_RX_PKT_IND to inform BCA arbiter when WLAN is
	U32 force_phy_stdby_when_bt_gnt:1;	// Enable force PHY signal to standby when BCA grant to Bluetooth
	U32 force_phy_stdby_when_mws_gnt:1;	// Enable force PHY signal to standby when BCA grant to MWS
	U32 Reserved:1;		// Always write 0. Ignore Read Value
	U32 wltxok_force_value:1;	// Force this value onto WLTxOk input when pta_ctrl[9] (wltxok_force_en)==1
	U32 wltxok_force_en:1;	// Enable force to WLTxOk input from BCA
	U32 wltx_force_value:1;	// Force this value onto output WLTx_Core when pta_ctrl[11] (wltx_force_en)==1
	U32 wltx_force_en:1;	// Enable force to output WLTx from core
	U32 wltxpri_tid_op:1;	// 0x0 = use transmit frame type to determine priority of tx frame; 0x1 = use transmit TID to determine priority of tx frame
	U32 wlrxpri_tid_op:1;	// 0x0 = use received frame type to determine priority of rx frame; 0x1 = use received TID to determine priority of rx frame
	U32 WlSyncActive:1;	// WLAN flow control signal
	U32 WlReqExt:1;		// WLAN Tx/Rx request signal to indicate 1 MAC frame exchange window (Tx.Packet + Rx.Ack) and (Rx.Packet + Tx.Ack)
	U32 wltxok_core:1;	// WLTxOk status (Read Only)
	U32 WlSleep:1;		// Software sets this bit when WLAN needs to go to sleep
	U32 Reserved1:9;	// Always write 0. Ignore Read Value
	U32 sw_rx_pri:2;	// Rx frame uses software Rx priority when pta_ctrl[31] (sw_en_pri)=1
	U32 sw_tx_pri:2;	// Tx frame uses software Tx priority when pta_ctrl[31] (sw_en_pri)=1
	U32 sw_en_pri:1;	// Enable software priority for Tx/Rx frame
} SMAC_CTRL_PTA_CTRL_ST;

typedef struct SMAC_CTRL_PTA_TX_CTRL_ST {
	U32 txtid:3;		// TX frame TID
	U32 reserved:1;		// Always write 0. Ignore read value
	U32 txtype:6;		// TX Frame Type
	U32 reserved1:18;	// Always write 0. Ignore read value
	U32 smac_wl_tx_align_mws:1;	// Indicates this TX frame is MWS aligned
	U32 smac_wl_tx_align:1;	// Indicates this TX frame is BT aligned
	U32 smac_tx_req_abort_pulse:1;	// Hardware will deassert WlTx when detecting this pulse
	U32 smac_tx_req_start_pulse:1;	// Hardware will assert WlTx when detecting this pulse
} SMAC_CTRL_PTA_TX_CTRL_ST;

typedef struct SMAC_CTRL_PTA_RX_CTRL_ST {
	U32 rxtid:3;		// RX frame TID
	U32 reserved:1;		// Always write 0. Ignore read value
	U32 rxtype:6;		// RX Frame Type
	U32 reserved1:21;	// Always write 0. Ignore read value
	U32 smac_rx_req_start_pulse:1;	// Hardware will assert WlRx when detecting this pulse
} SMAC_CTRL_PTA_RX_CTRL_ST;

#endif //_SMAC_CTRL_H_
