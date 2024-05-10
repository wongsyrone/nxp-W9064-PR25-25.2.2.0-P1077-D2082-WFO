/** @file ap8xLnxDesc.h
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

#ifndef AP8X_DESC_H_
#define AP8X_DESC_H_

#include <linux/if_ether.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/list.h>

#define roundup_MRVL(x, y)   ((((x) + ((y) - 1)) / (y)) * (y))

#define SOFT_STAT_STALE                               0x80

/* TODO. Do we need special Processing for EAPOL and TCP ACK? */
#if 0
#define txring_Ctrl_TAG_EAP     0x02	// Tag for EAPOL frames
#ifdef TCP_ACK_ENHANCEMENT
//for TCP ACK ENHANCEMENT.
#define txring_Ctrl_TAG_TCP_ACK 0x4
#endif
#endif

#define rxring_Ctrl_STAfromDS   0x1FE	// STA Index for packets from DS
#define rxring_Ctrl_STA_unknown 0x1FF	// STA Index for packets from Unknown Clients

/* TODO, how to check if the packet from DS? */

/* TODO, included in struct acnt_rx_s. Do we still need accounting buffer? */
// HW defined structure
typedef struct {		// HW Rx buffer
	union {
		struct {	// Overlay mark w/ SW status
			u_int16_t chan;	// SW: Channel, P20 (xxx number+band or CF)
			u_int16_t flags;	// SW: Flags (RXSWFLAG_*)
		};
		u_int32_t mark;	// BEEF_DCBA
	};
	//DWORD-1
	u_int32_t cfo:17;
	u_int32_t reservedcfo:7;
	u_int32_t nf_x:8;
	//DWORD-2
	u_int16_t dta:12;
	u_int16_t reserveddta:4;
	u_int8_t t2;
	u_int8_t rssi_x;	// RSSI
	//DWORD-3
	u_int16_t leg_len;	// LSIG-Len
	u_int16_t service;	//
	//DWORD-4
	u_int32_t rx_cq:24;	//
	u_int32_t reservedrxcq:8;
	//DWORD-5
	u_int32_t ht_sig1:24;	// HT-SIG-1 or VHT-SIG-A1
	u_int32_t reservedhtsig:8;
	//DWORD-6
	u_int32_t ht_sig2:18;	// [17:0]  HT-SIG-2 or VHT-SIG-A2
	u_int32_t Rx_LSig_Rsvd:1;	// [23:18] { 2'b0, lsig_rsvd, lsig_parity, lsig_bad_parity, htsig_bad_crc }
	u_int32_t Rx_LSig_parity:1;
	u_int32_t Rx_LSig_bad_parity:1;
	u_int32_t Rx_HTSig_bad_crc:3;
	u_int32_t rate:8;	// [31:24] Legacy rate code (LSIG) -- Format of PLCP (11a/b)
	//DWORD-7,8.9.10
	u_int32_t gain_code[4];	// [21:0]  gain_code(path)
	// [31:22] bbu_rxinfo_rsvd
	//DWORD-11
	u_int32_t pm_rssi_dbm_b:12;
	u_int32_t pm_rssi_dbm_a:12;
	u_int32_t mu_cq0:8;
	// DWORD-12
	u_int32_t pm_rssi_dbm_d:12;
	u_int32_t pm_rssi_dbm_c:12;
	u_int32_t mu_cq1:8;
	// DWORD-13
	u_int32_t pm_nf_dbm_b:12;
	u_int32_t pm_nf_dbm_a:12;
	u_int32_t mu_cq2:8;
	// DWORD-14
	u_int32_t pm_nf_dbm_d:12;
	u_int32_t pm_nf_dbm_c:12;
	u_int32_t mu_cq3:8;
	// DWORD-15
	u_int32_t rx_pkt_secondary:1;
	u_int32_t rx_dyn_bw:1;
	u_int32_t rx_ind_bw:2;
	u_int32_t rx_dup_likely_bw:2;
	u_int32_t rx_pkt_info:3;
	u_int32_t rx_vhtsigb:23;
	// DWORD-16
	u_int16_t lltf_phroll;
	u_int16_t htlf_phroll;
	// DWORD-17
	u_int32_t T2;
	// DWORD-18
	u_int32_t T3;
	// DWORD-19
	u_int32_t Rx_timestamp;
	// DWORD-20
	u_int32_t TSF;
	// DWORD-21
	u_int32_t param:24;
	u_int32_t Rx_AMPDU_Num:8;
	// DWORD-22
	u_int16_t qc;		//
	u_int16_t sq2;		//temp tookout foo fb_mcs_param;
	//DWORD - 23
	u_int32_t ht_ctrl;	//
	u_int32_t Hdr[0];	// Len from HW includes rx_info w/ hdr
} rx_info_t;

/* TODO, included in struct acnt_rx_s. Do we still need accounting buffer? */
/** local definitions **/
typedef struct {
	u_int16_t len;
	u_int16_t FrmCtl;
	u_int8_t dur[2];
	u_int8_t addr1[6];
	u_int8_t addr2[6];
	u_int8_t addr3[6];
	u_int8_t seq[2];
	u_int8_t addr4[6];
	u_int8_t Payload[0];
} dot11_t;

// HW defined structure
/* TODO, included in struct acnt_rx_s. Do we still need accounting buffer? */
typedef struct tx_info_s tx_info_t;	// Tx INFO used by MAC HW

typedef struct eudesc_t {
	u_int32_t key_index:14;
	u_int32_t key_size:2;
	u_int32_t hdr_start_offset:4;
	u_int32_t priority:4;
	u_int32_t op_mode:3;
	u_int32_t force_bypass:1;
	u_int32_t mic_size:2;
	u_int32_t rsvd:2;
} eudesc_t;

/* TODO, included in acnt_tx_t. Do we still need accounting buffer? */
struct tx_info_s {		// Tx INFO used by MAC HW
	union {
		struct {
			u_int8_t txTry;	// Max Tx Attempts
			u_int8_t txDone;	// Number of Tx Data attempts sent
			u_int16_t status;	// Status of Tx
		};
		u_int32_t dw0;	// Union to access as word
	};
	u_int32_t Hdr_fw;	// Packet, starting w/ 802.11 Header, it was used in fw
	u_int16_t ExpIFBRespTxTime;	//
	u_int8_t MID;		// Used to stop other related traffic on an Tx Failure
	u_int8_t DPD;		// DPD training
	u_int8_t NDP_Alt_PID40;
	u_int8_t NDP_Alt_PID80;
	u_int8_t NDP_Alt_PID160;
	u_int8_t resvdndp3;
	u_int32_t tsfLo;	//
	u_int32_t tsfHi;	//
	eudesc_t eu_desc;	// Encryption Unit Descriptor
	u_int32_t txParm1;	// Tx Params (TP_*)
	u_int16_t QCF;		// QoS Control Field
	u_int16_t swLegLen;	// Software Override L-SIG Len
	u_int16_t gid_PAID;	// VHT: 0:5=GID 6:14=PAID
	u_int8_t ndpParm;	// Used for NDP sounding
	u_int8_t txParm2;	// Tx Params (TP2_*)
	u_int32_t rateInfo;	// Rate Information (RI_*)
	u_int32_t rateDrop_fw;	// Rate Drop table, when used. it was a pointer used in fw.
	u_int32_t ndpRateInfo;	// Rate Info, for NDP
	u_int32_t ctrlWrapHTC;	// Used to send Control Wrapper frames
	u_int32_t altRateInfo;	//
	u_int16_t lltf_phroll;	//
	u_int16_t cfo;		//
	u_int32_t toa_tod_tx_time;	//
	u_int32_t toa_tod_rx_time;	//
	u_int16_t txParm3;	// Tx Params (TP3_*)

	u_int16_t toa_tod_rx_time32_39:8;
	u_int16_t cfo_16:1;
	u_int16_t deltaP_usr:3;
	u_int16_t deltaP:4;

	u_int32_t swAgSize:20;	// Software Override AMPDU Size
	u_int32_t swAgDensity:12;	//

	u_int32_t rtsRateInfo;	// Rate Info, for RTS
	u_int32_t alt_rtsrateinfo;	//
	u_int16_t alt_swaggr_size;	//
	u_int16_t alt_swaggr_density;

	// Software fields used from radio FW
	//u_int32_t             pad[1];             // Unused (Cache Alignment)
	u_int32_t Link_fw;	// Next in Chain, it was used in fw
	u_int32_t Owner_fw;	// TxRing using this TxINFO, it was used in fw
};

extern int wlTxRingInit(struct net_device *netdev);
extern void wlTxRingFree(struct net_device *netdev);
extern int wlTxRingAlloc(struct net_device *netdev);

#endif /* AP8X_DESC_H_ */
