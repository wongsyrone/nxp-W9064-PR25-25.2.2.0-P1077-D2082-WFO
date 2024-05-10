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

#define roundup_MRVL(x, y)   ((((x)+((y)-1))/(y))*(y))

#define SOFT_STAT_STALE                               0x80

#define EAGLE_RXD_CTRL_DRIVER_OWN                     0x00
#define EAGLE_RXD_CTRL_OS_OWN                         0x04
#define EAGLE_RXD_CTRL_DMA_OWN                        0x80

#define EAGLE_RXD_STATUS_IDLE                         0x00
#define EAGLE_RXD_STATUS_OK                           0x01
#define EAGLE_RXD_STATUS_MULTICAST_RX                 0x02
#define EAGLE_RXD_STATUS_BROADCAST_RX                 0x04
#define EAGLE_RXD_STATUS_FRAGMENT_RX                  0x08

#define EAGLE_TXD_STATUS_IDLE                   0x00000000
#define EAGLE_TXD_STATUS_USED                   0x00000001
#define EAGLE_TXD_STATUS_OK                     0x00000001
#define EAGLE_TXD_STATUS_OK_RETRY               0x00000002
#define EAGLE_TXD_STATUS_OK_MORE_RETRY          0x00000004
#define EAGLE_TXD_STATUS_MULTICAST_TX           0x00000008
#define EAGLE_TXD_STATUS_BROADCAST_TX           0x00000010
#define EAGLE_TXD_STATUS_FAILED_LINK_ERROR      0x00000020
#define EAGLE_TXD_STATUS_FAILED_EXCEED_LIMIT    0x00000040
#define EAGLE_TXD_STATUS_FAILED_AGING           0x00000080
#define EAGLE_TXD_STATUS_FW_OWNED               0x80000000

#define EAGLE_TXD_XMITCTRL_USE_RATEINFO         0x1
#define EAGLE_TXD_XMITCTRL_DISABLE_AMPDU        0x2
#define EAGLE_TXD_XMITCTRL_ENABLE_AMPDU         0x4
#define EAGLE_TXD_XMITCTRL_USE_MC_RATE          0x8	// Use multicast data rate

#define MRVL_PCI_DMA_SIGNATURE			0xCAFEEFAC

#ifdef SOC_W8764
typedef struct wlRateInfo_t {
#ifdef MV_CPU_LE
	u_int32_t Format:1;	//0 = Legacy format, 1 = Hi-throughput format
	u_int32_t ShortGI:1;	//0 = Use standard guard interval,1 = Use short guard interval
	u_int32_t Bandwidth:1;	//0 = Use 20 MHz channel,1 = Use 40 MHz channel
	u_int32_t RateIDMCS:7;	//= RateID[3:0]; Legacy format,= MCS[5:0]; HT format
	u_int32_t AdvCoding:1;	//AdvCoding 0 = No AdvCoding,1 = LDPC,2 = RS,3 = Reserved
	u_int32_t AntSelect:2;	//Bitmap to select one of the transmit antennae
	u_int32_t ActSubChan:2;	//Active subchannel for 40 MHz mode 00:lower, 01= upper, 10= both on lower and upper
	u_int32_t Preambletype:1;	//Preambletype 0= Long, 1= Short;
	u_int32_t pid:4;	// Power ID
	u_int32_t ant2:1;	// bit 2 of antenna selection field 
	u_int32_t ant3:1;
	u_int32_t bf:1;		// 0: beam forming off; 1: beam forming on
	u_int32_t gf:1;		// 0: green field off; 1, green field on
	u_int32_t count:4;
	u_int32_t rsvd2:3;
	u_int32_t drop:1;
#else
	union {
		u_int32_t u32_data;
		struct {
			u_int32_t drop:1;
			u_int32_t rsvd2:3;
			u_int32_t count:4;
			u_int32_t gf:1;
			u_int32_t bf:1;
			u_int32_t ant3:1;
			u_int32_t ant2:1;
			u_int32_t pid:4;
			u_int32_t Preambletype:1;
			u_int32_t ActSubChan:2;
			u_int32_t AntSelect:2;
			u_int32_t AdvCoding:1;
			u_int32_t RateIDMCS:7;
			u_int32_t Bandwidth:1;
			u_int32_t ShortGI:1;
			u_int32_t Format:1;
		};
	};
#endif
} __attribute__ ((packed)) wlRateInfo_t;
#else
typedef struct wlRateInfo_t {
#ifdef MV_CPU_LE
	u_int16_t Format:1;	//0 = Legacy format, 1 = Hi-throughput format
	u_int16_t ShortGI:1;	//0 = Use standard guard interval,1 = Use short guard interval
	u_int16_t Bandwidth:1;	//0 = Use 20 MHz channel,1 = Use 40 MHz channel
	u_int16_t RateIDMCS:6;	//= RateID[3:0]; Legacy format,= MCS[5:0]; HT format
	u_int16_t AdvCoding:2;	//AdvCoding 0 = No AdvCoding,1 = LDPC,2 = RS,3 = Reserved
	u_int16_t AntSelect:2;	//Bitmap to select one of the transmit antennae
	u_int16_t ActSubChan:2;	//Active subchannel for 40 MHz mode 00:lower, 01= upper, 10= both on lower and upper
	u_int16_t Preambletype:1;	//Preambletype 0= Long, 1= Short;
#else
	union {
		u_int16_t u16_data;
		struct {
			u_int16_t Preambletype:1;
			u_int16_t ActSubChan:2;
			u_int16_t AntSelect:2;
			u_int16_t AdvCoding:2;
			u_int16_t RateIDMCS:6;
			u_int16_t Bandwidth:1;
			u_int16_t ShortGI:1;
			u_int16_t Format:1;
		};
	};
#endif
} __attribute__ ((packed)) wlRateInfo_t;
#endif

#ifdef NEW_DP
#define MAX_TX_RING_SEND_SIZE   1024
#define MAX_TX_RING_DONE_SIZE   1024
#define MAX_RX_RING_SEND_SIZE   (1024*16)
#define MAX_RX_RING_DONE_SIZE   (1024*16)

typedef union {			// Union for Tx DA/SA or Mgmt Overrides
	struct {		// Fields for Data frames
		u_int8_t DA[6];	// L2 Destination Address
		u_int8_t SA[6];	// L2 Source Address
	};
	struct {		// Fields when marked as Mgmt
		u_int16_t RateCode;	// Rate Code: Table + Index
		// xxx MGMT: Key? Max Retries? Other?
		u_int8_t MaxRetry;
		u_int8_t pad[5];	// Unused
		u_int32_t Callback;	// Used for Packet returned to Firmware
	};
} tx_da_sa_t;

#define RateCode_Default        0xFFFF	// Don't override the Rate
#define RateCode_Type_MASK      0xC000	// Mask  to extract Type
#define RateCode_Type_SHIFT     14	// Shift to extract Type
#define RateCode_Type_VHT       0x8000	// Use VHT rates
#define RateCode_Type_HT        0x4000	// Use HT rates
#define RateCode_Type_Legacy    0x0000	// Use Legacy (a/b/g) rates
#define RateCode_MAXPWR         0x2000	// Send at Max Power / Off Channel
#define RateCode_RSVD           0x1000	// Unused
#define RateCode_STBC           0x0800	// Use Space Time Block Codes
#define RateCode_BFMR           0x0400	// Use Beamforming
#define RateCode_SS_MASK        0x0300	// Mask  to extract nSS-1
#define RateCode_SS_SHIFT       8	// Shift to extract nSS-1
#define RateCode_MCS_MASK       0x00F0	// Mask  to extract MCS rate
#define RateCode_MCS_SHIFT      4	// Shift to extract MCS rate
#define RateCode_BW_MASK        0x000C	// Mask  to extract Channel BW
#define RateCode_BW_SHIFT       2	// Shift to extract Channel BW
#define RateCode_BW_160MHZ      0x000C	// Send 160M wide packet (or 80+80)
#define RateCode_BW_80MHZ       0x0008	// Send  80M wide packet
#define RateCode_BW_40MHZ       0x0004	// Send  40M wide packet
#define RateCode_BW_20MHZ       0x0000	// Send  20M wide packet
#define RateCode_LDPC           0x0002	// Use Low Density Parity Codes
#define RateCode_SGI            0x0001	// Use Short Guard Interval
#define RateCode_Legacy_6MBPS       0
#define RateCode_Legacy_1MBPS_Short 8
#define RateCode_Legacy_1MBPS_Long  9

// RateCode usage notes:
// * General
//     * No error checking is provided on RateCodes, so usage of invalid values
//       or rates not supported by HW can result in undefined operation.
//     * Some values are not allowed by Std, but are included to sanitize the
//       table;
//     * MaxPwr should only be used for rates that can be sent using Max Power,
//       such as for TxEVM limits or regulatory. It is only valid for Host
//       Generated frames, and not for DRA, etc.
// * VHT
//     * Need to reconsile MU.
// * HT
//     * MCS and SS are made to mimic 11ac, so MCS=mcs[2:0] and SS=mcs[4:3];
//     * MCS32 is selected by providing MCS=10;
// * Legacy
//     * MCS0..7  = 6/9/12/18/24/36/48/54;
//     * MCS8..15 = 1S/1L/2S/2L/5.5S/5.5L/11S/11L;
//     * BW is used to request legacy duplicate modes;

typedef struct _wltxdesc_t {	// ToNIC Tx Request Ring Entry
	tx_da_sa_t u;		// Union for Tx DA/SA or Mgmt Overrides
	u_int32_t Ctrl;		// Bit fields (txring_Ctrl_*)
	// Note: Based on 32 bit addresses. If needing 64 bit PCIe addresses are
	// required, some small changes will be required both here and in the code,
	// and those will degrade performance. They can be ifdef-ed. Cisco usage
	// should be fine staying with 32 bit addressing.
	u_int32_t Data;		// PCIe Payload Pointer (Starts w/ SNAP)
	u_int32_t User;		// Value returned to Host when done

#ifdef TCP_ACK_ENHANCEMENT
	//for TCP ACK ENHANCEMENT. 
	u_int32_t tcp_dst_src;
	u_int32_t tcp_sn;
#endif
} wltxdesc_t;
#define txring_Ctrl_LenShift    0	// PCIe Payload size (Starts w/ SNAP)
#define txring_Ctrl_LenMask     0x3FFF	// PCIe Payload size (Starts w/ SNAP)
#define txring_Ctrl_QIDshift    14	// Queue ID (STA*UP, Mcast, MC2UC, etc)
#define txring_Ctrl_QIDmask     0xFFF	// Queue ID (STA*UP, Mcast, MC2UC, etc)
#define txring_Ctrl_TAGshift    26	// Tags for special Processing (txring_Ctrl_TAG_*)
#define txring_Ctrl_TAGmask     0x3F	// Tags for special Processing (txring_Ctrl_TAG_*)
#define txring_Ctrl_TAG_MGMT    0x01	// Has Host generated dot11 Header
#define txring_Ctrl_TAG_EAP     0x02	// Tag for EAPOL frames
#ifdef TCP_ACK_ENHANCEMENT
//for TCP ACK ENHANCEMENT.
#define txring_Ctrl_TAG_TCP_ACK 0x4
#endif

/*bit 28 & 29 is only used during tx continuous pkt mode*/
#define txring_Ctrl_TxContShift	28	//For tx continuous pkt descriptor tracking
#define txring_Ctrl_TxContMask	0x3	//Value to be stored must be less than txcontinuous_desc_num

#ifdef DOT11V_DMS
#define txring_Ctrl_TAG_AMSDU   0x10
#define txring_Ctrl_TAG_RSVD    0x20	// Unused
#else
#define txring_Ctrl_TAG_RSVD    0x3C	// Unused
#endif

typedef struct {		// FromNIC Tx Done Ring Entry
	u_int32_t User;		// Value returned to Host when done
} tx_ring_done_t;

enum {				// Type of Key
	key_type_none,		// Bypass (never stored in real keys)
	key_type_WEP40,		// WEP with  40 bit key + 24 bit IV =  64
	key_type_WEP104,	// WEP with 104 bit key + 24 bit IV = 128
	key_type_TKIP,		// TKIP
	key_type_CCMP128,	// CCMP with 128 bit Key
	key_type_CCMP256,	// CCMP with 256 bit Key + 16 byte MIC
	key_type_WAPI,		// WAPI
	key_type_unknown,	// Not known what key was used (Rx Only)
	key_type_GCMP128,	// GCMP with 128 bit Key
	key_type_GCMP256,	// GCMP with 256 bit Key + 16 byte MIC  
	// xxx 192 bit? MIC Size? MFP/BIP?
};
//typedef struct _wlrxdesc_t /*__attribute__ ((packed))*/ wlrxdesc_t;
typedef struct {		// ToNIC Rx Empty Buffer Ring Entry
	u_int32_t Data;		/* PCIe Payload Pointer               */
	u_int32_t User;		/* Value returned to Host when done   */
	//struct sk_buff  *pSkBuff;           /* associated sk_buff for Linux       */
	//void            *pBuffData;         /* virtual address of payload data    */ 
} wlrxdesc_t;

typedef struct {		// FromNIC Rx Done Ring Entry
	u_int32_t User;		// Value returned to Host when done
	u_int32_t TSF;		// Rx Radio Timestamp from MAC
	u_int32_t Ctrl;		// Bit fields (rxring_Ctrl_*)
} rx_ring_done_t;
#define rxring_Ctrl_CaseShift   0	// What is in the buffer (rxring_Case_*)
#define rxring_Ctrl_CaseMask    0x1F	// What is in the buffer (rxring_Case_*)
#define rxring_Ctrl_STAshift    5	// Which associated Client its from (or Mcast group)
#define rxring_Ctrl_STAmask     0x1FF	// Which associated Client its from (or Mcast group)
#define rxring_Ctrl_STA_unknown 0x1FF	// STA Index for packets from Unknown Clients
#define rxring_Ctrl_STAfromDS	0x1FE	// STA Index for packets from DS
#define rxring_Ctrl_TIDshift    14	// TID/UP for QoS Data frames
#define rxring_Ctrl_TIDmask     0xF	// TID/UP for QoS Data frames
#define rxring_Ctrl_KEYshift    18	// Key Type used (key_type_*)
#define rxring_Ctrl_KEYmask     0xF	// Key Type used (key_type_*)
#define rxring_Ctrl_Trunc     (1UL<<31)	// Packet Truncated
// Bits 31:22 are reserved

enum {				// What is in Rx Buffer and why it was delivered
	rxring_Case_fast_data,	// Data for Assoc Clients in Run State on Channel [Fmt1]
	rxring_Case_fast_bad_amsdu,	// Fast Data with bad AMSDU Header [Fmt2]
	rxring_Case_slow_noqueue,	// Data for Assoc Clients using unconfigured queue [Fmt0]
	rxring_Case_slow_norun,	// Data for Assoc Clients not matching Run State [Fmt0]
	rxring_Case_slow_mcast,	// Data for filtered Multicast groups [Fmt0]
	rxring_Case_slow_bad_sta,	// Data for Unassoc Clients [Fmt0]
	rxring_Case_slow_bad_mic,	// Decrypt failure [Fmt0]
	rxring_Case_slow_bad_PN,	// Decrypt PN replay [Fmt0]
	rxring_Case_slow_mgmt,	// Mgmt traffic to this AP or Bcast [Fmt0]
	rxring_Case_slow_promisc,	// Packets captured promiscuously [Fmt0]
	rxring_Case_slow_del_done,	// Client has been deleted [N/A]
	rxring_Case_drop,	// Buffer returned to Host [N/A]
};

//
// Rx Buffer Formats
//    Each Case listed above will indicate the format used, and each format will
//    carry their length in the packet buffer. Should the packet be too big for
//    the buffer, it will be truncated, but the full length will still be
//    indicated. Currently only a single, fixed size Rx Pool is envisioned.
//
// Fmt0 is used for Slow path, when some processing of dot11 headers may still
// be required, or for promiscuous mode captures. It is in the HW RxINFO
// (rx_info_t) format including dot11_t followed by Payload. The Length field in
// the dot11_t is updated to only include Payload bytes, and is in Little Endian
// format. If the frame is too big, it is truncated to the buffer size, and
// promiscuous packets may also be configured for truncation to reduce load. The
// mark field is replaced with software status, and the RSSI will be updated to
// apply Rx calibration.
//
// Fmt1 is used for fast path Data packets in the run state, where all rx
// processing of dot11 headers is performed from radio FW. It has an AMSDU
// centric format of DA/SA/Len followed by SNAP, with the Length in Big Endian
// Format. In most cases conversion to Ethernet format is accomplished by
// copying 12 bytes to drop 8 bytes in the middle.
//
// Fmt2 is used for fast path AMSDU packets that are malformed. They just
// contain the dot11 header (dot11_t) containing the residual Len (Little
// Endian) after any valid MSDU have been extracted. The header is followed by
// the first invalid MSDU which will be truncated to 64 bytes.
//

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
	u_int32_t rx_gain_code_a:22, bbu_rxinfo_res_9_0:10;
	u_int32_t rx_gain_code_b:22, bbu_rxinfo_res_19_10:10;
	u_int32_t rx_gain_code_c:22, bbu_rxinfo_res_29_20:10;
	u_int32_t rx_gain_code_d:22,
#ifdef SOC_W8964
	 bbu_rxinfo_res_35_30:6, mu_cq_valid:4;
#else
	 bbu_rxinfo_res_39_30:10;
#endif

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
typedef struct tx_info_s tx_info_t;	// Tx INFO used by MAC HW

#ifdef SOC_W8964
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

#else

struct tx_info_s {		// Tx INFO used by MAC HW
	union {
		struct {
			u_int8_t txTry;	// Max Tx Attempts
			u_int8_t txDone;	// Number of Tx Data attempts sent
			u_int16_t status;	// Status of Tx
		};
		u_int32_t dw0;	// Union to access as word
	};
	dot11_t *Hdr;		// Packet, starting w/ 802.11 Header
	u_int16_t swAgDensity;	// Software Override AMPDU Density
	u_int8_t MID;		// Used to stop other related traffic on an Tx Failure
	u_int8_t rsvd1;		// Unused
	u_int16_t rtsDur0;	// Dur value of RTS on non-last Frag or Special(Beacon)
	u_int16_t rtsDur1;	// Dur value of RTS
	u_int32_t tsfLo;	// 
	u_int32_t tsfHi;	// 
	u_int16_t fragDur0;	// Dur value of Data on non-last
	u_int16_t fragDur1;	// Dur value of Data
	u_int32_t txParm1;	// Tx Params (TP_*)
	u_int16_t QCF;		// QoS Control Field
	u_int16_t swLegLen;	// Software Override L-SIG Len
	u_int16_t rsvd2;	// Unused
	u_int8_t ndpParm;	// Used for NDP sounding
	u_int8_t txParm2;	// Tx Params (TP2_*)
	u_int32_t rateInfo;	// Rate Information (RI_*)
	u_int32_t *rateDrop;	// Rate Drop table, when used
	u_int32_t ndpRateInfo;	// Rate Info, for NDP
	u_int32_t ctrlWrapHTC;	// Used to send Control Wrapper frames
	u_int16_t lastFragSize;	// 
	u_int16_t ExpIFBrespTxTime;	// 
	u_int16_t gid_PAID;	// VHT: 0:5=GID 6:14=PAID
	u_int16_t ndpPwrID;	// 
	u_int32_t rsvd3[2];	// Unused
	u_int16_t txParm3;	// Tx Params (TP3_*)
	u_int16_t rsvd4;	// Unused
	u_int32_t swAgSize;	// Software Override AMPDU Size
	u_int32_t rtsRateInfo;	// Rate Info, for RTS
	// Software fields used from radio FW
	u_int32_t pad[1];	// Unused (Cache Alignment)
	tx_info_t *Link;	// Next in Chain
	void *Owner;		// TxRing using this TxINFO
};
#endif // #ifdef SOC_W8964

#else /* !NEW_DP */
typedef struct _wltxdesc_t /*__attribute__ ((packed))*/ wltxdesc_t;
struct _wltxdesc_t {
	u_int8_t DataRate;
	u_int8_t TxPriority;
	u_int16_t QosCtrl;
	u_int32_t PktPtr;
	u_int16_t PktLen;
#ifdef ZERO_COPY
	u_int16_t multiframes;
	u_int32_t PktPtrArray[5];
	u_int16_t PktLenArray[5];
#endif
	u_int8_t DestAddr[6];
	u_int32_t pPhysNext;
	u_int32_t SapPktInfo;
	wlRateInfo_t RateInfo;
#if 1
	u_int8_t type;
	u_int8_t xmitcontrol;	//bit 0: use rateinfo, bit 1: disable ampdu
	u_int16_t reserved;
#else
	u_int16_t type;
#endif
#ifdef TCP_ACK_ENHANCEMENT
	u_int32_t tcpack_sn;
	u_int32_t tcpack_src_dst;
#endif
	/* end TCP ACK Enh */

	struct sk_buff *pSkBuff;
	wltxdesc_t *pNext;
	u_int32_t SoftStat;
	u_int32_t ack_wcb_addr;
	u_int8_t *staInfo;
#ifdef ZERO_COPY
	struct sk_buff *pSkBuffArray[5];
#endif
	u_int32_t Status;
#ifdef QUEUE_STATS_LATENCY
	u_int32_t TimeStamp1;
	u_int32_t TimeStamp2;
#endif
} __attribute__ ((packed));
#endif /* #ifdef NEW_DP */

typedef struct HwRssiInfo_t {
	u_int32_t Rssi_a:8;
	u_int32_t Rssi_b:8;
	u_int32_t Rssi_c:8;
#ifdef SOC_W8764
	u_int32_t Rssi_d:8;
#else
	u_int32_t Reserved:8;
#endif
} __attribute__ ((packed)) HwRssiInfo_t1;

typedef struct HwNoiseFloorInfo_t {
	u_int32_t NoiseFloor_a:8;
	u_int32_t NoiseFloor_b:8;
	u_int32_t NoiseFloor_c:8;
#ifdef SOC_W8764
	u_int32_t NoiseFloor_d:8;
#else
	u_int32_t Reserved:8;
#endif
} __attribute__ ((packed)) HwNoiseFloorInfo_t;

#ifndef NEW_DP
#ifdef SOC_W8363
typedef struct _wlrxdesc_t /*__attribute__ ((packed))*/ wlrxdesc_t;
struct _wlrxdesc_t {
	u_int8_t RxControl;	/* the control element of the desc    */
	u_int8_t RSSI;		/* received signal strengt indication */
	u_int8_t Status;	/* status field containing USED bit   */
	u_int8_t Channel;	/* channel this pkt was received on   */
	u_int16_t PktLen;	/* total length of received data      */
	u_int8_t SQ2;		/* unused at the moment               */
	u_int8_t Rate;		/* received data rate                 */
	u_int32_t pPhysBuffData;	/* physical address of payload data   */
	u_int32_t pPhysNext;	/* physical address of next RX desc   */
	u_int16_t QosCtrl;	/* received QosCtrl field variable    */
	u_int16_t HtSig2;	/* like name states                   */
	struct HwRssiInfo_t HwRssiInfo;
	struct HwNoiseFloorInfo_t HwNoiseFloorInfo;
	u_int8_t NoiseFloor;
	struct sk_buff *pSkBuff;	/* associated sk_buff for Linux       */
	void *pBuffData;	/* virtual address of payload data    */
	wlrxdesc_t *pNext;	/* virtual address of next RX desc    */
} __attribute__ ((packed));
#else
typedef struct _wlrxdesc_t /*__attribute__ ((packed))*/ wlrxdesc_t;
struct _wlrxdesc_t {
	u_int16_t PktLen;	/* total length of received data      */
	u_int8_t SQ2;		/* unused at the moment               */
	u_int8_t Rate;		/* received data rate                 */
	u_int32_t pPhysBuffData;	/* physical address of payload data   */
	u_int32_t pPhysNext;	/* physical address of next RX desc   */
	u_int16_t QosCtrl;	/* received QosCtrl field variable    */
	u_int16_t HtSig2;	/* like name states                   */
#ifdef QUEUE_STATS_LATENCY
	u_int32_t TimeStamp1;	/*Used for Total latency calculation from fw start to drv end */
	u_int32_t TimeStamp2;	/*Used for latency calculation as pkt moves from one section to another */
#endif
	struct HwRssiInfo_t HwRssiInfo;
	struct HwNoiseFloorInfo_t HwNoiseFloorInfo;
	u_int8_t NoiseFloor;
#ifdef QUEUE_STATS_CNT_HIST
	u_int8_t qsRxTag;
	u_int8_t reserved[2];
#else
	u_int8_t reserved[3];
#endif
	u_int8_t RSSI;		/* received signal strengt indication */
	u_int8_t Status;	/* status field containing USED bit   */
	u_int8_t Channel;	/* channel this pkt was received on   */
	u_int8_t RxControl;	/* the control element of the desc    */
	//above are 32bits aligned and is same as FW, RxControl put at end for sync     
	struct sk_buff *pSkBuff;	/* associated sk_buff for Linux       */
	void *pBuffData;	/* virtual address of payload data    */
	wlrxdesc_t *pNext;	/* virtual address of next RX desc    */
} __attribute__ ((packed));
#endif
#endif /* #ifndef NEW_DP */
extern int wlTxRingAlloc(struct net_device *netdev);
extern int wlRxRingAlloc(struct net_device *netdev);
extern int wlTxRingInit(struct net_device *netdev);
extern int wlRxRingInit(struct net_device *netdev);
extern int wlRxRingReInit(struct net_device *netdev);
extern void wlTxRingFree(struct net_device *netdev);
extern void wlRxRingFree(struct net_device *netdev);
extern void wlTxRingCleanup(struct net_device *netdev);
extern void wlRxRingCleanup(struct net_device *netdev);

#endif /* AP8X_DESC_H_ */
