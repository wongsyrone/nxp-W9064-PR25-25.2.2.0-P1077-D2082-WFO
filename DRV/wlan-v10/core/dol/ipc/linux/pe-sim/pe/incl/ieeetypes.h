/** @file ieeetypes.h
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

#ifndef __IEEETYPES_H__
#define __IEEETYPES_H__

#define ETH_ALEN           6
#define ETH_HLEN           14
#define LLC_HDR_LEN        8
#define IP_HDR_LEN         20
#define LLC_SNAP_LSAP      0xaa
#define LLC_UI             0x03

#define IEEE_ETHERTYPE_PAE 0x888e	/* EAPOL PAE/802.1x                */
#define IEEE802_11Q_TYPE   0x8100
#define ETH_P_IP           0x0800	/* Internet Protocol packet        */
#define ETH_P_ARP          0x0806	/* Address Resolution packet       */
#define ETH_P_IPV6         0x86DD	/* IPv6 over bluebook              */
#define MAX_ETHER_PKT_SIZE 1800	/* should be 0x600, need to check. */

#define IEEE80211_SEQ_SHIFT 4

typedef enum {
	DATA = 0,
	DATA_CF_ACK,
	DATA_CF_POLL,
	DATA_CF_ACK_CF_POLL,
	NULL_DATA,
	CF_ACK,
	CF_POLL,
	CF_ACK_CF_POLL,
	QoS_DATA = 8,
	QoS_DATA_CF_ACK,
	QoS_DATA_CF_POLL,
	QoS_DATA_CF_ACK_CF_POLL,
	QoS_NULL_DATA,
	QoS_CF_ACK,
	QoS_CF_POLL,
	QoS_CF_ACK_CF_POLL
} IEEEtypes_DataSubType_e;

typedef ca_uint8_t IEEEtypes_DataSubType_t;

typedef enum {
	IEEE_TYPE_MANAGEMENT = 0,
	IEEE_TYPE_CONTROL,
	IEEE_TYPE_DATA
} IEEEtypes_MsgType_e;

typedef ca_uint8_t IEEEtypes_MsgType_t;

typedef enum {
	IEEE_MSG_ASSOCIATE_RQST = 0,
	IEEE_MSG_ASSOCIATE_RSP,
	IEEE_MSG_REASSOCIATE_RQST,
	IEEE_MSG_REASSOCIATE_RSP,
	IEEE_MSG_PROBE_RQST,
	IEEE_MSG_PROBE_RSP,
	IEEE_MSG_BEACON = 8,
	IEEE_MSG_ATIM,
	IEEE_MSG_DISASSOCIATE,
	IEEE_MSG_AUTHENTICATE,
	IEEE_MSG_DEAUTHENTICATE,
	IEEE_MSG_QOS_ACTION,
	IEEE_MSG_ACTION = 0x0d,
	IEEE_MSG_ACTION_NO_ACK = 0x0e
} IEEEtypes_MgmtSubType_e;

typedef ca_uint8_t IEEEtypes_MgmtSubType_t;

typedef enum {
	CTRL_TRIGGER = 2,
	BLK_ACK_REQ = 8,
	BLK_ACK,
	PS_POLL = 10,
	RTS,
	CTS,
	ACK,
	CF_END,
	CF_END_CF_ACK
} IEEEtypes_CtlSubType_e;

typedef ca_uint8_t IEEEtypes_CtlSubType_t;

typedef struct {
#ifdef CPU_BE
	ca_uint16_t Subtype:4;
	ca_uint16_t Type:2;
	ca_uint16_t ProtocolVersion:2;
	ca_uint16_t Order:1;
	ca_uint16_t Wep:1;
	ca_uint16_t MoreData:1;
	ca_uint16_t PwrMgmt:1;
	ca_uint16_t Retry:1;
	ca_uint16_t MoreFrag:1;
	ca_uint16_t FromDs:1;
	ca_uint16_t ToDs:1;
#else				/* CPU_LE */
	ca_uint16_t ProtocolVersion:2;
	ca_uint16_t Type:2;
	ca_uint16_t Subtype:4;
	ca_uint16_t ToDs:1;
	ca_uint16_t FromDs:1;
	ca_uint16_t MoreFrag:1;
	ca_uint16_t Retry:1;
	ca_uint16_t PwrMgmt:1;
	ca_uint16_t MoreData:1;
	ca_uint16_t Wep:1;
	ca_uint16_t Order:1;
#endif
} __packed IEEEtypes_FrameCtl_t;

typedef struct {
	ca_uint16_t FrmBodyLen;
	IEEEtypes_FrameCtl_t FrmCtl;
	ca_uint16_t DurationId;
	ca_uint8_t Addr1[ETH_ALEN];
	ca_uint8_t Addr2[ETH_ALEN];
	ca_uint8_t Addr3[ETH_ALEN];
	ca_uint16_t SeqCtl;
	ca_uint8_t Addr4[ETH_ALEN];
} __packed IEEEtypes_GenHdr_t;

typedef struct {
	ca_uint16_t type;
	ca_uint16_t control;
} __packed IEEE802_1QTag_t;

typedef struct {
#ifdef CPU_BE
	ca_uint8_t ver:4;
	ca_uint8_t ihl:4;
#else
	ca_uint8_t ihl:4;
	ca_uint8_t ver:4;
#endif
	ca_uint8_t tos;
	ca_uint16_t total_length;
	ca_uint16_t identification;
	ca_uint16_t flag_fragoffset;
	ca_uint8_t ttl;
	ca_uint8_t protocol;
	ca_uint16_t header_chksum;
	ca_uint8_t src_IP_addr[4];
	ca_uint8_t dst_IP_addr[4];
} __packed IEEEtypes_IPv4_Hdr_t;

/*
 *	IPv6 fixed header
 *
 *	BEWARE, it is incorrect. The first 4 bits of flow_lbl
 *	are glued to priority now, forming "class".
 */
typedef struct {
#ifdef CPU_BE
	ca_uint8_t ver:4;
	ca_uint8_t traffic_class:4;
#else
	ca_uint8_t traffic_class:4;
	ca_uint8_t ver:4;
#endif
	ca_uint8_t flow_label[3];
	ca_uint16_t payload_length;
	ca_uint8_t next_header;
	ca_uint8_t hop_limit;
	ca_uint8_t src_IP_addr[4];
	ca_uint8_t dst_IP_addr[4];
} __packed IEEEtypes_IPv6_Hdr_t;

struct ieee80211_hdr_3addr {
	IEEEtypes_FrameCtl_t frame_control;
	ca_uint16_t duration_id;
	ca_uint8_t addr1[ETH_ALEN];
	ca_uint8_t addr2[ETH_ALEN];
	ca_uint8_t addr3[ETH_ALEN];
	ca_uint16_t seq_ctrl;
} __packed;

typedef struct {
#ifdef CPU_LE
	ca_uint16_t AckPolicy:1;
	ca_uint16_t MTID:1;
	ca_uint16_t CompressedBA:1;
	ca_uint16_t reserved:9;
	ca_uint16_t TID:4;
#else
	ca_uint16_t rsv0:5;
	ca_uint16_t CompressedBA:1;
	ca_uint16_t MTID:1;
	ca_uint16_t AckPolicy:1;
	ca_uint16_t TID:4;
	ca_uint16_t reserved:4;
#endif
} __packed BA_Cntrl_t;

typedef struct {
#ifdef CPU_LE
	ca_uint16_t FragNo:4;
	ca_uint16_t StartSeqNo:12;
#else
	union {
		ca_uint16_t u16_data;
		struct {
			ca_uint16_t StartSeqNo:12;
			ca_uint16_t FragNo:4;
		};
	};
#endif
} __packed Sequence_Cntrl_t;

typedef struct {
	IEEEtypes_FrameCtl_t FrmCtl;
	ca_uint16_t DurationId;
	ca_uint8_t DestAddr[ETH_ALEN];
	ca_uint8_t SrcAddr[ETH_ALEN];
	BA_Cntrl_t BA_Ctrl;
	Sequence_Cntrl_t Seq_Ctrl;
} __packed IEEEtypes_BA_ReqFrame_t2;

struct ether_header {
	ca_uint8_t ether_dhost[ETH_ALEN];
	ca_uint8_t ether_shost[ETH_ALEN];
	ca_uint16_t ether_type;
};

struct llc_snap {
	ca_uint8_t llc_dsap;
	ca_uint8_t llc_ssap;
	ca_uint8_t control;
	ca_uint8_t org_code[3];
	ca_uint16_t ether_type;
} __packed;

enum {
	CONTROL_ID_UMRS = 0,
	CONTROL_ID_OM,
	CONTROL_ID_HLA,
	CONTROL_ID_BSR,
	CONTROL_ID_UPH,
	CONTROL_ID_BQR,
	CONTROL_ID_CAS
};

typedef struct IEEEtypes_htcHT_t {
	ca_uint32_t vht:1;
	ca_uint32_t ht_cControl_middle:29;
	ca_uint32_t ac_constraint:1;
	ca_uint32_t rdg:1;
} __packed IEEEtypes_htcHT_t;

typedef struct IEEEtypes_htcVHT_t {
	ca_uint32_t vht:1;
	ca_uint32_t he:1;
	ca_uint32_t vht_cControl_middle:28;
	ca_uint32_t ac_constraint:1;
	ca_uint32_t rdg:1;
} __packed IEEEtypes_htcVHT_t;

typedef struct IEEEtypes_htcHE_t {
	ca_uint32_t vht:1;
	ca_uint32_t he:1;
	ca_uint32_t a_control:30;
} __packed IEEEtypes_htcHE_t;

typedef struct IEEEtypes_htcField_t {
	union {
		IEEEtypes_htcHT_t ht_variant;
		IEEEtypes_htcVHT_t vht_variant;
		IEEEtypes_htcHE_t he_variant;
	};
} __packed IEEEtypes_htcField_t;

typedef struct IEEEtypes_AcontrolInfoOm_t {
	union {
		ca_uint16_t om_control;
		struct {
			ca_uint16_t rxnss:3;
			ca_uint16_t chbw:2;
			ca_uint16_t ulmu_disable:1;
			ca_uint16_t tx_nsts:3;
			ca_uint16_t er_su_disable:1;
			ca_uint16_t dl_mu_mimo_resound:1;
			ca_uint16_t ul_mu_data_disable:1;
			ca_uint16_t na:4;	/* there are only 12 bits for Control Information subfield for OM Control */
		};
	};
} __packed IEEEtypes_AcontrolInfoOm_t;

typedef struct IEEEtypes_fullHdr_t {
	IEEEtypes_FrameCtl_t FrmCtl;
	ca_uint16_t DurationId;
	ca_uint8_t addr1[ETH_ALEN];
	ca_uint8_t addr2[ETH_ALEN];
	ca_uint8_t addr3[ETH_ALEN];
	ca_uint16_t SeqCtl;
	union {
		ca_uint8_t addr4[ETH_ALEN];

		struct {
			ca_uint8_t addr4[ETH_ALEN];
			ca_uint16_t qos;
		} __packed wds_qos;

		struct {
			ca_uint8_t addr4[ETH_ALEN];
			IEEEtypes_htcField_t htc;
		} __packed wds_htc;

		struct {
			ca_uint8_t addr4[ETH_ALEN];
			ca_uint16_t qos;
			IEEEtypes_htcField_t htc;
		} __packed wds_qos_htc;

		struct {
			ca_uint16_t qos;
			IEEEtypes_htcField_t htc;
		} __packed qos_htc;

		ca_uint16_t qos;
		IEEEtypes_htcField_t htc;
	};
} __packed IEEEtypes_fullHdr_t;

#endif /* __IEEETYPES_H__ */
