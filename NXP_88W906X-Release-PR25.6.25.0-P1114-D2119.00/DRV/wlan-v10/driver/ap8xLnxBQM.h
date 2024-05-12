/** @file ap8xLnxBQM.h
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

#ifndef AP8X_BQM_H_
#define AP8X_BQM_H_
#include <linux/if_ether.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/list.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include "wltypes.h"
#include "IEEE_types.h"
#include "buildModes.h"
#include "wldebug.h"
#include "wl_hal.h"

#define NUM_OF_HW_DESCRIPTOR_DATA 16
#define SC5_RXQ_START_INDEX     0
#define SC5_RXQ_TESTNUM			1
#define SC5_RXQ_NUM             10
// Only Q#0, Q#8, Q#9 are enabled
#define	SC5_RXQ_MASK			0x0301

#define SC5_RXQ_PROMISCUOUS_INDEX   8
//#define SC5_RXQ_NUM             SC5_RXQ_TESTNUM
#define SC5_RXQ_MGMT_INDEX      9
#define SC5_BMQ_START_INDEX     10
#define SC5_BMQ_NUM             4

/*Base addr Lo                 0x00020000
  Base addr Hi                 0x00020004
  Q size addr                  0x00020008
  RDPTR                        0x00020024
  WRPTR                        0x00020028
*/

#define SC5_RQ                  0
#define SC5_SQ                  1

#define SC5_RQ_REG_OFFSET       0x00000000
#define SC5_SQ_REG_OFFSET       0x00000040

#define SC5_Q_ADDR_OFFSET       0x00020000
#define SC5_Q_SIZE_OFFSET       0x00020008
#define SC5_Q_THRESHOLD_OFFSET  0x00020018
#define SC5_Q_RDPTR_OFFSET      0x00020024
#define SC5_Q_WRPTR_OFFSET      0x00020028
#define SC5_Q_MAC_CTRL_OFFSET   0x00028000

#define SC5_RQ_RDPTR_OFFSET		0x00020024
#define SC5_RQ_WRPTR_OFFSET		0x00020028
#define SC5_SQ_WRPTR_OFFSET		0x00020064
#define SC5_SQ_RDPTR_OFFSET		0x00020068

#define SC5_Q_BASE_ADDR_REG(q, s)  ((SC5_Q_ADDR_OFFSET + s * SC5_SQ_REG_OFFSET) + ((q) << 8))
#define SC5_Q_SIZE_REG(q, s)       ((SC5_Q_SIZE_OFFSET + s * SC5_SQ_REG_OFFSET) + ((q) << 8))

#define SC5_TXDONE_INT_THRESHOLD	64
#define SC5_TXDONE_INT_TIMEOUT		0xFF

#define SC5_Q_THRES_REG(q, s)      ((SC5_Q_THRESHOLD_OFFSET + s * SC5_SQ_REG_OFFSET) + ((q) << 8))
#define SC5_Q_MAC_CTRL_REG(q, s)   ((SC5_Q_MAC_CTRL_OFFSET + s * SC5_SQ_REG_OFFSET) + ((q) << 8))

#define SC5_RQ_WRPTR_REG(q)      ((SC5_RQ_WRPTR_OFFSET) + ((q) << 8))
#define SC5_RQ_RDPTR_REG(q)      ((SC5_RQ_RDPTR_OFFSET) + ((q) << 8))
#define SC5_SQ_WRPTR_REG(q)      ((SC5_SQ_WRPTR_OFFSET) + ((q) << 8))
#define SC5_SQ_RDPTR_REG(q)      ((SC5_SQ_RDPTR_OFFSET) + ((q) << 8))

#define SQ5_MAC_CTRL_TIMEOUT(t)  (0x003FC000 & (t<<14))
#define SMAC_BUF_HI_ADDR_MCI         0x0
#define SMAC_BUF_HI_ADDR         0x20
//for tx cloned skb case, add ethhdr len to prevent write signature on ethhdr location.
#define SKB_SIGNATURE_SIZE		4
#define SKB_POINTER_OFFSET		(sizeof(void *) + ETH_HLEN)
#define SKB_SIGNATURE_OFFSET	(sizeof(void *) + SKB_SIGNATURE_SIZE + ETH_HLEN)
#define SKB_INFO_SIZE			SKB_SIGNATURE_OFFSET
#define	SKB_RADIOTAP_CHUNK	256
#define SKB_SIGNATURE			0x424B5324	// $SKB
#define SKB_DEBUG_SIGNATURE      0x2440ABCD
#define SKB_TAIL_SIGNATURE        0x40454E44	//@END
#define SKB_TAIL_SIGNATURE_OFFSET 0x8

#define TXBUF_ALIGN                     16
#define RXBUF_ALIGN                     16

#define USED_SIGNATURE			0xdeadbeef
// Signature of the buffer, which will be set after used
#define BMBUF_SIGNATURE		USED_SIGNATURE
#define PPDUACNT_END			0xdeadbeef
#define HF_OWN_SIGNATURE	0xdeadcafe
#define USED_BUFLEN			0x8000

#define SC5_TXQ_SIZE			0x400
// Increase the RXQ size to (8k-1) to avoid cfh-ul insufficient issue. 
// Note: Max = 8K-1 since the sq_size value will be 0x10000 to fill reg_sq_size_sq0. But only bit#15-3 are valid
#define SC5_RXQ_SIZE			(0x2000-1)
#define SC5_PROMQ_SIZE			0x400
#define SC5_RMGTQ_SIZE			0x400
#define SC5_BMQ_SIZE			0x400
//bootmem_1 is 96M and 96M/16K=0x1800 (max size). So far, we only set to 0x80
#define SC5_BMQ13_SIZE			0x80

// For JIRA-498, increase buffer release size to 16k
#define SC5_RELQ_SIZE			0x4000

#if defined(ACNT_REC) && defined (SOC_W906X)
//#define RACNTQ_SIZE                   (8192*8)
//#define RACNTQ_SIZE                   (1024*8)
//#define RACNTQ_SIZE                   (512*8)
#define RACNTQ_SIZE			(512*4)

// Giving 1M for Rx PPDU Acnt Record
#define	SC5_RXACNT_BUF			(0x400*0x400)
#endif				//#if defined(ACNT_REC) && defined (SOC_W906X)

#define MRVL_HDR_MGMT_EXTRA_BYTES_NUMBER     (sizeof(((mrvl_hdr_t*)0)->QoS) + sizeof(((mrvl_hdr_t*)0)->HTC))	/*Qos + HTC */
#define MRVL_HDR_PROMS_MGMT_EXTRA_BYTES_NUMBER     (IEEEtypes_ADDRESS_SIZE + sizeof(((mrvl_hdr_t*)0)->QoS) + sizeof(((mrvl_hdr_t*)0)->HTC))
#define MRVL_HDR_PROMS_QOS_DATA_EXTRA_BYTES_NUMBER     (IEEEtypes_ADDRESS_SIZE + sizeof(((mrvl_hdr_t*)0)->HTC))
#define MRVL_HDR_PROMS_WDS_QOS_DATA_EXTRA_BYTES_NUMBER     (sizeof(((mrvl_hdr_t*)0)->HTC))
#define MRVL_HDR_PROMS_NONE_QOS_DATA_EXTRA_BYTES_NUMBER     (IEEEtypes_ADDRESS_SIZE + sizeof(((mrvl_hdr_t*)0)->QoS) + sizeof(((mrvl_hdr_t*)0)->HTC))
#define MRVL_HDR_PROMS_WDS_NONE_QOS_DATA_EXTRA_BYTES_NUMBER     (sizeof(((mrvl_hdr_t*)0)->QoS) + sizeof(((mrvl_hdr_t*)0)->HTC))
#define MRVL_HDR_PROMS_CTRL_EXTRA_BYTES_NUMBER     (IEEEtypes_ADDRESS_SIZE + sizeof(((mrvl_hdr_t*)0)->seq) + IEEEtypes_ADDRESS_SIZE + sizeof(((mrvl_hdr_t*)0)->QoS) + sizeof(((mrvl_hdr_t*)0)->HTC))

#define HT_CTRL_OFFSET    24
#define HT_CTRL_OFFSET_WITH_ADDR4  30

#define SMAC_CFH_UL_TEMPLATE_SIZE 48
#define SMAC_CFH_UL_TEMPLATE_GAP 16
#define SMAC_HDR_LENGTH_BEFORE_MAC_HDR 4
#define SMAC_MAC_HDR_OFFSET (SMAC_CFH_UL_TEMPLATE_SIZE + SMAC_HDR_LENGTH_BEFORE_MAC_HDR)

#define SMAC_MGMT_EXTRA_BYTE (MRVL_HDR_MGMT_EXTRA_BYTES_NUMBER + sizeof(((mrvl_hdr_t*)0)->len) + sizeof(((mrvl_hdr_t*)0)->tag))

#define PFW_DRA_STAT_CNT_OFFSET	 0x60

// To avoid internal buffer recycle, the bpid of the dropped rx may be 0x80|bpid 
//      => Recover the real it
#define REL_RX_BPID(x)	(x&0x0f)

/*
	Ref: FS_NSS_A39x_App_Interface.pdf, 
		Fig_36, Dual-PE Format
*/
typedef struct {
	// [DWORD_0]
	union {
		u_int32_t pe0_lo_dword_addr;
		u_int32_t bgn_signature;
	};
	// [DWORD_1]
	union {
		struct {
			u_int32_t pe0_hi_byte_addr:8;
			u_int32_t attr:8;
			u_int32_t resrv0:8;
			u_int32_t bpid:8;
		};
		u_int32_t end_signature;
	};
	// [DWORD_2]
	u_int32_t pe1_lo_dword_addr;
	// [DWORD_3]
	u_int32_t pe1_hi_byte_addr:8;
	u_int32_t resrev1:24;
} bm_pe_hw_t;

typedef struct {
	struct list_head list;
	dma_addr_t phy_addr;
	u_int8_t *virt_addr;
	u_int8_t bpid;
	struct sk_buff *skb;
} bm_pe_t;

typedef struct {
	struct list_head list;
	u_int32_t qlen;
	spinlock_t lock;
} bm_pe_head_t;

/*
	Ref: FS_NSS_A39x_App_Interface.pdf, 
		Fig_35, Send and Receive Descriptor Formats
*/
typedef struct {
	// DWORD 0
	u_int32_t length:16;
	u_int32_t seqNum:16;
	// DWORD 1
	u_int32_t wr_offet:4;
	u_int32_t swqnum:8;
	u_int32_t reserv:1;
	u_int32_t qcv:1;
	u_int32_t host_int:1;
	u_int32_t wrap_null:1;
	u_int32_t cfh_length:8;
	u_int32_t cfh_format:4;
	u_int32_t tag3:4;
	// DWORD 2
	u_int32_t l4_chksum:16;
	u_int32_t tdest:16;
	// DWORD 3
	u_int32_t timestamp;
	// DWORD 4
	union {
		u_int32_t lo_dword_addr;
		u_int32_t used_signature;
	};
	// DWORD 5
	u_int32_t hi_byte_addr:8;
	u_int32_t tag4:8;
	u_int32_t vmid:8;
	u_int32_t bpid:8;

} cfh_header;

/*
	Ref: CFH_17_Rosecrans_v2.6.xlsx
		CFH-DL tab
	SMAC Firmware Tx Control for Host Management Frame Rev 1.0	
*/
#define TXDESC_IPHDR_SIZE		12	//size_of(ip_hdr0 + ip_hdr1 + ip_hdr2) below
#ifdef SOC_W906X
typedef struct _wltxdesc_t {
	struct {
		// DWORD 0
		u_int32_t length:16;
		u_int32_t seqNum:16;
		// DWORD 1
		u_int32_t wr_offet:4;
		u_int32_t swqnum:8;
		u_int32_t comm_reserv:1;
		u_int32_t qcv:1;
		u_int32_t host_int:1;
		u_int32_t wrap_null:1;
		u_int32_t cfh_length:8;
		u_int32_t cfh_format:4;
		u_int32_t tag3:4;
		// DWORD 2
		union {
			struct {
				u_int32_t l4_chksum:16;
				u_int32_t tdest:16;
			};
			u_int32_t skb_addr;
		};
		// DWORD 3
		u_int32_t timestamp;
		// DWORD 4
		union {
			u_int32_t lo_dword_addr;
			u_int32_t used_signature;
		};
		// DWORD 5
		u_int32_t hi_byte_addr:8;
		u_int32_t tag4:8;
		u_int32_t vmid:8;
		u_int32_t bpid:8;
	} hdr;

	// DWORD   6
	u_int32_t qid:13;
	u_int32_t mpdu_flag:1;
	u_int32_t ndr:1;
	u_int32_t vtv:1;
	u_int32_t llt:3;
	u_int32_t len_ovr:4;
	// From Chris' mail on 2018/8/9, am6:42: bit[31:24] are the txd1 drop reasons
	u_int32_t reserv:1;
	u_int32_t txd1_drop_reason:8;

	// DWORD   7
	u_int32_t mpdu_frame_ctrl:16;
	u_int32_t da0:16;
	// DWORD   8
	u_int32_t da1;
	// DWORD   9
	u_int32_t sa0;
	// DWORD   10
	u_int32_t sa1:16;
	u_int32_t pcp:3;
	u_int32_t cfi:1;
	u_int32_t vlan_id:12;
	// DWORD   11
	u_int32_t mpdu_ht_a_ctrl;
	// DWORD   12
	u_int32_t snap1;
	union {
		struct {
			// DWORD   13
			u_int32_t ip_hdr0;
			// DWORD   14
			u_int32_t ip_hdr1;
			// DWORD   15
			u_int32_t ip_hdr2;
		};
		u_int32_t ip_hdr[3];
	};
} wltxdesc_t;

/*
	Ref: CFH_17_Rosecrans_v2.6.xlsx
		CFH-UL tab
*/
typedef struct _wlrxdesc_t {	// ToNIC Rx Empty Buffer Ring Entry
	struct {
		// DWORD 0
		u_int32_t length:16;
		u_int32_t seqNum:16;
		// DWORD 1
		u_int32_t wr_offet:4;
		u_int32_t swqnum:8;
		u_int32_t startPPDU:1;
		u_int32_t qcv:1;
		u_int32_t host_int:1;
		u_int32_t wrap_null:1;
		u_int32_t cfh_length:8;
		u_int32_t cfh_format:4;
		u_int32_t tag3:4;
		// DWORD 2
		union {
			struct {
				u_int32_t l4_chksum:16;
				u_int32_t tdest:16;
			};
			struct {
				u_int32_t rxInfoIndex:16;
				u_int32_t mpduInfoIndex:16;
			};	// For SC5/SCBT (A0)
		};
		// DWORD 3
		u_int32_t timestamp;
		// DWORD 4
		union {
			u_int32_t lo_dword_addr;
			u_int32_t used_signature;
		};
		// DWORD 5
		u_int32_t hi_byte_addr:8;
#ifdef MISC_ACTION
		u_int32_t miscAction:4;	// 0: empty, 1: host need to send delba
		u_int32_t miscVal:4;	// Correspond to value in miscAction. miscAction=1: tid value
#else
		u_int32_t tag4:8;
#endif				//MISC_ACTION
		u_int32_t rssi:8;
		u_int32_t bpid:8;
	} hdr;

	// DWORD   6
	u_int16_t frame_ctrl;
	u_int16_t cfh_offset:15;
	u_int16_t fcs_state:1;
	// DWORD   7
	u_int32_t mpdu_flag:1;
	u_int32_t qos:4;
	u_int32_t sb_index:11;
	u_int32_t fpkt:1;
	u_int32_t lpkt:1;
	u_int32_t hdrFormat:1;	// 0: normal, 1: bypass
	u_int32_t mic_err:1;
	u_int32_t icv_err:1;
	u_int32_t euMode:3;
	u_int32_t macHdrLen:8;
	// DWORD   8-31 
	u_int32_t nss_hdr[24];

} wlrxdesc_t;
#endif				/* SOC_W906X */

#if defined(ACNT_REC) && defined (SOC_W906X)
//
// << Rx accounting Record >>
// Entities of Q15
typedef struct {
	// DWORD 0
	u_int32_t good_ppdu:1;
	u_int32_t bad_ppdu:1;
	u_int32_t resv_0:30;
	// DWORD 1
	u_int32_t resv_1;
	// DWORD 2
	union {
		u_int32_t rxinfo_addr_l;
		u_int32_t bgn_signature;
	};
	// DWORD 3
	union {
		struct {
			u_int32_t rxinfo_addr_h:8;
			u_int32_t resv_2:24;
		};
		u_int32_t end_signature;
	};

} rxacnt_rec;

#endif				//#if defined(ACNT_REC) && defined (SOC_W906X)

typedef struct {
	u32 buf_size;
	bm_pe_t *pe;
	bm_pe_head_t pe_list;
} wl_bm_t;

// there is one entry gap between wrinx and rdinx.
typedef struct {

	void *virt_addr;
	dma_addr_t phys_addr;
	u32 qsize;
	u32 rdinx;		// current index data not read yet
	u32 wrinx;		// current index data just filled yet
	spinlock_t inx_lock;
	wl_bm_t bm;
	struct sk_buff_head skbTrace;
} wl_qpair_rq_t;

typedef enum {
	rpkt_reuse_recycle,
	rpkt_reuse_no
} rpkt_reuse_type;

void rpkt_reuse_init(struct sk_buff_head *pqueue);
void rpkt_reuse_push(struct sk_buff_head *pqueue, struct sk_buff *skb);
struct sk_buff *rpkt_resue_get(struct sk_buff_head *pqueue);
void rpkt_reuse_flush(struct sk_buff_head *pqueue);
void rpkt_reuse_free_resource(struct sk_buff_head *pqueue, u32 * plast_qlen, u32 threshold);

typedef struct {

	void *virt_addr;
	dma_addr_t phys_addr;
	u32 qsize;
	u32 rdinx;
	u32 wrinx;
	spinlock_t inx_lock;
	wl_bm_t bm;
} wl_qpair_sq_t;

typedef struct {
	u16 version:2;
	u16 type:2;
	u16 subtype:4;
	u16 toDs:1;
	u16 fromDs:1;
	u16 moreFrag:1;
	u16 retry:1;
	u16 pwrManage:1;
	u16 moreData:1;
	u16 protectedFrm:1;
	u16 order:1;
} wl_frame_ctrl;

typedef struct _mrvl_hdr {
	UINT16 len;
	UINT16 tag;
	IEEEtypes_FrameCtl_t FrmCtl;
	UINT8 dur[2];
	UINT8 addr1[IEEEtypes_ADDRESS_SIZE];
	UINT8 addr2[IEEEtypes_ADDRESS_SIZE];
	UINT8 addr3[IEEEtypes_ADDRESS_SIZE];
	UINT8 seq[2];
	UINT8 addr4[IEEEtypes_ADDRESS_SIZE];
	UINT16 QoS;
	UINT32 HTC;
} PACK mrvl_hdr_t;

#define MAX_AMSDU_SUBFRAME  178	//11454(max mpdu size: 11k amsdu)/64(assuming min packet size is 64)
typedef struct {
	wlrxdesc_t rxdesc[MAX_AMSDU_SUBFRAME];
	UINT32 idx;
} wl_cfhul_amsdu;

#define		INVALID_QSIZE		0xffffffff
typedef enum {
	is_rq,
	is_sq,
	max_qpair
} QPAIR;
// Element size of the queue
struct qelmsize_tbl {
	U32 elm_size[NUM_OF_HW_DESCRIPTOR_DATA][max_qpair];	//[#_of_queue, (rq|sq)]
};

struct bqm_args {
	u_int32_t *tx_q_size;
	U8 txq_start_index;
	U8 txq_num;

	u_int32_t *relbuf_q_size;
	U8 bmq_release_index;
	U8 bmq_release_num;
#if defined(ACNT_REC) && defined (SOC_W906X)
	u_int32_t *racnt_q_size;
	U8 racntq_index;
	U8 racntq_num;
	U32 racntq_msix_mask;
	U8 rxacnt_intrid;
#endif				//defined(ACNT_REC) && defined (SOC_W906X)
#if defined(TXACNT_REC) && defined (SOC_W906X)
	U8 txacnt_intrid;
#endif				//#if defined(ACNT_REC) && defined (SOC_W906X)
	U32 tx_msix_mask;
	U32 buf_release_msix_mask;
	struct qelmsize_tbl q_elmsize_tbl;
};

/*
	PKT type info
*/
struct pkttype_info {
	// pkt type:
	UINT32 data_cnt, mgmt_cnt, ctrl_cnt;

	// data sub_type;
	UINT32 tcp_cnt;
	UINT32 tcp_byte_cnt;
	UINT32 udp_cnt;
	UINT32 icmp_cnt;
	UINT32 arp_cnt;
	UINT32 nipv4_cnt;
	UINT32 eap_cnt;
	UINT32 null_cnt;
	// mtmt sub_type;
	UINT32 assoc_req_cnt;
	UINT32 assoc_resp_cnt;
	UINT32 reassoc_req_cnt;
	UINT32 reassoc_resp_cnt;
	UINT32 prob_req_cnt;
	UINT32 prob_resp_cnt;
	UINT32 beacon_cnt;
	UINT32 atim_cnt;
	UINT32 disassoc_cnt;
	UINT32 auth_cnt;
	UINT32 deauth_cnt;
	IEEEtypes_FrameCtl_t pkt_fc;	// Frame control of the pkt

	// ctrl sub_type;
	UINT32 ba_req_cnt;
	UINT32 ba_cnt;
	UINT32 ps_poll_cnt;
	UINT32 rts_cnt;
	UINT32 cts_cnt;
	UINT32 ack_cnt;
	UINT32 cf_end_cnt;
	UINT32 cf_end_cf_ackt_cnt;
};

typedef enum {
	CNT_RANGE_DOWN = -1,
	CNT_RANGE_SAFE = 0,
	CNT_RANGE_UP = 1,
} CNT_RANGE;

typedef enum {
	drvstatsopt_geninfo = 1,
	drvstatsopt_warning,	// warning information
	drvstatsopt_rxinfo,	// driver rx information
	drvstatsopt_scheduleinfo,	// pfw scheduler info
	drvstatsopt_txprofile,	// driver tx profile
	drvstatsopt_smac,	// SMAC info
	drvstatsopt_hframe,	// hframe info
	drvstatsopt_pktcnt,	// Pkt Counter
	drvstatsopt_dra_stat,	// DRA statistics counters
	drvstatsopt_ba,		/* BA reorder statistics */
	drvstatsopt_txqos,
	drvstatsopt_end,
} drv_stats_option;

CNT_RANGE wlCheckCnterRange(SINT32 cntval, SINT32 * plastval, SINT32 diff);

extern int wlQMInit(struct net_device *netdev);
extern void post_init_bq_idx(struct net_device *netdev, bool is_init);
extern int wlQMCleanUp(struct net_device *netdev);

extern int wlRxRingReInit(struct net_device *netdev);
extern int wlRxQueueInit(struct net_device *netdev, int qid);
extern int wlTxQueueInit(struct net_device *netdev, int qid);
extern int wlBmQueueInit(struct net_device *netdev, int qid);
extern int wlRxBufInit(struct net_device *netdev, int qid);
extern int wlBufReleaseQueueInit(struct net_device *netdev, int qid);
extern struct sk_buff *wlPeToSkb(struct net_device *netdev, bm_pe_hw_t * pe_hw);
extern void wlTxQueueCleanup(struct net_device *netdev);
extern void wlRxQueueCleanup(struct net_device *netdev);
extern void wlBmBufDump(struct net_device *netdev, int qid);
extern struct sk_buff *wlCfhUlToSkb(struct net_device *netdev, wlrxdesc_t * cfh_ul, int rxQid);
extern wlrxdesc_t *wlGetCfhUl(struct net_device *netdev, int qid, wlrxdesc_t * cfh_tl_temp);
extern bm_pe_hw_t *wlGetRelBufPe(struct net_device *netdev, int qid);
extern BOOLEAN wlSQEmpty(struct net_device *netdev, u8 qid);
extern void mwl_hex_dump(const void *buf, size_t len);
extern void mwl_hex_dump_to_sysfs(const void *buf, size_t len, char *sysfs_buff);
extern void wlTest(struct net_device *netdev);
extern void InitCFHDL(struct net_device *netdev, struct bqm_args *pbqm_args, wltxdesc_t * cfg, struct sk_buff *skb, void *pStaInfo, BOOLEAN eap,
		      UINT8 nullpkt);
extern void InitCFHDLMgmt(struct net_device *netdev, struct bqm_args *pbqm_args, wltxdesc_t * cfg, struct sk_buff *skb);
extern void wlCfhUlDump(wlrxdesc_t * cfh_ul);
int wlRxBufFill(struct net_device *netdev);

extern int wlRxBufFillBMEM_Q13(struct net_device *netdev, bm_pe_hw_t * pehw);

extern void wl_show_stat(struct net_device *netdev, int option, int level, char *sysfs_buff);
extern int wl_show_stat_cmd(struct net_device *netdev, char *info_item, char *info_level, char *sysfs_buff);
extern void wl_show_smac_stat(struct net_device *netdev, SMAC_STATUS_st * pSMACStatus, char *sysfs_buff);
extern void wl_pkttype_stat(struct pkttype_info *wlpkt_type, IEEEtypes_FrameCtl_t * fc);
extern void wl_get_datpkt_prot(struct pkttype_info *wlpkt_type, U16 llc_type, struct iphdr *iph, u32 len);
extern void wlTxSkbTest_1(struct net_device *netdev, int pktcnt, int pktsize, int txqid, int frameType);
extern BOOLEAN wlSQIndexGet(wl_qpair_sq_t * sq);
extern u32 wlQueryWrPtr(struct net_device *netdev, int qid, int qoff);
extern void wlUpdateRdPtr(struct net_device *netdev, int qid, int qoff, u32 rdinx, bool is_init);
extern void wlUnmapBuffer(struct net_device *netdev, u8 * vaddr, u32 size);
extern wlrxdesc_t *wlProcessMsdu(struct net_device *netdev, wlrxdesc_t * cfh_ul, u32 * msduNo, u32 qid);
extern wlrxdesc_t *wlProcessErrCfhul(struct net_device *netdev, u32 * msduNo);
extern void wl_init_const(struct net_device *netdev);

static inline BOOLEAN isRQFull(wl_qpair_rq_t * rq)
{
	if (((rq->wrinx + 1) % rq->qsize) == rq->rdinx) {
		WLDBG_INFO(DBG_LEVEL_5, "QINDEX:, (wrinx, rdinx)(%d, %d) qisze = %d RQ full \n", rq->wrinx, rq->rdinx, rq->qsize);
		return TRUE;
	}
	return FALSE;
}

static inline BOOLEAN isRQEmpty(wl_qpair_rq_t * rq)
{
	if (rq->wrinx == rq->rdinx) {
		WLDBG_INFO(DBG_LEVEL_5, "QINDEX:, (rdinx, wrinx)=(%d, %d) RQ empty\n", rq->rdinx, rq->wrinx);
		return TRUE;
	} else {
		return FALSE;
	}
}

static inline BOOLEAN isSQFull(wl_qpair_sq_t * sq)
{
	if (((sq->wrinx + 1) % sq->qsize) == sq->rdinx) {
		WLDBG_INFO(DBG_LEVEL_5, "QINDEX:, (rdinx, wrinx)(%d, %d) qisze = %d SQ full \n", sq->wrinx, sq->rdinx, sq->qsize);
		return TRUE;
	}

	return FALSE;
}

static inline BOOLEAN isSQEmpty(wl_qpair_sq_t * sq)
{
	if (sq->wrinx == sq->rdinx) {
		WLDBG_INFO(DBG_LEVEL_5, "QINDEX:, (rdinx, wrinx)(%d, %d) qisze = %d SQ empty \n", sq->wrinx, sq->rdinx, sq->qsize);
		return TRUE;
	}

	return FALSE;
}

#define DBG_SKB_MAX_NUM 4096
typedef struct _dbg_skb_send {
	u_int32_t pa;
	u_int8_t *va_data;
	u_int8_t *va_skb;
	u_int32_t wr;
	struct timespec ts;
} dbg_skb_send;

typedef struct _dbg_skb_back {
	u_int32_t pa;
	u_int8_t *va_data;
	u_int8_t *va_skb;
	u_int32_t rd;
	u_int32_t bpid;
	u_int32_t signature;
	struct timespec ts;
} dbg_skb_back;

typedef struct _dbg_skb {
	dbg_skb_send *skb_send;
	dbg_skb_back *skb_back;
	UINT32 skb_send_idx;
	UINT32 skb_back_idx;
	UINT32 skb_stop;
	UINT32 skb_invalid;
	UINT32 skb_back_stop_idx;
} dbg_skb;

extern void wlBmRxDropMgmtKeep(struct net_device *netdev, struct sk_buff *skb);

#endif				/* AP8X_BQM_H_ */
