/** @file pkt.h
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

#ifndef __PKT_H__
#define __PKT_H__

#define PKT_DATA_HEADROOM        ((sizeof(void *) * 2) + 8)
#define PKT_HEADER_SIGNATURE     0xdeadbeef
#define PKT_DATA_SIGNATURE       0xbeefdead

#define PKT_DATA_FREE            0
#define PKT_DATA_ALLOC           1
#define PKT_DATA_FW_ASSIGNED     2
#define PKT_DATA_SEND_ETH        3
#define PKT_DATA_RECV_ETH        4

#define PKT_DATA_FROM_BM         0
#define PKT_DATA_FROM_ETH        1
#define PKT_DATA_FROM_HOST       2
#define PKT_DATA_FROM_LOCAL      3

struct pkt_data {
	struct pkt_data *next;
	struct pkt_data *prev;
	ca_uint32_t signature;
	ca_uint32_t status;
	ca_uint8_t data[0];
};

#ifdef CORTINA_TUNE_SLIM_PKT_HDR
struct pkt_hdr {
	struct pkt_hdr *next;
	struct pkt_hdr *prev;
#ifdef ENABLE_SIGNATURE_CHECK_PKT_HDR
	ca_uint32_t signature;
#endif
	ca_uint8_t *buf_ptr;	/* pointer to start of buffer */
	ca_uint32_t buf_size;	/* buffer size */
	struct vif *vif_info;	/* keep which virtual interface */
	struct sta_info *sta_info;	/* keep which station */
	ca_uint8_t *data;	/* pointer to start of data */
	ca_uint8_t data_type;	/* keep PKT_DATA_FROM_XXX */
	ca_uint8_t qid;		/* keep gueue id */
	ca_uint16_t priority;	/* keep priority of packet */
	ca_uint16_t len;	/* data size */
	bool is_clone;		/* if this header is a cloned one */
	bool is_bcmc;		/* if this packet is broadcast/multicast */
	ca_uint16_t ref_cnt;	/* keep how many users used this buffer */
	union {
		/* for wifi tx path */
		struct {
			ca_uint64_t orig_hdr;	/* pointer to ogirinal header */
			//wltxdesc_t txcfg;        /* keep tx descriptor */
		};
		/* for wifi rx path */
		struct {
			bool is_rx_amsdu_hold;	/* if this header is hold by AMSDU processing */
			struct list clone_list;	/* keep cloned packet header */
			struct pkt_hdr *clone_pkt;	/* which packet header is cloned by me */
			struct pkt_hdr *rx_sta_info;	/* keep which dst station */
		};
	};
};
#else
struct pkt_hdr {
	struct pkt_hdr *next;
	struct pkt_hdr *prev;
#ifdef ENABLE_SIGNATURE_CHECK_PKT_HDR
	ca_uint32_t signature;
#endif
	ca_uint8_t *buf_ptr;	/* pointer to start of buffer */
	ca_uint32_t buf_size;	/* buffer size */
	ca_uint64_t orig_hdr;	/* pointer to ogirinal header */
	ca_uint8_t *data;	/* pointer to start of data */
	ca_uint16_t len;	/* data size */
	ca_uint16_t ref_cnt;	/* keep how many users used this buffer */
	struct vif *vif_info;	/* keep which virtual interface */
	struct sta_info *sta_info;	/* keep which station */
	bool is_bcmc;		/* if this packet is broadcast/multicast */
	struct list clone_list;	/* keep cloned packet header */
	bool is_clone;		/* if this header is a cloned one */
	bool is_rx_amsdu_hold;	/* if this header is hold by AMSDU processing */
	struct pkt_hdr *clone_pkt;	/* which packet header is cloned by me */
	ca_uint8_t data_type;	/* keep PKT_DATA_FROM_XXX */
	ca_uint8_t qid;		/* keep gueue id */
	ca_uint16_t priority;	/* keep priority of packet */
	wltxdesc_t txcfg;	/* keep tx descriptor */
#ifndef CORTINA_TUNE_HW_CPY
	ca_uint8_t cb[48];	/* control buffer */
#endif
};
#endif

struct pkt_ctrl {
	bool initizliaed;
	struct pkt_hdr *pkt_hdr;
#ifndef LINUX_PE_SIM
	struct pkt_data *pkt_data[4];
#endif
	struct list pkt_hdr_free_list;
	struct list pkt_data_free_list[4];
	struct list pkt_from_host_list;
	struct list pkt_from_host_free_list;
	struct list pkt_from_eth_list[4];
	ca_uint8_t pkt_buf_headroom;
};

#ifdef DBG_BM_BUF_MONITOR
void dbg_check_buf(int rid, struct pkt_hdr *pkt_hdr, const char *fun);
#endif

int pkt_init(int rid);

void pkt_deinit(int rid);

#endif /* __PKT_H__ */
