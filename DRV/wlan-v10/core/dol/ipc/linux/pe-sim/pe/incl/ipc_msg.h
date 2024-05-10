/** @file ipc_msg.h
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

#ifndef __IPC_MSG_H__
#define __IPC_MSG_H__

/* message number for host to target */
#define WFO_IPC_H2T_CMD_SEND       1
#define WFO_IPC_H2T_PKT_SEND       2
#define WFO_IPC_H2T_PKT_RECV_REL   3
#define WFO_IPC_H2T_MAX            3

/* message number for target to host */
#define WFO_IPC_T2H_CMD_REPLY      1
#define WFO_IPC_T2H_PKT_RECV       2
#define WFO_IPC_T2H_PKT_SEND_DONE  3
#define WFO_IPC_T2H_EVENT          4
#define WFO_IPC_T2H_MAX            4

typedef struct {
	ca_uint16_t radio;
	ca_uint16_t qid;
	ca_uint32_t buf_phy_addr;
	ca_uint64_t skb_addr;
	ca_uint32_t buf_len;
	wltxdesc_t txcfg;
} __packed h2t_pkt_send_t;

typedef struct {
	ca_uint16_t radio;
	ca_uint16_t rsvd[3];
	ca_uint64_t pkt_hdr_addr;
} __packed h2t_pkt_recv_rel_t;

typedef struct {
	ca_uint16_t radio;
	ca_uint16_t rsvd;
	ca_uint32_t buf_phy_addr;
	ca_uint64_t pkt_hdr_addr;
	ca_uint32_t buf_len;
	ca_uint32_t is_data;
	ca_uint32_t rxcfg[8];
} __packed t2h_pkt_recv_t;

typedef struct {
	ca_uint16_t radio;
	ca_uint16_t rsvd;
	ca_uint32_t buf_phy_addr;
	ca_uint64_t skb_addr;
} __packed t2h_pkt_send_done_t;

#endif /* __IPC_MSG_H__ */
