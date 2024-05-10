/** @file sysadpt.h
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

#ifndef __SYSADPT_H__
#define __SYSADPT_H__

#define SYSADPT_MSG_IPC_SESSION             2

#define SYSADPT_MSG_IPC_DST_CPU             0

#define SYSADPT_MAX_RADIO                   3

#define SYSADPT_MAX_CMD_BUF_LEN             128

#define SYSADPT_MAX_VIF                     32

#define SYSADPT_MAX_STA                     320

#define SYSADPT_MAX_TID                     8

#define SYSADPT_MAX_EXTRA_PKT_HDR           (8 * 1024)

/* PKT_INFO_SIZE:
 *  4 (sig) + 8 (pkt Pointer) + ETH_HLEN (14) = 26
 *  no matter 32 or 64 bits platform, PKT_INFO_SIZE reserves 8 bytes to keep
 *  pointer to packet header.
 *
 * SYSADPT_BM_BUF_HEADROOM is set to 32 bytes to make sure it is enough for
 * PKT_INF_SIZE.
 *
 * Due to 8 bytes is reserved for pointer to packet header (no matter 32 or 64
 * bits platform), so it will be easy for host dirver to extract this pointer and
 * return it back to packet engine simulator/processor via IPC.
 */
#define SYSADPT_BM_BUF_HEADROOM             32

#define SYSADPT_NUM_OF_HW_DESC_DATA         16

#define SYSADPT_EXTRA_BM_BUF_NUM_Q10        4096

#define SYSADPT_EXTRA_BM_BUF_NUM_Q11        4096

#define SYSADPT_EXTRA_BM_BUF_NUM_Q12        1024

#define SYSADPT_AC_QUEUE_DROP_THRESHOLD     2304

#define SYSADPT_MAX_TX_PACKET_PER_POLL      128

#define SYSADPT_MAX_RX_PACKET_PER_POLL      128

#define SYSADPT_MAX_RX_REFILL_PER_POLL      5120

#define SYSADPT_MIN_DELTA_TIME_PER_POLL     100	/* us */

#define SYSADPT_ACTIVE_NOTIFY_PERIOD        1000	/* ms */

#define SYSADPT_MAX_TX_PEND_CNT_PER_MGMT_Q  128

#define SYSADPT_MAX_TX_PEND_CNT_PER_BCAST_Q 128

#define SYSADPT_MAX_TX_PEND_CNT_PER_Q       4096

#define SYSADPT_MAX_TX_PEND_CNT_PER_STA     4096

#define SYSADPT_MAX_TX_PENDING              8000	//6000

#define SYSADPT_MAX_TX_QID_PENDING          1800	//(SYSADPT_MAX_TX_PENDING/8)

#define SYSADPT_MAX_RETURN_HOST_PKT_NUM     32

#endif /* __SYSADPT_H__ */
