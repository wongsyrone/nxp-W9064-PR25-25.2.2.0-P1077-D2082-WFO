/** @file ipc_i.h
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

#ifndef __IPC_I_H__
#define __IPC_I_H__

#include "ca_types.h"

typedef struct ipc_pkt {
	ca_uint16_t session_id;
	ca_uint16_t dst_cpu_id;
	ca_uint16_t priority;
	ca_uint16_t msg_no;
	void *msg_data;		/* the message data to transmit. */
	ca_uint16_t msg_size;	/* the length of message data. */
} __packed ca_ipc_pkt_t;

typedef struct ipc_msg_handle {
	u16 msg_no;
	int (*proc) (ca_ipc_addr_t peer, ca_uint16_t msg_no,
		     ca_uint16_t trans_id, const void *msg_data,
		     ca_uint16_t * msg_size);
} ca_ipc_msg_handle_t;

ca_ipc_session_id_t ipc_fun_init(void);

void ipc_fun_deinit(ca_ipc_session_id_t session_id);

void ipc_check_msg(ca_ipc_session_id_t session_id);

ca_status_t ca_ipc_msg_handle_register(ca_ipc_session_id_t session_id,
				       const ca_ipc_msg_handle_t *
				       msg_handle_array,
				       ca_uint32_t msg_handle_count);

ca_status_t ca_ipc_msg_handle_unregister(ca_ipc_session_id_t session_id);

ca_status_t ca_ipc_msg_async_send(ca_ipc_pkt_t * p_ipc_pkt);

#endif /* __IPC_I_H__ */
