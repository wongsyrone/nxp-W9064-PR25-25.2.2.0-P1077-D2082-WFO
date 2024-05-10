/** @file ipc.c
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

#include <linux/slab.h>

#include "fifo.h"
#include "ipc.h"

static ca_ipc_msg_handle_t *handle_array;
static ca_uint16_t handle_count;

ca_status_t
ipc_init(void)
{
	fifo_init();
	handle_array = NULL;
	handle_count = 0;

	return CA_E_OK;
}

void
ipc_deinit(void)
{
	if (handle_array)
		kfree(handle_array);

	handle_array = NULL;
	handle_count = 0;
}

void
ipc_check_msg(void)
{
	char buf[256];
	int buf_size, msg_size, hdr_size;
	ca_ipc_pkt_t *p_ipc_pkt;
	int i;

	buf_size = sizeof(buf);

	while (h2t_fifo_peek(buf, buf_size)) {
		msg_size = h2t_fifo_out(buf, buf_size);
		hdr_size = sizeof(ca_ipc_pkt_t);
		p_ipc_pkt = (ca_ipc_pkt_t *) buf;

		if ((msg_size - hdr_size) != p_ipc_pkt->msg_size)
			continue;

		for (i = 0; i < handle_count; i++) {
			if (p_ipc_pkt->msg_no == handle_array[i].msg_no) {
				handle_array[i].proc(0, p_ipc_pkt->msg_no,
						     0, &buf[hdr_size],
						     &p_ipc_pkt->msg_size);
				break;
			}
		}
	}
}

ca_status_t
ca_ipc_msg_handle_register(ca_ipc_session_id_t session_id,
			   const ca_ipc_msg_handle_t * msg_handle_array,
			   ca_uint32_t msg_handle_count)
{
	int handle_size;

	if (msg_handle_count) {
		handle_size = (msg_handle_count * sizeof(ca_ipc_msg_handle_t));
		handle_array = kzalloc(handle_size, GFP_KERNEL);
		if (!handle_array)
			return -ENOMEM;
		memcpy(handle_array, msg_handle_array, handle_size);
		handle_count = msg_handle_count;
	}

	return CA_E_OK;
}

ca_status_t
ca_ipc_msg_handle_unregister(ca_ipc_session_id_t session_id)
{
	if (handle_array)
		kfree(handle_array);

	handle_array = NULL;
	handle_count = 0;

	return CA_E_OK;
}

ca_status_t
ca_ipc_msg_async_send(ca_ipc_pkt_t * p_ipc_pkt)
{
	char buf[256];
	int buf_size;

	buf_size = sizeof(ca_ipc_pkt_t);
	if ((buf_size + p_ipc_pkt->msg_size) > 256)
		return -ENOMEM;
	memcpy(buf, p_ipc_pkt, buf_size);
	memcpy(&buf[buf_size], p_ipc_pkt->msg_data, p_ipc_pkt->msg_size);
	buf_size += p_ipc_pkt->msg_size;

	t2h_fifo_in(buf, buf_size);

	return CA_E_OK;
}
