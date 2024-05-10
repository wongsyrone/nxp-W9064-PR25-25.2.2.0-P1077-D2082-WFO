/** @file pe.c
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

#include "radio.h"
#include "ipc_msg.h"
#include "ipc.h"
#include "pe.h"

bool pe_ready = false;
struct radio radio_info[SYSADPT_MAX_RADIO];

static int
__ipc_h2t_cmd_send(ca_ipc_addr_t peer, ca_uint16_t msg_no,
		   ca_uint16_t trans_id, const void *msg_data,
		   ca_uint16_t * msg_size)
{
	ca_uint16_t radio;

	if (msg_no != WFO_IPC_H2T_CMD_SEND)
		return -EINVAL;

	radio = *((ca_uint16_t *) msg_data);

	if ((radio <= 0) || (radio > SYSADPT_MAX_RADIO))
		return -EINVAL;

	cmd_proc_commands(radio, msg_data, *msg_size);

	return 0;
}

static int
__ipc_h2t_pkt_send(ca_ipc_addr_t peer, ca_uint16_t msg_no,
		   ca_uint16_t trans_id, const void *msg_data,
		   ca_uint16_t * msg_size)
{
	ca_uint16_t radio;

	if (msg_no != WFO_IPC_H2T_PKT_SEND)
		return -EINVAL;

	radio = *((ca_uint16_t *) msg_data);

	if ((radio <= 0) || (radio > SYSADPT_MAX_RADIO))
		return -EINVAL;

	tx_proc_host_pkt(radio, msg_data, *msg_size);

	return 0;
}

static int
__ipc_h2t_pkt_recv_rel(ca_ipc_addr_t peer, ca_uint16_t msg_no,
		       ca_uint16_t trans_id, const void *msg_data,
		       ca_uint16_t * msg_size)
{
	ca_uint16_t radio;

	if (msg_no != WFO_IPC_H2T_PKT_RECV_REL)
		return -EINVAL;

	radio = *((ca_uint16_t *) msg_data);

	if ((radio <= 0) || (radio > SYSADPT_MAX_RADIO))
		return -EINVAL;

	rx_rel_pkt_to_host(radio, msg_data, *msg_size);

	return 0;
}

ca_ipc_msg_handle_t wfo_ipc_msg[WFO_IPC_H2T_MAX] = {
	{.msg_no = WFO_IPC_H2T_CMD_SEND,.proc = __ipc_h2t_cmd_send}
	,
	{.msg_no = WFO_IPC_H2T_PKT_SEND,.proc = __ipc_h2t_pkt_send}
	,
	{.msg_no = WFO_IPC_H2T_PKT_RECV_REL,.proc = __ipc_h2t_pkt_recv_rel}
	,
};

void
pe_init(void)
{
	int i;

	for (i = 0; i < SYSADPT_MAX_RADIO; i++) {
		memset(&radio_info[i], 0, sizeof(struct radio));
		radio_info[i].rid = i + 1;
		stadb_init(radio_info[i].rid);
	}

	ca_ipc_msg_handle_register(SYSADPT_MSG_IPC_SESSION, wfo_ipc_msg,
				   WFO_IPC_H2T_MAX);

	pe_ready = true;
}

void
pe_deinit(void)
{
	int i;

	for (i = 0; i < SYSADPT_MAX_RADIO; i++) {
		stadb_deinit(radio_info[i].rid);
		memset(&radio_info[i], 0, sizeof(struct radio));
	}

	ca_ipc_msg_handle_unregister(SYSADPT_MSG_IPC_SESSION);

	pe_ready = false;
}
