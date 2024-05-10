/** @file ipc.h
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

#ifndef __IPC_H__
#define __IPC_H__

enum ipc_vendor {
	IPC_VENDOR_CORTINA,
	IPC_LINUX_PE_SIM,
	IPC_NOT_ASSIGN,
};

struct mwl_ipc_ops {
	const char *name;

	const char *version;

	int (*init) (void *ctrl);

	void (*deinit) (void *ctrl);

	void (*send_cmd) (void *ctrl, void *msg, u16 msg_size);

	void (*register_cmd_rcv) (void *ctrl,
				  void (*rcv_cmd) (void *data, const void *msg,
						   u16 * msg_size), void *data);

	void (*send_pkt) (void *ctrl, struct sk_buff * skb,
			  wltxdesc_t * txcfg, int qid);

	void (*register_pkt_rcv) (void *ctrl,
				  void (*rcv_pkt) (void *data,
						   struct sk_buff * skb,
						   bool is_data), void *data);

	void (*register_event_rcv) (void *ctrl,
				    void (*rcv_event) (void *data,
						       const void *event,
						       u16 * event_size),
				    void *data);
};

#endif /* __IPC_H__ */
