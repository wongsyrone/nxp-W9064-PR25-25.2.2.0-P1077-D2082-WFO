/** @file eth.c
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

#include "sysadpt.h"
#include "ca_types.h"
#include "radio.h"

#define MAX_HANDLE_NUM (SYSADPT_MAX_RADIO * SYSADPT_MAX_VIF)

struct eth_handle {
	int rid;
	int vid;
	bool valid;
};

struct eth_simple_hdr {
	ca_uint8_t *buf_ptr;
	ca_uint8_t *data;
	int len;
};

static struct eth_handle handle[MAX_HANDLE_NUM];

static void (*eth_recv_reg_fun) (int rid, int vid, void *pkt, ca_uint8_t * data,
				 int len, int priority);

static void (*eth_xmit_free_pkt) (int rid, void *pkt);

int
eth_init(void)
{
	int i;

	for (i = 0; i < MAX_HANDLE_NUM; i++)
		handle[i].valid = false;

	eth_recv_reg_fun = NULL;
	eth_xmit_free_pkt = NULL;

	return 0;
}

void
eth_deinit(void)
{
	int i;

	for (i = 0; i < MAX_HANDLE_NUM; i++)
		handle[i].valid = false;

	eth_recv_reg_fun = NULL;
	eth_xmit_free_pkt = NULL;
}

void *
eth_create_dev(int rid, int vid)
{
	int i, h;

	if ((rid <= 0) || (rid > SYSADPT_MAX_RADIO))
		return NULL;

	if ((vid < 0) || (vid >= SYSADPT_MAX_VIF))
		return NULL;

	for (i = 0; i < MAX_HANDLE_NUM; i++) {
		if (!handle[i].valid) {
			h = i;
			break;
		}
	}

	for (i = 0; i < MAX_HANDLE_NUM; i++) {
		if (!handle[i].valid)
			continue;
		if ((handle[i].rid == rid) && (handle[i].vid == vid))
			return (void *)&handle[i];
	}

	handle[h].rid = rid;
	handle[h].vid = vid;
	handle[h].valid = true;

	return (void *)&handle[h];
}

void
eth_destroy_dev(void *handle)
{
	struct eth_handle *eth_handle = (struct eth_handle *)handle;

	eth_handle->rid = 0;
	eth_handle->vid = 0;
	eth_handle->valid = false;
}

int
eth_reg_recv_fun(void (*rcv_pkt)
		 (int rid, int vid, void *pkt, ca_uint8_t * data, int len,
		  int priority))
{
	eth_recv_reg_fun = rcv_pkt;

	return 0;
}

void
eth_free_pkt(void *pkt)
{
	struct eth_simple_hdr *pkt_hdr = (struct eth_simple_hdr *)pkt;

	MFREE(pkt_hdr->buf_ptr);
	MFREE(pkt_hdr);
}

int
eth_reg_free_fun(void (*free_pkt) (int rid, void *pkt))
{
	eth_xmit_free_pkt = free_pkt;

	return 0;
}

void
eth_xmit_pkt(void *handle, void *pkt, ca_uint8_t * data, int len)
{
	struct eth_handle *eth_handle = (struct eth_handle *)handle;
	struct radio *radio;
	ca_uint8_t addr[ETH_ALEN];
	struct eth_simple_hdr *pkt_hdr;

	if (eth_handle->valid) {
		radio = &radio_info[eth_handle->rid - 1];

		if (radio->dbg_ctrl & DBG_DUMP_ETH_TX_PKT) {
			/* Dump conent of transmit packet to make sure WiFi
			 * driver transmits the correct packet to ethernet
			 * driver.
			 */
			hex_dump("ETH_TX:", data, len);
		}

		if ((radio->dbg_ctrl & DBG_ETH_LOOPBACK_PKT) &&
		    (eth_recv_reg_fun)) {
			/* Loop back the packet to WiFi to verify
			 * packet sending to WiFi from ethrent driver
			 * via registered receive function.
			 */
			if (!IS_MULTICAST_ADDR(data)) {
				memcpy(addr, data, ETH_ALEN);
				memcpy(data, data + ETH_ALEN, ETH_ALEN);
				memcpy(data + ETH_ALEN, addr, ETH_ALEN);
			}
			pkt_hdr = MALLOC(sizeof(struct eth_simple_hdr));
			/* ethenet driver should make sure headroom is enough */
			pkt_hdr->buf_ptr = MALLOC(len + PKT_INFO_SIZE);
			pkt_hdr->data = pkt_hdr->buf_ptr + PKT_INFO_SIZE;
			pkt_hdr->len = len;
			memcpy(pkt_hdr->data, data, len);
			eth_recv_reg_fun(radio->rid, eth_handle->vid, pkt_hdr, pkt_hdr->data, len, 0);	/* BE */
		}
	}

	/* For real ethernet driver, this registered free function should be
	 * called after transmission is completed.
	 */
	if (eth_xmit_free_pkt)
		eth_xmit_free_pkt(eth_handle->rid, pkt);
}
