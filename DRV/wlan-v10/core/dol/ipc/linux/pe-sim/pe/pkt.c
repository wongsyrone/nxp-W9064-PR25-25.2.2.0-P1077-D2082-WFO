/** @file pkt.c
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
#include "ipc.h"
#include "ipc_msg.h"

#ifdef DBG_BM_BUF_MONITOR
#define MONITOR_SIZE             16
#define BMQ10_BUF_NUM            (1024 + SYSADPT_EXTRA_BM_BUF_NUM_Q10)

#ifdef LINUX_PE_SIM
struct buf_mon {
	ca_uint64_t buf_start;
	ca_uint64_t mon_ptr;
};
#else
struct buf_mon {
	ca_uint32_t buf_start;
	ca_uint32_t mon_ptr;
};
#endif

struct buf_mon bmq10_mon[SYSADPT_MAX_RADIO][BMQ10_BUF_NUM];

void
dbg_check_buf(int rid, struct pkt_hdr *pkt_hdr, const char *fun)
{
	struct pkt_data *pkt_data;
	int i, j;

	if (pkt_hdr->qid != 10)
		return;

	pkt_data = (struct pkt_data *)
		(pkt_hdr->buf_ptr - PKT_DATA_HEADROOM);

	for (i = 0; i < BMQ10_BUF_NUM; i++) {
#ifdef LINUX_PE_SIM
		if (bmq10_mon[rid - 1][i].buf_start == (ca_uint64_t) pkt_data)
#else
		if (bmq10_mon[rid - 1][i].buf_start == pkt_data)
#endif
			break;
	}

	if (i == BMQ10_BUF_NUM) {
		printf("\t Packet corruption (%d:%s)\n", rid, fun);
		printf("\t pkt_hdr: %p, pkt_data: %p\n", pkt_hdr, pkt_data);
		return;
	}

	for (j = 0; j < MONITOR_SIZE; j++) {
		ca_uint8_t *mon_ptr =
			(ca_uint8_t *) bmq10_mon[rid - 1][i].mon_ptr;

		if (mon_ptr[j]) {
			printf("\t Monitor area polluted (%s)\n", fun);
			printf("\t buffer: %d, pkt_hdr: %p, pkt_data: %p\n",
			       i, pkt_hdr, pkt_data);
			hex_dump("POLLUTED", mon_ptr, MONITOR_SIZE);
			printf("\n");
#ifdef LINUX_PE_SIM
			printf("packet: %d, buffer start: %llx, monitor: %llx\n", i - 1, bmq10_mon[rid - 1][i - 1].buf_start, bmq10_mon[rid - 1][i - 1].mon_ptr);
			hex_dump("WHOLE PACKET",
				 (ca_uint8_t *) bmq10_mon[rid - 1][i -
								   1].buf_start,
				 4300);
			printf("packet: %d, buffer start: %llx, monitor %p\n",
			       i, bmq10_mon[rid - 1][i].buf_start, mon_ptr);
			hex_dump("WHOLE PACKET", pkt_data, 4300);
			printf("packet: %d, buffer start: %llx, monitor: %llx\n", i + 1, bmq10_mon[rid - 1][i + 1].buf_start, bmq10_mon[rid - 1][i + 1].mon_ptr);
			hex_dump("WHOLE PACKET",
				 (ca_uint8_t *) bmq10_mon[rid - 1][i +
								   1].buf_start,
				 4300);
#else
			printf("packet: %d, buffer start: %lx, monitor: %lx\n",
			       i - 1, bmq10_mon[rid - 1][i - 1].buf_start,
			       bmq10_mon[rid - 1][i - 1].mon_ptr);
			hex_dump("WHOLE PACKET",
				 (ca_uint8_t *) bmq10_mon[rid - 1][i -
								   1].buf_start,
				 4300);
			printf("packet: %d, buffer start: %lx, monitor %p\n", i,
			       bmq10_mon[rid - 1][i].buf_start, mon_ptr);
			hex_dump("WHOLE PACKET", pkt_data, 4300);
			printf("packet: %d, buffer start: %lx, monitor: %lx\n",
			       i + 1, bmq10_mon[rid - 1][i + 1].buf_start,
			       bmq10_mon[rid - 1][i + 1].mon_ptr);
			hex_dump("WHOLE PACKET",
				 (ca_uint8_t *) bmq10_mon[rid - 1][i +
								   1].buf_start,
				 4300);
#endif
			break;
		}
	}
}
#endif

int
pkt_init(int rid)
{
	struct radio *radio = &radio_info[rid - 1];
	struct pkt_ctrl *ctrl;
#ifdef LINUX_PE_SIM
	struct list_item *item;
#else
	ca_uint8_t *data;
#endif
	int i, j, mem_size, hdr_num;
	int buf_size[4], buf_num[4];
	uint extra_mem_size;

	memset(&radio->pkt_ctrl, 0, sizeof(struct pkt_ctrl));

	ctrl = &radio->pkt_ctrl;
	hdr_num = 0;
	extra_mem_size = PKT_DATA_HEADROOM + SYSADPT_BM_BUF_HEADROOM +
		RXBUF_ALIGN + PKT_TAIL_SIGNATURE_OFFSET * 6;
#ifndef LINUX_PE_SIM
	if (!ADDR_ALIGNED((long)extra_mem_size, RXBUF_ALIGN)) {
		extra_mem_size = (uint) ALIGN_ADDR(extra_mem_size, RXBUF_ALIGN);
	}
#endif
	for (i = 0; i < 4; i++) {
		if (!radio->bm_q_size[i])
			continue;
		buf_size[i] = radio->bm_buf_size[i] + extra_mem_size;
		if (i == 0)
			buf_num[i] =
				radio->bm_q_size[i] +
				SYSADPT_EXTRA_BM_BUF_NUM_Q10;
		else if (i == 1)
			buf_num[i] =
				radio->bm_q_size[i] +
				SYSADPT_EXTRA_BM_BUF_NUM_Q11;
		else if (i == 2)
			buf_num[i] =
				radio->bm_q_size[i] +
				SYSADPT_EXTRA_BM_BUF_NUM_Q12;
		else
			buf_num[i] = radio->bm_q_size[i];
		mem_size = buf_num[i] * buf_size[i];
		hdr_num += buf_num[i];
#ifndef LINUX_PE_SIM
		ctrl->pkt_data[i] = (struct pkt_data *)MALLOC(mem_size);
		if (!ctrl->pkt_data[i])
			goto no_mem;
		memset(ctrl->pkt_data[i], 0, mem_size);
#endif
		list_init(&ctrl->pkt_data_free_list[i]);
		printf("\t buf_num[%d] = %d\n", i, buf_num[i]);
		printf("\t buf_size[%d] = %d == bm_buf_size %d + extra_mem_size %d\n", i, buf_size[i], radio->bm_buf_size[i], extra_mem_size);
	}

	printf("\t PKT_DATA_HEADROOM: %d, BM_BUF_HEADROOM: %d\n",
	       (int)PKT_DATA_HEADROOM, SYSADPT_BM_BUF_HEADROOM);

	hdr_num += SYSADPT_MAX_EXTRA_PKT_HDR;
	mem_size = hdr_num * sizeof(struct pkt_hdr);
#ifdef LINUX_PE_SIM
	ctrl->pkt_hdr = (struct pkt_hdr *)vmalloc(mem_size);
#else
	ctrl->pkt_hdr = (struct pkt_hdr *)MALLOC_CACHE(mem_size);
#endif
	if (!ctrl->pkt_hdr)
		goto no_mem;
	memset(ctrl->pkt_hdr, 0, mem_size);
	list_init(&ctrl->pkt_hdr_free_list);
	list_init(&ctrl->pkt_from_host_list);
	list_init(&ctrl->pkt_from_host_free_list);
	for (i = 0; i < 4; i++)
		list_init(&ctrl->pkt_from_eth_list[i]);

	for (i = 0; i < 4; i++) {
		if (!radio->bm_q_size[i])
			continue;
#ifdef LINUX_PE_SIM
		for (j = 0; j < buf_num[i]; j++) {
			item = (struct list_item *)MALLOC(buf_size[i]);

			if (item)
				list_put_item(&ctrl->pkt_data_free_list[i],
					      item);
			else
				goto no_mem;
#ifdef DBG_BM_BUF_MONITOR
			if (i == 0) {
				ca_uint64_t buf_start = (ca_uint64_t) item;

				bmq10_mon[rid - 1][j].buf_start = buf_start;
				bmq10_mon[rid - 1][j].mon_ptr =
					buf_start + buf_size[i] - MONITOR_SIZE;
				memset((ca_uint8_t *) buf_start +
				       PKT_DATA_HEADROOM, 0,
				       buf_size[i] - PKT_DATA_HEADROOM);
			}
#endif
		}
#else
		data = (ca_uint8_t *) ctrl->pkt_data[i];
		if (data) {
			for (j = 0; j < buf_num[i]; j++) {
				list_put_item(&ctrl->pkt_data_free_list[i],
					      (struct list_item *)data);
#ifdef DBG_BM_BUF_MONITOR
				if (i == 0) {
					bmq10_mon[rid - 1][j].buf_start = data;
					bmq10_mon[rid - 1][j].mon_ptr =
						data + buf_size[i] -
						MONITOR_SIZE;
					memset((ca_uint8_t *) data +
					       PKT_DATA_HEADROOM, 0,
					       buf_size[i] - PKT_DATA_HEADROOM);
				}
#endif
				data += buf_size[i];
			}
		}
#endif
	}

	for (i = 0; i < hdr_num; i++) {
		memset(ctrl->pkt_hdr + i, 0, sizeof(struct pkt_hdr));
		list_put_item(&ctrl->pkt_hdr_free_list,
			      (struct list_item *)(ctrl->pkt_hdr + i));
	}

	printf("\t packet header number: %d, size: %d\n", hdr_num,
	       (int)sizeof(struct pkt_hdr));

#ifdef BA_REORDER
	ba_msdu_pkt_num = hdr_num;
#endif

	ctrl->initizliaed = true;

	return 0;

no_mem:
	for (i = 0; i < 4; i++)
#ifdef LINUX_PE_SIM
		while (1) {
			item = list_get_item(&ctrl->pkt_data_free_list[i]);
			if (item)
				MFREE(item);
			else
				break;
		}
#else
		if (ctrl->pkt_data[i])
			MFREE(ctrl->pkt_data[i]);
#endif
	if (ctrl->pkt_hdr)
		MFREE(ctrl->pkt_hdr);

	printf("\t %s(%d): fail to alloc memory\n", __func__, rid);
	return -ENOMEM;
}

void
pkt_deinit(int rid)
{
	struct radio *radio = &radio_info[rid - 1];
	struct pkt_ctrl *ctrl = &radio->pkt_ctrl;
#ifdef LINUX_PE_SIM
	struct list_item *item;
#endif
	int i;

	for (i = 0; i < 4; i++) {
#ifdef LINUX_PE_SIM
		while (1) {
			item = list_get_item(&ctrl->pkt_data_free_list[i]);
			if (item)
				MFREE(item);
			else
				break;
		}
#else
		if (ctrl->pkt_data[i])
			MFREE(ctrl->pkt_data[i]);
#endif
	}
	if (ctrl->pkt_hdr)
#ifdef LINUX_PE_SIM
		vfree(ctrl->pkt_hdr);
#else
		MFREE(ctrl->pkt_hdr);
#endif
}
