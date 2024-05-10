/** @file stadb_inline.h
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

#ifndef __STADB_INLINE_H__
#define __STADB_INLINE_H__

static inline ca_uint32_t
wang_32bit_mix(ca_uint32_t key)
{
	key += ~(key << 15);
	key ^= (key >> 10);
	key += (key << 3);
	key ^= (key >> 6);
	key += ~(key << 11);
	key ^= (key >> 16);

	return (key);
}

static inline ca_uint32_t
hash(ca_uint32_t key)
{
	ca_uint32_t result;

	result = wang_32bit_mix(key);
	result = result % SYSADPT_MAX_STA;

	return (result);
}

static inline int
locate_addr(struct radio *radio, ca_uint8_t * addr,
	    struct sta_item **item, ca_uint32_t * idx)
{
	ca_uint32_t key;

	memcpy(&key, addr + 2, 4);
	*idx = hash(key);

	*item = radio->stadb_ctrl->sta_db_p[*idx];

	if (!(*item)) {
		return -EFAULT;
	} else {
		if (!memcmp((*item)->sta_info.mac_addr, addr, ETH_ALEN)) {
			return 0;
		} else {
			while (((*item)->nxt_ht)) {
				*item = (*item)->nxt_ht;

				if (!memcmp((*item)->sta_info.mac_addr, addr,
					    ETH_ALEN))
					return 0;
			}
		}
	}

	return -EFAULT;
}

static inline int
stadb_addsta(ca_uint16_t rid, ca_uint16_t vid, ca_uint8_t * addr)
{
	struct radio *radio = &radio_info[rid - 1];
	struct sta_item *item = NULL;
	ca_uint32_t idx;
	struct list_item *tmp;
	struct sta_item *search;

	if (!radio->stadb_ctrl)
		return -EFAULT;

	if (!radio->stadb_ctrl->initizliaed)
		return -EFAULT;

	if (!locate_addr(radio, addr, &item, &idx))
		return -EEXIST;

	tmp = list_get_item(&radio->stadb_ctrl->free_sta_list);
	if (tmp) {
		search = radio->stadb_ctrl->sta_db_p[idx];
		item = (struct sta_item *)tmp;

		memset(&item->sta_info, 0, sizeof(struct sta_info));
		memcpy(&item->sta_info.mac_addr, addr, ETH_ALEN);
		item->sta_info.rid = rid;
		item->sta_info.vid = vid;

		if (search) {
			while (search->nxt_ht)
				search = search->nxt_ht;
			search->nxt_ht = item;
			item->prv_ht = search;
			item->nxt_ht = NULL;
		} else {
			item->nxt_ht = item->prv_ht = NULL;
			radio->stadb_ctrl->sta_db_p[idx] = item;
		}

		radio->vif_info[vid].sta_cnt++;

		list_put_item(&radio->stadb_ctrl->sta_list, tmp);

		return 0;
	}

	return -ENOSPC;
}

static inline int
stadb_delsta(ca_uint16_t rid, ca_uint8_t * addr)
{
	struct radio *radio = &radio_info[rid - 1];
	struct sta_item *item = NULL;
	ca_uint32_t idx;
	int result;
	struct sta_item *search;

	if (!radio->stadb_ctrl)
		return -EFAULT;

	if (!radio->stadb_ctrl->initizliaed)
		return -EFAULT;

	result = locate_addr(radio, addr, &item, &idx);
	if (result)
		return result;

	search = radio->stadb_ctrl->sta_db_p[idx];
	if (search) {
		while (memcmp(&(search->sta_info.mac_addr),
			      item->sta_info.mac_addr, ETH_ALEN))
			search = search->nxt_ht;
	}

	if (search && item) {
		if (search->prv_ht && search->nxt_ht) {
			item->nxt_ht->prv_ht = item->prv_ht;
			item->prv_ht->nxt_ht = item->nxt_ht;
		} else {
			if (search->prv_ht) {
				search->prv_ht->nxt_ht = NULL;
			} else if (search->nxt_ht) {
				search->nxt_ht->prv_ht = NULL;
				radio->stadb_ctrl->sta_db_p[idx] =
					search->nxt_ht;
			} else {
				radio->stadb_ctrl->sta_db_p[idx] = NULL;
			}
		}
		item->nxt_ht = item->prv_ht = NULL;
	}

	radio->vif_info[item->sta_info.vid].sta_cnt--;
	item->sta_info.rid = 0;
	item->sta_info.vid = 0;
	memset(item->sta_info.mac_addr, 0, ETH_ALEN);
	item->sta_info.enable = false;

	list_put_item(&radio->stadb_ctrl->free_sta_list,
		      list_remove_item(&radio->stadb_ctrl->sta_list,
				       (struct list_item *)item));

	return 0;
}

static inline void
stadb_delsta_all(ca_uint16_t rid)
{
	struct radio *radio = &radio_info[rid - 1];
	struct list_item *search;
	struct sta_item *search1;

	if (!radio->stadb_ctrl)
		return;

	if (!radio->stadb_ctrl->initizliaed)
		return;

	search = radio->stadb_ctrl->sta_list.head;
	while (search) {
		search1 = (struct sta_item *)search;
		stadb_delsta(rid, search1->sta_info.mac_addr);
		search = radio->stadb_ctrl->sta_list.head;;
	}
}

static inline void
stadb_delsta_vif(ca_uint16_t rid, ca_uint16_t vid)
{
	struct radio *radio = &radio_info[rid - 1];
	struct list_item *search;
	struct sta_item *search1;

	if (!radio->stadb_ctrl)
		return;

	if (!radio->stadb_ctrl->initizliaed)
		return;

	search = radio->stadb_ctrl->sta_list.head;
	while (search) {
		search1 = (struct sta_item *)search;
		if (search1->sta_info.vid == vid) {
			stadb_delsta(rid, search1->sta_info.mac_addr);
			search = radio->stadb_ctrl->sta_list.head;;
		} else
			search = search->nxt;
	}
}

static inline struct sta_info *
stadb_get_stainfo(ca_uint16_t rid, ca_uint8_t * addr)
{
	struct radio *radio = &radio_info[rid - 1];
	struct sta_item *item = NULL;
	ca_uint32_t idx;
	int result;

	if (!radio->stadb_ctrl)
		return NULL;

	if (!radio->stadb_ctrl->initizliaed)
		return NULL;

	result = locate_addr(radio, addr, &item, &idx);
	if (result)
		return NULL;

	return &item->sta_info;
}

#endif /* __STADB_INLINE_H__ */
