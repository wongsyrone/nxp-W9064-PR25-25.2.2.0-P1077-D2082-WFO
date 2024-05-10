/** @file stadb.h
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

#ifndef __STADB_H__
#define __STADB_H__

struct sta_info {
	ca_uint16_t rid;
	ca_uint16_t vid;
	ca_uint16_t stn_id;
	ca_uint8_t mac_addr[ETH_ALEN];
	bool enable;
	bool active_notify;
	ca_uint16_t threshold;
	bool startbytid[SYSADPT_MAX_TID];
	struct rssi_path_info rssi_path_info;
	struct rxppdu_airtime rxppdu_airtime;
	ca_uint64_t tx_bytes;
	ca_uint64_t rx_bytes;
	ca_uint16_t om_control;
};

struct sta_item {
	struct sta_item *nxt;
	struct sta_item *prv;
	struct sta_item *nxt_ht;
	struct sta_item *prv_ht;
	struct sta_info sta_info;
};

struct stadb_ctrl {
	bool initizliaed;
	ca_uint16_t max_sta_supported;
	struct sta_item *sta_db;
	struct sta_item *sta_db_p[SYSADPT_MAX_STA];
	struct list free_sta_list;
	struct list sta_list;
};

int stadb_init(ca_uint16_t rid);

void stadb_deinit(ca_uint16_t rid);

void stadb_list(ca_uint16_t rid);

void stadb_active_notify(ca_uint16_t rid);

#endif /* __STADB_H__ */
