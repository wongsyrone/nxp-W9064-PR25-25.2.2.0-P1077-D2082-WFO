/** @file ap8xLnxEvent.h
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2005-2020 NXP
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
#ifndef AP8X_EVENT_H_
#define AP8X_EVENT_H_

#include <linux/version.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/delay.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/net.h>
#include <linux/wireless.h>
#include <net/iw_handler.h>

#define HOST_EVENT_DATA_OK           0x0000
#define HOST_EVENT_DATA_TRUNCATED    0x0001

#define HOST_EVT_NONE                0x0000
#define HOST_EVT_STA_DEL             0x0001
#define HOST_EVT_PRINTF              0x0002
#define HOST_EVT_IDX_TEST            0x0003
#define HOST_EVT_EXCEPTION           0x0004
#define HOST_EVT_PARITY_ERR          0x0005
#define HOST_EVT_OFFCHAN             0x0006
#define HOST_EVT_PRD_CSI_DMA_DONE    0x0007
#define HOST_EVT_PROBE_RSP_IES       0x0008
#define HOST_EVT_FTM_TX_DONE         0x0009

#define HOST_EVT_MAX_SIZE_PRINTF 200

typedef struct host_evt_hdr_s {
	UINT16 id;
	UINT16 len;
	UINT16 seqNum;
	UINT16 status;
} host_evt_hdr_t;

typedef struct evt_sta_del_s {
	UINT32 result;
	UINT16 staIdx;
	UINT8 macAddr[6];
} evt_sta_del_t;

typedef struct evt_printf_s {
	char message[HOST_EVT_MAX_SIZE_PRINTF];
} evt_printf_t;

typedef struct evt_idx_test_s {
	UINT32 packet_count;
	UINT32 packet_size;
} evt_idx_test_t;

typedef struct evt_parity_err_s {
	UINT32 cpu_parity_check_status;
} evt_parity_err_t;

typedef struct evt_offchan_s {
	UINT32 next_state;
} evt_offchan_t;

#ifdef PRD_CSI_DMA
typedef struct evt_prdcsi_s {
	UINT8 delta_len_A_to_ref_path_mm;
	UINT8 delta_len_B_to_ref_path_mm;
	UINT8 delta_len_C_to_ref_path_mm;
	UINT8 delta_len_D_to_ref_path_mm;

	UINT8 delta_len_E_to_ref_path_mm;
	UINT8 delta_len_F_to_ref_path_mm;
	UINT8 delta_len_G_to_ref_path_mm;
	UINT8 antenna_spacing_mm;

	UINT32 Ant_A_low_chan:10;
	UINT32 Ant_B_low_chan:10;
	UINT32 Ant_C_low_chan:10;
	UINT32 reserved1:2;

	UINT32 Ant_D_low_chan:10;
	UINT32 Ant_E_low_chan:10;
	UINT32 Ant_F_low_chan:10;
	UINT32 reserved2:2;

	UINT32 Ant_A_high_chan:10;
	UINT32 Ant_B_high_chan:10;
	UINT32 Ant_C_high_chan:10;
	UINT32 reserved3:2;

	UINT32 Ant_D_high_chan:10;
	UINT32 Ant_E_high_chan:10;
	UINT32 Ant_F_high_chan:10;
	UINT32 reserved4:2;

	UINT32 Ant_G_low_chan:10;
	UINT32 Ant_G_high_chan:10;
	UINT32 reserved5:12;
} evt_prdcsi_t;
#endif

typedef struct evt_probe_rsp_s {
	u32 timestamp;
	u16 macid;
	u16 length;
	u8 ies[EVENT_BUFFQ_SIZE - sizeof(host_evt_hdr_t) - 8];
}
evt_probe_rsp_t;

typedef struct host_evt_msg_s {
	host_evt_hdr_t hdr;
	union {
		evt_sta_del_t sta_del;
		evt_printf_t print_f;
		evt_idx_test_t idx_test;
		evt_parity_err_t parity_err;
		evt_offchan_t offchan;
#ifdef PRD_CSI_DMA
		evt_prdcsi_t prdcsi;
#endif
		evt_probe_rsp_t probe_rsp_ies;

		UINT8 data[EVENT_BUFFQ_SIZE - sizeof(host_evt_hdr_t)];
	}
	b;
}
host_evt_msg_t;

/* Custom Event Tag for User Applications */
typedef enum {
	EVENT_TAG_WLMGR = 1,
	EVENT_TAG_END
} event_tag;

/* Wlmgr event id, cmd & data */
typedef enum {
	WLMGR_ID_COMMON = 0,	/* Add COMMON ID for DEV_UP & DEV_DOWN */
	WLMGR_ID_MUMODE,
	WLMGR_ID_DCS,
	WLMGR_ID_END
} wlmgr_id;

typedef enum {
	WLMGR_CMD_DLOFDMA = 1,
	WLMGR_CMD_DLMIMO,
	WLMGR_CMD_ULOFDMA,
	WLMGR_CMD_ULMIMO,
	WLMGR_CMD_ULOFDMA_ENABLE,
	WLMGR_CMD_ULOFDMA_DISABLE,
	WLMGR_CMD_NLIST,
	WLMGR_CMD_DEV_OFFCH_STARTED,
	WLMGR_CMD_DEV_OFFCH_COMPLETED,
	WLMGR_CMD_DEV_UP,
	WLMGR_CMD_DEV_DOWN,
	WLMGR_CMD_ACS_STARTED,
	WLMGR_CMD_ACS_COMPLETED,
	WLMGR_CMD_DEV_DFS,
	WLMGR_CMD_END
} wlmgr_cmd;

typedef struct wlmgr_event_s {
	UINT32 id;
	UINT32 cmd;
	UINT32 data[];
} wlmgr_event_t;

typedef struct custom_tlv_s {
	UINT8 name[32];
	UINT32 tag;
	UINT32 len;
	UINT8 value[];
} custom_tlv_t;

extern void wl_WiFi_AoA_Decode(struct work_struct *work);
extern UINT32 wlEventHandler(vmacApInfo_t * vmacSta_p, void *vAddr);

extern int wl_send_event(struct net_device *netdev, custom_tlv_t * tlv_data, BOOLEAN force_send, BOOLEAN for_all);
extern void wl_send_offchan_active_event(struct net_device *netdev, wlmgr_id id, wlmgr_cmd cmd, u32 offch_id);
extern void wl_send_dev_up_event(struct net_device *netdev);
extern void wl_send_dev_down_event(struct net_device *netdev);

#endif				/* AP8X_EVENT_H_ */
