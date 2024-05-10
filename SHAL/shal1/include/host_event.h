/** @file host_event.h
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2018-2020 NXP
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
#ifndef _HOST_EVENT_H_
#define _HOST_EVENT_H_
#include "basic_types.h"
#include "smac_hal_inf.h"
#include "shal_msg.h"

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

#define HOST_EVT_MAX_SIZE        256
#define HOST_EVT_MAX_SIZE_PRINTF 200

#define HOST_EVT_SEQNO_R7_PARITY_ECC 0xFFFF

typedef struct host_evt_hdr_s {
	u16 id;
	u16 len;
	u16 seqNum;
	u16 status;
} host_evt_hdr_t;

typedef struct evt_sta_del_s {
	u32 result;
	u16 staIdx;
	u8 macAddr[6];
} evt_sta_del_t;

typedef struct evt_printf_s {
	char message[HOST_EVT_MAX_SIZE_PRINTF];
} evt_printf_t;

typedef struct evt_idx_test_s {
	u32 packet_count;
	u32 packet_size;
} evt_idx_test_t;

typedef struct evt_parity_err_s {
	u32 cpu_parity_check_status;
} evt_parity_err_t;

typedef struct evt_offchan_s {
	u32 next_state;
} evt_offchan_t;

#ifdef PRD_CSI_DMA
typedef struct evt_prdcsi_s {
	u8 delta_len_A_to_ref_path_mm;
	u8 delta_len_B_to_ref_path_mm;
	u8 delta_len_C_to_ref_path_mm;
	u8 delta_len_D_to_ref_path_mm;

	u8 delta_len_E_to_ref_path_mm;
	u8 delta_len_F_to_ref_path_mm;
	u8 delta_len_G_to_ref_path_mm;
	u8 antenna_spacing_mm;

	u32 Ant_A_low_chan:10;
	u32 Ant_B_low_chan:10;
	u32 Ant_C_low_chan:10;
	u32 reserved1:2;

	u32 Ant_D_low_chan:10;
	u32 Ant_E_low_chan:10;
	u32 Ant_F_low_chan:10;
	u32 reserved2:2;

	u32 Ant_A_high_chan:10;
	u32 Ant_B_high_chan:10;
	u32 Ant_C_high_chan:10;
	u32 reserved3:2;

	u32 Ant_D_high_chan:10;
	u32 Ant_E_high_chan:10;
	u32 Ant_F_high_chan:10;
	u32 reserved4:2;

	u32 Ant_G_low_chan:10;
	u32 Ant_G_high_chan:10;
	u32 reserved5:12;
} evt_prdcsi_t;
#endif

#define EVT_PROBE_RSP_MAX_LEN  (HOST_EVT_MAX_SIZE - sizeof(host_evt_hdr_t) - 8)

typedef struct evt_probe_rsp_s {
	u32 timestamp;
	u16 macid;
	u16 length;
	u8 ies[EVT_PROBE_RSP_MAX_LEN];
} evt_probe_rsp_t;

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

		u8 data[HOST_EVT_MAX_SIZE - sizeof(host_evt_hdr_t)];
	}
	b;
}
host_evt_msg_t;

extern u32 host_event_sent(u16 eventId, u8 * pEvent, u16 len);
extern u32 host_event_sent_sta_del(u16 sta_id, u16 status, u8 * macAddr);

//#define DEBUG_PRINTF
#ifdef DEBUG_PRINTF
// Functions / Variables
extern void sprintf(void *, char *, ...);
extern u32 debug_printf_level;

// Define these to compile in certain debug prints
// These are more broader categories of debug to print out
//#define DEBUG_PRINTF_CALIBRATION
//#define DEBUG_PRINTF_POWER_TABLE
//#define DEBUG_PRINTF_CSI
//#define DEBUG_PRINTF_DRA

// Define these to enable certain debug print messages
// These are more distinct levels of prints for the above categories
// DEBUG_PRINTF_CALIBRATION
#define DEBUG_PRINTF_LEVEL_RXIQ    0x00000001
#define DEBUG_PRINTF_LEVEL_TXIQ    0x00000002
#define DEBUG_PRINTF_LEVEL_LO_Leak 0x00000004
#define DEBUG_PRINTF_LEVEL_TX_PWR  0x00000008
#define DEBUG_PRINTF_LEVEL_IBF     0x00000010
#define DEBUG_PRINTF_LEVEL_INT_CAL 0x00000020

// DEBUG_PRINTF_POWER_TABLE
#define DEBUG_PRINTF_LEVEL_PT_SAVE 0x00000001

// DEBUG_PRINTF_CSI
#define DEBUG_PRINTF_LEVEL_CSI_LEN 0x00000001

// DEBUG_PRINTF_DRA
#define DEBUG_PRINTF_LEVEL_DRA_TBL 0x00000001
#endif
extern u32 host_event_sent_printf(char *message);

extern u32 host_event_sent_idx_test(u32 packet_count, u32 packet_size);

extern u32 host_event_sent_exception(void);
extern u32 host_event_sent_parity_err(void);
extern u32 host_event_sent_offchan(u32 next_state);

#ifdef PRD_CSI_DMA
extern u32 host_event_sent_prd_csi_dma_done(void);
#endif

#endif /* _HOST_EVENT_H_ */
