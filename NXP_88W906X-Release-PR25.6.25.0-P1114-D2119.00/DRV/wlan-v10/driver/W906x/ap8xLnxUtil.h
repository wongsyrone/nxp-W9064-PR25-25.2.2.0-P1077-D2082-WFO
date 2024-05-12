/** @file ap8xLnxUtil.h
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
#ifndef _AP8XLNXUTIL_H
#define _AP8XLNXUTIL_H

#include "ap8xLnxBQM.h"

#define		FLPKT_LEN		256
#define		DRVDBG_ID_INVALID		0xffff
#define		SC5_BMQ10_POOL			0x1000
#define		NF_MAP_SIZE 	18

typedef enum rec_state {
	rec_invalid = 0,	//This record is invalid
	rec_normal,		//This record is normal 
	rec_error		//This record has problematic data
} rec_stat;

typedef enum {
	rxdbg_err_no = 0x00,
	rxdbg_err_dat_diff = 0x01,
	rxdbg_err_over_size = 0x02,
	rxdbg_err_flpkt = 0x04
} rxdbg_err_type;

typedef struct _rx_rawdat {
	U16 rdinx, wrinx;	//read/write index of the queue(0) to save the record
	int qid;		//Which SQ is this cfhul from
	wlrxdesc_t *pcfhul;	// Address of this cfhul
	wlrxdesc_t cfh_ul;	//cfh-ul
	U8 *ppayload;		//Pointer of the payload
	U8 rawdat[SC5_BMQ10_POOL];	// payload
	rec_stat valid;		// This record is valid or not
	rxdbg_err_type err_type;
} rx_rawdat;

typedef struct _rxdbg_queue {
	rx_rawdat records[FLPKT_LEN];	// Records to save the raw data,
	U16 rec_id;		// The id of the available record to be save. 
	// Active if rec_id != DRVDBG_ID_INVALID
	U16 rec_aft_err;	// How many records saved after error
} rxdbg_queue;

typedef struct _rxdbg_db {
	// ================================
	// Saved raw data
	U16 last_rxq;
	rxdbg_queue rxq_info[3];	// sq of cfhul (SQ0, SQ8, SQ9)

	wl_cfhul_amsdu err_cfhul_rec[10];
	u16 next_err_rec_id;
	// ================================
	// Display controller
	U16 showmsg_after_err;	//How many records to save after the problem is detected
	// ================================
	// Misc parameters
	u8 is_running;
	struct net_device *netdev;
} rxdbg_db;

typedef struct _rxdbg_intf {
	void (*init) (void *prxdbg, struct net_device * netdev);
	void (*active) (void *prxdbg, BOOLEAN is_set_act);
	void (*show_msg) (void *prxdbg);
	void (*rxdbg_push_errcfhul) (void *prxdbg, wl_cfhul_amsdu * pcfhul_amsdu, wlrxdesc_t * pcfhul);
	wlrxdesc_t *(*rxdbg_pull_errcfhul) (void *prxdbg);
	void (*rxdbg_push) (void *prxdbg, wlrxdesc_t * pcfhul, int qid, u16 rdinx, u16 wrinx);
	void (*rxdbg_chk) (void *prxdbg);
} rxdbg_intf;

typedef enum {
	rxdbg_cfhul,		//
	rxdbg_dummp		// dummy function
} submod_type;

void set_rxdbg_func(rxdbg_intf * prxdbg_intr, submod_type type);

// ============================================================================
// Exception recover module
// 
/*
	cfhul_info: This structure will save some fields of cfhul for buffer recover if exception occurs
*/
typedef struct _cfhul_buf_info {
	u32 bpid;
	u_int32_t lo_dword_addr;
} cfhul_buf_info;

typedef struct _cfhul_buf_pool {
	cfhul_buf_info rxq_info[3][SC5_RXQ_SIZE];	// One record maps to 1 RxQ
	u16 last_infoid[3];
} cfhul_buf_pool;

#ifdef MEMORY_USAGE_TRACE
#define MEM_SKB         0
#define MEM_VZALLOC     1
#define MEM_KMALLOC     2
#define MEM_DMAALLOC    3

typedef struct _mem_trace_func {
	UINT8 func[64];
	UINT32 line;
	UINT32 size;
	UINT8 type;
} mem_trace_func;

typedef struct _mem_trace_unit {
	UINT8 func_idx;
	void *addr;
	SINT32 length;
} mem_trace_unit;

typedef struct _mem_trace_db {
	UINT32 ispace;
	struct _mem_trace_db *next;
	mem_trace_unit unit[1800];
} mem_trace_db;

#define WL_MEM_TRACE_FUNC_NUM       128
#define WL_MEM_TRACE_SKB_NUM        7000
#define WL_MEM_TRACE_VZALLOC_NUM    32
#define WL_MEM_TRACE_KMALLOC_NUM    1000
#define WL_MEM_TRACE_DMAALLOC_NUM   128
#endif				/* MEMORY_USAGE_TRACE */

//void wl_update_cfhul_rec(cfhul_buf_pool *pcfhul_buf_pool, struct net_device *netdev, int qid, wlrxdesc_t *cfh_ul);
void wl_free_cfhul_lo(u_int32_t tmp_lodword_addr, struct net_device *netdev, u32 bpid);
void wl_update_cfhul_buf_rec(cfhul_buf_pool * pcfhul_buf_pool, struct net_device *netdev, int qid, u32 rdinx, wlrxdesc_t * cfh_ul);
#if 1
void wl_clr_cfhul_buf_rec(cfhul_buf_pool * pcfhul_buf_pool, int qid, u32 rdinx, wlrxdesc_t * pcfh_ul);
#else
void wl_clr_cfhul_buf_rec(struct net_device *netdev, int qid, wlrxdesc_t * cfh_ul);
#endif

void wl_save_last_rxskb(struct net_device *netdev, wlrxdesc_t * cfh_ul, struct sk_buff *skb);
void wl_clr_last_rxskb(struct net_device *netdev, u32 wlqm_aryid);
extern UINT32 wl_ch_load(vmacApInfo_t * vmacSta_p, UINT32 delta_time, UINT32 slotTickCnt, UINT8 scale_mapping);
extern void wl_get_ch_load_by_timer(ch_load_info_t * ch_load_info);
extern void wl_acs_ch_load_cb(UINT8 * data);
extern void wl_rrm_ch_load_cb(UINT8 * data);
extern void wl_bandsteer_ch_load_cb(UINT8 * data);

#ifdef MEMORY_USAGE_TRACE
void wl_get_meminfo_init(void);
void wl_get_meminfo_deinit(void);
SINT32 wl_get_meminfo_stat(void);
void *wl_util_alloc_skb(int len, const char *func, const int line);
void wl_util_free_skb(struct sk_buff *skb, const char *func, const int line);
void wl_util_receive_skb(struct sk_buff *skb, const char *func, const int line);
void *wl_util_vzalloc(size_t size, const char *func, const int line);
void wl_util_vfree(const void *ptr, const char *func, const int line);
void *wl_util_kmalloc(size_t size, gfp_t flags, const char *func, const int line);
void wl_util_kfree(const void *ptr, const char *func, const int line);
void *wl_util_dma_alloc_coherent(struct device *dev, size_t size, dma_addr_t * dma_handle, int flag, const char *func, const int line);
void wl_util_dma_free_coherent(struct device *dev, size_t size, void *cpu_addr, dma_addr_t dma_handle, const char *func, const int line);
#endif				/* MEMORY_USAGE_TRACE */

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
/* for kernel_read prototype changed
 commit bdd1d2d3d251c65b74ac4493e08db18971c09240
 Author: Christoph Hellwig <hch@lst.de>
 Date:   Fri Sep 1 17:39:13 2017 +0200

     fs: fix kernel_read prototype

     Use proper ssize_t and size_t types for the return value and count
     argument, move the offset last and make it an in/out argument like
     all other read/write helpers, and make the buf argument a void pointer
     to get rid of lots of casts in the callers.

     Signed-off-by: Christoph Hellwig <hch@lst.de>
     Signed-off-by: Al Viro <viro@zeniv.linux.org.uk>
 */
#define kernel_read(a, b, c, d) ap8x_kernel_read(a, b, c, d)
extern ssize_t ap8x_kernel_read(struct file *, void *, size_t, loff_t *);
#endif

/* Get free memory info in percentage
 */
extern u32 ap8x_get_free_sys_mem_info(void);

typedef struct _m_thread {
	unsigned long phandle_param;
	void (*handle_func) (unsigned long pparam);
#ifdef USE_TASKLET
	struct tasklet_struct task_obj;
#else
	struct work_struct task_obj;
#endif				//USE_TASKLET
} m_thread;

void mthread_init(m_thread *);
void mthread_deinit(m_thread *);
void mthread_run(m_thread * pparam);

extern SINT16 wl_util_get_nf(struct net_device *netdev, NfPathInfo_t * NF_path_p, SINT16 * s_value);
extern SINT16 wl_util_get_nf_from_fw(struct net_device *netdev);
extern SINT16 wl_util_get_rssi(struct net_device *netdev, RssiPathInfo_t * RSSI_path_p, SINT16 * s_value);
extern BOOLEAN wl_util_all_vapif_is_down(struct net_device *netdev);
extern BOOLEAN wl_util_dev_allow_offchan(struct net_device *netdev);
extern void wl_util_digi_to_hex_string(UINT8 * out_string, UINT8 * in_digit, UINT32 len);

#endif				//_AP8XLNXUTIL_H
