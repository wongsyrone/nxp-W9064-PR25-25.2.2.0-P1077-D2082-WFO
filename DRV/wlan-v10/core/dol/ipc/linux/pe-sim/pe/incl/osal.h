/** @file osal.h
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

#ifndef __OSAL_H__
#define __OSAL_H__

#include <linux/string.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/etherdevice.h>

#define LINUX_PE_SIM
#define BA_REORDER
#define ENABLE_PKT_SIGNATURE
/* #define DBG_BM_BUF_MONITOR */
/* #define ENABLE_PKT_DATA_STATUS */
#define ENABLE_SIGNATURE_CHECK_DATA
#define ENABLE_SIGNATURE_CHECK_PKT_HDR
/* #define CORTINA_TUNE */
/* #define CORTINA_TUNE_HW_CPY */
/* #define CORTINA_TUNE_HW_CPY_RX */
/* #define CORTINA_TUNE_SLIM_PKT_HDR */
/* #define CORTINA_TUNE_CACHE */

#define EPERM                       1
#define ENOMEM                      12
#define EFAULT                      14
#define EEXIST                      17
#define EINVAL                      22
#define ENOSPC                      28

#ifndef BIT
#define BIT(n) (1 << (n))
#endif

/* Please redefine LOCAL_US_TIMER to local timer (count in unit of us)
 * of packet engine processor
 */
#define LOCAL_US_TIMER              read32(radio->iobase1 + BBTX_TMR_FREE_TSF)
#define DIFF_UINT32(a, b)           ((b >= a) ? (b - a) : (0xFFFFFFFF - (a - b)))

#define JIFFIES                     jiffies
#define JIFFIES_TO_MSECS(x)         jiffies_to_msecs(x)
#define JIFFIES_TO_USECS(x)         jiffies_to_usecs(x)
#define TIMER_100MS                 HZ/10
#define TIMER_10MS                  HZ/100
#define TIMER_1MS                   HZ/1000

#define MALLOC(size)                kmalloc(size, GFP_ATOMIC)
#define MALLOC_CACHE(size)          kmalloc(size, GFP_ATOMIC)
#define MFREE(addr)                 kfree(addr)

#define PHYS_TO_VIRT(x)             phys_to_virt(x)
#define VIRT_TO_PHYS(x)             virt_to_phys(x)

#define BE16_TO_CPU(x)              be16_to_cpu(x)

#define memset                      memset
#define memcpy                      memcpy
#define memcmp                      memcmp
#define memmove                     memmove

#define write32                     writel
#define read32                      readl

#define ALIGN_ADDR(addr, align)     PTR_ALIGN(addr, align)
#define ADDR_ALIGNED(addr, align)   IS_ALIGNED(addr, align)

#define IS_MULTICAST_ADDR(addr)     is_multicast_ether_addr(addr)

#define printf(fmt, args...)        printk(fmt, ##args)

#define hex_dump(prefix, buf, len)  print_hex_dump(KERN_INFO, prefix, DUMP_PREFIX_OFFSET, 16, 1, buf, len, true);

/* functions needed for ethernet driver of packet engine to support
 * WiFi data offload
 */

/* Initialization of ethernet driver
 *
 * return:
 *    0: successful
 *    others: error code defined in this file.
 */
int eth_init(void);

/* Remove ethernet driver
 *
 * return:
 *    None.
 */
void eth_deinit(void);

/* Create ethernet device
 *
 * rid: specify which radio.
 * vid: specify which virtual interface.
 *
 * return:
 *    NULL: failed.
 *    others: handle for the created ethernet device.
 */
void *eth_create_dev(int rid, int vid);

/* Destroy ethernet device
 *
 * handle: specify which ethernet device to be destroyed
 *
 * return:
 *    None.
 */
void eth_destroy_dev(void *handle);

/* Register receive function for packet from ethernet driver
 *
 * rcv_pkt: function used to register as receive function.
 *          rid: radio id.
 *          vid: virtual interface id.
 *          pkt: original packet header of ethernet packet, used to call eth_free_pkt().
 *          data: point to start of ethernet packet.
 *                minimum headroom PKT_INFO_SIZE is needed for data from ethernet driver.
 *          len: length of ethernet packet.
 *          priority: 802.1d priority of the packet, upper layer will base on it to map the
 *                    packet to related AC.
 *                    0, 3: BE
 *                    1, 2: BK
 *                    4, 5: VI
 *                    6, 7: VO
 *                    -1: no priority, upper layer will do the mapping.
 *
 * return:
 *    0: successful
 *    others: error code defined in this file.
 */
int
eth_reg_recv_fun(void (*rcv_pkt)
		 (int rid, int vid, void *pkt, ca_uint8_t * data, int len,
		  int priority));

/* Free recevied packet from ethernet driver via registered receive function.
 *
 * pkt: point to packet header of received packet from ethernet driver.
 *
 * return:
 *    None.
 */
void eth_free_pkt(void *pkt);

/* Register free function for packet sent to ethernet driver
 *
 * free_pkt: function used to register as free function for packet sent to ethernet driver.
 *           rid: radio id.
 *           pkt: original packet header of transmit packet.
 *
 * return:
 *    0: successful.
 *    others: error code defined in this file.
 */
int eth_reg_free_fun(void (*free_pkt) (int rid, void *pkt));

/* Transmit packet to ethernet driver.
 *
 * handle: specify which ethernet device is used.
 * pkt: point to packet header of transmit packet, used to call registered free function.
 * data: point to start of data of transmit packet.
 * len: length of transmit packet.
 *
 * return:
 *    None.
 */
void eth_xmit_pkt(void *handle, void *pkt, ca_uint8_t * data, int len);

#endif /* __OSAL_H__ */
