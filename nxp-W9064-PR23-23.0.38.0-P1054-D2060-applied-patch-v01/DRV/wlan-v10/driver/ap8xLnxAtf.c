/** @file ap8xLnxAtf.c
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

#include "ap8xLnxIntf.h"
#include "ap8xLnxFwcmd.h"
#include "ap8xLnxAtf.h"

#ifndef PACK_STRUCT
#define PACK_STRUCT  __attribute__ ((packed))
#endif

#ifndef ALIGN32
#define ALIGN32 __attribute__((aligned(32)))	// Force cache alignment
#endif

#ifndef PACK_START
#define  PACK_START
#endif /* #ifndef PACK_START */

#ifndef PACK_END
#define PACK_END   __attribute__((__packed__))
#endif /* #ifndef PACK_END */

#define NUM_TXQUEUE     3072	// Number of Tx Queues supported (max 3K)

typedef enum {
	ATF_SEND_LOGS,
	ATF_SEND_STATS
} atfSendDataMode_t;

typedef PACK_START struct {
	UINT32 input_rate;
	UINT32 output_rate;
	UINT32 phy_rate;
	UINT32 txq_weigth;
	UINT8 used_airtime;
	UINT8 is_zero_drops;
	UINT16 txq_id;
	UINT8 tid;
	UINT8 accessCategory;
} PACK_END atf_txq_stats_t;

typedef PACK_START struct {
	UINT8 mode;		// has to be first
	UINT8 used_airtime;
	UINT8 rx_airtime;
	UINT8 shared_airtime;
	UINT16 txq_nr;
	atf_txq_stats_t txq_stats[0];
} PACK_END atf_stats_t;

#ifdef AIRTIME_FAIRNESS_TRACES
#define ATF_TRACE_BUFF_SIZE         (1024)
typedef PACK_START struct {
	u8 mode;
	char atf_trace_buffer[ATF_TRACE_BUFF_SIZE];
	u32 atf_trace_buffer_len;
} PACK_END atfTraces_t;
#endif /* AIRTIME_FAIRNESS_TRACES */

#define ATF_STATS_FULL_SIZE                 (sizeof(atf_stats_t) + (sizeof(atf_txq_stats_t) * NUM_TXQUEUE))
#define ATF_STATS_TRANSFER_SIZE(txq_nr)     (sizeof(atf_stats_t) + (sizeof(atf_txq_stats_t) * (txq_nr)))

void *atf_dma_data = NULL;
dma_addr_t atf_dma_phys_data;
unsigned int atf_dma_data_size;

atf_stats_t *atf_stats_shadow;
BOOLEAN atf_refresh_allowed = FALSE;
spinlock_t atf_refresh_lock;

static ssize_t atf_sysfs_read(struct file *fp,
			      struct kobject *kobj,
			      struct bin_attribute *bin_attr,
			      char *buf, loff_t off, size_t count);
static ssize_t atf_sysfs_write(struct file *fp,
			       struct kobject *kobj,
			       struct bin_attribute *bin_attr,
			       char *buf, loff_t off, size_t count);

static struct bin_attribute atf_stats_sysfs_attr = {
	.attr = {
		 .name = "atf_stats",
		 .mode = S_IRUGO,
		 },
	.read = atf_sysfs_read,
	.write = atf_sysfs_write,
};

static ssize_t
atf_sysfs_write(struct file *fp,
		struct kobject *kobj,
		struct bin_attribute *bin_attr,
		char *buf, loff_t off, size_t count)
{
	spin_lock(&atf_refresh_lock);
	if (count >= 1) {
		atf_refresh_allowed = (buf[0] != 0);
	}
	spin_unlock(&atf_refresh_lock);

	return count;
}

static ssize_t
atf_sysfs_read(struct file *fp,
	       struct kobject *kobj,
	       struct bin_attribute *bin_attr,
	       char *buf, loff_t off, size_t count)
{
	size_t max_data_size;
	uint8_t *src;

	spin_lock(&atf_refresh_lock);
	// max_data_size = atf_stats_shadow->txq_nr * sizeof(atf_txq_stats_t) + sizeof(atf_stats_t);
	max_data_size = ATF_STATS_FULL_SIZE;
	src = (uint8_t *) atf_stats_shadow;

	if (off > max_data_size) {
		off = max_data_size;
	}

	if (off + count >= max_data_size) {
		count = max_data_size - off;
	}

	memcpy(buf, &src[off], count);
	spin_unlock(&atf_refresh_lock);

	return count;
}

static int
atf_setup_dma(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	unsigned int size = ATF_STATS_FULL_SIZE;

	if (atf_dma_data != NULL) {
		printk("atf dma data already allocated, need to free before\n");
		BUG_ON(in_interrupt());

		pci_free_consistent(wlpptr->pPciDev, atf_dma_data_size,
				    atf_dma_data, atf_dma_phys_data);
		atf_dma_data = NULL;
		atf_dma_phys_data = (dma_addr_t) 0;
	}

	printk("== Trying pci_alloc_consistent size=%u...", size);

	atf_dma_data =
		pci_alloc_consistent(wlpptr->pPciDev, size, &atf_dma_phys_data);

	if (atf_dma_data == NULL) {
		printk("Failed!\n");
		return -1;
	}

	printk("OK cpu_addr=%p phys_addr=%pad\n", atf_dma_data,
	       &atf_dma_phys_data);

	atf_dma_data_size = size;

	printk("== Setting FW DMA values...");
	if (wlFwSetAtfDma(netdev, atf_dma_phys_data, size) != 0) {
		printk("Failed!\n");
		return -1;
	}

	printk("OK!\n");

	printk("== Setting sysfs for atf_stats...");
	if (sysfs_create_bin_file(&(netdev->dev.kobj), &atf_stats_sysfs_attr) !=
	    0) {
		printk("Failed!\n");
		return -1;
	}
	printk("OK!\n");

	atf_stats_shadow = wl_kmalloc(ATF_STATS_FULL_SIZE, GFP_KERNEL);
	if (atf_stats_shadow == NULL) {
		printk("wl_kmalloc for atf_stats_shadow failed!\n");
		return -1;
	}

	memset(atf_stats_shadow, 0, ATF_STATS_FULL_SIZE);

	atf_refresh_allowed = TRUE;
	spin_lock_init(&atf_refresh_lock);

	return 0;
}

int
atf_debug_enable(struct net_device *netdev, u8 debug_feature, u8 enable)
{
	static BOOLEAN is_dma_setup_done = FALSE;
	int ret;

	if (enable) {
		if (!is_dma_setup_done) {
			ret = atf_setup_dma(netdev);
			if (ret != 0)
				return ret;

			is_dma_setup_done = TRUE;
		}
	}

	printk("== calling wlFwAtfDebugEnable...");
	ret = wlFwAtfDebugEnable(netdev, debug_feature, enable);
	if (ret != 0)
		return ret;
	printk("OK\n");

	return 0;
}

void
atf_irq_task_handler(struct work_struct *work)
{
	struct wlprivate_data *wlpd_p =
		container_of(work, struct wlprivate_data, atf_irq_task);
	struct wlprivate *wlpptr = wlpd_p->masterwlp;
	struct net_device *netdev = wlpptr->netDev;
	u8 *mode = (u8 *) atf_dma_data;

	if (netdev == NULL) {
		printk("FAIL: netdev is NULL!\n");
		return;
	}

	switch (*mode) {
#ifdef AIRTIME_FAIRNESS_TRACES
	case ATF_DEBUG_TRACES:
		{
			atfTraces_t *atfTrace = (atfTraces_t *) atf_dma_data;
			printk(atfTrace->atf_trace_buffer);
			break;
		}
#endif // AIRTIME_FAIRNESS_TRACES

	case ATF_SEND_STATS:
		{
			atf_stats_t *atf_stats = (atf_stats_t *) atf_dma_data;

			if (atf_refresh_allowed) {
				spin_lock(&atf_refresh_lock);
				memcpy(atf_stats_shadow, atf_stats,
				       ATF_STATS_TRANSFER_SIZE(atf_stats->
							       txq_nr));
				spin_unlock(&atf_refresh_lock);
			} else {
				printk("%s: refresh not allowed!\n",
				       __FUNCTION__);
			}
			break;
		}

	default:
		// Not supported case
		printk("== ATF irq, Not supported case, mode: %d\n", *mode);
		break;
	}
	// unlock
	wlFwAtfTransfertDone(netdev);
}
