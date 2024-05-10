/** @file ap8xLnxMug.c
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2014-2020 NXP
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

#if defined(MRVL_MUG_ENABLE)

/** include files **/
#include <linux/debugfs.h>
#include <linux/pci.h>
#include <linux/sysfs.h>
#include <linux/netdevice.h>
#include "ap8xLnxRegs.h"
#include "ap8xLnxMug.h"
#include "ap8xLnxFwcmd.h"

//#define MUG_DEBUG(...)  printk(__VA_ARGS__)
#define MUG_DEBUG(...)

static ssize_t mug_sysfs_read(struct file *fp,
			      struct kobject *kobj,
			      struct bin_attribute *bin_attr,
			      char *buf, loff_t off, size_t count);
static ssize_t mug_sysfs_write(struct file *fp,
			       struct kobject *kobj,
			       struct bin_attribute *bin_attr,
			       char *buf, loff_t off, size_t count);

static const struct bin_attribute mug_fwinfo_sysfs_attr = {
	.attr = {
		 .name = "mug_fwinfo",
		 .mode = S_IRUGO,
		 },
	.read = mug_sysfs_read,
	.write = mug_sysfs_write,
};

static const struct bin_attribute mug_all_musets_sysfs_attr = {
	.attr = {
		 .name = "mug_all_musets",
		 .mode = S_IRUGO,
		 },
	.read = mug_sysfs_read,
	.write = mug_sysfs_write,
};

typedef enum __attribute__ ((packed)) {
U2D_CMD_DISABLE_UPDATES = 0, U2D_CMD_ENABLE_UPDATES = 1,} user2driver_cmd_t;

/******************************************************************************/

static ssize_t
mug_sysfs_write(struct file *fp,
		struct kobject *kobj,
		struct bin_attribute *bin_attr,
		char *buf, loff_t off, size_t count)
{
	struct device *dev = container_of(kobj, struct device, kobj);
	struct net_device *netdev = container_of(dev, struct net_device, dev);
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct mug_wlprivate_data *p_mug = &(wlpptr->wlpd_p->mug);
	user2driver_cmd_t cmd;

	(void)fp;
	(void)bin_attr;
	(void)off;

	MUG_DEBUG("%s off=%llu count=%u\n", __FUNCTION__, off, count);

	if (count < sizeof(user2driver_cmd_t)) {
		return 0;
	}

	memcpy(&cmd, buf, sizeof(cmd));

	spin_lock(&(p_mug->refresh_lock));

	switch (cmd) {
	case U2D_CMD_DISABLE_UPDATES:
		p_mug->refresh_allowed = false;
		break;
	case U2D_CMD_ENABLE_UPDATES:
		p_mug->refresh_allowed = true;
		break;

	default:
		printk("Unsupported user 2 driver command! \n");
		break;
	}

	spin_unlock(&(p_mug->refresh_lock));

	return count;
}

static ssize_t
mug_sysfs_read(struct file *fp,
	       struct kobject *kobj,
	       struct bin_attribute *bin_attr,
	       char *buf, loff_t off, size_t count)
{
	struct device *dev = container_of(kobj, struct device, kobj);
	struct net_device *netdev = container_of(dev, struct net_device, dev);
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct mug_wlprivate_data *p_mug = &(wlpptr->wlpd_p->mug);

	size_t max_data_size;
	uint8_t *src;

	MUG_DEBUG("%s p_mug=%p\n", __FUNCTION__, p_mug);

	if (bin_attr == &mug_fwinfo_sysfs_attr) {
		max_data_size = p_mug->p_fwinfo_shadow->hdr.size;
		src = (uint8_t *) p_mug->p_fwinfo_shadow;
		MUG_DEBUG("%s reading fwinfo size=%u \n",
			  __FUNCTION__, max_data_size);
	} else if (bin_attr == &mug_all_musets_sysfs_attr) {
		max_data_size = sizeof(mug_all_musets_t);
		src = (uint8_t *) p_mug->p_all_musets_shadow;
		MUG_DEBUG("%s reading all_musets size=%u \n",
			  __FUNCTION__, max_data_size);
	} else {
		printk("%s unknown bin attr \n", __FUNCTION__);
		return 0;
	}

	if (off > max_data_size) {
		off = max_data_size;
	}

	if (off + count >= max_data_size) {
		count = max_data_size - off;
	}

	memcpy(buf, &src[off], count);

	return count;
}

int
mug_setup_dma(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct mug_wlprivate_data *p_mug = &(wlpptr->wlpd_p->mug);
	const unsigned int size = MUG_FWINFO_FULL_SIZE;

	MUG_DEBUG("%s p_mug=%p\n", __FUNCTION__, p_mug);

	if (p_mug->dma_data != NULL) {
		// DMA already set up.
		return 0;
	}
#if 0
	if (p_mug->dma_data != NULL) {
		printk("mug dma data already allocated, need to free before\n");
		BUG_ON(in_interrupt());

		pci_free_consistent(wlpptr->pPciDev, p_mug->dma_data_size,
				    p_mug->dma_data, p_mug->dma_phys_data);
		p_mug->dma_data = NULL;
		p_mug->dma_phys_data = (dma_addr_t) NULL;
	}
#endif

	printk("Trying pci_alloc_consistent size=%u...", size);

	p_mug->dma_data =
		pci_alloc_consistent(wlpptr->pPciDev, size,
				     &p_mug->dma_phys_data);

	if (p_mug->dma_data == NULL) {
		printk("Failed!\n");
		return -1;
	}

	printk("OK cpu_addr=%p phys_addr=%p\n",
	       p_mug->dma_data, (void *)p_mug->dma_phys_data);

	p_mug->dma_data_size = size;

	printk("Setting FW DMA values...");
	if (wlFwSetMUDma(netdev, p_mug->dma_phys_data, size) != 0) {
		printk("Failed!\n");
		return -1;
	}

	printk("OK!\n");

	printk("Setting sysfs for mug_fwinfo...");
	if (sysfs_create_bin_file(&(netdev->dev.kobj), &mug_fwinfo_sysfs_attr)
	    != 0) {
		printk("Failed!\n");
		return -1;
	}
	printk("OK!\n");

	printk("Setting sysfs for mug_all_musets...");
	if (sysfs_create_bin_file
	    (&(netdev->dev.kobj), &mug_all_musets_sysfs_attr) != 0) {
		printk("Failed!\n");
		return -1;
	}
	printk("OK!\n");

	p_mug->p_fwinfo_shadow =
		(mug_fwinfo_t *) kmalloc(MUG_FWINFO_FULL_SIZE, GFP_KERNEL);
	if (p_mug->p_fwinfo_shadow == NULL) {
		printk("kmalloc for fwinfo shadow failed!\n");
		return -1;
	}
	memset(p_mug->p_fwinfo_shadow, 0, MUG_FWINFO_FULL_SIZE);

	p_mug->p_all_musets_shadow =
		(mug_all_musets_t *) kmalloc(sizeof(mug_all_musets_t),
					     GFP_KERNEL);
	if (p_mug->p_all_musets_shadow == NULL) {
		printk("kmalloc for all_musets shadow failed!\n");
		return -1;
	}
	memset(p_mug->p_all_musets_shadow, 0, sizeof(mug_all_musets_t));

	p_mug->refresh_allowed = TRUE;
	spin_lock_init(&p_mug->refresh_lock);

	return 0;
}

/**
 * IMPORTANT: Make sure caller to this function has locked MUSetflags
 */
void
mug_fill_active_musets(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct mug_wlprivate_data *p_mug = &(wlpptr->wlpd_p->mug);
	muset_t *p_muset_src;
	mug_muset_t *p_muset_dst;

	MUG_DEBUG("%s p_mug=%p\n", __FUNCTION__, p_mug);

	if (p_mug->p_all_musets_shadow == NULL) {
		return;
	}

	p_muset_src = (muset_t *) wlpptr->wlpd_p->MUSetList.tail;
	p_muset_dst = &(p_mug->p_all_musets_shadow->musets[0]);
	p_mug->p_all_musets_shadow->n_musets = wlpptr->wlpd_p->MUSetList.cnt;

	MUG_DEBUG("%s n_musets=%u\n",
		  __FUNCTION__, p_mug->p_all_musets_shadow->n_musets);

	while (p_muset_src != NULL) {
		p_muset_dst->index = p_muset_src->index;
		p_muset_dst->gid = p_muset_src->index + 1;
		p_muset_dst->staids[0] =
			(p_muset_src->StaInfo[0] !=
			 NULL) ? p_muset_src->StaInfo[0]->StnId : 0;
		p_muset_dst->staids[1] =
			(p_muset_src->StaInfo[1] !=
			 NULL) ? p_muset_src->StaInfo[1]->StnId : 0;
		p_muset_dst->staids[2] =
			(p_muset_src->StaInfo[2] !=
			 NULL) ? p_muset_src->StaInfo[2]->StnId : 0;

		strncpy(p_muset_dst->dev_name, p_muset_src->dev_name,
			sizeof(p_muset_dst->dev_name));

		p_muset_src = p_muset_src->prv;
		p_muset_dst++;
	}
}

void
mug_irq_task_handler(struct work_struct *work)
{
	struct mug_wlprivate_data *p_mug =
		container_of(work, struct mug_wlprivate_data, irq_task);
	mug_fwinfo_t *p_fwinfo = (mug_fwinfo_t *) p_mug->dma_data;
	struct timespec timer_start, timer_end;

	if (p_mug == NULL) {
		printk("FAIL: p_mug == NULL %s:%u\n", __FILE__, __LINE__);
		return;
	}

	if (p_mug->p_fwinfo_shadow == NULL) {
		return;
	}

	MUG_DEBUG("PCIe Host Interrupt MUG -- mug_fwinfo\n"
		  " --> size     = %u\n"
		  " --> n_user   = %u\n"
		  " --> n_compat = %u\n"
		  " --> n_group  = %u\n",
		  p_fwinfo->hdr.size,
		  p_fwinfo->n_user,
		  p_fwinfo->n_compat, p_fwinfo->group_info.n_group);

	spin_lock(&(p_mug->refresh_lock));

	if (p_mug->refresh_allowed) {
		getrawmonotonic(&timer_start);
		memcpy(p_mug->p_fwinfo_shadow, p_fwinfo, p_fwinfo->hdr.size);
		getrawmonotonic(&timer_end);
		MUG_DEBUG(">> refresh time: %ld\n",
			  timer_end.tv_nsec - timer_start.tv_nsec);
	} else {
		printk("%s: refresh not allowed!\n", __FUNCTION__);
	}

	spin_unlock(&(p_mug->refresh_lock));
}

int
mug_enable(struct net_device *netdev, int enable)
{
	if (enable && mug_setup_dma(netdev) != 0) {
		// Setup failed
		return -1;
	}

	printk("Setting FW MUG enable=%u...", enable);
	if (wlFwMUGEnable(netdev, enable) != 0) {
		printk("Failed!\n");
		return -1;
	}
	printk("OK!\n");

	return 0;
}

#endif /* #if defined(MRVL_MUG_ENABLE) */
