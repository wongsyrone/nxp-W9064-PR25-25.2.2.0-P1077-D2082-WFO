/** @file ap8xLnxMalloc.h
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2019-2020 NXP
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
#ifndef _AP8XLNXMALLOC_H
#define _AP8XLNXMALLOC_H

#include <linux/slab.h>
#include <linux/netdevice.h>

void *
kernel_alloc_skb(int len)
{
	return dev_alloc_skb(len);
}

void
kernel_free_skb(struct sk_buff *skb)
{
	dev_kfree_skb_any(skb);
}

void
kernel_receive_skb(struct sk_buff *skb)
{
	netif_receive_skb(skb);
}

void *
kernel_vzalloc(size_t size)
{
	return vzalloc(size);
}

void
kernel_vfree(const void *ptr)
{
	vfree(ptr);
}

void *
kernel_kmalloc(size_t size, gfp_t flags)
{
	return kmalloc(size, flags);
}

void *
kernel_kzalloc(size_t size, gfp_t flags)
{
	return kzalloc(size, flags);
}

void
kernel_kfree(const void *ptr)
{
	kfree(ptr);
}

void *
kernel_dma_alloc_coherent(struct device *dev, size_t size,
			  dma_addr_t * dma_handle, int flag)
{
	return dma_alloc_coherent(dev, size, dma_handle, flag);
}

void
kernel_dma_free_coherent(struct device *dev, size_t size, void *cpu_addr,
			 dma_addr_t dma_handle)
{
	dma_free_coherent(dev, size, cpu_addr, dma_handle);
}

#endif //_AP8XLNXMALLOC_H
