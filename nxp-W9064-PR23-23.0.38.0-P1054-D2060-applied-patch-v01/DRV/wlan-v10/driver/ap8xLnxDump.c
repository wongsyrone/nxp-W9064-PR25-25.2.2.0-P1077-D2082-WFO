/** @file ap8xLnxDump.c
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

/** include files **/
#ifdef AP8X_DUMP
#include <stdarg.h>
#include "wltypes.h"
#include "wl.h"
#include "IEEE_types.h"
#include "wl_mib.h"
#include "wl_hal.h"
#include "ap8xLnxApi.h"
#include "ap8xLnxFwcmd.h"
#include "ap8xLnxIntf.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#define WL_MAX_FILE_NAME_LEN 32
struct dev_dump {
	unsigned char filename[WL_MAX_FILE_NAME_LEN];
	struct net_device *netdev;
	struct proc_dir_entry *ap8x_dump_proc;
	unsigned char id;	//0: BB 1: RFA 2:RFB, 3:RFC, 4:RFD, 5:RFE, 6:RFF, 7:RFG, 8:RFH
};
#undef WL_MAX_FILE_NAME_LEN

#undef WL_MAXIMUM_CARDS
#define WL_MAXIMUM_CARDS MAX_CARDS_SUPPORT
extern struct proc_dir_entry *ap8x;
extern struct proc_dir_entry *proc_net;

struct register_map {
	unsigned char name[32];
	unsigned int base;
	unsigned int start;
	unsigned int end;
};

#define BB_SETS_SC 1
#ifdef SOC_W906X
#define RF_SETS_SC 48
struct register_map w9068_rf[RF_SETS_SC] = {
	{"RF Path A base", 0x0000, 0, 0xff},
	{"RF Path A xcvr pg 0", 0, 0x1000, 0x10ff},
	{"RF Path A xcvr pg 1", 0, 0x1100, 0x11ff},
	{"RF Path A xcvr pg 2", 0, 0x1200, 0x12ff},
	{"RF Path A xcvr pg 3", 0, 0x1300, 0x13ff},
	{"RF Path A xcvr pg 4", 0, 0x1400, 0x14ff},

	{"RF Path A base", 0x0000, 0, 0xff},
	{"RF Path B xcvr pg 0", 0, 0x3000, 0x30ff},
	{"RF Path B xcvr pg 1", 0, 0x3100, 0x31ff},
	{"RF Path B xcvr pg 2", 0, 0x3200, 0x32ff},
	{"RF Path B xcvr pg 3", 0, 0x3300, 0x33ff},
	{"RF Path B xcvr pg 4", 0, 0x3400, 0x34ff},

	{"RF Path A base", 0x0000, 0, 0xff},
	{"RF Path C xcvr pg 0", 0, 0x5000, 0x50ff},
	{"RF Path C xcvr pg 1", 0, 0x5100, 0x51ff},
	{"RF Path C xcvr pg 2", 0, 0x5200, 0x52ff},
	{"RF Path C xcvr pg 3", 0, 0x5300, 0x53ff},
	{"RF Path C xcvr pg 4", 0, 0x5400, 0x54ff},

	{"RF Path A base", 0x0000, 0, 0xff},
	{"RF Path D xcvr pg 0", 0, 0x7000, 0x70ff},
	{"RF Path D xcvr pg 1", 0, 0x7100, 0x71ff},
	{"RF Path D xcvr pg 2", 0, 0x7200, 0x72ff},
	{"RF Path D xcvr pg 3", 0, 0x7300, 0x73ff},
	{"RF Path D xcvr pg 4", 0, 0x7400, 0x74ff},

	{"RF Path E base", 0x8000, 0, 0xff},
	{"RF Path E xcvr pg 0", 0, 0x9000, 0x90ff},
	{"RF Path E xcvr pg 1", 0, 0x9100, 0x91ff},
	{"RF Path E xcvr pg 2", 0, 0x9200, 0x92ff},
	{"RF Path E xcvr pg 3", 0, 0x9300, 0x93ff},
	{"RF Path E xcvr pg 4", 0, 0x9400, 0x94ff},

	{"RF Path E base", 0x8000, 0, 0xff},
	{"RF Path F xcvr pg 0", 0, 0xb000, 0xb0ff},
	{"RF Path F xcvr pg 1", 0, 0xb100, 0xb1ff},
	{"RF Path F xcvr pg 2", 0, 0xb200, 0xb2ff},
	{"RF Path F xcvr pg 3", 0, 0xb300, 0xb3ff},
	{"RF Path F xcvr pg 4", 0, 0xb400, 0xb4ff},

	{"RF Path E base", 0x8000, 0, 0xff},
	{"RF Path G xcvr pg 0", 0, 0xd000, 0xd0ff},
	{"RF Path G xcvr pg 1", 0, 0xd100, 0xd1ff},
	{"RF Path G xcvr pg 2", 0, 0xd200, 0xd2ff},
	{"RF Path G xcvr pg 3", 0, 0xd300, 0xd3ff},
	{"RF Path G xcvr pg 4", 0, 0xd400, 0xd4ff},

	{"RF Path E base", 0x8000, 0, 0xff},
	{"RF Path H xcvr pg 0", 0, 0xf000, 0xf0ff},
	{"RF Path H xcvr pg 1", 0, 0xf100, 0xf1ff},
	{"RF Path H xcvr pg 2", 0, 0xf200, 0xf2ff},
	{"RF Path H xcvr pg 3", 0, 0xf300, 0xf3ff},
	{"RF Path H xcvr pg 4", 0, 0xf400, 0xf4ff},
};

struct register_map w9068_bb[BB_SETS_SC] = {
	{"BB", 0x000, 0, 0xee9},
};

#define RF_SETS RF_SETS_SC
#define BB_SETS BB_SETS_SC
#define TOTAL_SETS (RF_SETS / 6 + BB_SETS)
#define DUMP_BBP_FILE_NAME "%s_BBP"
#define DUMP_RFA_FILE_NAME "%s_RFA"
#define DUMP_RFB_FILE_NAME "%s_RFB"
#define DUMP_RFC_FILE_NAME "%s_RFC"
#define DUMP_RFD_FILE_NAME "%s_RFD"
#define DUMP_RFE_FILE_NAME "%s_RFE"
#define DUMP_RFF_FILE_NAME "%s_RFF"
#define DUMP_RFG_FILE_NAME "%s_RFG"
#define DUMP_RFH_FILE_NAME "%s_RFH"

struct register_map *rf = w9068_rf;
struct register_map *bb = w9068_bb;

#else
#define RF_SETS_SC4 20
struct register_map w8964_rf[RF_SETS_SC4] = {
	{"RF Path A base", 0xa00, 0, 0xff},
	{"RF Path A xcvr pg 1", 0, 0x1100, 0x11ff},
	{"RF Path A xcvr pg 2", 0, 0x2100, 0x21ff},
	{"RF Path A xcvr pg 3", 0, 0x3100, 0x31ff},
	{"RF Path A xcvr pg 4", 0, 0x4100, 0x41ff},
	{"RF Path B base", 0xb00, 0, 0xff},
	{"RF Path B xcvr pg 1", 0, 0x1200, 0x12ff},
	{"RF Path B xcvr pg 2", 0, 0x2200, 0x22ff},
	{"RF Path B xcvr pg 3", 0, 0x3200, 0x32ff},
	{"RF Path B xcvr pg 4", 0, 0x4200, 0x42ff},
	{"RF Path C base", 0xc00, 0, 0xff},
	{"RF Path C xcvr pg 1", 0, 0x1300, 0x13ff},
	{"RF Path C xcvr pg 2", 0, 0x2300, 0x23ff},
	{"RF Path C xcvr pg 3", 0, 0x3300, 0x33ff},
	{"RF Path C xcvr pg 4", 0, 0x4300, 0x43ff},
	{"RF Path D base", 0xd00, 0, 0xff},
	{"RF Path D xcvr pg 1", 0, 0x1400, 0x14ff},
	{"RF Path D xcvr pg 2", 0, 0x2400, 0x24ff},
	{"RF Path D xcvr pg 3", 0, 0x3400, 0x34ff},
	{"RF Path D xcvr pg 4", 0, 0x4400, 0x44ff},
};

struct register_map w8964_bb[BB_SETS_SC] = {
	{"BB", 0x000, 0, 0xee9},
};

#define RF_SETS RF_SETS_SC4
#define BB_SETS BB_SETS_SC
#define TOTAL_SETS (RF_SETS/5+BB_SETS)
#define DUMP_BBP_FILE_NAME "%s_BBP"
#define DUMP_RFA_FILE_NAME "%s_RFA"
#define DUMP_RFB_FILE_NAME "%s_RFB"
#define DUMP_RFC_FILE_NAME "%s_RFC"
#define DUMP_RFD_FILE_NAME "%s_RFD"

struct register_map *rf = w8964_rf;
struct register_map *bb = w8964_bb;
#endif /* #ifdef SOC_W906X */

static struct dev_dump devdump[WL_MAXIMUM_CARDS][TOTAL_SETS];

/**
 * This function is called at the beginning of a sequence.
 * ie, when:
 *	- the /proc file is read (first time)
 *	- after the function stop (end of sequence)
 *
 */
static void *
ap8x_dump_seq_start(struct seq_file *s, loff_t * pos)
{
	static unsigned long counter = 0;

	/* beginning a new sequence ? */
	if (*pos == 0) {
		/* yes => return a non null value to begin the sequence */
		return &counter;
	} else {
		/* no => it's the end of the sequence, return end to stop reading */
		*pos = 0;
		return NULL;
	}
}

/**
 * This function is called after the beginning of a sequence.
 * It's called untill the return is NULL (this ends the sequence).
 *
 */
static void *
ap8x_dump_seq_next(struct seq_file *s, void *v, loff_t * pos)
{
	unsigned long *tmp_v = (unsigned long *)v;

	(*tmp_v)++;
	(*pos)++;
	return NULL;
}

/**
 * This function is called at the end of a sequence
 *
 */
static void
ap8x_dump_seq_stop(struct seq_file *s, void *v)
{
	/* nothing to do, we use a static value in start() */
}

/**
 * This function is called for each "step" of a sequence
 *
 */
static int
ap8x_dump_seq_show(struct seq_file *s, void *v)
{
	//loff_t *spos = (loff_t *) v;
	struct dev_dump *dm_p = (struct dev_dump *)s->private;
	struct net_device *netdev = (struct net_device *)dm_p->netdev;
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	unsigned int i, val = 0, offset = 0, length = 0, offset_display;
	int j;
	MIB_PHY_DSSS_TABLE *PhyDSSSTable = mib->PhyDSSSTable;
	UINT8 *mib_rxAntenna_p = mib->mib_rxAntenna;
	UINT8 *mib_guardInterval_p = mib->mib_guardInterval;

	j = 0;
	seq_printf(s, "%s [%2d %2d %2d %2d]", netdev->name,
		   *mib_guardInterval_p, PhyDSSSTable->Chanflag.ChnlWidth,
		   PhyDSSSTable->Chanflag.ExtChnlOffset, *mib_rxAntenna_p);
	if (dm_p->id == 0) {
		for (j = 0; j < BB_SETS; j++) {
			//seq_printf(s, "\n%s\n",bb[j].name);
			seq_printf(s, "\n");
			offset = bb[j].base + bb[j].start;
			length = bb[j].end - bb[j].start + 1;
			offset_display = bb[j].start;
			for (i = 0; i < length; i++) {
				wlRegBB(netdev, WL_GET, offset + i, &val);
				if (i % 16 == 0) {
					seq_printf(s, "\n%04x:",
						   (int)(offset_display + i));
				}
				seq_printf(s, " %02x", (int)val);

			}
		}
	} else {
#ifdef SOC_W906X
		UINT16 start = 0, end = 0;
		if (dm_p->id == 2) {
			start = dm_p->id - 2;
			end = dm_p->id + 4;
		} else if (dm_p->id == 4) {
			start = dm_p->id + 2;
			end = dm_p->id + 8;
		} else if (dm_p->id == 6) {
			start = dm_p->id + 6;
			end = dm_p->id + 12;
		} else if (dm_p->id == 8) {
			start = dm_p->id + 10;
			end = dm_p->id + 16;
		} else if (dm_p->id == 10) {
			start = dm_p->id + 14;
			end = dm_p->id + 20;
		} else if (dm_p->id == 12) {
			start = dm_p->id + 18;
			end = dm_p->id + 24;
		} else if (dm_p->id == 14) {
			start = dm_p->id + 22;
			end = dm_p->id + 28;
		} else if (dm_p->id == 16) {
			start = dm_p->id + 26;
			end = dm_p->id + 32;
		}
#else
		UINT16 start = 0, end = 0;
		if (dm_p->id == 2) {
			start = dm_p->id - 2;
			end = dm_p->id + 3;
		} else if (dm_p->id == 4) {
			start = dm_p->id + 1;
			end = dm_p->id + 6;
		} else if (dm_p->id == 6) {
			start = dm_p->id + 4;
			end = dm_p->id + 9;
		} else if (dm_p->id == 8) {
			start = dm_p->id + 7;
			end = dm_p->id + 12;
		}
#endif /* #ifdef SOC_W906X */

		for (j = start; j < end; j++) {
			seq_printf(s, "\n\n%s", rf[j].name);
			//seq_printf(s, "\n");
			offset = rf[j].base + rf[j].start;
			length = rf[j].end - rf[j].start + 1;
			offset_display = rf[j].start;
			for (i = 0; i < length; i++) {
				wlRegRF(netdev, WL_GET, offset + i, &val);

				if (i % 16 == 0) {
					seq_printf(s, "\n%04x:",
						   (int)(offset_display + i));
				}
				seq_printf(s, " %02x", (int)val);
			}
			if (RF_SETS == 1)
				break;
		}
	}
	seq_printf(s, "\n");

	//seq_printf(s, "%Ld\n", *spos);
	return 0;
}

/**
 * This structure gather "function" to manage the sequence
 *
 */
static struct seq_operations ap8x_dump_seq_ops = {
	.start = ap8x_dump_seq_start,
	.next = ap8x_dump_seq_next,
	.stop = ap8x_dump_seq_stop,
	.show = ap8x_dump_seq_show
};

/**
 * This function is called when the /proc file is open.
 *
 */
static int
ap8x_dump_open(struct inode *inode, struct file *file)
{
	//return single_open(file, ap8x_dump_seq_show,NULL);
	int result;
	struct seq_file *s;

	result = seq_open(file, &ap8x_dump_seq_ops);
	s = (struct seq_file *)file->private_data;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
	s->private = PDE_DATA(inode);
#else
	s->private = PROC_I(inode)->pde->data;
#endif
	return result;
};

/**
 * This structure gather "function" that manage the /proc file
 *
 */
static struct file_operations ap8x_dump_file_ops = {
	.owner = THIS_MODULE,
	.open = ap8x_dump_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release
};

static int cardid = 0;
int
ap8x_dump_proc_register(struct net_device *dev)
{
	int i;

	if (cardid >= WL_MAXIMUM_CARDS) {
		printk("Error: more than %d cards not supported\n",
		       WL_MAXIMUM_CARDS);
		return 1;
	}
	if (ap8x == NULL) {
		ap8x = proc_mkdir("ap8x", proc_net);
		if (!ap8x)
			return 1;
	}
	for (i = 0; i < TOTAL_SETS; i++) {
		devdump[cardid][i].netdev = dev;
		switch (i) {
		case 0:
			sprintf(devdump[cardid][i].filename, DUMP_BBP_FILE_NAME,
				dev->name);
			break;
		case 1:
			sprintf(devdump[cardid][i].filename, DUMP_RFA_FILE_NAME,
				dev->name);
			break;
		case 2:
			sprintf(devdump[cardid][i].filename, DUMP_RFB_FILE_NAME,
				dev->name);
			break;
		case 3:
			sprintf(devdump[cardid][i].filename, DUMP_RFC_FILE_NAME,
				dev->name);
			break;
#ifdef SOC_W906X
		case 4:
			sprintf(devdump[cardid][i].filename, DUMP_RFD_FILE_NAME,
				dev->name);
			break;
		case 5:
			sprintf(devdump[cardid][i].filename, DUMP_RFE_FILE_NAME,
				dev->name);
			break;
		case 6:
			sprintf(devdump[cardid][i].filename, DUMP_RFF_FILE_NAME,
				dev->name);
			break;
		case 7:
			sprintf(devdump[cardid][i].filename, DUMP_RFG_FILE_NAME,
				dev->name);
			break;
		default:
			sprintf(devdump[cardid][i].filename, DUMP_RFH_FILE_NAME,
				dev->name);
			break;
#else
		default:
			sprintf(devdump[cardid][i].filename, DUMP_RFD_FILE_NAME,
				dev->name);
			break;
#endif /* #ifdef SOC_W906X */
		}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
		devdump[cardid][i].ap8x_dump_proc =
			proc_create_data(devdump[cardid][i].filename, 0666,
					 ap8x, &ap8x_dump_file_ops,
					 &devdump[cardid][i]);
		if (!devdump[cardid][i].ap8x_dump_proc) {
			printk("create_procfs_file %s failed\n",
			       devdump[cardid][i].filename);
			return 1;
		}
#else
		devdump[cardid][i].ap8x_dump_proc =
			create_proc_entry(devdump[cardid][i].filename, 0666,
					  ap8x);
		if (!devdump[cardid][i].ap8x_dump_proc) {
			printk("create_procfs_file %s failed\n",
			       devdump[cardid][i].filename);
			return 1;
		}

		devdump[cardid][i].ap8x_dump_proc->nlink = 1;
		devdump[cardid][i].ap8x_dump_proc->proc_fops =
			&ap8x_dump_file_ops;
		devdump[cardid][i].ap8x_dump_proc->data = &devdump[cardid][i];
#endif
		devdump[cardid][i].id = 2 * i;
	}
	cardid++;
	return 0;
}

int
ap8x_dump_proc_unregister(struct net_device *dev)
{
	int i, j;

	for (i = 0; i < WL_MAXIMUM_CARDS; i++) {
		if (devdump[i][0].netdev != dev)
			continue;

		for (j = 0; j < TOTAL_SETS; j++) {
			if (strlen(devdump[i][j].filename) > 0)
				remove_proc_entry(devdump[i][j].filename, ap8x);
		}
	}
	cardid--;
	return 0;
}
#endif
