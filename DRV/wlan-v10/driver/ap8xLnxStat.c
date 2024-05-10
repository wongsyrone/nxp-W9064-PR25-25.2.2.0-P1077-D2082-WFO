/** @file ap8xLnxStat.c
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
#if defined(SOC_W906X) || defined(AP8X_STATISTICS)
#include "ap8xLnxIntf.h"
#include <stdarg.h>
#include "ap8xLnxFwcmd.h"
#include "ap8xLnxRegs.h"
#include "ap8xLnxVer.h"
#include "ap8xLnxAcnt.h"
#include "mlmeApi.h"

#ifdef IEEE80211K
#include "msan_report.h"
#endif //IEEE80211K

#define WL_MAX_FILE_NAME_LEN 32
struct dev_stat {
	unsigned char filename[WL_MAX_FILE_NAME_LEN];
	struct net_device *netdev;
	struct proc_dir_entry *ap8x_proc;
};
#define WL_MAXIMUM_CARDS MAX_CARDS_SUPPORT
#define WL_MAXIMUM_INSTANCES (NUMOFAPS + 2) * WL_MAXIMUM_CARDS

#define WL_MUMODE_VERSION   1

static struct dev_stat devstat[WL_MAXIMUM_INSTANCES];
static int devstat_index = 0;
struct proc_dir_entry *ap8x = NULL;
struct proc_dir_entry *proc_net = NULL;

static UINT8 stat_info_level[16] = "all";

#ifdef SYSFS_STADB_INFO
#define MAX_VAP_NUM (NUMOFAPS * WL_MAXIMUM_CARDS)
#define MAX_MACFILENAME_LEN 17
#define	MAX(a,b) (((a)>(b))?(a):(b))
#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC2FILENAME(addr, file_name) sprintf(file_name, MACSTR, MAC2STR(addr))

struct clients_attribute {
	struct attribute attr;
	 ssize_t(*show) (struct kobject * kobj, struct clients_attribute * attr,
			 char *buf);
	 ssize_t(*store) (struct kobject * kobj,
			  struct clients_attribute * attr, char *buf);
};

struct clients_table_attribute {
	struct clients_attribute attr;
	UINT8 macAddr[IEEE80211_ADDR_LEN];
};

typedef enum {
	MODE_AP,
	MODE_VAP,
	MODE_STA,
	MODE_NUM
} clients_mode_e;

#define clients_mode_e UINT8

typedef enum {
	HDL_ADD,
	HDL_DEL,
	HDL_NUM
} clients_HDL_e;

#define clients_HDL_e UINT8

typedef enum {
	OPT_SUMMARY,
	OPT_RATETABLE,
	OPT_MU_MODE_INFO,
	OPT_RXRATE,
	OPT_NUM
} clients_query_options_e;

#define clients_query_options_e UINT8

struct clients_query_map {
	u8 *query_str;
	UINT8 query_opt;
};

static struct clients_query_map ap8xLnxStat_clients_query[] = {
	{"summary", OPT_SUMMARY},
	{"ratetable", OPT_RATETABLE},
	{"mu_mode_info", OPT_MU_MODE_INFO},
	{"rxrate", OPT_RXRATE},
};

struct clients_attribute_group {
	struct clients_attribute_group *next;
	struct attribute_group group;
	char name[MAX_MACFILENAME_LEN + 1];
};

struct clients_kobject {
	struct clients_kobject *next;
	struct kobject *kobj;
	struct clients_attribute_group *group_head;
	UINT16 conn_cnt;
};

struct clients_kobject_list {
	struct clients_kobject *head;
	UINT8 num;
};

struct clients_WQ_item {
	struct clients_WQ_item *nxt;
	struct clients_WQ_item *prv;
	IEEEtypes_MacAddr_t addr;
	vmacApInfo_t *vmac_p;
	UINT8 hdl;
};

static struct clients_kobject_list ap8xLnxStat_clients_kobjs = { NULL, 0 };
static struct clients_kobject_list ap8xLnxStat_clients_vap_kobjs = { NULL, 0 };

static UINT8 macAddr_query[IEEE80211_ADDR_LEN] =
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
static UINT8 option_query = OPT_NUM;
#endif /* SYSFS_STADB_INFO */

static UINT8 *_DeviceID_to_string(UINT16 id);
static UINT8 *_ChipRevision_to_string(UINT8 id);

#ifdef SYSFS_STADB_INFO
extern UINT16 getPhyRate(dbRateInfo_t * pRateTbl);
#ifdef MBSS
extern vmacApInfo_t *vmacGetMBssByAddr(vmacApInfo_t * vmacSta_p,
				       UINT8 * macAddr_p);
#endif
extern vmacEntry_t *sme_GetParentVMacEntry(UINT8 phyMacIndx);
extern BOOLEAN smeGetStaLinkInfo(vmacId_t mlme_vMacId, UINT8 * AssociatedFlag_p,
				 UINT8 * bssId_p);
#endif /* SYSFS_STADB_INFO */

extern long atohex2(const char *number);
void
clear_ap8x_stat(struct net_device *dev)
{
	struct net_device *netdev = dev;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct net_device_stats *stat = &(wlpptr->netDevStats);

	memset(stat, 0, sizeof(struct net_device_stats));
}

extern UINT32 dbg_level, dbg_class;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
static ssize_t
ap8x_proc_write(struct file *file, const char __user * buffer,
		size_t count, loff_t * data)
#else
int
ap8x_proc_write(struct file *file, const char *buffer,
		unsigned long count, void *data)
#endif
{
	if (buffer && !strncmp(buffer, "dbg_level=", strlen("dbg_level="))) {
		dbg_level = atohex2(&buffer[strlen("dbg_level=")]);
	} else if (buffer &&
		   !strncmp(buffer, "dbg_class=", strlen("dbg_class="))) {
		dbg_class = (atohex2(&buffer[strlen("dbg_class=")]) << 16);
	} else {
		int i;
		for (i = 0; i < WL_MAXIMUM_INSTANCES; i++) {
			if (devstat[i].netdev)
				clear_ap8x_stat(devstat[i].netdev);
		}
	}
	return count;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
static int
ap8x_stat_seq_show(struct seq_file *seq, void *p)
{
	struct dev_stat *dm_p = (struct dev_stat *)seq->private;
	struct net_device *netdev = (struct net_device *)dm_p->netdev;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct net_device_stats *stat = &(wlpptr->netDevStats);
	char *page = wl_kmalloc_autogfp(PAGE_SIZE);

	wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	stat = &(wlpptr->netDevStats);
	seq_printf(seq, "Driver dbg_level=%x, dbg_class=%x\n",
		   (unsigned int)dbg_level, (unsigned int)dbg_class);
	seq_printf(seq,
		   "\n====================================================\n");
	seq_printf(seq, "%s: rx statistics", netdev->name);
	seq_printf(seq, "\n-------------------------------\n");
	seq_printf(seq, "rx_packets.......................%10u\n",
		   (int)stat->rx_packets);
	seq_printf(seq, "rx_bytes.........................%10u\n",
		   (int)stat->rx_bytes);
	seq_printf(seq, "rx_errors........................%10u\n",
		   (int)stat->rx_errors);
	seq_printf(seq, "rx_dropped.......................%10u\n",
		   (int)stat->rx_dropped);
	seq_printf(seq, "multicast........................%10u\n",
		   (int)stat->multicast);
	seq_printf(seq, "rx_length_errors.................%10u\n",
		   (int)stat->rx_length_errors);
	seq_printf(seq, "rx_over_errors...................%10u\n",
		   (int)stat->rx_over_errors);
	seq_printf(seq, "rx_crc_errors....................%10u\n",
		   (int)stat->rx_crc_errors);
	seq_printf(seq, "rx_frame_errors..................%10u\n",
		   (int)stat->rx_frame_errors);
	seq_printf(seq, "rx_fifo_errors...................%10u\n",
		   (int)stat->rx_fifo_errors);
	seq_printf(seq, "rx_missed_errors.................%10u\n",
		   (int)stat->rx_missed_errors);
	seq_printf(seq, "rx_weakiv_count..................%10u\n",
		   (int)wlpptr->wlpd_p->privStats.weakiv_count);
	seq_printf(seq, "rx_multicast_bytes...............%10u\n",
		   (int)wlpptr->wlpd_p->privNdevStats.rx_mcast_bytes);
	seq_printf(seq, "rx_broadcast_bytes...............%10u\n",
		   (int)wlpptr->wlpd_p->privNdevStats.rx_bcast_bytes);

	seq_printf(seq,
		   "\n====================================================\n");
	seq_printf(seq, "%s: tx statistics", netdev->name);
	seq_printf(seq, "\n-------------------------------\n");
	seq_printf(seq, "tx_packets.......................%10u\n",
		   (int)stat->tx_packets);
	seq_printf(seq, "tx_bytes.........................%10u\n",
		   (int)stat->tx_bytes);
	seq_printf(seq, "tx_errors........................%10u\n",
		   (int)stat->tx_errors);
	seq_printf(seq, "tx_dropped.......................%10u\n",
		   (int)stat->tx_dropped);
	seq_printf(seq, "tx_aborted_errors................%10u\n",
		   (int)stat->tx_aborted_errors);
	seq_printf(seq, "tx_carrier_errors................%10u\n",
		   (int)stat->tx_carrier_errors);
	seq_printf(seq, "tx_fifo_errors...................%10u\n",
		   (int)stat->tx_fifo_errors);
	seq_printf(seq, "tx_heartbeat_errors..............%10u\n",
		   (int)stat->tx_heartbeat_errors);
	seq_printf(seq, "tx_window_errors.................%10u\n",
		   (int)stat->tx_window_errors);
	seq_printf(seq, "tx_headerroom_errors.............%10u\n",
		   (int)wlpptr->wlpd_p->privStats.skbheaderroomfailure);
	seq_printf(seq, "tx_tsoframe_counts...............%10u\n",
		   (int)wlpptr->wlpd_p->privStats.tsoframecount);
	seq_printf(seq, "tx_tcp_ack_drop_count............%10u\n",
		   (int)wlpptr->wlpd_p->privStats.tx_tcp_ack_drop_count);
	seq_printf(seq, "tx_multicast_bytes...............%10u\n",
		   (int)wlpptr->wlpd_p->privNdevStats.tx_mcast_bytes);
	seq_printf(seq, "tx_broadcast_bytes...............%10u\n",
		   (int)wlpptr->wlpd_p->privNdevStats.tx_bcast_bytes);

	seq_printf(seq,
		   "\n====================================================\n");
	seq_printf(seq, "%s(%s): statistics", "ap8xfw", netdev->name);
	seq_printf(seq, "\n-------------------------------\n");

	if (page) {
		if (wlFwGetHwStats(netdev, page) > PAGE_SIZE)
			BUG();

		seq_printf(seq, page);

		wl_kfree(page);
	} else {
		seq_printf(seq, "\nNo memory to store HW Stats!\n");
		printk(KERN_WARNING "\nNo memory to store HW Stats!\n");
	}

	return 0;
}

static int
ap8x_stat_open(struct inode *inode, struct file *file)
{
	return single_open(file, ap8x_stat_seq_show, PDE_DATA(inode));
}

static struct file_operations ap8x_proc_file_ops = {
	.owner = THIS_MODULE,
	.open = ap8x_stat_open,
	.read = seq_read,
	.write = ap8x_proc_write,
	.llseek = seq_lseek,
	.release = single_release
};
#else
static int
ap8x_proc_read(struct net_device *netdev, char *page, char **start, off_t off,
	       int count, int *eof, void *data)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct net_device_stats *stat = &(wlpptr->netDevStats);
	char *p = page;
	int len;
	{
		{
			wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
			stat = &(wlpptr->netDevStats);
			p += sprintf(p,
				     "\n====================================================\n");
			p += sprintf(p, "%s: rx statistics", netdev->name);
			p += sprintf(p, "\n-------------------------------\n");
			p += sprintf(p,
				     "rx_packets.......................%10u\n",
				     (int)stat->rx_packets);
			p += sprintf(p,
				     "rx_bytes.........................%10u\n",
				     (int)stat->rx_bytes);
			p += sprintf(p,
				     "rx_errors........................%10u\n",
				     (int)stat->rx_errors);
			p += sprintf(p,
				     "rx_dropped.......................%10u\n",
				     (int)stat->rx_dropped);
			p += sprintf(p,
				     "multicast........................%10u\n",
				     (int)stat->multicast);
			p += sprintf(p,
				     "rx_length_errors.................%10u\n",
				     (int)stat->rx_length_errors);
			p += sprintf(p,
				     "rx_over_errors...................%10u\n",
				     (int)stat->rx_over_errors);
			p += sprintf(p,
				     "rx_crc_errors....................%10u\n",
				     (int)stat->rx_crc_errors);
			p += sprintf(p,
				     "rx_frame_errors..................%10u\n",
				     (int)stat->rx_frame_errors);
			p += sprintf(p,
				     "rx_fifo_errors...................%10u\n",
				     (int)stat->rx_fifo_errors);
			p += sprintf(p,
				     "rx_missed_errors.................%10u\n",
				     (int)stat->rx_missed_errors);
			p += sprintf(p,
				     "rx_weakiv_count..................%10u\n",
				     (int)wlpptr->wlpd_p->privStats.
				     weakiv_count);
			p += sprintf(p,
				     "rx_multicast_bytes...............%10u\n",
				     (int)wlpptr->wlpd_p->privNdevStats.
				     rx_mcast_bytes);
			p += sprintf(p,
				     "rx_broadcast_bytes...............%10u\n",
				     (int)wlpptr->wlpd_p->privNdevStats.
				     rx_bcast_bytes)

				p +=
				sprintf(p,
					"\n====================================================\n");
			p += sprintf(p, "%s: tx statistics", netdev->name);
			p += sprintf(p, "\n-------------------------------\n");
			p += sprintf(p,
				     "tx_packets.......................%10u\n",
				     (int)stat->tx_packets);
			p += sprintf(p,
				     "tx_bytes.........................%10u\n",
				     (int)stat->tx_bytes);
			p += sprintf(p,
				     "tx_errors........................%10u\n",
				     (int)stat->tx_errors);
			p += sprintf(p,
				     "tx_dropped.......................%10u\n",
				     (int)stat->tx_dropped);
			p += sprintf(p,
				     "tx_aborted_errors................%10u\n",
				     (int)stat->tx_aborted_errors);
			p += sprintf(p,
				     "tx_carrier_errors................%10u\n",
				     (int)stat->tx_carrier_errors);
			p += sprintf(p,
				     "tx_fifo_errors...................%10u\n",
				     (int)stat->tx_fifo_errors);
			p += sprintf(p,
				     "tx_heartbeat_errors..............%10u\n",
				     (int)stat->tx_heartbeat_errors);
			p += sprintf(p,
				     "tx_window_errors.................%10u\n",
				     (int)stat->tx_window_errors);
			p += sprintf(p,
				     "tx_headerroom_errors.............%10u\n",
				     (int)wlpptr->wlpd_p->privStats.
				     skbheaderroomfailure);
			p += sprintf(p,
				     "tx_tsoframe_counts...............%10u\n",
				     (int)wlpptr->wlpd_p->privStats.
				     tsoframecount);
			p += sprintf(p,
				     "tx_tcp_ack_drop_count............%10u\n",
				     (int)wlpptr->wlpd_p->privStats.
				     tx_tcp_ack_drop_count);
			p += sprintf(p,
				     "tx_multicast_bytes...............%10u\n",
				     (int)wlpptr->wlpd_p->privNdevStats.
				     tx_mcast_bytes);
			p += sprintf(p,
				     "tx_broadcast_bytes...............%10u\n",
				     (int)wlpptr->wlpd_p->privNdevStats.
				     tx_bcast_bytes);

			p += sprintf(p,
				     "\n====================================================\n");
			p += sprintf(p, "%s(%s): statistics", "ap8xfw",
				     netdev->name);
			p += sprintf(p, "\n-------------------------------\n");
			p += wlFwGetHwStats(netdev, p);
		}
	}

	len = (p - page) - off;
	if (len < 0)
		len = 0;

	*eof = (len <= count) ? 1 : 0;
	*start = page + off;

	return len;
}

#define AP8X_STAT_PROC_FUN(index) \
	static int ap8x_proc_read ## index(char *page, char **start, off_t off, int count, int *eof, void *data){ \
		struct net_device *netdev = devstat[index].netdev; \
		return ap8x_proc_read(netdev, page, start, off, count, eof, data); \
	}

AP8X_STAT_PROC_FUN(0);
AP8X_STAT_PROC_FUN(1);
AP8X_STAT_PROC_FUN(2);
AP8X_STAT_PROC_FUN(3);
AP8X_STAT_PROC_FUN(4);
AP8X_STAT_PROC_FUN(5);
AP8X_STAT_PROC_FUN(6);
AP8X_STAT_PROC_FUN(7);
AP8X_STAT_PROC_FUN(8);
AP8X_STAT_PROC_FUN(9);
AP8X_STAT_PROC_FUN(10);
AP8X_STAT_PROC_FUN(11);
AP8X_STAT_PROC_FUN(12);
AP8X_STAT_PROC_FUN(13);
AP8X_STAT_PROC_FUN(14);
AP8X_STAT_PROC_FUN(15);
AP8X_STAT_PROC_FUN(16);
AP8X_STAT_PROC_FUN(17);
AP8X_STAT_PROC_FUN(18);
AP8X_STAT_PROC_FUN(19);
#endif

int
ap8x_stat_proc_register(struct net_device *dev)
{
#define WL_PROC(x) ap8x_proc_read ## x
#define WL_CASE(x) \
case x: \
	devstat[x].ap8x_proc->read_proc = WL_PROC( x); \
	break

	if (devstat_index >= (WL_MAXIMUM_INSTANCES)) {
		printk("Error: more than %d instances not supported\n",
		       WL_MAXIMUM_INSTANCES);
		return 1;
	}
	if (ap8x == NULL) {
		ap8x = proc_mkdir("ap8x", proc_net);
		if (!ap8x)
			return 1;
	}

	devstat[devstat_index].netdev = dev;

	sprintf(devstat[devstat_index].filename, "%s_stats", dev->name);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
	devstat[devstat_index].ap8x_proc =
		proc_create_data(devstat[devstat_index].filename, 0666, ap8x,
				 &ap8x_proc_file_ops, &devstat[devstat_index]);
#else
	devstat[devstat_index].ap8x_proc =
		create_proc_entry(devstat[devstat_index].filename, 0666, ap8x);

	if (!devstat[devstat_index].ap8x_proc) {
		printk("create_procfs_file %s failed\n",
		       devstat[devstat_index].filename);
		return 1;
	}

	switch (devstat_index) {
		WL_CASE(0);
		WL_CASE(1);
		WL_CASE(2);
		WL_CASE(3);
		WL_CASE(4);
		WL_CASE(5);
		WL_CASE(6);
		WL_CASE(7);
		WL_CASE(8);
		WL_CASE(9);
		WL_CASE(10);
		WL_CASE(11);
		WL_CASE(12);
		WL_CASE(13);
		WL_CASE(14);
		WL_CASE(15);
		WL_CASE(16);
		WL_CASE(17);
		WL_CASE(18);
		WL_CASE(19);
	default:
		break;
	}
	devstat[devstat_index].ap8x_proc->write_proc = ap8x_proc_write;
	devstat[devstat_index].ap8x_proc->nlink = 1;
#endif
	devstat_index++;
	return 0;
#undef WL_PROC
#undef WL_CASE
}

int
ap8x_stat_proc_unregister(struct net_device *dev)
{
	int i;

	for (i = 0; i < WL_MAXIMUM_INSTANCES; i++) {
		if (devstat[i].netdev == dev) {
			remove_proc_entry(devstat[i].filename, ap8x);
			devstat_index--;
			return 0;
		}
	}
	return 0;
}

int
ap8x_remove_folder(void)
{
	if (ap8x) {
		remove_proc_entry("ap8x", proc_net);
		ap8x = NULL;
		return 0;
	}
	return 1;
}

#undef WL_MAX_FILE_NAME_LEN
#undef WL_MAXIMUM_INSTANCES

#ifdef SOC_W906X
#ifdef TP_PROFILE
#include "wlprofile.h"

#define PR_ERR_CODE(_rc)        \
{                                                       \
        pr_err("%s: operation failed. probably wrong input (rc=%d)\n", __func__, _rc);  \
}

#define PR_INFO_CALLED          \
{                                                       \
        pr_info("%s is called\n", attr->attr.name);     \
}
static char if_name[IFNAMSIZ];
static ssize_t
ap8xLnxStat_tp_help(char *b)
{
	int o = 0;		/* buffer offset */
	int s = PAGE_SIZE;	/* buffer size */

	o += scnprintf(b + o, s - o, "\n");
	o += scnprintf(b + o, s - o,
		       "cat                                  tx_packets          - Print tx packets processed\n");
	o += scnprintf(b + o, s - o,
		       "cat                                  tx_bytes            - Print tx bytes processed\n");
	o += scnprintf(b + o, s - o,
		       "cat                                  tx_packets_rate     - Print tx packets rate\n");
	o += scnprintf(b + o, s - o,
		       "cat                                  tx_bytes_rate       - Print tx bytes rate\n");
	o += scnprintf(b + o, s - o,
		       "cat                                  rx_packets          - Print rx packets processed\n");
	o += scnprintf(b + o, s - o,
		       "cat                                  rx_bytes            - Print rx bytes  processed\n");
	o += scnprintf(b + o, s - o,
		       "cat                                  rx_packets_rate     - Print rx packets rate\n");
	o += scnprintf(b + o, s - o,
		       "cat                                  rx_bytes_rate       - Print rx bytes rate\n");
	o += scnprintf(b + o, s - o,
		       "cat                                  drop_point  - Print drop point info\n");
	o += scnprintf(b + o, s - o,
		       "echo [s] [d] [d]                           > tp_set      - Print Q registers\n");
	o += scnprintf(b + o, s - o, "\n");
	o += scnprintf(b + o, s - o,
		       "parameters:[s]if_name [d]tx drop point [d]tp_profile_mode");
	o += scnprintf(b + o, s - o, "\n");
	o += scnprintf(b + o, s - o,
		       "cat                                  tp_profile_mode      - Print tp profile mode\n");
	o += scnprintf(b + o, s - o, "\n");
	return o;
}

void
tp_profile_timer_func(unsigned long data)
{
	struct wlprivate *wlpptr = (struct wlprivate *)data;
	struct wlprivate_data *wlpd_p;

	if (wlpptr != NULL) {
		wlpd_p = wlpptr->wlpd_p;
		/* tx */
		wlpd_p->wl_tpprofile.tx.bytes_rate =
			wlpd_p->wl_tpprofile.tx.bytes -
			wlpd_p->wl_tpprofile.tx.bytes_last;
		wlpd_p->wl_tpprofile.tx.bytes_last =
			wlpd_p->wl_tpprofile.tx.bytes;

		wlpd_p->wl_tpprofile.tx.packets_rate =
			wlpd_p->wl_tpprofile.tx.packets -
			wlpd_p->wl_tpprofile.tx.packets_last;
		wlpd_p->wl_tpprofile.tx.packets_last =
			wlpd_p->wl_tpprofile.tx.packets;

		/* rx */
		wlpd_p->wl_tpprofile.rx.bytes_rate =
			wlpd_p->wl_tpprofile.rx.bytes -
			wlpd_p->wl_tpprofile.rx.bytes_last;
		wlpd_p->wl_tpprofile.rx.bytes_last =
			wlpd_p->wl_tpprofile.rx.bytes;

		wlpd_p->wl_tpprofile.rx.packets_rate =
			wlpd_p->wl_tpprofile.rx.packets -
			wlpd_p->wl_tpprofile.rx.packets_last;
		wlpd_p->wl_tpprofile.rx.packets_last =
			wlpd_p->wl_tpprofile.rx.packets;

		wlpd_p->tp_profile_timer.expires = jiffies + 1 * HZ;
		add_timer(&wlpd_p->tp_profile_timer);
	}
}

static void
ap8xLnxStat_sysfs_version_info(struct wlprivate *priv, char *sysfs_buff)
{
	extern void wlget_sw_version(struct wlprivate *priv, char *sysfs_buff,
				     int more);
	UINT8 *ver_buf;

	if (!priv || !sysfs_buff)
		return;

	ver_buf = wl_kmalloc(1024, GFP_KERNEL);
	if (!ver_buf) {
		return;
	}
	memset(ver_buf, 0, 1024);
	wlget_sw_version(priv, ver_buf, 0);
	Sysfs_Printk("%s\n", ver_buf);
	Sysfs_Printk("mu_ver: %d\n", WL_MUMODE_VERSION);
	wl_kfree(ver_buf);
}

static ssize_t
ap8xLnxStat_tp_show(struct device *dev,
		    struct device_attribute *attr, char *buf)
{
	const char *name = attr->attr.name;
	int off = 0;
	struct net_device *netdev;
	struct wlprivate *wlpptr;
	struct wlprivate_data *wlpd_p;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	if (!strcmp(name, "help")) {
		off = ap8xLnxStat_tp_help(buf);
		return off;
	}

	netdev = dev_get_by_name(&init_net, if_name);
	if (!netdev) {
		pr_err("%s: cannot find netdev by if_name:%s\n", __func__,
		       if_name);
		off = 1;
		return off;
	}
	wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	wlpd_p = wlpptr->wlpd_p;

	if (!strcmp(name, "tx_packets")) {
		off = sprintf(buf, "%lu\n", wlpd_p->wl_tpprofile.tx.packets);
	} else if (!strcmp(name, "tx_bytes")) {
		off = sprintf(buf, "%lu\n", wlpd_p->wl_tpprofile.tx.bytes);
	} else if (!strcmp(name, "drop_point")) {
		off = sprintf(buf, "%u\n", wlpd_p->wl_tpprofile.tp_point);
	} else if (!strcmp(name, "tp_profile_mode")) {
		off = sprintf(buf, "%u\n", wlpd_p->wl_tpprofile.mode);
	} else if (!strcmp(name, "tx_packets_rate")) {
		off = sprintf(buf, "%lu\n",
			      wlpd_p->wl_tpprofile.tx.packets_rate);
	} else if (!strcmp(name, "tx_bytes_rate")) {
		off = sprintf(buf, "%lu\n", wlpd_p->wl_tpprofile.tx.bytes_rate);
	} else if (!strcmp(name, "rx_packets")) {
		off = sprintf(buf, "%lu\n", wlpd_p->wl_tpprofile.rx.packets);
	} else if (!strcmp(name, "rx_bytes")) {
		off = sprintf(buf, "%lu\n", wlpd_p->wl_tpprofile.rx.bytes);
	} else if (!strcmp(name, "rx_packets_rate")) {
		off = sprintf(buf, "%lu\n",
			      wlpd_p->wl_tpprofile.rx.packets_rate);
	} else if (!strcmp(name, "rx_bytes_rate")) {
		off = sprintf(buf, "%lu\n", wlpd_p->wl_tpprofile.rx.bytes_rate);

	} else {
		off = 1;
		pr_err("%s: illegal operation <%s>\n", __func__,
		       attr->attr.name);
	}
	dev_put(netdev);
	return off;
}

#define STRINGIFY(x) STRINGIFY2(x)
#define STRINGIFY2(x) #x
static ssize_t
ap8xLnxStat_tp_config(struct device *dev,
		      struct device_attribute *attr, const char *buf,
		      size_t len)
{
	int a, b, c, d, e, err;

	unsigned long flags;
	struct net_device *netdev;
	struct wlprivate *wlpptr;
	struct wlprivate_data *wlpd_p;

	/* Read input parameters */
	err = a = b = c = d = e = 0;

	if (sscanf
	    (buf, "%" STRINGIFY(IFNAMSIZ) "s" "%d %d %d %d %d", if_name, &a, &b,
	     &c, &d, &e) <= 0) {
		err = 1;
		goto exit;
	}

	netdev = dev_get_by_name(&init_net, if_name);
	if (!netdev) {
		pr_err("%s: cannot find netdev by if_name:%s\n", __func__,
		       if_name);
		goto exit;
	}
	wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	wlpd_p = wlpptr->wlpd_p;

	local_irq_save(flags);
	wlpd_p->wl_tpprofile.tp_point = a;
	wlpd_p->wl_tpprofile.mode = b;
	local_irq_restore(flags);

	if (wlpd_p->wl_tpprofile.mode == 1) {
		if (!timer_pending(&wlpd_p->tp_profile_timer)) {
			wlpd_p->tp_profile_timer.expires = jiffies + 1 * HZ;
			wlpd_p->tp_profile_timer.data = (unsigned long)wlpptr;
			wlpd_p->tp_profile_timer.function =
				tp_profile_timer_func;
			add_timer(&wlpd_p->tp_profile_timer);
		}
	} else {
		del_timer(&wlpd_p->tp_profile_timer);
	}
	dev_put(netdev);

exit:
	return err ? -EINVAL : len;
}

static DEVICE_ATTR(help, S_IRUSR, ap8xLnxStat_tp_show, NULL);
static DEVICE_ATTR(drop_point, S_IRUSR, ap8xLnxStat_tp_show, NULL);
static DEVICE_ATTR(tp_set, S_IWUSR, NULL, ap8xLnxStat_tp_config);
static DEVICE_ATTR(tp_profile_mode, S_IRUSR, ap8xLnxStat_tp_show, NULL);
static DEVICE_ATTR(tx_packets, S_IRUSR, ap8xLnxStat_tp_show, NULL);
static DEVICE_ATTR(tx_bytes, S_IRUSR, ap8xLnxStat_tp_show, NULL);
static DEVICE_ATTR(tx_packets_rate, S_IRUSR, ap8xLnxStat_tp_show, NULL);
static DEVICE_ATTR(tx_bytes_rate, S_IRUSR, ap8xLnxStat_tp_show, NULL);
static DEVICE_ATTR(rx_packets, S_IRUSR, ap8xLnxStat_tp_show, NULL);
static DEVICE_ATTR(rx_bytes, S_IRUSR, ap8xLnxStat_tp_show, NULL);
static DEVICE_ATTR(rx_packets_rate, S_IRUSR, ap8xLnxStat_tp_show, NULL);
static DEVICE_ATTR(rx_bytes_rate, S_IRUSR, ap8xLnxStat_tp_show, NULL);

static struct attribute *ap8xLnxStat_tp_attrs[] = {
	&dev_attr_help.attr,
	&dev_attr_drop_point.attr,
	&dev_attr_tp_set.attr,
	&dev_attr_tp_profile_mode.attr,
	&dev_attr_tx_packets.attr,
	&dev_attr_tx_bytes.attr,
	&dev_attr_tx_packets_rate.attr,
	&dev_attr_tx_bytes_rate.attr,
	&dev_attr_rx_packets.attr,
	&dev_attr_rx_bytes.attr,
	&dev_attr_rx_packets_rate.attr,
	&dev_attr_rx_bytes_rate.attr,
	NULL
};

static struct attribute_group ap8xLnxStat_tp_group = {
	.attrs = ap8xLnxStat_tp_attrs,
};

static ssize_t
ap8xLnxStat_stat_show(struct kobject *kobj,
		      struct kobj_attribute *attr, char *buf)
{
	const UINT8 *name = attr->attr.name;
	SINT32 off = 0;
	struct kobject *parent_kobj = kobj->parent;
	struct device *dev = NULL;
	struct net_device *netdev;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	if (parent_kobj == NULL) {
		pr_err("Cannot find net device, kobject is null\n");
		return -EINVAL;
	}
	dev = kobj_to_dev(parent_kobj);
	if (dev == NULL) {
		pr_err("Cannot find net device, device is null\n");
		return -EINVAL;
	}
	netdev = to_net_dev(dev);
	if (dev == NULL) {
		pr_err("Cannot find net device, netdev is null\n");
		return -EINVAL;
	}

	if (!strcmp(name, "geninfo_stat")) {
		off = wl_show_stat_cmd(netdev, "geninfo", stat_info_level, buf);
	} else if (!strcmp(name, "warn_stat")) {
		off = wl_show_stat_cmd(netdev, "warn", stat_info_level, buf);
	} else if (!strcmp(name, "drvrxinfo_stat")) {
		off = wl_show_stat_cmd(netdev, "drvrxinfo", stat_info_level,
				       buf);
	} else if (!strcmp(name, "schinfo_stat")) {
		off = wl_show_stat_cmd(netdev, "schinfo", stat_info_level, buf);
	} else if (!strcmp(name, "tp_stat")) {
		off = wl_show_stat_cmd(netdev, "tp", stat_info_level, buf);
	} else if (!strcmp(name, "mac_stat")) {
		off = wl_show_stat_cmd(netdev, "mac", stat_info_level, buf);
	} else if (!strcmp(name, "hframe_stat")) {
		off = wl_show_stat_cmd(netdev, "hframe", stat_info_level, buf);
	} else if (!strcmp(name, "pktcnt_stat")) {
		off = wl_show_stat_cmd(netdev, "pktcnt", stat_info_level, buf);
	} else if (!strcmp(name, "dra_stat")) {
		off = wl_show_stat_cmd(netdev, "dra_stat", stat_info_level,
				       buf);
	} else if (!strcmp(name, "bareorder_stat")) {
		off = wl_show_stat_cmd(netdev, "bareorder", stat_info_level,
				       buf);
	} else {
		pr_err("%s: illegal operation <%s>\n", __func__,
		       attr->attr.name);
		return -EINVAL;
	}
	return strlen(buf);
}

static ssize_t
ap8xLnxStat_stat_store(struct kobject *kobj, struct kobj_attribute *attr,
		       const char *buf, size_t count)
{
	/* Read input parameters */
	if (sscanf(buf, "%" STRINGIFY(16) "s", stat_info_level) <= 0) {
		return -EINVAL;
	}

	return count;
}

#define SYSFS_ATTR(_name, _mode, _show, _store) \
	struct kobj_attribute dev_attr_##_name = __ATTR(_name, _mode, _show, _store)

/***** For radio stat info Start *****/
static SYSFS_ATTR(geninfo_stat, S_IRUSR | S_IWUSR, ap8xLnxStat_stat_show,
		  ap8xLnxStat_stat_store);
static SYSFS_ATTR(warn_stat, S_IRUSR | S_IWUSR, ap8xLnxStat_stat_show,
		  ap8xLnxStat_stat_store);
static SYSFS_ATTR(drvrxinfo_stat, S_IRUSR | S_IWUSR, ap8xLnxStat_stat_show,
		  ap8xLnxStat_stat_store);
static SYSFS_ATTR(schinfo_stat, S_IRUSR | S_IWUSR, ap8xLnxStat_stat_show,
		  ap8xLnxStat_stat_store);
static SYSFS_ATTR(tp_stat, S_IRUSR | S_IWUSR, ap8xLnxStat_stat_show,
		  ap8xLnxStat_stat_store);
static SYSFS_ATTR(mac_stat, S_IRUSR | S_IWUSR, ap8xLnxStat_stat_show,
		  ap8xLnxStat_stat_store);
static SYSFS_ATTR(hframe_stat, S_IRUSR | S_IWUSR, ap8xLnxStat_stat_show,
		  ap8xLnxStat_stat_store);
static SYSFS_ATTR(pktcnt_stat, S_IRUSR | S_IWUSR, ap8xLnxStat_stat_show,
		  ap8xLnxStat_stat_store);
static SYSFS_ATTR(dra_stat, S_IRUSR | S_IWUSR, ap8xLnxStat_stat_show,
		  ap8xLnxStat_stat_store);

static struct attribute *ap8xLnxStat_stat_attrs[] = {
	&dev_attr_geninfo_stat.attr,
	&dev_attr_warn_stat.attr,
	&dev_attr_drvrxinfo_stat.attr,
	&dev_attr_schinfo_stat.attr,
	&dev_attr_tp_stat.attr,
	&dev_attr_mac_stat.attr,
	&dev_attr_hframe_stat.attr,
	&dev_attr_pktcnt_stat.attr,
	&dev_attr_dra_stat.attr,
	NULL
};

static struct attribute_group ap8xLnxStat_stat_group = {
	.attrs = ap8xLnxStat_stat_attrs,
};

/***** For radio stat info End *****/

static SYSFS_ATTR(bareorder_stat, S_IRUSR | S_IWUSR, ap8xLnxStat_stat_show,
		  ap8xLnxStat_stat_store);

static struct attribute *ap8xLnxStat_vap_stat_attrs[] = {
	&dev_attr_bareorder_stat.attr,
	NULL
};

static struct attribute_group ap8xLnxStat_vap_stat_group = {
	.attrs = ap8xLnxStat_vap_stat_attrs,
};

/***** For radio hw info Start *****/
static ssize_t
ap8xLnxStat_hw_show(struct kobject *kobj,
		    struct kobj_attribute *attr, char *buf)
{
	struct kobject *parent_kobj = kobj->parent;
	struct device *dev = NULL;
	struct net_device *netdev;
	UINT8 *sysfs_buff = buf;
	struct resource *res[2];
	struct wlprivate *wlpptr;
	UINT32 val;
	UINT32 bw;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	if (parent_kobj == NULL) {
		pr_err("Cannot find net device, kobject is null\n");
		return -EINVAL;
	}

	dev = kobj_to_dev(parent_kobj);
	if (dev == NULL) {
		pr_err("Cannot find net device, device is null\n");
		return -EINVAL;
	}
	netdev = to_net_dev(dev);
	if (dev == NULL) {
		pr_err("Cannot find net device, netdev is null\n");
		return -EINVAL;
	}
	wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);

	Sysfs_Printk("\n======== [%s hw info] ========\n", netdev->name);
	/* Memor mapped I/O address space */
	ap8xLnxStat_sysfs_version_info(wlpptr, buf);
	if (IS_BUS_TYPE_MCI(wlpptr)) {
		res[0] = platform_get_resource(wlpptr->wlpd_p->pDev,
					       IORESOURCE_MEM, 0);
		res[1] = platform_get_resource(wlpptr->wlpd_p->pDev,
					       IORESOURCE_MEM, 1);
		res[0]->end += 0x100000;
		if (res[0]->end >= res[1]->start) {
			res[0]->end = res[1]->start - 1;
		}
	} else {
		res[0] = &wlpptr->wlpd_p->pPciDev->resource[0];
		res[1] = &wlpptr->wlpd_p->pPciDev->resource[2];
	}
	Sysfs_Printk("IoBase0 = v:%p p:(start:%llxh, end:%llxh)\n",
		     wlpptr->ioBase0, res[0]->start, res[0]->end);
	Sysfs_Printk("IoBase1 = v:%p p:(start:%llxh, end:%llxh)\n",
		     wlpptr->ioBase1, res[1]->start, res[1]->end);

	if (IS_BUS_TYPE_MCI(wlpptr))
		Sysfs_Printk("ioBaseExt:%p\n", wlpptr->ioBaseExt);

	Sysfs_Printk("cardindex:%u\n", wlpptr->cardindex);

	val = cpu_to_le32(*(volatile unsigned int *)
			  (wlpptr->ioBase1 + SC5_REG_SMAC_CTRLBASE));
	Sysfs_Printk("smac ctrlBase(0x%x)=%xh\n", SC5_REG_SMAC_CTRLBASE, val);
	Sysfs_Printk("Device:%s \nRevision:%s\n",
		     _DeviceID_to_string(wlpptr->devid),
		     _ChipRevision_to_string(wlpptr->hwData.chipRevision));
	Sysfs_Printk("intr_shift=%u \nmsix_num=%u\n",
		     wlpptr->wlpd_p->intr_shift, wlpptr->wlpd_p->msix_num);
	Sysfs_Printk("hframe base addr = %llxh\n",
		     (long long unsigned int)wlpptr->hframe_phy_addr);
	Sysfs_Printk("smac_ctrlbase_nss_hi_val_intr = %xh\n",
		     wlpptr->wlpd_p->reg.smac_ctrlbase_nss_hi_val_intr);
	Sysfs_Printk("frm_base = %xh\n", wlpptr->wlpd_p->sysintr_frm.frm_base);
	Sysfs_Printk("spi_num = %xh\n", wlpptr->wlpd_p->sysintr_frm.spi_num);
	Sysfs_Printk("SSU pSsuBuf = %p  pPhysSsuBuf = %pad size=0x%08x\n",
		     wlpptr->pSsuBuf, &wlpptr->wlpd_p->pPhysSsuBuf,
		     wlpptr->ssuSize);
#ifdef DSP_COMMAND
	Sysfs_Printk("DSP pDspBuf = %p  pPhysDspBuf = %pad size=0x%08x\n",
		     wlpptr->pDspBuf, &wlpptr->wlpd_p->pPhysDspBuf,
		     wlpptr->dspSize);
#endif
	Sysfs_Printk("wlpptr->pCmdBuf = %p  wlpptr->wlpd_p->pPhysCmdBuf = %x\n",
		     wlpptr->pCmdBuf, (u32) wlpptr->wlpd_p->pPhysCmdBuf);
	Sysfs_Printk("set qIntOffset = %xh\n", wlpptr->smacconfig.qIntOffset);
	Sysfs_Printk("MAC_CONFIG_st->magic = %xh\n", wlpptr->smacconfig.magic);
	Sysfs_Printk("MAC_STATUS_st->verCtrl[3] = %xh\n",
		     wlpptr->smacStatusAddr->verCtrl[3]);
	Sysfs_Printk("smac_base (v,p)=(%p, %xh)\n", wlpptr->smac_base_vp,
		     wlpptr->smacconfig.smacBmBaseAddr);
	Sysfs_Printk("rxSBinfoBaseAddr_v=%p, addr=%xh, UnitSize=%u, %lu\n",
		     wlpptr->rxSBinfoBaseAddr_v,
		     wlpptr->smacStatusAddr->rxSBinfoBaseAddr,
		     wlpptr->smacStatusAddr->rxSBinfoUnitSize,
		     (unsigned long)sizeof(RxSidebandInfo_t));
#if 0
	/* FW version foramt is changed, below version need remap, temporary disbaled */
	Sysfs_Printk("Major Version : %d\n",
		     wlpptr->wlpd_p->coredump.version_major);
	Sysfs_Printk("Minor Version : %d\n",
		     wlpptr->wlpd_p->coredump.version_minor);
	Sysfs_Printk("Patch Version : %d\n",
		     wlpptr->wlpd_p->coredump.version_patch);
#endif
	Sysfs_Printk("Num of Regions: %d\n",
		     wlpptr->wlpd_p->coredump.num_regions);
	Sysfs_Printk("Num of Symbols: %d\n",
		     wlpptr->wlpd_p->coredump.num_symbols);
	for (val = 0; val < wlpptr->wlpd_p->coredump.num_regions; val++) {
		Sysfs_Printk
			("region[%2d].address = 0x%10x, region[%2d].length = 0x%10x\n",
			 val, wlpptr->wlpd_p->coredump.region[val].address, val,
			 wlpptr->wlpd_p->coredump.region[val].length);
	}
	Sysfs_Printk("region code is %i (0x%x), HW version is %i (0x%x)",
		     wlpptr->hwData.regionCode, wlpptr->hwData.regionCode,
		     wlpptr->hwData.hwVersion, wlpptr->hwData.hwVersion);
	Sysfs_Printk("wlpptr->hwData.ulShalVersion:%04x\n",
		     wlpptr->hwData.ulShalVersion);
	Sysfs_Printk("Mac address = %s \n",
		     mac_display(&wlpptr->hwData.macAddr[0]));

	Sysfs_Printk("%s rsvd mem: pbuf=%llx vbuf=%p size=%llx\n",
		     wlpptr->wlpd_p->ext_membuf[0].extsym_name,
		     wlpptr->wlpd_p->ext_membuf[0].pbuf_pool,
		     wlpptr->wlpd_p->ext_membuf[0].vbuf_pool,
		     (u64) wlpptr->wlpd_p->ext_membuf[0].buf_pool_size);
	Sysfs_Printk("%s rsvd mem: pbuf=%llx vbuf=%p size=%llx\n",
		     wlpptr->wlpd_p->ext_membuf[1].extsym_name,
		     wlpptr->wlpd_p->ext_membuf[1].pbuf_pool,
		     wlpptr->wlpd_p->ext_membuf[1].vbuf_pool,
		     (u64) wlpptr->wlpd_p->ext_membuf[1].buf_pool_size);

	/* convert channel bw format as htbw cmd */
	switch (wlpptr->vmacSta_p->ShadowMib802dot11->PhyDSSSTable->Chanflag.
		ChnlWidth) {
	case CH_AUTO_WIDTH:
		bw = 0;
		break;
	case CH_10_MHz_WIDTH:
		bw = 1;
		break;
	case CH_20_MHz_WIDTH:
		bw = 2;
		break;
	case CH_40_MHz_WIDTH:
		bw = 3;
		break;
	case CH_80_MHz_WIDTH:
		bw = 4;
		break;
	case CH_160_MHz_WIDTH:
		bw = 5;
		break;
	case CH_5_MHz_WIDTH:
		bw = 8;
		break;
	default:
		bw = 0xff;
		break;
	}

	Sysfs_Printk("BW: %u\n", bw);

	return strlen(buf);
}

static ssize_t
ap8xLnxStat_hw_store(struct kobject *kobj, struct kobj_attribute *attr,
		     const char *buf, size_t count)
{
	return count;
}

static SYSFS_ATTR(hw_info, S_IRUSR | S_IWUSR, ap8xLnxStat_hw_show,
		  ap8xLnxStat_hw_store);

static struct attribute *ap8xLnxStat_hw_attrs[] = {
	&dev_attr_hw_info.attr,
	NULL
};

static struct attribute_group ap8xLnxStat_hw_group = {
	.attrs = ap8xLnxStat_hw_attrs,
};

/***** For radio hw info End *****/

#ifdef MEMORY_USAGE_TRACE
/***** For radio mem info Start *****/
extern SINT32 WL_memfree;
extern mem_trace_func MemTraceFunc[WL_MEM_TRACE_FUNC_NUM];
extern SINT32 MT_Skb_max;
extern SINT32 MT_Vzalloc_max;
extern SINT32 MT_Kmalloc_max;
extern SINT32 MT_Dmaalloc_max;

static UINT8 mem_dbg_level = 0;
/* rx buffer */
#define MEM_DBG_WLRXBUFINIT  "wlRxBufInit"
#define MEM_DBG_WLRXBUFFILL  "_wlRxBufFill"
#define MEM_DBG_DBGSKB_INIT  "dbgskb_init"
/* data base */
#define MEM_DBG_EXTSTADB_INIT  "extStaDb_Init"
#define MEM_DBG_ETHSTADB_INIT  "ethStaDb_Init"
/* Health Monitor */
#define MEM_DBG_WLMON_KTHREAD  "wlmon_kthread"

extern mem_trace_db *MemTraceSkbDb;

static ssize_t
ap8xLnxStat_mem_show(struct kobject *kobj,
		     struct kobj_attribute *attr, char *buf)
{
	struct kobject *parent_kobj = kobj->parent;
	struct device *dev = NULL;
	struct net_device *netdev;
	UINT8 *sysfs_buff = buf;
	SINT32 i = 0, t_skb_size, t_vz_size, t_km_size, t_dma_size, free_size;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	if (parent_kobj == NULL) {
		pr_err("Cannot find net device, kobject is null\n");
		return -EINVAL;
	}

	dev = kobj_to_dev(parent_kobj);
	if (dev == NULL) {
		pr_err("Cannot find net device, device is null\n");
		return -EINVAL;
	}
	netdev = to_net_dev(dev);
	if (dev == NULL) {
		pr_err("Cannot find net device, netdev is null\n");
		return -EINVAL;
	}
#if 1
	{
		mem_trace_db *temp_skb_db = MemTraceSkbDb;
		Sysfs_Printk("temp_skb_db space:\n");
		for (; temp_skb_db != NULL; temp_skb_db = temp_skb_db->next) {
			Sysfs_Printk("  %d", temp_skb_db->ispace);
		}
		Sysfs_Printk("\n");
	}
#endif

	if (mem_dbg_level == 0) {
		SINT32 rx_buf_size, stadb_size, hmon_size, sys_size;

		rx_buf_size = 0;
		stadb_size = 0;
		hmon_size = 0;
		sys_size = 0;
		t_vz_size = 0;
		t_dma_size = 0;
		Sysfs_Printk("\n============ [Memory info] ============\n");
		for (i = 0; i < WL_MEM_TRACE_FUNC_NUM; i++) {
			if (MemTraceFunc[i].type == MEM_SKB ||
			    MemTraceFunc[i].type == MEM_KMALLOC) {
				if (!strcmp
				    (MemTraceFunc[i].func, MEM_DBG_WLRXBUFINIT)
				    || !strcmp(MemTraceFunc[i].func,
					       MEM_DBG_WLRXBUFFILL) ||
				    !strcmp(MemTraceFunc[i].func,
					    MEM_DBG_DBGSKB_INIT)) {
					/* rx buffer */
					rx_buf_size += MemTraceFunc[i].size;
				} else if (!strcmp
					   (MemTraceFunc[i].func,
					    MEM_DBG_EXTSTADB_INIT) ||
					   !strcmp(MemTraceFunc[i].func,
						   MEM_DBG_ETHSTADB_INIT)) {
					/* data base */
					stadb_size += MemTraceFunc[i].size;
				} else if (!strcmp
					   (MemTraceFunc[i].func,
					    MEM_DBG_WLMON_KTHREAD)) {
					/* Health Monitor */
					hmon_size += MemTraceFunc[i].size;
				} else {
					/* System allocate */
					sys_size += MemTraceFunc[i].size;
				}
			} else if (MemTraceFunc[i].type == MEM_VZALLOC) {
				t_vz_size += MemTraceFunc[i].size;
			} else if (MemTraceFunc[i].type == MEM_DMAALLOC) {
				t_dma_size += MemTraceFunc[i].size;
			}
		}
		Sysfs_Printk("Driver Probe Size     :%6d KB\n",
			     t_vz_size / 1024);
		Sysfs_Printk("RX Buffer Size        :%6d KB\n",
			     rx_buf_size / 1024);
		Sysfs_Printk("Data Base Size        :%6d KB\n",
			     stadb_size / 1024);
		Sysfs_Printk("Health Monitor Size   :%6d KB\n",
			     hmon_size / 1024);
		Sysfs_Printk("System Size           :%6d KB\n",
			     sys_size / 1024);
		Sysfs_Printk("DMA Size              :%6d KB\n",
			     t_dma_size / 1024);
		Sysfs_Printk("======== Total Size :%6d KB ========\n",
			     (t_vz_size + rx_buf_size + stadb_size + hmon_size +
			      sys_size + t_dma_size) / 1024);
		free_size = wl_get_meminfo_stat();
		Sysfs_Printk
			("Actual usage:%6d KB (/proc/meminfo MemFree:%d KB - %d KB)\n",
			 (WL_memfree - free_size), WL_memfree, free_size);
	} else {
		Sysfs_Printk("\n======== [Memory skb info] ========\n");
		t_skb_size = 0;
		for (i = 0; i < WL_MEM_TRACE_FUNC_NUM; i++) {
			if (MemTraceFunc[i].size != 0 &&
			    MemTraceFunc[i].type == MEM_SKB) {
				Sysfs_Printk("%s \tline:%d \tsize:%d\n",
					     MemTraceFunc[i].func,
					     MemTraceFunc[i].line,
					     MemTraceFunc[i].size);
				t_skb_size += MemTraceFunc[i].size;
			}
		}
		Sysfs_Printk("total SKB usage size:%d KBytes\n",
			     t_skb_size / 1024);
		Sysfs_Printk("Max SKB alloc times:%d\n", MT_Skb_max);

		Sysfs_Printk("\n======== [Memory vzalloc info] ========\n");
		t_vz_size = 0;
		for (i = 0; i < WL_MEM_TRACE_FUNC_NUM; i++) {
			if (MemTraceFunc[i].size != 0 &&
			    MemTraceFunc[i].type == MEM_VZALLOC) {
				Sysfs_Printk("%s \tline:%d \tsize:%d\n",
					     MemTraceFunc[i].func,
					     MemTraceFunc[i].line,
					     MemTraceFunc[i].size);
				t_vz_size += MemTraceFunc[i].size;
			}
		}
		Sysfs_Printk("total vzalloc usage size:%d KBytes\n",
			     t_vz_size / 1024);
		Sysfs_Printk("Max vzalloc times:%d\n", MT_Vzalloc_max);

		Sysfs_Printk("\n======== [Memory kmalloc info] ========\n");
		t_km_size = 0;
		for (i = 0; i < WL_MEM_TRACE_FUNC_NUM; i++) {
			if (MemTraceFunc[i].size != 0 &&
			    MemTraceFunc[i].type == MEM_KMALLOC) {
				Sysfs_Printk("%s \tline:%d \tsize:%d\n",
					     MemTraceFunc[i].func,
					     MemTraceFunc[i].line,
					     MemTraceFunc[i].size);
				t_km_size += MemTraceFunc[i].size;
			}
		}
		Sysfs_Printk("total kmalloc usage size:%d KBytes\n",
			     t_km_size / 1024);
		Sysfs_Printk("Max kmalloc times:%d\n", MT_Kmalloc_max);

		Sysfs_Printk
			("\n======== [Memory dma_alloc_coherent info] ========\n");
		t_dma_size = 0;
		for (i = 0; i < WL_MEM_TRACE_FUNC_NUM; i++) {
			if (MemTraceFunc[i].size != 0 &&
			    MemTraceFunc[i].type == MEM_DMAALLOC) {
				Sysfs_Printk("%s \tline:%d \tsize:%d\n",
					     MemTraceFunc[i].func,
					     MemTraceFunc[i].line,
					     MemTraceFunc[i].size);
				t_dma_size += MemTraceFunc[i].size;
			}
		}
		Sysfs_Printk("total dma_alloc_coherent usage size:%d KBytes\n",
			     t_dma_size / 1024);
		Sysfs_Printk("Max dma_alloc_coherent times:%d\n",
			     MT_Dmaalloc_max);

		Sysfs_Printk("\n======== [Total mem info] ========\n");
		Sysfs_Printk("total alloc size:%d KBytes\n",
			     (t_skb_size + t_vz_size + t_km_size +
			      t_dma_size) / 1024);
		free_size = wl_get_meminfo_stat();
		Sysfs_Printk
			("Actual usage:%6d KB (/proc/meminfo MemFree:%d KB - %d KB)\n",
			 (WL_memfree - free_size), WL_memfree, free_size);
	}
	return strlen(buf);
}

static ssize_t
ap8xLnxStat_mem_store(struct kobject *kobj, struct kobj_attribute *attr,
		      const char *buf, size_t count)
{
	mem_dbg_level = simple_strtol(buf, NULL, 10);
	return count;
}

static SYSFS_ATTR(mem_info, S_IRUSR | S_IWUSR, ap8xLnxStat_mem_show,
		  ap8xLnxStat_mem_store);

static struct attribute *ap8xLnxStat_mem_attrs[] = {
	&dev_attr_mem_info.attr,
	NULL
};

static struct attribute_group ap8xLnxStat_mem_group = {
	.attrs = ap8xLnxStat_mem_attrs,
};

/***** For radio mem info End *****/
#endif /* MEMORY_USAGE_TRACE */

#ifdef AUTOCHANNEL
/***** For radio acs info Start *****/
static ssize_t
ap8xLnxStat_acs_show(struct kobject *kobj,
		     struct kobj_attribute *attr, char *buf)
{
	struct kobject *parent_kobj = kobj->parent;
	struct device *dev = NULL;
	struct net_device *netdev;
	UINT8 *sysfs_buff = buf;
	struct wlprivate *wlpptr;
	vmacApInfo_t *vmacSta_p = NULL;
	MIB_802DOT11 *mib;
	UINT32 i;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	if (parent_kobj == NULL) {
		pr_err("Cannot find net device, kobject is null\n");
		return -EINVAL;
	}

	dev = kobj_to_dev(parent_kobj);
	if (dev == NULL) {
		pr_err("Cannot find net device, device is null\n");
		return -EINVAL;
	}
	netdev = to_net_dev(dev);
	if (dev == NULL) {
		pr_err("Cannot find net device, netdev is null\n");
		return -EINVAL;
	}
	wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacSta_p = wlpptr->vmacSta_p;
	mib = vmacSta_p->ShadowMib802dot11;

	if (!vmacSta_p->InfUpFlag) {
		/* Still scan */
		Sysfs_Printk("%s is not interface up.\n", netdev->name);
	} else if (!*(mib->mib_autochannel)) {
		Sysfs_Printk("ACS(Auto Channel Select) not enable!!\n");
		Sysfs_Printk
			("Please enable by \"iwpriv [phy_ap] autochannel 1\"\n");
	} else if ((!vmacSta_p->preautochannelfinished)) {
		/* Still scan */
		Sysfs_Printk
			("ACS(Auto Channel Select) still in scan, wait a few seconds\n");
	} else {
		Sysfs_Printk("\n======== [Auto Channel Select] ========\n");
		Sysfs_Printk
			("channel \tBSS \tminrss \tmaxrss \tNF \tCh load  Score \tCal Score \tUse 2nd-CH\n");
		for (i = 0;
		     i < (IEEEtypes_MAX_CHANNELS + IEEEtypes_MAX_CHANNELS_A);
		     i++) {
			if (vmacSta_p->acs_db[i].channel != 0) {
				Sysfs_Printk
					("%3d \t\t%3d \t%3d \t%3d \t%3d \t%3d \t%6d \t%6d \t\t%c\n",
					 vmacSta_p->acs_db[i].channel,
					 vmacSta_p->acs_db[i].bss_num,
					 vmacSta_p->acs_db[i].min_rssi,
					 vmacSta_p->acs_db[i].max_rssi,
					 vmacSta_p->acs_db[i].noise_floor,
					 vmacSta_p->acs_db[i].ch_load,
					 vmacSta_p->acs_db[i].score,
					 vmacSta_p->autochannel[i],
					 vmacSta_p->acs_db[i].
					 is_2nd_ch ? 'Y' : 'N');
			}
		}
	}

	return strlen(buf);
}

static ssize_t
ap8xLnxStat_acs_store(struct kobject *kobj, struct kobj_attribute *attr,
		      const char *buf, size_t count)
{
	return count;
}

static SYSFS_ATTR(acs_info, S_IRUSR | S_IWUSR, ap8xLnxStat_acs_show,
		  ap8xLnxStat_acs_store);

static struct attribute *ap8xLnxStat_acs_attrs[] = {
	&dev_attr_acs_info.attr,
	NULL
};

static struct attribute_group ap8xLnxStat_acs_group = {
	.attrs = ap8xLnxStat_acs_attrs,
};

/***** For radio hw info End *****/
#endif /* AUTOCHANNEL */

static ssize_t
ap8xLnxStat_mmdu_show(struct kobject *kobj,
		      struct kobj_attribute *attr, char *buf)
{
	struct kobject *parent_kobj = kobj->parent;
	struct device *dev = NULL;
	struct net_device *netdev;
	UINT8 *sysfs_buff = buf;
	struct wlprivate *wlpptr;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;
	if (parent_kobj == NULL) {
		pr_err("Cannot find net device, kobject is null\n");
		return -EINVAL;
	}
	dev = kobj_to_dev(parent_kobj);
	if (dev == NULL) {
		pr_err("Cannot find net device, device is null\n");
		return -EINVAL;
	}
	netdev = to_net_dev(dev);
	if (netdev == NULL) {
		pr_err("Cannot find net device, netdev is null\n");
		return -EINVAL;
	}
	wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);

	Sysfs_Printk("mmdu_mgmt_enable: %d\n",
		     wlpptr->wlpd_p->mmdu_mgmt_enable);
	Sysfs_Printk("mmdu_data_enable: %d\n",
		     wlpptr->wlpd_p->mmdu_data_enable);

	return strlen(buf);
}

static SYSFS_ATTR(mmdu_enable, S_IRUSR, ap8xLnxStat_mmdu_show, NULL);

static struct attribute *ap8xLnxStat_mmdu_attrs[] = {
	&dev_attr_mmdu_enable.attr,
	NULL
};

static struct attribute_group ap8xLnxStat_mmdu_group = {
	.attrs = ap8xLnxStat_mmdu_attrs,
};

static UINT8 *
_DeviceID_to_string(UINT16 id)
{
	switch (id) {
	case SC3:
		return "SC3";
	case SC4:
		return "SC4";
	case SC4P:
		return "SC4P";
	case SC5:
		return "SC5";
	case SCBT:
		return "SCBT";
	default:
		break;
	}
	return "Device ID cannot recognized";
}

static UINT8 *
_ChipRevision_to_string(UINT8 id)
{
	switch (id) {
	case REV_Z1:
		return "Z1";
	case REV_Z2:
		return "Z2";
	case REV_A0:
		return "A0";
	default:
		return "Unknow revision";
	}
}

static UINT8 *
_AmpduTx_to_string(UINT8 mode, UINT8 * str)
{
	switch (mode) {
	case 0:
		sprintf(str, "Disable");
		break;
	case 1:
		sprintf(str, "Auto");
		break;
	case 2:
		sprintf(str, "Manual");
		break;
	default:
		sprintf(str, "%d", mode);
		break;
	}
	return str;
}

static UINT8 *
_MIMOPwSave_to_string(UINT8 mode)
{
	switch (mode) {
	case 0:
		return "POWER_STATIC";
	case 1:
		return "POWER_DYNAMIC";
	case 2:
		return "RESERVED";
	case 3:
		return "POWER_ENABLE";
	default:
		break;
	}
	return "MIMOPwSave not supported";
}

static UINT8 *
_CSMode_to_string(UINT8 mode)
{
	switch (mode) {
	case 0:
		return "CONSERV";
	case 1:
		return "AGGR";
	case 2:
		return "AUTO_ENABLED";
	case 3:
		return "AUTO_DISABLED";
	default:
		break;
	}
	return "CSMode not supported";
}

static UINT8 *
_RateAdaptMode_to_string(UINT8 mode)
{
	switch (mode) {
	case 0:
		return "Indoor";
	case 1:
		return "Outdoor";
	default:
		break;
	}
	return "Rate adapt mode not supported";
}

static UINT8 *
_filtertype_to_string(UINT8 type)
{
	switch (type) {
	case DISABLE_MODE:
		return "DISABLE_MODE";
	case ACCESS_MODE:
		return "ACCESS_MODE";
	case FILTER_MODE:
		return "FILTER_MODE";
	default:
		break;
	}
	return "wlan filter type not supported";
}

static UINT8 *
_wpawpa2mode_to_string(UINT8 mode)
{
	switch (mode) {
	case 0:
		return "disable wpa/wpa2";
	case 1:
		return "wpa-psk";
	case 2:
		return "wpa2-psk";
	case 3:
		return "wpa/wpa2-psk mix mode";
	case 4:
		return "hostapd config wpa/wpa2";
	default:
		break;
	}
	return "wpawpa2mode not supported";
}

static UINT8 *
_opmode_to_string(UINT8 opmode)
{
	switch (opmode) {
	case AP_MODE_B_ONLY:
		return "AP_MODE_B_ONLY";
	case AP_MODE_G_ONLY:
		return "AP_MODE_G_ONLY";
	case AP_MODE_MIXED:
		return "AP_MODE_MIXED";
	case AP_MODE_N_ONLY:
		return "AP_MODE_N_ONLY";
	case AP_MODE_BandN:
		return "AP_MODE_BandN";
	case AP_MODE_GandN:
		return "AP_MODE_GandN";
	case AP_MODE_BandGandN:
		return "AP_MODE_BandGandN";
	case AP_MODE_A_ONLY:
		return "AP_MODE_A_ONLY";
	case AP_MODE_AandG:
		return "AP_MODE_AandG";
	case AP_MODE_AandN:
		return "AP_MODE_AandN";
	case AP_MODE_11AC:
		return "AP_MODE_11AC";
	case AP_MODE_2_4GHZ_11AC_MIXED:
		return "AP_MODE_2_4GHZ_11AC_MIXED";

	case AP_MODE_5GHZ_Nand11AC:
		return "AP_MODE_5GHZ_Nand11AC";
#if defined(SOC_W906X) || defined(SOC_W9068)
	case AP_MODE_11AX:
		return "AP_MODE_11AX";
	case AP_MODE_2_4GHZ_Nand11AX:
		return "AP_MODE_2_4GHZ_Nand11AX";
	case AP_MODE_2_4GHZ_11AX_MIXED:
		return "AP_MODE_2_4GHZ_11AX_MIXED";
	case AP_MODE_5GHZ_11AX_ONLY:
		return "AP_MODE_5GHZ_11AX_ONLY";
	case AP_MODE_5GHZ_ACand11AX:
		return "AP_MODE_5GHZ_ACand11AX";
	case AP_MODE_5GHZ_NandACand11AX:
		return "AP_MODE_5GHZ_NandACand11AX";
#else
	case AP_MODE_4_9G_5G_PUBLIC_SAFETY:
		return "AP_MODE_4_9G_5G_PUBLIC_SAFETY";
#endif /* #if defined(SOC_W906X) || defined(SOC_W9068) */
	default:
		break;
	}
	return "opmode not supported";
}

static ssize_t
VAP_info_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct device *dev = NULL;
	struct net_device *netdev;
	struct wlprivate *priv;
	struct kobject *parent_kobj = kobj->parent;
	vmacApInfo_t *vmacSta_p;
	MIB_802DOT11 *mib;
	UINT8 *sysfs_buff = buf;
	MIB_OP_DATA *mib_OpData;
	UINT8 mode_str[64];

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	if (parent_kobj == NULL) {
		pr_err("Cannot find net device, kobject is null\n");
		return -EINVAL;
	}

	dev = kobj_to_dev(parent_kobj);
	if (dev == NULL) {
		pr_err("Cannot find net device, device is null\n");
		return -EINVAL;
	}

	netdev = to_net_dev(dev);
	if (dev == NULL) {
		pr_err("Cannot find net device, netdev is null\n");
		return -EINVAL;
	}

	priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	if (priv == NULL) {
		pr_err("Cannot find priv, priv is null\n");
		return strlen(buf);
	}
	vmacSta_p = priv->vmacSta_p;
	if (vmacSta_p == NULL) {
		pr_err("Cannot find vmacSta_p, vmacSta_p is null\n");
		return strlen(buf);
	}
	mib = vmacSta_p->ShadowMib802dot11;
	if (mib == NULL) {
		pr_err("Cannot find mib, mib is null\n");
		return strlen(buf);
	}

	memset(mode_str, 0, sizeof(mode_str));
	Sysfs_Printk("\n======== [%s info] ========\n", netdev->name);
	mib_OpData = mib->OperationTable;
	Sysfs_Printk("MAC:             %02x:%02x:%02x:%02x:%02x:%02x\n",
		     mib_OpData->StaMacAddr[0],
		     mib_OpData->StaMacAddr[1],
		     mib_OpData->StaMacAddr[2],
		     mib_OpData->StaMacAddr[3],
		     mib_OpData->StaMacAddr[4], mib_OpData->StaMacAddr[5]);

	Sysfs_Printk("opmode:          %s (%d)\n",
		     _opmode_to_string(*(mib->mib_ApMode)), *(mib->mib_ApMode));
	Sysfs_Printk("bcninterval:     %d\n", *(mib->mib_BcnPeriod));
	Sysfs_Printk("DTIM:            %d\n", mib->StationConfig->DtimPeriod);
	Sysfs_Printk("wpawpa2mode:     %s (%d)\n",
		     _wpawpa2mode_to_string(*(mib->mib_wpaWpa2Mode)),
		     *(mib->mib_wpaWpa2Mode));
	Sysfs_Printk("grouprekey time: %d\n", mib->RSNConfig->GroupRekeyTime);
	Sysfs_Printk("filter:          %s (%d)\n",
		     _filtertype_to_string(*(mib->mib_wlanfiltertype)),
		     *(mib->mib_wlanfiltertype));
	Sysfs_Printk("intrabss:        %d\n", *(mib->mib_intraBSS));
	Sysfs_Printk("amsdu:           %d\n",
		     *(mib->pMib_11nAggrMode) & WL_MODE_AMSDU_TX_MASK);
	Sysfs_Printk("wmmackpolicy:    %d\n", *(mib->mib_wmmAckPolicy));
	Sysfs_Printk("ampdufactor:     %d\n", *(mib->mib_ampdu_factor));
	Sysfs_Printk("ampduden:        %d\n", *(mib->mib_ampdu_density));
	Sysfs_Printk("deviceinfo:      %d\n", priv->wlpd_p->CardDeviceInfo);
	Sysfs_Printk("ratemode:        %s (%d)\n",
		     _RateAdaptMode_to_string(*(mib->mib_RateAdaptMode)),
		     *(mib->mib_RateAdaptMode));
	Sysfs_Printk("csmode:          %s (%d)\n",
		     _CSMode_to_string(*(mib->mib_CSMode)), *(mib->mib_CSMode));
	Sysfs_Printk("wdsmode:         %s (%d)\n",
		     *(mib->mib_wdsEnable) == 1 ? "on" : "off",
		     *(mib->mib_wdsEnable));
	Sysfs_Printk("strictshared:    %s (%d)\n",
		     *(mib->mib_strictWepShareKey) == 1 ? "share" : "both",
		     *(mib->mib_strictWepShareKey));
	Sysfs_Printk("disableassoc:    %s (%d)\n",
		     *(mib->mib_disableAssoc) == 1 ? "TRUE" : "FALSE",
		     *(mib->mib_disableAssoc));
	Sysfs_Printk("mimops mode:     %s (%d)\n",
		     _MIMOPwSave_to_string(*(mib->mib_psHtManagementAct)),
		     *(mib->mib_psHtManagementAct));
	Sysfs_Printk("ampdutx:         %s (%d)\n",
		     _AmpduTx_to_string(*(mib->mib_AmpduTx), mode_str),
		     *(mib->mib_AmpduTx));
	Sysfs_Printk("txqlimit:        %d bytes\n", vmacSta_p->txQLimit);
	Sysfs_Printk("rxintlimit:      %d bytes\n", vmacSta_p->work_to_do);
	Sysfs_Printk("mcast proxy:     %s (%d)\n",
		     *(mib->mib_MCastPrxy) == 1 ? "on" : "off",
		     *(mib->mib_MCastPrxy));
	Sysfs_Printk("amsdu pktcnt:    %d\n", *(mib->mib_amsdu_pktcnt));
	Sysfs_Printk("deviceid:        %s (0x%x)\n",
		     _DeviceID_to_string(priv->devid), priv->devid);
	Sysfs_Printk("ampduwincap:     %d bytes\n",
		     vmacSta_p->ampduWindowSizeCap);
	Sysfs_Printk("ampdubytcap:     %d bytes\n", vmacSta_p->ampduBytesCap);
	Sysfs_Printk("ampdudencap:     %d\n", vmacSta_p->ampduDensityCap);
	Sysfs_Printk("rootdev:         %s\n", priv->wlpd_p->rootdev->name);

	return strlen(buf);
}

static SYSFS_ATTR(info, S_IRUSR, VAP_info_show, NULL);

static struct attribute *VAP_info_attrs[] = {
	&dev_attr_info.attr,
	NULL
};

static struct attribute_group VAP_info_group = {
	.attrs = VAP_info_attrs,
};

#ifdef SYSFS_STADB_INFO
static void
ap8xLnxStat_clients_group_free(struct clients_attribute_group *free_group)
{
	int i = 0;

	if (free_group == NULL)
		return;

	if (free_group->group.attrs) {
		for (i = 0; i < OPT_NUM; i++) {
			if (free_group->group.attrs[i])
				wl_kfree(free_group->group.attrs[i]);
		}

		wl_kfree(free_group->group.attrs);
	}

	wl_kfree(free_group);
	return;
}

static struct clients_kobject *
ap8xLnxStat_clients_kobj_found(const char *name,
			       struct clients_kobject_list *list)
{
	struct clients_kobject *clients_kobj = NULL;
	int i;

	if ((list == NULL) || ((list->head == NULL) && (list->num == 0)))
		return NULL;

	for (clients_kobj = list->head, i = 0;
	     (clients_kobj != NULL) && (i < list->num);
	     clients_kobj = clients_kobj->next, i++) {
		if (clients_kobj->kobj == NULL) {
			break;
		}
		if (clients_kobj->kobj->parent == NULL) {
			break;
		}
		if (!memcmp(clients_kobj->kobj->parent->name, name,
			    MAX(strlen(clients_kobj->kobj->parent->name),
				strlen(name)))) {
			return clients_kobj;
		}
	}

	return NULL;
}

static int
ap8xLnxStat_clients_kobj_add(struct clients_kobject *kobj,
			     struct clients_kobject_list *list)
{
	if ((list == NULL) || (list->num >= MAX_VAP_NUM))
		return -ENOMEM;

	kobj->next = list->head;
	list->head = kobj;
	list->num++;

	return 0;
}

static void
ap8xLnxStat_clients_kobj_list_free(struct clients_kobject_list *list)
{
	struct clients_kobject *kobj = NULL, *kobj_free = NULL;
	struct clients_attribute_group *attr_group = NULL, *free_group = NULL;
	int i = 0, j = 0;

	if ((list == NULL) || (list->head == NULL) || (list->num == 0))
		return;

	for (kobj = list->head, i = 0; (kobj != NULL) && (i < list->num); i++) {
		for (attr_group = kobj->group_head, j = 0;
		     (attr_group != NULL) && (j < kobj->conn_cnt); j++) {
			free_group = attr_group;
			attr_group = attr_group->next;

			sysfs_remove_group(kobj->kobj, &free_group->group);

			ap8xLnxStat_clients_group_free(free_group);
		}

		kobject_del(kobj->kobj);
		kobj_free = kobj;
		kobj = kobj->next;
		wl_kfree(kobj_free);
	}
	list->head = NULL;
	list->num = 0;

	return;
}

static struct clients_attribute_group *
ap8xLnxStat_clients_group_found(const char *name, struct clients_kobject *kobj)
{
	struct clients_attribute_group *attr_group = NULL;
	int i;

	if ((kobj == NULL) ||
	    ((kobj->group_head == NULL) && (kobj->conn_cnt == 0)))
		return NULL;

	for (attr_group = kobj->group_head, i = 0;
	     (attr_group != NULL) && (i < kobj->conn_cnt);
	     attr_group = attr_group->next, i++) {
		if (!memcmp(attr_group->name, name,
			    MAX(strlen(attr_group->name), strlen(name))))
			return attr_group;
	}

	return NULL;
}

static int
ap8xLnxStat_clients_group_add(struct clients_attribute_group *attr_group,
			      struct clients_kobject *kobj)
{
	if ((kobj == NULL) || (attr_group == NULL))
		return -ENOMEM;

	attr_group->next = kobj->group_head;
	kobj->group_head = attr_group;

	return 0;
}

static void
ap8xLnxStat_clients_group_del(struct clients_attribute_group *attr_group,
			      struct clients_kobject *kobj)
{
	struct clients_attribute_group *curr_group = NULL, *prev_group = NULL;
	int i;

	if ((kobj == NULL) ||
	    ((kobj->group_head == NULL) && (kobj->conn_cnt == 0)))
		return;

	for (curr_group = kobj->group_head, i = 0;
	     (curr_group != NULL) && (i < kobj->conn_cnt);
	     curr_group = curr_group->next, i++) {
		if (curr_group == attr_group)
			break;
		prev_group = curr_group;
	}

	/* The match clinet group not found, return */
	if (!curr_group)
		return;

	if (curr_group == kobj->group_head)
		kobj->group_head = curr_group->next;
	else
		prev_group->next = curr_group->next;

	ap8xLnxStat_clients_group_free(curr_group);
}
#endif /* SYSFS_STADB_INFO */

void *
ap8xLnxStat_vap_init(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	struct kobject *dev_kobj = &netdev->dev.kobj;
	int err;

	if (!vmacSta_p->vap_info_kobj) {
		vmacSta_p->vap_info_kobj =
			kobject_create_and_add("vap_info", dev_kobj);
		if (!vmacSta_p->vap_info_kobj) {
			pr_err("%s: cannot create vap_info kobject\n",
			       __func__);
			return NULL;
		}
	}
	err = sysfs_create_group(vmacSta_p->vap_info_kobj, &VAP_info_group);
	if (err) {
		pr_err("%s: sysfs group failed for tp%d\n", __func__, err);
		return NULL;
	}

	if (!vmacSta_p->vap_stat_kobj) {
		vmacSta_p->vap_stat_kobj =
			kobject_create_and_add("stat", dev_kobj);
		if (!vmacSta_p->vap_stat_kobj) {
			pr_err("%s: cannot create stat kobject\n", __func__);
			return NULL;
		}
	}
	err = sysfs_create_group(vmacSta_p->vap_stat_kobj,
				 &ap8xLnxStat_vap_stat_group);
	if (err) {
		pr_err("%s: sysfs group failed for stat%d\n", __func__, err);
		return NULL;
	}

	return NULL;
}

int
ap8xLnxStat_vap_exit(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;

	if (vmacSta_p->vap_info_kobj) {
		sysfs_remove_group(vmacSta_p->vap_info_kobj, &VAP_info_group);
		kobject_del(vmacSta_p->vap_info_kobj);
	}
	if (vmacSta_p->vap_stat_kobj) {
		sysfs_remove_group(vmacSta_p->vap_stat_kobj,
				   &ap8xLnxStat_vap_stat_group);
		kobject_del(vmacSta_p->vap_stat_kobj);
	}
	return 0;
}

#ifdef SYSFS_STADB_INFO
static ssize_t
ap8xLnxStat_clients_ap_info(struct kobject *kobj,
			    struct kobj_attribute *attr, char *buf)
{
	ssize_t size = 0;
	char *pos = buf;
	const char *ifname = NULL;
	UINT8 AssociatedFlag = 0;
	UINT8 bssId[6];
	struct kobject *parent_kobj = (kobj) ? kobj->parent : NULL;
	struct net_device *netdev = NULL;
	struct wlprivate *wlpptr = NULL;
	vmacEntry_t *vmacEntry_p = NULL;

	if (!capable(CAP_NET_ADMIN))
		return size;

	ifname = (parent_kobj) ? kobject_name(parent_kobj) : NULL;
	if ((ifname == NULL) || (!strlen(ifname))) {
		pr_err("%s: cannot find netdev, ifname is NULL\n", __func__);
		return size;
	}

	netdev = (ifname) ? dev_get_by_name(&init_net, ifname) : NULL;
	if (netdev == NULL)
		return size;

	wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	if (wlpptr == NULL)
		return size;

	vmacEntry_p =
		sme_GetParentVMacEntry(((vmacApInfo_t *) wlpptr->vmacSta_p)->
				       VMacEntry.phyHwMacIndx);
	if (vmacEntry_p == NULL)
		return size;

	smeGetStaLinkInfo(vmacEntry_p->id, &AssociatedFlag, &bssId[0]);

	if (!AssociatedFlag)
		pos += sprintf(pos, "no connection\n");
	else
		pos += sprintf(pos, "AP MAC Address: " MACSTR "\n",
			       MAC2STR(&bssId[0]));

	return (ssize_t) (pos - buf);
}

#define CLIENTS_ATTR(_name, _mode, _show, _store) \
	struct kobj_attribute clients_attr_##_name = __ATTR(_name, _mode, _show, _store)

static CLIENTS_ATTR(ap_info, S_IWUSR | S_IRUSR, ap8xLnxStat_clients_ap_info,
		    NULL);

static struct attribute *ap8xLnxStat_ap_info_attrs[] = {
	&clients_attr_ap_info.attr,
	NULL
};

static struct attribute_group ap8xLnxStat_ap_info_group = {
	.attrs = ap8xLnxStat_ap_info_attrs,
};

void *
ap8xLnxStat_clients_init(struct net_device *netdev, UINT8 mode)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	struct kobject *dev_kobj = &netdev->dev.kobj;
	int err = 0;
	struct clients_kobject *clients_kobj = NULL;
	struct clients_kobject_list *kobj_list = NULL;

	if (mode >= MODE_NUM)
		return NULL;

	if (mode == MODE_STA) {
		vmacEntry_t *vmacEntry_p =
			sme_GetParentVMacEntry(vmacSta_p->VMacEntry.
					       phyHwMacIndx);
		vmacStaInfo_t *vStaInfo_p = NULL;

		if (!vmacEntry_p) {
			return NULL;
		}
		vStaInfo_p = (vmacStaInfo_t *) vmacEntry_p->info_p;
		if (!vStaInfo_p) {
			return NULL;
		}

		vStaInfo_p->sta_conn_info_kobj =
			kobject_create_and_add("connection_info", dev_kobj);
		if (!vStaInfo_p->sta_conn_info_kobj) {
			pr_err("%s: cannot create connection_info kobject\n",
			       __func__);
			return NULL;
		}

		err = sysfs_create_group(vStaInfo_p->sta_conn_info_kobj,
					 &ap8xLnxStat_ap_info_group);
		if (err) {
			pr_err("%s: sysfs group failed for connection_info %d\n", __func__, err);
			return NULL;
		}

		return NULL;
	}

	kobj_list = (mode == MODE_VAP) ?
		&ap8xLnxStat_clients_vap_kobjs : &ap8xLnxStat_clients_kobjs;
	if (kobj_list == NULL)
		return NULL;

	clients_kobj =
		ap8xLnxStat_clients_kobj_found((const char *)
					       kobject_name(dev_kobj),
					       kobj_list);
	if (clients_kobj)
		return NULL;

	if (kobj_list->num >= MAX_VAP_NUM)
		return NULL;

	/* create the "clients" kobj for radio interface */
	clients_kobj = wl_kzalloc(sizeof(struct clients_kobject), GFP_KERNEL);
	if (!clients_kobj) {
		pr_err("%s: cannot alloc memory for clients kobject\n",
		       __func__);
		return NULL;
	}

	clients_kobj->conn_cnt = 0;
	clients_kobj->group_head = NULL;
	clients_kobj->next = NULL;
	clients_kobj->kobj = kobject_create_and_add("clients", dev_kobj);
	if (!clients_kobj->kobj) {
		pr_err("%s: cannot create clients kobject\n", __func__);
		wl_kfree(clients_kobj);
		return NULL;
	}

	ap8xLnxStat_clients_kobj_add(clients_kobj, kobj_list);

	return (void *)clients_kobj;
}

void
ap8xLnxStat_clients_deinit(struct net_device *netdev, UINT8 mode)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	vmacEntry_t *vmacEntry_p =
		sme_GetParentVMacEntry(vmacSta_p->VMacEntry.phyHwMacIndx);
	vmacStaInfo_t *vStaInfo_p = NULL;

	if (mode == MODE_AP) {
		ap8xLnxStat_clients_kobj_list_free
			(&ap8xLnxStat_clients_vap_kobjs);
		ap8xLnxStat_clients_kobj_list_free(&ap8xLnxStat_clients_kobjs);
	}
	if (mode == MODE_STA) {
		if (!vmacEntry_p) {
			return;
		}
		vStaInfo_p = (vmacStaInfo_t *) vmacEntry_p->info_p;
		if (!vStaInfo_p) {
			return;
		}
		if (vStaInfo_p->sta_conn_info_kobj) {
			sysfs_remove_group(vStaInfo_p->sta_conn_info_kobj,
					   &ap8xLnxStat_ap_info_group);
			kobject_del(vStaInfo_p->sta_conn_info_kobj);
		}
	}
}
#else /* SYSFS_STADB_INFO */
void *
ap8xLnxStat_clients_init(struct net_device *netdev, UINT8 mode)
{
	return NULL;
};
#endif /* SYSFS_STADB_INFO */

int
ap8xLnxStat_sysfs_init(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	struct kobject *dev_kobj = &netdev->dev.kobj;
	int err;

	if (!vmacSta_p->tp_kobj) {
		vmacSta_p->tp_kobj = kobject_create_and_add("tp", dev_kobj);
		if (!vmacSta_p->tp_kobj) {
			pr_err("%s: cannot create qm kobject\n", __func__);
			return -ENOMEM;
		}
	}
	err = sysfs_create_group(vmacSta_p->tp_kobj, &ap8xLnxStat_tp_group);
	if (err) {
		pr_err("%s: sysfs group failed for tp%d\n", __func__, err);
		return err;
	}

	if (!vmacSta_p->stat_kobj) {
		vmacSta_p->stat_kobj = kobject_create_and_add("stat", dev_kobj);
		if (!vmacSta_p->stat_kobj) {
			pr_err("%s: cannot create qm kobject\n", __func__);
			return -ENOMEM;
		}
	}
	err = sysfs_create_group(vmacSta_p->stat_kobj, &ap8xLnxStat_stat_group);
	if (err) {
		pr_err("%s: sysfs group failed for tp%d\n", __func__, err);
		return err;
	}
#ifdef SYSFS_STADB_INFO
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 52)
	ap8xLnxStat_clients_init(netdev, MODE_AP);
#endif
#endif /* SYSFS_STADB_INFO */

	if (!vmacSta_p->hw_kobj) {
		vmacSta_p->hw_kobj = kobject_create_and_add("hw", dev_kobj);
		if (!vmacSta_p->hw_kobj) {
			pr_err("%s: cannot create hw kobject\n", __func__);
			return -ENOMEM;
		}
	}
	err = sysfs_create_group(vmacSta_p->hw_kobj, &ap8xLnxStat_hw_group);
	if (err) {
		pr_err("%s: sysfs group failed for hw%d\n", __func__, err);
		return err;
	}
#ifdef AUTOCHANNEL
	if (!vmacSta_p->acs_kobj) {
		vmacSta_p->acs_kobj = kobject_create_and_add("acs", dev_kobj);
		if (!vmacSta_p->acs_kobj) {
			pr_err("%s: cannot create acs kobject\n", __func__);
			return -ENOMEM;
		}
	}
	err = sysfs_create_group(vmacSta_p->acs_kobj, &ap8xLnxStat_acs_group);
	if (err) {
		pr_err("%s: sysfs group failed for acs %d\n", __func__, err);
		return err;
	}
#endif /* AUTOCHANNEL */

	if (!vmacSta_p->mmdu_kobj) {
		vmacSta_p->mmdu_kobj = kobject_create_and_add("mmdu", dev_kobj);
		if (!vmacSta_p->mmdu_kobj) {
			pr_err("%s: cannot create mmdu kobject\n", __func__);
			return -ENOMEM;
		}
	}
	err = sysfs_create_group(vmacSta_p->mmdu_kobj, &ap8xLnxStat_mmdu_group);
	if (err) {
		pr_err("%s: sysfs group failed for mmdu %d\n", __func__, err);
		return err;
	}
#ifdef MEMORY_USAGE_TRACE
	if (!vmacSta_p->mem_kobj) {
		vmacSta_p->mem_kobj = kobject_create_and_add("mem", dev_kobj);
		if (!vmacSta_p->mem_kobj) {
			pr_err("%s: cannot create hw kobject\n", __func__);
			return -ENOMEM;
		}
	}
	err = sysfs_create_group(vmacSta_p->mem_kobj, &ap8xLnxStat_mem_group);
	if (err) {
		pr_err("%s: sysfs group failed for mem%d\n", __func__, err);
		return err;
	}
#endif /* MEMORY_USAGE_TRACE */

	return err;
}

int
ap8xLnxStat_sysfs_exit(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;

	if (vmacSta_p->tp_kobj) {
		sysfs_remove_group(vmacSta_p->tp_kobj, &ap8xLnxStat_tp_group);
		kobject_del(vmacSta_p->tp_kobj);
	}
	if (vmacSta_p->stat_kobj) {
		sysfs_remove_group(vmacSta_p->stat_kobj,
				   &ap8xLnxStat_stat_group);
		kobject_del(vmacSta_p->stat_kobj);
	}
	if (vmacSta_p->hw_kobj) {
		sysfs_remove_group(vmacSta_p->hw_kobj, &ap8xLnxStat_hw_group);
		kobject_del(vmacSta_p->hw_kobj);
	}
	if (vmacSta_p->acs_kobj) {
		sysfs_remove_group(vmacSta_p->acs_kobj, &ap8xLnxStat_acs_group);
		kobject_del(vmacSta_p->acs_kobj);
	}
	if (vmacSta_p->mmdu_kobj) {
		sysfs_remove_group(vmacSta_p->mmdu_kobj,
				   &ap8xLnxStat_mmdu_group);
		kobject_del(vmacSta_p->mmdu_kobj);
	}
#ifdef MEMORY_USAGE_TRACE
	if (vmacSta_p->mem_kobj) {
		sysfs_remove_group(vmacSta_p->mem_kobj, &ap8xLnxStat_mem_group);
		kobject_del(vmacSta_p->mem_kobj);
	}
#endif /* MEMORY_USAGE_TRACE */
#ifdef SYSFS_STADB_INFO
	ap8xLnxStat_clients_deinit(netdev, MODE_AP);
#endif /* SYSFS_STADB_INFO */

	return 0;
}

#ifdef SYSFS_STADB_INFO
static ssize_t
ap8xLnxStat_clients_help(struct kobject *kobj,
			 struct kobj_attribute *attr, char *buf)
{
	char *pos = buf;
	pos += sprintf(pos,
		       "\nGet the informations of the client specified by MAC Address.\n");
	pos += sprintf(pos,
		       "######################################################################\n");
	pos += sprintf(pos,
		       "-Use \"query\" to get the client information by its MAC Address.\n");
	pos += sprintf(pos,
		       "#echo \"<MAC Address> [<query information>]\" > query\n");
	pos += sprintf(pos, "  <MAC Address>\n");
	pos += sprintf(pos,
		       "    the string of client MAC addrss, the format is \"xx:xx:xx:xx:xx:xx\"\n");
	pos += sprintf(pos, "  <query information>\n");
	pos += sprintf(pos,
		       "    the string of what information of client wants to get\n");
	pos += sprintf(pos,
		       "    \"summary\"    - get the summary of client with <MAC Address>\n");
	pos += sprintf(pos,
		       "    \"ratetable\"  - get the ratetable of the client with <MAC Address>\n");
	pos += sprintf(pos,
		       "    <query information> is optional, default is to get the summary\n");
	pos += sprintf(pos,
		       "#cat query         - get the specific information of the selected client\n");
	pos += sprintf(pos,
		       "######################################################################\n");
	pos += sprintf(pos,
		       "-Enter the clinet folder to get client information by its MAC Address.\n");
	pos += sprintf(pos, "#cd <MAC Address>\n");
	pos += sprintf(pos,
		       "#cat summary       - get the summary of client with <MAC Address>\n");
	pos += sprintf(pos,
		       "#cat ratetable     - get the ratetable of the client with <MAC Address>\n");
	pos += sprintf(pos,
		       "######################################################################\n\n");

	return (ssize_t) (pos - buf);
}

static ssize_t
ap8xLnxStat_clients_summary(struct net_device *netdev,
			    UINT8 * macAddr, char *buf)
{
	ssize_t size = 0;
	char *pos = buf;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	extStaDb_StaInfo_t *StaInfo_p;
	char mode[4] = { 0 }, state[64] = {
	0};
#ifdef SOC_W906X
	s16 rssi_value_signed[MAX_RF_ANT_NUM] = { 0 };
#else
	u16 a, b, c, d;
#endif

	if ((StaInfo_p = extStaDb_GetStaInfo(vmacSta_p,
					     (IEEEtypes_MacAddr_t *) macAddr,
					     STADB_DONT_UPDATE_AGINGTIME)) ==
	    NULL) {
		return size;
	}

	switch (StaInfo_p->ClientMode) {
	case BONLY_MODE:
		strcpy(mode, "b");
		break;
	case GONLY_MODE:
		strcpy(mode, "g");
		break;
	case NONLY_MODE:
		strcpy(mode, "n");
		break;
	case AONLY_MODE:
		strcpy(mode, "a");
		break;
	default:
		strcpy(mode, "NA");
		break;
	}

	switch (StaInfo_p->State) {
	case UNAUTHENTICATED:
		strcpy(state, "UNAUTHENTICATED");
		break;
	case SME_INIT_AUTHENTICATING:
	case EXT_INIT_AUTHENTICATING:
		strcpy(state, "AUTHENTICATING");
		break;
	case AUTHENTICATED:
		strcpy(state, "AUTHENTICATED");
		break;
	case SME_INIT_DEAUTHENTICATING:
	case EXT_INIT_DEAUTHENTICATING:
		strcpy(state, "DEAUTHENTICATING");
		break;
	case SME_INIT_ASSOCIATING:
	case EXT_INIT_ASSOCIATING:
		strcpy(state, "ASSOCIATING");
		break;
	case ASSOCIATED:
		{
			int flagPsk = 0;
			if ((mib->Privacy->RSNEnabled == 1) ||
			    (mib->RSNConfigWPA2->WPA2Enabled == 1)) {
				if (*(mib->mib_wpaWpa2Mode) < 4) {	/* For PSK modes use internal WPA state machine */
					if (StaInfo_p->keyMgmtHskHsm.super.
					    pCurrent != NULL) {
						if (StaInfo_p->keyMgmtHskHsm.
						    super.pCurrent ==
						    &StaInfo_p->keyMgmtHskHsm.
						    hsk_end) {
							strcpy(state,
							       "PSK PASSED");
							flagPsk = 1;
						}
					}
				} else if (StaInfo_p->keyMgmtStateInfo.
					   RSNDataTrafficEnabled == TRUE) {
					strcpy(state, "KEY CONFIGURED");
					flagPsk = 1;
				}
			}
			if (!flagPsk)
				strcpy(state, "ASSOCIATED");
		}
		break;
	case SME_INIT_REASSOCIATING:
	case EXT_INIT_REASSOCIATING:
		strcpy(state, "REASSOCIATING");
		break;
	case SME_INIT_DEASSOCIATING:
	case EXT_INIT_DEASSOCIATING:
		strcpy(state, "DEASSOCIATING");
		break;
	default:
		break;
	}

#ifdef SOC_W906X
	wl_util_get_rssi(netdev, &StaInfo_p->RSSI_path, rssi_value_signed);
#else
	a = StaInfo_p->RSSI_path.a;
	b = StaInfo_p->RSSI_path.b;
	c = StaInfo_p->RSSI_path.c;
	d = StaInfo_p->RSSI_path.d;
	if (a >= 2048 && b >= 2048 && c >= 2048 && d >= 2048) {
		a = ((4096 - a) >> 4);
		b = ((4096 - b) >> 4);
		c = ((4096 - c) >> 4);
		d = ((4096 - d) >> 4);
	}
#endif

	pos += sprintf(pos, "\nClient: " MACSTR "\n", MAC2STR(macAddr));
	pos += sprintf(pos, "StnId:  %d\n", StaInfo_p->StnId);
	pos += sprintf(pos, "Aid:    %d\n", StaInfo_p->Aid);
	pos += sprintf(pos, "Mode:   %s%s\n",
		       strcmp(mode, "NA") ? "802.11" : "", mode);
	pos += sprintf(pos, "State:  %s\n", state);
	pos += sprintf(pos, "Rate    %d Mbps\n",
		       (int)getPhyRate((dbRateInfo_t *) &
				       (StaInfo_p->RateInfo)));
#ifdef SOC_W906X
	pos += sprintf(pos,
		       "RSSI:   A %d  B %d  C %d  D %d E %d  F %d  G %d  H %d\n",
		       rssi_value_signed[0], rssi_value_signed[1],
		       rssi_value_signed[2], rssi_value_signed[3],
		       rssi_value_signed[4], rssi_value_signed[5],
		       rssi_value_signed[6], rssi_value_signed[7]);
#else
	pos += sprintf(pos, "RSSI:   A %d  B %d  C %d  D %d\n", a, b, c, d);
#endif

	pos += sprintf(pos, "VHT Cap: \n");
	pos += sprintf(pos, "  MaximumMPDULength           0x%X\n",
		       StaInfo_p->vhtCap.cap.MaximumMPDULength);
	pos += sprintf(pos, "  SupportedChannelWidthSet    0x%X\n",
		       StaInfo_p->vhtCap.cap.SupportedChannelWidthSet);
	pos += sprintf(pos, "  RxLDPC                      0x%X\n",
		       StaInfo_p->vhtCap.cap.RxLDPC);
	pos += sprintf(pos, "  ShortGI80MHz                0x%X\n",
		       StaInfo_p->vhtCap.cap.ShortGI80MHz);
	pos += sprintf(pos, "  ShortGI16080and80MHz        0x%X\n",
		       StaInfo_p->vhtCap.cap.ShortGI16080and80MHz);
	pos += sprintf(pos, "  TxSTBC                      0x%X\n",
		       StaInfo_p->vhtCap.cap.TxSTBC);
	pos += sprintf(pos, "  RxSTBC                      0x%X\n",
		       StaInfo_p->vhtCap.cap.RxSTBC);
	pos += sprintf(pos, "  SUBeamformerCapable         0x%X\n",
		       StaInfo_p->vhtCap.cap.SUBeamformerCapable);
	pos += sprintf(pos, "  SUBeamformeeCapable         0x%X\n",
		       StaInfo_p->vhtCap.cap.SUBeamformeeCapable);
	pos += sprintf(pos, "  CmprsdStrngNbOfBfmrAntSupd  0x%X\n",
		       StaInfo_p->vhtCap.cap.
		       CompressedSteeringNumberofBeamformerAntennaSupported);
	pos += sprintf(pos, "  NumberofSoundingDimensions  0x%X\n",
		       StaInfo_p->vhtCap.cap.NumberofSoundingDimensions);
	pos += sprintf(pos, "  MUBeamformerCapable         0x%X\n",
		       StaInfo_p->vhtCap.cap.MUBeamformerCapable);
	pos += sprintf(pos, "  MUBeamformeeCapable         0x%X\n",
		       StaInfo_p->vhtCap.cap.MUBeamformeeCapable);
	pos += sprintf(pos, "  VhtTxhopPS                  0x%X\n",
		       StaInfo_p->vhtCap.cap.VhtTxhopPS);
	pos += sprintf(pos, "  HtcVhtCapable               0x%X\n",
		       StaInfo_p->vhtCap.cap.HtcVhtCapable);
	pos += sprintf(pos, "  MaximumAmpduLengthExponent  0x%X\n",
		       StaInfo_p->vhtCap.cap.MaximumAmpduLengthExponent);
	pos += sprintf(pos, "  VhtLinkAdaptationCapable    0x%X\n",
		       StaInfo_p->vhtCap.cap.VhtLinkAdaptationCapable);
	pos += sprintf(pos, "  RxAntennaPatternConsistency 0x%X\n",
		       StaInfo_p->vhtCap.cap.RxAntennaPatternConsistency);
	pos += sprintf(pos, "  TxAntennaPatternConsistency 0x%X\n",
		       StaInfo_p->vhtCap.cap.TxAntennaPatternConsistency);
	pos += sprintf(pos, "MCS SET: \n");
	pos += sprintf(pos, "  TX map                      0x%X\n",
		       StaInfo_p->vhtCap.SupportedTxMcsSet & 0xFFFF);
	pos += sprintf(pos, "  TX datarate                 0x%X\n",
		       StaInfo_p->vhtCap.SupportedTxMcsSet >> 16);
	pos += sprintf(pos, "  RX map                      0x%X\n",
		       StaInfo_p->vhtCap.SupportedRxMcsSet & 0xFFFF);
	pos += sprintf(pos, "  RX datarate                 0x%X\n",
		       StaInfo_p->vhtCap.SupportedTxMcsSet >> 16);
	pos += sprintf(pos, "HT Cap: \n");
	pos += sprintf(pos, "  TX STBC                     0x%X\n",
		       StaInfo_p->HtElem.HTCapabilitiesInfo.TxSTBC);
	pos += sprintf(pos, "  RX STBC                     0x%X\n",
		       StaInfo_p->HtElem.HTCapabilitiesInfo.RxSTBC);

	size = pos - buf;

	return size;
}

static ssize_t
ap8xLnxStat_clients_ratetable_pack(UINT8 type, UINT8 * pTbl, char *buf)
{
	char *pos = buf;
	dbRateInfo_t *pRateTbl;
	int j, Rate, Nss;

#if 0
	if (type == 2)
		pos += sprintf(pos, "Rate table - current\n");
	else if (type == 1)
		pos += sprintf(pos, "Rate table - mu\n");
	else
		pos += sprintf(pos, "Rate table\n");
#endif
	pos += sprintf(pos,
		       "%3s %6s %5s %5s %5s %5s %5s %5s %4s %2s %5s %4s %5s %5s\n",
		       "Num", "Fmt", "STBC",
#ifdef SOC_W906X
		       "DCM",
#endif /* SOC_W906X */
		       "BW",
		       "SGI",
		       "Nss",
		       "RateId",
		       "GF/Pre", "PId", "LDPC", "BF", "TxAnt", "Rate");

	j = 0;
	// Check 1st 32bit DWORD of rate info
	pRateTbl = (dbRateInfo_t *) pTbl;
	while (*(UINT32 *) pRateTbl != 0) {
		if (pRateTbl->Format >= 2) {
			Rate = pRateTbl->RateIDMCS & 0xf;	//11ac, Rate[3:0]
			Nss = pRateTbl->RateIDMCS >> 4;	//11ac, Rate[6:4] = NssCode
			++Nss;	//Add 1 to correct Nss representation
		} else {
			Rate = pRateTbl->RateIDMCS;
			Nss = 0;
			if (pRateTbl->Format == 1) {
				if (pRateTbl->RateIDMCS < 8)
					Nss = 1;
				else if ((pRateTbl->RateIDMCS >= 8) &&
					 (pRateTbl->RateIDMCS < 16))
					Nss = 2;
				else if ((pRateTbl->RateIDMCS >= 16) &&
					 (pRateTbl->RateIDMCS < 24))
					Nss = 3;
			}
		}

		pos += sprintf(pos,
			       "%3d %5d %5d %5d %5d %5d %5d %5d %5d %5d %5d %5d %5d %5d\n",
			       (int)j, (int)pRateTbl->Format,
			       (int)pRateTbl->Stbc,
#ifdef SOC_W906X
			       (int)pRateTbl->Dcm,
#endif /* SOC_W906X */
			       (int)pRateTbl->Bandwidth,
			       (int)pRateTbl->ShortGI,
			       (int)Nss,
			       (int)Rate,
			       (int)pRateTbl->Preambletype,
			       (int)pRateTbl->PowerId,
			       (int)pRateTbl->AdvCoding,
			       (int)pRateTbl->BF,
			       (int)pRateTbl->AntSelect,
			       (int)getPhyRate((dbRateInfo_t *) pRateTbl));

		j++;
		pTbl += (2 * sizeof(dbRateInfo_t));	//SOC_W8864 rate parameter is 2 DWORD. Multiply by 2 because dbRateInfo_t is only 1 DWORD
		pRateTbl = (dbRateInfo_t *) pTbl;
	}

	return (ssize_t) (pos - buf);

}

static ssize_t
ap8xLnxStat_clients_ratetable(struct net_device *netdev,
			      UINT8 * macAddr, char *buf)
{
	ssize_t size = 0;
	char *pos = buf;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	extStaDb_StaInfo_t *StaInfo_p;
	UINT8 *pRateTable = NULL;

	size = RATEINFO_DWORD_SIZE * RATE_ADAPT_MAX_SUPPORTED_RATES;
	pRateTable = wl_kzalloc(size, GFP_KERNEL);

	if (!pRateTable)
		return 0;

	pos += sprintf(pos, "\nClient: " MACSTR "\n", MAC2STR(macAddr));
#ifdef SOC_W906X
	if ((StaInfo_p = extStaDb_GetStaInfo(vmacSta_p,
					     (IEEEtypes_MacAddr_t *) macAddr,
					     STADB_DONT_UPDATE_AGINGTIME)) ==
	    NULL) {
		size = 0;
		goto exit;
	}
	wlFwGetRateTable(netdev, macAddr, pRateTable, size, 0,
			 StaInfo_p->StnId);
#else
	wlFwGetRateTable(netdev, macAddr, pRateTable, size, 0);
#endif /* SOC_W906X */
	size += ap8xLnxStat_clients_ratetable_pack(0, pRateTable, pos);

exit:
	wl_kfree(pRateTable);
	pRateTable = NULL;

	return size;
}

static ssize_t
ap8xLnxStat_clients_mu_mode_info(struct net_device *netdev,
				 UINT8 * macAddr, char *buf)
{
	ssize_t size = 0;
	UINT8 *pos = buf;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
	extStaDb_StaInfo_t *StaInfo_p;
	UINT8 mode[4] = { 0 }, state[64] = {
	0};
	acnt_tx_t *acnt_tx_record =
		(acnt_tx_t *) wlpptr->wlpd_p->acnt_tx_record;
	acnt_tx_t *acnt_tx_record_dump = NULL;
	UINT32 currIdx;
	UINT32 bw = 0;
	UINT32 tx_sgi_mode = 0;
	UINT32 tx_airtime = 0;
	UINT32 tx_dcm = 0;
	UINT32 idx = 0;
	SINT16 RSSI;
#ifndef SOC_W906X
	UINT16 a, b, c, d;
#endif
	UINT8 dl_ofdma, dl_mimo, ul_ofdma, ul_mimo;
	UINT32 acnt_cnt_in_5s = 0;
	UINT32 tx_mcs = 0;
	UINT32 tx_mcs_0 = 0, tx_mcs_1 = 0, tx_mcs_2 = 0, tx_mcs_3 =
		0, tx_mcs_4 = 0;

	if ((StaInfo_p = extStaDb_GetStaInfo(vmacSta_p,
					     (IEEEtypes_MacAddr_t *) macAddr,
					     STADB_DONT_UPDATE_AGINGTIME)) ==
	    NULL) {
		return size;
	}

	/* Get STA opmode */
	switch (StaInfo_p->ClientMode) {
	case BONLY_MODE:
		strcpy(mode, "b");
		break;
	case GONLY_MODE:
		strcpy(mode, "g");
		break;
	case NONLY_MODE:
		strcpy(mode, "n");
		break;
	case AONLY_MODE:
		strcpy(mode, "a");
		break;
	default:
		strcpy(mode, "NA");
		break;
	}
	if (*(mib->mib_ApMode) & AP_MODE_11AX) {
		/* AP is 11ax */
		if (StaInfo_p->he_cap_ie == HE_CAPABILITIES_IE &&
		    !(ismemzero
		      ((u8 *) & StaInfo_p->he_mac_cap,
		       sizeof(HE_Mac_Capabilities_Info_t)) &&
		      ismemzero((u8 *) & StaInfo_p->he_phy_cap,
				sizeof(HE_Phy_Capabilities_Info_t)))) {
			strcpy(mode, "ax");
		} else if (StaInfo_p->vhtCap.len) {
			strcpy(mode, "ac");
		}
	} else if (*(vmacSta_p->Mib802dot11->mib_ApMode) & AP_MODE_11AC) {
		/* AP is 11ac */
		if (StaInfo_p->vhtCap.len) {
			strcpy(mode, "ac");
		}
	}

	switch (StaInfo_p->State) {
	case UNAUTHENTICATED:
		strcpy(state, "UNAUTHENTICATED");
		break;
	case SME_INIT_AUTHENTICATING:
	case EXT_INIT_AUTHENTICATING:
		strcpy(state, "AUTHENTICATING");
		break;
	case AUTHENTICATED:
		strcpy(state, "AUTHENTICATED");
		break;
	case SME_INIT_DEAUTHENTICATING:
	case EXT_INIT_DEAUTHENTICATING:
		strcpy(state, "DEAUTHENTICATING");
		break;
	case SME_INIT_ASSOCIATING:
	case EXT_INIT_ASSOCIATING:
		strcpy(state, "ASSOCIATING");
		break;
	case ASSOCIATED:
		{
			int flagPsk = 0;

			if ((mib->Privacy->RSNEnabled == 1) ||
			    (mib->RSNConfigWPA2->WPA2Enabled == 1)) {
				if (*(mib->mib_wpaWpa2Mode) < 4) {	/* For PSK modes use internal WPA state machine */
					if (StaInfo_p->keyMgmtHskHsm.super.
					    pCurrent != NULL) {
						if (StaInfo_p->keyMgmtHskHsm.
						    super.pCurrent ==
						    &StaInfo_p->keyMgmtHskHsm.
						    hsk_end) {
							strcpy(state,
							       "PSK PASSED");
							flagPsk = 1;
						}
					}
				} else if (StaInfo_p->keyMgmtStateInfo.
					   RSNDataTrafficEnabled == TRUE) {
					strcpy(state, "KEY CONFIGURED");
					flagPsk = 1;
				}
			}
			if (!flagPsk)
				strcpy(state, "ASSOCIATED");
		}
		break;
	case SME_INIT_REASSOCIATING:
	case EXT_INIT_REASSOCIATING:
		strcpy(state, "REASSOCIATING");
		break;
	case SME_INIT_DEASSOCIATING:
	case EXT_INIT_DEASSOCIATING:
		strcpy(state, "DEASSOCIATING");
		break;
	default:
		break;
	}

#ifdef SOC_W906X
	RSSI = wl_util_get_rssi(netdev, &StaInfo_p->RSSI_path, NULL);
#else
	a = StaInfo_p->RSSI_path.a;
	b = StaInfo_p->RSSI_path.b;
	c = StaInfo_p->RSSI_path.c;
	d = StaInfo_p->RSSI_path.d;
	if (a >= 2048 && b >= 2048 && c >= 2048 && d >= 2048) {
		a = ((4096 - a) >> 4);
		b = ((4096 - b) >> 4);
		c = ((4096 - c) >> 4);
		d = ((4096 - d) >> 4);
	}
	RSSI = (a + b + c + d) / 4;
#endif

	/* Caculate tx_airtime */
	if ((!strcmp(mode, "ax") || !strcmp(mode, "ac")) &&
	    (acnt_tx_record != NULL)) {
		UINT32 ar_timestamp =
			(UINT32) (readl(wlpptr->ioBase1 + BBTX_TMR_TSF));
		UINT32 delta_time = 0;

		currIdx = (wlpptr->wlpd_p->acnt_tx_record_idx == 0) ?
			(ACNT_TX_RECORD_MAX -
			 1) : (wlpptr->wlpd_p->acnt_tx_record_idx - 1);
		acnt_tx_record_dump = acnt_tx_record;
		for (idx = 0; idx < ACNT_TX_RECORD_MAX; idx++) {
			if (StaInfo_p->StnId ==
			    acnt_tx_record_dump[currIdx].StnId &&
			    acnt_tx_record_dump[currIdx].NumBytes > 0) {
				delta_time =
					(ar_timestamp >
					 acnt_tx_record_dump[currIdx].
					 TimeStamp) ? (ar_timestamp -
						       acnt_tx_record_dump
						       [currIdx].
						       TimeStamp) : ((0xFFFFFFFF
								      -
								      acnt_tx_record_dump
								      [currIdx].
								      TimeStamp)
								     +
								     ar_timestamp);
				if (delta_time < 5 * 1000000) {
					/* 5 seconds */
					tx_airtime +=
						acnt_tx_record_dump[currIdx].
						AirTime;

					tx_mcs = (acnt_tx_record_dump[currIdx].
						  rateInfo & 0x00000F00) >> 8;
					if (tx_mcs == 0)
						tx_mcs_0++;
					else if (tx_mcs == 1)
						tx_mcs_1++;
					else if (tx_mcs == 2)
						tx_mcs_2++;
					else if (tx_mcs == 3)
						tx_mcs_3++;
					else if (tx_mcs == 4)
						tx_mcs_4++;

					if (acnt_cnt_in_5s == 0) {
						/* only get last record */
						tx_sgi_mode =
							(acnt_tx_record_dump
							 [currIdx].
							 rateInfo & 0x000000c0)
							>> 6;
						bw = (acnt_tx_record_dump
						      [currIdx].
						      rateInfo & 0x00000030) >>
				     4;
						tx_dcm = (acnt_tx_record_dump
							  [currIdx].
							  rateInfo & 0x00000008)
							>> 3;
						if (tx_dcm == 0 &&
						    tx_sgi_mode == 3) {
							tx_sgi_mode = 4;	/* 4xLTF 3.2us */
						}
					}
					acnt_cnt_in_5s++;
				} else {
					break;
				}
			}

			if (currIdx == 0)
				currIdx = ACNT_TX_RECORD_MAX - 1;
			else
				currIdx--;
		}
		if (acnt_cnt_in_5s > 0) {
			do_div(tx_airtime, acnt_cnt_in_5s);

			tx_mcs_0 *= 100;
			tx_mcs_1 *= 100;
			tx_mcs_2 *= 100;
			tx_mcs_3 *= 100;
			tx_mcs_4 *= 100;
			do_div(tx_mcs_0, acnt_cnt_in_5s);
			do_div(tx_mcs_1, acnt_cnt_in_5s);
			do_div(tx_mcs_2, acnt_cnt_in_5s);
			do_div(tx_mcs_3, acnt_cnt_in_5s);
			do_div(tx_mcs_4, acnt_cnt_in_5s);
		}
	}

	/* Get STA MU capabilities */
	dl_ofdma = dl_mimo = ul_ofdma = ul_mimo = 0;
	if (!strcmp(mode, "ax")) {
		/* dl/ul ofdma is mandatory in AX */
		dl_ofdma = ul_ofdma = 1;
		if (StaInfo_p->he_phy_cap.su_beamformee == 1 &&
		    ((StaInfo_p->he_phy_cap.beamformee_sts_le_80mhz >= 3) ||
		     (StaInfo_p->he_phy_cap.beamformee_sts_gt_80mhz >= 3))) {
			dl_mimo = 1;
		}
		if (StaInfo_p->he_phy_cap.full_bw_ul_mu == 1) {
			ul_mimo = 1;
		}
	} else if (!strcmp(mode, "ac")) {
		if (StaInfo_p->vhtCap.cap.MUBeamformeeCapable == 1) {
			dl_mimo = 1;
		}
	}
	if (StaInfo_p->operating_mode.ulmu_disable) {
		ul_ofdma = 0;
		dl_mimo = 0;
	}

	pos += sprintf(pos, "\nClient: " MACSTR "\n", MAC2STR(macAddr));
	pos += sprintf(pos, "StnId: %d\n", StaInfo_p->StnId);
	pos += sprintf(pos, "Aid: %d\n", StaInfo_p->Aid);
	pos += sprintf(pos, "Mode: %s%s\n", strcmp(mode, "NA") ? "802.11" : "",
		       mode);
	pos += sprintf(pos, "State: %s\n", state);
	pos += sprintf(pos, "RSSI: %d\n", RSSI);
	pos += sprintf(pos, "NumberofSoundingDimensions: %d\n",
		       StaInfo_p->vhtCap.cap.NumberofSoundingDimensions);
	pos += sprintf(pos, "RxNss: %d\n", StaInfo_p->vht_peer_RxNss);
	pos += sprintf(pos, "RxChannelWidth: %d\n",
		       StaInfo_p->vht_RxChannelWidth);
	pos += sprintf(pos, "MuCapabilites: %d\n",
		       StaInfo_p->vhtCap.cap.MUBeamformeeCapable);
	pos += sprintf(pos,
		       "dl_ofdma: %d, dl_mimo: %d, ul_ofdma: %d, ul_mimo: %d\n",
		       dl_ofdma, dl_mimo, ul_ofdma, ul_mimo);
	pos += sprintf(pos, "TxAirTime: %d\n", tx_airtime);
	pos += sprintf(pos,
		       "TxMCS0: %d, TxMCS1: %d, TxMCS2: %d, TxMCS3: %d, TxMCS4: %d\n",
		       tx_mcs_0, tx_mcs_1, tx_mcs_2, tx_mcs_3, tx_mcs_4);
	{
		rxppdu_airtime_t l_rxppdu_airtime;
		memcpy(&l_rxppdu_airtime, &StaInfo_p->rxppdu_airtime,
		       sizeof(rxppdu_airtime_t));
		pos += sprintf(pos,
			       "RxAirTime: %u, pktlen: %u, l-sig: %u, rxTs: %x\n",
			       StaInfo_p->rxppdu_airtime.rx_airtime,
			       l_rxppdu_airtime.dbg_sum_pktlen,
			       l_rxppdu_airtime.rx_info_aux.ppdu_len,
			       l_rxppdu_airtime.rx_info_aux.rxTs);
		pos += sprintf(pos,
			       "pktcnt: %u, rx_su_pktcnt: %u, rx_mu_pktcnt: %u, nss: %u, mcs: %u, bw: %u, gi_ltf: %u, Ndbps10x: %u\n",
			       l_rxppdu_airtime.dbg_sum_pktcnt,
			       l_rxppdu_airtime.dbg_su_pktcnt,
			       l_rxppdu_airtime.dbg_mu_pktcnt,
			       l_rxppdu_airtime.dbg_nss,
			       l_rxppdu_airtime.dbg_mcs,
			       l_rxppdu_airtime.dbg_bw,
			       l_rxppdu_airtime.dbg_gi_ltf,
			       l_rxppdu_airtime.dbg_Ndbps10x);
		pos += sprintf(pos,
			       " sum_rx_airtime: %llu, sum_rx_pktcnt: %llu, sum_rx_pktlen: %llu\n",
			       l_rxppdu_airtime.sum_rx_airtime,
			       l_rxppdu_airtime.sum_rx_pktcnt,
			       l_rxppdu_airtime.sum_rx_pktlen);
	}
	pos += sprintf(pos, "rx_tsf: %llu\n", StaInfo_p->rxppdu_airtime.rx_tsf);

	pos += sprintf(pos, "TxSGI: %d\n", tx_sgi_mode);
	pos += sprintf(pos, "TxBW: %d\n", bw);
	pos += sprintf(pos, "tx_bytes: %llu\n", StaInfo_p->tx_bytes);
	pos += sprintf(pos, "rx_bytes: %llu\n", StaInfo_p->rx_bytes);
	pos += sprintf(pos, "rateinfo: 0x%08x\n",
		       *(UINT32 *) & StaInfo_p->rx_info_aux.rate_info);
	pos += sprintf(pos, "timestamp: %llu\n", (UINT64) ktime_get_ns());
	size = pos - (UINT8 *) buf;

	return size;
}

char *
pkt_type_strn(u8 rxinfo_pkttype)
{
	switch (rxinfo_pkttype) {
	case 0:
		return "lgcy";
	case 1:
		return "11n";
	case 2:
		return "11ac";
	case 3:
		return "11ax";
	}
	return "";
}

ssize_t
ap8xLnxStat_clients_rxrate(struct net_device * netdev,
			   UINT8 * macAddr, char *buf)
{
	ssize_t size = 0;
	UINT8 *pos = buf;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	extStaDb_StaInfo_t *StaInfo_p;
	dbRateInfo_t *prate_info;
	U8 Nss = 0;

	if ((StaInfo_p = extStaDb_GetStaInfo(vmacSta_p,
					     (IEEEtypes_MacAddr_t *) macAddr,
					     STADB_DONT_UPDATE_AGINGTIME)) ==
	    NULL) {
		printk("%s(), failed to get stadb (%02x:%02x:%02x:%02x:%02x:%02x)\n", __func__, macAddr[0], macAddr[1], macAddr[2], macAddr[3], macAddr[4], macAddr[5]
			);
		size = 0;
		goto exit;
	}
	prate_info = &StaInfo_p->rx_info_aux.rate_info;
	Nss = StaInfo_p->rx_info_aux.nss;
	pos += sprintf(pos,
		       "%6s %5s %5s %5s %5s %5s %5s %4s %2s %5s %4s %5s %6s\n",
		       "Fmt", "STBC", "DCM", "BW", "SGI", "Nss", "RateId",
		       "GF/Pre", "PId", "LDPC", "BF", "TxAnt", "RxRate");
	pos += sprintf(pos,
		       "%6s %5d %5d %5d %5d %5d %5d %5d %5d %5d %5d %02x %d Mbps\n",
		       pkt_type_strn(prate_info->Format), (int)prate_info->Stbc,
		       (int)prate_info->Dcm, (int)prate_info->Bandwidth,
		       (int)prate_info->ShortGI, (int)Nss,
		       (int)prate_info->RateIDMCS & 0xf,
		       (int)prate_info->Preambletype, (int)prate_info->PowerId,
		       (int)prate_info->AdvCoding, (int)prate_info->BF,
		       prate_info->AntSelect, (int)getPhyRate(prate_info));
	size = pos - (UINT8 *) buf;
exit:

	return size;
}

static ssize_t
ap8xLnxStat_clients_show(struct kobject *kobj,
			 struct clients_attribute *attr, char *buf)
{
	ssize_t size = 0;
	UINT8 macAddr[IEEE80211_ADDR_LEN] =
		{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	const char *ifname = NULL;
	const char *name = (attr) ? attr->attr.name : NULL;
	struct kobject *parent_kobj = (kobj) ? kobj->parent : NULL;
	struct net_device *netdev = NULL;
	struct clients_table_attribute *tab_attr =
		container_of(attr, struct clients_table_attribute, attr);

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	if (tab_attr)
		memcpy(macAddr, tab_attr->macAddr, IEEE80211_ADDR_LEN);

	if (is_broadcast_ether_addr(macAddr)) {
		pr_err("%s: cannot get STA mac address\n", __func__);
		return size;
	}

	ifname = (parent_kobj) ? kobject_name(parent_kobj) : NULL;
	if ((ifname == NULL) || (!strlen(ifname))) {
		pr_err("%s: cannot find netdev, ifname is NULL\n", __func__);
		return size;
	}

	netdev = dev_get_by_name(&init_net, ifname);
	if (!netdev) {
		pr_err("%s: cannot find netdev by ifname:%s\n", __func__,
		       ifname);
		return size;
	}

	if (!name)
		return size;

	if (!strcmp(name, "summary"))
		size = ap8xLnxStat_clients_summary(netdev, macAddr, buf);
	else if (!strcmp(name, "ratetable"))
		size = ap8xLnxStat_clients_ratetable(netdev, macAddr, buf);
	else if (!strcmp(name, "mu_mode_info"))
		size = ap8xLnxStat_clients_mu_mode_info(netdev, macAddr, buf);
	else if (!strcmp(name, "rxrate"))
		size = ap8xLnxStat_clients_rxrate(netdev, macAddr, buf);
	else
		pr_err("%s: illegal operation <%s>\n", __func__, name);

	dev_put(netdev);
	return size;
}

static UINT8
ap8xLnxStat_clients_find_query(char *query_str)
{
	int i;

	for (i = 0; i < OPT_NUM; i++) {
		if (!strncmp(ap8xLnxStat_clients_query[i].query_str,
			     query_str, strlen(query_str)))
			return ap8xLnxStat_clients_query[i].query_opt;
	}

	return OPT_NUM;
}

static ssize_t
ap8xLnxStat_clients_query_get(struct kobject *kobj,
			      struct kobj_attribute *attr, char *buf)
{
	ssize_t size = 0;
	UINT8 macAddr[IEEE80211_ADDR_LEN] =
		{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	const char *ifname = NULL;
	struct net_device *netdev = NULL;
	struct kobject *parent_kobj = (kobj) ? kobj->parent : NULL;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	if (is_broadcast_ether_addr(macAddr_query)) {
		char *pos = buf;
		pos += sprintf(pos,
			       "\nPlease set client MAC address befor query!\n");
		pos += sprintf(pos,
			       "For the detail usage, please refer \"clients_help\"\n");
		size = pos - buf;
		return size;
	} else
		memcpy(macAddr, macAddr_query, IEEE80211_ADDR_LEN);

	ifname = (parent_kobj) ? kobject_name(parent_kobj) : NULL;
	if ((ifname == NULL) || (!strlen(ifname))) {
		pr_err("%s: cannot find netdev, ifname is NULL\n", __func__);
		return size;
	}

	netdev = dev_get_by_name(&init_net, ifname);
	if (!netdev) {
		pr_err("%s: cannot find netdev by ifname:%s\n", __func__,
		       ifname);
		return size;
	}

	switch (option_query) {
	case OPT_RATETABLE:
		size = ap8xLnxStat_clients_ratetable(netdev, macAddr, buf);
		break;
	case OPT_MU_MODE_INFO:
		size = ap8xLnxStat_clients_mu_mode_info(netdev, macAddr, buf);
		break;
	case OPT_RXRATE:
		size = ap8xLnxStat_clients_rxrate(netdev, macAddr, buf);
		break;
	case OPT_SUMMARY:
	default:
		size = ap8xLnxStat_clients_summary(netdev, macAddr, buf);
		break;
	}

	dev_put(netdev);
	return size;
}

static ssize_t
ap8xLnxStat_clients_query_set(struct kobject *kobj,
			      struct kobj_attribute *attr,
			      const char *buf, size_t count)
{
	UINT8 macAddr[IEEE80211_ADDR_LEN] =
		{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	char option[128] = { 0 };

	/* Read input parameters */
	if (sscanf(buf, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx %10s",
		   &macAddr[0], &macAddr[1], &macAddr[2],
		   &macAddr[3], &macAddr[4], &macAddr[5], option) <= 0) {
		pr_err("%s: cannot get STA mac address\n", __func__);
		return -EINVAL;
	}

	memcpy(macAddr_query, macAddr, IEEE80211_ADDR_LEN);

	if (strlen(option))
		option_query = ap8xLnxStat_clients_find_query(option);

	return count;
}

#define CLIENTS_ATTR(_name, _mode, _show, _store) \
	struct kobj_attribute clients_attr_##_name = __ATTR(_name, _mode, _show, _store)

/* The query attribute for specific STA information */
static CLIENTS_ATTR(query, S_IWUSR | S_IRUSR, ap8xLnxStat_clients_query_get,
		    ap8xLnxStat_clients_query_set);
static CLIENTS_ATTR(help, S_IWUSR | S_IRUSR, ap8xLnxStat_clients_help, NULL);

static struct attribute *ap8xLnxStat_clients_attrs[] = {
	&clients_attr_query.attr,
	&clients_attr_help.attr,
	NULL
};

static struct attribute_group ap8xLnxStat_clients_group = {
	.attrs = ap8xLnxStat_clients_attrs,
};

static struct attribute **
ap8xLnxStat_clients_attrs_alloc(ssize_t(*show) (struct kobject * kobj,
						struct clients_attribute * attr,
						char *buf),
				IEEEtypes_MacAddr_t * addr_p, int len)
{
	struct attribute **tab_attr;
	struct clients_table_attribute *element;
	int i;

	tab_attr = kcalloc(1 + len, sizeof(struct attribute *), GFP_KERNEL);
	if (!tab_attr)
		return NULL;

	for (i = 0; i < len; i++) {
		element = wl_kzalloc(sizeof(struct clients_table_attribute),
				     GFP_KERNEL);
		if (!element)
			goto exit;

		element->attr.attr.name =
			ap8xLnxStat_clients_query[i].query_str;
		element->attr.attr.mode = S_IRUGO;
		element->attr.show = show;
		element->attr.store = NULL;
		memcpy(element->macAddr, addr_p, IEEE80211_ADDR_LEN);

		sysfs_attr_init(&element->attr.attr);

		tab_attr[i] = &element->attr.attr;
	}

	return tab_attr;

exit:
	while (--i >= 0)
		wl_kfree(tab_attr[i]);
	wl_kfree(tab_attr);
	return NULL;
}

static void
ap8xLnxStat_clients_add(vmacApInfo_t * vmac_p, IEEEtypes_MacAddr_t * addr_p)
{
	int err = 0;
	char name[128];
	struct kobject *dev_kobj = NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 52)
	struct clients_kobject *clients_kobj = NULL;
#endif
	struct clients_kobject *clients_vap_kobj = NULL;
	struct clients_attribute_group *clients_attr = NULL;
	vmacApInfo_t *vmacSta_p = NULL;

	dev_kobj = &vmac_p->dev->dev.kobj;

	if (vmac_p->OpMode == WL_OP_MODE_STA ||
	    vmac_p->OpMode == WL_OP_MODE_VSTA)
		return;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 52)
	memset(name, 0x00, sizeof(name));
	vmacSta_p = (!vmac_p->master) ? vmac_p : vmac_p->master;
	strncpy(name, vmacSta_p->dev->name, sizeof(vmacSta_p->dev->name));

	clients_kobj =
		ap8xLnxStat_clients_kobj_found((const char *)name,
					       &ap8xLnxStat_clients_kobjs);
#endif

	clients_vap_kobj =
		ap8xLnxStat_clients_kobj_found((const char *)
					       kobject_name(dev_kobj),
					       &ap8xLnxStat_clients_vap_kobjs);

	if (!clients_vap_kobj) {
#if 0
		clients_vap_kobj = (struct clients_kobject *)
			ap8xLnxStat_clients_init(dev_kobj, MODE_AP);
		if (!clients_vap_kobj) {
			pr_err("%s: cannot create clients kobject\n", __func__);
			return;
		}
#endif
		pr_err("%s: cannot find clients kobject\n", __func__);
		return;
	}

	memset(name, 0x00, sizeof(name));
	MAC2FILENAME((UINT8 *) addr_p, name);

	if (clients_vap_kobj->conn_cnt > 0) {
		struct kernfs_node *kn = NULL;

		kn = kernfs_find_and_get(clients_vap_kobj->kobj->sd, name);
		if (kn) {
			kernfs_put(kn);
			pr_err("%s: client \"%s\" existed!\n",
			       kobject_name(dev_kobj), name);
			return;
		}
	}

	clients_attr =
		wl_kzalloc(sizeof(struct clients_attribute_group), GFP_KERNEL);
	if (!clients_attr) {
		pr_err("%s: cannot alloc memory for clients kobject\n",
		       __func__);
		return;
	}

	clients_attr->next = NULL;
	strncpy(clients_attr->name, name, MAX_MACFILENAME_LEN);
	clients_attr->group.name = clients_attr->name;
	clients_attr->group.attrs =
		ap8xLnxStat_clients_attrs_alloc(ap8xLnxStat_clients_show,
						addr_p, OPT_NUM);
	if (!clients_attr->group.attrs) {
		pr_err("%s: create attributes for %s failed\n", __func__, name);
		goto exit;
	}

	err = sysfs_create_group(clients_vap_kobj->kobj, &clients_attr->group);
	if (err) {
		pr_err("%s: create entry for clients failed (%d)\n",
		       __func__, err);
		goto exit;
	}

	ap8xLnxStat_clients_group_add(clients_attr, clients_vap_kobj);

	if (clients_vap_kobj->conn_cnt++ == 0) {
		err = sysfs_create_group(clients_vap_kobj->kobj,
					 &ap8xLnxStat_clients_group);
		if (err)
			pr_err("%s: create group for clients kobject failed (%d)\n", __func__, err);
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 52)
	/* set client symlink into radio interface */
	if (clients_kobj) {
		if (clients_kobj->conn_cnt > 0) {
			struct kernfs_node *kn = NULL;

			kn = kernfs_find_and_get(clients_kobj->kobj->sd, name);
			if (kn) {
				kernfs_put(kn);
				pr_err("%s: client \"%s\" existed!\n",
				       __func__, name);
				/* client attribute has been added in group, *
				 * don't free client attribute memory        */
				return;
			}
		}

		err = __compat_only_sysfs_link_entry_to_kobj(clients_kobj->kobj,
							     clients_vap_kobj->
							     kobj,
							     (const char *)
							     name);
		if (err)
			pr_err("%s: create link for clients failed (%d)\n",
			       __func__, err);
		else {
			if (clients_kobj->conn_cnt++ == 0) {
				err = sysfs_create_group(clients_kobj->kobj,
							 &ap8xLnxStat_clients_group);
				if (err)
					pr_err("%s: create group for clients kobject failed (%d)\n", __func__, err);
			}
		}
	}
#endif

	return;

exit:
	ap8xLnxStat_clients_group_free(clients_attr);
}

static void
ap8xLnxStat_clients_del(vmacApInfo_t * vmac_p, IEEEtypes_MacAddr_t * addr_p)
{
	char name[128];
	vmacApInfo_t *vmacSta_p = NULL;
	struct clients_kobject *clients_kobj = NULL;
	struct clients_kobject *clients_vap_kobj = NULL;
	struct clients_attribute_group *clients_attr = NULL;

	if (vmac_p->OpMode == WL_OP_MODE_STA ||
	    vmac_p->OpMode == WL_OP_MODE_VSTA)
		return;

	memset(name, 0x00, sizeof(name));
	vmacSta_p = (!vmac_p->master) ? vmac_p : vmac_p->master;
	strncpy(name, vmacSta_p->dev->name, sizeof(vmacSta_p->dev->name));

	clients_kobj =
		ap8xLnxStat_clients_kobj_found((const char *)name,
					       &ap8xLnxStat_clients_kobjs);

	clients_vap_kobj =
		ap8xLnxStat_clients_kobj_found((const char *)vmac_p->dev->dev.
					       kobj.name,
					       &ap8xLnxStat_clients_vap_kobjs);

	if (clients_vap_kobj) {
		memset(name, 0x00, sizeof(name));
		MAC2FILENAME((UINT8 *) addr_p, name);

		clients_attr =
			ap8xLnxStat_clients_group_found((const char *)name,
							clients_vap_kobj);
		if (!clients_attr) {
			pr_err("%s: cannot find the match clients attribute group %s\n", __func__, name);
			return;
		}

		if (clients_kobj) {
			sysfs_remove_link(clients_kobj->kobj,
					  (const char *)name);
			if (clients_kobj->conn_cnt > 0) {
				if (--clients_kobj->conn_cnt == 0) {
					sysfs_remove_group(clients_kobj->kobj,
							   &ap8xLnxStat_clients_group);
				}
			}
		}

		sysfs_remove_group(clients_vap_kobj->kobj,
				   &clients_attr->group);

		ap8xLnxStat_clients_group_del(clients_attr, clients_vap_kobj);

		if (clients_vap_kobj->conn_cnt > 0) {
			if (--clients_vap_kobj->conn_cnt == 0) {
				sysfs_remove_group(clients_vap_kobj->kobj,
						   &ap8xLnxStat_clients_group);
			}
		}
	}

	return;
}

void
ap8xLnxStat_clients_WQadd(vmacApInfo_t * vmac_p,
			  IEEEtypes_MacAddr_t * addr_p, UINT8 hdl)
{
	struct net_device *netdev = vmac_p->dev;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct clients_WQ_item *wqitem;
	unsigned long listflags;

	if ((!wlpptr) || (!wlpptr->wlpd_p))
		return;

	wqitem = wl_kzalloc(sizeof(struct clients_WQ_item), GFP_ATOMIC);
	if (!wqitem) {
		pr_err("%s: cannot alloc memory for clients Work Queue\n",
		       __func__);
		return;
	}

	wqitem->vmac_p = vmac_p;
	memcpy(&wqitem->addr, addr_p, sizeof(IEEEtypes_MacAddr_t));
	wqitem->hdl = hdl;

	SPIN_LOCK_IRQSAVE(&wlpptr->wlpd_p->locks.sysfsHdlListLock, listflags);
	ListPutItem(&wlpptr->wlpd_p->sysfsSTAHdlList, (ListItem *) wqitem);
	SPIN_UNLOCK_IRQRESTORE(&wlpptr->wlpd_p->locks.sysfsHdlListLock,
			       listflags);

	schedule_work(&wlpptr->wlpd_p->sysfstask);
	return;
}

void
ap8xLnxStat_clients_WQhdl(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct clients_WQ_item *wqitem;
	List sysfsSTAHdlList;
	unsigned long listflags;
	unsigned int listcnt = 0;
	int i;

	if ((!wlpptr) || (!wlpptr->wlpd_p))
		return;

	SPIN_LOCK_IRQSAVE(&wlpptr->wlpd_p->locks.sysfsHdlListLock, listflags);
	memcpy(&sysfsSTAHdlList, &wlpptr->wlpd_p->sysfsSTAHdlList,
	       sizeof(List));
	wlpptr->wlpd_p->sysfsSTAHdlList.head = NULL;
	wlpptr->wlpd_p->sysfsSTAHdlList.tail = NULL;
	wlpptr->wlpd_p->sysfsSTAHdlList.cnt = 0;
	SPIN_UNLOCK_IRQRESTORE(&wlpptr->wlpd_p->locks.sysfsHdlListLock,
			       listflags);

	listcnt = sysfsSTAHdlList.cnt;
	for (i = 0; i < listcnt; i++) {
		wqitem = (struct clients_WQ_item *)
			ListGetItem(&sysfsSTAHdlList);
		if (!wqitem)
			continue;

		switch (wqitem->hdl) {
		case HDL_ADD:
			ap8xLnxStat_clients_add(wqitem->vmac_p, &wqitem->addr);
			break;
		case HDL_DEL:
			ap8xLnxStat_clients_del(wqitem->vmac_p, &wqitem->addr);
			break;
		default:
			break;
		}

		wl_kfree(wqitem);
		wqitem = NULL;
	}

	return;
}
#else /* SYSFS_STADB_INFO */
void
ap8xLnxStat_clients_WQadd(vmacApInfo_t * vmac_p, IEEEtypes_MacAddr_t * addr_p)
{
	return;
};

void
ap8xLnxStat_clients_WQhdl(struct net_device *netdev)
{
	return;
};
#endif /* SYSFS_STADB_INFO */
#else
int
ap8xLnxStat_sysfs_init(struct net_device *netdev)
{
	return 1;
};

int
ap8xLnxStat_sysfs_exit(struct net_device *netdev)
{
	return 1;
};

void *
ap8xLnxStat_clients_init(struct net_device *netdev, UINT8 mode)
{
	return;
};

void
ap8xLnxStat_clients_WQadd(vmacApInfo_t * vmac_p, IEEEtypes_MacAddr_t * addr_p)
{
	return;
};

void
ap8xLnxStat_clients_WQhdl(struct net_device *netdev)
{
	return;
};
#endif
#else
void *
ap8xLnxStat_vap_init(struct net_device *netdev)
{
	return;
};

int
ap8xLnxStat_vap_exit(struct net_device *netdev)
{
	return 1;
};

int
ap8xLnxStat_sysfs_init(struct net_device *netdev)
{
	return 1;
};

int
ap8xLnxStat_sysfs_exit(struct net_device *netdev)
{
	return 1;
};

void *
ap8xLnxStat_clients_init(struct net_device *netdev, UINT8 mode)
{
	return;
};

void
ap8xLnxStat_clients_WQadd(vmacApInfo_t * vmac_p, IEEEtypes_MacAddr_t * addr_p)
{
	return;
};

void
ap8xLnxStat_clients_WQhdl(struct net_device *netdev)
{
	return;
};
#endif /* #ifdef SOC_W906X */
#endif /* #if defined(SOC_W906X) || defined(AP8X_STATISTICS) */
