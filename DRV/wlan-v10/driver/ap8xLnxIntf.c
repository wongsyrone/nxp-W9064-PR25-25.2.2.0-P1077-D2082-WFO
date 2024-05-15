/** @file ap8xLnxIntf.c
 * IMPORTANT
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
#include <linux/module.h>
#include <linux/ethtool.h>
#include <linux/vmalloc.h>
#ifdef SOC_W906X
// PCI reset test
//  fix compile error for kernel 4.7.3
#include <linux/of_gpio.h>
#include <linux/pci.h>
#endif /* SOC_W906X */

#include "wldebug.h"
#include "ap8xLnxFwdl.h"
#include "ap8xLnxRegs.h"
#include "ap8xLnxVer.h"
#include "ap8xLnxDesc.h"
#include "ap8xLnxBQM.h"
#include "ap8xLnxFwcmd.h"
#include "ap8xLnxXmit.h"
#include "ap8xLnxIntf.h"
#include "ap8xLnxRecv.h"
#ifdef CB_SUPPORT
#include "ap8xLnxCB.h"
#endif // CB_SUPPORT
#ifdef SOC_W906X
#include "ap8xLnxAcnt.h"
#endif
#if defined(MRVL_MUG_ENABLE)
#include "ap8xLnxMug.h"
#endif /* #if defined(MRVL_MUG_ENABLE) */
#include "ap8xLnxWlLog.h"
#include "ap8xLnxEvent.h"
#include "mib.h"
#include "wlvmac.h"
#include <linux/workqueue.h>
#if defined(MFG_SUPPORT)
#include "wl_mib.h"
#endif
#include "wl_hal.h"
#include "wlApi.h"
#include "smeMain.h" // MRVL_DFS
#ifdef CLIENT_SUPPORT
#include "linkmgt.h"
#include "ap8xLnxWlLog.h"
#include "mlmeApi.h"
#include "mlmeParent.h"
#endif /* CLIENT_SUPPORT */
#include "StaDb.h"
#ifdef EWB
#include "ewb_hash.h"
#endif
#include "dfsMgmt.h"
#include "macMgmtMlme.h"
#include "wds.h"

#ifdef WTP_SUPPORT
#include <linux/netlink.h>
#endif
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/slab.h>
#include <linux/mm.h> /* mmap related stuff */
#include <linux/io.h>
#include <linux/of.h>
#ifdef MV_NSS_SUPPORT
#include <net/mvebu/mv_nss.h>
#endif
#ifdef CFG80211
#include "cfg80211.h"
#endif
#include "ap8xLnxMonitor.h"
#if defined(AIRTIME_FAIRNESS)
#include "ap8xLnxAtf.h"
#endif /* AIRTIME_FAIRNESS */
#ifdef IEEE80211K
#include "msan_report.h"
#endif // IEEE80211K
#ifdef CONFIG_MARVELL_MOCHI_DRIVER
#include <linux/mci_if.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 120)
enum mci_status
{
	MCI_OK,
	MCI_FAIL,
	MCI_PHY_TRAIN_FAIL,
	MCI_UNSUPPORTED_SPEED,
};
#endif
#endif /* CONFIG_MARVELL_MOCHI_DRIVER */
#ifdef WIFI_DATA_OFFLOAD
#include "ipc-ops.h"
#include "dol-ops.h"
#include "dol_core.h"
#endif

#ifndef VM_RESERVED
#define VM_RESERVED (VM_DONTEXPAND | VM_DONTDUMP)
#endif
/** local definitions **/
/* Match table for of_platform binding */
static const struct of_device_id wldriver_of_match[] = {
	{
		.compatible = "mrvl,sc5",
	},
	{
		.compatible = "marvell,sc5",
	},
	{},
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
static struct pci_device_id wlid_tbl[MAX_CARDS_SUPPORT + 1] = {
	{0x1b4b, 0x2a02, PCI_ANY_ID, PCI_ANY_ID, 0, 0,
	 (unsigned long)"NXP AP-8x 802.11 adapter"},
	{0x1b4b, PCI_ANY_ID, PCI_ANY_ID, PCI_ANY_ID, 0, 0,
	 (unsigned long)"NXP AP-8x 802.11 adapter 1"},
	{0, 0, 0, 0, 0, 0,
	 0},
	{0, 0, 0, 0, 0, 0,
	 0}};

#else
static struct pci_device_id wlid_tbl[MAX_CARDS_SUPPORT + 1] __devinitdata = {
	{0x11ab, 0x2a02, PCI_ANY_ID, PCI_ANY_ID, 0, 0,
	 (unsigned long)"NXP AP-8x 802.11 adapter"},
	{0x11ab, PCI_ANY_ID, PCI_ANY_ID, PCI_ANY_ID, 0, 0,
	 (unsigned long)"NXP AP-8x 802.11 adapter 1"},
	{0, 0, 0, 0, 0, 0,
	 0},
	{0, 0, 0, 0, 0, 0,
	 0}};
#endif
MODULE_AUTHOR("NXP");
MODULE_LICENSE("GPL");
MODULE_SUPPORTED_DEVICE("NXP AP-8x 802.11 adapter");
MODULE_DEVICE_TABLE(of, wldriver_of_match);
MODULE_DEVICE_TABLE(pci, wlid_tbl);

char *DRV_NAME = "wdev";
char *DRV_NAME_VMAC = "ap";

module_param(DRV_NAME, charp, 0);
MODULE_PARM_DESC(DRV_NAME, "Init physical device name");
module_param(DRV_NAME_VMAC, charp, 0);
MODULE_PARM_DESC(DRV_NAME_VMAC, "Init visual ap name");

unsigned int dbg_level = DEFAULT_WLDBG_LEVELS;
unsigned int dbg_class = DEFAULT_WLDBG_CLASSES;
unsigned int dbg_stop_tx_pending = 0;
unsigned int dbg_max_tx_pending = 40000;
unsigned int dbm_buf_num_pfw = 8;
module_param(dbg_max_tx_pending, uint, 0644);
MODULE_PARM_DESC(dbg_max_tx_pending, "Max num of Tx pending pkt");

unsigned int dbg_max_tx_pend_cnt_per_sta = 4196;
module_param(dbg_max_tx_pend_cnt_per_sta, uint, 0644);
MODULE_PARM_DESC(dbg_max_tx_pend_cnt_per_sta,
				 "Max num of Tx pending pkt per STA");

unsigned int dbg_max_tx_pend_cnt_per_q = 4096;
module_param(dbg_max_tx_pend_cnt_per_q, uint, 0644);
MODULE_PARM_DESC(dbg_max_tx_pend_cnt_per_q,
				 "Max num of Tx pending pkt per Queue");

unsigned int dbg_max_tx_pend_cnt_per_mgmt_q = 128;
module_param(dbg_max_tx_pend_cnt_per_mgmt_q, uint, 0644);
MODULE_PARM_DESC(dbg_max_tx_pend_cnt_per_mgmt_q,
				 "Max num of Tx pending pkt per Mgmt Queue");

unsigned int dbg_max_tx_pend_cnt_per_bcast_q = 128;
module_param(dbg_max_tx_pend_cnt_per_bcast_q, uint, 0644);
MODULE_PARM_DESC(dbg_max_tx_pend_cnt_per_bcast_q,
				 "Max num of Tx pending pkt per BCAST Queue");

unsigned int dbg_tcp_ack_drop_skip = 1;
module_param(dbg_tcp_ack_drop_skip, uint, 0644);
MODULE_PARM_DESC(dbg_tcp_ack_drop_skip, "TCP ACK packet drop rate");

unsigned int dbg_tx_pend_cnt_ctrl = 1;
module_param(dbg_tx_pend_cnt_ctrl, uint, 0644);
MODULE_PARM_DESC(dbg_tx_pend_cnt_ctrl, "Dynamic tx pending control");

unsigned int dbg_max_tx_pending_lo = 20000;
module_param(dbg_max_tx_pending_lo, uint, 0644);
MODULE_PARM_DESC(dbg_max_tx_pending_lo,
				 "Max num of Tx pending pkt when free mem is low");

unsigned int dbg_max_tx_pend_cnt_per_sta_lo = 1074;
module_param(dbg_max_tx_pend_cnt_per_sta_lo, uint, 0644);
MODULE_PARM_DESC(dbg_max_tx_pend_cnt_per_sta_lo,
				 "Max num of Tx pending pkt per STA when free mem is low");

unsigned int dbg_max_tx_pend_cnt_per_q_lo = 1024;
module_param(dbg_max_tx_pend_cnt_per_q_lo, uint, 0644);
MODULE_PARM_DESC(dbg_max_tx_pend_cnt_per_q_lo,
				 "Max num of Tx pending pkt per Queue when free mem is low");

module_param(dbg_level, uint, 0644);
MODULE_PARM_DESC(dbg_level, "Driver debug level");
module_param(dbg_class, uint, 0644);
MODULE_PARM_DESC(dbg_class, "Driver debug class");
module_param(dbg_stop_tx_pending, uint, 0644);
MODULE_PARM_DESC(dbg_stop_tx_pending, "Disable tx pending protection");
module_param(dbm_buf_num_pfw, uint, 0644);
MODULE_PARM_DESC(dbm_buf_num_pfw, "Number of PKT number for PFW TXQ");

BOOLEAN CheckSMACReady(struct net_device *netdev);

unsigned int sysintr;
module_param(sysintr, uint, 0644);
MODULE_PARM_DESC(sysintr, "Sys Interrupt Num");

unsigned int pci_only;
module_param(pci_only, uint, 0644);
MODULE_PARM_DESC(pci_only, "Only PCI interface is enabled");

#if defined(ACNT_REC) && defined(SOC_W906X)
unsigned int rxacnt_idmsg = 0;
module_param(rxacnt_idmsg, uint, 0644);
MODULE_PARM_DESC(rxacnt_msg, "Rx Acnt Id Msg");
#endif // if defined(ACNT_REC) && defined (SOC_W906X)

#if defined(TXACNT_REC) && defined(SOC_W906X)
unsigned int txacnt_msg = 0;
module_param(txacnt_msg, uint, 0644);
MODULE_PARM_DESC(txacnt_msg, "Tx Acnt Msg");

unsigned int txacnt_idmsg = 0;
module_param(txacnt_idmsg, uint, 0644);
MODULE_PARM_DESC(txacnt_msg, "Tx Acnt Id Msg");
#endif // defined(TXACNT_REC) && defined (SOC_W906X)

unsigned int dbg_invalid_skb = 0;
module_param(dbg_invalid_skb, uint, 0644);
MODULE_PARM_DESC(dbg_invalid_skb, "Enable debug trace for invalid skb");

unsigned int bss_num = NUMOFAPS;
module_param(bss_num, uint, S_IRUGO);
MODULE_PARM_DESC(bss_num, "Max supported BSS number");

unsigned int sta_num = MAX_STNS;
module_param(sta_num, uint, S_IRUGO);
MODULE_PARM_DESC(sta_num, "Max supported STA number");

unsigned int mem_dbg = 0;
module_param(mem_dbg, uint, S_IRUGO);
MODULE_PARM_DESC(mem_dbg, "Dymanic L0/L1 buffer BF memory");

unsigned int hm_gpio_trigger = 2;
module_param(hm_gpio_trigger, uint, S_IRUGO);
MODULE_PARM_DESC(hm_gpio_trigger, "GPIO trigger mode");

#ifdef WIFI_DATA_OFFLOAD
unsigned int wfo_disable = 0;
module_param(wfo_disable, uint, S_IRUGO);
MODULE_PARM_DESC(wfo_disable, "Disable wfo function of radio");
#endif

#define DEF_MAX_RECYCLE_CNT 5000
unsigned int max_recycle_cnt = DEF_MAX_RECYCLE_CNT;
module_param(max_recycle_cnt, uint, 0644);
MODULE_PARM_DESC(max_recycle_cnt, "Max pkt recycle count");

// Display txqid of the packet or not. Used for mmdu debug only
unsigned int txqid_msg = FALSE;
module_param(txqid_msg, uint, 0644);
MODULE_PARM_DESC(txqid_msg, "txqid msg");

#ifdef FS_CAL_FILE_SUPPORT
char *CAL_FILE_PATH = "./";
module_param(CAL_FILE_PATH, charp, 0);
MODULE_PARM_DESC(CAL_FILE_PATH, "FS CAL File path");
#endif
#define SET_MODULE_OWNER(x)

#define CMD_BUF_SIZE 0x4000
// #ifdef SSU_SUPPORT
///* SSU buffer size 32MB - currently larger than needed ~17MB for max 700*25000 100ms */
// #define SSU_BUF_SIZE        0x400000
// #endif
#define MAX_ISR_ITERATION 1 // 10

// #define BARBADO_RESET

#ifdef BARBADO_RESET
#define WDEV0_RESET_PIN 16
#define WDEV1_RESET_PIN 24
#else
#define WDEV0_RESET_PIN 55
#define WDEV1_RESET_PIN 24
#endif

int use_localadmin_addr = 1;
module_param(use_localadmin_addr, int, 0644);
MODULE_PARM_DESC(use_localadmin_addr,
				 "Use locally administered MAC address for the virtual APs");

int wfa_11ax_pf = 0;
module_param(wfa_11ax_pf, int, S_IRUGO);
MODULE_PARM_DESC(wfa_11ax_pf, "WFA 11AX Plugfest");

/*dynamic RTS/CTS protection */
int protect_dynamic = 1; // dynamic protect check is enabled
module_param(protect_dynamic, int, 0644);
MODULE_PARM_DESC(protect_dynamic, "enable protection check");

int protect_tx_rate_thres = 0; // 0Mbps
module_param(protect_tx_rate_thres, int, 0644);
MODULE_PARM_DESC(protect_tx_rate_thres,
				 "Tx rate threshold for protection check");

int protect_rx_rate_thres = 100000; // 100kbps
module_param(protect_rx_rate_thres, int, 0644);
MODULE_PARM_DESC(protect_rx_rate_thres,
				 "Rx rate threshold for protection check");

int txq_per_sta_timeout = 0; // 0: disable >0: timeout (us)
module_param(txq_per_sta_timeout, int, 0644);
MODULE_PARM_DESC(txq_per_sta_timeout,
				 "WFA 11AX Plugfest: for tx per sta fairly. 0: disable xmit fairly. >0: timeout");

int rssi_threshold = 85; // rssi threshhold
module_param(rssi_threshold, int, 0644);
MODULE_PARM_DESC(rssi_threshold, "rssi threshold");

int rssi_nf_delta = 10; // rssi nf delta
module_param(rssi_nf_delta, int, 0644);
MODULE_PARM_DESC(rssi_nf_delta, "rssi nf delta");

int ext_weight_1611 = 500;
module_param(ext_weight_1611, int, 0644);
MODULE_PARM_DESC(ext_weight_1611, "extra weight for 1/6/11");

unsigned int chld_nf_delta = 7; // channel load and nf delta
module_param(chld_nf_delta, uint, 0644);
MODULE_PARM_DESC(chld_nf_delta, "channel load and noise floor delta");

unsigned int chld_ceil = 12; // channel load ceil for 40M
module_param(chld_ceil, uint, 0644);
MODULE_PARM_DESC(chld_ceil, "channel load ceil for 40M");

unsigned int abs_nf_floor = 70; // nf floor for 40M
module_param(abs_nf_floor, uint, 0644);
MODULE_PARM_DESC(abs_nf_floor, "noise floor for 40M");

unsigned int acs_cal = 1;
module_param(acs_cal, uint, 0644);
MODULE_PARM_DESC(abs_cal, "acs calibration");

#define MACH_COMPAT_MAX_LEN 50
const static char mach_compat[PLATFORM_ID_MAX][MACH_COMPAT_MAX_LEN] = {
	"marvell,armada7040", /* A3900/A7K */
	"marvell,armada8040", /* A8K */
	"marvell,armada380",  /* A390 */
	"marvell,armada38x",  /* A380 */
};

const static struct intr_info intr_info_tbl_generic = {0, 32};
const static struct intr_info intr_info_tbl_mci = {0, 32};

const static struct intr_info intr_info_tbl[PLATFORM_ID_MAX] = {
	{0x1D, 32}, /* PCI: A3900_A7K */
	{0x1C, 32}, /* PCI: A8K */
	{0, 16},	/* PCI: A390 */
	{0, 16},	/* PCI: A380 */
};

int platform_id = PLATFORM_ID_MAX;

#ifndef __MOD_INC_USE_COUNT
#define WL_MOD_INC_USE(_m, _err)                         \
	if (1 /*isIfUsed == WL_FALSE*/)                      \
	{                                                    \
		isIfUsed++;                                      \
		if (!try_module_get(_m))                         \
		{                                                \
			printk("%s: try_module_get?!?\n", __func__); \
			_err;                                        \
		}                                                \
	}
#define WL_MOD_DEC_USE(_m) \
	if (isIfUsed)          \
	{                      \
		--isIfUsed;        \
		module_put(_m);    \
	}
#else
#define WL_MOD_INC_USE(_m, _err)    \
	if (1 /*isIfUsed == WL_FALSE*/) \
	{                               \
		isIfUsed++;                 \
		MOD_INC_USE_COUNT;          \
	}
#define WL_MOD_DEC_USE(_m) \
	if (isIfUsed)          \
	{                      \
		--isIfUsed;        \
		MOD_DEC_USE_COUNT; \
	}
#endif

#ifdef CLIENT_SUPPORT
/* This is for MLME use, please don't change without MLME owner input */
struct net_device *mainNetdev_p[NUM_OF_WLMACS];
/* end MLME use */

#endif /* CLIENT_SUPPORT */
/* default settings */

/** external functions **/
extern void *ap8xLnxStat_vap_init(struct net_device *netdev);
extern int ap8xLnxStat_vap_exit(struct net_device *netdev);
extern void *ap8xLnxStat_clients_init(struct net_device *netdev, UINT8 mode);
extern void ap8xLnxStat_clients_deinit(struct net_device *netdev, UINT8 mode);
extern int ap8xLnxStat_sysfs_init(struct net_device *netdev);
extern int ap8xLnxStat_sysfs_exit(struct net_device *netdev);
#ifdef SYSFS_STADB_INFO
extern void ap8xLnxStat_clients_WQhdl(struct net_device *netdev);
#endif /* SYSFS_STADB_INFO */
extern int ap8x_stat_proc_register(struct net_device *dev);
extern int ap8x_dump_proc_register(struct net_device *dev);
extern int ap8x_stat_proc_unregister(struct net_device *dev);
extern int ap8x_dump_proc_unregister(struct net_device *dev);
extern int ap8x_remove_folder(void);
extern vmacApInfo_t *Mac_Init(struct wlprivate *wlp, struct net_device *dev,
							  char *addr, UINT32 mode, int phyMacId);

extern void MrvlMICErrorHdl(vmacApInfo_t *vmacSta_p,
							COUNTER_MEASURE_EVENT event);
extern void MrvlICVErrorHdl(vmacApInfo_t *vmacSta_p);
extern extStaDb_Status_e extStaDb_RemoveStaNSendDeauthMsg(vmacApInfo_t *vmac_p,
														  IEEEtypes_MacAddr_t *
															  Addr_p);

extern void wl_register_dump_func(struct wlprivate_data *wlpd_p);
extern void wl_unregister_dump_func(struct wlprivate_data *wlpd_p);

#ifdef CCK_DESENSE
extern void cck_desense_timer_start(struct net_device *netdev);
extern void cck_desense_timer_stop(struct net_device *netdev);
#endif /* CCK_DESENSE */

#if defined(ACNT_REC) && defined(SOC_W906X)
static void wlRxInfoHdlr(struct net_device *netdev);
#endif // #if defined(ACNT_REC) && defined (SOC_W906X)

/** external data **/
extern Timer wfa_test_timer;
extern macmgmtQ_CmdBuf_t *smeCmdBuf_q;

/** internal functions **/

static int wlInit_wds(struct wlprivate *wlpptr);
static int wlreset_wds(struct net_device *netdev);
static void wlIntrPoll(struct net_device *netdev);
#ifdef CLIENT_SUPPORT
static int wlInit_client(struct wlprivate *wlp, unsigned char *macAddr_p,
						 unsigned char *ApRootmacAddr_p);
static int wlstop_client(struct net_device *netdev);
static BOOLEAN hook_intr(struct wlprivate *wlpptr, UINT32 isr_id);
int wlreset_client(struct net_device *netdev);
static void wlPowerResetFw(struct net_device *netdev);

extern void rtnl_lock(void);
extern void rtnl_unlock(void);

UINT8 tmpScanResults[NUM_OF_WLMACS][MAX_SCAN_BUF_SIZE];
UINT8 tmpNumScanDesc[NUM_OF_WLMACS];
#endif
#ifdef MBSS
static int wlstop_mbss(struct net_device *netdev);
static int wlopen_mbss(struct net_device *netdev);
#endif
#ifdef MRVL_DFS
int wlRadarDetection(struct net_device *netdev, UINT8 from);
int wlApplyCSAChannel(struct net_device *netdev);
#endif

int wlConsecTxFail(struct net_device *netdev);
#ifdef SOC_W906X
int wlOffChanTask(struct net_device *netdev);
static void wlOffChannelStop(struct net_device *netdev);
#else  // 906X off-channel
int wlOffChanDone(struct net_device *netdev);
#endif // 906X off-channel

/** public data **/

/** private data **/
static int isIfUsed = 0;
static UINT8 ChunkNum = 0;
static struct dentry *ACNT_f0, *ACNT_f1;

/** private functions **/
static int __init wlmodule_init(void);
static void __exit wlmodule_exit(void);
static void wlprobe_set_reg_value(struct wlprivate *wlpptr);
static void wlprobe_set_intr_info(struct wlprivate *wlpptr);
static int wl_get_platform_id(void);
static int wlprobe_mci(struct platform_device *pdev);
static int wlremove_mci(struct platform_device *pdev);
static int wlsuspend_mci(struct device *dev);
static int wlresume_mci(struct device *dev);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
static int wlprobe_pci(struct pci_dev *, const struct pci_device_id *);
static void wlremove_pci(struct pci_dev *);
#else
static int __devinit wlprobe_pci(struct pci_dev *,
								 const struct pci_device_id *);
static void __devexit wlremove_pci(struct pci_dev *);
#endif
static int wlsuspend_pci(struct pci_dev *, pm_message_t);
static int wlresume_pci(struct pci_dev *);
#ifdef WL_DEBUG
static const char *wlgetAdapterDescription(struct wlprivate *wlpptr, u_int32_t,
										   u_int32_t);
#endif
static int wlInit_mbss(struct wlprivate *wlp, unsigned char *macAddr);
#ifdef ENABLE_MONIF
static int wlInit_monif(struct wlprivate *wlp, unsigned char *macAddr);
#endif

#define SMAC_CTRLBASE_NSS_MCI_HI_VAL_INTR 0x00
#define SMAC_CTRLBASE_NSS_PCIE_HI_VAL_INTR 0x20
#define SMAC_CTRLBASE_NSS_PCIE_HI_VAL_NOINTR 0x30
// Default: No interrupt => enable it if necessary
#define SMAC_CTRLBASE_NSS_PCIE_HI_VAL SMAC_CTRLBASE_NSS_PCIE_HI_VAL_NOINTR

static const struct dev_pm_ops wldriver_mci_pm_ops = {
	.suspend = wlsuspend_mci,
	.resume = wlresume_mci,
};

static struct platform_driver wldriver_mci = {
	.probe = wlprobe_mci,
	.remove = wlremove_mci,
	.driver = {
		.name = MOD_NAME,
		.pm = &wldriver_mci_pm_ops,
		.of_match_table = wldriver_of_match,
	},
};

static struct pci_driver wldriver_pci = {
	//.name     = DRV_NAME,
	.name = MOD_NAME,
	.id_table = wlid_tbl,
	.probe = wlprobe_pci,
	.remove = wlremove_pci,
	.suspend = wlsuspend_pci,
	.resume = wlresume_pci,
};
struct wlprivate_data *global_private_data[MAX_CARDS_SUPPORT] = {NULL};

U8 gprv_dat_refcnt = 0;
static int wlopen(struct net_device *);
static int wlstop(struct net_device *);
static void wlsetMcList(struct net_device *);
static struct net_device_stats *wlgetStats(struct net_device *);
static int wlsetMacAddr(struct net_device *, void *);
static int wlchangeMtu(struct net_device *, int);
int wlreset(struct net_device *);
int wlreset_mbss(struct net_device *netdev);
int wlreset_client(struct net_device *netdev);
static void wlFwHardreset(struct net_device *netdev, int);
static void wlFwReDownload(struct net_device *netdev);

static void wltxTimeout(struct net_device *);
module_init(wlmodule_init);
module_exit(wlmodule_exit);
#ifdef NAPI
void wlInterruptMask(struct net_device *netdev, int mask);
#endif
#ifdef WDS_FEATURE
static int wlopen_wds(struct net_device *);
int wlstop_wds(struct net_device *);
int wlStop_wdsDevs(struct wlprivate *wlpptr);
static int wlsetMacAddr_wds(struct net_device *, void *);
static int wlchangeMtu_wds(struct net_device *, int);
static void wltxTimeout_wds(struct net_device *);
#endif

#ifdef SOC_W906X
// PCI reset test
#include <linux/of_gpio.h>
#include <linux/pci.h>

#ifdef CONFIG_PCIE_ARMADA_8K_LINK_RESET_BY_GPIO
extern int armada8k_pcie_link_reset(struct device *dev);
#endif /* CONFIG_PCIE_ARMADA_8K_LINK_RESET_BY_GPIO */

static struct device *
get_host_bridge_device(struct pci_dev *dev)
{
	struct pci_bus *bus = dev->bus;

	while (bus->parent)
		bus = bus->parent;

	return bus->bridge;
}

static int
wl_pcie_reset(struct pci_dev *pdev)
{
	struct device *root_bridge = get_host_bridge_device(pdev);
	struct device *dev = root_bridge->parent;

#ifdef CONFIG_PCIE_ARMADA_8K_LINK_RESET_BY_GPIO
	/* pcie_link_reset driver support- platform dependant code: a3900a1 AlliesBT V2 */
	dev_info(&pdev->dev, "pcie link reset:");

	if (armada8k_pcie_link_reset(dev))
	{
		dev_info(&pdev->dev, "Cannot re-enable device after reset.\n");
		return -1;
	}
#else
	/* generic gpio control- custom platform may change its gpio control code here */
	enum of_gpio_flags flags;
	int reset_gpio;
	struct gpio_desc *gpio;

	dev_info(&pdev->dev, "pcie gipo reset:");

	reset_gpio = of_get_named_gpio_flags(dev->of_node,
										 "reset-gpios", 0, &flags);
	if (!gpio_is_valid(reset_gpio))
	{
		dev_info(&pdev->dev, "gpio is invalid\n");
		return -1;
	}

	gpio = gpio_to_desc(reset_gpio);
	dev_info(&pdev->dev, "gpio %d ctrl\n", reset_gpio);
	gpiod_direction_output(gpio, (flags & OF_GPIO_ACTIVE_LOW) ? 1 : 0);
	mdelay(100);
	gpiod_direction_output(gpio, (flags & OF_GPIO_ACTIVE_LOW) ? 0 : 1);

#endif /* CONFIG_PCIE_ARMADA_8K_LINK_RESET_BY_GPIO */

	pci_restore_state(pdev);
	return 0;
}

#endif /* SOC_W906X */

/* keep track of how many times it is mmapped */

void wdev_mmap_open(struct vm_area_struct *vma)
{
	mmap_info *info = (mmap_info *)vma->vm_private_data;

	info->reference++;
}

void wdev_mmap_close(struct vm_area_struct *vma)
{
	mmap_info *info = (mmap_info *)vma->vm_private_data;

	info->reference--;
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 10, 0)
static int
wdev_mmap_fault(struct vm_fault *vmf)
{
	return 0;
}
#else
/* nopage is called the first time a memory area is accessed which is not in memory,
 * it does the actual mapping between kernel and user space memory
 */
static int
wdev_mmap_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct page *page;
	mmap_info *info;

	/* the data is in vma->vm_private_data */
	info = (mmap_info *)vma->vm_private_data;
	if (!info->data || vmf->pgoff >= FW_IO_NUM_PAGE)
	{
		printk("no data\n");
		return -ENODATA;
	}
	/* get the page */
	page = virt_to_page(info->data + 4096 * vmf->pgoff);
	/* increment the reference count of this page */
	get_page(page);
	vmf->page = page;
	return 0;
}
#endif

struct vm_operations_struct wdev_mmap_vm_ops = {
	.open = wdev_mmap_open,
	.close = wdev_mmap_close,
	.fault = wdev_mmap_fault,
};

int wdev_mmap(struct file *filp, struct vm_area_struct *vma)
{
	vma->vm_ops = &wdev_mmap_vm_ops;
	vma->vm_flags |= (unsigned long)VM_RESERVED;
	/* assign the file private data to the vm private data */
	vma->vm_private_data = filp->private_data;
	wdev_mmap_open(vma);
	return 0;
}

int wdev_close(struct inode *inode, struct file *filp)
{
	filp->private_data = NULL;
	return 0;
}

static void
AllocSharedMem(struct wlprivate *wlpptr)
{

	/* obtain new memory */

	if (!wlpptr->wlpd_p->AllocSharedMeminfo.data)
	{
		wlpptr->wlpd_p->AllocSharedMeminfo.data = (UINT8 *)
#ifdef SOC_W906X
			wl_dma_alloc_coherent(wlpptr->wlpd_p->dev,
								  FW_IO_MB_SIZE,
								  &wlpptr->wlpd_p->AllocSharedMeminfo.dataPhysicalLoc,
								  wlpptr->wlpd_p->dma_alloc_flags);
#else
			pci_alloc_consistent(wlpptr->pPciDev, FW_IO_MB_SIZE,
								 &wlpptr->wlpd_p->AllocSharedMeminfo.dataPhysicalLoc);
#endif /* SOC_W906X */

		if (wlpptr->wlpd_p->AllocSharedMeminfo.data)
		{
			memset(wlpptr->wlpd_p->AllocSharedMeminfo.data, 0,
				   FW_IO_MB_SIZE);
			//                      printk("Physical loc =%pad \n", &wlpptr->wlpd_p->AllocSharedMeminfo.dataPhysicalLoc);   //0316
		}
	}
}

void AllocMrvlPriSharedMem(struct wlprivate *wlpptr)
{
	if (!wlpptr->wlpd_p->MrvlPriSharedMem.data)
	{
		wlpptr->wlpd_p->MrvlPriSharedMem.data = (UINT8 *)
#ifdef SOC_W906X
			wl_dma_alloc_coherent(wlpptr->wlpd_p->dev,
								  sizeof(drv_fw_shared_t),
								  &wlpptr->wlpd_p->MrvlPriSharedMem.dataPhysicalLoc,
								  wlpptr->wlpd_p->dma_alloc_flags);
#else
			pci_alloc_consistent(wlpptr->pPciDev,
								 sizeof(drv_fw_shared_t),
								 &wlpptr->wlpd_p->MrvlPriSharedMem.dataPhysicalLoc);
#endif
	}
	//      printk("mrvl pri mailbox Physical loc =0x%pad \n", &wlpptr->wlpd_p->MrvlPriSharedMem.dataPhysicalLoc);  //0316
}

static int
wdev_open(int cardindex, struct inode *inode, struct file *filp)
{
	struct wlprivate *wlpptr;
	struct net_device *netdev;

	netdev = global_private_data[cardindex]->rootdev;
	wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	wlpptr->cmd_seqno = 0;
	/* assign this info struct to the file */
	filp->private_data = &wlpptr->wlpd_p->AllocSharedMeminfo;
	return 0;
}

int wdev_open0(struct inode *inode, struct file *filp)
{
	return wdev_open(0, inode, filp);
}

int wdev_open1(struct inode *inode, struct file *filp)
{
	return wdev_open(1, inode, filp);
}

static const struct file_operations wdev0_fops = {
	.open = wdev_open0,
	.release = wdev_close,
	.mmap = wdev_mmap,
};

static const struct file_operations wdev1_fops = {
	.open = wdev_open1,
	.release = wdev_close,
	.mmap = wdev_mmap,
};

/************** ACNT related**************/

void ACNT_mmap_open(struct vm_area_struct *vma)
{
	mmap_info *info = (mmap_info *)vma->vm_private_data;

	info->reference++;
}

void ACNT_mmap_close(struct vm_area_struct *vma)
{
	mmap_info *info = (mmap_info *)vma->vm_private_data;

	info->reference--;
}

#if defined(SOC_W906X) || defined(NEWDP_ACNT_CHUNKS)
static u32 SizeOfChunk;
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 10, 0)
static int
ACNT_mmap_fault(struct vm_fault *vmf)
{
	return 0;
}
#else
static int
ACNT_mmap_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct page *page;
	mmap_info *info;

	/* the data is in vma->vm_private_data */
	info = (mmap_info *)vma->vm_private_data;
	if (!info->data || vmf->pgoff >= SizeOfChunk / 4096)
	{
		printk("no data\n");
		return 0;
	}
	/* get the page */
	page = virt_to_page(info->data + 4096 * vmf->pgoff);
	// printk("info = 0x%X  page = 0x%X \n",info, page);
	/* increment the reference count of this page */
	get_page(page);
	vmf->page = page;
	return 0;
}
#endif
#else
static int
ACNT_mmap_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct page *page;
	mmap_info *info;

	/* the data is in vma->vm_private_data */
	info = (mmap_info *)vma->vm_private_data;
	if (!info->data || vmf->pgoff >= DEFAULT_ACNT_RING_SIZE / 4096)
	{
		printk("no data\n");
		return NULL;
	}
	/* get the page */
	page = virt_to_page(info->data + 4096 * vmf->pgoff);

	/* increment the reference count of this page */
	get_page(page);
	vmf->page = page;
	return 0;
}
#endif

struct vm_operations_struct ACNT_mmap_vm_ops = {
	.open = ACNT_mmap_open,
	.close = ACNT_mmap_close,
	.fault = ACNT_mmap_fault,
};

int ACNT_mmap(struct file *filp, struct vm_area_struct *vma)
{
	vma->vm_ops = &ACNT_mmap_vm_ops;
	vma->vm_flags |= (unsigned long)VM_RESERVED;
	/* assign the file private data to the vm private data */
	vma->vm_private_data = filp->private_data;
	ACNT_mmap_open(vma);
	return 0;
}

int ACNT_close(struct inode *inode, struct file *filp)
{
	filp->private_data = NULL;
	// to do
	// may need to do pci_free_consistent here
	// or pci_free_consistent when resize
	return 0;
}

int ACNT_open(struct inode *inode, struct file *filp)
{
	struct wlprivate *wlpptr;
	struct net_device *netdev;

	netdev = global_private_data[0]->rootdev;
	wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	/* assign this info struct to the file */
#if defined(SOC_W906X) || defined(NEWDP_ACNT_CHUNKS)
	filp->private_data = &wlpptr->wlpd_p->mmap_ACNTChunk[ChunkNum];
	ChunkNum++;
	if (ChunkNum >= wlpptr->wlpd_p->AcntChunkInfo.NumChunk)
	{
		ChunkNum = 0; // reset to 0
	}
	SizeOfChunk = wlpptr->wlpd_p->AcntChunkInfo.SizeOfChunk;
	// printk("filp->private_data = 0x%X \n", filp->private_data);
#else
	filp->private_data = &wlpptr->wlpd_p->ACNTmemInfo;
#endif
	return 0;
}

int ACNT1_open(struct inode *inode, struct file *filp)
{
	struct wlprivate *wlpptr;
	struct net_device *netdev;

	netdev = global_private_data[1]->rootdev;
	wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	/* assign this info struct to the file */
#if defined(SOC_W906X) || defined(NEWDP_ACNT_CHUNKS)
	filp->private_data = &wlpptr->wlpd_p->mmap_ACNTChunk[ChunkNum];
	ChunkNum++;
	if (ChunkNum >= wlpptr->wlpd_p->AcntChunkInfo.NumChunk)
	{
		ChunkNum = 0; // reset to 0
	}
#else
	filp->private_data = &wlpptr->wlpd_p->ACNTmemInfo;
#endif
	return 0;
}

static const struct file_operations ACNT_fops = {
	.open = ACNT_open,
	.release = ACNT_close,
	.mmap = ACNT_mmap,
};

static const struct file_operations ACNT1_fops = {
	.open = ACNT1_open,
	.release = ACNT_close,
	.mmap = ACNT_mmap,
};

#ifdef SOC_W906X
/* SM data */
#define SMDATA_SIZE_PER_STA 0x10000 // 64KB
void smdata_mmap_open(struct vm_area_struct *vma)
{
	mmap_info *info = (mmap_info *)vma->vm_private_data;

	info->reference++;
}

void smdata_mmap_close(struct vm_area_struct *vma)
{
	mmap_info *info = (mmap_info *)vma->vm_private_data;

	info->reference--;
}

static int
__smdata_mmap_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct page *page;
	mmap_info *info;

	/* the data is in vma->vm_private_data */
	info = (mmap_info *)vma->vm_private_data;

	if (!info->data || vmf->pgoff >= (SMDATA_SIZE_PER_STA * sta_num / 4096))
	{
		printk("no data\n");
		return 0;
	}

	/* get the page */
	page = virt_to_page(info->data + 4096 * vmf->pgoff);
	/* increment the reference count of this page */
	get_page(page);
	vmf->page = page;
	if (vmf->flags)
		printk("vm flags 0x%x\n", vmf->flags);
	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0)
static int
smdata_mmap_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	return __smdata_mmap_fault(vma, vmf);
}
#else
static int
smdata_mmap_fault(struct vm_fault *vmf)
{
	return __smdata_mmap_fault(vmf->vma, vmf);
}
#endif

struct vm_operations_struct smdata_mmap_vm_ops = {
	.open = smdata_mmap_open,
	.close = smdata_mmap_close,
	.fault = smdata_mmap_fault,
};

int smdata_mmap(struct file *filp, struct vm_area_struct *vma)
{
	vma->vm_ops = &smdata_mmap_vm_ops;
	vma->vm_flags |= (unsigned long)VM_RESERVED;
	/* assign the file private data to the vm private data */
	vma->vm_private_data = filp->private_data;
	smdata_mmap_open(vma);
	return 0;
}

int smdata_close(struct inode *inode, struct file *filp)
{
	filp->private_data = NULL;
	return 0;
}

int smdata_open(int cardindex, struct inode *inode, struct file *filp)
{
	struct wlprivate *wlpptr;
	struct net_device *netdev;

	netdev = global_private_data[cardindex]->rootdev;
	wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);

	if (!wlpptr->wlpd_p->smdata_mmap_info.data)
	{
		printk("smdata open fail: address null\n");
		return -1;
	}

	/* Upload the processed SM into DDR: set bit 4 of 0x640 */
	((SMAC_CTRL_BLK_st *)wlpptr->ioBase0)->status.sysRsvd11[0] |= 0x10;

	filp->private_data = &wlpptr->wlpd_p->smdata_mmap_info;

	return 0;
}

static int
smdata_open0(struct inode *inode, struct file *filp)
{
	return smdata_open(0, inode, filp);
}

static int
smdata_open1(struct inode *inode, struct file *filp)
{
	return smdata_open(1, inode, filp);
}

static int
smdata_open2(struct inode *inode, struct file *filp)
{
	return smdata_open(2, inode, filp);
}

static const struct file_operations smdata_fops[MAX_CARDS_SUPPORT] = {
	{
		.open = smdata_open0,
		.release = smdata_close,
		.mmap = smdata_mmap,
	},
	{
		.open = smdata_open1,
		.release = smdata_close,
		.mmap = smdata_mmap,
	},
	{
		.open = smdata_open2,
		.release = smdata_close,
		.mmap = smdata_mmap,
	},
};

static void
create_smdata_mmap(struct wlprivate *priv)
{
	char buf[10];
	int cardindex;
	U32 pa;
	UINT8 *va;

	if (!priv)
		return;

	cardindex = priv->cardindex;
	sprintf(buf, "SmData%d", cardindex);

	priv->wlpd_p->smdata_mmap_info.file =
		debugfs_create_file(buf, 0644, NULL, NULL,
							&smdata_fops[cardindex]);

	/* Obtain SM data base address from 0x604 */
	pa = priv->smacStatusAddr->sysRsvdMU0[1];
	if (!pa)
		return;

	va = phys_to_virt(pa);
	priv->wlpd_p->smdata_mmap_info.data = va;
}
#endif /* SOC_W906X */

static ssize_t
write_pid(int slot, struct file *file, const char __user *buf,
		  size_t count, loff_t *ppos)
{
	char mybuf[10];
	int pid = 0;
	struct wlprivate *wlpptr;
	struct net_device *netdev;

	/* read the value from user space */
	if (count > 10)
		return -EINVAL;
	if (copy_from_user(mybuf, buf, count) != 0)
		return -EFAULT;
	sscanf(mybuf, "%d", &pid);
	netdev = global_private_data[slot]->rootdev;
	wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	wlpptr->wlpd_p->PostReqSiginfo.pid = pid;
	return count;
}

static ssize_t
write_pid0(struct file *file, const char __user *buf,
		   size_t count, loff_t *ppos)
{
	return write_pid(0, file, buf, count, ppos);
}

static ssize_t
write_pid1(struct file *file, const char __user *buf,
		   size_t count, loff_t *ppos)
{
	return write_pid(1, file, buf, count, ppos);
}

static const struct file_operations postreq_fops0 = {
	.write = write_pid0,
};

static const struct file_operations postreq_fops1 = {
	.write = write_pid1,
};

DECLARE_LOCK(TxCSkbFreLock);
static int __init
wlmodule_init(void)
{

	struct pci_dev *dev = NULL, *dev1 = NULL;
	unsigned long device_id;
	// int i=0;
	int j = 0, k = 0, l = 0;
#ifdef SOC_W906X
	unsigned short Supported_VID[MRVL_PCI_VENDOR_ID_Count] =
		{MRVL_PCI_VENDOR_ID2};
#else
	unsigned short Supported_VID[MRVL_PCI_VENDOR_ID_Count] =
		{MRVL_PCI_VENDOR_ID1, MRVL_PCI_VENDOR_ID2};
#endif /* SOC_W906X */

#ifdef MEMORY_USAGE_TRACE
	wl_get_meminfo_init();
#endif /* MEMORY_USAGE_TRACE */

#ifdef SOC_W906X
	wl_get_platform_id();

	if (IS_PLATFORM(A390) || IS_PLATFORM(A380) || IS_PLATFORM(MAX)) // MAX is for generic platform
		pci_only = 1;

#ifdef PDM_PCI
	pci_only = 1;
	printk("pci only for axis-bt + palladium platform \n");
#endif
#ifdef WIFI_DATA_OFFLOAD
	pci_only = 1;
	printk("pci only for wifi data offload\n");
#endif

	SPIN_LOCK_INIT(&TxCSkbFreLock);
	if (!pci_only)
		platform_driver_register(&wldriver_mci);
#endif /* SOC_W906X */

	for (l = 0; l < MRVL_PCI_VENDOR_ID_Count; l++)
	{
		dev = NULL;
		while ((dev =
					pci_get_device(Supported_VID[l], PCI_ANY_ID,
								   dev)) != NULL)
		{
			if (((dev->class >> 16) & 0xff) !=
				PCI_BASE_CLASS_NETWORK)
			{
				continue;
			}

			dev1 = dev;
			while (dev1)
			{
				device_id = dev->device;
				if (pci_dev_driver(dev))
				{
					j++;
					WLDBG_INFO(DBG_LEVEL_2,
							   "device already inited\n");
					break;
				}

				wlid_tbl[k].vendor = Supported_VID[l];
				wlid_tbl[k].device = device_id;
				k++;
				dev1 = pci_get_device(Supported_VID[l],
									  device_id, dev);

				if (dev1 == dev)
				{
					WLDBG_INFO(DBG_LEVEL_2,
							   "same device id, same dev found\n");
					break;
				}
				else
				{
					if (dev1)
					{
						WLDBG_INFO(DBG_LEVEL_2,
								   "same device id, different dev found\n");
						/* decrements the reference count of the pci device */
						pci_dev_put(dev1);
					}
					else
						WLDBG_INFO(DBG_LEVEL_2,
								   "no more device for id(%x)\n",
								   device_id);

					/* increments the reference count of the pci device */
					pci_dev_get(dev);
					break;
				}
			}
		}
	}
	for (j = 0; j < k; j++)
		WLDBG_INFO(DBG_LEVEL_2, "found[%d] %x\n", j,
				   wlid_tbl[j].device);
	memset(&wlid_tbl[k], 0, sizeof(struct pci_device_id));
	if (pci_only && (k == 0))
		// do not register if no card found
		return -ENODEV;
	return pci_register_driver(&wldriver_pci);
}

static void __exit
wlmodule_exit(void)
{
#ifdef SOC_W906X
	if (!pci_only)
		platform_driver_unregister(&wldriver_mci);
#endif /* SOC_W906X */

	pci_unregister_driver(&wldriver_pci);

#ifdef MEMORY_USAGE_TRACE
	wl_get_meminfo_deinit();
#endif /* MEMORY_USAGE_TRACE */

	WLDBG_INFO(DBG_LEVEL_2, "Unloaded %s driver\n", DRV_NAME);
}

void wlwlan_setup(struct net_device *dev)
{
#if defined(SOC_W8964) && defined(OPENWRT)
	dev->tx_queue_len = 1000;
#endif
}

// static BOOLEAN function1 = FALSE;
static UINT8 cardindex = 0;
#ifdef SOC_W906X
static void
wl_init_txpend_cnt(void)
{
	u32 len = 0;
	struct device_node *node = of_find_node_by_path("/");
	const char *model = of_get_property(node, "model", &len);
	u8 *ptr = NULL;

	if (model)
	{
		ptr = strnstr(model, "G3", len);
		if (ptr)
		{
			dbg_max_tx_pend_cnt_per_q_lo = 512;
			dbg_max_tx_pend_cnt_per_sta_lo = 562;
		}
	}
}

static void
wlprobe_set_reg_value(struct wlprivate *wlpptr)
{
	if (IS_BUS_TYPE_MCI(wlpptr))
	{
		wlpptr->wlpd_p->reg.h2a_int_events =
			MACREG_REG_H2A_INTERRUPT_EVENTS_MCI;
		wlpptr->wlpd_p->reg.h2a_int_cause =
			MACREG_REG_H2A_INTERRUPT_CAUSE_MCI;
		wlpptr->wlpd_p->reg.h2a_int_mask =
			MACREG_REG_H2A_INTERRUPT_MASK_MCI;
		wlpptr->wlpd_p->reg.h2a_int_clear_sel =
			MACREG_REG_H2A_INTERRUPT_CLEAR_SEL_MCI;
		wlpptr->wlpd_p->reg.h2a_int_status_mask =
			MACREG_REG_H2A_INTERRUPT_STATUS_MASK_MCI;

		wlpptr->wlpd_p->reg.a2h_int_events =
			MACREG_REG_A2H_INTERRUPT_EVENTS_MCI;
		wlpptr->wlpd_p->reg.a2h_int_cause =
			MACREG_REG_A2H_INTERRUPT_CAUSE_MCI;
		wlpptr->wlpd_p->reg.a2h_int_mask =
			MACREG_REG_A2H_INTERRUPT_MASK_MCI;
		wlpptr->wlpd_p->reg.a2h_int_clear_sel =
			MACREG_REG_A2H_INTERRUPT_CLEAR_SEL_MCI;
		wlpptr->wlpd_p->reg.a2h_int_status_mask =
			MACREG_REG_A2H_INTERRUPT_STATUS_MASK_MCI;

		wlpptr->wlpd_p->reg.gen_ptr = MACREG_REG_GEN_PTR_MCI;
		wlpptr->wlpd_p->reg.int_code = MACREG_REG_INT_CODE_MCI;
		wlpptr->wlpd_p->reg.evt_rdptr = MACREG_REG_EVT_RDPTR_MCI;
		wlpptr->wlpd_p->reg.evt_wrptr = MACREG_REG_EVT_WRPTR_MCI;

		wlpptr->wlpd_p->reg.tx_send_head = MACREG_REG_TxSendHead_MCI;
		wlpptr->wlpd_p->reg.tx_send_tail = MACREG_REG_TxSendTail_MCI;
		wlpptr->wlpd_p->reg.tx_done_head = MACREG_REG_TxDoneHead_MCI;
		wlpptr->wlpd_p->reg.tx_done_tail = MACREG_REG_TxDoneTail_MCI;

		wlpptr->wlpd_p->reg.rx_desc_head = MACREG_REG_RxDescHead_MCI;
		wlpptr->wlpd_p->reg.rx_desc_tail = MACREG_REG_RxDescTail_MCI;
		wlpptr->wlpd_p->reg.rx_done_head = MACREG_REG_RxDoneHead_MCI;
		wlpptr->wlpd_p->reg.FwDbgStateAddr =
			MACREG_REG_FwDbgStateAddr_MCI;

		wlpptr->wlpd_p->reg.acnt_head = MACREG_REG_AcntHead_MCI;
		wlpptr->wlpd_p->reg.acnt_tail = MACREG_REG_AcntTail_MCI;

		wlpptr->wlpd_p->reg.offch_req_head =
			MACREG_REG_OffchReqHead_MCI;
		wlpptr->wlpd_p->reg.offch_req_tail =
			MACREG_REG_OffchReqTail_MCI;

		wlpptr->wlpd_p->reg.smac_buf_hi_addr = SMAC_BUF_HI_ADDR_MCI;
		wlpptr->wlpd_p->reg.smac_ctrlbase_nss_hi_val_intr =
			SMAC_CTRLBASE_NSS_MCI_HI_VAL_INTR;

		wlpptr->wlpd_p->reg.fw_int_event_offeset =
			MACREG_REG_A2H_INTERRUPT_EVENTS_MCI;
		wlpptr->wlpd_p->reg.fw_len_offset = MACREG_REG_INT_CODE_MCI;
		wlpptr->wlpd_p->reg.fw_int_cause_offset =
			MACREG_REG_A2H_INTERRUPT_CAUSE_MCI;
		wlpptr->wlpd_p->reg.fw_setup_int_trigger =
			MACREG_H2ARIC_BIT_DOOR_BELL;
	}
	else
	{
		wlpptr->wlpd_p->reg.h2a_int_events =
			MACREG_REG_H2A_INTERRUPT_EVENTS;
		wlpptr->wlpd_p->reg.h2a_int_cause =
			MACREG_REG_H2A_INTERRUPT_CAUSE;
		wlpptr->wlpd_p->reg.h2a_int_mask =
			MACREG_REG_H2A_INTERRUPT_MASK;
		wlpptr->wlpd_p->reg.h2a_int_clear_sel =
			MACREG_REG_H2A_INTERRUPT_CLEAR_SEL;
		wlpptr->wlpd_p->reg.h2a_int_status_mask =
			MACREG_REG_H2A_INTERRUPT_STATUS_MASK;

		wlpptr->wlpd_p->reg.a2h_int_events =
			MACREG_REG_A2H_INTERRUPT_EVENTS;
		wlpptr->wlpd_p->reg.a2h_int_cause =
			MACREG_REG_A2H_INTERRUPT_CAUSE;
		wlpptr->wlpd_p->reg.a2h_int_mask =
			MACREG_REG_A2H_INTERRUPT_MASK;
		wlpptr->wlpd_p->reg.a2h_int_clear_sel =
			MACREG_REG_A2H_INTERRUPT_CLEAR_SEL;
		wlpptr->wlpd_p->reg.a2h_int_status_mask =
			MACREG_REG_A2H_INTERRUPT_STATUS_MASK;

		wlpptr->wlpd_p->reg.gen_ptr = MACREG_REG_GEN_PTR;
		wlpptr->wlpd_p->reg.int_code = MACREG_REG_INT_CODE;
		wlpptr->wlpd_p->reg.evt_rdptr = MACREG_REG_EVT_RDPTR;
		wlpptr->wlpd_p->reg.evt_wrptr = MACREG_REG_EVT_WRPTR;

		wlpptr->wlpd_p->reg.tx_send_head = MACREG_REG_TxSendHead;
		wlpptr->wlpd_p->reg.tx_send_tail = MACREG_REG_TxSendTail;
		wlpptr->wlpd_p->reg.tx_done_head = MACREG_REG_TxDoneHead;
		wlpptr->wlpd_p->reg.tx_done_tail = MACREG_REG_TxDoneTail;

		wlpptr->wlpd_p->reg.rx_desc_head = MACREG_REG_RxDescHead;
		wlpptr->wlpd_p->reg.rx_desc_tail = MACREG_REG_RxDescTail;
		wlpptr->wlpd_p->reg.rx_done_head = MACREG_REG_RxDoneHead;
		wlpptr->wlpd_p->reg.FwDbgStateAddr = MACREG_REG_FwDbgStateAddr;

		wlpptr->wlpd_p->reg.acnt_head = MACREG_REG_AcntHead;
		wlpptr->wlpd_p->reg.acnt_tail = MACREG_REG_AcntTail;

		wlpptr->wlpd_p->reg.offch_req_head = MACREG_REG_OffchReqHead;
		wlpptr->wlpd_p->reg.offch_req_tail = MACREG_REG_OffchReqTail;

		wlpptr->wlpd_p->reg.smac_buf_hi_addr = SMAC_BUF_HI_ADDR;
		wlpptr->wlpd_p->reg.smac_ctrlbase_nss_hi_val_intr =
			SMAC_CTRLBASE_NSS_PCIE_HI_VAL_INTR;

		wlpptr->wlpd_p->reg.fw_int_event_offeset =
			MACREG_REG_H2A_INTERRUPT_EVENTS;
		wlpptr->wlpd_p->reg.fw_len_offset = PCI_REG_SCRATCH2_REG;
		wlpptr->wlpd_p->reg.fw_int_cause_offset =
			MACREG_REG_H2A_INTERRUPT_CAUSE;
		wlpptr->wlpd_p->reg.fw_setup_int_trigger =
			MACREG_A2HRIC_BIT_MASK;
	}
}

static void
wlprobe_set_intr_info(struct wlprivate *wlpptr)
{
	if (IS_BUS_TYPE_MCI(wlpptr))
	{
		wlpptr->wlpd_p->intr_shift = intr_info_tbl_mci.intr_shift;
		wlpptr->wlpd_p->msix_num = intr_info_tbl_mci.msix_num;
	}
	else
	{
		if (IS_PLATFORM(MAX)) // For generic platform
			wlpptr->wlpd_p->msix_num =
				intr_info_tbl_generic.msix_num;
		else
			wlpptr->wlpd_p->msix_num =
				intr_info_tbl[platform_id].msix_num;
	}
	pr_info("wlprobe: intr_shift=%u msix_num=%u\n",
			wlpptr->wlpd_p->intr_shift, wlpptr->wlpd_p->msix_num);
}

static int
wl_get_platform_id(void)
{
	int i;

	for (i = 0; i < PLATFORM_ID_MAX; i++)
	{
		if (of_machine_is_compatible(mach_compat[i]))
		{
			pr_info("machine is compatible id:%d %s\n", i,
					mach_compat[i]);
			platform_id = i;
			return 0;
		}
	}
	pr_err("This is a generic platform...\n");

	return 0;
}

const static u32 def_frm_base[PLATFORM_ID_MAX] = {
	0xF0290040, /* PCI: A3900_A7K */
	0xF0290040, /* PCI: A8K */
	0xF101A040, /* PCI: A390 */
	0xF101A040, /* PCI: A380 */
};

#define INTR_FRAME_MAX_NUM 4
const static struct intr_frame
	sysintr_frames[PLATFORM_ID_MAX][INTR_FRAME_MAX_NUM] = {
		{
			/* PCI: A3900_A7K */
			{0xF0290040, 0xC0},	 /// Frame_1
			{0xF02A0040, 0xE0},	 /// Frame_2
			{0xF0280040, 0xA0},	 /// Frame_0
			{0xF02B0040, 0x100}, /// Frame_3
		},
		{
			/* PCI: A8K */
			{0xF0290040, 0xC0},	 /// Frame_1
			{0xF02A0040, 0xE0},	 /// Frame_2
			{0xF0280040, 0xA0},	 /// Frame_0
			{0xF02B0040, 0x100}, /// Frame_3
		},
		{
			/* PCI: A390 */
			{0xF101A040, 0x00},
		},
		{
			/* PCI: A380 */
			{0xF101A040, 0x00},
		},
};

/*
 *  Get the interrupt frame information from the interrupt base address
 */
static void
wl_init_intrfrm(U32 intr_base, struct intr_frame *pintr_frm)
{
	const struct intr_frame *pif;
	int i;
	UINT8 idx_sf = ((U8)platform_id % PLATFORM_ID_MAX);

	memset(pintr_frm, 0, sizeof(struct intr_frame));
	for (i = 0; i < INTR_FRAME_MAX_NUM; i++)
	{
		pif = &sysintr_frames[idx_sf][i];
		if (pif->frm_base == intr_base)
		{
			memcpy(pintr_frm, pif, sizeof(struct intr_frame));
			break;
		}
	}
	if (i == INTR_FRAME_MAX_NUM)
	{
		WLDBG_ERROR(DBG_LEVEL_0,
					"Failed to find Interrupt Frame (%x)\n", intr_base);
		memcpy(pintr_frm, &sysintr_frames[idx_sf][0],
			   sizeof(struct intr_frame));
	}
	return;
}

static void
wl_get_intr_base(struct wlprivate *wlpptr)
{
	struct platform_device *pdev = wlpptr->wlpd_p->pDev;
	U32 intr_base;
	u32 id;

	if (IS_BUS_TYPE_MCI(wlpptr))
	{
		if (of_property_read_u32(pdev->dev.of_node, "device-identifier", &id))
		{
			WLDBG_ERROR(DBG_LEVEL_0,
						"Failed to get \"device-identifier\"\n");
		}

		if (of_property_read_u32(pdev->dev.of_node, "msi-base", &intr_base))
		{
			WLDBG_ERROR(DBG_LEVEL_0,
						"Failed to get \"msi-base\"\n");
			intr_base = def_frm_base[platform_id];
		}

		WLDBG_INFO(DBG_LEVEL_0, "id=%xh, base=%xh\n", id, intr_base);
	}
	else
	{
		intr_base = def_frm_base[platform_id];
	}

	wl_init_intrfrm(intr_base, &wlpptr->wlpd_p->sysintr_frm);
	return;
}

static void
wl_init_intr(struct wlprivate *wlpptr)
{
	U32 regval;

	if (!IS_BUS_TYPE_MCI(wlpptr))
	{
		if (wlpptr->intr_type == INTR_TYPE_MSIX)
		{
			wlpptr->num_vectors = wlpptr->wlpd_p->msix_num;

			/* PCIe MSIX Mode using New GIC mode: */
			// 0x38
			printk("%s(%d)\n", __func__, __LINE__);
			writel(SC5_PCIE_MODE_GIC,
				   wlpptr->ioBase1 + SC5_REG_PCIE_INTR_MODE_SEL);
			// 0x30
			writel(SMAC_CTRLBASE_NSS_PCIE_HI_VAL_NOINTR,
				   wlpptr->ioBase1 +
					   SC5_REG_SMAC_CTRLBASE_NSS_PCIE_HI);
			writel(PCI_REG_DOORBELL_ADDR,
				   wlpptr->ioBase1 + SC5_REG_FRAME_0);
			writel(PCI_REG_DOORBELL_ADDR,
				   wlpptr->ioBase1 + SC5_REG_FRAME_1);
			writel(PCI_REG_DOORBELL_ADDR,
				   wlpptr->ioBase1 + SC5_REG_FRAME_2);
			writel(PCI_REG_DOORBELL_ADDR,
				   wlpptr->ioBase1 + SC5_REG_FRAME_3);
		}
		else if (wlpptr->intr_type == PCI_INTR_TYPE_MSI)
		{
			wlpptr->num_vectors = 0;

			/* PCIe MSI Mode using New GIC mode: */
			// 0x38
			writel(SC5_PCIE_MODE_GIC,
				   wlpptr->ioBase1 + SC5_REG_PCIE_INTR_MODE_SEL);
			// 0x30
			writel(SMAC_CTRLBASE_NSS_PCIE_HI_VAL_NOINTR,
				   wlpptr->ioBase1 +
					   SC5_REG_SMAC_CTRLBASE_NSS_PCIE_HI);
			writel(PCI_REG_HOST_ITR_ADDR,
				   wlpptr->ioBase1 + SC5_REG_FRAME_0);
			writel(PCI_REG_HOST_ITR_ADDR,
				   wlpptr->ioBase1 + SC5_REG_FRAME_1);
			writel(PCI_REG_HOST_ITR_ADDR,
				   wlpptr->ioBase1 + SC5_REG_FRAME_2);
			writel(PCI_REG_HOST_ITR_ADDR,
				   wlpptr->ioBase1 + SC5_REG_FRAME_3);
		}
		return;
	}
	else
	{

		wlpptr->num_vectors = wlpptr->netDev->irq;

		wl_get_intr_base(wlpptr);
		printk("(base, spi)=(%xh, %xh)\n",
			   wlpptr->wlpd_p->sysintr_frm.frm_base,
			   wlpptr->wlpd_p->sysintr_frm.spi_num);
		// ++++++++
		// Fill base address of frame_x
		writel(wlpptr->wlpd_p->sysintr_frm.frm_base,
			   wlpptr->ioBase1 + SC5_REG_FRAME_0);
		WLDBG_INFO(DBG_LEVEL_0,
				   "=> %s(), W906x_REG_FRAME_0, w_reg(ioBase1+%xh) = %xh\n",
				   __func__, SC5_REG_FRAME_0,
				   wlpptr->wlpd_p->sysintr_frm.frm_base);
		writel(wlpptr->wlpd_p->sysintr_frm.frm_base,
			   wlpptr->ioBase1 + SC5_REG_FRAME_1);
		WLDBG_INFO(DBG_LEVEL_0,
				   "=> %s(), W906x_REG_FRAME_1, w_reg(ioBase1+%xh) = %xh\n",
				   __func__, SC5_REG_FRAME_1,
				   wlpptr->wlpd_p->sysintr_frm.frm_base);
		writel(wlpptr->wlpd_p->sysintr_frm.frm_base,
			   wlpptr->ioBase1 + SC5_REG_FRAME_2);
		WLDBG_INFO(DBG_LEVEL_0,
				   "=> %s(), W906x_REG_FRAME_2, w_reg(ioBase1+%xh) = %xh\n",
				   __func__, SC5_REG_FRAME_2,
				   wlpptr->wlpd_p->sysintr_frm.frm_base);
		writel(wlpptr->wlpd_p->sysintr_frm.frm_base,
			   wlpptr->ioBase1 + SC5_REG_FRAME_3);
		WLDBG_INFO(DBG_LEVEL_0,
				   "=> %s(), W906x_REG_FRAME_3, w_reg(ioBase1+%xh) = %xh\n",
				   __func__, SC5_REG_FRAME_3,
				   wlpptr->wlpd_p->sysintr_frm.frm_base);
		// --------

		// HW PCIE-MSIX setting
		// => #1, set intr mode selected
		writel(SC5_PCIE_MODE_GIC,
			   wlpptr->ioBase1 + SC5_REG_PCIE_INTR_MODE_SEL);
		printk("=> %s(),w_reg(ioBase1+%xh) = %xh\n", __func__,
			   SC5_REG_PCIE_INTR_MODE_SEL, SC5_PCIE_MODE_GIC);
		// set hframe register base
		writel(wlpptr->hframe_phy_addr,
			   wlpptr->ioBase1 + SC5_REG_HFRAME_BASE);
		printk("=> %s(),w_reg(ioBase1+%xh) = %llxh\n", __func__,
			   SC5_REG_HFRAME_BASE,
			   (long long unsigned int)wlpptr->hframe_phy_addr);
		// => #2, set ncc pcie val (Using interrupt mode or not)
		regval = wlpptr->wlpd_p->reg.smac_ctrlbase_nss_hi_val_intr;

		writel(regval,
			   wlpptr->ioBase1 + SC5_REG_SMAC_CTRLBASE_NSS_PCIE_HI);
		printk("=> %s(),w_reg(ioBase1+%xh) = %xh\n", __func__,
			   SC5_REG_SMAC_CTRLBASE_NSS_PCIE_HI, regval);

		// => #3, set pcie msi address
		writel(wlpptr->wlpd_p->sysintr_frm.frm_base,
			   wlpptr->ioBase1 + SC5_REG_PCIE_MSI_ADDR);
		printk("=> %s(),w_reg(ioBase1+%xh) = %xh\n", __func__,
			   SC5_REG_PCIE_MSI_ADDR,
			   wlpptr->wlpd_p->sysintr_frm.frm_base);

		// => #4, Set SC5_REG_PCIE_MSIX_DATA
		writel(wlpptr->wlpd_p->sysintr_frm.spi_num,
			   wlpptr->ioBase1 + SC5_REG_PCIE_MSIX_DATA);
		printk("=> %s(),w_reg(ioBase1+%xh) = %xh\n", __func__,
			   SC5_REG_PCIE_MSIX_DATA,
			   wlpptr->wlpd_p->sysintr_frm.spi_num);

		writel(wlpptr->hframe_phy_addr,
			   wlpptr->ioBase1 + SC5_REG_BASE_ADDR_HOST_128B);
		printk("===> w_reg(ioBase1+%xh) = %llxh\n",
			   SC5_REG_BASE_ADDR_HOST_128B,
			   (long long unsigned int)wlpptr->hframe_phy_addr);
		return;
	}
}

static void
wl_hook_intr(struct wlprivate *wlpptr)
{

	if (wlpptr->intr_type == INTR_TYPE_MSIX)
	{
		int irq_idx;

		for (irq_idx = 0; irq_idx < wlpptr->num_vectors; irq_idx++)
		{
			wlpptr->msix_ctx[irq_idx].netDev = wlpptr->netDev;
			wlpptr->msix_ctx[irq_idx].msg_id = irq_idx;
			hook_intr(wlpptr, irq_idx);
		}
	}
	else if (wlpptr->intr_type == PCI_INTR_TYPE_MSI)
	{
		int idx, qid, issq;

		/* intr remap to qid */
		for (idx = 0; idx < wlpptr->wlpd_p->msix_num; idx++)
		{
			if (idx >= 0 && idx < 6)
			{
				/* qid: rq0-5: */
				qid = idx;
				issq = 0;
			}
			else if (idx >= 8 && idx < 18)
			{
				/* qid: sq0-9 */
				qid = idx - 8;
				issq = 1;
			}
			else if (idx >= 18 && idx < 22)
			{
				/* qid: rq10-13 */
				qid = idx - 8;
				issq = 0;
			}
			else if (idx == 22)
			{
				/* qid: sq14 */
				qid = 14;
				issq = 1;
			}
			else if (idx == 23)
			{
				/* qid: rq8 */
				qid = 8;
				issq = 0;
			}
			else if (idx == 24)
			{
				/* qid: rq9 */
				qid = 9;
				issq = 0;
			}
			else if (idx == 25)
			{
				/* qid: rq6 -new for SCBT */
				qid = 6;
				issq = 0;
			}
			else if (idx == 26)
			{
				/* qid: rq7 -new for SCBT */
				qid = 7;
				issq = 0;
			}
			else if (idx == 27)
			{
				/* qid: sq10 -new for SCBT */
				qid = 10;
				issq = 1;
			}
			else if (idx == 28)
			{
				/* qid: sq11 -new for SCBT */
				qid = 11;
				issq = 1;
			}
			else if (idx == 29)
			{
				/* qid: sq12 -new for SCBT */
				qid = 12;
				issq = 1;
			}
			else if (idx == 30)
			{
				/* qid: sq13 -new for SCBT */
				qid = 13;
				issq = 1;
			}
			else if (idx == 31)
			{
				/* qid: sq15 -new for SC5/SCBT A0 */
				qid = 15;
				issq = 1;
			}
			else
				continue;

			writel(0,
				   wlpptr->ioBase1 + SC5_REG_FRM_SEL(qid,
													 ((int)(issq) &
													  0x1)));
			writel(BIT(idx),
				   wlpptr->ioBase1 + SC5_REG_EFF_ID(qid,
													((int)(issq) &
													 0x1)));
		}

		if (request_irq(wlpptr->netDev->irq, wlISR, IRQF_SHARED,
						wlpptr->netDev->name, (wlpptr->netDev)))
		{
			WLDBG_ERROR(DBG_LEVEL_2,
						"%s: request_irq failed failed\n",
						wlpptr->netDev->name);
		}
	}
	else
	{
		WLDBG_ERROR(DBG_LEVEL_2,
					"%s: INT not remap and request_irq. intr_type %d \n",
					wlpptr->netDev->name, wlpptr->intr_type);
	}

	return;
}

/*
Ref: Definition of SMAC:

	#define SWAR_IP_REV_SCBT_Z1         0x02011400
	#define SWAR_IP_REV_SCBT_A0         0x02020000

	#define SWAR_IP_REV_SC5_Z1          0x01003300
	#define SWAR_IP_REV_SC5_Z2          0x01003301
	#define SWAR_IP_REV_SC5_A0          0x01020000

Rule:
	Chip Id: 0xff000000
			0x01 => SC5
			0x02 => SCBT
	Revision: 0x00ff0000 >> 16| 0x000000ff
			SC5:
				0x00: z1
				0x01: z2
				0x02: a0
			SCBT:
				0x01: z1
				0x02: a0

*/
static void
wl_get_chipinfo(struct wlprivate *wlpptr)
{
	UINT32 val =
		cpu_to_le32(*(volatile unsigned int *)(wlpptr->ioBase1 + SC5_REG_SMAC_CTRLBASE));
	UINT8 chipid, rev;

	printk("reg(%x)=%xh\n", SC5_REG_SMAC_CTRLBASE, val);
	chipid = (val >> 24) & 0xf;
	rev = (val >> 16 & 0xff) | (val & 0xff);
	switch (chipid)
	{
	case 1: // This is SC5
		wlpptr->devid = SC5;
		printk("==> This is W9068, rev=%u\n", rev);
		switch (rev)
		{
		case 0:
			wlpptr->hwData.chipRevision = REV_Z1;
			break;
		case 1:
			wlpptr->hwData.chipRevision = REV_Z2;
			break;
		case 2:
			wlpptr->hwData.chipRevision = REV_A0;
			break;
		default:
			WLDBG_ERROR(DBG_LEVEL_0, "=> Unknow revision: %xh\n",
						val);
		}
		break;
	case 2: // This is SCBT
		wlpptr->devid = SCBT;
		printk("==> This is W9064, rev=%u\n", rev);
		switch (rev)
		{
		case 1:
			wlpptr->hwData.chipRevision = REV_Z1;
			break;
		case 2:
			wlpptr->hwData.chipRevision = REV_A0;
			break;
		default:
			WLDBG_ERROR(DBG_LEVEL_0, "=> Unknow revision: %xh\n",
						val);
		}
		break;
	default:
		// Unknown id: Using SC5
		printk("==> Unknown chip, ");
		wlpptr->devid = SC5;
	}

	switch (wlpptr->hwData.chipRevision)
	{
	case REV_Z1:
		printk("Revision: Z1\n");
		break;
	case REV_Z2:
		printk("Revision: Z2\n");
		break;
	case REV_A0:
		printk("Revision: A0\n");
		break;
	default:
		printk("Unknow revision: %xh\n", wlpptr->hwData.chipRevision);
	}

	return;
}

// mochi port base addr
static UINT32 mciportbase[2] = {0xfd000000, 0xfe000000};

static int
wlwlan_platform_data_get(struct platform_device *pdev, struct wlprivate *wlpptr)
{
	struct device_node *dn = pdev->dev.of_node;
	struct resource *res[2];
	const struct of_device_id *match;

	match = of_match_node(wldriver_of_match, dn);
	if (!match)
		return -ENODEV;

	/* Memor mapped I/O address space */
	res[0] = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	res[1] = platform_get_resource(pdev, IORESOURCE_MEM, 1);

	wlpptr->phys_addr_start = res[0]->start;
	// WAR++
	// Get more 1M space mapping so that memdump can get more information
	//      => It wil be removed after next rootfs release
	res[0]->end += 0x100000;
	if (res[0]->end >= res[1]->start)
	{
		res[0]->end = res[1]->start - 1;
	}
	printk("%s(), (IoBase0)=(%llx, %llx), more mapping space\n", __func__,
		   res[0]->start, res[0]->end);
	// WAR--
	wlpptr->ioBase0 = devm_ioremap_resource(&pdev->dev, res[0]);
	if (IS_ERR(wlpptr->ioBase0))
		return PTR_ERR(wlpptr->ioBase0);

	printk("%s(), (IoBase1)=(%llx, %llx)\n", __func__, res[1]->start,
		   res[1]->end);
	wlpptr->ioBase1 = devm_ioremap_resource(&pdev->dev, res[1]);
	if (IS_ERR(wlpptr->ioBase1))
		return PTR_ERR(wlpptr->ioBase1);
	wlpptr->phys_addr_end = res[1]->end;

	// add for mochi error monitor
	wlpptr->ioBaseExt =
		devm_ioremap(&pdev->dev, mciportbase[wlpptr->cardindex], 0x10);
	printk("%s(), carindex:%u: ioBaseExt: (v,p)=(%p, %x)\n", __func__,
		   wlpptr->cardindex, wlpptr->ioBaseExt,
		   mciportbase[wlpptr->cardindex]);

	return 0;
}

static BOOLEAN hook_intr(struct wlprivate *wlpptr, UINT32 isr_id);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 5, 0)
/* just back port it from v4.5 and should be remove it after upgrading
   major verion
 */
static int
platform_irq_count(struct platform_device *dev)
{
	int ret, nr = 0;

	while ((ret = platform_get_irq(dev, nr)) >= 0)
		nr++;

	if (ret == -EPROBE_DEFER)
		return ret;

	return nr;
}
#endif

static int
wlprobe_mci(struct platform_device *pdev)
{
	int err = 0;
	struct net_device *dev;
	struct wlprivate *wlpptr = NULL;
	struct wlprivate_data *wlpdptr = NULL;
	u32 vendor_id, device_id;
#ifdef CONFIG_MARVELL_MOCHI_DRIVER
	int mci_id = pdev->name[strlen(pdev->name) - 1] - '0';
#endif // CONFIG_MARVELL_MOCHI_DRIVER
	u8 i;

	WLDBG_ENTER(DBG_LEVEL_2);
	printk("=====> %s()\n", __func__);

	printk("the dma_coherent is %s\n",
		   pdev->dev.archdata.dma_coherent ? "true" : "false");
	pdev->dev.archdata.dma_coherent = true;

#ifdef CONFIG_MARVELL_MOCHI_DRIVER
	{
		u8 rcnt = 0;
		int mci_speed = MCI_LINK_SPEED_8G;
		do
		{
			int mci_ret = mci_do_reset((int)mci_id, mci_speed);
			if (mci_ret == MCI_FAIL)
				return -EIO;
			if (mci_ret == MCI_OK)
				break;
			if (mci_ret == MCI_UNSUPPORTED_SPEED)
				mci_speed--;
		} while ((rcnt++ < MAX_BUS_RESET) &&
				 (mci_speed >= MCI_LINK_SPEED_1G));

		if (rcnt >= MAX_BUS_RESET)
		{
			printk("Failed to reset mochi, after repeating %d times\n", rcnt);
			return -EIO;
		}
	}
#endif

	/* XXX, hard-coded ids here until we find how to get them */
	vendor_id = 0x11ab;

	for (i = 0; i < MAX_CARDS_SUPPORT; i++)
	{
		if (global_private_data[i] == NULL)
		{
			extern RateGrp_t RateGrpDefault[MAX_GROUP_PER_CHANNEL];
			if (!(global_private_data[i] =
					  wl_vzalloc(sizeof(struct wlprivate_data))))
			{
				dev_err(&pdev->dev,
						"Unable to allocate buffer for global_private_data(size %zu)\n",
						sizeof(struct wlprivate_data));
				return -ENOMEM;
			}
			memcpy(global_private_data[i]->RateGrpDefault,
				   RateGrpDefault,
				   sizeof(RateGrp_t) * MAX_GROUP_PER_CHANNEL);
			global_private_data[i]->AmpduPckReorder =
				(Ampdu_Pck_Reorder_t *)
					wl_vzalloc(sizeof(Ampdu_Pck_Reorder_t) *
							   (sta_num + 1));
			if (global_private_data[i]->AmpduPckReorder == NULL)
			{
				printk("Unable to allocate buffer for Ampdu_Pck_Reorder_t (size %zu)\n", sizeof(Ampdu_Pck_Reorder_t) * (sta_num + 1));
				return -ENOMEM;
			}
			global_private_data[i]->Ampdu_tx =
				(Ampdu_tx_t *)wl_vzalloc(sizeof(Ampdu_tx_t) *
										 (MAX_SUPPORT_AMPDU_TX_STREAM_RUNNING));
			if (global_private_data[i]->Ampdu_tx == NULL)
			{
				printk("Unable to allocate buffer for Ampdu_tx (size %zu)\n", sizeof(Ampdu_tx_t) * (MAX_SUPPORT_AMPDU_TX_STREAM_RUNNING));
				return -ENOMEM;
			}
		}
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0)
	dev = alloc_netdev(sizeof(struct wlprivate), DRV_NAME, NET_NAME_UNKNOWN,
					   ether_setup);
#else
	dev = alloc_netdev(sizeof(struct wlprivate), DRV_NAME, ether_setup);
#endif
	if (dev)
	{
		wlpptr = NETDEV_PRIV(struct wlprivate, dev);
		NETDEV_PRIV_S(dev) = wlpptr;
	}
	if (wlpptr == NULL)
	{
		dev_err(&pdev->dev, "%s: no mem for private driver context\n",
				DRV_NAME);
		goto err;
	}
	memset(wlpptr, 0, sizeof(struct wlprivate));
	wlpptr->netDev = dev;
	wlpdptr = global_private_data[cardindex % MAX_CARDS_SUPPORT];
	gprv_dat_refcnt++;
	wlpptr->cardindex = cardindex;
	cardindex++;
	if (wlpdptr == NULL)
	{
		dev_err(&pdev->dev,
				"%s: no mem for private driver data context\n",
				DRV_NAME);
		goto err;
	}
	wlpptr->wlpd_p = wlpdptr;
	wlpptr->wlpd_p->pDev = pdev;
	wlpptr->wlpd_p->dev = &pdev->dev;
	wlpptr->wlpd_p->dma_alloc_flags = GFP_KERNEL;
	wlpdptr->rootdev = wlpptr->netDev;
#ifdef CONFIG_MARVELL_MOCHI_DRIVER
	wlpdptr->mci_id = mci_id;
#endif // CONFIG_MARVELL_MOCHI_DRIVER
	err = wlwlan_platform_data_get(pdev, wlpptr);
	if (err)
	{
		dev_err(&pdev->dev, "%s: platform_data get failed\n", DRV_NAME);
		goto err;
	}

	wl_get_chipinfo(wlpptr);

	if ((wlpptr->hwData.chipRevision == REV_Z1) ||
		(wlpptr->hwData.chipRevision == REV_Z2))
	{
		dev_err(&pdev->dev, "%s: Unsupported chip revision Z1/Z2\n",
				DRV_NAME);
		goto err;
	}

	device_id = wlpptr->devid;

	wl_init_const(wlpptr->netDev);
	// wlpptr->ioBase0 = wlpptr->hwBase0;
	printk("wlprobe  wlpptr->ioBase0 = %p \n", wlpptr->ioBase0);

	wlpptr->smacCfgAddr = &((SMAC_CTRL_BLK_st *)wlpptr->ioBase0)->config;
	wlpptr->smacStatusAddr =
		&((SMAC_CTRL_BLK_st *)wlpptr->ioBase0)->status;

	/* Clean DMEM */
	memset_io(wlpptr->ioBase0, 0, sizeof(SMAC_CTRL_BLK_st));

	// wlpptr->ioBase1 = wlpptr->hwBase1;
	printk("wlprobe  wlpptr->ioBase1 = %p \n", wlpptr->ioBase1);

#define WIFIARB_POST_REQUEST_INTR_DEV_0 "wifiarb_post_request_dev0"
#define WIFIARB_POST_REQUEST_INTR_DEV_1 "wifiarb_post_request_dev1"
	sprintf(wlpptr->netDev->name, "%s%1d", DRV_NAME, wlinitcnt);
	switch (wlinitcnt)
	{
	case 0:
	{
		wlpptr->wlpd_p->AllocSharedMeminfo.file =
			debugfs_create_file(wlpptr->netDev->name, 0644,
								NULL, NULL, &wdev0_fops);
		wlpptr->wlpd_p->PostReqSiginfo.file =
			debugfs_create_file(WIFIARB_POST_REQUEST_INTR_DEV_0, 0200, NULL,
								NULL, &postreq_fops0);
		ACNT_f0 =
			debugfs_create_file("AcntChunk0", 0644, NULL,
								NULL, &ACNT_fops);
		break;
	}
	case 1:
	{
		wlpptr->wlpd_p->AllocSharedMeminfo.file =
			debugfs_create_file(wlpptr->netDev->name, 0644,
								NULL, NULL, &wdev1_fops);
		wlpptr->wlpd_p->PostReqSiginfo.file =
			debugfs_create_file(WIFIARB_POST_REQUEST_INTR_DEV_1, 0200, NULL,
								NULL, &postreq_fops1);
		ACNT_f1 =
			debugfs_create_file("AcntChunk1", 0644, NULL,
								NULL, &ACNT1_fops);
		break;
	}
	default:
		printk(" wlinitcnt = %d \n", wlinitcnt);
		break;
	}

	wlpptr->netDev->mem_start = wlpptr->phys_addr_start;
	wlpptr->netDev->mem_end = wlpptr->phys_addr_end;
	NETDEV_PRIV_S(wlpptr->netDev) = wlpptr;
	wlpptr->pDev = pdev;
	wlpptr->devid = device_id;
#ifdef SINGLE_DEV_INTERFACE
#ifdef WDS_FEATURE
	wlprobeInitWds(wlpptr);
#endif
#endif

	SET_MODULE_OWNER(*(wlpptr->netDev));

	platform_set_drvdata(pdev, (wlpptr->netDev));

	wlpptr->netDev->irq = platform_irq_count(pdev);
	wlpptr->wlpd_p->bus_type = BUS_TYPE_MCI;
	wlprobe_set_reg_value(wlpptr);
	wlprobe_set_intr_info(wlpptr);
	if (wlpptr->netDev->irq != wlpptr->wlpd_p->msix_num)
	{
		dev_err(&pdev->dev, "required %d irq, but %d available\n",
				wlpptr->wlpd_p->msix_num, wlpptr->netDev->irq);
		goto err;
	}

	/*
	 * initial interrupt
	 */
	wlpptr->intr_type = INTR_TYPE_MSIX;
	wl_init_intr(wlpptr);
	wl_hook_intr(wlpptr);

	wlpptr->wlpd_p->CardDeviceInfo = device_id & 0xff;
	if (wlpptr->wlpd_p->CardDeviceInfo == 4)
		wlpptr->wlpd_p->SDRAMSIZE_Addr = 0x40fc70b7; /* 16M SDRAM */
	else
		wlpptr->wlpd_p->SDRAMSIZE_Addr = 0x40fe70b7; /* 8M SDRAM */

	WLDBG_INFO(DBG_LEVEL_2,
			   "%s: %s: mem=0x%lx, irq=%d, ioBase0=%x, ioBase1=%x\n",
			   wlpptr->netDev->name, wlgetAdapterDescription(wlpptr, vendor_id, device_id),
			   wlpptr->netDev->mem_start, wlpptr->netDev->irq,
			   wlpptr->ioBase0, wlpptr->ioBase1);

	wlpptr->hframe_virt_addr = wl_dma_alloc_coherent(&pdev->dev,
													 SC5_HFRAME_MEM_SIZE,
													 &wlpptr->hframe_phy_addr,
													 GFP_KERNEL);

	if (wlpptr->hframe_virt_addr == NULL)
	{
		printk(KERN_ERR
			   "%s: Can not allocate memory for hframe register",
			   wlpptr->netDev->name);
		goto err;
	}

	/* Set hframe register base */
	writel(wlpptr->hframe_phy_addr, wlpptr->ioBase1 + SC5_REG_HFRAME_BASE);
	dev_info(&pdev->dev, "hframe base addr %llx \n",
			 (long long unsigned int)wlpptr->hframe_phy_addr);

	if (wlInit((wlpptr->netDev), device_id))
	{
		goto err;
	}

	if (start_wlmon(wlpptr))
	{
		printk("starting background monitor thread fail..\n");
	}

	create_smdata_mmap(wlpptr);

	WLDBG_EXIT(DBG_LEVEL_2);
	return 0;
err:
	// Allocated resources will be free in wlremove_mci()
	WLDBG_EXIT_INFO(DBG_LEVEL_2, "init error");

	return -EIO;
}

/*
	Remap the interrupt
	intr_id: interrupt id
	qid: which queue to use.
		-1 = map to R7
	isrq: Is mapping RQ

*/
static void
intr_sel_frm_effid(struct wlprivate *wlpptr, UINT32 intr_id, SINT32 qid,
				   BOOLEAN issq)
{
	if (qid < 0)
	{
		return;
	}

	WLDBG_INFO(DBG_LEVEL_0, "mapping %sQ(%d) to intr(%d)\n",
			   (issq ? "S" : "R"), qid, intr_id);
	// Note: Always using frame_0, unless we need different frames
	// Driver sets the same addres to fm_0 ~ fm_3 now
	//      ref: wl_init_intr()
	writel(0, wlpptr->ioBase1 + SC5_REG_FRM_SEL(qid, ((int)(issq) & 0x1)));
	WLDBG_INFO(DBG_LEVEL_0, "[FRM_SEL] writel(ioBase1+%xh) = %xh\n",
			   SC5_REG_FRM_SEL(qid, ((int)(issq) & 0x1)), 0);
	// Set the interrupt
	writel(intr_id + wlpptr->wlpd_p->sysintr_frm.spi_num,
		   wlpptr->ioBase1 + SC5_REG_EFF_ID(qid, ((int)(issq) & 0x1)));
	WLDBG_INFO(DBG_LEVEL_0, "[EFF_ID] writel(ioBase1+%xh) = %xh\n",
			   SC5_REG_EFF_ID(qid, ((int)(issq) & 0x1)),
			   intr_id + wlpptr->wlpd_p->sysintr_frm.spi_num);
	return;
}

static void
wldisable_intr(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);

	if (wlpptr->intr_type == INTR_TYPE_MSIX)
	{
		int isr_id;
		for (isr_id = 0; isr_id < wlpptr->num_vectors; isr_id++)
		{
			// unsigned irq_vec = wlpptr->msix_entries[isr_id].vector;
			unsigned irq_vec = wlpptr->msix_ctx[isr_id].irq_vec;
			disable_irq(irq_vec);
		}
	}
	else if (wlpptr->intr_type == PCI_INTR_TYPE_MSI)
	{
		disable_irq(wlpptr->netDev->irq);
	}
	return;
}

static void
wlfree_intr(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);

	if (wlpptr->intr_type == INTR_TYPE_MSIX)
	{
		int isr_id;
		for (isr_id = 0; isr_id < wlpptr->num_vectors; isr_id++)
		{
			// unsigned irq_vec = wlpptr->msix_entries[isr_id].vector;
			unsigned irq_vec = wlpptr->msix_ctx[isr_id].irq_vec;
			if (irq_vec != 0)
			{
				free_irq(irq_vec, &(wlpptr->msix_ctx[isr_id]));
			}
		}
	}
	else if (wlpptr->intr_type == PCI_INTR_TYPE_MSI)
	{
		free_irq(wlpptr->netDev->irq, wlpptr->netDev);
	}
	return;
}

#define IRQNAMESIZE 32
static char irq_name[MAX_CARDS_SUPPORT][SC5_MSIX_NUM][IRQNAMESIZE];

static BOOLEAN
hook_intr_2_queue(struct wlprivate *wlpptr, UINT32 isr_id, SINT32 qid,
				  BOOLEAN issq)
{
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	struct bqm_args *pbqm_args = &wlpd_p->bmq_args;

	unsigned int irq_vec;
	int card_idx;

	if (IS_BUS_TYPE_MCI(wlpptr))
		irq_vec = wlpptr->msix_ctx[isr_id].irq_vec =
			platform_get_irq(wlpptr->wlpd_p->pDev, isr_id);
	else
		irq_vec = wlpptr->msix_ctx[isr_id].irq_vec =
			wlpptr->msix_entries[isr_id].vector;

	card_idx = wlpptr->cardindex;
	sprintf(irq_name[card_idx][isr_id], "%s_%sQ[%d]", wlpptr->netDev->name,
			(issq ? "S" : "R"), qid);

	// ======== TXQ ========
	if ((((pbqm_args->txq_start_index <= qid) &&
		  (qid < (pbqm_args->txq_start_index + pbqm_args->txq_num))) ||
		 ((SC5_BMQ_START_INDEX <= qid) &&
		  (qid < (SC5_BMQ_START_INDEX + SC5_BMQ_NUM)))) &&
		(issq == FALSE))
	{
		if (request_irq(irq_vec, wlSC5MSIX_tx, IRQF_SHARED, irq_name[card_idx][isr_id], &(wlpptr->msix_ctx[isr_id])))
		{ //=> Give any to test....
			WLDBG_ERROR(DBG_LEVEL_2,
						"%s: request_irq for Q(%d) failed\n",
						wlpptr->netDev->name, qid);
			wlpptr->num_vectors = isr_id;
			return FALSE;
		}
		else
		{
			WLDBG_INFO(DBG_LEVEL_2,
					   "Intr[%d], %sQ[%d] => wlSC5MSIX_tx()\n",
					   isr_id, (issq ? "S" : "R"), qid);
		}
	}
	else
		// ======== RXQ ========
		if (((SC5_RXQ_START_INDEX == qid) ||
			 (SC5_RXQ_PROMISCUOUS_INDEX == qid) ||
			 (SC5_RXQ_MGMT_INDEX == qid)) &&
			(issq == TRUE))
		{
			if (request_irq(irq_vec, wlSC5MSIX_rx, IRQF_SHARED, irq_name[card_idx][isr_id], &(wlpptr->msix_ctx[isr_id])))
			{ //=> Give any to test....
				WLDBG_ERROR(DBG_LEVEL_2,
							"%s: request_irq for Q(%d) failed\n",
							wlpptr->netDev->name, qid);
				wlpptr->num_vectors = isr_id;
				return FALSE;
			}
			else
			{
				WLDBG_INFO(DBG_LEVEL_2,
						   "Intr[%d], %sQ[%d] => wlSC5MSIX_rx()\n",
						   isr_id, (issq ? "S" : "R"), qid);
			}
		}
		else
			// ======== RelQ ========
			if (((pbqm_args->bmq_release_index <= qid) &&
				 (qid <
				  (pbqm_args->bmq_release_index +
				   pbqm_args->bmq_release_num))) &&
				(issq == TRUE))
			{
				if (request_irq(irq_vec, wlSC5MSIX_rel, IRQF_SHARED, irq_name[card_idx][isr_id], &(wlpptr->msix_ctx[isr_id])))
				{ //=> Give any to test....
					WLDBG_ERROR(DBG_LEVEL_2,
								"%s: request_irq for Q(%d) failed\n",
								wlpptr->netDev->name, qid);
					wlpptr->num_vectors = isr_id;
					return FALSE;
				}
				else
				{
					WLDBG_INFO(DBG_LEVEL_2,
							   "Intr[%d], %sQ[%d] => wlSC5MSIX_rel()\n",
							   isr_id, (issq ? "S" : "R"), qid);
				}
			}
			else
#if defined(ACNT_REC)
				// ======== SMAC Accounting Record ========
				if (((pbqm_args->racntq_index <= qid) &&
					 (qid <
					  (pbqm_args->racntq_index +
					   pbqm_args->racntq_num))) &&
					(issq == TRUE))
				{
#if 0
		if (request_irq(irq_vec, wlSC5MSIX_RxInfo, IRQF_SHARED, irq_name[card_idx][isr_id], &(wlpptr->msix_ctx[isr_id]))) {	//=> Give any to test....
			WLDBG_ERROR(DBG_LEVEL_2,
				    "%s: request_irq for Q(%d) failed\n",
				    wlpptr->netDev->name, qid);
			wlpptr->num_vectors = isr_id;
			return FALSE;
		} else {
			WLDBG_INFO(DBG_LEVEL_2,
				   "Intr[%d], %sQ[%d] => wlSC5MSIX_RxInfo()\n",
				   isr_id, (issq ? "S" : "R"), qid);
		}
#else
					/*
					   WSW-6521: a problem is found that commit 7302791e will reset cfhul->rxInfoIndex
					   1. A fix for WSW-6521 has a side-effect that there are interrupt flood in SQ15 that driver may get thousands interrupts
					   2. The interrupt can only be disabled if not registering the IRQ-handler
					   3. The purpose of the IRQ-handler is to update the rd-ptr. But fm/hw will keep updating the data even rd-ptr is not touched (queue_full)
					   => A tmp solution: not register the IRQ-handler, until it's fixed
					 */
					wlpptr->msix_ctx[isr_id].irq_vec = 0;
#endif // 0
				}
				else
#endif // ACNT_REC
	   //  rx acnt irq
	   //  Intr#8 = RQ#4
#ifdef RXACNT_REC
					if (pbqm_args->rxacnt_intrid == (isr_id - wlpptr->wlpd_p->intr_shift))
				{
					if (request_irq(irq_vec, wlSC5MSIX_RAcntRec, IRQF_SHARED, irq_name[card_idx][isr_id], &(wlpptr->msix_ctx[isr_id])))
					{ //=> Give any to test....
						WLDBG_ERROR(DBG_LEVEL_2,
									"%s: request_irq for Q(%d) failed\n",
									wlpptr->netDev->name, qid);
						wlpptr->num_vectors = isr_id;
						return FALSE;
					}
					else
					{
						WLDBG_INFO(DBG_LEVEL_2,
								   "Intr[%d], %sQ[%d] => wlSC5MSIX_RAcntRec()\n",
								   isr_id, (issq ? "S" : "R"), qid);
					}
				}
				else
#endif // RXACNT_REC
#if defined(TXACNT_REC)
					// tx acnt irq
					// Intr#10 = RQ#5
					if (pbqm_args->txacnt_intrid == (isr_id - wlpptr->wlpd_p->intr_shift))
					{
						if (request_irq(irq_vec, wlSC5MSIX_TAcntRec, IRQF_SHARED, irq_name[card_idx][isr_id], &(wlpptr->msix_ctx[isr_id])))
						{ //=> Give any to test....
							WLDBG_ERROR(DBG_LEVEL_2,
										"%s: request_irq for Q(%d) failed\n",
										wlpptr->netDev->name, qid);
							wlpptr->num_vectors = isr_id;
							return FALSE;
						}
						else
						{
							WLDBG_INFO(DBG_LEVEL_2,
									   "Intr[%d], %sQ[%d] => wlSC5MSIX_RAcntRec()\n",
									   isr_id, (issq ? "S" : "R"), qid);
						}
					}
					else
#endif // #if defined(TXACNT_REC)

					// ======== R7 ========
					{
						if (request_irq(irq_vec, wlSC5MSIX_r7, IRQF_SHARED, irq_name[card_idx][isr_id], &(wlpptr->msix_ctx[isr_id])))
						{ //=> Give any to test....
							WLDBG_ERROR(DBG_LEVEL_2,
										"%s: request_irq for Q(%d) failed\n",
										wlpptr->netDev->name, qid);
							wlpptr->num_vectors = isr_id;
							return FALSE;
						}
						else
						{
							WLDBG_INFO(DBG_LEVEL_2,
									   "Intr[%d], %sQ[%d] => wlSC5MSIX_r7()\n",
									   isr_id, (issq ? "S" : "R"), qid);
						}
					}
	return TRUE;
}

/*
	A390 supports only 16 interrupts => remap the interrupts
	interrupt_0   ->  R7
	//Rx
	interrupt_1   ->  SQ0 => 0x30_9003_0308=0; 0x30_9003_030C=1    //frame0; ID1
	interrupt_2   ->  SQ8 => 0x30_9003_0388=0; 0x30_9003_038C=2    //frame0; ID2
	interrupt_3   ->  SQ9
	// ReleaseQ
	interrupt_4   ->  SQ10
	interrupt_5   ->  SQ11
	interrupt_6   ->  SQ12
	interrupt_7   ->  SQ13
	// BMQ
	interrupt_8   ->  RQ10
	interrupt_9   ->  RQ11
	interrupt_10  ->  RQ12
	interrupt_11  ->  RQ13
	// Tx (may not be needed)
	interrupt_12  ->  RQ6
	interrupt_13  ->  RQ7
	interrupt_14  ->  RQ8
	interrupt_15  ->  RQ9

remap_intr():
	input:
		wlpptr
		isr_id, which interrupt id to be mapped
	output:
		pqid, which queue to be mapped
		pissq, sq or rq to be mapped
*/
static void
remap_intr(struct wlprivate *wlpptr, UINT32 isr_id, SINT32 *pqid,
		   BOOLEAN *pissq)
{
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	struct bqm_args *pbqm_args = &wlpd_p->bmq_args;

	if (IS_PLATFORM(A390) || IS_PLATFORM(A380))
	{
		switch (isr_id)
		{
		case 0:
			*pqid = -1; // r7 interrupt
			*pissq = TRUE;
			break;
			// Rx
		case 1:
			*pqid = SC5_RXQ_START_INDEX;
			*pissq = TRUE;
			break;
		case 2:
			*pqid = SC5_RXQ_PROMISCUOUS_INDEX;
			*pissq = TRUE;
			break;
		case 3:
			*pqid = SC5_RXQ_MGMT_INDEX;
			*pissq = TRUE;
			break;
			// ReleaseQ
		case 4:
			*pqid = pbqm_args->bmq_release_index;
			*pissq = TRUE;
			break;
		case 5:
			if (wlpptr->devid == SCBT)
			{ // SC5 has only 1 release_q
				*pqid = pbqm_args->bmq_release_index + 1;
				*pissq = TRUE;
			}
			break;
		case 6:
			if (wlpptr->devid == SCBT)
			{ // SC5 has only 1 release_q
				*pqid = pbqm_args->bmq_release_index + 2;
				*pissq = TRUE;
			}
			break;
		case 7:
			if (wlpptr->devid == SCBT)
			{ // SC5 has only 1 release_q
				*pqid = pbqm_args->bmq_release_index + 3;
				*pissq = TRUE;
			}
			break;
			// BMQ
		case 8:
			*pqid = SC5_BMQ_START_INDEX;
			*pissq = FALSE;
			break;
		case 9:
			*pqid = SC5_BMQ_START_INDEX + 1;
			*pissq = FALSE;
			break;
		case 10:
			*pqid = SC5_BMQ_START_INDEX + 2;
			*pissq = FALSE;
			break;
		case 11:
			*pqid = SC5_BMQ_START_INDEX + 3;
			*pissq = FALSE;
			break;
			// Tx (May not be used)
		case 12:
			*pqid = pbqm_args->txq_start_index;
			*pissq = FALSE;
			break;
		case 13:
			*pqid = pbqm_args->txq_start_index + 1;
			*pissq = FALSE;
			break;
		case 14:
			if (wlpptr->devid == SCBT)
			{ // SC5 has only 2 tx_q
				*pqid = pbqm_args->txq_start_index + 2;
				*pissq = FALSE;
			}
			break;
		case 15:
			if (wlpptr->devid == SCBT)
			{ // SC5 has only 2 tx_q
				*pqid = pbqm_args->txq_start_index + 3;
				*pissq = FALSE;
			}
			break;
		default:
			*pqid = -1;
			*pissq = FALSE;
		}
	}
	else
	{
		if (isr_id < wlpptr->wlpd_p->intr_shift)
		{
			*pqid = -1;
			*pissq = FALSE;
		}
		else
		{
			*pqid = (isr_id - wlpptr->wlpd_p->intr_shift) / 2;
			if ((isr_id - wlpptr->wlpd_p->intr_shift) & 1)
			{
				*pissq = TRUE;
			}
			else
			{
				*pissq = FALSE;
			}
		}
	}
	return;
}

static BOOLEAN
hook_intr(struct wlprivate *wlpptr, UINT32 isr_id)
{
	SINT32 qid = -1;
	BOOLEAN issq = FALSE;

	WLDBG_INFO(DBG_LEVEL_2, "processing intr#%d\n", isr_id);

	remap_intr(wlpptr, isr_id, &qid, &issq);
	intr_sel_frm_effid(wlpptr, isr_id - wlpptr->wlpd_p->intr_shift, qid,
					   issq);

	hook_intr_2_queue(wlpptr, isr_id, qid, issq);
	return TRUE;
}
#endif /* SOC_W906X */

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 11, 0)
#define ap8x_enable_msix pci_enable_msix_exact
#else
#define ap8x_enable_msix pci_enable_msix
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
static int
wlprobe_pci(struct pci_dev *pdev, const struct pci_device_id *id)
#else
static int __devinit
wlprobe_pci(struct pci_dev *pdev, const struct pci_device_id *id)
#endif
{
	struct wlprivate *wlpptr = NULL;
	struct wlprivate_data *wlpdptr = NULL;
	phys_addr_t physAddr = 0;
	unsigned long resourceFlags;
	void *physAddr1[2];
	void *physAddr2[2];
	struct net_device *dev;
	int msi_err = 0;
	u8 i = 0;

	printk("=====> %s()\n", __func__);

	WLDBG_ENTER(DBG_LEVEL_2);
#if 0
	if (!function1) {
		function1 = TRUE;
	} else {
		return 0;
	}
#endif
	for (i = 0; i < MAX_CARDS_SUPPORT; i++)
	{
		if (global_private_data[i] == NULL)
		{
			if (!(global_private_data[i] =
					  wl_vzalloc(sizeof(struct wlprivate_data))))
			{
				pr_err("Unable to allocate buffer for global_private_data(size %lu)\n", (unsigned long)(sizeof(struct wlprivate_data)));
				return -ENOMEM;
			}
			global_private_data[i]->AmpduPckReorder =
				(Ampdu_Pck_Reorder_t *)
					wl_vzalloc(sizeof(Ampdu_Pck_Reorder_t) *
							   (sta_num + 1));
			if (global_private_data[i]->AmpduPckReorder == NULL)
			{
				printk("Unable to allocate buffer for Ampdu_Pck_Reorder_t (size %zu)\n", sizeof(Ampdu_Pck_Reorder_t) * (sta_num + 1));
				return -ENOMEM;
			}
			global_private_data[i]->Ampdu_tx =
				(Ampdu_tx_t *)wl_vzalloc(sizeof(Ampdu_tx_t) *
										 (MAX_SUPPORT_AMPDU_TX_STREAM_RUNNING));
			if (global_private_data[i]->Ampdu_tx == NULL)
			{
				printk("Unable to allocate buffer for Ampdu_tx (size %zu)\n", sizeof(Ampdu_tx_t) * (MAX_SUPPORT_AMPDU_TX_STREAM_RUNNING));
				return -ENOMEM;
			}
		}
	}
	if (pci_enable_device(pdev))
	{
		return -EIO;
	}
	if (pci_set_dma_mask(pdev, 0xffffffff))
	{
		printk(KERN_ERR "%s: 32-bit PCI DMA not supported", DRV_NAME);
		goto err_pci_disable_device;
	}
	pci_set_master(pdev);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0)
	dev = alloc_netdev(sizeof(struct wlprivate), DRV_NAME, NET_NAME_UNKNOWN,
					   ether_setup);
#else
	dev = alloc_netdev(sizeof(struct wlprivate), DRV_NAME, ether_setup);
#endif
	if (dev)
	{
		wlpptr = NETDEV_PRIV(struct wlprivate, dev);
		NETDEV_PRIV_S(dev) = wlpptr;
	}
	if (wlpptr == NULL)
	{
		printk(KERN_ERR "%s: no mem for private driver context\n",
			   DRV_NAME);
		goto err_pci_disable_device;
	}
	memset(wlpptr, 0, sizeof(struct wlprivate));
	wlpptr->netDev = dev;
	// wlpdptr = wl_kmalloc(sizeof(struct wlprivate_data), GFP_KERNEL);
	wlpdptr = global_private_data[cardindex % MAX_CARDS_SUPPORT];
	gprv_dat_refcnt++;
	wlpptr->cardindex = cardindex;
	cardindex++;
	if (wlpdptr == NULL)
	{
		printk(KERN_ERR "%s: no mem for private driver data context\n",
			   DRV_NAME);
		goto err_kfree;
	}
	wlpptr->wlpd_p = wlpdptr;
	wlpptr->wlpd_p->pPciDev = pdev;
	wlpptr->wlpd_p->dev = &pdev->dev;
	wlpptr->wlpd_p->dma_alloc_flags = GFP_ATOMIC;
	{
		if (wlpptr->cardindex == 0)
			wlpptr->wlpd_p->gpioresetpin = WDEV0_RESET_PIN;
		else if (wlpptr->cardindex == 1)
			wlpptr->wlpd_p->gpioresetpin = WDEV1_RESET_PIN;

		pci_read_config_dword(wlpptr->wlpd_p->pPciDev,
							  PCI_BASE_ADDRESS_0,
							  (u32 *)&wlpptr->wlpd_p->baseaddress0);
		pci_read_config_dword(wlpptr->wlpd_p->pPciDev,
							  PCI_BASE_ADDRESS_2,
							  (u32 *)&wlpptr->wlpd_p->baseaddress2);
#ifdef SOC_W906X
		pci_read_config_dword(wlpptr->wlpd_p->pPciDev,
							  PCI_BASE_ADDRESS_4,
							  (u32 *)&wlpptr->wlpd_p->baseaddress4);
#endif /* SOC_W906X */
	}
	wlpdptr->rootdev = wlpptr->netDev;

	if (pci_save_state(pdev))
	{
		dev_err(&pdev->dev, "Failed to save pci state\n");
		goto err_pci_disable_device;
	}

	physAddr = pci_resource_start(pdev, 0);
	resourceFlags = pci_resource_flags(pdev, 0);

	wlpptr->nextBarNum = 1; /* 32-bit */

	if (resourceFlags & 0x04)
		wlpptr->nextBarNum = 2; /* 64-bit */

	if (!request_mem_region(physAddr, pci_resource_len(pdev, 0), DRV_NAME))
	{
		printk(KERN_ERR "%s: cannot reserve PCI memory region 0\n",
			   DRV_NAME);
		goto err_kfree1;
	}

	physAddr1[0] = ioremap(physAddr, pci_resource_len(pdev, 0));
	physAddr1[1] = 0;
	wlpptr->ioBase0 = physAddr1[0];
#ifdef WIFI_DATA_OFFLOAD
	wlpptr->ioBase0_phy = physAddr;
#endif
	printk("wlprobe  wlpptr->ioBase0 = %p, len=0x%llx (pcie)\n",
		   wlpptr->ioBase0, pci_resource_len(pdev, 0));
	if (!wlpptr->ioBase0)
	{
		printk(KERN_ERR "%s: cannot remap PCI memory region 0\n",
			   DRV_NAME);
		goto err_release_mem_region_bar0;
	}
	wlpptr->smacCfgAddr = &((SMAC_CTRL_BLK_st *)wlpptr->ioBase0)->config;
	wlpptr->smacStatusAddr =
		&((SMAC_CTRL_BLK_st *)wlpptr->ioBase0)->status;

	/* Clean DMEM */
	memset_io(wlpptr->ioBase0, 0, sizeof(SMAC_CTRL_BLK_st));

	physAddr = pci_resource_start(pdev, wlpptr->nextBarNum);
	if (!request_mem_region(physAddr, pci_resource_len(pdev, wlpptr->nextBarNum), DRV_NAME))
	{
		printk(KERN_ERR "%s: cannot reserve PCI memory region 1\n",
			   DRV_NAME);
		goto err_iounmap_ioBase0;
	}

	physAddr2[0] =
		ioremap(physAddr, pci_resource_len(pdev, wlpptr->nextBarNum));
	physAddr2[1] = 0;
	wlpptr->ioBase1 = physAddr2[0];
#ifdef WIFI_DATA_OFFLOAD
	wlpptr->ioBase1_phy = physAddr;
#endif
	printk("wlprobe  wlpptr->ioBase1 = %p, len=0x%llx (pcie)\n",
		   wlpptr->ioBase1, pci_resource_len(pdev, wlpptr->nextBarNum));
	if (!wlpptr->ioBase1)
	{
		printk(KERN_ERR "%s: cannot remap PCI memory region 1\n",
			   DRV_NAME);
		goto err_release_mem_region_bar1;
	}
	wlpptr->bgscan_period = DEF_BGSCAN_PERIOD;

#ifdef SOC_W906X
	if (!wlpptr->wlpd_p->baseaddress4)
		goto here;
	if (resourceFlags & 0x04)
	{
		wlpptr->nextBarNum = 4; /* 64-bit */
	}

	physAddr = pci_resource_start(pdev, wlpptr->nextBarNum);
	if (!request_mem_region(physAddr, pci_resource_len(pdev, wlpptr->nextBarNum), DRV_NAME))
	{
		printk(KERN_ERR "%s: cannot reserve PCI memory region 2\n",
			   DRV_NAME);
		goto err_iounmap_ioBase2;
	}

	physAddr2[0] =
		ioremap(physAddr, pci_resource_len(pdev, wlpptr->nextBarNum));
	physAddr2[1] = 0;
	wlpptr->ioBase2 = physAddr2[0];
	printk("wlprobe  wlpptr->ioBase2 = %p, len=0x%llx (pcie)\n",
		   wlpptr->ioBase2, pci_resource_len(pdev, wlpptr->nextBarNum));
	if (!wlpptr->ioBase2)
	{
		printk(KERN_ERR "%s: cannot remap PCI memory region 1\n",
			   DRV_NAME);
		goto err_release_mem_region_bar2;
	}
here:

	wl_get_chipinfo(wlpptr);
	if ((wlpptr->hwData.chipRevision == REV_Z1) ||
		(wlpptr->hwData.chipRevision == REV_Z2))
	{
		dev_err(&pdev->dev, "%s: Unsupported chip revision Z1/Z2\n",
				DRV_NAME);
		goto err_iounmap_ioBase2;
	}
#endif /* SOC_W906X */
#define WIFIARB_POST_REQUEST_INTR_DEV_0 "wifiarb_post_request_dev0"
#define WIFIARB_POST_REQUEST_INTR_DEV_1 "wifiarb_post_request_dev1"
	sprintf(wlpptr->netDev->name, "%s%1d", DRV_NAME, wlinitcnt);
	switch (wlinitcnt)
	{
	case 0:
	{

		wlpptr->wlpd_p->AllocSharedMeminfo.file =
			debugfs_create_file(wlpptr->netDev->name, 0644,
								NULL, NULL, &wdev0_fops);
		wlpptr->wlpd_p->PostReqSiginfo.file =
			debugfs_create_file(WIFIARB_POST_REQUEST_INTR_DEV_0, 0200, NULL,
								NULL, &postreq_fops0);
#if defined(SOC_W906X) || defined(NEWDP_ACNT_CHUNKS)
		ACNT_f0 =
			debugfs_create_file("AcntChunk0", 0644, NULL,
								NULL, &ACNT_fops);
#else
		wlpptr->wlpd_p->ACNTmemInfo.file =
			debugfs_create_file("ACNT0mem", 0644, NULL,
								NULL, &ACNT_fops);
#endif

		break;
	}
	case 1:
	{

		wlpptr->wlpd_p->AllocSharedMeminfo.file =
			debugfs_create_file(wlpptr->netDev->name, 0644,
								NULL, NULL, &wdev1_fops);
		wlpptr->wlpd_p->PostReqSiginfo.file =
			debugfs_create_file(WIFIARB_POST_REQUEST_INTR_DEV_1, 0200, NULL,
								NULL, &postreq_fops1);
#if defined(SOC_W906X) || defined(NEWDP_ACNT_CHUNKS)
		ACNT_f1 =
			debugfs_create_file("AcntChunk1", 0644, NULL,
								NULL, &ACNT1_fops);
#else
		wlpptr->wlpd_p->ACNTmemInfo.file =
			debugfs_create_file("ACNT1mem", 0644, NULL,
								NULL, &ACNT_fops);
#endif
		break;
	}
	default:
		printk(" wlinitcnt = %d \n", wlinitcnt);
		break;
	}

	wlpptr->netDev->irq = pdev->irq;
	wlpptr->netDev->mem_start = pci_resource_start(pdev, 0);
	wlpptr->netDev->mem_end = physAddr + pci_resource_len(pdev, 1);
	NETDEV_PRIV_S(wlpptr->netDev) = wlpptr;
	wlpptr->pPciDev = pdev;
	wlpptr->devid = id->device;
	wlpptr->intr_type = PCI_INTR_TYPE_DEFAULT;
#ifdef SINGLE_DEV_INTERFACE
#ifdef WDS_FEATURE
	wlprobeInitWds(wlpptr);
#endif
#endif
	SET_MODULE_OWNER(*(wlpptr->netDev));

	pci_set_drvdata(pdev, (wlpptr->netDev));

#ifdef SOC_W906X
	wlpptr->hframe_virt_addr =
		pci_alloc_consistent(pdev, SC5_HFRAME_MEM_SIZE,
							 &wlpptr->hframe_phy_addr);
	if (wlpptr->hframe_virt_addr == NULL)
	{
		printk(KERN_ERR
			   "%s: Can not allocate memory for hframe register",
			   wlpptr->netDev->name);
		goto err_iounmap_ioBase1;
	}
	printk(KERN_ERR "hframe base addr %llx \n",
		   (long long unsigned int)wlpptr->hframe_phy_addr);

#ifdef WIFI_DATA_OFFLOAD
	if (wfo_disable & (1 << (cardindex - 1)))
	{
		wlpptr->wlpd_p->dol.disable = true;
		wlpptr->wlpd_p->ipc.disable = true;
	}
	else
	{
		wlpptr->wlpd_p->dol.disable = false;
		wlpptr->wlpd_p->ipc.disable = false;
	}
#endif

	wl_init_const(wlpptr->netDev);

	wlpptr->wlpd_p->bus_type = BUS_TYPE_PCI;
	wlprobe_set_reg_value(wlpptr);
	wlprobe_set_intr_info(wlpptr);

	if (pci_find_capability(pdev, PCI_CAP_ID_MSIX))
	{
		int msi_err = 0;

		wlpptr->intr_type = INTR_TYPE_MSIX;
		wl_init_intr(wlpptr);

		// writel(wlpptr->hframe_phy_addr,
		//       wlpptr->ioBase1 + SC5_REG_BASE_ADDR_HOST_128B);

		if (wlpptr->num_vectors)
			wlpptr->msix_entries =
				kcalloc(wlpptr->num_vectors,
						sizeof(struct msix_entry), GFP_KERNEL);

		if (wlpptr->msix_entries)
		{
			int i;
			for (i = 0; i < wlpptr->num_vectors; i++)
				wlpptr->msix_entries[i].entry = i;

			if ((msi_err =
					 ap8x_enable_msix(pdev, wlpptr->msix_entries,
									  wlpptr->num_vectors)) < 0)
			{
				dev_info(&pdev->dev,
						 "MSI-X Allocation Failed with error = %d. Fall back to try MSI\n",
						 msi_err);

				if (wlpptr->msix_entries)
					wl_kfree(wlpptr->msix_entries);

				wlpptr->msix_entries = NULL;
				wlpptr->num_vectors = 0;

				goto try_msi;
			}

			/* MSI-X vectors are allocated */
			dev_info(&pdev->dev,
					 "MSI-X enabled with %d vectors(starts from %d) allocated\n",
					 wlpptr->num_vectors,
					 wlpptr->msix_entries[0].vector);
		}

	} // end of pci_find_capability(pdev, PCI_CAP_ID_MSIX)
try_msi:

	/* If MSI-X is not enabled and try MSI */
	if (!wlpptr->msix_entries)
	{
		wlpptr->intr_type = PCI_INTR_TYPE_MSI;
		wl_init_intr(wlpptr);

		if ((msi_err = pci_enable_msi(pdev)) == 0)
		{
			wlpptr->netDev->irq = pdev->irq;
			dev_info(&pdev->dev, "MSI Enabled with vector=%d\n",
					 pdev->irq);
		}
		else
			dev_info(&pdev->dev,
					 "MSI Enabled failed with err=%d. Fall back to Legacy IRQ %d\n",
					 msi_err, wlpptr->netDev->irq);

	} // end of pci_find_capability(pdev, PCI_CAP_ID_MSI)

	wl_hook_intr(wlpptr);

	WLDBG_DATA(DBG_LEVEL_0, "%s: request_irq %x success pci_intr_type=%d\n",
			   wlpptr->netDev->name, wlpptr->netDev->irq,
			   wlpptr->intr_type);
#else
	if (request_irq(wlpptr->netDev->irq, wlISR, IRQF_SHARED,
					wlpptr->netDev->name, (wlpptr->netDev)))
	{
		printk(KERN_ERR "%s: request_irq failed\n",
			   wlpptr->netDev->name);
		goto err_iounmap_ioBase1;
	}
#endif /* SOC_W906X */

	wlpptr->wlpd_p->CardDeviceInfo = pdev->device & 0xff;
	if (wlpptr->wlpd_p->CardDeviceInfo == 4)
		wlpptr->wlpd_p->SDRAMSIZE_Addr = 0x40fc70b7; /* 16M SDRAM */
	else
		wlpptr->wlpd_p->SDRAMSIZE_Addr = 0x40fe70b7; /* 8M SDRAM */
	WLDBG_INFO(DBG_LEVEL_2,
			   "%s: %s: mem=0x%lx, irq=%d, ioBase0=%x, ioBase1=%x\n",
			   wlpptr->netDev->name, wlgetAdapterDescription(wlpptr, id->vendor, id->device),
			   wlpptr->netDev->mem_start, wlpptr->netDev->irq,
			   wlpptr->ioBase0, wlpptr->ioBase1);

#ifdef WIFI_DATA_OFFLOAD
	if (!wlpptr->wlpd_p->dol.disable)
	{
		dol_core_init(wlpptr);
		ipc_init(wlpptr);
		dol_init(wlpptr);
	}
#endif

	if (wlInit((wlpptr->netDev), id->device))
	{
		goto err_free_irq;
	}

	if (start_wlmon(wlpptr))
	{
		printk("starting background monitor thread fail..\n");
	}

	create_smdata_mmap(wlpptr);

	WLDBG_EXIT(DBG_LEVEL_2);
	return 0;

err_free_irq:
#ifdef SOC_W906X
	if (wlpptr->hframe_virt_addr != NULL)
		pci_free_consistent(pdev, SC5_HFRAME_MEM_SIZE,
							wlpptr->hframe_virt_addr,
							wlpptr->hframe_phy_addr);
	if (wlpptr->msix_entries)
	{
		int i = 0;
		for (i = 0; i < wlpptr->num_vectors; i++)
		{
			free_irq(wlpptr->msix_entries[i].vector,
					 &(wlpptr->msix_ctx[i]));
			wlpptr->msix_entries[i].vector = 0;
		}
	}
	else
	{
		free_irq(wlpptr->netDev->irq, (wlpptr->netDev));
		wlpptr->netDev->irq = 0;
	}
err_iounmap_ioBase2:
	iounmap(wlpptr->ioBase2);
err_release_mem_region_bar2:
	release_mem_region(pci_resource_start(pdev, 2),
					   pci_resource_len(pdev, 2));
#else
	free_irq(wlpptr->netDev->irq, (wlpptr->netDev));
#endif /* SOC_W906X */
err_iounmap_ioBase1:
	iounmap(wlpptr->ioBase1);
err_release_mem_region_bar1:
	release_mem_region(pci_resource_start(pdev, 1),
					   pci_resource_len(pdev, 1));
err_iounmap_ioBase0:
	iounmap(wlpptr->ioBase0);
err_release_mem_region_bar0:
	release_mem_region(pci_resource_start(pdev, 0),
					   pci_resource_len(pdev, 0));
err_kfree1:
#ifdef SOC_W8964
	if ((--gprv_dat_refcnt) == 0)
	{
		u8 i = 0;
		for (i = 0; i < MAX_CARDS_SUPPORT; i++)
		{
			vfree(global_private_data[i]);
			global_private_data[i] = NULL;
		}
	}
#endif /* SOC_W8964 */
err_kfree:
	free_netdev(dev);
err_pci_disable_device:
	pci_disable_device(pdev);
	WLDBG_EXIT_INFO(DBG_LEVEL_2, "init error");
	return -EIO;
}

#ifdef SOC_W906X
static int
wlremove_mci(struct platform_device *pdev)
{
	struct net_device *netdev = platform_get_drvdata(pdev);
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);

	WLDBG_ENTER(DBG_LEVEL_2);

	if (wlDeinit(netdev))
	{
		printk(KERN_ERR "%s: deinit of device failed\n", netdev->name);
	}

	if (wlpptr->hframe_virt_addr)
	{
		wl_dma_free_coherent(&(pdev->dev), SC5_HFRAME_MEM_SIZE,
							 wlpptr->hframe_virt_addr,
							 wlpptr->hframe_phy_addr);
	}

	if (netdev->irq)
	{
		wlfree_intr(netdev);
		netdev->irq = 0;
	}

	/* Release Shared Memory FW Host I/O Request MailBox Region */
	if (wlpptr->wlpd_p->AllocSharedMeminfo.data)
	{
		wl_dma_free_coherent(wlpptr->wlpd_p->dev, FW_IO_MB_SIZE,
							 wlpptr->wlpd_p->AllocSharedMeminfo.data,
							 wlpptr->wlpd_p->AllocSharedMeminfo.dataPhysicalLoc);
	}
	if (wlpptr->wlpd_p->MrvlPriSharedMem.data)
	{
		wl_dma_free_coherent(wlpptr->wlpd_p->dev,
							 sizeof(drv_fw_shared_t),
							 wlpptr->wlpd_p->MrvlPriSharedMem.data,
							 wlpptr->wlpd_p->MrvlPriSharedMem.dataPhysicalLoc);
	}
	if (wlpptr->wlpd_p->AllocSharedMeminfo.file)
	{
		debugfs_remove(wlpptr->wlpd_p->AllocSharedMeminfo.file);
		wlpptr->wlpd_p->AllocSharedMeminfo.file = NULL;
	}
	if (wlpptr->wlpd_p->PostReqSiginfo.file)
	{
		debugfs_remove(wlpptr->wlpd_p->PostReqSiginfo.file);
		wlpptr->wlpd_p->PostReqSiginfo.file = NULL;
	}
	if (ACNT_f0)
	{
		debugfs_remove(ACNT_f0);
		ACNT_f0 = NULL;
	}
	if (ACNT_f1)
	{
		debugfs_remove(ACNT_f1);
		ACNT_f1 = NULL;
	}

	if (wlpptr->wlpd_p->smdata_mmap_info.file)
	{
		debugfs_remove(wlpptr->wlpd_p->smdata_mmap_info.file);
		wlpptr->wlpd_p->smdata_mmap_info.file = NULL;
	}

	cardindex--;
	if ((--gprv_dat_refcnt) == 0)
	{
		u8 i = 0;
		for (i = 0; i < MAX_CARDS_SUPPORT; i++)
		{
			wl_vfree(global_private_data[i]->AmpduPckReorder);
			wl_vfree(global_private_data[i]->Ampdu_tx);
			wl_vfree(global_private_data[i]);
			global_private_data[i] = NULL;
		}
	}

#ifdef CFG80211
	/* destory cfg80211 subsystem */
	mwl_cfg80211_destroy(wlpptr);
#endif
	free_netdev(netdev);

	WLDBG_EXIT(DBG_LEVEL_2);
	return 0;
}
#endif /* SOC_W906X */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
static void
wlremove_pci(struct pci_dev *pdev)
#else
static void __devexit
wlremove_pci(struct pci_dev *pdev)
#endif
{
	struct net_device *netdev = pci_get_drvdata(pdev);
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);

	WLDBG_ENTER(DBG_LEVEL_2);

	if (wlDeinit(netdev))
	{
		printk(KERN_ERR "%s: deinit of device failed\n", netdev->name);
	}
	if (netdev->irq)
	{
#ifdef SOC_W906X
		wlfree_intr(netdev);
		netdev->irq = 0;
#else
		free_irq(netdev->irq, netdev);
#endif /* SOC_W906X */
	}

	if (wlpptr->msix_entries)
	{
		pci_disable_msix(pdev);
		wl_kfree(wlpptr->msix_entries);
		wlpptr->msix_entries = NULL;
		wlpptr->num_vectors = 0;
	}

	/* Release Shared Memory FW Host I/O Request MailBox Region */
	if (wlpptr->wlpd_p->AllocSharedMeminfo.data)
	{
		wl_dma_free_coherent(wlpptr->wlpd_p->dev, FW_IO_MB_SIZE,
							 wlpptr->wlpd_p->AllocSharedMeminfo.data,
							 wlpptr->wlpd_p->AllocSharedMeminfo.dataPhysicalLoc);
	}
	if (wlpptr->wlpd_p->MrvlPriSharedMem.data)
	{
		wl_dma_free_coherent(wlpptr->wlpd_p->dev,
							 sizeof(drv_fw_shared_t),
							 wlpptr->wlpd_p->MrvlPriSharedMem.data,
							 wlpptr->wlpd_p->MrvlPriSharedMem.dataPhysicalLoc);
	}
	if (wlpptr->wlpd_p->AllocSharedMeminfo.file)
	{
		debugfs_remove(wlpptr->wlpd_p->AllocSharedMeminfo.file);
		wlpptr->wlpd_p->AllocSharedMeminfo.file = NULL;
	}
	if (wlpptr->wlpd_p->PostReqSiginfo.file)
	{
		debugfs_remove(wlpptr->wlpd_p->PostReqSiginfo.file);
		wlpptr->wlpd_p->PostReqSiginfo.file = NULL;
	}
	if (ACNT_f0)
	{
		debugfs_remove(ACNT_f0);
		ACNT_f0 = NULL;
	}
	if (ACNT_f1)
	{
		debugfs_remove(ACNT_f1);
		ACNT_f1 = NULL;
	}
#ifdef SOC_W906X
	if (wlpptr->wlpd_p->smdata_mmap_info.file)
	{
		debugfs_remove(wlpptr->wlpd_p->smdata_mmap_info.file);
		wlpptr->wlpd_p->smdata_mmap_info.file = NULL;
	}
#endif /* SOC_W906X */

	wlPowerResetFw(netdev);
	mdelay(2000);
#ifdef SOC_W906X
	pci_free_consistent(pdev, SC5_HFRAME_MEM_SIZE, wlpptr->hframe_virt_addr,
						wlpptr->hframe_phy_addr);
	iounmap(wlpptr->ioBase2);
	release_mem_region(pci_resource_start(pdev, 4),
					   pci_resource_len(pdev, 4));
#endif
	iounmap(wlpptr->ioBase1);
	iounmap(wlpptr->ioBase0);
	release_mem_region(pci_resource_start(pdev, 2),
					   pci_resource_len(pdev, 2));
	release_mem_region(pci_resource_start(pdev, 0),
					   pci_resource_len(pdev, 0));
	pci_disable_device(pdev);
	pci_clear_master(pdev);

	cardindex--;
	if ((--gprv_dat_refcnt) == 0)
	{
		u8 i = 0;
		for (i = 0; i < MAX_CARDS_SUPPORT; i++)
		{
			wl_vfree(global_private_data[i]->AmpduPckReorder);
			wl_vfree(global_private_data[i]->Ampdu_tx);
			wl_vfree(global_private_data[i]);
			global_private_data[i] = NULL;
		}
	}

#ifdef CFG80211
	/* destory cfg80211 subsystem */
	mwl_cfg80211_destroy(wlpptr);
#endif

#ifdef WIFI_DATA_OFFLOAD
	if (!wlpptr->wlpd_p->dol.disable)
	{
		dol_deinit(wlpptr);
		ipc_deinit(wlpptr);
		dol_core_deinit(wlpptr);
	}
#endif

	free_netdev(netdev);
	WLDBG_EXIT(DBG_LEVEL_2);
}

static int
wlsuspend_mci(struct device *dev)
{
	WLDBG_INFO(DBG_LEVEL_2, "%s: suspended device\n", DRV_NAME);
	return 0;
}

static int
wlsuspend_pci(struct pci_dev *pdev, pm_message_t state)
{
	WLDBG_INFO(DBG_LEVEL_2, "%s: suspended device\n", DRV_NAME);
	return 0;
}

static int
wlresume_mci(struct device *dev)
{
	WLDBG_INFO(DBG_LEVEL_2, "%s: resumed device\n", DRV_NAME);
	return 0;
}

static int
wlresume_pci(struct pci_dev *pdev)
{
	WLDBG_INFO(DBG_LEVEL_2, "%s: resumed device\n", DRV_NAME);
	return 0;
}

#ifdef WL_DEBUG
static const char *
wlgetAdapterDescription(struct wlprivate *wlpptr, u_int32_t vendorid,
						u_int32_t devid)
{
#ifdef SOC_W906X
	if (IS_BUS_TYPE_MCI(wlpptr))
	{
		/* XXX, fix it until a valid id could be retrieved. */
		return "NXP AP-8x 802.11 adapter";
	}
	else
#endif /* SOC_W906X */
	{
		int numEntry =
			((sizeof(wlid_tbl) / sizeof(struct pci_device_id)) - 1);

		while (numEntry)
		{
			numEntry--;
			if ((wlid_tbl[numEntry].vendor == vendorid) &&
				(wlid_tbl[numEntry].device == devid))
			{
				if ((const char *)wlid_tbl[numEntry].driver_data != NULL)
				{
					return (const char *)wlid_tbl[numEntry].driver_data;
				}
				break;
			}
		}
		return "NXP ???";
	}
}
#endif
#ifdef NEW_DP
int doneTxDoneCnt = 50;
#endif
UINT32 AUTO_MU_TIME_CONSTANT = 10; // multiple of 10msec
static void
timer_routine(unsigned long arg)
{
	UINT8 num = NUM_OF_DESCRIPTOR_DATA;
	struct net_device *netdev = (struct net_device *)arg;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	struct bqm_args *pbqm_args = &wlpd_p->bmq_args;

	struct wlprivate *wlpptr_vap_p;
	vmacApInfo_t *vmacSta_vap_p;
	MIB_802DOT11 *mib;

	wlpptr->wlpd_p->Timer.function = timer_routine;
	wlpptr->wlpd_p->Timer.data = (unsigned long)netdev;
	wlpptr->wlpd_p->Timer.expires = jiffies + HZ / 100;
#ifndef AMSDUOVERAMPDU
	extStaDb_AggrFrameCk(wlpptr->vmacSta_p, 0);
#endif

	// If it's tx-sync => no packets are queued
	/*We constantly check all txq to see if any txq is not empty. Once any txq is not empty, we schedule a task again
	 * to enable all txq are flushed out when no new incoming pkt from host. Sometimes pkts can sit inside txq forever when txq depth
	 * is too deep.
	 */
#ifdef SOC_W906X
	if (wlpptr->wlpd_p->tx_async == TRUE)
	{
#else
	if (!wlpptr->wlpd_p->isTxTaskScheduled)
	{
#endif /* SOC_W906X */
		while (num--)
		{
			if (wlpptr->wlpd_p->txQ[num].qlen != 0)
			{
#ifdef USE_TASKLET
				tasklet_schedule(&wlpptr->wlpd_p->txtask);
#else
				schedule_work(&wlpptr->wlpd_p->txtask);
#endif
#ifndef SOC_W906X
				wlpptr->wlpd_p->isTxTaskScheduled = 1;
#endif
				break;
			}
		}
	}
#ifdef NEW_DP

	/*Auto MU set creation by finding potential sta to group */
	wlpptr->wlpd_p->MUtimercnt++;
	if ((wlpptr->wlpd_p->MUtimercnt >= AUTO_MU_TIME_CONSTANT))
	{ // every AUTO_MU_TIME_CONSTANT x HZ/100
		wlpptr->wlpd_p->MUtimercnt = 0;

#ifdef SOC_W906X
		if ((wlpptr->vdev[wlpptr->wlpd_p->MUcurVapidx] != NULL) &&
			((wlpptr->vdev[wlpptr->wlpd_p->MUcurVapidx]->flags & IFF_RUNNING)))
		{
#else
		if ((wlpptr->vdev[wlpptr->wlpd_p->MUcurVapidx]->flags & IFF_RUNNING))
		{
#endif

#ifdef USE_TASKLET
			wlpptr_vap_p =
				NETDEV_PRIV_P(struct wlprivate,
							  wlpptr->vdev[wlpptr->wlpd_p->MUcurVapidx]);
			vmacSta_vap_p = wlpptr_vap_p->vmacSta_p;
			mib = vmacSta_vap_p->ShadowMib802dot11;

			if (*(mib->mib_mumimo_mgmt))
			{
				tasklet_init(&wlpptr->wlpd_p->MUtask,
							 (void *)MUAutoSet_Hdlr,
							 (unsigned long)wlpptr->vdev[wlpptr->wlpd_p->MUcurVapidx]);
				tasklet_schedule(&wlpptr->wlpd_p->MUtask);
			}
#endif
		}
		wlpptr->wlpd_p->MUcurVapidx++;

		if (wlpptr->wlpd_p->MUcurVapidx >= bss_num)
			wlpptr->wlpd_p->MUcurVapidx = 0;
	}
#ifdef SOC_W906X
	// txdone poll only for  platform A390 and A380
	if (IS_PLATFORM(A390) || IS_PLATFORM(A380))
	{
		if (wlpptr->wlpd_p->bfwreset == 0)
		{
			if (!(doneTxDoneCnt++ % 5))
			{
				// Polling mode, simulate the tx-done interrupt
				wlpptr->BQRelId |=
					pbqm_args->buf_release_msix_mask;
				tasklet_hi_schedule(&wlpptr->wlpd_p->buf_rel_task);
			}
		}
	}

	if (wlpd_p->idx_test_arg.pkt_cnt > 0)
	{
		long pktcnt =
			(wlpd_p->idx_test_arg.pkt_cnt <
			 128)
				? wlpd_p->idx_test_arg.pkt_cnt
				: 128;
		wlTxSkbTest_1(netdev, pktcnt, wlpd_p->idx_test_arg.pkt_size,
					  wlpd_p->idx_test_arg.qid,
					  wlpd_p->idx_test_arg.frameType);
		wlpd_p->idx_test_arg.pkt_cnt -= pktcnt;
	}
#else
	if (wlpptr->wlpd_p->bfwreset == 0)
		if (!(doneTxDoneCnt++ % 5))
			wlTxDone(netdev);
#endif /* SOC_W906X */
#endif
#ifdef SOC_W906X
	if (IS_PLATFORM(A390) || IS_PLATFORM(A380))
		wlIntrPoll(netdev);
#endif /* SOC_W906X */
	{
		static uint8 passcnt = 0;
		if (passcnt < 100)
		{
			passcnt++;
		}
		else
		{
			// Run it once per 100ms or 1sec
			uint8 i;
			extern const u_int32_t
				buf_pool_max_entries[SC5_BMQ_NUM];
			static uint32 last_qlen[SC5_BMQ_NUM];

			for (i = SC5_BMQ_START_INDEX;
				 i < SC5_BMQ_START_INDEX + SC5_BMQ_NUM; i++)
			{
				struct wldesc_data *wlqm =
					&wlpptr->wlpd_p->descData[i];
				rpkt_reuse_free_resource(&wlqm->rq.skbTrace,
										 &last_qlen[i -
													SC5_BMQ_START_INDEX],
										 buf_pool_max_entries[i -
															  SC5_BMQ_START_INDEX]);
			}
			passcnt = 0;
		}
	}
	add_timer(&wlpptr->wlpd_p->Timer);
}

extern void wlRecv(struct net_device *netdev);
static void
_wlreset(struct work_struct *work)
{
	struct wlprivate_data *wlpd_p =
		container_of(work, struct wlprivate_data, resettask);
	struct wlprivate *wlpptr = wlpd_p->masterwlp;

	wlreset(wlpptr->netDev);
}

#ifdef MRVL_DFS
static void
_wlRadarDetection(struct work_struct *work)
{
	struct wlprivate_data *wlpd_p =
		container_of(work, struct wlprivate_data, dfstask);
	struct wlprivate *wlpptr = wlpd_p->masterwlp;

	wlRadarDetection(wlpptr->netDev, DFS_MAIN);
}

#ifdef CONCURRENT_DFS_SUPPORT
extern void dfs_proc_aux(struct net_device *dev,
						 SCANNER_CTL_EVENT event,
						 DFS_STATE dfs_status, UINT8 IsFromAux);
static void
_wlAuxChRadarDetection(struct work_struct *work)
{
	struct wlprivate_data *wlpd_p =
		container_of(work, struct wlprivate_data, dfstaskAux);
	struct wlprivate *wlpptr = wlpd_p->masterwlp;

	dfs_proc_aux(wlpptr->netDev, ScnrCtl_Radar_Detected, DFS_STATE_SCAN, 1);
}
#endif /* CONCURRENT_DFS_SUPPORT */
static void
_wlApplyCSAChannel(struct work_struct *work)
{
	struct wlprivate_data *wlpd_p =
		container_of(work, struct wlprivate_data, csatask);
	struct wlprivate *wlpptr = wlpd_p->masterwlp;

	wlApplyCSAChannel(wlpptr->netDev);
}
#endif

static void
_wlConsecTxFail(struct work_struct *work)
{
	struct wlprivate_data *wlpd_p =
		container_of(work, struct wlprivate_data, kickstatask);
	struct wlprivate *wlpptr = wlpd_p->masterwlp;

	wlConsecTxFail(wlpptr->netDev);
}

#ifdef NEW_DP
extern void wlHandleAcnt(struct net_device *netdev);
static void
_wlAcntRecordReady(struct work_struct *work)
{
	struct wlprivate_data *wlpd_p =
		container_of(work, struct wlprivate_data, acnttask);
	struct wlprivate *wlpptr = wlpd_p->masterwlp;

	wlHandleAcnt(wlpptr->netDev);
}

#ifdef SOC_W906X
static void
_wlOffChanTask(struct work_struct *work)
{
	struct wlprivate_data *wlpd_p =
		container_of(work, struct wlprivate_data, offchantask);
	struct wlprivate *wlpptr = wlpd_p->masterwlp;

	wlOffChanTask(wlpptr->netDev);
}
#else  // 906X off-channel
static void
_wlOffChanDone(struct work_struct *work)
{
	struct wlprivate_data *wlpd_p =
		container_of(work, struct wlprivate_data, offchandonetask);
	struct wlprivate *wlpptr = wlpd_p->masterwlp;

	wlOffChanDone(wlpptr->netDev);
}
#endif // 906X off-channel

#endif

#ifdef SYSFS_STADB_INFO
static void
_wlSysfsSTAHdlTask(struct work_struct *work)
{
	struct wlprivate_data *wlpd_p =
		container_of(work, struct wlprivate_data, sysfstask);
	struct wlprivate *wlpptr = wlpd_p->masterwlp;

	ap8xLnxStat_clients_WQhdl(wlpptr->netDev);
}
#endif /* SYSFS_STADB_INFO */

#ifndef USE_TASKLET
static void
_wlRecv(struct work_struct *work)
{
	struct wlprivate_data *wlpd_p =
		container_of(work, struct wlprivate_data, rxtask);
	struct wlprivate *wlpptr = wlpd_p->masterwlp;

	wlRecv(wlpptr->netDev);
}

static void
_wlDataTxHdl(struct work_struct *work)
{
	struct wlprivate_data *wlpd_p =
		container_of(work, struct wlprivate_data, txtask);
	struct wlprivate *wlpptr = wlpd_p->masterwlp;

	wlDataTxHdl(wlpptr->netDev);
}

#if defined(ACNT_REC) && defined(SOC_W906X)
// static void _wlRxInfo(struct work_struct *work)
//{
//       struct wlprivate_data *wlpd_p = container_of(work, struct wlprivate_data, rxinfotask);
//       struct wlprivate *wlpptr = wlpd_p->masterwlp;
//
//       wlrxinfo_qproc(wlpptr->netDev);
// }
// static void _wlRAcnt(struct work_struct *work)
//{
//       struct wlprivate_data *wlpd_p = container_of(work, struct wlprivate_data, rxtask);
//       struct wlprivate *wlpptr = wlpd_p->masterwlp;
//
//       wlRxPPDUAcntHndl(wlpptr->netDev);
// }

#endif // defined(TXACNT_REC) && defined (SOC_W906X)

#endif

#ifdef MV_NSS_SUPPORT
static struct mv_nss_ops *wlNssOps;
#endif

static const struct net_device_ops wl_netdev_ops = {
	.ndo_open = wlopen,
	.ndo_stop = wlstop,
	.ndo_start_xmit = wlDataTx,
	.ndo_do_ioctl = wlIoctl,
	.ndo_set_mac_address = wlsetMacAddr,
	.ndo_tx_timeout = wltxTimeout,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 2, 0)
	.ndo_set_rx_mode = wlsetMcList,
#else
	.ndo_set_multicast_list = wlsetMcList,
#endif
	.ndo_change_mtu = wlchangeMtu,
	.ndo_get_stats = wlgetStats,
};

static const struct ethtool_ops wl_ethtool_ops = {
	.get_settings = NULL,
};

#ifdef SOC_W906X
/** public functions **/
// Timeout period for checking SMAC ready
//      => If running on PDM system, it should be longer (longer than 300ms)
#define INIT_SMAC_RDY_TIMEUT 500
// Polling & check SMAC ready
//      TRUE: it's ready
//      FALSE: Failed to get ready within INIT_SMAC_RDY_TIMEUT
BOOLEAN
wlInitChkSmacRdy(struct net_device *netdev)
{
	BOOLEAN result = FALSE;
	int counter = 0;

	while (counter < INIT_SMAC_RDY_TIMEUT)
	{
		// Need to delya before checking CheckSMACReady(). Otherwise it may fail at the 1st time
		mdelay(1);
		if (CheckSMACReady(netdev))
		{
			result = TRUE;
			break;
		}
		counter++;
	}

	return result;
}

// MFG Support 2017/09/07
#ifdef MFG_SUPPORT
#define WAIT_FW_COMPLETE_ITERATIONS 9000000
#define MFG_CMD_MAX_LENGTH 2048

struct mfg_handle
{
	struct sock *nlsk;
	struct net_device *netdev;
};

struct hostcmd_header
{
	__le16 cmd;
	__le16 len;
	u8 seq_num;
	u8 macid;
	__le16 result;
} __packed;

struct cmd_header
{
	__le16 command;
	__le16 len;
} __packed;

static int devcnt;
static struct mfg_handle mfg_handle[2];

static void
mfg_send_cmd(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
#ifdef KF_MFG_MODE
	struct cmd_header *cmd_hdr = (struct cmd_header *)&wlpptr->pCmdBuf[2];
	u16 len = le16_to_cpu(cmd_hdr->len);

	writel(wlpptr->wlpd_p->pPhysCmdBuf, wlpptr->ioBase1 + 0xcd0);
	writel(0x00, wlpptr->ioBase1 + 0xcd4);
	writel(0x00, wlpptr->ioBase1 + MACREG_REG_INT_CODE);
	writel(len + 4, wlpptr->ioBase1 + 0xc40);
#endif
#if 0 // For MOCHI
	writel(wlpptr->wlpd_p->pPhysCmdBuf,
	       wlpptr->ioBase1 + MACREG_REG_GEN_PTR_MCI);
	writel(MACREG_H2ARIC_BIT_DOOR_BELL,
	       wlpptr->ioBase1 + MACREG_REG_H2A_INTERRUPT_EVENTS_MCI);
#else // For Auto check (PCIe or Mochi) reference from function wlprobe_set_reg_value(struct wlprivate *wlpptr)
	writel(wlpptr->wlpd_p->pPhysCmdBuf,
		   wlpptr->ioBase1 + wlpptr->wlpd_p->reg.gen_ptr);
	writel(MACREG_H2ARIC_BIT_DOOR_BELL,
		   wlpptr->ioBase1 + wlpptr->wlpd_p->reg.h2a_int_events);
#endif
}

static int
mfg_wait_complete(struct net_device *netdev, unsigned short cmd)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	unsigned long curr_iteration = WAIT_FW_COMPLETE_ITERATIONS;
	unsigned short int_code = 0;
#ifdef KF_MFG_MODE
	int offset = 2;
#else
	int offset = 0;
#endif

	do
	{
		int_code = le16_to_cpu(*((__le16 *)&wlpptr->pCmdBuf[offset]));
		udelay(1);
	} while ((int_code != cmd) && (--curr_iteration));

	if (curr_iteration == 0)
		return -EIO;

	// udelay(1);

	return 0;
}

static int
mfg_exec_cmd(struct net_device *netdev, unsigned short cmd)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	bool busy = false;

	if (!wlpptr->wlpd_p->inSendCmd)
	{
		wlpptr->wlpd_p->inSendCmd = true;
		mfg_send_cmd(netdev);
		if (mfg_wait_complete(netdev, 0x8000 | cmd))
		{
			printk(KERN_ERR "%s: timeout: 0x%04x\n", __func__, cmd);
			wlpptr->wlpd_p->inSendCmd = false;
			return -EIO;
		}
	}
	else
	{
		printk(KERN_WARNING "%s: previous command is still running\n",
			   __func__);
		busy = true;
	}

	if (!busy)
		wlpptr->wlpd_p->inSendCmd = false;

	return 0;
}

int send_mfg_cmd(struct net_device *netdev, char *mfgcmd)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct hostcmd_header *pcmd;
	struct cmd_header *cmd_hd = (struct cmd_header *)(mfgcmd + 4);
	u16 len;
	u16 cmd;
	unsigned long flags;
#ifdef KF_MFG_MODE
	int offset = 2;
#else
	int offset = 0;
#endif

	ktime_t start_time;
	s64 time_elapsed;

	pcmd = (struct hostcmd_header *)&wlpptr->pCmdBuf[0];

	SPIN_LOCK_IRQSAVE(&wlpptr->wlpd_p->locks.fwLock, flags);

	len = le16_to_cpu(cmd_hd->len);
	memset(pcmd, 0x00, len + 4);
#ifdef KF_MFG_MODE
	memcpy((char *)pcmd, mfgcmd, len + 4);
#else
	memcpy((char *)pcmd, cmd_hd, len);
#endif

	cmd = le16_to_cpu(cmd_hd->command);
	start_time = ktime_get_real();
	if (mfg_exec_cmd(netdev, cmd))
	{
		SPIN_UNLOCK_IRQRESTORE(&wlpptr->wlpd_p->locks.fwLock, flags);
		printk(KERN_ERR "%s: failed execution", __func__);
		return -EIO;
	}
	time_elapsed = ktime_to_us(ktime_sub(ktime_get_real(), start_time));
	// printk(KERN_ERR "Result from FW, time elapsed %lld us", time_elapsed);
	// netdev_notice(netdev, "time elapsed %lld us", time_elapsed);

	cmd_hd = (struct cmd_header *)&wlpptr->pCmdBuf[offset];
	len = le16_to_cpu(cmd_hd->len);
	memcpy(mfgcmd, (char *)&wlpptr->pCmdBuf[offset], len);

	SPIN_UNLOCK_IRQRESTORE(&wlpptr->wlpd_p->locks.fwLock, flags);

	return 0;
}

static void
process_mfgbridge_cmd(struct sk_buff *skb)
{
	int device_no;
	unsigned short len;
	unsigned char *cmd;
	struct sk_buff *resp_skb;
	int ret;
	struct nlmsghdr *nlh;
	unsigned int pid, seq;
	kuid_t uid;
	void *data;

	nlh = (struct nlmsghdr *)skb->data;
	pid = NETLINK_CREDS(skb)->pid;
	uid = NETLINK_CREDS(skb)->uid;
	seq = nlh->nlmsg_seq;
	data = NLMSG_DATA(nlh);

	cmd = wl_kmalloc(MFG_CMD_MAX_LENGTH, GFP_KERNEL);
	if (!cmd)
		return;

	if (!memcmp(data, "mfg ", strlen("mfg ")))
	{
		data += strlen("mfg ");
		device_no = *(int *)data;
		// printk("received bridge device_no =%d\n", device_no);
		data += sizeof(int);
		len = le16_to_cpu(*(__le16 *)(data + 2));
		*(unsigned short *)&cmd[0] = len;
		*(__le16 *)&cmd[2] = cpu_to_le16(1);
		memcpy(&cmd[4], data, len);
		if (send_mfg_cmd(mfg_handle[device_no].netdev, cmd))
		{
			printk(KERN_ERR "mfgcmd failed ...\n");
			goto out;
		}
	}
	else
		goto out;
	len = le16_to_cpu(*(__le16 *)(cmd + 2));
	resp_skb = alloc_skb(len + sizeof(struct nlmsghdr) + 1, GFP_ATOMIC);
	nlh = __nlmsg_put(resp_skb, NETLINK_CB(skb).portid, seq, 0, len, 0);
	nlh->nlmsg_flags = 0;
	data = NLMSG_DATA(nlh);
	memcpy((char *)data, cmd, len);
	// printk("jklchen memcpy len =%d\n", len);
	// mwl_hex_dump((u8*)data, len);
	NETLINK_CB(resp_skb).dst_group = 0;
	ret = netlink_unicast(skb->sk, resp_skb,
						  NETLINK_CB(skb).portid, MSG_DONTWAIT);
	if (ret < 0)
		printk(KERN_ERR "send failed...\n");
out:
	wl_kfree(cmd);
}

void mfg_handler_init(struct net_device *netdev)
{
	struct sock *nlsk;
	struct netlink_kernel_cfg cfg = {
		.input = process_mfgbridge_cmd,
	};
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate *parent_wlpptr = GET_PARENT_PRIV(wlpptr);

	printk(KERN_ERR "mfg_handler_init ChipRevision = %d\n",
		   parent_wlpptr->hwData.chipRevision);
#if 1
	nlsk = netlink_kernel_create(&init_net, 29 + devcnt, &cfg);
	printk("***********mfg netlink_kernel_create = %d\n", 29 + devcnt);
#else
	nlsk = netlink_kernel_create(&init_net, 30 + devcnt, &cfg);
	printk("PCIE  wdev0 30+devcnt =%d\n", 30 + devcnt);
#endif
	if (!nlsk)
	{
		printk("%s: Failed to create netlink ...\n", __func__);
		devcnt++;
		return;
	}

	mfg_handle[devcnt].nlsk = nlsk;
	mfg_handle[devcnt].netdev = netdev;
	devcnt++;
}
#endif
// endif mfg support
#endif /* SOC_W906X */

int wlinitcnt = 0;
extern char cwd[256];
extern void wl_get_cwd(char buf[]);
#ifdef SOC_W906X
extern mvl_status_t CH_radio_status[IEEEtypes_MAX_CHANNELS +
									IEEEtypes_MAX_CHANNELS_A];

int wlInit(struct net_device *netdev, u_int16_t devid)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	int retCode, index, i, j;
	int bssidmask = 0;
	unsigned char macaddr[6] = {0x00, 0xde, 0xad, 0xde, 0xad, 0xee};
	unsigned char major;
	unsigned char minor;
	unsigned char rel;
	coredump_cmd_t *core_dump = NULL;
	char *buff = NULL;

#ifdef WTP_SUPPORT
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
	struct netlink_kernel_cfg cfg = {
		.input = txWtpMgmtMsg,
	};
#endif
	int netlink_num = 31;
#endif

	WLDBG_ENTER(DBG_LEVEL_2);

	smeCmdBuf_q =
		(macmgmtQ_CmdBuf_t *)wl_vzalloc(sizeof(macmgmtQ_CmdBuf_t) *
										SME_CMD_BUF_Q_LIMIT);
	if (!smeCmdBuf_q)
	{
		printk("wlInit smeCmdBuf_q alloc fail: size=%zu*%d=%zu\n",
			   sizeof(macmgmtQ_CmdBuf_t), SME_CMD_BUF_Q_LIMIT,
			   sizeof(macmgmtQ_CmdBuf_t) * SME_CMD_BUF_Q_LIMIT);
		goto failed;
	}

	wl_register_dump_func(wlpptr->wlpd_p);
	wlpptr->wlpd_p->masterwlp = wlpptr;
#ifndef SOC_W906X
	wlpptr->wlpd_p->isTxTaskScheduled = 0;
#endif
#ifndef NAPI
#ifdef USE_TASKLET
	tasklet_init(&wlpptr->wlpd_p->rxtask, (void *)wlRecv,
				 (unsigned long)netdev);
#else
	INIT_WORK(&wlpptr->wlpd_p->rxtask, (void (*)(void *))_wlRecv);
#endif
#endif
#if defined(ACNT_REC) && defined(SOC_W906X)
	wlpptr->wlpd_p->rxinfotask.handle_func =
		(void (*)(unsigned long))wlrxinfo_qproc;
	wlpptr->wlpd_p->rxinfotask.phandle_param = (unsigned long)netdev;
	mthread_init(&wlpptr->wlpd_p->rxinfotask);
#endif // #if defined(ACNT_REC) && defined (SOC_W906X)
#if defined(RXACNT_REC) && defined(SOC_W906X)
	wlpptr->wlpd_p->racnttask.handle_func =
		(void (*)(unsigned long))wlRxPPDUAcntHndl;
	wlpptr->wlpd_p->racnttask.phandle_param = (unsigned long)netdev;
	mthread_init(&wlpptr->wlpd_p->racnttask);
#endif //
#if defined(TXACNT_REC) && defined(SOC_W906X)
	wlpptr->wlpd_p->tacnttask.handle_func = wlTxPPDUAcntHndl;
	wlpptr->wlpd_p->tacnttask.phandle_param = (unsigned long)netdev;
	mthread_init(&wlpptr->wlpd_p->tacnttask);
#endif // #if defined(ACNT_REC) && defined (SOC_W906X)

	// A390/A385 platform supports only 16 interrupts => Use polling function instead
	if (IS_PLATFORM(A390) || IS_PLATFORM(A380))
	{
#ifdef USE_TASKLET
		tasklet_init(&wlpptr->wlpd_p->intrtask, (void *)wlIntrPoll,
					 (unsigned long)netdev);
#else
		INIT_WORK(&wlpptr->wlpd_p->intrtask,
				  (void (*)(void *))wlIntrPoll);
#endif
	}

	tasklet_init(&wlpptr->wlpd_p->rx_refill_task, (void *)wlRxBufFill,
				 (unsigned long)netdev);
#ifdef USE_TASKLET
	tasklet_init(&wlpptr->wlpd_p->txtask, (void *)wlDataTxHdl,
				 (unsigned long)netdev);
	// tasklet_init(&wlpptr->wlpd_p->MUtask, (void*)MUAutoSet_Hdlr, (unsigned long)netdev);
	tasklet_init(&wlpptr->wlpd_p->buf_rel_task, (void *)wlTxDone,
				 (unsigned long)netdev);
#else
	INIT_WORK(&wlpptr->wlpd_p->txtask, (void (*)(void *))_wlDataTxHdl);
#endif

#ifdef MRVL_DFS
	INIT_WORK(&wlpptr->wlpd_p->dfstask, (void *)(void *)_wlRadarDetection);
	INIT_WORK(&wlpptr->wlpd_p->csatask, (void *)(void *)_wlApplyCSAChannel);
#ifdef CONCURRENT_DFS_SUPPORT
	INIT_WORK(&wlpptr->wlpd_p->dfstaskAux,
			  (void *)(void *)_wlAuxChRadarDetection);
#endif /* CONCURRENT_DFS_SUPPORT */
#endif
	INIT_WORK(&wlpptr->wlpd_p->resettask, (void *)(void *)_wlreset);
	INIT_WORK(&wlpptr->wlpd_p->kickstatask,
			  (void *)(void *)_wlConsecTxFail);
#ifdef SOC_W906X
	INIT_WORK(&wlpptr->wlpd_p->offchantask, (void *)(void *)_wlOffChanTask);
#else  // 906X off-channel
	INIT_WORK(&wlpptr->wlpd_p->offchandonetask,
			  (void *)(void *)_wlOffChanDone);
#endif // 906X off-channel
#ifdef NEW_DP
	if (!wfa_11ax_pf)
		INIT_WORK(&wlpptr->wlpd_p->acnttask,
				  (void *)(void *)_wlAcntRecordReady);
#endif
#ifdef SYSFS_STADB_INFO
	INIT_WORK(&wlpptr->wlpd_p->sysfstask,
			  (void *)(void *)_wlSysfsSTAHdlTask);
#endif /* SYSFS_STADB_INFO */

#ifdef WTP_SUPPORT
	wlpptr->nl_socket = netlink_kernel_create(&init_net, netlink_num, &cfg);
#endif
	SPIN_LOCK_INIT(&wlpptr->wlpd_p->locks.xmitLock);
	SPIN_LOCK_INIT(&wlpptr->wlpd_p->locks.fwLock);
#ifdef SOC_W906X
	SPIN_LOCK_INIT(&wlpptr->wlpd_p->locks.offChanListLock);
#endif
	SPIN_LOCK_INIT(&wlpptr->wlpd_p->locks.ReqidListLock);
	SPIN_LOCK_INIT(&wlpptr->wlpd_p->locks.intLock);
	SPIN_LOCK_INIT(&wlpptr->wlpd_p->locks.HMLock);
#ifdef SYSFS_STADB_INFO
	SPIN_LOCK_INIT(&wlpptr->wlpd_p->locks.sysfsHdlListLock);
#endif /* SYSFS_STADB_INFO */
#ifdef BAND_STEERING
	SPIN_LOCK_INIT(&wlpptr->wlpd_p->locks.bandSteerListLock);
#endif /* BAND_STEERING */
#ifdef WIFI_DATA_OFFLOAD
	SPIN_LOCK_INIT(&wlpptr->wlpd_p->locks.delayCmdLock);
#endif /* WIFI_DATA_OFFLOAD */
#ifdef CB_SUPPORT
	wlpptr->is_resp_mgmt = TRUE;
#endif // CB_SUPPORT
	wlpptr->wlpd_p->MUtimercnt = 0;
	wlpptr->wlpd_p->MUcurVapidx = 0;

	SPIN_LOCK_INIT(&wlpptr->wlpd_p->MUSetListLock);

	for (i = 0; i < sta_num; i++)
	{
		for (j = 0; j < MAX_UP; j++)
		{
			SPIN_LOCK_INIT(&wlpptr->wlpd_p->AmpduPckReorder[i].ba[j].BAreodrLock);
		}
		wlpptr->wlpd_p->txRateHistogram[i] = NULL;
		wlpptr->wlpd_p->scheHistogram[i] = NULL;
	}
	wlpptr->wlpd_p->acnt_tx_record = NULL;
	wlpptr->wlpd_p->acnt_tx_record_idx = 0;
	wlpptr->wlpd_p->acnt_RA_stats = NULL;

#ifdef NEWDP_ACNT_BA
	memset(&wlpptr->wlpd_p->txBAStats[0], 0, (sizeof(WLAN_TX_BA_HIST) * 3));
	for (i = 0; i < 3; i++)
		wlpptr->wlpd_p->txBAStats[i].pBAStats = NULL;
#endif
	wlpptr->pCmdBuf = (unsigned short *)
		wl_dma_alloc_coherent(wlpptr->wlpd_p->dev, CMD_BUF_SIZE,
							  &wlpptr->wlpd_p->pPhysCmdBuf,
							  wlpptr->wlpd_p->dma_alloc_flags);
#ifdef SOC_W906X
	/* set the deivce to non-dma_coherent device only for device on MoChi bus */
	if (IS_BUS_TYPE_MCI(wlpptr))
		wlpptr->wlpd_p->dev->archdata.dma_coherent = false;
	wlpptr->pFwDlBuf = (unsigned short *)
		wl_dma_alloc_coherent(wlpptr->wlpd_p->dev, CMD_BUF_SIZE,
							  &wlpptr->wlpd_p->pPhysFwDlBuf,
							  wlpptr->wlpd_p->dma_alloc_flags);
	if (IS_BUS_TYPE_MCI(wlpptr))
		wlpptr->wlpd_p->dev->archdata.dma_coherent = true;
		/* restore the deivce to dma_coherent device only for device on MoChi bus */
#endif /* SOC_W906X */
#ifdef SSU_SUPPORT
	wlpptr->ssuSize = SSU_BUF_SIZE;
	wlpptr->pSsuBuf = (unsigned short *)
		wl_dma_alloc_coherent(wlpptr->wlpd_p->dev, wlpptr->ssuSize,
							  &wlpptr->wlpd_p->pPhysSsuBuf,
							  wlpptr->wlpd_p->dma_alloc_flags);
	printk("wlInit SSU pSsuBuf = %p  pPhysSsuBuf = %pad size=0x%08x\n",
		   wlpptr->pSsuBuf, &wlpptr->wlpd_p->pPhysSsuBuf, wlpptr->ssuSize);
#endif
#ifdef DSP_COMMAND
	wlpptr->dspSize = DSP_BUF_SIZE;
	wlpptr->pDspBuf = (int *)
		wl_dma_alloc_coherent(wlpptr->wlpd_p->dev, wlpptr->dspSize,
							  &wlpptr->wlpd_p->pPhysDspBuf,
							  wlpptr->wlpd_p->dma_alloc_flags);
	printk("wlInit DSP pDspBuf = %p  pPhysDspBuf = %pad size=0x%08x\n",
		   wlpptr->pDspBuf, &wlpptr->wlpd_p->pPhysDspBuf, wlpptr->dspSize);
#endif
	printk("wlInit wlpptr->pCmdBuf = %p  wlpptr->wlpd_p->pPhysCmdBuf = %x\n", wlpptr->pCmdBuf, (u32)wlpptr->wlpd_p->pPhysCmdBuf);
	if (wlpptr->pCmdBuf == NULL)
	{
		printk(KERN_ERR "%s: can not alloc mem\n", netdev->name);
		goto err_init_cmd_buf;
	}
	memset(wlpptr->pCmdBuf, 0x00, CMD_BUF_SIZE);

#ifdef SOC_W906X
	if (wlpptr->pFwDlBuf == NULL)
	{
		printk(KERN_ERR "%s: can not alloc mem\n", netdev->name);
		goto err_init_fwdl_buf;
	}
	printk("wlInit wlpptr->pFwDlBuf = %p  wlpptr->wlpd_p->pPhysFwDlBuf = %x\n", wlpptr->pFwDlBuf, (u32)wlpptr->wlpd_p->pPhysFwDlBuf);
	memset(wlpptr->pFwDlBuf, 0x00, CMD_BUF_SIZE);
#endif					 /* SOC_W906X */
	ether_setup(netdev); /* init eth data structures */

#ifdef MV_NSS_SUPPORT
	wlNssOps = mv_nss_ops_get();
	if (wlNssOps == 0)
	{
		printk("cannot get NSS options...\n");
		return -ENODEV;
	}
#endif
	/* Allocate Shared Memory FW Host I/O Request MailBox Region */
	AllocSharedMem(wlpptr);
	AllocMrvlPriSharedMem(wlpptr); // mrvl private mailbox region
#ifdef BARBADO_RESET
	wlFwHardreset(netdev, 1);
	wlpptr->wlpd_p->bfwreset = FALSE;
	wlpptr->wlpd_p->bpreresetdone = TRUE;
#endif
	wl_get_cwd(cwd);
#ifdef FS_CAL_FILE_SUPPORT
	wlDownloadMFGFile(netdev);
#endif
	if (wlPrepareFwFile(netdev) == FAIL)
	{
		// printk(KERN_ERR  "%s: prepare firmware downloading failed\n", netdev->name);
		// goto err_init_rx;
		/* No external fw .bin, assume fw downoaded from debuggger */
		printk("%s: No firmware download, pleaes make sure fw has been loaded by debugger!!!!!\n", netdev->name);
	}
	else
	{
#ifndef SC_PALLADIUM
		if (wlFwDownload(netdev))
		{
			printk(KERN_ERR "%s: firmware downloading failed\n",
				   netdev->name);
			wl_kfree(wlpptr->FwPointer);
			goto err_init_qm;
		}
		wl_kfree(wlpptr->FwPointer);
#endif

#ifdef MFG_SUPPORT
		if (wlpptr->mfgEnable)
			mfg_handler_init(netdev);
#endif

		if ((retCode = wlTxRingAlloc(netdev)) != 0)
		{
			printk(KERN_ERR "%s: allocating TX ring failed\n",
				   netdev->name);
			goto err_init_tx1;
		}
		if ((retCode = wlTxRingInit(netdev)) != 0)
		{
			printk(KERN_ERR "%s: initializing TX ring failed\n",
				   netdev->name);
			goto err_init_qm;
		}

		if ((retCode = wlQMInit(netdev)) != 0)
		{
			printk(KERN_ERR "%s: initializing BM Q failed\n",
				   netdev->name);
			goto err_init_qm;
		}
#if defined(TXACNT_REC) && defined(SOC_W906X)
		wlTAcntBufInit(netdev);
#endif // #if defined(TXACNT_REC) && defined (SOC_W906X)
#if defined(RXACNT_REC) && defined(SOC_W906X)
		wlRxAcntPPDUBufInit(netdev);
#endif // #if defined(TXACNT_REC) && defined (SOC_W906X)
#ifdef DSP_COMMAND
#ifdef DSP_INT_MODE
		wlpptr->smacconfig.dspIntMode = 1;
#else
		wlpptr->smacconfig.dspIntMode = 0;
#endif
#endif
		wlpptr->smacconfig.dbm_buf_num_pfw = dbm_buf_num_pfw;

		if (bss_num > NUMOFAPS)
			bss_num = NUMOFAPS;
		if (sta_num > MAX_STNS)
			sta_num = MAX_STNS;

		dev_info(wlpptr->wlpd_p->dev,
				 "Setup device to %d BSSs and %d STAs\n", bss_num,
				 sta_num);
		wlpptr->smacconfig.num_running_bss = bss_num;
		wlpptr->smacconfig.num_running_sta = sta_num;

		memcpy(wlpptr->ioBase0, (void *)&wlpptr->smacconfig,
			   sizeof(SMAC_CONFIG_st));
		// write HAL VERSION for SMAC to checking DRV HAL version
		if (SMAC_HAL_VERSION >= 0x0080)
		{
			printk("=> %s(), MAC_CONFIG_st->magic = %xh\n",
				   __func__, SMAC_HAL_VERSION);
			writel(SMAC_HAL_VERSION, &wlpptr->smacCfgAddr->magic);
			// wlpptr->smacCfgAddr->magic = SMAC_HAL_VERSION;
		}

		printk("=> %s(), MAC_STATUS_st->verCtrl[3] = %xh\n", __func__,
			   0xF0000000);
		writel(0xF0000000, &wlpptr->smacStatusAddr->verCtrl[3]);
		if (wlInitChkSmacRdy(netdev) == FALSE)
		{
			WLDBG_ERROR(DBG_LEVEL_0,
						"Failed to get macRdy at init\n");
			goto err_init_qm;
		}
		else
		{
			WLDBG_INFO(DBG_LEVEL_0, "macRdy is ready now\n");
		}
		post_init_bq_idx(netdev, true);

#ifdef WIFI_DATA_OFFLOAD
		/* enable radio without taking care of DFS first */
		dol_radio_data_ctrl(wlpptr, wlpptr->wlpd_p->ipc_session_id,
							true);
#endif
		/* Is MMDU Support */
		major = wlpptr->smacStatusAddr->verCtrl[0] >> 24;
		minor = (wlpptr->smacStatusAddr->verCtrl[0] & 0x00FF0000) >> 16;
		rel = (wlpptr->smacStatusAddr->verCtrl[0] & 0x0000FF00) >> 8;
		if ((major >= 25) ||
			((major == 24) && ((minor == 4) || (minor == 5)) &&
			 (rel >= 11)))
		{
			/* After SMAC PR24.4.11/PR24.5.11(STA-Only) and PR25, we can check the cap bit to know the MMDU support */
			wlpptr->wlpd_p->mmdu_mgmt_enable =
				wlpptr->wlpd_p->mmdu_data_enable =
					!(wlpptr->smacStatusAddr->smacCap & SMAC_CAP_MMDU_NOT_SUPPORT);
		}
		else
		{
			wlpptr->wlpd_p->mmdu_mgmt_enable =
				wlpptr->wlpd_p->mmdu_data_enable = FALSE;
		}
		dev_info(wlpptr->wlpd_p->dev,
				 "%s MMDU support\n",
				 wlpptr->wlpd_p->mmdu_mgmt_enable ? "Enable" : "Disable");

		// Save the base address of rxSBinfoBaseAddr_v
		wlpptr->rxSBinfoBaseAddr_v = wlpptr->smac_base_vp +
									 (wlpptr->smacStatusAddr->rxSBinfoBaseAddr -
									  wlpptr->smacconfig.smacBmBaseAddr);

		printk("(v,p)=(%p, %x)\n", wlpptr->smac_base_vp,
			   wlpptr->smacconfig.smacBmBaseAddr);
		printk("rxSBinfoBaseAddr_v=%p, %x, %u, %lu\n",
			   wlpptr->rxSBinfoBaseAddr_v,
			   wlpptr->smacStatusAddr->rxSBinfoBaseAddr,
			   wlpptr->smacStatusAddr->rxSBinfoUnitSize,
			   (unsigned long)sizeof(RxSidebandInfo_t));

		do
		{
			UINT32 regionIdx;
			core_dump =
				(coredump_cmd_t *)
					wl_kmalloc(sizeof(coredump_cmd_t), GFP_ATOMIC);
			if (!core_dump)
			{
				printk("Error[%s:%d]: Allocating F/W Core Dump Memory \n", __func__, __LINE__);
				break;
			}

			buff = (char *)wl_kmalloc(MAX_CORE_DUMP_BUFFER,
									  GFP_ATOMIC);
			if (!buff)
			{
				printk("Error[%s:%d]: Allocating F/W Buffer for Core Dump \n", __func__, __LINE__);
				break;
			}
			memset((char *)buff, 0, MAX_CORE_DUMP_BUFFER);

			/*Get Core Dump From F/W */
			core_dump->context = 0;
			core_dump->flags = 0;
			core_dump->sizeB = MAX_CORE_DUMP_BUFFER;
			if (wlFwGetCoreSniff(netdev, core_dump, buff) == FAIL)
			{
				printk("Error[%s:%d]: Failed to get Core Dump \n", __func__, __LINE__);
				break;
			}
			else
			{
				// memcpy(&wlpptr->wlpd_p->coredump.version_major, buff, sizeof(coredump_t));
				memcpy(&wlpptr->wlpd_p->coredump, buff,
					   sizeof(coredump_t));
#if 0
/* FW version foramt is changed, below version need remap, temporary disbaled */
				printk("Major Version : %d\n",
				       wlpptr->wlpd_p->coredump.version_major);
				printk("Minor Version : %d\n",
				       wlpptr->wlpd_p->coredump.version_minor);
				printk("Patch Version : %d\n",
				       wlpptr->wlpd_p->coredump.version_patch);
#endif
				printk("Num of Regions: %d\n",
					   wlpptr->wlpd_p->coredump.num_regions);
				printk("Num of Symbols: %d\n",
					   wlpptr->wlpd_p->coredump.num_symbols);
				for (regionIdx = 0;
					 regionIdx <
					 wlpptr->wlpd_p->coredump.num_regions;
					 regionIdx++)
				{
					printk("region[%2d].address = 0x%10x, region[%2d].length = 0x%10x\n", regionIdx, wlpptr->wlpd_p->coredump.region[regionIdx].address, regionIdx, wlpptr->wlpd_p->coredump.region[regionIdx].length);
				}
			}
		} while (0);

		if (buff)
			wl_kfree(buff);

		if (core_dump)
			wl_kfree(core_dump);
	}
	if (wlFwGetHwSpecs(netdev))
	{
		printk(KERN_ERR "%s: failed to get HW specs\n", netdev->name);
		goto err_init_qm;
	}

	printk("wlpptr->hwData.ulShalVersion:%04x\n",
		   wlpptr->hwData.ulShalVersion);
	if (wlpptr->hwData.ulShalVersion < 0x0080 && SMAC_HAL_VERSION >= 0x0080)
	{
		printk("\nIncompatiable DRV/FW HAL version, DRV:%04x, HAL/FW:%04x\n\n", SMAC_HAL_VERSION, wlpptr->hwData.ulShalVersion);
		BUG();
	}

	wlpptr->wlpd_p->NumOfAPs = bss_num;
	wlpptr->wlpd_p->MonIfIndex = MONIF_INDEX;

	if (!wlpptr->cardindex)
		wl_init_txpend_cnt();

#ifdef SOC_W906X
	for (i = 0; i < MAX_MBSSID_SET; i++)
		wlpptr->wlpd_p->mbssSet[i].primbss = (UINT32)(bss_num);
#endif
	memcpy(netdev->dev_addr, &wlpptr->hwData.macAddr[0], 6);
	printk("Mac address = %s \n", mac_display(&wlpptr->hwData.macAddr[0]));
	printk("Mac_Init \n");

	/*{
	   UINT32 addr_val[64];

	   memset(addr_val, 0, 64 * sizeof(UINT32));
	   //get chip revision 0x80002018[7:0]
	   if( wlFwGetAddrValue(netdev, 0x80002018, 4, addr_val, 0) )
	   goto err_init_qm;

	   wlpptr->hwData.chipRevision = (addr_val[0]&0xff);
	   printk("W9064 revision Z%u (%x)\n", wlpptr->hwData.chipRevision, addr_val[0]);
	   } */

	wlInterruptDisable(netdev);

	memcpy(netdev->dev_addr, &wlpptr->hwData.macAddr[0], 6);

	wlpptr->vmacSta_p =
		Mac_Init(NULL, netdev, &wlpptr->hwData.macAddr[0],
				 WL_OP_MODE_AP, wlinitcnt);
	if (wlpptr->vmacSta_p == NULL)
	{
		printk(KERN_ERR "%s: failed to init driver mac\n",
			   netdev->name);
		goto err_init_qm;
	}
#ifdef FS_CAL_FILE_SUPPORT
	if (wlFreeMFGFileBuffer(netdev))
	{
		WLDBG_WARNING(DBG_LEVEL_3, "%s: MFG file free buffer failed\n",
					  netdev->name);
		goto err_init_qm;
	}
#endif
	if (wlFwSetHwSpecs(netdev))
	{
		WLDBG_ERROR(DBG_LEVEL_2, "failed to set HW specs");
	}
#ifndef TIMER_TASK
	init_timer(&wlpptr->wlpd_p->Timer);
	wlpptr->wlpd_p->Timer.function = timer_routine;
	wlpptr->wlpd_p->Timer.data = (unsigned long)netdev;
	wlpptr->wlpd_p->Timer.expires = jiffies + HZ / 10;
	add_timer(&wlpptr->wlpd_p->Timer);
#endif
	netdev->netdev_ops = &wl_netdev_ops;
	netdev->ethtool_ops = &wl_ethtool_ops;
	netdev->watchdog_timeo = 30 * HZ;
#ifdef WLAN_INCLUDE_TSO
	netdev->features |= NETIF_F_TSO;
	netdev->features |= NETIF_F_IP_CSUM;
	netdev->features |= NETIF_F_SG;
#endif
	netdev->needed_headroom = SKB_INFO_SIZE + SKB_RADIOTAP_CHUNK;
	wlpptr->wlreset = wlreset;
	wlSetupWEHdlr(netdev);
	sprintf(netdev->name, "%s%1d", DRV_NAME, wlinitcnt);

#if defined(SINGLE_DEV_INTERFACE) && !defined(CLIENTONLY)
	wlpptr->vdev[wlpptr->wlpd_p->vmacIndex++] = wlpptr->netDev;
#endif

	/* register cfg80211 virtual interface to wiphy wdev */
#ifdef CFG80211
	mwl_cfg80211_create(wlpptr, wlpptr->wlpd_p->dev);
	wlpptr->wdev.wiphy = wlpptr->wiphy;
	wlpptr->wdev.iftype = NL80211_IFTYPE_AP;
	wlpptr->wdev.netdev = netdev;
	netdev->ieee80211_ptr = &wlpptr->wdev;
	SET_NETDEV_DEV(netdev, wiphy_dev(wlpptr->wdev.wiphy));
#endif

	if (register_netdev(netdev))
	{
		printk(KERN_ERR "%s: failed to register device\n", DRV_NAME);
		goto err_register_netdev;
	}
#ifdef NAPI
	netif_napi_add(netdev, &wlpptr->napi, wlRecvPoll, MAX_NUM_RX_DESC);
#endif

	ap8x_stat_proc_register(netdev);
	ap8xLnxStat_sysfs_init(netdev);
#ifdef AP8X_DUMP
	ap8x_dump_proc_register(netdev);
#endif

#ifdef SINGLE_DEV_INTERFACE
#ifdef WDS_FEATURE
	wlInit_wds(wlpptr);
#endif
#endif
#ifdef CLIENTONLY
	if (wlInit_mbss(wlpptr, &wlpptr->hwData.macAddr[0]))
	{
		printk("*********** Fail to Init Client \n");
	}
#endif
#if defined(MBSS) && !defined(CLIENTONLY)
	memcpy(macaddr, wlpptr->hwData.macAddr, 6);

	for (index = 0; index < wlpptr->wlpd_p->NumOfAPs; index++)
	{

#ifdef SOC_W906X
		// Change local mac address assignment scheme for applying MBSSID usage.
		if (!use_localadmin_addr)
		{
			macaddr[5] =
				wlpptr->hwData.macAddr[5] +
				((index + 1) & 0xff);
		}
		else
		{
			macaddr[0] = (BIT(1) | (wlpptr->hwData.macAddr[5] << 2)); // enable local admin mac
			macaddr[5] =
				wlpptr->hwData.macAddr[5] +
				((index + 1) & 0xff);
		}

		if (wlInit_mbss(wlpptr, &macaddr[0]))
		{
			printk(KERN_ERR "%s: failed to setup mbss No. %d\n",
				   netdev->name, index);
			break;
		}
#else  // SOC_W906X
		if (wlInit_mbss(wlpptr, &macaddr[0]))
		{
			printk(KERN_ERR "%s: failed to setup mbss No. %d\n",
				   netdev->name, index);
			break;
		}

		if (!use_localadmin_addr)
		{
			macaddr[5] =
				wlpptr->hwData.macAddr[5] +
				((index + 1) & 0xff);
		}
		else
		{
			/* uses mac addr bit 41 & up as mbss addresses */
			for (i = 1; i < 32; i++)
			{
				if ((bssidmask & (1 << i)) == 0)
				{
					break;
				}
			}

			if (i)
			{
				/*When the first byte of mac addr is not 0x00, there might be chances that
				   same mac addr assigned to different VAPs */
				/*so make 0x00 */
				/* macaddr[0]=wlpptr->hwData.macAddr[0] |((i<<2)|0x2); */
				macaddr[0] = 0x00 | ((i << 2) | 0x2);
			}
			bssidmask |= 1 << i;
		}
#endif // SOC_W906X
	}
#endif

#ifdef CLIENT_SUPPORT
	{

		/*For client interface, we use different mac addr from master mac addr */
		/*If client interface also takes master mac addr like ap0, then there will be conflict if ap0 is up too */
		/*This procedure to generate client mac addr is also same in macclone api */
		bssidmask = 0;
		memcpy(macaddr, wlpptr->hwData.macAddr, 6);
#if defined(MBSS)
		for (index = 0; index < wlpptr->wlpd_p->NumOfAPs; index++)
		{
#else
		for (index = 0; index < 1; index++)
		{
#endif
			if (!use_localadmin_addr)
			{
				macaddr[5] =
					wlpptr->hwData.macAddr[5] +
					((index + 1) & 0xff);
			}
			else
			{
				/* uses mac addr bit 41 & up as mbss addresses */
				for (i = 1; i < 32; i++)
				{
					if ((bssidmask & (1 << i)) == 0)
						break;
				}

				if (i)
				{
					macaddr[0] =
						wlpptr->hwData.macAddr[0] | ((i << 2) | 0x2);
				}

				bssidmask |= 1 << i;
			}
		}

#ifdef SINGLE_DEV_INTERFACE
		/* Set static for continue debugging purposes */
		UINT8 myAddr[6] = {0x00, 0x40, 0x05, 0x8F, 0x55, 0x17};

		/* Update the static with AP's wireless mac address */
		memcpy(&myAddr[0], &wlpptr->hwData.macAddr[0], 6);

		if (wlInit_client(wlpptr, &myAddr[0], &wlpptr->hwData.macAddr[0]))
#else
		if (!use_localadmin_addr)
			macaddr[0] |= 0x02; /* Usse local administration bit for STA */

		if (wlInit_client(wlpptr, &macaddr[0], &macaddr[0]))
#endif
		{
			printk("*********** Fail to Init Client \n");
		}
	}
#ifdef ENABLE_MONIF
	{
		UINT8 myAddr[6] = {0x00, 0x77, 0x77, 0x77, 0x77, 0x77}; // for easy checking.
		if (wlInit_monif(wlpptr, &myAddr[0]))
		{
			printk("Fail to init monitor interface  ...\n");
		}
	}
#endif
#endif /* CLIENT_SUPPORT */
#ifdef QUEUE_STATS
	wldbgResetQueueStats();
#endif
#ifdef MULTI_AP_SUPPORT
	FourAddr_HashInit();

	INIT_LIST_HEAD(&wlpptr->wlpd_p->unassocSTA.sta_track_list);
	wlpptr->wlpd_p->unassocSTA.sta_track_num = 0;
#endif
#ifdef TP_PROFILE
	init_timer(&wlpptr->wlpd_p->tp_profile_timer);
#endif
#ifdef BAND_STEERING
	INIT_LIST_HEAD(&wlpptr->wlpd_p->bandSteer.sta_track_list);
	wlpptr->wlpd_p->bandSteer.sta_track_num = 0;
	INIT_LIST_HEAD(&wlpptr->wlpd_p->bandSteer.sta_auth_list);
	wlpptr->wlpd_p->bandSteer.sta_auth_num = 0;
	skb_queue_head_init(&wlpptr->wlpd_p->bandSteer.skb_queue);
	TimerInit(&wlpptr->wlpd_p->bandSteer.queued_timer);
	wlpptr->wlpd_p->bandSteer.queued_skb_num = 0;
#endif /* BAND_STEERING */
	memset(CH_radio_status, 0,
		   sizeof(mvl_status_t) * (IEEEtypes_MAX_CHANNELS +
								   IEEEtypes_MAX_CHANNELS_A));
#ifdef WLS_FTM_SUPPORT
	{
		extern int wlsFTM_init(struct net_device *);
		wlsFTM_init(netdev);
	}
#endif
#if (defined WLS_FTM_SUPPORT) || (defined AOA_PROC_SUPPORT)
	{
		extern int hal_csi_init(struct net_device *);
		hal_csi_init(netdev);
	}
#endif
#ifdef PRD_CSI_DMA
	INIT_WORK(&wlpptr->wlpd_p->prd_csi_dma_done_wq,
			  (void *)(void *)wl_WiFi_AoA_Decode);
#endif

#ifdef CCK_DESENSE
	/* init for CCK-desense */
	memset(&wlpptr->cck_des, 0, sizeof(wlpptr->cck_des));

	init_timer(&wlpptr->cck_des.timer);
	wlpptr->cck_des.timer_start = 0;

	wlpptr->cck_des.on_time_ms = CCK_DESENSE_ON_DURATION_MS;
	wlpptr->cck_des.off_time_ms = CCK_DESENSE_OFF_DURATION_MS;
	wlpptr->cck_des.update_cycles = CCK_DESENSE_UPDATE_CYCLE_CNT;
	wlpptr->cck_des.auth_time_ms = CCK_DESENSE_AUTH_DURATION_MS;

	/*CCK desense config */
	wlpptr->cck_des.cck_des_conf.enable = CCK_DESENSE_DYNAMIC_ENABLE;
	wlpptr->cck_des.cck_des_conf.threshold_ceiling =
		CCK_DESENSE_THRESHOLD_CEILING;
	wlpptr->cck_des.cck_des_conf.rssi_margin = CCK_DESENSE_RSSI_MARGIN;

	/* Rx abort config */
	wlpptr->cck_des.rx_abort_conf.enable = RX_ABORT_DYNAMIC_ENABLE;
	wlpptr->cck_des.rx_abort_conf.threshold_ceiling =
		RX_ABORT_THRESHOLD_CEILING;
	wlpptr->cck_des.rx_abort_conf.rssi_margin = RX_ABORT_RSSI_MARGIN;

	/* poll timer */
	init_timer(&wlpptr->cck_des.loadcfg.polltimer);
	wlpptr->cck_des.loadcfg.poll_time_ms = CCK_DESENSE_POLL_DURATION_MS;

	wlpptr->cck_des.loadcfg.enable = CCK_DESENSE_OPT_ENABLE;
	wlpptr->cck_des.loadcfg.thres_tx = CCK_DESENSE_THRES_TX_KBPS;
	wlpptr->cck_des.loadcfg.thres_cca = CCK_DESENSE_THRES_CCA_LEVEL;
#endif /* CCK_DESENSE */
	wlinitcnt++;
	WLDBG_EXIT(DBG_LEVEL_2);
	return SUCCESS;

err_register_netdev:
err_init_tx1:
	wlTxRingFree(netdev);

err_init_qm:
	wlQMCleanUp(netdev);
err_init_fwdl_buf:
err_init_cmd_buf:
#ifdef USE_TASKLET
#ifndef NAPI
	tasklet_kill(&wlpptr->wlpd_p->rxtask);
#endif
	tasklet_kill(&wlpptr->wlpd_p->txtask);
	tasklet_kill(&wlpptr->wlpd_p->MUtask);
	for (i = 0; i < sta_num; i++)
	{
		for (j = 0; j < MAX_UP; j++)
			tasklet_kill(&wlpptr->wlpd_p->AmpduPckReorder[i].ba[j].BArodertask);
	}
#endif
	tasklet_kill(&wlpptr->wlpd_p->rx_refill_task);

	if (IS_PLATFORM(A390) || IS_PLATFORM(A380))
	{
#ifdef USE_TASKLET
		tasklet_kill(&wlpptr->wlpd_p->intrtask);
#endif // USE_TASKLET
	}
	flush_scheduled_work();

	wl_dma_free_coherent(wlpptr->wlpd_p->dev, CMD_BUF_SIZE,
						 wlpptr->pCmdBuf, wlpptr->wlpd_p->pPhysCmdBuf);
failed:
	WLDBG_EXIT_INFO(DBG_LEVEL_2, NULL);
	return FAIL;
}
#else
int wlInit(struct net_device *netdev, u_int16_t devid)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	int retCode, index, i;
	int bssidmask = 0;
	unsigned char macaddr[6] = {0x00, 0xde, 0xad, 0xde, 0xad, 0xee};
#ifdef WTP_SUPPORT
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
	struct netlink_kernel_cfg cfg = {
		.input = txWtpMgmtMsg,
	};
#endif
	int netlink_num = 31;
#endif

	WLDBG_ENTER(DBG_LEVEL_2);

	wlpptr->wlpd_p->masterwlp = wlpptr;
#ifndef SOC_W906X
	wlpptr->wlpd_p->isTxTaskScheduled = 0;
#endif
#ifndef NAPI
#ifdef USE_TASKLET
	tasklet_init(&wlpptr->wlpd_p->rxtask, (void *)wlRecv,
				 (unsigned long)netdev);
#else
	INIT_WORK(&wlpptr->wlpd_p->rxtask, (void (*)(void *))_wlRecv);
#endif
#endif
#if defined(ACNT_REC) && defined(SOC_W906X)
	wlpptr->wlpd_p->rxinfotask.handle_func = wlrxinfo_qproc;
	wlpptr->wlpd_p->rxinfotask.phandle_param = netdev;
	mthread_init(&wlpptr->wlpd_p->rxinfotask);

	wlpptr->wlpd_p->racnttask.handle_func = wlRxPPDUAcntHndl;
	wlpptr->wlpd_p->racnttask.phandle_param = netdev;
	mthread_init(&wlpptr->wlpd_p->racnttask);
// #ifdef USE_TASKLET
//       tasklet_init(&wlpptr->wlpd_p->rxinfotask, (void *)wlrxinfo_qproc, (unsigned long)netdev);
//       tasklet_init(&wlpptr->wlpd_p->racnttask, (void *)wlRxPPDUAcntHndl, (unsigned long)netdev);
// #else
//       INIT_WORK(&wlpptr->wlpd_p->rxinfotask, (void (*)(void *))_wlRxInfo);
//       INIT_WORK(&wlpptr->wlpd_p->racnttask, (void (*)(void *))_wlRAcnt);
// #endif
#endif // #if defined(ACNT_REC) && defined (SOC_W906X)

#ifdef USE_TASKLET
	tasklet_init(&wlpptr->wlpd_p->txtask, (void *)wlDataTxHdl,
				 (unsigned long)netdev);
	tasklet_init(&wlpptr->wlpd_p->MUtask, (void *)MUAutoSet_Hdlr,
				 (unsigned long)netdev);
#else
	INIT_WORK(&wlpptr->wlpd_p->txtask, (void (*)(void *))_wlDataTxHdl);
#endif
#ifdef MRVL_DFS
	INIT_WORK(&wlpptr->wlpd_p->dfstask, (void *)(void *)_wlRadarDetection);
	INIT_WORK(&wlpptr->wlpd_p->csatask, (void *)(void *)_wlApplyCSAChannel);
#endif

	INIT_WORK(&wlpptr->wlpd_p->resettask, (void *)(void *)_wlreset);
	INIT_WORK(&wlpptr->wlpd_p->kickstatask,
			  (void *)(void *)_wlConsecTxFail);
#ifdef SOC_W906X
	INIT_WORK(&wlpptr->wlpd_p->offchantask, (void *)(void *)_wlOffChanTask);
#else  // 906X off-channel
	INIT_WORK(&wlpptr->wlpd_p->offchandonetask,
			  (void *)(void *)_wlOffChanDone);
#endif // 906X off-channel
#ifdef NEW_DP
	INIT_WORK(&wlpptr->wlpd_p->acnttask,
			  (void *)(void *)_wlAcntRecordReady);
#endif

#if defined(MRVL_MUG_ENABLE)
	INIT_WORK(&wlpptr->wlpd_p->mug.irq_task,
			  (void *)(void *)mug_irq_task_handler);
#endif

#if defined(AIRTIME_FAIRNESS)
	INIT_WORK(&wlpptr->wlpd_p->atf_irq_task,
			  (void *)(void *)atf_irq_task_handler);
#endif /* AIRTIME_FAIRNESS */

#ifdef WTP_SUPPORT
	wlpptr->nl_socket = netlink_kernel_create(&init_net, netlink_num, &cfg);
#endif
	SPIN_LOCK_INIT(&wlpptr->wlpd_p->locks.xmitLock);
	SPIN_LOCK_INIT(&wlpptr->wlpd_p->locks.fwLock);
#ifdef SOC_W906X
	SPIN_LOCK_INIT(&wlpptr->wlpd_p->locks.offChanListLock);
#endif
	SPIN_LOCK_INIT(&wlpptr->wlpd_p->locks.ReqidListLock);

	wlpptr->wlpd_p->MUtimercnt = 0;
	wlpptr->wlpd_p->MUcurVapidx = 0;

	SPIN_LOCK_INIT(&wlpptr->wlpd_p->MUSetListLock);

	for (i = 0; i < sta_num; i++)
	{
		wlpptr->wlpd_p->txRateHistogram[i] = NULL;
		SPIN_LOCK_INIT(&wlpptr->wlpd_p->txRateHistoLock[i]);
	}
#ifdef NEWDP_ACNT_BA
	memset(&wlpptr->wlpd_p->txBAStats[0], 0, (sizeof(WLAN_TX_BA_HIST) * 3));
	for (i = 0; i < 3; i++)
		wlpptr->wlpd_p->txBAStats[i].pBAStats = NULL;
#endif

	wlpptr->pCmdBuf = (unsigned short *)
		pci_alloc_consistent(wlpptr->pPciDev, CMD_BUF_SIZE,
							 &wlpptr->wlpd_p->pPhysCmdBuf);
#ifdef SSU_SUPPORT
	wlpptr->ssuSize = SSU_BUF_SIZE;
	wlpptr->pSsuBuf = (unsigned short *)
		pci_alloc_consistent(wlpptr->pPciDev, wlpptr->ssuSize,
							 &wlpptr->wlpd_p->pPhysSsuBuf);
	printk("wlInit SSU pSsuBuf = %p  pPhysSsuBuf = %pad size=0x%08x\n",
		   wlpptr->pSsuBuf, &wlpptr->wlpd_p->pPhysSsuBuf, wlpptr->ssuSize);
#endif
	printk("wlInit wlpptr->pCmdBuf = %p  wlpptr->wlpd_p->pPhysCmdBuf = %p \n", wlpptr->pCmdBuf, (void *)wlpptr->wlpd_p->pPhysCmdBuf);
	if (wlpptr->pCmdBuf == NULL)
	{
		printk(KERN_ERR "%s: can not alloc mem\n", netdev->name);
		goto err_init_cmd_buf;
	}
	memset(wlpptr->pCmdBuf, 0x00, CMD_BUF_SIZE);

	ether_setup(netdev); /* init eth data structures */

#ifdef MV_NSS_SUPPORT
	wlNssOps = mv_nss_ops_get();
	if (wlNssOps == 0)
	{
		printk("cannot get NSS options...\n");
		return -ENODEV;
	}
#endif

	if ((retCode = wlTxRingAlloc(netdev)) == 0)
	{
		if ((retCode = wlTxRingInit(netdev)) != 0)
		{
			printk(KERN_ERR "%s: initializing TX ring failed\n",
				   netdev->name);
			goto err_init_tx2;
		}
	}
	else
	{
		printk(KERN_ERR "%s: allocating TX ring failed\n",
			   netdev->name);
		goto err_init_tx1;
	}

	if ((retCode = wlRxRingAlloc(netdev)) == 0)
	{
		if ((retCode = wlRxRingInit(netdev)) != 0)
		{
			printk(KERN_ERR "%s: initializing RX ring failed\n",
				   netdev->name);
			goto err_init_rx;
		}
	}
	else
	{
		printk(KERN_ERR "%s: allocating RX ring failed\n",
			   netdev->name);
		goto err_init_rx;
	}

	/* Allocate Shared Memory FW Host I/O Request MailBox Region */
	AllocSharedMem(wlpptr);
	AllocMrvlPriSharedMem(wlpptr); // mrvl private mailbox region
#ifdef BARBADO_RESET
	wlFwHardreset(netdev, 1);
	wlpptr->wlpd_p->bfwreset = FALSE;
	wlpptr->wlpd_p->bpreresetdone = TRUE;
#endif
	wl_get_cwd(cwd);
	if (wlPrepareFwFile(netdev))
	{
		// printk(KERN_ERR  "%s: prepare firmware downloading failed\n", netdev->name);
		// goto err_init_rx;
		/* No external fw .bin, assume fw downoaded from debuggger */
		printk("%s: No firmware download, pleaes make sure fw has been loaded by debugger!!!!!\n", netdev->name);
	}
	else
	{
#ifndef SC_PALLADIUM
		if (wlFwDownload(netdev))
		{
			printk(KERN_ERR "%s: firmware downloading failed\n",
				   netdev->name);
			wl_kfree(wlpptr->FwPointer);
			goto err_init_rx;
		}
		wl_kfree(wlpptr->FwPointer);
#endif
	}
	if (wlFwGetHwSpecs(netdev))
	{
		printk(KERN_ERR "%s: failed to get HW specs\n", netdev->name);
		goto err_init_rx;
	}
	memcpy(netdev->dev_addr, &wlpptr->hwData.macAddr[0], 6);
	printk("Mac address = %s \n", mac_display(&wlpptr->hwData.macAddr[0]));
	printk("Mac_Init \n");
	wlpptr->vmacSta_p =
		Mac_Init(NULL, netdev, &wlpptr->hwData.macAddr[0],
				 WL_OP_MODE_AP, wlinitcnt);
	if (wlpptr->vmacSta_p == NULL)
	{
		printk(KERN_ERR "%s: failed to init driver mac\n",
			   netdev->name);
		goto err_init_rx;
	}
#ifndef NEW_DP
	writel((wlpptr->wlpd_p->descData[0].pPhysTxRing),
		   wlpptr->ioBase0 + wlpptr->wlpd_p->descData[0].wcbBase);
#if NUM_OF_DESCRIPTOR_DATA > 3
	int i;
	for (i = 1; i < TOTAL_TX_QUEUES; i++)
		writel((wlpptr->wlpd_p->descData[i].pPhysTxRing),
			   wlpptr->ioBase0 + wlpptr->wlpd_p->descData[i].wcbBase);
#endif
	writel((wlpptr->wlpd_p->descData[0].pPhysRxRing),
		   wlpptr->ioBase0 + wlpptr->wlpd_p->descData[0].rxDescRead);
	writel((wlpptr->wlpd_p->descData[0].pPhysRxRing),
		   wlpptr->ioBase0 + wlpptr->wlpd_p->descData[0].rxDescWrite);
#endif
	if (wlFwSetHwSpecs(netdev))
	{
		WLDBG_ERROR(DBG_LEVEL_2, "failed to set HW specs");
	}

	netdev->netdev_ops = &wl_netdev_ops;
	netdev->ethtool_ops = &wl_ethtool_ops;
	netdev->watchdog_timeo = 30 * HZ;
#ifdef WLAN_INCLUDE_TSO
	netdev->features |= NETIF_F_TSO;
	netdev->features |= NETIF_F_IP_CSUM;
	netdev->features |= NETIF_F_SG;
#endif
	netdev->needed_headroom = SKB_INFO_SIZE + SKB_RADIOTAP_CHUNK;
	wlpptr->wlreset = wlreset;
	wlSetupWEHdlr(netdev);
	sprintf(netdev->name, "%s%1d", DRV_NAME, wlinitcnt);

#if defined(SINGLE_DEV_INTERFACE) && !defined(CLIENTONLY)
	wlpptr->vdev[wlpptr->wlpd_p->vmacIndex++] = wlpptr->netDev;
#endif

	/* register cfg80211 virtual interface to wiphy wdev */
#ifdef CFG80211
	mwl_cfg80211_create(wlpptr);
	wlpptr->wdev.wiphy = wlpptr->wiphy;
	wlpptr->wdev.iftype = NL80211_IFTYPE_AP;
	wlpptr->wdev.netdev = netdev;
	netdev->ieee80211_ptr = &wlpptr->wdev;
	SET_NETDEV_DEV(netdev, wiphy_dev(wlpptr->wdev.wiphy));
#endif

	if (register_netdev(netdev))
	{
		printk(KERN_ERR "%s: failed to register device\n", DRV_NAME);
		goto err_register_netdev;
	}
#ifdef NAPI
	netif_napi_add(netdev, &wlpptr->napi, wlRecvPoll, MAX_NUM_RX_DESC);
#endif

	ap8x_stat_proc_register(netdev);
#ifdef AP8X_DUMP
	ap8x_dump_proc_register(netdev);
#endif

#ifdef SINGLE_DEV_INTERFACE
#ifdef WDS_FEATURE
	wlInit_wds(wlpptr);
#endif
#endif
#ifdef CLIENTONLY
	if (wlInit_mbss(wlpptr, &wlpptr->hwData.macAddr[0]))
	{
		printk("*********** Fail to Init Client \n");
	}
#endif
#if defined(MBSS) && !defined(CLIENTONLY)
	memcpy(macaddr, wlpptr->hwData.macAddr, 6);
	for (index = 0; index < bss_num; index++)
	{
		if (wlInit_mbss(wlpptr, &macaddr[0]))
		{
			printk(KERN_ERR "%s: failed to setup mbss No. %d\n",
				   netdev->name, index);
			break;
		}
#if 1
		macaddr[5] = wlpptr->hwData.macAddr[5] + ((index + 1) & 0xf);
#else
		int i;
		// uses mac addr bit 41 & up as mbss addresses
		for (i = 1; i < 32; i++)
		{

			if ((bssidmask & (1 << i)) == 0)
			{
				break;
			}
		}

		if (i)
		{

			macaddr[0] =
				wlpptr->hwData.macAddr[0] | ((i << 2) | 0x2);
		}
		bssidmask |= 1 << i;
#endif
	}
#endif

#ifndef TIMER_TASK
	init_timer(&wlpptr->wlpd_p->Timer);
	wlpptr->wlpd_p->Timer.function = timer_routine;
	wlpptr->wlpd_p->Timer.data = (unsigned long)netdev;
	wlpptr->wlpd_p->Timer.expires = jiffies + HZ / 10;
	add_timer(&wlpptr->wlpd_p->Timer);
#endif

#ifdef CLIENT_SUPPORT
	{

		/*For client interface, we use different mac addr from master mac addr */
		/*If client interface also takes master mac addr like ap0, then there will be conflict if ap0 is up too */
		/*This procedure to generate client mac addr is also same in macclone api */
		bssidmask = 0;
		memcpy(macaddr, wlpptr->hwData.macAddr, 6);
#if defined(MBSS)
		for (index = 0; index < bss_num; index++)
#else
		for (index = 0; index < 1; index++)
#endif
		{
#if 1
			macaddr[5] =
				wlpptr->hwData.macAddr[5] + ((index + 1) & 0xf);
#else
			int i;
			// uses mac addr bit 41 & up as mbss addresses
			for (i = 1; i < 32; i++)
			{
				if ((bssidmask & (1 << i)) == 0)
					break;
			}
			if (i)
			{
				macaddr[0] =
					wlpptr->hwData.macAddr[0] | ((i << 2) | 0x2);
			}
			bssidmask |= 1 << i;
#endif
		}

#ifdef SINGLE_DEV_INTERFACE
		/* Set static for continue debugging purposes */
		UINT8 myAddr[6] = {0x00, 0x40, 0x05, 0x8F, 0x55, 0x17};

		/* Update the static with AP's wireless mac address */
		memcpy(&myAddr[0], &wlpptr->hwData.macAddr[0], 6);

		if (wlInit_client(wlpptr, &myAddr[0], &wlpptr->hwData.macAddr[0]))
#else

		macaddr[0] |= 0x02; // Usse local administration bit for STA

		if (wlInit_client(wlpptr, &macaddr[0], &macaddr[0]))
#endif
		{
			printk("*********** Fail to Init Client \n");
		}
	}
#ifdef ENABLE_MONIF
	{
		UINT8 myAddr[6] = {0x00, 0x77, 0x77, 0x77, 0x77, 0x77}; // for easy checking.
		if (wlInit_monif(wlpptr, &myAddr[0]))
		{
			printk("Fail to init monitor interface  ...\n");
		}
	}
#endif
#endif /* CLIENT_SUPPORT */
#ifdef QUEUE_STATS
	wldbgResetQueueStats();
#endif
#ifdef MULTI_AP_SUPPORT
	FourAddr_HashInit();
#endif
	wlinitcnt++;
	WLDBG_EXIT(DBG_LEVEL_2);
	return SUCCESS;

err_register_netdev:
err_init_rx:
	wlRxRingCleanup(netdev);
	wlRxRingFree(netdev);
err_init_tx2:
	wlTxRingCleanup(netdev);
err_init_tx1:
	wlTxRingFree(netdev);
err_init_cmd_buf:
#ifdef USE_TASKLET
#ifndef NAPI
	tasklet_kill(&wlpptr->wlpd_p->rxtask);
#endif
	tasklet_kill(&wlpptr->wlpd_p->txtask);
	tasklet_kill(&wlpptr->wlpd_p->MUtask);
#endif
	flush_scheduled_work();

	pci_free_consistent(wlpptr->pPciDev, CMD_BUF_SIZE,
						wlpptr->pCmdBuf, wlpptr->wlpd_p->pPhysCmdBuf);
	WLDBG_EXIT_INFO(DBG_LEVEL_2, NULL);
	return FAIL;
}
#endif /* SOC_W906X */

void wlFreeQueueTxPkt(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	UINT8 num = NUM_OF_DESCRIPTOR_DATA;
	struct sk_buff *skb;

	while (num--)
	{
		while ((skb = skb_dequeue(&wlpd_p->txQ[num])) != 0)
		{
			wl_free_skb(skb);
		}
	}

	num = NUM_OF_TCP_ACK_Q;
	while (num--)
	{
		while ((skb = skb_dequeue(&wlpd_p->tcp_ackQ[num])) != 0)
		{
			wl_free_skb(skb);
		}
	}
}

#ifdef MBSS
void wlDeinit_mbss(struct net_device *netdev);
#endif
#ifdef CLIENT_SUPPORT
extern void wlDeinit_client(struct net_device *netdev);
#endif /* CLIENT_SUPPORT */

#ifdef SOC_W906X
int wlDeinit(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	UINT32 i, j;
	// May not need to re-enable it => disable it temporally
	// wlFwHardreset(netdev, 0);

	WLDBG_ENTER(DBG_LEVEL_2);

	wlFwSetAcntStop(netdev);
	TimerRemove(&wfa_test_timer);

	if (wlpd_p->downloadSuccessful == TRUE)
	{
		disableSMACRx(netdev);
	}

	/* disable all interupts from hframe */
	writel(0x0, wlpptr->ioBase1 + SC5_REG_PCIE_INTR_MODE_SEL);

	ap8x_stat_proc_unregister(netdev);
	ap8xLnxStat_sysfs_exit(netdev);
#ifdef AP8X_DUMP
	ap8x_dump_proc_unregister(netdev);
#endif

	stop_wlmon(wlpptr);

	del_timer(&wlpptr->wlpd_p->Timer);
	{
		int stream;
		for (stream = 0; stream < MAX_SUPPORT_AMPDU_TX_STREAM_RUNNING;
			 stream++)
			TimerRemove(&wlpptr->wlpd_p->Ampdu_tx[stream].timer);
	}
#ifdef MRVL_DFS
	DfsDeInit(wlpptr->wlpd_p);
#endif

	if (wlpd_p->downloadSuccessful == TRUE)
	{
		SendResetCmd(wlpptr->vmacSta_p, 1);
	}
	if (netdev->flags & IFF_RUNNING)
	{
		if (wlstop(netdev))
		{
			printk(KERN_ERR "%s: failed to stop device\n",
				   DRV_NAME);
		}
	}
	wlInterruptDisable(netdev);
	wlFwReset(netdev);
#ifdef SINGLE_DEV_INTERFACE
#ifdef WDS_FEATURE
	wds_wlDeinit(netdev);
#endif
#endif
#ifdef MBSS
	wlDeinit_mbss(netdev);
#endif
#ifdef CLIENT_SUPPORT
	wlDeinit_client(netdev);
#endif /* CLIENT_SUPPORT */

	flush_scheduled_work();

#ifdef TP_PROFILE
	del_timer(&wlpptr->wlpd_p->tp_profile_timer);
#endif
#ifdef USE_TASKLET
#ifndef NAPI
	tasklet_kill(&wlpptr->wlpd_p->rxtask);
#endif
	tasklet_kill(&wlpptr->wlpd_p->txtask);
	tasklet_kill(&wlpptr->wlpd_p->MUtask);
	tasklet_kill(&wlpptr->wlpd_p->buf_rel_task);
	for (i = 0; i < sta_num; i++)
	{
		for (j = 0; j < MAX_UP; j++)
			tasklet_kill(&wlpptr->wlpd_p->AmpduPckReorder[i].ba[j].BArodertask);

		if (wlpptr->wlpd_p->txRateHistogram[i])
		{
			wl_kfree(wlpptr->wlpd_p->txRateHistogram[i]);
			wlpptr->wlpd_p->txRateHistogram[i] = NULL;
		}
		if (wlpptr->wlpd_p->scheHistogram[i])
		{
			wl_kfree(wlpptr->wlpd_p->scheHistogram[i]);
			wlpptr->wlpd_p->scheHistogram[i] = NULL;
		}
	}
	if (IS_PLATFORM(A390) || IS_PLATFORM(A380))
	{
		tasklet_kill(&wlpptr->wlpd_p->intrtask);
	}
#if defined(ACNT_REC) && defined(SOC_W906X)
	mthread_deinit(&wlpptr->wlpd_p->rxinfotask);
#endif // #if defined(ACNT_REC) && defined (SOC_W906X)
#if defined(RXACNT_REC) && defined(SOC_W906X)
	mthread_deinit(&wlpptr->wlpd_p->racnttask);
#endif // RXACNT_REC
#if defined(TXACNT_REC) && defined(SOC_W906X)
	mthread_deinit(&wlpptr->wlpd_p->tacnttask);
#endif // #if defined(ACNT_REC) && defined (SOC_W906X)
	tasklet_kill(&wlpptr->wlpd_p->rx_refill_task);

#endif // USE_TASKLET

#ifdef WTP_SUPPORT
	netlink_kernel_release(wlpptr->nl_socket);
#endif

	flush_scheduled_work();

	// Free the quequed txpkt
	wlFreeQueueTxPkt(netdev);
	if (wlpptr->vmacSta_p != NULL)
	{
		DisableMacMgmtTimers(wlpptr->vmacSta_p);
		MacMgmtMemCleanup(wlpptr->vmacSta_p);
#ifdef AUTOCHANNEL
		ACS_stop_timer(wlpptr->vmacSta_p);
#endif /* AUTOCHANNEL */
#ifdef COEXIST_20_40_SUPPORT
		Disable_StartCoexisTimer(wlpptr->vmacSta_p);
#endif /* COEXIST_20_40_SUPPORT */
#ifdef IEEE80211K
		Disable_MSAN_timer(netdev);
#endif /* IEEE80211K */
	}
	wlTxRingFree(netdev);
	if (wlpptr->vmacSta_p != NULL)
	{
		wlDestroySysCfg(wlpptr->vmacSta_p);
		wlpptr->vmacSta_p = NULL;
	}
	wlQMCleanUp(netdev);
	wl_free_scheHistogram(netdev);
	wl_unregister_dump_func(wlpptr->wlpd_p);
	unregister_netdev(netdev);
	if (wlinitcnt == 1)
	{ // last one
		ap8x_remove_folder();
		mib_Free();
	}
	wlinitcnt--;
	wl_dma_free_coherent(wlpptr->wlpd_p->dev, CMD_BUF_SIZE,
						 (caddr_t)wlpptr->pCmdBuf,
						 wlpptr->wlpd_p->pPhysCmdBuf);
#ifdef SOC_W906X
	wl_dma_free_coherent(wlpptr->wlpd_p->dev, CMD_BUF_SIZE,
						 (caddr_t)wlpptr->pFwDlBuf,
						 wlpptr->wlpd_p->pPhysFwDlBuf);
#endif /*SOC_W906X */
#ifdef SSU_SUPPORT
	if (wlpptr->pSsuBuf)
		wl_dma_free_coherent(wlpptr->wlpd_p->dev, wlpptr->ssuSize,
							 wlpptr->pSsuBuf,
							 wlpptr->wlpd_p->pPhysSsuBuf);
#endif
#ifdef DSP_COMMAND
	if (wlpptr->pDspBuf)
		wl_dma_free_coherent(wlpptr->wlpd_p->dev, wlpptr->dspSize,
							 wlpptr->pDspBuf,
							 wlpptr->wlpd_p->pPhysDspBuf);
#endif
#ifdef WLS_FTM_SUPPORT
	{
		extern void wlsFTM_Deinit(struct net_device *);
		wlsFTM_Deinit(netdev);
	}
#endif
#if (defined WLS_FTM_SUPPORT) || (defined AOA_PROC_SUPPORT)
	{
		extern void hal_csi_deinit(struct net_device *);
		hal_csi_deinit(netdev);
	}
#endif

#ifdef CCK_DESENSE
	del_timer(&wlpptr->cck_des.timer);
	del_timer(&wlpptr->cck_des.loadcfg.polltimer);
#endif /* CCK_DESENSE */

	if (smeCmdBuf_q)
	{
		wl_vfree(smeCmdBuf_q);
		smeCmdBuf_q = NULL;
	}
	//      free(wlpptr->wlpd_p);
	WLDBG_EXIT(DBG_LEVEL_2);
	return SUCCESS;
}
#else
int wlDeinit(struct net_device *netdev)
{

	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	wlFwHardreset(netdev, 0);

	WLDBG_ENTER(DBG_LEVEL_2);

	ap8x_stat_proc_unregister(netdev);
#ifdef AP8X_DUMP
	ap8x_dump_proc_unregister(netdev);
#endif

	del_timer(&wlpptr->wlpd_p->Timer);
	{
		int stream;
		for (stream = 0; stream < MAX_SUPPORT_AMPDU_TX_STREAM_RUNNING;
			 stream++)
			TimerRemove(&wlpptr->wlpd_p->Ampdu_tx[stream].timer);
	}
#ifdef MRVL_DFS
	DfsDeInit(wlpptr->wlpd_p);
#endif

	SendResetCmd(wlpptr->vmacSta_p, 1);
	if (netdev->flags & IFF_RUNNING)
	{
		if (wlstop(netdev))
		{
			printk(KERN_ERR "%s: failed to stop device\n",
				   DRV_NAME);
		}
	}
#ifdef SINGLE_DEV_INTERFACE
#ifdef WDS_FEATURE
	wds_wlDeinit(netdev);
#endif
#endif
#ifdef MBSS
	wlDeinit_mbss(netdev);
#endif
#ifdef CLIENT_SUPPORT
	wlDeinit_client(netdev);
#endif /* CLIENT_SUPPORT */
#ifdef USE_TASKLET
#ifndef NAPI
	tasklet_kill(&wlpptr->wlpd_p->rxtask);
#endif
	tasklet_kill(&wlpptr->wlpd_p->txtask);
	tasklet_kill(&wlpptr->wlpd_p->MUtask);
#endif
	flush_scheduled_work();

	wlInterruptDisable(netdev);
	wlFwReset(netdev);
	wlRxRingCleanup(netdev);
	wlRxRingFree(netdev);
	wlTxRingCleanup(netdev);
	wlTxRingFree(netdev);
	DisableMacMgmtTimers(wlpptr->vmacSta_p);
	MacMgmtMemCleanup(wlpptr->vmacSta_p);
	wlDestroySysCfg(wlpptr->vmacSta_p);
	wlpptr->vmacSta_p = NULL;
	unregister_netdev(netdev);

	if (wlinitcnt == 1) // last one
		ap8x_remove_folder();
	wlinitcnt--;
	pci_free_consistent(wlpptr->pPciDev, CMD_BUF_SIZE,
						(caddr_t)wlpptr->pCmdBuf,
						wlpptr->wlpd_p->pPhysCmdBuf);
	//      free(wlpptr->wlpd_p);
	WLDBG_EXIT(DBG_LEVEL_2);
	return SUCCESS;
}
#endif /* SOC_W906X */
#if defined(ACNT_REC) && defined(SOC_W906X)
static void
wlRxInfoHdlr(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);

	mthread_run(&wlpptr->wlpd_p->rxinfotask);
	return;
}
#endif // defined(ACNT_REC) && defined (SOC_W906X)
#if defined(RXACNT_REC) && defined(SOC_W906X)
static void
wlRAcntHdlr(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);

	mthread_run(&wlpptr->wlpd_p->racnttask);
	return;
}
#endif // defined(ACNT_REC) && defined (SOC_W906X)

#ifndef NAPI
static void
wlRecvHdlr(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);

#ifdef USE_TASKLET
	tasklet_schedule(&wlpptr->wlpd_p->rxtask);
#else
	schedule_work(&wlpptr->wlpd_p->rxtask);
#endif
	return;
}
#endif

#ifdef MRVL_DFS
int wlRadarDetection(struct net_device *netdev, UINT8 from)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	smeQ_MgmtMsg_t *toSmeMsg = NULL;
	vmacApInfo_t *syscfg = (vmacApInfo_t *)wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = syscfg->Mib802dot11;
	MIB_PHY_DSSS_TABLE *PhyDSSSTable = mib->PhyDSSSTable;

#ifdef CONCURRENT_DFS_SUPPORT
	if (from == DFS_AUX)
	{
		WLSYSLOG(netdev, WLSYSLOG_CLASS_ALL,
				 WLSYSLOG_MSG_GEN_RADARDETECTION_AUX);
		WLSNDEVT(netdev, IWEVCUSTOM,
				 (IEEEtypes_MacAddr_t *)&wlpptr->hwData.macAddr[0],
				 WLSYSLOG_MSG_GEN_RADARDETECTION_AUX);
	}
	else
#endif
	{
		WLSYSLOG(netdev, WLSYSLOG_CLASS_ALL,
				 WLSYSLOG_MSG_GEN_RADARDETECTION);
		WLSNDEVT(netdev, IWEVCUSTOM,
				 (IEEEtypes_MacAddr_t *)&wlpptr->hwData.macAddr[0],
				 WLSYSLOG_MSG_GEN_RADARDETECTION);
	}
	/* Send Radar detection indication to SME layer */
	if ((toSmeMsg =
			 (smeQ_MgmtMsg_t *)wl_kmalloc(sizeof(smeQ_MgmtMsg_t),
										  GFP_ATOMIC)) == NULL)
	{
		WLDBG_INFO(DBG_LEVEL_2,
				   "wlChannelSet: failed to alloc msg buffer\n");
		return 1;
	}

	memset(toSmeMsg, 0, sizeof(smeQ_MgmtMsg_t));

	toSmeMsg->vmacSta_p = wlpptr->vmacSta_p;

	toSmeMsg->MsgType = SME_NOTIFY_RADAR_DETECTION_IND;

#ifdef CONCURRENT_DFS_SUPPORT
	toSmeMsg->Msg.RadarDetectionInd.chInfo.from = from;
	toSmeMsg->Msg.RadarDetectionInd.chInfo.channel = PhyDSSSTable->CurrChan;
	toSmeMsg->Msg.RadarDetectionInd.chInfo.channel2 = PhyDSSSTable->SecChan;
#else
	toSmeMsg->Msg.RadarDetectionInd.chInfo.channel = PhyDSSSTable->CurrChan;
#endif
	memcpy(&toSmeMsg->Msg.RadarDetectionInd.chInfo.chanflag,
		   &PhyDSSSTable->Chanflag, sizeof(CHNL_FLAGS));

	smeQ_MgmtWriteNoBlock(toSmeMsg);
	wl_kfree((UINT8 *)toSmeMsg);

	return 0;
}

void radarDetectionHdlr(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);

	schedule_work(&wlpptr->wlpd_p->dfstask);
	return;
}

#ifdef CONCURRENT_DFS_SUPPORT
void radarAuxChDetectionHdlr(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);

	schedule_work(&wlpptr->wlpd_p->dfstaskAux);
	return;
}
#endif /* CONCURRENT_DFS_SUPPORT */
void SimulateRadarDetect(struct net_device *netdev)
{
	radarDetectionHdlr(netdev);
}

int wlApplyCSAChannel(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *syscfg = (vmacApInfo_t *)wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = syscfg->Mib802dot11;
	MIB_PHY_DSSS_TABLE *PhyDSSSTable = mib->PhyDSSSTable;

	ApplyCSAChannel(netdev, PhyDSSSTable->CurrChan);

	return 0;
}

static void
dfsChanSwitchHdlr(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);

	schedule_work(&wlpptr->wlpd_p->csatask);
	return;
}

#endif // MRVL_DFS

// NOTE: the flag is off default. need to remove for verification later when fw ready.
static void
AcntRdyIsrHdlr(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	schedule_work(&wlpptr->wlpd_p->acnttask);

	return;
}

#if defined(MRVL_MUG_ENABLE)
static void
MugDataRdyIsrHdrl(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);

	schedule_work(&wlpptr->wlpd_p->mug.irq_task);
	return;
}
#endif /* #if defined(MRVL_MUG_ENABLE) */

#if defined(AIRTIME_FAIRNESS_TRACES)
static void
AtfDataRdyIsrHdrl(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);

	schedule_work(&wlpptr->wlpd_p->atf_irq_task);
	return;
}
#endif /* AIRTIME_FAIRNESS */

/*Function to kick out client when consecutive tx failure count > limit*/
int wlConsecTxFail(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *syscfg = (vmacApInfo_t *)wlpptr->vmacSta_p;

	IEEEtypes_MacAddr_t addr = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

	if ((syscfg->OpMode == WL_OP_MODE_VSTA) ||
		(syscfg->OpMode == WL_OP_MODE_STA))
	{
		ClientModeTxMonitor = 0;
	}
	else
	{
		wlFwGetConsecTxFailAddr(netdev, (IEEEtypes_MacAddr_t *)addr);
		extStaDb_RemoveStaNSendDeauthMsg(syscfg,
										 (IEEEtypes_MacAddr_t *)addr);
	}

	return 0;
}

#ifdef SOC_W8964
/*Event handler to kick out client when consecutive tx failure count > limit*/
static void
ConsecTxFailHdlr(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	schedule_work(&wlpptr->wlpd_p->kickstatask);

	return;
}
#endif /* SOC_W8964 */

#ifdef SOC_W906X
int wlOffChanTask(struct net_device *netdev)
{
	wlFwNewDP_handle_OffChan_event(netdev);
	return 0;
}

void offChanDoneHdlr(struct net_device *netdev, offchan_status next_state)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);

	if ((wlpptr->offchan_state == OFFCHAN_STARTED) &&
		(next_state == OFFCHAN_CH_CHANGE))
	{
		wlpptr->offchan_state = OFFCHAN_CH_CHANGE;
		schedule_work(&wlpptr->wlpd_p->offchantask);
	}
	else if ((wlpptr->offchan_state == OFFCHAN_CH_CHANGE) &&
			 (next_state == OFFCHAN_DONE))
	{
		wlpptr->offchan_state = OFFCHAN_DONE;
		schedule_work(&wlpptr->wlpd_p->offchantask);
	}
	else
	{
		printk("offChanDoneHdlr() err, offchan_state = %d, next_state = %d\n", wlpptr->offchan_state, next_state);
	}

	return;
}
#else // 906X off-channel
int wlOffChanDone(struct net_device *netdev)
{

	wlFwNewDP_handle_OffChan_event(netdev);
	return 0;
}

#ifdef SOC_W8964
static void
OffChanDoneHdlr(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	schedule_work(&wlpptr->wlpd_p->offchandonetask);

	return;
}
#endif /* SOC_W8964 */
#endif // 906X off-channel

extern void wlHandleAcnt(struct net_device *netdev);

#ifdef SOC_W906X

extern void wllpRx(struct net_device *netdev);

#if defined(ACNT_REC) && defined(SOC_W906X)
irqreturn_t
wlSC5MSIX_RxInfo(int irq, void *dev_id)
{
	struct msix_context *ctx = (struct msix_context *)dev_id;
	struct net_device *netdev = ctx->netDev;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p;
	unsigned int intStatus;
	int qid;
	UINT32 msg_id = ctx->msg_id;
	irqreturn_t retVal = IRQ_NONE;
	vmacSta_p = wlpptr->vmacSta_p;

	qid = msg_id >> 1;
	intStatus = 1 << qid;
	WLDBG_INFO(DBG_LEVEL_3,
			   "ISR: %s: qid %d %s, msg_id=%d, INTR_SHIFT=%d\n", __func__,
			   qid, (msg_id & 0x01) ? "SQ" : "RQ", msg_id,
			   wlpptr->wlpd_p->intr_shift);

	spin_lock(&wlpptr->wlpd_p->locks.intLock);
	wlpptr->RAcntQId |= intStatus;
	spin_unlock(&wlpptr->wlpd_p->locks.intLock);

	intStatus &= ~SC5_RX_MSIX_MASK;
	if ((msg_id & 0x01) == 1)
	{ // SQ = 1
		// ACNT handler...
		// printk("%s(), calling wlRxInfoHdlr()\n", __func__);
		wlRxInfoHdlr(netdev);
	}
	retVal = IRQ_HANDLED;

	return retVal;
}
#endif // defined(ACNT_REC) && defined (SOC_W906X)

boolean quiet_enable = FALSE;
void quiet_stop_allInf(struct net_device *netdev, boolean quiet)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	int i = 0;

	while (i <= bss_num)
	{
		if (wlpptr->vdev[i])
		{
			if (quiet)
			{
				netif_stop_queue(wlpptr->vdev[i]);
			}
			else
			{
				netif_wake_queue(wlpptr->vdev[i]);
			}
		}
		i++;
	}

	return;
}

UINT32 rx_r7_intr[6] = {0};

irqreturn_t
wlSC5MSIX_r7(int irq, void *dev_id)
{
	struct msix_context *ctx = (struct msix_context *)dev_id;
	struct net_device *netdev = ctx->netDev;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p;
	unsigned int intStatus;
	int qid;
	UINT32 msg_id = ctx->msg_id;
	irqreturn_t retVal = IRQ_NONE;
	unsigned int reg_evt_rdptr = wlpptr->wlpd_p->reg.evt_rdptr;
	unsigned int reg_evt_wrptr = wlpptr->wlpd_p->reg.evt_wrptr;

	vmacSta_p = wlpptr->vmacSta_p;
	qid = msg_id >> 1;
	intStatus = 1 << qid;
	WLDBG_INFO(DBG_LEVEL_3,
			   "ISR: %s: qid %d %s, msg_id=%d, INTR_SHIFT=%d\n", __func__,
			   qid, (msg_id & 0x01) ? "SQ" : "RQ", msg_id,
			   wlpptr->wlpd_p->intr_shift);
	if ((msg_id & 0x01) == 0)
	{ // RQ = 0
#if 1 // Notify host to stop/resume tx
		// printk("intStatus = 0x%x\n", intStatus);
		if (intStatus & SC5_EVENT_QUIET)
		{
			// extern UINT32 quiet_dbg[10];
			// printk("SC5_EVENT_QUIET, quiet_enable = %x -> ", quiet_enable);

			if (quiet_enable == FALSE)
			{
				quiet_enable = TRUE;
			}
			else
			{
				quiet_enable = FALSE;
			}
			quiet_stop_allInf(netdev, quiet_enable);
			// printk("%x, quiet_dbg: %d\n", quiet_enable, quiet_dbg[0]);

			intStatus &= ~SC5_EVENT_QUIET;
			retVal = IRQ_HANDLED;
			rx_r7_intr[4]++;
		}
#endif
		if (intStatus & SC5_EVENT_RADAR_DETECTED)
		{
			char evBuf[64];
			u32 dfs_freq;

			WLSYSLOG(netdev, WLSYSLOG_CLASS_ALL,
					 WLSYSLOG_MSG_GEN_RADARDETECTION);
			dfs_freq =
				((drv_fw_shared_t *)wlpptr->wlpd_p->MrvlPriSharedMem.data)->dfs_freg;
			if (dfs_freq != 0)
			{
				sprintf(evBuf,
						"DFS radar detection Freq = %d\n",
						ENDIAN_SWAP32(dfs_freq));
				WLSNDEVT(netdev, IWEVCUSTOM,
						 (IEEEtypes_MacAddr_t *)&wlpptr->hwData.macAddr[0], evBuf);
			}
			else
			{
				WLSNDEVT(netdev, IWEVCUSTOM,
						 (IEEEtypes_MacAddr_t *)&wlpptr->hwData.macAddr[0],
						 WLSYSLOG_MSG_GEN_RADARDETECTION);
			}
			radarDetectionHdlr(netdev);

			intStatus &= ~SC5_EVENT_RADAR_DETECTED;
			retVal = IRQ_HANDLED;
			rx_r7_intr[0]++;
		}
#ifdef CONCURRENT_DFS_SUPPORT
		if (intStatus & SC5_EVENT_RADAR_DETECTED_AUX)
		{
			// printk("SC5_EVENT_RADAR_DETECTED_AUX ::: intStatus = 0x%x\n", intStatus);
			//  Add handler here
			WLSYSLOG(netdev, WLSYSLOG_CLASS_ALL,
					 WLSYSLOG_MSG_GEN_RADARDETECTION_AUX);
			radarAuxChDetectionHdlr(netdev);
			intStatus &= ~SC5_EVENT_RADAR_DETECTED_AUX;
			retVal = IRQ_HANDLED;
			rx_r7_intr[5]++;
			// printk("SC5_EVENT_RADAR_DETECTED_AUX received %d\n", rx_r7_intr[5]);
		}
#endif /* CONCURRENT_DFS_SUPPORT */
		if (intStatus & SC5_EVENT_CHAN_SWITCHED)
		{

			dfsChanSwitchHdlr(netdev);

			intStatus &= ~SC5_EVENT_CHAN_SWITCHED;
			retVal = IRQ_HANDLED;
			rx_r7_intr[1]++;
		}
		if ((intStatus & SC5_EVENT_FW) && (wlpptr->event_bufq_vaddr))
		{
			UINT32 wrptr, rdptr;
			rdptr = readl(wlpptr->ioBase1 + reg_evt_rdptr);
			wrptr = readl(wlpptr->ioBase1 + reg_evt_wrptr);

			// printk("%s: SC5_EVENT_FW received rdptr=%d wrptr=%d\n", __func__, rdptr, wrptr);
			while (rdptr != wrptr)
			{
				rx_r7_intr[3]++;
				/*
				   Do NOT use phy_to_virt()/virt_to_phy() for memory allocated by wl_dma_alloc_coherent()
				   The address translation is wrong. Just give Eventhandler Virtual addr directly
				 */
				wlEventHandler(vmacSta_p,
							   wlpptr->event_bufq_vaddr +
								   rdptr * EVENT_BUFFQ_SIZE);

				rdptr = (rdptr + 1) % EVENT_BUFFQ_NUM;
				writel(rdptr, wlpptr->ioBase1 + reg_evt_rdptr);
			}
			intStatus &= ~SC5_EVENT_FW;
			retVal = IRQ_HANDLED;
			rx_r7_intr[2]++;
		}
		// NOTE: the flag default is off, need to remove this flag when doing the verification.
		if (intStatus & SC5_EVENT_ACNT_HEAD_READY)
		{

			// printk("%s: W906x_EVENT_ACNT_HEAD_READY received\n", __func__);
			intStatus &= ~SC5_EVENT_ACNT_HEAD_READY;
			if (!wfa_11ax_pf)
				AcntRdyIsrHdlr(netdev);
			retVal = IRQ_HANDLED;
			// rx_r7_intr[1]++;
		}
	}

	return retVal;
}

irqreturn_t
wlSC5MSIX_rx(int irq, void *dev_id)
{
	struct msix_context *ctx = (struct msix_context *)dev_id;
	struct net_device *netdev = ctx->netDev;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	unsigned int intStatus;
	int qid;
	UINT32 msg_id = ctx->msg_id - wlpd_p->intr_shift;
	irqreturn_t retVal = IRQ_NONE;

	qid = msg_id >> 1;
	intStatus = 1 << qid;
	WLDBG_INFO(DBG_LEVEL_3,
			   "ISR: %s: qid %d %s, msg_id=%d, INTR_SHIFT=%d\n", __func__,
			   qid, (msg_id & 0x01) ? "SQ" : "RQ", msg_id,
			   wlpd_p->intr_shift);
	wlpd_p->drv_stats_val.rxq_intr_cnt[qid - SC5_RXQ_START_INDEX]++;

	spin_lock(&wlpptr->wlpd_p->locks.intLock);
	wlpptr->RxQId |= intStatus;
	spin_unlock(&wlpptr->wlpd_p->locks.intLock);

	intStatus &= ~SC5_RX_MSIX_MASK;
	wlRecvHdlr(netdev);
	//                      wllpRx(netdev);
	retVal = IRQ_HANDLED;

	return retVal;
}

irqreturn_t
wlSC5MSIX_rel(int irq, void *dev_id)
{
	struct msix_context *ctx = (struct msix_context *)dev_id;
	struct net_device *netdev = ctx->netDev;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	struct bqm_args *pbqm_args = &wlpd_p->bmq_args;
	unsigned int intStatus;
	int qid;
	UINT32 msg_id = ctx->msg_id - wlpd_p->intr_shift;
	irqreturn_t retVal = IRQ_NONE;

	qid = msg_id >> 1;
	intStatus = 1 << qid;
	WLDBG_INFO(DBG_LEVEL_3,
			   "ISR: %s: qid %d %s, msg_id=%d, INTR_SHIFT=%d\n", __func__,
			   qid, (msg_id & 0x01) ? "SQ" : "RQ", msg_id,
			   wlpd_p->intr_shift);
	if (intStatus & pbqm_args->buf_release_msix_mask)
	{
		spin_lock(&wlpptr->wlpd_p->locks.intLock);
		wlpptr->BQRelId |= intStatus;
		spin_unlock(&wlpptr->wlpd_p->locks.intLock);
		intStatus &= ~pbqm_args->buf_release_msix_mask;
		tasklet_hi_schedule(&wlpptr->wlpd_p->buf_rel_task);
		retVal = IRQ_HANDLED;
	}

	return retVal;
}

irqreturn_t
wlSC5MSIX_tx(int irq, void *dev_id)
{
	struct msix_context *ctx = (struct msix_context *)dev_id;
	struct net_device *netdev = ctx->netDev;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	struct bqm_args *pbqm_args = &wlpd_p->bmq_args;

	unsigned int currIteration = 0;
	unsigned int intStatus;
	int qid;
	UINT32 msg_id = ctx->msg_id - wlpd_p->intr_shift;
	irqreturn_t retVal = IRQ_NONE;

	qid = msg_id >> 1;
	intStatus = 1 << qid;
	WLDBG_INFO(DBG_LEVEL_3,
			   "ISR: %s: qid %d %s, msg_id=%d, INTR_SHIFT=%d\n", __func__,
			   qid, (msg_id & 0x01) ? "SQ" : "RQ", msg_id,
			   wlpd_p->intr_shift);
	if ((msg_id & 0x01) == 0)
	{ // RQ = 0
		if (intStatus & pbqm_args->tx_msix_mask)
		{
			WLDBG_INFO(DBG_LEVEL_3, "ISR: TXQ: qid %d \n", qid);
			intStatus &= ~pbqm_args->tx_msix_mask;
			retVal = IRQ_HANDLED;
		}
		if (intStatus & SC5_BUF_MSIX_MASK)
		{
			WLDBG_INFO(DBG_LEVEL_3, "ISR: BMQ qid %d \n", qid);
			tasklet_hi_schedule(&wlpptr->wlpd_p->rx_refill_task);
			intStatus &= ~SC5_BUF_MSIX_MASK;
			retVal = IRQ_HANDLED;
		}
	}

	currIteration++;

	return retVal;
}

// #endif

irqreturn_t
wlISR(int irq, void *dev_id)
{
	struct net_device *netdev = (struct net_device *)dev_id;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	unsigned int reg_evt_rdptr = wlpptr->wlpd_p->reg.evt_rdptr;
	unsigned int reg_evt_wrptr = wlpptr->wlpd_p->reg.evt_wrptr;
	unsigned int intStatus;
	unsigned int currIteration = 0;
	UINT32 qid = 0;

	irqreturn_t retVal = IRQ_NONE;

	do
	{
		intStatus =
			(readl(wlpptr->ioBase1 + SC5_MACREG_REG_INTERRUPT_CAUSE));
		if (intStatus != 0x00000000)
		{
			if (intStatus == 0xffffffff)
			{
				WLDBG_INFO(DBG_LEVEL_2, "card plugged out???");
				retVal = IRQ_HANDLED;
				break; /* card plugged out -> do not handle any IRQ */
			}

			if (!wlpptr->wlpd_p->pPciDev->msi_enabled)
			{
				writel((MACREG_A2HRIC_BIT_MASK_MSI &
						~intStatus),
					   wlpptr->ioBase1 +
						   SC5_MACREG_REG_INTERRUPT_CAUSE);
			}
		}

		if (intStatus & SC5_RX_INTR_MASK)
		{
			spin_lock(&wlpptr->wlpd_p->locks.intLock);
			wlpptr->RxQId |=
				(intStatus & SC5_RX_INTR_MASK) >>
				SC5_RX_INTR_START;
			;
			spin_unlock(&wlpptr->wlpd_p->locks.intLock);
			intStatus &= ~SC5_RX_INTR_MASK;
			wlRecvHdlr(netdev);
			retVal = IRQ_HANDLED;
		}

		if (intStatus & SC5_BUF_RELEASE_MASK)
		{
			if (intStatus & BIT(30))
				qid = 13;
			else if (intStatus & BIT(29))
				qid = 12;
			else if (intStatus & BIT(28))
				qid = 11;
			else if (intStatus & BIT(27))
				qid = 10;
			else if (intStatus & BIT(22)) /* SC5 */
				qid = 14;

			spin_lock(&wlpptr->wlpd_p->locks.intLock);
			wlpptr->BQRelId |= BIT(qid);
			spin_unlock(&wlpptr->wlpd_p->locks.intLock);
			tasklet_hi_schedule(&wlpptr->wlpd_p->buf_rel_task);
			intStatus &= ~SC5_BUF_RELEASE_MASK;
			retVal = IRQ_HANDLED;
		}
		if (intStatus & SC5_TX_INTR_MASK)
		{
			intStatus &= ~SC5_TX_INTR_MASK;
			retVal = IRQ_HANDLED;
		}
		if (intStatus & SC5_BUF_INTR_MASK)
		{
			tasklet_hi_schedule(&wlpptr->wlpd_p->rx_refill_task);
			intStatus &= ~SC5_BUF_INTR_MASK;
			retVal = IRQ_HANDLED;
		}
#if defined(ACNT_REC) && defined(SOC_W906X)
		if (intStatus & SC5_RXINFO_INTR_MASK)
		{
			if (intStatus & BIT(31))
				qid = 15;

			spin_lock(&wlpptr->wlpd_p->locks.intLock);
			wlpptr->RAcntQId |= BIT(qid);
			spin_unlock(&wlpptr->wlpd_p->locks.intLock);
			// ACNT handler...
			wlRxInfoHdlr(netdev);
			intStatus &= ~SC5_RXINFO_INTR_MASK;
			retVal = IRQ_HANDLED;
		}
#endif
		// R7 handler
#if 1 // Notify host to stop/resume tx
		// printk("intStatus = 0x%x\n", intStatus);
		if (intStatus & SC5_EVENT_QUIET)
		{
			// extern UINT32 quiet_dbg[10];
			// printk("SC5_EVENT_QUIET, quiet_enable = %x -> ", quiet_enable);

			if (quiet_enable == FALSE)
			{
				quiet_enable = TRUE;
			}
			else
			{
				quiet_enable = FALSE;
			}
			quiet_stop_allInf(netdev, quiet_enable);
			// printk("%x, quiet_dbg: %d\n", quiet_enable, quiet_dbg[0]);

			intStatus &= ~SC5_EVENT_QUIET;
			retVal = IRQ_HANDLED;
			rx_r7_intr[4]++;
		}
#endif
		if (intStatus & SC5_EVENT_RADAR_DETECTED)
		{
			char evBuf[64];
			u32 dfs_freq;

			WLSYSLOG(netdev, WLSYSLOG_CLASS_ALL,
					 WLSYSLOG_MSG_GEN_RADARDETECTION);
			dfs_freq =
				((drv_fw_shared_t *)wlpptr->wlpd_p->MrvlPriSharedMem.data)->dfs_freg;
			if (dfs_freq != 0)
			{
				sprintf(evBuf,
						"DFS radar detection Freq = %d\n",
						ENDIAN_SWAP32(dfs_freq));
				WLSNDEVT(netdev, IWEVCUSTOM,
						 (IEEEtypes_MacAddr_t *)&wlpptr->hwData.macAddr[0], evBuf);
			}
			else
			{
				WLSNDEVT(netdev, IWEVCUSTOM,
						 (IEEEtypes_MacAddr_t *)&wlpptr->hwData.macAddr[0],
						 WLSYSLOG_MSG_GEN_RADARDETECTION);
			}
			radarDetectionHdlr(netdev);

			intStatus &= ~SC5_EVENT_RADAR_DETECTED;
			retVal = IRQ_HANDLED;
			rx_r7_intr[0]++;
		}
#ifdef CONCURRENT_DFS_SUPPORT
		if (intStatus & SC5_EVENT_RADAR_DETECTED_AUX)
		{
			WLSYSLOG(netdev, WLSYSLOG_CLASS_ALL,
					 WLSYSLOG_MSG_GEN_RADARDETECTION_AUX);
			// printk("SC5_EVENT_RADAR_DETECTED_AUX ::: intStatus = 0x%x\n", intStatus);
			//  Add handler here
			radarAuxChDetectionHdlr(netdev);
			intStatus &= ~SC5_EVENT_RADAR_DETECTED_AUX;
			retVal = IRQ_HANDLED;
			rx_r7_intr[5]++;
			// printk("SC5_EVENT_RADAR_DETECTED_AUX received %d\n", rx_r7_intr[5]);
		}
#endif /* CONCURRENT_DFS_SUPPORT */
		if (intStatus & SC5_EVENT_CHAN_SWITCHED)
		{

			dfsChanSwitchHdlr(netdev);

			intStatus &= ~SC5_EVENT_CHAN_SWITCHED;
			retVal = IRQ_HANDLED;
			rx_r7_intr[1]++;
		}
		if ((intStatus & SC5_EVENT_FW) && (wlpptr->event_bufq_vaddr))
		{
			UINT32 wrptr, rdptr;
			rdptr = readl(wlpptr->ioBase1 + reg_evt_rdptr);
			wrptr = readl(wlpptr->ioBase1 + reg_evt_wrptr);

			// printk("%s: SC5_EVENT_FW received rdptr=%d wrptr=%d\n", __func__, rdptr, wrptr);
			while (rdptr != wrptr)
			{
				rx_r7_intr[3]++;
				/*
				   Do NOT use phy_to_virt()/virt_to_phy() for memory allocated by wl_dma_alloc_coherent()
				   The address translation is wrong. Just give Eventhandler Virtual addr directly
				 */
				wlEventHandler(vmacSta_p,
							   wlpptr->event_bufq_vaddr +
								   rdptr * EVENT_BUFFQ_SIZE);

				rdptr = (rdptr + 1) % EVENT_BUFFQ_NUM;
				writel(rdptr, wlpptr->ioBase1 + reg_evt_rdptr);
			}
			intStatus &= ~SC5_EVENT_FW;
			retVal = IRQ_HANDLED;
			rx_r7_intr[2]++;
		}
		// NOTE: the flag default is off, need to remove this flag when doing the verification.
		if (intStatus & SC5_EVENT_ACNT_HEAD_READY)
		{
			// printk("%s: W906x_EVENT_ACNT_HEAD_READY received\n", __func__);
			intStatus &= ~SC5_EVENT_ACNT_HEAD_READY;
			if (!wfa_11ax_pf)
				AcntRdyIsrHdlr(netdev);
			retVal = IRQ_HANDLED;
			// rx_r7_intr[1]++;
		}

		currIteration++;
	} while (currIteration < MAX_ISR_ITERATION);
	return retVal;
}

#else /* SOC_W906X */

irqreturn_t
wlISR(int irq, void *dev_id)
{
	struct net_device *netdev = (struct net_device *)dev_id;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	unsigned int currIteration = 0;
	unsigned int intStatus;
	irqreturn_t retVal = IRQ_NONE;

#ifdef NAPI
	unsigned int mask;
#endif
	do
	{
		intStatus =
			(readl(wlpptr->ioBase1 + MACREG_REG_A2H_INTERRUPT_CAUSE));
#ifdef NAPI
		mask = (readl(wlpptr->ioBase1 + MACREG_REG_A2H_INTERRUPT_MASK));
#endif
		if (intStatus != 0x00000000)
		{
			if (intStatus == 0xffffffff)
			{
				WLDBG_INFO(DBG_LEVEL_2, "card plugged out???");
				retVal = IRQ_HANDLED;
				break; /* card plugged out -> do not handle any IRQ */
			}
#ifdef NAPI
			intStatus &= mask;
#endif
			writel((MACREG_A2HRIC_BIT_MASK & ~intStatus),
				   wlpptr->ioBase1 +
					   MACREG_REG_A2H_INTERRUPT_CAUSE);
		}
		if ((intStatus & ISR_SRC_BITS) ||
			(currIteration < MAX_ISR_ITERATION))
		{
			/* Eliminate txdone interrupt handling within ISR to reduce cpu util.
			 * MACREG_A2HRIC_BIT_MASK change, wlTxDone is now executed within transmit path
			 if (intStatus & MACREG_A2HRIC_BIT_TX_DONE)
			 {
			 intStatus &= ~MACREG_A2HRIC_BIT_TX_DONE;
			 wlTxDone(netdev);
			 retVal = IRQ_HANDLED;
			 }*/

#ifndef NEW_DP
			if (intStatus & MACREG_A2HRIC_BIT_RX_RDY)
			{
				intStatus &= ~MACREG_A2HRIC_BIT_RX_RDY;
#ifdef NAPI
				if (netdev->flags & IFF_RUNNING)
				{
					wlInterruptMask(netdev,
									MACREG_A2HRIC_BIT_RX_RDY);
					napi_schedule(&wlpptr->napi);
				}
#else
				wlRecvHdlr(netdev);
#endif
				retVal = IRQ_HANDLED;
			}
#else /* #ifndef NEW_DP */
			// newdp
			if (intStatus & MACREG_A2HRIC_RX_DONE_HEAD_RDY)
			{
				intStatus &= ~MACREG_A2HRIC_RX_DONE_HEAD_RDY;
#ifdef NAPI
				if (netdev->flags & IFF_RUNNING)
				{
					wlInterruptMask(netdev,
									MACREG_A2HRIC_RX_DONE_HEAD_RDY);
					napi_schedule(&wlpptr->napi);
				}
#else
				wlRecvHdlr(netdev);
#endif
				retVal = IRQ_HANDLED;
			}

			if (intStatus & MACREG_A2HRIC_BIT_OPC_DONE)
			{
				intStatus &= ~MACREG_A2HRIC_BIT_OPC_DONE;
				wlFwCmdComplete(netdev);
				retVal = IRQ_HANDLED;
			}

			if (intStatus & MACREG_A2HRIC_ACNT_HEAD_RDY)
			{
				intStatus &= ~MACREG_A2HRIC_ACNT_HEAD_RDY;
				AcntRdyIsrHdlr(netdev);
				retVal = IRQ_HANDLED;
			}

			if (intStatus & MACREG_A2HRIC_NEWDP_OFFCHAN)
			{

				intStatus &= ~MACREG_A2HRIC_NEWDP_OFFCHAN;
				OffChanDoneHdlr(netdev);

				// wlFwNewDP_wifiarb_post_req_intr(netdev);

				retVal = IRQ_HANDLED;
			}

			if (intStatus & MACREG_A2HRIC_NEWDP_SENSORD)
			{
				intStatus &= ~MACREG_A2HRIC_NEWDP_SENSORD;
				wlFwNewDP_wifiarb_post_req_intr(netdev);
				retVal = IRQ_HANDLED;
			}
#ifdef SSU_SUPPORT
			if (intStatus & MACREG_A2HRIC_BIT_SSU_DONE)
			{
				static UINT32 ssu_counter = 0;
				// extern void ssu_dump_file(UINT32 pPhyAddr, UINT32 *pSsuPci, UINT32 sizeBytes, UINT32 printFlag);

				intStatus &= ~MACREG_A2HRIC_BIT_SSU_DONE;
				// printk("SSU Done counter = %d phyAddr=0x%08x vbase=0x%08x len=%d bytes\n", ssu_counter++,
				//         wlpptr->wlpd_p->pPhysSsuBuf, wlpptr->pSsuBuf, wlpptr->ssuSize);
				// ssu_dump_file(wlpptr->wlpd_p->pPhysSsuBuf, wlpptr->pSsuBuf, wlpptr->ssuSize, 1);
				retVal = IRQ_HANDLED;
			}
#endif
			if (intStatus & MACREG_A2HRIC_NEWDP_DFS)
			{
				char evBuf[64];
				u32 dfs_freq;

				intStatus &= ~MACREG_A2HRIC_NEWDP_DFS;

				WLSYSLOG(netdev, WLSYSLOG_CLASS_ALL,
						 WLSYSLOG_MSG_GEN_RADARDETECTION);
				dfs_freq =
					((drv_fw_shared_t *)wlpptr->wlpd_p->MrvlPriSharedMem.data)->dfs_freg;
				if (dfs_freq != 0)
				{
					sprintf(evBuf,
							"DFS radar detection Freq = %d\n",
							ENDIAN_SWAP32(dfs_freq));
					WLSNDEVT(netdev, IWEVCUSTOM,
							 (IEEEtypes_MacAddr_t *)&wlpptr->hwData.macAddr[0],
							 evBuf);
				}
				else
				{
					WLSNDEVT(netdev, IWEVCUSTOM,
							 (IEEEtypes_MacAddr_t *)&wlpptr->hwData.macAddr[0],
							 WLSYSLOG_MSG_GEN_RADARDETECTION);
				}
				radarDetectionHdlr(netdev);
				retVal = IRQ_HANDLED;
			}
			if (intStatus & MACREG_A2HRIC_NEWDP_CHANNEL_SWITCH)
			{
				intStatus &=
					~MACREG_A2HRIC_NEWDP_CHANNEL_SWITCH;
				dfsChanSwitchHdlr(netdev);
				retVal = IRQ_HANDLED;
			}
#if defined(MRVL_MUG_ENABLE)
			if (intStatus & MACREG_A2HRIC_BIT_MUG_DATA_RDY)
			{
				// printk("MUG DATA RDY ISR\n");
				intStatus &= ~MACREG_A2HRIC_BIT_MUG_DATA_RDY;
				MugDataRdyIsrHdrl(netdev);
				retVal = IRQ_HANDLED;
			}
#endif /* #if defined(MRVL_MUG_ENABLE) */

#if defined(AIRTIME_FAIRNESS)
			if (intStatus & MACREG_A2HRIC_BIT_ATF_DATA_RDY)
			{
				// printk("ATF DATA RDY ISR\n");
				intStatus &= ~MACREG_A2HRIC_BIT_ATF_DATA_RDY;
				AtfDataRdyIsrHdrl(netdev);
				retVal = IRQ_HANDLED;
			}
#endif /* AIRTIME_FAIRNESS */

			// no other intr for newDP testing
			break;
#endif /*  #ifndef NEW_DP */
			if (intStatus & MACREG_A2HRIC_BIT_OPC_DONE)
			{
				intStatus &= ~MACREG_A2HRIC_BIT_OPC_DONE;
				wlFwCmdComplete(netdev);
				retVal = IRQ_HANDLED;
			}
			if (intStatus & MACREG_A2HRIC_BIT_MAC_EVENT)
			{
				intStatus &= ~MACREG_A2HRIC_BIT_MAC_EVENT;
				retVal = IRQ_HANDLED;
			}
			if (intStatus & MACREG_A2HRIC_BIT_ICV_ERROR)
			{
				WLDBG_INFO(DBG_LEVEL_2,
						   "MACREG_A2HRIC_BIT_ICV_ERROR *************. \n");
				MrvlICVErrorHdl(vmacSta_p);
				intStatus &= ~MACREG_A2HRIC_BIT_ICV_ERROR;
				retVal = IRQ_HANDLED;
			}
			if (intStatus & MACREG_A2HRIC_BIT_WEAKIV_ERROR)
			{
				MIB_802DOT11 *mib =
					wlpptr->vmacSta_p->ShadowMib802dot11;
				intStatus &= ~MACREG_A2HRIC_BIT_WEAKIV_ERROR;

				wlpptr->wlpd_p->privStats.weakiv_count++;
				wlpptr->wlpd_p->privStats.weakiv_threshold_count++;

				if ((wlpptr->wlpd_p->privStats.weakiv_threshold_count) >=
					*(mib->mib_weakiv_threshold))
				{
					wlpptr->wlpd_p->privStats.weakiv_threshold_count = 0;
					WLSYSLOG(netdev, WLSYSLOG_CLASS_ALL,
							 WLSYSLOG_MSG_WEP_WEAKIV_ERROR);
					WLSNDEVT(netdev, IWEVCUSTOM,
							 (IEEEtypes_MacAddr_t *)&wlpptr->hwData.macAddr[0],
							 WLSYSLOG_MSG_WEP_WEAKIV_ERROR);
				}
				retVal = IRQ_HANDLED;
			}
			if (intStatus & MACREG_A2HRIC_BIT_QUEUE_EMPTY)
			{
				intStatus &= ~MACREG_A2HRIC_BIT_QUEUE_EMPTY;
				if (extStaDb_AggrFrameCk(vmacSta_p, 1))
				{
					// interrupt when there are amsdu frames to fw.
					writel(MACREG_H2ARIC_BIT_PPA_READY,
						   wlpptr->ioBase1 +
							   MACREG_REG_H2A_INTERRUPT_EVENTS);
				}
				retVal = IRQ_HANDLED;
			}
			if (intStatus & MACREG_A2HRIC_BIT_QUEUE_FULL)
			{
				intStatus &= ~MACREG_A2HRIC_BIT_QUEUE_FULL;
				retVal = IRQ_HANDLED;
			}
#ifdef IEEE80211_DH
			if (intStatus & MACREG_A2HRIC_BIT_RADAR_DETECT)
			{
				intStatus &= ~MACREG_A2HRIC_BIT_RADAR_DETECT;
				WLSYSLOG(netdev, WLSYSLOG_CLASS_ALL,
						 WLSYSLOG_MSG_GEN_RADARDETECTION);
				WLSNDEVT(netdev, IWEVCUSTOM,
						 (IEEEtypes_MacAddr_t *)&wlpptr->hwData.macAddr[0],
						 WLSYSLOG_MSG_GEN_RADARDETECTION);
#ifdef MRVL_DFS
				radarDetectionHdlr(netdev);
#endif
				retVal = IRQ_HANDLED;
			}
			if (intStatus & MACREG_A2HRIC_BIT_CHAN_SWITCH)
			{
				intStatus &= ~MACREG_A2HRIC_BIT_CHAN_SWITCH;
#ifdef MRVL_DFS
				dfsChanSwitchHdlr(netdev);
#endif
				retVal = IRQ_HANDLED;
			}
#endif // IEEE80211_DH
			if (intStatus & MACREG_A2HRIC_BIT_TX_WATCHDOG)
			{
				intStatus &= ~MACREG_A2HRIC_BIT_TX_WATCHDOG;
				wlpptr->netDevStats.tx_heartbeat_errors++;
				wlResetTask(netdev);
				retVal = IRQ_HANDLED;
			}
#if defined(AMPDU_SUPPORT_SBA) || (BA_WATCHDOG)
			if (intStatus & MACREG_A2HRIC_BA_WATCHDOG)
			{
#ifdef SOC_W8864
#define BA_STREAM 4
#else
#define BA_STREAM 5
#endif
#define INVALID_WATCHDOG 0xAA
				u_int8_t bitmap = 0xAA, stream = 0;
				intStatus &= ~MACREG_A2HRIC_BA_WATCHDOG;
				wlFwGetWatchdogbitmap(netdev, &bitmap);
				printk("watchdog cause by queue %d\n", bitmap);
				if (bitmap != INVALID_WATCHDOG)
				{
					if (bitmap == BA_STREAM)
						stream = 0;
					else if (bitmap > BA_STREAM)
						stream = bitmap - BA_STREAM;
					else
						stream = bitmap + 3;
					/** queue 0 is stream 3*/
					if (bitmap != 0xFF)
					{
						/* Check if the stream is in use before disabling it */
						if (wlpptr->wlpd_p->Ampdu_tx[stream].InUse)
						{
							disableAmpduTxstream(vmacSta_p,
												 stream);
						}
					}
					else
						disableAmpduTxAll(vmacSta_p);
				}
				retVal = IRQ_HANDLED;
			}
#endif /* _AMPDU_SUPPORT_SBA */

			if (intStatus & MACREG_A2HRIC_CONSEC_TXFAIL)
			{
				MIB_802DOT11 *mib =
					vmacSta_p->ShadowMib802dot11;
				intStatus &= ~MACREG_A2HRIC_CONSEC_TXFAIL;
				printk("Consecutive tx fail cnt > %d\n",
					   (u_int32_t) *
						   (mib->mib_consectxfaillimit));
				ConsecTxFailHdlr(netdev);
				retVal = IRQ_HANDLED;
			}
		}
		currIteration++;
	} while (currIteration < MAX_ISR_ITERATION);

	return retVal;
}
#endif /* SOC_W906X */

void wlInterruptEnable(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	unsigned int reg_a2h_intr_mask = wlpptr->wlpd_p->reg.a2h_int_mask;

	if (wlChkAdapter(netdev))
	{
#ifdef SOC_W906X
		UINT32 hfctrl =
			IS_BUS_TYPE_MCI(wlpptr) ? MACREG_HFCTRL_MASK : MACREG_HFCTRL_MASK_MSI;
		printk("%s(), w_reg(%p)=%xh\n", __func__,
			   (wlpptr->ioBase1 + reg_a2h_intr_mask), 0);
		writel(0x00, wlpptr->ioBase1 + reg_a2h_intr_mask);
		// writel((MACREG_A2HRIC_BIT_MASK),
		printk("%s(), w_reg(%p)=%xh\n", __func__,
			   (wlpptr->ioBase1 + reg_a2h_intr_mask), hfctrl);
		writel(hfctrl, wlpptr->ioBase1 + reg_a2h_intr_mask);
#ifdef WIFI_DATA_OFFLOAD
#define TXQ_6_EFF_ID SC5_REG_EFF_ID(6, 0)
#define RXQ_0_EFF_ID SC5_REG_EFF_ID(0, 1)
#define BMQ_10_EFF_ID SC5_REG_EFF_ID(10, 0)
#define BMQ_11_EFF_ID SC5_REG_EFF_ID(11, 0)
#define BMQ_12_EFF_ID SC5_REG_EFF_ID(12, 0)
#define REL_10_EFF_ID SC5_REG_EFF_ID(10, 1)
#define REL_11_EFF_ID SC5_REG_EFF_ID(11, 1)
#define REL_12_EFF_ID SC5_REG_EFF_ID(12, 1)
#define REL_13_EFF_ID SC5_REG_EFF_ID(13, 1)

		if (!wlpptr->wlpd_p->dol.disable)
		{
			/* disable interrupts for queues handled by packet engine
			 * simulator/processor
			 */
			writel(0xff, wlpptr->ioBase1 + TXQ_6_EFF_ID);
			writel(0xff, wlpptr->ioBase1 + RXQ_0_EFF_ID);
			writel(0xff, wlpptr->ioBase1 + BMQ_10_EFF_ID);
			writel(0xff, wlpptr->ioBase1 + BMQ_11_EFF_ID);
			writel(0xff, wlpptr->ioBase1 + BMQ_12_EFF_ID);
			writel(0xff, wlpptr->ioBase1 + REL_10_EFF_ID);
			writel(0xff, wlpptr->ioBase1 + REL_11_EFF_ID);
			writel(0xff, wlpptr->ioBase1 + REL_12_EFF_ID);
			writel(0xff, wlpptr->ioBase1 + REL_13_EFF_ID);
		}
#endif
#else
		writel(0x00, wlpptr->ioBase1 + MACREG_REG_A2H_INTERRUPT_MASK);

		writel((MACREG_A2HRIC_BIT_MASK),
			   wlpptr->ioBase1 + MACREG_REG_A2H_INTERRUPT_MASK);
#endif /* SOC_W906X */
	}
}

void wlInterruptDisable(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	unsigned int reg_a2h_intr_mask = wlpptr->wlpd_p->reg.a2h_int_mask;

	if (wlChkAdapter(netdev))
	{
#ifdef SOC_W906X
		writel(0x00, wlpptr->ioBase1 + reg_a2h_intr_mask);
#else
		writel(0x00, wlpptr->ioBase1 + MACREG_REG_A2H_INTERRUPT_MASK);
#endif /* SOC_W906X */
	}
}

void wlInterruptUnMask(struct net_device *netdev, int mask)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	unsigned int reg_a2h_intr_mask = wlpptr->wlpd_p->reg.a2h_int_mask;

	if (wlChkAdapter(netdev))
	{
#ifdef SOC_W906X
		writel((readl(wlpptr->ioBase1 + reg_a2h_intr_mask) | (mask)),
			   wlpptr->ioBase1 + reg_a2h_intr_mask);
#else
		writel((readl(wlpptr->ioBase1 + MACREG_REG_A2H_INTERRUPT_MASK) |
				(mask)),
			   wlpptr->ioBase1 + MACREG_REG_A2H_INTERRUPT_MASK);
#endif /* SOC_W906X */
	}
}

void wlInterruptMask(struct net_device *netdev, int mask)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	unsigned int reg_a2h_intr_mask = wlpptr->wlpd_p->reg.a2h_int_mask;

	if (wlChkAdapter(netdev))
	{
#ifdef SOC_W906X
		writel((readl(wlpptr->ioBase1 + reg_a2h_intr_mask) & (~mask)),
			   wlpptr->ioBase1 + reg_a2h_intr_mask);
#else
		writel((readl(wlpptr->ioBase1 + MACREG_REG_A2H_INTERRUPT_MASK) &
				(~mask)),
			   wlpptr->ioBase1 + MACREG_REG_A2H_INTERRUPT_MASK);
#endif /* SOC_W906X */
	}
}

void wlFwReset(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);

#ifdef SOC_W906X
	if (!IS_BUS_TYPE_MCI(wlpptr))
	{
		if (wlChkAdapter(netdev))
		{
			WLDBG_INFO(DBG_LEVEL_2, "write ISR_RESET to %u\n",
					   MACREG_REG_H2A_INTERRUPT_EVENTS);
			writel(ISR_RESET,
				   wlpptr->ioBase1 +
					   MACREG_REG_H2A_INTERRUPT_EVENTS);
		}
		else
		{
			WLDBG_INFO(DBG_LEVEL_2, "int_code = %u\n",
					   wlpptr->wlpd_p->reg.int_code);
		}
	}
#else
	if (wlChkAdapter(netdev))
	{
		writel(ISR_RESET,
			   wlpptr->ioBase1 + MACREG_REG_H2A_INTERRUPT_EVENTS);
	}
#endif
}

int wlChkAdapter(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	u_int32_t regval;
	unsigned int reg_int_code = wlpptr->wlpd_p->reg.int_code;

#ifdef SOC_W906X
	regval = readl(wlpptr->ioBase1 + reg_int_code);
#else
	regval = readl(wlpptr->ioBase1 + MACREG_REG_INT_CODE);
#endif
	if (regval == 0xffffffff)
	{
		printk(" wlChkAdapter FALSE  regval = %x \n", regval);
		return FALSE;
	}
	return TRUE;
}

#ifdef WFA_TKIP_NEGATIVE
extern int allow_ht_tkip;

int wlValidateSettings(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	int retval = SUCCESS;

	/* Perform checks on the validity of configuration combinations */
	/* Check the validity of the opmode and security mode combination */
	if (!allow_ht_tkip && (((*(mib->mib_wpaWpa2Mode) & 0x0F) == 1) || ((*(mib->mib_wpaWpa2Mode) & 0x0F) == 3)) &&
		(IsHTmode(*(mib->mib_ApMode)) || IsVHTmode(*(mib->mib_ApMode))))
	{
		/*WPA-TKIP or WPA-AES mode */
		printk("HT mode not supported when WPA is enabled\n");
		WLSYSLOG(netdev, WLSYSLOG_CLASS_ALL,
				 "HT mode not supported when WPA is enabled\n");
		WLSNDEVT(netdev, IWEVCUSTOM,
				 (IEEEtypes_MacAddr_t *)&wlpptr->hwData.macAddr[0],
				 "HT mode not supported when WPA is enabled\n");

		WLDBG_EXIT_INFO(DBG_LEVEL_0, "settings not valid");
		retval = FAIL;
	}

	if ((mib->Privacy->PrivInvoked == 1) &&
		(IsHTmode(*(mib->mib_ApMode)) || IsVHTmode(*(mib->mib_ApMode))))
	{
		printk("HT mode not supported when WEP is enabled\n");
		WLSYSLOG(netdev, WLSYSLOG_CLASS_ALL,
				 "HT mode not supported when WEP is enabled\n");
		WLSNDEVT(netdev, IWEVCUSTOM,
				 (IEEEtypes_MacAddr_t *)&wlpptr->hwData.macAddr[0],
				 "HT mode not supported when WEP is enabled\n");
		retval = FAIL;
	}

	return retval;
}
#endif

#ifdef BAND_STEERING
void sta_track_expire(struct wlprivate *wlpptr, int force)
{
	vmacApInfo_t *vmacSta_p = (vmacApInfo_t *)wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
	struct sta_track_info *info;

	if (!wlpptr->wlpd_p->bandSteer.sta_track_num)
		return;

	while ((info =
				list_first_entry(&wlpptr->wlpd_p->bandSteer.sta_track_list,
								 struct sta_track_info, list)) &&
		   (wlpptr->wlpd_p->bandSteer.sta_track_num))
	{
		if (!force &&
			!((jiffies - info->last_seen) >=
			  *(mib->mib_bandsteer_sta_track_max_age)) &&
			!(wlpptr->wlpd_p->bandSteer.sta_track_num >
			  *(mib->mib_bandsteer_sta_track_max_num)))
			break;
		force = 0;

		list_del(&info->list);
		wlpptr->wlpd_p->bandSteer.sta_track_num--;
		wl_kfree(info);
	}
}

struct sta_track_info *
sta_track_get(struct wlprivate *wlpptr, const u8 *addr)
{
	struct sta_track_info *info;

	if (!wlpptr->wlpd_p->bandSteer.sta_track_num)
		return NULL;

	list_for_each_entry(info, &wlpptr->wlpd_p->bandSteer.sta_track_list,
						list) if (memcmp(addr, info->addr, ETH_ALEN) == 0) return info;

	return NULL;
}

void sta_track_add(struct wlprivate *wlpptr, const u8 *addr)
{
	vmacApInfo_t *vmacSta_p = (vmacApInfo_t *)wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
	struct sta_track_info *info;

	info = sta_track_get(wlpptr, addr);
	if (info)
	{
		/* Move the most recent entry to the end of the list */
		list_del(&info->list);
		info->last_seen = jiffies;
		list_add_tail(&info->list,
					  &wlpptr->wlpd_p->bandSteer.sta_track_list);
		return;
	}

	/* Add a new entry */
	info = wl_kmalloc(sizeof(struct sta_track_info), GFP_ATOMIC);
	if (info == NULL)
		return;

	memcpy(info->addr, addr, ETH_ALEN);
	info->last_seen = jiffies;

	if (wlpptr->wlpd_p->bandSteer.sta_track_num >=
		*(mib->mib_bandsteer_sta_track_max_num))
	{
		/* Expire oldest entry to make room for a new one */
		sta_track_expire(wlpptr, 1);
	}

	list_add_tail(&info->list, &wlpptr->wlpd_p->bandSteer.sta_track_list);
	wlpptr->wlpd_p->bandSteer.sta_track_num++;
}

void sta_track_deinit(struct wlprivate *wlpptr)
{
	struct sta_track_info *info;

	if (!wlpptr->wlpd_p->bandSteer.sta_track_num)
		return;

	while ((info =
				list_first_entry(&wlpptr->wlpd_p->bandSteer.sta_track_list,
								 struct sta_track_info, list)) &&
		   (wlpptr->wlpd_p->bandSteer.sta_track_num))
	{
		list_del(&info->list);
		wlpptr->wlpd_p->bandSteer.sta_track_num--;
		wl_kfree(info);
	}
}

struct sta_auth_info *
sta_auth_get(struct wlprivate *wlpptr, const u8 *addr)
{
	struct sta_auth_info *info;

	if (!wlpptr->wlpd_p->bandSteer.sta_auth_num)
		return NULL;

	list_for_each_entry(info, &wlpptr->wlpd_p->bandSteer.sta_auth_list,
						list) if (memcmp(addr, info->addr, ETH_ALEN) == 0) return info;

	return NULL;
}

void sta_auth_add(struct wlprivate *wlpptr, const u8 *addr)
{
	struct sta_auth_info *info;

	info = sta_auth_get(wlpptr, addr);
	if (info)
	{
		info->count++;
		return;
	}

	if (wlpptr->wlpd_p->bandSteer.sta_auth_num >= sta_num)
		return;

	/* Add a new entry */
	info = wl_kmalloc(sizeof(struct sta_auth_info), GFP_ATOMIC);
	if (info == NULL)
		return;

	memcpy(info->addr, addr, ETH_ALEN);
	info->count = 1;

	list_add_tail(&info->list, &wlpptr->wlpd_p->bandSteer.sta_auth_list);
	wlpptr->wlpd_p->bandSteer.sta_auth_num++;
}

void sta_auth_del(struct wlprivate *wlpptr, const u8 *addr)
{
	struct sta_auth_info *info;

	info = sta_auth_get(wlpptr, addr);
	if (info)
	{
		list_del(&info->list);
		wlpptr->wlpd_p->bandSteer.sta_auth_num--;
		wl_kfree(info);
	}
}

void sta_auth_deinit(struct wlprivate *wlpptr)
{
	struct sta_auth_info *info;

	if (!wlpptr->wlpd_p->bandSteer.sta_auth_num)
		return;

	while ((info =
				list_first_entry(&wlpptr->wlpd_p->bandSteer.sta_auth_list,
								 struct sta_auth_info, list)) &&
		   (wlpptr->wlpd_p->bandSteer.sta_auth_num))
	{
		list_del(&info->list);
		wlpptr->wlpd_p->bandSteer.sta_auth_num--;
		wl_kfree(info);
	}
}
#endif /* BAND_STEERING */

#ifdef MULTI_AP_SUPPORT
void unassocsta_track_expire(struct wlprivate *wlpptr, int force)
{
	vmacApInfo_t *vmacSta_p = (vmacApInfo_t *)wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
	struct unassocsta_track_info *info;

	if (!wlpptr->wlpd_p->unassocSTA.sta_track_num)
		return;

	while ((info =
				list_first_entry(&wlpptr->wlpd_p->unassocSTA.sta_track_list,
								 struct unassocsta_track_info, list)) &&
		   (wlpptr->wlpd_p->unassocSTA.sta_track_num))
	{
		if (!force &&
			!((jiffies - info->last_seen) >=
			  *(mib->mib_unassocsta_track_max_age)) &&
			!(wlpptr->wlpd_p->unassocSTA.sta_track_num >
			  *(mib->mib_unassocsta_track_max_num)))
			break;
		force = 0;

		list_del(&info->list);
		wlpptr->wlpd_p->unassocSTA.sta_track_num--;
		wl_kfree(info);
	}
}

struct unassocsta_track_info *
unassocsta_track_get(struct wlprivate *wlpptr, const u8 *addr, u8 channel)
{
	struct unassocsta_track_info *info;

	if (!wlpptr->wlpd_p->unassocSTA.sta_track_num)
		return NULL;

	list_for_each_entry(info, &wlpptr->wlpd_p->unassocSTA.sta_track_list,
						list) if ((memcmp(addr, info->addr, ETH_ALEN) == 0) &&
								  (info->channel == channel)) return info;

	return NULL;
}

void unassocsta_track_add(struct wlprivate *wlpptr, const u8 *addr, u8 channel,
						  u32 rssi)
{
	vmacApInfo_t *vmacSta_p = (vmacApInfo_t *)wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
	struct unassocsta_track_info *info;

	info = unassocsta_track_get(wlpptr, addr, channel);
	if (info)
	{
		/* Move the most recent entry to the end of the list */
		list_del(&info->list);
		info->rssi = rssi;
		info->last_seen = jiffies;
		list_add_tail(&info->list,
					  &wlpptr->wlpd_p->unassocSTA.sta_track_list);
		return;
	}

	/* Add a new entry */
	info = wl_kzalloc(sizeof(struct unassocsta_track_info), GFP_ATOMIC);
	if (info == NULL)
		return;

	memcpy(info->addr, addr, ETH_ALEN);
	info->channel = channel;
	info->rssi = rssi;
	info->last_seen = jiffies;

	if (wlpptr->wlpd_p->unassocSTA.sta_track_num >=
		*(mib->mib_unassocsta_track_max_num))
	{
		/* Expire oldest entry to make room for a new one */
		unassocsta_track_expire(wlpptr, 1);
	}

	list_add_tail(&info->list, &wlpptr->wlpd_p->unassocSTA.sta_track_list);
	wlpptr->wlpd_p->unassocSTA.sta_track_num++;
}

void unassocsta_track_deinit(struct wlprivate *wlpptr)
{
	struct unassocsta_track_info *info;

	if (!wlpptr->wlpd_p->unassocSTA.sta_track_num)
		return;

	while ((info =
				list_first_entry(&wlpptr->wlpd_p->unassocSTA.sta_track_list,
								 struct unassocsta_track_info, list)) &&
		   (wlpptr->wlpd_p->unassocSTA.sta_track_num))
	{
		list_del(&info->list);
		wlpptr->wlpd_p->unassocSTA.sta_track_num--;
		wl_kfree(info);
	}
}
#endif

/** private functions **/

static int
wlopen(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;

	WLDBG_ENTER(DBG_LEVEL_2);
#ifdef CLIENTONLY
	// this will handle ifconfig down/up case
	wlpptr->wlreset(netdev);
	WL_MOD_INC_USE(THIS_MODULE, return -EIO);
	return 0;
#else
	memset(&wlpptr->wlpd_p->privStats, 0x00, sizeof(struct wlpriv_stats));
	if (wfa_11ax_pf)
	{
		vmacSta_p->dl_ofdma_para.sta_cnt = 0;
		memset(vmacSta_p->ofdma_mu_sta_addr, 0x0,
			   IEEEtypes_ADDRESS_SIZE * MAX_OFDMADL_STA);
	}

	netdev->type = ARPHRD_ETHER;

	if (netdev->flags & IFF_RUNNING)
	{
		vmacSta_p->InfUpFlag = 0;
		netif_stop_queue(netdev);
		netdev->flags &= ~IFF_RUNNING;
		wlInterruptDisable(netdev);
	}
#ifdef WFA_TKIP_NEGATIVE
	if (wlValidateSettings(netdev))
		return -EIO;
#endif

	if (wlFwApplySettings(netdev))
		return -EIO;

	wlInterruptEnable(netdev);
	netif_wake_queue(netdev);
	vmacSta_p->InfUpFlag = 1;
	netdev->flags |= IFF_RUNNING;

#ifdef AUTOCHANNEL
	scanControl(wlpptr->vmacSta_p);
#endif

	/* Initialize the STADB timers */
	if (wlpptr->vmacSta_p->master == NULL)
	{
		extStaDb_AgingTimerInit(wlpptr->vmacSta_p);
		extStaDb_ProcessKeepAliveTimerInit(wlpptr->vmacSta_p);
	}
#ifdef SOC_W8964
	wlFwRadioStatusNotification(netdev, 1);
#endif /* SOC_W8964 */
	WL_MOD_INC_USE(THIS_MODULE, return -EIO);
	WLDBG_EXIT(DBG_LEVEL_2);
#ifdef NAPI
	napi_enable(&wlpptr->napi);
#endif
	return 0;
#endif
}

static int
wlstop(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
#ifdef BAND_STEERING
	int i;
	unsigned long flags;
#endif /* BAND_STEERING */
	u32 numVif, j;
	u32 warnmsg = 0;

	WLDBG_ENTER(DBG_LEVEL_2);

	/* Return if any Virtual device  is running */
#ifdef ENABLE_MONIF
	numVif = wlpptr->wlpd_p->NumOfAPs + 2; // VAP + STA + MON
#else
	numVif = wlpptr->wlpd_p->NumOfAPs + 1; // VAP + STA
#endif

	for (j = 0; j < numVif; j++)
	{
		if ((wlpptr->vdev[j] != NULL) &&
			(wlpptr->vdev[j]->flags & IFF_RUNNING))
		{
			if (!warnmsg)
			{
				printk(KERN_INFO
					   "disable %s will also disable all its virtual net devices.\n",
					   netdev->name);
				warnmsg = 1;
			}
			printk(KERN_INFO "disable %s\n", wlpptr->vdev[j]->name);
			dev_close(wlpptr->vdev[j]);
		}
	}

	/*Set InfUpFlag in beginning of stop function to prevent sending Auth pkt during stop process. */
	/*When down interface, some connected client sends Auth pkt right away and AP still process it */
	/*till Assoc Resp during down process. This can cause GlobalStationCnt in fw to be +1, which is wrong. */
	vmacSta_p->InfUpFlag = 0;

	if (netdev->flags & IFF_RUNNING)
	{
		netif_stop_queue(netdev);
		netdev->flags &= ~IFF_RUNNING;

#ifdef SOC_W906X
		wlOffChannelStop(netdev);
#endif
#ifdef AUTOCHANNEL
		ACS_stop_timer(wlpptr->vmacSta_p);
#endif /* AUTOCHANNEL */

		if (wlFwSetAPBss(netdev, WL_DISABLE))
		{
			WLDBG_WARNING(DBG_LEVEL_2, "disabling AP bss failed");
		}
		if (wlFwSetRadio(netdev, WL_DISABLE, WL_AUTO_PREAMBLE))
		{
			WLDBG_WARNING(DBG_LEVEL_2, "disabling rf failed");
		}
		wlInterruptDisable(netdev);
#ifdef SOC_W8964
		wlFwRadioStatusNotification(netdev, 0);
#endif /* SOC_W8964 */
	}
#ifdef NAPI
	napi_disable(&wlpptr->napi);
#endif
#ifdef BAND_STEERING
	SPIN_LOCK_IRQSAVE(&wlpptr->wlpd_p->locks.bandSteerListLock, flags);
	TimerRemove(&wlpptr->wlpd_p->bandSteer.queued_timer);
	for (i = 0; i < skb_queue_len(&wlpptr->wlpd_p->bandSteer.skb_queue);
		 i++)
	{
		struct sk_buff *skb = NULL;

		skb = skb_dequeue(&wlpptr->wlpd_p->bandSteer.skb_queue);
		if (skb)
			wl_free_skb(skb);
	}
	wlpptr->wlpd_p->bandSteer.queued_skb_num = 0;
	SPIN_UNLOCK_IRQRESTORE(&wlpptr->wlpd_p->locks.bandSteerListLock, flags);
	sta_track_deinit(wlpptr);
	sta_auth_deinit(wlpptr);
#endif /* BAND_STEERING */
#ifdef MULTI_AP_SUPPORT
	TimerRemove(&wlpptr->wlpd_p->unassocSTA.waitTimer);
	TimerRemove(&wlpptr->wlpd_p->unassocSTA.scanTimer);
	unassocsta_track_deinit(wlpptr);
	if (wlpptr->wlpd_p->unassocSTA.unassocsta_query)
		wl_kfree(wlpptr->wlpd_p->unassocSTA.unassocsta_query);
#endif /* MULTI_AP_SUPPORT */
	WL_MOD_DEC_USE(THIS_MODULE);
	WLDBG_EXIT(DBG_LEVEL_2);
	return 0;
}

static void
wlsetMcList(struct net_device *netdev)
{
	//      struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);

	WLDBG_ENTER(DBG_LEVEL_2);
	WLDBG_EXIT(DBG_LEVEL_2);
}

void calculate_err_count(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	struct wlprivate *wlptmpptr = NULL;
	vmacApInfo_t *vmactmp_p = NULL;
	char *sta_buf, *show_buf;
	int i = 0, entries;
	extStaDb_StaInfo_t *pStaInfo;
	SMAC_STA_STATISTICS_st StaStatsTbl;
	u32 tx_err, rx_err;

	if ((netdev->flags & IFF_RUNNING) == 0)
	{
		return;
	}

	entries = extStaDb_entries(vmacSta_p, 0);
	if (entries)
	{
		sta_buf = wl_kmalloc(entries * 64, GFP_KERNEL);

		if (sta_buf != NULL)
		{
			extStaDb_list(vmacSta_p, sta_buf, 1);
			show_buf = sta_buf;
			for (i = 0; i < entries; i++)
			{
				if ((pStaInfo =
						 extStaDb_GetStaInfo(vmacSta_p,
											 (IEEEtypes_MacAddr_t *)
												 show_buf,
											 STADB_DONT_UPDATE_AGINGTIME)) == NULL)
				{
					break;
				}

				memset(&StaStatsTbl, 0,
					   sizeof(SMAC_STA_STATISTICS_st));
				if (wlFwGetStaStats(netdev, pStaInfo->StnId,
									&StaStatsTbl) != SUCCESS)
				{
					WLDBG_INFO(DBG_LEVEL_11,
							   "cannot get StnId %d stats from fw%d\n",
							   StaInfo_p->StnId);
					break;
				}

				if (vmacSta_p->master)
				{
					vmactmp_p = vmacSta_p->master;
					wlptmpptr =
						NETDEV_PRIV_P(struct wlprivate,
									  vmactmp_p->dev);
				}
				rx_err = pStaInfo->rx_err;
				pStaInfo->rx_err =
					StaStatsTbl.dot11FCSErrorCount;
				if (pStaInfo->rx_err > rx_err)
				{
					wlpptr->netDevStats.rx_errors +=
						pStaInfo->rx_err - rx_err;
					if (wlptmpptr)
						wlptmpptr->netDevStats.rx_errors +=
							pStaInfo->rx_err -
							rx_err;
				}
				tx_err = pStaInfo->tx_err;
				if (StaStatsTbl.dot11MPDUCount >
					(StaStatsTbl.dot11SuccessCount +
					 StaStatsTbl.dot11RetryCount))
					pStaInfo->tx_err =
						StaStatsTbl.dot11MPDUCount -
						StaStatsTbl.dot11SuccessCount -
						StaStatsTbl.dot11RetryCount;
				if (pStaInfo->tx_err > tx_err)
				{
					wlpptr->netDevStats.tx_errors +=
						pStaInfo->tx_err - tx_err;
					if (wlptmpptr)
						wlptmpptr->netDevStats.tx_errors +=
							pStaInfo->tx_err -
							tx_err;
				}

				show_buf += sizeof(STA_INFO);
			}
			wl_kfree(sta_buf);
		}
	}
}

static struct net_device_stats *
wlgetStats(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);

	WLDBG_ENTER(DBG_LEVEL_2);

	calculate_err_count(netdev);

	WLDBG_EXIT(DBG_LEVEL_2);
	return &(wlpptr->netDevStats);
}

static int
wlsetMacAddr(struct net_device *netdev, void *addr)
{
	struct sockaddr *macAddr = (struct sockaddr *)addr;

	WLDBG_ENTER(DBG_LEVEL_2);

	if (is_valid_ether_addr(macAddr->sa_data))
	{
		WLDBG_EXIT(DBG_LEVEL_2);
		return 0; /* for safety do not allow changes in MAC-ADDR! */
	}
	WLDBG_EXIT_INFO(DBG_LEVEL_2, "invalid addr");
	return -EADDRNOTAVAIL;
}

static int
wlchangeMtu(struct net_device *netdev, int mtu)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);

	netdev->mtu = mtu;
	if (netdev->flags & IFF_RUNNING)
	{
		return (wlpptr->wlreset(netdev));
	}
	else
		return -EPERM;

	return 0;
}

#ifdef SOC_W906X
static void
wlreset_allInf(struct net_device *netdev)
{
#if defined(MBSS)
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	int i = 0, gid;
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	u32 pri_mbssid_map = 0; // primary mbssid bitmap of all groups
	u32 mask = 0;
	mbss_set_t *pset = wlpd_p->mbssSet;

	// printk("%s()...\n",__func__);

	// if mbssid set existing. make sure the primary mbssid is the last bssid brought up in its group.
	for (gid = 0; gid < MAX_MBSSID_SET && pset[gid].mbssid_set; gid++)
	{
		pri_mbssid_map |= (1 << pset[gid].primbss);
	}

	i = 0;
	while (i <= bss_num)
	{
		// bring the vitual interface back if it brought down the routine
		if (wlpptr->vdev[i])
		{
			if ((NETDEV_PRIV_P(struct wlprivate, wlpptr->vdev[i]))->vmacSta_p->OpMode == WL_OP_MODE_AP ||
				((NETDEV_PRIV_P(struct wlprivate,
								wlpptr->vdev[i]))
					 ->vmacSta_p->OpMode ==
				 WL_OP_MODE_VAP))
			{
				if (wlpptr->wlpd_p->dev_running[i])
				{

					// bring up primary mbssids later.
					if (pri_mbssid_map & (1 << i))
					{
						mask |= (1 << i);
						i++;
						continue;
					}

					wlreset_mbss(wlpptr->vdev[i]);
				}
			}
			if ((NETDEV_PRIV_P(struct wlprivate, wlpptr->vdev[i]))->vmacSta_p->OpMode == WL_OP_MODE_VSTA)
			{
				if (wlpptr->wlpd_p->dev_running[i])
				{

					wlreset_client(wlpptr->vdev[i]);
				}
			}
		}
		i++;
	}

	// bring up all primary mbssids
	i = 0;
	while (mask)
	{
		if (mask & 0x1)
		{
			printk("bring up primary bssid: macid:%u\n", i);
			wlreset_mbss(wlpptr->vdev[i]);
		}

		mask >>= 1;
		i++;
	}

	// all mbssid_set changed already launched.
	wlpd_p->bss_inupdate = 0;

#endif
}
#else // W906X
static void
wlreset_allInf(struct net_device *netdev)
{
#if defined(MBSS)
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	int i = 0;

	while (i <= MAX_VMAC_INSTANCE_AP)
	{
		// bring the vitual interface back if it brought down the routine
		if (wlpptr->vdev[i])
		{
			if ((NETDEV_PRIV_P(struct wlprivate, wlpptr->vdev[i]))->vmacSta_p->OpMode == WL_OP_MODE_AP ||
				((NETDEV_PRIV_P(struct wlprivate,
								wlpptr->vdev[i]))
					 ->vmacSta_p->OpMode ==
				 WL_OP_MODE_VAP))
			{
				if (wlpptr->wlpd_p->dev_running[i])
				{

					wlreset_mbss(wlpptr->vdev[i]);
				}
			}
			if ((NETDEV_PRIV_P(struct wlprivate, wlpptr->vdev[i]))->vmacSta_p->OpMode == WL_OP_MODE_VSTA)
			{
				if (wlpptr->wlpd_p->dev_running[i])
				{

					wlreset_client(wlpptr->vdev[i]);
				}
			}
		}
		i++;
	}
#endif
}
#endif // W906X
static void
wlstop_allInf(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	int i = 0;

	while (i <= bss_num)
	{
		// remember the interface up/down status, and bring down it.
		if (wlpptr->vdev[i])
		{
			wlpptr->wlpd_p->dev_running[i] = 0;
			if ((NETDEV_PRIV_P(struct wlprivate, wlpptr->vdev[i]))->vmacSta_p->OpMode == WL_OP_MODE_AP ||
				((NETDEV_PRIV_P(struct wlprivate,
								wlpptr->vdev[i]))
					 ->vmacSta_p->OpMode ==
				 WL_OP_MODE_VAP))
			{

				if (wlpptr->vdev[i]->flags & IFF_RUNNING)
				{

					wlpptr->wlpd_p->dev_running[i] = 1;
				}
#ifdef WIFI_DATA_OFFLOAD
				if (wlpptr->wlpd_p->dol.vif_added_to_pe[wlpptr->vmacSta_p->VMacEntry.macId])
				{
					dol_del_vif(wlpptr,
								wlpptr->wlpd_p->ipc_session_id,
								wlpptr->vmacSta_p->VMacEntry.macId);
					wlpptr->wlpd_p->dol.vif_added_to_pe[wlpptr->vmacSta_p->VMacEntry.macId] = 0;
				}
#endif
				wlstop_mbss(wlpptr->vdev[i]);
			}
			if ((NETDEV_PRIV_P(struct wlprivate, wlpptr->vdev[i]))->vmacSta_p->OpMode == WL_OP_MODE_VSTA)
			{
				if (wlpptr->vdev[i]->flags & IFF_RUNNING)
				{

					wlpptr->wlpd_p->dev_running[i] = 1;
					wlstop_client(wlpptr->vdev[i]);
				}
			}
		}
		i++;
	}
}

void wlVirtualInfUp(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;

#ifdef SINGLE_DEV_INTERFACE
	wlrestart_wdsports(netdev);
#endif

	if (wfa_11ax_pf)
	{
		memset(&vmacSta_p->dl_ofdma_para, 0x0,
			   sizeof(struct dl_ofdma_parameter_s));
		memset(vmacSta_p->ofdma_mu_sta_addr, 0x0,
			   IEEEtypes_ADDRESS_SIZE * MAX_OFDMADL_STA);
		if (vmacSta_p->master)
		{
			memset(&vmacSta_p->master->dl_ofdma_para, 0x0,
				   sizeof(struct dl_ofdma_parameter_s));
			memset(vmacSta_p->master->ofdma_mu_sta_addr, 0x0,
				   IEEEtypes_ADDRESS_SIZE * MAX_OFDMADL_STA);
		}
	}

	netif_wake_queue(netdev); /* restart Q if interface was running */
	vmacSta_p->InfUpFlag = 1;
	netdev->flags |= IFF_RUNNING;

	wlFwApplySettings(netdev); // ok, no crash
#ifdef SOC_W8964
	wlFwRadioStatusNotification(netdev, 1);
#endif /* SOC_W8964 */

	wlInterruptEnable(netdev);
	wlreset_allInf(netdev);
	wlpptr->wlpd_p->bpreresetdone = TRUE;

	wlpptr->wlpd_p->inReset = WL_FALSE;

	return;
}

void wlVirtualInfDown(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;

#ifdef MRVL_DFS
	DfsCmd_t dfsCmd;
#endif
#ifdef AUTOCHANNEL
	{
		Disable_ScanTimerProcess(vmacSta_p);
		vmacSta_p->busyScanning = 0;
		Disable_extStaDb_ProcessKeepAliveTimer(vmacSta_p);
		Disable_MonitorTimerProcess(vmacSta_p);
	}
#endif
	wlInterruptDisable(netdev);
#if defined(CLIENT_SUPPORT)
	{
		printk(KERN_INFO "[%s]%s Stop client netdev = %p chk1\n",
			   netdev->name, __FUNCTION__, wlpptr->txNetdev_p);
		if (wlpptr->txNetdev_p)
		{
			if (wlpptr->txNetdev_p->flags & IFF_RUNNING)
			{
				vmacSta_p->InfUpFlag = 0;
				netif_stop_queue(wlpptr->txNetdev_p);
				wlpptr->txNetdev_p->flags &= ~IFF_RUNNING;
			}
		}
	}
#endif
	if (netdev->flags & IFF_RUNNING)
	{
		vmacSta_p->InfUpFlag = 0;
		netif_stop_queue(netdev);
		netif_carrier_off(netdev);
		netdev->flags &= ~IFF_RUNNING;
	}
	wlstop_allInf(netdev);
#ifdef MRVL_DFS
	/* Send the reset message to
	 * the DFS event dispatcher
	 */
	dfsCmd.CmdType = DFS_CMD_WL_RESET;
	evtDFSMsg(netdev, (UINT8 *)&dfsCmd);
#endif
	return;
}

static void
wltxwait_txdone(struct net_device *netdev)
{
#ifdef SOC_W906X
	/*{
	   // Chip has been reset => no need to get anything
	   struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	   struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;

	   //Set all tx-done bits
	   wlpptr->BQRelId |= wlpd_p->bmq_args.buf_release_msix_mask;
	   wlTxDone(netdev);
	   } */
#else
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	UINT32 txDoneTail;
	UINT32 txDoneHead, txDoneHeadnew;
	do
	{
		mdelay(10);
		wlTxDone(netdev);
		txDoneHeadnew = readl(priv->ioBase1 + MACREG_REG_TxDoneHead);
		txDoneTail =
			priv->wlpd_p->descData[0].TxDoneTail & (MAX_TX_RING_DONE_SIZE - 1);
		txDoneHead = txDoneHeadnew & (MAX_TX_RING_DONE_SIZE - 1);
		printk("\n\ntxDoneHead=%d, txDoneTail=%d\n\n", txDoneHead,
			   txDoneTail);
	} while (txDoneTail != txDoneHead);
	priv->wlpd_p->descData[0].TxDoneTail = 0;
#endif /* SOC_W906X */
}

static void
wlPowerResetFw(struct net_device *netdev)
{
#ifdef SOC_W906X
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	wl_pcie_reset(priv->pPciDev);
	priv->wlpd_p->bpreresetdone = FALSE;
#else
#define GPIO_0_31_DATAOUT_REG 0x18100
#define GPIO_0_31_DATAOUT_CONTROL_REG 0x18104
#define GPIO_32_59_DATAOUT_REG 0x18140
#define GPIO_32_59_DATAOUT_CONTROL_REG 0x18144
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	UINT32 temp;
	void *ptr1, *ptr2;
	UINT32 value, mask;

	if (priv->wlpd_p->gpioresetpin < 32)
	{
		ptr1 = ioremap(0xf1000000 + GPIO_0_31_DATAOUT_REG, 4);
		ptr2 = ioremap(0xf1000000 + GPIO_0_31_DATAOUT_CONTROL_REG, 4);
		value = 1 << priv->wlpd_p->gpioresetpin;
		mask = ~value;
	}
	else if (priv->wlpd_p->gpioresetpin < 60)
	{
		ptr1 = ioremap(0xf1000000 + GPIO_32_59_DATAOUT_REG, 4);
		ptr2 = ioremap(0xf1000000 + GPIO_32_59_DATAOUT_CONTROL_REG, 4);
		value = 1 << (priv->wlpd_p->gpioresetpin - 32);
		mask = ~value;
	}
	else
	{
		printk("unknown reset pin\n");
		return;
	}
	printk("%s: power reset by GPIO %d\n", netdev->name,
		   priv->wlpd_p->gpioresetpin);

	priv->wlpd_p->bfwreset = TRUE;
	temp = *((volatile unsigned int *)ptr2);
	*((volatile unsigned int *)ptr2) = temp & mask;
	temp = *((volatile unsigned int *)ptr1);
	*((volatile unsigned int *)ptr1) = temp & mask;	 // reset
	*((volatile unsigned int *)ptr1) = temp | value; // undo reset
	priv->wlpd_p->bpreresetdone = FALSE;
#endif
}

#ifdef SOC_W906X
static void
wlOffChannelReqListFree(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	offChanListItem *offChanListItem_p = NULL;
	// UINT32 listcnt = 0;
	unsigned long listflags;

	SPIN_LOCK_IRQSAVE(&wlpptr->wlpd_p->locks.offChanListLock, listflags);
	while ((offChanListItem_p =
				(offChanListItem *)ListGetItem(&wlpptr->wlpd_p->offChanList)) != NULL)
	{
		if (offChanListItem_p->txSkb_p != NULL)
		{
			wl_free_skb(offChanListItem_p->txSkb_p);
		}
		wl_kfree(offChanListItem_p);

#if 0
		/*To prevent going into infinite loop when tail status is 1 and id doesn't match with any in ReqIdList */
		listcnt++;
		if (listcnt > wlpptr->wlpd_p->offChanList.cnt) {
			break;
		}
#endif
	}
	SPIN_UNLOCK_IRQRESTORE(&wlpptr->wlpd_p->locks.offChanListLock,
						   listflags);
}

static void
wlOffChannelStop(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct net_device *netdev_offchan = NULL;
	struct wlprivate *wlpptr_offchan = NULL;
	UINT32 retry_cnt = 0;

	if (wlpptr->master)
	{
		// This is virtual i/f. We should check its physical i/f.
		netdev_offchan = wlpptr->master;
		wlpptr_offchan =
			NETDEV_PRIV_P(struct wlprivate, netdev_offchan);
	}
	else
	{
		netdev_offchan = netdev;
		wlpptr_offchan = wlpptr;
	}
	// Purge offchan queue
	wlOffChannelReqListFree(netdev_offchan);
	// Wait for offchan goes back to idle state
	while (wlpptr_offchan->offchan_state != OFFCHAN_IDLE && retry_cnt < 50)
	{
		retry_cnt++;
		mdelay(10);
	}

	return;
}
#else  // 906X off-channel
static void
wlOffChannelReqListFree(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	ReqIdListItem *ReqIdListItem_p = NULL;
	UINT32 listcnt = 0;

	while ((ReqIdListItem_p =
				(ReqIdListItem *)ListGetItem(&wlpptr->wlpd_p->ReqIdList)) !=
		   NULL)
	{
		if (ReqIdListItem_p->txSkb_p != NULL)
		{
			wl_free_skb(ReqIdListItem_p->txSkb_p);
		}
		wl_kfree(ReqIdListItem_p);

		/*To prevent going into infinite loop when tail status is 1 and id doesn't match with any in ReqIdList */
		listcnt++;
		if (listcnt > wlpptr->wlpd_p->ReqIdList.cnt)
		{
			break;
		}
	}
}
#endif // 906X off-channel

static void
wlFwHardreset(struct net_device *netdev, int firsttime)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate *parent_wlpptr = GET_PARENT_PRIV(priv);
	UINT32 txSendTail;

	if (!firsttime)
	{
		wlVirtualInfDown(netdev);
		wltxwait_txdone(netdev);
		// remember the SendTail which is updated by FW before fw gone.
#ifdef SOC_W906X
		txSendTail =
			readl(priv->ioBase1 + priv->wlpd_p->reg.tx_send_tail);
#else
		txSendTail = readl(priv->ioBase1 + MACREG_REG_TxSendTail);
#endif /* SOC_W906X */
	}
#ifdef SOC_W906X
	if (IS_BUS_TYPE_MCI(parent_wlpptr) == FALSE)
#endif /* SOC_W906X */
	{
		wlPowerResetFw(netdev);
	}
#ifdef SOC_W906X
	else
	{
#ifdef CONFIG_MARVELL_MOCHI_DRIVER
		struct wlprivate_data *wlpd_p = priv->wlpd_p;
		u8 rcnt = 0;
		int mci_inst = wlpd_p->mci_id;
		int mci_speed = MCI_LINK_SPEED_8G;

		do
		{
			int mci_ret = mci_do_reset(mci_inst, mci_speed);
			if (mci_ret == MCI_FAIL)
			{
				pr_info("The Mochi device doesn't present\n");
				return;
			}
			if (mci_ret == MCI_OK)
				break;
			if (mci_ret == MCI_UNSUPPORTED_SPEED)
				mci_speed--;
		} while ((rcnt++ < MAX_BUS_RESET) &&
				 (mci_speed >= MCI_LINK_SPEED_1G));

		if (rcnt >= MAX_BUS_RESET)
		{
			printk("Failed to reset mochi, after repeating %d times\n", rcnt);
			return;
		}
#else
		WLDBG_WARNING(DBG_LEVEL_1,
					  "No mci_do_reset() in system, firmware redownload may fail\n");
#endif // CONFIG_MARVELL_MOCHI_DRIVER
	}
#endif // SOC_W906X
	// cleanup tx queue
	if (!firsttime)
	{
#ifdef SOC_W906X
		wlTxRingFree(netdev);
		wlQMCleanUp(netdev);
		wlOffChannelReqListFree(netdev);
		wlfree_intr(netdev);
#else
		UINT32 txSendHeadNew;

		txSendHeadNew = priv->wlpd_p->descData[0].TxSentHead;
		printk("TxSentHead=%d TxSentTail=%d txQueRecord=%d\n",
			   txSendHeadNew, txSendTail,
			   skb_queue_len(&priv->wlpd_p->txQueRecord));
		skb_queue_purge(&priv->wlpd_p->txQueRecord);
		priv->wlpd_p->descData[0].TxSentTail = 0;
		priv->wlpd_p->descData[0].TxSentHead = 0;

		wlTxRingFree(netdev);
		wlRxRingFree(netdev);
		wlOffChannelReqListFree(netdev);
#endif /* SOC_W906X */
	}
#ifdef SOC_W906X
	if (!IS_BUS_TYPE_MCI(priv))
	{
		pci_free_consistent(priv->pPciDev, SC5_HFRAME_MEM_SIZE,
							priv->hframe_virt_addr,
							priv->hframe_phy_addr);
#else
	{
		pci_free_consistent(priv->pPciDev, 0x4000,
							priv->pCmdBuf, priv->wlpd_p->pPhysCmdBuf);

#endif /* SOC_W906X */

		mdelay(2000);

#ifdef SOC_W906X
		if (pci_save_state(priv->pPciDev))
		{
			dev_err(&priv->pPciDev->dev,
					"Failed to save pci state\n");
			return;
		}
#else
		printk("%s: baseaddress0 0x%X \n", netdev->name,
			   (unsigned int)priv->wlpd_p->baseaddress0);
		printk("%s: baseaddress2 0x%X \n", netdev->name,
			   (unsigned int)priv->wlpd_p->baseaddress2);

		pci_write_config_dword(priv->wlpd_p->pPciDev,
							   PCI_BASE_ADDRESS_0,
							   priv->wlpd_p->baseaddress0);
		pci_write_config_dword(priv->wlpd_p->pPciDev,
							   PCI_BASE_ADDRESS_2,
							   priv->wlpd_p->baseaddress2);
#endif

		mdelay(1000);

#ifdef SOC_W906X
		iounmap(priv->ioBase2);
		release_mem_region(pci_resource_start(priv->pPciDev, 4),
						   pci_resource_len(priv->pPciDev, 4));
#endif
		iounmap(priv->ioBase1);
		iounmap(priv->ioBase0);

		release_mem_region(pci_resource_start(priv->pPciDev, 2),
						   pci_resource_len(priv->pPciDev, 2));
		release_mem_region(pci_resource_start(priv->pPciDev, 0),
						   pci_resource_len(priv->pPciDev, 0));
		pci_disable_device(priv->pPciDev);

		{
			phys_addr_t physAddr = 0;
			unsigned long resourceFlags;
			void *physAddr1[2];
			void *physAddr2[2];

			if (pci_enable_device(priv->pPciDev))
			{
				printk("pci enable device fail \n");
			}

			if (pci_set_dma_mask(priv->pPciDev, 0xffffffff))
			{
				printk("32-bit PCI DMA not supported");
			}
			pci_set_master(priv->pPciDev);

			physAddr = pci_resource_start(priv->pPciDev, 0);
			resourceFlags = pci_resource_flags(priv->pPciDev, 0);

			priv->nextBarNum = 1; /* 32-bit */

			if (resourceFlags & 0x04)
				priv->nextBarNum = 2; /* 64-bit */

			if (!request_mem_region(physAddr, pci_resource_len(priv->pPciDev, 0),
									DRV_NAME))
			{
				printk(KERN_ERR
					   "%s: cannot reserve PCI memory region 0\n",
					   DRV_NAME);
			}

			physAddr1[0] =
				ioremap(physAddr,
						pci_resource_len(priv->pPciDev, 0));
			physAddr1[1] = 0;
			priv->ioBase0 = physAddr1[0];

			printk("wlprobe  wlpptr->ioBase0 = %p \n",
				   priv->ioBase0);

			if (!priv->ioBase0)
			{
				printk(KERN_ERR
					   "%s: cannot remap PCI memory region 0\n",
					   DRV_NAME);
			}
#ifdef SOC_W906X
			priv->smacCfgAddr =
				&((SMAC_CTRL_BLK_st *)priv->ioBase0)->config;
			priv->smacStatusAddr =
				&((SMAC_CTRL_BLK_st *)priv->ioBase0)->status;
#endif

			physAddr =
				pci_resource_start(priv->pPciDev,
								   priv->nextBarNum);
			if (!request_mem_region(physAddr,
									pci_resource_len(priv->pPciDev, priv->nextBarNum),
									DRV_NAME))
			{
				printk(KERN_ERR
					   "%s: cannot reserve PCI memory region 1\n",
					   DRV_NAME);
			}
			physAddr2[0] =
				ioremap(physAddr,
						pci_resource_len(priv->pPciDev,
										 priv->nextBarNum));
			physAddr2[1] = 0;
			priv->ioBase1 = physAddr2[0];

			printk("wlprobe  wlpptr->ioBase1 = %p\n",
				   priv->ioBase1);

			if (!priv->ioBase1)
			{
				printk(KERN_ERR
					   "%s: cannot remap PCI memory region 1\n",
					   DRV_NAME);
			}
#ifdef SOC_W906X
			if (resourceFlags & 0x04)
			{
				priv->nextBarNum = 4; /* 64-bit */
			}

			physAddr =
				pci_resource_start(priv->pPciDev,
								   priv->nextBarNum);
			if (!request_mem_region(physAddr,
									pci_resource_len(priv->pPciDev, priv->nextBarNum),
									DRV_NAME))
			{
				printk(KERN_ERR
					   "%s: cannot reserve PCI memory region 2\n",
					   DRV_NAME);
			}

			physAddr2[0] =
				ioremap(physAddr,
						pci_resource_len(priv->pPciDev,
										 priv->nextBarNum));
			physAddr2[1] = 0;
			priv->ioBase2 = physAddr2[0];
			printk("wlprobe  wlpptr->ioBase2 = %p\n",
				   priv->ioBase2);
			if (!priv->ioBase2)
			{
				printk(KERN_ERR
					   "%s: cannot remap PCI memory region 2\n",
					   DRV_NAME);
			}
			priv->hframe_virt_addr = (unsigned short *)
				pci_alloc_consistent(priv->pPciDev,
									 SC5_HFRAME_MEM_SIZE,
									 &priv->hframe_phy_addr);
#else
			priv->pCmdBuf = (unsigned short *)
				pci_alloc_consistent(priv->pPciDev, 0x4000,
									 &priv->wlpd_p->pPhysCmdBuf);
#endif

			priv->netDev->mem_start =
				pci_resource_start(priv->pPciDev, 0);
			priv->netDev->mem_end =
				physAddr + pci_resource_len(priv->pPciDev, 1);

#ifdef SOC_W8964
			writel(0, priv->ioBase1 + MACREG_REG_TxSendHead);
			writel(0, priv->ioBase1 + MACREG_REG_TxSendTail);
			writel(0, priv->ioBase1 + MACREG_REG_TxDoneHead);
			writel(0, priv->ioBase1 + MACREG_REG_TxDoneTail);
			// writel(0, priv->ioBase1 + MACREG_REG_RxDescHead);
			writel(0, priv->ioBase1 + MACREG_REG_RxDescTail);
			writel(0, priv->ioBase1 + MACREG_REG_RxDoneHead);
			writel(0, priv->ioBase1 + MACREG_REG_RxDoneTail);

			writel(0, priv->ioBase1 + MACREG_REG_AcntHead);
			writel(0, priv->ioBase1 + MACREG_REG_AcntTail);
			writel(0, priv->ioBase1 + MACREG_REG_OffchReqHead);
			writel(0, priv->ioBase1 + MACREG_REG_OffchReqTail);

			if (!firsttime)
			{
				int retCode;

				if ((retCode = wlTxRingAlloc(netdev)) == 0)
				{
					if ((retCode =
							 wlTxRingInit(netdev)) != 0)
					{
						printk(KERN_ERR
							   "%s: initializing TX ring failed\n",
							   netdev->name);
					}
				}
				else
				{
					printk(KERN_ERR
						   "%s: allocating TX ring failed\n",
						   netdev->name);
				}

				if ((retCode = wlRxRingAlloc(netdev)) == 0)
				{
					if ((retCode =
							 wlRxRingReInit(netdev)) != 0)
					{
						printk(KERN_ERR
							   "%s: initializing RX ring failed\n",
							   netdev->name);
					}
				}
				else
				{
					printk(KERN_ERR
						   "%s: allocating RX ring failed\n",
						   netdev->name);
				}
			}
			else
			{
				writel(1023,
					   priv->ioBase1 + MACREG_REG_RxDescHead);
			}
			AllocSharedMem(priv);
			AllocMrvlPriSharedMem(priv); // mrvl private mailbox region
#endif									 /* SOC_W8964 */
		}
	}
/*
	writel(0, priv->ioBase1 + priv->wlpd_p->reg.tx_send_head);
	writel(0, priv->ioBase1 + priv->wlpd_p->reg.tx_send_tail);
	writel(0, priv->ioBase1 + priv->wlpd_p->reg.tx_done_head);
	writel(0, priv->ioBase1 + priv->wlpd_p->reg.tx_done_tail);
	//writel(0, priv->ioBase1 + priv->wlpd_p->reg.rx_desc_head);
	writel(0, priv->ioBase1 + priv->wlpd_p->reg.rx_desc_tail);
	writel(0, priv->ioBase1 + priv->wlpd_p->reg.rx_done_head);
	writel(0, priv->ioBase1 + priv->wlpd_p->reg.rx_done_tail);

	writel(0, priv->ioBase1 + priv->wlpd_p->reg.acnt_head);
	writel(0, priv->ioBase1 + priv->wlpd_p->reg.acnt_tail);
	writel(0, priv->ioBase1 + priv->wlpd_p->reg.offch_req_head);
	writel(0, priv->ioBase1 + priv->wlpd_p->reg.offch_req_tail);
*/
#ifdef SOC_W906X
	AllocSharedMem(priv);
	AllocMrvlPriSharedMem(priv); // mrvl private mailbox region

	if (priv->intr_type == PCI_INTR_TYPE_MSI)
		enable_irq(priv->netDev->irq);

	wl_init_intr(priv);
	wl_hook_intr(priv);

	writel(priv->hframe_phy_addr, priv->ioBase1 + SC5_REG_HFRAME_BASE);
	printk("hframe base addr %llx \n",
		   (long long unsigned int)priv->hframe_phy_addr);

	/* Clean DMEM */
	memset_io(priv->ioBase0, 0, sizeof(SMAC_CTRL_BLK_st));
#endif /* SOC_W906X */
}

#ifdef SOC_W906X
void wlReinit(struct net_device *netdev)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate *parent_wlpptr = GET_PARENT_PRIV(priv);
	int retCode;

	if ((retCode = wlTxRingAlloc(netdev)) != 0)
	{
		printk(KERN_ERR "%s: allocating TX ring failed\n",
			   netdev->name);
	}

	if ((retCode = wlTxRingInit(netdev)) != 0)
	{
		printk(KERN_ERR "%s: initializing TX ring failed\n",
			   netdev->name);
	}

	if ((retCode = wlQMInit(netdev)) != 0)
	{
		printk(KERN_ERR "%s: initializing BM Q failed\n", netdev->name);
	}

	memcpy(parent_wlpptr->ioBase0, (void *)&parent_wlpptr->smacconfig,
		   sizeof(SMAC_CONFIG_st));

	printk("=> %s(), MAC_STATUS_st->verCtrl[3] = %xh\n", __func__,
		   0xF0000000);
	writel(0xF0000000, &parent_wlpptr->smacStatusAddr->verCtrl[3]);
	if (wlInitChkSmacRdy(netdev) == FALSE)
	{
		WLDBG_ERROR(DBG_LEVEL_0, "Failed to get macRdy at init\n");
	}
	else
	{
		WLDBG_INFO(DBG_LEVEL_0, "macRdy is ready now\n");
	}
	post_init_bq_idx(netdev, true);

#ifdef WIFI_DATA_OFFLOAD
	/* enable radio without taking care of DFS first */
	dol_radio_data_ctrl(parent_wlpptr,
						parent_wlpptr->wlpd_p->ipc_session_id, true);
#endif

	// because of timing, fw cmd, issued for old fw, still might happen during fw redownloaded,
	// so clear flag here to make sure no hit cmdtimout for this new download
	priv->wlpd_p->smon.exceptionAbortCmdExec = 0;

	if (wlFwGetHwSpecs(netdev))
	{
		printk(KERN_ERR "%s: failed to get HW specs\n", netdev->name);
	}
	wlInterruptDisable(netdev);
	if (wlFwSetHwSpecs(netdev))
	{
		WLDBG_ERROR(DBG_LEVEL_2, "failed to set HW specs");
	}
	return;
}
#endif /* SOC_W906X */

// halt=0, do hw reset
void wlFwHardResetAndReInit(struct net_device *netdev, U8 halt)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;

	priv->wlpd_p->downloadSuccessful = FALSE; // Firmware has been resetted
#ifdef SOC_W906X
	// "bfwreset" will show that the firmware may have been dead that it won't reply events, (HOST_EVT_STA_DEL)
	// => Driver should call FreeStnId_newdp() to free the StnId in extStaDb_DelSta()
	priv->wlpd_p->bfwreset = TRUE;

	// Stop Tx any pkt
	printk("Stopping Tx path\n");

	// Disable the rx of smac
	printk("Stopping RX path\n");
	{
		U32 regval;
		*(u32 *)(&((SMAC_CTRL_BLK_st *)priv->ioBase0)->config.rxEnable) = 0;
		regval = readl(priv->ioBase1 + BBRX_CFG);
		if (regval & 0x01)
			writel((regval & 0xFFFFFFFE), priv->ioBase1 + BBRX_CFG);
	}
	/* disable all interupts from hframe */
	writel(0x0, priv->ioBase1 + SC5_REG_PCIE_INTR_MODE_SEL);

	/* disable all interrupts from device */
	wldisable_intr(netdev);
	msleep(100);
#endif // SOC_W906X

	if (halt)
		return;
	wlFwHardreset(netdev, 0);
	wlFwReDownload(netdev);
#ifdef SOC_W906X
	wlReinit(netdev);
	priv->wlpd_p->bfwreset = FALSE;
	priv->wlpd_p->bpreresetdone = TRUE;
	vmacSta_p->StopTraffic = FALSE;
#endif /* SOC_W906X */
	wlVirtualInfUp(netdev);

	priv->wlpd_p->bfwreset = FALSE;
}

static void
wlFwReDownload(struct net_device *netdev)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);

#ifdef FS_CAL_FILE_SUPPORT
	wlDownloadMFGFile(netdev);
#endif
	if (wlPrepareFwFile(netdev))
	{
		/* No external fw .bin, assume fw downoaded from debuggger */
		printk("%s: No firmware download, pleaes make sure fw has been loaded by debugger!!!!!\n", netdev->name);
	}
	else
	{
		if (wlFwDownload(netdev))
		{
			printk(KERN_ERR "%s: firmware downloading failed\n",
				   netdev->name);
		}
		wl_kfree(priv->FwPointer);
	}
#ifdef FS_CAL_FILE_SUPPORT
	if (wlFreeMFGFileBuffer(netdev))
	{
		WLDBG_WARNING(DBG_LEVEL_3, "%s: MFG file free buffer failed\n",
					  netdev->name);
	}
#endif
#ifdef SOC_W8964
	if (wlFwGetHwSpecs(netdev))
	{
		printk(KERN_ERR "%s: failed to get HW specs\n", netdev->name);
	}
	memcpy(netdev->dev_addr, &priv->hwData.macAddr[0], 6);
	printk("Mac address = %s \n", mac_display(&priv->hwData.macAddr[0]));
	if (wlFwSetHwSpecs(netdev))
	{
		printk("failed to set HW specs\n");
	}
#endif /* SOC_W8964 */

	{
		struct wlprivate *wlpptr;
		UINT8 index;

#ifdef ENABLE_MONIF
		// VAP + STA + MON
		for (index = 0; index <= bss_num + 1; index++)
		{
#else
		for (index = 0; index <= bss_num; index++)
		{
#endif
			if (priv->vdev[index])
			{
				wlpptr = NETDEV_PRIV_P(struct wlprivate,
									   priv->vdev[index]);
				wlpptr->ioBase0 = priv->ioBase0;
				wlpptr->ioBase1 = priv->ioBase1;
				wlpptr->netDev->mem_start =
					priv->netDev->mem_start;
				wlpptr->netDev->mem_end = priv->netDev->mem_end;
				wlpptr->pCmdBuf = priv->pCmdBuf;
			}
		}
	}

#ifdef SOC_W8964
	wlVirtualInfUp(netdev);
	priv->wlpd_p->bfwreset = FALSE;
#endif /* SOC_W8964 */
}

int wlreset(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;

#ifdef MRVL_DFS
	DfsCmd_t dfsCmd;
#endif
#ifdef AUTOCHANNEL
	{
		Disable_ScanTimerProcess(vmacSta_p);
		vmacSta_p->busyScanning = 0;
		Disable_extStaDb_ProcessKeepAliveTimer(vmacSta_p);
		Disable_MonitorTimerProcess(vmacSta_p);
	}
#endif
	vmacSta_p->download = TRUE;
	WLDBG_ENTER(DBG_LEVEL_2);

	if (wlpptr->wlpd_p->inReset)
	{
		return 0;
	}
	else
	{
		wlpptr->wlpd_p->inReset = WL_TRUE;
	}
#ifdef WIFI_DATA_OFFLOAD
	dol_suspend_radio(wlpptr, wlpptr->wlpd_p->ipc_session_id, true);
#endif
	wlpptr->wlpd_p->bBssStartEnable = 0;
#if defined(CLIENT_SUPPORT)
	{
		printk(KERN_INFO "[%s]%s Stop client netdev = %p \n",
			   netdev->name, __FUNCTION__, wlpptr->txNetdev_p);
		if (wlpptr->txNetdev_p)
		{
			if (wlpptr->txNetdev_p->flags & IFF_RUNNING)
			{
				vmacSta_p->InfUpFlag = 0;
				netif_stop_queue(wlpptr->txNetdev_p);
				wlpptr->txNetdev_p->flags &= ~IFF_RUNNING;
			}
		}
	}
#endif
	if (netdev->flags & IFF_RUNNING)
	{
		vmacSta_p->InfUpFlag = 0;
		netif_stop_queue(netdev);
		netif_carrier_off(netdev);
		netdev->flags &= ~IFF_RUNNING;
	}
	wlstop_allInf(netdev);
#ifdef SOC_W906X
	macMgmtMlme_ResetProbeRspBuf(vmacSta_p);
	wlOffChannelStop(netdev);
#endif
	if (wlFwSetAPBss(netdev, WL_DISABLE))
	{
		WLDBG_EXIT_INFO(DBG_LEVEL_2, "disable AP bss failed");
		// if fw stop responding, do not block fw download
		// goto err_fw_cmd;
	}
	if (wlFwSetRadio(netdev, WL_DISABLE, WL_AUTO_PREAMBLE))
	{
		WLDBG_EXIT_INFO(DBG_LEVEL_2, "disable rf failed");
		// if fw stop responding, do not block fw download
		// goto err_fw_cmd;
	}
	wlInterruptDisable(netdev);

#ifdef SINGLE_DEV_INTERFACE
	wlrestart_wdsports(netdev);
#endif
	netif_wake_queue(netdev); /* restart Q if interface was running */
	vmacSta_p->InfUpFlag = 1;
	netdev->flags |= IFF_RUNNING;

	if (wlFwApplySettings(netdev))
		return -EIO;

	wlInterruptEnable(netdev);

	WLDBG_EXIT(DBG_LEVEL_2);
	wlpptr->vmacSta_p->download = FALSE;
	wlpptr->wlpd_p->inReset = WL_FALSE;
#ifdef MFG_SUPPORT
	if (wlpptr->mfgEnable)
	{
		return 0;
	}
#endif
#ifdef AUTOCHANNEL
	scanControl(wlpptr->vmacSta_p);
#endif
	wlreset_allInf(netdev);
	wlpptr->wlpd_p->inResetQ = WL_FALSE;
#ifdef WIFI_DATA_OFFLOAD
	dol_suspend_radio(wlpptr, wlpptr->wlpd_p->ipc_session_id, false);
#endif

#ifdef MRVL_DFS
	/* Send the reset message to
	 * the DFS event dispatcher
	 */
	dfsCmd.CmdType = DFS_CMD_WL_RESET;
	evtDFSMsg(netdev, (UINT8 *)&dfsCmd);

#endif
	wlpptr->wlpd_p->BcnAddHtOpMode = 0;
	wlpptr->wlpd_p->TxGf = 0;

	if (!netif_queue_stopped(netdev))
		netif_carrier_on(netdev);

#ifdef MULTI_AP_SUPPORT
	FourAddr_ClearHashEntry();
#endif

#ifdef COEXIST_20_40_SUPPORT
	{
		MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
		MIB_PHY_DSSS_TABLE *PhyDSSSTable = mib->PhyDSSSTable;
		extern int wlFwSet11N_20_40_Switch(struct net_device * netdev,
										   UINT8 mode);
		extern void Check20_40_Channel_switch(int option, int *mode);
		extern void Disable_StartCoexisTimer(vmacApInfo_t * vmacSta_p);

		if ((*(mib->USER_ChnlWidth) & 0xf0) &&
			((*(vmacSta_p->Mib802dot11->mib_ApMode) & AP_MODE_BAND_MASK) < AP_MODE_A_ONLY))
		{
			wlFwSet11N_20_40_Switch(vmacSta_p->dev, 0);
			*(mib->USER_ChnlWidth) = 0;
		}
		else if ((PhyDSSSTable->Chanflag.ChnlWidth == CH_AUTO_WIDTH) || (PhyDSSSTable->Chanflag.ChnlWidth == CH_160_MHz_WIDTH) ||
				 (PhyDSSSTable->Chanflag.ChnlWidth ==
				  CH_40_MHz_WIDTH) ||
				 (PhyDSSSTable->Chanflag.ChnlWidth ==
				  CH_80_MHz_WIDTH))
		{

			if (PhyDSSSTable->CurrChan == 14)
				*(mib->USER_ChnlWidth) = 0;
			else
				*(mib->USER_ChnlWidth) = 1;
			Disable_StartCoexisTimer(vmacSta_p);
		}
	}
#endif

	return 0;
	/*
	   err_fw_cmd:
			wlpptr->vmacSta_p->download = FALSE;
			wlpptr->wlpd_p->inReset = WL_FALSE;
			wlpptr->wlpd_p->inResetQ = WL_FALSE;
			return -EFAULT;*/
}

static void
wltxTimeout(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);

	WLDBG_ENTER(DBG_LEVEL_2);

	if (wlpptr->wlpd_p->inReset)
	{
		return;
	}
#ifdef MRVL_DFS
	if ((netdev->flags & IFF_RUNNING) == 0)
	{
		return;
	}
#endif

	wlpptr->wlpd_p->isTxTimeout = WL_TRUE;
	wlpptr->wlreset(netdev);
	wlpptr->wlpd_p->isTxTimeout = WL_FALSE;
	WLDBG_EXIT(DBG_LEVEL_2);
}

void wlSendEvent(struct net_device *dev, int cmd, IEEEtypes_MacAddr_t *Addr,
				 const char *info)
{
	union iwreq_data wrqu;
	char buf[128];

	memset(&wrqu, 0, sizeof(wrqu));

	if ((dev->flags & IFF_RUNNING) == 0)
		return;

	if (cmd == IWEVCUSTOM)
	{
		snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x:%s",
				 *((unsigned char *)Addr), *((unsigned char *)Addr + 1),
				 *((unsigned char *)Addr + 2),
				 *((unsigned char *)Addr + 3),
				 *((unsigned char *)Addr + 4),
				 *((unsigned char *)Addr + 5), info);
		wrqu.data.length = strlen(buf);
	}
	else
	{
		wrqu.data.length = 0;
		memcpy(wrqu.ap_addr.sa_data, (unsigned char *)Addr,
			   sizeof(IEEEtypes_MacAddr_t));
		wrqu.ap_addr.sa_family = ARPHRD_ETHER;
	}
	/* Send event to user space */
	wireless_send_event(dev, cmd, &wrqu, buf);
	return;
}

#ifdef WDS_FEATURE
static const struct net_device_ops wlwds_netdev_ops = {
	.ndo_open = wlopen_wds,
	.ndo_stop = wlstop_wds,
	.ndo_start_xmit = wlDataTx,
	.ndo_do_ioctl = wlIoctl,
	.ndo_set_mac_address = wlsetMacAddr_wds,
	.ndo_tx_timeout = wltxTimeout_wds,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 2, 0)
	.ndo_set_rx_mode = wlsetMcList,
#else
	.ndo_set_multicast_list = wlsetMcList,
#endif
	.ndo_change_mtu = wlchangeMtu_wds,
	.ndo_get_stats = wlgetStats,
};

int wlInit_wds(struct wlprivate *wlpptr)
{
	UINT16 i;
	struct net_device *dev;
	char temp_name[32] = {0};
	int name_len = 0;
	//      char devName[16];
	for (i = 0; i < MAX_WDS_PORT; i++)
	{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0)
		dev = alloc_netdev(0, DRV_NAME_WDS, NET_NAME_UNKNOWN,
						   wlwlan_setup);
#else
		dev = alloc_netdev(0, DRV_NAME_WDS, wlwlan_setup);
#endif
		NETDEV_PRIV_S(dev) = NETDEV_PRIV(struct wlprivate, dev);
		wlpptr->vmacSta_p->wdsPort[i].netDevWds = dev;
		wlpptr->vmacSta_p->wdsPort[i].netDevWds->netdev_ops =
			&wlwds_netdev_ops;
		wlpptr->vmacSta_p->wdsPort[i].netDevWds->ethtool_ops =
			&wl_ethtool_ops;
		wlpptr->vmacSta_p->wdsPort[i].netDevWds->watchdog_timeo =
			30 * HZ;

		wlpptr->vmacSta_p->wdsPort[i].netDevWds->irq =
			wlpptr->netDev->irq;
		wlpptr->vmacSta_p->wdsPort[i].netDevWds->mem_start =
			wlpptr->netDev->mem_start;
		wlpptr->vmacSta_p->wdsPort[i].netDevWds->mem_end =
			wlpptr->netDev->mem_end;
		NETDEV_PRIV_S(wlpptr->vmacSta_p->wdsPort[i].netDevWds) =
			(void *)wlpptr;
		wlpptr->vmacSta_p->wdsPort[i].netDevWds->needed_headroom =
			SKB_INFO_SIZE;
		wlpptr->vmacSta_p->wdsPort[i].pWdsDevInfo =
			(void *)&wlpptr->vmacSta_p->wdsPeerInfo[i];
		sprintf(temp_name, DRV_NAME_WDS, wlpptr->netDev->name, (int)i);

		name_len = strlen(temp_name);
		if (name_len <= IFNAMSIZ)
			memcpy(wlpptr->vmacSta_p->wdsPort[i].netDevWds->name,
				   temp_name, name_len);
		// setWdsPeerInfo(&wlpptr->vmacSta_p->wdsPeerInfo[i], AP_MODE_G_ONLY); // Set to default G.

		wlpptr->vmacSta_p->wdsActive[i] = FALSE;
		wlpptr->vmacSta_p->wdsPort[i].active = FALSE;
		memcpy(wlpptr->vmacSta_p->wdsPort[i].netDevWds->dev_addr,
			   wlpptr->vmacSta_p->macStaAddr, 6);
		ether_setup(wlpptr->vmacSta_p->wdsPort[i].netDevWds);

		/* register cfg80211 virtual interface to wiphy wdev */
#ifdef CFG80211
		wlpptr->vmacSta_p->wdsPort[i].wdev.wiphy = wlpptr->wiphy;
		wlpptr->vmacSta_p->wdsPort[i].wdev.iftype = NL80211_IFTYPE_WDS;
		wlpptr->vmacSta_p->wdsPort[i].wdev.netdev =
			wlpptr->vmacSta_p->wdsPort[i].netDevWds;
		wlpptr->vmacSta_p->wdsPort[i].netDevWds->ieee80211_ptr =
			&wlpptr->vmacSta_p->wdsPort[i].wdev;
		SET_NETDEV_DEV(wlpptr->vmacSta_p->wdsPort[i].netDevWds,
					   wiphy_dev(wlpptr->vmacSta_p->wdsPort[i].wdev.wiphy));
#endif
		if (register_netdev(wlpptr->vmacSta_p->wdsPort[i].netDevWds))
		{
			printk(KERN_ERR "%s: failed to register WDS device\n",
				   wlpptr->vmacSta_p->wdsPort[i].netDevWds->name);
			return FALSE;
		}
		wlpptr->vmacSta_p->wdsPort[i].wdsPortRegistered = TRUE;
	}

	return SUCCESS;
}

int wlStop_wdsDevs(struct wlprivate *wlpptr)
{
	UINT16 i;

	for (i = 0; i < MAX_WDS_PORT; i++)
	{
		wlstop_wds(wlpptr->vmacSta_p->wdsPort[i].netDevWds);
	}

	return SUCCESS;
}

static int
wlopen_wds(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;

	//      wlfacilitate_e radioOnOff = WL_ENABLE ;

	WLDBG_ENTER(DBG_LEVEL_2);

	netdev->type = ARPHRD_ETHER;

	if (netdev->flags & IFF_RUNNING)
	{
		vmacSta_p->InfUpFlag = 0;
		netif_stop_queue(netdev);
		netdev->flags &= ~IFF_RUNNING;
	}
	else
	{
		WL_MOD_INC_USE(THIS_MODULE, return -EIO);
	}

	netif_wake_queue(netdev); /* Start/Restart Q if stopped. */
	vmacSta_p->InfUpFlag = 1;
	netdev->flags |= IFF_RUNNING;
	WLDBG_EXIT(DBG_LEVEL_2);
	return 0;
}

int wlstop_wds(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;

	vmacSta_p->InfUpFlag = 0;
	WLDBG_ENTER(DBG_LEVEL_2);

	if (netdev->flags & IFF_RUNNING)
	{
		netif_stop_queue(netdev);
		netdev->flags &= ~IFF_RUNNING;
		WL_MOD_DEC_USE(THIS_MODULE);
	}
	netif_carrier_on(netdev);

	WLDBG_EXIT(DBG_LEVEL_2);
	return 0;
}

static void
wltxTimeout_wds(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);

	WLDBG_ENTER(DBG_LEVEL_2);

	if (wlpptr->wlpd_p->inReset)
	{
		return;
	}

	wlreset_wds(netdev);
	WLDBG_EXIT(DBG_LEVEL_2);
}

static int
wlsetMacAddr_wds(struct net_device *netdev, void *addr)
{
	//      struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct sockaddr *macAddr = (struct sockaddr *)addr;

	WLDBG_ENTER(DBG_LEVEL_2);
	if (is_valid_ether_addr(macAddr->sa_data))
	{
		// memcpy(netdev->dev_addr, addr, 6);
		setWdsPortMacAddr(netdev, (UINT8 *)addr);
		WLDBG_EXIT(DBG_LEVEL_2);
		return 0;
	}
	WLDBG_EXIT_INFO(DBG_LEVEL_2, "invalid addr");
	return -EADDRNOTAVAIL;
}

static int
wlchangeMtu_wds(struct net_device *netdev, int mtu)
{
	netdev->mtu = mtu;
	if (netdev->flags & IFF_RUNNING)
	{
		return (wlreset_wds(netdev));
	}
	else
		return -EPERM;

	return 0;
}

int wlreset_wds(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;

	WLDBG_ENTER(DBG_LEVEL_2);

	if (wlpptr->wlpd_p->inReset)
	{
		return 0;
	}
	disableAmpduTxAll(wlpptr->vmacSta_p);

	if (netdev->flags & IFF_RUNNING)
	{
		vmacSta_p->InfUpFlag = 0;
		netif_stop_queue(netdev);
		netdev->flags &= ~IFF_RUNNING;
	}

	netif_wake_queue(netdev); /* restart Q if interface was running */
	vmacSta_p->InfUpFlag = 1;
	netdev->flags |= IFF_RUNNING;

	WLDBG_EXIT(DBG_LEVEL_2);
	return 0;
}

#endif

static int
wlopen_mbss(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;

	WLDBG_ENTER(DBG_LEVEL_2);
	if ((vmacSta_p->VMacEntry.macId == (bss_num - 1)) &&
		(wlpd_p->SharedBssState == SHARE_STA))
	{
		printk("BSS_%u alreay occupied by STA\n",
			   vmacSta_p->VMacEntry.macId);
		return -EIO;
	}

	if (wfa_11ax_pf)
	{
		vmacSta_p->dl_ofdma_para.sta_cnt = 0;
		memset(vmacSta_p->ofdma_mu_sta_addr, 0x0,
			   IEEEtypes_ADDRESS_SIZE * MAX_OFDMADL_STA);
		if (vmacSta_p->master)
		{
			vmacSta_p->master->dl_ofdma_para.sta_cnt = 0;
			memset(vmacSta_p->master->ofdma_mu_sta_addr, 0x0,
				   IEEEtypes_ADDRESS_SIZE * MAX_OFDMADL_STA);
		}
	}
	netdev->type = ARPHRD_ETHER;

	if (netdev->flags & IFF_RUNNING)
	{
		vmacSta_p->InfUpFlag = 0;
		netif_stop_queue(netdev);
		netdev->flags &= ~IFF_RUNNING;
	}
	else
	{
		WL_MOD_INC_USE(THIS_MODULE, return -EIO);
	}
#ifdef CB_SUPPORT
	if (wlpptr->cb_enable == TRUE)
	{
		TimerInit(&wlpptr->bnc_timer);
		TimerFireIn(&wlpptr->bnc_timer,
					1, &bcn_timer_routine, (void *)wlpptr->netDev, 1);
		// init_timer(&wlpptr->bnc_timer);
		// wlpptr->bnc_timer.function = bcn_timer_routine;
		// wlpptr->bnc_timer.data = (unsigned long)wlpptr->netDev;
		// HZ => 1 sec
		// wlpptr->bnc_timer.expires = jiffies + HZ;
		// add_timer(&wlpptr->bnc_timer);
	}
#endif // CB_SUPPORT
#ifdef WFA_TKIP_NEGATIVE
	if (wlValidateSettings(netdev))
		return -EIO;
#endif

	if (vmacSta_p->master)
	{
		MIB_802DOT11 *rootmib = vmacSta_p->master->ShadowMib802dot11;
		MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
		if (Is5GBand(*(rootmib->mib_ApMode)) !=
			(Is5GBand(*(mib->mib_ApMode))))
		{
			/* Correct the opmode and supported rate if the band of each vap is different from root radio device
			 */
			*(mib->mib_ApMode) = *(rootmib->mib_ApMode);
#ifdef BRS_SUPPORT
			*(mib->BssBasicRateMask) = *(rootmib->BssBasicRateMask);
			*(mib->NotBssBasicRateMask) =
				*(rootmib->NotBssBasicRateMask);
			*(mib->mib_shortSlotTime) =
				*(rootmib->mib_shortSlotTime);
#endif
		}
	}

	wlFwMultiBssApplySettings(netdev);
	if (wlpptr->master)
	{
		// set wdev0 OpMode to follow wdev0apX's opmode
		if (vmacSta_p->master)
			vmacSta_p->master->OpMode = vmacSta_p->OpMode;
	}

	netif_wake_queue(netdev); /* Start/Restart Q if stopped. */
	vmacSta_p->InfUpFlag = 1;
	netdev->flags |= IFF_RUNNING;

	if ((wlpptr->devid == SC5 || wlpptr->devid == SCBT) &&
		(vmacSta_p->VMacEntry.macId == (bss_num - 1)))
		wlpd_p->SharedBssState = SHARE_VAP;

#ifdef SOC_W906X
	// Notice mbsset of this bss is down
	update_mbss_status(wlpptr, 1);
#endif
	ap8xLnxStat_clients_init(netdev, 1);

#ifdef WIFI_DATA_OFFLOAD
	dol_vif_data_ctrl(wlpptr, wlpptr->wlpd_p->ipc_session_id,
					  wlpptr->vmacSta_p->VMacEntry.macId, true);
#endif

	// SMAC might not ready here, so get BssTsfBase here is not reliable.
	// clear the BssTsfBse and let it be retrieved at sending the first prob Resp frame.
	vmacSta_p->BssTsfBase = 0;

#ifdef CCK_DESENSE
	if (wlpptr->master)
	{
		cck_desense_timer_start(wlpptr->master);
	}
#endif /* CCK_DESENSE */

	TimerInit(&vmacSta_p->deauth_block_timer);
	vmacSta_p->deauth_block = 0;

	netif_carrier_on(netdev);

	WLDBG_EXIT(DBG_LEVEL_2);
	return 0;
}

static int
wlstop_mbss(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;

	/*Set InfUpFlag in beginning of stop function to prevent sending Auth pkt during stop process. */
	/*When down interface, some connected client sends Auth pkt right away and AP still process it */
	/*till Assoc Resp during down process. This can cause GlobalStationCnt in fw to be +1, which is wrong. */
	vmacSta_p->InfUpFlag = 0;

	WLDBG_ENTER(DBG_LEVEL_2);
#ifdef WDS_FEATURE
	wlStop_wdsDevs(wlpptr);
#endif
#ifdef CB_SUPPORT
	if (wlpptr->cb_enable == TRUE)
	{
		while (timer_pending(&wlpptr->bnc_timer))
		{
			msleep(1);
		}
		TimerRemove(&wlpptr->bnc_timer);
	}
#endif // CB_SUPPORT
	if (wlpptr->vmacSta_p != NULL)
		SendResetCmd(wlpptr->vmacSta_p, 0);

	if (netdev->flags & IFF_RUNNING)
	{
#ifdef SOC_W906X
		wlOffChannelStop(netdev);
#endif

#ifdef SOC_W906X
		if (wlpptr->wlpd_p->downloadSuccessful == TRUE)
#endif /* SOC_W906X */
		{
			if (wlFwSetAPBss(netdev, WL_DISABLE_VMAC))
			{
				WLDBG_EXIT_INFO(DBG_LEVEL_2,
								"disable AP bss failed");
			}
		}
		netif_stop_queue(netdev);
		netif_carrier_off(netdev);
		netdev->flags &= ~IFF_RUNNING;
#ifdef SOC_W906X
		// Notice mbsset of this bss is down
		update_mbss_status(wlpptr, 0);
#endif

		WL_MOD_DEC_USE(THIS_MODULE);
	}
	if (wlpptr->vmacSta_p != NULL)
	{
		DisableMacMgmtTimers(wlpptr->vmacSta_p);
		if ((wlpptr->devid == SC5 || wlpptr->devid == SCBT) &&
			vmacSta_p->VMacEntry.macId == (bss_num - 1) &&
			wlpd_p->SharedBssState == SHARE_VAP)
			wlpd_p->SharedBssState = SHARE_NONE;
	}
#ifdef WIFI_DATA_OFFLOAD
#if 0 /* dlin */
	dol_vif_data_ctrl(wlpptr, wlpptr->wlpd_p->ipc_session_id,
			  wlpptr->vmacSta_p->VMacEntry.macId, false);
#endif
#endif

#ifdef CCK_DESENSE
	if (wlpptr->master)
	{
		cck_desense_timer_stop(wlpptr->master);
	}
#endif /* CCK_DESENSE */

#ifdef SOC_W906X
	if (vmacSta_p != NULL)
	{
		// clear BssTsfBase and let it refresh at the first prob Resp sending.
		vmacSta_p->BssTsfBase = 0;

		macMgmtMlme_ResetProbeRspBuf(vmacSta_p);
	}
#endif

	TimerRemove(&vmacSta_p->deauth_block_timer);

	WLDBG_INFO(DBG_LEVEL_2, "Stop mbss name = %s \n", netdev->name);

	WLDBG_EXIT(DBG_LEVEL_2);
	return 0;
}

int wlreset_mbss(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;

	WLDBG_ENTER(DBG_LEVEL_2);

	// clear BssTsfBase and let it refresh at the first prob Resp sending.
	vmacSta_p->BssTsfBase = 0;

	if (wlpptr->wlpd_p->inReset)
	{
		return 0;
	}
#ifdef CONFIG_IEEE80211W
	{
		extern IEEEtypes_MacAddr_t bcast; // = {0xff,0xff,0xff,0xff,0xff,0xff};
		extStaDb_RemoveAllStns(vmacSta_p,
							   IEEEtypes_REASON_DEAUTH_LEAVING);
#ifdef SOC_W906X
		macMgmtMlme_SendDeauthenticateMsg(vmacSta_p, &bcast, 0,
										  IEEEtypes_REASON_DEAUTH_LEAVING,
										  FALSE);
#else
		macMgmtMlme_SendDeauthenticateMsg(vmacSta_p, &bcast, 0,
										  IEEEtypes_REASON_DEAUTH_LEAVING);
#endif /* SOC_W906X */
	}
#endif

#ifdef WDS_FEATURE
	{
		int i;
		// Stop any wds port queues that are active.
		for (i = 0; i < MAX_WDS_PORT; i++)
		{
			if (wdsPortActive(netdev, i))
			{
				vmacSta_p->InfUpFlag = 0;
				netif_stop_queue(wlpptr->vmacSta_p->wdsPort[i].netDevWds);
				wlpptr->vmacSta_p->wdsPort[i].netDevWds->flags &= ~IFF_RUNNING;
			}
		}
	}
#endif

	if (netdev->flags & IFF_RUNNING)
	{
#ifdef SOC_W906X
		wlOffChannelStop(netdev);
#endif
		vmacSta_p->InfUpFlag = 0;
		if (wlFwSetAPBss(netdev, WL_DISABLE_VMAC))
		{
			WLDBG_EXIT_INFO(DBG_LEVEL_2, "disable AP bss failed");
		}
		netif_stop_queue(netdev);
		netdev->flags &= ~IFF_RUNNING;
		/* If phy_radio commit, it will do wlstop_mbss(), disable IFF_RUNNING and WL_MOD_DEC_USE first,
		 * and can't enter this section. "isIfUsed" will sync error. */
		WL_MOD_DEC_USE(THIS_MODULE);
	}
	wlFwMultiBssApplySettings(netdev);
	netif_wake_queue(netdev); /* restart Q if interface was running */
	vmacSta_p->InfUpFlag = 1;
	netdev->flags |= IFF_RUNNING;
	/* If phy_radio commit, decrease "isIfUsed" in wlstop_mbss() and must increase it here. */
	WL_MOD_INC_USE(THIS_MODULE, return -EIO);
#ifdef WDS_FEATURE
	{
		int i;
		/* wake any wds port queues that are active. */
		for (i = 0; i < MAX_WDS_PORT; i++)
		{
			if (wdsPortActive(netdev, i) &&
				netif_running(wlpptr->vmacSta_p->wdsPort[i].netDevWds))
			{
				netif_wake_queue(wlpptr->vmacSta_p->wdsPort[i].netDevWds);
				wlpptr->vmacSta_p->wdsPort[i].netDevWds->flags |= IFF_RUNNING;
			}
		}
	}
#endif

#ifdef WIFI_DATA_OFFLOAD
	if (!wlpptr->wlpd_p->dol.vif_added_to_pe[vmacSta_p->VMacEntry.macId])
	{
		dol_add_vif(wlpptr, wlpptr->wlpd_p->ipc_session_id,
					vmacSta_p->VMacEntry.macId,
					(u8 *)&vmacSta_p->macStaAddr);
		dol_vif_data_ctrl(wlpptr, wlpptr->wlpd_p->ipc_session_id,
						  vmacSta_p->VMacEntry.macId, true);
		wlpptr->wlpd_p->dol.vif_added_to_pe[vmacSta_p->VMacEntry.macId] = 1;
	}
#endif

#ifdef CCK_DESENSE
	cck_desense_timer_start(wlpptr->master);
#endif /*CCK_DESENSE */
	netif_carrier_on(netdev);

	WLDBG_EXIT(DBG_LEVEL_2);
	return 0;
}

static void
wltxTimeout_mbss(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);

	WLDBG_ENTER(DBG_LEVEL_2);

	if (wlpptr->wlpd_p->inReset)
	{
		return;
	}
	// Dont do anything here to trigger wlreset_mbss
	// wlreset_mbss(netdev);
	printk("wltxTimeout_mbss(%s) happened****\n", netdev->name);
	WLDBG_EXIT(DBG_LEVEL_2);
}

static int
wlsetMacAddr_mbss(struct net_device *netdev, void *addr)
{
	//      struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct sockaddr *macAddr = (struct sockaddr *)addr;

	WLDBG_ENTER(DBG_LEVEL_2);
	if (is_valid_ether_addr(macAddr->sa_data))
	{
		memcpy(netdev->dev_addr, addr, 6);
		WLDBG_EXIT(DBG_LEVEL_2);
		return 0;
	}
	WLDBG_EXIT_INFO(DBG_LEVEL_2, "invalid addr");
	return -EADDRNOTAVAIL;
}

static int
wlchangeMtu_mbss(struct net_device *netdev, int mtu)
{
	WLDBG_ENTER(DBG_LEVEL_2);
	netdev->mtu = mtu;
	if (netdev->flags & IFF_RUNNING)
	{
		WLDBG_EXIT(DBG_LEVEL_2);
		return (wlreset_mbss(netdev));
	}
	else
		WLDBG_EXIT(DBG_LEVEL_2);
	return -EPERM;
	WLDBG_EXIT(DBG_LEVEL_2);
	return 0;
}

#ifdef ENABLE_MONIF
int wlmonif_tx(struct sk_buff *skb, struct net_device *netdev)
{
	wl_free_skb(skb);
	return 0;
}

static int
wlopen_monif(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	PROM_CNF_t PromCnf;

	WLDBG_ENTER(DBG_LEVEL_2);

	netdev->type = ARPHRD_IEEE80211_RADIOTAP;

	PromCnf.PromDataMask = 1;
	PromCnf.PromMgmtMask = 1;
	PromCnf.PromCtrlMask = 1;
	wlFwNewDP_config_prom(wlpptr->master, &PromCnf);

	if (netdev->flags & IFF_RUNNING)
	{
		netif_stop_queue(netdev);
		netdev->flags &= ~IFF_RUNNING;
	}
	else
		WL_MOD_INC_USE(THIS_MODULE, return -EIO);

	netif_wake_queue(netdev); /* Start/Restart Q if stopped. */
	netdev->flags |= IFF_RUNNING;

	WLDBG_EXIT(DBG_LEVEL_2);
	return 0;
}

static int
wlstop_monif(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	PROM_CNF_t PromCnf;

	WLDBG_ENTER(DBG_LEVEL_2);

	PromCnf.PromDataMask = 0;
	PromCnf.PromMgmtMask = 0;
	PromCnf.PromCtrlMask = 0;
	wlFwNewDP_config_prom(wlpptr->master, &PromCnf);

	if (netdev->flags & IFF_RUNNING)
	{
		netif_stop_queue(netdev);
		netdev->flags &= ~IFF_RUNNING;
		WL_MOD_DEC_USE(THIS_MODULE);
	}
	printk("Stop mbss name = %s \n", netdev->name);

	WLDBG_EXIT(DBG_LEVEL_2);
	return 0;
}

int wlreset_monif(struct net_device *netdev)
{
	WLDBG_ENTER(DBG_LEVEL_2);

	if (netdev->flags & IFF_RUNNING)
	{
		netif_stop_queue(netdev);
		netdev->flags &= ~IFF_RUNNING;
	}

	netif_wake_queue(netdev); /* restart Q if interface was running */
	netdev->flags |= IFF_RUNNING;

	WLDBG_EXIT(DBG_LEVEL_2);
	return 0;
}

static const struct net_device_ops wlmonif_netdev_ops = {
	.ndo_open = wlopen_monif,
	.ndo_stop = wlstop_monif,
	.ndo_start_xmit = wlmonif_tx,
	.ndo_do_ioctl = NULL, // wlIoctl_monif,
	.ndo_set_mac_address = wlsetMacAddr_mbss,
	.ndo_tx_timeout = NULL,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 2, 0)
	.ndo_set_rx_mode = NULL,
#else
	.ndo_set_multicast_list = NULL,
#endif
	.ndo_change_mtu = wlchangeMtu_mbss,
	.ndo_get_stats = wlgetStats,
};

int wlInit_monif(struct wlprivate *wlp, unsigned char *macAddr)
{
	struct wlprivate *wlpptr = NULL;
	struct net_device *dev;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0)
	dev = alloc_netdev(sizeof(struct wlprivate), DEV_NAME_MON_INTF,
					   NET_NAME_UNKNOWN, wlwlan_setup);
#else
	dev = alloc_netdev(sizeof(struct wlprivate), DEV_NAME_MON_INTF,
					   wlwlan_setup);
#endif
	if (dev)
	{
		wlpptr = NETDEV_PRIV(struct wlprivate, dev);
		NETDEV_PRIV_S(dev) = wlpptr;
	}

	if (wlpptr == NULL)
	{
		printk("%s: no mem for private driver context\n", DRV_NAME);
		goto err_out;
	}
	memset(wlpptr, 0, sizeof(struct wlprivate));
	memcpy(wlpptr, wlp, sizeof(struct wlprivate));
	wlpptr->netDev = dev;
	wlpptr->ioBase0 = wlp->ioBase0;
	wlpptr->ioBase1 = wlp->ioBase1;
	sprintf(wlpptr->netDev->name, "%s%1d%s%1d", DRV_NAME, wlinitcnt,
			DEV_NAME_MON_INTF, 0);
	wlpptr->netDev->irq = wlp->netDev->irq;
	wlpptr->netDev->mem_start = wlp->netDev->mem_start;
	wlpptr->netDev->mem_end = wlp->netDev->mem_end;
	wlpptr->smacStatusAddr = wlp->smacStatusAddr;

	NETDEV_PRIV_S(wlpptr->netDev) = wlpptr;
	SET_MODULE_OWNER(*(wlpptr->netDev));
	memcpy(wlpptr->netDev->dev_addr, &macAddr[0], 6);
	memcpy(&wlpptr->hwData.macAddr[0], &macAddr[0], 6);

	// wlpptr->vmacSta_p = NULL; //no need?
	wlpptr->vmacSta_p =
		Mac_Init((void *)wlp, wlpptr->netDev, &macAddr[0],
				 WL_OP_MODE_MONIF, wlinitcnt);
	if (wlpptr->vmacSta_p == NULL)
	{
		printk(KERN_ERR "%s: failed to init driver mac\n",
			   wlpptr->netDev->name);
		goto err_out;
	}

	wlpptr->netDev->netdev_ops = &wlmonif_netdev_ops;
	wlpptr->netDev->ethtool_ops = &wl_ethtool_ops;
	wlpptr->netDev->watchdog_timeo = 30 * HZ;

#ifdef WLAN_INCLUDE_TSO
	wlpptr->netDev->features |= NETIF_F_TSO;
	wlpptr->netDev->features |= NETIF_F_IP_CSUM;
	wlpptr->netDev->features |= NETIF_F_SG;
#endif
	wlpptr->netDev->needed_headroom = SKB_INFO_SIZE + SKB_RADIOTAP_CHUNK;

	wlpptr->wlreset = wlreset_monif;
	wlSetupWEHdlr(wlpptr->netDev);
	wlpptr->wlpd_p = wlp->wlpd_p;
	wlpptr->master = wlp->netDev;
	printk("[%s] wlinitcnt=%d, vmacIndex=%d\n", __func__, wlinitcnt,
		   wlp->wlpd_p->vmacIndex);
	wlp->vdev[wlp->wlpd_p->vmacIndex++] = wlpptr->netDev;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 6)
#else
	atomic_set(&wlpptr->netDev->refcnt, 0);
#endif
	ether_setup(wlpptr->netDev);

	/* register cfg80211 virtual interface to wiphy wdev */
#ifdef CFG80211
	wlpptr->wdev.wiphy = wlp->wiphy;
	wlpptr->wdev.iftype = NL80211_IFTYPE_MONITOR;
	wlpptr->wdev.netdev = wlpptr->netDev;
	wlpptr->netDev->ieee80211_ptr = &wlpptr->wdev;
	SET_NETDEV_DEV(wlpptr->netDev, wiphy_dev(wlpptr->wdev.wiphy));
#endif
	wlpptr->bgscan_period = DEF_BGSCAN_PERIOD;
	if (register_netdev(wlpptr->netDev))
	{
		printk("%s: failed to register device\n", wlpptr->netDev->name);
		goto err_register_netdev;
	}
	wlpptr->netDev->mtu = wlp->netDev->mtu;
	memcpy(wlpptr->netDev->dev_addr, macAddr, 6);

	WLDBG_EXIT(DBG_LEVEL_2);
	return 0;
err_out:
err_register_netdev:
	wl_kfree(wlpptr);
	WLDBG_EXIT(DBG_LEVEL_2);
	return -EIO;
}
#endif

static const struct net_device_ops wlmbss_netdev_ops = {
	.ndo_open = wlopen_mbss,
	.ndo_stop = wlstop_mbss,
	.ndo_start_xmit = wlDataTx,
	.ndo_do_ioctl = wlIoctl,
	.ndo_set_mac_address = wlsetMacAddr_mbss,
	.ndo_tx_timeout = wltxTimeout_mbss,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 2, 0)
	.ndo_set_rx_mode = wlsetMcList,
#else
	.ndo_set_multicast_list = wlsetMcList,
#endif
	.ndo_change_mtu = wlchangeMtu_mbss,
	.ndo_get_stats = wlgetStats,
};

int wlInit_mbss(struct wlprivate *wlp, unsigned char *macAddr)
{
	//      int retCode;
	struct wlprivate *wlpptr = NULL;
	UINT8 i;
	struct net_device *dev;
	char temp_name[32] = {0};
	int name_len = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0)
	dev = alloc_netdev(sizeof(struct wlprivate), DRV_NAME_VMAC,
					   NET_NAME_UNKNOWN, wlwlan_setup);
#else
	dev = alloc_netdev(sizeof(struct wlprivate), DRV_NAME_VMAC,
					   wlwlan_setup);
#endif
	if (dev)
	{
		wlpptr = NETDEV_PRIV(struct wlprivate, dev);
		NETDEV_PRIV_S(dev) = wlpptr;
	}

	if (wlpptr == NULL)
	{
		printk("%s: no mem for private driver context\n", DRV_NAME);
		goto err_out;
	}
	memset(wlpptr, 0, sizeof(struct wlprivate));
	memcpy(wlpptr, wlp, sizeof(struct wlprivate));
	wlpptr->netDev = dev;

	// from probe
	wlpptr->ioBase0 = wlp->ioBase0;
	wlpptr->ioBase1 = wlp->ioBase1;

	// sprintf(wlpptr->netDev->name, "ap%1d", wlp->wlpd_p->vmacIndex);
	sprintf(temp_name, "%s%1d%s%1d", DRV_NAME, wlinitcnt, DRV_NAME_VMAC,
			wlp->wlpd_p->vmacIndex);
	name_len = strlen(temp_name);

	if (name_len <= IFNAMSIZ)
		memcpy(wlpptr->netDev->name, temp_name, name_len);

	wlpptr->netDev->irq = wlp->netDev->irq;
	wlpptr->netDev->mem_start = wlp->netDev->mem_start;
	wlpptr->netDev->mem_end = wlp->netDev->mem_end;
	NETDEV_PRIV_S(wlpptr->netDev) = wlpptr;
	wlpptr->smacStatusAddr = wlp->smacStatusAddr;

	SET_MODULE_OWNER(*(wlpptr->netDev));

	//      pci_set_drvdata(wlpptr->pPciDev, (wlpptr->netDev));

	// from init
	memcpy(wlpptr->netDev->dev_addr, &macAddr[0], 6);
	memcpy(&wlpptr->hwData.macAddr[0], &macAddr[0], 6);
	wlpptr->vmacSta_p =
		Mac_Init((void *)wlp, wlpptr->netDev, &macAddr[0],
				 WL_OP_MODE_VAP, wlinitcnt);

	if (wlpptr->vmacSta_p == NULL)
	{
		printk(KERN_ERR "%s: failed to init driver mac\n",
			   wlpptr->netDev->name);
		goto err_out;
	}

	memcpy(&wlpptr->vmacSta_p->BFMRconfig.addr[0], &macAddr[0], 6);
	wlpptr->vmacSta_p->BFMRinitstatus.addr_init = 1;

	wlpptr->netDev->netdev_ops = &wlmbss_netdev_ops;
	wlpptr->netDev->ethtool_ops = &wl_ethtool_ops;
	wlpptr->netDev->watchdog_timeo = 30 * HZ;

#ifdef WLAN_INCLUDE_TSO
	wlpptr->netDev->features |= NETIF_F_TSO;
	wlpptr->netDev->features |= NETIF_F_IP_CSUM;
	wlpptr->netDev->features |= NETIF_F_SG;
#endif
	wlpptr->netDev->needed_headroom = SKB_INFO_SIZE + SKB_RADIOTAP_CHUNK;

	wlpptr->wlreset = wlreset_mbss;
	wlSetupWEHdlr(wlpptr->netDev);
	wlpptr->wlpd_p = wlp->wlpd_p;
	wlpptr->master = wlp->netDev;
#ifdef CB_SUPPORT
	wlpptr->is_resp_mgmt = TRUE;
	wlpptr->vap_id = wlp->wlpd_p->vmacIndex;
	// printk("%s(), [%s], vap_id: %u\n", __func__, wlpptr->netDev->name, wlpptr->vap_id);
#endif // #ifdef CB_SUPPORT
	wlp->vdev[wlp->wlpd_p->vmacIndex++] = wlpptr->netDev;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 6)
#else
	atomic_set(&wlpptr->netDev->refcnt, 0);
#endif
	ether_setup(wlpptr->netDev);

	/* register cfg80211 virtual interface to wiphy wdev */
#ifdef CFG80211
	wlpptr->wdev.wiphy = wlp->wiphy;
	wlpptr->wdev.iftype = NL80211_IFTYPE_AP;
	wlpptr->wdev.netdev = wlpptr->netDev;
	wlpptr->netDev->ieee80211_ptr = &wlpptr->wdev;
	SET_NETDEV_DEV(wlpptr->netDev, wiphy_dev(wlpptr->wdev.wiphy));
#endif
	wlpptr->bgscan_period = DEF_BGSCAN_PERIOD;

	if (register_netdev(wlpptr->netDev))
	{
		printk("%s: failed to register device\n", wlpptr->netDev->name);
		goto err_register_netdev;
	}
	ap8x_stat_proc_register(wlpptr->netDev);
	wlpptr->netDev->mtu = wlp->netDev->mtu;
	memcpy(wlpptr->netDev->dev_addr, macAddr, 6);
#ifdef WDS_FEATURE
	wlInit_wds(wlpptr);
#endif

	SPIN_LOCK_INIT(&wlpptr->vmacSta_p->MUStaListLock);

	for (i = 0; i < ARRAY_SIZE(wlpptr->vmacSta_p->MUStaList); i++)
		MUStaListInit((MU_Sta_List *)&wlpptr->vmacSta_p->MUStaList[i]);

	switch (wlpptr->devid)
	{
	case SC4:
		wlpptr->vmacSta_p->MUSet_Prefer_UsrCnt = 3;
		break;
	case SC5:
		wlpptr->vmacSta_p->MUSet_Prefer_UsrCnt = 7;
		break;
	case SCBT:
		wlpptr->vmacSta_p->MUSet_Prefer_UsrCnt = 3;
		break;
	default:
		wlpptr->vmacSta_p->MUSet_Prefer_UsrCnt = 3;
	}

	ap8xLnxStat_vap_init(dev);

#ifdef WIFI_DATA_OFFLOAD
	if (!wlpptr->wlpd_p->dol.vif_added_to_pe[wlpptr->vmacSta_p->VMacEntry.macId])
	{
		dol_add_vif(wlpptr, wlpptr->wlpd_p->ipc_session_id,
					wlpptr->vmacSta_p->VMacEntry.macId, &macAddr[0]);
		wlpptr->wlpd_p->dol.vif_added_to_pe[wlpptr->vmacSta_p->VMacEntry.macId] = 1;
	}
#endif

	WLDBG_EXIT(DBG_LEVEL_2);
	return 0;
err_out:
err_register_netdev:
	wl_kfree(wlpptr);
	WLDBG_EXIT(DBG_LEVEL_2);
	return -EIO;
}

void wlDeinit_mbss(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate *wlp;
	int i;

	WLDBG_ENTER(DBG_LEVEL_2);
#ifdef SOC_W906X
	if (wlpptr->wlpd_p->downloadSuccessful == TRUE)
#endif /* SOC_W906X */
	{
		SendResetCmd(wlpptr->vmacSta_p, 1);
	}
#if defined(SINGLE_DEV_INTERFACE) && !defined(CLIENTONLY)
	for (i = 1; i < wlpptr->wlpd_p->vmacIndex; i++)
#else
	for (i = 0; i < wlpptr->wlpd_p->vmacIndex; i++)
#endif
	{
#ifdef WIFI_DATA_OFFLOAD
		if (wlpptr->wlpd_p->dol.vif_added_to_pe[wlpptr->vmacSta_p->VMacEntry.macId])
		{
			dol_del_vif(wlpptr, wlpptr->wlpd_p->ipc_session_id,
						wlpptr->vmacSta_p->VMacEntry.macId);
			wlpptr->wlpd_p->dol.vif_added_to_pe[wlpptr->vmacSta_p->VMacEntry.macId] =
				0;
		}
#endif
		wds_wlDeinit(wlpptr->vdev[i]);
		if (wlpptr->vdev[i]->flags & IFF_RUNNING)
		{
			if (wlstop_mbss(wlpptr->vdev[i]))
			{
				printk(KERN_ERR "%s: failed to stop device\n",
					   wlpptr->vdev[i]->name);
			}
		}
		wlp = NETDEV_PRIV_P(struct wlprivate, wlpptr->vdev[i]);
		DisableMacMgmtTimers(wlp->vmacSta_p);
		MacMgmtMemCleanup(wlp->vmacSta_p);
		wlDestroySysCfg(wlp->vmacSta_p);
		ap8xLnxStat_vap_exit(wlpptr->vdev[i]);
		wlp->vmacSta_p = NULL;
		ap8x_stat_proc_unregister(wlpptr->vdev[i]);
		unregister_netdev(wlpptr->vdev[i]);
		free_netdev(wlpptr->vdev[i]);
	}
	wlpptr->wlpd_p->vmacIndex = 0;
	WLDBG_EXIT(DBG_LEVEL_2);
	return;
}

int wlResetTask(struct net_device *dev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);

	if (wlpptr->wlpd_p->inResetQ)
		return 0;
	wlpptr->wlpd_p->inResetQ = TRUE;
	schedule_work(&wlpptr->wlpd_p->resettask);
	return 0;
}

#ifdef CLIENT_SUPPORT
/* Temporary declaration until suitable MIBs is made available */
UINT8 tmpClientBSSID[NUM_OF_WLMACS][6] = {{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};

void wlLinkMgt(struct net_device *netdev, UINT8 phyIndex)
{
	UINT8 ieBuf[256];
	UINT16 ieBufLen = 0;
	UINT8 ssidLen;
	UINT8 chnlListLen = 0;
	UINT8 chnlScanList[IEEEtypes_MAX_CHANNELS + IEEEtypes_MAX_CHANNELS_A];
	UINT8 currChnlIndex = 0;
	UINT8 i;
	IEEEtypes_InfoElementHdr_t *IE_p;
	vmacApInfo_t *vmacSta_p, *primary_vmacSta_p;
	MIB_802DOT11 *mib, *primary_mib;
	struct wlprivate *wlMPrvPtr = NULL, *wlSPrvPtr = NULL;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	MIB_PHY_DSSS_TABLE *PhyDSSSTable;
	UINT8 mainChnlList[IEEEtypes_MAX_CHANNELS + IEEEtypes_MAX_CHANNELS_A];

	vmacStaInfo_t *vStaInfo_p;

	vStaInfo_p =
		(vmacStaInfo_t *)vmacGetVMacStaInfo(parentGetVMacId(phyIndex));
	if (!vStaInfo_p)
		return;

	memset(&chnlScanList[0], 0,
		   (IEEEtypes_MAX_CHANNELS + IEEEtypes_MAX_CHANNELS_A));
	memset(&vStaInfo_p->linkInfo, 0, sizeof(iw_linkInfo_t));

	/* Get VMAC structure of the master and host client. */
	if (wlpptr->master)
	{
		/* Get Primary info. */
		wlMPrvPtr = NETDEV_PRIV_P(struct wlprivate, wlpptr->master);
		primary_vmacSta_p = wlMPrvPtr->vmacSta_p;
		/* primary MIB used for channel settings, client only comes up after AP apply settings */
		primary_mib = primary_vmacSta_p->Mib802dot11;

		/* Get host Client info. */
		wlSPrvPtr = NETDEV_PRIV_P(struct wlprivate, wlpptr->netDev);
		vmacSta_p = wlSPrvPtr->vmacSta_p;
		mib = vmacSta_p->Mib802dot11;
	}
	else
		return;
	/* Setup the mode,filter registers appropriate for station operation */
	Disable_extStaDb_ProcessKeepAliveTimer(primary_vmacSta_p);
	Disable_MonitorTimerProcess(primary_vmacSta_p);

	extStaDb_ProcessKeepAliveTimerInit(primary_vmacSta_p);
	MonitorTimerInit(primary_vmacSta_p);

	PhyDSSSTable = mib->PhyDSSSTable;

	/* Pass the channel list */
	/* if autochannel is enabled then pass in the channel list */
	/* else if autochannel is disabled only pass in a single ch */
	if (*(primary_mib->mib_autochannel))
	{
		/* Stop Autochannel on AP first */
		StopAutoChannel(primary_vmacSta_p);

		/* get range to scan */
		domainGetInfo(mainChnlList);

		if (*(vmacSta_p->Mib802dot11->mib_STAMode) == CLIENT_MODE_AUTO)
		{ // ||
			//(*(vmacSta_p->Mib802dot11->mib_STAMode) == CLIENT_MODE_N))
			for (i = 0; i < IEEEtypes_MAX_CHANNELS; i++)
			{
				if (mainChnlList[i] > 0)
				{
					chnlScanList[currChnlIndex] =
						mainChnlList[i];
					currChnlIndex++;
				}
			}

			for (i = 0; i < IEEEtypes_MAX_CHANNELS_A; i++)
			{
				if (mainChnlList[i + IEEEtypes_MAX_CHANNELS] >
					0)
				{
					chnlScanList[currChnlIndex] =
						mainChnlList[i +
									 IEEEtypes_MAX_CHANNELS];
					currChnlIndex++;
				}
			}
			chnlListLen = currChnlIndex;
		}
		else if ((*(vmacSta_p->Mib802dot11->mib_STAMode) <
				  CLIENT_MODE_A) ||
				 (*(vmacSta_p->Mib802dot11->mib_STAMode) ==
				  CLIENT_MODE_N_24))
		{
			for (i = 0; i < IEEEtypes_MAX_CHANNELS; i++)
			{
				chnlScanList[i] = mainChnlList[i];
			}
			chnlScanList[i] = 0;
			chnlListLen = IEEEtypes_MAX_CHANNELS;
		}
		else
		{
			for (i = 0; i < IEEEtypes_MAX_CHANNELS_A; i++)
			{
				chnlScanList[i] =
					mainChnlList[i +
								 IEEEtypes_MAX_CHANNELS];
			}
			chnlScanList[i] = 0;
			chnlListLen = IEEEtypes_MAX_CHANNELS_A;
		}
	}
	else
	{
		chnlScanList[0] = PhyDSSSTable->CurrChan;
		chnlListLen = 1;
	}

	/* Set the first channel */
	mlmeApiSetRfChannel(vStaInfo_p, chnlScanList[0], 1, TRUE);

	ieBufLen = 0;
	/* Build IE Buf */
	IE_p = (IEEEtypes_InfoElementHdr_t *)&ieBuf[ieBufLen];

	/* SSID element */
	/* Pick SSID from station net device */
#ifdef RSN_RESOLVE
	strncpy((char *)&tmpClientSSID[phyIndex][0],
			(const char *)&(mib->StationConfig->DesiredSsId[0]), 32);
#endif /* RSN_RESOLVE */
	ssidLen = strlen((const char *)&(mib->StationConfig->DesiredSsId[0]));
	IE_p->ElementId = SSID;
	IE_p->Len = ssidLen;
	ieBufLen += sizeof(IEEEtypes_InfoElementHdr_t);
	strncpy((char *)&ieBuf[ieBufLen],
			(const char *)&(mib->StationConfig->DesiredSsId[0]), 32);
	ieBufLen += IE_p->Len;
	IE_p = (IEEEtypes_InfoElementHdr_t *)&ieBuf[ieBufLen];

	/* DS_PARAM_SET element */
	IE_p->ElementId = DS_PARAM_SET;
	IE_p->Len = chnlListLen;
	ieBufLen += sizeof(IEEEtypes_InfoElementHdr_t);
	memcpy((char *)&ieBuf[ieBufLen], &chnlScanList[0], chnlListLen);
	ieBufLen += IE_p->Len;
	IE_p = (IEEEtypes_InfoElementHdr_t *)&ieBuf[ieBufLen];

	// link Mgt might need a MIBs to control funct call
#ifdef RSN_RESOLVE
	defaultKeyMgmtInit(phyIndex);
#endif

#ifdef MRVL_WPS_CLIENT
	if (!is_zero_ether_addr(mib->StationConfig->DesiredBSSId))
		memcpy(&tmpClientBSSID[phyIndex][0],
			   &(mib->StationConfig->DesiredBSSId[0]), 6);
#endif
	/* If user initiated a scan and it is in progress then do not start link mgt */
	if (((vmacApInfo_t *)(wlpptr->vmacSta_p))->gUserInitScan != TRUE)
		linkMgtStart(phyIndex, &tmpClientBSSID[phyIndex][0], &ieBuf[0],
					 ieBufLen);
}

void wlInitClientLink(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p;
	MIB_802DOT11 *mib;

	/* Get VMAC structure of the client.                       */
	/* If master pointer zero, then this is the master device. */
	if (wlpptr->master)
	{
		vmacSta_p = wlpptr->vmacSta_p;
		mib = vmacSta_p->Mib802dot11;
		// set wdev0 OpMode to follow wdev0staX's opmode
		vmacSta_p->master->OpMode = vmacSta_p->OpMode;
	}
	else
	{
		// printk("wlInitClientLink: ERROR -cannot get master mib from netdev = %x \n", netdev);
		return;
	}

	if (!(*(mib->mib_STAMacCloneEnable) == 1))
	{
		vmacEntry_t *vmacEntry_p;
		if ((vmacEntry_p =
				 sme_GetParentVMacEntry(vmacSta_p->VMacEntry.phyHwMacIndx)) != NULL)
		{
			wlFwSetMacAddr_Client(netdev,
								  &vmacEntry_p->vmacAddr[0]);
		}
		wlLinkMgt(netdev, vmacSta_p->VMacEntry.phyHwMacIndx);
	}
}

void wlUpdateMibsWithBssProfile(struct wlprivate *wlpptr, vmacStaInfo_t *vStaInfo_p)
{
	UINT32 ch_bw_changed_to = 0;
	MIB_802DOT11 *mib = wlpptr->vmacSta_p->ShadowMib802dot11;

	if (IsVHTmode(*(mib->mib_ApMode)))
	{

		if (vStaInfo_p->bssDescProfile_p->VHTOp.len)
		{
			if (vStaInfo_p->bssDescProfile_p->VHTOp.ch_width == 2)
			{
				ch_bw_changed_to = CH_160_MHz_WIDTH;
			}
			else if (vStaInfo_p->bssDescProfile_p->VHTOp.ch_width == 1)
			{

#ifdef SUPPORTED_EXT_NSS_BW
				int ret = 0;
				printk("%s ", __FUNCTION__);

				if (1 ==
					(ret =
						 isSupport160MhzByCenterFreq(wlpptr,
													 VHT_EXTENDED_NSS_BW_CAPABLE,
													 vStaInfo_p->bssDescProfile_p->VHTOp.center_freq0,
													 vStaInfo_p->bssDescProfile_p->VHTOp.center_freq1,
													 vStaInfo_p->bssDescProfile_p->ADDHTElement.OpMode.center_freq2)))
				{

					ch_bw_changed_to = CH_160_MHz_WIDTH;
				}
				else if (0 == ret)
				{

					ch_bw_changed_to = CH_80_MHz_WIDTH;
					printk("80MHz or less\n");
				}
#else
				if (vStaInfo_p->bssDescProfile_p->VHTOp.center_freq1 == 0)
				{
					ch_bw_changed_to = CH_80_MHz_WIDTH;
				}
				else
				{
					UINT8 diff;
					if (vStaInfo_p->bssDescProfile_p->VHTOp.center_freq1 >
						vStaInfo_p->bssDescProfile_p->VHTOp.center_freq0)
					{
						diff = vStaInfo_p->bssDescProfile_p->VHTOp.center_freq1 -
							   vStaInfo_p->bssDescProfile_p->VHTOp.center_freq0;
					}
					else
					{
						diff = vStaInfo_p->bssDescProfile_p->VHTOp.center_freq0 -
							   vStaInfo_p->bssDescProfile_p->VHTOp.center_freq1;
					}
					if (diff == 8)
					{
						ch_bw_changed_to =
							CH_160_MHz_WIDTH;
					}
					else if (diff > 8)
					{
#ifdef SOC_W906X
						isSupport80plus80Mhz(wlpptr);
#else
						WLDBG_ERROR(DBG_LEVEL_1,
									"80MHz + 80MHz, not support\n");
#endif
					}
					else
					{
						printk("%s reserved\n",
							   __FUNCTION__);
					}
				}
#endif /* SUPPORTED_EXT_NSS_BW */
			}
			else
			{
				if (vStaInfo_p->bssDescProfile_p->HTElement.HTCapabilitiesInfo.SupChanWidth)
					ch_bw_changed_to = CH_40_MHz_WIDTH;
				else
					ch_bw_changed_to = CH_20_MHz_WIDTH;
			}
		}
		else
		{
			if (vStaInfo_p->bssDescProfile_p->HTElement.HTCapabilitiesInfo.SupChanWidth)
				ch_bw_changed_to = CH_40_MHz_WIDTH;
			else
				ch_bw_changed_to = CH_20_MHz_WIDTH;
		}
		if (ch_bw_changed_to)
		{
			if (mib->PhyDSSSTable->Chanflag.ChnlWidth ==
				CH_AUTO_WIDTH)
			{
				wlpptr->wlpd_p->repeaterUpdateChannelWidth =
					ch_bw_changed_to;
			}
			else if (mib->PhyDSSSTable->Chanflag.ChnlWidth >
					 ch_bw_changed_to)
			{
				wlpptr->wlpd_p->repeaterUpdateChannelWidth =
					ch_bw_changed_to;
			}
		}
	}
}

extern int WlLoadRateGrp(struct net_device *netdev);
/* Client Parent Session Callback function */
void wlStatusUpdate_clientParent(UINT32 data1, UINT8 *info_p, UINT32 data2)
{
	UINT32 statusId = data1;
	UINT32 linkUp = data2;
	vmacEntry_t *vmacEntry_p = (vmacEntry_t *)info_p;
	struct net_device *dev_p;
	struct wlprivate *priv;
	UINT8 mlmeAssociatedFlag;
	UINT8 mlmeBssid[6];
	UINT8 numDescpt = 0;
	UINT8 *buf_p;
	UINT16 bufSize = MAX_SCAN_BUF_SIZE;
	MIB_802DOT11 *mib = NULL;
	vmacApInfo_t *vmacSta_p = NULL;

	if (info_p == NULL)
	{
		return;
	}
	dev_p = (struct net_device *)vmacEntry_p->privInfo_p;
	priv = NETDEV_PRIV_P(struct wlprivate, dev_p);
	mib = priv->vmacSta_p->Mib802dot11;
	vmacSta_p = priv->vmacSta_p;
	switch (statusId)
	{
	case MmgtIndicationSignals:
		if (!smeGetStaLinkInfo(vmacEntry_p->id,
							   &mlmeAssociatedFlag, &mlmeBssid[0]))
		{
			return;
		}

		if (linkUp && mlmeAssociatedFlag)
		{

			wlFwSetAid(dev_p, mlmeBssid, 0);

			printk("**** %s: LINK UP to %02x%02x%02x%02x%02x%02x\n",
				   dev_p->name, mlmeBssid[0], mlmeBssid[1],
				   mlmeBssid[2], mlmeBssid[3], mlmeBssid[4],
				   mlmeBssid[5]);

#ifdef MRVL_WPS_CLIENT
			/* Send event to user space */
			WLSNDEVT(dev_p, IWEVREGISTERED, &mlmeBssid, NULL);
#ifdef CFG80211
#ifdef CFG80211_COMPATIABLE
			mwl_cfg80211_connect_result_event(dev_p,
											  (uint8_t *)&mlmeBssid,
											  WLAN_STATUS_SUCCESS);
#else
#ifdef SOC_W906X
			mwl_cfg80211_connect_result_event(dev_p,
											  (uint8_t *)&mlmeBssid,
											  WLAN_STATUS_SUCCESS);
#else
			mwl_send_vendor_assoc_event(dev_p,
										(uint8_t *)&mlmeBssid);
#endif // SOC_W906X
#endif /* CFG80211_COMPATIABLE */
#endif /* CFG80211 */
#endif
			WLSYSLOG(dev_p, WLSYSLOG_CLASS_ALL,
					 WLSYSLOG_MSG_CLIENT_CONNECTED
					 "%02x%02x%02x%02x%02x%02x\n",
					 mlmeBssid[0],
					 mlmeBssid[1], mlmeBssid[2], mlmeBssid[3],
					 mlmeBssid[4], mlmeBssid[5]);

#ifndef MRVL_WPS_CLIENT
			WLSNDEVT(dev_p, IWEVCUSTOM, &vmacEntry_p->vmacAddr,
					 WLSYSLOG_MSG_CLIENT_CONNECTED);
#endif
			memcpy(priv->hwData.macAddr, mlmeBssid, 6);

			if (WlLoadRateGrp(dev_p))
			{
				WLDBG_WARNING(DBG_LEVEL_0,
							  "set per rate power fail");
			}
			/* If Mac cloneing disabled, set vmacEntry to active here. */
			if (!(*(mib->mib_STAMacCloneEnable) == 1))
				vmacEntry_p->active = 1;
			wlUpdateMibsWithBssProfile(priv,
									   (vmacStaInfo_t *)
										   vmacEntry_p->info_p);
		}
		else
		{
			priv->wlpd_p->repeaterUpdateChannelWidth = 0;
			printk("**** %s: LINK NOT UP\n", dev_p->name);
#ifdef WPA_STA
			/* Verify that Key timer is disabled. */
			sme_DisableKeyMgmtTimer(vmacEntry_p);
#endif /* WPA_STA */

#if 1 // enable if you want to use link mgt to connect
			/* do not restart linkmgt if user started a scan */
			/* scan complete will trigger a link Mgt restart */
			if (vmacSta_p->gUserInitScan != TRUE)
				linkMgtReStart(vmacEntry_p->phyHwMacIndx,
							   vmacEntry_p);
#endif // end link mgt

			if (*(mib->mib_STAMacCloneEnable) == 2)
				ethStaDb_RemoveAllStns(vmacSta_p);

			/* Remove client and remote ap from Fw and driver databases. */
			RemoveRemoteAPFw((UINT8 *)&mlmeBssid[0], vmacEntry_p);
			WLSYSLOG(dev_p, WLSYSLOG_CLASS_ALL,
					 WLSYSLOG_MSG_CLIENT_DISCONNECTED);

#ifndef MRVL_WPS_CLIENT
			WLSNDEVT(dev_p, IWEVCUSTOM, &vmacEntry_p->vmacAddr,
					 WLSYSLOG_MSG_CLIENT_DISCONNECTED);
#endif
#ifdef MRVL_WPS_CLIENT
			/* Send event to user space */
			if ((mlmeBssid[0] && mlmeBssid[1] && mlmeBssid[2] &&
				 mlmeBssid[3] && mlmeBssid[4] && mlmeBssid[5]))
			{
				WLSNDEVT(dev_p, IWEVEXPIRED,
						 (IEEEtypes_MacAddr_t *)&mlmeBssid[0],
						 NULL);
#ifdef CFG80211
#ifdef CFG80211_COMPATIABLE
				mwl_cfg80211_connect_result_event(dev_p,
												  (uint8_t *)&mlmeBssid,
												  WLAN_STATUS_UNSPECIFIED_FAILURE);
#else
#ifdef SOC_W906X
				mwl_cfg80211_connect_result_event(dev_p,
												  (uint8_t *)&mlmeBssid,
												  WLAN_STATUS_UNSPECIFIED_FAILURE);
#else
				mwl_send_vendor_disassoc_event(dev_p,
											   (uint8_t *)&mlmeBssid[0]);
#endif // SOC_W906X
#endif /* CFG80211_COMPATIABLE */
#endif /* CFG80211 */
			}
#endif

			memset(priv->hwData.macAddr, 0, 6);
		}
		break;

	case MlmeScan_Cnfm:
		/* If enable IEEE80211K, log will be printed frequently */
		//              printk("***** %s SCAN completed\n", dev_p->name);

		//              WLSYSLOG(dev_p, WLSYSLOG_CLASS_ALL, WLSYSLOG_MSG_CLIENT_SCAN_DONE);

#ifdef WMON
		if (!gScan)
#endif
		{
			/* If user initiated a scan */
			if (vmacSta_p->gUserInitScan == TRUE)
			{
				vmacSta_p->gUserInitScan = FALSE;

#ifdef MRVL_WPS_CLIENT
				/* Send event to user space */
				WLSNDEVT(dev_p, IWEVCUSTOM,
						 &vmacEntry_p->vmacAddr,
						 WLSYSLOG_MSG_CLIENT_SCAN_DONE);
#endif

				/* handle the case where a scan completed and link management restarted */
				if (smeGetScanResults(vmacEntry_p->phyHwMacIndx, &numDescpt,
									  &bufSize, &buf_p) == MLME_SUCCESS)
				{
					tmpNumScanDesc[vmacEntry_p->phyHwMacIndx] =
						numDescpt;
					if (numDescpt > 0)
					{
						memset(tmpScanResults
								   [vmacEntry_p->phyHwMacIndx],
							   0,
							   MAX_SCAN_BUF_SIZE);
						memcpy(tmpScanResults
								   [vmacEntry_p->phyHwMacIndx],
							   buf_p,
							   bufSize);
					}
				}

				/* reset the busy scanning flag */
				priv->vmacSta_p->busyScanning = 0;

				/*Restart link management */
				if (dev_p->flags & IFF_RUNNING)
				{
					smeGetStaLinkInfo(vmacEntry_p->id,
									  &mlmeAssociatedFlag,
									  &mlmeBssid[0]);

					if (mlmeAssociatedFlag)
					{
#ifdef AMPDU_SUPPORT_TX_CLIENT
						cleanupAmpduTx(vmacSta_p,
									   (UINT8 *)&mlmeBssid[0]);
#endif
						linkMgtReStart(vmacEntry_p->phyHwMacIndx,
									   vmacEntry_p);
					}
					else
					{
						if (*(mib->mib_STAAutoScan))
						{
#ifndef MRVL_WPS_CLIENT
							wlLinkMgt(dev_p,
									  vmacEntry_p->phyHwMacIndx);
#endif
						}
					}
				}
#ifndef OFFCHANNEL_SUPPORT
#ifdef IEEE80211K
				/* update neighbor report list */
				MSAN_update_neighbor_list(dev_p);
#endif // IEEE80211K
#endif // OFFCHANNEL_SUPPORT
			}
			else
			{
				// linkMgtParseScanResult() might need a MIBs to control funct call
				linkMgtParseScanResult(vmacEntry_p->phyHwMacIndx);
			}
		}
		break;
	case MlmeReset_Cnfm:
	{
		struct net_device *apdev_p = priv->master;
		struct wlprivate *appriv =
							 NETDEV_PRIV_P(struct wlprivate, apdev_p),
						 *appriv1;
		vmacApInfo_t *vap_p;
		int i;
		for (i = 0; i < appriv->wlpd_p->vmacIndex; i++)
		{
			appriv1 =
				NETDEV_PRIV_P(struct wlprivate,
							  appriv->vdev[i]);
			vap_p = appriv1->vmacSta_p;
			if ((appriv->vdev[i]->flags & IFF_RUNNING) &&
				(vap_p->VMacEntry.modeOfService ==
				 VMAC_MODE_AP))
				wlreset_mbss(appriv->vdev[i]);
		}
	}
	break;
	default:
		break;
	}
}

int wlopen_client(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	MIB_802DOT11 *mib;
#ifdef CFG80211
	struct wlprivate *wiphy_priv =
		mwl_cfg80211_get_priv(wlpptr->wdev.wiphy);
#endif
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;

	//      wlfacilitate_e radioOnOff = WL_ENABLE ;

	WLDBG_ENTER(DBG_LEVEL_2);

	if ((wlpptr->devid == SC5 || wlpptr->devid == SCBT) &&
		vmacSta_p->VMacEntry.macId == (bss_num - 1) &&
		wlpd_p->SharedBssState == SHARE_VAP)
	{
		printk("BSS_%u alreay occupied by VAP\n",
			   vmacSta_p->VMacEntry.macId);
		return -EIO;
	}

	netdev->type = ARPHRD_ETHER;

#ifdef CFG80211
	if (wiphy_priv->request)
	{
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 7, 0)
		struct cfg80211_scan_info info = {
			.aborted = true,
		};

		cfg80211_scan_done(wiphy_priv->request, &info);
#else
		cfg80211_scan_done(wiphy_priv->request, 1);
#endif
		WLDBG_INFO(DBG_LEVEL_2, "aborting scan on wlopen_client\n");
		wiphy_priv->request = NULL;
	}
#endif

	if (netdev->flags & IFF_RUNNING)
	{
		vmacSta_p->InfUpFlag = 0;
		netif_stop_queue(netdev);
		netdev->flags &= ~IFF_RUNNING;
	}
#ifdef WFA_TKIP_NEGATIVE
	if (wlValidateSettings(netdev))
		return -EIO;
#endif

	wlFwApplyClientSettings(netdev);

#ifdef SOC_W906X
	mib = vmacSta_p->Mib802dot11;
	if (!(*(mib->mib_STAMacCloneEnable) == 1))
	{
		if (wlFwSetBssForClientMode(netdev, WL_ENABLE))
		{
			WLDBG_ERROR(DBG_LEVEL_0,
						"Falied to start the %d"
						"th BSS for client mode\n",
						vmacSta_p->VMacEntry.macId);
			return -EIO;
		}
	}
#endif /* SOC_W906X */

	netif_wake_queue(netdev); /* Start/Restart Q if stopped. */
	vmacSta_p->InfUpFlag = 1;
	netdev->flags |= IFF_RUNNING;
	WL_MOD_INC_USE(THIS_MODULE, return -EIO);

	if ((wlpptr->devid == SC5 || wlpptr->devid == SCBT) &&
		vmacSta_p->VMacEntry.macId == (bss_num - 1))
		wlpd_p->SharedBssState = SHARE_STA;

	/* Wireless Client Specific */
	{
		// Moved to ieee80211_encapSta for Client auto connect.
		// wlLinkMgt(netdev, vmacEntry_p->phyHwMacIndx);
		wlInitClientLink(netdev);
	}
	/* end Wireless Client Specific */
	WLDBG_EXIT(DBG_LEVEL_2);
	return 0;
}

static int
wlstop_client(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacEntry_t *vmacParentEntry_p =
		(vmacEntry_t *)wlpptr->clntParent_priv_p;
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
#ifdef CFG80211
	struct wlprivate *wiphy_priv =
		mwl_cfg80211_get_priv(wlpptr->wdev.wiphy);
#endif
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;

	WLDBG_ENTER(DBG_LEVEL_2);
	vmacSta_p->InfUpFlag = 0;

	/* Wireless Client Specific */
	// linkMgtStop() might need a MIBs to control funct call
	linkMgtStop(vmacParentEntry_p->phyHwMacIndx);

	if (vmacParentEntry_p->active)
	{
		smeStopBss(vmacParentEntry_p->phyHwMacIndx);
	}
#ifdef SOC_W906X
	if ((wlpd_p->downloadSuccessful == TRUE) &&
		wlFwSetBssForClientMode(netdev, WL_DISABLE))
	{
		WLDBG_ERROR(DBG_LEVEL_0,
					"Falied to stop the %d"
					"th BSS for client mode\n",
					vmacSta_p->VMacEntry.macId);
		return -EIO;
	}
#endif /* SOC_W906X */

	vmacParentEntry_p->active = 0;
	/* end Wireless Client Specific */

#ifdef CFG80211
	if (wiphy_priv->request)
	{
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 7, 0)
		struct cfg80211_scan_info info = {
			.aborted = true,
		};

		cfg80211_scan_done(wiphy_priv->request, &info);
#else
		cfg80211_scan_done(wiphy_priv->request, 1);
#endif
		WLDBG_INFO(DBG_LEVEL_2, "aborting scan on wlstop_client\n");
		wiphy_priv->request = NULL;
	}
#endif

	if (netdev->flags & IFF_RUNNING)
	{
		netif_stop_queue(netdev);
		netdev->flags &= ~IFF_RUNNING;
	}

	if ((wlpptr->devid == SC5 || wlpptr->devid == SCBT) &&
		vmacSta_p->VMacEntry.macId == (bss_num - 1) &&
		wlpd_p->SharedBssState == SHARE_STA)
		wlpd_p->SharedBssState = SHARE_NONE;

	WL_MOD_DEC_USE(THIS_MODULE);
	WLDBG_EXIT(DBG_LEVEL_2);
	return 0;
}

int wlreset_client(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacEntry_t *vmacParentEntry_p =
		(vmacEntry_t *)wlpptr->clntParent_priv_p;
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
#ifdef CFG80211
	struct wlprivate *wiphy_priv =
		mwl_cfg80211_get_priv(wlpptr->wdev.wiphy);
#endif

	WLDBG_ENTER(DBG_LEVEL_2);

	if (wlpptr->wlpd_p->inReset)
	{
		return 0;
	}

	/* Wireless Client Specific */
	// printk("********  wlreset_client\n");
	smeStopBss(vmacParentEntry_p->phyHwMacIndx);
	/* end Wireless Client Specific */

#ifdef CFG80211
	if (wiphy_priv->request)
	{
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 7, 0)
		struct cfg80211_scan_info info = {
			.aborted = true,
		};

		cfg80211_scan_done(wiphy_priv->request, &info);
#else
		cfg80211_scan_done(wiphy_priv->request, 1);
#endif
		WLDBG_INFO(DBG_LEVEL_2, "aborting scan on wlreset_client\n");
		wiphy_priv->request = NULL;
	}
#endif

	if (netdev->flags & IFF_RUNNING)
	{
		vmacSta_p->InfUpFlag = 0;
		netif_stop_queue(netdev);
		netdev->flags &= ~IFF_RUNNING;

#ifdef MULTI_AP_SUPPORT
		FourAddr_ClearHashEntrySTA();
#endif
	}
	wlFwApplyClientSettings(netdev);

#ifdef SOC_W906X
	if ((!(*(vmacSta_p->Mib802dot11->mib_STAMacCloneEnable) == 1)) &&
		(wlpptr->wlpd_p->downloadSuccessful == TRUE) &&
		/* check SharedBssState to avoid ERROR return from FW */
		(wlpptr->wlpd_p->SharedBssState == SHARE_NONE))
	{
		if (wlFwSetBssForClientMode(netdev, WL_ENABLE))
		{
			WLDBG_ERROR(DBG_LEVEL_0,
						"Falied to start the %d"
						"th BSS for client mode\n",
						vmacSta_p->VMacEntry.macId);
			return -EIO;
		}
	}
#endif /* SOC_W906X */

	netif_wake_queue(netdev); /* restart Q if interface was running */
	vmacSta_p->InfUpFlag = 1;
	netdev->flags |= IFF_RUNNING;

	wlInitClientLink(netdev);
	WLDBG_EXIT(DBG_LEVEL_2);
	return 0;
}

static void
wltxTimeout_client(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);

	WLDBG_ENTER(DBG_LEVEL_2);

	if (wlpptr->wlpd_p->inReset)
	{
		return;
	}

	wlreset_client(netdev);
	WLDBG_EXIT(DBG_LEVEL_2);
}

static int
wlsetMacAddr_client(struct net_device *netdev, void *addr)
{
	struct sockaddr *macAddr = (struct sockaddr *)addr;

	WLDBG_ENTER(DBG_LEVEL_2);
	if (is_valid_ether_addr(macAddr->sa_data))
	{
		memcpy(netdev->dev_addr, addr, 6);
		WLDBG_EXIT(DBG_LEVEL_2);
		return 0;
	}
	WLDBG_EXIT_INFO(DBG_LEVEL_2, "invalid addr");
	return -EADDRNOTAVAIL;
}

static int
wlchangeMtu_client(struct net_device *netdev, int mtu)
{
	WLDBG_ENTER(DBG_LEVEL_2);
	netdev->mtu = mtu;
	if (netdev->flags & IFF_RUNNING)
	{
		WLDBG_EXIT(DBG_LEVEL_2);
		return (wlreset_client(netdev));
	}
	else
		WLDBG_EXIT(DBG_LEVEL_2);
	return -EPERM;
	WLDBG_EXIT(DBG_LEVEL_2);
	return 0;
}

static const struct net_device_ops wlclient_netdev_ops = {
	.ndo_open = wlopen_client,
	.ndo_stop = wlstop_client,
	.ndo_start_xmit = wlDataTx,
	.ndo_do_ioctl = wlIoctl,
	.ndo_set_mac_address = wlsetMacAddr_client,
	.ndo_tx_timeout = wltxTimeout_client,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 2, 0)
	.ndo_set_rx_mode = wlsetMcList,
#else
	.ndo_set_multicast_list = wlsetMcList,
#endif
	.ndo_change_mtu = wlchangeMtu_client,
	.ndo_get_stats = wlgetStats,
};

int wlInit_client(struct wlprivate *wlp, unsigned char *macAddr_p,
				  unsigned char *ApRootmacAddr_p)
{
	struct wlprivate *wlpptr = NULL;
	vmacEntry_t *clientVMacEntry_p;
	struct net_device *dev;

	/* end Wireless Client Specific */
	WLDBG_ENTER(DBG_LEVEL_2);
	{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0)
		dev = alloc_netdev(sizeof(struct wlprivate), DRV_NAME_CLIENT,
						   NET_NAME_UNKNOWN, wlwlan_setup);
#else
		dev = alloc_netdev(sizeof(struct wlprivate), DRV_NAME_CLIENT,
						   wlwlan_setup);
#endif
		if (dev)
		{
			wlpptr = NETDEV_PRIV(struct wlprivate, dev);
			NETDEV_PRIV_S(dev) = wlpptr;
		}

		if (wlpptr == NULL)
		{
			printk("%s: no mem for private driver context\n",
				   DRV_NAME);
			goto err_out;
		}
		memset(wlpptr, 0, sizeof(struct wlprivate));
		memcpy(wlpptr, wlp, sizeof(struct wlprivate));
		wlpptr->netDev = dev;
		wlpptr->netDev->flags = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 6)
		wlpptr->netDev->priv_flags = 0;
#else
		wlpptr->netDev->br_port = NULL;
#endif
		// from probe
		wlpptr->ioBase0 = wlp->ioBase0;
		wlpptr->ioBase1 = wlp->ioBase1;
		// sprintf(wlpptr->netDev->name, wlp->netDev->name);
		sprintf(wlpptr->netDev->name, "%s%1d%s%1d", DRV_NAME, wlinitcnt,
				DRV_NAME_CLIENT, 0);
		wlpptr->netDev->irq = wlp->netDev->irq;
		wlpptr->netDev->mem_start = wlp->netDev->mem_start;
		wlpptr->netDev->mem_end = wlp->netDev->mem_end;
		wlpptr->netDev->needed_headroom = SKB_INFO_SIZE;
		NETDEV_PRIV_S(wlpptr->netDev) = wlpptr;
		wlpptr->smacStatusAddr = wlp->smacStatusAddr;

		SET_MODULE_OWNER(*(wlpptr->netDev));

		/* Use the same address as root AP for stations. */
		memcpy(wlpptr->netDev->dev_addr, ApRootmacAddr_p, 6);
		memcpy(&wlpptr->hwData.macAddr[0], macAddr_p, 6);
		wlpptr->vmacSta_p =
			Mac_Init(wlp, wlpptr->netDev, macAddr_p,
					 WL_OP_MODE_VSTA, wlinitcnt);

		if (wlpptr->vmacSta_p == NULL)
		{
			printk(KERN_ERR "%s: failed to init driver mac\n",
				   wlpptr->netDev->name);
			goto err_out;
		}

		memcpy(&wlpptr->vmacSta_p->BFMRconfig.addr[0], macAddr_p, 6);
		wlpptr->vmacSta_p->BFMRinitstatus.addr_init = 1;

		wlpptr->netDev->netdev_ops = &wlclient_netdev_ops;
		wlpptr->netDev->ethtool_ops = &wl_ethtool_ops;
		wlpptr->netDev->watchdog_timeo = 30 * HZ;
		wlpptr->wlreset = wlreset_client;
		wlSetupWEHdlr(wlpptr->netDev);
		wlpptr->wlpd_p = wlp->wlpd_p;
		wlpptr->master = wlp->netDev;
		wlp->vdev[wlp->wlpd_p->vmacIndex++] = wlpptr->netDev;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 6)
#else
		atomic_set(&wlpptr->netDev->refcnt, 0);
#endif
		ether_setup(wlpptr->netDev);

		/* register cfg80211 virtual interface to wiphy wdev */
#ifdef CFG80211
		wlpptr->wdev.wiphy = wlp->wiphy;
		wlpptr->wdev.iftype = NL80211_IFTYPE_STATION;
		wlpptr->wdev.netdev = wlpptr->netDev;
		wlpptr->wdev.use_4addr = 1;
		wlpptr->netDev->ieee80211_ptr = &wlpptr->wdev;
		SET_NETDEV_DEV(wlpptr->netDev, wiphy_dev(wlpptr->wdev.wiphy));
#endif
		wlpptr->bgscan_period = DEF_BGSCAN_PERIOD;

		if (register_netdev(wlpptr->netDev))
		{
			printk("%s: failed to register device\n",
				   wlpptr->netDev->name);
			goto err_register_netdev;
		}
		ap8x_stat_proc_register(wlpptr->netDev);

		/* Wireless Client Specific */
		{
			{
				if ((clientVMacEntry_p =
						 smeInitParentSession(wlinitcnt, macAddr_p,
											  0,
											  &wlStatusUpdate_clientParent,
											  (void *)wlpptr->netDev)) == NULL)
				{
					goto err_init;
				}
				mainNetdev_p[wlinitcnt] = wlp->netDev;
				wlpptr->txNetdev_p = wlpptr->netDev;
				wlpptr->clntParent_priv_p =
					(void *)clientVMacEntry_p;
				wlpptr->vmacSta_p->VMacEntry.id =
					clientVMacEntry_p->id;
			}
			// Initialize Client PeerInfo.
			InitClientPeerInfo(wlpptr->netDev);
		}
	}
	/* end Wireless Client Specific */

#ifdef EWB
	wetHashInit();
#endif

	ap8xLnxStat_clients_init(wlpptr->netDev, 2);

	WLDBG_EXIT(DBG_LEVEL_2);
	return 0;
err_init:
	ap8x_stat_proc_unregister(wlpptr->netDev);
	//              wlRxRingCleanup(netdev);
err_out:
err_register_netdev:
	wl_kfree(wlpptr);
	WLDBG_EXIT(DBG_LEVEL_2);
	return -EIO;
}

void wlDeinit_client(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacEntry_t *vmacParentEntry_p =
		(vmacEntry_t *)wlpptr->clntParent_priv_p;
	struct wlprivate *wlp;
	int i;

	WLDBG_ENTER(DBG_LEVEL_2);
#if defined(SINGLE_DEV_INTERFACE) && !defined(CLIENTONLY)
	for (i = 1; i < wlpptr->wlpd_p->vmacIndex; i++)
#else
	for (i = 0; i < wlpptr->wlpd_p->vmacIndex; i++)
#endif
	{
		if (wlpptr->vdev[i]->flags & IFF_RUNNING)
		{
			if (wlstop_client(wlpptr->vdev[i]))
			{
				printk(KERN_ERR "%s: failed to stop device\n",
					   wlpptr->vdev[i]->name);
			}
		}
		wlp = NETDEV_PRIV_P(struct wlprivate, wlpptr->vdev[i]);
		DisableMacMgmtTimers(wlp->vmacSta_p);

		/* Wireless Client Specific */
		smeStopBss(vmacParentEntry_p->phyHwMacIndx);
		/* end Wireless Client Specific */

		ap8x_stat_proc_unregister(wlpptr->vdev[i]);

		wl_kfree(wlp->vmacSta_p);
		unregister_netdev(wlpptr->vdev[i]);
		free_netdev(wlpptr->vdev[i]);
	}
	wlpptr->wlpd_p->vmacIndex = 0;
#ifdef EWB
	wetHashDeInit();
#endif
	ap8xLnxStat_clients_deinit(netdev, 2);

	WLDBG_EXIT(DBG_LEVEL_2);
	return;
}

#endif /* CLIENT_SUPPORT */
void WlSendDeauth(struct net_device *netdev)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	u32 entries, i;
	unsigned char *sta_buf, *show_buf;
	extStaDb_StaInfo_t *pStaInfo;

	entries = extStaDb_entries(vmacSta_p, 0);
	if (entries == 0)
	{
		// printk(" zero station list\n");
		return;
	}
	sta_buf = wl_kmalloc(entries * 256, GFP_KERNEL);
	if (sta_buf == NULL)
	{
		printk("wl_kmalloc fail \n");
		return;
	}
	extStaDb_list(vmacSta_p, sta_buf, 1);
	show_buf = sta_buf;
	for (i = 0; i < entries; i++)
	{
		if ((pStaInfo =
				 extStaDb_GetStaInfo(vmacSta_p,
									 (IEEEtypes_MacAddr_t *)show_buf,
									 STADB_DONT_UPDATE_AGINGTIME)) ==
			NULL)
		{
			printk("error: NO station info found \n");
			break;
		}
#ifdef SOC_W906X
		macMgmtMlme_SendDeauthenticateMsg(vmacSta_p, &pStaInfo->Addr,
										  pStaInfo->StnId,
										  IEEEtypes_REASON_DEAUTH_LEAVING,
										  TRUE);
#else
		macMgmtMlme_SendDeauthenticateMsg(vmacSta_p,
										  (IEEEtypes_MacAddr_t *)
											  pStaInfo->Addr,
										  pStaInfo->StnId,
										  IEEEtypes_REASON_DEAUTH_LEAVING);
#endif
		show_buf += sizeof(STA_INFO);
	}
	wl_kfree(sta_buf);
}

void wlReadyStart160MhzBcn(DfsApDesc *dfsDesc_p)
{
	struct wlprivate *priv;
	vmacApInfo_t *vmacSta_p;
	MIB_802DOT11 *mib;
	struct net_device *dev;
	// DfsAp *dfsap;
	DfsAp *me;
	MIB_PHY_DSSS_TABLE *PhyDSSSTable;
	MIB_SPECTRUM_MGMT *mib_SpectrumMagament_p;
	UINT8 channel;

	me = (DfsAp *)(dfsDesc_p->me);
	dev = me->pNetDev;
	priv = NETDEV_PRIV_P(struct wlprivate, dev);
	vmacSta_p = priv->vmacSta_p;
	mib = vmacSta_p->ShadowMib802dot11;
	PhyDSSSTable = mib->PhyDSSSTable;
	mib_SpectrumMagament_p = mib->SpectrumMagament;
	if (priv->wlpd_p->bStopBcnProbeResp && macMgmtMlme_DfsEnabled(dev) &&
		((PhyDSSSTable->Chanflag.ChnlWidth == CH_160_MHz_WIDTH) ||
		 (PhyDSSSTable->Chanflag.ChnlWidth == CH_AUTO_WIDTH)))
	{

		if (PhyDSSSTable->Chanflag.FreqBand != FREQ_BAND_5GHZ)
		{
			printk("error:wrong band %d\n",
				   PhyDSSSTable->Chanflag.FreqBand);
		}
		if (mib->StationConfig->SpectrumManagementRequired != TRUE)
		{
			printk("error:spectrum management disabled\n");
		}
#ifdef CONCURRENT_DFS_SUPPORT
		channel =
			DfsDecideNewTargetChannel(dev, dfsDesc_p, TRUE, FALSE);
#else
		channel = DfsDecideNewTargetChannel(dev, dfsDesc_p, TRUE);
#endif /* CONCURRENT_DFS_SUPPORT */
		if (channel == 0)
		{
			// should not happen. Just in case.
			channel = 36;
		}
		printk("160Mhz:next target channel %d \n", channel);
		PhyDSSSTable->CurrChan = channel;
		me->dfsApDesc.currChanInfo.channel = channel;
		memcpy(&me->dfsApDesc.currChanInfo.chanflag,
			   &PhyDSSSTable->Chanflag, sizeof(CHNL_FLAGS));
		FireCACTimer(me);
		mhsm_transition(&me->super, &me->Dfs_Scan);
	}

	return;
}

static void
wlIntrPoll(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	struct bqm_args *pbqm_args = &wlpd_p->bmq_args;

	u8 qid;
	struct msix_context ctx;

	// Check the RxQ
	for (qid = SC5_RXQ_START_INDEX;
		 qid < (SC5_RXQ_START_INDEX + SC5_RXQ_NUM); qid++)
	{
		if (wlSQEmpty(netdev, qid) == FALSE)
		{
			ctx.msg_id = (qid << 1) + wlpd_p->intr_shift;
			ctx.netDev = netdev;
			wlSC5MSIX_rx(0, (void *)&ctx); //"irq" is not used
		}
	}
	// Check the ReleaseQ
	for (qid = pbqm_args->bmq_release_index;
		 qid < (pbqm_args->bmq_release_index + pbqm_args->bmq_release_num);
		 qid++)
	{
		if (wlSQEmpty(netdev, qid) == FALSE)
		{
			ctx.msg_id = (qid << 1) + wlpd_p->intr_shift;
			ctx.netDev = netdev;
			wlSC5MSIX_rel(0, (void *)&ctx); //"irq" is not used
		}
	}
	return;
}

#ifdef SOC_W906X
void update_mbss_status(struct wlprivate *wlpptr, u8 status)
{
	struct wlprivate_data *wlpd_p =
		(wlpptr != NULL) ? wlpptr->wlpd_p : NULL;
	vmacApInfo_t *vmacSta_p = (wlpptr != NULL) ? wlpptr->vmacSta_p : NULL;
	// mbss_set_t    *pset = &wlpd_p->mbssSet;

	if (wlpd_p == NULL || vmacSta_p == NULL)
	{
		return;
	}
	if (status)
	{
		wlpd_p->bss_active |= (1 << vmacSta_p->VMacEntry.macId);
	}
	else
	{
		wlpd_p->bss_active &= (~(1 << vmacSta_p->VMacEntry.macId));
		wlpd_p->smon.ActVapBitmap &=
			(~(1 << vmacSta_p->VMacEntry.macId));
	}
}
#endif
#ifdef MV_NSS_SUPPORT
struct sk_buff *
wlAllocSkb(unsigned int length)
{
	struct sk_buff *skb;
	mv_nss_metadata_t *mdat_ptr = NULL;

	skb = wlNssOps->alloc_skb(length, GFP_ATOMIC);
	if (skb)
	{
		mdat_ptr =
			(mv_nss_metadata_t *)wlNssOps->get_metadata_skb(skb);

#ifdef MV_NSS_METADATA_RESET
		memset(mdat_ptr, 0, sizeof(mv_nss_metadata_t));
#endif
		MARK_DATA_SKB(skb);
		mdat_ptr->radio_id = 0;
		mdat_ptr->port_src = 0x16;
		mdat_ptr->frm_type = 0;
	}

	return skb;
}

void wlFreeSkb(struct sk_buff *skb)
{
	return wlNssOps->free_skb(skb);
}

int wlReceiveSkb(struct sk_buff *skb)
{
	if (IS_DATA_SKB(skb))
		return wlNssOps->receive_skb(skb);
	else
		return netif_receive_skb(skb);
}
#endif /* NSS_SUPPORT */
