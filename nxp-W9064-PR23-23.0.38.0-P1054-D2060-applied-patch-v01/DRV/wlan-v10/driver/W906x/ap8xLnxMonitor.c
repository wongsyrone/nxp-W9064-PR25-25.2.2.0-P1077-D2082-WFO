/** @file ap8xLnxMonitor.c
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
#include <linux/kthread.h>
#include <linux/notifier.h>
#ifdef CONFIG_MARVELL_MOCHI_DRIVER
#include <linux/mci_if.h>
#endif
#include <linux/thermal.h>
#include "ap8xLnxMonitor.h"
#include "ap8xLnxIntf.h"
#include "ap8xLnxFwcmd.h"
#include "ap8xLnxVer.h"
#include "wlApi.h"

#define MOCHI_MON
//#define AVL_DB_SNAPSHOT

#define SMAC_STUCK_TRIGGER_CNT   3
int wlmon_kthread(void *arg);

int wlmon_bmq_refill_Info_dump(struct net_device *netdev, u8 * plog,
			       U32 maxlen);
static int sprintSmacStatus(u8 * pdest, SMAC_STATUS_st * pSMACStatus,
			    UINT32 maxlen, UINT32 format);
int wlmon_rx_stuck_detct(struct net_device *netdev,
			 SMAC_STATUS_st * pCurSmacStatus, void **buf);
int wlmon_tx_stuck_detct(struct net_device *netdev,
			 SMAC_STATUS_st * pCurSmacStatus, void **buf);
int mochi_error_detect(struct net_device *netdev, void **buf);
UINT32 get_mci_errcnt(struct wlprivate *wlpptr);
int pfw_scheduler_info_detect(struct net_device *netdev, void **buf);
int wlmon_beacon_stuck_detct(struct net_device *netdev,
			     SMAC_STATUS_st * pCurSmacStatus, void **buf);
void wlmon_log_bmq_buff_refill(struct net_device *netdev, U32 qid,
			       U32 refill_cnt);
int sprintf_hex_dump(u8 * pdest, u8 * psrc, UINT32 maxlen, UINT32 maxbuflen);
void wlmon_show_thermal(struct net_device *netdev);
int wlmon_host_temperature_get(UINT32 * ptemp);
u32 wlmon_read_hw_registers(struct wlprivate *wlpptr, u32 start, u32 len,
			    u32 * pbuf);

#ifdef AVL_DB_SNAPSHOT
int wlmon_dump_AVL_sta_db(struct net_device *netdev, u64 tms);
#endif

UINT32 hm_max_bmq_diff = BMQ_DIFFMSG_COUNT;

extern struct wlprivate_data *global_private_data[MAX_CARDS_SUPPORT];

extern u64 dump_file(UINT8 * valbuf, UINT32 length, UINT8 * fname,
		     UINT32 append);
extern int wlFwGetQueueStats(struct net_device *netdev, int option,
			     UINT8 fromHM, char *sysfs_buff);
extern u32 get_mbssid_profile(void *wlpd, u8 xmit_bssids);
extern int register_reboot_notifier(struct notifier_block *nb);
extern int unregister_reboot_notifier(struct notifier_block *nb);
extern void wl_unregister_dump_func(struct wlprivate_data *wlpd_p);
extern void wlget_sw_version(struct wlprivate *priv, char *sysfs_buff,
			     int more);
char coredumppath[64] = "/var";

//ADMA inaccessable address holes. per SCBT-A0 ADMA register spec. 
//offset values in register spec.
static invalid_addr_hole inv_adma = {
	.num = 0xF,
	.addr = {
		 {0x60, 0x7C},
		 {0xE0, 0xFC},
		 {0x160, 0x17C},
		 {0x1E0, 0x1FC},
		 {0x260, 0x7FC},
		 {0x860, 0x87C},
		 {0x8E0, 0x8FC},
		 {0x960, 0x97C},
		 {0x9E0, 0x9FC},
		 {0xA60, 0xFFC},
		 {0x1060, 0x107C},
		 {0X10E0, 0X10FC},
		 {0x1160, 0x117C},
		 {0x11E0, 0x11FC},
		 {0x1260, 0x17FC}}
};

//BMAN inaccessable address holes. per SCBT-A0 ADMA register spec. 
//offset values in register spec. (remove 0x920 ~ 0x9FC)
static invalid_addr_hole inv_bman = {
	.num = 0x1,
	.addr = {
		 {0x120, 0x1FC}}
};

//AVL inaccessable address holes. per SCBT-A0 ADMA register spec. 
//offset values in register spec.
static invalid_addr_hole inv_avl = {
	.num = 0x5,
	.addr = {
		 {0x60, 0x60},
		 {0x80, 0x80},
		 {0x9C, 0x1FC},
		 {0x210, 0x2FC},
		 {0x380, 0x3FC}}
};

static int
hm_reboot_handler(struct notifier_block *nb, unsigned long state, void *cmd)
{
	struct net_device *netdev;
	struct wlprivate *wlpptr;
	char ifname[20];
	int i;

	for (i = 0; i < MAX_CARDS_SUPPORT; i++) {
		sprintf(ifname, "wdev%1d", i);
		netdev = dev_get_by_name(&init_net, ifname);
		if (netdev) {
			wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
			wl_unregister_dump_func(wlpptr->wlpd_p);
			if (wlpptr->wlpd_p->wlmon_task) {
				pr_info("stop wlmon_%s thread\n", ifname);
				kthread_stop(wlpptr->wlpd_p->wlmon_task);
				wlFwHardResetAndReInit(netdev, 1);
			}
		}
	}
	return NOTIFY_OK;
}

static struct notifier_block hm_reboot_notifier = {
	.notifier_call = hm_reboot_handler,
};

static void
hm_reboot_nofifier_register(int action, struct notifier_block *nb)
{
	static int notifier_registered = 0;

	/* action: 1 register, 0 unregister */
	if (!action) {
		if (notifier_registered) {
			unregister_reboot_notifier(nb);
			notifier_registered = 0;
		}
	} else {
		if (!notifier_registered) {
			register_reboot_notifier(nb);
			notifier_registered = 1;
		}
	}

}

#ifdef CONFIG_ARMADA3900_ICU_MCI
static bool notifier_registered = false;
static int
ap8x_mci_bus_handler(struct notifier_block *self, unsigned long val, void *port)
{
	switch (val) {
	case MCI_CRC_ERR:
	case MCI_SEQ_ERR:
	case MCI_RXI_FULL_ERR:
		pr_debug("The MoChi Port %u status is %lu\n", *(u32 *) port,
			 val);
		break;
	default:
		pr_err("Unknown mci status = [%lu]\n", val);
		break;
	}
	return NOTIFY_OK;
}

static struct notifier_block ap8x_mci_bus_notifier = {
	.notifier_call = ap8x_mci_bus_handler,
	.priority = 200
};
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 4, 120)
void __iomem *cp_gpio_base;
static void
wlmon_ext_trigger_init(struct wlprivate *wlpptr)
{
	u32 val;
	unsigned char tlvData[MAX_TLV_LEN];
	char buff[120];

	dev_info(wlpptr->wlpd_p->dev, "Set gpio trigger mode to %ul",
		 hm_gpio_trigger);

	switch (hm_gpio_trigger) {
	case 1:
		cp_gpio_base = ioremap(0xF2440000, SZ_4K);
		// set CP_MPP[59].function = 0x0
		val = wl_util_readl(wlpptr->netDev, cp_gpio_base + 0x01C);
		val &= 0xFFFF0FFF;
		wl_util_writel(wlpptr->netDev, val, cp_gpio_base + 0x01C);
		// set CP_GPIO[59].Output = 0
		val = wl_util_readl(wlpptr->netDev, cp_gpio_base + 0x140);
		val &= ~(1 << 27);
		wl_util_writel(wlpptr->netDev, val, cp_gpio_base + 0x140);
		// set CP_GPIO[59].OE = 0 (active low)
		val = wl_util_readl(wlpptr->netDev, cp_gpio_base + 0x144);
		val &= ~(1 << 27);
		wl_util_writel(wlpptr->netDev, val, cp_gpio_base + 0x144);
		break;
	case 2:
		/* iwpriv wdev1 setcmd "setreg addr 0xb0000a0c 0x0"                 //  GPIO_OUTPUT: bit[1] := 0, set output '0' for GPIO[1] */
		/* iwpriv wdev1 setcmd "tlv 14 3 1 0 0" <<< GPIO 1, Output, Low >> wlFwGetTLVSet() */
		tlvData[0] = 1;
		tlvData[1] = 0;
		tlvData[2] = 0;
		wlFwGetTLVSet(wlpptr->netDev, 1, 14, 3, tlvData, buff);
		break;
	case 3:
		/* no initialization required */
		break;
	default:
		dev_err(wlpptr->wlpd_p->dev,
			"unsupported gpio trigger mode %ul", hm_gpio_trigger);
	}
	return;
}

void
wlmon_ext_trigger_assert(struct net_device *netdev)
{
	u32 val;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	unsigned char tlvData[MAX_TLV_LEN];
	char buff[120];

	switch (hm_gpio_trigger) {
	case 1:
		// set CP_GPIO[59].Output = 1
		val = wl_util_readl(netdev, cp_gpio_base + 0x140);
		val |= (1 << 27);
		wl_util_writel(netdev, val, cp_gpio_base + 0x140);
		break;
	case 2:
		tlvData[0] = 1;
		tlvData[1] = 0;
		tlvData[2] = 1;
		wlFwGetTLVSet(wlpptr->netDev, 1, 14, 3, tlvData, buff);
		break;
	case 3:
		wl_util_writel(netdev, 2, wlpptr->ioBase1 + 0x13F84);
		break;
	default:
		dev_err(wlpptr->wlpd_p->dev,
			"unsupported gpio trigger mode %ul", hm_gpio_trigger);
	}
	return;
}

void
wlmon_ext_trigger_deassert(struct wlprivate *wlpptr)
{
	u32 val;

	switch (hm_gpio_trigger) {
	case 1:
		// set CP_GPIO[59].Output = 0
		val = wl_util_readl(wlpptr->netDev, cp_gpio_base + 0x140);
		val &= ~(1 << 27);
		wl_util_writel(wlpptr->netDev, val, cp_gpio_base + 0x140);
		break;
	case 2:
	case 3:
		/* TBD */
		break;
	default:
		dev_err(wlpptr->wlpd_p->dev,
			"unsupported gpio trigger mode %ul", hm_gpio_trigger);
	}
	return;
}

static void
wlmon_ext_trigger_release(struct wlprivate *wlpptr)
{
	u32 val;

	switch (hm_gpio_trigger) {
	case 1:
		if (cp_gpio_base) {
			// set CP_GPIO[59].Output = 0
			val = wl_util_readl(wlpptr->netDev, cp_gpio_base + 0x140);
			val &= ~(1 << 27);
			wl_util_writel(wlpptr->netDev, val, cp_gpio_base + 0x140);
			iounmap(cp_gpio_base);
			cp_gpio_base = NULL;
		}
		break;
	case 2:
	case 3:
		/* TBD */
		break;
	default:
		dev_err(wlpptr->wlpd_p->dev,
			"unsupported gpio trigger mode %ul", hm_gpio_trigger);
	}
	return;
}
#else
#define wlmon_ext_trigger_init(x) do { } while (0)
#define wlmon_ext_trigger_assert(x) do { } while (0)
#define wlmon_ext_trigger_deassert(x) do { } while (0)
#define wlmon_ext_trigger_release(x) do { } while (0)
#endif

int
register_wlmon_notifier(void *wlpd)
{
	struct wlprivate_data *wlpd_p = (struct wlprivate_data *)wlpd;
	struct notifier_block *nb = 0;

	if (wlpd_p->smon.nb == NULL) {
		nb = (struct notifier_block *)
			wl_kmalloc(sizeof(struct notifier_block), GFP_ATOMIC);
		if (!nb) {
			printk("Error[%s:%d]: Allocating notifier_block Memory \n", __func__, __LINE__);
			return -EADDRNOTAVAIL;
		}

		memset((void *)nb, 0, sizeof(struct notifier_block));
		nb->notifier_call = wldbgCoreDump;
		wlpd_p->smon.nb = nb;
		wlpd_p->smon.active = 1;
	}

	return blocking_notifier_chain_register(&wlpd_p->smon.
						wlmon_notifier_list, nb);
}

int
unregister_wlmon_notifier(void *wlpd)
{
	struct wlprivate_data *wlpd_p = (struct wlprivate_data *)wlpd;
	struct notifier_block *nb = wlpd_p->smon.nb;
	int rc;

	if (nb) {
		rc = blocking_notifier_chain_unregister(&wlpd_p->smon.
							wlmon_notifier_list,
							nb);
		if (rc == 0) {
			wlpd_p->smon.nb = NULL;
			wl_kfree(nb);
			return 0;
		}

		return rc;
	}

	return 0;
}

static int
wlmon_smac_detect(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	u32 *smacL;
	u8 *stuckCnt;
	u32 smac_cur[SMAC_CPU_NUM];
	int stuck_detected = 0;
	u32 i;

	if (wlpd_p->smon.active == 0 ||
	    !(wlpd_p->smon.ActiveBitmap & MON_SMAC_STUCK))
		return 0;

	if (wlpd_p->smon.ActiveIf == 0)
		return 0;

	smacL = wlpd_p->smon.cm_heartbit;
	stuckCnt = wlpd_p->smon.cm_stuckcnt;

	wl_util_lock(netdev);
	memcpy((void *)&smac_cur[0],
	       (void *)&wlpptr->smacStatusAddr->smacSts[0], sizeof(smac_cur));
	wl_util_unlock(netdev);

	//printk("smacCur:%X %X %X %X %X %X %X\n", smac_cur[0],smac_cur[1],smac_cur[2],smac_cur[3],smac_cur[4],smac_cur[5],smac_cur[6]);

	for (i = 0; i < SMAC_CPU_NUM; i++) {
		if (smacL[i] == smac_cur[i]) {
			if (++stuckCnt[i] >= SMAC_STUCK_TRIGGER_CNT)
				stuck_detected = 1;
		} else
			stuckCnt[i] = 0;
	}

	memcpy(smacL, smac_cur, sizeof(wlpd_p->smon.cm_heartbit));
	if (stuck_detected) {
		printk(" macsts:%X %X %X %X %X %X %X\n", smacL[0], smacL[1],
		       smacL[2], smacL[3], smacL[4], smacL[5], smacL[6]);
		printk("%s MAC CM3_x stuck cnt:%u %u %u %u %u %u %u\n",
		       wlpd_p->rootdev->name, stuckCnt[0], stuckCnt[1],
		       stuckCnt[2], stuckCnt[3], stuckCnt[4], stuckCnt[5],
		       stuckCnt[6]);
		return 1;
	}

	return 0;
}

#define WLMON_PRNT_BUF_SIZE  (4096*32)

extern BOOLEAN wlDbg_chk_bm_enq(struct net_device *netdev, UINT32 max_diff);
static int
wlmon_bmq_resouce_detct(struct net_device *netdev, void **buf)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	//SMAC_STATUS_st        smacStatus;
	//SMAC_STATUS_st* pSMACStatus = &smacStatus;
	struct drv_stats *wldrvstat_p = &wlpd_p->drv_stats_val;
	int idx = 0;
	int initidx = 0;
	char *plog = NULL;
	u32 i;
	BOOLEAN result;
	u64 ts;
	u64 ts_sec, ts_ms;

	if (wlpd_p->smon.active == 0 ||
	    !(wlpd_p->smon.ActiveBitmap & MON_DRV_BMQ_RESOURCE))
		return 0;

	if ((result = wlDbg_chk_bm_enq(netdev, hm_max_bmq_diff))) {

		if ((plog =
		     (void *)wl_kmalloc(WLMON_PRNT_BUF_SIZE,
					GFP_ATOMIC)) == NULL) {
			printk("Error[%s:%d]: Allocating wlmon buffer failure \n", __func__, __LINE__);
			goto exit;
		}

		ts = xxGetTimeStamp();
		convert_tscale(ts, &ts_sec, &ts_ms, NULL);
		initidx =
			sprintf(&plog[idx],
				"[%llu.%llu] Buffer resources warning:\n",
				ts_sec, ts_ms);
		idx = initidx;

		//memcpy(pSMACStatus, wlpptr->smacStatusAddr, sizeof(SMAC_STATUS_st));

		for (i = SC5_BMQ_START_INDEX;
		     i < SC5_BMQ_START_INDEX + SC5_BMQ_NUM; i++) {
			int offset = i - SC5_BMQ_START_INDEX;
			idx += sprintf(&plog[idx],
				       "\t Q[%d] = %d, (eq=%d, drop=%d, ret=%d)\n",
				       i,
				       (wldrvstat_p->enq_bmqbuf_cnt[offset] -
					wldrvstat_p->xx_buf_free_SQ14[offset] -
					wldrvstat_p->bmqbuf_ret_cnt[offset]),
				       wldrvstat_p->enq_bmqbuf_cnt[offset],
				       wldrvstat_p->xx_buf_free_SQ14[offset],
				       wldrvstat_p->bmqbuf_ret_cnt[offset]);
		}

		wlmon_bmq_refill_Info_dump(netdev, &plog[idx],
					   WLMON_PRNT_BUF_SIZE - idx);

		//idx += sprintSmacStatus(&plog[idx], pSMACStatus, WLMON_PRNT_BUF_SIZE-idx);

		*buf = plog;
		//printk("idx=%d [%s:%d]\n",idx, __func__, __LINE__);
		return 1;

	}

exit:

	//printk("null out\n");
	*buf = NULL;
	return 0;

}

//actively check collected statistic error counter and log to file
static int
wlmon_error_cnt_detect(struct net_device *netdev, void **buf)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	struct except_cnt *pnew = &wlpd_p->except_cnt;
	struct except_cnt *pold = (struct except_cnt *)wlpd_p->smon.pexcept_cnt;
	u32 size = 0;
	int idx = 0;
	int initidx = 0;
	char *plog = NULL;
	u32 i;
	u64 ts;
	u64 ts_sec, ts_ms;
	static u8 once = 0;

	if (wlpd_p->smon.active == 0 ||
	    !(wlpd_p->smon.ActiveBitmap & MON_DRV_ERR_CNTS))
		return 0;

	if ((plog =
	     (void *)wl_kmalloc(WLMON_PRNT_BUF_SIZE, GFP_ATOMIC)) == NULL) {
		printk("Error[%s:%d]: Allocating wlmon buffer failure \n",
		       __func__, __LINE__);
		return 0;
	}

	ts = xxGetTimeStamp();	//us
	convert_tscale(ts, &ts_sec, &ts_ms, NULL);
	initidx = sprintf(&plog[idx], "[%llu.%llu]:\n", ts_sec, ts_ms);
	idx = initidx;

	size += sizeof(pnew->cnt_cfhul_invalid_signature);
	if (pnew->cnt_cfhul_invalid_signature !=
	    pold->cnt_cfhul_invalid_signature) {
		idx += sprintf(&plog[idx], "cnt_cfhul_invalid_signature:%u\n",
			       pnew->cnt_cfhul_invalid_signature);
		pold->cnt_cfhul_invalid_signature =
			pnew->cnt_cfhul_invalid_signature;
	}

	size += sizeof(pnew->cnt_tx_misalign);
	if (pnew->cnt_tx_misalign != pold->cnt_tx_misalign) {
#if 0				//ignore this counter change because Ax chip can accept it.  need confirm ?
		idx += sprintf(&plog[idx], "cnt_tx_misalign:%u\n",
			       pnew->cnt_tx_misalign);
#endif
		pold->cnt_tx_misalign = pnew->cnt_tx_misalign;
	}

	size += sizeof(pnew->cnt_z1_frag_buffer);
	if (pnew->cnt_z1_frag_buffer != pold->cnt_z1_frag_buffer) {
		idx += sprintf(&plog[idx], "cnt_z1_frag_buffer:%u\n",
			       pnew->cnt_z1_frag_buffer);
		pold->cnt_z1_frag_buffer = pnew->cnt_z1_frag_buffer;
	}

	size += sizeof(pnew->cnt_cfhul_error);
	if (pnew->cnt_cfhul_error != pold->cnt_cfhul_error) {
		idx += sprintf(&plog[idx], "cnt_cfhul_error:%u\n",
			       pnew->cnt_cfhul_error);
		pold->cnt_cfhul_error = pnew->cnt_cfhul_error;
	}

	size += sizeof(pnew->cnt_cfhul_snap_error);
	if (pnew->cnt_cfhul_snap_error != pold->cnt_cfhul_snap_error) {
		idx += sprintf(&plog[idx], "cnt_cfhul_snap_error:%u\n",
			       pnew->cnt_cfhul_snap_error);
		pold->cnt_cfhul_oversize = pnew->cnt_cfhul_snap_error;
	}

	size += sizeof(pnew->cnt_cfhul_oversize);
	if (pnew->cnt_cfhul_oversize != pold->cnt_cfhul_oversize) {
		idx += sprintf(&plog[idx], "cnt_cfhul_oversize:%u\n",
			       pnew->cnt_cfhul_oversize);
		pold->cnt_cfhul_oversize = pnew->cnt_cfhul_oversize;
	}

	size += sizeof(pnew->cnt_invalid_amsdu_subframe_len);
	if (pnew->cnt_invalid_amsdu_subframe_len !=
	    pold->cnt_invalid_amsdu_subframe_len) {
		idx += sprintf(&plog[idx],
			       "cnt_invalid_amsdu_subframe_len:%u\n",
			       pnew->cnt_invalid_amsdu_subframe_len);
		pold->cnt_invalid_amsdu_subframe_len =
			pnew->cnt_invalid_amsdu_subframe_len;

	}

	size += sizeof(pnew->cnt_invalid_mpdu_frames);
	if (pnew->cnt_invalid_mpdu_frames != pold->cnt_invalid_mpdu_frames) {
		idx += sprintf(&plog[idx], "cnt_invalid_mpdu_frames:%u\n",
			       pnew->cnt_invalid_mpdu_frames);
		pold->cnt_invalid_mpdu_frames = pnew->cnt_invalid_mpdu_frames;

	}

	size += sizeof(pnew->cnt_amsdu_subframes);
	if (pnew->cnt_amsdu_subframes != pold->cnt_amsdu_subframes) {
		idx += sprintf(&plog[idx], "cnt_amsdu_subframes:%u\n",
			       pnew->cnt_amsdu_subframes);
		pold->cnt_amsdu_subframes = pnew->cnt_amsdu_subframes;

	}

	size += sizeof(pnew->cnt_skbtrace_reset);
	if (pnew->cnt_skbtrace_reset != pold->cnt_skbtrace_reset) {
		idx += sprintf(&plog[idx], "cnt_skbtrace_reset:%u\n",
			       pnew->cnt_skbtrace_reset);
		pold->cnt_skbtrace_reset = pnew->cnt_skbtrace_reset;

	}

	size += sizeof(pnew->rx_invalid_sig_cnt);
	for (i = 0; i < SC5_BMQ_NUM; i++) {
		if (pnew->rx_invalid_sig_cnt[i] != pold->rx_invalid_sig_cnt[i]) {
			idx += sprintf(&plog[idx],
				       "rx_invalid_sig_cnt[%u]:%u\n", i,
				       pnew->rx_invalid_sig_cnt[i]);
			pold->rx_invalid_sig_cnt[i] =
				pnew->rx_invalid_sig_cnt[i];

		}
	}

	size += sizeof(pnew->dup_txdone_cnt);
	if (pnew->dup_txdone_cnt != pold->dup_txdone_cnt) {
		idx += sprintf(&plog[idx], "dup_txdone_cnt:%u\n",
			       pnew->dup_txdone_cnt);
		pold->dup_txdone_cnt = pnew->dup_txdone_cnt;

	}

	size += sizeof(pnew->sml_hdroom_cnt);
	if (pnew->sml_hdroom_cnt != pold->sml_hdroom_cnt) {
		idx += sprintf(&plog[idx], "sml_hdroom_cnt:%u\n",
			       pnew->sml_hdroom_cnt);
		pold->sml_hdroom_cnt = pnew->sml_hdroom_cnt;

	}

	size += sizeof(pnew->sml_rx_hdroom_cnt);
	if (pnew->sml_rx_hdroom_cnt != pold->sml_rx_hdroom_cnt) {
		idx += sprintf(&plog[idx], "sml_rx_hdroom_cnt:%u\n",
			       pnew->sml_rx_hdroom_cnt);
		pold->sml_rx_hdroom_cnt = pnew->sml_rx_hdroom_cnt;

	}

	size += sizeof(pnew->rxbuf_mis_align_cnt);
	if (pnew->rxbuf_mis_align_cnt != pold->rxbuf_mis_align_cnt) {
		idx += sprintf(&plog[idx], "rxbuf_mis_align_cnt:%u\n",
			       pnew->rxbuf_mis_align_cnt);
		pold->rxbuf_mis_align_cnt = pnew->rxbuf_mis_align_cnt;

	}

	size += sizeof(pnew->pe_invlid_bpid);
	if (pnew->pe_invlid_bpid != pold->pe_invlid_bpid) {
		idx += sprintf(&plog[idx], "pe_invlid_bpid:%u\n",
			       pnew->pe_invlid_bpid);
		pold->pe_invlid_bpid = pnew->pe_invlid_bpid;

	}

	size += sizeof(pnew->cfhul_bpid_err);
	if (pnew->cfhul_bpid_err != pold->cfhul_bpid_err) {
		idx += sprintf(&plog[idx], "cfhul_bpid_err:%u\n",
			       pnew->cfhul_bpid_err);
		pold->cfhul_bpid_err = pnew->cfhul_bpid_err;

	}

	size += sizeof(pnew->cfhul_hdr_loaddr_err);
	if (pnew->cfhul_hdr_loaddr_err != pold->cfhul_hdr_loaddr_err) {
		idx += sprintf(&plog[idx], "cfhul_hdr_loaddr_err:%u\n",
			       pnew->cfhul_hdr_loaddr_err);
		pold->cfhul_hdr_loaddr_err = pnew->cfhul_hdr_loaddr_err;

	}
	//entries are not error log, skip them. 
	size += sizeof(pnew->cfhul_flpkt_log);

	for (i = 0; i < SC5_BMQ_NUM; i++) {
		size += sizeof(pnew->cfhul_flpkt_error[i]);
		if (pnew->cfhul_flpkt_error[i] != pold->cfhul_flpkt_error[i]) {
			idx += sprintf(&plog[idx], "cfhul_flpkt_error[%u]:%u\n",
				       i, pnew->cfhul_flpkt_error[i]);
			pold->cfhul_flpkt_error[i] = pnew->cfhul_flpkt_error[i];
		}
	}

	size += sizeof(pnew->cfhul_hdrlen_err);
	if (pnew->cfhul_hdrlen_err != pold->cfhul_hdrlen_err) {
		idx += sprintf(&plog[idx], "cfhul_hdrlen_err:%u\n",
			       pnew->cfhul_hdrlen_err);
		pold->cfhul_hdrlen_err = pnew->cfhul_hdrlen_err;

	}

	size += sizeof(pnew->cfhul_buf_map_err);
	if (pnew->cfhul_buf_map_err != pold->cfhul_buf_map_err) {
		idx += sprintf(&plog[idx], "cfhul_buf_map_err:%u\n",
			       pnew->cfhul_buf_map_err);
		pold->cfhul_buf_map_err = pnew->cfhul_buf_map_err;

	}

	size += sizeof(pnew->tx_drop_over_max_pending);
	if (pnew->tx_drop_over_max_pending != pold->tx_drop_over_max_pending) {
		idx += sprintf(&plog[idx], "tx_drop_over_max_pending:%u\n",
			       pnew->tx_drop_over_max_pending);
		pold->tx_drop_over_max_pending = pnew->tx_drop_over_max_pending;

	}

	size += sizeof(pnew->buf_desc_not_updated);
	if (pnew->buf_desc_not_updated != pold->buf_desc_not_updated) {
		idx += sprintf(&plog[idx], "buf_desc_not_updated:%u\n",
			       pnew->buf_desc_not_updated);
		pold->buf_desc_not_updated = pnew->buf_desc_not_updated;

	}

	size += sizeof(pnew->invalid_buf_addr);
	if (pnew->invalid_buf_addr != pold->invalid_buf_addr) {
		idx += sprintf(&plog[idx], "invalid_buf_addr:%u\n",
			       pnew->invalid_buf_addr);
		pold->invalid_buf_addr = pnew->invalid_buf_addr;

	}

	size += sizeof(pnew->cfhul_flpkt_lost);
	if (pnew->cfhul_flpkt_lost[0] != pold->cfhul_flpkt_lost[0] ||
	    pnew->cfhul_flpkt_lost[1] != pold->cfhul_flpkt_lost[1] ||
	    pnew->cfhul_flpkt_lost[2] != pold->cfhul_flpkt_lost[2]) {
		idx += sprintf(&plog[idx],
			       "Lost AMSDU subframes (fpkt,midle,lpkt)=%u,%u,%u\n",
			       pnew->cfhul_flpkt_lost[0],
			       pnew->cfhul_flpkt_lost[1],
			       pnew->cfhul_flpkt_lost[2]);
		pold->cfhul_flpkt_lost[0] = pnew->cfhul_flpkt_lost[0];
		pold->cfhul_flpkt_lost[1] = pnew->cfhul_flpkt_lost[1];
		pold->cfhul_flpkt_lost[2] = pnew->cfhul_flpkt_lost[2];
	}
	if (pnew->cfhul_flpkt_lost[3] != pold->cfhul_flpkt_lost[3]) {
		idx += sprintf(&plog[idx],
			       "AMSDU subframe number over limit:%u\n",
			       pnew->cfhul_flpkt_lost[3]);
		pold->cfhul_flpkt_lost[3] = pnew->cfhul_flpkt_lost[3];

	}
	//not error counters, skip
	size += sizeof(pnew->qidcnt);
	size += sizeof(pnew->in_pkt);
	size += sizeof(pnew->lastpkt_status);

	size += sizeof(pnew->msdu_err);
	if (pnew->msdu_err != pold->msdu_err) {
		idx += sprintf(&plog[idx], "msdu_err:%u\n", pnew->msdu_err);
		pold->msdu_err = pnew->msdu_err;

	}

	size += sizeof(pnew->skb_hddat_err);
	if (pnew->skb_hddat_err != pold->skb_hddat_err) {
		idx += sprintf(&plog[idx], "skb_hddat_err:%u\n",
			       pnew->skb_hddat_err);
		pold->skb_hddat_err = pnew->skb_hddat_err;
	}

	size += sizeof(pnew->badPNcntUcast);
	if (pnew->badPNcntUcast != pold->badPNcntUcast) {
		idx += sprintf(&plog[idx], "Incorrect PN Ucast cnt:%u\n",
			       pnew->badPNcntUcast);
		pold->badPNcntUcast = pnew->badPNcntUcast;
	}

	size += sizeof(pnew->badPNcntMcast);
	if (pnew->badPNcntMcast != pold->badPNcntMcast) {
		idx += sprintf(&plog[idx], "Incorrect PN Mcast cnt:%u\n",
			       pnew->badPNcntMcast);
		pold->badPNcntMcast = pnew->badPNcntMcast;
	}

	size += sizeof(pnew->badPNcntMgmtcast);
	if (pnew->badPNcntMgmtcast != pold->badPNcntMgmtcast) {
		idx += sprintf(&plog[idx], "Incorrect PN mgmt cnt:%u\n",
			       pnew->badPNcntMgmtcast);
		pold->badPNcntMgmtcast = pnew->badPNcntMgmtcast;
	}

	size += sizeof(pnew->badAcntStnid);
	if (pnew->badAcntStnid != pold->badAcntStnid) {
		idx += sprintf(&plog[idx],
			       "Invalid STN ID in Acnt Record cnt:%u\n",
			       pnew->badAcntStnid);
		pold->badAcntStnid = pnew->badAcntStnid;
	}
	//not error counters, skip
	size += sizeof(pnew->skip_feed_starv);

	if (idx > WLMON_PRNT_BUF_SIZE) {
		printk("[%s,%d]:wlmon error dump run out of buffer\n", __func__,
		       __LINE__);
		BUG();
	}

	if (size != sizeof(struct except_cnt) && once == 0) {
		once++;
		printk("Info: Some entries not check in health monitor\n");
	}

	if ((idx == initidx) && plog) {
		wl_kfree(plog);
		return 0;
	}

	*buf = plog;
	//printk("idx=%d\n",idx);
	return 1;
}

void
wlmon_log_buffer(struct net_device *netdev, UINT8 * buf, UINT32 len)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	char *pcmdbuf = (char *)wlpd_p->smon.piocmdlog;
	UINT32 *pcmdidx = &wlpd_p->smon.cmdlogidx;
	unsigned long HMLockflag;

	if (wlpd_p->smon.active == 0 ||
	    !(wlpd_p->smon.ActiveBitmap & MON_DRV_CMD))
		return;

	SPIN_LOCK_IRQSAVE(&wlpd_p->locks.HMLock, HMLockflag);
	if (*pcmdidx + len < WLMON_PRNT_BUF_SIZE - 1) {
		strcat(&pcmdbuf[*pcmdidx], buf);
		*pcmdidx = strlen(pcmdbuf);
	}
#if 0				//TODO: handle this messages later
	else {
		printk("[HM warning]: miss to log a cmd\n");
	}
#endif
	SPIN_UNLOCK_IRQRESTORE(&wlpd_p->locks.HMLock, HMLockflag);

}

static int
wlmon_log_cmd(struct net_device *netdev, void **buf)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	char *pcmdbuf = (char *)wlpd_p->smon.piocmdlog;
	UINT32 *pcmdidx = &wlpd_p->smon.cmdlogidx;
	int idx = 0;
	char *plog = NULL;
	unsigned long HMLockflag;

	if (wlpd_p->smon.active == 0 ||
	    !(wlpd_p->smon.ActiveBitmap & MON_DRV_CMD)) {
		*pcmdidx = 0;
		pcmdbuf[0] = 0;
		return 0;
	}

	if (*pcmdidx) {

		if ((plog =
		     (void *)wl_kmalloc(WLMON_PRNT_BUF_SIZE,
					GFP_ATOMIC)) == NULL) {
			printk("Error[%s:%d]: Allocating wlmon cmd log buffer failure \n", __func__, __LINE__);
			goto exit;
		}

		SPIN_LOCK_IRQSAVE(&wlpd_p->locks.HMLock, HMLockflag);
		idx = (*pcmdidx) + 1;
		memcpy(plog, pcmdbuf, idx);
		pcmdbuf[0] = 0;
		*pcmdidx = 0;
		SPIN_UNLOCK_IRQRESTORE(&wlpd_p->locks.HMLock, HMLockflag);

		if (idx > WLMON_PRNT_BUF_SIZE) {
			printk("[%s:%d]:wlmon error dump run out of buffer\n",
			       __func__, __LINE__);
			BUG();
		}

		*buf = plog;
		//printk("idx=%d [%s:%d]\n",idx, __func__, __LINE__);
		return 1;

	}
exit:
	//printk("null out\n");
	*buf = NULL;
	return 0;

}

void
wlmon_show_thermal(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	u32 i;
	u64 ts;
	u64 ts_sec, ts_ms;
	u32 idx = wlpd_p->smon.thm_chanload_idx;
	u32 k;
	host_thm_chan_load_t *pthm;

	printk("\n[timestamp]:	  host_temperature, radio_temperature, channel_load\n");
	for (i = 0; i < MAX_SMACSTATUS_LOG_ENTRY; i++) {

		k = (idx + i) % MAX_SMACSTATUS_LOG_ENTRY;
		pthm = &wlpd_p->smon.thm_chanload[k];
		ts = pthm->timestamp;
		convert_tscale(ts, &ts_sec, &ts_ms, NULL);
		printk("[%llu.%llu]:      %u                %u              %u\n", ts_sec, ts_ms, pthm->host_temp, pthm->radio_temp, pthm->chan_load);
	}
}

int
wlmon_host_temperature_get(UINT32 * ptemp)
{
	struct thermal_zone_device *tzd;
	int temp = 0;
	int temperature = 0;

	/* Read thermal */
	tzd = thermal_zone_get_zone_by_name("cpu");
	if (thermal_zone_get_temp(tzd, &temp) == 0) {

		temperature = temp / 1000;

		//printk("thermal_zone_get_temp: %d\n", temperature);
		*ptemp = (UINT32) temperature;
		return SUCCESS;
	}

	return FAIL;
}

static int
wlmon_temperature_check(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	u64 ts;
	u32 temp = 0;		//host temperature
	u32 temperature_radio;	//radio temperature

	int ret = 0;

	if (wlpd_p->smon.active == 0)
		return 0;

	ts = xxGetTimeStamp();	//us

	if (wlpd_p->smon.ActiveBitmap & MON_TEMPERATURE) {
		mvl_status_t tmp_status;
		memset(&tmp_status, 0, sizeof(tmp_status));
		if (wlFwGetRadioStatus(netdev, &tmp_status) == SUCCESS) {

			temperature_radio =
				(tmp_status.temperature * 4935 -
				 2271500) / 10000;
			if (temperature_radio >
			    wlpd_p->smon.temperature_threshold) {
				printk("[HM]:%s temperature is too high, %d deg C\n", wlpd_p->rootdev->name, temperature_radio);
			}
		} else {
			printk("Get Radio temperature fail...\n");
			ret = 0;
			goto exit;
		}

		//get host thermal
		if (wlmon_host_temperature_get(&temp) == SUCCESS) {
			u32 idx = wlpd_p->smon.thm_chanload_idx;

			if (temp > wlpd_p->smon.temperature_threshold_host) {
				printk("[HM]:%s host temperature is over threshold, %d deg C\n", wlpd_p->rootdev->name, temp);
			}

			wlpd_p->smon.thm_chanload_idx =
				(idx + 1) % MAX_SMACSTATUS_LOG_ENTRY;
			wlpd_p->smon.thm_chanload[idx].timestamp = ts;
			wlpd_p->smon.thm_chanload[idx].chan_load =
				tmp_status.total_load;
			wlpd_p->smon.thm_chanload[idx].host_temp = temp;
			wlpd_p->smon.thm_chanload[idx].radio_temp =
				temperature_radio;
		} else {
			printk("Get host temperature fal...\n");
		}
	}

exit:
	return 0;
}

static void
wlmon_collect_active_interfaces(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	UINT32 idx;

	wlpd_p->smon.lastActVapBitmap = wlpd_p->smon.ActVapBitmap;
	wlpd_p->smon.ActiveIf = 0;
	wlpd_p->smon.ActVapBitmap = 0;

	if (wlpd_p->smon.active == 0)
		return;

	//printk("%s:%d\n", __func__, __LINE__);

	//TODO:
	for (idx = 0; idx <= wlpd_p->NumOfAPs; idx++) {

		if (wlpptr->vdev[idx] != NULL &&
		    (wlpptr->vdev[idx]->flags & IFF_RUNNING)) {
			struct net_device *vdev = wlpptr->vdev[idx];
			struct wlprivate *wlp =
				NETDEV_PRIV(struct wlprivate, vdev);

			if (wlp->vmacSta_p->OpMode == WL_OP_MODE_VAP) {
				wlpd_p->smon.ActiveIf |= WL_OP_MODE_VAP;
				wlpd_p->smon.ActVapBitmap |= (1 << idx);
			} else if (wlp->vmacSta_p->OpMode == WL_OP_MODE_VSTA)
				wlpd_p->smon.ActiveIf |= WL_OP_MODE_VSTA;
		}
	}

}

int
sprintf_hex_dump(u8 * pdest, u8 * psrc, UINT32 maxlen, UINT32 maxbuflen)
{
	int i;
	int idx = 0;
	u8 *p = psrc;

	for (i = 0; i < maxlen; i++) {

		if ((i % 16) == 0) {
			idx += sprintf(&pdest[idx], "\n[%04x]:", i);
		}

		idx += sprintf(&pdest[idx], "%02x ", p[i]);

		if (idx > (maxbuflen - 16))
			break;
	}

	idx += sprintf(&pdest[idx], "\n");
	return idx;
}

static int
sprintSmacStatus(u8 * pdest, SMAC_STATUS_st * pSMACStatus, UINT32 maxlen,
		 UINT32 format)
{
	int idx = 0;
	int i, k;

	if (format & SMAC_STATUS_FORMAT_RAW) {
		u8 *p;
		idx += sprintf(&pdest[idx], "mac status dump:[0x400~0x7FF]\n");
		p = (u8 *) pSMACStatus;
		for (i = 0; i < sizeof(SMAC_STATUS_st); i++) {
			if (i % 16 == 0) {
				idx += sprintf(&pdest[idx], "\n[%04x]:",
					       (0x400 + i));
			}
			idx += sprintf(&pdest[idx], "%02x ", p[i]);
		}

	}

	if (format & SMAC_STATUS_FORMAT_TXT) {
		SMAC_STATUS_st *p;

		idx += sprintf(&pdest[idx], "\nMAC STATUS:\n");
		p = pSMACStatus;

		idx += sprintf(&pdest[idx], " 0x400: SMAC Ready:\n");
		for (i = 0, k = 0; i < 1; i++) {
			idx += sprintf(&pdest[idx],
				       "%08x: %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x \n",
				       (i * 16), p->smacRdy[k],
				       p->smacRdy[k + 1], p->smacRdy[k + 2],
				       p->smacRdy[k + 3], p->smacRdy[k + 4],
				       p->smacRdy[k + 5], p->smacRdy[k + 6],
				       p->smacRdy[k + 7], p->smacRdy[k + 8],
				       p->smacRdy[k + 9], p->smacRdy[k + 10],
				       p->smacRdy[k + 11]);
		}

		idx += sprintf(&pdest[idx], " 0x40C: smacDmemVer %u\n",
			       p->smacDmemVer);
		idx += sprintf(&pdest[idx], " 0x40E: smacDmemLen %u\n",
			       p->smacDmemLen);

		idx += sprintf(&pdest[idx], " 0x410: verCtrl:\n");
		for (i = 0, k = 0; i < 1; i++, k += 4) {
			idx += sprintf(&pdest[idx],
				       "%08x: %08x %08x %08x %08x\n", (i * 16),
				       p->verCtrl[k], p->verCtrl[k + 1],
				       p->verCtrl[k + 2], p->verCtrl[k + 3]);
		}

		idx += sprintf(&pdest[idx],
			       " 0x420: txInputCnt %u\ttxSchedCnt %u\ttxProcCnt %u\ttxBufRetCnt %u\n",
			       p->txInputCnt, p->txSchedCnt, p->txProcCnt,
			       p->txBufRetCnt);

		idx += sprintf(&pdest[idx],
			       " 0x430: txAcRingCnt %u\ttxCtlFrmCnt %u\ttxEuDoneCnt %u\ttxRdyDeassert %u\n",
			       p->txAcRingCnt, p->txCtlFrmCnt, p->txEuDoneCnt,
			       p->txRdyDeassert);

		idx += sprintf(&pdest[idx],
			       " 0x440: sop_EvtMacHdr %u\teop_EvtEuDone %u\tfcs_EvtFcs %u\teop2_Q2RxAmsdu %u\n",
			       p->sop_EvtMacHdr, p->eop_EvtEuDone,
			       p->fcs_EvtFcs, p->eop2_Q2RxAmsdu);

		idx += sprintf(&pdest[idx],
			       " 0x450: sop_EuPrgm %u\teopDrp_EuErr %u\tfcsDrp_FcsErr %u\teop2Drp_Cnt %u\n",
			       p->sop_EuPrgm, p->eopDrp_EuErr, p->fcsDrp_FcsErr,
			       p->eop2Drp_Cnt);

		idx += sprintf(&pdest[idx],
			       " 0x460: uniPktCnt %u\tmultiPktCnt %u\tbman_GetBuf %u\tbman_RetBuf %u\n",
			       p->fcs_UniMCast[0], p->fcs_UniMCast[1],
			       p->bman_GetBuf, p->bman_RetBuf);

		idx += sprintf(&pdest[idx],
			       " 0x470: slotTickCnt %u\tfirstSlotTickCnt %u\ttxMgmPktCnt %u\ttxBcnCnt %u\n",
			       p->slotTickCnt, p->firstSlotTickCnt,
			       p->txMgmPktCnt, p->txBcnCnt);

		idx += sprintf(&pdest[idx], " 0x480: debug log1:\n");
		for (i = 0, k = 0; i < 1; i++, k += 4) {
			idx += sprintf(&pdest[idx],
				       "%08x: %08x %08x %08x %08x\n", (i * 16),
				       p->sysRsvd1[k], p->sysRsvd1[k + 1],
				       p->sysRsvd1[k + 2], p->sysRsvd1[k + 3]);
		}

		idx += sprintf(&pdest[idx], " 0x490: TXD1 counts:\n");
		for (i = 0, k = 0; i < 1; i++, k += 4) {
			idx += sprintf(&pdest[idx],
				       "%08x: %08x %08x %08x %08x\n", (i * 16),
				       p->sysRsvd2[k], p->sysRsvd2[k + 1],
				       p->sysRsvd2[k + 2], p->sysRsvd2[k + 3]);
		}

		idx += sprintf(&pdest[idx],
			       " 0x4a0: PGM %u, DONE %u, MSDU %u, MPDU %u\n",
			       p->sysRsvd3[0], p->sysRsvd3[1], p->sysRsvd3[2],
			       p->sysRsvd3[3]);

		idx += sprintf(&pdest[idx], " 0x4b0: TXD5 counts:\n");
		for (i = 0, k = 0; i < 1; i++, k += 4) {
			idx += sprintf(&pdest[idx],
				       "%08x: %08x %08x %08x %08x\n", (i * 16),
				       p->sysRsvd4[k], p->sysRsvd4[k + 1],
				       p->sysRsvd4[k + 2], p->sysRsvd4[k + 3]);
		}

		idx += sprintf(&pdest[idx], " 0x4c0: debug log2:\n");
		for (i = 0, k = 0; i < 1; i++, k += 4) {
			idx += sprintf(&pdest[idx],
				       "%08x: %08x %08x %08x %08x\n", (i * 16),
				       p->sysRsvd5[k], p->sysRsvd5[k + 1],
				       p->sysRsvd5[k + 2], p->sysRsvd5[k + 3]);
		}

		idx += sprintf(&pdest[idx], " 0x4d0: sysRsvd6:\n");
		for (i = 0, k = 0; i < 3; i++, k += 4) {
			idx += sprintf(&pdest[idx],
				       "%08x: %08x %08x %08x %08x\n", (i * 16),
				       p->sysRsvd6[k], p->sysRsvd6[k + 1],
				       p->sysRsvd6[k + 2], p->sysRsvd6[k + 3]);
		}

		idx += sprintf(&pdest[idx], " 0x500: MAC status:\n");
		for (i = 0, k = 0; i < 3; i++, k += 4) {
			idx += sprintf(&pdest[idx],
				       "%08x: %08x %08x %08x %08x\n", (i * 16),
				       p->smacSts[k], p->smacSts[k + 1],
				       p->smacSts[k + 2], p->smacSts[k + 3]);
		}
		idx += sprintf(&pdest[idx], "%08x: %08x %08x %08x %08x\n",
			       (i * 16), p->sysRsvd7[0], p->sysRsvd7[1],
			       p->txAcntNoADMA, p->rxAcntNoADMA);

		idx += sprintf(&pdest[idx],
			       " 0x540: sopDrp_GiantPkt %u, txStopAck %u, lastTxInfoErr %u, bmanErr_GetBuf %u,%u,%u,%u\n",
			       p->sopDrp_GiantPkt, p->txStopAck,
			       p->lastTxInfoErr, p->bmanErr_GetBuf[0],
			       p->bmanErr_GetBuf[1], p->bmanErr_GetBuf[2],
			       p->bmanErr_GetBuf[3]);

		idx += sprintf(&pdest[idx], " 0x550: eopDrp_EmptyBuf %u\n",
			       p->eopDrp_EmptyBuf);

		idx += sprintf(&pdest[idx],
			       " 0x560: txDataTxMsduCnt %u, txDataBufRetMsduCnt %u, txMgtTxMsduCnt %u, txMgtBufRetMsduCnt %u\n",
			       p->txDataTxMsduCnt, p->txDataBufRetMsduCnt,
			       p->txMgtTxMsduCnt, p->txMgtBufRetMsduCnt);

		idx += sprintf(&pdest[idx],
			       " 0x570: bman_StsReqBp %u, maxSizeBcnbuf %u, rxSBinfoBaseAddr %xh, rxSBinfoUnitSize %u\n",
			       p->bman_StsReqBp, p->maxSizeBcnbuf,
			       p->rxSBinfoBaseAddr, p->rxSBinfoUnitSize);
		idx += sprintf(&pdest[idx], " 0x580: sysRsvd9:\n");
		for (i = 0, k = 0; i < 4; i++, k += 4) {
			idx += sprintf(&pdest[idx],
				       "%08x: %08x %08x %08x %08x\n", (i * 16),
				       p->sysRsvd9[k], p->sysRsvd9[k + 1],
				       p->sysRsvd9[k + 2], p->sysRsvd9[k + 3]);
		}

		idx += sprintf(&pdest[idx], " 0x5c0: sysRsvd10:\n");
		for (i = 0, k = 0; i < 2; i++, k += 4) {
			idx += sprintf(&pdest[idx],
				       "%08x: %08x %08x %08x %08x\n", (i * 16),
				       p->sysRsvd10[k], p->sysRsvd10[k + 1],
				       p->sysRsvd10[k + 2],
				       p->sysRsvd10[k + 3]);
		}
		idx += sprintf(&pdest[idx],
			       "0x5E0: TStxPeRise %x, TStxRdyFall %x, TStxSum_H %x, TSsys_H %x, TStxSum %x\n",
			       p->TStxPeRise, p->TStxRdyFall, p->TStxSum_H,
			       p->TSsys_H, p->TStxSum);

		idx += sprintf(&pdest[idx], "0x5F0: %08x %08x %08x %08x\n",
			       p->sysRsvdBB[0], p->sysRsvdBB[1],
			       p->sysRsvdBB[2], p->sysRsvdBB[3]);
		idx += sprintf(&pdest[idx], "0x600: %08x %08x %08x %08x\n",
			       p->sysRsvdMU0[0], p->sysRsvdMU0[1],
			       p->sysRsvdMU0[2], p->sysRsvdMU0[3]);

		idx += sprintf(&pdest[idx], " 0x610: sysRsvdMU:\n");
		for (i = 0, k = 0; i < 3; i++, k += 4) {
			idx += sprintf(&pdest[idx],
				       "%08x: %08x %08x %08x %08x\n", (i * 16),
				       p->sysRsvdMU[k], p->sysRsvdMU[k + 1],
				       p->sysRsvdMU[k + 2],
				       p->sysRsvdMU[k + 3]);
		}

		idx += sprintf(&pdest[idx], " 0x640: sysRsvd11:\n");
		for (i = 0, k = 0; i < 4; i++, k += 4) {
			idx += sprintf(&pdest[idx],
				       "%08x: %08x %08x %08x %08x\n", (i * 16),
				       p->sysRsvd11[k], p->sysRsvd11[k + 1],
				       p->sysRsvd11[k + 2],
				       p->sysRsvd11[k + 3]);
		}

		idx += sprintf(&pdest[idx], " 0x680: sysRsvd12:\n");
		for (i = 0, k = 0; i < 1; i++, k += 4) {
			idx += sprintf(&pdest[idx],
				       "%08x: %08x %08x %08x %08x\n", (i * 16),
				       p->sysRsvd12[k], p->sysRsvd12[k + 1],
				       p->sysRsvd12[k + 2],
				       p->sysRsvd12[k + 3]);
		}

		idx += sprintf(&pdest[idx], " 0x690: CSI Information:\n");
		idx += sprintf(&pdest[idx],
			       "CSI_Pkt_RAW_RSSI - AB: %d CD: %d EF: %d GH: %d\n",
			       pSMACStatus->CSI_RSSI_AB,
			       pSMACStatus->CSI_RSSI_CD,
			       pSMACStatus->CSI_RSSI_EF,
			       pSMACStatus->CSI_RSSI_GH);
		idx += sprintf(&pdest[idx],
			       "CSI_Pkt_MAC_Addr - %02x:%02x:%02x:%02x:%02x:%02x\n",
			       pSMACStatus->CSI_Pkt_MAC_Addr[0],
			       pSMACStatus->CSI_Pkt_MAC_Addr[1],
			       pSMACStatus->CSI_Pkt_MAC_Addr[2],
			       pSMACStatus->CSI_Pkt_MAC_Addr[3],
			       pSMACStatus->CSI_Pkt_MAC_Addr[4],
			       pSMACStatus->CSI_Pkt_MAC_Addr[5]);
		idx += sprintf(&pdest[idx], "CSI_Pkt_Type - 0x%x\n",
			       pSMACStatus->CSI_Pkt_Type);
		idx += sprintf(&pdest[idx], "CSI_Pkt_SubType - 0x%x\n",
			       pSMACStatus->CSI_Pkt_SubType);
		idx += sprintf(&pdest[idx], "CSI_TX_Timestamp - 0x%x\n",
			       p->CSI_TX_Timestamp);
		idx += sprintf(&pdest[idx], "CSI_RX_Timestamp_Lo - 0x%x\n",
			       p->CSI_RX_Timestamp_Lo);
		idx += sprintf(&pdest[idx], "CSI_RX_Timestamp_Hi - 0x%x\n",
			       p->CSI_RX_Timestamp_Hi);
		idx += sprintf(&pdest[idx], "CSI_CFO - 0x%x\n", p->CSI_CFO);
		idx += sprintf(&pdest[idx], "CSI_reserved1 - 0x%x\n",
			       p->CSI_reserved1);
		idx += sprintf(&pdest[idx], "CSI_DTA - 0x%x\n", p->CSI_DTA);
		idx += sprintf(&pdest[idx], "CSI_Valid - 0x%x\n", p->CSI_Valid);
		idx += sprintf(&pdest[idx], "CSI_Count - 0x%x\n", p->CSI_Count);
		idx += sprintf(&pdest[idx], "CSI_reserved2 - 0x%x\n",
			       p->CSI_reserved2);

		idx += sprintf(&pdest[idx], " 0x6B8: CM3 Start / Stop Flag:\n");
		idx += sprintf(&pdest[idx], "%08x %08x\n", p->cm3StartFlag,
			       p->cm3StopFlag);

		idx += sprintf(&pdest[idx], " 0x6c0: txBcnCntBss:\n");
		for (i = 0, k = 0; i < 4; i++, k += 8) {
			idx += sprintf(&pdest[idx],
				       "%08x: %04x %04x %04x %04x : %04x %04x %04x %04x\n",
				       (i * 16), p->txBcnCntBss[k],
				       p->txBcnCntBss[k + 1],
				       p->txBcnCntBss[k + 2],
				       p->txBcnCntBss[k + 3],
				       p->txBcnCntBss[k + 4],
				       p->txBcnCntBss[k + 5],
				       p->txBcnCntBss[k + 6],
				       p->txBcnCntBss[k + 7]);
		}

		idx += sprintf(&pdest[idx], " 0x700: lastCm3Event:\n");
		for (i = 0; i < 7; i++) {
			idx += sprintf(&pdest[idx], "CM3-%d %02x\n", i,
				       p->lastCm3Event[i]);
		}

		idx += sprintf(&pdest[idx], " 0x710: Rsvd:\n");
		for (i = 0, k = 0; i < (sizeof(p->rsvd) / 16); i++, k += 16) {
			idx += sprintf(&pdest[idx],
				       "%08x: %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x\n",
				       (i * 16), p->rsvd[k], p->rsvd[k + 1],
				       p->rsvd[k + 2], p->rsvd[k + 3],
				       p->rsvd[k + 4], p->rsvd[k + 5],
				       p->rsvd[k + 6], p->rsvd[k + 7],
				       p->rsvd[k + 8], p->rsvd[k + 9],
				       p->rsvd[k + 10], p->rsvd[k + 11],
				       p->rsvd[k + 12], p->rsvd[k + 13],
				       p->rsvd[k + 14], p->rsvd[k + 15]);
		}
	}

	idx += sprintf(&pdest[idx], "\n");

	if (idx > maxlen) {
		printk("[%s,%d]:wlmon error dump run out of buffer\n", __func__,
		       __LINE__);
		BUG();
	}

	return idx;

}

int
IsBssBcnStuck(struct net_device *netdev, UINT32 * bssbitmap, U64 * maxstuckivl)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	SMAC_STATUS_st *pLast = (SMAC_STATUS_st *) wlpd_p->smon.psmacStatus;
	SMAC_STATUS_st *pCur = &pLast[1];
	UINT32 idx = 0;
	UINT32 map;
	UINT32 nonxmitmap;
	UINT64 tms;

	*bssbitmap = 0;		//output stuck bss bitmap
	*maxstuckivl = 0;	//output max time interval of stuck BSSs

	if (wlpd_p->smon.active == 0 || wlpd_p->smon.ActVapBitmap == 0)
		return 0;

	map = (wlpd_p->smon.ActVapBitmap & wlpd_p->smon.lastActVapBitmap);

	//rule out non-beaconing bssids in non-transmitted BSSID profile.
	nonxmitmap = get_mbssid_profile((void *)wlpd_p, 0);
	//only keep xmit mbssid profile and individual bssid
	map &= ~nonxmitmap;
	//printk("hm:txbcnmap:0x%x\n", map);

	convert_tscale(xxGetTimeStamp(), NULL, &tms, NULL);

	while (map) {

		if (map & 0x1) {

			if (pLast->txBcnCntBss[idx] &&
			    (pCur->txBcnCntBss[idx] == pLast->txBcnCntBss[idx])
			    && !wlpd_p->bStopBcnProbeResp) {
				*bssbitmap |= (1 << idx);
				wlpd_p->smon.bcnstuckcnt[idx]++;	//stuck counter
				if (wlpd_p->smon.bcnstucktimestamp[idx] == 0)	//handle corner case in case vap is just started.
					wlpd_p->smon.bcnstucktimestamp[idx] =
						tms;
				else {
					UINT64 diff =
						tms -
						wlpd_p->smon.
						bcnstucktimestamp[idx];

					if (diff > *maxstuckivl)
						*maxstuckivl = diff;
				}

			} else {
				//No stuck
				wlpd_p->smon.bcnstuckcnt[idx] = 0;
				wlpd_p->smon.bcnstucktimestamp[idx] = tms;	//reset to current tms                                
			}

		} else {
			//not active VAP, invalidate this BSS record;
			wlpd_p->smon.bcnstuckcnt[idx] = 0;
			wlpd_p->smon.bcnstucktimestamp[idx] = 0;
		}

		idx++;
		map = map >> 1;
	}

	return ((*bssbitmap) ? 1 : 0);
}

int
wlmon_beacon_stuck_detct(struct net_device *netdev,
			 SMAC_STATUS_st * pCurSmacStatus, void **buf)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
	char *plog = NULL;
	UINT64 ts, ts_sec, ts_ms;
	int bssstuck = 0;
	UINT32 bssbitmap = 0;

	if (wlpd_p->smon.active == 0 ||
	    !(wlpd_p->smon.ActiveBitmap & MON_SMAC_BCN_STUCK))
		return 0;
	if ((vmacSta_p->preautochannelfinished == 0) &&
	    (*(mib->mib_autochannel) != 0)) {
		/* healthmonitor should ignore beacon stuck detect during ACS scan. */
		return 0;
	}
	if (wlpd_p->smon.ActiveIf & WL_OP_MODE_VAP) {
		//monitor beacon tx stuck
		SMAC_STATUS_st *pLast =
			(SMAC_STATUS_st *) wlpd_p->smon.psmacStatus;
		UINT64 tdif = 0;
		int idx = 0;

		tdif = wlpd_p->smon.smacStsLogtime[1] -
			wlpd_p->smon.smacStsLogtime[0];
		if ((bssstuck = IsBssBcnStuck(netdev, &bssbitmap, &tdif)) &&	//same tx bss beacon cnt
		    tdif > BCN_STUCK_THRESHOLD &&	//measure interval > 50000 ms
		    wlpd_p->smon.smacStsLogtime[0] != 0 &&	//bypass initial corner case
		    pLast->txBcnCnt != 0) {	//bypass inital corner case

			//bcn stuck already hit before, no more dump again
			if (wlpd_p->smon.bcnstuck_st)
				goto exit;

			if ((plog =
			     (void *)wl_kmalloc(WLMON_PRNT_BUF_SIZE,
						GFP_ATOMIC)) == NULL) {
				printk("Error[%s:%d]: Allocating wlmon buffer failure \n", __func__, __LINE__);
				goto exit;
			}

			ts = xxGetTimeStamp();	//us
			convert_tscale(ts, &ts_sec, &ts_ms, NULL);

			if (bssstuck) {
				idx += sprintf(&plog[idx],
					       "[%llu.%llu] BSS Beacon stuck alarm: Stuck VAPs Bitmap:%08x \n",
					       ts_sec, ts_ms, bssbitmap);
			} else {
				idx += sprintf(&plog[idx],
					       "[%llu.%llu] Beacon stuck alarm: \n",
					       ts_sec, ts_ms);
			}

			if (idx > WLMON_PRNT_BUF_SIZE) {
				printk("[%s,%d]:wlmon error dump run out of buffer\n", __func__, __LINE__);
				BUG();
			}

			*buf = plog;

			wlpd_p->smon.bcnstuck_st = 1;
			return 1;
		} else
			wlpd_p->smon.bcnstuck_st = 0;

	}
exit:
	*buf = NULL;
	return 0;

}

int
wlmon_tx_stuck_detct(struct net_device *netdev, SMAC_STATUS_st * pCurSmacStatus,
		     void **buf)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	UINT32(*txdiff)[NUM_SFWTX_CHK_POINTS] = wlpd_p->smon.TxPktDiff;
	UINT32 TxPktIdx = wlpd_p->smon.TxPktIdx;
	char *plog = NULL;
	UINT64 ts, ts_sec, ts_ms;
	//UINT32  format = wlpd_p->smon.smacStatusFormat;

	if (wlpd_p->smon.active == 0 ||
	    !(wlpd_p->smon.ActiveBitmap & MON_SMAC_TX_STUCK))
		return 0;

	if (wlpd_p->smon.ActiveIf) {
		//monitor beacon tx stuck
		SMAC_STATUS_st *pLast =
			(SMAC_STATUS_st *) wlpd_p->smon.psmacStatus;
		int idx = 0;
		int i, j;
		UINT32 sum[NUM_SFWTX_CHK_POINTS];

		txdiff[TxPktIdx][0] =
			(pCurSmacStatus->txInputCnt >=
			 pLast->txInputCnt) ? (pCurSmacStatus->txInputCnt -
					       pLast->
					       txInputCnt) : (pCurSmacStatus->
							      txInputCnt +
							      ~pLast->
							      txInputCnt + 1);
		txdiff[TxPktIdx][1] =
			(pCurSmacStatus->txAcRingCnt >=
			 pLast->txAcRingCnt) ? (pCurSmacStatus->txAcRingCnt -
						pLast->
						txAcRingCnt) : (pCurSmacStatus->
								txAcRingCnt +
								~pLast->
								txAcRingCnt +
								1);
		txdiff[TxPktIdx][2] =
			(pCurSmacStatus->txSchedCnt >=
			 pLast->txSchedCnt) ? (pCurSmacStatus->txSchedCnt -
					       pLast->
					       txSchedCnt) : (pCurSmacStatus->
							      txSchedCnt +
							      ~pLast->
							      txSchedCnt + 1);
		txdiff[TxPktIdx][3] =
			(pCurSmacStatus->txProcCnt >=
			 pLast->txProcCnt) ? (pCurSmacStatus->txProcCnt -
					      pLast->
					      txProcCnt) : (pCurSmacStatus->
							    txProcCnt +
							    ~pLast->txProcCnt +
							    1);
		txdiff[TxPktIdx][4] =
			(pCurSmacStatus->txEuDoneCnt >=
			 pLast->txEuDoneCnt) ? (pCurSmacStatus->txEuDoneCnt -
						pLast->
						txEuDoneCnt) : (pCurSmacStatus->
								txEuDoneCnt +
								~pLast->
								txEuDoneCnt +
								1);
		txdiff[TxPktIdx][5] =
			(pCurSmacStatus->txBufRetCnt >=
			 pLast->txBufRetCnt) ? (pCurSmacStatus->txBufRetCnt -
						pLast->
						txBufRetCnt) : (pCurSmacStatus->
								txBufRetCnt +
								~pLast->
								txBufRetCnt +
								1);
		wlpd_p->smon.TxPktIdx = (TxPktIdx + 1) % NUM_SFWTX_RECORDS;

		memset((void *)sum, 0, sizeof(sum));

		//sum all txdiff values 
		for (i = 0; i < NUM_SFWTX_CHK_POINTS; i++) {
			for (j = 0; j < NUM_SFWTX_RECORDS; j++)
				sum[i] += txdiff[j][i];
		}

		if (txdiff[TxPktIdx][0]) {

			for (i = 1; i < NUM_SFWTX_CHK_POINTS; i++) {

				/* a counter that has been no change during the last 4 records
				   It might be a stuck. If txInputCnt still keep increasing during the last 4 records, it is considered to be a stuck.
				 */
				if (sum[i] == 0 && sum[0] > txdiff[TxPktIdx][0]) {

					if (wlpd_p->smon.txstuck_st)	//alreday detect tx stuck before, skip dumping 
						goto exit;

					if ((plog =
					     (void *)
					     wl_kmalloc(WLMON_PRNT_BUF_SIZE,
							GFP_ATOMIC)) == NULL) {
						printk("Error[%s:%d]: Allocating wlmon buffer failure \n", __func__, __LINE__);
						goto exit;
					}

					ts = xxGetTimeStamp();	//us
					convert_tscale(ts, &ts_sec, &ts_ms,
						       NULL);

					idx += sprintf(&plog[idx],
						       "[%llu.%llu] Tx stuck alarm: \n",
						       ts_sec, ts_ms);

					idx += sprintf(&plog[idx], "\n");

					if (idx > WLMON_PRNT_BUF_SIZE) {
						printk("[%s,%d]:wlmon error dump run out of buffer\n", __func__, __LINE__);
						BUG();
					}

					*buf = plog;
					wlpd_p->smon.txstuck_st = 1;
					//printk("idx=%d [%s:%d]\n",idx, __func__, __LINE__);
					return 1;
				}

			}

			//monitor recovery
			if (wlpd_p->smon.txstuck_st) {

				for (i = 0; i < NUM_SFWTX_CHK_POINTS && sum[i];
				     i++) ;

				if (i == NUM_SFWTX_CHK_POINTS) {
					//tx stuck might be not stuck again. fw redownload ? 
					//keep monitoring 

					printk("recovery tx stuck monitoring\n");
					wlpd_p->smon.txstuck_st = 0;
				}
			}

		}

	}

exit:
	//printk("null out\n");
	*buf = NULL;
	return 0;

}

int
wlmon_rx_stuck_detct(struct net_device *netdev, SMAC_STATUS_st * pCurSmacStatus,
		     void **buf)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	UINT32(*rxdiff)[NUM_SFWRX_CHK_POINTS] = wlpd_p->smon.RxPktDiff;
	UINT32 RxPktIdx = wlpd_p->smon.RxPktIdx;
	UINT32 RxOldIdx;
	char *plog = NULL;
	UINT64 ts, ts_sec, ts_ms;

	if (wlpd_p->smon.active == 0 ||
	    !(wlpd_p->smon.ActiveBitmap & MON_SMAC_RX_STUCK))
		return 0;

	if (wlpd_p->smon.ActiveIf) {
		//monitor beacon tx stuck
		SMAC_STATUS_st *pLast =
			(SMAC_STATUS_st *) wlpd_p->smon.psmacStatus;
		int idx = 0;
		int i, j;
		UINT32 sum[NUM_SFWRX_CHK_POINTS];

		rxdiff[RxPktIdx][0] =
			(pCurSmacStatus->sop_EvtMacHdr >=
			 pLast->sop_EvtMacHdr) ? (pCurSmacStatus->
						  sop_EvtMacHdr -
						  pLast->
						  sop_EvtMacHdr)
			: (pCurSmacStatus->sop_EvtMacHdr +
			   ~pLast->sop_EvtMacHdr + 1);
		rxdiff[RxPktIdx][1] =
			(pCurSmacStatus->sop_EuPrgm >=
			 pLast->sop_EuPrgm) ? (pCurSmacStatus->sop_EuPrgm -
					       pLast->
					       sop_EuPrgm) : (pCurSmacStatus->
							      sop_EuPrgm +
							      ~pLast->
							      sop_EuPrgm + 1);
		rxdiff[RxPktIdx][2] =
			(pCurSmacStatus->eop_EvtEuDone >=
			 pLast->eop_EvtEuDone) ? (pCurSmacStatus->
						  eop_EvtEuDone -
						  pLast->
						  eop_EvtEuDone)
			: (pCurSmacStatus->eop_EvtEuDone +
			   ~pLast->eop_EvtEuDone + 1);
		rxdiff[RxPktIdx][3] =
			(pCurSmacStatus->eop2_Q2RxAmsdu >=
			 pLast->eop2_Q2RxAmsdu) ? (pCurSmacStatus->
						   eop2_Q2RxAmsdu -
						   pLast->
						   eop2_Q2RxAmsdu)
			: (pCurSmacStatus->eop2_Q2RxAmsdu +
			   ~pLast->eop2_Q2RxAmsdu + 1);
		rxdiff[RxPktIdx][4] =
			(pCurSmacStatus->eop2Drp_Cnt >=
			 pLast->eop2Drp_Cnt) ? (pCurSmacStatus->eop2Drp_Cnt -
						pLast->
						eop2Drp_Cnt) : (pCurSmacStatus->
								eop2Drp_Cnt +
								~pLast->
								eop2Drp_Cnt +
								1);

		wlpd_p->smon.RxPktIdx = (RxPktIdx + 1) % NUM_SFWRX_RECORDS;

		memset((void *)sum, 0, sizeof(sum));
		//sum all txdiff values 
		for (i = 0; i < NUM_SFWRX_CHK_POINTS; i++) {

			for (j = 0; j < NUM_SFWRX_RECORDS; j++)
				sum[i] += rxdiff[j][i];
		}

		//the oldest index in recoreds.
		RxOldIdx = wlpd_p->smon.RxPktIdx;

		if (rxdiff[RxOldIdx][0]) {

			for (i = 1; i < NUM_SFWRX_CHK_POINTS - 1; i++) {
				/* a counter that has been no change during the last 4 records
				   It might be a stuck. If sop_EvtMacHdr still keep increasing during the last 4 records, it is considered to be a stuck.
				 */
				if (sum[i] == 0 &&
				    sum[0] > rxdiff[RxOldIdx][0] &&
				    (i != 3 || sum[4] == 0)) {

					if (wlpd_p->smon.rxstuck_st)	//alreday detect rx stuck before, skip dumping 
						goto exit;

					if ((plog =
					     (void *)
					     wl_kmalloc(WLMON_PRNT_BUF_SIZE,
							GFP_ATOMIC)) == NULL) {
						printk("Error[%s:%d]: Allocating wlmon buffer failure \n", __func__, __LINE__);
						goto exit;
					}

					ts = xxGetTimeStamp();	//us
					convert_tscale(ts, &ts_sec, &ts_ms,
						       NULL);
					idx += sprintf(&plog[idx],
						       "[%llu.%llu] Rx stuck warning: \n",
						       ts_sec, ts_ms);

					idx += sprintf(&plog[idx], "\n");

					if (idx > WLMON_PRNT_BUF_SIZE) {
						printk("[%s,%d]:wlmon error dump run out of buffer\n", __func__, __LINE__);
						BUG();
					}

					*buf = plog;
					wlpd_p->smon.rxstuck_st = 1;
					return 1;
				}

			}

			//monitor recovery
			if (wlpd_p->smon.rxstuck_st) {

				for (i = 0;
				     i < NUM_SFWRX_CHK_POINTS - 1 && sum[i];
				     i++) ;

				if (i == NUM_SFWRX_CHK_POINTS - 1) {
					//rx stuck might be not stuck again. fw redownload ? 
					//keep monitoring 
					printk("recovery rx stuck monitoring\n");
					wlpd_p->smon.rxstuck_st = 0;
				}
			}

		}
	}
exit:
	//printk("null out\n");
	*buf = NULL;
	return 0;
}

#define LAST_CMD_FW_PROCESSED_OFFSET 0x12383C
void
wlmon_dbg_show_last_cmd_fw_processed(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	void *addr[1];

	addr[0] = (wlpptr->ioBase0 + LAST_CMD_FW_PROCESSED_OFFSET);
	printk("[HM]: LAST_CMD_FW_PROCESSED:[0x2012383C]=0x%08x\n",
	       wl_util_readl(netdev, addr[0]));
}

void
wlmon_dbg_show_alivecnt(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	U32 index = wlpd_p->smon.smacStatusLogIdx;
	U32 i;

	printk("pfw_alive_counters:\n");
	for (i = 0; i < MAX_SMACSTATUS_LOG_ENTRY; i++) {
		printk("cmd_thread: %u, sche_thread: %u, idle_thread: %u\n",
		       wlpd_p->smon.pfwaliveCnt[0].alivecnt[index],
		       wlpd_p->smon.pfwaliveCnt[1].alivecnt[index],
		       wlpd_p->smon.pfwaliveCnt[2].alivecnt[index]);

		index = (index + 1) % MAX_SMACSTATUS_LOG_ENTRY;
	}
}

int
wlmon_dbg_mem_usage_check(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	struct sysinfo val;
	static int memUsed = 0;

	if (wlpd_p->smon.active == 0 ||
	    !(wlpd_p->smon.ActiveBitmap & MON_MEM_USAGE))
		return 0;

	si_meminfo(&val);

	if (val.freeram <= (val.totalram * 20 / 100)) {
		if (memUsed < 0x04) {
			printk("[HM]: Available memory < 20%%\n");
			memUsed = 0x04;
			return 1;
		}
	} else if (val.freeram <= (val.totalram * 30 / 100)) {
		if (memUsed < 0x3) {
			printk("[HM]: Available memory < 30%%\n");
			memUsed = 0x3;
		}
	} else if (val.freeram <= (val.totalram * 40 / 100)) {
		if (memUsed < 0x2) {
			printk("[HM]: Available memory < 40%%\n");
			memUsed = 0x2;
		}
	} else if (val.freeram <= (val.totalram * 50 / 100)) {
		if (memUsed < 0x1) {
			printk("[HM]: Available memory < 50%%\n");
			memUsed = 0x1;
		}
	}

	return 0;
}

void
wlmon_dbg_show_adma_cmd_status(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	void *addr[4];

	//dump some ADMA/EU registers
#define ADMA_STUCK_CHK_ADDR  0x123830
#define CMD_CMP_CHK_ADDR     0x123838
#define EU_FABRIC_STATUS     0x1ABA8
#define EU_SM_STATUS         0x1C2F4

	if (wlpd_p->bus_type == BUS_TYPE_MCI) {

		addr[0] = (wlpptr->ioBase0 + ADMA_STUCK_CHK_ADDR);
		addr[1] = (wlpptr->ioBase0 + CMD_CMP_CHK_ADDR);
		printk("ADMA:[0x20123830]=0x%08x\n", wl_util_readl(netdev, addr[0]));
		printk("CmdStatus:[0x20123838]=%08x\n", wl_util_readl(netdev, addr[1]));
	} else {

		u32 *pbuf = NULL;

		if ((pbuf = (u32 *) wl_kmalloc(1024, GFP_KERNEL))) {

			if (!wlFwGetAddrValue
			    (netdev, (SMAC_DMEM_START + ADMA_STUCK_CHK_ADDR), 4,
			     pbuf, 0)) {
				printk("%x %x %x %x\n", pbuf[0], pbuf[1],
				       pbuf[2], pbuf[3]);
				printk("ADMA:[0x20123830]=0x%08x\n", pbuf[0]);
				printk("CmdStatus:[0x20123838]=%08x\n",
				       pbuf[2]);
			}
			wl_kfree(pbuf);
		}
	}

	addr[2] = (wlpptr->ioBase1 + EU_FABRIC_STATUS);
	addr[3] = (wlpptr->ioBase1 + EU_SM_STATUS);

	printk("EU FABRIC:[0x9001ABA8]=0x%08x\n", wl_util_readl(netdev, addr[2]));
	printk("EU SM:[0x9001C2F4]=0x%08x\n", wl_util_readl(netdev, addr[3]));
}

int
wlmon_pfw_alive_counters_detct(struct net_device *netdev, void **buf)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	char *plog = NULL;
	UINT64 ts, ts_sec, ts_ms;

	if (wlpd_p->smon.active == 0 ||
	    !(wlpd_p->smon.ActiveBitmap & MON_PFW_ALIVE_CNTS))
		return 0;

	if (wlpd_p->smon.ActiveIf) {
		//monitor pfw alive counters stuck
		pfw_alive_cnter *pLast =
			(pfw_alive_cnter *) wlpd_p->smon.pfwaliveCnt;
		int idx = 0;
		int i;
		UINT32 newcnt[3];
		void *pfwdbgstate;
		UINT32 dmemaddr;
		U32 index =
			(wlpd_p->smon.smacStatusLogIdx +
			 4) % MAX_SMACSTATUS_LOG_ENTRY;
		U32 index_last =
			(wlpd_p->smon.smacStatusLogIdx +
			 3) % MAX_SMACSTATUS_LOG_ENTRY;

		if (wlpptr->wlpd_p->bus_type == BUS_TYPE_MCI) {	//MOCHI 

			dmemaddr = wl_util_readl(netdev, wlpptr->ioBase1 + wlpptr->wlpd_p->reg.FwDbgStateAddr) - SMAC_DMEM_START;
			pfwdbgstate = (void *)(wlpptr->ioBase0 + dmemaddr);
			memcpy((void *)newcnt,
			       (void *)(pfwdbgstate + PFW_ALIVE_CNT_OFFSET),
			       sizeof(newcnt));
		} else {	//PCIE interface
			u8 *pbuf = NULL;

#define DMEM_DEBUG_START_OFFSET 0x123800

			if ((pbuf = (u8 *) wl_kmalloc(1024, GFP_KERNEL))) {

				if (!wlFwGetAddrValue
				    (netdev,
				     (SMAC_DMEM_START +
				      DMEM_DEBUG_START_OFFSET), 64,
				     (u32 *) pbuf, 0)) {
					memcpy((void *)newcnt,
					       (void *)(pbuf +
							PFW_ALIVE_CNT_OFFSET),
					       sizeof(newcnt));

					//printk("--new:%u %u %u\n",newcnt[0],newcnt[1],newcnt[2]);
				} else {
					wl_kfree(pbuf);
					goto exit;
				}

				wl_kfree(pbuf);
			} else {
				goto exit;
			}

		}

		//printk("new:%u %u %u\n",newcnt[0],newcnt[1],newcnt[2]);

		for (i = 0; i < 3; i++) {
			if (newcnt[i] == pLast[i].alivecnt[index_last])
				pLast[i].stuckcnt++;
			else
				pLast[i].stuckcnt = 0;
			pLast[i].alivecnt[index] = newcnt[i];
		}

		//let it only be print once stuckcnt hit the threshold
		//in case pfw come back the counters will be cleared and recount again.
		if (pLast[0].stuckcnt == PFW_ALIVE_THRESHOLD ||
		    pLast[1].stuckcnt == PFW_ALIVE_THRESHOLD ||
		    pLast[2].stuckcnt == PFW_ALIVE_THRESHOLD) {

			if ((plog =
			     (void *)wl_kmalloc(WLMON_PRNT_BUF_SIZE,
						GFP_ATOMIC)) == NULL) {
				printk("Error[%s:%d]: Allocating wlmon buffer failure \n", __func__, __LINE__);
				goto exit;
			}

			ts = xxGetTimeStamp();	//ms
			convert_tscale(ts, &ts_sec, &ts_ms, NULL);
			if (pLast[0].stuckcnt == PFW_ALIVE_THRESHOLD) {
				idx += sprintf(&plog[idx],
					       "[%llu.%llu] PFW cmd thread stuck alarm: cmd_thread_alive:%u\n",
					       ts_sec, ts_ms,
					       pLast[0].alivecnt[index]);
			}

			if (pLast[1].stuckcnt == PFW_ALIVE_THRESHOLD) {
				idx += sprintf(&plog[idx],
					       "[%llu.%llu] PFW sche thread stuck alarm: sche_thread_alive:%u\n",
					       ts_sec, ts_ms,
					       pLast[1].alivecnt[index]);
			}

			if (pLast[2].stuckcnt == PFW_ALIVE_THRESHOLD) {
				idx += sprintf(&plog[idx],
					       "[%llu.%llu] PFW idle thread stuck alarm: idle_thread_alive:%u\n",
					       ts_sec, ts_ms,
					       pLast[2].alivecnt[index]);
			}

			if (idx > WLMON_PRNT_BUF_SIZE) {
				printk("[%s,%d]:wlmon error dump run out of buffer\n", __func__, __LINE__);
				BUG();
			}

			*buf = plog;
			return 1;
		}
	}
exit:
	*buf = NULL;
	return 0;
}

void
wlmon_log_bmq_buff_refill(struct net_device *netdev, U32 qid, U32 refill_cnt)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	bmq_refill_info *bqInfo = wlpd_p->smon.bmqInfo;
	UINT64 cts = xxGetTimeStamp();	//ms timestamp
	UINT32 idx;

	if (wlpd_p->smon.active == 0)
		return;

	if (wlpd_p->smon.ActiveIf == 0)
		return;

	//qid = 10 ~ 12 
	if (qid < SC5_BMQ_START_INDEX ||
	    qid > SC5_BMQ_START_INDEX + SC5_BMQ_NUM - 2) {
		printk("Invalid refill QID:%u\n", qid);
		return;
	}

	idx = qid - SC5_BMQ_START_INDEX;

	//inital case, only record the current timestamp and collect info from next time.
	if (bqInfo[idx].ts == 0) {
		memset((void *)&bqInfo[idx], 0, sizeof(bmq_refill_info));
		bqInfo[idx].ts = cts;
		return;
	}

	bqInfo[idx].tsivl += (cts - bqInfo[idx].ts);
	bqInfo[idx].refillcnt++;
	bqInfo[idx].buffcnt += refill_cnt;

	bqInfo[idx].lastbuffcnt = refill_cnt;	//log the buffer count of the last refill during the period
	bqInfo[idx].ts = cts;	//log the last refill timestamp
	return;

}

int
wlmon_bmq_refill_Info_dump(struct net_device *netdev, u8 * plog, U32 maxlen)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	bmq_refill_info *bqInfo = wlpd_p->smon.bmqInfo;
	UINT64 cts = xxGetTimeStamp();
	UINT32 idx = 0;
	UINT32 i;
	UINT64 ts_sec, ts_ms, ts_ims;

	convert_tscale(cts, &ts_sec, &ts_ms, NULL);
	idx += sprintf(&plog[idx], "[%llu.%llu] bmq refill Info:\n", ts_sec,
		       ts_ms);
	for (i = 0; i < 3; i++) {

		if (bqInfo[i].ts == 0)
			continue;

		convert_tscale(bqInfo[i].ts, &ts_sec, &ts_ms, NULL);

		convert_tscale(bqInfo[i].tsivl, NULL, &ts_ims, NULL);

		idx += sprintf(&plog[idx],
			       "Q[%u]:\nThe last refill timestamp:[%llu.%llu], %u buff refilled\n",
			       (i + SC5_BMQ_START_INDEX), ts_sec, ts_ms,
			       bqInfo[i].lastbuffcnt);
		idx += sprintf(&plog[idx],
			       "measuring interval:[%llu ms], refill cnt:%u, %u buff refilled\n",
			       ts_ims, bqInfo[i].refillcnt, bqInfo[i].buffcnt);
		memset((void *)&bqInfo[i], 0, sizeof(bmq_refill_info));
		bqInfo[i].ts = cts;
	}

	if (idx > maxlen) {
		printk("[%s,%d]:wlmon error dump run out of buffer\n", __func__,
		       __LINE__);
		BUG();
	}

	return idx;
}

#ifdef MOCHI_MON
UINT32
get_mci_errcnt(struct wlprivate * wlpptr)
{
	UINT32 regval;

	regval = 0x40021;
	//printk("%s(), Write %p = %08x\n", __func__, wlpptr->ioBaseExt+0x04, regval);
	wl_util_writel(wlpptr->netDev, regval, wlpptr->ioBaseExt+0x04);
	regval = wl_util_readl(wlpptr->netDev, wlpptr->ioBaseExt + 0x00);
	//printk("%s(), Read %p = %08x\n", __func__, wlpptr->ioBaseExt+0x00, regval);

	return (regval & 0xFF);
}

int
mochi_error_detect(struct net_device *netdev, void **buf)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	UINT32 newcnt = 0;
	int idx = 0;
	UINT64 ts = xxGetTimeStamp();
	char *plog = NULL;
	UINT64 ts_sec, ts_ms;

	if (wlpd_p->smon.active == 0 ||
	    !(wlpd_p->smon.ActiveBitmap & MON_MOCHI_ERROR) ||
	    wlpd_p->bus_type == BUS_TYPE_PCI)
		return 0;

	newcnt = get_mci_errcnt(wlpptr);
	if (newcnt != wlpd_p->smon.MochiErrCnt) {

		if ((plog =
		     (void *)wl_kmalloc(WLMON_PRNT_BUF_SIZE,
					GFP_ATOMIC)) == NULL) {
			printk("Error[%s:%d]: Allocating wlmon buffer failure \n", __func__, __LINE__);
			goto exit;
		}

		convert_tscale(ts, &ts_sec, &ts_ms, NULL);
		sprintf(&plog[idx], "[%llu.%llu] Mochi Error Counter: %u\n\n",
			ts_sec, ts_ms, newcnt);

		wlpd_p->smon.MochiErrCnt = newcnt;
		*buf = plog;
		return 1;
	}

exit:
	*buf = NULL;
	return 0;
}
#endif

void
wlmon_log_pfw_schInfo(struct net_device *netdev, QS_TX_SCHEDULER_INFO_t * pbuf)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	QS_TX_SCHEDULER_INFO_t *ptxsi = wlpd_p->smon.pPFWSchInfo;
	memcpy((void *)ptxsi, (void *)pbuf, sizeof(QS_TX_SCHEDULER_INFO_t));
}

int
pfw_scheduler_info_detect(struct net_device *netdev, void **buf)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	QS_TX_SCHEDULER_INFO_t *pQS_Sched = wlpd_p->smon.pPFWSchInfo;
	int i;
	UINT8 flag = 0;
	int idx = 0;
	char *plog = NULL;
	int didx = 0;
	UINT32 maxval = 0;

	if (wlpd_p->smon.active == 0 ||
	    !(wlpd_p->smon.ActiveBitmap & MON_PFW_SCHE_INFO))
		return 0;

	//request fromHM
	if (wlFwGetQueueStats(netdev, QS_GET_TX_SCHEDULER_INFO, 1, NULL) == 0) {

		for (i = 0; i < 10; i++) {

			if (pQS_Sched->debug_scheduler2[i][2] > PFW_SCHEDULE_DELAY) {	//> 10ms
				flag = 1;
				//get the max delay and store the index and value
				if (pQS_Sched->debug_scheduler2[i][2] > maxval) {
					maxval = pQS_Sched->
						debug_scheduler2[i][2];
					didx = i;
				}
			}
		}

		//to prevent log redundant information, skip the record that might be the same as last collection.
		if (flag && maxval == wlpd_p->smon.maxschdelay &&
		    didx == wlpd_p->smon.pfwidx)
			flag = 0;

		if (flag) {
			char s[12][14] = {
				"TimeoutCnt",
				"MaxAggrCnt",
				"NumMpduCnt",
				"NumMpdu   ",
				"NumByteCnt",
				"NumBytes  ",
				"TimeoutCt2",
				"          ",
				"AmpdLenMax",
				"          ",
				"          ",
				"Density   "
			};

			if ((plog =
			     (void *)wl_kmalloc(WLMON_PRNT_BUF_SIZE,
						GFP_ATOMIC)) == NULL) {
				printk("Error[%s:%d]: Allocating wlmon buffer failure \n", __func__, __LINE__);
				goto exit;
			}

			idx += sprintf(&plog[idx], "\nPFW scheduler info\n");
			for (i = 0; i < 12; i++) {
				idx += sprintf(&plog[idx], "%s:\t%10u\n", s[i],
					       ENDIAN_SWAP32((int)pQS_Sched->
							     debug_scheduler
							     [i]));
			}
			idx += sprintf(&plog[idx],
				       "\tNumMpdu   \tNumBytes  \tTimeDelay\n");
			for (i = 0; i < 10; i++) {
				idx += sprintf(&plog[idx],
					       "\t%10u\t%10u\t%10u\n",
					       ENDIAN_SWAP32((int)pQS_Sched->
							     debug_scheduler2[i]
							     [0]),
					       ENDIAN_SWAP32((int)pQS_Sched->
							     debug_scheduler2[i]
							     [1]),
					       ENDIAN_SWAP32((int)pQS_Sched->
							     debug_scheduler2[i]
							     [2]));
			}

			if (idx > WLMON_PRNT_BUF_SIZE) {
				printk("[%s,%d]:wlmon error dump run out of buffer\n", __func__, __LINE__);
				BUG();
			}

			wlpd_p->smon.maxschdelay = maxval;
			wlpd_p->smon.pfwidx = didx;

			*buf = plog;
			return 1;
		}

	}

exit:
	*buf = NULL;
	return 0;

}

#define ROUND_ROBIN_CMD_LOGS

#define MAX_DUMP_FILESIZE  0x4000
extern int atoi(const char *num_str);
u8 CoreDumpEndSig[] = "--end of coredump--";

u8
hm_dump_file(void *wlpd, UINT8 * valbuf, UINT32 length, UINT8 * fname,
	     UINT32 append)
{
	struct wlprivate_data *wlpd_p = (struct wlprivate_data *)wlpd;
	u64 flen = 0;
	u32 fnameid;
	u8 swNewFile = 0;	//flag to denote switch to next new file
#ifdef ROUND_ROBIN_CMD_LOGS
	u32 cmdlogidx = 0;
	char tempbuf[32];
	u32 size;
#endif

	if (length == 0)
		goto exit;

	flen = dump_file(valbuf, length, fname, append);

	if (flen > MAX_DUMP_FILESIZE) {
		u32 idx = strlen(fname) - 1;

		while (idx > 0 && fname[idx] != '-')
			idx--;

		if (idx == 0) {
			printk("[HM]:invalid filename:%s\n", fname);
			//WLDBG_ERROR(DBG_LEVEL_0, "[HM]:invalid filename:%s\n", fname);
			//filp_close(filp_core, current->files);
			goto exit;
		}

		fnameid = atoi(&fname[idx + 1]);
		fnameid++;
		swNewFile = 1;
		if (memcmp
		    (wlpd_p->smon.dumpstsname, fname,
		     (u32) strlen(wlpd_p->smon.dumpstsname)) == 0) {
			sprintf(&fname[idx], "-%u", fnameid);	// ++sts_index);
			sprintf(&wlpd_p->smon.dumpstsname[idx], "-%u", fnameid);	//sts_index);
			//printk("dump to next file:%s\n",fname);
		} else if (memcmp
			   (wlpd_p->smon.dumpcmdname, fname,
			    (u32) strlen(wlpd_p->smon.dumpcmdname)) == 0) {
			//only keep 2 cmd files
#ifdef ROUND_ROBIN_CMD_LOGS
			cmdlogidx = fnameid;
			fnameid &= 0x1;
#endif
			sprintf(&fname[idx], "-%u", fnameid);	//  ++cmd_index);
			sprintf(&wlpd_p->smon.dumpcmdname[idx], "-%u", fnameid);	//cmd_index);
			//printk("dump to next file:%s\n",fname);
#ifdef ROUND_ROBIN_CMD_LOGS
			size = (u32) sprintf((char *)&tempbuf[0],
					     "-- logFile_idx:%u --\n",
					     cmdlogidx);
			dump_file(tempbuf, size, fname, 0);
#endif
		}
	}

exit:

	return swNewFile;
}

void
hm_copy_file(UINT8 * srcfname, UINT8 * dstfname)
{
	struct file *filp_coreS = NULL;
	struct file *filp_coreD = NULL;
	UINT8 *plog = NULL;
	unsigned int lenS = 0;

	filp_coreS = filp_open(srcfname, O_RDONLY, 0);
	if (IS_ERR(filp_coreS)) {
		printk("open src file fail:%s\n", srcfname);
		goto exit0;
	}

	filp_coreD = filp_open(dstfname, O_RDWR | O_CREAT | O_TRUNC, 0);
	if (IS_ERR(filp_coreD)) {
		printk("open target file fail:%s\n", dstfname);
		goto exit1;
	}

	if ((plog = (void *)wl_kmalloc(MAX_DUMP_FILESIZE, GFP_ATOMIC)) == NULL) {
		printk("Error[%s:%d]: Allocating copy buffer failure \n",
		       __func__, __LINE__);
		goto exit2;
	}

	lenS = kernel_read(filp_coreS, plog, MAX_DUMP_FILESIZE,
			   &filp_coreS->f_pos);
	printk("***copying file size:%u\n", lenS);

	if (lenS > 0) {
		__kernel_write(filp_coreD, plog, lenS, &filp_coreD->f_pos);
		printk("***target file pos:%llx\n", filp_coreD->f_pos);
	}

exit2:
	filp_close(filp_coreD, current->files);
exit1:
	filp_close(filp_coreS, current->files);
exit0:
	return;
}

void
wlmon_kumper_callback(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	//char  stsfname[48];
	//char  cmdfname[48];
	char *pbuf = NULL;
	u32 i;
	u32 idx = 0;
	char *fname[2];
	u32 fnameidx;
	char *elog = "<end of log>";

	if (wlpd_p->smon.active == 0)
		return;

	if (wlmon_log_cmd(netdev, (void **)&pbuf)) {
		hm_dump_file((void *)wlpd_p, pbuf, strlen(pbuf),
			     (UINT8 *) wlpd_p->smon.dumpcmdname, 1);
		wl_kfree(pbuf);
	}

	wlpd_p->smon.ActiveBitmap = 0;

	fname[0] = wlpd_p->smon.dumpcmdname;
	fname[1] = wlpd_p->smon.dumpstsname;

	printk("cmd:%s sts:%s\n", fname[0], fname[1]);

	for (i = 0; i < 2; i++) {
		idx = strlen(fname[i]) - 1;
		while (idx > 0 && *(fname[i] + idx) != '-')
			idx--;

		fnameidx = atoi((fname[i] + idx + 1));
		sprintf((fname[i] + idx), "-%u", ++fnameidx);

		printk("kdumper:%s\n", fname[i]);
		hm_dump_file((void *)wlpd_p, elog, sizeof(elog), fname[i], 1);
	}

	printk("wait awhile\n");
	mdelay(11 * 1000);
}

extern int mwl_drv_set_wdevReset(struct net_device *netdev);
extern int mwl_drv_set_wdevhalt(struct net_device *netdev);

static void
wlmon_fw_recovery(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;

	wlmon_ext_trigger_deassert(wlpptr);

	if (wlpd_p->smon.ActiveBitmap & MON_FW_AUTO_RECOVERY) {
		msleep(100);
		mwl_drv_set_wdevReset(netdev);
		wlpd_p->smon.exceptionEvt_rcvd = 0;
	} else {
		wlpd_p->smon.ActiveBitmap = 0;	//turn off monitor by off bitmap
		mwl_drv_set_wdevhalt(netdev);
	}
}

static void
wlmon_config_fw_exception(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;

	//driver manually issue coredumpmode cmd will make pfw gen exception evt.
	//clear counter to prevent dump again at next round.
	//wlpd_p->smon.exceptionEvt_rcvd = 0; 

	//set action = 1 to force PFW entering coredumpmode
	blocking_notifier_call_chain(&wlpd_p->smon.wlmon_notifier_list, 1,
				     (void *)netdev);

}

extern void wl_show_except_cnt(struct net_device *netdev, char *sysfs_buff);
extern void wl_show_stat(struct net_device *netdev, int option, int level,
			 char *sysfs_buff);
extern void wl_show_pktcnt_stat(struct net_device *netdev, char *sysfs_buff);
extern int wlIoctlGet(struct net_device *netdev, int cmd, char *param_str,
		      int param_len, char *ret_str, UINT16 * ret_len);

static void
wlmon_smacstatus_log_buffer(struct net_device *netdev,
			    SMAC_STATUS_st * pCurSmacStatus, U64 tms)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	SMAC_STATUS_st *pbuf = (SMAC_STATUS_st *) wlpd_p->smon.psmacStatusLog;

	if (!pCurSmacStatus)
		return;

	memcpy((void *)&pbuf[wlpd_p->smon.smacStatusLogIdx],
	       (void *)pCurSmacStatus, sizeof(SMAC_STATUS_st));
	memset(wlpd_p->smon.psmacWarningLog[wlpd_p->smon.smacStatusLogIdx], 0,
	       SMACSTATUS_LOG_MAX_LENGTH);
	wl_show_except_cnt(netdev,
			   wlpd_p->smon.psmacWarningLog[wlpd_p->smon.
							smacStatusLogIdx]);
	memset(wlpd_p->smon.psmacScheduleInfo[wlpd_p->smon.smacStatusLogIdx], 0,
	       SMACSTATUS_LOG_MAX_LENGTH);
	wl_show_stat(netdev, drvstatsopt_scheduleinfo, 0,
		     wlpd_p->smon.psmacScheduleInfo[wlpd_p->smon.
						    smacStatusLogIdx]);
	memset(wlpd_p->smon.psmacPktcnt[wlpd_p->smon.smacStatusLogIdx], 0,
	       SMACSTATUS_LOG_MAX_LENGTH);
	wl_show_pktcnt_stat(netdev,
			    wlpd_p->smon.psmacPktcnt[wlpd_p->smon.
						     smacStatusLogIdx]);
	memset(wlpd_p->smon.psmacGenInfo[wlpd_p->smon.smacStatusLogIdx], 0,
	       SMACSTATUS_LOG_MAX_LENGTH);
	wl_show_stat(netdev, drvstatsopt_geninfo, 0,
		     wlpd_p->smon.psmacGenInfo[wlpd_p->smon.smacStatusLogIdx]);

	wlpd_p->smon.smacStsTimestamp[wlpd_p->smon.smacStatusLogIdx] = tms;
	wlpd_p->smon.smacStatusLogIdx =
		(wlpd_p->smon.smacStatusLogIdx + 1) % MAX_SMACSTATUS_LOG_ENTRY;

}

static u8
is_Invalid_Addr(u32 offset, invalid_addr_hole * pholes)
{
	u8 invalid = FALSE;
	u32 i;

	if (!pholes)
		goto exit;

	for (i = 0; i < pholes->num; i++) {

		if (offset >= pholes->addr[i][0] &&
		    offset <= pholes->addr[i][1]) {
			invalid = TRUE;
			break;
		}
	}

exit:
	return invalid;
}

#define IOBASE1_R7_MEMORY_BASE 0x90000000

static int
hw_registers_print(char *plog, u32 * pbuf, u32 reg_addr_offset, u32 len)
{
	int i;
	int str_len = 0;

	for (i = 0; i < len; i++) {

		if ((reg_addr_offset & 0xF) == 0)
			str_len +=
				sprintf(&plog[str_len], "%08x:",
					(u32) (reg_addr_offset +
					       IOBASE1_R7_MEMORY_BASE));

		if (pbuf)
			str_len += sprintf(&plog[str_len], "%08x", pbuf[i]);
		else
			str_len += sprintf(&plog[str_len], "--------");

		reg_addr_offset += sizeof(u32);

		if ((reg_addr_offset & 0xF) == 0)
			str_len += sprintf(&plog[str_len], "\n");
		else
			str_len += sprintf(&plog[str_len], " ");

	}

	return str_len;
}

//note: len is u32 unit size.  
//adma addr is out of pcie iobase1 mapping area. need to access by fw cmd. (in diag mode)
int
wlmon_dump_adma_registers(struct wlprivate *wlpptr, char *plog)
{
	u32 *pbuf;
	u32 adma_base = 0xA0000;
	u32 reg_addr_offset, len;
	int str_len = 0;
	u32 block, section;
	u32 prev_end = 0;

	if (!(pbuf = (u32 *) wl_kmalloc(2048, GFP_KERNEL)))
		goto exit;

	/*
	   Adma accessable registers block
	   1. 0xA0000 ~ 0xA005C
	   2. 0xA0080 ~ 0xA00DC
	   3. 0xA0100 ~ 0xA015C
	   4. 0xA0180 ~ 0xA01DC
	   5. 0xA0200 ~ 0xA025C

	   6. 0xA0800 ~ 0xA085C
	   7. 0xA0880 ~ 0xA08DC
	   8. 0xA0900 ~ 0xA095C
	   9. 0xA0980 ~ 0xA09DC
	   10. 0xA0A00 ~ 0xA0A5C

	   11. 0xA1000 ~ 0xA105C
	   12. 0xA1080 ~ 0xA10DC
	   13. 0xA1100 ~ 0xA115C
	   14. 0xA1180 ~ 0xA11DC
	   15. 0xA1200 ~ 0xA125C
	 */

	len = 24;
	for (section = 0; section < 3; section++) {

		for (block = 0; block < 5; block++) {

			reg_addr_offset =
				adma_base + (section * 0x800) + (block * 0x80);

			//print "-----" for non-accessable registers. for compatible with mochi interfaces
			if (prev_end) {
				u32 offset = reg_addr_offset - prev_end;
				str_len +=
					hw_registers_print(&plog[str_len], NULL,
							   prev_end,
							   (offset /
							    sizeof(u32)));
			}

			if (!wlmon_read_hw_registers
			    (wlpptr, (IOBASE1_R7_MEMORY_BASE + reg_addr_offset),
			     len, pbuf))
				str_len +=
					hw_registers_print(&plog[str_len], pbuf,
							   reg_addr_offset,
							   len);
			else
				str_len +=
					hw_registers_print(&plog[str_len], NULL,
							   reg_addr_offset,
							   len);

			prev_end = reg_addr_offset + len * sizeof(u32);

		}

	}

	str_len += sprintf(&plog[str_len], "\n");

	wl_kfree(pbuf);
exit:

	return str_len;
}

//Read hw registers in PFW diag mode.

u32
wlmon_read_hw_registers(struct wlprivate * wlpptr, u32 start, u32 len,
			u32 * pbuf)
{
	struct net_device *netdev = wlpptr->netDev;
	u32 entry;
	u32 *buffer = pbuf;
	u32 ret = SUCCESS;

	while (len > 0) {

		if (len > 64) {
			len -= 64;
			entry = 64;
		} else {
			entry = len;
			len = 0;
		}

		if (!
		    (ret =
		     wlFwGetCoreDumpAddrValue(netdev, start, entry, buffer, 0)))
			buffer += entry;
		else
			break;

		start += (entry * sizeof(u32));
	}

	return ret;
}

static int
wlmon_dump_hw_regsiters(struct wlprivate *wlpptr, char *plog,
			unsigned int start_addr, unsigned end_addr,
			invalid_addr_hole * pholes)
{
	unsigned int reg_addr_offset = 0;
	int str_len = 0;

	for (reg_addr_offset = start_addr; reg_addr_offset <= end_addr;) {

		if ((reg_addr_offset % 16) == 0)
			str_len +=
				sprintf(&plog[str_len], "%08x:",
					(u32) (reg_addr_offset +
					       IOBASE1_R7_MEMORY_BASE));

		if (is_Invalid_Addr((reg_addr_offset - start_addr), pholes)) {
			str_len += sprintf(&plog[str_len], "--------");
		} else {

			if (!IS_BUS_TYPE_MCI(wlpptr) && reg_addr_offset > SZ_256K) {	//PCIE only provide 256K remap size in iobase1
				str_len += sprintf(&plog[str_len], "--------");
				//printk("%s():PCIE: reg_addr_offset: %x\n",__func__, reg_addr_offset);
			} else {
				str_len += sprintf(&plog[str_len], "%08x", wl_util_readl(wlpptr->netDev, wlpptr->ioBase1 + reg_addr_offset));
			}
		}

		reg_addr_offset += 4;

		if ((reg_addr_offset % 16) == 0)
			str_len += sprintf(&plog[str_len], "\n");
		else
			str_len += sprintf(&plog[str_len], " ");
	}
	str_len += sprintf(&plog[str_len], "\n");

	return str_len;
}

static int
wlmon_dump_txq_cnt(struct wlprivate *wlpptr, char *plog, unsigned int startid,
		   unsigned int length)
{
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	unsigned int i, endid;
	int str_len = 0;
	unsigned int txq_pend, txq_drop, txq_send, txq_rel, txq_txd1_drop;

	endid = startid + length;

	if (endid >= SMAC_QID_NUM - 1)
		endid = SMAC_QID_NUM - 1;

	str_len +=
		sprintf(&plog[str_len], "TXQ pkt cnt: txqid form %4u to %4u:\n",
			startid, endid);
	str_len +=
		sprintf(&plog[str_len],
			"txqid:  pend  drop  send  rel txd1_drop\n");
	for (i = startid; i <= endid; i++) {
		txq_send = wlpd_p->except_cnt.txq_send_cnt[i];
		txq_rel = wlpd_p->except_cnt.txq_rel_cnt[i];
		txq_drop = wlpd_p->except_cnt.txq_drop_cnt[i];
		txq_pend = txq_send - txq_rel;
		txq_txd1_drop = wlpd_p->except_cnt.txq_txd1_drop_cnt[i];
		str_len +=
			sprintf(&plog[str_len], "%4u:  %u  %u  %u  %u %u\n", i,
				txq_pend, txq_drop, txq_send, txq_rel,
				txq_txd1_drop);
	}
	str_len += sprintf(&plog[str_len], "\n");

	return str_len;
}

int
wlmon_smacstatus_log_dump(struct net_device *netdev, void **buf, u8 * stsfname,
			  u8 skipSmac)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	SMAC_STATUS_st *pbuf = (SMAC_STATUS_st *) wlpd_p->smon.psmacStatusLog;
	U32 index = wlpd_p->smon.smacStatusLogIdx;
	char *plog = NULL;
	int i;
	int idx = 0;
	u64 ts_sec, ts_ms;
	UINT32 format = wlpd_p->smon.smacStatusFormat;

	//HM not enabled or NO active interfaces, ignore smac status dump of the last 5 samples.
	if (wlpd_p->smon.active == 0 || wlpd_p->smon.ActiveIf == 0)
		goto exit;

	if ((plog =
	     (void *)wl_kzalloc(WLMON_PRNT_BUF_SIZE, GFP_ATOMIC)) == NULL) {
		printk("Error[%s:%d]: Allocating wlmon buffer failure \n",
		       __func__, __LINE__);
		goto exit;
	}

	if (wlpd_p->smon.exceptionDelayCoreDumpCnt == DELAY_COREDUMP_TIME) {
		idx += sprintf(&plog[idx],
			       "---- SMAC_STATUS_st dump before entering coredump mode ---\n");
	}

	if (skipSmac == 0) {
		UINT16 ret_len;

		for (i = 0; i < wlpptr->wlpd_p->NumOfAPs; i++) {
			idx += sprintf(&plog[idx], "\n----%sap%d ",
				       netdev->name, i);
			wlIoctlGet(wlpptr->vdev[i], WL_IOCTL_GET_STALISTEXT,
				   NULL, 0, &plog[idx], &ret_len);
			idx += ret_len;
		}
		idx += sprintf(&plog[idx], "\n\n");
	}
	//output smac statsu snapshot
	for (i = 0; i < MAX_SMACSTATUS_LOG_ENTRY && skipSmac == 0; i++) {

		convert_tscale(wlpd_p->smon.smacStsTimestamp[index], &ts_sec,
			       &ts_ms, NULL);
		idx += sprintf(&plog[idx], "[%llu.%llu]:\n", ts_sec, ts_ms);
		idx += sprintSmacStatus(&plog[idx], &pbuf[index],
					WLMON_PRNT_BUF_SIZE - idx, format);
		idx += sprintf(&plog[idx], "\n\n");

		idx += sprintf(&plog[idx], "\nSTAT 1 -----------\n");
		memcpy(&plog[idx], wlpd_p->smon.psmacGenInfo[index],
		       strlen(wlpd_p->smon.psmacGenInfo[index]));
		idx += strlen(wlpd_p->smon.psmacGenInfo[index]);

		idx += sprintf(&plog[idx], "\nSTAT 2 -----------\n");
		memcpy(&plog[idx], wlpd_p->smon.psmacWarningLog[index],
		       strlen(wlpd_p->smon.psmacWarningLog[index]));
		idx += strlen(wlpd_p->smon.psmacWarningLog[index]);

		idx += sprintf(&plog[idx], "\nSTAT 4 -----------\n");
		memcpy(&plog[idx], wlpd_p->smon.psmacScheduleInfo[index],
		       strlen(wlpd_p->smon.psmacScheduleInfo[index]));
		idx += strlen(wlpd_p->smon.psmacScheduleInfo[index]);

		idx += sprintf(&plog[idx], "\nSTAT 8 -----------\n");
		memcpy(&plog[idx], wlpd_p->smon.psmacPktcnt[index],
		       strlen(wlpd_p->smon.psmacPktcnt[index]));
		idx += strlen(wlpd_p->smon.psmacPktcnt[index]);

		index = (index + 1) % MAX_SMACSTATUS_LOG_ENTRY;

		if (idx > WLMON_PRNT_BUF_SIZE) {
			printk("[%s,%d]:wlmon error dump run out of buffer\n",
			       __func__, __LINE__);
			BUG();
		}

	}
	//output to file
	hm_dump_file(wlpd_p, plog, strlen(plog), (UINT8 *) stsfname, 1);
	idx = 0;

#ifdef AVL_DB_SNAPSHOT
	//only dump once before entering coredump
	if (skipSmac == 0) {
		u64 ts = ((sta_db_snap *) (wlpd_p->smon.pStaDbTable))->
			StaDbTimestamp;
		u8 *lbuf =
			((sta_db_snap *) (wlpd_p->smon.pStaDbTable))->StaDbBuf;

		idx += sprintf(&plog[idx],
			       "the last snapshot of avl sta db:\n");
		convert_tscale(ts, &ts_sec, &ts_ms, NULL);
		idx += sprintf(&plog[idx], "[%llu.%llu]:\n", ts_sec, ts_ms);
		idx += sprintf(&plog[idx], "%s\n", lbuf);

		if (idx > WLMON_PRNT_BUF_SIZE) {
			printk("[%s,%d]:wlmon error dump run out of buffer\n",
			       __func__, __LINE__);
			BUG();
		}
		//output to file
		hm_dump_file(wlpd_p, plog, strlen(plog), (UINT8 *) stsfname, 1);
		idx = 0;
	}
#endif

	//print timestamp of HFramex dump
	convert_tscale(xxGetTimeStamp(), &ts_sec, &ts_ms, NULL);
	idx += sprintf(&plog[idx], "[%llu.%llu]:\n", ts_sec, ts_ms);

	idx += wlmon_dump_txq_cnt(wlpptr, &plog[idx], 0, SMAC_QID_NUM);

	/* HFrame1 0x20000 ~ 0x21000 */
	idx += sprintf(&plog[idx], "\nHFrame1 0x20000 ~ 0x21000\n");
	idx += wlmon_dump_hw_regsiters(wlpptr, &plog[idx], 0x20000, 0x21000,
				       NULL);
	/* HFrame2 0x28000 ~ 0x29000 */
	idx += sprintf(&plog[idx], "\nHFrame2 0x28000 ~ 0x29000\n");
	idx += wlmon_dump_hw_regsiters(wlpptr, &plog[idx], 0x28000, 0x29000,
				       NULL);
	/* HFrame3 0x30000 ~ 0x31000 */
	idx += sprintf(&plog[idx], "\nHFrame3 0x30000 ~ 0x31000\n");
	idx += wlmon_dump_hw_regsiters(wlpptr, &plog[idx], 0x30000, 0x31000,
				       NULL);
	/* Rx 0x10000 ~ 0x10ffc */
	idx += sprintf(&plog[idx], "\nRx 0x10000 ~ 0x10FFC\n");
	idx += wlmon_dump_hw_regsiters(wlpptr, &plog[idx], 0x10000, 0x10FFC,
				       NULL);

	/* BF 0x11000 ~ 0x111FC */
	idx += sprintf(&plog[idx], "\nBF 0x11000 ~ 0x111FC\n");
	idx += wlmon_dump_hw_regsiters(wlpptr, &plog[idx], 0x11000, 0x111FC,
				       NULL);

	/* DFS 0x12000 ~ 0x120FC */
	idx += sprintf(&plog[idx], "\nDFS 0x12000 ~ 0x120FC\n");
	idx += wlmon_dump_hw_regsiters(wlpptr, &plog[idx], 0x12000, 0x120FC,
				       NULL);

	/* BMAN 0x13800 ~ 0x13A68 holes:13920~139FC, efined but unaccess: 930~93C */
	idx += sprintf(&plog[idx], "\nBMAN 0x13800 ~ 0x13A68\n");
	idx += wlmon_dump_hw_regsiters(wlpptr, &plog[idx], 0x13800, 0x13A68,
				       &inv_bman);

	if (idx > WLMON_PRNT_BUF_SIZE) {
		printk("[%s,%d]:wlmon error dump run out of buffer\n", __func__,
		       __LINE__);
		BUG();
	}
	//output to file
	hm_dump_file(wlpd_p, plog, strlen(plog), (UINT8 *) stsfname, 1);
	idx = 0;

	/* EU 0x1C000 ~ 0x20000 */
	idx += sprintf(&plog[idx], "\nEU 0x1C000 ~ 0x1CA00\n");
	idx += wlmon_dump_hw_regsiters(wlpptr, &plog[idx], 0x1C000, 0x1CA00,
				       NULL);

	/* TxDMA 0x14000 ~ 0x15000 */
	idx += sprintf(&plog[idx], "\nTxDMA 0x14000 ~ 0x15000\n");
	idx += wlmon_dump_hw_regsiters(wlpptr, &plog[idx], 0x14000, 0x15000,
				       NULL);

	/* AVL 0x1A000 ~ 0x1A5FC */
	idx += sprintf(&plog[idx], "\nAVL 0x1A000 ~ 0x1A5FC\n");
	idx += wlmon_dump_hw_regsiters(wlpptr, &plog[idx], 0x1A000, 0x1AC00,
				       &inv_avl);

	/* SMAC_CTRL 0x1A800 ~ 0x1ABAC, no memory hole */
	idx += sprintf(&plog[idx], "\nSMAC_CTRL 0x1A800 ~ 0x1ABAC\n");
	idx += wlmon_dump_hw_regsiters(wlpptr, &plog[idx], 0x1A800, 0x1ABAC,
				       NULL);

	/* ADMA 0xA0000 ~ 0xA125C */
	idx += sprintf(&plog[idx], "\nADMA 0xA0000 ~ 0xA125C\n");
	if (IS_BUS_TYPE_MCI(wlpptr))
		idx += wlmon_dump_hw_regsiters(wlpptr, &plog[idx], 0xA0000,
					       0xA125C, &inv_adma);
	else
		idx += wlmon_dump_adma_registers(wlpptr, &plog[idx]);	//out of pcie iobase1 mapping area, need to access by cmd in diag mode.

	if (idx > WLMON_PRNT_BUF_SIZE) {
		printk("[%s,%d]:wlmon error dump run out of buffer\n", __func__,
		       __LINE__);
		BUG();
	}

	*buf = plog;
	return 1;

exit:
	*buf = NULL;
	return 0;

}

void
wlmon_show_version(struct net_device *netdev, UINT8 * stsfname)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	int idx;
	UINT8 *pbuf;
	UINT8 devstr[16];
	int idx2 = 0;

	if ((pbuf =
	     (void *)wl_kmalloc(WLMON_PRNT_BUF_SIZE, GFP_ATOMIC)) == NULL) {
		printk("Error[%s:%d]: Allocating wlmon buffer failure \n",
		       __func__, __LINE__);
		goto exit;
	}

	wlget_sw_version(wlpptr, pbuf, 1);
	idx = strlen(pbuf);

	if (wlpptr->devid == SC5)
		idx2 += sprintf(&devstr[idx2], "W9068-");
	else if (wlpptr->devid == SCBT)
		idx2 += sprintf(&devstr[idx2], "W9064-");
	else
		idx2 += sprintf(&devstr[idx2], "------");

	if (wlpptr->hwData.chipRevision == REV_Z1)
		idx2 += sprintf(&devstr[idx2], "Z1");
	else if (wlpptr->hwData.chipRevision == REV_Z2)
		idx2 += sprintf(&devstr[idx2], "Z2");
	else if (wlpptr->hwData.chipRevision == REV_A0)
		idx2 += sprintf(&devstr[idx2], "A0");
	else
		idx2 += sprintf(&devstr[idx2], "--");

	sprintf(&pbuf[idx], "Hw DevID:%x  ChipRevision:%x %s\n\n",
		wlpptr->devid, wlpptr->hwData.chipRevision, devstr);
	printk("%s", pbuf);

	//no print to log if HM is disabled.
	if (wlpd_p->smon.active == 0)
		goto free_exit;

	hm_dump_file(wlpd_p, pbuf, strlen(pbuf), (UINT8 *) stsfname, 1);

free_exit:
	wl_kfree(pbuf);

exit:
	return;
}

#ifdef AVL_DB_SNAPSHOT
int
wlmon_dump_AVL_sta_db(struct net_device *netdev, u64 tms)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	UINT32 addr;
	UINT32 *addr_val = wl_kmalloc(64 * sizeof(UINT32), GFP_KERNEL);
	UINT16 *val = (UINT16 *) addr_val, startIdx, index;
	UINT8 *ptr = NULL;
	int idx = 0;
	UINT8 *buf;
	UINT32 length;
	UINT32 i, j;
	UINT8 *plog;

	if (addr_val == NULL) {
		printk("%s(): Fail to allocate memory for AVL sta db dump\n",
		       __func__);
		goto exit2;
	}

	memset(addr_val, 0, 64 * sizeof(UINT32));
	length = 32;
	addr = 0;		// 4 byte boundary

	buf = wl_kmalloc(length * 32 + 100, GFP_ATOMIC);
	if (buf == NULL) {
		printk("%s(): Fail to allocate memory buffer for AVL sta db dump\n", __func__);
		goto exit1;
	}

	((sta_db_snap *) wlpd_p->smon.pStaDbTable)->StaDbTimestamp = tms;
	plog = ((sta_db_snap *) wlpd_p->smon.pStaDbTable)->StaDbBuf;

	//printk("dump avl db\n");
	idx = sprintf(&plog[idx], "Dump avl db:\n");

	startIdx = 0;
	index = 1;
	while (index <= (SMAC_BSS_NUM + SMAC_STA_NUM)) {
		if (wlFwGetAddrValue(netdev, addr, startIdx, addr_val, 2)) {
			printk("Could not get the memory address value\n");
			goto exit0;
		}
		j = 0;
		for (i = 0; i < length * 4; i += 4) {
			val[i] = ENDIAN_SWAP16(val[i]);
			if ((val[i] > 0) && (val[i] < 0xffff)) {
				ptr = (UINT8 *) & val[i + 1];
				j += sprintf(buf + j, "%3d	%04i: ", index,
					     val[i]);
				j += sprintf(buf + j,
					     "%02x:%02x:%02x:%02x:%02x:%02x\n",
					     ptr[0], ptr[1], ptr[2], ptr[3],
					     ptr[4], ptr[5]);
				startIdx = val[i];
				index++;
			} else {
				if (val[i] == 0xffff)
					startIdx = 0xffff;
				break;
			}
		}

		if (j > 0) {
			//printk("%s", buf);
			idx += sprintf(&plog[idx], "%s", buf);
		}

		if (startIdx == 0xffff)
			break;
	}

	if (idx > MAX_STADB_BUFF_SIZE) {
		printk("[%s,%d]:wlmon error dump run out of buffer\n", __func__,
		       __LINE__);
		BUG();
	}

exit0:
	wl_kfree(buf);
exit1:
	wl_kfree(addr_val);
exit2:

	return idx;
}
#endif //AVL_DB_SNAPSHOT

#define DUMPEND_SIGNATURE "__End"

static inline UINT32
prev_idx(UINT32 i)
{
	return (((i - 1) < i) ? (i - 1) : 3);
}

static inline UINT32
get_delta(UINT32(*arr)[1], UINT32 i)
{
	UINT32 cnt = 3, delta = 0;
	while (cnt--) {
		if (arr[i] > arr[prev_idx(i)])
			delta += (arr[i][0] - arr[prev_idx(i)][0]);
		else
			delta += (arr[i][0] + ~(arr[prev_idx(i)][0]) + 1);
		i = prev_idx(i);
	}
	return delta;
}

static UINT32
wlmon_txstuck_detect_persta(struct wlprivate_data *wlpd_p, UINT16 stnId)
{
	UINT32(*txdonediff)[1];
	UINT32 txdidx = 0, delta_txdone = 0;

	if (wlpd_p == NULL)
		return 0;
	if (wlpd_p->except_cnt.tx_sta_pend_cnt[stnId] >=
	    dbg_max_tx_pend_cnt_per_sta) {
		/* record tx done */
		txdidx = wlpd_p->except_cnt.txdidx[stnId][0];
		txdonediff = wlpd_p->except_cnt.txdonediff[stnId];
		txdonediff[txdidx][0] =
			wlpd_p->except_cnt.tx_sta_rel_cnt[stnId];
		txdidx = (txdidx + 1) % 4;
		if (txdonediff[txdidx][0]) {
			delta_txdone =
				get_delta(txdonediff,
					  wlpd_p->except_cnt.txdidx[stnId][0]);
			if (delta_txdone == 0) {
				memset(txdonediff, 0,
				       sizeof(wlpd_p->except_cnt.
					      txdonediff[stnId]));
				wlpd_p->except_cnt.mon_fw_recovery |= BIT(0);
				wlpd_p->except_cnt.txdidx[stnId][0] = txdidx;
				return 1;
			}
		}
		wlpd_p->except_cnt.txdidx[stnId][0] = txdidx;
	}
	return 0;
}

static UINT32
wlmon_txstuck_recovery_detect(struct net_device *netdev)
{
	UINT8 macAddr[6];
	UINT32 entries = 0, i = 0;
	UINT8 *sta_buf = NULL, *p = NULL;
	extStaDb_StaInfo_t *pStaInfo = NULL;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;

	if (vmacSta_p->VMacEntry.modeOfService != VMAC_MODE_CLNT_INFRA) {
		//AP mode
		entries = extStaDb_entries(vmacSta_p, 0);
		if (entries == 0)
			return 0;
		sta_buf = wl_kmalloc(entries * 64, GFP_KERNEL);
		if (sta_buf == NULL) {
			printk("Failed to monitor connected STAs (%u),"
			       "no memory\n", entries);
			return 0;
		}
		p = sta_buf;
		for (i = 0; i < entries; i++) {
			memcpy(macAddr, p, sizeof(macAddr));
			if ((pStaInfo = extStaDb_GetStaInfo(vmacSta_p,
							    (IEEEtypes_MacAddr_t
							     *) macAddr,
							    STADB_DONT_UPDATE_AGINGTIME))
			    == NULL) {
				p += sizeof(STA_INFO);
				continue;
			}
			if (wlmon_txstuck_detect_persta
			    (wlpd_p, pStaInfo->StnId))
				return 0;
			p += sizeof(STA_INFO);
		}
		if (sta_buf)
			wl_kfree(sta_buf);
	} else {
		//STA mode
		if ((pStaInfo = extStaDb_GetStaInfo(vmacSta_p,
						    (IEEEtypes_MacAddr_t *)
						    macAddr,
						    STADB_DONT_UPDATE_AGINGTIME))
		    == NULL)
			return 0;
		if (wlmon_txstuck_detect_persta(wlpd_p, pStaInfo->StnId))
			return 1;
	}
	return 0;
}

static UINT32
wlmon_rxstuck_recovery_detect(struct net_device *netdev)
{
	SMAC_STATUS_st cur_smac_sts;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	UINT32 rxidx = 0, delta_cfhuld = 0, delta_stat2 = 0, delta_stat8 =
		0, delta_stat10 = 0;

	/* rx amsduq full detect */
	memset(&cur_smac_sts, 0, sizeof(SMAC_STATUS_st));
	memcpy(&cur_smac_sts, wlpptr->smacStatusAddr, sizeof(SMAC_STATUS_st));
	if (cur_smac_sts.eop2Drp_RxAmsduQFull) {
		wlpd_p->except_cnt.mon_fw_recovery |= BIT(1);
		return 1;
	}

	/* rx drop for invalid stat 2 */
	rxidx = wlpd_p->except_cnt.rxidx;
	wlpd_p->except_cnt.cfhuld[rxidx][0] = wlpd_p->except_cnt.cfhul_data_cnt;
	wlpd_p->except_cnt.rx_exception[rxidx][0] =
		wlpd_p->except_cnt.cnt_cfhul_invalid_signature +
		wlpd_p->except_cnt.cnt_cfhul_error +
		wlpd_p->except_cnt.cnt_cfhul_snap_error +
		wlpd_p->except_cnt.cnt_cfhul_oversize;
	wlpd_p->except_cnt.stat8_data_diff[rxidx][0] =
		wlpd_p->rpkt_type_cnt.data_cnt;
	wlpd_p->except_cnt.stat10_data_diff[rxidx][0] =
		wlpptr->vmacSta_p->BA_Rodr2Host;

	rxidx = (rxidx + 1) % 4;
	if (wlpd_p->except_cnt.cfhuld[rxidx][0] &&
	    wlpd_p->except_cnt.rx_exception[rxidx][0]) {
		delta_cfhuld =
			get_delta(wlpd_p->except_cnt.cfhuld,
				  wlpd_p->except_cnt.rxidx);
		delta_stat2 =
			get_delta(wlpd_p->except_cnt.rx_exception,
				  wlpd_p->except_cnt.rxidx);
		if ((delta_stat2 * 10) > (delta_cfhuld * 8)) {
			memset(wlpd_p->except_cnt.cfhuld, 0,
			       sizeof(wlpd_p->except_cnt.cfhuld));
			memset(wlpd_p->except_cnt.rx_exception, 0,
			       sizeof(wlpd_p->except_cnt.rx_exception));
			wlpd_p->except_cnt.mon_fw_recovery |= BIT(2);
			wlpd_p->except_cnt.rxidx = rxidx;
			return 1;
		}
	}

	/* rx drop for invalid stat 10 */
	if (!wlpd_p->fastdata_reordering_disable) {
		if (wlpd_p->except_cnt.stat8_data_diff[rxidx][0] &&
		    wlpd_p->except_cnt.stat10_data_diff[rxidx][0]) {
			delta_stat8 =
				get_delta(wlpd_p->except_cnt.stat8_data_diff,
					  wlpd_p->except_cnt.rxidx);
			delta_stat10 =
				get_delta(wlpd_p->except_cnt.stat10_data_diff,
					  wlpd_p->except_cnt.rxidx);
			if (delta_stat10 * 10 < delta_stat8) {
				memset(wlpd_p->except_cnt.stat8_data_diff, 0,
				       sizeof(wlpd_p->except_cnt.
					      stat8_data_diff));
				memset(wlpd_p->except_cnt.stat10_data_diff, 0,
				       sizeof(wlpd_p->except_cnt.
					      stat10_data_diff));
				wlpd_p->except_cnt.mon_fw_recovery |= BIT(3);
				wlpd_p->except_cnt.rxidx = rxidx;
				return 1;
			}
		}
	}
	wlpd_p->except_cnt.rxidx = rxidx;

	return 0;
}

static UINT32
wlmon_memleak_detect(struct net_device *netdev)
{
#define MEM_LEAK_THRESH 25600
	extern u32 recovered_errcfhul;
	UINT32 mem_leak = 0, diff = 0;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;

	/* memory leak */
	diff = (wlpd_p->except_cnt.cnt_cfhul_invalid_signature >
		wlpd_p->except_cnt.free_err_pkts[0]) ? (wlpd_p->except_cnt.
							cnt_cfhul_invalid_signature
							-
							wlpd_p->except_cnt.
							free_err_pkts[0]) :
		wlpd_p->except_cnt.cnt_cfhul_invalid_signature;
	if (diff >= MEM_LEAK_THRESH) {
		wlpd_p->except_cnt.mon_fw_recovery |= BIT(4);
		mem_leak = 1;
	}

	diff = (wlpd_p->except_cnt.cnt_cfhul_error >
		wlpd_p->except_cnt.free_err_pkts[0]) ? (wlpd_p->except_cnt.
							cnt_cfhul_error -
							wlpd_p->except_cnt.
							free_err_pkts[0]) :
		wlpd_p->except_cnt.cnt_cfhul_error;
	if (diff >= MEM_LEAK_THRESH) {
		wlpd_p->except_cnt.mon_fw_recovery |= BIT(5);
		mem_leak = 1;
	}

	diff = (wlpd_p->except_cnt.cnt_cfhul_snap_error >
		wlpd_p->except_cnt.free_err_pkts[0]) ? (wlpd_p->except_cnt.
							cnt_cfhul_snap_error -
							wlpd_p->except_cnt.
							free_err_pkts[0]) :
		wlpd_p->except_cnt.cnt_cfhul_snap_error;
	if (diff >= MEM_LEAK_THRESH) {
		wlpd_p->except_cnt.mon_fw_recovery |= BIT(6);
		mem_leak = 1;
	}

	diff = (wlpd_p->except_cnt.cnt_cfhul_oversize >
		wlpd_p->except_cnt.free_err_pkts[0]) ? (wlpd_p->except_cnt.
							cnt_cfhul_oversize -
							wlpd_p->except_cnt.
							free_err_pkts[0]) :
		wlpd_p->except_cnt.cnt_cfhul_oversize;
	if (diff >= MEM_LEAK_THRESH) {
		wlpd_p->except_cnt.mon_fw_recovery |= BIT(7);
		mem_leak = 1;
	}

	if (wlpd_p->except_cnt.cfhul_flpkt_lost[0] -
	    recovered_errcfhul >= MEM_LEAK_THRESH) {
		wlpd_p->except_cnt.mon_fw_recovery |= BIT(8);
		mem_leak = 1;
	}

	if (wlpd_p->except_cnt.cfhul_flpkt_lost[2] -
	    recovered_errcfhul >= MEM_LEAK_THRESH) {
		wlpd_p->except_cnt.mon_fw_recovery |= BIT(9);
		mem_leak = 1;
	}

	if (wlpd_p->except_cnt.cfhul_flpkt_lost[3] >= MEM_LEAK_THRESH) {
		wlpd_p->except_cnt.mon_fw_recovery |= BIT(10);
		mem_leak = 1;
	}

	if (wlpd_p->except_cnt.cfhul_hdr_loaddr_err >= MEM_LEAK_THRESH) {
		wlpd_p->except_cnt.mon_fw_recovery |= BIT(11);
		mem_leak = 1;
	}

	if (wlpd_p->except_cnt.rx_invalid_sig_cnt[0] >= MEM_LEAK_THRESH ||
	    wlpd_p->except_cnt.rx_invalid_sig_cnt[1] > MEM_LEAK_THRESH ||
	    wlpd_p->except_cnt.rx_invalid_sig_cnt[2] > MEM_LEAK_THRESH ||
	    wlpd_p->except_cnt.rx_invalid_sig_cnt[3] > MEM_LEAK_THRESH) {
		mem_leak = 1;
		wlpd_p->except_cnt.mon_fw_recovery |= BIT(12);
	}

	if (wlpd_p->except_cnt.skb_invalid_addr_cnt >= MEM_LEAK_THRESH) {
		mem_leak = 1;
		wlpd_p->except_cnt.mon_fw_recovery |= BIT(13);
	}

	if (wlpd_p->except_cnt.skb_notlinked_cnt >= MEM_LEAK_THRESH) {
		mem_leak = 1;
		wlpd_p->except_cnt.mon_fw_recovery |= BIT(14);
	}

	if (wlpd_p->except_cnt.cfhul_hdrlen_err >= MEM_LEAK_THRESH) {
		mem_leak = 1;
		wlpd_p->except_cnt.mon_fw_recovery |= BIT(15);
	}

	if (wlpd_p->except_cnt.cfhul_buf_map_err >= MEM_LEAK_THRESH) {
		mem_leak = 1;
		wlpd_p->except_cnt.mon_fw_recovery |= BIT(16);
	}

	if (wlpd_p->except_cnt.skb_overpanic_cnt >= MEM_LEAK_THRESH) {
		mem_leak = 1;
		wlpd_p->except_cnt.mon_fw_recovery |= BIT(17);
	}

	return mem_leak;
}

static UINT32
wlmon_recovery_detect(struct net_device *netdev)
{
	UINT32 i = 0, ret = 0, recovery_cnt = 0;
	struct net_device *vdev = NULL;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;

	if (!(wlpd_p->smon.ActiveBitmap & MON_RECOVERY_DETECT))
		return 0;

	/* tx stuck detect */
#if defined(SINGLE_DEV_INTERFACE) && !defined(CLIENTONLY)
	for (i = 1; i < wlpptr->wlpd_p->vmacIndex; i++)
#else
	for (i = 0; i < wlpptr->wlpd_p->vmacIndex; i++)
#endif
	{
		vdev = wlpptr->vdev[i];
		if (vdev && (vdev->flags & IFF_RUNNING)) {
			if (wlmon_txstuck_recovery_detect(vdev)) {
				ret = 1;
				goto out;
			}
		}
	}
	/* rx stuck detec */
	if (wlmon_rxstuck_recovery_detect(netdev)) {
		ret = 1;
		goto out;
	}
	/* memory leak detct */
	if (wlmon_memleak_detect(netdev)) {
		ret = 1;
		goto out;
	}

out:
	if (ret) {
		recovery_cnt = (wlpd_p->except_cnt.mon_fw_recovery >> 24);
		recovery_cnt += 1;
		wlpd_p->except_cnt.mon_fw_recovery |= (recovery_cnt << 24);
	}
	return 0;
}

int
wlmon_kthread(void *arg)
{
	struct wlprivate *wlpptr = (struct wlprivate *)arg;
	struct net_device *netdev = wlpptr->netDev;
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	unsigned int timeout;
	char *pbuf = NULL;
	char stsfname[96];
	char cmdfname[48];
	char enddump[110];
	u32 time;
	u8 bcnflag = 0;
	u8 cntflag = 0;
	u8 bmqflag = 0;
	u8 cmdflag = 0;
	u8 txstuckflag = 0;
	u8 rxstuckflag = 0;
#ifdef MOCHI_MON
	u8 mochiflag = 0;
#endif
	u8 pfwschflag = 0;
	u8 pfwaliveflag = 0;
	SMAC_STATUS_st *pCurSmacStatus = NULL;
	u32 len;
	int i;

	time = (UINT32) xxGetTimeStamp();	//use last word partial fileanme
	len = sprintf(stsfname, "/tmp/dump%s_sts_%04x-1", wlpd_p->rootdev->name,
		      time);
	strcpy(wlpd_p->smon.dumpstsname, stsfname);

	len = sprintf(cmdfname, "/tmp/dump%s_cmds-1", wlpd_p->rootdev->name);
	strcpy(wlpd_p->smon.dumpcmdname, cmdfname);

	if (!wlpd_p->smon.pexcept_cnt) {
		if (!
		    (wlpd_p->smon.pexcept_cnt =
		     (void *)wl_kmalloc(sizeof(struct except_cnt),
					GFP_ATOMIC))) {
			printk("Error[%s:%d]: Allocating Core Dump Memory \n",
			       __func__, __LINE__);
			return 0;
		}
		memset(wlpd_p->smon.pexcept_cnt, 0, sizeof(struct except_cnt));
	}

	if (!wlpd_p->smon.piocmdlog) {
		if (!
		    (wlpd_p->smon.piocmdlog =
		     (void *)wl_kmalloc(WLMON_PRNT_BUF_SIZE, GFP_ATOMIC))) {
			printk("Error[%s:%d]: Allocating IOCTL fwcmd log Memory \n", __func__, __LINE__);
			return 0;
		}
		memset(wlpd_p->smon.piocmdlog, 0, WLMON_PRNT_BUF_SIZE);
		wlpd_p->smon.cmdlogidx =
			(UINT32) sprintf((char *)wlpd_p->smon.piocmdlog,
					 "\n--- Starting IOCTL FwCmd log---\n");
	}
	//allocating SMAC_STATUS_st buffer for smac status checking.
	if (!wlpd_p->smon.psmacStatus) {

		SMAC_STATUS_st *ptemp = NULL;

		//Allocate 2*sizeof(SMAC_STATUS_st) for store old, @[0], and current, @[1], SMAC_STATUS_st counters. 
		if (!
		    (wlpd_p->smon.psmacStatus =
		     (void *)wl_kmalloc(2 * sizeof(SMAC_STATUS_st),
					GFP_ATOMIC))) {
			printk("Error[%s:%d]: Allocating MAC_STATUS_st log Memory \n", __func__, __LINE__);
			return 0;
		}
		memset(wlpd_p->smon.psmacStatus, 0, 2 * sizeof(SMAC_STATUS_st));
		ptemp = (SMAC_STATUS_st *) wlpd_p->smon.psmacStatus;
		pCurSmacStatus = &ptemp[1];
	}
	//Todo: for efficiency, should integrate psmacStatusLog with psmacStatus later 
	if (!wlpd_p->smon.psmacStatusLog) {

		//Allocate 2*sizeof(SMAC_STATUS_st) for store old, @[0], and current, @[1], SMAC_STATUS_st counters. 
		if (!
		    (wlpd_p->smon.psmacStatusLog =
		     (void *)wl_kmalloc(MAX_SMACSTATUS_LOG_ENTRY *
					sizeof(SMAC_STATUS_st), GFP_ATOMIC))) {
			printk("Error[%s:%d]: Allocating MAC_STATUS_st log buffer \n", __func__, __LINE__);
			return 0;
		}
		memset(wlpd_p->smon.psmacStatusLog, 0,
		       MAX_SMACSTATUS_LOG_ENTRY * sizeof(SMAC_STATUS_st));
		wlpd_p->smon.smacStatusLogIdx = 0;
	}

	if (!wlpd_p->smon.psmacWarningLog[0]) {
		for (i = 0; i < MAX_SMACSTATUS_LOG_ENTRY; i++) {
			if (!
			    (wlpd_p->smon.psmacWarningLog[i] =
			     (void *)wl_kmalloc(SMACSTATUS_LOG_MAX_LENGTH,
						GFP_ATOMIC))) {
				printk("Error[%s:%d]: Allocating MAC_STATUS_st log buffer \n", __func__, __LINE__);
				return 0;
			}
			memset(wlpd_p->smon.psmacWarningLog[i], 0,
			       SMACSTATUS_LOG_MAX_LENGTH);
		}
	}
	if (!wlpd_p->smon.psmacScheduleInfo[0]) {
		for (i = 0; i < MAX_SMACSTATUS_LOG_ENTRY; i++) {
			if (!
			    (wlpd_p->smon.psmacScheduleInfo[i] =
			     (void *)wl_kmalloc(SMACSTATUS_LOG_MAX_LENGTH,
						GFP_ATOMIC))) {
				printk("Error[%s:%d]: Allocating MAC_STATUS_st log buffer \n", __func__, __LINE__);
				return 0;
			}
			memset(wlpd_p->smon.psmacScheduleInfo[i], 0,
			       SMACSTATUS_LOG_MAX_LENGTH);
		}
	}
	if (!wlpd_p->smon.psmacPktcnt[0]) {
		for (i = 0; i < MAX_SMACSTATUS_LOG_ENTRY; i++) {
			if (!
			    (wlpd_p->smon.psmacPktcnt[i] =
			     (void *)wl_kmalloc(SMACSTATUS_LOG_MAX_LENGTH,
						GFP_ATOMIC))) {
				printk("Error[%s:%d]: Allocating MAC_STATUS_st log buffer \n", __func__, __LINE__);
				return 0;
			}
			memset(wlpd_p->smon.psmacPktcnt[i], 0,
			       SMACSTATUS_LOG_MAX_LENGTH);
		}
	}
	//per SMAC request, add "stat 1" info to log 
	if (!wlpd_p->smon.psmacGenInfo[0]) {
		for (i = 0; i < MAX_SMACSTATUS_LOG_ENTRY; i++) {
			if (!
			    (wlpd_p->smon.psmacGenInfo[i] =
			     (void *)wl_kmalloc(SMACSTATUS_LOG_MAX_LENGTH,
						GFP_ATOMIC))) {
				printk("Error[%s:%d]: Allocating MAC_STATUS_st log buffer (psmacGenInfo) \n", __func__, __LINE__);
				return 0;
			}
			memset(wlpd_p->smon.psmacGenInfo[i], 0,
			       SMACSTATUS_LOG_MAX_LENGTH);
		}
	}

	if (!wlpd_p->smon.pPFWSchInfo) {
		if (!
		    (wlpd_p->smon.pPFWSchInfo =
		     (void *)wl_kmalloc(sizeof(QS_TX_SCHEDULER_INFO_t),
					GFP_ATOMIC))) {
			printk("Error[%s:%d]: Allocating PFW scheduler Info log Memory \n", __func__, __LINE__);
			return 0;
		}
		memset(wlpd_p->smon.pPFWSchInfo, 0,
		       sizeof(QS_TX_SCHEDULER_INFO_t));
	}

	if (!wlpd_p->smon.pStaDbTable) {

		if (!
		    (wlpd_p->smon.pStaDbTable =
		     (void *)wl_kmalloc(sizeof(sta_db_snap), GFP_ATOMIC))) {
			printk("Error[%s:%d]: Allocating sta db snap pool\n",
			       __func__, __LINE__);
			return 0;
		}
		memset(wlpd_p->smon.pStaDbTable, 0, sizeof(sta_db_snap));
	}

	if (!wlpd_p->smon.pLastCmdBuf) {

		if (!
		    (wlpd_p->smon.pLastCmdBuf =
		     (void *)wl_kmalloc(HM_CMDBUF_SIZE, GFP_ATOMIC))) {
			printk("Error[%s:%d]: Allocating HM temp cmd buffer fail\n", __func__, __LINE__);
			return 0;
		}
		memset(wlpd_p->smon.pLastCmdBuf, 0, HM_CMDBUF_SIZE);
	}

	if (!wlpd_p->smon.active) {
		//default enable HM
		wldbgCoreMonitor(netdev, WLMON_DEFAULT_DISABLE,
				 WLMON_DEFAULT_HMMASK, SMAC_STATUS_FORMAT_RAW);
	}

	wlpd_p->smon.temperature_threshold =
		WLMON_DEFAULT_TEMPERATURE_THRESHOLD;
	wlpd_p->smon.temperature_threshold_host =
		WLMON_DEFAULT_TEMPERATURE_THRESHOLD_HOST;

#ifdef CONFIG_ARMADA3900_ICU_MCI
	if (notifier_registered == false) {
		register_mci_err_handler(&ap8x_mci_bus_notifier);
		notifier_registered = true;
	}
#endif
	wlpd_p->smon.ready = 1;

	for (;;) {

		if (kthread_should_stop())
			break;

		if (wlmon_recovery_detect(netdev)) {
			wlmon_config_fw_exception(netdev);
			wlmon_fw_recovery(netdev);
		}

		if (wlpd_p->bfwreset == TRUE) {
			goto _next;
		}

		if (wlpd_p->smon.exceptionCmdTOEvt_rcvd) {
			char logbuf[128];
			int size;

			printk("[HM]: Cmd Timeout detected. Auto active fw exception event\n");
			wlpd_p->smon.exceptionEvt_rcvd = 1;
			wlpd_p->smon.exceptionCmdTOEvt_rcvd = 0;

			if (wlpd_p->bus_type == BUS_TYPE_MCI)
				wlmon_dbg_show_last_cmd_fw_processed(netdev);
			wlmon_dbg_show_alivecnt(netdev);

			size = (UINT32) sprintf(&logbuf[0],
						"[HM]: Cmd Timeout detected. Auto active fw exception event\n");
			hm_dump_file(wlpd_p, logbuf, strlen(logbuf),
				     (UINT8 *) stsfname, 1);

			wlmon_dbg_show_adma_cmd_status(netdev);

		}

		if (wlpd_p->smon.exceptionEvt_rcvd ||
		    wlpd_p->smon.exceptionDelayCoreDumpCnt) {

			//during delay coredump period. Ignore any new incoming exception event
			//if not in delaycoredump period, setup delay coredump 
			if (wlpd_p->smon.exceptionDelayCoreDumpCnt == 0)
				wlpd_p->smon.exceptionDelayCoreDumpCnt =
					DELAY_COREDUMP_TIME;

			if (wlpd_p->smon.exceptionEvt_rcvd) {
				u32 is_sfw;
				wl_util_lock(netdev);
				is_sfw = (wlpptr->smacStatusAddr->smacSts[7] == 0x07390000);
				wl_util_unlock(netdev);
				wlmon_ext_trigger_assert(netdev);
				printk("%s CoreDump of receiving %s exception event:\n", wlpd_p->rootdev->name, is_sfw ? "SFW" : "PFW");
				//print drv/fw version number
				wlmon_show_version(netdev, stsfname);
				wlmon_show_thermal(netdev);
			}

			//dump the last 5 second info before exception received.
			if (wlpd_p->smon.exceptionEvt_rcvd &&
			    wlpd_p->smon.exceptionDelayCoreDumpCnt ==
			    DELAY_COREDUMP_TIME) {

				if (wlmon_smacstatus_log_dump
				    (netdev, (void **)&pbuf, stsfname, 0)) {
					hm_dump_file(wlpd_p, pbuf, strlen(pbuf),
						     (UINT8 *) stsfname, 1);
					wl_kfree(pbuf);
				}
			}

			wlpd_p->smon.exceptionEvt_rcvd = 0;

			//keep collect data for next 5 second after exception received.
			if (--(wlpd_p->smon.exceptionDelayCoreDumpCnt) > 0) {
				/*  no need to log smac status after fw exception. 
				   UINT64 tms;

				   convert_tscale(xxGetTimeStamp(),NULL, &tms, NULL);
				   //copy to smac log buffer
				   wlmon_smacstatus_log_buffer(netdev, wlpptr->smacStatusAddr, (tms*1000LL));
				 */
				goto _next;
			} else {
				//done to collect next 5 second info after exception. dumping them out. 
				if (wlmon_smacstatus_log_dump
				    (netdev, (void **)&pbuf, stsfname, 1)) {

					sprintf(enddump, "%s%s", stsfname,
						DUMPEND_SIGNATURE);
					//printk("filename:%s\n",enddump);
					hm_dump_file(wlpd_p, pbuf, strlen(pbuf),
						     (UINT8 *) stsfname, 1);
					wl_kfree(pbuf);
					//create a empty file with the last sts filename as prefix and postfix by __End to denote end of coredump log
					hm_dump_file(wlpd_p, CoreDumpEndSig,
						     strlen(CoreDumpEndSig),
						     (UINT8 *) enddump, 1);
				}
			}

			//PFW alreay in coredumpmode, action=0
			if (wlpd_p->smon.exceptionAbortCmdExec == 0) {
				blocking_notifier_call_chain(&wlpd_p->smon.
							     wlmon_notifier_list,
							     0, (void *)netdev);
			} else {
				printk("Fw cmd timeout, skip pfw active coredump\n");
				//wlpd_p->smon.exceptionAbortCmdExec = 0;
				//msleep(3000);
			}

			wlmon_fw_recovery(netdev);
			goto _next;
		}

		if (wlpd_p->smon.parityErrEvt_rcvd) {
			wlpd_p->smon.parityErrEvt_rcvd = 0;
			printk("[HM]:%s ECC/parity error 0x%X\n",
			       wlpd_p->rootdev->name,
			       wlpd_p->smon.cpu_parity_check_status);
			/* ECC/parity error recovery */
			wlmon_fw_recovery(netdev);
		}

		if (wlmon_smac_detect(netdev)) {
			printk("[HM]: CoreDump of detecting MAC stucks at %s\n",
			       wlpd_p->rootdev->name);
			wlmon_config_fw_exception(netdev);
			goto _next;
		}
		//Collect Active Interface types of this device 
		wlmon_collect_active_interfaces(netdev);

		//printk("%s:Interface %s is %d\n",__func__, wlpd_p->rootdev->name,wlpd_p->smon.ActiveIf);

		if (wlpd_p->smon.ActiveIf && pCurSmacStatus) {
			UINT64 tms;

			wl_util_lock(netdev);
			memcpy(pCurSmacStatus, wlpptr->smacStatusAddr,
			       sizeof(SMAC_STATUS_st));
			wl_util_unlock(netdev);

			convert_tscale(xxGetTimeStamp(), NULL, &tms, NULL);
			wlpd_p->smon.smacStsLogtime[1] = tms;	//record ms timetick of pCurSmacStatus  

			//copy to smac log buffer
			wlmon_smacstatus_log_buffer(netdev, pCurSmacStatus,
						    (tms * 1000LL));

#ifdef AVL_DB_SNAPSHOT
			//log the last snap of avl sta db before coredump
			wlmon_dump_AVL_sta_db(netdev, (tms * 1000LL));
#endif

			if (wlmon_beacon_stuck_detct
			    (netdev, pCurSmacStatus, (void **)&pbuf)) {
				if (!bcnflag) {
					bcnflag = 1;
					printk("[HM]:%s beacon stuck messages dump to %s\n", wlpd_p->rootdev->name, stsfname);
				}
				hm_dump_file(wlpd_p, pbuf, strlen(pbuf),
					     (UINT8 *) stsfname, 1);
				wl_kfree(pbuf);

				wlmon_config_fw_exception(netdev);
				goto _next;
			}

			//Tx Stuck detecting
			if (wlmon_tx_stuck_detct
			    (netdev, pCurSmacStatus, (void **)&pbuf)) {
				if (!txstuckflag) {
					txstuckflag = 1;
					printk("[HM]:%s Tx stuck messages dump to %s\n", wlpd_p->rootdev->name, stsfname);
				}
				hm_dump_file(wlpd_p, pbuf, strlen(pbuf),
					     (UINT8 *) stsfname, 1);
				wl_kfree(pbuf);

				wlmon_config_fw_exception(netdev);
				wlmon_fw_recovery(netdev);
				goto _next;
			}

			//Rx Stuck detecting
			if (wlmon_rx_stuck_detct
			    (netdev, pCurSmacStatus, (void **)&pbuf)) {
				if (!rxstuckflag) {
					rxstuckflag = 1;
					printk("[HM]:%s Rx stuck messages dump to %s\n", wlpd_p->rootdev->name, stsfname);
				}
				hm_dump_file(wlpd_p, pbuf, strlen(pbuf),
					     (UINT8 *) stsfname, 1);
				wl_kfree(pbuf);

				wlmon_config_fw_exception(netdev);
				wlmon_fw_recovery(netdev);
				goto _next;
			}

			//MEM usage check
			if (wlmon_dbg_mem_usage_check(netdev)) {
				wlmon_config_fw_exception(netdev);
				goto _next;
			}
			//log PFW scheduler Info
			if (pfw_scheduler_info_detect(netdev, (void **)&pbuf)) {
				if (!pfwschflag) {
					pfwschflag = 1;
					printk("[HM]:%s PFW schedule delay alarm dump to %s\n", wlpd_p->rootdev->name, stsfname);
				}
				hm_dump_file(wlpd_p, pbuf, strlen(pbuf),
					     (UINT8 *) stsfname, 1);
				wl_kfree(pbuf);
			}
			//store current smac status for next comparing 
			memcpy(wlpd_p->smon.psmacStatus, pCurSmacStatus,
			       sizeof(SMAC_STATUS_st));
			wlpd_p->smon.smacStsLogtime[0] =
				wlpd_p->smon.smacStsLogtime[1];

			if (wlmon_pfw_alive_counters_detct
			    (netdev, (void **)&pbuf)) {
				if (!pfwaliveflag) {
					pfwaliveflag = 1;
					printk("[HM]:%s PFW alive counters alarm dump to %s\n", wlpd_p->rootdev->name, stsfname);
				}
				hm_dump_file(wlpd_p, pbuf, strlen(pbuf),
					     (UINT8 *) stsfname, 1);
				wl_kfree(pbuf);

				wlmon_config_fw_exception(netdev);
				goto _next;
			}

		}

		//active monitor to statistic error counters
		if (wlmon_error_cnt_detect(netdev, (void **)&pbuf)) {
			if (!cntflag) {
				cntflag = 1;
				printk("[HM]:%s statistic error messages dump to %s\n", wlpd_p->rootdev->name, stsfname);
			}
			hm_dump_file(wlpd_p, pbuf, strlen(pbuf),
				     (UINT8 *) stsfname, 1);
			wl_kfree(pbuf);
		}
		//BMQ buffer monitor
		if (wlmon_bmq_resouce_detct(netdev, (void **)&pbuf)) {
			if (!bmqflag) {
				bmqflag = 1;
				printk("[HM]:%s buffer resources messages dump to %s\n", wlpd_p->rootdev->name, stsfname);
			}

			hm_dump_file(wlpd_p, pbuf, strlen(pbuf),
				     (UINT8 *) stsfname, 1);
			wl_kfree(pbuf);
		}
		//note: mochi error monitoring will consume the bandwidth, so the MOCHI_MON default is off 
#ifdef MOCHI_MON
		//mochi error counter monitor
		if (mochi_error_detect(netdev, (void **)&pbuf)) {
			if (!mochiflag) {
				mochiflag = 1;
				printk("[HM]:%s Mochi Error Count dump to %s\n",
				       wlpd_p->rootdev->name, stsfname);
			}

			hm_dump_file(wlpd_p, pbuf, strlen(pbuf),
				     (UINT8 *) stsfname, 1);
			wl_kfree(pbuf);
		}
#endif

		if (wlmon_log_cmd(netdev, (void **)&pbuf)) {
			u8 swNextFile = 0;
			UINT32 size;

			if (!cmdflag) {
				cmdflag = 1;
				printk("[HM]:%s ioctl/cmds dump to %s\n",
				       wlpd_p->rootdev->name, cmdfname);
			}

			swNextFile =
				hm_dump_file(wlpd_p, pbuf, strlen(pbuf),
					     (UINT8 *) cmdfname, 1);
			wl_kfree(pbuf);

			//print cmd log field names at head of this new file
			if (swNextFile) {
				char logbuf[128];

				size = (UINT32) sprintf(&logbuf[0],
							"[CmdTimeStamp]:   DevName  FWCmd   CPUID   PID   ProcName  CmdCmpTime(usec)\n");
				wlmon_log_buffer(netdev, logbuf, size);
			}
		}

		if (wlmon_temperature_check(netdev)) {
			/* todo */
		}
_next:

		if (!wlpptr->wlpd_p->smon.exceptionEvt_rcvd) {
			set_current_state(TASK_INTERRUPTIBLE);
			/* schedule 1 sec */
			timeout = schedule_timeout_interruptible(HZ);
		}
	}

	if (wlpd_p->smon.pexcept_cnt) {
		wl_kfree(wlpd_p->smon.pexcept_cnt);
		wlpd_p->smon.pexcept_cnt = NULL;
	}

	if (wlpd_p->smon.pPFWSchInfo) {
		wl_kfree(wlpd_p->smon.pPFWSchInfo);
		wlpd_p->smon.pPFWSchInfo = NULL;
	}

	if (wlpd_p->smon.psmacStatus) {
		wl_kfree(wlpd_p->smon.psmacStatus);
		wlpd_p->smon.psmacStatus = NULL;
	}

	if (wlpd_p->smon.psmacStatusLog) {
		wl_kfree(wlpd_p->smon.psmacStatusLog);
		wlpd_p->smon.psmacStatusLog = NULL;
	}

	for (i = 0; i < MAX_SMACSTATUS_LOG_ENTRY; i++) {
		if (wlpd_p->smon.psmacWarningLog[i]) {
			wl_kfree(wlpd_p->smon.psmacWarningLog[i]);
			wlpd_p->smon.psmacWarningLog[i] = NULL;
		}
	}
	for (i = 0; i < MAX_SMACSTATUS_LOG_ENTRY; i++) {
		if (wlpd_p->smon.psmacScheduleInfo[i]) {
			wl_kfree(wlpd_p->smon.psmacScheduleInfo[i]);
			wlpd_p->smon.psmacScheduleInfo[i] = NULL;
		}
	}
	for (i = 0; i < MAX_SMACSTATUS_LOG_ENTRY; i++) {
		if (wlpd_p->smon.psmacPktcnt[i]) {
			wl_kfree(wlpd_p->smon.psmacPktcnt[i]);
			wlpd_p->smon.psmacPktcnt[i] = NULL;
		}
	}
	for (i = 0; i < MAX_SMACSTATUS_LOG_ENTRY; i++) {
		if (wlpd_p->smon.psmacGenInfo[i]) {
			wl_kfree(wlpd_p->smon.psmacGenInfo[i]);
			wlpd_p->smon.psmacGenInfo[i] = NULL;
		}
	}

	if (wlpd_p->smon.pStaDbTable) {
		wl_kfree(wlpd_p->smon.pStaDbTable);
		wlpd_p->smon.pStaDbTable = NULL;
	}

	if (wlpd_p->smon.pLastCmdBuf) {
		wl_kfree(wlpd_p->smon.pLastCmdBuf);
		wlpd_p->smon.pLastCmdBuf = NULL;
	}

	if (wlpd_p->smon.piocmdlog) {
		wl_kfree(wlpd_p->smon.piocmdlog);
		wlpd_p->smon.piocmdlog = NULL;
	}

	if (wlpd_p->smon.active) {
		wldbgCoreMonitor(netdev, WLMON_DEFAULT_DISABLE,
				 WLMON_DEFAULT_HMMASK, SMAC_STATUS_FORMAT_RAW);
	}
#ifdef CONFIG_ARMADA3900_ICU_MCI
	if (notifier_registered == true) {
		unregister_mci_err_handler(&ap8x_mci_bus_notifier);
		notifier_registered = false;
	}
#endif

	pr_info("%s break\n", __func__);

	return 0;
}

int
start_wlmon(void *wlp)
{
	struct wlprivate *wlpptr = (struct wlprivate *)wlp;
	struct wlprivate_data *wlpdptr = wlpptr->wlpd_p;
	int rc = 0;
	char name[32];

	sprintf(name, "%s%1d", "wlmon_wdev", wlpptr->cardindex);
	printk("%s monitor thread created\n", name);

	wlpdptr->wlmon_task =
		kthread_create(wlmon_kthread, (void *)wlpptr, name);
	if (IS_ERR(wlpdptr->wlmon_task)) {
		rc = PTR_ERR(wlpdptr->wlmon_task);
		wlpdptr->wlmon_task = NULL;
	} else {
		wake_up_process(wlpdptr->wlmon_task);
		hm_reboot_nofifier_register(1, &hm_reboot_notifier);
	}

	wlmon_ext_trigger_init(wlpptr);
	return rc;
}

int
stop_wlmon(void *wlp)
{
	struct wlprivate *wlpptr = (struct wlprivate *)wlp;

	wlmon_ext_trigger_release(wlpptr);
	if (wlpptr->wlpd_p->wlmon_task) {
		kthread_stop(wlpptr->wlpd_p->wlmon_task);
		wlpptr->wlpd_p->wlmon_task = NULL;
		hm_reboot_nofifier_register(0, &hm_reboot_notifier);
	}

	return 0;
}
