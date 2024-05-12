/** @file ap8xLnxApi.c
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2005-2021 NXP
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
#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/sched.h>
#include <linux/rcupdate.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/dcache.h>

#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/wireless.h>
#include <linux/pci.h>
#include <linux/delay.h>
#include <linux/string.h>
#include <linux/mman.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/firmware.h>
#include <linux/of.h>

#include <net/iw_handler.h>
#include <asm/processor.h>
#include <asm/uaccess.h>

#include "wl.h"
#include "wldebug.h"
#include "ap8xLnxApi.h"
#include "ap8xLnxVer.h"
#include "IEEE_types.h"
#include "wl_mib.h"
#include "wl_hal.h"
#include "ap8xLnxFwcmd.h"
#include "ap8xLnxWlLog.h"
#include "wlApi.h"
#include "qos.h"
#include "ap8xLnxIoctl.h"
#include "ap8xLnxFwdl.h"
#include "StaDb.h"
#include "domain.h"		// Added by ARUN to support 802.11d
#include "wlvmac.h"
#include "macmgmtap.h"
#include "macMgmtMlme.h"
#include "idList.h"
#include "keyMgmtSta.h"
#include "bcngen.h"
#include "wlFun.h"
#include "ap8xLnxRegs.h"
#include "ap8xLnxIntf.h"
#include "ap8xLnxFwcmd.h"
#include "ioctl_cfg80211.h"
#include "ap8xLnxAtf.h"
#ifdef SOC_W906X
#include "ap8xLnxBQM.h"
#include "shal_txinfo.h"
#else
#include "ap8xLnxMug.h"
#endif
#ifdef EWB
#include "ewb_hash.h"
#endif

#ifdef WDS_FEATURE
#include "wds.h"
#endif

#ifdef CLIENT_SUPPORT
#include "linkmgt.h"
#include "mlme.h"
#include "mlmeApi.h"
#endif

#ifdef MPRXY
#include "ap8xLnxMPrxy.h"
#endif

#ifdef NEW_DP
#include "ap8xLnxAcnt.h"
#endif

#ifdef IEEE80211K
#include "msan_report.h"
#endif				//IEEE80211K

#if defined(AP_STEERING_SUPPORT)  && defined(IEEE80211K)
#include "bsstm.h"
#endif				/* AP_STEERING_SUPPORT && IEEE80211K */

#ifdef MULTI_AP_SUPPORT
#include "1905.h"
#endif				/* MULTI_AP_SUPPORT */
Timer wfa_test_timer;


int getMacFromString(unsigned char *macAddr, const char *pStr);
int IPAsciiToNum(unsigned int *IPAddr, const char *pIPStr);

void ratetable_print_SOCW8864(UINT8 * pTbl);

#ifdef AP_STEERING_SUPPORT
#define IW_UTILITY_GET_CH_UTILIZATION_NONWIFI   "getchutil_nonwifi"
#define IW_UTILITY_GET_CH_UTILIZATION_OTHERS    "getchutil_others"
#define IW_UTILITY_GET_CH_UTILIZATION		"getchutil"
#define IW_UTILITY_GET_AP_LIST_RSSI			"getaprssi"
#define IW_UTILITY_GET_STA_COUNT			"getstacnt"
#define IW_UTILITY_GET_STA_BSS_TM			"getstabtm"
#define IW_UTILITY_GET_STA_LIST				"getstalist_for_msan"
#define IW_UTILITY_GET_BTM_RSSI_THRESHOLD	"getbtmrssi"

#define IW_UTILITY_SET_BTM_REQUEST			"btmreq"
#define IW_UTILITY_SET_AP_STEER_ENABLE		"ap_steer_enable"
#define IW_UTILITY_SET_AP_STEER_DISABLE		"ap_steer_disable"
#define IW_UTILITY_SET_STA_THPUT_START		"sta_thput_start"
#define IW_UTILITY_SET_STA_THPUT_STOP		"sta_thput_stop"
#define IW_UTILITY_SET_BTM_RSSI_THRESHOLD	"btm_rssi"

#define IW_UTILITY_SET_BTM_REQUEST_FOR_WTS	"wts_btmreq"
#define IW_UTILITY_GET_STA_RSSI_FOR_WTS		"wts_starssi"
#endif				/* AP_STEERING_SUPPORT */

#ifdef MULTI_AP_SUPPORT
#define IW_UTILITY_MULTI_AP_ATTR			"multiap"
#define IW_UTILITY_MULTI_AP_VERSION			"multiap_version"
#define IW_UTILITY_multi_ap_vid				"multiap_vid"
#define IW_UTILITY_SET_1905_TLV				"1905tlv"
#endif				/* MULTI_AP_SUPPORT */

#define WPAHEX64

#define MAX_IOCTL_PARAMS                4
#define MAX_IOCTL_PARAM_LEN             64

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 6)
#define NIPQUAD(addr) \
	((unsigned char*)&addr)[0], \
	((unsigned char*)&addr)[1], \
	((unsigned char*)&addr)[2], \
	((unsigned char*)&addr)[3]
#endif

/*
 * Statistics flags (bitmask in (struct iw_quality *)->updated)
 */
#ifndef IW_QUAL_QUAL_UPDATED
#define IW_QUAL_QUAL_UPDATED    0x01	/* Value was updated since last read */
#define IW_QUAL_LEVEL_UPDATED   0x02
#define IW_QUAL_NOISE_UPDATED   0x04
#define IW_QUAL_QUAL_INVALID    0x10	/* Driver doesn't provide value */
#define IW_QUAL_LEVEL_INVALID   0x20
#define IW_QUAL_NOISE_INVALID   0x40
#endif				/* IW_QUAL_QUAL_UPDATED */
#ifndef IW_QUAL_DBM
#define IW_QUAL_DBM 0x08;
#endif
#ifndef IW_QUAL_ALL_UPDATED
#define IW_QUAL_ALL_UPDATED     (IW_QUAL_QUAL_UPDATED | IW_QUAL_LEVEL_UPDATED | IW_QUAL_NOISE_UPDATED)
#endif
#ifndef IW_QUAL_ALL_INVALID
#define IW_QUAL_ALL_INVALID     (IW_QUAL_QUAL_INVALID | IW_QUAL_LEVEL_INVALID | IW_QUAL_NOISE_INVALID)
#endif
static int wlioctl_priv_wlparam(struct net_device *dev, struct iw_request_info *info, void *wrqu, char *extra);

int getMacFromString(unsigned char *macAddr, const char *pStr);

void HexStringToHexDigi(char *outHexData, char *inHexString, USHORT Len);
void HexDigiToHexString(char *outHexSring, char *inHexDigit, USHORT Len);
int IsHexKey(char *keyStr);
extern void wlmon_log_buffer(struct net_device *netdev, UINT8 * buf, UINT32 len);
extern UINT8 getRegulatoryClass(vmacApInfo_t * vmacSta_p);
extern void wldump_txskb_info(struct net_device *netdev);
#ifdef SOC_W906X
extern int _DUTToPoweLevel(u8 * sign, u32 * a, u8 * digit, u32 PowerLevel);
extern int _PoweLevelToDUT(u8 sign, u32 a, u32 b, u8 * digit, UINT32 * PowerLevel);
extern int _atof(u8 * str, u8 * sign, u32 * a, u32 * b, u8 * decDigit);
#endif

#ifdef CLIENT_SUPPORT
static MRVL_SCAN_ENTRY siteSurvey[IEEEtypes_MAX_BSS_DESCRIPTS];
static MRVL_SCAN_ENTRY siteSurveyEntry;
#endif

static IEEEtypes_MacAddr_t bcastMacAddr = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

#define EXT_FW_SIZE 1024 * 1024 * 2
UINT8 *ExtFwImage;

/* Since the scan cmd's return data is the largest one,
   use its size for cmd buffer size */
static char cmdGetBuf[MAX_SCAN_BUF_SIZE];

UINT16 dfs_chirp_count_min = 5;
UINT16 dfs_chirp_time_interval = 1000;
UINT16 dfs_pw_filter = 0x00;
UINT16 dfs_min_num_radar = 5;
UINT16 dfs_min_pri_count = 4;
#ifdef BARBADOS_DFS_TEST
UINT8 dfs_sim_evt = 0;
BOOLEAN dfs_clear_nol = FALSE;
BOOLEAN bForceToNonMonitorMode = FALSE;
#endif
extern UINT32 vht_cap;
extern UINT32 ie192_version;

#ifdef SOC_W906X
extern int use_localadmin_addr;
#endif				/* SOC_W906X */

// This will be used to overwrite the channel # check which determines if this is a 2.4G or 5G frequency band.
// For 4.9 / 5G channels like CH 7 - 16.
BOOLEAN force_5G_channel = FALSE;

BOOLEAN WFA_PeerInfo_HE_CAP_1NSS = FALSE;

#ifdef WFA_TKIP_NEGATIVE
int allow_ht_tkip = 0;
#endif
#ifdef SOC_W906X
UINT32 ofdma_autogrp = 0;
mvl_status_t CH_radio_status[IEEEtypes_MAX_CHANNELS + IEEEtypes_MAX_CHANNELS_A];

int auto_group_ofdma_mu(vmacApInfo_t * vmac_p);
int reset_mode = 3;
#endif

typedef struct fw_mib_s {
	char str[31];
	U8 num;
} fw_mib_t;

fw_mib_t fw_mib_str[MIB_MAX] = {
	{"tf_dra_mode", 1},
	{"tf_max_pe", 1},
	{"tf_alpha", 1},
	{"tf_eta", 1},
	{"tf_ap_max_rssi", 1},
	{"tf_cs_required", 1},
	{"tf_gi_ltf", 1},
	{"tf_mcs", 1},
	{"tf_nss", SMAC_MAX_OFDMA_USERS},
	{"tf_fb_bitmap", 1},
	{"tf_target_rssi", SMAC_MAX_OFDMA_USERS},
	{"tf_targer_per", 1},
	{"tf_a_step", 1},
	{"tf_fec_type", SMAC_MAX_OFDMA_USERS},
	{"tf_dcm", 1},
	{"tf_ru_alloc", SMAC_MAX_OFDMA_USERS},
	{"tf_data_len", SMAC_MAX_OFDMA_USERS},
	{"tf_extra_space", 1},
	{"tf_bsrp_len", 1},
	{"tf_ss_start", SMAC_MAX_OFDMA_USERS},
	{"tf_bw", 1},
	{"txinfo_tf_type", 1},
	{"tf_type", 1},
	{"tf_delta", 1},
	{"ebf_insufficient_ndp_enable", 1},
	{"tf_mu_rts", 1},
	{"tf_ofdma_mumimo_auto", 1},
	{"tf_ofdma_mumimo_len", 1},
	{"tf_mu_ack_seq", 1},
	{"tf_mu_ack_action", 1},
	{"tf_mu_ack_mcs", 1},
	{"tf_mu_ack_nss", SMAC_MAX_OFDMA_USERS},
	{"tf_mu_ack_len", 1},
	{"tf_mu_ack_target_rssi", SMAC_MAX_OFDMA_USERS},
	{"tf_ofdma_txop", 1},
	{"tf_nosig_count_thres", 1},
	{"tf_rateinfo", 2},
	{"tf_mu_rts_ul", 1},
	{"dra_per_th_up_low_rate", 1},
	{"dra_per_th_up_high_rate", 1},
	{"dra_per_th_down_low_rate", 1},
	{"dra_per_th_down_high_rate", 1},
	{"dra_per_th_up_noisy_rate", 1},
	{"dra_per_th_down_noisy_rate", 1},
	{"tf_mu_bar_sta_limit", 1},
	{"dra_per_stdy_state_roll_avg_fac", 1},
	{"dra_per_nf_bin_thresh_lo_2g", 1},
	{"dra_per_nf_bin_thresh_lo_5g", 1},
	{"dra_per_nf_offset_scale_fac_2g", 1},
	{"dra_per_nf_offset_scale_fac_5g", 1},
	{"dra_en_rate_down_jump", 1},
};

typedef struct fw_dbg_s {
	char str[31];
	U8 num;
} fw_dbg_t;

fw_dbg_t fw_dbg_str[FW_DBG_MAX] = {
	{"ul_mu", 1},
};

typedef struct protect_mode_s {
	char str[32];
} protect_mode_t;

protect_mode_t force_protect_str[FORCE_PROTECT_MAX] = {
	{"disable"},
	{"rts"},
	{"cts_to_self"},
};

void FireAOATimer(aoacmddata * paoadata)
{
	char buff[MAX_TLV_LEN];
#define CSI_TYPE 12
#define CSI_TLV_LEN 10
	UINT8 csi_mac_idx = 0;
	extern int wlFwGetTLVSet(struct net_device *netdev, UINT8 act, UINT16 type, UINT16 len, UINT8 * tlvData, char *string_buff);
	extern UINT32 wlDataTx_NDP(struct net_device *netdev, IEEEtypes_MacAddr_t * da, u32 txratectrl);
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, paoadata->netdev);
	IEEEtypes_MacAddr_t mac;
	vmacApInfo_t *mastervmacSta_p;
	UINT8 AOATimerON = 0;
	UINT8 sta_idx = 0;
	char brd_mac_addr[6] = { 0 };
	if (priv->vmacSta_p->master == NULL)
		mastervmacSta_p = priv->vmacSta_p;
	else
		mastervmacSta_p = priv->vmacSta_p->master;

	for (csi_mac_idx = 0; csi_mac_idx < 6; csi_mac_idx++) {
		mac[csi_mac_idx] = paoadata->tlvData[csi_mac_idx + 2];	//MAC Address
	}
	wlFwGetTLVSet(paoadata->netdev, WL_SET, CSI_TYPE, CSI_TLV_LEN, paoadata->tlvData, buff);
	//wlDataTx_NDP(paoadata->netdev, &mac, 0);
	for (sta_idx = 0; sta_idx < AOASupMacNum; sta_idx++) {
		if (memcmp(mastervmacSta_p->aoa.StaAddr[sta_idx], brd_mac_addr, 6) != 0) {
			wlDataTx_NDP(paoadata->netdev, &mastervmacSta_p->aoa.StaAddr[sta_idx], 0);
		}
	}

	for (sta_idx = 0; sta_idx < AOASupMacNum; sta_idx++) {
		if (mastervmacSta_p->aoa.StaCounter[sta_idx] > 0) {
			AOATimerON = 1;
		}
	}
	if (AOATimerON) {
		TimerFireIn(&mastervmacSta_p->aoa.AOATimer, 1, &FireAOATimer, (unsigned char *)&mastervmacSta_p->aoa, mastervmacSta_p->aoa.ticks);
	} else
		printk(" ****** AOATimer STOP ****** \n");
	return;
}

UINT32 isAes4RsnValid(UINT8 ouiType)
{
	if ((ouiType == IEEEtypes_RSN_CIPHER_SUITE_CCMP) ||
	    (ouiType == IEEEtypes_RSN_CIPHER_SUITE_GCMP) ||
	    (ouiType == IEEEtypes_RSN_CIPHER_SUITE_GCMP_256) || (ouiType == IEEEtypes_RSN_CIPHER_SUITE_CCMP_256))
		return TRUE;
	else
		return FALSE;
}

void keymgmt_aesInfoGet(UINT8 ouiType, UINT32 * pKeyTypeId, UINT32 * pKenLen)
{
	switch (ouiType) {
	default:
#ifdef SOC_W906X
	case IEEEtypes_RSN_CIPHER_SUITE_CCMP:
		*pKeyTypeId = KEY_TYPE_ID_CCMP;
		*pKenLen = 16;
		break;
	case IEEEtypes_RSN_CIPHER_SUITE_GCMP:
		*pKeyTypeId = KEY_TYPE_ID_GCMP;
		*pKenLen = 16;
		break;
	case IEEEtypes_RSN_CIPHER_SUITE_GCMP_256:
		*pKeyTypeId = KEY_TYPE_ID_GCMP;
		*pKenLen = 32;
		break;
	case IEEEtypes_RSN_CIPHER_SUITE_CCMP_256:
		*pKeyTypeId = KEY_TYPE_ID_CCMP;
		*pKenLen = 32;
#else
	case IEEEtypes_RSN_CIPHER_SUITE_CCMP:
		*pKeyTypeId = KEY_TYPE_ID_AES;
		*pKenLen = 16;
		break;
	case IEEEtypes_RSN_CIPHER_SUITE_GCMP:
		*pKeyTypeId = KEY_TYPE_ID_GCMP_128;
		*pKenLen = 16;
		break;
	case IEEEtypes_RSN_CIPHER_SUITE_GCMP_256:
		*pKeyTypeId = KEY_TYPE_ID_GCMP_256;
		*pKenLen = 32;
		break;
	case IEEEtypes_RSN_CIPHER_SUITE_CCMP_256:
		*pKeyTypeId = KEY_TYPE_ID_CCMP_256;
		*pKenLen = 32;
#endif
		break;
	}
}

int LoadExternalFw(struct wlprivate *priv, char *filename)
{
	int retval = 1;

#ifdef DEFAULT_MFG_MODE
	if (priv->mfgLoaded) {
		printk("read img file: already done\n");
		return 1;
	}
#endif

	printk("read img file: %s...\n", filename);

	if (request_firmware(&priv->fw_entry, filename, priv->wlpd_p->dev) != 0) {
		dev_err(priv->wlpd_p->dev, "Cannot find firmware: %s\n", filename);
		return 0;
	}

	if (priv->fw_entry->data == NULL) {
		printk("ERROR: Firmware download failed! - CANNOT alloc Firmware size image memory = %d bytes. \n", EXT_FW_SIZE);
		retval = 0;
		goto exit;
	}
	if (priv->fw_entry->size >= EXT_FW_SIZE) {
		printk("ERROR: Firmware download failed! - Firmware size exceeds image memory = %d bytes. \n", EXT_FW_SIZE);
		release_firmware(priv->fw_entry);
		retval = 0;
		goto exit;
	}

	if (!priv->fw_entry->size) {
		/* No file is loaded */
		printk("Error, No file is loaded\n");
		retval = 0;
		goto exit;
	}
	printk("FW len = %d\n", (int)priv->fw_entry->size);

 exit:
	return retval;
}

static bool get_cwd = false;
static char cwd[256];
static void wl_get_cwd(char buf[])
{
	char *cwd;
	struct path pwd, root;
	char tmpbuf[256];

	pwd = current->fs->pwd;
	path_get(&pwd);
	root = current->fs->root;
	path_get(&root);

	cwd = d_path(&pwd, tmpbuf, 256 * sizeof(char));
	printk(KERN_ALERT "The current working directory is %s\n", cwd);
	strcpy(buf, cwd);
}

int LoadExternalFw_from_cwd(struct wlprivate *priv, char *filename)
{
	int retval = 1;
	int i = 0, j;
	char *dirfl_name = NULL;
	struct file *filp;

#ifdef DEFAULT_MFG_MODE
	if (priv->mfgLoaded) {
		printk("read img file: already done\n");
		return 1;
	}
#endif

	if (!get_cwd) {
		wl_get_cwd(cwd);
		get_cwd = true;
	}
	dirfl_name = (char *)wl_kmalloc(strlen(cwd) + strlen(filename) + 2, GFP_KERNEL);
	if (dirfl_name == NULL) {
		printk("ERROR: Firmware download failed! - CANNOT alloc Firmware filename memory.\n");
		return 0;
	}
	// "filename" will include the directory in OpenWrt
	sprintf(dirfl_name, "%s/%s", cwd, filename);
	filename = dirfl_name;
	printk("read img file: %s...\n", filename);
	filp = filp_open(filename, 0, 0);
	if (!IS_ERR(filp)) {
		ExtFwImage = (UINT8 *) wl_kmalloc(EXT_FW_SIZE, GFP_KERNEL);
		if (ExtFwImage == NULL) {
			printk("ERROR: Firmware download failed! - CANNOT alloc Firmware size image memory = %d bytes. \n", EXT_FW_SIZE);
			retval = 0;
			goto exit;
		}
		while ((j = kernel_read(filp, &ExtFwImage[i++], 0x01, &filp->f_pos)) != 0) {
			if (i >= EXT_FW_SIZE) {
				printk("ERROR: Firmware download failed! - Firmware size exceeds image memory = %d bytes. \n", EXT_FW_SIZE);
				wl_kfree(ExtFwImage);
				retval = 0;
				goto exit;
			}
		}
		filp_close(filp, current->files);
	}
	if (!i) {
		/* No file is loaded */
		printk("Error, No file is loaded\n");
		retval = 0;
		goto exit;
	}

	priv->FwPointer = ExtFwImage;
	priv->FwSize = i - 1;

	printk("FW len = %d\n", (int)priv->FwSize);

 exit:
	wl_kfree(dirfl_name);

	return retval;
}

#define NUM_GRPS_2G 19		//group 0~18
#define NUM_GRPS_5G 39		//group 0~38
RateGrp_t RateGrpDefault[MAX_GROUP_PER_CHANNEL] = {
	//group 0
	{4, 0xf, {0x0500, 0x0600, 0x0700, 0x0800}
	 }
	,
	{2, 0xf, {0x0900, 0x0a00}
	 }
	,
	{2, 0xf, {0x0b00, 0x0c00}
	 }
	,
	{8, 0xf, {0x0001, 0x0101, 0x0201, 0x0301, 0x0002, 0x0102, 0x0202, 0x0302}
	 }
	,
	{2, 0xf, {0x0401, 0x0402}
	 }
	,
	{6, 0xf, {0x0501, 0x0601, 0x0701, 0x0502, 0x0602, 0x0702}
	 }
	,
	{2, 0xf, {0x0802, 0x0902}
	 }
	,
	{16, 0xf, {0x0801, 0x0901, 0x0a01, 0x0b01, 0x1001, 0x1101, 0x1201, 0x1301, 0x4002, 0x4102, 0x4202, 0x4302, 0x8002, 0x8102, 0x8202, 0x8302}
	 }
	,
	{4, 0xf, {0x0c01, 0x1401, 0x4402, 0x8402}
	 }
	,
	{12, 0xf, {0x0d01, 0x0e01, 0x0f01, 0x1501, 0x1601, 0x1701, 0x4502, 0x4602, 0x4702, 0x8502, 0x8602, 0x8702}
	 }
	,
	{4, 0xf, {0x4802, 0x4902, 0x8802, 0x8902}
	 }
	,
	{18, 0xf,
	 {0x0005, 0x0105, 0x0205, 0x0305, 0x0405, 0x0505, 0x0605, 0x0705, 0x0006, 0x0106, 0x0206, 0x0306, 0x0406, 0x0506, 0x0606, 0x0706, 0x0806,
	  0x0906}
	 }
	,
	{8, 0xf, {0x0011, 0x0111, 0x0211, 0x0311, 0x0012, 0x0112, 0x0212, 0x0312}
	 }
	,
	{2, 0xf, {0x0411, 0x0412}
	 }
	,
	{6, 0xf, {0x0511, 0x0611, 0x0711, 0x0512, 0x0612, 0x0712}
	 }
	,
	{2, 0xf, {0x0812, 0x0912}
	 }
	,
	{16, 0xf, {0x0811, 0x0911, 0x0a11, 0x0b11, 0x1011, 0x1111, 0x1211, 0x1311, 0x4012, 0x4112, 0x4212, 0x4312, 0x8012, 0x8112, 0x8212, 0x8312}
	 }
	,
	{4, 0xf, {0x0c11, 0x1411, 0x4412, 0x8412}
	 }
	,
	{12, 0xf, {0x0d11, 0x0e11, 0x0f11, 0x1511, 0x1611, 0x1711, 0x4512, 0x4612, 0x4712, 0x8512, 0x8612, 0x8712}
	 }
	,
	{4, 0xf, {0x4812, 0x4912, 0x8812, 0x8912}
	 }
	,
	{18, 0xf,
	 {0x0015, 0x0115, 0x0215, 0x0315, 0x0415, 0x0515, 0x0615, 0x0715, 0x0016, 0x0116, 0x0216, 0x0316, 0x0416, 0x0516, 0x0616, 0x0716, 0x0816,
	  0x0916}
	 }
	,
	{4, 0xf, {0x0022, 0x0122, 0x0222, 0x0322}
	 }
	,
	{1, 0xf, {0x0422}
	 }
	,
	{3, 0xf, {0x0522, 0x0622, 0x0722}
	 }
	,
	{2, 0xf, {0x0822, 0x0922}
	 }
	,
	{8, 0xf, {0x4022, 0x4122, 0x4222, 0x4322, 0x8022, 0x8122, 0x8222, 0x8322}
	 }
	,
	{2, 0xf, {0x4422, 0x8422}
	 }
	,
	{6, 0xf, {0x4522, 0x4622, 0x4722, 0x8522, 0x8622, 0x8722}
	 }
	,
	{4, 0xf, {0x4822, 0x4922, 0x8822, 0x8922}
	 }
	,
	{10, 0xf, {0x0026, 0x0126, 0x0226, 0x0326, 0x0426, 0x0526, 0x0626, 0x0726, 0x0826, 0x0926}
	 }
	,
	{4, 0xf, {0x0032, 0x0132, 0x0232, 0x0332}
	 }
	,
	{1, 0xf, {0x0432}
	 }
	,
	{3, 0xf, {0x0532, 0x0632, 0x0732}
	 }
	,
	{2, 0xf, {0x0832, 0x0932}
	 }
	,
	{8, 0xf, {0x4032, 0x4132, 0x4232, 0x4332, 0x8032, 0x8132, 0x8232, 0x8332}
	 }
	,
	{2, 0xf, {0x4432, 0x8432}
	 }
	,
	{6, 0xf, {0x4532, 0x4632, 0x4732, 0x8532, 0x8632, 0x8732}
	 }
	,
	{4, 0xf, {0x4832, 0x4932, 0x8832, 0x8932}
	 }
	,
	// group 38
	{10, 0xf, {0x0036, 0x0136, 0x0236, 0x0336, 0x0436, 0x0536, 0x0636, 0x0736, 0x0836, 0x0936}
	 }
	,
	//end of group
	{0}
	,
};

static const long frequency_list[] = {
	2412, 2417, 2422, 2427, 2432, 2437, 2442,
	2447, 2452, 2457, 2462, 2467, 2472, 2484
};

static const int index_to_rate[] = {
	2, 4, 11, 22, 44, 12, 18, 24, 36, 48, 72, 96, 108, 144
};

static unsigned short PhyRate[][5] = {
	{2, 13, 15, 27, 30},	//0
	{4, 26, 29, 54, 60},	//1
	{11, 39, 43, 81, 90},	//2
	{22, 52, 58, 108, 120},	//3
	{44, 78, 87, 162, 180},	//4
	{12, 104, 115, 216, 240},	//5
	{18, 117, 130, 243, 270},	//6
	{24, 130, 144, 270, 300},	//7
	{36, 26, 29, 54, 60},	//8
	{48, 52, 58, 108, 120},	//9
	{72, 78, 87, 162, 180},	//10
	{96, 104, 116, 216, 240},	//11
	{108, 156, 173, 324, 360},	//12
	{0, 208, 231, 432, 480},	//13
	{0, 234, 260, 486, 540},	//14
	{0, 260, 289, 540, 600},	//15

	{0, 39, 43, 81, 90},	//16
	{0, 78, 87, 162, 180},	//17
	{0, 117, 130, 243, 270},	//18
	{0, 156, 173, 324, 360},	//19
	{0, 234, 260, 486, 540},	//20
	{0, 312, 347, 648, 720},	//21
	{0, 351, 390, 729, 810},	//22
	{0, 390, 433, 810, 900},	//23

	/* 4SS */
	{0, 52, 57, 108, 120},	//24
	{0, 104, 115, 216, 240},	//25
	{0, 156, 231, 324, 360},	//26
	{0, 208, 231, 432, 480},	//27
	{0, 312, 346, 648, 720},	//28
	{0, 416, 462, 864, 960},	//29
	{0, 468, 520, 972, 1080},	//30
	{0, 520, 578, 1080, 1200},	//31

};

/*20Mhz: Nss1_LGI, Nss1_SGI, Nss2_LGI, Nss2_SGI, Nss3_LGI, Nss3_SGI, Nss4_LGI, Nss4_SGI */
static unsigned short PhyRate_11ac20M[][8] = {
	{13, 15, 26, 29, 39, 44, 52, 58},	// 0
	{26, 29, 52, 58, 78, 87, 104, 116},	// 1
	{39, 44, 78, 87, 117, 130, 156, 174},	// 2
	{52, 58, 104, 116, 156, 174, 208, 232},	// 3
	{78, 87, 156, 174, 234, 260, 312, 346},	// 4
	{104, 116, 208, 231, 312, 347, 416, 462},	// 5
	{117, 130, 234, 260, 351, 390, 468, 520},	// 6
	{130, 145, 260, 289, 390, 434, 520, 578},	// 7
	{156, 174, 312, 347, 468, 520, 624, 694},	// 8
	{174, 193, 347, 386, 520, 578, 694, 772},	// 9
};

/*40Mhz: Nss1_LGI, Nss1_SGI, Nss2_LGI, Nss2_SGI, Nss3_LGI, Nss3_SGI, Nss4_LGI, Nss4_SGI */
static unsigned short PhyRate_11ac40M[][8] = {
	{27, 30, 54, 60, 81, 90, 108, 120},	// 0
	{54, 60, 108, 120, 162, 180, 216, 240},	// 1
	{81, 90, 162, 180, 243, 270, 324, 360},	// 2
	{108, 120, 216, 240, 324, 360, 432, 480},	// 3
	{162, 180, 324, 360, 486, 540, 648, 720},	// 4
	{216, 240, 432, 480, 648, 720, 864, 960},	// 5
	{243, 270, 486, 540, 729, 810, 972, 1080},	// 6
	{270, 300, 540, 600, 810, 900, 1080, 1200},	// 7
	{324, 360, 648, 720, 972, 1080, 1296, 1440},	// 8
	{360, 400, 720, 800, 1080, 1200, 1440, 1600},	// 9
};

/*80Mhz: Nss1_LGI, Nss1_SGI, Nss2_LGI, Nss2_SGI, Nss3_LGI, Nss3_SGI, Nss4_LGI, Nss4_SGI */
static unsigned short PhyRate_11ac80M[][8] = {
	{59, 65, 117, 130, 175, 195, 234, 260},	// 0
	{117, 130, 234, 260, 351, 390, 468, 520},	// 1
	{175, 195, 351, 390, 527, 585, 702, 780},	// 2
	{234, 260, 468, 520, 702, 780, 936, 1040},	// 3
	{351, 390, 702, 780, 1053, 1170, 1404, 1560},	// 4
	{468, 520, 936, 1040, 1404, 1560, 1872, 2080},	// 5
	{527, 585, 1053, 1170, 2, 2, 2106, 2340},	// 6, Nss 3 mcs6 not valid.
	{585, 650, 1170, 1300, 1755, 1950, 2340, 2600},	// 7
	{702, 780, 1404, 1560, 2106, 2340, 2808, 3120},	// 8
	{780, 867, 1560, 1733, 2340, 2600, 3120, 3466},	// 9

};

/*160Mhz: Nss1_LGI, Nss1_SGI, Nss2_LGI, Nss2_SGI, Nss3_LGI, Nss3_SGI, Nss4_LGI, Nss4_SGI */
static unsigned short PhyRate_11ac160M[][8] = {
	{117, 130, 234, 260, 351, 390, 468, 520},	// 0
	{234, 260, 468, 520, 702, 780, 936, 1040},	// 1
	{351, 390, 702, 780, 1053, 1170, 1404, 1560},	// 2
	{468, 520, 936, 1040, 1404, 1560, 1872, 2080},	// 3
	{702, 780, 1404, 1560, 2106, 2340, 2808, 3120},	// 4
	{936, 1040, 1872, 2080, 2808, 3120, 3744, 4160},	// 5
	{1053, 1170, 2106, 2340, 3159, 3510, 4212, 4680},	// 6
	{1170, 1300, 2340, 2600, 3510, 3900, 4680, 5200},	// 7
	{1404, 1560, 2808, 3120, 4212, 4680, 5616, 6240},	// 8
	{1560, 1733, 2130, 3467, 4680, 5200, 6240, 6934},	// 9
};

static const UINT32 HE_PHY_RATE[12][8][3][2] = {
	{			//MCS0
	 {{7300, 3600}, {8100, 4000}, {8600, 4300}},
	 {{14600, 7300}, {16300, 8100}, {17200, 8600}},
	 {{21900, 0}, {24400, 0}, {25800, 0}},
	 {{29300, 0}, {32500, 0}, {34400, 0}},
	 {{36600, 0}, {40600, 0}, {43000, 0}},
	 {{43900, 0}, {48800, 0}, {51600, 0}},
	 {{51200, 0}, {56900, 0}, {60200, 0}},
	 {{58500, 0}, {65000, 0}, {68800, 0}},
	 },
	{			//MCS1
	 {{14600, 7300}, {16300, 8100}, {17200, 8600}},
	 {{29300, 14600}, {32500, 16300}, {34400, 17200}},
	 {{43900, 0}, {48800, 0}, {51600, 0}},
	 {{58500, 0}, {65000, 0}, {68800, 0}},
	 {{73100, 0}, {81300, 0}, {86000, 0}},
	 {{87800, 0}, {97500, 0}, {103200, 0}},
	 {{102400, 0}, {113800, 0}, {120400, 0}},
	 {{117000, 0}, {130000, 0}, {137600, 0}},
	 },
	{			//MCS2
	 {{21900, 0}, {24400, 0}, {25800, 0}},
	 {{43900, 0}, {48800, 0}, {51600, 0}},
	 {{65800, 0}, {73100, 0}, {77400, 0}},
	 {{87800, 0}, {97500, 0}, {103200, 0}},
	 {{109700, 0}, {121900, 0}, {129000, 0}},
	 {{131600, 0}, {146300, 0}, {154900, 0}},
	 {{153600, 0}, {170600, 0}, {180700, 0}},
	 {{175500, 0}, {195999, 0}, {206500, 0}},
	 },
	{			//MCS3
	 {{29300, 14600}, {32500, 16300}, {34400, 17200}},
	 {{58500, 29300}, {65000, 32500}, {68800, 34400}},
	 {{87800, 0}, {97500, 0}, {103200, 0}},
	 {{117000, 0}, {130000, 0}, {137700, 0}},
	 {{146300, 0}, {162500, 0}, {172100, 0}},
	 {{175500, 0}, {195000, 0}, {206500, 0}},
	 {{204800, 0}, {227500, 0}, {240900, 0}},
	 {{234000, 0}, {260000, 0}, {275300, 0}},

	 },

	{			//MCS4 
	 {{43900, 21900}, {48800, 24400}, {51600, 25800}},
	 {{87800, 43900}, {97500, 48800}, {103200, 51600}},
	 {{131600, 0}, {146300, 0}, {154900, 0}},
	 {{175500, 0}, {195000, 0}, {206500, 0}},
	 {{219400, 0}, {243800, 0}, {258100, 0}},
	 {{263300, 0}, {292500, 0}, {309700, 0}},
	 {{307100, 0}, {341300, 0}, {361300, 0}},
	 {{351000, 0}, {390000, 0}, {412900, 0}},
	 },
	{			//MCS5
	 {{58500, 0}, {65000, 0}, {68800, 0}},
	 {{117000, 0}, {130000, 0}, {137600, 0}},
	 {{175500, 0}, {195000, 0}, {206500, 0}},
	 {{234000, 0}, {260000, 0}, {275300, 0}},
	 {{292500, 0}, {325000, 0}, {344100, 0}},
	 {{351000, 0}, {390000, 0}, {412900, 0}},
	 {{409500, 0}, {455000, 0}, {481800, 0}},
	 {{468000, 0}, {520000, 0}, {550600, 0}},

	 },

	{			//MCS6 
	 {{65800, 0}, {73100, 0}, {77400, 0}},
	 {{131600, 0}, {146300, 0}, {154900, 0}},
	 {{197400, 0}, {219400, 0}, {232300, 0}},
	 {{263300, 0}, {292500, 0}, {309700, 0}},
	 {{329100, 0}, {365600, 0}, {387100, 0}},
	 {{394900, 0}, {438800, 0}, {464600, 0}},
	 {{460700, 0}, {511900, 0}, {542000, 0}},
	 {{526500, 0}, {585000, 0}, {619400, 0}},
	 },
	{			//MCS7
	 {{73100, 0}, {81300, 0}, {86000, 0}},
	 {{146300, 0}, {162500, 0}, {172100, 0}},
	 {{219400, 0}, {243800, 0}, {258100, 0}},
	 {{292500, 0}, {325000, 0}, {344100, 0}},
	 {{365600, 0}, {406300, 0}, {430100, 0}},
	 {{438800, 0}, {487600, 0}, {516200, 0}},
	 {{511900, 0}, {568800, 0}, {602200, 0}},
	 {{585000, 0}, {650000, 0}, {688200, 0}},

	 },

	{			//MCS8 .. 
	 {{87800, 0}, {97500, 0}, {103200, 0}},
	 {{175500, 0}, {195000, 0}, {206500, 0}},
	 {{263300, 0}, {292500, 0}, {309700, 0}},
	 {{351000, 0}, {390000, 0}, {412900, 0}},
	 {{438800, 0}, {487500, 0}, {516200, 0}},
	 {{526500, 0}, {585000, 0}, {619400, 0}},
	 {{614300, 0}, {682500, 0}, {722600, 0}},
	 {{702000, 0}, {780000, 0}, {825900, 0}},
	 },
	{			//MCS9
	 {{97500, 0}, {108300, 0}, {114700, 0}},
	 {{195000, 0}, {216700, 0}, {229400, 0}},
	 {{292500, 0}, {325000, 0}, {344100, 0}},
	 {{390000, 0}, {433300, 0}, {458800, 0}},
	 {{487500, 0}, {541700, 0}, {573500, 0}},
	 {{585000, 0}, {650000, 0}, {688200, 0}},
	 {{682500, 0}, {758300, 0}, {802900, 0}},
	 {{780000, 0}, {866700, 0}, {917600, 0}},

	 },

	{			//MCS10. 
	 {{109700, 0}, {121900, 0}, {129000, 0}},
	 {{219400, 0}, {243800, 0}, {258100, 0}},
	 {{329100, 0}, {365600, 0}, {387100, 0}},
	 {{438800, 0}, {487500, 0}, {516200, 0}},
	 {{548400, 0}, {609400, 0}, {645200, 0}},
	 {{658100, 0}, {731300, 0}, {774300, 0}},
	 {{767800, 0}, {853100, 0}, {903300, 0}},
	 {{877500, 0}, {975000, 0}, {1032400, 0}},
	 },
	{			//MCS11
	 {{121900, 0}, {135400, 0}, {143400, 0}},
	 {{243800, 0}, {270800, 0}, {286800, 0}},
	 {{365600, 0}, {406300, 0}, {430100, 0}},
	 {{487500, 0}, {541700, 0}, {573500, 0}},
	 {{609400, 0}, {677100, 0}, {716900, 0}},
	 {{731300, 0}, {812500, 0}, {860300, 0}},
	 {{853100, 0}, {947900, 0}, {1003700, 0}},
	 {{970000, 0}, {1083300, 0}, {1147100, 0}},

	 }
};

int legacyRateToId(int rate)
{
	int i;

	for (i = 0; i < 13; i++) {
		if (PhyRate[i][0] == rate)
			return i;
	}
	return -1;
}

#ifdef WNM
void *FindIEWithinIEs(UINT8 * data_p, UINT32 lenPacket, UINT8 attrib, UINT8 * OUI)
#else
void *FindIEWithinIEs(UINT8 * data_p, UINT32 lenPacket, UINT8 attrib, UINT8 * OUI)
#endif				//WNM
{
	UINT32 lenOffset = 0;

	if (lenPacket == 0)
		return NULL;

	while (lenOffset <= lenPacket) {
		if (*(IEEEtypes_ElementId_t *) data_p == attrib) {
			if (attrib == PROPRIETARY_IE) {
				if ((OUI[0] == data_p[2]) && (OUI[1] == data_p[3]) && (OUI[2] == data_p[4]) && (OUI[3] == data_p[5]))
					return data_p;
			} else
				return data_p;
		}

		lenOffset += (2 + *((UINT8 *) (data_p + 1)));
		data_p += (2 + *((UINT8 *) (data_p + 1)));
	}
	return NULL;
}

void *FindAttributeWithinWPSIE(UINT8 * wsc_attr_buf, UINT32 wsc_attr_len, UINT32 target_attr)
{
	UINT32 lenOffset = 0;
	while (lenOffset < wsc_attr_len) {
		if ((wsc_attr_buf[0] == ((target_attr & 0xFF00) >> 8)) && (wsc_attr_buf[1] == (target_attr & 0x00FF))
		    && (0x00 == wsc_attr_buf[2]) && (0x01 == wsc_attr_buf[3])) {
			return wsc_attr_buf;
		}
		lenOffset += (4 + *(wsc_attr_buf + 3));
		wsc_attr_buf += (4 + *(wsc_attr_buf + 3));
	}
	return NULL;
}

static UINT8 gi_convert(UINT8 gi, UINT8 dcm, UINT8 stbc)
{
	//2->1.6us, 1->0.8us, 0->0.8us, dcm & stbc & 3->0.8us, 3->3.2us
	UINT8 converted_gi;
	UINT8 gi_to[3] = { 2, 2, 1 };
	if (gi != 3)
		converted_gi = gi_to[gi];
	else if (dcm && stbc)
		converted_gi = 2;
	else
		converted_gi = 0;
	return converted_gi;
};

UINT16 getPhyRate(dbRateInfo_t * pRateTbl)
{
	UINT16 he_nsd[4] = { 234, 468, 980, 1960 };
	UINT8 index = 0;
	UINT8 Nss_11ac = 0;	//0:Nss==1, 1:Nss==2, 2:Nss==3
	UINT8 Rate_11ac = 0;
	UINT8 Dcm = 0;
	UINT8 stbc = 0;
	UINT8 gi_ = 0;
	if (pRateTbl->Format == 1) {
		index = (pRateTbl->Bandwidth << 1) | pRateTbl->ShortGI;
		index += 1;
	} else if (pRateTbl->Format == 2) {
		Rate_11ac = pRateTbl->RateIDMCS & 0xf;	//11ac, Rate[3:0]
		Nss_11ac = pRateTbl->RateIDMCS >> 4;	//11ac, Rate[6:4] = NssCode                                 iu
		index = (Nss_11ac << 1) | pRateTbl->ShortGI;
	} else if (pRateTbl->Format == 3) {
		Rate_11ac = pRateTbl->RateIDMCS & 0xf;	//11ac, Rate[3:0]
		Nss_11ac = pRateTbl->RateIDMCS >> 4;	//11ac, Rate[6:4] = NssCode
	}

	if (pRateTbl->Format < 2)
		return PhyRate[pRateTbl->RateIDMCS][index] / 2;
	else if (pRateTbl->Format < 3) {
		if (pRateTbl->Bandwidth == 0)
			return PhyRate_11ac20M[Rate_11ac][index] / 2;
		else if (pRateTbl->Bandwidth == 1)
			return PhyRate_11ac40M[Rate_11ac][index] / 2;
		else if (pRateTbl->Bandwidth == 2)
			return PhyRate_11ac80M[Rate_11ac][index] / 2;
		else
			return PhyRate_11ac160M[Rate_11ac][index] / 2;
	} else {
#ifdef SOC_W906X
		Dcm = pRateTbl->Dcm;
		stbc = pRateTbl->Stbc;
		gi_ = gi_convert(pRateTbl->ShortGI, Dcm, stbc);

		if (Dcm && stbc) {
			// Reset these since they are only used for indicating 4x+0.8 us in this case.
			Dcm = 0;
			stbc = 0;
		}
		return ((HE_PHY_RATE[Rate_11ac][Nss_11ac][gi_][Dcm] / 100) * (he_nsd[pRateTbl->Bandwidth])) / 2340;
#else
		return ((HE_PHY_RATE[Rate_11ac][Nss_11ac][pRateTbl->ShortGI][Dcm] / 100) * (pRateTbl->Bandwidth + 1)) / 10;
#endif				/* SOC_W906X */
	}
}

UINT16 getNss(dbRateInfo_t * pRateTbl)
{
	UINT8 Nss_11ac = 0;	//0:Nss==1, 1:Nss==2, 2:Nss==3

	if (pRateTbl->Format == 1) {
		/*empty here */
	} else if (pRateTbl->Format == 2) {
		Nss_11ac = pRateTbl->RateIDMCS >> 4;	//11ac, Rate[6:4] = NssCode
	}
	return Nss_11ac + 1;
}

int rateChecked(int rate, int mode)
{
	int i;
	int minRateIndex = 0;
	int maxRateIndex = 0;

	if (mode == AP_MODE_B_ONLY) {
		maxRateIndex = 4;
	} else if (mode == AP_MODE_G_ONLY) {
		//minRateIndex = 4;
		maxRateIndex = 14;
	} else if (mode == AP_MODE_A_ONLY) {
		minRateIndex = 4;
		maxRateIndex = 14;
	} else if (mode == AP_MODE_N_ONLY) {
		if (((rate >= 256) && (rate <= 279)) || (rate == 288))
			return 1;
		else
			maxRateIndex = 14;
	} else if (mode & AP_MODE_11AC) {
		// SC3 supports only 3 streams
		if (((rate & 0x30) >> 4) > 2) {
			return 0;
		}
		//11ac rate is between mcs0 and mcs9
		if ((rate & 0xf) > 9) {
			return 0;
		}
		return 1;
	} else
		return 0;

	for (i = minRateIndex; i < maxRateIndex; i++) {
		if (index_to_rate[i] == rate)
			return 1;
	}
	return 0;
}

/* Counts the number of ones in the provided bitmap */
UINT32 countNumOnes(UINT32 bitmap)
{
	UINT32 num_ones = 0;

	while (bitmap) {
		num_ones++;
		bitmap &= (bitmap - 1);
	}
	return num_ones;
}

struct iw_statistics *wlGetStats(struct net_device *dev)
{
#ifdef CLIENT_SUPPORT
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	iw_linkInfo_t *linkInfo_p = NULL;

	WLDBG_ENTER(DBG_LEVEL_1);
	if (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_CLNT_INFRA) {
		wlFwGetHwStatsForWlStats(dev, &wlpptr->wlpd_p->wStats);
		linkInfo_p = mlmeApiGetStaLinkInfo(dev);
		if (linkInfo_p) {
			wlpptr->wlpd_p->wStats.qual.level = -linkInfo_p->wStats.qual.level;
			wlpptr->wlpd_p->wStats.qual.noise = -linkInfo_p->wStats.qual.noise;
			wlpptr->wlpd_p->wStats.qual.qual = linkInfo_p->wStats.qual.qual;
			wlpptr->wlpd_p->wStats.qual.updated = IW_QUAL_ALL_UPDATED;
			wlpptr->wlpd_p->wStats.status = 0;
		}
	}

	WLDBG_EXIT(DBG_LEVEL_1);
	return &wlpptr->wlpd_p->wStats;
#else
	return NULL;
#endif
}

#ifdef SSU_SUPPORT
void ssu_dump_file(UINT32 pPhyAddr, UINT32 * pSsuPci, UINT32 sizeBytes, UINT32 printFlag)
{
	struct file *filp_ssu = NULL;
	UINT8 cmdGetBuf[200];
	UINT8 *data_p = cmdGetBuf;
	UINT32 *tmp = pSsuPci;
	UINT32 gap = 0, cnt = 0, ts = 0, id = 0, i, len = 0;

	printk("ssu dump location phys = %x virt = %p len = %d bytes\n", pPhyAddr, pSsuPci, sizeBytes);
	if (pSsuPci == NULL)
		return;

	memset(cmdGetBuf, 0, sizeof(cmdGetBuf));

	filp_ssu = filp_open("/tmp/test_ssu", O_RDWR | O_CREAT | O_TRUNC, 0);

	if (printFlag)
		printk("ssu test open = %p \n", filp_ssu);

	if (!IS_ERR(filp_ssu)) {
		for (i = 0; i < sizeBytes / sizeof(UINT32); i++) {
			if (tmp[i] == 0x12345678) {
				if (ts == 0)
					ts = tmp[i + 3];
				if (id == 0)
					id = tmp[i + 1];

				if (printFlag)
					printk("[%4d] len=%d id=%d ts=%d cnt=%d \n", i, (i - gap), (tmp[i + 1] - id), (tmp[i + 3] - ts), ++cnt);
				len = i - gap;
				gap = i;
				ts = tmp[i + 3];
				id = tmp[i + 1];
			} else if ((i > 64) && (gap > 0) && ((i - gap) == len) && (tmp[i] == 0)) {
				if (printFlag)
					printk("[%d] stop len=%d value=0x%08x total=%d\n", i, (i - gap), tmp[i], (int)(sizeBytes / sizeof(UINT32)));
				break;
			}

			if ((i != 0) && !(i % 8)) {
				data_p += sprintf(data_p, "\n");
				__kernel_write(filp_ssu, cmdGetBuf, strlen(cmdGetBuf), &filp_ssu->f_pos);
				data_p = cmdGetBuf;
				memset(data_p, 0, sizeof(cmdGetBuf));
				data_p += sprintf(data_p, "%08x ", pSsuPci[i]);
			} else {
				data_p += sprintf(data_p, "%08x ", pSsuPci[i]);
			}
		}
		data_p += sprintf(data_p, "\n");
		__kernel_write(filp_ssu, cmdGetBuf, strlen(cmdGetBuf), &filp_ssu->f_pos);
		filp_close(filp_ssu, current->files);
		/* Print out top of SSU dump for debug purposes */
		if (printFlag) {
			for (i = 0; i < 12; i += 4) {
				printk("%08x %08x %08x %08x \n", pSsuPci[i], pSsuPci[i + 1], pSsuPci[i + 2], pSsuPci[i + 3]);
			}
		}
		printk("SSU write to file completed.\n");
	} else {
		printk("SSU file open error! %p \n", filp_ssu);
	}
}
#endif

void SetBwChChangedStatus(struct net_device *dev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	MIB_PHY_DSSS_TABLE *PhyDSSSTable = mib->PhyDSSSTable;
	MIB_802DOT11 *mibOperation = vmacSta_p->Mib802dot11;
	MIB_PHY_DSSS_TABLE *PhyDSSSTableOperation = mibOperation->PhyDSSSTable;
	DfsAp *me;
	DfsApDesc *dfsDesc_p = NULL;

	me = wlpd_p->pdfsApMain;
	dfsDesc_p = (DfsApDesc *) & me->dfsApDesc;
	wlpd_p->bCACBWChanged = FALSE;
	wlpd_p->bCACChannelChanged = FALSE;
	if (PhyDSSSTable->Chanflag.ChnlWidth != PhyDSSSTableOperation->Chanflag.ChnlWidth) {
		wlpd_p->bCACBWChanged = TRUE;
	}

	if (PhyDSSSTable->CurrChan != PhyDSSSTableOperation->CurrChan) {
		wlpd_p->bCACChannelChanged = TRUE;
	}

}

void RestartDataTrafficReset(struct net_device *dev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	DfsAp *me;
	DfsApDesc *dfsDesc_p = NULL;

	me = wlpd_p->pdfsApMain;
	dfsDesc_p = (DfsApDesc *) & me->dfsApDesc;
	macMgmtMlme_RestartDataTraffic(dev);
	macMgmtMlme_Reset(dev, dfsDesc_p->vaplist, &dfsDesc_p->vapcount);
}

void RestartDFS(struct net_device *dev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	DfsAp *me;

	me = wlpd_p->pdfsApMain;
	SetBwChChangedStatus(dev);
	if (wlpptr->wlpd_p->bCACChannelChanged || wlpptr->wlpd_p->bCACBWChanged) {
		DisarmCACTimer(me);
	}

	if (wlpd_p->bCACTimerFired)
		mhsm_transition(&me->super, &me->Dfs_Scan);
	else {
		if (wlpptr->wlpd_p->bCACChannelChanged || wlpptr->wlpd_p->bCACBWChanged) {
			mhsm_transition(&me->super, &me->Dfs_Operational);
		}

		RestartDataTrafficReset(dev);
	}

}

static int wlconfig_commit(struct net_device *dev, struct iw_request_info *info, char *cwrq, char *extra)
{
	int rc = 0;

	WLDBG_IOCTL(DBG_LEVEL_0, "%s:%s CpuID:%u, PID:%i, ProcName:\"%s\"\n",
		    dev->name, __FUNCTION__, smp_processor_id(), current->pid, current->comm);
	WLDBG_ENTER_INFO(DBG_LEVEL_1, "");
	rc = mwl_config_commit(dev);
	WLDBG_EXIT(DBG_LEVEL_1);

	return rc;
}

static int wlget_name(struct net_device *dev, struct iw_request_info *info, char *cwrq, char *extra)
{
	WLDBG_IOCTL(DBG_LEVEL_0, "%s:%s CpuID:%u, PID:%i, ProcName:\"%s\"\n",
		    dev->name, __FUNCTION__, smp_processor_id(), current->pid, current->comm);

	WLDBG_ENTER_INFO(DBG_LEVEL_1, "");

	strcpy(cwrq, "IEEE802.11-DS");

	WLDBG_EXIT(DBG_LEVEL_1);

	return 0;
}

void BFMRinit(struct wlprivate *priv)
{
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;

	if ((vmacSta_p->BFMRinitstatus.chan_init) &&
	    (vmacSta_p->BFMRinitstatus.bw_init) &&
	    (vmacSta_p->BFMRinitstatus.rx_ant_init) &&
	    (vmacSta_p->BFMRinitstatus.tx_ant_init) &&
	    (vmacSta_p->BFMRinitstatus.ht_cap_init) && (vmacSta_p->BFMRinitstatus.addr_init) && (vmacSta_p->BFMRinitstatus.vht_cap_init)) {
		vmacSta_p->BFMRinitDone = TRUE;
	} else {
		vmacSta_p->BFMRinitDone = FALSE;
	}
}

void SendBFMRconfig(struct net_device *dev)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, dev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;

	if (vmacSta_p->BFMRinitDone && vmacSta_p->bBFMRconfigChanged) {

		wlFwNewDP_bfmr_config(dev, &vmacSta_p->BFMRconfig, 0);
		vmacSta_p->bBFMRconfigChanged = FALSE;
	} else if (!vmacSta_p->BFMRinitDone) {
		BFMRinit(priv);
		if (vmacSta_p->BFMRinitDone) {

			wlFwNewDP_bfmr_config(dev, &vmacSta_p->BFMRconfig, 0);
		}
	}
}

static int wlset_freq(struct net_device *dev, struct iw_request_info *info, struct iw_freq *fwrq, char *extra)
{
	int rc = 0;
	int channel = 0;

	WLDBG_ENTER_INFO(DBG_LEVEL_1, "");

	if ((fwrq->e == 1) && (fwrq->m >= (int)2.412e8) && (fwrq->m <= (int)2.487e8)) {
		int f = fwrq->m / 100000;
		int c = 0;
		while ((c < 14) && (f != frequency_list[c]))
			c++;
		fwrq->e = 0;
		fwrq->m = c + 1;
	}

	if ((fwrq->m > 1000) || (fwrq->e > 0))
		return -EOPNOTSUPP;
	else
		channel = fwrq->m;

	WLDBG_IOCTL(DBG_LEVEL_0, "%s:%s channel %d CpuID:%u, PID:%i, ProcName:\"%s\"\n",
		    dev->name, __FUNCTION__, channel, smp_processor_id(), current->pid, current->comm);

	rc = mwl_config_set_channel(dev, channel);

	WLDBG_EXIT(DBG_LEVEL_1);

	return rc;
}

static int wlget_freq(struct net_device *dev, struct iw_request_info *info, struct iw_freq *fwrq, char *extra)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, dev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	MIB_PHY_DSSS_TABLE *PhyDSSSTable = mib->PhyDSSSTable;

	WLDBG_ENTER_INFO(DBG_LEVEL_1, "");

	fwrq->m = PhyDSSSTable->CurrChan;
	fwrq->e = 0;

	WLDBG_IOCTL(DBG_LEVEL_0, "%s:%s channel %d CpuID:%u, PID:%i, ProcName:\"%s\"\n",
		    dev->name, __FUNCTION__, PhyDSSSTable->CurrChan, smp_processor_id(), current->pid, current->comm);

	WLDBG_EXIT(DBG_LEVEL_1);

	return 0;
}

static int wlget_sens(struct net_device *dev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
#ifdef CLIENT_SUPPORT
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	iw_linkInfo_t *linkInfo_p = NULL;

	if (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_CLNT_INFRA) {
		linkInfo_p = mlmeApiGetStaLinkInfo(dev);
		if (linkInfo_p) {
			wrqu->sens.fixed = 1;
			wrqu->sens.value = linkInfo_p->wStats.qual.qual;
		}
	}
#endif
	WLDBG_IOCTL(DBG_LEVEL_0, "%s:%s CpuID:%u, PID:%i, ProcName:\"%s\"\n",
		    dev->name, __FUNCTION__, smp_processor_id(), current->pid, current->comm);
	return 0;
}

static int wlget_range(struct net_device *dev, struct iw_request_info *info, struct iw_point *dwrq, char *extra)
{
#ifdef CLIENT_SUPPORT
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	iw_linkInfo_t *linkInfo_p = NULL;
	struct iw_range *range;

	WLDBG_ENTER_INFO(DBG_LEVEL_1, "");
	range = (struct iw_range *)extra;
	dwrq->length = sizeof(struct iw_range);
	memset(range, 0, sizeof(struct iw_range));

	range->we_version_compiled = WIRELESS_EXT;
	range->throughput = 0;
	range->min_nwid = 0x00;
	range->max_nwid = 0x1FF;

	if (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_CLNT_INFRA) {
		linkInfo_p = mlmeApiGetStaLinkInfo(dev);
		if (linkInfo_p) {
			range->sensitivity = linkInfo_p->max_qual.qual;

			range->max_qual.qual = linkInfo_p->max_qual.qual;
			range->max_qual.level = linkInfo_p->max_qual.level;
			range->max_qual.noise = linkInfo_p->max_qual.noise;
			range->max_qual.updated = IW_QUAL_ALL_UPDATED;

			range->avg_qual.qual = linkInfo_p->avg_qual.qual;
			range->avg_qual.level = linkInfo_p->avg_qual.level;
			range->avg_qual.noise = linkInfo_p->avg_qual.noise;
			range->avg_qual.updated = IW_QUAL_ALL_UPDATED;
		}
	}

	WLDBG_EXIT(DBG_LEVEL_1);
#endif
	WLDBG_IOCTL(DBG_LEVEL_0, "%s:%s CpuID:%u, PID:%i, ProcName:\"%s\"\n",
		    dev->name, __FUNCTION__, smp_processor_id(), current->pid, current->comm);
	return 0;
}

static int wlget_stats(struct net_device *dev, struct iw_request_info *info, struct iw_statistics *stats, char *extra)
{
#ifdef CLIENT_SUPPORT
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	iw_linkInfo_t *linkInfo_p = NULL;

	WLDBG_ENTER_INFO(DBG_LEVEL_1, "");

	if (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_CLNT_INFRA) {
		linkInfo_p = mlmeApiGetStaLinkInfo(dev);
		memset(stats, 0, sizeof(struct iw_statistics));

		if (linkInfo_p) {
			stats->qual.level = linkInfo_p->wStats.qual.level;
			stats->qual.noise = linkInfo_p->wStats.qual.noise;
			stats->qual.qual = linkInfo_p->wStats.qual.qual;
			stats->qual.updated = IW_QUAL_ALL_UPDATED | IW_QUAL_DBM;
		}

		wlFwGetHwStatsForWlStats(dev, stats);
	}

	WLDBG_EXIT(DBG_LEVEL_1);
#endif
	WLDBG_IOCTL(DBG_LEVEL_0, "%s:%s CpuID:%u, PID:%i, ProcName:\"%s\"\n",
		    dev->name, __FUNCTION__, smp_processor_id(), current->pid, current->comm);
	return 0;
}

static int wlset_scan(struct net_device *dev, struct iw_request_info *info, struct iw_point *srq, char *extra)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
	struct iw_request_info infoScan;
	struct scanParam {
		int Param;
		int Value;
	} scanParam;

	scanParam.Param = WL_PARAM_STASCAN;
	scanParam.Value = 0x01;
	wlpptr->cmdFlags = srq->flags;
	wlioctl_priv_wlparam(dev, (struct iw_request_info *)&infoScan, (void *)srq, (char *)&scanParam);
	WLDBG_IOCTL(DBG_LEVEL_0, "%s:%s CpuID:%u, PID:%i, ProcName:\"%s\"\n",
		    dev->name, __FUNCTION__, smp_processor_id(), current->pid, current->comm);
	return 0;
}

#ifdef CLIENT_SUPPORT
static UINT32 add_IE(UINT8 * buf, UINT32 bufsize, const UINT8 * ie, UINT32 ielen, const char *header, UINT32 header_len)
{
	UINT8 *strEnd;
	int i;

	if (bufsize < header_len)
		return 0;
	strEnd = buf;
	memcpy(strEnd, header, header_len);
	bufsize -= header_len;
	strEnd += header_len;
	for (i = 0; i < ielen && bufsize > 2; i++) {
		strEnd += sprintf(strEnd, "%02x", ie[i]);
		bufsize -= 2;
	}
	return (i == ielen ? strEnd - (UINT8 *) buf : 0);
}
#endif
static int wlget_scan(struct net_device *netdev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
#ifdef CLIENT_SUPPORT
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
#define MAX_IE_LENGTH  512
	UINT8 buffer[MAX_IE_LENGTH];
	char *current_ev = extra;
	char *current_ev_pre = extra;
	struct iw_event iwe;
	struct iw_point *srq = &(wrqu->essid);
	char *end_buf = current_ev + wrqu->data.length;
	static const char wpa_header[] = "WPA_IE = ";
	static const char wps_header[] = "WPS_IE = ";
	static const char wpa2_header[] = "WPA2_IE = ";
	static char headerGrpCipherTkip[] = "Multicast Cipher = TKIP ";
	static char headerUniCipherTkip[] = "Unicast Cipher = TKIP ";
	static char headerGrpCipherAes[] = "Multicast Cipher = AES ";
	static char headerUniCipherAes[] = "Unicast Cipher = AES ";
	static char headerGrpCipherUnknown[] = "Multicast Cipher = Unknown ";
	static char headerUniCipherUnknown[] = "Unicast Cipher = Unknown ";
	/* Read the entries one by one */

	scanDescptHdr_t *curDescpt_p = NULL;
	IEEEtypes_SsIdElement_t *ssidIE_p;
	IEEEtypes_DsParamSet_t *dsPSetIE_p;
	IEEEtypes_SuppRatesElement_t *PeerSupportedRates_p = NULL;
	IEEEtypes_ExtSuppRatesElement_t *PeerExtSupportedRates_p = NULL;
	IEEEtypes_HT_Element_t *pHT = NULL;
	IEEEtypes_Add_HT_Element_t *pHTAdd = NULL;
	IEEEtypes_Generic_HT_Element_t *pHTGen = NULL;
	UINT32 LegacyRateBitMap = 0;
	IEEEtypes_RSN_IE_t *RSN_p = NULL;
	IEEEtypes_RSN_IE_t *RSNWps_p = NULL;
	WSC_HeaderIE_t *WPS_p = NULL;
	IEEEtypes_RSN_IE_WPA2_t *wpa2IE_p = NULL;
	UINT8 scannedChannel = 0;
	UINT16 parsedLen = 0;
	UINT8 scannedSSID[33];
	UINT8 i = 0, j = 0;
	//klocwork10. apType might be used upto [0~10] because of sprintf add '\n'
	UINT8 apType[11];
	UINT32 mdidx = 0;
	BOOLEAN apGonly = FALSE;

	WLDBG_IOCTL(DBG_LEVEL_0, "%s:%s CpuID:%u, PID:%i, ProcName:\"%s\"\n",
		    netdev->name, __FUNCTION__, smp_processor_id(), current->pid, current->comm);

	if (!vmacSta_p->busyScanning) {
		for (i = 0; i < tmpNumScanDesc[vmacSta_p->VMacEntry.phyHwMacIndx]; i++) {
			curDescpt_p = (scanDescptHdr_t *) (&tmpScanResults[vmacSta_p->VMacEntry.phyHwMacIndx][0] + parsedLen);

			iwe.cmd = SIOCGIWAP;
			iwe.u.ap_addr.sa_family = ARPHRD_ETHER;
			memcpy(iwe.u.ap_addr.sa_data, curDescpt_p->bssId, ETH_ALEN);
			current_ev_pre = current_ev;
			current_ev = iwe_stream_add_event(info, current_ev, end_buf, &iwe, IW_EV_ADDR_LEN);
			if (current_ev_pre == current_ev) {
				if (wrqu->data.length < 0xffff)
					return -E2BIG;
				else
					goto exit;
			}

			memset(buffer, 0, MAX_IE_LENGTH);
			memset(&scannedSSID[0], 0, sizeof(scannedSSID));
			memset(&apType[0], 0, sizeof(apType));

			mdidx = sprintf(&apType[0], "Mode = ");
			scannedChannel = 0;
			apGonly = FALSE;
			/* Add the SSID */
			if ((ssidIE_p = (IEEEtypes_SsIdElement_t *) smeParseIeType(SSID,
										   (((UINT8 *) curDescpt_p) + sizeof(scanDescptHdr_t)),
										   curDescpt_p->length + sizeof(curDescpt_p->length) -
										   sizeof(scanDescptHdr_t))) != NULL) {
				memcpy(&scannedSSID[0], &ssidIE_p->SsId[0], ssidIE_p->Len);
				iwe.u.data.length = le16_to_cpu(ssidIE_p->Len);
				if (iwe.u.data.length > 32)
					iwe.u.data.length = 32;
				iwe.cmd = SIOCGIWESSID;
				iwe.u.data.flags = 1;
				current_ev_pre = current_ev;
				current_ev = iwe_stream_add_point(info, current_ev, end_buf, &iwe, &ssidIE_p->SsId[0]);
				if (current_ev_pre == current_ev) {
					if (wrqu->data.length < 0xffff)
						return -E2BIG;
					else
						goto exit;
				}
			}

			/* Add mode */
			iwe.cmd = SIOCGIWMODE;
			if (curDescpt_p->CapInfo.Ess || curDescpt_p->CapInfo.Ibss) {
				if (curDescpt_p->CapInfo.Ess)
					iwe.u.mode = IW_MODE_MASTER;
				else
					iwe.u.mode = IW_MODE_ADHOC;
				current_ev = iwe_stream_add_event(info, current_ev, end_buf, &iwe, IW_EV_UINT_LEN);
			}

			if ((dsPSetIE_p = (IEEEtypes_DsParamSet_t *) smeParseIeType(DS_PARAM_SET,
										    (((UINT8 *) curDescpt_p) + sizeof(scanDescptHdr_t)),
										    curDescpt_p->length + sizeof(curDescpt_p->length) -
										    sizeof(scanDescptHdr_t))) != NULL) {
				scannedChannel = dsPSetIE_p->CurrentChan;
				/* Add frequency */
				iwe.cmd = SIOCGIWFREQ;
				iwe.u.freq.m = dsPSetIE_p->CurrentChan;
				iwe.u.freq.e = 0;
				current_ev = iwe_stream_add_event(info, current_ev, end_buf, &iwe, IW_EV_FREQ_LEN);
			}

			/* Add quality statistics */
			iwe.cmd = IWEVQUAL;
			iwe.u.qual.updated = 0x10;
			iwe.u.qual.level = (__u8) le16_to_cpu(-curDescpt_p->rssi);
			iwe.u.qual.noise = (__u8) le16_to_cpu(-0x95);
			if (iwe.u.qual.level > iwe.u.qual.noise)
				iwe.u.qual.qual = iwe.u.qual.level - iwe.u.qual.noise;
			else
				iwe.u.qual.qual = 0;
			current_ev = iwe_stream_add_event(info, current_ev, end_buf, &iwe, IW_EV_QUAL_LEN);

			/* Add encryption capability */
			iwe.cmd = SIOCGIWENCODE;
			if (curDescpt_p->CapInfo.Privacy)
				iwe.u.data.flags = IW_ENCODE_ENABLED | IW_ENCODE_NOKEY;
			else
				iwe.u.data.flags = IW_ENCODE_DISABLED;
			iwe.u.data.length = 0;
			current_ev_pre = current_ev;
			current_ev = iwe_stream_add_point(info, current_ev, end_buf, &iwe, &scannedSSID[0]);
			if (current_ev_pre == current_ev) {
				if (wrqu->data.length < 0xffff)
					return -E2BIG;
				else
					goto exit;
			}

			PeerSupportedRates_p = (IEEEtypes_SuppRatesElement_t *) smeParseIeType(SUPPORTED_RATES,
											       (((UINT8 *) curDescpt_p) + sizeof(scanDescptHdr_t)),
											       curDescpt_p->length + sizeof(curDescpt_p->length) -
											       sizeof(scanDescptHdr_t));

			PeerExtSupportedRates_p = (IEEEtypes_ExtSuppRatesElement_t *) smeParseIeType(EXT_SUPPORTED_RATES,
												     (((UINT8 *) curDescpt_p) +
												      sizeof(scanDescptHdr_t)),
												     curDescpt_p->length +
												     sizeof(curDescpt_p->length) -
												     sizeof(scanDescptHdr_t));

			/* Add rates */
			iwe.cmd = SIOCGIWRATE;
			iwe.u.bitrate.fixed = iwe.u.bitrate.disabled = 0;
			if (PeerSupportedRates_p) {
				char *current_val = current_ev + IW_EV_LCP_LEN;
				for (j = 0; j < PeerSupportedRates_p->Len; j++) {
					/* Bit rate given in 500 kb/s units (+ 0x80) */
					iwe.u.bitrate.value = ((PeerSupportedRates_p->Rates[j] & 0x7f) * 500000);
					current_val = iwe_stream_add_value(info, current_ev, current_val, end_buf, &iwe, IW_EV_PARAM_LEN);
				}
				/* Check if we added any event */
				if ((current_val - current_ev) > IW_EV_LCP_LEN)
					current_ev = current_val;

			}
			if (PeerExtSupportedRates_p) {
				char *current_val = current_ev + IW_EV_LCP_LEN;
				for (j = 0; j < PeerExtSupportedRates_p->Len; j++) {
					/* Bit rate given in 500 kb/s units (+ 0x80) */
					iwe.u.bitrate.value = ((PeerExtSupportedRates_p->Rates[j] & 0x7f) * 500000);
					current_val = iwe_stream_add_value(info, current_ev, current_val, end_buf, &iwe, IW_EV_PARAM_LEN);
				}
				/* Check if we added any event */
				if ((current_val - current_ev) > IW_EV_LCP_LEN)
					current_ev = current_val;

			}

			/* Add WPA. */
			if ((RSN_p = linkMgtParseWpaIe((((UINT8 *) curDescpt_p) + sizeof(scanDescptHdr_t)),
						       curDescpt_p->length + sizeof(curDescpt_p->length) - sizeof(scanDescptHdr_t)))) {
				memset(&iwe, 0, sizeof(iwe));
				iwe.cmd = IWEVGENIE;
				iwe.u.data.length = RSN_p->Len + 2;
				if (iwe.u.data.length != 0) {
					current_ev_pre = current_ev;
					current_ev = iwe_stream_add_point(info, current_ev, end_buf, &iwe, (char *)RSN_p);
					if (current_ev_pre == current_ev) {
						if (wrqu->data.length < 0xffff)
							return -E2BIG;
						else
							goto exit;
					}
				}

				memset(&iwe, 0, sizeof(iwe));
				iwe.cmd = IWEVCUSTOM;
				iwe.u.data.length = add_IE(buffer, sizeof(buffer), (UINT8 *) RSN_p, RSN_p->Len + 2,
							   wpa_header, sizeof(wpa_header) - 1);
				if (iwe.u.data.length != 0) {
					current_ev_pre = current_ev;
					current_ev = iwe_stream_add_point(info, current_ev, end_buf, &iwe, buffer);
					if (current_ev_pre == current_ev) {
						if (wrqu->data.length < 0xffff)
							return -E2BIG;
						else
							goto exit;
					}
				}

				memset(&iwe, 0, sizeof(iwe));
				iwe.cmd = IWEVCUSTOM;
				if (RSN_p->GrpKeyCipher[3] == RSN_TKIP_ID) {
					iwe.u.data.length = sizeof(headerGrpCipherTkip);
					current_ev_pre = current_ev;
					current_ev = iwe_stream_add_point(info, current_ev, end_buf, &iwe, headerGrpCipherTkip);
					if (current_ev_pre == current_ev) {
						if (wrqu->data.length < 0xffff)
							return -E2BIG;
						else
							goto exit;
					}
				} else if (RSN_p->GrpKeyCipher[3] == RSN_AES_ID) {
					current_ev_pre = current_ev;
					iwe.u.data.length = sizeof(headerGrpCipherAes);
					current_ev = iwe_stream_add_point(info, current_ev, end_buf, &iwe, headerGrpCipherAes);
					if (current_ev_pre == current_ev) {
						if (wrqu->data.length < 0xffff)
							return -E2BIG;
						else
							goto exit;
					}
				} else {
					iwe.u.data.length = sizeof(headerGrpCipherUnknown);
					current_ev_pre = current_ev;
					current_ev = iwe_stream_add_point(info, current_ev, end_buf, &iwe, headerGrpCipherUnknown);
					if (current_ev_pre == current_ev) {
						if (wrqu->data.length < 0xffff)
							return -E2BIG;
						else
							goto exit;
					}
				}

				memset(&iwe, 0, sizeof(iwe));
				iwe.cmd = IWEVCUSTOM;
				if (RSN_p->PwsKeyCipherList[3] == RSN_TKIP_ID) {
					iwe.u.data.length = sizeof(headerUniCipherAes);
					current_ev_pre = current_ev;
					current_ev = iwe_stream_add_point(info, current_ev, end_buf, &iwe, headerUniCipherTkip);
					if (current_ev_pre == current_ev) {
						if (wrqu->data.length < 0xffff)
							return -E2BIG;
						else
							goto exit;
					}
				} else if (RSN_p->PwsKeyCipherList[3] == RSN_AES_ID) {
					iwe.u.data.length = sizeof(headerUniCipherAes);
					current_ev_pre = current_ev;
					current_ev = iwe_stream_add_point(info, current_ev, end_buf, &iwe, headerUniCipherAes);
					if (current_ev_pre == current_ev) {
						if (wrqu->data.length < 0xffff)
							return -E2BIG;
						else
							goto exit;
					}
				} else {
					iwe.u.data.length = sizeof(headerUniCipherUnknown);
					current_ev_pre = current_ev;
					current_ev = iwe_stream_add_point(info, current_ev, end_buf, &iwe, headerUniCipherUnknown);
					if (current_ev_pre == current_ev) {
						if (wrqu->data.length < 0xffff)
							return -E2BIG;
						else
							goto exit;
					}
				}
			}
			/* Add WPA */
			if ((RSNWps_p = linkMgtParseWpsIe((((UINT8 *) curDescpt_p) + sizeof(scanDescptHdr_t)),
							  curDescpt_p->length + sizeof(curDescpt_p->length) - sizeof(scanDescptHdr_t)))) {
				UINT16 DevPasswdId = 0;
				memset(&iwe, 0, sizeof(iwe));
				iwe.cmd = IWEVCUSTOM;
				iwe.u.data.length = add_IE(buffer, sizeof(buffer), (UINT8 *) RSNWps_p, RSNWps_p->Len + 2,
							   wps_header, sizeof(wps_header) - 1);
				WPS_p =
				    linkMgtParseWpsInfo(0x1012, (UINT8 *) RSNWps_p,
							curDescpt_p->length + sizeof(curDescpt_p->length) - sizeof(scanDescptHdr_t));
				if (WPS_p) {
					/* Do nothing with this for now. Maybe needed later to identify PIN/PBC. */
					DevPasswdId = *((UINT16 *) ((UINT8 *) WPS_p + sizeof(WSC_HeaderIE_t)));
				}
				if (iwe.u.data.length != 0) {
					current_ev_pre = current_ev;
					current_ev = iwe_stream_add_point(info, current_ev, end_buf, &iwe, buffer);
					if (current_ev_pre == current_ev) {
						if (wrqu->data.length < 0xffff)
							return -E2BIG;
						else
							goto exit;
					}
				}
			}
#ifdef MRVL_WPS_CLIENT
			/* Add WPS */
			if ((RSNWps_p = linkMgtParseWpsIe((((UINT8 *) curDescpt_p) + sizeof(scanDescptHdr_t)),
							  curDescpt_p->length + sizeof(curDescpt_p->length) - sizeof(scanDescptHdr_t)))) {
				iwe.cmd = IWEVGENIE;
				iwe.u.data.flags = 1;
				iwe.u.data.length = sizeof(IEEEtypes_InfoElementHdr_t) + RSNWps_p->Len;
				if (iwe.u.data.length != 0) {
					current_ev = iwe_stream_add_point(info, current_ev, end_buf, &iwe, (char *)RSNWps_p);
				}
			}
#endif
			/* Add WPA2 */
			if ((wpa2IE_p = (IEEEtypes_RSN_IE_WPA2_t *) smeParseIeType(RSN_IEWPA2,
										   (((UINT8 *) curDescpt_p) + sizeof(scanDescptHdr_t)),
										   curDescpt_p->length + sizeof(curDescpt_p->length) -
										   sizeof(scanDescptHdr_t)))) {
				memset(&iwe, 0, sizeof(iwe));
				iwe.cmd = IWEVGENIE;
				iwe.u.data.length = wpa2IE_p->Len + 2;
				if (iwe.u.data.length != 0) {
					current_ev_pre = current_ev;
					current_ev = iwe_stream_add_point(info, current_ev, end_buf, &iwe, (char *)wpa2IE_p);
					if (current_ev_pre == current_ev) {
						if (wrqu->data.length < 0xffff)
							return -E2BIG;
						else
							goto exit;
					}
				}

				memset(&iwe, 0, sizeof(iwe));
				iwe.cmd = IWEVCUSTOM;
				iwe.u.data.length = add_IE(buffer, sizeof(buffer), (UINT8 *) wpa2IE_p, wpa2IE_p->Len + 2,
							   wpa2_header, sizeof(wpa2_header) - 1);
				if (iwe.u.data.length != 0) {
					current_ev_pre = current_ev;
					current_ev = iwe_stream_add_point(info, current_ev, end_buf, &iwe, buffer);
					if (current_ev_pre == current_ev) {
						if (wrqu->data.length < 0xffff)
							return -E2BIG;
						else
							goto exit;
					}
				}

				memset(&iwe, 0, sizeof(iwe));
				iwe.cmd = IWEVCUSTOM;
				if (wpa2IE_p->GrpKeyCipher[3] == RSN_TKIP_ID) {
					iwe.u.data.length = sizeof(headerGrpCipherTkip);
					current_ev_pre = current_ev;
					current_ev = iwe_stream_add_point(info, current_ev, end_buf, &iwe, headerGrpCipherTkip);
					if (current_ev_pre == current_ev) {
						if (wrqu->data.length < 0xffff)
							return -E2BIG;
						else
							goto exit;
					}
				} else if (wpa2IE_p->GrpKeyCipher[3] == RSN_AES_ID) {
					iwe.u.data.length = sizeof(headerGrpCipherAes);
					current_ev_pre = current_ev;
					current_ev = iwe_stream_add_point(info, current_ev, end_buf, &iwe, headerGrpCipherAes);
					if (current_ev_pre == current_ev) {
						if (wrqu->data.length < 0xffff)
							return -E2BIG;
						else
							goto exit;
					}
				} else {
					iwe.u.data.length = sizeof(headerGrpCipherUnknown);
					current_ev_pre = current_ev;
					current_ev = iwe_stream_add_point(info, current_ev, end_buf, &iwe, headerGrpCipherUnknown);
					if (current_ev_pre == current_ev) {
						if (wrqu->data.length < 0xffff)
							return -E2BIG;
						else
							goto exit;
					}
				}

				memset(&iwe, 0, sizeof(iwe));
				iwe.cmd = IWEVCUSTOM;
				if (wpa2IE_p->PwsKeyCipherList[3] == RSN_TKIP_ID) {
					iwe.u.data.length = sizeof(headerUniCipherAes);
					current_ev_pre = current_ev;
					current_ev = iwe_stream_add_point(info, current_ev, end_buf, &iwe, headerUniCipherTkip);
					if (current_ev_pre == current_ev) {
						if (wrqu->data.length < 0xffff)
							return -E2BIG;
						else
							goto exit;
					}
				} else if (wpa2IE_p->PwsKeyCipherList[3] == RSN_AES_ID) {
					iwe.u.data.length = sizeof(headerUniCipherAes);
					current_ev_pre = current_ev;
					current_ev = iwe_stream_add_point(info, current_ev, end_buf, &iwe, headerUniCipherAes);
					if (current_ev_pre == current_ev) {
						if (wrqu->data.length < 0xffff)
							return -E2BIG;
						else
							goto exit;
					}
				} else {
					iwe.u.data.length = sizeof(headerUniCipherUnknown);
					current_ev_pre = current_ev;
					current_ev = iwe_stream_add_point(info, current_ev, end_buf, &iwe, headerUniCipherUnknown);
					if (current_ev_pre == current_ev) {
						if (wrqu->data.length < 0xffff)
							return -E2BIG;
						else
							goto exit;
					}
				}
			}

			LegacyRateBitMap = GetAssocRespLegacyRateBitMap(PeerSupportedRates_p, PeerExtSupportedRates_p);

			if (scannedChannel <= 14) {
				if (PeerSupportedRates_p) {
					int j;
					for (j = 0; (j < PeerSupportedRates_p->Len) && !apGonly; j++) {
						/* Only look for 6 Mbps as basic rate - consider this to be G only. */
						if (PeerSupportedRates_p->Rates[j] == 0x8c) {
							mdidx += sprintf(&apType[mdidx], "G");
							apGonly = TRUE;
						}
					}
				}
				if (!apGonly) {
					if (LegacyRateBitMap & 0x0f)
						mdidx += sprintf(&apType[mdidx], "B");
					if (PeerSupportedRates_p && PeerExtSupportedRates_p)
						mdidx += sprintf(&apType[mdidx], "G");
				}
			} else {
				if (LegacyRateBitMap & 0x1fe0)
					mdidx += sprintf(&apType[mdidx], "A");
			}

			pHT = (IEEEtypes_HT_Element_t *) smeParseIeType(HT,
									(((UINT8 *) curDescpt_p) + sizeof(scanDescptHdr_t)),
									curDescpt_p->length + sizeof(curDescpt_p->length) - sizeof(scanDescptHdr_t));

			pHTAdd = (IEEEtypes_Add_HT_Element_t *) smeParseIeType(ADD_HT,
									       (((UINT8 *) curDescpt_p) + sizeof(scanDescptHdr_t)),
									       curDescpt_p->length + sizeof(curDescpt_p->length) -
									       sizeof(scanDescptHdr_t));
			// If cannot find HT element then look for High Throughput elements using PROPRIETARY_IE.
			if (pHT == NULL) {
				pHTGen = linkMgtParseHTGenIe((((UINT8 *) curDescpt_p) + sizeof(scanDescptHdr_t)),
							     curDescpt_p->length + sizeof(curDescpt_p->length) - sizeof(scanDescptHdr_t));
			}

			if (pHT || pHTGen) {
				mdidx += sprintf(&apType[mdidx], "N");
			}

			memset(&iwe, 0, sizeof(iwe));
			iwe.cmd = IWEVCUSTOM;
			iwe.u.data.length = mdidx + 1;	//(sizeof(apType)-1);
			current_ev_pre = current_ev;
			current_ev = iwe_stream_add_point(info, current_ev, end_buf, &iwe, apType);
			if (current_ev_pre == current_ev) {
				if (wrqu->data.length < 0xffff)
					return -E2BIG;
				else
					goto exit;
			}
#ifdef AP_STEERING_SUPPORT
			memset(buffer, 0, MAX_IE_LENGTH);
			sprintf(buffer, "BcnInterval = %u", le16_to_cpu(curDescpt_p->BcnInterval));
			memset(&iwe, 0, sizeof(iwe));
			iwe.cmd = IWEVCUSTOM;
			iwe.u.data.length = strlen(buffer);

			current_ev_pre = current_ev;
			current_ev = iwe_stream_add_point(info, current_ev, end_buf, &iwe, buffer);
			if (current_ev_pre == current_ev) {
				if (wrqu->data.length < 0xffff)
					return -E2BIG;
				else
					goto exit;
			}
#endif				/* AP_STEERING_SUPPORT */

			parsedLen += curDescpt_p->length + sizeof(curDescpt_p->length);
		}
		srq->length = current_ev - extra;
		srq->flags = wlpptr->cmdFlags;
		return 0;
	} else {
		printk(".");
		mdelay(60);
		return -EAGAIN;
	}

 exit:
	srq->length = current_ev - extra;
	srq->flags = wlpptr->cmdFlags;
#endif
	return 0;
}

static int wlset_essid(struct net_device *dev, struct iw_request_info *info, struct iw_point *dwrq, char *extra)
{
	int rc = 0;

	WLDBG_ENTER_INFO(DBG_LEVEL_1, "");
	WLDBG_IOCTL(DBG_LEVEL_0, "%s:%s CpuID:%u, PID:%i, ProcName:\"%s\"\n",
		    dev->name, __FUNCTION__, smp_processor_id(), current->pid, current->comm);
	rc = mwl_config_set_essid(dev, extra, (uint8_t) dwrq->length);
	WLDBG_EXIT(DBG_LEVEL_1);

	return rc;
}

static int wlget_essid(struct net_device *dev, struct iw_request_info *info, struct iw_point *dwrq, char *extra)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, dev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	ULONG SsidLen = 0;

	WLDBG_ENTER_INFO(DBG_LEVEL_1, "");
	WLDBG_IOCTL(DBG_LEVEL_0, "%s:%s CpuID:%u, PID:%i, ProcName:\"%s\"\n",
		    dev->name, __FUNCTION__, smp_processor_id(), current->pid, current->comm);

	SsidLen = strlen(&(mib->StationConfig->DesiredSsId[0]));
	SsidLen = (SsidLen > 32) ? 32 : SsidLen;
	memcpy(extra, &(mib->StationConfig->DesiredSsId[0]), SsidLen);

	dwrq->length = SsidLen;
	dwrq->flags = 1;

	WLDBG_EXIT(DBG_LEVEL_1);

	return 0;
}

static int wlset_bssid(struct net_device *dev, struct iw_request_info *info, struct sockaddr *ap_addr, char *extra)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, dev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	int rc = 0;

	WLDBG_IOCTL(DBG_LEVEL_0, "%s:%s CpuID:%u, PID:%i, ProcName:\"%s\"\n",
		    dev->name, __FUNCTION__, smp_processor_id(), current->pid, current->comm);
	memcpy(&(mib->StationConfig->DesiredBSSId[0]), ap_addr->sa_data, MAC_ADDR_SIZE);

	WLDBG_EXIT(DBG_LEVEL_1);
	return rc;
}

static int wlset_rts(struct net_device *dev, struct iw_request_info *info, struct iw_param *vwrq, char *extra)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, dev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	int rc = 0;

	WLDBG_ENTER(DBG_LEVEL_1);

	WLDBG_IOCTL(DBG_LEVEL_0, "%s:%s CpuID:%u, PID:%i, ProcName:\"%s\"\n",
		    dev->name, __FUNCTION__, smp_processor_id(), current->pid, current->comm);

	if (priv->master) {
		printk("This parameter cannot be set to virtual interface %s, please use %s instead!\n", dev->name, priv->master->name);
		rc = -EOPNOTSUPP;
		return rc;
	}
	/* turn off RTS/CTS for 11ac taffic when rts threshold is set to 0.
	   The actual rts threshold will be still set to 2437 */
	if (vwrq->value == 0) {
		wlFwSetRTSThreshold(dev, 0);
	}
#ifdef SOC_W906X
	if ((vwrq->value < 255) || (vwrq->value > 11454))
		vwrq->value = 0xffff;
#else
	if ((vwrq->value < 255) || (vwrq->value > 2346))
		vwrq->value = 2347;
#endif				/* SOC_W906X */
	*(mib->mib_RtsThresh) = vwrq->value;
	WLDBG_EXIT(DBG_LEVEL_1);

	return rc;
}

static int wlget_rts(struct net_device *dev, struct iw_request_info *info, struct iw_param *vwrq, char *extra)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, dev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	WLDBG_ENTER_INFO(DBG_LEVEL_1, "");

	WLDBG_IOCTL(DBG_LEVEL_0, "%s:%s CpuID:%u, PID:%i, ProcName:\"%s\"\n",
		    dev->name, __FUNCTION__, smp_processor_id(), current->pid, current->comm);

	if (*(mib->mib_RtsThresh) > 2346)
		vwrq->disabled = 1;
	else {
		vwrq->disabled = 0;
		vwrq->fixed = 1;
		vwrq->value = *(mib->mib_RtsThresh);
	}

	WLDBG_EXIT(DBG_LEVEL_1);

	return 0;
}

static int wlget_frag(struct net_device *dev, struct iw_request_info *info, struct iw_param *vwrq, char *extra)
{
	WLDBG_ENTER_INFO(DBG_LEVEL_1, "");

	WLDBG_IOCTL(DBG_LEVEL_0, "%s:%s CpuID:%u, PID:%i, ProcName:\"%s\"\n",
		    dev->name, __FUNCTION__, smp_processor_id(), current->pid, current->comm);

	vwrq->disabled = 1;

	WLDBG_EXIT(DBG_LEVEL_1);

	return 0;
}

static int wlget_wap(struct net_device *dev, struct iw_request_info *info, struct sockaddr *awrq, char *extra)
{
	WLDBG_ENTER_INFO(DBG_LEVEL_1, "");

	WLDBG_IOCTL(DBG_LEVEL_0, "%s:%s CpuID:%u, PID:%i, ProcName:\"%s\"\n",
		    dev->name, __FUNCTION__, smp_processor_id(), current->pid, current->comm);

	memcpy(awrq->sa_data, dev->dev_addr, 6);
	WLDBG_EXIT(DBG_LEVEL_1);

	return 0;
}

static int wlset_mlme(struct net_device *dev, struct iw_request_info *info, struct sockaddr *awrq, char *extra)
{
	int rc = -ENOTSUPP;

#ifdef CLIENT_SUPPORT

	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	struct iw_mlme *iwMlme_p = NULL;

	WLDBG_ENTER(DBG_LEVEL_1);

	WLDBG_IOCTL(DBG_LEVEL_0, "%s:%s CpuID:%u, PID:%i, ProcName:\"%s\"\n",
		    dev->name, __FUNCTION__, smp_processor_id(), current->pid, current->comm);

	if (vmacSta_p->VMacEntry.modeOfService != VMAC_MODE_CLNT_INFRA) {

		WLDBG_ERROR(DBG_LEVEL_1, "Not client mode\n");
		WLDBG_EXIT(DBG_LEVEL_1);
		return rc;
	}

	rc = 0;

	iwMlme_p = (struct iw_mlme *)extra;

	if (iwMlme_p->cmd != IW_MLME_DEAUTH) {

		WLDBG_WARNING(DBG_LEVEL_1, "Unsupported IW_MLME command : %d\n", iwMlme_p->cmd);
		rc = -EOPNOTSUPP;
	} else {

		if (!netif_carrier_ok(dev)) {

			WLDBG_INFO(DBG_LEVEL_1, "Set MLME Deauth, but netif_carrier_off\n");
		} else {

			IEEEtypes_DeauthCmd_t deAuthCmd;

			memcpy(deAuthCmd.PeerStaAddr, iwMlme_p->addr.sa_data, sizeof(IEEEtypes_MacAddr_t));
			deAuthCmd.Reason = iwMlme_p->reason_code;

			if (wl_MacMlme_DeAuthStaCmd((void *)vmacSta_p, (void *)&deAuthCmd)
			    == MLME_FAILURE) {

				WLDBG_ERROR(DBG_LEVEL_1, "IW_MLME command : %d failed\n", iwMlme_p->cmd);
				rc = -EPERM;
			}
		}
	}

	WLDBG_EXIT(DBG_LEVEL_1);

#endif

	return rc;
}

static int wlset_encode(struct net_device *dev, struct iw_request_info *info, struct iw_point *dwrq, char *extra)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, dev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	int rc = 0;

	PRINT1(IOCTL, "wlset_encode: enter\n");
	if (dwrq->flags & IW_ENCODE_DISABLED) {
		PRINT1(IOCTL, "wlset_encode: IW_ENCODE_DISABLED\n");

		mib->Privacy->RSNEnabled = 0;
		mib->RSNConfigWPA2->WPA2Enabled = 0;
		mib->RSNConfigWPA2->WPA2OnlyEnabled = 0;

		mib->AuthAlg->Enable = 0;
		mib->StationConfig->PrivOption = 0;
		mib->Privacy->PrivInvoked = 0;
		mib->AuthAlg->Type = 0;
		WL_FUN_SetAuthType((void *)priv, 0);
		if (WL_FUN_SetPrivacyOption((void *)priv, 0)) {
		} else
			rc = -EIO;
	} else {
		PRINT1(IOCTL, "wlset_encode: IW_ENCODE_ENABLED\n");
		mib->Privacy->RSNEnabled = 0;
		mib->RSNConfigWPA2->WPA2Enabled = 0;
		mib->RSNConfigWPA2->WPA2OnlyEnabled = 0;

		mib->AuthAlg->Enable = 1;
		mib->StationConfig->PrivOption = 1;
		mib->Privacy->PrivInvoked = 1;
		if (WL_FUN_SetPrivacyOption((void *)priv, 1)) {
		} else
			rc = -EIO;

		if (dwrq->flags & IW_ENCODE_OPEN) {
			int index = (dwrq->flags & IW_ENCODE_INDEX) - 1;

			if ((index < 0) || (index > 3))
				*(mib->mib_defaultkeyindex) = index = 0;
			else
				*(mib->mib_defaultkeyindex) = index;

			PRINT1(IOCTL, "wlset_encode: IW_ENCODE_OPEN\n");
			mib->AuthAlg->Type = 0;
			WL_FUN_SetAuthType((void *)priv, 0);
		}
		if (dwrq->flags & IW_ENCODE_RESTRICTED) {
			int index = (dwrq->flags & IW_ENCODE_INDEX) - 1;

			if ((index < 0) || (index > 3))
				*(mib->mib_defaultkeyindex) = index = 0;
			else
				*(mib->mib_defaultkeyindex) = index;

			PRINT1(IOCTL, "wlset_encode: IW_ENCODE_RESTRICTED\n");
			mib->AuthAlg->Type = 1;
			WL_FUN_SetAuthType((void *)priv, 1);
		}
		if (dwrq->length > 1) {	//set open/restracted mode at [1] len=1
			int index = (dwrq->flags & IW_ENCODE_INDEX) - 1;
			int wep_type = 1;
			UCHAR tmpWEPKey[16];

			if (dwrq->length > 13)
				return -EINVAL;

			if ((index < 0) || (index > 3))
				*(mib->mib_defaultkeyindex) = index = 0;
			else
				*(mib->mib_defaultkeyindex) = index;

			if (dwrq->length == 5) {
				wep_type = 1;
				mib->WepDefaultKeys[index].WepType = wep_type;

			}
			if (dwrq->length == 13) {
				wep_type = 2;
				mib->WepDefaultKeys[index].WepType = wep_type;
			}
			if ((dwrq->length != 5) && (dwrq->length != 13)) {
				// Invalid key length
				rc = -EIO;
				return rc;
			}
			memset(mib->WepDefaultKeys[index].WepDefaultKeyValue, 0, 13);
			memcpy(tmpWEPKey, extra, dwrq->length);
			memcpy(mib->WepDefaultKeys[index].WepDefaultKeyValue, tmpWEPKey, dwrq->length);
			if (WL_FUN_SetWEPKey((void *)priv, index, wep_type, tmpWEPKey)) {
				PRINT1(IOCTL, "wlset_encode: WL_FUN_SetWEPKey TRUE length = %d index = %d type = %d\n", dwrq->length, index,
				       wep_type);
				PRINT1(IOCTL, "wep key = %x %x %x %x %x %x %x %x %x %x %x %x %x \n", mib->WepDefaultKeys[index].WepDefaultKeyValue[0],
				       mib->WepDefaultKeys[index].WepDefaultKeyValue[1], mib->WepDefaultKeys[index].WepDefaultKeyValue[2],
				       mib->WepDefaultKeys[index].WepDefaultKeyValue[3], mib->WepDefaultKeys[index].WepDefaultKeyValue[4],
				       mib->WepDefaultKeys[index].WepDefaultKeyValue[5], mib->WepDefaultKeys[index].WepDefaultKeyValue[6],
				       mib->WepDefaultKeys[index].WepDefaultKeyValue[7], mib->WepDefaultKeys[index].WepDefaultKeyValue[8],
				       mib->WepDefaultKeys[index].WepDefaultKeyValue[9], mib->WepDefaultKeys[index].WepDefaultKeyValue[10],
				       mib->WepDefaultKeys[index].WepDefaultKeyValue[11], mib->WepDefaultKeys[index].WepDefaultKeyValue[12]);

			} else
				rc = -EIO;
		}
	}

	return rc;
}

static int wlget_encode(struct net_device *dev, struct iw_request_info *info, struct iw_point *dwrq, char *extra)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, dev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	int rc = 0;
	int index = (dwrq->flags & IW_ENCODE_INDEX) - 1;

	PRINT1(IOCTL, "wlget_encode: enter\n");
	if (mib->Privacy->PrivInvoked) {
		if (mib->AuthAlg->Type)
			dwrq->flags = IW_ENCODE_RESTRICTED;
		else
			dwrq->flags = IW_ENCODE_OPEN;
	} else {
		dwrq->flags = IW_ENCODE_DISABLED;
	}

	if (index < 0 || index > 3)
		index = *(mib->mib_defaultkeyindex);
	//to show key
	memcpy(extra, mib->WepDefaultKeys[index].WepDefaultKeyValue, sizeof(mib->WepDefaultKeys[index].WepDefaultKeyValue));
	//not show key
	//dwrq->flags |= IW_ENCODE_NOKEY;
	//memset(extra, 0, 16);
	if (mib->WepDefaultKeys[index].WepType == 1)
		dwrq->length = 5;
	if (mib->WepDefaultKeys[index].WepType == 2)
		dwrq->length = 13;

	if (dwrq->length > 16) {
		dwrq->length = 0;
	}
	return rc;
}

static int wlset_auth(struct net_device *dev, struct iw_request_info *info, struct iw_point *dwrq, char *extra)
{
	int rc = -ENOTSUPP;

#ifdef CLIENT_SUPPORT

	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, dev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	struct iw_param *auth_p = (struct iw_param *)dwrq;
#ifdef MRVL_WPS_CLIENT
	vmacEntry_t *vmacEntry_p = NULL;
	STA_SYSTEM_MIBS *pStaSystemMibs;
#endif

	WLDBG_ENTER(DBG_LEVEL_1);

	WLDBG_IOCTL(DBG_LEVEL_0, "%s:%s CpuID:%u, PID:%i, ProcName:\"%s\"\n",
		    dev->name, __FUNCTION__, smp_processor_id(), current->pid, current->comm);

	if (vmacSta_p->VMacEntry.modeOfService != VMAC_MODE_CLNT_INFRA) {

		WLDBG_ERROR(DBG_LEVEL_1, "Not client mode\n");
		WLDBG_EXIT(DBG_LEVEL_1);
		return rc;
	}
#ifdef MRVL_WPS_CLIENT
	vmacEntry_p = sme_GetParentVMacEntry(vmacSta_p->VMacEntry.phyHwMacIndx);

	if (vmacEntry_p == NULL) {
		WLDBG_ERROR(DBG_LEVEL_1, "Can't get parent VMAC entry\n");
		WLDBG_EXIT(DBG_LEVEL_1);
		return -EPERM;
	}
	pStaSystemMibs = sme_GetStaSystemMibsPtr(vmacEntry_p);
	if (pStaSystemMibs == NULL) {
		WLDBG_ERROR(DBG_LEVEL_1, "Can't get station system MIB\n");
		WLDBG_EXIT(DBG_LEVEL_1);
		return -EPERM;
	}
#endif

	rc = 0;

	switch (auth_p->flags & IW_AUTH_INDEX) {

	case IW_AUTH_WPA_VERSION:
		if (auth_p->value == IW_AUTH_WPA_VERSION_DISABLED) {
			mib->Privacy->RSNEnabled = 0;
			mib->Privacy->RSNLinkStatus = 0;
			mib->RSNConfigWPA2->WPA2Enabled = 0;
			mib->RSNConfigWPA2->WPA2OnlyEnabled = 0;
			mib->UnicastCiphers->Enabled = FALSE;
			mib->WPA2UnicastCiphers->Enabled = FALSE;
			mib->WPA2AuthSuites->Enabled = FALSE;
#ifdef MRVL_WPS_CLIENT
			pStaSystemMibs->mib_StaCfg_p->wpawpa2Mode = 0;
#endif
		} else if (auth_p->value == IW_AUTH_WPA_VERSION_WPA) {
			/* there is no need to clean mib->Privacy->PrivInvoked
			 * and mib->AuthAlg->Type here
			 */
			mib->Privacy->RSNEnabled = 1;
			mib->Privacy->RSNLinkStatus = 0;
			mib->RSNConfigWPA2->WPA2Enabled = 0;
			mib->RSNConfigWPA2->WPA2OnlyEnabled = 0;
#ifdef MRVL_WPS_CLIENT
			pStaSystemMibs->mib_StaCfg_p->wpawpa2Mode = 1;
#endif
		} else if (auth_p->value == IW_AUTH_WPA_VERSION_WPA2) {
			/* there is no need to clean mib->Privacy->PrivInvoked
			 * and mib->AuthAlg->Type here
			 */
			mib->Privacy->RSNEnabled = 1;
			mib->Privacy->RSNLinkStatus = 0;
			mib->RSNConfigWPA2->WPA2Enabled = 1;
			mib->RSNConfigWPA2->WPA2OnlyEnabled = 1;
#ifdef MRVL_WPS_CLIENT
			pStaSystemMibs->mib_StaCfg_p->wpawpa2Mode = 2;
#endif
		} else {
			WLDBG_ERROR(DBG_LEVEL_1, "Unsupported IW_AUTH_WPA_VERSION : %d\n", auth_p->value);
			rc = -EOPNOTSUPP;
		}
		break;

	case IW_AUTH_CIPHER_PAIRWISE:
		if (auth_p->value == IW_AUTH_CIPHER_NONE) {
			mib->UnicastCiphers->Enabled = FALSE;
			mib->WPA2UnicastCiphers->Enabled = FALSE;
		} else if (auth_p->value == IW_AUTH_CIPHER_TKIP) {
			mib->UnicastCiphers->UnicastCipher[0] = 0x00;
			mib->UnicastCiphers->UnicastCipher[1] = 0x50;
			mib->UnicastCiphers->UnicastCipher[2] = 0xF2;
			mib->UnicastCiphers->UnicastCipher[3] = 0x02;
			*(mib->mib_cipherSuite) = 2;
			mib->UnicastCiphers->Enabled = TRUE;
			mib->WPA2UnicastCiphers->Enabled = FALSE;
		} else if (auth_p->value == IW_AUTH_CIPHER_CCMP) {
			mib->WPA2UnicastCiphers->UnicastCipher[0] = 0x00;
			mib->WPA2UnicastCiphers->UnicastCipher[1] = 0x0F;
			mib->WPA2UnicastCiphers->UnicastCipher[2] = 0xAC;
			mib->WPA2UnicastCiphers->UnicastCipher[3] = 0x04;
			*(mib->mib_cipherSuite) = 4;
			mib->UnicastCiphers->Enabled = FALSE;
			mib->WPA2UnicastCiphers->Enabled = TRUE;
		}
		break;

	case IW_AUTH_CIPHER_GROUP:
		if (auth_p->value == IW_AUTH_CIPHER_TKIP) {
			mib->RSNConfigWPA2->MulticastCipher[0] = 0x00;
			mib->RSNConfigWPA2->MulticastCipher[1] = 0x0F;
			mib->RSNConfigWPA2->MulticastCipher[2] = 0xAC;
			mib->RSNConfigWPA2->MulticastCipher[3] = 0x02;
		} else if (auth_p->value == IW_AUTH_CIPHER_CCMP) {
			mib->RSNConfigWPA2->MulticastCipher[0] = 0x00;
			mib->RSNConfigWPA2->MulticastCipher[1] = 0x0F;
			mib->RSNConfigWPA2->MulticastCipher[2] = 0xAC;
			mib->RSNConfigWPA2->MulticastCipher[3] = 0x04;
		}
		break;

	case IW_AUTH_KEY_MGMT:
		if (auth_p->value == IW_AUTH_KEY_MGMT_802_1X) {
			mib->WPA2AuthSuites->AuthSuites[0] = 0x00;
			mib->WPA2AuthSuites->AuthSuites[1] = 0x0F;
			mib->WPA2AuthSuites->AuthSuites[2] = 0xAC;
			mib->WPA2AuthSuites->AuthSuites[3] = 0x01;
			mib->WPA2AuthSuites->Enabled = TRUE;
		} else if (auth_p->value == IW_AUTH_KEY_MGMT_PSK) {
			mib->WPA2AuthSuites->AuthSuites[0] = 0x00;
			mib->WPA2AuthSuites->AuthSuites[1] = 0x0F;
			mib->WPA2AuthSuites->AuthSuites[2] = 0xAC;
			mib->WPA2AuthSuites->AuthSuites[3] = 0x02;
			mib->WPA2AuthSuites->Enabled = TRUE;
		} else {
			WLDBG_ERROR(DBG_LEVEL_1, "Unsupported IW_AUTH_KEY_MGMT : %d\n", auth_p->value);
			rc = -EOPNOTSUPP;
		}
		break;

	case IW_AUTH_80211_AUTH_ALG:
		if (auth_p->value == IW_AUTH_ALG_OPEN_SYSTEM) {
			mib->AuthAlg->Type = 0;
		} else if (auth_p->value == IW_AUTH_ALG_SHARED_KEY) {
			mib->AuthAlg->Type = 1;
		} else {
			WLDBG_ERROR(DBG_LEVEL_1, "Unsupported IW_AUTH_80211_AUTH_ALG : %d\n", auth_p->value);
			rc = -EOPNOTSUPP;
		}
		break;

	case IW_AUTH_PRIVACY_INVOKED:
		mib->Privacy->PrivInvoked = auth_p->value;
		break;

	default:
		WLDBG_ERROR(DBG_LEVEL_1, "Unsupported IW_AUTH_INDEX : %d\n", auth_p->flags);
		rc = -EOPNOTSUPP;
		break;
	}

	WLDBG_EXIT(DBG_LEVEL_1);

#endif

	return rc;
}

static int wlset_encodeext(struct net_device *dev, struct iw_request_info *info, struct iw_point *dwrq, char *extra)
{
	int rc = -ENOTSUPP;

#ifdef CLIENT_SUPPORT

	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, dev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	struct iw_encode_ext *enc_p = (struct iw_encode_ext *)extra;
	int len;
	UINT8 *key_p;

	WLDBG_ENTER(DBG_LEVEL_1);

	if (vmacSta_p->VMacEntry.modeOfService != VMAC_MODE_CLNT_INFRA) {

		WLDBG_ERROR(DBG_LEVEL_1, "Not client mode\n");
		WLDBG_EXIT(DBG_LEVEL_1);
		return rc;
	}

	rc = 0;

	len = enc_p->key_len;
	key_p = (UINT8 *) enc_p->key;

	/* SIOCSIWENCODE is replaced by this extension function.
	 * All encode setting will be done by this function.
	 */

	if (dwrq->flags & IW_ENCODE_DISABLED) {

		/* remove key
		 */

		memset(mib->RSNConfigWPA2->PSKValue, 0, 32);
		memset(mib->RSNConfigWPA2->PSKPassPhrase, 0, 65);
		*(mib->mib_WPA2PSKValueEnabled) = 0;

		memset(mib->RSNConfig->PSKValue, 0, 32);
		memset(mib->RSNConfig->PSKPassPhrase, 0, sizeof(mib->RSNConfig->PSKPassPhrase));
		*(mib->mib_WPAPSKValueEnabled) = 1;

	} else {

		switch (enc_p->alg) {

		case IW_ENCODE_ALG_NONE:
			break;

		case IW_ENCODE_ALG_WEP:

			if ((len == 5) || len == 13) {

				UINT8 keyIdx;
				UINT8 wepType;

				keyIdx = (dwrq->flags & IW_ENCODE_INDEX) - 1;

				if (keyIdx > 3)
					*(mib->mib_defaultkeyindex) = keyIdx = 0;
				else
					*(mib->mib_defaultkeyindex) = keyIdx;

				if (len == 5) {
					wepType = 1;
					mib->WepDefaultKeys[keyIdx].WepType = wepType;
				} else {
					wepType = 2;
					mib->WepDefaultKeys[keyIdx].WepType = wepType;
				}

				memset(mib->WepDefaultKeys[keyIdx].WepDefaultKeyValue, 0, 13);
				memcpy(mib->WepDefaultKeys[keyIdx].WepDefaultKeyValue, key_p, len);

				if (WL_FUN_SetWEPKey((void *)priv, keyIdx, wepType, key_p)) {
					WLDBG_INFO(DBG_LEVEL_1, "wlset_encode: WL_FUN_SetWEPKey TRUE length = %d index = %d type = %d\n", len, keyIdx,
						   wepType);
					WLDBG_INFO(DBG_LEVEL_1, "wep key = %x %x %x %x %x %x %x %x %x %x %x %x %x \n",
						   mib->WepDefaultKeys[keyIdx].WepDefaultKeyValue[0],
						   mib->WepDefaultKeys[keyIdx].WepDefaultKeyValue[1],
						   mib->WepDefaultKeys[keyIdx].WepDefaultKeyValue[2],
						   mib->WepDefaultKeys[keyIdx].WepDefaultKeyValue[3],
						   mib->WepDefaultKeys[keyIdx].WepDefaultKeyValue[4],
						   mib->WepDefaultKeys[keyIdx].WepDefaultKeyValue[5],
						   mib->WepDefaultKeys[keyIdx].WepDefaultKeyValue[6],
						   mib->WepDefaultKeys[keyIdx].WepDefaultKeyValue[7],
						   mib->WepDefaultKeys[keyIdx].WepDefaultKeyValue[8],
						   mib->WepDefaultKeys[keyIdx].WepDefaultKeyValue[9],
						   mib->WepDefaultKeys[keyIdx].WepDefaultKeyValue[10],
						   mib->WepDefaultKeys[keyIdx].WepDefaultKeyValue[11],
						   mib->WepDefaultKeys[keyIdx].WepDefaultKeyValue[12]);
				} else
					rc = -EPERM;

			} else {

				WLDBG_ERROR(DBG_LEVEL_1, "Incorrect wep key length : %d\n", len);
				rc = -EINVAL;
			}

			break;

		case IW_ENCODE_ALG_TKIP:
		case IW_ENCODE_ALG_CCMP:

			if (enc_p->ext_flags & IW_ENCODE_EXT_GROUP_KEY) {

				phyMacId_t idx;
				UINT8 keyIdx;
				UINT8 *macStaAddr_p = GetParentStaBSSID(vmacSta_p->VMacEntry.phyHwMacIndx);

				if (macStaAddr_p == NULL)
					break;
				idx = vmacSta_p->VMacEntry.phyHwMacIndx;
				keyIdx = (dwrq->flags & IW_ENCODE_INDEX) - 1;

				/* group key
				 */
#ifdef SOC_W906X
				if (enc_p->alg == IW_ENCODE_ALG_TKIP) {

					TKIP_TYPE_KEY param;
					UINT32 keyInfo = ENCR_KEY_FLAG_GTK_RX_KEY |
					    ENCR_KEY_FLAG_MICKEY_VALID | ENCR_KEY_FLAG_TSC_VALID | ENCR_KEY_FLAG_STA_MODE;

					memcpy(mib_MrvlRSN_GrpKeyUr1[idx].EncryptKey, key_p, TK_SIZE);
					memcpy(mib_MrvlRSN_GrpKeyUr1[idx].TxMICKey, key_p + TK_SIZE, MIC_KEY_LENGTH);
					memcpy(mib_MrvlRSN_GrpKeyUr1[idx].RxMICKey, key_p + TK_SIZE + MIC_SIZE, MIC_KEY_LENGTH);
					mib_MrvlRSN_GrpKeyUr1[idx].g_IV16 = 0x0001;
					mib_MrvlRSN_GrpKeyUr1[idx].g_IV32 = 0;

					memcpy(param.KeyMaterial, mib_MrvlRSN_GrpKeyUr1[idx].EncryptKey, TK_SIZE);
					memcpy(param.RxMicKey, mib_MrvlRSN_GrpKeyUr1[idx].RxMICKey, MIC_KEY_LENGTH);
					memcpy(param.TxMicKey, mib_MrvlRSN_GrpKeyUr1[idx].TxMICKey, MIC_KEY_LENGTH);

					param.Tsc.low = mib_MrvlRSN_GrpKeyUr1[idx].g_IV16;
					param.Tsc.high = mib_MrvlRSN_GrpKeyUr1[idx].g_IV32;

					wlFwSetSecurityKey(dev, ACT_SET, KEY_TYPE_ID_TKIP, macStaAddr_p, keyIdx, TK_SIZE, keyInfo, (UINT8 *) & param);

				} else {
					AES_TYPE_KEY param;
					UINT32 keyInfo = ENCR_KEY_FLAG_GTK_RX_KEY | ENCR_KEY_FLAG_STA_MODE;

					memcpy(mib_MrvlRSN_GrpKeyUr1[idx].EncryptKey, key_p, TK_SIZE);

					memcpy(param.KeyMaterial, key_p, TK_SIZE);

					wlFwSetSecurityKey(dev, ACT_SET, KEY_TYPE_ID_CCMP, macStaAddr_p, keyIdx, TK_SIZE, keyInfo, (UINT8 *) & param);
				}
#else
				if (enc_p->alg == IW_ENCODE_ALG_TKIP) {

					ENCR_TKIPSEQCNT TkipTsc;

					memcpy(mib_MrvlRSN_GrpKeyUr1[idx].EncryptKey, key_p, TK_SIZE);
					memcpy(mib_MrvlRSN_GrpKeyUr1[idx].TxMICKey, key_p + TK_SIZE, MIC_KEY_LENGTH);
					memcpy(mib_MrvlRSN_GrpKeyUr1[idx].RxMICKey, key_p + TK_SIZE + MIC_SIZE, MIC_KEY_LENGTH);
					mib_MrvlRSN_GrpKeyUr1[idx].g_IV16 = 0x0001;
					mib_MrvlRSN_GrpKeyUr1[idx].g_IV32 = 0;

					TkipTsc.low = mib_MrvlRSN_GrpKeyUr1[idx].g_IV16;
					TkipTsc.high = mib_MrvlRSN_GrpKeyUr1[idx].g_IV32;

					wlFwSetWpaTkipGroupK_STA(dev,
								 macStaAddr_p,
								 &mib_MrvlRSN_GrpKeyUr1[idx].EncryptKey[0],
								 TK_SIZE,
								 (UINT8 *) & mib_MrvlRSN_GrpKeyUr1[idx].RxMICKey,
								 MIC_KEY_LENGTH,
								 (UINT8 *) & mib_MrvlRSN_GrpKeyUr1[idx].TxMICKey, MIC_KEY_LENGTH, TkipTsc, keyIdx);

				} else {

					memcpy(mib_MrvlRSN_GrpKeyUr1[idx].EncryptKey, key_p, TK_SIZE);
					wlFwSetWpaAesGroupK_STA(dev,
								macStaAddr_p,
								&mib_MrvlRSN_GrpKeyUr1[idx].EncryptKey[0], keyIdx, IEEEtypes_RSN_CIPHER_SUITE_CCMP);
				}
#endif
			} else {

				/* pairwise key
				 */

				/* If we want to support 1X, 4 ways handshake should run in wpa_supplicant and set
				 * key via this I/O control. Need time to check if 1X will bypass 4 ways handshake of driver
				 * and the way to set F/W. This part of code will be added later.
				 */
			}
			break;

		case IW_ENCODE_ALG_PMK:

			if ((len <= 7) || (len > 64)) {
				WLDBG_ERROR(DBG_LEVEL_1, "Incorrect key length : %d\n", len);
				rc = -EINVAL;
				break;
			}
			if (len == 64) {

				if (!IsHexKey(key_p)) {
					WLDBG_ERROR(DBG_LEVEL_1, "Key is not Hex\n");
					rc = -EINVAL;
					break;
				}

				if (mib->RSNConfigWPA2->WPA2Enabled) {

					memset(mib->RSNConfigWPA2->PSKValue, 0, 32);
					HexStringToHexDigi(mib->RSNConfigWPA2->PSKValue, key_p, 32);
					memset(mib->RSNConfigWPA2->PSKPassPhrase, 0, 65);
					strcpy(mib->RSNConfigWPA2->PSKPassPhrase, key_p);

					*(mib->mib_WPA2PSKValueEnabled) = 1;
				} else {

					memset(mib->RSNConfig->PSKValue, 0, 32);
					HexStringToHexDigi(mib->RSNConfig->PSKValue, key_p, 32);
					memset(mib->RSNConfig->PSKPassPhrase, 0, sizeof(mib->RSNConfig->PSKPassPhrase));
					strcpy(mib->RSNConfig->PSKPassPhrase, key_p);

					*(mib->mib_WPAPSKValueEnabled) = 1;
				}
				break;
			}

			if (mib->RSNConfigWPA2->WPA2Enabled) {

				memset(mib->RSNConfigWPA2->PSKPassPhrase, 0, 65);
				strcpy(mib->RSNConfigWPA2->PSKPassPhrase, key_p);
			} else {

				memset(mib->RSNConfig->PSKPassPhrase, 0, sizeof(mib->RSNConfig->PSKPassPhrase));
				strcpy(mib->RSNConfig->PSKPassPhrase, key_p);
			}
			break;

		default:
			WLDBG_ERROR(DBG_LEVEL_1, "Unsupport encode algorithm : %d\n", enc_p->alg);
			rc = -EOPNOTSUPP;
			break;
		}
	}

	WLDBG_EXIT(DBG_LEVEL_1);

#endif

	return rc;
}

typedef struct param_applicable_t {
	UINT16 command;
	UINT16 applicable;
} param_applicable;
static param_applicable priv_wlparam[] = {
	{WL_PARAM_AUTHTYPE, 0},
	{WL_PARAM_BAND, 0},
	{WL_PARAM_REGIONCODE, 1},
	{WL_PARAM_HIDESSID, 0},
	{WL_PARAM_PREAMBLE, 0},
	{WL_PARAM_GPROTECT, 1},
	{WL_PARAM_BEACON, 1},
	{WL_PARAM_DTIM, 0},
	{WL_PARAM_FIXRATE, 1},
	{WL_PARAM_ANTENNA, 1},
	{WL_PARAM_WPAWPA2MODE, 0},
#ifdef MRVL_WAPI
	{WL_PARAM_WAPIMODE, 0},
#endif
	{WL_PARAM_AUTHSUITE, 0},
	{WL_PARAM_GROUPREKEYTIME, 0},
	{WL_PARAM_WMM, 1},
	{WL_PARAM_WMMACKPOLICY, 0},
	{WL_PARAM_FILTER, 0},
	{WL_PARAM_INTRABSS, 0},
	{WL_PARAM_AMSDU, 0},
	{WL_PARAM_HTBANDWIDTH, 1},
	{WL_PARAM_GUARDINTERVAL, 1},
	{WL_PARAM_EXTSUBCH, 1},
	{WL_PARAM_HTPROTECT, 1},
	{WL_PARAM_GETFWSTAT, 1},
	{WL_PARAM_AGINGTIME, 1},
	{WL_PARAM_AUTOCHANNEL, 1},
	{WL_PARAM_AMPDUFACTOR, 0},
	{WL_PARAM_AMPDUDENSITY, 0},
	{WL_PARAM_CARDDEVINFO, 0},
	{WL_PARAM_INTEROP, 0},
	{WL_PARAM_OPTLEVEL, 0},
	{WL_PARAM_REGIONPWR, 1},
	{WL_PARAM_ADAPTMODE, 0},
	{WL_PARAM_SETKEYS, 0},
	{WL_PARAM_DELKEYS, 0},
	{WL_PARAM_MLME_REQ, 0},
	{WL_PARAM_COUNTERMEASURES, 0},
	{WL_PARAM_CSADAPTMODE, 0},
	{WL_PARAM_DELWEPKEY, 0},
	{WL_PARAM_WDSMODE, 0},
	{WL_PARAM_STRICTWEPSHARE, 0},
	{WL_PARAM_11H_CSA_CHAN, 1},
	{WL_PARAM_11H_CSA_COUNT, 1},
	{WL_PARAM_11H_CSA_MODE, 1},
	{WL_PARAM_11H_CSA_START, 1},
	{WL_PARAM_SPECTRUM_MGMT, 1},
	{WL_PARAM_POWER_CONSTRAINT, 1},
	{WL_PARAM_11H_DFS_MODE, 1},
	{WL_PARAM_11D_MODE, 1},
	{WL_PARAM_TXPWRFRACTION, 1},
	{WL_PARAM_DISABLEASSOC, 0},
	{WL_PARAM_PSHT_MANAGEMENTACT, 0},
	{WL_PARAM_STAMODE, 0},
	{WL_PARAM_STASCAN, 0},
	{WL_PARAM_AMPDU_TX, 0},
	{WL_PARAM_11HCACTIMEOUT, 1},
	{WL_PARAM_11hNOPTIMEOUT, 1},
	{WL_PARAM_11hDFSMODE, 1},
	{WL_PARAM_MCASTPRXY, 0},
	{WL_PARAM_11H_STA_MODE, 0},
	{WL_PARAM_RSSI, 0},
	{WL_PARAM_INTOLERANT, 1},
	{WL_PARAM_TXQLIMIT, 0},
	{WL_PARAM_RXINTLIMIT, 0},
	{WL_PARAM_LINKSTATUS, 0},
	{WL_PARAM_ANTENNATX, 1},
	{WL_PARAM_RXPATHOPT, 1},
	{WL_PARAM_HTGF, 1},
	{WL_PARAM_HTSTBC, 1},
	{WL_PARAM_3X3RATE, 1},
	{WL_PARAM_AMSDU_FLUSHTIME, 1},
	{WL_PARAM_AMSDU_MAXSIZE, 1},
	{WL_PARAM_AMSDU_ALLOWSIZE, 1},
#ifdef SOC_W906X
	{WL_PARAM_AMSDU_PKTCNT, 0},
#else
	{WL_PARAM_AMSDU_PKTCNT, 1},
#endif
#ifdef WTP_USPPORT
	{WL_PARAM_ROOTIF_NAME, 0},
	{WL_PARAM_SET_HT_IE, 0},
	{WL_PARAM_SET_VHT_IE, 0},
	{WL_PARAM_SET_PROBE_IE, 0},
#endif
	{WL_PARAM_SET_PROP_IE, 0},
	{WL_PARAM_OFF_CHANNEL_REQ_SEND, 0},
	{WL_PARAM_CONFIG_PROMISCUOUS, 0},
	{WL_PARAM_GET_DEVICE_ID, 0},
	{WL_PARAM_SET_SKU, 0},
	{WL_PARAM_SET_OFFCHPWR, 0},
#ifdef IEEE80211K
	{WL_PARAM_RRM_EN, 1},
#endif
	{WL_PARAM_11HETSICACTIMEOUT, 1},
	{WL_PARAM_STA_AUTO_SCAN, 0},
#ifdef SOC_W906X
	{WL_PARAM_AMPDUWINDOWLIMIT, 0},
	{WL_PARAM_AMPDUBYTESLIMIT, 0},
	{WL_PARAM_AMPDUDENSITYLIMIT, 0},
	{WL_PARAM_HE_LDPC, 1},
	{WL_PARAM_MU_EDCA_EN, 0},
#else
#ifdef DOT11V_DMS
	{WL_PARAM_DOT11V_DMS, 0},
#endif
#endif
};

int is_the_param_applicable(UINT16 cmd)
{
	int i;

	for (i = 0; i < sizeof(priv_wlparam) / 4; i++) {
		if (priv_wlparam[i].command == cmd)
			return priv_wlparam[i].applicable;
	}
	return 0;
}

int Is5GBand(UINT8 opmode)	//where is AP_MODE_11AX ???
{
	switch (opmode) {
	case AP_MODE_B_ONLY:
	case AP_MODE_G_ONLY:
	case AP_MODE_MIXED:
	case AP_MODE_N_ONLY:
	case AP_MODE_BandN:
	case AP_MODE_GandN:
	case AP_MODE_BandGandN:
	case AP_MODE_2_4GHZ_11AC_MIXED:
#ifdef SOC_W906X
	case AP_MODE_2_4GHZ_Nand11AX:
	case AP_MODE_2_4GHZ_11AX_MIXED:
	case (AP_MODE_G_ONLY | AP_MODE_11AC | AP_MODE_11AX | AP_MODE_N_ONLY):
	case (AP_MODE_G_ONLY | AP_MODE_11AC | AP_MODE_N_ONLY):
	case (AP_MODE_G_ONLY | AP_MODE_11AX | AP_MODE_N_ONLY):
#endif
		return 0;
	case AP_MODE_A_ONLY:
	case AP_MODE_AandN:
	case AP_MODE_5GHZ_11AC_ONLY:
	case AP_MODE_5GHZ_Nand11AC:
#ifdef SOC_W906X
	case AP_MODE_5GHZ_11AX_ONLY:
	case AP_MODE_5GHZ_ACand11AX:
	case AP_MODE_5GHZ_NandACand11AX:
#endif
		return 1;
	default:
		printk("opmode [0x%02x] not supported\n", opmode);
		break;
	}
	return 1;
}

int Is2GNeedCoexScan(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;

#ifdef COEXIST_20_40_SUPPORT
	if (*(vmacSta_p->ShadowMib802dot11->mib_HT40MIntoler) &&
	    ((vmacSta_p->ShadowMib802dot11->PhyDSSSTable->Chanflag.ChnlWidth == CH_AUTO_WIDTH)
	     || (vmacSta_p->ShadowMib802dot11->PhyDSSSTable->Chanflag.ChnlWidth == CH_160_MHz_WIDTH)
	     || (vmacSta_p->ShadowMib802dot11->PhyDSSSTable->Chanflag.ChnlWidth == CH_40_MHz_WIDTH)
	     || (vmacSta_p->ShadowMib802dot11->PhyDSSSTable->Chanflag.ChnlWidth == CH_80_MHz_WIDTH)))
		if (!Is5GBand(*(vmacSta_p->ShadowMib802dot11->mib_ApMode))) {
			return 1;
		}
#endif
	return 0;
}

int IsChanListScanFinished(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;

	return vmacSta_p->ChanIdx == vmacSta_p->NumScanChannels;
}

int IsACSOnoing(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate *wlpptr_master = wlpptr;
	struct net_device *netdev_master = netdev;
	vmacApInfo_t *vmacSta_p = NULL;

	if (wlpptr->master) {
		netdev_master = wlpptr->master;
		wlpptr_master = NETDEV_PRIV_P(struct wlprivate, wlpptr->master);
	}

	vmacSta_p = wlpptr_master->vmacSta_p;
	return ((*vmacSta_p->ShadowMib802dot11->mib_autochannel || !IsChanListScanFinished(netdev_master))
		&& (vmacSta_p->preautochannelfinished == 0));
}

int IsHTmode(UINT8 opmode)
{
	if ((opmode & AP_MODE_N_ONLY)
	    || (opmode & AP_MODE_11AC)
#ifdef SOC_W906X
	    || (opmode & AP_MODE_11AX)
#endif
	    )
		return 1;
	else
		return 0;
}

int IsVHTmode(UINT8 opmode)
{
	if ((opmode & AP_MODE_11AC)
#ifdef SOC_W906X
	    || (opmode & AP_MODE_11AX)
#endif
	    )
		return 1;
	else
		return 0;
}

void apmode_integrity(UINT8 * pmib_ApMode)
{
	BOOLEAN In_24g;
	if (*pmib_ApMode & AP_MODE_A_ONLY) {
		In_24g = FALSE;
	} else {
		In_24g = TRUE;
	}
	// If in HE mode => AC/N should be set
	if (*pmib_ApMode & AP_MODE_11AX) {
		if (In_24g == TRUE) {
			*pmib_ApMode |= (AP_MODE_N_ONLY);
		} else {
			*pmib_ApMode |= (AP_MODE_11AC | AP_MODE_N_ONLY);
		}
	}
	if (*pmib_ApMode & AP_MODE_11AC) {
		*pmib_ApMode |= AP_MODE_N_ONLY;
	}
	return;
}

#ifdef SOC_W906X
void getTkipStaKeyMaterial(extStaDb_StaInfo_t * StaInfo_p, TKIP_TYPE_KEY * pKey)
{
	memcpy(pKey->KeyMaterial, StaInfo_p->keyMgmtStateInfo.PairwiseTempKey1, MAX_ENCR_KEY_LENGTH);
	memcpy(pKey->TxMicKey, StaInfo_p->keyMgmtStateInfo.RSNPwkTxMICKey, MIC_KEY_LENGTH);
	memcpy(pKey->RxMicKey, StaInfo_p->keyMgmtStateInfo.RSNPwkRxMICKey, MIC_KEY_LENGTH);
	pKey->Rsc.low = 0;
	pKey->Rsc.high = 0;
	pKey->Tsc.low = ENDIAN_SWAP16(StaInfo_p->keyMgmtStateInfo.TxIV16);
	pKey->Tsc.high = ENDIAN_SWAP32(StaInfo_p->keyMgmtStateInfo.TxIV32);
}
#endif

static int wlioctl_priv_wlparam(struct net_device *dev, struct iw_request_info *info, void *wrqu, char *extra)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, dev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	int param = *((int *)extra);
	int value = *((int *)(extra + sizeof(int)));
	UINT8 *pvalue = *((UINT8 **) (extra + sizeof(int)));
	int rc = 0;
	MIB_PHY_DSSS_TABLE *PhyDSSSTable = mib->PhyDSSSTable;
	MIB_SPECTRUM_MGMT *mib_SpectrumMagament_p = mib->SpectrumMagament;
	struct wlprivate_data *wlpd_p = priv->wlpd_p;
	char logbuf[256];
	UINT32 size;
	u32 len = 0;
	struct device_node *node = of_find_node_by_path("/");
	const char *model = of_get_property(node, "model", &len);

	WLDBG_ENTER_INFO(DBG_LEVEL_1, "cmd: %d, value: %d\n", param, value);

	WLDBG_IOCTL(DBG_LEVEL_0, "%s:wlioctl_priv cmd:0x%x, value: 0x%x, CpuID:%u, PID:%i, ProcName:\"%s\"\n",
		    dev->name, param, value, smp_processor_id(), current->pid, current->comm);

#ifdef SOC_W906X
	if (wlpd_p->smon.active && wlpd_p->smon.ready) {
		UINT64 tsec, tms;

		convert_tscale(xxGetTimeStamp(), &tsec, &tms, NULL);
		size =
		    (UINT32) sprintf(&logbuf[0], "[%llu:%llu]: %s:wlioctl_priv cmd:0x%x, value: 0x%x, CpuID:%u, PID:%i, ProcName:\"%s\"\n", tsec, tms,
				     dev->name, param, value, smp_processor_id(), current->pid, current->comm);
		wlmon_log_buffer(dev, logbuf, size);
	}
#endif				/* SOC_W906X */

	if (is_the_param_applicable(param) && priv->master) {
		printk("This parameter cannot be set to virtual interface %s, please use %s instead!\n", dev->name, priv->master->name);
		rc = -EOPNOTSUPP;
		return rc;
	}

	switch (param) {
	case WL_PARAM_AUTHTYPE:
		if (value < 0 || value > 2) {
			rc = -EOPNOTSUPP;
			break;
		}
		mib->AuthAlg->Type = (UCHAR) value;
		break;

	case WL_PARAM_BAND:
		if (value < 0 /*|| (UCHAR)value > 7 */ ) {
			rc = -EOPNOTSUPP;
			break;
		}
#ifdef SOC_W8964
		// Check if this is a 4.9G / 5 GHz mode
		if (value & AP_MODE_4_9G_5G_PUBLIC_SAFETY)	// Detect special mode for 4.9 / 5G Japan and Public Safety.
		{		// To be backwards compatible with current opmode setting
			force_5G_channel = TRUE;	// E.g. opmode set before OR after channel is set
			value = value & ~(AP_MODE_4_9G_5G_PUBLIC_SAFETY);	// Undo the bit so the proper opmode can be set
		} else {
			force_5G_channel = FALSE;
		}
#endif
		if (model && strnstr(model, "G3", len)) {
			MIB_802DOT11 *rootmib;
			if (vmacSta_p->master) {
				rootmib = vmacSta_p->master->ShadowMib802dot11;
				if (Is5GBand(*(rootmib->mib_ApMode)) && (!Is5GBand(value))) {
					rc = -EOPNOTSUPP;
					printk("band mismatched\n");
					break;
				}
				if ((!Is5GBand(*(rootmib->mib_ApMode))) && (Is5GBand(value))) {
					rc = -EOPNOTSUPP;
					printk("band mismatched\n");
					break;
				}
			}
			*(mib->mib_ApMode) = (UCHAR) value;
			apmode_integrity(mib->mib_ApMode);
#ifdef BRS_SUPPORT
			wlset_rateSupport(mib);
#endif
		} else {
			struct wlprivate *wlp, *vpriv;
			struct net_device *vdev;
			vmacApInfo_t *vmac;
			int i;

			wlp = NETDEV_PRIV_P(struct wlprivate, wlpd_p->rootdev);

			for (i = 0; i < wlp->wlpd_p->NumOfAPs + 2; i++) {
				vdev = wlp->vdev[i];
				vpriv = NETDEV_PRIV_P(struct wlprivate, vdev);

				vmac = vpriv->vmacSta_p;
				vpriv = NETDEV_PRIV_P(struct wlprivate, vdev);

				vmac = vpriv->vmacSta_p;
				mib = vmac->ShadowMib802dot11;
				*(mib->mib_ApMode) = (UCHAR) value;
				apmode_integrity(mib->mib_ApMode);
#ifdef BRS_SUPPORT
				wlset_rateSupport(mib);
#endif
			}
		}
		break;

	case WL_PARAM_REGIONCODE:
#ifdef SOC_W906X
#ifndef EEPROM_REGION_PWRTABLE_SUPPORT
		domainSetDomain(value);
		mib_SpectrumMagament_p->countryCode = value;
		*(mib->mib_regionCode) = value;
#else
		printk("Setting Region Code not supported!\n");
#endif
		/* Set op_ch & scan_ch list to default */
		domainGetInfo(vmacSta_p->ChannelList);
		domainGetInfo(vmacSta_p->OpChanList);
#else
		{
			// Check if region code is from device or from external
			UINT32 Device_Region_Code = 0;
			if (wlFwGet_Device_Region_Code(dev, &Device_Region_Code) != SUCCESS) {
				domainSetDomain(value);
				mib_SpectrumMagament_p->countryCode = value;
				*(mib->mib_regionCode) = value;
				printk("Setting Region Code to %ld\n", value);
			} else {
				printk("Setting Region Code not supported!\n");
			}
		}
#endif
		break;

	case WL_PARAM_HIDESSID:
		if (value)
			*(mib->mib_broadcastssid) = 0;
		else
			*(mib->mib_broadcastssid) = 1;
		break;

	case WL_PARAM_PREAMBLE:
		switch ((UCHAR) value) {
		case 0:
			mib->StationConfig->mib_preAmble = PREAMBLE_AUTO_SELECT;
			break;
		case 1:
			mib->StationConfig->mib_preAmble = PREAMBLE_SHORT;
			break;
		case 2:
			mib->StationConfig->mib_preAmble = PREAMBLE_LONG;
			break;
		default:
			rc = -EOPNOTSUPP;
			break;
		}
		break;

	case WL_PARAM_GPROTECT:
		if (value)
			*(mib->mib_forceProtectiondisable) = 0;
		else
			*(mib->mib_forceProtectiondisable) = 1;
		break;

	case WL_PARAM_BEACON:
		if (value < 20 || value > 1000) {
			rc = -EOPNOTSUPP;
			break;
		}

		*(mib->mib_BcnPeriod) = (value);
		break;

	case WL_PARAM_DTIM:
		if (value < 1 || value > 255) {
			rc = -EOPNOTSUPP;
			break;
		}

		mib->StationConfig->DtimPeriod = (UCHAR) value;
		break;

	case WL_PARAM_FIXRATE:
		if (value < 0 || value > 2) {
			rc = -EOPNOTSUPP;
			break;
		}
		*(mib->mib_enableFixedRateTx) = (UCHAR) value;
		break;

	case WL_PARAM_ANTENNA:
		{
			UINT8 max_antenna_num = 0x0;
			if (priv->devid == SC5) {
				max_antenna_num = 8;
			} else {
				max_antenna_num = 4;
			}
			if (value < 0 || value > max_antenna_num) {
				rc = -EOPNOTSUPP;
				break;
			}
			*(mib->mib_rxAntenna) = (UCHAR) value;

			if (*(mib->mib_rxAntenna) == 0) {
				if (priv->devid == SC5) {
					*(mib->mib_rxAntBitmap) = 0xff;
				} else {
					*(mib->mib_rxAntBitmap) = 0xf;
				}
			} else if (*(mib->mib_rxAntenna) == 8)
				*(mib->mib_rxAntBitmap) = 0xff;
			else if (*(mib->mib_rxAntenna) == 7)
				*(mib->mib_rxAntBitmap) = 0x7f;
			else if (*(mib->mib_rxAntenna) == 6)
				*(mib->mib_rxAntBitmap) = 0x3f;
			else if (*(mib->mib_rxAntenna) == 5)
				*(mib->mib_rxAntBitmap) = 0x1f;
			else if (*(mib->mib_rxAntenna) == 4)
				*(mib->mib_rxAntBitmap) = 0xf;
			else if (*(mib->mib_rxAntenna) == 3)
				*(mib->mib_rxAntBitmap) = 0x7;
			else if (*(mib->mib_rxAntenna) == 2)
				*(mib->mib_rxAntBitmap) = 0x3;
			else
				*(mib->mib_rxAntBitmap) = 0x1;
		}
		break;

	case WL_PARAM_ANTENNATX:
		{
			UINT8 max_antenna_bitmap = 0x0;
			if (priv->devid == SC5) {
				max_antenna_bitmap = 0xff;
			} else {
				max_antenna_bitmap = 0xf;
			}
			if (value < 0 || value > max_antenna_bitmap) {
				rc = -EOPNOTSUPP;
				break;
			}
			/* 0:AB(Auto), 1:A, 2:B, 3:AB, 7:ABC */
			*(mib->mib_txAntenna) = (UCHAR) value;
		}
		break;

	case WL_PARAM_FILTER:
		if (value < 0 || value > 2) {
			rc = -EOPNOTSUPP;
			break;
		}
		*(mib->mib_wlanfiltertype) = (UCHAR) value;
		break;

	case WL_PARAM_WMM:
		*(mib->QoSOptImpl) = (UCHAR) value;
		break;

	case WL_PARAM_WPAWPA2MODE:
		{
#ifdef MRVL_WPS_CLIENT
			vmacEntry_t *vmacEntry_p = NULL;
			STA_SYSTEM_MIBS *pStaSystemMibs;
#endif
			if ((value & 0x0000000F) > 0x0A) {
				rc = -EOPNOTSUPP;
				break;
			}
			*(mib->mib_wpaWpa2Mode) = (UCHAR) value;

#ifdef MRVL_WPS_CLIENT
			if ((vmacEntry_p = sme_GetParentVMacEntry(vmacSta_p->VMacEntry.phyHwMacIndx)) != NULL) {
				pStaSystemMibs = sme_GetStaSystemMibsPtr(vmacEntry_p);
				if (pStaSystemMibs != NULL) {
					pStaSystemMibs->mib_StaCfg_p->wpawpa2Mode = value;
				}
			}
#ifdef SOC_W8964
			if (value == 16) {	// wps                              
				memset(priv->wpsProbeRequestIe, 0, sizeof(priv->wpsProbeRequestIe));
				priv->wpsProbeRequestIeLen = 0;
				memset(vmacSta_p->RsnIE, 0, sizeof(IEEEtypes_RSN_IE_WPA2_t));
				vmacSta_p->RsnIESetByHost = 0;
			}
#endif
#endif

#ifdef MRVL_WSC
			if ((value == 0) || ((value & 0x0000000F) == 0))
#else
			if (value == 0)
#endif
			{
				mib->Privacy->RSNEnabled = 0;
				mib->Privacy->RSNLinkStatus = 0;
				mib->RSNConfigWPA2->WPA2Enabled = 0;
				mib->RSNConfigWPA2->WPA2OnlyEnabled = 0;
			} else {
				mib->Privacy->PrivInvoked = 0;	/* WEP disable */
				mib->AuthAlg->Type = 0;	/* Reset WEP to open mode */
				mib->Privacy->RSNEnabled = 1;
				mib->Privacy->RSNLinkStatus = 0;
				mib->RSNConfigWPA2->WPA2Enabled = 0;
				mib->RSNConfigWPA2->WPA2OnlyEnabled = 0;
				*(mib->mib_WPAPSKValueEnabled) = 0;	//PSK

				mib->RSNConfig->MulticastCipher[0] = 0x00;
				mib->RSNConfig->MulticastCipher[1] = 0x50;
				mib->RSNConfig->MulticastCipher[2] = 0xF2;
				mib->RSNConfig->MulticastCipher[3] = 0x02;	// TKIP

				mib->UnicastCiphers->UnicastCipher[0] = 0x00;
				mib->UnicastCiphers->UnicastCipher[1] = 0x50;
				mib->UnicastCiphers->UnicastCipher[2] = 0xF2;
				mib->UnicastCiphers->UnicastCipher[3] = 0x02;	// TKIP
				mib->UnicastCiphers->Enabled = TRUE;

				mib->RSNConfigAuthSuites->AuthSuites[0] = 0x00;
				mib->RSNConfigAuthSuites->AuthSuites[1] = 0x50;
				mib->RSNConfigAuthSuites->AuthSuites[2] = 0xF2;

				if ((value & 0x0000000F) == 4 || (value & 0x0000000F) == 6)
					mib->RSNConfigAuthSuites->AuthSuites[3] = 0x01;	// Auth8021x
				else
					mib->RSNConfigAuthSuites->AuthSuites[3] = 0x02;	// AuthPSK

				mib->RSNConfigAuthSuites->Enabled = TRUE;

				*(mib->mib_cipherSuite) = 2;

				if ((value & 0x0000000F) == 2 || (value & 0x0000000F) == 5 || (value & 0x0000000F) == 9
				    || (value & 0x0000000F) == 0xA) {
					mib->RSNConfigWPA2->WPA2Enabled = 1;
					mib->RSNConfigWPA2->WPA2OnlyEnabled = 1;

					mib->RSNConfigWPA2->MulticastCipher[0] = 0x00;
					mib->RSNConfigWPA2->MulticastCipher[1] = 0x0F;
					mib->RSNConfigWPA2->MulticastCipher[2] = 0xAC;
					mib->RSNConfigWPA2->MulticastCipher[3] = 0x04;	// AES

					mib->WPA2UnicastCiphers->UnicastCipher[0] = 0x00;
					mib->WPA2UnicastCiphers->UnicastCipher[1] = 0x0F;
					mib->WPA2UnicastCiphers->UnicastCipher[2] = 0xAC;
					mib->WPA2UnicastCiphers->UnicastCipher[3] = 0x04;	// AES
					mib->WPA2UnicastCiphers->Enabled = TRUE;

					mib->WPA2AuthSuites->AuthSuites[0] = 0x00;
					mib->WPA2AuthSuites->AuthSuites[1] = 0x0F;
					mib->WPA2AuthSuites->AuthSuites[2] = 0xAC;

					if ((value & 0x0000000F) == 5)
						mib->WPA2AuthSuites->AuthSuites[3] = 0x01;	// Auth8021x
					else if ((value & 0x0000000F) == 9)
						mib->WPA2AuthSuites->AuthSuites[3] = 0x08;	// AuthSAE
					else if ((value & 0x0000000F) == 0xA)
						mib->WPA2AuthSuites->AuthSuites[3] = 0x12;	// AuthOWE
					else
						mib->WPA2AuthSuites->AuthSuites[3] = 0x02;	// AuthPSK

					mib->WPA2AuthSuites->Enabled = TRUE;

					*(mib->mib_cipherSuite) = 4;

				} else if ((value & 0x0000000F) == 7 || (value & 0x0000000F) == 8) {
					mib->RSNConfigWPA2->WPA2Enabled = 1;
					mib->RSNConfigWPA2->WPA2OnlyEnabled = 1;

					mib->WPA2AuthSuites->AuthSuites[0] = 0x00;
					mib->WPA2AuthSuites->AuthSuites[1] = 0x0F;
					mib->WPA2AuthSuites->AuthSuites[2] = 0xAC;

					if ((value & 0x0000000F) == 7) {
						*(mib->mib_cipherSuite) = IEEEtypes_RSN_CIPHER_SUITE_GCMP;
						mib->WPA2AuthSuites->AuthSuites[3] = 11;	// SuiteB
					} else {
						*(mib->mib_cipherSuite) = IEEEtypes_RSN_CIPHER_SUITE_GCMP_256;
						mib->WPA2AuthSuites->AuthSuites[3] = 12;	// SuiteB_192
					}

					mib->WPA2AuthSuites->Enabled = TRUE;
				} else if ((value & 0x0000000F) == 7 && (value & 0x0000000F) == 8) {
					mib->RSNConfigWPA2->WPA2Enabled = 1;
					mib->RSNConfigWPA2->WPA2OnlyEnabled = 1;

					mib->WPA2AuthSuites->AuthSuites[0] = 0x00;
					mib->WPA2AuthSuites->AuthSuites[1] = 0x0F;
					mib->WPA2AuthSuites->AuthSuites[2] = 0xAC;

					if ((value & 0x0000000F) == 8) {
						*(mib->mib_cipherSuite) = 8;	//gcmp128
						mib->WPA2AuthSuites->AuthSuites[3] = 11;	// SuiteB
					} else {
						*(mib->mib_cipherSuite) = 9;	//gcmp256
						mib->WPA2AuthSuites->AuthSuites[3] = 12;	// SuiteB_192
					}
					mib->WPA2AuthSuites->Enabled = TRUE;
				} else if ((value & 0x0000000F) == 3 || (value & 0x0000000F) == 6) {
					mib->RSNConfigWPA2->WPA2Enabled = 1;
					mib->RSNConfigWPA2->WPA2OnlyEnabled = 0;
					mib->RSNConfigWPA2->MulticastCipher[0] = 0x00;
					mib->RSNConfigWPA2->MulticastCipher[1] = 0x0F;
					mib->RSNConfigWPA2->MulticastCipher[2] = 0xAC;
					mib->RSNConfigWPA2->MulticastCipher[3] = 0x02;	// TKIP

					mib->UnicastCiphers->UnicastCipher[0] = 0x00;
					mib->UnicastCiphers->UnicastCipher[1] = 0x50;
					mib->UnicastCiphers->UnicastCipher[2] = 0xF2;
					mib->UnicastCiphers->UnicastCipher[3] = 0x02;	// TKIP
					mib->UnicastCiphers->Enabled = TRUE;

					mib->WPA2UnicastCiphers->UnicastCipher[0] = 0x00;
					mib->WPA2UnicastCiphers->UnicastCipher[1] = 0x0F;
					mib->WPA2UnicastCiphers->UnicastCipher[2] = 0xAC;
					mib->WPA2UnicastCiphers->UnicastCipher[3] = 0x04;	// AES
					mib->WPA2UnicastCiphers->Enabled = TRUE;

					mib->WPA2AuthSuites->AuthSuites[0] = 0x00;
					mib->WPA2AuthSuites->AuthSuites[1] = 0x0F;
					mib->WPA2AuthSuites->AuthSuites[2] = 0xAC;

					if ((value & 0x0000000F) == 6)
						mib->WPA2AuthSuites->AuthSuites[3] = 0x01;	// Auth8021x
					else
						mib->WPA2AuthSuites->AuthSuites[3] = 0x02;	// AuthPSK

					mib->WPA2AuthSuites->Enabled = TRUE;

					*(mib->mib_cipherSuite) = 4;

				}
			}

			PRINT1(IOCTL, "mib->Privacy->RSNEnabled %d\n", mib->Privacy->RSNEnabled);
			PRINT1(IOCTL, "mib->RSNConfigWPA2->WPA2Enabled %d\n", mib->RSNConfigWPA2->WPA2Enabled);
			PRINT1(IOCTL, "mib->RSNConfigWPA2->WPA2OnlyEnabled %d\n", mib->RSNConfigWPA2->WPA2OnlyEnabled);
			PRINT1(IOCTL, "mib->mib_wpaWpa2Mode %x\n", *(mib->mib_wpaWpa2Mode));

			break;

#ifdef MRVL_WAPI
	case WL_PARAM_WAPIMODE:
			if (value == 0)
				mib->Privacy->WAPIEnabled = (UCHAR) value;
			else
				printk("Note: wapimode only can be enabled by wapid\n");
			break;
#endif

	case WL_PARAM_GROUPREKEYTIME:
			if (value < 0) {
				rc = -EOPNOTSUPP;
				break;
			}
			if (value)
				mib->RSNConfig->GroupRekeyTime = (value);
			else	/* disable rekey */
				mib->RSNConfig->GroupRekeyTime = (0xffffffff / 10);

			PRINT1(IOCTL, "mib->RSNConfig->GroupRekeyTime %d\n", mib->RSNConfig->GroupRekeyTime);

		}
		break;

	case WL_PARAM_INTRABSS:
		if (value < 0 || value > 1) {
			rc = -EOPNOTSUPP;
			break;
		}
		*(mib->mib_intraBSS) = (UCHAR) value;
		break;

	case WL_PARAM_AMSDU:
		if (value < 0 || value > 3) {
			rc = -EOPNOTSUPP;
			break;
		}

		*(mib->mib_amsdutx) = value;	//0:amsdu disable, 1:4K, 2:8K, 3:11K (for VHT, for 11n it is considered 8K)

		{
			//keep the ampdu setting
			*(mib->pMib_11nAggrMode) = (*(mib->pMib_11nAggrMode) & WL_MODE_AMPDU_TX) | (UCHAR) value;
		}

		break;

	case WL_PARAM_HTBANDWIDTH:
#ifdef SOC_W906X
		if ((PhyDSSSTable->Chanflag.radiomode == RADIO_MODE_80p80) && (value != 4)) {
			WLDBG_ERROR(DBG_LEVEL_1, "Radio mode is 80+80, only 80MHZ is accepted. Please set htbw to 4\n");
			rc = -EOPNOTSUPP;
			break;
		}
#ifdef CONCURRENT_DFS_SUPPORT
		if (priv->wlpd_p->ext_scnr_en && (value == 5)) {
			WLDBG_ERROR(DBG_LEVEL_1, "160MHZ badnwith is not accepted when concurrent DFS mode is enabled.\n");
			rc = -EOPNOTSUPP;
			break;
		}
#endif				/* CONCURRENT_DFS_SUPPORT */
#endif
		priv->auto_bw = 0;

		switch (value) {
		case 0:
			switch (priv->devid) {
			case SC4:
			case SC4P:	/*check the optimal auto BW setting for SC4P. */
				PhyDSSSTable->Chanflag.ChnlWidth = CH_160_MHz_WIDTH;
				vht_cap = 0x339b7976;
				ie192_version = 2;
				break;
			case SC5:
			case SCBT:
				priv->auto_bw = 1;
				if (PhyDSSSTable->Chanflag.FreqBand == FREQ_BAND_5GHZ)
					PhyDSSSTable->Chanflag.ChnlWidth = CH_80_MHz_WIDTH;
				else if (PhyDSSSTable->Chanflag.FreqBand == FREQ_BAND_2DOT4GHZ)
					PhyDSSSTable->Chanflag.ChnlWidth = CH_40_MHz_WIDTH;

				vht_cap = 0x339b7930;
				break;
			default:
				WLDBG_ERROR(DBG_LEVEL_1, "Not support chip. Consider what's optimal auto BW settting for thsi chip.\n");
				break;
			}
			break;
		case 1:
			PhyDSSSTable->Chanflag.ChnlWidth = CH_10_MHz_WIDTH;
			break;
		case 2:
			PhyDSSSTable->Chanflag.ChnlWidth = CH_20_MHz_WIDTH;
			break;
		case 3:
			PhyDSSSTable->Chanflag.ChnlWidth = CH_40_MHz_WIDTH;
			break;
		case 4:
			PhyDSSSTable->Chanflag.ChnlWidth = CH_80_MHz_WIDTH;
			vht_cap = 0x339b7930;
			break;
		case 5:
			PhyDSSSTable->Chanflag.ChnlWidth = CH_160_MHz_WIDTH;
			vht_cap = 0x339b7976;
			ie192_version = 2;
			break;
		case 6:
#ifdef SOC_W906X
			rc = -EOPNOTSUPP;	/* SC5/SCBT only supports new VHT operation IE */
#else
			PhyDSSSTable->Chanflag.ChnlWidth = CH_160_MHz_WIDTH;
			vht_cap = 0x339b7976;
			ie192_version = 1;
#endif
			break;
		case 8:
			PhyDSSSTable->Chanflag.ChnlWidth = CH_5_MHz_WIDTH;
			break;
		default:
			rc = -EOPNOTSUPP;
			break;
		}
#ifdef INTOLERANT40
		*(mib->USER_ChnlWidth) = PhyDSSSTable->Chanflag.ChnlWidth;
		if ((*(mib->USER_ChnlWidth) == CH_40_MHz_WIDTH) || (*(mib->USER_ChnlWidth) == CH_AUTO_WIDTH) ||
		    (*(mib->USER_ChnlWidth) == CH_80_MHz_WIDTH) || (*(mib->USER_ChnlWidth) == CH_160_MHz_WIDTH))
			*(mib->mib_FortyMIntolerant) = 0;
		else
			*(mib->mib_FortyMIntolerant) = 1;
#endif
#ifdef COEXIST_20_40_SUPPORT
		if ((PhyDSSSTable->Chanflag.ChnlWidth == CH_AUTO_WIDTH) || (PhyDSSSTable->Chanflag.ChnlWidth == CH_160_MHz_WIDTH) ||
		    (PhyDSSSTable->Chanflag.ChnlWidth == CH_40_MHz_WIDTH) || (PhyDSSSTable->Chanflag.ChnlWidth == CH_80_MHz_WIDTH)) {
			if (PhyDSSSTable->CurrChan == 14)
				*(mib->USER_ChnlWidth) = 0;
			else
				*(mib->USER_ChnlWidth) = 1;
		} else
			*(mib->USER_ChnlWidth) = 0;
#endif
		break;

	case WL_PARAM_WMMACKPOLICY:
		if (value < 0 || value > 3) {
			rc = -EOPNOTSUPP;
			break;
		}
		*(mib->mib_wmmAckPolicy) = (UCHAR) value;
		break;

	case WL_PARAM_GUARDINTERVAL:
		if (value < 0 || value > 2) {
			rc = -EOPNOTSUPP;
			break;
		}
		*(mib->mib_guardInterval) = (UCHAR) value;
		break;

	case WL_PARAM_EXTSUBCH:
		if (value < 0 || value > 2) {
			rc = -EOPNOTSUPP;
			break;
		}
		switch (PhyDSSSTable->CurrChan) {
		case 1:
		case 2:
		case 3:
		case 4:
			if (value == 1)
				return -EINVAL;
			break;
		case 5:
		case 6:
		case 7:
		case 8:
		case 9:
		case 10:
			break;
		case 11:
		case 12:
		case 13:
		case 14:
			if (value == 2)
				return -EINVAL;
			break;
		}
		*(mib->mib_extSubCh) = (UCHAR) value;
		break;

	case WL_PARAM_HTPROTECT:
		if (value < 0 || value > 4) {
			rc = -EOPNOTSUPP;
			break;
		}
		*(mib->mib_htProtect) = (UCHAR) value;
		break;

	case WL_PARAM_GETFWSTAT:
		wlFwGetHwStats(dev, NULL);
		break;

	case WL_PARAM_AGINGTIME:
		if (value < 60 || value > 86400) {
			rc = -EOPNOTSUPP;
			break;
		}
		*(mib->mib_agingtime) = value;
		break;
	case WL_PARAM_ANTENNATX2:
		*(mib->mib_txAntenna2) = value;
		break;
	case WL_PARAM_CDD:
		if (value < 0 || value > 1) {
			rc = -EINVAL;
			break;
		}

		*(mib->mib_CDD) = value;
		break;
	case WL_PARAM_ACS_THRESHOLD:
		if (value < 0) {
			rc = -EINVAL;
			break;
		}

		*(mib->mib_acs_threshold) = value;
		break;
	case WL_PARAM_AUTOCHANNEL:
		if (value < 0 || value > 2) {
			rc = -EINVAL;
			break;
		}
		/* wait for scan complete */
		if (vmacSta_p->preautochannelfinished == 0) {
			unsigned long wait_ret = 0;
			wait_ret = wait_for_completion_timeout(&vmacSta_p->scan_complete, vmacSta_p->scan_timeout);
			if (vmacSta_p->preautochannelfinished == 0)
				printk(KERN_WARNING "Wait scan finish timeout, autochannel, %us, %lu\n", (vmacSta_p->scan_timeout / HZ), wait_ret);
			else
				printk("Pre-Auto channel finished for autochannel\n");

		}
		*(mib->mib_autochannel) = value;
		vmacSta_p->preautochannelfinished = 1;
		vmacSta_p->acs_cur_bcn = 0;
		if (!vmacSta_p->acs_mode) {
			vmacSta_p->acs_ch_load_weight = 40;
			vmacSta_p->acs_ch_nf_weight = 50;
			vmacSta_p->acs_ch_distance_weight = 300;
			vmacSta_p->acs_bss_distance_weight = 300;
			vmacSta_p->acs_bss_num_weight = 100;
			vmacSta_p->acs_rssi_weight = 150;
			vmacSta_p->acs_adjacent_bss_weight = 0;
			vmacSta_p->acs_adjacent_bss_weight_plus = 0;
		} else {
			vmacSta_p->acs_ch_load_weight = 0;
			vmacSta_p->acs_ch_nf_weight = 0;
			vmacSta_p->acs_ch_distance_weight = 10;
			vmacSta_p->acs_bss_distance_weight = 10;
			vmacSta_p->acs_bss_num_weight = 100;
			vmacSta_p->acs_rssi_weight = 0;
			vmacSta_p->acs_adjacent_bss_weight = 0;
			vmacSta_p->acs_adjacent_bss_weight_plus = 0;
		}
		if (value != 0 && vmacSta_p->acs_IntervalTime == 0) {
			vmacSta_p->acs_IntervalTime = 10;
		}
		if (value == 2) {
			if (vmacSta_p->ChannelList[0] == 0 && vmacSta_p->ChannelList[IEEEtypes_MAX_CHANNELS] == 0) {
				/* if not set scanchannel list, set it to default */
				domainGetInfo(vmacSta_p->ChannelList);
			}
			if (vmacSta_p->OpChanList[0] == 0 && vmacSta_p->OpChanList[IEEEtypes_MAX_CHANNELS] == 0) {
				/* if not set op channel list, set it to default */
				domainGetInfo(vmacSta_p->OpChanList);
			}
		}
		break;
	case WL_PARAM_AMPDUFACTOR:
		if (value < 0 || value > 3) {
			rc = -EINVAL;
			break;
		}
		*(mib->mib_ampdu_factor) = value;
		break;
	case WL_PARAM_AMPDUDENSITY:
		if (value < 0 || value > 7) {
			rc = -EINVAL;
			break;
		}
		*(mib->mib_ampdu_density) = value;
		break;
#ifdef INTEROP
	case WL_PARAM_INTEROP:
		*(mib->mib_interop) = value;
		break;
#endif
	case WL_PARAM_OPTLEVEL:
		*(mib->mib_optlevel) = value;
		break;

	case WL_PARAM_REGIONPWR:
		{
			int i;
			if (value < MINTXPOWER || value > 18) {
				rc = -EINVAL;
				break;
			}

			*(mib->mib_MaxTxPwr) = value;
			for (i = 0; i < TX_POWER_LEVEL_TOTAL; i++) {
				if (mib->PhyDSSSTable->maxTxPow[i] > *(mib->mib_MaxTxPwr))
					mib->PhyDSSSTable->maxTxPow[i] = *(mib->mib_MaxTxPwr);
			}
		}
		break;

#ifdef PWRFRAC
	case WL_PARAM_TXPWRFRACTION:
		{
			if (value < 0 || value > 5) {
				rc = -EINVAL;
				break;
			}

			*(mib->mib_TxPwrFraction) = value;
		}
		break;
#endif

	case WL_PARAM_ADAPTMODE:
		{
			if (value < 0 || value > 1) {
				rc = -EINVAL;
				break;
			}

			*(mib->mib_RateAdaptMode) = value;
		}
		break;
#ifdef WDS_FEATURE
	case WL_PARAM_WDSMODE:
		{
			if (value < 0 || value > 1) {
				rc = -EINVAL;
				break;
			}

			*(mib->mib_wdsEnable) = value;
		}
		break;
#endif
	case WL_PARAM_DISABLEASSOC:
		{
			if (value < 0 || value > 1) {
				rc = -EINVAL;
				break;
			}

			*(mib->mib_disableAssoc) = value;
		}
		break;
	case WL_PARAM_CSADAPTMODE:
		{
			if (value < 0 || value > 3) {
				rc = -EINVAL;
				break;
			}

			*(mib->mib_CSMode) = value;
		}
		break;

		/* MRV_8021X */
	case WL_PARAM_SETKEYS:
		{
			struct wlreq_key wk;

			if (pvalue == NULL) {
				rc = -EINVAL;
				break;
			}

			if (copy_from_user((char *)&wk, pvalue, sizeof(wk))) {
				rc = -EINVAL;
				break;
			}
			rc = mwl_config_set_key(dev, &wk);
		}
		break;

	case WL_PARAM_SETKEYS_GROUP_RX:
		{
			wlreq_key wk;
			extStaDb_StaInfo_t *pStaInfo = NULL;

			if (pvalue == NULL) {
				rc = -EINVAL;
				break;
			}
			if (copy_from_user((char *)&wk, pvalue, sizeof(wk))) {
				rc = -EINVAL;
				break;
			}

			if (wk.ik_keyix == WL_KEYIX_NONE) {
				if (extStaDb_SetRSNPwkAndDataTraffic(vmacSta_p,
								     (IEEEtypes_MacAddr_t *) wk.ik_macaddr,
								     &wk.ik_keydata[0],
								     (UINT32 *) & wk.ik_keydata[16],
								     (UINT32 *) & wk.ik_keydata[24]) != STATE_SUCCESS) {
					rc = -EOPNOTSUPP;
					break;
				}
				if (extStaDb_SetPairwiseTSC(vmacSta_p, (IEEEtypes_MacAddr_t *) wk.ik_macaddr, 0, 0x0001) != STATE_SUCCESS) {
					rc = -EOPNOTSUPP;
					break;
				}

				if ((pStaInfo = extStaDb_GetStaInfo(vmacSta_p, (IEEEtypes_MacAddr_t *) wk.ik_macaddr,
								    STADB_UPDATE_AGINGTIME)) == NULL) {
					rc = -EOPNOTSUPP;
					break;
				}
				//to do, set keys
			} else if ((0 < wk.ik_keyix) && (wk.ik_keyix < 4)) {
				if (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_AP) {
					wlFwSetWpaGroupK_rx(dev, &wk);
				}

			} else {
				rc = -ENOTSUPP;
				break;
			}
		}
		break;

	case WL_PARAM_DELKEYS:
		{
			struct wlreq_del_key wk;

			if (pvalue == NULL) {
				rc = -EINVAL;
				break;
			}
			if (copy_from_user((char *)&wk, pvalue, sizeof(wk))) {
				rc = -EINVAL;
				break;
			}

			if (extStaDb_SetRSNDataTrafficEnabled(vmacSta_p, (IEEEtypes_MacAddr_t *) wk.idk_macaddr, FALSE) != STATE_SUCCESS) {
				break;
			}
		}
		break;
	case WL_PARAM_MLME_REQ:
		{
			struct wlreq_mlme mlme;

			if (pvalue == NULL) {
				rc = -EINVAL;
				break;
			}

			if (copy_from_user((char *)&mlme, pvalue, sizeof(mlme))) {
				rc = -EINVAL;
				break;
			}

			rc = mwl_config_send_mlme(dev, &mlme);
		}
		break;

#ifdef WTP_SUPPORT
	case WL_PARAM_ROOTIF_NAME:
		{
			UCHAR buf[64], buf_len = 0;
			if (priv->master) {
				buf_len = strlen(priv->master->name);
				memcpy(buf, priv->master->name, buf_len);
			} else {
				buf_len = strlen(dev->name);
				memcpy(buf, dev->name, buf_len);
			}
			buf[buf_len] = '\0';
			if (copy_to_user(pvalue, buf, buf_len + 1)) {
				rc = -EFAULT;
				break;
			}
		}
		break;

	case WL_PARAM_SET_HT_IE:
		{
			struct wlreq_setIE wlSetIE;

			if (pvalue == NULL) {
				rc = -EINVAL;
				break;
			}

			if (copy_from_user((char *)&wlSetIE, pvalue, sizeof(wlSetIE))) {
				rc = -EINVAL;
				break;
			}
			vmacSta_p->wtp_info.extHtIE = true;
			memcpy(vmacSta_p->wtp_info.HTCapIE, wlSetIE.HtCapIE, wlSetIE.HtCapIE[1] + 2);
			memcpy(vmacSta_p->wtp_info.addHTIE, wlSetIE.HtInfoIE, wlSetIE.HtInfoIE[1] + 2);
		}
		break;

	case WL_PARAM_SET_VHT_IE:
		{
			struct wlreq_setIE wlSetIE;

			if (pvalue == NULL) {
				rc = -EINVAL;
				break;
			}

			if (copy_from_user((char *)&wlSetIE, pvalue, sizeof(wlSetIE))) {
				rc = -EINVAL;
				break;
			}
			vmacSta_p->wtp_info.extVhtIE = true;
			memcpy(vmacSta_p->wtp_info.vhtCapIE, wlSetIE.vhtCapIE, wlSetIE.vhtCapIE[1] + 2);
			memcpy(vmacSta_p->wtp_info.vhtInfoIE, wlSetIE.vhtInfoIE, wlSetIE.vhtInfoIE[1] + 2);
		}
		break;
#ifdef SOC_W906X
	case WL_PARAM_SET_HE_IE:
		{
			struct wlreq_setIE wlSetIE;

			if (pvalue == NULL) {
				rc = -EINVAL;
				break;
			}

			if (copy_from_user((char *)&wlSetIE, pvalue, sizeof(wlSetIE))) {
				rc = -EINVAL;
				break;
			}
			vmacSta_p->wtp_info.extHeIE = true;
			memcpy(vmacSta_p->wtp_info.heCapIe, wlSetIE.heCapIE, wlSetIE.heCapIE[1] + 2);
			memcpy(vmacSta_p->wtp_info.heOpIe, wlSetIE.heOpIE, wlSetIE.heOpIE[1] + 2);
		}
		break;
#endif
	case WL_PARAM_SET_PROP_IE:
		{
			struct wlreq_setIE wlSetIE;

			if (pvalue == NULL) {
				rc = -EINVAL;
				break;
			}

			if (copy_from_user((char *)&wlSetIE, pvalue, sizeof(wlSetIE))) {
				rc = -EINVAL;
				break;
			}
			//hexdump("wlSetIE : ", wlSetIE.proprietaryIE, wlSetIE.proprietaryIE[1] + 2, ' ');
			vmacSta_p->wtp_info.extPropIE = true;
			memcpy(vmacSta_p->wtp_info.propIE, wlSetIE.proprietaryIE, wlSetIE.proprietaryIE[1] + 2);
		}
		break;

	case WL_PARAM_SET_PROBE_IE:
		{
			struct wlreq_setIE wlSetIE;

			if (pvalue == NULL) {
				rc = -EINVAL;
				break;
			}

			if (copy_from_user((char *)&wlSetIE, pvalue, sizeof(wlSetIE))) {
				rc = -EINVAL;
				break;
			}
			//hexdump("wlSetIE extProbe : ", wlSetIE.extProbeIE, wlSetIE.extProbeIE[1] + 2, ' ');
			if (wlFwSetPropProbeIE(dev, wlSetIE.extProbeIE, wlSetIE.extProbeIE[1] + 2)) {
				WLDBG_EXIT_INFO(DBG_LEVEL_1, "Failed setting WSC IE");
			}
		}
#endif
	case WL_PARAM_COUNTERMEASURES:
		{
			if (value) {
				vmacSta_p->MIC_ErrordisableStaAsso = 1;
				extStaDb_RemoveAllStns(vmacSta_p, IEEEtypes_REASON_MIC_FAILURE);
#ifdef SOC_W906X
				macMgmtMlme_SendDeauthenticateMsg(vmacSta_p, &bcastMacAddr, 0, IEEEtypes_REASON_MIC_FAILURE, FALSE);
#else
				macMgmtMlme_SendDeauthenticateMsg(vmacSta_p, &bcastMacAddr, 0, IEEEtypes_REASON_MIC_FAILURE);
#endif
			} else {
				vmacSta_p->MIC_ErrordisableStaAsso = 0;
			}
		}
		break;
		/* MRV_8021X */

	case WL_PARAM_DELWEPKEY:
		{
			if (value < 0 || value > 3) {
				rc = -EINVAL;
				break;
			}
			PRINT1(IOCTL, "wep key = %x %x %x %x %x %x %x %x %x %x %x %x %x \n",
			       mib->WepDefaultKeys[value].WepDefaultKeyValue[0],
			       mib->WepDefaultKeys[value].WepDefaultKeyValue[1],
			       mib->WepDefaultKeys[value].WepDefaultKeyValue[2],
			       mib->WepDefaultKeys[value].WepDefaultKeyValue[3],
			       mib->WepDefaultKeys[value].WepDefaultKeyValue[4],
			       mib->WepDefaultKeys[value].WepDefaultKeyValue[5],
			       mib->WepDefaultKeys[value].WepDefaultKeyValue[6],
			       mib->WepDefaultKeys[value].WepDefaultKeyValue[7],
			       mib->WepDefaultKeys[value].WepDefaultKeyValue[8],
			       mib->WepDefaultKeys[value].WepDefaultKeyValue[9],
			       mib->WepDefaultKeys[value].WepDefaultKeyValue[10],
			       mib->WepDefaultKeys[value].WepDefaultKeyValue[11], mib->WepDefaultKeys[value].WepDefaultKeyValue[12]);

			memset(mib->WepDefaultKeys[value].WepDefaultKeyValue, 0, 13);

			PRINT1(IOCTL, "wep key = %x %x %x %x %x %x %x %x %x %x %x %x %x \n",
			       mib->WepDefaultKeys[value].WepDefaultKeyValue[0],
			       mib->WepDefaultKeys[value].WepDefaultKeyValue[1],
			       mib->WepDefaultKeys[value].WepDefaultKeyValue[2],
			       mib->WepDefaultKeys[value].WepDefaultKeyValue[3],
			       mib->WepDefaultKeys[value].WepDefaultKeyValue[4],
			       mib->WepDefaultKeys[value].WepDefaultKeyValue[5],
			       mib->WepDefaultKeys[value].WepDefaultKeyValue[6],
			       mib->WepDefaultKeys[value].WepDefaultKeyValue[7],
			       mib->WepDefaultKeys[value].WepDefaultKeyValue[8],
			       mib->WepDefaultKeys[value].WepDefaultKeyValue[9],
			       mib->WepDefaultKeys[value].WepDefaultKeyValue[10],
			       mib->WepDefaultKeys[value].WepDefaultKeyValue[11], mib->WepDefaultKeys[value].WepDefaultKeyValue[12]);
		}
		break;

	case WL_PARAM_STRICTWEPSHARE:
		{
			if (value < 0 || value > 1) {
				rc = -EINVAL;
				break;
			}

			*(mib->mib_strictWepShareKey) = value;
		}
		break;
	case WL_PARAM_11H_DFS_MODE:
		{
			if (value < 0 || value > 3) {
				rc = -EINVAL;
				break;
			}
			if ((PhyDSSSTable->Chanflag.FreqBand == FREQ_BAND_5GHZ) && (PhyDSSSTable->CurrChan >= 52)) {
				wlFwSetRadarDetection(dev, value);
			} else {
				rc = -EOPNOTSUPP;
				break;
			}
		}
		break;

	case WL_PARAM_11H_CSA_CHAN:
		{
			if (!domainChannelValid(value, FREQ_BAND_5GHZ)) {
				rc = -EINVAL;
				break;
			}
			mib_SpectrumMagament_p->csaChannelNumber = value;
		}
		break;

	case WL_PARAM_11H_CSA_COUNT:
		{
			if (value < 0 || value > 255) {
				rc = -EINVAL;
				break;
			}
			mib_SpectrumMagament_p->csaCount = value;
		}
		break;

	case WL_PARAM_11H_CSA_MODE:
		{
			if (value < 0 || value > 1) {
				rc = -EINVAL;
				break;
			}
			mib_SpectrumMagament_p->csaMode = value;
		}
		break;

	case WL_PARAM_11H_CSA_START:
		{
			int i;

			if (value < 0 || value > 1) {
				rc = -EINVAL;
				break;
			}
			if (value == 0) {
				break;
			}

			if (PhyDSSSTable->Chanflag.FreqBand != FREQ_BAND_5GHZ) {
				PRINT1(IOCTL, "wlioctl_priv_wlparam: wrong band %d\n", PhyDSSSTable->Chanflag.FreqBand);
				rc = -EOPNOTSUPP;
				break;
			}
			if (mib->StationConfig->SpectrumManagementRequired != TRUE) {
				PRINT1(IOCTL, "wlioctl_priv_wlparam: spectrum management disabled\n");
				rc = -EOPNOTSUPP;
				break;
			}
			if (!domainChannelValid(mib_SpectrumMagament_p->csaChannelNumber, FREQ_BAND_5GHZ)) {
				PRINT1(IOCTL, "wlioctl_priv_wlparam: wrong channel:%d\n", mib_SpectrumMagament_p->csaChannelNumber);
				rc = -EOPNOTSUPP;
				break;
			}
			if (priv->devid == SC5 || priv->devid == SCBT) {
				Dfs_ChanSwitchReq_t chanSwitch;

				/* Insert Channel Switch Announcement IE in the beacon/probe-response
				 * and initiate countdown process */
				memset(&chanSwitch, 0, sizeof(Dfs_ChanSwitchReq_t));
				chanSwitch.ChannelSwitchCmd.Mode = mib_SpectrumMagament_p->csaMode;
				chanSwitch.ChannelSwitchCmd.ChannelNumber = mib_SpectrumMagament_p->csaChannelNumber;
				chanSwitch.ChannelSwitchCmd.ChannelSwitchCount = mib_SpectrumMagament_p->csaCount;
				chanSwitch.chInfo.channel = mib_SpectrumMagament_p->csaChannelNumber;
				macMgmtMlme_SendChannelSwitchCmd(dev, &chanSwitch);
			} else {
				Dfs_ChanSwitchReq_t chanSwitch;

				chanSwitch.ChannelSwitchCmd.Mode = mib_SpectrumMagament_p->csaMode;
				chanSwitch.ChannelSwitchCmd.ChannelNumber = mib_SpectrumMagament_p->csaChannelNumber;
				chanSwitch.ChannelSwitchCmd.ChannelSwitchCount = mib_SpectrumMagament_p->csaCount;

				/* Send Channel Switch Command to all the AP virtual interfaces */
				for (i = 0; i <= bss_num; i++) {
					if (priv->vdev[i] && priv->vdev[i]->flags & IFF_RUNNING) {
						struct net_device *vdev = priv->vdev[i];
						struct wlprivate *vpriv = NETDEV_PRIV_P(struct wlprivate, vdev);
						SendChannelSwitchCmd(vpriv->vmacSta_p, &chanSwitch);
					}
				}
			}

		}
		break;

	case WL_PARAM_SPECTRUM_MGMT:
		{
			if (value < 0 || value > 2) {
				rc = -EINVAL;
				break;
			}
			mib_SpectrumMagament_p->spectrumManagement = value;
			mib->StationConfig->SpectrumManagementRequired = value ? TRUE : FALSE;
			/* If spectrum management is enabled, set power constraint and
			 * country info.
			 */
			if (value) {
				mib_SpectrumMagament_p->multiDomainCapability = 1;
			}
		}
		break;

	case WL_PARAM_POWER_CONSTRAINT:
		{
			if (value < 0 || value > 30) {
				rc = -EINVAL;
				break;
			}
			if (PhyDSSSTable->Chanflag.FreqBand != FREQ_BAND_5GHZ
#ifdef IEEE80211K
			    && !*(mib->mib_rrm)
#endif
			    ) {
				PRINT1(IOCTL, "wlioctl_priv_wlparam: wrong Freq band :%d\n", PhyDSSSTable->Chanflag.FreqBand);
				rc = -EOPNOTSUPP;
				break;
			}
			mib_SpectrumMagament_p->powerConstraint = value;
		}
		break;

	case WL_PARAM_11D_MODE:
		{
			if (value < 0 || value > 2) {
				rc = -EINVAL;
				break;
			}
			mib_SpectrumMagament_p->multiDomainCapability = value;
		}
		break;
#ifdef CLIENT_SUPPORT
	case WL_PARAM_11H_STA_MODE:
		{
			vmacEntry_t *vmacEntry_p = NULL;
			STA_SYSTEM_MIBS *pStaSystemMibs;

			if (value < 0 || value > 1) {
				rc = -EINVAL;
				break;
			}
			if ((vmacEntry_p = sme_GetParentVMacEntry(vmacSta_p->VMacEntry.phyHwMacIndx)) == NULL) {
				rc = -EFAULT;
				break;
			}
			pStaSystemMibs = sme_GetStaSystemMibsPtr(vmacEntry_p);
			if (pStaSystemMibs == NULL) {
				rc = -EFAULT;
				break;
			}
			pStaSystemMibs->mib_StaCfg_p->sta11hMode = value;
		}
		break;
#endif				//CLIENT_SUPPORT
#ifdef MRVL_DFS
		/* This code is for simulating a radar generation
		 * to validate the DFS SM logic
		 */
	case WL_PARAM_11HCACTIMEOUT:
		{
			if (value < 5 || value > 60) {
				rc = -EINVAL;
				break;
			}
			*(mib->mib_CACTimeOut) = value;
		}
		break;
	case WL_PARAM_11HETSICACTIMEOUT:
		{
			*(mib->mib_ETSICACTimeOut) = value;
		}
		break;

	case WL_PARAM_11hNOPTIMEOUT:
		{
			if (value < 5 || value > 1800) {
				rc = -EINVAL;
				break;
			}
			*(mib->mib_NOPTimeOut) = value;
		}
		break;
#endif				// MRVL_DFS

	case WL_PARAM_PSHT_MANAGEMENTACT:
		{
			extern BOOLEAN macMgmtMlme_SendMimoPsHtManagementAction(vmacApInfo_t * vmacSta_p, IEEEtypes_MacAddr_t * Addr, UINT8 mode);
			extern int wlFwSetMimoPsHt(struct net_device *netdev, UINT8 * addr, UINT8 enable, UINT8 mode);
			UINT8 addr[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
			UINT8 i;
			UINT32 entries;
			UINT8 *staBuf = NULL;
			UINT8 *listBuf = NULL;
			extStaDb_StaInfo_t *pStaInfo;

			switch (value) {
			case 0:
			case 1:
			case 3:
				*(mib->mib_psHtManagementAct) = (UINT8) value;
				if (macMgmtMlme_SendMimoPsHtManagementAction(vmacSta_p, (IEEEtypes_MacAddr_t *) & addr, *(mib->mib_psHtManagementAct))
				    == TRUE) {
					entries = extStaDb_entries(vmacSta_p, 0);
					staBuf = wl_kmalloc(entries * sizeof(STA_INFO), GFP_KERNEL);
					if (staBuf != NULL) {
						extStaDb_list(vmacSta_p, staBuf, 1);

						if (entries) {
							listBuf = staBuf;
							for (i = 0; i < entries; i++) {
								if ((pStaInfo =
								     extStaDb_GetStaInfo(vmacSta_p, (IEEEtypes_MacAddr_t *) listBuf,
											 STADB_DONT_UPDATE_AGINGTIME)) != NULL) {
									if ((pStaInfo->State == ASSOCIATED) && (pStaInfo->ClientMode == NONLY_MODE)) {
										UINT8 enable = 1;
										UINT8 mode = *(mib->mib_psHtManagementAct);

										if (mode == 3) {
											enable = 0;
											mode = 0;
										}
										wlFwSetMimoPsHt(dev, listBuf, enable, mode);
									}
									listBuf += sizeof(STA_INFO);
								}
							}
						}
					}
					wl_kfree(staBuf);
				}
				break;
			default:
				rc = -EINVAL;
				break;
			}
		}
		break;
	case WL_PARAM_AMPDU_TX:
		{
			switch (value) {
			case 0:
			case 1:
			case 2:
			case 3:
#ifndef AMPDU_SUPPORT_TX_CLIENT
				if (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_CLNT_INFRA)
					*(mib->mib_AmpduTx) = 0;
				else
#endif
					*(mib->mib_AmpduTx) = (UINT8) value;
				if (*(mib->mib_AmpduTx)) {
					*(mib->pMib_11nAggrMode) |= WL_MODE_AMPDU_TX;
				} else {
					*(mib->pMib_11nAggrMode) &= ~WL_MODE_AMPDU_TX;
				}
				break;
			default:
				rc = -EINVAL;
				break;
			}
		}
		break;
#ifdef SOC_W906X
	case WL_PARAM_AMPDUWINDOWLIMIT:
		{
			vmacSta_p->ampduWindowSizeCap = value;
		}
		break;
	case WL_PARAM_AMPDUBYTESLIMIT:
		{
			vmacSta_p->ampduBytesCap = value;
		}
		break;
	case WL_PARAM_AMPDUDENSITYLIMIT:
		{
			vmacSta_p->ampduDensityCap = value;
		}
		break;
#endif
	case WL_PARAM_TXQLIMIT:
		{
			vmacSta_p->txQLimit = value;
		}
		break;
	case WL_PARAM_RXINTLIMIT:
		{
			vmacSta_p->work_to_do = value;
		}
		break;
#if defined ( INTOLERANT40) || defined (COEXIST_20_40_SUPPORT)

	case WL_PARAM_INTOLERANT:
		{
			if (value < 0 || value > 1)
				rc = -EINVAL;

			*(mib->mib_HT40MIntoler) = (UINT8) value;
		}
		break;
#endif
#ifdef CLIENT_SUPPORT
	case WL_PARAM_STAMODE:
		{
			vmacEntry_t *vmacEntry_p = NULL;
			struct net_device *staDev = NULL;
			struct wlprivate *stapriv = NULL;
			vmacApInfo_t *vmacSta_p = NULL;
			if (value < 0) {
				rc = -EOPNOTSUPP;
				break;
			}
			*(mib->mib_STAMode) = (UCHAR) value;
			if ((vmacEntry_p = sme_GetParentVMacEntry(((vmacApInfo_t *) priv->vmacSta_p)->VMacEntry.phyHwMacIndx)) != NULL) {
				staDev = (struct net_device *)vmacEntry_p->privInfo_p;
				stapriv = NETDEV_PRIV_P(struct wlprivate, staDev);
				vmacSta_p = stapriv->vmacSta_p;
				wlset_mibChannel(vmacEntry_p, *(mib->mib_STAMode));
			}
		}
		break;
#endif
#ifdef CLIENT_SUPPORT
	case WL_PARAM_STA_AUTO_SCAN:
		{
			if ((value != 0) && (value != 1)) {
				rc = -EOPNOTSUPP;
				break;
			}
			*(mib->mib_STAAutoScan) = (UCHAR) value;
		}
		break;
	case WL_PARAM_STASCAN:
		{
			UINT8 bcAddr1[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };	/* BROADCAST BSSID */
			UINT8 ieBuf[2 + IEEE_80211_MAX_NUMBER_OF_CHANNELS];
			UINT16 ieBufLen = 0;
			IEEEtypes_InfoElementHdr_t *IE_p;
			vmacEntry_t *vmacEntry_p = NULL;
			struct net_device *staDev = NULL;
			struct wlprivate *stapriv = NULL;
			vmacApInfo_t *vmacSta_p = NULL;
			MIB_802DOT11 *mib = NULL;
			UINT8 mlmeAssociatedFlag;
			UINT8 mlmeBssid[6];
			UINT8 currChnlIndex = 0;
			UINT8 chnlListLen = 0;
			UINT8 chnlScanList[IEEEtypes_MAX_CHANNELS + IEEEtypes_MAX_CHANNELS_A];
			UINT8 i = 0;
			MIB_PHY_DSSS_TABLE *PhyDSSSTable;
			UINT8 mainChnlList[IEEEtypes_MAX_CHANNELS + IEEEtypes_MAX_CHANNELS_A];
			struct iw_point *srq;
			struct iw_scan_req req;
#ifdef AP_SCAN_SUPPORT
			int clientDisable = 0;
#endif
			if (value != 1) {
				rc = -EINVAL;
				break;
			}

			vmacEntry_p = sme_GetParentVMacEntry(((vmacApInfo_t *) priv->vmacSta_p)->VMacEntry.phyHwMacIndx);
			if (vmacEntry_p == NULL) {
				rc = -EFAULT;
				break;
			}
			staDev = (struct net_device *)vmacEntry_p->privInfo_p;
			stapriv = NETDEV_PRIV_P(struct wlprivate, staDev);
			vmacSta_p = stapriv->vmacSta_p;
			mib = vmacSta_p->Mib802dot11;
			//when this command issued on AP mode, system would crash because of no STA interface
			//so the following checking is necessary.
#ifdef AP_SCAN_SUPPORT
			if (*(mib->mib_STAMode) == CLIENT_MODE_DISABLE) {
				*(mib->mib_STAMode) = CLIENT_MODE_AUTO;
				clientDisable = 1;
			}
#else
			if (*(mib->mib_STAMode) == CLIENT_MODE_DISABLE) {
				rc = -EOPNOTSUPP;
				break;
			}
#endif

			memset(&mainChnlList[0], 0, (IEEEtypes_MAX_CHANNELS + IEEEtypes_MAX_CHANNELS_A));
			memset(&chnlScanList[0], 0, (IEEEtypes_MAX_CHANNELS + IEEEtypes_MAX_CHANNELS_A));

			PhyDSSSTable = mib->PhyDSSSTable;

			/* Stop Autochannel on AP first */
			if (priv->master) {
				struct wlprivate *wlMPrvPtr = NETDEV_PRIV_P(struct wlprivate, priv->master);
				StopAutoChannel(wlMPrvPtr->vmacSta_p);
			}
			/* get range to scan */
			domainGetInfo(mainChnlList);

			if ((*(vmacSta_p->Mib802dot11->mib_STAMode) == CLIENT_MODE_AUTO) || (*(vmacSta_p->Mib802dot11->mib_STAMode) == CLIENT_MODE_N)) {
				for (i = 0; i < IEEEtypes_MAX_CHANNELS; i++) {
					if (mainChnlList[i] > 0) {
						chnlScanList[currChnlIndex] = mainChnlList[i];
						currChnlIndex++;
					}
				}

				for (i = 0; i < IEEEtypes_MAX_CHANNELS_A; i++) {
					if (mainChnlList[i + IEEEtypes_MAX_CHANNELS] > 0) {
						chnlScanList[currChnlIndex] = mainChnlList[i + IEEEtypes_MAX_CHANNELS];
						currChnlIndex++;
					}
				}
				chnlListLen = currChnlIndex;
			} else if (*(vmacSta_p->Mib802dot11->mib_STAMode) == CLIENT_MODE_N_24) {
				for (i = 0; i < IEEEtypes_MAX_CHANNELS; i++) {
					chnlScanList[i] = mainChnlList[i];
				}
				chnlScanList[i] = 0;
				chnlListLen = IEEEtypes_MAX_CHANNELS;
			} else if (*(vmacSta_p->Mib802dot11->mib_STAMode) == CLIENT_MODE_N_5) {
				for (i = 0; i < IEEEtypes_MAX_CHANNELS_A; i++) {
					chnlScanList[i] = mainChnlList[i + IEEEtypes_MAX_CHANNELS];
				}
				chnlScanList[i] = 0;
				chnlListLen = IEEEtypes_MAX_CHANNELS_A;
			}
#ifdef AP_SCAN_SUPPORT
			if (clientDisable)
				*(mib->mib_STAMode) = CLIENT_MODE_DISABLE;
#endif
			ieBufLen = 0;
			/* Build IE Buf */
			IE_p = (IEEEtypes_InfoElementHdr_t *) & ieBuf[ieBufLen];

			/* SSID element */
			/* For scan all SSIDs to be scanned */

			/* DS_PARAM_SET element */
			IE_p->ElementId = DS_PARAM_SET;
			IE_p->Len = chnlListLen;
			ieBufLen += sizeof(IEEEtypes_InfoElementHdr_t);
			memcpy((char *)&ieBuf[ieBufLen], &chnlScanList[0], chnlListLen);

			ieBufLen += IE_p->Len;
			IE_p = (IEEEtypes_InfoElementHdr_t *) & ieBuf[ieBufLen];

			if ((vmacEntry_p = sme_GetParentVMacEntry(((vmacApInfo_t *) priv->vmacSta_p)->VMacEntry.phyHwMacIndx)) == NULL) {
				rc = -EFAULT;
				break;
			}

			if (!smeGetStaLinkInfo(vmacEntry_p->id, &mlmeAssociatedFlag, &mlmeBssid[0])) {
				rc = -EFAULT;
				break;
			}

			/* Set a flag indicating usr initiated scan */
			vmacSta_p->gUserInitScan = TRUE;

			if (!mlmeAssociatedFlag && (staDev->flags & IFF_RUNNING)) {
				//printk("stopping BSS \n");
				linkMgtStop(vmacEntry_p->phyHwMacIndx);
				smeStopBss(vmacEntry_p->phyHwMacIndx);
			}

			srq = (struct iw_point *)wrqu;
			if ((srq != NULL) && (srq->length == sizeof(struct iw_scan_req))) {
				if (copy_from_user(&req, srq->pointer, sizeof(struct iw_scan_req))) {
					rc = -EINVAL;
					break;
				}

				if (srq->flags == IW_SCAN_THIS_ESSID) {
					if (req.essid_len > 0) {
						IE_p->ElementId = SSID;
						IE_p->Len = req.essid_len;
						ieBufLen += sizeof(IEEEtypes_InfoElementHdr_t);
						memcpy((char *)&ieBuf[ieBufLen], req.essid, req.essid_len);

						ieBufLen += IE_p->Len;
						IE_p = (IEEEtypes_InfoElementHdr_t *) & ieBuf[ieBufLen];
					}
				}

				if (memcmp((char *)&req.bssid.sa_data[0], bcAddr1, sizeof(IEEEtypes_MacAddr_t))) {
					memcpy((char *)&bcAddr1[0], (char *)&req.bssid.sa_data, sizeof(IEEEtypes_MacAddr_t));
				}
			}
			if (smeSendScanRequest(vmacEntry_p->phyHwMacIndx, 0, 3, 200, &bcAddr1[0], &ieBuf[0], ieBufLen) == MLME_SUCCESS) {
				/*set the busy scanning flag */
				vmacSta_p->busyScanning = 1;
				break;
			} else {
				/* Reset a flag indicating usr initiated scan */
				vmacSta_p->gUserInitScan = FALSE;
				rc = -EALREADY;
				break;
			}
		}
		break;
#endif
#ifdef MPRXY
	case WL_PARAM_MCASTPRXY:
		{
			if (value < 0 || value > 1) {
				rc = -EOPNOTSUPP;
				break;
			}
			*(mib->mib_MCastPrxy) = (UCHAR) value;

			/*mcast proxy is turned on */
			if (*(mib->mib_MCastPrxy)) {
				/*If mib is same as default,  use 10 to set limit */
				if (*(mib->mib_consectxfaillimit) == CONSECTXFAILLIMIT) {
					*(mib->mib_consectxfaillimit) = _CONSECTXFAILLIMIT;
					wlFwSetConsecTxFailLimit(dev, _CONSECTXFAILLIMIT);
				}

			} else {	/*Set back to default value */
				if (*(mib->mib_consectxfaillimit) == _CONSECTXFAILLIMIT) {
					*(mib->mib_consectxfaillimit) = CONSECTXFAILLIMIT;
					wlFwSetConsecTxFailLimit(dev, CONSECTXFAILLIMIT);
				}
			}
		}
		break;
#endif
#ifdef RXPATHOPT
	case WL_PARAM_RXPATHOPT:
		if (value < 0 || value > 1500) {
			rc = -EOPNOTSUPP;
			break;
		}
		*(mib->mib_RxPathOpt) = value;
		break;
#endif
	case WL_PARAM_HTGF:
		if (value < 0 || value > 1) {
			rc = -EOPNOTSUPP;
			break;
		}
		*(mib->mib_HtGreenField) = value;
		break;

	case WL_PARAM_HTSTBC:
		if (value < 0 || value > 1) {
			rc = -EOPNOTSUPP;
			break;
		}
		*(mib->mib_HtStbc) = value;
		break;

	case WL_PARAM_3X3RATE:
		if (value < 0 || value > 1) {
			rc = -EOPNOTSUPP;
			break;
		}
		*(mib->mib_3x3Rate) = value;
		break;
	case WL_PARAM_AMSDU_FLUSHTIME:
		*(mib->mib_amsdu_flushtime) = value;
		break;
	case WL_PARAM_AMSDU_MAXSIZE:
		*(mib->mib_amsdu_maxsize) = value;
		break;
	case WL_PARAM_AMSDU_ALLOWSIZE:
		*(mib->mib_amsdu_allowsize) = value;
		break;
	case WL_PARAM_AMSDU_PKTCNT:
		*(mib->mib_amsdu_pktcnt) = value;
		break;
#ifdef IEEE80211K
	case WL_PARAM_RRM_EN:
		if (*(mib->mib_rrm) != value) {
			*(mib->mib_rrm) = value;
			vmacSta_p->rrm_cload.started = 0;
			MSAN_rrm_ie(dev, value);
		}
		break;
#endif

	case WL_PARAM_OFF_CHANNEL_REQ_SEND:
		{
			DOT11_OFFCHAN_REQ_t offchan_req;

			if (pvalue == NULL) {
				rc = -EINVAL;
				break;
			}
			memset(&offchan_req, 0x00, sizeof(DOT11_OFFCHAN_REQ_t));
			if (copy_from_user((char *)&offchan_req, pvalue, sizeof(DOT11_OFFCHAN_REQ_t))) {
				rc = -EINVAL;
				break;
			}
			offchan_req.id = OFFCHAN_GET_ID_FROM_FEATURE(OFFCHAN_BY_CMD, offchan_req.id);

			if (offchan_req.req_type == OFF_CHAN_REQ_TYPE_RX || offchan_req.req_type == OFF_CHAN_REQ_TYPE_TX ||
			    offchan_req.req_type == OFF_CHAN_REQ_TYPE_SENSORD) {
				if (wlFwNewDP_queue_OffChan_req(dev, &offchan_req) == FAIL) {
					rc = -EINVAL;
					break;
				}
			} else {
				printk("invalid req type \n");
				rc = -EINVAL;
			}
			break;
		}

	case WL_PARAM_CONFIG_PROMISCUOUS:
		{
			PROM_CNF_t PromCnf;

			if (pvalue == NULL) {
				rc = -EINVAL;
				break;
			}
			memset(&PromCnf, 0x00, sizeof(PROM_CNF_t));
			if (copy_from_user((char *)&PromCnf, pvalue, sizeof(PROM_CNF_t))) {
				rc = -EINVAL;
				break;
			}

			wlFwNewDP_config_prom(dev, &PromCnf);
			break;
		}

	case WL_PARAM_PEEK_ACNT_RECDS:
		{
			headTailInfo_t headtail;

			if (pvalue == NULL) {
				rc = -EINVAL;
				break;
			}

			wlAcntPeekRecds(dev, &headtail.head, &headtail.tail);
			if (copy_to_user(pvalue, &headtail, sizeof(headTailInfo_t))) {
				rc = -EFAULT;
				break;
			}

			break;
		}

	case WL_PARAM_READ_ACNT_RECDS:
		{
			readRecdsInfo_t rdRecdsInfo;

			if (pvalue == NULL) {
				rc = -EINVAL;
				break;
			}
			memset(&rdRecdsInfo, 0x00, sizeof(readRecdsInfo_t));
			if (copy_from_user((char *)&rdRecdsInfo, pvalue, sizeof(readRecdsInfo_t))) {
				rc = -EINVAL;
				break;
			}
			wlAcntReadRecds(dev, rdRecdsInfo.tail, rdRecdsInfo.pBuf, &rdRecdsInfo.bufSize);

			if (copy_to_user(pvalue, &rdRecdsInfo, sizeof(readRecdsInfo_t))) {
				rc = -EFAULT;
				break;
			}
			break;
		}
	case WL_PARAM_SET_ACNT_TAIL:
		{

			u32 newtail;
#ifdef SOC_W906X
			unsigned int reg_acnt_tail = priv->wlpd_p->reg.acnt_tail;
#else
			unsigned int reg_acnt_tail = MACREG_REG_AcntTail;
#endif
			if (pvalue == NULL) {
				rc = -EINVAL;
				break;
			}
			if (copy_from_user((char *)&newtail, pvalue, sizeof(u32))) {
				rc = -EINVAL;
				break;
			}
			writel(newtail, priv->ioBase1 + reg_acnt_tail);

			break;
		}

	case WL_PARAM_SET_ACNT_BUF_SIZE:
		{
#if defined(SOC_W906X) || defined(NEWDP_ACNT_CHUNKS)
			SetAcntBufInfo_t SetInfo;

			if (pvalue == NULL) {
				rc = -EINVAL;
				break;
			}
			if (copy_from_user((char *)&SetInfo, pvalue, sizeof(SetAcntBufInfo_t))) {
				rc = -EINVAL;
				break;
			}

			if (wlAcntSetBufSize(dev, &SetInfo) == 0) {
				rc = -EINVAL;
				break;
			}
#else
			u32 BufSize;

			if (pvalue == NULL) {
				rc = -EINVAL;
				break;
			}
			if (copy_from_user((char *)&BufSize, pvalue, sizeof(u32))) {
				rc = -EINVAL;
				break;
			}

			if (wlAcntSetBufSize(dev, BufSize) == 0) {
				rc = -EINVAL;
				break;
			}
#endif
			break;
		}
	case WL_PARAM_GET_ACNT_BUF_SIZE:
		{
			if (pvalue == NULL) {
				rc = -EINVAL;
				break;
			}

			if (copy_to_user(pvalue, &priv->wlpd_p->descData[0].AcntRingSize, sizeof(u32))) {
				rc = -EFAULT;
				break;
			}

			break;
		}
#if defined(SOC_W906X) || defined(NEWDP_ACNT_CHUNKS)
	case WL_PARAM_GET_ACNT_CHUNK_INFO:
		{
			if (pvalue == NULL) {
				rc = -EINVAL;
				break;
			}

			if (copy_to_user(pvalue, &priv->wlpd_p->AcntChunkInfo, sizeof(acnt_chunk_info_t))) {
				rc = -EFAULT;
				break;
			}

			break;
		}
#endif
	case WL_PARAM_SENSORD_INIT:
		{
			sensord_init_t sensordinit;

			if (pvalue == NULL) {
				rc = -EINVAL;
				break;
			}
			memset(&sensordinit, 0x00, sizeof(sensord_init_t));
			if (copy_from_user((char *)&sensordinit, pvalue, sizeof(sensord_init_t))) {
				rc = -EINVAL;
				break;
			}

			wlFwNewDP_sensorD_init(dev, &sensordinit, 1);
			break;
		}
	case WL_PARAM_SENSORD_CMD:
		{

			wlFwNewDP_sensorD_cmd(dev);
			break;
		}
	case WL_PARAM_RADIO_STATUS:
		{
			radio_status_t *pRadioStatus;

			if (pvalue == NULL || priv->wlpd_p->MrvlPriSharedMem.data == NULL) {
				rc = -EINVAL;
				break;
			}

			pRadioStatus = (radio_status_t *) & ((drv_fw_shared_t *) priv->wlpd_p->MrvlPriSharedMem.data)->RadioStatus;
			if (copy_to_user(pvalue, pRadioStatus, sizeof(radio_status_t))) {
				rc = -EFAULT;
				break;
			}
			break;
		}
	case WL_PARAM_SENSORD_SET_BLANKING:
		{
			u8 blankingmask;

			if (pvalue == NULL) {
				rc = -EINVAL;
				break;
			}
			if (copy_from_user((char *)&blankingmask, pvalue, sizeof(u8))) {
				rc = -EINVAL;
				break;
			}

			wlFwNewDP_sensord_set_blanking(dev, &blankingmask);
			break;
		}
	case WL_PARAM_DFS_DETECT:
		{
			u32 dfs_freg;

			if (pvalue == NULL || priv->wlpd_p->MrvlPriSharedMem.data == NULL) {
				rc = -EINVAL;
				break;
			}
			dfs_freg = ((drv_fw_shared_t *) priv->wlpd_p->MrvlPriSharedMem.data)->dfs_freg;
			if (copy_to_user(pvalue, &dfs_freg, sizeof(u32))) {
				rc = -EFAULT;
				break;
			}
			break;
		}

	case WL_PARAM_BFMR_SBF_OPEN:
		{
			wlcfg_sbf_open_t sbfOpen;

			if (pvalue == NULL) {
				rc = -EINVAL;
				break;
			}
			if (copy_from_user((char *)&sbfOpen, pvalue, sizeof(wlcfg_sbf_open_t))) {
				rc = -EINVAL;
				break;
			}
			wlFwNewDP_bfmr_sbf_open(dev, &sbfOpen);
			break;
		}
#ifdef SOC_W906X
	case WL_PARAM_FW_GETCORE_DUMP:
		{
#if 0				//To be implemented, can use wldebug.c method for now
			coredump_cmd_t *core_dump = NULL;
			char *buff = NULL;

			do {
				core_dump = (coredump_cmd_t *) wl_kmalloc(sizeof(coredump_cmd_t), GFP_ATOMIC);
				if (!core_dump) {
					printk(KERN_ERR "Error[%s:%d]: Allocating F/W Core Dump Memory \n", __func__, __LINE__);
					rc = -ENOMEM;
					break;
				}

				buff = (char *)wl_kmalloc(MAX_CORE_DUMP_BUFFER, GFP_ATOMIC);
				if (!buff) {
					printk(KERN_ERR "Error: Allocating F/W Buffer for Core Dump \n", __func__, __LINE__);
					rc = -ENOMEM;
					break;
				}

				/*Copy Core Dump Command From User Space */
				if (copy_from_user((char *)core_dump, (char *)value, sizeof(coredump_cmd_t))) {
					rc = -ENOMEM;
					break;
				}
				memset((char *)buff, 0, MAX_CORE_DUMP_BUFFER);
				/*Get Core Dump From F/W */
				if (wlFwGetCoreDump(dev, core_dump, buff) == FAIL) {
					rc = -EINVAL;
					break;
				}
				/*Copy Core Dump Buffer to User Space, Which copies to a file in Flash */
				if (copy_to_user((char *)core_dump->buffer, (char *)buff, MAX_CORE_DUMP_BUFFER)) {
					rc = -ENOMEM;
					break;
				}
				/*Copy Core Dump Command to User Space */
				if (copy_to_user((char *)value, (char *)core_dump, sizeof(coredump_cmd_t))) {
					rc = -ENOMEM;
					break;
				}
			} while (0);

			if (buff)
				wl_kfree(buff);

			if (core_dump)
				wl_kfree(core_dump);
#endif
			break;
		}
	case WL_PARAM_FW_CREATE_CORE:
		{
			UINT16 status;
			status = 1;
			wlFwDiagMode(dev, status);
			break;
		}
#endif
	case WL_PARAM_BFMR_SBF_CLOSE:
		{
			wlcfg_sbf_close_t sbfClose;

			if (pvalue == NULL) {
				rc = -EINVAL;
				break;
			}
			if (copy_from_user((char *)&sbfClose, pvalue, sizeof(wlcfg_sbf_close_t))) {
				rc = -EINVAL;
				break;
			}
			wlFwNewDP_bfmr_sbf_close(dev, &sbfClose);
			break;
		}
	case WL_PARAM_SET_POWER_PER_RATE:
		{
			Info_rate_power_table_t *pInfo;

			pInfo = (Info_rate_power_table_t *) priv->wlpd_p->descData[0].pInfoPwrTbl;
			if (pvalue == NULL) {
				rc = -EINVAL;
				break;
			}
			if (pInfo->DrvCnt != pInfo->FwCnt) {
				rc = -EAGAIN;
				break;
			} else {
				if (copy_from_user((char *)&pInfo->RatePwrTbl, pvalue, sizeof(rate_power_table_t))) {
					rc = -EINVAL;
					break;
				}
				printk("channel =%d, NumberOfEntry =%d \n", pInfo->RatePwrTbl.channel, pInfo->RatePwrTbl.NumOfEntry);
				if (pInfo->DrvCnt == 0xFFFFFFFF) {
					pInfo->DrvCnt = 0;
				} else {
					pInfo->DrvCnt += 1;
				}
			}
#ifdef SOC_W906X
			if (SUCCESS == wlFwSetPowerPerRate(dev))
				pInfo->FwCnt += 1;
			else {
				printk("Load power table fail...\n");
				rc = -EAGAIN;
				break;
			}
			//printk("%s:pInfo->FwCnt:%u\n",__func__, pInfo->FwCnt);
#else
			wlFwSetPowerPerRate(dev);
#endif

			switch (pInfo->RatePwrTbl.channel) {
			case 1:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[0].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[0].channel = 1;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[0].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 2:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[1].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[1].channel = 2;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[1].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 3:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[2].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[2].channel = 3;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[2].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 4:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[3].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[3].channel = 4;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[3].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 5:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[4].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[4].channel = 5;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[4].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 6:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[5].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[5].channel = 6;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[5].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 7:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[6].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[6].channel = 7;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[6].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 8:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[7].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[7].channel = 8;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[7].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 9:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[8].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[8].channel = 9;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[8].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 10:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[9].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[9].channel = 10;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[9].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 11:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[10].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[10].channel = 11;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[10].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 12:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[11].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[11].channel = 12;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[11].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 13:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[12].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[12].channel = 13;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[12].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 14:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[13].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[13].channel = 14;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[13].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
				/* for 5G */
#ifdef SOC_W906X
			case 36:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[14].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[14].channel = 36;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[14].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 40:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[15].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[15].channel = 40;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[15].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 44:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[16].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[16].channel = 44;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[16].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 48:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[17].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[17].channel = 48;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[17].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 52:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[18].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[18].channel = 52;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[18].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 56:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[19].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[19].channel = 56;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[19].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 60:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[20].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[20].channel = 60;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[20].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 64:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[21].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[21].channel = 64;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[21].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 100:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[22].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[22].channel = 100;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[22].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 104:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[23].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[23].channel = 104;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[23].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 108:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[24].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[24].channel = 108;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[24].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 112:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[25].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[25].channel = 112;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[25].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 116:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[26].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[26].channel = 116;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[26].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 120:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[27].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[27].channel = 120;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[27].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 124:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[28].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[28].channel = 124;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[28].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 128:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[29].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[29].channel = 128;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[29].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 132:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[30].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[30].channel = 132;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[30].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 136:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[31].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[31].channel = 136;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[31].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 140:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[32].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[32].channel = 140;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[32].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 144:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[33].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[33].channel = 144;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[33].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 149:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[34].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[34].channel = 149;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[34].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 153:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[35].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[35].channel = 153;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[35].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 157:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[36].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[36].channel = 157;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[36].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 161:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[37].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[37].channel = 161;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[37].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 165:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[38].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[38].channel = 165;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[38].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 169:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[39].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[39].channel = 169;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[39].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 173:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[40].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[40].channel = 173;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[40].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 177:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[41].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[41].channel = 177;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[41].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 181:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[42].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[42].channel = 181;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[42].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
#else
			case 16:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[14].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[14].channel = 16;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[14].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 36:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[15].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[15].channel = 36;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[15].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 40:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[16].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[16].channel = 40;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[16].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 44:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[17].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[17].channel = 44;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[17].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 48:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[18].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[18].channel = 48;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[18].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 52:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[19].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[19].channel = 52;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[19].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 56:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[20].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[20].channel = 56;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[20].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 60:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[21].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[21].channel = 60;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[21].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 64:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[22].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[22].channel = 64;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[22].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 68:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[23].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[23].channel = 68;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[23].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 72:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[24].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[24].channel = 72;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[24].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 76:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[25].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[25].channel = 76;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[25].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 80:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[26].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[26].channel = 80;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[26].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 84:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[27].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[27].channel = 84;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[27].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 88:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[28].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[28].channel = 88;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[28].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 92:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[29].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[29].channel = 92;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[29].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 96:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[30].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[30].channel = 96;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[30].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 100:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[31].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[31].channel = 100;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[31].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 104:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[32].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[32].channel = 104;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[32].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 108:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[33].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[33].channel = 108;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[33].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 112:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[34].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[34].channel = 112;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[34].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 116:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[35].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[35].channel = 116;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[35].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 120:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[36].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[36].channel = 120;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[36].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 124:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[37].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[37].channel = 124;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[37].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 128:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[38].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[38].channel = 128;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[38].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 132:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[39].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[39].channel = 132;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[39].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 136:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[40].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[40].channel = 136;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[40].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 140:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[41].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[41].channel = 140;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[41].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 144:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[42].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[42].channel = 144;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[42].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 149:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[43].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[43].channel = 149;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[43].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 153:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[44].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[44].channel = 153;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[44].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 157:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[45].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[45].channel = 157;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[45].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 161:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[46].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[46].channel = 161;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[46].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 165:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[47].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[47].channel = 165;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[47].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 169:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[48].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[48].channel = 169;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[48].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 173:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[49].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[49].channel = 173;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[49].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 177:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[50].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[50].channel = 177;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[50].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 181:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[51].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[51].channel = 181;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[51].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 183:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[52].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[52].channel = 183;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[52].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 184:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[53].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[53].channel = 184;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[53].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 185:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[54].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[54].channel = 185;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[54].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 186:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[55].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[55].channel = 186;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[55].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 187:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[56].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[56].channel = 187;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[56].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 188:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[57].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[57].channel = 188;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[57].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 189:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[58].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[58].channel = 189;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[58].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 192:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[59].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[59].channel = 192;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[59].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 194:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[60].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[60].channel = 194;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[60].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 196:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[61].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[61].channel = 196;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[61].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 201:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[62].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[62].channel = 201;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[62].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 202:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[63].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[63].channel = 202;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[63].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 203:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[64].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[64].channel = 203;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[64].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 204:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[65].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[65].channel = 204;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[65].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 205:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[66].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[66].channel = 205;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[66].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 206:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[67].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[67].channel = 206;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[67].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 207:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[68].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[68].channel = 207;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[68].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 208:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[69].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[69].channel = 208;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[69].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 209:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[70].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[70].channel = 209;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[70].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 210:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[71].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[71].channel = 210;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[71].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 211:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[72].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[72].channel = 211;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[72].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 212:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[73].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[73].channel = 212;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[73].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 213:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[74].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[74].channel = 213;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[74].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 214:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[75].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[75].channel = 214;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[75].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 215:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[76].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[76].channel = 215;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[76].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 216:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[77].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[77].channel = 216;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[77].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 217:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[78].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[78].channel = 217;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[78].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 218:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[79].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[79].channel = 218;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[79].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 219:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[80].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[80].channel = 219;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[80].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 220:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[81].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[81].channel = 220;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[81].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 221:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[82].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[82].channel = 221;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[82].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 222:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[83].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[83].channel = 222;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[83].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 223:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[84].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[84].channel = 223;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[84].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 224:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[85].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[85].channel = 224;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[85].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 225:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[86].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[86].channel = 225;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[86].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
				break;
			case 226:
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[87].bValid = TRUE;
				priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[87].channel = 226;
				memcpy(&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[87].PerChanPwr, &pInfo->RatePwrTbl, sizeof(rate_power_table_t));
#endif
				break;
			default:
				break;
			}
			break;
		}
	case WL_PARAM_SET_SKU:
		{
			UINT32 sku;

			if (pvalue == NULL) {
				rc = -EINVAL;
				break;
			}
			if (copy_from_user((char *)&sku, pvalue, 4)) {
				rc = -EINVAL;
				break;
			}
			//printk(" driver sku = 0x%X \n", sku);
			wlFwNewDP_set_sku(dev, sku);
			break;
		}
	case WL_PARAM_SET_OFFCHPWR:
		{
			setoffchpwr_t setoffchpwr;

			if (pvalue == NULL) {
				rc = -EINVAL;
				break;
			}
			if (copy_from_user((char *)&setoffchpwr, pvalue, sizeof(setoffchpwr_t))) {
				rc = -EINVAL;
				break;
			}
			wlFwNewDP_Set_Offchanpwr(dev, setoffchpwr.Pwr, setoffchpwr.AntBitMap, setoffchpwr.Channel);

			break;
		}
#ifdef SOC_W906X
	case WL_PARAM_HE_LDPC:
		*(mib->mib_heldpc_enable) = value;
		break;

	case WL_PARAM_BSS_COLOR:
		if ((value >= 0) && (value < 64)) {
			mib->StationConfig->bss_color = value;
			if (value == 0)
				WLDBG_INFO(DBG_LEVEL_0, "random BSS color: %d. \n", mib->StationConfig->bss_color);
		} else {
			WLDBG_ERROR(DBG_LEVEL_0, "invalid BSS color. Should be 1~63 or 0. \n");
			rc = -EINVAL;
		}
		break;
	case WL_PARAM_MU_EDCA_EN:
		if (!priv->master) {
			printk("Error. Please enter vap interface instead\n");
			rc = -EOPNOTSUPP;
			break;
		}

		if ((value == 0) || (value == 1)) {
			if (vmacSta_p->VMacEntry.muedcaEnable != value) {
				vmacSta_p->VMacEntry.muedcaEnable = value;
				wlFwSetIEs(dev);
			}
		} else {
			WLDBG_ERROR(DBG_LEVEL_0, "Invalid MU WMM setting, should be 0 or 1. \n");
			rc = -EINVAL;
		}
		break;

	case WL_PARAM_HE_TWT_EN:
		if (!priv->master) {
			printk("Error. Please enter vap interface instead\n");
			rc = -EOPNOTSUPP;
			break;
		}

		if ((value == 0) || (value == 1)) {
			if (*mib->he_twt_activated != value) {
				*mib->he_twt_activated = value;
			}
		} else {
			WLDBG_ERROR(DBG_LEVEL_0, "Invalid TWT setting, should be 0 or 1. \n");
			rc = -EINVAL;
		}
		break;
	case WL_PARAM_WLS_FTM_EN:
#ifdef WLS_FTM_SUPPORT
		if ((value == 0) || (value == 1)) {
			*(mib->wls_ftm_enable) = value;
		} else {
			WLDBG_ERROR(DBG_LEVEL_0, "Invalid WLS setting, should be 0 or 1. \n");
			rc = -EINVAL;
		}
#else
		WLDBG_ERROR(DBG_LEVEL_0, "Cmd wls not supported\n");
		rc = -EINVAL;
#endif
		break;

	case WL_PARAM_HE_MUBF_EN:
		if (!priv->master) {
			printk("Error. Please enter vap interface instead\n");
			rc = -EOPNOTSUPP;
			break;
		}

		if ((value == 0) || (value == 1)) {
			if (*mib->he_mu_bf != value) {
				*mib->he_mu_bf = value;
			}
		} else {
			WLDBG_ERROR(DBG_LEVEL_0, "Invalid MU BF setting, should be 0 or 1. \n");
			rc = -EINVAL;
		}
		break;

	case WL_PARAM_HE_SUBF_EN:
		if (!priv->master) {
			printk("Error. Please enter vap interface instead\n");
			rc = -EOPNOTSUPP;
			break;
		}

		if ((value == 0) || (value == 1)) {
			if (*mib->he_su_bf != value) {
				*mib->he_su_bf = value;
			}
		} else {
			WLDBG_ERROR(DBG_LEVEL_0, "Invalid SU BF setting, should be 0 or 1. \n");
			rc = -EINVAL;
		}
		break;

#else
#ifdef BAND_STEERING
	case WL_PARAM_BANDSTEER:
		//*(mib->mib_bandsteer) = value;
		if (value == 1) {
			*(mib->mib_bandsteer) = value;
			*(mib->mib_bandsteer_handler) = BAND_STEERING_HDL_BY_HOST;
		} else {	//(value == 0)
			if ((*(mib->mib_bandsteer) == 0) ||
			    ((*(mib->mib_bandsteer) == 1) && (*(mib->mib_bandsteer_handler) == BAND_STEERING_HDL_BY_HOST))) {
				*(mib->mib_bandsteer) = value;
				*(mib->mib_bandsteer_handler) = BAND_STEERING_HDL_BY_DRV;
			}
		}
		break;
#endif
#ifdef DOT11V_DMS
	case WL_PARAM_DOT11V_DMS:
		if ((value == 0) || (value == 1))
			*(mib->mib_dms) = value;
		else {
			printk("dms input must be 0 or 1\n");
			rc = -EINVAL;
		}
		break;
#endif
	case WL_PARAM_RESET_RATE_MODE:
		if (value < 5) {
			*(mib->mib_reset_rate_mode) = value;
			if (wlFwSetResetRateMode(dev, *(mib->mib_reset_rate_mode))) {
				WLDBG_EXIT_INFO(DBG_LEVEL_1, "Failed setting WL_PARAM_RESET_RATE_MODE");
			}
		} else {
			printk("input value must be 0:RSSI, 1:force highest, 2:force mid, 3:force lowest \n");
			rc = -EINVAL;
		}
		break;
#endif
#if defined(WFA_TKIP_NEGATIVE) && defined(SOC_W906X)
	case WL_PARAM_HT_TKIP:
		if ((value == 0) || (value == 1))
			allow_ht_tkip = value;
		break;
#endif
	default:
		PRINT1(IOCTL, "%s: get_mp31ep_param: unknown param %d\n", dev->name, param);
		rc = -EOPNOTSUPP;
		break;

	}

	WLDBG_EXIT(DBG_LEVEL_1);

	return rc;
}

static int wlioctl_priv_get_wlparam(struct net_device *dev, struct iw_request_info *info, void *wrqu, char *extra)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, dev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	int *param = (int *)extra;
	int rc = 0;

#ifdef CLIENT_SUPPORT
	UINT8 AssociatedFlag = 0;
	UINT8 bssId[6];
	STA_SYSTEM_MIBS *pStaSystemMibs;
	vmacEntry_t *vmacEntry_p = NULL;
#endif				//CLIENT_SUPPORT
	MIB_PHY_DSSS_TABLE *PhyDSSSTable = mib->PhyDSSSTable;
	MIB_SPECTRUM_MGMT *mib_SpectrumMagament_p = mib->SpectrumMagament;
	struct wlprivate_data *wlpd_p = priv->wlpd_p;
	char logbuf[256];
	UINT32 size;

	WLDBG_ENTER(DBG_LEVEL_1);

	WLDBG_IOCTL(DBG_LEVEL_0, "%s:wlioctl_priv_get cmd:0x%x, CpuID:%u, PID:%i, ProcName:\"%s\"\n",
		    dev->name, *param, smp_processor_id(), current->pid, current->comm);

#ifdef SOC_W906X
	if (wlpd_p->smon.active) {
		UINT64 tsec, tms;

		convert_tscale(xxGetTimeStamp(), &tsec, &tms, NULL);
		size = (UINT32) sprintf(&logbuf[0], "[%llu.%llu]: %s:wlioctl_priv_get cmd:0x%x, CpuID:%u, PID:%i, ProcName:\"%s\"\n", tsec, tms,
					dev->name, *param, smp_processor_id(), current->pid, current->comm);
		wlmon_log_buffer(dev, logbuf, size);
	}
#endif				/* SOC_W906X */

	switch (*param) {
	case WL_PARAM_AUTHTYPE:
		*param = mib->AuthAlg->Type;
		break;

	case WL_PARAM_BAND:
#ifdef SOC_W906X
		*param = *(mib->mib_ApMode);
#else
		if (force_5G_channel) {
			*param = *(mib->mib_ApMode) + AP_MODE_4_9G_5G_PUBLIC_SAFETY;	// Set bit 5 to indicate that this is a 4.9G / 5G channel (forced)
		} else {
			*param = *(mib->mib_ApMode);
		}
#endif
		break;

	case WL_PARAM_REGIONCODE:
		// domainGetDomain returns the global value instead of the region code for a given adapter
		//*param = domainGetDomain();
		// Therefore change to:
		*param = *(mib->mib_regionCode);
		break;

	case WL_PARAM_HIDESSID:
		if (*(mib->mib_broadcastssid))
			*param = 0;
		else
			*param = 1;
		break;

	case WL_PARAM_PREAMBLE:
		switch (mib->StationConfig->mib_preAmble) {
		case PREAMBLE_AUTO_SELECT:
			*param = 0;
			break;
		case PREAMBLE_SHORT:
			*param = 1;
			break;
		case PREAMBLE_LONG:
			*param = 2;
			break;
		default:
			break;
		}
		break;

	case WL_PARAM_GPROTECT:
		if (*(mib->mib_forceProtectiondisable))
			*param = 0;
		else
			*param = 1;
		break;

	case WL_PARAM_BEACON:
		*param = (*(mib->mib_BcnPeriod));
		break;

	case WL_PARAM_DTIM:
		*param = mib->StationConfig->DtimPeriod;
		break;

	case WL_PARAM_FIXRATE:
		*param = *(mib->mib_enableFixedRateTx);
		break;

	case WL_PARAM_ANTENNA:
		*param = *(mib->mib_rxAntenna);
		break;

	case WL_PARAM_ANTENNATX:
		*param = *(mib->mib_txAntenna);
		break;

	case WL_PARAM_FILTER:
		*param = *mib->mib_wlanfiltertype;
		break;

	case WL_PARAM_WMM:
		*param = *(mib->QoSOptImpl);
		break;

	case WL_PARAM_WPAWPA2MODE:
		*param = *(mib->mib_wpaWpa2Mode);
		break;

#ifdef MRVL_WAPI
	case WL_PARAM_WAPIMODE:
		*param = mib->Privacy->WAPIEnabled;
		break;
#endif

	case WL_PARAM_GROUPREKEYTIME:
		*param = (mib->RSNConfig->GroupRekeyTime);
		break;

	case WL_PARAM_INTRABSS:
		*param = *(mib->mib_intraBSS);
		break;

	case WL_PARAM_AMSDU:
		*param = *(mib->pMib_11nAggrMode) & WL_MODE_AMSDU_TX_MASK;
		break;

	case WL_PARAM_HTBANDWIDTH:
		switch (PhyDSSSTable->Chanflag.ChnlWidth) {
		case CH_AUTO_WIDTH:
			*param = 0;
			break;
		case CH_10_MHz_WIDTH:
			*param = 1;
			break;
		case CH_20_MHz_WIDTH:
			*param = 2;
			break;
		case CH_40_MHz_WIDTH:
			*param = 3;
			break;
		case CH_80_MHz_WIDTH:
			*param = 4;
			break;
		case CH_160_MHz_WIDTH:
			*param = 5;
			break;
		case CH_5_MHz_WIDTH:
			*param = 8;
			break;
		default:
			rc = -EOPNOTSUPP;
			break;
		}
		if (priv->auto_bw == 1)
			*param = 0;
#ifdef SOC_W8964
		wlFwGetPHYBW(dev);
#endif
		break;

	case WL_PARAM_WMMACKPOLICY:
		*param = *(mib->mib_wmmAckPolicy);
		break;

	case WL_PARAM_GUARDINTERVAL:
		*param = *(mib->mib_guardInterval);
		break;

	case WL_PARAM_EXTSUBCH:
		*param = *(mib->mib_extSubCh);
		break;

	case WL_PARAM_HTPROTECT:
		*param = *(mib->mib_htProtect);
		break;

	case WL_PARAM_GETFWSTAT:
		wlFwGetHwStats(dev, NULL);
		break;

	case WL_PARAM_AGINGTIME:
		*param = *(mib->mib_agingtime);
		break;
	case WL_PARAM_ANTENNATX2:
		*param = *(mib->mib_txAntenna2);
		break;
	case WL_PARAM_CDD:
		*param = *(mib->mib_CDD);
		break;
	case WL_PARAM_ACS_THRESHOLD:
		*param = *(mib->mib_acs_threshold);
		break;
	case WL_PARAM_AUTOCHANNEL:
		*param = *(mib->mib_autochannel);
		break;
	case WL_PARAM_AMPDUFACTOR:
		*param = *(mib->mib_ampdu_factor);
		break;
	case WL_PARAM_AMPDUDENSITY:
		*param = *(mib->mib_ampdu_density);
		break;
#ifdef INTEROP
	case WL_PARAM_INTEROP:
		*param = *(mib->mib_interop);
		break;
#endif
	case WL_PARAM_CARDDEVINFO:
		{
			*param = priv->wlpd_p->CardDeviceInfo;

		}
		break;
	case WL_PARAM_OPTLEVEL:
		*param = *(mib->mib_optlevel);
		break;
	case WL_PARAM_REGIONPWR:
		*param = *(mib->mib_MaxTxPwr);
		break;
	case WL_PARAM_ADAPTMODE:
		*param = *(mib->mib_RateAdaptMode);
		break;
	case WL_PARAM_CSADAPTMODE:
		*param = *(mib->mib_CSMode);
		break;
	case WL_PARAM_11H_CSA_CHAN:
		*param = mib_SpectrumMagament_p->csaChannelNumber;
		break;
	case WL_PARAM_11H_CSA_COUNT:
		*param = mib_SpectrumMagament_p->csaCount;
		break;
	case WL_PARAM_11H_CSA_MODE:
		*param = mib_SpectrumMagament_p->csaMode;
		break;
	case WL_PARAM_SPECTRUM_MGMT:
		*param = mib_SpectrumMagament_p->spectrumManagement;
		break;
	case WL_PARAM_POWER_CONSTRAINT:
		*param = mib_SpectrumMagament_p->powerConstraint;
		break;
	case WL_PARAM_11D_MODE:
		*param = mib_SpectrumMagament_p->multiDomainCapability;
		break;
#ifdef CLIENT_SUPPORT
	case WL_PARAM_11H_STA_MODE:
		if ((vmacEntry_p = sme_GetParentVMacEntry(vmacSta_p->VMacEntry.phyHwMacIndx)) != NULL) {
			pStaSystemMibs = sme_GetStaSystemMibsPtr(vmacEntry_p);
			if (pStaSystemMibs != NULL) {
				*param = pStaSystemMibs->mib_StaCfg_p->sta11hMode;
			}
		}
		break;
#endif				//CLIENT_SUPPORT
#ifdef WDS_FEATURE
	case WL_PARAM_WDSMODE:
		*param = *(mib->mib_wdsEnable);
		break;
#endif
	case WL_PARAM_DISABLEASSOC:
		*param = *(mib->mib_disableAssoc);
		break;
	case WL_PARAM_STRICTWEPSHARE:
		*param = *(mib->mib_strictWepShareKey);
		break;

#ifdef PWRFRAC
	case WL_PARAM_TXPWRFRACTION:
		*param = *(mib->mib_TxPwrFraction);
		break;
#endif

	case WL_PARAM_PSHT_MANAGEMENTACT:
		*param = *(mib->mib_psHtManagementAct);
		break;

#ifdef CLIENT_SUPPORT
	case WL_PARAM_STAMODE:
		*param = *(mib->mib_STAMode);
		break;
	case WL_PARAM_STA_AUTO_SCAN:
		*param = *(mib->mib_STAAutoScan);
		break;
#endif
	case WL_PARAM_AMPDU_TX:
		*param = *(mib->mib_AmpduTx);
		break;
#ifdef MRVL_DFS
	case WL_PARAM_11HCACTIMEOUT:
		*param = *(mib->mib_CACTimeOut);
		break;
	case WL_PARAM_11HETSICACTIMEOUT:
		*param = *(mib->mib_ETSICACTimeOut);
		break;
	case WL_PARAM_11hNOPTIMEOUT:
		*param = *(mib->mib_NOPTimeOut);
		break;
	case WL_PARAM_11hDFSMODE:
		if (priv->wlpd_p->pdfsApMain)
			*param = DfsGetCurrentState(priv->wlpd_p->pdfsApMain);
		else
			*param = 0;
		break;
#endif				//MRVL_DFS
#ifdef SOC_W906X
	case WL_PARAM_AMPDUWINDOWLIMIT:
		{
			*param = vmacSta_p->ampduWindowSizeCap;
		}
		break;
	case WL_PARAM_AMPDUBYTESLIMIT:
		{
			*param = vmacSta_p->ampduBytesCap;
		}
		break;
	case WL_PARAM_AMPDUDENSITYLIMIT:
		{
			*param = vmacSta_p->ampduDensityCap;
		}
		break;
#endif
	case WL_PARAM_TXQLIMIT:
		{
			*param = vmacSta_p->txQLimit;
		}
		break;
	case WL_PARAM_RXINTLIMIT:
		{
			*param = vmacSta_p->work_to_do;
		}
		break;
#ifdef INTOLERANT40
	case WL_PARAM_INTOLERANT:
		{
			*param = *(mib->mib_HT40MIntoler);
		}
		break;
#endif
#ifdef MPRXY
	case WL_PARAM_MCASTPRXY:
		*param = *(mib->mib_MCastPrxy);
		break;
#endif
	case WL_PARAM_RSSI:
		{
#ifdef SOC_W906X
			s16 rssi_value_signed[MAX_RF_ANT_NUM] = { 0 };

			if (vmacSta_p->OpMode == WL_OP_MODE_STA || vmacSta_p->OpMode == WL_OP_MODE_VSTA) {
				wl_util_get_rssi(dev, &vmacSta_p->RSSI_path, rssi_value_signed);
				printk("RSSI:A %d  B %d  C %d  D %d E %d  F %d  G %d  H %d \n",
				       rssi_value_signed[0], rssi_value_signed[1], rssi_value_signed[2], rssi_value_signed[3],
				       rssi_value_signed[4], rssi_value_signed[5], rssi_value_signed[6], rssi_value_signed[7]);
				*param = rssi_value_signed[0];	//to do
			}
#else
			u16 a, b, c, d;

			if (vmacSta_p->OpMode == WL_OP_MODE_STA || vmacSta_p->OpMode == WL_OP_MODE_VSTA) {
				a = vmacSta_p->RSSI_path.a;
				b = vmacSta_p->RSSI_path.b;
				c = vmacSta_p->RSSI_path.c;
				d = vmacSta_p->RSSI_path.d;
				if (a >= 2048 && b >= 2048 && c >= 2048 && d >= 2048) {
					a = ((4096 - a) >> 4);
					b = ((4096 - b) >> 4);
					c = ((4096 - c) >> 4);
					d = ((4096 - d) >> 4);
				}
				printk("RSSI:A -%d  B -%d  C -%d  D -%d\n", a, b, c, d);
				*param = -a;	//to do
			}
#endif
			else {
				printk(" for STA mode use only \n");
				*param = 0;
			}
		}
		break;

#ifdef CLIENT_SUPPORT
	case WL_PARAM_LINKSTATUS:
		if ((vmacEntry_p = sme_GetParentVMacEntry(vmacSta_p->VMacEntry.phyHwMacIndx)) != NULL) {
			vmacStaInfo_t *vStaInfo_p = (vmacStaInfo_t *) vmacEntry_p->info_p;

			if (vStaInfo_p->staSecurityMibs.mib_PrivacyTable_p->RSNEnabled) {
				*param = vStaInfo_p->staSecurityMibs.mib_PrivacyTable_p->RSNLinkStatus;
			} else {
				smeGetStaLinkInfo(vmacEntry_p->id, &AssociatedFlag, &bssId[0]);
				*param = AssociatedFlag;
			}
		}
		break;
#endif
#ifdef RXPATHOPT
	case WL_PARAM_RXPATHOPT:
		*param = *(mib->mib_RxPathOpt);
		break;
#endif
	case WL_PARAM_HTGF:
		*param = *(mib->mib_HtGreenField);
		break;

	case WL_PARAM_HTSTBC:
		*param = *(mib->mib_HtStbc);
		break;

	case WL_PARAM_3X3RATE:
		*param = *(mib->mib_3x3Rate);
		break;
	case WL_PARAM_AMSDU_FLUSHTIME:
		*param = *(mib->mib_amsdu_flushtime);
		break;
	case WL_PARAM_AMSDU_MAXSIZE:
		*param = *(mib->mib_amsdu_maxsize);
		break;
	case WL_PARAM_AMSDU_ALLOWSIZE:
		*param = *(mib->mib_amsdu_allowsize);
		break;
	case WL_PARAM_AMSDU_PKTCNT:
		*param = *(mib->mib_amsdu_pktcnt);
		break;
#ifdef CONFIG_IEEE80211W
	case WL_PARAM_BIPKEYSN:
		{
			printk("**pn-1: %x:%x:%x:%x:%x:%x **\n", vmacSta_p->pn[0],
			       vmacSta_p->pn[1], vmacSta_p->pn[2], vmacSta_p->pn[3], vmacSta_p->pn[4], vmacSta_p->pn[5]);

			memcpy(param, vmacSta_p->pn, 6);
			printk("**param: %x:%x **\n", param[0], param[1]);
			break;
		}
#endif
	case WL_PARAM_GET_DEVICE_ID:
		*param = priv->devid;
		break;

#ifdef IEEE80211K
	case WL_PARAM_RRM_EN:
		*param = *(mib->mib_rrm);
		break;
#endif

#ifdef SOC_W906X
	case WL_PARAM_HE_LDPC:
		*param = *(mib->mib_heldpc_enable);
		break;

	case WL_PARAM_BSS_COLOR:
		if (vmacSta_p->master) {
			vmacSta_p = vmacSta_p->master;
			mib = vmacSta_p->Mib802dot11;
		}
		if (mib->StationConfig->bss_color)
			*param = mib->StationConfig->bss_color;
		else {
			*param = vmacSta_p->bss_color;
		}
		break;
	case WL_PARAM_MU_EDCA_EN:
		if (!priv->master) {
			printk("Error. Please enter vap interface instead\n");
			rc = -EOPNOTSUPP;
			break;
		}
		*param = vmacSta_p->VMacEntry.muedcaEnable;
		break;

	case WL_PARAM_HE_TWT_EN:
		if (!priv->master) {
			printk("Error. Please enter vap interface instead\n");
			rc = -EOPNOTSUPP;
			break;
		}
		*param = *vmacSta_p->Mib802dot11->he_twt_activated;
		break;
	case WL_PARAM_WLS_FTM_EN:
#ifdef WLS_FTM_SUPPORT
		*param = *vmacSta_p->Mib802dot11->wls_ftm_enable;
#else
		WLDBG_ERROR(DBG_LEVEL_0, "Cmd getwls not supported\n");
		rc = -EINVAL;
#endif
		break;

	case WL_PARAM_HE_MUBF_EN:
		if (!priv->master) {
			printk("Error. Please enter vap interface instead\n");
			rc = -EOPNOTSUPP;
			break;
		}
		*param = *vmacSta_p->Mib802dot11->he_mu_bf;
		break;

	case WL_PARAM_HE_SUBF_EN:
		if (!priv->master) {
			printk("Error. Please enter vap interface instead\n");
			rc = -EOPNOTSUPP;
			break;
		}
		*param = *vmacSta_p->Mib802dot11->he_su_bf;
		break;

#else
#ifdef BAND_STEERING
	case WL_PARAM_BANDSTEER:
		*param = *(mib->mib_bandsteer);
		break;
#endif
#ifdef DOT11V_DMS
	case WL_PARAM_DOT11V_DMS:
		*param = *(mib->mib_dms);
		break;
#endif
	case WL_PARAM_RESET_RATE_MODE:
		*param = *(mib->mib_reset_rate_mode);
		break;
#endif
#if defined(WFA_TKIP_NEGATIVE) && defined(SOC_W906X)
	case WL_PARAM_HT_TKIP:
		*param = allow_ht_tkip;
		break;
#endif
	default:
		PRINT1(IOCTL, "%s: get_mp31ep_param: unknown param %d\n", dev->name, *param);
		rc = -EOPNOTSUPP;
		break;
	}

	WLDBG_EXIT(DBG_LEVEL_1);
	return rc;
}

static int wlioctl_priv_bss_start(struct net_device *dev, struct iw_request_info *info, void *wrqu, char *extra)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, dev);
	struct wlprivate_data *wlpd_p = priv->wlpd_p;
	char logbuf[256];
	UINT32 size;
	int rc = 0;

	WLDBG_IOCTL(DBG_LEVEL_0, "%s:wlioctl_bss_start, CpuID:%u, PID:%i, ProcName:\"%s\"\n",
		    dev->name, smp_processor_id(), current->pid, current->comm);

#ifdef SOC_W906X
	if (wlpd_p->smon.active) {
		UINT64 tsec, tms;

		convert_tscale(xxGetTimeStamp(), &tsec, &tms, NULL);
		size = (UINT32) sprintf(&logbuf[0], "[%llu.%llu]: %s:wlioctl_bss_start, CpuID:%u, PID:%i, ProcName:\"%s\"\n", tsec, tms,
					dev->name, smp_processor_id(), current->pid, current->comm);
		wlmon_log_buffer(dev, logbuf, size);
	}
#endif

	WLDBG_ENTER_INFO(DBG_LEVEL_1, "");
	if (wlFwApplySettings(dev))
		return -EIO;
	WLDBG_EXIT(DBG_LEVEL_1);

	return rc;
}

static const iw_handler wlhandler[] = {
	(iw_handler) wlconfig_commit,	/* 0x8B00: SIOCSIWCOMMIT */
	(iw_handler) wlget_name,	/* 0x8B01: SIOCGIWNAME */
	(iw_handler) NULL,	/* 0x8B02: SIOCSIWNWID */
	(iw_handler) NULL,	/* 0x8B03: SIOCGIWNWID */
	(iw_handler) wlset_freq,	/* 0x8B04: SIOCSIWFREQ */
	(iw_handler) wlget_freq,	/* 0x8B05: SIOCGIWFREQ */
	(iw_handler) NULL,	/* 0x8B06: SIOCSIWMODE */
	(iw_handler) NULL,	/* 0x8B07: SIOCGIWMODE */
	(iw_handler) NULL,	/* 0x8B08: SIOCSIWSENS */
	(iw_handler) wlget_sens,	/* 0x8B09: SIOCGIWSENS */
	(iw_handler) NULL,	/* 0x8B0A: SIOCSIWRANGE */
	(iw_handler) wlget_range,	/* 0x8B0B: SIOCGIWRANGE */
	(iw_handler) NULL,	/* 0x8B0C: SIOCSIWPRIV */
	(iw_handler) NULL,	/* 0x8B0D: SIOCGIWPRIV */
	(iw_handler) NULL,	/* 0x8B0E: SIOCSIWSTATS */
	(iw_handler) wlget_stats,	/* 0x8B0F: SIOCGIWSTATS */
#if WIRELESS_EXT > 15
	iw_handler_set_spy,	/* 0x8B10: SIOCSIWSPY */
	iw_handler_get_spy,	/* 0x8B11: SIOCGIWSPY */
	iw_handler_set_thrspy,	/* 0x8B13: SIOCSIWTHRSPY */
	iw_handler_get_thrspy,	/* 0x8B14: SIOCGIWTHRSPY */
#else				/* WIRELESS_EXT > 15 */
	(iw_handler) NULL,	/* 0x8B10: SIOCSIWSPY */
	(iw_handler) NULL,	/* 0x8B11: SIOCGIWSPY */
	(iw_handler) NULL,	/* -- hole -- */
	(iw_handler) NULL,	/* -- hole -- */
#endif				/* WIRELESS_EXT > 15 */
	(iw_handler) wlset_bssid,	/* 0x8B14: SIOCSIWAP */
	(iw_handler) wlget_wap,	/* 0x8B15: SIOCGIWAP */
	(iw_handler) wlset_mlme,	/* 0xBB16: SIOCSIWMLME */
	(iw_handler) NULL,	/* 0x8B17: SIOCGIWAPLIST */
	(iw_handler) wlset_scan,	/* 0x8B18: SIOCSIWSCAN */
	(iw_handler) wlget_scan,	/* 0x8B19: SIOCGIWSCAN */
	(iw_handler) wlset_essid,	/* 0x8B1A: SIOCSIWESSID */
	(iw_handler) wlget_essid,	/* 0x8B1B: SIOCGIWESSID */
	(iw_handler) NULL,	/* 0x8B1C: SIOCSIWNICKN */
	(iw_handler) NULL,	/* 0x8B1D: SIOCGIWNICKN */
	(iw_handler) NULL,	/* -- hole -- */
	(iw_handler) NULL,	/* -- hole -- */
	(iw_handler) NULL,	/* 0x8B20: SIOCSIWRATE */
	(iw_handler) NULL,	/* 0x8B21: SIOCGIWRATE */
	(iw_handler) wlset_rts,	/* 0x8B22: SIOCSIWRTS */
	(iw_handler) wlget_rts,	/* 0x8B23: SIOCGIWRTS */
	(iw_handler) NULL,	/* 0x8B24: SIOCSIWFRAG */
	(iw_handler) wlget_frag,	/* 0x8B25: SIOCGIWFRAG */
	(iw_handler) NULL,	/* 0x8B26: SIOCSIWTXPOW */
	(iw_handler) NULL,	/* 0x8B27: SIOCGIWTXPOW */
	(iw_handler) NULL,	/* 0x8B28: SIOCSIWRETRY */
	(iw_handler) NULL,	/* 0x8B29: SIOCGIWRETRY */
	(iw_handler) wlset_encode,	/* 0x8B2A: SIOCSIWENCODE */
	(iw_handler) wlget_encode,	/* 0x8B2B: SIOCGIWENCODE */
	(iw_handler) NULL,	/* 0x8B2C: SIOCSIWPOWER */
	(iw_handler) NULL,	/* 0x8B2D: SIOCGIWPOWER */
	(iw_handler) NULL,	/* -- hole -- */
	(iw_handler) NULL,	/* -- hole -- */
	(iw_handler) NULL,	/* 0x8B30: SIOCSIWGENIE */
	(iw_handler) NULL,	/* 0x8B31: SIOCGIWGENIE */
	(iw_handler) wlset_auth,	/* 0x8B32: SIOCSIWAUTH */
	(iw_handler) NULL,	/* 0x8B33: SIOCGIWAUTH */
	(iw_handler) wlset_encodeext,	/* 0x8B34: SIOCSIWENCODEEXT */
	(iw_handler) NULL,	/* 0x8B35: SIOCGIWENCODEEXT */
	(iw_handler) NULL,	/* 0x8B36: SIOCSIWPMKSA */
};

static const iw_handler wlprivate_handler[] = {
	/* SIOCIWFIRSTPRIV + */
	(iw_handler) wlioctl_priv_wlparam,	/* 0 */
	(iw_handler) wlioctl_priv_get_wlparam,	/* 1 */
	(iw_handler) wlioctl_priv_bss_start,	/* 2 */
	(iw_handler) NULL,
	(iw_handler) NULL,
	(iw_handler) NULL,
	(iw_handler) NULL,
	(iw_handler) NULL,
	(iw_handler) NULL,
	(iw_handler) NULL,
	//(iw_handler) wlset_staMacFilter,
	//(iw_handler) wlset_staMacFilter,

};

static const struct iw_priv_args wlprivate_args[] = {
	//{ WL_IOCTL_BSS_START, 0, 0, "bssstart" },
	{WL_IOCTL_GET_VERSION, IW_PRIV_TYPE_CHAR | 128, IW_PRIV_TYPE_CHAR | 128, "version"},
	{WL_IOCTL_SET_TXRATE, IW_PRIV_TYPE_CHAR | 128, 0, "txrate"},
	{WL_IOCTL_GET_TXRATE, 0, IW_PRIV_TYPE_CHAR | 128, "gettxrate"},
	{WL_IOCTL_SET_CIPHERSUITE, IW_PRIV_TYPE_CHAR | 128, 0, "ciphersuite"},
	{WL_IOCTL_GET_CIPHERSUITE, 0, IW_PRIV_TYPE_CHAR | 128, "getciphersuite"},
	{WL_IOCTL_SET_PASSPHRASE, IW_PRIV_TYPE_CHAR | 128, 0, "passphrase"},
	{WL_IOCTL_GET_PASSPHRASE, 0, IW_PRIV_TYPE_CHAR | 128, "getpassphrase"},
	{WL_IOCTL_SET_FILTERMAC, IW_PRIV_TYPE_CHAR | 128, 0, "filtermac"},
	{WL_IOCTL_GET_FILTERMAC, 0, IW_PRIV_TYPE_CHAR | 2560, "getfiltermac"},
	{WL_IOCTL_SET_WMMEDCAAP, IW_PRIV_TYPE_CHAR | 128, 0, "wmmedcaap"},
	{WL_IOCTL_GET_WMMEDCAAP, 0, IW_PRIV_TYPE_CHAR | 128, "getwmmedcaap"},
	{WL_IOCTL_SET_WMMEDCASTA, IW_PRIV_TYPE_CHAR | 128, 0, "wmmedcasta"},
	{WL_IOCTL_GET_WMMEDCASTA, 0, IW_PRIV_TYPE_CHAR | 128, "getwmmedcasta"},
	{WL_IOCTL_SET_BSSID, IW_PRIV_TYPE_CHAR | 128, 0, "bssid"},
	{WL_IOCTL_GET_BSSID, 0, IW_PRIV_TYPE_CHAR | 128, "getbssid"},
	{WL_IOCTL_SET_CLIENT, IW_PRIV_TYPE_CHAR | 128, 0, "macclone"},

	{WL_IOCTL_GET_STALISTEXT, 0, IW_PRIV_TYPE_CHAR | 2560, "getstalistext"},
	{WL_IOCTL_SET_TXPOWER, IW_PRIV_TYPE_CHAR | 128, 0, "txpower"},
	{WL_IOCTL_GET_TXPOWER, 0, IW_PRIV_TYPE_CHAR | 128, "gettxpower"},
	{WL_IOCTL_GETCMD, IW_PRIV_TYPE_CHAR | 128, IW_PRIV_TYPE_CHAR | 1024, "getcmd"},
	{WL_IOCTL_SET_WDS_PORT, IW_PRIV_TYPE_CHAR | 128, 0, "setwds"},
	{WL_IOCTL_GET_WDS_PORT, 0, IW_PRIV_TYPE_CHAR | 128, "getwds"},
	{WL_IOCTL_SETCMD, IW_PRIV_TYPE_CHAR | 1536, 0, "setcmd"},
	{WL_IOCTL_GET_STASCAN, 0, IW_PRIV_TYPE_CHAR | 2560, "getstascan"},

	/* --- sub-ioctls handlers --- */
	{WL_IOCTL_WL_PARAM,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, ""},
	{WL_IOCTL_WL_GET_PARAM,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, ""},
	/* --- sub-ioctls definitions --- */
	{WL_PARAM_BAND,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "opmode"},
	{WL_PARAM_BAND,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getopmode"},
	{WL_PARAM_REGIONCODE,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "regioncode"},
	{WL_PARAM_REGIONCODE,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getregioncode"},
	{WL_PARAM_HIDESSID,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "hidessid"},
	{WL_PARAM_HIDESSID,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "gethidessid"},
	{WL_PARAM_PREAMBLE,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "preamble"},
	{WL_PARAM_PREAMBLE,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getpreamble"},
	{WL_PARAM_GPROTECT,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "gprotect"},
	{WL_PARAM_GPROTECT,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getgprotect"},
	{WL_PARAM_BEACON,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "bcninterval"},
	{WL_PARAM_BEACON,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getbcninterval"},
	{WL_PARAM_DTIM,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "dtim"},
	{WL_PARAM_DTIM,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getdtim"},
	{WL_PARAM_FIXRATE,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "fixrate"},
	{WL_PARAM_FIXRATE,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getfixrate"},
	{WL_PARAM_ANTENNA,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "rxantenna"},
	{WL_PARAM_ANTENNA,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getrxantenna"},
	{WL_PARAM_WPAWPA2MODE,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "wpawpa2mode"},
	{WL_PARAM_WPAWPA2MODE,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getwpawpa2mode"},
#ifdef MRVL_WAPI
	{WL_PARAM_WAPIMODE,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "wapimode"},
	{WL_PARAM_WAPIMODE,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getwapimode"},
#endif
	{WL_PARAM_GROUPREKEYTIME,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "grouprekey"},
	{WL_PARAM_GROUPREKEYTIME,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getgrouprekey"},
	{WL_PARAM_WMM,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "wmm"},
	{WL_PARAM_WMM,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getwmm"},
	{WL_PARAM_FILTER,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "filter"},
	{WL_PARAM_FILTER,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getfilter"},
	{WL_PARAM_INTRABSS,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "intrabss"},
	{WL_PARAM_INTRABSS,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getintrabss"},
	{WL_PARAM_AMSDU,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "amsdu"},
	{WL_PARAM_AMSDU,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getamsdu"},
	{WL_PARAM_HTBANDWIDTH,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "htbw"},
	{WL_PARAM_HTBANDWIDTH,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "gethtbw"},
	{WL_PARAM_WMMACKPOLICY,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "wmmackpolicy"},
	{WL_PARAM_WMMACKPOLICY,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getwmmackpolicy"},
	{WL_PARAM_GUARDINTERVAL,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "guardint"},
	{WL_PARAM_GUARDINTERVAL,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getguardint"},
	{WL_PARAM_EXTSUBCH,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "extsubch"},
	{WL_PARAM_EXTSUBCH,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getextsubch"},
	{WL_PARAM_HTPROTECT,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "htprotect"},
	{WL_PARAM_HTPROTECT,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "gethtprotect"},
	{WL_PARAM_GETFWSTAT,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getfwstat"},
	{WL_PARAM_AGINGTIME,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "agingtime"},
	{WL_PARAM_AGINGTIME,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getagingtime"},
	{WL_PARAM_ANTENNATX2,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "txantenna2"},
	{WL_PARAM_ANTENNATX2,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "gettxantenna2"},
	{WL_PARAM_AUTOCHANNEL,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "autochannel"},
	{WL_PARAM_AUTOCHANNEL,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getautochannel"},
	{WL_PARAM_AMPDUFACTOR,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "ampdufactor"},
	{WL_PARAM_AMPDUFACTOR,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getampdufactor"},
	{WL_PARAM_AMPDUDENSITY,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "ampduden"},
	{WL_PARAM_AMPDUDENSITY,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getampduden"},
	{WL_PARAM_CARDDEVINFO,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getdeviceinfo"},
#ifdef INTEROP
	{WL_PARAM_INTEROP,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "interop"},
	{WL_PARAM_INTEROP,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getinterop"},
#endif
	{WL_PARAM_OPTLEVEL,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "optlevel"},
	{WL_PARAM_OPTLEVEL,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getoptlevel"},
	{WL_PARAM_REGIONPWR,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "maxtxpower"},
	{WL_PARAM_REGIONPWR,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getmaxtxpower"},
	{WL_PARAM_ADAPTMODE,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "ratemode"},
	{WL_PARAM_ADAPTMODE,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getratemode"},
	{WL_PARAM_CSADAPTMODE,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "csmode"},
	{WL_PARAM_CSADAPTMODE,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getcsmode"},
	{WL_PARAM_DELWEPKEY,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "delwepkey"},
	{WL_PARAM_WDSMODE,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "wdsmode"},
	{WL_PARAM_WDSMODE,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getwdsmode"},
	{WL_PARAM_STRICTWEPSHARE,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "strictshared"},
	{WL_PARAM_STRICTWEPSHARE,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getstrictshared"},
	{WL_PARAM_DISABLEASSOC,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "disableassoc"},
	{WL_PARAM_DISABLEASSOC,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getdisableassoc"},
	{WL_PARAM_11H_DFS_MODE,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "11hdfsmode"},
	{WL_PARAM_11H_CSA_CHAN,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "11hcsachan"},
	{WL_PARAM_11H_CSA_CHAN,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get11hcsachan"},
	{WL_PARAM_11H_CSA_COUNT,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "11hcsacount"},
	{WL_PARAM_11H_CSA_COUNT,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get11hcsacount"},
	{WL_PARAM_11H_CSA_MODE,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "11hcsamode"},
	{WL_PARAM_11H_CSA_MODE,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get11hcsamode"},
	{WL_PARAM_11H_CSA_START,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "11hcsastart"},
	{WL_PARAM_SPECTRUM_MGMT,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "11hspecmgt"},
	{WL_PARAM_SPECTRUM_MGMT,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get11hspecmgt"},
	{WL_PARAM_POWER_CONSTRAINT,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "11hpwrconstr"},
	{WL_PARAM_POWER_CONSTRAINT,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get11hpwrconstr"},
	{WL_PARAM_11D_MODE,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "11dmode"},
	{WL_PARAM_11D_MODE,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get11dmode"},
	{WL_PARAM_11H_STA_MODE,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "11hstamode"},
	{WL_PARAM_11H_STA_MODE,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get11hstamode"},
	{WL_PARAM_TXPWRFRACTION,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "pwrfraction"},
	{WL_PARAM_TXPWRFRACTION,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getpwrfraction"},
	{WL_PARAM_PSHT_MANAGEMENTACT,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "mimops"},
	{WL_PARAM_PSHT_MANAGEMENTACT,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getmimops"},
	{WL_PARAM_STAMODE,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "stamode"},
	{WL_PARAM_STAMODE,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getstamode"},
	{WL_PARAM_STASCAN,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "stascan"},
	{WL_PARAM_AMPDU_TX,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "ampdutx"},
	{WL_PARAM_AMPDU_TX,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getampdutx"},
	{WL_PARAM_11HCACTIMEOUT,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "11hCACTimeOut"},
	{WL_PARAM_11HCACTIMEOUT,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get11hCACTout"},
	{WL_PARAM_11HETSICACTIMEOUT,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "11hETSICAC"},
	{WL_PARAM_11HETSICACTIMEOUT,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getETSICAC"},
	{WL_PARAM_11hNOPTIMEOUT,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "11hNOPTimeOut"},
	{WL_PARAM_11hNOPTIMEOUT,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get11hNOPTout"},
	{WL_PARAM_11hDFSMODE,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get11hDFSMode"},
	{WL_PARAM_TXQLIMIT,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "txqlimit"},
	{WL_PARAM_TXQLIMIT,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "gettxqlimit"},
	{WL_PARAM_RXINTLIMIT,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "rxintlimit"},
	{WL_PARAM_RXINTLIMIT,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getrxintlimit"},
	{WL_PARAM_INTOLERANT,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "intoler"},
	{WL_PARAM_INTOLERANT,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getintoler"},
	{WL_PARAM_MCASTPRXY,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "mcastproxy"},
	{WL_PARAM_MCASTPRXY,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getmcastproxy"},
	{WL_PARAM_RSSI,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getrssi"},
	{WL_PARAM_LINKSTATUS,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getlinkstatus"},
	{WL_PARAM_ANTENNATX,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "txantenna"},
	{WL_PARAM_ANTENNATX,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "gettxantenna"},
	{WL_PARAM_RXPATHOPT,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "rxpathopt"},
	{WL_PARAM_RXPATHOPT,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getrxpathopt"},
	{WL_PARAM_HTGF,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "htgf"},
	{WL_PARAM_HTGF,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "gethtgf"},
	{WL_PARAM_HTSTBC,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "htstbc"},
	{WL_PARAM_HTSTBC,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "gethtstbc"},
	{WL_PARAM_3X3RATE,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "3x3rate"},
	{WL_PARAM_3X3RATE,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "get3x3rate"},
	{WL_PARAM_AMSDU_FLUSHTIME,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "amsduft"},
	{WL_PARAM_AMSDU_FLUSHTIME,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getamsduft"},
	{WL_PARAM_AMSDU_MAXSIZE,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "amsdums"},
	{WL_PARAM_AMSDU_MAXSIZE,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getamsdums"},
	{WL_PARAM_AMSDU_ALLOWSIZE,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "amsduas"},
	{WL_PARAM_AMSDU_ALLOWSIZE,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getamsduas"},
	{WL_PARAM_AMSDU_PKTCNT,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "amsdupc"},
	{WL_PARAM_AMSDU_PKTCNT,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getamsdupc"},
	{WL_PARAM_CDD,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "cdd"},
	{WL_PARAM_CDD,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getcdd"},
	{WL_PARAM_ACS_THRESHOLD,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "acsthrd"},
	{WL_PARAM_ACS_THRESHOLD,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getacsthrd"},
	{WL_PARAM_BIPKEYSN,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "bipkeysn"},
	{WL_PARAM_BIPKEYSN,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getbipkeysn"},
	{WL_PARAM_GET_DEVICE_ID,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getdeviceid"},
#ifdef IEEE80211K
	{WL_PARAM_RRM_EN,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "rrm"},
	{WL_PARAM_RRM_EN,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getrrm"},
#endif
	{WL_PARAM_STA_AUTO_SCAN,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "autoscan"},
	{WL_PARAM_STA_AUTO_SCAN,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getautoscan"},
#ifdef SOC_W906X
	{WL_PARAM_AMPDUWINDOWLIMIT,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "ampduwincap"},
	{WL_PARAM_AMPDUWINDOWLIMIT,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getampduwincap"},
	{WL_PARAM_AMPDUBYTESLIMIT,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "ampdubytcap"},
	{WL_PARAM_AMPDUBYTESLIMIT,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getampdubytcap"},
	{WL_PARAM_AMPDUDENSITYLIMIT,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "ampdudencap"},
	{WL_PARAM_AMPDUDENSITYLIMIT,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getampdudencap"},
	{WL_PARAM_HE_LDPC,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "heldpc"},
	{WL_PARAM_HE_LDPC,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getheldpc"},
	{WL_PARAM_BSS_COLOR,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "bsscolor"},
	{WL_PARAM_BSS_COLOR,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getbsscolor"},
	{WL_PARAM_HT_TKIP,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "httkip"},
	{WL_PARAM_HT_TKIP,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "gethttkip"},
	{WL_PARAM_MU_EDCA_EN,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "muedca"},
	{WL_PARAM_MU_EDCA_EN,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getmuedca"},
	{WL_PARAM_HE_TWT_EN,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "hetwt"},
	{WL_PARAM_HE_TWT_EN,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "gethetwt"},
	{WL_PARAM_WLS_FTM_EN,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "wls"},
	{WL_PARAM_WLS_FTM_EN,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getwls"},
	{WL_PARAM_HE_MUBF_EN,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "hemubf"},
	{WL_PARAM_HE_MUBF_EN,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "gethemubf"},
	{WL_PARAM_HE_SUBF_EN,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "hesubf"},
	{WL_PARAM_HE_SUBF_EN,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "gethesubf"},
#else
#ifdef BAND_STEERING
	{WL_PARAM_BANDSTEER,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "bandsteer"},
	{WL_PARAM_BANDSTEER,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getbandsteer"},
#endif
#ifdef DOT11V_DMS
	{WL_PARAM_DOT11V_DMS,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "dms"},
	{WL_PARAM_DOT11V_DMS,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getdms"},
#endif
	{WL_PARAM_RESET_RATE_MODE,
	 IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "resetratemode"},
	{WL_PARAM_RESET_RATE_MODE,
	 0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, "getresetratemode"},
#endif
};

const struct iw_handler_def wlDefHandler = {
 num_standard:sizeof(wlhandler) / sizeof(iw_handler),
 num_private:sizeof(wlprivate_handler) / sizeof(iw_handler),
 num_private_args:sizeof(wlprivate_args) / sizeof(struct iw_priv_args),
 standard:(iw_handler *) wlhandler,
 private:(iw_handler *) wlprivate_handler,
 private_args:(struct iw_priv_args *)wlprivate_args,
};

int wlSetupWEHdlr(struct net_device *netdev)
{
	netdev->wireless_handlers = (struct iw_handler_def *)&wlDefHandler;
	return 0;
}

int atoi(const char *num_str)
{
	int val = 0;

	for (;; num_str++) {
		switch (*num_str) {
		case '0' ... '9':
			val = 10 * val + (*num_str - '0');
			break;
		default:
			return val;
		}
	}
}

int atoi_2(const char *num_str)
{
	int val = 0;
	BOOLEAN bNegativeNum = FALSE;

	if (*num_str == '-') {
		bNegativeNum = TRUE;
		num_str++;
	}
	for (;; num_str++) {
		switch (*num_str) {
		case '0' ... '9':
			val = 10 * val + (*num_str - '0');
			break;
		default:
			if (!bNegativeNum)
				return val;
			else {
				val = ~val + 1;
				return val;
			}
		}
	}
}

static long atohex(const char *number)
{
	long n = 0;

	if (*number == '0' && (*(number + 1) == 'x' || *(number + 1) == 'X'))
		number += 2;
	while (*number <= ' ' && *number > 0)
		++number;
	while ((*number >= '0' && *number <= '9') || (*number >= 'A' && *number <= 'F') || (*number >= 'a' && *number <= 'f')) {
		if (*number >= '0' && *number <= '9') {
			n = (n * 0x10) + ((*number++) - '0');
		} else if (*number >= 'A' && *number <= 'F') {
			n = (n * 0x10) + ((*number++) - 'A' + 10);
		} else {	/* if (*number>='a' && *number<='f') */
			n = (n * 0x10) + ((*number++) - 'a' + 10);
		}
	}
	return n;
}

long atohex2(const char *number)
{
	long n = 0;

	while (*number <= ' ' && *number > 0)
		++number;
	if (*number == 0)
		return n;
	if (*number == '0' && (*(number + 1) == 'x' || *(number + 1) == 'X'))
		n = atohex(number + 2);
	else
		n = atoi(number);
	return n;
}

static param_applicable priv_iocmd[] = {
	{WL_IOCTL_BSS_START, 0},
	{WL_IOCTL_SET_TXRATE, 0},
	{WL_IOCTL_SET_CIPHERSUITE, 0},
	{WL_IOCTL_SET_PASSPHRASE, 0},
	{WL_IOCTL_SET_FILTERMAC, 0},
	{WL_IOCTL_SET_BSSID, 0},
	{WL_IOCTL_SET_TXPOWER, 1},
	{WL_IOCTL_SET_APPIE, 0},
	{WL_IOCTL_SET_CLIENT, 0},
	{WL_IOCTL_SET_MGMT_SEND, 0},
	{WL_IOCTL_SET_WDS_PORT, 0},
};

int is_the_cmd_applicable(UINT16 cmd)
{
	int i;

	for (i = 0; i < sizeof(priv_iocmd) / 4; i++) {
		if (priv_iocmd[i].command == cmd)
			return priv_iocmd[i].applicable;
	}
	return 0;
}

void dev_send_frame(vmacApInfo_t * vmacSta_p)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev);
	UINT8 *buf;
	IEEEtypes_fullHdr_t *fullHdr_p;

	if ((vmacSta_p->dev->flags & IFF_RUNNING) == 0)
		return;

	buf = (UINT8 *) wl_kzalloc(512, GFP_KERNEL);
	if (buf == NULL) {
		return;
	}

	fullHdr_p = (IEEEtypes_fullHdr_t *) buf;
	fullHdr_p->FrmCtl.Type = IEEE_TYPE_DATA;
	fullHdr_p->FrmCtl.Subtype = QoS_DATA;
	fullHdr_p->FrmCtl.FromDs = 1;
	fullHdr_p->FrmCtl.ToDs = 0;

	//printk("[%s]send S-MPDU->[%s] fix rate:0x%X\n",  vmacSta_p->dev->name, mac_display(wlpptr->sndpkt_mac), (0x0F0000C0 | wlpptr->wfa_sndpkt_rate));

	memcpy(fullHdr_p->Addr3, vmacSta_p->macStaAddr, IEEEtypes_ADDRESS_SIZE);
	memcpy(fullHdr_p->Addr1, wlpptr->sndpkt_mac, IEEEtypes_ADDRESS_SIZE);
	memcpy(fullHdr_p->Addr2, vmacSta_p->macStaAddr, IEEEtypes_ADDRESS_SIZE);

	fullHdr_p->FrmCtl.Wep = 0;
	fullHdr_p->qos = 0x00;
	fullHdr_p->DurationId = 16 * 1000;	//16ms

	wlFwSendFrame(vmacSta_p->dev, 50, 0, 0, (0x0F0000C0 | wlpptr->wfa_sndpkt_rate), 26, 257, (UINT8 *) buf, (UINT8 *) & buf[26]);

	if (wlpptr->wfa_sndpkt_interval)
		TimerFireInByJiffies(&wfa_test_timer, 1, &dev_send_frame, (unsigned char *)vmacSta_p,
				     wlpptr->wfa_sndpkt_interval * TIMER_1MS + ((wlpptr->wfa_sndpkt_interval * HZ % 1000) ? 1 : 0));

	wl_kfree(buf);

	return;
}

#ifdef SOC_W906X
int WlLoadRateGrp(struct net_device *netdev)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = priv->wlpd_p;
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	MIB_PHY_DSSS_TABLE *PhyDSSSTable = mib->PhyDSSSTable;
	Info_rate_power_table_t *pInfo;
	BOOLEAN bSetPowerFail;
	UINT32 i, j, m;
	UINT32 k = 0;
	rate_power_table_t *ratepwrtbl_p;
	int retval = SUCCESS;

	ratepwrtbl_p = (rate_power_table_t *) wl_kmalloc(sizeof(rate_power_table_t), GFP_KERNEL);

	if (wlpd_p->AllChanGrpsPwrTbl.NumOfChan != 0) {
		k = 0;
		memset(ratepwrtbl_p, 0, sizeof(rate_power_table_t));
		for (m = 0; m < wlpd_p->AllChanGrpsPwrTbl.NumOfChan; m++) {
			if (wlpd_p->AllChanGrpsPwrTbl.PerChanGrpsPwrTbl[m].channel == PhyDSSSTable->CurrChan) {
				printk("curr chan =%d \n", PhyDSSSTable->CurrChan);
				ratepwrtbl_p->channel = wlpd_p->AllChanGrpsPwrTbl.PerChanGrpsPwrTbl[m].channel;
				break;
			} else {
				continue;
			}

		}
		if (m == wlpd_p->AllChanGrpsPwrTbl.NumOfChan) {
			retval = FAIL;
			goto exit;
		}
		for (j = 0; j < wlpd_p->AllChanGrpsPwrTbl.PerChanGrpsPwrTbl[m].NumOfGrpPerChan; j++) {
			if (wlpd_p->RateGrpDefault[j].NumOfEntry != 0) {
				for (i = 0; i < wlpd_p->RateGrpDefault[j].NumOfEntry; i++) {
					UINT16 Power;
					//UINT16 temp;

					Power = (UINT16) wlpd_p->AllChanGrpsPwrTbl.PerChanGrpsPwrTbl[m].GrpsPwr[j];
					//temp = (UINT16)Power;
					ratepwrtbl_p->NumOfEntry++;
					ratepwrtbl_p->RatePower[k] =
					    (UINT64) wlpd_p->RateGrpDefault[j].
					    AxAnt << 24 | (UINT64) Power << 32 | (UINT64) Power << 48 | (UINT64) wlpd_p->RateGrpDefault[j].Rate[i];

					k++;

				}
			} else {
				break;
			}
		}

		if (ratepwrtbl_p->NumOfEntry > MAX_RATE_POWER_ENTRY) {
			printk("Error: rate power entries over buffer range\n");
			BUG();
		}

	} else {
		//for Cisco power table

		for (i = 0; i < IEEE_80211_MAX_NUMBER_OF_CHANNELS; i++) {
			if (priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[i].channel == PhyDSSSTable->CurrChan) {
				if (priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[i].bValid) {
					memcpy((void *)ratepwrtbl_p, (void *)&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[i].PerChanPwr,
					       sizeof(rate_power_table_t));
					break;
				}
			}
		}
		if (i == IEEE_80211_MAX_NUMBER_OF_CHANNELS) {
			//printk("NO valid entry for barbado power table \n");
			goto exit;
		}

	}

	pInfo = (Info_rate_power_table_t *) priv->wlpd_p->descData[0].pInfoPwrTbl;
	bSetPowerFail = TRUE;
	for (i = 0; i < 10; i++) {
		if (pInfo->DrvCnt == pInfo->FwCnt) {
			int retval = FAIL;

			memcpy((void *)&pInfo->RatePwrTbl, (void *)ratepwrtbl_p, sizeof(rate_power_table_t));

			if (pInfo->DrvCnt == 0xFFFFFFFF) {
				pInfo->DrvCnt = 0;
			} else {
				pInfo->DrvCnt += 1;
			}

			if ((retval = wlFwSetPowerPerRate(netdev)) == SUCCESS)
				pInfo->FwCnt += 1;

			bSetPowerFail = FALSE;
			break;
		} else {
			printk("delay:%u\n", i);
			mdelay(10);	//10 msec
		}
	}
	if (bSetPowerFail) {
		printk("Fail to set power per rate\n");
		retval = FAIL;
		goto exit;
	}

 exit:
	wl_kfree(ratepwrtbl_p);
	return retval;
}
#else
int WlLoadRateGrp(struct net_device *netdev)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = priv->wlpd_p;
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	MIB_PHY_DSSS_TABLE *PhyDSSSTable = mib->PhyDSSSTable;
	Info_rate_power_table_t *pInfo;
	BOOLEAN bSetPowerFail;
	UINT8 i, j, m;
	UINT8 k = 0;
	rate_power_table_t *ratepwrtbl_p;
	int retval = SUCCESS;

	ratepwrtbl_p = (rate_power_table_t *) wl_kmalloc(sizeof(rate_power_table_t), GFP_KERNEL);

	if (wlpd_p->AllChanGrpsPwrTbl.NumOfChan != 0) {
		k = 0;
		memset(ratepwrtbl_p, 0, sizeof(rate_power_table_t));
		for (m = 0; m < wlpd_p->AllChanGrpsPwrTbl.NumOfChan; m++) {
			if (wlpd_p->AllChanGrpsPwrTbl.PerChanGrpsPwrTbl[m].channel == PhyDSSSTable->CurrChan) {
				//printk("curr chan =%d \n", PhyDSSSTable->CurrChan);
				ratepwrtbl_p->channel = wlpd_p->AllChanGrpsPwrTbl.PerChanGrpsPwrTbl[m].channel;
				break;
			} else {
				continue;
			}

		}
		if (m == wlpd_p->AllChanGrpsPwrTbl.NumOfChan) {
			retval = FAIL;
			return retval;
		}
		for (j = 0; j < wlpd_p->AllChanGrpsPwrTbl.PerChanGrpsPwrTbl[m].NumOfGrpPerChan; j++) {
			if (wlpd_p->RateGrpDefault[j].NumOfEntry != 0) {
				for (i = 0; i < wlpd_p->RateGrpDefault[j].NumOfEntry; i++) {
					s8 Power;
					UINT8 temp;

					Power = wlpd_p->AllChanGrpsPwrTbl.PerChanGrpsPwrTbl[m].GrpsPwr[j];
					temp = (UINT8) Power;
					ratepwrtbl_p->NumOfEntry++;
					ratepwrtbl_p->RatePower[k] = wlpd_p->RateGrpDefault[j].AxAnt << 24 | temp << 16 |
					    wlpd_p->RateGrpDefault[j].Rate[i];
					k++;

				}
			} else {
				break;
			}
		}

	} else {
		//for Cisco power table

		for (i = 0; i < IEEE_80211_MAX_NUMBER_OF_CHANNELS; i++) {
			if (priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[i].channel == PhyDSSSTable->CurrChan) {
				if (priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[i].bValid) {
					memcpy((void *)ratepwrtbl_p, (void *)&priv->wlpd_p->AllChanPwrTbl.PerChanPwrTbl[i].PerChanPwr,
					       sizeof(rate_power_table_t));
					break;
				}
			}
		}
		if (i == IEEE_80211_MAX_NUMBER_OF_CHANNELS) {
			//printk("NO valid entry for barbado power table \n");
			return retval;
		}

	}
	pInfo = (Info_rate_power_table_t *) priv->wlpd_p->descData[0].pInfoPwrTbl;
	bSetPowerFail = TRUE;
	for (i = 0; i < 10; i++) {
		if (pInfo->DrvCnt == pInfo->FwCnt) {
			memcpy((void *)&pInfo->RatePwrTbl, (void *)ratepwrtbl_p, sizeof(rate_power_table_t));

			if (pInfo->DrvCnt == 0xFFFFFFFF) {
				pInfo->DrvCnt = 0;
			} else {
				pInfo->DrvCnt += 1;
			}
			wlFwSetPowerPerRate(netdev);
			bSetPowerFail = FALSE;
			break;
		} else {
			mdelay(10);	//10 msec
		}
	}
	if (bSetPowerFail) {
		printk("Fail to set power per rate\n");
		retval = FAIL;
		return retval;
	}

	wl_kfree(ratepwrtbl_p);
	return retval;
}
#endif

void eepromAction(struct net_device *netdev, UINT32 offset, UINT8 * data, UINT32 len, UINT16 action)
{
	UINT32 i, m, remainder;

	i = len / MAX_EEPROM_DATA;
	remainder = len % MAX_EEPROM_DATA;
	if (i == 0) {
		if (wlFwNewDP_eeprom(netdev, offset, data, remainder, action)) {
			printk(" eeprom action %d fail \n", action);
		}
	} else {
		for (m = 0; m < i; m++) {
			if (wlFwNewDP_eeprom(netdev, offset, data, MAX_EEPROM_DATA, action)) {
				printk(" eeprom action %d fail \n", action);
				return;
			}
			offset += MAX_EEPROM_DATA;
			data += MAX_EEPROM_DATA;
			mdelay(1);
		}
		if (remainder != 0) {
			if (wlFwNewDP_eeprom(netdev, offset, data, remainder, action)) {
				printk(" eeprom action %d fail \n", action);
			}
		}
	}
}

#ifdef OPENWRT
static int iwinfo_request_getstalistext(struct net_device *netdev, struct mwl_ioctl_response *response, int result_length)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	int rc = -1;
	UCHAR *sta_buf = NULL, *show_buf = NULL;
	int i;
	int entries = extStaDb_entries(vmacSta_p, 0);
	extStaDb_StaInfo_t *pStaInfo;

	if (!entries) {
		rc = 0;
		goto get_done;
	}
	sta_buf = wl_vzalloc(entries * sizeof(STA_INFO));
	if (!sta_buf || (result_length < (entries * 64)))
		goto get_done;

	extStaDb_list(vmacSta_p, sta_buf, 1);

	response->u.list.num = entries;
	if (entries) {
		show_buf = sta_buf;
		for (i = 0; i < entries; i++) {
			if (NULL == (pStaInfo = extStaDb_GetStaInfo(vmacSta_p, (IEEEtypes_MacAddr_t *) show_buf, STADB_DONT_UPDATE_AGINGTIME))) {
				goto get_done;
			}
			memcpy(response->u.list.entry[i].addr, pStaInfo->Addr, sizeof(pStaInfo->Addr));
			memcpy(response->u.list.entry[i].bssid, pStaInfo->Bssid, sizeof(pStaInfo->Bssid));
			response->u.list.entry[i].state = pStaInfo->State;
			response->u.list.entry[i].pwrmode = pStaInfo->PwrMode;
			response->u.list.entry[i].aid = pStaInfo->Aid;
			response->u.list.entry[i].clientmode = pStaInfo->ClientMode;
			response->u.list.entry[i].timestamp = pStaInfo->TimeStamp;
			response->u.list.entry[i].sq2 = pStaInfo->Sq2;
			response->u.list.entry[i].sq1 = pStaInfo->Sq1;
			response->u.list.entry[i].rate = pStaInfo->Rate;
			response->u.list.entry[i].rssi = pStaInfo->RSSI;
			response->u.list.entry[i].tx_rate.rate = getPhyRate((dbRateInfo_t *) & (pStaInfo->RateInfo)),
			    response->u.list.entry[i].tx_rate.mcs = pStaInfo->RateInfo.RateIDMCS,
			    response->u.list.entry[i].tx_rate.is_40mhz = (1 == pStaInfo->RateInfo.Bandwidth);
			response->u.list.entry[i].tx_rate.is_short_gi = (1 == pStaInfo->RateInfo.ShortGI);
			response->u.list.entry[i].tx_rate.is_ht = (0 != pStaInfo->RateInfo.Bandwidth);
			response->u.list.entry[i].tx_rate.is_vht = (2 == pStaInfo->RateInfo.Bandwidth);
			response->u.list.entry[i].tx_rate.nss = getNss((dbRateInfo_t *) & (pStaInfo->RateInfo));
			show_buf += sizeof(STA_INFO);
		}
	}
	rc = entries * sizeof(response->u.list.entry[0]) + sizeof(response->u.list.num);

 get_done:

	if (sta_buf)
		wl_vfree(sta_buf);
	return rc;

}

static int iwinfo_internal_update_auth_suite(struct mwl_ioctl_response *response, MIB_802DOT11 * mib)
{
	switch (mib->RSNConfigAuthSuites->AuthSuites[3]) {
	case 0:
		/*none */
		{
			response->u.encryption.auth_suites |= MWL_IWINFO_KMGMT_NONE;
		}
		break;
	case 1:
		/*802.1x */
		{
			response->u.encryption.auth_suites |= MWL_IWINFO_KMGMT_8021x;
		}
		break;
	case 2:
		 /*PSK*/ {
			response->u.encryption.auth_suites |= MWL_IWINFO_KMGMT_PSK;
		}
		break;
	default:
		{
			printk("[iwinfo]unknown auth_suites %u\n", mib->RSNConfigAuthSuites->AuthSuites[3]);
		}
	}
	return 0;
}

static int iwinfo_request_handler(struct net_device *netdev, MIB_802DOT11 * mib, int id, uint8_t * data_buffer, int data_length,
				  uint8_t * result_buffer, int result_length)
{
	int copy_size = 0;
	struct mwl_ioctl_request *request;
	struct mwl_ioctl_response *response;

	if (data_length < sizeof(struct mwl_ioctl_request)) {
		return -1;
	}
	if (result_length < sizeof(struct mwl_ioctl_response)) {
		return -1;
	}
	request = (struct mwl_ioctl_request *)data_buffer;
	response = (struct mwl_ioctl_response *)result_buffer;
	switch (id) {
	case MWL_IOCTL_ID_GET_MAGIC:
		{
#ifdef DEBUG_IWINFO
			printk("get magic command\n");
#endif
			response->magic = MWL_IOCTL_MAGIC;
			copy_size = 0;
		}
		break;
	case MWL_IOCTL_ID_GET_ASSOCLIST:
		{
#ifdef DEBUG_IWINFO
			printk("get getstalistext\n");
#endif
			response->magic = MWL_IOCTL_MAGIC;
			copy_size = iwinfo_request_getstalistext(netdev, response, result_length);
		}
		break;
	case MWL_IOCTL_ID_GET_HARDWAREID:
		{
#ifdef DEBUG_IWINFO
			printk("get hardwareid\n");
#endif
			response->magic = MWL_IOCTL_MAGIC;
			response->u.hardwareid.vendor_id = 0x11ab;
			response->u.hardwareid.device_id = 0x2a02;
			response->u.hardwareid.subsystem_vendor_id = 0x11ab;
			response->u.hardwareid.subsystem_device_id = 0x2a02;
			copy_size = sizeof(response->u.hardwareid);
		}
		break;
	case MWL_IOCTL_ID_GET_HARDWARENAME:
		{
#ifdef DEBUG_IWINFO
			printk("get hardwarename\n");
#endif
			response->magic = MWL_IOCTL_MAGIC;
			strncpy(response->u.hardwarename.cat, "11AX", sizeof(response->u.hardwarename.cat));
			strncpy(response->u.hardwarename.model, "88W906X", sizeof(response->u.hardwarename.model));
			copy_size = sizeof(response->u.hardwarename);
		}
		break;
	case MWL_IOCTL_ID_GET_ENCRYPTION:
		{
#ifdef DEBUG_IWINFO
			printk("get encryption\n");
#endif
			response->magic = MWL_IOCTL_MAGIC;
			memset(&(response->u.encryption), 0, sizeof(response->u.encryption));
			switch (*(mib->mib_wpaWpa2Mode) & 0xF) {
			case 0:
				/*disable */
				{
					copy_size = sizeof(response->u.encryption);
					if (mib->Privacy->PrivInvoked) {
						/*wep */
						response->u.encryption.enabled = 0;
						response->u.encryption.wpa_version = 0;
						switch (mib->AuthAlg->Type) {
						case 0:
							/*open */
							{
								response->u.encryption.auth_algs = MWL_IWINFO_AUTH_OPEN;
							}
							break;
						case 1:
							/*restricted */
							{
								response->u.encryption.auth_algs = MWL_IWINFO_AUTH_SHARED;
							}
							break;
						default:
							{
								printk("[iwinfo] unexpected auth_type: %u\n", mib->AuthAlg->Type);
							}
						}
						switch (mib->WepDefaultKeys[0].WepType) {
						case 0:
							/*not set */
							{
								printk("[iwinfo]unexpected wep type case\n");
							}
							break;
						case 1:
							/*40 bit */
							{
								response->u.encryption.pair_ciphers = MWL_IWINFO_CIPHER_WEP40;
								response->u.encryption.group_ciphers = MWL_IWINFO_CIPHER_WEP40;
							}
							break;
						case 2:
							/*104 bit */
							{
								response->u.encryption.pair_ciphers = MWL_IWINFO_CIPHER_WEP104;
								response->u.encryption.group_ciphers = MWL_IWINFO_CIPHER_WEP104;
							}
							break;
						default:
							{
								printk("[iwinfo]unexpected wep type: %u\n", mib->WepDefaultKeys[0].WepType);
							}
						}
					} else {
						/*no encryption */
						response->u.encryption.enabled = 0;
					}
				}
				break;
			case 1:	/*wpa */
			case 2:	/*wpa2 */
			case 3:	/*wpa2/wpa mixed */
			case 4:	/* hostapd configured */
				{
					copy_size = sizeof(response->u.encryption);
					response->u.encryption.enabled = 1;
					if (mib->RSNConfigWPA2->WPA2Enabled) {
						if (mib->RSNConfigWPA2->WPA2OnlyEnabled) {
							response->u.encryption.wpa_version = 2;
							if (mib->WPA2UnicastCiphers->UnicastCipher[3] == 0x04) {
								response->u.encryption.pair_ciphers |= MWL_IWINFO_CIPHER_CCMP;
							} else if (mib->WPA2UnicastCiphers->UnicastCipher[3] == 0x02) {
								response->u.encryption.pair_ciphers |= MWL_IWINFO_CIPHER_TKIP;
							}
							if (mib->RSNConfigWPA2->MulticastCipher[3] == 0x02) {
								response->u.encryption.group_ciphers |= MWL_IWINFO_CIPHER_TKIP;
							} else if (mib->RSNConfigWPA2->MulticastCipher[3] == 0x04) {
								response->u.encryption.group_ciphers |= MWL_IWINFO_CIPHER_CCMP;
							}
						} else {
							response->u.encryption.wpa_version = 3;
							if (mib->UnicastCiphers->UnicastCipher[3] == 0x02) {
								response->u.encryption.pair_ciphers |= MWL_IWINFO_CIPHER_TKIP;
							} else if (mib->UnicastCiphers->UnicastCipher[3] == 0x04) {
								response->u.encryption.pair_ciphers |= MWL_IWINFO_CIPHER_CCMP;
							}
							if (mib->WPA2UnicastCiphers->UnicastCipher[3] == 0x04) {
								response->u.encryption.pair_ciphers |= MWL_IWINFO_CIPHER_CCMP;
							} else if (mib->WPA2UnicastCiphers->UnicastCipher[3] == 0x02) {
								response->u.encryption.pair_ciphers |= MWL_IWINFO_CIPHER_TKIP;
							}
							if (mib->RSNConfig->MulticastCipher[3] == 0x02) {
								response->u.encryption.group_ciphers |= MWL_IWINFO_CIPHER_TKIP;
							} else if (mib->RSNConfig->MulticastCipher[3] == 0x04) {
								response->u.encryption.group_ciphers |= MWL_IWINFO_CIPHER_CCMP;
							}
						}
					} else {
						response->u.encryption.wpa_version = 1;
						if (mib->UnicastCiphers->UnicastCipher[3] == 0x02) {
							response->u.encryption.pair_ciphers |= MWL_IWINFO_CIPHER_TKIP;
						} else if (mib->UnicastCiphers->UnicastCipher[3] == 0x04) {
							response->u.encryption.pair_ciphers |= MWL_IWINFO_CIPHER_CCMP;
						}
						if (mib->RSNConfig->MulticastCipher[3] == 0x02) {
							response->u.encryption.group_ciphers |= MWL_IWINFO_CIPHER_TKIP;
						} else if (mib->RSNConfig->MulticastCipher[3] == 0x04) {
							response->u.encryption.group_ciphers |= MWL_IWINFO_CIPHER_CCMP;
						}
					}
					iwinfo_internal_update_auth_suite(response, mib);
				}
				break;
			default:
				{
					/*empty */
					copy_size = -1;
				}
			}
		}
		break;
	case MWL_IOCTL_ID_GET_HWMODE:
		{
#ifdef DEBUG_IWINFO
			printk("get hardwaremode\n");
#endif
			response->magic = MWL_IOCTL_MAGIC;
			response->u.hardwaremode.mode = *(mib->mib_ApMode);
			copy_size = sizeof(response->u.hardwaremode);
		}
		break;
	case MWL_IOCTL_ID_GET_HTMODE:
		{
			MIB_PHY_DSSS_TABLE *PhyDSSSTable = mib->PhyDSSSTable;
			printk("get htmode\n");
			response->magic = MWL_IOCTL_MAGIC;
			switch (PhyDSSSTable->Chanflag.ChnlWidth) {
			case CH_AUTO_WIDTH:
			case CH_10_MHz_WIDTH:
			case CH_20_MHz_WIDTH:
			case CH_40_MHz_WIDTH:
			case CH_80_MHz_WIDTH:
			case CH_5_MHz_WIDTH:
			case CH_160_MHz_WIDTH:
				{
					response->u.htbw.mode = PhyDSSSTable->Chanflag.ChnlWidth;
				}
				break;
			default:
				{
					printk("[iwinfo] unexpected htbw: %u\n", PhyDSSSTable->Chanflag.ChnlWidth);
				}
			}
			copy_size = sizeof(response->u.htbw);
		}
		break;
	case MWL_IOCTL_ID_GET_PHYNAME:
		{
			/*assume wdevXapX format */
			printk("get phyname\n");
			request->u.phyname.name[sizeof(request->u.phyname.name) - 1] = '\0';
			response->magic = MWL_IOCTL_MAGIC;
			strncpy(response->u.phyname.name, request->u.phyname.name, 5);	//the first 5 char
			response->u.phyname.name[5] = '\0';
			copy_size = 5 + 1;	//include '\0'
		}
		break;
	default:
		{
			printk("NOT support command");
		}
	}
	if (copy_size < 0) {
		return -1;
	} else {
		return sizeof(response->magic) + copy_size;
	}
}
#endif

extern void idx_test(struct net_device *netdev, long pktcnt, long pktsize, long txqid, long frameType);
extern int wlFwSetRTSRetry(struct net_device *netdev, int rts_retry);
extern int wlFwSetMUConfig(struct net_device *netdev, u32 corr_thr_decimal, u16 sta_cep_age_thr, u16 period_ms);
extern UINT32 GetCenterFreq(UINT32 ch, UINT32 bw);

#ifdef SOC_W906X
// => Move to drv_config.c later
int mwl_drv_set_wdevReset(struct net_device *netdev)
{
	printk("===> redownloading firmware now\n");
	wlFwHardResetAndReInit(netdev, 0);
	return 0;
}

int mwl_drv_set_wdevhalt(struct net_device *netdev)
{
	printk("===> %s is halted now\n", netdev->name);
	//only halt fw
	wlFwHardResetAndReInit(netdev, 1);
	return 0;
}
#else
#ifdef CFG80211
extern int mwl_drv_set_wdevReset(struct net_device *netdev);
#else
int mwl_drv_set_wdevReset(struct net_device *netdev)
{
	return 1;
};
#endif
#endif				//SOC_W906X
#ifdef NULLPKT_DBG
void show_nullpkt(struct wlprivate_data *wlpd_p)
{
	wlrxdesc_t l_nullpkt_cfhul[10];
	static U8 l_last_null_pkt[10][1024];
	int i;
	int maxcnt = (wlpd_p->rpkt_type_cnt.null_cnt < 10) ? (wlpd_p->rpkt_type_cnt.null_cnt) : 10;

	memcpy(l_nullpkt_cfhul, wlpd_p->nullpkt_cfhul, sizeof(wlrxdesc_t) * 10);
	memcpy(l_last_null_pkt, wlpd_p->last_null_pkt, sizeof(u8) * 10 * 1024);

	for (i = 0; i < maxcnt; i++) {
		wlrxdesc_t *cfh_ul = &l_nullpkt_cfhul[i];
		U16 pktlen = (cfh_ul->hdr.length < 1024) ? cfh_ul->hdr.length : 1024;
		printk("cfh-ul of null pkt: (%d)\n", i);
		mwl_hex_dump(&l_nullpkt_cfhul[i], sizeof(wlrxdesc_t));
		printk("null_pkt payload:\n");
		mwl_hex_dump(l_last_null_pkt[i], pktlen);
	}

	return;
}
#endif				//NULLPKT_DBG

void wlget_sw_version(struct wlprivate *priv, char *buf, int more)
{
#ifdef SOC_W906X
	UINT8 *pVer = (UINT8 *) & priv->hwData.fwReleaseNumber;
	UINT8 *pVerS = (UINT8 *) & priv->hwData.smacReleaseNumber;
	UINT8 *pPfwShal = (UINT8 *) & priv->hwData.ulShalVersion;
	UINT16 shalVersion = SMAC_HAL_VERSION;
	UINT8 *pfwRel = (UINT8 *) & priv->hwData.sfwReleaseNumber;
	U32 len = 0;
	U8 majorVer = 0, minorVer = 0, relVer = 0, patchVer = 0, pfwBuildVer = 0, drvBuildVer = 0;
	U8 pfwShalVer = 0, pfwShalSubVer = 0;
	U8 pfwMajorVer = 0, pfwRelVer = 0;
	U16 pfwVer = 0, drvVer = 0;
	UINT8 *ptr = NULL;

	if (!priv || !buf)
		return;

#ifdef MV_CPU_BE
	majorVer = *pVerS;
	minorVer = *(pVerS + 1);
	relVerS = *(pVerS + 2);
	patchVerS = *(pVerS + 3);
	pfwVer = *(pVer + 2) << 8 | *(pVer + 3);
	pfwBuildVer = *(pVer + 1);
	pfwShalVer = *pPfwShal;
	pfwShalSubVer = *(pPfwShal + 1)
	    pfwMajorVer = *pfwRel;
	pfwRelVer = *(pfwRel + 1);
#else
	majorVer = *(pVerS + 3);
	minorVer = *(pVerS + 2);
	relVer = *(pVerS + 1);
	patchVer = *pVerS;
	pfwVer = *(pVer + 1) << 8 | *pVer;
	pfwBuildVer = *(pVer + 2);
	pfwShalVer = *(pPfwShal + 1);
	pfwShalSubVer = *pPfwShal;
	pfwMajorVer = *(pfwRel + 3);
	pfwRelVer = *(pfwRel + 2);
#endif
	ptr = strchr(DRV_VERSION_SUFFIX, '.');
	if (ptr) {
		ptr++;
		ptr = strchr(ptr, '.');
	}
	if (ptr) {
		ptr++;
		drvVer = atoi(ptr);
		ptr = strchr(ptr, '.');
	}
	if (ptr) {
		ptr++;
		drvBuildVer = atoi(ptr);
	}

	if (minorVer > 1) {
		sprintf(buf, "\n\n%d.%d.%d.%d-P%04d.%02d-D%04d.%02d\n",
			majorVer, minorVer, relVer, patchVer, pfwVer, pfwBuildVer, drvVer, drvBuildVer);
	} else {
		sprintf(buf, "\n\n%d.%d.%d.%d-P%04d-D%04d\n", majorVer, minorVer, relVer, patchVer, pfwVer, drvVer);
	}

	len = strlen(buf);

	if (more) {
		sprintf(buf + len,
			"\n\nDriver  : %s%s\t[SHAL %x.%x] \nFirmware: %d.%d.%04d.%02d \t\t[SHAL %x.%x]\nMAC    : %d.%d.%d.%d\t\t[SHAL %x.%x]\n",
			wfa_11ax_pf ? "WFA_" : "", DRV_VERSION, ((shalVersion & 0xff00) >> 8), (shalVersion & 0xff), pfwMajorVer, pfwRelVer, pfwVer,
			pfwBuildVer, pfwShalVer, pfwShalSubVer, majorVer, minorVer, relVer, patchVer, pfwShalVer, pfwShalSubVer);
	}
#else
	UINT8 *pVer = (UINT8 *) & priv->hwData.fwReleaseNumber;
#ifdef MV_CPU_BE
	sprintf(buf, "Driver version: %s, Firmware version: %d.%d.%d.%d\n", DRV_VERSION, *pVer, *(pVer + 1), *(pVer + 2), *(pVer + 3));
#else
	sprintf(buf, "Driver version: %s, Firmware version: %d.%d.%d.%d\n", DRV_VERSION, *(pVer + 3), *(pVer + 2), *(pVer + 1), *pVer);
#endif
#endif
}

extern void get_info(struct net_device *netdev);
UINT32 quiet_dbg[10] = { 0 };

extern cbinfo_sta_t g_dbg_cbinfo_sta;
static u8 mcpkt_tmp[] = {
	'\x01', '\x00', '\x5e', '\x00', '\x00', '\x05', '\x00', '\x50', '\x43', '\xcb', '\xcb', '\xcb', '\x08', '\x00', '\x45', '\x00',
	'\x00', '\x5c', '\x71', '\x14', '\x40', '\x00', '\x01', '\x11', '\x65', '\xcd', '\xc0', '\xa8', '\x01', '\x02', '\xe1', '\x00',
	'\x00', '\x05', '\xcf', '\xf7', '\x13', '\x89', '\x00', '\x48', '\xcd', '\x61', '\x00', '\x00', '\x07', '\xa5', '\x88', '\x83',
	'\x3e', '\xe8', '\x00', '\x08', '\x1e', '\x08', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x01', '\x00', '\x00',
	'\x13', '\x89', '\x00', '\x00', '\x00', '\x40', '\x00', '\x00', '\x00', '\x00', '\xff', '\xff', '\xfc', '\x18', '\x00', '\x0f',
	'\x42', '\x40', '\x30', '\x31', '\x32', '\x33', '\x34', '\x35', '\x36', '\x37', '\x38', '\x39', '\x30', '\x31', '\x32', '\x33',
	'\x34', '\x35', '\x36', '\x37', '\x38', '\x39', '\x30', '\x31', '\x32', '\x33',
};

void mcpkt_test_tmfunc(unsigned long arg)
{
	struct net_device *netdev = (struct net_device *)arg;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	static u16 sn = 0, iv = 0;
	struct sk_buff *txSkb_p;

	//printk("==>%s(), %u\n", __func__, wlpptr->mctest_cnt);
	if (wlpptr->mctest_sngap > 0) {
		sn += wlpptr->mctest_sngap;
		printk("==>%s(), Add gap:%u, => sn: %u\n", __func__, wlpptr->mctest_sngap, sn);
		wlpptr->mctest_sngap = 0;
	}
	//Using the same number to test
	iv = sn;
	// Test sending mcast packets
	txSkb_p = wl_alloc_skb(sizeof(mcpkt_tmp) + 256);
	skb_reserve(txSkb_p, (SKB_INFO_SIZE + 14));	// reserve 8 bytes for skb virtual address and 14 bytes for ether hdr
	skb_put(txSkb_p, sizeof(mcpkt_tmp));
	memcpy(txSkb_p->data, mcpkt_tmp, sizeof(mcpkt_tmp));
	printk("(sn, iv)=(%u, %u), mcpkt[%lu]\n", sn, iv, sizeof(mcpkt_tmp));
	send_mcast_pkt(netdev, txSkb_p, iv, sn++);
	wlpptr->mctest_cnt--;
	if (wlpptr->mctest_cnt > 0) {
		// More mc_pkts to be sent
		TimerFireIn(&wlpptr->cb_mctmer, 1, &mcpkt_test_tmfunc, (void *)wlpptr->netDev, 1);
	}
	return;
}

static u16 ap8x_anpi_conversion(u32 noise)
{
	if (noise >= 110)
		return 0;
	else
		return (2 * (110 - noise));
}

int wlIoctlSet(struct net_device *netdev, int cmd, char *param_str, int param_len, char *ret_str, UINT16 * ret_len)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	int rc = 0;
	char *bufBack = cmdGetBuf;
	struct wlprivate_data *wlpd_p = priv->wlpd_p;
#ifdef SOC_W906X
	static char logbuf[256];
#endif				//SOC_W906X
	UINT32 size;

#ifdef MRVL_WPS_CLIENT
	UINT8 desireBSSID[6];
	int count = 0;
	char *ptr = NULL;
#endif
	char (*param)[66] = wl_kzalloc(sizeof(*param) * MAX_GROUP_PER_CHANNEL, GFP_KERNEL);

	WLDBG_ENTER(DBG_LEVEL_1);
	if (param == NULL) {
		rc = -EFAULT;
		return rc;
	}

	if (is_the_cmd_applicable(cmd) && priv->master) {
		rc = -EOPNOTSUPP;
		wl_kfree(param);
		return rc;
	}

	if (ret_str != NULL) {
		//ret_str[0] = '\0';
		cmdGetBuf[0] = '\0';
		*ret_len = 1;
	}

	WLDBG_IOCTL(DBG_LEVEL_0, "%s:wlioctl cmd:0x%x, CpuID:%u, PID:%i, ProcName:\"%s\"\n",
		    netdev->name, cmd, smp_processor_id(), current->pid, current->comm);

#ifdef SOC_W906X
	if (wlpd_p->smon.active) {
		UINT64 tsec, tms;

		convert_tscale(xxGetTimeStamp(), &tsec, &tms, NULL);
		size = (UINT32) sprintf(&logbuf[0], "[%llu.%llu]: %s:wlioctl cmd:0x%x, CpuID:%u, PID:%i, ProcName:\"%s\"\n", tsec, tms,
					netdev->name, cmd, smp_processor_id(), current->pid, current->comm);
		wlmon_log_buffer(netdev, logbuf, size);
	}
#endif

	switch (cmd) {
	case WL_IOCTL_SET_TXRATE:
		{
			int rate = 2;
#ifdef BRS_SUPPORT
			UINT32 rateMask = 0;
			UCHAR i;
			UCHAR len = 0;
			UCHAR *ptr;

			/* get arg numbers */
			ptr = param_str;
			while ((*ptr != 0)) {

				while ((*ptr != ' ') && (*ptr != 0)) {
					ptr++;
				}
				if (*ptr == 0)
					break;

				len++;

				while ((*ptr == ' ') && (*ptr != 0)) {
					ptr++;
				}
			}
			//printk("len %d\n", len);
#endif
			sscanf(param_str, "%64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s\n",
			       param[0], param[1], param[2], param[3], param[4], param[5], param[6], param[7], param[8], param[9], param[10],
			       param[11], param[12], param[13]);

			rate = atoi(param[1]);

			if (strcmp(param[0], "b") == 0) {
				if (!rateChecked(rate, AP_MODE_B_ONLY)) {
					rc = -EFAULT;
					break;
				}
				PRINT1(IOCTL, "%d\n", rate);

				*(mib->mib_txDataRate) = (UCHAR) rate;
				*(mib->mib_FixedRateTxType) = 0;
			} else if (strcmp(param[0], "g") == 0) {
				if (!rateChecked(rate, AP_MODE_G_ONLY)) {
					rc = -EFAULT;
					break;
				}
				PRINT1(IOCTL, "%d\n", rate);

				*(mib->mib_txDataRateG) = (UCHAR) rate;
				*(mib->mib_FixedRateTxType) = 0x10;
			} else if (strcmp(param[0], "n") == 0) {
				if ((rate > 271) && !(*(mib->mib_3x3Rate))) {
					rc = -EFAULT;
					break;
				}
				if (!rateChecked(rate, AP_MODE_N_ONLY)) {
					rc = -EFAULT;
					break;
				}
				PRINT1(IOCTL, "%d\n", rate);

				*(mib->mib_txDataRateN) = (UCHAR) rate;
				*(mib->mib_FixedRateTxType) = 0x1;

			} else if (strcmp(param[0], "a") == 0) {
				if (!rateChecked(rate, AP_MODE_A_ONLY)) {
					rc = -EFAULT;
					break;
				}

				PRINT1(IOCTL, "%d\n", rate);

				*(mib->mib_txDataRateA) = (UCHAR) rate;
				*(mib->mib_FixedRateTxType) = 0x20;

			} else if (strcmp(param[0], "mcbc") == 0) {

				if (rate > 0x1ff) {
					/*VHT MCS rate:
					 * 512 (0x200 NSS1_MCS0), 513 (0x201 NSS1_MCS1), 514 (0x202 NSS1_MCS2)...
					 * 528 (0x210 NSS2_MCS0), 529 (0x211 NSS2_MCS1), 530 (0x212 NSS2_MCS2)...
					 * 544 (0x220 NSS3_MCS0), 545 (0x221 NSS3_MCS1), 546 (0x222 NSS3_MCS2)...
					 */
					if (!rateChecked(rate, AP_MODE_11AC)) {
						rc = -EFAULT;
						break;
					}
					*(mib->mib_MultiRateTxType) = 2;
				} else if (rate > 0xff) {
					/* HT MCS rate: 256 (0x100 MCS0), 257(0x101 MCS1), 258(0x102 MCS2) .... */
					if (!rateChecked(rate, AP_MODE_N_ONLY)) {
						rc = -EFAULT;
						break;
					}
					*(mib->mib_MultiRateTxType) = 1;
				} else {	/* G rate: 2, 4, 11, 22, 44, 12, 18, 24, 36, 48, 72, 96, 108, 144 */
					if (!rateChecked(rate, AP_MODE_G_ONLY)) {
						rc = -EFAULT;
						break;
					}
					*(mib->mib_MultiRateTxType) = 0;
				}

				PRINT1(IOCTL, "%d\n", rate);

				*(mib->mib_MulticastRate) = (UCHAR) rate;

			} else if (strcmp(param[0], "mgt") == 0) {
				if (!rateChecked(rate, AP_MODE_G_ONLY)) {
					rc = -EFAULT;
					break;
				}

				PRINT1(IOCTL, "%d\n", rate);

				*(mib->mib_ManagementRate) = (UCHAR) rate;
			}
#ifdef BRS_SUPPORT
			else if ((strcmp(param[0], "brs") == 0) || (strcmp(param[0], "srs") == 0)) {
				if (len > 12) {
					rc = -EFAULT;
					break;
				}

				for (i = 0; i < len; i++) {

					rate = atoi(param[1 + i]);

					if (!rateChecked(rate, AP_MODE_G_ONLY)) {
						rc = -EFAULT;
						break;
					}
					IEEEToMrvlRateBitMapConversion((UCHAR) rate, &rateMask);
				}
				if (rc == -EFAULT)
					break;

				if (strcmp(param[0], "brs") == 0) {
					*(mib->BssBasicRateMask) = rateMask;
					(*(mib->NotBssBasicRateMask)) &= ~rateMask;
				} else {
					if ((rateMask | ~(*(mib->BssBasicRateMask))) & *(mib->BssBasicRateMask)) {
						/* some basic rate is added */
						rc = -EFAULT;
						break;
					}
					*(mib->NotBssBasicRateMask) = rateMask;
				}
			}
#endif
			else if ((strcmp(param[0], "vht") == 0)) {
				rate = atohex2(param[1]);
				if (!rateChecked(rate, AP_MODE_11AC)) {
					rc = -EFAULT;
					break;
				}
				*(mib->mib_txDataRateVHT) = (UCHAR) rate;
				*(mib->mib_FixedRateTxType) = 0x2;

			}
			//rateinfo
			else if ((strcmp(param[0], "ri") == 0)) {
				rate = atohex2(param[1]);

				*(mib->mib_txDataRateInfo) = rate;
				*(mib->mib_FixedRateTxType) = 0x4;
			}
#ifdef CONFIG_MC_BC_RATE
			else if ((strcmp(param[0], "mc_ri") == 0)) {
				rate = atohex2(param[1]);

				*(mib->mib_mcDataRateInfo) = rate;
			} else if ((strcmp(param[0], "bc_ri") == 0)) {
				rate = atohex2(param[1]);

				*(mib->mib_bcDataRateInfo) = rate;
			}
#endif
			else {
				rc = -EFAULT;
				break;
			}
		}
		break;

	case WL_IOCTL_SET_CIPHERSUITE:
		{
			sscanf(param_str, "%64s %64s\n", param[0], param[1]);

			if (strcmp(param[0], "wpa") == 0) {
				if (strcmp(param[1], "tkip") == 0) {
					*(mib->mib_cipherSuite) = 2;

					mib->RSNConfig->MulticastCipher[0] = 0x00;
					mib->RSNConfig->MulticastCipher[1] = 0x50;
					mib->RSNConfig->MulticastCipher[2] = 0xF2;
					mib->RSNConfig->MulticastCipher[3] = IEEEtypes_RSN_CIPHER_SUITE_TKIP;

					mib->UnicastCiphers->UnicastCipher[0] = 0x00;
					mib->UnicastCiphers->UnicastCipher[1] = 0x50;
					mib->UnicastCiphers->UnicastCipher[2] = 0xF2;
					mib->UnicastCiphers->UnicastCipher[3] = IEEEtypes_RSN_CIPHER_SUITE_TKIP;
					mib->UnicastCiphers->Enabled = TRUE;

				} else if (strcmp(param[1], "aes-ccmp") == 0) {
					*(mib->mib_cipherSuite) = IEEEtypes_RSN_CIPHER_SUITE_CCMP;

					mib->RSNConfig->MulticastCipher[0] = 0x00;
					mib->RSNConfig->MulticastCipher[1] = 0x50;
					mib->RSNConfig->MulticastCipher[2] = 0xF2;
					if (mib->RSNConfigWPA2->WPA2Enabled && !mib->RSNConfigWPA2->WPA2OnlyEnabled) {
						mib->RSNConfig->MulticastCipher[3] = IEEEtypes_RSN_CIPHER_SUITE_TKIP;
					} else {
						mib->RSNConfig->MulticastCipher[3] = IEEEtypes_RSN_CIPHER_SUITE_CCMP;
					}

					mib->UnicastCiphers->UnicastCipher[0] = 0x00;
					mib->UnicastCiphers->UnicastCipher[1] = 0x50;
					mib->UnicastCiphers->UnicastCipher[2] = 0xF2;
					mib->UnicastCiphers->UnicastCipher[3] = IEEEtypes_RSN_CIPHER_SUITE_CCMP;
					mib->UnicastCiphers->Enabled = TRUE;
				} else {
					rc = -EFAULT;
				}

				PRINT1(IOCTL, "mib->RSNConfig->MulticastCipher: %02x %02x %02x %02x\n",
				       mib->RSNConfig->MulticastCipher[0],
				       mib->RSNConfig->MulticastCipher[1], mib->RSNConfig->MulticastCipher[2], mib->RSNConfig->MulticastCipher[3]);
				PRINT1(IOCTL, "mib->RSNConfig->UnicastCiphers: %02x %02x %02x %02x\n",
				       mib->UnicastCiphers->UnicastCipher[0],
				       mib->UnicastCiphers->UnicastCipher[1],
				       mib->UnicastCiphers->UnicastCipher[2], mib->UnicastCiphers->UnicastCipher[3]);
				PRINT1(IOCTL, "mib->UnicastCiphers->Enabled %d\n", mib->UnicastCiphers->Enabled);
			} else if (strcmp(param[0], "wpa2") == 0) {
				if (strcmp(param[1], "aes-ccmp") == 0) {
					mib->RSNConfigWPA2->MulticastCipher[0] = 0x00;
					mib->RSNConfigWPA2->MulticastCipher[1] = 0x0F;
					mib->RSNConfigWPA2->MulticastCipher[2] = 0xAC;
					if (mib->RSNConfigWPA2->WPA2Enabled && !mib->RSNConfigWPA2->WPA2OnlyEnabled) {
						mib->RSNConfigWPA2->MulticastCipher[3] = IEEEtypes_RSN_CIPHER_SUITE_TKIP;
					} else {
						mib->RSNConfigWPA2->MulticastCipher[3] = IEEEtypes_RSN_CIPHER_SUITE_CCMP;
					}
					*(mib->mib_cipherSuite) = IEEEtypes_RSN_CIPHER_SUITE_CCMP;

					mib->WPA2UnicastCiphers->UnicastCipher[0] = 0x00;
					mib->WPA2UnicastCiphers->UnicastCipher[1] = 0x0F;
					mib->WPA2UnicastCiphers->UnicastCipher[2] = 0xAC;
					mib->WPA2UnicastCiphers->UnicastCipher[3] = IEEEtypes_RSN_CIPHER_SUITE_CCMP;
					mib->WPA2UnicastCiphers->Enabled = TRUE;

				} else if (strcmp(param[1], "aes-ccmp-256") == 0) {

					mib->RSNConfigWPA2->MulticastCipher[0] = 0x00;
					mib->RSNConfigWPA2->MulticastCipher[1] = 0x0F;
					mib->RSNConfigWPA2->MulticastCipher[2] = 0xAC;
					mib->RSNConfigWPA2->MulticastCipher[3] = IEEEtypes_RSN_CIPHER_SUITE_CCMP_256;	// CCMP-256

					*(mib->mib_cipherSuite) = IEEEtypes_RSN_CIPHER_SUITE_CCMP_256;

					mib->WPA2UnicastCiphers->UnicastCipher[0] = 0x00;
					mib->WPA2UnicastCiphers->UnicastCipher[1] = 0x0F;
					mib->WPA2UnicastCiphers->UnicastCipher[2] = 0xAC;
					mib->WPA2UnicastCiphers->UnicastCipher[3] = IEEEtypes_RSN_CIPHER_SUITE_CCMP_256;	// CCMP-256
					mib->WPA2UnicastCiphers->Enabled = TRUE;
				} else if (strcmp(param[1], "aes-gcmp") == 0) {
					mib->RSNConfigWPA2->MulticastCipher[0] = 0x00;
					mib->RSNConfigWPA2->MulticastCipher[1] = 0x0F;
					mib->RSNConfigWPA2->MulticastCipher[2] = 0xAC;
					mib->RSNConfigWPA2->MulticastCipher[3] = IEEEtypes_RSN_CIPHER_SUITE_GCMP;	// GCMP-128

					*(mib->mib_cipherSuite) = IEEEtypes_RSN_CIPHER_SUITE_GCMP;

					mib->WPA2UnicastCiphers->UnicastCipher[0] = 0x00;
					mib->WPA2UnicastCiphers->UnicastCipher[1] = 0x0F;
					mib->WPA2UnicastCiphers->UnicastCipher[2] = 0xAC;
					mib->WPA2UnicastCiphers->UnicastCipher[3] = IEEEtypes_RSN_CIPHER_SUITE_GCMP;	// GCMP-128
					mib->WPA2UnicastCiphers->Enabled = TRUE;
				} else if (strcmp(param[1], "aes-gcmp-256") == 0) {
					mib->RSNConfigWPA2->MulticastCipher[0] = 0x00;
					mib->RSNConfigWPA2->MulticastCipher[1] = 0x0F;
					mib->RSNConfigWPA2->MulticastCipher[2] = 0xAC;
					mib->RSNConfigWPA2->MulticastCipher[3] = IEEEtypes_RSN_CIPHER_SUITE_GCMP_256;	// GCMP-256

					*(mib->mib_cipherSuite) = IEEEtypes_RSN_CIPHER_SUITE_GCMP_256;

					mib->WPA2UnicastCiphers->UnicastCipher[0] = 0x00;
					mib->WPA2UnicastCiphers->UnicastCipher[1] = 0x0F;
					mib->WPA2UnicastCiphers->UnicastCipher[2] = 0xAC;
					mib->WPA2UnicastCiphers->UnicastCipher[3] = IEEEtypes_RSN_CIPHER_SUITE_GCMP_256;	// GCMP-256
					mib->WPA2UnicastCiphers->Enabled = TRUE;
				} else if (strcmp(param[1], "tkip") == 0) {
					mib->RSNConfigWPA2->MulticastCipher[0] = 0x00;
					mib->RSNConfigWPA2->MulticastCipher[1] = 0x0F;
					mib->RSNConfigWPA2->MulticastCipher[2] = 0xAC;
					mib->RSNConfigWPA2->MulticastCipher[3] = IEEEtypes_RSN_CIPHER_SUITE_TKIP;	// TKIP

					*(mib->mib_cipherSuite) = IEEEtypes_RSN_CIPHER_SUITE_TKIP;

					mib->WPA2UnicastCiphers->UnicastCipher[0] = 0x00;
					mib->WPA2UnicastCiphers->UnicastCipher[1] = 0x0F;
					mib->WPA2UnicastCiphers->UnicastCipher[2] = 0xAC;
					mib->WPA2UnicastCiphers->UnicastCipher[3] = IEEEtypes_RSN_CIPHER_SUITE_TKIP;	// TKIP
					mib->WPA2UnicastCiphers->Enabled = TRUE;
				} else {
					rc = -EFAULT;
				}

				PRINT1(IOCTL, "mib->RSNConfigWPA2->MulticastCipher: %02x %02x %02x %02x\n",
				       mib->RSNConfigWPA2->MulticastCipher[0],
				       mib->RSNConfigWPA2->MulticastCipher[1],
				       mib->RSNConfigWPA2->MulticastCipher[2], mib->RSNConfigWPA2->MulticastCipher[3]);
				PRINT1(IOCTL, "mib->WPA2UnicastCiphers->UnicastCiphers: %02x %02x %02x %02x\n",
				       mib->WPA2UnicastCiphers->UnicastCipher[0],
				       mib->WPA2UnicastCiphers->UnicastCipher[1],
				       mib->WPA2UnicastCiphers->UnicastCipher[2], mib->WPA2UnicastCiphers->UnicastCipher[3]);
				PRINT1(IOCTL, "mib->WPA2UnicastCiphers->Enabled %d\n", mib->WPA2UnicastCiphers->Enabled);

			} else {
				rc = -EFAULT;
			}

			PRINT1(IOCTL, "*(mib->mib_cipherSuite): %d\n", *(mib->mib_cipherSuite));
		}
		break;

	case WL_IOCTL_SET_PASSPHRASE:
		sscanf(param_str, "%64s %64s\n", param[0], param[1]);

		if (strcmp(param[0], "wpa") == 0) {
			char *p;
			int len;

			p = strstr(param_str, "wpa");
			p += 4;
			len = strlen(p);
			if ((len <= 7) || (len > 64))
			{
				rc = -EFAULT;
				break;
			}
			if (len == 64) {
				if (!IsHexKey(p)) {
					rc = -EFAULT;
					break;
				}
				memset(mib->RSNConfig->PSKValue, 0, 32);
				HexStringToHexDigi(mib->RSNConfig->PSKValue, p, 32);
				memset(mib->RSNConfig->PSKPassPhrase, 0, sizeof(mib->RSNConfig->PSKPassPhrase));
				strcpy(mib->RSNConfig->PSKPassPhrase, p);

				*(mib->mib_WPAPSKValueEnabled) = 1;
				break;
			}

			memset(mib->RSNConfig->PSKPassPhrase, 0, sizeof(mib->RSNConfig->PSKPassPhrase));
			strcpy(mib->RSNConfig->PSKPassPhrase, p);
			PRINT1(IOCTL, "mib->RSNConfig->PSKPassPhrase: %s\n", mib->RSNConfig->PSKPassPhrase);
		} else if (strcmp(param[0], "wpa2") == 0) {
			char *p;
			int len;

			p = strstr(param_str, "wpa2");
			p += 5;
			len = strlen(p);
			if ((len <= 7) || (len > 64))
			{
				rc = -EFAULT;
				break;
			}
			if (len == 64) {
				if (!IsHexKey(p)) {
					rc = -EFAULT;
					break;
				}
				memset(mib->RSNConfigWPA2->PSKValue, 0, 32);
				HexStringToHexDigi(mib->RSNConfigWPA2->PSKValue, p, 32);
				memset(mib->RSNConfigWPA2->PSKPassPhrase, 0, 65);
				strcpy(mib->RSNConfigWPA2->PSKPassPhrase, p);

				*(mib->mib_WPA2PSKValueEnabled) = 1;
				break;
			}

			memset(mib->RSNConfigWPA2->PSKPassPhrase, 0, 65);
			strcpy(mib->RSNConfigWPA2->PSKPassPhrase, p);
			PRINT1(IOCTL, "mib->RSNConfigWPA2->PSKPassPhrase: %s\n", mib->RSNConfigWPA2->PSKPassPhrase);
		} else
			rc = -EFAULT;

		break;

	case WL_IOCTL_SET_FILTERMAC:
		{
			UINT8 *mib_wlanfilterno_p = mib->mib_wlanfilterno;
			UINT8 MacAddr[6], i, SameMAC = 0;

			sscanf(param_str, "%64s %64s\n", param[0], param[1]);

			if (strcmp(param[0], "deleteall") == 0) {
				*mib_wlanfilterno_p = 0;
				memset(mib->mib_wlanfiltermac, 0, FILERMACNUM * 6);
				break;
			}

			if ((strlen((char *)param[1]) != 12) || (!IsHexKey((char *)param[1]))) {
				rc = -EFAULT;
				break;
			}
			getMacFromString(MacAddr, param[1]);

			if (strcmp(param[0], "add") == 0) {

				for (i = 0; i < FILERMACNUM; i++) {
					if (memcmp(mib->mib_wlanfiltermac + i * 6, MacAddr, 6) == 0) {
						SameMAC = 1;
						break;
					}
				}

				if (SameMAC == 0) {
					if (*mib_wlanfilterno_p < FILERMACNUM) {
						memcpy((mib->mib_wlanfiltermac + *mib_wlanfilterno_p * 6), MacAddr, 6);
						(*mib_wlanfilterno_p)++;
					} else
						rc = -EFAULT;
				}
			} else if (strcmp(param[0], "del") == 0) {
				for (i = 0; i < FILERMACNUM; i++) {
					if (memcmp(mib->mib_wlanfiltermac + i * 6, MacAddr, 6) == 0) {
						(*mib_wlanfilterno_p)--;
						if (*mib_wlanfilterno_p == 0) {
							if (i != 0) {
								rc = -EFAULT;
								break;
							} else
								memset(mib->mib_wlanfiltermac, 0, 6);
						} else {
							if (i > *mib_wlanfilterno_p) {
								rc = -EFAULT;
								break;
							} else {
								memcpy(mib->mib_wlanfiltermac + i * 6, mib->mib_wlanfiltermac + ((i + 1) * 6),
								       (*mib_wlanfilterno_p - i) * 6);
								memset(mib->mib_wlanfiltermac + *mib_wlanfilterno_p * 6, 0, 6);
							}
						}
						break;
					}
				}
			} else
				rc = -EFAULT;
		}
		break;

	case WL_IOCTL_SET_BSSID:
		{
			MIB_OP_DATA *mib_OpData = mib->OperationTable;
			UINT8 MacAddr[6];

			sscanf(param_str, "%64s\n", param[0]);

			if (strlen((char *)param[0]) != 12) {
				rc = -EFAULT;
				break;
			}
			getMacFromString(MacAddr, param[0]);
			memcpy(mib_OpData->StaMacAddr, MacAddr, 6);
			memcpy(netdev->dev_addr, MacAddr, 6);

			/*Unlike vmac, parent interface macBssId is not updated in SendStartCmd. So we update here */
			if (priv->master == NULL)
				memcpy(vmacSta_p->macBssId, MacAddr, 6);

		}
		break;

#ifdef CLIENT_SUPPORT
	case WL_IOCTL_SET_CLIENT:
		{
			/* Set this mib to control mode of 11a, 11b, 11g, 11n, */
			extern const char *mac_display(const UINT8 * mac);
			UINT8 clientAddr[6];
			UINT8 enable;
			struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
			vmacApInfo_t *vmacSta_p;
			vmacEntry_t *vmacEntry_p = NULL;
			struct wlprivate *wlMPrvPtr = wlpptr;
			UINT8 mlmeAssociatedFlag;
			UINT8 mlmeBssid[6];

			/* Get VMAC structure of the master */
			if (!wlpptr->master) {
				printk("Device %s is not a client device \n", netdev->name);
				rc = -EFAULT;
				break;
			}

			vmacSta_p = wlMPrvPtr->vmacSta_p;

			sscanf(param_str, "%64s %64s \n", param[0], param[1]);

			enable = atohex(param[0]);

			if (enable == 0) {
				*(mib->mib_STAMacCloneEnable) = 0;
				//printk("maccloneing disabled mib_STAMacCloneEnable = %x \n", *(mib->mib_STAMacCloneEnable));
			} else if (enable == 1) {
				*(mib->mib_STAMacCloneEnable) = 1;
				//printk("maccloneing enabled mib_STAMacCloneEnable = %x \n", *(mib->mib_STAMacCloneEnable));
				break;
			} else {
				printk("macclone: invalid set option. \n");
				rc = -EFAULT;
				break;
			}

			if ((vmacEntry_p = sme_GetParentVMacEntry(((vmacApInfo_t *) priv->vmacSta_p)->VMacEntry.phyHwMacIndx)) == NULL)
				break;

			smeGetStaLinkInfo(vmacEntry_p->id, &mlmeAssociatedFlag, &mlmeBssid[0]);
			wlFwRemoveMacAddr(vmacSta_p->dev, &vmacEntry_p->vmacAddr[0]);
			if (mlmeAssociatedFlag)
				cleanupAmpduTx(vmacSta_p, (UINT8 *) & mlmeBssid[0]);

			if (strlen((char *)param[1]) == 12) {
				getMacFromString(clientAddr, param[1]);
				memcpy(&vmacEntry_p->vmacAddr[0], clientAddr, 6);
			} else {

				/*The method to generate wdev0sta0 mac addr is same as in wlInit for client */
				/*If GUI is used to config client, it comes to here too and we have to assign correct wdev0sta0 mac addr */
				/*eventhough it is already initialized in wlInit */
				int i, index, bssidmask = 0;
				UINT8 macaddr[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
				memcpy(macaddr, wlpptr->master->dev_addr, 6);
#if defined(MBSS)
				//for (index = 0; index < NUMOFAPS; index++)
				for (index = 0; index < wlpptr->wlpd_p->NumOfAPs; index++)
#else
				for (index = 0; index < 1; index++)
#endif
				{
#ifdef SOC_W906X
					if (!use_localadmin_addr)
#else				/* SOC_W906X */
					if (1)
#endif				/* SOC_W906X */
						macaddr[5] = wlpptr->master->dev_addr[5] + ((index + 1) & 0xf);
					else {
						/* uses mac addr bit 41 & up as mbss addresses */
						for (i = 1; i < 32; i++) {
							if ((bssidmask & (1 << i)) == 0)
								break;
						}
						if (i) {
							macaddr[0] = wlpptr->master->dev_addr[0] | ((i << 2) | 0x2);
						}
						bssidmask |= 1 << i;
					}
				}
#ifdef SOC_W906X
				if (!use_localadmin_addr)
#endif
					macaddr[0] |= 0x02;	//Usse local administration bit for STA 

				memcpy(&vmacEntry_p->vmacAddr[0], &macaddr[0], 6);

			}

			/*If we change wdev0sta0 mac addr, we also change these areas. */
			/*macStaAddr is used for mac addr comparison in tx and rx */
			memcpy(netdev->dev_addr, &vmacEntry_p->vmacAddr[0], 6);
			memcpy(&wlpptr->hwData.macAddr[0], &vmacEntry_p->vmacAddr[0], 6);
			memcpy(&vmacSta_p->macStaAddr[0], &vmacEntry_p->vmacAddr[0], 6);
			memcpy(&vmacSta_p->macBssId[0], &vmacEntry_p->vmacAddr[0], 6);
			memcpy(&vmacSta_p->VMacEntry.vmacAddr[0], &vmacEntry_p->vmacAddr[0], 6);

			printk("Mac cloning disabled : Mac Client Addr = %s\n", mac_display(&vmacEntry_p->vmacAddr[0]));

		}
		break;
#endif				/* CLIENT_SUPPORT */

#ifdef WDS_FEATURE
	case WL_IOCTL_SET_WDS_PORT:
		{
			UINT8 MacAddr[6], index = 0;
			UINT32 wdsPortMode = 0;
			sscanf(param_str, "%64s %64s %64s\n", param[0], param[1], param[2]);

			if (strlen((char *)param[0]) == 3) {
				if (strcmp(param[0], "off") == 0) {
					*(mib->mib_wdsEnable) = 0;
				} else
					rc = -EFAULT;
				break;
			}
			if ((strlen((char *)param[1]) != 12) || (!IsHexKey((char *)param[1]))) {
				rc = -EFAULT;
				break;
			}
			if (!getMacFromString(MacAddr, param[1])) {
				rc = -EFAULT;
				break;
			}

			if (strlen((char *)param[0]) != 1) {
				rc = -EFAULT;
				break;
			}
			index = atoi(param[0]);

			if (strlen((char *)param[2]) != 1) {
				if (strlen((char *)param[2]) == 3) {
					if (strcmp((char *)param[2], "ac1") == 0) {
						wdsPortMode = AC_1SS_MODE;
					} else if (strcmp((char *)param[2], "ac2") == 0) {
						wdsPortMode = AC_2SS_MODE;
					} else {
						wdsPortMode = AC_3SS_MODE;
					}
				} else {
					wdsPortMode = 0xFF;
				}
			} else {
				switch ((char)param[2][0]) {
				case 'b':
					wdsPortMode = BONLY_MODE;
					break;
				case 'g':
					wdsPortMode = GONLY_MODE;
					break;
				case 'a':
					wdsPortMode = AONLY_MODE;
					break;
				case 'n':
					wdsPortMode = NONLY_MODE;
					break;
				default:
					wdsPortMode = 0xFF;
					break;
				}
			}
			if (!setWdsPort(netdev, MacAddr, index, wdsPortMode)) {
				rc = -ENODEV;
			}
		}
		break;
#endif

	case WL_IOCTL_SET_WMMEDCAAP:
		{
			extern mib_QAPEDCATable_t mib_QAPEDCATable[4];
			int index, cw_min, cw_max, aifsn, tx_op_lim_b, tx_op_lim;

			sscanf(param_str, "%64s %64s %64s %64s %64s %64s\n", param[0], param[1], param[2], param[3], param[4], param[5]);
			index = atoi(param[0]);
			if ((index < 0) || (index > 3)) {
				rc = -EFAULT;
				break;
			}
			cw_min = atoi(param[1]);
			cw_max = atoi(param[2]);
			if ( /*(cw_min < BE_CWMIN) || (cw_max > BE_CWMAX) || */ (cw_min > cw_max)) {
				rc = -EFAULT;
				break;
			}
			aifsn = atoi(param[3]);
			tx_op_lim_b = atoi(param[4]);
			tx_op_lim = atoi(param[5]);

			mib_QAPEDCATable[index].QAPEDCATblIndx = index;
			mib_QAPEDCATable[index].QAPEDCATblCWmin = cw_min;
			mib_QAPEDCATable[index].QAPEDCATblCWmax = cw_max;
			mib_QAPEDCATable[index].QAPEDCATblAIFSN = aifsn;
			mib_QAPEDCATable[index].QAPEDCATblTXOPLimit = tx_op_lim;
			mib_QAPEDCATable[index].QAPEDCATblTXOPLimitBAP = tx_op_lim_b;

			//printk("WMM: %d %d %d %d %d %d %d\n", index, cw_min, cw_max, aifsn, tx_op_lim_b, tx_op_lim);
		}
		break;

	case WL_IOCTL_SET_WMMEDCASTA:
		{
			extern mib_QStaEDCATable_t mib_QStaEDCATable[4];
			int index, cw_min, cw_max, aifsn, tx_op_lim_b, tx_op_lim, acm;
			int input_cnt = 0, set_ie = 0;

			if (wfa_11ax_pf)
				input_cnt = sscanf(param_str, "%64s %64s %64s %64s %64s %64s %64s %64s\n",
						   param[0], param[1], param[2], param[3], param[4], param[5], param[6], param[7]);
			else
				sscanf(param_str, "%64s %64s %64s %64s %64s %64s %64s\n",
				       param[0], param[1], param[2], param[3], param[4], param[5], param[6]);

			index = atoi(param[0]);
			if ((index < 0) || (index > 3)) {
				rc = -EFAULT;
				break;
			}
			cw_min = atoi(param[1]);
			cw_max = atoi(param[2]);
			if ( /*(cw_min < BE_CWMIN) || (cw_max > BE_CWMAX) || */ (cw_min > cw_max)) {
				rc = -EFAULT;
				break;
			}
			aifsn = atoi(param[3]);
			tx_op_lim_b = atoi(param[4]);
			tx_op_lim = atoi(param[5]);
			acm = atoi(param[6]);

			mib_QStaEDCATable[index].QStaEDCATblIndx = index;
			mib_QStaEDCATable[index].QStaEDCATblCWmin = cw_min;
			mib_QStaEDCATable[index].QStaEDCATblCWmax = cw_max;
			mib_QStaEDCATable[index].QStaEDCATblAIFSN = aifsn;
			mib_QStaEDCATable[index].QStaEDCATblTXOPLimit = tx_op_lim;
			mib_QStaEDCATable[index].QStaEDCATblTXOPLimitBSta = tx_op_lim_b;
			mib_QStaEDCATable[index].QStaEDCATblMandatory = acm;
			//printk("WMM: %d %d %d %d %d %d %d\n", index, cw_min, cw_max, aifsn, tx_op_lim_b, tx_op_lim, acm);
			if (wfa_11ax_pf) {
				set_ie = atoi(param[7]);
				if (set_ie) {
					if (vmacSta_p->VMacEntry.edca_param_set_update_cnt == 15)
						vmacSta_p->VMacEntry.edca_param_set_update_cnt = 0;
					else
						vmacSta_p->VMacEntry.edca_param_set_update_cnt++;
					wlFwSetIEs(netdev);
				}
			}
		}
		break;

	case WL_IOCTL_SET_TXPOWER:
		{
			UINT16 i, setcap;
			sscanf(param_str,
			       "%64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s \n",
			       param[0], param[1], param[2], param[3], param[4], param[5], param[6], param[7], param[8], param[9], param[10],
			       param[11], param[12], param[13], param[14], param[15], param[16], param[17], param[18], param[19], param[20],
			       param[21], param[22], param[23], param[24], param[25], param[26], param[27], param[28], param[29], param[30],
			       param[31], param[32]);

			setcap = atoi(param[0]);
			for (i = 0; i < TX_POWER_LEVEL_TOTAL; i++) {
				if (setcap) {
					mib->PhyDSSSTable->powinited |= 2;
					mib->PhyDSSSTable->maxTxPow[i] = (SINT16) atoi_2(param[i + 1]);
				} else {
					mib->PhyDSSSTable->powinited |= 1;
					mib->PhyDSSSTable->targetPowers[i] = (SINT16) atoi_2(param[i + 1]);
				}
			}
		}
		break;

	case WL_IOCTL_SETCMD:
		{
			int input_cnt;

			input_cnt =
			    sscanf(param_str,
				   "%64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s\n",
				   param[0], param[1], param[2], param[3], param[4], param[5], param[6], param[7], param[8], param[9], param[10],
				   param[11], param[12], param[13], param[14], param[15], param[16], param[17], param[18], param[19], param[20],
				   param[21], param[22], param[23], param[24], param[25], param[26], param[27], param[28], param[29], param[30],
				   param[31], param[32], param[33], param[34], param[35], param[36], param[37], param[38], param[39], param[40],
				   param[41], param[42], param[43], param[44], param[45], param[46], param[47], param[48], param[49], param[50],
				   param[51], param[52], param[53], param[54], param[55], param[56], param[57], param[58], param[59], param[60],
				   param[61], param[62], param[63], param[64]);
			if ((strcmp(param[0], "scanchannels") == 0)) {
				int i, j, offset;

				if (strcmp(param[1], "help") == 0) {
					printk("Usage: scanchannels set scan channel list.\n");
					printk(" Eg. scanchannels <band> <ch 1> <ch 2> ... <ch n>\n");
					printk(" band : 0:2.4g / 1:5g\n");

					rc = -EFAULT;
					break;
				} else if (strcmp(param[1], "get") == 0) {
					printk("Scan Channel List:");
					j = 0;
					for (i = 0; i < IEEE_80211_MAX_NUMBER_OF_CHANNELS; i++) {
						if ((mib->PhyDSSSTable->Chanflag.ChnlWidth != CH_20_MHz_WIDTH)) {
							if (*(mib->mib_regionCode) == DOMAIN_CODE_ALL) {
								if (vmacSta_p->ChannelList[i] == 181) {
									continue;
								}
							} else {
								if (vmacSta_p->ChannelList[i] >= 165) {
									continue;
								}
							}
						}
						if (vmacSta_p->ChannelList[i] != 0) {
							j++;
							printk(" %d", vmacSta_p->ChannelList[i]);
							if (0 == (j % 20)) {
								printk("\n");
							}
						}
					}
					printk("\n");
					break;
				}
				offset = atoi(param[1]) ? IEEEtypes_MAX_CHANNELS : 0;
				/* TBD: Check scanchannel list in ap_op_ch_list */
				memset(vmacSta_p->ChannelList, 0, sizeof(UINT8) * IEEEtypes_MAX_CHANNELS + IEEEtypes_MAX_CHANNELS_A);
				for (i = 0; i < IEEE_80211_MAX_NUMBER_OF_CHANNELS; i++) {
					vmacSta_p->ChannelList[i + offset] = atohex2(param[i + 2]);
					if (vmacSta_p->ChannelList[i + offset] == 0) {
						break;
					}
				}
			}
#ifdef WIFI_ZB_COEX_EXTERNAL_GPIO_TRIGGER
			else if (strcmp(param[0], "set_coex") == 0) {
				UINT8 set = WL_GET;
				u8 enable;
				u8 gpioLevelDetect;
				u8 gpioLevelTrigger;
				u32 gpioReqPin;
				u32 gpioGrantPin;
				u32 gpioPriPin;

				if (!param[1][0]) {	//get
					set = WL_GET;
					wlFwSetCoexConfig(netdev, &enable, &gpioLevelDetect, &gpioLevelTrigger, &gpioReqPin, &gpioGrantPin,
							  &gpioPriPin, set);
					printk
					    ("get coex conf enable=%u gpioLevelDetect=%u gpioLevelTrigger=%u gpioReqPin=%u gpioGrantPin=%u gpioPriPin=%u\n",
					     enable, gpioLevelDetect, gpioLevelTrigger, gpioReqPin, gpioGrantPin, gpioPriPin);
				} else if (strcmp(param[1], "disable") == 0) {	//disable
					set = WL_SET;
					enable = 0;
					wlFwSetCoexConfig(netdev, &enable, &gpioLevelDetect, &gpioLevelTrigger, &gpioReqPin, &gpioGrantPin,
							  &gpioPriPin, set);
				} else if ((strcmp(param[1], "enable") == 0) && param[2][0] && param[3][0] && param[4][0] && param[5][0] && param[6][0]) {	//enable
					set = WL_SET;
					enable = 1;
					gpioLevelDetect = (u8) atohex2(param[2]);
					gpioLevelTrigger = (u8) atohex2(param[3]);
					gpioReqPin = (u32) atohex2(param[4]);
					gpioGrantPin = (u32) atohex2(param[5]);
					gpioPriPin = (u32) atohex2(param[6]);
					wlFwSetCoexConfig(netdev, &enable, &gpioLevelDetect, &gpioLevelTrigger, &gpioReqPin, &gpioGrantPin,
							  &gpioPriPin, set);
				} else {
					printk
					    ("Invalid arguments! Please use command format: \niwpriv <wdev0|wdev1> setcmd \"set_coex [<enable gpioLevelDetect gpioLevelTrigger gpioReqPin gpioGrantPin gpioPriPin|disable>]\"\n");
				}
			}
#endif
#ifdef SOC_W8964
			else if (strcmp(param[0], "rts_retry") == 0) {
				long retrycnt = atohex2(param[1]);
				wlFwSetRTSRetry(netdev, (int)retrycnt);
			} else if (strcmp(param[0], "bg_scan") == 0) {
				long scan_period = atohex2(param[1]);

				priv->bgscan_period = scan_period;
				printk("=> %s(), set bgscan_period = %d, %p\n", __func__, priv->bgscan_period, priv);
			}
#endif
#ifdef SOC_W906X
			else if (strcmp(param[0], "muedcacfg") == 0) {
				int index, cw_min, cw_max, set_ie = 0;
				if (!priv->master) {
					printk("Error. Please enter vap interface instead\n");
					rc = -EOPNOTSUPP;
					break;
				}

				index = atoi(param[1]);
				if (index > 3) {
					printk("Invalid ACI number %d range is 0 ~ 3\n", index);
					rc = -EOPNOTSUPP;
					break;
				}
				cw_min = atoi(param[2]);
				cw_max = atoi(param[3]);
				if (cw_min > cw_max) {
					rc = -EFAULT;
					break;
				}
				vmacSta_p->VMacEntry.mib_QAP_MUEDCA_Table[index].aifsn = atoi(param[4]);
				vmacSta_p->VMacEntry.mib_QAP_MUEDCA_Table[index].acm = atoi(param[5]);
				vmacSta_p->VMacEntry.mib_QAP_MUEDCA_Table[index].aci = index;
				vmacSta_p->VMacEntry.mib_QAP_MUEDCA_Table[index].ecw_min = cw_min;
				vmacSta_p->VMacEntry.mib_QAP_MUEDCA_Table[index].ecw_max = cw_max;
				vmacSta_p->VMacEntry.mib_QAP_MUEDCA_Table[index].timer = atoi(param[6]);
				if (vmacSta_p->VMacEntry.muedcaEnable) {
					set_ie = atoi(param[7]);

					if (set_ie) {
						if (vmacSta_p->VMacEntry.edca_param_set_update_cnt == 15)
							vmacSta_p->VMacEntry.edca_param_set_update_cnt = 0;
						else
							vmacSta_p->VMacEntry.edca_param_set_update_cnt++;
						wlFwSetIEs(netdev);
					}
				}
			} else if (strcmp(param[0], "sched_mode") == 0) {
				extern UINT32 wlFwSetSchedMode(struct net_device *netdev, UINT16 action, UINT32 mode_selected,
							       void *pCfg, UINT16 len, UINT16 * pStatus);
				UINT32 action = atohex2(param[1]);
				UINT32 mode = atohex2(param[2]);	//bitmapping
				UINT32 mode_mask = 0, mode_tmp = 0, found;
				UINT16 status = 0, i, idx = 1;

				if (input_cnt == 1) {
					UINT32 partial_mode;

					//get bsrp/auto_pc/auto_dra
					mode = MODE_SELECT_BSRP_OFF | MODE_SELECT_AUTO_PC_OFF | MODE_SELECT_AUTO_DRA_OFF;

					wlFwSetSchedMode(netdev, 3, mode, (void *)&partial_mode, sizeof(partial_mode), &status);

					printk("[SCHED_MODE] bsrp     : %s\n", (partial_mode & MODE_SELECT_BSRP_OFF) ? "off" : "on");
					printk("[SCHED_MODE] auto_pc  : %s\n", (partial_mode & MODE_SELECT_AUTO_PC_OFF) ? "off" : "on");
					printk("[SCHED_MODE] auto_dra : %s\n", (partial_mode & MODE_SELECT_AUTO_DRA_OFF) ? "off" : "on");
					break;
				}
				//Check bsrp, auto_pc, and auto_dra, 0 is on and 1 is off
				for (i = 0; i < 3; i++) {
					found = 0;
					if (!strncmp("bsrp", param[idx], 4)) {
						found = MODE_SELECT_BSRP_OFF;
					} else if (!strncmp("auto_pc", param[idx], 7)) {
						found = MODE_SELECT_AUTO_PC_OFF;
					} else if (!strncmp("auto_dra", param[idx], 8)) {
						found = MODE_SELECT_AUTO_DRA_OFF;
					}
					if (found) {

						if (!strncmp("off", param[idx + 1], 3)) {
							mode_tmp |= found;
						} else if (!strncmp("on", param[idx + 1], 2)) {
							//disable, do nothing
						} else {
							printk("Unknow parameter %s should be <on/off> for parameter %s\n", param[idx + 1],
							       param[idx]);
							mode_mask = 0xffffffff;	//exit command
							break;
						}
						mode_mask |= found;
						idx += 2;
					}
				}
				if (mode_mask) {
					if (mode_mask != 0xffffffff) {
						UINT32 partial_mode = mode_mask;

						wlFwSetSchedMode(netdev, HostCmd_ACT_GEN_SET, mode_tmp, (void *)&partial_mode, sizeof(partial_mode),
								 &status);
						//printk("[SCHED_MODE] Change parameter done!  mode_tmp=0x%08x mode_mask=0x%08x\n", mode_tmp, mode_mask);
					}
					break;
				}
				//printk("[sched_mode]: action=%d mode=0x%x input_cnt=%d\n", action, mode, input_cnt); 
				if (action == 99)	//test mode
				{
					sched_cfg_test_t test = { 0 };

					test.tf_type = atohex2(param[3]);
					test.rateInfo = ENDIAN_SWAP32(atohex2(param[4]));
					test.param[0] = ENDIAN_SWAP32(atohex2(param[5]));

					wlFwSetSchedMode(netdev, action, mode, (void *)&test, sizeof(test), &status);
				}
#ifdef AP_TWT
				else if (action == 98)	//twt-test
				{
					sched_cfg_test_t test = { 0 };

					//type=1 <trigger interval> < ??? > 
					//type=2 debug

					test.tf_type = atohex2(param[3]);

					test.param[0] = atohex2(param[4]);
					test.param[1] = atohex2(param[5]);

					wlFwSetSchedMode(netdev, action, mode, (void *)&test, sizeof(test), &status);

				} else if (action == 97)	//twt-test
				{
					sched_cfg_test_t test = { 0 };
					extern u8 wfa_itwt_wakedur_early_end;

					//type=1 <trigger interval> < ??? > 
					//type=2 debug

					test.tf_type = atohex2(param[3]);

					test.param[0] = atohex2(param[4]);
					test.param[1] = atohex2(param[5]);

					if (test.tf_type == 0) {
						wfa_itwt_wakedur_early_end = (u8) test.param[0];
						printk("Config wfa_itwt_wakedur_early_end to %u units\n", wfa_itwt_wakedur_early_end);
					} else if (test.tf_type == 1) {
						extern u8 wfa_flag_5_60_1;

						wfa_flag_5_60_1 = (u8) test.param[0];
						printk("Starting iTWT 5.60.1 testing...\n");
					} else if (test.tf_type == 2) {
						extern u32 wfa_twt_rx_mon_time;
						extern u32 wfa_twt_tx_mon_time;

						wfa_twt_rx_mon_time = test.param[0];
						wfa_twt_tx_mon_time = test.param[1];
						printk("Cinfig iTWT Rx mode monitoring time:Rx:%u Tx:%u\n", wfa_twt_rx_mon_time, wfa_twt_tx_mon_time);
					} else if (test.tf_type == 3) {
						extern u32 wfa_twt_rx_mon_length;

						wfa_twt_rx_mon_length = test.param[0];
						printk("Cinfig iTWT Rx mode monitoring length:%u\n", wfa_twt_rx_mon_length);
					}

				}
#endif
				else if (mode & MODE_SELECT_UL_OFDMA) {
					sched_cfg_ul_ofdma_t cfg = { 0 };
					UINT8 max_user;
					MIB_PHY_DSSS_TABLE *PhyDSSSTable = mib->PhyDSSSTable;

					if (action == HostCmd_ACT_GEN_SET) {
						if (PhyDSSSTable->Chanflag.ChnlWidth == CH_20_MHz_WIDTH) {
							max_user = min(SMAC_MAX_OFDMA_USERS, 8);
						} else {
							max_user = min(SMAC_MAX_OFDMA_USERS, 16);
						}

						if (mode & MODE_SELECT_CNTI) {
							UINT32 state = 0;

							cfg.rateInfo = 0xff010500;
							cfg.minUserInfo = 1;
							cfg.maxUserInfo = max_user;
							cfg.period_tmr = 0;	//not used 
							cfg.gap_tmr = 0;	//not used

							//Usage: schedu_mode <action> <mode> [rate <rateInfo>] [min <min_users>] [max <max_users>]
							if (input_cnt > 3) {
								int loop = (input_cnt - 3) / 2;
								int i, idx = 3;

								for (i = 0; i < loop; i++) {
									if (!strncmp("rate", param[idx], 4)) {
										cfg.rateInfo = atohex2(param[idx + 1]);
									} else if (!strncmp("min", param[idx], 3)) {
										cfg.minUserInfo = atohex2(param[idx + 1]);
									} else if (!strncmp("max", param[idx], 3)) {
										cfg.maxUserInfo = atohex2(param[idx + 1]);
									} else {
										printk("Unknown parameter %s\n", param[idx]);
										printk
										    ("Usage: schedu_mode <action> <mode> [rate <rateInfo>] [min <min_users>] [max <max_users>]\n");
										state = 1;
										break;
									}
									idx += 2;
								}
								if (state)
									break;
							}
							printk("sched_mode: action=%u, mode=0x%x, minUser=%u maxUser=%u, rate=0x%x\n",
							       action, mode, cfg.minUserInfo, cfg.maxUserInfo, cfg.rateInfo);
						} else {
							if (input_cnt != 8) {
								printk
								    ("Usage: schedu_mode <action> <mode> <min_users> <max_users> <bsrp_timer> <basic_tf_gap> <rateInfo>\n");
								printk("       action      : 0-get, 1-set, 2-delete\n");
								printk("       mode        : bit3-ul_ofdma\n");
								printk("       min_user    : min. number of users in trigger frame\n");
								printk("       max_user    : max. number of users in trigger frame\n");
								printk("       bsrp_timer  : bsrp periodically sending timer, unit=usec\n");
								printk
								    ("       basic_tf_gap: the gap between bsrp and basic trigger frame, unit=usec\n");
								printk
								    ("       rateInfo    : tx rate for sending trigger frame, same format as rate control\n");
								break;
							}
							cfg.minUserInfo = atohex2(param[3]);

							if ((cfg.minUserInfo == 0) || (cfg.minUserInfo > max_user)) {
								printk("Error: invalid minimum user number %u, range is 1 to %d\n",
								       cfg.minUserInfo, max_user);
								break;
							}
							cfg.maxUserInfo = atohex2(param[4]);
							if (cfg.maxUserInfo < cfg.minUserInfo) {
								printk
								    ("Error: invalid maximum user number %u, shall be larger or equal to minimum user number %u.\n",
								     cfg.maxUserInfo, cfg.minUserInfo);
								break;
							}
							if (cfg.maxUserInfo > max_user) {
								printk("Error: invalid maximum user number %u, range is %d to %d\n",
								       cfg.maxUserInfo, cfg.minUserInfo, max_user);
								break;
							}
							cfg.period_tmr = ENDIAN_SWAP32(atohex2(param[5]));	//msec
							cfg.gap_tmr = ENDIAN_SWAP32(atohex2(param[6]));	//gap between BSRP and basic TF
							cfg.rateInfo = ENDIAN_SWAP32(atohex2(param[7]));
							printk
							    ("sched_mode: action=%u, mode=%x, minUser=%u maxUser=%u, period=%u[usec] gap=%u[usec], rate=0x%x\n",
							     action, mode, cfg.minUserInfo, cfg.maxUserInfo, cfg.period_tmr, cfg.gap_tmr,
							     cfg.rateInfo);
						}
						cfg.period_tmr = ENDIAN_SWAP32(cfg.period_tmr);	//msec
						cfg.gap_tmr = ENDIAN_SWAP32(cfg.gap_tmr);	//gap between BSRP and basic TF
						cfg.rateInfo = ENDIAN_SWAP32(cfg.rateInfo);

						cfg.minUserInfo = ENDIAN_SWAP32(cfg.minUserInfo);
						cfg.maxUserInfo = ENDIAN_SWAP32(cfg.maxUserInfo);

						if (wfa_11ax_pf)
							memcpy((void *)&vmacSta_p->ul_ofdma, (void *)&cfg, sizeof(sched_cfg_ul_ofdma_t));

						action = HostCmd_ACT_GEN_SET;
						vmacSta_p->VMacEntry.muedcaEnable = TRUE;
						wlFwSetIEs(netdev);
					} else if (action == HostCmd_ACT_GEN_DEL) {
						vmacSta_p->VMacEntry.muedcaEnable = FALSE;;
						wlFwSetIEs(netdev);
					}

					wlFwSetSchedMode(netdev, action, mode, (void *)&cfg, sizeof(cfg), &status);

					if (action == HostCmd_ACT_GEN_GET) {
						printk
						    ("[UL_OFDMA]: status=%d minuser=%d, maxuser=%d period_tmr=%d usec, gap_tmr=%d usec rateinfo=0x%08x maxUserInfo=%d\n",
						     status, ENDIAN_SWAP32(cfg.minUserInfo), ENDIAN_SWAP32(cfg.maxUserInfo),
						     ENDIAN_SWAP32(cfg.period_tmr), ENDIAN_SWAP32(cfg.gap_tmr), ENDIAN_SWAP32(cfg.rateInfo),
						     ENDIAN_SWAP32(cfg.maxUserInfo));
					}
				}
			} else if (strcmp(param[0], "protection") == 0) {
				extern UINT32 wlFwSetProtectMode(struct net_device *netdev, UINT32 action, UINT32 * mode);
				U32 mode;

				if (input_cnt < 2)	//GET
				{
					wlFwSetProtectMode(netdev, HostCmd_ACT_GEN_GET, &mode);
					if (mode < FORCE_PROTECT_MAX) {
						printk("Protection Mode is %s\n", force_protect_str[mode].str);
					} else {
						printk("Protection Mode in FW is unknown value %d\n", mode);
					}
				} else	//SET
				{
					for (mode = 0; mode < FORCE_PROTECT_MAX; mode++) {
						if (strcmp(param[1], force_protect_str[mode].str) == 0)
							break;
					}
					if (mode < FORCE_PROTECT_MAX) {
						wlFwSetProtectMode(netdev, HostCmd_ACT_GEN_SET, &mode);
					} else {
						printk("\nCommand Usage: protection <varable name>\n");
						for (mode = 0; mode < FORCE_PROTECT_MAX; mode++) {
							printk("        [%d] : cvariable name = %s\n", mode, force_protect_str[mode].str);
						}
					}
				}
			} else if (strcmp(param[0], "fw_mib") == 0) {
				extern UINT32 wlFwSetMib(struct net_device *netdev, UINT32 action, UINT32 mibIdx, UINT32 * pValue, UINT32 * pNum);
				UINT32 mibIdx = MIB_MAX, i, num;
				UINT32 value[SMAC_MAX_OFDMA_USERS];
				char *tf_type_str[TF_MAX] = { "basic", "bfrp", "mu_bar", "mu_rts", "bsrp" };

				if (input_cnt < 2) {
					for (mibIdx = 0; mibIdx < MIB_MAX; mibIdx++) {
						num = 0;
						wlFwSetMib(netdev, HostCmd_ACT_GEN_GET, mibIdx, value, &num);
						num = MIN(num, SMAC_MAX_OFDMA_USERS);
						printk("  [%3d] : num=%2d   %-32s = ", mibIdx, fw_mib_str[mibIdx].num, fw_mib_str[mibIdx].str);
						if (mibIdx == MIB_TF_RATEINFO) {
							printk("%-6s : 0x%08x\n", tf_type_str[0], value[0]);
							for (i = 1; i < TF_MAX; i++)
								printk("%53s %-6s : 0x%08x\n", " ", tf_type_str[i], value[i]);
						} else {
							for (i = 0; i < num; i++) {
								if (i && (i % 4) == 0)
									printk("\n%69s", " ");
								printk("0x%x ", value[i]);
							}
							printk("\n");
						}
					}
				} else {
					num = input_cnt - 2;
					for (mibIdx = 0; mibIdx < MIB_MAX; mibIdx++) {
						if (strcmp(param[1], fw_mib_str[mibIdx].str) == 0) {
							if (num > fw_mib_str[mibIdx].num)
								num = fw_mib_str[mibIdx].num;
							break;
						}
					}
					if (mibIdx < MIB_MAX) {
						if (mibIdx == MIB_TF_RATEINFO) {
							for (i = 0; i < TF_MAX; i++) {
								if (strcmp(param[2], tf_type_str[i]) == 0) {
									value[0] = i;
									value[1] = atohex2(param[3]);
									break;
								}
							}
							if (i == TF_MAX)
								goto FW_MIB_ERR;
						} else {
							for (i = 0; i < num; i++) {
								value[i] = atohex2(param[2 + i]);
							}
						}
						wlFwSetMib(netdev, HostCmd_ACT_GEN_SET, mibIdx, value, &num);
					} else {
 FW_MIB_ERR:
						WLDBG_ERROR(DBG_LEVEL_0, "Invalid input parameter %s\n", param[1]);
						printk("\nCommand Usage: fw_mib <varable value0  value1 ...>\n");
						for (mibIdx = 0; mibIdx < MIB_MAX; mibIdx++) {
							printk("        [%3d] : num_of_parameters=%2d   variable = %s\n",
							       mibIdx, fw_mib_str[mibIdx].num, fw_mib_str[mibIdx].str);
						}
					}
				}
			} else if (strcmp(param[0], "fw_dbg") == 0) {
				extern UINT32 wlFwSetDbg(struct net_device *netdev, UINT32 action, UINT32 dbgIdx, UINT32 * pValue, UINT32 * pNum);
				UINT32 dbgIdx = FW_DBG_MAX, i = 0, num = 0;
				UINT32 value[SMAC_MAX_OFDMA_USERS];

				if (input_cnt < 2)	//Action for Get
				{
					for (dbgIdx = 0; dbgIdx < FW_DBG_MAX; dbgIdx++) {
						num = 0;
						wlFwSetDbg(netdev, HostCmd_ACT_GEN_GET, dbgIdx, value, &num);
						num = MIN(num, 1);
						printk("  [%3d] : num=%2d   %-32s = 0x%08x\n", dbgIdx, fw_dbg_str[dbgIdx].num, fw_dbg_str[dbgIdx].str,
						       value[0]);
					}
				} else	//Action for Set
				{
					num = input_cnt - 2;
					for (dbgIdx = 0; dbgIdx < FW_DBG_MAX; dbgIdx++) {
						if (strcmp(param[1], fw_dbg_str[dbgIdx].str) == 0) {
							break;
						}
					}
					if (dbgIdx < FW_DBG_MAX) {
						value[i] = atohex2(param[2 + i]);
						wlFwSetDbg(netdev, HostCmd_ACT_GEN_SET, dbgIdx, value, &num);
					} else {
						WLDBG_ERROR(DBG_LEVEL_0, "Invalid input parameter %s\n", param[1]);
						printk("\nCommand Usage: fw_dbg <varable> <value>\n");
						for (dbgIdx = 0; dbgIdx < FW_DBG_MAX; dbgIdx++) {
							printk("        [%3d] : num_of_parameters=%2d   variable = %s\n",
							       dbgIdx, fw_dbg_str[dbgIdx].num, fw_dbg_str[dbgIdx].str);
						}
					}
				}
			} else if (strcmp(param[0], "wfa_test") == 0) {
				extern UINT32 wlFwSetWfaTest(struct net_device *netdev,
							     UINT32 action, UINT32 version, UINT32 testId, UINT32 stepid, void *cfg, UINT32 cfgLen);
				// <action> <version> <testId> <stepId> <maxStaNum> <maxDelayTime>
				UINT32 action = atohex2(param[1]);
				UINT32 version = atohex2(param[2]);
				UINT32 testId = atohex2(param[3]);
				UINT32 stepid = atohex2(param[4]);

				//printk("WFA Test action=%d version=0x%x  testId=0x%x \n", action, version, testId);       
				switch (testId >> 12) {
				case 0x04028:	//4.40    
				case 0x0502d:	//5.45            
					//start(1) or stop(0) 
					action = action ? 1 : 0;
					//if (vmacSta_p->VMacEntry.muedcaEnable != action)
					{
						UINT32 maxStaNum = atohex2(param[5]);
						UINT32 maxDelayTime = atohex2(param[6]);
						ul_ofdma_t cfg;

						cfg.maxStaNum = maxStaNum;
						cfg.maxDelayTime = maxDelayTime;

						printk("[%s]WFA Test 0x%08x action=%d maxStaNum=%d maxDelayTime=%d\n", netdev->name, testId, action,
						       maxStaNum, maxDelayTime);

						vmacSta_p->VMacEntry.muedcaEnable = action;
						wlFwSetIEs(netdev);
						wlFwSetWfaTest(netdev, action, version, testId, stepid, &cfg, sizeof(cfg));
					}
					break;
				case 0x04029:	//4.41
					break;
				}
			} else if (strcmp(param[0], "tf_test") == 0) {
				extern UINT32 wlFwSentTriggerFrameCmd(struct net_device *netdev, UINT8 action, UINT8 type, UINT32 rateInfo,
								      UINT32 period, UINT32 padNum, void *pData);
				struct file *filp;
				tf_basic_t *ptf = NULL;
				UINT8 type = 2, comment = 0, format = 0, idx = 0;
				UINT32 action = atohex2(param[1]);
				UINT32 rateInfo = atohex2(param[2]);
				UINT32 period = atohex2(param[3]);
				UINT32 padNum = atohex2(param[5]);	//number of padding octets 
				UINT32 len, str_len, total_len;
				char *local_buff, *s;

				//check opmode, mudt be 11ax mode
				if ((*(mib->mib_ApMode) & AP_MODE_11AX) == 0) {
					printk("Error:: opmode = 0x%x not enable 11ax\n", *(mib->mib_ApMode));
					break;
				}
				if (action == 0) {
					//send disable command
					wlFwSentTriggerFrameCmd(netdev, action, type, rateInfo, period, padNum, NULL);
					break;
				} else if ((action & 0xf) > 3) {
					printk("Error:: action = 0x%x not supported\n", action);
					break;
				} else if (action & 0x30)	//semi+auto  
				{
					ptf = (tf_basic_t *) wl_kmalloc(sizeof(tf_basic_t), GFP_KERNEL);

					if (ptf == NULL) {
						printk("Error: allocate %d bytes failed\n", (int)sizeof(tf_basic_t));
						break;
					}
					ptf->common.tf_type = atohex2(param[6]);
					goto ul_ofdma_trigger;
				}

				ptf = (tf_basic_t *) wl_kmalloc(sizeof(tf_basic_t), GFP_KERNEL);
				if (ptf == NULL) {
					printk("Error: allocate %d bytes failed\n", (int)sizeof(tf_basic_t));
					break;
				}
				if (strlen(param[4]) == 0) {
					//use default setting
					printk("NO input file, use default setting with type = %d\n", type);
				} else {
					filp = filp_open(param[4], O_RDONLY, 0);
					if (IS_ERR(filp)) {
						printk("Open file %s Error\n", param[4]);
						break;
					} else {
						if (action == 3) {
							printk("Open file %s period=%d usec rateInfo=0x%08x type=%d\n", param[4], period, rateInfo,
							       type);
						} else {
							printk("Open file %s period=%d msec rateInfo=0x%08x type=%d\n", param[4], period, rateInfo,
							       type);
						}

						local_buff = wl_vzalloc(256);
						if (!local_buff) {
							rc = -ENOMEM;
							break;
						}

						ptf->common.tf_num_users = 0;
						s = local_buff;
						str_len = 0;
						total_len = 0;
						while (total_len < 10000) {
							len = kernel_read(filp, s, 1, &filp->f_pos);
							if (len == 0 && str_len == 0) {
								break;
							}
							total_len++;
							str_len++;
							if (*s == '#') {
								comment = 1;
							}
							if ((format == 1) && (*s == '=')) {
								*s = ' ';
							}
							if (*s == '\n' || (len == 0)) {

								if (!comment) {
									if (memcmp(local_buff, "[COMMON_INFO]", 8) == 0) {
										format = 1;
										goto next;
									} else if (memcmp(local_buff, "[USER_INFO]", 11) == 0) {
										format = 2;
										goto next;
									}
									if (format == 1) {
										sscanf(local_buff, "%32s %32s\n", param[0], param[1]);

										if (strcmp(param[0], "TF_Type") == 0)
											ptf->common.tf_type = atohex2(param[1]);
										else if (strcmp(param[0], "TF_UL_LEN") == 0)
											ptf->common.tf_ul_len = ENDIAN_SWAP16(atohex2(param[1]));
										else if (strcmp(param[0], "TF_MORE_FLAG") == 0)
											ptf->common.tf_more_flag = atohex2(param[1]);
										else if (strcmp(param[0], "TF_CS_REQUIRED") == 0)
											ptf->common.tf_cs_required = atohex2(param[1]);
										else if (strcmp(param[0], "TF_LDPC_EXTRA") == 0)
											ptf->common.tf_ldpc_extra = atohex2(param[1]);
										else if (strcmp(param[0], "TF_AP_TX_POWER") == 0)
											ptf->common.tf_ap_tx_power = atohex2(param[1]);
										else if (strcmp(param[0], "TF_UL_SPATIAL_REUSE") == 0)
											ptf->common.tf_ul_spatial_reuse =
											    ENDIAN_SWAP16(atohex2(param[1]));
										else if (strcmp(param[0], "TF_BW") == 0)
											ptf->common.tf_bw = atohex2(param[1]);
										else if (strcmp(param[0], "TF_GI_LTF") == 0)
											ptf->common.tf_gi_ltf = atohex2(param[1]);
										else if (strcmp(param[0], "TF_MUMIMO_LTF_MODE") == 0)
											ptf->common.tf_mumimo_ltf_mode = atohex2(param[1]);
										else if (strcmp(param[0], "TF_NO_HELTF_MIDAMBLE_PERIODICITY") == 0)
											ptf->common.tf_midamble_period = atohex2(param[1]);
										else if (strcmp(param[0], "TF_STBC") == 0)
											ptf->common.tf_stbc = atohex2(param[1]);
										else if (strcmp(param[0], "TF_UL_PE") == 0)
											ptf->common.tf_max_pe = atohex2(param[1]);
										else if (strcmp(param[0], "TF_DOPPLER") == 0)
											ptf->common.tf_doppler = atohex2(param[1]);
										else if (strcmp(param[0], "TF_HESIGA_RSVD") == 0)
											ptf->common.tf_hesiga_rsvd = ENDIAN_SWAP16(atohex2(param[1]));
										else if (strcmp(param[0], "TF_NO_HELTF_SYM") == 0)
											ptf->common.tf_no_heltf_sym = atohex2(param[1]);
										else if (strcmp(param[0], "TF_A_FACTOR_INIT") == 0)
											ptf->common.tf_a_factor_init = atohex2(param[1]);
										else if (strcmp(param[0], "TF_NSYM_INIT") == 0)
											ptf->common.tf_nsym_init = ENDIAN_SWAP16(atohex2(param[1]));
										else if (strcmp(param[0], "TF_MU_RTS") == 0)
											ptf->common.tf_mu_rts = atohex2(param[1]);
										else if (strcmp(param[0], "TF_En_MDRHPF") == 0)
											ptf->common.tf_en_mdrhpf = atohex2(param[1]);
										else if (strlen(param[0]) == 0)
											goto next;
										else
											printk
											    ("TF-COMMON_INFO: Can't find the field name=%s value=%s\n",
											     param[0], param[1]);
									} else if (format == 2) {
										UINT8 mac[6];
										extStaDb_StaInfo_t *pStaInfo;

										sscanf(local_buff,
										       "%32s %32s %32s %32s %32s %32s %32s %32s %32s %32s %32s %32s %32s %32s\n",
										       param[0], param[1], param[2], param[3], param[4], param[5],
										       param[6], param[7], param[8], param[9], param[10], param[11],
										       param[12], param[13]);

										if (strlen(param[0]) == 0) {
											//skip
											goto next;
										}

										if (idx >= SMAC_MAX_OFDMA_USERS) {
											printk
											    ("tf_test error: too many user info input %d max = %d\n",
											     idx, SMAC_MAX_OFDMA_USERS);
											break;
										}

										getMacFromString(mac, param[0]);
										pStaInfo =
										    extStaDb_GetStaInfo(vmacSta_p, (IEEEtypes_MacAddr_t *) mac,
													STADB_DONT_UPDATE_AGINGTIME);
										if (pStaInfo) {
											ptf->user[idx].staId =
											    ENDIAN_SWAP16(pStaInfo->StnId + bss_num);
										} else {
											ptf->user[idx].staId = ENDIAN_SWAP16(sta_num + bss_num + idx);
										}
										ptf->user[idx].tf_ru_allocation = atohex2(param[1]);
										ptf->user[idx].tf_fec_type = atohex2(param[2]);
										ptf->user[idx].tf_mcs = atohex2(param[3]);
										ptf->user[idx].tf_dcm = atohex2(param[4]);
										ptf->user[idx].tf_start_ss = atohex2(param[5]);
										ptf->user[idx].tf_target_rssi = atohex2(param[6]);
										ptf->user[idx].tf_mpdu_spac_fac = atohex2(param[7]);
										ptf->user[idx].tf_tid_aggr_limit = atohex2(param[8]);
										ptf->user[idx].tf_pref_ac = atohex2(param[9]);
										ptf->user[idx].tf_nss = atohex2(param[10]);
										ptf->user[idx].tf_datalen = ENDIAN_SWAP32(atohex2(param[11]));
										ptf->user[idx].tf_ru_alloc_idx = atohex2(param[12]);
										ptf->user[idx].tf_rssi_delta = atohex2(param[13]);
										idx++;
									}
								}
 next:
								str_len = 0;
								comment = 0;
								memset(local_buff, 0x00, 256);
								s = local_buff;
								continue;
							}
							s++;
						}
						wl_vfree(local_buff);
						if (total_len >= 10000) {
							printk("Error: file exceed the max size 10000 bytes, only %d user download\n", idx);
						}

						ptf->common.tf_num_users = idx;
					}
					filp_close(filp, current->files);
				}
 ul_ofdma_trigger:
				if (wfa_11ax_pf) {
					priv->tf_test_arg.type = type;
					priv->tf_test_arg.rate_info = rateInfo;
					priv->tf_test_arg.period = period;
					priv->tf_test_arg.pad_num = padNum;
					memcpy(&priv->tf_test_arg.tf, ptf, sizeof(tf_basic_t));
					printk("==>[wfa_11ax_pf], save tf_test param (type=%u, rate_info: 0x%x, period: %u, pad: %u)\n",
					       priv->tf_test_arg.type, priv->tf_test_arg.rate_info, priv->tf_test_arg.period,
					       priv->tf_test_arg.pad_num);
				}
				wlFwSentTriggerFrameCmd(netdev, action, type, rateInfo, period, padNum, (void *)ptf);
				if (ptf)
					wl_kfree(ptf);
			} else if (strcmp(param[0], "tf_onoff") == 0) {
				tf_test_arg_t *ptf_arg = &priv->tf_test_arg;
				long action = atohex2(param[1]);
				if (action == 1) {
					printk("==>[wfa_11ax_pf], Try to enable trigger frame [%s]\n", netdev->name);
					wlFwSentTriggerFrameCmd(netdev, 3, ptf_arg->type, ptf_arg->rate_info,
								ptf_arg->period, ptf_arg->pad_num, (void *)(&ptf_arg->tf));
				} else {
					printk("==>[wfa_11ax_pf], Try to disable trigger frame [%s]\n", netdev->name);
					wlFwSentTriggerFrameCmd(netdev, 0, ptf_arg->type, ptf_arg->rate_info,
								ptf_arg->period, ptf_arg->pad_num, (void *)(&ptf_arg->tf));
				}
			} else if (strcmp(param[0], "idx_test") == 0) {	// Format: idx_test [pkt_cnt] [pkt_size]
				long pktcnt = atohex2(param[1]);	// Example: iwpriv wdev0 setcmd "idx_test 3"
				long pktsize = atohex2(param[2]);
				long txqid = QUEUE_STAOFFSET;
				long frameType = IEEE_TYPE_DATA;

				if (input_cnt > 3)
					txqid = atohex2(param[3]);

				if (input_cnt > 4) {
					frameType = atohex2(param[4]);
					if (frameType > IEEE_TYPE_DATA)
						frameType = IEEE_TYPE_DATA;
				}
				//printk("*** Note: packet will be Tx thru qid = %d frameType=%d.\n", (int)txqid, frameType);
				idx_test(netdev, pktcnt, pktsize, txqid, frameType);
			} else if (strcmp(param[0], "cb_bcn_mask") == 0) {
				UINT32 is_on = atoi(param[1]);
				cb_set_bcn_mask(netdev, is_on);
			} else if (strcmp(param[0], "cb_bcn_mask_test") == 0) {
				// Self-test for beacon on/off
				UINT32 bcn_drop_cnt = atoi(param[1]);

				priv->bcn_drop_cnt = bcn_drop_cnt;
				priv->txbcn_sn = cb_get_bcn_sn(netdev);
				if (bcn_drop_cnt > 0) {
					cb_set_bcn_mask(netdev, FALSE);
				} else {
					cb_set_bcn_mask(netdev, TRUE);
				}
				printk("sn_now: %u, Drop %u beacons before sending the next beacon\n", priv->txbcn_sn, bcn_drop_cnt);
			} else if (strcmp(param[0], "cb_bcn_sn") == 0) {
				UINT32 sn = atoi(param[1]);
				cb_set_bcn_sn(netdev, sn);
			} else if (strcmp(param[0], "cb_init") == 0) {
				long resp_mgmt = atohex2(param[1]);
				set_cb(netdev, 1, (int)resp_mgmt);
			}
			// CB TSF APIs
			else if (strcmp(param[0], "cb_set_tsf") == 0) {
				uint64_t tsf_set_val;	//=0x123456
				if (priv->cb_enable == FALSE) {
					printk("[%s], cb is uninitialized\n", netdev->name);
					return -EFAULT;
				}
				sscanf(param[1], "%llx", &tsf_set_val);
				set_tsf(netdev, tsf_set_val);
			} else if (strcmp(param[0], "cb_get_tsf") == 0) {
				uint64_t tsf_get_val;
				tsf_get_val = get_tsf(netdev);
				printk("tsf_val=0x%llx\n", tsf_get_val);
			} else if (strcmp(param[0], "cb_adjust_tsf") == 0) {
				uint64_t tsf_diff_val;	//=0x123456
				if (priv->cb_enable == FALSE) {
					printk("[%s], cb is uninitialized\n", netdev->name);
					return -EFAULT;
				}
				sscanf(param[1], "%llx", &tsf_diff_val);
				adjust_tsf(netdev, tsf_diff_val);
			} else if (strcmp(param[0], "cb_tsf_diff") == 0) {
				uint64_t tsf_set_val;	//=0x123456
				uint64_t tsf_get_val;
				if (priv->cb_enable == FALSE) {
					printk("[%s], cb is uninitialized\n", netdev->name);
					return -EFAULT;
				}
				sscanf(param[1], "%llx", &tsf_set_val);
				set_cb(netdev, 1, 0);
				set_tsf(netdev, tsf_set_val);
				tsf_get_val = get_tsf(netdev);
				printk("(set, get)=(0x%llx, 0x%llx), diff: 0x%llx\n", tsf_set_val, tsf_get_val, (tsf_get_val - tsf_set_val));
			}
			// CB RSSI APIs
			else if (strcmp(param[0], "cb_get_rssi") == 0) {
				char *sta_mac = param[1];
				UINT16 ctrl_rssi;
				UINT32 reset_rssi = FALSE;
				if (priv->cb_enable == FALSE) {
					printk("[%s], cb is uninitialized\n", netdev->name);
					return -EFAULT;
				}
				reset_rssi = atoi(param[2]);
				if (reset_rssi == 255)
					get_rssi(netdev, sta_mac, &ctrl_rssi, TRUE);
				else
					get_rssi(netdev, sta_mac, &ctrl_rssi, FALSE);
				printk("ctrl_rssi = %d\n", (SINT16) ctrl_rssi);
			}
			// CB no_ack APIs
			else if (strcmp(param[0], "cb_noack") == 0) {
				char *sta_mac = param[1];
				long is_on = atohex2(param[2]);
				if (priv->cb_enable == FALSE) {
					printk("[%s], cb is uninitialized\n", netdev->name);
					return -EFAULT;
				}
				set_noack(netdev, sta_mac, is_on);
			}
			// CB handover APIs
			else if (strcmp(param[0], "cb_get") == 0) {
				char *sta_mac = param[1];
				if (priv->cb_enable == FALSE) {
					printk("[%s], cb is uninitialized\n", netdev->name);
					return -EFAULT;
				}
				get_handover_params_cmd(netdev, sta_mac);
				printk("writing %lu bytes\n", sizeof(g_dbg_cbinfo_sta));
				dump_binfile((UINT8 *) (&g_dbg_cbinfo_sta), sizeof(g_dbg_cbinfo_sta), "/tmp/cb_param", 0);
				printk("Write to [/tmp/cb_param] done\n");
				//mwl_hex_dump(&g_dbg_cbinfo_sta, sizeof(g_dbg_cbinfo_sta));
			} else if (strcmp(param[0], "cb_set") == 0) {
				char *sta_mac = param[1];
				uint16_t tx_allow = atohex2(param[2]);
				if (priv->cb_enable == FALSE) {
					printk("[%s], cb is uninitialized\n", netdev->name);
					return -EFAULT;
				}
				// Clear g_dbg_cbinfo_sta
				printk("Clear g_dbg_cbinfo_sta\n");
				memset(&g_dbg_cbinfo_sta, 0, sizeof(g_dbg_cbinfo_sta));
				read_binfile((UINT8 *) (&g_dbg_cbinfo_sta), sizeof(g_dbg_cbinfo_sta), "/tmp/cb_param");
				printk("Read from [/tmp/cb_param]:\n");
				//mwl_hex_dump(&g_dbg_cbinfo_sta, sizeof(g_dbg_cbinfo_sta));
				// Set parameters
				g_dbg_cbinfo_sta.enable_tx = tx_allow;
				set_handover_params_cmd(netdev, sta_mac, &g_dbg_cbinfo_sta, sizeof(g_dbg_cbinfo_sta));
			} else if (strcmp(param[0], "cb_info") == 0) {
				vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
				if (priv->cb_enable == FALSE) {
					printk("[%s], cb is uninitialized\n", netdev->name);
					return -EFAULT;
				}
				printk("cb_info:\n");
				printk("\t tx_drop_cnt: %u\n", priv->cbinfo_bss.tx_drop_cnt);
				printk("\t rx_dup_cnt: %u\n", priv->cbinfo_bss.rx_dup_cnt);
				printk("\t (vapid, macid)=(%u, %u)\n", priv->vap_id, vmacSta_p->VMacEntry.macId);
			} else if (strcmp(param[0], "mcpkt_test") == 0) {
				uint16_t pktcnt = atohex2(param[1]);
				uint16_t gap = atohex2(param[2]);
				if (priv->cb_enable == FALSE) {
					printk("[%s], cb is uninitialized\n", netdev->name);
					return -EFAULT;
				}
				priv->mctest_cnt = pktcnt;
				priv->mctest_sngap = gap;
				TimerFireIn(&priv->cb_mctmer, 1, &mcpkt_test_tmfunc, (void *)priv->netDev, 1);
			} else if (strcmp(param[0], "txpkt_info") == 0) {
				wldump_txskb_info(netdev);
			} else if (strcmp(param[0], "he_rts_threshold") == 0) {
				MIB_802DOT11 *mib1 = vmacSta_p->Mib802dot11;
				UINT16 rts_threshold = (UINT16) atohex2(param[1]);
				printk("Set rts_threshold: %u\n", rts_threshold);
				mib1->he_rts_threshold = rts_threshold;
				wlFwSetIEs(netdev);
			}
#ifdef NULLPKT_DBG
			else if (strcmp(param[0], "nullpkt") == 0) {
				// Show the received null packet => for debug only
				show_nullpkt(wlpd_p);
			}
#endif				//NULLPKT_DBG
			else if (strcmp(param[0], "txd1_drop") == 0) {
				DROPPKT_INFO *dpkt_info = &wlpd_p->droppkt_info;
				int i;

				printk("Dropped pkts records: %u \n", dpkt_info->dropbuf_cnt);
				for (i = 0; i < dpkt_info->dropbuf_cnt; i++) {
					printk("(%u)\n", i);
					mwl_hex_dump(&dpkt_info->dropbuf[i], sizeof(wltxdesc_t));
				}
			} else if (strcmp(param[0], "txd1_drop_func") == 0) {
				UINT32 is_on = atoi(param[1]);
				if (is_on != 0) {
					printk("Enable txd1 drop func\n");
					wlpd_p->is_txd1_drop = TRUE;
				} else {
					printk("Disable txd1 drop func\n");
					wlpd_p->is_txd1_drop = FALSE;
				}
			}
#if defined(TXACNT_REC) && defined (SOC_W906X)
			else if (strcmp(param[0], "txacnt_status") == 0) {
				struct wlprivate_data *wlpd_p = priv->wlpd_p;
				U8 uid;
				printk("PPDU TYPE:\n");
				printk("\t ppdu_host_gen_noack: %u\n", wlpd_p->txacnt_ppdurec_cnt[ppdu_host_gen_noack]);
				printk("\t ppdu_host_gen_ack: %u\n", wlpd_p->txacnt_ppdurec_cnt[ppdu_host_gen_ack]);
				printk("\t ppdu_host_gen_ba: %u\n", wlpd_p->txacnt_ppdurec_cnt[ppdu_host_gen_ba]);
				printk("\t ppdu_sfw_gen: %u\n", wlpd_p->txacnt_ppdurec_cnt[ppdu_sfw_gen]);
				printk("\t ppdu_txdone: %u\n", wlpd_p->txacnt_ppdurec_cnt[ppdu_txdone]);
				printk("================================\n");
				printk("SMAC TxDone Info: \n");
				for (uid = 0; uid < 16; uid++) {
					printk("\t usr_id: %u\n", uid);
					printk("\t tacnt_txdone_ack: %u\n", wlpd_p->txacnt_txdone_cnt[uid][tacnt_txdone_ack]);
					printk("\t tacnt_txdone_ba: %u\n", wlpd_p->txacnt_txdone_cnt[uid][tacnt_txdone_ba]);
					printk("\t tacnt_txdone_timeout: %u\n", wlpd_p->txacnt_txdone_cnt[uid][tacnt_txdone_timeout]);
					printk("\n");
				}

			}
#endif				// defined(TXACNT_REC) && defined (SOC_W906X)
			else if (strcmp(param[0], "cfhul_dbg_msg") == 0) {
				struct wlprivate_data *wlpd_p = priv->wlpd_p;
				wlpd_p->irxdbg_intr.show_msg(&wlpd_p->vrxdbg_db);
			} else if (strcmp(param[0], "cfhul_dbg") == 0) {
				struct wlprivate_data *wlpd_p = priv->wlpd_p;
				if (strcmp(param[1], "on") == 0) {
					set_rxdbg_func(&wlpd_p->irxdbg_intr, rxdbg_cfhul);
				} else {
					set_rxdbg_func(&wlpd_p->irxdbg_intr, rxdbg_dummp);
				}
				wlpd_p->irxdbg_intr.init(&wlpd_p->vrxdbg_db, netdev);
				wlpd_p->irxdbg_intr.active(&wlpd_p->vrxdbg_db, TRUE);
			} else if (strcmp(param[0], "dbgskb") == 0) {

				if (strcmp(param[1], "dump") == 0) {
					UINT32 i, start = 0, len = DBG_SKB_MAX_NUM, end;
					if (input_cnt > 3) {
						start = atoi(param[3]);
						start = (start > 0) ? start : 0;
					}
					if (input_cnt > 4) {
						len = atoi(param[4]);
						len = (len > 0) ? len : 0;
					}
					end = start + len - 1;
					end = (end < DBG_SKB_MAX_NUM - 1) ? end : (DBG_SKB_MAX_NUM - 1);
					if ((strcmp(param[2], "send") == 0) || (strcmp(param[2], "all") == 0)) {
						dbg_skb_send *p = wlpd_p->dbgskb.skb_send;
						if (p) {
							for (i = start; i <= end; i++) {
								printk("[send %4d] pa %8x va %p skb %p wr %4x ts %lu:%lu\n",
								       i,
								       (p + i)->pa,
								       (p + i)->va_data,
								       (p + i)->va_skb, (p + i)->wr, (p + i)->ts.tv_sec, (p + i)->ts.tv_nsec);
							}
						}
					}
					if ((strcmp(param[2], "back") == 0) || (strcmp(param[2], "all") == 0)) {
						dbg_skb_back *p = wlpd_p->dbgskb.skb_back;
						if (p) {
							for (i = start; i <= end; i++) {
								printk("[back %4d] pa %8x va %p skb %p rd %4x bpid %3d signature %8x ts %lu:%lu\n",
								       i,
								       (p + i)->pa,
								       (p + i)->va_data,
								       (p + i)->va_skb,
								       (p + i)->rd,
								       (p + i)->bpid, (p + i)->signature, (p + i)->ts.tv_sec, (p + i)->ts.tv_nsec);
							}
						}
					}

				}
			} else if ((strcmp(param[0], "txnullpkt") == 0)) {
				extern UINT32 wlDataTx_NDP(struct net_device *netdev, IEEEtypes_MacAddr_t * da, u32 txratectrl);
				IEEEtypes_MacAddr_t mac;

				getMacFromString(mac, param[1]);
				if (wlDataTx_NDP(netdev, &mac, 0) != SUCCESS)
					printk("tx null packet fail!\n");
			} else if (strcmp(param[0], "txpendcnt") == 0) {
				if (strcmp(param[1], "sta") == 0) {
					struct wlprivate_data *wlpd_p = priv->wlpd_p;
					UINT32 stnid = atohex2(param[2]);
					UINT32 sta_pend, sta_drop, sta_send, sta_rel;
					sta_send = wlpd_p->except_cnt.tx_sta_send_cnt[stnid];
					sta_rel = wlpd_p->except_cnt.tx_sta_rel_cnt[stnid];
					sta_pend = sta_send - sta_rel;
					sta_drop = wlpd_p->except_cnt.tx_sta_drop_cnt[stnid];
					printk("stnid %u, (p, d, s, r)=(%u ,%u, %u, %u)\n", stnid, sta_pend, sta_drop, sta_send, sta_rel);
				} else if (strcmp(param[1], "bcast") == 0) {
					struct wlprivate_data *wlpd_p = priv->wlpd_p;
					UINT32 bcast_pend, bcast_drop, bcast_send, bcast_rel;
					bcast_send = wlpd_p->except_cnt.tx_bcast_send_cnt;
					bcast_rel = wlpd_p->except_cnt.tx_bcast_rel_cnt;
					bcast_pend = bcast_send - bcast_rel;
					bcast_drop = wlpd_p->except_cnt.tx_bcast_drop_cnt;
					printk("mcast/bcast, (p, d, s, r)=(%u ,%u, %u, %u)\n", bcast_pend, bcast_drop, bcast_send, bcast_rel);
				} else if (strcmp(param[1], "txq") == 0) {
					struct wlprivate_data *wlpd_p = priv->wlpd_p;
					UINT32 i, start = 0, len = 512, end;
					UINT32 txq_pend, txq_drop, txq_send, txq_rel;

					if (input_cnt > 2) {
						start = atoi(param[2]);
						start = (start > 0) ? start : 0;
					}
					if (input_cnt > 3) {
						len = atoi(param[3]);
						len = (len > 0) ? len : 0;
					}

					end = start + len - 1;
					end = (end < SMAC_QID_NUM - 1) ? end : (SMAC_QID_NUM - 1);

					for (i = start; i <= end; i++) {
						txq_send = wlpd_p->except_cnt.txq_send_cnt[i];
						txq_rel = wlpd_p->except_cnt.txq_rel_cnt[i];
						txq_pend = txq_send - txq_rel;
						txq_drop = wlpd_p->except_cnt.txq_drop_cnt[i];
						printk("txqid %4u, (p, d, s, r)=(%u ,%u, %u, %u)\n", i, txq_pend, txq_drop, txq_send, txq_rel);
					}
				} else if (strcmp(param[1], "txd1_drop") == 0) {
					struct wlprivate_data *wlpd_p = priv->wlpd_p;
					UINT32 i, start = 0, len = 512, end;
					BOOLEAN is_drop = FALSE;
					BOOLEAN isclr = FALSE;
					DROPPKT_INFO *pdropbuf = &wlpd_p->droppkt_info;

					if (input_cnt > 2) {
						start = atoi(param[2]);
						start = (start > 0) ? start : 0;
					}
					if (input_cnt > 3) {
						len = atoi(param[3]);
						len = (len > 0) ? len : 0;
					}
					if ((input_cnt > 4) && (strcmp(param[4], "clr") == 0)) {
						isclr = TRUE;
						is_drop = TRUE;	//Will clear the counter => not showing msg
					}

					end = start + len - 1;
					end = (end < SMAC_QID_NUM - 1) ? end : (SMAC_QID_NUM - 1);

					for (i = start; i <= end; i++) {
						if (wlpd_p->except_cnt.txq_txd1_drop_cnt[i] == 0) {
							continue;
						}

						if (isclr == TRUE) {
							wlpd_p->except_cnt.txq_txd1_drop_cnt[i] = 0;
							memset(pdropbuf->drop_reason, 0, sizeof(pdropbuf->drop_reason));
						} else {
							printk("txqid %4u, (txd1_drop)=(%u), reason: (%u, %u, %u, %u, %u, %u, %u, %u)\n", i,
							       wlpd_p->except_cnt.txq_txd1_drop_cnt[i],
							       pdropbuf->drop_reason[i][0], pdropbuf->drop_reason[i][1],
							       pdropbuf->drop_reason[i][2], pdropbuf->drop_reason[i][3],
							       pdropbuf->drop_reason[i][4], pdropbuf->drop_reason[i][5],
							       pdropbuf->drop_reason[i][6], pdropbuf->drop_reason[i][7]);
							is_drop = TRUE;
						}
					}
					if (is_drop == FALSE) {
						printk("No txd1 drop in q[%u - %u]\n", start, end);
					}
				}

			} else if (strcmp(param[0], "tx_async") == 0) {
				struct wlprivate_data *wlpd_p = priv->wlpd_p;
				u8 i;
				u32 qlen_all = 0;
				for (i = 0; i < NUM_OF_DESCRIPTOR_DATA; i++) {
					qlen_all += skb_queue_len(&wlpd_p->txQ[i]);
				}
				if (input_cnt > 1) {	//Set the param
					u32 mode = atohex2(param[1]);
					if (qlen_all > 0) {
						printk("tx-async running, skip switching\n");
					} else {
						if (mode == 0) {	// Send packets directly
							wlpd_p->tx_async = FALSE;
						} else {
							wlpd_p->tx_async = TRUE;
						}
					}
				}
				printk("tx_async = %d\n", wlpd_p->tx_async);
			} else if (!strcmp(param[0], "obss_pd")) {
				u32 mode = atohex2(param[1]);
				u32 val = atoi_2(param[2]);
				UINT32 addr;
				switch (mode) {
				case 1:	//Set/Get OBSS
					addr = 0xa86;
					break;
				case 2:	//Set/Get EBSS
					addr = 0xa87;
					break;
				case 0:	//Set/Get self-BSS
				default:
					addr = 0xa88;
				}
				if (val == 0) {
					// Get
					wlRegBB(netdev, WL_GET, addr, (UINT32 *) & val);
					printk("OBSS_PD, Get, addr(%x) = %d (0x%2x)\n", addr, (SINT8) val, val);
				} else {
					// Set
					printk("OBSS_PD, Set, addr(%x) = %x\n", addr, val);
					wlRegBB(netdev, WL_SET, addr, (UINT32 *) & val);
				}
			} else if (!strcmp(param[0], "stat"))
				wl_show_stat_cmd(netdev, param[1], param[2], NULL);
			else if (!strcmp(param[0], "getrxinfo")) {
				struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
				struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;

				wlpd_p->rxinfo_inused = TRUE;
				printk("Last rx_info:\n");
				mwl_hex_dump(&wlpd_p->last_rxinfo, sizeof(rx_info_ppdu_t));
				wlpd_p->rxinfo_inused = FALSE;
			} else if (!strcmp(param[0], "gettxscheinfo")) {
				if (strcmp(param[1], "acnt") == 0) {
					u32 entry = 25;

					if (strlen(param[2]))
						entry = atoi(param[2]);
					if (entry > NUM_INTERNAL_STAT)
						entry = NUM_INTERNAL_STAT;

					dump_acnt_internal_stat(entry);
				} else if (strcmp(param[1], "all") == 0) {
					u8 *pbuf = wl_vzalloc(4000 * 32);
					u8 linebuf[256];
					u32 entry = 0;
					u8 *ptr = pbuf;
					u8 *filename;

					if (strlen(param[2]))
						filename = param[2];
					else
						filename = "/tmp/gettxscheinfo.txt";

					if (!pbuf)
						return -ENOMEM;

					if (wlFwGetAddrValue(netdev, (u32) 0x0019e800, (4000 * 32) / sizeof(u32), (u32 *) pbuf, 3)) {
						printk("Fail to get ALL FW log tx schedule internal state\n");
						wl_vfree(pbuf);
						return -EIO;
					}

					dump_file("ALL FW log tx schedule internal state\n", strlen("ALL FW log tx schedule internal state\n"),
						  filename, 0);
					for (entry = 0; entry < 4000; entry++) {
						hex_dump_to_buffer(ptr, 32, 32, 4, linebuf, sizeof(linebuf), false);
						linebuf[strlen(linebuf)] = '\n';
						dump_file(linebuf, strlen(linebuf), filename, 1);
						ptr += 32;
					}

					wl_vfree(pbuf);
				} else if (strcmp(param[1], "raw") == 0) {
					if (strcmp(param[2], "f") == 0) {
						char filename[256];
						memset(filename, 0, 256);

						if (strlen(param[3])) {
							strncpy(filename, param[3], sizeof(filename) - 1);
							wl_write_acnt_tx_record(netdev, filename);
						}
					} else if (strlen(param[2])) {
						u32 entry = 0;
						entry = atoi(param[2]);

						if (entry > ACNT_TX_RECORD_MAX)
							entry = ACNT_TX_RECORD_MAX;

						wl_dump_acnt_tx_record(netdev, entry);
					}
				} else if (strcmp(param[1], "enable") == 0) {
					wl_enable_acnt_record_logging(netdev, acnt_code_tx_enqueue);
				} else if (strcmp(param[1], "disable") == 0) {
					wl_disable_acnt_record_logging(netdev, acnt_code_tx_enqueue);
				}
			}
#ifdef CCK_DESENSE
			else if (!strcmp(param[0], "cck-desense") || !strcmp(param[0], "rx_abort")) {
				extern void cck_desense_timer_start(struct net_device *netdev);
				extern void cck_desense_timer_stop(struct net_device *netdev);
				extern void cck_desense_ctrl(struct net_device *netdev, int state);
				extern void cck_desense_polltimer_start(struct net_device *netdev);
				extern void cck_desense_polltimer_stop(struct net_device *netdev);

				struct wlprivate *wlpptr;
				int set_timer = 0;
				u32 val;
				struct cck_des_config *conf;
				u8 loadcfg = 0;

				if (priv->master)
					wlpptr = NETDEV_PRIV_P(struct wlprivate, priv->master);
				else
					wlpptr = priv;

				if (!strcmp(param[0], "cck-desense"))
					conf = &wlpptr->cck_des.cck_des_conf;
				else
					conf = &wlpptr->cck_des.rx_abort_conf;

				if (input_cnt == 1) {
					printk("%s: %d %d %d %d %d %d\n", param[0], conf->enable, conf->rssi_margin, conf->threshold_ceiling,
					       wlpptr->cck_des.on_time_ms, wlpptr->cck_des.off_time_ms, wlpptr->cck_des.update_cycles);
					break;
				}

				if (input_cnt > 1) {
					if (!strcmp(param[1], "run")) {
						cck_desense_ctrl(wlpptr->netDev, CCK_DES_RUN);
					} else if (!strcmp(param[1], "result")) {
						if (conf->enable) {
							if (!strcmp(param[0], "cck-desense")
							    && (*(wlpptr->vmacSta_p->Mib802dot11->mib_ApMode) & AP_MODE_A_ONLY))
								printk("%s not enable in 5G band\n", param[0]);
							else
								printk("%s: minRSSI %d threshold %d state: %s\n", param[0], wlpptr->cck_des.rssi_min,
								       conf->threshold, (wlpptr->cck_des.state & 0x1) ? "ON" : "OFF");
						} else {
							printk("%s: disable\n", param[0]);
						}

					} else if (!strcmp(param[1], "loadcfg")) {
						loadcfg = 1;
						if (input_cnt == 2) {
							printk("%s loadcfg: %d %d %d\n", param[0], wlpptr->cck_des.loadcfg.enable,
							       wlpptr->cck_des.loadcfg.thres_tx, wlpptr->cck_des.loadcfg.thres_cca);
						}
					} else {
						conf->enable = atoi(param[1]);
						set_timer = 1;
					}
				}

				if (loadcfg) {
					if (input_cnt > 2) {
						if (!strcmp(param[2], "result")) {
							if (conf->enable) {
								if (!strcmp(param[0], "cck-desense")
								    && (*(wlpptr->vmacSta_p->Mib802dot11->mib_ApMode) & AP_MODE_A_ONLY))
									printk("%s not enable in 5G band\n", param[0]);
								else
									printk("%s loadcfg: state %s off_reason 0x%x Tx %u kbps CCA %u\n", param[0],
									       ((wlpptr->cck_des.state & 0x1) ? "ON" : "OFF"),
									       wlpptr->cck_des.off_reason, wlpptr->cck_des.loadcfg.data.txbps_avg,
									       wlpptr->cck_des.loadcfg.data.cca_avg);
							} else {
								printk("%s: disable\n", param[0]);
							}

						} else {
							u8 enable = 0;

							wlpptr->cck_des.loadcfg.enable = atoi(param[2]);

							if (input_cnt > 3)
								wlpptr->cck_des.loadcfg.thres_tx = atoi(param[3]);
							if (input_cnt > 4)
								wlpptr->cck_des.loadcfg.thres_cca = atoi(param[4]);

							enable = (wlpptr->cck_des.cck_des_conf.enable || wlpptr->cck_des.rx_abort_conf.enable) &&
							    wlpptr->cck_des.loadcfg.enable;

							if (enable)
								cck_desense_polltimer_start(wlpptr->netDev);
							else
								cck_desense_polltimer_stop(wlpptr->netDev);
						}
					}

					break;
				}

				if (input_cnt > 2)
					conf->rssi_margin = atoi(param[2]);
				if (input_cnt > 3)
					conf->threshold_ceiling = atoi_2(param[3]);
				if (input_cnt > 4) {
					val = atoi(param[4]);
					if (val > 0)
						wlpptr->cck_des.on_time_ms = val;
					else {
						printk("%s: On duration should > 0\n", param[0]);
					}
				}
				if (input_cnt > 5)
					wlpptr->cck_des.off_time_ms = atoi(param[5]);
				if (input_cnt > 6)
					wlpptr->cck_des.update_cycles = atoi(param[6]);

				if (set_timer) {
					if (conf->enable)
						cck_desense_timer_start(wlpptr->netDev);
					else
						cck_desense_timer_stop(wlpptr->netDev);
				}
			}
#endif				/* CCK_DESENSE */
#endif

#ifdef WTP_SUPPORT
			else if (strcmp(param[0], "wtp") == 0) {
				if (strcmp(param[1], "enable") == 0) {
					mib->mib_wtp_cfg->wtp_enabled = 1;
					printk("WTP enabled ...\n");
				} else if (strcmp(param[1], "disable") == 0) {
					mib->mib_wtp_cfg->wtp_enabled = 0;
					printk("WTP disabled ...\n");
				} else {
					printk("usage: \"wtp enable\" or \"wtp disable\"\n");
					rc = -EFAULT;
					break;
				}
			} else if (strcmp(param[0], "wtpmacmode") == 0) {
				if (strcmp(param[1], "localmac") == 0) {
					mib->mib_wtp_cfg->mac_mode = WTP_MAC_MODE_LOCALMAC;
					//
					//flush acnt recds to kick wlHandleAcnt()
					//
#if defined(SOC_W906X) || defined(NEWDP_ACNT_CHUNKS)
					wlAcntProcess_chunks(netdev);
#else
					wlAcntProcess(netdev);
#endif
					printk("set WTP local mac mode ...\n");
				} else if (strcmp(param[1], "splitmac") == 0) {
					mib->mib_wtp_cfg->mac_mode = WTP_MAC_MODE_SPLITMAC;
					printk("set WTP split mac mode ...\n");
				} else {
					printk("usage: \"wtpmacmode localmac\" or \"wtpmacmode splitmac\"\n");
					rc = -EFAULT;
					break;
				}
			} else if (strcmp(param[0], "wtptunnelmode") == 0) {
				if (strcmp(param[1], "80211") == 0) {
					mib->mib_wtp_cfg->frame_tunnel_mode = WTP_TUNNEL_MODE_NATIVE_80211;
					printk("set WTP frame tunnel mode to 80211 ...\n");
				} else if (strcmp(param[1], "8023") == 0) {
					mib->mib_wtp_cfg->frame_tunnel_mode = WTP_TUNNEL_MODE_802_3;
					printk("set WTP frame tunnel mode to 802.3 ...\n");
				} else {
					printk("usage: \"wtptunnelmode 80211\" or \"wtptunnelmode 8023\"\n");
					rc = -EFAULT;
					break;
				}
			} else if (strcmp(param[0], "getwtpcfg") == 0) {
				printk("======= GET WTP configs =======\n");
				if (mib->mib_wtp_cfg->wtp_enabled)
					printk("WTP enabled \n");
				else
					printk("WTP disabled \n");
				if (mib->mib_wtp_cfg->mac_mode == WTP_MAC_MODE_LOCALMAC)
					printk("WTP mac mode = LOCAL MAC\n");
				else if (mib->mib_wtp_cfg->mac_mode == WTP_MAC_MODE_SPLITMAC)
					printk("WTP mac mode = SPLIT MAC\n");
				if (mib->mib_wtp_cfg->frame_tunnel_mode == WTP_TUNNEL_MODE_NATIVE_80211)
					printk("WTP frame tunnel mode = NATIVE 80211\n");
				else if (mib->mib_wtp_cfg->frame_tunnel_mode == WTP_TUNNEL_MODE_802_3)
					printk("WTP frame tunnel mode = 802.3\n");
				else if (mib->mib_wtp_cfg->frame_tunnel_mode == WTP_TUNNEL_MODE_LOCAL_BRIDGING)
					printk("WTP frame tunnel mode = Local bridging\n");
				printk("===============================\n");
			} else if (strcmp(param[0], "getradiostat") == 0) {
				struct RadioStats *stats;
				stats = wl_vzalloc(sizeof(struct RadioStats));
				if (!stats) {
					rc = -ENOMEM;
					break;
				}
				wlFwGetWTPRadioStats(netdev, (char *)stats);
				printk("Stats->RxOverrunErr=%d\n", stats->RxOverrunErr);
				printk("Stats->RxMacCrcErr=%d\n", stats->RxMacCrcErr);
				printk("Stats->RxWepErr=%d\n", stats->RxWepErr);
				printk("Stats->MaxRetries=%d\n", stats->MaxRetries);
				printk("Stats->RxAck=%d\n", stats->RxAck);
				printk("Stats->NoAck=%d\n", stats->NoAck);
				printk("Stats->NoCts=%d\n", stats->NoCts);
				printk("Stats->RxCts=%d\n", stats->RxCts);
				printk("Stats->TxRts=%d\n", stats->TxRts);
				printk("Stats->TxCts=%d\n", stats->TxCts);
				printk("Stats->TxUcFrags=%d\n", stats->TxUcFrags);
				printk("Stats->Tries=%d\n", stats->Tries);
				printk("Stats->TxMultRetries=%d\n", stats->TxMultRetries);
				printk("Stats->RxUc=%d\n", stats->RxUc);
				printk("Stats->TxBroadcast=%d\n", stats->TxBroadcast);
				printk("Stats->RxBroadcast=%d\n", stats->RxBroadcast);
				printk("Stats->TxMgmt=%d\n", stats->TxMgmt);
				printk("Stats->TxCtrl=%d\n", stats->TxCtrl);
				printk("Stats->TxBeacon=%d\n", stats->TxBeacon);
				printk("Stats->TxProbeRsp=%d\n", stats->TxProbeRsp);
				printk("Stats->RxMgmt=%d\n", stats->RxMgmt);
				printk("Stats->RxCtrl=%d\n", stats->RxCtrl);
				printk("Stats->RxBeacon=%d\n", stats->RxBeacon);
				printk("Stats->RxProbeReq=%d\n", stats->RxProbeReq);
				printk("Stats->DupFrag=%d\n", stats->DupFrag);
				printk("Stats->RxFrag=%d\n", stats->RxFrag);
				printk("Stats->RxAged=%d\n", stats->RxAged);
				printk("Stats->TxKb=%d\n", stats->TxKb);
				printk("Stats->RxKb=%d\n", stats->RxKb);
				printk("Stats->TxAggr=%d\n", stats->TxAggr);
				printk("Stats->Jammed=%d\n", stats->Jammed);
				printk("Stats->TxConcats=%d\n", stats->TxConcats);
				printk("Stats->RxConcats=%d\n", stats->RxConcats);
				printk("Stats->TxHwWatchdog=%d\n", stats->TxHwWatchdog);
				printk("Stats->TxSwWatchdog=%d\n", stats->TxSwWatchdog);
				printk("Stats->NoAckPolicy=%d\n", stats->NoAckPolicy);
				printk("Stats->TxAged=%d\n", stats->TxAged);
				memcpy(bufBack, (char *)stats, sizeof(struct RadioStats));
				wl_vfree(stats);
				*ret_len = sizeof(struct RadioStats);
			}
#endif
#ifdef MFG_SUPPORT
			else if ((strcmp(param[0], "extfw") == 0) || (strcmp(param[0], "mfgfw") == 0)) {
				int mfgCmd = 0;
				if (strcmp(param[0], "mfgfw") == 0)
					mfgCmd = 1;

				if (!LoadExternalFw(priv, param[1])) {
					/* No file is loaded */
					rc = -EFAULT;
					break;
				}

				if (netdev->flags & IFF_RUNNING) {
					if (mfgCmd)
						priv->mfgEnable = 1;

					/* Only load one time for mfgfw */
					if (!priv->mfgLoaded)
						rc = priv->wlreset(netdev);
					else
						rc = 0;

					if (mfgCmd)
						priv->mfgLoaded = 1;
					else
						priv->mfgLoaded = 0;
				} else if (priv->devid == SC4) {
					rc = 0;
				} else if (priv->devid == SC4P) {
					rc = 0;
				} else if (priv->devid == SC5) {
					rc = 0;
				} else if (priv->devid == SCBT) {
					rc = 0;
				} else {
					rc = -EFAULT;
				}

				if (rc) {
					if (mfgCmd) {
						priv->mfgEnable = 0;
						priv->mfgLoaded = 0;
					}
					printk("FW download failed.\n");
				} else {
					if (!priv->mfgLoaded)
						printk("FW download ok.\n");
				}
				break;
			} else if (strcmp(param[0], "mfg") == 0) {
				extern int wlFwMfgCmdIssue(struct net_device *netdev, char *pData, char *pDataOut);

				char *pOut = cmdGetBuf;
				char *pIn = param_str + strlen(param[0]) + 1;
				UINT16 len = 0;

				wlFwMfgCmdIssue(netdev, pIn, (pOut + 4));
				len = le16_to_cpu(*(UINT16 *) (pOut + 6));
				*(int *)&pOut[0] = len;
				*ret_len = len + sizeof(int);

				bufBack = pOut;

				break;
			} else if (strcmp(param[0], "fwrev") == 0) {
				if (wlPrepareFwFile(netdev)) {
					printk("Error: wlPrepareFwFile return status as failed\n");
				}
				if (netdev->flags & IFF_RUNNING)
					rc = priv->wlreset(netdev);
				else
					rc = -EFAULT;

				break;
			} else
#endif
			if (strcmp(param[0], "addba") == 0) {
				extern void AddbaTimerProcess(UINT8 * data);
				char macaddr[6];
				//char macaddr2[6];
				int tid;
				UINT32 seqNo = 0;
				int stream;

				if ((strlen((char *)param[1]) != 12) || (!IsHexKey((char *)param[1]))) {
					rc = -EFAULT;
					break;
				}
				getMacFromString(macaddr, param[1]);
				tid = atohex2(param[2]);
				stream = atohex2(param[3]);
				if ((stream > 7) || (tid > 7)) {
					rc = -EFAULT;
					break;
				}

				if (priv->wlpd_p->Ampdu_tx[stream].InUse != 1) {
					priv->wlpd_p->Ampdu_tx[stream].MacAddr[0] = macaddr[0];
					priv->wlpd_p->Ampdu_tx[stream].MacAddr[1] = macaddr[1];
					priv->wlpd_p->Ampdu_tx[stream].MacAddr[2] = macaddr[2];
					priv->wlpd_p->Ampdu_tx[stream].MacAddr[3] = macaddr[3];
					priv->wlpd_p->Ampdu_tx[stream].MacAddr[4] = macaddr[4];
					priv->wlpd_p->Ampdu_tx[stream].MacAddr[5] = macaddr[5];
					priv->wlpd_p->Ampdu_tx[stream].AccessCat = tid;
					priv->wlpd_p->Ampdu_tx[stream].InUse = 1;
					priv->wlpd_p->Ampdu_tx[stream].TimeOut = 0;
					priv->wlpd_p->Ampdu_tx[stream].AddBaResponseReceive = 0;
					priv->wlpd_p->Ampdu_tx[stream].DialogToken = priv->wlpd_p->Global_DialogToken;
					priv->wlpd_p->Global_DialogToken = (priv->wlpd_p->Global_DialogToken + 1) % 63;
					if (priv->wlpd_p->Ampdu_tx[stream].initTimer == 0) {
						TimerInit(&priv->wlpd_p->Ampdu_tx[stream].timer);
						priv->wlpd_p->Ampdu_tx[stream].initTimer = 1;
					}
					TimerDisarm(&priv->wlpd_p->Ampdu_tx[stream].timer);
					priv->wlpd_p->Ampdu_tx[stream].vmacSta_p = vmacSta_p;
					TimerFireIn(&priv->wlpd_p->Ampdu_tx[stream].timer, 1, &AddbaTimerProcess,
						    (UINT8 *) & priv->wlpd_p->Ampdu_tx[stream], 10);
				} else {
					printk("Stream %x is already in use \n", stream);
					break;
				}
				if (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_CLNT_INFRA)
					SendAddBAReqSta(vmacSta_p, macaddr, tid, 1, seqNo, priv->wlpd_p->Ampdu_tx[stream].DialogToken);
				else
					SendAddBAReq(vmacSta_p, macaddr, tid, 1, seqNo, priv->wlpd_p->Ampdu_tx[stream].DialogToken, 0, &(priv->wlpd_p->Ampdu_tx[stream].BufSizeInReq));	      /** Only support immediate ba **/
				//  wlFwCreateBAStream(64, 64 , macaddr,    10, tid, 1,  stream);  //for mike stupid code
			} else if (strcmp(param[0], "ampdu_stat") == 0) {
				int i, j;

				for (i = 0; i < MAX_SUPPORT_AMPDU_TX_STREAM_RUNNING; i++) {
					printk(": ");
					for (j = 0; j < 6; j++) {
						printk("%x ", priv->wlpd_p->Ampdu_tx[i].MacAddr[j]);
					}
					printk("tid %x Inuse %x timeout %d pps %d\n", priv->wlpd_p->Ampdu_tx[i].AccessCat,
					       priv->wlpd_p->Ampdu_tx[i].InUse, (int)priv->wlpd_p->Ampdu_tx[i].TimeOut,
					       (int)priv->wlpd_p->Ampdu_tx[i].txa_avgpps);
					printk("\n");
				}

			} else if (strcmp(param[0], "delba") == 0) {
				char macaddr2[6];
				int tid;
				int i;

				if ((strlen((char *)param[1]) != 12) || (!IsHexKey((char *)param[1]))) {
					rc = -EFAULT;
					break;
				}
				getMacFromString(macaddr2, param[1]);
				tid = atohex2(param[2]);
				if (tid > 7) {
					rc = -EFAULT;
					break;
				}

				for (i = 0; i < 7; i++) {
					printk(" AMacaddr2 %x %x %x %x %x %x\n", priv->wlpd_p->Ampdu_tx[i].MacAddr[0],
					       priv->wlpd_p->Ampdu_tx[i].MacAddr[1], priv->wlpd_p->Ampdu_tx[i].MacAddr[2],
					       priv->wlpd_p->Ampdu_tx[i].MacAddr[3], priv->wlpd_p->Ampdu_tx[i].MacAddr[4],
					       priv->wlpd_p->Ampdu_tx[i].MacAddr[5]);
					printk(" Macaddr2 %x %x %x %x %x %x\n", macaddr2[0], macaddr2[1], macaddr2[2], macaddr2[3], macaddr2[4],
					       macaddr2[5]);
					printk(" tid = %x , In Use = %x \n*******\n", priv->wlpd_p->Ampdu_tx[i].AccessCat,
					       priv->wlpd_p->Ampdu_tx[i].InUse);
					disableAmpduTx(vmacSta_p, macaddr2, tid);
				}
			} else if (strcmp(param[0], "del2ba") == 0) {
								   /** fake command use by WIFI testbed **/
				char macaddr2[6];
				int tid;

				if ((strlen((char *)param[1]) != 12) || (!IsHexKey((char *)param[1]))) {
					rc = -EFAULT;
					break;
				}
				getMacFromString(macaddr2, param[1]);
				tid = atohex2(param[2]);
				if (tid > 7) {
					rc = -EFAULT;
					break;
				}

				SendDelBA2(vmacSta_p, macaddr2, tid);
			} else if (strcmp(param[0], "AmpduRxDisable") == 0) {
				/*
				   Format:
				   AmpduRxDisable [0|1] [mac_addr]
				   if [mac_addr] exist => Add mac_addr to the exception list
				   example:
				   - Disable ampdu from sta
				   iwpriv wdev1ap0 setcmd "AmpduRxDisable 1"
				   - While ampdu is allowed, disabling ampdu for just a specific sta
				   iwpirv wdev1ap0 setcmd "AmpduRxDisable 0 005043112233"
				 */
				UINT8 option;
				IEEEtypes_MacAddr_t macaddr;

				if ((strlen((char *)param[1]) != 1) || (!IsHexKey((char *)param[1]))) {
					rc = -EFAULT;
					break;
				}

				option = atohex2(param[1]);
				if (strlen((char *)param[2]) > 0) {
					mac_pool *pmac_pool;
					getMacFromString(macaddr, param[2]);
					if (option == 0) {	//Disable == 0 => Set the accept list
						pmac_pool = &vmacSta_p->ampdu_acpt_pool;
					} else {	// Otherwise, set the reject list
						pmac_pool = &vmacSta_p->ampdu_rejt_pool;
					}
					memcpy(pmac_pool->mac_pool[pmac_pool->avail_id], macaddr, sizeof(IEEEtypes_MacAddr_t));
					pmac_pool->avail_id = (pmac_pool->avail_id + 1) % MAC_POOL_SIZE;

				} else {
					vmacSta_p->Ampdu_Rx_Disable_Flag = option;
				}

			} else if (strcmp(param[0], "AmsduRxDisable") == 0) {
				UINT8 option;

				if ((strlen((char *)param[1]) != 1) || (!IsHexKey((char *)param[1]))) {
					rc = -EFAULT;
					break;
				}

				option = atohex2(param[1]);

				vmacSta_p->Amsdu_Rx_Disable_Flag = option;
			} else if (strcmp(param[0], "rifs") == 0) {
				UINT8 QNum;
				QNum = atohex2(param[1]);
				*(mib->mib_rifsQNum) = QNum;
				//wlFwSetRifs(netdev, QNum);
			} else if (strcmp(param[0], "no_aggr_for_vo") == 0) {
				*(mib->disable_aggr_for_vo) = atoi(param[1]);
				printk("disable_aggr_for_vo = %d \n", *(mib->disable_aggr_for_vo));
			} else if (strcmp(param[0], "enable_arp_for_vo") == 0) {
				MIB_802DOT11 *mib1 = vmacSta_p->Mib802dot11;

				*(mib->enable_arp_for_vo) = atoi(param[1]);
				*(mib1->enable_arp_for_vo) = *(mib->enable_arp_for_vo);
				printk("enable_arp_for_vo=%d, %s\n", *(mib->enable_arp_for_vo),
				       *(mib->enable_arp_for_vo) ? "ARP will be set to priority VO." : "ARP will be set to priority BE (default).");
			} else if (strcmp(param[0], "disable_qosctl") == 0) {
				MIB_802DOT11 *mib1 = vmacSta_p->Mib802dot11;

				*(mib->disable_qosctl) = atoi(param[1]);
				*(mib1->disable_qosctl) = *(mib->disable_qosctl);
				printk("disable_qosctl=%d, %s\n", *(mib->disable_qosctl),
				       *(mib->disable_qosctl) ?
				       "MC/BC TX - Qos data will not be set" : "MC/BC TX - Qos data will be set if QSTA is connected.");
			}
#ifdef COEXIST_20_40_SUPPORT
			else if (strcmp(param[0], "intolerant40") == 0) {
				UINT8 protection2040;
				UINT8 mode;

				if ((strlen((char *)param[1]) != 1) || (!IsHexKey((char *)param[1]))) {
					printk(" intolerant40 = %x HT40MIntoler=%x \n", *(vmacSta_p->Mib802dot11->mib_FortyMIntolerant),
					       *(vmacSta_p->Mib802dot11->mib_HT40MIntoler));
					printk("shadow intolerant40 = %x HT40MIntoler=%x \n", *(vmacSta_p->ShadowMib802dot11->mib_FortyMIntolerant),
					       *(vmacSta_p->ShadowMib802dot11->mib_HT40MIntoler));
				} else {

					protection2040 = atohex2(param[1]);
					mode = atohex2(param[2]);
					/* wait for scan complete */
					if (vmacSta_p->preautochannelfinished == 0) {
						unsigned long wait_ret = 0;
						wait_ret = wait_for_completion_timeout(&vmacSta_p->scan_complete, vmacSta_p->scan_timeout);
						if (vmacSta_p->preautochannelfinished == 0)
							printk(KERN_WARNING "Wait scan finish timeout, intolerant40, %us, %lu\n",
							       (vmacSta_p->scan_timeout / HZ), wait_ret);
						else
							printk("Pre-Auto channel finsihed for intolerant40\n");
					}
					if (protection2040 == 0) {
						*(vmacSta_p->ShadowMib802dot11->mib_HT40MIntoler) = 0;
											    /** 20/40 coexist protection mechanism off **/
						printk("Setting 20/40 Coexist off\n");

					}
					if (protection2040 == 1) {
						*(vmacSta_p->ShadowMib802dot11->mib_HT40MIntoler) = 1;
											    /** 20/40 coexist protection mechanism on **/
						printk("Setting 20/40 Coexist on\n");

					} else if (protection2040 == 2) {
						*(vmacSta_p->ShadowMib802dot11->mib_FortyMIntolerant) = 1;
						printk("Setting tolerant AP\n");
					} else if (protection2040 == 3) {
						extern int wlFwSet11N_20_40_Switch(struct net_device *netdev, UINT8 mode);

						*(vmacSta_p->ShadowMib802dot11->mib_FortyMIntolerant) = mode;
						*(mib->USER_ChnlWidth) = mode;

						wlFwSet11N_20_40_Switch(vmacSta_p->dev, mode);
						printk("Setting 20/40 with bw %d\n", mode);
					}
				}

			} else if (strcmp(param[0], "TriggerScanInterval") == 0) {
				UINT16 TriggerScanInterval;

				TriggerScanInterval = atohex2(param[1]);

				printk("Set TriggerScanInterval to %x\n", TriggerScanInterval);

				*(mib->mib_Channel_Width_Trigger_Scan_Interval) = TriggerScanInterval;

			}
#endif

#ifdef EXPLICIT_BF

			else if (strcmp(param[0], "SetBF") == 0) {
				extern int wlFwSet11N_BF_Mode(struct net_device *netdev, UINT8 bf_option, UINT8 bf_csi_steering, UINT8 bf_mcsfeedback,
							      UINT8 bf_mode, UINT8 bf_interval, UINT8 bf_slp, UINT8 bf_power);
				UINT8 option, csi_steering, mcsfeedback, mode, interval, slp, power;

				if (strcmp(param[1], "help") == 0) {
					printk("Usage: SetBF option csi_steering mcsfeedback mode interval slp power \n");
					printk(" Eg. SetBF  0 3 0 0 1 1 255\n");
					printk(" Option          : 0 Auto, send NDPA every second\n");
					printk("                     : 1 Send NDPA manually\n");
					printk("CSI steering : 0 csi steering no feedback\n");
					printk("                      : 1 csi steering fb csi\n");
					printk("                      : 2 csi steering fb no compress bf\n");
					printk("                      : 3 csi steering fb compress bf\n");
					printk("Mcsfeedback   : 0 MCS feedback off,  1 MCS feedback on\n");
					printk("Mode             : 0 NDPA\n");
					printk("                      : 1 Control Wrapper \n");
					printk("Interval         : in ~20msec\n");
					printk("slp                 : 1 ON 0 OFF\n");
					printk("power            : trpc power id for NDP, use 0xff to take pid from last transmitted data pck \n");

					rc = -EFAULT;
					break;
				}

				option = atohex2(param[1]);
				csi_steering = atohex2(param[2]);
				mcsfeedback = atohex2(param[3]);
				mode = atohex2(param[4]);
				interval = atohex2(param[5]);
				slp = atohex2(param[6]);
				power = atohex2(param[7]);

				printk("Set 11n BF mode option=%d csi_steer=%d mcsfb=%d mode=%d interval=%d slp=%d, power=%d\n",
				       option, csi_steering, mcsfeedback, mode, interval, slp, power);

				wlFwSet11N_BF_Mode(vmacSta_p->dev, option, csi_steering, mcsfeedback, mode, interval, slp, power);

			}
#ifdef SOC_W906X
			else if (strcmp(param[0], "SetOfdma") == 0) {
				extern int wlFwSetOfdma_Mode(struct net_device *netdev, UINT8 option, UINT8 ru_mode, UINT32 max_delay, U32 max_sta);
				int fwcmd_set = 1;
				if (strcmp(param[1], "help") == 0) {
					printk("Usage: SetOfdma option ru_mode max_delay max_sta \n");
					printk(" Eg. SetOfdma  1 2 3000 4\n");
					printk(" Option          : 0/1/2 off/On/delay-On\n");
					printk(" ru_mode : 0 auto_ru\n");
					printk("                      : 1 fix ru 26\n");
					printk("                      : 2 fix ru 52\n");
					printk("                      : 3 fix ru 106\n");
					printk("                      : 4 fix ru 242\n");
					printk(" max_delay   : hold packet till expiry in us\n");
					printk(" max_sta             : max expect STA to hold packet\n");

					rc = -EFAULT;
					break;
				}

				if (input_cnt == 1) {
					int i;
					printk("Set ofdma option=%d ru_mode=%d max_delay=%d max_sta=%d postponed cmd %lu seconds\n",
					       vmacSta_p->dl_ofdma_para.option,
					       vmacSta_p->dl_ofdma_para.ru_mode,
					       vmacSta_p->dl_ofdma_para.max_delay,
					       vmacSta_p->dl_ofdma_para.max_sta, vmacSta_p->dl_ofdma_para.postpone_time / HZ);

					for (i = 0; i < vmacSta_p->dl_ofdma_para.sta_cnt; i++) {
						printk("per STA txq dropped cnt: %d\n", wlpd_p->except_cnt.tx_sta_drop_cnt[i]);
						printk("per STA txq sent cnt: %d\n", wlpd_p->except_cnt.tx_sta_send_cnt[i]);
						printk("per STA txq released cnt: %d\n", wlpd_p->except_cnt.tx_sta_rel_cnt[i]);
					}

					break;
				}

				vmacSta_p->dl_ofdma_para.option = atohex2(param[1]);
				vmacSta_p->dl_ofdma_para.ru_mode = atohex2(param[2]);
				vmacSta_p->dl_ofdma_para.max_delay = atohex2(param[3]);
				vmacSta_p->dl_ofdma_para.max_sta = atohex2(param[4]);

				if (input_cnt >= 6)
					vmacSta_p->dl_ofdma_para.postpone_time = atohex2(param[5]) * HZ;

				printk("Set ofdma option=%d ru_mode=%d max_delay=%d max_sta=%d postponed cmd %lu seconds\n",
				       vmacSta_p->dl_ofdma_para.option,
				       vmacSta_p->dl_ofdma_para.ru_mode,
				       vmacSta_p->dl_ofdma_para.max_delay,
				       vmacSta_p->dl_ofdma_para.max_sta, vmacSta_p->dl_ofdma_para.postpone_time / HZ);

				if (!vmacSta_p->dl_ofdma_para.option) {
					vmacSta_p->dl_ofdma_para.sta_cnt = 0;
					/* disable OFDMA */
				}
				if (vmacSta_p->dl_ofdma_para.option == 2) {
					vmacSta_p->dl_ofdma_para.option = 1;
					fwcmd_set = 0;
				}

				if (fwcmd_set) {
					printk("Set ofdma fw cmd (NOW): option=%d ru_mode=%d max_delay=%d max_sta=%d\n",
					       vmacSta_p->dl_ofdma_para.option,
					       vmacSta_p->dl_ofdma_para.ru_mode,
					       vmacSta_p->dl_ofdma_para.max_delay, vmacSta_p->dl_ofdma_para.max_sta);

					wlFwSetOfdma_Mode(vmacSta_p->dev, vmacSta_p->dl_ofdma_para.option,
							  vmacSta_p->dl_ofdma_para.ru_mode,
							  vmacSta_p->dl_ofdma_para.max_delay, vmacSta_p->dl_ofdma_para.max_sta);
					/* fw cmd issued and no need to do in ADDBA response */
					vmacSta_p->dl_ofdma_para.max_sta = 0;
				}

				if (vmacSta_p->master)
					memcpy(&vmacSta_p->master->dl_ofdma_para, &vmacSta_p->dl_ofdma_para, sizeof(vmacSta_p->dl_ofdma_para));
			}
#endif

			/*Get auto MU set creation status */
			else if ((strcmp(param[0], "get_mumimomgmt") == 0)) {
				if (!priv->master) {
					printk("Error. Please enter vap interface instead\n");
					rc = -EOPNOTSUPP;
					break;
				}

				printk("mumimo mgmt status is %d\n", (int)*(mib->mib_mumimo_mgmt));
				break;
			}
			/*Set auto MU set creation, 1: enable, 0: disable */
			else if ((strcmp(param[0], "set_mumimomgmt") == 0)) {
				int val;
				if (!priv->master) {
					printk("Error. Please enter vap interface instead\n");
					rc = -EOPNOTSUPP;
					break;
				}

				val = atoi(param[1]);
				if (val != 0 && val != 1) {
					printk("incorrect status values \n");
					break;
				}
				*(mib->mib_mumimo_mgmt) = val;
				printk("mumimo mgmt status is %d\n", (int)*(mib->mib_mumimo_mgmt));
				break;
			}
			/*Get list of MU capable stations */
			else if (strcmp(param[0], "GetMUSta") == 0) {
				if (!priv->master) {
					printk("Error. Please enter vap interface instead\n");
					rc = -EOPNOTSUPP;
					break;
				}

				MUDisplayMUStaList(vmacSta_p);
				break;
			}
			/*Get list of MU sets that are created */
			else if (strcmp(param[0], "GetMUSet") == 0) {
				if (strcmp(param[1], "drv") == 0)
					MUDisplayMUSetList(vmacSta_p);
				else if (strcmp(param[1], "fw") == 0) {
					extern int wlFwGetMUSet(struct net_device *netdev, UINT8 index);
					printk("GetMUSet");
					wlFwGetMUSet(netdev, 0);
				} else
					MUDisplayMUSetList(vmacSta_p);

				break;
			}
			/*Set MU set manually by providing sta id
			 * "SetMUSet <staid1 for user1> <staid2 for user2> <staid3 for user3>". Set staid=0 if MU user is not needed
			 */
			else if (strcmp(param[0], "SetMUSet") == 0) {
#ifdef SOC_W906X
				UINT8 i, j, MUUsrCnt = 0;
				UINT16 *Stnid;
				MUCapStaNode_t *item_p = NULL;
				extStaDb_StaInfo_t **StaInfo;

				Stnid = wl_vzalloc(MU_MAX_USERS * sizeof(UINT16));
				StaInfo = wl_vzalloc(MU_MAX_USERS * sizeof(extStaDb_StaInfo_t *));
				if (!Stnid || !StaInfo) {
					rc = -ENOMEM;
					break;
				}

				for (i = 0; i < MU_MAX_USERS; i++) {
					StaInfo[i] = NULL;
					Stnid[i] = (UINT16) 0XFFFF;

					if (*param[i + 1] != 0)
						Stnid[i] = atohex2(param[i + 1]);
				}

				//printk("Stnid:%x %x %x %x %x %x %x %x %x\n", Stnid[0],Stnid[1],Stnid[2],Stnid[3],Stnid[4],Stnid[5],Stnid[6],Stnid[7],Stnid[8]);

				if (!priv->master) {
					printk("Error. Please enter vap interface instead\n");
					rc = -EOPNOTSUPP;
					wl_vfree(Stnid);
					wl_vfree(StaInfo);
					break;
				}

				/*Find matching sta id in MUStaList */
				for (i = 0; i < ARRAY_SIZE(vmacSta_p->MUStaList); i++) {
					for (j = 0; j < MU_MAX_USERS; j++) {

						if (Stnid[j] == (UINT16) 0XFFFF)
							continue;

						item_p = (MUCapStaNode_t *) vmacSta_p->MUStaList[i].tail;	//get first item added to list from tail
						while (item_p != NULL) {
							if (item_p->StaInfo_p->StnId == Stnid[j]) {
								StaInfo[MUUsrCnt] = item_p->StaInfo_p;
								MUUsrCnt++;
								break;
							}

							item_p = item_p->prv;
						}
					}
				}

				if (MUUsrCnt >= 2)
					MUManualSet(vmacSta_p, StaInfo);
				else
					printk("FAIL to create MU set, no. of user < 2\n");

				wl_vfree(Stnid);
				wl_vfree(StaInfo);
				break;
#else
				UINT8 i, j, MUUsrCnt = 0;
				UINT16 Stnid[3];
				MUCapStaNode_t *item_p = NULL;
				extStaDb_StaInfo_t *StaInfo[3] = { NULL, NULL, NULL };

				Stnid[0] = atohex2(param[1]);
				Stnid[1] = atohex2(param[2]);
				Stnid[2] = atohex2(param[3]);

				if (!priv->master) {
					printk("Error. Please enter vap interface instead\n");
					rc = -EOPNOTSUPP;
					break;
				}

				if ((Stnid[0] == 0) && (Stnid[1] == 0) && (Stnid[2] == 0)) {
					printk("Usage: SetMUSet <staid1> <staid2> <staid3>\n");
					rc = -EOPNOTSUPP;
					break;
				}

				if (Stnid[0] == Stnid[1] || Stnid[0] == Stnid[2] || Stnid[1] == Stnid[2]) {
					printk("SetMUSet error: staids must be different\n");
					printk("Usage: SetMUSet <staid1> <staid2> <staid3>\n");
					rc = -EOPNOTSUPP;
					break;
				}

				/*Find matching sta id in MUStaList */
				for (i = 0; i < 4; i++) {
					for (j = 0; j < 3; j++) {

						item_p = (MUCapStaNode_t *) vmacSta_p->MUStaList[i].tail;	//get first item added to list from tail
						while (item_p != NULL) {
							if (item_p->StaInfo_p->StnId == Stnid[j]) {
								StaInfo[MUUsrCnt] = item_p->StaInfo_p;
								MUUsrCnt++;
								break;
							}

							item_p = (MUCapStaNode_t *) item_p->prv;
						}
					}
				}

				if (MUUsrCnt >= 2) {
					if (!MUManualSet(vmacSta_p, StaInfo[0], StaInfo[1], StaInfo[2])) {
						printk("SetMUSet FAIL (MUManualSet)\n");
					}
				} else
					printk("SetMUSet FAIL, no. of user < 2\n");
				break;
#endif
			}
#ifdef SOC_W906X
			else if (strcmp(param[0], "SetMUSet_debug") == 0) {
				UINT8 i, j, MUUsrCnt = 0;
				UINT16 *Stnid;
				MUCapStaNode_t *item_p = NULL;
				extStaDb_StaInfo_t **StaInfo;
				UINT8 myGid = 1;
				u32 cmd_option = 1;	/* 1 as default for VHT MU group */

				myGid = atohex(param[1]);

				Stnid = wl_kmalloc(MU_MAX_USERS * sizeof(UINT16), GFP_KERNEL);
				StaInfo = wl_kmalloc(MU_MAX_USERS * sizeof(extStaDb_StaInfo_t *), GFP_KERNEL);
				if (!Stnid || !StaInfo) {
					rc = -ENOMEM;
					break;
				}

				for (i = 0; i < MU_MAX_USERS; i++) {
					StaInfo[i] = NULL;
					Stnid[i] = (UINT16) 0xFFFF;

					if (*param[i + 2] == 0)
						break;
					else
						Stnid[i] = atohex(param[i + 2]);
				}

				MUUsrCnt = i;

				printk("Value of MuUsr=%d Gid=%d\n", MUUsrCnt, myGid);

				for (i = 0; i < MUUsrCnt; i++)
					printk("Stnid:%x\n", Stnid[i]);

				if (!priv->master) {
					printk("Error. Please enter vap interface instead\n");
					rc = -EOPNOTSUPP;
					wl_kfree(Stnid);
					wl_kfree(StaInfo);
					break;
				}

				/*Find matching sta id in MUStaList */
				for (i = 0; i < ARRAY_SIZE(vmacSta_p->MUStaList); i++) {
					for (j = 0; j < MU_MAX_USERS; j++) {
						if (Stnid[j] == (UINT16) 0xFFFF)
							break;

						item_p = (MUCapStaNode_t *) vmacSta_p->MUStaList[i].tail;	//get first item added to list from tail
						while (item_p != NULL) {
							if (item_p->StaInfo_p->StnId == Stnid[j]) {
								StaInfo[j] = item_p->StaInfo_p;
								break;
							}
							item_p = item_p->prv;
						}
					}
				}

				if (myGid != 0) {
					for (i = 0; i < MUUsrCnt; i++) {
						if (StaInfo[i] != NULL) {
							printk("%x %x %x %x %x\n", StaInfo[i]->StnId, StaInfo[i]->Addr[0], StaInfo[i]->Addr[1],
							       StaInfo[i]->Addr[2], StaInfo[i]->Addr[3]);
							if (!is_he_capable_sta(StaInfo[i]))
								SendGroupIDMgmtframe(vmacSta_p, StaInfo[i]->Addr, myGid, i);
							else
								cmd_option = 2;	/* 2 for HE MU group */
							Stnid[i] = StaInfo[i]->StnId;
						} else
							Stnid[i] = 0xffff;	//dummy
					}
				}

				if (wlFwSetMUSet(vmacSta_p->dev, cmd_option, myGid, myGid - 1, Stnid))
					printk("Set %s MU set OK!\n", (cmd_option == 2) ? "HE" : "VHT");
				else {
					printk("Error. Set MU set fail!\n");
					rc = -EOPNOTSUPP;
				}

				wl_kfree(Stnid);
				wl_kfree(StaInfo);
				break;
			} else if (strcmp(param[0], "AxAutoGrp") == 0) {
				u32 enable = atoi(param[1]);

				if (enable) {
					ofdma_autogrp = enable;

					if (ofdma_autogrp == 2) {
						int num;

						//first enable. Do autogroup for existing STAs
						num = auto_group_ofdma_mu(vmacSta_p);
						printk("%d STAs are grouped\n", num);
					}
				} else
					ofdma_autogrp = 0;
				break;
			} else if (strcmp(param[0], "healthmonitor") == 0) {
				UINT32 enable = atohex2(param[1]);
				UINT32 bitmap = (UINT32) (WLMON_DEFAULT_HMMASK);
				UINT32 format = (UINT32) (SMAC_STATUS_FORMAT_RAW);

				if (input_cnt > 2)
					bitmap = atohex2(param[2]);
				if (input_cnt > 3)
					format = atohex2(param[3]);

				wldbgCoreMonitor(netdev, enable, bitmap, format);
				break;
			} else if (strcmp(param[0], "healthmonitor_temperature_threshold") == 0) {
				struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
				UINT32 val;
				UINT8 set = WL_GET;
				if (param[1][0]) {
					val = atohex2(param[1]);
					set = WL_SET;
				}

				if (set == WL_SET) {
					wlpptr->wlpd_p->smon.temperature_threshold = val;
				} else {
					val = wlpptr->wlpd_p->smon.temperature_threshold;
				}
				printk("%s healthmonitor_temperature_threshold = %d\n", set ? "Set" : "Get", (int)val);

				break;
			} else if (strcmp(param[0], "coredumppath") == 0) {
				extern char coredumppath[64];
				u32 len = strlen(param[1]);

				if (param[1][0] != '/' || len > 32 || param[1][len - 1] == '/' || param[1][len - 1] == '.') {
					printk("invalid path/length: %s,  ex: /tmp, /var\n", param[1]);
					break;
				}

				strcpy((char *)coredumppath, param[1]);
				printk("change coredump path to %s\n", coredumppath);
			} else if (strcmp(param[0], "MBssidSet") == 0) {
				u32 bitmap, groupid, i;
				u8 vapidx = 0;
				u32 temp = 0;
				u8 primary_bssid = bss_num;

				if (priv->master) {
					printk("Error. Please enter root interface instead\n");
					rc = -EOPNOTSUPP;
					break;
				}

				if ((groupid = atohex2(param[1])) >= MAX_MBSSID_SET) {
					printk("Error. Invalid MBSSID group ID:%u\n", groupid);
					rc = -EOPNOTSUPP;
					break;
				}

				if (*(mib->mib_mbssid) == 0) {
					printk("Error: Multiple BSSID not enabled\n");
					rc = -EOPNOTSUPP;
					break;
				}

				bitmap = atohex2(param[2]);

				//check bitmap conflict with other existing mbss set
				for (i = 0; i < MAX_MBSSID_SET; i++) {

					if (i == groupid)
						continue;

					if (bitmap & wlpd_p->mbssSet[i].mbssid_set) {
						printk("Error: bssid 0x%x has been existing in group(%u)\n", bitmap & wlpd_p->mbssSet[i].mbssid_set,
						       i);
						rc = -EOPNOTSUPP;
						goto errmbssid;
					}
				}

				temp = bitmap;
				printk("MBssidSet bitmap:%x\n", bitmap);

				while (temp) {
					if (temp & 0x1) {
						if (vapidx < primary_bssid)
							primary_bssid = vapidx;
					}
					temp >>= 1;
					vapidx++;
				}

				//put all mbss in the group into update list. HM should temporary stop monitoring bcn stuck till commit  
				wlpd_p->bss_inupdate |= wlpd_p->mbssSet[groupid].mbssid_set;
				wlpd_p->bss_inupdate |= bitmap;

				wlpd_p->mbssSet[groupid].mbssid_set = bitmap;
				wlpd_p->mbssSet[groupid].primbss = primary_bssid;
				printk("mbssid group:%u, primary mbssid:%u, mbssid set:%x\n", groupid, primary_bssid, bitmap);
				//printk("--%u, %u, %s\n", priv->wlpd_p->mbssSet.mbssid_set,priv->wlpd_p->mbssSet.primbss, priv->netDev->name);

				if (wlFwSetMBSSIDSet(vmacSta_p->dev, 1, groupid, primary_bssid, bitmap))
					printk("Config MBSSID set success!\n");
				else {
					printk("Error: Config MBSSID set fail!\n");
					rc = -EOPNOTSUPP;
				}
 errmbssid:
				break;
			} else if (strcmp(param[0], "MBssidEnable") == 0) {
				*(mib->mib_mbssid) = atoi(param[1]);
				break;
			} else if (strcmp(param[0], "superBA") == 0) {
				if (input_cnt > 1) {
					u32 mode = atohex2(param[1]);
					/*
					   SuperBA param:
					   0: disable
					   1: Always using super BA
					   2: AddBa_Req: using 128
					   AddBa_Rsp: always 64
					   3: AddBa_Req: always 64
					   AddBa_Rsp: depends
					 */
					if (mode < 4) {
						*(mib->mib_superBA) = mode;
						printk("SuperBA: param: %u\n", *(mib->mib_superBA));
					} else {
						rc = -EOPNOTSUPP;
					}
				}
				break;
			}
#endif
			/*Delete MU set by a given index
			 * "DelMUSet <mu_set _index>"
			 */
			else if (strcmp(param[0], "DelMUSet") == 0) {
				UINT8 index = 0;

				if (!priv->master) {
					printk("Error. Please enter vap interface instead\n");
					rc = -EOPNOTSUPP;
					break;
				}

				index = atoi(param[1]);
				MUDel_MUSetIndex(vmacSta_p, index);
			}
#ifdef MRVL_MUG_ENABLE
			else if ((strcmp(param[0], "mug_enable") == 0)) {
				u32 enable = atoi(param[1]);

				if (priv->master) {
					printk("Error. Please enter non-vap interface instead\n");
					rc = -EOPNOTSUPP;
					break;
				}

				mug_enable(netdev, enable);
				break;
			} else if ((strcmp(param[0], "GetMUInfo") == 0) || (strcmp(param[0], "GetMUGroups") == 0)) {
				extern int wlFwGetMUInfo(struct net_device *netdev, int groups_only);

				int groups_only = (strcmp(param[0], "GetMUGroups") == 0);

				if (wlFwGetMUInfo(netdev, groups_only) != 0) {
					printk("wlFwGetMUInfo FAILED!\n");
					break;
				} else {
					printk("wlFwGetMUInfo OK\n");
				}

				break;
			} else if (strcmp(param[0], "SetMUConfig") == 0) {
				u32 corr_thr_decimal = atoi(param[1]);
				u16 sta_cep_age_thr = atoi(param[2]);
				u16 period_ms = atoi(param[3]);

				if (priv->master) {
					printk("Error. Please enter non-vap interface instead\n");
					rc = -EOPNOTSUPP;
					break;
				}

				if (corr_thr_decimal == 0 || sta_cep_age_thr == 0) {
					printk("wlFwSetMUConfig() FAILED\n");
				} else {
					if (wlFwSetMUConfig(netdev, corr_thr_decimal, sta_cep_age_thr, period_ms) == 0) {
						printk("Set MU config OK!\n");
					}
				}
			}
#endif
			/*To adjust MU auto grouping frequency */
			else if (strcmp(param[0], "MUAutoTimer") == 0) {
				extern UINT32 AUTO_MU_TIME_CONSTANT;
				if (strcmp(param[1], "set") == 0) {
					int val = atoi(param[2]);
					AUTO_MU_TIME_CONSTANT = val;
					printk("MU auto grouping %u*10msec\n", (unsigned int)AUTO_MU_TIME_CONSTANT);
				} else
					printk("MU auto grouping %u*10msec\n", (unsigned int)AUTO_MU_TIME_CONSTANT);

				break;
			}
			/*To set preference of 2 or 3 users in MU set */
			else if (strcmp(param[0], "MUPreferUsrCnt") == 0) {
				u32 mu_max_user;

				if (!priv->master) {
					printk("Error. Please enter vap interface instead\n");
					rc = -EOPNOTSUPP;
					break;
				}

				switch (priv->devid) {
				case SC4:
					mu_max_user = 3;
					break;
				case SC5:
					mu_max_user = 8;
					break;
				case SCBT:
					mu_max_user = 4;
					break;
				default:
					mu_max_user = 3;
				}

				if (param[1]) {
					UINT8 val = atoi(param[1]);
					if (val > 1 && val <= mu_max_user)
						vmacSta_p->MUSet_Prefer_UsrCnt = val;
					else
						vmacSta_p->MUSet_Prefer_UsrCnt = mu_max_user;

					printk("MU set user cnt preference: %d\n", vmacSta_p->MUSet_Prefer_UsrCnt);
				}

				break;
			} else if (strcmp(param[0], "getMUPreferUsrCnt") == 0) {
				if (!priv->master) {
					printk("Error. Please enter vap interface instead\n");
					rc = -EOPNOTSUPP;
					break;
				}
				printk("MU set user cnt preference: %d\n", vmacSta_p->MUSet_Prefer_UsrCnt);
			}
			/* AIRTIME_FAIRNESS */
			else if (strcmp(param[0], "atf") == 0) {
				if (strcmp(param[1], "enable") == 0) {
					atf_enable(netdev, mib, param[2]);
				} else if (strcmp(param[1], "set") == 0) {
					atf_config_set(netdev, mib, param[2], param[3], param[4], param[5], param[6], param[7], param[8]);
				} else if (strcmp(param[1], "reset") == 0) {
					atf_config_reset(netdev, mib);
				} else if (strcmp(param[1], "get") == 0) {
					atf_get_fw_cfg_dump_cur(netdev);
				} else if (strcmp(param[1], "debug") == 0) {
					atf_dump_all_info(netdev, mib);
				} else {
					atf_print_usage();
				}
			}
			/* end of AIRTIME_FAIRNESS */
			else if (strcmp(param[0], "gid") == 0) {
				char macaddr2[6];
				int i, j;
				extern void SendGroupIDMgmtframe(vmacApInfo_t * vmacSta_p, IEEEtypes_MacAddr_t StaAddr, UINT8 gid,
								 UINT8 userposition);

				printk("in groupidmgmtframe\n");

				for (i = 0; i < 64; i++) {	//why need SU 0 and 63 ????
#ifdef SOC_W906X
					for (j = 0; j < 4; j++) {
#else
					for (j = 0; j < 3; j++) {
#endif
						SendGroupIDMgmtframe(vmacSta_p, macaddr2, i, j);
					}
					printk("\n");
				}
				printk("\n");
			} else if (strcmp(param[0], "NoAck") == 0) {
				extern int wlFwSetNoAck(struct net_device *netdev, UINT8 Enable, UINT8 be_enable,
							UINT8 bk_enable, UINT8 vi_enable, UINT8 vo_enable);
				UINT8 Enable;

				if (input_cnt == 2) {	/*only 1 setting for all ACs */
					Enable = atohex2(param[1]);
					printk("Set NoACK= %x\n", Enable);
					wlFwSetNoAck(netdev, Enable, 0, 0, 0, 0);
				} else if (input_cnt == 5) {
					wlFwSetNoAck(netdev, 0, atohex2(param[1]), atohex2(param[2]), atohex2(param[3]), atohex2(param[4]));
				} else {
					WLDBG_ERROR(DBG_LEVEL_1, "Invalid command arguments. \n");
					printk("Command examples:\n");
					printk("Enable NOACK for all ACs: NoAck 1");
					printk("Disable NOACK for all ACs: NoAck 0");
					printk("Enable NOACK for BE only: NoAck 1 0 0 0");
					printk("Enable NOACK for BK and VI: NoAck 0 1 1 0");
					rc = -EOPNOTSUPP;

				}
			} else if (strcmp(param[0], "NoSteer") == 0) {
				extern int wlFwSetNoSteer(struct net_device *netdev, UINT8 Enable);
				UINT8 Enable;
				Enable = atohex2(param[1]);
				printk("Set NoSteer = %x\n", Enable);
				wlFwSetNoSteer(netdev, Enable);
			} else if (strcmp(param[0], "SetCDD") == 0) {
				extern int wlFwSetCDD(struct net_device *netdev, UINT32 cdd_mode);
				UINT32 cdd_mode;
				cdd_mode = atohex2(param[1]);
				printk("Set CDD= %x\n", (unsigned int)cdd_mode);
				wlFwSetCDD(netdev, cdd_mode);

			} else if ((strcmp(param[0], "get_bftype") == 0)) {
				printk("bftype is %d\n", (int)*(mib->mib_bftype));
				break;
			} else if ((strcmp(param[0], "set_bftype") == 0)) {
				int val = atoi(param[1]);
				*(mib->mib_bftype) = val;
				printk("bftype is %d\n", (int)*(mib->mib_bftype));
				break;
			} else if ((strcmp(param[0], "get_bwSignaltype") == 0)) {
				printk("bw_Signaltype is %d\n", (int)*(mib->mib_bwSignaltype));
				break;
			} else if ((strcmp(param[0], "set_bwSignaltype") == 0)) {

				UINT8 i, type = 0, bitmap = 0;

				if (strcmp(param[1], "type") == 0)
					type = atoi(param[2]);

				if (strcmp(param[3], "val") == 0) {
					if (type == 3)
						bitmap = atohex2(param[4]);
				}

				/*Static BW signalling */
				if (type == 1) {
					*(mib->mib_bwSignaltype) = type;
					printk("BW signalling: static\n");
				}
				/*Dynamic BW signalling */
				else if (type == 2) {
					*(mib->mib_bwSignaltype) = type;
					printk("BW signalling: dynamic\n");
				}
				/*Force CTS CCA busy in certain bw. This is for test purposes */
				else if (type == 3) {
					printk("BW signalling: CTS in");

					for (i = 0; i < 3; i++) {
						if ((bitmap >> i) & 0x1) {
							if (i == 0)	//20Mhz
								printk(" 20MHz");
							else if (i == 1)	//40Mhz
								printk(" 40MHz");
							else if (i == 2)	//80Mhz
								printk(" 80MHz");
						}
					}
					printk("\n");
				} else {
					*(mib->mib_bwSignaltype) = 0;
					printk("BW signalling not set\n");
					printk("set_bwSignaltype type [1:static, 2:dynamic]\n");
					printk("To set dynamic CTS bw, set_bwSignaltype type 3 val [0x1:20M, 0x2:40M, 0x4:80M]\n");
				}

				wlFwSetBWSignalType(netdev, type, bitmap);

				break;
			}
#endif
			else if ((strcmp(param[0], "get_weakiv_threshold") == 0)) {
				printk("weakiv_threshold is %d\n", (int)*(mib->mib_weakiv_threshold));
				break;
			} else if ((strcmp(param[0], "set_weakiv_threshold") == 0)) {
				int val = atoi(param[1]);
				*(mib->mib_weakiv_threshold) = val;
				printk("weakiv_threshold is %d\n", (int)*(mib->mib_weakiv_threshold));
				break;
			}
#ifdef POWERSAVE_OFFLOAD
			else if (strcmp(param[0], "SetTim") == 0) {
				UINT16 Aid;
				UINT32 Set;

				Aid = atohex2(param[1]);
				Set = atohex2(param[2]);

				printk("SetTim\n");

				wlFwSetTIM(netdev, Aid, Set);

			} else if (strcmp(param[0], "SetPowerSaveStation") == 0) {
				UINT8 NoOfStations;

				printk("SetPowerSaveStation\n");

				NoOfStations = atohex2(param[1]);

				wlFwSetPowerSaveStation(netdev, NoOfStations);

			} else if (strcmp(param[0], "GetTim") == 0) {
				printk(" Get TIM:\n");
				wlFwGetTIM(netdev);
			}
#endif
			else if (strcmp(param[0], "getbcn") == 0) {
#define LINECHAR        16
				UINT16 len = 0;
				UINT8 *pBcn, *p;
				UINT8 i;
				UINT16 lineLen;

				pBcn = wl_kmalloc(MAX_BEACON_SIZE, GFP_KERNEL);
				if (pBcn == NULL) {
					rc = -EFAULT;
					break;
				}

				if (wlFwGetBeacon(netdev, pBcn, &len) == FAIL) {
					rc = -EFAULT;
					wl_kfree(pBcn);
					break;
				}

				sprintf(bufBack, "Beacon: len %d\n", len);
				p = bufBack + strlen(bufBack);
				lineLen = (len / LINECHAR == 0 ? len / LINECHAR : 1 + len / LINECHAR);
				for (i = 0; i < lineLen; i++) {
					sprintf(p, "%04d: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
						i * LINECHAR, pBcn[i * LINECHAR + 0], pBcn[i * LINECHAR + 1], pBcn[i * LINECHAR + 2],
						pBcn[i * LINECHAR + 3], pBcn[i * LINECHAR + 4], pBcn[i * LINECHAR + 5], pBcn[i * LINECHAR + 6],
						pBcn[i * LINECHAR + 7], pBcn[i * LINECHAR + 8], pBcn[i * LINECHAR + 9], pBcn[i * LINECHAR + 10],
						pBcn[i * LINECHAR + 11], pBcn[i * LINECHAR + 12], pBcn[i * LINECHAR + 13], pBcn[i * LINECHAR + 14],
						pBcn[i * LINECHAR + 15]);
					p = bufBack + strlen(bufBack);
				}

				*ret_len = strlen(bufBack);
				printk("%s", bufBack);
				wl_kfree(pBcn);
				break;
			} else if ((strcmp(param[0], "annex") == 0) || (strcmp(param[0], "readeepromhdr") == 0)) {
				UINT16 len;
				int i;
				int annex;
				int index;

				annex = atohex2(param[1]);
				index = atohex2(param[2]);

				if (strcmp(param[0], "readeepromhdr") == 0)
					annex = 255;

				if (wlFwGetCalTable(netdev, (UINT8) annex, (UINT8) index) == FAIL) {
					rc = -EFAULT;
					break;
				}

				if ((priv->calTbl[0] == annex) || (annex == 0) || (annex == 255)) {
					char tmpStr[16];
					len = priv->calTbl[2] | (priv->calTbl[3] << 8);
					if (annex == 255) {
						len = 128;
						sprintf(bufBack, "EEPROM header(128 bytes) \n");
					} else
						sprintf(bufBack, "Annex %d\n", annex);
					for (i = 0; i < len / 4; i++) {
						memset(tmpStr, 0, 16);
						sprintf(tmpStr, "%02x %02x %02x %02x\n", priv->calTbl[i * 4],
							priv->calTbl[i * 4 + 1], priv->calTbl[i * 4 + 2], priv->calTbl[i * 4 + 3]);
						strcat(bufBack, tmpStr);
					}
				} else
					sprintf(bufBack, "No Annex %d\n", annex);

				*ret_len = strlen(bufBack);
				printk("%s", bufBack);
				break;
			} else if ((strcmp(param[0], "or") == 0)) {
				UINT32 reg, val;
				UINT8 set = WL_GET;
				int i;

				for (i = 0; i < 4; i++) {
					/* for RF */
					printk("\nRF BASE %c registers \n", 'A' + i);
					for (reg = 0xA00 + (0x100 * i); reg <= 0xAFF + (0x100 * i); reg++) {
						wlRegRF(netdev, set, reg, &val);
						printk("0x%02X	0x%02X\n", (int)(reg - (0xA00 + (0x100 * i))), (int)val);
					}
				}
				for (i = 0; i < 4; i++) {
					printk("\nRF XCVR path %c registers \n", 'A' + i);
					for (reg = 0x100 + (0x100 * i); reg <= 0x1FF + (0x100 * i); reg++) {
						wlRegRF(netdev, set, reg, &val);
						printk("0x%03X	0x%02X\n", (int)(reg), (int)val);
					}
				}

				/* for BBP */
				printk("\nBBU Registers \n");
				for (reg = 0x00; reg <= 0x6DB; reg++) {
					wlRegBB(netdev, set, reg, &val);
					if (reg < 0x100)
						printk("0x%02X	0x%02X\n", (int)reg, (int)val);
					else
						printk("0x%03X	0x%02X\n", (int)reg, (int)val);
				}

			} else if ((strcmp(param[0], "getaddrtable") == 0)) {
				wlFwGetAddrtable(netdev);
			} else if ((strcmp(param[0], "getfwencrinfo") == 0)) {
				char macaddr[6];
				getMacFromString(macaddr, param[1]);
				wlFwGetEncrInfo(netdev, macaddr);
			} else if ((strcmp(param[0], "setreg") == 0)) {
				UINT32 reg, val;
				UINT8 set = WL_GET;
				reg = atohex2(param[2]);
				if (param[3][0]) {
					val = atohex2(param[3]);
					set = WL_SET;
				}

				if (strcmp(param[1], "mac") == 0) {
#ifdef SOC_W8964
					if (set == WL_SET) {
						PciWriteMacReg(netdev, reg, val);
					} else
						val = PciReadMacReg(netdev, reg);
					printk("%s mac reg %x = %x\n", set ? "Set" : "Get", (int)reg, (int)val);
#endif
					break;
				} else if (strcmp(param[1], "rf") == 0) {
					wlRegRF(netdev, set, reg, &val);
					printk("%s rf reg %x = %x\n", set ? "Set" : "Get", (int)reg, (int)val);
					break;
				} else if (strcmp(param[1], "bb") == 0) {
					wlRegBB(netdev, set, reg, &val);
					printk("%s bb reg %x = %x\n", set ? "Set" : "Get", (int)reg, (int)val);
					break;
				} else if (strcmp(param[1], "cau") == 0) {
					wlRegCAU(netdev, set, reg, &val);
					printk("%s cau reg %x = %x\n", set ? "Set" : "Get", (int)reg, (int)val);
					break;
				} else if (strcmp(param[1], "addr0") == 0) {
					if (set == WL_SET)
						*(volatile unsigned int *)(priv->ioBase0 + reg) = le32_to_cpu(val);
					else
						val = cpu_to_le32(*(volatile unsigned int *)(priv->ioBase0 + reg));
					printk("%s addr %x = %x\n", set ? "Set" : "Get", (int)reg + 0xc0000000, (int)val);
					break;
				} else if (strcmp(param[1], "addr1") == 0) {
					if (set == WL_SET)
						*(volatile unsigned int *)(priv->ioBase1 + reg) = le32_to_cpu(val);
					else
						val = cpu_to_le32(*(volatile unsigned int *)(priv->ioBase1 + reg));
					printk("%s addr %x = %x\n", set ? "Set" : "Get", (int)reg + 0x80000000, (int)val);
					break;
				} else if (strcmp(param[1], "addr") == 0) {
					UINT32 *addr_val = wl_kmalloc(64 * sizeof(UINT32), GFP_KERNEL);
					if (addr_val == NULL) {
						rc = -EFAULT;
						break;
					}
					memset(addr_val, 0, 64 * sizeof(UINT32));
					addr_val[0] = val;
					if (set == WL_SET) {
#ifdef SOC_W906X
						wlFwGetAddrValue(netdev, reg, 1, addr_val, 1);
#else
						wlFwGetAddrValue(netdev, reg, 4, addr_val, 1);
#endif
					} else
#ifdef SOC_W906X
						wlFwGetAddrValue(netdev, reg, 1, addr_val, 0);
#else
						wlFwGetAddrValue(netdev, reg, 4, addr_val, 0);
#endif
					printk("%s addr %x = %x\n", set ? "Set" : "Get", (int)reg, (int)addr_val[0]);
					wl_kfree(addr_val);
					break;
				} else {
					rc = -EFAULT;
					break;
				}
#ifdef SOC_W906X
			} else if ((strcmp(param[0], "hmdebug") == 0)) {

				UINT32 reg, val = 0;
				UINT8 set = 0xff;
				reg = atohex2(param[2]);
				if (param[3][0]) {
					val = atohex2(param[3]);
				}

				if (strcmp(param[1], "echo") == 0) {
					//fw use host_print to send back the address drv provided in cmd
					UINT32 *addr_val = wl_kmalloc(64 * sizeof(UINT32), GFP_KERNEL);

					//printk("hmdebug\n");
					if (addr_val == NULL) {
						rc = -EFAULT;
						break;
					}

					set = 0xff;
					memset(addr_val, 0, 64 * sizeof(UINT32));
					addr_val[0] = val;

					wlFwGetAddrValue(netdev, reg, 1, addr_val, set);

					wl_kfree(addr_val);
					break;
				} else if (strcmp(param[1], "fw") == 0) {
					//let fw create the failure cases for HM detecting
					UINT32 *addr_val = wl_kmalloc(64 * sizeof(UINT32), GFP_KERNEL);

					if (addr_val == NULL) {
						rc = -EFAULT;
						break;
					}

					set = 0xfe;
					memset(addr_val, 0, 64 * sizeof(UINT32));
					addr_val[0] = val;
					if (reg == 1)
						printk("config mac cpu stuck case\n");
					else if (reg == 2)
						printk("config beacon stuck case\n");
					else if (reg == 3)
						printk("config tx stuck case\n");
					else if (reg == 4)
						printk("config rx stuck case\n");
					else if (reg == 5)
						printk("config pfw scheduler long delay case\n");
					else if (reg == 6)
						printk("config pfw alive counters stuck case\n");
					else if (reg == 7)
						printk("config vap beacon stuck case\n");
					else if (reg == 8)
						printk("config smac exception case\n");
					else
						printk("other params\n");

					wlFwGetAddrValue(netdev, reg, 1, addr_val, set);

					wl_kfree(addr_val);
					break;
				} else if (strcmp(param[1], "drv") == 0) {
					extern UINT32 hm_max_bmq_diff;
					//let drv create the failure cases for HM detecting
					if (reg == 1) {
						printk("config bmq buffer resource alarm threshold to %u and refill status alarm case\n", val);
						hm_max_bmq_diff = val;
					} else
						printk("wrong param\n");
				} else {
					rc = -EFAULT;
					break;
				}
#endif
#ifdef SOC_W906X
			} else if ((strcmp(param[0], "offchan") == 0)) {
				struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
				u32 ch = (u32) atoi(param[1]);
				u32 bw = (u32) atoi(param[2]);
				u32 dwell = (u32) atoi(param[3]);
				int ret;
				u16 result;

				if (wlpptr->master) {
					printk("offchan only apply to physical interface...\n");
					break;
				}

				if ((ch == 0) || (dwell == 0)) {
					printk("offchan <ch> <bw> <dwell>\n");
					printk("This command supports RX mode only.\n");
					printk("ch is in decimal. Ex. channel #36 = 36\n");
					printk("bw is in HAL_CHANWIDTH_* format. 0=20M, 1=40M, 4=80M, 5=160M\n");
					printk("dwell is in decimal, mSec. 50ms = 50\n");
					rc = -EFAULT;
					break;
				}

				ret = wlFwOffChannel(netdev, ch, bw, dwell, OFF_CHAN_REQ_TYPE_RX, NULL, &result);
				if (ret == SUCCESS) {
					switch (result) {
					case HostCmd_RESULT_OFFCHAN_BCN_GUARD:
						{
							//printk("HostCmd_RESULT_OFFCHAN_BCN_GUARD\n");
							ret = wlFwOffChannel(netdev, ch, bw, dwell, OFF_CHAN_REQ_TYPE_RX, NULL, &result);
							if ((ret != SUCCESS) || (result != HostCmd_RESULT_OK)) {
								printk("Offchan failed again, %d / %d\n", ret, result);
							}
							break;
						}
					case HostCmd_RESULT_OFFCHAN_IN_PROCESS:
						{
							printk("HostCmd_RESULT_OFFCHAN_IN_PROCESS, this request is canceled\n");
							break;
						}
					default:
						{
							break;
						}
					}
				}

				break;
			} else if ((strcmp(param[0], "offchan_dbg") == 0)) {
				struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
				u32 fw_offchan_state = 0xFFFFFFFF;
				int ret = 0;

				ret = wlFwOffChannel_dbg(netdev, &fw_offchan_state);

				printk("offChanList.cnt = %d, offchan_state = %d, fw_offchan_state = %d\n", wlpptr->wlpd_p->offChanList.cnt,
				       wlpptr->offchan_state, fw_offchan_state);
				printk("txStop = 0x%08x, bcnStop = 0x%08x, opMode = 0x%08x\n", ((SMAC_CTRL_BLK_st *) wlpptr->ioBase0)->config.txStop,
				       ((SMAC_CTRL_BLK_st *) wlpptr->ioBase0)->config.bcnStop, ((SMAC_CTRL_BLK_st *) wlpptr->ioBase0)->config.opMode);
				break;
#endif				//906X off-channel
			} else if ((strcmp(param[0], "debug") == 0)) {
				DebugCmdParse(netdev, param_str + 6);
				break;
			} else if ((strcmp(param[0], "memdump") == 0)) {
				unsigned int i, val, offset, length, j = 0;
				unsigned char *buf = NULL;

				if (strcmp(param[1], "mm") == 0) {
					int k;
					offset = atohex2(param[2]) & 0xfffffffc;
					/*if (offset>0xafff || offset < 0xa000)
					   {
					   rc = -EFAULT;
					   break; 
					   } */

					length = atohex2(param[3]) * 4;
					if (!length)
						length = 32;
					buf = wl_kmalloc(length * 10 + 100, GFP_KERNEL);
					if (buf == NULL) {
						rc = -EFAULT;
						break;
					}

					sprintf(buf + j, "dump mem\n");
					j = strlen(buf);
					for (k = 0; k < length; k += 256) {
						for (i = 0; i < 256; i += 4) {
							volatile unsigned int val = 0;

							val = le32_to_cpu(*(volatile unsigned int *)(priv->ioBase1 + offset + i));

							//val = PciReadMacReg(netdev, offset+i);
							if (i % 16 == 0) {
								sprintf(buf + j, "\n0x%08x", (int)(0x80000000 + offset + i + k));
								j = strlen(buf);
							}
							sprintf(buf + j, "  %08x", val);
							j = strlen(buf);
						}
						printk("%s\n", buf);
						j = 0;
					}
					if (buf != NULL)
						wl_kfree(buf);
				} else if (strcmp(param[1], "ms") == 0) {
#ifdef SOC_W906X
					int k;
					unsigned char *valbuf = NULL;

					offset = atohex2(param[2]) & 0xfffffffc;

					length = atohex2(param[3]) * 4;

					if (!length)
						length = 256;
					if ((length % 256) != 0) {
						length = ((length / 256) + 1) * 256;
					}

					valbuf = wl_kmalloc(sizeof(unsigned char) * length, GFP_KERNEL);

					if (valbuf == NULL) {
						rc = -EFAULT;
						break;
					}

					printk("dump mem\n");
					if ((!IS_BUS_TYPE_MCI(priv)) && (offset + length) > 0x100000) {	//over iobase0 remap boundary. PCIE BAR0 1M.

						u32 *addr = (u32 *) valbuf;
						u32 seg;

						printk("memory over pcie iobase0(BAR0) boundary , read through cmd path.\n");

						for (seg = 0; seg < (length / 256); seg++) {

							memset((void *)valbuf, 0, (sizeof(unsigned char) * length));

							if (wlFwGetAddrValue
							    (netdev, (SMAC_DMEM_START + offset + seg * 256), (256 / 4), (u32 *) valbuf, 0)) {
								printk("Could not get the memory address value\n");
								rc = -EFAULT;
								goto ms_exit;
							}

							for (i = 0, k = 0; i < 256; i += 4) {

								if ((i % 16) == 0) {
									printk("\n0x%08x", (u32) (SMAC_DMEM_START + offset + seg * 256 + i));
								}
								printk("  %08x", addr[k++]);
							}
						}

					} else {

						for (k = 0; k < length; k += 256) {
							for (i = 0; i < 256; i += 4) {
								volatile unsigned int val = 0;

								*(unsigned int *)(&valbuf[k * 256 + i]) = val =
								    le32_to_cpu(*(volatile unsigned int *)(priv->ioBase0 + offset + i + k));
							}
						}
						for (k = 0; k < length; k += 256) {
							for (i = 0; i < 256; i += 4) {
								volatile unsigned int val = 0;

								val = *(unsigned int *)(&valbuf[k * 256 + i]);

								if (i % 16 == 0) {
									printk("\n0x%08x", (int)(0x20000000 + offset + i + k));
								}
								printk("  %08x", val);
							}
						}
					}

					printk("\n");
 ms_exit:
					if (valbuf != NULL)
						wl_kfree(valbuf);
#else
					int k;
					offset = atohex2(param[2]) & 0xfffffffc;

					length = atohex2(param[3]) * 4;
					if (!length)
						length = 32;
					buf = wl_kmalloc(length * 10 + 100, GFP_KERNEL);
					if (buf == NULL) {
						rc = -EFAULT;
						break;
					}

					sprintf(buf + j, "dump mem\n");
					j = strlen(buf);
					for (k = 0; k < length; k += 256) {
						for (i = 0; i < 256; i += 4) {
							volatile unsigned int val = 0;

							val = le32_to_cpu(*(volatile unsigned int *)(priv->ioBase0 + offset + i + k));

							if (i % 16 == 0) {
								sprintf(buf + j, "\n0x%08x", (int)(0xC0000000 + offset + i + k));
								j = strlen(buf);
							}
							sprintf(buf + j, "  %08x", val);
							j = strlen(buf);
						}
						printk("%s\n", buf);
						j = 0;
					}
					if (buf != NULL)
						wl_kfree(buf);
#endif
				} else if (strcmp(param[1], "rf") == 0) {
					offset = atohex2(param[2]);
					length = atohex2(param[3]);
					if (!length)
						length = 32;
					buf = wl_kmalloc(length * 10 + 100, GFP_KERNEL);
					if (buf == NULL) {
						rc = -EFAULT;
						break;
					}

					sprintf(buf + j, "dump rf regs\n");
					j = strlen(buf);
					for (i = 0; i < length; i++) {
						wlRegRF(netdev, WL_GET, offset + i, &val);
						if (i % 8 == 0) {
							sprintf(buf + j, "\n%02x: ", (int)(offset + i));
							j = strlen(buf);
						}
						sprintf(buf + j, "  %02x", (int)val);
						j = strlen(buf);
					}
					printk("%s\n\n", buf);
					if (buf != NULL)
						wl_kfree(buf);
				} else if (strcmp(param[1], "bb") == 0) {
					offset = atohex2(param[2]);
					length = atohex2(param[3]);
					if (!length)
						length = 32;
					buf = wl_kmalloc(length * 10 + 100, GFP_KERNEL);
					if (buf == NULL) {
						rc = -EFAULT;
						break;
					}

					sprintf(buf + j, "dump bb regs\n");
					j = strlen(buf);
					for (i = 0; i < length; i++) {
						wlRegBB(netdev, WL_GET, offset + i, &val);
						if (i % 8 == 0) {
							sprintf(buf + j, "\n%02x: ", (int)(offset + i));
							j = strlen(buf);
						}
						sprintf(buf + j, "  %02x", (int)val);
						j = strlen(buf);
					}
					printk("%s\n\n", buf);
					if (buf != NULL)
						wl_kfree(buf);
#ifdef SOC_W8964
				} else if (strcmp(param[1], "addr1") == 0) {
					int k;
					offset = atohex2(param[2]) & 0xfffffffc;

					length = atohex2(param[3]) * 4;
					if (!length)
						length = 32;
					buf = wl_kmalloc(length * 10 + 100, GFP_KERNEL);
					if (buf == NULL) {
						rc = -EFAULT;
						break;
					}

					sprintf(buf + j, "dump mem\n");
					j = strlen(buf);
					for (k = 0; k < length; k += 256) {
						for (i = 0; i < 256; i += 4) {
							volatile unsigned int val = 0;

							val = le32_to_cpu(*(volatile unsigned int *)(offset + i + k));

							if (i % 16 == 0) {
								sprintf(buf + j, "\n0x%08x", (int)(offset + i + k));
								j = strlen(buf);
							}
							sprintf(buf + j, "  %08x", val);
							j = strlen(buf);
						}
						printk("%s\n", buf);
						j = 0;
					}
					if (buf != NULL)
						wl_kfree(buf);
#endif
				} else if (strcmp(param[1], "addr") == 0) {
					UINT32 addr;
					UINT32 *addr_val = wl_kmalloc(64 * sizeof(UINT32), GFP_KERNEL);
					if (addr_val == NULL) {
						rc = -EFAULT;
						break;
					}
					memset(addr_val, 0, 64 * sizeof(UINT32));
					addr = atohex2(param[2]) & 0xfffffffc;	// 4 byte boundary
					// length is unit of 4 bytes
					length = atohex2(param[3]);
					if (!length)
						length = 32;
					if (length > 64)
						length = 64;
					if (wlFwGetAddrValue(netdev, addr, length, addr_val, 0)) {
						printk("Could not get the memory address value\n");
						rc = -EFAULT;
						wl_kfree(addr_val);
						break;
					}
					buf = wl_kmalloc(length * 16 + 100, GFP_KERNEL);
					if (buf == NULL) {
						rc = -EFAULT;
						wl_kfree(addr_val);
						break;
					}
					j += sprintf(buf + j, "dump addr\n");
					for (i = 0; i < length; i++) {
						if (i % 2 == 0) {
							j += sprintf(buf + j, "\n%08x: ", (int)(addr + i * 4));
						}
						j += sprintf(buf + j, "  %08x", (int)addr_val[i]);
					}
					printk("%s\n\n", buf);
					if (buf != NULL)
						wl_kfree(buf);
					wl_kfree(addr_val);
				}
#ifdef SOC_W906X
				else if (strcmp(param[1], "db") == 0) {
					UINT32 addr;
					UINT32 *addr_val = wl_kmalloc(64 * sizeof(UINT32), GFP_KERNEL);
					UINT16 *val = (UINT16 *) addr_val, startIdx, index;
					UINT8 *ptr = NULL;

					if (addr_val == NULL) {
						rc = -EFAULT;
						break;
					}
					memset(addr_val, 0, 64 * sizeof(UINT32));
					length = 32;
					addr = atohex2(param[2]);	// 4 byte boundary

					buf = wl_kmalloc(length * 32 + 100, GFP_KERNEL);
					if (buf == NULL) {
						rc = -EFAULT;
						wl_kfree(addr_val);
						break;
					}
					printk("dump avl db\n");
					startIdx = 0;
					index = 1;
					while (index <= (SMAC_BSS_NUM + SMAC_STA_NUM)) {
						if (wlFwGetAddrValue(netdev, addr, startIdx, addr_val, 2)) {
							printk("Could not get the memory address value\n");
							rc = -EFAULT;
							wl_kfree(buf);
							wl_kfree(addr_val);
							break;
						}
						j = 0;
						for (i = 0; i < length * 4; i += 4) {
							val[i] = ENDIAN_SWAP16(val[i]);
							if ((val[i] > 0) && (val[i] < 0xffff)) {
								ptr = (UINT8 *) & val[i + 1];
								j += sprintf(buf + j, "%3d  %04i: ", index, val[i]);
								j += sprintf(buf + j, "%02x:%02x:%02x:%02x:%02x:%02x\n",
									     ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);
								startIdx = val[i];
								index++;
							} else {
								if (val[i] == 0xffff)
									startIdx = 0xffff;
								break;
							}
						}
						if (j > 0)
							printk("%s", buf);
						if (startIdx == 0xffff)
							break;
					}
					if (buf != NULL)
						wl_kfree(buf);
					wl_kfree(addr_val);
				}
#endif
				break;
			}
#ifdef MRVL_WPS_CLIENT
			else if ((strcmp(param[0], "bssid") == 0)) {
				char *tmpptr;
				tmpptr = param[1];
				ptr = strsep(&tmpptr, ":");

				if (ptr) {
					desireBSSID[count++] = atohex(ptr);
					while ((ptr = strsep(&tmpptr, ":")) != NULL) {
						desireBSSID[count++] = atohex(ptr);
					}
					memcpy(mib->StationConfig->DesiredBSSId, desireBSSID, IEEEtypes_ADDRESS_SIZE);
#ifdef DBG
					printk("BSSID IS :%02X:%02X:%02X:%02X:%02X:%02X\n",
					       desireBSSID[0], desireBSSID[1], desireBSSID[2], desireBSSID[3], desireBSSID[4], desireBSSID[5]);
#endif
				}
				break;
			}
#endif				//MRVL_WPS_CLIENT
#ifdef EWB
			else if (strcmp(param[0], "ewbtable") == 0) {
				int i, j;
				hash_entry *pEntry;

				for (i = 0; i < HASH_ENTRY_COLUMN_MAX; i++) {
					pEntry = &hashTable[i];
					for (j = 0; j < HASH_ENTRY_ROW_MAX; j++) {
						if (pEntry && pEntry->nwIpAddr) {
							printk("Index [%d,%d] \t IP=%x \t MAC=%02X:%02X:%02X:%02X:%02X:%02X\n",
							       i, j, (int)pEntry->nwIpAddr, pEntry->hwAddr[0], pEntry->hwAddr[1], pEntry->hwAddr[2],
							       pEntry->hwAddr[3], pEntry->hwAddr[4], pEntry->hwAddr[5]);

							pEntry = (hash_entry *) pEntry->nxtEntry;
						} else
							break;
					}
				}
			}
#endif				/* EWB */
			else if (strcmp(param[0], "getratetable") == 0) {
				UINT32 size;
				UINT8 *pRateTable = NULL;
				UINT8 type = 0;
#ifdef SOC_W906X
				UINT32 sta_id = 0;
				extStaDb_StaInfo_t *pStaInfo = NULL;
#endif

				if (param[1]) {
					size = RATEINFO_DWORD_SIZE * RATE_ADAPT_MAX_SUPPORTED_RATES;
					pRateTable = wl_kmalloc(size, GFP_KERNEL);

					if (pRateTable) {
						char macaddr[6];

#ifdef SOC_W906X
						if (strcmp(param[3], "current") == 0) {
							type = 2;
						} else if (strcmp(param[3], "mu") == 0)
							type = 1;
						else
							type = 0;

						memset(pRateTable, 0, size);
						if (!getMacFromString(macaddr, param[1])) {
							printk("need input STA MAC addr like 005043225678\n");
						}

						if ((pStaInfo =
						     extStaDb_GetStaInfo(vmacSta_p, (IEEEtypes_MacAddr_t *) macaddr,
									 STADB_DONT_UPDATE_AGINGTIME)) != NULL)
							sta_id = pStaInfo->StnId;
						else
							sta_id = atohex2(param[2]);
						wlFwGetRateTable(netdev, (UINT8 *) macaddr, (UINT8 *) pRateTable, size, type, sta_id);
#else
						if (strcmp(param[2], "mu") == 0)
							type = 1;
						else
							type = 0;

						memset(pRateTable, 0, size);
						getMacFromString(macaddr, param[1]);

						wlFwGetRateTable(netdev, (UINT8 *) macaddr, (UINT8 *) pRateTable, size, type);
#endif
						printk("%02x %02x %02x %02x %02x %02x: Client\n",
						       (int)macaddr[0],
						       (int)macaddr[1], (int)macaddr[2], (int)macaddr[3], (int)macaddr[4], (int)macaddr[5]
						    );

						ratetable_print_SOCW8864((UINT8 *) pRateTable);
						wl_kfree(pRateTable);
						pRateTable = NULL;
					}
				}

				*ret_len = strlen(bufBack);
			}
			/*Set custom rate in rate table.
			 * 1) Assoc client, it creates a rate table entry
			 * 2) Use "setratetable <client_mac_addr> clear" before adding custom rate. This clears existing rates in rate table
			 * 3) After clear, "setratetable <client_mac_addr> <32bit rateinfo>"
			 * CAUTION: Everytime client reassoc, you need to restart all over because auto rate table is created everytime client joins.
			 * NOTE: FW needs to compile with CUSTOM_RATETABLE flag
			 */
			else if (strcmp(param[0], "setratetable") == 0) {
				char macaddr[6];
				UINT32 rateinfo = 0;

				if (strcmp(param[2], "clear") == 0) {
					getMacFromString(macaddr, param[1]);
#ifdef SOC_W906X
					wlFwSetRateTable(netdev, 0, (UINT8 *) macaddr, atohex2(param[3]), rateinfo);
#else
					wlFwSetRateTable(netdev, 0, (UINT8 *) macaddr, rateinfo);
#endif
				} else if (param[2]) {
					getMacFromString(macaddr, param[1]);
					rateinfo = atohex2(param[2]);

					printk("%02x %02x %02x %02x %02x %02x: Client ,",
					       (int)macaddr[0], (int)macaddr[1], (int)macaddr[2], (int)macaddr[3], (int)macaddr[4], (int)macaddr[5]
					    );

					printk("rateinfo 0x%x\n", (unsigned int)rateinfo);
#ifdef SOC_W906X
					wlFwSetRateTable(netdev, 1, (UINT8 *) macaddr, atohex2(param[3]), rateinfo);
#else
					wlFwSetRateTable(netdev, 1, (UINT8 *) macaddr, rateinfo);
#endif
				}

			}
#ifdef DYNAMIC_BA_SUPPORT
			else if ((strcmp(param[0], "get_ampdu_bamgmt") == 0)) {
				printk("AMPDU Bandwidth mgmt status is %d\n", (int)*(mib->mib_ampdu_bamgmt));
				break;
			} else if ((strcmp(param[0], "set_ampdu_bamgmt") == 0)) {
				int val = atoi(param[1]);
				if (val != 0 && val != 1) {
					printk("incorrect status values \n");
					break;
				}
				*(mib->mib_ampdu_bamgmt) = val;
				printk("AMPDU Bandwidth mgmt status is %d\n", (int)*(mib->mib_ampdu_bamgmt));
				break;
			} else if ((strcmp(param[0], "get_ampdu_mintraffic") == 0)) {
				printk("AMPDU Min Traffic \n -------------------- \n");
				printk("AC_BK = %d \n", (int)*(mib->mib_ampdu_mintraffic[1]));
				printk("AC_BE = %d \n", (int)*(mib->mib_ampdu_mintraffic[0]));
				printk("AC_VI = %d \n", (int)*(mib->mib_ampdu_mintraffic[2]));
				printk("AC_VO = %d \n", (int)*(mib->mib_ampdu_mintraffic[3]));
				break;
			} else if ((strcmp(param[0], "set_ampdu_mintraffic") == 0)) {
				if (!atoi(param[1]) || !atoi(param[2]) || !atoi(param[3]) || !atoi(param[4]))
					printk("Some values are set to Zero !!!!! \n");

				*(mib->mib_ampdu_mintraffic[1]) = atoi(param[1]);
				*(mib->mib_ampdu_mintraffic[0]) = atoi(param[2]);
				*(mib->mib_ampdu_mintraffic[2]) = atoi(param[3]);
				*(mib->mib_ampdu_mintraffic[3]) = atoi(param[4]);
				printk("Now AMPDU Min Traffic \n -------------------- \n");
				printk("AC_BK = %d \n", (int)*(mib->mib_ampdu_mintraffic[1]));
				printk("AC_BE = %d \n", (int)*(mib->mib_ampdu_mintraffic[0]));
				printk("AC_VI = %d \n", (int)*(mib->mib_ampdu_mintraffic[2]));
				printk("AC_VO = %d \n", (int)*(mib->mib_ampdu_mintraffic[3]));
				break;
			} else if ((strcmp(param[0], "get_ampdu_low_ac_threshold") == 0)) {
				printk("AMPDU Low Threshold \n -------------------- \n");
				printk("AC_BK = %d \n", (int)*(mib->mib_ampdu_low_AC_thres[1]));
				printk("AC_BE = %d \n", (int)*(mib->mib_ampdu_low_AC_thres[0]));
				printk("AC_VI = %d \n", (int)*(mib->mib_ampdu_low_AC_thres[2]));
				printk("AC_VO = %d \n", (int)*(mib->mib_ampdu_low_AC_thres[3]));
				break;
			} else if ((strcmp(param[0], "set_ampdu_low_ac_threshold") == 0)) {
				if (!atoi(param[1]) || !atoi(param[2]) || !atoi(param[3]) || !atoi(param[4]))
					printk("Some values are set to Zero !!!!! \n");

				*(mib->mib_ampdu_low_AC_thres[1]) = atoi(param[1]);
				*(mib->mib_ampdu_low_AC_thres[0]) = atoi(param[2]);
				*(mib->mib_ampdu_low_AC_thres[2]) = atoi(param[3]);
				*(mib->mib_ampdu_low_AC_thres[3]) = atoi(param[4]);
				printk("Now AMPDU Low Threshold \n -------------------- \n");
				printk("AC_BK = %d \n", (int)*(mib->mib_ampdu_low_AC_thres[1]));
				printk("AC_BE = %d \n", (int)*(mib->mib_ampdu_low_AC_thres[0]));
				printk("AC_VI = %d \n", (int)*(mib->mib_ampdu_low_AC_thres[2]));
				printk("AC_VO = %d \n", (int)*(mib->mib_ampdu_low_AC_thres[3]));
				break;
			}
#endif				/* DYNAMIC_BA_SUPPORT */
#ifdef  BARBADOS_DFS_TEST
			else if (strcmp(param[0], "dfstest") == 0) {

				dfs_probability = atohex2(param[1]);
				if (dfs_probability) {
					dfs_test = 1;
					dfs_monitor = 1;
				}

				printk("dfstest : dfs_test_mode = %x \n", dfs_probability);
			} else if (strcmp(param[0], "dfs_test") == 0) {
				dfs_test = atohex2(param[1]);
				printk("dfs_test : dfs_test = %x \n", dfs_test);
			} else if (strcmp(param[0], "dfs_monitor") == 0) {
				dfs_monitor = atohex2(param[1]);
				printk("dfs_monitor : dfs_monitor = %x \n", dfs_monitor);
			} else if (strcmp(param[0], "dfs_sim") == 0) {
				dfs_sim_evt = atohex2(param[1]);
				printk("radar detect simulation, dfs_sim = %d\n", dfs_sim_evt);
				if (dfs_sim_evt) {
					SimulateRadarDetect(netdev);
				}
			} else if (strcmp(param[0], "dfs_clear_nol") == 0) {
				dfs_clear_nol = TRUE;
				TimerDisarm(&priv->wlpd_p->pdfsApMain->dfsApDesc.NOCTimer);
				DfsRemoveFromNOL(&priv->wlpd_p->pdfsApMain->dfsApDesc);
				dfs_clear_nol = FALSE;
			}
#else
			else if (strcmp(param[0], "dfstest") == 0) {
				extern UINT8 dfs_test_mode;

				dfs_test_mode = atohex2(param[1]);

				printk("dfstest : dfs_test_mode = %x \n", dfs_test_mode);
			}
#endif
			else if (strcmp(param[0], "dfschirp") == 0) {

				dfs_chirp_count_min = atohex2(param[1]);
				dfs_chirp_time_interval = atohex2(param[2]);
				dfs_pw_filter = atohex2(param[3]);
				dfs_min_num_radar = atohex2(param[4]);
				dfs_min_pri_count = atohex2(param[5]);

				printk
				    ("dfschirp : dfs_chirp_count_min = %d, dfs_chirp_time_interval = %d units of 10ms, dfs_pw_filter = %d dfs_min_num_radar = %d dfs_min_pri_count = %d \n",
				     dfs_chirp_count_min, dfs_chirp_time_interval, dfs_pw_filter, dfs_min_num_radar, dfs_min_pri_count);
			}
#ifdef MPRXY
			else if (strcmp(param[0], "ipmcgrp") == 0) {
				UINT32 McIPAddr;
				UINT8 UcMACAddr[6];
				UINT8 i, j;
				BOOLEAN IPMcEntryExists = FALSE;
				BOOLEAN UcMACEntryExists = FALSE;
				BOOLEAN IPMFilterEntryExists = FALSE;
				UINT32 tempIPAddr;

				if (!IPAsciiToNum((unsigned int *)&McIPAddr, (const char *)&param[2])) {
					rc = -EFAULT;
					break;
				}

				if (McIPAddr == 0 &&
				    ((strcmp(param[1], "add") == 0) || (strcmp(param[1], "del") == 0) ||
				     (strcmp(param[1], "delgrp") == 0) || (strcmp(param[1], "addipmfilter") == 0)
				     || (strcmp(param[1], "delipmfilter") == 0))) {
					rc = -EFAULT;
					break;
				}

				if (!getMacFromString(UcMACAddr, param[3]) && ((strcmp(param[1], "add") == 0) || (strcmp(param[1], "del") == 0))) {
					rc = -EFAULT;
					break;
				}

				if (strcmp(param[1], "add") == 0) {
					for (i = 0; i < MAX_IP_MCAST_GRPS; i++) {
						if (mib->mib_IPMcastGrpTbl[i]->mib_McastIPAddr == McIPAddr) {
							IPMcEntryExists = TRUE;

							if (mib->mib_IPMcastGrpTbl[i]->mib_MAddrCount < MAX_UCAST_MAC_IN_GRP) {
								/*check if unicast adddress entry already exists in table */
								for (j = 0; j < MAX_UCAST_MAC_IN_GRP; j++) {
									if (memcmp((char *)&mib->mib_IPMcastGrpTbl[i]->mib_UCastAddr[j],
										   (char *)&UcMACAddr, 6) == 0) {
										UcMACEntryExists = TRUE;
										break;
									}
								}

								if (UcMACEntryExists == FALSE) {
									/* Add the MAC address into the table */
									memcpy((char *)&mib->mib_IPMcastGrpTbl[i]->
									       mib_UCastAddr[mib->mib_IPMcastGrpTbl[i]->mib_MAddrCount],
									       (char *)&UcMACAddr, 6);
									mib->mib_IPMcastGrpTbl[i]->mib_MAddrCount++;
									break;
								}
							} else {
								rc = -EFAULT;
								break;
							}
						}
					}

					/* if IP multicast group entry does not exist */
					if (IPMcEntryExists == FALSE) {
						/*check if space available in table */
						if (*(mib->mib_IPMcastGrpCount) < MAX_IP_MCAST_GRPS) {
							mib->mib_IPMcastGrpTbl[*(mib->mib_IPMcastGrpCount)]->mib_McastIPAddr = McIPAddr;

							/* Add the MAC address into the table */
							i = *(mib->mib_IPMcastGrpCount);

							memcpy((char *)&mib->mib_IPMcastGrpTbl[i]->
							       mib_UCastAddr[mib->mib_IPMcastGrpTbl[i]->mib_MAddrCount], (char *)&UcMACAddr, 6);

							/* increment unicast mac address count */
							mib->mib_IPMcastGrpTbl[i]->mib_MAddrCount++;

							/*increment the IP multicast group slot by 1 */
							*(mib->mib_IPMcastGrpCount) = *(mib->mib_IPMcastGrpCount) + 1;
						} else {
							rc = -EFAULT;
							break;
						}
					}
				} else if (strcmp(param[1], "del") == 0) {
					/* check if IP Multicast group entry already exists */
					for (i = 0; i < MAX_IP_MCAST_GRPS; i++) {
						/*match IP multicast grp address with entry */
						if (mib->mib_IPMcastGrpTbl[i]->mib_McastIPAddr == McIPAddr) {
							/*find the unicast address entry in the IP multicast group */
							for (j = 0; j < MAX_UCAST_MAC_IN_GRP; j++) {
								if (memcmp((char *)&mib->mib_IPMcastGrpTbl[i]->mib_UCastAddr[j],
									   (char *)&UcMACAddr, 6) == 0) {
									/*decrement the count for unicast mac entries */
									mib->mib_IPMcastGrpTbl[i]->mib_MAddrCount--;

									/*if this is the very first entry, slot zero */
									if (mib->mib_IPMcastGrpTbl[i]->mib_MAddrCount == 0) {
										/* set the entry to zero */
										memset((char *)&mib->mib_IPMcastGrpTbl[i]->mib_UCastAddr[j], 0, 6);
										break;
									} else {
										/*if this is other than slot zero */
										/* set the entry to zero */
										memset((char *)&mib->mib_IPMcastGrpTbl[i]->mib_UCastAddr[j], 0, 6);
										/* move up entries to fill the vacant spot */
										memcpy((char *)&mib->mib_IPMcastGrpTbl[i]->mib_UCastAddr[j],
										       (char *)&mib->mib_IPMcastGrpTbl[i]->mib_UCastAddr[j + 1],
										       (mib->mib_IPMcastGrpTbl[i]->mib_MAddrCount - j) * 6);
										/* clear the last unicast entry since all entries moved up by 1 */
										memset((char *)&mib->mib_IPMcastGrpTbl[i]->
										       mib_UCastAddr[mib->mib_IPMcastGrpTbl[i]->mib_MAddrCount], 0,
										       6);
										break;
									}
								}
							}
						}
					}
				} else if (strcmp(param[1], "delgrp") == 0) {
					/* check if IP Multicast group entry already exists */
					for (i = 0; i < MAX_IP_MCAST_GRPS; i++) {
						/*match IP multicast grp address with entry */
						if (mib->mib_IPMcastGrpTbl[i]->mib_McastIPAddr == McIPAddr) {
							/*decrement the count of IP multicast groups */
							*(mib->mib_IPMcastGrpCount) = *(mib->mib_IPMcastGrpCount) - 1;

							/* if this is first entry i.e. slot zero */
							/* set the entire group entry to zero */
							/* set the entry to zero */
							if (i == 0) {
								memset((char *)mib->mib_IPMcastGrpTbl[i], 0, sizeof(MIB_IPMCAST_GRP_TBL));
								break;
							} else {
								/* if this is a slot other than zero */
								/* set the entry to zero */
								memset((char *)mib->mib_IPMcastGrpTbl[i], 0, sizeof(MIB_IPMCAST_GRP_TBL));

								/* move up entries to fill the vacant spot */
								memcpy((char *)&mib->mib_IPMcastGrpTbl[i],
								       (char *)&mib->mib_IPMcastGrpTbl[i + 1],
								       (*(mib->mib_IPMcastGrpCount) - i) * sizeof(MIB_IPMCAST_GRP_TBL));

								/* clear the last unicast entry since all entries moved up by 1 */
								memset((char *)mib->mib_IPMcastGrpTbl[*(mib->mib_IPMcastGrpCount)],
								       0, sizeof(MIB_IPMCAST_GRP_TBL));
							}
						}
					}
				} else if (strcmp(param[1], "getgrp") == 0) {
					/* check if IP Multicast group entry already exists */
					for (i = 0; i < MAX_IP_MCAST_GRPS; i++) {
						/*match IP multicast grp address with entry */
						if (mib->mib_IPMcastGrpTbl[i]->mib_McastIPAddr == McIPAddr) {
							tempIPAddr = htonl(mib->mib_IPMcastGrpTbl[i]->mib_McastIPAddr);

							for (j = 0; j < MAX_UCAST_MAC_IN_GRP; j++)
								printk("%u.%u.%u.%u %02x%02x%02x%02x%02x%02x\n",
								       NIPQUAD(tempIPAddr),
								       mib->mib_IPMcastGrpTbl[i]->mib_UCastAddr[j][0],
								       mib->mib_IPMcastGrpTbl[i]->mib_UCastAddr[j][1],
								       mib->mib_IPMcastGrpTbl[i]->mib_UCastAddr[j][2],
								       mib->mib_IPMcastGrpTbl[i]->mib_UCastAddr[j][3],
								       mib->mib_IPMcastGrpTbl[i]->mib_UCastAddr[j][4],
								       mib->mib_IPMcastGrpTbl[i]->mib_UCastAddr[j][5]);
						}
					}
				} else if (strcmp(param[1], "getallgrps") == 0) {
					/* check if IP Multicast group entry already exists */
					for (i = 0; i < MAX_IP_MCAST_GRPS; i++) {
						if (mib->mib_IPMcastGrpTbl[i]->mib_McastIPAddr) {
							tempIPAddr = htonl(mib->mib_IPMcastGrpTbl[i]->mib_McastIPAddr);

							printk("IP Multicast Group: %u.%u.%u.%u \t Cnt:%d\n", NIPQUAD(tempIPAddr),
							       mib->mib_IPMcastGrpTbl[i]->mib_MAddrCount);

							for (j = 0; j < MAX_UCAST_MAC_IN_GRP; j++) {
								printk("%u.%u.%u.%u %02x%02x%02x%02x%02x%02x\n",
								       NIPQUAD(tempIPAddr),
								       mib->mib_IPMcastGrpTbl[i]->mib_UCastAddr[j][0],
								       mib->mib_IPMcastGrpTbl[i]->mib_UCastAddr[j][1],
								       mib->mib_IPMcastGrpTbl[i]->mib_UCastAddr[j][2],
								       mib->mib_IPMcastGrpTbl[i]->mib_UCastAddr[j][3],
								       mib->mib_IPMcastGrpTbl[i]->mib_UCastAddr[j][4],
								       mib->mib_IPMcastGrpTbl[i]->mib_UCastAddr[j][5]);
							}
						}
					}
				} else if (strcmp(param[1], "addipmfilter") == 0) {
					/* check if IP Multicast address entry already exists */
					for (i = 0; i < MAX_IP_MCAST_GRPS; i++) {
						/*match IP multicast address with entry */
						if (*(mib->mib_IPMFilteredAddress[i]) == McIPAddr) {
							IPMFilterEntryExists = TRUE;
							break;
						}
					}

					if (!IPMFilterEntryExists) {
						/*create a entry */
						/*check if space available in table */
						if (*(mib->mib_IPMFilteredAddressIndex) < MAX_IP_MCAST_GRPS) {
							*(mib->mib_IPMFilteredAddress[*(mib->mib_IPMFilteredAddressIndex)]) = McIPAddr;

							/*increment the IP multicast filter address index by 1 */
							*(mib->mib_IPMFilteredAddressIndex) = *(mib->mib_IPMFilteredAddressIndex) + 1;
						} else {
							rc = -EFAULT;
							break;
						}
					}
				} else if (strcmp(param[1], "delipmfilter") == 0) {
					/* check if IP Multicast Filter entry already exists */
					for (i = 0; i < MAX_IP_MCAST_GRPS; i++) {
						/*match IP multicast grp address with entry */
						if (*(mib->mib_IPMFilteredAddress[i]) == McIPAddr) {
							/* set the entry to zero */
							*(mib->mib_IPMFilteredAddress[i]) = 0;

							/*decrement the count of IP multicast groups */
							*(mib->mib_IPMFilteredAddressIndex) = *(mib->mib_IPMFilteredAddressIndex) - 1;

							/* move up entries to fill the vacant spot */
							for (j = 0; j < (*(mib->mib_IPMFilteredAddressIndex) - i); j++)
								*(mib->mib_IPMFilteredAddress[i + j]) = *(mib->mib_IPMFilteredAddress[i + j + 1]);

							/* clear the last entry since all entries moved up by 1 */
							*(mib->mib_IPMFilteredAddress[*(mib->mib_IPMFilteredAddressIndex)]) = 0;

							break;
						}
					}
				} else if (strcmp(param[1], "getipmfilter") == 0) {
					for (i = 0; i < MAX_IP_MCAST_GRPS; i++) {
						tempIPAddr = htonl(*(mib->mib_IPMFilteredAddress[i]));

						printk("%u.%u.%u.%u \n", NIPQUAD(tempIPAddr));
					}
				} else {
					rc = -EFAULT;
					break;
				}
			}
#endif			 /*MPRXY*/
			    else if ((strcmp(param[0], "rptrmode") == 0)) {
				struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
				vmacApInfo_t *vmacSta_p;
				struct wlprivate *wlMPrvPtr = wlpptr;
				UINT8 *p = bufBack;
				char macaddr[6];
				extStaDb_StaInfo_t *pStaInfo;
				int val;

				/* Get VMAC structure of the master */
				if (!wlpptr->master) {
					printk("Device %s is not a client device \n", netdev->name);
					rc = -EFAULT;
					break;
				}
				vmacSta_p = wlMPrvPtr->vmacSta_p;

				if (strlen(param[1]) == 0) {
					sprintf(p, "mode: %d\n", *(mib->mib_RptrMode));
					printk("mode: %d\n", *(mib->mib_RptrMode));
				} else if ((strcmp(param[1], "0") == 0) || (strcmp(param[1], "1") == 0)) {
					val = atoi(param[1]);

					if (val < 0 || val > 1) {
						rc = -EOPNOTSUPP;
						break;
					}
					*(mib->mib_RptrMode) = val;
					if (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_CLNT_INFRA) {
						if (val)
							*(mib->mib_STAMacCloneEnable) = 2;
						else
							*(mib->mib_STAMacCloneEnable) = 0;
					}
				} else if ((strcmp(param[1], "devicetype") == 0)) {
					if (strlen(param[2]) > (MAXRPTRDEVTYPESTR - 1)) {
						rc = -EOPNOTSUPP;
						break;
					}

					if (strlen(param[2]) != 0) {
						memcpy(mib->mib_RptrDeviceType, param[2], strlen(param[2]));
					} else {
						sprintf(p, "DeviceType: %s\n", mib->mib_RptrDeviceType);
						printk("DeviceType: %s\n", mib->mib_RptrDeviceType);
					}
				} else if ((strcmp(param[1], "agingtime") == 0)) {
					if (strlen(param[2]) != 0) {
						val = atoi(param[2]);
						if (val < 60 || val > 86400) {
							rc = -EOPNOTSUPP;
							break;
						}
						*(mib->mib_agingtimeRptr) = val;
					} else {
						sprintf(p, "agingtime: %d\n", (int)*mib->mib_agingtimeRptr);
						printk("agingtime: %d\n", (int)*mib->mib_agingtimeRptr);
					}
				} else if ((strcmp(param[1], "listmac") == 0)) {
					extern UINT16 ethStaDb_list(vmacApInfo_t * vmac_p);
					ethStaDb_list(vmacSta_p);
				} else if ((strcmp(param[1], "addmac") == 0)) {
					getMacFromString(macaddr, param[2]);
					if ((pStaInfo =
					     extStaDb_GetStaInfo(vmacSta_p, (IEEEtypes_MacAddr_t *) macaddr, STADB_DONT_UPDATE_AGINGTIME)) != NULL) {
						pStaInfo->StaType = 0x02;
					}
				} else if ((strcmp(param[1], "delmac") == 0)) {
					getMacFromString(macaddr, param[2]);
					if ((pStaInfo =
					     extStaDb_GetStaInfo(vmacSta_p, (IEEEtypes_MacAddr_t *) macaddr, STADB_DONT_UPDATE_AGINGTIME)) != NULL) {
						pStaInfo->StaType = 0;
						ethStaDb_RemoveStaPerWlan(vmacSta_p, (IEEEtypes_MacAddr_t *) macaddr);
					}
				} else {
					rc = -EFAULT;
					break;
				}
				*ret_len = strlen(bufBack);
				break;
			} else if ((strcmp(param[0], "loadtxpwrtable") == 0)) {
				struct file *filp = NULL;
				char buff[120], *s;
				int len, index = 0, i, value = 0;

				filp = filp_open(param[1], O_RDONLY, 0);
				// if (filp != NULL) // Note: this one doesn't work and will cause crash
				if (!IS_ERR(filp)) {	// MUST use this one, important!!!
					printk("loadtxpwrtable open <%s>: OK\n", param[1]);

					/* reset the whole table */
					for (i = 0; i < IEEE_80211_MAX_NUMBER_OF_CHANNELS; i++)
						memset(mib->PhyTXPowerTable[i], 0, sizeof(MIB_TX_POWER_TABLE));

					while (1) {
						s = buff;
						while ((len = kernel_read(filp, s, 0x01, &filp->f_pos)) == 1) {
							if (*s == '\n') {
								/* skip blank line */
								if (s == buff)
									break;

								/* parse this line and assign value to data structure */
								*s = '\0';
								printk("index=<%d>: <%s>\n", index, buff);

								/* 8964 total param: ch + setcap + 32 txpower + CDD + tx2 = 36 */
								sscanf(buff,
								       "%64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s\n",
								       param[0], param[1], param[2], param[3], param[4], param[5], param[6], param[7],
								       param[8], param[9], param[10], param[11], param[12], param[13], param[14],
								       param[15], param[16], param[17], param[18], param[19], param[20], param[21],
								       param[22], param[23], param[24], param[25], param[26], param[27], param[28],
								       param[29], param[30], param[31], param[32], param[33], param[34], param[35]);

								if (strcmp(param[34], "on") == 0)
									value = 1;
								else if (strcmp(param[34], "off") == 0)
									value = 0;
								else {
									printk("txpower table format error: CCD should be on|off\n");
									break;
								}
								mib->PhyTXPowerTable[index]->CDD = value;
								mib->PhyTXPowerTable[index]->txantenna2 = atohex2(param[35]);
								mib->PhyTXPowerTable[index]->Channel = atoi(param[0]);
								mib->PhyTXPowerTable[index]->setcap = atoi(param[1]);

								for (i = 0; i < TX_POWER_LEVEL_TOTAL; i++) {
									s16 pwr;
									pwr = (s16) atoi_2(param[i + 2]);
									mib->PhyTXPowerTable[index]->TxPower[i] = pwr;
								}

								index++;
								break;
							} else
								s++;
						}
						if (len <= 0)
							break;
					}

					filp_close(filp, current->files);
				} else
					printk("loadtxpwrtable open <%s>: FAIL\n", param[1]);

				break;
			} else if ((strcmp(param[0], "gettxpwrtable") == 0)) {
				int index;
				printk("txpower table:\n");
				for (index = 0; index < IEEE_80211_MAX_NUMBER_OF_CHANNELS; index++) {
					if (mib->PhyTXPowerTable[index]->Channel == 0)
						break;
					printk
					    ("%d %d 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x %d %d\n",
					     mib->PhyTXPowerTable[index]->Channel, mib->PhyTXPowerTable[index]->setcap,
					     mib->PhyTXPowerTable[index]->TxPower[0], mib->PhyTXPowerTable[index]->TxPower[1],
					     mib->PhyTXPowerTable[index]->TxPower[2], mib->PhyTXPowerTable[index]->TxPower[3],
					     mib->PhyTXPowerTable[index]->TxPower[4], mib->PhyTXPowerTable[index]->TxPower[5],
					     mib->PhyTXPowerTable[index]->TxPower[6], mib->PhyTXPowerTable[index]->TxPower[7],
					     mib->PhyTXPowerTable[index]->TxPower[8], mib->PhyTXPowerTable[index]->TxPower[9],
					     mib->PhyTXPowerTable[index]->TxPower[10], mib->PhyTXPowerTable[index]->TxPower[11],
					     mib->PhyTXPowerTable[index]->TxPower[12], mib->PhyTXPowerTable[index]->TxPower[13],
					     mib->PhyTXPowerTable[index]->TxPower[14], mib->PhyTXPowerTable[index]->TxPower[15],
					     mib->PhyTXPowerTable[index]->TxPower[16], mib->PhyTXPowerTable[index]->TxPower[17],
					     mib->PhyTXPowerTable[index]->TxPower[18], mib->PhyTXPowerTable[index]->TxPower[19],
					     mib->PhyTXPowerTable[index]->TxPower[20], mib->PhyTXPowerTable[index]->TxPower[21],
					     mib->PhyTXPowerTable[index]->TxPower[22], mib->PhyTXPowerTable[index]->TxPower[23],
					     mib->PhyTXPowerTable[index]->TxPower[24], mib->PhyTXPowerTable[index]->TxPower[25],
					     mib->PhyTXPowerTable[index]->TxPower[26], mib->PhyTXPowerTable[index]->TxPower[27],
					     mib->PhyTXPowerTable[index]->TxPower[28], mib->PhyTXPowerTable[index]->TxPower[29],
					     mib->PhyTXPowerTable[index]->TxPower[30], mib->PhyTXPowerTable[index]->TxPower[31],
					     mib->PhyTXPowerTable[index]->CDD, mib->PhyTXPowerTable[index]->txantenna2);
				}
				break;
			} else if (strcmp(param[0], "linklost") == 0) {
				extern UINT32 g_PrbeReqCheckTheshold[NUM_OF_WLMACS];
				UINT32 numOfInterval, macIndex;

				macIndex = atoi(param[1]);
				numOfInterval = atoi(param[2]);

				if (numOfInterval < 4)
					numOfInterval = 4;

				g_PrbeReqCheckTheshold[macIndex] = numOfInterval;
			}
#ifdef SSU_SUPPORT
			else if (strcmp(param[0], "ssutest") == 0) {
				/* Fixed to 0x80000*4 bytes for now - 2 MBytes, more than is needed for 10ms trace. */
				//#define  SSU_DUMP_SIZE_DWORDS  0x80000
				//ssu_cmd_t ssuCfg;
				UINT32 *pSsuPci = (UINT32 *) priv->pSsuBuf;
				UINT16 dump = 0;

				dump = atohex2(param[1]);

				if (dump == 1) {
					UINT32 printFlag = atohex2(param[2]);

					ssu_dump_file(priv->wlpd_p->pPhysSsuBuf, pSsuPci, priv->ssuSize, printFlag);
				} else {
					ssu_cmd_t ssuCfg;
					int index = 2;

					/* Clear memory before performing spectral dump from firmware. */
					memset((void *)&ssuCfg, 0x00, sizeof(ssuCfg));
					memset(pSsuPci, 0, priv->ssuSize);
					if (dump == 0) {
						ssuCfg.Time = atohex2(param[5]);
						printk("SSU fft_length =%d\n", (int)atohex2(param[2]) & 0x03);
						printk("SSU fft_skip   =%d\n", (int)atohex2(param[3]) & 0x03);
						printk("SSU adc_dec    =%d\n", (int)atohex2(param[4]) & 0x03);
						printk("SSU Time       =%d\n", ssuCfg.Time);
					}

					if (dump == 2) {
						index = 2;
						ssuCfg.Nskip = atohex2(param[index++]);
						ssuCfg.Nsel = atohex2(param[index++]);
						ssuCfg.AdcDownSample = atohex2(param[index++]);
						ssuCfg.MaskAdcPacket = atohex2(param[index++]);
						ssuCfg.Output16bits = atohex2(param[index++]);
						ssuCfg.PowerEnable = atohex2(param[index++]);
						ssuCfg.RateDeduction = atohex2(param[index++]);
						ssuCfg.PacketAvg = atohex2(param[index++]);
						ssuCfg.Time = atohex2(param[index++]);
						ssuCfg.TestMode = 1;
						ssuCfg.FFT_length = 0;
						ssuCfg.ADC_length = 0;
						ssuCfg.RecordLength = 0;
						ssuCfg.BufferNumbers = 0;
						ssuCfg.BufferSize = 0;
					}
					if (ssuCfg.Time == 0)
						ssuCfg.Time = 10;	//default msec

					ssuCfg.BufferBaseAddress = (UINT32) priv->wlpd_p->pPhysSsuBuf;
					ssuCfg.BufferBaseSize = priv->ssuSize;

					/* Currently number of SSU buffers set to 250 - firmware actually uses 10 buffers per descriptor
					   for a total of 2500 buffers equivalent to 10ms dump.  Need to change this to support SSU dumps
					   of 10 to 100ms in 10ms steps. */
					if (wlFwSetSpectralAnalysis(netdev, &ssuCfg))
						printk("SSU Error - command error.\n");
					else
						printk("ssutest : start \n");

				}

			}
#endif
#ifdef QUEUE_STATS
			else if ((strcmp(param[0], "qstats") == 0)) {
#ifdef QUEUE_STATS_CNT_HIST
				if ((strcmp(param[1], "pktcount") == 0)) {
					if (strlen(param[2]) > 0) {
						dbgUdpSrcVal = atoi(param[2]);
					}
#ifdef SOC_W906X
					if (wlFwGetQueueStats(netdev, QS_GET_TX_COUNTER, 0, NULL) == FAIL) {
#else
					if (wlFwGetQueueStats(netdev, QS_GET_TX_COUNTER, NULL) == FAIL) {
#endif
						printk("Error: wlFwGetQueueStats get QS_GET_TX_COUNTER failed\n");
					}
				} else if ((strcmp(param[1], "retry_histogram") == 0)) {
#ifdef SOC_W906X
					if (wlFwGetQueueStats(netdev, QS_GET_RETRY_HIST, 0, NULL) == FAIL) {
#else
					if (wlFwGetQueueStats(netdev, QS_GET_RETRY_HIST, NULL) == FAIL) {
#endif
						printk("Error: wlFwGetQueueStats get QS_GET_RETRY_HIST failed\n");
					}
				}
#ifdef NEWDP_ACNT_BA
				/*To collect total BA records specified by ACNT_BA_SIZE. After buffer is full, no more BA records collection.
				 * Need to use "qstats reset" to clear buffer to record BA records again.
				 * To enable/ disable this CLI, "qstats txba_histogram staid <0:disable|1:enable> <staid_1> <staid_2> <staid_3> <0:SU|1:MU>"
				 * To print output "qstats txba_histogram". Raw data is save in /tmp/ba_histo file
				 */
				else if ((strcmp(param[1], "txba_histogram") == 0)) {
					UINT8 i, type = 0, enable = 0;
					UINT16 staid[3] = { 0, 0, 0 };
					WLAN_TX_BA_HIST *pBA = NULL;
					extern UINT8 BA_HISTO_STAID_MAP[10];

					/*Set enable/disable txba histogram for up to 3 stations from staid 0 to 8 */
					if ((strcmp(param[2], "staid") == 0)) {

						enable = atoi(param[3]);	//0:Disable, 1:Enable
						staid[0] = atoi(param[4]);
						staid[1] = atoi(param[5]);
						staid[2] = atoi(param[6]);

						memset((UINT8 *) & BA_HISTO_STAID_MAP[0], 0, (sizeof(UINT8) * 10));

						if (atoi(param[7]) < 2)	//0:SU, 1:MU
							type = atoi(param[7]);
						else
							type = 0;

						for (i = 0; i < 3; i++) {

#ifdef SOC_W906X
							/*Only support staid from 0 to 8 */
							if (staid[i] < 9) {
#else
							/*Only support staid from 1 to 9 */
							if ((staid[i] > 0) && (staid[i] < 10)) {
#endif
								BA_HISTO_STAID_MAP[staid[i]] = i;	//create stnid map to ba_histo buffer for faster acnt update
							} else {
								printk("staid %d is out of supported id range\n", staid[i]);
								continue;
							}

							/*Update info when staid is valid */
							pBA = &priv->wlpd_p->txBAStats[i];
							pBA->StatsEnable = enable;
							if (enable) {
								printk("BA histogram %s, staid:%d, type:%s\n", enable ? "enable" : "disable",
								       staid[i], type ? "MU" : "SU");

								if (pBA->pBAStats == NULL) {

									if ((pBA->pBAStats =
									     (WLAN_TX_BA_STATS *) wl_kmalloc_autogfp(sizeof(WLAN_TX_BA_STATS) *
														     ACNT_BA_SIZE)) != NULL) {
										memset(pBA->pBAStats, 0, (sizeof(WLAN_TX_BA_STATS) * ACNT_BA_SIZE));
										//printk("Alloc memory for BA histo\n");
									} else {
										printk("BAStats[%d]: Alloc memory FAIL for txba_histogram\n", i);
										break;
									}
								}

								pBA->Stnid = staid[i];
								pBA->Type = type;
								pBA->Index = 0;

							} else {
								printk("BA histogram %s\n", enable ? "enable" : "disable");
								if (pBA->pBAStats != NULL) {
									wl_kfree(pBA->pBAStats);
									pBA->pBAStats = NULL;
								}
							}
						}

						break;
					}

					/*Print txba_histogram */
					staid[0] = atoi(param[2]);
#ifdef SOC_W906X
					wlFwGetQueueStats(netdev, (QS_GET_BA_HIST | (staid[0] << 4)), 0, NULL);
#else
					wlFwGetQueueStats(netdev, (QS_GET_BA_HIST | (staid[0] << 4)), NULL);
#endif

				}
#endif
				else if ((strcmp(param[1], "txrate_histogram") == 0)) {
					int indx, i, staid;
					int entries = extStaDb_entries(vmacSta_p, 0);
					UINT8 *staBuf = wl_kmalloc(entries * sizeof(STA_INFO), GFP_KERNEL);
					UINT8 *listBuf;
					extStaDb_StaInfo_t *pStaInfo;

					if (staBuf == NULL) {
						printk("Can't alloc memory for txrate_histogram\n");
						break;
					}

					/*Print only staid */
					if ((strcmp(param[2], "staid") == 0)) {
						staid = atoi(param[3]);
						printk("Total SU RA tx attempt cnt, <4:%u, >=4:%u, >=15:%u, >=50:%u, >=100:%u, >=250:%u\n",
						       (unsigned int)
						       RA_TX_ATTEMPT[SU_MIMO][0], (unsigned int)RA_TX_ATTEMPT[SU_MIMO][1],
						       (unsigned int)RA_TX_ATTEMPT[SU_MIMO][2], (unsigned int)RA_TX_ATTEMPT[SU_MIMO][3],
						       (unsigned int)RA_TX_ATTEMPT[SU_MIMO][4], (unsigned int)RA_TX_ATTEMPT[SU_MIMO][5]);

						printk("Total MU RA tx attempt cnt, <4:%u, >=4:%u, >=15:%u, >=50:%u, >=100:%u, >=250:%u\n\n",
						       (unsigned int)RA_TX_ATTEMPT[MU_MIMO][0], (unsigned int)RA_TX_ATTEMPT[MU_MIMO][1],
						       (unsigned int)RA_TX_ATTEMPT[MU_MIMO][2], (unsigned int)RA_TX_ATTEMPT[MU_MIMO][3],
						       (unsigned int)RA_TX_ATTEMPT[MU_MIMO][4], (unsigned int)RA_TX_ATTEMPT[MU_MIMO][5]);

						printk("staid: %d\n", staid);
						printk("============================\n");
#ifdef SOC_W906X
						wlFwGetQueueStats(netdev, (QS_GET_TX_RATE_HIST | (staid << 4)), 0, NULL);
#else
						wlFwGetQueueStats(netdev, (QS_GET_TX_RATE_HIST | ((staid - 1) << 4)), NULL);
#endif

						if (staBuf != NULL)
							wl_kfree(staBuf);
						break;
					}
					if (staBuf != NULL) {
						if (!extStaDb_list(vmacSta_p, staBuf, 1)) {
							wl_kfree(staBuf);
							break;
						}

						if (entries) {
							printk("Total SU RA tx attempt cnt, <4:%u, >=4:%u, >=15:%u, >=50:%u, >=100:%u, >=250:%u\n",
							       (unsigned int)RA_TX_ATTEMPT[SU_MIMO][0], (unsigned int)RA_TX_ATTEMPT[SU_MIMO][1],
							       (unsigned int)RA_TX_ATTEMPT[SU_MIMO][2], (unsigned int)RA_TX_ATTEMPT[SU_MIMO][3],
							       (unsigned int)RA_TX_ATTEMPT[SU_MIMO][4], (unsigned int)RA_TX_ATTEMPT[SU_MIMO][5]);

							printk("Total MU RA tx attempt cnt, <4:%u, >=4:%u, >=15:%u, >=50:%u, >=100:%u, >=250:%u\n\n",
							       (unsigned int)RA_TX_ATTEMPT[MU_MIMO][0], (unsigned int)RA_TX_ATTEMPT[MU_MIMO][1],
							       (unsigned int)RA_TX_ATTEMPT[MU_MIMO][2], (unsigned int)RA_TX_ATTEMPT[MU_MIMO][3],
							       (unsigned int)RA_TX_ATTEMPT[MU_MIMO][4], (unsigned int)RA_TX_ATTEMPT[MU_MIMO][5]);

							listBuf = staBuf;
							for (i = 0; i < entries; i++) {
								if ((pStaInfo =
								     extStaDb_GetStaInfo(vmacSta_p, (IEEEtypes_MacAddr_t *) listBuf,
											 STADB_SKIP_MATCH_VAP)) != NULL) {
									//if(wldbgIsInTxMacList((UINT8* )pStaInfo->Addr) )
									{
										//printk("\nRate Histogram (Total samples = %10u)\n", (unsigned int)(jiffies-pStaInfo->jiffies));
										printk("\nSTA %02x:%02x:%02x:%02x:%02x:%02x\n",
										       pStaInfo->Addr[0],
										       pStaInfo->Addr[1],
										       pStaInfo->Addr[2],
										       pStaInfo->Addr[3], pStaInfo->Addr[4], pStaInfo->Addr[5]);
										printk("============================\n");
#ifdef SOC_W906X
										indx = (pStaInfo->StnId < sta_num) ? pStaInfo->StnId : 0;
										if (wlFwGetQueueStats
										    (netdev, (QS_GET_TX_RATE_HIST | (indx << 4)), 0, NULL) == FAIL) {
#else
										indx = pStaInfo->StnId ? (pStaInfo->StnId - 1) : 0;
										if (wlFwGetQueueStats
										    (netdev, (QS_GET_TX_RATE_HIST | (indx << 4)), NULL) == FAIL) {
#endif
										}
									}
									listBuf += sizeof(STA_INFO);
								}
							}
						} else {

							if (vmacSta_p->OpMode == WL_OP_MODE_STA || vmacSta_p->OpMode == WL_OP_MODE_VSTA ||
							    vmacSta_p->OpMode == WL_OP_MODE_VAP) {
								if (vmacSta_p->OpMode == WL_OP_MODE_VAP) {
									int i;

									for (i = 0; i < MAX_WDS_PORT; i++) {
										if (vmacSta_p->wdsActive[i]) {

											printk("\nWDS %02x:%02x:%02x:%02x:%02x:%02x\n",
											       vmacSta_p->wdsPort[i].wdsMacAddr[0],
											       vmacSta_p->wdsPort[i].wdsMacAddr[1],
											       vmacSta_p->wdsPort[i].wdsMacAddr[2],
											       vmacSta_p->wdsPort[i].wdsMacAddr[3],
											       vmacSta_p->wdsPort[i].wdsMacAddr[4],
											       vmacSta_p->wdsPort[i].wdsMacAddr[5]);
											printk("============================\n");
#ifdef SOC_W906X
											if (wlFwGetQueueStats(netdev, (QS_GET_TX_RATE_HIST), 0, NULL)
											    == FAIL) {
#else
											if (wlFwGetQueueStats(netdev, (QS_GET_TX_RATE_HIST), NULL) ==
											    FAIL) {
#endif
											}
										}
									}
								} else {
									vmacEntry_t *vmacEntry_p = NULL;
									pStaInfo = NULL;
									if ((vmacEntry_p =
									     sme_GetParentVMacEntry(vmacSta_p->VMacEntry.phyHwMacIndx)) != NULL) {
										vmacStaInfo_t *vStaInfo_p = (vmacStaInfo_t *) vmacEntry_p->info_p;

										pStaInfo = extStaDb_GetStaInfo(vmacSta_p,
													       (IEEEtypes_MacAddr_t *) & vStaInfo_p->
													       macMgmtMlme_ThisStaData.BssId[0],
													       STADB_DONT_UPDATE_AGINGTIME);
									}

									printk("\n STA mode, tx Data Frame Rate Histogram\n");
									printk("============================\n");
#ifdef SOC_W906X
									indx = (pStaInfo && (pStaInfo->StnId < sta_num)) ? pStaInfo->StnId : 0;
									if (wlFwGetQueueStats(netdev, (QS_GET_TX_RATE_HIST | (indx << 4)), 0, NULL) ==
									    FAIL) {
#else
									indx = (pStaInfo && pStaInfo->StnId) ? (pStaInfo->StnId - 1) : 0;
									if (wlFwGetQueueStats(netdev, (QS_GET_TX_RATE_HIST | (indx << 4)), NULL) ==
									    FAIL) {
#endif
									}
								}

							} else {
								printk("\ntx Rate Histogram => no available data\n");
							}
						}
						wl_kfree(staBuf);
					}
				} else if ((strcmp(param[1], "rxrate_histogram") == 0)) {
#ifdef SOC_W906X
					if (wlFwGetQueueStats(netdev, QS_GET_RX_RATE_HIST, 0, NULL) == FAIL) {
#else
					if (wlFwGetQueueStats(netdev, QS_GET_RX_RATE_HIST, NULL) == FAIL) {
#endif
						printk("\nRx Rate Histogram => no available data\n");
					}
				} else if ((strcmp(param[1], "addrxmac") == 0)) {
					int k;
					for (k = 0; k < QS_NUM_STA_SUPPORTED; k++) {
						if (strlen(param[k + 2]) == 12) {
							getMacFromString(rxPktStats_sta[k].addr, param[k + 2]);
							rxPktStats_sta[k].valid = 1;
							printk("Added Rx STA: %02x %02x %02x %02x %02x %02x\n",
							       rxPktStats_sta[k].addr[0],
							       rxPktStats_sta[k].addr[1],
							       rxPktStats_sta[k].addr[2],
							       rxPktStats_sta[k].addr[3], rxPktStats_sta[k].addr[4], rxPktStats_sta[k].addr[5]);
							memcpy(&qs_rxMacAddrSave[k * 6], rxPktStats_sta[k].addr, 6);
						} else {
							break;
						}
					}
					numOfRxSta = k;
					wlFwSetMacSa(netdev, numOfRxSta, (UINT8 *) qs_rxMacAddrSave);
				} else if ((strcmp(param[1], "addtxmac") == 0)) {
					int k;
					for (k = 0; k < QS_NUM_STA_SUPPORTED; k++) {
						if (strlen(param[k + 2]) == 12) {
							getMacFromString(txPktStats_sta[k].addr, param[k + 2]);
							txPktStats_sta[k].valid = 1;
							printk("Added Tx STA: %02x %02x %02x %02x %02x %02x\n",
							       (int)txPktStats_sta[k].addr[0],
							       (int)txPktStats_sta[k].addr[1],
							       (int)txPktStats_sta[k].addr[2],
							       (int)txPktStats_sta[k].addr[3],
							       (int)txPktStats_sta[k].addr[4], (int)txPktStats_sta[k].addr[5]);
						} else {
							break;
						}
					}
				}
#endif
#ifdef QUEUE_STATS_LATENCY
				if ((strcmp(param[1], "txlatency") == 0)) {
#ifdef SOC_W906X
					if (wlFwGetQueueStats(netdev, QS_GET_TX_LATENCY, 0, NULL) == FAIL) {
#else
					if (wlFwGetQueueStats(netdev, QS_GET_TX_LATENCY, NULL) == FAIL) {
#endif
						printk("Error: wlFwGetQueueStats get QS_GET_TX_LATENCY failed\n");
					}
				}
				if ((strcmp(param[1], "rxlatency") == 0)) {
#ifdef SOC_W906X
					if (wlFwGetQueueStats(netdev, QS_GET_RX_LATENCY, 0, NULL) == FAIL) {
#else
					if (wlFwGetQueueStats(netdev, QS_GET_RX_LATENCY, NULL) == FAIL) {
#endif
						printk("Error: wlFwGetQueueStats get QS_GET_RX_LATENCY failed\n");
					}
				}
#endif
				if ((strcmp(param[1], "reset") == 0)) {
					int i, k, nss, bw, mcs, sgi;

#ifdef NEWDP_ACNT_BA
					for (i = 0; i < 3; i++) {
						priv->wlpd_p->txBAStats[i].Index = 0;
						if (priv->wlpd_p->txBAStats[i].pBAStats != NULL)
							memset(priv->wlpd_p->txBAStats[i].pBAStats, 0, (sizeof(WLAN_TX_BA_STATS) * ACNT_BA_SIZE));
					}

#endif

					memset(&RA_TX_ATTEMPT[0], 0, (sizeof(UINT32) * 2 * 6));

					for (i = 0; i < QS_NUM_STA_SUPPORTED; i++)
						txPktStats_sta[i].valid = 0;
					for (i = 0; i < sta_num; i++) {
						if (priv->wlpd_p->txRateHistogram[i] != NULL) {

							memset(priv->wlpd_p->txRateHistogram[i]->CurRateInfo, 0, sizeof(UINT32) * SU_MU_TYPE_CNT);
							memset(priv->wlpd_p->txRateHistogram[i]->TotalTxCnt, 0, sizeof(UINT32) * SU_MU_TYPE_CNT);

							for (k = 0; k < RATE_ADAPT_MAX_SUPPORTED_RATES; k++) {
								priv->wlpd_p->txRateHistogram[i]->SU_rate[k].cnt = 0;
								memset(priv->wlpd_p->txRateHistogram[i]->SU_rate[k].per, 0,
								       sizeof(UINT32) * TX_RATE_HISTO_PER_CNT);

							}
							for (nss = 0; nss < (QS_NUM_SUPPORTED_11AC_NSS - 1); nss++) {
								for (bw = 0; bw < QS_NUM_SUPPORTED_11AC_BW; bw++) {
									for (mcs = 0; mcs < QS_NUM_SUPPORTED_11AC_MCS; mcs++) {
										for (sgi = 0; sgi < QS_NUM_SUPPORTED_GI; sgi++) {
											priv->wlpd_p->txRateHistogram[i]->MU_rate[nss][bw][sgi][mcs].
											    cnt = 0;
											memset(priv->wlpd_p->txRateHistogram[i]->
											       MU_rate[nss][bw][sgi][mcs].per, 0,
											       sizeof(UINT32) * TX_RATE_HISTO_PER_CNT);
										}
									}
								}
							}

							for (k = 0; k < TX_RATE_HISTO_CUSTOM_CNT; k++) {
								priv->wlpd_p->txRateHistogram[i]->custom_rate[k].cnt = 0;
								memset(priv->wlpd_p->txRateHistogram[i]->custom_rate[k].per, 0,
								       sizeof(UINT32) * TX_RATE_HISTO_PER_CNT);

							}

						}
					}

					memset(&priv->wlpd_p->rxRateHistogram, 0, sizeof(WLAN_RATE_HIST));
#if defined(ACNT_REC) && defined (SOC_W906X)
					memset(&priv->wlpd_p->drvrxRateHistogram, 0, sizeof(DRV_RATE_HIST));
#endif				// defined(ACNT_REC) && defined (SOC_W906X)
				}

				if (strcmp(param[1], "rastats") == 0) {
					if (strcmp(param[2], "raw") == 0) {
						if (strcmp(param[3], "f") == 0) {
							char *filename;
							int filename_len = 256;

							filename = wl_vzalloc(filename_len);
							if (!filename) {
								rc = -ENOMEM;
								break;
							}

							if (strlen(param[4])) {
								strncpy(filename, param[4], filename_len - 1);
								wl_write_acnt_RA_stats(netdev, filename);
							}
							wl_vfree(filename);
						} else if (strlen(param[3])) {
							u32 entry = 0;
							entry = atoi(param[3]);

							if (entry > ACNT_TX_RECORD_MAX)
								entry = ACNT_TX_RECORD_MAX;

							wl_dump_acnt_RA_stats(netdev, entry);
						}
					} else if (strcmp(param[2], "log_enable") == 0) {
						wl_enable_acnt_record_logging(netdev, acnt_code_RA_stats);
					} else if (strcmp(param[2], "log_disable") == 0) {
						wl_disable_acnt_record_logging(netdev, acnt_code_RA_stats);
					}
				}
			}
#endif

			else if (strcmp(param[0], "rccal") == 0) {
				extern int wlFwSetRCcal(struct net_device *netdev);
				wlFwSetRCcal(netdev);
				printk("RC Cal done\n");
			} else if (strcmp(param[0], "gettemp") == 0) {
				extern int wlFwGetTemp(struct net_device *netdev);
				wlFwGetTemp(netdev);
			}
#ifdef SOC_W906X
			else if (strcmp(param[0], "getbcngpio17toggle") == 0) {
				u8 enabled = 0;
				wlFwBcnGpio17Toggle(netdev, WL_GET, &enabled);

				if (enabled)
					printk("Beacon GPIO17 toggle IS enabled.\n");
				else
					printk("Beacon GPIO17 toggle is NOT enabled.\n");
			} else if (strcmp(param[0], "bcngpio17toggle") == 0) {
				u8 enabled = atoi(param[1]) & 0xFF;
				wlFwBcnGpio17Toggle(netdev, WL_SET, &enabled);

				if (enabled)
					printk("Beacon GPIO17 toggle IS enabled.\n");
				else
					printk("Beacon GPIO17 toggle is NOT enabled.\n");
			}
#endif
#ifdef SOC_W8964
			else if (strcmp(param[0], "getphybw") == 0) {
				extern int wlFwGetPHYBW(struct net_device *netdev);
				wlFwGetPHYBW(netdev);
			}

			else if (strcmp(param[0], "alphatimingfc") == 0) {
				extern int wlFwSetAlphaTimingFc(struct net_device *netdev, UINT8 Enable, int Fc_Value);
				wlFwSetAlphaTimingFc(netdev, atoi(param[1]), atoi(param[2]));
			}
#endif
			/* Cmd to set limit number of stations that can assoc to a virtual interface. Each virtual interface has a separate limit.
			 * "macMgmtMlme_AssocReAssocReqHandler" function will check the limit. If over limit, error status is sent in assoc resp
			 **/
			else if ((strcmp(param[0], "maxsta") == 0)) {
				int val;
				//Only take virtual interface as input
				if (!is_the_cmd_applicable(cmd) && !priv->master) {
					printk("Error. Please enter virtual interface instead\n");
					rc = -EOPNOTSUPP;
					wl_kfree(param);
					return rc;
				}
				val = atoi(param[1]);
				if (val < 1 || val > sta_num) {
					printk("Incorrect value. Value between 1 to %d only. Default is %d\n", sta_num, sta_num);
					break;
				}
				*(mib->mib_maxsta) = val;
				printk("Configure %s max station limit = %d\n", netdev->name, (int)*(mib->mib_maxsta));
				break;
			} else if ((strcmp(param[0], "getmaxsta") == 0)) {
				//Only take virtual interface as input
				if (!is_the_cmd_applicable(cmd) && !priv->master) {
					printk("Error. Please enter virtual interface instead\n");
					rc = -EOPNOTSUPP;
					wl_kfree(param);
					return rc;
				}
				printk("Max station limit in %s is %d\n", netdev->name, (int)*(mib->mib_maxsta));
				break;
			} else if ((strcmp(param[0], "txfaillimit") == 0)) {
				int val;
				//Only take parent interface as input
				if (priv->master) {
					printk("Error. Please enter parent interface %s instead\n", priv->master->name);
					rc = -EOPNOTSUPP;
					wl_kfree(param);
					return rc;
				}

				val = atoi(param[1]);
				if (val >= 0)
					*(mib->mib_consectxfaillimit) = val;
				else {
					printk("Error. Please enter value >= 0\n");
					break;
				}

				if (!wlFwSetConsecTxFailLimit(netdev, *(mib->mib_consectxfaillimit))) {
					if (*(mib->mib_consectxfaillimit))
						printk("Config %s txfail limit > %d\n", netdev->name, (int)*(mib->mib_consectxfaillimit));
					else
						printk("txfail limit is disabled\n");
				}

				break;
			} else if ((strcmp(param[0], "gettxfaillimit") == 0)) {
				UINT32 val;

				//Only take parent interface as input
				if (priv->master) {
					printk("Error. Please enter parent interface %s instead\n", priv->master->name);
					rc = -EOPNOTSUPP;
					wl_kfree(param);
					return rc;
				}
				if (!wlFwGetConsecTxFailLimit(netdev, (UINT32 *) & val)) {
					if (val)
						printk("Consecutive txfail limit > %d\n", (int)val);
					else
						printk("txfail limit is disabled\n");
				}

				break;
			}
#ifdef MRVL_WAPI
			else if ((strcmp(param[0], "wapi") == 0)) {
				char macaddr[6];
				u16 auth_type;

				if (strcmp(param[1], "ucast_rekey") == 0) {
					auth_type = 0x00F2;
					if (!getMacFromString(macaddr, param[2])) {
						rc = -EFAULT;
						break;
					}
				} else if (strcmp(param[1], "mcast_rekey") == 0) {
					auth_type = 0x00F4;
					memcpy(macaddr, bcastMacAddr, 6);
				} else {
					rc = -EFAULT;
					break;
				}

				macMgmtMlme_WAPI_event(netdev, IWEVASSOCREQIE, auth_type, macaddr, netdev->dev_addr, NULL);
			}
#endif
#ifdef WNC_LED_CTRL
			else if ((strcmp(param[0], "led") == 0)) {
				if (strcmp(param[1], "on") == 0) {
					printk("set led on ...\n");
					wlFwLedOn(netdev, 1);
				} else if (strcmp(param[1], "off") == 0) {
					printk("set led off ...\n");
					wlFwLedOn(netdev, 0);
				} else {
					rc = -EFAULT;
				}
				break;
			}
#endif

#ifdef CLIENT_SUPPORT
			/*Set client mode to send Probe Req during tx or not */
			else if ((strcmp(param[0], "fastreconnect") == 0)) {
				ProbeReqOnTx = atoi(param[1]);
				if (ProbeReqOnTx > 1) {
					printk("Pls submit value 0 or 1 only\n");
					ProbeReqOnTx = 0;
					rc = -EOPNOTSUPP;
				}

				break;
			}
#endif

#ifdef NEW_DP
			else if ((strcmp(param[0], "newdp") == 0)) {
				UINT8 ch = 36, width = 6, rates = 8, rate_type = 1, rate_bw = 2, rate_gi = 0, rate_ss = 2;

				if (strcmp(param[1], "ch") == 0) {
					ch = atohex2(param[2]);

				}
				if (strcmp(param[3], "w") == 0) {
					width = atohex2(param[4]);

					printk("channel :%d width %d\n", ch, width);
				}

				if (strcmp(param[5], "r") == 0) {
					rate_type = atohex2(param[6]);
					rates = atohex2(param[7]);
					rate_bw = atohex2(param[8]);
					rate_gi = atohex2(param[9]);
					rate_ss = atohex2(param[10]);

				}
				wlFwNewDP_Cmd(netdev, ch, width, rates, rate_type, rate_bw, rate_gi, rate_ss);
				printk("channel :%d width %d rate_type=%d [11n/ac] rates = %d bw = %d [20/40/80] rate_gi[SGI/LGI]=%d rate_ss=%d\n",
				       ch, width, rate_type, rates, rate_bw, rate_gi, rate_ss);
				break;
			} else if ((strcmp(param[0], "txratectrl") == 0)) {
				UINT32 type = 1, val = 0, staid = 0;

				if (strcmp(param[1], "type") == 0)
					type = atoi(param[2]);

				printk("Rate drop using ");
				if (strcmp(param[3], "val") == 0) {
					/*Auto rate */
					if (type == 1)
						printk("auto rate\n");

					/*Fixed rate using rate tbl index */
					else if (type == 2) {
						val = atoi(param[4]);
						printk("rate table index %u\n", (unsigned int)val);
					}
					/*Fixed rate using rateinfo */
					else if (type == 3) {
						val = atohex2(param[4]);
						printk("rateinfo 0x%x\n", (unsigned int)val);
					}
					/*Fixed rate per sta. Specify station index to have fixed rateinfo
					 * txratectrl type 4 val 0x0f4f0522 staidx 1 //sta index 1 to have fixed rateinfo
					 */
					else if (type == 4) {
						val = atohex2(param[4]);

						if (strcmp(param[5], "staidx") == 0)
							staid = atoi(param[6]);

						printk("per sta index %u, rateinfo 0x%x\n", (unsigned int)staid, (unsigned int)val);
					}
					/*Fixed rate using adaptive rateinfo */
					else if (type == 5) {
						val = atohex2(param[4]);
						printk("Adaptive fixed rate with rate drop. Rateinfo 0x%x\n", (unsigned int)val);
					}
					/*Fixed rate using adaptive rateinfo without rate drop */
					else if (type == 6) {
						val = atohex2(param[4]);
						printk("Adaptive fixed rate without rate drop. Rateinfo 0x%x\n", (unsigned int)val);
					}
#ifdef CONFIG_MC_BC_RATE
					/*Fixed MC rate using rateinfo */
					else if (type == 7) {
						val = atohex2(param[4]);
						printk("MC rateinfo 0x%x\n", (unsigned int)val);
					}
					/*Fixed BC rate using rateinfo */
					else if (type == 8) {
						val = atohex2(param[4]);
						printk("BC rateinfo 0x%x\n", (unsigned int)val);
					}
#endif
				}

				wlFwNewDP_RateDrop(netdev, type, val, staid);
				break;
#ifdef SOC_W8964
			} else if ((strcmp(param[0], "newdpcnt") == 0)) {
				NewdpRxCounter_t *pNewDpCnts = (NewdpRxCounter_t *) & priv->wlpd_p->rxCnts;
				printk
				    ("fastDataCnt = %d\nfastBadAmsduCnt = %d\nslowNoqueueCnt = %d\nslowNoRunCnt = %d\nslowMcastCnt = %d\nslowBadStaCnt = %d\n",
				     pNewDpCnts->fastDataCnt, pNewDpCnts->fastBadAmsduCnt, pNewDpCnts->slowNoqueueCnt, pNewDpCnts->slowNoRunCnt,
				     pNewDpCnts->slowMcastCnt, pNewDpCnts->slowBadStaCnt);
				printk
				    ("slowBadMicCnt = %d\nslowBadPNCnt = %d\nslowMgmtCnt = %d\nslowPromiscCnt = %d\ndropCnt = %d\noffChanPktCnt = %d\nMU PktCnt = %d\n",
				     pNewDpCnts->slowBadMicCnt, pNewDpCnts->slowBadPNCnt, pNewDpCnts->slowMgmtCnt, pNewDpCnts->slowPromiscCnt,
				     pNewDpCnts->dropCnt, pNewDpCnts->offchPromiscCnt, pNewDpCnts->mu_pktcnt);
				break;
#endif
			} else if ((strcmp(param[0], "newdpacntsize") == 0)) {
				wlAcntSetBufSize(netdev, (SetAcntBufInfo_t *) 0x20000);
				break;
			} else if ((strcmp(param[0], "newdpacnt") == 0)) {
				u_int8_t *acnBuf = NULL;
				u_int32_t head, tail, bufSize = 0;
				u_int32_t maxSize = priv->wlpd_p->descData[0].AcntRingSize;
				wlAcntPeekRecds(netdev, &head, &tail);

				if (tail > head) {
					if (tail >= maxSize)
						bufSize = head;
					else
						bufSize = maxSize - tail;
				} else {
					bufSize = head - tail;
				}
				acnBuf = (u_int8_t *) wl_kmalloc_autogfp(bufSize);
				wlAcntReadRecds(netdev, (tail + bufSize), acnBuf, &bufSize);
				if (bufSize > 0) {
					acnt_t *pAcntRec;
					printk("acnt head=%d, tail=%d, buf size=%d\n", head, tail, bufSize);
					pAcntRec = (acnt_t *) acnBuf;
					switch (pAcntRec->Code) {
					case acnt_code_busy:
						printk("acnt_code_busy\n");
						break;
					case acnt_code_wrap:
						printk("cnt_code_wrap\n");
						break;
					case acnt_code_drop:
						printk("acnt_code_drop\n");
						break;
					case acnt_code_tx_enqueue:
						printk("acnt_code_tx_enqueue\n");
						break;
					case acnt_code_rx_ppdu:
						printk("acnt_code_rx_ppdu\n");
						break;
					case acnt_code_tx_flush:
						printk("acnt_code_tx_flush\n");
						break;
					case acnt_code_rx_reset:
						printk("acnt_code_rx_reset\n");
						break;
					case acnt_code_tx_getNewTxq:
						printk("acnt_code_tx_getNewTxq\n");
						break;
					default:
						{
							printk("invalide accounting record\n");
						}
					}
				}
				if (acnBuf)
					wl_kfree(acnBuf);
				break;
			} else if ((strcmp(param[0], "newdpoffch") == 0)) {
				DOT11_OFFCHAN_REQ_t offchan;

				if (IsACSOnoing(netdev)) {
					rc = -EINVAL;
					printk("newdpoffch acs is ongoing\n");
					break;
				}
				memset((UINT8 *) & offchan, 0x0, sizeof(DOT11_OFFCHAN_REQ_t));
				offchan.channel = atoi(param[1]);
				offchan.id = OFFCHAN_GET_ID_FROM_FEATURE(OFFCHAN_BY_CMD, atoi(param[2]));
				offchan.dwell_time = atoi(param[3]);

				printk("Offchan ch:%u, id:%u, dwell:%u\n", (unsigned int)offchan.channel, (unsigned int)offchan.id,
				       (unsigned int)offchan.dwell_time);
				wlFwNewDP_queue_OffChan_req(netdev, &offchan);
				break;
			} else if ((strcmp(param[0], "newdpoffch_nf") == 0)) {
				DOT11_OFFCHAN_REQ_t offchan;
				memset((UINT8 *) & offchan, 0x0, sizeof(DOT11_OFFCHAN_REQ_t));
				offchan.channel = atoi(param[1]);
				offchan.id = OFFCHAN_GET_ID_FROM_FEATURE(OFFCHAN_BY_CMD, atoi(param[2]));
				offchan.dwell_time = atoi(param[3]);
				offchan.req_type = OFFCHAN_TYPE_RX_NF;	/* NF-reading feedback */
				printk("Offchan_nf ch:%u, id:%u, dwell:%u\n", (unsigned int)offchan.channel, (unsigned int)offchan.id,
				       (unsigned int)offchan.dwell_time);
				wlFwNewDP_queue_OffChan_req(netdev, &offchan);
				break;
			}

			/*To continuously send a fixed len pkt generated in fw using rate info supplied by user or send carrier wave (cw).
			 * Can also be used to send a continuous modulated wave from the rate info supplied by user (CMW / labtool cmd 17)
			 * Before switching from one tx mode to another (e.g tx pkt to cw or vice versa), it has to be disabled first.
			 */
			else if ((strcmp(param[0], "txcontinuous") == 0)) {
				UINT8 mode = 0;
				UINT32 rateinfo = 0;

				mode = atoi(param[1]);

				if (mode == 0) {
					printk("Tx continuous disabled\n");

				} else if (mode == 1) {
					rateinfo = atohex2(param[2]);
					printk("Tx continuous pkt, rateinfo 0x%x\n", rateinfo);
				} else if (mode == 2) {
					printk("Tx continuous carrier wave mode\n");
				} else if (mode == 3) {
					rateinfo = atohex2(param[2]);
					printk("Tx continuous modulated wave mode, rateinfo 0x%x\n", rateinfo);
				} else {
					printk("txcontinuous [0:disable|1:pkt|2:cw mode|3:cmw mode] [32bits rateinfo]\n");
				}

				if (mode <= 3)
					wlFwSetTxContinuous(netdev, mode, rateinfo);

				break;
			}

			/*To set Receiver Start of Packet Detection Threshold (Rx SOP threshold) */
			else if ((strcmp(param[0], "rxsop") == 0)) {
				UINT8 params, threshold1 = 0, threshold2 = 0;
				MIB_802DOT11 *mib1 = vmacSta_p->Mib802dot11;

				params = atoi(param[1]);
				threshold1 = atohex2(param[2]);

				if (params) {
					if (params == 1)
						printk("rxsop param %d, threshold 0x%x\n", params, threshold1);
					else if (params == 2) {
						threshold2 = atohex2(param[3]);
						mib1->rxsop_ed_threshold1 = threshold1;
						mib1->rxsop_ed_threshold2 = threshold2;
						printk("CCA ED param %d, threshold hi 0x%x, thereshold lo 0x%x\n", params, threshold1, threshold2);
					} else if (params == 4) {
						mib1->rxsop_cck_threshold1 = threshold1;
						printk("CCK De-sense param %d, threshold 0x%x\n", params, threshold1);
					}
					wlFwNewDP_RxSOP(netdev, params, threshold1, threshold2);
				} else {
					printk("Usage: rxsop <type> <threshold1> <threshold2>\n");
					printk("Type: 2 - CCA ED Thresholds. threshold1 = high, threshold2 = low\n");
					printk("Type: 4 - CCK De-sense: Only threshold1 required\n");
					printk(" A threshold value of 0 means to disable this mode\n");
				}
				break;
			}
#endif

#if defined(SOC_W906X) || defined(SOC_W9068)
			/*To set 11b OBW to default or 16MHz */
			else if ((strcmp(param[0], "obw16_11b") == 0)) {
				UINT8 params;

				params = atoi(param[1]);
				if (params) {
					wlFwOBW16_11b(netdev, 1);
					mib->obw16_11b_val = 1;
					printk("11b OBW set to 16 MHz!\n");
				} else {
					wlFwOBW16_11b(netdev, 0);
					mib->obw16_11b_val = 0;
					printk("11b OBW set to Default!\n");
				}
				break;
			}
#endif
			else if ((strcmp(param[0], "loadpwrperrate") == 0)) {
				struct file *filp = NULL;
				char *buff, *s;
				int len, index = 0, i, j = 0, k = 0;

				buff = (char *)wl_kmalloc(500, GFP_KERNEL);
				memset(buff, 0, 500);
				filp = filp_open(param[1], O_RDONLY, 0);
				// if (filp != NULL) // Note: this one doesn't work and will cause crash
				if (!IS_ERR(filp)) {	// MUST use this one, important!!!
					printk("loadpwrperrate open <%s>: OK\n", param[1]);

					/* reset the whole table */
					for (i = 0; i < IEEE_80211_MAX_NUMBER_OF_CHANNELS; i++)
						memset(&wlpd_p->AllChanGrpsPwrTbl.PerChanGrpsPwrTbl[i], 0, sizeof(PerChanGrpsPwr_t));

					while (1) {
						s = buff;
						while ((len = kernel_read(filp, s, 0x01, &filp->f_pos)) == 1) {
							if (*s == '\n') {
								/* skip blank line */
								if (s == buff) {
									break;
								}
								/* parse this line and assign value to data structure */
								*s = '\0';
								//printk("index=<%d>: <%s>\n", index, buff);
								sscanf(buff,
								       "%64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s\n",
								       param[0], param[1], param[2], param[3], param[4], param[5], param[6], param[7],
								       param[8], param[9], param[10], param[11], param[12], param[13], param[14],
								       param[15], param[16], param[17], param[18], param[19], param[20], param[21],
								       param[22], param[23], param[24], param[25], param[26], param[27], param[28],
								       param[29], param[30], param[31], param[32], param[33], param[34], param[35],
								       param[36], param[37], param[38], param[39], param[40], param[41], param[42],
								       param[43], param[44], param[45], param[46], param[47], param[48], param[49],
								       param[MAX_GROUP_PER_CHANNEL]);

								wlpd_p->AllChanGrpsPwrTbl.PerChanGrpsPwrTbl[j].channel = atoi(param[0]);
								k++;
								//printk("channel =%d \n",wlpd_p->AllChanGrpsPwrTbl.PerChanGrpsPwrTbl[j].channel);
								for (i = 1; i < (MAX_GROUP_PER_CHANNEL + 1); i++) {
									s8 pwr;

									pwr = atoi_2(param[i]);

									if (pwr == -1) {
										wlpd_p->AllChanGrpsPwrTbl.PerChanGrpsPwrTbl[j].NumOfGrpPerChan =
										    i - 1;
										//printk("NumOfGrpPerChan =%d \n", AllChanGrpsPwrTbl.PerChanGrpsPwrTbl[j].NumOfGrpPerChan);
										break;
									}
									wlpd_p->AllChanGrpsPwrTbl.PerChanGrpsPwrTbl[j].GrpsPwr[i - 1] = pwr;
									//printk("pwr =%d \n", wlpd_p->AllChanGrpsPwrTbl.PerChanGrpsPwrTbl[j].GrpsPwr[i-1]);

								}
								index++;
								j++;
								break;
							} else
								s++;
						}
						if (len <= 0)
							break;
					}
					wlpd_p->AllChanGrpsPwrTbl.NumOfChan = k;
					filp_close(filp, current->files);
				} else
					printk("loadpwrperrate open <%s>: FAIL\n", param[1]);
				wl_kfree(buff);
				break;

			} else if ((strcmp(param[0], "loadrategrps") == 0)) {
				struct file *filp = NULL;
				char *buff, *s;
				int len, i, GrpId, NumOfEntry;

				buff = (char *)wl_kmalloc(500, GFP_KERNEL);
				memset(buff, 0, 500);
				filp = filp_open(param[1], O_RDONLY, 0);
				// if (filp != NULL) // Note: this one doesn't work and will cause crash
				if (!IS_ERR(filp)) {	// MUST use this one, important!!!
					printk("loadrategrps open <%s>: OK\n", param[1]);
					memset(wlpd_p->RateGrpDefault, 0, sizeof(RateGrp_t) * MAX_GROUP_PER_CHANNEL);
					while (1) {
						s = buff;
						while ((len = kernel_read(filp, s, 0x01, &filp->f_pos)) == 1) {
							if (*s == '\n') {
								/* skip blank line */
								if (s == buff) {
									break;
								}
								/* parse this line and assign value to data structure */
								*s = '\0';
								//3(grp # + NumOfEntry+Ant) + MAX_RATES_PER_GROUP=43
								sscanf(buff,
								       "%64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s\n",
								       (char *)param[0], (char *)param[1], (char *)param[2], (char *)param[3],
								       (char *)param[4], (char *)param[5], (char *)param[6], (char *)param[7],
								       (char *)param[8], (char *)param[9], (char *)param[10], (char *)param[11],
								       param[12], param[13], param[14], param[15], param[16], param[17], param[18],
								       param[19], param[20], param[21], param[22], param[23], param[24], param[25],
								       param[26], param[27], param[28], param[29], param[30], param[31], param[32],
								       param[33], param[34], param[35], param[36], param[37], param[38], param[39],
								       param[40], param[41], param[42], param[43], param[44], param[45], param[46],
								       param[47], param[48], param[49], param[50]);
								GrpId = atohex2(param[0]);
								NumOfEntry = atohex2(param[1]);
								if (NumOfEntry != 0) {
									printk("GrpId=<%d>: <%s>\n", GrpId, buff);
									wlpd_p->RateGrpDefault[GrpId].NumOfEntry = NumOfEntry;
									wlpd_p->RateGrpDefault[GrpId].AxAnt = atohex2(param[2]);
									for (i = 0; i < NumOfEntry; i++) {
										wlpd_p->RateGrpDefault[GrpId].Rate[i] = atohex2(param[i + 3]);
										//printk("Rate= 0x%X \n", wlpd_p->RateGrpDefault[GrpId].Rate[i]);
									}
								}
								break;
							} else
								s++;
						}
						if (len <= 0)
							break;
					}
					filp_close(filp, current->files);
				} else
					printk("RateGrps.conf open <%s>: FAIL\n", param[1]);
				wl_kfree(buff);
				break;

			} else if ((strcmp(param[0], "loadpwrgrpstbl") == 0)) {
				struct file *filp = NULL;
				char *buff, *s;
				int len, i, GrpId, NumOfEntry;
				int index = 0, j = 0, k = 0;
				BOOLEAN bStartTxPwrTbl = FALSE;
				BOOLEAN bStartRateGrpsConf = FALSE;
				BOOLEAN bStartPwrPerRateGrps = FALSE;
				char *TxPwrTbl = "[TX_PWR_TBL]";
				char *RateGrpsConf = "[RATE_GRPS_CONF]";
				char *PwrPerRateGrps = "[PWR_PER_RATE_GRPS]";
#ifdef SOC_W8964
				int value = 0;
#endif
				buff = (char *)wl_kmalloc(4096, GFP_KERNEL);
				memset(buff, 0, 4096);
				filp = filp_open(param[1], O_RDONLY, 0);
				// if (filp != NULL) // Note: this one doesn't work and will cause crash
				if (!IS_ERR(filp)) {	// MUST use this one, important!!!
					printk("loadpwrgrpstbl open <%s>: OK\n", param[1]);
					memset(wlpd_p->RateGrpDefault, 0, sizeof(RateGrp_t) * MAX_GROUP_PER_CHANNEL);
					for (i = 0; i < IEEE_80211_MAX_NUMBER_OF_CHANNELS; i++)
						memset(mib->PhyTXPowerTable[i], 0, sizeof(MIB_TX_POWER_TABLE));
					while (1) {
						s = buff;
						while ((len = kernel_read(filp, s, 0x01, &filp->f_pos)) == 1) {

							if (len >= 4096) {
								printk("out of buffer range\n");
								BUG();
							}

							if (*s == '\n') {
								/* skip blank line */
								if (s == buff) {
									break;
								}
								/* parse this line and assign value to data structure */
								*s = '\0';
								sscanf(buff, "%64s", param[0]);
								if (strncmp(param[0], TxPwrTbl, 12) == 0) {
									bStartTxPwrTbl = TRUE;
									bStartRateGrpsConf = FALSE;
									bStartPwrPerRateGrps = FALSE;
									break;
								}
								sscanf(buff, "%64s", param[0]);
								if (strncmp(param[0], RateGrpsConf, 16) == 0) {
									bStartTxPwrTbl = FALSE;
									bStartRateGrpsConf = TRUE;
									bStartPwrPerRateGrps = FALSE;
									break;
								}
								if (strncmp(param[0], PwrPerRateGrps, 19) == 0) {
									bStartTxPwrTbl = FALSE;
									bStartRateGrpsConf = FALSE;
									bStartPwrPerRateGrps = TRUE;
									break;
								}
								if (bStartTxPwrTbl || bStartRateGrpsConf || bStartPwrPerRateGrps) {
									if (bStartTxPwrTbl) {
										goto TxPwrTbl;
									}
									if (bStartRateGrpsConf) {
										goto RateGrpsConf;
									}
									if (bStartPwrPerRateGrps) {
										goto PwrPerRateGrps;
									}
								}
								printk("Error: unknown string \n");
 TxPwrTbl:
#ifdef SOC_W8964
								printk("index=<%d>: <%s>\n", index, buff);

								/* 8964 total param: ch + setcap + 32 txpower + CDD + tx2 = 36 */
								sscanf(buff,
								       "%64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s\n",
								       param[0], param[1], param[2], param[3], param[4], param[5], param[6], param[7],
								       param[8], param[9], param[10], param[11], param[12], param[13], param[14],
								       param[15], param[16], param[17], param[18], param[19], param[20], param[21],
								       param[22], param[23], param[24], param[25], param[26], param[27], param[28],
								       param[29], param[30], param[31], param[32], param[33], param[34], param[35]);

								if (strcmp(param[34], "on") == 0)
									value = 0x13;
								else if (strcmp(param[34], "off") == 0)
									value = 0;
								else {
									printk("txpower table format error: CCD should be on|off\n");
									break;
								}
								mib->PhyTXPowerTable[index]->CDD = value;
								mib->PhyTXPowerTable[index]->txantenna2 = atohex2(param[35]);
								mib->PhyTXPowerTable[index]->Channel = atoi(param[0]);
								mib->PhyTXPowerTable[index]->setcap = atoi(param[1]);

								for (i = 0; i < TX_POWER_LEVEL_TOTAL; i++) {
									s16 pwr;
									pwr = (s16) atoi_2(param[i + 2]);
									mib->PhyTXPowerTable[index]->TxPower[i] = pwr;
								}

								index++;
#endif
								break;
 RateGrpsConf:
								memset(param[0], 0, sizeof(*param));
								memset(param[1], 0, sizeof(*param));
								sscanf(buff,
								       "%64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s\n",
								       param[0], param[1], param[2], param[3], param[4], param[5], param[6], param[7],
								       param[8], param[9], param[10], param[11], param[12], param[13], param[14],
								       param[15], param[16], param[17], param[18], param[19], param[20], param[21],
								       param[22], param[23], param[24], param[25], param[26], param[27], param[28],
								       param[29], param[30], param[31], param[32], param[33], param[34], param[35],
								       param[36], param[37], param[38], param[39], param[40], param[41], param[42],
								       param[43], param[44], param[45], param[46], param[47], param[48], param[49],
								       param[50]);
								GrpId = atohex2(param[0]);
								NumOfEntry = atohex2(param[1]);
								if (NumOfEntry != 0) {
									//printk("GrpId=<%d>: <%s>\n", GrpId, buff);
									wlpd_p->RateGrpDefault[GrpId].NumOfEntry = NumOfEntry;
									wlpd_p->RateGrpDefault[GrpId].AxAnt = atohex2(param[2]);
									//printk("GrpId=<%d>: entries:%u, AxAnt:%x\n", GrpId, wlpd_p->RateGrpDefault[GrpId].NumOfEntry, wlpd_p->RateGrpDefault[GrpId].AxAnt);

									if (NumOfEntry > MAX_RATES_PER_GROUP || GrpId > MAX_GROUP_PER_CHANNEL - 1) {
										printk("Error: RateGrpsConf out of range\n");
									}

									for (i = 0; i < NumOfEntry; i++) {
										wlpd_p->RateGrpDefault[GrpId].Rate[i] = atohex2(param[i + 3]);
										//printk("Rate= 0x%X \n", wlpd_p->RateGrpDefault[GrpId].Rate[i]);
									}
								}
								break;
 PwrPerRateGrps:
#ifdef SOC_W906X
								sscanf(buff,
								       "%64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s\n",
								       param[0], param[1], param[2], param[3], param[4], param[5], param[6], param[7],
								       param[8], param[9], param[10], param[11], param[12], param[13], param[14],
								       param[15], param[16], param[17], param[18], param[19], param[20], param[21],
								       param[22], param[23], param[24], param[25], param[26], param[27], param[28],
								       param[29], param[30], param[31], param[32], param[33], param[34], param[35],
								       param[36], param[37], param[38], param[39], param[40], param[41], param[42],
								       param[43], param[44], param[45], param[46], param[47], param[48], param[49],
								       param[50], param[51], param[52], param[53], param[54], param[55], param[56],
								       param[57], param[58], param[59], param[60], param[61], param[62], param[63],
								       param[64], param[65], param[66], param[67], param[68], param[69], param[70],
								       param[71], param[72], param[73], param[74], param[75], param[76], param[77],
								       param[78], param[79], param[80], param[81], param[82], param[83], param[84],
								       param[85], param[86], param[87], param[88], param[89], param[90], param[91],
								       param[92], param[93], param[94], param[95], param[96], param[97], param[98],
								       param[99], param[100], param[101], param[102], param[103], param[104],
								       param[105], param[106], param[107], param[108], param[109], param[110],
								       param[111], param[112], param[113], param[114], param[115], param[116],
								       param[117], param[118], param[119], param[120], param[121], param[122],
								       param[123], param[124], param[125], param[126], param[127], param[128],
								       param[129], param[130], param[131], param[132], param[133], param[134],
								       param[135], param[136], param[137], param[138], param[139], param[140],
								       param[141], param[142], param[143], param[144], param[145], param[146],
								       param[147], param[148], param[149], param[150], param[151], param[152],
								       param[153], param[154], param[155], param[156], param[157], param[158],
								       param[159], param[160], param[161], param[162], param[163], param[164],
								       param[165], param[166], param[167], param[168], param[169], param[170],
								       param[171], param[172], param[173], param[174], param[175], param[176],
								       param[177], param[178], param[179], param[180], param[181], param[182],
								       param[183], param[184], param[185], param[186], param[187], param[188],
								       param[189], param[190], param[191], param[192], param[193], param[194],
								       param[195], param[196], param[197], param[198], param[199], param[200],
								       param[201], param[202], param[203], param[204], param[205], param[206],
								       param[207], param[208], param[209], param[210], param[211], param[212],
								       param[213], param[214], param[215], param[216], param[217], param[218],
								       param[219], param[220], param[221], param[222], param[223], param[224],
								       param[225], param[226], param[227], param[228], param[229], param[230],
								       param[231], param[232], param[233], param[234], param[235], param[236],
								       param[237], param[238], param[239], param[240], param[241], param[242],
								       param[243], param[244], param[245], param[246], param[247], param[248],
								       param[249], param[250], param[251], param[252], param[253], param[254],
								       param[255], param[256], param[257], param[258], param[259], param[260],
								       param[261], param[262], param[263], param[264], param[265], param[266],
								       param[267], param[268], param[269], param[270], param[271], param[272],
								       param[273], param[274], param[275], param[276], param[277], param[278],
								       param[279], param[MAX_GROUP_PER_CHANNEL]);
#else
								sscanf(buff,
								       "%64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s %64s\n",
								       param[0], param[1], param[2], param[3], param[4], param[5], param[6], param[7],
								       param[8], param[9], param[10], param[11], param[12], param[13], param[14],
								       param[15], param[16], param[17], param[18], param[19], param[20], param[21],
								       param[22], param[23], param[24], param[25], param[26], param[27], param[28],
								       param[29], param[30], param[31], param[32], param[33], param[34], param[35],
								       param[36], param[37], param[38], param[39], param[40], param[41], param[42],
								       param[43], param[44], param[45], param[46], param[47], param[48], param[49],
								       param[MAX_GROUP_PER_CHANNEL]);
#endif

								wlpd_p->AllChanGrpsPwrTbl.PerChanGrpsPwrTbl[j].channel = atoi(param[0]);
								k++;
								//printk("channel =%d \n",wlpd_p->AllChanGrpsPwrTbl.PerChanGrpsPwrTbl[j].channel);
								for (i = 1; i < (MAX_GROUP_PER_CHANNEL + 1); i++) {
#ifdef SOC_W906X
									UINT32 pwr;
									UINT8 sign = 0;
									UINT32 intg, dec;
									UINT8 decDigit[8];

									if (!_atof(param[i], &sign, &intg, &dec, decDigit)) {
										printk("invalid floating point format..\n");
										continue;
									}

									if (intg == 255) {
										wlpd_p->AllChanGrpsPwrTbl.PerChanGrpsPwrTbl[j].NumOfGrpPerChan =
										    i - 1;
										//printk("ch:%d, NumOfGrpPerChan =%d \n",
										//wlpd_p->AllChanGrpsPwrTbl.PerChanGrpsPwrTbl[j].channel,AllChanGrpsPwrTbl.PerChanGrpsPwrTbl[j].NumOfGrpPerChan);
										break;
									}

									if (!_PoweLevelToDUT(sign, intg, dec, decDigit, &pwr)) {
										printk("fail to convert power value..\n");
										continue;
									}
#else
									s8 pwr;

									pwr = atoi_2(param[i]);

									if (pwr == -1) {
										wlpd_p->AllChanGrpsPwrTbl.PerChanGrpsPwrTbl[j].NumOfGrpPerChan =
										    i - 1;
										//printk("NumOfGrpPerChan =%d \n", wlpd_p->AllChanGrpsPwrTbl.PerChanGrpsPwrTbl[j].NumOfGrpPerChan);
										break;
									}
#endif
									wlpd_p->AllChanGrpsPwrTbl.PerChanGrpsPwrTbl[j].GrpsPwr[i - 1] = pwr;
									//printk("pwr =%d \n", wlpd_p->AllChanGrpsPwrTbl.PerChanGrpsPwrTbl[j].GrpsPwr[i-1]);

								}
								index++;
								j++;
								break;

							} else
								s++;
						}
						if (len <= 0)
							break;
					}
					wlpd_p->AllChanGrpsPwrTbl.NumOfChan = k;
					filp_close(filp, current->files);
				} else
					printk("RateGrps.conf open <%s>: FAIL\n", param[1]);
				wl_kfree(buff);
				break;
			} else if ((strcmp(param[0], "setperratepwr") == 0)) {
				Info_rate_power_table_t *pInfo;
				UINT8 i;

				pInfo = (Info_rate_power_table_t *) priv->wlpd_p->descData[0].pInfoPwrTbl;

				pInfo->RatePwrTbl.channel = atoi(param[1]);
				pInfo->RatePwrTbl.NumOfEntry = atoi(param[2]);

				if (pInfo->RatePwrTbl.NumOfEntry > 16) {
					printk("max entry is 16 \n");
					rc = -EFAULT;
					break;
				}
				printk("channel =%d, NumberOfEntry =%d \n", pInfo->RatePwrTbl.channel, pInfo->RatePwrTbl.NumOfEntry);
				for (i = 0; i < pInfo->RatePwrTbl.NumOfEntry; i++) {
					/*RatePower from bit0 onwards, format:2, stbc:1, bf:1, bw:2, resvd:2, mcs:6, nss:2, power:8, active_tx:8 */
					pInfo->RatePwrTbl.RatePower[i] = atohex2(param[3 + i]);
					printk("perratepwr = 0x%X \n", (unsigned int)pInfo->RatePwrTbl.RatePower[i]);
				}
				if (pInfo->DrvCnt != pInfo->FwCnt) {
					printk("fw is not ready\n");
					rc = -EAGAIN;
					break;
				} else {
					if (pInfo->DrvCnt == 0xFFFFFFFF) {
						pInfo->DrvCnt = 0;
					} else {
						pInfo->DrvCnt += 1;
					}
				}
				wlFwSetPowerPerRate(netdev);
#ifdef SOC_W906X
			} else if ((strcmp(param[0], "getperratepwr") == 0)) {
				UINT32 RatePower;	//From bit0 onwards, format:2, stbc:1, bf:1, bw:2, resvd:2, mcs:6, nss:2, power:8, active_tx:8
				//UINT8 trpcid;
				UINT16 dBm[2];
				UINT8 ant;
				UINT8 dbm_sign[2];
				UINT32 dbm_A[2];
				UINT8 dbm_digit[2][4];
				int i;

				RatePower = atohex2(param[1]);	//Only need to supply first 16bits, no need for power and active_tx

				wlFwGetPowerPerRate(netdev, RatePower, dBm, &ant);

				if (ant == 0 && dBm[0] == 0 && dBm[1] == 0) {
					printk("Rate:%x not found in table\n", RatePower);
					break;
				}

				for (i = 0; i < 2; i++)
					_DUTToPoweLevel(&dbm_sign[i], &dbm_A[i], &dbm_digit[i][0], (u32) dBm[i]);

				printk("RatePower: %x: dBm_pri:%c%u.%1u%1u%1u%1u,dBm_sec:%c%u.%1u%1u%1u%1u, ant_bitmap:0x%x \n",
				       RatePower, (dbm_sign[0] ? '-' : '+'), dbm_A[0], dbm_digit[0][0], dbm_digit[0][1], dbm_digit[0][2],
				       dbm_digit[0][3], (dbm_sign[1] ? '-' : '+'), dbm_A[1], dbm_digit[1][0], dbm_digit[1][1], dbm_digit[1][2],
				       dbm_digit[1][3], ant);
				break;
#else
			} else if ((strcmp(param[0], "getperratepwr") == 0)) {
				UINT32 RatePower;	//From bit0 onwards, format:2, stbc:1, bf:1, bw:2, resvd:2, mcs:6, nss:2, power:8, active_tx:8
				UINT8 trpcid;
				UINT16 dBm;
				UINT16 ant;

				RatePower = atohex2(param[1]);	//Only need to supply first 16bits, no need for power and active_tx

				wlFwGetPowerPerRate(netdev, RatePower, &trpcid, &dBm, &ant);

				printk("TrpcId: %d, dBm:%d, ant_bitmap:0x%x \n", trpcid, (SINT16) dBm, ant);

				break;
#endif
			} else if ((strcmp(param[0], "getnf") == 0)) {
#ifdef SOC_W906X
				s16 nf_value_signed[MAX_RF_ANT_NUM] = { 0 };

				wl_util_get_nf(netdev, &priv->wlpd_p->NF_path, nf_value_signed);
				printk(" nf_a: %d nf_b: %d nf_c: %d nf_d: %d nf_e: %d nf_f: %d nf_g: %d nf_h: %d \n ",
				       nf_value_signed[0], nf_value_signed[1], nf_value_signed[2], nf_value_signed[3],
				       nf_value_signed[4], nf_value_signed[5], nf_value_signed[6], nf_value_signed[7]);
#else
				u16 a, b, c, d;

				a = priv->wlpd_p->NF_path.a;
				b = priv->wlpd_p->NF_path.b;
				c = priv->wlpd_p->NF_path.c;
				d = priv->wlpd_p->NF_path.d;
				if (a >= 2048 && b >= 2048 && c >= 2048 && d >= 2048) {

					a = ((4096 - a) >> 4);
					b = ((4096 - b) >> 4);
					c = ((4096 - c) >> 4);
					d = ((4096 - d) >> 4);
					printk(" nf_a: -%d nf_b: -%d nf_c: -%d nf_d: -%d \n ", a, b, c, d);
				}
#endif
				break;
			} else if ((strcmp(param[0], "getradiostatus") == 0)) {
				radio_status_t *pRadioStatus;

				pRadioStatus = (radio_status_t *) & ((drv_fw_shared_t *) priv->wlpd_p->MrvlPriSharedMem.data)->RadioStatus;

				printk("dead =%d, dumping =%d, enabled =%d, SI_init =%d, DFS_required =%d,TimeSinceEnabled =%u \n",
				       pRadioStatus->dead, pRadioStatus->dumping, pRadioStatus->enabled,
				       pRadioStatus->SI_init, pRadioStatus->DFS_required, (unsigned int)pRadioStatus->TimeSinceEnabled);
			} else if ((strcmp(param[0], "ldpc") == 0)) {
				if (atoi(param[1])) {
					priv->wlpd_p->ldpcdisable = 0;
				} else {
					priv->wlpd_p->ldpcdisable = 1;
				}
				printk("ldpc =%d \n", atoi(param[1]));

			} else if ((strcmp(param[0], "tlv") == 0)) {
				extern int wlFwGetTLVSet(struct net_device *netdev, UINT8 act, UINT16 type, UINT16 len, UINT8 * tlvData,
							 char *string_buff);
				UINT16 type = 0, len = 0;
				UINT8 *tlvData, i;
				char *buff;

				buff = wl_kzalloc(120, GFP_KERNEL);
				tlvData = wl_kzalloc(MAX_TLV_LEN, GFP_KERNEL);
				if (!buff || !tlvData) {
					rc = -ENOMEM;
					break;
				}

				type = atoi(param[1]);
				len = atoi(param[2]);
				for (i = 0; i < len; i++)
					tlvData[i] = atohex(param[i + 3]);
				printk("SET tlv type=%d len=%d\n", type, len);
				for (i = 0; i < len; i++) {
					if ((i != 0) && !(i % 16)) {
						printk("\n");
						printk("%02x ", tlvData[i]);
					} else
						printk("%02x ", tlvData[i]);
				}
				printk("\n");
#ifdef WLS_FTM_SUPPORT
				wlpd_p->wls_ftm_config->wlsFTM_TriggerCsiEvent = FALSE;
#endif
				wlFwGetTLVSet(netdev, 1, type, len, tlvData, buff);
				wl_kfree(buff);
				wl_kfree(tlvData);
#ifdef PRD_CSI_DMA
			} else if ((strcmp(param[0], "csi") == 0)) {
#define CSI_TYPE 12
#define CSI_TLV_LEN 10
				extern int wlFwGetTLVSet(struct net_device *netdev, UINT8 act, UINT16 type, UINT16 len, UINT8 * tlvData,
							 char *string_buff);
				char buff[MAX_TLV_LEN];
				UINT8 tlvData[MAX_TLV_LEN];
				vmacApInfo_t *mastervmacSta_p;
				UINT8 sta_idx = 0;
				if (priv->vmacSta_p->master == NULL)
					mastervmacSta_p = priv->vmacSta_p;
				else
					mastervmacSta_p = priv->vmacSta_p->master;

				memset(tlvData, 0x00, MAX_TLV_LEN);

				if (strcmp(param[1], "get") == 0) {
					wlFwGetTLVSet(netdev, WL_GET, CSI_TYPE, 0, tlvData, buff);
					printk("Current CSI Settings are:\n");
					printk("CSI is %s\n", (tlvData[1] ? "Enabled" : "Disabled"));
					printk("MAC Address Filter: %02x.%02x.%02x.%02x.%02x.%02x\n", tlvData[2], tlvData[3], tlvData[4], tlvData[5],
					       tlvData[6], tlvData[7]);
					printk("Packet Type Filter: 0x%02x\n", tlvData[8]);
					printk("Packet Subtype Filter: 0x%02x\n", tlvData[9]);
					printk("CSI Detection Count (0-255): 0x%02x\n", tlvData[13]);
				} else if (strcmp(param[1], "set") == 0) {
					UINT8 csi_mac_idx = 0;
					char csi_mac_addr[6] = { 0 };

					tlvData[1] = (atohex2(param[2]) ? 1 : 0);	// Enable
					getMacFromString(csi_mac_addr, param[3]);
					for (csi_mac_idx = 0; csi_mac_idx < 6; csi_mac_idx++) {
						tlvData[csi_mac_idx + 2] = csi_mac_addr[csi_mac_idx];	// MAC Address
					}
					tlvData[8] = atohex2(param[4]) & 0xFF;	// Packet Type
					tlvData[9] = atohex2(param[5]) & 0xFF;	// Packet Subtype

#ifdef WLS_FTM_SUPPORT
					wlpd_p->wls_ftm_config->wlsFTM_TriggerCsiEvent = FALSE;
#endif
					wlFwGetTLVSet(netdev, WL_SET, CSI_TYPE, CSI_TLV_LEN, tlvData, buff);
				} else if (strcmp(param[1], "scale") == 0) {
					UINT8 temp = atohex2(param[2]) & 0xff;
					if (temp < 4) {	// valid input
						UINT32 val;
						wlRegBB(netdev, WL_GET, 0x6ac, &val);
						val = (val & 0xfc) | temp;
						wlRegBB(netdev, WL_SET, 0x6ac, &val);
						printk("CSI scale value set to %d\n", temp);
					} else {
						printk("CSI scale value %d out of range, should be [0:3]\n", temp);
					}
				} else if (strcmp(param[1], "type") == 0) {
					UINT8 temp = atohex2(param[2]) & 0xff;
					if ((temp == 1) || (temp == 2)) {	// valid input
						mastervmacSta_p->aoa.csiType = temp;
						printk("Set to capture %s CSI\n", ((temp == 1) ? "MDPU" : "NDP"));
					} else {
						printk("CSI type value %d can only be 1 (MDPU) or 2 (NDP)\n", temp);
					}
				} else if (strcmp(param[1], "N") == 0) {
#define CSI_N_REP_MAX 32
					UINT8 temp = atohex2(param[2]) & 0xff;
					if (temp <= CSI_N_REP_MAX) {	// valid input+
						mastervmacSta_p->aoa.setcsiCounter = temp;
						mastervmacSta_p->aoa.CurrentcsiCounter = temp;
						for (sta_idx = 0; sta_idx < AOASupMacNum; sta_idx++) {
							mastervmacSta_p->aoa.StaCounter[sta_idx] = temp;
						}
					} else {
						printk("CSI N repetition value %d out of range, should be [0:%d]\n", temp, CSI_N_REP_MAX);
					}
				} else if (strcmp(param[1], "setstation") == 0) {
					unsigned char inputaddr[6] = { 0 };

					getMacFromString(inputaddr, param[3]);
					if ((atohex2(param[2]) > 0) && (atohex2(param[2]) <= AOASupMacNum)) {
						memcpy(mastervmacSta_p->aoa.StaAddr[atohex2(param[2]) - 1], inputaddr, sizeof(inputaddr));
					} else
						printk("error sation mac number \n");

					for (sta_idx = 0; sta_idx < AOASupMacNum; sta_idx++) {
						printk("%pM\n", mastervmacSta_p->aoa.StaAddr[sta_idx]);
					}
				} else if (strcmp(param[1], "setrun") == 0) {
					UINT8 csi_mac_idx = 0;
					char csi_mac_addr[6] = { 0 };
					char brd_mac_addr[6] = { 0 };
					UINT8 wildcheck = 0;
					mastervmacSta_p->aoa.CurrentcsiCounter = mastervmacSta_p->aoa.setcsiCounter;
					if (mastervmacSta_p->aoa.CurrentcsiCounter < 1 || mastervmacSta_p->aoa.CurrentcsiCounter > 32)
						mastervmacSta_p->aoa.CurrentcsiCounter = 1;
					else
						mastervmacSta_p->aoa.CurrentcsiCounter = mastervmacSta_p->aoa.setcsiCounter;;
					if ((mastervmacSta_p->aoa.csiType != 1) && (mastervmacSta_p->aoa.csiType != 2))
						mastervmacSta_p->aoa.csiType = 1;
					mastervmacSta_p->aoa.ticks = atohex2(param[2]);

					tlvData[1] = mastervmacSta_p->aoa.csiType;	//
					getMacFromString(csi_mac_addr, param[3]);
					for (csi_mac_idx = 0; csi_mac_idx < 6; csi_mac_idx++) {
						tlvData[csi_mac_idx + 2] = csi_mac_addr[csi_mac_idx];	// MAC Address
					}
					tlvData[8] = atohex2(param[4]) & 0xFF;	// Packet Type
					tlvData[9] = atohex2(param[5]) & 0xFF;	// Packet Subtype

					mastervmacSta_p->aoa.AoAMode = aoa_macfilter_mode;
					memcpy(mastervmacSta_p->aoa.tlvData, tlvData, sizeof(tlvData));
					mastervmacSta_p->aoa.netdev = netdev;

					if (memcmp(csi_mac_addr, brd_mac_addr, 6) == 0)	//broadcase
					{

						for (sta_idx = 0; sta_idx < AOASupMacNum; sta_idx++) {
							if (memcmp(csi_mac_addr, mastervmacSta_p->aoa.StaAddr[sta_idx], 6) == 0) {
								mastervmacSta_p->aoa.StaCounter[sta_idx] = 0;
							} else {
								mastervmacSta_p->aoa.StaCounter[sta_idx] = mastervmacSta_p->aoa.setcsiCounter;
							}
							wildcheck += mastervmacSta_p->aoa.StaCounter[sta_idx];
						}
						if (wildcheck == 0) {
							printk("Set to received all AOA. \n");
							mastervmacSta_p->aoa.AoAMode = aoa_brd_mode;
							mastervmacSta_p->aoa.StaCounter[0] = mastervmacSta_p->aoa.setcsiCounter;
						}

					} else {
						mastervmacSta_p->aoa.StaCounter[0] = mastervmacSta_p->aoa.setcsiCounter;
						memcpy(mastervmacSta_p->aoa.StaAddr[0], csi_mac_addr, sizeof(csi_mac_addr));
						for (sta_idx = 1; sta_idx < AOASupMacNum; sta_idx++) {
							mastervmacSta_p->aoa.StaCounter[sta_idx] = 0;
						}
					}

#ifdef WLS_FTM_SUPPORT
					wlpd_p->wls_ftm_config->wlsFTM_TriggerCsiEvent = FALSE;
#endif
					TimerInit(&mastervmacSta_p->aoa.AOATimer);
					FireAOATimer(&mastervmacSta_p->aoa);
				} else if (strcmp(param[1], "setstoprun") == 0) {
					mastervmacSta_p->aoa.CurrentcsiCounter = 0;
					for (sta_idx = 0; sta_idx < AOASupMacNum; sta_idx++) {
						mastervmacSta_p->aoa.StaCounter[sta_idx] = 0;
					}
					TimerDisarm(&mastervmacSta_p->aoa.AOATimer);
					mastervmacSta_p->aoa.tlvData[1] = 0;
					wlFwGetTLVSet(netdev, WL_SET, CSI_TYPE, CSI_TLV_LEN, mastervmacSta_p->aoa.tlvData, buff);
					mastervmacSta_p->aoa.AoAMode = aoa_stop_mode;
				} else if (strcmp(param[1], "help") == 0) {
					printk("CSI Command Syntax:\n");
					printk("- get:\n");
					printk("-- Gets current CSI Settings.\n");
					printk("-- Example: iwpriv wdev0 setcmd \"csi get\"\n\n\n");
					printk("- type:\n");
					printk("-- Sets current CSI scaling parameter.\n");
					printk("-- Example: iwpriv wdev0 setcmd \"csi scale 2\"\n\n");
					printk("-- Sets CSI type to capture: 1 - Capture CSI of regular MPDUs. 2: - Capture CSI of NDPs.\n");
					printk("-- Example: iwpriv wdev0 setcmd \"csi type 1\"\n\n");
					printk("- N:\n");
					printk("-- Sets number of CSI to capture.\n");
					printk("-- Example: iwpriv wdev0 setcmd \"csi N 4\"\n\n");
					printk("- set:\n");
					printk("-- Enables / disables CSI filtering with specified settings.\n");
					printk("-- set <Enable> <MAC Address to Filter> <Packet Type to Filter> <Packet Subtype to Filter>\n\n");
					printk("-- <Enable>: 1 - Enable CSI Data Dumping. 0 - Disable CSI Data Dumping.\n");
					printk("-- <MAC Address to Filter>: MAC Address Filter for CSI Data Dump.\n");
					printk("--- A MAC Address of 000000000000 means wildcard.\n");
					printk("-- <Packet Type to Filter>: Packet Type Filter for CSI Data Dump.\n");
					printk("--- A Packet Type of 0xFF means wildcard.\n");
					printk("-- <Packet Subtype to Filter>: Packet Subtype Filter for CSI Data Dump.\n");
					printk("--- A Packet Subtype of 0xFF means wildcard.\n\n");
					printk("-- Example: iwpriv wdev0 setcmd \"csi set 1 000000000000 0xFF 0xFF\"\n");
					printk("-- Example: iwpriv wdev0 setcmd \"csi set 1 005043211234 0x02 0x08\"\n");
					printk("-- setstation <Station Number 1-5 > <MAC Address to Filter>\n\n");
					printk("-- Example: iwpriv wdev0ap0 setcmd \"csi setstation 1 005043211234\"\n");
					printk("-- setrun <100ms> <MAC Address to Filter> <Packet Type to Filter> <Packet Subtype to Filter>\n\n");
					printk("-- Example: iwpriv wdev0ap0 setcmd \"csi setrun 1 005043211234 0x02 0x08\"\n");
					printk("-- Example: iwpriv wdev0ap0 setcmd \"csi setstoprun \"\n");
				} else {
					printk("Invalid Input. Type \"csi help\" for command syntax.\n");
				}
#endif
			} else if ((strcmp(param[0], "ampducfg") == 0)) {
				//usage:ampducfg client_addr bitmap_tid
				//bitmap_tid: 0x0~0xff, 0: disable, 1: enable
				//ex: iwpriv wdev0ap0 setcmd "ampducfg 42504321bc2f 0x81"
				//client_addr=42504321bc2f, ampdutx enabled on tid(0, 7), disabled on tid(1, 2, 3, 4, 5, 6)
				u32 entries, i, j, sta_ampducfg = 0xff;
				UCHAR *sta_buf = NULL;
				extStaDb_StaInfo_t *pStaInfo;
				unsigned char sta_addr[6];
				vmacApInfo_t *master = NULL;
				unsigned char all_sta[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
				u16 win_size = 0;
				u8 *listBuf;

				if (input_cnt < 3) {
					printk("Usage: iwpriv wdev0ap0 setcmd \"ampducfg 42504321bc2f 0x81 [window size]\"");
					break;
				}
				if (priv->vmacSta_p->master == NULL)
					master = priv->vmacSta_p;
				else
					master = priv->vmacSta_p->master;
				memset(sta_addr, 0, sizeof(sta_addr));
				getMacFromString(sta_addr, param[1]);
				sta_ampducfg = atohex2(param[2]);

				if (input_cnt == 4) {
					win_size = atohex2(param[3]);
					if (win_size > 128) {
						WLDBG_ERROR(DBG_LEVEL_0, "Invlaid window size, max AMPDU window size is 128\n");
						rc = -EINVAL;
						break;
					}
				}
				if (memcmp(sta_addr, all_sta, sizeof(all_sta))) {
					entries = extStaDb_entries(vmacSta_p, 0);
					if (entries == 0) {
						printk("zero station list\n");
						break;
					}
				} else {
					if (input_cnt == 4) {
						if (priv->vmacSta_p->master == NULL) {
							WLDBG_ERROR(DBG_LEVEL_0, "Please enter VAP interface.\n");
							rc = -EINVAL;
							break;
						}
						for (i = 0; i < 8; i++) {
							if ((sta_ampducfg >> i) & 0x01)
								priv->vmacSta_p->winsize[i] = win_size;
						}
						printk("change AMPDU window size for all STAs: 0x%x\n", win_size);
						break;
					} else {
						master->ampducfg = sta_ampducfg;
						printk("ampducfg for all STAs: 0x%x\n", master->ampducfg);
					}
					break;
				}
				sta_buf = wl_kmalloc(entries * 64, GFP_KERNEL);
				listBuf = sta_buf;
				if (sta_buf == NULL) {
					printk("wl_kmalloc fail \n");
					break;
				}
				extStaDb_list(vmacSta_p, sta_buf, 1);
				for (i = 0; i < entries; i++) {
					if ((pStaInfo = extStaDb_GetStaInfo(vmacSta_p,
									    (IEEEtypes_MacAddr_t *) sta_buf, STADB_DONT_UPDATE_AGINGTIME)) == NULL) {
						printk("error: NO station info found \n");
						break;
					}
					if (memcmp(pStaInfo->Addr, sta_addr, sizeof(sta_addr)) == 0) {
						if (input_cnt == 4) {
							for (j = 0; j < 8; j++) {
								if ((sta_ampducfg >> j) & 0x01) {
									pStaInfo->aggr11n.winsize[j] = win_size;
									printk(MACSTR ", change AMPDU window size 0x%x\n", MAC2STR(sta_addr),
									       pStaInfo->aggr11n.winsize[j]);
								}
							}
						} else
							pStaInfo->aggr11n.ampducfg = sta_ampducfg;

						break;
					}
					sta_buf += sizeof(STA_INFO);
				}
				wl_kfree(listBuf);
				if (i >= entries) {
					printk(MACSTR ", not found\n", MAC2STR(sta_addr));
				} else {
					if (input_cnt != 4)
						printk(MACSTR ", ampducfg 0x%x\n", MAC2STR(sta_addr), pStaInfo->aggr11n.ampducfg);
				}
			} else if ((strcmp(param[0], "getampducfg") == 0)) {
				//usage: getampducfg client_addr
				//cliend addr: connected STA in getstalist/ffffffffffff
				//ex: iwpriv wdev0ap0 setcmd "getampducfg 42504321bc2f"
				u32 entries, i;
				UCHAR *sta_buf = NULL;
				extStaDb_StaInfo_t *pStaInfo;
				unsigned char sta_addr[6];
				vmacApInfo_t *master = NULL;
				unsigned char all_sta[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

				if (input_cnt < 2) {
					printk("Usage: iwpriv wdev0ap0 setcmd \"getampducfg 42504321bc2f\"\n");
					break;
				}
				if (priv->vmacSta_p->master == NULL)
					master = priv->vmacSta_p;
				else
					master = priv->vmacSta_p->master;
				memset(sta_addr, 0, sizeof(sta_addr));
				getMacFromString(sta_addr, param[1]);
				if (memcmp(sta_addr, all_sta, sizeof(all_sta))) {
					entries = extStaDb_entries(vmacSta_p, 0);
					if (entries == 0) {
						printk("zero station list\n");
						break;
					}
				} else {
					printk("ampducfg for all STAs: 0x%x\n", master->ampducfg);
					break;
				}
				sta_buf = wl_kmalloc(entries * 64, GFP_KERNEL);
				if (sta_buf == NULL) {
					printk("wl_kmalloc fail \n");
					break;
				}
				extStaDb_list(vmacSta_p, sta_buf, 1);
				for (i = 0; i < entries; i++) {
					if ((pStaInfo = extStaDb_GetStaInfo(vmacSta_p,
									    (IEEEtypes_MacAddr_t *) sta_buf, STADB_DONT_UPDATE_AGINGTIME)) == NULL) {
						printk("error: NO station info found \n");
						break;
					}
					if (memcmp(pStaInfo->Addr, sta_addr, sizeof(sta_addr)) == 0) {
						printk(MACSTR ", ampducfg: 0x%x\n", MAC2STR(sta_addr), pStaInfo->aggr11n.ampducfg);
						break;
					}
					sta_buf += sizeof(STA_INFO);
				}
				wl_kfree(sta_buf);
				if (i >= entries)
					printk(MACSTR ", not found\n", MAC2STR(sta_addr));
			} else if ((strcmp(param[0], "amsducfg") == 0)) {
				//usage:amsducfg client_addr enable/disable_amsducfg bitmap_tid amsdu_size
				//enable/disable_amsducfg: 1:enable, 0: not used
				//bitmap_tid: 0~7
				//amsdu_size: 0=disable amsdu, 1=4k, 2=8k, 3=11k, 0xff = *(mib->mib_amsdutx)
				//ex: iwpriv wdev0 setcmd "amsducfg 42504321bc2f 0x1 0x81 0x1"
				//client_addr=42504321bc2f, enable amsducfg operation in fw, amsdu on tid 7 and 0, size=4k
				u32 entries, i;
				vmacApInfo_t *master = NULL;
				unsigned char all_sta[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
				extStaDb_StaInfo_t *pStaInfo;
				amsducfg_t amsducfg;
				unsigned char *sta_buf = NULL;

				if (input_cnt < 5) {
					printk("iwpriv wdev0ap0 setcmd \"amsducfg 42504321bc2f 0x1 0x81 0x1\"\n");
					break;
				}
				if (priv->vmacSta_p->master == NULL)
					master = priv->vmacSta_p;
				else
					master = priv->vmacSta_p->master;
				getMacFromString(amsducfg.peeraddr, param[1]);
				amsducfg.amsduCfgEnable = atohex2(param[2]);	//when disable, bitmap_tid and amsdu_size don't care
				amsducfg.priority_aggr = atohex2(param[3]);
				if (!amsducfg.amsduCfgEnable)
					amsducfg.size = 0;
				else {
					amsducfg.size = 0xff;
					if (input_cnt > 4)
						amsducfg.size = atohex2(param[4]);
					if (amsducfg.size == 0xff)
						amsducfg.size = *(mib->mib_amsdutx);
				}
				if (memcmp(amsducfg.peeraddr, all_sta, sizeof(all_sta))) {
					entries = extStaDb_entries(vmacSta_p, 0);
					if (entries == 0) {
						printk("zero station list\n");
						break;
					}
					sta_buf = wl_kmalloc(entries * 64, GFP_KERNEL);
					if (sta_buf == NULL) {
						printk("wl_kmalloc fail\n");
						break;
					}
					extStaDb_list(vmacSta_p, sta_buf, 1);
					for (i = 0; i < entries; i++) {
						if ((pStaInfo = extStaDb_GetStaInfo(vmacSta_p,
										    (IEEEtypes_MacAddr_t *) sta_buf,
										    STADB_DONT_UPDATE_AGINGTIME)) == NULL) {
							printk("error: NO station info found\n");
							break;
						}
						if (memcmp(pStaInfo->Addr, amsducfg.peeraddr, sizeof(amsducfg.peeraddr)) == 0) {
							memcpy(&pStaInfo->aggr11n.amsducfg, &amsducfg, sizeof(amsducfg_t));
							break;
						}
						sta_buf += sizeof(STA_INFO);
					}
					wl_kfree(sta_buf);
					if (i >= entries) {
						printk(MACSTR ", not found\n", MAC2STR(amsducfg.peeraddr));
						break;
					}
					printk(MACSTR ", amsducfg, enable: %u, tids: 0x%x, size: %u\n",
					       MAC2STR(amsducfg.peeraddr), amsducfg.amsduCfgEnable, amsducfg.priority_aggr, amsducfg.size);
				} else {
					memcpy(&master->amsducfg, &amsducfg, sizeof(amsducfg_t));
					printk("amsducfg for all STAs, enable: %u, tids: 0x%x, size: %u\n",
					       master->amsducfg.amsduCfgEnable, master->amsducfg.priority_aggr, master->amsducfg.size);
				}
				wlFwNewDP_amsducfg(netdev, &amsducfg);
			} else if ((strcmp(param[0], "getamsducfg") == 0)) {
				//usage: getamsducfg client_addr
				//cliend addr: connected STA in getstalist/ffffffffffff
				//ex: iwpriv wdev0ap0 setcmd "getamsducfg 42504321bc2f"
				u32 entries, i;
				vmacApInfo_t *master = NULL;
				unsigned char all_sta[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
				extStaDb_StaInfo_t *pStaInfo;
				unsigned char sta_addr[6];
				unsigned char *sta_buf = NULL;

				if (input_cnt < 2) {
					printk("Usage: iwpriv wdev0ap0 setcmd \"getamsducfg 42504321bc2f\"\n");
					break;
				}
				if (priv->vmacSta_p->master == NULL)
					master = priv->vmacSta_p;
				else
					master = priv->vmacSta_p->master;
				memset(sta_addr, 0, sizeof(sta_addr));
				getMacFromString(sta_addr, param[1]);
				if (memcmp(sta_addr, all_sta, sizeof(all_sta))) {
					entries = extStaDb_entries(vmacSta_p, 0);
					if (entries == 0) {
						printk("zero station list\n");
						break;
					}
					sta_buf = wl_kmalloc(entries * 64, GFP_KERNEL);
					if (sta_buf == NULL) {
						printk("wl_kmalloc fail\n");
						break;
					}
					extStaDb_list(vmacSta_p, sta_buf, 1);
					for (i = 0; i < entries; i++) {
						if ((pStaInfo = extStaDb_GetStaInfo(vmacSta_p,
										    (IEEEtypes_MacAddr_t *) sta_buf,
										    STADB_DONT_UPDATE_AGINGTIME)) == NULL) {
							printk("error: NO station info found\n");
							break;
						}
						if (memcmp(pStaInfo->Addr, sta_addr, sizeof(sta_addr)) == 0) {
							printk(MACSTR ", amsducfg, tids: 0x%x, size: %u\n",
							       MAC2STR(pStaInfo->Addr),
							       pStaInfo->aggr11n.amsducfg.priority_aggr,
							       pStaInfo->aggr11n.amsducfg.amsduCfgEnable ? pStaInfo->aggr11n.amsducfg.size : *(mib->
																	       mib_amsdutx));
							break;
						}
						sta_buf += sizeof(STA_INFO);
					}
					wl_kfree(sta_buf);
					if (i >= entries) {
						printk(MACSTR ", not found\n", MAC2STR(sta_addr));
						break;
					}
				} else {
					printk("amsducfg for all STAs, tids: 0x%x, size: %u\n",
					       master->amsducfg.priority_aggr,
					       master->amsducfg.amsduCfgEnable ? master->amsducfg.size : *(mib->mib_amsdutx));
				}
			} else if ((strcmp(param[0], "bbdbg") == 0)) {
				// BBP BF debug; Q_dump
				int i, j;
				UINT32 val;
				char out[24 * 4 + 22];

				printk("\nQ_dump...\n");
#ifdef SOC_W906X
				if (param[1][0]) {
					UINT32 client_id = atohex2(param[1]);
					printk("client_id = %u\n", (unsigned int)client_id);
					val = 0x03;
					wlRegBB(netdev, WL_SET, 0x857, (UINT32 *) & val);
					val = 0x4c;
					wlRegBB(netdev, WL_SET, 0x37c, (UINT32 *) & val);
					val = 0x03;
					wlRegBB(netdev, WL_SET, 0x641, (UINT32 *) & val);
					val = 0x03;
					wlRegBB(netdev, WL_SET, 0x859, (UINT32 *) & val);
					val = client_id;
					wlRegBB(netdev, WL_SET, 0x642, (UINT32 *) & val);
				}
#else
				if (param[1]) {
					UINT32 client_id = atohex2(param[1]);
					printk("client_id = %u\n", (unsigned int)client_id);
					val = 0x03;
					wlRegBB(netdev, WL_SET, 0x857, (UINT32 *) & val);
					val = 0x4c;
					wlRegBB(netdev, WL_SET, 0x37c, (UINT32 *) & val);
					val = 0x01;
					wlRegBB(netdev, WL_SET, 0x641, (UINT32 *) & val);
					val = 0x00;
					wlRegBB(netdev, WL_SET, 0x859, (UINT32 *) & val);
					val = client_id;
					wlRegBB(netdev, WL_SET, 0x642, (UINT32 *) & val);
				}
#endif
				for (i = 0; i < 244; i++) {
					wlRegBB(netdev, WL_SET, 0x643, (UINT32 *) & i);
					val = 0x21;
					wlRegBB(netdev, WL_SET, 0x641, &val);
					val = 0x01;
					wlRegBB(netdev, WL_SET, 0x641, &val);
					//printk("tone %3d, byte23..0:",i);
					sprintf(out, "tone %3d, byte23..0:", i);
					for (j = 23; j >= 0; j--) {
						wlRegBB(netdev, WL_SET, 0x644, (UINT32 *) & j);
						wlRegBB(netdev, WL_GET, 0x646, &val);
						sprintf(&out[20 + (23 - j) * 3], " %2x", (unsigned int)val);
						//printk(" %x", val);
					}
					printk("%s \n", out);
				}
				/* disabe test mode */
				val = 0x00;
				wlRegBB(netdev, WL_SET, 0x641, (UINT32 *) & val);
			} else if ((strcmp(param[0], "mu_sm_cache") == 0)) {
				// BBP MU SM cache
				int i, j;
				UINT32 val;
				char *out;

				out = wl_vzalloc(32 * 4 + 22);
				if (!out) {
					rc = -ENOMEM;
					break;
				}

				printk("\nmu sm cache dump...\n");
				val = 0x03;
				wlRegBB(netdev, WL_SET, 0x857, (UINT32 *) & val);
				val = 0x4c;
				wlRegBB(netdev, WL_SET, 0x37c, (UINT32 *) & val);
				//Enable True ID (0x641[1])
				val = 0x2;
				wlRegBB(netdev, WL_SET, 0x641, (UINT32 *) & val);
				if (param[1][0]) {
					UINT32 client_id = atohex2(param[1]) & 0xFF;
					val = client_id;
				} else {
					val = 0x1;
				}
				wlRegBB(netdev, WL_SET, 0x642, (UINT32 *) & val);
				// Readback
				wlRegBB(netdev, WL_GET, 0x642, &val);
				printk("\nClient ID is: %x\n", (unsigned int)val);
				val = 0x0;
				wlRegBB(netdev, WL_SET, 0x643, (UINT32 *) & val);

				// Read back the header first
				val = 0x04;
				wlRegBB(netdev, WL_SET, 0x859, (UINT32 *) & val);

				for (i = 0; i < 1; i++) {
					wlRegBB(netdev, WL_SET, 0x643, (UINT32 *) & i);
					//Enable True ID (0x641[1])
					val = 0x23;
					wlRegBB(netdev, WL_SET, 0x641, &val);
					//Enable True ID (0x641[1])
					val = 0x03;
					wlRegBB(netdev, WL_SET, 0x641, &val);
					sprintf(out, "Header  , byte15..0:");
					for (j = 15; j >= 0; j--) {
						wlRegBB(netdev, WL_SET, 0x644, (UINT32 *) & j);
						wlRegBB(netdev, WL_GET, 0x646, &val);
						sprintf(&out[20 + (15 - j) * 3], " %2x", (unsigned int)val);
					}
					printk("%s \n\n", out);
				}

				// Read back the tones
				val = 0x03;
				wlRegBB(netdev, WL_SET, 0x859, (UINT32 *) & val);

				for (i = 0; i < 244; i++) {
					wlRegBB(netdev, WL_SET, 0x643, (UINT32 *) & i);
					//Enable True ID (0x641[1])
					val = 0x23;
					wlRegBB(netdev, WL_SET, 0x641, &val);
					//Enable True ID (0x641[1])
					val = 0x03;
					wlRegBB(netdev, WL_SET, 0x641, &val);
					sprintf(out, "Tone %3d, byte31..0:", i);
					for (j = 31; j >= 0; j--) {
						wlRegBB(netdev, WL_SET, 0x644, (UINT32 *) & j);
						wlRegBB(netdev, WL_GET, 0x646, &val);
						sprintf(&out[20 + (31 - j) * 3], " %2x", (unsigned int)val);
					}
					printk("%s \n", out);
				}
				/* disabe test mode */
				val = 0x00;
				wlRegBB(netdev, WL_SET, 0x641, (UINT32 *) & val);
				wl_vfree(out);
			} else if ((strcmp(param[0], "sku") == 0)) {
				UINT32 sku;

				sku = atohex2(param[1]);
				wlFwNewDP_set_sku(netdev, sku);
			} else if ((strcmp(param[0], "rxantbitmap") == 0)) {
				UINT32 bitmap;
				UINT8 max_antenna_bitmap = 0x0;
				if (priv->devid == SC5) {
					max_antenna_bitmap = 0xff;
				} else {
					max_antenna_bitmap = 0xf;
				}
				if (param[1][0]) {
					bitmap = atohex2(param[1]);
					if (bitmap > max_antenna_bitmap) {
						rc = -EOPNOTSUPP;
						break;
					}
					*(mib->mib_rxAntBitmap) = (UCHAR) (bitmap & 0xff);
					*(mib->mib_rxAntenna) = countNumOnes((bitmap & 0xff));
				} else {
					printk("rxantbitmap: %x\n", *(mib->mib_rxAntBitmap));
				}
			} else if (strcmp(param[0], "retrycfgenable") == 0) {
				UINT8 Enable;
				Enable = atoi(param[1]);
				printk("Set %s retrycfgenable= %x\n", netdev->name, Enable);
				priv->retrycfgenable = Enable;
			} else if ((strcmp(param[0], "retrycfg") == 0)) {
				UINT8 i;
				//                                        BK BE VI VO
				//iwpriv wdev0ap0 setcmd "retrycfg legacy 32 32 64 32"
				//iwpriv wdev0ap0 setcmd "retrycfg 11n 32 32 64 32"
				//iwpriv wdev0ap0 setcmd "retrycfg 11ac 32 32 64 32"
				//
				//printk(" vap name %s \n", netdev->name);
				if ((strcmp(param[1], "legacy") == 0)) {
					for (i = 0; i < 4; i++) {
						priv->retrycfgVAP.RetryLegacy[i] = atoi(param[2 + i]);
						printk(" legacy retry cnt %d \n", priv->retrycfgVAP.RetryLegacy[i]);
					}
				} else if ((strcmp(param[1], "11n") == 0)) {
					for (i = 0; i < 4; i++) {
						priv->retrycfgVAP.Retry11n[i] = atoi(param[2 + i]);
						printk(" 11n retry cnt %d \n", priv->retrycfgVAP.Retry11n[i]);
					}

				} else if ((strcmp(param[1], "11ac") == 0)) {
					for (i = 0; i < 4; i++) {
						priv->retrycfgVAP.Retry11ac[i] = atoi(param[2 + i]);
						printk(" 11ac retry cnt %d \n", priv->retrycfgVAP.Retry11ac[i]);
					}
				}
			} else if ((strcmp(param[0], "radioratescfg") == 0)) {
				MIB_STA_CFG *mib_StaCfg;
				mib_StaCfg = mib->StationConfig;

				//HT:
				//0x12: bit0-bit7, 0x34: bit8-bit15, 0x56: bit16-bit23
				//example:
				//iwpriv wdev0ap0 setcmd "radioratescfg HT 0x12 0x34 0x56"

				//VHT:
				//0xffea: TxMCS MAP, bit0-bit15
				//example:
				//iwpriv wdev0ap0 setcmd "radioratescfg VHT 0xffea"

				printk(" vap name %s \n", netdev->name);
				if ((strcmp(param[1], "HT") == 0)) {
					mib_StaCfg->SupportedTxHtMCScfg.SupportedTxHtMCSset_0 = atohex2(param[2]);
					mib_StaCfg->SupportedTxHtMCScfg.SupportedTxHtMCSset_1 = atohex2(param[3]);
					mib_StaCfg->SupportedTxHtMCScfg.SupportedTxHtMCSset_2 = atohex2(param[4]);

				} else if ((strcmp(param[1], "VHT") == 0)) {
					mib_StaCfg->SupportedTxVhtMcsSet = atohex2(param[2]);
					printk("VHT radio rates 0x%X \n", (unsigned int)mib_StaCfg->SupportedTxVhtMcsSet);
#ifdef SOC_W906X
				} else if ((strcmp(param[1], "HE") == 0)) {
					mib_StaCfg->supoorted_tx_he_80m_mcs_set = atohex2(param[2]);
					mib_StaCfg->supoorted_tx_he_160m_mcs_set = atohex2(param[3]);
					mib_StaCfg->supoorted_tx_he_80p80m_mcs_set = atohex2(param[4]);
					printk("HE radio rates 0x%X 0x%X 0x%X\n",
					       (unsigned int)mib_StaCfg->supoorted_tx_he_80m_mcs_set,
					       (unsigned int)mib_StaCfg->supoorted_tx_he_160m_mcs_set,
					       (unsigned int)mib_StaCfg->supoorted_tx_he_80p80m_mcs_set);
				} else if ((strcmp(param[1], "HERX") == 0)) {	/* Added for WFA 11ax test HE-4.31.1 */
					mib_StaCfg->supoorted_rx_he_80m_mcs_set = atohex2(param[2]);
					mib_StaCfg->supoorted_rx_he_160m_mcs_set = atohex2(param[3]);
					mib_StaCfg->supoorted_rx_he_80p80m_mcs_set = atohex2(param[4]);
					printk("HE RX radio rates 0x%X 0x%X 0x%X\n",
					       (unsigned int)mib_StaCfg->supoorted_rx_he_80m_mcs_set,
					       (unsigned int)mib_StaCfg->supoorted_rx_he_160m_mcs_set,
					       (unsigned int)mib_StaCfg->supoorted_rx_he_80p80m_mcs_set);
#endif
				} else {
					printk("unknown mode \n");
				}
			} else if ((strcmp(param[0], "eewr") == 0)) {
				struct file *filp = NULL;
				UINT32 NumOfEntry = 0, len = 0, i = 0;
				char *data = NULL;
				UINT32 offset;
				//eewr offset len eeprom.conf
				//ex: iwpriv wdev0 setcmd "eewr 0x1234  0x20 /demo/eeprom_out.conf"
				offset = atohex2(param[1]);
				NumOfEntry = atohex2(param[2]);
				filp = filp_open(param[3], O_RDONLY, 0);
				data = (char *)wl_kmalloc_autogfp(NumOfEntry);
				if (!IS_ERR(filp)) {
					for (i = 0; i < NumOfEntry; i++) {
						len = kernel_read(filp, &data[i], 0x01, &filp->f_pos);
						if (len == 0) {
							//printk("kernel_read fail  \n");
							break;
						}

					}
					eepromAction(netdev, offset, data, NumOfEntry, 1);	//write
					if (data != NULL)
						wl_kfree(data);
					filp_close(filp, current->files);
				} else {
					if (data)
						wl_kfree(data);
					printk("open <%s>: FAIL\n", param[2]);
					break;
				}

			} else if ((strcmp(param[0], "eerd") == 0)) {
				struct file *filp_eeprom = NULL;
				UINT32 NumOfEntry, offset;
				char *data = NULL;

				//eerd offset len eeprom_out.conf
				//ex: iwpriv wdev0 setcmd "eerd 0x1234 0x100 /demo/eeprom_out.conf"
				offset = atohex2(param[1]);
				NumOfEntry = atohex2(param[2]);
				filp_eeprom = filp_open(param[3], O_RDWR | O_CREAT | O_TRUNC, 0);
				if (!IS_ERR(filp_eeprom)) {
					data = (char *)wl_kmalloc_autogfp(NumOfEntry);
					eepromAction(netdev, offset, data, NumOfEntry, 0);	//read
					__kernel_write(filp_eeprom, data, NumOfEntry, &filp_eeprom->f_pos);
					filp_close(filp_eeprom, current->files);
				} else {
					printk(".conf open <%s>: FAIL\n", param[3]);
					break;
				}

				if (data != NULL)
					wl_kfree(data);
			} else if ((strcmp(param[0], "eepromaccess") == 0)) {
				UINT32 action;

				action = atohex2(param[1]);	//1:lock, 0:unlock
				wlFwNewDP_EEPROM_access(netdev, action);
			} else if ((strcmp(param[0], "memdump_ddr") == 0)) {
				if (input_cnt == 3) {
					struct file *filp_DDR_Data = NULL;
					UINT8 *DDR_Virtual_Addr = NULL;
					UINT32 SizeInDw = 0;

					DDR_Virtual_Addr = (UINT8 *) atohex2(param[1]);
					SizeInDw = atohex2(param[2]);

					filp_DDR_Data = filp_open("/tmp/DDR_Data_Output.bin", O_RDWR | O_CREAT | O_TRUNC, 0);
					if (!IS_ERR(filp_DDR_Data)) {
						__kernel_write(filp_DDR_Data, (UINT8 *) DDR_Virtual_Addr, (SizeInDw * 4), &filp_DDR_Data->f_pos);	// Use virtual address instead of physical address
						filp_close(filp_DDR_Data, current->files);
						printk("DDR Data saved to /tmp/DDR_Data_Output.bin!\n");
					} else {
						printk("Error opening /tmp/DDR_Data_Output.bin!\n");
					}
				} else {
					printk("Usage: memdump_ddr <Virtual Address 0x> <# of DWORDS>\n");
				}
			} else if ((strcmp(param[0], "offchpwr") == 0)) {
				SINT8 pwr;
				UINT8 bitmap;
				UINT8 channel;

				pwr = (SINT8) atoi_2(param[1]);
				bitmap = atoi(param[2]);
				channel = atoi(param[3]);
				wlFwNewDP_Set_Offchanpwr(netdev, pwr, bitmap, channel);

			} else if (strcmp(param[0], "wdevreset") == 0) {
#ifdef SOC_W906X
				/* wdevreset 1/2/3 , 1 STA Only FW, 2 AP Only FW, 3 both AP & STA FW */
				reset_mode = 3;
				if (param[1] != NULL) {
					reset_mode = atoi(param[1]);
					printk("reset_mode = %u\n", reset_mode);
				}
#endif
				mwl_drv_set_wdevReset(netdev);
				break;
			}
			/*For WiFi usage: To set group bit in TA in NDPA and use 6Mbps */
			else if (strcmp(param[0], "ndpa_useta") == 0) {
				UINT32 mode = 0;

				mode = atoi(param[1]);

				if (mode == 2) {
					printk("TA grp bit not set, use 6Mbps\n");
				} else if (mode == 1)
					printk("TA grp bit is set, use 6Mbps\n");
				else {
					mode = 0;
					printk("Back to default: TA grp bit not set, not using 6Mbps\n");
				}
				wlFwNewDP_NDPA_UseTA(netdev, mode);
				break;
			} else if ((strcmp(param[0], "radio_status") == 0)) {
				mvl_status_t tmp_status;
				struct wlprivate *wlpptr;
				u32 numVif = priv->wlpd_p->NumOfAPs + 1;	/* VAP + STA */
				u16 i;
				time64_t t = 0;

				if (priv->wlpd_p->privNdevStats.ch_start_time_sec)
					t = ktime_get_seconds() - priv->wlpd_p->privNdevStats.ch_start_time_sec;

				if (priv->master)
					wlpptr = NETDEV_PRIV_P(struct wlprivate, priv->master);
				else
					wlpptr = priv;

				for (i = 0; i < numVif; i++) {
					if (wlpptr->vdev[i] != NULL)
						calculate_err_count(wlpptr->vdev[i]);
				}

				memset(&tmp_status, 0, sizeof(tmp_status));
				wlFwGetRadioStatus(netdev, &tmp_status);
				printk("============================\n");
				printk("noise:           \t-%d\tANPI index %u\n", tmp_status.noise, ap8x_anpi_conversion(tmp_status.noise));
				printk("noiseavg:        \t-%d\n", tmp_status.noiseavg);
				printk("noisemax:        \t-%d\n", tmp_status.noisemax);
				printk("load:            \t%d (percentages)\n", tmp_status.load);
				printk("rxload:          \t%d (percentages)\n", tmp_status.rxload);
				printk("rx_local_ch_util:\t0 (percentages)\n");
				printk("rx_non-local_ch_util:\t0 (percentages)\n");
				printk("tx_ch_util:      \t%d (percentages)\n", tmp_status.total_load - tmp_status.rxload);
				printk("total_ch_util:      \t%d (percentages)\n", tmp_status.total_load);
				printk("host_timestamp:  \t%d (us)\n", tmp_status.host_timestamp);
				printk("temperature:     \t%d (deg C)\n", (tmp_status.temperature * 4935 - 2271500) / 10000);
				printk("cca_block:       \t%d (percentages)\n", tmp_status.cca_block);
				printk("nav_block:       \t%d (percentages)\n", tmp_status.nav_block);
				printk("avail_slot_cnt:  \t%d\n", tmp_status.avail_slot_cnt);
				printk("tx_retries_cnt:  \t%lu\n", priv->wlpd_p->privNdevStats.tx_retries);
				printk("time_since_ch_change:\t%lld\n", t);
				printk("ch_change_count: \t%u\n", priv->wlpd_p->privNdevStats.ch_change_count);
				break;
			}
#ifdef IEEE80211K
			else if ((strcmp(param[0], "sendbcnreport") == 0)) {
				UINT8 bssid[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
				UINT8 stamac[6];
				IEEEtypes_SsId_t ssid;
				UINT8 RegDomain, ch;
				UINT8 RandInt, MeasDur, MeasMode;
				UINT8 ReportDetail, MeasDurMand;
				UINT8 VoWiFi_case;
				UINT16 ReportCond;

				if (!*(mib->mib_rrm)) {
					printk("RRM is not enabled ...\n");
					return rc;
				}

				memset(ssid, 0, sizeof(IEEEtypes_SsId_t));
				getMacFromString(stamac, param[1]);
				printk("stamac=%02x:%02x:%02x:%02x:%02x:%02x\n", stamac[0], stamac[1], stamac[2], stamac[3], stamac[4], stamac[5]);

				RegDomain = atoi(param[2]);
				ch = atoi(param[3]);
				RandInt = atoi(param[4]);
				MeasDur = atoi(param[5]);
				MeasMode = atoi(param[6]);
				memcpy(ssid, param[7], strlen(param[7]) < IEEEtypes_SSID_SIZE ? strlen(param[7]) : IEEEtypes_SSID_SIZE);
				ReportCond = atoi(param[8]);
				ReportDetail = atoi(param[9]);
				MeasDurMand = atoi(param[10]);
				VoWiFi_case = atoi(param[11]);

				printk("regdom=%d\n", RegDomain);
				printk("ch=%d\n", ch);
				printk("RandInt=%d\n", RandInt);
				printk("MeasDur=%d\n", MeasDur);
				printk("MeasMode=%d\n", MeasMode);
				printk("ssid=%s\n", ssid);
				printk("ReportCond=%d, %s\n", ReportCond, param[8]);
				printk("ReportDetail=%d\n", ReportDetail);
				printk("MeasDurMand=%d\n", MeasDurMand);

				macMgmtMlme_RmBeaconRequest(netdev,
							    stamac,
							    bssid,
							    RegDomain,
							    ch, RandInt, MeasDur, MeasMode, ssid, ReportCond, ReportDetail, MeasDurMand, VoWiFi_case);
			} else if ((strcmp(param[0], "getnlist") == 0)) {
				MSAN_neighbor_dump_list(netdev, NULL, param[1], param[2]);
			} else if ((strcmp(param[0], "nlistcfg") == 0)) {
				UINT8 nap_bssid[6];
				UINT16 cap;
				UINT8 reach, sec, key_scop, mobility_do, ht, vht;
				UINT8 reg_class, chan, phy_type;
				neighbor_list_entrie_t nlist;

				if (strcmp(param[1], "help") == 0) {
					printk("Usage: nlistcfg -c\n");
					printk("	-c  -- clear all nighbor list database\n");
					printk
					    ("Usage: nlistcfg <mac addr> <AP Reachability> <Security> <Key Scope> <Capabilities> <Mobility Domain> <HT> <VHT> <Reg Class> <channel> <Phy type>\n");
					printk
					    ("	<AP Reachability> whether the AP identified by this BSSID is reachable by the STA.(1:Not Reachable, 2:Unknown, 3:Reachable)\n");
					printk
					    ("	<Security> this BSSID supports the same security provisioning as used by the STA in its current association.\n");
					printk("	<Key Scope> this BSSID has the same authenticator as the AP sending the report.\n");
					return FALSE;
				} else if (strcmp(param[1], "-c") == 0) {
					MSAN_clean_nb_list_All(netdev);
					return FALSE;
				}
				memset(&nlist, 0, sizeof(struct neighbor_list_entrie_t));

				getMacFromString(nap_bssid, param[1]);
				printk("stamac=%02x:%02x:%02x:%02x:%02x:%02x\n",
				       nap_bssid[0], nap_bssid[1], nap_bssid[2], nap_bssid[3], nap_bssid[4], nap_bssid[5]);

				reach = (UINT8) atoi(param[2]);
				sec = (UINT8) atoi(param[3]);
				key_scop = (UINT8) atoi(param[4]);
				cap = (UINT16) atoi(param[5]);
				mobility_do = (UINT8) atoi(param[6]);
				ht = (UINT8) atoi(param[7]);
				vht = (UINT8) atoi(param[8]);
				reg_class = (UINT8) atoi(param[9]);
				chan = (UINT8) atoi(param[10]);
				phy_type = (UINT8) atoi(param[11]);

				nlist.ssid_len = strlen(&(mib->StationConfig->DesiredSsId[0]));
				memcpy(nlist.SsId, &(mib->StationConfig->DesiredSsId[0]), nlist.ssid_len);
				memcpy(nlist.bssid, nap_bssid, 6);
				nlist.bssid_info.ApReachability = reach & 0x3;
				nlist.bssid_info.Security = sec & 1;
				nlist.bssid_info.KeyScope = key_scop & 1;
				nlist.bssid_info.Capa_SpectrumMgmt = cap & 1;
				nlist.bssid_info.Capa_QoS = (cap >> 1) & 1;
				nlist.bssid_info.Capa_APSD = (cap >> 2) & 1;
				nlist.bssid_info.Capa_Rrm = (cap >> 3) & 1;
				nlist.bssid_info.Capa_DBlckAck = (cap >> 4) & 1;
				nlist.bssid_info.Capa_IBlckAck = (cap >> 5) & 1;
				nlist.bssid_info.MobilityDomain = mobility_do & 1;
				nlist.bssid_info.HT = ht & 1;
				nlist.bssid_info.VHT = vht & 1;
				nlist.reg_class = (reg_class > 0) ? reg_class : getRegulatoryClass(vmacSta_p);
				nlist.chan = chan;
				nlist.phy_type = phy_type;
				nlist.time_stamp = ktime_to_timespec(ktime_get_real()).tv_sec;
				printk("ssid=%s\n", nlist.SsId);
				printk("reach=%d\n", reach);
				printk("sec=%d\n", sec);
				printk("key_scop=%d\n", key_scop);
				printk("cap=%d\n", cap);
				printk("mobil=%d\n", mobility_do);
				printk("ht=%d\n", ht);
				printk("vht=%d\n", vht);
				printk("reg_class=%d\n", reg_class);
				printk("chan=%d\n", chan);
				printk("phy_type=%d\n", phy_type);

				MSAN_neighbor_add(netdev, &nlist, NULL, 0);
			} else if ((strcmp(param[0], "sendnlistrep") == 0)) {
#include "macmgmtap.h"
				macmgmtQ_MgmtMsg2_t *MgmtResp_p;
				struct IEEEtypes_Neighbor_Report_Element_t *NeighborRpt_Element;
				struct sk_buff *skb;
				IEEEtypes_MacAddr_t destaddr;
				extern struct sk_buff *mlmeApiPrepMgtMsg2(UINT32 Subtype,
									  IEEEtypes_MacAddr_t * DestAddr, IEEEtypes_MacAddr_t * SrcAddr, UINT16 size);

				neighbor_list_entrie_t *nlist = &wlpd_p->nb_info.nb_list[0];

				if (!*(mib->mib_rrm)) {
					printk("RRM is not enabled ...\n");
					return rc;
				}

				getMacFromString(destaddr, param[1]);
				printk("destaddr=%02x:%02x:%02x:%02x:%02x:%02x\n",
				       destaddr[0], destaddr[1], destaddr[2], destaddr[3], destaddr[4], destaddr[5]);

				if ((skb = mlmeApiPrepMgtMsg2(IEEE_MSG_QOS_ACTION, &destaddr, &vmacSta_p->VMacEntry.vmacAddr, 3 + 2 + 13))
				    == NULL) {
					printk("Failed to allocate buffer ...\n");
					return FALSE;
				}
				MgmtResp_p = (macmgmtQ_MgmtMsg2_t *) skb->data;
				MgmtResp_p->Body.Action.Category = AC_RADIO_MEASUREMENT;
				MgmtResp_p->Body.Action.Action = AF_RM_NEIGHBOR_RESPONSE;
				MgmtResp_p->Body.Action.DialogToken = 1;
				NeighborRpt_Element = (struct IEEEtypes_Neighbor_Report_Element_t *)
				    &MgmtResp_p->Body.Action.Data;
				NeighborRpt_Element->ElementId = NEIGHBOR_REPORT;
				NeighborRpt_Element->Len = sizeof(struct IEEEtypes_Neighbor_Report_Element_t) - 2;	//no optional subelem for now.
				memcpy(NeighborRpt_Element->Bssid, nlist->bssid, 6);
				NeighborRpt_Element->BssidInfo.ApReachability = nlist->bssid_info.ApReachability;
				NeighborRpt_Element->BssidInfo.Security = nlist->bssid_info.Security;
				NeighborRpt_Element->BssidInfo.KeyScope = nlist->bssid_info.KeyScope;
				NeighborRpt_Element->BssidInfo = nlist->bssid_info;
				NeighborRpt_Element->RegulatoryClass = nlist->reg_class;
				NeighborRpt_Element->Channel = nlist->chan;
				NeighborRpt_Element->PhyType = nlist->phy_type;

				if (txMgmtMsg(vmacSta_p->dev, skb) != OS_SUCCESS) {
					wl_free_skb(skb);
					return FALSE;
				}
			} else if ((strcmp(param[0], "quiet") == 0)) {
				UINT8 enable;
				UINT8 period;
				UINT16 duration;
				UINT16 offset;
				UINT16 offset1;
				UINT8 txStop_en;

				if (strcmp(param[1], "help") == 0) {
					printk("Usage: quiet <enable/disable> <period> <duration> <offset> <offset1> <txStop_en>\n");
					return FALSE;
				}
				enable = (UINT8) atoi(param[1]);
				period = (UINT8) atoi(param[2]);
				duration = (UINT16) atoi(param[3]);
				offset = (UINT16) atoi(param[4]);
				offset1 = (UINT16) atoi(param[5]);
				txStop_en = (UINT8) atoi(param[6]);
#if 1
				if (enable) {
					if ((period == 0) || (duration == 0) || (offset == 0)) {
						printk("Usage: quiet <enable/disable> <period> <duration> <offset> <offset1> <txStop_en>\n");
						return FALSE;
					}
				}

				wlFwSetQuiet(netdev, enable, period, duration, offset, offset1, txStop_en);
#else
				if (enable) {
					IEEEtypes_QuietElement_t QuietIE;

					memset(&QuietIE, 0, sizeof(struct IEEEtypes_QuietElement_t));
					QuietIE.ElementId = QUIET;
					QuietIE.Duration = (u16) atoi(param[2]);
					QuietIE.Len = 6;
					bcngen_AddQuiet_IE(vmacSta_p, &QuietIE);
				} else {
					bcngen_RemoveQuiet_IE(vmacSta_p);
				}
#endif
				*(mib->mib_quiet) = enable;
			} else if ((strcmp(param[0], "quiet_dbg") == 0)) {
				struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);

				printk("txStop = 0x%08x, bcnStop = 0x%08x, opMode = 0x%08x\n",
				       ((SMAC_CTRL_BLK_st *) wlpptr->ioBase0)->config.txStop,
				       ((SMAC_CTRL_BLK_st *) wlpptr->ioBase0)->config.bcnStop, ((SMAC_CTRL_BLK_st *) wlpptr->ioBase0)->config.opMode);
				printk("quiet_dbg[] = %d\n", quiet_dbg[0]);
				break;
			}
#endif				/* IEEE80211K */
#ifdef AP_STEERING_SUPPORT
#ifdef IEEE80211K
			else if (strcmp(param[0], IW_UTILITY_SET_AP_STEER_ENABLE) == 0) {
				macMgmtMlme_AssocDenied(IEEEtypes_STATUS_ASSOC_DENIED_BUSY);
			} else if (strcmp(param[0], IW_UTILITY_SET_AP_STEER_DISABLE) == 0) {
				macMgmtMlme_AssocDenied(IEEEtypes_STATUS_SUCCESS);
			} else if (strcmp(param[0], IW_UTILITY_SET_BTM_REQUEST) == 0) {
				struct IEEEtypes_BSS_TM_Request_t BSS_TM_Req;
				extStaDb_StaInfo_t *pStaInfo;
				UINT32 entries, i;
				UINT8 destaddr[6];
				UINT8 *staBuf = NULL;
				UINT8 *listBuf = NULL;

				if (strcmp(param[1], "help") == 0) {
					printk
					    ("Usage: btmreq <sta mac> <Abridged> <DisassocImm> <BSSTermiInc> <ESSDisassocImm> <disassoc_timer> <validity_interval>\n");
					return FALSE;
				}

				sscanf(param[1], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &destaddr[0],
				       &destaddr[1], &destaddr[2], &destaddr[3], &destaddr[4], &destaddr[5]);

				entries = extStaDb_entries(vmacSta_p, 0);
				staBuf = wl_kmalloc(entries * sizeof(STA_INFO), GFP_KERNEL);
				if (staBuf != NULL) {
					extStaDb_list(vmacSta_p, staBuf, 1);
					if (entries) {
						listBuf = staBuf;

						for (i = 0; i < entries; i++) {
							if (!memcmp(listBuf, destaddr, IEEEtypes_ADDRESS_SIZE)) {
								if ((pStaInfo =
								     extStaDb_GetStaInfo(vmacSta_p, (IEEEtypes_MacAddr_t *) listBuf,
											 STADB_DONT_UPDATE_AGINGTIME)) != NULL) {
									pStaInfo->btmreq_count++;
								}
								break;
							}
							listBuf += sizeof(STA_INFO);
						}
					}
					wl_kfree(staBuf);
				}

				memset(&BSS_TM_Req, 0, sizeof(struct IEEEtypes_BSS_TM_Request_t));
				if (strlen(param[2]) == 0) {
					BSS_TM_Req.DisassocImm = mib->mib_BSSTMRequest->DisassocImm;
					BSS_TM_Req.disassoc_timer = mib->mib_BSSTMRequest->disassoc_timer;
					BSS_TM_Req.validity_interval = mib->mib_BSSTMRequest->validity_interval;
				} else {
					BSS_TM_Req.Abridged = atoi(param[2]);
					BSS_TM_Req.DisassocImm = atoi(param[3]);
					BSS_TM_Req.BSSTermiInc = atoi(param[4]);
					BSS_TM_Req.ESSDisassocImm = atoi(param[5]);
					BSS_TM_Req.disassoc_timer = atoi(param[6]);
					BSS_TM_Req.validity_interval = atoi(param[7]);
				}
				if (wlpd_p->nb_info.nb_elem_number == 0) {
					MSAN_get_neighbor_bySSID(vmacSta_p->dev, &vmacSta_p->macSsId);
				}
				if (bsstm_send_request(netdev, destaddr, &BSS_TM_Req) == FALSE) {
					rc = -EFAULT;
				}
			} else if (strcmp(param[0], IW_UTILITY_SET_BTM_RSSI_THRESHOLD) == 0) {
				mib->mib_BTM_rssi_low = atoi(param[1]);
				mib->mib_BTM_rssi_high = atoi(param[2]);
			} else if (strcmp(param[0], IW_UTILITY_SET_BTM_REQUEST_FOR_WTS) == 0) {
				struct IEEEtypes_BSS_TM_Request_t BSS_TM_Req;
				extStaDb_StaInfo_t *pStaInfo;
				UINT32 entries, i;
				UINT8 destaddr[6];
				UINT8 targetaddr[6];
				UINT8 *staBuf = NULL;
				UINT8 *listBuf = NULL;
				UINT8 BssTM_status = 0;

				if (strcmp(param[1], "help") == 0) {
					printk
					    ("Usage: wts_btmreq <sta mac> <target addr> <abridged> <Disassoc Imm> <BSS Term> <ESS Disassoc Imm> <Disassoc Timer>\n");
					return FALSE;
				}

				sscanf(param[1], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &destaddr[0],
				       &destaddr[1], &destaddr[2], &destaddr[3], &destaddr[4], &destaddr[5]);

				sscanf(param[2], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &targetaddr[0],
				       &targetaddr[1], &targetaddr[2], &targetaddr[3], &targetaddr[4], &targetaddr[5]);

				entries = extStaDb_entries(vmacSta_p, 0);
				staBuf = wl_kmalloc(entries * sizeof(STA_INFO), GFP_KERNEL);
				if (staBuf != NULL) {
					extStaDb_list(vmacSta_p, staBuf, 1);
					if (entries) {
						listBuf = staBuf;

						for (i = 0; i < entries; i++) {
							if (!memcmp(listBuf, destaddr, IEEEtypes_ADDRESS_SIZE)) {
								if ((pStaInfo =
								     extStaDb_GetStaInfo(vmacSta_p, (IEEEtypes_MacAddr_t *) listBuf,
											 STADB_DONT_UPDATE_AGINGTIME)) != NULL) {
									if (pStaInfo->ExtCapElem.ElementId == EXT_CAP_IE) {
										pStaInfo->btmreq_count++;
										BssTM_status = pStaInfo->ExtCapElem.ExtCap.BSSTransition;
									}
								}
								break;
							}
							listBuf += sizeof(STA_INFO);
						}
					}
					wl_kfree(staBuf);
				}
				printk("WTS_BTM send request, status:%d\n", BssTM_status);
				if (BssTM_status == 0) {
					/* STA not support, disassoc it! */
#ifndef MULTI_AP_SUPPORT
					macMgmtMlme_SendDisassociateMsg(vmacSta_p, (IEEEtypes_MacAddr_t *) destaddr, 0,
									IEEEtypes_REASON_DISASSOC_AP_BUSY);
#else
					macMgmtMlme_SendDisassociateMsg4MAP(vmacSta_p, (IEEEtypes_MacAddr_t *) destaddr, 0,
									    IEEEtypes_REASON_DISASSOC_AP_BUSY);
#endif
				} else {
					UINT8 preferred_list = 0;

					MSAN_clean_neighbor_list(netdev);
					preferred_list = MSAN_get_neighbor_byAddr(netdev, (IEEEtypes_MacAddr_t *) targetaddr);
					memset(&BSS_TM_Req, 0, sizeof(struct IEEEtypes_BSS_TM_Request_t));
					BSS_TM_Req.Abridged = atoi(param[3]);
					BSS_TM_Req.DisassocImm = atoi(param[4]);
					BSS_TM_Req.BSSTermiInc = atoi(param[5]);
					BSS_TM_Req.ESSDisassocImm = atoi(param[6]);
					BSS_TM_Req.disassoc_timer = atoi(param[7]);
					BSS_TM_Req.validity_interval = mib->mib_BSSTMRequest->validity_interval;
					if (bsstm_send_request(netdev, destaddr, &BSS_TM_Req) == FALSE) {
						rc = -EFAULT;
					}
				}
			} else if (strcmp(param[0], "config_btmreq") == 0) {
				MIB_802DOT11 *mib1 = vmacSta_p->Mib802dot11;

				if (strcmp(param[1], "help") == 0) {
					printk
					    ("Usage: config_btmreq <abridged> <Disassoc Imm> <BSS Term> <ESS Disassoc Imm> <Disassoc Timer> <Validity Interval>\n");
					return FALSE;
				}

				mib->mib_BSSTMRequest->Abridged = atoi(param[1]);
				mib->mib_BSSTMRequest->DisassocImm = atoi(param[2]);
				mib->mib_BSSTMRequest->BSSTermiInc = atoi(param[3]);
				mib->mib_BSSTMRequest->ESSDisassocImm = atoi(param[4]);
				mib->mib_BSSTMRequest->disassoc_timer = atoi(param[5]);
				mib->mib_BSSTMRequest->validity_interval = atoi(param[6]);

				memcpy(mib1->mib_BSSTMRequest, mib->mib_BSSTMRequest, sizeof(IEEEtypes_BSS_TM_Request_t));
			}
#endif				/* IEEE80211K */
			else if (strcmp(param[0], "sta_btm_enable") == 0) {
				MIB_802DOT11 *mib1 = vmacSta_p->Mib802dot11;;

				*(mib->mib_btm_enabled) = atoi(param[1]) ? 1 : 0;
				*(mib1->mib_btm_enabled) = *(mib->mib_btm_enabled);

				/* update BTM bit in Beacon/Probe Resp */
				wlFwSetIEs(netdev);
			}
#endif				/* AP_STEERING_SUPPORT */
#ifdef MULTI_AP_SUPPORT
			else if (strcmp(param[0], IW_UTILITY_MULTI_AP_ATTR) == 0) {
				MIB_802DOT11 *mib1 = vmacSta_p->Mib802dot11;

				mib->multi_ap_attr = atoi(param[1]);
				mib1->multi_ap_attr = mib->multi_ap_attr;

				printk("IOCTL: multi_ap_attr=0x%02x\n", mib->multi_ap_attr);
			} else if (strcmp(param[0], "eap_rate_fixed") == 0) {
				MIB_802DOT11 *mib1 = vmacSta_p->Mib802dot11;

				*(mib->mib_eap_rate_fixed) = atoi(param[1]);
				*(mib1->mib_eap_rate_fixed) = *(mib->mib_eap_rate_fixed);
				if (*(mib->mib_eap_rate_fixed))
					printk("EAPOL key will be sent by fixed rate.\n");
			} else if (strcmp(param[0], IW_UTILITY_MULTI_AP_VERSION) == 0) {
				MIB_802DOT11 *mib1 = vmacSta_p->Mib802dot11;

				mib->multi_ap_ver = atoi(param[1]);
				mib1->multi_ap_ver = mib->multi_ap_ver;

				printk("IOCTL: multi_ap_ver=0x%02x\n", mib->multi_ap_ver);
			} else if (strcmp(param[0], IW_UTILITY_multi_ap_vid) == 0) {
				MIB_802DOT11 *mib1 = vmacSta_p->Mib802dot11;
				UINT16 multi_ap_vid = atoi(param[1]);

				mib->multi_ap_vid = (UINT16) SHORT_SWAP(multi_ap_vid);
				mib1->multi_ap_vid = mib->multi_ap_vid;

				printk("IOCTL: multi_ap_vid=%d\n", multi_ap_vid);
			} else if ((strcmp(param[0], "unassocsta_offchan_time") == 0)) {
				MIB_802DOT11 *mib1 = vmacSta_p->Mib802dot11;
				UINT32 time_val = atoi(param[1]);

				if (time_val < 5 || time_val > 1000) {
					rc = -EFAULT;
					break;
				}

				*(mib->mib_unassocsta_track_time) = time_val;
				*(mib1->mib_unassocsta_track_time) = *(mib->mib_unassocsta_track_time);

				printk("Set unassocsta offchan time as %d(ms)\n", *(mib->mib_unassocsta_track_time));
			} else if (strcmp(param[0], IW_UTILITY_SET_1905_TLV) == 0) {
				struct MultiAP_TLV_Element_t *map_tlv = (struct MultiAP_TLV_Element_t *)(param_str + strlen(param[0]) + 1);

				MAP_tlv_Query_process(vmacSta_p, map_tlv);
			}
#endif				/* MULTI_AP_SUPPORT */
#ifdef RADAR_SCANNER_SUPPORT
			else if ((strcmp(param[0], "enablescnr") == 0)) {
				UINT8 i, value, max_antenna_bitmap = 0x0;

				if (priv->devid == SC5)
					max_antenna_bitmap = 0xff;
				else
					max_antenna_bitmap = 0xf;

				if (((*(mib->mib_rxAntBitmap) != 0) && (*(mib->mib_rxAntBitmap) != max_antenna_bitmap)) ||
				    ((*(mib->mib_txAntenna) != 0) && (*(mib->mib_txAntenna) != max_antenna_bitmap))) {
					WLDBG_ERROR(DBG_LEVEL_1, "Only support DFS scan with 4x4/8x8 tx/rx antenna(0x%X,0x%X)\n",
						    *(mib->mib_txAntenna), *(mib->mib_rxAntBitmap));
					rc = -EOPNOTSUPP;
					break;
				}
				if (input_cnt == 1) {
					printk("rader scanner mode is %s\n", priv->wlpd_p->ext_scnr_en ? "enable" : "disable");
					break;
				}
				value = atoi(param[1]);
				if (priv->wlpd_p->ext_scnr_en != value) {
#ifdef CONCURRENT_DFS_SUPPORT
					if ((wlpd_p->pdfsApMain != NULL) && (value == 0)) {
						DisarmAuxCACTimer(wlpd_p->pdfsApMain);
						wlpd_p->pdfsApMain->scnr_ctl_evt(netdev, ScnrCtl_Chan_Operational, DFS_STATE_UNKNOWN, 1);
						if ((mib->PhyDSSSTable->Chanflag.radiomode != RADIO_MODE_80p80)
						    && (mib->PhyDSSSTable->Chanflag.ChnlWidth != CH_160_MHz_WIDTH))
							mib->PhyDSSSTable->Chanflag.radiomode = RADIO_MODE_NORMAL;
					}
#endif				/* CONCURRENT_DFS_SUPPORT */
					priv->wlpd_p->ext_scnr_en = value;
				}
#ifdef CONCURRENT_DFS_SUPPORT
				if (priv->wlpd_p->ext_scnr_en == 1) {
					if ((mib->PhyDSSSTable->Chanflag.radiomode == RADIO_MODE_80p80)
					    || (mib->PhyDSSSTable->Chanflag.ChnlWidth == CH_160_MHz_WIDTH)) {
						WLDBG_ERROR(DBG_LEVEL_1,
							    "concurrent DFS mode avoid to run at 80MHZ + 80MHZ mode or 160MHZ badnwith!\n");
						rc = -EOPNOTSUPP;
						break;
					}
					for (i = 0; *param[i + 2] != 0; i++)
						priv->wlpd_p->dfs_ctl_chlist[i] = atoi(param[i + 2]);
				} else {
					memset(priv->wlpd_p->dfs_ctl_chlist, 0, IEEE_80211_MAX_NUMBER_OF_CHANNELS);
					priv->wlpd_p->dfs_ctl_ch_index = 0;
				}
#endif				/* CONCURRENT_DFS_SUPPORT */
				printk("%s rader scanner mode...\n", priv->wlpd_p->ext_scnr_en ? "enable" : "disable");
			} else if ((strcmp(param[0], "dfsSetChanSw") == 0)) {
				int chan = atoi(param[1]);
				int no_cac = atoi(param[2]);
				int do_csa = atoi(param[3]);
				dfs_sme_channel_switch(netdev, chan, no_cac, do_csa);
			} else if ((strcmp(param[0], "radar_event") == 0)) {
				extern void radarDetectionHdlr(struct net_device
							       *netdev);
				vmacApInfo_t *vmacSta_p;
				struct wlprivate *wlpptr;
				int i;

				if (priv->vmacSta_p->master)
					vmacSta_p = priv->vmacSta_p->master;
				else
					vmacSta_p = priv->vmacSta_p;
				wlpptr = NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev);
				if (priv->wlpd_p->pdfsApMain) {
					for (i = 0; i <= NUMOFAPS; i++)
						if (wlpptr->vdev[i] && wlpptr->vdev[i]->flags & IFF_RUNNING) {
#ifdef CONCURRENT_DFS_SUPPORT
							extern void radarAuxChDetectionHdlr(struct
											    net_device
											    *netdev);
							int path = atoi(param[1]);

							if (path == DFS_PATH_DEDICATED) {
								radarAuxChDetectionHdlr(netdev);
								break;
							} else
#endif				/* CONCURRENT_DFS_SUPPORT */
								radarDetectionHdlr(netdev);
							break;
						}
				} else
					rc = -EOPNOTSUPP;
				break;
			}
#endif
#ifdef SOC_W906X
			else if ((strcmp(param[0], "max_nav") == 0)) {
				/* For 11n test plan 4.2.3, max nav is 25,000 us */
				struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
				UINT32 max_nav;

				max_nav = atoi(param[1]);
				*(u32 *) (&((SMAC_CTRL_BLK_st *) wlpptr->ioBase0)->config.maxNAV) = max_nav;
			}
#endif				/* SOC_W906X */
			/*WiFi pre-cert CLI */
			else if ((strcmp(param[0], "qosctrl") == 0)) {
				UINT8 mode = 0;	//0:disable, 1:11n, 2:11ac
				UINT32 limit;
				extern UINT8 qosctrl_mode;
				extern UINT32 qosctrl_txQLimit;

				mode = atoi(param[1]);
				limit = atoi(param[2]);
				if (mode < 3) {
					qosctrl_mode = mode;
					if (qosctrl_mode == 1)	//11n
						qosctrl_txQLimit = 1000;
					else if (qosctrl_mode == 2)	//11ac
						qosctrl_txQLimit = 2304;

					if (limit)
						qosctrl_txQLimit = limit;

				} else {
					qosctrl_mode = 0;
				}

				printk("QOS ctrl mode %d, limit %u\n", qosctrl_mode, (unsigned int)qosctrl_txQLimit);
			} else if ((strcmp(param[0], "setqosctrl") == 0)) {
				UINT32 mode, type, ac, thres;
				extern UINT32 qosctrl_loopthres[2][4];
				extern UINT32 qosctrl_pktthres[2][4];

				mode = atoi(param[1]);	//0:11n, 1:11ac
				type = atoi(param[2]);	//0: AC loop setting, 1: pkt setting
				ac = atoi(param[3]);	//0:BK, 1:BE, 2:VI, 3:VO
				thres = atoi(param[4]);	//threshold

				if (type == 0) {	//set AC loop thres
					if (mode < 2 && ac < 4) {
						qosctrl_loopthres[mode][ac] = thres;

						printk("%s TxQ loop thres, BK:%u, BE:%u, VI:%u, VO:%u\n", mode ? "11ac" : "11n",
						       (unsigned int)qosctrl_loopthres[mode][0], (unsigned int)qosctrl_loopthres[mode][1],
						       (unsigned int)qosctrl_loopthres[mode][2], (unsigned int)qosctrl_loopthres[mode][3]);
					}
				} else if (type == 1) {	//set pkt thres
					if (mode < 2 && ac < 4) {
						qosctrl_pktthres[mode][ac] = thres;

						printk("%s TxQ pkt thres, BK:%u, BE:%u, VI:%u, VO:%u\n", mode ? "11ac" : "11n",
						       (unsigned int)qosctrl_pktthres[mode][0], (unsigned int)qosctrl_pktthres[mode][1],
						       (unsigned int)qosctrl_pktthres[mode][2], (unsigned int)qosctrl_pktthres[mode][3]);
					}
				}

			} else if ((strcmp(param[0], "getqosctrl") == 0)) {
				UINT32 mode, type;
				extern UINT32 qosctrl_loopthres[2][4];
				extern UINT32 qosctrl_pktthres[2][4];

				mode = atoi(param[1]);	//0:11n, 1:11ac
				type = atoi(param[2]);	//0: AC loop setting, 1: tx pkt setting

				if (type == 0) {	// get loop thres
					if (mode < 2) {

						printk("%s TxQ loop thres, BK:%u, BE:%u, VI:%u, VO:%u\n", mode ? "11ac" : "11n",
						       (unsigned int)qosctrl_loopthres[mode][0], (unsigned int)qosctrl_loopthres[mode][1],
						       (unsigned int)qosctrl_loopthres[mode][2], (unsigned int)qosctrl_loopthres[mode][3]);
					}
				} else if (type == 1) {	// get pkt thres
					if (mode < 2) {

						printk("%s TxQ pkt thres, BK:%u, BE:%u, VI:%u, VO:%u\n", mode ? "11ac" : "11n",
						       (unsigned int)qosctrl_pktthres[mode][0], (unsigned int)qosctrl_pktthres[mode][1],
						       (unsigned int)qosctrl_pktthres[mode][2], (unsigned int)qosctrl_pktthres[mode][3]);
					}
				}
#ifdef OPENWRT
			} else if ((strcmp(param[0], "iwinfo") == 0)) {
				int id = 0, data_length = 0, result_length = 0, len;
				uint8_t *data = NULL, *result = NULL;
				uint8_t *data_buffer, *result_buffer;

				rc = -EFAULT;
#ifdef DEBUG_IWINFO
				printk("API of iwinfo for OpenWRT is called\n");
#endif
				if (param[1][0]) {
#ifdef DEBUG_IWINFO
					printk("CMD id: %s\n", param[1]);
#endif
					if (1 != sscanf(param[1], "%d", &id)) {
						rc = -EFAULT;
						break;
					}
				}
				if (param[2][0]) {
#ifdef DEBUG_IWINFO
					printk("Data ptr %s\n", param[2]);
#endif
					if (1 != sscanf(param[2], "%lx", (unsigned long *)&data)) {
						rc = -EFAULT;
						break;
					}
				}
				if (param[3][0]) {
#ifdef DEBUG_IWINFO
					printk("Data len %s\n", param[3]);
#endif
					if (1 != sscanf(param[3], "%d", &data_length)) {
						rc = -EFAULT;
						break;
					}
				}
				if (param[4][0]) {
#ifdef DEBUG_IWINFO
					printk("Result ptr %s\n", param[4]);
#endif
					if (1 != sscanf(param[4], "%lx", (unsigned long *)&result)) {
						rc = -EFAULT;
						break;
					}
				}
				if (param[5][0]) {
#ifdef DEBUG_IWINFO
					printk("Result len %s\n", param[5]);
#endif
					if (1 != sscanf(param[5], "%d", &result_length)) {
						rc = -EFAULT;
						break;
					}
				}
				if (data_length > 1024 * 32) {
					printk("data length too big %d\n", data_length);
				}
				if (result_length > 1024 * 32) {
					printk("result length too big %d\n", result_length);
				}
				data_buffer = wl_vzalloc(data_length);
				result_buffer = wl_vzalloc(result_length);
				if (NULL == data_buffer || NULL == result_buffer) {
					if (data_buffer) {
						wl_vfree(data_buffer);
					}
					if (result_buffer) {
						wl_vfree(result_buffer);
					}
					break;
				}
				if (copy_from_user(data_buffer, data, data_length)) {
					rc = -EFAULT;
					break;
				}
				if ((len = iwinfo_request_handler(netdev, mib, id, data_buffer, data_length, result_buffer, result_length)) > 0) {
#ifdef DEBUG_IWINFO
					printk("result vs buffer: %d:%d\n", len, result_length);
#endif
					if (len < result_length) {
						if (copy_to_user(result, result_buffer, len))
							rc = -EFAULT;
						else
							rc = 0;
					} else {
						rc = -EFAULT;
					}
				} else {
					printk("handler failed with %d id = %d\n", len, id);
					rc = -EFAULT;
				}
				wl_vfree(result_buffer);
				wl_vfree(data_buffer);
#endif
			} else if ((strcmp(param[0], "mu_bfmer") == 0)) {
				if (strcmp(param[1], "1") == 0) {
					*(mib->mib_mu_bfmer) = 1;	//enable
				} else {
					*(mib->mib_mu_bfmer) = 0;	//disable
				}
			} else if ((strcmp(param[0], "mu_bfmee") == 0)) {
				if (strcmp(param[1], "1") == 0) {
					*(mib->mib_mu_bfmee) = 1;	//enable
				} else {
					*(mib->mib_mu_bfmee) = 0;	//disable
				}
			}
#ifdef FIPS_SUPPORT
			else if ((strcmp(param[0], "fipstest") == 0)) {
				UINT32 status, checkParamFailed = 0, i, j;
				UINT16 alg = 0, encdec = 0;
				UINT8 *inBuff;
				DataEntry_t *Key, *Nounce, *AAD, *InData, *OutData;

				inBuff = wl_kmalloc(1024, GFP_KERNEL);
				Key = wl_kmalloc(sizeof(DataEntry_t), GFP_KERNEL);
				Nounce = wl_kmalloc(sizeof(DataEntry_t), GFP_KERNEL);
				AAD = wl_kmalloc(sizeof(DataEntry_t), GFP_KERNEL);
				InData = wl_kmalloc(sizeof(DataEntry_t), GFP_KERNEL);
				OutData = wl_kmalloc(sizeof(DataEntry_t), GFP_KERNEL);

				if (strcmp(param[1], "auto") == 0) {
					// fipstest  auto
					status = wlFwSendFipsTestAll(netdev);
					if (status)
						printk("FIPS Auto Test Failed. (0x%08x)\n", (unsigned int)status);
					else
						printk("FIPS Auto Test Success.\n");
				} else if (strcmp(param[1], "file") == 0) {
					struct file *filp;
					char *buff, *s, *param_tmp;
					int comment, len = 0, mmt_test = 0, mct_test = 0;
					int count = 0, done = 0, loop;
					DataEntry_t *pExp;

					filp = filp_open(param[2], O_RDONLY, 0);
					if (IS_ERR(filp)) {
						printk("Open file %s Error\n", param[2]);
					} else {
						printk("Open file %s OK\n", param[2]);
						Nounce->Length = 0;
						AAD->Length = 0;
						buff = wl_kmalloc(1024, GFP_KERNEL);
						pExp = wl_kmalloc(sizeof(DataEntry_t), GFP_KERNEL);
						param_tmp = wl_kmalloc(1024, GFP_KERNEL);
						while (1) {
							memset(buff, 0x00, 1024);
							s = buff;
							comment = 0;
							while ((len = kernel_read(filp, s, 1, &filp->f_pos)) == 1) {
								if (*s == '#') {
									comment = 1;;
								}
								if (*s == '\n') {
									/* skip blank line */
									if (s == buff)
										break;

									if (comment) {
										sscanf(buff, "%64s %64s %1023s\n", param[0], param[1], param[2]);
										if (strcmp(param[2], "MMT") == 0)
											mmt_test = 1;
										else if (strcmp(param[2], "MCT") == 0)
											mct_test = 1;
										printk("%s", buff);
										break;
									}
									sscanf(buff, "%64s %64s %1023s\n", param[0], param[1], param_tmp);
									encdec = 0;
									if (strcmp(param[0], "[ENCRYPT]") == 0)
										encdec = 1;
									else if (strcmp(param[0], "COUNT") == 0) {
										count = atoi(param_tmp);
										done = 0;
									} else if (strcmp(param[0], "KEY") == 0) {
										Key->Length = strlen(param_tmp) / 2;
										if ((Key->Length == 0) || (Key->Length > sizeof(Key->Data))) {
											printk("Invalid key size=%d key=%s\n", Key->Length,
											       param_tmp);
											checkParamFailed = 1;
										} else {
											HexStringToHexDigi(Key->Data, param_tmp, Key->Length);
											done |= (1 << 0);
										}
									} else if (strcmp(param[0], "PLAINTEXT") == 0) {
										InData->Length = strlen(param_tmp) / 2;
										if (mmt_test == 0) {
											if (InData->Length > sizeof(InData->Data)) {
												printk("Invalid Data size=%d data=%s\n",
												       InData->Length, param_tmp);
												checkParamFailed = 1;
											} else {
												HexStringToHexDigi(InData->Data, param_tmp,
														   InData->Length);
												done |= (1 << 1);
											}
										} else {
											strcpy(inBuff, param_tmp);
											done |= (1 << 1);
										}

									} else if (strcmp(param[0], "CIPHERTEXT") == 0) {
										pExp->Length = strlen(param_tmp) / 2;
										if (pExp->Length > sizeof(pExp->Data)) {
											printk("Invalid Data size=%d data=%s\n", pExp->Length,
											       param_tmp);
											checkParamFailed = 1;
										} else {
											HexStringToHexDigi(pExp->Data, param_tmp, pExp->Length);
											done |= (1 << 2);
										}
									}
									if ((checkParamFailed == 0) && (done == 0x07)) {
										if (mmt_test) {
											status = 0;
											loop = InData->Length / 16;
											printk("\nCOUNT   = %d\n", count);
											printk("Output  = ");
											InData->Length = 16;
											for (i = 0; i < loop; i++) {
												HexStringToHexDigi(InData->Data, &inBuff[32 * i], 16);
												status +=
												    wlFwSendFipsTest(netdev, encdec, EncrTypeAesOnly,
														     Key, Nounce, AAD, InData,
														     OutData);

												for (j = 0; j < OutData->Length; j++)
													printk("%02x", OutData->Data[j]);
											}
											printk("\n");
										} else if (mct_test) {
											loop = 1000;
											status = 0;
											printk("\nCOUNT   = %d\n", count);
											printk("Output  = ");
											for (i = 0; i < loop; i++) {
												status +=
												    wlFwSendFipsTest(netdev, encdec, EncrTypeAesOnly,
														     Key, Nounce, AAD, InData,
														     OutData);

												memcpy(InData->Data, OutData->Data, InData->Length);
											}
											for (j = 0; j < OutData->Length; j++)
												printk("%02x", OutData->Data[j]);
											printk("\n");
										} else {
											status = wlFwSendFipsTest(netdev, encdec, EncrTypeAesOnly,
														  Key, Nounce, AAD, InData, OutData);

											printk("\nCOUNT   = %d\n", count);
											printk("Output  = ");
											for (i = 0; i < OutData->Length; i++)
												printk("%02x", OutData->Data[i]);
											printk("\n");
										}
										printk("Expect  = %s\n", param_tmp);
										if (status)
											printk("Status  = 0x%x\n", status);

										done = 0;
									}
									break;
								} else
									s++;
							}
							if (len <= 0)
								break;
						}
						filp_close(filp, current->files);
						wl_kfree(pExp);
						wl_kfree(param_tmp);
						wl_kfree(buff);
					}
				} else {
					// fipstest  <encdec>  <alg>  <key>  <nonce>  <aad>  <data>
					if (strcmp(param[1], "enc") == 0)
						encdec = 1;
					else if (strcmp(param[1], "dec") == 0)
						encdec = 0;
					else {
						printk("Invalid encryption parameter %s\n", param[1]);
						checkParamFailed = 1;
					}

					if (strcmp(param[2], "aes-ccmp") == 0)
						alg = EncrTypeAes;
					else if (strcmp(param[2], "aes-ccmp-256") == 0)
						alg = EncrTypeCcmp256;
					else if (strcmp(param[2], "aes-gcmp") == 0)
						alg = EncrTypeGcmp128;
					else if (strcmp(param[2], "aes-gcmp-256") == 0)
						alg = EncrTypeGcmp256;
					else if (strcmp(param[2], "aes-only") == 0)
						alg = EncrTypeAesOnly;
					else {
						printk("Invalid algorithm parameter %s\n", param[2]);
						checkParamFailed = 1;
					}
					Key->Length = strlen(param[3]) / 2;
					if ((Key->Length == 0) || (Key->Length > sizeof(Key->Data))) {
						printk("Invalid key size=%d key=%s\n", Key->Length, param[3]);
						checkParamFailed = 1;
					}
					if (alg == EncrTypeAesOnly) {
						InData->Length = strlen(param[4]) / 2;
						if (InData->Length > sizeof(InData->Data)) {
							printk("Invalid Data size=%d data=%s\n", InData->Length, param[4]);
							checkParamFailed = 1;
						}
					} else {
						Nounce->Length = strlen(param[4]) / 2;
						if ((Nounce->Length == 0) || (Nounce->Length > sizeof(Nounce->Data))) {
							printk("Invalid nounce size=%d nounce=%s\n", Nounce->Length, param[4]);
							checkParamFailed = 1;
						}

						AAD->Length = strlen(param[5]) / 2;
						if (AAD->Length > sizeof(AAD->Data)) {
							printk("Invalid AAD size=%d AAD=%s\n", AAD->Length, param[5]);
							checkParamFailed = 1;
						}
						InData->Length = strlen(param[6]) / 2;
						if (InData->Length > sizeof(InData->Data)) {
							printk("Invalid Data size=%d data=%s\n", InData->Length, param[6]);
							checkParamFailed = 1;
						}
					}

					if (checkParamFailed == 0) {
						HexStringToHexDigi(Key->Data, param[3], Key->Length);
						if (alg == EncrTypeAesOnly) {
							HexStringToHexDigi(InData->Data, param[4], InData->Length);
							Nounce->Length = 0;
							AAD->Length = 0;
						} else {
							HexStringToHexDigi(Nounce->Data, param[4], Nounce->Length);
							HexStringToHexDigi(AAD->Data, param[5], AAD->Length);
							HexStringToHexDigi(InData->Data, param[6], InData->Length);
						}

						status = wlFwSendFipsTest(netdev, encdec, alg, Key, Nounce, AAD, InData, OutData);

						printk("\nFIPS %s mode=%s\n", param[1], param[2]);
						printk("Status: %u\n", (unsigned int)status);
						printk("KEY   : %s\n", param[3]);
						if (alg == EncrTypeAesOnly) {
							printk("Data  : %s\n", param[4]);
						} else {
							printk("Nounce: %s\n", param[4]);
							printk("AAD   : %s\n", param[5]);
							printk("Data  : %s\n", param[6]);
						}
						printk("Output: ");
						for (i = 0; i < OutData->Length; i++)
							printk("%02x", OutData->Data[i]);
						printk("\n");
					}
				}
				wl_kfree(inBuff);
				wl_kfree(Key);
				wl_kfree(Nounce);
				wl_kfree(AAD);
				wl_kfree(InData);
				wl_kfree(OutData);
			}
#endif
#ifdef SOC_W8964
			else if (strcmp(param[0], "rateupdateticks") == 0) {
				UINT32 n_ticks = atoi(param[1]);
				if (n_ticks < 2 || n_ticks > 200) {
					printk("Invalid value (ticks from 2 ~ 200) ...\n");
					rc = -EOPNOTSUPP;
					break;
				}
				printk("set n_ticks = %d\n", n_ticks);
				wlFwSetRateUpdateTicks(netdev, &n_ticks, 1);
				break;
			} else if (strcmp(param[0], "getrateupdateticks") == 0) {
				UINT32 n_ticks;;
				wlFwSetRateUpdateTicks(netdev, &n_ticks, 0);
				printk("get n_ticks = %d\n", n_ticks);
				break;
			}

			else if (strcmp(param[0], "usecustomrate") == 0) {
				UINT32 cust_rate = atoi(param[1]);
				if (cust_rate != 0 && cust_rate != 1) {
					printk("Invalid value (1:enable, 0:disable) ...\n");
					rc = -EOPNOTSUPP;
					break;
				}
				printk("set usecustomrate = %s\n", cust_rate ? "enable" : "disable");
				wlFwUseCustomRate(netdev, &cust_rate, 1);
				break;
			} else if (strcmp(param[0], "getcustomrate") == 0) {
				UINT32 cust_rate;;
				wlFwUseCustomRate(netdev, &cust_rate, 0);;
				printk("get cust_rate = %d\n", cust_rate);
				break;
			}
#endif
			else if (strcmp(param[0], "mcast_cts") == 0) {
				UINT8 enable = atoi(param[1]);
				wlFwSetMcastCtsToSelf(netdev, &enable);
				printk("multicast pkts send cts to self = %d\n", enable);
			}

			/*WiFi pre-cert CLI ends */
#ifdef SOC_W906X
			else if ((strcmp(param[0], "getspec") == 0)) {
				wlFwGetHwSpecs(netdev);
			} else if ((strcmp(param[0], "getmaccfg") == 0)) {
				UINT8 i;

				printk(" MAC CONFIG \n");
				printk("macBmBaseAddr = 0x%X, macBmSize = 0x%X, ddrHighAddr = 0x%X, bpRelQid = %d \n",
				       priv->smacCfgAddr->smacBmBaseAddr,
				       priv->smacCfgAddr->smacBmSize, priv->smacCfgAddr->ddrHighAddr, priv->smacCfgAddr->bpRelQid);
				printk("bpReqCnt = %d\n", priv->smacCfgAddr->bpReqCnt);
				for (i = 0; i < 8; i++) {
					if (priv->smacCfgAddr->bpReqInfo[i].size != 0) {
						printk("bpReqInfo size = %d, bpid = %d, qid = %d \n",
						       priv->smacCfgAddr->bpReqInfo[i].size,
						       priv->smacCfgAddr->bpReqInfo[i].bpid, priv->smacCfgAddr->bpReqInfo[i].bpid);
					}
				}
			} else if ((strcmp(param[0], "getmacstatus") == 0)) {
				wl_show_smac_stat(netdev, NULL, NULL);
#ifdef DSP_COMMAND
			} else if ((strcmp(param[0], "dspcmd") == 0)) {
				UINT8 index;
				UINT8 priority;
				UINT32 result;
				index = (UINT8) (atohex2(param[1]) & 0xffff);
				/*if (strcmp(param[2], "mid") == 0)
				   priority = 1;
				   else */ if (strcmp(param[2], "high") == 0)
					priority = 1;
				else
					priority = 0;
				wlDspCmd(netdev, index, priority, &result);
				printk("\nDSP command: index %x, priority %x  \n", index, priority);
				printk("\nDSP command result: %x  \n", result);
#ifdef DSP_TRIG_CMD
			} else if ((strcmp(param[0], "dsptrig") == 0)) {
				UINT8 index, priority;
				UINT8 muGID, numUser, pkttype;
				//UINT32 result;
				index = (UINT8) (atohex2(param[1]) & 0xffff);
				if (strcmp(param[2], "high") == 0)
					priority = 1;
				else
					priority = 0;

				muGID = (UINT8) (atohex2(param[3]));
				numUser = (UINT8) (atohex2(param[4]));
				pkttype = (UINT8) (atohex2(param[5]));

				wlDspTrig(netdev, index, priority, muGID, numUser, pkttype);
				printk("\nDSP0 command: index %x, priority %x, muGID %d, Users: %d, Pkttype: %d\n", index, priority, muGID, numUser,
				       pkttype);
				//printk("DSP command input: %x, %x\n", inputPtr, outputPtr);
				//printk("\nDSP command result: %x  \n", result);
#endif
#endif				/* DSP_COMMAND */
			} else if ((strcmp(param[0], "radiomode") == 0)) {
				u8 ch2;

				if (input_cnt == 1) {
					printk("radio mode %d, BAND 1 %d, Channel 1 %d, BW 1 %d,"
					       "BAND 2 %d, channel 2 %d, BW 2 %d\n",
					       mib->PhyDSSSTable->Chanflag.radiomode,
					       mib->PhyDSSSTable->Chanflag.FreqBand,
					       mib->PhyDSSSTable->CurrChan,
					       mib->PhyDSSSTable->Chanflag.ChnlWidth,
					       mib->PhyDSSSTable->Chanflag.FreqBand2,
					       mib->PhyDSSSTable->SecChan, mib->PhyDSSSTable->Chanflag.ChnlWidth2);
					break;
				} else if (input_cnt == 2) {
					mib->PhyDSSSTable->Chanflag.radiomode = (atohex2(param[1]) & 0xffff);

					if (mib->PhyDSSSTable->Chanflag.radiomode != RADIO_MODE_NORMAL) {
						WLDBG_ERROR(DBG_LEVEL_1, "Only one argument. Change radio mode to normal. \n");
						mib->PhyDSSSTable->Chanflag.radiomode = RADIO_MODE_NORMAL;
					}

					mib->PhyDSSSTable->SecChan = 0;
					mib->PhyDSSSTable->Chanflag.ChnlWidth2 = 0;
					mib->PhyDSSSTable->Chanflag.FreqBand2 = 0;

				} else if (input_cnt == 3) {
#ifdef CONCURRENT_DFS_SUPPORT
					if (priv->wlpd_p->ext_scnr_en) {
						WLDBG_ERROR(DBG_LEVEL_1, "80MHZ + 80MHZ mode is not accepted when concurrent DFS mode is enabled.\n");
						rc = -EOPNOTSUPP;
						break;
					}
#endif				/* CONCURRENT_DFS_SUPPORT */
					ch2 = (atohex2(param[2]) & 0xffff);
#ifdef MRVL_DFS
					if (ch2) {
						/*Check if the target channel is a DFS channel and in NOL.
						 * If so, do not let the channel to change.
						 */
						if (DfsPresentInNOL(netdev, ch2)) {
							printk("Target channel :%d is already in NOL\n", ch2);
							rc = -EOPNOTSUPP;
							break;
						}
					}
#endif
					mib->PhyDSSSTable->Chanflag.radiomode = (atohex2(param[1]) & 0xffff);

					if (mib->PhyDSSSTable->Chanflag.radiomode != RADIO_MODE_80p80) {
						WLDBG_ERROR(DBG_LEVEL_1, "2 arguments. Change radio mode to 80+80MHZ. \n");
						mib->PhyDSSSTable->Chanflag.radiomode = RADIO_MODE_80p80;
					}

					mib->PhyDSSSTable->SecChan = (atohex2(param[2]) & 0xffff);
					mib->PhyDSSSTable->Chanflag.ChnlWidth = CH_80_MHz_WIDTH;
					mib->PhyDSSSTable->Chanflag.ChnlWidth2 = CH_80_MHz_WIDTH;
					mib->PhyDSSSTable->Chanflag.FreqBand2 = FREQ_BAND_5GHZ;
				} else if (input_cnt == 5) {
					mib->PhyDSSSTable->Chanflag.radiomode = (atohex2(param[1]) & 0xffff);

					if (mib->PhyDSSSTable->Chanflag.radiomode != RADIO_MODE_7x7p1x1) {
						WLDBG_ERROR(DBG_LEVEL_1, "4 arguments. Change radio mode to 7+1/3+1 mode. \n");
						mib->PhyDSSSTable->Chanflag.radiomode = RADIO_MODE_7x7p1x1;
					}

					mib->PhyDSSSTable->Chanflag.FreqBand2 = (atohex2(param[2]) & 0xffff);
					mib->PhyDSSSTable->SecChan = (atohex2(param[3]) & 0xffff);
					mib->PhyDSSSTable->Chanflag.ChnlWidth2 = (atohex2(param[4]) & 0xffff);
				} else {
					WLDBG_ERROR(DBG_LEVEL_1, "Invalid command arguments. \n");
					printk("Command examples:\n");
					printk("Change to normal mode: radiomode 0");
					printk("Change to 80+80MHZ: radiomode 1 149");
					printk("Change to 7+1/3+1 mode, second band is 5G and second" "bandwidth is 20MHZ: radiomode 2 4 149 2");
					rc = -EFAULT;
				}

				if (!domainChannelValid
				    (mib->PhyDSSSTable->SecChan, mib->PhyDSSSTable->SecChan <= 14 ? FREQ_BAND_2DOT4GHZ : FREQ_BAND_5GHZ)) {
					mib->PhyDSSSTable->SecChan = 0;
					mib->PhyDSSSTable->Chanflag.radiomode = RADIO_MODE_NORMAL;
					WLDBG_ERROR(DBG_LEVEL_1, "Invalid second channel. \n");
					rc = -EOPNOTSUPP;
				} else {
					if (mib->PhyDSSSTable->Chanflag.radiomode == RADIO_MODE_80p80) {
						if (GetCenterFreq(mib->PhyDSSSTable->CurrChan, CH_80_MHz_WIDTH) ==
						    GetCenterFreq(mib->PhyDSSSTable->SecChan, CH_80_MHz_WIDTH)) {
							mib->PhyDSSSTable->SecChan = 0;
							mib->PhyDSSSTable->Chanflag.radiomode = RADIO_MODE_NORMAL;
							WLDBG_ERROR(DBG_LEVEL_1, "channel %d and channel %d on the same 80MHZ channel width.\n",
								    mib->PhyDSSSTable->SecChan, mib->PhyDSSSTable->CurrChan);
							rc = -EOPNOTSUPP;
						}
					}

					if (mib->PhyDSSSTable->Chanflag.radiomode != RADIO_MODE_NORMAL) {
						if ((priv->devid == SC5) || (priv->devid == SCBT)) {
							if ((priv->hwData.chipRevision != REV_A0) &&
							    (mib->PhyDSSSTable->CurrChan > mib->PhyDSSSTable->SecChan)) {
								mib->PhyDSSSTable->SecChan = 0;
								mib->PhyDSSSTable->Chanflag.radiomode = RADIO_MODE_NORMAL;
								WLDBG_ERROR(DBG_LEVEL_1, "Z0/Z1 chip doesn't support the smaller second channel.\n");
								rc = -EOPNOTSUPP;
							}
						}
					}
				}
			} else if ((strcmp(param[0], "fixpe") == 0)) {

				if (strcmp(param[1], "disable") == 0) {
					wlFw_SetFixedPe(netdev, 0, 0);
				} else {
					u8 pe = atohex2(param[2]) & 0xff;
					if ((pe == 0) || (pe == 8) || (pe == 16))
						wlFw_SetFixedPe(netdev, pe, 1);
					else {
						WLDBG_ERROR(DBG_LEVEL_1, "Invalid command arguments. \n");
						printk("Command examples:\n");
						printk("Disable fixed PE: fixpe disable \n");
						printk("Set fixed PE to 8: fixpe 8 \n");
						rc = -EINVAL;
					}
				}

			} else if ((strcmp(param[0], "bfmee") == 0)) {

				if (strcmp(param[1], "1") == 0) {
					*(mib->mib_bfmee) = 1;	//enable
					priv->smacCfgAddr->bfControl = 1;
				} else if (strcmp(param[1], "0") == 0) {
					*(mib->mib_bfmee) = 0;	//disable
					priv->smacCfgAddr->bfControl = 0;
				}
				printk("\nBFmee is: %s\n", *(mib->mib_bfmee) ? "enabled" : "disabled");

			} else if ((strcmp(param[0], "beamchange") == 0)) {
				if (strcmp(param[1], "on") == 0) {
					printk("set beam change on.\n");
					*(mib->mib_beamChange_disable) = 0;
					wlFwSetBeamChange(netdev, 1);
				} else if (strcmp(param[1], "off") == 0) {
					printk("set beam change off.\n");
					*(mib->mib_beamChange_disable) = 1;
					wlFwSetBeamChange(netdev, 0);
				} else {
					printk("usage: \"beamchange [on/off]\"\n");
					rc = -EFAULT;
					break;
				}
			} else if ((strcmp(param[0], "omctrl") == 0)) {
				extern UINT32 wlDataTx_SendOMFrame(struct net_device *dev, IEEEtypes_MacAddr_t da, UINT16 StnId, UINT16 RxNSS,
								   UINT16 ChnlWidth);
				int i, entries;
				UCHAR *sta_buf, *show_buf;
				extStaDb_StaInfo_t *pStaInfo;
				UINT16 RxNSS = atoi(param[1]);
				UINT16 ChnlWidth = atoi(param[2]);

				entries = extStaDb_entries(vmacSta_p, 0);

				sta_buf = wl_kmalloc(entries * 64, GFP_KERNEL);
				if (sta_buf == NULL) {
					rc = -EFAULT;
					break;
				}

				extStaDb_list(vmacSta_p, sta_buf, 1);

				if (entries) {
					show_buf = sta_buf;
					for (i = 0; i < entries; i++) {
						if ((pStaInfo =
						     extStaDb_GetStaInfo(vmacSta_p, (IEEEtypes_MacAddr_t *) show_buf,
									 STADB_DONT_UPDATE_AGINGTIME)) == NULL) {
							wl_kfree(sta_buf);
							rc = -EFAULT;
							return rc;
						}

						printk("send om control->[%s]  RxNSS:%d ChnlWidth:%d\n", mac_display(pStaInfo->Addr), RxNSS,
						       ChnlWidth);
						wlDataTx_SendOMFrame(netdev, pStaInfo->Addr, pStaInfo->StnId, RxNSS, ChnlWidth);
						show_buf += sizeof(STA_INFO);
					}
				} else {
					struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
					vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
					vmacEntry_t *vmacEntry_p = NULL;
					UINT16 stnId = 0;

					if ((vmacEntry_p = sme_GetParentVMacEntry(vmacSta_p->VMacEntry.phyHwMacIndx)) != NULL) {
						vmacStaInfo_t *vStaInfo_p = (vmacStaInfo_t *) vmacEntry_p->info_p;

						pStaInfo =
						    extStaDb_GetStaInfo(vmacSta_p,
									(IEEEtypes_MacAddr_t *) & vStaInfo_p->macMgmtMlme_ThisStaData.BssId[0],
									STADB_DONT_UPDATE_AGINGTIME);
						if (pStaInfo != NULL) {
							stnId = pStaInfo->StnId;
						}
						printk("send om control->[%s] stnId:%d	RxNSS:%d ChnlWidth:%d\n",
						       mac_display(&vStaInfo_p->macMgmtMlme_ThisStaData.BssId[0]), stnId, RxNSS, ChnlWidth);
						wlDataTx_SendOMFrame(netdev, &vStaInfo_p->macMgmtMlme_ThisStaData.BssId[0], stnId, RxNSS, ChnlWidth);
					}
				}
				wl_kfree(sta_buf);
			} else if ((strcmp(param[0], "petype") == 0)) {
				if (strcmp(param[1], "default") == 0) {
					printk("set petype default.\n");
					mib->HEConfig->pe_type = MIB_PE_TYPE_DEFAULT;
				} else if (strcmp(param[1], "aggressive") == 0) {
					printk("set petype aggressive.\n");
					mib->HEConfig->pe_type = MIB_PE_TYPE_AGGRESSIVE;
				} else {
					printk("usage: \"petype [default/aggressive]\"\n");
					rc = -EFAULT;
					break;
				}
			}
#endif				/* SOC_W906X */
#ifdef BAND_STEERING
			else if ((strcmp(param[0], "bandsteer") == 0)) {
				UINT32 value = atoi(param[2]);

				if (strcmp(param[1], "1") == 0)
					*(mib->mib_bandsteer) = 1;
				else if (strcmp(param[1], "0") == 0)
					*(mib->mib_bandsteer) = 0;
				else if (strcmp(param[1], "handler") == 0)
					*(mib->mib_bandsteer_handler) = value;
				else if (strcmp(param[1], "mode") == 0)
					*(mib->mib_bandsteer_mode) = value;
				else if (strcmp(param[1], "timer_interval") == 0)
					*(mib->mib_bandsteer_timer_interval) = (value * HZ + 500) / 1000;
				else if (strcmp(param[1], "rssi_threshold") == 0)
					*(mib->mib_bandsteer_rssi_threshold) = value;
				else if (strcmp(param[1], "sta_track_max_num") == 0)
					*(mib->mib_bandsteer_sta_track_max_num) = value;
				else if (strcmp(param[1], "sta_track_max_age") == 0)
					*(mib->mib_bandsteer_sta_track_max_age) = (value * HZ);
				else if (strcmp(param[1], "sta_auth_retry_cnt") == 0)
					*(mib->mib_bandsteer_sta_auth_retry_cnt) = value;
			}
#endif				/* BAND_STEERING */
			else if ((strcmp(param[0], "pinfo_rx_1nss") == 0)) {
				WFA_PeerInfo_HE_CAP_1NSS = atoi(param[1]);
			}
#ifdef SOC_W906X
			else if ((strcmp(param[0], "bareorder_holdtime") == 0)) {
				MIB_802DOT11 *mib1 = vmacSta_p->Mib802dot11;

				*(mib->mib_BAReorder_holdtime) = atoi(param[1]) * TIMER_1MS;
				*(mib1->mib_BAReorder_holdtime) = *(mib->mib_BAReorder_holdtime);

				printk("\nBA Reorder Hold Time set as %dms\n", atoi(param[1]));
			}
			//Spatial reuse enable/disable and setting non-SRG and SRG pwr threshold setting
			//Use this CLI only after BSS is up
			//"srparam 1 -72 0"
			//"srparam test 1 <inteference mac or FFFFFFFFFFFF for wild card>"
			//"srpaarm getrssi"
			else if ((strcmp(param[0], "srparam") == 0)) {
				SINT8 thresNonSrg = 0, thresSrg = 0;
				UINT8 enable = 0;

				if (strcmp(param[1], "") == 0) {
					printk("Invalid usage. See example below:\n");
					printk("srparam <b1:use def pwr, b0:enable> <NonSRG thres> <SRG thres>\n");
					printk("srparam <0:disable>\n");
					return FALSE;
				}
				//Dump interference RSSI log, which is filtered by interference mac addr
				if (strcmp(param[1], "getrssi") == 0) {
					SINT8 intfRssi[SR_RSSI_LOG_SIZE] = { 0 };
					UINT8 i;

					wlFw_SetSR(netdev, enable, thresNonSrg, thresSrg, HAL_SFW_SR_GET_RSSI, intfRssi);
					printk("Interference RSSI\n");
					for (i = 0; i < SR_RSSI_LOG_SIZE; i++) {
						if (intfRssi[i] != -2)
							printk("%d\n", intfRssi[i]);
						else
							printk("end\n");
					}
				}
				//Set interference mac addr to filter for RSSI log
				else if (strcmp(param[1], "test") == 0) {
					char macaddr[6] = { 0 };

					if (strcmp(param[2], "") == 0) {
						printk("srparam test <1:enable | 0:disable> <mac_addr>\n");
						return FALSE;
					}

					enable = (UINT8) atoi(param[2]);
					if (enable) {
						if (strcmp(param[3], "") == 0) {
							printk("srparam test 1 <mac_addr>\n");
							return FALSE;
						}
						getMacFromString(macaddr, param[3]);
					}

					wlFw_SetSR(netdev, enable, 0, 0, HAL_SFW_SR_SET_TESTMODE, macaddr);
				}
				//Set enable/disable threshold
				else {
					enable = (UINT8) atoi(param[1]);

					if (enable) {
						if ((strcmp(param[2], "") == 0) || (strcmp(param[3], "") == 0)) {
							printk("Invalid usage. See example below:\n");
							printk("srparam <b1:use def pwr, b0:enable> <NonSRG thres> <SRG thres>\n");
							return FALSE;
						} else {
							thresNonSrg = (SINT8) atoi_2(param[2]);
							thresSrg = (SINT8) atoi_2(param[3]);

							if ((thresNonSrg > -62) || (thresNonSrg < -82)) {
								printk("Enter threshold between -62 to -82\n");
								return FALSE;
							}
						}
					}
					wlFw_SetSR(netdev, enable, thresNonSrg, thresSrg, HAL_SFW_SR_SET_SRPARAM, NULL);
				}
			}
#endif				/* SOC_W906X */
#ifdef AUTOCHANNEL
			else if ((strcmp(param[0], "ap_op_ch_list") == 0)) {
				int i, j, offset;

				if (strcmp(param[1], "help") == 0) {
					printk("Usage: ap_op_ch_list set AP opreation channel list.\n");
					printk(" Eg. ap_op_ch_list <band> <ch 1> <ch 2> ... <ch n>\n");
					printk(" band : 0:2.4g / 1:5g\n");

					rc = -EFAULT;
					break;
				} else if (strcmp(param[1], "get") == 0) {
					printk("AP Operation Channel List:");
					j = 0;
					for (i = 0; i < IEEE_80211_MAX_NUMBER_OF_CHANNELS; i++) {
						if ((mib->PhyDSSSTable->Chanflag.ChnlWidth != CH_20_MHz_WIDTH)) {
							if (*(mib->mib_regionCode) == DOMAIN_CODE_ALL) {
								if (vmacSta_p->OpChanList[i] == 181) {
									continue;
								}
							} else {
								if (vmacSta_p->OpChanList[i] >= 165) {
									continue;
								}
							}
						}
						if (vmacSta_p->OpChanList[i] != 0) {
							j++;
							printk(" %d", vmacSta_p->OpChanList[i]);
							if (0 == (j % 20)) {
								printk("\n");
							}
						}
					}
					printk("\n");
					break;
				}
				offset = atoi(param[1]) ? IEEEtypes_MAX_CHANNELS : 0;
				/* TBD: Check scanchannel list in ap_op_ch_list */
				memset(vmacSta_p->OpChanList, 0, sizeof(UINT8) * IEEE_80211_MAX_NUMBER_OF_CHANNELS);
				for (i = 0; i < IEEE_80211_MAX_NUMBER_OF_CHANNELS; i++) {
					vmacSta_p->OpChanList[i + offset] = atohex2(param[i + 2]);
					if (vmacSta_p->OpChanList[i + offset] == 0) {
						break;
					}
				}
			} else if ((strcmp(param[0], "acs_interval") == 0)) {
				ch_load_info_t *ch_load_p = &vmacSta_p->acs_cload;
				UINT32 interval;

				if (vmacSta_p->master != NULL) {
					printk("This parameter cannot be set to virtual interface %s, please use %s instead!\n", vmacSta_p->dev->name,
					       priv->master->name);
					rc = -EOPNOTSUPP;
					return rc;
				}
				if (strcmp(param[1], "help") == 0) {
					printk("Usage: acs_interval set a interval timer to collect current channel's acs data\n");
					printk(" Eg. acs_interval <interval value(1~60 sec.)>\n");
					break;
				} else if (strcmp(param[1], "get") == 0) {
					printk("acs interval :%d\n", ch_load_p->interval);
					break;
				}
				interval = atoi(param[1]);
				if (0 == interval || interval > 60) {
					printk("acs_interval <interval value(1~60 sec.)>\n");
					rc = -EINVAL;
					break;
				}
				TimerDisarm(&ch_load_p->timer);
				memset(ch_load_p, 0, sizeof(ch_load_info_t));
				ch_load_p->tag = CH_LOAD_ACS;
				ch_load_p->master = (UINT8 *) vmacSta_p;
				ch_load_p->dur = 500;
				ch_load_p->interval = atoi(param[1]) * 1000;
				ch_load_p->ignore_time = ((ch_load_p->interval + ch_load_p->dur) / 1000) + 1;	//ceil(ignore_time)
				ch_load_p->loop_count = 0;
				ch_load_p->callback = &wl_acs_ch_load_cb;
				ch_load_p->started = 1;
				wl_get_ch_load_by_timer(ch_load_p);
			} else if ((strcmp(param[0], "acs_mode") == 0)) {
				if (vmacSta_p->master != NULL) {
					printk("This parameter cannot be set to virtual interface %s, please use %s instead!\n", vmacSta_p->dev->name,
					       priv->master->name);
					rc = -EOPNOTSUPP;
					return rc;
				}
				if (strcmp(param[1], "help") == 0) {
					printk("Usage: acs_mode set mode to collect channel's acs data\n");
					printk(" Eg. acs_mode 0 for Legacy Mode\n");
					printk("     acs_mode 1 for NF-reading Mode\n");
					break;
				} else if (strcmp(param[1], "get") == 0) {
					printk("acs mode :%d\n", vmacSta_p->acs_mode);
					break;
				} else if (strcmp(param[1], "set") == 0) {
					vmacSta_p->acs_mode = atoi(param[2]);
					printk("set acs mode tp %d\n", vmacSta_p->acs_mode);
					if (!vmacSta_p->acs_mode) {
						vmacSta_p->acs_ch_load_weight = 40;
						vmacSta_p->acs_ch_nf_weight = 50;
						vmacSta_p->acs_ch_distance_weight = 300;
						vmacSta_p->acs_bss_distance_weight = 300;
						vmacSta_p->acs_bss_num_weight = 100;
						vmacSta_p->acs_rssi_weight = 150;
						vmacSta_p->acs_adjacent_bss_weight = 0;
						vmacSta_p->acs_adjacent_bss_weight_plus = 0;
					} else {
						vmacSta_p->acs_ch_load_weight = 0;
						vmacSta_p->acs_ch_nf_weight = 0;
						vmacSta_p->acs_ch_distance_weight = 10;
						vmacSta_p->acs_bss_distance_weight = 10;
						vmacSta_p->acs_bss_num_weight = 100;
						vmacSta_p->acs_rssi_weight = 0;
						vmacSta_p->acs_adjacent_bss_weight = 0;
						vmacSta_p->acs_adjacent_bss_weight_plus = 0;
					}
					printk("update the weight to...\n");
					printk("acs_ch_load_weight: %d\n", vmacSta_p->acs_ch_load_weight);
					printk("acs_ch_nf_weight: %d\n", vmacSta_p->acs_ch_nf_weight);
					printk("acs_ch_distance_weight: %d\n", vmacSta_p->acs_ch_distance_weight);
					printk("acs_bss_distance_weight: %d\n", vmacSta_p->acs_bss_distance_weight);
					printk("acs_bss_num_weight: %d\n", vmacSta_p->acs_bss_num_weight);
					printk("acs_rssi_weight: %d\n", vmacSta_p->acs_rssi_weight);
					printk("acs_adjacent_bss_weight: %d\n", vmacSta_p->acs_adjacent_bss_weight);
					printk("acs_adjacent_bss_weight_plus: %d\n", vmacSta_p->acs_adjacent_bss_weight_plus);
					break;
				}

			}
#endif				/* AUTOCHANNEL */
			else if ((strcmp(param[0], "dev_send_frame") == 0)) {
				UINT8 enable;
				struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev);

				enable = (UINT8) atoi(param[1]);
				sscanf(param[2], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n",
				       &(wlpptr->sndpkt_mac[0]), &(wlpptr->sndpkt_mac[1]), &(wlpptr->sndpkt_mac[2]),
				       &(wlpptr->sndpkt_mac[3]), &(wlpptr->sndpkt_mac[4]), &(wlpptr->sndpkt_mac[5]));

				if (strcmp(param[3], "11AX") == 0)
					wlpptr->wfa_sndpkt_rate = 3;
				else if (strcmp(param[3], "11AC") == 0)
					wlpptr->wfa_sndpkt_rate = 2;
				else if (strcmp(param[3], "11N") == 0)
					wlpptr->wfa_sndpkt_rate = 1;
				else
					wlpptr->wfa_sndpkt_rate = 0;

				if (atoi(param[4]))
					wlpptr->wfa_sndpkt_interval = atoi(param[4]);

				if (wfa_11ax_pf) {
					if (enable) {
						printk("enable wfa_test_timer to send test frames, interval:%d\n", wlpptr->wfa_sndpkt_interval);
						TimerInit(&wfa_test_timer);
						TimerFireInByJiffies(&wfa_test_timer, 1, &dev_send_frame, (unsigned char *)vmacSta_p, 50);
					} else {
						TimerRemove(&wfa_test_timer);
					}
				}
			} else if ((strcmp(param[0], "wfa_testbed") == 0)) {
				struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev);
				//MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
				UINT8 enable = (UINT8) atoi(param[1]);
				if (enable == 1) {
					printk("Running as the testbed\n");
					wlpptr->is_wfa_testbed = true;
				} else {
					printk("Running as the uut\n");
					wlpptr->is_wfa_testbed = false;
				}
			} else if ((strcmp(param[0], "cac") == 0)) {
				UINT8 enable;

				if (priv->master) {
					printk("Cannot be set to virtual interface\n");
					rc = -EFAULT;
					break;
				}
				enable = atoi(param[1]);
				EM_CAC_Scan(vmacSta_p, 121, 0, enable);
			} else if ((strcmp(param[0], "cac_start") == 0)) {
				UINT8 op_class;
				UINT8 ch;

				if (input_cnt < 5) {
					WLDBG_ERROR(DBG_LEVEL_1, "Invalid command arguments. \n");
					printk("Command examples:\n");
					printk("cac_start <op_class> <channel> <cac_method> <cac_completion>\n");
					rc = -EFAULT;
				}
				op_class = atoi(param[1]);
				ch = atoi(param[2]);
				EM_CAC_Scan(vmacSta_p, op_class, ch, 1);
			} else if ((strcmp(param[0], "cac_stop") == 0)) {
				UINT8 op_class;
				UINT8 ch;

				if (input_cnt < 3) {
					WLDBG_ERROR(DBG_LEVEL_1, "Invalid command arguments. \n");
					printk("Command examples:\n");
					printk("cac_stop <op_class> <channel>\n");
					rc = -EFAULT;
				}
				op_class = atoi(param[1]);
				ch = atoi(param[2]);
				EM_CAC_Scan(vmacSta_p, op_class, ch, 0);
			} else if ((strcmp(param[0], "HostSetMUSet") == 0)) {
				UINT8 i, MUUsrCnt = 0;
				UINT16 Stnid[MU_MAX_USERS];
				extStaDb_StaInfo_t *StaInfo_p;
				UINT8 myGid;
				SINT8 cmd_option;

				cmd_option = atohex(param[1]);
				myGid = atohex(param[2]) + 1;	/* GID from 1 ~ 62 */
				MUUsrCnt = atoi(param[3]);
				if (cmd_option < 0 || cmd_option > 2) {
					printk("Error. Set MU set option(%d) failed\n", cmd_option);
					rc = -EFAULT;
				}

				printk("Value of MuUsr=%d Gid=%d\n", MUUsrCnt, myGid);

				for (i = 0; (i < MU_MAX_USERS) && (i < MUUsrCnt); i++) {
					Stnid[i] = (UINT16) 0xFFFF;
					if (*param[i + 4] == 0)
						break;
					else
						Stnid[i] = atoi(param[i + 4]);
				}
				Stnid[i] = (UINT16) 0xFFFF;

				printk("Stnid:");
				for (i = 0; i < MUUsrCnt; i++)
					printk(" %x", Stnid[i]);
				printk("\n");

				if (cmd_option == 0) {
					/* Delete Group! */
					if (wlFwSetMUSet(vmacSta_p->dev, 0, 0, myGid - 1, Stnid)) {
						printk("Delete DL-MU Set GID:%d OK!\n", myGid);
					} else {
						printk("Delete DL-MU in PENDING\n");
						rc = -EFAULT;
					}
					break;
				}

				if (!priv->master) {
					printk("Error. Please enter vap interface instead\n");
					rc = -EOPNOTSUPP;
					break;
				}

				if (cmd_option == 1) {
					/* 11AC Group, need to send action frame to STA */
					for (i = 0; i < MUUsrCnt; i++) {
						StaInfo_p = extStaDb_GetStaInfoStn(vmacSta_p, Stnid[i]);
						if (StaInfo_p != NULL) {
							printk("SendGroupIDMgmtframe StnId:%d, addr:%s\n", StaInfo_p->StnId,
							       mac_display(StaInfo_p->Addr));
							SendGroupIDMgmtframe(vmacSta_p, StaInfo_p->Addr, myGid, i);
						}
					}
				}

				if (wlFwSetMUSet(vmacSta_p->dev, cmd_option, myGid, myGid - 1, Stnid)) {
					switch (cmd_option) {
					case 1:
						printk("Set VHT DL-MU set GID:%d OK!\n", myGid);
						break;
					case 2:
						printk("Set HE DL-MU set GID:%d OK!\n", myGid);
						break;
					case 3:
						printk("Set DL-OFDMA MU set GID:%d OK!\n", myGid);
						break;
					}
				} else {
					printk("Set DL-MU in Pending\n");
					rc = -EFAULT;
				}
			} else if ((strcmp(param[0], "rrm_offchan_time") == 0)) {
				UINT32 time_val, i;
				offchan_node_t node;

				if (priv->master) {
					printk("Error. Please enter radio interface instead\n");
					rc = -EOPNOTSUPP;
					break;
				}

				if (input_cnt < 2) {
					printk("rrm_offchan_time trigger=%dms interval=%dms dwell time=%dms\n",
					       wlpd_p->offchan_scan.user_offch.trigger_time, wlpd_p->offchan_scan.user_offch.interval_time,
					       wlpd_p->offchan_scan.user_offch.dwell_time);
					break;
				}
				if (strcmp(param[1], "help") == 0) {
					printk("Set a user offchannel list to scan\n");
					printk("Command examples:(millisecond)\n");
					printk("rrm_offchan_time <trigger time> <interval time> <dwell time>\n");
					printk("If time = 0, set to default time(trigger=%d interval=%d dwell=%d)\n", RRM_DEFAULT_TRIGGER_TIME,
					       RRM_DEFAULT_INTERVAL_TIME, RRM_DEFAULT_DWELL_TIME);
					printk("If dwell = 0, disable user offchannel\n");
					break;
				}
				memset(&node, 0, sizeof(offchan_node_t));
				time_val = atoi(param[3]);
				if (time_val > 0) {
					if (time_val > 1000) {
						printk("failed dwell time = %dms > 1000ms\n", time_val);
						rc = -EFAULT;
						break;
					}
					node.dwell_time = time_val;
					node.active = TRUE;
				} else {
					/* Disable user offchan list */
					node.interval_time = RRM_DEFAULT_DWELL_TIME;
					node.active = FALSE;
				}

				time_val = atoi(param[2]);
				if (time_val > 0)
					node.interval_time = time_val;
				else
					node.interval_time = RRM_DEFAULT_INTERVAL_TIME;

				time_val = atoi(param[1]);
				if (time_val > 0)
					node.trigger_time = time_val;
				else
					node.trigger_time = RRM_DEFAULT_TRIGGER_TIME;

				if (atoi(param[4]))
					node.repeat = (atoi(param[4]) == 0) ? FALSE : TRUE;
				for (i = 0; *param[i + 5] != 0; i++)
					node.offchanlist[i] = atoi(param[i + 5]);
				OffchannelScanSet(netdev, &node, FALSE);
			} else if ((strcmp(param[0], "HostSetOfdma") == 0)) {
				UINT8 i, MUUsrCnt = 0;
				UINT8 enable;
				UINT16 Stnid[MU_OFDMA_MAX_USER];

				enable = atohex(param[1]);
				MUUsrCnt = atoi(param[2]);

				memset(Stnid, 0, sizeof(Stnid));
				for (i = 0; (i < MU_OFDMA_MAX_USER) && (i < MUUsrCnt); i++) {
					if (*param[i + 3] == 0)
						break;
					else
						Stnid[i] = atoi(param[i + 3]);
				}
				Stnid[i] = (UINT16) 0xFFFF;

				printk("OFDMA Stnid:");
				for (i = 0; (i < MU_OFDMA_MAX_USER) && (i < MUUsrCnt); i++)
					printk(" %d", Stnid[i]);
				printk("\n");

				if (wlFwSetOFDMASet(vmacSta_p->dev, enable, MUUsrCnt, Stnid) == SUCCESS) {
					printk("%s OFDMA mode OK!\n", enable ? "Set" : "Delete");
				} else {
					printk("%s OFDMA mode Failed!!\n", enable ? "Set" : "Delete");
					rc = -EOPNOTSUPP;
				}
				break;
			} else if ((strcmp(param[0], "HostSetULMUSet") == 0)) {
				ul_stnid_ru_t StaList[MU_MAX_USERS];
				UINT32 RateInfo, value, Flag, offset;
				UINT16 action, gid;
				UINT8 mu_mode, BandWidth, StaNum = 0, i, j;
				UINT8 *pos = param_str;

				if (!priv->master) {
					printk("Error. Please enter vap interface instead\n");
					rc = -EOPNOTSUPP;
					break;
				}

				input_cnt = 0;
				while (sscanf(pos, "%64s%n", param[input_cnt], &offset) == 1) {
					input_cnt++;
					if (input_cnt >= MAX_GROUP_PER_CHANNEL) {
						break;
					}
					pos += offset;
				}

				if (strcmp(param[1], "help") == 0) {
					printk("Usage: HostSetULMUSet action gid RateInfo Flag mode BandWidth StaNum StaList\n");
					printk(" Eg. Create: HostSetULMUSet 1 1 0x0f4007e3 0 1 2 2 0xCF 0x7FFBA 0 0x100CF 0x7FFB0 0\n");
					printk(" Eg. Delete: HostSetULMUSet 2 1\n");
					printk(" action             : 1:Set 2:Delete\n");
					printk(" gid                : Group ID\n");
					printk(" RateInfo           : Tx Rate for trigger frame\n");
					printk(" Flag               : 0: Reinitialize SU Rate, 1: StaList changed, Oterhs: reserved\n");
					printk(" mode               : 1:MIMO 2:OFDMA\n");
					printk(" BandWidth          : 20MHz = 0 ... 160MHz = 3\n");
					printk(" StaNum             : sta count\n");
					printk(" StaList            : Sta List\n");
					printk("   StnID            : param1[16:31]\n");
					printk("   RU_alloc         : param1[0:15]\n");
					printk("   SU_Rate_NSS      : param2[24:31]\n");
					printk("   SU_Rate_MCS      : param2[16:23]\n");
					printk("   SU_rssi          : param2[0:15]\n");
					printk("   CSI              : param3 \n");
					printk("   DataLen          : param4 \n");

					rc = -EFAULT;
					break;
				}
				action = atoi(param[1]);
				gid = atoi(param[2]);
				if (action == HostCmd_ACT_GEN_SET) {
					RateInfo = atohex(param[3]);
					Flag = atoi(param[4]);
					mu_mode = atoi(param[5]);
					BandWidth = atoi(param[6]);
					StaNum = atoi(param[7]);

					if ((mu_mode != 1) && (mu_mode != 2)) {
						printk("Error. Set UL MU set mu_mode(%d) failed\n", mu_mode);
						rc = -EFAULT;
						break;
					}

					if (BandWidth >= 4 /*BW_MAX */ ) {
						printk("Error. Set UL MU set BandWidth(%d) failed\n", BandWidth);
						rc = -EFAULT;
						break;
					}

					if (StaNum > MU_MAX_USERS) {
						printk("Error. Set UL MU set StaNum(%d) failed\n", StaNum);
						rc = -EFAULT;
						break;
					}
					printk("Value of ULMU action=Set Gid=%d RateInfo=0x%08x Flag:%d mode=%d bw=%d StaNum=%d\n",
					       gid, RateInfo, Flag, mu_mode, BandWidth, StaNum);
					memset(StaList, 0, sizeof(ul_stnid_ru_t) * MU_MAX_USERS);
					for (i = 0, j = 0; i < StaNum; i++, j += 4) {
						value = atohex(param[j + 8]);
						StaList[i].StnID = (value >> 16) & 0xFFFF;
						if (StaList[i].StnID >= sta_num) {
							printk("Error: StnID %d out of range [max=%d]\n", StaList[i].StnID, sta_num);
							rc = -EFAULT;
							break;
						}
						StaList[i].RU_alloc = value & 0xFFFF;
						value = atohex(param[j + 9]);
						StaList[i].SU_Rate_NSS = (value >> 24) & 0xFF;
						StaList[i].SU_Rate_MCS = (value >> 16) & 0xFF;
						StaList[i].SU_rssi = ENDIAN_SWAP16(value & 0xFFFF);
						StaList[i].CSI = ENDIAN_SWAP32(atoi(param[j + 10]));
						StaList[i].DataLen = ENDIAN_SWAP32(atoi(param[j + 11]));
						StaList[i].StnID = ENDIAN_SWAP16(StaList[i].StnID);
						StaList[i].RU_alloc = ENDIAN_SWAP16(StaList[i].RU_alloc);
					}
					if (rc == -EFAULT) {
						break;
					}

					printk("(Stnid,ru,nss,MCS,rssi,CSI,DataLen):\n");
					for (i = 0; i < StaNum; i++) {
						printk(" (%d,0x%x,%d,%d,%d,%d,%d)", StaList[i].StnID, StaList[i].RU_alloc, StaList[i].SU_Rate_NSS,
						       StaList[i].SU_Rate_MCS, StaList[i].SU_rssi, StaList[i].CSI, StaList[i].DataLen);
						printk("\n");
					}
					if (wlFwSetULMUSet(vmacSta_p->dev, action, RateInfo, Flag, gid, mu_mode, BandWidth, StaNum, StaList) ==
					    SUCCESS) {
						printk("Set ULMU %s GID:%d OK!\n", (mu_mode == 1) ? "MIMO" : "OFDMA", gid);
					} else {
						printk("Set ULMU %s GID:%d Failed!!\n", (mu_mode == 1) ? "MIMO" : "OFDMA", gid);
					}
				} else if (action <= HostCmd_ACT_GEN_DEL) {
					if (wlFwSetULMUSet(vmacSta_p->dev, action, 0, 0, gid, 0, 0, 0, NULL) == SUCCESS) {
						printk("%s ULMU GID:%d OK!\n", (action == HostCmd_ACT_GEN_DEL) ? "Delete" : "Get", gid);
					} else {
						printk("%s ULMU GID:%d Failed!!\n", (action == HostCmd_ACT_GEN_DEL) ? "Delete" : "Get", gid);
					}
				} else {
					printk("Error. Set UL MU set action(%d) failed\n", action);
					rc = -EFAULT;
					break;
				}
				break;
			} else if ((strcmp(param[0], "HostSetAcntWithMu") == 0)) {
				UINT16 action;

				action = atoi(param[1]);
				if (wlFwSetAcntWithMu(vmacSta_p->dev, action) == SUCCESS) {
					printk("%s Acnt with MU OK!\n", (action == HostCmd_ACT_GEN_SET) ? "Enable" : "Disable");
				} else {
					printk("%s Acnt with MU Failed!!\n", (action == HostCmd_ACT_GEN_SET) ? "Enable" : "Disable");
					rc = -EOPNOTSUPP;
				}
				break;
			} else if ((strcmp(param[0], "HostDelDlGid") == 0)) {
				vmacApInfo_t *master_p = vmacSta_p;
				UINT8 gid;

				if (vmacSta_p->master) {
					master_p = vmacSta_p->master;
				}

				gid = atoi(param[1]);
				if (gid == 0 || gid >= 63) {
					printk("%s Delete DL gid failed, gid=%d, DL_GroupSet:0x%016llx\n", master_p->dev->name, gid,
					       master_p->DL_GroupSet);
					break;
				}
				master_p->DL_GroupSet = master_p->DL_GroupSet & (~((UINT64) 0x1 << gid));
			} else if ((strcmp(param[0], "HostDelUlGid") == 0)) {
				vmacApInfo_t *master_p = vmacSta_p;
				UINT8 gid;

				if (vmacSta_p->master) {
					master_p = vmacSta_p->master;
				}

				gid = atoi(param[1]);
				if (gid == 0 || gid >= 63) {
					printk("%s Delete UL gid failed, gid=%d, UL_GroupSeq=%d, UL_GroupSet:0x%016llx\n", master_p->dev->name, gid,
					       master_p->UL_GroupSeq, master_p->UL_GroupSet);
					break;
				}
				master_p->UL_GroupSet = master_p->UL_GroupSet & (~((UINT64) 0x1 << gid));
			} else if ((strcmp(param[0], "HostSet_dl_ofdma") == 0)) {
				MIB_802DOT11 *mib1 = vmacSta_p->Mib802dot11;
				union iwreq_data wreq;
				UINT8 i;
				UINT8 *msg_buf;

				if (priv->master) {
					printk("Cannot be set to virtual interface\n");
					rc = -EOPNOTSUPP;
					break;
				}
				msg_buf = wl_kmalloc(IW_CUSTOM_MAX, GFP_KERNEL);
				if (msg_buf == NULL) {
					printk("kmalloc failed in HostSet_dl_ofdma\n");
					rc = -EOPNOTSUPP;
					break;
				}
				mib1->DL_ofdma_enable = atoi(param[1]);
				sprintf(msg_buf, "wlmgr: mumode dl_ofdma %d", mib1->DL_ofdma_enable);
				memset(&wreq, 0, sizeof(wreq));
				wreq.data.length = strlen(msg_buf);
				for (i = 0; i <= bss_num; i++) {
					if (priv->vdev[i]) {
						wireless_send_event(priv->vdev[i], IWEVCUSTOM, &wreq, msg_buf);
					}
				}
				if (mib1->DL_ofdma_enable == 2 && mib1->DL_mimo_enable > 0) {
					/* In force mode, disable dl_mimo */
					mib1->DL_mimo_enable = 0;
					sprintf(msg_buf, "wlmgr: mumode dl_mimo %d", mib1->DL_mimo_enable);
					memset(&wreq, 0, sizeof(wreq));
					wreq.data.length = strlen(msg_buf);
					for (i = 0; i <= bss_num; i++) {
						if (priv->vdev[i]) {
							wireless_send_event(priv->vdev[i], IWEVCUSTOM, &wreq, msg_buf);
						}
					}
				}
				wl_kfree(msg_buf);
			} else if ((strcmp(param[0], "HostSet_dl_mimo") == 0)) {
				MIB_802DOT11 *mib1 = vmacSta_p->Mib802dot11;
				union iwreq_data wreq;
				UINT8 i;
				UINT8 *msg_buf;

				if (priv->master) {
					printk("Cannot be set to virtual interface\n");
					rc = -EOPNOTSUPP;
					break;
				}
				msg_buf = wl_kmalloc(IW_CUSTOM_MAX, GFP_KERNEL);
				if (msg_buf == NULL) {
					printk("kmalloc failed in HostSet_dl_ofdma\n");
					rc = -EOPNOTSUPP;
					break;
				}
				mib1->DL_mimo_enable = atoi(param[1]);
				sprintf(msg_buf, "wlmgr: mumode dl_mimo %d", mib1->DL_mimo_enable);
				memset(&wreq, 0, sizeof(wreq));
				wreq.data.length = strlen(msg_buf);
				for (i = 0; i <= bss_num; i++) {
					if (priv->vdev[i]) {
						wireless_send_event(priv->vdev[i], IWEVCUSTOM, &wreq, msg_buf);
					}
				}
				if (mib1->DL_mimo_enable == 2 && mib1->DL_ofdma_enable > 0) {
					/* In force mode, disable dl_ofdma */
					mib1->DL_ofdma_enable = 0;
					sprintf(msg_buf, "wlmgr: mumode dl_ofdma %d", mib1->DL_ofdma_enable);
					memset(&wreq, 0, sizeof(wreq));
					wreq.data.length = strlen(msg_buf);
					for (i = 0; i <= bss_num; i++) {
						if (priv->vdev[i]) {
							wireless_send_event(priv->vdev[i], IWEVCUSTOM, &wreq, msg_buf);
						}
					}
				}
				wl_kfree(msg_buf);
			} else if ((strcmp(param[0], "HostSet_ul_ofdma") == 0)) {
				MIB_802DOT11 *mib1 = vmacSta_p->Mib802dot11;
				union iwreq_data wreq;
				UINT8 i;
				UINT8 *msg_buf;

				if (priv->master) {
					printk("Cannot be set to virtual interface\n");
					rc = -EOPNOTSUPP;
					break;
				}
				msg_buf = wl_kmalloc(IW_CUSTOM_MAX, GFP_KERNEL);
				if (msg_buf == NULL) {
					printk("kmalloc failed in HostSet_dl_ofdma\n");
					rc = -EOPNOTSUPP;
					break;
				}
				mib1->UL_ofdma_enable = atoi(param[1]);
				sprintf(msg_buf, "wlmgr: mumode ul_ofdma %d", mib1->UL_ofdma_enable);
				memset(&wreq, 0, sizeof(wreq));
				wreq.data.length = strlen(msg_buf);
				for (i = 0; i <= bss_num; i++) {
					if (priv->vdev[i]) {
						wireless_send_event(priv->vdev[i], IWEVCUSTOM, &wreq, msg_buf);
					}
				}
				if (mib1->UL_ofdma_enable == 2 && mib1->UL_mimo_enable > 0) {
					/* In force mode, disable ul_mimo */
					mib1->UL_mimo_enable = 0;
					sprintf(msg_buf, "wlmgr: mumode ul_mimo %d", mib1->UL_mimo_enable);
					memset(&wreq, 0, sizeof(wreq));
					wreq.data.length = strlen(msg_buf);
					for (i = 0; i <= bss_num; i++) {
						if (priv->vdev[i]) {
							wireless_send_event(priv->vdev[i], IWEVCUSTOM, &wreq, msg_buf);
						}
					}
				}
				wl_kfree(msg_buf);
			} else if ((strcmp(param[0], "HostSet_ul_mimo") == 0)) {
				MIB_802DOT11 *mib1 = vmacSta_p->Mib802dot11;
				union iwreq_data wreq;
				UINT8 i;
				UINT8 *msg_buf;

				if (priv->master) {
					printk("Cannot be set to virtual interface\n");
					rc = -EOPNOTSUPP;
					break;
				}
				msg_buf = wl_kmalloc(IW_CUSTOM_MAX, GFP_KERNEL);
				if (msg_buf == NULL) {
					printk("kmalloc failed in HostSet_dl_ofdma\n");
					rc = -EOPNOTSUPP;
					break;
				}
				mib1->UL_mimo_enable = atoi(param[1]);
				sprintf(msg_buf, "wlmgr: mumode ul_mimo %d", mib1->UL_mimo_enable);
				memset(&wreq, 0, sizeof(wreq));
				wreq.data.length = strlen(msg_buf);
				for (i = 0; i <= bss_num; i++) {
					if (priv->vdev[i]) {
						wireless_send_event(priv->vdev[i], IWEVCUSTOM, &wreq, msg_buf);
					}
				}
				if (mib1->UL_mimo_enable == 2 && mib1->UL_ofdma_enable > 0) {
					/* In force mode, disable ul_ofdma */
					mib1->UL_ofdma_enable = 0;
					sprintf(msg_buf, "wlmgr: mumode ul_ofdma %d", mib1->UL_ofdma_enable);
					memset(&wreq, 0, sizeof(wreq));
					wreq.data.length = strlen(msg_buf);
					for (i = 0; i <= bss_num; i++) {
						if (priv->vdev[i]) {
							wireless_send_event(priv->vdev[i], IWEVCUSTOM, &wreq, msg_buf);
						}
					}
				}
				wl_kfree(msg_buf);
			} else if ((strcmp(param[0], "dfs_opt") == 0)) {
				SINT32 ret = 0, i;
				UINT8 fcc_min_radar_num_pri[8];
				UINT8 etsi_min_radar_num_pri[8];
				UINT8 jpn_w53_min_radar_num_pri[8];
				UINT8 jpn_w56_min_radar_num_pri[8];
				UINT8 false_detect_th;
				UINT8 fcc_zc_error_th;
				UINT8 etsi_zc_error_th;
				UINT8 jp_zc_error_th;
				UINT8 jpw53_zc_error_th;

				if (priv->master) {
					printk("Cannot be set to virtual interface\n");
					rc = -EFAULT;
					break;
				}
				if (strcmp(param[1], "help") == 0) {
					printk("Usage: iwpriv <radio> setcmd \"dfs_opt <DFS_params> <value> <force>\"\n\n");
					printk("DFS_params              default min Max\n");
					printk("fcc_min_radar_num_pri[8]      %d   %d   %d\n",
					       FCC_MIN_RADAR_NUM_PRI_DEFAULT, FCC_MIN_RADAR_NUM_PRI_MIN, FCC_MIN_RADAR_NUM_PRI_MAX);
					printk("etsi_min_radar_num_pri[8]     %d   %d   %d\n",
					       ETSI_MIN_RADAR_NUM_PRI_DEFAULT, ETSI_MIN_RADAR_NUM_PRI_MIN, ETSI_MIN_RADAR_NUM_PRI_MAX);
					printk("jpn_w53_min_radar_num_pri[8]  %d   %d   %d\n",
					       JPN_W53_MIN_RADAR_NUM_PRI_DEFAULT, JPN_W53_MIN_RADAR_NUM_PRI_MIN, JPN_W53_MIN_RADAR_NUM_PRI_MAX);
					printk("jpn_w56_min_radar_num_pri[8]  %d   %d   %d\n",
					       JPN_W56_MIN_RADAR_NUM_PRI_DEFAULT, JPN_W56_MIN_RADAR_NUM_PRI_MIN, JPN_W56_MIN_RADAR_NUM_PRI_MAX);
					printk("false_detect_th               %d   %d   %d\n",
					       FALSE_DETECT_TH_DEFAULT, FALSE_DETECT_TH_MIN, FALSE_DETECT_TH_MAX);
					printk("fcc_zc_error_th               %d   %d   %d\n",
					       FCC_ZC_ERROR_TH_DEFAULT, FCC_ZC_ERROR_TH_MIN, FCC_ZC_ERROR_TH_MAX);
					printk("etsi_zc_error_th              %d   %d   %d\n",
					       ETSI_ZC_ERROR_TH_DEFAULT, ETSI_ZC_ERROR_TH_MIN, ETSI_ZC_ERROR_TH_MAX);
					printk("jp_zc_error_th                %d   %d   %d\n",
					       JP_ZC_ERROR_TH_DEFAULT, JP_ZC_ERROR_TH_MIN, JP_ZC_ERROR_TH_MAX);
					printk("jpw53_zc_error_th             %d   %d   %d\n",
					       JPW53_ZC_ERROR_TH_DEFAULT, JPW53_ZC_ERROR_TH_MIN, JPW53_ZC_ERROR_TH_MAX);

					printk("example:\n");
					printk("set jpn_w53_min_radar_num_pri only\n");
					printk("    iwpriv wdev0 setcmd \"dfs_opt jpn_w53_min_radar_num_pri 2 2 2 2 2 2 2 2\"\n");
					printk("set false_detect_th only\n");
					printk("    iwpriv wdev0 setcmd \"dfs_opt false_detect_th 9\"\n");
					printk("set jp_zc_error_th in force mode\n");
					printk("    iwpriv wdev0 setcmd \"dfs_opt jp_zc_error_th 3 force\"\n");
					printk("get dfs option\n");
					printk("    iwpriv wdev0 setcmd \"dfs_opt get\"\n");
					break;

				}
				if (strcmp(param[1], "get") == 0) {
					ret =
					    wlFwDFSParams(vmacSta_p->dev, DFS_GET_ALL, fcc_min_radar_num_pri, etsi_min_radar_num_pri,
							  jpn_w53_min_radar_num_pri, jpn_w56_min_radar_num_pri, &false_detect_th, &fcc_zc_error_th,
							  &etsi_zc_error_th, &jp_zc_error_th, &jpw53_zc_error_th);
					printk("fcc_min_radar_num_pri       %d %d %d %d %d %d %d %d\n", fcc_min_radar_num_pri[0],
					       fcc_min_radar_num_pri[1], fcc_min_radar_num_pri[2], fcc_min_radar_num_pri[3], fcc_min_radar_num_pri[4],
					       fcc_min_radar_num_pri[5], fcc_min_radar_num_pri[6], fcc_min_radar_num_pri[7]);
					printk("etsi_min_radar_num_pri      %d %d %d %d %d %d %d %d\n", etsi_min_radar_num_pri[0],
					       etsi_min_radar_num_pri[1], etsi_min_radar_num_pri[2], etsi_min_radar_num_pri[3],
					       etsi_min_radar_num_pri[4], etsi_min_radar_num_pri[5], etsi_min_radar_num_pri[6],
					       etsi_min_radar_num_pri[7]);
					printk("jpn_w53_min_radar_num_pri   %d %d %d %d %d %d %d %d\n", jpn_w53_min_radar_num_pri[0],
					       jpn_w53_min_radar_num_pri[1], jpn_w53_min_radar_num_pri[2], jpn_w53_min_radar_num_pri[3],
					       jpn_w53_min_radar_num_pri[4], jpn_w53_min_radar_num_pri[5], jpn_w53_min_radar_num_pri[6],
					       jpn_w53_min_radar_num_pri[7]);
					printk("jpn_w56_min_radar_num_pri   %d %d %d %d %d %d %d %d\n", jpn_w56_min_radar_num_pri[0],
					       jpn_w56_min_radar_num_pri[1], jpn_w56_min_radar_num_pri[2], jpn_w56_min_radar_num_pri[3],
					       jpn_w56_min_radar_num_pri[4], jpn_w56_min_radar_num_pri[5], jpn_w56_min_radar_num_pri[6],
					       jpn_w56_min_radar_num_pri[7]);
					printk("false_detect_th             %d\n", false_detect_th);
					printk("fcc_zc_error_th             %d\n", fcc_zc_error_th);
					printk("etsi_zc_error_th            %d\n", etsi_zc_error_th);
					printk("jp_zc_error_th              %d\n", jp_zc_error_th);
					printk("jpw53_zc_error_th           %d\n", jpw53_zc_error_th);
				} else if (strcmp(param[1], "fcc_min_radar_num_pri") == 0) {
					for (i = 0; i < (sizeof(fcc_min_radar_num_pri) / sizeof(UINT8)); i++) {
						fcc_min_radar_num_pri[i] = atoi(param[i + 2]);
						if (strcmp(param[(sizeof(fcc_min_radar_num_pri) / sizeof(UINT8)) + 2], "force") != 0) {
							if (fcc_min_radar_num_pri[i] < FCC_MIN_RADAR_NUM_PRI_MIN ||
							    fcc_min_radar_num_pri[i] > FCC_MIN_RADAR_NUM_PRI_MAX) {
								printk("Error: fcc_min_radar_num_pri[%d] %d out of range [min=%d] [max=%d]\n", i,
								       fcc_min_radar_num_pri[i], FCC_MIN_RADAR_NUM_PRI_MIN,
								       FCC_MIN_RADAR_NUM_PRI_MAX);
								ret = -1;
								break;
							}
						}
					}
					if (!ret)
						ret =
						    wlFwDFSParams(vmacSta_p->dev, DFS_SET_FCC_MIN_RADAR_NUM_PRI, fcc_min_radar_num_pri,
								  etsi_min_radar_num_pri, jpn_w53_min_radar_num_pri, jpn_w56_min_radar_num_pri,
								  &false_detect_th, &fcc_zc_error_th, &etsi_zc_error_th, &jp_zc_error_th,
								  &jpw53_zc_error_th);
				} else if (strcmp(param[1], "etsi_min_radar_num_pri") == 0) {
					for (i = 0; i < (sizeof(etsi_min_radar_num_pri) / sizeof(UINT8)); i++) {
						etsi_min_radar_num_pri[i] = atoi(param[i + 2]);
						if (strcmp(param[(sizeof(etsi_min_radar_num_pri) / sizeof(UINT8)) + 2], "force") != 0) {
							if (etsi_min_radar_num_pri[i] < ETSI_MIN_RADAR_NUM_PRI_MIN ||
							    etsi_min_radar_num_pri[i] > ETSI_MIN_RADAR_NUM_PRI_MAX) {
								printk("Error: etsi_min_radar_num_pri[%d] %d out of range [min=%d] [max=%d]\n", i,
								       etsi_min_radar_num_pri[i], ETSI_MIN_RADAR_NUM_PRI_MIN,
								       ETSI_MIN_RADAR_NUM_PRI_MAX);
								ret = -1;
								break;
							}
						}
					}
					if (!ret)
						ret =
						    wlFwDFSParams(vmacSta_p->dev, DFS_SET_ETSI_MIN_RADAR_NUM_PRI, fcc_min_radar_num_pri,
								  etsi_min_radar_num_pri, jpn_w53_min_radar_num_pri, jpn_w56_min_radar_num_pri,
								  &false_detect_th, &fcc_zc_error_th, &etsi_zc_error_th, &jp_zc_error_th,
								  &jpw53_zc_error_th);
				} else if (strcmp(param[1], "jpn_w53_min_radar_num_pri") == 0) {
					for (i = 0; i < (sizeof(jpn_w53_min_radar_num_pri) / sizeof(UINT8)); i++) {
						jpn_w53_min_radar_num_pri[i] = atoi(param[i + 2]);
						if (strcmp(param[(sizeof(jpn_w53_min_radar_num_pri) / sizeof(UINT8)) + 2], "force") != 0) {
							if (jpn_w53_min_radar_num_pri[i] < JPN_W53_MIN_RADAR_NUM_PRI_MIN ||
							    jpn_w53_min_radar_num_pri[i] > JPN_W53_MIN_RADAR_NUM_PRI_MAX) {
								printk("Error: jpn_w53_min_radar_num_pri[%d] %d out of range [min=%d] [max=%d]\n", i,
								       jpn_w53_min_radar_num_pri[i], JPN_W53_MIN_RADAR_NUM_PRI_MIN,
								       JPN_W53_MIN_RADAR_NUM_PRI_MAX);
								ret = -1;
								break;
							}
						}
					}
					if (!ret)
						ret =
						    wlFwDFSParams(vmacSta_p->dev, DFS_SET_JPN_W53_MIN_RADAR_NUM_PRI, fcc_min_radar_num_pri,
								  etsi_min_radar_num_pri, jpn_w53_min_radar_num_pri, jpn_w56_min_radar_num_pri,
								  &false_detect_th, &fcc_zc_error_th, &etsi_zc_error_th, &jp_zc_error_th,
								  &jpw53_zc_error_th);
				} else if (strcmp(param[1], "jpn_w56_min_radar_num_pri") == 0) {
					for (i = 0; i < (sizeof(jpn_w56_min_radar_num_pri) / sizeof(UINT8)); i++) {
						jpn_w56_min_radar_num_pri[i] = atoi(param[i + 2]);
						if (strcmp(param[(sizeof(jpn_w56_min_radar_num_pri) / sizeof(UINT8)) + 2], "force") != 0) {
							if (jpn_w56_min_radar_num_pri[i] < JPN_W56_MIN_RADAR_NUM_PRI_MIN ||
							    jpn_w56_min_radar_num_pri[i] > JPN_W56_MIN_RADAR_NUM_PRI_MAX) {
								printk("Error: jpn_w56_min_radar_num_pri[%d] %d out of range [min=%d] [max=%d]\n", i,
								       jpn_w56_min_radar_num_pri[i], JPN_W56_MIN_RADAR_NUM_PRI_MIN,
								       JPN_W56_MIN_RADAR_NUM_PRI_MAX);
								ret = -1;
								break;
							}
						}
					}
					if (!ret)
						ret =
						    wlFwDFSParams(vmacSta_p->dev, DFS_SET_JPN_W56_MIN_RADAR_NUM_PRI, fcc_min_radar_num_pri,
								  etsi_min_radar_num_pri, jpn_w53_min_radar_num_pri, jpn_w56_min_radar_num_pri,
								  &false_detect_th, &fcc_zc_error_th, &etsi_zc_error_th, &jp_zc_error_th,
								  &jpw53_zc_error_th);
				} else if (strcmp(param[1], "false_detect_th") == 0) {
					false_detect_th = atoi(param[2]);
					if (strcmp(param[(sizeof(false_detect_th) / sizeof(UINT8)) + 2], "force") != 0) {
						if (false_detect_th < FALSE_DETECT_TH_MIN || false_detect_th > FALSE_DETECT_TH_MAX) {
							printk("Error: false_detect_th %d out of range [min=%d] [max=%d]\n", false_detect_th,
							       FALSE_DETECT_TH_MIN, FALSE_DETECT_TH_MAX);
							break;
						}
					}
					ret =
					    wlFwDFSParams(vmacSta_p->dev, DFS_SET_FALSE_DETECT_TH, fcc_min_radar_num_pri, etsi_min_radar_num_pri,
							  jpn_w53_min_radar_num_pri, jpn_w56_min_radar_num_pri, &false_detect_th, &fcc_zc_error_th,
							  &etsi_zc_error_th, &jp_zc_error_th, &jpw53_zc_error_th);
				} else if (strcmp(param[1], "fcc_zc_error_th") == 0) {
					fcc_zc_error_th = atoi(param[2]);
					if (strcmp(param[(sizeof(fcc_zc_error_th) / sizeof(UINT8)) + 2], "force") != 0) {
						if (fcc_zc_error_th < FCC_ZC_ERROR_TH_MIN || fcc_zc_error_th > FCC_ZC_ERROR_TH_MAX) {
							printk("Error: fcc_zc_error_th %d out of range [min=%d] [max=%d]\n", fcc_zc_error_th,
							       FCC_ZC_ERROR_TH_MIN, FCC_ZC_ERROR_TH_MAX);
							break;
						}
					}
					ret =
					    wlFwDFSParams(vmacSta_p->dev, DFS_SET_FCC_ZC_ERROR_TH, fcc_min_radar_num_pri, etsi_min_radar_num_pri,
							  jpn_w53_min_radar_num_pri, jpn_w56_min_radar_num_pri, &false_detect_th, &fcc_zc_error_th,
							  &etsi_zc_error_th, &jp_zc_error_th, &jpw53_zc_error_th);
				} else if (strcmp(param[1], "etsi_zc_error_th") == 0) {
					etsi_zc_error_th = atoi(param[2]);
					if (strcmp(param[(sizeof(etsi_zc_error_th) / sizeof(UINT8)) + 2], "force") != 0) {
						if (etsi_zc_error_th < ETSI_ZC_ERROR_TH_MIN || etsi_zc_error_th > ETSI_ZC_ERROR_TH_MAX) {
							printk("Error: etsi_zc_error_th %d out of range [min=%d] [max=%d]\n", etsi_zc_error_th,
							       ETSI_ZC_ERROR_TH_MIN, ETSI_ZC_ERROR_TH_MAX);
							break;
						}
					}
					ret =
					    wlFwDFSParams(vmacSta_p->dev, DFS_SET_ETSI_ZC_ERROR_TH, fcc_min_radar_num_pri, etsi_min_radar_num_pri,
							  jpn_w53_min_radar_num_pri, jpn_w56_min_radar_num_pri, &false_detect_th, &fcc_zc_error_th,
							  &etsi_zc_error_th, &jp_zc_error_th, &jpw53_zc_error_th);
				} else if (strcmp(param[1], "jp_zc_error_th") == 0) {
					jp_zc_error_th = atoi(param[2]);
					if (strcmp(param[(sizeof(jp_zc_error_th) / sizeof(UINT8)) + 2], "force") != 0) {
						if (jp_zc_error_th < JP_ZC_ERROR_TH_MIN || jp_zc_error_th > JP_ZC_ERROR_TH_MAX) {
							printk("Error: jp_zc_error_th %d out of range [min=%d] [max=%d]\n", jp_zc_error_th,
							       JP_ZC_ERROR_TH_MIN, JP_ZC_ERROR_TH_MAX);
							break;
						}
					}
					ret =
					    wlFwDFSParams(vmacSta_p->dev, DFS_SET_JP_ZC_ERROR_TH, fcc_min_radar_num_pri, etsi_min_radar_num_pri,
							  jpn_w53_min_radar_num_pri, jpn_w56_min_radar_num_pri, &false_detect_th, &fcc_zc_error_th,
							  &etsi_zc_error_th, &jp_zc_error_th, &jpw53_zc_error_th);
				} else if (strcmp(param[1], "jpw53_zc_error_th") == 0) {
					jpw53_zc_error_th = atoi(param[2]);
					if (strcmp(param[(sizeof(jpw53_zc_error_th) / sizeof(UINT8)) + 2], "force") != 0) {
						if (jpw53_zc_error_th < JPW53_ZC_ERROR_TH_MIN || jpw53_zc_error_th > JPW53_ZC_ERROR_TH_MAX) {
							printk("Error: jpw53_zc_error_th %d out of range [min=%d] [max=%d]\n", jpw53_zc_error_th,
							       JPW53_ZC_ERROR_TH_MIN, JPW53_ZC_ERROR_TH_MAX);
							break;
						}
					}
					ret =
					    wlFwDFSParams(vmacSta_p->dev, DFS_SET_JPW53_ZC_ERROR_TH, fcc_min_radar_num_pri, etsi_min_radar_num_pri,
							  jpn_w53_min_radar_num_pri, jpn_w56_min_radar_num_pri, &false_detect_th, &fcc_zc_error_th,
							  &etsi_zc_error_th, &jp_zc_error_th, &jpw53_zc_error_th);
				} else {
					printk("Please enter correct parameters or refer to the instructions in the help.\n");
					printk("\t iwpriv wdev0 setcmd \"dfs_opt help\"\n");
					break;
				}

				if (ret == FAIL) {
					printk("wlFwDFSParams failed, %s %s %s\n", param[0], param[1], param[2]);
					rc = -EOPNOTSUPP;
				}
				break;
			}
#ifdef MRVL_WSC
			else if ((strcmp(param[0], "wpsrfband") == 0)) {
				WSC_RFBand_Attribute_t *wps_rf_band_attr = NULL;
				UINT8 *wsc_ie = NULL;
				UINT32 lenOffset = 0;
				UINT8 WPS_OUI[4] = { 0x00, 0x50, 0xf2, 0x04 }
				, wsc_ie_len;
				UINT8 value = atoi(param[1]);

				if (value < 0 || value > 3) {
					rc = -EOPNOTSUPP;
					break;
				}
				if (!vmacSta_p->WPSOn) {
					printk("%s WPS is disabled\n", netdev->name);
					rc = -EOPNOTSUPP;
					break;
				}

				if (value == 0) {
					printk("%s ioctl wps_rf_band = %d, could set value(1:2g, 2:5g, 3:2G&5G)\n", netdev->name,
					       vmacSta_p->wps_rf_band);
				} else {
					if (Is5GBand(*(mib->mib_ApMode)))
						value |= 2;
					else
						value |= 1;

					if (vmacSta_p->thisbeaconIEs.Len != 0) {
						wsc_ie =
						    FindIEWithinIEs(vmacSta_p->thisbeaconIEs.WSCData, vmacSta_p->thisbeaconIEs.Len, PROPRIETARY_IE,
								    WPS_OUI);
						if (wsc_ie) {
							wsc_ie_len = *(wsc_ie + 1);
							wps_rf_band_attr =
							    FindAttributeWithinWPSIE(wsc_ie + sizeof(IEEEtypes_InfoElementHdr_t) + WSC_OUI_LENGTH,
										     wsc_ie_len - WSC_OUI_LENGTH, WSC_RF_BAND_ATTRB);
							if (wps_rf_band_attr) {
								wps_rf_band_attr->RFBand = value;
								if (wlFwSetWscIE(netdev, 0, (WSC_COMB_IE_t *) & vmacSta_p->thisbeaconIEs)) {
									printk("Error: Setting Beacon WSC IE\n");
									rc = -EFAULT;
									break;
								}
							}
						} else {
							printk("Error: No WPS IE in beacon\n");
							rc = -EFAULT;
							break;
						}
					} else {
						printk("Error: thisbeaconIEs is Empty\n");
						rc = -EFAULT;
						break;
					}

					wsc_ie = NULL;
					wps_rf_band_attr = NULL;
					lenOffset = 0;
					if (vmacSta_p->thisprobeRespIEs.Len != 0) {
						wsc_ie =
						    FindIEWithinIEs(vmacSta_p->thisprobeRespIEs.WSCData, vmacSta_p->thisprobeRespIEs.Len,
								    PROPRIETARY_IE, WPS_OUI);
						if (wsc_ie) {
							wsc_ie_len = *(wsc_ie + 1);
							wps_rf_band_attr =
							    FindAttributeWithinWPSIE(wsc_ie + sizeof(IEEEtypes_InfoElementHdr_t) + WSC_OUI_LENGTH,
										     wsc_ie_len - WSC_OUI_LENGTH, WSC_RF_BAND_ATTRB);
							if (wps_rf_band_attr) {
								wps_rf_band_attr->RFBand = value;
								if (wlFwSetIEs(netdev)) {
									printk("Error: No WPS IE in thisprobeRespIEs\n");
									rc = -EFAULT;
									break;
								}
							}
						} else {
							printk("Error: No WPS IE in thisprobeRespIEs\n");
							rc = -EFAULT;
							break;
						}
					} else {
						printk("Error: thisprobeRespIEs is Empty\n");
						rc = -EFAULT;
						break;
					}
				}
				vmacSta_p->wps_rf_band = value;
			}
#endif
			else {
				rc = -EFAULT;
				break;
			}
		}
		break;

	case WL_IOCTL_SET_MGMT_SEND:
		{
#ifdef SOC_W906X
			struct wlreq_set_mlme_send *frm = (struct wlreq_set_mlme_send *)param_str;
			UINT8 *ptr;
			struct sk_buff *txSkb_p = wl_alloc_skb(frm->len + 64);

			if (txSkb_p) {
				memcpy(txSkb_p->data, frm->buf, 24);
				memcpy(txSkb_p->data + 30, &frm->buf[24], frm->len - 24);
				ptr = txSkb_p->data - 2;
				ptr[0] = (frm->len + 6) >> 8;
				ptr[1] = (frm->len + 6);
				skb_put(txSkb_p, frm->len + 6);

				if (txMgmtMsg(vmacSta_p->dev, txSkb_p) != OS_SUCCESS)
					wl_free_skb(txSkb_p);
			}
#else
			struct wlreq_set_mlme_send *frm = (struct wlreq_set_mlme_send *)param_str;
#ifdef BAND_STEERING
			IEEEtypes_Frame_t *wlanMsg_p;
			UINT8 bctAddr[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
			wlanMsg_p = (IEEEtypes_Frame_t *) frm;

			if (memcmp(wlanMsg_p->Hdr.Addr1, vmacSta_p->macBssId, 6) == 0 || memcmp(wlanMsg_p->Hdr.Addr1, bctAddr, 6) == 0) {
				struct sk_buff *skb = wl_alloc_skb(frm->len + 2);
				if (skb == NULL) {
					printk("band steering alloc skb failed\n");
					break;
				}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
				if (skb_linearize(skb))
#else
				if (skb_linearize(skb, GFP_ATOMIC))
#endif
				{
					wl_free_skb(skb);
					printk("band steer linearize skb failed\n");
					break;
				}

				memcpy(skb->data + 2, frm->buf, frm->len);
				skb_put(skb, frm->len + 2);
				skb_pull(skb, 2);

				wlanMsg_p = (IEEEtypes_Frame_t *) ((UINT8 *) skb->data - 2);
				wlanMsg_p->Hdr.FrmBodyLen = skb->len;

				switch (wlanMsg_p->Hdr.FrmCtl.Subtype) {
					extern SINT8 evtDot11MgtMsg(vmacApInfo_t * vmacSta_p, UINT8 * message, struct sk_buff *skb, UINT32 rssi);
				case IEEE_MSG_PROBE_RQST:
					if (memcmp(wlanMsg_p->Hdr.Addr1, bctAddr, 6) == 0)
						memcpy(wlanMsg_p->Hdr.Addr1, vmacSta_p->macBssId, 6);
					macMgmtMlme_ProbeRqst(vmacSta_p, (macmgmtQ_MgmtMsg3_t *) wlanMsg_p);
					break;
				case IEEE_MSG_AUTHENTICATE:
					evtDot11MgtMsg(vmacSta_p, (UINT8 *) wlanMsg_p, skb, 0);
					break;
				default:
					break;
				}
				wl_free_skb(skb);
			} else
#endif
			{
				UINT8 *ptr;
				IEEEtypes_Frame_t *wlanMsg_p;
				struct sk_buff *txSkb_p = wl_alloc_skb(frm->len + 64);
				memcpy(txSkb_p->data, frm->buf, 24);
				memcpy(txSkb_p->data + 30, &frm->buf[24], frm->len - 24);
				ptr = txSkb_p->data - 2;
				ptr[0] = (frm->len + 6) >> 8;
				ptr[1] = (frm->len + 6);
				skb_put(txSkb_p, frm->len + 6);

				wlanMsg_p = (IEEEtypes_Frame_t *) ((UINT8 *) txSkb_p->data - 2);

				if (wlanMsg_p->Hdr.FrmCtl.Subtype == IEEE_MSG_AUTHENTICATE) {
					extern extStaDb_StaInfo_t *macMgtStaDbInit(vmacApInfo_t * vmacSta_p, IEEEtypes_MacAddr_t * staMacAddr,
										   IEEEtypes_MacAddr_t * apMacAddr);
					extern void macMgmtRemoveSta(vmacApInfo_t * vmacSta_p, extStaDb_StaInfo_t * StaInfo_p);
					extStaDb_StaInfo_t *pStaInfo;
					macmgmtQ_MgmtMsg3_t *MgmtMsg_p = (macmgmtQ_MgmtMsg3_t *) wlanMsg_p;

					if ((pStaInfo = extStaDb_GetStaInfo(vmacSta_p, &wlanMsg_p->Hdr.Addr1, STADB_DONT_UPDATE_AGINGTIME)) == NULL) {
						//added call to check other VAP's pStaInfo
						if ((pStaInfo = extStaDb_GetStaInfo(vmacSta_p, &wlanMsg_p->Hdr.Addr1, STADB_SKIP_MATCH_VAP)))
							macMgmtRemoveSta(vmacSta_p, pStaInfo);
						if ((pStaInfo =
						     macMgtStaDbInit(vmacSta_p, &wlanMsg_p->Hdr.Addr1,
								     (IEEEtypes_MacAddr_t *) vmacSta_p->macBssId)) == NULL) {
							wl_free_skb(txSkb_p);
							WLDBG_ENTER_INFO(DBG_LEVEL_11, "init data base fail\n");
							return -1;
						}
					}

					if (MgmtMsg_p->Body.Auth.AuthAlg == 0x03 &&
					    MgmtMsg_p->Body.Auth.AuthTransSeq == 0x02 && MgmtMsg_p->Body.Auth.StatusCode == 0x00) {
						if (pStaInfo->State != ASSOCIATED)
							pStaInfo->State = AUTHENTICATED;
					}
				}
#ifdef OWE_SUPPORT
				if ((wlanMsg_p->Hdr.FrmCtl.Subtype == IEEE_MSG_ASSOCIATE_RSP)
				    || (wlanMsg_p->Hdr.FrmCtl.Subtype == IEEE_MSG_REASSOCIATE_RSP)) {
					extern SINT8 evtDot11MgtMsg(vmacApInfo_t * vmacSta_p, UINT8 * message, struct sk_buff *skb, UINT32 rssi);
					IEEEtypes_Frame_t *Msg_p;
					UINT8 *temp_p = NULL;
					extStaDb_StaInfo_t *pStaInfo;
					macmgmtQ_MgmtMsg3_t *MgmtMsg_p = (macmgmtQ_MgmtMsg3_t *) wlanMsg_p;

					pStaInfo = extStaDb_GetStaInfo(vmacSta_p, &wlanMsg_p->Hdr.Addr1, STADB_DONT_UPDATE_AGINGTIME);
					temp_p =
					    FindIEWithinIEs(&wlanMsg_p->Body[0] + 6, frm->len - 6 - sizeof(IEEEtypes_GenHdr_t) + sizeof(UINT16),
							    EXTENSION, NULL);
					if (temp_p) {
						memcpy(&pStaInfo->AP_DHIEBuf[0], temp_p, *(temp_p + 1) + 2);
					}

					memset(pStaInfo->EXT_RsnIE, 0, 64);
					temp_p =
					    FindIEWithinIEs(&wlanMsg_p->Body[0] + 6, frm->len - 6 - sizeof(IEEEtypes_GenHdr_t) + sizeof(UINT16),
							    RSN_IEWPA2, NULL);
					if (temp_p) {
						memcpy(&pStaInfo->EXT_RsnIE[0], temp_p, *(temp_p + 1) + 2);
					}

					Msg_p = (IEEEtypes_Frame_t *) ((UINT8 *) pStaInfo->assocReq_skb->data - 2);
					Msg_p->Hdr.FrmBodyLen = pStaInfo->assocReq_skb->len;

					if (MgmtMsg_p->Body.AssocRsp.StatusCode == IEEEtypes_STATUS_SUCCESS)
						evtDot11MgtMsg(vmacSta_p, (UINT8 *) Msg_p, pStaInfo->assocReq_skb, pStaInfo->assocReq_skb_rssi);

					wl_free_skb(pStaInfo->assocReq_skb);
					pStaInfo->assocReq_skb = NULL;

					if (MgmtMsg_p->Body.AssocRsp.StatusCode == IEEEtypes_STATUS_SUCCESS) {
						wl_free_skb(txSkb_p);
						return 0;
					}
				}
#endif				/* OWE_SUPPORT */

				if (txMgmtMsg(vmacSta_p->dev, txSkb_p) != OS_SUCCESS)
					wl_free_skb(txSkb_p);
			}
#endif
		}
		break;

	case WL_IOCTL_SET_APPIE:
		{
			struct wlreq_set_appie *appie = (struct wlreq_set_appie *)param_str;

			rc = mwl_config_set_appie(netdev, appie);

#ifdef SOC_W906X
			/* update probeResp WSCIE */
			if (appie->appFrmType == WL_APPIE_FRAMETYPE_PROBE_RESP)
				wlFwSetIEs(netdev);
#endif
		}

		break;

#ifdef MRVL_WAPI
		/* allow multiple IEs, all contents are prepared by upper layer (caller), can be used for generic IE */
	case WL_IOCTL_SET_WAPI:
		{
			WAPI_COMB_IE_t WAPIIE;
			UINT16 ieType = 0;
			struct wlreq_set_appie *appie = (struct wlreq_set_appie *)param_str;

			/* Note: parame_str points to ioctl data from wapid:
			   u32  io_packet;
			   struct  _iodata
			   {
			   u32 wDataLen;
			   char pbData[96];
			   }iodata;

			   use wlreq_set_appie to parse the data because its data struct is same.
			 */

			/* wapi ioctl (from wapid to driver) coming in */

			memset(&WAPIIE, 0, sizeof(WAPI_COMB_IE_t));

			if (appie == NULL) {
				break;
			}

			if (appie->appFrmType == P80211_PACKET_WAPIFLAG) {
				mib->Privacy->WAPIEnabled = 1;
				vmacSta_p->Mib802dot11->Privacy->WAPIEnabled = 1;
				wlFwSetApBeacon(netdev);
			} else if (appie->appFrmType == P80211_PACKET_SETKEY) {
#ifdef SOC_W906X
				struct wlreq_wapi_key *wk = (struct wlreq_wapi_key *)appie->appBuf;
				UINT32 keyInfo = ENCR_KEY_FLAG_PTK;
				WAPI_TYPE_KEY param;

				/* for mcst key, use bssid to replace bcast MAC */
				if (memcmp(wk->ik_macaddr, bcastMacAddr, 6) == 0) {
					memcpy(wk->ik_macaddr, vmacSta_p->macBssId, 6);
					keyInfo = ENCR_KEY_FLAG_GTK_RX_KEY | ENCR_KEY_FLAG_GTK_TX_KEY;
				}
				memcpy(aram.KeyMaterial, wk->ik_keydata, WAPI_KEY_LENGTH);
				memcpy(param.MicKeyMaterial, wk->ik_keydata[WAPI_KEY_LENGTH], WAPI_KEY_LENGTH);

				wlPrintData(DBG_LEVEL_1 | DBG_CLASS_DATA, __FUNCTION__, wk->ik_keydata, 32, NULL);

				/* appie->appBuf = wapid's pbData: MAC + 1 + Keyindex + key + key-mic */
				if (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_AP) {
					wlFwSetSecurityKey(dev, ACT_SET, KEY_TYPE_ID_WAPI,
							   wk->ik_macaddr, wk->ik_keyid, wk->ik_keylen, keyInfo, (UINT8 *) & param);
				}
#else
				struct wlreq_wapi_key *wk = (struct wlreq_wapi_key *)appie->appBuf;
				int gkey = 0;
				extern int wlFwSetWapiKey(struct net_device *netdev, struct wlreq_wapi_key *wapi_key, int groupkey);

				/* for mcst key, use bssid to replace bcast MAC */
				if (memcmp(wk->ik_macaddr, bcastMacAddr, 6) == 0) {
					memcpy(wk->ik_macaddr, vmacSta_p->macBssId, 6);
					gkey = 1;
				}

				wlPrintData(DBG_LEVEL_1 | DBG_CLASS_DATA, __FUNCTION__, wk->ik_keydata, 32, NULL);

				/* appie->appBuf = wapid's pbData: MAC + 1 + Keyindex + key + key-mic */
				if (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_AP) {
					wlFwSetWapiKey(netdev, wk, gkey);
				}
#endif
#ifdef CLIENT_SUPPORT
				/* to do */
#endif

				break;
			} else if (appie->appFrmType == WL_APPIE_FRAMETYPE_BEACON && (appie->appBufLen > 8)) {
				ieType = 0;
				WAPIIE.beaconIE.Len = appie->appBufLen;	// the len already counts IE-id and IE-length (1 byte each)
				memcpy(&WAPIIE.beaconIE.WAPIData[0], &appie->appBuf[0], appie->appBufLen);
				memcpy(&vmacSta_p->thisbeaconIEs, &WAPIIE.beaconIE, sizeof(WAPI_BeaconIEs_t));
			} else if (appie->appFrmType == WL_APPIE_FRAMETYPE_PROBE_RESP && (appie->appBufLen > 8)) {
				ieType = 1;
				WAPIIE.probeRespIE.Len = appie->appBufLen;
				memcpy(&WAPIIE.probeRespIE.WAPIData[0], &appie->appBuf[0], appie->appBufLen);
				memcpy(&vmacSta_p->thisprobeRespIEs, &WAPIIE.probeRespIE, sizeof(WAPI_ProbeRespIEs_t));
			} else {
				break;
			}

			if (wlFwSetWapiIE(netdev, ieType, &WAPIIE)) {
				WLDBG_EXIT_INFO(DBG_LEVEL_1, "Failed setting APPS IE");
			}
		}
		break;
#endif				//MRVL_WAPI

	default:

		if (cmd >= SIOCSIWCOMMIT && cmd <= SIOCGIWPOWER) {
			rc = -EOPNOTSUPP;
			break;
		}

		PRINT1(IOCTL, "unsupported ioctl(0x%04x)\n", cmd);

		rc = -EOPNOTSUPP;

		break;

	}

	if (ret_str != NULL) {
		if (copy_to_user(ret_str, bufBack, *ret_len)) {
			rc = -EFAULT;
		}
	}

	WLDBG_EXIT(DBG_LEVEL_1);
	wl_kfree(param);
	return rc;
}

ssize_t ap8xLnxStat_clients_rxrate(struct net_device * netdev, UINT8 * macAddr, char *buf);
char *ap8xLnxStat_get_client_mode_str(extStaDb_StaInfo_t * pStaInfo, MIB_802DOT11 * mib);

int wlIoctlGet(struct net_device *netdev, int cmd, char *param_str, int param_len, char *ret_str, UINT16 * ret_len)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	int rc = 0;
	char *buf = cmdGetBuf;
	char param[MAX_IOCTL_PARAMS][MAX_IOCTL_PARAM_LEN];
	struct wlprivate_data *wlpd_p = priv->wlpd_p;
	char *logbuf;
	UINT32 size;

#ifdef MPRXY
	UINT32 tempIPAddr;
	UINT8 *tmpStr = NULL;
	UINT32 i, j;
#endif

	WLDBG_IOCTL(DBG_LEVEL_0, "%s:wlioctlGet cmd:0x%x, CpuID:%u, PID:%i, ProcName:\"%s\"\n",
		    netdev->name, cmd, smp_processor_id(), current->pid, current->comm);

#ifdef SOC_W906X
	if (wlpd_p->smon.active) {
		UINT64 tms, tsec;

		logbuf = wl_vzalloc(256);
		if (NULL == logbuf)
			return -EFAULT;

		convert_tscale(xxGetTimeStamp(), &tsec, &tms, NULL);
		size = (UINT32) sprintf(&logbuf[0], "[%llu.%llu]: %s:wlioctlGet cmd:0x%x, CpuID:%u, PID:%i, ProcName:\"%s\"\n", tsec, tms,
					netdev->name, cmd, smp_processor_id(), current->pid, current->comm);
		wlmon_log_buffer(netdev, logbuf, size);
		wl_vfree(logbuf);
	}
#endif				/* SOC_W906X */

	WLDBG_ENTER(DBG_LEVEL_1);
	switch (cmd) {
	case WL_IOCTL_GET_VERSION:
		{
			int more = 0;

			sscanf(param_str, "%64s", param[0]);
			if (strcmp(param[0], "all") == 0)
				more = 1;

			wlget_sw_version(priv, buf, more);
		}

		break;
	case WL_IOCTL_GET_TXRATE:
		{
			int b_rate = 2, g_rate = 2, n_rate = 0, a_rate, vht_rate, m_rate, manage_rate, i = 0;
			char *p = buf;
			int rateMask;
#ifdef CONFIG_MC_BC_RATE
			UINT32 mc_rate = 0, bc_rate = 0;
#endif

			if (*(mib->mib_enableFixedRateTx) == 0) {
				sprintf(buf, "Auto Rate\n");
			} else {
				b_rate = *(mib->mib_txDataRate);
				g_rate = *(mib->mib_txDataRateG);
				a_rate = *(mib->mib_txDataRateA);
				vht_rate = *(mib->mib_txDataRateVHT);
				n_rate = *(mib->mib_txDataRateN) + 256;

				sprintf(buf, "B Rate: %d, G Rate: %d, A Rate: %d, N Rate: %d, vht Rate: 0x%x\n", b_rate, g_rate, a_rate, n_rate,
					vht_rate);
			}
			if (*(mib->mib_MultiRateTxType) == 2)
				m_rate = *(mib->mib_MulticastRate) + 512;
			else if (*(mib->mib_MultiRateTxType) == 1)
				m_rate = *(mib->mib_MulticastRate) + 256;
			else
				m_rate = *(mib->mib_MulticastRate);
			manage_rate = *(mib->mib_ManagementRate);
			p += strlen(buf);
			sprintf(p, "Multicast Rate: %d, Management Rate: %d\n", m_rate, manage_rate);
#ifdef CONFIG_MC_BC_RATE
			mc_rate = *(mib->mib_mcDataRateInfo);
			p = buf + strlen(buf);
			sprintf(p, "Multicast RateInfo: 0x%08x\n", mc_rate);

			bc_rate = *(mib->mib_bcDataRateInfo);
			p = buf + strlen(buf);
			sprintf(p, "Broadcast RateInfo: 0x%08x\n", bc_rate);
#endif
#ifdef BRS_SUPPORT
			p = buf + strlen(buf);
			sprintf(p, "BSS Basic Rate: ");

			p = buf + strlen(buf);

			rateMask = *(mib->BssBasicRateMask);
			i = 0;
			while (rateMask) {
				if (rateMask & 0x01) {
					if (mib->StationConfig->OpRateSet[i]) {
						sprintf(p, "%d ", mib->StationConfig->OpRateSet[i]);
						p = buf + strlen(buf);
					}
				}
				rateMask >>= 1;
				i++;
			}

			p = buf + strlen(buf);
			sprintf(p, "\nNot BSS Basic Rate: ");

			p = buf + strlen(buf);
			rateMask = *(mib->NotBssBasicRateMask);
			i = 0;
			while (rateMask) {
				if (rateMask & 0x01) {
					if (mib->StationConfig->OpRateSet[i]) {
						sprintf(p, "%d ", mib->StationConfig->OpRateSet[i]);
						p = buf + strlen(buf);
					}
				}
				rateMask >>= 1;
				i++;
			}
#endif
		}
		break;

	case WL_IOCTL_GET_CIPHERSUITE:
		sprintf(buf, "\n");
		if (mib->RSNConfigWPA2->WPA2Enabled && !mib->RSNConfigWPA2->WPA2OnlyEnabled) {
			strcat(buf, "Mixed Mode  ");
			if (mib->UnicastCiphers->UnicastCipher[3] == 0x02)
				strcat(buf, "wpa:tkip  ");
			else if (mib->UnicastCiphers->UnicastCipher[3] == 0x04)
				strcat(buf, "wpa:aes  ");
			else
				strcat(buf, "wpa:  ciphersuite undefined ");

			if (mib->WPA2UnicastCiphers->UnicastCipher[3] == 0x04)
				strcat(buf, "wpa2:aes  ");
			else if (mib->WPA2UnicastCiphers->UnicastCipher[3] == 0x02)
				strcat(buf, "wpa2:tkip  ");
			else
				strcat(buf, "wpa2:ciphersuite undefined  ");

			if (mib->RSNConfig->MulticastCipher[3] == 0x02)
				strcat(buf, "multicast:tkip \n");
			else if (mib->RSNConfig->MulticastCipher[3] == 0x04)
				strcat(buf, "multicast:aes \n");
			else
				strcat(buf, "multicast:ciphersuite undefined \n");
		} else {
			if ((mib->UnicastCiphers->UnicastCipher[3] == 0x02) && (mib->RSNConfig->MulticastCipher[3] == 0x02))
				strcat(buf, "wpa:tkip  ");
			else if ((mib->UnicastCiphers->UnicastCipher[3] == 0x04) && (mib->RSNConfig->MulticastCipher[3] == 0x04))
				strcat(buf, "wpa:aes  ");
			else
				strcat(buf, "wpa:ciphersuite undefined  ");

			if ((mib->WPA2UnicastCiphers->UnicastCipher[3] == 0x04) && (mib->RSNConfigWPA2->MulticastCipher[3] == 0x04))
				strcat(buf, "wpa2:aes \n");
			else if ((mib->WPA2UnicastCiphers->UnicastCipher[3] == 0x02) && (mib->RSNConfigWPA2->MulticastCipher[3] == 0x02))
				strcat(buf, "wpa2:tkip \n");
			else
				strcat(buf, "wpa2:ciphersuite undefined \n");
		}

		break;

	case WL_IOCTL_GET_PASSPHRASE:
		sprintf(buf, "wpa: %s, wpa2: %s\n", mib->RSNConfig->PSKPassPhrase, mib->RSNConfigWPA2->PSKPassPhrase);
		break;

	case WL_IOCTL_GET_FILTERMAC:
		{
			UCHAR buf1[48], *filter_buf = mib->mib_wlanfiltermac;
			char *out_buf = buf;
			int i;

			sprintf(out_buf, "\n");
			out_buf++;
			for (i = 0; i < FILERMACNUM; i++) {
				sprintf(buf1, "MAC %d: %02x:%02x:%02x:%02x:%02x:%02x\n", (i + 1), *(filter_buf + i * 6),
					*(filter_buf + i * 6 + 1), *(filter_buf + i * 6 + 2), *(filter_buf + i * 6 + 3),
					*(filter_buf + i * 6 + 4), *(filter_buf + i * 6 + 5));
				sprintf(out_buf, "%s", buf1);
				out_buf += strlen(buf1);
			}

		}
		break;

	case WL_IOCTL_GET_BSSID:
		{
			MIB_OP_DATA *mib_OpData = mib->OperationTable;

			sprintf(buf, "MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
				mib_OpData->StaMacAddr[0],
				mib_OpData->StaMacAddr[1],
				mib_OpData->StaMacAddr[2], mib_OpData->StaMacAddr[3], mib_OpData->StaMacAddr[4], mib_OpData->StaMacAddr[5]);

		}
		break;

	case WL_IOCTL_GET_WMMEDCAAP:
		{
			extern mib_QAPEDCATable_t mib_QAPEDCATable[4];
			int cw_min, cw_max, aifsn, tx_op_lim_b, tx_op_lim;
			char strName[4][6] = { "AC_BE", "AC_BK", "AC_VI", "AC_VO" };
			char *strBuf = buf;
			int i, strlen = 0;

			for (i = 0; i < 4; i++) {
				cw_min = mib_QAPEDCATable[i].QAPEDCATblCWmin;
				cw_max = mib_QAPEDCATable[i].QAPEDCATblCWmax;
				aifsn = mib_QAPEDCATable[i].QAPEDCATblAIFSN;
				tx_op_lim = mib_QAPEDCATable[i].QAPEDCATblTXOPLimit;
				tx_op_lim_b = mib_QAPEDCATable[i].QAPEDCATblTXOPLimitBAP;
				strlen +=
				    sprintf(strBuf + strlen, "\n%s %d %d %d %d %d\n", strName[i], cw_min, cw_max, aifsn, tx_op_lim_b, tx_op_lim);
			}
		}
		break;

	case WL_IOCTL_GET_WMMEDCASTA:
		{
			extern mib_QStaEDCATable_t mib_QStaEDCATable[4];
			int cw_min, cw_max, aifsn, tx_op_lim_b, tx_op_lim, acm;
			char strName[4][6] = { "AC_BE", "AC_BK", "AC_VI", "AC_VO" };
			char *strBuf = buf;
			int i, strlen = 0;

			for (i = 0; i < 4; i++) {
				cw_min = mib_QStaEDCATable[i].QStaEDCATblCWmin;
				cw_max = mib_QStaEDCATable[i].QStaEDCATblCWmax;
				aifsn = mib_QStaEDCATable[i].QStaEDCATblAIFSN;
				tx_op_lim = mib_QStaEDCATable[i].QStaEDCATblTXOPLimit;
				tx_op_lim_b = mib_QStaEDCATable[i].QStaEDCATblTXOPLimitBSta;
				acm = mib_QStaEDCATable[i].QStaEDCATblMandatory;
				strlen +=
				    sprintf(strBuf + strlen, "\n%s %d %d %d %d %d %d\n", strName[i], cw_min, cw_max, aifsn, tx_op_lim_b, tx_op_lim,
					    acm);
			}
		}
		break;
	case WL_IOCTL_GET_STALISTEXT:
		{
			UCHAR *sta_buf, *show_buf, buf1[512];
			char *out_buf = buf;
			int i = 0, entries;
			extStaDb_StaInfo_t *pStaInfo;
			char tmpBuf[48];
#ifdef SOC_W906X
			s16 rssi_value_signed[MAX_RF_ANT_NUM] = { 0 };
			SMAC_STA_STATISTICS_st StaStatsTbl;
			u32 tx_err, tx_retries, rx_err, tx_fail_retry, tx_succ_one_retry, tx_succ_multi_retry, retried, tx_retried_last_100;
#else
			u16 a, b, c, d;
#endif
			entries = extStaDb_entries(vmacSta_p, 0);

			sta_buf = wl_kmalloc(entries * 64, GFP_KERNEL);
			if (sta_buf == NULL) {
				rc = -EFAULT;
				break;
			}

			extStaDb_list(vmacSta_p, sta_buf, 1);

			if (entries) {
				show_buf = sta_buf;
				sprintf(out_buf, "\n");
				out_buf++;
				for (i = 0; i < entries; i++) {
					U8 macAddr[6];

					if ((pStaInfo =
					     extStaDb_GetStaInfo(vmacSta_p, (IEEEtypes_MacAddr_t *) show_buf, STADB_DONT_UPDATE_AGINGTIME)) == NULL) {
						wl_kfree(sta_buf);
						rc = -EFAULT;
						return rc;
					}
					memcpy(&macAddr, show_buf, sizeof(U8) * 6);
					memset(tmpBuf, 0, sizeof(tmpBuf));
					strcpy(&tmpBuf[0], ap8xLnxStat_get_client_mode_str(pStaInfo, mib));

					switch (pStaInfo->State) {

					case UNAUTHENTICATED:
						strcat(tmpBuf, "UNAUTHENTICATED ");
						break;

					case SME_INIT_AUTHENTICATING:
					case EXT_INIT_AUTHENTICATING:
						strcat(tmpBuf, "AUTHENTICATING ");
						break;

					case AUTHENTICATED:
						strcat(tmpBuf, "AUTHENTICATED ");
						break;

					case SME_INIT_DEAUTHENTICATING:
					case EXT_INIT_DEAUTHENTICATING:
						strcat(tmpBuf, "DEAUTHENTICATING ");
						break;

					case SME_INIT_ASSOCIATING:
					case EXT_INIT_ASSOCIATING:
						strcat(tmpBuf, "ASSOCIATING ");
						break;

					case ASSOCIATED:
						{
							int flagPsk = 0;
							if ((mib->Privacy->RSNEnabled == 1) || (mib->RSNConfigWPA2->WPA2Enabled == 1)) {

								if (*(mib->mib_wpaWpa2Mode) < 4) {	/* For PSK modes use internal WPA state machine */
									if (pStaInfo->keyMgmtHskHsm.super.pCurrent != NULL) {
										if (pStaInfo->keyMgmtHskHsm.super.pCurrent ==
										    &pStaInfo->keyMgmtHskHsm.hsk_end) {
											strcat(tmpBuf, "PSK-PASSED ");
											flagPsk = 1;
										}
									}
								} else if (pStaInfo->keyMgmtStateInfo.RSNDataTrafficEnabled == TRUE) {
									strcat(tmpBuf, "KEY_CONFIGURED ");
									flagPsk = 1;
								}
							}
							if (!flagPsk)
								strcat(tmpBuf, "ASSOCIATED ");
						}
						break;

					case SME_INIT_REASSOCIATING:
					case EXT_INIT_REASSOCIATING:
						strcat(tmpBuf, "REASSOCIATING ");
						break;

					case SME_INIT_DEASSOCIATING:
					case EXT_INIT_DEASSOCIATING:
						strcat(tmpBuf, "DEASSOCIATING ");
						break;
					default:
						break;
					}
#ifdef SOC_W906X
					wl_util_get_rssi(netdev, &pStaInfo->RSSI_path, rssi_value_signed);
					memset(&StaStatsTbl, 0, sizeof(SMAC_STA_STATISTICS_st));
					if (wlFwGetStaStats(netdev, pStaInfo->StnId, &StaStatsTbl) != SUCCESS) {
						WLDBG_INFO(DBG_LEVEL_1, "cannot get StnId %d stats from fw%d\n", pStaInfo->StnId);
						break;
					}
					tx_retries = StaStatsTbl.dot11RetryCount;
					tx_err = StaStatsTbl.dot11MPDUCount - StaStatsTbl.dot11SuccessCount - StaStatsTbl.dot11RetryCount;
					rx_err = StaStatsTbl.dot11FCSErrorCount;
					tx_fail_retry = StaStatsTbl.dot11FailedRertransCount;
					tx_succ_one_retry = StaStatsTbl.dot11RetryCount_1;
					tx_succ_multi_retry = StaStatsTbl.dot11MultipleRetryCount;

					retried = StaStatsTbl.dot11FailedRertransCount + StaStatsTbl.dot11RetryCount_1;
					if (pStaInfo->tx_packets < 100)
						tx_retried_last_100 = retried;
					else if (pStaInfo->tx_packets - pStaInfo->tx_packets_sampled >= 100)
						tx_retried_last_100 = min((u32) (retried - pStaInfo->tx_retried_sampled), (u32) 100);
					else {
						u32 updated = pStaInfo->tx_packets - pStaInfo->tx_packets_sampled;

						tx_retried_last_100 =
						    pStaInfo->tx_retried_last_100 * (100 - updated) + (retried -
												       pStaInfo->tx_retried_sampled) * updated;
						tx_retried_last_100 /= 100;
					}
					sprintf(buf1,
						"%d: StnId %d Aid %d %02x:%02x:%02x:%02x:%02x:%02x %s TxRate %d Mbps, RxRate %d Mbps, RSSI:A %d  B %d  C %d  D %d E %d  F %d  G %d  H %d, txpkt %d txbytes %lld rxpkt %d rxbytes %lld txError %d txRetries %d txFailRetry %d txSuccOneRetry %d txSuccMultiRetry %d rxError %d txLastRetried %d\n",
						i + 1, pStaInfo->StnId, pStaInfo->Aid, *show_buf, *(show_buf + 1), *(show_buf + 2), *(show_buf + 3),
						*(show_buf + 4), *(show_buf + 5), tmpBuf,
						//pStaInfo->RateInfo.RateIDMCS,
						(int)getPhyRate((dbRateInfo_t *) & (pStaInfo->RateInfo)),
						(int)getPhyRate((dbRateInfo_t *) & (pStaInfo->rx_info_aux.rate_info)),
						rssi_value_signed[0], rssi_value_signed[1], rssi_value_signed[2], rssi_value_signed[3],
						rssi_value_signed[4], rssi_value_signed[5], rssi_value_signed[6], rssi_value_signed[7],
						pStaInfo->tx_packets, pStaInfo->tx_bytes, pStaInfo->rx_packets, pStaInfo->rx_bytes, tx_err,
						tx_retries, tx_fail_retry, tx_succ_one_retry, tx_succ_multi_retry, rx_err, tx_retried_last_100);
#else
					a = pStaInfo->RSSI_path.a;
					b = pStaInfo->RSSI_path.b;
					c = pStaInfo->RSSI_path.c;
					d = pStaInfo->RSSI_path.d;
					if (a >= 2048 && b >= 2048 && c >= 2048 && d >= 2048) {
						a = ((4096 - a) >> 4);
						b = ((4096 - b) >> 4);
						c = ((4096 - c) >> 4);
						d = ((4096 - d) >> 4);
					}
					sprintf(buf1,
						"%d: StnId %d Aid %d %02x:%02x:%02x:%02x:%02x:%02x %s Rate %d Mbps, RSSI:A -%d  B -%d  C -%d  D -%d, txpkt %d txbytes %lld rxpkt %d rxbytes %lld\n",
						i + 1, pStaInfo->StnId, pStaInfo->Aid, *show_buf, *(show_buf + 1), *(show_buf + 2), *(show_buf + 3),
						*(show_buf + 4), *(show_buf + 5), tmpBuf,
						//pStaInfo->RateInfo.RateIDMCS,
						(int)getPhyRate((dbRateInfo_t *) & (pStaInfo->RateInfo)),
						a, b, c, d, pStaInfo->tx_packets, pStaInfo->tx_bytes, pStaInfo->rx_packets, pStaInfo->rx_bytes);
#endif

					show_buf += sizeof(STA_INFO);

/* Define SHOW_STA_IN_KERNEL to print the STA info in kernel's log buffer.
 * Since the max buffer from iwpriv is only 4KB, the returned data exceeding 4KB will cause iwpriv segmentation fault.
 */
#define SHOW_STA_IN_KERNEL

					if (param_str == NULL) {
						strcpy(out_buf, buf1);
						out_buf += strlen(buf1);
					} else {
						printk("%s", buf1);
					}
					memset(buf1, 0, sizeof(buf1));
					ap8xLnxStat_clients_rxrate(netdev, macAddr, buf1);
					printk("%s", buf1);

				}
			} else {
				out_buf[0] = 0;
			}
			sprintf(out_buf, "Total %d Stations connected\n", i);
			wl_kfree(sta_buf);
		}
		break;

	case WL_IOCTL_GET_TXPOWER:
		{
			int i;
			char *out_buf = buf;
#if defined(EEPROM_REGION_PWRTABLE_SUPPORT)
			int j, k;
			int status = 0xFF;
			UINT8 region_code = 0;
			UINT8 number_of_channels = 0;	// number of channels in EEPROM region power table to fetch
			channel_power_tbl_t EEPROM_Channel_PwrTbl;

			// Clear out
			memset(&EEPROM_Channel_PwrTbl, 0x0, sizeof(channel_power_tbl_t));

			// Get preliminary data back first
#ifdef SOC_W906X
			status = wlFwGet_EEPROM_PwrTbl(netdev, &EEPROM_Channel_PwrTbl, &region_code, &number_of_channels, 0);
#else
			status = wlFwGet_Device_PwrTbl(netdev, &EEPROM_Channel_PwrTbl, &region_code, &number_of_channels, 0);
#endif
			if (status != SUCCESS) {
				printk("\nUnable to get EEPROM Power Table! Error: 0x%02x\n", status);
			} else {
				printk("\nRegion Code: %d\n", region_code);
				printk("Number of Channels: %d\n\n", number_of_channels);
				for (j = 0; j < number_of_channels; j++) {
					// Fetch channel data from FW
#ifdef SOC_W906X
					status = wlFwGet_EEPROM_PwrTbl(netdev, &EEPROM_Channel_PwrTbl, &region_code, &number_of_channels, j);
#else
					status = wlFwGet_Device_PwrTbl(netdev, &EEPROM_Channel_PwrTbl, &region_code, &number_of_channels, j);
#endif
					if (status != SUCCESS) {
						printk("\nUnable to get Channel Index %d! Error: 0x%02x\n", j, status);
						continue;
					}
					printk("\n%d ", EEPROM_Channel_PwrTbl.channel);
					for (k = 0; k < MAX_GROUP_PER_CHANNEL_RATE; k++) {
						printk("%d ", (SINT8) EEPROM_Channel_PwrTbl.grpPwr[k]);
					}
					printk("\n");
					for (i = 0; i < HAL_TRPC_ID_MAX; i++) {
						printk("%d ", (SINT8) EEPROM_Channel_PwrTbl.txPwr[i]);
					}
					printk("\n%d ", EEPROM_Channel_PwrTbl.DFS_Capable);
					printk("%d ", EEPROM_Channel_PwrTbl.AxAnt);
					printk("%d ", EEPROM_Channel_PwrTbl.CDD);
					printk("%d\n", EEPROM_Channel_PwrTbl.rsvd);
				}
				printk("\n");
				sprintf(out_buf, "0x%02x\n", status);
				out_buf += strlen("0x00\n");
			}
#else
			UINT16 powlist[TX_POWER_LEVEL_TOTAL];
			UINT16 tmp_bw = mib->PhyDSSSTable->Chanflag.ChnlWidth;
			memset((void *)powlist, 0x00, sizeof(powlist));
			wlFwGettxpower(netdev, powlist, mib->PhyDSSSTable->CurrChan,
				       mib->PhyDSSSTable->Chanflag.FreqBand, tmp_bw, mib->PhyDSSSTable->Chanflag.ExtChnlOffset);
			sprintf(out_buf, "\nCurrent Channel Power level list (FW) :");
			out_buf += strlen("\nCurrent Channel Power level list (FW) :");
			for (i = 0; i < TX_POWER_LEVEL_TOTAL; i++) {
				sprintf(out_buf, "0x%02x ", powlist[i]);
				out_buf += strlen("0x00 ");
			}
			sprintf(out_buf, "\n");
			out_buf++;

#endif				//EEPROM_REGION_PWRTABLE_SUPPORT
		}
		break;

		/*MRV_8021X */

	case WL_IOCTL_GET_IE:
		{
			struct wlreq_ie IEReq;

			memset(IEReq.IE, 0, sizeof(IEReq.IE));
			memcpy(&IEReq, param_str, param_len);
			rc = mwl_config_get_ie(netdev, &IEReq, ret_len);
			if (rc)
				return rc;
			if (copy_to_user(ret_str, &IEReq, *ret_len))
				rc = -EFAULT;
			return rc;
		}
		break;

	case WL_IOCTL_GET_SCAN_BSSPROFILE:
		{
			scanDescptHdr_t *curDescpt_p = NULL;
			UINT16 parsedLen = 0;
			int i;

			PRINT1(IOCTL, "INSIDE getbssprofile\n");
			PRINT1(IOCTL, "Found :%d number of scan respults\n", tmpNumScanDesc[vmacSta_p->VMacEntry.phyHwMacIndx]);
			if (vmacSta_p->busyScanning) {
				rc = -EFAULT;
				break;
			}
			for (i = 0; i < tmpNumScanDesc[vmacSta_p->VMacEntry.phyHwMacIndx]; i++) {
				curDescpt_p = (scanDescptHdr_t *) (&tmpScanResults[vmacSta_p->VMacEntry.phyHwMacIndx][0] + parsedLen);

				if ((smeSetBssProfile(0,
						      curDescpt_p->bssId, &curDescpt_p->CapInfo,
						      (((UINT8 *) curDescpt_p) + sizeof(scanDescptHdr_t)),
						      curDescpt_p->length + sizeof(curDescpt_p->length) - sizeof(scanDescptHdr_t),
						      FALSE)) == MLME_SUCCESS) {
					memset(&siteSurveyEntry, 0, sizeof(MRVL_SCAN_ENTRY));
					//                      smeCopyBssProfile( 0, &siteSurvey[i] );
					smeCopyBssProfile(0, &siteSurveyEntry);
					/* Only accept if WPS IE is present */
					if (siteSurveyEntry.result.wps_ie_len > 0) {
						memcpy(&siteSurvey[i], &siteSurveyEntry, sizeof(MRVL_SCAN_ENTRY));
						PRINT1(IOCTL, "THE BSS PROFILE :[%02X:%02X:%02X:%02X:%02X:%02X]%d\n",
						       siteSurvey[i].result.bssid[0], siteSurvey[i].result.bssid[1],
						       siteSurvey[i].result.bssid[2], siteSurvey[i].result.bssid[3],
						       siteSurvey[i].result.bssid[4], siteSurvey[i].result.bssid[5], i);
					}
				}
				parsedLen += curDescpt_p->length + sizeof(curDescpt_p->length);
			}
			*ret_len = sizeof(MRVL_SCAN_ENTRY) * tmpNumScanDesc[vmacSta_p->VMacEntry.phyHwMacIndx];
			if (copy_to_user(ret_str, &siteSurvey[0], *ret_len))
				rc = -EFAULT;
			return rc;
		}
		break;

#ifdef WDS_FEATURE
	case WL_IOCTL_GET_WDS_PORT:
		{
			UINT8 index = 0;
			UINT8 wdsModeStr[20];
			char *out_buf = buf;
			sprintf(out_buf, "\n");
			out_buf += strlen(out_buf);
			for (index = 0; validWdsIndex(index); index++) {
				getWdsModeStr(wdsModeStr, priv->vmacSta_p->wdsPort[index].wdsPortMode);

				sprintf(out_buf, "ap0wds%x HWaddr %x:%x:%x:%x:%x:%x  802.%s Port %s \n",
					index,
					priv->vmacSta_p->wdsPort[index].wdsMacAddr[0],
					priv->vmacSta_p->wdsPort[index].wdsMacAddr[1],
					priv->vmacSta_p->wdsPort[index].wdsMacAddr[2],
					priv->vmacSta_p->wdsPort[index].wdsMacAddr[3],
					priv->vmacSta_p->wdsPort[index].wdsMacAddr[4],
					priv->vmacSta_p->wdsPort[index].wdsMacAddr[5],
					wdsModeStr, priv->vmacSta_p->wdsPort[index].active ? "Active" : "Inactive");
				out_buf += strlen(out_buf);
			}
		}
		break;
#endif
	case WL_IOCTL_GETCMD:
		{
			param_str[param_len] = '\0';
			*param[0] = '\0';
			*param[1] = '\0';
			*param[2] = '\0';
			sscanf(param_str, "%64s %64s %64s\n", param[0], param[1], param[2]);

			if ((strcmp(param[0], "getsysload") == 0)) {
				radio_cpu_load_t sys_load;

				if (wlFwGetSysLoad(netdev, &sys_load) == SUCCESS)
					printk("1s:%d 4s:%d 8s:%d 16s:%d\n", sys_load.load_onesec, sys_load.load_foursec, sys_load.load_eightsec,
					       sys_load.load_sixteensec);
				else {
					printk("FW doesn't support sysload\n");
					rc = -EFAULT;
				}
				return rc;
			}
#ifdef MRVL_DFS
			if ((strcmp(param[0], "get11hNOCList") == 0)) {
				if (priv->wlpd_p->pdfsApMain) {
					DfsPrintNOLChannelDetails(priv->wlpd_p->pdfsApMain, buf, 4000);
				} else {
					rc = -EFAULT;
					break;
				}
			}
#endif				//MRVL_DFS
#if defined(CLIENT_SUPPORT) && defined (MRVL_WSC)
			if ((strcmp(param[0], "getbssprofile") == 0)) {
				scanDescptHdr_t *curDescpt_p = NULL;
				UINT16 parsedLen = 0;
				int i;

				printk("INSIDE getbssprofile\n");
				printk("Found :%d number of scan respults\n", tmpNumScanDesc[vmacSta_p->VMacEntry.phyHwMacIndx]);
				if (vmacSta_p->busyScanning) {
					rc = -EFAULT;
					break;
				}
				for (i = 0; i < tmpNumScanDesc[vmacSta_p->VMacEntry.phyHwMacIndx]; i++) {
					curDescpt_p = (scanDescptHdr_t *) (&tmpScanResults[vmacSta_p->VMacEntry.phyHwMacIndx][0] + parsedLen);

					if ((smeSetBssProfile(0, curDescpt_p->bssId, &curDescpt_p->CapInfo,
							      (((UINT8 *) curDescpt_p) + sizeof(scanDescptHdr_t)),
							      curDescpt_p->length + sizeof(curDescpt_p->length) - sizeof(scanDescptHdr_t),
							      FALSE)) == MLME_SUCCESS) {
						memset(&siteSurveyEntry, 0, sizeof(MRVL_SCAN_ENTRY));
						//                  smeCopyBssProfile( 0, &siteSurvey[i] );
						smeCopyBssProfile(0, &siteSurveyEntry);
						/* Only accept if WPS IE is present */
						if (siteSurveyEntry.result.wps_ie_len > 0) {
							memcpy(&siteSurvey[i], &siteSurveyEntry, sizeof(MRVL_SCAN_ENTRY));
#ifdef MRVL_WPS_DEBUG
							printk("THE BSS PROFILE :[%02X:%02X:%02X:%02X:%02X:%02X]%d\n",
							       siteSurvey[i].result.bssid[0], siteSurvey[i].result.bssid[1],
							       siteSurvey[i].result.bssid[2], siteSurvey[i].result.bssid[3],
							       siteSurvey[i].result.bssid[4], siteSurvey[i].result.bssid[5], i);
#endif
						}
					}

					parsedLen += curDescpt_p->length + sizeof(curDescpt_p->length);
				}
				*ret_len = sizeof(MRVL_SCAN_ENTRY) * tmpNumScanDesc[vmacSta_p->VMacEntry.phyHwMacIndx];
				if (copy_to_user(ret_str, &siteSurvey[0], *ret_len))
					rc = -EFAULT;
				return rc;
			}
#endif				//MRVL_WSC
#ifdef MPRXY
			if (strcmp(param[0], "ipmcgrp") == 0) {
				if (strcmp(param[1], "getallgrps") == 0) {
					tmpStr = buf;
					sprintf(tmpStr, "\n");
					tmpStr += strlen(tmpStr);

					/* check if IP Multicast group entry already exists */
					for (i = 0; i < MAX_IP_MCAST_GRPS; i++) {
						if (mib->mib_IPMcastGrpTbl[i]->mib_McastIPAddr) {
							tempIPAddr = htonl(mib->mib_IPMcastGrpTbl[i]->mib_McastIPAddr);

							for (j = 0; j < MAX_UCAST_MAC_IN_GRP; j++) {
								sprintf(tmpStr, "%u.%u.%u.%u %02x%02x%02x%02x%02x%02x\n",
									NIPQUAD(tempIPAddr),
									mib->mib_IPMcastGrpTbl[i]->mib_UCastAddr[j][0],
									mib->mib_IPMcastGrpTbl[i]->mib_UCastAddr[j][1],
									mib->mib_IPMcastGrpTbl[i]->mib_UCastAddr[j][2],
									mib->mib_IPMcastGrpTbl[i]->mib_UCastAddr[j][3],
									mib->mib_IPMcastGrpTbl[i]->mib_UCastAddr[j][4],
									mib->mib_IPMcastGrpTbl[i]->mib_UCastAddr[j][5]);

								tmpStr = buf + strlen(buf);
							}
						}
					}
				}
			}
#endif
			if (strcmp(param[0], "tlv") == 0) {
				char *out_buf = buf;
				extern int wlFwGetTLVSet(struct net_device *netdev, UINT8 act, UINT16 type, UINT16 len, UINT8 * tlvData,
							 char *string_buff);
				UINT16 type = atoi(param[1]);
				wlFwGetTLVSet(netdev, 0, type, 0, NULL, out_buf);
			}
			if (strcmp(param[0], "getchnls") == 0)	// get current regincode supported channels based on opmode 2G or 5G
			{
				int i = 0;
				char *out_buf = buf;
				UINT8 IEEERegionChnls[IEEE_80211_MAX_NUMBER_OF_CHANNELS];
				extern void getChnlList(UINT8, UINT8 *);

				getChnlList(*(mib->mib_regionCode), IEEERegionChnls);
				sprintf(out_buf, "regioncode:0x%2x\n", *(mib->mib_regionCode));
				out_buf += strlen("regioncode:0x00\n");

				if (*(mib->mib_ApMode) & AP_MODE_A_ONLY) {	//5G
					sprintf(out_buf, "5G:\n");
					out_buf += strlen("5G:\n");

					for (i = 14; i < IEEE_80211_MAX_NUMBER_OF_CHANNELS; i++) {
						if (IEEERegionChnls[i] != 0) {
							sprintf(out_buf, "%03d ", IEEERegionChnls[i]);
							out_buf += strlen("000 ");
						}
					}
				} else {	// 2.4G
					sprintf(out_buf, "2G:\n");
					out_buf += strlen("2G:\n");

					for (i = 0; i < 14; i++) {
						if (IEEERegionChnls[i] != 0) {
							sprintf(out_buf, "%03d ", IEEERegionChnls[i]);
							out_buf += strlen("000 ");
						}
					}
				}
				sprintf(out_buf, "\n");
				out_buf += strlen("\n");

			}
#ifdef AP_STEERING_SUPPORT

#ifdef SOC_W906X
			if (strcmp(param[0], IW_UTILITY_GET_CH_UTILIZATION_NONWIFI) == 0) {
				struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
				vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
				MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
				MIB_PHY_DSSS_TABLE *PhyDSSSTable = mib->PhyDSSSTable;
				mvl_status_t tmp_status;
				SINT32 chanIndx, off_chan = (SINT32) PhyDSSSTable->CurrChan;
				char *out_buf = buf;

				if (strcmp(param[1], "help") == 0) {
					printk("Usage: iwpriv <vap> getcmd \"getchutil_nonwifi [-c <off-channel>]\"\n");
					printk("-c, off-channel parameter, default is current channel\n");
					return FALSE;
				} else if (strcmp(param[1], "-c") == 0) {
					/* off-channel */
					off_chan = atoi(param[2]);
					if (!domainChannelValid(off_chan, Is5GBand(*(mib->mib_ApMode)) ? FREQ_BAND_5GHZ : FREQ_BAND_2DOT4GHZ)) {
						/* Invalid channel */
						off_chan = PhyDSSSTable->CurrChan;
					}
				}
				memset(&tmp_status, 0, sizeof(tmp_status));
				if (off_chan == PhyDSSSTable->CurrChan) {
					wlFwGetRadioStatus(netdev, &tmp_status);
				} else {
					chanIndx = GetRegionChanIndx(GetDomainIndxIEEERegion(domainGetDomain()), off_chan);
					if (chanIndx >= 0 && chanIndx < IEEEtypes_MAX_CHANNELS + IEEEtypes_MAX_CHANNELS_A)
						memcpy(&tmp_status, &CH_radio_status[chanIndx], sizeof(mvl_status_t));
				}
				memset(out_buf, 0, MAX_SCAN_BUF_SIZE);
				if (tmp_status.channel != off_chan) {
					sprintf(out_buf, "chutil_nonwifi channel not find! (%d,%d)\n", off_chan, tmp_status.channel);
				} else {
					sprintf(out_buf, "channel:%d chutil_nonwifi:%d [0~100]\n", off_chan, tmp_status.total_load);
				}
				out_buf += strlen("\n");
			}
			if (strcmp(param[0], IW_UTILITY_GET_CH_UTILIZATION_OTHERS) == 0) {
				struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
				vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
				MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
				MIB_PHY_DSSS_TABLE *PhyDSSSTable = mib->PhyDSSSTable;
				mvl_status_t tmp_status;
				SINT32 chanIndx, off_chan = (SINT32) PhyDSSSTable->CurrChan;
				char *out_buf = buf;

				if (strcmp(param[1], "help") == 0) {
					printk("Usage: iwpriv <vap> getcmd \"getchutil_others [-c <off-channel>]\"\n");
					printk("-c, off-channel parameter, default is current channel\n");
					return FALSE;
				} else if (strcmp(param[1], "-c") == 0) {
					/* off-channel */
					off_chan = atoi(param[2]);
					if (!domainChannelValid(off_chan, Is5GBand(*(mib->mib_ApMode)) ? FREQ_BAND_5GHZ : FREQ_BAND_2DOT4GHZ)) {
						/* Invalid channel */
						off_chan = PhyDSSSTable->CurrChan;
					}
				}
				memset(&tmp_status, 0, sizeof(tmp_status));
				if (off_chan == PhyDSSSTable->CurrChan) {
					wlFwGetRadioStatus(netdev, &tmp_status);
				} else {
					chanIndx = GetRegionChanIndx(GetDomainIndxIEEERegion(domainGetDomain()), off_chan);
					if (chanIndx >= 0 && chanIndx < IEEEtypes_MAX_CHANNELS + IEEEtypes_MAX_CHANNELS_A)
						memcpy(&tmp_status, &CH_radio_status[chanIndx], sizeof(mvl_status_t));
				}
				memset(out_buf, 0, MAX_SCAN_BUF_SIZE);
				if (tmp_status.channel != off_chan) {
					sprintf(out_buf, "chutil_others channel not find! (%d,%d)\n", off_chan, tmp_status.channel);
				} else {
					sprintf(out_buf, "channel:%d chutil_others:%d [0~100]\n", off_chan, tmp_status.total_load);
				}
				out_buf += strlen("\n");
			}
			if (strcmp(param[0], IW_UTILITY_GET_CH_UTILIZATION) == 0) {
				struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
				vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
				MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
				MIB_PHY_DSSS_TABLE *PhyDSSSTable = mib->PhyDSSSTable;
				mvl_status_t tmp_status;
				SINT32 chanIndx, off_chan = (SINT32) PhyDSSSTable->CurrChan;
				char *out_buf = buf;

				if (strcmp(param[1], "help") == 0) {
					printk("Usage: iwpriv <vap> getcmd \"getchutil [-c <off-channel>]\"\n");
					printk("-c, off-channel parameter, default is current channel\n");
					return FALSE;
				} else if (strcmp(param[1], "-c") == 0) {
					/* off-channel */
					off_chan = atoi(param[2]);
					if (!domainChannelValid(off_chan, Is5GBand(*(mib->mib_ApMode)) ? FREQ_BAND_5GHZ : FREQ_BAND_2DOT4GHZ)) {
						/* Invalid channel */
						off_chan = PhyDSSSTable->CurrChan;
					}
				} else if (!strcmp(param[1], "-f")) {
					ch_load_info_t *ch_load_p = NULL;

					if (!strcmp(param[2], "acs")) {
#ifdef AUTOCHANNEL
						ch_load_p = &vmacSta_p->acs_cload;
						TimerDisarm(&ch_load_p->timer);
						memset(ch_load_p, 0, sizeof(ch_load_info_t));
						ch_load_p->tag = CH_LOAD_ACS;
						ch_load_p->callback = &wl_acs_ch_load_cb;
#endif				/* AUTOCHANNEL */
#ifdef IEEE80211K
					} else if (!strcmp(param[2], "rrm")) {
						ch_load_p = &vmacSta_p->rrm_cload;
						TimerDisarm(&ch_load_p->timer);
						memset(ch_load_p, 0, sizeof(ch_load_info_t));
						ch_load_p->tag = CH_LOAD_RRM;
						ch_load_p->callback = &wl_rrm_ch_load_cb;
#endif				/* IEEE80211K */
#ifdef BAND_STEERING
					} else if (!strcmp(param[2], "bandsteer")) {
						ch_load_p = &vmacSta_p->bandsteer_cload;
						TimerDisarm(&ch_load_p->timer);
						memset(ch_load_p, 0, sizeof(ch_load_info_t));
						ch_load_p->tag = CH_LOAD_BANDSTEER;
						ch_load_p->callback = &wl_bandsteer_ch_load_cb;
#endif				/* BAND_STEERING */
					}
					if (ch_load_p) {
						ch_load_p->master = (UINT8 *) vmacSta_p;
						ch_load_p->dur = atoi(param[3]);
						ch_load_p->interval = atoi(param[4]);
						ch_load_p->loop_count = atoi(param[5]);
						ch_load_p->started = 1;
						wl_get_ch_load_by_timer(ch_load_p);
					}
					break;
				}
				memset(out_buf, 0, MAX_SCAN_BUF_SIZE);
				memset(&tmp_status, 0, sizeof(tmp_status));
				if (off_chan == PhyDSSSTable->CurrChan) {
					wlFwGetRadioStatus(netdev, &tmp_status);
				} else {
					chanIndx = GetRegionChanIndx(GetDomainIndxIEEERegion(domainGetDomain()), off_chan);
					if (chanIndx >= 0 && chanIndx < IEEEtypes_MAX_CHANNELS + IEEEtypes_MAX_CHANNELS_A)
						memcpy(&tmp_status, &CH_radio_status[chanIndx], sizeof(mvl_status_t));
				}
				if (tmp_status.channel != off_chan) {
					sprintf(out_buf, "chutil channel not find! (%d,%d)\n", off_chan, tmp_status.channel);
				} else {
					sprintf(out_buf, "channel:%d chutil:%d [0~100]\n", off_chan, tmp_status.total_load);
				}
			}
			if (strcmp(param[0], "nf") == 0) {
				struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
				vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
				MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
				MIB_PHY_DSSS_TABLE *PhyDSSSTable = mib->PhyDSSSTable;
				mvl_status_t tmp_status;
				SINT32 chanIndx, off_chan = (SINT32) PhyDSSSTable->CurrChan;
				char *out_buf = buf;

				if (strcmp(param[1], "help") == 0) {
					printk("Usage: iwpriv <vap> getcmd \"nf [-c <off-channel>]\"\n");
					printk("-c, off-channel parameter, default is current channel\n");
					return FALSE;
				} else if (strcmp(param[1], "-c") == 0) {
					/* off-channel */
					off_chan = atoi(param[2]);
					if (!domainChannelValid(off_chan, Is5GBand(*(mib->mib_ApMode)) ? FREQ_BAND_5GHZ : FREQ_BAND_2DOT4GHZ)) {
						/* Invalid channel */
						off_chan = PhyDSSSTable->CurrChan;
					}
				}
				memset(&tmp_status, 0, sizeof(tmp_status));
				if (off_chan == PhyDSSSTable->CurrChan) {
					wlFwGetRadioStatus(netdev, &tmp_status);
				} else {
					chanIndx = GetRegionChanIndx(GetDomainIndxIEEERegion(domainGetDomain()), off_chan);
					if (chanIndx >= 0 && chanIndx < IEEEtypes_MAX_CHANNELS + IEEEtypes_MAX_CHANNELS_A)
						memcpy(&tmp_status, &CH_radio_status[chanIndx], sizeof(mvl_status_t));
				}
				memset(out_buf, 0, MAX_SCAN_BUF_SIZE);
				if (tmp_status.channel != off_chan) {
					sprintf(out_buf, "nf channel not find! (%d,%d)\n", off_chan, tmp_status.channel);
				} else {
					if (tmp_status.noise > 0)
						sprintf(out_buf, "channel:%d nf:-%d\n", off_chan, tmp_status.noise);
					else
						sprintf(out_buf, "channel:%d nf:%d\n", off_chan, tmp_status.noise);
				}
				out_buf += strlen("\n");
			}
#elif defined (SOC_W8964)
			if (strcmp(param[0], IW_UTILITY_GET_CH_UTILIZATION) == 0) {
				struct wlreq_qbss_load QbssReq;
				char *out_buf = buf;

				memset(out_buf, 0, MAX_SCAN_BUF_SIZE);
				memset(&QbssReq, 0, sizeof(struct wlreq_qbss_load));
				wlFwGetQBSSLoad(netdev, &QbssReq.channel_util, &QbssReq.sta_cnt);
				sprintf(out_buf, "%d\n", QbssReq.channel_util);
				out_buf += strlen("\n");
			} else if (strcmp(param[0], IW_UTILITY_GET_STA_COUNT) == 0) {
				struct wlreq_qbss_load QbssReq;
				char *out_buf = buf;

				memset(out_buf, 0, MAX_SCAN_BUF_SIZE);
				memset(&QbssReq, 0, sizeof(struct wlreq_qbss_load));
				wlFwGetQBSSLoad(netdev, &QbssReq.channel_util, &QbssReq.sta_cnt);
				sprintf(out_buf, "%d\n", QbssReq.sta_cnt);
				out_buf += strlen("\n");
			}
#endif
#ifdef IEEE80211K
			else if (strcmp(param[0], IW_UTILITY_GET_STA_BSS_TM) == 0) {
				UINT8 i;
				UINT32 entries;
				UINT8 *staBuf = NULL;
				UINT8 *listBuf = NULL;
				extStaDb_StaInfo_t *pStaInfo;
				UINT8 destaddr[IEEEtypes_ADDRESS_SIZE];
				UINT8 BssTM_status = 0;
				UINT8 BssTM_count = 0;
				char *out_buf = buf;

				memset(out_buf, 0, MAX_SCAN_BUF_SIZE);
				sscanf(param[1], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &destaddr[0],
				       &destaddr[1], &destaddr[2], &destaddr[3], &destaddr[4], &destaddr[5]);

				entries = extStaDb_entries(vmacSta_p, 0);
				staBuf = wl_kmalloc(entries * sizeof(STA_INFO), GFP_KERNEL);
				if (staBuf != NULL) {
					extStaDb_list(vmacSta_p, staBuf, 1);
					if (entries) {
						listBuf = staBuf;

						for (i = 0; i < entries; i++) {
							if (!memcmp(listBuf, destaddr, IEEEtypes_ADDRESS_SIZE)) {
								if ((pStaInfo =
								     extStaDb_GetStaInfo(vmacSta_p, (IEEEtypes_MacAddr_t *) listBuf,
											 STADB_DONT_UPDATE_AGINGTIME)) != NULL) {
									BssTM_status = pStaInfo->ExtCapElem.ExtCap.BSSTransition;
									BssTM_count = pStaInfo->btmreq_count;
								}
								break;
							}
							listBuf += sizeof(STA_INFO);
						}
					}
					wl_kfree(staBuf);
				}
				sprintf(out_buf, "status:%d count:%d \n", BssTM_status, BssTM_count);
				out_buf += strlen("\n");
			} else if (strcmp(param[0], IW_UTILITY_GET_BTM_RSSI_THRESHOLD) == 0) {
				char *out_buf = buf;

				memset(out_buf, 0, MAX_SCAN_BUF_SIZE);
				sprintf(out_buf, "low:%d high:%d \n", mib->mib_BTM_rssi_low, mib->mib_BTM_rssi_high);
				out_buf += strlen("\n");
			} else if (strcmp(param[0], IW_UTILITY_GET_AP_LIST_RSSI) == 0) {
				char *out_buf = buf;

				memset(out_buf, 0, MAX_SCAN_BUF_SIZE);
				MSAN_neighbor_dump_list(netdev, out_buf, param[1], param[2]);
				out_buf += strlen("\n");
			} else if (strcmp(param[0], IW_UTILITY_GET_STA_LIST) == 0) {
				UCHAR *sta_buf, *show_buf, buf1[256];
				char *out_buf = buf;
				int i, entries;
				extStaDb_StaInfo_t *pStaInfo;
				s16 rssi = 0;

				memset(out_buf, 0, MAX_SCAN_BUF_SIZE);
				entries = extStaDb_entries(vmacSta_p, 0);
				sta_buf = wl_kmalloc(entries * 64, GFP_KERNEL);
				if (sta_buf == NULL) {
					rc = -EFAULT;
					break;
				}

				extStaDb_list(vmacSta_p, sta_buf, 1);

				if (entries) {
					show_buf = sta_buf;
					sprintf(out_buf, "\n");
					out_buf++;
					for (i = 0; i < entries; i++) {
						rssi = 0;
						if ((pStaInfo =
						     extStaDb_GetStaInfo(vmacSta_p, (IEEEtypes_MacAddr_t *) show_buf,
									 STADB_DONT_UPDATE_AGINGTIME)) == NULL) {
							wl_kfree(sta_buf);
							rc = -EFAULT;
							return rc;
						}
#ifdef SOC_W906X
						rssi = wl_util_get_rssi(netdev, &pStaInfo->RSSI_path, NULL);
#else				/* SOC_W906X */
						rssi = pStaInfo->RSSI;
#endif				/* SOC_W906X */
						sprintf(buf1, "Aid %d %02x:%02x:%02x:%02x:%02x:%02x RSSI %d BTM %d AgingTime %d\n",
							pStaInfo->Aid, *show_buf, *(show_buf + 1), *(show_buf + 2), *(show_buf + 3), *(show_buf + 4),
							*(show_buf + 5), rssi, pStaInfo->ExtCapElem.ExtCap.BSSTransition, pStaInfo->TimeStamp);

						show_buf += sizeof(STA_INFO);
						strcpy(out_buf, buf1);
						out_buf += strlen(buf1);
					}
				} else {
					out_buf[0] = 0;
				}
				wl_kfree(sta_buf);
			} else if (strcmp(param[0], IW_UTILITY_GET_STA_RSSI_FOR_WTS) == 0) {
				extStaDb_StaInfo_t *pStaInfo;
				UINT32 entries;
				UINT8 i;
				UINT8 *staBuf = NULL;
				UINT8 *listBuf = NULL;
				UINT8 destaddr[IEEEtypes_ADDRESS_SIZE];
				char *out_buf = buf;
				UINT8 ret_rssi = 0;

				memset(out_buf, 0, MAX_SCAN_BUF_SIZE);
				sscanf(param[1], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &destaddr[0],
				       &destaddr[1], &destaddr[2], &destaddr[3], &destaddr[4], &destaddr[5]);

				entries = extStaDb_entries(vmacSta_p, 0);
				staBuf = wl_kmalloc(entries * sizeof(STA_INFO), GFP_KERNEL);
				if (staBuf != NULL) {
					extStaDb_list(vmacSta_p, staBuf, 1);
					if (entries) {
						listBuf = staBuf;

						for (i = 0; i < entries; i++) {
							if (!memcmp(listBuf, destaddr, IEEEtypes_ADDRESS_SIZE)) {
								if ((pStaInfo =
								     extStaDb_GetStaInfo(vmacSta_p, (IEEEtypes_MacAddr_t *) listBuf,
											 STADB_DONT_UPDATE_AGINGTIME)) != NULL) {
									ret_rssi = pStaInfo->RSSI;
								}
								break;
							}
							listBuf += sizeof(STA_INFO);
						}
					}
					wl_kfree(staBuf);
				}
				sprintf(out_buf, "rssi:%d \n", ret_rssi);
				out_buf += strlen("\n");
			} else if (strcmp(param[0], "config_btmreq") == 0) {
				char *out_buf = buf;

				memset(out_buf, 0, MAX_SCAN_BUF_SIZE);
				sprintf(out_buf,
					"btmreq configuration:\n"
					"Abridged: %d\nDisassociation Imminent: %d\nBSS Termination: %d\nESS Disassociation Imminent: %d\nDisassociation Timer: %d\nValidity Interval: %d\n",
					mib->mib_BSSTMRequest->Abridged, mib->mib_BSSTMRequest->DisassocImm, mib->mib_BSSTMRequest->BSSTermiInc,
					mib->mib_BSSTMRequest->ESSDisassocImm, mib->mib_BSSTMRequest->disassoc_timer,
					mib->mib_BSSTMRequest->validity_interval);
				out_buf += strlen("\n");
			}
#endif				/* IEEE80211K */
#endif				/*AP_STEERING_SUPPORT */
#ifdef MULTI_AP_SUPPORT

			else if (strcmp(param[0], IW_UTILITY_MULTI_AP_ATTR) == 0) {
				char *out_buf = buf;

				memset(out_buf, 0, MAX_SCAN_BUF_SIZE);
				sprintf(out_buf, "multiap:%d\n", mib->multi_ap_attr);
				out_buf += strlen("\n");
			} else if (strcmp(param[0], IW_UTILITY_MULTI_AP_VERSION) == 0) {
				char *out_buf = buf;

				memset(out_buf, 0, MAX_SCAN_BUF_SIZE);
				sprintf(out_buf, "multi_ap_ver:%d\n", mib->multi_ap_ver);
				out_buf += strlen("\n");
			} else if (strcmp(param[0], IW_UTILITY_multi_ap_vid) == 0) {
				char *out_buf = buf;

				memset(out_buf, 0, MAX_SCAN_BUF_SIZE);
				sprintf(out_buf, "multi_ap_vid:%d\n", (UINT16) SHORT_SWAP(mib->multi_ap_vid));
				out_buf += strlen("\n");
			} else if ((strcmp(param[0], "unassocsta_offchan_time") == 0)) {
				char *out_buf = buf;

				memset(out_buf, 0, MAX_SCAN_BUF_SIZE);
				sprintf(out_buf, "unassocsta offchan time %d(ms)\n", *(mib->mib_unassocsta_track_time));
				out_buf += strlen("\n");
			}
#endif				/* MULTI_AP_SUPPORT */
#ifdef IEEE80211K
			else if (strcmp(param[0], "getnlist") == 0) {
				*ret_len = sizeof(wlpd_p->nb_info.nb_list);
				if (copy_to_user(ret_str, wlpd_p->nb_info.nb_list, *ret_len))
					rc = -EFAULT;
				return rc;
			}
#endif
#ifdef SOC_W906X
			else if (strcmp(param[0], "muedcacfg") == 0) {
				int i;

				if (!priv->master) {
					printk("Error. Please enter vap interface instead\n");
					rc = -EOPNOTSUPP;
					break;
				}

				for (i = 0; i < 4; i++) {
					printk("[%d] aifsn=%d acm=%d ecw_min=%d ecw_max=%d edca_timer=%d\n",
					       vmacSta_p->VMacEntry.mib_QAP_MUEDCA_Table[i].aci,
					       vmacSta_p->VMacEntry.mib_QAP_MUEDCA_Table[i].aifsn,
					       vmacSta_p->VMacEntry.mib_QAP_MUEDCA_Table[i].acm,
					       vmacSta_p->VMacEntry.mib_QAP_MUEDCA_Table[i].ecw_min,
					       vmacSta_p->VMacEntry.mib_QAP_MUEDCA_Table[i].ecw_max,
					       vmacSta_p->VMacEntry.mib_QAP_MUEDCA_Table[i].timer);
				};
			} else if ((strcmp(param[0], "beamchange") == 0)) {
				char *out_buf = buf;

				memset(out_buf, 0, MAX_SCAN_BUF_SIZE);
				sprintf(out_buf, "beam change: %s.\n", *(mib->mib_beamChange_disable) ? "Off" : "On");
				out_buf += strlen("\n");
			} else if ((strcmp(param[0], "petype") == 0)) {
				char *out_buf = buf;

				memset(out_buf, 0, MAX_SCAN_BUF_SIZE);
				sprintf(out_buf, "petype: %s.\n", (mib->HEConfig->pe_type == MIB_PE_TYPE_DEFAULT) ? "default" : "aggressive");
				out_buf += strlen("\n");
			}
#endif
#ifdef BAND_STEERING
			else if ((strcmp(param[0], "bandsteer") == 0)) {
				char *out_buf = buf;

				if (strcmp(param[1], "config") == 0) {
					sprintf(out_buf, "\n[%s] bandsteer-%s%s%s mode:0x%X\n"
						"sta_track_max_num:%u sta_track_max_age:%u(s)\n"
						"sta_auth_retry_cnt:%d timer_interval:%u(ms) rssi_threshold:%u\n",
						netdev->name,
						(*(mib->mib_bandsteer) == 0) ? "disabled" : "enablded ",
						((*(mib->mib_bandsteer) == 1) &&
						 (*(mib->mib_bandsteer_handler) == BAND_STEERING_HDL_BY_HOST)) ?
						"(handled by Host)" : "",
						((*(mib->mib_bandsteer) == 1) &&
						 (*(mib->mib_bandsteer_handler) == BAND_STEERING_HDL_BY_DRV)) ?
						"(handled by Driver)" : "",
						*(mib->mib_bandsteer_mode),
						*(mib->mib_bandsteer_sta_track_max_num),
						*(mib->mib_bandsteer_sta_track_max_age) / HZ,
						*(mib->mib_bandsteer_sta_auth_retry_cnt),
						*(mib->mib_bandsteer_timer_interval) * 1000 / HZ, *(mib->mib_bandsteer_rssi_threshold));
				} else if (strcmp(param[1], "track_sta_info") == 0) {
					if (priv->wlpd_p->bandSteer.sta_track_num) {
						struct sta_track_info *info;

						sprintf(out_buf, "\nsta_track_num:%d\n", priv->wlpd_p->bandSteer.sta_track_num);
						list_for_each_entry(info, &priv->wlpd_p->bandSteer.sta_track_list, list)
						    sprintf(out_buf + strlen(out_buf),
							    "%02X:%02X:%02X:%02X:%02X:%02X aging_time:%lu(s)\n",
							    info->addr[0], info->addr[1], info->addr[2],
							    info->addr[3], info->addr[4], info->addr[5], (jiffies - info->last_seen) / HZ);
					}
				}
			}
#endif				/* BAND_STEERING */
			else if (strcmp(param[0], "pool_buf_size") == 0) {
				char *out_buf = buf;
				extern u32 BF_Buf_Size;
				extern u32 L0L1_Buf_Size;

				memset(out_buf, 0, MAX_SCAN_BUF_SIZE);
				sprintf(out_buf, "\nL0/L1 buffer size: %d K\nBF memory size: %d K\n", L0L1_Buf_Size / 1024, BF_Buf_Size / 1024);
				out_buf += strlen("\n");
			} else if (strcmp(param[0], "MBssid") == 0) {
				char *out_buf = buf;

				memset(out_buf, 0, MAX_SCAN_BUF_SIZE);
				sprintf(out_buf, "%d\n", *(mib->mib_mbssid));
				out_buf += strlen("\n");
			} else if (strcmp(param[0], "enable_arp_for_vo") == 0) {
				char *out_buf = buf;

				memset(out_buf, 0, MAX_SCAN_BUF_SIZE);
				sprintf(out_buf, "enable_arp_for_vo=%d, %s\n", *(mib->enable_arp_for_vo),
					*(mib->enable_arp_for_vo) ? "ARP will be set to priority VO." : "ARP will be set to priority BE (default).");
				out_buf += strlen("\n");
			} else if (strcmp(param[0], "disable_qosctl") == 0) {
				char *out_buf = buf;

				memset(out_buf, 0, MAX_SCAN_BUF_SIZE);
				sprintf(out_buf, "disable_qosctl=%d, %s\n", *(mib->disable_qosctl),
					*(mib->disable_qosctl) ?
					"MC/BC TX - Qos data will not be set" : "MC/BC TX - Qos data will be set if QSTA is connected.");
				out_buf += strlen("\n");
			}
#ifdef MULTI_AP_SUPPORT
			else if ((strcmp(param[0], "cac_status") == 0)) {
				UINT8 log_flag;

				log_flag = atoi(param[1]);
				memset(buf, 0, MAX_SCAN_BUF_SIZE);
				*ret_len = EM_get_cac_status(buf, log_flag);
				if (log_flag != 1) {
					if (copy_to_user(ret_str, buf, *ret_len))
						rc = -EFAULT;
				}
				return rc;
			}
#endif				/* MULTI_AP_SUPPORT */
			else if ((strcmp(param[0], "HostGetDlGid") == 0)) {
				vmacApInfo_t *master_p = vmacSta_p;
				char *out_buf = buf;
				UINT8 i;

				if (vmacSta_p->master) {
					master_p = vmacSta_p->master;
				}
				/* Get DL group ID, from i = 1, reuse GID for DL MIMO */
				memset(out_buf, 0, MAX_SCAN_BUF_SIZE);
				for (i = 1; i < 63; i++) {
					if (!((master_p->DL_GroupSet >> i) & 0x1)) {
						/* find a new gid */
						break;
					}
				}
				if (i == 63) {
					printk("DL Group full! DL_GroupSet:0x%016llx", master_p->DL_GroupSet);
					sprintf(out_buf, "0\n");
					break;
				}
				master_p->DL_GroupSet |= ((UINT64) 0x1 << i);

				memset(out_buf, 0, MAX_SCAN_BUF_SIZE);
				sprintf(out_buf, "%d\n", i);
			} else if ((strcmp(param[0], "HostGetUlGid") == 0)) {
				vmacApInfo_t *master_p = vmacSta_p;
				char *out_buf = buf;
				UINT8 i, j;

				if (vmacSta_p->master) {
					master_p = vmacSta_p->master;
				}
				/* Get UL group ID, from i = 1 */
				if (master_p->UL_GroupSeq == 0) {
					master_p->UL_GroupSeq = 1;
				}
				memset(out_buf, 0, MAX_SCAN_BUF_SIZE);
				for (i = master_p->UL_GroupSeq, j = 0; j < 63; i++, j++) {
					if (i >= 63) {
						i = 1;
					}
					if (!((master_p->UL_GroupSet >> i) & 0x1)) {
						/* find a new gid */
						break;
					}
				}
				if (j == 63) {
					printk("UL Group full! UL_GroupSet:0x%016llx", master_p->UL_GroupSet);
					sprintf(out_buf, "0\n");
					break;
				}
				master_p->UL_GroupSeq = i + 1;
				if (master_p->UL_GroupSeq >= 63) {
					master_p->UL_GroupSeq = 1;
				}
				master_p->UL_GroupSet |= ((UINT64) 0x1 << i);

				memset(out_buf, 0, MAX_SCAN_BUF_SIZE);
				sprintf(out_buf, "%d\n", i);
			} else if ((strcmp(param[0], "Host_dl_ofdma") == 0)) {
				vmacApInfo_t *master_p = vmacSta_p;
				MIB_802DOT11 *mib1;
				char *out_buf = buf;

				if (vmacSta_p->master) {
					master_p = vmacSta_p->master;
				}
				mib1 = master_p->Mib802dot11;
				memset(out_buf, 0, MAX_SCAN_BUF_SIZE);
				sprintf(out_buf, "%d\n", mib1->DL_ofdma_enable);
			} else if ((strcmp(param[0], "Host_dl_mimo") == 0)) {
				vmacApInfo_t *master_p = vmacSta_p;
				MIB_802DOT11 *mib1;
				char *out_buf = buf;

				if (vmacSta_p->master) {
					master_p = vmacSta_p->master;
				}
				mib1 = master_p->Mib802dot11;
				memset(out_buf, 0, MAX_SCAN_BUF_SIZE);
				sprintf(out_buf, "%d\n", mib1->DL_mimo_enable);
			} else if ((strcmp(param[0], "Host_ul_ofdma") == 0)) {
				vmacApInfo_t *master_p = vmacSta_p;
				MIB_802DOT11 *mib1;
				char *out_buf = buf;

				if (vmacSta_p->master) {
					master_p = vmacSta_p->master;
				}
				mib1 = master_p->Mib802dot11;
				memset(out_buf, 0, MAX_SCAN_BUF_SIZE);
				sprintf(out_buf, "%d\n", mib1->UL_ofdma_enable);
			} else if ((strcmp(param[0], "Host_ul_mimo") == 0)) {
				vmacApInfo_t *master_p = vmacSta_p;
				MIB_802DOT11 *mib1;
				char *out_buf = buf;

				if (vmacSta_p->master) {
					master_p = vmacSta_p->master;
				}
				mib1 = master_p->Mib802dot11;
				memset(out_buf, 0, MAX_SCAN_BUF_SIZE);
				sprintf(out_buf, "%d\n", mib1->UL_mimo_enable);
			}
		}
		break;

#ifdef CLIENT_SUPPORT
	case WL_IOCTL_GET_STASCAN:
		{
			scanDescptHdr_t *curDescpt_p = NULL;
			IEEEtypes_SsIdElement_t *ssidIE_p;
			IEEEtypes_DsParamSet_t *dsPSetIE_p;
			IEEEtypes_SuppRatesElement_t *PeerSupportedRates_p = NULL;
			IEEEtypes_ExtSuppRatesElement_t *PeerExtSupportedRates_p = NULL;
			IEEEtypes_HT_Element_t *pHT = NULL;
			IEEEtypes_Add_HT_Element_t *pHTAdd = NULL;
			IEEEtypes_Generic_HT_Element_t *pHTGen = NULL;
			UINT32 LegacyRateBitMap = 0;
			IEEEtypes_RSN_IE_t *RSN_p = NULL;
			IEEEtypes_RSN_IE_WPA2_t *wpa2IE_p = NULL;
			UINT8 scannedChannel = 0;
			UINT16 parsedLen = 0;
			UINT8 scannedSSID[33];
			UINT8 i = 0;
			UINT8 mdcnt = 0;
			UINT8 apType[6];
			UINT8 encryptType[10];
			UINT8 cipherType[6];
			BOOLEAN apGonly = FALSE;
			char *out_buf = buf;

			/* Fill the output buffer */
			sprintf(out_buf, "\n");
			out_buf++;

			for (i = 0; i < tmpNumScanDesc[vmacSta_p->VMacEntry.phyHwMacIndx]; i++) {
				curDescpt_p = (scanDescptHdr_t *) (&tmpScanResults[vmacSta_p->VMacEntry.phyHwMacIndx][0] + parsedLen);

				memset(&scannedSSID[0], 0, sizeof(scannedSSID));
				memset(&apType[0], 0, sizeof(apType));
				sprintf(&encryptType[0], "None");
				sprintf(&cipherType[0], " ");
				mdcnt = 0;
				scannedChannel = 0;
				apGonly = FALSE;

				if ((ssidIE_p = (IEEEtypes_SsIdElement_t *) smeParseIeType(SSID,
											   (((UINT8 *) curDescpt_p) + sizeof(scanDescptHdr_t)),
											   curDescpt_p->length + sizeof(curDescpt_p->length) -
											   sizeof(scanDescptHdr_t))) != NULL) {
					memcpy(&scannedSSID[0], &ssidIE_p->SsId[0], ssidIE_p->Len);
				}
				if ((dsPSetIE_p = (IEEEtypes_DsParamSet_t *) smeParseIeType(DS_PARAM_SET,
											    (((UINT8 *) curDescpt_p) + sizeof(scanDescptHdr_t)),
											    curDescpt_p->length + sizeof(curDescpt_p->length) -
											    sizeof(scanDescptHdr_t))) != NULL) {
					scannedChannel = dsPSetIE_p->CurrentChan;
				}

				if (curDescpt_p->CapInfo.Privacy)
					sprintf(&encryptType[0], "WEP");

				PeerSupportedRates_p = (IEEEtypes_SuppRatesElement_t *) smeParseIeType(SUPPORTED_RATES,
												       (((UINT8 *) curDescpt_p) +
													sizeof(scanDescptHdr_t)),
												       curDescpt_p->length +
												       sizeof(curDescpt_p->length) -
												       sizeof(scanDescptHdr_t));

				PeerExtSupportedRates_p = (IEEEtypes_ExtSuppRatesElement_t *) smeParseIeType(EXT_SUPPORTED_RATES,
													     (((UINT8 *) curDescpt_p) +
													      sizeof(scanDescptHdr_t)),
													     curDescpt_p->length +
													     sizeof(curDescpt_p->length) -
													     sizeof(scanDescptHdr_t));

				LegacyRateBitMap = GetAssocRespLegacyRateBitMap(PeerSupportedRates_p, PeerExtSupportedRates_p);

				if (scannedChannel <= 14) {
					if (PeerSupportedRates_p) {
						int j;
						for (j = 0; (j < PeerSupportedRates_p->Len) && !apGonly; j++) {
							/* Only look for 6 Mbps as basic rate - consider this to be G only. */
							if (PeerSupportedRates_p->Rates[j] == 0x8c) {
								sprintf(&apType[mdcnt++], "G");
								apGonly = TRUE;
							}
						}
					}
					if (!apGonly) {
						if (LegacyRateBitMap & 0x0f)
							sprintf(&apType[mdcnt++], "B");
						if (PeerSupportedRates_p && PeerExtSupportedRates_p)
							sprintf(&apType[mdcnt++], "G");
					}
				} else {
					if (LegacyRateBitMap & 0x1fe0)
						sprintf(&apType[mdcnt++], "A");
				}

				pHT = (IEEEtypes_HT_Element_t *) smeParseIeType(HT,
										(((UINT8 *) curDescpt_p) + sizeof(scanDescptHdr_t)),
										curDescpt_p->length + sizeof(curDescpt_p->length) -
										sizeof(scanDescptHdr_t));

				pHTAdd = (IEEEtypes_Add_HT_Element_t *) smeParseIeType(ADD_HT,
										       (((UINT8 *) curDescpt_p) + sizeof(scanDescptHdr_t)),
										       curDescpt_p->length + sizeof(curDescpt_p->length) -
										       sizeof(scanDescptHdr_t));
				// If cannot find HT element then look for High Throughput elements using PROPRIETARY_IE.
				if (pHT == NULL) {
					pHTGen = linkMgtParseHTGenIe((((UINT8 *) curDescpt_p) + sizeof(scanDescptHdr_t)),
								     curDescpt_p->length + sizeof(curDescpt_p->length) - sizeof(scanDescptHdr_t));
				}
				if ((RSN_p = linkMgtParseWpaIe((((UINT8 *) curDescpt_p) + sizeof(scanDescptHdr_t)),
							       curDescpt_p->length + sizeof(curDescpt_p->length) - sizeof(scanDescptHdr_t)))) {
					sprintf(&encryptType[0], "WPA");

					if (RSN_p->PwsKeyCipherList[3] == RSN_TKIP_ID)
						sprintf(&cipherType[0], "TKIP");
					else if (RSN_p->PwsKeyCipherList[3] == RSN_AES_ID)
						sprintf(&cipherType[0], "AES");
				}

				if ((wpa2IE_p = (IEEEtypes_RSN_IE_WPA2_t *) smeParseIeType(RSN_IEWPA2,
											   (((UINT8 *) curDescpt_p) + sizeof(scanDescptHdr_t)),
											   curDescpt_p->length + sizeof(curDescpt_p->length) -
											   sizeof(scanDescptHdr_t)))) {
					UINT32 key_mgmt;

					key_mgmt =
					    U8_ARRAY_TO_U32(wpa2IE_p->AuthKeyList[0], wpa2IE_p->AuthKeyList[1], wpa2IE_p->AuthKeyList[2],
							    wpa2IE_p->AuthKeyList[3]);
					// RSN_AES_ID, RSN_TKIP_ID
					if ((wpa2IE_p->GrpKeyCipher[3] == RSN_TKIP_ID) && (wpa2IE_p->PwsKeyCipherList[3] == RSN_AES_ID))
						sprintf(&encryptType[0], "WPA-WPA2");
					else
						sprintf(&encryptType[0], "WPA2");

					if (wpa2IE_p->PwsKeyCipherList[3] == RSN_TKIP_ID)
						sprintf(&cipherType[0], "TKIP");
					else if (wpa2IE_p->PwsKeyCipherList[3] == RSN_AES_ID)
						sprintf(&cipherType[0], "AES");

					switch (key_mgmt) {
					case KEY_MGMT_SAE:
					case KEY_MGMT_SUITE_B:
					case KEY_MGMT_SUITE_B_192:
					case KEY_MGMT_OWE:
						sprintf(&encryptType[0], "WPA3");
						break;
					default:
						break;
					}
				}

				if (pHT || pHTGen) {
					sprintf(&apType[mdcnt++], "N");
				}

				parsedLen += curDescpt_p->length + sizeof(curDescpt_p->length);

				sprintf(out_buf, "#%3d SSID=%-32s %02x:%02x:%02x:%02x:%02x:%02x %3d -%d %s %s %s\n",
					i + 1,
					(const char *)&scannedSSID[0],
					curDescpt_p->bssId[0],
					curDescpt_p->bssId[1],
					curDescpt_p->bssId[2],
					curDescpt_p->bssId[3],
					curDescpt_p->bssId[4],
					curDescpt_p->bssId[5], scannedChannel, curDescpt_p->rssi, apType, encryptType, cipherType);

				out_buf += strlen(out_buf);
			}
		}
		break;
#endif				/* CLIENT SUPPORT */

	default:
		if (cmd >= SIOCSIWCOMMIT && cmd <= SIOCGIWPOWER) {
			rc = -EOPNOTSUPP;
			break;
		}

		PRINT1(IOCTL, "unsupported ioctl(0x%04x)\n", cmd);

		rc = -EOPNOTSUPP;

		break;
	}

	if (rc == 0) {
		*ret_len = strlen(buf);

		if (copy_to_user(ret_str, buf, *ret_len))
			rc = -EFAULT;
	}
	WLDBG_EXIT(DBG_LEVEL_1);

	return rc;
}

int wlIoctl(struct net_device *dev, struct ifreq *rq, int cmd)
{
	struct iwreq *wrq = (struct iwreq *)rq;
	int rc = 0;
	char *param = NULL;

	WLDBG_ENTER(DBG_LEVEL_1);

	param = wl_kmalloc(wrq->u.data.length + 1, GFP_KERNEL);

	if (param == NULL)
		return -ENOMEM;

	param[wrq->u.data.length] = 0;

	if (wrq->u.data.length > 0) {
		if (copy_from_user(param, wrq->u.data.pointer, wrq->u.data.length)) {
			wl_kfree(param);
			return -ENOMEM;
		}
	}

	if (IW_IS_SET(cmd)) {
		rc = wlIoctlSet(dev, cmd, param, wrq->u.data.length, wrq->u.data.pointer, &wrq->u.data.length);
	} else if (IW_IS_GET(cmd)) {
		rc = wlIoctlGet(dev, cmd, param, wrq->u.data.length, wrq->u.data.pointer, &wrq->u.data.length);
	} else
		rc = -EOPNOTSUPP;

	if (param != NULL)
		wl_kfree(param);

	WLDBG_EXIT(DBG_LEVEL_1);

	return rc;
}

/* Helper functions */

int getMacFromString(unsigned char *macAddr, const char *pStr)
{
	int nAddr = 0;
	const char *endofstr;

	memset(macAddr, 0, 6);

	if (strlen(pStr) > 0) {
		endofstr = pStr + strlen(pStr);
		while (pStr < endofstr) {
			if (*pStr == '%' && *(pStr + 1) == '3' && (*(pStr + 2) == 'A' || *(pStr + 2) == 'a')) {
				pStr = pStr + 3;
				continue;
			}

			if (*pStr >= 'A' && *pStr <= 'F') {
				macAddr[nAddr] = *pStr - 'A' + 10;
			} else if (*pStr >= 'a' && *pStr <= 'f') {
				macAddr[nAddr] = *pStr - 'a' + 10;
			} else if (*pStr >= '0' && *pStr <= '9') {
				macAddr[nAddr] = *pStr - '0';
			} else {
				return 0;
			}

			pStr++;

			if (*pStr >= 'A' && *pStr <= 'F') {
				macAddr[nAddr] = (macAddr[nAddr] << 4) | (*pStr - 'A' + 10);
			} else if (*pStr >= 'a' && *pStr <= 'f') {
				macAddr[nAddr] = (macAddr[nAddr] << 4) | (*pStr - 'a' + 10);
			} else if (*pStr >= '0' && *pStr <= '9') {
				macAddr[nAddr] = (macAddr[nAddr] << 4) | (*pStr - '0');
			} else {
				return 0;
			}

			pStr++;
			nAddr++;
		}

		if (nAddr != 6) {
			return 0;
		}
	} else {
		return 0;
	}

	return 1;
}

#define _U      0x01		/* upper */
#define _L      0x02		/* lower */
#define _D      0x04		/* digit */
#define _C      0x08		/* cntrl */
#define _P      0x10		/* punct */
#define _S      0x20		/* white space (space/lf/tab) */
#define _X      0x40		/* hex digit */
#define _SP     0x80		/* hard space (0x20) */

unsigned char _ctype[] = {
	_C, _C, _C, _C, _C, _C, _C, _C,	/* 0-7 */
	_C, _C | _S, _C | _S, _C | _S, _C | _S, _C | _S, _C, _C,	/* 8-15 */
	_C, _C, _C, _C, _C, _C, _C, _C,	/* 16-23 */
	_C, _C, _C, _C, _C, _C, _C, _C,	/* 24-31 */
	_S | _SP, _P, _P, _P, _P, _P, _P, _P,	/* 32-39 */
	_P, _P, _P, _P, _P, _P, _P, _P,	/* 40-47 */
	_D, _D, _D, _D, _D, _D, _D, _D,	/* 48-55 */
	_D, _D, _P, _P, _P, _P, _P, _P,	/* 56-63 */
	_P, _U | _X, _U | _X, _U | _X, _U | _X, _U | _X, _U | _X, _U,	/* 64-71 */
	_U, _U, _U, _U, _U, _U, _U, _U,	/* 72-79 */
	_U, _U, _U, _U, _U, _U, _U, _U,	/* 80-87 */
	_U, _U, _U, _P, _P, _P, _P, _P,	/* 88-95 */
	_P, _L | _X, _L | _X, _L | _X, _L | _X, _L | _X, _L | _X, _L,	/* 96-103 */
	_L, _L, _L, _L, _L, _L, _L, _L,	/* 104-111 */
	_L, _L, _L, _L, _L, _L, _L, _L,	/* 112-119 */
	_L, _L, _L, _P, _P, _P, _P, _C,	/* 120-127 */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,	/* 128-143 */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,	/* 144-159 */
	_S | _SP, _P, _P, _P, _P, _P, _P, _P, _P, _P, _P, _P, _P, _P, _P, _P,	/* 160-175 */
	_P, _P, _P, _P, _P, _P, _P, _P, _P, _P, _P, _P, _P, _P, _P, _P,	/* 176-191 */
	_U, _U, _U, _U, _U, _U, _U, _U, _U, _U, _U, _U, _U, _U, _U, _U,	/* 192-207 */
	_U, _U, _U, _U, _U, _U, _U, _P, _U, _U, _U, _U, _U, _U, _U, _L,	/* 208-223 */
	_L, _L, _L, _L, _L, _L, _L, _L, _L, _L, _L, _L, _L, _L, _L, _L,	/* 224-239 */
	_L, _L, _L, _L, _L, _L, _L, _P, _L, _L, _L, _L, _L, _L, _L, _L
};				/* 240-255 */
#define tolower(c) __tolower(c)
#define toupper(c) __toupper(c)
#define __ismask(x) (_ctype[(int)(unsigned char)(x)])
#define islower(c)      ((__ismask(c) & (_L)) != 0)
#define isupper(c)      ((__ismask(c) & (_U)) != 0)

static inline unsigned char __tolower(unsigned char c)
{
	if (isupper(c))
		c -= 'A' - 'a';
	return c;
}

static inline unsigned char __toupper(unsigned char c)
{
	if (islower(c))
		c -= 'a' - 'A';
	return c;
}

void HexStringToHexDigi(char *outHexData, char *inHexString, USHORT Len)
{
	char HexString[] = "0123456789ABCDEF";
	UCHAR i, HiNible, LoNible;

	for (i = 0; i < Len; ++i) {
		HiNible = strchr(HexString, toupper(inHexString[2 * i])) - HexString;
		LoNible = strchr(HexString, toupper(inHexString[2 * i + 1])) - HexString;
		outHexData[i] = (HiNible << 4) + LoNible;
	}
}

void HexDigiToHexString(char *outHexSring, char *inHexDigit, USHORT Len)
{
	UCHAR i, HiNible, LoNible;

	for (i = 0; i < Len; ++i) {
		HiNible = (inHexDigit[i] >> 4) & 0x0f;
		LoNible = inHexDigit[i] & 0x0f;
		outHexSring[i * 2] = (HiNible < 0x0a) ? (HiNible + 0x30) : (HiNible + 0x61 - 10);
		outHexSring[i * 2 + 1] = (LoNible < 0x0a) ? (LoNible + 0x30) : (LoNible + 0x61 - 10);
	}
}

int IsHexKey(char *keyStr)
{
	while (*keyStr != '\0') {
		if ((*keyStr >= '0' && *keyStr <= '9') || (*keyStr >= 'A' && *keyStr <= 'F')
		    || (*keyStr >= 'a' && *keyStr <= 'f')) {
			keyStr++;
			continue;
		} else
			return 0;
	}
	return 1;
}

#define isdigit(c)      ((__ismask(c) & (_D)) != 0)
#define isspace(c)      ((__ismask(c) & (_S)) != 0)
#define isascii(c) (((unsigned char)(c)) <= 0x7f)
#define isxdigit(c)     ((__ismask(c) & (_D | _X)) != 0)

int IPAsciiToNum(unsigned int *IPAddr, const char *pIPStr)
{
	unsigned long val;
	int base, n;
	char c;
	unsigned int parts[4];
	unsigned int *pp = parts;

	c = *pIPStr;
	memset((void *)parts, 0, sizeof(parts));

	for (;;) {
		/*
		 * Collect number up to ``.''.
		 * Values are specified as for C:
		 * 0x=hex, 0=octal, isdigit=decimal.
		 */
		if (!isdigit(c))
			return (0);
		val = 0;
		base = 10;
		if (c == '0') {
			c = *++pIPStr;
			if (c == 'x' || c == 'X')
				base = 16, c = *++pIPStr;
			else
				base = 8;
		}
		for (;;) {
			if (isascii(c) && isdigit(c)) {
				val = (val * base) + (c - '0');
				c = *++pIPStr;
			} else if (base == 16 && isascii(c) && isxdigit(c)) {
				val = (val << 4) | (c + 10 - (islower(c) ? 'a' : 'A'));
				c = *++pIPStr;
			} else
				break;
		}
		if (c == '.') {
			/*
			 * Internet format:
			 *  a.b.c.d
			 *  a.b.c   (with c treated as 16 bits)
			 *  a.b     (with b treated as 24 bits)
			 */
			if (pp >= parts + 3)
				return (0);
			*pp++ = val;
			c = *++pIPStr;
		} else
			break;
	}
	/*
	 * Check for trailing characters.
	 */
	if (c != '\0' && (!isascii(c) || !isspace(c)))
		return (0);
	/*
	 * Concoct the address according to
	 * the number of parts specified.
	 */
	n = pp - parts + 1;
	switch (n) {

	case 0:
		return (0);	/* initial nondigit */

	case 1:		/* a -- 32 bits */
		break;

	case 2:		/* a.b -- 8.24 bits */
		if (val > 0xffffff)
			return (0);
		val |= (unsigned long)(parts[0] << 24);
		break;

	case 3:		/* a.b.c -- 8.8.16 bits */
		if (val > 0xffff)
			return (0);
		val |= (unsigned long)((parts[0] << 24) | (parts[1] << 16));
		break;

	case 4:		/* a.b.c.d -- 8.8.8.8 bits */
		if (val > 0xff)
			return (0);
		val |= (unsigned long)((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8));
		break;
	}
	if (IPAddr)
		*IPAddr = val;
	return (1);

}

enum {
	BAND24G = 0,
	BAND5G = 1,
};

typedef struct wmm_q_status_s {
	int bkQLen;		//BK queue length
	int beQLen;		//BE queue length
	int viQLen;		//VI queue length
	int voQLen;		//VO queue length
} wmm_q_status_t;

typedef struct wifi_qos_cap_s {
	char wmmSupport;	// 1 means yes, 0 means no. Status configured by users.
	char sharePhyQueue;	// 1 means yes, 0 means no. It indicates whether multiple logical devices share one physical queue.
	char band;		// 1 means interface work on 5g band, 0 means on 24g band.
	wmm_q_status_t defaultQLen;	// default queue length
} wifi_qos_cap_t;

/***************************************************************************************
* Function: get_wifi_qos_cap
*
* Description:
*     This function is used to get QoS capability of a Wi-Fi interface.
*
* Parameters:
*     ifName: (in) interface name .
*     cap     : (out) QoS capability of input interface.Memory should been allocated by caller.
*
* Return Values:
*	NULL   : Interface does not exsit ,or function fails.
*    Pointer: used as a handler to get queue status.
*
***************************************************************************************/
extern struct wlprivate_data *global_private_data[MAX_CARDS_SUPPORT];
extern char *DRV_NAME;

struct net_device *get_wifi_qos_cap(char *ifName, wifi_qos_cap_t * cap)
{
	UINT8 rootname[sizeof(DRV_NAME) + 1];
	struct net_device *netdev;
	int i;
	struct wlprivate *priv;
	vmacApInfo_t *vmacSta_p;
	MIB_PHY_DSSS_TABLE *PhyDSSSTable;

	for (i = 0; i < MAX_CARDS_SUPPORT; i++) {
		netdev = global_private_data[i]->rootdev;
		memset(rootname, 0, sizeof(DRV_NAME) + 1);
		sprintf(rootname, "%s%1d", DRV_NAME, i);
		if (netdev && (!memcmp(rootname, ifName, strlen(rootname)))) {
			priv = NETDEV_PRIV_P(struct wlprivate, netdev);
			vmacSta_p = priv->vmacSta_p;
			PhyDSSSTable = vmacSta_p->Mib802dot11->PhyDSSSTable;
			if (vmacSta_p->Mib802dot11->QoSOptImpl)
				cap->wmmSupport = 1;
			else
				cap->wmmSupport = 0;
			cap->sharePhyQueue = 1;
			cap->defaultQLen.bkQLen = MAX_NUM_TX_DESC;
			cap->defaultQLen.beQLen = MAX_NUM_TX_DESC;
			cap->defaultQLen.viQLen = MAX_NUM_TX_DESC;
			cap->defaultQLen.voQLen = MAX_NUM_TX_DESC;
			if (PhyDSSSTable->Chanflag.FreqBand == FREQ_BAND_5GHZ)
				cap->band = BAND5G;
			else
				cap->band = BAND24G;
			return netdev;

		}
	}
	return NULL;
}

/***************************************************************************************
* Function: get_wifi_wmm_queue_status
*
* Description:
*     This function is to get instantaneous status of WMM queue.
*
* Parameters:
*       pdev  :(in)  interface handler returned by get_wifi_qos_cap().
*       status:(out) instantaneous status.
*
* Return Values:
*      0:    successful
*    -1:    failed
*
* Note:
*     Efficiency must be considered. This function will be invoked tons of times per second.
*
***************************************************************************************/
int get_wifi_wmm_queue_status(struct net_device *pdev, wmm_q_status_t * status)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, pdev);

	if (wlpptr && wlpptr->wlpd_p) {
		memcpy((char *)status, (char *)&(wlpptr->wlpd_p->fwDescCnt[0]), sizeof(wmm_q_status_t));
		return 0;
	}
	return -1;
}

void ratetable_print_SOCW8864(UINT8 * pTbl)
{
	dbRateInfo_t *pRateTbl;
	int j, Rate, Nss;

#ifdef SOC_W906X
	printk("%3s %6s %5s %5s %5s %5s %5s %5s %4s %2s %5s %4s %5s %5s\n",
#else
	printk("%3s %6s %5s %5s %5s %5s %5s %4s %2s %5s %4s %5s %5s\n",
#endif				/* SOC_W906X */
	       "Num", "Fmt", "STBC",
#ifdef SOC_W906X
	       "DCM",
#endif				/* SOC_W906X */
	       "BW", "SGI", "Nss", "RateId", "GF/Pre", "PId", "LDPC", "BF", "TxAnt", "Rate");

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
				else if ((pRateTbl->RateIDMCS >= 8) && (pRateTbl->RateIDMCS < 16))
					Nss = 2;
				else if ((pRateTbl->RateIDMCS >= 16) && (pRateTbl->RateIDMCS < 24))
					Nss = 3;
				else if ((pRateTbl->RateIDMCS >= 24) && (pRateTbl->RateIDMCS < 32))
					Nss = 4;
			}
		}
#ifdef SOC_W906X
		printk("%3d %5d %5d %5d %5d %5d %5d %5d %5d %5d %5d %5d %5d %5d\n",
#else
		printk("%3d %5d %5d %5d %5d %5d %5d %5d %5d %5d %5d %5d %5d\n",
#endif				/* SOC_W906X */
		       (int)j, (int)pRateTbl->Format, (int)pRateTbl->Stbc,
#ifdef SOC_W906X
		       (int)pRateTbl->Dcm,
#endif				/* SOC_W906X */
		       (int)pRateTbl->Bandwidth,
		       (int)pRateTbl->ShortGI,
		       (int)Nss,
		       (int)Rate,
		       (int)pRateTbl->Preambletype,
		       (int)pRateTbl->PowerId,
		       (int)pRateTbl->AdvCoding, (int)pRateTbl->BF, (int)pRateTbl->AntSelect, (int)getPhyRate((dbRateInfo_t *) pRateTbl));

		j++;
		pTbl += (2 * sizeof(dbRateInfo_t));	//SOC_W8864 rate parameter is 2 DWORD. Multiply by 2 because dbRateInfo_t is only 1 DWORD
		pRateTbl = (dbRateInfo_t *) pTbl;
	}
	printk("\n");

}

int mwl_wext_rx_mgmt(struct net_device *netdev, void *mgt, size_t len)	//, uint8_t rssi)
{
	UINT8 *buf = NULL;
	int buf_len = 1024;
	union iwreq_data wreq;
	static const char tag_rxmgmt[] = "drv_mgmtrx";

	if ((netdev->flags & IFF_RUNNING) == 0)
		return 0;

	buf = wl_kzalloc(buf_len, GFP_ATOMIC);
	if (!buf)
		return -ENOMEM;

	memcpy(buf, tag_rxmgmt, strlen(tag_rxmgmt));
	memcpy(&buf[strlen(tag_rxmgmt)], mgt, len);
	memset(&wreq, 0, sizeof(wreq));
	wreq.data.length = strlen(tag_rxmgmt) + len;
	wireless_send_event(netdev, IWEVCUSTOM, &wreq, buf);

	wl_kfree(buf);
	return 0;
}

#ifdef SOC_W906X
//convert floating string fomat to (sign)a.b interger format. example: -12.35 sign=1, a=12, b=35, decDigit[0-3]=3,5,0,0
//decDigit return max 4 digits after decimal point.
int _atof(u8 * str, u8 * sign, u32 * a, u32 * b, u8 * decDigit)
{
	u8 fra_idx = 0;
	u32 i;
	u32 token1 = 0;
	u32 token2 = 0;
	u32 digit = 0;
	u8 frdigit[4];
	u8 didx = 0;

	*sign = 0;
	while (isspace(*str))
		str += 1;

	if (str[0] == '-') {
		*sign = 1;
		str += 1;
	} else if (str[0] == '+') {
		*sign = 0;
		str += 1;
	}

	memset(frdigit, 0, sizeof(frdigit));
	for (i = 0, fra_idx = strlen(str); i < strlen(str); i++) {

		if (str[i] == '.') {
			fra_idx = i;
			didx = 0;
			continue;
		}

		digit = str[i] - '0';
		//printf("digit:%u\n",digit);
		if (digit > 9)
			return 0;

		if (i < fra_idx) {
			token1 = token1 * 10 + digit;
		} else if (i > fra_idx) {
			token2 = token2 * 10 + digit;
			frdigit[didx++] = digit;
		}
		//only get 3 digits after decimal point
		if (didx > 2)
			break;
	}

	//if(sign == 1)
	//      token1 = 0 - token1;

	*a = token1;
	*b = token2;

	memcpy(decDigit, frdigit, 4);

	//printk("a.b=%d.%d:%d.%d%d%d%d \n", *a, *b, *a, decDigit[0],decDigit[1],decDigit[2],decDigit[3]);
	return 1;
}

/*
	Convert floating format (a.b) to PowerLevel format used in FW
	only use 11bits to store the PowerLevel. 
*/
int _PoweLevelToDUT(u8 sign, u32 a, u32 b, u8 * digit, UINT32 * PowerLevel)
{
	//long int X = 0;
	//int Z = 0;
	int i;
	u8 carry = 0;
	//int pwr=0;

	//power valid range  [-64 ~ 63.9375] data is from labtool   
	if ((!sign && (a > 63 || (a == 63 && b > 9375))) || (sign && a > 64)) {
		printk("Invalid power value: %d.%d\n", a, b);
		return 0;
	}

	a = a * 16;

	for (i = 4; i >= 0; i--) {

		digit[i] *= 16;
		digit[i] += carry;

		carry = 0;
		while (digit[i] >= 10) {
			carry++;
			digit[i] -= 10;
		}
	}

	a += carry;

	//round to integer 
	if (digit[0] >= 5)
		a += 1;

	if (sign) {
		a = (~a) + 1;
		a = a + (1 << 11);
	}

	*PowerLevel = a;
	//printk("PowerLevel:%08x\n", *PowerLevel);
	return 1;
}

//convert PowerLevel from FW format to decimal floating represent by two int a.b 
int _DUTToPoweLevel(u8 * sign, u32 * a, u8 * digit, u32 PowerLevel)
{
	//Power level sign+6+4  -64 to 63.9375
	//float X = 0;
	UINT32 Pwrbuff = PowerLevel;
	int i;

	*sign = 0;
	if (PowerLevel & (1 << 10))	//sign bit is 1
	{
		*sign = 1;
		Pwrbuff += (~0x7ff);
		Pwrbuff = (~Pwrbuff) + 1;
	}

	*a = Pwrbuff / 16;
	Pwrbuff = Pwrbuff % 16;

	//printf("Pwrbuff:%u\n", Pwrbuff);

	for (i = 0; i < 4; i++) {
		digit[i] = 0;

		Pwrbuff *= 10;

		digit[i] = Pwrbuff / 16;

		Pwrbuff -= (digit[i] * 16);
		//printf("digit:%u\n", digit[i]);  
	}

	//printf("%c%u.%u%u%u%u\n", *sign ? '-':'+', *a, digit[0], digit[1],digit[2],digit[3]);    

	return 0;
}

//temporary auto gruping incoming clients for PF3 for OFDMA DL
//return #STAs grouped
int auto_group_ofdma_mu(vmacApInfo_t * vmac_p)
{
	UINT8 i, MUUsrCnt = 0;
	UINT16 Stnid[MU_MAX_USERS];
	MUCapStaNode_t *item_p = NULL;
	extStaDb_StaInfo_t *StaInfo[MU_MAX_USERS];
	UINT8 myGid = 1;

	for (i = 0; i < MU_MAX_USERS; i++) {
		StaInfo[i] = NULL;
		Stnid[i] = (UINT16) 0xFFFF;
	}

	//get all STAs to group 
	for (i = 0; i < ARRAY_SIZE(vmac_p->MUStaList); i++) {
		item_p = (MUCapStaNode_t *) vmac_p->MUStaList[i].tail;	//get first item added to list from tail
		while (item_p != NULL && MUUsrCnt < MU_MAX_USERS) {
			StaInfo[MUUsrCnt++] = item_p->StaInfo_p;
			item_p = item_p->prv;
		}
	}

	if (MUUsrCnt == 0)
		return 0;

	if (wlFwSetMUSet(vmac_p->dev, 1, myGid, myGid - 1, Stnid)) {
		printk("Set MU set OK!\n");
	} else {
		printk("Error. Set MU set fail!\n");
		return 0;
	}

	return MUUsrCnt;
}

//get nontransmitted bssid_profile bitmap
//xmit_bssid: 1: transmitted bssid profile, 0:nontransmitted bssid profile, 2:nontransmitted bssid w/o including inupdate
u32 get_mbssid_profile(void *wlpd, u8 xmit_bssids)
{
	struct wlprivate_data *wlpd_p = wlpd;
	u32 bitmap = 0;
	mbss_set_t *pset = wlpd_p->mbssSet;
	u32 i;

	for (i = 0; i < MAX_MBSSID_SET; i++) {
		if (pset[i].mbssid_set) {
			if (xmit_bssids == 1)
				bitmap |= (pset[i].mbssid_set & (1 << pset[i].primbss));
			else {
				bitmap |= (pset[i].mbssid_set & ~(1 << pset[i].primbss));
			}
		}
	}

	//to prevent HM false alarm, including all mbssid that are configured but not commit yet. 
	if (xmit_bssids == 0)
		bitmap |= wlpd_p->bss_inupdate;

	//printk("%s:%x\n",__func__, bitmap);

	return bitmap;
}

//get individual BSSs that do not join any MBSSID group
//note: the return BSSs also include non-active BSSs.
u32 get_individual_bss(void *wlpd)
{
	struct wlprivate_data *wlpd_p = wlpd;
	u32 bitmap = 0;
	mbss_set_t *pset = wlpd_p->mbssSet;
	u32 set = 0;
	u32 i;

	for (i = 0; i < MAX_MBSSID_SET; i++) {
		set |= pset[i].mbssid_set;
		//printk("set:%x\n", set);
	}

	//bitmap = (~set) & wlpd_p->bss_active;

	//printk("get_individual_bss:%x, active bss:%x\n", bitmap,wlpd_p->bss_active );

	bitmap = ~set;

	return bitmap;
}

#endif

EXPORT_SYMBOL(get_wifi_wmm_queue_status);
EXPORT_SYMBOL(get_wifi_qos_cap);
