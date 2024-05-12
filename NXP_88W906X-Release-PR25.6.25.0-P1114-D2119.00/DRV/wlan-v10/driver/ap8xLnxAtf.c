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
#include "StaDb.h"

extern int atoi(const char *num_str);
extern int getMacFromString(unsigned char *macAddr, const char *pStr);
IEEEtypes_MacAddr_t g_atf_mode4_mac[SMAC_STA_NUM];
int g_atf_mode4_set;

void atf_enable(struct net_device *netdev, MIB_802DOT11 * mib, char *param2)
{
	u8 enable = atoi(param2);
	int ret;

	if (enable)
		printk("Enable ATF\n");
	else
		printk("Disable ATF\n");

	(mib->mib_atf_info)->enable = enable;
	ret = wlFwAtfEnable(netdev, enable);
	if (ret != 0)
		printk("ERROR: atf enable fail: %d\n", ret);
}

int atf_config_mode1(MIB_802DOT11 * mib, char *param3, char *param4)
{
	u32 threshold;

	printk("Configure for ATF mode1 (Auto Simple ATF mode)\n");

	if (strcmp(param3, "threshold") != 0) {
		//wrong input
		printk("ERROR: wrong format\n");
		printk("iwpriv <ifname> setcmd \"atf set 1 threshold <rate>\"\n");
		return 0;
	}

	threshold = atoi(param4);
	threshold *= ATF_RATE_M_Hz;
	(mib->mib_atf_info)->mode1_threshold_rate_hi = threshold;
	(mib->mib_atf_info)->mode = ATF_MODE1_AUTO_SIMPLE;
	printk("Set rate threshold to %d Mbps\n", threshold / ATF_RATE_M_Hz);

	return 1;
}

int atf_config_mode2(MIB_802DOT11 * mib, char *param3, char *param4, char *param5, char *param6)
{
	u32 threshold;
	u8 percent;

	printk("Configure for ATF mode2 (Reversed ATF mode)\n");
	if ((strcmp(param3, "threshold") != 0) || (strcmp(param5, "percent") != 0)) {
		//wrong input
		printk("ERROR: wrong format\n");
		printk("iwpriv <ifname> setcmd \"atf set 2 threshold <rate> percent <val>\"\n");
		return 0;
	}

	threshold = atoi(param4);
	threshold *= ATF_RATE_M_Hz;
	percent = atoi(param6);
	(mib->mib_atf_info)->mode2_threshold_rate_lo = threshold;
	(mib->mib_atf_info)->mode2_airtime_percent = percent;
	(mib->mib_atf_info)->mode = ATF_MODE2_REVERSED;

	printk("Set rate threshold to %d Mbps\n", threshold / ATF_RATE_M_Hz);
	printk("Set airtime percent to %d%%\n", percent);

	return 1;
}

int atf_config_mode3(MIB_802DOT11 * mib, char *param3, char *param4, char *param5, char *param6, char *param7, char *param8)
{
	u8 mcs_lo, mcs_hi;
	u8 percent;

	printk("Configure for ATF mode3 (Configured ATF mode)\n");

	if ((strcmp(param3, "mcs_lo") != 0) || (strcmp(param5, "mcs_hi") != 0) || (strcmp(param7, "percent") != 0)) {
		//wrong input
		printk("ERROR: wrong format\n");
		printk("iwpriv <ifname> setcmd \"atf set 3 mcs_lo <mcs> mcs_hi <mcs> percent <val>\"\n");
		return 0;
	}

	mcs_lo = atoi(param4);
	mcs_hi = atoi(param6);
	percent = atoi(param8);

	(mib->mib_atf_info)->mode3_threshold_mcs_lo = mcs_lo;
	(mib->mib_atf_info)->mode3_threshold_mcs_hi = mcs_hi;
	(mib->mib_atf_info)->mode3_airtime_percent = percent;
	(mib->mib_atf_info)->mode = ATF_MODE3_CONFIGURED;

	printk("Set mcs low to %d\n", mcs_lo);
	printk("Set mcs high to %d\n", mcs_hi);
	printk("Set airtime percent to %d%%\n", percent);

	return 1;
}

int atf_config_mode4(struct net_device *netdev, MIB_802DOT11 * mib, char *param3, char *param4, char *param5, char *param6)
{
	u8 percent;
	int id;
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);

	printk("Configure for ATF mode4 (Advanced ATF mode)\n");
	if ((strcmp(param3, "bss") == 0) && (strcmp(param4, "percent") == 0)) {
		percent = atoi(param5);
		id = priv->vap_id;
		(mib->mib_atf_info)->mode4_bss_percent[id] = percent;
		printk("bss vap id %d: set airtime to %d%%\n", id, percent);
	} else if ((strcmp(param3, "sta") == 0) && (strcmp(param5, "percent") == 0)) {
		extStaDb_StaInfo_t *pStaInfo;
		IEEEtypes_MacAddr_t macaddr;
		vmacApInfo_t *vmacSta_p = priv->vmacSta_p;

		getMacFromString(macaddr, param4);
		pStaInfo = extStaDb_GetStaInfo(vmacSta_p, (IEEEtypes_MacAddr_t *) macaddr, STADB_DONT_UPDATE_AGINGTIME);
		if (pStaInfo) {
			percent = atoi(param6);
			id = pStaInfo->StnId;
			(mib->mib_atf_info)->mode4_sta_percent[id] = percent;
			memcpy(g_atf_mode4_mac[id], &macaddr, sizeof(IEEEtypes_MacAddr_t));
			printk("stn %d (mac %pM): set airtime to %d%%\n", id, macaddr, percent);
		} else {
			printk("ERROR: no such station with mac %pM\n", macaddr);
			return 0;
		}
	} else {
		//wrong input
		printk("ERROR: wrong format\n");
		printk("iwpriv <ifname> setcmd \"atf set 4 bss percent <val>\"\n");
		printk("iwpriv <ifname> setcmd \"atf set 4 sta <mac> percent <val>\"\n");
		return 0;
	}

	(mib->mib_atf_info)->mode = ATF_MODE4_ADVANCED;
	g_atf_mode4_set = 1;
	return 1;
}

/* When station is re-associate, it will be assigned a new staidx
 * we need to apply ATF setting (if any) to the new staidx */
void atf_check_setting(struct net_device *netdev, IEEEtypes_MacAddr_t * macaddr, u32 staidx)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	int i;
	int percent = 0;

	if (!g_atf_mode4_set)
		return;

	for (i = 0; i < SMAC_STA_NUM; i++) {
		if (!memcmp(g_atf_mode4_mac[i], macaddr, sizeof(IEEEtypes_MacAddr_t))) {
			percent = (mib->mib_atf_info)->mode4_sta_percent[i];

			//clear the value in old staid
			(mib->mib_atf_info)->mode4_sta_percent[i] = 0;
			memset(g_atf_mode4_mac[i], 0, sizeof(IEEEtypes_MacAddr_t));
		}
	}

	if (percent) {
		int ret;
		(mib->mib_atf_info)->mode4_sta_percent[staidx] = percent;
		memcpy(g_atf_mode4_mac[staidx], macaddr, sizeof(IEEEtypes_MacAddr_t));

		ret = wlFwAtfCfgSet(netdev, mib->mib_atf_info);
		if (ret != 0)
			printk("ERROR: atf enable fail: %d\n", ret);
	}
}

int atf_sanity_check_enable(MIB_802DOT11 * mib)
{
	u8 enable = (mib->mib_atf_info)->enable;
	if (enable) {
		printk("ERROR: cannot configure ATF while ATF is enabled.\n");
		printk("Please disable ATF using below command\n");
		printk("$ iwpriv <ifname> setcmd \"atf enable 0\"\n");
		return FAIL;
	}
	return 0;
}

int atf_cfg_sanity_check(MIB_802DOT11 * mib, char *mode_str)
{
	u8 mode = atoi(mode_str);

	if (atf_sanity_check_enable(mib))
		return FAIL;

	if (mode >= ATF_MODE_MAX || mode == ATF_MODE0_DISABLED) {
		printk("ERROR: no such mode: %d\n", mode);
		printk("Supported mode:\n");
		printk("    mode1: Auto Simple ATF mode\n");
		printk("    mode2: Reversed ATF mode\n");
		printk("    mode3: Configured ATF mode\n");
		printk("    mode4: Advanced ATF mode\n");
		return FAIL;
	}
	return 0;
}

void atf_config_set(struct net_device *netdev, MIB_802DOT11 * mib, char *param2,
		    char *param3, char *param4, char *param5, char *param6, char *param7, char *param8)
{
	u8 mode = atoi(param2);
	int cfg_set = 0;

	if (atf_cfg_sanity_check(mib, param2))
		return;

	switch (mode) {
	case ATF_MODE1_AUTO_SIMPLE:
		cfg_set = atf_config_mode1(mib, param3, param4);
		break;
	case ATF_MODE2_REVERSED:
		cfg_set = atf_config_mode2(mib, param3, param4, param5, param6);
		break;
	case ATF_MODE3_CONFIGURED:
		cfg_set = atf_config_mode3(mib, param3, param4, param5, param6, param7, param8);
		break;
	case ATF_MODE4_ADVANCED:
		cfg_set = atf_config_mode4(netdev, mib, param3, param4, param5, param6);
		break;
	default:
		{
			printk("ERROR: wrong mode\n");
			atf_print_usage();
			break;
		}
	}

	if (cfg_set) {
		int ret;
		ret = wlFwAtfCfgSet(netdev, mib->mib_atf_info);
		if (ret != 0)
			printk("ERROR: atf enable fail: %d\n", ret);
	}
}

void atf_config_reset(struct net_device *netdev, MIB_802DOT11 * mib)
{
	int ret;

	if (atf_sanity_check_enable(mib))
		return;

	printk("Reset all ATF config to default value\n");
	memset(mib->mib_atf_info, 0, sizeof(atf_info_t));
	g_atf_mode4_set = 0;

	ret = wlFwAtfCfgReset(netdev);
	if (ret != 0)
		printk("ERROR: atf config reset fail: %d\n", ret);
}

void atf_print_mode1(atf_info_t * atf_info, int more_msg)
{
	u32 threshold;
	u32 airtime;

	threshold = atf_info->mode1_threshold_rate_hi;
	airtime = atf_info->mode1_min_airtime;
	printk("Mode1 Auto Simple ATF mode\n");
	printk("rate threshold (high): %d Mbps\n", threshold / ATF_RATE_M_Hz);
	printk("current minimum airtime: %d micro sec\n", airtime);

	if (more_msg)
		printk("Station with PHY rate lower than the threshold will use minimum airtime\n");
	printk("\n");
}

void atf_print_mode2(atf_info_t * atf_info, int more_msg)
{
	u32 threshold;
	u8 percent;

	threshold = atf_info->mode2_threshold_rate_lo;
	percent = atf_info->mode2_airtime_percent;

	printk("Mode2 Reversed ATF mode\n");
	printk("rate threshold (low): %d Mbps\n", threshold / ATF_RATE_M_Hz);
	printk("airtime percent: %d\n", percent);

	if (more_msg) {
		printk("For the station with PHY rate higher than the threshold\n");
		printk("airtime will be reduced to %d%% of default airtime\n", percent);
	}
	printk("\n");
}

void atf_print_mode3(atf_info_t * atf_info, int more_msg)
{
	u8 percent;
	u8 mcs_hi, mcs_lo;

	mcs_lo = atf_info->mode3_threshold_mcs_lo;
	mcs_hi = atf_info->mode3_threshold_mcs_hi;
	percent = atf_info->mode3_airtime_percent;

	printk("Mode3 Configured ATF mode\n");
	printk("mcs low: %d\n", mcs_lo);
	printk("mcs high: %d\n", mcs_hi);

	if (more_msg) {
		printk("airtime percent: %d\n", percent);
		printk("1. For the station with mcs < %d: AMPDU aggregation size = 1\n", mcs_lo);
		printk("2. For the station with mcs between %d and %d\n", mcs_lo, mcs_hi);
		printk("   airtime will be reduced to %d%% of default airtime\n", percent);
	}
	printk("\n");
}

void atf_print_mode4(atf_info_t * atf_info)
{
	int i;
	u8 percent;

	printk("Mode4 Advanced ATF mode\n");
	printk("Configured BSS/STA:\n");

	for (i = 0; i < SMAC_BSS_NUM; i++) {
		percent = atf_info->mode4_bss_percent[i];
		if (percent)
			printk("BSS %d: reduce airtime to %d%% of default airtime\n", i, percent);
	}

	for (i = 0; i < SMAC_STA_NUM; i++) {
		percent = atf_info->mode4_sta_percent[i];
		if (percent)
			printk("STA %d (mac %pM): reduce airtime to %d%% of default airtime\n", i, g_atf_mode4_mac[i], percent);
	}

	printk("\n");
}

void atf_print_enable(atf_info_t * atf_info)
{
	if (atf_info->enable) {
		printk("ATF is Enabled\n\n");
	} else {
		printk("ATF is Disabled\n\n");
	}
}

void atf_dump_status_cur_mode(atf_info_t * atf_info)
{
	u8 mode = atf_info->mode;

	if (mode == ATF_MODE0_DISABLED)
		return;

	printk("ATF mode: ");

	switch (mode) {
	case ATF_MODE1_AUTO_SIMPLE:
		atf_print_mode1(atf_info, 1);
		break;
	case ATF_MODE2_REVERSED:
		atf_print_mode2(atf_info, 1);
		break;
	case ATF_MODE3_CONFIGURED:
		atf_print_mode3(atf_info, 1);
		break;
	case ATF_MODE4_ADVANCED:
		atf_print_mode4(atf_info);
		break;
	default:
		printk("ERROR: invalid mode: %d\n", mode);
		break;
	}
}

void atf_dump_status_all_mode(atf_info_t * atf_info)
{
	printk("ATF mode: mode%d\n\n", atf_info->mode);

	if (atf_info->mode == ATF_MODE0_DISABLED) {
		printk("No mode is configured\n");
		return;
	}

	atf_print_mode1(atf_info, 0);
	atf_print_mode2(atf_info, 0);
	atf_print_mode3(atf_info, 0);
	atf_print_mode4(atf_info);
}

void atf_get_cfg_from_fw(struct net_device *netdev, atf_info_t * atf_info)
{
	int ret;

	ret = wlFwAtfCfgGet(netdev, atf_info);
	if (ret != 0) {
		printk("ERROR: atf config get fail: %d\n", ret);
		atf_info = NULL;
	}
}

void atf_get_fw_cfg_dump_cur(struct net_device *netdev)
{
	atf_info_t fw_atf_cfg;

	printk("ATF Status\n");

	atf_get_cfg_from_fw(netdev, &fw_atf_cfg);
	atf_print_enable(&fw_atf_cfg);
	atf_dump_status_cur_mode(&fw_atf_cfg);
}

void atf_dump_all_info(struct net_device *netdev, MIB_802DOT11 * mib)
{
	int ret;
	atf_info_t fw_atf_cfg;

	printk("### ATF status from FW ###\n");
	atf_get_cfg_from_fw(netdev, &fw_atf_cfg);
	atf_print_enable(&fw_atf_cfg);
	atf_dump_status_all_mode(&fw_atf_cfg);
	printk("\n");

	/* compare with driver setting */
	/* driver does not have minimum airtime, so we get it from firmware */
	(mib->mib_atf_info)->mode1_min_airtime = fw_atf_cfg.mode1_min_airtime;
	ret = memcmp(mib->mib_atf_info, &fw_atf_cfg, sizeof(atf_info_t));
	if (ret) {
		printk("ERROR: firmware status is different with driver setting\n\n");

		printk("### ATF setting in driver ###\n");
		atf_print_enable(mib->mib_atf_info);
		atf_dump_status_all_mode(mib->mib_atf_info);
		printk("\n");
	}
}

void atf_print_usage(void)
{
	printk("Enable/Disable ATF\n");
	printk("$ iwpriv <ifname> setcmd \"atf enable <#>\"\n");
	printk("0: disable\n");
	printk("1: enable\n");
	printk("\n");

	printk("Configure ATF\n");
	printk("$ iwpriv <ifname> setcmd \"atf set <mode> <mode_parameter>\"\n");
	printk("Supported mode: 1-4\n");
	printk("\n");

	printk("Mode1: Auto Simple ATF mode\n");
	printk("$ iwpriv <ifname> setcmd \"atf set 1 threshold <rate>\"\n");
	printk("<rate>: in unit of Mbps\n");
	printk("Station with PHY rate lower than the threshold will use minimum airtime\n");
	printk("\n");

	printk("Mode2: Reversed ATF mode\n");
	printk("$ iwpriv <ifname> setcmd \"atf set 2 threshold <rate> percent <val>\"\n");
	printk("<rate>: in unit of Mbps\n");
	printk("For the station with PHY rate higher than the threshold\n");
	printk("airtime will be reduced to configured percentage of default airtime\n");
	printk("\n");

	printk("Mode3: Configured ATF mode\n");
	printk("$ iwpriv <ifname> setcmd \"atf set 3 mcs_lo <mcs> mcs_hi <mcs> percent <val>\"\n");
	printk("1. For the station with mcs < mcs_lo: AMPDU aggregation size = 1\n");
	printk("2. For the station with mcs between mcs_lo and mcs_hi\n");
	printk("   airtime will be reduced to configured percentage of default airtime\n");
	printk("\n");

	printk("Mode4: Advanced ATF mode\n");
	printk("$ iwpriv <ifname> setcmd \"atf set 4 bss percent <val>\"\n");
	printk("$ iwpriv <ifname> setcmd \"atf set 4 sta <mac> percent <val>\"\n");
	printk("Reduce airtime to configured percentage of default airtime for BSS or specific STA\n");
}
