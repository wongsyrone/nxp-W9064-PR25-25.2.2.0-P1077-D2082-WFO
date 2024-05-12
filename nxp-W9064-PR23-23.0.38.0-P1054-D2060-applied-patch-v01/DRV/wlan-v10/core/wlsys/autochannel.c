/** @file autochannel.c
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2002-2020 NXP
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

/*
 *
 * Purpose:
 *    This file contains the implementations of the auto channel selection functions.
 *
 */
#include "ap8xLnxRegs.h"
#include "ap8xLnxFwcmd.h"
#include "ap8xLnxXmit.h"
#include "ap8xLnxIntf.h"
#include "ap8xLnxVer.h"

#include "wltypes.h"
#include "IEEE_types.h"
#include "mib.h"
#include "util.h"

#include "osif.h"
#include "wl_mib.h"
#include "wl_hal.h"
#include "qos.h"
#include "wlmac.h"

#include "wl_macros.h"
#include "wldebug.h"
#include "StaDb.h"
#include "domain.h"
#include "macMgmtMlme.h"
#ifdef CFG80211
#include "cfg80211.h"
#endif
#ifdef IEEE80211K
#include "msan_report.h"
#endif //IEEE80211K

#ifdef AUTOCHANNEL

void SendScanCmd(vmacApInfo_t * vmacSta_p, UINT8 * channels);
void StopAutoChannel(vmacApInfo_t * vmacSta_p);
UINT32
Rx_Traffic_Cnt(vmacApInfo_t * vmacSta_p)
{
#ifdef SOC_W906X		//TODO: Need SMAC register to replace  here
	return 0;
#else
	return PciReadMacReg(vmacSta_p->dev, RX_TRAFFIC_CNT);
#endif
}

UINT32
Rx_Traffic_Err_Cnt(vmacApInfo_t * vmacSta_p)
{
#ifdef SOC_W906X		//TODO: Need SMAC register to replace  here
	return 0;
#else
	return PciReadMacReg(vmacSta_p->dev, RX_TRAFFIC_ERR_CNT);
#endif
}

UINT32
Rx_Traffic_BBU(vmacApInfo_t * vmacSta_p)
{
#ifdef SOC_W906X		//TODO: Need SMAC register to replace  here
	return 0;
#else
	return PciReadMacReg(vmacSta_p->dev, RX_BBU_RXRDY_CNT);
#endif
}

static void
PrepareNextScan(vmacApInfo_t * vmacSta_p)
{
	vmacSta_p->autochannelstarted = 0;
}

static BOOLEAN
SetupScan(vmacApInfo_t * vmacAP_p)
{
	vmacApInfo_t *vmacSta_p;
	MIB_802DOT11 *mib;
	UINT8 *mib_autochannel_p;

#ifdef COEXIST_20_40_SUPPORT
	UINT8 ScanningFlag = 0;
#endif
	MIB_PHY_DSSS_TABLE *PhyDSSSTable;
	struct net_device *netdev = NULL;
	struct wlprivate *wlpptr = NULL;
	BOOLEAN vmacSTA_UP = 0;
	int i = 0, j;

	if (vmacAP_p->master)
		vmacSta_p = vmacAP_p->master;
	else
		vmacSta_p = vmacAP_p;
	mib = vmacSta_p->ShadowMib802dot11;
	mib_autochannel_p = mib->mib_autochannel;
	PhyDSSSTable = mib->PhyDSSSTable;

	netdev = vmacSta_p->dev;
	wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);

	vmacSta_p->preautochannelfinished = 0;
	vmacSta_p->acs_cur_bcn = 0;

	while (i <= bss_num) {
		//find the STA wdevxsta0 device here.
		if (wlpptr->vdev[i]) {
			if ((NETDEV_PRIV_P(struct wlprivate, wlpptr->vdev[i]))->
			    vmacSta_p->OpMode == WL_OP_MODE_VSTA) {
				if (wlpptr->wlpd_p->dev_running[i]) {	//interface used to be UP and running
					vmacSTA_UP = 1;
					break;
				}
			}
		}
		i++;
	}
#ifdef COEXIST_20_40_SUPPORT
	if (*(vmacSta_p->ShadowMib802dot11->mib_HT40MIntoler) &&
	    ((PhyDSSSTable->Chanflag.ChnlWidth == CH_AUTO_WIDTH) ||
	     (PhyDSSSTable->Chanflag.ChnlWidth == CH_160_MHz_WIDTH) ||
	     (PhyDSSSTable->Chanflag.ChnlWidth == CH_40_MHz_WIDTH) ||
	     (PhyDSSSTable->Chanflag.ChnlWidth == CH_80_MHz_WIDTH)))
		if (*(vmacSta_p->Mib802dot11->mib_ApMode) == AP_MODE_N_ONLY ||
		    *(vmacSta_p->Mib802dot11->mib_ApMode) == AP_MODE_BandN ||
		    *(vmacSta_p->Mib802dot11->mib_ApMode) == AP_MODE_GandN ||
		    *(vmacSta_p->Mib802dot11->mib_ApMode) == AP_MODE_BandGandN
		    || *(vmacSta_p->Mib802dot11->mib_ApMode) ==
		    AP_MODE_2_4GHZ_11AC_MIXED
#ifdef SOC_W906X
		    || *(vmacSta_p->Mib802dot11->mib_ApMode) ==
		    AP_MODE_2_4GHZ_Nand11AX ||
		    *(vmacSta_p->Mib802dot11->mib_ApMode) ==
		    AP_MODE_2_4GHZ_11AX_MIXED
#endif /* SOC_W906X */
			) {
			/** only do 20/40 coexist for n mode in 2.4G band **/
			void Disable_StartCoexisTimer(vmacApInfo_t * vmacSta_p);

			*(mib->USER_ChnlWidth) = 1;
			ScanningFlag = 1;

		}
#endif

#ifdef CLIENT_SUPPORT
#ifdef COEXIST_20_40_SUPPORT
	if ((*mib_autochannel_p || ScanningFlag) && (!vmacSta_p->busyScanning)
	    && ((*(mib->mib_STAMode) == CLIENT_MODE_DISABLE) || (!vmacSTA_UP)))
#else
	if (*mib_autochannel_p && (!vmacSta_p->busyScanning) &&
	    ((*(mib->mib_STAMode) == CLIENT_MODE_DISABLE) || (!vmacSTA_UP)))
#endif
#else
	if (*mib_autochannel_p && !vmacSta_p->busyScanning)
#endif
	{
		UINT8 scanChannel[IEEEtypes_MAX_CHANNELS +
				  IEEEtypes_MAX_CHANNELS_A] =
			{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 0, 36, 40,
44, 48, 52, 56, 60, 64, 149, 153, 157, 161, 165, 0, 0, 0, 0, 0, 0 };
		if (*(mib->mib_regionCode) == DOMAIN_CODE_ALL) {
			UINT8 i;

			for (i = 0;
			     i <
			     (IEEEtypes_MAX_CHANNELS +
			      IEEEtypes_MAX_CHANNELS_A); i++) {
				if (scanChannel[i] == 165) {
					break;
				}
			}

			if ((i + 4) >=
			    (IEEEtypes_MAX_CHANNELS + IEEEtypes_MAX_CHANNELS_A))
				return FALSE;

			scanChannel[i + 1] = 169;
			scanChannel[i + 2] = 173;
			scanChannel[i + 3] = 177;
			scanChannel[i + 4] = 181;

		}
		/* get range to scan */
		domainGetInfo(scanChannel);
		if (*(vmacSta_p->Mib802dot11->mib_autochannel) == 2) {
			memset(scanChannel, 0,
			       sizeof(UINT8) * (IEEEtypes_MAX_CHANNELS +
						IEEEtypes_MAX_CHANNELS_A));
			for (i = 0;
			     i <
			     (IEEEtypes_MAX_CHANNELS +
			      IEEEtypes_MAX_CHANNELS_A); i++) {
				for (j = 0;
				     j <
				     (IEEEtypes_MAX_CHANNELS +
				      IEEEtypes_MAX_CHANNELS_A); j++) {
					if (vmacSta_p->ChannelList[i] ==
					    vmacSta_p->OpChanList[j]) {
						scanChannel[i] =
							vmacSta_p->
							ChannelList[i];
						break;
					}
				}
			}
		}
		if (PhyDSSSTable->Chanflag.ChnlWidth != CH_20_MHz_WIDTH) {
			UINT8 i;

			for (i = 0;
			     i <
			     (IEEEtypes_MAX_CHANNELS +
			      IEEEtypes_MAX_CHANNELS_A); i++) {
				if (*(mib->mib_regionCode) == DOMAIN_CODE_ALL) {
					if (scanChannel[i] == 181) {
						scanChannel[i] = 0;
					}
				} else {
					if (scanChannel[i] >= 165) {
						scanChannel[i] = 0;
					}
				}
				if (!domainChannelValid(144, FREQ_BAND_5GHZ)) {
					if ((PhyDSSSTable->Chanflag.ChnlWidth ==
					     CH_80_MHz_WIDTH) &&
					    (scanChannel[i] >= 132 &&
					     scanChannel[i] <= 144)) {
						scanChannel[i] = 0;
					} else if ((PhyDSSSTable->Chanflag.
						    ChnlWidth ==
						    CH_40_MHz_WIDTH) &&
						   (scanChannel[i] >= 140 &&
						    scanChannel[i] <= 144)) {
						scanChannel[i] = 0;
					}
				}
			}
		}
#ifdef EXCLUDE_DFS_CHANNEL
		if (*(vmacSta_p->Mib802dot11->mib_autochannel) != 2) {
			UINT8 i, j = 0;
			for (i = 0;
			     i <
			     (IEEEtypes_MAX_CHANNELS +
			      IEEEtypes_MAX_CHANNELS_A); i++) {
				switch (*(mib->mib_regionCode)) {
				case DOMAIN_CODE_ETSI:	// select 36, 40, 44, 48
					if (scanChannel[i] >= 52) {
						scanChannel[i] = 0;
					}
					break;
				default:	// select 36,40,44,48,   149,153,157,161
					if (scanChannel[i] >= 52 &&
					    scanChannel[i] <= 144) {
						scanChannel[i] = 0;
					}
				}
			}
			// Reorganize the channel list
			for (i = 0; (i < IEEEtypes_MAX_CHANNELS_A); i++) {
				if ((j == 0) &&
				    (scanChannel[i + IEEEtypes_MAX_CHANNELS] ==
				     0)) {
					j = i + IEEEtypes_MAX_CHANNELS;
				}
				if ((j != 0) &&
				    (scanChannel[i + IEEEtypes_MAX_CHANNELS] !=
				     0)) {
					// Move the channel id
					scanChannel[j++] =
						scanChannel[i +
							    IEEEtypes_MAX_CHANNELS];
					scanChannel[i +
						    IEEEtypes_MAX_CHANNELS] = 0;
				}
			}
		}
#endif //EXCLUDE_DFS_CHANNEL
		SendScanCmd(vmacSta_p, scanChannel);
		return TRUE;
	}
#ifdef SOC_W8964
	wlSetOpModeMCU(vmacSta_p, MCU_MODE_AP);
#endif
	if (*mib_autochannel_p == 0)
		return FALSE;
	return TRUE;
}

#ifdef SOC_W8964
extern BOOLEAN
wlSetOpModeMCU(vmacApInfo_t * vmacSta_p, UINT32 mode)
{
	switch (mode) {
	case MCU_MODE_AP:
		PciWriteMacReg(vmacSta_p->dev, TX_MODE, WL_AP_MODE);
		break;
	case MCU_MODE_STA_INFRA:
		PciWriteMacReg(vmacSta_p->dev, TX_MODE, WL_STA_MODE);
		break;
	case MCU_MODE_STA_ADHOC:
		PciWriteMacReg(vmacSta_p->dev, TX_MODE,
			       (UINT32) (WL_IBSS_MODE));
		break;
	default:
		return FALSE;
	}
	return TRUE;
}
#endif

static unsigned int
ACS_get_channel_load(vmacApInfo_t * vmacSta_p, UINT32 chan)
{
	int i;
	for (i = 0; i < IEEEtypes_MAX_CHANNELS; i++) {
		if (chan == (UINT32) vmacSta_p->acs_db[i].channel)
			return abs(vmacSta_p->acs_db[i].ch_load);
	}

	/* not found in acs db, just return high channel load */
	return 99;
}

static unsigned int
ACS_get_channel_noise_floor(vmacApInfo_t * vmacSta_p, UINT32 chan)
{
	int i;
	for (i = 0; i < IEEEtypes_MAX_CHANNELS; i++) {
		if (chan == (UINT32) vmacSta_p->acs_db[i].channel)
			return abs(vmacSta_p->acs_db[i].noise_floor);
	}

	/* not found in acs db, just return high noise floor */
	return 1;
}

static inline unsigned int
chld_delta(unsigned int ld0, unsigned int ld1)
{
#define MAX_CHLD_DELTA 0xFFFFFFFF
	if (ld0 == 99 || ld1 == 99) {
		// unexpected channel load, use 20M BW
		printk("unknown chld: %u, %u\n", ld0, ld1);
		return MAX_CHLD_DELTA;
	}
	// channel load too high, use 20M BW
	if (ld0 >= chld_ceil || ld1 >= chld_ceil) {
		printk("exceed chld_ceil: %u, %u, %u\n", chld_ceil, ld0, ld1);
		return MAX_CHLD_DELTA;
	}
	printk("chld abs_delta(%u, %u)=%u\n", ld0, ld1, abs(ld0 - ld1));
	return abs(ld0 - ld1);
}

static inline unsigned int
nf_delta(unsigned int nf0, unsigned int nf1)
{
#define MAX_NF_DELTA 0xFFFFFFFF
	if (nf0 == 1 || nf1 == 1) {
		// unexpected noise floor, use 20M BW
		printk("unknown nf: %u, %u\n", nf0, nf1);
		return MAX_NF_DELTA;
	}
	if (nf0 <= abs_nf_floor || nf1 <= abs_nf_floor) {
		// high noise, use 20M BW
		printk("abs_nf_floor: %u, %u, %u\n", abs_nf_floor, nf0, nf1);
		return MAX_NF_DELTA;
	}
	if (nf0 >= 85 || nf1 >= 85) {
		// low noise, allow 40M BW
		printk("skip low noise: %u, %u\n", nf0, nf1);
		return 0;
	}
	printk("nf abs_delta(%u, %u)=%u\n", nf0, nf1, abs(nf0 - nf1));
	return abs(nf0 - nf1);
}

static int
ACS_whitelist_forBW(vmacApInfo_t * vmacSta_p, UINT32 chan, UINT32 ext)
{
	int BW = -1;
	unsigned int i = 0;

	if (vmacSta_p == NULL || chan == 0)
		goto out;

	if (vmacSta_p->acs_db[0].bss_num && (vmacSta_p->acs_db[10].bss_num ||
					     vmacSta_p->acs_db[11].bss_num ||
					     vmacSta_p->acs_db[12].bss_num)) {
		printk("acs wl0, T:%u, C:(%u, %u, %u, %u, %u, %u, %u, %u)\n",
		       chan, vmacSta_p->acs_db[0].channel,
		       vmacSta_p->acs_db[0].bss_num,
		       vmacSta_p->acs_db[10].channel,
		       vmacSta_p->acs_db[10].bss_num,
		       vmacSta_p->acs_db[11].channel,
		       vmacSta_p->acs_db[11].bss_num,
		       vmacSta_p->acs_db[12].channel,
		       vmacSta_p->acs_db[12].bss_num);
		BW = NO_EXT_CHANNEL;
		goto out;
	}

	if (chan == 1 || chan == 2 || chan == 3) {
		i = 0;
		while (vmacSta_p->ScanParams.ChanList[i]) {
			if (vmacSta_p->acs_db[i].bss_num &&
			    vmacSta_p->acs_db[i].channel < 10) {
				printk("acs wl1, T:%u, C:(%u, %u)\n", chan,
				       vmacSta_p->acs_db[i].channel,
				       vmacSta_p->acs_db[i].bss_num);
				BW = NO_EXT_CHANNEL;
				goto out;
			}
			i++;
		}
		if (vmacSta_p->acs_db[9].bss_num && chan == 1) {
			printk("acs wl2, T:%u, C:(%u, %u)\n",
			       chan, vmacSta_p->acs_db[9].channel,
			       vmacSta_p->acs_db[9].bss_num);
			BW = ext;
		} else if ((vmacSta_p->acs_db[9].bss_num == 0) &&
			   vmacSta_p->acs_db[10].bss_num &&
			   (chan == 1 || chan == 2)) {
			printk("acs wl3, T:%u, C:(%u, %u)\n",
			       chan, vmacSta_p->acs_db[10].channel,
			       vmacSta_p->acs_db[10].bss_num);
			BW = ext;
		} else if (vmacSta_p->acs_db[9].bss_num == 0 &&
			   vmacSta_p->acs_db[10].bss_num == 0) {
			printk("acs wl4, T:%u, C:(%u, %u)\n",
			       chan, vmacSta_p->acs_db[11].channel,
			       vmacSta_p->acs_db[11].bss_num);
			BW = ext;
		} else {
			printk("acs wl5, T:%u\n", chan);
			BW = NO_EXT_CHANNEL;
		}
		goto out;
	}

	if (chan == 11 || chan == 12 || chan == 13) {
		i = 0;
		while (vmacSta_p->ScanParams.ChanList[i]) {
			if (vmacSta_p->acs_db[i].bss_num &&
			    vmacSta_p->acs_db[i].channel > 4) {
				printk("acs wl6, T:%u, C:(%u, %u)\n", chan,
				       vmacSta_p->acs_db[i].channel,
				       vmacSta_p->acs_db[i].bss_num);
				BW = NO_EXT_CHANNEL;
				goto out;
			}
			i++;
		}
		if (vmacSta_p->acs_db[3].bss_num && chan == 13) {
			printk("acs wl7, T:%u, C:(%u, %u)\n",
			       chan, vmacSta_p->acs_db[3].channel,
			       vmacSta_p->acs_db[3].bss_num);
			BW = ext;
		} else if (vmacSta_p->acs_db[3].bss_num == 0 &&
			   vmacSta_p->acs_db[2].bss_num &&
			   (chan == 12 || chan == 13)) {
			printk("acs wl8, T:%u, C:(%u, %u)\n",
			       chan, vmacSta_p->acs_db[2].channel,
			       vmacSta_p->acs_db[2].bss_num);
			BW = ext;
		} else if (vmacSta_p->acs_db[3].bss_num == 0 &&
			   vmacSta_p->acs_db[2].bss_num == 0) {
			printk("acs wl9, T:%u, C:(%u, %u)\n",
			       chan, vmacSta_p->acs_db[1].channel,
			       vmacSta_p->acs_db[1].bss_num);
			BW = ext;
		} else {
			printk("acs wl10, T:%u\n", chan);
			BW = NO_EXT_CHANNEL;
		}
		goto out;

	}
out:
	if (BW > 0)
		printk("wave 40M for ch: %u, ext: %u", chan, ext);
	else if (BW == 0)
		printk("force 20M for chan: %u", chan);
	else
		printk("bypass acs whitelist\n");
	return BW;
}

static inline int
ACS_wifi_noise(vmacApInfo_t * vmacSta_p)
{
	int i = 0;
	while (vmacSta_p->ScanParams.ChanList[i]) {
		if (vmacSta_p->acs_db[i].bss_num &&
		    vmacSta_p->acs_db[i].raw_max_rssi >= -(rssi_threshold))
			return 1;
		i++;
	}
	return 0;
}

static int
ACS_is_bandwidth_available(vmacApInfo_t * vmacSta_p, UINT32 chan, UINT32 ext)
{
	int wl_bw = -1;
	unsigned int channel_nf0, channel_nf1, channel_nf2;
	unsigned int channel_load0, channel_load1, channel_load2;

	if (ACS_wifi_noise(vmacSta_p)) {
		if ((wl_bw = ACS_whitelist_forBW(vmacSta_p, chan, ext)) >= 0)
			return wl_bw;
	}

	if ((chan < 5) || (chan > 9)) {
		if (ext == EXT_CH_ABOVE_CTRL_CH) {
			/* get channel noise floor */
			channel_nf0 =
				ACS_get_channel_noise_floor(vmacSta_p, chan);
			channel_nf1 =
				ACS_get_channel_noise_floor(vmacSta_p,
							    chan + 2);
			channel_nf2 =
				ACS_get_channel_noise_floor(vmacSta_p,
							    chan + 4);
			/* get channel load */
			channel_load0 = ACS_get_channel_load(vmacSta_p, chan);
			channel_load1 =
				ACS_get_channel_load(vmacSta_p, chan + 2);
			channel_load2 =
				ACS_get_channel_load(vmacSta_p, chan + 4);
		} else {
			/* get channel noise floor */
			channel_nf0 =
				ACS_get_channel_noise_floor(vmacSta_p, chan);
			channel_nf1 =
				ACS_get_channel_noise_floor(vmacSta_p,
							    chan - 2);
			channel_nf2 =
				ACS_get_channel_noise_floor(vmacSta_p,
							    chan - 4);
			/* get channel load */
			channel_load0 = ACS_get_channel_load(vmacSta_p, chan);
			channel_load1 =
				ACS_get_channel_load(vmacSta_p, chan - 2);
			channel_load2 =
				ACS_get_channel_load(vmacSta_p, chan - 4);
		}

		/* if the NF difference between them is larger than 15 or if the LOAD difference between them is larger than 30 */
		if ((nf_delta(channel_nf0, channel_nf1) > chld_nf_delta) ||
		    (nf_delta(channel_nf0, channel_nf2) > chld_nf_delta) ||
		    (chld_delta(channel_load0, channel_load1) > chld_nf_delta)
		    || (chld_delta(channel_load0, channel_load2) >
			chld_nf_delta)) {
			printk("BW 20\n");
			return NO_EXT_CHANNEL;
		} else {
			printk("BW 40: %u\n", ext);
			return ext;
		}
	} else {
		/* check above */
		channel_nf0 = ACS_get_channel_noise_floor(vmacSta_p, chan);
		channel_nf1 = ACS_get_channel_noise_floor(vmacSta_p, chan + 2);
		channel_nf2 = ACS_get_channel_noise_floor(vmacSta_p, chan + 4);

		channel_load0 = ACS_get_channel_load(vmacSta_p, chan);
		channel_load1 = ACS_get_channel_load(vmacSta_p, chan + 2);
		channel_load2 = ACS_get_channel_load(vmacSta_p, chan + 4);

		if ((nf_delta(channel_nf0, channel_nf1) <= chld_nf_delta) &&
		    (nf_delta(channel_nf0, channel_nf2) <= chld_nf_delta) &&
		    (chld_delta(channel_load0, channel_load1) <= chld_nf_delta)
		    && (chld_delta(channel_load0, channel_load2) <=
			chld_nf_delta)) {
			printk("BW 40 above\n");
			return EXT_CH_ABOVE_CTRL_CH;
		}

		/* check below */
		channel_nf0 = ACS_get_channel_noise_floor(vmacSta_p, chan);
		channel_nf1 = ACS_get_channel_noise_floor(vmacSta_p, chan - 2);
		channel_nf2 = ACS_get_channel_noise_floor(vmacSta_p, chan - 4);

		channel_load0 = ACS_get_channel_load(vmacSta_p, chan);
		channel_load1 = ACS_get_channel_load(vmacSta_p, chan - 2);
		channel_load2 = ACS_get_channel_load(vmacSta_p, chan - 4);

		if ((nf_delta(channel_nf0, channel_nf1) <= chld_nf_delta) &&
		    (nf_delta(channel_nf0, channel_nf2) <= chld_nf_delta) &&
		    (chld_delta(channel_load0, channel_load1) <= chld_nf_delta)
		    && (chld_delta(channel_load0, channel_load2) <=
			chld_nf_delta)) {
			printk("BW 40 below\n");
			return EXT_CH_BELOW_CTRL_CH;
		}
	}

	printk("BW 20\n");
	return NO_EXT_CHANNEL;
}

extern BOOLEAN
wlUpdateAutoChan(vmacApInfo_t * vmacSta_p, UINT32 chan, UINT8 shadowMIB)
{
	MIB_802DOT11 *mib =
		shadowMIB ? vmacSta_p->ShadowMib802dot11 : vmacSta_p->
		Mib802dot11;

	MIB_PHY_DSSS_TABLE *PhyDSSSTable = mib->PhyDSSSTable;
	UINT8 *mib_extSubCh_p = mib->mib_extSubCh;
#ifdef CFG80211
	int i = 0;
	struct net_device *netdev = vmacSta_p->dev;
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
#endif
	extern int wlFwSet11N_20_40_Switch(struct net_device *netdev,
					   UINT8 mode);
#ifdef IEEE80211K
	MSAN_get_ACS_db(vmacSta_p, vmacSta_p->NumScanChannels, 0);
#endif /* IEEE80211K */

	PhyDSSSTable->CurrChan = chan;

	PhyDSSSTable->Chanflag.ExtChnlOffset = EXT_CH_ABOVE_CTRL_CH;

	if ((PhyDSSSTable->Chanflag.ChnlWidth == CH_40_MHz_WIDTH) ||
	    (PhyDSSSTable->Chanflag.ChnlWidth == CH_AUTO_WIDTH) ||
	    (PhyDSSSTable->Chanflag.ChnlWidth == CH_80_MHz_WIDTH) ||
	    (PhyDSSSTable->Chanflag.ChnlWidth == CH_160_MHz_WIDTH)) {
		switch (PhyDSSSTable->CurrChan) {
		case 1:
		case 2:
		case 3:
		case 4:
			/* if the bandwidth is auto, check available bandwidth */
			if ((PhyDSSSTable->Chanflag.ChnlWidth == CH_AUTO_WIDTH)
			    && !ACS_is_bandwidth_available(vmacSta_p, chan,
							   EXT_CH_ABOVE_CTRL_CH))
				PhyDSSSTable->Chanflag.ChnlWidth =
					CH_20_MHz_WIDTH;
			else
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
			wlFwSet11N_20_40_Switch(vmacSta_p->dev,
						(PhyDSSSTable->Chanflag.
						 ChnlWidth ==
						 CH_20_MHz_WIDTH) ? 0 : 1);
			break;
		case 5:
			/* Now AutoBW use 5-1 instead of 5-9 for wifi cert convenience */
			/*if(*mib_extSubCh_p==0)
			   {
			   if(domainChannelValid(chan+4, FREQ_BAND_2DOT4GHZ))
			   PhyDSSSTable->Chanflag.ExtChnlOffset=EXT_CH_ABOVE_CTRL_CH;
			   else if(domainChannelValid(chan-4, FREQ_BAND_2DOT4GHZ))
			   PhyDSSSTable->Chanflag.ExtChnlOffset=EXT_CH_BELOW_CTRL_CH;
			   }
			   else if(*mib_extSubCh_p==1)
			   {
			   if(domainChannelValid(chan-4, FREQ_BAND_2DOT4GHZ))
			   PhyDSSSTable->Chanflag.ExtChnlOffset=EXT_CH_BELOW_CTRL_CH;
			   else
			   PhyDSSSTable->Chanflag.ExtChnlOffset=EXT_CH_ABOVE_CTRL_CH;
			   }
			   else if(*mib_extSubCh_p==2)
			   {
			   if(domainChannelValid(chan+4, FREQ_BAND_2DOT4GHZ))
			   PhyDSSSTable->Chanflag.ExtChnlOffset=EXT_CH_ABOVE_CTRL_CH;
			   else
			   PhyDSSSTable->Chanflag.ExtChnlOffset=EXT_CH_BELOW_CTRL_CH;
			   }
			   break; */
		case 6:
		case 7:
		case 8:
		case 9:
			if (PhyDSSSTable->Chanflag.ChnlWidth == CH_AUTO_WIDTH) {
				unsigned int ret =
					ACS_is_bandwidth_available(vmacSta_p,
								   chan,
								   PhyDSSSTable->
								   Chanflag.
								   ExtChnlOffset);
				if (!ret)
					PhyDSSSTable->Chanflag.ChnlWidth =
						CH_20_MHz_WIDTH;
				else
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						ret;
			} else {
				if ((*mib_extSubCh_p == 0) ||
				    (*mib_extSubCh_p == 1)) {
					if (domainChannelValid
					    (chan - 4, FREQ_BAND_2DOT4GHZ))
						PhyDSSSTable->Chanflag.
							ExtChnlOffset =
							EXT_CH_BELOW_CTRL_CH;
					else
						PhyDSSSTable->Chanflag.
							ExtChnlOffset =
							EXT_CH_ABOVE_CTRL_CH;
				} else if (*mib_extSubCh_p == 2) {
					if (domainChannelValid
					    (chan + 4, FREQ_BAND_2DOT4GHZ))
						PhyDSSSTable->Chanflag.
							ExtChnlOffset =
							EXT_CH_ABOVE_CTRL_CH;
					else
						PhyDSSSTable->Chanflag.
							ExtChnlOffset =
							EXT_CH_BELOW_CTRL_CH;
				}
			}
			wlFwSet11N_20_40_Switch(vmacSta_p->dev,
						(PhyDSSSTable->Chanflag.
						 ChnlWidth ==
						 CH_20_MHz_WIDTH) ? 0 : 1);
			break;
		case 10:
		case 11:
		case 12:
		case 13:
		case 14:
			if ((PhyDSSSTable->Chanflag.ChnlWidth == CH_AUTO_WIDTH)
			    && !ACS_is_bandwidth_available(vmacSta_p, chan,
							   EXT_CH_BELOW_CTRL_CH))
				PhyDSSSTable->Chanflag.ChnlWidth =
					CH_20_MHz_WIDTH;
			else
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
			wlFwSet11N_20_40_Switch(vmacSta_p->dev,
						(PhyDSSSTable->Chanflag.
						 ChnlWidth ==
						 CH_20_MHz_WIDTH) ? 0 : 1);
			break;
			/* for 5G */
		case 36:
			PhyDSSSTable->Chanflag.ExtChnlOffset =
				EXT_CH_ABOVE_CTRL_CH;
			break;
		case 40:
			PhyDSSSTable->Chanflag.ExtChnlOffset =
				EXT_CH_BELOW_CTRL_CH;
			break;
		case 44:
			PhyDSSSTable->Chanflag.ExtChnlOffset =
				EXT_CH_ABOVE_CTRL_CH;
			break;
		case 48:
			PhyDSSSTable->Chanflag.ExtChnlOffset =
				EXT_CH_BELOW_CTRL_CH;
			break;
		case 52:
			PhyDSSSTable->Chanflag.ExtChnlOffset =
				EXT_CH_ABOVE_CTRL_CH;
			break;
		case 56:
			PhyDSSSTable->Chanflag.ExtChnlOffset =
				EXT_CH_BELOW_CTRL_CH;
			break;
		case 60:
			PhyDSSSTable->Chanflag.ExtChnlOffset =
				EXT_CH_ABOVE_CTRL_CH;
			break;
		case 64:
			PhyDSSSTable->Chanflag.ExtChnlOffset =
				EXT_CH_BELOW_CTRL_CH;
			break;

		case 100:
			PhyDSSSTable->Chanflag.ExtChnlOffset =
				EXT_CH_ABOVE_CTRL_CH;
			break;
		case 104:
			PhyDSSSTable->Chanflag.ExtChnlOffset =
				EXT_CH_BELOW_CTRL_CH;
			break;
		case 108:
			PhyDSSSTable->Chanflag.ExtChnlOffset =
				EXT_CH_ABOVE_CTRL_CH;
			break;
		case 112:
			PhyDSSSTable->Chanflag.ExtChnlOffset =
				EXT_CH_BELOW_CTRL_CH;
			break;
		case 116:
			PhyDSSSTable->Chanflag.ExtChnlOffset =
				EXT_CH_ABOVE_CTRL_CH;
			break;
		case 120:
			PhyDSSSTable->Chanflag.ExtChnlOffset =
				EXT_CH_BELOW_CTRL_CH;
			break;
		case 124:
			PhyDSSSTable->Chanflag.ExtChnlOffset =
				EXT_CH_ABOVE_CTRL_CH;
			break;
		case 128:
			PhyDSSSTable->Chanflag.ExtChnlOffset =
				EXT_CH_BELOW_CTRL_CH;
			break;
		case 132:
			PhyDSSSTable->Chanflag.ExtChnlOffset =
				EXT_CH_ABOVE_CTRL_CH;
			break;
		case 136:
			PhyDSSSTable->Chanflag.ExtChnlOffset =
				EXT_CH_BELOW_CTRL_CH;
			break;
		case 140:
			PhyDSSSTable->Chanflag.ExtChnlOffset =
				EXT_CH_ABOVE_CTRL_CH;
			break;
		case 144:
			PhyDSSSTable->Chanflag.ExtChnlOffset =
				EXT_CH_BELOW_CTRL_CH;
			break;
		case 149:
			PhyDSSSTable->Chanflag.ExtChnlOffset =
				EXT_CH_ABOVE_CTRL_CH;
			break;
		case 153:
			PhyDSSSTable->Chanflag.ExtChnlOffset =
				EXT_CH_BELOW_CTRL_CH;
			break;
		case 157:
			PhyDSSSTable->Chanflag.ExtChnlOffset =
				EXT_CH_ABOVE_CTRL_CH;
			break;
		case 161:
			PhyDSSSTable->Chanflag.ExtChnlOffset =
				EXT_CH_BELOW_CTRL_CH;
			break;
		case 165:
			if (*(mib->mib_regionCode) == DOMAIN_CODE_ALL) {
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
			}
			/* Channel 165 currently only supports 20 MHz BW. */
			/* Commented out for now.  Causes channel width to be set
			   to 20 MHz if current channel is 165 and then switched
			   to another channel. */
			/* PhyDSSSTable->Chanflag.ChnlWidth        = CH_20_MHz_WIDTH; */
			/* PhyDSSSTable->Chanflag.ExtChnlOffset = NO_EXT_CHANNEL; */
			break;
			if (*(mib->mib_regionCode) == DOMAIN_CODE_ALL) {
		case 68:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
		case 72:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
		case 76:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
		case 80:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
		case 84:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
		case 88:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
		case 92:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
		case 96:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;

		case 169:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
		case 173:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
		case 177:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
		case 181:
				PhyDSSSTable->Chanflag.ChnlWidth =
					CH_20_MHz_WIDTH;
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					NO_EXT_CHANNEL;
				break;
		case 184:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
		case 188:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
		case 192:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
		case 196:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
			}

		default:
			break;
		}
	}
	if (PhyDSSSTable->CurrChan <= 14)
		PhyDSSSTable->Chanflag.FreqBand = FREQ_BAND_2DOT4GHZ;
	else
		PhyDSSSTable->Chanflag.FreqBand = FREQ_BAND_5GHZ;

	vmacSta_p->preautochannelfinished = 1;
	ACS_start_timer(vmacSta_p);

#ifdef CFG80211
	if (PhyDSSSTable->CurrChan) {
		for (i = 0; i < bss_num; i++)
			mwl_send_vendor_acs_completed(priv->vdev[i],
						      PhyDSSSTable->CurrChan);
	}
#endif

	return TRUE;
}

extern BOOLEAN
wlSetRFChan(vmacApInfo_t * vmacSta_p, UINT32 channel)
{
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	MIB_PHY_DSSS_TABLE *PhyDSSSTable = mib->PhyDSSSTable;
	CHNL_FLAGS Chanflag;
	UINT8 retval;

	if (ACS_OpChanCheck(vmacSta_p, channel) == FAIL) {
		printk("autochannel is enabled and channel : %d is not in opreation channel list.\n", channel);
		return FALSE;
	}

	Chanflag = PhyDSSSTable->Chanflag;
	Chanflag.ChnlWidth = CH_20_MHz_WIDTH;
	Chanflag.ExtChnlOffset = EXT_CH_ABOVE_CTRL_CH;
	if (domainChannelValid
	    (channel, channel <= 14 ? FREQ_BAND_2DOT4GHZ : FREQ_BAND_5GHZ)) {
		if (channel <= 14)
			Chanflag.FreqBand = FREQ_BAND_2DOT4GHZ;
		else
			Chanflag.FreqBand = FREQ_BAND_5GHZ;
#ifdef SOC_W906X
		// TODO: check how to set the second channel for autochannel
		if (PhyDSSSTable->SecChan != 0 &&
		    PhyDSSSTable->Chanflag.radiomode == RADIO_MODE_7x7p1x1) {
			/* swap primary and 2nd channel according to fw design */
			retval = wlchannelSet(vmacSta_p->dev,
					      PhyDSSSTable->SecChan, channel,
					      Chanflag, 1);
		} else {
			retval = wlchannelSet(vmacSta_p->dev, channel,
					      PhyDSSSTable->SecChan, Chanflag,
					      1);
		}
		if (retval != SUCCESS) {
#else
		if (wlchannelSet(vmacSta_p->dev, channel, Chanflag, 1)) {
#endif
			WLDBG_EXIT_INFO(DBG_LEVEL_15, "setting channel failed");
			return FALSE;
		}
	} else {
		printk("WARNNING: invalid channel %d for current domain\n",
		       (int)channel);
	}
	return TRUE;
}

void
scanControl(vmacApInfo_t * vmacSta_p)
{
#ifdef MRVL_DFS
	if ((!channelSelected
	     (vmacSta_p,
	      ((*(vmacSta_p->Mib802dot11->mib_ApMode)) & AP_MODE_BAND_MASK) >=
	      AP_MODE_A_ONLY))
	    && !vmacSta_p->dfsCacExp)
#else
	if (!channelSelected
	    (vmacSta_p,
	     ((*(vmacSta_p->Mib802dot11->mib_ApMode)) & AP_MODE_BAND_MASK) >=
	     AP_MODE_A_ONLY))
#endif
	{
		if (SetupScan(vmacSta_p))
			return;
	} else {
		PrepareNextScan(vmacSta_p);
	}
#ifdef MRVL_DFS
	vmacSta_p->dfsCacExp = 0;
#endif
	extStaDb_ProcessKeepAliveTimerInit(vmacSta_p);
	MonitorTimerInit(vmacSta_p);
}

#ifndef IEEE80211_DH
BOOLEAN
UpdateCurrentChannelInMIB(vmacApInfo_t * vmacSta_p, UINT32 channel)
{
	extern BOOLEAN force_5G_channel;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	MIB_PHY_DSSS_TABLE *PhyDSSSTable = mib->PhyDSSSTable;
	UINT8 *mib_extSubCh_p = mib->mib_extSubCh;

	if (domainChannelValid
	    (channel,
	     force_5G_channel ? FREQ_BAND_5GHZ : (channel <=
						  14 ? FREQ_BAND_2DOT4GHZ :
						  FREQ_BAND_5GHZ))) {
		PhyDSSSTable->CurrChan = channel;

		/* Currentlly, 40M is not supported for channel 14 */
		if (PhyDSSSTable->CurrChan == 14) {
			if ((PhyDSSSTable->Chanflag.ChnlWidth == CH_AUTO_WIDTH)
			    || (PhyDSSSTable->Chanflag.ChnlWidth ==
				CH_40_MHz_WIDTH) ||
			    (PhyDSSSTable->Chanflag.ChnlWidth ==
			     CH_80_MHz_WIDTH) ||
			    (PhyDSSSTable->Chanflag.ChnlWidth ==
			     CH_160_MHz_WIDTH))
				PhyDSSSTable->Chanflag.ChnlWidth =
					CH_20_MHz_WIDTH;
		}
		//PhyDSSSTable->Chanflag.ChnlWidth=CH_40_MHz_WIDTH;
		PhyDSSSTable->Chanflag.ExtChnlOffset = EXT_CH_ABOVE_CTRL_CH;
		if (((PhyDSSSTable->Chanflag.ChnlWidth == CH_40_MHz_WIDTH) ||
		     (PhyDSSSTable->Chanflag.ChnlWidth == CH_80_MHz_WIDTH) ||
		     (PhyDSSSTable->Chanflag.ChnlWidth == CH_160_MHz_WIDTH) ||
		     (PhyDSSSTable->Chanflag.ChnlWidth == CH_AUTO_WIDTH))) {
			switch (PhyDSSSTable->CurrChan) {
			case 1:
			case 2:
			case 3:
			case 4:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 5:
				if (*mib_extSubCh_p == 0)
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_ABOVE_CTRL_CH;
				else if (*mib_extSubCh_p == 1)
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_BELOW_CTRL_CH;
				else if (*mib_extSubCh_p == 2)
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_ABOVE_CTRL_CH;
				break;
			case 6:
			case 7:
			case 8:
			case 9:
			case 10:
				if (*mib_extSubCh_p == 0)
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_BELOW_CTRL_CH;
				else if (*mib_extSubCh_p == 1)
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_BELOW_CTRL_CH;
				else if (*mib_extSubCh_p == 2)
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_ABOVE_CTRL_CH;
				break;
			case 11:
			case 12:
			case 13:
			case 14:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
				/* for 5G */
			case 36:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 40:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
			case 44:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 48:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
			case 52:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 56:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
			case 60:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 64:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;

			case 68:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 72:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
			case 76:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 80:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
			case 84:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 88:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
			case 92:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 96:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;

			case 100:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 104:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
			case 108:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 112:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
			case 116:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 120:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
			case 124:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 128:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
			case 132:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 136:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
			case 140:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 144:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
			case 149:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 153:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
			case 157:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 161:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
			case 165:
				if (*(mib->mib_regionCode) == DOMAIN_CODE_ALL) {
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_ABOVE_CTRL_CH;
				} else {
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_BELOW_CTRL_CH;
				}
				break;
			case 169:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
			case 173:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 177:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
			case 181:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					NO_EXT_CHANNEL;
				break;

			case 184:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 188:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
			case 192:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_ABOVE_CTRL_CH;
				break;
			case 196:
				PhyDSSSTable->Chanflag.ExtChnlOffset =
					EXT_CH_BELOW_CTRL_CH;
				break;
			default:
				break;
			}
		}
		if (force_5G_channel) {
			PhyDSSSTable->Chanflag.FreqBand = FREQ_BAND_5GHZ;
		} else {
			if (PhyDSSSTable->CurrChan <= 14)
				PhyDSSSTable->Chanflag.FreqBand =
					FREQ_BAND_2DOT4GHZ;
			else
				PhyDSSSTable->Chanflag.FreqBand =
					FREQ_BAND_5GHZ;
		}
	} else {
		WLDBG_INFO(DBG_LEVEL_15, "invalid channel %d\n", channel);
		return FALSE;
	}
	wlFwApplyChannelSettings(vmacSta_p->dev);
	return TRUE;
}
#endif //IEEE80211_DH

void
EnableBlockTrafficMode(vmacApInfo_t * vmacSta_p)
{
	vmacSta_p->StopTraffic = TRUE;
}

void
DisableBlockTrafficMode(vmacApInfo_t * vmacSta_p)
{
	vmacSta_p->StopTraffic = FALSE;
}

void
StopAutoChannel(vmacApInfo_t * vmacSta_p)
{
	void syncSrv_RestorePreScanSettings(vmacApInfo_t * vmacSta_p);
	UINT8 cur_channel;
	UINT8 *mib_autochannel_p =
		vmacSta_p->ShadowMib802dot11->mib_autochannel;

	if (vmacSta_p->busyScanning)
		syncSrv_RestorePreScanSettings(vmacSta_p);
	vmacSta_p->busyScanning = 0;
	if (*mib_autochannel_p) {
		/*Dont know why change vmacSta_p->autochannelstarted to be 1 here, but this prevent wdev0 doing autoscanning
		 * when stamode=6/7/8, and wdev0sta0 is down at the first commit. comment it out looks OK.
		 */
		//vmacSta_p->autochannelstarted = 1;

		/* Select channel and update when on parent interface only. Parent interface has master pointer as NULL
		 * In situation where wdev0 and wdev0ap0 are up; and then we use wdev0sta0 to do stascan, cur_channel could be assigned
		 * with 0 (5G) or 1 (2G). This is because ChanList[i] in virtual interface is 0. After that, any previously associated client
		 * to wdev0ap0 will fail to ping even if chan is set to 1 in 2G. 5G will fail because chan is set to 0, which is invalid.
		 */
		if (!vmacSta_p->master) {
			cur_channel =
				channelSelected(vmacSta_p,
						((*
						  (vmacSta_p->Mib802dot11->
						   mib_ApMode)) &
						 AP_MODE_BAND_MASK) >=
						AP_MODE_A_ONLY);

			if (cur_channel != 0)
				wlUpdateAutoChan(vmacSta_p, cur_channel, 0);
		}
		DisableBlockTrafficMode(vmacSta_p);
	}

	Disable_ScanTimerProcess(vmacSta_p);
	ACS_stop_timer(vmacSta_p);

	return;
}

UINT8
ACS_OpChanCheck(vmacApInfo_t * vmacSta_p, UINT8 channel)
{
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	UINT8 i;

	if (*(mib->mib_autochannel) == 2) {

		for (i = 0; i < IEEE_80211_MAX_NUMBER_OF_CHANNELS; i++) {
			if (channel == vmacSta_p->OpChanList[i]) {
				break;
			}
		}
		if (i == IEEE_80211_MAX_NUMBER_OF_CHANNELS) {
			return FAIL;
		}
	}
	return SUCCESS;
}

#define LOAD_DESENSE_SLOPE  10
#define LOAD_DESENSE_START_DBM  (0)
#define NF_WEIGHT 205
#define NF_MAP_SIZE	18
#define CH_AXIS_NUM	11

unsigned int
ACS_channel_score_from_nf_reading(unsigned int *NF_map)
{
	int kk;
	int i;
	int score_out = 0;
	int NF_weight = NF_WEIGHT;
	int Load_desense_slope = LOAD_DESENSE_SLOPE;
	static int NF_axis[NF_MAP_SIZE] =
		{ -10, -15, -20, -25, -30, -35, -40, -45, -50, -55, -60, -65,
	-70, -75, -80, -85, -90, -95 };
	char NF_idx_range[NF_MAP_SIZE] = { 0 };
	char Load_idx_range[NF_MAP_SIZE] = { 0 };
	int NF_level_TH = -80;
	unsigned int Load_desense_factor[NF_MAP_SIZE] = { 0 };	/* Load_desense_factor = ones(size(NF_axis)); */
	unsigned int Ch_load = 0;	/* Ch_load = zeros(1,length(channel_axis)); */
	int NF = 0;		/* NF = zeros(1,length(channel_axis)); */

	/*
	 *      for kk = 1:length(Load_desense_factor)
	 *          if NF_axis(kk) > -30
	 *              Load_desense_factor(kk) = 1;
	 *          else
	 *          Load_desense_factor(kk) = 1 + (NF_axis(kk) + 30)*Load_desense_slope;
	 *      end
	 *  end
	 */
	for (kk = 0; kk < NF_MAP_SIZE; kk++) {
		if (NF_axis[kk] > LOAD_DESENSE_START_DBM) {
			Load_desense_factor[kk] = 1024;
		} else {
			Load_desense_factor[kk] =
				1024 + (NF_axis[kk] -
					LOAD_DESENSE_START_DBM) *
				Load_desense_slope;
			if (Load_desense_factor[kk] < 100) {
				Load_desense_factor[kk] = 100;
			}
		}
	}

	/* NF_idx_range = find(NF_axis<NF_level_TH);
	 * Load_idx_range = find(NF_axis>=NF_level_TH);
	 */
	for (kk = 0; kk < NF_MAP_SIZE; kk++) {
		if (NF_axis[kk] < NF_level_TH) {
			NF_idx_range[kk] = 1;
		}
		if (NF_axis[kk] >= NF_level_TH) {
			Load_idx_range[kk] = 1;
		}
	}

	/* debug print */
	/*
	   printk("\n\n");
	   for(kk=0;kk< NF_MAP_SIZE; kk++)
	   {
	   printk("%d %d %d %d\n",NF_axis[kk], Load_desense_factor[kk],NF_idx_range[kk],Load_idx_range[kk]);
	   }
	   printk("\n\n");
	 */

	/*
	 * for kk = 1:length(channel_axis)
	 *   Ch_load(kk) = sum(Load_desense_factor(Load_idx_range)*NF_map(Load_idx_range,kk))/sum(NF_map(:,kk));
	 *   T1 = NF_axis(NF_idx_range)*NF_map(NF_idx_range,kk);
	 *   T2 = sum(NF_map(NF_idx_range,kk));
	 *   NF(kk) = T1/T2;
	 * end
	 */
	{
		unsigned int sum_NF_map = 0;
		unsigned int sum_NF_map_Load_idx_range = 0;
		int T1 = 0;
		int T2 = 0;

		for (i = 0; i < NF_MAP_SIZE; i++) {
			sum_NF_map += NF_map[i];
			if (Load_idx_range[i] == 1) {
				sum_NF_map_Load_idx_range +=
					(Load_desense_factor[i] * NF_map[i]);
			}
		}

		if (sum_NF_map > 0) {
			Ch_load = (sum_NF_map_Load_idx_range * 100 / sum_NF_map);	/* Ch_load is an integer, 1 unit is (1/1024) of 1% */
		} else {
			Ch_load = 0;
		}
		printk("Ch_load:%d\n", Ch_load);

		for (i = 0; i < NF_MAP_SIZE; i++) {
			if (NF_idx_range[i] == 1) {
				T1 += NF_axis[i] * NF_map[i];
				T2 += NF_map[i];
			}
		}

		if (T2 > 0) {
			NF = (T1 << 10) / T2;
		} else {
			NF = NF_level_TH << 10;
		}
		printk("NF:%d T1:%d T2:%d\n", NF, T1, T2);
	}

	score_out =
		((1024 - NF_weight) * Ch_load + NF_weight * (102400 + NF) +
		 (1 << 18)) >> 19;
	printk("Channel score: %d\n", score_out);
	return score_out;
}

void
ACS_start_timer(vmacApInfo_t * vmacSta_p)
{
	ch_load_info_t *ch_load_p = &vmacSta_p->acs_cload;

	if (vmacSta_p->master != NULL) {
		return;
	}

	if (ch_load_p->started == 0) {
		TimerDisarm(&ch_load_p->timer);
		memset(ch_load_p, 0, sizeof(ch_load_info_t));
		ch_load_p->tag = CH_LOAD_ACS;
		ch_load_p->master = (UINT8 *) vmacSta_p;
		ch_load_p->dur = 500;
		ch_load_p->interval = 10000;
		ch_load_p->ignore_time = ((ch_load_p->interval + ch_load_p->dur) / 1000) + 1;	//ceil(ignore_time)
		ch_load_p->loop_count = 0;
		ch_load_p->callback = &wl_acs_ch_load_cb;
		ch_load_p->started = 1;
	}
	wl_get_ch_load_by_timer(ch_load_p);
}

void
ACS_stop_timer(vmacApInfo_t * vmacSta_p)
{
	ch_load_info_t *ch_load_p = &vmacSta_p->acs_cload;

	if (vmacSta_p->master != NULL) {
		return;
	}
	TimerDisarm(&ch_load_p->timer);
}
#endif
