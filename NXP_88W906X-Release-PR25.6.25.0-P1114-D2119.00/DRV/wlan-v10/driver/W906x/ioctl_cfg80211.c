/** @file ioctl_cfg80211.c
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
#include <linux/kernel.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/wireless.h>

#include "ioctl_cfg80211.h"
#include "ap8xLnxIntf.h"
#include "wl_hal.h"
#include "domain.h"
#include "ap8xLnxWlLog.h"
#include "macMgmtMlme.h"
#include "ap8xLnxFwcmd.h"
#include "keyMgmtSta.h"
#include "mlmeApi.h"
#include "bcngen.h"
#include "wl.h"
#include "wlFun.h"
#include "cfg80211.h"


int mwl_config_commit(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;

#ifdef WFA_TKIP_NEGATIVE
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	extern int allow_ht_tkip;
#endif
	MIB_PHY_DSSS_TABLE *PhyDSSSTable = mib->PhyDSSSTable;
	MIB_802DOT11 *mibOperation = vmacSta_p->Mib802dot11;
	MIB_PHY_DSSS_TABLE *PhyDSSSTableOperation = mibOperation->PhyDSSSTable;
	DfsAp *me;
	DfsApDesc *dfsDesc_p = NULL;

#ifdef WFA_TKIP_NEGATIVE
	/* Perform checks on the validity of configuration combinations */
	/* Check the validity of the opmode and security mode combination */
	if (!allow_ht_tkip && ((*(mib->mib_wpaWpa2Mode) & 0x0F) == 1 && (*(mib->mib_ApMode) == AP_MODE_N_ONLY || *(mib->mib_ApMode) == AP_MODE_BandN || *(mib->mib_ApMode) == AP_MODE_GandN || *(mib->mib_ApMode) == AP_MODE_BandGandN || *(mib->mib_ApMode) == AP_MODE_2_4GHZ_11AC_MIXED || *(mib->mib_ApMode) == AP_MODE_5GHZ_Nand11AC || *(mib->mib_ApMode) == AP_MODE_AandN))) {	/*WPA-TKIP or WPA-AES mode */
		printk("HT mode not supported when WPA is enabled\n");
		WLSYSLOG(netdev, WLSYSLOG_CLASS_ALL, "HT mode not supported when WPA is enabled\n");
		WLSNDEVT(netdev, IWEVCUSTOM, (IEEEtypes_MacAddr_t *) & wlpptr->hwData.macAddr[0], "HT mode not supported when WPA is enabled\n");
		return -EINVAL;
	}

	if ((mib->Privacy->PrivInvoked == 1) &&
	    (*(mib->mib_ApMode) == AP_MODE_N_ONLY
	     || *(mib->mib_ApMode) == AP_MODE_BandN
	     || *(mib->mib_ApMode) == AP_MODE_GandN
	     || *(mib->mib_ApMode) == AP_MODE_BandGandN
	     || *(mib->mib_ApMode) == AP_MODE_2_4GHZ_11AC_MIXED
	     || *(mib->mib_ApMode) == AP_MODE_5GHZ_Nand11AC || *(mib->mib_ApMode) == AP_MODE_AandN)) {
		printk("HT mode not supported when WEP is enabled\n");
		WLSYSLOG(netdev, WLSYSLOG_CLASS_ALL, "HT mode not supported when WEP is enabled\n");
		WLSNDEVT(netdev, IWEVCUSTOM, (IEEEtypes_MacAddr_t *) & wlpptr->hwData.macAddr[0], "HT mode not supported when WEP is enabled\n");
		return -EINVAL;
	}
#endif
	ACS_stop_timer(vmacSta_p);
	if (macMgmtMlme_DfsEnabled(vmacSta_p->dev)) {
		if (DfsPresentInNOL(netdev, PhyDSSSTable->CurrChan)) {
			printk("error: BW and channel combination not allowed Per NOL.\n");
			PhyDSSSTable->Chanflag.ChnlWidth = PhyDSSSTableOperation->Chanflag.ChnlWidth;
			return -EPERM;
		}
	}
	if (netdev->flags & IFF_RUNNING)
		return (wlpptr->wlreset(netdev));
	else {
		me = wlpd_p->pdfsApMain;

		if ((me != NULL) && (wlpptr->master == NULL)) {
			dfsDesc_p = (DfsApDesc *) & me->dfsApDesc;
			if ((DfsGetCurrentState(me)) == DFS_STATE_SCAN) {
				/* Stops CAC timer */
				return (wlpptr->wlreset(netdev));
			} else {
				printk("*Failed wlconfig_commit netdev = %s \n", netdev->name);
				return -EPERM;
			}
		} else {
			/* If not master device (if master device private wlpptr->master is always NULL). */
			if (wlpptr->master) {
				mib_Update();
				return 0;
			} else {
				printk("failed wlconfig_commit netdev = %s \n", netdev->name);
				return -EPERM;
			}
		}
	}

	return 0;
}

int mwl_config_set_channel(struct net_device *netdev, uint8_t channel)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	MIB_PHY_DSSS_TABLE *PhyDSSSTable = mib->PhyDSSSTable;
	UINT8 *mib_extSubCh_p = mib->mib_extSubCh;
	int rc = 0;

	if (priv->master) {
		printk("This parameter cannot be set to virtual interface %s," " please use %s instead!\n", netdev->name, priv->master->name);
		rc = -EOPNOTSUPP;
		return rc;
	}

	if (ACS_OpChanCheck(vmacSta_p, channel) == FAIL) {
		rc = -EPERM;
		printk("autochannel is enabled and channel : %d is not in opreation channel list.\n", channel);
		return rc;
	}

	if (channel) {
#ifdef MRVL_DFS
		/*Check if the target channel is a DFS channel and in NOL.
		 * If so, do not let the channel to change.
		 */
		if (DfsPresentInNOL(netdev, channel)) {
			printk("Target channel :%d is already in NOL\n", channel);
			rc = -EOPNOTSUPP;
			return rc;
		}
#endif
		if (domainChannelValid(channel, channel <= 14 ? FREQ_BAND_2DOT4GHZ : FREQ_BAND_5GHZ)) {
			PhyDSSSTable->CurrChan = channel;
			PhyDSSSTable->powinited = 0;
			/* Set 20MHz BW for channel 14,For ch165 and ch140 so as to avoid overlapping channel pairs */
			if (PhyDSSSTable->CurrChan == 14)
				PhyDSSSTable->Chanflag.ChnlWidth = CH_20_MHz_WIDTH;
			else if (PhyDSSSTable->CurrChan >= 36) {	//only apply for 5G
				UINT8 domainCode, domainInd_IEEERegion;

				if ((priv->auto_bw == 1) || (PhyDSSSTable->Chanflag.ChnlWidth == CH_AUTO_WIDTH)) {
					priv->auto_bw = 1;
					switch (priv->devid) {
					case SC4:
					case SC4P:	/*check the optimal auto BW setting for SC4P. */
						PhyDSSSTable->Chanflag.ChnlWidth = CH_160_MHz_WIDTH;
						break;
					case SC5:
					case SCBT:
						PhyDSSSTable->Chanflag.ChnlWidth = CH_80_MHz_WIDTH;
						break;
					default:
						WLDBG_ERROR(DBG_LEVEL_1,
							    "Not support chip. Consider what's optimal auto BW settting for this chip.\n");
						break;
					}
				}

				domainCode = domainGetDomain();	// get current domain
				domainInd_IEEERegion = GetDomainIndxIEEERegion(domainCode);
				switch (PhyDSSSTable->Chanflag.ChnlWidth) {
				case CH_40_MHz_WIDTH:
					if (IsTestchannel40MzChannel(channel, domainInd_IEEERegion) == FALSE) {
						PhyDSSSTable->Chanflag.ChnlWidth = CH_20_MHz_WIDTH;
					}
					break;
				case CH_80_MHz_WIDTH:
					if (IsTestchannel80MzChannel(channel, domainInd_IEEERegion) == FALSE) {
						if (IsTestchannel40MzChannel(channel, domainInd_IEEERegion) == FALSE) {
							PhyDSSSTable->Chanflag.ChnlWidth = CH_20_MHz_WIDTH;
						} else {
							PhyDSSSTable->Chanflag.ChnlWidth = CH_40_MHz_WIDTH;
						}
					}

					break;
				case CH_160_MHz_WIDTH:
				case CH_AUTO_WIDTH:
					if (Is160MzChannel(channel, domainInd_IEEERegion) == FALSE) {
						if (IsTestchannel80MzChannel(channel, domainInd_IEEERegion) == FALSE) {
							if (IsTestchannel40MzChannel(channel, domainInd_IEEERegion) == FALSE) {
								PhyDSSSTable->Chanflag.ChnlWidth = CH_20_MHz_WIDTH;
							} else {
								PhyDSSSTable->Chanflag.ChnlWidth = CH_40_MHz_WIDTH;
							}
						} else {
							PhyDSSSTable->Chanflag.ChnlWidth = CH_80_MHz_WIDTH;
						}
					}
					break;
				}
			} else {
				if ((priv->auto_bw == 1) || (PhyDSSSTable->Chanflag.ChnlWidth == CH_AUTO_WIDTH)) {
					switch (priv->devid) {
					case SC4:
					case SC4P:	/*check the optimal auto BW setting for SC4P. */
					case SC5:
					case SCBT:
						priv->auto_bw = 1;
						PhyDSSSTable->Chanflag.ChnlWidth = CH_40_MHz_WIDTH;
						break;
					default:
						WLDBG_ERROR(DBG_LEVEL_1,
							    "Not support chip. Consider what's optimal auto BW settting for this chip.\n");
						break;
					}
				}
			}

			PhyDSSSTable->Chanflag.ExtChnlOffset = EXT_CH_ABOVE_CTRL_CH;

			if (((PhyDSSSTable->Chanflag.ChnlWidth == CH_40_MHz_WIDTH) || (PhyDSSSTable->Chanflag.ChnlWidth == CH_80_MHz_WIDTH) ||
			     (PhyDSSSTable->Chanflag.ChnlWidth == CH_AUTO_WIDTH || (PhyDSSSTable->Chanflag.ChnlWidth == CH_160_MHz_WIDTH)))) {
				switch (PhyDSSSTable->CurrChan) {
				case 1:
				case 2:
				case 3:
				case 4:
					PhyDSSSTable->Chanflag.ExtChnlOffset = EXT_CH_ABOVE_CTRL_CH;
					break;
				case 5:	/* AutoBW: for CH5 let it be CH5-10, rather than CH5-1 */
					/* Now AutoBW use 5-1 instead of 5-9 for wifi cert convenience */
				case 6:	/* AutoBW: for CH6 let it be CH6-2, rather than CH6-10 */
				case 7:	/* AutoBW: for CH7 let it be CH7-3, rather than CH7-11 */
				case 8:
				case 9:
				case 10:
					if (*mib_extSubCh_p == 0)
						PhyDSSSTable->Chanflag.ExtChnlOffset = EXT_CH_BELOW_CTRL_CH;
					else if (*mib_extSubCh_p == 1)
						PhyDSSSTable->Chanflag.ExtChnlOffset = EXT_CH_BELOW_CTRL_CH;
					else if (*mib_extSubCh_p == 2)
						PhyDSSSTable->Chanflag.ExtChnlOffset = EXT_CH_ABOVE_CTRL_CH;
					break;
				case 11:
				case 12:
				case 13:
				case 14:	/* support 20Mhz BW only */
					PhyDSSSTable->Chanflag.ExtChnlOffset = EXT_CH_BELOW_CTRL_CH;
					break;
					/* for 5G */
				case 36:
					PhyDSSSTable->Chanflag.ExtChnlOffset = EXT_CH_ABOVE_CTRL_CH;
					break;
				case 40:
					PhyDSSSTable->Chanflag.ExtChnlOffset = EXT_CH_BELOW_CTRL_CH;
					break;
				case 44:
					PhyDSSSTable->Chanflag.ExtChnlOffset = EXT_CH_ABOVE_CTRL_CH;
					break;
				case 48:
					PhyDSSSTable->Chanflag.ExtChnlOffset = EXT_CH_BELOW_CTRL_CH;
					break;
				case 52:
					PhyDSSSTable->Chanflag.ExtChnlOffset = EXT_CH_ABOVE_CTRL_CH;
					break;
				case 56:
					PhyDSSSTable->Chanflag.ExtChnlOffset = EXT_CH_BELOW_CTRL_CH;
					break;
				case 60:
					PhyDSSSTable->Chanflag.ExtChnlOffset = EXT_CH_ABOVE_CTRL_CH;
					break;
				case 64:
					PhyDSSSTable->Chanflag.ExtChnlOffset = EXT_CH_BELOW_CTRL_CH;
					break;

				case 100:
					PhyDSSSTable->Chanflag.ExtChnlOffset = EXT_CH_ABOVE_CTRL_CH;
					break;
				case 104:
					PhyDSSSTable->Chanflag.ExtChnlOffset = EXT_CH_BELOW_CTRL_CH;
					break;
				case 108:
					PhyDSSSTable->Chanflag.ExtChnlOffset = EXT_CH_ABOVE_CTRL_CH;
					break;
				case 112:
					PhyDSSSTable->Chanflag.ExtChnlOffset = EXT_CH_BELOW_CTRL_CH;
					break;
				case 116:
					PhyDSSSTable->Chanflag.ExtChnlOffset = EXT_CH_ABOVE_CTRL_CH;
					break;
				case 120:
					PhyDSSSTable->Chanflag.ExtChnlOffset = EXT_CH_BELOW_CTRL_CH;
					break;
				case 124:
					PhyDSSSTable->Chanflag.ExtChnlOffset = EXT_CH_ABOVE_CTRL_CH;
					break;
				case 128:
					PhyDSSSTable->Chanflag.ExtChnlOffset = EXT_CH_BELOW_CTRL_CH;
					break;
				case 132:
					PhyDSSSTable->Chanflag.ExtChnlOffset = EXT_CH_ABOVE_CTRL_CH;
					break;
				case 136:
					PhyDSSSTable->Chanflag.ExtChnlOffset = EXT_CH_BELOW_CTRL_CH;
					break;
				case 140:
					PhyDSSSTable->Chanflag.ExtChnlOffset = EXT_CH_ABOVE_CTRL_CH;
					break;
				case 144:
					PhyDSSSTable->Chanflag.ExtChnlOffset = EXT_CH_BELOW_CTRL_CH;
					break;
				case 149:
					PhyDSSSTable->Chanflag.ExtChnlOffset = EXT_CH_ABOVE_CTRL_CH;
					break;
				case 153:
					PhyDSSSTable->Chanflag.ExtChnlOffset = EXT_CH_BELOW_CTRL_CH;
					break;
				case 157:
					PhyDSSSTable->Chanflag.ExtChnlOffset = EXT_CH_ABOVE_CTRL_CH;
					break;
				case 161:
					PhyDSSSTable->Chanflag.ExtChnlOffset = EXT_CH_BELOW_CTRL_CH;
					break;
				case 165:
					if (*(mib->mib_regionCode) == DOMAIN_CODE_ALL) {
						PhyDSSSTable->Chanflag.ExtChnlOffset = EXT_CH_ABOVE_CTRL_CH;
					} else {
						PhyDSSSTable->Chanflag.ExtChnlOffset = EXT_CH_BELOW_CTRL_CH;
					}
					break;
				case 169:
					PhyDSSSTable->Chanflag.ExtChnlOffset = EXT_CH_BELOW_CTRL_CH;
					break;
				case 173:
					PhyDSSSTable->Chanflag.ExtChnlOffset = EXT_CH_ABOVE_CTRL_CH;
					break;
				case 177:
					PhyDSSSTable->Chanflag.ExtChnlOffset = EXT_CH_BELOW_CTRL_CH;
					break;
				case 181:
					PhyDSSSTable->Chanflag.ExtChnlOffset = NO_EXT_CHANNEL;
					break;
				}
			}
			if (PhyDSSSTable->CurrChan <= 14)
				PhyDSSSTable->Chanflag.FreqBand = FREQ_BAND_2DOT4GHZ;
			else
				PhyDSSSTable->Chanflag.FreqBand = FREQ_BAND_5GHZ;
		} else {
			PRINT1(IOCTL, "Invalid channel %d for domain %x\n", channel, domainGetDomain());
			rc = -EOPNOTSUPP;
		}
	} else {
		printk("WARNING: wlset_freq is called with zero channel value!\n");
		rc = -EOPNOTSUPP;
	}
	return rc;
}

int mwl_config_set_bcninterval(struct net_device *netdev, uint16_t bcninterval)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	int rc = 0;

	if (bcninterval < 20 || bcninterval > 1000)
		rc = -EOPNOTSUPP;
	else
		*(mib->mib_BcnPeriod) = bcninterval;

	return rc;
}

int mwl_config_set_essid(struct net_device *netdev, const char *ssid, uint8_t ssid_len)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	memset(&(mib->StationConfig->DesiredSsId[0]), 0, 32);
	memcpy(&(mib->StationConfig->DesiredSsId[0]), ssid, ssid_len);

	return 0;
}

#ifdef WNM
void *FindIEWithinIEs(UINT8 * data_p, UINT32 lenPacket, UINT8 attrib, UINT8 * OUI)
#else
static void *FindIEWithinIEs(UINT8 * data_p, UINT32 lenPacket, UINT8 attrib, UINT8 * OUI)
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

extern BOOLEAN RsnBIPcap(IEEEtypes_RSN_IE_WPA2_t * ie_p, UINT8 * mfpc, UINT8 * mfpr);
extern void *FindAttributeWithinWPSIE(UINT8 * wsc_attr_buf, UINT32 wsc_attr_len, UINT32 target_attr);
int mwl_config_set_appie(struct net_device *netdev, struct wlreq_set_appie *appie)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	WSC_COMB_IE_t APWSCIE;
	UINT16 ieType = 0;
	UINT8 *rsn_ie = NULL;
	UINT8 *wpa_ie = NULL;
	UINT8 WPA_OUI[4] = { 0x00, 0x50, 0xf2, 0x01 };
#ifdef MRVL_80211R
	UINT8 *md_ie = NULL;
#endif
	UINT8 *rsnx_ie = NULL;
#ifdef MULTI_AP_SUPPORT
	IEEEtypes_MultiAP_Element_t *MultiAP_IE_p = NULL;
	UINT8 MAP_OUI[4] = { 0x50, 0x6F, 0x9A, 0x1B };
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	UINT16 version_len = 0;
#endif				/*MULTI_AP_SUPPORT */
#ifdef MBO_SUPPORT
	UINT8 MBO_OUI[4] = { 0x50, 0x6F, 0x9A, 0x16 };
	struct IEEEtypes_MBO_Element_t *pMBO = NULL;
#endif				/* MBO_SUPPORT */
#if defined(AP_STEERING_SUPPORT) || defined(MBO_SUPPORT)
	IEEEtypes_Extended_Cap_Element_t *pExtCap = NULL;
	//MIB_802DOT11 *mib1 = vmacSta_p->Mib802dot11;
#endif				/* AP_STEERING_SUPPORT || MBO_SUPPORT */
#if defined(AP_STEERING_SUPPORT) || defined(MBO_SUPPORT) || defined(MULTI_AP_SUPPORT)
	MIB_802DOT11 *mib1 = vmacSta_p->Mib802dot11;
#endif				/* AP_STEERING_SUPPORT || MBO_SUPPORT || MULTI_AP_SUPPORT */
	UINT8 *wps_ie = NULL;
	WSC_RFBand_Attribute_t *wps_rf_band_arrt = NULL;
	UINT8 WPS_OUI[4] = { 0x00, 0x50, 0xf2, 0x04 };

	memset(&APWSCIE, 0, sizeof(WSC_COMB_IE_t));

	if (appie == NULL)
		return -EINVAL;

	if (appie->appBufLen == 8) {
		memset(&vmacSta_p->thisbeaconIEs, 0, sizeof(WSC_BeaconIEs_t));
		memset(&vmacSta_p->thisprobeRespIEs, 0, sizeof(WSC_ProbeRespIEs_t));
#ifdef MBO_SUPPORT
		if (mib1->mib_mbo_enabled) {
			if (wlFwSetIEs(netdev))
				WLDBG_EXIT_INFO(DBG_LEVEL_1, "Failed setting IES");
		}
		mib1->mib_mbo_assoc_disallow = 0;
#endif				/* MBO_SUPPORT */

		if (vmacSta_p->WPSOn) {
			if (wlFwSetIEs(netdev))
				WLDBG_EXIT_INFO(DBG_LEVEL_1, "Failed setting IES");
			vmacSta_p->WPSOn = 0;
		}
	}
#ifndef WNM
	if (appie->appBufLen < 8) {
		printk("incorrect wsc_ie at the driver\n");
#ifdef MBO_SUPPORT
		if (appie->appFrmType == WL_APPIE_FRAMETYPE_BEACON) {
			mib1->mib_mbo_enabled = 0;
			mib1->mib_mbo_wnm = 0;
			mib1->Interworking = 0;
		}
#endif				/* MBO_SUPPORT */
#ifdef AP_STEERING_SUPPORT
		if (appie->appFrmType == WL_APPIE_FRAMETYPE_BEACON)
			*(mib1->mib_btm_enabled) = 1;	//same as default
#endif				/* AP_STEERING_SUPPORT */
		return -EINVAL;
	}
#endif				//WNM
	switch (appie->appFrmType) {
	case WL_APPIE_IETYPE_RSN:
	case WL_OPTIE_BEACON_INCL_RSN:
	case WL_OPTIE_ASSOC_INCL_RSN:
		rsn_ie = FindIEWithinIEs(appie->appBuf, appie->appBufLen, RSN_IEWPA2, NULL);
		wpa_ie = FindIEWithinIEs(appie->appBuf, appie->appBufLen, RSN_IE, WPA_OUI);
#ifdef MRVL_80211R
		md_ie = FindIEWithinIEs(appie->appBuf, appie->appBufLen, MD_IE, NULL);
#endif
		rsnx_ie = FindIEWithinIEs(appie->appBuf, appie->appBufLen, RSNX_IE, NULL);

		memset(vmacSta_p->RSNXIE, 0, sizeof(IEEEtypes_RSNX_IE_t));
#if defined(CONFIG_IEEE80211W) || defined(CONFIG_HS2)
		memset(vmacSta_p->RsnIE, 0, sizeof(IEEEtypes_RSN_IE_WPA2_t));
		memset(vmacSta_p->WpaIE, 0, sizeof(IEEEtypes_RSN_IE_WPAMixedMode_t));
		if (rsn_ie != NULL || wpa_ie != NULL) {
			if (rsn_ie != NULL) {
				memcpy(vmacSta_p->RsnIE, rsn_ie, rsn_ie[1] + 2);
			}
			if (wpa_ie != NULL) {
				memcpy(vmacSta_p->WpaIE, wpa_ie, wpa_ie[1] + 2);
			}
			vmacSta_p->RsnIESetByHost = 1;
		} else {
			memset(vmacSta_p->RsnIE, 0, sizeof(IEEEtypes_RSN_IE_WPA2_t));
			memset(vmacSta_p->WpaIE, 0, sizeof(IEEEtypes_RSN_IE_WPAMixedMode_t));
			vmacSta_p->RsnIESetByHost = 0;
		}
#endif
#ifdef MRVL_80211R
		if (md_ie != NULL)
			memcpy(vmacSta_p->MDIE, md_ie, 5);
		else
			memset(vmacSta_p->MDIE, 0, 5);
#endif

		if (rsnx_ie) {
			if ((rsnx_ie[1] + 2) <= MAX_SIZE_RSNX_IE_BUF) {
				/* mwl_cfg80211_hex_dump("rsnx_ie", rsnx_ie, rsnx_ie[1] + 2); */
				memcpy(vmacSta_p->RSNXIE, rsnx_ie, rsnx_ie[1] + 2);
			}
		}
#ifdef CONFIG_IEEE80211W
		RsnBIPcap((IEEEtypes_RSN_IE_WPA2_t *) vmacSta_p->RsnIE, &vmacSta_p->ieee80211w, &vmacSta_p->ieee80211wRequired);

		printk("after ieee80211wRequired=%d ieee80211w=%d\n", vmacSta_p->ieee80211wRequired, vmacSta_p->ieee80211w);
#endif
		return 0;

	case WL_APPIE_FRAMETYPE_BEACON:
#ifdef WNM
		{
#else
		if (appie->appBufLen > 8) {
#endif				//WNM
#if defined(CONFIG_HS2)
			IEEEtypes_INTERWORKING_Element_t *pIW;
			IEEEtypes_HS_INDICATION_Element_t *pHS2;
			IEEEtypes_Extended_Cap_Element_t *pEC;
			IEEEtypes_P2P_Element_t *pP2P;
#endif
			ieType = 0;
			APWSCIE.beaconIE.Len = appie->appBufLen;
			memcpy(&APWSCIE.beaconIE.WSCData[0], appie->appBuf,
			       (appie->appBufLen > WSC_BEACON_IE_MAX_LENGTH) ? WSC_BEACON_IE_MAX_LENGTH : appie->appBufLen);
			wps_ie = FindIEWithinIEs(APWSCIE.beaconIE.WSCData, APWSCIE.beaconIE.Len, PROPRIETARY_IE, WPS_OUI);
			if (wps_ie) {
				vmacSta_p->WPSOn = 1;
				wps_rf_band_arrt =
				    FindAttributeWithinWPSIE(wps_ie + sizeof(IEEEtypes_InfoElementHdr_t) + WSC_OUI_LENGTH,
							     *(wps_ie + 1) - WSC_OUI_LENGTH, WSC_RF_BAND_ATTRB);
				if (wps_rf_band_arrt && vmacSta_p->wps_rf_band) {
					wps_rf_band_arrt->RFBand = vmacSta_p->wps_rf_band;
				}
			}
			memcpy(&vmacSta_p->thisbeaconIEs, &APWSCIE.beaconIE, sizeof(WSC_BeaconIEs_t));
			//_hexdump(vmacSta_p->dev->name, &vmacSta_p->thisbeaconIEs, vmacSta_p->thisbeaconIEs.Len + 2);
			//HS2.0 todo
			//need to decode the IEs to set different mibs
			//include *(mib->mib_intraBSS), *(mib->mib_HS2Indicator)
			// *(mib->mib_InterworkingActive) = 0;    /* 0: Disable, 1:enable */
			// *(mib->mib_AdvertismentProtocolActive) = 0;    /* 0: Disable, 1:enable */
			// *(mib->mib_RoamingConsortiumActive) = 0;    /* 0: Disable, 1:enable */
			// *(mib->mib_EmergencyAlertIDActive) = 0;        /* 0: Disable, 1:enable */
#if defined(CONFIG_HS2)
			pIW = FindIEWithinIEs(vmacSta_p->thisbeaconIEs.WSCData, vmacSta_p->thisbeaconIEs.Len, INTERWORKING, NULL);
			pEC = FindIEWithinIEs(vmacSta_p->thisbeaconIEs.WSCData, vmacSta_p->thisbeaconIEs.Len, EXT_CAP_IE, NULL);
			pHS2 = FindIEWithinIEs(vmacSta_p->thisbeaconIEs.WSCData, vmacSta_p->thisbeaconIEs.Len, HS_INDICATION, oui);
			pP2P = FindIEWithinIEs(vmacSta_p->thisbeaconIEs.WSCData, vmacSta_p->thisbeaconIEs.Len, HS_INDICATION, oui_p2p);

			if (pP2P && (pP2P->P2P_mgmt_type == 0x0a)) {
				if (pP2P->P2P_mgmt_bitmap & 0x1)	//P2P managable
					printk("%s: P2P managable", vmacSta_p->dev->name);
				if (pP2P->P2P_mgmt_bitmap & 0x2)	//P2P cross connect permit
					printk("%s: P2P cross connect permitted\n", vmacSta_p->dev->name);
				else
					printk("%s: P2P cross connect not permitted\n", vmacSta_p->dev->name);
			}
			if (pHS2) {
				vmacSta_p->hotspot = 1;
				vmacSta_p->dgaf_disable = pHS2->dgaf_disable;
				printk("%s: Downstream Group-Addressed Forwarding %s\n", vmacSta_p->dev->name,
				       vmacSta_p->dgaf_disable ? "Disabled" : "Enabled");
			}
			if (pIW) {
				//_hexdump("Interworking", pIW, pIW->Len+2);
				vmacSta_p->interworking = 1;
				vmacSta_p->access_network_type = pIW->AccessNetworkType;
				vmacSta_p->internet = pIW->Internet;
				vmacSta_p->asra = pIW->ASRA;
				vmacSta_p->esr = pIW->ESR;
				vmacSta_p->uesa = pIW->UESA;
				vmacSta_p->venue_info_set = (pIW->Len == 9) ? 1 : 0;
				if (vmacSta_p->venue_info_set) {
					vmacSta_p->venue_group = pIW->Body[0];
					vmacSta_p->venue_type = pIW->Body[1];
				}
				if (pIW->Len > 3)
					vmacSta_p->hessidset = 1;
				else
					vmacSta_p->hessidset = 0;
				memcpy(vmacSta_p->hessid, &pIW->Body[(pIW->Len == 9) ? 2 : 0], 6);
				//*(mib->mib_intraBSS) = ((pIW->AccessNetworkType==ACCESSNETWORKTYPE_CHARGEABLE_PUBLIC_NETWORK)||(pIW->AccessNetworkType==ACCESSNETWORKTYPE_FREE_PUBLIC_NETWORK))  ? 0:1;
				printk("%s: L2 Traffic Inspection and Filtering %s\n", vmacSta_p->dev->name,
				       *(mib->mib_intraBSS) ? "Disabled" : "Enabled");
			}
			if (pEC) {
				//_hexdump("Extended Cap", pEC, pEC->Len+2);
				vmacSta_p->proxyarp = pEC->cap[0] & 0x10;
				vmacSta_p->qosmap = (pEC->Len > 4) ? pEC->cap[3] & 0x1 : 0;
				vmacSta_p->tdls = (pEC->Len > 4) ? pEC->cap[3] : 0;

				if (vmacSta_p->tdls & 0x40)
					printk("%s: TDLS Prohibited\n", vmacSta_p->dev->name);
				/* 0x40- TDLS Prohibited */
				if (vmacSta_p->tdls & 0x80)
					printk("%s: TDLS Channel Switching Prohibited\n", vmacSta_p->dev->name);
				/* 0x80- TDLS Channel Switching Prohibited */
			}
#endif
		}
#ifdef MBO_SUPPORT
		if (vmacSta_p->thisbeaconIEs.Len > 0) {
			pMBO = FindIEWithinIEs(vmacSta_p->thisbeaconIEs.WSCData, vmacSta_p->thisbeaconIEs.Len, PROPRIETARY_IE, MBO_OUI);
			if (pMBO)
				mib1->mib_mbo_enabled = 1;
			else
				mib1->mib_mbo_enabled = 0;
		} else
			mib1->mib_mbo_enabled = 0;
#endif				/* MBO_SUPPORT */

#if defined(AP_STEERING_SUPPORT) || defined(MBO_SUPPORT)
		if (vmacSta_p->thisbeaconIEs.Len > 0) {
			pExtCap = FindIEWithinIEs(vmacSta_p->thisbeaconIEs.WSCData, vmacSta_p->thisbeaconIEs.Len, EXT_CAP_IE, NULL);
			if (pExtCap) {
				UINT16 extCapLen = pExtCap->Len + 2;
#ifdef AP_STEERING_SUPPORT
				*(mib1->mib_btm_enabled) = pExtCap->ExtCap.BSSTransition;
#endif				/* AP_STEERING_SUPPORT */
#ifdef MBO_SUPPORT
				mib1->mib_mbo_wnm = pExtCap->ExtCap.WNMNotification;
				mib1->Interworking = pExtCap->ExtCap.Interworking;
#endif				/* MBO_SUPPORT */

				/* remove duplicated extended capabilities */
				memmove(&(pExtCap->ElementId), vmacSta_p->thisbeaconIEs.WSCData + extCapLen,
					vmacSta_p->thisbeaconIEs.Len - extCapLen - (&(pExtCap->ElementId) - vmacSta_p->thisbeaconIEs.WSCData));
				vmacSta_p->thisbeaconIEs.Len -= extCapLen;
			} else {
#ifdef AP_STEERING_SUPPORT
				*(mib1->mib_btm_enabled) = 1;	//same as default
#endif				/* AP_STEERING_SUPPORT */
#ifdef MBO_SUPPORT
				mib1->mib_mbo_wnm = 0;
				mib1->Interworking = 0;
#endif				/* MBO_SUPPORT */
			}
		} else {
#ifdef AP_STEERING_SUPPORT
			*(mib1->mib_btm_enabled) = 1;	//same as default
#endif				/* AP_STEERING_SUPPORT */
#ifdef MBO_SUPPORT
			mib1->mib_mbo_wnm = 0;
			mib1->Interworking = 0;
#endif				/* MBO_SUPPORT */
		}
#endif				/* AP_STEERING_SUPPORT || MBO_SUPPORT */
		break;

	case WL_APPIE_FRAMETYPE_PROBE_RESP:
#ifdef WNM
		{
#else
		if (appie->appBufLen > 8) {
#endif				//WNM
			ieType = 1;
			APWSCIE.probeRespIE.Len = appie->appBufLen;
			memcpy(&APWSCIE.probeRespIE.WSCData[0], appie->appBuf,
			       (appie->appBufLen > WSC_PROBERESP_IE_MAX_LENGTH) ? WSC_PROBERESP_IE_MAX_LENGTH : appie->appBufLen);

			wps_ie = FindIEWithinIEs(APWSCIE.probeRespIE.WSCData, APWSCIE.probeRespIE.Len, PROPRIETARY_IE, WPS_OUI);
			if (wps_ie) {
				vmacSta_p->WPSOn = 1;
				wps_rf_band_arrt =
				    FindAttributeWithinWPSIE(wps_ie + sizeof(IEEEtypes_InfoElementHdr_t) + WSC_OUI_LENGTH,
							     *(wps_ie + 1) - WSC_OUI_LENGTH, WSC_RF_BAND_ATTRB);
				if (wps_rf_band_arrt && vmacSta_p->wps_rf_band) {
					wps_rf_band_arrt->RFBand = vmacSta_p->wps_rf_band;
				}
			}
			memcpy(&vmacSta_p->thisprobeRespIEs, &APWSCIE.probeRespIE, sizeof(WSC_ProbeRespIEs_t));
		}

		if (vmacSta_p->thisprobeRespIEs.Len > 0) {
			pExtCap = FindIEWithinIEs(vmacSta_p->thisprobeRespIEs.WSCData, vmacSta_p->thisprobeRespIEs.Len, EXT_CAP_IE, NULL);
			if (pExtCap) {
				UINT16 extCapLen = pExtCap->Len + 2;
				/* remove duplicated extended capabilities */
				memmove(&(pExtCap->ElementId), vmacSta_p->thisprobeRespIEs.WSCData + extCapLen,
					vmacSta_p->thisprobeRespIEs.Len - extCapLen - (&(pExtCap->ElementId) - vmacSta_p->thisprobeRespIEs.WSCData));
				vmacSta_p->thisprobeRespIEs.Len -= extCapLen;
			}
			if (wlFwSetIEs(netdev))
				WLDBG_EXIT_INFO(DBG_LEVEL_1, "Failed setting IES");

#if defined(AP_STEERING_SUPPORT) || defined(MBO_SUPPORT)
#ifdef MBO_SUPPORT
			if (mib1->mib_mbo_enabled) {
				UINT8 changed = 0;
				pMBO = FindIEWithinIEs(vmacSta_p->thisprobeRespIEs.WSCData, vmacSta_p->thisprobeRespIEs.Len, PROPRIETARY_IE, MBO_OUI);

				if ((pMBO) && (pMBO->Len >= 0x0a) && (*(pMBO->variable + 3) == 0x04)) {
					if (!mib1->mib_mbo_assoc_disallow) {
						mib1->mib_mbo_assoc_disallow = 1;
						changed = 1;
					}
				} else {
					if (mib1->mib_mbo_assoc_disallow) {
						mib1->mib_mbo_assoc_disallow = 0;
						changed = 1;
					}
				}

				if (changed) {
#ifdef MULTI_AP_SUPPORT
					static const char *tag = "mbo_assoc_allow";
					char evBuf[64] = { 0 };
					UINT32 evLen = 0;
					union iwreq_data wreq;
#endif				/* MULTI_AP_SUPPORT */
					if (wlFwSetIEs(netdev))
						WLDBG_EXIT_INFO(DBG_LEVEL_1, "Failed setting IES");

#ifdef MULTI_AP_SUPPORT
					snprintf(evBuf, sizeof(evBuf), "%s", tag);
					evLen = strlen(evBuf);
					memcpy(&evBuf[evLen], (IEEEtypes_MacAddr_t *) & priv->hwData.macAddr[0], sizeof(IEEEtypes_MacAddr_t));
					evLen += sizeof(IEEEtypes_MacAddr_t);
					if (mib1->mib_mbo_assoc_disallow)
						evBuf[evLen++] = 0;
					else
						evBuf[evLen++] = 1;

					memset(&wreq, 0, sizeof(wreq));
					wreq.data.length = evLen;
					if (vmacSta_p->dev->flags & IFF_RUNNING)
						wireless_send_event(vmacSta_p->dev, IWEVCUSTOM, &wreq, evBuf);
#endif				/* MULTI_AP_SUPPORT */
					return 0;
				}
			}
#endif				/* MBO_SUPPORT */
#endif				/* AP_STEERING_SUPPORT || MBO_SUPPORT */
		}
		break;

	case WL_AAPIE_FRAMETYPE_ASSOC_RESPONSE:
		break;

	case WL_OPTIE_PROBE_RESP_INCL_RSN:
		return 0;

	case WL_OPTIE_BEACON_NORSN:
#ifdef MULTI_AP_SUPPORT
		MultiAP_IE_p = FindIEWithinIEs(appie->appBuf, appie->appBufLen, PROPRIETARY_IE, MAP_OUI);
		if (MultiAP_IE_p != NULL) {
			//memcpy(&vmacSta_p->MultiAP_IE, MultiAP_IE_p, sizeof(struct IEEEtypes_MultiAP_Element_t));
			mib->multi_ap_attr = MAP_ATTRIBUTE_DISABLE;
			if (MultiAP_IE_p->attributes.TearDown)
				mib->multi_ap_attr |= MAP_ATTRIBUTE_TEARDOWN;
			if (MultiAP_IE_p->attributes.FrontBSS)
				mib->multi_ap_attr |= MAP_ATTRIBUTE_FRONTHAUL_BSS;
			if (MultiAP_IE_p->attributes.BackBSS)
				mib->multi_ap_attr |= MAP_ATTRIBUTE_BACKHAUL_BSS;
			/* Encode bit 3 and bit 4 for R2, Table 4. */
			if (MultiAP_IE_p->attributes.R1bSTAdisAllowed)
				mib->multi_ap_attr |= MAP_ATTRIBUTE_R1BSTA_DISALLOWED;
			if (MultiAP_IE_p->attributes.R2bSTAdisAllowed)
				mib->multi_ap_attr |= MAP_ATTRIBUTE_R2BSTA_DISALLOWED;
			mib1->multi_ap_attr = mib->multi_ap_attr;

			if (MultiAP_IE_p->Len >= MAP_R1_IE_LEN + sizeof(IEEEtypes_MultiAP_Version_t)) {
				IEEEtypes_MultiAP_Version_t *version = (IEEEtypes_MultiAP_Version_t *) MultiAP_IE_p->variable;

				if ((version->ElementId == 0x07) && (version->Len == 0x01)) {
					mib->multi_ap_ver = version->value;
					mib1->multi_ap_ver = mib->multi_ap_ver;
					version_len += version->Len + 2;
				}

				if ((version_len && (MultiAP_IE_p->Len >=
						     (MAP_R1_IE_LEN +
						      sizeof(IEEEtypes_MultiAP_Version_t) +
						      sizeof(IEEEtypes_MultiAP_Traffic_t)))) ||
				    (MultiAP_IE_p->Len >= (MAP_R1_IE_LEN + sizeof(IEEEtypes_MultiAP_Traffic_t)))) {
					IEEEtypes_MultiAP_Traffic_t *traffic = (IEEEtypes_MultiAP_Traffic_t *) (MultiAP_IE_p->variable + version_len);

					if ((traffic->ElementId == 0x08) && (traffic->Len == 0x02)) {
						mib->multi_ap_vid = traffic->vid;
						mib1->multi_ap_vid = mib->multi_ap_vid;
					}
				}
			}
		}
#endif				/*MULTI_AP_SUPPORT */
		wpa_ie = FindIEWithinIEs(appie->appBuf, appie->appBufLen, RSN_IE, WPA_OUI);
		if (wpa_ie != NULL) {
			memcpy(vmacSta_p->WpaIE, wpa_ie, wpa_ie[1] + 2);
			vmacSta_p->RsnIESetByHost = 1;
		}
		break;

#ifdef MRVL_WPS_CLIENT
	case WL_APPIE_FRAMETYPE_PROBE_REQUEST:
		if ((appie->appBufLen > 0) && (appie->appBuf != NULL)) {
			IEEEtypes_InfoElementHdr_t *pIW;
			UINT8 *pos = priv->wpsProbeRequestIe;
			UINT8 oui[4] = { 0x00, 0x50, 0xf2, 0x04 };

			WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)appie->appBuf, appie->appBufLen);

			pIW = FindIEWithinIEs(appie->appBuf, appie->appBufLen, PROPRIETARY_IE, oui);

			memset(priv->wpsProbeRequestIe, 0, sizeof(priv->wpsProbeRequestIe));
			priv->wpsProbeRequestIeLen = 0;
			/* copy intwerworking first because FW will treate ext cap as the last IE */
			if (pIW != NULL) {
				memcpy(priv->wpsProbeRequestIe, pIW, pIW->Len + sizeof(IEEEtypes_InfoElementHdr_t));
				priv->wpsProbeRequestIeLen += pIW->Len + sizeof(IEEEtypes_InfoElementHdr_t);
				pos += priv->wpsProbeRequestIeLen;
			}
		} else {
			memset(priv->wpsProbeRequestIe, 0, sizeof(priv->wpsProbeRequestIe));
			priv->wpsProbeRequestIeLen = 0;
		}

		return 0;
#endif

	default:
		/* Remove beacon IE */
		memset(&vmacSta_p->thisbeaconIEs, 0, sizeof(WSC_BeaconIEs_t));
		ieType = 0;
		if (wlFwSetWscIE(netdev, ieType, &APWSCIE))
			WLDBG_EXIT_INFO(DBG_LEVEL_1, "Failed setting WSC IE");

		/* Remove Probe response IE */
		memset(&vmacSta_p->thisprobeRespIEs, 0, sizeof(WSC_ProbeRespIEs_t));
		ieType = 1;
		if (wlFwSetWscIE(netdev, ieType, &APWSCIE))
			WLDBG_EXIT_INFO(DBG_LEVEL_1, "Failed setting WSC IE");

		vmacSta_p->WPSOn = 0;
		return 0;
	}

	if (APWSCIE.beaconIE.Len > 0) {
		pExtCap = FindIEWithinIEs(APWSCIE.beaconIE.WSCData, APWSCIE.beaconIE.Len, EXT_CAP_IE, NULL);

		if (pExtCap) {
			UINT16 extCapLen = pExtCap->Len + 2;

			/* remove duplicated extended capabilities */
			memmove(&(pExtCap->ElementId), APWSCIE.beaconIE.WSCData + extCapLen,
				APWSCIE.beaconIE.Len - extCapLen - (&(pExtCap->ElementId) - APWSCIE.beaconIE.WSCData));
			APWSCIE.beaconIE.Len -= extCapLen;
		}
	}

	if (wlFwSetWscIE(netdev, ieType, &APWSCIE))
		WLDBG_EXIT_INFO(DBG_LEVEL_1, "Failed setting WSC IE");

	return 0;
}

extern extStaDb_Status_e extStaDb_RemoveSta(vmacApInfo_t * vmac_p, IEEEtypes_MacAddr_t * Addr_p);
int mwl_config_send_mlme(struct net_device *netdev, struct wlreq_mlme *mlme)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;

	switch (mlme->im_op) {
	case WL_MLME_DEAUTH:
		if (vmacSta_p->wtp_info.mac_mode != WTP_MAC_MODE_SPLITMAC) {
			macMgmtMlme_SendDeauthenticateMsg(vmacSta_p, &mlme->im_macaddr, 0, mlme->im_reason, FALSE);
			if (extStaDb_GetStaInfo(vmacSta_p, &mlme->im_macaddr, STADB_DONT_UPDATE_AGINGTIME) != NULL) {
				msleep(500);
			}
			//RemoveSta when non-splitmac mode
			extStaDb_RemoveSta(vmacSta_p, &mlme->im_macaddr);
		} else
			macMgmtMlme_SendDeauthenticateMsg(vmacSta_p, &mlme->im_macaddr, 0, mlme->im_reason, TRUE);
		break;
	case WL_MLME_DISASSOC:
		macMgmtMlme_SendDisassociateMsg(vmacSta_p, &mlme->im_macaddr, 0, mlme->im_reason);
		break;
#ifdef WTP_SUPPORT
	case WL_MLME_AUTHORIZE:
		macMgmtMlme_set_sta_authorized(vmacSta_p, &mlme->im_macaddr);
		break;

	case WL_MLME_ASSOC:
		{
			PeerInfo_t PeerInfo;
			memset(&PeerInfo, 0x00, sizeof(PeerInfo_t));
			memcpy(&PeerInfo, mlme->PeerInfo, sizeof(mlme->PeerInfo));
			macMgmtMlme_set_sta_associated(vmacSta_p, &mlme->im_macaddr, mlme->Aid,
						       (PeerInfo_t *) & PeerInfo, mlme->QosInfo, mlme->isQosSta,
						       mlme->rsnSta, (UINT8 *) & mlme->rsnIE);
			break;
		}

	case WL_MLME_DELSTA:
		macMgmtMlme_del_sta_entry(vmacSta_p, &mlme->im_macaddr);
		break;
#endif
#ifdef MRVL_80211R
	case WL_MLME_SET_ASSOC:
	case WL_MLME_SET_REASSOC:
		macMgmtMlme_SendAssocMsg(vmacSta_p, (IEEEtypes_MacAddr_t *) & mlme->im_macaddr, mlme->im_optie, mlme->im_optie_len);
		break;
	case WL_MLME_SET_AUTH:
		macMgmtMlme_SendAuthenticateMsg(vmacSta_p, (IEEEtypes_MacAddr_t *) & mlme->im_macaddr,
						mlme->im_seq, mlme->im_reason, mlme->im_optie, mlme->im_optie_len);
		break;
#endif

	default:
		return -EOPNOTSUPP;
	}
	return 0;
}

extern void getTkipStaKeyMaterial(extStaDb_StaInfo_t * StaInfo_p, TKIP_TYPE_KEY * pKey);
int mwl_config_set_key(struct net_device *netdev, struct wlreq_key *wk)
{
#ifndef CLIENT_SUPPORT
#define GetParentStaBSSID(x) NULL
#endif

	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	MIB_802DOT11 *mib1 = vmacSta_p->Mib802dot11;
	extStaDb_StaInfo_t *pStaInfo = NULL;
#ifdef CLIENT_SUPPORT
	vmacEntry_t *vmacEntry_p = NULL;
	STA_SECURITY_MIBS *pStaSecurityMibs = NULL;
	keyMgmtInfoSta_t *pKeyMgmtInfoSta = NULL;
#endif

#ifdef MRVL_WPS_CLIENT
	if (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_CLNT_INFRA) {
		if ((vmacEntry_p = sme_GetParentVMacEntry(vmacSta_p->VMacEntry.phyHwMacIndx)) == NULL)
			return -EFAULT;
	}

	if (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_CLNT_INFRA) {
		pStaSecurityMibs = sme_GetStaSecurityMibsPtr(vmacEntry_p);
		pKeyMgmtInfoSta = sme_GetKeyMgmtInfoStaPtr(vmacEntry_p);
		if (pStaSecurityMibs == NULL || pKeyMgmtInfoSta == NULL)
			return -EINVAL;
	}
#endif				//MRVL_WPS_CLIENT

	if (wk->ik_keyix == WL_KEYIX_NONE) {
		if (extStaDb_SetRSNPwkAndDataTraffic(vmacSta_p,
						     vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_CLNT_INFRA ?
						     (IEEEtypes_MacAddr_t *) GetParentStaBSSID((vmacEntry_p)->phyHwMacIndx) :
						     (IEEEtypes_MacAddr_t *) wk->ik_macaddr,
						     &wk->ik_keydata[0],
						     (UINT32 *) & wk->ik_keydata[16], (UINT32 *) & wk->ik_keydata[24]) != STATE_SUCCESS)
			return -EOPNOTSUPP;
		if (extStaDb_SetPairwiseTSC(vmacSta_p,
					    vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_CLNT_INFRA ?
					    (IEEEtypes_MacAddr_t *) GetParentStaBSSID((vmacEntry_p)->phyHwMacIndx) :
					    (IEEEtypes_MacAddr_t *) wk->ik_macaddr, 0, 0x0001) != STATE_SUCCESS)
			return -EOPNOTSUPP;

		if ((pStaInfo = extStaDb_GetStaInfo(vmacSta_p,
						    vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_CLNT_INFRA ?
						    (IEEEtypes_MacAddr_t *) GetParentStaBSSID((vmacEntry_p)->phyHwMacIndx) :
						    (IEEEtypes_MacAddr_t *) wk->ik_macaddr, STADB_UPDATE_AGINGTIME)) == NULL)
			return -EOPNOTSUPP;
#ifdef CLIENT_SUPPORT
		if (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_CLNT_INFRA) {
			UINT8 keyType = KEY_TYPE_ID_CCMP;
			UINT32 keyInfo = ENCR_KEY_FLAG_PTK | ENCR_KEY_FLAG_STA_MODE;
			TKIP_TYPE_KEY tkipParam;
			AES_TYPE_KEY aesParam;
			UINT8 *pParam = (UINT8 *) & aesParam;
			UINT8 OuiType = CIPHER_OUI_TYPE_NONE;

			udelay(100);
			if (!pStaSecurityMibs->mib_RSNConfigWPA2_p->WPA2OnlyEnabled && !pStaSecurityMibs->mib_RSNConfigWPA2_p->WPA2Enabled) {
				//WPA
				AddRSN_IE_TO(pStaSecurityMibs->thisStaRsnIE_p, (IEEEtypes_RSN_IE_t *) (&pStaInfo->keyMgmtStateInfo.RsnIEBuf[0]));
				if (pStaSecurityMibs->mib_RSNConfigUnicastCiphers_p->UnicastCipher[3] == 2) {
					pParam = (UINT8 *) & tkipParam;

					keyType = KEY_TYPE_ID_TKIP;
					keyInfo |= ENCR_KEY_FLAG_MICKEY_VALID | ENCR_KEY_FLAG_TSC_VALID;
					getTkipStaKeyMaterial(pStaInfo, &tkipParam);
					OuiType = CIPHER_OUI_TYPE_TKIP;
				} else if ((pStaSecurityMibs->mib_RSNConfigUnicastCiphers_p->UnicastCipher[3] == 4)) {
					pParam = (UINT8 *) & aesParam;

					keyType = KEY_TYPE_ID_CCMP;
					memcpy(aesParam.KeyMaterial, wk->ik_keydata, wk->ik_keylen);
					OuiType = CIPHER_OUI_TYPE_CCMP;
				}
			} else {
				// WPA2
				AddRSN_IEWPA2_TO(pStaSecurityMibs->thisStaRsnIEWPA2_p,
						 (IEEEtypes_RSN_IE_WPA2_t *) (&pStaInfo->keyMgmtStateInfo.RsnIEBuf[0]));
				if (isAes4RsnValid(pStaSecurityMibs->mib_RSNConfigWPA2UnicastCiphers_p->UnicastCipher[3])) {
					pParam = (UINT8 *) & aesParam;	//ccmp/gcmp 128/256

					if ((pStaSecurityMibs->mib_RSNConfigWPA2UnicastCiphers_p->UnicastCipher[3] == IEEEtypes_RSN_CIPHER_SUITE_GCMP)
					    || (pStaSecurityMibs->mib_RSNConfigWPA2UnicastCiphers_p->UnicastCipher[3] ==
						IEEEtypes_RSN_CIPHER_SUITE_GCMP_256)) {
						keyType = KEY_TYPE_ID_GCMP;
						OuiType = CIPHER_OUI_TYPE_GCMP;
					} else {
						keyType = KEY_TYPE_ID_CCMP;
						OuiType = CIPHER_OUI_TYPE_CCMP;
					}

					memcpy(aesParam.KeyMaterial, wk->ik_keydata, wk->ik_keylen);

				} else {
					pParam = (UINT8 *) & tkipParam;

					keyType = KEY_TYPE_ID_TKIP;
					keyInfo |= ENCR_KEY_FLAG_MICKEY_VALID | ENCR_KEY_FLAG_TSC_VALID;

					getTkipStaKeyMaterial(pStaInfo, &tkipParam);
					OuiType = CIPHER_OUI_TYPE_TKIP;

				}
			}

			wlFwSetSecurityKey(netdev, ACT_SET, keyType, pStaInfo->Addr, 0, wk->ik_keylen, keyInfo, pParam);
#ifdef CONFIG_IEEE80211W
			if (pStaInfo)
				pStaInfo->ptkCipherOuiType = OuiType;
#endif
			printk("WL_PARAM_SETKEYS :::::: Send PTK to FW type=%d idx=%d len=%d\n", wk->ik_type, wk->ik_keyix, wk->ik_keylen);

			if (pKeyMgmtInfoSta)
				pKeyMgmtInfoSta->pKeyData->RSNDataTrafficEnabled = 1;
			if (pStaInfo)
				pStaInfo->keyMgmtStateInfo.RSNDataTrafficEnabled = 1;
			return 0;
		} else
#endif
		{
			if (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_AP) {
				wlFwSetWpaWpa2PWK(netdev, pStaInfo);
				return 0;
			}
		}
	} else if ((wk->ik_keyix < 4)) {
		/* In WEP mode, key index maybe = 0 */
		if (wk->ik_type == WL_CIPHER_TKIP) {
			UINT32 keyInfo = ENCR_KEY_FLAG_GTK_RX_KEY | ENCR_KEY_FLAG_MICKEY_VALID | ENCR_KEY_FLAG_TSC_VALID;
			TKIP_TYPE_KEY param;

			if (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_AP) {
				memcpy(mib1->mib_MrvlRSN_GrpKey->EncryptKey, &wk->ik_keydata[0], TK_SIZE);
				memcpy(mib1->mib_MrvlRSN_GrpKey->TxMICKey, &wk->ik_keydata[TK_SIZE], 8);
				memcpy(mib1->mib_MrvlRSN_GrpKey->RxMICKey, &wk->ik_keydata[TK_SIZE + 8], 8);
				mib1->mib_MrvlRSN_GrpKey->g_IV16 = 0x0001;
				mib1->mib_MrvlRSN_GrpKey->g_IV32 = 0;
				mib1->mib_MrvlRSN_GrpKey->g_KeyIndex = (UINT8) wk->ik_keyix;

				memcpy(param.KeyMaterial, mib1->mib_MrvlRSN_GrpKey->EncryptKey, TK_SIZE);
				memcpy(param.RxMicKey, mib1->mib_MrvlRSN_GrpKey->RxMICKey, MIC_KEY_LENGTH);
				memcpy(param.TxMicKey, mib1->mib_MrvlRSN_GrpKey->TxMICKey, MIC_KEY_LENGTH);

				param.Tsc.low = mib1->mib_MrvlRSN_GrpKey->g_IV16;
				param.Tsc.high = mib1->mib_MrvlRSN_GrpKey->g_IV32;

				wlFwSetSecurityKey(netdev, ACT_SET, KEY_TYPE_ID_TKIP,
						   vmacSta_p->macStaAddr, wk->ik_keyix, TK_SIZE, keyInfo, (UINT8 *) & param);

				//need to update shadow mib, when directly modify run-time mib.
				memcpy(mib->mib_MrvlRSN_GrpKey, mib1->mib_MrvlRSN_GrpKey, sizeof(MRVL_MIB_RSN_GRP_KEY));
			}
#ifdef CLIENT_SUPPORT
			else if (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_CLNT_INFRA) {
				UINT8 *macStaAddr_p = vmacEntry_p->vmacAddr;

				memcpy(mib_MrvlRSN_GrpKeyUr1[vmacEntry_p->phyHwMacIndx].EncryptKey, &wk->ik_keydata[0], TK_SIZE);
				memcpy(mib_MrvlRSN_GrpKeyUr1[vmacEntry_p->phyHwMacIndx].TxMICKey, &wk->ik_keydata[16], 8);
				memcpy(mib_MrvlRSN_GrpKeyUr1[vmacEntry_p->phyHwMacIndx].RxMICKey, &wk->ik_keydata[24], 8);

				mib_MrvlRSN_GrpKeyUr1[vmacEntry_p->phyHwMacIndx].g_IV16 = 0x0001;
				mib_MrvlRSN_GrpKeyUr1[vmacEntry_p->phyHwMacIndx].g_IV32 = 0;

				memcpy(param.KeyMaterial, mib_MrvlRSN_GrpKeyUr1[vmacEntry_p->phyHwMacIndx].EncryptKey, TK_SIZE);
				memcpy(param.RxMicKey, mib_MrvlRSN_GrpKeyUr1[vmacEntry_p->phyHwMacIndx].RxMICKey, MIC_KEY_LENGTH);
				memcpy(param.TxMicKey, mib_MrvlRSN_GrpKeyUr1[vmacEntry_p->phyHwMacIndx].TxMICKey, MIC_KEY_LENGTH);

				param.Tsc.low = mib_MrvlRSN_GrpKeyUr1[vmacEntry_p->phyHwMacIndx].g_IV16;
				param.Tsc.high = mib_MrvlRSN_GrpKeyUr1[vmacEntry_p->phyHwMacIndx].g_IV32;
				keyInfo |= ENCR_KEY_FLAG_STA_MODE;
				if (macStaAddr_p) {
					wlFwSetSecurityKey(netdev, ACT_SET, KEY_TYPE_ID_TKIP,
							   macStaAddr_p, wk->ik_keyix, TK_SIZE, keyInfo, (UINT8 *) & param);
					printk("WL_PARAM_SETKEYS :::::: Send GTK to FW type=%d idx=%d len=%d\n",
					       wk->ik_type, wk->ik_keyix, wk->ik_keylen);
				}

				if (pKeyMgmtInfoSta)
					pKeyMgmtInfoSta->pKeyData->RSNSecured = 1;
			}
#endif
			return 0;
		} else if ((wk->ik_type == WL_CIPHER_CCMP) ||
			   (wk->ik_type == WL_CIPHER_GCMP) || (wk->ik_type == WL_CIPHER_CCMP_256) || (wk->ik_type == WL_CIPHER_GCMP_256)) {
			AES_TYPE_KEY param;
			UINT8 keyType = KEY_TYPE_ID_CCMP;
			UINT32 keyInfo = ENCR_KEY_FLAG_GTK_RX_KEY;

			if (wk->ik_keylen > 32)
				wk->ik_keylen = 32;

			if ((wk->ik_type == WL_CIPHER_GCMP) || (wk->ik_type == WL_CIPHER_GCMP_256))
				keyType = KEY_TYPE_ID_GCMP;

			memcpy(param.KeyMaterial, wk->ik_keydata, wk->ik_keylen);

			if (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_AP) {
				memcpy(mib1->mib_MrvlRSN_GrpKey->EncryptKey, &wk->ik_keydata[0], wk->ik_keylen);
				mib1->mib_MrvlRSN_GrpKey->g_KeyIndex = (UINT8) wk->ik_keyix;

				wlFwSetSecurityKey(netdev, ACT_SET, keyType,
						   vmacSta_p->macStaAddr, wk->ik_keyix, wk->ik_keylen, keyInfo, (UINT8 *) & param);

				//need to update shadow mib, when directly modify run-time mib.
				memcpy(mib->mib_MrvlRSN_GrpKey, mib1->mib_MrvlRSN_GrpKey, sizeof(MRVL_MIB_RSN_GRP_KEY));
			}
#ifdef CLIENT_SUPPORT
			else if (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_CLNT_INFRA) {
				memcpy(mib_MrvlRSN_GrpKeyUr1[vmacEntry_p->phyHwMacIndx].EncryptKey, &wk->ik_keydata[0], wk->ik_keylen);

				keyInfo |= ENCR_KEY_FLAG_STA_MODE;
				wlFwSetSecurityKey(netdev, ACT_SET, keyType,
						   vmacEntry_p->vmacAddr, wk->ik_keyix, wk->ik_keylen, keyInfo, (UINT8 *) & param);
				printk("WL_PARAM_SETKEYS :::::: Send GTK to FW type=%d idx=%d len=%d\n", wk->ik_type, wk->ik_keyix, wk->ik_keylen);
			}
#endif
			return 0;
		} else if ((wk->ik_type == WL_CIPHER_WEP40) || (wk->ik_type == WL_CIPHER_WEP104)) {
			if (wk->ik_keylen == 5 || wk->ik_keylen == 13) {
				mwl_config_set_wepkey(netdev, wk->ik_keydata, wk->ik_keylen, MWL_WEP_ENCODE_RESTRICTED, wk->ik_keyix);
			} else if (wk->ik_keylen < 13) {
				mwl_config_set_wepkey(netdev, wk->ik_keydata, wk->ik_keylen, MWL_WEP_ENCODE_OPEN, wk->ik_keyix);
			}
			return 0;
		} else
			return -ENOTSUPP;
	}
#ifdef CONFIG_IEEE80211W
	else if ((3 < wk->ik_keyix) && (wk->ik_keyix < 6)) {
		if (wk->ik_keylen > 32)
			wk->ik_keylen = 32;
		vmacSta_p->igtksaInstalled = 0;
		if (wk->ik_type == WL_CIPHER_IGTK ||
		    wk->ik_type == WL_CIPHER_AES_GMAC || wk->ik_type == WL_CIPHER_AES_GMAC_256 || wk->ik_type == WL_CIPHER_AES_CMAC_256) {
#ifdef CLIENT_SUPPORT
			AES_TYPE_KEY param;
			UINT8 keyType = KEY_TYPE_ID_CCMP;
			UINT32 keyInfo = ENCR_KEY_FLAG_IGTK_RX_KEY;
			if (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_CLNT_INFRA) {
				memset(&param, 0x00, sizeof(param));
				if ((wk->ik_type == WL_CIPHER_AES_GMAC) || (wk->ik_type == WL_CIPHER_AES_GMAC_256))
					keyType = KEY_TYPE_ID_GMAC;
				if (wk->ik_type == WL_CIPHER_AES_CMAC_256)
					keyType = KEY_TYPE_ID_CMAC;
				memcpy(&param.KeyMaterial[0], &wk->ik_keydata[0], wk->ik_keylen);
			}
#endif

			vmacSta_p->GN_igtk = (UINT8) wk->ik_keyix;
			memcpy(&vmacSta_p->igtk[0], &wk->ik_keydata[0], wk->ik_keylen);
			memcpy(&vmacSta_p->pn[0], &wk->ik_keytsc, 6);
			vmacSta_p->igtksaInstalled = wk->ik_type;

#ifdef CLIENT_SUPPORT
			if (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_CLNT_INFRA) {
				keyInfo |= ENCR_KEY_FLAG_STA_MODE;
				if ((pStaInfo = extStaDb_GetStaInfo(vmacSta_p,
								    (IEEEtypes_MacAddr_t *) GetParentStaBSSID((vmacEntry_p)->phyHwMacIndx),
								    STADB_UPDATE_AGINGTIME)) == NULL)
					return -EOPNOTSUPP;
				printk("WL_PARAM :::::: IGTK type=%d idx=%d len=%d\n", wk->ik_type, wk->ik_keyix, wk->ik_keylen);
				pStaInfo->Ieee80211wSta = TRUE;
			}
#endif
			return 0;
		} else
			printk("%s: Line %d\n", __FUNCTION__, __LINE__);

		return 0;
	}
#endif
	else
		return -ENOTSUPP;

	return 0;
}

int mwl_config_del_key(struct net_device *netdev, uint16_t key_idx, uint8_t * macaddr)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;

	extStaDb_SetRSNDataTrafficEnabled(vmacSta_p, (IEEEtypes_MacAddr_t *) macaddr, FALSE);


	return 0;
}

int mwl_config_get_seqnum(struct net_device *netdev, uint8_t * seqnum)
{
#ifdef CONFIG_IEEE80211W
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;

	printk("**pn-1: %x:%x:%x:%x:%x:%x **\n", vmacSta_p->pn[0],
	       vmacSta_p->pn[1], vmacSta_p->pn[2], vmacSta_p->pn[3], vmacSta_p->pn[4], vmacSta_p->pn[5]);

	memcpy(seqnum, vmacSta_p->pn, 6);
	printk("**param: %x:%x **\n", seqnum[0], seqnum[1]);
#endif
	return 0;
}

int mwl_config_get_ie(struct net_device *netdev, struct wlreq_ie *IEReq, UINT16 * ret_len)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	unsigned char ieBuf[256];
#ifdef MRVL_80211R
	UINT16 len;
	UINT8 reassoc;
#endif
#ifdef OWE_SUPPORT
	extStaDb_StaInfo_t *pStaInfo = extStaDb_GetStaInfo(vmacSta_p, (IEEEtypes_MacAddr_t *) & IEReq->macAddr, STADB_DONT_UPDATE_AGINGTIME);
#endif

	if (IEReq->IEtype == RSN_IEWPA2) {
		if (extStaDb_GetRSN_IE(vmacSta_p, &IEReq->macAddr, (UINT8 *) ieBuf) != STATE_SUCCESS)
			return -EFAULT;
		if ((ieBuf[1] > 0) && (ieBuf[1] < 254)) {
			IEReq->IELen = ieBuf[1] + 2;
			memcpy(IEReq->IE, ieBuf, IEReq->IELen);
			//*ret_len = IEReq.IE[1] + 2 + sizeof(IEReq.macAddr) + 2; /*2 bytes for IE type and IE len */
			*ret_len = IEReq->IE[1] + 2 + sizeof(IEReq->macAddr) + 2 + 1;	//one byte reassod added for 80211r
		} else {
			IEReq->IELen = 0;
			*ret_len = sizeof(IEReq->macAddr);
		}
#ifdef MRVL_80211R
		if (extStaDb_Get_11r_IEs(vmacSta_p, &IEReq->macAddr, (UINT8 *) ieBuf, &len, &reassoc) == STATE_SUCCESS) {
			if (len != 0) {
				memcpy(&IEReq->IE[IEReq->IELen], ieBuf, len);
				IEReq->IELen += len;
				*ret_len += len;
			}
			IEReq->reassoc = reassoc;
		}
#endif
#ifdef OWE_SUPPORT
		if (pStaInfo && pStaInfo->STA_DHIEBuf[1] > 0) {
			memcpy(&IEReq->IE[IEReq->IELen], &pStaInfo->STA_DHIEBuf[0], pStaInfo->STA_DHIEBuf[1] + 2);
			IEReq->IELen += pStaInfo->STA_DHIEBuf[1] + 2;
			*ret_len += pStaInfo->STA_DHIEBuf[1] + 2;
		}
#endif

		if (pStaInfo && pStaInfo->RsnxIE_Buf[1] > 0) {
			memcpy(&IEReq->IE[IEReq->IELen], &pStaInfo->RsnxIE_Buf[0], pStaInfo->RsnxIE_Buf[1] + 2);
			IEReq->IELen += pStaInfo->RsnxIE_Buf[1] + 2;
			*ret_len += pStaInfo->RsnxIE_Buf[1] + 2;
		}
	}
	return 0;
}

int mwl_config_set_wepkey(struct net_device *netdev, UINT8 * data, int key_len, UINT8 encode, UINT16 key_index)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	int rc = 0;

	if (encode & MWL_WEP_ENCODE_DISABLED) {
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
		mib->Privacy->RSNEnabled = 0;
		mib->RSNConfigWPA2->WPA2Enabled = 0;
		mib->RSNConfigWPA2->WPA2OnlyEnabled = 0;

		mib->AuthAlg->Enable = 1;
		mib->StationConfig->PrivOption = 1;
		mib->Privacy->PrivInvoked = 1;
		if (WL_FUN_SetPrivacyOption((void *)priv, 1)) {
		} else
			rc = -EIO;

		if (encode & MWL_WEP_ENCODE_OPEN) {
			if (key_index > 3)
				*(mib->mib_defaultkeyindex) = key_index = 0;
			else
				*(mib->mib_defaultkeyindex) = key_index;

			mib->AuthAlg->Type = 0;
			WL_FUN_SetAuthType((void *)priv, 0);
		}
		if (encode & MWL_WEP_ENCODE_RESTRICTED) {
			if (key_index > 3)
				*(mib->mib_defaultkeyindex) = key_index = 0;
			else
				*(mib->mib_defaultkeyindex) = key_index;

			mib->AuthAlg->Type = 1;
			WL_FUN_SetAuthType((void *)priv, 1);
		}
		if (key_len > 0)	//set open/restracted mode at [1] len=1
		{
			int wep_type = 1;
			UCHAR tmpWEPKey[16];	// 13 -> 16 to fix compile warning.

			if (key_len > 13)
				return -EINVAL;

			if (key_index > 3)
				*(mib->mib_defaultkeyindex) = key_index = 0;
			else
				*(mib->mib_defaultkeyindex) = key_index;

			if (key_len == 5) {
				wep_type = 1;
				mib->WepDefaultKeys[key_index].WepType = wep_type;

			}
			if (key_len == 13) {
				wep_type = 2;
				mib->WepDefaultKeys[key_index].WepType = wep_type;
			}
			memset(mib->WepDefaultKeys[key_index].WepDefaultKeyValue, 0, 13);
			memset(tmpWEPKey, 0, sizeof(tmpWEPKey));
			memcpy(tmpWEPKey, data, key_len);
			memcpy(mib->WepDefaultKeys[key_index].WepDefaultKeyValue, tmpWEPKey, key_len);
			if (WL_FUN_SetWEPKey((void *)priv, key_index, wep_type, tmpWEPKey)) {
				PRINT1(IOCTL, "mwl_drv_set_wepkey: length = %d index = %d type = %d\n", key_len, key_index, wep_type);
				PRINT1(IOCTL, "wep key = %x %x %x %x %x %x %x %x %x %x %x %x %x \n",
				       mib->WepDefaultKeys[key_index].WepDefaultKeyValue[0],
				       mib->WepDefaultKeys[key_index].WepDefaultKeyValue[1],
				       mib->WepDefaultKeys[key_index].WepDefaultKeyValue[2],
				       mib->WepDefaultKeys[key_index].WepDefaultKeyValue[3],
				       mib->WepDefaultKeys[key_index].WepDefaultKeyValue[4],
				       mib->WepDefaultKeys[key_index].WepDefaultKeyValue[5],
				       mib->WepDefaultKeys[key_index].WepDefaultKeyValue[6],
				       mib->WepDefaultKeys[key_index].WepDefaultKeyValue[7],
				       mib->WepDefaultKeys[key_index].WepDefaultKeyValue[8],
				       mib->WepDefaultKeys[key_index].WepDefaultKeyValue[9],
				       mib->WepDefaultKeys[key_index].WepDefaultKeyValue[10],
				       mib->WepDefaultKeys[key_index].WepDefaultKeyValue[11], mib->WepDefaultKeys[key_index].WepDefaultKeyValue[12]);
			} else
				rc = -EIO;
		}
	}

	return rc;
}
