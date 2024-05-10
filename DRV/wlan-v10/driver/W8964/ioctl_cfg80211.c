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

UINT8
keymgmt_wlCipher2AesMode(UINT8 ik_type)
{
	if (ik_type == WL_CIPHER_CCMP)
		return IEEEtypes_RSN_CIPHER_SUITE_CCMP;
	else if (ik_type == WL_CIPHER_GCMP)
		return IEEEtypes_RSN_CIPHER_SUITE_GCMP;
	else if (ik_type == WL_CIPHER_CCMP_256)
		return IEEEtypes_RSN_CIPHER_SUITE_CCMP_256;
	else if (ik_type == WL_CIPHER_GCMP_256)
		return IEEEtypes_RSN_CIPHER_SUITE_GCMP_256;
	else
		return IEEEtypes_RSN_CIPHER_SUITE_CCMP;
}

// This will be used to overwrite the channel # check which determines if this is a 2.4G or 5G frequency band.
// For 4.9 / 5G channels like CH 7 - 16.
extern BOOLEAN force_5G_channel;

int
mwl_config_commit(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;

#ifdef WFA_TKIP_NEGATIVE
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
#endif
	MIB_PHY_DSSS_TABLE *PhyDSSSTable = mib->PhyDSSSTable;
	MIB_802DOT11 *mibOperation = vmacSta_p->Mib802dot11;
	MIB_PHY_DSSS_TABLE *PhyDSSSTableOperation = mibOperation->PhyDSSSTable;
	DfsAp *me;
	DfsApDesc *dfsDesc_p = NULL;

	wlFwSetMutexGet(netdev);
#ifdef WFA_TKIP_NEGATIVE
	/* Perform checks on the validity of configuration combinations */
	/* Check the validity of the opmode and security mode combination */
	if ((*(mib->mib_wpaWpa2Mode) & 0x0F) == 1 && (*(mib->mib_ApMode) == AP_MODE_N_ONLY || *(mib->mib_ApMode) == AP_MODE_BandN || *(mib->mib_ApMode) == AP_MODE_GandN || *(mib->mib_ApMode) == AP_MODE_BandGandN || *(mib->mib_ApMode) == AP_MODE_2_4GHZ_11AC_MIXED || *(mib->mib_ApMode) == AP_MODE_5GHZ_Nand11AC || *(mib->mib_ApMode) == AP_MODE_AandN)) {	/*WPA-TKIP or WPA-AES mode */
		printk("HT mode not supported when WPA is enabled\n");
		WLSYSLOG(netdev, WLSYSLOG_CLASS_ALL,
			 "HT mode not supported when WPA is enabled\n");
		WLSNDEVT(netdev, IWEVCUSTOM,
			 (IEEEtypes_MacAddr_t *) & wlpptr->hwData.macAddr[0],
			 "HT mode not supported when WPA is enabled\n");
		wlFwSetMutexPut(netdev);
		return -EINVAL;
	}
	if ((mib->Privacy->PrivInvoked == 1) &&
	    (*(mib->mib_ApMode) == AP_MODE_N_ONLY
	     || *(mib->mib_ApMode) == AP_MODE_BandN
	     || *(mib->mib_ApMode) == AP_MODE_GandN
	     || *(mib->mib_ApMode) == AP_MODE_BandGandN
	     || *(mib->mib_ApMode) == AP_MODE_2_4GHZ_11AC_MIXED
	     || *(mib->mib_ApMode) == AP_MODE_5GHZ_Nand11AC
	     || *(mib->mib_ApMode) == AP_MODE_AandN)) {
		printk("HT mode not supported when WEP is enabled\n");
		WLSYSLOG(netdev, WLSYSLOG_CLASS_ALL,
			 "HT mode not supported when WEP is enabled\n");
		WLSNDEVT(netdev, IWEVCUSTOM,
			 (IEEEtypes_MacAddr_t *) & wlpptr->hwData.macAddr[0],
			 "HT mode not supported when WEP is enabled\n");
		wlFwSetMutexPut(netdev);
		return -EINVAL;
	}
#endif
	if (macMgmtMlme_DfsEnabled(vmacSta_p->dev)) {
		if (DfsPresentInNOL(netdev, PhyDSSSTable->CurrChan)) {
			printk("error: BW and channel combination not allowed Per NOL.\n");
			PhyDSSSTable->Chanflag.ChnlWidth =
				PhyDSSSTableOperation->Chanflag.ChnlWidth;
			wlFwSetMutexPut(netdev);
			return -EPERM;
		}
	}
	if (netdev->flags & IFF_RUNNING) {
		int ret;

		ret = wlpptr->wlreset(netdev);
		wlFwSetMutexPut(netdev);
		return ret;
	} else {
		me = wlpd_p->pdfsApMain;

		if ((me != NULL) && (wlpptr->master == NULL)) {
			dfsDesc_p = (DfsApDesc *) & me->dfsApDesc;
			if ((DfsGetCurrentState(me)) == DFS_STATE_SCAN) {
				int ret;
				/* Stops CAC timer */
				//DisarmCACTimer(me);
				//TimerRemove(&dfsDesc_p->CACTimer);
				//dev->flags |= IFF_RUNNING;
				ret = wlpptr->wlreset(netdev);
				wlFwSetMutexPut(netdev);
				return ret;
			} else {
				printk("*Failed wlconfig_commit netdev = %s \n",
				       netdev->name);
				wlFwSetMutexPut(netdev);
				return -EPERM;
			}
		} else {
			/* If not master device (if master device private wlpptr->master is always NULL). */
			if (wlpptr->master) {
				mib_Update();
				wlFwSetMutexPut(netdev);
				return 0;
			} else {
				printk("failed wlconfig_commit netdev = %s \n",
				       netdev->name);
				wlFwSetMutexPut(netdev);
				return -EPERM;
			}
		}
	}

	wlFwSetMutexPut(netdev);
	return 0;
}

int
mwl_config_set_channel(struct net_device *netdev, uint8_t channel)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	MIB_PHY_DSSS_TABLE *PhyDSSSTable = mib->PhyDSSSTable;
	UINT8 *mib_extSubCh_p = mib->mib_extSubCh;
	int rc = 0;
	extern void verify_chan_bw(MIB_PHY_DSSS_TABLE * PhyDSSSTable);

	if (priv->master) {
		printk("This parameter cannot be set to virtual interface %s,"
		       " please use %s instead!\n",
		       netdev->name, priv->master->name);
		rc = -EOPNOTSUPP;
		return rc;
	}

	if (channel) {
#ifdef MRVL_DFS
		/*Check if the target channel is a DFS channel and in NOL.
		 * If so, do not let the channel to change.
		 */
		if (DfsPresentInNOL(netdev, channel)) {
			PRINT1(IOCTL, "Target channel :%d is already in NOL\n",
			       channel);
			rc = -EOPNOTSUPP;
			return rc;
		}
#endif
		if (domainChannelValid
		    (channel,
		     force_5G_channel ? FREQ_BAND_5GHZ : (channel <=
							  14 ?
							  FREQ_BAND_2DOT4GHZ :
							  FREQ_BAND_5GHZ))) {
			PhyDSSSTable->CurrChan = channel;
			PhyDSSSTable->powinited = 0;
			/* Set 20MHz BW for channel 14,For ch165 and ch140 so as to avoid overlapping channel pairs */
			if (PhyDSSSTable->CurrChan == 14)
				PhyDSSSTable->Chanflag.ChnlWidth =
					CH_20_MHz_WIDTH;

			if (PhyDSSSTable->CurrChan >= 36)	//only apply for 5G
				verify_chan_bw(PhyDSSSTable);

			PhyDSSSTable->Chanflag.ExtChnlOffset =
				EXT_CH_ABOVE_CTRL_CH;

			if (((PhyDSSSTable->Chanflag.ChnlWidth ==
			      CH_40_MHz_WIDTH) ||
			     (PhyDSSSTable->Chanflag.ChnlWidth ==
			      CH_80_MHz_WIDTH) ||
			     (PhyDSSSTable->Chanflag.ChnlWidth == CH_AUTO_WIDTH
			      || (PhyDSSSTable->Chanflag.ChnlWidth ==
				  CH_160_MHz_WIDTH)))) {
				switch (PhyDSSSTable->CurrChan) {
				case 1:
				case 2:
				case 3:
				case 4:
					PhyDSSSTable->Chanflag.ExtChnlOffset =
						EXT_CH_ABOVE_CTRL_CH;
					break;
				case 5:	/* AutoBW: for CH5 let it be CH5-10, rather than CH5-1 */
					/* Now AutoBW use 5-1 instead of 5-9 for wifi cert convenience */
					/* if(*mib_extSubCh_p==0)
					   PhyDSSSTable->Chanflag.ExtChnlOffset=EXT_CH_ABOVE_CTRL_CH;
					   else if(*mib_extSubCh_p==1)
					   PhyDSSSTable->Chanflag.ExtChnlOffset=EXT_CH_BELOW_CTRL_CH;
					   else if(*mib_extSubCh_p==2)
					   PhyDSSSTable->Chanflag.ExtChnlOffset=EXT_CH_ABOVE_CTRL_CH;
					   break; */
				case 6:	/* AutoBW: for CH6 let it be CH6-2, rather than CH6-10 */
				case 7:	/* AutoBW: for CH7 let it be CH7-3, rather than CH7-11 */
				case 8:
				case 9:
				case 10:
					if (*mib_extSubCh_p == 0)
						PhyDSSSTable->Chanflag.
							ExtChnlOffset =
							EXT_CH_BELOW_CTRL_CH;
					else if (*mib_extSubCh_p == 1)
						PhyDSSSTable->Chanflag.
							ExtChnlOffset =
							EXT_CH_BELOW_CTRL_CH;
					else if (*mib_extSubCh_p == 2)
						PhyDSSSTable->Chanflag.
							ExtChnlOffset =
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
					if (*(mib->mib_regionCode) ==
					    DOMAIN_CODE_ALL) {
						PhyDSSSTable->Chanflag.
							ExtChnlOffset =
							EXT_CH_ABOVE_CTRL_CH;
					} else {
						PhyDSSSTable->Chanflag.
							ExtChnlOffset =
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
				}
			}
			if (force_5G_channel) {
				PhyDSSSTable->Chanflag.FreqBand =
					FREQ_BAND_5GHZ;
			} else {
				if (PhyDSSSTable->CurrChan <= 14)
					PhyDSSSTable->Chanflag.FreqBand =
						FREQ_BAND_2DOT4GHZ;
				else
					PhyDSSSTable->Chanflag.FreqBand =
						FREQ_BAND_5GHZ;
			}
		} else {
			PRINT1(IOCTL, "Invalid channel %d for domain %x\n",
			       channel, domainGetDomain());
			rc = -EOPNOTSUPP;
		}
	} else {
		printk("WARNING: wlset_freq is called with zero channel value!\n");
		rc = -EOPNOTSUPP;
	}

	WLDBG_EXIT(DBG_LEVEL_1);

	return rc;
}

int
mwl_config_set_bcninterval(struct net_device *netdev, uint16_t bcninterval)
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

int
mwl_config_set_essid(struct net_device *netdev, const char *ssid,
		     uint8_t ssid_len)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	memset(&(mib->StationConfig->DesiredSsId[0]), 0, 32);
	memcpy(&(mib->StationConfig->DesiredSsId[0]), ssid, ssid_len);

	return 0;
}

#ifdef WNM
void *
FindIEWithinIEs(UINT8 * data_p, UINT32 lenPacket, UINT8 attrib, UINT8 * OUI)
#else
static void *
FindIEWithinIEs(UINT8 * data_p, UINT32 lenPacket, UINT8 attrib, UINT8 * OUI)
#endif				//WNM
{
	UINT32 lenOffset = 0;

	while (lenOffset <= lenPacket) {
		if (*(IEEEtypes_ElementId_t *) data_p == attrib) {
			if (attrib == PROPRIETARY_IE) {
				if ((OUI[0] == data_p[2]) &&
				    (OUI[1] == data_p[3]) &&
				    (OUI[2] == data_p[4]) &&
				    (OUI[3] == data_p[5]))
					return data_p;
			} else
				return data_p;
		}

		lenOffset += (2 + *((UINT8 *) (data_p + 1)));
		data_p += (2 + *((UINT8 *) (data_p + 1)));
	}
	return NULL;
}

extern BOOLEAN RsnBIPcap(IEEEtypes_RSN_IE_WPA2_t * ie_p, UINT8 * mfpc,
			 UINT8 * mfpr);
int
mwl_config_set_appie(struct net_device *netdev, struct wlreq_set_appie *appie)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	WSC_COMB_IE_t APWSCIE;
	UINT16 ieType = 0;
	UINT8 *rsn_ie = NULL;
#ifdef MRVL_80211R
	UINT8 *md_ie = NULL;
#endif

	memset(&APWSCIE, 0, sizeof(WSC_COMB_IE_t));

	if (appie == NULL)
		return -EINVAL;

	if (appie->appBufLen == 8) {
		memset(&vmacSta_p->thisbeaconIEs, 0, sizeof(WSC_BeaconIEs_t));
		memset(&vmacSta_p->thisprobeRespIEs, 0,
		       sizeof(WSC_ProbeRespIEs_t));
		vmacSta_p->WPSOn = 0;
	}

	switch (appie->appFrmType) {
	case WL_APPIE_IETYPE_RSN:
	case WL_OPTIE_BEACON_INCL_RSN:
	case WL_OPTIE_ASSOC_INCL_RSN:
		memset(vmacSta_p->RsnIE, 0, sizeof(IEEEtypes_RSN_IE_WPA2_t));

		rsn_ie = FindIEWithinIEs(appie->appBuf, appie->appBufLen,
					 RSN_IEWPA2, NULL);
#ifdef MRVL_80211R
		md_ie = FindIEWithinIEs(appie->appBuf, appie->appBufLen, MD_IE,
					NULL);
#endif
		if (rsn_ie != NULL) {
			IEEEtypes_RSN_IE_WPA2_t *pRSNE = vmacSta_p->RsnIE;
#ifdef CONFIG_IEEE80211W
			parsing_rsn_ie((UINT8 *) rsn_ie, vmacSta_p->RsnIE,
				       &vmacSta_p->ieee80211w,
				       &vmacSta_p->ieee80211wRequired);
#else
			parsing_rsn_ie((UINT8 *) rsn_ie, vmacSta_p->RsnIE);
#endif
			if (pRSNE->AuthKeyCnt[0] == 1) {
				/* relocate RsnCap, PMKIDCnt, GrpMgtKeyCipher, PMKIDList if AuthKeyCnt is 1. */
				memmove(pRSNE->AuthKeyList1, pRSNE->RsnCap, 24);
			}
			memset(vmacSta_p->RsnIE, 0,
			       sizeof(IEEEtypes_RSN_IE_WPA2_t));
			memcpy(vmacSta_p->RsnIE, rsn_ie, appie->appBufLen);
		} else {
			memset(vmacSta_p->RsnIE, 0,
			       sizeof(IEEEtypes_RSN_IE_WPA2_t));
#ifdef CONFIG_IEEE80211W
			vmacSta_p->ieee80211w = 0;
			vmacSta_p->ieee80211wRequired = 0;
#endif
		}
#ifdef MRVL_80211R
		if (md_ie != NULL)
			memcpy(vmacSta_p->MDIE, md_ie, 5);
		else
			memset(vmacSta_p->MDIE, 0, 5);
#endif
		vmacSta_p->RsnIESetByHost = 1;

		return 0;

	case WL_APPIE_FRAMETYPE_BEACON:
#ifdef WNM
		{
#else
		if (appie->appBufLen > 8) {
#endif //WNM
#if defined(CONFIG_HS2)
			IEEEtypes_INTERWORKING_Element_t *pIW;
			IEEEtypes_HS_INDICATION_Element_t *pHS2;
			IEEEtypes_Extended_Cap_Element_t *pEC;
			IEEEtypes_P2P_Element_t *pP2P;
			UINT8 oui[4] = { 0x50, 0x6f, 0x9a, 0x10 };
			UINT8 oui_p2p[4] = { 0x50, 0x6f, 0x9a, 0x9 };
#endif

			ieType = 0;
			APWSCIE.beaconIE.Len = appie->appBufLen;
			memcpy(&APWSCIE.beaconIE.WSCData[0], appie->appBuf,
			       appie->appBufLen);
			memcpy(&vmacSta_p->thisbeaconIEs, &APWSCIE.beaconIE,
			       sizeof(WSC_BeaconIEs_t));
			vmacSta_p->WPSOn = 1;
			//_hexdump(vmacSta_p->dev->name, &vmacSta_p->thisbeaconIEs, vmacSta_p->thisbeaconIEs.Len + 2);
			//HS2.0 todo 
			//need to decode the IEs to set different mibs
			//include *(mib->mib_intraBSS), *(mib->mib_HS2Indicator)
			// *(mib->mib_InterworkingActive) = 0;  /* 0: Disable, 1:enable */
			// *(mib->mib_AdvertismentProtocolActive) = 0;  /* 0: Disable, 1:enable */
			// *(mib->mib_RoamingConsortiumActive) = 0;     /* 0: Disable, 1:enable */
			// *(mib->mib_EmergencyAlertIDActive) = 0;      /* 0: Disable, 1:enable */
#if defined(CONFIG_HS2)
			pIW = FindIEWithinIEs(vmacSta_p->thisbeaconIEs.WSCData,
					      vmacSta_p->thisbeaconIEs.Len,
					      INTERWORKING, NULL);
			pEC = FindIEWithinIEs(vmacSta_p->thisbeaconIEs.WSCData,
					      vmacSta_p->thisbeaconIEs.Len,
					      EXT_CAP_IE, NULL);
			pHS2 = FindIEWithinIEs(vmacSta_p->thisbeaconIEs.WSCData,
					       vmacSta_p->thisbeaconIEs.Len,
					       HS_INDICATION, oui);
			pP2P = FindIEWithinIEs(vmacSta_p->thisbeaconIEs.WSCData,
					       vmacSta_p->thisbeaconIEs.Len,
					       HS_INDICATION, oui_p2p);

			if (pP2P && (pP2P->P2P_mgmt_type == 0x0a)) {
				if (pP2P->P2P_mgmt_bitmap & 0x1)	//P2P managable        
					printk("%s: P2P managable",
					       vmacSta_p->dev->name);
				if (pP2P->P2P_mgmt_bitmap & 0x2)	//P2P cross connect permit
					printk("%s: P2P cross connect permitted\n", vmacSta_p->dev->name);
				else
					printk("%s: P2P cross connect not permitted\n", vmacSta_p->dev->name);
			}
			if (pHS2) {
				vmacSta_p->hotspot = 1;
				vmacSta_p->dgaf_disable = pHS2->dgaf_disable;
				printk("%s: Downstream Group-Addressed Forwarding %s\n", vmacSta_p->dev->name, vmacSta_p->dgaf_disable ? "Disabled" : "Enabled");
			}
			if (pIW) {
				//_hexdump("Interworking", pIW, pIW->Len+2);
				vmacSta_p->interworking = 1;
				vmacSta_p->access_network_type =
					pIW->AccessNetworkType;
				vmacSta_p->internet = pIW->Internet;
				vmacSta_p->asra = pIW->ASRA;
				vmacSta_p->esr = pIW->ESR;
				vmacSta_p->uesa = pIW->UESA;
				vmacSta_p->venue_info_set =
					(pIW->Len == 9) ? 1 : 0;
				if (vmacSta_p->venue_info_set) {
					vmacSta_p->venue_group = pIW->Body[0];
					vmacSta_p->venue_type = pIW->Body[1];
				}
				if (pIW->Len > 3)
					vmacSta_p->hessidset = 1;
				else
					vmacSta_p->hessidset = 0;
				memcpy(vmacSta_p->hessid,
				       &pIW->Body[(pIW->Len == 9) ? 2 : 0], 6);
				//*(mib->mib_intraBSS) = ((pIW->AccessNetworkType==ACCESSNETWORKTYPE_CHARGEABLE_PUBLIC_NETWORK)||(pIW->AccessNetworkType==ACCESSNETWORKTYPE_FREE_PUBLIC_NETWORK))  ? 0:1;
				printk("%s: L2 Traffic Inspection and Filtering %s\n", vmacSta_p->dev->name, *(mib->mib_intraBSS) ? "Disabled" : "Enabled");
			}
			if (pEC) {
				//_hexdump("Extended Cap", pEC, pEC->Len+2);
				vmacSta_p->proxyarp = pEC->cap[0] & 0x10;
				vmacSta_p->qosmap =
					(pEC->Len > 4) ? pEC->cap[3] & 0x1 : 0;
				vmacSta_p->tdls =
					(pEC->Len > 4) ? pEC->cap[3] : 0;

				if (vmacSta_p->tdls & 0x40)
					printk("%s: TDLS Prohibited\n",
					       vmacSta_p->dev->name);
				/* 0x40- TDLS Prohibited */
				if (vmacSta_p->tdls & 0x80)
					printk("%s: TDLS Channel Switching Prohibited\n", vmacSta_p->dev->name);
				/* 0x80- TDLS Channel Switching Prohibited */
			}
#endif
		}
		break;

	case WL_APPIE_FRAMETYPE_PROBE_RESP:
#ifdef WNM
		{
#else
		if (appie->appBufLen > 8) {
#endif //WNM
			ieType = 1;
			APWSCIE.probeRespIE.Len = appie->appBufLen;
			memcpy(&APWSCIE.probeRespIE.WSCData[0],
			       &appie->appBuf[0], appie->appBufLen);
			memcpy(&vmacSta_p->thisprobeRespIEs,
			       &APWSCIE.probeRespIE,
			       sizeof(WSC_ProbeRespIEs_t));
			vmacSta_p->WPSOn = 1;
		}
		break;

	case WL_AAPIE_FRAMETYPE_ASSOC_RESPONSE:
		break;

	case WL_OPTIE_PROBE_RESP_INCL_RSN:
		return 0;

#ifdef MRVL_WPS_CLIENT
	case WL_APPIE_FRAMETYPE_PROBE_REQUEST:
		if ((appie->appBufLen > 0) && (appie->appBuf != NULL)) {
			IEEEtypes_InfoElementHdr_t *pIW;
			UINT8 *pos = &priv->wpsProbeRequestIe;
			UINT8 oui[4] = { 0x00, 0x50, 0xf2, 0x04 };

			WLDBG_DUMP_DATA(DBG_LEVEL_0, (void *)appie->appBuf,
					appie->appBufLen);

			pIW = FindIEWithinIEs(appie->appBuf, appie->appBufLen,
					      PROPRIETARY_IE, oui);

			memset(priv->wpsProbeRequestIe, 0,
			       sizeof(priv->wpsProbeRequestIe));
			priv->wpsProbeRequestIeLen = 0;
			/* copy intwerworking first because FW will treate ext cap as the last IE */
			if (pIW != NULL) {
				memcpy(priv->wpsProbeRequestIe,
				       pIW,
				       pIW->Len +
				       sizeof(IEEEtypes_InfoElementHdr_t));
				priv->wpsProbeRequestIeLen +=
					pIW->Len +
					sizeof(IEEEtypes_InfoElementHdr_t);
				pos += priv->wpsProbeRequestIeLen;
			}
		} else {
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
		memset(&vmacSta_p->thisprobeRespIEs, 0,
		       sizeof(WSC_ProbeRespIEs_t));
		ieType = 1;
		if (wlFwSetWscIE(netdev, ieType, &APWSCIE))
			WLDBG_EXIT_INFO(DBG_LEVEL_1, "Failed setting WSC IE");

		vmacSta_p->WPSOn = 0;
		return 0;
	}

	if (wlFwSetWscIE(netdev, ieType, &APWSCIE))
		WLDBG_EXIT_INFO(DBG_LEVEL_1, "Failed setting WSC IE");

	return 0;
}

extern extStaDb_Status_e extStaDb_RemoveSta(vmacApInfo_t * vmac_p,
					    IEEEtypes_MacAddr_t * Addr_p);
int
mwl_config_send_mlme(struct net_device *netdev, struct wlreq_mlme *mlme)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;

	switch (mlme->im_op) {
		extern extStaDb_Status_e extStaDb_RemoveSta(vmacApInfo_t *
							    vmac_p,
							    IEEEtypes_MacAddr_t
							    * Addr_p);
	case WL_MLME_DEAUTH:
		macMgmtMlme_SendDeauthenticateMsg(vmacSta_p, &mlme->im_macaddr,
						  0, mlme->im_reason);
		if (vmacSta_p->wtp_info.mac_mode != WTP_MAC_MODE_SPLITMAC) {
			//RemoveSta when non-splitmac mode
			extStaDb_RemoveSta(vmacSta_p,
					   (IEEEtypes_MacAddr_t *) & mlme->
					   im_macaddr);
		}
		break;
	case WL_MLME_DISASSOC:
		macMgmtMlme_SendDisassociateMsg(vmacSta_p, &mlme->im_macaddr, 0,
						mlme->im_reason);
		break;
#ifdef WTP_SUPPORT
	case WL_MLME_AUTHORIZE:
		macMgmtMlme_set_sta_authorized(vmacSta_p, &mlme->im_macaddr);
		break;

	case WL_MLME_ASSOC:
		macMgmtMlme_set_sta_associated(vmacSta_p, &mlme->im_macaddr,
					       mlme->Aid,
					       (PeerInfo_t *) & mlme->PeerInfo,
					       mlme->QosInfo, mlme->isQosSta,
					       mlme->rsnSta,
					       (UINT8 *) & mlme->rsnIE);
		break;

	case WL_MLME_DELSTA:
		macMgmtMlme_del_sta_entry(vmacSta_p, &mlme->im_macaddr);
		break;
#endif
#ifdef MRVL_80211R
	case WL_MLME_SET_ASSOC:
	case WL_MLME_SET_REASSOC:
		macMgmtMlme_SendAssocMsg(vmacSta_p,
					 (IEEEtypes_MacAddr_t *) & mlme->
					 im_macaddr, mlme->im_optie,
					 mlme->im_optie_len);
		break;
	case WL_MLME_SET_AUTH:
		macMgmtMlme_SendAuthenticateMsg(vmacSta_p,
						(IEEEtypes_MacAddr_t *) & mlme->
						im_macaddr, mlme->im_seq,
						mlme->im_reason, mlme->im_optie,
						mlme->im_optie_len);
		break;
#endif

	default:
		return -EOPNOTSUPP;
	}
	return 0;
}

extern void getTkipStaKeyMaterial(extStaDb_StaInfo_t * StaInfo_p,
				  TKIP_TYPE_KEY * pKey);
int
mwl_config_set_key(struct net_device *netdev, struct wlreq_key *wk)
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
		if ((vmacEntry_p =
		     sme_GetParentVMacEntry(vmacSta_p->VMacEntry.
					    phyHwMacIndx)) == NULL)
			return -EFAULT;
	}

	if (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_CLNT_INFRA) {
		pStaSecurityMibs = sme_GetStaSecurityMibsPtr(vmacEntry_p);
		pKeyMgmtInfoSta = sme_GetKeyMgmtInfoStaPtr(vmacEntry_p);
		if (pStaSecurityMibs == NULL || pKeyMgmtInfoSta == NULL)
			return -EINVAL;
	}
#endif //MRVL_WPS_CLIENT

	if (wk->ik_keyix == WL_KEYIX_NONE) {
		if (extStaDb_SetRSNPwkAndDataTraffic(vmacSta_p,
						     vmacSta_p->VMacEntry.
						     modeOfService ==
						     VMAC_MODE_CLNT_INFRA
						     ? (IEEEtypes_MacAddr_t *)
						     GetParentStaBSSID((vmacEntry_p)->phyHwMacIndx) : (IEEEtypes_MacAddr_t *) wk->ik_macaddr, &wk->ik_keydata[0], (UINT32 *) & wk->ik_keydata[16], (UINT32 *) & wk->ik_keydata[24]) != STATE_SUCCESS)
			return -EOPNOTSUPP;

		if (extStaDb_SetPairwiseTSC(vmacSta_p,
					    vmacSta_p->VMacEntry.
					    modeOfService ==
					    VMAC_MODE_CLNT_INFRA
					    ? (IEEEtypes_MacAddr_t *)
					    GetParentStaBSSID((vmacEntry_p)->
							      phyHwMacIndx)
					    : (IEEEtypes_MacAddr_t *) wk->
					    ik_macaddr, 0,
					    0x0001) != STATE_SUCCESS)
			return -EOPNOTSUPP;

		if ((pStaInfo = extStaDb_GetStaInfo(vmacSta_p,
						    vmacSta_p->VMacEntry.
						    modeOfService ==
						    VMAC_MODE_CLNT_INFRA
						    ? (IEEEtypes_MacAddr_t *)
						    GetParentStaBSSID((vmacEntry_p)->phyHwMacIndx) : (IEEEtypes_MacAddr_t *) wk->ik_macaddr, STADB_UPDATE_AGINGTIME)) == NULL)
			return -EOPNOTSUPP;
#ifdef CLIENT_SUPPORT
		if (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_CLNT_INFRA) {
			udelay(100);
			if (!pStaSecurityMibs->mib_RSNConfigWPA2_p->
			    WPA2OnlyEnabled &&
			    !pStaSecurityMibs->mib_RSNConfigWPA2_p->
			    WPA2Enabled) {
				//WPA
				AddRSN_IE_TO(pStaSecurityMibs->thisStaRsnIE_p,
					     (IEEEtypes_RSN_IE_t *) (&pStaInfo->
								     keyMgmtStateInfo.
								     RsnIEBuf
								     [0]));
				mdelay(100);
				if (pStaSecurityMibs->
				    mib_RSNConfigUnicastCiphers_p->
				    UnicastCipher[3] == 2) {
					// TKIP
					wlFwSetWpaTkipMode_STA(netdev,
							       (UINT8 *) &
							       pStaInfo->Addr);
				} else if ((pStaSecurityMibs->
					    mib_RSNConfigUnicastCiphers_p->
					    UnicastCipher[3] == 4)) {
					// AES
					wlFwSetWpaAesMode_STA(netdev,
							      (UINT8 *) &
							      pStaInfo->Addr,
							      pStaSecurityMibs->
							      mib_RSNConfigUnicastCiphers_p->
							      UnicastCipher[3]);
				}
			} else {
				// WPA2
				AddRSN_IEWPA2_TO(pStaSecurityMibs->
						 thisStaRsnIEWPA2_p,
						 (IEEEtypes_RSN_IE_WPA2_t
						  *) (&pStaInfo->
						      keyMgmtStateInfo.
						      RsnIEBuf[0]));
				mdelay(100);
				if (isAes4RsnValid
				    (pStaSecurityMibs->
				     mib_RSNConfigWPA2UnicastCiphers_p->
				     UnicastCipher[3])) {
					// AES
					wlFwSetWpaAesMode_STA(netdev,
							      (UINT8 *) &
							      pStaInfo->Addr,
							      pStaSecurityMibs->
							      mib_RSNConfigWPA2UnicastCiphers_p->
							      UnicastCipher[3]);
				} else {
					// TKIP
					//Not sure if this is correct setting for firmware in this case????
					wlFwSetWpaTkipMode_STA(netdev,
							       (UINT8 *) &
							       pStaInfo->Addr);
				}
			}
			mdelay(100);
			wlFwSetWpaWpa2PWK_STA(netdev, pStaInfo);
			printk("WL_PARAM_SETKEYS :::::: Send PTK to FW type=%d idx=%d len=%d\n", wk->ik_type, wk->ik_keyix, wk->ik_keylen);
			if (pKeyMgmtInfoSta)
				pKeyMgmtInfoSta->pKeyData->
					RSNDataTrafficEnabled = 1;
			if (pStaInfo)
				pStaInfo->keyMgmtStateInfo.
					RSNDataTrafficEnabled = 1;
			return 0;
		} else
#endif
		{
			if (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_AP) {
				if (wk->ik_type == WL_CIPHER_TKIP)
					wlFwSetWpaTkipMode(netdev,
							   pStaInfo->Addr);
				else
					wlFwSetWpaAesMode(netdev,
							  pStaInfo->Addr,
							  wk->ik_type);

				wlFwSetWpaWpa2PWK(netdev, pStaInfo);
				return 0;
			}
		}
	} else if ((0 < wk->ik_keyix) && (wk->ik_keyix < 4)) {
		if (wk->ik_type == WL_CIPHER_TKIP) {
			if (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_AP) {
				memcpy(mib1->mib_MrvlRSN_GrpKey->EncryptKey,
				       &wk->ik_keydata[0], 16);
				memcpy(mib1->mib_MrvlRSN_GrpKey->TxMICKey,
				       &wk->ik_keydata[16], 8);
				memcpy(mib1->mib_MrvlRSN_GrpKey->RxMICKey,
				       &wk->ik_keydata[24], 8);
				mib1->mib_MrvlRSN_GrpKey->g_IV16 = 0x0001;
				mib1->mib_MrvlRSN_GrpKey->g_IV32 = 0;
				mib1->mib_MrvlRSN_GrpKey->g_KeyIndex =
					(UINT8) wk->ik_keyix;
				wlFwSetWpaTkipGroupK(netdev,
						     mib1->mib_MrvlRSN_GrpKey->
						     g_KeyIndex);
				//need to update shadow mib, when directly modify run-time mib.
				memcpy(mib->mib_MrvlRSN_GrpKey,
				       mib1->mib_MrvlRSN_GrpKey,
				       sizeof(MRVL_MIB_RSN_GRP_KEY));
			}
#ifdef CLIENT_SUPPORT
			else if (vmacSta_p->VMacEntry.modeOfService ==
				 VMAC_MODE_CLNT_INFRA) {
				ENCR_TKIPSEQCNT TkipTsc;
				memcpy(mib_MrvlRSN_GrpKeyUr1
				       [vmacEntry_p->phyHwMacIndx].EncryptKey,
				       &wk->ik_keydata[0], TK_SIZE);
				memcpy(mib_MrvlRSN_GrpKeyUr1
				       [vmacEntry_p->phyHwMacIndx].TxMICKey,
				       &wk->ik_keydata[16], 8);
				memcpy(mib_MrvlRSN_GrpKeyUr1
				       [vmacEntry_p->phyHwMacIndx].RxMICKey,
				       &wk->ik_keydata[24], 8);
				mib_MrvlRSN_GrpKeyUr1[vmacEntry_p->
						      phyHwMacIndx].g_IV16 =
					0x0001;
				mib_MrvlRSN_GrpKeyUr1[vmacEntry_p->
						      phyHwMacIndx].g_IV32 = 0;

				TkipTsc.low =
					mib_MrvlRSN_GrpKeyUr1[vmacEntry_p->
							      phyHwMacIndx].
					g_IV16;
				TkipTsc.high =
					mib_MrvlRSN_GrpKeyUr1[vmacEntry_p->
							      phyHwMacIndx].
					g_IV32;

				{
					UINT8 *macStaAddr_p =
						GetParentStaBSSID(vmacEntry_p->
								  phyHwMacIndx);

					if (macStaAddr_p)
						wlFwSetWpaTkipGroupK_STA(netdev,
									 macStaAddr_p,
									 &mib_MrvlRSN_GrpKeyUr1
									 [vmacEntry_p->
									  phyHwMacIndx].
									 EncryptKey
									 [0],
									 TK_SIZE,
									 (UINT8
									  *) &
									 mib_MrvlRSN_GrpKeyUr1
									 [vmacEntry_p->
									  phyHwMacIndx].
									 RxMICKey,
									 MIC_KEY_LENGTH,
									 (UINT8
									  *) &
									 mib_MrvlRSN_GrpKeyUr1
									 [vmacEntry_p->
									  phyHwMacIndx].
									 TxMICKey,
									 MIC_KEY_LENGTH,
									 TkipTsc,
									 wk->
									 ik_keyix);
				}

				if (pKeyMgmtInfoSta)
					pKeyMgmtInfoSta->pKeyData->RSNSecured =
						1;
			}
#endif
			return 0;
		} else if ((wk->ik_type == WL_CIPHER_CCMP) ||
			   (wk->ik_type == WL_CIPHER_GCMP) ||
			   (wk->ik_type == WL_CIPHER_CCMP_256) ||
			   (wk->ik_type == WL_CIPHER_GCMP_256)) {
			if (wk->ik_keylen > 32)
				wk->ik_keylen = 32;

			if (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_AP) {
				memcpy(mib1->mib_MrvlRSN_GrpKey->EncryptKey,
				       &wk->ik_keydata[0], wk->ik_keylen);
				mib1->mib_MrvlRSN_GrpKey->g_KeyIndex =
					(UINT8) wk->ik_keyix;

				wlFwSetWpaAesGroupK(netdev,
						    mib1->mib_MrvlRSN_GrpKey->
						    g_KeyIndex,
						    keymgmt_wlCipher2AesMode
						    (wk->ik_type));

				//need to update shadow mib, when directly modify run-time mib.
				memcpy(mib->mib_MrvlRSN_GrpKey,
				       mib1->mib_MrvlRSN_GrpKey,
				       sizeof(MRVL_MIB_RSN_GRP_KEY));
			}
#ifdef CLIENT_SUPPORT
			else if (vmacSta_p->VMacEntry.modeOfService ==
				 VMAC_MODE_CLNT_INFRA) {
				memcpy(mib_MrvlRSN_GrpKeyUr1
				       [vmacEntry_p->phyHwMacIndx].EncryptKey,
				       &wk->ik_keydata[0], wk->ik_keylen);
				wlFwSetWpaAesGroupK_STA(netdev,
							GetParentStaBSSID
							(vmacEntry_p->
							 phyHwMacIndx),
							&mib_MrvlRSN_GrpKeyUr1
							[vmacEntry_p->
							 phyHwMacIndx].
							EncryptKey[0],
							wk->ik_keyix,
							keymgmt_wlCipher2AesMode
							(wk->ik_type));
				printk("WL_PARAM_SETKEYS :::::: Send GTK to FW type=%d idx=%d len=%d\n", wk->ik_type, wk->ik_keyix, wk->ik_keylen);
			}
#endif
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
		    wk->ik_type == WL_CIPHER_AES_GMAC ||
		    wk->ik_type == WL_CIPHER_AES_GMAC_256 ||
		    wk->ik_type == WL_CIPHER_AES_CMAC_256) {
			vmacSta_p->GN_igtk = (UINT8) wk->ik_keyix;
			memcpy(&vmacSta_p->igtk[0], &wk->ik_keydata[0],
			       wk->ik_keylen);
			memcpy(&vmacSta_p->pn[0], &wk->ik_keytsc, 6);
			vmacSta_p->igtksaInstalled = wk->ik_type;

#ifdef CLIENT_SUPPORT
			if (vmacSta_p->VMacEntry.modeOfService ==
			    VMAC_MODE_CLNT_INFRA) {
				if ((pStaInfo =
				     extStaDb_GetStaInfo(vmacSta_p,
							 (IEEEtypes_MacAddr_t *)
							 GetParentStaBSSID((vmacEntry_p)->phyHwMacIndx), STADB_UPDATE_AGINGTIME)) == NULL)
					return -EOPNOTSUPP;

				printk("WL_PARAM_SETKEYS :::::: Send IGTK type=%d idx=%d len=%d\n", wk->ik_type, wk->ik_keyix, wk->ik_keylen);
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

int
mwl_config_del_key(struct net_device *netdev, uint16_t key_idx,
		   uint8_t * macaddr)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;

	extStaDb_SetRSNDataTrafficEnabled(vmacSta_p,
					  (IEEEtypes_MacAddr_t *) macaddr,
					  FALSE);

	return 0;
}

int
mwl_config_get_seqnum(struct net_device *netdev, uint8_t * seqnum)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;

	printk("**pn-1: %x:%x:%x:%x:%x:%x **\n", vmacSta_p->pn[0],
	       vmacSta_p->pn[1],
	       vmacSta_p->pn[2],
	       vmacSta_p->pn[3], vmacSta_p->pn[4], vmacSta_p->pn[5]);

	memcpy(seqnum, vmacSta_p->pn, 6);
	printk("**param: %x:%x **\n", seqnum[0], seqnum[1]);
	return 0;
}

int
mwl_config_get_ie(struct net_device *netdev, struct wlreq_ie *IEReq,
		  UINT16 * ret_len)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	unsigned char ieBuf[256];
#ifdef MRVL_80211R
	UINT16 len = 0;
	UINT8 reassoc = 0;
#endif

	if (IEReq->IEtype == RSN_IEWPA2) {
		if (extStaDb_GetRSN_IE
		    (vmacSta_p, &IEReq->macAddr,
		     (UINT8 *) ieBuf) != STATE_SUCCESS)
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
		if (extStaDb_Get_11r_IEs
		    (vmacSta_p, &IEReq->macAddr, (UINT8 *) ieBuf, &len,
		     &reassoc) == STATE_SUCCESS) {
			if (len != 0) {
				memcpy(&IEReq->IE[IEReq->IELen], ieBuf, len);
				IEReq->IELen += len;
				*ret_len += len;
			}
			IEReq->reassoc = reassoc;
		}
#endif
#ifdef OWE_SUPPORT
		{
			extStaDb_StaInfo_t *pStaInfo;
			pStaInfo =
				extStaDb_GetStaInfo(vmacSta_p,
						    (IEEEtypes_MacAddr_t *) &
						    IEReq->macAddr, 0);
			if (pStaInfo && pStaInfo->STA_DHIEBuf[1] > 0) {
				memcpy(&IEReq->IE[IEReq->IELen],
				       pStaInfo->STA_DHIEBuf,
				       pStaInfo->STA_DHIEBuf[1] + 2);
				IEReq->IELen += (pStaInfo->STA_DHIEBuf[1] + 2);
				*ret_len += (pStaInfo->STA_DHIEBuf[1] + 2);
			}
		}
#endif /* OWE_SUPPORT */
	}
	return 0;
}
