/** @file drv_config.c
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2006-2020 NXP
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

/* Description:  This file implements driver configuration related functions. */

#include "ap8xLnxVer.h"
#include "ap8xLnxWlLog.h"
#include "wldebug.h"
#include "bcngen.h"
#include "mlmeApi.h"
#include "macmgmtap.h"
#include "keyMgmtSta.h"
#include "ap8xLnxIntf.h"
#include "ap8xLnxApi.h"
#include "ap8xLnxAcnt.h"
#include "ap8xLnxFwcmd.h"
#include "ap8xLnxFwdl.h"
#include "domain.h"
#include "wds.h"
#include "cfg80211.h"
#include "vendor.h"
#include "hostcmd.h"
#include "drv_config.h"
#include "wlApi.h"
#include "wl.h"
#include "wlFun.h"
#include "wldebug.h"
#include "linkmgt.h"
#include "ewb_hash.h"
#include "ap8xLnxMPrxy.h"
#include "wl_mib.h"
#include "wlvmac.h"
#include "hostcmd.h"
#include "macMgmtMlme.h"
#include "ap8xLnxFwcmd.h"
#include "ap8xLnxMug.h"

#define WPAHEX64

extern UINT32 vht_cap;
extern UINT32 ie192_version;

#ifdef CLIENT_SUPPORT
static MRVL_SCAN_ENTRY siteSurveyEntry;
#endif

static IEEEtypes_MacAddr_t bcastMacAddr =
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
extern void HexStringToHexDigi(char *outHexData, char *inHexString, u16 Len);
extern int IsHexKey(char *keyStr);
extern SINT32 linkMgtStop(UINT8 phyIndex);
extern int rateChecked(int rate, int mode);
extern UINT16 getPhyRate(dbRateInfo_t * pRateTbl);
#ifdef POWERSAVE_OFFLOAD
extern int wlFwGetTIM(struct net_device *netdev);
extern int wlFwSetTIM(struct net_device *netdev, u_int16_t AID, u_int32_t Set);
extern int wlFwSetPowerSaveStation(struct net_device *netdev,
				   u_int8_t StationPowerSave);
#endif

int
mwl_drv_get_version(struct net_device *netdev, char *version)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);

	uint8_t *pVer = (UINT8 *) & priv->hwData.fwReleaseNumber;
#ifdef MV_CPU_BE
	sprintf(version, "Driver version: %s, Firmware version: %d.%d.%d.%d\n",
		DRV_VERSION, *pVer, *(pVer + 1), *(pVer + 2), *(pVer + 3));
#else
	sprintf(version, "Driver version: %s, Firmware version: %d.%d.%d.%d\n",
		DRV_VERSION, *(pVer + 3), *(pVer + 2), *(pVer + 1), *pVer);
#endif

	return 0;
}

int
mwl_drv_commit(struct net_device *netdev)
{
	struct net_device *dev = netdev;
	struct wlprivate *wlpptr = mwl_netdev_get_priv(netdev);
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

	WLDBG_ENTER_INFO(DBG_LEVEL_1, "");
#ifdef WFA_TKIP_NEGATIVE
	/* Perform checks on the validity of configuration combinations */
	/* Check the validity of the opmode and security mode combination */
	if ((*(mib->mib_wpaWpa2Mode) & 0x0F) == 1 &&
	    (*(mib->mib_ApMode) == AP_MODE_N_ONLY
	     || *(mib->mib_ApMode) == AP_MODE_BandN
	     || *(mib->mib_ApMode) == AP_MODE_GandN
	     || *(mib->mib_ApMode) == AP_MODE_BandGandN
#ifdef SOC_W8864
	     || *(mib->mib_ApMode) == AP_MODE_2_4GHZ_11AC_MIXED
	     || *(mib->mib_ApMode) == AP_MODE_5GHZ_Nand11AC
#endif
	     || *(mib->mib_ApMode) == AP_MODE_AandN)) {	/*WPA-TKIP or WPA-AES mode */
		printk("HT mode not supported when WPA is enabled\n");
		WLSYSLOG(dev, WLSYSLOG_CLASS_ALL,
			 "HT mode not supported when WPA is enabled\n");
		WLSNDEVT(dev, IWEVCUSTOM,
			 (IEEEtypes_MacAddr_t *) & wlpptr->hwData.macAddr[0],
			 "HT mode not supported when WPA is enabled\n");
		return -EINVAL;
	}
	if ((mib->Privacy->PrivInvoked == 1) &&
	    (*(mib->mib_ApMode) == AP_MODE_N_ONLY
	     || *(mib->mib_ApMode) == AP_MODE_BandN
	     || *(mib->mib_ApMode) == AP_MODE_GandN
	     || *(mib->mib_ApMode) == AP_MODE_BandGandN
#ifdef SOC_W8864
	     || *(mib->mib_ApMode) == AP_MODE_2_4GHZ_11AC_MIXED
	     || *(mib->mib_ApMode) == AP_MODE_5GHZ_Nand11AC
#endif
	     || *(mib->mib_ApMode) == AP_MODE_AandN)) {
		printk("HT mode not supported when WEP is enabled\n");
		WLSYSLOG(dev, WLSYSLOG_CLASS_ALL,
			 "HT mode not supported when WEP is enabled\n");
		WLSNDEVT(dev, IWEVCUSTOM,
			 (IEEEtypes_MacAddr_t *) & wlpptr->hwData.macAddr[0],
			 "HT mode not supported when WEP is enabled\n");
		return -EINVAL;
	}
#endif
	if (macMgmtMlme_DfsEnabled(vmacSta_p->dev)) {
		if (DfsPresentInNOL(dev, PhyDSSSTable->CurrChan)) {
			printk("error: BW and channel combination not allowed Per NOL.\n");
			PhyDSSSTable->Chanflag.ChnlWidth =
				PhyDSSSTableOperation->Chanflag.ChnlWidth;
			return -EPERM;
		}
	}
	if (dev->flags & IFF_RUNNING) {
		return (wlpptr->wlreset(dev));
	} else {
		me = wlpd_p->pdfsApMain;

		if ((me != NULL) && (wlpptr->master == NULL)) {
			dfsDesc_p = (DfsApDesc *) & me->dfsApDesc;
			if ((DfsGetCurrentState(me)) == DFS_STATE_SCAN) {
				/* Stops CAC timer */
				//DisarmCACTimer(me);
				//TimerRemove(&dfsDesc_p->CACTimer);
				//dev->flags |= IFF_RUNNING;
				return (wlpptr->wlreset(dev));
			} else {
				printk("*Failed wlconfig_commit netdev = %s \n",
				       dev->name);
				return -EPERM;
			}
		} else {
			/* If not master device (if master device private wlpptr->master is always NULL). */
			if (wlpptr->master) {
				mib_Update();
				return 0;
			} else {
				printk("failed wlconfig_commit netdev = %s \n",
				       dev->name);
				return -EPERM;

			}
		}
	}

	WLDBG_EXIT(DBG_LEVEL_1);
	return 0;
}

int
mwl_drv_set_opmode(struct net_device *netdev, uint8_t opmode)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	*(mib->mib_ApMode) = opmode;
#ifdef BRS_SUPPORT
	wlset_rateSupport(mib);

#endif

	return 0;
}

int
mwl_drv_get_opmode(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return *(mib->mib_ApMode);
}

int
mwl_drv_set_stamode(struct net_device *netdev, uint8_t stamode)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	vmacEntry_t *vmacEntry_p = NULL;

	if (stamode < 0) {
		return EOPNOTSUPP;
	}
	*(mib->mib_STAMode) = (unsigned char)stamode;
	vmacEntry_p = sme_GetParentVMacEntry(vmacSta_p->VMacEntry.phyHwMacIndx);
	wlset_mibChannel(vmacEntry_p, *(mib->mib_STAMode));
	return 0;
}

int
mwl_drv_get_stamode(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return *(mib->mib_STAMode);
}

extern UINT8 keymgmt_wlCipher2AesMode(UINT8 ik_type);
int
mwl_drv_set_key(struct net_device *netdev, uint8_t key_type,
		uint16_t key_idx, uint8_t key_len, uint8_t key_flag,
		uint8_t * macaddr, uint64_t key_recv_seq, uint64_t key_xmit_seq,
		uint8_t * key, uint8_t * key_pn)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	MIB_802DOT11 *mib1 = vmacSta_p->Mib802dot11;

#ifndef CLIENT_SUPPORT
#define GetParentStaBSSID(x) NULL
#endif
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
#endif //MRVL_WPS_CLIENT

#ifdef MRVL_WPS_CLIENT
	if (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_CLNT_INFRA) {
		pStaSecurityMibs = sme_GetStaSecurityMibsPtr(vmacEntry_p);
		pKeyMgmtInfoSta = sme_GetKeyMgmtInfoStaPtr(vmacEntry_p);
		if (pStaSecurityMibs == NULL || pKeyMgmtInfoSta == NULL)
			return -EFAULT;
	}
#endif //MRVL_WPS_CLIENT

	if (key_idx == WL_KEYIX_NONE) {
		if (extStaDb_SetRSNPwkAndDataTraffic(vmacSta_p,
						     vmacSta_p->VMacEntry.
						     modeOfService ==
						     VMAC_MODE_CLNT_INFRA
						     ? (IEEEtypes_MacAddr_t *)
						     GetParentStaBSSID((vmacEntry_p)->phyHwMacIndx) : (IEEEtypes_MacAddr_t *) macaddr, &key[0], (UINT32 *) & key[16], (UINT32 *) & key[24]) != STATE_SUCCESS) {
			return -EOPNOTSUPP;
		}
		if (extStaDb_SetPairwiseTSC(vmacSta_p,
					    vmacSta_p->VMacEntry.
					    modeOfService ==
					    VMAC_MODE_CLNT_INFRA
					    ? (IEEEtypes_MacAddr_t *)
					    GetParentStaBSSID((vmacEntry_p)->
							      phyHwMacIndx)
					    : (IEEEtypes_MacAddr_t *) macaddr,
					    0, 0x0001) != STATE_SUCCESS) {
			return -EOPNOTSUPP;
		}

		if ((pStaInfo = extStaDb_GetStaInfo(vmacSta_p,
						    vmacSta_p->VMacEntry.
						    modeOfService ==
						    VMAC_MODE_CLNT_INFRA
						    ? (IEEEtypes_MacAddr_t *)
						    GetParentStaBSSID((vmacEntry_p)->phyHwMacIndx) : (IEEEtypes_MacAddr_t *) macaddr, 1)) == NULL) {
			return -EOPNOTSUPP;
		}
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

			wlFwSetWpaWpa2PWK_STA(netdev, pStaInfo);
			printk("WL_PARAM_SETKEYS :::::: Send PTK to FW type=%d idx=%d len=%d\n", key_type, key_idx, key_len);
			if (pKeyMgmtInfoSta)
				pKeyMgmtInfoSta->pKeyData->
					RSNDataTrafficEnabled = 1;
			if (pStaInfo)
				pStaInfo->keyMgmtStateInfo.
					RSNDataTrafficEnabled = 1;
		} else
#endif
		{
			if (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_AP) {
				if (key_type == WL_CIPHER_TKIP)
					wlFwSetWpaTkipMode(netdev,
							   pStaInfo->Addr);
				else
					wlFwSetWpaAesMode(netdev,
							  pStaInfo->Addr,
							  key_type);

				wlFwSetWpaWpa2PWK(netdev, pStaInfo);
			}
		}
	} else if ((0 < key_idx) && (key_idx < 4)) {
		if (key_type == WL_CIPHER_TKIP) {
			if (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_AP) {
				memcpy(mib1->mib_MrvlRSN_GrpKey->EncryptKey,
				       &key[0], 16);
				memcpy(mib1->mib_MrvlRSN_GrpKey->TxMICKey,
				       &key[16], 8);
				memcpy(mib1->mib_MrvlRSN_GrpKey->RxMICKey,
				       &key[24], 8);
				mib1->mib_MrvlRSN_GrpKey->g_IV16 = 0x0001;
				mib1->mib_MrvlRSN_GrpKey->g_IV32 = 0;
				mib1->mib_MrvlRSN_GrpKey->g_KeyIndex =
					(UINT8) key_idx;
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
				       &key[0], TK_SIZE);
				memcpy(mib_MrvlRSN_GrpKeyUr1
				       [vmacEntry_p->phyHwMacIndx].TxMICKey,
				       &key[16], 8);
				memcpy(mib_MrvlRSN_GrpKeyUr1
				       [vmacEntry_p->phyHwMacIndx].RxMICKey,
				       &key[24], 8);
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

				wlFwSetWpaTkipGroupK_STA(netdev,
							 GetParentStaBSSID
							 (vmacEntry_p->
							  phyHwMacIndx),
							 &mib_MrvlRSN_GrpKeyUr1
							 [vmacEntry_p->
							  phyHwMacIndx].
							 EncryptKey[0], TK_SIZE,
							 (UINT8 *) &
							 mib_MrvlRSN_GrpKeyUr1
							 [vmacEntry_p->
							  phyHwMacIndx].
							 RxMICKey,
							 MIC_KEY_LENGTH,
							 (UINT8 *) &
							 mib_MrvlRSN_GrpKeyUr1
							 [vmacEntry_p->
							  phyHwMacIndx].
							 TxMICKey,
							 MIC_KEY_LENGTH,
							 TkipTsc, key_idx);

				if (pKeyMgmtInfoSta)
					pKeyMgmtInfoSta->pKeyData->RSNSecured =
						1;
			}
#endif
		} else if ((key_type == WL_CIPHER_CCMP) ||
			   (key_type == WL_CIPHER_GCMP) ||
			   (key_type == WL_CIPHER_CCMP_256) ||
			   (key_type == WL_CIPHER_GCMP_256)) {
			if (key_len > 32)
				key_len = 32;

			if (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_AP) {
				memcpy(mib1->mib_MrvlRSN_GrpKey->EncryptKey,
				       &key[0], key_len);
				mib1->mib_MrvlRSN_GrpKey->g_KeyIndex =
					(UINT8) key_idx;

				wlFwSetWpaAesGroupK(netdev,
						    mib1->mib_MrvlRSN_GrpKey->
						    g_KeyIndex,
						    keymgmt_wlCipher2AesMode
						    (key_type));

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
				       &key[0], key_len);
				wlFwSetWpaAesGroupK_STA(netdev,
							GetParentStaBSSID
							(vmacEntry_p->
							 phyHwMacIndx),
							&mib_MrvlRSN_GrpKeyUr1
							[vmacEntry_p->
							 phyHwMacIndx].
							EncryptKey[0], key_idx,
							keymgmt_wlCipher2AesMode
							(key_type));
				printk("WL_PARAM_SETKEYS :::::: Send GTK to FW type=%d idx=%d len=%d\n", key_type, key_idx, key_len);
			}
#endif
		} else {
			return -ENOTSUPP;
		}
	}
#ifdef CONFIG_IEEE80211W
	else if ((3 < key_idx) && (key_idx < 6)) {
		if (key_len > 32)
			key_len = 32;
		vmacSta_p->igtksaInstalled = 0;
		if (key_type == WL_CIPHER_IGTK ||
		    key_type == WL_CIPHER_AES_GMAC ||
		    key_type == WL_CIPHER_AES_GMAC_256 ||
		    key_type == WL_CIPHER_AES_CMAC_256) {
			vmacSta_p->GN_igtk = (UINT8) key_idx;
			memcpy(&vmacSta_p->igtk[0], &key[0], key_len);
			memcpy(&vmacSta_p->pn[0], &key_xmit_seq, 6);
			vmacSta_p->igtksaInstalled = key_type;

#ifdef CLIENT_SUPPORT
			if (vmacSta_p->VMacEntry.modeOfService ==
			    VMAC_MODE_CLNT_INFRA) {
				if ((pStaInfo =
				     extStaDb_GetStaInfo(vmacSta_p,
							 (IEEEtypes_MacAddr_t *)
							 GetParentStaBSSID((vmacEntry_p)->phyHwMacIndx), 1)) == NULL) {
					return -ENOTSUPP;
				}
				printk("WL_PARAM_SETKEYS :::::: Send IGTK type=%d idx=%d len=%d\n", key_type, key_idx, key_len);
				pStaInfo->Ieee80211wSta = TRUE;
			}
#endif
		} else {
			printk("%s: Line %d\n", __FUNCTION__, __LINE__);
		}
	}
#endif
	else {
		return -ENOTSUPP;
	}

	return 0;
}

int
mwl_drv_del_key(struct net_device *netdev, uint16_t key_idx, uint8_t * macaddr)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;

	extStaDb_SetRSNDataTrafficEnabled(vmacSta_p,
					  (IEEEtypes_MacAddr_t *) macaddr,
					  FALSE);

	return 0;
}

extern vmacEntry_t *sme_GetParentVMacEntry(UINT8 phyMacIndx);
extern STA_SYSTEM_MIBS *sme_GetStaSystemMibsPtr(vmacEntry_t * vmacEntry_p);
int
mwl_drv_set_wpawpa2mode(struct net_device *netdev, uint8_t wpawpa2mode)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	uint8_t mode = wpawpa2mode;

#ifdef MRVL_WPS_CLIENT
	vmacEntry_t *vmacEntry_p = NULL;
	STA_SYSTEM_MIBS *pStaSystemMibs;
#endif
	if ((mode & 0x0F) < 0 || (mode & 0x0F) > 0xA)
		return -EOPNOTSUPP;
#if 0				/* WFA_TKIP_NEGATIVE */
	/* Check the validity of security mode and operating mode combination */
	/* WPA-TKIP and WPA-AES not allowed when HT modes are enabled */
	if (((mode & 0xFF) == 1) &&
	    (*(mib->mib_ApMode) == AP_MODE_N_ONLY
	     || *(mib->mib_ApMode) == AP_MODE_BandN
	     || *(mib->mib_ApMode) == AP_MODE_GandN
	     || *(mib->mib_ApMode) == AP_MODE_BandGandN
	     || *(mib->mib_ApMode) == AP_MODE_AandN)) {
		printk("This Security mode not supported when HT mode is enabled\n");

		WLSYSLOG(dev, WLSYSLOG_CLASS_ALL,
			 "This Security mode not supported when HT mode is enabled\n");
		WLSNDEVT(dev, IWEVCUSTOM,
			 (IEEEtypes_MacAddr_t *) & priv->hwData.macAddr[0],
			 "This Security mode not supported when HT mode is enabled\n");

		return -EOPNOTSUPP;
	}
#endif
	*(mib->mib_wpaWpa2Mode) = mode;

#ifdef MRVL_WPS_CLIENT
	if ((vmacEntry_p =
	     sme_GetParentVMacEntry(vmacSta_p->VMacEntry.phyHwMacIndx)) !=
	    NULL) {
		pStaSystemMibs = sme_GetStaSystemMibsPtr(vmacEntry_p);
		if (pStaSystemMibs != NULL) {
			pStaSystemMibs->mib_StaCfg_p->wpawpa2Mode = mode;
		}
	}
#endif

#ifdef MRVL_WSC
	if ((mode == 0) || ((mode & 0x0F) == 0))
#else
	if (mode == 0)
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

		if ((mode & 0x0F) == 4 || (mode & 0x0F) == 6)
			mib->RSNConfigAuthSuites->AuthSuites[3] = 0x01;	// Auth8021x
		else
			mib->RSNConfigAuthSuites->AuthSuites[3] = 0x02;	// AuthPSK

		mib->RSNConfigAuthSuites->Enabled = TRUE;

		*(mib->mib_cipherSuite) = 2;

		if ((mode & 0x0F) == 2 || (mode & 0x0F) == 5 ||
		    (mode & 0x0F) == 9 || (mode & 0x0F) == 0x0A) {
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

			if ((mode & 0x0F) == 5)
				mib->WPA2AuthSuites->AuthSuites[3] = 0x01;	// Auth8021x
			else if ((mode & 0x0F) == 9)
				mib->WPA2AuthSuites->AuthSuites[3] = 0x08;	// AuthSAE
			else if ((mode & 0x0F) == 0xA)
				mib->WPA2AuthSuites->AuthSuites[3] = 0x12;	// AuthOWE
			else
				mib->WPA2AuthSuites->AuthSuites[3] = 0x02;	// AuthPSK

			mib->WPA2AuthSuites->Enabled = TRUE;

			*(mib->mib_cipherSuite) = 4;

		} else if ((mode & 0x0F) == 7 || (mode & 0x0F) == 8) {
			mib->RSNConfigWPA2->WPA2Enabled = 1;
			mib->RSNConfigWPA2->WPA2OnlyEnabled = 1;

			mib->WPA2AuthSuites->AuthSuites[0] = 0x00;
			mib->WPA2AuthSuites->AuthSuites[1] = 0x0F;
			mib->WPA2AuthSuites->AuthSuites[2] = 0xAC;

			if ((mode & 0x0F) == 7) {
				*(mib->mib_cipherSuite) =
					IEEEtypes_RSN_CIPHER_SUITE_GCMP;
				mib->WPA2AuthSuites->AuthSuites[3] = 11;	// SuiteB
			} else {
				*(mib->mib_cipherSuite) =
					IEEEtypes_RSN_CIPHER_SUITE_GCMP_256;
				mib->WPA2AuthSuites->AuthSuites[3] = 12;	// SuiteB_192
			}

			mib->WPA2AuthSuites->Enabled = TRUE;
		} else if ((mode & 0x0F) == 7 && (mode & 0x0F) == 8) {
			mib->RSNConfigWPA2->WPA2Enabled = 1;
			mib->RSNConfigWPA2->WPA2OnlyEnabled = 1;

			mib->WPA2AuthSuites->AuthSuites[0] = 0x00;
			mib->WPA2AuthSuites->AuthSuites[1] = 0x0F;
			mib->WPA2AuthSuites->AuthSuites[2] = 0xAC;

			if ((mode & 0x0F) == 8) {
				*(mib->mib_cipherSuite) = 8;	//gcmp128
				mib->WPA2AuthSuites->AuthSuites[3] = 11;	// SuiteB
			} else {
				*(mib->mib_cipherSuite) = 9;	//gcmp256
				mib->WPA2AuthSuites->AuthSuites[3] = 12;	// SuiteB_192
			}
			mib->WPA2AuthSuites->Enabled = TRUE;
		} else if ((mode & 0x0F) == 3 || (mode & 0x0F) == 6) {
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

			if ((mode & 0x0F) == 6)
				mib->WPA2AuthSuites->AuthSuites[3] = 0x01;	// Auth8021x
			else
				mib->WPA2AuthSuites->AuthSuites[3] = 0x02;	// AuthPSK

			mib->WPA2AuthSuites->Enabled = TRUE;

			*(mib->mib_cipherSuite) = 4;
		}
	}

	PRINT1(IOCTL, "mib->Privacy->RSNEnabled %d\n",
	       mib->Privacy->RSNEnabled);
	PRINT1(IOCTL, "mib->RSNConfigWPA2->WPA2Enabled %d\n",
	       mib->RSNConfigWPA2->WPA2Enabled);
	PRINT1(IOCTL, "mib->RSNConfigWPA2->WPA2OnlyEnabled %d\n",
	       mib->RSNConfigWPA2->WPA2OnlyEnabled);
	PRINT1(IOCTL, "mib->mib_wpaWpa2Mode %x\n", *(mib->mib_wpaWpa2Mode));

	return 0;
}

int
mwl_drv_get_wpawpa2mode(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return *(mib->mib_wpaWpa2Mode);
}

int
mwl_drv_set_passphrase(struct net_device *netdev, uint8_t mode,
		       char *passphrase, uint8_t len)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	if (mode == 0) {	/* wpa */
#ifdef WPAHEX64
		if ((len <= 7) || (len > 64))
#else
		if ((len <= 7) || (len > 63))
#endif
		{
			return -EFAULT;
		}
#ifdef WPAHEX64
		if (len == 64) {
			if (!IsHexKey(passphrase)) {
				return -EFAULT;
			}
			memset(mib->RSNConfig->PSKValue, 0, 32);
			HexStringToHexDigi(mib->RSNConfig->PSKValue, passphrase,
					   32);
			memset(mib->RSNConfig->PSKPassPhrase, 0, 65);
			memcpy(mib->RSNConfig->PSKPassPhrase, passphrase, len);

			*(mib->mib_WPAPSKValueEnabled) = 1;
			return 0;
		}
#endif

		memset(mib->RSNConfig->PSKPassPhrase, 0, 65);
		memcpy(mib->RSNConfig->PSKPassPhrase, passphrase, len);
	} else if (mode == 1) {	/*wpa2 */
#ifdef WPAHEX64
		if ((len <= 7) || (len > 64))
#else
		if ((len <= 7) || (len > 63))
#endif
		{
			return -EFAULT;
		}
#ifdef WPAHEX64
		if (len == 64) {
			if (!IsHexKey(passphrase)) {
				return -EFAULT;
			}
			memset(mib->RSNConfigWPA2->PSKValue, 0, 32);
			HexStringToHexDigi(mib->RSNConfigWPA2->PSKValue,
					   passphrase, 32);
			memset(mib->RSNConfigWPA2->PSKPassPhrase, 0, 65);
			memcpy(mib->RSNConfigWPA2->PSKPassPhrase, passphrase,
			       len);

			*(mib->mib_WPA2PSKValueEnabled) = 1;
			return 0;
		}
#endif

		memset(mib->RSNConfigWPA2->PSKPassPhrase, 0, 65);
		memcpy(mib->RSNConfigWPA2->PSKPassPhrase, passphrase, len);
	} else {
		return -EFAULT;
	}

	return 0;
}

int
mwl_drv_get_passphrase(struct net_device *netdev, char *passphrase)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	sprintf(passphrase, "wpa: %s, wpa2: %s\n",
		mib->RSNConfig->PSKPassPhrase,
		mib->RSNConfigWPA2->PSKPassPhrase);
	return 0;
}

int
mwl_drv_set_ciphersuite(struct net_device *netdev, uint8_t wpamode,
			uint8_t cipher)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	uint8_t mode;

	mode = wpamode;

	if (mode == 0) {	/* wpa */
		if (cipher == WL_CIPHER_TKIP) {
			*(mib->mib_cipherSuite) = 2;

			mib->RSNConfig->MulticastCipher[0] = 0x00;
			mib->RSNConfig->MulticastCipher[1] = 0x50;
			mib->RSNConfig->MulticastCipher[2] = 0xF2;
			mib->RSNConfig->MulticastCipher[3] = 0x02;	// TKIP

			mib->UnicastCiphers->UnicastCipher[0] = 0x00;
			mib->UnicastCiphers->UnicastCipher[1] = 0x50;
			mib->UnicastCiphers->UnicastCipher[2] = 0xF2;
			mib->UnicastCiphers->UnicastCipher[3] = 0x02;	// TKIP
			mib->UnicastCiphers->Enabled = TRUE;
		} else if (cipher == WL_CIPHER_CCMP) {
			/* If mixed mode only allow WPA TKIP for multicast and unicast. */
			if (mib->RSNConfigWPA2->WPA2Enabled &&
			    !mib->RSNConfigWPA2->WPA2OnlyEnabled) {
				*(mib->mib_cipherSuite) = 4;

				mib->RSNConfig->MulticastCipher[0] = 0x00;
				mib->RSNConfig->MulticastCipher[1] = 0x50;
				mib->RSNConfig->MulticastCipher[2] = 0xF2;
				mib->RSNConfig->MulticastCipher[3] = 0x02;	// TKIP

				mib->UnicastCiphers->UnicastCipher[0] = 0x00;
				mib->UnicastCiphers->UnicastCipher[1] = 0x50;
				mib->UnicastCiphers->UnicastCipher[2] = 0xF2;
				mib->UnicastCiphers->UnicastCipher[3] = 0x02;	// TKIP
				mib->UnicastCiphers->Enabled = TRUE;
			} else {
				*(mib->mib_cipherSuite) = 4;

				mib->RSNConfig->MulticastCipher[0] = 0x00;
				mib->RSNConfig->MulticastCipher[1] = 0x50;
				mib->RSNConfig->MulticastCipher[2] = 0xF2;
				mib->RSNConfig->MulticastCipher[3] = 0x04;	// AES

				mib->UnicastCiphers->UnicastCipher[0] = 0x00;
				mib->UnicastCiphers->UnicastCipher[1] = 0x50;
				mib->UnicastCiphers->UnicastCipher[2] = 0xF2;
				mib->UnicastCiphers->UnicastCipher[3] = 0x04;	// AES
				mib->UnicastCiphers->Enabled = TRUE;
			}
		} else {
			return -EFAULT;
		}

		PRINT1(IOCTL,
		       "mib->RSNConfig->MulticastCipher: %02x %02x %02x %02x\n",
		       mib->RSNConfig->MulticastCipher[0],
		       mib->RSNConfig->MulticastCipher[1],
		       mib->RSNConfig->MulticastCipher[2],
		       mib->RSNConfig->MulticastCipher[3]);
		PRINT1(IOCTL,
		       "mib->RSNConfig->UnicastCiphers: %02x %02x %02x %02x\n",
		       mib->UnicastCiphers->UnicastCipher[0],
		       mib->UnicastCiphers->UnicastCipher[1],
		       mib->UnicastCiphers->UnicastCipher[2],
		       mib->UnicastCiphers->UnicastCipher[3]);
		PRINT1(IOCTL, "mib->UnicastCiphers->Enabled %d\n",
		       mib->UnicastCiphers->Enabled);
	} else if (mode == 1) {	/*wpa2 */
		if (cipher == WL_CIPHER_CCMP) {
			/* If mixed mode only allow WPA2 TKIP for multicast. */
			if (mib->RSNConfigWPA2->WPA2Enabled &&
			    !mib->RSNConfigWPA2->WPA2OnlyEnabled) {
				mib->RSNConfigWPA2->MulticastCipher[0] = 0x00;
				mib->RSNConfigWPA2->MulticastCipher[1] = 0x0F;
				mib->RSNConfigWPA2->MulticastCipher[2] = 0xAC;
				mib->RSNConfigWPA2->MulticastCipher[3] =
					IEEEtypes_RSN_CIPHER_SUITE_TKIP;
			} else {
				mib->RSNConfigWPA2->MulticastCipher[0] = 0x00;
				mib->RSNConfigWPA2->MulticastCipher[1] = 0x0F;
				mib->RSNConfigWPA2->MulticastCipher[2] = 0xAC;
				mib->RSNConfigWPA2->MulticastCipher[3] =
					IEEEtypes_RSN_CIPHER_SUITE_CCMP;
			}

			*(mib->mib_cipherSuite) =
				IEEEtypes_RSN_CIPHER_SUITE_CCMP;

			mib->WPA2UnicastCiphers->UnicastCipher[0] = 0x00;
			mib->WPA2UnicastCiphers->UnicastCipher[1] = 0x0F;
			mib->WPA2UnicastCiphers->UnicastCipher[2] = 0xAC;
			mib->WPA2UnicastCiphers->UnicastCipher[3] =
				IEEEtypes_RSN_CIPHER_SUITE_CCMP;
			mib->WPA2UnicastCiphers->Enabled = TRUE;
		} else if (cipher == WL_CIPHER_CCMP_256) {
			mib->RSNConfigWPA2->MulticastCipher[0] = 0x00;
			mib->RSNConfigWPA2->MulticastCipher[1] = 0x0F;
			mib->RSNConfigWPA2->MulticastCipher[2] = 0xAC;
			mib->RSNConfigWPA2->MulticastCipher[3] = IEEEtypes_RSN_CIPHER_SUITE_CCMP_256;	// CCMP-256

			*(mib->mib_cipherSuite) =
				IEEEtypes_RSN_CIPHER_SUITE_CCMP_256;

			mib->WPA2UnicastCiphers->UnicastCipher[0] = 0x00;
			mib->WPA2UnicastCiphers->UnicastCipher[1] = 0x0F;
			mib->WPA2UnicastCiphers->UnicastCipher[2] = 0xAC;
			mib->WPA2UnicastCiphers->UnicastCipher[3] = IEEEtypes_RSN_CIPHER_SUITE_CCMP_256;	// CCMP-256
			mib->WPA2UnicastCiphers->Enabled = TRUE;
		} else if (cipher == WL_CIPHER_GCMP) {
			mib->RSNConfigWPA2->MulticastCipher[0] = 0x00;
			mib->RSNConfigWPA2->MulticastCipher[1] = 0x0F;
			mib->RSNConfigWPA2->MulticastCipher[2] = 0xAC;
			mib->RSNConfigWPA2->MulticastCipher[3] = IEEEtypes_RSN_CIPHER_SUITE_GCMP;	// GCMP-128

			*(mib->mib_cipherSuite) =
				IEEEtypes_RSN_CIPHER_SUITE_GCMP;

			mib->WPA2UnicastCiphers->UnicastCipher[0] = 0x00;
			mib->WPA2UnicastCiphers->UnicastCipher[1] = 0x0F;
			mib->WPA2UnicastCiphers->UnicastCipher[2] = 0xAC;
			mib->WPA2UnicastCiphers->UnicastCipher[3] = IEEEtypes_RSN_CIPHER_SUITE_GCMP;	// GCMP-128
			mib->WPA2UnicastCiphers->Enabled = TRUE;
		} else if (cipher == WL_CIPHER_GCMP_256) {
			mib->RSNConfigWPA2->MulticastCipher[0] = 0x00;
			mib->RSNConfigWPA2->MulticastCipher[1] = 0x0F;
			mib->RSNConfigWPA2->MulticastCipher[2] = 0xAC;
			mib->RSNConfigWPA2->MulticastCipher[3] = IEEEtypes_RSN_CIPHER_SUITE_GCMP_256;	// GCMP-256

			*(mib->mib_cipherSuite) =
				IEEEtypes_RSN_CIPHER_SUITE_GCMP_256;

			mib->WPA2UnicastCiphers->UnicastCipher[0] = 0x00;
			mib->WPA2UnicastCiphers->UnicastCipher[1] = 0x0F;
			mib->WPA2UnicastCiphers->UnicastCipher[2] = 0xAC;
			mib->WPA2UnicastCiphers->UnicastCipher[3] = IEEEtypes_RSN_CIPHER_SUITE_GCMP_256;	// GCMP-256
			mib->WPA2UnicastCiphers->Enabled = TRUE;
		} else if (cipher == WL_CIPHER_TKIP) {
			mib->RSNConfigWPA2->MulticastCipher[0] = 0x00;
			mib->RSNConfigWPA2->MulticastCipher[1] = 0x0F;
			mib->RSNConfigWPA2->MulticastCipher[2] = 0xAC;
			mib->RSNConfigWPA2->MulticastCipher[3] = 0x02;	// TKIP

			*(mib->mib_cipherSuite) = 2;

			mib->WPA2UnicastCiphers->UnicastCipher[0] = 0x00;
			mib->WPA2UnicastCiphers->UnicastCipher[1] = 0x0F;
			mib->WPA2UnicastCiphers->UnicastCipher[2] = 0xAC;
			mib->WPA2UnicastCiphers->UnicastCipher[3] = 0x02;	// TKIP
			mib->WPA2UnicastCiphers->Enabled = TRUE;
		} else {
			return -EFAULT;
		}

		PRINT1(IOCTL,
		       "mib->RSNConfigWPA2->MulticastCipher: %02x %02x %02x %02x\n",
		       mib->RSNConfigWPA2->MulticastCipher[0],
		       mib->RSNConfigWPA2->MulticastCipher[1],
		       mib->RSNConfigWPA2->MulticastCipher[2],
		       mib->RSNConfigWPA2->MulticastCipher[3]);
		PRINT1(IOCTL,
		       "mib->WPA2UnicastCiphers->UnicastCiphers: %02x %02x %02x %02x\n",
		       mib->WPA2UnicastCiphers->UnicastCipher[0],
		       mib->WPA2UnicastCiphers->UnicastCipher[1],
		       mib->WPA2UnicastCiphers->UnicastCipher[2],
		       mib->WPA2UnicastCiphers->UnicastCipher[3]);
		PRINT1(IOCTL, "mib->WPA2UnicastCiphers->Enabled %d\n",
		       mib->WPA2UnicastCiphers->Enabled);
	} else {
		return -EFAULT;
	}

	PRINT1(IOCTL, "*(mib->mib_cipherSuite): %d\n", *(mib->mib_cipherSuite));
	return 0;
}

int
mwl_drv_get_ciphersuite(struct net_device *netdev, char *ciphersuite)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	sprintf(ciphersuite, "\n");
	if (mib->RSNConfigWPA2->WPA2Enabled &&
	    !mib->RSNConfigWPA2->WPA2OnlyEnabled) {
		strcat(ciphersuite, "Mixed Mode  ");
		if (mib->UnicastCiphers->UnicastCipher[3] == 0x02)
			strcat(ciphersuite, "wpa:tkip  ");
		else if (mib->UnicastCiphers->UnicastCipher[3] == 0x04)
			strcat(ciphersuite, "wpa:aes  ");
		else
			strcat(ciphersuite, "wpa:  ciphersuite undefined ");

		if (mib->WPA2UnicastCiphers->UnicastCipher[3] == 0x04)
			strcat(ciphersuite, "wpa2:aes  ");
		else if (mib->WPA2UnicastCiphers->UnicastCipher[3] == 0x02)
			strcat(ciphersuite, "wpa2:tkip  ");
		else
			strcat(ciphersuite, "wpa2:ciphersuite undefined  ");

		if (mib->RSNConfig->MulticastCipher[3] == 0x02)
			strcat(ciphersuite, "multicast:tkip \n");
		else if (mib->RSNConfig->MulticastCipher[3] == 0x04)
			strcat(ciphersuite, "multicast:aes \n");
		else
			strcat(ciphersuite,
			       "multicast:ciphersuite undefined \n");
	} else {
		if ((mib->UnicastCiphers->UnicastCipher[3] == 0x02) &&
		    (mib->RSNConfig->MulticastCipher[3] == 0x02))
			strcat(ciphersuite, "wpa:tkip  ");
		else if ((mib->UnicastCiphers->UnicastCipher[3] == 0x04) &&
			 (mib->RSNConfig->MulticastCipher[3] == 0x04))
			strcat(ciphersuite, "wpa:aes  ");
		else
			strcat(ciphersuite, "wpa:ciphersuite undefined  ");

		if ((mib->WPA2UnicastCiphers->UnicastCipher[3] == 0x04) &&
		    (mib->RSNConfigWPA2->MulticastCipher[3] == 0x04))
			strcat(ciphersuite, "wpa2:aes \n");
		else if ((mib->WPA2UnicastCiphers->UnicastCipher[3] == 0x02) &&
			 (mib->RSNConfigWPA2->MulticastCipher[3] == 0x02))
			strcat(ciphersuite, "wpa2:tkip \n");
		else
			strcat(ciphersuite, "wpa2:ciphersuite undefined \n");
	}

	return 0;
}

int
mwl_drv_set_wmm(struct net_device *netdev, uint8_t mode)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	*(mib->QoSOptImpl) = (u8) mode;
	return 0;
}

int
mwl_drv_get_wmm(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return *(mib->QoSOptImpl);
}

int
mwl_drv_set_wmmedcaap(struct net_device *netdev, uint32_t ac, uint32_t * param)
{
	extern mib_QAPEDCATable_t mib_QAPEDCATable[4];
	uint32_t index, cw_min, cw_max, aifsn, tx_op_lim_b, tx_op_lim;

	index = ac;
	if ((index < 0) || (index > 3)) {
		return -EFAULT;
	}

	cw_min = param[0];
	cw_max = param[1];
	if ( /*(cw_min < BE_CWMIN) || (cw_max > BE_CWMAX) || */
		(cw_min > cw_max)) {
		return -EFAULT;
	}

	aifsn = param[2];
	tx_op_lim_b = param[3];
	tx_op_lim = param[4];

	mib_QAPEDCATable[index].QAPEDCATblIndx = index;
	mib_QAPEDCATable[index].QAPEDCATblCWmin = cw_min;
	mib_QAPEDCATable[index].QAPEDCATblCWmax = cw_max;
	mib_QAPEDCATable[index].QAPEDCATblAIFSN = aifsn;
	mib_QAPEDCATable[index].QAPEDCATblTXOPLimit = tx_op_lim;
	mib_QAPEDCATable[index].QAPEDCATblTXOPLimitBAP = tx_op_lim_b;

	//printk("WMM: %d %d %d %d %d %d\n", index, cw_min, cw_max, aifsn, tx_op_lim_b, tx_op_lim);
	return 0;
}

int
mwl_drv_get_wmmedcaap(struct net_device *netdev, char *wmmedcaap)
{
	extern mib_QAPEDCATable_t mib_QAPEDCATable[4];
	int cw_min, cw_max, aifsn, tx_op_lim_b, tx_op_lim;
	char strName[4][6] = { "AC_BE", "AC_BK", "AC_VI", "AC_VO" };
	int i;
	char (*strBuf)[256] = kmalloc(4 * sizeof(*strBuf), GFP_KERNEL);
	if (strBuf == NULL) {
		kfree(strBuf);
		return -1;
	}

	for (i = 0; i < 4; i++) {
		cw_min = mib_QAPEDCATable[i].QAPEDCATblCWmin;
		cw_max = mib_QAPEDCATable[i].QAPEDCATblCWmax;
		aifsn = mib_QAPEDCATable[i].QAPEDCATblAIFSN;
		tx_op_lim = mib_QAPEDCATable[i].QAPEDCATblTXOPLimit;
		tx_op_lim_b = mib_QAPEDCATable[i].QAPEDCATblTXOPLimitBAP;

		sprintf(&(strBuf[i][0]), "\n%s %d %d %d %d %d\n", strName[i],
			cw_min, cw_max, aifsn, tx_op_lim_b, tx_op_lim);
	}
	sprintf(wmmedcaap, "%s%s%s%s", strBuf[0], strBuf[1], strBuf[2],
		strBuf[3]);
	kfree(strBuf);
	return 0;
}

int
mwl_drv_set_amsdu(struct net_device *netdev, uint8_t value)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	if (value < 0 || value > 3) {
		return -EFAULT;
	}

	*(mib->mib_amsdutx) = value;	//0:amsdu disable, 1:4K, 2:8K, 3:11K (for VHT, for 11n it is considered 8K)
#if 0
	/*If 2G, we disable AMSDU and only enable AMPDU in GUI Auto aggregation mode.
	 * If AMSDU is turned on, UDP Tx to MBAir in 2G has low thpt due to MBAir going to sleep in middle of traffic.
	 * TODO: Still debugging 9/18/2013
	 */
	if (*(mib->mib_ApMode) <= AP_MODE_BandGandN
#ifdef SOC_W8864
	    || *(mib->mib_ApMode) == AP_MODE_2_4GHZ_11AC_MIXED
#endif
		) {
		*(mib->pMib_11nAggrMode) &= WL_MODE_AMPDU_TX;
	} else
#endif
	{
		//keep the ampdu setting
		*(mib->pMib_11nAggrMode) =
			(*(mib->pMib_11nAggrMode) & WL_MODE_AMPDU_TX) | (u8)
			value;
	}

	return 0;
}

int
mwl_drv_get_amsdu(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return *(mib->pMib_11nAggrMode) & WL_MODE_AMSDU_TX_MASK;
}

int
mwl_drv_set_rxantenna(struct net_device *netdev, uint8_t value)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	if (value < 0 || value > 0x7) {
		return -EFAULT;
	}
	*(mib->mib_rxAntenna) = (u8) value;

	if (*(mib->mib_rxAntenna) == 4 || *(mib->mib_rxAntenna) == 0)
		*(mib->mib_rxAntBitmap) = 0xf;
	else if (*(mib->mib_rxAntenna) == 3)
		*(mib->mib_rxAntBitmap) = 7;
	else if (*(mib->mib_rxAntenna) == 2)
		*(mib->mib_rxAntBitmap) = 3;
	else
		*(mib->mib_rxAntBitmap) = 1;

	return 0;
}

int
mwl_drv_get_rxantenna(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return *(mib->mib_rxAntenna);
}

int
mwl_drv_set_optlevel(struct net_device *netdev, uint8_t value)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	*(mib->mib_optlevel) = value;

	return 0;
}

int
mwl_drv_get_optlevel(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return *(mib->mib_optlevel);
}

int
mwl_drv_set_macclone(struct net_device *netdev, uint8_t enable)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	vmacEntry_t *vmacEntry_p = NULL;
	UINT8 mlmeAssociatedFlag;
	UINT8 mlmeBssid[6];
	int i, index, bssidmask = 0;
	UINT8 macaddr[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

#ifdef CLIENT_SUPPORT
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);

	/* Get VMAC structure of the master */
	if (!wlpptr->master) {
		printk("Device %s is not a client device \n", netdev->name);
		return -EFAULT;
	}

	if (enable == 0) {
		*(mib->mib_STAMacCloneEnable) = 0;
		//printk("maccloneing disabled mib_STAMacCloneEnable = %x \n", *(mib->mib_STAMacCloneEnable));
	} else if (enable == 1) {
		*(mib->mib_STAMacCloneEnable) = 1;
		//printk("maccloneing enabled mib_STAMacCloneEnable = %x \n", *(mib->mib_STAMacCloneEnable));
	} else {
		printk("macclone: invalid set option. \n");
		return -EFAULT;
	}

	if ((vmacEntry_p =
	     sme_GetParentVMacEntry(((vmacApInfo_t *) priv->vmacSta_p)->
				    VMacEntry.phyHwMacIndx)) == NULL)
		return -EFAULT;

	smeGetStaLinkInfo(vmacEntry_p->id, &mlmeAssociatedFlag, &mlmeBssid[0]);
	wlFwRemoveMacAddr(vmacSta_p->dev, &vmacEntry_p->vmacAddr[0]);
	if (mlmeAssociatedFlag)
		cleanupAmpduTx(vmacSta_p, (UINT8 *) & mlmeBssid[0]);

	/*The method to generate wdev0sta0 mac addr is same as in wlInit for client */
	/*If GUI is used to config client, it comes to here too and we have to assign correct wdev0sta0 mac addr */
	/*eventhough it is already initialized in wlInit */
	memcpy(macaddr, wlpptr->master->dev_addr, 6);

#if defined(MBSS)
	for (index = 0; index < NUMOFAPS; index++)
#else
	for (index = 0; index < 1; index++)
#endif
	{
		//uses mac addr bit 41 & up as mbss addresses
		for (i = 1; i < 32; i++) {
			if ((bssidmask & (1 << i)) == 0)
				break;
		}
		if (i) {
			macaddr[0] =
				wlpptr->master->dev_addr[0] | ((i << 2) | 0x2);
		}
		bssidmask |= 1 << i;
	}
	memcpy(&vmacEntry_p->vmacAddr[0], &macaddr[0], 6);

	/*If we change wdev0sta0 mac addr, we also change these areas. */
	/*macStaAddr is used for mac addr comparison in tx and rx */
	memcpy(netdev->dev_addr, &vmacEntry_p->vmacAddr[0], 6);
	memcpy(&wlpptr->hwData.macAddr[0], &vmacEntry_p->vmacAddr[0], 6);
	memcpy(&vmacSta_p->macStaAddr[0], &vmacEntry_p->vmacAddr[0], 6);
	memcpy(&vmacSta_p->macBssId[0], &vmacEntry_p->vmacAddr[0], 6);
	memcpy(&vmacSta_p->VMacEntry.vmacAddr[0], &vmacEntry_p->vmacAddr[0], 6);

	printk("Mac cloning disabled : Mac Client Addr = %s\n",
	       mac_display(&vmacEntry_p->vmacAddr[0]));

#endif

	return 0;
}

int
mwl_drv_set_stascan(struct net_device *netdev, uint8_t enable)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

#ifdef CLIENT_SUPPORT
	UINT8 bcAddr1[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };	/* BROADCAST BSSID */
	UINT8 ieBuf[2 + IEEE_80211_MAX_NUMBER_OF_CHANNELS];
	UINT16 ieBufLen = 0;
	IEEEtypes_InfoElementHdr_t *IE_p;
	vmacEntry_t *vmacEntry_p = NULL;
	struct net_device *staDev = NULL;
	struct wlprivate *stapriv = NULL;
	UINT8 mlmeAssociatedFlag;
	UINT8 mlmeBssid[6];
	UINT8 currChnlIndex = 0;
	UINT8 chnlListLen = 0;
	UINT8 chnlScanList[IEEEtypes_MAX_CHANNELS + IEEEtypes_MAX_CHANNELS_A];
	UINT8 i = 0;
	MIB_PHY_DSSS_TABLE *PhyDSSSTable;
	UINT8 mainChnlList[IEEEtypes_MAX_CHANNELS + IEEEtypes_MAX_CHANNELS_A];

	if (enable != 1) {
		return -EINVAL;
	}

	vmacEntry_p =
		sme_GetParentVMacEntry(((vmacApInfo_t *) priv->vmacSta_p)->
				       VMacEntry.phyHwMacIndx);
	staDev = (struct net_device *)vmacEntry_p->privInfo_p;
	stapriv = NETDEV_PRIV_P(struct wlprivate, staDev);

	//when this command issued on AP mode, system would crash because of no STA interface
	//so the following checking is necessary.
	if (*(mib->mib_STAMode) == CLIENT_MODE_DISABLE) {
		return -EOPNOTSUPP;
	}

	memset(&mainChnlList[0], 0,
	       (IEEEtypes_MAX_CHANNELS + IEEEtypes_MAX_CHANNELS_A));
	memset(&chnlScanList[0], 0,
	       (IEEEtypes_MAX_CHANNELS + IEEEtypes_MAX_CHANNELS_A));

	PhyDSSSTable = mib->PhyDSSSTable;

	/* Stop Autochannel on AP first */
	StopAutoChannel(vmacSta_p);

	/* get range to scan */
	domainGetInfo(mainChnlList);

	if ((*(vmacSta_p->Mib802dot11->mib_STAMode) == CLIENT_MODE_AUTO) ||
	    (*(vmacSta_p->Mib802dot11->mib_STAMode) == CLIENT_MODE_N)) {
		for (i = 0; i < IEEEtypes_MAX_CHANNELS; i++) {
			if (mainChnlList[i] > 0) {
				chnlScanList[currChnlIndex] = mainChnlList[i];
				currChnlIndex++;
			}
		}

		for (i = 0; i < IEEEtypes_MAX_CHANNELS_A; i++) {
			if (mainChnlList[i + IEEEtypes_MAX_CHANNELS] > 0) {
				chnlScanList[currChnlIndex] =
					mainChnlList[i +
						     IEEEtypes_MAX_CHANNELS];
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
			chnlScanList[i] =
				mainChnlList[i + IEEEtypes_MAX_CHANNELS];
		}
		chnlScanList[i] = 0;
		chnlListLen = IEEEtypes_MAX_CHANNELS_A;
	}

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

	if ((vmacEntry_p =
	     sme_GetParentVMacEntry(((vmacApInfo_t *) priv->vmacSta_p)->
				    VMacEntry.phyHwMacIndx)) == NULL) {
		return -EFAULT;
	}

	if (!smeGetStaLinkInfo
	    (vmacEntry_p->id, &mlmeAssociatedFlag, &mlmeBssid[0])) {
		return -EFAULT;
	}

	/* Set a flag indicating usr initiated scan */
	vmacSta_p->gUserInitScan = TRUE;

	if (!mlmeAssociatedFlag && (staDev->flags & IFF_RUNNING)) {
		//printk("stopping BSS \n");
		linkMgtStop(vmacEntry_p->phyHwMacIndx);
		smeStopBss(vmacEntry_p->phyHwMacIndx);
	}

	if (smeSendScanRequest
	    (vmacEntry_p->phyHwMacIndx, 0, 3, 200, &bcAddr1[0], &ieBuf[0],
	     ieBufLen) == MLME_SUCCESS) {
		/*set the busy scanning flag */
		vmacSta_p->busyScanning = 1;
	} else {
		/* Reset a flag indicating usr initiated scan */
		vmacSta_p->gUserInitScan = FALSE;
		return -EALREADY;
	}
#endif

	return 0;
}

int
mwl_drv_get_stascan(struct net_device *netdev, char *stascan)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;

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

	/* Fill the output buffer */
	sprintf(stascan, "\n");
	stascan++;

	for (i = 0; i < tmpNumScanDesc[vmacSta_p->VMacEntry.phyHwMacIndx]; i++) {
		curDescpt_p =
			(scanDescptHdr_t
			 *) (&tmpScanResults[vmacSta_p->VMacEntry.
					     phyHwMacIndx][0] + parsedLen);

		memset(&scannedSSID[0], 0, sizeof(scannedSSID));
		memset(&apType[0], 0, sizeof(apType));
		sprintf(&encryptType[0], "None");
		sprintf(&cipherType[0], " ");
		mdcnt = 0;
		scannedChannel = 0;
		apGonly = FALSE;

		if ((ssidIE_p = (IEEEtypes_SsIdElement_t *) smeParseIeType(SSID,
									   (((UINT8 *) curDescpt_p) + sizeof(scanDescptHdr_t)), curDescpt_p->length + sizeof(curDescpt_p->length) - sizeof(scanDescptHdr_t))) != NULL) {
			memcpy(&scannedSSID[0], &ssidIE_p->SsId[0],
			       ssidIE_p->Len);
		}
		if ((dsPSetIE_p =
		     (IEEEtypes_DsParamSet_t *) smeParseIeType(DS_PARAM_SET,
							       (((UINT8 *)
								 curDescpt_p) +
								sizeof
								(scanDescptHdr_t)),
							       curDescpt_p->
							       length +
							       sizeof
							       (curDescpt_p->
								length) -
							       sizeof
							       (scanDescptHdr_t)))
		    != NULL) {
			scannedChannel = dsPSetIE_p->CurrentChan;
		}

		if (curDescpt_p->CapInfo.Privacy)
			sprintf(&encryptType[0], "WEP");

		PeerSupportedRates_p =
			(IEEEtypes_SuppRatesElement_t *)
			smeParseIeType(SUPPORTED_RATES,
				       (((UINT8 *) curDescpt_p) +
					sizeof(scanDescptHdr_t)),
				       curDescpt_p->length +
				       sizeof(curDescpt_p->length) -
				       sizeof(scanDescptHdr_t));

		PeerExtSupportedRates_p =
			(IEEEtypes_ExtSuppRatesElement_t *)
			smeParseIeType(EXT_SUPPORTED_RATES,
				       (((UINT8 *) curDescpt_p) +
					sizeof(scanDescptHdr_t)),
				       curDescpt_p->length +
				       sizeof(curDescpt_p->length) -
				       sizeof(scanDescptHdr_t));

		LegacyRateBitMap =
			GetAssocRespLegacyRateBitMap(PeerSupportedRates_p,
						     PeerExtSupportedRates_p);

		if (scannedChannel <= 14) {
			if (PeerSupportedRates_p) {
				int j;
				for (j = 0;
				     (j < PeerSupportedRates_p->Len) &&
				     !apGonly; j++) {
					/* Only look for 6 Mbps as basic rate - consider this to be G only. */
					if (PeerSupportedRates_p->Rates[j] ==
					    0x8c) {
						sprintf(&apType[mdcnt++], "G");
						apGonly = TRUE;
					}
				}
			}
			if (!apGonly) {
				if (LegacyRateBitMap & 0x0f)
					sprintf(&apType[mdcnt++], "B");
				if (PeerSupportedRates_p &&
				    PeerExtSupportedRates_p)
					sprintf(&apType[mdcnt++], "G");
			}
		} else {
			if (LegacyRateBitMap & 0x1fe0)
				sprintf(&apType[mdcnt++], "A");
		}

		pHT = (IEEEtypes_HT_Element_t *) smeParseIeType(HT,
								(((UINT8 *)
								  curDescpt_p) +
								 sizeof
								 (scanDescptHdr_t)),
								curDescpt_p->
								length +
								sizeof
								(curDescpt_p->
								 length) -
								sizeof
								(scanDescptHdr_t));

		pHTAdd = (IEEEtypes_Add_HT_Element_t *) smeParseIeType(ADD_HT,
								       (((UINT8
									  *)
									 curDescpt_p)
									+
									sizeof
									(scanDescptHdr_t)),
								       curDescpt_p->
								       length +
								       sizeof
								       (curDescpt_p->
									length)
								       -
								       sizeof
								       (scanDescptHdr_t));
		// If cannot find HT element then look for High Throughput elements using PROPRIETARY_IE.
		if (pHT == NULL) {
			pHTGen = linkMgtParseHTGenIe((((UINT8 *) curDescpt_p) +
						      sizeof(scanDescptHdr_t)),
						     curDescpt_p->length +
						     sizeof(curDescpt_p->
							    length) -
						     sizeof(scanDescptHdr_t));
		}
		if ((RSN_p =
		     linkMgtParseWpaIe((((UINT8 *) curDescpt_p) +
					sizeof(scanDescptHdr_t)),
				       curDescpt_p->length +
				       sizeof(curDescpt_p->length) -
				       sizeof(scanDescptHdr_t)))) {
			sprintf(&encryptType[0], "WPA");

			if (RSN_p->PwsKeyCipherList[3] == RSN_TKIP_ID)
				sprintf(&cipherType[0], "TKIP");
			else if (RSN_p->PwsKeyCipherList[3] == RSN_AES_ID)
				sprintf(&cipherType[0], "AES");
		}

		if ((wpa2IE_p =
		     (IEEEtypes_RSN_IE_WPA2_t *) smeParseIeType(RSN_IEWPA2,
								(((UINT8 *)
								  curDescpt_p) +
								 sizeof
								 (scanDescptHdr_t)),
								curDescpt_p->
								length +
								sizeof
								(curDescpt_p->
								 length) -
								sizeof
								(scanDescptHdr_t))))
		{
			// RSN_AES_ID, RSN_TKIP_ID
			if ((wpa2IE_p->GrpKeyCipher[3] == RSN_TKIP_ID) &&
			    (wpa2IE_p->PwsKeyCipherList[3] == RSN_AES_ID))
				sprintf(&encryptType[0], "WPA-WPA2");
			else
				sprintf(&encryptType[0], "WPA2");

			if (wpa2IE_p->PwsKeyCipherList[3] == RSN_TKIP_ID)
				sprintf(&cipherType[0], "TKIP");
			else if (wpa2IE_p->PwsKeyCipherList[3] == RSN_AES_ID)
				sprintf(&cipherType[0], "AES");
		}

		if (pHT || pHTGen) {
			sprintf(&apType[mdcnt++], "N");
		}

		parsedLen += curDescpt_p->length + sizeof(curDescpt_p->length);

		sprintf(stascan,
			"#%3d SSID=%-32s %02x:%02x:%02x:%02x:%02x:%02x %3d -%d %s %s %s\n",
			i + 1, (const char *)&scannedSSID[0],
			curDescpt_p->bssId[0], curDescpt_p->bssId[1],
			curDescpt_p->bssId[2], curDescpt_p->bssId[3],
			curDescpt_p->bssId[4], curDescpt_p->bssId[5],
			scannedChannel, curDescpt_p->rssi, apType, encryptType,
			cipherType);

		stascan += strlen(stascan);
	}

	return 0;
}

int
mwl_drv_set_fixrate(struct net_device *netdev, uint8_t value)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	if (value < 0 || value > 2) {
		return -EFAULT;
	}
	*(mib->mib_enableFixedRateTx) = (u8) value;

	return 0;
}

int
mwl_drv_get_fixrate(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return *(mib->mib_enableFixedRateTx);
}

int
mwl_drv_set_txrate(struct net_device *netdev, uint8_t type, uint16_t rate)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

#ifdef BRS_SUPPORT
	uint32_t rateMask = 0;
#endif

	if (type == MWL_RATE_B) {
		if (!rateChecked(rate, AP_MODE_B_ONLY)) {
			return -EFAULT;
		}
		//printk("B: %d\n", rate);

		*(mib->mib_txDataRate) = (u8) rate;
		*(mib->mib_FixedRateTxType) = 0;
	} else if (type == MWL_RATE_G) {
		if (!rateChecked(rate, AP_MODE_G_ONLY)) {
			return -EFAULT;
		}
		//printk("G: %d\n", rate);

		*(mib->mib_txDataRateG) = (u8) rate;
		*(mib->mib_FixedRateTxType) = 0x10;
	} else if (type == MWL_RATE_N) {
		if ((rate > 271) && !(*(mib->mib_3x3Rate))) {
			return -EFAULT;
		}
		if (!rateChecked(rate, AP_MODE_N_ONLY)) {
			return -EFAULT;
		}
		//printk("N: %d\n", rate);

		*(mib->mib_txDataRateN) = (u8) rate;
		*(mib->mib_FixedRateTxType) = 0x1;

	} else if (type == MWL_RATE_A) {
		if (!rateChecked(rate, AP_MODE_A_ONLY)) {
			return -EFAULT;
		}
		//PRINT1(IOCTL,"A: %d\n", rate);

		*(mib->mib_txDataRateA) = (u8) rate;
		*(mib->mib_FixedRateTxType) = 0x20;

	} else if (type == MWL_RATE_MCBC) {

		if (rate > 0x1ff) {
			/*VHT MCS rate:
			 * 512 (0x200 NSS1_MCS0), 513 (0x201 NSS1_MCS1), 514 (0x202 NSS1_MCS2)...
			 * 528 (0x210 NSS2_MCS0), 529 (0x211 NSS2_MCS1), 530 (0x212 NSS2_MCS2)...
			 * 544 (0x220 NSS3_MCS0), 545 (0x221 NSS3_MCS1), 546 (0x222 NSS3_MCS2)...
			 */
			if (!rateChecked(rate, AP_MODE_11AC)) {
				return -EFAULT;
			}
			*(mib->mib_MultiRateTxType) = 2;
		} else if (rate > 0xff) {
			/* HT MCS rate: 256 (0x100 MCS0), 257(0x101 MCS1), 258(0x102 MCS2) .... */
			if (!rateChecked(rate, AP_MODE_N_ONLY)) {
				return -EFAULT;
			}
			*(mib->mib_MultiRateTxType) = 1;
		} else {	/* G rate: 2, 4, 11, 22, 44, 12, 18, 24, 36, 48, 72, 96, 108, 144 */

			if (!rateChecked(rate, AP_MODE_G_ONLY)) {
				return -EFAULT;
			}
			*(mib->mib_MultiRateTxType) = 0;
		}

		//printk("MCBC: %x\n", rate);

		*(mib->mib_MulticastRate) = (u8) rate;

	} else if (type == MWL_RATE_MGT) {
		if (!rateChecked(rate, AP_MODE_G_ONLY)) {
			return -EFAULT;
		}
		//printk("MGT: %x\n", rate);

		*(mib->mib_ManagementRate) = (u8) rate;
	}
#ifdef BRS_SUPPORT
	else if ((type == MWL_RATE_BRS) || (type == MWL_RATE_SRS)) {

		if (!rateChecked(rate, AP_MODE_G_ONLY)) {
			return -EFAULT;
		}
		IEEEToMrvlRateBitMapConversion((u8) rate, &rateMask);

		if (type == MWL_RATE_BRS) {
			*(mib->BssBasicRateMask) = rateMask;
			(*(mib->NotBssBasicRateMask)) &= ~rateMask;
		} else {
			if ((rateMask | ~(*(mib->BssBasicRateMask))) &
			    *(mib->BssBasicRateMask)) {
				/* some basic rate is added */
				return -EFAULT;
			}
			*(mib->NotBssBasicRateMask) = rateMask;
		}
	}
#endif
#if defined(SOC_W8864)
	else if (type == MWL_RATE_VHT) {
		if (!rateChecked(rate, AP_MODE_11AC)) {
			return -EFAULT;
		}
		*(mib->mib_txDataRateVHT) = (u8) rate;
		*(mib->mib_FixedRateTxType) = 0x2;

	}
	//rateinfo
	else if (type == MWL_RATE_RATE_INFO) {
		*(mib->mib_txDataRateInfo) = rate;
		*(mib->mib_FixedRateTxType) = 0x4;
	}
#endif
	else {
		return -EFAULT;
	}

	return 0;
}

int
mwl_drv_get_txrate(struct net_device *netdev, char *txrate)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

#ifdef SOC_W8864
	int b_rate = 2, g_rate = 2, n_rate =
		0, a_rate, vht_rate, m_rate, manage_rate, i = 0;
#else
	int b_rate = 2, g_rate = 2, n_rate = 0, a_rate, m_rate, manage_rate, i =
		0;
#endif
	char *p = txrate;
	int rateMask;

	if (*(mib->mib_enableFixedRateTx) == 0) {
		sprintf(txrate, "Auto Rate\n");
	} else {
		b_rate = *(mib->mib_txDataRate);
		g_rate = *(mib->mib_txDataRateG);
		a_rate = *(mib->mib_txDataRateA);
#ifdef SOC_W8864
		vht_rate = *(mib->mib_txDataRateVHT);
#endif

		n_rate = *(mib->mib_txDataRateN) + 256;

#ifdef SOC_W8864
		sprintf(txrate,
			"B Rate: %d, G Rate: %d, A Rate: %d, N Rate: %d, vht Rate: 0x%x\n",
			b_rate, g_rate, a_rate, n_rate, vht_rate);
#else
		sprintf(txrate,
			"B Rate: %d, G Rate: %d, A Rate: %d, N Rate: %d\n",
			b_rate, g_rate, a_rate, n_rate);
#endif
	}
	if (*(mib->mib_MultiRateTxType) == 2)
		m_rate = *(mib->mib_MulticastRate) + 512;
	else if (*(mib->mib_MultiRateTxType) == 1)
		m_rate = *(mib->mib_MulticastRate) + 256;
	else
		m_rate = *(mib->mib_MulticastRate);
	manage_rate = *(mib->mib_ManagementRate);
	p += strlen(txrate);
	sprintf(p, "Multicast Rate: %d, Management Rate: %d\n", m_rate,
		manage_rate);
#ifdef BRS_SUPPORT
	p = txrate + strlen(txrate);
	sprintf(p, "BSS Basic Rate: ");

	p = txrate + strlen(txrate);

	rateMask = *(mib->BssBasicRateMask);
	i = 0;
	while (rateMask) {
		if (rateMask & 0x01) {
			if (mib->StationConfig->OpRateSet[i]) {
				sprintf(p, "%d ",
					mib->StationConfig->OpRateSet[i]);
				p = txrate + strlen(txrate);
			}
		}
		rateMask >>= 1;
		i++;
	}

	p = txrate + strlen(txrate);
	sprintf(p, "\nNot BSS Basic Rate: ");

	p = txrate + strlen(txrate);
	rateMask = *(mib->NotBssBasicRateMask);
	i = 0;
	while (rateMask) {
		if (rateMask & 0x01) {
			if (mib->StationConfig->OpRateSet[i]) {
				sprintf(p, "%d ",
					mib->StationConfig->OpRateSet[i]);
				p = txrate + strlen(txrate);
			}
		}
		rateMask >>= 1;
		i++;
	}
#endif

	return 0;
}

int
mwl_drv_set_mcastproxy(struct net_device *netdev, uint8_t value)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	if (value < 0 || value > 1) {
		return -EOPNOTSUPP;
	}
	*(mib->mib_MCastPrxy) = (u8) value;

	/*mcast proxy is turned on */
	if (*(mib->mib_MCastPrxy)) {
		/*If mib is same as default,  use 10 to set limit */
		if (*(mib->mib_consectxfaillimit) == CONSECTXFAILLIMIT) {
			*(mib->mib_consectxfaillimit) = _CONSECTXFAILLIMIT;
			wlFwSetConsecTxFailLimit(netdev, _CONSECTXFAILLIMIT);
		}

	} else {		/*Set back to default value */
		if (*(mib->mib_consectxfaillimit) == _CONSECTXFAILLIMIT) {
			*(mib->mib_consectxfaillimit) = CONSECTXFAILLIMIT;
			wlFwSetConsecTxFailLimit(netdev, CONSECTXFAILLIMIT);
		}
	}

	return 0;
}

int
mwl_drv_get_mcastproxy(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return *(mib->mib_MCastPrxy);
}

int
mwl_drv_set_11hstamode(struct net_device *netdev, uint8_t value)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;

	vmacEntry_t *vmacEntry_p = NULL;
	STA_SYSTEM_MIBS *pStaSystemMibs;

	if (value < 0 || value > 1) {
		return -EINVAL;
	}
	if ((vmacEntry_p =
	     sme_GetParentVMacEntry(vmacSta_p->VMacEntry.phyHwMacIndx)) ==
	    NULL) {
		return -EFAULT;
	}
	pStaSystemMibs = sme_GetStaSystemMibsPtr(vmacEntry_p);
	if (pStaSystemMibs == NULL) {
		return -EFAULT;
	}
	pStaSystemMibs->mib_StaCfg_p->sta11hMode = value;

	return 0;
}

#ifdef CLIENT_SUPPORT
int
mwl_drv_get_11hstamode(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;

	int param = -EFAULT;

	vmacEntry_t *vmacEntry_p = NULL;
	STA_SYSTEM_MIBS *pStaSystemMibs;

	if ((vmacEntry_p =
	     sme_GetParentVMacEntry(vmacSta_p->VMacEntry.phyHwMacIndx)) !=
	    NULL) {
		pStaSystemMibs = sme_GetStaSystemMibsPtr(vmacEntry_p);
		if (pStaSystemMibs != NULL) {
			param = pStaSystemMibs->mib_StaCfg_p->sta11hMode;
		}
	}

	return param;
}
#endif //CLIENT_SUPPORT

int
mwl_drv_get_rssi(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;

	u16 a, b, c, d;

	if (vmacSta_p->OpMode == WL_OP_MODE_STA ||
	    vmacSta_p->OpMode == WL_OP_MODE_VSTA) {
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
		return -a;	//to do
	} else {
		printk(" for STA mode use only \n");
		return 0;
	}
}

int
mwl_drv_get_linkstatus(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	int param = -EFAULT;

	UINT8 AssociatedFlag = 0;
	UINT8 bssId[6];

	vmacEntry_t *vmacEntry_p = NULL;

	if ((vmacEntry_p =
	     sme_GetParentVMacEntry(vmacSta_p->VMacEntry.phyHwMacIndx)) !=
	    NULL) {
		vmacStaInfo_t *vStaInfo_p =
			(vmacStaInfo_t *) vmacEntry_p->info_p;

		if (vStaInfo_p->staSecurityMibs.mib_PrivacyTable_p->RSNEnabled) {
			param = vStaInfo_p->staSecurityMibs.mib_PrivacyTable_p->
				RSNLinkStatus;
		} else {
			smeGetStaLinkInfo(vmacEntry_p->id,
					  &AssociatedFlag, &bssId[0]);
			param = AssociatedFlag;
		}
	}

	return param;
}

int
mwl_drv_get_stalistext(struct net_device *netdev, char *stalistext)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	UCHAR *sta_buf, *show_buf, buf1[256];
	char *out_buf = stalistext;
	int i, entries;
	extStaDb_StaInfo_t *pStaInfo;
	char tmpBuf[48];
	u16 a, b, c, d;
	entries = extStaDb_entries(vmacSta_p, 0);

	memset(tmpBuf, 0, sizeof(tmpBuf));

	sta_buf = kmalloc(entries * 64, GFP_KERNEL);
	if (sta_buf == NULL) {
		return -EFAULT;
	}

	extStaDb_list(vmacSta_p, sta_buf, 1);

	if (entries) {
		show_buf = sta_buf;
		sprintf(out_buf, "\n");
		out_buf++;
		for (i = 0; i < entries; i++) {
			if ((pStaInfo =
			     extStaDb_GetStaInfo(vmacSta_p,
						 (IEEEtypes_MacAddr_t *)
						 show_buf, 0)) == NULL) {
				kfree(sta_buf);
				return -EFAULT;
			}
			switch (pStaInfo->ClientMode) {
			case BONLY_MODE:
				strcpy(&tmpBuf[0], "b ");
				break;

			case GONLY_MODE:
				strcpy(&tmpBuf[0], "g ");
				break;

			case NONLY_MODE:
				strcpy(&tmpBuf[0], "n ");
				break;

			case AONLY_MODE:
				strcpy(&tmpBuf[0], "a ");
				break;

			default:
				strcpy(&tmpBuf[0], "NA ");
				break;

			}

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
					if ((mib->Privacy->RSNEnabled == 1) ||
					    (mib->RSNConfigWPA2->WPA2Enabled ==
					     1)) {

						if (*(mib->mib_wpaWpa2Mode) < 4) {	/* For PSK modes use internal WPA state machine */
							if (pStaInfo->
							    keyMgmtHskHsm.super.
							    pCurrent != NULL) {
								if (pStaInfo->
								    keyMgmtHskHsm.
								    super.
								    pCurrent ==
								    &pStaInfo->
								    keyMgmtHskHsm.
								    hsk_end) {
									strcat(tmpBuf, "PSK-PASSED ");
									flagPsk = 1;
								}
							}
						} else if (pStaInfo->
							   keyMgmtStateInfo.
							   RSNDataTrafficEnabled
							   == TRUE) {
							strcat(tmpBuf,
							       "KEY_CONFIGURED ");
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

#ifdef SOC_W8764
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
				"%d: StnId %d Aid %d %02x:%02x:%02x:%02x:%02x:%02x %s Rate %d Mbps, RSSI:A -%d  B -%d  C -%d  D -%d\n",
				i + 1, pStaInfo->StnId, pStaInfo->Aid,
				*show_buf, *(show_buf + 1), *(show_buf + 2),
				*(show_buf + 3), *(show_buf + 4),
				*(show_buf + 5), tmpBuf,
				//pStaInfo->RateInfo.RateIDMCS,
				(int)getPhyRate((dbRateInfo_t *) &
						(pStaInfo->RateInfo)), a, b, c,
				d);
#else
			sprintf(buf1,
				"%d: %02x:%02x:%02x:%02x:%02x:%02x %s Rate %d Mbps, RSSI %d\n",
				i + 1, *show_buf, *(show_buf + 1),
				*(show_buf + 2), *(show_buf + 3),
				*(show_buf + 4), *(show_buf + 5), tmpBuf,
				//pStaInfo->RateInfo.RateIDMCS,
				(int)getPhyRate((dbRateInfo_t *) &
						(pStaInfo->RateInfo)),
				pStaInfo->RSSI);
#endif

			show_buf += sizeof(STA_INFO);
			strcpy(out_buf, buf1);
			out_buf += strlen(buf1);
		}
	} else {
		out_buf[0] = 0;
	}
	kfree(sta_buf);

	return 0;
}

int
mwl_drv_set_grouprekey(struct net_device *netdev, uint32_t value)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	if (value < 0) {
		return -EOPNOTSUPP;
	}
	if (value)
		mib->RSNConfig->GroupRekeyTime = (value);
	else			/* disable rekey */
		mib->RSNConfig->GroupRekeyTime = (0xffffffff / 10);

	PRINT1(IOCTL, "mib->RSNConfig->GroupRekeyTime %d\n",
	       mib->RSNConfig->GroupRekeyTime);

	return 0;
}

int
mwl_drv_get_grouprekey(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return (mib->RSNConfig->GroupRekeyTime);
}

int
mwl_drv_set_wmmedcasta(struct net_device *netdev, uint32_t ac, uint32_t * param)
{
	extern mib_QStaEDCATable_t mib_QStaEDCATable[4];
	uint32_t index, cw_min, cw_max, aifsn, tx_op_lim_b, tx_op_lim, acm;

	index = ac;
	if ((index < 0) || (index > 3)) {
		return -EFAULT;
	}

	cw_min = param[0];
	cw_max = param[1];
	if ( /*(cw_min < BE_CWMIN) || (cw_max > BE_CWMAX) || */
		(cw_min > cw_max)) {
		return -EFAULT;
	}

	aifsn = param[2];
	tx_op_lim_b = param[3];
	tx_op_lim = param[4];
	acm = param[5];

	mib_QStaEDCATable[index].QStaEDCATblIndx = index;
	mib_QStaEDCATable[index].QStaEDCATblCWmin = cw_min;
	mib_QStaEDCATable[index].QStaEDCATblCWmax = cw_max;
	mib_QStaEDCATable[index].QStaEDCATblAIFSN = aifsn;
	mib_QStaEDCATable[index].QStaEDCATblTXOPLimit = tx_op_lim;
	mib_QStaEDCATable[index].QStaEDCATblTXOPLimitBSta = tx_op_lim_b;
	mib_QStaEDCATable[index].QStaEDCATblMandatory = acm;

	//printk("WMM: %d %d %d %d %d %d %d\n", index, cw_min, cw_max, aifsn, tx_op_lim_b, tx_op_lim, acm);
	return 0;
}

int
mwl_drv_get_wmmedcasta(struct net_device *netdev, char *wmmedcasta)
{
	extern mib_QStaEDCATable_t mib_QStaEDCATable[4];
	int cw_min, cw_max, aifsn, tx_op_lim_b, tx_op_lim, acm;
	char strName[4][6] = { "AC_BE", "AC_BK", "AC_VI", "AC_VO" };
	int i;
	char (*strBuf)[256] = kmalloc(4 * sizeof(*strBuf), GFP_KERNEL);
	if (strBuf == NULL) {
		kfree(strBuf);
		return -1;
	}

	for (i = 0; i < 4; i++) {
		cw_min = mib_QStaEDCATable[i].QStaEDCATblCWmin;
		cw_max = mib_QStaEDCATable[i].QStaEDCATblCWmax;
		aifsn = mib_QStaEDCATable[i].QStaEDCATblAIFSN;
		tx_op_lim = mib_QStaEDCATable[i].QStaEDCATblTXOPLimit;
		tx_op_lim_b = mib_QStaEDCATable[i].QStaEDCATblTXOPLimitBSta;
		acm = mib_QStaEDCATable[i].QStaEDCATblMandatory;
		sprintf(&(strBuf[i][0]), "\n%s %d %d %d %d %d %d\n", strName[i],
			cw_min, cw_max, aifsn, tx_op_lim_b, tx_op_lim, acm);
	}
	sprintf(wmmedcasta, "%s%s%s%s", strBuf[0], strBuf[1], strBuf[2],
		strBuf[3]);
	kfree(strBuf);

	return 0;
}

int
mwl_drv_set_htbw(struct net_device *netdev, uint8_t value)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	MIB_PHY_DSSS_TABLE *PhyDSSSTable = mib->PhyDSSSTable;

	switch (value) {
	case 0:
		PhyDSSSTable->Chanflag.ChnlWidth = CH_AUTO_WIDTH;
		vht_cap = 0x339b7930;
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
#ifdef SOC_W8964
	case 5:
		PhyDSSSTable->Chanflag.ChnlWidth = CH_160_MHz_WIDTH;
		vht_cap = 0x339b7976;
		ie192_version = 2;
		break;
	case 6:
		PhyDSSSTable->Chanflag.ChnlWidth = CH_160_MHz_WIDTH;
		vht_cap = 0x339b7976;
		ie192_version = 1;
		break;
	case 8:
		PhyDSSSTable->Chanflag.ChnlWidth = CH_5_MHz_WIDTH;
		break;
#endif
	default:
		return -EOPNOTSUPP;
		break;
	}
#ifdef INTOLERANT40
	*(mib->USER_ChnlWidth) = PhyDSSSTable->Chanflag.ChnlWidth;
	if ((*(mib->USER_ChnlWidth) == CH_40_MHz_WIDTH) ||
	    (*(mib->USER_ChnlWidth) == CH_AUTO_WIDTH))
		*(mib->mib_FortyMIntolerant) = 0;
	else
		*(mib->mib_FortyMIntolerant) = 1;
#endif
#ifdef COEXIST_20_40_SUPPORT
	if ((PhyDSSSTable->Chanflag.ChnlWidth == CH_AUTO_WIDTH) ||
	    (PhyDSSSTable->Chanflag.ChnlWidth == CH_160_MHz_WIDTH) ||
	    (PhyDSSSTable->Chanflag.ChnlWidth == CH_40_MHz_WIDTH) ||
	    (PhyDSSSTable->Chanflag.ChnlWidth == CH_80_MHz_WIDTH)) {
		if (PhyDSSSTable->CurrChan == 14)
			*(mib->USER_ChnlWidth) = 0;
		else
			*(mib->USER_ChnlWidth) = 1;
	} else
		*(mib->USER_ChnlWidth) = 0;
#endif

	return 0;
}

int
mwl_drv_get_htbw(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	MIB_PHY_DSSS_TABLE *PhyDSSSTable = mib->PhyDSSSTable;

	int param = -EFAULT;
	switch (PhyDSSSTable->Chanflag.ChnlWidth) {
	case CH_AUTO_WIDTH:
		param = 0;
		break;
	case CH_10_MHz_WIDTH:
		param = 1;
		break;
	case CH_20_MHz_WIDTH:
		param = 2;
		break;
	case CH_40_MHz_WIDTH:
		param = 3;
		break;
	case CH_80_MHz_WIDTH:
		param = 4;
		break;
#ifdef SOC_W8964
	case CH_160_MHz_WIDTH:
		param = 5;
		break;
	case CH_5_MHz_WIDTH:
		param = 8;
		break;
#endif
	default:
		param = -EOPNOTSUPP;
		break;
	}
#ifdef SOC_W8964
	wlFwGetPHYBW(netdev);
#endif

	return param;
}

int
mwl_drv_set_filter(struct net_device *netdev, uint8_t value)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	if (value < 0 || value > 2) {
		return -EOPNOTSUPP;
	}
	*(mib->mib_wlanfiltertype) = (u8) value;

	return 0;
}

int
mwl_drv_get_filter(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return *mib->mib_wlanfiltertype;
}

int
mwl_drv_add_filtermac(struct net_device *netdev, char *macaddr, uint8_t len)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	unsigned char *mib_wlanfilterno_p = mib->mib_wlanfilterno;
	uint8_t i, SameMAC = 0;

	if (len != 6) {
		return -EFAULT;
	}

	for (i = 0; i < FILERMACNUM; i++) {
		if (memcmp(mib->mib_wlanfiltermac + i * 6, macaddr, 6) == 0) {
			SameMAC = 1;
			break;
		}
	}

	if (SameMAC == 0) {
		if (*mib_wlanfilterno_p < FILERMACNUM) {
			memcpy((mib->mib_wlanfiltermac +
				*mib_wlanfilterno_p * 6), macaddr, 6);
			(*mib_wlanfilterno_p)++;
		} else
			return -EFAULT;
	}

	return 0;
}

int
mwl_drv_del_filtermac(struct net_device *netdev, char *macaddr, uint8_t len)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	unsigned char *mib_wlanfilterno_p = mib->mib_wlanfilterno;
	uint8_t i;

	if (len != 6 && len != 1) {
		return -EFAULT;
	}

	if (len == 1) {
		if (macaddr[0] == 0) {
			*mib_wlanfilterno_p = 0;
			memset(mib->mib_wlanfiltermac, 0, FILERMACNUM * 6);
			return 0;
		} else {
			return -EFAULT;
		}
	}

	for (i = 0; i < FILERMACNUM; i++) {
		if (memcmp(mib->mib_wlanfiltermac + i * 6, macaddr, 6) == 0) {
			(*mib_wlanfilterno_p)--;
			if (*mib_wlanfilterno_p == 0) {
				if (i != 0) {
					return -EFAULT;
				} else
					memset(mib->mib_wlanfiltermac, 0, 6);
			} else {
				if (i > *mib_wlanfilterno_p) {
					return -EFAULT;
				} else {
					memcpy(mib->mib_wlanfiltermac + i * 6,
					       mib->mib_wlanfiltermac +
					       ((i + 1) * 6),
					       (*mib_wlanfilterno_p - i) * 6);
					memset(mib->mib_wlanfiltermac +
					       *mib_wlanfilterno_p * 6, 0, 6);
				}
			}
			break;
		}
	}
	return 0;
}

int
mwl_drv_get_filtermac(struct net_device *netdev, char *buf)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	UCHAR buf1[48], *filter_buf = mib->mib_wlanfiltermac;
	char *out_buf = buf;
	int i;

	for (i = 0; i < FILERMACNUM; i++) {
		sprintf(buf1, "MAC %d: %02x:%02x:%02x:%02x:%02x:%02x\n",
			(i + 1), *(filter_buf + i * 6),
			*(filter_buf + i * 6 + 1), *(filter_buf + i * 6 + 2),
			*(filter_buf + i * 6 + 3), *(filter_buf + i * 6 + 4),
			*(filter_buf + i * 6 + 5));
		sprintf(out_buf, "%s", buf1);
		out_buf += strlen(buf1);
	}

	return 0;
}

int
mwl_drv_set_intrabss(struct net_device *netdev, uint8_t intrabss)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	if (intrabss > 1) {
		return -EOPNOTSUPP;
	} else {
		*(mib->mib_intraBSS) = intrabss;
	}

	return 0;
}

int
mwl_drv_get_intrabss(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return *(mib->mib_intraBSS);
}

int
mwl_drv_set_hidessid(struct net_device *netdev, uint8_t hidessid)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	if (hidessid > 1)
		return -EOPNOTSUPP;

	if (hidessid)
		*(mib->mib_broadcastssid) = 0;
	else
		*(mib->mib_broadcastssid) = 1;

	return 0;
}

int
mwl_drv_get_hidessid(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	if (*(mib->mib_broadcastssid))
		return 0;
	else
		return 1;
}

int
mwl_drv_set_bcninterval(struct net_device *netdev, uint16_t bcninterval)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	int rc = 0;

	if (bcninterval < 20 || bcninterval > 1000) {
		rc = -EOPNOTSUPP;
	} else {
		*(mib->mib_BcnPeriod) = bcninterval;
	}

	return rc;
}

int
mwl_drv_get_bcninterval(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return *(mib->mib_BcnPeriod);
}

int
mwl_drv_set_dtim(struct net_device *netdev, uint8_t dtim)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	int rc = 0;

	if (dtim < 1) {
		rc = -EOPNOTSUPP;
	} else {
		mib->StationConfig->DtimPeriod = dtim;
	}

	return rc;
}

int
mwl_drv_get_dtim(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return mib->StationConfig->DtimPeriod;
}

int
mwl_drv_set_gprotect(struct net_device *netdev, uint8_t gprotect)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	if (gprotect > 1)
		return -EOPNOTSUPP;

	if (gprotect)
		*(mib->mib_forceProtectiondisable) = 0;
	else
		*(mib->mib_forceProtectiondisable) = 1;

	return 0;
}

int
mwl_drv_get_gprotect(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	if (*(mib->mib_forceProtectiondisable))
		return 0;
	else
		return 1;
}

int
mwl_drv_set_preamble(struct net_device *netdev, uint8_t preamble)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	int rc = 0;

	switch (preamble) {
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

	return rc;
}

int
mwl_drv_get_preamble(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	switch (mib->StationConfig->mib_preAmble) {
	case PREAMBLE_AUTO_SELECT:
		return 0;
	case PREAMBLE_SHORT:
		return 1;
	case PREAMBLE_LONG:
		return 2;
	default:
		return 0xFF;
	}
}

int
mwl_drv_set_agingtime(struct net_device *netdev, uint32_t agingtime)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	int rc = 0;

	if (agingtime < 60 || agingtime > 86400) {
		rc = -EOPNOTSUPP;
	} else {
		*(mib->mib_agingtime) = agingtime;
	}

	return rc;
}

int
mwl_drv_get_agingtime(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return *(mib->mib_agingtime);
}

int
mwl_drv_set_ssid(struct net_device *netdev, const char *ssid, uint8_t ssid_len)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	memset(&(mib->StationConfig->DesiredSsId[0]), 0, 32);
	memcpy(&(mib->StationConfig->DesiredSsId[0]), ssid, ssid_len);

	return 0;
}

int
mwl_drv_get_ssid(struct net_device *netdev, char *ssid)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	uint8_t ssid_len;
	ssid_len = strlen(&(mib->StationConfig->DesiredSsId[0]));

	if (ssid_len) {
		memcpy(ssid, &(mib->StationConfig->DesiredSsId[0]), ssid_len);
	}

	return ssid_len;
}

int
mwl_drv_set_bssid(struct net_device *netdev, uint8_t * bssid)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	MIB_OP_DATA *mib_OpData = mib->OperationTable;

	memcpy(mib_OpData->StaMacAddr, bssid, 6);
	memcpy(netdev->dev_addr, bssid, 6);

	/*Unlike vmac, parent interface macBssId is not updated in SendStartCmd. So we update here */
	if (priv->master == NULL)
		memcpy(vmacSta_p->macBssId, bssid, 6);

	return 0;
}

int
mwl_drv_get_bssid(struct net_device *netdev, char *bssid)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	MIB_OP_DATA *mib_OpData = mib->OperationTable;

	sprintf(bssid, "MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
		mib_OpData->StaMacAddr[0],
		mib_OpData->StaMacAddr[1],
		mib_OpData->StaMacAddr[2],
		mib_OpData->StaMacAddr[3],
		mib_OpData->StaMacAddr[4], mib_OpData->StaMacAddr[5]);

	return 0;
}

int
mwl_drv_set_regioncode(struct net_device *netdev, uint8_t regioncode)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	MIB_SPECTRUM_MGMT *mib_SpectrumMagament_p = mib->SpectrumMagament;
	UINT32 Device_Region_Code = 0;

	// Check if region code is from device or from external
	if (wlFwGet_Device_Region_Code(netdev, &Device_Region_Code) != SUCCESS) {
		domainSetDomain(regioncode);
#ifdef IEEE80211_DH
		mib_SpectrumMagament_p->countryCode = regioncode;
#endif
		*(mib->mib_regionCode) = regioncode;
		printk("Setting Region Code to %d\n", regioncode);
	} else {
		printk("Setting Region Code not supported!\n");
	}
	return 0;
}

int
mwl_drv_get_regioncode(struct net_device *netdev, uint8_t * flag)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	UINT32 Device_Region_Code = 0;

	if (wlFwGet_Device_Region_Code(netdev, &Device_Region_Code) != SUCCESS) {
		*flag = 0;
	} else {
		*flag = 1;
	}

	return *(mib->mib_regionCode);
}

int
mwl_drv_set_ratemode(struct net_device *netdev, uint8_t ratemode)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	int rc = 0;

	if (ratemode > 1) {
		rc = -EINVAL;
	} else {
		*(mib->mib_RateAdaptMode) = ratemode;
	}

	return rc;
}

int
mwl_drv_get_ratemode(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return *(mib->mib_RateAdaptMode);
}

int
mwl_drv_set_wdsmode(struct net_device *netdev, uint8_t wdsmode)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	int rc = 0;

	if (wdsmode > 1) {
		rc = -EINVAL;
	} else {
		*(mib->mib_wdsEnable) = wdsmode;
	}

	return rc;
}

int
mwl_drv_get_wdsmode(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return *(mib->mib_wdsEnable);
}

int
mwl_drv_set_disableassoc(struct net_device *netdev, uint8_t disableassoc)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	int rc = 0;

	if (disableassoc > 1) {
		rc = -EINVAL;
	} else {
		*(mib->mib_disableAssoc) = disableassoc;
	}

	return rc;
}

int
mwl_drv_get_disableassoc(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return *(mib->mib_disableAssoc);
}

int
mwl_drv_set_wds(struct net_device *netdev, uint8_t * wds)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	int rc = 0;

#ifdef WDS_FEATURE
	UINT8 MacAddr[6], index = 0;
	UINT32 wdsPortMode = 0;

	index = wds[0];
	memcpy(MacAddr, &wds[1], 6);

#ifdef SOC_W8864
	wdsPortMode = wds[7];
#else
	wdsPortMode = 0xFF;
#endif
	if (!setWdsPort(netdev, MacAddr, index, wdsPortMode)) {
		rc = -ENODEV;
	} else {
		/* In order to show info correctly by getwds command, need to also fill in those parts */
		memcpy(priv->vmacSta_p->wdsPort[index].wdsMacAddr, MacAddr, 6);
		priv->vmacSta_p->wdsPort[index].active = 1;
	}

	return rc;
#else
	printk("Not supported to set wds.\n");
	rc = -ENODEV;
	return rc;
#endif

}

int
mwl_drv_get_wds(struct net_device *netdev, char *wds)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	UINT8 index = 0;
	UINT8 wdsModeStr[12];
	char *out_buf = wds;

	for (index = 0; validWdsIndex(index); index++) {
		getWdsModeStr(wdsModeStr,
			      priv->vmacSta_p->wdsPort[index].wdsPortMode);

		sprintf(out_buf,
			"ap0wds%x HWaddr %x:%x:%x:%x:%x:%x  802.%s Port %s \n",
			index, priv->vmacSta_p->wdsPort[index].wdsMacAddr[0],
			priv->vmacSta_p->wdsPort[index].wdsMacAddr[1],
			priv->vmacSta_p->wdsPort[index].wdsMacAddr[2],
			priv->vmacSta_p->wdsPort[index].wdsMacAddr[3],
			priv->vmacSta_p->wdsPort[index].wdsMacAddr[4],
			priv->vmacSta_p->wdsPort[index].wdsMacAddr[5],
			wdsModeStr,
			priv->vmacSta_p->wdsPort[index].
			active ? "Active" : "Inactive");
		out_buf += strlen(out_buf);
	}

	return 0;
}

#ifdef IEEE80211_DH
int
mwl_drv_set_11dmode(struct net_device *netdev, uint8_t dmode)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	MIB_SPECTRUM_MGMT *mib_SpectrumMagament_p = mib->SpectrumMagament;
	int rc = 0;

	if (dmode > 2) {
		rc = -EINVAL;
	} else {
		mib_SpectrumMagament_p->multiDomainCapability = dmode;
	}

	return rc;
}

int
mwl_drv_get_11dmode(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	MIB_SPECTRUM_MGMT *mib_SpectrumMagament_p = mib->SpectrumMagament;

	return mib_SpectrumMagament_p->multiDomainCapability;
}

int
mwl_drv_set_11hspecmgt(struct net_device *netdev, uint8_t hspecmgt)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	MIB_SPECTRUM_MGMT *mib_SpectrumMagament_p = mib->SpectrumMagament;
	int rc = 0;

	if (hspecmgt > 2) {
		rc = -EINVAL;
	} else {
		mib_SpectrumMagament_p->spectrumManagement = hspecmgt;
		mib->StationConfig->SpectrumManagementRequired =
			hspecmgt ? TRUE : FALSE;
		/* If spectrum management is enabled, set power constraint and
		 * country info.
		 */
		if (hspecmgt) {
			mib_SpectrumMagament_p->multiDomainCapability = 1;
		}
	}

	return rc;

}

int
mwl_drv_get_11hspecmgt(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	MIB_SPECTRUM_MGMT *mib_SpectrumMagament_p = mib->SpectrumMagament;

	return mib_SpectrumMagament_p->spectrumManagement;
}

int
mwl_drv_set_11hpwrconstr(struct net_device *netdev, uint8_t hpwrconstr)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	MIB_PHY_DSSS_TABLE *PhyDSSSTable = mib->PhyDSSSTable;
	MIB_SPECTRUM_MGMT *mib_SpectrumMagament_p = mib->SpectrumMagament;
	int rc = 0;

	if (hpwrconstr > 30) {
		rc = -EINVAL;
	} else {
		if (PhyDSSSTable->Chanflag.FreqBand != FREQ_BAND_5GHZ
#ifdef IEEE80211K
		    && !*(mib->mib_rrm)
#endif
			) {
			printk("mwl_drv_set_11hpwrconstr: wrong Freq band :%d\n", PhyDSSSTable->Chanflag.FreqBand);
			rc = -EOPNOTSUPP;
		} else {
			mib_SpectrumMagament_p->powerConstraint = hpwrconstr;
		}
	}

	return rc;

}

int
mwl_drv_get_11hpwrconstr(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	MIB_SPECTRUM_MGMT *mib_SpectrumMagament_p = mib->SpectrumMagament;

	return mib_SpectrumMagament_p->powerConstraint;
}

int
mwl_drv_set_11hcsaMode(struct net_device *netdev, uint8_t value)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	if (value < 0 || value > 1)
		return -EINVAL;

	mib->SpectrumMagament->csaMode = value;

	return 0;
}

int
mwl_drv_get_11hcsaMode(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return mib->SpectrumMagament->csaMode;
}

int
mwl_drv_set_11hcsaCount(struct net_device *netdev, uint8_t value)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	if (value < 0 || value > 255)
		return -EINVAL;

	mib->SpectrumMagament->csaCount = value;

	return 0;
}

int
mwl_drv_get_11hcsaCount(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return mib->SpectrumMagament->csaCount;
}

int
mwl_drv_set_11hdfsMode(struct net_device *netdev, uint8_t value)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	if (value < 0 || value > 3)
		return -EINVAL;

	if ((mib->PhyDSSSTable->Chanflag.FreqBand == FREQ_BAND_5GHZ) &&
	    (mib->PhyDSSSTable->CurrChan >= 52)) {

		wlFwSetRadarDetection(netdev, value);

		return 0;
	}

	return -EOPNOTSUPP;
}

int
mwl_drv_get_11hdfsMode(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);

	if (priv->wlpd_p->pdfsApMain)
		return (int)DfsGetCurrentState(priv->wlpd_p->pdfsApMain);
	else
		return 0;
}

int
mwl_drv_set_11hcsaChan(struct net_device *netdev, uint8_t value)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	if (!domainChannelValid(value, FREQ_BAND_5GHZ))
		return -EINVAL;

	mib->SpectrumMagament->csaChannelNumber = value;

	return 0;
}

int
mwl_drv_get_11hcsaChan(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return mib->SpectrumMagament->csaChannelNumber;
}

int
mwl_drv_set_11hcsaStart(struct net_device *netdev, uint8_t value)
{
	int i = 0;
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	IEEEtypes_ChannelSwitchCmd_t ChannelSwitchCmd;
	struct net_device *vdev = NULL;
	struct wlprivate *vpriv = NULL;

	if (value < 0 || value > 1) {
		return -EINVAL;
	}

	if (value == 0) {
		return 0;
	}

	if (mib->PhyDSSSTable->Chanflag.FreqBand != FREQ_BAND_5GHZ) {
		PRINT1(IOCTL, "wlioctl_priv_wlparam: wrong band %d\n",
		       mib->PhyDSSSTable->Chanflag.FreqBand);
		return -EOPNOTSUPP;
	}

	if (mib->StationConfig->SpectrumManagementRequired != TRUE) {
		PRINT1(IOCTL,
		       "wlioctl_priv_wlparam: spectrum management disabled\n");
		return -EOPNOTSUPP;
	}

	if (!domainChannelValid
	    (mib->SpectrumMagament->csaChannelNumber, FREQ_BAND_5GHZ)) {
		PRINT1(IOCTL, "wlioctl_priv_wlparam: wrong channel:%d\n",
		       mib->SpectrumMagament->csaChannelNumber);
		return -EOPNOTSUPP;
	}

	ChannelSwitchCmd.Mode = mib->SpectrumMagament->csaMode;
	ChannelSwitchCmd.ChannelNumber =
		mib->SpectrumMagament->csaChannelNumber;
	ChannelSwitchCmd.ChannelSwitchCount = mib->SpectrumMagament->csaCount;

	/* Send Channel Switch Command to all the AP virtual interfaces */
	for (i = 0; i <= MAX_VMAC_INSTANCE_AP; i++) {
		if (priv->vdev[i] && priv->vdev[i]->flags & IFF_RUNNING) {
			vdev = priv->vdev[i];
			vpriv = NETDEV_PRIV_P(struct wlprivate, vdev);
			SendChannelSwitchCmd(vpriv->vmacSta_p,
					     &ChannelSwitchCmd,
					     sizeof(ChannelSwitchCmd));
		}
	}

	return 0;
}
#endif

#ifdef MRVL_DFS
int
mwl_drv_set_11hnopTimeout(struct net_device *netdev, uint16_t value)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	if (value < 5 || value > 1800)
		return -EINVAL;

	*(mib->mib_NOPTimeOut) = value;

	return 0;
}

int
mwl_drv_get_11hnopTimeout(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return *(mib->mib_NOPTimeOut);
}

int
mwl_drv_set_11hcacTimeout(struct net_device *netdev, uint8_t value)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	if (value < 5 || value > 60)
		return -EINVAL;

	*(mib->mib_CACTimeOut) = value;

	return 0;
}

int
mwl_drv_get_11hcacTimeout(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return *(mib->mib_CACTimeOut);
}

#endif

int
mwl_drv_set_csMode(struct net_device *netdev, uint8_t value)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	if (value < 0 || value > 3)
		return -EINVAL;

	*(mib->mib_CSMode) = value;

	return 0;
}

int
mwl_drv_get_csMode(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return *(mib->mib_CSMode);
}

int
mwl_drv_set_guardIntv(struct net_device *netdev, uint8_t value)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	if (value < 0 || value > 2)
		return -ENOTSUPP;

	*(mib->mib_guardInterval) = value;

	return 0;
}

int
mwl_drv_get_guardIntv(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return *(mib->mib_guardInterval);
}

int
mwl_drv_set_extSubCh(struct net_device *netdev, uint8_t value)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	if (value > 2)
		return -EOPNOTSUPP;

	switch (mib->PhyDSSSTable->CurrChan) {
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
	*(mib->mib_extSubCh) = value;

	return 0;
}

int
mwl_drv_get_extSubCh(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return *(mib->mib_extSubCh);
}

int
mwl_drv_set_htProtect(struct net_device *netdev, uint8_t value)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	if (value > 4)
		return -ENOTSUPP;

	*(mib->mib_htProtect) = value;

	return 0;
}

int
mwl_drv_get_htProtect(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return *(mib->mib_htProtect);
}

int
mwl_drv_set_ampduFactor(struct net_device *netdev, uint8_t value)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	if (value > 3)
		return -EINVAL;

	*(mib->mib_ampdu_factor) = value;

	return 0;
}

int
mwl_drv_get_ampduFactor(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return *(mib->mib_ampdu_factor);
}

int
mwl_drv_set_ampduDen(struct net_device *netdev, uint8_t value)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	if (value > 7)
		return -EINVAL;

	*(mib->mib_ampdu_density) = value;

	return 0;
}

int
mwl_drv_get_ampduDen(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return *(mib->mib_ampdu_density);
}

#ifdef AMPDU_SUPPORT
int
mwl_drv_set_ampduTx(struct net_device *netdev, uint8_t value)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

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
		return -EINVAL;
	}

	return 0;
}

int
mwl_drv_get_ampduTx(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return *(mib->mib_AmpduTx);
}
#endif

int
mwl_drv_set_txPower(struct net_device *netdev, uint8_t value)
{
	/* To do, not support right now */
	return -ENOTSUPP;
}

static char cmdGetBuf[MAX_SCAN_BUF_SIZE];
int
mwl_drv_get_txPower(struct net_device *netdev)
{
	int i;
	char *out_buf = cmdGetBuf;
#if defined(EEPROM_REGION_PWRTABLE_SUPPORT)
	int j, k;
	int status = 0xFF;
	UINT8 region_code = 0;
	UINT8 number_of_channels = 0;	// number of channels in EEPROM region power table to fetch
	channel_power_tbl_t EEPROM_Channel_PwrTbl;

	// Clear out
	memset(&EEPROM_Channel_PwrTbl, 0x0, sizeof(channel_power_tbl_t));

	// Get preliminary data back first
	status = wlFwGet_EEPROM_PwrTbl(netdev, &EEPROM_Channel_PwrTbl,
				       &region_code, &number_of_channels, 0);
	if (status != SUCCESS) {
		printk("\nUnable to get EEPROM Power Table! Error: 0x%02x\n",
		       status);
	} else {
		printk("\nRegion Code: %d\n", region_code);
		printk("Number of Channels: %d\n\n", number_of_channels);
		for (j = 0; j < number_of_channels; j++) {
			// Fetch channel data from FW
			status = wlFwGet_EEPROM_PwrTbl(netdev,
						       &EEPROM_Channel_PwrTbl,
						       &region_code,
						       &number_of_channels, j);
			if (status != SUCCESS) {
				printk("\nUnable to get Channel Index %d! Error: 0x%02x\n", j, status);
				continue;
			}
			printk("\n%d ", EEPROM_Channel_PwrTbl.channel);
			for (k = 0; k < MAX_GROUP_PER_CHANNEL_RATE; k++) {
				printk("%d ",
				       (SINT8) EEPROM_Channel_PwrTbl.grpPwr[k]);
			}
			printk("\n");
			for (i = 0; i < HAL_TRPC_ID_MAX; i++) {
				printk("%d ",
				       (SINT8) EEPROM_Channel_PwrTbl.txPwr[i]);
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
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
#if defined(SOC_W8366)||defined(SOC_W8764)
	UINT16 powlist[TX_POWER_LEVEL_TOTAL];
#ifdef SOC_W8864
	UINT16 tmp_bw = mib->PhyDSSSTable->Chanflag.ChnlWidth;
#else
	UINT16 tmp_bw =
		(mib->PhyDSSSTable->Chanflag.ChnlWidth ==
		 CH_AUTO_WIDTH) ? CH_40_MHz_WIDTH : mib->PhyDSSSTable->Chanflag.
		ChnlWidth;
#endif

	wlFwGettxpower(netdev, powlist, mib->PhyDSSSTable->CurrChan,
		       mib->PhyDSSSTable->Chanflag.FreqBand, tmp_bw,
		       mib->PhyDSSSTable->Chanflag.ExtChnlOffset);
	sprintf(out_buf, "\nCurrent Channel Power level list (FW) :");
	out_buf += strlen("\nCurrent Channel Power level list (FW) :");
	for (i = 0; i < TX_POWER_LEVEL_TOTAL; i++) {
		sprintf(out_buf, "0x%02x ", powlist[i]);
		out_buf += strlen("0x00 ");
	}
	sprintf(out_buf, "\n");
	out_buf++;
#else
	char strBuf[14][32];
	if (*(mib->mib_ApMode) & AP_MODE_A_ONLY) {
		sprintf(out_buf, "\n20M(5G):\n");
		out_buf += strlen("\n20M(5G):\n");
		for (i = 0; i < PWTAGETRATETABLE20M_5G_ENTRY; i++) {
			sprintf(out_buf, "%03d 0x%02x 0x%02x 0x%02x\n",
				mib->PowerTagetRateTable20M_5G[i * 4 + 0],
				mib->PowerTagetRateTable20M_5G[i * 4 + 1],
				mib->PowerTagetRateTable20M_5G[i * 4 + 2],
				mib->PowerTagetRateTable20M_5G[i * 4 + 3]);
			out_buf += strlen("000 0x00 0x00 0x00\n");
		}
		sprintf(out_buf, "\n40M(5G):\n");
		out_buf += strlen("\n40M(5G):\n");
		for (i = 0; i < PWTAGETRATETABLE40M_5G_ENTRY; i++) {
			sprintf(out_buf, "%03d 0x%02x 0x%02x 0x%02x\n",
				mib->PowerTagetRateTable40M_5G[i * 4 + 0],
				mib->PowerTagetRateTable40M_5G[i * 4 + 1],
				mib->PowerTagetRateTable40M_5G[i * 4 + 2],
				mib->PowerTagetRateTable40M_5G[i * 4 + 3]);
			out_buf += strlen("000 0x00 0x00 0x00\n");
		}
	} else {		// 2.4G
		for (i = 0; i < 14; i++) {
			sprintf(&(strBuf[i][0]),
				"%02d:  0x%02x 0x%02x 0x%02x 0x%02x\n", i + 1,
				mib->PowerTagetRateTable20M[i * 4 + 0],
				mib->PowerTagetRateTable20M[i * 4 + 1],
				mib->PowerTagetRateTable20M[i * 4 + 2],
				mib->PowerTagetRateTable20M[i * 4 + 3]);
		}
		sprintf(out_buf, "\n20M(2.4G):\n%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
			strBuf[0], strBuf[1], strBuf[2], strBuf[3], strBuf[4],
			strBuf[5], strBuf[6], strBuf[7], strBuf[8], strBuf[9],
			strBuf[10], strBuf[11], strBuf[12], strBuf[13]);

		memset(&(strBuf[0][0]), 0, sizeof(strBuf));
		out_buf += strlen(out_buf);

		for (i = 0; i < 9; i++) {
			sprintf(&(strBuf[i][0]),
				"%02d:  0x%02x 0x%02x 0x%02x 0x%02x\n", i + 1,
				mib->PowerTagetRateTable40M[i * 4 + 0],
				mib->PowerTagetRateTable40M[i * 4 + 1],
				mib->PowerTagetRateTable40M[i * 4 + 2],
				mib->PowerTagetRateTable40M[i * 4 + 3]);
		}
		sprintf(out_buf, "\n40M(2.4G):\n%s%s%s%s%s%s%s%s%s",
			strBuf[0], strBuf[1], strBuf[2], strBuf[3], strBuf[4],
			strBuf[5], strBuf[6], strBuf[7], strBuf[8]);
	}
#endif
#endif //EEPROM_REGION_PWRTABLE_SUPPORT

	return 0;
}

int
mwl_drv_get_fwStat(struct net_device *netdev)
{
	wlFwGetHwStats(netdev, NULL);
	return 0;
}

int
mwl_drv_set_autoChannel(struct net_device *netdev, uint8_t value)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	if (value > 2)
		return -EINVAL;

	*(mib->mib_autochannel) = value;

	return 0;
}

int
mwl_drv_get_autoChannel(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return *(mib->mib_autochannel);
}

int
mwl_drv_set_maxTxPower(struct net_device *netdev, uint8_t value)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	int i;

	if (value < MINTXPOWER || value > 18) {
		return -EINVAL;
	}

	*(mib->mib_MaxTxPwr) = value;

	for (i = 0; i < TX_POWER_LEVEL_TOTAL; i++) {
		if (mib->PhyDSSSTable->maxTxPow[i] > *(mib->mib_MaxTxPwr))
			mib->PhyDSSSTable->maxTxPow[i] = *(mib->mib_MaxTxPwr);
	}

	return 0;
}

int
mwl_drv_get_maxTxPower(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return *(mib->mib_MaxTxPwr);
}

int
mwl_drv_del_wepKey(struct net_device *netdev, uint8_t value)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	if (value > 3)
		return -EINVAL;

	printk("wep key = %x %x %x %x %x %x %x %x %x %x %x %x %x \n",
	       //PRINT1(IOCTL, "wep key = %x %x %x %x %x %x %x %x %x %x %x %x %x \n",
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
	       mib->WepDefaultKeys[value].WepDefaultKeyValue[11],
	       mib->WepDefaultKeys[value].WepDefaultKeyValue[12]);

	memset(mib->WepDefaultKeys[value].WepDefaultKeyValue, 0, 13);

	printk("wep key = %x %x %x %x %x %x %x %x %x %x %x %x %x \n",
	       //PRINT1(IOCTL, "wep key = %x %x %x %x %x %x %x %x %x %x %x %x %x \n",
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
	       mib->WepDefaultKeys[value].WepDefaultKeyValue[11],
	       mib->WepDefaultKeys[value].WepDefaultKeyValue[12]);

	return 0;
}

int
mwl_drv_set_strictShared(struct net_device *netdev, uint8_t value)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	if (value > 1)
		return -EINVAL;

	*(mib->mib_strictWepShareKey) = value;

	return 0;
}

int
mwl_drv_get_strictShared(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return *(mib->mib_strictWepShareKey);
}

#ifdef PWRFRAC
int
mwl_drv_set_txPowerFraction(struct net_device *netdev, uint8_t value)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	if (value > 5)
		return -EINVAL;

	*(mib->mib_TxPwrFraction) = value;

	return 0;
}

int
mwl_drv_get_txPowerFraction(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return *(mib->mib_TxPwrFraction);
}
#endif
extern BOOLEAN macMgmtMlme_SendMimoPsHtManagementAction(vmacApInfo_t *
							vmacSta_p,
							IEEEtypes_MacAddr_t *
							Addr, UINT8 mode);
extern int wlFwSetMimoPsHt(struct net_device *netdev, UINT8 * addr,
			   UINT8 enable, UINT8 mode);
int
mwl_drv_set_mimops(struct net_device *netdev, int minops)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	int rc = 0;
	UINT8 addr[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	UINT8 i;
	UINT32 entries;
	UINT8 *staBuf = NULL;
	UINT8 *listBuf = NULL;
	extStaDb_StaInfo_t *pStaInfo;

	switch (minops) {
	case 0:
	case 1:
	case 3:
		*(mib->mib_psHtManagementAct) = (UINT8) minops;
		if (macMgmtMlme_SendMimoPsHtManagementAction
		    (vmacSta_p, (IEEEtypes_MacAddr_t *) & addr,
		     *(mib->mib_psHtManagementAct)) == TRUE) {
			entries = extStaDb_entries(vmacSta_p, 0);
			staBuf = kmalloc(entries * sizeof(STA_INFO),
					 GFP_KERNEL);
			if (staBuf != NULL) {
				extStaDb_list(vmacSta_p, staBuf, 1);

				if (entries) {
					listBuf = staBuf;
					for (i = 0; i < entries; i++) {
						if ((pStaInfo =
						     extStaDb_GetStaInfo
						     (vmacSta_p,
						      (IEEEtypes_MacAddr_t *)
						      listBuf, 0)) != NULL) {
							if ((pStaInfo->State ==
							     ASSOCIATED) &&
							    (pStaInfo->
							     ClientMode ==
							     NONLY_MODE)) {
								UINT8 enable =
									1;
								UINT8 mode =
									*(mib->
									  mib_psHtManagementAct);

								if (mode == 3) {
									enable = 0;
									mode = 0;
								}
								wlFwSetMimoPsHt
									(netdev,
									 listBuf,
									 enable,
									 mode);
							}
							listBuf +=
								sizeof
								(STA_INFO);
						}
					}
				}
			}
			kfree(staBuf);
		}
		break;
	default:
		rc = -EINVAL;
		break;
	}

	return rc;
}

int
mwl_drv_get_mimops(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return *(mib->mib_psHtManagementAct);
}

int
mwl_drv_set_txantenna(struct net_device *netdev, int txantenna)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	int rc = 0;

#ifdef SOC_W8764
	if (txantenna < 0 || txantenna > 0xf)
#else
	if (txantenna < 0 || txantenna > 7)
#endif
	{
		rc = -EOPNOTSUPP;
		return rc;
	}

	/* 0:AB(Auto), 1:A, 2:B, 3:AB, 7:ABC */
	*(mib->mib_txAntenna) = (UCHAR) txantenna;

	return rc;

}

int
mwl_drv_get_txantenna(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return *(mib->mib_txAntenna);
}

int
mwl_drv_set_htgf(struct net_device *netdev, int htgf)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	int rc = 0;

	if (htgf < 0 || htgf > 1) {
		rc = -EOPNOTSUPP;
		return rc;
	}
#ifdef SOC_W8363
	rc = -EOPNOTSUPP;
#else
	*(mib->mib_HtGreenField) = htgf;
#endif

	return rc;
}

int
mwl_drv_get_htgf(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return *(mib->mib_HtGreenField);
}

int
mwl_drv_set_htstbc(struct net_device *netdev, int htstbc)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	int rc = 0;

	if (htstbc < 0 || htstbc > 1) {
		rc = -EOPNOTSUPP;
		return rc;
	}
#if defined(SOC_W8366) || defined (SOC_W8764)
	//currently, W8366 supports stbc.
	*(mib->mib_HtStbc) = htstbc;
#else
	rc = -EOPNOTSUPP;
#endif

	return rc;
}

int
mwl_drv_get_htstbc(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return *(mib->mib_HtStbc);
}

int
mwl_drv_set_3x3rate(struct net_device *netdev, int rate3x3)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	int rc = 0;

	if (rate3x3 < 0 || rate3x3 > 1) {
		rc = -EOPNOTSUPP;
		return rc;
	}
#if defined(SOC_W8366)||defined(SOC_W8764)
	*(mib->mib_3x3Rate) = rate3x3;
#else
	rc = -EOPNOTSUPP;
#endif

	return rc;
}

int
mwl_drv_get_3x3rate(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return *(mib->mib_3x3Rate);
}

int
mwl_drv_set_intolerant40(struct net_device *netdev, unsigned char *param,
			 int data_len)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	int rc = 0;

#ifdef COEXIST_20_40_SUPPORT

	UINT8 protection2040;
	UINT8 mode = 0;

	printk("param0=%d, param1=%d data_len=%d \n", *param, *(param + 1),
	       data_len);

	if (data_len <= 0) {
		printk(" intolerant40 = %x HT40MIntoler=%x \n",
		       *(vmacSta_p->Mib802dot11->mib_FortyMIntolerant),
		       *(vmacSta_p->Mib802dot11->mib_HT40MIntoler));
		printk("shadow intolerant40 = %x HT40MIntoler=%x \n",
		       *(vmacSta_p->ShadowMib802dot11->mib_FortyMIntolerant),
		       *(vmacSta_p->ShadowMib802dot11->mib_HT40MIntoler));
	} else {
		if (data_len == 1) {
			mode = 0;
		} else if (data_len == 2) {
			mode = *(param + 1);
		}

		protection2040 = *param;

		if (protection2040 == 0) {
			*(vmacSta_p->ShadowMib802dot11->mib_HT40MIntoler) = 0;	/** 20/40 coexist protection mechanism off **/
			printk("Setting 20/40 Coexist off\n");

		}
		if (protection2040 == 1) {
			*(vmacSta_p->ShadowMib802dot11->mib_HT40MIntoler) = 1;	/** 20/40 coexist protection mechanism on **/
			printk("Setting 20/40 Coexist on\n");

		}

		else if (protection2040 == 2) {
			*(vmacSta_p->ShadowMib802dot11->mib_FortyMIntolerant) =
				1;
			printk("Setting tolerant AP\n");
		} else if (protection2040 == 3) {
			extern int wlFwSet11N_20_40_Switch(struct net_device
							   *netdev, UINT8 mode);

			*(vmacSta_p->ShadowMib802dot11->mib_FortyMIntolerant) =
				mode;
			*(mib->USER_ChnlWidth) = mode;

			wlFwSet11N_20_40_Switch(vmacSta_p->dev, mode);
			printk("Setting 20/40 with bw %d\n", mode);
		}
	}

#endif

	return rc;
}

int
mwl_drv_set_txqlimit(struct net_device *netdev, unsigned int txqlimit)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	int rc = 0;

	printk("txqlimit=%d \n", txqlimit);

	vmacSta_p->txQLimit = txqlimit;

	return rc;
}

int
mwl_drv_get_txqlimit(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;

	return vmacSta_p->txQLimit;
}

int
mwl_drv_set_rifs(struct net_device *netdev, unsigned char rifs)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	int rc = 0;

	printk("rifs=%d \n", rifs);

	*(mib->mib_rifsQNum) = rifs;

	return rc;
}

int
mwl_drv_set_bftype(struct net_device *netdev, int bftype)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	int rc = 0;

	*(mib->mib_bftype) = bftype;

	printk("bftype is %d\n", (int)*(mib->mib_bftype));

	return rc;
}

#ifdef BAND_STEERING
int
mwl_drv_set_bandsteer(struct net_device *netdev, uint8_t bandsteer)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	*(mib->mib_bandsteer) = bandsteer;

	return 0;
}

int
mwl_drv_get_bandsteer(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return *(mib->mib_bandsteer);
}
#endif

extern void *FindIEWithinIEs(UINT8 * data_p, UINT32 lenPacket, UINT8 attrib,
			     UINT8 * OUI);
int
mwl_drv_set_appie(struct net_device *netdev, struct mwl_appie *appie)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	MIB_802DOT11 *mib1 = vmacSta_p->Mib802dot11;

	WSC_COMB_IE_t APWSCIE;
	UINT16 ieType = 0;
	UINT8 *rsn_ie = NULL;
#ifdef MRVL_80211R
	UINT8 *md_ie = NULL;
#endif
#ifdef MULTI_AP_SUPPORT
	IEEEtypes_MultiAP_Element_t *MultiAP_IE_p = NULL;
	UINT8 MAP_OUI[4] = { 0x50, 0x6F, 0x9A, 0x1B };
	UINT16 version_len = 0;
#endif /*MULTI_AP_SUPPORT */

	memset(&APWSCIE, 0, sizeof(WSC_COMB_IE_t));

	if (appie == NULL)
		return -EINVAL;

	if (appie->len == 8) {
		memset(&vmacSta_p->thisbeaconIEs, 0, sizeof(WSC_BeaconIEs_t));
		memset(&vmacSta_p->thisprobeRespIEs, 0,
		       sizeof(WSC_ProbeRespIEs_t));
		vmacSta_p->WPSOn = 0;
	}

	switch (appie->type) {
	case WL_APPIE_IETYPE_RSN:
	case WL_OPTIE_BEACON_INCL_RSN:
	case WL_OPTIE_ASSOC_INCL_RSN:
		memset(vmacSta_p->RsnIE, 0, sizeof(IEEEtypes_RSN_IE_WPA2_t));

		rsn_ie = FindIEWithinIEs(appie->buf, appie->len, RSN_IEWPA2,
					 NULL);
#ifdef MRVL_80211R
		md_ie = FindIEWithinIEs(appie->buf, appie->len, MD_IE, NULL);
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
			memcpy(vmacSta_p->RsnIE, rsn_ie, appie->len);
		} else {
			memset(vmacSta_p->RsnIE, 0,
			       sizeof(IEEEtypes_RSN_IE_WPA2_t));
#ifdef CONFIG_IEEE80211W
			vmacSta_p->ieee80211wRequired = vmacSta_p->ieee80211w =
				0;
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
#ifndef WNM
		if (appie->len > 8) {
#endif /* WNM */

#if defined(CONFIG_HS2)
			IEEEtypes_INTERWORKING_Element_t *pIW;
			IEEEtypes_HS_INDICATION_Element_t *pHS2;
			IEEEtypes_Extended_Cap_Element_t *pEC;
			IEEEtypes_P2P_Element_t *pP2P;
			UINT8 oui[4] = { 0x50, 0x6f, 0x9a, 0x10 };
			UINT8 oui_p2p[4] = { 0x50, 0x6f, 0x9a, 0x9 };
#endif
			ieType = 0;
			APWSCIE.beaconIE.Len = appie->len;
			memcpy(&APWSCIE.beaconIE.WSCData[0], appie->buf,
			       appie->len);
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
				{
					printk("%s: P2P managable",
					       vmacSta_p->dev->name);
				}
				if (pP2P->P2P_mgmt_bitmap & 0x2)	//P2P cross connect permit
				{
					printk("%s: P2P cross connect permitted\n", vmacSta_p->dev->name);
				} else {
					printk("%s: P2P cross connect not permitted\n", vmacSta_p->dev->name);
				}
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

#ifndef WNM
		}
#endif /* WNM */
		break;
	case WL_APPIE_FRAMETYPE_PROBE_RESP:
#ifndef WNM
		if (appie->len > 8) {
#endif /* WNM */
			ieType = 1;
			APWSCIE.probeRespIE.Len = appie->len;
			memcpy(&APWSCIE.probeRespIE.WSCData[0], &appie->buf[0],
			       appie->len);
			memcpy(&vmacSta_p->thisprobeRespIEs,
			       &APWSCIE.probeRespIE,
			       sizeof(WSC_ProbeRespIEs_t));
			vmacSta_p->WPSOn = 1;
#ifndef WNM
		}
#endif /* WNM */
		break;
	case WL_AAPIE_FRAMETYPE_ASSOC_RESPONSE:
		break;
	case WL_OPTIE_PROBE_RESP_INCL_RSN:
		return 0;
	case WL_OPTIE_BEACON_NORSN:
#ifdef MULTI_AP_SUPPORT
		MultiAP_IE_p =
			FindIEWithinIEs(appie->buf, appie->len, PROPRIETARY_IE,
					MAP_OUI);
		if (MultiAP_IE_p != NULL) {
			//memcpy(&vmacSta_p->MultiAP_IE, MultiAP_IE_p, sizeof(struct IEEEtypes_MultiAP_Element_t));
			mib->multi_ap_attr = MAP_ATTRIBUTE_DISABLE;
			if (MultiAP_IE_p->attributes.TearDown)
				mib->multi_ap_attr |= MAP_ATTRIBUTE_TEARDOWN;
			if (MultiAP_IE_p->attributes.FrontBSS)
				mib->multi_ap_attr |=
					MAP_ATTRIBUTE_FRONTHAUL_BSS;
			if (MultiAP_IE_p->attributes.BackBSS)
				mib->multi_ap_attr |=
					MAP_ATTRIBUTE_BACKHAUL_BSS;
			/* Encode bit 3 and bit 4 for R2, Table 4. */
			if (MultiAP_IE_p->attributes.R1bSTAdisAllowed)
				mib->multi_ap_attr |=
					MAP_ATTRIBUTE_R1BSTA_DISALLOWED;
			if (MultiAP_IE_p->attributes.R2bSTAdisAllowed)
				mib->multi_ap_attr |=
					MAP_ATTRIBUTE_R2BSTA_DISALLOWED;
			mib1->multi_ap_attr = mib->multi_ap_attr;

			if (MultiAP_IE_p->Len >=
			    MAP_R1_IE_LEN +
			    sizeof(IEEEtypes_MultiAP_Version_t)) {
				IEEEtypes_MultiAP_Version_t *version =
					(IEEEtypes_MultiAP_Version_t *)
					MultiAP_IE_p->variable;

				if ((version->ElementId == 0x07) &&
				    (version->Len == 0x01)) {
					mib->multi_ap_ver = version->value;
					mib1->multi_ap_ver = mib->multi_ap_ver;
					version_len += version->Len + 2;
				}

				if ((version_len && (MultiAP_IE_p->Len >=
						     (MAP_R1_IE_LEN +
						      sizeof
						      (IEEEtypes_MultiAP_Version_t)
						      +
						      sizeof
						      (IEEEtypes_MultiAP_Traffic_t))))
				    || (MultiAP_IE_p->Len >=
					(MAP_R1_IE_LEN +
					 sizeof(IEEEtypes_MultiAP_Traffic_t))))
				{
					IEEEtypes_MultiAP_Traffic_t *traffic =
						(IEEEtypes_MultiAP_Traffic_t
						 *) (MultiAP_IE_p->variable +
						     version_len);

					if ((traffic->ElementId == 0x08) &&
					    (traffic->Len == 0x02)) {
						mib->multi_ap_vid =
							traffic->vid;
						mib1->multi_ap_vid =
							mib->multi_ap_vid;
					}
				}
			}
		}
#endif /*MULTI_AP_SUPPORT */
		break;
	case WL_OPTIE_PROBE_RESP_NORSN:
		return 0;
	default:
		{
			/* Remove beacon IE */
			memset(&vmacSta_p->thisbeaconIEs, 0,
			       sizeof(WSC_BeaconIEs_t));
			ieType = 0;
			if (wlFwSetWscIE(netdev, ieType, &APWSCIE)) {
				WLDBG_EXIT_INFO(DBG_LEVEL_1,
						"Failed setting WSC IE");
			}

			/* Remove Probe response IE */
			memset(&vmacSta_p->thisprobeRespIEs, 0,
			       sizeof(WSC_ProbeRespIEs_t));
			ieType = 1;
			if (wlFwSetWscIE(netdev, ieType, &APWSCIE)) {
				WLDBG_EXIT_INFO(DBG_LEVEL_1,
						"Failed setting WSC IE");
			}

			vmacSta_p->WPSOn = 0;
			return 0;
		}
	}

	if (wlFwSetWscIE(netdev, ieType, &APWSCIE)) {
		WLDBG_EXIT_INFO(DBG_LEVEL_1, "Failed setting WSC IE");
	}

	return 0;
}

int
mwl_drv_get_ie(struct net_device *netdev, uint8_t ie_type, uint8_t * macaddr,
	       uint16_t * ie_len, uint8_t * reassoc, uint8_t * ie)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
#ifdef MRVL_80211R
	uint8_t buf[256];
	uint16_t len;
#endif

	if (ie_type == RSN_IEWPA2) {
		if (extStaDb_GetRSN_IE
		    (vmacSta_p, (IEEEtypes_MacAddr_t *) macaddr,
		     ie) != STATE_SUCCESS)
			return -EFAULT;

		if (ie[1] > 0)
			*ie_len = ie[1] + 2;
		else
			*ie_len = 0;
#ifdef MRVL_80211R
		if (extStaDb_Get_11r_IEs
		    (vmacSta_p, (IEEEtypes_MacAddr_t *) macaddr, buf, &len,
		     reassoc) == STATE_SUCCESS) {
			if (len != 0) {
				memcpy(&ie[*ie_len], buf, len);
				*ie_len += len;
			}
		}
#endif
		return 0;
	} else if (ie_type == EXTENSION) {
#ifdef OWE_SUPPORT
		extStaDb_StaInfo_t *pStaInfo;
		pStaInfo =
			extStaDb_GetStaInfo(vmacSta_p,
					    (IEEEtypes_MacAddr_t *) macaddr, 0);

		if (pStaInfo->STA_DHIEBuf[1] > 0)
			*ie_len = pStaInfo->STA_DHIEBuf[1] + 2;
		else
			*ie_len = 0;

		memcpy(ie, &pStaInfo->STA_DHIEBuf[0], *ie_len);
#endif /* OWE_SUPPORT */
		return 0;
	}
	return -EOPNOTSUPP;
}

int
mwl_drv_send_mlme(struct net_device *netdev, struct mwl_mlme *mlme)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;

	switch (mlme->op) {
		extern extStaDb_Status_e extStaDb_RemoveSta(vmacApInfo_t *
							    vmac_p,
							    IEEEtypes_MacAddr_t
							    * Addr_p);
	case WL_MLME_DEAUTH:
		macMgmtMlme_SendDeauthenticateMsg(vmacSta_p, &mlme->macaddr, 0,
						  mlme->reason);
		if (vmacSta_p->wtp_info.mac_mode != WTP_MAC_MODE_SPLITMAC) {
			//RemoveSta when non-splitmac mode
			extStaDb_RemoveSta(vmacSta_p, &mlme->macaddr);
		}
		break;
	case WL_MLME_DISASSOC:
		macMgmtMlme_SendDisassociateMsg(vmacSta_p, &mlme->macaddr, 0,
						mlme->reason);
		break;
#ifdef WTP_SUPPORT
	case WL_MLME_AUTHORIZE:
		macMgmtMlme_set_sta_authorized(vmacSta_p, &mlme->macaddr);
		break;

	case WL_MLME_ASSOC:
		macMgmtMlme_set_sta_associated(vmacSta_p, &mlme->macaddr,
					       mlme->aid,
					       (PeerInfo_t *) & mlme->peer_info,
					       mlme->qos_info, mlme->is_qos_sta,
					       mlme->rsn_sta, mlme->rsn_ie);
		break;

	case WL_MLME_DELSTA:
		macMgmtMlme_del_sta_entry(vmacSta_p, &mlme->macaddr);
		break;
#endif
#ifdef MRVL_80211R
	case WL_MLME_SET_ASSOC:
	case WL_MLME_SET_REASSOC:
		macMgmtMlme_SendAssocMsg(vmacSta_p,
					 (IEEEtypes_MacAddr_t *) & mlme->
					 macaddr, mlme->optie, mlme->optie_len);
		break;
	case WL_MLME_SET_AUTH:
		macMgmtMlme_SendAuthenticateMsg(vmacSta_p,
						(IEEEtypes_MacAddr_t *) & mlme->
						macaddr, mlme->seq,
						mlme->reason, mlme->optie,
						mlme->optie_len);
		break;
#endif
	default:
		return -EOPNOTSUPP;
	}
	return 0;
}

int
mwl_drv_set_countermeasures(struct net_device *netdev, int enabled)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;

	if (enabled) {
		vmacSta_p->MIC_ErrordisableStaAsso = 1;
		macMgmtMlme_SendDeauthenticateMsg(vmacSta_p, &bcastMacAddr, 0,
						  IEEEtypes_REASON_MIC_FAILURE);
		extStaDb_RemoveAllStns(vmacSta_p, IEEEtypes_REASON_MIC_FAILURE);
	} else {
		vmacSta_p->MIC_ErrordisableStaAsso = 0;
	}
	return 0;
}

int
mwl_drv_get_seqnum(struct net_device *netdev, uint8_t * seqnum)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
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
mwl_drv_send_mgmt(struct net_device *netdev, struct mwl_mgmt *mgmt)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	IEEEtypes_Frame_t *wlanMsg_p;

#ifdef BAND_STEERING
	wlanMsg_p = (IEEEtypes_Frame_t *) mgmt;

	if (memcmp(wlanMsg_p->Hdr.Addr1, vmacSta_p->macBssId, 6) == 0 ||
	    memcmp(wlanMsg_p->Hdr.Addr1, bcastMacAddr, 6) == 0) {
		struct sk_buff *skb = wl_alloc_skb(mgmt->len + 2);
		if (skb == NULL) {
			printk("band steering alloc skb failed\n");
			return -ENOMEM;
		}

		memcpy(skb->data + 2, mgmt->buf, mgmt->len);
		skb_put(skb, mgmt->len + 2);
		skb_pull(skb, 2);

		wlanMsg_p = (IEEEtypes_Frame_t *) ((UINT8 *) skb->data - 2);
		wlanMsg_p->Hdr.FrmBodyLen = skb->len;

		switch (wlanMsg_p->Hdr.FrmCtl.Subtype) {
			extern SINT8 evtDot11MgtMsg(vmacApInfo_t * vmacSta_p,
						    UINT8 * message,
						    struct sk_buff *skb,
						    UINT32 rssi);
		case IEEE_MSG_PROBE_RQST:
			if (memcmp(wlanMsg_p->Hdr.Addr1, bcastMacAddr, 6) == 0)
				memcpy(wlanMsg_p->Hdr.Addr1,
				       vmacSta_p->macBssId, 6);
			macMgmtMlme_ProbeRqst(vmacSta_p,
					      (macmgmtQ_MgmtMsg3_t *)
					      wlanMsg_p);
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
		uint8_t *ptr;
		struct sk_buff *txSkb_p = wl_alloc_skb(mgmt->len + 64);
		memcpy(txSkb_p->data, mgmt->buf, 24);
		memcpy(txSkb_p->data + 30, &mgmt->buf[24], mgmt->len - 24);
		ptr = txSkb_p->data - 2;
		ptr[0] = (mgmt->len + 6) >> 8;
		ptr[1] = (mgmt->len + 6);
		skb_put(txSkb_p, mgmt->len + 6);

		wlanMsg_p = (IEEEtypes_Frame_t *) ((UINT8 *) txSkb_p->data - 2);

		if (wlanMsg_p->Hdr.FrmCtl.Subtype == IEEE_MSG_AUTHENTICATE) {
			extern extStaDb_StaInfo_t *macMgtStaDbInit(vmacApInfo_t
								   * vmacSta_p,
								   IEEEtypes_MacAddr_t
								   * staMacAddr,
								   IEEEtypes_MacAddr_t
								   * apMacAddr);
			extern void macMgmtRemoveSta(vmacApInfo_t * vmacSta_p,
						     extStaDb_StaInfo_t *
						     StaInfo_p);
			extStaDb_StaInfo_t *pStaInfo;
			macmgmtQ_MgmtMsg3_t *MgmtMsg_p = wlanMsg_p;

			if ((pStaInfo =
			     extStaDb_GetStaInfo(vmacSta_p,
						 &wlanMsg_p->Hdr.Addr1,
						 0)) == NULL) {
				//added call to check other VAP's pStaInfo
				if ((pStaInfo =
				     extStaDb_GetStaInfo(vmacSta_p,
							 &wlanMsg_p->Hdr.Addr1,
							 2)))
					macMgmtRemoveSta(vmacSta_p, pStaInfo);
				if ((pStaInfo =
				     macMgtStaDbInit(vmacSta_p,
						     &wlanMsg_p->Hdr.Addr1,
						     (IEEEtypes_MacAddr_t *)
						     vmacSta_p->macBssId)) ==
				    NULL) {
					wl_free_skb(txSkb_p);
					WLDBG_ENTER_INFO(DBG_LEVEL_11,
							 "init data base fail\n");
					return -1;
				}
			}

			if (MgmtMsg_p->Body.Auth.AuthAlg == 0x03 &&
			    MgmtMsg_p->Body.Auth.AuthTransSeq == 0x02 &&
			    MgmtMsg_p->Body.Auth.StatusCode == 0x00) {
				if (pStaInfo->State != ASSOCIATED)
					pStaInfo->State = AUTHENTICATED;
			}
		}
#ifdef OWE_SUPPORT
		if ((wlanMsg_p->Hdr.FrmCtl.Subtype == IEEE_MSG_ASSOCIATE_RSP) ||
		    (wlanMsg_p->Hdr.FrmCtl.Subtype ==
		     IEEE_MSG_REASSOCIATE_RSP)) {
			extern SINT8 evtDot11MgtMsg(vmacApInfo_t * vmacSta_p,
						    UINT8 * message,
						    struct sk_buff *skb,
						    UINT32 rssi);
			IEEEtypes_Frame_t *Msg_p;
			UINT8 *temp_p = NULL;
			extStaDb_StaInfo_t *pStaInfo;
			macmgmtQ_MgmtMsg3_t *MgmtMsg_p =
				(macmgmtQ_MgmtMsg3_t *) wlanMsg_p;

			pStaInfo =
				extStaDb_GetStaInfo(vmacSta_p,
						    &wlanMsg_p->Hdr.Addr1, 0);
			if (pStaInfo == NULL) {
				wl_free_skb(txSkb_p);
				return 0;
			}

			temp_p = FindIEWithinIEs(&wlanMsg_p->Body[0] + 6,
						 mgmt->len - 6 -
						 sizeof(IEEEtypes_GenHdr_t) +
						 sizeof(UINT16), EXTENSION,
						 NULL);
			if (temp_p) {
				memcpy(&pStaInfo->AP_DHIEBuf[0], temp_p,
				       *(temp_p + 1) + 2);
			}

			memset(pStaInfo->EXT_RsnIE, 0, 64);
			temp_p = FindIEWithinIEs(&wlanMsg_p->Body[0] + 6,
						 mgmt->len - 6 -
						 sizeof(IEEEtypes_GenHdr_t) +
						 sizeof(UINT16), RSN_IEWPA2,
						 NULL);
			if (temp_p) {
				memcpy(&pStaInfo->EXT_RsnIE[0], temp_p,
				       *(temp_p + 1) + 2);
			}

			Msg_p = (IEEEtypes_Frame_t *) ((UINT8 *) pStaInfo->
						       assocReq_skb->data - 2);
			Msg_p->Hdr.FrmBodyLen = pStaInfo->assocReq_skb->len;

			if (MgmtMsg_p->Body.AssocRsp.StatusCode ==
			    IEEEtypes_STATUS_SUCCESS)
				evtDot11MgtMsg(vmacSta_p, (UINT8 *) Msg_p,
					       pStaInfo->assocReq_skb,
					       pStaInfo->assocReq_skb_rssi);

			wl_free_skb(pStaInfo->assocReq_skb);
			pStaInfo->assocReq_skb = NULL;

			if (MgmtMsg_p->Body.AssocRsp.StatusCode ==
			    IEEEtypes_STATUS_SUCCESS) {
				wl_free_skb(txSkb_p);
				return 0;
			}
		}
#endif /* OWE_SUPPORT */
		if (txMgmtMsg(vmacSta_p->dev, txSkb_p) != OS_SUCCESS)
			wl_free_skb(txSkb_p);
	}

	return 0;
}

int
mwl_drv_set_rts(struct net_device *netdev, uint16_t rts)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	int rc = 0;

	WLDBG_ENTER(DBG_LEVEL_1);
	if (priv->master) {
		printk("This parameter cannot be set to virtual interface %s, please use %s instead!\n", netdev->name, priv->master->name);
		rc = -EOPNOTSUPP;
		return rc;
	}
	/* turn off RTS/CTS for 11ac taffic when rts threshold is set to 0.
	   The actual rts threshold will be still set to 2437 */
	if (rts == 0) {
		wlFwSetRTSThreshold(netdev, 0);
	}

	if ((rts < 255) || (rts > 2346))
		rts = 2347;
	*(mib->mib_RtsThresh) = rts;

	printk("RTS threshold is set to %d\n", *(mib->mib_RtsThresh));
	WLDBG_EXIT(DBG_LEVEL_1);

	return 0;

}

int
mwl_drv_set_channel(struct net_device *netdev, uint8_t channel)
{
	extern BOOLEAN force_5G_channel;
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	MIB_PHY_DSSS_TABLE *PhyDSSSTable = mib->PhyDSSSTable;
	UINT8 *mib_extSubCh_p = mib->mib_extSubCh;
	int rc = 0;

	WLDBG_ENTER_INFO(DBG_LEVEL_1, "");

	if (priv->master) {
		printk("This parameter cannot be set to virtual interface %s, please use %s instead!\n", netdev->name, priv->master->name);
		rc = -EOPNOTSUPP;
		return rc;
	}

	if (channel) {
#ifdef MRVL_DFS
		/*Check if the target channel is a DFS channel and in NOL.
		 * If so, do not let the channel to change.
		 */
		if (DfsPresentInNOL(netdev, channel)) {
			//#ifdef DEBUG_PRINT
			printk("Target channel :%d is already in NOL\n",
			       channel);
			//#endif
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
			if (PhyDSSSTable->CurrChan == 14) {
				PhyDSSSTable->Chanflag.ChnlWidth =
					CH_20_MHz_WIDTH;
			}

			if (PhyDSSSTable->CurrChan >= 36)	//only apply for 5G
			{
				UINT8 domainCode, domainInd_IEEERegion;

				domainCode = domainGetDomain();	// get current domain
				domainInd_IEEERegion =
					GetDomainIndxIEEERegion(domainCode);
				switch (PhyDSSSTable->Chanflag.ChnlWidth) {
				case CH_40_MHz_WIDTH:
					if (IsTestchannel40MzChannel
					    (channel,
					     domainInd_IEEERegion) == FALSE) {
						PhyDSSSTable->Chanflag.
							ChnlWidth =
							CH_20_MHz_WIDTH;
					}
					break;
				case CH_80_MHz_WIDTH:
					if (IsTestchannel80MzChannel
					    (channel,
					     domainInd_IEEERegion) == FALSE) {
						if (IsTestchannel40MzChannel
						    (channel,
						     domainInd_IEEERegion) ==
						    FALSE) {
							PhyDSSSTable->Chanflag.
								ChnlWidth =
								CH_20_MHz_WIDTH;
						} else {
							PhyDSSSTable->Chanflag.
								ChnlWidth =
								CH_40_MHz_WIDTH;
						}
					}

					break;
				case CH_160_MHz_WIDTH:
				case CH_AUTO_WIDTH:
					if (Is160MzChannel
					    (channel,
					     domainInd_IEEERegion) == FALSE) {
						if (IsTestchannel80MzChannel
						    (channel,
						     domainInd_IEEERegion) ==
						    FALSE) {
							if (IsTestchannel40MzChannel(channel, domainInd_IEEERegion) == FALSE) {
								PhyDSSSTable->
									Chanflag.
									ChnlWidth
									=
									CH_20_MHz_WIDTH;
							} else {
								PhyDSSSTable->
									Chanflag.
									ChnlWidth
									=
									CH_40_MHz_WIDTH;
							}
						} else {
							PhyDSSSTable->Chanflag.
								ChnlWidth =
								CH_80_MHz_WIDTH;
						}
					}
					break;
				}
			}
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

	return 0;

}

int
mwl_drv_set_wepkey(struct net_device *netdev, uint8_t * data, int key_len)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	int rc = 0;
	uint8_t encode, index;

	encode = data[0] >> 4;
	index = data[0] & 0x0F;

	if (encode & MWL_WEP_ENCODE_DISABLED) {
		printk("mwl_drv_set_wepkey: MWL_WEP_ENCODE_DISABLED\n");
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
		printk("mwl_drv_set_wepkey: MWL_WEP_ENCODE_ENABLED\n");
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
			if ((index < 0) || (index > 3))
				*(mib->mib_defaultkeyindex) = index = 0;
			else
				*(mib->mib_defaultkeyindex) = index;

			printk("mwl_drv_set_wepkey: MWL_WEP_ENCODE_OPEN\n");
			mib->AuthAlg->Type = 0;
			WL_FUN_SetAuthType((void *)priv, 0);
		}
		if (encode & MWL_WEP_ENCODE_RESTRICTED) {
			if ((index < 0) || (index > 3))
				*(mib->mib_defaultkeyindex) = index = 0;
			else
				*(mib->mib_defaultkeyindex) = index;

			printk("mwl_drv_set_wepkey: MWL_WEP_ENCODE_RESTRICTED\n");
			mib->AuthAlg->Type = 1;
			WL_FUN_SetAuthType((void *)priv, 1);
		}
		if (key_len > 0)	//set open/restracted mode at [1] len=1
		{
			int wep_type = 1;
			UCHAR tmpWEPKey[13];

			if (key_len > 13)
				return -EINVAL;

			if ((index < 0) || (index > 3))
				*(mib->mib_defaultkeyindex) = index = 0;
			else
				*(mib->mib_defaultkeyindex) = index;

			if (key_len == 5) {
				wep_type = 1;
				mib->WepDefaultKeys[index].WepType = wep_type;

			}
			if (key_len == 13) {
				wep_type = 2;
				mib->WepDefaultKeys[index].WepType = wep_type;
			}
			memset(mib->WepDefaultKeys[index].WepDefaultKeyValue, 0,
			       13);
			memcpy(tmpWEPKey, &data[1], key_len);
			memcpy(mib->WepDefaultKeys[index].WepDefaultKeyValue,
			       tmpWEPKey, key_len);
			if (WL_FUN_SetWEPKey
			    ((void *)priv, index, wep_type, tmpWEPKey)) {
				printk("mwl_drv_set_wepkey: length = %d index = %d type = %d\n", key_len, index, wep_type);
				printk("wep key = %x %x %x %x %x %x %x %x %x %x %x %x %x \n", mib->WepDefaultKeys[index].WepDefaultKeyValue[0], mib->WepDefaultKeys[index].WepDefaultKeyValue[1], mib->WepDefaultKeys[index].WepDefaultKeyValue[2], mib->WepDefaultKeys[index].WepDefaultKeyValue[3], mib->WepDefaultKeys[index].WepDefaultKeyValue[4], mib->WepDefaultKeys[index].WepDefaultKeyValue[5], mib->WepDefaultKeys[index].WepDefaultKeyValue[6], mib->WepDefaultKeys[index].WepDefaultKeyValue[7], mib->WepDefaultKeys[index].WepDefaultKeyValue[8], mib->WepDefaultKeys[index].WepDefaultKeyValue[9], mib->WepDefaultKeys[index].WepDefaultKeyValue[10], mib->WepDefaultKeys[index].WepDefaultKeyValue[11], mib->WepDefaultKeys[index].WepDefaultKeyValue[12]);
			} else
				rc = -EIO;
		}
	}

	return rc;
}

#ifdef MRVL_WAPI
int
mwl_drv_set_wapimode(struct net_device *netdev, uint8_t wapimode)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	if (wapimode == 0) {
		mib->Privacy->WAPIEnabled = wapimode;
	} else {
		printk("Note: wapimode only can be enabled by wapid\n");
		return -ENOTSUPP;
	}

	return 0;
}

int
mwl_drv_get_wapimode(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return mib->Privacy->WAPIEnabled;
}
#endif

int
mwl_drv_set_wmmackpolicy(struct net_device *netdev, uint8_t wmmackpolicy)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	if (wmmackpolicy < 0 || wmmackpolicy > 3)
		return -EOPNOTSUPP;
	*(mib->mib_wmmAckPolicy) = wmmackpolicy;

	return 0;
}

int
mwl_drv_get_wmmackpolicy(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return *(mib->mib_wmmAckPolicy);
}

int
mwl_drv_set_txantenna2(struct net_device *netdev, uint8_t txantenna2)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	*(mib->mib_txAntenna2) = txantenna2;

	return 0;
}

int
mwl_drv_get_txantenna2(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return *(mib->mib_txAntenna2);
}

int
mwl_drv_get_deviceinfo(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);

	return priv->wlpd_p->CardDeviceInfo;
}

#ifdef INTEROP
int
mwl_drv_set_interop(struct net_device *netdev, uint8_t interop)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	*(mib->mib_interop) = interop;

	return 0;
}

int
mwl_drv_get_interop(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return *(mib->mib_interop);
}
#endif

int
mwl_drv_set_11hETSICAC(struct net_device *netdev, uint16_t timeout)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	*(mib->mib_ETSICACTimeOut) = timeout;

	return 0;
}

int
mwl_drv_get_11hETSICAC(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return *(mib->mib_ETSICACTimeOut);
}

int
mwl_drv_set_rxintlimit(struct net_device *netdev, uint32_t value)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;

	vmacSta_p->work_to_do = value;

	return 0;
}

int
mwl_drv_get_rxintlimit(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;

	return vmacSta_p->work_to_do;
}

#if defined ( INTOLERANT40) ||defined (COEXIST_20_40_SUPPORT)
int
mwl_drv_set_intoler(struct net_device *netdev, uint8_t value)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	if (value < 0 || value > 1)
		return -EINVAL;

	*(mib->mib_HT40MIntoler) = value;

	return 0;
}

int
mwl_drv_get_intoler(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return *(mib->mib_HT40MIntoler);
}
#endif

#ifdef RXPATHOPT
int
mwl_drv_set_rxpathopt(struct net_device *netdev, uint32_t value)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	if (value < 0 || value > 1500)
		return -EOPNOTSUPP;
	*(mib->mib_RxPathOpt) = value;

	return 0;
}

int
mwl_drv_get_rxpathopt(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return *(mib->mib_RxPathOpt);
}
#endif

int
mwl_drv_set_amsduft(struct net_device *netdev, uint16_t value)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	*(mib->mib_amsdu_flushtime) = value;

	return 0;
}

int
mwl_drv_get_amsduft(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return *(mib->mib_amsdu_flushtime);
}

int
mwl_drv_set_amsdums(struct net_device *netdev, uint16_t value)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	*(mib->mib_amsdu_maxsize) = value;

	return 0;
}

int
mwl_drv_get_amsdums(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return *(mib->mib_amsdu_maxsize);
}

int
mwl_drv_set_amsduas(struct net_device *netdev, uint16_t value)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	*(mib->mib_amsdu_allowsize) = value;

	return 0;
}

int
mwl_drv_get_amsduas(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return *(mib->mib_amsdu_allowsize);
}

int
mwl_drv_set_amsdupc(struct net_device *netdev, uint8_t value)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	*(mib->mib_amsdu_pktcnt) = value;

	return 0;
}

int
mwl_drv_get_amsdupc(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return *(mib->mib_amsdu_pktcnt);
}

int
mwl_drv_set_ccd(struct net_device *netdev, uint32_t value)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	if (value < 0 || value > 1)
		return -EINVAL;

	*(mib->mib_CDD) = value;

	return 0;
}

int
mwl_drv_get_ccd(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return *(mib->mib_CDD);
}

int
mwl_drv_set_acsthrd(struct net_device *netdev, uint32_t value)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	if (value < 0)
		return -EINVAL;

	*(mib->mib_acs_threshold) = value;

	return 0;
}

int
mwl_drv_get_acsthrd(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return *(mib->mib_acs_threshold);
}

int
mwl_drv_get_deviceid(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);

	return priv->devid;
}

#ifdef IEEE80211K
int
mwl_drv_set_rrm(struct net_device *netdev, uint8_t value)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	*(mib->mib_rrm) = value;

	return 0;
}

int
mwl_drv_get_rrm(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return *(mib->mib_rrm);
}
#endif

#ifdef CLIENT_SUPPORT
int
mwl_drv_set_autoscan(struct net_device *netdev, uint8_t value)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	if ((value != 0) && (value != 1))
		return -EOPNOTSUPP;

	*(mib->mib_STAAutoScan) = value;

	return 0;
}

int
mwl_drv_get_autoscan(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return *(mib->mib_STAAutoScan);
}
#endif

#ifdef DOT11V_DMS
int
mwl_drv_set_dms(struct net_device *netdev, uint32_t value)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	if ((value == 0) || (value == 1)) {
		*(mib->mib_dms) = value;
	} else {
		printk("dms input must be 0 or 1\n");
		return -EINVAL;
	}

	return 0;
}

int
mwl_drv_get_dms(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return *(mib->mib_dms);
}
#endif

int
mwl_drv_get_sysload(struct net_device *netdev)
{
	radio_cpu_load_t sys_load;
	if (wlFwGetSysLoad(netdev, &sys_load) == SUCCESS) {
		printk("1s:%d 4s:%d 8s:%d 16s:%d\n", sys_load.load_onesec,
		       sys_load.load_foursec, sys_load.load_eightsec,
		       sys_load.load_sixteensec);
	} else {
		printk("FW doesn't support sysload\n");
		return -EFAULT;
	}

	return 0;
}

#ifdef MRVL_DFS
int
mwl_drv_get_11hNOCList(struct net_device *netdev, uint8_t * buff)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);

	if (priv->wlpd_p->pdfsApMain) {
		DfsPrintNOLChannelDetails(priv->wlpd_p->pdfsApMain, buff, 4000);
		return strlen(buff);
	} else {
		return -EFAULT;
	}
}
#endif

#if defined(CLIENT_SUPPORT) && defined (MRVL_WSC)
int
mwl_drv_get_bssprofile(struct net_device *netdev, uint8_t * buff)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;

	MRVL_SCAN_ENTRY *siteSurvey = (MRVL_SCAN_ENTRY *) buff;

	scanDescptHdr_t *curDescpt_p = NULL;
	UINT16 parsedLen = 0;
	int i;

	printk("INSIDE getbssprofile\n");
	printk("Found :%d number of scan respults\n",
	       tmpNumScanDesc[vmacSta_p->VMacEntry.phyHwMacIndx]);
	if (vmacSta_p->busyScanning)
		return -EFAULT;
	for (i = 0; i < tmpNumScanDesc[vmacSta_p->VMacEntry.phyHwMacIndx]; i++) {
		curDescpt_p =
			(scanDescptHdr_t
			 *) (&tmpScanResults[vmacSta_p->VMacEntry.
					     phyHwMacIndx][0] + parsedLen);

		if ((smeSetBssProfile
		     (0, curDescpt_p->bssId, curDescpt_p->CapInfo,
		      (((UINT8 *) curDescpt_p) + sizeof(scanDescptHdr_t)),
		      curDescpt_p->length + sizeof(curDescpt_p->length) -
		      sizeof(scanDescptHdr_t), FALSE)) == MLME_SUCCESS) {
			memset(&siteSurveyEntry, 0, sizeof(MRVL_SCAN_ENTRY));
			//                                      smeCopyBssProfile( 0, &siteSurvey[i] );
			smeCopyBssProfile(0, &siteSurveyEntry);
			/* Only accept if WPS IE is present */
			if (siteSurveyEntry.result.wps_ie_len > 0) {
				memcpy(&siteSurvey[i], &siteSurveyEntry,
				       sizeof(MRVL_SCAN_ENTRY));
#ifdef MRVL_WPS_DEBUG
				printk("THE BSS PROFILE :[%02X:%02X:%02X:%02X:%02X:%02X]%d\n", siteSurvey[i].result.bssid[0], siteSurvey[i].result.bssid[1], siteSurvey[i].result.bssid[2], siteSurvey[i].result.bssid[3], siteSurvey[i].result.bssid[4], siteSurvey[i].result.bssid[5], i);
#endif
			}
		}

		parsedLen += curDescpt_p->length + sizeof(curDescpt_p->length);
	}

	return sizeof(MRVL_SCAN_ENTRY) *
		tmpNumScanDesc[vmacSta_p->VMacEntry.phyHwMacIndx];
}
#endif

int
mwl_drv_get_tlv(struct net_device *netdev, uint16_t type, uint8_t * buff)
{
	extern int wlFwGetTLVSet(struct net_device *netdev, UINT8 act,
				 UINT16 type, UINT16 len, UINT8 * tlvData,
				 char *string_buff);
	wlFwGetTLVSet(netdev, 0, type, 0, NULL, buff);

	return strlen(buff);
}

int
mwl_drv_get_chnls(struct net_device *netdev, uint8_t * buff)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	int i = 0;
	char *out_buf = buff;
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
	} else {		// 2.4G
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

	return strlen(out_buf);
}

int
mwl_drv_set_scanchannels(struct net_device *netdev, uint8_t * chlist)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;

	int i;
	int offset =
		(*(vmacSta_p->Mib802dot11->mib_ApMode) <
		 AP_MODE_A_ONLY) ? 0 : IEEEtypes_MAX_CHANNELS;
	for (i = 0; i < IEEE_80211_MAX_NUMBER_OF_CHANNELS; i++) {
		vmacSta_p->ChannelList[i + offset] = chlist[i];
	}

	return 0;
}

#ifdef WTP_SUPPORT
int
mwl_drv_set_wtp(struct net_device *netdev, int enable)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	if (enable == 0) {
		mib->mib_wtp_cfg->wtp_enabled = 1;
		printk("WTP enabled ...\n");
	} else if (enable == 0) {
		mib->mib_wtp_cfg->wtp_enabled = 0;
		printk("WTP disabled ...\n");
	} else {
		printk("usage: \"wtp enable\" or \"wtp disable\"\n");
		return -EFAULT;
	}

	return 0;
}

int
mwl_drv_set_wtpmacmode(struct net_device *netdev, int macmode)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	if (macmode == WTP_MAC_MODE_LOCALMAC) {
		mib->mib_wtp_cfg->mac_mode = WTP_MAC_MODE_LOCALMAC;
		//
		//flush acnt recds to kick wlHandleAcnt()
		//
#ifdef NEWDP_ACNT_CHUNKS
		wlAcntProcess_chunks(netdev);
#else
		wlAcntProcess(netdev);
#endif
		printk("set WTP local mac mode ...\n");
	} else if (macmode == WTP_MAC_MODE_SPLITMAC) {
		mib->mib_wtp_cfg->mac_mode = WTP_MAC_MODE_SPLITMAC;
		printk("set WTP split mac mode ...\n");
	} else {
		printk("usage: \"wtpmacmode localmac\" or \"wtpmacmode splitmac\"\n");
		return -EFAULT;
	}

	return 0;
}

int
mwl_drv_set_wtptunnelmode(struct net_device *netdev, int tunnelmode)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	if (tunnelmode == WTP_TUNNEL_MODE_NATIVE_80211) {
		mib->mib_wtp_cfg->frame_tunnel_mode =
			WTP_TUNNEL_MODE_NATIVE_80211;
		printk("set WTP frame tunnel mode to 80211 ...\n");
	} else if (tunnelmode == WTP_TUNNEL_MODE_802_3) {
		mib->mib_wtp_cfg->frame_tunnel_mode = WTP_TUNNEL_MODE_802_3;
		printk("set WTP frame tunnel mode to 802.3 ...\n");
	} else {
		printk("usage: \"wtptunnelmode 80211\" or \"wtptunnelmode 8023\"\n");
		return -EFAULT;
	}

	return 0;
}

int
mwl_drv_get_wtpcfg(struct net_device *netdev, uint8_t * buff)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

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
	else if (mib->mib_wtp_cfg->frame_tunnel_mode ==
		 WTP_TUNNEL_MODE_LOCAL_BRIDGING)
		printk("WTP frame tunnel mode = Local bridging\n");
	printk("===============================\n");

	return 0;
}

int
mwl_drv_get_radiostat(struct net_device *netdev, uint8_t * buff)
{
	struct RadioStats stats;
	memset((char *)&stats, 0, sizeof(struct RadioStats));
	wlFwGetWTPRadioStats(netdev, (char *)&stats);
	printk("Stats->RxOverrunErr=%d\n", stats.RxOverrunErr);
	printk("Stats->RxMacCrcErr=%d\n", stats.RxMacCrcErr);
	printk("Stats->RxWepErr=%d\n", stats.RxWepErr);
	printk("Stats->MaxRetries=%d\n", stats.MaxRetries);
	printk("Stats->RxAck=%d\n", stats.RxAck);
	printk("Stats->NoAck=%d\n", stats.NoAck);
	printk("Stats->NoCts=%d\n", stats.NoCts);
	printk("Stats->RxCts=%d\n", stats.RxCts);
	printk("Stats->TxRts=%d\n", stats.TxRts);
	printk("Stats->TxCts=%d\n", stats.TxCts);
	printk("Stats->TxUcFrags=%d\n", stats.TxUcFrags);
	printk("Stats->Tries=%d\n", stats.Tries);
	printk("Stats->TxMultRetries=%d\n", stats.TxMultRetries);
	printk("Stats->RxUc=%d\n", stats.RxUc);
	printk("Stats->TxBroadcast=%d\n", stats.TxBroadcast);
	printk("Stats->RxBroadcast=%d\n", stats.RxBroadcast);
	printk("Stats->TxMgmt=%d\n", stats.TxMgmt);
	printk("Stats->TxCtrl=%d\n", stats.TxCtrl);
	printk("Stats->TxBeacon=%d\n", stats.TxBeacon);
	printk("Stats->TxProbeRsp=%d\n", stats.TxProbeRsp);
	printk("Stats->RxMgmt=%d\n", stats.RxMgmt);
	printk("Stats->RxCtrl=%d\n", stats.RxCtrl);
	printk("Stats->RxBeacon=%d\n", stats.RxBeacon);
	printk("Stats->RxProbeReq=%d\n", stats.RxProbeReq);
	printk("Stats->DupFrag=%d\n", stats.DupFrag);
	printk("Stats->RxFrag=%d\n", stats.RxFrag);
	printk("Stats->RxAged=%d\n", stats.RxAged);
	printk("Stats->TxKb=%d\n", stats.TxKb);
	printk("Stats->RxKb=%d\n", stats.RxKb);
	printk("Stats->TxAggr=%d\n", stats.TxAggr);
	printk("Stats->Jammed=%d\n", stats.Jammed);
	printk("Stats->TxConcats=%d\n", stats.TxConcats);
	printk("Stats->RxConcats=%d\n", stats.RxConcats);
	printk("Stats->TxHwWatchdog=%d\n", stats.TxHwWatchdog);
	printk("Stats->TxSwWatchdog=%d\n", stats.TxSwWatchdog);
	printk("Stats->NoAckPolicy=%d\n", stats.NoAckPolicy);
	printk("Stats->TxAged=%d\n", stats.TxAged);
	memcpy(buff, (char *)&stats, sizeof(struct RadioStats));

	return sizeof(struct RadioStats);
}
#endif

extern int LoadExternalFw(struct wlprivate *priv, char *filename);
#ifdef MFG_SUPPORT
int
mwl_drv_set_extfw(struct net_device *netdev, char *filepath)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);

	int rc = 0;
	int mfgCmd = 0;

	if (!LoadExternalFw(priv, filepath)) {
		/* No file is loaded */
		return -EFAULT;
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

	return rc;
}

int
mwl_drv_set_mfgfw(struct net_device *netdev, char *filepath)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);

	int rc = 0;
	int mfgCmd = 1;

	if (!LoadExternalFw(priv, filepath)) {
		/* No file is loaded */
		return -EFAULT;
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

	return rc;

}

int
mwl_drv_set_mfg(struct net_device *netdev, uint8_t * cmd, uint8_t * buff)
{
	extern int wlFwMfgCmdIssue(struct net_device *netdev, char *pData,
				   char *pDataOut);

	char *pOut = buff;
	UINT16 len = 0;

	wlFwMfgCmdIssue(netdev, cmd, (pOut + 4));
	len = le16_to_cpu(*(UINT16 *) (pOut + 6));
	*(int *)&pOut[0] = len;

	return len + sizeof(int);
}

int
mwl_drv_set_fwrev(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);

	wlPrepareFwFile(netdev);
	if (netdev->flags & IFF_RUNNING)
		return priv->wlreset(netdev);
	else
		return -EFAULT;
}
#endif

#ifdef AMPDU_SUPPORT
int
mwl_drv_set_addba(struct net_device *netdev, uint8_t * mac, int tid, int stream)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;

	extern void AddbaTimerProcess(UINT8 * data);
	UINT32 seqNo = 0;

#ifdef SOC_W8864
	if ((stream > 7) || (tid > 7))
		return -EFAULT;
#else
	if ((stream > 1) || (tid > 7))
		return -EFAULT;
#endif

	if (priv->wlpd_p->Ampdu_tx[stream].InUse != 1) {
		priv->wlpd_p->Ampdu_tx[stream].MacAddr[0] = mac[0];
		priv->wlpd_p->Ampdu_tx[stream].MacAddr[1] = mac[1];
		priv->wlpd_p->Ampdu_tx[stream].MacAddr[2] = mac[2];
		priv->wlpd_p->Ampdu_tx[stream].MacAddr[3] = mac[3];
		priv->wlpd_p->Ampdu_tx[stream].MacAddr[4] = mac[4];
		priv->wlpd_p->Ampdu_tx[stream].MacAddr[5] = mac[5];
		priv->wlpd_p->Ampdu_tx[stream].AccessCat = tid;
		priv->wlpd_p->Ampdu_tx[stream].InUse = 1;
		priv->wlpd_p->Ampdu_tx[stream].TimeOut = 0;
		priv->wlpd_p->Ampdu_tx[stream].AddBaResponseReceive = 0;
		priv->wlpd_p->Ampdu_tx[stream].DialogToken =
			priv->wlpd_p->Global_DialogToken;
		priv->wlpd_p->Global_DialogToken =
			(priv->wlpd_p->Global_DialogToken + 1) % 63;
		if (priv->wlpd_p->Ampdu_tx[stream].initTimer == 0) {
			TimerInit(&priv->wlpd_p->Ampdu_tx[stream].timer);
			priv->wlpd_p->Ampdu_tx[stream].initTimer = 1;
		}
		TimerDisarm(&priv->wlpd_p->Ampdu_tx[stream].timer);
		priv->wlpd_p->Ampdu_tx[stream].vmacSta_p = vmacSta_p;
		TimerFireIn(&priv->wlpd_p->Ampdu_tx[stream].timer, 1,
			    &AddbaTimerProcess,
			    (UINT8 *) & priv->wlpd_p->Ampdu_tx[stream], 10);
	} else {
		printk("Stream %x is already in use \n", stream);
		return 0;
	}
#ifdef SOC_W8764		// Added to allow manual ampdu  setup for Client mode.
	if (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_CLNT_INFRA)
		SendAddBAReqSta(vmacSta_p, mac, tid, 1, seqNo,
				priv->wlpd_p->Ampdu_tx[stream].DialogToken);
	else
#endif
		SendAddBAReq(vmacSta_p, mac, tid, 1, seqNo, priv->wlpd_p->Ampdu_tx[stream].DialogToken);/** Only support immediate ba **/
	//      wlFwCreateBAStream(64, 64 , macaddr,    10, tid, 1,  stream);  //for mike stupid code

	return 0;
}

int
mwl_drv_get_ampdustat(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	int i, j;

	for (i = 0; i < MAX_SUPPORT_AMPDU_TX_STREAM; i++) {
		printk(": ");
		for (j = 0; j < 6; j++) {
			printk("%x ", priv->wlpd_p->Ampdu_tx[i].MacAddr[j]);
		}
		printk("tid %x Inuse %x timeout %d pps %d\n",
		       priv->wlpd_p->Ampdu_tx[i].AccessCat,
		       priv->wlpd_p->Ampdu_tx[i].InUse,
		       (int)priv->wlpd_p->Ampdu_tx[i].TimeOut,
		       (int)priv->wlpd_p->Ampdu_tx[i].txa_avgpps);
		printk("\n");
	}

	return 0;
}

int
mwl_drv_set_delba(struct net_device *netdev, uint8_t * macaddr, uint8_t tid)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	int i;

	if (tid > 7) {
		return -EFAULT;
	}

	for (i = 0; i < 7; i++) {
		printk(" AMacaddr2 %x %x %x %x %x %x\n",
		       priv->wlpd_p->Ampdu_tx[i].MacAddr[0],
		       priv->wlpd_p->Ampdu_tx[i].MacAddr[1],
		       priv->wlpd_p->Ampdu_tx[i].MacAddr[2],
		       priv->wlpd_p->Ampdu_tx[i].MacAddr[3],
		       priv->wlpd_p->Ampdu_tx[i].MacAddr[4],
		       priv->wlpd_p->Ampdu_tx[i].MacAddr[5]);
		printk(" Macaddr2 %x %x %x %x %x %x\n", macaddr[0], macaddr[1],
		       macaddr[2], macaddr[3], macaddr[4], macaddr[5]);
		printk(" tid = %x , In Use = %x \n*******\n",
		       priv->wlpd_p->Ampdu_tx[i].AccessCat,
		       priv->wlpd_p->Ampdu_tx[i].InUse);
		disableAmpduTx(vmacSta_p, macaddr, tid);
	}

	return 0;
}

int
mwl_drv_set_del2ba(struct net_device *netdev, uint8_t * macaddr, uint8_t tid)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;

	if (tid > 7) {
		return -EFAULT;
	}

	SendDelBA2(vmacSta_p, macaddr, tid);

	return 0;
}

int
mwl_drv_set_ampdurxdisable(struct net_device *netdev, uint8_t option)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;

	vmacSta_p->Ampdu_Rx_Disable_Flag = option;

	return 0;
}

int
mwl_drv_set_triggerscaninterval(struct net_device *netdev,
				uint16_t triggerscaninterval)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

#ifdef COEXIST_20_40_SUPPORT

	printk("Set triggerscaninterval to %x\n", triggerscaninterval);

	*(mib->mib_Channel_Width_Trigger_Scan_Interval) = triggerscaninterval;

#endif

	return 0;
}

int
mwl_drv_set_bf(struct net_device *netdev, uint8_t * param)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;

#ifdef EXPLICIT_BF
	extern int wlFwSet11N_BF_Mode(struct net_device *netdev,
				      UINT8 bf_option, UINT8 bf_csi_steering,
				      UINT8 bf_mcsfeedback, UINT8 bf_mode,
				      UINT8 bf_interval, UINT8 bf_slp,
				      UINT8 bf_power);
	UINT8 option, csi_steering, mcsfeedback, mode, interval, slp, power;

	/*if (strcmp(param[1],"help")== 0)
	   {
	   printk("Usage: SetBF csi_steering mcsfeedback mode interval slp power \n");
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

	   return -EFAULT;
	   } */

	option = param[0];
	csi_steering = param[1];
	mcsfeedback = param[2];
	mode = param[3];
	interval = param[4];
	slp = param[5];
	power = param[6];

	printk("Set 11n BF mode option=%d csi_steer=%d mcsfb=%d mode=%d interval=%d slp=%d, power=%d\n", option, csi_steering, mcsfeedback, mode, interval, slp, power);

	wlFwSet11N_BF_Mode(vmacSta_p->dev, option, csi_steering, mcsfeedback,
			   mode, interval, slp, power);
#endif

	return 0;
}

int
mwl_drv_get_mumimomgmt(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

#ifdef EXPLICIT_BF
	if (!priv->master) {
		printk("Error. Please enter vap interface instead\n");
		return -EOPNOTSUPP;
	}

	printk("mumimo mgmt status is %d\n", (int)*(mib->mib_mumimo_mgmt));
#endif

	return 0;
}

int
mwl_drv_set_mumimomgmt(struct net_device *netdev, uint32_t value)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

#ifdef EXPLICIT_BF
	if (!priv->master) {
		printk("Error. Please enter vap interface instead\n");
		return -EOPNOTSUPP;
	}

	if (value != 0 && value != 1) {
		printk("incorrect status values \n");
	}
	*(mib->mib_mumimo_mgmt) = value;
	printk("mumimo mgmt status is %d\n", (int)*(mib->mib_mumimo_mgmt));
#endif

	return 0;
}

int
mwl_drv_get_musta(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;

#ifdef EXPLICIT_BF
	if (!priv->master) {
		printk("Error. Please enter vap interface instead\n");
		return -EOPNOTSUPP;
	}

	MUDisplayMUStaList(vmacSta_p);
#endif

	return 0;
}

int
mwl_drv_get_muset(struct net_device *netdev, uint8_t value)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;

#ifdef EXPLICIT_BF
	if (value == 0)
		MUDisplayMUSetList(vmacSta_p);
	else if (value == 1) {
		extern int wlFwGetMUSet(struct net_device *netdev, UINT8 index);
		printk("GetMUSet");
		wlFwGetMUSet(netdev, 0);
	} else
		MUDisplayMUSetList(vmacSta_p);
#endif

	return 0;
}

int
mwl_drv_set_muset(struct net_device *netdev, uint16_t * param)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;

#ifdef EXPLICIT_BF
	uint8_t i, j, MUUsrCnt = 0;
	uint16_t Stnid[3];
	MUCapStaNode_t *item_p = NULL;
	extStaDb_StaInfo_t *StaInfo[3] = { NULL, NULL, NULL };

	Stnid[0] = param[0];
	Stnid[1] = param[1];
	Stnid[2] = param[2];

	if (!priv->master) {
		printk("Error. Please enter vap interface instead\n");
		return -EOPNOTSUPP;
	}

	if ((Stnid[0] == NULL) && (Stnid[1] == NULL) && (Stnid[2] == NULL)) {
		printk("SetMUSet <staid1> <staid2> <staid3>\n");
		return -EOPNOTSUPP;
	}

	/* Find matching sta id in MUStaList */
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
	} else {
		printk("SetMUSet FAIL, no. of user < 2\n");
	}
#endif

	return 0;
}

int
mwl_drv_del_muset(struct net_device *netdev, uint8_t index)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;

#ifdef EXPLICIT_BF
	if (!priv->master) {
		printk("Error. Please enter vap interface instead\n");
		return -EOPNOTSUPP;
	}

	MUDel_MUSetIndex(vmacSta_p, index);
#endif

	return 0;
}

int
mwl_drv_set_mug_enable(struct net_device *netdev, uint32_t enable)
{
#ifdef MRVL_MUG_ENABLE
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	if (priv->master) {
		printk("Error. Please enter non-vap interface instead\n");
		return -EOPNOTSUPP;
	}

	mug_enable(netdev, enable);
#endif

	return 0;
}

int
mwl_drv_get_muinfo(struct net_device *netdev, uint8_t value)
{
#ifdef MRVL_MUG_ENABLE
	extern int wlFwGetMUInfo(struct net_device *netdev, int groups_only);

	if (wlFwGetMUInfo(netdev, value) != 0) {
		printk("wlFwGetMUInfo FAILED!\n");
	} else {
		printk("wlFwGetMUInfo OK\n");
	}
#endif

	return 0;
}

int
mwl_drv_get_mugroups(struct net_device *netdev, uint8_t value)
{
#ifdef MRVL_MUG_ENABLE
	extern int wlFwGetMUInfo(struct net_device *netdev, int groups_only);

	if (wlFwGetMUInfo(netdev, value) != 0) {
		printk("wlFwGetMUInfo FAILED!\n");
	} else {
		printk("wlFwGetMUInfo OK\n");
	}
#endif

	return 0;
}

int
mwl_drv_set_muconfig(struct net_device *netdev, uint32_t corr_thr_decimal,
		     uint16_t sta_cep_age_thr, uint16_t period_ms)
{
#ifdef MRVL_MUG_ENABLE
	extern int wlFwSetMUConfig(struct net_device *netdev,
				   u32 corr_thr_decimal, u16 sta_cep_age_thr,
				   u16 period_ms);
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	if (priv->master) {
		printk("Error. Please enter non-vap interface instead\n");
		return -EOPNOTSUPP;
	}

	if (corr_thr_decimal == 0 || sta_cep_age_thr == 0) {
		printk("wlFwSetMUConfig() FAILED\n");
	} else {
		if (wlFwSetMUConfig
		    (netdev, corr_thr_decimal, sta_cep_age_thr,
		     period_ms) == 0) {
			printk("Set MU config OK!\n");
		}
	}
#endif

	return 0;
}

int
mwl_drv_set_muautotimer(struct net_device *netdev, uint8_t set, uint32_t value)
{
#ifdef EXPLICIT_BF
	extern UINT32 AUTO_MU_TIME_CONSTANT;

	if (set == 1) {
		AUTO_MU_TIME_CONSTANT = value;
		printk("MU auto grouping %d*10msec\n", AUTO_MU_TIME_CONSTANT);
	} else
		printk("MU auto grouping %d*10msec\n", AUTO_MU_TIME_CONSTANT);
#endif

	return 0;
}

int
mwl_drv_set_mupreferusrcnt(struct net_device *netdev, uint8_t value)
{
#ifdef EXPLICIT_BF
	extern UINT8 MUSet_Prefer_UsrCnt;

	if (value != 0) {
		if (value > 1 && value < 4)
			MUSet_Prefer_UsrCnt = value;
		else
			MUSet_Prefer_UsrCnt = 3;

		printk("MU set user cnt preference: %d\n", MUSet_Prefer_UsrCnt);
	} else
		printk("MU set user cnt preference: %d\n", MUSet_Prefer_UsrCnt);
#endif

	return 0;
}

int
mwl_drv_set_gid(struct net_device *netdev, uint8_t * macaddr)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;

#ifdef EXPLICIT_BF
	int i, j;
	extern void SendGroupIDMgmtframe(vmacApInfo_t * vmacSta_p,
					 IEEEtypes_MacAddr_t StaAddr, UINT8 gid,
					 UINT8 userposition);

	printk("in groupidmgmtframe\n");

	for (i = 0; i < 64; i++) {
		for (j = 0; j < 3; j++) {
			SendGroupIDMgmtframe(vmacSta_p, macaddr, i, j);
		}
		printk("\n");
	}
	printk("\n");
#endif

	return 0;
}

int
mwl_drv_set_noack(struct net_device *netdev, uint8_t enable)
{
#ifdef EXPLICIT_BF
	extern int wlFwSetNoAck(struct net_device *netdev, UINT8 Enable);
	printk("Set NoACK= %x\n", enable);
	wlFwSetNoAck(netdev, enable);
#endif

	return 0;
}

int
mwl_drv_set_nosteer(struct net_device *netdev, uint8_t enable)
{
#ifdef EXPLICIT_BF
	extern int wlFwSetNoSteer(struct net_device *netdev, UINT8 Enable);
	printk("Set NoSteer = %x\n", enable);
	wlFwSetNoSteer(netdev, enable);
#endif

	return 0;
}

int
mwl_drv_get_bftype(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

#ifdef EXPLICIT_BF
	printk("bftype is %d\n", (int)*(mib->mib_bftype));
#endif

	return 0;
}

int
mwl_drv_get_bwsignaltype(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

#ifdef EXPLICIT_BF
	printk("bw_Signaltype is %d\n", (int)*(mib->mib_bwSignaltype));
#endif

	return 0;
}

int
mwl_drv_set_bwsignaltype(struct net_device *netdev, uint8_t type,
			 uint8_t bitmap)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

#ifdef EXPLICIT_BF
	uint8_t i;

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
#endif

	return 0;
}

int
mwl_drv_get_weakiv_threshold(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	printk("weakiv_threshold is %d\n", (int)*(mib->mib_weakiv_threshold));

	return 0;
}

int
mwl_drv_set_weakiv_threshold(struct net_device *netdev, uint32_t value)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	*(mib->mib_weakiv_threshold) = value;
	printk("weakiv_threshold is %d\n", (int)*(mib->mib_weakiv_threshold));

	return 0;
}

int
mwl_drv_set_tim(struct net_device *netdev, uint16_t aid, uint32_t set)
{
#ifdef POWERSAVE_OFFLOAD
	printk("SetTim\n");

	wlFwSetTIM(netdev, aid, set);
#endif

	return 0;
}

int
mwl_drv_set_powersavestation(struct net_device *netdev, uint8_t noofstations)
{
#ifdef POWERSAVE_OFFLOAD
	wlFwSetPowerSaveStation(netdev, noofstations);
#endif

	return 0;
}

int
mwl_drv_get_tim(struct net_device *netdev)
{
#ifdef POWERSAVE_OFFLOAD
	printk(" Get TIM:\n");
	wlFwGetTIM(netdev);
#endif

	return 0;
}
#endif

int
mwl_drv_get_bcn(struct net_device *netdev)
{
#define LINECHAR	16
	uint16_t len = 0;
	uint8_t *pBcn, *p;
	uint8_t i;
	uint16_t lineLen;
	uint8_t cmdGetBuf[200];
	char *bufBack = cmdGetBuf;
	uint16_t *ret_len;

	pBcn = kmalloc(MAX_BEACON_SIZE, GFP_KERNEL);
	if (pBcn == NULL) {
		return -EFAULT;
	}

	if (wlFwGetBeacon(netdev, pBcn, &len) == FAIL) {
		return -EFAULT;
		kfree(pBcn);
	}

	sprintf(bufBack, "Beacon: len %d\n", len);
	p = bufBack + strlen(bufBack);
	lineLen = (len / LINECHAR == 0 ? len / LINECHAR : 1 + len / LINECHAR);
	for (i = 0; i < lineLen; i++) {
		sprintf(p,
			"%04d: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
			i * LINECHAR, pBcn[i * LINECHAR + 0],
			pBcn[i * LINECHAR + 1], pBcn[i * LINECHAR + 2],
			pBcn[i * LINECHAR + 3], pBcn[i * LINECHAR + 4],
			pBcn[i * LINECHAR + 5], pBcn[i * LINECHAR + 6],
			pBcn[i * LINECHAR + 7], pBcn[i * LINECHAR + 8],
			pBcn[i * LINECHAR + 9], pBcn[i * LINECHAR + 10],
			pBcn[i * LINECHAR + 11], pBcn[i * LINECHAR + 12],
			pBcn[i * LINECHAR + 13], pBcn[i * LINECHAR + 14],
			pBcn[i * LINECHAR + 15]);
		p = bufBack + strlen(bufBack);
	}

	*ret_len = strlen(bufBack);
	printk("%s", bufBack);
	kfree(pBcn);

	return 0;
}

int
mwl_drv_set_annex(struct net_device *netdev, uint32_t annex, uint32_t index)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
#define LINECHAR	16
	uint16_t len;
	uint32_t i;
	uint8_t cmdGetBuf[200];
	char *bufBack = cmdGetBuf;
	uint16_t *ret_len;

	if (wlFwGetCalTable(netdev, (uint8_t) annex, (uint8_t) index) == FAIL) {
		return -EFAULT;
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
			sprintf(tmpStr, "%02x %02x %02x %02x\n",
				priv->calTbl[i * 4], priv->calTbl[i * 4 + 1],
				priv->calTbl[i * 4 + 2],
				priv->calTbl[i * 4 + 3]);
			strcat(bufBack, tmpStr);
		}
	} else
		sprintf(bufBack, "No Annex %d\n", annex);

	*ret_len = strlen(bufBack);
	printk("%s", bufBack);

	return 0;
}

int
mwl_drv_set_readeepromhdr(struct net_device *netdev, uint32_t annex,
			  uint32_t index)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
#define LINECHAR	16
	uint16_t len;
	uint32_t i;
	uint8_t cmdGetBuf[200];
	char *bufBack = cmdGetBuf;
	uint16_t *ret_len;

	if (wlFwGetCalTable(netdev, (uint8_t) annex, (uint8_t) index) == FAIL) {
		return -EFAULT;
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
			sprintf(tmpStr, "%02x %02x %02x %02x\n",
				priv->calTbl[i * 4], priv->calTbl[i * 4 + 1],
				priv->calTbl[i * 4 + 2],
				priv->calTbl[i * 4 + 3]);
			strcat(bufBack, tmpStr);
		}
	} else
		sprintf(bufBack, "No Annex %d\n", annex);

	*ret_len = strlen(bufBack);
	printk("%s", bufBack);

	return 0;
}

#if defined (SOC_W8366) || defined (SOC_W8364) || defined (SOC_W8764)
int
mwl_drv_get_or(struct net_device *netdev)
{
	uint32_t i, reg, val, set = WL_GET;

	for (i = 0; i < 4; i++) {
		/* for RF */
		printk("\nRF BASE %u registers \n", 'A' + i);
		for (reg = 0xA00 + (0x100 * i); reg <= 0xAFF + (0x100 * i);
		     reg++) {
			wlRegRF(netdev, set, reg, &val);
			printk("0x%02X	0x%02X\n",
			       (int)(reg - (0xA00 + (0x100 * i))), (int)val);
		}
	}
	for (i = 0; i < 4; i++) {
		printk("\nRF XCVR path %c registers \n", 'A' + i);
		for (reg = 0x100 + (0x100 * i); reg <= 0x1FF + (0x100 * i);
		     reg++) {
			wlRegRF(netdev, set, reg, &val);
			printk("0x%03X	0x%02X\n", (int)(reg), (int)val);
		}
	}

	/* for BBP */
#ifdef SOC_W8864
	printk("\nBBU Registers \n");
	for (reg = 0x00; reg <= 0x6DB; reg++)
#else
	for (reg = 0x00; reg <= 0x56C; reg++)
#endif
	{
		wlRegBB(netdev, set, reg, &val);
		if (reg < 0x100)
			printk("0x%02X	0x%02X\n", (int)reg, (int)val);
		else
			printk("0x%03X	0x%02X\n", (int)reg, (int)val);
	}

	return 0;

}
#endif

int
mwl_drv_get_addrtable(struct net_device *netdev)
{
	wlFwGetAddrtable(netdev);
	return 0;
}

int
mwl_drv_get_fwencrinfo(struct net_device *netdev, uint8_t * macaddr)
{
	wlFwGetEncrInfo(netdev, macaddr);
	return 0;
}

int
mwl_drv_set_reg(struct net_device *netdev, uint32_t regtype, uint32_t reg,
		uint32_t value)
{
	unsigned long set = WL_GET;
	int rc = 0;
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);

	if (regtype == MWL_SET_REG_MAC) {
		if (set == WL_SET) {
			PciWriteMacReg(netdev, reg, value);
		} else
			value = PciReadMacReg(netdev, reg);
		printk("%s mac reg %x = %x\n", set ? "Set" : "Get", (int)reg,
		       (int)value);
	} else if (regtype == MWL_SET_REG_RF) {
		wlRegRF(netdev, set, reg, &value);
		printk("%s rf reg %x = %x\n", set ? "Set" : "Get", (int)reg,
		       (int)value);
	} else if (regtype == MWL_SET_REG_BB) {
		wlRegBB(netdev, set, reg, &value);
		printk("%s bb reg %x = %x\n", set ? "Set" : "Get", (int)reg,
		       (int)value);
	} else if (regtype == MWL_SET_REG_CAU) {
		wlRegCAU(netdev, set, reg, &value);
		printk("%s cau reg %x = %x\n", set ? "Set" : "Get", (int)reg,
		       (int)value);
	} else if (regtype == MWL_SET_REG_ADDR0) {
		if (set == WL_SET)
			*(volatile unsigned int *)((unsigned int)priv->ioBase0 +
						   reg) = le32_to_cpu(value);
		else
			value = cpu_to_le32(*(volatile unsigned int *)
					    ((unsigned int)priv->ioBase0 +
					     reg));
		printk("%s addr %x = %x\n", set ? "Set" : "Get",
		       (int)reg + 0xc0000000, (int)value);
	} else if (regtype == MWL_SET_REG_ADDR1) {
		if (set == WL_SET)
			*(volatile unsigned int *)((unsigned int)priv->ioBase1 +
						   reg) = le32_to_cpu(value);
		else
			value = cpu_to_le32(*(volatile unsigned int *)
					    ((unsigned int)priv->ioBase1 +
					     reg));
		printk("%s addr %x = %x\n", set ? "Set" : "Get",
		       (int)reg + 0x80000000, (int)value);
	} else if (regtype == MWL_SET_REG_ADDR) {
		UINT32 *addr_val = kmalloc(64 * sizeof(UINT32), GFP_KERNEL);
		if (addr_val == NULL) {
			rc = -EFAULT;
			return rc;
		}
		memset(addr_val, 0, 64 * sizeof(UINT32));
		addr_val[0] = value;
		if (set == WL_SET) {
			wlFwGetAddrValue(netdev, reg, 4, addr_val, 1);
		} else
			wlFwGetAddrValue(netdev, reg, 4, addr_val, 0);
		printk("%s addr %x = %x\n", set ? "Set" : "Get", (int)reg,
		       (int)addr_val[0]);
		kfree(addr_val);
	} else {
		rc = -EFAULT;
		return rc;
	}
	return 0;
}

extern u_int32_t debug_tcpack;
extern UINT32 vht_cap;
extern UINT32 SupportedRxVhtMcsSet;
//extern UINT32 SupportedTxVhtMcsSet;
extern UINT32 ch_width;
extern UINT32 center_freq0;
extern UINT32 center_freq1;
extern UINT32 basic_vht_mcs;
extern UINT32 dbg_level;
extern UINT32 dbg_class;
#ifdef CAP_MAX_RATE
extern u_int32_t MCSCapEnable;
extern u_int32_t MCSCap;
#endif
extern char DebugData[1000];
struct payload_mgmt {
	UINT16 len;
	UINT8 data[1000];
} PACK;
extern struct payload_mgmt authAndAssoc[2];
#ifdef CONFIG_IEEE80211W
extern void macMgmtMlme_SAQuery(vmacApInfo_t * vmacSta_p,
				IEEEtypes_MacAddr_t * Addr,
				IEEEtypes_MacAddr_t * SrcAddr, UINT32 stamode);
#endif
extern SINT8 evtDot11MgtMsg(vmacApInfo_t * vmacSta_p, UINT8 * message,
			    struct sk_buff *skb, UINT32 rssi);
extern BOOLEAN DebugSendMgtMsg(struct net_device *netdev, UINT32 SubtypeAndMore,
			       IEEEtypes_MacAddr_t * DestAddr,
			       IEEEtypes_MacAddr_t * SrcAddr,
			       IEEEtypes_MacAddr_t * Bssid, UINT8 * data,
			       UINT16 size);
extern struct sk_buff *ieee80211_getmgtframe(UINT8 ** frm, unsigned int pktlen);

int
mwl_drv_set_debug(struct net_device *netdev, uint32_t * data, int data_len)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
	MIB_STA_CFG *mib_StaCfg = mib->StationConfig;

	if (data[0] == MWL_DEBUG_INJECTRX) {
		macmgmtQ_MgmtMsg3_t *MgmtMsg_p;
		struct sk_buff *skb;
		UINT8 *frm;
		UINT32 frameSize = 0;
		UINT32 subtype = 0;
		UINT32 len = 0;
		UINT32 wep = data[2];
		UINT32 adjustheader = wep ? 8 : 0;
		UINT32 adjusttail = wep ? 8 : 0;
		char SrcAddr[6];
		//char DstAddr[6];
		//char Bssid[6];
		//memcpy(DstAddr, vmacSta_p->macStaAddr, 6);
		//memcpy(Bssid, vmacSta_p->macStaAddr, 6);
		extStaDb_list(vmacSta_p, SrcAddr, 1);
		if (data[1] == MWL_DEBUG_INJECTRX_AUTH) {
			subtype = IEEE_MSG_AUTHENTICATE;
			len = authAndAssoc[0].len;
			memcpy(DebugData, authAndAssoc[0].data, len);
		} else if (data[1] == MWL_DEBUG_INJECTRX_ASSOC) {
			subtype = IEEE_MSG_ASSOCIATE_RQST;
			len = authAndAssoc[1].len;
			memcpy(DebugData, authAndAssoc[1].data, len);
		} else if (data[1] == MWL_DEBUG_INJECTRX_DEAUTH) {
			subtype = IEEE_MSG_DEAUTHENTICATE;
			len = 2;
			DebugData[0] = 1;
			DebugData[1] = 0;
		} else if (data[1] == MWL_DEBUG_INJECTRX_DEASSOC) {
			subtype = IEEE_MSG_DISASSOCIATE;
			len = 2;
			DebugData[0] = 1;
			DebugData[1] = 0;
		}
		if ((skb = ieee80211_getmgtframe(&frm, 1000)) != NULL) {
			MgmtMsg_p = (macmgmtQ_MgmtMsg3_t *) skb->data;
			MgmtMsg_p->Hdr.FrmCtl.Type = IEEE_TYPE_MANAGEMENT;
			MgmtMsg_p->Hdr.FrmCtl.Subtype = subtype;
			MgmtMsg_p->Hdr.FrmCtl.Retry = 0;
			MgmtMsg_p->Hdr.FrmCtl.Wep = wep;
			MgmtMsg_p->Hdr.Duration = 300;
			memcpy(&MgmtMsg_p->Hdr.DestAddr, vmacSta_p->macStaAddr,
			       sizeof(IEEEtypes_MacAddr_t));
			memcpy(&MgmtMsg_p->Hdr.SrcAddr, SrcAddr,
			       sizeof(IEEEtypes_MacAddr_t));
			memcpy(&MgmtMsg_p->Hdr.BssId, vmacSta_p->macStaAddr,
			       sizeof(IEEEtypes_MacAddr_t));
			memcpy(&MgmtMsg_p->Body.data[adjustheader], DebugData,
			       len);
			frameSize =
				sizeof(IEEEtypes_MgmtHdr3_t) + len +
				adjustheader + adjusttail;
			skb_trim(skb, frameSize);
			MgmtMsg_p->Hdr.FrmBodyLen = frameSize;
			wlDumpData(__FUNCTION__, MgmtMsg_p,
				   MgmtMsg_p->Hdr.FrmBodyLen + 2);
			evtDot11MgtMsg(vmacSta_p, (UINT8 *) MgmtMsg_p, skb, 0);
		}

	} else if (data[0] == MWL_DEBUG_DEBUG_TX) {
		UINT32 subtype = 0;
		UINT32 len;
		char Addr[64] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
		char SrcAddr[6];
		char Bssid[6];
		char DebugData[64];
		UINT8 sent = 0;
		UINT32 flag = data[2];
		UINT8 brcst = data[3];
		UINT8 plain = data[4];
		memcpy(SrcAddr, vmacSta_p->macStaAddr, 6);
		memcpy(Bssid, vmacSta_p->macStaAddr, 6);
		if (!brcst) {
			/* allow using the 5th argument to specify unicast MAC */
			memcpy(Addr, &data[5], 6);
			extStaDb_list(vmacSta_p, Addr, 1);

			printk("\n ### Unicast MAC (%02x:%02x:%02x:%02x:%02x:%02x)\n", Addr[0], Addr[1], Addr[2], Addr[3], Addr[4], Addr[5]);

			if (vmacSta_p->VMacEntry.modeOfService ==
			    VMAC_MODE_CLNT_INFRA)
				memcpy(Bssid, Addr, 6);

			if (Addr[0] & 0x1) {
				printk("conflicted mac address and brcst flag setting!!!\n");
				goto out;
			}
		} else {
			flag = 0;
			if (plain == 1)	//plain
				;	//DebugBitSet(1);
			else if (plain == 2)	//wrong key
				;	//DebugBitSet(0);
		}
		if (data[1] == MWL_DEBUG_TX_DEAUTHALL) {
			extStaDb_RemoveAllStns(vmacSta_p,
					       IEEEtypes_REASON_DEAUTH_LEAVING);
		} else if (data[1] == MWL_DEBUG_TX_DEAUTH) {
			subtype = IEEE_MSG_DEAUTHENTICATE;
			len = 2;
			DebugData[0] = 1;
			DebugData[1] = 0;
		} else if (data[1] == MWL_DEBUG_TX_DEASSOC) {
			subtype = IEEE_MSG_DISASSOCIATE;
			len = 2;
			DebugData[0] = 1;
			DebugData[1] = 0;
		} else if (data[1] == MWL_DEBUG_TX_SAQUERY) {
			subtype = IEEE_MSG_QOS_ACTION | flag;
#ifdef CONFIG_IEEE80211W
			macMgmtMlme_SAQuery(vmacSta_p,
					    (IEEEtypes_MacAddr_t *) Addr,
					    (IEEEtypes_MacAddr_t *) SrcAddr,
					    subtype);
#endif
			sent = 1;
		}

		if (sent == 0) {
			subtype |= flag;
			DebugSendMgtMsg(netdev, subtype,
					(IEEEtypes_MacAddr_t *) Addr,
					(IEEEtypes_MacAddr_t *) SrcAddr,
					(IEEEtypes_MacAddr_t *) Bssid,
					DebugData, len);

			// for deauth or disassoc
			if (plain == 0) {	//correctly protected deauthentication
				if (brcst)
					extStaDb_RemoveAllStns(vmacSta_p,
							       IEEEtypes_REASON_DEAUTH_LEAVING);
				else
					extStaDb_DelSta(vmacSta_p,
							(IEEEtypes_MacAddr_t *)
							Addr, 0);
			}
		}
	} else if (data[0] == MWL_DEBUG_TCP_ACK) {
		debug_tcpack = data[1];
		printk("debug_tcpack %s\n",
		       debug_tcpack ? "enabled" : "disabled");
	}
#ifdef CAP_MAX_RATE
	else if (data[0] == MWL_DEBUG_MCS_CAP) {
		MCSCapEnable = data[1];

		printk("MCS cap %s. To enable, mcscap 1 <mcs_value>\n",
		       MCSCapEnable ? "enabled" : "disabled");
		if (MCSCapEnable) {
			if (data[2] > 23) {
				printk("Pls specify MCS <= 23\n");
				MCSCapEnable = 0;
				printk("MCS cap disabled\n");
			} else {
				MCSCap = data[2];
				printk("Rate capped at MCS%d\n", MCSCap);
			}
		}
	}
#endif
	else if (data[0] == MWL_DEBUG_VHT_CAP) {

		vht_cap = data[1];
		SupportedRxVhtMcsSet = data[2];
		mib_StaCfg->SupportedTxVhtMcsSet = data[3];
		printk("vht_cap=%x  SupportedRxVhtMcsSet=%x  SupportedTxVhtMcsSet=%x\n", (unsigned int)vht_cap, (unsigned int)SupportedRxVhtMcsSet, (unsigned int)mib_StaCfg->SupportedTxVhtMcsSet);

	} else if (data[0] == MWL_DEBUG_VHT_OPT) {
		if (data_len > 4) {
			basic_vht_mcs = data[4];
		}
		if (data_len > 3) {
			center_freq1 = data[3];
		}
		if (data_len > 2) {
			center_freq0 = data[2];
		}
		if (data_len > 1) {
			ch_width = data[1];
		}
		printk("ch_width=%d  center_freq0=%d  center_freq1=%d  basic_vht_mcs=%x\n", (int)ch_width, (int)center_freq0, (int)center_freq1, (unsigned int)basic_vht_mcs);
	} else if (data[0] == MWL_DEBUG_READ) {
		UINT32 location;
		location = data[1];
		printk("location %x = %x\n", (int)location,
		       (int)(*(volatile unsigned long *)(location)));
	} else if (data[0] == MWL_DEBUG_WRITE) {
		UINT32 location, val;
		location = data[1];
		val = data[2];
		(*(volatile unsigned long *)(location)) = val;
		printk("write %x to location %x\n", (int)val, (int)location);
	} else if (data[0] == MWL_DEBUG_DUMP) {
		struct wlprivate *priv =
			NETDEV_PRIV_P(struct wlprivate, netdev);
		{
			unsigned long i, val, offset, length;

			if (data[1] == MWL_DEBUG_DUMP_MM) {
				offset = data[2];
				if (offset > 0xffff) {
					goto out;
				}

				length = data[3];
				if (!length)
					length = 32;

				printk("dump mem\n");
				for (i = 0; i < length; i += 4) {
					volatile unsigned int val = 0;

					val = *(volatile unsigned int
						*)((unsigned int)priv->ioBase1 +
						   offset + i);

					if (i % 8 == 0) {
						printk("\n%08x: ",
						       (int)(0x80000000 +
							     offset + i));
					}
					printk("  %08x", val);
				}
			} else if (data[1] == MWL_DEBUG_DUMP_RF) {
				offset = data[2];
				length = data[3];
				if (!length)
					length = 32;

				printk("dump rf regs\n");
				for (i = 0; i < length; i++) {
					wlRegRF(netdev, 0, offset + i,
						(UINT32 *) & val);
					if (i % 8 == 0) {
						printk("\n%02x: ",
						       (int)(offset + i));
					}
					printk("  %02x", (int)val);
				}
			} else if (data[1] == MWL_DEBUG_DUMP_BB) {
				offset = data[2];
				length = data[3];
				if (!length)
					length = 32;

				printk("dump bb regs\n");
				for (i = 0; i < length; i++) {
					wlRegBB(netdev, 0, offset + i,
						(UINT32 *) & val);
					if (i % 8 == 0) {
						printk("\n%02x: ",
						       (int)(offset + i));
					}
					printk("  %02x", (int)val);
				}
			}
		}
	} else if (data[0] == MWL_DEBUG_MAP) {
#if 1
		extern void wlRxDescriptorDump(struct net_device *netdev);
		extern void wlTxDescriptorDump(struct net_device *netdev);
		wlRxDescriptorDump(netdev);
		wlTxDescriptorDump(netdev);
#else
		UINT8 mac[6];
		int param1, param2, set = 0;
		MacAddrString(strArray_p->strArray[1], mac);
		set = atohex2(strArray_p->strArray[2]);
		if (set) {
			param1 = atohex2(strArray_p->strArray[3]);
			param2 = atohex2(strArray_p->strArray[4]);
		}
#endif
	} else if (data[0] == MWL_DEBUG_HELP) {
		printk("read <location>\nwrite <location> <value>\ndump <start location> <length>\nfunc <arg#> <param ...>\n");
	} else {
		printk("No Valid Commands found\n");
	}
out:
	return 0;
}

int
mwl_drv_get_memdump(struct net_device *netdev, uint32_t * data)
{
	signed long i, val, offset, length, j = 0;
	signed char *buf = NULL;
	int rc = 0;
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);

	if (data[0] == MWL_GET_MEMDUMP_MM) {
		int k;
		offset = data[1] & 0xfffffffc;
		/*if (offset>0xafff || offset < 0xa000)
		   {
		   rc = -EFAULT;
		   break;
		   } */

		length = data[2] * 4;
		if (!length)
			length = 32;
		buf = kmalloc(length * 10 + 100, GFP_KERNEL);
		if (buf == NULL) {
			rc = -EFAULT;
			return rc;
		}

		sprintf(buf + j, "dump mem\n");
		j = strlen(buf);

		for (k = 0; k < length; k += 256) {
			for (i = 0; i < 256; i += 4) {
				volatile unsigned int val = 0;
				val = le32_to_cpu(*(volatile unsigned int *)
						  ((unsigned int)priv->ioBase1 +
						   offset + i));

				//val = PciReadMacReg(netdev, offset+i);
				if (i % 16 == 0) {
					sprintf(buf + j, "\n0x%08x",
						(int)(0x80000000 + offset + i +
						      k));
					j = strlen(buf);
				}
				sprintf(buf + j, "  %08x", val);
				j = strlen(buf);
			}
			printk("%s\n", buf);
			j = 0;
		}
		if (buf != NULL)
			kfree(buf);
	} else if (data[0] == MWL_GET_MEMDUMP_MS) {

		int k;
		offset = data[1] & 0xfffffffc;

		length = data[2] * 4;
		if (!length)
			length = 32;
		buf = kmalloc(length * 10 + 100, GFP_KERNEL);
		if (buf == NULL) {
			rc = -EFAULT;
			return rc;
		}

		sprintf(buf + j, "dump mem\n");
		j = strlen(buf);
		for (k = 0; k < length; k += 256) {
			for (i = 0; i < 256; i += 4) {
				volatile unsigned int val = 0;

				val = le32_to_cpu(*(volatile unsigned int *)
						  ((unsigned int)priv->ioBase0 +
						   offset + i + k));

				if (i % 16 == 0) {
					sprintf(buf + j, "\n0x%08x",
						(int)(0xC0000000 + offset + i +
						      k));
					j = strlen(buf);
				}
				sprintf(buf + j, "  %08x", val);
				j = strlen(buf);
			}
			printk("%s\n", buf);
			j = 0;
		}
		if (buf != NULL)
			kfree(buf);
	} else if (data[0] == MWL_GET_MEMDUMP_RF) {

		offset = data[1];
		length = data[2];
		if (!length)
			length = 32;
		buf = kmalloc(length * 10 + 100, GFP_KERNEL);
		if (buf == NULL) {
			rc = -EFAULT;
			return rc;
		}

		sprintf(buf + j, "dump rf regs\n");
		j = strlen(buf);
		for (i = 0; i < length; i++) {
			wlRegRF(netdev, WL_GET, offset + i, (UINT32 *) & val);
			if (i % 8 == 0) {
				sprintf(buf + j, "\n%02x: ", (int)(offset + i));
				j = strlen(buf);
			}
			sprintf(buf + j, "  %02x", (int)val);
			j = strlen(buf);
		}
		printk("%s\n\n", buf);
		if (buf != NULL)
			kfree(buf);
	} else if (data[0] == MWL_GET_MEMDUMP_BB) {

		offset = data[1];
		length = data[2];
		if (!length)
			length = 32;
		buf = kmalloc(length * 10 + 100, GFP_KERNEL);
		if (buf == NULL) {
			rc = -EFAULT;
			return rc;
		}

		sprintf(buf + j, "dump bb regs\n");
		j = strlen(buf);
		for (i = 0; i < length; i++) {
			wlRegBB(netdev, WL_GET, offset + i, (UINT32 *) & val);
			if (i % 8 == 0) {
				sprintf(buf + j, "\n%02x: ", (int)(offset + i));
				j = strlen(buf);
			}
			sprintf(buf + j, "  %02x", (int)val);
			j = strlen(buf);
		}
		printk("%s\n\n", buf);
		if (buf != NULL)
			kfree(buf);
	} else if (data[0] == MWL_GET_MEMDUMP_ADDR) {

		UINT32 addr;
		UINT32 *addr_val = kmalloc(64 * sizeof(UINT32), GFP_KERNEL);
		if (addr_val == NULL) {
			rc = -EFAULT;
			return rc;
		}
		memset(addr_val, 0, 64 * sizeof(UINT32));
		addr = data[1] & 0xfffffffc;	// 4 byte boundary
		// length is unit of 4 bytes
		length = data[2];
		if (!length)
			length = 32;
		if (length > 64)
			length = 64;
		if (wlFwGetAddrValue(netdev, addr, length, addr_val, 0)) {
			printk("Could not get the memory address value\n");
			rc = -EFAULT;
			kfree(addr_val);
			return rc;
		}
		buf = kmalloc(length * 16 + 100, GFP_KERNEL);
		if (buf == NULL) {
			rc = -EFAULT;
			kfree(addr_val);
			return rc;
		}
		j += sprintf(buf + j, "dump addr\n");
		for (i = 0; i < length; i++) {
			if (i % 2 == 0) {
				j += sprintf(buf + j, "\n%08x: ",
					     (int)(addr + i * 4));
			}
			j += sprintf(buf + j, "  %08x", (int)addr_val[i]);
		}
		printk("%s\n\n", buf);
		if (buf != NULL)
			kfree(buf);
		kfree(addr_val);
	}
	return 0;
}

int
mwl_drv_set_desire_bssid(struct net_device *netdev, uint8_t * desireBSSID)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	memcpy(mib->StationConfig->DesiredBSSId, desireBSSID,
	       IEEEtypes_ADDRESS_SIZE);

	//#ifdef DBG
	printk("BSSID IS :%02X:%02X:%02X:%02X:%02X:%02X\n",
	       desireBSSID[0],
	       desireBSSID[1],
	       desireBSSID[2], desireBSSID[3], desireBSSID[4], desireBSSID[5]);
	//#endif

	return 0;
}

#ifdef EWB
extern hash_entry hashTable[HASH_ENTRY_COLUMN_MAX];
int
mwl_drv_get_ewbtable(void)
{
	int i, j;
	hash_entry *pEntry;

	for (i = 0; i < HASH_ENTRY_COLUMN_MAX; i++) {
		pEntry = &hashTable[i];
		for (j = 0; j < HASH_ENTRY_ROW_MAX; j++) {
			if (pEntry && pEntry->nwIpAddr) {
				printk("Index [%d,%d] \t IP=%x \t MAC=%02X:%02X:%02X:%02X:%02X:%02X\n", i, j, (int)pEntry->nwIpAddr, pEntry->hwAddr[0], pEntry->hwAddr[1], pEntry->hwAddr[2], pEntry->hwAddr[3], pEntry->hwAddr[4], pEntry->hwAddr[5]);

				pEntry = (hash_entry *) pEntry->nxtEntry;
			} else
				break;
		}
	}

	return 0;
}
#endif

#if defined (SOC_W8366) || defined (SOC_W8364) || defined (SOC_W8764)
int
mwl_drv_set_ratetable(struct net_device *netdev, uint8_t clear,
		      uint8_t * macaddr, uint32_t rateinfo)
{
	if (clear == 1) {
		wlFwSetRateTable(netdev, 0, (UINT8 *) macaddr, 0);
		printk("%02x %02x %02x %02x %02x %02x: Client ,",
		       (int)macaddr[0],
		       (int)macaddr[1],
		       (int)macaddr[2],
		       (int)macaddr[3], (int)macaddr[4], (int)macaddr[5]
			);
		printk("clear ratetable\n");
	} else {
		printk("%02x %02x %02x %02x %02x %02x: Client ,",
		       (int)macaddr[0],
		       (int)macaddr[1],
		       (int)macaddr[2],
		       (int)macaddr[3], (int)macaddr[4], (int)macaddr[5]
			);
		printk("rateinfo 0x%x\n", rateinfo);
		wlFwSetRateTable(netdev, 1, (UINT8 *) macaddr, rateinfo);
	}
	return 0;
}

#ifdef SOC_W8864
extern void ratetable_print_SOCW8864(UINT8 * pTbl);
#else
extern void ratetable_print_SOCW8764(UINT8 * pTbl);
#endif

int
mwl_drv_get_ratetable(struct net_device *netdev, uint8_t mu, uint8_t * macaddr)
{
	UINT32 size;
	UINT8 *pRateTable = NULL;
	UINT8 type = 0;

	size = RATEINFO_DWORD_SIZE * RATE_ADAPT_MAX_SUPPORTED_RATES;
	pRateTable = kmalloc(size, GFP_KERNEL);

	if (mu)
		type = 1;
	else
		type = 0;

	memset(pRateTable, 0, size);
	wlFwGetRateTable(netdev, (UINT8 *) macaddr, (UINT8 *) pRateTable, size,
			 type);

	printk("%02x %02x %02x %02x %02x %02x: Client\n",
	       (int)macaddr[0],
	       (int)macaddr[1],
	       (int)macaddr[2],
	       (int)macaddr[3], (int)macaddr[4], (int)macaddr[5]
		);

#ifdef SOC_W8864
	ratetable_print_SOCW8864((UINT8 *) pRateTable);
#else
	ratetable_print_SOCW8764((UINT8 *) pRateTable);
#endif

	kfree(pRateTable);
	pRateTable = NULL;

	return 0;
}
#endif

#ifdef DYNAMIC_BA_SUPPORT
int
mwl_drv_set_ampdu_bamgmt(struct net_device *netdev, uint32_t val)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	int rc = 0;
	if (val != 0 && val != 1) {
		printk("incorrect status values \n");
		rc = -EFAULT;
		return rc;
	} else {
		*(mib->mib_ampdu_bamgmt) = val;
		printk("AMPDU Bandwidth mgmt status is %d\n",
		       (int)*(mib->mib_ampdu_bamgmt));
	}
	return 0;
}

int
mwl_drv_get_ampdu_bamgmt(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	printk("AMPDU Bandwidth mgmt status is %d\n",
	       (int)*(mib->mib_ampdu_bamgmt));
	return 0;
}

int
mwl_drv_set_ampdu_mintraffic(struct net_device *netdev, uint32_t bk,
			     uint32_t be, uint32_t vi, uint32_t vo)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	if (!bk || !be || !vi || !vo)
		printk("Some values are set to Zero !!!!! \n");

	*(mib->mib_ampdu_mintraffic[1]) = bk;
	*(mib->mib_ampdu_mintraffic[0]) = be;
	*(mib->mib_ampdu_mintraffic[2]) = vi;
	*(mib->mib_ampdu_mintraffic[3]) = vo;
	printk("Now AMPDU Min Traffic \n -------------------- \n");
	printk("AC_BK = %d \n", (int)*(mib->mib_ampdu_mintraffic[1]));
	printk("AC_BE = %d \n", (int)*(mib->mib_ampdu_mintraffic[0]));
	printk("AC_VI = %d \n", (int)*(mib->mib_ampdu_mintraffic[2]));
	printk("AC_VO = %d \n", (int)*(mib->mib_ampdu_mintraffic[3]));

	return 0;
}

int
mwl_drv_get_ampdu_mintraffic(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	printk("AMPDU Min Traffic \n -------------------- \n");
	printk("AC_BK = %d \n", (int)*(mib->mib_ampdu_mintraffic[1]));
	printk("AC_BE = %d \n", (int)*(mib->mib_ampdu_mintraffic[0]));
	printk("AC_VI = %d \n", (int)*(mib->mib_ampdu_mintraffic[2]));
	printk("AC_VO = %d \n", (int)*(mib->mib_ampdu_mintraffic[3]));

	return 0;
}

int
mwl_drv_set_ac_threshold(struct net_device *netdev, uint32_t bk, uint32_t be,
			 uint32_t vi, uint32_t vo)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	if (!bk || !be || !vi || !vo)
		printk("Some values are set to Zero !!!!! \n");

	*(mib->mib_ampdu_low_AC_thres[1]) = bk;
	*(mib->mib_ampdu_low_AC_thres[0]) = be;
	*(mib->mib_ampdu_low_AC_thres[2]) = vi;
	*(mib->mib_ampdu_low_AC_thres[3]) = vo;

	printk("Now AMPDU Low Threshold \n -------------------- \n");
	printk("AC_BK = %d \n", (int)*(mib->mib_ampdu_low_AC_thres[1]));
	printk("AC_BE = %d \n", (int)*(mib->mib_ampdu_low_AC_thres[0]));
	printk("AC_VI = %d \n", (int)*(mib->mib_ampdu_low_AC_thres[2]));
	printk("AC_VO = %d \n", (int)*(mib->mib_ampdu_low_AC_thres[3]));

	return 0;
}

int
mwl_drv_get_ac_threshold(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	printk("AMPDU Low Threshold \n -------------------- \n");
	printk("AC_BK = %d \n", (int)*(mib->mib_ampdu_low_AC_thres[1]));
	printk("AC_BE = %d \n", (int)*(mib->mib_ampdu_low_AC_thres[0]));
	printk("AC_VI = %d \n", (int)*(mib->mib_ampdu_low_AC_thres[2]));
	printk("AC_VO = %d \n", (int)*(mib->mib_ampdu_low_AC_thres[3]));

	return 0;
}
#endif

#ifdef BARBADOS_DFS_TEST
int
mwl_drv_set_dfstest(uint8_t testmode)
{
	extern UINT8 dfs_test_mode;

	dfs_test_mode = testmode;

	printk("dfstest : dfs_test_mode = %x \n", dfs_test_mode);

	return 0;
}
#endif

extern int IPAsciiToNum(unsigned int *IPAddr, const char *pIPStr);
extern int getMacFromString(unsigned char *macAddr, const char *pStr);
#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
((unsigned char *)&addr)[1], \
((unsigned char *)&addr)[2], \
((unsigned char *)&addr)[3]

#ifdef MPRXY
int
mwl_drv_set_ipmcgrp(struct net_device *netdev, uint8_t setmode,
		    uint8_t * ipaddr, uint8_t * macaddr)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	UINT32 McIPAddr;
	UINT8 UcMACAddr[6];
	UINT8 i, j;
	BOOLEAN IPMcEntryExists = FALSE;
	BOOLEAN UcMACEntryExists = FALSE;
	BOOLEAN IPMFilterEntryExists = FALSE;
	UINT32 tempIPAddr;
	int rc = 0;

	if (!IPAsciiToNum((unsigned int *)&McIPAddr, ipaddr) &&
	    setmode != MWL_SET_IPMCGRP_GETALLGRPS &&
	    setmode != MWL_SET_IPMCGRP_GETIPMFILTER) {
		rc = -EFAULT;
		return rc;
	}

	if (McIPAddr == 0 &&
	    ((MWL_SET_IPMCGRP_ADD == setmode) ||
	     (MWL_SET_IPMCGRP_DEL == setmode) ||
	     (MWL_SET_IPMCGRP_DELGRP == setmode) ||
	     (MWL_SET_IPMCGRP_ADDIPMFILTER == setmode) ||
	     (MWL_SET_IPMCGRP_DELIPMFILTER == setmode))) {
		rc = -EFAULT;
		return rc;
	}

	if (!getMacFromString(UcMACAddr, macaddr) &&
	    ((MWL_SET_IPMCGRP_ADD == setmode) ||
	     (MWL_SET_IPMCGRP_DEL == setmode))) {
		rc = -EFAULT;
		return rc;
	}

	if (MWL_SET_IPMCGRP_ADD == setmode) {
		for (i = 0; i < MAX_IP_MCAST_GRPS; i++) {
			if (mib->mib_IPMcastGrpTbl[i]->mib_McastIPAddr ==
			    McIPAddr) {
				IPMcEntryExists = TRUE;

				if (mib->mib_IPMcastGrpTbl[i]->mib_MAddrCount <
				    MAX_UCAST_MAC_IN_GRP) {
					/*check if unicast adddress entry already exists in table */
					for (j = 0; j < MAX_UCAST_MAC_IN_GRP;
					     j++) {
						if (memcmp
						    ((char *)&mib->
						     mib_IPMcastGrpTbl[i]->
						     mib_UCastAddr[j],
						     (char *)&UcMACAddr,
						     6) == 0) {
							UcMACEntryExists = TRUE;
							break;
						}
					}

					if (UcMACEntryExists == FALSE) {
						/* Add the MAC address into the table */
						memcpy((char *)&mib->
						       mib_IPMcastGrpTbl[i]->
						       mib_UCastAddr[mib->
								     mib_IPMcastGrpTbl
								     [i]->
								     mib_MAddrCount],
						       (char *)&UcMACAddr, 6);
						mib->mib_IPMcastGrpTbl[i]->
							mib_MAddrCount++;
						break;
					}
				} else {
					rc = -EFAULT;
					return rc;
				}
			}
		}

		/* if IP multicast group entry does not exist */
		if (IPMcEntryExists == FALSE) {
			/*check if space available in table */
			if (*(mib->mib_IPMcastGrpCount) < MAX_IP_MCAST_GRPS) {
				mib->mib_IPMcastGrpTbl[*
						       (mib->
							mib_IPMcastGrpCount)]->
					mib_McastIPAddr = McIPAddr;

				/* Add the MAC address into the table */
				i = *(mib->mib_IPMcastGrpCount);

				memcpy((char *)&mib->mib_IPMcastGrpTbl[i]->
				       mib_UCastAddr[mib->mib_IPMcastGrpTbl[i]->
						     mib_MAddrCount],
				       (char *)&UcMACAddr, 6);

				/* increment unicast mac address count */
				mib->mib_IPMcastGrpTbl[i]->mib_MAddrCount++;

				/*increment the IP multicast group slot by 1 */
				*(mib->mib_IPMcastGrpCount) =
					*(mib->mib_IPMcastGrpCount) + 1;
			} else {
				rc = -EFAULT;
				return rc;
			}
		}
	} else if (MWL_SET_IPMCGRP_DEL == setmode) {
		/* check if IP Multicast group entry already exists */
		for (i = 0; i < MAX_IP_MCAST_GRPS; i++) {
			/*match IP multicast grp address with entry */
			if (mib->mib_IPMcastGrpTbl[i]->mib_McastIPAddr ==
			    McIPAddr) {
				/*find the unicast address entry in the IP multicast group */
				for (j = 0; j < MAX_UCAST_MAC_IN_GRP; j++) {
					if (memcmp
					    ((char *)&mib->
					     mib_IPMcastGrpTbl[i]->
					     mib_UCastAddr[j],
					     (char *)&UcMACAddr, 6) == 0) {
						/*decrement the count for unicast mac entries */
						mib->mib_IPMcastGrpTbl[i]->
							mib_MAddrCount--;

						/*if this is the very first entry, slot zero */
						if (mib->mib_IPMcastGrpTbl[i]->
						    mib_MAddrCount == 0) {
							/* set the entry to zero */
							memset((char *)&mib->
							       mib_IPMcastGrpTbl
							       [i]->
							       mib_UCastAddr[j],
							       0, 6);
							break;
						} else {
							/*if this is other than slot zero */
							/* set the entry to zero */
							memset((char *)&mib->
							       mib_IPMcastGrpTbl
							       [i]->
							       mib_UCastAddr[j],
							       0, 6);
							/* move up entries to fill the vacant spot */
							memcpy((char *)&mib->
							       mib_IPMcastGrpTbl
							       [i]->
							       mib_UCastAddr[j],
							       (char *)&mib->
							       mib_IPMcastGrpTbl
							       [i]->
							       mib_UCastAddr[j +
									     1],
							       (mib->
								mib_IPMcastGrpTbl
								[i]->
								mib_MAddrCount -
								j) * 6);
							/* clear the last unicast entry since all entries moved up by 1 */
							memset((char *)&mib->
							       mib_IPMcastGrpTbl
							       [i]->
							       mib_UCastAddr
							       [mib->
								mib_IPMcastGrpTbl
								[i]->
								mib_MAddrCount],
							       0, 6);
							break;
						}
					}
				}
			}
		}
	} else if (MWL_SET_IPMCGRP_DELGRP == setmode) {
		/* check if IP Multicast group entry already exists */
		for (i = 0; i < MAX_IP_MCAST_GRPS; i++) {
			/*match IP multicast grp address with entry */
			if (mib->mib_IPMcastGrpTbl[i]->mib_McastIPAddr ==
			    McIPAddr) {
				/*decrement the count of IP multicast groups */
				*(mib->mib_IPMcastGrpCount) =
					*(mib->mib_IPMcastGrpCount) - 1;

				/* if this is first entry i.e. slot zero */
				/* set the entire group entry to zero */
				/* set the entry to zero */
				if (i == 0) {
					memset((char *)mib->
					       mib_IPMcastGrpTbl[i], 0,
					       sizeof(MIB_IPMCAST_GRP_TBL));
					break;
				} else {
					/* if this is a slot other than zero */
					/* set the entry to zero */
					memset((char *)mib->
					       mib_IPMcastGrpTbl[i], 0,
					       sizeof(MIB_IPMCAST_GRP_TBL));

					/* move up entries to fill the vacant spot */
					memcpy((char *)&mib->
					       mib_IPMcastGrpTbl[i],
					       (char *)&mib->
					       mib_IPMcastGrpTbl[i + 1],
					       (*(mib->mib_IPMcastGrpCount) -
						i) *
					       sizeof(MIB_IPMCAST_GRP_TBL));

					/* clear the last unicast entry since all entries moved up by 1 */
					memset((char *)mib->
					       mib_IPMcastGrpTbl[*
								 (mib->
								  mib_IPMcastGrpCount)],
					       0, sizeof(MIB_IPMCAST_GRP_TBL));
				}
			}
		}
	} else if (MWL_SET_IPMCGRP_GETGRP == setmode) {
		/* check if IP Multicast group entry already exists */
		for (i = 0; i < MAX_IP_MCAST_GRPS; i++) {
			/*match IP multicast grp address with entry */
			if (mib->mib_IPMcastGrpTbl[i]->mib_McastIPAddr ==
			    McIPAddr) {
				tempIPAddr =
					htonl(mib->mib_IPMcastGrpTbl[i]->
					      mib_McastIPAddr);

				for (j = 0; j < MAX_UCAST_MAC_IN_GRP; j++)
					printk("%u.%u.%u.%u %02x%02x%02x%02x%02x%02x\n", NIPQUAD(tempIPAddr), mib->mib_IPMcastGrpTbl[i]->mib_UCastAddr[j][0], mib->mib_IPMcastGrpTbl[i]->mib_UCastAddr[j][1], mib->mib_IPMcastGrpTbl[i]->mib_UCastAddr[j][2], mib->mib_IPMcastGrpTbl[i]->mib_UCastAddr[j][3], mib->mib_IPMcastGrpTbl[i]->mib_UCastAddr[j][4], mib->mib_IPMcastGrpTbl[i]->mib_UCastAddr[j][5]);
			}
		}
	} else if (MWL_SET_IPMCGRP_GETALLGRPS == setmode) {
		/* check if IP Multicast group entry already exists */
		for (i = 0; i < MAX_IP_MCAST_GRPS; i++) {
			if (mib->mib_IPMcastGrpTbl[i]->mib_McastIPAddr) {
				tempIPAddr =
					htonl(mib->mib_IPMcastGrpTbl[i]->
					      mib_McastIPAddr);

				printk("IP Multicast Group: %u.%u.%u.%u \t Cnt:%d\n", NIPQUAD(tempIPAddr), mib->mib_IPMcastGrpTbl[i]->mib_MAddrCount);

				for (j = 0; j < MAX_UCAST_MAC_IN_GRP; j++) {
					printk("%u.%u.%u.%u %02x%02x%02x%02x%02x%02x\n", NIPQUAD(tempIPAddr), mib->mib_IPMcastGrpTbl[i]->mib_UCastAddr[j][0], mib->mib_IPMcastGrpTbl[i]->mib_UCastAddr[j][1], mib->mib_IPMcastGrpTbl[i]->mib_UCastAddr[j][2], mib->mib_IPMcastGrpTbl[i]->mib_UCastAddr[j][3], mib->mib_IPMcastGrpTbl[i]->mib_UCastAddr[j][4], mib->mib_IPMcastGrpTbl[i]->mib_UCastAddr[j][5]);
				}
			}
		}
	} else if (MWL_SET_IPMCGRP_ADDIPMFILTER == setmode) {
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
			if (*(mib->mib_IPMFilteredAddressIndex) <
			    MAX_IP_MCAST_GRPS) {
				*(mib->
				  mib_IPMFilteredAddress[*
							 (mib->
							  mib_IPMFilteredAddressIndex)])
				   = McIPAddr;

				/*increment the IP multicast filter address index by 1 */
				*(mib->mib_IPMFilteredAddressIndex) =
					*(mib->mib_IPMFilteredAddressIndex) + 1;
			} else {
				rc = -EFAULT;
				return rc;
			}
		}
	} else if (MWL_SET_IPMCGRP_DELIPMFILTER == setmode) {
		/* check if IP Multicast Filter entry already exists */
		for (i = 0; i < MAX_IP_MCAST_GRPS; i++) {
			/*match IP multicast grp address with entry */
			if (*(mib->mib_IPMFilteredAddress[i]) == McIPAddr) {
				/* set the entry to zero */
				*(mib->mib_IPMFilteredAddress[i]) = 0;

				/*decrement the count of IP multicast groups */
				*(mib->mib_IPMFilteredAddressIndex) =
					*(mib->mib_IPMFilteredAddressIndex) - 1;

				/* move up entries to fill the vacant spot */
				for (j = 0;
				     j <
				     (*(mib->mib_IPMFilteredAddressIndex) - i);
				     j++)
					*(mib->mib_IPMFilteredAddress[i + j]) =
						*(mib->
						  mib_IPMFilteredAddress[i + j +
									 1]);

				/* clear the last entry since all entries moved up by 1 */
				*(mib->
				  mib_IPMFilteredAddress[*
							 (mib->
							  mib_IPMFilteredAddressIndex)])
				   = 0;

				break;
			}
		}
	} else if (MWL_SET_IPMCGRP_GETIPMFILTER == setmode) {
		for (i = 0; i < MAX_IP_MCAST_GRPS; i++) {
			tempIPAddr = htonl(*(mib->mib_IPMFilteredAddress[i]));

			printk("%u.%u.%u.%u \n", NIPQUAD(tempIPAddr));
		}
	}

	else {
		rc = -EFAULT;
		return rc;
	}

	return 0;
}
#endif

extern int atoi(const char *num_str);

int
mwl_drv_set_rptrmode(struct net_device *netdev, uint8_t mode,
		     uint8_t * devicetype, uint8_t * agingtime,
		     uint8_t * macaddr)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	extStaDb_StaInfo_t *pStaInfo;
	int val;
	int rc = 0;

	/* Get VMAC structure of the master */
	if (!priv->master) {
		printk("Device %s is not a client device \n", netdev->name);
		rc = -EFAULT;
		return rc;
	}

	if (MWL_SET_RPTRMODE_NONE == mode) {
		printk("mode: %d\n", *(mib->mib_RptrMode));
	} else if ((MWL_SET_RPTRMODE_ZERO == mode) ||
		   (MWL_SET_RPTRMODE_ONE == mode)) {
		val = mode - 1;

		if (val < 0 || val > 1) {
			rc = -EOPNOTSUPP;
			return rc;
		}
		*(mib->mib_RptrMode) = val;
		if (vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_CLNT_INFRA) {
			if (val)
				*(mib->mib_STAMacCloneEnable) = 2;
			else
				*(mib->mib_STAMacCloneEnable) = 0;
		}
	} else if (MWL_SET_RPTRMODE_DEVICETYPE == mode) {
		if (strlen(devicetype) > (MAXRPTRDEVTYPESTR - 1)) {
			rc = -EOPNOTSUPP;
			return rc;
		}

		if (strlen(devicetype) != 0) {
			memcpy(mib->mib_RptrDeviceType, devicetype,
			       strlen(devicetype));
		} else {
			printk("DeviceType: %s\n", mib->mib_RptrDeviceType);
		}
	} else if (MWL_SET_IPMCGRP_AGINGTIME == mode) {
		if (strlen(agingtime) != 0) {
			val = atoi(agingtime);
			if (val < 60 || val > 86400) {
				rc = -EOPNOTSUPP;
				return rc;
			}
			*(mib->mib_agingtimeRptr) = val;
		} else {
			printk("agingtime: %d\n", (int)*mib->mib_agingtimeRptr);
		}
	} else if (MWL_SET_IPMCGRP_LISTMAC == mode) {
		extern UINT16 ethStaDb_list(vmacApInfo_t * vmac_p);
		ethStaDb_list(vmacSta_p);
	} else if (MWL_SET_IPMCGRP_ADDMAC == mode) {
		getMacFromString(macaddr, macaddr);
		if ((pStaInfo =
		     extStaDb_GetStaInfo(vmacSta_p,
					 (IEEEtypes_MacAddr_t *) macaddr,
					 0)) != NULL) {
			pStaInfo->StaType = 0x02;
		}
	} else if (MWL_SET_IPMCGRP_DELMAC == mode) {
		getMacFromString(macaddr, macaddr);
		if ((pStaInfo =
		     extStaDb_GetStaInfo(vmacSta_p,
					 (IEEEtypes_MacAddr_t *) macaddr,
					 0)) != NULL) {
			pStaInfo->StaType = 0;
			ethStaDb_RemoveStaPerWlan(vmacSta_p,
						  (IEEEtypes_MacAddr_t *)
						  macaddr);
		}
	} else {
		rc = -EFAULT;
		return rc;
	}

	return 0;
}

extern long atohex(const char *number);
extern int atoi_2(const char *num_str);
extern long atohex2(const char *number);

int
mwl_drv_set_load_txpowertable(struct net_device *netdev, uint8_t * filename)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	struct file *filp = NULL;
	mm_segment_t oldfs;
	char buff[120], *s;
	int len, index = 0, i, value = 0;

	char param[36][10];
	memset(param, 0, sizeof(param));
	oldfs = get_fs();
	set_fs(KERNEL_DS);

	filp = filp_open(filename, O_RDONLY, 0);
	// if (filp != NULL) // Note: this one doesn't work and will cause crash
	if (!IS_ERR(filp))	// MUST use this one, important!!!
	{
		printk("loadtxpwrtable open <%s>: OK\n", filename);

		/* reset the whole table */
		for (i = 0; i < IEEE_80211_MAX_NUMBER_OF_CHANNELS; i++)
			memset(mib->PhyTXPowerTable[i], 0,
			       sizeof(MIB_TX_POWER_TABLE));

		while (1) {
			s = buff;
			while ((len =
				vfs_read(filp, s, 0x01, &filp->f_pos)) == 1) {
				if (*s == '\n') {
					/* skip blank line */
					if (s == buff)
						break;

					/* parse this line and assign value to data structure */
					*s = '\0';
					printk("index=<%d>: <%s>\n", index,
					       buff);
#if defined(SOC_W8964)
					/* 8964 total param: ch + setcap + 32 txpower + CDD + tx2 = 36 */
					sscanf(buff,
					       "%s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s\n",
					       param[0], param[1], param[2],
					       param[3], param[4], param[5],
					       param[6], param[7], param[8],
					       param[9], param[10], param[11],
					       param[12], param[13], param[14],
					       param[15], param[16], param[17],
					       param[18], param[19], param[20],
					       param[21], param[22], param[23],
					       param[24], param[25], param[26],
					       param[27], param[28], param[29],
					       param[30], param[31], param[32],
					       param[33], param[34], param[35]);

					if (strcmp(param[34], "on") == 0)
						value = 1;
					else if (strcmp(param[34], "off") == 0)
						value = 0;

#elif defined(SOC_W8864)
					/* 8864 total param: ch + setcap + 16 txpower + CDD + tx2 = 20 */
					sscanf(buff,
					       "%s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s\n",
					       param[0], param[1], param[2],
					       param[3], param[4], param[5]
					       , param[6], param[7], param[8],
					       param[9], param[10], param[11],
					       param[12], param[13], param[14],
					       param[15], param[16], param[17]
					       , param[18], param[19]);

					if (strcmp(param[18], "on") == 0)
						value = 1;
					else if (strcmp(param[18], "off") == 0)
						value = 0;
#else
					/* total param: ch + setcap + 12 txpower + CDD + tx2 = 16 */
					sscanf(buff,
					       "%s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s\n",
					       param[0], param[1], param[2],
					       param[3], param[4], param[5]
					       , param[6], param[7], param[8],
					       param[9], param[10], param[11],
					       param[12], param[13], param[14],
					       param[15]);

					if (strcmp(param[14], "on") == 0)
						value = 1;
					else if (strcmp(param[14], "off") == 0)
						value = 0;
#endif
					else {
						printk("txpower table format error: CCD should be on|off\n");
						break;
					}
					mib->PhyTXPowerTable[index]->CDD =
						value;

#if defined(SOC_W8964)
					mib->PhyTXPowerTable[index]->
						txantenna2 = atohex2(param[35]);
#elif defined (SOC_W8864)
					mib->PhyTXPowerTable[index]->
						txantenna2 = atohex2(param[19]);
#else
					mib->PhyTXPowerTable[index]->
						txantenna2 = atohex2(param[15]);
#endif

					mib->PhyTXPowerTable[index]->Channel =
						atoi(param[0]);
					mib->PhyTXPowerTable[index]->setcap =
						atoi(param[1]);

					for (i = 0; i < TX_POWER_LEVEL_TOTAL;
					     i++) {

#ifdef SOC_W8964
						s16 pwr;

						pwr = (s16)
							atoi_2(param[i + 2]);
						mib->PhyTXPowerTable[index]->
							TxPower[i] = pwr;
#else
						mib->PhyTXPowerTable[index]->
							TxPower[i] =
							atohex2(param[i + 2]);
#endif
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
		printk("loadtxpwrtable open <%s>: FAIL\n", filename);

	set_fs(oldfs);

	return 0;
}

int
mwl_drv_get_txpowertable(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	int index;
	printk("txpower table:\n");
	for (index = 0; index < IEEE_80211_MAX_NUMBER_OF_CHANNELS; index++) {
		if (mib->PhyTXPowerTable[index]->Channel == 0)
			break;
#if defined(SOC_W8964)
		printk("%d %d 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x %d %d\n",
#elif defined(SOC_W8864)
		printk("%d %d 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x %d %d\n",
#else
		printk("%d %d 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x %d %d\n",
#endif
		       mib->PhyTXPowerTable[index]->Channel,
		       mib->PhyTXPowerTable[index]->setcap,
		       mib->PhyTXPowerTable[index]->TxPower[0],
		       mib->PhyTXPowerTable[index]->TxPower[1],
		       mib->PhyTXPowerTable[index]->TxPower[2],
		       mib->PhyTXPowerTable[index]->TxPower[3],
		       mib->PhyTXPowerTable[index]->TxPower[4],
		       mib->PhyTXPowerTable[index]->TxPower[5],
		       mib->PhyTXPowerTable[index]->TxPower[6],
		       mib->PhyTXPowerTable[index]->TxPower[7],
		       mib->PhyTXPowerTable[index]->TxPower[8],
		       mib->PhyTXPowerTable[index]->TxPower[9],
		       mib->PhyTXPowerTable[index]->TxPower[10],
		       mib->PhyTXPowerTable[index]->TxPower[11],
#ifdef SOC_W8864
		       mib->PhyTXPowerTable[index]->TxPower[12],
		       mib->PhyTXPowerTable[index]->TxPower[13],
		       mib->PhyTXPowerTable[index]->TxPower[14],
		       mib->PhyTXPowerTable[index]->TxPower[15],
#endif
#ifdef SOC_W8964
		       mib->PhyTXPowerTable[index]->TxPower[16],
		       mib->PhyTXPowerTable[index]->TxPower[17],
		       mib->PhyTXPowerTable[index]->TxPower[18],
		       mib->PhyTXPowerTable[index]->TxPower[19],
		       mib->PhyTXPowerTable[index]->TxPower[20],
		       mib->PhyTXPowerTable[index]->TxPower[21],
		       mib->PhyTXPowerTable[index]->TxPower[22],
		       mib->PhyTXPowerTable[index]->TxPower[23],
		       mib->PhyTXPowerTable[index]->TxPower[24],
		       mib->PhyTXPowerTable[index]->TxPower[25],
		       mib->PhyTXPowerTable[index]->TxPower[26],
		       mib->PhyTXPowerTable[index]->TxPower[27],
		       mib->PhyTXPowerTable[index]->TxPower[28],
		       mib->PhyTXPowerTable[index]->TxPower[29],
		       mib->PhyTXPowerTable[index]->TxPower[30],
		       mib->PhyTXPowerTable[index]->TxPower[31],
#endif
		       mib->PhyTXPowerTable[index]->CDD,
		       mib->PhyTXPowerTable[index]->txantenna2);
	}
	return 0;
}

extern UINT32 g_PrbeReqCheckTheshold[NUM_OF_WLMACS];
int
mwl_drv_set_linklost(uint32_t macIndex, uint32_t numOfInterval)
{
	extern UINT32 g_PrbeReqCheckTheshold[NUM_OF_WLMACS];

	if (numOfInterval < 4)
		numOfInterval = 4;

	g_PrbeReqCheckTheshold[macIndex] = numOfInterval;
	printk("Set wdev%d PrbeReqCheckTheshold to %d\n", macIndex,
	       numOfInterval);

	return 0;
}

#ifdef SSU_SUPPORT
extern void ssu_dump_file(UINT32 pPhyAddr, UINT32 * pSsuPci, UINT32 sizeBytes,
			  UINT32 printFlag);
int
mwl_drv_set_ssutest(struct wlprivate *priv, uint32_t * data)
{

	/* Fixed to 0x80000*4 bytes for now - 2 MBytes, more than is needed for 10ms trace. */
	//#define  SSU_DUMP_SIZE_DWORDS  0x80000
	ssu_cmd_t ssuCfg;
	struct net_device *netdev = priv->netDev;
	UINT32 *pSsuPci = (UINT32 *) priv->pSsuBuf;
	UINT16 dump = 0;

	dump = data[0];

	if (dump == 1) {
		UINT32 printFlag = data[1];
		ssu_dump_file(priv->wlpd_p->pPhysSsuBuf, pSsuPci, priv->ssuSize,
			      printFlag);
	} else {
		/* Clear memory before performing spectral dump from firmware. */
		memset((void *)&ssuCfg, 0x00, sizeof(ssuCfg));
		memset(pSsuPci, 0, priv->ssuSize);
		if (dump == 0) {
			ssuCfg.Time = data[4];
			printk("SSU fft_length =%d\n", data[1] & 0x03);
			printk("SSU fft_skip   =%d\n", data[2] & 0x03);
			printk("SSU adc_dec    =%d\n", data[3] & 0x03);
			printk("SSU Time       =%d\n", ssuCfg.Time);
		}

		if (dump == 2) {
			ssuCfg.Nskip = data[1];
			ssuCfg.Nsel = data[2];
			ssuCfg.AdcDownSample = data[3];
			ssuCfg.MaskAdcPacket = data[4];
			ssuCfg.Output16bits = data[5];
			ssuCfg.PowerEnable = data[6];
			ssuCfg.RateDeduction = data[7];
			ssuCfg.PacketAvg = data[8];
			ssuCfg.Time = data[9];
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

	return 0;
}
#endif

#ifdef QUEUE_STATS
int
mwl_drv_get_qstats(struct net_device *netdev, uint8_t qstattype,
		   uint32_t pktcount, uint32_t staidlabel, uint32_t enable,
		   uint32_t staid1, uint32_t staid2, uint32_t staid3,
		   uint32_t sumu, uint32_t staid4, uint8_t * macaddr)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	int rc = 0;

#ifdef QUEUE_STATS
#ifdef QUEUE_STATS_CNT_HIST
	extern wldbgStaTxPktStats_t txPktStats_sta[QS_NUM_STA_SUPPORTED];
	extern wldbgStaRxPktStats_t rxPktStats_sta[QS_NUM_STA_SUPPORTED];
#endif
	extern UINT32 dbgUdpSrcVal;
	extern UINT8 qs_rxMacAddrSave[24];
	extern int numOfRxSta;
#endif

	extern UINT32 RA_TX_ATTEMPT[2][6];	//[0:SU, 1:MU][6]
	extern UINT8 BA_HISTO_STAID_MAP[10];	//staid map to txBAStats[]

#ifdef QUEUE_STATS_CNT_HIST
	if (MWL_GET_QSTATS_PKTCOUNT == qstattype) {
		dbgUdpSrcVal = pktcount;
		wlFwGetQueueStats(netdev, QS_GET_TX_COUNTER, NULL);
	} else if (MWL_GET_QSTATS_RETRY_HISTOGRAM == qstattype) {
		wlFwGetQueueStats(netdev, QS_GET_RETRY_HIST, NULL);
	}
#ifdef NEWDP_ACNT_BA
	/*To collect total BA records specified by ACNT_BA_SIZE. After buffer is full, no more BA records collection.
	 * Need to use "qstats reset" to clear buffer to record BA records again.
	 * To enable/ disable this CLI, "qstats txba_histogram staid <0:disable|1:enable> <staid_1> <staid_2> <staid_3> <0:SU|1:MU>"
	 * To print output "qstats txba_histogram". Raw data is save in /tmp/ba_histo file
	 */
	else if (MWL_GET_QSTATS_TXBA_HISTOGRAM == qstattype) {
		UINT8 i, type = 0;
		UINT16 staid[3] = { 0, 0, 0 };
		WLAN_TX_BA_HIST *pBA = NULL;
		extern UINT8 BA_HISTO_STAID_MAP[10];
		/*Set enable/disable txba histogram for up to 3 stations from staid 1 to 9 */
		if (staidlabel == 1) {

			staid[0] = staid1;
			staid[1] = staid2;
			staid[2] = staid3;

			memset((UINT8 *) & BA_HISTO_STAID_MAP[0], 0,
			       (sizeof(UINT8) * 10));

			if (sumu < 2)	//0:SU, 1:MU
				type = sumu;
			else
				type = 0;

			for (i = 0; i < 3; i++) {

				/*Only support staid from 1 to 9 */
				if ((staid[i] > 0) && (staid[i] < 10)) {
					BA_HISTO_STAID_MAP[staid[i]] = i;	//create stnid map to ba_histo buffer for faster acnt update
				} else {
					printk("staid %d is out of supported id range\n", staid[i]);
					continue;
				}

				/*Update info when staid is valid */
				pBA = &priv->wlpd_p->txBAStats[i];
				pBA->StatsEnable = enable;
				if (enable) {
					printk("BA histogram %s, staid:%d, type:%s\n", enable ? "enable" : "disable", staid[i], type ? "MU" : "SU");

					if (pBA->pBAStats == NULL) {

						if ((pBA->pBAStats =
						     (WLAN_TX_BA_STATS *)
						     malloc(sizeof
							    (WLAN_TX_BA_STATS) *
							    ACNT_BA_SIZE)) !=
						    NULL) {
							memset(pBA->pBAStats, 0,
							       (sizeof
								(WLAN_TX_BA_STATS)
								*
								ACNT_BA_SIZE));
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
					printk("BA histogram %s\n",
					       enable ? "enable" : "disable");
					if (pBA->pBAStats != NULL) {
						free(pBA->pBAStats);
						pBA->pBAStats = NULL;
					}
				}
			}

			return 0;
		}

		/*Print txba_histogram */
		staid[0] = staid4;
		wlFwGetQueueStats(netdev, (QS_GET_BA_HIST | (staid[0] << 4)),
				  NULL);

	}
#endif
	else if (MWL_GET_QSTATS_TXRATE_HISTOGRAM == qstattype) {
		int indx, i, staid;
		int entries = extStaDb_entries(vmacSta_p, 0);
		UINT8 *staBuf = kmalloc(entries * sizeof(STA_INFO), GFP_KERNEL);
		UINT8 *listBuf;
		extStaDb_StaInfo_t *pStaInfo;

		if (staBuf == NULL) {
			printk("Can't alloc memory for txrate_histogram\n");
			rc = -EFAULT;
			return rc;
		}

		/*Print only staid */
		if (staidlabel == 1) {
			staid = staid1;
			printk("Total SU RA tx attempt cnt, <4:%d, >=4:%d, >=15:%d, >=50:%d, >=100:%d, >=250:%d\n", RA_TX_ATTEMPT[SU_MIMO][0], RA_TX_ATTEMPT[SU_MIMO][1], RA_TX_ATTEMPT[SU_MIMO][2], RA_TX_ATTEMPT[SU_MIMO][3], RA_TX_ATTEMPT[SU_MIMO][4], RA_TX_ATTEMPT[SU_MIMO][5]);

			printk("Total MU RA tx attempt cnt, <4:%d, >=4:%d, >=15:%d, >=50:%d, >=100:%d, >=250:%d\n\n", RA_TX_ATTEMPT[MU_MIMO][0], RA_TX_ATTEMPT[MU_MIMO][1], RA_TX_ATTEMPT[MU_MIMO][2], RA_TX_ATTEMPT[MU_MIMO][3], RA_TX_ATTEMPT[MU_MIMO][4], RA_TX_ATTEMPT[MU_MIMO][5]);

			printk("staid: %d\n", staid);
			printk("============================\n");
			wlFwGetQueueStats(netdev,
					  (QS_GET_TX_RATE_HIST |
					   ((staid - 1) << 4)), NULL);

			if (staBuf != NULL)
				kfree(staBuf);
			return 0;
		}
		if (staBuf != NULL) {
			if (!extStaDb_list(vmacSta_p, staBuf, 1)) {
				kfree(staBuf);
				rc = -EFAULT;
				return rc;
			}

			if (entries) {
				printk("Total SU RA tx attempt cnt, <4:%d, >=4:%d, >=15:%d, >=50:%d, >=100:%d, >=250:%d\n", RA_TX_ATTEMPT[SU_MIMO][0], RA_TX_ATTEMPT[SU_MIMO][1], RA_TX_ATTEMPT[SU_MIMO][2], RA_TX_ATTEMPT[SU_MIMO][3], RA_TX_ATTEMPT[SU_MIMO][4], RA_TX_ATTEMPT[SU_MIMO][5]);

				printk("Total MU RA tx attempt cnt, <4:%d, >=4:%d, >=15:%d, >=50:%d, >=100:%d, >=250:%d\n\n", RA_TX_ATTEMPT[MU_MIMO][0], RA_TX_ATTEMPT[MU_MIMO][1], RA_TX_ATTEMPT[MU_MIMO][2], RA_TX_ATTEMPT[MU_MIMO][3], RA_TX_ATTEMPT[MU_MIMO][4], RA_TX_ATTEMPT[MU_MIMO][5]);

				listBuf = staBuf;
				for (i = 0; i < entries; i++) {
					if ((pStaInfo =
					     extStaDb_GetStaInfo(vmacSta_p,
								 (IEEEtypes_MacAddr_t
								  *) listBuf,
								 2)) != NULL) {
						//if(wldbgIsInTxMacList((UINT8* )pStaInfo->Addr) )
						//printk("\nRate Histogram (Total samples = %10u)\n", (unsigned int)(jiffies-pStaInfo->jiffies));
						printk("\nSTA %02x:%02x:%02x:%02x:%02x:%02x\n", pStaInfo->Addr[0], pStaInfo->Addr[1], pStaInfo->Addr[2], pStaInfo->Addr[3], pStaInfo->Addr[4], pStaInfo->Addr[5]);
						printk("============================\n");
						indx = pStaInfo->
							StnId ? (pStaInfo->
								 StnId - 1) : 0;
						if (wlFwGetQueueStats
						    (netdev,
						     (QS_GET_TX_RATE_HIST |
						      (indx << 4)),
						     NULL) == 1) {
						}
						listBuf += sizeof(STA_INFO);
					}
				}
			} else {
				if (vmacSta_p->OpMode == WL_OP_MODE_STA ||
				    vmacSta_p->OpMode == WL_OP_MODE_VSTA ||
				    vmacSta_p->OpMode == WL_OP_MODE_VAP) {
					if (vmacSta_p->OpMode == WL_OP_MODE_VAP) {
						UINT32 i;

						for (i = 0; i < MAX_WDS_PORT;
						     i++) {
							if (vmacSta_p->
							    wdsActive[i]) {

								printk("\nWDS %02x:%02x:%02x:%02x:%02x:%02x\n", vmacSta_p->wdsPort[i].wdsMacAddr[0], vmacSta_p->wdsPort[i].wdsMacAddr[1], vmacSta_p->wdsPort[i].wdsMacAddr[2], vmacSta_p->wdsPort[i].wdsMacAddr[3], vmacSta_p->wdsPort[i].wdsMacAddr[4], vmacSta_p->wdsPort[i].wdsMacAddr[5]);
								printk("============================\n");
								if (wlFwGetQueueStats(netdev, (QS_GET_TX_RATE_HIST), NULL) == 1) {
								}
							}
						}
					} else {
						printk("\n STA mode, tx Data Frame Rate Histogram\n");
						printk("============================\n");
						if (wlFwGetQueueStats
						    (netdev,
						     QS_GET_TX_RATE_HIST,
						     NULL) == 1) {
						}
					}

				} else {
					printk("\ntx Rate Histogram => no available data\n");
				}
			}
			kfree(staBuf);
		}
	} else if (MWL_GET_QSTATS_RXRATE_HISTOGRAM == qstattype) {
		if (wlFwGetQueueStats(netdev, QS_GET_RX_RATE_HIST, NULL) == 1) {
			printk("\nRx Rate Histogram => no available data\n");
		}
	} else if (MWL_GET_QSTATS_ADDRXMAC == qstattype) {
		int k;
		for (k = 0; k < QS_NUM_STA_SUPPORTED; k++) {
			memcpy(rxPktStats_sta[k].addr, macaddr, 6);
			rxPktStats_sta[k].valid = 1;
			printk("Added Rx STA: %02x %02x %02x %02x %02x %02x\n",
			       rxPktStats_sta[k].addr[0],
			       rxPktStats_sta[k].addr[1],
			       rxPktStats_sta[k].addr[2],
			       rxPktStats_sta[k].addr[3],
			       rxPktStats_sta[k].addr[4],
			       rxPktStats_sta[k].addr[5]);
			memcpy(&qs_rxMacAddrSave[k * 6], rxPktStats_sta[k].addr,
			       6);
		}
		numOfRxSta = k;
		wlFwSetMacSa(netdev, numOfRxSta, (UINT8 *) qs_rxMacAddrSave);
	} else if (MWL_GET_QSTATS_ADDTXMAC == qstattype) {
		int k;
		for (k = 0; k < QS_NUM_STA_SUPPORTED; k++) {
			memcpy(txPktStats_sta[k].addr, macaddr, 6);
			txPktStats_sta[k].valid = 1;
			printk("Added Tx STA: %02x %02x %02x %02x %02x %02x\n",
			       (int)txPktStats_sta[k].addr[0],
			       (int)txPktStats_sta[k].addr[1],
			       (int)txPktStats_sta[k].addr[2],
			       (int)txPktStats_sta[k].addr[3],
			       (int)txPktStats_sta[k].addr[4],
			       (int)txPktStats_sta[k].addr[5]);
		}
	}
#endif
#ifdef QUEUE_STATS_LATENCY
	if (MWL_GET_QSTATS_TXLATENCY == qstattype) {
		wlFwGetQueueStats(netdev, QS_GET_TX_LATENCY, NULL);
	}
	if (MWL_GET_QSTATS_RXLATENCY == qstattype) {
		wlFwGetQueueStats(netdev, QS_GET_RX_LATENCY, NULL);
	}
#endif
	if (MWL_GET_QSTATS_RESET == qstattype) {
		int i, k, nss, bw, mcs, sgi;

#ifdef NEWDP_ACNT_BA
		for (i = 0; i < 3; i++) {
			priv->wlpd_p->txBAStats[i].Index = 0;
			if (priv->wlpd_p->txBAStats[i].pBAStats != NULL)
				memset(priv->wlpd_p->txBAStats[i].pBAStats, 0,
				       (sizeof(WLAN_TX_BA_STATS) *
					ACNT_BA_SIZE));
		}
#endif

		memset(&RA_TX_ATTEMPT[0], 0, (sizeof(UINT32) * 2 * 6));

		for (i = 0; i < QS_NUM_STA_SUPPORTED; i++)
			txPktStats_sta[i].valid = 0;
		for (i = 0; i < MAX_STNS; i++) {
			if (priv->wlpd_p->txRateHistogram[i] != NULL) {

				memset(priv->wlpd_p->txRateHistogram[i]->
				       CurRateInfo, 0,
				       sizeof(UINT32) * SU_MU_TYPE_CNT);
				memset(priv->wlpd_p->txRateHistogram[i]->
				       TotalTxCnt, 0,
				       sizeof(UINT32) * SU_MU_TYPE_CNT);

				for (k = 0; k < RATE_ADAPT_MAX_SUPPORTED_RATES;
				     k++) {
					priv->wlpd_p->txRateHistogram[i]->
						SU_rate[k].cnt = 0;
					memset(priv->wlpd_p->
					       txRateHistogram[i]->SU_rate[k].
					       per, 0,
					       sizeof(UINT32) *
					       TX_RATE_HISTO_PER_CNT);

				}
				for (nss = 0;
				     nss < (QS_NUM_SUPPORTED_11AC_NSS - 1);
				     nss++) {
					for (bw = 0;
					     bw < QS_NUM_SUPPORTED_11AC_BW;
					     bw++) {
						for (mcs = 0;
						     mcs <
						     QS_NUM_SUPPORTED_11AC_MCS;
						     mcs++) {
							for (sgi = 0;
							     sgi <
							     QS_NUM_SUPPORTED_GI;
							     sgi++) {
								priv->wlpd_p->
									txRateHistogram
									[i]->
									MU_rate
									[nss]
									[bw]
									[sgi]
									[mcs].
									cnt = 0;
								memset(priv->
								       wlpd_p->
								       txRateHistogram
								       [i]->
								       MU_rate
								       [nss][bw]
								       [sgi]
								       [mcs].
								       per, 0,
								       sizeof
								       (UINT32)
								       *
								       TX_RATE_HISTO_PER_CNT);
							}
						}
					}
				}

				for (k = 0; k < TX_RATE_HISTO_CUSTOM_CNT; k++) {
					priv->wlpd_p->txRateHistogram[i]->
						custom_rate[k].cnt = 0;
					memset(priv->wlpd_p->
					       txRateHistogram[i]->
					       custom_rate[k].per, 0,
					       sizeof(UINT32) *
					       TX_RATE_HISTO_PER_CNT);

				}

			}
		}

		memset(&priv->wlpd_p->rxRateHistogram, 0,
		       sizeof(WLAN_RATE_HIST));
	}

	return 0;
}
#endif

#ifdef SOC_W8864
int
mwl_drv_set_rccal(struct net_device *netdev)
{
	extern int wlFwSetRCcal(struct net_device *netdev);
	wlFwSetRCcal(netdev);
	printk("RC Cal done\n");

	return 0;
}

int
mwl_drv_get_temp(struct net_device *netdev)
{
	extern int wlFwGetTemp(struct net_device *netdev);
	wlFwGetTemp(netdev);

	return 0;
}
#endif

int
mwl_drv_set_maxsta(struct net_device *netdev, uint32_t maxsta)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	int rc = 0;
	int val;

	//Only take virtual interface as input
	if (!priv->master) {
		printk("Error. Please enter virtual interface instead\n");
		rc = -EOPNOTSUPP;
		return rc;
	}
	val = maxsta;
	if (val < 1 || val >= MAX_STNS) {
		printk("Incorrect value. Value between 1 to 64 only. Default is 64\n");
		rc = -EFAULT;
		return rc;
	}
	*(mib->mib_maxsta) = val;
	printk("Configure %s max station limit = %d\n", netdev->name,
	       (int)*(mib->mib_maxsta));

	return 0;
}

int
mwl_drv_get_maxsta(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	int rc = 0;

	if (!priv->master) {
		printk("Error. Please enter virtual interface instead\n");
		rc = -EOPNOTSUPP;
		return rc;
	}

	printk("Max station limit in %s is %d\n", netdev->name,
	       (int)*(mib->mib_maxsta));

	return 0;
}

int
mwl_drv_set_txfaillimit(struct net_device *netdev, uint32_t txfaillimit)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	int rc = 0;
	int val;

	//Only take parent interface as input
	if (priv->master) {
		printk("Error. Please enter parent interface %s instead\n",
		       priv->master->name);
		rc = -EOPNOTSUPP;
		return rc;
	}

	val = txfaillimit;
	if (val >= 0)
		*(mib->mib_consectxfaillimit) = val;
	else {
		printk("Error. Please enter value >= 0\n");
		rc = -EFAULT;
		return rc;
	}

	if (!wlFwSetConsecTxFailLimit(netdev, *(mib->mib_consectxfaillimit))) {
		if (*(mib->mib_consectxfaillimit))
			printk("Config %s txfail limit > %d\n", netdev->name,
			       (int)*(mib->mib_consectxfaillimit));
		else
			printk("txfail limit is disabled\n");
	}

	return 0;
}

int
mwl_drv_get_txfaillimit(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	int rc = 0;
	UINT32 val;

	//Only take parent interface as input
	if (priv->master) {
		printk("Error. Please enter parent interface %s instead\n",
		       priv->master->name);
		rc = -EOPNOTSUPP;
		return rc;
	}
	if (!wlFwGetConsecTxFailLimit(netdev, (UINT32 *) & val)) {
		if (val)
			printk("Consecutive txfail limit > %d\n", (int)val);
		else
			printk("txfail limit is disabled\n");
	}

	return 0;
}

#ifdef MRVL_WAPI
int
mwl_drv_set_wapi(struct net_device *netdev, uint8_t broadcast,
		 uint8_t * macaddr)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	int rc = 0;
	u16 auth_type;

	if (broadcast == 0) {
		auth_type = 0x00F2;
	} else if (broadcast == 1) {
		auth_type = 0x00F4;
		memcpy(macaddr, bcastMacAddr, 6);
	} else {
		rc = -EFAULT;
		return rc;
	}

	macMgmtMlme_WAPI_event(netdev, IWEVASSOCREQIE, auth_type, macaddr,
			       netdev->dev_addr, NULL);

	return 0;
}
#endif

#ifdef WNC_LED_CTRL
int
mwl_drv_set_led(struct net_device *netdev, uint32_t onoff)
{
	int rc = 0;
	if (onoff == 1) {
		printk("set led on ...\n");
		wlFwLedOn(netdev, 1);
	} else if (onoff == 0) {
		printk("set led off ...\n");
		wlFwLedOn(netdev, 0);
	} else {
		rc = -EFAULT;
		return rc;
	}
	return 0;
}
#endif

#ifdef CLIENT_SUPPORT
int
mwl_drv_set_fastreconnect(uint32_t probereqontx)
{
	int rc = 0;
	extern UINT8 ProbeReqOnTx;
	ProbeReqOnTx = probereqontx;
	printk("ProbeReqOnTx: %d\n", ProbeReqOnTx);

	if (ProbeReqOnTx < 0 || ProbeReqOnTx > 1) {
		printk("Pls submit value 0 or 1 only\n");
		ProbeReqOnTx = 0;
		rc = -EOPNOTSUPP;
		return rc;
	}
	return 0;
}
#endif

#ifdef NEW_DP
int
mwl_drv_set_newdp(struct net_device *netdev, uint32_t ch, uint32_t width,
		  uint32_t rates, uint32_t rate_type, uint32_t rate_bw,
		  uint32_t rate_gi, uint32_t rate_ss)
{
	wlFwNewDP_Cmd(netdev, ch, width, rates, rate_type, rate_bw, rate_gi,
		      rate_ss);
	printk("channel :%d width %d rate_type=%d [11n/ac] rates = %d bw = %d [20/40/80] rate_gi[SGI/LGI]=%d rate_ss=%d\n", ch, width, rate_type, rates, rate_bw, rate_gi, rate_ss);

	return 0;
}

int
mwl_drv_set_txratectrl(struct net_device *netdev, uint32_t type, uint32_t val,
		       uint32_t staid)
{
	printk("Rate drop using ");

	/*Auto rate */
	if (type == 1)
		printk("auto rate\n");

	/*Fixed rate using rate tbl index */
	else if (type == 2) {
		printk("rate table index %d\n", val);
	}

	/*Fixed rate using rateinfo */
	else if (type == 3) {
		printk("rateinfo 0x%x\n", val);
	}

	/*Fixed rate per sta. Specify station index to have fixed rateinfo
	 * txratectrl type 4 val 0x0f4f0522 staidx 1 //sta index 1 to have fixed rateinfo
	 */
	else if (type == 4) {
		printk("per sta index %d, rateinfo 0x%x\n", staid, val);
	}

	wlFwNewDP_RateDrop(netdev, type, val, staid);
	return 0;
}

int
mwl_drv_get_newdpcnt(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);

	NewdpRxCounter_t *pNewDpCnts =
		(NewdpRxCounter_t *) & priv->wlpd_p->rxCnts;
	printk("fastDataCnt = %d\nfastBadAmsduCnt = %d\nslowNoqueueCnt = %d\nslowNoRunCnt = %d\nslowMcastCnt = %d\nslowBadStaCnt = %d\n", pNewDpCnts->fastDataCnt, pNewDpCnts->fastBadAmsduCnt, pNewDpCnts->slowNoqueueCnt, pNewDpCnts->slowNoRunCnt, pNewDpCnts->slowMcastCnt, pNewDpCnts->slowBadStaCnt);
	printk("slowBadMicCnt = %d\nslowBadPNCnt = %d\nslowMgmtCnt = %d\nslowPromiscCnt = %d\ndropCnt = %d\noffChanPktCnt = %d\nMU PktCnt = %d\n", pNewDpCnts->slowBadMicCnt, pNewDpCnts->slowBadPNCnt, pNewDpCnts->slowMgmtCnt, pNewDpCnts->slowPromiscCnt, pNewDpCnts->dropCnt, pNewDpCnts->offchPromiscCnt, pNewDpCnts->mu_pktcnt);

	return 0;
}

int
mwl_drv_set_newdpacntsize(struct net_device *netdev)
{
	wlAcntSetBufSize(netdev, 0x20000);
	return 0;
}

int
mwl_drv_get_newdpacnt(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
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
	acnBuf = (u_int8_t *) malloc(bufSize);
	wlAcntReadRecds(netdev, (tail + bufSize), acnBuf, &bufSize);
	if (bufSize > 0) {
		acnt_t *pAcntRec;
		printk("acnt head=%d, tail=%d, buf size=%d\n", head, tail,
		       bufSize);
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
		free(acnBuf);

	return 0;
}

#endif

int
mwl_drv_set_newdpOffch(struct net_device *netdev,
		       DOT11_OFFCHAN_REQ_t * pOffchan)
{
	return wlFwNewDP_queue_OffChan_req(netdev, pOffchan);
}

int
mwl_drv_set_txContinuous(struct net_device *netdev, uint8_t mode,
			 uint32_t rateinfo)
{
	return wlFwSetTxContinuous(netdev, mode, rateinfo);
}

int
mwl_drv_set_rxSop(struct net_device *netdev, uint8_t params, uint8_t threshold1,
		  uint8_t threshold2)
{
	return wlFwNewDP_RxSOP(netdev, params, threshold1, threshold2);
}

int
mwl_drv_set_pwrPerRate(struct net_device *netdev, struct file *filp, char *path)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	struct wlprivate_data *wlpd_p = priv->wlpd_p;
	char buff[500], *s;
	int len, index = 0, i, j = 0, k = 0;
	char (*param)[66] = kmalloc(sizeof(*param) * 65, GFP_KERNEL);

	memset(buff, 0, 500);

	// if (filp != NULL) // Note: this one doesn't work and will cause crash
	if (!IS_ERR(filp))	// MUST use this one, important!!!
	{
		printk("loadpwrperrate open <%s>: OK\n", path);

		/* reset the whole table */
		for (i = 0; i < IEEE_80211_MAX_NUMBER_OF_CHANNELS; i++)
			memset(&wlpd_p->AllChanGrpsPwrTbl.PerChanGrpsPwrTbl[i],
			       0, sizeof(PerChanGrpsPwr_t));

		while (1) {
			s = buff;
			while ((len =
				vfs_read(filp, s, 0x01, &filp->f_pos)) == 1) {
				if (*s == '\n') {
					/* skip blank line */
					if (s == buff) {
						break;
					}
					/* parse this line and assign value to data structure */
					*s = '\0';
					//printk("index=<%d>: <%s>\n", index, buff);
					sscanf(buff,
					       "%s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s\n",
					       param[0], param[1], param[2],
					       param[3], param[4], param[5],
					       param[6], param[7], param[8],
					       param[9], param[10], param[11],
					       param[12], param[13], param[14],
					       param[15], param[16], param[17],
					       param[18], param[19], param[20],
					       param[21], param[22], param[23],
					       param[24], param[25], param[26],
					       param[27], param[28], param[29],
					       param[30], param[31], param[32],
					       param[33], param[34], param[35],
					       param[36], param[37], param[38],
					       param[39], param[40], param[41],
					       param[42], param[43], param[44],
					       param[45], param[46], param[47],
					       param[48], param[49],
					       param[MAX_GROUP_PER_CHANNEL]);

					wlpd_p->AllChanGrpsPwrTbl.
						PerChanGrpsPwrTbl[j].channel =
						atoi(param[0]);
					k++;
					//printk("channel =%d \n",wlpd_p->AllChanGrpsPwrTbl.PerChanGrpsPwrTbl[j].channel);
					for (i = 1;
					     i < (MAX_GROUP_PER_CHANNEL + 1);
					     i++) {
						s8 pwr;

						pwr = atoi_2(param[i]);

						if (pwr == -1) {
							wlpd_p->AllChanGrpsPwrTbl.PerChanGrpsPwrTbl[j].NumOfGrpPerChan = i - 1;
							//printk("NumOfGrpPerChan =%d \n", wlpd_p->AllChanGrpsPwrTbl.PerChanGrpsPwrTbl[j].NumOfGrpPerChan);
							break;
						}
						wlpd_p->AllChanGrpsPwrTbl.
							PerChanGrpsPwrTbl[j].
							GrpsPwr[i - 1] = pwr;
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
#if 0
		for (i = 0; i < wlpd_p->AllChanGrpsPwrTbl.NumOfChan; i++) {
			UINT8 channel;

			channel =
				wlpd_p->AllChanGrpsPwrTbl.PerChanGrpsPwrTbl[i].
				channel;
			if (channel >= 1 && channel <= 14) {
				if (wlpd_p->AllChanGrpsPwrTbl.
				    PerChanGrpsPwrTbl[i].NumOfGrpPerChan !=
				    NUM_GRPS_2G) {
					printk(" 2.4G group number does not match \n");
					return;
				}

			} else if (channel >= 36 || channel <= 165) {
				if (wlpd_p->AllChanGrpsPwrTbl.
				    PerChanGrpsPwrTbl[i].NumOfGrpPerChan !=
				    NUM_GRPS_5G) {
					printk(" 5G group number does not match\n");
					return;
				}
			}

		}
#endif
		filp_close(filp, current->files);
	} else
		printk("loadpwrperrate open <%s>: FAIL\n", path);

	free(param);

	return 0;
}

int
mwl_drv_set_rateGrps(struct net_device *netdev, struct file *filp, char *path)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	struct wlprivate_data *wlpd_p = priv->wlpd_p;
	char buff[500], *s;
	int len, i, GrpId, NumOfEntry;
	char (*param)[66] = kmalloc(sizeof(*param) * 65, GFP_KERNEL);

	memset(buff, 0, 500);

	// if (filp != NULL) // Note: this one doesn't work and will cause crash
	if (!IS_ERR(filp))	// MUST use this one, important!!!
	{
		printk("loadrategrps open <%s>: OK\n", path);
		memset(wlpd_p->RateGrpDefault, 0,
		       sizeof(RateGrp_t) * MAX_GROUP_PER_CHANNEL);
		while (1) {
			s = buff;
			while ((len =
				vfs_read(filp, s, 0x01, &filp->f_pos)) == 1) {
				if (*s == '\n') {
					/* skip blank line */
					if (s == buff) {
						break;
					}
					/* parse this line and assign value to data structure */
					*s = '\0';
					//3(grp # + NumOfEntry+Ant) + MAX_RATES_PER_GROUP=43
					sscanf(buff,
					       "%s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s\n",
					       param[0], param[1], param[2],
					       param[3], param[4], param[5],
					       param[6], param[7], param[8],
					       param[9], param[10], param[11],
					       param[12], param[13], param[14],
					       param[15], param[16], param[17],
					       param[18], param[19], param[20],
					       param[21], param[22], param[23],
					       param[24], param[25], param[26],
					       param[27], param[28], param[29],
					       param[30], param[31], param[32],
					       param[33], param[34], param[35],
					       param[36], param[37], param[38],
					       param[39], param[40], param[41],
					       param[42]);
					GrpId = atohex2(param[0]);
					NumOfEntry = atohex2(param[1]);
					if (NumOfEntry != 0) {
						printk("GrpId=<%d>: <%s>\n",
						       GrpId, buff);
						wlpd_p->RateGrpDefault[GrpId].
							NumOfEntry = NumOfEntry;
						wlpd_p->RateGrpDefault[GrpId].
							AxAnt =
							atohex2(param[2]);
						for (i = 0; i < NumOfEntry; i++) {
							wlpd_p->RateGrpDefault
								[GrpId].
								Rate[i] =
								atohex2(param
									[i +
									 3]);
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
		printk("RateGrps.conf open <%s>: FAIL\n", path);

	free(param);

	return 0;
}

int
mwl_drv_set_pwrGrpsTbl(struct net_device *netdev, struct file *filp, char *path)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	struct wlprivate_data *wlpd_p = priv->wlpd_p;
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	char buff[500], *s;
	int len, i, value = 0, GrpId, NumOfEntry;
	int index = 0, j = 0, k = 0;
	BOOLEAN bStartTxPwrTbl = FALSE;
	BOOLEAN bStartRateGrpsConf = FALSE;
	BOOLEAN bStartPwrPerRateGrps = FALSE;
	char *TxPwrTbl = "[TX_PWR_TBL]";
	char *RateGrpsConf = "[RATE_GRPS_CONF]";
	char *PwrPerRateGrps = "[PWR_PER_RATE_GRPS]";
	char (*param)[66] = kmalloc(sizeof(*param) * 65, GFP_KERNEL);

	memset(buff, 0, 500);
	// if (filp != NULL) // Note: this one doesn't work and will cause crash
	if (!IS_ERR(filp))	// MUST use this one, important!!!
	{
		printk("loadpwrgrpstbl open <%s>: OK\n", path);
		memset(wlpd_p->RateGrpDefault, 0,
		       sizeof(RateGrp_t) * MAX_GROUP_PER_CHANNEL);
		for (i = 0; i < IEEE_80211_MAX_NUMBER_OF_CHANNELS; i++)
			memset(mib->PhyTXPowerTable[i], 0,
			       sizeof(MIB_TX_POWER_TABLE));
		while (1) {
			s = buff;
			while ((len =
				vfs_read(filp, s, 0x01, &filp->f_pos)) == 1) {
				if (*s == '\n') {
					/* skip blank line */
					if (s == buff) {
						break;
					}
					/* parse this line and assign value to data structure */
					*s = '\0';
					sscanf(buff, "%s", param[0]);
					if (strncmp(param[0], TxPwrTbl, 12) ==
					    0) {
						bStartTxPwrTbl = TRUE;
						bStartRateGrpsConf = FALSE;
						bStartPwrPerRateGrps = FALSE;
						break;
					}
					sscanf(buff, "%s", param[0]);
					if (strncmp(param[0], RateGrpsConf, 16)
					    == 0) {
						bStartTxPwrTbl = FALSE;
						bStartRateGrpsConf = TRUE;
						bStartPwrPerRateGrps = FALSE;
						break;
					}
					if (strncmp
					    (param[0], PwrPerRateGrps,
					     19) == 0) {
						bStartTxPwrTbl = FALSE;
						bStartRateGrpsConf = FALSE;
						bStartPwrPerRateGrps = TRUE;
						break;
					}
					if (bStartTxPwrTbl || bStartRateGrpsConf
					    || bStartPwrPerRateGrps) {
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
					printk("index=<%d>: <%s>\n", index,
					       buff);
#if defined(SOC_W8964)
					/* 8964 total param: ch + setcap + 32 txpower + CDD + tx2 = 36 */
					sscanf(buff,
					       "%s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s\n",
					       param[0], param[1], param[2],
					       param[3], param[4], param[5],
					       param[6], param[7], param[8],
					       param[9], param[10], param[11],
					       param[12], param[13], param[14],
					       param[15], param[16], param[17],
					       param[18], param[19], param[20],
					       param[21], param[22], param[23],
					       param[24], param[25], param[26],
					       param[27], param[28], param[29],
					       param[30], param[31], param[32],
					       param[33], param[34], param[35]);

					if (strcmp(param[34], "on") == 0)
						value = 0x13;
					else if (strcmp(param[34], "off") == 0)
						value = 0;

#elif defined(SOC_W8864)
					/* 8864 total param: ch + setcap + 16 txpower + CDD + tx2 = 20 */
					sscanf(buff,
					       "%s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s\n",
					       param[0], param[1], param[2],
					       param[3], param[4], param[5]
					       , param[6], param[7], param[8],
					       param[9], param[10], param[11],
					       param[12], param[13], param[14],
					       param[15], param[16], param[17]
					       , param[18], param[19]);

					if (strcmp(param[18], "on") == 0)
						value = 1;
					else if (strcmp(param[18], "off") == 0)
						value = 0;
#else
					/* total param: ch + setcap + 12 txpower + CDD + tx2 = 16 */
					sscanf(buff,
					       "%s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s\n",
					       param[0], param[1], param[2],
					       param[3], param[4], param[5]
					       , param[6], param[7], param[8],
					       param[9], param[10], param[11],
					       param[12], param[13], param[14],
					       param[15]);

					if (strcmp(param[14], "on") == 0)
						value = 1;
					else if (strcmp(param[14], "off") == 0)
						value = 0;
#endif
					else {
						printk("txpower table format error: CCD should be on|off\n");
						break;
					}
					mib->PhyTXPowerTable[index]->CDD =
						value;

#if defined(SOC_W8964)
					mib->PhyTXPowerTable[index]->
						txantenna2 = atohex2(param[35]);
#elif defined (SOC_W8864)
					mib->PhyTXPowerTable[index]->
						txantenna2 = atohex2(param[19]);
#else
					mib->PhyTXPowerTable[index]->
						txantenna2 = atohex2(param[15]);
#endif

					mib->PhyTXPowerTable[index]->Channel =
						atoi(param[0]);
					mib->PhyTXPowerTable[index]->setcap =
						atoi(param[1]);

					for (i = 0; i < TX_POWER_LEVEL_TOTAL;
					     i++) {

#ifdef SOC_W8964
						s16 pwr;

						pwr = (s16)
							atoi_2(param[i + 2]);
						mib->PhyTXPowerTable[index]->
							TxPower[i] = pwr;
#else
						mib->PhyTXPowerTable[index]->
							TxPower[i] =
							atohex2(param[i + 2]);
#endif
					}

					index++;
					break;
RateGrpsConf:
					memset(param[0], 0, sizeof(*param));
					memset(param[1], 0, sizeof(*param));
					sscanf(buff,
					       "%s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s\n",
					       param[0], param[1], param[2],
					       param[3], param[4], param[5],
					       param[6], param[7], param[8],
					       param[9], param[10], param[11],
					       param[12], param[13], param[14],
					       param[15], param[16], param[17],
					       param[18], param[19], param[20],
					       param[21], param[22], param[23],
					       param[24], param[25], param[26],
					       param[27], param[28], param[29],
					       param[30], param[31], param[32],
					       param[33], param[34], param[35],
					       param[36], param[37], param[38],
					       param[39], param[40], param[41],
					       param[42]);
					GrpId = atohex2(param[0]);
					NumOfEntry = atohex2(param[1]);
					if (NumOfEntry != 0) {
						//printk("GrpId=<%d>: <%s>\n", GrpId, buff);
						wlpd_p->RateGrpDefault[GrpId].
							NumOfEntry = NumOfEntry;
						wlpd_p->RateGrpDefault[GrpId].
							AxAnt =
							atohex2(param[2]);
						for (i = 0; i < NumOfEntry; i++) {
							wlpd_p->RateGrpDefault
								[GrpId].
								Rate[i] =
								atohex2(param
									[i +
									 3]);
							//printk("Rate= 0x%X \n", wlpd_p->RateGrpDefault[GrpId].Rate[i]);
						}
					}
					break;
PwrPerRateGrps:
					//printk("index=<%d>: <%s>\n", index, buff);
					sscanf(buff,
					       "%s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s\n",
					       param[0], param[1], param[2],
					       param[3], param[4], param[5],
					       param[6], param[7], param[8],
					       param[9], param[10], param[11],
					       param[12], param[13], param[14],
					       param[15], param[16], param[17],
					       param[18], param[19], param[20],
					       param[21], param[22], param[23],
					       param[24], param[25], param[26],
					       param[27], param[28], param[29],
					       param[30], param[31], param[32],
					       param[33], param[34], param[35],
					       param[36], param[37], param[38],
					       param[39], param[40], param[41],
					       param[42], param[43], param[44],
					       param[45], param[46], param[47],
					       param[48], param[49],
					       param[MAX_GROUP_PER_CHANNEL]);

					wlpd_p->AllChanGrpsPwrTbl.
						PerChanGrpsPwrTbl[j].channel =
						atoi(param[0]);
					k++;
					//printk("channel =%d \n",wlpd_p->AllChanGrpsPwrTbl.PerChanGrpsPwrTbl[j].channel);
					for (i = 1;
					     i < (MAX_GROUP_PER_CHANNEL + 1);
					     i++) {
						s8 pwr;

						pwr = atoi_2(param[i]);

						if (pwr == -1) {
							wlpd_p->AllChanGrpsPwrTbl.PerChanGrpsPwrTbl[j].NumOfGrpPerChan = i - 1;
							//printk("NumOfGrpPerChan =%d \n", wlpd_p->AllChanGrpsPwrTbl.PerChanGrpsPwrTbl[j].NumOfGrpPerChan);
							break;
						}
						wlpd_p->AllChanGrpsPwrTbl.
							PerChanGrpsPwrTbl[j].
							GrpsPwr[i - 1] = pwr;
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
		printk("loadpwrgrpstbl open <%s>: FAIL\n", param[1]);

	return 0;
}

int
mwl_drv_set_perRatePwr(struct net_device *netdev)
{
	printk("mwl_drv_set_perRatePwr\n");
	return wlFwSetPowerPerRate(netdev);
}

int
mwl_drv_get_perRatePwr(struct net_device *netdev, uint32_t RatePower,
		       uint8_t * trpcid, uint16_t * dBm, uint16_t * ant)
{
	return wlFwGetPowerPerRate(netdev, RatePower, trpcid, dBm, ant);
}

int
mwl_drv_get_nf(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
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
		printk(" nf_a: -%d nf_b: -%d nf_c: -%d nf_d: -%d \n ",
		       a, b, c, d);
	}

	return 0;
}

int
mwl_drv_get_radioStatus(struct net_device *netdev)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	radio_status_t *pRadioStatus;

	pRadioStatus =
		(radio_status_t *) & ((drv_fw_shared_t *) priv->wlpd_p->
				      MrvlPriSharedMem.data)->RadioStatus;

	printk("dead =%d, dumping =%d, enabled =%d, SI_init =%d, DFS_required =%d,TimeSinceEnabled =%d \n", pRadioStatus->dead, pRadioStatus->dumping, pRadioStatus->enabled, pRadioStatus->SI_init, pRadioStatus->DFS_required, pRadioStatus->TimeSinceEnabled);

	return 0;
}

int
mwl_drv_set_ldpc(struct net_device *netdev, uint8_t enable)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);

	priv->wlpd_p->ldpcdisable = 1 - enable;

	printk("ldpc =%d \n", enable);

	return 0;
}

extern int wlFwGetTLVSet(struct net_device *netdev, UINT8 act, UINT16 type,
			 UINT16 len, UINT8 * tlvData, char *string_buff);
int
mwl_drv_set_tlv(struct net_device *netdev, uint8_t act, uint16_t type,
		uint16_t len, uint8_t * tlvData, char *buff)
{
	return wlFwGetTLVSet(netdev, 1, type, len, tlvData, buff);
}

int
mwl_drv_set_ampduCfg(struct net_device *netdev, uint8_t cfg)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	u32 entries, i;
	UCHAR *sta_buf, *show_buf;
	extStaDb_StaInfo_t *pStaInfo;

	entries = extStaDb_entries(vmacSta_p, 0);
	if (entries == 0) {
		printk(" zero station list\n");
		return -ENODEV;
	}
	sta_buf = kmalloc(entries * 64, GFP_KERNEL);
	if (sta_buf == NULL) {
		printk("kmalloc fail \n");
		return -ENOMEM;

	}
	extStaDb_list(vmacSta_p, sta_buf, 1);
	show_buf = sta_buf;
	for (i = 0; i < entries; i++) {
		if ((pStaInfo =
		     extStaDb_GetStaInfo(vmacSta_p,
					 (IEEEtypes_MacAddr_t *) show_buf,
					 0)) == NULL) {
			kfree(sta_buf);
			printk("error: NO station info found \n");
			return -ENODEV;
		}
		pStaInfo->aggr11n.ampducfg = cfg;
		show_buf += sizeof(STA_INFO);
	}
	kfree(sta_buf);
	return 0;
}

int
mwl_drv_set_amsduCfg(struct net_device *netdev, amsducfg_t * amsducfg)
{
	return wlFwNewDP_amsducfg(netdev, amsducfg);
}

int
mwl_drv_set_bbDbg(struct net_device *netdev, UINT8 hasId, UINT32 client_id)
{
#ifdef SOC_W8964
	int i, j;
	UINT32 val;
	char out[24 * 4 + 22];

	printk("\nQ_dump...\n");

	if (hasId) {
		printk("client_id = %d\n", client_id);
		val = 0x03;
		wlRegBB(netdev, WL_SET, 0x857, &val);
		val = 0x4c;
		wlRegBB(netdev, WL_SET, 0x37c, &val);
		val = 0x03;
		wlRegBB(netdev, WL_SET, 0x641, &val);
		val = 0x03;
		wlRegBB(netdev, WL_SET, 0x859, &val);
		val = client_id;
		wlRegBB(netdev, WL_SET, 0x642, &val);
	}

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
			sprintf(&out[20 + (23 - j) * 3], " %2x", val);
			//printk(" %x", val);
		}
		printk("%s \n", out);
	}
	/* disabe test mode */
	val = 0x00;
	wlRegBB(netdev, WL_SET, 0x641, &val);
#endif
	return 0;
}

int
mwl_drv_set_mu_sm_cache(struct net_device *netdev, UINT8 hasId,
			UINT32 client_id)
{
	// BBP MU SM cache
#ifdef SOC_W8964
	int i, j;
	UINT32 val;
	char out[32 * 4 + 22];

	printk("\nmu sm cache dump...\n");
	val = 0x03;
	wlRegBB(netdev, WL_SET, 0x857, (UINT32 *) & val);
	val = 0x4c;
	wlRegBB(netdev, WL_SET, 0x37c, (UINT32 *) & val);
	//Enable True ID (0x641[1])
	val = 0x2;
	wlRegBB(netdev, WL_SET, 0x641, (UINT32 *) & val);
	if (hasId) {
		val = client_id;
	} else {
		val = 0x1;
	}
	wlRegBB(netdev, WL_SET, 0x642, (UINT32 *) & val);
	// Readback
	wlRegBB(netdev, WL_GET, 0x642, &val);
	printk("\nClient ID is: %x\n", val);
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
			sprintf(&out[20 + (15 - j) * 3], " %2x", val);
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
			sprintf(&out[20 + (31 - j) * 3], " %2x", val);
		}
		printk("%s \n", out);
	}
	/* disabe test mode */
	val = 0x00;
	wlRegBB(netdev, WL_SET, 0x641, (UINT32 *) & val);
#endif

	return 0;
}

int
mwl_drv_set_sku(struct net_device *netdev, UINT32 sku)
{
	return wlFwNewDP_set_sku(netdev, sku);
}

int
mwl_drv_set_rxAntBitmap(struct net_device *netdev, uint8_t hasBitmap,
			UINT32 bitmap)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	if (hasBitmap) {
		printk("bitmap: %x\n", bitmap);

		if (bitmap < 0 || bitmap > 0xf) {
			return -EOPNOTSUPP;
		}
		*(mib->mib_rxAntBitmap) = (UCHAR) (bitmap & 0xf);
		*(mib->mib_rxAntenna) = countNumOnes((bitmap & 0xf));
	} else {
		printk("rxantbitmap: %x\n", *(mib->mib_rxAntBitmap));
	}

	return 0;
}

int
mwl_drv_set_retryCfgEnable(struct net_device *netdev, UINT8 Enable)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);

	printk("Set %s retrycfgenable= %x\n", netdev->name, Enable);
	priv->retrycfgenable = Enable;

	return 0;
}

int
mwl_drv_set_retryCfg(struct net_device *netdev, char *mode, char *param)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	UINT8 i;
	//                                        BK BE VI VO
	//iwpriv wdev0ap0 setcmd "retrycfg legacy 32 32 64 32"
	//iwpriv wdev0ap0 setcmd "retrycfg 11n 32 32 64 32"
	//iwpriv wdev0ap0 setcmd "retrycfg 11ac 32 32 64 32"
	//
	//printk(" vap name %s \n", netdev->name);
	if ((strcmp(mode, "legacy") == 0)) {
		for (i = 0; i < 4; i++) {
			priv->retrycfgVAP.RetryLegacy[i] = param[i];
			printk(" legacy retry cnt %d \n",
			       priv->retrycfgVAP.RetryLegacy[i]);
		}
	} else if ((strcmp(mode, "11n") == 0)) {
		for (i = 0; i < 4; i++) {
			priv->retrycfgVAP.Retry11n[i] = param[i];
			printk(" 11n retry cnt %d \n",
			       priv->retrycfgVAP.Retry11n[i]);
		}

	} else if ((strcmp(mode, "11ac") == 0)) {
		for (i = 0; i < 4; i++) {
			priv->retrycfgVAP.Retry11ac[i] = param[i];
			printk(" 11ac retry cnt %d \n",
			       priv->retrycfgVAP.Retry11ac[i]);
		}
	}

	return 0;
}

int
mwl_drv_set_radioRatesCfg(struct net_device *netdev, char *mode, UINT8 * param)
{
	struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

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
	if ((strcmp(mode, "HT") == 0)) {
		mib_StaCfg->SupportedTxHtMCScfg.SupportedTxHtMCSset_0 =
			param[0];
		mib_StaCfg->SupportedTxHtMCScfg.SupportedTxHtMCSset_1 =
			param[1];
		mib_StaCfg->SupportedTxHtMCScfg.SupportedTxHtMCSset_2 =
			param[2];

		printk("HT radio rates 0 0x%X \n",
		       mib_StaCfg->SupportedTxHtMCScfg.SupportedTxHtMCSset_0);
		printk("HT radio rates 1 0x%X \n",
		       mib_StaCfg->SupportedTxHtMCScfg.SupportedTxHtMCSset_1);
		printk("HT radio rates 2 0x%X \n",
		       mib_StaCfg->SupportedTxHtMCScfg.SupportedTxHtMCSset_2);
	} else if ((strcmp(mode, "VHT") == 0)) {
		mib_StaCfg->SupportedTxVhtMcsSet = *((uint16 *) param);
		printk("VHT radio rates 0x%X \n",
		       mib_StaCfg->SupportedTxVhtMcsSet);

	} else {
		printk("unknown mode \n");
	}

	return 0;
}

int
mwl_drv_set_eewr(struct net_device *netdev, uint32_t offset,
		 uint32_t NumOfEntry, char *path)
{
	struct file *filp = NULL;
	mm_segment_t oldfs;
	UINT32 len = 0, i = 0;
	char *data = NULL;
	//eewr offset len eeprom.conf
	//ex: iwpriv wdev0 setcmd "eewr 0x1234  0x20 /demo/eeprom_out.conf"
	oldfs = get_fs();
	set_fs(KERNEL_DS);
	filp = filp_open(path, O_RDONLY, 0);
	data = (char *)malloc(NumOfEntry);

	if (!IS_ERR(filp)) {
		for (i = 0; i < NumOfEntry; i++) {
			len = vfs_read(filp, &data[i], 0x01, &filp->f_pos);
			if (len == 0) {
				//printk("vfs_read fail  \n");
				return -ENODATA;
			}

		}
		eepromAction(netdev, offset, data, NumOfEntry, 1);	//write
		if (data != NULL)
			free(data);
		filp_close(filp, current->files);
		set_fs(oldfs);
	} else {
		printk("open <%s>: FAIL\n", path);
		return -EINVAL;
	}

	return 0;
}

int
mwl_drv_get_eerd(struct net_device *netdev, uint32_t offset,
		 uint32_t NumOfEntry, char *path)
{
	struct file *filp_eeprom = NULL;
	mm_segment_t oldfs;
	char *data = NULL;

	//eerd offset len eeprom_out.conf
	//ex: iwpriv wdev0 setcmd "eerd 0x1234 0x100 /demo/eeprom_out.conf"

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	filp_eeprom = filp_open(path, O_RDWR | O_CREAT | O_TRUNC, 0);
	if (!IS_ERR(filp_eeprom)) {
		data = (char *)malloc(NumOfEntry);
		eepromAction(netdev, offset, data, NumOfEntry, 0);	//read
		vfs_write(filp_eeprom, data, NumOfEntry, &filp_eeprom->f_pos);
		filp_close(filp_eeprom, current->files);
	} else {
		printk(".conf open <%s>: FAIL\n", path);
		return -EINVAL;
	}
	set_fs(oldfs);
	if (data != NULL)
		free(data);
	return 0;
}

int
mwl_drv_set_eepromAccess(struct net_device *netdev)
{
	//struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	//vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	//MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return 0;
}

int
mwl_drv_set_offChPwr(struct net_device *netdev)
{
	//struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	//vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	//MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return 0;
}

int
mwl_drv_set_wdevReset(struct net_device *netdev)
{
	//struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	//vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	//MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return 0;
}

int
mwl_drv_set_npda_useta(struct net_device *netdev)
{
	//struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	//vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	//MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return 0;
}

int
mwl_drv_set_sendBcnReport(struct net_device *netdev)
{
	//struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	//vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	//MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return 0;
}

int
mwl_drv_get_nList(struct net_device *netdev)
{
	//struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	//vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	//MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return 0;
}

int
mwl_drv_get_nListCfg(struct net_device *netdev)
{
	//struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	//vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	//MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return 0;
}

int
mwl_drv_set_sendNlistRep(struct net_device *netdev)
{
	//struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	//vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	//MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return 0;
}

int
mwl_drv_set_enableScnr(struct net_device *netdev)
{
	//struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	//vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	//MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return 0;
}

int
mwl_drv_set_dfsSetChanSw(struct net_device *netdev)
{
	//struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	//vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	//MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return 0;
}

int
mwl_drv_set_radar_event(struct net_device *netdev)
{
	//struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	//vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	//MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return 0;
}

int
mwl_drv_set_qosCtrl1(struct net_device *netdev)
{
	//struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	//vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	//MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return 0;
}

int
mwl_drv_set_qosCtrl2(struct net_device *netdev)
{
	//struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	//vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	//MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return 0;
}

int
mwl_drv_get_qosCtrl(struct net_device *netdev)
{
	//struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	//vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	//MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return 0;
}

int
mwl_drv_set_mu_bfmer(struct net_device *netdev)
{
	//struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	//vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	//MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return 0;
}

int
mwl_drv_set_fipsTest(struct net_device *netdev)
{
	//struct wlprivate *priv = mwl_netdev_get_priv(netdev);
	//vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	//MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;

	return 0;
}
