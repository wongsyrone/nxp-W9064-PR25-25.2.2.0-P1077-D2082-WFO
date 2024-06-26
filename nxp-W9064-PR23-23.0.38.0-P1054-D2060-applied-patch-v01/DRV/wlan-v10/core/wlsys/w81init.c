/** @file w81init.c
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

#include "ap8xLnxIntf.h"
#include "ap8xLnxDesc.h"
#include "buildModes.h"
#include "wltypes.h"
#include "IEEE_types.h"
#include "mib.h"
#include "wl_macros.h"
#include "ds.h"
#include "keyMgmtCommon.h"
#include "keyMgmt.h"
#include "timer.h"
#include "tkip.h"
#include "StaDb.h"
#include "macmgmtap.h"
#include "macMgmtMlme.h"
#include "wldebug.h"
#include "wl_hal.h"

extern void SetupAdaptRow(void);
extern vmacApInfo_t *wlCreateSysCfg(struct wlprivate *wlp, UINT32 opMode,
				    MFG_CAL_DATA * calData, char *addr, int,
				    int vMacId);
extern void ampdu_Init(struct net_device *dev);
extern void wds_Init(struct net_device *netdev);
#ifdef STA_QOS
void InitStaQosParam();
#endif

#ifdef SOC_W906X
muedca_entry_t mib_QAP_MUEDCA_Table_def[4] = {
	{0, 0, 0, 0, 15, 15, 255},	//BE
	{0, 0, 1, 0, 15, 15, 255},	//BK
	{0, 0, 2, 0, 15, 15, 255},	//VI
	{0, 0, 3, 0, 15, 15, 255}	//VO
};

#endif

UINT8
system_Init(vmacApInfo_t * sSysCfg_p, char *addr)
{

	sSysCfg_p->txPwrTblLoaded = 0;
	sSysCfg_p->regionCodeLoaded = 0;

	/* updated this from 300 to 1024 to achieve lower/zero loss higher UDP traffics
	   Further tuning increases to 2304 needed for lower PHY rate */
	sSysCfg_p->txQLimit = 2304;

	sSysCfg_p->work_to_do = MAX_NUM_RX_DESC;
#ifdef SOC_W906X
	sSysCfg_p->ampduWindowSizeCap = 0xffff;
	sSysCfg_p->ampduDensityCap = 0;
	sSysCfg_p->ampduBytesCap = (1 << 20) - 4;
#endif
#ifdef CONFIG_IEEE80211W
	sSysCfg_p->assoc_sa_query_max_timeout = 1000;
	sSysCfg_p->assoc_sa_query_retry_timeout = 201;
#endif /* CONFIG_IEEE80211W */
	return (OS_SUCCESS);
}

/******************************************************************************
 *
 * Name: Ap_Init
 *
 * Description:
 *   This routine is to initialize AP
 *
 * Conditions For Use:
 *   None.
 *
 * Arguments:
 *
 *
 * Return Value:
 *   None
 *
 * Notes:
 *   None.
 *
 * PDL:
 *
 * END PDL
 *
 ****************************************************************************/

vmacApInfo_t *
Mac_Init(struct wlprivate * wlp, struct net_device * dev, char *addr,
	 UINT32 mode, int phyMacId)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
	vmacApInfo_t *vmacSta_p = NULL;

	WLDBG_INFO(DBG_LEVEL_3, " Mac_Init: wireless AP Initialization. \n");
	vmacSta_p =
		wlCreateSysCfg(wlpptr, mode, NULL, addr, phyMacId,
			       wlp ? wlp->wlpd_p->vmacIndex : 0);
	if (vmacSta_p == NULL)
		return NULL;
	vmacSta_p->dev = dev;
	if (wlp) {
		vmacSta_p->master = wlp->vmacSta_p;
		vmacSta_p->VMacEntry.macId = wlp->wlpd_p->vmacIndex;
#ifdef SOC_W906X
		if ((wlp->wlpd_p->vmacIndex == wlp->wlpd_p->NumOfAPs) &&
		    (mode == WL_OP_MODE_VSTA)) {
			vmacSta_p->VMacEntry.macId = wlp->wlpd_p->NumOfAPs - 1;
			printk("**Overwrite Clinet macid:%u\n",
			       vmacSta_p->VMacEntry.macId);
		}

		vmacSta_p->VMacEntry.muedcaEnable = 0;
		vmacSta_p->VMacEntry.edca_param_set_update_cnt = 0;
		memcpy((void *)vmacSta_p->VMacEntry.mib_QAP_MUEDCA_Table,
		       (void *)mib_QAP_MUEDCA_Table_def,
		       sizeof(vmacSta_p->VMacEntry.mib_QAP_MUEDCA_Table));
#endif
	} else {
		vmacSta_p->master = NULL;
		vmacSta_p->VMacEntry.macId = 0;
	}
	vmacSta_p->VMacEntry.phyHwMacIndx = phyMacId;
	wlpptr->vmacSta_p = vmacSta_p;
	system_Init(vmacSta_p, addr);
	if (mode == WL_OP_MODE_AP) {
		extStaDb_Init(vmacSta_p, sta_num);
		ampdu_Init(dev);
	}

	ethStaDb_Init(vmacSta_p, sta_num);
	macMgmtAp_Init(vmacSta_p, MAX_AID, (IEEEtypes_MacAddr_t *) addr);
	if (mode == WL_OP_MODE_AP)
		smeMain_Init(vmacSta_p);

#ifdef MRVL_WSC
	memset(&vmacSta_p->thisbeaconIEs, 0, sizeof(WSC_BeaconIEs_t));
	memset(&vmacSta_p->thisprobeRespIEs, 0, sizeof(WSC_ProbeRespIEs_t));
	vmacSta_p->WPSOn = 0;
#endif
#ifdef MRVL_WAPI
	memset(&vmacSta_p->thisbeaconIEsWAPI, 0, sizeof(WAPI_BeaconIEs_t));
	memset(&vmacSta_p->thisprobeRespIEsWAPI, 0,
	       sizeof(WAPI_ProbeRespIEs_t));
#endif
#ifdef MRVL_DFS
	if (wlp)
		wlpptr->wlpd_p->pdfsApMain = NULL;
	vmacSta_p->dfsCacExp = 0;
#endif
#ifdef WTP_SUPPORT
	vmacSta_p->wtp_info.extHtIE = false;
	vmacSta_p->wtp_info.extVhtIE = false;
	vmacSta_p->wtp_info.extPropIE = false;
#endif

	return vmacSta_p;
}
