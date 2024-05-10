/** @file msan_report.c
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2017-2020 NXP
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

/*!
 * \file    msan_report.c
 * \brief   neighbor report management
 */

/*=============================================================================
 *                               INCLUDE FILES
 *=============================================================================
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/wireless.h>
#include <linux/pci.h>
#include <linux/delay.h>
#include <linux/string.h>

#include "wl.h"
#include "wldebug.h"
#include "ap8xLnxApi.h"
#include "IEEE_types.h"
#include "wl_mib.h"
#include "macMgmtMlme.h"
#include "domain.h"
#include "ap8xLnxFwcmd.h"
#include "cfg80211.h"
#include "vendor.h"

#ifdef CLIENT_SUPPORT
#include "linkmgt.h"
#include "mlme.h"
#include "mlmeApi.h"
#endif

#include "ap8xLnxXmit.h"

#ifdef IEEE80211K
#include "msan_report.h"
#endif //IEEE80211K

#ifdef IEEE80211K
/*=============================================================================
 *                                DEFINITIONS
 *=============================================================================
*/
#define NBREPORT_LIST_LIFESPAN              (10*60)	//10 mins
#define RRM_UC_CHECK_INTERVEL               (500 * TIMER_1MS)
#define RRM_UC_CHECK_TIME                   (500 )

#define ACS_INTERVAL_MAX_TIME               (60000)	// 60 * 1000 ms

#ifdef OFFCHANNEL_SUPPORT
static UINT32 L_offchan_id = 0;
#endif /* OFFCHANNEL_SUPPORT  */
static UINT8 InScanFlag = 0;

#define UNASSOCSTA_CURRCHAN_TRACK_INTERVEL (200 * TIMER_1MS)
#define UNASSOCSTA_OFFCHAN_TRACK_INTERVEL (80 * TIMER_1MS)

/*=============================================================================
 *                         IMPORTED PUBLIC VARIABLES
 *=============================================================================
 */

/*=============================================================================
 *                         IMPORTED PUBLIC FUNCTIONS
 *=============================================================================
 */
extern BOOLEAN isMcIdIE(UINT8 * data_p);
extern UINT8 getRegulatoryClass(vmacApInfo_t * vmacSta_p);
extern void *syncSrv_ParseAttrib(macmgmtQ_MgmtMsg_t * mgtFrame_p, UINT8 attrib,
				 UINT16 len);

/*=============================================================================
 *                          MODULE LEVEL VARIABLES
 *=============================================================================
 */
neighbor_list_entrie_t nlist_entry[NB_LIST_MAX_NUM];
int nlist_number = 0;

/* real neighbor report element list */
IEEEtypes_Neighbor_Report_Element_t nb_elem_list[NB_LIST_MAX_NUM];
UINT8 nb_list_num = 0;

static UINT32 nbr_offchan_channel = 0;

static u8 unassocsta_offchan_channel_number = 0;
static u8 unassocsta_offchan_channel_list[UNASSOC_METRICS_CHANNEL_MAX];
static UINT32 unassocsta_offchan_channel = 0;
static UINT32 unassocsta_offchan_id = 0;

/*=============================================================================
 *                   PRIVATE PROCEDURES (ANSI Prototypes)
 *=============================================================================
 */
static void neighbor_report_scan_cb(UINT8 * data);

/*=============================================================================
*                         CODED PROCEDURES
 *=============================================================================
 */

/*
 *Function Name:
 *
 *Parameters:
 *
 *Description:
 *
 *Returns:
 *
 */

static UINT32
neighbor_report_find_cand(void)
{
	UINT32 i, index = 0;

	if (nlist_number == 0) {
		return 0;
	}
	for (i = 0; i < nlist_number && i < NB_LIST_MAX_NUM; i++) {
		/* find the oldest timestamp AP. */
		if ((nlist_entry[i].time_stamp < nlist_entry[index].time_stamp)
		    &&
		    ((nlist_entry[index].time_stamp -
		      nlist_entry[i].time_stamp) < NBREPORT_LIST_LIFESPAN)) {
			index = i;
		}
	}
	return index;
}

static void
neighbor_report_delete(struct net_device *netdev, UINT8 index)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	UINT8 i;

	if (index >= NB_LIST_MAX_NUM) {
		return;
	}
	if (nlist_number == 0) {
		memset(&nlist_entry[0], 0,
		       sizeof(neighbor_list_entrie_t) * NB_LIST_MAX_NUM);
		return;
	}

	for (i = 0; i <= bss_num; i++) {
		if (wlpptr->vdev[i] && wlpptr->vdev[i]->flags & IFF_RUNNING) {
#ifdef CFG80211
			mwl_send_vendor_neighbor_event(wlpptr->vdev[i],
						       (void *)
						       &nlist_entry[index],
						       sizeof
						       (neighbor_list_entrie_t),
						       0);
#endif /* CFG80211 */
		}
	}

	for (i = index; i < (nlist_number - 1) && i < (NB_LIST_MAX_NUM - 1);
	     i++) {
		memcpy(&nlist_entry[i], &nlist_entry[i + 1],
		       sizeof(neighbor_list_entrie_t));
	}
	memset(&nlist_entry[i], 0, sizeof(neighbor_list_entrie_t));
	nlist_number--;
}

void
MSAN_neighbor_add(struct net_device *netdev,
		  struct neighbor_list_entrie_t *nlist)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	UINT32 nlist_idx = 0;
	UINT32 ignore_time;

	// check if there is the same BSSID in nlist.
	for (nlist_idx = 0;
	     nlist_idx < nlist_number && nlist_idx < NB_LIST_MAX_NUM;
	     nlist_idx++) {
		if (!memcmp
		    (nlist_entry[nlist_idx].bssid, nlist->bssid,
		     IEEEtypes_ADDRESS_SIZE)) {
			break;
		}
	}

	if (vmacSta_p->acs_cload.interval > ACS_INTERVAL_MAX_TIME) {
		ignore_time = 60;
	} else {
		ignore_time = vmacSta_p->acs_cload.interval / 1000;
	}
	if (nlist_idx == NB_LIST_MAX_NUM)	// nlist full, need to delete one neighbor
	{
		nlist_idx = neighbor_report_find_cand();
		neighbor_report_delete(netdev, nlist_idx);
		nlist_idx = nlist_number;
	}
	if (nlist_entry[nlist_idx].time_stamp != 0 &&
	    nlist_entry[nlist_idx].nf != 0 &&
	    (nlist->time_stamp - nlist_entry[nlist_idx].time_stamp) <
	    ignore_time && nlist->nf < nlist_entry[nlist_idx].nf) {
		/* find max nf in this interval bcn info */
		/* we have found the neighbor AP, must update time_stamp */
		nlist_entry[nlist_idx].time_stamp = nlist->time_stamp;
		return;
	}
	memcpy(&nlist_entry[nlist_idx], nlist,
	       sizeof(struct neighbor_list_entrie_t));

	if (nlist_number == nlist_idx) {
		nlist_number++;
	}
}

#ifndef OFFCHANNEL_SUPPORT
static void
neighbor_report_scan_done(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	scanDescptHdr_t *curDescpt_p = NULL;
	UINT16 parsedLen = 0;
	UINT32 i = 0, nlist_idx = 0;
	neighbor_list_entrie_t *nlist = NULL;
#ifdef MRVL_80211R
	IEEEtypes_MOBILITY_DOMAIN_IE_t *MDIE_p;
#endif /* MRVL_80211R */
	IEEEtypes_HT_Element_t *pHT = NULL;
	IEEEtypes_Generic_HT_Element_t *pHTGen = NULL;
	IEEEtypes_VhOpt_t *pVHT = NULL;
	IEEEtypes_DsParamSet_t *dsPSetIE_p = NULL;
	IEEEtypes_SsIdElement_t *ssidIE_p;
	UINT8 *attrib_p = NULL;

	if (vmacSta_p->busyScanning) {
		return;
	}

	if (nlist_number == 0) {
		memset(&nlist_entry[0], 0,
		       sizeof(neighbor_list_entrie_t) * NB_LIST_MAX_NUM);
	}

	for (i = 0; i < tmpNumScanDesc[vmacSta_p->VMacEntry.phyHwMacIndx]; i++) {
		curDescpt_p =
			(scanDescptHdr_t
			 *) (&tmpScanResults[vmacSta_p->VMacEntry.
					     phyHwMacIndx][0] + parsedLen);

		// check if there is the same BSSID in nlist.
		for (nlist_idx = 0;
		     nlist_idx < nlist_number && nlist_idx < NB_LIST_MAX_NUM;
		     nlist_idx++) {
			if (!memcmp
			    (nlist_entry[nlist_idx].bssid, curDescpt_p->bssId,
			     IEEEtypes_ADDRESS_SIZE)) {
				nlist_entry[nlist_idx].not_found_count = 0;
				break;
			}
		}

		if (nlist_idx == NB_LIST_MAX_NUM)	// nlist full, need to delete one neighbor
		{
			nlist_idx = neighbor_report_find_cand();
			if (nlist_entry[nlist_idx].not_found_count == 0) {
				// nlist is full
				printk("%s neighbor report number more than %d!\n", __FUNCTION__, nlist_idx);
				break;
			}
			neighbor_report_delete(netdev, nlist_idx);
			nlist_idx = nlist_number;
		}

		nlist = &nlist_entry[nlist_idx];
		memset(nlist->SsId, 0, sizeof(IEEEtypes_SsId_t));
		if ((ssidIE_p = (IEEEtypes_SsIdElement_t *) smeParseIeType(SSID,
									   (((UINT8 *) curDescpt_p) + sizeof(scanDescptHdr_t)), curDescpt_p->length + sizeof(curDescpt_p->length) - sizeof(scanDescptHdr_t))) != NULL) {
			memcpy(nlist->SsId, &ssidIE_p->SsId[0], ssidIE_p->Len);
			nlist->ssid_len = ssidIE_p->Len;
		}

		memcpy(nlist->bssid, curDescpt_p->bssId, 6);
		nlist->bssid_info.ApReachability = 0x3;	//AP Reachability
		nlist->bssid_info.Security = 1;
		nlist->bssid_info.KeyScope = 0;
		nlist->bssid_info.Capa_SpectrumMgmt =
			curDescpt_p->CapInfo.SpectrumMgmt;
		nlist->bssid_info.Capa_QoS = curDescpt_p->CapInfo.QoS;
		nlist->bssid_info.Capa_APSD = curDescpt_p->CapInfo.APSD;
		nlist->bssid_info.Capa_Rrm = curDescpt_p->CapInfo.Rrm;
		nlist->bssid_info.Capa_DBlckAck = curDescpt_p->CapInfo.BlckAck;
		nlist->bssid_info.Capa_IBlckAck = curDescpt_p->CapInfo.Rsrvd2;
		nlist->bssid_info.MobilityDomain = 0;
		nlist->time_stamp = ktime_to_timespec(ktime_get_real()).tv_sec;

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
		// If cannot find HT element then look for High Throughput elements using PROPRIETARY_IE.
		if (pHT == NULL) {
			pHTGen = linkMgtParseHTGenIe((((UINT8 *) curDescpt_p) +
						      sizeof(scanDescptHdr_t)),
						     curDescpt_p->length +
						     sizeof(curDescpt_p->
							    length) -
						     sizeof(scanDescptHdr_t));
		}
		if (pHT || pHTGen) {
			nlist->bssid_info.HT = 1;
			nlist->phy_type = PHY_HT;
		}
		if ((pVHT = (IEEEtypes_VhOpt_t *) smeParseIeType(VHT_OPERATION,
								 (((UINT8 *)
								   curDescpt_p)
								  +
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
			nlist->bssid_info.VHT = 1;
			nlist->phy_type = PHY_VHT;
		}

		nlist->reg_class = getRegulatoryClass(vmacSta_p);

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
			nlist->chan = dsPSetIE_p->CurrentChan;
		}
#ifdef MRVL_80211R
		if ((MDIE_p =
		     (struct IEEEtypes_MOBILITY_DOMAIN_IE_t *)
		     smeParseIeType(MD_IE,
				    (((UINT8 *) curDescpt_p) +
				     sizeof(scanDescptHdr_t)),
				    curDescpt_p->length +
				    sizeof(curDescpt_p->length) -
				    sizeof(scanDescptHdr_t))) != NULL) {
			memcpy(&nlist->md_ie, MDIE_p,
			       sizeof(struct IEEEtypes_MOBILITY_DOMAIN_IE_t));
			nlist->bssid_info.MobilityDomain = 1;
		}
#endif /* MRVL_80211R */

		/* find the same company IE */
		attrib_p = ((UINT8 *) curDescpt_p) + sizeof(scanDescptHdr_t);
		while ((attrib_p = (UINT8 *) smeParseIeType(PROPRIETARY_IE,
							    attrib_p,
							    curDescpt_p->
							    length +
							    sizeof(curDescpt_p->
								   length) -
							    sizeof
							    (scanDescptHdr_t)))
		       != NULL) {
			WME_param_elem_t *WMMIE_p =
				(WME_param_elem_t *) attrib_p;

			if (WMMIE_p->OUI.Type == 2) {
				/* is WMM/WME Parameter Element */
				nlist->bssid_info.Capa_QoS = 1;
#ifdef WMM_PS_SUPPORT
				if (WMMIE_p->QoS_info.U_APSD) {
					nlist->bssid_info.Capa_APSD = 1;
				}
#else
				if (WMMIE_p->QoS_info.more_data_ack) {
					/* this bit is others AP's APSD */
					nlist->bssid_info.Capa_APSD = 1;
				}
#endif /* WMM_PS_SUPPORT */
			}
			//Now process to the next element pointer.
			attrib_p += (2 + *((UINT8 *) (attrib_p + 1)));
		}

		if (nlist_number == nlist_idx) {
			nlist_number++;
		}
		parsedLen += curDescpt_p->length + sizeof(curDescpt_p->length);
	}
}
#endif /* OFFCHANNEL_SUPPORT */

#ifdef OFFCHANNEL_SUPPORT
static SINT32
nlist_scan(struct net_device *netdev)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	DOT11_OFFCHAN_REQ_t offchan;
	UINT8 chnlScanList[IEEEtypes_MAX_CHANNELS + IEEEtypes_MAX_CHANNELS_A];
	UINT8 mainChnlList[IEEEtypes_MAX_CHANNELS + IEEEtypes_MAX_CHANNELS_A];
	UINT8 currChnlIndex = 0;
	UINT8 i;

	if (InScanFlag) {
		/* one band in scanning, wait 30s */
		InScanFlag = 0;
		return -EPERM;
	} else {
		InScanFlag = 1;
	}
	if (!*(mib->mib_rrm)) {
		/* Not enable rrm, wait 30s */
		InScanFlag = 0;
		return -EPERM;
	}

	memset(&mainChnlList[0], 0,
	       (IEEEtypes_MAX_CHANNELS + IEEEtypes_MAX_CHANNELS_A));
	memset(&chnlScanList[0], 0,
	       (IEEEtypes_MAX_CHANNELS + IEEEtypes_MAX_CHANNELS_A));

	/* get range to scan */
	domainGetInfo(mainChnlList);
	if (Is5GBand(*(mib->mib_ApMode))) {
		for (i = 0; i < IEEEtypes_MAX_CHANNELS_A; i++) {
			if (mainChnlList[i + IEEEtypes_MAX_CHANNELS] > 0) {
				chnlScanList[currChnlIndex] =
					mainChnlList[i +
						     IEEEtypes_MAX_CHANNELS];
				currChnlIndex++;
			}
		}
	} else {
		for (i = 0; i < IEEEtypes_MAX_CHANNELS; i++) {
			if (mainChnlList[i] > 0) {
				chnlScanList[currChnlIndex] = mainChnlList[i];
				currChnlIndex++;
			}
		}
	}

	nbr_offchan_channel = (UINT32) chnlScanList[vmacSta_p->SepareChanIdx];
	memset((UINT8 *) & offchan, 0x0, sizeof(DOT11_OFFCHAN_REQ_t));
	offchan.channel = nbr_offchan_channel;
	offchan.id = L_offchan_id++;
	offchan.dwell_time = priv->wlpd_p->rrm_dwell_time;

	wlFwNewDP_queue_OffChan_req(netdev, &offchan);

	if (vmacSta_p->SepareNumScanChannels == 0 ||
	    vmacSta_p->SepareNumScanChannels != currChnlIndex) {
		vmacSta_p->SepareNumScanChannels = currChnlIndex;
	}
	vmacSta_p->SepareChanIdx++;
	if (vmacSta_p->SepareChanIdx >= vmacSta_p->SepareNumScanChannels) {
		vmacSta_p->SepareChanIdx = 0;
	}
	return 0;
}
#else //OFFCHANNEL_SUPPORT
static SINT32
nlist_scan(struct net_device *netdev)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	MIB_802DOT11 *mib = priv->vmacSta_p->Mib802dot11;
	UINT8 bcAddr1[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };	/* BROADCAST BSSID */
	UINT8 ieBuf[2 + IEEE_80211_MAX_NUMBER_OF_CHANNELS];
	UINT16 ieBufLen = 0;
	IEEEtypes_InfoElementHdr_t *IE_p;
	vmacEntry_t *vmacEntry_p = NULL;
	struct net_device *staDev = NULL;
	struct wlprivate *stapriv = NULL;
	vmacApInfo_t *vmacSta_p = NULL;
	UINT8 mlmeAssociatedFlag;
	UINT8 mlmeBssid[6];
	UINT8 currChnlIndex = 0;
	UINT8 chnlListLen = 0;
	UINT8 chnlScanList[IEEEtypes_MAX_CHANNELS + IEEEtypes_MAX_CHANNELS_A];
	UINT8 i = 0;
	MIB_PHY_DSSS_TABLE *PhyDSSSTable;
	UINT8 mainChnlList[IEEEtypes_MAX_CHANNELS + IEEEtypes_MAX_CHANNELS_A];
#ifdef AP_SCAN_SUPPORT
	int clientDisable = 0;
#endif

	if (InScanFlag) {
		/* one band in scanning, wait 30s */
		InScanFlag = 0;
		return -EPERM;
	} else {
		InScanFlag = 1;
	}
	if (!*(mib->mib_rrm)) {
		/* Not enable rrm, wait 30s */
		InScanFlag = 0;
		return -EPERM;
	}

	vmacEntry_p =
		sme_GetParentVMacEntry(((vmacApInfo_t *) priv->vmacSta_p)->
				       VMacEntry.phyHwMacIndx);
	if (vmacEntry_p == NULL) {
		InScanFlag = 0;
		return -ENODEV;
	}

	staDev = (struct net_device *)vmacEntry_p->privInfo_p;
	stapriv = NETDEV_PRIV_P(struct wlprivate, staDev);
	vmacSta_p = stapriv->vmacSta_p;
	//when this command issued on AP mode, system would crash because of no STA interface
	//so the following checking is necessary.
	if (vmacSta_p->busyScanning) {
		InScanFlag = 0;
		return -EBUSY;
	}
#ifdef AP_SCAN_SUPPORT
	if (*(mib->mib_STAMode) == CLIENT_MODE_DISABLE) {
		*(mib->mib_STAMode) = CLIENT_MODE_AUTO;
		clientDisable = 1;
	}
#else
	if (*(mib->mib_STAMode) == CLIENT_MODE_DISABLE) {
		InScanFlag = 0;
		return -EOPNOTSUPP;
	}
#endif

	memset(&mainChnlList[0], 0,
	       (IEEEtypes_MAX_CHANNELS + IEEEtypes_MAX_CHANNELS_A));
	memset(&chnlScanList[0], 0,
	       (IEEEtypes_MAX_CHANNELS + IEEEtypes_MAX_CHANNELS_A));

	PhyDSSSTable = mib->PhyDSSSTable;

	/* Stop Autochannel on AP first */
	if (priv->master) {
		struct wlprivate *wlMPrvPtr =
			NETDEV_PRIV_P(struct wlprivate, priv->master);
		StopAutoChannel(wlMPrvPtr->vmacSta_p);
	}
	/* get range to scan */
	domainGetInfo(mainChnlList);

	if (Is5GBand(*(mib->mib_ApMode))) {
		for (i = 0; i < IEEEtypes_MAX_CHANNELS_A; i++) {
			if (mainChnlList[i + IEEEtypes_MAX_CHANNELS] > 0) {
				chnlScanList[currChnlIndex] =
					mainChnlList[i +
						     IEEEtypes_MAX_CHANNELS];
				currChnlIndex++;
			}
		}
		chnlListLen = currChnlIndex;
	} else {
		for (i = 0; i < IEEEtypes_MAX_CHANNELS; i++) {
			if (mainChnlList[i] > 0) {
				chnlScanList[currChnlIndex] = mainChnlList[i];
				currChnlIndex++;
			}
		}
		chnlListLen = currChnlIndex;
	}

#ifdef AP_SCAN_SUPPORT
	if (clientDisable)
		*(mib->mib_STAMode) = CLIENT_MODE_DISABLE;
#endif
	ieBufLen = 0;
	/* Build IE Buf */
	IE_p = (IEEEtypes_InfoElementHdr_t *) & ieBuf[ieBufLen];

	/* DS_PARAM_SET element, only one channel at a time */
	IE_p->ElementId = DS_PARAM_SET;
	IE_p->Len = 1;
	ieBufLen += sizeof(IEEEtypes_InfoElementHdr_t);
	ieBuf[ieBufLen] = chnlScanList[priv->vmacSta_p->SepareChanIdx];
	ieBufLen += IE_p->Len;
	IE_p = (IEEEtypes_InfoElementHdr_t *) & ieBuf[ieBufLen];

	if (!smeGetStaLinkInfo(vmacEntry_p->id, &mlmeAssociatedFlag,
			       &mlmeBssid[0])) {
		InScanFlag = 0;
		return -EFAULT;
	}

	/* Set a flag indicating usr initiated scan */
	vmacSta_p->gUserInitScan = TRUE;
	if (priv->vmacSta_p->SepareNumScanChannels == 0 ||
	    priv->vmacSta_p->SepareNumScanChannels != chnlListLen) {
		priv->vmacSta_p->SepareNumScanChannels = chnlListLen;
	}
	priv->vmacSta_p->SepareChanIdx++;
	if (priv->vmacSta_p->SepareChanIdx >=
	    priv->vmacSta_p->SepareNumScanChannels) {
		priv->vmacSta_p->SepareChanIdx = 0;
	}

	if (!mlmeAssociatedFlag && (staDev->flags & IFF_RUNNING)) {
		linkMgtStop(vmacEntry_p->phyHwMacIndx);
		smeStopBss(vmacEntry_p->phyHwMacIndx);
	}

	if (smeSendScanRequest
	    (vmacEntry_p->phyHwMacIndx, SCAN_PASSIVE, 3,
	     priv->wlpd_p->rrm_dwell_time, &bcAddr1[0], &ieBuf[0],
	     ieBufLen) == MLME_SUCCESS) {
		/*set the busy scanning flag */
		vmacSta_p->busyScanning = 1;
	} else {
		/* Reset a flag indicating usr initiated scan */
		vmacSta_p->gUserInitScan = FALSE;
		InScanFlag = 0;
		return -EALREADY;
	}
	return 0;
}
#endif //OFFCHANNEL_SUPPORT

static void
neighbor_report_scan_cb(UINT8 * data)
{
	struct net_device *netdev = (struct net_device *)data;
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	SINT32 ret = 0;

	if (priv->master) {
		priv = NETDEV_PRIV_P(struct wlprivate, priv->master);
	}
	/* if zero, set rrm offchan time to default */
	if (priv->wlpd_p->rrm_trigger_time == 0) {
		priv->wlpd_p->rrm_trigger_time = RRM_DEFAULT_TRIGGER_TIME;
	}
	if (priv->wlpd_p->rrm_interval_time == 0) {
		priv->wlpd_p->rrm_interval_time = RRM_DEFAULT_INTERVAL_TIME;
	}
	if (priv->wlpd_p->rrm_dwell_time == 0) {
		priv->wlpd_p->rrm_dwell_time = RRM_DEFAULT_DWELL_TIME;
	}

	ret = nlist_scan(netdev);

	TimerDisarm(&priv->vmacSta_p->RRM_ScanTimer);
	if (ret == -EPERM) {
		/* not ready, after 30s to scan */
		TimerFireInByJiffies(&priv->vmacSta_p->RRM_ScanTimer, 1,
				     &neighbor_report_scan_cb, (UINT8 *) netdev,
				     30000 * TIMER_1MS);
	} else if (ret == -EBUSY) {
		/* scan busy, wait dwell + interval time ms to scan */
		TimerFireInByJiffies(&priv->vmacSta_p->RRM_ScanTimer, 1,
				     &neighbor_report_scan_cb, (UINT8 *) netdev,
				     (priv->wlpd_p->rrm_dwell_time +
				      priv->wlpd_p->rrm_interval_time) *
				     TIMER_1MS);
	} else if (priv->vmacSta_p->SepareChanIdx == 0) {
		/* after dwell + trigger time ms to scan */
		TimerFireInByJiffies(&priv->vmacSta_p->RRM_ScanTimer, 1,
				     &neighbor_report_scan_cb, (UINT8 *) netdev,
				     (priv->wlpd_p->rrm_dwell_time +
				      priv->wlpd_p->rrm_trigger_time) *
				     TIMER_1MS);
	} else {
		/* after dwell + interval time ms to scan */
		TimerFireInByJiffies(&priv->vmacSta_p->RRM_ScanTimer, 1,
				     &neighbor_report_scan_cb, (UINT8 *) netdev,
				     (priv->wlpd_p->rrm_dwell_time +
				      priv->wlpd_p->rrm_interval_time) *
				     TIMER_1MS);
	}
}

void
MSAN_neighbor_scan(struct net_device *netdev, int enable)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;

	if (enable) {
		if (vmacSta_p) {
			vmacSta_p->SepareNumScanChannels = 0;
			vmacSta_p->SepareChanIdx = 0;
		}
	} else {
		TimerDisarm(&vmacSta_p->RRM_ScanTimer);
		nlist_number = 0;
		memset(&nlist_entry[0], 0,
		       sizeof(neighbor_list_entrie_t) * NB_LIST_MAX_NUM);
	}
}

void
MSAN_neighbor_bcnproc(struct net_device *netdev, void *BssData_p, UINT32 len,
		      RssiPathInfo_t * prssiPaths, UINT8 scan_path)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	macmgmtQ_MgmtMsg_t *MgmtMsg_p;
	IEEEtypes_Bcn_t *Beacon_p = NULL;
	neighbor_list_entrie_t nlist;
#ifdef MRVL_80211R
	IEEEtypes_MOBILITY_DOMAIN_IE_t *MDIE_p = NULL;
#endif /* MRVL_80211R */
	IEEEtypes_Generic_HT_Element_t *pHTGen = NULL;
	IEEEtypes_SsIdElement_t *ssidIE_p = NULL;
	IEEEtypes_HT_Element_t *pHT_Cap = NULL;
	IEEEtypes_Add_HT_Element_t *pHT_Info = NULL;
	IEEEtypes_DsParamSet_t *dsPSetIE_p = NULL;
	IEEEtypes_VhtCap_t *pVHT_Cap = NULL;
	IEEEtypes_VhOpt_t *pVHT = NULL;
	UINT32 attpib_len;
	UINT8 failaddr[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	UINT8 *attrib_p = NULL;
	SINT32 rssi_avg = 0;
	UINT8 WMM_OUI[3] = { 0x00, 0x50, 0xf2 };
	SINT32 nf;
	SINT32 rthresh;

	rssi_avg = (SINT32) wl_util_get_rssi(netdev, prssiPaths, NULL);
	nf = (SINT32) wl_util_get_nf(netdev, NULL, NULL);
	/* nf is signed value */

	rthresh = -rssi_threshold;
	if ((rssi_avg <= rthresh) || ((rssi_avg - nf) <= rssi_nf_delta)) {
		//printk("skip weak signal, rssi: %d, rssi_threshold: %d, nf: %d, delta: %d\n",
		//              rssi_avg, rthresh, nf, rssi_nf_delta);
		/* weak signal */
		return;
	}

	attpib_len =
		sizeof(IEEEtypes_MgmtHdr2_t) + sizeof(IEEEtypes_TimeStamp_t)
		+ sizeof(IEEEtypes_BcnInterval_t) + sizeof(IEEEtypes_CapInfo_t);

	if (len > MAX_BEACON_SIZE || len <= attpib_len) {
		return;
	}
	MgmtMsg_p = (macmgmtQ_MgmtMsg_t *) BssData_p;
	if (scan_path == SCAN_BY_ACS) {
		Beacon_p = &(MgmtMsg_p->Body.Bcn);
	} else {
		Beacon_p = (IEEEtypes_Bcn_t *) & (MgmtMsg_p->Hdr.Rsrvd);
	}
	attrib_p = (UINT8 *) & (Beacon_p->SsId);
	if (!memcmp(MgmtMsg_p->Hdr.BssId, failaddr, 6)) {
		return;
	}
	memset(&nlist, 0, sizeof(struct neighbor_list_entrie_t));
	memcpy(nlist.bssid, MgmtMsg_p->Hdr.BssId, 6);

	if ((ssidIE_p = (IEEEtypes_SsIdElement_t *) smeParseIeType(SSID,
								   ((UINT8 *)
								    attrib_p),
								   (len -
								    attpib_len)))
	    != NULL) {
		if (ssidIE_p->Len >= IEEEtypes_SSID_SIZE) {
			//printk("%s ssid length(%d) more than 32, maybe not bcn frame!!\n",__FUNCTION__,  ssidIE_p->Len);
			return;
		}
		memcpy(nlist.SsId, &ssidIE_p->SsId[0], ssidIE_p->Len);
		nlist.ssid_len = ssidIE_p->Len;
	} else {
		//printk("%s not found SSID !!!!!!!!!!!!!!!!\n",__FUNCTION__ );
		return;
	}

	if ((dsPSetIE_p =
	     (IEEEtypes_DsParamSet_t *) smeParseIeType(DS_PARAM_SET,
						       (UINT8 *) attrib_p,
						       (len - attpib_len))) !=
	    NULL) {
		nlist.chan = dsPSetIE_p->CurrentChan;
	}

	nlist.width = NR_CHAN_WIDTH_20;
	if ((pHT_Cap =
	     (IEEEtypes_HT_Element_t *) smeParseIeType(HT, (UINT8 *) attrib_p,
						       (len - attpib_len))) !=
	    NULL) {
		if (pHT_Cap->HTCapabilitiesInfo.SupChanWidth)
			nlist.width = NR_CHAN_WIDTH_40;
	}
	if ((pHT_Info =
	     (IEEEtypes_Add_HT_Element_t *) smeParseIeType(ADD_HT,
							   (UINT8 *) attrib_p,
							   (len -
							    attpib_len))) !=
	    NULL) {
		if (nlist.chan == 0) {
			nlist.chan = pHT_Info->ControlChan;
		}
		if (pHT_Info->ControlChan < 15) {
			/* Only for 2.4G */
			if (pHT_Info->AddChan.ExtChanOffset == 0x1) {
				nlist.width = NR_CHAN_WIDTH_40;
				nlist.bw_2g_40_above = 0x1;
			} else if (pHT_Info->AddChan.ExtChanOffset == 0x3) {
				nlist.width = NR_CHAN_WIDTH_40;
				nlist.bw_2g_40_above = 0x2;
			} else {
				nlist.width = NR_CHAN_WIDTH_20;
				nlist.bw_2g_40_above = 0;
			}
		}
	}
	if (nlist.chan == 0) {
		/* Cannot find channel */
		return;
	}

	pHTGen = linkMgtParseHTGenIe((UINT8 *) attrib_p, (len - attpib_len));
	if (pHT_Cap || pHTGen) {
		nlist.bssid_info.HT = 1;
		nlist.phy_type = PHY_HT;
	}
	if ((pVHT_Cap =
	     (IEEEtypes_VhtCap_t *) smeParseIeType(VHT_CAP, (UINT8 *) attrib_p,
						   (len - attpib_len))) !=
	    NULL) {
		if (pVHT_Cap->cap.SupportedChannelWidthSet > 0)
			nlist.width = NR_CHAN_WIDTH_160;
	}
	if ((pVHT =
	     (IEEEtypes_VhOpt_t *) smeParseIeType(VHT_OPERATION,
						  (UINT8 *) attrib_p,
						  (len - attpib_len))) !=
	    NULL) {
		nlist.bssid_info.VHT = 1;
		nlist.phy_type = PHY_VHT;
		if (pVHT->ch_width == 1 && nlist.width < NR_CHAN_WIDTH_80) {
			nlist.width = NR_CHAN_WIDTH_80;
		} else if (pVHT->ch_width == 2) {
			nlist.width = NR_CHAN_WIDTH_160;
		}
	}
#ifdef MRVL_80211R
	/* find the Mobility Domain IE */
	if ((MDIE_p =
	     (struct IEEEtypes_MOBILITY_DOMAIN_IE_t *)smeParseIeType(MD_IE,
								     (UINT8 *)
								     attrib_p,
								     (len -
								      attpib_len)))
	    != NULL) {
		memcpy(&nlist.md_ie, MDIE_p,
		       sizeof(struct IEEEtypes_MOBILITY_DOMAIN_IE_t));
		nlist.bssid_info.MobilityDomain = 1;
	}
#endif /* MRVL_80211R */
	{
		QBSS_load_t *QBSS_IE_p;

		/* find the QBSS IE */
		if ((QBSS_IE_p =
		     (QBSS_load_t *) smeParseIeType(QBSS_LOAD,
						    (UINT8 *) attrib_p,
						    (len - attpib_len))) !=
		    NULL) {
			nlist.sta_cnt = QBSS_IE_p->sta_cnt;
			nlist.channel_util = QBSS_IE_p->channel_util;
		} else {
			/* Neighbor AP has not QBSS IE */
			nlist.sta_cnt = 0xFFFF;
			nlist.channel_util = 0;
		}
	}

	/* find the same company IE */
	while ((attrib_p =
		(UINT8 *) smeParseIeType(PROPRIETARY_IE, attrib_p,
					 len -
					 ((attrib_p - (UINT8 *) BssData_p) +
					  2))) != NULL) {
		WME_param_elem_t *WMMIE_p = (WME_param_elem_t *) attrib_p;

		if ((!memcmp(WMMIE_p->OUI.OUI, WMM_OUI, 3)) &&
		    (WMMIE_p->OUI.Type == 2)) {
			/* WMM/WME Parameter Element */
			nlist.bssid_info.Capa_QoS = 1;
#ifdef WMM_PS_SUPPORT
			if (WMMIE_p->QoS_info.U_APSD) {
				nlist.bssid_info.Capa_APSD = 1;
			}
#else
			if (WMMIE_p->QoS_info.more_data_ack) {
				/* this bit is others AP's APSD */
				nlist.bssid_info.Capa_APSD = 1;
			}
#endif /* WMM_PS_SUPPORT */
		}
		if (isMcIdIE((UINT8 *) attrib_p) == TRUE) {
			nlist.bssid_info.Security = 1;
			nlist.bssid_info.KeyScope = 0;
			//break;
		}
		//Now process to the next element pointer.
		attrib_p += (2 + *((UINT8 *) (attrib_p + 1)));
		if ((len - ((attrib_p - (UINT8 *) BssData_p) + 2)) <= 0) {
			break;
		}
	}

	nlist.rssi = rssi_avg;
#ifdef MBO_SUPPORT
	nlist.reg_class = nlist.chan <= 13 ? 81 : 115;
#else
	nlist.reg_class = getRegulatoryClass(vmacSta_p);
#endif
	nlist.bssid_info.ApReachability = 0x3;	//AP Reachability
	nlist.bssid_info.Capa_SpectrumMgmt = Beacon_p->CapInfo.SpectrumMgmt;
	//nlist.bssid_info.Capa_QoS = Beacon_p->CapInfo.QoS;
	//nlist.bssid_info.Capa_APSD = Beacon_p->CapInfo.APSD;
	nlist.bssid_info.Capa_Rrm = Beacon_p->CapInfo.Rrm;
	nlist.bssid_info.Capa_DBlckAck = Beacon_p->CapInfo.BlckAck;
	nlist.bssid_info.Capa_IBlckAck = Beacon_p->CapInfo.Rsrvd2;
	nlist.time_stamp = ktime_to_timespec(ktime_get_real()).tv_sec;
	nlist.nf = nf;

	MSAN_neighbor_add(vmacSta_p->dev, &nlist);
}

UINT8
MSAN_get_neighbor_bySSID(struct IEEEtypes_SsIdElement_t *ssid,
			 struct IEEEtypes_Neighbor_Report_Element_t **nr_list)
{
	UINT8 i, num;

	if (ssid == NULL) {
		return 0;
	}

	nb_list_num = 0;
	memset(&nb_elem_list[0], 0,
	       sizeof(struct IEEEtypes_Neighbor_Report_Element_t) *
	       NB_LIST_MAX_NUM);
	for (i = 0, num = 0; i < nlist_number && i < NB_LIST_MAX_NUM; i++) {
		if (!memcmp(ssid->SsId, nlist_entry[i].SsId, ssid->Len)) {
			nb_elem_list[num].ElementId = NEIGHBOR_REPORT;
			nb_elem_list[num].Len =	/* No optional subelement for now */
				sizeof(struct
				       IEEEtypes_Neighbor_Report_Element_t) - 2;
			memcpy(nb_elem_list[num].Bssid, nlist_entry[i].bssid,
			       6);
			nb_elem_list[num].BssidInfo = nlist_entry[i].bssid_info;
			nb_elem_list[num].RegulatoryClass =
				nlist_entry[i].reg_class;
			nb_elem_list[num].Channel = nlist_entry[i].chan;
			nb_elem_list[num].PhyType = nlist_entry[i].phy_type;
			num++;
		}
	}
	nb_list_num = num;
	*nr_list = &nb_elem_list[0];
	return num;
}

UINT8
MSAN_get_neighbor_byDefault(struct IEEEtypes_Neighbor_Report_Element_t **
			    nr_list)
{
	UINT8 i, num;

	nb_list_num = 0;
	memset(&nb_elem_list[0], 0,
	       sizeof(struct IEEEtypes_Neighbor_Report_Element_t) *
	       NB_LIST_MAX_NUM);
	for (i = 0, num = 0; i < nlist_number && i < NB_LIST_MAX_NUM; i++) {
		nb_elem_list[num].ElementId = NEIGHBOR_REPORT;
		nb_elem_list[num].Len =	/* No optional subelement for now */
			sizeof(struct IEEEtypes_Neighbor_Report_Element_t) - 2;
		memcpy(nb_elem_list[num].Bssid, nlist_entry[i].bssid, 6);
		nb_elem_list[num].BssidInfo = nlist_entry[i].bssid_info;
		nb_elem_list[num].RegulatoryClass = nlist_entry[i].reg_class;
		nb_elem_list[num].Channel = nlist_entry[i].chan;
		nb_elem_list[num].PhyType = nlist_entry[i].phy_type;
		num++;
	}
	nb_list_num = num;
	*nr_list = &nb_elem_list[0];
	return num;
}

UINT8
MSAN_get_neighbor_byAddr(IEEEtypes_MacAddr_t * target_addr,
			 struct IEEEtypes_Neighbor_Report_Element_t ** nr_list)
{
	UINT8 i;

	if (target_addr == NULL) {
		return 0;
	}

	for (i = 0; i < nlist_number && i < NB_LIST_MAX_NUM; i++) {
		if (!memcmp
		    (target_addr, nlist_entry[i].bssid,
		     IEEEtypes_ADDRESS_SIZE)) {
			nb_elem_list[nb_list_num].ElementId = NEIGHBOR_REPORT;
			nb_elem_list[nb_list_num].Len =	/* No optional subelement for now */
				sizeof(struct
				       IEEEtypes_Neighbor_Report_Element_t) - 2;
			memcpy(nb_elem_list[nb_list_num].Bssid,
			       nlist_entry[i].bssid, 6);
			nb_elem_list[nb_list_num].BssidInfo =
				nlist_entry[i].bssid_info;
			nb_elem_list[nb_list_num].RegulatoryClass =
				nlist_entry[i].reg_class;
			nb_elem_list[nb_list_num].Channel = nlist_entry[i].chan;
			nb_elem_list[nb_list_num].PhyType =
				nlist_entry[i].phy_type;
			nb_list_num++;
		}
	}
	*nr_list = &nb_elem_list[0];
	return nb_list_num;
}

UINT8
MSAN_get_neighbor_list(struct IEEEtypes_Neighbor_Report_Element_t ** nr_list)
{
	*nr_list = &nb_elem_list[0];
	return nb_list_num;
}

void
MSAN_clean_neighbor_list(void)
{
	nb_list_num = 0;
	memset(&nb_elem_list[0], 0,
	       sizeof(struct IEEEtypes_Neighbor_Report_Element_t) *
	       NB_LIST_MAX_NUM);
}

void
MSAN_clean_nb_list_All(void)
{
	nb_list_num = 0;
	memset(&nb_elem_list[0], 0,
	       sizeof(struct IEEEtypes_Neighbor_Report_Element_t) *
	       NB_LIST_MAX_NUM);

	nlist_number = 0;
	memset(&nlist_entry[0], 0,
	       sizeof(struct neighbor_list_entrie_t) * NB_LIST_MAX_NUM);
}

void
MSAN_update_neighbor_list(struct net_device *netdev)
{
	struct wlprivate *stapriv = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p;
	UINT32 i, nlist_idx;
	s32 curr_time = 0, offset_time;
	struct net_device *mnetdev = stapriv->master;
	struct wlprivate *priv = NULL;
	MIB_802DOT11 *mib = NULL;

#ifdef OFFCHANNEL_SUPPORT
	mnetdev = netdev;
#endif /* OFFCHANNEL_SUPPORT */
	priv = NETDEV_PRIV_P(struct wlprivate, mnetdev);
	vmacSta_p = priv->vmacSta_p;
	mib = vmacSta_p->Mib802dot11;

	if (!*(mib->mib_rrm) && !*(mib->mib_autochannel)) {
		InScanFlag = 0;
		return;
	}

	/* Delete Timer */
	TimerDisarm(&vmacSta_p->RRM_ScanTimer);

#ifndef OFFCHANNEL_SUPPORT
	neighbor_report_scan_done(netdev);
#endif //OFFCHANNEL_SUPPORT

	curr_time = ktime_to_timespec(ktime_get_real()).tv_sec;

	if (vmacSta_p->SepareChanIdx == 0) {
		/* delete some APs that exceed the life span */
		if (nlist_number == 0) {
			memset(&nlist_entry[0], 0,
			       sizeof(neighbor_list_entrie_t) *
			       NB_LIST_MAX_NUM);
		} else {
			for (nlist_idx = 0;
			     nlist_idx < nlist_number &&
			     nlist_idx < NB_LIST_MAX_NUM; nlist_idx++) {
				offset_time =
					nlist_entry[nlist_idx].time_stamp +
					NBREPORT_LIST_LIFESPAN;
				if (offset_time <= curr_time) {
					if ((nlist_entry[nlist_idx].time_stamp <
					     offset_time) ||
					    (nlist_entry[nlist_idx].time_stamp >
					     curr_time)) {
						neighbor_report_delete(mnetdev,
								       nlist_idx);
						nlist_idx =
							(nlist_idx >
							 0) ? (nlist_idx -
							       1) : 0;
					}
				} else {
					if ((nlist_entry[nlist_idx].time_stamp <
					     offset_time) &&
					    (nlist_entry[nlist_idx].time_stamp >
					     curr_time)) {
						neighbor_report_delete(mnetdev,
								       nlist_idx);
						nlist_idx =
							(nlist_idx >
							 0) ? (nlist_idx -
							       1) : 0;
					}
				}

				for (i = 0; i <= bss_num; i++) {
					if (priv->vdev[i] &&
					    priv->vdev[i]->
					    flags & IFF_RUNNING) {
						struct net_device *vdev =
							priv->vdev[i];
						struct wlprivate *nr_priv =
							NETDEV_PRIV_P(struct
								      wlprivate,
								      vdev);
						vmacApInfo_t *nr_vap_p =
							nr_priv->vmacSta_p;

						if (!memcmp
						    (nr_vap_p->macSsId.SsId,
						     nlist_entry[nlist_idx].
						     SsId,
						     nr_vap_p->macSsId.Len)) {
#ifdef CFG80211
							mwl_send_vendor_neighbor_event
								(vdev,
								 (void *)
								 &nlist_entry
								 [nlist_idx],
								 sizeof
								 (neighbor_list_entrie_t),
								 1);
#endif /* CFG80211 */
						}
					}
				}
			}
		}
		/* after trigger time ms to scan */
		TimerFireInByJiffies(&vmacSta_p->RRM_ScanTimer, 1,
				     &neighbor_report_scan_cb,
				     (UINT8 *) mnetdev,
				     priv->wlpd_p->rrm_trigger_time *
				     TIMER_1MS);
	} else {
		/* after interval to scan */
		if (priv->wlpd_p->rrm_interval_time == 0) {
			priv->wlpd_p->rrm_interval_time =
				RRM_DEFAULT_INTERVAL_TIME;
		}
		TimerFireInByJiffies(&vmacSta_p->RRM_ScanTimer, 1,
				     &neighbor_report_scan_cb,
				     (UINT8 *) mnetdev,
				     priv->wlpd_p->rrm_interval_time *
				     TIMER_1MS);
	}

	InScanFlag = 0;
}

void
MSAN_neighbor_dump_list(struct net_device *netdev, UINT8 * ret_str,
			UINT8 * param1, UINT8 * param2)
{
	struct wlprivate *stapriv = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = stapriv->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	UINT32 ret_len;
	SINT16 i, nb_idx = 0;
	UINT8 msg_status = 0xFF;
	UINT8 btm_rssi[128];
	s32 curr_time = 0, offset_time;

	ret_len = 0;
	if (ret_str) {
		msg_status = 0;
	} else if (param1 == NULL) {
		msg_status = 0xFF;
	} else if (!strcmp(param1, "help")) {
		printk("Usage: getnlist [-detail] [-detail <index>] [-ssid <SSID>]\n");
		return;
	} else if (!strcmp(param1, "-detail")) {
		msg_status = 1;
		nb_idx = -1;
		if (param2[0] != 0) {
			nb_idx = simple_strtol(param2, NULL, 10);
		}
	} else if (!strcmp(param1, "-ssid")) {
		msg_status = 2;
	}
	curr_time = ktime_to_timespec(ktime_get_real()).tv_sec;
	offset_time = 0;
	for (i = 0; i < nlist_number; i++) {
		neighbor_list_entrie_t *nlist = &nlist_entry[i];

		if (msg_status == 0) {
			if (memcmp(mib->StationConfig->DesiredSsId, nlist->SsId,
				   strlen(mib->StationConfig->DesiredSsId) <
				   IEEEtypes_SSID_SIZE ? strlen(mib->
								StationConfig->
								DesiredSsId) :
				   IEEEtypes_SSID_SIZE)) {
				continue;
			}
		} else if (msg_status == 1 &&
			   (0 <= nb_idx && nb_idx < nlist_number)) {
			if (i != nb_idx) {
				continue;
			}
		} else if (msg_status == 2) {
			if (memcmp(param2, nlist->SsId, strlen(param2))) {
				continue;
			}
		}
		offset_time = curr_time - nlist->time_stamp;
		if (offset_time > NBREPORT_LIST_LIFESPAN || offset_time < 0) {
			continue;
		}

		if (msg_status == 0) {
			memset(btm_rssi, 0, 128);
			sprintf(btm_rssi,
				"bssid=%02x:%02x:%02x:%02x:%02x:%02x rssi=%d \n",
				nlist->bssid[0], nlist->bssid[1],
				nlist->bssid[2], nlist->bssid[3],
				nlist->bssid[4], nlist->bssid[5], nlist->rssi);
			strcat(ret_str, btm_rssi);
		} else {
			printk("index:%3d  bssid=%02x:%02x:%02x:%02x:%02x:%02x",
			       i, nlist->bssid[0], nlist->bssid[1],
			       nlist->bssid[2], nlist->bssid[3],
			       nlist->bssid[4], nlist->bssid[5]);
			printk("  chan=%3d", nlist->chan);
			printk("  width=");
			if (nlist->width == NR_CHAN_WIDTH_160) {
				printk("160MHz");
			} else if (nlist->width == NR_CHAN_WIDTH_80) {
				printk("80MHz ");
			} else if (nlist->width == NR_CHAN_WIDTH_40) {
				if (nlist->bw_2g_40_above == 0x1) {
					printk("40MHz+");
				} else if (nlist->bw_2g_40_above == 0x2) {
					printk("40MHz-");
				} else {
					printk("40MHz ");
				}
			} else {
				printk("20MHz ");
			}
			printk("  rssi=%3d", nlist->rssi);
			printk("  MDIE=0x%04X", nlist->md_ie.MDID);
			printk("  missing time=%4d", offset_time);
			printk("  nf=%4d", nlist->nf);
			if (nlist->sta_cnt != 0xFFFF) {
				printk("  sta_cnt=%2d", nlist->sta_cnt);
				printk("  chload=%2d", nlist->channel_util);
			}
			printk("  ssid=%s\n", nlist->SsId);
			if (msg_status == 1) {
				printk("bssid_info.ApReachability=%d\n",
				       nlist->bssid_info.ApReachability);
				printk("bssid_info.Security=%d\n",
				       nlist->bssid_info.Security);
				printk("bssid_info.KeyScope=%d\n",
				       nlist->bssid_info.KeyScope);
				printk("bssid_info.Capa_SpectrumMgmt=%d\n",
				       nlist->bssid_info.Capa_SpectrumMgmt);
				printk("bssid_info.Capa_QoS=%d\n",
				       nlist->bssid_info.Capa_QoS);
				printk("bssid_info.Capa_APSD=%d\n",
				       nlist->bssid_info.Capa_APSD);
				printk("bssid_info.Capa_Rrm=%d\n",
				       nlist->bssid_info.Capa_Rrm);
				printk("bssid_info.Capa_DBlckAck=%d\n",
				       nlist->bssid_info.Capa_DBlckAck);
				printk("bssid_info.Capa_IBlckAck=%d\n",
				       nlist->bssid_info.Capa_IBlckAck);
				printk("bssid_info.MobilityDomain=%d\n",
				       nlist->bssid_info.MobilityDomain);
				printk("bssid_info.HT=%d\n",
				       nlist->bssid_info.HT);
				printk("bssid_info.VHT=%d\n",
				       nlist->bssid_info.VHT);
				printk("bssid_info.Reserved=%d\n",
				       nlist->bssid_info.Reserved);
				printk("reg_class=%d\n", nlist->reg_class);
				printk("phy_type=%d\n", nlist->phy_type);
				printk("===================================================\n");
			}
		}
	}
	return;
}

void
MSAN_rrm_ie(struct net_device *netdev, int enable)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	ch_load_info_t *ch_load_p = &vmacSta_p->rrm_cload;

	if (enable && *(mib->mib_rrm)) {
		TimerDisarm(&ch_load_p->timer);
		if (ch_load_p->started == 0) {
			memset(ch_load_p, 0, sizeof(ch_load_info_t));
			ch_load_p->tag = CH_LOAD_RRM;
			ch_load_p->master = (UINT8 *) vmacSta_p;
			ch_load_p->dur = 500;
			ch_load_p->interval = 0;
			ch_load_p->loop_count = 0;
			ch_load_p->callback = &wl_rrm_ch_load_cb;
			ch_load_p->started = 1;
		}
		wl_get_ch_load_by_timer(ch_load_p);
	} else {
		ch_load_p->started = 0;
		TimerDisarm(&ch_load_p->timer);
	}
}

UINT32
MSAN_get_channel_util(vmacApInfo_t * vmacSta_p)
{
	vmacApInfo_t *vmactmp_p = vmacSta_p;

	if (vmacSta_p->master != NULL) {
		vmactmp_p = vmacSta_p->master;
	}

	return (UINT32) vmactmp_p->rrm_cload.ch_load;
}

#ifdef AUTOCHANNEL
static const UINT8 nb_2G_ChList[13] =
	{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13 };

static void
nb_find_2nd_ch(UINT8 ch_list_num, acs_data_t * acs_db)
{
	UINT8 i, j, k;

	for (i = 0; i < ch_list_num; i++) {
		if (acs_db[i].bw == NR_CHAN_WIDTH_160) {
			if (acs_db[i].channel > 15) {
				for (j = 0;
				     j <
				     domainGetSizeOfGrpChList160Mhz() /
				     sizeof(GRP_CHANNEL_LIST_160Mhz); j++) {
					if (channel_exists
					    (acs_db[i].channel,
					     GrpChList160Mhz[j].channelEntry,
					     8)) {
						for (k = 0; k < ch_list_num;
						     k++) {
							if (i == k) {
								continue;
							}
							if (channel_exists
							    (acs_db[k].channel,
							     GrpChList160Mhz[j].
							     channelEntry, 8)) {
								acs_db[k].
									is_2nd_ch
									= TRUE;
							}
						}
						break;
					}
				}
			}
		} else if (acs_db[i].bw == NR_CHAN_WIDTH_80) {
			if (acs_db[i].channel > 15) {
				for (j = 0;
				     j <
				     domainGetSizeOfGrpChList80Mhz() /
				     sizeof(GRP_CHANNEL_LIST_80Mhz); j++) {
					if (channel_exists
					    (acs_db[i].channel,
					     GrpChList80Mhz[j].channelEntry,
					     4)) {
						for (k = 0; k < ch_list_num;
						     k++) {
							if (i == k) {
								continue;
							}
							if (channel_exists
							    (acs_db[k].channel,
							     GrpChList80Mhz[j].
							     channelEntry, 4)) {
								acs_db[k].
									is_2nd_ch
									= TRUE;
							}
						}
						break;
					}
				}
			}
		} else if (acs_db[i].bw == NR_CHAN_WIDTH_40) {
			if (acs_db[i].channel > 15) {
				for (j = 0;
				     j <
				     domainGetSizeOfGrpChList40Mhz() /
				     sizeof(GRP_CHANNEL_LIST_40Mhz); j++) {
					if (channel_exists
					    (acs_db[i].channel,
					     GrpChList40Mhz[j].channelEntry,
					     2)) {
						for (k = 0; k < ch_list_num;
						     k++) {
							if (i == k) {
								continue;
							}
							if (channel_exists
							    (acs_db[k].channel,
							     GrpChList40Mhz[j].
							     channelEntry, 2)) {
								acs_db[k].
									is_2nd_ch
									= TRUE;
							}
						}
						break;
					}
				}
			} else {
				/* For 2.4G 40MHZ */
				SINT8 above_2nd_ch, below_2nd_ch;

				above_2nd_ch = below_2nd_ch = 0;
				if (acs_db[i].bw_2g_40_above & 0x1) {
					above_2nd_ch = acs_db[i].channel + 4;
					if (above_2nd_ch > 15) {
						printk("%s acs_db[%d].channel:%d bw:%d 40mhz:%d failed!!\n", __func__, i, acs_db[i].channel, acs_db[i].bw, acs_db[i].bw_2g_40_above);
						above_2nd_ch = 0;
					}
				}
				if (acs_db[i].bw_2g_40_above & 0x2) {
					below_2nd_ch =
						(SINT8) acs_db[i].channel - 4;
					if (below_2nd_ch <= 0) {
						printk("%s acs_db[%d].channel:%d bw:%d 40mhz:%d failed!!\n", __func__, i, acs_db[i].channel, acs_db[i].bw, acs_db[i].bw_2g_40_above);
						below_2nd_ch = 0;
					}
				}
				for (k = 0; k < ch_list_num; k++) {
					if (acs_db[k].is_2nd_ch) {
						continue;
					}
					if (above_2nd_ch == acs_db[k].channel) {
						acs_db[k].is_2nd_ch = TRUE;
					} else if (below_2nd_ch ==
						   acs_db[k].channel) {
						acs_db[k].is_2nd_ch = TRUE;
					}
				}
			}
		}
	}
}

static void
nb_check_ht40_avail(UINT8 ch_list_num, acs_data_t * acs_db)
{
	SINT32 i, j;
	/* i: ch_list_num, j: nlist_number */

	for (i = 0; i < ch_list_num; i++) {
		SINT8 affect_ch_low, affect_ch_high;
		/* affect range for HT40 operation in acs_db[i].channel */
		if (acs_db[i].channel <= 4) {
			/* Ext channel is above */
			affect_ch_low = acs_db[i].channel - 3;
			affect_ch_high = acs_db[i].channel + 7;
		} else {
			/* Ext channel is below */
			affect_ch_low = acs_db[i].channel - 7;
			affect_ch_high = acs_db[i].channel + 3;
		}
		if (affect_ch_low < 1)
			affect_ch_low = 1;
		if (affect_ch_low > 14)
			affect_ch_low = 14;

		for (j = 0; j < nlist_number; j++) {
			neighbor_list_entrie_t *nlist = &nlist_entry[j];

			/* 2.4GHz only */
			if (nlist->chan > 14)
				continue;

			/* BW20MHz same channel */
			if (nlist->bw_2g_40_above == 0 &&
			    nlist->chan == acs_db[i].channel)
				continue;

			/*
			 * BW40MHz same channel && same ext_channel
			 * NOTE: W9064: 1-4ch=above, 5-13ch=below
			 */
			if (nlist->chan == acs_db[i].channel &&
			    ((nlist->bw_2g_40_above == 0x01 && nlist->chan <= 4)
			     || (nlist->bw_2g_40_above == 0x02 &&
				 nlist->chan >= 5)))
				continue;

			if (nlist->chan >= affect_ch_low &&
			    nlist->chan <= affect_ch_high) {
				acs_db[i].ht40avail = 0;
			}
		}
	}
}

void
MSAN_get_ACS_db(vmacApInfo_t * vmacSta_p, UINT8 ch_list_num, UINT8 channel)
{
	SINT32 i, j;
	SINT32 curr_time = 0, offset_time;
	acs_data_t *acs_db = vmacSta_p->acs_db;
	s32 cal_nlist_rssi = 0;

	curr_time = ktime_to_timespec(ktime_get_real()).tv_sec;
	offset_time = 0;
	vmacSta_p->bss_channel_idx[0] = 0xFF;
	vmacSta_p->bss_channel_idx[1] = 0xFF;

	/* Get ACS data from neighbor list */
	if (channel == 0) {
		/* clean bss_num, min/max rssi in acs_db */
		for (j = 0; j < ch_list_num; j++) {
			acs_db[j].bss_num = 0;
			acs_db[j].min_rssi = 0;
			acs_db[j].max_rssi = 0;
			acs_db[j].is_2nd_ch = 0;
			acs_db[j].bw = 0;
			acs_db[j].bw_2g_40_above = 0;
			acs_db[j].ht40avail = 1;
		}
		/* Update all ACS database */
		for (i = 0; i < nlist_number; i++) {
			neighbor_list_entrie_t *nlist = &nlist_entry[i];

			offset_time = curr_time - nlist->time_stamp;
			if (offset_time > 60 || offset_time < 0) {
				/* if the bss is 60s ago, ignore it */
				continue;
			}
			for (j = 0; j < ch_list_num; j++) {
				if (nlist->chan == acs_db[j].channel) {
					acs_db[j].bss_num++;
					acs_db[j].noise_floor += nlist->nf;

					cal_nlist_rssi =
						(nlist->rssi <
						 -100) ? -(rssi_threshold) :
						nlist->rssi;
					if (acs_db[j].min_rssi == 0) {
						acs_db[j].min_rssi =
							nlist->rssi;
						acs_db[j].raw_min_rssi =
							cal_nlist_rssi;
					}
					acs_db[j].raw_min_rssi =
						acs_db[j].raw_min_rssi <
						cal_nlist_rssi ? acs_db[j].
						raw_min_rssi : cal_nlist_rssi;
					acs_db[j].min_rssi =
						acs_db[j].min_rssi <
						nlist->rssi ? acs_db[j].
						min_rssi : nlist->rssi;

					cal_nlist_rssi =
						(nlist->rssi >
						 100) ? -35 : nlist->rssi;
					if (acs_db[j].max_rssi == 0) {
						acs_db[j].max_rssi =
							nlist->rssi;
						acs_db[j].raw_max_rssi =
							cal_nlist_rssi;
					}
					acs_db[j].raw_max_rssi =
						acs_db[j].raw_max_rssi >
						cal_nlist_rssi ? acs_db[j].
						raw_max_rssi : cal_nlist_rssi;
					acs_db[j].max_rssi =
						acs_db[j].max_rssi >
						nlist->rssi ? acs_db[j].
						max_rssi : nlist->rssi;

					acs_db[j].rssi_ls +=
						(rssi_threshold -
						 abs(cal_nlist_rssi));
					if (acs_db[j].rssi_ls > rssi_threshold)
						acs_db[j].rssi_ls =
							rssi_threshold;

					/* set bw */
					acs_db[j].bw =
						acs_db[j].bw >
						nlist->width ? acs_db[j].
						bw : nlist->width;
					acs_db[j].bw_2g_40_above |=
						nlist->bw_2g_40_above;
					printk("[%d], acs_db.channel = %d, acs_db.bss_num = %d, acs_db.min_rssi = %d, acs_db.max_rssi = %d, nlist.rssi=%d\n", j, acs_db[j].channel, acs_db[j].bss_num, acs_db[j].raw_min_rssi, acs_db[j].raw_max_rssi, nlist->rssi);
					break;
				}
			}
		}

		/* caculate avg nf & min/max rssi */
		for (j = 0; j < ch_list_num; j++) {
			acs_db[j].noise_floor =
				(acs_db[j].noise_floor /
				 (acs_db[j].bss_num + 1));
			if (acs_db[j].bss_num > 0) {
				acs_db[j].min_rssi =
					acs_db[j].min_rssi -
					acs_db[j].noise_floor;
				acs_db[j].min_rssi =
					acs_db[j].min_rssi >=
					100 ? 100 : acs_db[j].min_rssi;
				acs_db[j].min_rssi =
					acs_db[j].min_rssi <=
					0 ? 1 : acs_db[j].min_rssi;
				acs_db[j].max_rssi =
					acs_db[j].max_rssi -
					acs_db[j].noise_floor;
				acs_db[j].max_rssi =
					acs_db[j].max_rssi >=
					100 ? 100 : acs_db[j].max_rssi;
				acs_db[j].max_rssi =
					acs_db[j].max_rssi <=
					0 ? 1 : acs_db[j].max_rssi;

				/* keep the 2 channel index at which there are more bss */
				if (vmacSta_p->bss_channel_idx[0] == 0xFF)
					vmacSta_p->bss_channel_idx[0] = j;
				else if (acs_db[j].bss_num >
					 acs_db[vmacSta_p->bss_channel_idx[0]].
					 bss_num) {
					vmacSta_p->bss_channel_idx[1] =
						vmacSta_p->bss_channel_idx[0];
					vmacSta_p->bss_channel_idx[0] = j;
				} else if ((vmacSta_p->bss_channel_idx[1] ==
					    0xFF) ||
					   (vmacSta_p->bss_channel_idx[j] >
					    vmacSta_p->
					    bss_channel_idx[vmacSta_p->
							    bss_channel_idx
							    [1]]))
					vmacSta_p->bss_channel_idx[1] = j;
			}
		}
		printk("worst channel (bss): %u %u, %u %u\n",
		       vmacSta_p->bss_channel_idx[0],
		       acs_db[vmacSta_p->bss_channel_idx[0]].bss_num,
		       vmacSta_p->bss_channel_idx[1],
		       acs_db[vmacSta_p->bss_channel_idx[1]].bss_num);

		/* find 2nd-CH */
		nb_find_2nd_ch(ch_list_num, acs_db);
		/* Calculate HT40 availability for each channel */
		nb_check_ht40_avail(ch_list_num, acs_db);
	} else {
		/* Update specific channel in ACS database */
		for (j = 0; j < ch_list_num; j++) {
			if (channel == acs_db[j].channel) {
				break;
			}
		}
		if (j == ch_list_num) {
			return;
		}

		acs_db[j].bss_num = 0;
		acs_db[j].min_rssi = 0;
		acs_db[j].max_rssi = 0;
		acs_db[j].bw = 0;
		acs_db[j].bw_2g_40_above = 0;
		acs_db[j].ht40avail = 1;
		for (i = 0; i < nlist_number; i++) {
			neighbor_list_entrie_t *nlist = &nlist_entry[i];

			offset_time = curr_time - nlist->time_stamp;
			if (offset_time > vmacSta_p->acs_cload.ignore_time ||
			    offset_time < 0) {
				/* if the bss is interval*2 ago, ignore it */
				continue;
			}
			if (channel == nlist->chan) {
				acs_db[j].bss_num++;
				acs_db[j].noise_floor += nlist->nf;

				cal_nlist_rssi =
					(nlist->rssi <
					 -100) ? -(rssi_threshold) : nlist->
					rssi;
				if (acs_db[j].min_rssi == 0) {
					acs_db[j].min_rssi = nlist->rssi;
					acs_db[j].raw_min_rssi = cal_nlist_rssi;
				}
				acs_db[j].raw_min_rssi =
					acs_db[j].raw_min_rssi <
					cal_nlist_rssi ? acs_db[j].
					raw_min_rssi : cal_nlist_rssi;
				acs_db[j].min_rssi =
					acs_db[j].min_rssi <
					nlist->rssi ? acs_db[j].
					min_rssi : nlist->rssi;

				cal_nlist_rssi =
					(nlist->rssi > 100) ? -35 : nlist->rssi;
				if (acs_db[j].max_rssi == 0) {
					acs_db[j].max_rssi = nlist->rssi;
					acs_db[j].raw_max_rssi = cal_nlist_rssi;
				}
				acs_db[j].raw_max_rssi =
					acs_db[j].raw_max_rssi >
					cal_nlist_rssi ? acs_db[j].
					raw_max_rssi : cal_nlist_rssi;
				acs_db[j].max_rssi =
					acs_db[j].max_rssi >
					nlist->rssi ? acs_db[j].
					max_rssi : nlist->rssi;

				acs_db[j].rssi_ls +=
					(rssi_threshold - abs(cal_nlist_rssi));
				if (acs_db[j].rssi_ls > rssi_threshold)
					acs_db[j].rssi_ls = rssi_threshold;

				/* set bw */
				acs_db[j].bw =
					acs_db[j].bw >
					nlist->width ? acs_db[j].bw : nlist->
					width;
				acs_db[j].bw_2g_40_above |=
					nlist->bw_2g_40_above;
			}
		}
		/* caculate avg nf & min/max rssi */
		acs_db[j].noise_floor =
			(acs_db[j].noise_floor / (acs_db[j].bss_num + 1));
		if (acs_db[j].bss_num > 0) {
			acs_db[j].min_rssi =
				acs_db[j].min_rssi - acs_db[j].noise_floor;
			acs_db[j].min_rssi =
				acs_db[j].min_rssi >=
				100 ? 100 : acs_db[j].min_rssi;
			acs_db[j].min_rssi =
				acs_db[j].min_rssi <=
				0 ? 1 : acs_db[j].min_rssi;
			acs_db[j].max_rssi =
				acs_db[j].max_rssi - acs_db[j].noise_floor;
			acs_db[j].max_rssi =
				acs_db[j].max_rssi >=
				100 ? 100 : acs_db[j].max_rssi;
			acs_db[j].max_rssi =
				acs_db[j].max_rssi <=
				0 ? 1 : acs_db[j].max_rssi;
		}
		/* find 2nd-CH */
		nb_find_2nd_ch(ch_list_num, acs_db);
		/* Calculate HT40 availability for each channel */
		nb_check_ht40_avail(ch_list_num, acs_db);
	}
}
#endif /* AUTOCHANNEL */

void
Disable_MSAN_timer(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;

	TimerDisarm(&vmacSta_p->RRM_ScanTimer);
	MSAN_rrm_ie(netdev, 0);
}

void
Enable_MSAN_timer(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;

	TimerDisarm(&vmacSta_p->RRM_ScanTimer);
	TimerInit(&vmacSta_p->RRM_ScanTimer);
	/* not ready, after 10s to scan */
	TimerFireInByJiffies(&vmacSta_p->RRM_ScanTimer, 1,
			     &neighbor_report_scan_cb, (UINT8 *) netdev,
			     10000 * TIMER_1MS);
	MSAN_rrm_ie(netdev, 1);
}
#endif //IEEE80211K

#ifdef MULTI_AP_SUPPORT
int
MSAN_unassocsta_offchan_init(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct unassociated_sta_link_metrics_query *query = NULL;
	int i;

	if (!wlpptr)
		return -1;

	query = (struct unassociated_sta_link_metrics_query *)wlpptr->wlpd_p->
		unassocSTA.unassocsta_query;
	if (!query)
		return -1;

	memset(unassocsta_offchan_channel_list, 0, UNASSOC_METRICS_CHANNEL_MAX);
	unassocsta_offchan_channel_number = query->num_of_channel;
	for (i = 0; i < unassocsta_offchan_channel_number; i++)
		unassocsta_offchan_channel_list[i] =
			query->unassociated_sta_info[i].channel;

	return 0;
}

void
MSAN_unassocsta_offchan_scan(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct unassociated_sta_link_metrics_query *query = NULL;
	DOT11_OFFCHAN_REQ_t offchan;
	UINT8 offChanIdx;
	int ret = 0;

	if (!wlpptr)
		return;

	query = (struct unassociated_sta_link_metrics_query *)wlpptr->wlpd_p->
		unassocSTA.unassocsta_query;
	if (!query)
		return;

	offChanIdx = wlpptr->wlpd_p->unassocSTA.offChanIdx;
	if (offChanIdx >= UNASSOC_METRICS_CHANNEL_MAX)
		return;

	unassocsta_offchan_channel =
		(UINT32) unassocsta_offchan_channel_list[offChanIdx];
	memset((UINT8 *) & offchan, 0x0, sizeof(DOT11_OFFCHAN_REQ_t));
	offchan.channel = unassocsta_offchan_channel;
	offchan.id = unassocsta_offchan_id++;
	offchan.dwell_time =
		*(wlpptr->vmacSta_p->Mib802dot11->mib_unassocsta_track_time);

	*(wlpptr->vmacSta_p->Mib802dot11->mib_unassocsta_track_enabled) = 1;
	ret = wlFwNewDP_queue_OffChan_req(netdev, &offchan);
	if (ret != 0) {
		printk("%s offchan request failed %d\n", __FUNCTION__, ret);
		return;
	}
}

extern struct unassocsta_track_info *unassocsta_track_get(struct wlprivate
							  *wlpptr,
							  const u8 * addr,
							  u8 channel);
extern void unassocsta_track_add(struct wlprivate *wlpptr, const u8 * addr,
				 u8 channel, u32 rssi);
void
MSAN_unassocsta_send_event(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct unassociated_sta_link_metrics_query *query = NULL;
	struct unassociated_sta_link_metrics_resp *resp = NULL;
	struct unassocsta_track_info *info = NULL;
	UINT8 i, j, reult_num_of_sta = 0;
	UINT8 num_of_channel = 0, num_of_sta = 0, channel = 0;

	query = (struct unassociated_sta_link_metrics_query *)wlpptr->wlpd_p->
		unassocSTA.unassocsta_query;
	if (!query)
		return;

	resp = wl_kzalloc(UNASSOC_RESP_SIZE, GFP_ATOMIC);
	if (!resp)
		return;

	num_of_channel = (query->num_of_channel < UNASSOC_METRICS_CHANNEL_MAX) ?
		query->num_of_channel : UNASSOC_METRICS_CHANNEL_MAX;
	for (i = 0; i < num_of_channel; i++) {
		channel = query->unassociated_sta_info[i].channel;
		num_of_sta =
			(query->unassociated_sta_info[i].num_of_sta <
			 UNASSOC_METRICS_STA_MAX) ? query->
			unassociated_sta_info[i].
			num_of_sta : UNASSOC_METRICS_STA_MAX;
		for (j = 0; j < num_of_sta; j++) {
			u8 *sta_mac_addr =
				query->unassociated_sta_info[i].
				sta_mac_addr_list[j];

			info = unassocsta_track_get(wlpptr,
						    (const u8 *)sta_mac_addr,
						    channel);
			if (!info)
				continue;

			memcpy(resp->unassociated_sta_info[reult_num_of_sta].
			       sta_mac_addr, (IEEEtypes_MacAddr_t *) info->addr,
			       ETH_ALEN);
			resp->unassociated_sta_info[reult_num_of_sta].channel =
				channel;
			resp->unassociated_sta_info[reult_num_of_sta].
				time_delta = (jiffies - info->last_seen);
			resp->unassociated_sta_info[reult_num_of_sta].rssi =
				-(info->rssi);
			reult_num_of_sta++;
		}
	}

	resp->operating_class = query->operating_class;
	resp->num_of_sta = reult_num_of_sta;

	//if (resp->num_of_sta) {
#if defined(SOC_W906X) && defined(CFG80211)
	mwl_send_vendor_unassocsta_event(wlpptr->wlpd_p->unassocSTA.netDev,
					 resp);
#endif /* SOC_W906X */
	//}

	wl_kfree(resp);
}

void
MSAN_unassocsta_offchan_cb(UINT8 * data)
{
	struct net_device *netdev = (struct net_device *)data;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct unassociated_sta_link_metrics_query *query = NULL;
	MIB_802DOT11 *mib = wlpptr->vmacSta_p->Mib802dot11;
	UINT8 offChanIdx;

	if (!wlpptr)
		return;

	*(mib->mib_unassocsta_track_enabled) = 0;
	wlpptr->wlpd_p->unassocSTA.offChanIdx++;

	query = (struct unassociated_sta_link_metrics_query *)wlpptr->wlpd_p->
		unassocSTA.unassocsta_query;
	if (!query)
		return;

	offChanIdx = wlpptr->wlpd_p->unassocSTA.offChanIdx;
	if (offChanIdx >= UNASSOC_METRICS_CHANNEL_MAX)
		return;

	if (unassocsta_offchan_channel_number > offChanIdx) {
		//if (unassocsta_offchan_channel_list[offChanIdx] != mib->PhyDSSSTable->CurrChan) {
		MSAN_unassocsta_offchan_scan(netdev);
		//} else {
		//wlpptr->wlpd_p->unassocSTA.offChanIdx++;
		//      *(mib->mib_unassocsta_track_enabled) = 1;
		//      MSAN_unassocsta_offchan_done(netdev, UNASSOCSTA_TRACK_MODE_CURRCHAN);
		//}
	} else
		wlpptr->wlpd_p->unassocSTA.isTrackCompleted = 1;
}

void
MSAN_unassocsta_offchan_done(struct net_device *netdev, u8 mode)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);

	if (!wlpptr)
		return;

	if (*(wlpptr->vmacSta_p->Mib802dot11->mib_unassocsta_track_enabled) ==
	    0)
		return;

	/* stop track flag and resetin offchan_cb */
	if (mode == UNASSOCSTA_TRACK_MODE_OFFCHAN)
		*(wlpptr->vmacSta_p->Mib802dot11->
		  mib_unassocsta_track_enabled) = 0;

	TimerDisarm(&wlpptr->wlpd_p->unassocSTA.scanTimer);
	TimerFireInByJiffies(&wlpptr->wlpd_p->unassocSTA.scanTimer, 1,
			     &MSAN_unassocsta_offchan_cb,
			     (UINT8 *) netdev,
			     (mode == UNASSOCSTA_TRACK_MODE_CURRCHAN) ?
			     UNASSOCSTA_CURRCHAN_TRACK_INTERVEL :
			     UNASSOCSTA_OFFCHAN_TRACK_INTERVEL);
}

void
MSAN_unassocsta_recv_proc(vmacApInfo_t * vmacSta_p,
			  IEEEtypes_Frame_t * wlanMsg_p, UINT32 rssi)
{
	vmacApInfo_t *vmactmp_p = NULL;
	struct wlprivate *wlpptr = NULL;
	struct unassociated_sta_link_metrics_query *query = NULL;

	if (vmacSta_p->master)
		vmactmp_p = vmacSta_p->master;
	else
		vmactmp_p = vmacSta_p;

	wlpptr = NETDEV_PRIV_P(struct wlprivate, vmactmp_p->dev);

	if (!wlpptr)
		return;

	if (*(wlpptr->vmacSta_p->Mib802dot11->mib_unassocsta_track_enabled) ==
	    0)
		return;

	query = (struct unassociated_sta_link_metrics_query *)wlpptr->wlpd_p->
		unassocSTA.unassocsta_query;
	if (!query)
		return;

	if ((*(vmactmp_p->Mib802dot11->mib_unassocsta_track_max_num) > 0))
		unassocsta_track_add(wlpptr, (UINT8 *) wlanMsg_p->Hdr.Addr2,
				     unassocsta_offchan_channel, rssi);
}
#endif /* MULTI_AP_SUPPORT */
