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
#endif				//IEEE80211K

#ifdef IEEE80211K
/*=============================================================================
 *                                DEFINITIONS
 *=============================================================================
*/
#define NBREPORT_LIST_LIFESPAN              (7200)	// 2 hours (2 * 60 * 60)
#define RRM_UC_CHECK_INTERVEL               (500 * TIMER_1MS)
#define RRM_UC_CHECK_TIME                   (500 )

#define ACS_INTERVAL_MAX_TIME               (60000)	// 60 * 1000 ms

#define UNASSOCSTA_CURRCHAN_TRACK_INTERVEL (200 * TIMER_1MS)
#define UNASSOCSTA_OFFCHAN_TRACK_INTERVEL (80 * TIMER_1MS)

#define OFFCHANNEL_STOP_TIME_BY_TP_THRESHOLD (30000 * TIMER_1MS)	/* 30s */
#define OFFCHANNEL_STOP_TIME_BY_DEV_BUSY (10000 * TIMER_1MS)	/* 10s */
#define OFFCHANNEL_STOP_TIME_BY_FAILED (1000 * TIMER_1MS)	/* 1s */

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
extern void *syncSrv_ParseAttrib(macmgmtQ_MgmtMsg_t * mgtFrame_p, UINT8 attrib, UINT16 len);

/*=============================================================================
 *                          MODULE LEVEL VARIABLES
 *=============================================================================
 */

/*=============================================================================
 *                   PRIVATE PROCEDURES (ANSI Prototypes)
 *=============================================================================
 */
static void offchan_scan_timer_cb(UINT8 * data);
static BOOLEAN MSAN_optimize_offchan_scan_time(struct net_device *netdev, offchan_node_t * curr_node);

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

static UINT32 neighbor_report_find_cand(nb_info_t * nb_info_p)
{
	UINT32 i, index = 0;

	if (nb_info_p->nb_number == 0)
		return 0;

	for (i = 0; i < nb_info_p->nb_number && i < NB_LIST_MAX_NUM; i++) {
		/* find the oldest timestamp AP. */
		if ((nb_info_p->nb_list[i].time_stamp < nb_info_p->nb_list[index].time_stamp) &&
		    ((nb_info_p->nb_list[index].time_stamp - nb_info_p->nb_list[i].time_stamp) < NBREPORT_LIST_LIFESPAN))
			index = i;
	}
	return index;
}

static void neighbor_report_delete(struct net_device *netdev, UINT32 index)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	nb_info_t *nb_info_p = &(wlpptr->wlpd_p->nb_info);
	UINT32 i;

	if (index >= NB_LIST_MAX_NUM)
		return;

	if (wlpptr->master)
		wlpptr = NETDEV_PRIV_P(struct wlprivate, wlpptr->master);

	if (nb_info_p->nb_number == 0) {
		MSAN_clean_nb_list_All(netdev);
		return;
	}
#ifdef CFG80211
	for (i = 0; i <= bss_num; i++) {
		if (wlpptr->vdev[i] && wlpptr->vdev[i]->flags & IFF_RUNNING)
			mwl_send_vendor_neighbor_event(wlpptr->vdev[i], (void *)&nb_info_p->nb_list[index], sizeof(neighbor_list_entrie_t), 0);
	}
#endif				/* CFG80211 */

	if (nb_info_p->nb_list[index].bcn_buf)
		wl_kfree(nb_info_p->nb_list[index].bcn_buf);

	for (i = index; i < (nb_info_p->nb_number - 1) && i < (NB_LIST_MAX_NUM - 1); i++)
		memcpy(&nb_info_p->nb_list[i], &nb_info_p->nb_list[i + 1], sizeof(neighbor_list_entrie_t));

	memset(&nb_info_p->nb_list[i], 0, sizeof(neighbor_list_entrie_t));
	nb_info_p->nb_number--;
}

void MSAN_neighbor_add(struct net_device *netdev, struct neighbor_list_entrie_t *nlist, UINT8 * bcn_buf, UINT32 bcn_len)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	nb_info_t *nb_info_p = &(wlpptr->wlpd_p->nb_info);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	UINT32 nlist_idx = 0;
	UINT32 ignore_time;

	/* check if there is the same BSSID in nlist. */
	for (nlist_idx = 0; nlist_idx < nb_info_p->nb_number && nlist_idx < NB_LIST_MAX_NUM; nlist_idx++) {
		if (!memcmp(nb_info_p->nb_list[nlist_idx].bssid, nlist->bssid, IEEEtypes_ADDRESS_SIZE))
			break;
	}

	if (vmacSta_p->acs_cload.interval > ACS_INTERVAL_MAX_TIME)
		ignore_time = 60;
	else
		ignore_time = vmacSta_p->acs_cload.interval / 1000;

	/* nlist full, need to delete one neighbor */
	if (nlist_idx == NB_LIST_MAX_NUM) {
		nlist_idx = neighbor_report_find_cand(nb_info_p);
		neighbor_report_delete(netdev, nlist_idx);
		nlist_idx = nb_info_p->nb_number;
	}
	if ((nb_info_p->nb_list[nlist_idx].time_stamp != 0) &&
	    (nb_info_p->nb_list[nlist_idx].nf != 0) &&
	    ((nlist->time_stamp - nb_info_p->nb_list[nlist_idx].time_stamp) < ignore_time) && (nlist->nf < nb_info_p->nb_list[nlist_idx].nf)) {
		/* find max nf in this interval bcn info
		 * we have found the neighbor AP, must update time_stamp
		 */
		nb_info_p->nb_list[nlist_idx].time_stamp = nlist->time_stamp;
		return;
	}
	/* Record the beacon buffer in nb_list */
	if ((bcn_len > 0) && (bcn_len < (MAX_BEACON_SIZE - sizeof(UINT32))) && (bcn_buf != NULL)) {
		if (nb_info_p->nb_list[nlist_idx].bcn_buf == NULL)
			nb_info_p->nb_list[nlist_idx].bcn_buf = (nlist_bcn_buf_t *) wl_kzalloc(MAX_BEACON_SIZE, GFP_ATOMIC);

		if (nb_info_p->nb_list[nlist_idx].bcn_buf) {
			memset((UINT8 *) nb_info_p->nb_list[nlist_idx].bcn_buf, 0, MAX_BEACON_SIZE);
			nb_info_p->nb_list[nlist_idx].bcn_buf->len = bcn_len;
			memcpy(nb_info_p->nb_list[nlist_idx].bcn_buf->buf, bcn_buf, bcn_len);
		}
	}

	nlist->bcn_buf = nb_info_p->nb_list[nlist_idx].bcn_buf;
	memcpy(&nb_info_p->nb_list[nlist_idx], nlist, sizeof(struct neighbor_list_entrie_t));

	if (nb_info_p->nb_number == nlist_idx)
		nb_info_p->nb_number++;
}

u32 suite_to_cipher(u32 cipher)
{
	switch (cipher) {
	case CIPHER_WPA_WEP40:
	case CIPHER_RSN_WEP40:
		return WPA_CIPHER_WEP40;
	case CIPHER_WPA_TKIP:
		return WPA_CIPHER_TKIP;
	case CIPHER_RSN_TKIP:
		return WPA2_CIPHER_TKIP;
	case CIPHER_WPA_CCMP:
		return WPA_CIPHER_CCMP;
	case CIPHER_RSN_CCMP:
		return WPA2_CIPHER_CCMP;
	case CIPHER_WPA_WEP104:
	case CIPHER_RSN_WEP104:
		return WPA_CIPHER_WEP104;
	case CIPHER_GCMP_128:
		return WPA_CIPHER_GCMP_128;
	case CIPHER_GCMP_256:
		return WPA_CIPHER_GCMP_256;
	case CIPHER_CCMP_256:
		return WPA_CIPHER_CCMP_256;
	default:
		return 0;
	}
}

u32 suite_to_key_mgmt(u32 cipher)
{
	switch (cipher) {
	case KEY_MGMT_WPA_IEEE8021X:
	case KEY_MGMT_RSN_IEEE8021X:
		return WPA_KEY_MGMT_IEEE8021X;
	case KEY_MGMT_WPA_PSK:
	case KEY_MGMT_RSN_PSK:
		return WPA_KEY_MGMT_PSK;
	case KEY_MGMT_PSK_SHA256:
		return WPA_KEY_MGMT_PSK_SHA256;
	case KEY_MGMT_SAE:
		return WPA_KEY_MGMT_SAE;
	case KEY_MGMT_SUITE_B:
		return WPA_KEY_MGMT_SUITE_B;
	case KEY_MGMT_SUITE_B_192:
		return WPA_KEY_MGMT_SUITE_B_192;
	case KEY_MGMT_OWE:
		return WPA_KEY_MGMT_OWE;
	default:
		return 0;
	}
}

void parse_cipher_and_key_mgmt(u8 * ie_p, u32 * cipher, u32 * key_mgmt)
{
	s16 len = ie_p[1];
	u16 offset = 0;
	u8 count;
	u8 i;

	if (ie_p[0] == PROPRIETARY_IE)
		offset = 8;
	else if (ie_p[0] == RSN_IEWPA2)
		offset = 4;
	else
		return;

	if (len < offset)
		return;

	/* group cipher suite */
	*cipher |= suite_to_cipher(U8_ARRAY_TO_U32(ie_p[offset], ie_p[offset + 1], ie_p[offset + 2], ie_p[offset + 3]));
	offset += 4;

	/* pairwise cipher Suite */
	count = ie_p[offset];
	offset += 2;
	if (len < (offset + count * 4))
		return;
	for (i = 0; i < count; i++) {
		*cipher |= suite_to_cipher(U8_ARRAY_TO_U32(ie_p[offset], ie_p[offset + 1], ie_p[offset + 2], ie_p[offset + 3]));
		offset += 4;
	}

	/* AKM Suites */
	count = ie_p[offset];
	offset += 2;
	if (len < (offset + count * 4))
		return;
	for (i = 0; i < count; i++) {
		*key_mgmt |= suite_to_key_mgmt(U8_ARRAY_TO_U32(ie_p[offset], ie_p[offset + 1], ie_p[offset + 2], ie_p[offset + 3]));
		offset += 4;
	}
}

void cipher_akm_to_text(u8 * cipher_type, u8 * encrypt_type, u32 cipher, u32 key_mgmt)
{
	if (cipher == WPA_CIPHER_NONE) {
		sprintf(encrypt_type + strlen(encrypt_type), "None");
	} else {
		if (cipher & WPA_CIPHER_WEP40)
			sprintf(cipher_type + strlen(cipher_type), "WEP ");
		if ((cipher & WPA_CIPHER_TKIP) || (cipher & WPA2_CIPHER_TKIP))
			sprintf(cipher_type + strlen(cipher_type), "TKIP ");
		if ((cipher & WPA_CIPHER_CCMP) || (cipher & WPA2_CIPHER_CCMP))
			sprintf(cipher_type + strlen(cipher_type), "AES ");

		if ((cipher & WPA_CIPHER_TKIP) || (cipher & WPA_CIPHER_CCMP))
			sprintf(encrypt_type + strlen(encrypt_type), "WPA ");
		if ((cipher & WPA2_CIPHER_TKIP) || (cipher & WPA2_CIPHER_CCMP))
			sprintf(encrypt_type + strlen(encrypt_type), "WPA2 ");
		if (key_mgmt & (WPA_KEY_MGMT_SAE | WPA_KEY_MGMT_OWE | WPA_KEY_MGMT_SUITE_B | WPA_KEY_MGMT_SUITE_B_192)) {
			sprintf(encrypt_type, "WPA3 ");
			if (key_mgmt & (WPA_KEY_MGMT_PSK | WPA_KEY_MGMT_PSK_SHA256))
				sprintf(encrypt_type + strlen(encrypt_type), "WPA2 ");
		}
		if (key_mgmt & (WPA_KEY_MGMT_IEEE8021X | WPA_KEY_MGMT_SUITE_B | WPA_KEY_MGMT_SUITE_B_192))
			sprintf(encrypt_type + strlen(encrypt_type), "EAP ");
	}
}

void MSAN_neighbor_bcnproc(struct net_device *netdev, void *BssData_p, UINT32 len, RssiPathInfo_t * prssiPaths, UINT8 scan_path)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	macmgmtQ_MgmtMsg_t *MgmtMsg_p;
	IEEEtypes_Bcn_t *Beacon_p = NULL;
	neighbor_list_entrie_t nlist;
#ifdef MRVL_80211R
	IEEEtypes_MOBILITY_DOMAIN_IE_t *MDIE_p = NULL;
#endif				/* MRVL_80211R */
	IEEEtypes_Generic_HT_Element_t *pHTGen = NULL;
	IEEEtypes_SsIdElement_t *ssidIE_p = NULL;
	IEEEtypes_HT_Element_t *pHT_Cap = NULL;
	IEEEtypes_Add_HT_Element_t *pHT_Info = NULL;
	IEEEtypes_DsParamSet_t *dsPSetIE_p = NULL;
	IEEEtypes_VhtCap_t *pVHT_Cap = NULL;
	IEEEtypes_VhOpt_t *pVHT = NULL;
	HE_Capabilities_IE_t *phe_cap = NULL;
	IEEEtypes_CapInfo_t *pCapInfo = NULL;
	UINT32 attpib_len;
	UINT8 failaddr[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	UINT8 *attrib_p = NULL;
	SINT32 rssi_avg = 0;
	UINT8 WMM_OUI[3] = { 0x00, 0x50, 0xf2 };
	SINT32 nf;
	SINT32 rthresh;
	IEEEtypes_RSN_IE_WPA2_t *wpa2IE_p = NULL;
	UINT8 *pos = NULL;
	u32 key_mgmt = 0;
	u32 cipher = 0;
	IEEEtypes_SuppRatesElement_t *PeerSupportedRates_p = NULL;
	IEEEtypes_ExtSuppRatesElement_t *PeerExtSupportedRates_p = NULL;
	UINT32 LegacyRateBitMap = 0;
	BOOLEAN apGonly = FALSE;
	UINT8 mdcnt = 0;
	UINT32 bcn_len;
	SINT32 frame_len;

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

	attpib_len = sizeof(IEEEtypes_MgmtHdr2_t) + sizeof(IEEEtypes_TimeStamp_t)
	    + sizeof(IEEEtypes_BcnInterval_t) + sizeof(IEEEtypes_CapInfo_t);

	if (len > MAX_BEACON_SIZE || len <= attpib_len) {
		return;
	}
	frame_len = len;
	MgmtMsg_p = (macmgmtQ_MgmtMsg_t *) BssData_p;
	bcn_len = len - sizeof(IEEEtypes_MgmtHdr2_t);
	if (scan_path == SCAN_BY_ACS) {
		Beacon_p = &(MgmtMsg_p->Body.Bcn);
	} else {
		Beacon_p = (IEEEtypes_Bcn_t *) & (MgmtMsg_p->Hdr.Rsrvd);
		bcn_len += sizeof(IEEEtypes_MacAddr_t);
	}
	attrib_p = (UINT8 *) & (Beacon_p->SsId);
	if (!memcmp(MgmtMsg_p->Hdr.BssId, failaddr, 6)) {
		return;
	}
	memset(&nlist, 0, sizeof(struct neighbor_list_entrie_t));
	memcpy(nlist.bssid, MgmtMsg_p->Hdr.BssId, 6);

	if ((ssidIE_p = (IEEEtypes_SsIdElement_t *) smeParseIeType(SSID, ((UINT8 *) attrib_p), (len - attpib_len))) != NULL) {
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

	if ((dsPSetIE_p = (IEEEtypes_DsParamSet_t *) smeParseIeType(DS_PARAM_SET, (UINT8 *) attrib_p, (len - attpib_len))) != NULL) {
		nlist.chan = dsPSetIE_p->CurrentChan;
	}

	nlist.width = NR_CHAN_WIDTH_20;
	if ((pHT_Cap = (IEEEtypes_HT_Element_t *) smeParseIeType(HT, (UINT8 *) attrib_p, (len - attpib_len))) != NULL) {
		if (pHT_Cap->HTCapabilitiesInfo.SupChanWidth)
			nlist.width = NR_CHAN_WIDTH_40;
	}
	if ((pHT_Info = (IEEEtypes_Add_HT_Element_t *) smeParseIeType(ADD_HT, (UINT8 *) attrib_p, (len - attpib_len))) != NULL) {
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
	if ((pVHT_Cap = (IEEEtypes_VhtCap_t *) smeParseIeType(VHT_CAP, (UINT8 *) attrib_p, (len - attpib_len))) != NULL) {
		if (pVHT_Cap->cap.SupportedChannelWidthSet > 0)
			nlist.width = NR_CHAN_WIDTH_160;
	}
	if ((pVHT = (IEEEtypes_VhOpt_t *) smeParseIeType(VHT_OPERATION, (UINT8 *) attrib_p, (len - attpib_len))) != NULL) {
		nlist.bssid_info.VHT = 1;
		nlist.phy_type = PHY_VHT;
		if (pVHT->ch_width == 1 && nlist.width < NR_CHAN_WIDTH_80) {
			nlist.width = NR_CHAN_WIDTH_80;
		} else if (pVHT->ch_width == 2) {
			nlist.width = NR_CHAN_WIDTH_160;
		}
	}
	if ((phe_cap = (HE_Capabilities_IE_t *) smeParseExtIeType(HE_CAPABILITIES_IE, (u8 *) attrib_p, (len - attpib_len))) != NULL)
		nlist.bssid_info.HE = 1;

	PeerSupportedRates_p = (IEEEtypes_SuppRatesElement_t *) smeParseIeType(SUPPORTED_RATES, (UINT8 *) attrib_p, (len - attpib_len));
	PeerExtSupportedRates_p = (IEEEtypes_ExtSuppRatesElement_t *) smeParseIeType(EXT_SUPPORTED_RATES, (UINT8 *) attrib_p, (len - attpib_len));
	LegacyRateBitMap = GetAssocRespLegacyRateBitMap(PeerSupportedRates_p, PeerExtSupportedRates_p);
	if (nlist.chan <= 14) {
		if (PeerSupportedRates_p) {
			int j;
			for (j = 0; (j < PeerSupportedRates_p->Len) && !apGonly; j++) {
				/* Only look for 6 Mbps as basic rate - consider this to be G only. */
				if (PeerSupportedRates_p->Rates[j] == 0x8c) {
					sprintf(&nlist.apType[mdcnt++], "G");
					apGonly = TRUE;
				}
			}
		}
		if (!apGonly) {
			if (LegacyRateBitMap & RATE_BITMAP_B)
				sprintf(&nlist.apType[mdcnt++], "B");

			/* If GreenField is enabled, it is only 11N, otherwise it is 11GN mode in 2.4G, judges G mode here first. */
			if ((LegacyRateBitMap & RATE_BITMAP_G) && (!pHT_Cap || !pHT_Cap->HTCapabilitiesInfo.GreenField))
				sprintf(&nlist.apType[mdcnt++], "G");
		}
	} else {
		/* If GreenField is enabled, it is only 11N, otherwise it is 11AN mode in 5G, judges A mode here first. */
		if ((LegacyRateBitMap & RATE_BITMAP_G) && (!pHT_Cap || !pHT_Cap->HTCapabilitiesInfo.GreenField))
			sprintf(&nlist.apType[mdcnt++], "A");
	}
	if (pHT_Cap || pHTGen)
		sprintf(&nlist.apType[mdcnt++], "N");

	if (nlist.bssid_info.VHT) {
		sprintf(&nlist.apType[mdcnt], "-AC");
		mdcnt += 3;
	}

	if (nlist.bssid_info.HE) {
		sprintf(&nlist.apType[mdcnt], "-AX");
		mdcnt += 3;
	}
#ifdef MRVL_80211R
	/* find the Mobility Domain IE */
	if ((MDIE_p = (struct IEEEtypes_MOBILITY_DOMAIN_IE_t *)smeParseIeType(MD_IE, (UINT8 *) attrib_p, (len - attpib_len))) != NULL) {
		memcpy(&nlist.md_ie, MDIE_p, sizeof(struct IEEEtypes_MOBILITY_DOMAIN_IE_t));
		nlist.bssid_info.MobilityDomain = 1;
	}
#endif				/* MRVL_80211R */
	{
		QBSS_load_t *QBSS_IE_p;

		/* find the QBSS IE */
		if ((QBSS_IE_p = (QBSS_load_t *) smeParseIeType(QBSS_LOAD, (UINT8 *) attrib_p, (len - attpib_len))) != NULL) {
			nlist.sta_cnt = QBSS_IE_p->sta_cnt;
			nlist.channel_util = QBSS_IE_p->channel_util;
		} else {
			/* Neighbor AP has not QBSS IE */
			nlist.sta_cnt = 0xFFFF;
			nlist.channel_util = 0;
		}
	}

	pCapInfo = (IEEEtypes_CapInfo_t *) & (Beacon_p->CapInfo);
	if (pCapInfo->Privacy)
		nlist.bssid_info.Security = 1;

	/* find the same company IE */
	pos = attrib_p;
	while ((pos = (UINT8 *) smeParseIeType(PROPRIETARY_IE, pos, frame_len - ((pos - (UINT8 *) BssData_p) + 2))) != NULL) {
		WME_param_elem_t *WMMIE_p = (WME_param_elem_t *) pos;

		if (!memcmp(WMMIE_p->OUI.OUI, WMM_OUI, 3)) {
			if (WMMIE_p->OUI.Type == 1) {
				nlist.bssid_info.Security = 1;
				parse_cipher_and_key_mgmt((u8 *) pos, &cipher, &key_mgmt);
			} else if (WMMIE_p->OUI.Type == 2) {
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
#endif				/* WMM_PS_SUPPORT */
			}
		}
		if (isMcIdIE((UINT8 *) pos) == TRUE) {
			nlist.bssid_info.Security = 1;
			nlist.bssid_info.KeyScope = 0;
			//break;
		}
		//Now process to the next element pointer.
		pos += (2 + *((UINT8 *) (pos + 1)));
		if ((frame_len - ((pos - (UINT8 *) BssData_p) + 2)) <= 0) {
			break;
		}
	}

	if ((wpa2IE_p = (IEEEtypes_RSN_IE_WPA2_t *) smeParseIeType(RSN_IEWPA2, (UINT8 *) attrib_p, (len - attpib_len))) != NULL) {
		nlist.bssid_info.Security = 1;
		parse_cipher_and_key_mgmt((u8 *) wpa2IE_p, &cipher, &key_mgmt);
	}
	if (nlist.bssid_info.Security && (cipher == 0))
		cipher = WPA_CIPHER_WEP40;
	cipher_akm_to_text(&nlist.cipherType[0], &nlist.encryptType[0], cipher, key_mgmt);

	nlist.BcnInterval = Beacon_p->BcnInterval;
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

	MSAN_neighbor_add(vmacSta_p->dev, &nlist, (UINT8 *) Beacon_p, bcn_len);
	if ((wlpptr->wlpd_p->wlmgr_dcs == TRUE) && (wlpptr->wlpd_p->offchan_scan.offchan_feature_active[OFFCHAN_BY_DCS] == TRUE)) {
		/* Only send nlist event during DCS offchan scan */
		custom_tlv_t *tlv_buf;
		wlmgr_event_t *event_data;

		tlv_buf = (custom_tlv_t *) wl_kzalloc(IW_CUSTOM_MAX, GFP_ATOMIC);
		if (tlv_buf) {
			tlv_buf->tag = EVENT_TAG_WLMGR;
			event_data = (wlmgr_event_t *) tlv_buf->value;
			event_data->id = WLMGR_ID_DCS;
			event_data->cmd = WLMGR_CMD_NLIST;
			memcpy((UINT8 *) event_data->data, &nlist, sizeof(neighbor_list_entrie_t));
			tlv_buf->len = sizeof(wlmgr_event_t) + sizeof(neighbor_list_entrie_t);
			/* Set "force_send" to FALSE so that it does not send nlist event when dev is not IFF_RUNNING */
			wl_send_event(netdev, tlv_buf, FALSE, FALSE);
			wl_kfree(tlv_buf);
		}
	}
}

UINT8 MSAN_get_neighbor_bySSID(struct net_device *netdev, struct IEEEtypes_SsIdElement_t *ssid)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	nb_info_t *nb_info_p = &(wlpptr->wlpd_p->nb_info);
	UINT32 i;

	if (ssid == NULL)
		return 0;

	memset(&nb_info_p->nb_elem[0], 0, sizeof(struct IEEEtypes_Neighbor_Report_Element_t) * NB_LIST_MAX_NUM);
	for (i = 0, nb_info_p->nb_elem_number = 0; i < nb_info_p->nb_number && i < NB_LIST_MAX_NUM; i++) {
		if (!memcmp(ssid->SsId, nb_info_p->nb_list[i].SsId, ssid->Len)) {
			nb_info_p->nb_elem[nb_info_p->nb_elem_number].ElementId = NEIGHBOR_REPORT;
			nb_info_p->nb_elem[nb_info_p->nb_elem_number].Len =	/* No optional subelement for now */
			    sizeof(struct IEEEtypes_Neighbor_Report_Element_t) - 2;
			memcpy(nb_info_p->nb_elem[nb_info_p->nb_elem_number].Bssid, nb_info_p->nb_list[i].bssid, 6);
			nb_info_p->nb_elem[nb_info_p->nb_elem_number].BssidInfo = nb_info_p->nb_list[i].bssid_info;
			nb_info_p->nb_elem[nb_info_p->nb_elem_number].RegulatoryClass = nb_info_p->nb_list[i].reg_class;
			nb_info_p->nb_elem[nb_info_p->nb_elem_number].Channel = nb_info_p->nb_list[i].chan;
			nb_info_p->nb_elem[nb_info_p->nb_elem_number].PhyType = nb_info_p->nb_list[i].phy_type;
			nb_info_p->nb_elem_number++;
		}
	}

	return nb_info_p->nb_elem_number;
}

UINT8 MSAN_get_neighbor_byDefault(struct net_device * netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	nb_info_t *nb_info_p = &(wlpptr->wlpd_p->nb_info);
	UINT32 i;

	memset(&nb_info_p->nb_elem[0], 0, sizeof(struct IEEEtypes_Neighbor_Report_Element_t) * NB_LIST_MAX_NUM);
	for (i = 0; i < nb_info_p->nb_number && i < NB_LIST_MAX_NUM; i++) {
		nb_info_p->nb_elem[i].ElementId = NEIGHBOR_REPORT;
		nb_info_p->nb_elem[i].Len =	/* No optional subelement for now */
		    sizeof(struct IEEEtypes_Neighbor_Report_Element_t) - 2;
		memcpy(nb_info_p->nb_elem[i].Bssid, nb_info_p->nb_list[i].bssid, 6);
		nb_info_p->nb_elem[i].BssidInfo = nb_info_p->nb_list[i].bssid_info;
		nb_info_p->nb_elem[i].RegulatoryClass = nb_info_p->nb_list[i].reg_class;
		nb_info_p->nb_elem[i].Channel = nb_info_p->nb_list[i].chan;
		nb_info_p->nb_elem[i].PhyType = nb_info_p->nb_list[i].phy_type;
	}
	nb_info_p->nb_elem_number = i;

	return nb_info_p->nb_elem_number;
}

UINT8 MSAN_get_neighbor_byAddr(struct net_device * netdev, IEEEtypes_MacAddr_t * target_addr)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	nb_info_t *nb_info_p = &(wlpptr->wlpd_p->nb_info);
	UINT32 i;

	if (target_addr == NULL)
		return 0;

	for (i = 0, nb_info_p->nb_elem_number = 0; i < nb_info_p->nb_number && i < NB_LIST_MAX_NUM; i++) {
		if (!memcmp(target_addr, nb_info_p->nb_list[i].bssid, IEEEtypes_ADDRESS_SIZE)) {
			nb_info_p->nb_elem[nb_info_p->nb_elem_number].ElementId = NEIGHBOR_REPORT;
			nb_info_p->nb_elem[nb_info_p->nb_elem_number].Len =	/* No optional subelement for now */
			    sizeof(struct IEEEtypes_Neighbor_Report_Element_t) - 2;
			memcpy(nb_info_p->nb_elem[nb_info_p->nb_elem_number].Bssid, nb_info_p->nb_list[i].bssid, 6);
			nb_info_p->nb_elem[nb_info_p->nb_elem_number].BssidInfo = nb_info_p->nb_list[i].bssid_info;
			nb_info_p->nb_elem[nb_info_p->nb_elem_number].RegulatoryClass = nb_info_p->nb_list[i].reg_class;
			nb_info_p->nb_elem[nb_info_p->nb_elem_number].Channel = nb_info_p->nb_list[i].chan;
			nb_info_p->nb_elem[nb_info_p->nb_elem_number].PhyType = nb_info_p->nb_list[i].phy_type;
			nb_info_p->nb_elem_number++;
		}
	}

	return nb_info_p->nb_elem_number;
}

void MSAN_clean_neighbor_list(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	nb_info_t *nb_info_p = &(wlpptr->wlpd_p->nb_info);

	nb_info_p->nb_elem_number = 0;
	memset(&nb_info_p->nb_elem[0], 0, sizeof(struct IEEEtypes_Neighbor_Report_Element_t) * NB_LIST_MAX_NUM);
}

void MSAN_clean_nb_list_All(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	nb_info_t *nb_info_p = &(wlpptr->wlpd_p->nb_info);
	UINT32 i;

	nb_info_p->nb_elem_number = 0;
	memset(&nb_info_p->nb_elem[0], 0, sizeof(struct IEEEtypes_Neighbor_Report_Element_t) * NB_LIST_MAX_NUM);

	nb_info_p->nb_number = 0;
	for (i = 0; i < NB_LIST_MAX_NUM; i++) {
		if (nb_info_p->nb_list[i].bcn_buf)
			wl_kfree(nb_info_p->nb_list[i].bcn_buf);
	}
	memset(&nb_info_p->nb_list[0], 0, sizeof(struct neighbor_list_entrie_t) * NB_LIST_MAX_NUM);
}

void MSAN_update_neighbor_list(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	offchan_scan_t *offchan_scan_p = &(wlpptr->wlpd_p->offchan_scan);
	nb_info_t *nb_info_p = &(wlpptr->wlpd_p->nb_info);
	MIB_802DOT11 *mib = NULL;
#ifdef CFG80211
	UINT32 i;
#endif				/* CFG80211 */
	UINT32 nlist_idx;
	SINT32 curr_time = 0, offset_time;

	if (wlpptr->master)
		wlpptr = NETDEV_PRIV_P(struct wlprivate, wlpptr->master);

	mib = wlpptr->vmacSta_p->Mib802dot11;
	curr_time = ktime_to_timespec(ktime_get_real()).tv_sec;

	if (offchan_scan_p->next_offch.ch_idx >= offchan_scan_p->next_offch.ch_num) {
		/* delete some APs that exceed the life span */
		if (nb_info_p->nb_number > 0) {
			for (nlist_idx = 0; nlist_idx < nb_info_p->nb_number && nlist_idx < NB_LIST_MAX_NUM; nlist_idx++) {
				offset_time = nb_info_p->nb_list[nlist_idx].time_stamp + NBREPORT_LIST_LIFESPAN;
				if (offset_time <= curr_time) {
					if ((nb_info_p->nb_list[nlist_idx].time_stamp < offset_time)
					    || (nb_info_p->nb_list[nlist_idx].time_stamp > curr_time)) {
						neighbor_report_delete(netdev, nlist_idx);
						nlist_idx = (nlist_idx > 0) ? (nlist_idx - 1) : 0;
					}
				} else {
					if ((nb_info_p->nb_list[nlist_idx].time_stamp < offset_time)
					    && (nb_info_p->nb_list[nlist_idx].time_stamp > curr_time)) {
						neighbor_report_delete(netdev, nlist_idx);
						nlist_idx = (nlist_idx > 0) ? (nlist_idx - 1) : 0;
					}
				}
#ifdef CFG80211
				for (i = 0; i <= bss_num; i++) {
					if (wlpptr->vdev[i] && wlpptr->vdev[i]->flags & IFF_RUNNING) {
						struct net_device *vdev = wlpptr->vdev[i];
						struct wlprivate *nr_priv = NETDEV_PRIV_P(struct wlprivate, vdev);
						vmacApInfo_t *nr_vap_p = nr_priv->vmacSta_p;

						if (!memcmp(nr_vap_p->macSsId.SsId, nb_info_p->nb_list[nlist_idx].SsId, nr_vap_p->macSsId.Len))
							mwl_send_vendor_neighbor_event(vdev, (void *)&nb_info_p->nb_list[nlist_idx],
										       sizeof(neighbor_list_entrie_t), 1);
					}
				}
#endif				/* CFG80211 */
			}
		} else
			MSAN_clean_nb_list_All(netdev);
	}
}

void MSAN_neighbor_dump_list(struct net_device *netdev, UINT8 * ret_str, UINT8 * param1, UINT8 * param2)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	nb_info_t *nb_info_p = &(wlpptr->wlpd_p->nb_info);
	UINT32 ret_len;
	SINT32 i, nb_idx = 0;
	UINT8 msg_status = 0xFF;
	UINT8 btm_rssi[128];
	SINT32 curr_time = 0, offset_time;

	ret_len = 0;
	if (ret_str)
		msg_status = 0;
	else if (param1 == NULL)
		msg_status = 0xFF;
	else if (!strcmp(param1, "help")) {
		printk("Usage: getnlist [-detail] [-detail <index>] [-ssid <SSID>]\n");
		return;
	} else if (!strcmp(param1, "-detail")) {
		msg_status = 1;
		nb_idx = -1;
		if (param2[0] != 0)
			nb_idx = simple_strtol(param2, NULL, 10);
	} else if (!strcmp(param1, "-ssid"))
		msg_status = 2;

	curr_time = ktime_to_timespec(ktime_get_real()).tv_sec;
	offset_time = 0;

	for (i = 0; i < nb_info_p->nb_number && i < NB_LIST_MAX_NUM; i++) {
		neighbor_list_entrie_t *nlist = &nb_info_p->nb_list[i];

		if (msg_status == 0) {
			if (memcmp(mib->StationConfig->DesiredSsId, nlist->SsId,
				   strlen(mib->StationConfig->DesiredSsId) <
				   IEEEtypes_SSID_SIZE ? strlen(mib->StationConfig->DesiredSsId) : IEEEtypes_SSID_SIZE))
				continue;
		} else if (msg_status == 1 && (0 <= nb_idx && nb_idx < nb_info_p->nb_number)) {
			if (i != nb_idx)
				continue;
		} else if (msg_status == 2) {
			if (memcmp(param2, nlist->SsId, strlen(param2)))
				continue;
		}
		offset_time = curr_time - nlist->time_stamp;
		if (offset_time > NBREPORT_LIST_LIFESPAN || offset_time < 0)
			continue;

		if (msg_status == 0) {
			memset(btm_rssi, 0, 128);
			sprintf(btm_rssi, "bssid=%02x:%02x:%02x:%02x:%02x:%02x rssi=%d \n",
				nlist->bssid[0], nlist->bssid[1], nlist->bssid[2], nlist->bssid[3], nlist->bssid[4], nlist->bssid[5], nlist->rssi);
			strcat(ret_str, btm_rssi);
		} else {
			printk("index:%3d  bssid=%02x:%02x:%02x:%02x:%02x:%02x", i,
			       nlist->bssid[0], nlist->bssid[1], nlist->bssid[2], nlist->bssid[3], nlist->bssid[4], nlist->bssid[5]);
			printk("  chan=%3d", nlist->chan);
			printk("  width=");
			if (nlist->width == NR_CHAN_WIDTH_160)
				printk("160MHz");
			else if (nlist->width == NR_CHAN_WIDTH_80)
				printk("80MHz ");
			else if (nlist->width == NR_CHAN_WIDTH_40) {
				if (nlist->bw_2g_40_above == 0x1)
					printk("40MHz+");
				else if (nlist->bw_2g_40_above == 0x2)
					printk("40MHz-");
				else
					printk("40MHz ");
			} else
				printk("20MHz ");

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
				printk("bssid_info.ApReachability=%d\n", nlist->bssid_info.ApReachability);
				printk("bssid_info.Security=%d\n", nlist->bssid_info.Security);
				printk("bssid_info.KeyScope=%d\n", nlist->bssid_info.KeyScope);
				printk("bssid_info.Capa_SpectrumMgmt=%d\n", nlist->bssid_info.Capa_SpectrumMgmt);
				printk("bssid_info.Capa_QoS=%d\n", nlist->bssid_info.Capa_QoS);
				printk("bssid_info.Capa_APSD=%d\n", nlist->bssid_info.Capa_APSD);
				printk("bssid_info.Capa_Rrm=%d\n", nlist->bssid_info.Capa_Rrm);
				printk("bssid_info.Capa_DBlckAck=%d\n", nlist->bssid_info.Capa_DBlckAck);
				printk("bssid_info.Capa_IBlckAck=%d\n", nlist->bssid_info.Capa_IBlckAck);
				printk("bssid_info.MobilityDomain=%d\n", nlist->bssid_info.MobilityDomain);
				printk("bssid_info.HT=%d\n", nlist->bssid_info.HT);
				printk("bssid_info.VHT=%d\n", nlist->bssid_info.VHT);
				printk("bssid_info.HE=%d\n", nlist->bssid_info.HE);
				printk("bssid_info.Reserved=%d\n", nlist->bssid_info.Reserved);
				printk("reg_class=%d\n", nlist->reg_class);
				printk("phy_type=%d\n", nlist->phy_type);
				printk("encrypt=%s%s\n", nlist->encryptType, nlist->cipherType);
				printk("BcnInterval=%u\n", le16_to_cpu(nlist->BcnInterval));
				printk("type=%s\n", nlist->apType);
				printk("===================================================\n");
			}
		}
	}
	return;
}

void MSAN_rrm_ie(struct net_device *netdev, int enable)
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

UINT32 MSAN_get_channel_util(vmacApInfo_t * vmacSta_p)
{
	vmacApInfo_t *vmactmp_p = vmacSta_p;

	if (vmacSta_p->master != NULL) {
		vmactmp_p = vmacSta_p->master;
	}

	return (UINT32) vmactmp_p->rrm_cload.ch_load;
}

#ifdef AUTOCHANNEL
static const UINT8 nb_2G_ChList[13] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13 };

static void nb_find_2nd_ch(UINT8 ch_list_num, acs_data_t * acs_db)
{
	UINT8 i, j, k;

	for (i = 0; i < ch_list_num; i++) {
		if (acs_db[i].bw == NR_CHAN_WIDTH_160) {
			if (acs_db[i].channel > 15) {
				for (j = 0; j < domainGetSizeOfGrpChList160Mhz() / sizeof(GRP_CHANNEL_LIST_160Mhz); j++) {
					if (channel_exists(acs_db[i].channel, GrpChList160Mhz[j].channelEntry, 8)) {
						for (k = 0; k < ch_list_num; k++) {
							if (i == k) {
								continue;
							}
							if (channel_exists(acs_db[k].channel, GrpChList160Mhz[j].channelEntry, 8)) {
								acs_db[k].is_2nd_ch = TRUE;
							}
						}
						break;
					}
				}
			}
		} else if (acs_db[i].bw == NR_CHAN_WIDTH_80) {
			if (acs_db[i].channel > 15) {
				for (j = 0; j < domainGetSizeOfGrpChList80Mhz() / sizeof(GRP_CHANNEL_LIST_80Mhz); j++) {
					if (channel_exists(acs_db[i].channel, GrpChList80Mhz[j].channelEntry, 4)) {
						for (k = 0; k < ch_list_num; k++) {
							if (i == k) {
								continue;
							}
							if (channel_exists(acs_db[k].channel, GrpChList80Mhz[j].channelEntry, 4)) {
								acs_db[k].is_2nd_ch = TRUE;
							}
						}
						break;
					}
				}
			}
		} else if (acs_db[i].bw == NR_CHAN_WIDTH_40) {
			if (acs_db[i].channel > 15) {
				for (j = 0; j < domainGetSizeOfGrpChList40Mhz() / sizeof(GRP_CHANNEL_LIST_40Mhz); j++) {
					if (channel_exists(acs_db[i].channel, GrpChList40Mhz[j].channelEntry, 2)) {
						for (k = 0; k < ch_list_num; k++) {
							if (i == k) {
								continue;
							}
							if (channel_exists(acs_db[k].channel, GrpChList40Mhz[j].channelEntry, 2)) {
								acs_db[k].is_2nd_ch = TRUE;
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
						printk("%s acs_db[%d].channel:%d bw:%d 40mhz:%d failed!!\n", __func__, i, acs_db[i].channel,
						       acs_db[i].bw, acs_db[i].bw_2g_40_above);
						above_2nd_ch = 0;
					}
				}
				if (acs_db[i].bw_2g_40_above & 0x2) {
					below_2nd_ch = (SINT8) acs_db[i].channel - 4;
					if (below_2nd_ch <= 0) {
						printk("%s acs_db[%d].channel:%d bw:%d 40mhz:%d failed!!\n", __func__, i, acs_db[i].channel,
						       acs_db[i].bw, acs_db[i].bw_2g_40_above);
						below_2nd_ch = 0;
					}
				}
				for (k = 0; k < ch_list_num; k++) {
					if (acs_db[k].is_2nd_ch) {
						continue;
					}
					if (above_2nd_ch == acs_db[k].channel) {
						acs_db[k].is_2nd_ch = TRUE;
					} else if (below_2nd_ch == acs_db[k].channel) {
						acs_db[k].is_2nd_ch = TRUE;
					}
				}
			}
		}
	}
}

static void nb_check_ht40_avail(struct net_device *netdev, UINT8 ch_list_num, acs_data_t * acs_db)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	nb_info_t *nb_info_p = &(wlpptr->wlpd_p->nb_info);
	SINT32 i, j;
	/* i: ch_list_num, j: nb_number */

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

		for (j = 0; j < nb_info_p->nb_number; j++) {
			neighbor_list_entrie_t *nlist = &nb_info_p->nb_list[j];

			/* 2.4GHz only */
			if (nlist->chan > 14)
				continue;

			/* BW20MHz same channel */
			if (nlist->bw_2g_40_above == 0 && nlist->chan == acs_db[i].channel)
				continue;

			/*
			 * BW40MHz same channel && same ext_channel
			 * NOTE: W9064: 1-4ch=above, 5-13ch=below
			 */
			if (nlist->chan == acs_db[i].channel &&
			    ((nlist->bw_2g_40_above == 0x01 && nlist->chan <= 4) || (nlist->bw_2g_40_above == 0x02 && nlist->chan >= 5)))
				continue;

			if (nlist->chan >= affect_ch_low && nlist->chan <= affect_ch_high) {
				acs_db[i].ht40avail = 0;
			}
		}
	}
}

void MSAN_get_ACS_db(vmacApInfo_t * vmacSta_p, UINT8 ch_list_num, UINT8 channel, UINT8 NF4rrm)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev);
	nb_info_t *nb_info_p = &(wlpptr->wlpd_p->nb_info);
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
		for (i = 0; i < nb_info_p->nb_number; i++) {
			neighbor_list_entrie_t *nlist = &nb_info_p->nb_list[i];

			offset_time = curr_time - nlist->time_stamp;

			/* if the bss is 60s ago, ignore it */
			if (offset_time > 60 || offset_time < 0)
				continue;

			for (j = 0; j < ch_list_num; j++) {
				if (nlist->chan == acs_db[j].channel) {
					acs_db[j].bss_num++;
					if (NF4rrm)
						acs_db[j].noise_floor += nlist->nf;

					cal_nlist_rssi = (nlist->rssi < -100) ? -(rssi_threshold) : nlist->rssi;
					if (acs_db[j].min_rssi == 0) {
						acs_db[j].min_rssi = nlist->rssi;
						acs_db[j].raw_min_rssi = cal_nlist_rssi;
					}
					acs_db[j].raw_min_rssi = acs_db[j].raw_min_rssi < cal_nlist_rssi ? acs_db[j].raw_min_rssi : cal_nlist_rssi;
					acs_db[j].min_rssi = acs_db[j].min_rssi < nlist->rssi ? acs_db[j].min_rssi : nlist->rssi;

					cal_nlist_rssi = (nlist->rssi > 100) ? -35 : nlist->rssi;
					if (acs_db[j].max_rssi == 0) {
						acs_db[j].max_rssi = nlist->rssi;
						acs_db[j].raw_max_rssi = cal_nlist_rssi;
					}
					acs_db[j].raw_max_rssi = acs_db[j].raw_max_rssi > cal_nlist_rssi ? acs_db[j].raw_max_rssi : cal_nlist_rssi;
					acs_db[j].max_rssi = acs_db[j].max_rssi > nlist->rssi ? acs_db[j].max_rssi : nlist->rssi;

					acs_db[j].rssi_ls += (rssi_threshold - abs(cal_nlist_rssi));
					if (acs_db[j].rssi_ls > rssi_threshold)
						acs_db[j].rssi_ls = rssi_threshold;

					/* set bw */
					acs_db[j].bw = acs_db[j].bw > nlist->width ? acs_db[j].bw : nlist->width;
					acs_db[j].bw_2g_40_above |= nlist->bw_2g_40_above;
					printk
					    ("[%d], acs_db.channel = %d, acs_db.bss_num = %d, acs_db.min_rssi = %d, acs_db.max_rssi = %d, nlist.rssi=%d\n",
					     j, acs_db[j].channel, acs_db[j].bss_num, acs_db[j].raw_min_rssi, acs_db[j].raw_max_rssi, nlist->rssi);
					break;
				}
			}
		}

		/* caculate avg nf & min/max rssi */
		for (j = 0; j < ch_list_num; j++) {
			if (NF4rrm)
				acs_db[j].noise_floor = (acs_db[j].noise_floor / (acs_db[j].bss_num + 1));
			if (acs_db[j].bss_num > 0) {
				acs_db[j].min_rssi = acs_db[j].min_rssi - acs_db[j].noise_floor;
				acs_db[j].min_rssi = acs_db[j].min_rssi >= 100 ? 100 : acs_db[j].min_rssi;
				acs_db[j].min_rssi = acs_db[j].min_rssi <= 0 ? 1 : acs_db[j].min_rssi;
				acs_db[j].max_rssi = acs_db[j].max_rssi - acs_db[j].noise_floor;
				acs_db[j].max_rssi = acs_db[j].max_rssi >= 100 ? 100 : acs_db[j].max_rssi;
				acs_db[j].max_rssi = acs_db[j].max_rssi <= 0 ? 1 : acs_db[j].max_rssi;

				/* keep the 2 channel index at which there are more bss */
				if (vmacSta_p->bss_channel_idx[0] == 0xFF)
					vmacSta_p->bss_channel_idx[0] = j;
				else if (acs_db[j].bss_num > acs_db[vmacSta_p->bss_channel_idx[0]].bss_num) {
					vmacSta_p->bss_channel_idx[1] = vmacSta_p->bss_channel_idx[0];
					vmacSta_p->bss_channel_idx[0] = j;
				} else if ((vmacSta_p->bss_channel_idx[1] == 0xFF) ||
					   (acs_db[j].bss_num > acs_db[vmacSta_p->bss_channel_idx[1]].bss_num))
					vmacSta_p->bss_channel_idx[1] = j;
			}
		}
		printk("worst channel (bss): ch0_idx=%u, ch1_idx=%u\n", vmacSta_p->bss_channel_idx[0], vmacSta_p->bss_channel_idx[1]);

		/* find 2nd-CH */
		nb_find_2nd_ch(ch_list_num, acs_db);
		/* Calculate HT40 availability for each channel */
		nb_check_ht40_avail(vmacSta_p->dev, ch_list_num, acs_db);
	} else {
		/* Update specific channel in ACS database */
		for (j = 0; j < ch_list_num; j++) {
			if (channel == acs_db[j].channel)
				break;
		}
		if (j == ch_list_num)
			return;

		acs_db[j].bss_num = 0;
		acs_db[j].min_rssi = 0;
		acs_db[j].max_rssi = 0;
		acs_db[j].bw = 0;
		acs_db[j].bw_2g_40_above = 0;
		acs_db[j].ht40avail = 1;
		for (i = 0; i < nb_info_p->nb_number; i++) {
			neighbor_list_entrie_t *nlist = &nb_info_p->nb_list[i];

			offset_time = curr_time - nlist->time_stamp;
			/* if the bss is interval*2 ago, ignore it */
			if (offset_time > vmacSta_p->acs_cload.ignore_time || offset_time < 0)
				continue;

			if (channel == nlist->chan) {
				acs_db[j].bss_num++;
				acs_db[j].noise_floor += nlist->nf;

				cal_nlist_rssi = (nlist->rssi < -100) ? -(rssi_threshold) : nlist->rssi;
				if (acs_db[j].min_rssi == 0) {
					acs_db[j].min_rssi = nlist->rssi;
					acs_db[j].raw_min_rssi = cal_nlist_rssi;
				}
				acs_db[j].raw_min_rssi = acs_db[j].raw_min_rssi < cal_nlist_rssi ? acs_db[j].raw_min_rssi : cal_nlist_rssi;
				acs_db[j].min_rssi = acs_db[j].min_rssi < nlist->rssi ? acs_db[j].min_rssi : nlist->rssi;

				cal_nlist_rssi = (nlist->rssi > 100) ? -35 : nlist->rssi;
				if (acs_db[j].max_rssi == 0) {
					acs_db[j].max_rssi = nlist->rssi;
					acs_db[j].raw_max_rssi = cal_nlist_rssi;
				}
				acs_db[j].raw_max_rssi = acs_db[j].raw_max_rssi > cal_nlist_rssi ? acs_db[j].raw_max_rssi : cal_nlist_rssi;
				acs_db[j].max_rssi = acs_db[j].max_rssi > nlist->rssi ? acs_db[j].max_rssi : nlist->rssi;

				acs_db[j].rssi_ls += (rssi_threshold - abs(cal_nlist_rssi));
				if (acs_db[j].rssi_ls > rssi_threshold)
					acs_db[j].rssi_ls = rssi_threshold;

				/* set bw */
				acs_db[j].bw = acs_db[j].bw > nlist->width ? acs_db[j].bw : nlist->width;
				acs_db[j].bw_2g_40_above |= nlist->bw_2g_40_above;
			}
		}
		/* caculate avg nf & min/max rssi */
		acs_db[j].noise_floor = (acs_db[j].noise_floor / (acs_db[j].bss_num + 1));
		if (acs_db[j].bss_num > 0) {
			acs_db[j].min_rssi = acs_db[j].min_rssi - acs_db[j].noise_floor;
			acs_db[j].min_rssi = acs_db[j].min_rssi >= 100 ? 100 : acs_db[j].min_rssi;
			acs_db[j].min_rssi = acs_db[j].min_rssi <= 0 ? 1 : acs_db[j].min_rssi;
			acs_db[j].max_rssi = acs_db[j].max_rssi - acs_db[j].noise_floor;
			acs_db[j].max_rssi = acs_db[j].max_rssi >= 100 ? 100 : acs_db[j].max_rssi;
			acs_db[j].max_rssi = acs_db[j].max_rssi <= 0 ? 1 : acs_db[j].max_rssi;
		}
		/* find 2nd-CH */
		nb_find_2nd_ch(ch_list_num, acs_db);
		/* Calculate HT40 availability for each channel */
		nb_check_ht40_avail(vmacSta_p->dev, ch_list_num, acs_db);
	}
}
#endif				/* AUTOCHANNEL */
#endif				//IEEE80211K

void OffchannelScanDisable(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);

	/* If offchan scan still not init, ignore it */
	if (wlpptr->wlpd_p->offchan_scan.init_flag == FALSE)
		return;

	wlpptr->wlpd_p->offchan_scan.init_flag = FALSE;
	wlpptr->wlpd_p->offchan_scan.status_abnormal = FALSE;
	TimerDisarm(&wlpptr->wlpd_p->offchan_scan.timer);
	MSAN_rrm_ie(netdev, 0);
}

void OffchannelScanEnable(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
	offchan_node_t node;

	/* Init sysfs_query_nlist_idx */
	wlpptr->wlpd_p->nb_info.sysfs_query_nlist_idx = -1;

	/* Already init offchan scan, don't do any offchan scan */
	if (wlpptr->wlpd_p->offchan_scan.init_flag == TRUE)
		return;

	wlpptr->wlpd_p->offchan_scan.init_flag = TRUE;
	wlpptr->wlpd_p->offchan_scan.status_abnormal = FALSE;
	memset(&node, 0, sizeof(offchan_node_t));
	node.trigger_time = RRM_NO_STA_NO_NEIGHBOR_TRIGGER_TIME;
	node.interval_time = RRM_NO_STA_NO_NEIGHBOR_INTERVAL_TIME;
	node.dwell_time = RRM_NO_STA_NO_NEIGHBOR_DWELL_TIME;
	node.repeat = TRUE;	/* For rrm, it always turn-on repeat */
	if (*(mib->mib_rrm)) {
		MSAN_rrm_ie(netdev, 1);
		node.active = TRUE;
	} else {
		/* If rrm = 0, set active = FALSE and delete offchannel list timer */
		MSAN_rrm_ie(netdev, 0);
		node.active = FALSE;
		TimerDisarm(&wlpptr->wlpd_p->offchan_scan.timer);
	}
	wlpptr->wlpd_p->offchan_scan.status = OFFCHAN_IDLE;
	OffchannelScanSet(netdev, &node, TRUE);	/* this is rrm offchannel list */
}

#ifdef MULTI_AP_SUPPORT
int MSAN_unassocsta_offchan_init(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct unassociated_sta_link_metrics_query *query = NULL;
	nb_info_t *nb_info_p = &(wlpptr->wlpd_p->nb_info);
	int i;

	if (!wlpptr)
		return -1;

	query = (struct unassociated_sta_link_metrics_query *)wlpptr->wlpd_p->unassocSTA.unassocsta_query;
	if (!query)
		return -1;

	memset(nb_info_p->unassocsta_offchan_channel_list, 0, UNASSOC_METRICS_CHANNEL_MAX);
	nb_info_p->unassocsta_offchan_channel_number = query->num_of_channel;
	for (i = 0; i < nb_info_p->unassocsta_offchan_channel_number; i++)
		nb_info_p->unassocsta_offchan_channel_list[i] = query->unassociated_sta_info[i].channel;

	return 0;
}

void MSAN_unassocsta_offchan_scan(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct unassociated_sta_link_metrics_query *query = NULL;
	nb_info_t *nb_info_p = &(wlpptr->wlpd_p->nb_info);
	DOT11_OFFCHAN_REQ_t offchan;
	UINT8 offChanIdx;
	int ret = 0;

	if (!wlpptr)
		return;

	query = (struct unassociated_sta_link_metrics_query *)wlpptr->wlpd_p->unassocSTA.unassocsta_query;
	if (!query)
		return;

	offChanIdx = wlpptr->wlpd_p->unassocSTA.offChanIdx;
	if (offChanIdx >= UNASSOC_METRICS_CHANNEL_MAX)
		return;

	if (IsACSOnoing(netdev)) {
		printk("%s offchan request failed as acs is ongoing\n", __FUNCTION__);
		return;
	}

	nb_info_p->unassocsta_offchan_channel = (UINT32) nb_info_p->unassocsta_offchan_channel_list[offChanIdx];
	memset((UINT8 *) & offchan, 0x0, sizeof(DOT11_OFFCHAN_REQ_t));
	offchan.channel = nb_info_p->unassocsta_offchan_channel;
	offchan.id = OFFCHAN_GET_ID_FROM_FEATURE(OFFCHAN_BY_UNASSOCSTA, nb_info_p->unassocsta_offchan_id++);
	offchan.dwell_time = *(wlpptr->vmacSta_p->Mib802dot11->mib_unassocsta_track_time);

	*(wlpptr->vmacSta_p->Mib802dot11->mib_unassocsta_track_enabled) = 1;

	ret = wlFwNewDP_queue_OffChan_req(netdev, &offchan);
	if (ret != 0) {
		printk("%s offchan request failed %d\n", __FUNCTION__, ret);
		return;
	}
}

extern struct unassocsta_track_info *unassocsta_track_get(struct wlprivate *wlpptr, const u8 * addr, u8 channel);
extern void unassocsta_track_add(struct wlprivate *wlpptr, const u8 * addr, u8 channel, u32 rssi);
void MSAN_unassocsta_send_event(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct unassociated_sta_link_metrics_query *query = NULL;
	struct unassociated_sta_link_metrics_resp *resp = NULL;
	struct unassocsta_track_info *info = NULL;
	UINT8 i, j, reult_num_of_sta = 0;
	UINT8 num_of_channel = 0, num_of_sta = 0, channel = 0;

	query = (struct unassociated_sta_link_metrics_query *)wlpptr->wlpd_p->unassocSTA.unassocsta_query;
	if (!query)
		return;

	resp = wl_kzalloc(UNASSOC_RESP_SIZE, GFP_ATOMIC);
	if (!resp)
		return;

	num_of_channel = (query->num_of_channel < UNASSOC_METRICS_CHANNEL_MAX) ? query->num_of_channel : UNASSOC_METRICS_CHANNEL_MAX;
	for (i = 0; i < num_of_channel; i++) {
		channel = query->unassociated_sta_info[i].channel;
		num_of_sta = (query->unassociated_sta_info[i].num_of_sta < UNASSOC_METRICS_STA_MAX) ?
		    query->unassociated_sta_info[i].num_of_sta : UNASSOC_METRICS_STA_MAX;
		for (j = 0; j < num_of_sta; j++) {
			u8 *sta_mac_addr = query->unassociated_sta_info[i].sta_mac_addr_list[j];

			info = unassocsta_track_get(wlpptr, (const u8 *)sta_mac_addr, channel);
			if (!info)
				continue;

			memcpy(resp->unassociated_sta_info[reult_num_of_sta].sta_mac_addr, (IEEEtypes_MacAddr_t *) info->addr, ETH_ALEN);
			resp->unassociated_sta_info[reult_num_of_sta].channel = channel;
			resp->unassociated_sta_info[reult_num_of_sta].time_delta = (jiffies - info->last_seen);
			resp->unassociated_sta_info[reult_num_of_sta].rssi = -(info->rssi);
			reult_num_of_sta++;
		}
	}

	resp->operating_class = query->operating_class;
	resp->num_of_sta = reult_num_of_sta;

	//if (resp->num_of_sta) {
#if defined(SOC_W906X) && defined(CFG80211)
	mwl_send_vendor_unassocsta_event(wlpptr->wlpd_p->unassocSTA.netDev, resp);
#endif				/* SOC_W906X */
	//}

	wl_kfree(resp);
}

void MSAN_unassocsta_offchan_cb(UINT8 * data)
{
	struct net_device *netdev = (struct net_device *)data;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct unassociated_sta_link_metrics_query *query = NULL;
	MIB_802DOT11 *mib = wlpptr->vmacSta_p->Mib802dot11;
	nb_info_t *nb_info_p = &(wlpptr->wlpd_p->nb_info);
	UINT8 offChanIdx;

	if (!wlpptr)
		return;

	*(mib->mib_unassocsta_track_enabled) = 0;
	wlpptr->wlpd_p->unassocSTA.offChanIdx++;

	query = (struct unassociated_sta_link_metrics_query *)wlpptr->wlpd_p->unassocSTA.unassocsta_query;
	if (!query)
		return;

	offChanIdx = wlpptr->wlpd_p->unassocSTA.offChanIdx;
	if (offChanIdx >= UNASSOC_METRICS_CHANNEL_MAX)
		return;

	if (nb_info_p->unassocsta_offchan_channel_number > offChanIdx) {
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

void MSAN_unassocsta_offchan_done(struct net_device *netdev, u8 mode)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);

	if (!wlpptr)
		return;

	if (*(wlpptr->vmacSta_p->Mib802dot11->mib_unassocsta_track_enabled) == 0)
		return;

	/* stop track flag and resetin offchan_cb */
	if (mode == UNASSOCSTA_TRACK_MODE_OFFCHAN)
		*(wlpptr->vmacSta_p->Mib802dot11->mib_unassocsta_track_enabled) = 0;

	TimerDisarm(&wlpptr->wlpd_p->unassocSTA.scanTimer);
	TimerFireInByJiffies(&wlpptr->wlpd_p->unassocSTA.scanTimer, 1,
			     &MSAN_unassocsta_offchan_cb,
			     (UINT8 *) netdev,
			     (mode == UNASSOCSTA_TRACK_MODE_CURRCHAN) ? UNASSOCSTA_CURRCHAN_TRACK_INTERVEL : UNASSOCSTA_OFFCHAN_TRACK_INTERVEL);
}

void MSAN_unassocsta_recv_proc(vmacApInfo_t * vmacSta_p, IEEEtypes_Frame_t * wlanMsg_p, UINT32 rssi)
{
	vmacApInfo_t *vmactmp_p = NULL;
	struct wlprivate *wlpptr = NULL;
	struct unassociated_sta_link_metrics_query *query = NULL;
	nb_info_t *nb_info_p = NULL;

	if (vmacSta_p->master)
		vmactmp_p = vmacSta_p->master;
	else
		vmactmp_p = vmacSta_p;

	wlpptr = NETDEV_PRIV_P(struct wlprivate, vmactmp_p->dev);

	if (!wlpptr)
		return;

	if (*(wlpptr->vmacSta_p->Mib802dot11->mib_unassocsta_track_enabled) == 0)
		return;

	nb_info_p = &(wlpptr->wlpd_p->nb_info);
	query = (struct unassociated_sta_link_metrics_query *)wlpptr->wlpd_p->unassocSTA.unassocsta_query;
	if (!query)
		return;

	if ((*(vmactmp_p->Mib802dot11->mib_unassocsta_track_max_num) > 0))
		unassocsta_track_add(wlpptr, (UINT8 *) wlanMsg_p->Hdr.Addr2, nb_info_p->unassocsta_offchan_channel, rssi);
}
#endif				/* MULTI_AP_SUPPORT */

static BOOLEAN MSAN_optimize_offchan_scan_time(struct net_device *netdev, offchan_node_t * curr_node)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p;
	UINT16 i, sta_cnt, query_cnt;

	if (priv->master) {
		priv = NETDEV_PRIV_P(struct wlprivate, priv->master);
	}
	wlpd_p = priv->wlpd_p;
	query_cnt = 0;
	sta_cnt = 0;
	/* Find the same SSID from neighbor */
	for (i = 0; i <= bss_num; i++) {
		if (priv->vdev[i] && priv->vdev[i]->flags & IFF_RUNNING) {
			struct net_device *vdev = priv->vdev[i];
			struct wlprivate *vpriv = NETDEV_PRIV_P(struct wlprivate, vdev);

			query_cnt += MSAN_get_neighbor_bySSID(netdev, &vpriv->vmacSta_p->macSsId);
			sta_cnt += extStaDb_entries(vpriv->vmacSta_p, 0);
		}
	}

	if (query_cnt > 0) {
		/* There are some neighbors have the same SSID */
		curr_node->trigger_time = RRM_DEFAULT_TRIGGER_TIME;	// 10 mins
		curr_node->interval_time = RRM_DEFAULT_INTERVAL_TIME;	// 3000 ms
		curr_node->dwell_time = RRM_DEFAULT_DWELL_TIME;	// 60 ms
	} else {
		/* No neighbor have the same SSID */
		if (sta_cnt == 0) {
			/* There is no any STA connect with AP */
			curr_node->trigger_time = RRM_NO_STA_NO_NEIGHBOR_TRIGGER_TIME;	// 30 s
			curr_node->interval_time = RRM_NO_STA_NO_NEIGHBOR_INTERVAL_TIME;	// 300 ms
			curr_node->dwell_time = RRM_NO_STA_NO_NEIGHBOR_DWELL_TIME;	// 140 ms
		} else {
			/* Some STAs connect with AP */
			curr_node->trigger_time = RRM_STA_NO_NEIGHBOR_TRIGGER_TIME;	// 60s
			curr_node->interval_time = RRM_STA_NO_NEIGHBOR_INTERVAL_TIME;	// 300 ms
			curr_node->dwell_time = RRM_STA_NO_NEIGHBOR_DWELL_TIME;	// 90 ms
		}
	}
#if 0				/* TBD: If avg pktcnt > threshold, stop offchan scan 30s */
	if (wlpd_p->offchan_avg_pktcnt > RRM_STOP_OFFCHAN_THRESHOLD) {
		return FALSE;
	}
#endif
	return TRUE;
}

void MSAN_update_avg_ptkcnt(struct net_device *netdev)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p;
	UINT32 ptk_cnt;

	wlpd_p = priv->wlpd_p;
	ptk_cnt = wlpd_p->offchan_sum_pktcnt;
	wlpd_p->offchan_sum_pktcnt = wlpd_p->rpkt_type_cnt.data_cnt + wlpd_p->tpkt_type_cnt.data_cnt;
	wlpd_p->offchan_avg_pktcnt = (wlpd_p->offchan_sum_pktcnt - ptk_cnt);
}

static void offchan_scan_timer_cb(UINT8 * data)
{
	struct net_device *netdev = (struct net_device *)data;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);

	/* Put the job "offchan_scan_mgt" into work queue */
	schedule_work(&wlpptr->wlpd_p->offchan_scan_mgt);
}

void offchan_scan_mgt_handler(struct work_struct *work)
{
	struct wlprivate_data *wlpd_p = container_of(work, struct wlprivate_data, offchan_scan_mgt);
	struct wlprivate *wlpptr = wlpd_p->masterwlp;
	struct net_device *netdev = wlpptr->netDev;
	struct offchan_scan_t *offchan_scan_p = &(wlpptr->wlpd_p->offchan_scan);
	MIB_802DOT11 *mib = wlpptr->vmacSta_p->ShadowMib802dot11;
	UINT8 mainChnlList[IEEE_80211_MAX_NUMBER_OF_CHANNELS];
	unsigned long listflags;
	UINT8 currChnlIndex = 0;
	UINT8 i;

	/* find the new offchan */
	switch (offchan_scan_p->status) {
	case OFFCHAN_IDLE:
		{
			offchan_node_t *node_p;
			DOT11_OFFCHAN_REQ_t offchan;
			BOOLEAN is_rrm = FALSE;

			/* If the offchannel list still not init, and status == OFFCHAN_IDLE.
			 * (If status is not OFFCHAN_IDLE, it means there is a offchannel scan still work, and need to process it)
			 */
			if (offchan_scan_p->init_flag == FALSE)
				break;

			TimerDisarm(&offchan_scan_p->timer);
			TimerInit(&offchan_scan_p->timer);

			/* ACS Still working, wait 1s to do it */
			if (wl_util_dev_allow_offchan(netdev) == FALSE) {
				TimerFireInByJiffies(&offchan_scan_p->timer, 1, &offchan_scan_timer_cb, (UINT8 *) netdev,
						     OFFCHANNEL_STOP_TIME_BY_DEV_BUSY);
				return;
			}

			/* find next channel */
			SPIN_LOCK_IRQSAVE(&wlpptr->wlpd_p->locks.offChanScanLock, listflags);
			/* If the user offchannel list is active, proceed, otherwise check the rrm offchannel list */
			if (offchan_scan_p->user_offch.active)
				node_p = &(offchan_scan_p->user_offch);
			else if (offchan_scan_p->rrm_offch.active) {
				node_p = &(offchan_scan_p->rrm_offch);
				is_rrm = TRUE;
			} else {
				/* There is no more offchan need to scan */
				memset(&(offchan_scan_p->next_offch), 0, sizeof(offchan_node_t));
				SPIN_UNLOCK_IRQRESTORE(&wlpptr->wlpd_p->locks.offChanScanLock, listflags);
				break;
			}

			if (node_p->ch_idx >= node_p->ch_num)
				node_p->ch_idx = 0;

			if ((is_rrm == TRUE) && (MSAN_optimize_offchan_scan_time(netdev, node_p) == FALSE)) {
				/* TBD:If avg pkt cnt> threshold, please stop chan scanning for 30 seconds  */
				SPIN_UNLOCK_IRQRESTORE(&wlpptr->wlpd_p->locks.offChanScanLock, listflags);
				TimerFireInByJiffies(&offchan_scan_p->timer, 1, &offchan_scan_timer_cb, (UINT8 *) netdev,
						     OFFCHANNEL_STOP_TIME_BY_TP_THRESHOLD);
				break;
			}
			if (node_p->ch_num == 0) {
				/* offchan list is empty, fill it from domain code */
				memset(mainChnlList, 0, sizeof(UINT8) * IEEE_80211_MAX_NUMBER_OF_CHANNELS);
				memset(node_p->offchanlist, 0, sizeof(UINT8) * IEEE_80211_MAX_NUMBER_OF_CHANNELS);
				/* get range to scan */
				domainGetInfo(mainChnlList);
				currChnlIndex = 0;
				if (Is5GBand(*(mib->mib_ApMode))) {
					for (i = 0; i < IEEEtypes_MAX_CHANNELS_A; i++) {
						if (mainChnlList[i + IEEEtypes_MAX_CHANNELS] > 0) {
							node_p->offchanlist[currChnlIndex] = mainChnlList[i + IEEEtypes_MAX_CHANNELS];
							currChnlIndex++;
						}
					}
				} else {
					for (i = 0; i < IEEEtypes_MAX_CHANNELS; i++) {
						if (mainChnlList[i] > 0) {
							node_p->offchanlist[currChnlIndex] = mainChnlList[i];
							currChnlIndex++;
						}
					}
				}
				node_p->ch_idx = 0;
				node_p->ch_num = currChnlIndex;
			}
			/* get next channel to do */
			memset((UINT8 *) & offchan, 0x0, sizeof(DOT11_OFFCHAN_REQ_t));
			offchan.channel = node_p->offchanlist[node_p->ch_idx];
			offchan.id = OFFCHAN_GET_ID_FROM_FEATURE(OFFCHAN_BY_LIST, offchan_scan_p->id);
			offchan.dwell_time = node_p->dwell_time;
			SPIN_UNLOCK_IRQRESTORE(&wlpptr->wlpd_p->locks.offChanScanLock, listflags);
			if (offchan.channel) {
				/* If Failed, wait OFFCHANNEL_STOP_TIME_BY_FAILED and do gagin */
				if ((wlpptr->offchan_state != OFFCHAN_IDLE) || (wlFwNewDP_queue_OffChan_req(netdev, &offchan) == FAIL)) {
					TimerFireInByJiffies(&offchan_scan_p->timer, 1, &offchan_scan_timer_cb, (UINT8 *) netdev,
							     OFFCHANNEL_STOP_TIME_BY_FAILED);
					break;
				}
			}
			SPIN_LOCK_IRQSAVE(&wlpptr->wlpd_p->locks.offChanScanLock, listflags);
			offchan_scan_p->status = OFFCHAN_STARTED;
			node_p->ch_idx++;
			offchan_scan_p->id++;
			/* Successfully add offchannel to "offChanList", copy the offchannel list info to next_offch, it will be used in "OFFCHAN_DONE" */
			memcpy(&(offchan_scan_p->next_offch), node_p, sizeof(offchan_node_t));
			/* If all channels have done a round and not to repeat, set active to FALSE */
			if ((node_p->repeat == FALSE) && (node_p->ch_idx == node_p->ch_num))
				node_p->active = FALSE;

			SPIN_UNLOCK_IRQRESTORE(&wlpptr->wlpd_p->locks.offChanScanLock, listflags);
		}
		break;
	case OFFCHAN_STARTED:
		break;
	case OFFCHAN_CH_CHANGE:
		/* Set a offchan "dwell + 100ms" timer to avoid offchan_state abnormal */
		offchan_scan_p->status = OFFCHAN_WAIT4_DWELL;
		TimerFireInByJiffies(&offchan_scan_p->timer, 1, &offchan_scan_timer_cb, (UINT8 *) netdev,
				     msecs_to_jiffies(offchan_scan_p->next_offch.dwell_time + 100));
		break;
	case OFFCHAN_WAIT4_DWELL:
		{
			/* After dwell time, offchannel status still not DONE ? */
			u32 fw_offchan_state = 0xFFFFFFFF;
			int ret = 0;

			ret = wlFwOffChannel_dbg(netdev, &fw_offchan_state);
			if ((fw_offchan_state == OFFCHAN_WAIT4_BCNDONE) || (fw_offchan_state == OFFCHAN_WAIT4_TXSTOPPED)
			    || (fw_offchan_state == OFFCHAN_WAIT4_DWELL)) {
				/* offchan_state enters an abnormal state and bcn stuck occurs, do fw reset! */
				wlpptr->wlpd_p->offchan_scan.status_abnormal = TRUE;
			}
		}
		break;
	case OFFCHAN_DONE:
		/* Receive OFFCHAN_DONE event from FW, reset status_abnormal flag */
		wlpptr->wlpd_p->offchan_scan.status_abnormal = FALSE;
		offchan_scan_p->status = OFFCHAN_IDLE;
		TimerDisarm(&offchan_scan_p->timer);
		if ((offchan_scan_p->init_flag == TRUE) &&
		    (offchan_scan_p->next_offch.trigger_time > 0) && (offchan_scan_p->next_offch.interval_time > 0)) {
			TimerInit(&offchan_scan_p->timer);
			if (offchan_scan_p->next_offch.ch_idx >= offchan_scan_p->next_offch.ch_num)
				/* after trigger time ms to scan */
				TimerFireInByJiffies(&offchan_scan_p->timer, 1, &offchan_scan_timer_cb, (UINT8 *) netdev,
						     msecs_to_jiffies(offchan_scan_p->next_offch.trigger_time));
			else
				/* after interval time ms to scan */
				TimerFireInByJiffies(&offchan_scan_p->timer, 1, &offchan_scan_timer_cb, (UINT8 *) netdev,
						     msecs_to_jiffies(offchan_scan_p->next_offch.interval_time));
			break;
		} else
			schedule_work(&wlpptr->wlpd_p->offchan_scan_mgt);
		break;
	default:
		break;
	}
}

void OffchannelScanSet(struct net_device *netdev, offchan_node_t * node, BOOLEAN is_rrm)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	offchan_node_t *node_p;
	unsigned long listflags;
	UINT32 i;
	boolean is_active = FALSE;

	SPIN_LOCK_IRQSAVE(&wlpptr->wlpd_p->locks.offChanScanLock, listflags);
	if (is_rrm) {
		node_p = &(wlpptr->wlpd_p->offchan_scan.rrm_offch);
		/* If reset dev, also reset the channel index of user_offch  */
		wlpptr->wlpd_p->offchan_scan.user_offch.ch_idx = 0;
	} else
		node_p = &(wlpptr->wlpd_p->offchan_scan.user_offch);
	memcpy(node_p, node, sizeof(offchan_node_t));
	for (i = 0; node->offchanlist[i] != 0; i++) ;
	node_p->ch_num = i;
	node_p->ch_idx = 0;
	is_active = wlpptr->wlpd_p->offchan_scan.rrm_offch.active | wlpptr->wlpd_p->offchan_scan.user_offch.active;
	SPIN_UNLOCK_IRQRESTORE(&wlpptr->wlpd_p->locks.offChanScanLock, listflags);
	if (is_active) {
		schedule_work(&wlpptr->wlpd_p->offchan_scan_mgt);
	}
}
