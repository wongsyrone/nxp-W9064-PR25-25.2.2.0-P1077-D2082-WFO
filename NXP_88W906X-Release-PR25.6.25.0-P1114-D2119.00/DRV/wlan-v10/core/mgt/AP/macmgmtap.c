/** @file macmgmtap.c
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2002-2021 NXP
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

/*****************************************************************************
 *
 * Purpose:
 *    This file contains the implementations of the function prototypes given
 *    in the associated header file for the MAC Management Service Task.
 *
 * Public Procedures:
 *    macMgmtAp_Init       Initialzies all MAC Management Service Task and
 *                           related components
 *    macMgmtAp_Start      Starts running the MAC Management Service Task
 *
 * Private Procedures:
 *    MacMgmtApTask            The actual MAC Management Service Task
 *    RegisterRead           Reads a value from a specified register
 *    RegisterWrite          Writes a value to a specified register
 *    SignalStrengthRead     Reads signal strength
 *    StationInfoRead        Reads staton info
 *    StationInfoWrite       Writes station info
 *    StationListRead        Reads the list of known stations
 *    StatisticsRead         Reads accumulated statistics
 *
 * Notes:
 *    None.
 *
 *****************************************************************************/

/*============================================================================= */
/*                               INCLUDE FILES */
/*============================================================================= */
#include "ap8xLnxIntf.h"
#include "wltypes.h"
#include "IEEE_types.h"

#include "mib.h"
#include "ds.h"
#include "keyMgmtCommon.h"
#include "keyMgmt.h"
#include "tkip.h"
#include "StaDb.h"
#include "macmgmtap.h"
#include "macMgmtMlme.h"
#include "timer.h"
#include "wldebug.h"
#include "wlvmac.h"
#include "mlmeApi.h"
#ifdef WTP_SUPPORT
#include <linux/netlink.h>
#include "ap8xLnxIoctl.h"
#endif
#ifdef CFG80211
#include "cfg80211.h"
#endif
#ifdef CCK_DESENSE
#include "wlApi.h"
#endif				/* CCK_DESENSE */

/*============================================================================= */
/*                                DEFINITIONS */
/*============================================================================= */
#define MAC_MGMT_MAIN_EVENT_TRIGGERS macMgmtMain_802_11_MGMT_MSG_RCVD | \
	macMgmtMain_PWR_MODE_CHANGE_RCVD | \
	macMgmtMain_SME_MSG_RCVD | \
	macMgmtMain_TIMER_CALLBACK | \
	macMgmtMain_TIMER_EXPIRED

/*============================================================================= */
/*                             GLOBAL VARIABLES */
/*============================================================================= */
extern UINT8 StopWirelessflag;
#ifdef CCK_DESENSE
extern int wlFwNewDP_RxSOP(struct net_device *netdev, UINT8 params, UINT8 threshold1, UINT8 threshold2);
extern void cck_desense_ctrl(struct net_device *netdev, int state);
#endif				/* CCK_DESENSE */

/* */
/* State that the MAC Management Service Task is in */
/* */

extern void macMgtSyncSrvInit(vmacApInfo_t * vmacSta_p);
extern SINT8 evtSmeCmdMsg(vmacApInfo_t * vmacSta_p, UINT8 *);
extern SINT8 evtDot11MgtMsg(vmacApInfo_t * vmacSta_p, UINT8 *, struct sk_buff *skb, UINT32 rssi);
extern void RxBeacon(vmacApInfo_t * vmacSta_p, void *BssData_p, UINT16 len, UINT32 rssi);

extern int wlMgmtTx(struct sk_buff *skb, struct net_device *netdev);
extern int wlDataTx(struct sk_buff *skb, struct net_device *netdev);
extern int wlDataTxUnencr(struct sk_buff *skb, struct net_device *netdev, extStaDb_StaInfo_t * pStaInfo);
#ifdef BAND_STEERING
extern struct wlprivate_data *global_private_data[MAX_CARDS_SUPPORT];
extern void sta_track_add(struct wlprivate *wlpptr, const u8 * addr);
extern void sta_track_expire(struct wlprivate *wlpptr, int force);
extern struct sta_track_info *sta_track_get(struct wlprivate *wlpptr, const u8 * addr);
extern void sta_auth_add(struct wlprivate *wlpptr, const u8 * addr);
extern void sta_auth_del(struct wlprivate *wlpptr, const u8 * addr);
extern struct sta_auth_info *sta_auth_get(struct wlprivate *wlpptr, const u8 * addr);
#ifdef MBSS
extern vmacApInfo_t *vmacGetMBssByAddr(vmacApInfo_t * vmacSta_p, UINT8 * macAddr_p);
#endif
extern int wlFwGetRadioStatus(struct net_device *netdev, mvl_status_t * radio_status);
#endif				/* BAND_STEERING */
/*============================================================================= */
/*                   PRIVATE PROCEDURES (ANSI Prototypes) */
/*============================================================================= */

/*============================================================================= */
/*                         CODED PUBLIC PROCEDURES */
/*============================================================================= */
#if 0
void dispCSIorNonCompMatrix(UINT8 * pData, UINT8 Nb, UINT8 Nr, UINT8 Nc, UINT8 Ng, UINT8 type);
void dispCompressedCode(UINT8 * pCodeData, UINT8 code, UINT8 numAngles, UINT8 Ng);
#endif

/******************************************************************************
 *
 * Name: macMgmtAp_Init
 *
 * Description:
 *   This routine is called to initialize the the MAC Management Service Task
 *   and related components.
 *
 * Conditions For Use:
 *   None.
 *
 * Arguments:
 *   None.
 *
 * Return Value:
 *   Status indicating success or failure
 *
 * Notes:
 *   None.
 *
 * PDL:
 *   Create 802_11 receive queue and sme msg receive queue
 *   If the queue was successfully initialized Then
 *      Create the MAC Management Task by calling os_TaskCreate()
 *      If creating the MAC Management Task succeeded Then
 *         Set the MAC Management Service State to IDLE
 *         Set the power mode to active
 *         Return OS_SUCCESS
 *      End If
 *   End If
 *
 *   Return OS_FAIL
 * END PDL
 *
 *****************************************************************************/
extern WL_STATUS macMgmtAp_Init(vmacApInfo_t * vmacSta_p, UINT32 maxStns, IEEEtypes_MacAddr_t * stnMacAddr)
{
	/* Init the AP Synchronization State Machine Service */
	macMgtSyncSrvInit(vmacSta_p);
	macMgmtMlme_Init(vmacSta_p, maxStns, stnMacAddr);
#if !defined(CONDOR2) && defined(HARRIER)
	/* Init RF calibration timer */
	TimerInit(&rfCalTimer);
#endif

	return OS_SUCCESS;
}

/******************************************************************************
 *
 * Name: macMgmtQ_SmeWriteNoBlock
 *
 * Description:
 *   This routine is called to write a message to the queue where messages
 *   from the SME task are placed for the MAC Management Service Task. If
 *   writing to the queue cannot immediately occur, then the routine returns
 *   with a failure status (non-blocking).
 *
 * Conditions For Use:
 *   The queue has been initialized by calling macMgmtQ_Init().
 *
 * Arguments:
 *   Arg1 (i  ): SmeCmd_p - a pointer to the message to be placed on
 *               the queue
 *
 * Return Value:
 *   Status indicating success or failure
 *
 * Notes:
 *   None.
 *
 * PDL:
 *   Call os_QueueWriteNoBlock() to write SmeCmd_p to the SME message queue
 *   If the message was successfully placed on the queue Then
 *      Return OS_SUCCESS
 *   Else
 *      Return OS_FAIL
 *   End If
 * END PDL
 *
 *****************************************************************************/
extern WL_STATUS macMgmtQ_SmeWriteNoBlock(vmacApInfo_t * vmacSta_p, macmgmtQ_SmeCmd_t * SmeCmd_p)
{
	//      WL_STATUS status;
	evtSmeCmdMsg(vmacSta_p, (UINT8 *) SmeCmd_p);
	return OS_SUCCESS;
}

#ifdef CLIENT_SUPPORT
WLAN_RX_INFO curRxInfo_g;
#endif				/* CLIENT_SUPPORT */

/*============================================================================= */
/*                         CODED PRIVATE PROCEDURES */
/*============================================================================= */

#ifdef BAND_STEERING
static int vap_check(struct wlprivate *wlpptr)
{
	int i = 0;

	/* check if VAP is enabled. */
	while (i < bss_num) {
		struct net_device *dev;

		if (wlpptr->vdev[i]) {
			dev = wlpptr->vdev[i];

			if ((dev->flags & IFF_RUNNING))
				return 1;
		}
		i++;
	}

	return 0;
}

static struct wlprivate *bandSteeringSelect5GPref(struct wlprivate *wlpptr, int found5GPref1)
{
	UINT8 cardindex = wlpptr->cardindex;
	vmacApInfo_t *vmacSta_p2 = NULL;
	struct wlprivate *wlpptr2 = NULL;
	struct net_device *netdev2 = NULL;
	struct wlprivate *wlpptr_5GPref = NULL;
	UINT32 load = 100;
	int i;
	UINT32 mask = (found5GPref1) ? BAND_STEERING_MODE_5G1 : BAND_STEERING_MODE_5G2;

	/* found prefered 5G AP */
	for (i = 0; i < MAX_CARDS_SUPPORT; i++) {
		if (i == cardindex)
			continue;
		netdev2 = global_private_data[i]->rootdev;
		if (netdev2 == NULL)
			continue;
		wlpptr2 = NETDEV_PRIV_P(struct wlprivate, netdev2);
		if (wlpptr2 == NULL)
			continue;
		vmacSta_p2 = wlpptr2->vmacSta_p;

		/* check if 5G radio prefer is set and is enabled */
		if ((*(vmacSta_p2->Mib802dot11->mib_bandsteer_mode) & mask) &&
		    (Is5GBand(*(vmacSta_p2->Mib802dot11->mib_ApMode))) && (netdev2->flags & IFF_RUNNING)) {
			wlpptr_5GPref = wlpptr2;
			goto skip_checkload;
		}
	}

	/* prefered 5G AP not found, select 5G radio based on loading */
	for (i = 0; i < MAX_CARDS_SUPPORT; i++) {
		mvl_status_t tmp_status;

		if (i == cardindex)
			continue;
		netdev2 = global_private_data[i]->rootdev;
		if (netdev2 == NULL)
			continue;
		wlpptr2 = NETDEV_PRIV_P(struct wlprivate, netdev2);
		if (wlpptr2 == NULL)
			continue;
		vmacSta_p2 = wlpptr2->vmacSta_p;

		/* check if 5G radio is enabled */
		if ((Is5GBand(*(vmacSta_p2->Mib802dot11->mib_ApMode))) && (netdev2->flags & IFF_RUNNING)) {
			/* compare 5G radio loading from FW */
			memset(&tmp_status, 0, sizeof(tmp_status));
			wlFwGetRadioStatus(netdev2, &tmp_status);
			if (tmp_status.total_load < load) {
				load = tmp_status.total_load;
				wlpptr_5GPref = wlpptr2;
			}
		}
	}

 skip_checkload:
	return wlpptr_5GPref;
}

static struct wlprivate *bandSteeringfind2dot4G(struct wlprivate *wlpptr)
{
	UINT8 cardindex = wlpptr->cardindex;
	vmacApInfo_t *vmacSta_p2 = NULL;
	struct wlprivate *wlpptr2 = NULL;
	struct net_device *netdev2 = NULL;
	int i;

	for (i = 0; i < MAX_CARDS_SUPPORT; i++) {
		if (i == cardindex)
			continue;
		netdev2 = global_private_data[i]->rootdev;
		if (netdev2 == NULL)
			continue;
		wlpptr2 = NETDEV_PRIV_P(struct wlprivate, netdev2);
		if (wlpptr2 == NULL)
			continue;
		vmacSta_p2 = wlpptr2->vmacSta_p;

		/* check if 2.4G radio is enabled */
		if ((!(Is5GBand(*(vmacSta_p2->Mib802dot11->mib_ApMode)))) && (netdev2->flags & IFF_RUNNING))
			return wlpptr2;
	}

	return NULL;
}

int bandSteeringCheck(struct wlprivate *wlpptr, IEEEtypes_Frame_t * wlanMsg_p, UINT32 rssi)
{
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	struct wlprivate *wlpptr2 = NULL;
	struct sta_track_info *info = NULL;

	if (*(vmacSta_p->Mib802dot11->mib_bandsteer_handler) != BAND_STEERING_HDL_BY_DRV)
		return 0;

	if (rssi <= *(vmacSta_p->Mib802dot11->mib_bandsteer_rssi_threshold)) {
		if (*(vmacSta_p->Mib802dot11->mib_bandsteer_mode) & BAND_STEERING_MODE_FROM_2_4G_TO_5G) {
			/* frame received by 2.4G AP. */
			if (!(Is5GBand(*(vmacSta_p->Mib802dot11->mib_ApMode)))) {

				/* get the 5G radio for steering */
				wlpptr2 = bandSteeringSelect5GPref(wlpptr, 1);
				if (wlpptr2) {
					/* check if 5G VAP is enabled. */
					if (vap_check(wlpptr2)) {
						/* check if client is capable of 5G operation */
						sta_track_expire(wlpptr2, 0);
						info = sta_track_get(wlpptr2, (UINT8 *) (wlanMsg_p->Hdr.Addr2));
						if (info)
							return 1;
						else
							return 2;
					}
				}
			}
		} else if (*(vmacSta_p->Mib802dot11->mib_bandsteer_mode) & BAND_STEERING_MODE_FROM_5G_TO_2_4G) {

			/* frame received by 5G AP. */
			if ((Is5GBand(*(vmacSta_p->Mib802dot11->mib_ApMode)))) {
				/* get the 2.4G radio for steering */
				wlpptr2 = bandSteeringfind2dot4G(wlpptr);
				if (wlpptr2) {
					/* check if 2.4G VAP is enabled. */
					if (vap_check(wlpptr2)) {
						/* check if client is capable of 2.4G operation */
						sta_track_expire(wlpptr2, 0);
						info = sta_track_get(wlpptr2, (UINT8 *) (wlanMsg_p->Hdr.Addr2));
						if (info)
							return 1;
						else
							return 2;
					}
				}
			}
		} else if (*(vmacSta_p->Mib802dot11->mib_bandsteer_mode) & BAND_STEERING_MODE_FROM_5G1_TO_5G2) {

			/* frame received by 5G AP1. */
			if ((*(vmacSta_p->Mib802dot11->mib_bandsteer_mode) & BAND_STEERING_MODE_5G1) &&
			    (Is5GBand(*(vmacSta_p->Mib802dot11->mib_ApMode)))) {
				/* get the 5G radio for steering */
				wlpptr2 = bandSteeringSelect5GPref(wlpptr, 0);
				if (wlpptr2) {
					/* check if 5G2 VAP is enabled. */
					if (vap_check(wlpptr2))
						return 1;
				}
			}
		}
	}

	return 0;
}

#define BANDSTEER_ALIGNTIMER (50 * HZ) / 1000
void bandSteeringTimerhandler(unsigned long data_p)
{
	struct wlprivate *wlpptr = (struct wlprivate *)data_p;
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	vmacApInfo_t *vmactem_p = NULL;
	struct sk_buff *skb = NULL;
	int i;
	UINT32 timer = (*(vmacSta_p->Mib802dot11->mib_bandsteer_timer_interval) > BANDSTEER_ALIGNTIMER) ?
	    *(vmacSta_p->Mib802dot11->mib_bandsteer_timer_interval) - BANDSTEER_ALIGNTIMER : *(vmacSta_p->Mib802dot11->mib_bandsteer_timer_interval);

	SPIN_LOCK_BH(&wlpptr->wlpd_p->locks.bandSteerListLock);

	if (wlpptr->wlpd_p->bandSteer.queued_skb_num > skb_queue_len(&wlpptr->wlpd_p->bandSteer.skb_queue))
		wlpptr->wlpd_p->bandSteer.queued_skb_num = skb_queue_len(&wlpptr->wlpd_p->bandSteer.skb_queue);

	/* process the skb in queue. */
	for (i = 0; i < wlpptr->wlpd_p->bandSteer.queued_skb_num; i++) {
		IEEEtypes_Frame_t *wlanMsg_p = NULL;

		skb = skb_dequeue(&wlpptr->wlpd_p->bandSteer.skb_queue);
		if (skb == NULL)
			continue;
		wlanMsg_p = (IEEEtypes_Frame_t *) ((UINT8 *) skb->data - 2);

		if (wlanMsg_p->Hdr.FrmCtl.Subtype == IEEE_MSG_PROBE_RQST) {
			if (bandSteeringCheck(wlpptr, wlanMsg_p, *(wlpptr->vmacSta_p->Mib802dot11->mib_bandsteer_rssi_threshold)) != 1)
				macMgmtMlme_ProbeRqst(vmacSta_p, (macmgmtQ_MgmtMsg3_t *) wlanMsg_p);
		} else if (wlanMsg_p->Hdr.FrmCtl.Subtype == IEEE_MSG_AUTHENTICATE) {
			if (bandSteeringCheck(wlpptr, wlanMsg_p, *(wlpptr->vmacSta_p->Mib802dot11->mib_bandsteer_rssi_threshold)) != 1) {
#ifdef MBSS
				vmactem_p = vmacGetMBssByAddr(vmacSta_p, (UINT8 *) (wlanMsg_p->Hdr.Addr3));
#endif
				if (vmactem_p)
					vmacSta_p = vmactem_p;

				sta_auth_del(wlpptr, (UINT8 *) wlanMsg_p->Hdr.Addr2);
				evtDot11MgtMsg(vmacSta_p, (UINT8 *) wlanMsg_p, skb, 60);
			}

		}
		wl_free_skb(skb);
	}
	wlpptr->wlpd_p->bandSteer.queued_skb_num = 0;

	/* rearm the timer if there is skb in queue. */
	if (skb_queue_len(&wlpptr->wlpd_p->bandSteer.skb_queue)) {
		wlpptr->wlpd_p->bandSteer.queued_skb_num = skb_queue_len(&wlpptr->wlpd_p->bandSteer.skb_queue);

		if (wlpptr->wlpd_p->bandSteer.queued_timer.function) {
			vmacSta_p = wlpptr->vmacSta_p;

			wlpptr->wlpd_p->bandSteer.queued_timer.expires = jiffies + timer;
			if (!(timer_pending(&wlpptr->wlpd_p->bandSteer.queued_timer)))
				add_timer(&wlpptr->wlpd_p->bandSteer.queued_timer);
		}
	}
	SPIN_UNLOCK_BH(&wlpptr->wlpd_p->locks.bandSteerListLock);

	return;
}

void bandSteeringQueueSkb(struct wlprivate *wlpptr, struct sk_buff *skb)
{
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	UINT32 timer = (*(vmacSta_p->Mib802dot11->mib_bandsteer_timer_interval) > BANDSTEER_ALIGNTIMER) ?
	    *(vmacSta_p->Mib802dot11->mib_bandsteer_timer_interval) - BANDSTEER_ALIGNTIMER : *(vmacSta_p->Mib802dot11->mib_bandsteer_timer_interval);

	SPIN_LOCK_BH(&wlpptr->wlpd_p->locks.bandSteerListLock);

	skb_queue_tail(&wlpptr->wlpd_p->bandSteer.skb_queue, skb);

	if (!(timer_pending(&wlpptr->wlpd_p->bandSteer.queued_timer))) {
		wlpptr->wlpd_p->bandSteer.queued_skb_num = skb_queue_len(&wlpptr->wlpd_p->bandSteer.skb_queue);

		/* start a timer to process the skb later. */
		wlpptr->wlpd_p->bandSteer.queued_timer.function = &bandSteeringTimerhandler;
		wlpptr->wlpd_p->bandSteer.queued_timer.data = (unsigned long)wlpptr;
		wlpptr->wlpd_p->bandSteer.queued_timer.expires = jiffies + timer;
		add_timer(&wlpptr->wlpd_p->bandSteer.queued_timer);
	}
	SPIN_UNLOCK_BH(&wlpptr->wlpd_p->locks.bandSteerListLock);

	return;
}

void forwardMgmtPacket(vmacApInfo_t * vmacSta_p, macmgmtQ_MgmtMsg3_t * MgmtMsg_p, u_int8_t rssi)
{
#ifdef MRVL_WSC
	static const char *tag;
	static const char *tag1 = "raw-mlme-probe_request";
	static const char *tag2 = "raw-mlme-authenticate";
#ifdef MRVL_WPS2
	/* some WPS STA (e.g. broadcom) send probe request with length > 256 */
#define IW_CUSTOM_MAX2 512
	unsigned char buf[IW_CUSTOM_MAX2] = { 0 };
#else
	unsigned char buf[IW_CUSTOM_MAX] = { 0 };
#endif
	union iwreq_data wreq;

	if (MgmtMsg_p->Hdr.FrmCtl.Subtype == IEEE_MSG_PROBE_RQST)
		tag = tag1;
	else if (MgmtMsg_p->Hdr.FrmCtl.Subtype == IEEE_MSG_AUTHENTICATE)
		tag = tag2;
	else
		return;

	/* Send an event to upper layer with the probe request */
	/* IWEVENT mechanism restricts the size to 256 bytes */
#ifdef MRVL_WPS2
	if ((MgmtMsg_p->Hdr.FrmBodyLen + strlen(tag) + sizeof(UINT16)) <= IW_CUSTOM_MAX2)
#else
	if ((MgmtMsg_p->Hdr.FrmBodyLen + strlen(tag) + sizeof(UINT16)) <= IW_CUSTOM_MAX)
#endif
	{
		snprintf(buf, sizeof(buf), "%s", tag);
		memcpy(&buf[strlen(tag)], (char *)MgmtMsg_p, MgmtMsg_p->Hdr.FrmBodyLen + sizeof(UINT16));
		memset(&wreq, 0, sizeof(wreq));
		wreq.data.flags = rssi;
		wreq.data.length = strlen(tag) + MgmtMsg_p->Hdr.FrmBodyLen + sizeof(UINT16);
		if (vmacSta_p->dev->flags & IFF_RUNNING)
			wireless_send_event(vmacSta_p->dev, IWEVCUSTOM, &wreq, buf);
#ifdef CFG80211
		//mwl_cfg80211_rx_mgmt(vmacSta_p->dev, ((uint8_t *)MgmtMsg_p) + 2, MgmtMsg_p->Hdr.FrmBodyLen, rssi);
		if (MgmtMsg_p->Hdr.FrmCtl.Subtype == IEEE_MSG_PROBE_RQST) {
#ifdef SOC_W906X
			macmgmtQ_MgmtMsg3_t *msgbuf;

			msgbuf = (macmgmtQ_MgmtMsg3_t *) wl_kmalloc(MgmtMsg_p->Hdr.FrmBodyLen + 2, GFP_ATOMIC);
			if (msgbuf) {
				memset((UINT8 *) msgbuf, 0, MgmtMsg_p->Hdr.FrmBodyLen + 2);
				memcpy(&(msgbuf->Hdr), &(MgmtMsg_p->Hdr), sizeof(IEEEtypes_MgmtHdr3_t));
				memcpy(&(msgbuf->Hdr.Rsrvd), &(MgmtMsg_p->Body),
				       MgmtMsg_p->Hdr.FrmBodyLen - sizeof(IEEEtypes_MgmtHdr3_t) + sizeof(UINT16));
				msgbuf->Hdr.FrmBodyLen -= ETH_ALEN;	// Remove Addr4 bssid length here.

				mwl_cfg80211_rx_mgmt(vmacSta_p->dev, &(msgbuf->Hdr.FrmCtl), msgbuf->Hdr.FrmBodyLen, rssi);

				wl_kfree(msgbuf);
			}
#else				/* SOC_W906X */
			mwl_send_vendor_probe_req_event(vmacSta_p->dev, ((uint8_t *) MgmtMsg_p) + 2, MgmtMsg_p->Hdr.FrmBodyLen, rssi);
#endif				/* SOC_W906X */
		} else if (MgmtMsg_p->Hdr.FrmCtl.Subtype == IEEE_MSG_AUTHENTICATE) {
			if (MgmtMsg_p->Body.Auth.AuthAlg == 0x03) {
#ifdef SOC_W906X
				macmgmtQ_MgmtMsg3_t *msgbuf;

				msgbuf = (macmgmtQ_MgmtMsg3_t *) wl_kmalloc(MgmtMsg_p->Hdr.FrmBodyLen + 2, GFP_ATOMIC);
				if (msgbuf) {
					memset((UINT8 *) msgbuf, 0, MgmtMsg_p->Hdr.FrmBodyLen + 2);
					memcpy(&(msgbuf->Hdr), &(MgmtMsg_p->Hdr), sizeof(IEEEtypes_MgmtHdr3_t));
					memcpy(&(msgbuf->Hdr.Rsrvd), &(MgmtMsg_p->Body),
					       MgmtMsg_p->Hdr.FrmBodyLen - sizeof(IEEEtypes_MgmtHdr3_t) + sizeof(UINT16));
					msgbuf->Hdr.FrmBodyLen -= ETH_ALEN;	// Remove Addr4 bssid length here.

					mwl_cfg80211_rx_mgmt(vmacSta_p->dev, &(msgbuf->Hdr.FrmCtl), msgbuf->Hdr.FrmBodyLen, rssi);

					wl_kfree(msgbuf);
				}
#else				/* SOC_W906X */
				memcpy(&MgmtMsg_p->Hdr.Rsrvd, &MgmtMsg_p->Body,
				       MgmtMsg_p->Hdr.FrmBodyLen - sizeof(IEEEtypes_MgmtHdr3_t) + sizeof(UINT16));
				mwl_send_vendor_auth_event(vmacSta_p->dev, ((uint8_t *) MgmtMsg_p) + 2,
							   MgmtMsg_p->Hdr.FrmBodyLen - sizeof(IEEEtypes_MacAddr_t), rssi);
#endif				/* SOC_W906X */
			} else {
#ifdef SOC_W906X
				macmgmtQ_MgmtMsg3_t *msgbuf;

				msgbuf = (macmgmtQ_MgmtMsg3_t *) wl_kmalloc(MgmtMsg_p->Hdr.FrmBodyLen + 2, GFP_ATOMIC);
				if (msgbuf) {
					memset((UINT8 *) msgbuf, 0, MgmtMsg_p->Hdr.FrmBodyLen + 2);
					memcpy(&(msgbuf->Hdr), &(MgmtMsg_p->Hdr), sizeof(IEEEtypes_MgmtHdr3_t));
					memcpy(&(msgbuf->Hdr.Rsrvd), &(MgmtMsg_p->Body),
					       MgmtMsg_p->Hdr.FrmBodyLen - sizeof(IEEEtypes_MgmtHdr3_t) + sizeof(UINT16));
					msgbuf->Hdr.FrmBodyLen -= ETH_ALEN;	// Remove Addr4 bssid length here.

					mwl_cfg80211_rx_mgmt(vmacSta_p->dev, &(msgbuf->Hdr.FrmCtl), msgbuf->Hdr.FrmBodyLen, rssi);

					wl_kfree(msgbuf);
				}
#else				/* SOC_W906X */
				mwl_send_vendor_auth_event(vmacSta_p->dev, ((uint8_t *) MgmtMsg_p) + 2, MgmtMsg_p->Hdr.FrmBodyLen, rssi);
#endif				/* SOC_W906X */
			}
		}
#endif
	} else {
		if (MgmtMsg_p->Hdr.FrmCtl.Subtype == IEEE_MSG_PROBE_RQST)
			WLDBG_INFO(DBG_LEVEL_7, "Probe Request Frame larger than allowed event buffer");

		if (MgmtMsg_p->Hdr.FrmCtl.Subtype == IEEE_MSG_AUTHENTICATE)
			WLDBG_INFO(DBG_LEVEL_7, "Authenticate Frame larger than allowed event buffer");
	}
#endif
}

#define bandSteeringForwardAuthenticate forwardMgmtPacket

extern void macMgmtMlme_ProbeRqst1(vmacApInfo_t * vmacSta_p, macmgmtQ_MgmtMsg3_t * MgmtMsg_p);
static void bandSteeringForwardProbeRqst(vmacApInfo_t * vmac_ap, macmgmtQ_MgmtMsg3_t * MgmtMsg_p, u_int8_t rssi)
{
	struct net_device *dev;
	struct wlprivate *wlpptr, *wlpptr1;
	vmacApInfo_t *vmacSta_p;
	UINT8 bctAddr[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	int i = 0;
	if (vmac_ap->master)
		vmacSta_p = vmac_ap->master;
	else
		vmacSta_p = vmac_ap;
	wlpptr = NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev);
	if (memcmp(MgmtMsg_p->Hdr.DestAddr, bctAddr, 6) == 0) {
		while (i <= bss_num) {
			if (wlpptr->vdev[i]) {
				dev = wlpptr->vdev[i];
				wlpptr1 = NETDEV_PRIV_P(struct wlprivate, dev);
				if (wlpptr1->vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_AP) {
					MIB_802DOT11 *mib = wlpptr1->vmacSta_p->Mib802dot11;

					if ((isMacAccessList(wlpptr1->vmacSta_p, &(MgmtMsg_p->Hdr.SrcAddr)) == SUCCESS) ||
					    ((*(mib->mib_broadcastssid) == FALSE) && (MgmtMsg_p->Body.ProbeRqst.SsId.Len &&
										      !memcmp((mib->StationConfig->DesiredSsId),
											      MgmtMsg_p->Body.ProbeRqst.SsId.SsId,
											      MgmtMsg_p->Body.ProbeRqst.SsId.Len)))) {

						if ((*(wlpptr1->vmacSta_p->Mib802dot11->mib_bandsteer) == 1) &&
						    (*(wlpptr1->vmacSta_p->Mib802dot11->mib_bandsteer_handler) == BAND_STEERING_HDL_BY_HOST))
							forwardMgmtPacket(wlpptr1->vmacSta_p, MgmtMsg_p, rssi);
						else
							macMgmtMlme_ProbeRqst1(wlpptr1->vmacSta_p, MgmtMsg_p);
					}
				}
			}
			i++;
		}
	} else {
		if (vmac_ap->VMacEntry.modeOfService == VMAC_MODE_AP)
			if (isMacAccessList(vmac_ap, &(MgmtMsg_p->Hdr.SrcAddr)) == SUCCESS) {
				if ((*(vmac_ap->Mib802dot11->mib_bandsteer) == 1) &&
				    (*(vmac_ap->Mib802dot11->mib_bandsteer_handler) == BAND_STEERING_HDL_BY_HOST)) {
					forwardMgmtPacket(vmac_ap, MgmtMsg_p, rssi);
				} else {
					vmacApInfo_t *vmactem_p;

					vmactem_p = vmacGetMBssByAddr(vmacSta_p, MgmtMsg_p->Hdr.DestAddr);
					if (vmactem_p) {
						vmacSta_p = vmactem_p;
					} else {
						return;
					}
					macMgmtMlme_ProbeRqst1(vmacSta_p, MgmtMsg_p);
				}
			}
	}
}

static int bandSteeringProcess(vmacApInfo_t * vmacSta_p, IEEEtypes_Frame_t * wlanMsg_p, struct sk_buff *skb, UINT32 rssi)
{
	vmacApInfo_t *vmactmp_p = NULL;
	struct wlprivate *wlpptr = NULL;
	int result = 0;

	if (vmacSta_p->master)
		vmactmp_p = vmacSta_p->master;
	else
		vmactmp_p = vmacSta_p;

	wlpptr = NETDEV_PRIV_P(struct wlprivate, vmactmp_p->dev);

	if ((*(vmacSta_p->Mib802dot11->mib_bandsteer_sta_track_max_num) > 0))
		sta_track_add(wlpptr, (UINT8 *) wlanMsg_p->Hdr.Addr2);

	if (*(vmacSta_p->Mib802dot11->mib_bandsteer_handler) == BAND_STEERING_HDL_BY_DRV) {
		UINT8 bctAddr[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

		if (((wlanMsg_p->Hdr.FrmCtl.Subtype == IEEE_MSG_PROBE_RQST) &&
		     (memcmp(wlanMsg_p->Hdr.Addr1, bctAddr, 6) == 0)) || (wlanMsg_p->Hdr.FrmCtl.Subtype == IEEE_MSG_AUTHENTICATE)) {
			switch (bandSteeringCheck(wlpptr, wlanMsg_p, rssi)) {
			case 0x01:
				if (wlanMsg_p->Hdr.FrmCtl.Subtype == IEEE_MSG_AUTHENTICATE) {
					struct sta_auth_info *info = NULL;

					if (*(vmacSta_p->Mib802dot11->mib_bandsteer_sta_auth_retry_cnt) > 0) {
						sta_auth_add(wlpptr, (UINT8 *) wlanMsg_p->Hdr.Addr2);
						info = sta_auth_get(wlpptr, (UINT8 *) wlanMsg_p->Hdr.Addr2);
						if (info) {
							/* send auth resp if auth req received more than max retry count */
							if (info->count > *(vmacSta_p->Mib802dot11->mib_bandsteer_sta_auth_retry_cnt)) {
								sta_auth_del(wlpptr, (UINT8 *) wlanMsg_p->Hdr.Addr2);
								break;
							}
						}
					}
				}
				result = 1;
				break;
			case 0x02:
				if (*(vmacSta_p->Mib802dot11->mib_bandsteer_timer_interval) > 0) {
					/* Queue the skb and process the skb later. */
					bandSteeringQueueSkb(wlpptr, skb);
					result = 2;
				}
				/* else Send the probe or Authenticate response. */
				break;
			default:
				/* Send the probe or Authenticate response. */
				break;
			}
		}
	} else if (*(vmacSta_p->Mib802dot11->mib_bandsteer_handler) == BAND_STEERING_HDL_BY_HOST) {
		if (wlanMsg_p->Hdr.FrmCtl.Subtype == IEEE_MSG_PROBE_RQST) {
			bandSteeringForwardProbeRqst(vmacSta_p, (macmgmtQ_MgmtMsg3_t *) wlanMsg_p, rssi);
			result = 1;
		} else if (wlanMsg_p->Hdr.FrmCtl.Subtype == IEEE_MSG_AUTHENTICATE) {
			/* deliver authenticate to hostapd include <11dot packet and rssi> */
			bandSteeringForwardAuthenticate(vmacSta_p, (macmgmtQ_MgmtMsg3_t *) wlanMsg_p, rssi);
			result = 1;
		}
	}

	return result;
}
#endif				/* BAND_STEERING */

int akm_sae_enabled(UINT8 * pData)
{
	IEEEtypes_RSN_IE_WPA2_t *pIe = (IEEEtypes_RSN_IE_WPA2_t *) pData;
	IEEEtypes_RSN_IE_WPA2_t RSNE;
	IEEEtypes_RSN_IE_WPA2_t *pRSNE = &RSNE;
	UINT8 *ptr;
	UINT16 len, totalLen = pIe->Len + 2;
	SINT8 left = pIe->Len;

	len = &pIe->GrpKeyCipher[0] - pData;	//Fixed parameters

	memset((void *)pRSNE, 0x00, sizeof(IEEEtypes_RSN_IE_WPA2_t));
	memcpy((void *)pRSNE, (void *)pIe, len);

	ptr = &pIe->GrpKeyCipher[0];
	left -= sizeof(pRSNE->Ver);

	if ((ptr - pData) >= totalLen) {
		return 0;
	}
	//Group Data Cipher Suite
	memcpy(pRSNE->GrpKeyCipher, ptr, sizeof(pRSNE->GrpKeyCipher));
	ptr += sizeof(pRSNE->GrpKeyCipher);
	left -= sizeof(pRSNE->GrpKeyCipher);

	if ((ptr - pData) >= totalLen) {
		return 0;
	}
	pRSNE->PwsKeyCnt[0] = *ptr++;
	pRSNE->PwsKeyCnt[1] = *ptr++;
	left -= sizeof(pRSNE->PwsKeyCnt);
	if (left < pRSNE->PwsKeyCnt[0] * sizeof(pRSNE->PwsKeyCipherList)) {
		return 0;
	}
	//Check Pairwise Cipher Suite List
	if (pRSNE->PwsKeyCnt[0] == 1) {
		memcpy(pRSNE->PwsKeyCipherList, ptr, sizeof(pRSNE->PwsKeyCipherList));
		ptr += sizeof(pRSNE->PwsKeyCipherList);
	} else {
		if (pRSNE->PwsKeyCnt[0])
			memcpy(pRSNE->PwsKeyCipherList, ptr, sizeof(pRSNE->PwsKeyCipherList));
		ptr += sizeof(pRSNE->PwsKeyCipherList) * pRSNE->PwsKeyCnt[0];
	}
	left -= sizeof(pRSNE->PwsKeyCipherList) * pRSNE->PwsKeyCnt[0];
	if ((ptr - pData) >= totalLen) {
		return 0;
	}
	//Check AKM Cipher Suite Count
	pRSNE->AuthKeyCnt[0] = *ptr++;
	pRSNE->AuthKeyCnt[1] = *ptr++;
	left -= sizeof(pRSNE->AuthKeyCnt);
	if ((pRSNE->AuthKeyCnt[0] == 0) || (left < pRSNE->AuthKeyCnt[0] * sizeof(pRSNE->AuthKeyList))) {
		return 0;
	}
	//Check AKM Cipher Suite List
	if ((ptr - pData) >= totalLen) {
		return 0;
	}

	if (pRSNE->AuthKeyCnt[0] > 2)
		pRSNE->AuthKeyCnt[0] = 2;
	memcpy(pRSNE->AuthKeyList, ptr, sizeof(pRSNE->AuthKeyList) * pRSNE->AuthKeyCnt[0]);
	if (pRSNE->AuthKeyCnt[0] == 1) {
		if (pRSNE->AuthKeyList[3] == 0x08) {
			return 1;
		}
	} else if (pRSNE->AuthKeyCnt[0] == 2) {
		if ((pRSNE->AuthKeyList[3] == 0x08) || (pRSNE->AuthKeyList1[3] == 0x08)) {
			return 1;
		}
	}

	return 0;
}

void receiveWlanMsg(struct net_device *dev, struct sk_buff *skb, UINT32 rssi, BOOLEAN stationpacket)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, dev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	//      MIB_802DOT11 *mib=vmacSta_p->Mib802dot11;
	//      macmgmtQ_SmeCmd_t *SmeCmd_p;
	//      struct sk_buff *mgmtBuff_p;
	IEEEtypes_Frame_t *wlanMsg_p;
#ifdef WTP_SUPPORT
	vmacApInfo_t *vmactmp_p;
	struct wlprivate *wlpptr, *wlpptr1;
	static const char tag1[] = "wtp-splitmac-mgmt-pkt";
	static const char tag2[] = "wtp-localmac-mgmt-pkt";
	UINT8 i;
	UINT8 bctAddr[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
#endif
#ifdef MRVL_80211R
	static const char tag_action[] = "mlme-action";
	UINT8 *msg;
	UINT16 len;
#endif
	union iwreq_data wreq;
	UINT8 buf[1024] = { 0 };

	wlanMsg_p = (IEEEtypes_Frame_t *) ((UINT8 *) skb->data - 2);

	wlanMsg_p->Hdr.FrmBodyLen = skb->len;
	if (wlanMsg_p->Hdr.FrmCtl.Subtype != IEEE_MSG_ACTION_NO_ACK && skb->len > 1024) {
		if (dbg_class & 0x80000000)
			print_hex_dump(KERN_INFO, "", DUMP_PREFIX_ADDRESS, 16, 1, wlanMsg_p, skb->len, true);
		/* keep the skb in sysfs */
		wlBmRxDropMgmtKeep(dev, skb);
		return;
	}
#ifdef WTP_SUPPORT
	if (wlanMsg_p->Hdr.FrmCtl.Subtype != IEEE_MSG_BEACON) {	//do not handle beacon
		if (memcmp(wlanMsg_p->Hdr.Addr1, bctAddr, 6) == 0) {
			if (vmacSta_p->master)
				vmactmp_p = vmacSta_p->master;
			else
				vmactmp_p = vmacSta_p;
			wlpptr = NETDEV_PRIV_P(struct wlprivate, vmactmp_p->dev);
			for (i = 0; wlpptr->vdev[i] && i <= bss_num; i++) {
				wlpptr1 = NETDEV_PRIV_P(struct wlprivate, wlpptr->vdev[i]);
				if (wlpptr1->vmacSta_p->wtp_info.WTP_enabled && wlpptr1->vmacSta_p->VMacEntry.modeOfService == VMAC_MODE_AP) {
					if (wlpptr1->vmacSta_p->wtp_info.mac_mode == WTP_MAC_MODE_SPLITMAC) {
						memcpy(buf, tag1, strlen(tag1));
						memcpy(&buf[strlen(tag1)], skb->data, 24);
						memcpy(&buf[strlen(tag1) + 24], skb->data + 30, skb->len - 30);
						memset(&wreq, 0, sizeof(wreq));
						wreq.data.length = strlen(tag1) + skb->len + sizeof(UINT16) - 6;
						if (vmacSta_p->dev->flags & IFF_RUNNING)
							wireless_send_event(wlpptr1->vmacSta_p->dev, IWEVCUSTOM, &wreq, buf);
					} else {
						if ((wlanMsg_p->Hdr.FrmCtl.Subtype == IEEE_MSG_ASSOCIATE_RQST) ||
						    (wlanMsg_p->Hdr.FrmCtl.Subtype == IEEE_MSG_REASSOCIATE_RQST) ||
						    (wlanMsg_p->Hdr.FrmCtl.Subtype == IEEE_MSG_AUTHENTICATE)) {
							memcpy(buf, tag2, strlen(tag2));
							memcpy(&buf[strlen(tag2)], skb->data, 24);
							memcpy(&buf[strlen(tag2) + 24], skb->data + 30, skb->len - 30);
							memset(&wreq, 0, sizeof(wreq));
							wreq.data.length = strlen(tag2) + skb->len + sizeof(UINT16) - 6;
							if (vmacSta_p->dev->flags & IFF_RUNNING)
								wireless_send_event(wlpptr1->vmacSta_p->dev, IWEVCUSTOM, &wreq, buf);
						}
					}
				}
			}
		} else {
			if (vmacSta_p->wtp_info.WTP_enabled) {
				if (vmacSta_p->wtp_info.mac_mode == WTP_MAC_MODE_SPLITMAC) {
					memcpy(buf, tag1, strlen(tag1));
					memcpy(&buf[strlen(tag1)], skb->data, 24);
					memcpy(&buf[strlen(tag1) + 24], skb->data + 30, skb->len - 30);
					memset(&wreq, 0, sizeof(wreq));
					wreq.data.length = strlen(tag1) + skb->len + sizeof(UINT16) - 6;
					if (vmacSta_p->dev->flags & IFF_RUNNING)
						wireless_send_event(vmacSta_p->dev, IWEVCUSTOM, &wreq, buf);
				} else {	//LOCAL MAC.
					if ((wlanMsg_p->Hdr.FrmCtl.Subtype == IEEE_MSG_ASSOCIATE_RQST) ||
					    (wlanMsg_p->Hdr.FrmCtl.Subtype == IEEE_MSG_REASSOCIATE_RQST) ||
					    (wlanMsg_p->Hdr.FrmCtl.Subtype == IEEE_MSG_AUTHENTICATE)) {
						memcpy(buf, tag2, strlen(tag2));
						memcpy(&buf[strlen(tag2)], skb->data, 24);
						memcpy(&buf[strlen(tag2) + 24], skb->data + 30, skb->len - 30);
						memset(&wreq, 0, sizeof(wreq));
						wreq.data.length = strlen(tag2) + skb->len + sizeof(UINT16) - 6;
						if (vmacSta_p->dev->flags & IFF_RUNNING)
							wireless_send_event(vmacSta_p->dev, IWEVCUSTOM, &wreq, buf);
					}
				}
			}
		}
	}
#endif
#ifdef WLS_FTM_SUPPORT
	{
		extern void wlsFTM_receiveWlanMsg(struct net_device *netdev, struct sk_buff *skb, UINT32 rssi, BOOLEAN stationpacket);
		wlsFTM_receiveWlanMsg(dev, skb, rssi, stationpacket);
	}
#endif
//#ifdef CB_SUPPORT
//      if ((wlanMsg_p->Hdr.FrmCtl.Type == IEEE_TYPE_MANAGEMENT) &&
//              (priv->is_resp_mgmt == FALSE)
//              ) {
//              // Skip the mgmt for this bss
//              //printk("%s(), Skip the mgmt for this bss\n", dev->name);
//              wl_free_skb(skb);
//              return;
//      }
//#endif //CB_SUPPORT

	WLDBG_INFO(DBG_LEVEL_11, "IEEE_TYPE_MANAGEMENT message received. \n");
	switch (wlanMsg_p->Hdr.FrmCtl.Subtype) {
	case 0xf:		//fw debug type
		/*printk("FW: %s\n", (UINT8 *)((UINT8 *)wlanMsg_p + 6)); */
		/*WLDBG_INFO(DBG_LEVEL_11,"%s\n", (UINT8 *)((UINT32)wlanMsg_p+2+sizeof(IEEEtypes_MgmtHdr2_t))); */
		break;
#ifndef INTEROP
	case IEEE_MSG_QOS_ACTION:
		WLDBG_INFO(DBG_LEVEL_11, "IEEE_MSG_QOS_ACTION message received. \n");
		break;
#endif
#ifdef MRVL_80211R
	case IEEE_MSG_ACTION:
		if ((wlanMsg_p->Body[0] == 6) ||	//Action Category = Fast BSS Transition
		    (wlanMsg_p->Body[0] == 10) ||	//Action Category = WNM
		    (wlanMsg_p->Body[0] == 4) ||	//Action Category = Public
		    (wlanMsg_p->Body[0] == 9)) {	//Action Category = Protected Dual of Public
#ifdef CFG80211
			UINT8 wildcard_bssid[IEEEtypes_ADDRESS_SIZE] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
			macmgmtQ_MgmtMsg3_t *MgmtMsg_p = NULL;
#endif				/* CFG80211 */

			msg = (UINT8 *) wlanMsg_p;
			//len = (*(UINT16 *)msg -= 6);
			len = wlanMsg_p->Hdr.FrmBodyLen - 6;
			memcpy(buf, tag_action, strlen(tag_action));
			memcpy(&buf[strlen(tag_action)], msg, 26);
			memcpy(&buf[strlen(tag_action) + 26], msg + 32, len + 2 - 26);
			memset(&wreq, 0, sizeof(wreq));
			wreq.data.length = strlen(tag_action) + skb->len + 2;	// + sizeof(UINT16);
			if (vmacSta_p->dev->flags & IFF_RUNNING) {
				/* sync. with data.length check with kernel */
				if (wreq.data.length <= IW_CUSTOM_MAX * 2)
					wireless_send_event(vmacSta_p->dev, IWEVCUSTOM, &wreq, buf);
				else
					wireless_send_event(vmacSta_p->dev, IWEVGENIE, &wreq, buf);
			}
#ifdef CFG80211
			MgmtMsg_p = (macmgmtQ_MgmtMsg3_t *) (buf + strlen(tag_action));
			MgmtMsg_p->Hdr.FrmBodyLen -= ETH_ALEN;	// Remove Addr4 bssid length here.

			if (wlanMsg_p->Body[0] == 4 && !memcmp(wildcard_bssid, MgmtMsg_p->Hdr.BssId, IEEEtypes_ADDRESS_SIZE)) {
				UINT32 vap_idx = 0;
				/* If Public action bssid is wildcard, send it to all the AP virtual interfaces */
				for (vap_idx = 0; vap_idx <= bss_num; vap_idx++) {
					if (priv->vdev[vap_idx] && priv->vdev[vap_idx]->flags & IFF_RUNNING) {
						mwl_cfg80211_rx_mgmt(priv->vdev[vap_idx], ((UINT8 *) MgmtMsg_p) + 2, MgmtMsg_p->Hdr.FrmBodyLen, rssi);
					}
				}
			} else {
				mwl_cfg80211_rx_mgmt(vmacSta_p->dev, ((UINT8 *) MgmtMsg_p) + 2, MgmtMsg_p->Hdr.FrmBodyLen, rssi);
			}
#endif				/* CFG80211 */
			if ((wlanMsg_p->Body[0] == 10) || (wlanMsg_p->Body[0] == 4))
				evtDot11MgtMsg(vmacSta_p, (UINT8 *) wlanMsg_p, skb, rssi);
			break;
		} else if (!stationpacket) {
			evtDot11MgtMsg(vmacSta_p, (UINT8 *) wlanMsg_p, skb, rssi);
			break;
		} else {
			goto fall_to_default;
		}
#endif
	case IEEE_MSG_PROBE_RQST:
		if (priv->wlpd_p->bStopBcnProbeResp && macMgmtMlme_DfsEnabled(dev))
			break;
#ifdef BAND_STEERING
		if (*(vmacSta_p->Mib802dot11->mib_bandsteer) == 1) {
			switch (bandSteeringProcess(vmacSta_p, (IEEEtypes_Frame_t *) wlanMsg_p, skb, rssi)) {
			case 0:
				/* Send the probe response. */
				macMgmtMlme_ProbeRqst(vmacSta_p, (macmgmtQ_MgmtMsg3_t *) wlanMsg_p);
				break;
			case 2:
				/* Probe request has been queue, processed it later. */
				return;
			default:	//1
				/* Probe request should be ignored, or has been forward to host. */
				break;
			}
		} else
			macMgmtMlme_ProbeRqst(vmacSta_p, (macmgmtQ_MgmtMsg3_t *) wlanMsg_p);
#else				/* BAND_STEERING */
		macMgmtMlme_ProbeRqst(vmacSta_p, (macmgmtQ_MgmtMsg3_t *) wlanMsg_p);
#endif				/* BAND_STEERING */
		break;
#ifdef CLIENT_SUPPORT
		/* Intercept beacon here for AP.
		 * Client beacon will be handled later.
		 */
	case IEEE_MSG_BEACON:
		RxBeacon(vmacSta_p, wlanMsg_p, skb->len, rssi);
#endif				//CLIENT_SUPPORT
#ifdef MRVL_80211R
 fall_to_default:
#endif				//MRVL_80211R
	default:
		/* 802.11 Management frame::feed MLME State Machines */
#ifdef CLIENT_SUPPORT
		{
#define SK_BUF_RESERVED_PAD     (2 + sizeof(void *))
			if (stationpacket) {
				vmacEntry_t *targetVMacEntry_p = NULL;
				IEEEtypes_MgmtHdr_t *Hdr_p;

				/*Have to handle broadcast deauth pkt too. Checking whether deauth pkt bssid is for station is done at later part */
				if ((wlanMsg_p->Hdr.FrmCtl.Subtype == IEEE_MSG_BEACON)
				    || (wlanMsg_p->Hdr.FrmCtl.Subtype == IEEE_MSG_QOS_ACTION)
				    || (((wlanMsg_p->Hdr.FrmCtl.Subtype == IEEE_MSG_DEAUTHENTICATE) ||
					 (wlanMsg_p->Hdr.FrmCtl.Subtype == IEEE_MSG_DISASSOCIATE)) && IS_GROUP((UINT8 *) & (wlanMsg_p->Hdr.Addr1))))
					targetVMacEntry_p = sme_GetParentVMacEntry(vmacSta_p->VMacEntry.phyHwMacIndx);
				else
					targetVMacEntry_p = vmacGetVMacEntryByAddr((UINT8 *) & wlanMsg_p->Hdr.Addr1);
				if (targetVMacEntry_p) {
					curRxInfo_g.RSSI = (UINT8) rssi;
					//printk("****** client process dot11 rssi=%d\n",curRxInfo_g.RSSI);
					//skb_push(skb, SK_BUF_RESERVED_PAD);
					skb_push(skb, 2);	/* For UINT16 FrmBodyLen */
					Hdr_p = (IEEEtypes_MgmtHdr_t *) (skb->data);
					Hdr_p->FrmBodyLen = skb->len;
					skb_push(skb, sizeof(void *));	/* For priv_p pointer */
					targetVMacEntry_p->dot11MsgEvt(skb->data, (UINT8 *) & curRxInfo_g, targetVMacEntry_p->info_p);
					skb_pull(skb, SK_BUF_RESERVED_PAD);
				}
			} else {
#ifdef WTP_SUPPORT
				if (!(vmacSta_p->wtp_info.WTP_enabled && vmacSta_p->wtp_info.mac_mode == WTP_MAC_MODE_SPLITMAC)
				    || ((wlanMsg_p->Hdr.FrmCtl.Subtype == IEEE_MSG_QOS_ACTION) && (wlanMsg_p->Body[0] == BlkAck)))
#endif
				{
#ifdef BAND_STEERING
					if ((wlanMsg_p->Hdr.FrmCtl.Subtype == IEEE_MSG_AUTHENTICATE) &&
					    (*(vmacSta_p->Mib802dot11->mib_bandsteer) == 1)) {

						//printk("%s: authenticate from : [%s] - rssi: [%d]\n", priv->netDev->name, mac_display(wlanMsg_p->Hdr.Addr2), rssi);
						switch (bandSteeringProcess(vmacSta_p, (IEEEtypes_Frame_t *) wlanMsg_p, skb, rssi)) {
						case 0:
							/* Process the authenticate frame. */
							evtDot11MgtMsg(vmacSta_p, (UINT8 *) wlanMsg_p, skb, rssi);
							break;
						case 2:
							/* Authenticate request has been queue, processed later. */
							return;
						default:	//1
							/* Authenticate has been processed, or forward to host. */
							break;
						}
					} else
#endif				/* BAND_STEERING */
					if (wlanMsg_p->Hdr.FrmCtl.Subtype == IEEE_MSG_AUTHENTICATE
						    && ((macmgmtQ_MgmtMsg3_t *) wlanMsg_p)->Body.Auth.AuthAlg == AUTH_SAE) {
						macmgmtQ_MgmtMsg3_t *mgmtMsg;

						///skb_push(skb, sizeof(mgmtMsg->Hdr.FrmBodyLen));
						mgmtMsg = (macmgmtQ_MgmtMsg3_t *) wlanMsg_p;
						/* Remove address4 */
						memmove(&(mgmtMsg->Hdr.Rsrvd), &(mgmtMsg->Body),
							mgmtMsg->Hdr.FrmBodyLen - sizeof(IEEEtypes_MgmtHdr3_t) + sizeof(UINT16));
						mgmtMsg->Hdr.FrmBodyLen -= ETH_ALEN;

#ifdef CFG80211
						mwl_cfg80211_rx_mgmt(vmacSta_p->dev, &(mgmtMsg->Hdr.FrmCtl), mgmtMsg->Hdr.FrmBodyLen, rssi);
#else
						mwl_wext_rx_mgmt(vmacSta_p->dev, mgmtMsg, mgmtMsg->Hdr.FrmBodyLen + sizeof(UINT16));
#endif
					} else
#if defined(OWE_SUPPORT) || defined(MBO_SUPPORT)
						if (((wlanMsg_p->Hdr.FrmCtl.Subtype == IEEE_MSG_ASSOCIATE_RQST) ||
						     (wlanMsg_p->Hdr.FrmCtl.Subtype == IEEE_MSG_REASSOCIATE_RQST)) &&
						    (((vmacSta_p->Mib802dot11->WPA2AuthSuites->AuthSuites[3]) == 0x12)
						     || (vmacSta_p->Mib802dot11->RSNConfigWPA2->WPA2Enabled &&
							 akm_sae_enabled((UINT8 *) vmacSta_p->Mib802dot11->thisStaRsnIEWPA2))
#ifdef MBO_SUPPORT
						     || (vmacSta_p->Mib802dot11->mib_mbo_enabled)
#endif				/* MBO_SUPPORT */
						    )) {
						extStaDb_StaInfo_t *pStaInfo;
						pStaInfo = extStaDb_GetStaInfo(vmacSta_p, &wlanMsg_p->Hdr.Addr2, 0);

						if (pStaInfo == NULL) {
							evtDot11MgtMsg(vmacSta_p, (UINT8 *) wlanMsg_p, skb, rssi);
							wl_free_skb(skb);
							return;
						}

						if (pStaInfo->assocReq_skb == NULL) {
							macmgmtQ_MgmtMsg3_t *mgmtMsg = (macmgmtQ_MgmtMsg3_t *) (skb->data - 2);

							pStaInfo->assocReq_skb = skb;
							pStaInfo->assocReq_skb_rssi = rssi;
							memmove(&(mgmtMsg->Hdr.Rsrvd), &(mgmtMsg->Body),
								mgmtMsg->Hdr.FrmBodyLen - sizeof(IEEEtypes_MgmtHdr3_t) +
								sizeof(mgmtMsg->Hdr.FrmBodyLen));
							mgmtMsg->Hdr.FrmBodyLen -= ETH_ALEN;
							/* forward associate frame to hostapd to process Diffie-Hellman element or MBP OCE IE */
							pending_assoc_start_timer(pStaInfo);
#ifdef CFG80211
							mwl_cfg80211_rx_mgmt(vmacSta_p->dev, &(mgmtMsg->Hdr.FrmCtl), (mgmtMsg->Hdr.FrmBodyLen), rssi);
#else
							mwl_wext_rx_mgmt(vmacSta_p->dev, mgmtMsg,
									 mgmtMsg->Hdr.FrmBodyLen + sizeof(mgmtMsg->Hdr.FrmBodyLen));
#endif
							mgmtMsg->Hdr.FrmBodyLen += ETH_ALEN;
							memmove(&(mgmtMsg->Body), &(mgmtMsg->Hdr.Rsrvd),
								mgmtMsg->Hdr.FrmBodyLen - sizeof(IEEEtypes_MgmtHdr3_t) +
								sizeof(mgmtMsg->Hdr.FrmBodyLen));
						} else {
							/* an associate frame in process, drop the new associate frame */
							wl_free_skb(skb);
						}
						return;
					} else
#endif				/* OWE_SUPPORT || MBO_SUPPORT */
					{
#ifdef IEEE80211K
						if (wlanMsg_p->Hdr.FrmCtl.Subtype == IEEE_MSG_QOS_ACTION && (wlanMsg_p->Body[0] == 4 ||	//Action Category = Public
													     wlanMsg_p->Body[0] == AC_WNM)) {	//Action Category = WNM
							macmgmtQ_MgmtMsg3_t *MgmtMsg_p = (macmgmtQ_MgmtMsg3_t *) wlanMsg_p;
							macmgmtQ_MgmtMsg3_t *msgbuf;

							if ((msgbuf =
							     (macmgmtQ_MgmtMsg3_t *) wl_kmalloc(MgmtMsg_p->Hdr.FrmBodyLen + 2, GFP_ATOMIC)) == NULL) {
								WLDBG_INFO(DBG_LEVEL_15, "receiveWlanMsg: failed to alloc msg buffer\n");
							} else {
								memset((UINT8 *) msgbuf, 0, MgmtMsg_p->Hdr.FrmBodyLen + 2);
								memcpy(&(msgbuf->Hdr), &(MgmtMsg_p->Hdr), sizeof(IEEEtypes_MgmtHdr3_t));
								memcpy(&(msgbuf->Hdr.Rsrvd), &(MgmtMsg_p->Body),
								       MgmtMsg_p->Hdr.FrmBodyLen - sizeof(IEEEtypes_MgmtHdr3_t) + sizeof(UINT16));
								msgbuf->Hdr.FrmBodyLen -= ETH_ALEN;	// Remove Addr4 bssid length here.
#ifdef CFG80211
								mwl_cfg80211_rx_mgmt(vmacSta_p->dev, &(msgbuf->Hdr.FrmCtl),
										     msgbuf->Hdr.FrmBodyLen, 0);
#else				/* CFG80211 */
								mwl_wext_rx_mgmt(vmacSta_p->dev, msgbuf, msgbuf->Hdr.FrmBodyLen + sizeof(UINT16));
#endif				/* CFG80211 */
								wl_kfree(msgbuf);
							}
						}
#endif				/* IEEE80211K */
						evtDot11MgtMsg(vmacSta_p, (UINT8 *) wlanMsg_p, skb, rssi);
					}
				}
			}
		}
#else				/* CLIENT_SUPPORT */
#ifdef WTP_SUPPORT
		if (!(vmacSta_p->wtp_info.WTP_enabled && vmacSta_p->wtp_info.mac_mode == WTP_MAC_MODE_SPLITMAC) ||
		    ||((wlanMsg_p->Hdr.FrmCtl.Subtype == IEEE_MSG_QOS_ACTION) && (wlanMsg_p->Body[0] == BlkAck)))
#endif
			evtDot11MgtMsg(vmacSta_p, (UINT8 *) wlanMsg_p, skb, rssi);
#endif				/* CLIENT_SUPPORT */
		break;
	}

	wl_free_skb(skb);
}

#ifdef WTP_SUPPORT
extern void txWtpMgmtMsg(struct sk_buff *skb)
{
	struct wlreq_set_mlme_send *frm;
	struct net_device *dev;
	char *ifname, tmpbuf[30];
	int *sig;

	skb_pull(skb, sizeof(struct nlmsghdr));
	sig = (int *)skb->data;
	skb_pull(skb, 4);

	if (*sig == NL_TX_MGMT_SIGNATURE) {
		ifname = skb->data;
		if ((dev = dev_get_by_name(&init_net, ifname)) == NULL) {
			printk("Failed to get netdev, ifname=%s ...\n", ifname);
			return;
		}
		skb_pull(skb, strlen(ifname) + 1);
		frm = (struct wlreq_set_mlme_send *)skb->data;
		frm->len = ntohs(frm->len + 6);
		memcpy(tmpbuf, skb->data, 26);	//include hdr length
		memcpy(skb_push(skb, 6), tmpbuf, 26);
		skb_pull(skb, 2);
		//printk("NL send mlme frame ... \n");
		//hexdump("Frame Tx", skb->data - 2, skb->len + 2, ' ');
		if (txMgmtMsg(dev, skb) != OS_SUCCESS)
			wl_free_skb(skb);
	}
	return;
}
#endif

extern WL_STATUS txMgmtMsg(struct net_device *dev, struct sk_buff *skb)
{
	//      WL_STATUS status = FAIL;
	WLDBG_INFO(DBG_LEVEL_11, "IEEE_TYPE_MGMT_CONTROL message txed skb = %x \n", skb);
	if (wlMgmtTx(skb, dev))
		wl_free_skb(skb);
	return SUCCESS;
}

extern WL_STATUS txDataMsg(struct net_device *dev, struct sk_buff *skb)
{
	//      WL_STATUS status = FAIL;
	WLDBG_INFO(DBG_LEVEL_11, "IEEE_TYPE_Data message txed skb = %x \n", skb);
	if (wlDataTx(skb, dev))
		wl_free_skb(skb);
	return SUCCESS;
}

extern WL_STATUS txDataMsg_UnEncrypted(struct net_device *dev, struct sk_buff *skb, extStaDb_StaInfo_t * pStaInfo)
{
	//      WL_STATUS status = FAIL;
	WLDBG_INFO(DBG_LEVEL_11, "IEEE_TYPE_Data message txed skb = %x \n", skb);
	if (wlDataTxUnencr(skb, dev, pStaInfo))
		wl_free_skb(skb);
	return SUCCESS;
}

/* defines for CSI, non-compressed, and compressed Tx Beamforming Matrices */
UINT8 csiBits[4] = { 4, 5, 6, 8 };
UINT8 nonCompBits[4] = { 4, 2, 6, 8 };
UINT8 numSubCarriers[2][3] = { {56, 30, 16}
,
{114, 58, 30}
};
UINT8 compBits[4][2] = { {1, 3}
,
{2, 4}
,
{3, 5}
,
{4, 6}
};

/* Number of Angles, based on Nr and Nc : only defined for 2x1, 2x2, 3x1, 3x2, 3x3, 4x1, 4x2, 4x3, 4x4 - leave
 * others set to 0. */
UINT8 numAnglesNa[4][4] = { {0, 0, 0, 0}
,
{2, 2, 0, 0}
,
{4, 6, 6, 0}
,
{6, 10, 12, 12}
};

#define DWORDBITSIZE        8 * sizeof(UINT32)
#define TXBF_BITSIZE        DWORDBITSIZE - sizeof(UINT8)
#define TXBF_BYTEINC        sizeof(UINT32) - sizeof(UINT8)
#define TXBF_CSIAMPBITMASK  7
#define TXBF_CSIAMPBITSIZE  3
/* Work with 24 bits at a time and check for overlap.  Always use memcpy to cross byte boundaries. */
UINT8 txBfMatrix[58][4][3][2];	/* For debug use max of 2 (I,J) x 58 subtones * 4 paths *3 streams max */
UINT8 txBfCsiAmp[58] = { 0 };

#if 0
void dispCSIorNonCompMatrix(UINT8 * pData, UINT8 Nb, UINT8 Nr, UINT8 Nc, UINT8 Ng, UINT8 type)
{
	UINT32 subCar_cnt;
	UINT32 i = 0, j = 0, k = 0;
	UINT32 reportSizePerSS = 2 * Nb * Nr * Nc;
	UINT32 bit = 0;
	UINT32 bitMask = (1 << Nb) - 1;
	UINT32 tmpData = 0;

	memcpy((UINT8 *) & tmpData, pData, sizeof(UINT32));
	pData += TXBF_BYTEINC;
	printk("Non compressed report size per stream = %d number of tones = %d\n", (int)reportSizePerSS, (int)Ng);
	for (subCar_cnt = 0; subCar_cnt < Ng; subCar_cnt++) {
		printk("tone %d \n", (int)subCar_cnt);
		if (type == ACTION_MIMO_CSI_REPORT) {
			if ((bit + TXBF_CSIAMPBITSIZE) >= DWORDBITSIZE) {
				memcpy((UINT8 *) & tmpData, pData, sizeof(UINT32));
				bit = bit % TXBF_BITSIZE;
				pData += TXBF_BYTEINC;
			}
			txBfCsiAmp[subCar_cnt] = tmpData & TXBF_CSIAMPBITMASK;
			printk("CSI tone Amplitude = %d \n", txBfCsiAmp[subCar_cnt]);
			tmpData >>= TXBF_CSIAMPBITSIZE;
			bit += TXBF_CSIAMPBITSIZE;
		}
		for (i = 0; i < Nr; i++) {
			for (j = 0; j < Nc; j++) {
				while (k <= 1) {
					if ((bit + Nb) < DWORDBITSIZE) {
						txBfMatrix[subCar_cnt][i][j][k++] = tmpData & bitMask;
						tmpData >>= Nb;
						bit += Nb;
					} else {
						memcpy((UINT8 *) & tmpData, pData, sizeof(UINT32));
						bit = bit % TXBF_BITSIZE;
						pData += TXBF_BYTEINC;
					}
				}
				k = 0;
				printk("(%d,%d) I=0x%2x J=0x%2x ", (int)i, (int)j, txBfMatrix[subCar_cnt][i][j][0], txBfMatrix[subCar_cnt][i][j][1]);
			}
			printk("\n");
		}
		printk("\n");
	}
}

void dispCompressedCode(UINT8 * pCodeData, UINT8 code, UINT8 numAngles, UINT8 Ng)
{
	UINT32 val = 0;
	UINT32 i = 0;
	UINT32 byteCount = 0;
	UINT8 subCar_cnt = 0;
	UINT8 *pByte = pCodeData;

	switch (code) {
	case 0:		/* psi = 1 bit, phi 3 bits */
		{
			IEEEtypes_CompBeamReportCode0_t *pCode0;
			pCode0 = (IEEEtypes_CompBeamReportCode0_t *) pCodeData;
			for (subCar_cnt = 0; subCar_cnt < Ng; subCar_cnt++) {
				printk("Angles for tone index %d \n", subCar_cnt);
				for (i = 0; i < numAngles; i++) {
					printk(" %x %x", pCode0->psi, pCode0->phi);
					if (i % 2)
						pCode0++;
					else
						*((UINT8 *) pCode0) = ((UINT8) * ((UINT8 *) pCode0)) >> 4;
				}
			}
		}
		break;
	case 1:		/* psi = 2 bit, phi 4 bits */
		{
			IEEEtypes_CompBeamReportCode1_t *pCode1;

			val = (UINT32) * pByte;
			pCode1 = (IEEEtypes_CompBeamReportCode1_t *) & val;
			byteCount = 0;
			for (subCar_cnt = 0; subCar_cnt < Ng; subCar_cnt++) {
				printk("Angles for tone index %d \n", subCar_cnt);
				for (i = 0; i < numAngles; i++) {
					if (byteCount > 2) {
						byteCount = 0;
						pByte += 3;
						memcpy((UINT8 *) & val, pByte, sizeof(UINT32));
					}
					printk(" %x %x", pCode1->psi, pCode1->phi);
					val = val >> 6;
					byteCount++;
				}
			}
		}
		break;
	case 2:		/* psi = 3 bits, phi 5 bits */
		{
			IEEEtypes_CompBeamReportCode2_t *pCode2 = (IEEEtypes_CompBeamReportCode2_t *) pCodeData;
			for (subCar_cnt = 0; subCar_cnt < Ng; subCar_cnt++) {
				printk("Angles for tone index %d \n", subCar_cnt);
				for (i = 0; i < numAngles; i++) {
					printk(" %x %x", pCode2->psi, pCode2->phi);
					pCode2++;
				}
			}
		}
		break;
	case 3:		/* psi = 4 bits, phi 6 bits */
		{
			IEEEtypes_CompBeamReportCode3_t *pCode3;
			memcpy((UINT8 *) & val, pByte, sizeof(UINT32));
			pCode3 = (IEEEtypes_CompBeamReportCode3_t *) & val;
			byteCount = 0;
			for (subCar_cnt = 0; subCar_cnt < Ng; subCar_cnt++) {
				printk("Angles for tone index %d \n", subCar_cnt);
				while (i < numAngles) {
					printk(" %x %x", pCode3->psi, pCode3->phi);
					val = val >> 10;
					i++;
					byteCount++;
					if ((byteCount > 2) && (i < numAngles)) {
						byteCount = 0;
						pByte += 4;
						val = ((val & 0x3) | (((UINT32) (*pByte) >> 2))) & 0x3FF;
						printk(" %x %x", pCode3->psi, pCode3->phi);
						memcpy((UINT8 *) & val, pByte + 1, sizeof(UINT32));
						i++;
					}
				}
				i = 0;
			}
		}
		break;
	default:
		printk("Invalid Code = %d \n", code);
		break;
	}
}
#endif

#ifdef CCK_DESENSE
void cck_desesne_check_stats(struct wlprivate *wlpptr)
{
	u8 i;
	u32 txbps = 0;
	u32 cca = 0;
	u8 enable;
	u8 datalen = CCK_DES_POLLDATA_SIZE;

	enable = (wlpptr->cck_des.cck_des_conf.enable || wlpptr->cck_des.rx_abort_conf.enable) ? 1 : 0;
	if (!enable)
		return;

	if (!wlpptr->cck_des.loadcfg.enable || (!wlpptr->cck_des.loadcfg.thres_tx && !wlpptr->cck_des.loadcfg.thres_cca)) {
		wlpptr->cck_des.off_reason &= ~(CCK_DES_OFF_LOW_TRAFFIC | CCK_DES_OFF_LOW_CCA);
		return;
	}

	for (i = 0; i < datalen; i++) {
		txbps += wlpptr->cck_des.loadcfg.data.txbps[i];
		cca += wlpptr->cck_des.loadcfg.data.cca[i];
	}

	txbps /= datalen;
	cca /= datalen;

	if (txbps < wlpptr->cck_des.loadcfg.thres_tx)
		/* Low traffic */
		wlpptr->cck_des.off_reason |= CCK_DES_OFF_LOW_TRAFFIC;
	else
		wlpptr->cck_des.off_reason &= ~CCK_DES_OFF_LOW_TRAFFIC;

	if (cca < wlpptr->cck_des.loadcfg.thres_cca)
		/* Low channel load */
		wlpptr->cck_des.off_reason |= CCK_DES_OFF_LOW_CCA;
	else
		wlpptr->cck_des.off_reason &= ~CCK_DES_OFF_LOW_CCA;

	wlpptr->cck_des.loadcfg.data.txbps_avg = txbps;
	wlpptr->cck_des.loadcfg.data.cca_avg = cca;
}

void cck_desense_run(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	u32 ivap, ista, entries, entries_total = 0;
	extStaDb_StaInfo_t *pStaInfo;
	u8 *sta_buf, *show_buf;
	u32 rssi_avg;
	s32 rssi_avg_signed;
	int minRSSI = 0, r1, r2;
	u8 threshold = 0;
	int enable;
	MIB_802DOT11 *mib;
	u8 rx_ant_num, max_rx_ant_num;

	enable = (wlpptr->cck_des.cck_des_conf.enable || wlpptr->cck_des.rx_abort_conf.enable) ? 1 : 0;
	if (!enable)
		return;

	mib = wlpptr->vmacSta_p->ShadowMib802dot11;
	max_rx_ant_num = (wlpptr->devid == SCBT) ? 4 : 8;
	rx_ant_num = (*(mib->mib_rxAntenna) == 0 || *(mib->mib_rxAntenna) >= max_rx_ant_num) ? max_rx_ant_num : *(mib->mib_rxAntenna);

	for (ivap = 0; ivap <= wlpd_p->NumOfAPs; ivap++) {
		if (wlpptr->vdev[ivap] != NULL && (wlpptr->vdev[ivap]->flags & IFF_RUNNING)) {
			struct wlprivate *wlpptr_v = NETDEV_PRIV_P(struct wlprivate, wlpptr->vdev[ivap]);

			if (wlpptr_v->vmacSta_p->OpMode != WL_OP_MODE_VAP)
				continue;

			entries = extStaDb_entries(wlpptr_v->vmacSta_p, 0);
			if (entries) {
				sta_buf = wl_kmalloc(entries * 64, GFP_ATOMIC);
				if (!sta_buf) {
					printk("vap%2d sta buf alloc failed\n", ivap);
					return;
				}

				extStaDb_list(wlpptr_v->vmacSta_p, sta_buf, 1);
				show_buf = sta_buf;

				for (ista = 0; ista < entries; ista++) {
					if ((pStaInfo =
					     extStaDb_GetStaInfo(wlpptr_v->vmacSta_p, (IEEEtypes_MacAddr_t *) show_buf,
								 STADB_DONT_UPDATE_AGINGTIME)) == NULL) {
						wl_kfree(sta_buf);
						printk("vap%2d GetStaInfo failed\n", ivap);
						return;
					}

					if (wlpptr->devid == SCBT)
						rssi_avg =
						    (pStaInfo->RSSI_path.a + pStaInfo->RSSI_path.b + pStaInfo->RSSI_path.e +
						     pStaInfo->RSSI_path.f) / rx_ant_num;
					else
						rssi_avg =
						    (pStaInfo->RSSI_path.a + pStaInfo->RSSI_path.b + pStaInfo->RSSI_path.c + pStaInfo->RSSI_path.d +
						     pStaInfo->RSSI_path.e + pStaInfo->RSSI_path.f + pStaInfo->RSSI_path.g +
						     pStaInfo->RSSI_path.h) / rx_ant_num;

					rssi_avg_signed = (rssi_avg >= 2048) ? -((4096 - rssi_avg) >> 4) : (rssi_avg >> 4);
					rssi_avg_signed = (rssi_avg_signed < 0) ? rssi_avg_signed : -pStaInfo->assocRSSI;
					minRSSI = (minRSSI > rssi_avg_signed) ? rssi_avg_signed : minRSSI;

					show_buf += sizeof(STA_INFO);
				}

				wl_kfree(sta_buf);
				entries_total += entries;
			}
		}
	}

	wlpptr->cck_des.rssi_min = minRSSI;

	if (!entries_total) {
		wlpptr->cck_des.off_reason |= CCK_DES_OFF_NO_STA_CONNECTED;

		if (wlpptr->cck_des.state & CCK_DES_STATE_ON) {
			wlpptr->cck_des.off_reason &= ~CCK_DES_OFF_TIMER;
			cck_desense_ctrl(netdev, CCK_DES_OFF);

			if (wlpptr->cck_des.loadcfg.enable && wlpptr->cck_des.off_time_ms > 0) {
				/* T_off is non-zero */
				unsigned long expires = jiffies + wlpptr->cck_des.off_time_ms * HZ / 1000;

				mod_timer_pending(&wlpptr->cck_des.timer, expires);
			}
		}

		return;
	}

	wlpptr->cck_des.off_reason &= ~CCK_DES_OFF_NO_STA_CONNECTED;
	if (wlpptr->cck_des.rssi_min >= 0) {
		wlpptr->cck_des.rssi_min = 0;
		return;
	}

	if (wlpptr->cck_des.cck_des_conf.enable && (*(wlpptr->vmacSta_p->Mib802dot11->mib_ApMode) & AP_MODE_G_ONLY)) {
		// 2G Only
		u8 threshold_lo_cap = 77;
		r1 = minRSSI - wlpptr->cck_des.cck_des_conf.rssi_margin;
		threshold = (r1 > wlpptr->cck_des.cck_des_conf.threshold_ceiling) ? -wlpptr->cck_des.cck_des_conf.threshold_ceiling : -r1;

		// Set lower bound for phase 2 algorithm.
		if ((threshold > threshold_lo_cap) && (wlpptr->cck_des.loadcfg.enable))
			threshold = threshold_lo_cap;

		wlpptr->cck_des.cck_des_conf.threshold = threshold;
		wlFwNewDP_RxSOP(netdev, 4, threshold, 0);
	}

	if (wlpptr->cck_des.rx_abort_conf.enable) {
		u8 threshold_lo_cap = ((Is5GBand(*(wlpptr->vmacSta_p->Mib802dot11->mib_ApMode))) ? 82 : 77);
		r2 = minRSSI - wlpptr->cck_des.rx_abort_conf.rssi_margin;
		threshold = (r2 > wlpptr->cck_des.rx_abort_conf.threshold_ceiling) ? -wlpptr->cck_des.rx_abort_conf.threshold_ceiling : -r2;

		// Set lower bound for phase 2 algorithm
		if ((threshold > threshold_lo_cap) && (wlpptr->cck_des.loadcfg.enable))
			threshold = threshold_lo_cap;

		wlpptr->cck_des.rx_abort_conf.threshold = threshold;
		wlpptr->smacCfgAddr->rssiAbortThres = threshold;
		wlpptr->smacCfgAddr->rssiAbortEn = 1;
	}

}

void cck_desense_ctrl(struct net_device *netdev, int cmd)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	u8 enable;

	enable = (wlpptr->cck_des.cck_des_conf.enable || wlpptr->cck_des.rx_abort_conf.enable) ? 1 : 0;
	if (!enable && cmd != CCK_DES_OFF)
		return;

	switch (cmd) {
	case CCK_DES_OFF:
		if (wlpptr->cck_des.loadcfg.enable && wlpptr->cck_des.state == CCK_DES_STATE_ON) {
			if (!(wlpptr->cck_des.off_reason & (CCK_DES_OFF_LOW_TRAFFIC | CCK_DES_OFF_LOW_CCA))) {
				return;
			}
		}
		/* cmd: Off */
		wlFwNewDP_RxSOP(netdev, 4, 0, 0);

		wlpptr->smacCfgAddr->rssiAbortEn = 0;

		wlpptr->cck_des.state &= ~CCK_DES_STATE_ON;
		wlpptr->cck_des.auth_cnt = 0;
		break;

	case CCK_DES_ON:
		/* cmd: On */
		if (wlpptr->cck_des.loadcfg.enable && !(wlpptr->cck_des.state & CCK_DES_STATE_ON)) {
			/* Keep OFF for low tx tp and low ch load case */
			if (wlpptr->cck_des.off_reason & (CCK_DES_OFF_LOW_TRAFFIC | CCK_DES_OFF_LOW_CCA)) {
				wlpptr->cck_des.cycles = 0;
				return;
			}
		}

		wlpptr->cck_des.cycles %= wlpptr->cck_des.update_cycles;

		if (wlpptr->cck_des.state & CCK_DES_STATE_ASSOC || wlpptr->cck_des.cycles == 0
		    || wlpptr->cck_des.off_reason & CCK_DES_OFF_NO_STA_CONNECTED) {
			cck_desense_run(netdev);
		} else {
			if (wlpptr->cck_des.cck_des_conf.enable && (*(wlpptr->vmacSta_p->Mib802dot11->mib_ApMode) & AP_MODE_G_ONLY)) {
				/* CCK desense On */
				wlFwNewDP_RxSOP(netdev, 4, wlpptr->cck_des.cck_des_conf.threshold, 0);
			}

			if (wlpptr->cck_des.rx_abort_conf.enable) {
				/* Rx abort On */
				wlpptr->smacCfgAddr->rssiAbortThres = wlpptr->cck_des.rx_abort_conf.threshold;
				wlpptr->smacCfgAddr->rssiAbortEn = 1;
			}
		}

		if (!(wlpptr->cck_des.off_reason & CCK_DES_OFF_NO_STA_CONNECTED)) {
			wlpptr->cck_des.state = CCK_DES_STATE_ON;
			wlpptr->cck_des.cycles += 1;
			wlpptr->cck_des.auth_cnt = 0;
		} else
			wlpptr->cck_des.cycles = 0;
		break;

	case CCK_DES_RUN:
		/* cmd: run now. threshold calculating and configuring */
		cck_desense_run(netdev);
		break;

	case CCK_DES_DISASSOC:
		/* cmd: STA disassoc. Run threshold calculating and configuring */
		if (wlpptr->cck_des.loadcfg.enable)
			cck_desense_run(netdev);
		else
			wlpptr->cck_des.state |= CCK_DES_STATE_ASSOC;	// Schedule to run recal in next ON
		break;

	case CCK_DES_ASSOC_RSP:
		/* cmd: STA assoc. */
		if (wlpptr->cck_des.loadcfg.enable && !(wlpptr->cck_des.state & CCK_DES_STATE_ON)) {
			if (wlpptr->cck_des.auth_cnt > 0)
				wlpptr->cck_des.auth_cnt -= 1;
		}

		wlpptr->cck_des.state |= CCK_DES_STATE_ASSOC;
		break;

	case CCK_DES_AUTH_REQ:
		/* cmd: Auth Req is in process */
		if (wlpptr->cck_des.loadcfg.enable && !(wlpptr->cck_des.state & CCK_DES_STATE_ON)) {
			wlpptr->cck_des.auth_cnt += 1;
		}
		break;

	default:
		break;

	}

}

void cck_desense_timer_func(unsigned long data)
{
	struct wlprivate *wlpptr = (struct wlprivate *)data;
	unsigned long t = 0;

	if (wlpptr != NULL) {
		if (!wlpptr->cck_des.timer_start)
			return;

		if (wlpptr->cck_des.on_time_ms > 0) {
			if (!(wlpptr->cck_des.state & CCK_DES_STATE_ON) || !(wlpptr->cck_des.off_time_ms)) {
				/* CCK-desense: current state Off, enter state On */
				if (!wlpptr->cck_des.auth_cnt) {
					/* no auth req in OFF state */
					cck_desense_ctrl(wlpptr->netDev, CCK_DES_ON);
					if (!wlpptr->cck_des.loadcfg.enable || wlpptr->cck_des.state & CCK_DES_STATE_ON
					    || !(wlpptr->cck_des.off_time_ms))
						t = wlpptr->cck_des.on_time_ms;
					else
						t = wlpptr->cck_des.off_time_ms;
				} else {
					/* reserve auth_tims_ms to process auth/assoc seq for all auth req in OFF state */
					t = wlpptr->cck_des.auth_time_ms;
					wlpptr->cck_des.auth_cnt = 0;
				}
			} else {
				if (wlpptr->cck_des.off_time_ms > 0) {
					/*CCK-desense: current state On, enter state Off */
					wlpptr->cck_des.off_reason |= CCK_DES_OFF_TIMER;
					cck_desense_ctrl(wlpptr->netDev, CCK_DES_OFF);
					t = wlpptr->cck_des.off_time_ms;
				}
			}

			wlpptr->cck_des.timer.expires = jiffies + t * HZ / 1000;
			add_timer(&wlpptr->cck_des.timer);
		}
	}
}

void cck_desense_polltimer_func(unsigned long data)
{
	struct wlprivate *wlpptr = (struct wlprivate *)data;
	u8 index;
	u32 tx_bytes;
	mvl_status_t rf_status;
	u8 datalen = CCK_DES_POLLDATA_SIZE;

	if (wlpptr != NULL) {
		if (!wlpptr->cck_des.loadcfg.polltimer_start)
			return;

		/* save tx bps */
		tx_bytes = wlpptr->wlpd_p->wl_tpprofile.tx.bytes;
		if (wlpptr->cck_des.loadcfg.data.tx_bytes > 0) {
			index = wlpptr->cck_des.loadcfg.data.txbps_idx;
			wlpptr->cck_des.loadcfg.data.txbps[index] = (tx_bytes - wlpptr->cck_des.loadcfg.data.tx_bytes) * 8 / 100;
			wlpptr->cck_des.loadcfg.data.tx_bytes = tx_bytes;
			wlpptr->cck_des.loadcfg.data.txbps_idx = (index + 1) % datalen;
		} else {
			wlpptr->cck_des.loadcfg.data.tx_bytes = tx_bytes;
		}

		if (!(wlpptr->cck_des.state & CCK_DES_STATE_ON)) {
			index = wlpptr->cck_des.loadcfg.data.cca_idx;
			/* save ch load whe cck_des OFF */
			memset(&rf_status, 0, sizeof(rf_status));
			if (wlFwGetRadioStatus(wlpptr->netDev, &rf_status) == SUCCESS) {
				wlpptr->cck_des.loadcfg.data.cca[index] = rf_status.rxload;
				wlpptr->cck_des.loadcfg.data.cca_idx = (index + 1) % datalen;
			}
		}

		cck_desesne_check_stats(wlpptr);
		if ((wlpptr->cck_des.state & CCK_DES_STATE_ON) && (wlpptr->cck_des.off_reason & (CCK_DES_OFF_LOW_TRAFFIC | CCK_DES_OFF_LOW_CCA))) {

			wlpptr->cck_des.off_reason &= ~CCK_DES_OFF_TIMER;
			cck_desense_ctrl(wlpptr->netDev, CCK_DES_OFF);

			if (wlpptr->cck_des.off_time_ms > 0) {
				/* T_off is non-zero */
				unsigned long expires = jiffies + wlpptr->cck_des.off_time_ms * HZ / 1000;

				mod_timer_pending(&wlpptr->cck_des.timer, expires);
			}
		}

		wlpptr->cck_des.loadcfg.polltimer.expires = jiffies + wlpptr->cck_des.loadcfg.poll_time_ms * HZ / 1000;
		add_timer(&wlpptr->cck_des.loadcfg.polltimer);
	}
}

void cck_desense_polltimer_start(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);

	if (wlpptr->cck_des.loadcfg.enable && !wlpptr->cck_des.loadcfg.polltimer_start &&
	    wlpptr->cck_des.loadcfg.poll_time_ms > 0 && !timer_pending(&wlpptr->cck_des.loadcfg.polltimer)) {

		memset(&wlpptr->cck_des.loadcfg.data, 0, sizeof(wlpptr->cck_des.loadcfg.data));

		wlpptr->cck_des.loadcfg.polltimer.data = (unsigned long)wlpptr;
		wlpptr->cck_des.loadcfg.polltimer.function = cck_desense_polltimer_func;
		wlpptr->cck_des.loadcfg.polltimer.expires = jiffies + wlpptr->cck_des.loadcfg.poll_time_ms * HZ / 1000;
		add_timer(&wlpptr->cck_des.loadcfg.polltimer);
		wlpptr->cck_des.loadcfg.polltimer_start = 1;
	}

}

void cck_desense_polltimer_stop(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);

	if (!wlpptr->cck_des.loadcfg.polltimer_start)
		return;

	del_timer_sync(&wlpptr->cck_des.loadcfg.polltimer);
	/* clean low tracffic/cca flags */
	wlpptr->cck_des.off_reason &= ~(CCK_DES_OFF_LOW_TRAFFIC | CCK_DES_OFF_LOW_CCA);
	wlpptr->cck_des.loadcfg.polltimer_start = 0;
}

void cck_desense_timer_start(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	int enable;
	unsigned long t = 0;

	enable = (wlpptr->cck_des.cck_des_conf.enable || wlpptr->cck_des.rx_abort_conf.enable) ? 1 : 0;
	if (enable && !wlpptr->cck_des.timer_start && wlpptr->cck_des.on_time_ms > 0) {
		if (!timer_pending(&wlpptr->cck_des.timer)) {
			if (!(wlpptr->cck_des.state & CCK_DES_STATE_ON) || !(wlpptr->cck_des.off_time_ms)) {
				/* CCK-desense: current state Off, enter state On */
				cck_desense_ctrl(netdev, CCK_DES_ON);
				if (!wlpptr->cck_des.loadcfg.enable || wlpptr->cck_des.state & CCK_DES_STATE_ON || !(wlpptr->cck_des.off_time_ms))
					t = wlpptr->cck_des.on_time_ms;
				else
					t = wlpptr->cck_des.off_time_ms;
			} else {
				if (wlpptr->cck_des.off_time_ms > 0) {
					/*CCK-desense: current state On, enter state Off */
					wlpptr->cck_des.off_reason |= CCK_DES_OFF_TIMER;
					cck_desense_ctrl(netdev, CCK_DES_OFF);
					t = wlpptr->cck_des.off_time_ms;
				}
			}
			wlpptr->cck_des.timer.expires = jiffies + t * HZ / 1000;
			wlpptr->cck_des.timer.data = (unsigned long)wlpptr;
			wlpptr->cck_des.timer.function = cck_desense_timer_func;
			add_timer(&wlpptr->cck_des.timer);
			wlpptr->cck_des.timer_start = 1;
		}

		cck_desense_polltimer_start(netdev);
	}
}

void cck_desense_timer_stop(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	u32 ivap;
	int enable;

	if (!wlpptr->cck_des.timer_start)
		return;

	enable = (wlpptr->cck_des.cck_des_conf.enable || wlpptr->cck_des.rx_abort_conf.enable) ? 1 : 0;
	if (enable) {
		/* Return if any VAP is running */
		for (ivap = 0; ivap < wlpd_p->NumOfAPs; ivap++) {
			if (wlpptr->vdev[ivap] != NULL && (wlpptr->vdev[ivap]->flags & IFF_RUNNING))
				return;
		}
	}

	cck_desense_polltimer_stop(netdev);

	del_timer_sync(&wlpptr->cck_des.timer);
	wlpptr->cck_des.timer_start = 0;

	/* disbale cck-desense/rx_abort */
	wlpptr->cck_des.off_reason |= CCK_DES_OFF_TIMER;
	cck_desense_ctrl(netdev, CCK_DES_OFF);

}
#endif				/* CCK_DESENSE */

#ifdef SOC_W906X
#include "shal_stats.h"
#include "ap8xLnxFwcmd.h"
extern int wlxmit(struct net_device *netdev, struct sk_buff *skb, UINT8 typeAndBits,
		  extStaDb_StaInfo_t * pStaInfo, UINT32 bcast, BOOLEAN eap, UINT8 nullpkt);

int StaKeepAliveCheck(vmacApInfo_t * vmacSta_p, extStaDb_StaInfo_t * StaInfo_p, int cmd)
{
	vmacApInfo_t *vmacAp_p = NULL;
	struct wlprivate *wlpptr = NULL;
	int retval = 0;
	SMAC_STA_STATISTICS_st StaStatsTbl;

	if (!vmacSta_p || !StaInfo_p)
		goto ret;

	if (StaInfo_p->StnId >= sta_num)
		goto ret;

	if ((vmacAp_p = vmacGetMBssByAddr(vmacSta_p, StaInfo_p->Bssid)) == NULL)
		goto ret;

	wlpptr = NETDEV_PRIV_P(struct wlprivate, vmacAp_p->dev);

	if (cmd == 0) {
		/* reset tx succ cnt */
		wlpptr->wlpd_p->sta_tx_succ[StaInfo_p->StnId] = 0;
		wlpptr->wlpd_p->sta_keep_alive_tx_succ[StaInfo_p->StnId] = 0;
		retval = 1;
		goto ret;
	}

	if (wlFwGetStaStats(vmacAp_p->dev, StaInfo_p->StnId, &StaStatsTbl) != SUCCESS) {
		WLDBG_INFO(DBG_LEVEL_11, "cannot get StnId %d stats from fw%d\n", StaInfo_p->StnId);
		goto ret;
	}

	if (wlpptr->wlpd_p->sta_tx_succ[StaInfo_p->StnId] > 0)
		wlpptr->wlpd_p->sta_keep_alive_tx_succ[StaInfo_p->StnId] +=
		    StaStatsTbl.dot11SuccessCount - wlpptr->wlpd_p->sta_tx_succ[StaInfo_p->StnId];

	wlpptr->wlpd_p->sta_tx_succ[StaInfo_p->StnId] = StaStatsTbl.dot11SuccessCount;

	if (cmd == 1) {
		/* send test pkt */
		if (!wlpptr->wlpd_p->mmdu_data_enable) {
			extern int wlFwSendFrame(struct net_device *netdev, UINT16 staIdx, UINT8 reportId, UINT8 tid,
						 UINT32 rateInfo, UINT8 machdrLen, UINT16 payloadLen, UINT8 * pMacHdr, UINT8 * pData);

			IEEEtypes_fullHdr_t *Hdr_p;
			UINT8 *buf = (UINT8 *) wl_kzalloc(64, GFP_ATOMIC);
			u32 hdrlen;
			u32 txrate;
			u8 tid;

			if (!buf)
				goto ret;

			memset(buf, 0, 64);

			Hdr_p = (IEEEtypes_fullHdr_t *) buf;
			Hdr_p->FrmCtl.Type = IEEE_TYPE_DATA;

			if (*(vmacSta_p->Mib802dot11->QoSOptImpl) && StaInfo_p->IsStaQSTA) {
				/* wmm enabled */
				Hdr_p->FrmCtl.Subtype = QoS_NULL_DATA;
				Hdr_p->qos = 0x6;	//AC_VO
				hdrlen = 26;
				tid = 0x6;
			} else {
				/* wmm disabled */
				Hdr_p->FrmCtl.Subtype = NULL_DATA;
				hdrlen = 24;
				tid = 0;
			}

			Hdr_p->FrmCtl.FromDs = 1;
			Hdr_p->FrmCtl.ToDs = 0;
			memcpy(Hdr_p->Addr1, StaInfo_p->Addr, IEEEtypes_ADDRESS_SIZE);
			memcpy(Hdr_p->Addr2, vmacAp_p->macStaAddr, IEEEtypes_ADDRESS_SIZE);
			memcpy(Hdr_p->Addr3, vmacAp_p->macStaAddr, IEEEtypes_ADDRESS_SIZE);

			if (*(vmacSta_p->Mib802dot11->mib_ApMode) & AP_MODE_A_ONLY)
				txrate = 0x0f010400;	// 5G/6Mbps
			else
				txrate = 0x0f010000;	// 2G/1Mbps

			if (wlFwSendFrame(vmacAp_p->dev, StaInfo_p->StnId, 1, tid, txrate, hdrlen, 0, (UINT8 *) buf, NULL) != SUCCESS) {
				WLDBG_ERROR(DBG_LEVEL_11, "sent test NULL data pkt to sta %d fail\n", StaInfo_p->StnId);
				wl_kfree(buf);
				goto ret;
			}
			wl_kfree(buf);
		} else {
			struct sk_buff *skb = NULL;
			ether_hdr_t *ethHdr = NULL;

			if ((skb = wl_alloc_skb(ETH_HLEN + TXBUF_ALIGN + SKB_INFO_SIZE)) == NULL) {
				WLDBG_INFO(DBG_LEVEL_11, "Error: cannot get socket buffer. \n ");
				goto ret;
			}
			skb_reserve(skb, SKB_INFO_SIZE - ETH_HLEN);
			skb_put(skb, ETH_HLEN + TXBUF_ALIGN);
			memset(skb->data, 0, skb->len);

			ethHdr = (ether_hdr_t *) skb->data;
			MACADDR_CPY(&ethHdr->da, StaInfo_p->Addr);
			MACADDR_CPY(&ethHdr->sa, vmacAp_p->macStaAddr);
			ethHdr->type = IEEE_QOS_CTL_AMSDU;

			// via eap=1 path to disable ampdu tx for this NDP
			if ((skb = ieee80211_encap(skb, vmacAp_p->dev, 1, StaInfo_p)) == NULL)
				goto ret;

			SPIN_LOCK_BH(&wlpptr->wlpd_p->locks.xmitLock);
			wlxmit(vmacAp_p->dev, skb, IEEE_TYPE_DATA, StaInfo_p, 0, 0, 1);
			SPIN_UNLOCK_BH(&wlpptr->wlpd_p->locks.xmitLock);
		}

		retval = 1;

	} else if (cmd == 2) {
		/* check tx succ cnt */
		if (wlpptr->wlpd_p->sta_keep_alive_tx_succ[StaInfo_p->StnId] > 0) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)
			vmacAp_p->dev->last_rx = jiffies;	//Update last_rx of the VAP
#endif
			retval = 1;
		}
	}
 ret:
	return retval;
}
#endif				/* SOC_W906X */
