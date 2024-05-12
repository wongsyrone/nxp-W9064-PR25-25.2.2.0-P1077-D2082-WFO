/** @file 1905.c
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
 * \file    1905.c
 * \brief   Multi-AP management
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
#include "StaDb.h"
#include "ap8xLnxIoctl.h"
#include "ap8xLnxFwcmd.h"

#ifdef CLIENT_SUPPORT
#include "linkmgt.h"
#include "mlme.h"
#include "mlmeApi.h"
#endif

#ifdef IEEE80211K
#include "msan_report.h"
#endif //IEEE80211K

#include "1905.h"

#ifdef MULTI_AP_SUPPORT

/*=============================================================================
 *                                DEFINITIONS
 *=============================================================================
*/

/*=============================================================================
 *                         IMPORTED PUBLIC VARIABLES
 *=============================================================================
 */
extern UINT8 getDialogToken(void);

extern struct sk_buff *mlmeApiPrepMgtMsg2(UINT32 Subtype,
					  IEEEtypes_MacAddr_t * DestAddr,
					  IEEEtypes_MacAddr_t * SrcAddr,
					  UINT16 size);
extern BOOLEAN bsstm_process_request(struct net_device *netdev,
				     IEEEtypes_MacAddr_t * destaddr,
				     struct sk_buff *skb);

/*=============================================================================
 *                          MODULE LEVEL VARIABLES
 *=============================================================================
 */
static UINT8 MAP_BcnReport_Token[16];

/*=============================================================================
 *                   PRIVATE PROCEDURES (ANSI Prototypes)
 *=============================================================================
 */
void
_map_hex_dump(const char *title, UINT8 * buf, UINT32 len)
{
	int i;
	printk("%s - %s - hexdump(len=%lu):\n", "[1905]", title,
	       (unsigned long)len);
	if (buf == NULL) {
		printk(" [NULL]");
	} else {
		for (i = 0; i < len; i++) {
			printk(" %02x", buf[i]);
			if ((i + 1) % 16 == 0)
				printk("\n");
		}
	}
	printk("\n");
}

static void
_map_add_token(UINT8 token)
{
	UINT8 index;

	for (index = 0; MAP_BcnReport_Token[index] != 0 && index < 16;
	     index++) ;
	if (index >= 16) {	// full token
		memcpy(&(MAP_BcnReport_Token[0]), &(MAP_BcnReport_Token[8]), 8);
		memset(&(MAP_BcnReport_Token[8]), 0, 8);
		index = 8;	// clear the previous 8 tokens.
	}
	MAP_BcnReport_Token[index] = token;
}

static UINT8
_map_del_token(UINT8 token)
{
	UINT8 i, j;

	for (i = 0; MAP_BcnReport_Token[i] != token && i < 16; i++) ;
	if (i < 16) {		// full token
		for (j = i; j < 16; j++) {
			if (j == 15) {
				MAP_BcnReport_Token[j] = 0;
			} else {
				MAP_BcnReport_Token[j] =
					MAP_BcnReport_Token[j + 1];
			}
			if (MAP_BcnReport_Token[j] == 0) {
				break;
			}
		}
	}

	return i;
}

/*============================================================================= 
 *                         CODED PROCEDURES 
 *=============================================================================
 */

#ifdef AP_STEERING_SUPPORT
void
MAP_tlv_AP_metrics_process(IEEEtypes_MacAddr_t * addr,
			   vmacApInfo_t * vmac_p,
			   unsigned char *buf, UINT16 * buf_len)
{
	struct MultiAP_AP_LM_Resp_Element_t *tlv_resp = NULL;
	struct wlreq_qbss_load QbssReq;
	UINT8 *pos = NULL;
	UINT16 len = 0;

	if (IW_CUSTOM_MAX - *buf_len <
	    sizeof(struct MultiAP_AP_LM_Resp_Element_t) +
	    (sizeof(struct IEEEtypes_ESP_info_field_t) * 4)) {
		printk("MAP_TLV_AP_LM_RESP not enough buffer size!!!\n");
		return;
	}

	memset(&QbssReq, 0, sizeof(struct wlreq_qbss_load));
	wlFwGetQBSSLoad(vmac_p->dev, &QbssReq.channel_util, &QbssReq.sta_cnt);

	pos = buf + *buf_len;
	tlv_resp = (struct MultiAP_AP_LM_Resp_Element_t *)pos;
	tlv_resp->tlv.tlvType = MAP_TLV_AP_LM_RESP;
	memcpy(tlv_resp->bssid, addr, sizeof(IEEEtypes_MacAddr_t));
	tlv_resp->channel_util = QbssReq.channel_util;
	tlv_resp->STA_num = QbssReq.sta_cnt;
	tlv_resp->AC_BE = 1;
	tlv_resp->AC_BK = 1;
	tlv_resp->AC_VO = 1;
	tlv_resp->AC_VI = 1;
	tlv_resp->AC_EST[0].ACI = 0;
	tlv_resp->AC_EST[0].BA_WinSize = 6;
	tlv_resp->AC_EST[1].ACI = 1;
	tlv_resp->AC_EST[1].BA_WinSize = 6;
	tlv_resp->AC_EST[2].ACI = 2;
	tlv_resp->AC_EST[2].BA_WinSize = 6;
	tlv_resp->AC_EST[3].ACI = 3;
	tlv_resp->AC_EST[3].BA_WinSize = 6;
	len = sizeof(struct MultiAP_AP_LM_Resp_Element_t) +
		(sizeof(struct IEEEtypes_ESP_info_field_t) * 4) -
		sizeof(struct MultiAP_TLV_Element_t);
	tlv_resp->tlv.tlvLen = len;

	*buf_len += (len + sizeof(struct MultiAP_TLV_Element_t));
}
#endif /* AP_STEERING_SUPPORT */

void
MAP_tlv_STA_traffic_stats_process(vmacApInfo_t * vmac_p,
				  unsigned char *buf, UINT16 * buf_len)
{
	struct MultiAP_STA_TS_Resp_Element_t *tlv_resp = NULL;
	vmacApInfo_t *vmacSta_p;
	extStaDb_StaInfo_t *StaInfo_p;
	ExtStaInfoItem_t *Curr_p, *Item_p;
	unsigned long dbflags;
	UINT8 *pos = NULL;
	UINT16 len = 0;

	if (IW_CUSTOM_MAX - *buf_len <
	    sizeof(struct MultiAP_STA_TS_Resp_Element_t) +
	    sizeof(struct MultiAP_STA_TS_Value_t)) {
		printk("MAP_TLV_AP_LM_RESP not enough buffer size!!!\n");
		return;
	}

	pos = buf + *buf_len;
	tlv_resp = (struct MultiAP_STA_TS_Resp_Element_t *)pos;
	tlv_resp->tlv.tlvType = MAP_TLV_STA_TRAFFIC_STATS;
	tlv_resp->tlv.tlvLen = 0;	/* reset before checking Associated STA Traffic Stats */
	pos += sizeof(struct MultiAP_TLV_Element_t);

	if (vmac_p->master)
		vmacSta_p = vmac_p->master;
	else
		vmacSta_p = vmac_p;

	SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);
	Curr_p = (ExtStaInfoItem_t *) (vmacSta_p->StaCtl->StaList.head);
	while (Curr_p != NULL) {
		Item_p = Curr_p;
		if ((StaInfo_p =
		     extStaDb_GetStaInfo(vmac_p, &(Item_p->StaInfo.Addr),
					 STADB_NO_BLOCK))) {
			if (StaInfo_p->State == ASSOCIATED) {
				struct MultiAP_STA_TS_Value_t *value = NULL;

				value = (struct MultiAP_STA_TS_Value_t *)pos;
				memcpy(value->mac_addr, StaInfo_p->Addr,
				       sizeof(IEEEtypes_MacAddr_t));
				value->BytesSent = 0;
				value->BytesReceived = 0;
				value->PacketsSent = 0;
				value->PacketsReceived = 0;
				value->TxPacketsErrors = 0;
				value->RxPacketsErrors = 0;
				value->RetransmissionCount = 0;
				len += sizeof(struct MultiAP_STA_TS_Value_t);
				pos += len;
			}
		}
		Curr_p = Curr_p->nxt;
	}
	SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);

	tlv_resp->tlv.tlvLen = len;
	*buf_len += (len + sizeof(struct MultiAP_TLV_Element_t));
}

void
MAP_tlv_STA_metrics_process(IEEEtypes_MacAddr_t * addr,
			    vmacApInfo_t * vmac_p,
			    unsigned char *buf, UINT16 * buf_len)
{
	struct MultiAP_STA_LM_Resp_Element_t *tlv_resp = NULL;
	vmacApInfo_t *vmacSta_p;
	extStaDb_StaInfo_t *StaInfo_p;
	ExtStaInfoItem_t *Curr_p, *Item_p;
	unsigned long dbflags;
	UINT8 *pos = NULL;
	UINT16 len = 0;

	pos = buf + *buf_len;
	tlv_resp = (struct MultiAP_STA_LM_Resp_Element_t *)pos;
	tlv_resp->tlv.tlvType = MAP_TLV_STA_LM_RESP;
	tlv_resp->tlv.tlvLen = 0;	/* reset before checking Associated STA link metrics */
	pos += sizeof(struct MultiAP_TLV_Element_t);

	if (vmac_p->master)
		vmacSta_p = vmac_p->master;
	else
		vmacSta_p = vmac_p;

	SPIN_LOCK_IRQSAVE(&vmacSta_p->StaCtl->dbLock, dbflags);
	Curr_p = (ExtStaInfoItem_t *) (vmacSta_p->StaCtl->StaList.head);
	while (Curr_p != NULL) {
		Item_p = Curr_p;
		if ((StaInfo_p =
		     extStaDb_GetStaInfo(vmac_p, &(Item_p->StaInfo.Addr),
					 STADB_NO_BLOCK))) {
			if (StaInfo_p->State == ASSOCIATED) {
				struct MultiAP_STA_LM_Value_t *value = NULL;
				struct MultiAP_STA_LM_Report_t *report = NULL;

				value = (struct MultiAP_STA_LM_Value_t *)pos;
				memcpy(value->mac_addr, StaInfo_p->Addr,
				       sizeof(IEEEtypes_MacAddr_t));
				value->num_bssid = 1;
				pos += sizeof(MultiAP_STA_LM_Value_t);
				report = (struct MultiAP_STA_LM_Report_t *)pos;
				memcpy(report->bssid, addr,
				       sizeof(IEEEtypes_MacAddr_t));
				report->delta_ms = 100;
				report->EST_downlink = 1;
				report->EST_uplink = 1;
				report->rssi_uplink = 10;
				len += (sizeof(struct MultiAP_STA_LM_Value_t) +
					sizeof(struct MultiAP_STA_LM_Report_t));
				pos += sizeof(struct MultiAP_STA_LM_Report_t);
			}
		}
		Curr_p = Curr_p->nxt;
	}
	SPIN_UNLOCK_IRQRESTORE(&vmacSta_p->StaCtl->dbLock, dbflags);

	tlv_resp->tlv.tlvLen = len;
	*buf_len += (len + sizeof(struct MultiAP_TLV_Element_t));
}

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
void
MAP_tlv_Query_process(vmacApInfo_t * vmac_p, MultiAP_TLV_Element_t * map_tlv)
{
	static const char *tag = "1905LM";
	unsigned char buf[IW_CUSTOM_MAX] = { 0 };
	union iwreq_data wreq;
	UINT16 msg_len = 0;

	snprintf(buf, sizeof(buf), "%s", tag);
	switch (map_tlv->tlvType) {
#ifdef AP_STEERING_SUPPORT
	case MAP_TLV_AP_LM_QUERY:
		{
			struct MultiAP_AP_LM_Query_Element_t *tlv_query =
				(struct MultiAP_AP_LM_Query_Element_t *)map_tlv;
			UINT8 index = 0;

			msg_len = strlen(tag);
			for (index = 0; index < tlv_query->BSSID_num; index++) {
				/* 17.2.22 AP Metrics TLV format */
				MAP_tlv_AP_metrics_process(&tlv_query->
							   bssid[index], vmac_p,
							   buf, &msg_len);

				/* 17.2.35 Associated STA Traffic Stats TLV */
				MAP_tlv_STA_traffic_stats_process(vmac_p, buf,
								  &msg_len);

				/* 17.2.24 Associated STA Link Metrics TLV format */
				MAP_tlv_STA_metrics_process(&tlv_query->
							    bssid[index],
							    vmac_p, buf,
							    &msg_len);
			}
		}
		break;
#endif /* AP_STEERING_SUPPORT */
	case MAP_TLV_STA_MAC_ADDR:
		{
			struct MultiAP_STA_LM_Query_Element_t *tlv_query =
				(struct MultiAP_STA_LM_Query_Element_t *)
				map_tlv;
			struct MultiAP_STA_LM_Resp_Element_t *tlv_resp = NULL;
			struct MultiAP_STA_LM_Report_t *report = NULL;
			UINT8 *pos = (buf + strlen(tag));
#ifdef IEEE80211K
			struct IEEEtypes_Neighbor_Report_Element_t *nlistbyssid
				= NULL;
			UINT8 index, nb_num = 0;

			nb_num = MSAN_get_neighbor_bySSID(&vmac_p->macSsId,
							  &nlistbyssid);
			tlv_resp = (struct MultiAP_STA_LM_Resp_Element_t *)pos;
			tlv_resp->tlv.tlvType = MAP_TLV_STA_LM_RESP;
			memcpy(tlv_resp->value[0].mac_addr, tlv_query->mac_addr,
			       sizeof(IEEEtypes_MacAddr_t));
			tlv_resp->value[0].num_bssid = nb_num;
			pos += sizeof(struct MultiAP_STA_LM_Resp_Element_t) +
				sizeof(struct MultiAP_STA_LM_Value_t);
			for (index = 0; index < nb_num; index++) {
				if ((pos - buf) >
				    (IW_CUSTOM_MAX -
				     (sizeof(struct MultiAP_STA_LM_Report_t))))
				{
					printk("MAP_TLV_STA_LM_RESP not enough buffer size!!!\n");
					break;
				}
				report = (struct MultiAP_STA_LM_Report_t *)pos;
				memcpy(report->bssid, nlistbyssid[index].Bssid,
				       sizeof(IEEEtypes_MacAddr_t));
				report->delta_ms = 100;
				report->EST_downlink = 1;
				report->EST_uplink = 1;
				report->rssi_uplink = 10;
				pos += sizeof(MultiAP_STA_LM_Report_t);
			}
#endif //IEEE80211K
			msg_len = (pos - buf);
			tlv_resp->tlv.tlvLen =
				msg_len - strlen(tag) -
				sizeof(struct MultiAP_TLV_Element_t);
		}
		break;
	case MAP_TLV_UNASSOC_STA_LM_QUERY:
		{
			struct MultiAP_Unassociated_STA_LM_Query_Element_t
				*tlv_query =
				(struct
				 MultiAP_Unassociated_STA_LM_Query_Element_t *)
				map_tlv;
			struct MultiAP_Unassociated_STA_LM_Resp_Element_t
				*tlv_resp = NULL;
			struct MultiAP_Unassociated_STA_LM_Report_t *report =
				NULL;
			UINT8 index = 0, ch_list_num;
			UINT8 *pos = (buf + strlen(tag));
			UINT8 *ch_list, *sta_mac_pos;

			tlv_resp =
				(struct
				 MultiAP_Unassociated_STA_LM_Resp_Element_t *)
				pos;
			tlv_resp->tlv.tlvType = MAP_TLV_UNASSOC_STA_LM_RESP;
			tlv_resp->op_class = tlv_query->op_class;
			ch_list = &tlv_query->variable[0];
			ch_list_num = tlv_query->channel_num;
			if (ch_list_num >
			    (tlv_resp->tlv.tlvLen -
			     sizeof
			     (MultiAP_Unassociated_STA_LM_Resp_Element_t))) {
				printk("MAP_TLV_STA_LM_RESP format error!!channel number is bigger than tlv length.\n");
				break;
			}
			tlv_resp->STA_num = tlv_query->variable[ch_list_num];
			sta_mac_pos = &tlv_query->variable[ch_list_num + 1];
			pos += sizeof
				(MultiAP_Unassociated_STA_LM_Resp_Element_t);

			for (index = 0;
			     index < tlv_resp->STA_num && *sta_mac_pos != 0;
			     index++) {
				if ((pos - buf) >
				    (IW_CUSTOM_MAX -
				     (sizeof
				      (struct
				       MultiAP_Unassociated_STA_LM_Report_t))))
				{
					printk("MAP_TLV_STA_LM_RESP not enough buffer size!!!\n");
					break;
				}
				report = (struct
					  MultiAP_Unassociated_STA_LM_Report_t
					  *)pos;
				memcpy(report->mac_addr, sta_mac_pos,
				       sizeof(IEEEtypes_MacAddr_t));
				sta_mac_pos += sizeof(IEEEtypes_MacAddr_t);
				report->channel = 36;
				report->delta_ms = 100;
				report->rssi_uplink = 10;
				pos += sizeof
					(MultiAP_Unassociated_STA_LM_Report_t);
			}
			msg_len = (pos - buf);
			tlv_resp->tlv.tlvLen =
				msg_len - strlen(tag) -
				sizeof(struct MultiAP_TLV_Element_t);
		}
		break;
#ifdef IEEE80211K
	case MAP_TLV_BEACON_LM_QUERY:
		{
			struct wlprivate *wlpptr =
				NETDEV_PRIV_P(struct wlprivate, vmac_p->dev);
			struct MultiAP_Beacon_LM_Query_Element_t *tlv_query =
				(struct MultiAP_Beacon_LM_Query_Element_t *)
				map_tlv;
			IEEEtypes_RadioMeasurementRequestElement_t
				*RequestElement;
			macmgmtQ_MgmtMsg2_t *MgmtMsg_p;
			IEEEtypes_BeaconRequest_t *bcn_req;
			extStaDb_StaInfo_t *StaInfo_p;
			struct sk_buff *skb;
			UINT16 len = 0;
			UINT8 index_h;
			UINT8 *var_pos;
			UINT8 *opt;

			/* check if STA support beacon report */
			if ((StaInfo_p =
			     extStaDb_GetStaInfo(vmac_p, &(tlv_query->mac_addr),
						 1)) == NULL ||
			    (StaInfo_p->State != ASSOCIATED)) {
				printk("MAP_TLV_BEACON_LM_QUERY cannot found STA info:%s\n", mac_display((UINT8 *) & (tlv_query->mac_addr)));
				/* The STA is unassociated */
				return;
			}

			if (!StaInfo_p->RRM_Cap_IE.BcnActMeasCap ||
			    !StaInfo_p->RRM_Cap_IE.BcnActMeasCap) {
				/* The STA does not support beacon report */
				printk("MAP_TLV_BEACON_LM_QUERY STA does not support beacon report (%d,%d)\n", StaInfo_p->RRM_Cap_IE.BcnActMeasCap, StaInfo_p->RRM_Cap_IE.BcnActMeasCap);
				MAP_tlv_Resp_process(vmac_p, NULL,
						     (IEEEtypes_MacAddr_t *) &
						     (tlv_query->mac_addr), 2);
				return;
			}
			skb = mlmeApiPrepMgtMsg2(IEEE_MSG_QOS_ACTION,
						 (IEEEtypes_MacAddr_t *)
						 tlv_query->mac_addr,
						 (IEEEtypes_MacAddr_t *)
						 vmac_p->dev->dev_addr, 512);
			if (skb == NULL) {
				printk("MAP_TLV_BEACON_LM_QUERY STA action allocate failed\n");
				return;
			}
			MgmtMsg_p = (macmgmtQ_MgmtMsg2_t *) skb->data;
			RequestElement =
				(IEEEtypes_RadioMeasurementRequestElement_t *)
				& MgmtMsg_p->Body.Action.Data.RadioMeasReq.
				RequestElement[0];

			MgmtMsg_p->Body.Action.Category = AC_RADIO_MEASUREMENT;
			MgmtMsg_p->Body.Action.Action =
				AF_RM_MEASUREMENT_REQUEST;
			MgmtMsg_p->Body.Action.DialogToken =
				wlpptr->wlpd_p->Global_DialogToken;
			wlpptr->wlpd_p->Global_DialogToken =
				(wlpptr->wlpd_p->Global_DialogToken + 1) % 63;
			MgmtMsg_p->Body.Action.Data.RadioMeasReq.
				NoOfRepetitions = 0;

			RequestElement->ElementId = MEASUREMENT_REQ;
			RequestElement->Token = getDialogToken();
			_map_add_token(RequestElement->Token);

			*(UINT8 *) & RequestElement->Mode = 0;
			RequestElement->Mode.DurMand = 1;
			RequestElement->Type = TYPE_REQ_BCN;

			bcn_req =
				(IEEEtypes_BeaconRequest_t *) & RequestElement->
				BcnReq;
			bcn_req->RegClass = tlv_query->op_class;
			bcn_req->Channel = tlv_query->channel_num;
			bcn_req->RandInt = 0;
			bcn_req->Dur = 200;	// TBD
			bcn_req->MeasMode = 1;	//0:passive, 1:active, 2:Beacon Table
			memcpy(bcn_req->Bssid, tlv_query->bssid,
			       sizeof(IEEEtypes_MacAddr_t));
			opt = (UINT8 *) & bcn_req->OptSubElem;
			var_pos = tlv_query->variable;
			/***** SSID Start  *******/
			if (var_pos[0] != 0) {
				struct IEEEtypes_SsIdElement_t *element =
					(struct IEEEtypes_SsIdElement_t *)opt;

				element->ElementId = SSID;
				element->Len = var_pos[0];
				memcpy(element->SsId, &var_pos[1], element->Len);	// SSID
				opt += element->Len + 2;
				var_pos += element->Len;
			}
			var_pos++;
			/***** SSID End  *******/
			/***** AP Channel Report Start *******/
			if (var_pos[0] != 0) {
				UINT8 ch_num = var_pos[0];	// Number of AP Channel Reports.

				for (index_h = 0; index_h < ch_num; index_h++) {
					struct IEEEtypes_ChannelReportEL_t
						*element =
						(struct
						 IEEEtypes_ChannelReportEL_t *)
						opt;

					var_pos++;	// Length of an AP Channel Report.
					if (var_pos[0]) {
						element->ElementId =
							CHAN_REPORT;
						element->Len = var_pos[0];	// include 1 octet of op class.
						element->RegClass = var_pos[1];
						memcpy(element->ChanList,
						       &var_pos[2],
						       (var_pos[0] - 1));
						opt += element->Len + 2;
						var_pos += element->Len;
					}
				}
			}
			var_pos++;
			/***** AP Channel Report End *******/
			/***** Reporting Detail Start *******/
			if (tlv_query->report_detail) {
				struct IEEEtypes_ReportingDetail_t *element =
					(struct IEEEtypes_ReportingDetail_t *)
					opt;
				element->ElementId = 2;
				element->Len = var_pos[0] + 1;
				element->reporting_detail_value =
					tlv_query->report_detail;
				if (var_pos[0] != 0) {
					memcpy(element->variable, &var_pos[1],
					       var_pos[0]);
				}
				opt += element->Len + 2;
				var_pos += element->Len;
			}
			/***** Reporting Detail End *******/
			len = opt - (UINT8 *) & bcn_req->OptSubElem;
			RequestElement->Len =
				3 + sizeof(IEEEtypes_BeaconRequest_t) + len - 1;
			skb_trim(skb,
				 sizeof(struct IEEEtypes_MgmtHdr2_t) + 23 +
				 len);
//                      _map_hex_dump("bcn_report_req", (uint8_t *)skb->data, sizeof(struct IEEEtypes_MgmtHdr2_t)+23+len);
			if (txMgmtMsg(vmac_p->dev, skb) != OS_SUCCESS) {
				_map_del_token(RequestElement->Token);
				wl_free_skb(skb);
			}
			return;
		}
		break;
#endif /* IEEE80211K */
	default:
		break;
	}
//      _map_hex_dump("1905_resp:", (uint8_t *)buf, msg_len);
	memset(&wreq, 0, sizeof(wreq));
	wreq.data.length = msg_len;
	wireless_send_event(vmac_p->dev, IWEVCUSTOM, &wreq, buf);
}

void
MAP_tlv_Resp_process(vmacApInfo_t * vmacSta_p, void *msg_data,
		     IEEEtypes_MacAddr_t * sta_mac_addr_p, UINT8 status)
{
	static const char *tag = "1905LM";
	unsigned char buf[1024] = { 0 };
	union iwreq_data wreq;
	struct macmgmtQ_MgmtMsg3_t *MgmtMsg_p =
		(struct macmgmtQ_MgmtMsg3_t *)msg_data;
	struct IEEEtypes_MeasurementReportElement_t *ie_p = NULL;
	struct MultiAP_Beacon_LM_Resp_Element_t *tlv_resp = NULL;
	UINT16 msg_len = 0;
	UINT8 index = 0;
	UINT8 *pos = NULL;

	msg_len = sizeof(struct IEEEtypes_MgmtHdr3_t) + 3;
	snprintf(buf, sizeof(buf), "%s", tag);
	pos = (buf + strlen(tag));
	tlv_resp = (struct MultiAP_Beacon_LM_Resp_Element_t *)pos;
	tlv_resp->tlv.tlvType = MAP_TLV_BEACON_LM_RESP;
	memcpy(tlv_resp->mac_addr, sta_mac_addr_p, sizeof(IEEEtypes_MacAddr_t));
	tlv_resp->status = status;
	tlv_resp->element_num = 0;
	pos += sizeof(struct MultiAP_Beacon_LM_Resp_Element_t);
	if (status != 0) {
		/*      00: Success - Beacon report received from STA
		   01: Failure - STA indicates support for 11k Beacon Report but no Beacon report received
		   10: Failure - STA does not indicate support for 11k Beacon Report
		   11: Failure - unspecified
		 */
		goto send_resp;
	}
	ie_p = (struct IEEEtypes_MeasurementReportElement_t *)&MgmtMsg_p->Body.
		Action.Data.MeasurementReport[0];
//      _map_hex_dump("bcn_report_resp", (uint8_t *)ie_p, ie_p->Len);

	while (msg_len < MgmtMsg_p->Hdr.FrmBodyLen) {
		if (ie_p == NULL) {
			break;
		}
		if (ie_p->Mode.Refused) {
			break;
		}
		index = _map_del_token(ie_p->MeasurementToken);
		if (index < 16) {
			tlv_resp->element_num++;
			memcpy(pos, ie_p, (ie_p->Len + 2));
		}
		msg_len += ie_p->Len + 2;
		pos += ie_p->Len + 2;
		ie_p = (struct IEEEtypes_MeasurementReportElement_t *)((UINT8 *)
								       ie_p +
								       ie_p->
								       Len + 2);
	}
send_resp:
	msg_len = (pos - buf);

	tlv_resp->tlv.tlvLen =
		msg_len - strlen(tag) - sizeof(struct MultiAP_TLV_Element_t);
//      _map_hex_dump("1905_resp:", (uint8_t *)buf, msg_len);
	memset(&wreq, 0, sizeof(wreq));
	wreq.data.length = msg_len;
	wireless_send_event(vmacSta_p->dev, IWEVCUSTOM, &wreq, buf);
}

/* CAC part */
/*=============================================================================
 *                         IMPORTED PUBLIC VARIABLES
 *=============================================================================
 */
#ifdef MRVL_DFS

#define DFS_DISABLED    0
#define DFS_ENABLED     1

extern int DecideDFSOperation(struct net_device *netdev,
			      BOOLEAN bChannelChanged,
			      BOOLEAN bBandWidthChanged, UINT8 currDFSState,
			      UINT8 newDFSState, MIB_802DOT11 * mib);
extern DFS_STATUS dfs_set_aux_ch(struct net_device *dev, UINT16 channel);
extern void set_dfs_ctl_status(DfsApDesc * dfsDesc_p, UINT8 path,
			       DFS_STATE status);
extern void FireEMCACTimer(DfsAp * me);
extern void EM_update_cac_status(vmacApInfo_t * vmacSta_p, UINT8 ch,
				 UINT8 status, UINT32 indication);

static cac_status_t CAC_STATUS;
static cac_complete_indication_t CAC_ind;
static UINT8 CAC_Scan_Flag = 0;
static UINT8 CAC_scan_ch_index = 0;
static UINT8 CAC_max_ch_num = 0;
static cac_channel_scan_list_t CSC_chList[DFS_MAX_CHANNELS];

void
EMCACTimeoutHandler(void *data_p)
{
	DfsAp *me;
	struct net_device *dev;
	struct wlprivate *wlpptr = NULL;
	struct wlprivate_data *wlpd_p = NULL;
	UINT8 ch;

	WLDBG_INFO(DBG_LEVEL_1, "enter EM CAC timeout handler\n");
	me = (DfsAp *) data_p;
	dev = me->pNetDev;
	wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
	wlpd_p = wlpptr->wlpd_p;
	me->scnr_ctl_evt(dev, ScnrCtl_CAC_Done, DFS_STATE_OPERATIONAL, 1);
	/* If the channel is NOL, put it into radar_channel_report */
	if (DfsFindInNOL
	    (&me->dfsApDesc.NOCList,
	     me->dfsApDesc.CtlChanInfo.channel) == DFS_FAILURE) {
		EM_update_cac_status(wlpptr->vmacSta_p,
				     me->dfsApDesc.CtlChanInfo.channel,
				     0 /*available channel */ ,
				     1 /*indecation */ );
	}
	if (me->dfsApDesc.EMCACState == DFS_STATE_EM_SCAN_ALL) {
		CAC_scan_ch_index++;
		if (CAC_scan_ch_index < CAC_max_ch_num) {
			ch = CSC_chList[CAC_scan_ch_index].channel;
			// restore the channel
			me->dfsApDesc.CtlChanInfo.channel = ch;
			// switch to new channel
			dfs_set_aux_ch(dev, ch);
			// Start Aux ch CAC
			if (ch != 36)
				FireEMCACTimer(wlpptr->wlpd_p->pdfsApMain);
			return;
		}
	}
	me->dfsApDesc.EMCACState = DFS_STATE_INIT;
	wlFwSetRadarDetection(dev, DR_DFS_DISABLE);
}

void
FireEMCACTimer(DfsAp * me)
{
	DfsApDesc *dfsDesc_p = NULL;
	struct net_device *dev;
	struct wlprivate *wlpptr = NULL;
	struct wlprivate_data *wlpd_p = NULL;
	vmacApInfo_t *vmacSta_p = NULL;
	MIB_802DOT11 *mib = NULL;

	if (me == NULL) {
		PRINT1(INFO, "FireEMCACTimer: error: NULL pointer\n");
		return;
	}
	dev = me->pNetDev;
	wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
	wlpd_p = wlpptr->wlpd_p;
	dfsDesc_p = (DfsApDesc *) & me->dfsApDesc;
	vmacSta_p = wlpptr->vmacSta_p;
	mib = vmacSta_p->ShadowMib802dot11;
	macMgmtMlme_StartAuxRadarDetection(dev, DR_SCANNER_SERVICE_START);
	if (*(mib->mib_CACTimeOut))
		dfsDesc_p->CtlCACTimeOut = (*(mib->mib_CACTimeOut)) * 10;
	EM_update_cac_status(wlpptr->vmacSta_p,
			     me->dfsApDesc.CtlChanInfo.channel,
			     6 /*on-going channel */ , 0 /*indecation */ );
	TimerFireIn(&dfsDesc_p->EMCACTimer, 1, &EMCACTimeoutHandler,
		    (unsigned char *)me, dfsDesc_p->CtlCACTimeOut);
	me->scnr_ctl_evt(dev, ScnrCtl_Channel_switch_start_cac, DFS_STATE_SCAN,
			 1);
	return;
}

void
DisarmEMCACTimer(DfsAp * me)
{
	DfsApDesc *dfsDesc_p = NULL;
	struct net_device *dev;
	struct wlprivate *wlpptr = NULL;
	struct wlprivate_data *wlpd_p = NULL;

	if (me == NULL) {
		PRINT1(INFO, "DisarmEMCACTimer: error: NULL pointer\n");
		return;
	}
	dev = me->pNetDev;
	wlpptr = NETDEV_PRIV_P(struct wlprivate, dev);
	wlpd_p = wlpptr->wlpd_p;
	dfsDesc_p = (DfsApDesc *) & me->dfsApDesc;
	TimerDisarm(&dfsDesc_p->EMCACTimer);
}

void
EM_remove_ch_from_available_report(UINT8 ch)
{
	UINT8 i;

	/* remove ch from available_channel_report */
	for (i = 0;
	     i < CAC_STATUS.available_channel_report.num_of_available_channel;
	     i++) {
		if (ch ==
		    CAC_STATUS.available_channel_report.
		    available_channel_info[i].channel) {
			break;
		}
	}
	if (i < CAC_STATUS.available_channel_report.num_of_available_channel) {
		for (;
		     i <
		     CAC_STATUS.available_channel_report.
		     num_of_available_channel; i++) {
			memcpy(&CAC_STATUS.available_channel_report.
			       available_channel_info[i],
			       &CAC_STATUS.available_channel_report.
			       available_channel_info[i + 1],
			       sizeof(cac_available_channel_t));
		}
		memset(&CAC_STATUS.available_channel_report.
		       available_channel_info[i], 0,
		       sizeof(cac_available_channel_t));
		CAC_STATUS.available_channel_report.num_of_available_channel--;
	}
}

void
EM_remove_ch_from_radar_report(UINT8 ch)
{
	UINT8 i;

	/* remove ch from radar_channel_report */
	for (i = 0; i < CAC_STATUS.radar_channel_report.num_of_radar_channel;
	     i++) {
		if (ch ==
		    CAC_STATUS.radar_channel_report.radar_channel_info[i].
		    channel) {
			break;
		}
	}
	if (i < CAC_STATUS.radar_channel_report.num_of_radar_channel) {
		for (; i < CAC_STATUS.radar_channel_report.num_of_radar_channel;
		     i++) {
			memcpy(&CAC_STATUS.radar_channel_report.
			       radar_channel_info[i],
			       &CAC_STATUS.radar_channel_report.
			       radar_channel_info[i + 1],
			       sizeof(cac_radar_channel_t));
		}
		memset(&CAC_STATUS.radar_channel_report.radar_channel_info[i],
		       0, sizeof(cac_radar_channel_t));
		CAC_STATUS.radar_channel_report.num_of_radar_channel--;
	}
}

void
EM_update_cac_status(vmacApInfo_t * vmacSta_p, UINT8 ch, UINT8 status,
		     UINT32 indication)
{
	struct wlprivate *wlpptr =
		NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev);
	DfsApDesc *dfsDesc_p;
	UINT8 op_class = 115;
	UINT8 i;

	dfsDesc_p = &wlpptr->wlpd_p->pdfsApMain->dfsApDesc;

	/* status = 0 is available channel, 1 is radar channel, 6 is on-going */
	memset(&CAC_STATUS.ongoing_channel_report.ongoing_channel_info[0], 0,
	       sizeof(cac_ongoing_channel_t));
	CAC_STATUS.ongoing_channel_report.num_of_ongoing_channel = 0;

	/* Update timestamp */
	for (i = 0; i < CAC_max_ch_num; i++) {
		if (CSC_chList[i].channel == dfsDesc_p->CtlChanInfo.channel) {
			CSC_chList[i].timestamp =
				ktime_to_timespec(ktime_get_real()).tv_sec;
			op_class = CSC_chList[i].op_class;
			break;
		}
	}

	switch (status) {
	case 0:
		{
			cac_available_channel_t *cac_channel = NULL;

			EM_remove_ch_from_radar_report(ch);

			for (i = 0; i < 30; i++) {
				cac_channel =
					&CAC_STATUS.available_channel_report.
					available_channel_info[i];
				if (cac_channel->channel == 0) {
					CAC_STATUS.available_channel_report.
						num_of_available_channel++;
					cac_channel->channel = ch;
					cac_channel->op_class = op_class;
					cac_channel->minutes = 0;
					break;
				}
				if (cac_channel->channel == ch) {
					cac_channel->channel = ch;
					cac_channel->op_class = op_class;
					cac_channel->minutes = 0;
					break;
				}
			}
		}
		break;
	case 1:
		{
			cac_radar_channel_t *cac_channel = NULL;

			/* remove ch from available_channel_report */
			EM_remove_ch_from_available_report(ch);

			/* add ch to radar_channel_report */
			for (i = 0; i < 30; i++) {
				cac_channel =
					&CAC_STATUS.radar_channel_report.
					radar_channel_info[i];
				if (cac_channel->channel == 0) {
					CAC_STATUS.radar_channel_report.
						num_of_radar_channel++;
					cac_channel->channel = ch;
					cac_channel->op_class = op_class;
					cac_channel->seconds = 0;
					break;
				}
				if (cac_channel->channel == ch) {
					cac_channel->channel = ch;
					cac_channel->op_class = op_class;
					cac_channel->seconds = 0;
					break;
				}
			}
		}
		break;
	case 6:
		{
			cac_ongoing_channel_t *cac_channel = NULL;

			EM_remove_ch_from_available_report(ch);
			EM_remove_ch_from_radar_report(ch);

			cac_channel =
				&CAC_STATUS.ongoing_channel_report.
				ongoing_channel_info[0];
			if (cac_channel->channel == 0) {
				CAC_STATUS.ongoing_channel_report.
					num_of_ongoing_channel = 1;
				cac_channel->channel = ch;
				cac_channel->op_class = op_class;
				cac_channel->seconds = 0;
				break;
			}
		}
		break;
	default:
		printk("%s status:%d failed\n", __func__, status);
		break;
	}
	if (indication && CAC_Scan_Flag) {
		static const char *tag = "1905_CAC_IND";
		unsigned char buf[1024] = { 0 };
		union iwreq_data wreq;
		UINT8 *pos = NULL;

		snprintf(buf, sizeof(buf), "%s", tag);
		pos = (buf + strlen(tag));

		strcpy(CAC_ind.dev_name, vmacSta_p->dev->name);
		CAC_ind.channel = ch;
		CAC_ind.op_class = op_class;
		CAC_ind.status = status;

		memcpy(pos, &CAC_ind, sizeof(cac_complete_indication_t));
		memset(&wreq, 0, sizeof(wreq));
		wreq.data.length =
			sizeof(cac_complete_indication_t) + strlen(tag);
		wireless_send_event(vmacSta_p->dev, IWEVCUSTOM, &wreq, buf);
	}
}

SINT32
EM_get_cac_status(UINT8 * buf, UINT8 log)
{
	SINT32 cur_time;
	UINT8 i, ch_index, found;

	cur_time = ktime_to_timespec(ktime_get_real()).tv_sec;
	for (ch_index = 0; ch_index < CAC_max_ch_num; ch_index++) {
		found = 0;
		for (i = 0;
		     i <
		     CAC_STATUS.available_channel_report.
		     num_of_available_channel; i++) {
			if (CSC_chList[ch_index].channel ==
			    CAC_STATUS.available_channel_report.
			    available_channel_info[i].channel) {
				found = 1;
				CAC_STATUS.available_channel_report.
					available_channel_info[i].minutes =
					(cur_time -
					 CSC_chList[ch_index].timestamp) / 60;
				break;
			}
		}
		if (found) {
			continue;
		}
		for (i = 0;
		     i < CAC_STATUS.radar_channel_report.num_of_radar_channel;
		     i++) {
			if (CSC_chList[ch_index].channel ==
			    CAC_STATUS.radar_channel_report.
			    radar_channel_info[i].channel) {
				found = 1;
				CAC_STATUS.radar_channel_report.
					radar_channel_info[i].seconds =
					(cur_time -
					 CSC_chList[ch_index].timestamp);
				break;
			}
		}
		if (found) {
			continue;
		}
		for (i = 0;
		     i <
		     CAC_STATUS.ongoing_channel_report.num_of_ongoing_channel;
		     i++) {
			if (CSC_chList[ch_index].channel ==
			    CAC_STATUS.ongoing_channel_report.
			    ongoing_channel_info[i].channel) {
				CAC_STATUS.ongoing_channel_report.
					ongoing_channel_info[i].seconds =
					(cur_time -
					 CSC_chList[ch_index].timestamp);
				break;
			}
		}
	}

	if (log > 0) {
		printk("available_channel_report:\n");
		for (i = 0;
		     i <
		     CAC_STATUS.available_channel_report.
		     num_of_available_channel; i++) {
			printk("ch:%d,%d,%d\n",
			       CAC_STATUS.available_channel_report.
			       available_channel_info[i].op_class,
			       CAC_STATUS.available_channel_report.
			       available_channel_info[i].channel,
			       CAC_STATUS.available_channel_report.
			       available_channel_info[i].minutes);
		}
		printk("\nradar_channel_report:\n");
		for (i = 0;
		     i < CAC_STATUS.radar_channel_report.num_of_radar_channel;
		     i++) {
			printk("ch:%d,%d,%d\n",
			       CAC_STATUS.radar_channel_report.
			       radar_channel_info[i].op_class,
			       CAC_STATUS.radar_channel_report.
			       radar_channel_info[i].channel,
			       CAC_STATUS.radar_channel_report.
			       radar_channel_info[i].seconds);
		}
		printk("\nongoing_channel_report:\n");
		for (i = 0;
		     i <
		     CAC_STATUS.ongoing_channel_report.num_of_ongoing_channel;
		     i++) {
			printk("ch:%d,%d,%d\n",
			       CAC_STATUS.ongoing_channel_report.
			       ongoing_channel_info[i].op_class,
			       CAC_STATUS.ongoing_channel_report.
			       ongoing_channel_info[i].channel,
			       CAC_STATUS.ongoing_channel_report.
			       ongoing_channel_info[i].seconds);
		}
		printk("\n");
	}
	memcpy(buf, &CAC_STATUS, sizeof(cac_status_t));
	return sizeof(cac_status_t);
}

void
EM_get_dfs_ch_list(vmacApInfo_t * vmacSta_p, UINT8 op_class, UINT8 ch)
{
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	UINT8 domainCode, domainInd;
	UINT8 i, count = 0;

	/* status = 0 is available channel, 1 is radar channel, 2 is on-going */
	if (mib->PhyDSSSTable->Chanflag.FreqBand != FREQ_BAND_5GHZ) {
		WLDBG_ERROR(DBG_LEVEL_0, "%s This is not a 5GHz mode\n",
			    __func__);
		return;
	}

	domainCode = domainGetDomain();	// get current domain
	for (i = 0; i < domainGetSizeOfdfsEnabledChannels(); i++)
		if (domainCode == dfsEnabledChannels[i].domainCode)
			break;
	if (i == domainGetSizeOfdfsEnabledChannels()) {
		WLDBG_ERROR(DBG_LEVEL_0, "%s Could not find the domain\n",
			    __func__);
		return;
	}
	domainInd = i;

	for (i = 0; i < DFS_MAX_CHANNELS; i++) {
		if (dfsEnabledChannels[domainInd].dfschannelEntry[i] == 0) {
			continue;
		}
		CSC_chList[count].channel =
			dfsEnabledChannels[domainInd].dfschannelEntry[i];
		count++;
	}
	CAC_max_ch_num = count;
}

void
EM_CAC_Scan(vmacApInfo_t * vmacSta_p, UINT8 op_class, UINT8 ch, UINT8 enable)
{
	struct wlprivate *wlpptr =
		NETDEV_PRIV_P(struct wlprivate, vmacSta_p->dev);
	DfsApDesc *dfsDesc_p;
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	MIB_SPECTRUM_MGMT *mib_SpectrumMagament_p = mib->SpectrumMagament;
	UINT8 i;

	if (enable == 2) {
		/* Init all channel to available channel report */
		cac_available_channel_t *cac_channel = NULL;

		memset(&CAC_STATUS, 0, sizeof(cac_status_t));
		memset(&CSC_chList[0], 0,
		       sizeof(cac_channel_scan_list_t) * DFS_MAX_CHANNELS);
		/* get range to scan */
		EM_get_dfs_ch_list(vmacSta_p, op_class, ch);
		if (CAC_max_ch_num == 0) {
			WLDBG_ERROR(DBG_LEVEL_0, "%s available channel is 0\n",
				    __func__);
			return;
		}
		/* set op class */
		for (i = 0; i < CAC_max_ch_num && i < DFS_MAX_CHANNELS; i++) {
			if (CSC_chList[i].channel >= 36 &&
			    CSC_chList[i].channel <= 48) {
				CSC_chList[i].op_class = 115;
			} else if (CSC_chList[i].channel >= 52 &&
				   CSC_chList[i].channel <= 64) {
				CSC_chList[i].op_class = 118;
			} else if (CSC_chList[i].channel >= 100 &&
				   CSC_chList[i].channel <= 144) {
				CSC_chList[i].op_class = 121;
			} else if (CSC_chList[i].channel >= 149 &&
				   CSC_chList[i].channel <= 161) {
				CSC_chList[i].op_class = 124;
			}
			CSC_chList[i].timestamp =
				ktime_to_timespec(ktime_get_real()).tv_sec;

			cac_channel =
				&CAC_STATUS.available_channel_report.
				available_channel_info[i];
			CAC_STATUS.available_channel_report.
				num_of_available_channel++;
			cac_channel->channel = CSC_chList[i].channel;
			cac_channel->op_class = CSC_chList[i].op_class;
			cac_channel->minutes = 0;
		}
		return;
	}

	if (mib_SpectrumMagament_p->spectrumManagement == 0 && enable) {
		mib_SpectrumMagament_p->spectrumManagement = 1;
		mib_SpectrumMagament_p->multiDomainCapability = 1;
		if (DecideDFSOperation
		    (vmacSta_p->dev, TRUE, FALSE, DFS_DISABLED, DFS_ENABLED,
		     mib) == FAIL) {
			WLDBG_ERROR(DBG_LEVEL_0, "DecideDFSOperation Failed\n");
			return;
		}
	}

	if (wlpptr->wlpd_p->pdfsApMain == NULL) {
		WLDBG_ERROR(DBG_LEVEL_0,
			    "pdfsApMain is Null, not enable 11hspecmgt\n");
		return;
	}
	if (Is5GBand(*(mib->mib_ApMode)) == 0) {
		WLDBG_ERROR(DBG_LEVEL_0, "%s opmode:%d is not 5G mode\n",
			    vmacSta_p->dev->name, *(mib->mib_ApMode));
		return;
	}

	dfsDesc_p = &wlpptr->wlpd_p->pdfsApMain->dfsApDesc;
	CAC_Scan_Flag = enable;
	DisarmCACTimer(wlpptr->wlpd_p->pdfsApMain);
	DisarmAuxCACTimer(wlpptr->wlpd_p->pdfsApMain);
	if (enable == 0) {
		/* EasyMesh-CAC disable */
		wlpptr->wlpd_p->ext_scnr_en = 0;
		dfsDesc_p->EMCACState = DFS_STATE_INIT;
		wlFwSetRadarDetection(vmacSta_p->dev, DR_DFS_DISABLE);
		DisarmEMCACTimer(wlpptr->wlpd_p->pdfsApMain);
		if (DfsFindInNOL
		    (&dfsDesc_p->NOCList,
		     dfsDesc_p->CtlChanInfo.channel) == DFS_FAILURE) {
			EM_update_cac_status(wlpptr->vmacSta_p,
					     dfsDesc_p->CtlChanInfo.channel,
					     0 /*available channel */ ,
					     1 /*indecation */ );
		}
		return;
	}

	wlpptr->wlpd_p->ext_scnr_en = 1;
	if (ch == 0) {
		/* EasyMesh-CAC all channel scan */
		dfsDesc_p->EMCACState = DFS_STATE_EM_SCAN_ALL;
		memset(&CAC_STATUS, 0, sizeof(cac_status_t));
		memset(&CSC_chList[0], 0,
		       sizeof(cac_channel_scan_list_t) * DFS_MAX_CHANNELS);
		/* get range to scan */
		EM_get_dfs_ch_list(vmacSta_p, op_class, ch);
		if (CAC_max_ch_num == 0) {
			WLDBG_ERROR(DBG_LEVEL_0, "%s available channel is 0\n",
				    __func__);
			return;
		}
		/* set op class */
		for (i = 0; i < CAC_max_ch_num; i++) {
			if (CSC_chList[i].channel >= 36 &&
			    CSC_chList[i].channel <= 48) {
				CSC_chList[i].op_class = 115;
			} else if (CSC_chList[i].channel >= 52 &&
				   CSC_chList[i].channel <= 64) {
				CSC_chList[i].op_class = 118;
			} else if (CSC_chList[i].channel >= 100 &&
				   CSC_chList[i].channel <= 144) {
				CSC_chList[i].op_class = 121;
			} else if (CSC_chList[i].channel >= 149 &&
				   CSC_chList[i].channel <= 161) {
				CSC_chList[i].op_class = 124;
			}
		}
		CAC_scan_ch_index = 0;
		ch = CSC_chList[CAC_scan_ch_index].channel;
	} else {
		if (ch == 36 || ch == 149) {
			return;
		}
		dfsDesc_p->EMCACState = DFS_STATE_EM_SCAN;
		if (CAC_max_ch_num == 0) {
			memset(&CAC_STATUS, 0, sizeof(cac_status_t));
			memset(&CSC_chList[0], 0,
			       sizeof(cac_channel_scan_list_t) *
			       DFS_MAX_CHANNELS);
			/* get range to scan */
			EM_get_dfs_ch_list(vmacSta_p, op_class, ch);
		}
		/* set op class */
		for (i = 0; i < CAC_max_ch_num; i++) {
			if (CSC_chList[i].channel == ch) {
				CSC_chList[i].op_class = op_class;
				break;
			}
		}
	}
	// restore the channel
	dfsDesc_p->currChanInfo.channel = mib->PhyDSSSTable->CurrChan;
	dfsDesc_p->currChanInfo.chanflag.FreqBand = FREQ_BAND_5GHZ;
	dfsDesc_p->currChanInfo.chanflag.ChnlWidth = CH_20_MHz_WIDTH;
	dfsDesc_p->CtlChanInfo.channel = ch;
	dfsDesc_p->CtlChanInfo.chanflag.radiomode = RADIO_MODE_7x7p1x1;
	dfsDesc_p->CtlChanInfo.chanflag.FreqBand = FREQ_BAND_5GHZ;
	dfsDesc_p->CtlChanInfo.chanflag.ChnlWidth = CH_20_MHz_WIDTH;
	dfsDesc_p->CtlChanInfo.chanflag.FreqBand2 = FREQ_BAND_5GHZ;
	dfsDesc_p->CtlChanInfo.chanflag.ChnlWidth2 = CH_20_MHz_WIDTH;
	// switch to new channel
	dfs_set_aux_ch(vmacSta_p->dev, ch);

	// Start Aux ch CAC
	FireEMCACTimer(wlpptr->wlpd_p->pdfsApMain);
	set_dfs_ctl_status(dfsDesc_p, DFS_PATH_DEDICATED, DFS_STATE_SCAN);
}
#endif /* MRVL_DFS */

#endif /* MULTI_AP_SUPPORT */
