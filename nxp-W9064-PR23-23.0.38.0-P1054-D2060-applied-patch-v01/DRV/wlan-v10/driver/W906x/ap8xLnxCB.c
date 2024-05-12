/** @file ap8xLnxCB.c
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2019-2020 NXP
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
#ifdef CB_SUPPORT
#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/wireless.h>
#include <linux/ieee80211.h>
#include <linux/ctype.h>

#include "ap8xLnxIntf.h"
#include "ap8xLnxCB.h"
#include "ap8xLnxFwcmd.h"
#include "StaDb.h"

#define ENT_FUNC()	printk("=> %s()\n", __func__)
#define EXT_FUNC()	printk("<= %s()\n", __func__)

typedef struct _sta_info {
	IEEEtypes_MacAddr_t mac_addr;
	UINT32 Aid;
	UINT32 StnId;
	PeerInfo_t PeerInfo;
	UINT8 Qosinfo;
	UINT32 qosFlag;
	UINT32 wdsFlag;
	HostCmd_STA_CB_PARAMS_SYNC sta_cb_param;
//security_ap++
//      extStaDb_StaInfo_t      StaInfo;
	IEEEtypes_MacAddr_t Addr;
	keyMgmtInfo_t keyMgmtStateInfo;	//keyMgmtInfo;
#ifdef CONFIG_IEEE80211W
	UINT8 ptkCipherOuiType;
#endif
//security_ap--
} sta_info;

static void update_bcn_handler(struct net_device *netdev);
extern extStaDb_StaInfo_t *macMgtStaDbInit(vmacApInfo_t * vmacSta_p,
					   IEEEtypes_MacAddr_t * staMacAddr,
					   IEEEtypes_MacAddr_t * apMacAddr);
extern UINT16 extStaDb_entries(vmacApInfo_t * vmac_p, UINT8 flag);
extern void flush_any_pending_ampdu_pck(struct net_device *dev,
					extStaDb_StaInfo_t * pStaInfo);
/* 
 * get_handover_params_cmd: send HANDOVER_START command to target
 * sta_mac: station's MAC address
 */
void
get_handover_params_cmd(struct net_device *netdev, char *sta_mac)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	IEEEtypes_MacAddr_t sta_mac_addr;
	sta_info sta_info_v;
	extStaDb_StaInfo_t *StaInfo_p = NULL;

	//printk("=>%s(%s), sta_mac: %s\n", __func__, netdev->name, sta_mac);
	sscanf(sta_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
	       &sta_mac_addr[0], &sta_mac_addr[1], &sta_mac_addr[2],
	       &sta_mac_addr[3], &sta_mac_addr[4], &sta_mac_addr[5]);

	if ((StaInfo_p =
	     extStaDb_GetStaInfo(vmacSta_p, &sta_mac_addr,
				 STADB_UPDATE_AGINGTIME)) == NULL) {
		return;
	}

	sta_info_v.sta_cb_param.staid = StaInfo_p->StnId;
	wlFwGetStaCBParam(netdev, &(sta_info_v.sta_cb_param));

	sta_info_v.Aid = StaInfo_p->Aid;
	sta_info_v.StnId = StaInfo_p->StnId;
	//memcpy(&PeerInfo, mlme->PeerInfo, sizeof(mlme->PeerInfo));
	sta_info_v.Qosinfo = StaInfo_p->Qosinfo;
	sta_info_v.qosFlag = StaInfo_p->IsStaQSTA;
	sta_info_v.wdsFlag = 0;

	/*setStaPeerInfo(&sta_info_v.PeerInfo, 
	   StaInfo_p->ApMode,   //apmode
	   strArray_p->strArray[5],     //nss
	   strArray_p->strArray[6],     //bw
	   strArray_p->strArray[7]);    //gi
	 */
	memcpy((void *)&sta_info_v.PeerInfo, &StaInfo_p->PeerInfo,
	       sizeof(PeerInfo_t));
	//security_ap++
	//memcpy(&sta_info_v.StaInfo, StaInfo_p, sizeof(extStaDb_StaInfo_t));
	memcpy(sta_info_v.Addr, StaInfo_p->Addr, sizeof(IEEEtypes_MacAddr_t));
	memcpy(&sta_info_v.keyMgmtStateInfo, &StaInfo_p->keyMgmtStateInfo,
	       sizeof(keyMgmtInfo_t));
#ifdef CONFIG_IEEE80211W
	memcpy(&sta_info_v.ptkCipherOuiType, &StaInfo_p->ptkCipherOuiType,
	       sizeof(UINT8));
#endif //CONFIG_IEEE80211W

	//security_ap--

	// Flush all the saved rx-pkts
	flush_any_pending_ampdu_pck(netdev, StaInfo_p);

	wlFwSetNewStn(netdev, (u_int8_t *) sta_mac_addr, 0, 0, StaInfoDbActionRemoveEntry, NULL, 0, 0, 0);	//del station first

	FreeAid(vmacSta_p, StaInfo_p->Aid);
	FreeStnId(vmacSta_p, StaInfo_p->StnId);
	extStaDb_DelSta(vmacSta_p, &sta_mac_addr, STADB_DONT_UPDATE_AGINGTIME);
	priv->is_resp_mgmt = FALSE;

	if (priv->cb_callbk_func.get_handover_params_event) {
		priv->cb_callbk_func.get_handover_params_event(sta_mac,
							       &sta_info_v,
							       sizeof
							       (sta_info_v), 0);
	}
	EXT_FUNC();
	return;
}

EXPORT_SYMBOL(get_handover_params_cmd);

/* 
 * set_handover_params_cmd: send handover_msg to target
 * sta_mac: station's MAC address
 * msg: buffer including all handover parameters
 * msg_len: msg buffer length
 */
void
set_handover_params_cmd(struct net_device *netdev, char *sta_mac, void *msg,
			int msg_len)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	sta_info *psta_info = (sta_info *) msg;
	IEEEtypes_MacAddr_t sta_mac_addr;
	extStaDb_StaInfo_t *pStaInfo = NULL;

	//printk("=>%s(%s), sta_mac: %s\n", __func__, netdev->name, sta_mac);
	sscanf(sta_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
	       &sta_mac_addr[0], &sta_mac_addr[1], &sta_mac_addr[2],
	       &sta_mac_addr[3], &sta_mac_addr[4], &sta_mac_addr[5]);

	if ((pStaInfo =
	     extStaDb_GetStaInfo(vmacSta_p, &sta_mac_addr,
				 STADB_UPDATE_AGINGTIME)) != NULL) {
		// Sta data base has existed => no need to add
		//printk("%s(), pStaInfo exists, not adding \n", __func__);
		goto funcFinal;
	}

	if ((pStaInfo =
	     macMgtStaDbInit(vmacSta_p, &sta_mac_addr,
			     (IEEEtypes_MacAddr_t *) & vmacSta_p->macBssId))) {
		pStaInfo->Aid = AssignAid(vmacSta_p);
		pStaInfo->StnId = AssignStnId(vmacSta_p);

		//printk("=> (aid, stnid)=(%u, %u)\n", pStaInfo->Aid, pStaInfo->StnId);
		pStaInfo->FwStaPtr = wlFwSetNewStn(netdev, (u_int8_t *) sta_mac_addr, psta_info->Aid, psta_info->StnId, StaInfoDbActionAddEntry, &psta_info->PeerInfo, psta_info->Qosinfo, psta_info->qosFlag, psta_info->wdsFlag);	//add new station
		pStaInfo->State = ASSOCIATED;
		priv->is_resp_mgmt = TRUE;
//security_ap++
//              memcpy(pStaInfo, &psta_info->StaInfo, sizeof(extStaDb_StaInfo_t));
		memcpy(pStaInfo->Addr, psta_info->Addr,
		       sizeof(IEEEtypes_MacAddr_t));
		memcpy(&pStaInfo->keyMgmtStateInfo,
		       &psta_info->keyMgmtStateInfo, sizeof(keyMgmtInfo_t));
#ifdef CONFIG_IEEE80211W
		memcpy(&pStaInfo->ptkCipherOuiType,
		       &psta_info->ptkCipherOuiType, sizeof(UINT8));
#endif //CONFIG_IEEE80211W
		printk("%s, vmacSta_p->Mib802dot11->Privacy->RSNEnabled: %u\n",
		       __func__, vmacSta_p->Mib802dot11->Privacy->RSNEnabled);

		if (vmacSta_p->Mib802dot11->Privacy->RSNEnabled == TRUE) {
			//vmacSta_p->Mib802dot11->Privacy->RSNEnabled = TRUE;
			wlFwSetWpaWpa2PWK(netdev, pStaInfo);
		}
//security_ap--
	}

	wlFwSetStaCBParam(netdev, &(psta_info->sta_cb_param));

	if (priv->cb_callbk_func.set_handover_params_event) {
		priv->cb_callbk_func.set_handover_params_event(sta_mac, 0);
	}

funcFinal:
	return;
}

EXPORT_SYMBOL(set_handover_params_cmd);

typedef enum {
	NOACK_DEACT = 0,
	NOACK_ACT
} NOACK_MODE;

/* 
* function: set_noack: enable or disable noack feature for given sta
* Input parameters:
* 	net_device: Pointer of the net_device of the interface
* 	sta_mac: station's MAC address
* 	enable: 1 if auto-gen frames should not be sent, 0 otherwise
* Return: None
*/
void
set_noack(struct net_device *netdev, char *sta_mac, int enable)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	IEEEtypes_MacAddr_t sta_mac_addr;
	extStaDb_StaInfo_t *pStaInfo = NULL;

	sscanf(sta_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
	       &sta_mac_addr[0], &sta_mac_addr[1], &sta_mac_addr[2],
	       &sta_mac_addr[3], &sta_mac_addr[4], &sta_mac_addr[5]);
	if ((pStaInfo =
	     extStaDb_GetStaInfo(vmacSta_p, &sta_mac_addr,
				 STADB_UPDATE_AGINGTIME)) == NULL) {
		// Sta data base has existed => no need to add
		printk("%s(), pStaInfo not exists [%s]\n", __func__, sta_mac);
		goto funcFinal;
	}
	//printk("==> %s(), stnid: %u, enable=%d\n", __func__, pStaInfo->StnId, enable);
	wlFwSetStaCBNoAck(netdev, pStaInfo->StnId,
			  (enable == 1) ? (NOACK_ACT) : (NOACK_DEACT));

funcFinal:
	return;
}

EXPORT_SYMBOL(set_noack);

extern int wlDataTx(struct sk_buff *skb, struct net_device *netdev);
/* Implemented by NXP or AT
 * send_mcast_pkt: send mcast frame with given iv and SN
 * skb: multicast ethernet frame
 * iv: iv to use in WLAN frame if encrypted mode, ignore otherwise
 * sn: sequence number to use in WLAN frame
 */
void
send_mcast_pkt(struct net_device *netdev, struct sk_buff *skb, uint64_t iv,
	       uint16_t sn)
{
	wlDataTx(skb, netdev);
	return;
}

/* Implemented by NXP or AT
* function: get_tsf: returns the current 64 bit value of TSF
* Input parameters:
* 	net_device: Pointer of the net_device of the interface
* Return value:
* 	TSF of the beacon
*/
uint64_t
get_tsf(struct net_device * netdev)
{
	uint64_t tsf_val = 0;
	tsf_info_t tsf;

	//printk("=>%s(%s)\n", __func__, netdev->name);
	memset(&tsf, 0, sizeof(tsf_info_t));
	if (!wlFwGetTsf(netdev, &tsf)) {
		////printk("\t HwTsfTime: %08llx\n", tsf.HwTsfTime);
		////printk("\t BssTsfBase: %08llx\n", tsf.BssTsfBase);
		//printk("\t BssTsfTime: %016llx\n", tsf.BssTsfTime);
		////vmacSta_p->BssTsfBase = tsf.BssTsfBase;
		memcpy(&tsf_val, &tsf.BssTsfTime, sizeof(uint64_t));
	}
	//printk("<=%s(), %llx\n", __func__, tsf_val);
	return tsf_val;
}

EXPORT_SYMBOL(get_tsf);

#define DMEM_BASE                      (0x20000000)
typedef struct HAL_BEACON_st {
// DW0
	U16 bcnBodyLen;
	U8 testTxMode;		///< MFG only
	U8 reserved;
// DW1
	U32 startTsf[2];
// DW3
	U32 bcnTbtt[2];
// DW5
	U32 timestamp[2];
// DW7
	U16 bcnInterval;
	U16 capability;
//DW6
	U8 body[SMAC_BCN_BUFSIZE - (4 * 8)];
} HAL_BEACON_st;

/* Implemented by NXP or AT
* function: get_rssi():set_tsf: set new value of tsf and adjust all timers
* Input parameters:
* 	net_device: Pointer of the net_device of the interface
* Return value: None
*/
void
set_tsf(struct net_device *netdev, uint64_t tsf)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate *parent_wlpptr = GET_PARENT_PRIV(wlpptr);
	U32 Shal_BcnBuff_val = 0;
	HAL_BEACON_st* pShal_BcnBuff = NULL;
	U8 l_Shal_BcnBuff[offsetof(HAL_BEACON_st,body)];
	HAL_BEACON_st *pl_bcnbuf = (HAL_BEACON_st *) l_Shal_BcnBuff;
	uint64_t start_tsf, timestamp, new_start_tsf;


	wl_util_lock(netdev);
	Shal_BcnBuff_val= (parent_wlpptr->bcnBasePtr +
			(((SMAC_CTRL_BLK_st*)wlpptr->ioBase0)->status.maxSizeBcnbuf)*(wlpptr->vap_id)) - DMEM_BASE;
	pShal_BcnBuff = (HAL_BEACON_st*)((u8*)wlpptr->ioBase0 + Shal_BcnBuff_val);
	//printk("=>%s(%s), vapid=%u, (base_of_all, len) = %x, %p, %u\n", __func__, netdev->name, wlpptr->vap_id,
	//      parent_wlpptr->bcnBasePtr,
	//      pShal_BcnBuff,
	//      (((SMAC_CTRL_BLK_st*)wlpptr->ioBase0)->status.maxSizeBcnbuf)
	//      );

	memcpy(l_Shal_BcnBuff, pShal_BcnBuff, offsetof(HAL_BEACON_st, body));

	start_tsf =
		((uint64_t) (pl_bcnbuf->startTsf[1])) << 32 | pl_bcnbuf->
		startTsf[0];
	timestamp =
		((uint64_t) (pl_bcnbuf->timestamp[1])) << 32 | pl_bcnbuf->
		timestamp[0];
	new_start_tsf = start_tsf + (timestamp - tsf);

	pShal_BcnBuff->startTsf[0] = (U32) new_start_tsf;
	pShal_BcnBuff->startTsf[1] = (U32) (new_start_tsf >> 32);
	wl_util_unlock(netdev);

	return;
}

EXPORT_SYMBOL(set_tsf);

/* Implemented by NXP
* function: get_rssi(): returns the current rssi average over all types of frames
* Input parameters:
* 	net_device: Pointer of the net_device of the interface
* 	sta_mac: station's MAC address
* Return value:
*	RSSI value
*/
uint16_t
get_rssi(struct net_device * netdev, char *sta_mac)
{
	struct wlprivate *priv;
	vmacApInfo_t *vmacSta_p;
	IEEEtypes_MacAddr_t sta_mac_addr;
	extStaDb_StaInfo_t *pStaInfo;
	uint16_t urssi_val = 0;

	if (netdev == NULL) {
		goto funcfinal;
	}
	priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacSta_p = priv->vmacSta_p;

	sscanf(sta_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
	       &sta_mac_addr[0], &sta_mac_addr[1], &sta_mac_addr[2],
	       &sta_mac_addr[3], &sta_mac_addr[4], &sta_mac_addr[5]);
	//printk("=>%s(%s), %s, (%02x:%02x:%02x:%02x:%02x:%02x)\n", __func__, netdev->name, 
	//      sta_mac,
	//      sta_mac_addr[0], sta_mac_addr[1], sta_mac_addr[2], 
	//      sta_mac_addr[3], sta_mac_addr[4], sta_mac_addr[5]);

	if (NULL ==
	    (pStaInfo =
	     extStaDb_GetStaInfo(vmacSta_p, &sta_mac_addr,
				 STADB_DONT_UPDATE_AGINGTIME))) {
		printk("%s(), Can't find StaInfo\n", __func__);
		goto funcfinal;
	}

	urssi_val =
		(uint16_t) wl_util_get_rssi(netdev, &pStaInfo->RSSI_path, NULL);

funcfinal:
	//printk("<=%s(), (u, s)=(%u, %d)\n", __func__, urssi_val, srssi_val);
	return urssi_val;
}

EXPORT_SYMBOL(get_rssi);

extern struct wlprivate_data *global_private_data[MAX_CARDS_SUPPORT];
/*
* function: get_netdev(): Get the pointer of the net_device of the network interface, which will be used for the operation of this network interface
* Input Parameters:
* 	dev_name: Name of the interface
* Return: net_device: Pointer of the net_device of the interface
*/
struct net_device *
get_netdev(char *dev_name)
{
	struct wlprivate *wlpptr;
	u8 card_idx, vap_idx;
	struct net_device *vnet_dev, *ret_dev = NULL;

	//printk("=>get_netdev(), %s\n", dev_name);
	for (card_idx = 0; card_idx < MAX_CARDS_SUPPORT; card_idx++) {
		if ((global_private_data[card_idx % MAX_CARDS_SUPPORT])->
		    rootdev == NULL) {
			printk("rootdev == NULL (%u)\n", card_idx);
			continue;
		}
		//printk("root: %s\n", global_private_data[card_idx % MAX_CARDS_SUPPORT]->rootdev->name);
		wlpptr = NETDEV_PRIV(struct wlprivate,
				     global_private_data[card_idx %
							 MAX_CARDS_SUPPORT]->
				     rootdev);
		if (wlpptr == NULL) {
			printk("wlpptr == NULL (%u)\n", card_idx);
			continue;
		}
		//printk("[%s] (%p, %p)\n", wlpptr->netDev->name, 
		//      global_private_data[card_idx % MAX_CARDS_SUPPORT]->rootdev,
		//      wlpptr->netDev
		//      );
		for (vap_idx = 0; vap_idx < MAX_VMAC_INSTANCE_AP; vap_idx++) {
			vnet_dev = wlpptr->vdev[vap_idx];
			if (vnet_dev == NULL) {
				printk("(%u, %u) is NULL\n", card_idx, vap_idx);
				continue;
			}
			//printk("\t[%s]\n", vnet_dev->name);
			if (!strcmp(vnet_dev->name, dev_name)) {
				//printk("=====> found: %s, %p, vap_id: %u\n", dev_name, vnet_dev,
				//      NETDEV_PRIV(struct wlprivate, vnet_dev)->vap_id
				//      );
				ret_dev = vnet_dev;
				break;
			}
		}
		if (ret_dev != NULL) {
			break;
		}
	}

	return ret_dev;
}

EXPORT_SYMBOL(get_netdev);

/*
* function: set_cb(): Set the network interface as part of the CB group
* Input parameters:
*	net_device: Pointer of the net_device of the interface
*   mode: Set to cb mode or not
* 	is_resp_mgmt: Will this network interface response the management packets or not
* Return: None
*/
void
set_cb(struct net_device *netdev, u8 mode, int is_resp_mgmt)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);

	printk("%s(), %s, is_resp_mgmt=%d\n", __func__, netdev->name,
	       is_resp_mgmt);
	if (priv == NULL) {
		goto funcFinal;
	}
	// Enable the cb mode
	priv->is_resp_mgmt = is_resp_mgmt;
	priv->cb_enable = mode;
	wlFwSetApCBMode(netdev, priv->cb_enable);

	if (priv->cb_enable == TRUE) {
		// Lunch a timer to call beacon_update() periodically
		TimerInit(&priv->bnc_timer);
		TimerFireIn(&priv->bnc_timer,
			    1, &bcn_timer_routine, (void *)priv->netDev, 1);
	} else {
		// Close the timer if it's not cb_enabled
		while (timer_pending(&priv->bnc_timer)) {
			msleep(1);
		}
		TimerRemove(&priv->bnc_timer);
	}
	printk("<= %s()\n", __func__);

funcFinal:
	return;
}

EXPORT_SYMBOL(set_cb);

/*
* function: set_cbcallbk_func(): Pass the pointers of the callback functions
* Input parameters:
*	net_device: Pointer of the net_device of the interface
* 	pcallcb_func: Structure of the callback function pointers
* Return: None
*/
void
set_cbcallbk_func(struct net_device *netdev, cbcallbk_intf * pcallcb_func)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	if (pcallcb_func == NULL) {
		return;
	}
	printk("ap8x, %s()\n", __func__);
	memcpy(&priv->cb_callbk_func, pcallcb_func, sizeof(cbcallbk_intf));
	return;
}

EXPORT_SYMBOL(set_cbcallbk_func);

void
bcn_timer_routine(unsigned long arg)
{
	struct net_device *netdev = (struct net_device *)arg;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;

	if (vmacSta_p->InfUpFlag == 0) {
		// closed
		return;
	}
	// Call update beacon packet handler
	update_bcn_handler(netdev);

	TimerInit(&wlpptr->bnc_timer);
	TimerFireIn(&wlpptr->bnc_timer,
		    1, &bcn_timer_routine, (void *)wlpptr->netDev, 1);
}

extern int mwl_config_set_essid(struct net_device *netdev, const char *ssid,
				uint8_t ssid_len);
/*
	Note: Limitations:
		- The sequence of IE in new bcn == the one in the old bcn
		- The added ones are appended to the end of the buffer
*/
static void
update_mib(struct net_device *netdev, u8 * new_bcn, u8 * old_bcn)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
	u8 *pn_bcn_buf = new_bcn;
	u8 *po_bcn_buf = old_bcn;
	IEEEtypes_InfoElementHdr_t *pIE_new =
		(IEEEtypes_InfoElementHdr_t *) pn_bcn_buf;
	IEEEtypes_InfoElementHdr_t *pIE_old =
		(IEEEtypes_InfoElementHdr_t *) po_bcn_buf;

	while (pIE_new->Len > 0) {
		switch (pIE_new->ElementId) {
		case SSID:
			/*if ((pIE_old->ElementId == SSID) && memcmp(pIE_new, pIE_old, pIE_old->Len)) {
			   mwl_config_set_essid(netdev,
			   ((IEEEtypes_SsIdElement_t*)pIE_new)->SsId, 
			   pIE_new->Len);
			   } */
			break;
		case DS_PARAM_SET:
			break;
		case TIM:
			break;
		case RSN_IEWPA2:
			break;
		case HT:
			break;
		case ADD_HT:
			break;
		case CHAN_REPORT:
			break;
		case EXT_CAP_IE:
			/*if ((pIE_old->ElementId == EXT_CAP_IE) && memcmp(pIE_new, pIE_old, pIE_old->Len)) {
			   IEEEtypes_Extended_Cap_Element_t     *pExtCap = (IEEEtypes_Extended_Cap_Element_t*)pIE_new;
			   } */
			break;
		case VHT_CAP:
			if ((pIE_old->ElementId == VHT_CAP) &&
			    memcmp(pIE_new, pIE_old, pIE_old->Len)) {
				IEEEtypes_VhtCap_t *ptr =
					(IEEEtypes_VhtCap_t *) pIE_new;
				*(mib->pMib_11nAggrMode) &=
					~WL_MODE_AMSDU_TX_MASK;
				if (ptr->cap.MaximumMPDULength == 1) {
					*(mib->pMib_11nAggrMode) |=
						WL_MODE_AMSDU_TX_8K;
				} else if (ptr->cap.MaximumMPDULength == 2) {
					*(mib->pMib_11nAggrMode) |=
						WL_MODE_AMSDU_TX_11K;
				}
				//printk("==> mib->pMib_11nAggrMode = %u, \n", *(mib->pMib_11nAggrMode));
			}
			break;
		case VHT_OPERATION:
			break;
		case PROPRIETARY_IE:
			break;
		}
		pn_bcn_buf += (pIE_new->Len + 2);
		pIE_new = (IEEEtypes_InfoElementHdr_t *) pn_bcn_buf;
		po_bcn_buf += (pIE_old->Len + 2);
		pIE_old = (IEEEtypes_InfoElementHdr_t *) po_bcn_buf;
	}
	wlFwSetIEs(netdev);
	return;
}

static void
update_bcn_handler(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	int res_cb;
	struct wlprivate *parent_wlpptr = GET_PARENT_PRIV(wlpptr);
	U32 Shal_BcnBuff_val = (parent_wlpptr->bcnBasePtr +
				(((SMAC_CTRL_BLK_st *) wlpptr->ioBase0)->status.
				 maxSizeBcnbuf) * (wlpptr->vap_id)) - DMEM_BASE;
	HAL_BEACON_st *pShal_BcnBuff =
		(HAL_BEACON_st *) ((u8 *) wlpptr->ioBase0 + Shal_BcnBuff_val);
	HAL_BEACON_st *pl_bcnbuf;
	uint64_t timestamp;
	struct sk_buff *skb_bcn;
	struct sk_buff *skb_orig_bcn;

	// Always turn on beacon, since it may have been turned off in the last run
	wlpptr->smacCfgAddr->bcnStop &= ~(0x1 << wlpptr->vap_id);

	// beacon_update() callback has not hooked up
	if (wlpptr->cb_callbk_func.beacon_update == NULL) {
		printk("%s(), beacon_update() == NULL\n", __func__);
		return;
	}
	// Allocate a local buffer to save the beacon packet
	skb_bcn = wl_alloc_skb(sizeof(HAL_BEACON_st));
	memcpy(skb_bcn->data, pShal_BcnBuff, sizeof(HAL_BEACON_st));

	//skb_reset_tail_pointer(skb_bcn);
	pl_bcnbuf = (HAL_BEACON_st *) skb_bcn->data;
	if (pl_bcnbuf->bcnBodyLen == 0) {
		return;
	}
	// Make beacon skb to set the data, length
	skb_reserve(skb_bcn, offsetof(HAL_BEACON_st, body));
	skb_put(skb_bcn, pl_bcnbuf->bcnBodyLen - 12);
	skb_orig_bcn = skb_copy(skb_bcn, GFP_ATOMIC);

	// Calculate the next tsf
	timestamp =
		(((uint64_t) (pl_bcnbuf->timestamp[1])) << 32 | pl_bcnbuf->
		 timestamp[0]) + pl_bcnbuf->bcnInterval;
	// Call to update beacon
	res_cb = wlpptr->cb_callbk_func.beacon_update(netdev->dev_addr, skb_bcn,
						      timestamp);
	if (res_cb != 0) {
		//Need to drop the next beacon
		wlpptr->smacCfgAddr->bcnStop |= (0x1 << wlpptr->vap_id);
	}
	// Parsing the skb & set the IE if modified
	if (memcmp(skb_bcn->data, skb_orig_bcn->data, skb_bcn->len)) {
		//printk("==> BCN buffer is modified\n");
		update_mib(netdev, skb_bcn->data, skb_orig_bcn->data);
	}
	wl_free_skb(skb_bcn);
	wl_free_skb(skb_orig_bcn);
	return;
}

#endif //CB_SUPPORT
