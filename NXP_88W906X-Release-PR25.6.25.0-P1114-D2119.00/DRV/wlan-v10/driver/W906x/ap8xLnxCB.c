/** @file ap8xLnxCB.c
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2019-2021 NXP
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

#define DMEM_BASE                      (0x20000000)

#if 0
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
	// BA-Info
	cbba_info_t cbba_info[2][MAX_TID];	// 0: rx, 1: tx
} sta_info;
#endif				//0

struct ether_header {
	UINT8 ether_dhost[IEEEtypes_ADDRESS_SIZE];
	UINT8 ether_shost[IEEEtypes_ADDRESS_SIZE];
	UINT16 ether_type;
};

struct ieee80211_frame {
	IEEEtypes_FrameCtl_t FrmCtl;
	UINT8 dur[2];
	UINT8 addr1[IEEEtypes_ADDRESS_SIZE];
	UINT8 addr2[IEEEtypes_ADDRESS_SIZE];
	UINT8 addr3[IEEEtypes_ADDRESS_SIZE];
	UINT8 seq[2];
	UINT8 addr4[IEEEtypes_ADDRESS_SIZE];
} PACK;

//static void update_bcn_handler(struct net_device* netdev);
static void update_bcn_handler_1(struct net_device *netdev);

extern extStaDb_StaInfo_t *macMgtStaDbInit(vmacApInfo_t * vmacSta_p, IEEEtypes_MacAddr_t * staMacAddr, IEEEtypes_MacAddr_t * apMacAddr);
extern UINT16 extStaDb_entries(vmacApInfo_t * vmac_p, UINT8 flag);
extern void flush_any_pending_ampdu_pck(struct net_device *dev, extStaDb_StaInfo_t * pStaInfo);
cbinfo_sta_t g_dbg_cbinfo_sta;
extern void wl_reset_ba(struct net_device *netdev, extStaDb_StaInfo_t * pStaInfo, UINT8 tsid);
extern unsigned int bss_num;
/* 
 * get_handover_params_cmd: send HANDOVER_START command to target
 * sta_mac: station's MAC address
 */
void get_handover_params_cmd(struct net_device *netdev, char *sta_mac)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = priv->wlpd_p;
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	IEEEtypes_MacAddr_t sta_mac_addr;
	extStaDb_StaInfo_t *StaInfo_p = NULL;
	cbinfo_sta_t *pcbinfo_sta;
	u32 bgn_txqid;
	u8 i;
	SMAC_TXQ_ENTRY_st *pTxq;
	SMAC_STA_ENTRY_st *pSta;
	struct wlprivate *parent_wlpptr = GET_PARENT_PRIV(priv);
	U32 shal_txq_entry_val = parent_wlpptr->txqBasePtr - SMAC_DMEM_START;
	U32 shal_sta_entry_val = parent_wlpptr->staBasePtr - SMAC_DMEM_START;

	//printk("=>%s(%s), sta_mac: %s\n", __func__, netdev->name, sta_mac);
	sscanf(sta_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
	       &sta_mac_addr[0], &sta_mac_addr[1], &sta_mac_addr[2], &sta_mac_addr[3], &sta_mac_addr[4], &sta_mac_addr[5]);

	if ((StaInfo_p = extStaDb_GetStaInfo(vmacSta_p, &sta_mac_addr, STADB_UPDATE_AGINGTIME)) == NULL) {
		return;
	}
	// Save the AP setting
	pcbinfo_sta = &StaInfo_p->cbinfo_sta;
	bgn_txqid = QUEUE_STAOFFSET + StaInfo_p->StnId * MAX_TID;
	pTxq = (SMAC_TXQ_ENTRY_st *) (shal_txq_entry_val + priv->ioBase0) + bgn_txqid;
	memcpy(pcbinfo_sta->sta_macaddr, sta_mac_addr, sizeof(IEEEtypes_MacAddr_t));
	pcbinfo_sta->enable_tx = StaInfo_p->cbinfo_sta.enable_tx;
	for (i = 0; i < MAX_TID; i++) {
		pcbinfo_sta->sn[i] = pTxq[i].SN;
		if (pTxq[i].SN != (wlpd_p->except_cnt.txq_send_cnt[bgn_txqid + i] & 0xffff)) {
			printk("tid: %u, (txq_sn, tx_send_cnt)=(%u, %u)\n", i, pTxq[i].SN, (wlpd_p->except_cnt.txq_send_cnt[bgn_txqid + i] & 0xffff));
		}
	}
	pSta = (SMAC_STA_ENTRY_st *) (shal_sta_entry_val + priv->ioBase0) + (bss_num + StaInfo_p->StnId);
	for (i = 0; i < 16; i++) {
		pcbinfo_sta->iv[i] = pSta->pn[i];
	}
	memcpy(&pcbinfo_sta->keyMgmtStateInfo, &StaInfo_p->keyMgmtStateInfo, sizeof(keyMgmtInfo_t));
	memcpy(&pcbinfo_sta->ptkCipherOuiType, &StaInfo_p->ptkCipherOuiType, sizeof(UINT8));

#if 0
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
	memcpy((void *)&sta_info_v.PeerInfo, &StaInfo_p->PeerInfo, sizeof(PeerInfo_t));
	//security_ap++
	//memcpy(&sta_info_v.StaInfo, StaInfo_p, sizeof(extStaDb_StaInfo_t));
	memcpy(sta_info_v.Addr, StaInfo_p->Addr, sizeof(IEEEtypes_MacAddr_t));
	memcpy(&sta_info_v.keyMgmtStateInfo, &StaInfo_p->keyMgmtStateInfo, sizeof(keyMgmtInfo_t));
#ifdef CONFIG_IEEE80211W
	memcpy(&sta_info_v.ptkCipherOuiType, &StaInfo_p->ptkCipherOuiType, sizeof(UINT8));
#endif				//CONFIG_IEEE80211W

	//security_ap--
	memcpy(sta_info_v.cbba_info, StaInfo_p->cbba_info, sizeof(sta_info_v.cbba_info));
	// ampdu seq
	wlFwGetSeqNoBAStream(netdev, sta_mac_addr, 0, &g_baseq);

	// Flush all the saved rx-pkts
	flush_any_pending_ampdu_pck(netdev, StaInfo_p);

	wlFwSetNewStn(netdev, (u_int8_t *) sta_mac_addr, 0, 0, StaInfoDbActionRemoveEntry, NULL, 0, 0, 0);	//del station first

	FreeAid(vmacSta_p, StaInfo_p->Aid);
	FreeStnId(vmacSta_p, StaInfo_p->StnId);
	extStaDb_DelSta(vmacSta_p, &sta_mac_addr, STADB_DONT_UPDATE_AGINGTIME);
	priv->is_resp_mgmt = FALSE;
#endif				//0
	if (priv->cb_callbk_func.get_handover_params_event) {
		//priv->cb_callbk_func.get_handover_params_event(sta_mac, &sta_info_v, sizeof(sta_info_v), 0);
		priv->cb_callbk_func.get_handover_params_event(sta_mac, pcbinfo_sta, sizeof(cbinfo_sta_t), 0);
	}
	// for unit test only
	{
		//memcpy(&g_sta_info_v, &sta_info_v, sizeof(sta_info_v));
		printk("get_handover_params_event: %p\n", priv->cb_callbk_func.get_handover_params_event);
		memcpy(&g_dbg_cbinfo_sta, pcbinfo_sta, sizeof(cbinfo_sta_t));
		printk("[%s - sta: %pM], StnId: %u\n", netdev->name, sta_mac_addr, StaInfo_p->StnId);
		printk("[tx_allow: %u]\n", g_dbg_cbinfo_sta.enable_tx);
		printk("sn[%u]: (%04x, %04x, %04x, %04x - %04x, %04x, %04x, %04x)\n",
		       bgn_txqid,
		       g_dbg_cbinfo_sta.sn[0], g_dbg_cbinfo_sta.sn[1], g_dbg_cbinfo_sta.sn[2], g_dbg_cbinfo_sta.sn[3],
		       g_dbg_cbinfo_sta.sn[4], g_dbg_cbinfo_sta.sn[5], g_dbg_cbinfo_sta.sn[6], g_dbg_cbinfo_sta.sn[7]);
	}
	EXT_FUNC();
	return;
}

EXPORT_SYMBOL(get_handover_params_cmd);

static void set_ba_from_msg(struct net_device *netdev, IEEEtypes_MacAddr_t sta_mac_addr, extStaDb_StaInfo_t * pStaInfo, cbinfo_sta_t * pcbinfo_sta)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	u8 tid;
	// rx BA
	for (tid = 0; tid < MAX_TID; tid++) {
		cbba_info_t *pcbba_info = &pcbinfo_sta->cbba_info[0][tid];
		if (pcbba_info->valid == false) {
			continue;
		}
		//printk("Calling wlFwCreateBAStream(%u)\n", tid);
		priv->is_ba4roam = true;
		wlFwCreateBAStream(netdev, pcbba_info->BarThrs,	//pAddBaRspFrm->ParamSet.BufSize,
				   pcbba_info->WindowSize,	//pAddBaRspFrm->ParamSet.BufSize,
				   sta_mac_addr,	//(u_int8_t *)&(MgmtMsg_p->Hdr.SrcAddr),
				   pcbba_info->DialogToken,	//10,
				   tid, pcbba_info->ba_type,	//amsdu_bitmap,
				   pcbba_info->direction,	// 1, rx
				   pcbba_info->ParamInfo,	//pStaInfo->HtElem.MacHTParamInfo,
				   netdev->dev_addr,	//(u_int8_t *)&(MgmtMsg_p->Hdr.DestAddr),
				   pcbba_info->seqNo,	// Starting_Seq_No (==0)
				   pcbba_info->vhtrxfactor,	//7, ==pStaInfo->vhtCap.cap.MaximumAmpduLengthExponent,
				   pcbba_info->queueid,	// qid
				   (u_int16_t) pStaInfo->StnId);
		priv->is_ba4roam = false;
	}
	// Tx BA
	for (tid = 0; tid < MAX_TID; tid++) {
		cbba_info_t *pcbba_info = &pcbinfo_sta->cbba_info[1][tid];
		if (pcbba_info->valid == false) {
			continue;
		}
		//printk("Calling wlFwCreateBAStream(%u)\n", tid);
		wlFwCreateBAStream(netdev, pcbba_info->BarThrs,	//pAddBaRspFrm->ParamSet.BufSize,
				   pcbba_info->WindowSize,	//pAddBaRspFrm->ParamSet.BufSize,
				   sta_mac_addr,	//(u_int8_t *)&(MgmtMsg_p->Hdr.SrcAddr)
				   pcbba_info->DialogToken,	//10,
				   tid, pcbba_info->ba_type,	//amsdu_bitmap (==0x3),
				   pcbba_info->direction,	// 0, tx
				   pcbba_info->ParamInfo,	// pStaInfo->HtElem.MacHTParamInfo (==0x17
				   NULL,	//(u_int8_t *)&(MgmtMsg_p->Hdr.DestAddr),
				   pcbinfo_sta->sn[tid],	//pcbba_info->seqNo,       // pAddBaReqFrm->SeqControl.Starting_Seq_No (==0)
				   pcbba_info->vhtrxfactor,	// pStaInfo->vhtCap.cap.MaximumAmpduLengthExponent ( ==7)
				   pcbba_info->queueid,	//qid (==0)(u_int16_t)pStaInfo->StnId);
				   (u_int16_t) pStaInfo->StnId);
	}
	return;
}

/* 
 * set_handover_params_cmd: send handover_msg to target
 * sta_mac: station's MAC address
 * msg: buffer including all handover parameters
 * msg_len: msg buffer length
 */
void set_handover_params_cmd(struct net_device *netdev, char *sta_mac, void *msg, int msg_len)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	IEEEtypes_MacAddr_t sta_mac_addr;
	extStaDb_StaInfo_t *pStaInfo = NULL;
	cbinfo_sta_t *pcbinfo_sta;
	u32 bgn_txqid;
	u8 i;
	SMAC_TXQ_ENTRY_st *pTxq;
	SMAC_STA_ENTRY_st *pSta;
	struct wlprivate *parent_wlpptr = GET_PARENT_PRIV(priv);
	U32 shal_txq_entry_val = parent_wlpptr->txqBasePtr - SMAC_DMEM_START;
	U32 shal_sta_entry_val = parent_wlpptr->staBasePtr - SMAC_DMEM_START;

	//printk("=>%s(%s), sta_mac: %s\n", __func__, netdev->name, sta_mac);
	sscanf(sta_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
	       &sta_mac_addr[0], &sta_mac_addr[1], &sta_mac_addr[2], &sta_mac_addr[3], &sta_mac_addr[4], &sta_mac_addr[5]);

	if ((pStaInfo = extStaDb_GetStaInfo(vmacSta_p, &sta_mac_addr, STADB_UPDATE_AGINGTIME)) == NULL) {
		// Sta database has not existed => can't be sync
		printk("%s(), pStaInfo exists, not adding \n", __func__);
		goto funcFinal;
	}
	if (msg_len != sizeof(cbinfo_sta_t)) {
		printk("Invalid msg type, size=%d, exp: %lu\n", msg_len, sizeof(cbinfo_sta_t));
		goto funcFinal;
	}
	// Save the passed down handover parameters
	pcbinfo_sta = &pStaInfo->cbinfo_sta;
	memcpy(pcbinfo_sta, msg, msg_len);
	printk("[%s, stnid: %u], tx_allow: %u, %d\n", netdev->name, pStaInfo->StnId, pcbinfo_sta->enable_tx, msg_len);

	// Save the handover parameters to AP setting
	memcpy(&pStaInfo->keyMgmtStateInfo, &pcbinfo_sta->keyMgmtStateInfo, sizeof(keyMgmtInfo_t));
	memcpy(&pStaInfo->ptkCipherOuiType, &pcbinfo_sta->ptkCipherOuiType, sizeof(UINT8));
	if (vmacSta_p->Mib802dot11->Privacy->RSNEnabled == TRUE) {
		//vmacSta_p->Mib802dot11->Privacy->RSNEnabled = TRUE;
		wlFwSetWpaWpa2PWK(netdev, pStaInfo);
		pSta = (SMAC_STA_ENTRY_st *) (shal_sta_entry_val + priv->ioBase0) + (SMAC_BSS_NUM + pStaInfo->StnId);
		for (i = 0; i < 16; i++) {
			pSta->pn[i] = pcbinfo_sta->iv[i];
		}
	}
#if 0
	if ((pStaInfo = macMgtStaDbInit(vmacSta_p, &sta_mac_addr, (IEEEtypes_MacAddr_t *) & vmacSta_p->macBssId))) {
		pStaInfo->Aid = AssignAid(vmacSta_p);
		pStaInfo->StnId = AssignStnId(vmacSta_p);

		psta_info->PeerInfo.TxBFCapabilities = WORD_SWAP(psta_info->PeerInfo.TxBFCapabilities);
		psta_info->PeerInfo.assocRSSI = 6;

		//printk("=> (aid, stnid)=(%u, %u)\n", pStaInfo->Aid, pStaInfo->StnId);
		pStaInfo->FwStaPtr = wlFwSetNewStn(netdev, (u_int8_t *) sta_mac_addr, psta_info->Aid, psta_info->StnId, StaInfoDbActionAddEntry, &psta_info->PeerInfo, psta_info->Qosinfo, psta_info->qosFlag, psta_info->wdsFlag);	//add new station
		pStaInfo->State = ASSOCIATED;
		priv->is_resp_mgmt = TRUE;
//security_ap++
//              memcpy(pStaInfo, &psta_info->StaInfo, sizeof(extStaDb_StaInfo_t));
		memcpy(pStaInfo->Addr, psta_info->Addr, sizeof(IEEEtypes_MacAddr_t));
		memcpy(&pStaInfo->keyMgmtStateInfo, &psta_info->keyMgmtStateInfo, sizeof(keyMgmtInfo_t));
#ifdef CONFIG_IEEE80211W
		memcpy(&pStaInfo->ptkCipherOuiType, &psta_info->ptkCipherOuiType, sizeof(UINT8));
#endif				//CONFIG_IEEE80211W
		printk("%s, vmacSta_p->Mib802dot11->Privacy->RSNEnabled: %u\n", __func__, vmacSta_p->Mib802dot11->Privacy->RSNEnabled);

		if (vmacSta_p->Mib802dot11->Privacy->RSNEnabled == TRUE) {
			//vmacSta_p->Mib802dot11->Privacy->RSNEnabled = TRUE;
			wlFwSetWpaWpa2PWK(netdev, pStaInfo);
		}
//security_ap--
	}
	//wlFwSetStaCBParam(netdev, &(psta_info->sta_cb_param));
	//=====> Skip StaCBParam temporally
	//wlFwSetStaCBParam(netdev, &(psta_info->sta_cb_param));
#endif				//0
	bgn_txqid = QUEUE_STAOFFSET + pStaInfo->StnId * MAX_TID;
	pTxq = (SMAC_TXQ_ENTRY_st *) (shal_txq_entry_val + priv->ioBase0) + bgn_txqid;
	for (i = 0; i < MAX_TID; i++) {
		pTxq[i].SN = pcbinfo_sta->sn[i];
	}
	// Rebuild the BA if it has been setup
	set_ba_from_msg(netdev, sta_mac_addr, pStaInfo, pcbinfo_sta);

	// Notify the result
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
void set_noack(struct net_device *netdev, char *sta_mac, int enable)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = priv->vmacSta_p;
	IEEEtypes_MacAddr_t sta_mac_addr;
	extStaDb_StaInfo_t *pStaInfo = NULL;

	sscanf(sta_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
	       &sta_mac_addr[0], &sta_mac_addr[1], &sta_mac_addr[2], &sta_mac_addr[3], &sta_mac_addr[4], &sta_mac_addr[5]);
	if ((pStaInfo = extStaDb_GetStaInfo(vmacSta_p, &sta_mac_addr, STADB_UPDATE_AGINGTIME)) == NULL) {
		// Sta data base has existed => no need to add
		printk("%s(), pStaInfo not exists [%s]\n", __func__, sta_mac);
		goto funcFinal;
	}
	//printk("==> %s(), stnid: %u, enable=%d\n", __func__, pStaInfo->StnId, enable);
	wlFwSetStaCBNoAck(netdev, pStaInfo->StnId, (enable == 1) ? (NOACK_ACT) : (NOACK_DEACT));

 funcFinal:
	return;
}

EXPORT_SYMBOL(set_noack);

extern int wlDataTx(struct sk_buff *skb, struct net_device *netdev);
inline static void set_mcast_sn(struct wlprivate *wlpptr, U16 iv, U16 sn)
{
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	struct wlprivate *parent_wlpptr = GET_PARENT_PRIV(wlpptr);
	U32 shal_txq_entry_val = parent_wlpptr->txqBasePtr - DMEM_BASE;
	//U32 shal_bss_entry_val = parent_wlpptr->bssBasePtr - DMEM_BASE;
	U32 shal_sta_entry_val = parent_wlpptr->staBasePtr - DMEM_BASE;
	SMAC_TXQ_ENTRY_st *pTxq;
	//SMAC_BSS_ENTRY_st *pBss;
	SMAC_STA_ENTRY_st *pSta;

	//pBss = (SMAC_BSS_ENTRY_st *)(shal_bss_entry_val +  wlpptr->ioBase0) + wlpptr->vap_id;
	pTxq = (SMAC_TXQ_ENTRY_st *) (shal_txq_entry_val + wlpptr->ioBase0) + wlpptr->vap_id * 8;
	pSta = (SMAC_STA_ENTRY_st *) (shal_sta_entry_val + wlpptr->ioBase0) + wlpptr->vap_id;
	printk("%s(), Set mcast sn: %u, iv: %u\n", __func__, sn, iv);
	if (vmacSta_p->Mib802dot11->Privacy->RSNEnabled == TRUE) {
		memcpy(pSta->pn, &iv, sizeof(U16));
	}
	pTxq[0].SN = sn;
	//wlpd_p->except_cnt.txq_send_cnt[mcq] = sn;
}

void cb_set_bcn_mask(struct net_device *netdev, bool is_on)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);

	if (wlpptr->bcn_is_on == is_on) {
		// Reduce the redundant tasks
		return;
	}
	if (is_on != 0) {
		// enable beacon
		wlpptr->smacCfgAddr->bcnStop &= ~(0x1 << wlpptr->vap_id);
	} else {
		// disable beacon
		wlpptr->smacCfgAddr->bcnStop |= (0x1 << wlpptr->vap_id);
	}
	wlpptr->bcn_is_on = is_on;

	return;
}

void cb_set_bcn_sn(struct net_device *netdev, U16 sn)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate *parent_wlpptr = GET_PARENT_PRIV(wlpptr);
	U32 shal_bss_entry_val = parent_wlpptr->bssBasePtr - DMEM_BASE;
	SMAC_BSS_ENTRY_st *pBss;

	pBss = (SMAC_BSS_ENTRY_st *) (shal_bss_entry_val + wlpptr->ioBase0) + wlpptr->vap_id;
	pBss->SN = sn;
	printk("sn (set): (%xh, %u)\n", sn, sn);
	return;
}

U16 cb_get_bcn_sn(struct net_device * netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate *parent_wlpptr = GET_PARENT_PRIV(wlpptr);
	U32 shal_bss_entry_val = parent_wlpptr->bssBasePtr - DMEM_BASE;
	SMAC_BSS_ENTRY_st *pBss;

	pBss = (SMAC_BSS_ENTRY_st *) (shal_bss_entry_val + wlpptr->ioBase0) + wlpptr->vap_id;
	return pBss->SN;
}

inline static bool is_mcpkt_pending(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate_data *wlpd_p = wlpptr->wlpd_p;
	UINT16 mcq = wlpptr->vap_id * MAX_TID;
	UINT32 txq_drop, txq_send, txq_rel;
	UINT16 pendcnt;

	txq_send = wlpd_p->except_cnt.txq_send_cnt[mcq];
	txq_rel = wlpd_p->except_cnt.txq_rel_cnt[mcq];
	txq_drop = wlpd_p->except_cnt.txq_drop_cnt[mcq];
	pendcnt = txq_send - (txq_rel + txq_drop);
	if (pendcnt == 0) {
		return false;
	} else {
		printk("%s(), (s, r, d)=(%u, %u, %u)=>%u\n", __func__, txq_send, txq_rel, txq_drop, pendcnt);
		return true;
	}
}

void cb_mcpkt_timer_routine(unsigned long arg)
{
	struct net_device *netdev = (struct net_device *)arg;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	cb_mcinfo_t *pcb_mcinfo;
	struct sk_buff *skb;
	cb_mcinfo_t last_cb_mcinfo;
	if (vmacSta_p->InfUpFlag == 0) {
		// closed
		return;
	}
	if (skb_queue_len(&wlpptr->cb_ncpkt_q) == 0) {
		//printk("[WARNING], %s(), skb_queue_len(cb_ncpkt_q) == 0\n", __func__);
		return;
	}
	if (is_mcpkt_pending(netdev) == true) {
		// Polling again, until all queued mc packets have been sent
		TimerFireIn(&wlpptr->cb_mctmer, 1, &cb_mcpkt_timer_routine, (void *)wlpptr->netDev, 1);
		//printk("%s() mc pending => more check\n", __func__);
	} else {
		// no pending packets => resume sending the queued packets
		spin_lock_bh(&wlpptr->cbmc_lock);
		wlpptr->cb_mc_wait2sync = false;
		spin_unlock_bh(&wlpptr->cbmc_lock);
		// 1st skb in queue
		skb = skb_dequeue(&wlpptr->cb_ncpkt_q);
		pcb_mcinfo = (cb_mcinfo_t *) (skb->cb);
		memcpy(&last_cb_mcinfo, pcb_mcinfo, sizeof(last_cb_mcinfo));

		// Reset the SN
		wlpptr->cbmc_info.sn = pcb_mcinfo->sn;
		wlpptr->cbmc_info.iv = pcb_mcinfo->iv;
		set_mcast_sn(wlpptr, wlpptr->cbmc_info.iv, wlpptr->cbmc_info.sn);
		wlDataTx(skb, netdev);
		// other skb in queue
		while ((skb = skb_dequeue(&wlpptr->cb_ncpkt_q)) != NULL) {
			pcb_mcinfo = (cb_mcinfo_t *) (skb->cb);
			if ((pcb_mcinfo->sn - last_cb_mcinfo.sn) == 1) {
				wlDataTx(skb, netdev);
				memcpy(&last_cb_mcinfo, pcb_mcinfo, sizeof(last_cb_mcinfo));
			} else {
				// another gap again => leaving now
				break;
			}
		}
		// Update the saved iv/sn
		memcpy(&wlpptr->cbmc_info, &last_cb_mcinfo, sizeof(last_cb_mcinfo));
	}
}

/* Implemented by NXP or AT
 * send_mcast_pkt: send mcast frame with given iv and SN
 * skb: multicast ethernet frame
 * iv: iv to use in WLAN frame if encrypted mode, ignore otherwise
 * sn: sequence number to use in WLAN frame
 */
void send_mcast_pkt(struct net_device *netdev, struct sk_buff *skb, uint64_t iv, uint16_t sn)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);

	if (((sn - priv->cbmc_info.sn) != 1) ||	// A gap in sn
	    (skb_queue_len(&priv->cb_ncpkt_q) > 0)) {	// Already sending async
		cb_mcinfo_t *pcb_mcinfo = (cb_mcinfo_t *) (skb->cb);
		// missing packets found
		// => Queue the packets
		pcb_mcinfo->iv = iv;
		pcb_mcinfo->sn = sn;
		skb_queue_tail(&priv->cb_ncpkt_q, skb);
		// => kickoff the thread to polling the packet status
		spin_lock_bh(&priv->cbmc_lock);
		priv->cb_mc_wait2sync = true;
		spin_unlock_bh(&priv->cbmc_lock);
		TimerFireIn(&priv->cb_mctmer, 1, &cb_mcpkt_timer_routine, (void *)priv->netDev, 1);
	} else {
		// No gap, => just send the packet
		wlDataTx(skb, netdev);
		priv->cbmc_info.sn = sn;
		priv->cbmc_info.iv = iv;
	}
	return;
}

EXPORT_SYMBOL(send_mcast_pkt);

bool chk_mcpkt_rdy(struct net_device * netdev)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	return (!priv->cb_mc_wait2sync);
}

EXPORT_SYMBOL(chk_mcpkt_rdy);

/* Implemented by NXP or AT
* function: get_tsf: returns the current 64 bit value of TSF
* Input parameters:
* 	net_device: Pointer of the net_device of the interface
* Return value:
* 	TSF of the beacon
*/
uint64_t get_tsf(struct net_device * netdev)
{
	uint64_t tsf_val = 0;
	tsf_info_t tsf;

	//printk("=>%s(%s)\n", __func__, netdev->name);
	memset(&tsf, 0, sizeof(tsf_info_t));
	if (!wlFwGetTsf(netdev, &tsf)) {
		tsf_val = tsf.BssTsfTime;
	}
	//printk("<=%s(), %llx\n", __func__, tsf_val);
	return tsf_val;
}

EXPORT_SYMBOL(get_tsf);

/* Implemented by NXP or AT
* function: set_tsf():set_tsf: set new value of tsf and adjust all timers
* Input parameters:
* 	net_device: Pointer of the net_device of the interface
* Return value: None
*/
void set_tsf(struct net_device *netdev, uint64_t new_tsf)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate *parent_wlpptr = GET_PARENT_PRIV(wlpptr);
	U32 Shal_BcnBuff_val = (parent_wlpptr->bcnBasePtr +
				(((SMAC_CTRL_BLK_st *) wlpptr->ioBase0)->status.maxSizeBcnbuf) * (wlpptr->vap_id)) - DMEM_BASE;
	HAL_BEACON_st *pShal_BcnBuff = (HAL_BEACON_st *) ((u8 *) wlpptr->ioBase0 + Shal_BcnBuff_val);
	U8 l_Shal_BcnBuff[offsetof(HAL_BEACON_st, body)];
	HAL_BEACON_st *pl_bcnbuf = (HAL_BEACON_st *) l_Shal_BcnBuff;
	uint64_t start_tsf, new_start_tsf;
	tsf_info_t tsf_all;
	uint64_t tsf_val = 0;
	uint64_t bcnTbtt_64;
	uint32_t shift_tus;
	uint32_t otsf_offset, ntsf_offset;
	uint64_t bcntsf;

	memset(&tsf_all, 0, sizeof(tsf_info_t));
	/*
	   TSF = hw_counter + start_tsf
	 */
	if (!wlFwGetTsf(netdev, &tsf_all)) {
		// Get the current TSF
		tsf_val = tsf_all.BssTsfTime;

		// Get the "start_tsf" from beacon buffer
		memcpy_fromio(l_Shal_BcnBuff, pShal_BcnBuff, offsetof(HAL_BEACON_st, body));
		start_tsf = ((uint64_t) (pl_bcnbuf->startTsf[1])) << 32 | pl_bcnbuf->startTsf[0];

		// Calculate the new start_tsf
		new_start_tsf = start_tsf + (tsf_val - new_tsf);

		// Update the new startTsf back to firmware
		pShal_BcnBuff->startTsf[0] = (U32) new_start_tsf;
		pShal_BcnBuff->startTsf[1] = (U32) (new_start_tsf >> 32);
		// Update TBTT
		bcntsf = (uint64_t) (pShal_BcnBuff->timestamp[1]) << 32 | pShal_BcnBuff->timestamp[0];

		otsf_offset = (tsf_val - bcntsf);
		ntsf_offset = (new_tsf % 102400);
		// Ensure it's positive
		shift_tus = otsf_offset - ntsf_offset + 102400;
		bcnTbtt_64 = (((uint64_t) pShal_BcnBuff->bcnTbtt[1]) << 32) | pShal_BcnBuff->bcnTbtt[0];
		bcnTbtt_64 += shift_tus;
		pShal_BcnBuff->bcnTbtt[0] = (U32) bcnTbtt_64;
		pShal_BcnBuff->bcnTbtt[1] = (U32) (bcnTbtt_64 >> 32);
		/*{
		   printk("(otsf, bcntsf, ntsf, stsf)=(%llu, %llu, %llu, %lu), %u\n", tsf_val, bcntsf, new_tsf, shift_tus,
		   pShal_BcnBuff->bcnInterval);
		   } */
	}
	return;
}

EXPORT_SYMBOL(set_tsf);

/*
* adjust_tsf: adjust new value of tsf according to given delta and adjust all timers
* netdev: the net_device pointer of the network interface
* delta: value to add to current value of tsf (can be negative)
*/
void adjust_tsf(struct net_device *netdev, int64_t delta)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate *parent_wlpptr = GET_PARENT_PRIV(wlpptr);
	U32 Shal_BcnBuff_val = (parent_wlpptr->bcnBasePtr +
				(((SMAC_CTRL_BLK_st *) wlpptr->ioBase0)->status.maxSizeBcnbuf) * (wlpptr->vap_id)) - DMEM_BASE;
	HAL_BEACON_st *pShal_BcnBuff = (HAL_BEACON_st *) ((u8 *) wlpptr->ioBase0 + Shal_BcnBuff_val);
	U8 l_Shal_BcnBuff[offsetof(HAL_BEACON_st, body)];
	HAL_BEACON_st *pl_bcnbuf = (HAL_BEACON_st *) l_Shal_BcnBuff;
	uint64_t start_tsf, new_start_tsf;
	tsf_info_t tsf_all;
	uint64_t tsf_val = 0;

	memset(&tsf_all, 0, sizeof(tsf_info_t));
	/*
	   TSF = hw_counter + start_tsf
	 */
	if (!wlFwGetTsf(netdev, &tsf_all)) {
		tsf_val = tsf_all.BssTsfTime;
		memcpy_fromio(l_Shal_BcnBuff, pShal_BcnBuff, offsetof(HAL_BEACON_st, body));
		start_tsf = ((uint64_t) (pl_bcnbuf->startTsf[1])) << 32 | pl_bcnbuf->startTsf[0];
		new_start_tsf = start_tsf - delta;
		// Update the new startTsf back to firmware
		pShal_BcnBuff->startTsf[0] = (U32) new_start_tsf;
		pShal_BcnBuff->startTsf[1] = (U32) (new_start_tsf >> 32);
	}
	return;
}

EXPORT_SYMBOL(adjust_tsf);

/* Implemented by NXP
* function: get_rssi(): returns the current rssi average over all types of frames
* Input parameters:
* 	net_device: Pointer of the net_device of the interface
* 	sta_mac: station's MAC address
*	rx_rssi: return average of Crtl RSSI
*	reset_ctrl_rssi: reset Ctrl RSSI average
* Return value:
*	RSSI value
*/
uint16_t get_rssi(struct net_device * netdev, char *sta_mac, UINT16 * ctrl_rssi, bool reset_ctrl_rssi)
{
	struct wlprivate *priv;
	vmacApInfo_t *vmacSta_p;
	IEEEtypes_MacAddr_t sta_mac_addr;
	extStaDb_StaInfo_t *pStaInfo;
	uint16_t urssi_val = -1;
	SMAC_STA_ENTRY_st *pSta;
	struct wlprivate *parent_wlpptr;
	U32 shal_sta_entry_val;

	if (netdev == NULL) {
		goto funcfinal;
	}
	priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacSta_p = priv->vmacSta_p;
	parent_wlpptr = GET_PARENT_PRIV(priv);
	shal_sta_entry_val = parent_wlpptr->staBasePtr - SMAC_DMEM_START;

	sscanf(sta_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
	       &sta_mac_addr[0], &sta_mac_addr[1], &sta_mac_addr[2], &sta_mac_addr[3], &sta_mac_addr[4], &sta_mac_addr[5]);
	//printk("=>%s(%s), %s, (%02x:%02x:%02x:%02x:%02x:%02x)\n", __func__, netdev->name, 
	//      sta_mac,
	//      sta_mac_addr[0], sta_mac_addr[1], sta_mac_addr[2], 
	//      sta_mac_addr[3], sta_mac_addr[4], sta_mac_addr[5]);

	if (NULL == (pStaInfo = extStaDb_GetStaInfo(vmacSta_p, &sta_mac_addr, STADB_DONT_UPDATE_AGINGTIME))) {
		printk("%s(), Can't find StaInfo\n", __func__);
		*ctrl_rssi = -1;
		goto funcfinal;
	}

	urssi_val = (uint16_t) wl_util_get_rssi(netdev, &pStaInfo->RSSI_path, NULL);
	pSta = (SMAC_STA_ENTRY_st *) (shal_sta_entry_val + priv->ioBase0) + (bss_num + pStaInfo->StnId);

	//printk("<=%s(), (u, s)=(%u, %d)\n", __func__, urssi_val, srssi_val);
	//printk("RSSI [%pM]: %d\n", sta_mac_addr, (int16_t)urssi_val);
	if (reset_ctrl_rssi) {
		printk("reset rssi\n");
		pSta->rx_rssi = -1;
	}

	*ctrl_rssi = pSta->rx_rssi;
	//printk("Ctrl RSSI [%pM], ctrl_rssi: %d\n", pSta->macAddr, (int16_t) *ctrl_rssi);

 funcfinal:
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
struct net_device *get_netdev(char *dev_name)
{
	struct wlprivate *wlpptr;
	u8 card_idx, vap_idx;
	struct net_device *vnet_dev, *ret_dev = NULL;

	//printk("=>get_netdev(), %s\n", dev_name);
	for (card_idx = 0; card_idx < MAX_CARDS_SUPPORT; card_idx++) {
		if ((global_private_data[card_idx % MAX_CARDS_SUPPORT])->rootdev == NULL) {
			printk("rootdev == NULL (%u)\n", card_idx);
			continue;
		}
		//printk("root: %s\n", global_private_data[card_idx % MAX_CARDS_SUPPORT]->rootdev->name);
		wlpptr = NETDEV_PRIV(struct wlprivate, global_private_data[card_idx % MAX_CARDS_SUPPORT]->rootdev);
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
void set_cb(struct net_device *netdev, u8 mode, int is_resp_mgmt)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct wlprivate *parent_wlpptr = GET_PARENT_PRIV(priv);
	struct wlprivate_data *wlpd_p = priv->wlpd_p;
	UINT16 mcq = priv->vap_id * MAX_TID;

	printk("%s(), %s, is_resp_mgmt=%d\n", __func__, netdev->name, is_resp_mgmt);
	if (priv == NULL) {
		goto funcFinal;
	}
	// Enable the cb mode
	priv->is_resp_mgmt = is_resp_mgmt;
	priv->cb_enable = mode;
	priv->cbinfo_bss.enable_tx = is_resp_mgmt;
	wlFwSetApCBMode(netdev, priv->cb_enable);
	if ((parent_wlpptr->bcnBasePtr == 0) ||
	    (parent_wlpptr->bssBasePtr == 0) || (parent_wlpptr->txqBasePtr == 0) || (parent_wlpptr->staBasePtr == 0)) {
		printk("Error: Not all info ready, force to disable CB\n");
		priv->cb_enable = FALSE;
		goto funcFinal;
	}

	if (priv->cb_enable == TRUE) {
		// Initialize the CB function
		// Lunch a timer to call beacon_update() periodically
		TimerInit(&priv->bnc_timer);
		TimerFireIn(&priv->bnc_timer, 1, &bcn_timer_routine, (void *)priv->netDev, 1);
		TimerInit(&priv->cb_mctmer);
		TimerInit(&priv->cb_mctesttmer);
		skb_queue_head_init(&priv->cb_ncpkt_q);
		spin_lock_init(&priv->cbmc_lock);
		priv->cbmc_info.sn = wlpd_p->except_cnt.txq_send_cnt[mcq];
		priv->cbmc_info.iv = 0;
		printk("%s(), init cbmc_sn: %u\n", __func__, priv->cbmc_info.sn);
	} else {
		// Close the timer if it's not cb_enabled
		while (timer_pending(&priv->bnc_timer)) {
			msleep(1);
		}
		TimerRemove(&priv->bnc_timer);
		// Close the timer if it's not cb_enabled
		while (timer_pending(&priv->cb_mctmer)) {
			msleep(1);
		}
		TimerRemove(&priv->cb_mctmer);
	}
	printk("<= %s()\n", __func__);

 funcFinal:
	return;
}

EXPORT_SYMBOL(set_cb);

/*
* function: set_cust_ie(): Set the customer IE
* Input parameters:
*	net_device: Pointer of the net_device of the interface
*   buf: the buffer pointer of the IE
* 	len: the length of buffer
* Return: None
*/
void set_cust_ie(struct net_device *netdev, UINT8 * buf, UINT8 len)
{
	struct wlprivate *priv = NETDEV_PRIV_P(struct wlprivate, netdev);

	if ((0 < len) && (len <= sizeof(priv->cust_ie))) {
		priv->custie_len = len;
		memcpy(priv->cust_ie, buf, len);
		wlFwSetIEs(netdev);
	} else {
		printk("Invalid length: %u, limit: %lu\n", len, sizeof(priv->cust_ie));
	}
	return;
}

EXPORT_SYMBOL(set_cust_ie);

/*
* function: set_cbcallbk_func(): Pass the pointers of the callback functions
* Input parameters:
*	net_device: Pointer of the net_device of the interface
* 	pcallcb_func: Structure of the callback function pointers
* Return: None
*/
void set_cbcallbk_func(struct net_device *netdev, cbcallbk_intf * pcallcb_func)
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

void bcn_timer_routine(unsigned long arg)
{
	struct net_device *netdev = (struct net_device *)arg;
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;

	if (vmacSta_p->InfUpFlag == 0) {
		// closed
		return;
	}
	if (wlpptr->bcn_drop_cnt > 0) {
		// Drop beacons
		update_bcn_handler_1(netdev);
	}
	// Call update beacon packet handler
	//update_bcn_handler(netdev);

	//TimerInit(&wlpptr->bnc_timer);
	//TimerFireIn(&wlpptr->bnc_timer,
	//                              1, &bcn_timer_routine, (void *)wlpptr->netDev, 1);
	TimerFireInByJiffies(&wlpptr->bnc_timer, 1, &bcn_timer_routine, (void *)wlpptr->netDev, (HZ / 20));
}

#if 0
extern int mwl_config_set_essid(struct net_device *netdev, const char *ssid, uint8_t ssid_len);
/*
	Note: Limitations:
		- The sequence of IE in new bcn == the one in the old bcn
		- The added ones are appended to the end of the buffer
*/
static void update_mib(struct net_device *netdev, u8 * new_bcn, u8 * old_bcn)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	vmacApInfo_t *vmacSta_p = wlpptr->vmacSta_p;
	MIB_802DOT11 *mib = vmacSta_p->Mib802dot11;
	u8 *pn_bcn_buf = new_bcn;
	u8 *po_bcn_buf = old_bcn;
	IEEEtypes_InfoElementHdr_t *pIE_new = (IEEEtypes_InfoElementHdr_t *) pn_bcn_buf;
	IEEEtypes_InfoElementHdr_t *pIE_old = (IEEEtypes_InfoElementHdr_t *) po_bcn_buf;

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
			if ((pIE_old->ElementId == VHT_CAP) && memcmp(pIE_new, pIE_old, pIE_old->Len)) {
				IEEEtypes_VhtCap_t *ptr = (IEEEtypes_VhtCap_t *) pIE_new;
				*(mib->pMib_11nAggrMode) &= ~WL_MODE_AMSDU_TX_MASK;
				if (ptr->cap.MaximumMPDULength == 1) {
					*(mib->pMib_11nAggrMode) |= WL_MODE_AMSDU_TX_8K;
				} else if (ptr->cap.MaximumMPDULength == 2) {
					*(mib->pMib_11nAggrMode) |= WL_MODE_AMSDU_TX_11K;
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

static void update_bcn_handler(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	int res_cb;
	struct wlprivate *parent_wlpptr = GET_PARENT_PRIV(wlpptr);
	U32 Shal_BcnBuff_val = (parent_wlpptr->bcnBasePtr +
				(((SMAC_CTRL_BLK_st *) wlpptr->ioBase0)->status.maxSizeBcnbuf) * (wlpptr->vap_id)) - DMEM_BASE;
	HAL_BEACON_st *pShal_BcnBuff = (HAL_BEACON_st *) ((u8 *) wlpptr->ioBase0 + Shal_BcnBuff_val);
	HAL_BEACON_st *pl_bcnbuf;
	uint64_t timestamp;
	struct sk_buff *skb_bcn;
	struct sk_buff *skb_orig_bcn;

	// Always turn on beacon, since it may have been turned off in the last run
	wlpptr->smacCfgAddr->bcnStop &= ~(0x1 << wlpptr->vap_id);

	// beacon_update() callback has not hooked up
	if (wlpptr->cb_callbk_func.beacon_update == NULL) {
//              printk("%s(), beacon_update() == NULL\n", __func__);
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
	timestamp = (((uint64_t) (pl_bcnbuf->timestamp[1])) << 32 | pl_bcnbuf->timestamp[0]) + pl_bcnbuf->bcnInterval;
	// Call to update beacon
	res_cb = wlpptr->cb_callbk_func.beacon_update(netdev->dev_addr, skb_bcn, timestamp);
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
#endif				//0

static void update_bcn_handler_1(struct net_device *netdev)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	uint16_t bcn_sn = cb_get_bcn_sn(netdev);
	uint16_t sn_diff = (bcn_sn - wlpptr->txbcn_sn) & 0xfff;

	if (sn_diff >= wlpptr->bcn_drop_cnt) {	// drop enough bcn || next bcn has not been sent (sn_diff & 0x800 >0) , the number is also > bcn_drop_cnt
		//(wlpptr->txbcn_sn > bcn_sn)) {                                //
		// Enable the beacon
		cb_set_bcn_mask(netdev, TRUE);
		if ((sn_diff & 0x800) == 0) {
			//if (bcn_sn > ((wlpptr->txbcn_sn)&0xfff)) {
			wlpptr->txbcn_sn = bcn_sn + 1;
		}
	} else {
		// Disable the beacon if it has been sent
		cb_set_bcn_mask(netdev, FALSE);
	}
	return;
}

/*
	Check if the packet can be sent or dropped
*/
bool cb_tx_allow(struct net_device * netdev, struct sk_buff * skb, void *pStaInfo, int type)
{
	struct wlprivate *wlpptr = NETDEV_PRIV_P(struct wlprivate, netdev);
	struct ieee80211_frame *ieee80211_hdr = (struct ieee80211_frame *)&skb->data[0];
	struct ether_header *pEth;

	// auth / assoc / prob_resp, mcast pkt, cbinfo_bss->enable_tx == false  => drop
	if (type == IEEE_TYPE_MANAGEMENT) {
		if ((ieee80211_hdr->FrmCtl.Subtype == IEEE_MSG_ASSOCIATE_RQST) ||
		    (ieee80211_hdr->FrmCtl.Subtype == IEEE_MSG_ASSOCIATE_RSP) ||
		    (ieee80211_hdr->FrmCtl.Subtype == IEEE_MSG_AUTHENTICATE) || (ieee80211_hdr->FrmCtl.Subtype == IEEE_MSG_PROBE_RSP)) {
			// dbg
			/*if (wlpptr->cbinfo_bss.enable_tx == false) {
			   printk("[%s] drop mgmt_type[%u]\n", netdev->name, ieee80211_hdr->FrmCtl.Subtype);
			   } else {
			   printk("[%s] accept mgmt_type[%u]\n", netdev->name, ieee80211_hdr->FrmCtl.Subtype);
			   } */
			return wlpptr->cbinfo_bss.enable_tx;
		} else {
			if (pStaInfo != NULL) {
				// Other mgmt packets => check the STA status
				// dbg
				/*if (wlpptr->cbinfo_sta[((extStaDb_StaInfo_t*)pStaInfo)->StnId].enable_tx == false) {
				   printk("[%s] drop unicast mgmt pkts[%u]\n", netdev->name, ieee80211_hdr->FrmCtl.Subtype);
				   } */
				//return wlpd_p->cbinfo_sta[((extStaDb_StaInfo_t*)pStaInfo)->StnId].enable_tx;
				return ((extStaDb_StaInfo_t *) pStaInfo)->cbinfo_sta.enable_tx;
			} else {
				// dbg
				/*if (wlpptr->cbinfo_bss.enable_tx == false) {
				   printk("[%s] drop bcast mgmt_type[%u]\n", netdev->name, ieee80211_hdr->FrmCtl.Subtype);
				   } */
				return wlpptr->cbinfo_bss.enable_tx;
			}
		}
	}
	// Processing data packets
	pEth = (struct ether_header *)skb->data;
	if (type == IEEE_TYPE_DATA) {
		if (IS_GROUP((UINT8 *) & (pEth->ether_dhost))) {
			// mcast pkts => use enable_tx of bss
			/*if (wlpptr->cbinfo_bss.enable_tx == false) {
			   printk("[%s] drop mcast pkts\n", netdev->name);
			   } */
			return wlpptr->cbinfo_bss.enable_tx;
		} else {
			// unicast pkt => use cbinfo_sta[stnid]->enable_tx
			if (((extStaDb_StaInfo_t *) pStaInfo)->cbinfo_sta.enable_tx == false) {
				/*
				   printk("[%s] drop unicast, [da:%pM], [sa: %pM][stnid: %u]\n",
				   netdev->name,
				   pEth->ether_dhost, pEth->ether_shost,
				   ((extStaDb_StaInfo_t*)pStaInfo)->StnId);
				 */
				wlpptr->cbinfo_bss.tx_drop_cnt++;
			}
			return ((extStaDb_StaInfo_t *) pStaInfo)->cbinfo_sta.enable_tx;
		}
	}
	return true;
}

#endif				//CB_SUPPORT
