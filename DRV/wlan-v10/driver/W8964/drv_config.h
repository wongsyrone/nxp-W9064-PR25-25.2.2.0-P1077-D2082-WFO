/** @file drv_config.h
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

/* Description:  This file defines driver configuration related functions. */

#ifndef _DRV_CONFIG_H
#define __DRV_CONFIG_H

enum mwl_tx_rate_type {
	MWL_RATE_B,
	MWL_RATE_G,
	MWL_RATE_N,
	MWL_RATE_A,
	MWL_RATE_MCBC,
	MWL_RATE_MGT,
#ifdef BRS_SUPPORT
	MWL_RATE_BRS,
	MWL_RATE_SRS,
#endif
	MWL_RATE_VHT,
	MWL_RATE_RATE_INFO
};

enum mwl_set_reg_type {
	MWL_SET_REG_MAC,
	MWL_SET_REG_RF,
	MWL_SET_REG_BB,
	MWL_SET_REG_CAU,
	MWL_SET_REG_ADDR0,
	MWL_SET_REG_ADDR1,
	MWL_SET_REG_ADDR
};

enum mwl_debug_type {
	MWL_DEBUG_INJECTRX,
	MWL_DEBUG_DEBUG_TX,
	MWL_DEBUG_TCP_ACK,
	MWL_DEBUG_MCS_CAP,
	MWL_DEBUG_VHT_CAP,
	MWL_DEBUG_VHT_OPT,
	MWL_DEBUG_READ,
	MWL_DEBUG_WRITE,
	MWL_DEBUG_DUMP,
	MWL_DEBUG_MAP,
	MWL_DEBUG_HELP
};

enum mwl_debug_injectrx_type {
	MWL_DEBUG_INJECTRX_AUTH,
	MWL_DEBUG_INJECTRX_ASSOC,
	MWL_DEBUG_INJECTRX_DEAUTH,
	MWL_DEBUG_INJECTRX_DEASSOC
};

enum mwl_debug_tx_type {
	MWL_DEBUG_TX_DEAUTHALL,
	MWL_DEBUG_TX_DEAUTH,
	MWL_DEBUG_TX_DEASSOC,
	MWL_DEBUG_TX_SAQUERY
};

enum mwl_debug_dump_type {
	MWL_DEBUG_DUMP_MM,
	MWL_DEBUG_DUMP_RF,
	MWL_DEBUG_DUMP_BB
};

enum mwl_memdump_type {
	MWL_GET_MEMDUMP_MM,
	MWL_GET_MEMDUMP_MS,
	MWL_GET_MEMDUMP_RF,
	MWL_GET_MEMDUMP_BB,
	MWL_GET_MEMDUMP_ADDR,
};

enum mwl_ipmcgrp_type {
	MWL_SET_IPMCGRP_ADD,
	MWL_SET_IPMCGRP_DEL,
	MWL_SET_IPMCGRP_DELGRP,
	MWL_SET_IPMCGRP_ADDIPMFILTER,
	MWL_SET_IPMCGRP_DELIPMFILTER,
	MWL_SET_IPMCGRP_GETGRP,
	MWL_SET_IPMCGRP_GETALLGRPS,
	MWL_SET_IPMCGRP_GETIPMFILTER
};

enum mwl_rptrmode_type {
	MWL_SET_RPTRMODE_NONE,
	MWL_SET_RPTRMODE_ZERO,
	MWL_SET_RPTRMODE_ONE,
	MWL_SET_RPTRMODE_DEVICETYPE,
	MWL_SET_IPMCGRP_AGINGTIME,
	MWL_SET_IPMCGRP_LISTMAC,
	MWL_SET_IPMCGRP_ADDMAC,
	MWL_SET_IPMCGRP_DELMAC
};

enum mwl_qstats_type {
	MWL_GET_QSTATS_PKTCOUNT,
	MWL_GET_QSTATS_RETRY_HISTOGRAM,
	MWL_GET_QSTATS_TXBA_HISTOGRAM,
	MWL_GET_QSTATS_TXRATE_HISTOGRAM,
	MWL_GET_QSTATS_RXRATE_HISTOGRAM,
	MWL_GET_QSTATS_ADDRXMAC,
	MWL_GET_QSTATS_ADDTXMAC,
	MWL_GET_QSTATS_TXLATENCY,
	MWL_GET_QSTATS_RXLATENCY,
	MWL_GET_QSTATS_RESET,
};

#define MWL_WEP_ENCODE_DISABLED	0x01	/* Encoding disabled */
#define MWL_WEP_ENCODE_RESTRICTED	0x02	/* Refuse non-encoded packets */
#define MWL_WEP_ENCODE_OPEN		0x04	/* Accept non-encoded packets */

int mwl_drv_get_version(struct net_device *netdev, char *version);
int mwl_drv_commit(struct net_device *netdev);
int mwl_drv_set_opmode(struct net_device *netdev, uint8_t opmode);
int mwl_drv_get_opmode(struct net_device *netdev);
int mwl_drv_set_stamode(struct net_device *netdev, uint8_t stamode);
int mwl_drv_get_stamode(struct net_device *netdev);
int mwl_drv_set_key(struct net_device *netdev, uint8_t key_type,
		    uint16_t key_idx, uint8_t key_len, uint8_t key_flag,
		    uint8_t * macaddr, uint64_t key_recv_seq,
		    uint64_t key_xmit_seq, uint8_t * key, uint8_t * key_pn);
int mwl_drv_del_key(struct net_device *netdev, uint16_t key_idx,
		    uint8_t * macaddr);
int mwl_drv_set_wpawpa2mode(struct net_device *netdev, uint8_t wpawpa2mode);
int mwl_drv_get_wpawpa2mode(struct net_device *netdev);
int mwl_drv_set_passphrase(struct net_device *netdev, uint8_t mode,
			   char *passphrase, uint8_t len);
int mwl_drv_get_passphrase(struct net_device *netdev, char *passphrase);
int mwl_drv_set_ciphersuite(struct net_device *netdev, uint8_t wpamode,
			    uint8_t cipher);
int mwl_drv_get_ciphersuite(struct net_device *netdev, char *ciphersuite);
int mwl_drv_set_wmm(struct net_device *netdev, uint8_t mode);
int mwl_drv_get_wmm(struct net_device *netdev);
int mwl_drv_set_wmmedcaap(struct net_device *netdev, uint32_t ac,
			  uint32_t * param);
int mwl_drv_get_wmmedcaap(struct net_device *netdev, char *wmmedcaap);
int mwl_drv_set_amsdu(struct net_device *netdev, uint8_t value);
int mwl_drv_get_amsdu(struct net_device *netdev);
int mwl_drv_set_rxantenna(struct net_device *netdev, uint8_t value);
int mwl_drv_get_rxantenna(struct net_device *netdev);
int mwl_drv_set_optlevel(struct net_device *netdev, uint8_t value);
int mwl_drv_get_optlevel(struct net_device *netdev);
int mwl_drv_set_macclone(struct net_device *netdev, uint8_t enable);
int mwl_drv_set_stascan(struct net_device *netdev, uint8_t enable);
int mwl_drv_get_stascan(struct net_device *netdev, char *stascan);
int mwl_drv_set_fixrate(struct net_device *netdev, uint8_t value);
int mwl_drv_get_fixrate(struct net_device *netdev);
int mwl_drv_set_txrate(struct net_device *netdev, uint8_t type, uint16_t rate);
int mwl_drv_get_txrate(struct net_device *netdev, char *txrate);
int mwl_drv_set_mcastproxy(struct net_device *netdev, uint8_t value);
int mwl_drv_get_mcastproxy(struct net_device *netdev);
int mwl_drv_set_11hstamode(struct net_device *netdev, uint8_t value);
int mwl_drv_get_11hstamode(struct net_device *netdev);
int mwl_drv_get_rssi(struct net_device *netdev);
int mwl_drv_get_linkstatus(struct net_device *netdev);
int mwl_drv_get_stalistext(struct net_device *netdev, char *stalistext);
int mwl_drv_set_grouprekey(struct net_device *netdev, uint32_t value);
int mwl_drv_get_grouprekey(struct net_device *netdev);
int mwl_drv_set_wmmedcasta(struct net_device *netdev, uint32_t ac,
			   uint32_t * param);
int mwl_drv_get_wmmedcasta(struct net_device *netdev, char *wmmedcasta);
int mwl_drv_set_htbw(struct net_device *netdev, uint8_t value);
int mwl_drv_get_htbw(struct net_device *netdev);
int mwl_drv_set_filter(struct net_device *netdev, uint8_t value);
int mwl_drv_get_filter(struct net_device *netdev);
int mwl_drv_add_filtermac(struct net_device *netdev, char *macaddr,
			  uint8_t len);
int mwl_drv_del_filtermac(struct net_device *netdev, char *macaddr,
			  uint8_t len);
int mwl_drv_get_filtermac(struct net_device *netdev, char *buf);
int mwl_drv_set_intrabss(struct net_device *netdev, uint8_t intrabss);
int mwl_drv_get_intrabss(struct net_device *netdev);
int mwl_drv_set_hidessid(struct net_device *netdev, uint8_t hidessid);
int mwl_drv_get_hidessid(struct net_device *netdev);
int mwl_drv_set_bcninterval(struct net_device *netdev, uint16_t bcninterval);
int mwl_drv_get_bcninterval(struct net_device *netdev);
int mwl_drv_set_dtim(struct net_device *netdev, uint8_t dtim);
int mwl_drv_get_dtim(struct net_device *netdev);
int mwl_drv_set_gprotect(struct net_device *netdev, uint8_t gprotect);
int mwl_drv_get_gprotect(struct net_device *netdev);
int mwl_drv_set_preamble(struct net_device *netdev, uint8_t preamble);
int mwl_drv_get_preamble(struct net_device *netdev);
int mwl_drv_set_agingtime(struct net_device *netdev, uint32_t agingtime);
int mwl_drv_get_agingtime(struct net_device *netdev);
int mwl_drv_set_ssid(struct net_device *netdev, const char *ssid,
		     uint8_t ssid_len);
int mwl_drv_get_ssid(struct net_device *netdev, char *ssid);
int mwl_drv_set_bssid(struct net_device *netdev, uint8_t * bssid);
int mwl_drv_get_bssid(struct net_device *netdev, char *bssid);
int mwl_drv_set_regioncode(struct net_device *netdev, uint8_t regioncode);
int mwl_drv_get_regioncode(struct net_device *netdev, uint8_t * flag);
int mwl_drv_set_ratemode(struct net_device *netdev, uint8_t ratemode);
int mwl_drv_get_ratemode(struct net_device *netdev);
int mwl_drv_set_wdsmode(struct net_device *netdev, uint8_t wdsmode);
int mwl_drv_get_wdsmode(struct net_device *netdev);
int mwl_drv_set_disableassoc(struct net_device *netdev, uint8_t disableassoc);
int mwl_drv_get_disableassoc(struct net_device *netdev);
int mwl_drv_set_wds(struct net_device *netdev, uint8_t * wds);
int mwl_drv_get_wds(struct net_device *netdev, char *wds);
#ifdef IEEE80211_DH
int mwl_drv_set_11dmode(struct net_device *netdev, uint8_t dmode);
int mwl_drv_get_11dmode(struct net_device *netdev);
int mwl_drv_set_11hspecmgt(struct net_device *netdev, uint8_t hspecmgt);
int mwl_drv_get_11hspecmgt(struct net_device *netdev);
int mwl_drv_set_11hpwrconstr(struct net_device *netdev, uint8_t hpwrconstr);
int mwl_drv_get_11hpwrconstr(struct net_device *netdev);
int mwl_drv_set_11hcsaMode(struct net_device *netdev, uint8_t csamode);
int mwl_drv_get_11hcsaMode(struct net_device *netdev);
int mwl_drv_set_11hcsaCount(struct net_device *netdev, uint8_t value);
int mwl_drv_get_11hcsaCount(struct net_device *netdev);
int mwl_drv_set_11hdfsMode(struct net_device *netdev, uint8_t value);
int mwl_drv_get_11hdfsMode(struct net_device *netdev);
int mwl_drv_set_11hcsaChan(struct net_device *netdev, uint8_t value);
int mwl_drv_get_11hcsaChan(struct net_device *netdev);
int mwl_drv_set_11hcsaStart(struct net_device *netdev, uint8_t value);
#endif
#ifdef MRVL_DFS
int mwl_drv_set_11hnopTimeout(struct net_device *netdev, uint16_t value);
int mwl_drv_get_11hnopTimeout(struct net_device *netdev);
int mwl_drv_set_11hcacTimeout(struct net_device *netdev, uint8_t value);
int mwl_drv_get_11hcacTimeout(struct net_device *netdev);
#endif
int mwl_drv_set_csMode(struct net_device *netdev, uint8_t value);
int mwl_drv_get_csMode(struct net_device *netdev);
int mwl_drv_set_guardIntv(struct net_device *netdev, uint8_t value);
int mwl_drv_get_guardIntv(struct net_device *netdev);
int mwl_drv_set_extSubCh(struct net_device *netdev, uint8_t value);
int mwl_drv_get_extSubCh(struct net_device *netdev);
int mwl_drv_set_htProtect(struct net_device *netdev, uint8_t value);
int mwl_drv_get_htProtect(struct net_device *netdev);
int mwl_drv_set_ampduFactor(struct net_device *netdev, uint8_t value);
int mwl_drv_get_ampduFactor(struct net_device *netdev);
int mwl_drv_set_ampduDen(struct net_device *netdev, uint8_t value);
int mwl_drv_get_ampduDen(struct net_device *netdev);
#ifdef AMPDU_SUPPORT
int mwl_drv_set_ampduTx(struct net_device *netdev, uint8_t value);
int mwl_drv_get_ampduTx(struct net_device *netdev);
#endif
int mwl_drv_set_txPower(struct net_device *netdev, uint8_t value);
int mwl_drv_get_txPower(struct net_device *netdev);
int mwl_drv_get_fwStat(struct net_device *netdev);
int mwl_drv_set_autoChannel(struct net_device *netdev, uint8_t value);
int mwl_drv_get_autoChannel(struct net_device *netdev);
int mwl_drv_set_maxTxPower(struct net_device *netdev, uint8_t value);
int mwl_drv_get_maxTxPower(struct net_device *netdev);
int mwl_drv_del_wepKey(struct net_device *netdev, uint8_t value);
int mwl_drv_set_strictShared(struct net_device *netdev, uint8_t value);
int mwl_drv_get_strictShared(struct net_device *netdev);
#ifdef PWRFRAC
int mwl_drv_set_txPowerFraction(struct net_device *netdev, uint8_t value);
int mwl_drv_get_txPowerFraction(struct net_device *netdev);
#endif
int mwl_drv_set_mimops(struct net_device *netdev, int minops);
int mwl_drv_get_mimops(struct net_device *netdev);
int mwl_drv_set_txantenna(struct net_device *netdev, int txantenna);
int mwl_drv_get_txantenna(struct net_device *netdev);
int mwl_drv_set_htgf(struct net_device *netdev, int htgf);
int mwl_drv_get_htgf(struct net_device *netdev);
int mwl_drv_set_htstbc(struct net_device *netdev, int htstbc);
int mwl_drv_get_htstbc(struct net_device *netdev);
int mwl_drv_set_3x3rate(struct net_device *netdev, int rate3x3);
int mwl_drv_get_3x3rate(struct net_device *netdev);
int mwl_drv_set_intolerant40(struct net_device *netdev, unsigned char *param,
			     int data_len);
int mwl_drv_set_txqlimit(struct net_device *netdev, unsigned int txqlimit);
int mwl_drv_get_txqlimit(struct net_device *netdev);
int mwl_drv_set_rifs(struct net_device *netdev, unsigned char rifs);
int mwl_drv_set_bftype(struct net_device *netdev, int bftype);
int mwl_drv_set_bandsteer(struct net_device *netdev, uint8_t bandsteer);
int mwl_drv_get_bandsteer(struct net_device *netdev);
int mwl_drv_set_appie(struct net_device *netdev, struct mwl_appie *appie);
int mwl_drv_get_ie(struct net_device *netdev, uint8_t ie_type,
		   uint8_t * macaddr, uint16_t * ie_len, uint8_t * reassoc,
		   uint8_t * ie);
int mwl_drv_send_mlme(struct net_device *netdev, struct mwl_mlme *mlme);
int mwl_drv_set_countermeasures(struct net_device *netdev, int enabled);
int mwl_drv_get_seqnum(struct net_device *netdev, uint8_t * seqnum);
int mwl_drv_send_mgmt(struct net_device *netdev, struct mwl_mgmt *mgmt);
int mwl_drv_set_rts(struct net_device *netdev, uint16_t rts);
int mwl_drv_set_channel(struct net_device *netdev, uint8_t channel);
int mwl_drv_set_wepkey(struct net_device *netdev, uint8_t * data, int key_len);
int mwl_drv_set_wapimode(struct net_device *netdev, uint8_t wapimode);
int mwl_drv_get_wapimode(struct net_device *netdev);
int mwl_drv_set_wmmackpolicy(struct net_device *netdev, uint8_t wmmackpolicy);
int mwl_drv_get_wmmackpolicy(struct net_device *netdev);
int mwl_drv_set_txantenna2(struct net_device *netdev, uint8_t txantenna2);
int mwl_drv_get_txantenna2(struct net_device *netdev);
int mwl_drv_get_deviceinfo(struct net_device *netdev);
int mwl_drv_set_interop(struct net_device *netdev, uint8_t interop);
int mwl_drv_get_interop(struct net_device *netdev);
int mwl_drv_set_11hETSICAC(struct net_device *netdev, uint16_t timeout);
int mwl_drv_get_11hETSICAC(struct net_device *netdev);
int mwl_drv_set_rxintlimit(struct net_device *netdev, uint32_t value);
int mwl_drv_get_rxintlimit(struct net_device *netdev);
int mwl_drv_set_intoler(struct net_device *netdev, uint8_t value);
int mwl_drv_get_intoler(struct net_device *netdev);
int mwl_drv_set_rxpathopt(struct net_device *netdev, uint32_t value);
int mwl_drv_get_rxpathopt(struct net_device *netdev);
int mwl_drv_set_amsduft(struct net_device *netdev, uint16_t value);
int mwl_drv_get_amsduft(struct net_device *netdev);
int mwl_drv_set_amsdums(struct net_device *netdev, uint16_t value);
int mwl_drv_get_amsdums(struct net_device *netdev);
int mwl_drv_set_amsduas(struct net_device *netdev, uint16_t value);
int mwl_drv_get_amsduas(struct net_device *netdev);
int mwl_drv_set_amsdupc(struct net_device *netdev, uint8_t value);
int mwl_drv_get_amsdupc(struct net_device *netdev);
int mwl_drv_set_cdd(struct net_device *netdev, uint32_t value);
int mwl_drv_get_cdd(struct net_device *netdev);
int mwl_drv_set_acsthrd(struct net_device *netdev, uint32_t value);
int mwl_drv_get_acsthrd(struct net_device *netdev);
int mwl_drv_get_deviceid(struct net_device *netdev);
int mwl_drv_set_rrm(struct net_device *netdev, uint8_t value);
int mwl_drv_get_rrm(struct net_device *netdev);
int mwl_drv_set_autoscan(struct net_device *netdev, uint8_t value);
int mwl_drv_get_autoscan(struct net_device *netdev);
int mwl_drv_set_dms(struct net_device *netdev, uint32_t value);
int mwl_drv_get_dms(struct net_device *netdev);
int mwl_drv_get_sysload(struct net_device *netdev);
int mwl_drv_get_11hNOCList(struct net_device *netdev, uint8_t * out);
int mwl_drv_get_bssprofile(struct net_device *netdev, uint8_t * out);
int mwl_drv_get_tlv(struct net_device *netdev, uint16_t type, uint8_t * out);
int mwl_drv_get_chnls(struct net_device *netdev, uint8_t * buff);
int mwl_drv_set_scanchannels(struct net_device *netdev, uint8_t * chlist);
int mwl_drv_set_wtp(struct net_device *netdev, int enable);
int mwl_drv_set_wtpmacmode(struct net_device *netdev, int macmode);
int mwl_drv_set_wtptunnelmode(struct net_device *netdev, int tunnelmode);
int mwl_drv_get_wtpcfg(struct net_device *netdev, uint8_t * out);
int mwl_drv_get_radiostat(struct net_device *netdev, uint8_t * out);
int mwl_drv_set_extfw(struct net_device *netdev, char *filepath);
int mwl_drv_set_mfgfw(struct net_device *netdev, char *filepath);
int mwl_drv_set_mfg(struct net_device *netdev, uint8_t * cmd, uint8_t * out);
int mwl_drv_set_fwrev(struct net_device *netdev);
int mwl_drv_set_addba(struct net_device *netdev, uint8_t * mac, int tid,
		      int stream);
int mwl_drv_get_ampdustat(struct net_device *netdev);
int mwl_drv_set_delba(struct net_device *netdev, uint8_t * macaddr,
		      uint8_t tid);
int mwl_drv_set_del2ba(struct net_device *netdev, uint8_t * macaddr,
		       uint8_t tid);
int mwl_drv_set_ampdurxdisable(struct net_device *netdev, uint8_t option);
int mwl_drv_set_triggerscaninterval(struct net_device *netdev,
				    uint16_t triggerscaninterval);
int mwl_drv_set_bf(struct net_device *netdev, uint8_t * param);
int mwl_drv_get_mumimomgmt(struct net_device *netdev);
int mwl_drv_set_mumimomgmt(struct net_device *netdev, uint32_t value);
int mwl_drv_get_musta(struct net_device *netdev);
int mwl_drv_get_muset(struct net_device *netdev, uint8_t value);
int mwl_drv_set_muset(struct net_device *netdev, uint16_t * param);
int mwl_drv_del_muset(struct net_device *netdev, uint8_t index);
int mwl_drv_set_mug_enable(struct net_device *netdev, uint32_t enable);
int mwl_drv_get_muinfo(struct net_device *netdev, uint8_t value);
int mwl_drv_get_mugroups(struct net_device *netdev, uint8_t value);
int mwl_drv_set_muconfig(struct net_device *netdev, uint32_t corr_thr_decimal,
			 uint16_t sta_cep_age_thr, uint16_t period_ms);
int mwl_drv_set_muautotimer(struct net_device *netdev, uint8_t set,
			    uint32_t value);
int mwl_drv_set_mupreferusrcnt(struct net_device *netdev, uint8_t value);
int mwl_drv_set_gid(struct net_device *netdev, uint8_t * macaddr);
int mwl_drv_set_noack(struct net_device *netdev, uint8_t enable);
int mwl_drv_set_nosteer(struct net_device *netdev, uint8_t enable);
int mwl_drv_set_txhop(struct net_device *netdev, uint8_t enable,
		      uint8_t txhopstatus);
int mwl_drv_get_bftype(struct net_device *netdev);
int mwl_drv_get_bwsignaltype(struct net_device *netdev);
int mwl_drv_set_bwsignaltype(struct net_device *netdev, uint8_t type,
			     uint8_t bitmap);
int mwl_drv_get_weakiv_threshold(struct net_device *netdev);
int mwl_drv_set_weakiv_threshold(struct net_device *netdev, uint32_t value);
int mwl_drv_set_tim(struct net_device *netdev, uint16_t aid, uint32_t set);
int mwl_drv_set_powersavestation(struct net_device *netdev,
				 uint8_t noofstations);
int mwl_drv_get_tim(struct net_device *netdev);
int mwl_drv_get_bcn(struct net_device *netdev);
int mwl_drv_set_annex(struct net_device *netdev, uint32_t annex,
		      uint32_t index);
int mwl_drv_set_readeepromhdr(struct net_device *netdev, uint32_t annex,
			      uint32_t index);
int mwl_drv_get_or(struct net_device *netdev);
int mwl_drv_get_addrtable(struct net_device *netdev);
int mwl_drv_get_fwencrinfo(struct net_device *netdev, uint8_t * macaddr);
int mwl_drv_set_reg(struct net_device *netdev, uint32_t regtype, uint32_t reg,
		    uint32_t value);
int mwl_drv_set_debug(struct net_device *netdev, uint32_t * data, int data_len);
int mwl_drv_get_memdump(struct net_device *netdev, uint32_t * data);
int mwl_drv_set_desire_bssid(struct net_device *netdev, uint8_t * desireBSSID);
int mwl_drv_get_ewbtable(void);
int mwl_drv_set_ratetable(struct net_device *netdev, uint8_t clear,
			  uint8_t * macaddr, uint32_t rateinfo);
int mwl_drv_get_ratetable(struct net_device *netdev, uint8_t mu,
			  uint8_t * macaddr);
int mwl_drv_set_ampdu_bamgmt(struct net_device *netdev, uint32_t val);
int mwl_drv_get_ampdu_bamgmt(struct net_device *netdev);
int mwl_drv_set_ampdu_mintraffic(struct net_device *netdev, uint32_t bk,
				 uint32_t be, uint32_t vi, uint32_t vo);
int mwl_drv_get_ampdu_mintraffic(struct net_device *netdev);
int mwl_drv_set_ac_threshold(struct net_device *netdev, uint32_t bk,
			     uint32_t be, uint32_t vi, uint32_t vo);
int mwl_drv_get_ac_threshold(struct net_device *netdev);
int mwl_drv_set_dfstest(uint8_t testmode);
int mwl_drv_set_ipmcgrp(struct net_device *netdev, uint8_t setmode,
			uint8_t * ipaddr, uint8_t * macaddr);
int mwl_drv_set_rptrmode(struct net_device *netdev, uint8_t mode,
			 uint8_t * devicetype, uint8_t * agingtime,
			 uint8_t * macaddr);
int mwl_drv_set_load_txpowertable(struct net_device *netdev,
				  uint8_t * filename);
int mwl_drv_get_txpowertable(struct net_device *netdev);
int mwl_drv_set_linklost(uint32_t macIndex, uint32_t numOfInterval);
int mwl_drv_set_ssutest(struct wlprivate *priv, uint32_t * data);
int mwl_drv_get_qstats(struct net_device *netdev, uint8_t qstattype,
		       uint32_t pktcount, uint32_t staidlabel, uint32_t enable,
		       uint32_t staid1, uint32_t staid2, uint32_t staid3,
		       uint32_t sumu, uint32_t staid4, uint8_t * macaddr);
int mwl_drv_set_rccal(struct net_device *netdev);
int mwl_drv_get_temp(struct net_device *netdev);
int mwl_drv_set_maxsta(struct net_device *netdev, uint32_t maxsta);
int mwl_drv_get_maxsta(struct net_device *netdev);
int mwl_drv_set_txfaillimit(struct net_device *netdev, uint32_t txfaillimit);
int mwl_drv_get_txfaillimit(struct net_device *netdev);
int mwl_drv_set_wapi(struct net_device *netdev, uint8_t broadcast,
		     uint8_t * macaddr);
int mwl_drv_set_led(struct net_device *netdev, uint32_t onoff);
int mwl_drv_set_fastreconnect(uint32_t probereqontx);
int mwl_drv_set_newdp(struct net_device *netdev, uint32_t ch, uint32_t width,
		      uint32_t rates, uint32_t rate_type, uint32_t rate_bw,
		      uint32_t rate_gi, uint32_t rate_ss);
int mwl_drv_set_txratectrl(struct net_device *netdev, uint32_t type,
			   uint32_t val, uint32_t staid);
int mwl_drv_get_newdpcnt(struct net_device *netdev);
int mwl_drv_set_newdpacntsize(struct net_device *netdev);
int mwl_drv_get_newdpacnt(struct net_device *netdev);
int mwl_drv_set_newdpOffch(struct net_device *netdev,
			   DOT11_OFFCHAN_REQ_t * pOffchan);
int mwl_drv_set_txContinuous(struct net_device *netdev, uint8_t mode,
			     uint32_t rateinfo);
int mwl_drv_set_rxSop(struct net_device *netdev, uint8_t params,
		      uint8_t threshold1, uint8_t threshold2);
int mwl_drv_set_pwrPerRate(struct net_device *netdev, struct file *filp,
			   char *path);
int mwl_drv_set_rateGrps(struct net_device *netdev, struct file *filp,
			 char *path);
int mwl_drv_set_pwrGrpsTbl(struct net_device *netdev, struct file *filp,
			   char *path);
int mwl_drv_set_perRatePwr(struct net_device *netdev);
int mwl_drv_get_perRatePwr(struct net_device *netdev, uint32_t RatePower,
			   uint8_t * trpcid, uint16_t * dBm, uint16_t * ant);
int mwl_drv_get_nf(struct net_device *netdev);
int mwl_drv_get_radioStatus(struct net_device *netdev);
int mwl_drv_set_ldpc(struct net_device *netdev, uint8_t enable);
int mwl_drv_set_tlv(struct net_device *netdev, uint8_t act, uint16_t type,
		    uint16_t len, uint8_t * tlvData, char *buff);
int mwl_drv_set_ampduCfg(struct net_device *netdev, uint8_t cfg);
int mwl_drv_set_amsduCfg(struct net_device *netdev, amsducfg_t * amsducfg);
int mwl_drv_set_bbDbg(struct net_device *netdev, UINT8 hasId, UINT32 client_id);
int mwl_drv_set_mu_sm_cache(struct net_device *netdev, UINT8 hasId,
			    UINT32 client_id);
int mwl_drv_set_sku(struct net_device *netdev, UINT32 sku);
int mwl_drv_set_rxAntBitmap(struct net_device *netdev, uint8_t hasBitmap,
			    UINT32 bitmap);
int mwl_drv_set_retryCfgEnable(struct net_device *netdev, UINT8 Enable);
int mwl_drv_set_retryCfg(struct net_device *netdev, char *mode, char *param);
int mwl_drv_set_radioRatesCfg(struct net_device *netdev, char *mode,
			      UINT8 * param);
int mwl_drv_set_eewr(struct net_device *netdev, uint32_t offset,
		     uint32_t NumOfEntry, char *path);
int mwl_drv_get_eerd(struct net_device *netdev, uint32_t offset,
		     uint32_t NumOfEntry, char *path);
#endif /* _DRV_CONFIG_H */
