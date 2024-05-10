/** @file vendor.h
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

/* Description:  This file defines vendor commands related functions. */

#ifndef _MWL_VENDOR_H
#define _MWL_VENDOR_H

#define MRVL_OUI	0x005043

enum mwl_vendor_commands {
	MWL_VENDOR_CMD_GET_VERSION,
	MWL_VENDOR_CMD_COMMIT,
	MWL_VENDOR_CMD_SET_OPMODE,
	MWL_VENDOR_CMD_GET_OPMODE,
	MWL_VENDOR_CMD_SET_STAMODE,
	MWL_VENDOR_CMD_GET_STAMODE,	//0x05
	MWL_VENDOR_CMD_SET_KEY,
	MWL_VENDOR_CMD_DEL_KEY,
	MWL_VENDOR_CMD_SET_WPAWPA2MODE,
	MWL_VENDOR_CMD_GET_WPAWPA2MODE,
	MWL_VENDOR_CMD_SET_PASSPHRASE,	//0x0A
	MWL_VENDOR_CMD_GET_PASSPHRASE,
	MWL_VENDOR_CMD_SET_CIPHERSUITE,
	MWL_VENDOR_CMD_GET_CIPHERSUITE,
	MWL_VENDOR_CMD_SET_WMM,
	MWL_VENDOR_CMD_GET_WMM,	//0x0F
	MWL_VENDOR_CMD_SET_WMMEDCAAP,	//0x10
	MWL_VENDOR_CMD_GET_WMMEDCAAP,
	MWL_VENDOR_CMD_SET_AMSDU,
	MWL_VENDOR_CMD_GET_AMSDU,
	MWL_VENDOR_CMD_SET_RXANTENNA,
	MWL_VENDOR_CMD_GET_RXANTENNA,	//0x15
	MWL_VENDOR_CMD_SET_OPTLEVEL,
	MWL_VENDOR_CMD_GET_OPTLEVEL,
	MWL_VENDOR_CMD_SET_MACCLONE,
	MWL_VENDOR_CMD_SET_STASCAN,
	MWL_VENDOR_CMD_GET_STASCAN,	//0x1A
	MWL_VENDOR_CMD_SET_FIXRATE,
	MWL_VENDOR_CMD_GET_FIXRATE,
	MWL_VENDOR_CMD_SET_TXRATE,
	MWL_VENDOR_CMD_GET_TXRATE,
	MWL_VENDOR_CMD_SET_MCASTPROXY,	//0x1F
	MWL_VENDOR_CMD_GET_MCASTPROXY,	//0x20
	MWL_VENDOR_CMD_SET_11HSTAMODE,
	MWL_VENDOR_CMD_GET_11HSTAMODE,
	MWL_VENDOR_CMD_GET_RSSI,
	MWL_VENDOR_CMD_GET_LINKSTATUS,
	MWL_VENDOR_CMD_GET_STALISTEXT,	//0x25
	MWL_VENDOR_CMD_SET_GROUPREKEY,
	MWL_VENDOR_CMD_GET_GROUPREKEY,
	MWL_VENDOR_CMD_SET_WMMEDCASTA,
	MWL_VENDOR_CMD_GET_WMMEDCASTA,
	MWL_VENDOR_CMD_SET_HTBW,	//0x2A
	MWL_VENDOR_CMD_GET_HTBW,
	MWL_VENDOR_CMD_SET_FILTER,
	MWL_VENDOR_CMD_GET_FILTER,
	/* split filtermac command to two commands */
	MWL_VENDOR_CMD_ADD_FILTERMAC,
	MWL_VENDOR_CMD_DEL_FILTERMAC,	//0x2F
	MWL_VENDOR_CMD_GET_FILTERMAC,	//0x30
	MWL_VENDOR_CMD_SET_INTRABSS,
	MWL_VENDOR_CMD_GET_INTRABSS,
	MWL_VENDOR_CMD_SET_HIDESSID,
	MWL_VENDOR_CMD_GET_HIDESSID,
	MWL_VENDOR_CMD_SET_BCNINTERVAL,	//0x35
	MWL_VENDOR_CMD_GET_BCNINTERVAL,
	MWL_VENDOR_CMD_SET_DTIM,
	MWL_VENDOR_CMD_GET_DTIM,
	MWL_VENDOR_CMD_SET_GPROTECT,
	MWL_VENDOR_CMD_GET_GPROTECT,	//0x3A
	MWL_VENDOR_CMD_SET_PREAMBLE,
	MWL_VENDOR_CMD_GET_PREAMBLE,
	MWL_VENDOR_CMD_SET_AGINGTIME,
	MWL_VENDOR_CMD_GET_AGINGTIME,
	MWL_VENDOR_CMD_SET_SSID,	//0x3F
	MWL_VENDOR_CMD_GET_SSID,	//0x40
	MWL_VENDOR_CMD_SET_BSSID,
	MWL_VENDOR_CMD_GET_BSSID,
	MWL_VENDOR_CMD_SET_REGIONCODE,
	MWL_VENDOR_CMD_GET_REGIONCODE,
	MWL_VENDOR_CMD_SET_RATEMODE,	//0x45
	MWL_VENDOR_CMD_GET_RATEMODE,
	MWL_VENDOR_CMD_SET_WDSMODE,
	MWL_VENDOR_CMD_GET_WDSMODE,
	MWL_VENDOR_CMD_SET_DISABLEASSOC,
	MWL_VENDOR_CMD_GET_DISABLEASSOC,	//0x4A
	MWL_VENDOR_CMD_SET_WDS,
	MWL_VENDOR_CMD_GET_WDS,
	MWL_VENDOR_CMD_SET_11DMODE,
	MWL_VENDOR_CMD_GET_11DMODE,
	MWL_VENDOR_CMD_SET_11HSPECMGT,	//0x4F
	MWL_VENDOR_CMD_GET_11HSPECMGT,	//0x50
	MWL_VENDOR_CMD_SET_11HPWRCONSTR,
	MWL_VENDOR_CMD_GET_11HPWRCONSTR,
	MWL_VENDOR_CMD_SET_11HCSAMODE,
	MWL_VENDOR_CMD_GET_11HCSAMODE,
	MWL_VENDOR_CMD_SET_11HCSACOUNT,	//0x55
	MWL_VENDOR_CMD_GET_11HCSACOUNT,
	MWL_VENDOR_CMD_SET_11HNOPTIMEOUT,
	MWL_VENDOR_CMD_GET_11HNOPTIMEOUT,
	MWL_VENDOR_CMD_SET_11HCACTIMEOUT,
	MWL_VENDOR_CMD_GET_11HCACTIMEOUT,	//0x5A
	MWL_VENDOR_CMD_SET_CSMODE,
	MWL_VENDOR_CMD_GET_CSMODE,
	MWL_VENDOR_CMD_SET_11HDFSMODE,
	MWL_VENDOR_CMD_GET_11HDFSMODE,
	MWL_VENDOR_CMD_SET_11HCSACHAN,	//0x5F
	MWL_VENDOR_CMD_GET_11HCSACHAN,	//0x60
	MWL_VENDOR_CMD_SET_11HCSASTART,
	MWL_VENDOR_CMD_SET_GUARDINT,
	MWL_VENDOR_CMD_GET_GUARDINT,
	MWL_VENDOR_CMD_SET_EXTSUBCH,
	MWL_VENDOR_CMD_GET_EXTSUBCH,	//0x65
	MWL_VENDOR_CMD_SET_HTPROTECT,
	MWL_VENDOR_CMD_GET_HTPROTECT,
	MWL_VENDOR_CMD_SET_AMPDUFACTOR,
	MWL_VENDOR_CMD_GET_AMPDUFACTOR,
	MWL_VENDOR_CMD_SET_AMPDUDEN,	//0x6A
	MWL_VENDOR_CMD_GET_AMPDUDEN,
	MWL_VENDOR_CMD_SET_AMPDUTX,
	MWL_VENDOR_CMD_GET_AMPDUTX,
	MWL_VENDOR_CMD_SET_TXPOWER,
	MWL_VENDOR_CMD_GET_TXPOWER,	//0x6F
	MWL_VENDOR_CMD_GET_FWSTAT,	//0x70
	MWL_VENDOR_CMD_SET_AUTOCHANNEL,
	MWL_VENDOR_CMD_GET_AUTOCHANNEL,
	MWL_VENDOR_CMD_SET_MAXTXPOWER,
	MWL_VENDOR_CMD_GET_MAXTXPOWER,
	MWL_VENDOR_CMD_DEL_WEPKEY,	//0x75
	MWL_VENDOR_CMD_SET_STRICTSHARED,
	MWL_VENDOR_CMD_GET_STRICTSHARED,
	MWL_VENDOR_CMD_SET_PWRFRACTION,
	MWL_VENDOR_CMD_GET_PWRFRACTION,
	MWL_VENDOR_CMD_SET_MIMOPS,	//0x7A
	MWL_VENDOR_CMD_GET_MIMOPS,
	MWL_VENDOR_CMD_SET_TXANTENNA,
	MWL_VENDOR_CMD_GET_TXANTENNA,
	MWL_VENDOR_CMD_SET_HTGF,
	MWL_VENDOR_CMD_GET_HTGF,	//0x7F
	MWL_VENDOR_CMD_SET_HTSTBC,	//0x80
	MWL_VENDOR_CMD_GET_HTSTBC,
	MWL_VENDOR_CMD_SET_3X3RATE,
	MWL_VENDOR_CMD_GET_3X3RATE,
	MWL_VENDOR_CMD_SET_INTOLERANT40,
	MWL_VENDOR_CMD_GET_INTOLERANT40,	//0x85
	MWL_VENDOR_CMD_SET_TXQLIMIT,
	MWL_VENDOR_CMD_GET_TXQLIMIT,
	MWL_VENDOR_CMD_SET_RIFS,
	MWL_VENDOR_CMD_SET_BFTYPE,
	MWL_VENDOR_CMD_SET_BANDSTEER,	//0x8A
	MWL_VENDOR_CMD_GET_BANDSTEER,
	MWL_VENDOR_CMD_SET_APPIE,
	MWL_VENDOR_CMD_GET_IE,
	MWL_VENDOR_CMD_SEND_MLME,
	MWL_VENDOR_CMD_SET_COUNTERMEASURES,	//0x8F
	MWL_VENDOR_CMD_GET_SEQNUM,	//0x90
	MWL_VENDOR_CMD_SEND_MGMT,
	MWL_VENDOR_CMD_SET_RTS,
	MWL_VENDOR_CMD_SET_CHANNEL,
	MWL_VENDOR_CMD_SET_WEPKEY,
	MWL_VENDOR_CMD_SET_WAPIMODE,	//0x95
	MWL_VENDOR_CMD_GET_WAPIMODE,
	MWL_VENDOR_CMD_SET_WMMACKPOLICY,
	MWL_VENDOR_CMD_GET_WMMACKPOLICY,
	MWL_VENDOR_CMD_SET_TXANTENNA2,
	MWL_VENDOR_CMD_GET_TXANTENNA2,	//0x9A
	MWL_VENDOR_CMD_GET_DEVICEINFO,
	MWL_VENDOR_CMD_SET_INTEROP,
	MWL_VENDOR_CMD_GET_INTEROP,
	MWL_VENDOR_CMD_SET_11HETSICAC,
	MWL_VENDOR_CMD_GET_11HETSICAC,
	MWL_VENDOR_CMD_SET_RXINTLIMIT,
	MWL_VENDOR_CMD_GET_RXINTLIMIT,
	MWL_VENDOR_CMD_SET_INTOLER,
	MWL_VENDOR_CMD_GET_INTOLER,
	MWL_VENDOR_CMD_SET_RXPATHOPT,
	MWL_VENDOR_CMD_GET_RXPATHOPT,
	MWL_VENDOR_CMD_SET_AMSDUFT,
	MWL_VENDOR_CMD_GET_AMSDUFT,
	MWL_VENDOR_CMD_SET_AMSDUMS,
	MWL_VENDOR_CMD_GET_AMSDUMS,
	MWL_VENDOR_CMD_SET_AMSDUAS,
	MWL_VENDOR_CMD_GET_AMSDUAS,
	MWL_VENDOR_CMD_SET_AMSDUPC,
	MWL_VENDOR_CMD_GET_AMSDUPC,
	MWL_VENDOR_CMD_SET_CDD,
	MWL_VENDOR_CMD_GET_CDD,
	MWL_VENDOR_CMD_SET_ACSTHRD,
	MWL_VENDOR_CMD_GET_ACSTHRD,
	MWL_VENDOR_CMD_SET_BIPKEYSN,	//no used
	MWL_VENDOR_CMD_GET_BIPKEYSN,
	MWL_VENDOR_CMD_GET_DEVICEID,
	MWL_VENDOR_CMD_SET_RRM,
	MWL_VENDOR_CMD_GET_RRM,
	MWL_VENDOR_CMD_SET_AUTOSCAN,
	MWL_VENDOR_CMD_GET_AUTOSCAN,
	MWL_VENDOR_CMD_SET_DMS,
	MWL_VENDOR_CMD_GET_DMS,
	MWL_VENDOR_CMD_GET_SYSLOAD,
	MWL_VENDOR_CMD_GET_11HNOCLIST,
	MWL_VENDOR_CMD_GET_BSSPROFILE,
	MWL_VENDOR_CMD_GET_TLV,
	MWL_VENDOR_CMD_GET_CHNLS,
	MWL_VENDOR_CMD_SET_SCANCHNL,
	MWL_VENDOR_CMD_SET_WTP,
	MWL_VENDOR_CMD_SET_WTPMACMODE,
	MWL_VENDOR_CMD_SET_WTPTUNNELMODE,
	MWL_VENDOR_CMD_GET_WTPCFG,
	MWL_VENDOR_CMD_GET_RADIOSTAT,
	MWL_VENDOR_CMD_SET_EXTFW,
	MWL_VENDOR_CMD_SET_MFGFW,
	MWL_VENDOR_CMD_SET_MFG,
	MWL_VENDOR_CMD_SET_FWREV,
	MWL_VENDOR_CMD_SET_ADDBA,
	MWL_VENDOR_CMD_GET_AMPDUSTAT,
	MWL_VENDOR_CMD_SET_DELBA,
	MWL_VENDOR_CMD_SET_DEL2BA,
	MWL_VENDOR_CMD_SET_AMPDURXDISABLE,
	MWL_VENDOR_CMD_SET_TRIGGERSCANINTERVAL,
	MWL_VENDOR_CMD_SET_BF,	//0xD0
	MWL_VENDOR_CMD_GET_MUMIMOMGMT,
	MWL_VENDOR_CMD_SET_MUMIMOMGMT,
	MWL_VENDOR_CMD_GET_MUSTA,
	MWL_VENDOR_CMD_GET_MUSET,
	MWL_VENDOR_CMD_SET_MUSET,
	MWL_VENDOR_CMD_DEL_MUSET,
	MWL_VENDOR_CMD_SET_MUG_ENABLE,
	MWL_VENDOR_CMD_GET_MUINFO,
	MWL_VENDOR_CMD_GET_MUGROUPS,
	MWL_VENDOR_CMD_SET_MUCONFIG,
	MWL_VENDOR_CMD_SET_MUAUTOTIMER,
	MWL_VENDOR_CMD_SET_MUPREFERUSRCNT,
	MWL_VENDOR_CMD_SET_GID,
	MWL_VENDOR_CMD_SET_NOACK,
	MWL_VENDOR_CMD_SET_NOSTEER,
	MWL_VENDOR_CMD_SET_TXHOP,
	MWL_VENDOR_CMD_GET_BFTYPE,
	MWL_VENDOR_CMD_GET_BWSIGNALTYPE,
	MWL_VENDOR_CMD_SET_BWSIGNALTYPE,
	MWL_VENDOR_CMD_GET_WEAKIV_THRESHOLD,
	MWL_VENDOR_CMD_SET_WEAKIV_THRESHOLD,
	MWL_VENDOR_CMD_SET_TIM,
	MWL_VENDOR_CMD_SET_POWERSAVESTATION,
	MWL_VENDOR_CMD_GET_TIM,
	MWL_VENDOR_CMD_GET_BCN,
	MWL_VENDOR_CMD_SET_ANNEX,
	MWL_VENDOR_CMD_SET_READEEPROMHDR,
	MWL_VENDOR_CMD_GET_OR,
	MWL_VENDOR_CMD_GET_ADDRTABLE,
	MWL_VENDOR_CMD_GET_FWENCRINFO,
	MWL_VENDOR_CMD_SET_REG,
	MWL_VENDOR_CMD_SET_DEBUG,
	MWL_VENDOR_CMD_GET_MEMDUMP,
	MWL_VENDOR_CMD_SET_DESIRE_BSSID,
	MWL_VENDOR_CMD_GET_EWBTABLE,
	MWL_VENDOR_CMD_SET_RATETABLE,
	MWL_VENDOR_CMD_GET_RATETABLE,
	MWL_VENDOR_CMD_SET_AMPDU_BAMGMT,
	MWL_VENDOR_CMD_GET_AMPDU_BAMGMT,
	MWL_VENDOR_CMD_SET_MINTRAFFIC,
	MWL_VENDOR_CMD_GET_MINTRAFFIC,
	MWL_VENDOR_CMD_SET_AMPDU_AC_THRESHOLD,
	MWL_VENDOR_CMD_GET_AMPDU_AC_THRESHOLD,
	MWL_VENDOR_CMD_SET_DFSTEST,
	MWL_VENDOR_CMD_SET_IPMCGRP,
	MWL_VENDOR_CMD_SET_RPTRMODE,
	MWL_VENDOR_CMD_SET_LOAD_TXPWRTABLE,
	MWL_VENDOR_CMD_GET_TXPWRTABLE,
	MWL_VENDOR_CMD_SET_LINKLOST,
	MWL_VENDOR_CMD_SET_SSUTEST,
	MWL_VENDOR_CMD_GET_QSTATS,
	MWL_VENDOR_CMD_SET_RCCAL,
	MWL_VENDOR_CMD_GET_TEMP,
	MWL_VENDOR_CMD_SET_MAXSTA,
	MWL_VENDOR_CMD_GET_MAXSTA,
	MWL_VENDOR_CMD_SET_TXFAILLIMIT,
	MWL_VENDOR_CMD_GET_TXFAILLIMIT,
	MWL_VENDOR_CMD_SET_WAPI,
	MWL_VENDOR_CMD_SET_LED,
	MWL_VENDOR_CMD_SET_FASTRECONNECT,
	MWL_VENDOR_CMD_SET_NEWDP,
	MWL_VENDOR_CMD_SET_TXRATECTRL,
	MWL_VENDOR_CMD_GET_NEWDPCNT,
	MWL_VENDOR_CMD_SET_NEWDPACNTSIZE,
	MWL_VENDOR_CMD_GET_NEWDPACNT,
	MWL_VENDOR_CMD_SET_NEWDPOFFCH,
	MWL_VENDOR_CMD_SET_TXCONTINUOUS,
	MWL_VENDOR_CMD_SET_RXSOP,
	MWL_VENDOR_CMD_SET_PWRPERRATE,
	MWL_VENDOR_CMD_SET_RATEGRPS,
	MWL_VENDOR_CMD_SET_PWRGRPSTBL,
	MWL_VENDOR_CMD_SET_PERRATEPWR,
	MWL_VENDOR_CMD_GET_PERRATEPWR,
	MWL_VENDOR_CMD_GET_NF,
	MWL_VENDOR_CMD_GET_RADIOSTATUS,
	MWL_VENDOR_CMD_SET_LDPC,
	MWL_VENDOR_CMD_SET_TLV,
	MWL_VENDOR_CMD_SET_AMPDUCFG,
	MWL_VENDOR_CMD_SET_AMSDUCFG,
	MWL_VENDOR_CMD_SET_BBDBG,
	MWL_VENDOR_CMD_SET_MU_SM_CACHE,
	MWL_VENDOR_CMD_SET_SKU,
	MWL_VENDOR_CMD_SET_RXANTBITMAP,
	MWL_VENDOR_CMD_SET_RETRYCFGENABLE,
	MWL_VENDOR_CMD_SET_RETRYCFG,
	MWL_VENDOR_CMD_SET_RADIORATESCFG,
	MWL_VENDOR_CMD_SET_EEWR,
	MWL_VENDOR_CMD_GET_EERD,
	MWL_VENDOR_CMD_SET_EEPROMACCESS,
	MWL_VENDOR_CMD_SET_OFFCHPWR,
	MWL_VENDOR_CMD_SET_WDEVRESET,
	MWL_VENDOR_CMD_SET_NDPA_USETA,
	MWL_VENDOR_CMD_SET_SENDBCNREPORT,
	MWL_VENDOR_CMD_GET_NLIST,
	MWL_VENDOR_CMD_GET_NLISTCFG,
	MWL_VENDOR_CMD_SET_SENDNLISTREP,
	//MWL_VENDOR_CMD_SET_ENABLESCNR,
	//MWL_VENDOR_CMD_SET_DFSSETCHANSW,
	//MWL_VENDOR_CMD_SET_RADAR_EVENT
	MWL_VENDOR_CMD_SET_QOSCTRL1,
	MWL_VENDOR_CMD_SET_QOSCTRL2,
	MWL_VENDOR_CMD_GET_QOSCTRL,
	MWL_VENDOR_CMD_SET_MU_BFMER,
	MWL_VENDOR_CMD_SET_FIPSTEST,
	MWL_VENDOR_CMD_DO_ACS,
	MWL_VENDOR_CMD_GET_MULTIAP,
	MWL_VENDOR_CMD_CONFIG_WPA,
	MWL_VENDOR_CMD_GET_BAND_CAPA,
	MWL_VENDOR_CMD_GET_CHANNEL_UTIL,
	MWL_VENDOR_CMD_GET_STATION_INFO,
	MWL_VENDOR_CMD_GET_ESPI,
	MWL_VENDOR_CMD_GET_UNASSOCIATED_STA_LINK_METRICS,
	MWL_VENDOR_CMD_GET_AP_RADIO_BASIC_CAPABILITIES,

	NUM_MWL_VENDOR_CMD,
	MAX_MWL_VENDOR_CMD = NUM_MWL_VENDOR_CMD - 1
};

enum mwl_vendor_attributes {
	MWL_VENDOR_ATTR_INVALID,
	MWL_VENDOR_ATTR_VERSION,
	MWL_VENDOR_ATTR_OPMODE,
	MWL_VENDOR_ATTR_STAMODE,
	MWL_VENDOR_ATTR_WPAWPA2MODE,
	MWL_VENDOR_ATTR_PASSPHRASE,
	MWL_VENDOR_ATTR_CIPHERSUITE,
	MWL_VENDOR_ATTR_WMM,
	MWL_VENDOR_ATTR_WMMEDCAAP,
	MWL_VENDOR_ATTR_AMSDU,
	MWL_VENDOR_ATTR_RXANTENNA,
	MWL_VENDOR_ATTR_OPTLEVEL,
	MWL_VENDOR_ATTR_STASCAN,
	MWL_VENDOR_ATTR_FIXRATE,
	MWL_VENDOR_ATTR_TXRATE,
	MWL_VENDOR_ATTR_MCASTPROXY,
	MWL_VENDOR_ATTR_11HSTAMODE,
	MWL_VENDOR_ATTR_MAC,
	MWL_VENDOR_ATTR_APPIE,
	MWL_VENDOR_ATTR_MLME,
	MWL_VENDOR_ATTR_MGMT,
	MWL_VENDOR_ATTR_COUNTERMEASURES,
	MWL_VENDOR_ATTR_SEQNUM,
	MWL_VENDOR_ATTR_RSSI,
	MWL_VENDOR_ATTR_LINKSTATUS,
	MWL_VENDOR_ATTR_STALISTEXT,
	MWL_VENDOR_ATTR_GROUPREKEY,
	MWL_VENDOR_ATTR_WMMEDCASTA,
	MWL_VENDOR_ATTR_HTBW,
	MWL_VENDOR_ATTR_FILTER,
	MWL_VENDOR_ATTR_FILTERMAC,
	MWL_VENDOR_ATTR_INTRABSS,
	MWL_VENDOR_ATTR_HIDESSID,
	MWL_VENDOR_ATTR_BCNINTERVAL,
	MWL_VENDOR_ATTR_DTIM,
	MWL_VENDOR_ATTR_GPROTECT,
	MWL_VENDOR_ATTR_PREAMBLE,
	MWL_VENDOR_ATTR_AGINGTIME,
	MWL_VENDOR_ATTR_SSID,
	MWL_VENDOR_ATTR_BSSID,
	MWL_VENDOR_ATTR_REGIONCODE,
	MWL_VENDOR_ATTR_RATEMODE,
	MWL_VENDOR_ATTR_WDSMODE,
	MWL_VENDOR_ATTR_DISABLEASSOC,
	MWL_VENDOR_ATTR_WDS,
	MWL_VENDOR_ATTR_11DMODE,
	MWL_VENDOR_ATTR_11HSPECMGT,
	MWL_VENDOR_ATTR_11HPWRCONSTR,
	MWL_VENDOR_ATTR_11HCSAMODE,
	MWL_VENDOR_ATTR_11HCSACOUNT,
	MWL_VENDOR_ATTR_11HNOPTIMEOUT,
	MWL_VENDOR_ATTR_11HCACTIMEOUT,
	MWL_VENDOR_ATTR_CSMODE,
	MWL_VENDOR_ATTR_11HDFSMODE,
	MWL_VENDOR_ATTR_11HCSACHAN,
	MWL_VENDOR_ATTR_GUARDINT,
	MWL_VENDOR_ATTR_EXTSUBCH,
	MWL_VENDOR_ATTR_HTPROTECT,
	MWL_VENDOR_ATTR_AMPDUFACTOR,
	MWL_VENDOR_ATTR_AMPDUDEN,
	MWL_VENDOR_ATTR_AMPDUTX,
	MWL_VENDOR_ATTR_TXPOWER,
	MWL_VENDOR_ATTR_FWSTAT,
	MWL_VENDOR_ATTR_AUTOCHANNEL,
	MWL_VENDOR_ATTR_MAXTXPOWER,
	MWL_VENDOR_ATTR_STRICTSHARED,
	MWL_VENDOR_ATTR_PWRFRACTION,
	MWL_VENDOR_ATTR_MIMOPS,
	MWL_VENDOR_ATTR_TXANTENNA,
	MWL_VENDOR_ATTR_HTGF,
	MWL_VENDOR_ATTR_HTSTBC,
	MWL_VENDOR_ATTR_3X3RATE,
	MWL_VENDOR_ATTR_INTOLERENT40,
	MWL_VENDOR_ATTR_TXQLIMIT,
	MWL_VENDOR_ATTR_RIFS,
	MWL_VENDOR_ATTR_BFTYPE,
	MWL_VENDOR_ATTR_BANDSTEER,
	MWL_VENDOR_ATTR_CHANNEL,
	MWL_VENDOR_ATTR_RRM,
	MWL_VENDOR_ATTR_MULTIAP,
	MWL_VENDOR_ATTR_WPA,
	MWL_VENDOR_ATTR_MAC_ADDRESS,
	MWL_VENDOR_ATTR_ASSOC_REQ_FRAME,
	MWL_VENDOR_ATTR_STATION_INFO,
	MWL_VENDOR_ATTR_REASON_CODE,
	MWL_VENDOR_ATTR_HT_CAPA,
	MWL_VENDOR_ATTR_VHT_CAPA,
	MWL_VENDOR_ATTR_HE_CAPA,
	MWL_VENDOR_ATTR_UTILIZATION,
	MWL_VENDOR_ATTR_UTIL_RX_SELF,
	MWL_VENDOR_ATTR_UTIL_RX_OTHER,
	MWL_VENDOR_ATTR_UTIL_TX,
	MWL_VENDOR_ATTR_UTIL_RX,
	MWL_VENDOR_ATTR_ESPI,
	MWL_VENDOR_ATTR_UNASSOCIATED_STA_LINK_METRICS_QUERY,
	MWL_VENDOR_ATTR_UNASSOCIATED_STA_LINK_METRICS_RESP,
	MWL_VENDOR_ATTR_AP_RADIO_BASIC_CAPABILITIES,
	MWL_VENDOR_ATTR_MULTIAP_IE,

	NUM_MWL_VENDOR_ATTR,
	MAX_MWL_VENDOR_ATTR = NUM_MWL_VENDOR_ATTR - 1
};

enum mwl_vendor_attr_key {
	MWL_VENDOR_ATTR_KEY_INVALID,
	MWL_VENDOR_ATTR_KEY_TYPE,
	MWL_VENDOR_ATTR_KEY_INDEX,
	MWL_VENDOR_ATTR_KEY_LEN,
	MWL_VENDOR_ATTR_KEY_FLAG,
	MWL_VENDOR_ATTR_KEY_MAC,
	MWL_VENDOR_ATTR_KEY_RECV_SEQ,
	MWL_VENDOR_ATTR_KEY_XMIT_SEQ,
	MWL_VENDOR_ATTR_KEY_DATA,
	MWL_VENDOR_ATTR_KEY_PN,

	NUM_MWL_VENDOR_ATTR_KEY,
	MAX_MWL_VENDOR_ATTR_KEY = NUM_MWL_VENDOR_ATTR_KEY - 1
};

enum mwl_vendor_attr_ie {
	MWL_VENDOR_ATTR_IE_INVALID,
	MWL_VENDOR_ATTR_IE_TYPE,
	MWL_VENDOR_ATTR_IE_LEN,
	MWL_VENDOR_ATTR_IE_MAC,
	MWL_VENDOR_ATTR_IE_REASSOC,
	MWL_VENDOR_ATTR_IE_DATA,

	NUM_MWL_VENDOR_ATTR_IE,
	MAX_MWL_VENDOR_ATTR_IE = NUM_MWL_VENDOR_ATTR_IE - 1
};

enum mwl_vendor_events {
	MWL_VENDOR_EVENT_TEST,
	MWL_VENDOR_EVENT_ASSOC,
	MWL_VENDOR_EVENT_DISASSOC,
	MWL_VENDOR_EVENT_PROBE_REQ,
	MWL_VENDOR_EVENT_AUTH,
	MWL_VENDOR_EVENT_WPS_REQ,
	MWL_VENDOR_EVENT_ACS_COMPLETED,
	MWL_VENDOR_EVENT_NEIGHBOR_LIST,
	MWL_VENDOR_EVENT_ASSOC_NOTIFICATION,
	MWL_VENDOR_EVENT_DISASSOC_NOTIFICATION,
	MWL_VENDOR_EVENT_UNASSOCIATED_STA_LINK_METRICS,
	MWL_VENDOR_EVENT_MULTIAP_IE,
};

struct mwl_mlme {
	uint8_t op;		/* operation to perform */
	uint8_t ssid_len;	/* length of optional ssid */
	uint16_t reason;	/* 802.11 reason code */
	uint8_t macaddr[6];
	uint8_t ssid[32];
	uint8_t aid;
	uint8_t qos_info;
	uint8_t is_qos_sta;
	uint8_t peer_info[36];
	uint8_t rsn_sta;
	uint8_t rsn_ie[64];
	uint16_t seq;
	uint8_t optie[256];
	uint8_t optie_len;
} __attribute__ ((packed));

struct mwl_mgmt {
	uint16_t len;
	uint8_t buf[512 - 2];	/*total size of 512 bytes */// fix compile warning
} __attribute__ ((packed));

struct mwl_beacon_data {
	u8 tail[256];
	size_t tail_len;
} __attribute__ ((packed));

struct mwl_crypto_settings {
	u32 wpa_versions;
	u32 cipher_group;
	int n_ciphers_pairwise;
	u32 ciphers_pairwise[5];
	int n_akm_suites;
	u32 akm_suites[2];
} __attribute__ ((packed));

struct mwl_ap_settings {
	struct mwl_beacon_data beacon;
	u8 ssid[32];
	size_t ssid_len;
	struct mwl_crypto_settings crypto;
} __attribute__ ((packed));

struct mwl_failed_connection {
	uint8_t sta_mac_addr[6];
	uint16_t reason;
} __attribute__ ((packed));

struct mwl_espi_flag_t {
	uint8_t reserved:4;
	uint8_t include_vi:1;
	uint8_t include_vo:1;
	uint8_t include_bk:1;
	uint8_t include_be:1;
} __attribute__ ((packed));

struct mwl_espi_info {
	struct mwl_espi_flag_t espi_flag;
	uint8_t espi[4][3];
} __attribute__ ((packed));

#define UNASSOC_METRICS_STA_MAX 8
#define UNASSOC_METRICS_CHANNEL_MAX 13

struct unassociated_sta_query_info_t {
	u8 channel;
	u8 num_of_sta;
	u8 sta_mac_addr_list[UNASSOC_METRICS_STA_MAX][ETH_ALEN];
} __attribute__ ((packed));

struct unassociated_sta_link_metrics_query {
	u8 operating_class;
	u8 num_of_channel;
	struct unassociated_sta_query_info_t
		unassociated_sta_info[UNASSOC_METRICS_CHANNEL_MAX];
} __attribute__ ((packed));

struct unassociated_sta_resp_info_t {
	u8 sta_mac_addr[ETH_ALEN];
	u8 channel;
	u32 time_delta;
	s8 rssi;
} __attribute__ ((packed));

struct unassociated_sta_link_metrics_resp {
	u8 operating_class;
	u8 num_of_sta;
	struct unassociated_sta_resp_info_t unassociated_sta_info[];
} __attribute__ ((packed));

#define UNASSOC_RESP_SIZE \
	sizeof(struct unassociated_sta_link_metrics_resp) + \
	sizeof(struct unassociated_sta_resp_info_t) * \
	UNASSOC_METRICS_STA_MAX * UNASSOC_METRICS_CHANNEL_MAX

#ifdef MRVL_WSC
#define MWL_APPIE_FRAMETYPE_BEACON           1
#define MWL_APPIE_FRAMETYPE_PROBE_RESP       2
#define MWL_AAPIE_FRAMETYPE_ASSOC_RESPONSE   3
#define MWL_APPIE_IETYPE_RSN                 48

#define MWL_OPTIE_BEACON_INCL_RSN            4
#define MWL_OPTIE_BEACON_NORSN               5
#define MWL_OPTIE_PROBE_RESP_INCL_RSN        6
#define MWL_OPTIE_PROBE_RESP_NORSN           7
#define MWL_OPTIE_ASSOC_INCL_RSN             9

struct mwl_appie {
	uint32_t type;
	uint32_t len;
	uint8_t buf[512 - 8];	/*total size of 512 bytes */
} __attribute__ ((packed));
#endif /* MRVL_WSC */

#define MWL_KEY_XMIT	         0x01	/* key used for xmit */
#define MWL_KEY_RECV	         0x02	/* key used for recv */
#define MWL_KEY_GROUP	         0x04	/* key used for WPA group operation */
#define MWL_KEY_DEFAULT	    	 0x80	/* default xmit key */
#define MWL_KEYIX_NONE      	 ((u_int16_t) - 1)

#define MWL_CIPHER_NONE          0x00
#define MWL_CIPHER_WEP40         0x01
#define MWL_CIPHER_TKIP          0x02
#define MWL_CIPHER_WRAP          0x03
#define MWL_CIPHER_CCMP          0x04
#define MWL_CIPHER_WEP104        0x05
#define MWL_CIPHER_IGTK          0x06
#define MWL_CIPHER_GCMP          0x08
#define MWL_CIPHER_GCMP_256      0x09
#define MWL_CIPHER_CCMP_256      0x0A
#define MWL_CIPHER_AES_GMAC      0x0B
#define MWL_CIPHER_AES_GMAC_256  0x0C
#define MWL_CIPHER_AES_CMAC_256  0x0D

#define MWL_CIPHER_MODE_WPA      0x00
#define MWL_CIPHER_MODE_WPA2     0x01

#define MWL_MLME_ASSOC           1	/* associate station */
#define MWL_MLME_DISASSOC        2	/* disassociate station */
#define MWL_MLME_DEAUTH          3	/* deauthenticate station */
#define MWL_MLME_AUTHORIZE       4	/* authorize station */
#define MWL_MLME_UNAUTHORIZE     5	/* unauthorize station */
#define MWL_MLME_CLEAR_STATS     6	/* clear station statistic */
#define MWL_MLME_DELSTA          7
#define MWL_MLME_SET_REASSOC     8
#define MWL_MLME_SET_AUTH        9
#define MWL_MLME_SET_ASSOC       10

#define WLAN_MAX_KEY_LEN         32
#define IE_BUF_LEN               8

#endif /* _MWL_VENDOR_H */
