/** @file ap8xLnxIoctl.h
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2005-2020 NXP
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
#ifndef AP8X_IOCTL_H_
#define AP8X_IOCTL_H_

#include <linux/version.h>
#include <linux/wireless.h>

#define WL_IOCTL_WL_PARAM                       (SIOCIWFIRSTPRIV + 0)
#define WL_IOCTL_WL_GET_PARAM           (SIOCIWFIRSTPRIV + 1)
#define WL_IOCTL_BSS_START                      (SIOCIWFIRSTPRIV + 2)
#define WL_IOCTL_GET_VERSION                    (SIOCIWFIRSTPRIV + 3)
#define WL_IOCTL_SET_TXRATE                     (SIOCIWFIRSTPRIV + 4)
#define WL_IOCTL_GET_TXRATE                     (SIOCIWFIRSTPRIV + 5)
#define WL_IOCTL_SET_CIPHERSUITE                (SIOCIWFIRSTPRIV + 6)
#define WL_IOCTL_GET_CIPHERSUITE                (SIOCIWFIRSTPRIV + 7)
#define WL_IOCTL_SET_PASSPHRASE         (SIOCIWFIRSTPRIV + 8)
#define WL_IOCTL_GET_PASSPHRASE         (SIOCIWFIRSTPRIV + 9)
#define WL_IOCTL_SET_FILTERMAC          (SIOCIWFIRSTPRIV + 10)
#define WL_IOCTL_GET_FILTERMAC          (SIOCIWFIRSTPRIV + 11)
#define WL_IOCTL_SET_BSSID                              (SIOCIWFIRSTPRIV + 12)
#define WL_IOCTL_GET_BSSID                              (SIOCIWFIRSTPRIV + 13)
#define WL_IOCTL_SET_TXPOWER                    (SIOCIWFIRSTPRIV + 14)
#define WL_IOCTL_GET_TXPOWER                    (SIOCIWFIRSTPRIV + 15)
#define WL_IOCTL_SET_WMMEDCAAP          (SIOCIWFIRSTPRIV + 16)
#define WL_IOCTL_GET_WMMEDCAAP          (SIOCIWFIRSTPRIV + 17)
#define WL_IOCTL_SET_WMMEDCASTA         (SIOCIWFIRSTPRIV + 18)
#define WL_IOCTL_GET_WMMEDCASTA         (SIOCIWFIRSTPRIV + 19)
#define WL_IOCTL_SETCMD                                 (SIOCIWFIRSTPRIV + 20)
#define WL_IOCTL_GETCMD                                 (SIOCIWFIRSTPRIV + 25)
#define WL_IOCTL_GET_STALISTEXT         (SIOCIWFIRSTPRIV + 21)
#define   WL_IOCTL_SET_APPIE                    (SIOCIWFIRSTPRIV + 22)
#define   WL_IOCTL_GET_IE                       (SIOCIWFIRSTPRIV + 23)
#define   WL_IOCTL_GET_SCAN_BSSPROFILE                  (SIOCIWFIRSTPRIV + 31)
#define   WL_IOCTL_SET_CLIENT                   (SIOCIWFIRSTPRIV + 24)
#define WL_IOCTL_SET_WDS_PORT                   (SIOCIWFIRSTPRIV + 26)
#define WL_IOCTL_GET_WDS_PORT       (SIOCIWFIRSTPRIV + 27)
#define   WL_IOCTL_GET_STASCAN                  (SIOCIWFIRSTPRIV + 29)
#define WL_IOCTL_SET_WAPI                       (SIOCIWFIRSTPRIV + 30)
#define WL_IOCTL_SET_MGMT_SEND             (SIOCIWFIRSTPRIV + 28)

enum {
	WL_PARAM_AUTHTYPE = 1,
	WL_PARAM_BAND = 2,
	WL_PARAM_REGIONCODE = 3,
	WL_PARAM_HIDESSID = 4,
	WL_PARAM_PREAMBLE = 5,
	WL_PARAM_GPROTECT = 6,
	WL_PARAM_BEACON = 7,
	WL_PARAM_DTIM = 8,
	WL_PARAM_FIXRATE = 9,
	WL_PARAM_ANTENNA = 10,
	WL_PARAM_WPAWPA2MODE = 11,
	WL_PARAM_AUTHSUITE = 12,
	WL_PARAM_GROUPREKEYTIME = 13,
	WL_PARAM_WMM = 14,
	WL_PARAM_WMMACKPOLICY = 15,
	WL_PARAM_FILTER = 16,
	WL_PARAM_INTRABSS = 17,
	WL_PARAM_AMSDU = 18,
	WL_PARAM_HTBANDWIDTH = 19,
	WL_PARAM_GUARDINTERVAL = 20,
	WL_PARAM_EXTSUBCH = 21,
	WL_PARAM_HTPROTECT = 22,
	WL_PARAM_GETFWSTAT = 23,
	WL_PARAM_AGINGTIME = 24,
	WL_PARAM_ANTENNATX2 = 25,
	WL_PARAM_AUTOCHANNEL = 26,
	WL_PARAM_AMPDUFACTOR = 27,
	WL_PARAM_AMPDUDENSITY = 28,
	WL_PARAM_CARDDEVINFO = 29,
	WL_PARAM_INTEROP = 30,
	WL_PARAM_OPTLEVEL = 31,
	WL_PARAM_REGIONPWR = 32,
	WL_PARAM_ADAPTMODE = 33,
	WL_PARAM_SETKEYS = 34,
	WL_PARAM_DELKEYS = 35,
	WL_PARAM_MLME_REQ = 36,
	WL_PARAM_COUNTERMEASURES = 37,
	WL_PARAM_CSADAPTMODE = 38,
	WL_PARAM_DELWEPKEY = 39,
	WL_PARAM_WDSMODE = 40,
	WL_PARAM_STRICTWEPSHARE = 41,
	WL_PARAM_11H_CSA_CHAN = 42,
	WL_PARAM_11H_CSA_COUNT = 43,
	WL_PARAM_11H_CSA_MODE = 44,
	WL_PARAM_11H_CSA_START = 45,
	WL_PARAM_SPECTRUM_MGMT = 46,
	WL_PARAM_POWER_CONSTRAINT = 47,
	WL_PARAM_11H_DFS_MODE = 48,
	WL_PARAM_11D_MODE = 49,
	WL_PARAM_TXPWRFRACTION = 50,
	WL_PARAM_DISABLEASSOC = 51,
	WL_PARAM_PSHT_MANAGEMENTACT = 52,
	/* CLIENT_SUPPORT */
	WL_PARAM_STAMODE = 53,
	WL_PARAM_STASCAN = 54,
	WL_PARAM_AMPDU_TX = 55,
	WL_PARAM_11HCACTIMEOUT = 56,
	WL_PARAM_11hNOPTIMEOUT = 57,
	WL_PARAM_11hDFSMODE = 58,
	WL_PARAM_MCASTPRXY = 59,
	WL_PARAM_11H_STA_MODE = 60,
	WL_PARAM_RSSI = 61,
	WL_PARAM_INTOLERANT = 62,
	WL_PARAM_TXQLIMIT = 63,
	WL_PARAM_RXINTLIMIT = 64,
	WL_PARAM_LINKSTATUS = 65,
	WL_PARAM_ANTENNATX = 66,
	WL_PARAM_RXPATHOPT = 67,
	WL_PARAM_HTGF = 68,
	WL_PARAM_HTSTBC = 69,
	WL_PARAM_3X3RATE = 70,
	WL_PARAM_AMSDU_FLUSHTIME = 71,
	WL_PARAM_AMSDU_MAXSIZE = 72,
	WL_PARAM_AMSDU_ALLOWSIZE = 73,
	WL_PARAM_AMSDU_PKTCNT = 74,
	WL_PARAM_CDD = 75,
	WL_PARAM_WAPIMODE = 76,
	WL_PARAM_ACS_THRESHOLD = 80,
	WL_PARAM_ROOTIF_NAME = 81,
	WL_PARAM_SET_HT_IE = 82,
	WL_PARAM_SET_VHT_IE = 83,
	WL_PARAM_SET_PROP_IE = 84,
	WL_PARAM_SET_PROBE_IE = 85,
	WL_PARAM_OFF_CHANNEL_REQ_SEND = 86,
	WL_PARAM_CONFIG_PROMISCUOUS = 87,
	WL_PARAM_PEEK_ACNT_RECDS = 88,
	WL_PARAM_READ_ACNT_RECDS = 89,
	WL_PARAM_SET_ACNT_BUF_SIZE = 90,
	WL_PARAM_SENSORD_INIT = 91,
	WL_PARAM_SENSORD_CMD = 92,
	WL_PARAM_SETKEYS_GROUP_RX = 93,
	WL_PARAM_RADIO_STATUS = 94,
	WL_PARAM_SENSORD_SET_BLANKING = 95,
	WL_PARAM_DFS_DETECT = 96,
	WL_PARAM_BFMR_CONFIG = 97,
	WL_PARAM_BFMR_SBF_OPEN = 98,
	WL_PARAM_BFMR_SBF_CLOSE = 99,
	WL_PARAM_GET_ACNT_BUF_SIZE = 100,
	WL_PARAM_SET_ACNT_TAIL = 101,
	WL_PARAM_GET_ACNT_CHUNK_INFO = 102,
	WL_PARAM_SET_POWER_PER_RATE = 103,
	WL_PARAM_GET_DEVICE_ID = 104,
	WL_PARAM_SET_SKU = 105,
	WL_PARAM_SET_OFFCHPWR = 106,
	WL_PARAM_BIPKEYSN = 107,
#ifdef IEEE80211K
	WL_PARAM_RRM_EN = 108,
#endif
	WL_PARAM_11HETSICACTIMEOUT = 109,
	WL_PARAM_11HCACENABLE = 110,
	WL_PARAM_STOP_TRAFFIC = 111,
	WL_PARAM_STA_AUTO_SCAN = 112,
#ifdef SOC_W906X
	WL_PARAM_AMPDUWINDOWLIMIT = 113,
	WL_PARAM_AMPDUBYTESLIMIT = 114,
	WL_PARAM_AMPDUDENSITYLIMIT = 115,
	WL_PARAM_FW_GETCORE_DUMP = 158,
	WL_PARAM_FW_CREATE_CORE = 159,
	WL_PARAM_SET_HE_IE = 160,
	WL_PARAM_HE_LDPC = 161,
	WL_PARAM_BSS_COLOR = 162,
	WL_PARAM_HT_TKIP = 163,
	WL_PARAM_MU_EDCA_EN = 164,
	WL_PARAM_HE_TWT_EN = 165,
	WL_PARAM_WLS_FTM_EN = 166,
	WL_PARAM_HE_MUBF_EN = 167,
	WL_PARAM_HE_SUBF_EN = 168,
#else
	WL_PARAM_BANDSTEER = 113,
	WL_PARAM_DOT11V_DMS = 114,
	WL_PARAM_RESET_RATE_MODE = 115,
#endif
};

enum {
	OFF_CHAN_REQ_TYPE_RX = 0,
	OFF_CHAN_REQ_TYPE_TX = 1,
	OFF_CHAN_REQ_TYPE_SENSORD = 2
};
#define WL_KEY_XMIT             0x01	/* key used for xmit */
#define WL_KEY_RECV             0x02	/* key used for recv */
#define WL_KEY_GROUP        0x04	/* key used for WPA group operation */
#define WL_KEY_DEFAULT      0x80	/* default xmit key */
#define WL_KEYIX_NONE       ((u_int16_t)-1)

#define WL_CIPHER_NONE      0x00
#define WL_CIPHER_WEP40     0x01
#define WL_CIPHER_TKIP      0x02
#define WL_CIPHER_WRAP      0x03
#define WL_CIPHER_CCMP      0x04
#define WL_CIPHER_WEP104    0x05
#define WL_CIPHER_IGTK      0x06
#define WL_CIPHER_GCMP      0x08
#define WL_CIPHER_GCMP_256  0x09
#define WL_CIPHER_CCMP_256  0x0A
#define WL_CIPHER_AES_GMAC      0x0B
#define WL_CIPHER_AES_GMAC_256  0x0C
#define WL_CIPHER_AES_CMAC_256  0x0D

#define NL_TX_MGMT_SIGNATURE 0x238a9d83
#define DEFAULT_ACNT_RING_SIZE   0x10000
#define PER_RATE_TX_POWER_SIZE   0x1000

struct wlreq_ie {
	u_int8_t macAddr[6];
	u_int8_t IEtype;
	u_int8_t IELen;
	u_int8_t reassoc;
	u_int8_t IE[256];
};

#ifdef MRVL_WSC
struct wlreq_wscie {
	u_int8_t macAddr[6];
	u_int8_t wscIE[280];
};
#endif

typedef struct wlreq_key {
	u_int8_t ik_type;	/* key/cipher type */
	u_int8_t ik_pad;
	u_int16_t ik_keyix;	/* key index */
	u_int8_t ik_keylen;	/* key length in bytes */
	u_int8_t ik_flags;
	u_int8_t ik_macaddr[6];
	u_int64_t ik_keyrsc;	/* key receive sequence counter */
	u_int64_t ik_keytsc;	/* key transmit sequence counter */
	u_int8_t ik_keydata[16 + 8 + 8];
#ifdef CONFIG_IEEE80211W
	u_int8_t ik_pn[6];
#endif
} wlreq_key;

struct wlreq_del_key {
	u_int8_t idk_keyix;	/* key index */
	u_int8_t idk_macaddr[6];
};

#define WL_MLME_ASSOC           1	/* associate station */
#define WL_MLME_DISASSOC                2	/* disassociate station */
#define WL_MLME_DEAUTH          3	/* deauthenticate station */
#define WL_MLME_AUTHORIZE       4	/* authorize station */
#define WL_MLME_UNAUTHORIZE     5	/* unauthorize station */
#define WL_MLME_CLEAR_STATS     6	/* clear station statistic */
#define         WL_MLME_DELSTA          7
#define WL_MLME_SET_REASSOC     8
#define WL_MLME_SET_AUTH                9
#define WL_MLME_SET_ASSOC       10

struct wlreq_mlme {
	u_int8_t im_op;		/* operation to perform */
	u_int8_t im_ssid_len;	/* length of optional ssid */
	u_int16_t im_reason;	/* 802.11 reason code */
	u_int8_t im_macaddr[6];
	u_int8_t im_ssid[32];
	u_int8_t Aid;
	u_int8_t QosInfo;
	u_int8_t isQosSta;
	u_int8_t PeerInfo[36];
	u_int8_t rsnSta;
	u_int8_t rsnIE[64];
	u_int16_t im_seq;
	u_int8_t im_optie[256];
	u_int8_t im_optie_len;
};

struct wlreq_set_mlme_send {
	u_int16_t len;
	u_int8_t buf[];		/*total size of 512 bytes */
} __attribute__ ((packed));

#ifdef MRVL_WSC
#define WL_APPIE_FRAMETYPE_BEACON           1
#define WL_APPIE_FRAMETYPE_PROBE_RESP       2
#define WL_AAPIE_FRAMETYPE_ASSOC_RESPONSE       3
#define WL_APPIE_IETYPE_RSN                                     48

#define WL_OPTIE_BEACON_INCL_RSN                        4
#define WL_OPTIE_BEACON_NORSN                   5
#define WL_OPTIE_PROBE_RESP_INCL_RSN            6
#define WL_OPTIE_PROBE_RESP_NORSN               7
#define WL_OPTIE_ASSOC_INCL_RSN                 9
#ifdef MRVL_WPS_CLIENT
#define WL_APPIE_FRAMETYPE_PROBE_REQUEST	8
#endif

struct wlreq_set_appie {
	u_int32_t appFrmType;
	u_int32_t appBufLen;
	u_int8_t appBuf[504];	/*total size of 512 bytes */
} __attribute__ ((packed));

#endif				//MRVL_WSC

#ifdef MRVL_WAPI
/* come from wapid, 1 and 2 is useed as beacon/probe-resp */
#define P80211_PACKET_WAPIFLAG          0
#define P80211_PACKET_SETKEY                    3

#define KEY_LEN                         16
/* from wapid */
struct wlreq_wapi_key {
	u_int8_t ik_macaddr[6];	/* sta mac, all "ff" for mcastkey */
	u_int8_t ik_flags;	/* always = 1 */
	u_int8_t ik_keyid;	/* key index */
	u_int8_t ik_keydata[KEY_LEN * 2];	/* mcastkey: 32 byte key; ucastkey: uek (16 byte) + uck (16 byte) */
};
#endif

#define MAX_HE_CAP_IE_LENGTH 54
#define MAX_HE_OP_IE_LENGTH 13

struct wlreq_setIE {
	u_int8_t HtCapIE[64];
	u_int8_t HtInfoIE[64];
	u_int8_t vhtCapIE[32];
	u_int8_t vhtInfoIE[32];
	u_int8_t proprietaryIE[128];
	u_int8_t extProbeIE[64];
	u_int8_t heCapIE[MAX_HE_CAP_IE_LENGTH];
	u_int8_t heOpIE[MAX_HE_OP_IE_LENGTH];
};

//=======================================================
struct RadioStats {
	u_int32_t RxOverrunErr;	//RxOverflows  /* no buffer to handle rx */
	u_int32_t RxMacCrcErr;	//RxFCSErrors
	u_int32_t RxWepErr;	//RxUndecryptableFrames   /* Decrypt and MIC errors */

	u_int32_t MaxRetries;	/* packet failures */
	u_int32_t RxAck;
	u_int32_t NoAck;
	u_int32_t NoCts;	/* no cts - RTS tx failure */

	u_int32_t RxCts;	/* cts received hardware */
	u_int32_t TxRts;	/* rts transmitted */
	u_int32_t TxCts;	//TxCTSCount /* CTS to self only */

	u_int32_t TxUcFrags;	//stat->tx_packets - multicast?    /* Tx unicast */
	u_int32_t Tries;	/* Total TX tries */
	u_int32_t TxMultRetries;	/* Number of packets with multiple retries */

	u_int32_t RxUc;		/* Rx unicast */

	u_int32_t TxBroadcast;
	u_int32_t RxBroadcast;

	u_int32_t TxMgmt;	/* Mgmt Tx */
	u_int32_t TxCtrl;	/* control frame Tx */
	u_int32_t TxBeacon;
	u_int32_t TxProbeRsp;	/* Transmitted Probe Responses */

	u_int32_t RxMgmt;	/* Mgmt Rx */
	u_int32_t RxCtrl;	/* control frame Rx */
	u_int32_t RxBeacon;
	u_int32_t RxProbeReq;	/* Transmitted Probe Responses */

	u_int32_t DupFrag;	/* Duplicate Rx frame fragments */
	u_int32_t RxFrag;	/* # Received frame fragments */
	u_int32_t RxAged;	/* Rx packets aged (fragmented dropped ) */

	u_int32_t TxKb;		//stat->tx_byte /* Total KB of packets  */
	u_int32_t RxKb;		//stat->rx_bytes  /* Total KB of packets */

	u_int32_t TxAggr;	/* Number of aggregated packets - AMPDU and AMSDU */
	u_int32_t Jammed;	/* Jammer recovery */
	u_int32_t TxConcats;	/* transmit concat packets */
	u_int32_t RxConcats;	/* receive concat packets */
	u_int32_t TxHwWatchdog;	/* HW watchdog errors */
	u_int32_t TxSwWatchdog;	/* Packet stuck in SW etc */
	u_int32_t NoAckPolicy;	/* Frames submitted with no Ack Expected */

	u_int32_t TxAged;
};

/* Queue statistics per UP/AC per radio */
struct TxQueueStats {
	u_int32_t QueueDepth;	/* Queue depth programmable */
	u_int32_t QueueCurrent;	/* Number of packets in queue currently */

	u_int32_t TxSent;	/* Total number of Tx */
	u_int32_t TxRetries;	/* Number of retried packets */
	u_int32_t TxDiscard;	/* Number of queue discards */
	u_int32_t TxFail;	/* Number of packets dropped due to failure like maxretry */
	u_int32_t TxMultRetries;	/* Number of packets with multiple retries */
};

/* Client statistics are per UP or AC */
struct ClientStats {
	u_int32_t TxUc[8];	/* Total unicast Tx */
	u_int32_t TxRetry[8];	/* Number of retries */

	u_int32_t TxQueueDiscards;	/* Queue discards */
	u_int32_t TxQueueFail;	/* Failed packets (maxretry etc) */

	u_int32_t RxUc[8];	/* Total unicast Rx */
	u_int32_t RxRetry[8];	/* Per rate statistics */

	u_int32_t TxKb;		/* Total KB of packets  */
	u_int32_t RxKb;		/* Total KB of packets */

	u_int32_t RxDup;	/* Number of Rx duplicates */
	u_int32_t TxAggr;	/* Number of aggregated packets - AMPDU and AMSDU */

	u_int32_t rssi;
	u_int32_t snr;
};
typedef struct _headTailInfo {
	u32 head;
	u32 tail;
} headTailInfo_t;

typedef struct _readRecdsInfo {
	u32 tail;
	u8 *pBuf;
	u32 bufSize;
} readRecdsInfo_t;

typedef struct acnt_chunk_info_s {
	u8 NumChunk;
	u32 SizeOfChunk;
} acnt_chunk_info_t;

typedef enum {
	ACNT_PAUSE = 0,
	ACNT_SET_BUF = 1,
} acnt_action_type;

typedef struct SetAcntBufInfo_s {
	u32 ActionType;
	u32 size;

} SetAcntBufInfo_t;

typedef struct setoffchpwr_s {
	u8 Pwr;
	u8 AntBitMap;
	u8 Channel;
} setoffchpwr_t;

//(real-time signals are in the range of 35 to 64)
#define SIG_wifiarb_post_req_intr 40	/* we define our own signal, hard coded since SIGRTMIN is different in user and in kernel space */
#define wifiarb_post_req_intr_notification 0x1
typedef struct sfw_notification_s {
	u_int32_t devnum:2;	//0: wdev0, 1 = wdev1
	u_int32_t rsvd:14;
	u_int32_t notification_src:16;
} sfw_notification_t;
//=======================================================

//API for iwinfo
#define MWL_IOCTL_MAGIC             0x4d52564c
#define MWL_IOCTL_ID_GET_MAGIC              1
#define MWL_IOCTL_ID_GET_ASSOCLIST          2
#define MWL_IOCTL_ID_GET_HARDWAREID         3
#define MWL_IOCTL_ID_GET_HARDWARENAME       4
#define MWL_IOCTL_ID_GET_ENCRYPTION         5
#define MWL_IOCTL_ID_GET_HWMODE             6
#define MWL_IOCTL_ID_GET_HTMODE             7
#define MWL_IOCTL_ID_GET_PHYNAME            8

#define MWL_IWINFO_CIPHER_NONE   (1 << 0)
#define MWL_IWINFO_CIPHER_WEP40  (1 << 1)
#define MWL_IWINFO_CIPHER_TKIP   (1 << 2)
#define MWL_IWINFO_CIPHER_WRAP   (1 << 3)
#define MWL_IWINFO_CIPHER_CCMP   (1 << 4)
#define MWL_IWINFO_CIPHER_WEP104 (1 << 5)
#define MWL_IWINFO_CIPHER_AESOCB (1 << 6)
#define MWL_IWINFO_CIPHER_CKIP   (1 << 7)
#define MWL_IWINFO_CIPHER_COUNT  8

#define MWL_IWINFO_KMGMT_NONE    (1 << 0)
#define MWL_IWINFO_KMGMT_8021x   (1 << 1)
#define MWL_IWINFO_KMGMT_PSK     (1 << 2)
#define MWL_IWINFO_KMGMT_COUNT   3

#define MWL_IWINFO_AUTH_OPEN     (1 << 0)
#define MWL_IWINFO_AUTH_SHARED   (1 << 1)
#define MWL_IWINFO_AUTH_COUNT    2

struct iwinfo_rate_entry {
	uint32_t rate;
	int8_t mcs;
	uint8_t is_40mhz:1;
	uint8_t is_short_gi:1;
	uint8_t is_ht:1;
	uint8_t is_vht:1;
	uint8_t mhz;
	uint8_t nss;
};

struct mwl_ioctl_request {
	union {
		struct {
			char name[32];
		} phyname;
	} u;
};

struct mwl_ioctl_response {
	int magic;
	union {
		struct {
			int num;
			struct {
				uint8_t addr[6];
				uint8_t bssid[6];
				uint8_t state;
				uint8_t pwrmode;
				uint8_t clientmode;
				uint16_t aid;
				uint32_t timestamp;
				uint8_t sq2;	/* Signal Quality 2 */
				uint8_t sq1;	/* Signal Quality 1 */
				uint8_t rate;	/* rate at which frame was received */
				uint8_t rssi;	/* RF Signal Strength Indicator */
				struct iwinfo_rate_entry tx_rate;
				struct iwinfo_rate_entry rx_rate;
			} entry[0];
		} list;
		struct {
			uint16_t vendor_id;
			uint16_t device_id;
			uint16_t subsystem_vendor_id;
			uint16_t subsystem_device_id;
		} hardwareid;
		struct {
			uint8_t cat[32];
			uint8_t model[32];
		} hardwarename;
		struct {
			uint8_t enabled;
			uint8_t wpa_version;
			uint8_t group_ciphers;
			uint8_t pair_ciphers;
			uint8_t auth_suites;
			uint8_t auth_algs;
		} encryption;
		struct {
			uint8_t mode;
		} hardwaremode;
		struct {
			uint8_t mode;
		} htbw;
		struct {
			char name[32];
		} phyname;
	} u;
};

#ifdef AP_STEERING_SUPPORT
struct wlreq_qbss_load {
	u_int16_t sta_cnt;
	u_int8_t channel_util;	/*channel utilization */
};
#endif

#endif				/* AP8X_IOCTL_H_ */
