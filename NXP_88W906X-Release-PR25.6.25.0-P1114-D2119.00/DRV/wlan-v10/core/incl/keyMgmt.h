/** @file keyMgmt.h
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

#ifndef _HANDHSK_H_
#define _HANDHSK_H_

#include "mhsm.h"

#include "tkip.h"
#include "wl_mib.h"
#include "wl_hal.h"

#include "timer.h"

#define MAX_SIZE_MDIE_BUF 6
#define MAX_SIZE_FTIE_BUF 128

#define S_SWAP(a,b) do { unsigned char  t = S[a]; S[a] = S[b]; S[b] = t; } while(0)
#define WS_SWAP(a,b) do { unsigned char  t = WS[a]; WS[a] = WS[b]; WS[b] = t; } while(0)

#define U8_ARRAY_TO_U32(a, b, c, d) \
	((((UINT32) (a)) << 24) | (((UINT32) (b)) << 16) | (((UINT32) (c)) << 8) | \
	 (UINT32) (d))

#define WPA_CIPHER_NONE (0)
#define WPA_CIPHER_WEP40 BIT(1)
#define WPA_CIPHER_TKIP BIT(2)
#define WPA_CIPHER_CCMP BIT(4)
#define WPA_CIPHER_WEP104 BIT(5)
#define WPA_CIPHER_GCMP_128 BIT(8)
#define WPA_CIPHER_GCMP_256 BIT(9)
#define WPA_CIPHER_CCMP_256 BIT(10)
#define WPA2_CIPHER_TKIP BIT(11)
#define WPA2_CIPHER_CCMP BIT(12)

#define WPA_KEY_MGMT_IEEE8021X BIT(1)
#define WPA_KEY_MGMT_PSK BIT(2)
#define WPA_KEY_MGMT_PSK_SHA256 BIT(6)
#define WPA_KEY_MGMT_SAE BIT(8)
#define WPA_KEY_MGMT_SUITE_B BIT(11)
#define WPA_KEY_MGMT_SUITE_B_192 BIT(12)
#define WPA_KEY_MGMT_OWE BIT(18)

#define CIPHER_WPA_WEP40 U8_ARRAY_TO_U32(0x00, 0x50, 0xf2, 1)
#define CIPHER_WPA_TKIP U8_ARRAY_TO_U32(0x00, 0x50, 0xf2, 2)
#define CIPHER_WPA_CCMP U8_ARRAY_TO_U32(0x00, 0x50, 0xf2, 4)
#define CIPHER_WPA_WEP104 U8_ARRAY_TO_U32(0x00, 0x50, 0xf2, 5)

#define CIPHER_RSN_WEP40 U8_ARRAY_TO_U32(0x00, 0x0f, 0xac, 1)
#define CIPHER_RSN_TKIP U8_ARRAY_TO_U32(0x00, 0x0f, 0xac, 2)
#define CIPHER_RSN_CCMP U8_ARRAY_TO_U32(0x00, 0x0f, 0xac, 4)
#define CIPHER_RSN_WEP104 U8_ARRAY_TO_U32(0x00, 0x0f, 0xac, 5)
#define CIPHER_GCMP_128 U8_ARRAY_TO_U32(0x00, 0x0f, 0xac, 8)
#define CIPHER_GCMP_256 U8_ARRAY_TO_U32(0x00, 0x0f, 0xac, 9)
#define CIPHER_CCMP_256 U8_ARRAY_TO_U32(0x00, 0x0f, 0xac, 10)

#define KEY_MGMT_WPA_IEEE8021X U8_ARRAY_TO_U32(0x00, 0x50, 0xf2, 1)
#define KEY_MGMT_WPA_PSK U8_ARRAY_TO_U32(0x00, 0x50, 0xf2, 2)
#define KEY_MGMT_RSN_IEEE8021X U8_ARRAY_TO_U32(0x00, 0x0f, 0xac, 1)
#define KEY_MGMT_RSN_PSK U8_ARRAY_TO_U32(0x00, 0x0f, 0xac, 2)
#define KEY_MGMT_PSK_SHA256 U8_ARRAY_TO_U32(0x00, 0x0f, 0xac, 6)
#define KEY_MGMT_SAE U8_ARRAY_TO_U32(0x00, 0x0f, 0xac, 8)
#define KEY_MGMT_SUITE_B U8_ARRAY_TO_U32(0x00, 0x0f, 0xac, 11)
#define KEY_MGMT_SUITE_B_192 U8_ARRAY_TO_U32(0x00, 0x0f, 0xac, 12)
#define KEY_MGMT_OWE U8_ARRAY_TO_U32(0x00, 0x0f, 0xac, 18)

typedef struct {
	Mhsm_t super;
	MhsmState_t sTop;
	MhsmState_t hsk_start;
	MhsmState_t waiting_4_msg_2;
	MhsmState_t waiting_4_msg_4;
	MhsmState_t waiting_4_grpmsg_2;
	MhsmState_t hsk_end;
	Timer timer;
	struct timer_list keyTimer;
	UINT8 timeout_ctr;
	void *pData;
	vmacApInfo_t *vmacSta_p;
} keyMgmthsk_hsm_t;
#if !defined (ECL_WPA)
typedef struct {
	UINT8 ANonce[NONCE_SIZE];
	UINT8 SNonce[NONCE_SIZE];
	UINT8 EAPOL_MIC_Key[EAPOL_MIC_KEY_SIZE];
	UINT8 EAPOL_Encr_Key[EAPOL_ENCR_KEY_SIZE];
	UINT8 PairwiseTempKey1[TK_SIZE_MAX];
	UINT8 RSNPwkTxMICKey[8];
	UINT8 RSNPwkRxMICKey[8];
	UINT8 PairwiseTempKey1_tmp[TK_SIZE_MAX];
	UINT8 RSNPwkTxMICKey_tmp[8];
	UINT8 RSNPwkRxMICKey_tmp[8];
	UINT32 counter;		/*store only the lower counter */
	/*actually we should store both the lower and the upper counter. But */
	/*  in our implementation we only increment the lower counter */
	UINT8 RsnIEBuf[MAX_SIZE_RSN_IE_BUF];
#ifdef MRVL_80211R
	UINT8 mdie_buf[MAX_SIZE_MDIE_BUF];
	UINT8 ftie_buf[MAX_SIZE_FTIE_BUF];
	UINT8 pending_assoc;
	struct sk_buff *assoc;
	UINT8 reassoc;
#endif
	UINT32 TxIV32;
	UINT32 RxIV32;
	UINT16 TxIV16;
	UINT8 RSNDataTrafficEnabled;
	UINT8 TimeoutCtr;
	UINT16 Phase1KeyTx[5];
	UINT16 Phase1KeyRx[5];
	UINT8 PMK[32];
	/*keyMgmtState_e keyMgmtState; */
} keyMgmtInfo_t;
#endif
typedef enum {
	STA_ASSO_EVT,
	MSGRECVD_EVT,
	KEYMGMTTIMEOUT_EVT,
	GRPKEYTIMEOUT_EVT,
	UPDATEKEYS_EVT
} keyMgmthsk_event_e;
typedef UINT8 keyMgmthsk_event_t;

typedef struct {
	Timer discon_timer;
	Timer timer;
	MIC_Fail_State_t status;
	BOOLEAN MICCounterMeasureEnabled;	//indicates if counter Measures is enabled
	UINT32 disableStaAsso;	//1= Sta Association is disabled
} MIC_Error_t;

void HskCtor(keyMgmthsk_hsm_t * me);
extern void SendKeyMgmtInitEvent(vmacApInfo_t * vmacSta_p);
extern void KeyMgmtReset(vmacApInfo_t * vmacSta_p);

#if !defined(PORTABLE_ARCH)
/*
extern inline UINT32 (*DoWPAAndSchedFrameFp)(WLAN_TX_FRAME *Frame_p, keyMgmtInfo_t *pKeyMgmtInfo,
UINT16 ethertype, BOOLEAN BcastFlag);
extern inline UINT32 DoTKIPAndSchedFrameAP(WLAN_TX_FRAME *Frame_p, keyMgmtInfo_t *pKeyMgmtInfo,
UINT16 ethertype, BOOLEAN BcastFlag);
extern inline USR_BUF_DESC *ProcessTKIPPcktAP(keyMgmtInfo_t *pkeyInfo, USR_BUF_DESC *usp,
WLAN_RX_FRAME **Data11Frame_pp);
extern inline USR_BUF_DESC *(*ProcessWPAPcktFp)(keyMgmtInfo_t *pkeyInfo, USR_BUF_DESC *usp,
WLAN_RX_FRAME **Data11Frame_pp);
#ifdef AP_WPA2
inline UINT32 DoCCMPAndSchedFrameAP(WLAN_TX_FRAME *Frame_p, keyMgmtInfo_t *pKeyMgmtInfo,
UINT16 ethertype, BOOLEAN BcastFlag);
inline USR_BUF_DESC *ProcessCCMPPcktAP(keyMgmtInfo_t *pkeyInfo,
USR_BUF_DESC *usp,
WLAN_RX_FRAME **Data11Frame_pp);
#endif
*/
#else
extern UINT32(*DoWPAAndSchedFrameFp) (WLAN_TX_FRAME * Frame_p, keyMgmtInfo_t * pKeyMgmtInfo, UINT16 ethertype, BOOLEAN BcastFlag);
extern INLINE UINT32 DoTKIPAndSchedFrameAP(WLAN_TX_FRAME * Frame_p, keyMgmtInfo_t * pKeyMgmtInfo, UINT16 ethertype, BOOLEAN BcastFlag);
extern INLINE USR_BUF_DESC *ProcessTKIPPcktAP(keyMgmtInfo_t * pkeyInfo, USR_BUF_DESC * usp, WLAN_RX_FRAME ** Data11Frame_pp);
extern USR_BUF_DESC *(*ProcessWPAPcktFp) (keyMgmtInfo_t * pkeyInfo, USR_BUF_DESC * usp, WLAN_RX_FRAME ** Data11Frame_pp);
#ifdef AP_WPA2
inline UINT32 DoCCMPAndSchedFrameAP(WLAN_TX_FRAME * Frame_p, keyMgmtInfo_t * pKeyMgmtInfo, UINT16 ethertype, BOOLEAN BcastFlag);
inline USR_BUF_DESC *ProcessCCMPPcktAP(keyMgmtInfo_t * pkeyInfo, USR_BUF_DESC * usp, WLAN_RX_FRAME ** Data11Frame_pp);
#endif
#endif
#endif
