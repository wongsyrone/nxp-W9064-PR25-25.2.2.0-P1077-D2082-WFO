/** @file mlmeAuth.c
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

#include "wltypes.h"
#include "IEEE_types.h"
#include "wl_mib.h"
#include "mib.h"
#include "osif.h"
#include "timer.h"

#include "ds.h"
#include "keyMgmtCommon.h"
#include "keyMgmt.h"
#include "tkip.h"
#include "StaDb.h"
#include "macmgmtap.h"
#include "mhsm.h"
#include "mlme.h"
#include "wldebug.h"
#include <linux/random.h>
#include "ap8xLnxWlLog.h"

#define SYS_LOG(x)

//extern struct net_dev *g_dev;
static UINT16 max_shared_key_authentications;
#define AUTH_BODY_LEN_WITH_NO_CHAL_TEXT 6
#define IEEEtypes_CHALLENGE_TEXT_LEN    128

typedef struct tx80211_MgmtMsg_t {
	UINT32 reserved;
	UINT16 stnId;
	UINT16 macQId;
	macmgmtQ_MgmtMsg_t MgmtFrame;
} PACK_END tx80211_MgmtMsg_t;

typedef struct Challenge_t {
	BOOLEAN Free;
	IEEEtypes_MacAddr_t Addr;
	UINT8 Text[IEEEtypes_CHALLENGE_TEXT_SIZE + 2];
} PACK_END Challenge_t;

static Challenge_t *Challenge = NULL;
static SINT32 AllocateChallengeTextSpace(IEEEtypes_MacAddr_t * MacAddr_p);
static void FreeChallengeText(IEEEtypes_MacAddr_t * MacAddr_p);
static SINT32 GetChallengeText(IEEEtypes_MacAddr_t * MacAddr_p);
static void wep_decrypt(vmacApInfo_t * vmacSta_p,
			macmgmtQ_MgmtMsg3_t * MgmtMsg_p);

UINT32 NumAvailSharedAuthentications;
extern BOOLEAN isStrictShareMode(vmacApInfo_t * vmacSta_p, BOOLEAN bType);
extern BOOLEAN isAuthAlgTypeMatch(vmacApInfo_t * vmacSta_p, UINT8 x,
				  BOOLEAN bType);
extern BOOLEAN isWepRequired(vmacApInfo_t * vmacSta_p, BOOLEAN bType);
#ifdef AP_MAC_LINUX
extern struct sk_buff *mlmeApiPrepMgtMsg2(UINT32 Subtype,
					  IEEEtypes_MacAddr_t * DestAddr,
					  IEEEtypes_MacAddr_t * SrcAddr,
					  UINT16 size);
#else
extern tx80211_MgmtMsg_t *mlmeApiPrepMgtMsg2(UINT32 Subtype,
					     IEEEtypes_MacAddr_t * DestAddr,
					     IEEEtypes_MacAddr_t * SrcAddr,
					     UINT16 size);
#endif

WL_STATUS
mlmeAuthInit(UINT16 NoStns)
{
	UINT32 i;
	max_shared_key_authentications = NoStns;
	NumAvailSharedAuthentications = max_shared_key_authentications;
	Challenge = wl_kmalloc_autogfp(sizeof(Challenge_t) * NoStns);
	if (Challenge == NULL)
		return (OS_FAIL);

	for (i = 0; i < max_shared_key_authentications; i++) {
		Challenge[i].Free = TRUE;
		memset(Challenge[i].Addr, 0, sizeof(IEEEtypes_MacAddr_t));
	}
	return (OS_SUCCESS);
}

void
mlmeAuthCleanup(vmacApInfo_t * vmacSta_p)
{
	if (Challenge)
		wl_kfree(Challenge);
	Challenge = NULL;
}

void
mlmeAuthError(vmacApInfo_t * vmacSta_p, IEEEtypes_StatusCode_t statusCode,
	      UINT16 arAlg_in, UINT8 * Addr)
{
	macmgmtQ_MgmtMsg2_t *MgmtMsg_p;
	//tx80211_MgmtMsg_t *TxMsg_p;
	extStaDb_StaInfo_t *StaInfo_p;
	//IEEEtypes_MacAddr_t SrcMacAddr;
	struct sk_buff *txSkb_p;

	if (!vmacSta_p->InfUpFlag)
		return;

	if ((StaInfo_p =
	     extStaDb_GetStaInfo(vmacSta_p, (IEEEtypes_MacAddr_t *) Addr,
				 1)) == NULL) {
		return;
	}
	if ((txSkb_p =
	     mlmeApiPrepMgtMsg2(IEEE_MSG_AUTHENTICATE,
				(IEEEtypes_MacAddr_t *) Addr,
				(IEEEtypes_MacAddr_t *) vmacSta_p->macStaAddr,
				AUTH_BODY_LEN_WITH_NO_CHAL_TEXT)) == NULL) {
		WLDBG_INFO(DBG_LEVEL_8, "AUTH fail txSkb_p == NULL \n");
		return;
	}
	MgmtMsg_p = (macmgmtQ_MgmtMsg2_t *) txSkb_p->data;
	memset(&MgmtMsg_p->Body.Auth, 0, AUTH_BODY_LEN_WITH_NO_CHAL_TEXT);
	MgmtMsg_p->Body.Auth.AuthAlg = ENDIAN_SWAP16(arAlg_in);
	MgmtMsg_p->Body.Auth.AuthTransSeq = ENDIAN_SWAP16(2);
	MgmtMsg_p->Body.Auth.StatusCode = statusCode;
	if (txMgmtMsg(vmacSta_p->dev, txSkb_p) != OS_SUCCESS)
		wl_free_skb(txSkb_p);

	WLSYSLOG(vmacSta_p->dev, WLSYSLOG_CLASS_ALL,
		 WLSYSLOG_MSG_MLME_AUTH_FAILURE
		 "%02x%02x%02x%02x%02x%02x Reason %d\n",
		 ((unsigned char *)Addr)[0], ((unsigned char *)Addr)[1],
		 ((unsigned char *)Addr)[2], ((unsigned char *)Addr)[3],
		 ((unsigned char *)Addr)[4], ((unsigned char *)Addr)[5],
		 statusCode);
	{
		extern void macMgmtRemoveSta(vmacApInfo_t * vmacSta_p,
					     extStaDb_StaInfo_t * StaInfo_p);
		macMgmtRemoveSta(vmacSta_p, StaInfo_p);
	}
}

static UINT32
mlmeAuthValidateMsg(vmacApInfo_t * vmacSta_p, macmgmtQ_MgmtMsg3_t * MgmtMsg_p,
		    BOOLEAN txAuth)
{
	extStaDb_StaInfo_t *StaInfo_p;
	BOOLEAN bType = FALSE;

	if ((StaInfo_p =
	     extStaDb_GetStaInfo(vmacSta_p, &MgmtMsg_p->Hdr.SrcAddr,
				 STADB_UPDATE_AGINGTIME)) == NULL) {
		/* Station not in StaDb, so how can this statemachine run ??? */
		return (1);
	}

	if ((MgmtMsg_p->Body.Auth.AuthTransSeq != ENDIAN_SWAP16(1) &&
	     MgmtMsg_p->Body.Auth.AuthTransSeq != ENDIAN_SWAP16(3)) ||
	    (MgmtMsg_p->Body.Auth.AuthTransSeq == ENDIAN_SWAP16(3) &&
	     StaInfo_p->State != EXT_INIT_AUTHENTICATING)) {
		/* Send response message */
		WLDBG_INFO(DBG_LEVEL_8, "mlmeAuthValidateMsg Error  = %x \n",
			   MgmtMsg_p);
		if (txAuth) {
			mlmeAuthError(vmacSta_p, IEEEtypes_STATUS_RX_AUTH_NOSEQ,
				      MgmtMsg_p->Body.Auth.AuthAlg,
				      (UINT8 *) & MgmtMsg_p->Hdr.SrcAddr);

		}
		return (1);
	}

	if (isStrictShareMode(vmacSta_p, bType)) {
		if (!isAuthAlgTypeMatch
		    (vmacSta_p, ENDIAN_SWAP16(MgmtMsg_p->Body.Auth.AuthAlg),
		     bType) ||
		    (ENDIAN_SWAP16(MgmtMsg_p->Body.Auth.AuthAlg) ==
		     AUTH_SHARED_KEY && !isWepRequired(vmacSta_p, bType))) {
			/* Send response message */
			WLDBG_INFO(DBG_LEVEL_8,
				   "mlmeAuthValidateMsg isStrictShareMode Error  = %x \n",
				   MgmtMsg_p);
			if (txAuth) {
				mlmeAuthError(vmacSta_p,
					      IEEEtypes_STATUS_UNSUPPORTED_AUTHALG,
					      MgmtMsg_p->Body.Auth.AuthAlg,
					      (UINT8 *) & MgmtMsg_p->Hdr.
					      SrcAddr);
			}
			return (1);
		}
	}

	return (0);
}

SINT32
mlmeAuthDoOpenSys(vmacApInfo_t * vmacSta_p, AuthRspSrvApMsg * authRspMsg_p)
{
	macmgmtQ_MgmtMsg_t *MgmtMsg_p;
	extStaDb_StaInfo_t *StaInfo_p;
	macmgmtQ_MgmtMsg2_t *MgmtRsp;
	//tx80211_MgmtMsg_t * TxMsg_p;
	IEEEtypes_MacAddr_t SrcMacAddr;
	struct sk_buff *txSkb_p;

	if (!vmacSta_p->InfUpFlag)
		return (MLME_FAILURE);

	if (authRspMsg_p == NULL) {
		WLDBG_INFO(DBG_LEVEL_8, "AUTH NULL ptr \n");
		return (MLME_FAILURE);
	}

	if ((StaInfo_p =
	     extStaDb_GetStaInfo(vmacSta_p,
				 (IEEEtypes_MacAddr_t *) authRspMsg_p->rspMac,
				 STADB_UPDATE_AGINGTIME)) == NULL) {
		return (MLME_FAILURE);
	}

	MgmtMsg_p = (macmgmtQ_MgmtMsg_t *) authRspMsg_p->mgtMsg;

	memcpy(SrcMacAddr, MgmtMsg_p->Hdr.DestAddr,
	       sizeof(IEEEtypes_MacAddr_t));

	if ((txSkb_p =
	     mlmeApiPrepMgtMsg2(IEEE_MSG_AUTHENTICATE,
				(IEEEtypes_MacAddr_t *) MgmtMsg_p->Hdr.SrcAddr,
				(IEEEtypes_MacAddr_t *) MgmtMsg_p->Hdr.DestAddr,
				AUTH_BODY_LEN_WITH_NO_CHAL_TEXT)) == NULL) {
		WLDBG_INFO(DBG_LEVEL_8, "AUTH fail txSkb_p == NULL \n");
		return (MLME_FAILURE);
	}
	//TxMsg_p = (tx80211_MgmtMsg_t *) txSkb_p->data;
	MgmtRsp = (macmgmtQ_MgmtMsg2_t *) txSkb_p->data;

	if (MgmtRsp) {
		memset(&MgmtRsp->Body.Auth, 0, AUTH_BODY_LEN_WITH_NO_CHAL_TEXT);
		MgmtRsp->Body.Auth.AuthAlg = ENDIAN_SWAP16(0);	// MgmtMsg_p->Body.Auth.AuthAlg;
		MgmtRsp->Body.Auth.AuthTransSeq = ENDIAN_SWAP16(2);
		MgmtRsp->Body.Auth.StatusCode = IEEEtypes_STATUS_SUCCESS;
		//MgmtRsp->Hdr.FrmBodyLen = AUTH_BODY_LEN_WITH_NO_CHAL_TEXT;
		if (txMgmtMsg(vmacSta_p->dev, txSkb_p) != OS_SUCCESS)
			wl_free_skb(txSkb_p);
		if (StaInfo_p->State != ASSOCIATED)
			StaInfo_p->State = AUTHENTICATED;
	}
	return (MLME_SUCCESS);
}

SINT32
mlmeAuthDoSharedKeySeq1(vmacApInfo_t * vmacSta_p,
			AuthRspSrvApMsg * authRspMsg_p)
{
	macmgmtQ_MgmtMsg3_t *MgmtMsg_p;
	extStaDb_StaInfo_t *StaInfo_p;
	macmgmtQ_MgmtMsg2_t *MgmtRsp;
	//tx80211_MgmtMsg_t *TxMsg_p;
	IEEEtypes_MacAddr_t SrcMacAddr;
	SINT32 retcode = MLME_FAILURE;
	UINT32 value;
	SINT32 i, ChallengeIdx;
	struct sk_buff *txSkb_p;

	if (!vmacSta_p->InfUpFlag)
		return (MLME_FAILURE);

	if (authRspMsg_p == NULL) {
		return (MLME_FAILURE);
	}

	WLDBG_INFO(DBG_LEVEL_8,
		   "mlmeAuthDoSharedKeySeq1: Entered --- rspMac = %02x:%02x:%02x:%02x:%02x:%02x\n",
		   authRspMsg_p->rspMac[0], authRspMsg_p->rspMac[1],
		   authRspMsg_p->rspMac[2], authRspMsg_p->rspMac[3],
		   authRspMsg_p->rspMac[4], authRspMsg_p->rspMac[5]);

	MgmtMsg_p = (macmgmtQ_MgmtMsg3_t *) authRspMsg_p->mgtMsg;
	if ((StaInfo_p =
	     extStaDb_GetStaInfo(vmacSta_p,
				 (IEEEtypes_MacAddr_t *) authRspMsg_p->rspMac,
				 STADB_UPDATE_AGINGTIME)) == NULL) {
		WLDBG_INFO(DBG_LEVEL_8,
			   "mlmeAuthDoSharedKeySeq1: extStaDb_GetStaInfo Failed = %02x:%02x:%02x:%02x:%02x:%02x\n",
			   authRspMsg_p->rspMac[0], authRspMsg_p->rspMac[1],
			   authRspMsg_p->rspMac[2], authRspMsg_p->rspMac[3],
			   authRspMsg_p->rspMac[4], authRspMsg_p->rspMac[5]);
		return (MLME_FAILURE);
	}
	if (mlmeAuthValidateMsg(vmacSta_p, MgmtMsg_p, TRUE)) {
		WLDBG_INFO(DBG_LEVEL_8,
			   "mlmeAuthDoSharedKeySeq1: Validation failed --- rspMac = %02x:%02x:%02x\n",
			   authRspMsg_p->rspMac[3], authRspMsg_p->rspMac[4],
			   authRspMsg_p->rspMac[5]);
		return (MLME_FAILURE);
	}

	StaInfo_p->State = UNAUTHENTICATED;
	// Start from fresh
	FreeChallengeText(&MgmtMsg_p->Hdr.SrcAddr);
	WLDBG_INFO(DBG_LEVEL_8,
		   "mlmeAuthDoSharedKeySeq1: get management packet for = %02x:%02x:%02x:%02x:%02x:%02x\n",
		   authRspMsg_p->rspMac[0], authRspMsg_p->rspMac[1],
		   authRspMsg_p->rspMac[2], authRspMsg_p->rspMac[3],
		   authRspMsg_p->rspMac[4], authRspMsg_p->rspMac[5]);
	memcpy(SrcMacAddr, MgmtMsg_p->Hdr.DestAddr,
	       sizeof(IEEEtypes_MacAddr_t));

	if ((txSkb_p =
	     mlmeApiPrepMgtMsg2(IEEE_MSG_AUTHENTICATE, &MgmtMsg_p->Hdr.SrcAddr,
				&SrcMacAddr,
				(AUTH_BODY_LEN_WITH_NO_CHAL_TEXT + 2 +
				 IEEEtypes_CHALLENGE_TEXT_LEN))) == NULL) {
		WLDBG_INFO(DBG_LEVEL_8, "AUTH fail txSkb_p == NULL \n");
		return (MLME_FAILURE);
	}
	WLDBG_INFO(DBG_LEVEL_8,
		   "mlmeApiPrepMgtMsg2 size  = %d txSkb_p = %x tsSkb_p->data = %x\n",
		   (AUTH_BODY_LEN_WITH_NO_CHAL_TEXT + 2 +
		    IEEEtypes_CHALLENGE_TEXT_LEN), txSkb_p, txSkb_p->data);
	MgmtRsp = (macmgmtQ_MgmtMsg2_t *) txSkb_p->data;

	MgmtRsp->Body.Auth.AuthAlg = MgmtMsg_p->Body.Auth.AuthAlg;
	MgmtRsp->Body.Auth.AuthTransSeq = ENDIAN_SWAP16(2);
	if ((ChallengeIdx =
	     AllocateChallengeTextSpace(&MgmtMsg_p->Hdr.SrcAddr)) < 0) {
		WLDBG_INFO(DBG_LEVEL_8,
			   "mlmeAuthDoSharedKeySeq1: Failed! SrcAddr = %02x:%02x:%02x\n",
			   MgmtMsg_p->Hdr.SrcAddr[3], MgmtMsg_p->Hdr.SrcAddr[4],
			   MgmtMsg_p->Hdr.SrcAddr[5]);
		MgmtRsp->Body.Auth.StatusCode = IEEEtypes_STATUS_UNSPEC_FAILURE;
		//MgmtRsp->Hdr.FrmBodyLen = AUTH_BODY_LEN_WITH_NO_CHAL_TEXT;
	} else {
		MgmtRsp->Body.Auth.StatusCode = IEEEtypes_STATUS_SUCCESS;
		MgmtRsp->Body.Auth.ChallengeText.Len =
			IEEEtypes_CHALLENGE_TEXT_LEN;
		MgmtRsp->Body.Auth.ChallengeText.ElementId = CHALLENGE_TEXT;
		//MgmtRsp->Hdr.FrmBodyLen = AUTH_BODY_LEN_WITH_NO_CHAL_TEXT + 2 + IEEEtypes_CHALLENGE_TEXT_LEN;
		for (i = 0; i < IEEEtypes_CHALLENGE_TEXT_LEN; i += 4) {
#ifdef ECOS
			value = rand();
#else
			value = prandom_u32();	//rand();
#endif
			memcpy(&MgmtRsp->Body.Auth.ChallengeText.Text[i],
			       &value, 4);
			memcpy(&Challenge[ChallengeIdx].Text[i], &value, 4);
		}

		StaInfo_p->State = EXT_INIT_AUTHENTICATING;
		retcode = MLME_SUCCESS;
	}
	if (txMgmtMsg(vmacSta_p->dev, txSkb_p) != OS_SUCCESS)
		wl_free_skb(txSkb_p);
	return retcode;
}

SINT32
mlmeAuthDoSharedKeySeq3(vmacApInfo_t * vmacSta_p,
			AuthRspSrvApMsg * authRspMsg_p)
{
	macmgmtQ_MgmtMsg3_t *MgmtMsg_p;
	extStaDb_StaInfo_t *StaInfo_p;
	macmgmtQ_MgmtMsg2_t *MgmtRsp;
	SINT32 retcode = MLME_FAILURE;
	//tx80211_MgmtMsg_t *TxMsg_p;
	IEEEtypes_MacAddr_t SrcMacAddr;
	SINT32 i;
	struct sk_buff *txSkb_p;

	if (!vmacSta_p->InfUpFlag)
		return (MLME_FAILURE);

	if (authRspMsg_p == NULL) {
		return (MLME_FAILURE);
	}

	SYS_LOG(("mlmeAuthDoSharedKeySeq3: Entered --- rspMac = %02x:%02x:%02x\n", authRspMsg_p->rspMac[3], authRspMsg_p->rspMac[4], authRspMsg_p->rspMac[5]));

	MgmtMsg_p = (macmgmtQ_MgmtMsg3_t *) authRspMsg_p->mgtMsg;
	if ((StaInfo_p =
	     extStaDb_GetStaInfo(vmacSta_p,
				 (IEEEtypes_MacAddr_t *) authRspMsg_p->rspMac,
				 STADB_UPDATE_AGINGTIME)) == NULL) {
		return (MLME_FAILURE);
	}

	memcpy(SrcMacAddr, MgmtMsg_p->Hdr.DestAddr,
	       sizeof(IEEEtypes_MacAddr_t));
	if ((txSkb_p =
	     mlmeApiPrepMgtMsg2(IEEE_MSG_AUTHENTICATE,
				(IEEEtypes_MacAddr_t *) MgmtMsg_p->Hdr.SrcAddr,
				(IEEEtypes_MacAddr_t *) MgmtMsg_p->Hdr.DestAddr,
				AUTH_BODY_LEN_WITH_NO_CHAL_TEXT)) == NULL) {
		WLDBG_INFO(DBG_LEVEL_8, "AUTH fail txSkb_p == NULL \n");
		return (MLME_FAILURE);
	}
	MgmtRsp = (macmgmtQ_MgmtMsg2_t *) txSkb_p->data;
	MgmtRsp->Body.Auth.AuthAlg = MgmtMsg_p->Body.Auth.AuthAlg;
	MgmtRsp->Body.Auth.AuthTransSeq = ENDIAN_SWAP16(4);
	//MgmtRsp->Hdr.FrmBodyLen = AUTH_BODY_LEN_WITH_NO_CHAL_TEXT;

	if (MgmtMsg_p->Hdr.FrmCtl.Wep == 0) {
		/* This is not WEP challenge text */
		MgmtRsp->Body.Auth.StatusCode = IEEEtypes_STATUS_UNSPEC_FAILURE;
		StaInfo_p->State = UNAUTHENTICATED;
		retcode = MLME_FAILURE;
		goto send_resp;
	} else {
		wep_decrypt(vmacSta_p, MgmtMsg_p);
	}
	if (mlmeAuthValidateMsg(vmacSta_p, MgmtMsg_p, FALSE)) {
		SYS_LOG(("mlmeAuthDoSharedKeySeq3: validation failed! --- rspMac = %02x:%02x:%02x\n", authRspMsg_p->rspMac[3], authRspMsg_p->rspMac[4], authRspMsg_p->rspMac[5]));
		MgmtRsp->Body.Auth.AuthAlg = AUTH_SHARED_KEY;
		MgmtRsp->Body.Auth.StatusCode = IEEEtypes_STATUS_CHALLENGE_FAIL;
		StaInfo_p->State = UNAUTHENTICATED;
		retcode = MLME_FAILURE;
	} else {
		if ((i = GetChallengeText(&MgmtMsg_p->Hdr.SrcAddr)) < 0) {
			MgmtRsp->Body.Auth.StatusCode =
				IEEEtypes_STATUS_UNSPEC_FAILURE;
			StaInfo_p->State = UNAUTHENTICATED;
			SYS_LOG(("mlmeAuthDoSharedKeySeq3: Failed! SrcAddr = %02x:%02x:%02x\n", MgmtMsg_p->Hdr.SrcAddr[3], MgmtMsg_p->Hdr.SrcAddr[4], MgmtMsg_p->Hdr.SrcAddr[5]));
		} else {
			if ((MgmtMsg_p->Body.Auth.ChallengeText.Len ==
			     IEEEtypes_CHALLENGE_TEXT_LEN) &&
			    !memcmp(MgmtMsg_p->Body.Auth.ChallengeText.Text,
				    Challenge[i].Text,
				    IEEEtypes_CHALLENGE_TEXT_LEN)) {
				MgmtRsp->Body.Auth.AuthAlg = AUTH_SHARED_KEY;
				MgmtRsp->Body.Auth.StatusCode =
					IEEEtypes_STATUS_SUCCESS;
				StaInfo_p->State = AUTHENTICATED;
				retcode = MLME_SUCCESS;
			} else {
				MgmtRsp->Body.Auth.StatusCode =
					IEEEtypes_STATUS_CHALLENGE_FAIL;
				StaInfo_p->State = UNAUTHENTICATED;
			}
			FreeChallengeText(&MgmtMsg_p->Hdr.SrcAddr);
		}
	}
send_resp:
	if (txMgmtMsg(vmacSta_p->dev, txSkb_p) != OS_SUCCESS)
		wl_free_skb(txSkb_p);
	return (retcode);
}

static SINT32
AllocateChallengeTextSpace(IEEEtypes_MacAddr_t * MacAddr_p)
{
	int i;

	for (i = 0; i < max_shared_key_authentications; i++) {
		if (Challenge[i].Free == TRUE) {
			Challenge[i].Free = FALSE;
			memcpy(Challenge[i].Addr, MacAddr_p,
			       sizeof(IEEEtypes_MacAddr_t));
			NumAvailSharedAuthentications--;
			return i;
		}
	}
	return (-1);
}

static SINT32
GetChallengeText(IEEEtypes_MacAddr_t * MacAddr_p)
{
	int i;

	for (i = 0; i < max_shared_key_authentications; i++) {
		if (Challenge[i].Free == FALSE) {
			if (!memcmp
			    (Challenge[i].Addr, MacAddr_p,
			     sizeof(IEEEtypes_MacAddr_t))) {
				return i;
			}
		}
	}
	return (-1);
}

static void
FreeChallengeText(IEEEtypes_MacAddr_t * MacAddr_p)
{
	int i;

	for (i = 0; i < max_shared_key_authentications; i++) {
		if (!memcmp
		    (MacAddr_p, Challenge[i].Addr,
		     sizeof(IEEEtypes_MacAddr_t))) {
			Challenge[i].Free = TRUE;
			memset(Challenge[i].Addr, 0,
			       sizeof(IEEEtypes_MacAddr_t));
			NumAvailSharedAuthentications++;
			return;
		}
	}
}

struct rc4context {
	UINT32 x;
	UINT32 y;
	UINT8 state[256];
};

static UINT8
rc4_byte(struct rc4context *rc4WS)
{
	UINT32 x;
	UINT32 y;
	UINT32 sx, sy;
	UINT8 *state;

	state = rc4WS->state;
	x = (rc4WS->x + 1) & 0xff;
	sx = state[x];
	y = (sx + rc4WS->y) & 0xff;
	sy = state[y];
	rc4WS->x = x;
	rc4WS->y = y;
	state[y] = (u8) sx;
	state[x] = (u8) sy;

	return state[(sx + sy) & 0xff];
}

extern unsigned long crc32_table[256];

static void
wep_decrypt(vmacApInfo_t * vmacSta_p, macmgmtQ_MgmtMsg3_t * MgmtMsg_p)
{
	MIB_802DOT11 *mib = vmacSta_p->ShadowMib802dot11;
	UINT32 WepType =
		mib->WepDefaultKeys[*(mib->mib_defaultkeyindex)].WepType;
	UINT32 keylength = 0, crc, i, j, k, len, crc_check;
	UINT8 *pos, *iv, wepkey[16];
	UINT8 t, u;
	struct rc4context rc4WS;

	len = MgmtMsg_p->Hdr.FrmBodyLen - sizeof(IEEEtypes_MgmtHdr3_t) + 2;
	iv = (UINT8 *) & (MgmtMsg_p->Body.Auth);

	if (len <= 8) {
		/* Auth data length is not enough for challenge text */
		return;
	}
	memset(&wepkey[0], 0, 16);
	memcpy(&wepkey[0], iv, 3);

	if (WepType == 1)	//40 bit
		keylength = 5;
	else if (WepType == 2)
		keylength = 13;	//128 bit

	memcpy(&wepkey[3],
	       &mib->WepDefaultKeys[*(mib->mib_defaultkeyindex)].
	       WepDefaultKeyValue[0], keylength);

	/* Setup RC4 state */
	rc4WS.x = 0;
	rc4WS.y = 0;
	for (i = 0; i < 256; i++)
		rc4WS.state[i] = i;
	j = 0;
	k = 0;
	for (i = 0; i < 256; i++) {
		t = rc4WS.state[i];
		j = (j + rc4WS.state[i] + wepkey[k]) & 0xff;
		u = rc4WS.state[j];
		rc4WS.state[j] = t;
		rc4WS.state[i] = u;
		k++;
		if (k >= (3 + keylength))
			k = 0;
	}

	/*dncrypted data and remove IV(4 bytes) */
	pos = iv;
	for (i = 0; i < (len - 4); i++)
		pos[i] = pos[i + 4] ^ rc4_byte(&rc4WS);

	/* Compute CRC32 over unencrypted data */
	crc = ~0;
	i = j = 0;
	for (k = 0; k < (len - 8); pos++, k++) {
		crc = crc32_table[(crc ^ *pos) & 0xff] ^ (crc >> 8);
	}
	crc = ~crc;

	pos = (UINT8 *) & (MgmtMsg_p->Body.Auth);
	MgmtMsg_p->Hdr.FrmBodyLen -= 4;	/* remove 4 bytes IV */
	len = MgmtMsg_p->Hdr.FrmBodyLen - sizeof(IEEEtypes_MgmtHdr3_t) + 2;
	crc_check = (UINT32) * ((UINT32 *) & pos[len - 4]);
	/* check CRC */
	if (crc != crc_check) {
		/* crc check failed */
	}
}
