/** @file tkip.c
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
#include "ap8xLnxIntf.h"
#include "wltypes.h"
#include "IEEE_types.h"
#include "osif.h"

#include "mib.h"
#include "wl_mib.h"
#include "wl_hal.h"
#include "qos.h"
#include "wlmac.h"
#include "ds.h"
#include "keyMgmtCommon.h"
#include "keyMgmt.h"
#include "tkip.h"
#include "StaDb.h"
#include "macmgmtap.h"

#include "macMgmtMlme.h"
#include "macMgmtMlme.h"
#include "encryptapi.h"

#define MACADDR_CPY(macaddr1,macaddr2) { *(UINT16*)macaddr1 = *(UINT16*)macaddr2; \
	*(UINT16 *)((UINT16*)macaddr1+1) = *(UINT16 *)((UINT16*)macaddr2+1); \
	*(UINT16 *)((UINT16*)macaddr1+2) = *(UINT16 *)((UINT16*)macaddr2+2);}

UINT32 timeout_val = 20000;
UINT8 S[256] = { 0 };

extern IEEEtypes_MacAddr_t bcast;	// = {0xff,0xff,0xff,0xff,0xff,0xff};
extern unsigned long crc32_table[256];

extern void Mrvl_hmac_md5(UINT8 * text_data, int text_len, UINT8 * key, int key_len, void *digest);

void ComputeEAPOL_MIC(vmacApInfo_t * vmacSta_p, UINT8 * data, UINT16 data_length,
		      UINT8 * MIC_Key, UINT8 MIC_Key_length, UINT8 * computed_MIC, UINT8 * RsnIEBuf)
{
	MIB_RSNCONFIG_UNICAST_CIPHERS *mib_RSNConfigUnicastCiphers_p = vmacSta_p->Mib802dot11->UnicastCiphers;
	MIB_RSNCONFIGWPA2 *mib_RSNConfigWPA2_p = vmacSta_p->Mib802dot11->RSNConfigWPA2;
	if (RsnIEBuf) {
		//zeroize the MIC key field before calculating the data
		memset(data + 77 + sizeof(Hdr_8021x_t), 0x00, EAPOL_MIC_SIZE);
		if ((RsnIEBuf[0] == 221 && RsnIEBuf[17] == 2)
		    || (RsnIEBuf[0] == 48 && RsnIEBuf[13] == 2)
		    ) {
			Mrvl_hmac_md5(data, (int)data_length, MIC_Key, (int)MIC_Key_length, (void *)computed_MIC);
		} else if ((RsnIEBuf[0] == 221 && RsnIEBuf[17] == 4)
			   || (RsnIEBuf[0] == 48 && isAes4RsnValid(RsnIEBuf[13]))
		    ) {
			Mrvl_hmac_sha1(data, (int)data_length, MIC_Key, (int)MIC_Key_length, (void *)computed_MIC);
		}
	} else {
		memset(data + 77 + sizeof(Hdr_8021x_t), 0x00, EAPOL_MIC_SIZE);
		if (!mib_RSNConfigWPA2_p->WPA2OnlyEnabled && !mib_RSNConfigWPA2_p->WPA2Enabled
		    && mib_RSNConfigUnicastCiphers_p->UnicastCipher[3] == 2) {
			Mrvl_hmac_md5(data, (int)data_length, MIC_Key, (int)MIC_Key_length, (void *)computed_MIC);
		} else {
			Mrvl_hmac_sha1(data, (int)data_length, MIC_Key, (int)MIC_Key_length, (void *)computed_MIC);
		}
	}
}

Status_e checkEAPOL_MIC(UINT8 * MIC1, UINT8 * MIC2, UINT8 length)
{
	return memcmp(MIC1, MIC2, length) == 0 ? SUCCESS : FAIL;
}

void apppendEAPOL_MIC(UINT8 * data, UINT8 * MIC_Data)
{
	memcpy(data, MIC_Data, EAPOL_MIC_SIZE);
}

Status_e CompareRSN_IE(UINT8 * pRSN_IE_data, UINT8 * PrbReqRSNIE)
{
	UINT8 length = 2 + PrbReqRSNIE[1];
	return memcmp(pRSN_IE_data, PrbReqRSNIE, length) == 0 ? SUCCESS : FAIL;
}

void Insert8021xHdr(Hdr_8021x_t * pHdr, UINT16 data_length)
{
	pHdr->protocol_ver = 0x01;
	pHdr->pckt_type = 0x03;
	pHdr->pckt_body_len = SHORT_SWAP(data_length);
}

void genetate_PTK(vmacApInfo_t * vmacSta_p, UINT8 * PMK, IEEEtypes_MacAddr_t * pAddr1,
		  IEEEtypes_MacAddr_t * pAddr2, UINT8 * pNonce1, UINT8 * pNonce2, UINT8 * pPTK)
{
	UINT8 inp_data[76], prefix[30];

	if (memcmp(pAddr1, pAddr2, 6) < 0) {
		MACADDR_CPY(inp_data, pAddr1);
		MACADDR_CPY((inp_data + 6), pAddr2);
	} else {
		MACADDR_CPY(inp_data, pAddr2);
		MACADDR_CPY((inp_data + 6), pAddr1);
	}

	if (memcmp(pNonce1, pNonce2, NONCE_SIZE) < 0) {
		memcpy(inp_data + 6 + 6, pNonce1, NONCE_SIZE);
		memcpy(inp_data + 6 + 6 + NONCE_SIZE, pNonce2, NONCE_SIZE);
	} else {
		memcpy(inp_data + 6 + 6, pNonce2, NONCE_SIZE);
		memcpy(inp_data + 6 + 6 + NONCE_SIZE, pNonce1, NONCE_SIZE);
	}
	strcpy(prefix, "Pairwise key expansion");

	if (PMK) {
		Mrvl_PRF(PMK, 32, prefix, strlen(prefix), inp_data, sizeof(inp_data), pPTK, 64);
	} else {
		Mrvl_PRF(vmacSta_p->Mib802dot11->RSNConfig->PSKValue, 32, prefix, strlen(prefix), inp_data, sizeof(inp_data), pPTK, 64);
	}
}

void generateRand(UINT8 * Data, UINT32 length)
{
	UINT32 i;

	for (i = length; i--;) {
		Data[i] = prandom_u32();
	}
}

void EncryptGrpKey(UINT8 * Encr_Key, UINT8 * IV, UINT8 * Data, UINT16 data_length)
{
	/* Setup RC4 state */
	UINT32 i, j, k;
	UINT8 kpos, key[32];

	memcpy(key, IV, 16);
	memcpy(key + 16, Encr_Key, 16);

	for (i = 0; i < 256; i++)
		S[i] = i;
	j = 0;
	kpos = 0;
	for (i = 0; i < 256; i++) {
		j = (j + S[i] + key[kpos]) & 0xff;
		kpos++;
		if (kpos >= sizeof(key))
			kpos = 0;
		S_SWAP(i, j);
	}

	i = j = 0;
	//Discard the first 256 bytes
	for (k = 0; k < 256; k++) {
		i = (i + 1) & 0xff;
		j = (j + S[i]) & 0xff;
		S_SWAP(i, j);
	}
	for (k = 0; k < data_length; k++) {
		i = (i + 1) & 0xff;
		j = (j + S[i]) & 0xff;
		S_SWAP(i, j);
		*Data++ ^= S[(S[i] + S[j]) & 0xff];
	}
}

void MicErrTimerExpCb(vmacApInfo_t * vmacSta_p)
{
	switch (vmacSta_p->MIC_Errorstatus) {
	case FIRST_MIC_FAIL_IN_60_SEC:
		vmacSta_p->MIC_Errorstatus = NO_MIC_FAILURE;
		break;
	case SECOND_MIC_FAIL_IN_60_SEC:
		vmacSta_p->MIC_Errorstatus = NO_MIC_FAILURE;
		vmacSta_p->MIC_ErrordisableStaAsso = 0;
		break;
	default:
		break;
	}
}
