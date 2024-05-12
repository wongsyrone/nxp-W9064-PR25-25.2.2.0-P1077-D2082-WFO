/** @file ccmp.h
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

#ifndef _CCMP_H_
#define _CCMP_H_

#define BLK_SIZE 16

typedef union {			/* AES cipher block */
	UINT32 x[BLK_SIZE / 4];	/* access as 8-bit octets or 32-bit words */
	UINT8 b[BLK_SIZE];
} block_u;

void AES_Encrypt(const UINT32 in_blk[4], UINT32 out_blk[4], UINT32 keys[]);
void AES_DecryptWrap(const UINT32 in_blk[4], UINT32 out_blk[4], UINT32 enc_keys[], UINT32 dec_keys[]);
void AES_SetKey(const UINT32 in_key[], UINT32 out_key[]);
void AES_SetKeyWrap(const UINT32 in_key[], UINT32 enc_key[], UINT32 dec_key[]);
inline void MakeCCMCounterNonce(UINT8 * pCCMNonce, IEEEtypes_Frame_t * pRxPckt, UINT16);
inline void MakeMICIV(UINT8 * pMICIV, IEEEtypes_Frame_t * pRxPkt, UINT16 payload_size, UINT16);
inline void MakeMICHdr1(UINT8 * pMICHdr, IEEEtypes_GenHdr_t * pHdr, UINT8);
inline void MakeMICHdr2(UINT8 * pMICHdr, IEEEtypes_GenHdr_t * pHdr, UINT16);
void GenerateEncrData(UINT8 * pCCMCtrNonce, UINT8 * pSrcTxt, UINT8 * pDstTxt, UINT16 data_len, UINT32 * pKey);
void GenerateMIC(UINT8 *, UINT8 *, UINT8 *, UINT8 *, UINT8 *, UINT8 *, UINT32, UINT32 *);
inline UINT32 DoCCMPDecrypt(IEEEtypes_Frame_t * pRxPckt, UINT8 * pDest, UINT16 data_length, UINT32 * pKey, UINT16 Priority);

extern void InsertCCMPHdr(UINT8 * pCCMPHdr, UINT8 keyID, UINT16 IV16, UINT32 IV32);
#endif
