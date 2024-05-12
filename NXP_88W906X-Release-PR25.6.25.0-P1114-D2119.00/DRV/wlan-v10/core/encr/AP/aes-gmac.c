/*
 * Copyright (c) 2004-2015, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

//#include "hmac.h"
#include "IEEE_types.h"
#include "aes.h"

#define WLAN_FC_RETRY           0x0800
#define WLAN_FC_PWRMGT          0x1000
#define WLAN_FC_MOREDATA        0x2000
static inline void WPA_PUT_LE16(u8 * a, u16 val)
{
	a[1] = val >> 8;
	a[0] = val & 0xff;
}

#define le_to_host16(n) (n)

static inline u32 WPA_GET_BE32(const u8 * a)
{
	return ((u32) a[0] << 24) | (a[1] << 16) | (a[2] << 8) | a[3];
}

static inline void WPA_PUT_BE32(u8 * a, u32 val)
{
	a[0] = (val >> 24) & 0xff;
	a[1] = (val >> 16) & 0xff;
	a[2] = (val >> 8) & 0xff;
	a[3] = val & 0xff;
}

static void inc32(u8 * block)
{
	u32 val;
	val = WPA_GET_BE32(block + AES_BLOCK_SIZE - 4);
	val++;
	WPA_PUT_BE32(block + AES_BLOCK_SIZE - 4, val);
}

static inline void WPA_PUT_BE64(u8 * a, u64 val)
{
	a[0] = val >> 56;
	a[1] = val >> 48;
	a[2] = val >> 40;
	a[3] = val >> 32;
	a[4] = val >> 24;
	a[5] = val >> 16;
	a[6] = val >> 8;
	a[7] = val & 0xff;
}

static void xor_block(u8 * dst, const u8 * src)
{
	u32 *d = (u32 *) dst;
	u32 *s = (u32 *) src;
	*d++ ^= *s++;
	*d++ ^= *s++;
	*d++ ^= *s++;
	*d++ ^= *s++;
}

static void shift_right_block(u8 * v)
{
	u32 val;

	val = WPA_GET_BE32(v + 12);
	val >>= 1;
	if (v[11] & 0x01)
		val |= 0x80000000;
	WPA_PUT_BE32(v + 12, val);

	val = WPA_GET_BE32(v + 8);
	val >>= 1;
	if (v[7] & 0x01)
		val |= 0x80000000;
	WPA_PUT_BE32(v + 8, val);

	val = WPA_GET_BE32(v + 4);
	val >>= 1;
	if (v[3] & 0x01)
		val |= 0x80000000;
	WPA_PUT_BE32(v + 4, val);

	val = WPA_GET_BE32(v);
	val >>= 1;
	WPA_PUT_BE32(v, val);
}

/* Multiplication in GF(2^128) */
static void gf_mult(const u8 * x, const u8 * y, u8 * z)
{
	u8 v[16];
	int i, j;

	memset(z, 0, 16);	/* Z_0 = 0^128 */
	memcpy(v, y, 16);	/* V_0 = Y */

	for (i = 0; i < 16; i++) {
		for (j = 0; j < 8; j++) {
			if (x[i] & BIT(7 - j)) {
				/* Z_(i + 1) = Z_i XOR V_i */
				xor_block(z, v);
			} else {
				/* Z_(i + 1) = Z_i */
			}

			if (v[15] & 0x01) {
				/* V_(i + 1) = (V_i >> 1) XOR R */
				shift_right_block(v);
				/* R = 11100001 || 0^120 */
				v[0] ^= 0xe1;
			} else {
				/* V_(i + 1) = V_i >> 1 */
				shift_right_block(v);
			}
		}
	}
}

static void ghash_start(u8 * y)
{
	/* Y_0 = 0^128 */
	memset(y, 0, 16);
}

static void ghash(const u8 * h, const u8 * x, size_t xlen, u8 * y)
{
	size_t m, i;
	const u8 *xpos = x;
	u8 tmp[16];

	m = xlen / 16;

	for (i = 0; i < m; i++) {
		/* Y_i = (Y^(i-1) XOR X_i) dot H */
		xor_block(y, xpos);
		xpos += 16;

		/* dot operation:
		 * multiplication operation for binary Galois (finite) field of
		 * 2^128 elements */
		gf_mult(y, h, tmp);
		memcpy(y, tmp, 16);
	}

	if (x + xlen > xpos) {
		/* Add zero padded last block */
		size_t last = x + xlen - xpos;
		memcpy(tmp, xpos, last);
		memset(tmp + last, 0, sizeof(tmp) - last);

		/* Y_i = (Y^(i-1) XOR X_i) dot H */
		xor_block(y, tmp);

		/* dot operation:
		 * multiplication operation for binary Galois (finite) field of
		 * 2^128 elements */
		gf_mult(y, h, tmp);
		memcpy(y, tmp, 16);
	}

	/* Return Y_m */
}

//#define AES_BLOCK_SIZE 16
static void aes_gctr(void *aes, const u8 * icb, const u8 * x, size_t xlen, u8 * y)
{
	size_t i, n, last;
	u8 cb[AES_BLOCK_SIZE], tmp[AES_BLOCK_SIZE];
	const u8 *xpos = x;
	u8 *ypos = y;

	if (xlen == 0)
		return;

	n = xlen / 16;

	memcpy(cb, icb, AES_BLOCK_SIZE);
	/* Full blocks */
	for (i = 0; i < n; i++) {
		aes_encrypt(aes, cb, ypos);
		xor_block(ypos, xpos);
		xpos += AES_BLOCK_SIZE;
		ypos += AES_BLOCK_SIZE;
		inc32(cb);
	}

	last = x + xlen - xpos;
	if (last) {
		/* Last, partial block */
		aes_encrypt(aes, cb, tmp);
		for (i = 0; i < last; i++)
			*ypos++ = *xpos++ ^ tmp[i];
	}
}

static void *aes_gcm_init_hash_subkey(const u8 * key, size_t key_len, u8 * H)
{
	void *aes;

	aes = aes_encrypt_init(key, key_len);
	if (aes == NULL)
		return NULL;

	/* Generate hash subkey H = AES_K(0^128) */
	memset(H, 0, AES_BLOCK_SIZE);
	aes_encrypt(aes, H, H);
	//(MSG_EXCESSIVE, "Hash subkey H for GHASH",
	//              H, AES_BLOCK_SIZE);
	return aes;
}

static void aes_gcm_prepare_j0(const u8 * iv, size_t iv_len, const u8 * H, u8 * J0)
{
	u8 len_buf[16];

	if (iv_len == 12) {
		/* Prepare block J_0 = IV || 0^31 || 1 [len(IV) = 96] */
		memcpy(J0, iv, iv_len);
		memset(J0 + iv_len, 0, AES_BLOCK_SIZE - iv_len);
		J0[AES_BLOCK_SIZE - 1] = 0x01;
	} else {
		/*
		 * s = 128 * ceil(len(IV)/128) - len(IV)
		 * J_0 = GHASH_H(IV || 0^(s+64) || [len(IV)]_64)
		 */
		ghash_start(J0);
		ghash(H, iv, iv_len, J0);
		WPA_PUT_BE64(len_buf, 0);
		WPA_PUT_BE64(len_buf + 8, iv_len * 8);
		ghash(H, len_buf, sizeof(len_buf), J0);
	}
}

static void aes_gcm_gctr(void *aes, const u8 * J0, const u8 * in, size_t len, u8 * out)
{
	u8 J0inc[AES_BLOCK_SIZE];

	if (len == 0)
		return;

	memcpy(J0inc, J0, AES_BLOCK_SIZE);
	inc32(J0inc);
	aes_gctr(aes, J0inc, in, len, out);
}

static void aes_gcm_ghash(const u8 * H, const u8 * aad, size_t aad_len, const u8 * crypt, size_t crypt_len, u8 * S)
{
	u8 len_buf[16];

	/*
	 * u = 128 * ceil[len(C)/128] - len(C)
	 * v = 128 * ceil[len(A)/128] - len(A)
	 * S = GHASH_H(A || 0^v || C || 0^u || [len(A)]64 || [len(C)]64)
	 * (i.e., zero padded to block size A || C and lengths of each in bits)
	 */
	ghash_start(S);
	ghash(H, aad, aad_len, S);
	ghash(H, crypt, crypt_len, S);
	WPA_PUT_BE64(len_buf, aad_len * 8);
	WPA_PUT_BE64(len_buf + 8, crypt_len * 8);
	ghash(H, len_buf, sizeof(len_buf), S);

	//wpa_hexdump_key(MSG_EXCESSIVE, "S = GHASH_H(...)", S, 16);
}

/**
 * aes_gcm_ae - GCM-AE_K(IV, P, A)
 */
int aes_gcm_ae(const u8 * key, size_t key_len, const u8 * iv, size_t iv_len,
	       const u8 * plain, size_t plain_len, const u8 * aad, size_t aad_len, u8 * crypt, u8 * tag)
{
	u8 H[AES_BLOCK_SIZE];
	u8 J0[AES_BLOCK_SIZE];
	u8 S[16];
	void *aes = NULL;
	int ret = 0;

	aes = aes_gcm_init_hash_subkey(key, key_len, H);
	if (aes == NULL) {
		ret = -1;
		goto exit;
	}

	aes_gcm_prepare_j0(iv, iv_len, H, J0);

	/* C = GCTR_K(inc_32(J_0), P) */
	aes_gcm_gctr(aes, J0, plain, plain_len, crypt);

	aes_gcm_ghash(H, aad, aad_len, crypt, plain_len, S);

	/* T = MSB_t(GCTR_K(J_0, S)) */
	aes_gctr(aes, J0, S, sizeof(S), tag);

	/* Return (C, T) */

	wl_kfree(aes);
 exit:
	return ret;
}

/**
 * aes_gcm_ad - GCM-AD_K(IV, C, A, T)
 */
int aes_gcm_ad(const u8 * key, size_t key_len, const u8 * iv, size_t iv_len,
	       const u8 * crypt, size_t crypt_len, const u8 * aad, size_t aad_len, const u8 * tag, u8 * plain)
{
	u8 H[AES_BLOCK_SIZE];
	u8 J0[AES_BLOCK_SIZE];
	u8 S[16], T[16];
	void *aes = NULL;
	int ret = 0;

	aes = aes_gcm_init_hash_subkey(key, key_len, H);
	if (aes == NULL) {
		ret = -1;
		goto exit;
	}
	aes_gcm_prepare_j0(iv, iv_len, H, J0);

	/* P = GCTR_K(inc_32(J_0), C) */
	aes_gcm_gctr(aes, J0, crypt, crypt_len, plain);

	aes_gcm_ghash(H, aad, aad_len, crypt, crypt_len, S);

	/* T' = MSB_t(GCTR_K(J_0, S)) */
	aes_gctr(aes, J0, S, sizeof(S), T);

	wl_kfree(aes);

	if (memcmp(tag, T, 16) != 0) {
		//wpa_printf(MSG_EXCESSIVE, "GCM: Tag mismatch");
		//return -1;
		ret = -1;
		goto exit;
	}

 exit:
	return ret;
}

int aes_gmac(const u8 * key, size_t key_len, const u8 * iv, size_t iv_len, const u8 * aad, size_t aad_len, u8 * tag)
{
	return aes_gcm_ae(key, key_len, iv, iv_len, NULL, 0, aad, aad_len, NULL, tag);
}

u8 *bip_gmac_protect(const u8 * igtk, size_t igtk_len, u8 * frame, size_t len, u8 * ipn, int keyid, size_t * prot_len)
{
	u8 *prot, *pos, *buf;
	u16 fc;
	IEEEtypes_MgmtHdr2_t *hdr;
	size_t plen;
	u8 nonce[12], *npos;

	plen = len + 26;
	prot = wl_kmalloc_autogfp(plen);
	if (prot == NULL)
		return NULL;
	memcpy(prot, frame, len);
	pos = prot + len;
	*pos++ = 76;
	*pos++ = 24;
	WPA_PUT_LE16(pos, keyid);
	pos += 2;
	memcpy(pos, ipn, 6);
	pos += 6;
	memset(pos, 0, 16);	/* MIC */

	buf = wl_kmalloc_autogfp(plen + 20 - 24);
	if (buf == NULL) {
		wl_kfree(prot);
		return NULL;
	}

	/* BIP AAD: FC(masked) A1 A2 A3 */
	hdr = (IEEEtypes_MgmtHdr2_t *) frame;
	fc = *(u16 *) & hdr->FrmCtl;
	//fc = le_to_host16(hdr->FrmCtl);

	fc &= ~(WLAN_FC_RETRY | WLAN_FC_PWRMGT | WLAN_FC_MOREDATA);
	WPA_PUT_LE16(buf, fc);
	memcpy(buf + 2, hdr->DestAddr, ETH_ALEN);
	memcpy(buf + 2 + ETH_ALEN, hdr->SrcAddr, ETH_ALEN);
	memcpy(buf + 2 * ETH_ALEN, hdr->BssId, ETH_ALEN);

	memcpy(buf + 20, prot + 24, plen - 24);
	//wpa_hexdump(MSG_MSGDUMP, "BIP-GMAC: AAD|Body(masked)",
	//          buf, plen + 20 - 24);
	/* Nonce: A2 | IPN */
	memcpy(nonce, hdr->SrcAddr, ETH_ALEN);
	npos = nonce + ETH_ALEN;
	*npos++ = ipn[5];
	*npos++ = ipn[4];
	*npos++ = ipn[3];
	*npos++ = ipn[2];
	*npos++ = ipn[1];
	*npos++ = ipn[0];
	//wpa_hexdump(MSG_EXCESSIVE, "BIP-GMAC: Nonce", nonce, sizeof(nonce));
	/* MIC = AES-GMAC(AAD || Frame Body(masked)) */

	if (aes_gmac(igtk, igtk_len, nonce, sizeof(nonce), buf, plen + 20 - 24, pos) < 0) {
		wl_kfree(prot);
		wl_kfree(buf);
		return NULL;
	}

	wl_kfree(buf);

	*prot_len = plen;
	return prot;
}
