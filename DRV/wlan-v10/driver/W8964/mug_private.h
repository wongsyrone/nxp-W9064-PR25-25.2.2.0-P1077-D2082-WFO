/** @file mug_private.h
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2018-2020 NXP
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
#ifndef __MUG_PRIVATE_H__
#define __MUG_PRIVATE_H__

/******************************************************************************/

#define NTONES_MAX          124
#define RXANTENNAS_MAX      4
#define NSTS_MAX            3

#define BFINFO_DWORDS                       28
// First + 1 is because 1st DWORD contains the length.
// Last +1 is for "ceil" of / 4.
#define LTF_RECORD_LENGTH_MAX_DWORD         (1 + ((2 * NTONES_MAX * RXANTENNAS_MAX) / 4) + 1)
// First + 1 is because 1st DWORD contains the length.
// Last +1 is for "ceil" of / 4
#define CSI_RECORD_LENGTH_MAX_DWORD         (1 + ((2 * RXANTENNAS_MAX * NSTS_MAX * NTONES_MAX) / 4) + 1)
#define CSI_LLTF_SINGLE_BUFFER_SIZE_DWORD   (BFINFO_DWORDS + LTF_RECORD_LENGTH_MAX_DWORD + CSI_RECORD_LENGTH_MAX_DWORD)
/* Make CSI_LLTF_BUFFERS_NUMBER value is a power of 2 to allow proper looping on CSI data! */
//#define CSI_LLTF_BUFFERS_NUMBER             1024
//#define CSI_LLTF_INTERRUPT_THRESHOLD        (CSI_LLTF_BUFFERS_NUMBER - 128)
#define CSI_LLTF_BUFFERS_NUMBER             256
/* Threshold: the CSI IRQ is generated when this number of buffers has been written
 * by the DMA */
#define CSI_LLTF_INTERRUPT_THRESHOLD        (CSI_LLTF_BUFFERS_NUMBER / 2)

/******************************************************************************/

/* CEP definitions */

/* Number of fractional bits at numerator and at denominator.
 * In both cases we do squares of values (x.3), so total number of bits is 6 */
#define MUG_CEP_NUM_FRAC_NBITS  6
#define MUG_CEP_DEN_FRAC_NBITS  6

/* Number of integer bits at numerator.
 * The number of integer bits of the numerator has been computed starting from input value
 * data size (s8.3) and taking into account the series of operations done to obtain
 * the numerator.
 */
#define MUG_CEP_NUM_NBITS       27

/* To avoid using float point calculations when performing num/den,
 * the numerator of each projection value is shifted left of nbits(cep) - MUG_CEP_NUM_NBITS
 * prior to perform the integer division with the denominator.
 */
#define MUG_CEP_NUM_SHIFT_VALUE (sizeof(int32_t) * 8 - (MUG_CEP_NUM_NBITS))

/* This is the total number of fraction bits of each CEP value */
#define MUG_CEP_FRAC_NBITS      (MUG_CEP_NUM_SHIFT_VALUE +          \
MUG_CEP_NUM_FRAC_NBITS -           \
MUG_CEP_DEN_FRAC_NBITS)

/**
 * NOTE:
 * According to our calculations, the format of each CEP  value is s(32,MUG_CEP_FRAC_NBITS).
 *
 * HOWEVER based on our assumption the TRUE value has a different format...
 *
 * ASSUMPTION
 * We know that each CEP value should have a range [0..1] (because SUM is 1) BUT
 * actually they are ranged [0..4] because the FFT matrix we have used in our calculations
 * is unitary instead of having 1/2 values.
 *
 * WHY 0..4 and not 0..1 ?
 * If we used the correct FFT matrix, in the CEP there would be 1 extra fractional bit
 * (to represent 1/2), that becomes 2 bits when the SQUARE is done (to compute CEP).
 * So here we go two extra fractional bits that if not accounted becomes two extra
 * integer bits giving 2^2 = 4.
 *
 * CONCLUSION:
 * We can re-scale the CEP to be in RANGE [0..1] by accounting as fractional two
 * extra bits.
 *
 * AND, based on the previous assumption we know that the integer has only 1 bit
 * (max value is 1!!), so we can assume that the TRUE format of CEP is:
 *
 * integer bits:    1
 * fractional bits: MUG_CEP_FRAC_NBITS + 2
 * total bits:      MUG_CEP_FRAC_NBITS + 3
 * With MUG_CEP_FRAC_NBITS = 5, total number of bits is 8.
 *
 * WHAT can we say about correlation value?
 * The TRUE number of bits of correlation will be:
 * total       = 8 * 2 + log2(4) = 18.
 * fractional  = 7 * 2 = 14
 *
 * IN THE END, the correlation can be stored in a 32 bit and to get the floating-point value,
 * just divide with value by 2^14 :-)
 */
#define MUG_CORRELATION_FRAC_NBITS               ((MUG_CEP_FRAC_NBITS + 2) * 2)
#define MUG_DECIMAL_2_CORRELATION(decimal)      ((decimal) * (1 << MUG_CORRELATION_FRAC_NBITS) / 100)

/******************************************************************************/

/* PAIRS DATA STRUCTURE
 * The user_compat pair are stored into an array, that can be easily indexed
 * using a hash table.
 *
 * ORGANIZATION
 * The pairs are organized in the following way. Note that the top row represents
 * the 1st user of the pair, bottom row is the 2nd user and each column is a pair.
 *
 * Pair index: 0  1    n-1    n         n+n-1                     1/2 (n-1) x n - 1
 * 1st user:   u0 u0...u0   | u1 u1 ... u1   | ... | un-3 un-3  | un-2
 * 2nd user:   u1 u2...un-1 | u2 u3 ... un-1 | ... | un-2 un-1  | un-1
 *
 * For the indexing to work correctly, the pairs must be organized so that 1st user index
 * is always lower than the 2nd user index.
 *
 * INDEXING
 * Given a user pair (k,l), we want to find the associate pair offset.
 * The pair offset is composed of two parts:
 * - the offset of where all the pairs related to user k starts
 * (i.e. in the top row the first occurrence of uk),
 * - the offset of user l inside this pairs list
 * (i.e. in the bottom row the occurrence of ul having in the top row uk)
 *
 * The first offset is found with:
 *
 * SUM i=1 to k, (n-i)
 *
 * That is equivalent to:
 *
 * 1/2 x k x (2n - k - 1)
 *
 * The second offset is found with:
 *
 * l - k - 1
 *
 */

#define MUG_GET_PAIR_OFFSET(u1, u2) \
(((2 * (MUG_MAX_USERS) - (u1) - 1) * (u1) / 2) + ((u2) - (u1) - 1))

typedef PACK_START struct {
	u16 staid;
	u16 n_pkts;
	u8 n_tx_ss;
	u8 bss_id;
	u8 macaddr[6];		// Peer's L2 Address
	s32 best_compat_offset;	/* Note: offset is relative to the start of user_compat */
	u16 cep_samples;
	u8 cep_age;
	u8 bw_category;
	u8 n_triplets;		/* Number of 3x group candidates containing the user */
	u8 n_pairs;		/* Number of 2x group candidates containing the user */
} PACK_END mug_user_info_t;

typedef PACK_START struct {
	u16 user_pair_idx[2];
	u32 rf_correlation;	// RF correlation format: sXX.YY, with XX + YY = 32 and XX = MUG_PROJ_NUMERATOR_NBITS
} PACK_END mug_compat_pair_t;

#define MUG_FWINFO_PRIVATE \
struct \
{ \
    u16 csi_irqs;  \
    u32 csi_time; \
    u32 corr_time; \
    u32 group_time; \
} dbg; /* Debug info, may be removed once done...*/ \
u16               n_user;                           \
mug_user_info_t   user_info[MUG_MAX_USERS];         \
u16               n_compat;                         \
mug_compat_pair_t user_compat[0];	/* Leave the user_compat as last element */

#define MUG_FWINFO_FULL_SIZE    (sizeof(mug_fwinfo_t) + (sizeof(mug_compat_pair_t) * MUG_MAX_PAIRS))

#endif /* #ifndef __MUG_PRIVATE_H__ */
