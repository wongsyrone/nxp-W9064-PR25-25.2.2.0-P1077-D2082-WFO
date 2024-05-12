/** @file shal_sbf.h
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2014-2020 NXP
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

/**
 * @file
 * @brief SMAC SBF structures
 */

#ifndef _SHAL_SBF_H_
#define _SHAL_SBF_H_

#include "shal_sta.h"

#define SMAC_SBF_NUM                          (SMAC_STA_NUM + SMAC_MU_GROUP_SIZE)
#define SMAC_SBF_NUM_RUNNING                  (SMAC_STA_NUM_RUNNING + SMAC_MU_GROUP_SIZE)
#define SMAC_SBF_UNKNOWN                      0xFFFF

#define SBF_CSI_TYPE_BF_INFO              (1 << 0)
#define SBF_CSI_TYPE_LLTF                 (1 << 1)
#define SBF_CSI_TYPE_CSI                  (1 << 2)
#define SBF_CSI_TYPE_TDDE                 (1 << 3)

/// RBF structure forwarding
struct RBF_ENTRY_s;

//SMAC_BF_TYPE_t defined in Shal_sta.h
/*
typedef enum
{
    SMAC_BF_TYPE_HW_EXP = 0,
    SMAC_BF_TYPE_HW_IMP,
    SMAC_BF_TYPE_SW_IMP
} SMAC_BF_TYPE_t;
*/

typedef struct {
	U8 *addr;		///< DDR pointer
	U32 steerindx;		///< Allocated size available
	U32 size;		///< Used size
	U8 pktType;		///< Type of the packet
	U8 valid;		///< Keep track if data are valid;
} SBF_FB_INFO_st;

typedef struct {
	U8 *addr;		///< DDR pointer
	U32 memSize;		///< Allocated size available
	U32 size;		///< Used size
	U8 pktType;		///< Type of the packet
	U8 valid;		///< Keep track if data are valid;
} SBF_MEM_INFO_st;

typedef struct {
	SBF_MEM_INFO_st info;
	U16 rdIdx;		///< Read index: updated by PFW
	U16 wrIdx;		///< Write idnex: updated by SFW
	U16 entrySize;		///< Size of one CSI data entry
	U16 maxEntries;		///< Maximum number of CSI data entries in info
} SBF_CSI_INFO_st;

typedef struct SMAC_SBF_ENTRY_s {
	// Configuration information
	U8 valid:1;		///< Tell if the SBF entry is valid    
	U8 mu:1;		///< Tell if this is a MU SBF
	U8 mu_upload:1;		/// mu upload is ongoing
	U8 insuffNdp:1;		///< insufficient NDP enable?
	U8 txType:4;		///< MU_GROUP_TYPE_VHT/HE
	SMAC_BF_TYPE_t bfType;	///< Type of BF
	U8 lowestBW;		///< Lowest BW that triggers CSI generation
	U8 lowestSS;		///< Lowest SS  that triggers CSI generation
	U8 bw;			///< BW for sounding (SU)
	U8 ss;			///< SS for sounding (SU)
	U8 bfModes;		///< Different BF mode enabled
	U8 csiType;		///< CSI data requested
	struct SBF_USER_SLOT_s {
		U8 ss;		///< Number of allocated SS
		U8 rbfIdx;	///< Index of the user in the RBF entry
	} users[8];		///< User list in case of MU: TODO define max SS
	U8 nbUsers;		///< Number of users in the MU group
	U16 staGrpIdx;		///< Index of the STA or MU_GROUP related to this SBF entry
	// Dynamic data used by PFW/SFW
	SBF_MEM_INFO_st sm;	///< SM to be used for steering
	SBF_CSI_INFO_st csi;	///< CSI data buffers for CSI processing
	// Dynamic data used only by SFW
	U32 csiMask;		///< Mask on CSI information requested
	U32 csiEvents;		///< Currently received events
	SBF_FB_INFO_st ifb;	///< IFB to be processed to generate SM
	struct RBF_ENTRY_s *rbf;	///< RBF entry or NULL
	U8 soundedUser;		///< userIdx of the current sounded user
	U8 uploadRequested;	///< Tell if an upload was requested after IFB handling
	U8 smId;		///< SM ID
	U8 rbfBW;		///< BW info in rbf
	U8 rbfSS;		///< SS info in rbf
	U8 rbfcacheOffset;	///< cache offset info in rbf
	U8 doneDMA:3;		///< DMA done
	U8 muuploadstart:1;
	U8 doneDMA2:1;		/// DMA upload done
	U8 cacheupdated:1;	///new cache in ddr
	U8 sound:1;		///sounding happening
	U8 su_upload:1;
	U8 legacyEn;		///< IBF/CSI legacy_en
	U32 timeStamp;		///< Timestamp for aging 32bit
	U8 agingTimeOut;	///< aging time out
	U8 ibfRxMode;		///< IBF RX MODE
	U8 ibfBW;		///< IBF BW
	U8 ibfSS;		///< IBF SS
	U8 mudoneDMA;
	U8 steerindex;
	U8 muCombine;
	U8 mucnt;		//total success mu combine
	U32 bflen;
} SMAC_SBF_ENTRY_st;

#endif // _SHAL_SBF_H_
