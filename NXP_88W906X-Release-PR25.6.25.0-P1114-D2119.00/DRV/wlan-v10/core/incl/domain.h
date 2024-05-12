/** @file domain.h
  *
  * @brief This file contains WLAN driver specific defines etc.
  *
  * Copyright 2002-2021 NXP
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

#ifndef _DOMAIN_H_
#define _DOMAIN_H_

#define DOMAIN_CODE_FCC     0x10
#define DOMAIN_CODE_IC      0x20
#define DOMAIN_CODE_ETSI    0x30
#define DOMAIN_CODE_SPAIN   0x31
#define DOMAIN_CODE_FRANCE  0x32
#define DOMAIN_CODE_ITALY   0x33
#define DOMAIN_CODE_MKK     0x40
#define DOMAIN_CODE_DGT     0x80
#define DOMAIN_CODE_AUS     0x81
#define DOMAIN_CODE_ASIA    0x90	// Asia (Singapore, Thailand, Indonesia, Malaysia, Hong Kong, Vietnam, sometimes China)
#ifdef JAPAN_CHANNEL_SPACING_10_SUPPORT
#define DOMAIN_CODE_MKK2     0x41  /** for japan channel with spacing 10 **/
#endif
#define DOMAIN_CODE_MKK3     0x41  /** for japan channel - 5450-5725 MHz */
#define DOMAIN_CODE_MKK_N    0x43  /** for japan channel after July 1st 2020 */
#define DOMAIN_CODE_CHN		0x91
#define DOMAIN_CODE_TH			0x92	// Thailand, add in Asia region.
/* Uncomment the following line to have special domain support for Barbados */
//#define BARBADOS_DOMAIN

#ifdef BARBADOS_DOMAIN
#define DOMAIN_BARBADOS_A		0xa0
#define DOMAIN_BARBADOS_B		0xa1
#endif

#define DOMAIN_CODE_ALL		0xff

#define DFS_MAX_CHANNELS 				31	//15
#define MAX_OP_CLASS_NUM 256
#define MAX_NON_OP_CH_NUM 30

typedef PACK_START struct _DFS_CHANNEL_LIST {
	UINT8 domainCode;
	UINT8 dfschannelEntry[DFS_MAX_CHANNELS];
} PACK_END DFS_CHANNEL_LIST;

typedef PACK_START struct _GRP_CHANNEL_LIST_40Mhz {
	UINT8 channelEntry[2];
} PACK_END GRP_CHANNEL_LIST_40Mhz;

typedef PACK_START struct _GRP_CHANNEL_LIST_80Mhz {
	UINT8 channelEntry[4];
} PACK_END GRP_CHANNEL_LIST_80Mhz;
typedef PACK_START struct _GRP_CHANNEL_LIST_160Mhz {
	UINT8 channelEntry[8];
} PACK_END GRP_CHANNEL_LIST_160Mhz;

typedef struct op_class_tab_t {
	u8 op_class;
	u8 max_power;
	u8 non_op_channel_nums;
	u8 non_op_channel_list[MAX_NON_OP_CH_NUM];
} op_class_tab_t;

typedef struct op_class_info_t {
	u8 domain_code;
	u8 op_class_nums;
	op_class_tab_t op_class_tab[MAX_OP_CLASS_NUM];
} op_class_info_t;

extern DFS_CHANNEL_LIST dfsEnabledChannels[];
extern GRP_CHANNEL_LIST_40Mhz GrpChList40Mhz[];
extern GRP_CHANNEL_LIST_80Mhz GrpChList80Mhz[];
extern GRP_CHANNEL_LIST_160Mhz GrpChList160Mhz[];
int domainGetInfo(unsigned char *ChannelList /* NULL Terminate */ );
int domainChannelValid(unsigned char channel, unsigned char band);
unsigned char domainGetRegulatory(UINT8 domainCode);
int domainGetSizeOfdfsEnabledChannels(void);
int domainGetSizeOfIEEERegionChannel(void);
int domainGetSizeOfGrpChList40Mhz(void);
int domainGetSizeOfGrpChList80Mhz(void);
int domainGetSizeOfGrpChList160Mhz(void);
void Get5GChannelList(UINT8 domainCode, UINT8 * IEEERegionChannel_5G);
BOOLEAN channel_exists(UINT8 channel, UINT8 * list, UINT8 len);
BOOLEAN Is160MzChannel(UINT8 testchannel, UINT8 domainInd_IEEERegion);
BOOLEAN IsTestchannel80MzChannel(UINT8 testchannel, UINT8 domainInd_IEEERegion);
BOOLEAN IsTestchannel40MzChannel(UINT8 testchannel, UINT8 domainInd_IEEERegion);
BOOLEAN Is80MzChannelInFallBack(UINT8 * FallbackChannelList, UINT8 fallbackchannel, UINT8 fallbackCnt);
BOOLEAN Is40MzChannel(UINT8 * FallbackChannelList, UINT8 fallbackchannel, UINT8 fallbackCnt);
void GetDfs160MhzGrpChan(UINT8 domainInd, UINT8 channel, UINT8 * GrpChan);
int GetDomainIndxIEEERegion(UINT8 domainCode);
int GetRegionChan(UINT8 domainInd_IEEERegion, UINT8 j);
UINT8 FindFallbackChannel(UINT8 fallbackCnt, UINT8 * FallbackChannelList, UINT8 BW);
unsigned char domainGetDomain(void);
extern int domainSetDomain(unsigned char domain);
extern int domainGetPowerInfo(unsigned char *info);
#ifdef CONCURRENT_DFS_SUPPORT
int GetNumOfChList160Mhz(void);
int GetNumOfChList80Mhz(void);
int GetNumOfChList40Mhz(void);
#endif				/* CONCURRENT_DFS_SUPPORT */
extern int GetRegionChanIndx(UINT8 domainInd_IEEERegion, UINT8 channel);
extern boolean get_ch_report_list_by_reg_code(UINT8 reg_code, u8 op_class, UINT8 * ch_list_p);
#endif /*_DOMAIN_H_*/
