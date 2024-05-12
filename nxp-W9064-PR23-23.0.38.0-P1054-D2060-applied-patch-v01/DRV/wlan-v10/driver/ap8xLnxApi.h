/** @file ap8xLnxApi.h
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
#ifndef	AP8X_API_H_
#define	AP8X_API_H_
#include "ieeetypescommon.h"

int wldo_ioctl(struct net_device *dev, struct ifreq *rq, int cmd);
struct iw_statistics *wlGetStats(struct net_device *dev);
UINT32 isAes4RsnValid(UINT8 ouiType);

extern int wlIoctl(struct net_device *dev, struct ifreq *rq, int cmd);
extern int wlSetupWEHdlr(struct net_device *netdev);
#if defined(SOC_W906X) || defined(SOC_W9068)
#define MAX_RATES_PER_GROUP		32
#define MAX_GROUP_PER_CHANNEL	280
#else
#define MAX_RATES_PER_GROUP		40
#define MAX_GROUP_PER_CHANNEL	50
#endif
#define MAX_RF_ANT_NUM 8
typedef struct RateGrp_s {
	UINT16 NumOfEntry;	//Number of valid entry  in Rate[]
	UINT8 AxAnt;
#if defined(SOC_W906X) || defined(SOC_W9068)
	UINT32 Rate[MAX_RATES_PER_GROUP];
#else
	UINT16 Rate[MAX_RATES_PER_GROUP];
#endif
} RateGrp_t;
//
//the following are for loadpwrperrate SC4_PwrPerRateGrps.ini
//

typedef struct PerChanGrpsPwr_s {
	UINT8 channel;
	UINT16 NumOfGrpPerChan;
#if defined(SOC_W906X) || defined(SOC_W9068)
	SINT16 GrpsPwr[MAX_GROUP_PER_CHANNEL];
#else
	s8 GrpsPwr[MAX_GROUP_PER_CHANNEL];
#endif
} PerChanGrpsPwr_t;

typedef struct AllChanGrpsPwrTbl_s {
	UINT16 NumOfChan;	//Number of valid entry  in PerChanGrpsPwrTbl[]
	PerChanGrpsPwr_t PerChanGrpsPwrTbl[IEEE_80211_MAX_NUMBER_OF_CHANNELS];

} AllChanGrpsPwrTbl_t;

#define IOCTL_SETCMD_IWINFO_CMD_ID_MAGIC    0x01

void eepromAction(struct net_device *netdev, UINT32 offset, UINT8 * data,
		  UINT32 len, UINT16 action);
long atohex2(const char *number);
UINT32 countNumOnes(UINT32 bitmap);
int Is5GBand(UINT8 opmode);
int IsHTmode(UINT8 opmode);
int IsVHTmode(UINT8 opmode);
#endif /* AP8X_API_H_ */
