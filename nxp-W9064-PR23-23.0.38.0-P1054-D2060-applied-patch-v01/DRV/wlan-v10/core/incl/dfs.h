/** @file dfs.h
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

/*
*
*        Header file for AP DFS State Machines
*
*/

#ifndef _DFS_SM_
#define _DFS_SM_

#ifdef MRVL_DFS
#include <linux/netdevice.h>
#include "mhsm.h"
#include "timer.h"
#include "wltypes.h"
#include "List.h"
#include "hostcmd.h"
#include "wl_hal.h"
#include "buildModes.h"

#define MAX_VMAC_AP    NUMOFAPS
struct wlprivate_data;

#define DFS_DEFAULT_CAC_TIMEOUT  600	// 600*100 ms = 60 seconds
#define DFS_DEFAULT_NOC_TIMEOUT  18000	// 18000*100 ms = 1800 seconds
#define DFS_DEFAULT_CSA_TIMEOUT  100	// 100*100 ms = 10 seconds

#define DFS_DEFAULT_CSAMODE 			1
#define DFS_DEFAULT_COUNTDOWN_NUMBER	20

typedef enum _DFS_STATE {
	DFS_STATE_UNKNOWN = 0,
	DFS_STATE_INIT,
	DFS_STATE_SCAN,
	DFS_STATE_OPERATIONAL,
	DFS_STATE_CSA,
#ifdef RADAR_SCANNER_SUPPORT
	DFS_STATE_IDLE,
	DFS_STATE_NOT_DFS_CH,
#endif
	DFS_STATE_EM_SCAN,	/* Only scan once, do not change channel when radar detect */
	DFS_STATE_EM_SCAN_ALL,	/* Scan all op_channel, do not change channel when radar detect */
	DFS_STATE_MAX,
} DFS_STATE;
typedef UINT8 DFS_STATE_t;

#define DFS_QUIET_MODE		0
#define DFS_NORMAL_MODE		1

#ifdef RADAR_SCANNER_SUPPORT
#define DFS_MSG_AP_SWITCH_ CH_NOCAC "AP - Switch to subch without CAC:  "

#ifdef CONCURRENT_DFS_SUPPORT
#define DFS_PATH_DEDICATED		1
#define DFS_PATH_NORMAL			0
#define NELEMENTS(x) (sizeof(x)/sizeof(x[0]))
#define DR_SCANNER_SERVICE_START                        4
#define DR_SCANNER_SERVICE_STOP                         5
#endif /* CONCURRENT_DFS_SUPPORT */

typedef enum {
	ScnrCtl_Radar_Detected,
	ScnrCtl_CAC_Done,
	ScnrCtl_Switched_to_subch,
	ScnrCtl_Channel_switch_start_cac,
	ScnrCtl_Starting_CSA,
	ScnrCtl_Chan_Operational,
} SCANNER_CTL_EVENT;
#endif

typedef enum _DFS_STATUS {
	DFS_FAILURE = 0,
	DFS_SUCCESS
} DFS_STATUS;

typedef struct _DfsChanInfo {
	UINT8 channel;
	UINT8 channel2;
	UINT8 from;
	CHNL_FLAGS chanflag;
#ifdef RADAR_SCANNER_SUPPORT
	UINT8 no_cac;
	UINT8 do_csa;
#endif
} DfsChanInfo;

typedef struct _Dfs_RadarDetInd_t {
	DfsChanInfo chInfo;
} Dfs_RadarDetInd_t;

typedef struct _Dfs_ChanSwitchCfrm_t {
	UINT8 result;
	DfsChanInfo chInfo;
} Dfs_ChanSwitchCfrm_t;

typedef struct _Dfs_ChanSwitchReq_t {
	U8 usageflag;
	IEEEtypes_ChannelSwitchCmd_t ChannelSwitchCmd;
	DfsChanInfo chInfo;
} Dfs_ChanSwitchReq_t;

typedef struct _NOCListItem {
	struct _NOCListItem *nxt;
	struct _NOCListItem *prv;
	UINT8 channel;
	unsigned long occurance;	/* should be same size as jiffies of the system */
	UINT8 BW;
} NOCListItem;

typedef struct _DfsApDesc {
	DFS_STATE_t currState;
	DfsChanInfo currChanInfo;
	void *me;
	Timer CACTimer;
	Timer NOCTimer;
	Timer CSATimer;
	List NOCList;
	UINT16 CACTimeOut;
	UINT16 CSATimeOut;
	UINT16 NOCTimeOut;
	UINT32 cac_complete;
	UINT8 vaplist[MAX_VMAC_AP];
	UINT8 vapcount;
#ifdef CONCURRENT_DFS_SUPPORT
	Timer CtlCACTimer;
	UINT16 CtlCACTimeOut;
	DFS_STATE_t CtlAuxState;
	DFS_STATE_t CtlOpState;
	DfsChanInfo CtlChanInfo;
	UINT16 CtlReadyCh;
#endif				/* CONCURRENT_DFS_SUPPORT */
	Timer EMCACTimer;
	DFS_STATE_t EMCACState;
	BOOLEAN RadarDetected;
	ktime_t RadarDetectedTime;
} DfsApDesc;

typedef struct _DfsAp {
	Mhsm_t super;
	MhsmState_t sTop;
	MhsmState_t Dfs_Ap;
	MhsmState_t Dfs_Init, Dfs_Scan, Dfs_Operational, Dfs_Csa;
	DfsApDesc dfsApDesc;
	UINT32 dropData;
	struct net_device *pNetDev;
#ifdef RADAR_SCANNER_SUPPORT
#ifdef CONCURRENT_DFS_SUPPORT
	void (*scnr_ctl_evt) (struct net_device * dev,
			      SCANNER_CTL_EVENT event,
			      DFS_STATE dfs_status, UINT8 IsFromAux);
#endif				/* CONCURRENT_DFS_SUPPORT */
	void (*scnr_send_evt) (struct net_device * dev,
			       SCANNER_CTL_EVENT event, DFS_STATE dfs_status);
#endif				/* RADAR_SCANNER_SUPPORT */
} DfsAp;

typedef struct _DfsApMsg {
	UINT8 opMode;
	UINT8 *mgtMsg;
} DfsApMsg;

/* MLME State Machine Events */
enum DfsEvents {
	CHANNEL_CHANGE_EVT,
	RADAR_EVT,
	CAC_EXPIRY_EVT,
	WL_RESET_EVT,
	CSA_EXPIRY_EVT
};

/*** Definition for Trae Log ***/
#define MAX_DFS_TRACE_LOG   64

typedef struct _dfsTraceLog_t {
	UINT32 timestamp;
	UINT32 state:4;
	UINT32 event:4;
	UINT32 radiomode:4;
	UINT32 chanInfo:1;
	UINT32 rsvd:19;

	UINT32 bw:4;
	UINT32 chan:8;
	UINT32 isDfs:1;
	UINT32 rsvd1:3;
	UINT32 bw2:4;
	UINT32 chan2:8;
	UINT32 isDfs2:1;
	UINT32 rsvd2:3;

	UINT32 tag;
} dfsTraceLog_t;

extern void dfsTrace(struct net_device *netdev, UINT8 state, UINT8 event,
		     DfsChanInfo * pInfo, UINT32 tag);
/* Function declarations */
void DfsInit(struct net_device *pNetDev, struct wlprivate_data *wlpd_p);
void DfsDeInit(struct wlprivate_data *wlpd_p);
void DFSApCtor(struct net_device *pNetDev, DfsAp * me);
DFS_STATUS DfsEnabledChannel(struct net_device *pNetDev,
			     DfsChanInfo * chanInfo_p);
DFS_STATUS DfsAddToNOL(DfsApDesc * dfsDesc_p, UINT8 channel,
		       CHNL_FLAGS chanflag, unsigned long occurance);
#ifdef CONCURRENT_DFS_SUPPORT
DFS_STATUS UpdateNOL(DfsApDesc * dfsDesc_p, UINT8 IsFromAux);
#else
DFS_STATUS UpdateNOL(DfsApDesc * dfsDesc_p);
#endif /* CONCURRENT_DFS_SUPPORT */
void GetDfs80MhzGrpChan(UINT8 domainInd, UINT8 channel, UINT8 * GrpChan);
DFS_STATUS DfsRemoveFromNOL(DfsApDesc * dfsDesc_p);
//static void NOCTimeoutHandler(void *data_p);
DFS_STATUS IsTestChannelHiddenInNOL_160MHz(DfsApDesc * dfsDesc_p,
					   UINT8 testchannel);
DFS_STATUS IsTestChannelHiddenInNOL_80MHz(DfsApDesc * dfsDesc_p,
					  UINT8 testchannel);
DFS_STATUS IsTestChannelHiddenInNOL_40MHz(DfsApDesc * dfsDesc_p,
					  UINT8 testchannel);
#ifdef CONCURRENT_DFS_SUPPORT
UINT8 DfsDecideNewTargetChannel(struct net_device *dev, DfsApDesc * dfsDesc_p,
				BOOLEAN bChkDFSgroup, UINT8 IsFromAux);
#else
UINT8 DfsDecideNewTargetChannel(struct net_device *dev, DfsApDesc * dfsDesc_p,
				BOOLEAN bChkDFSgroup);
#endif /* CONCURRENT_DFS_SUPPORT */
DFS_STATUS DfsFindInNOL(List * NOCList, UINT8 chan);
void DfsPrintNOLChannelDetails(DfsAp * me, char *NOLPrintStr_p, int maxLength);
DFS_STATE DfsGetCurrentState(DfsAp * me);
UINT16 DfsGetCACTimeOut(DfsAp * me);
UINT16 DfsGetNOCTimeOut(DfsAp * me);
DFS_STATUS DfsSetCACTimeOut(DfsAp * me, UINT16 timeout);
DFS_STATUS DfsSetNOCTimeOut(DfsAp * me, UINT16 timeout);
UINT8 DFSGetExtensionChannelOfDFSChan(UINT8 domain, UINT8 extChnlOffset,
				      UINT8 channel);
UINT8 DFSGetCurrentRadarDetectionMode(DfsAp * me, UINT8 channel, UINT8 secChan,
				      CHNL_FLAGS chanFlag);
DFS_STATUS DfsPresentInNOL(struct net_device *dev, UINT8 channel);
void DFSApReset(DfsAp * me);
void FireCACTimer(DfsAp * me);
void DisarmCACTimer(DfsAp * me);
extern SINT8 evtDFSMsg(struct net_device *dev, UINT8 * message);
#ifdef RADAR_SCANNER_SUPPORT
void dfs_controller_send_event(struct net_device *dev, SCANNER_CTL_EVENT event,
			       DFS_STATE dfs_status);
DFS_STATUS dfs_sme_channel_switch(struct net_device *dev, UINT16 channel,
				  UINT8 no_cac, UINT8 do_csa);
#ifdef CONCURRENT_DFS_SUPPORT
void DFSCtlInit(struct net_device *pNetDev);
DFS_STATUS IsTheSameGroup(UINT16 ch1, UINT16 ch2, UINT8 bw);
void concurrent_dfs_proc(struct net_device *dev, SCANNER_CTL_EVENT event,
			 DFS_STATE dfs_status, UINT8 IsFromAux);
void AuxCACTimeoutHandler(void *data_p);
void FireAuxCACTimer(DfsAp * me);
void DisarmAuxCACTimer(DfsAp * me);
#endif /* CONCURRENT_DFS_SUPPORT */
#endif /* RADAR_SCANNER_SUPPORT */
#endif /* MRVL_DFS */
#endif /* _DFS_SM_ */
